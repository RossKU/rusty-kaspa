use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::push_index;
use crate::contract::spot::order::{e_num, e_pick, e_roll, ops};

// ============================================================================
// DECAY (Dutch) ORDERS — `decay_sell` / `decay_buy`
// (kob/TIME_CONTRACTS_DESIGN.md §2 — ADDITIVE contracts beside frozen v18;
//  SPOT_GENERATION stays 18, v18 bytecode untouched)
// ============================================================================
//
// The price numerator is a function of `tx.lock_time` L:
//
//   eff       = min( max(L, t0), t_end )          // clamp, handles L=0 and L<t0
//   pnum_eff  = pnum − dslope × (eff − t0)        // dslope ≥ 1, integer, exact
//
// with build-time invariants `t0 < t_end < LOCK_TIME_THRESHOLD` and
// `dslope × (t_end − t0) ≤ pnum − 1` (so `pnum_eff ≥ p_floor ≥ 1`; the floor
// is derived, not stored).
//
// Soundness argument (design §2.1, reproduced verbatim): the schedule f(L) is
// monotone in the taker-favorable direction as L grows. Consensus (T1)
// guarantees `actual acceptance DAA > L`. Therefore:
// (a) a taker understating L executes at f(L) which is *worse for the taker*
// than f(actual) — self-defeating, allowed, harmless; (b) a taker overstating L
// makes the tx unminable until DAA > L, at which point f(L) is exactly the
// maker's declared price for that time; (c) hence the executed price always lies
// inside the maker's declared envelope [f(actual), f(t0)] — the maker's schedule
// can never be violated, only under-used by lazy takers. `L=0` (Finalized type)
// carries no consensus time information, and the clamp maps it to `eff = t0` =
// the worst-for-taker end — the required default, obtained for free.
// A unix-ms-type L (≥ 5e11) would fast-forward the schedule to the floor while
// being minable immediately — killed by an explicit in-branch type guard
// `L < 500_000_000_000` (§2.5 line D1). An L ≥ 2^63 arrives negative from
// OpTxLockTime (T5): it passes the `<` guard but clamps to t0 (worst-for-taker)
// and is unminable for ~292M years anyway — fail-safe both ways.
//
// Direction is HARDWIRED per side, because only one direction is enforceable:
// - decay_sell (Dutch): `pnum/pden` = KAS per token; `pnum_eff` falls with
//   time ⇒ ask price decays. (Rising sell schedules are unenforceable.)
// - decay_buy (rising bid): in the buy, `pnum/pden` = tokens per KAS (floor is
//   `token_sum ≥ kas_in/pden×pnum`), so a rising bid = *fewer* tokens demanded
//   per KAS = `pnum_eff` falls — the SAME formula, both sides.
//
// State layouts (new fields PREPENDED — pushed first = deepest — so every v18
// body depth reference [0..N) survives; only dispatch roll depth, cleanup
// counts and the new checks change):
//
//   decay_sell (172B = 27 + v18 sell 145):
//     [0x08][dslope 8B][0x08][t0 8B][0x08][t_end 8B] ‖ v18 sell 145B layout
//   decay_buy  (205B = 27 + v18 buy 178): same three fields prepended.
//
// Selector maps identical to the v18 parents (sell: 0=CANCEL 1=FILL 2=PARTIAL
// 3=CANCEL-MARK 4=EXPIRE 5=IOC; buy: same). Decay lives inside the
// fill-family branches, each computing `pnum_eff` once at branch entry and
// using it wherever v18 used `pnum`. CANCEL/CANCEL-MARK/EXPIRE are
// semantics-identical to v18 (owner paths never price).
//
// BUILDER FREEZE RULE (design §2.6): the decayed attestation pair must NOT be
// gcd-normalized — the covenant D3/D4 checks demand the raw `(pnum_eff, pden)`
// bytes. Consistently, the decay RS builders store the RAW state pair (no gcd
// normalization anywhere on the decay path); the shared `decay_effective_pnum`
// helper generates builder values, covenant expectations and test vectors.

/// Consensus `LOCK_TIME_THRESHOLD` (values below = DAA-score type lock times).
pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

// Extra opcode bytes not present in `order::ops`.
const OP_MIN: u8 = 0xa3;
const OP_MAX: u8 = 0xa4;

/// Push the 5-byte `LOCK_TIME_THRESHOLD` literal (500_000_000_000 LE).
fn push_locktime_threshold(b: &mut Vec<u8>) {
    b.push(0x05);
    b.extend_from_slice(&[0x00, 0x88, 0x52, 0x6a, 0x74]);
}

/// ONE shared integer schedule helper (design §2.7): builder sigscript values,
/// covenant emitter expectations and test vectors must all come from here.
///
/// `eff = min(max(L, t0), t_end); pnum_eff = pnum − dslope×(eff − t0)`.
/// Callers must respect the build invariants (`dslope×(t_end−t0) ≤ pnum−1`);
/// saturating arithmetic only guards against misuse outside them.
pub fn decay_effective_pnum(price_num: u64, dslope: u64, t0: u64, t_end: u64, lock_time: u64) -> u64 {
    let eff = lock_time.max(t0).min(t_end);
    price_num.saturating_sub(dslope.saturating_mul(eff - t0))
}

/// Emit the shared D1+D2 block (design §2.5): lock-time type guard + clamp +
/// `pnum_eff` computation. Stack-effect: pushes `pnum_eff` on top.
///
/// Depth contract (identical in every decay fill-family branch): with the
/// block's own intermediates accounted for, `t0` is picked at `t0_depth+1`,
/// `t_end` at `t_end_depth+1`, `dslope` at `dslope_depth+1` and `pnum` at
/// `pnum_depth+1`, where the `*_depth` arguments are the base depths at block
/// entry.
fn emit_decay_pnum_eff(b: &mut Vec<u8>, t_end_depth: usize, t0_depth: usize, dslope_depth: usize, pnum_depth: usize) {
    use ops::*;
    // D1: L on stack + unix-ms type guard (schedule fast-forward killer).
    b.push(TXLOCKTIME);
    b.push(DUP);
    push_locktime_threshold(b);
    b.push(LT);
    b.push(VERIFY); // L < 500e9 (DAA-domain only; L ≥ 2^63 arrives negative
                    // from OpTxLockTime — passes `<`, clamps to t0, harmless)
    // D2: eff = min(max(L, t0), t_end); dec = (eff−t0)×dslope;
    //     pnum_eff = pnum − dec (no overflow: ≤ pnum−1 by build invariant).
    e_pick(b, t0_depth + 1);
    b.push(OP_MAX); // max(L, t0)
    e_pick(b, t_end_depth + 1);
    b.push(OP_MIN); // eff
    e_pick(b, t0_depth + 1);
    b.push(SUB); // eff − t0
    e_pick(b, dslope_depth + 1);
    b.push(MUL); // dec
    e_pick(b, pnum_depth + 1);
    b.push(SWAP);
    b.push(SUB); // pnum_eff = pnum − dec
}

// ============================================================================
// decay_sell body
// ============================================================================

/// Build the decay_sell body.
///
/// Stack after state push (12 items):
///   expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill(5), pden(6),
///   pnum(7), otspkh(8), t_end(9), t0(10), dslope(11); selector at depth 12
/// (v18 sell: 9).
pub fn build_decay_sell_body() -> Vec<u8> {
    use ops::*;
    let mut b: Vec<u8> = Vec::with_capacity(640);

    // ===== DISPATCH: selector (depth 12) to top =====
    e_roll(&mut b, 12);
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(EQUAL);
    b.push(IF); // selector == 4 -> EXPIRE (v18-identical, deeper cleanup)
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0 (GTC guard)
        b.push(CLTV);
        // stack: cpend(0), mmfee(1), sspkh(2), ohash(3), mfill(4), pden(5),
        //        pnum(6), otspkh(7), t_end(8), t0(9), dslope(10)
        b.push(TXINPUTINDEX);
        b.push(OP0);
        b.push(AUTHOUTPUTIDX); // r = auth_outputs[self][0]
        b.push(DUP);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 9); // otspkh (depth 7, +2 for r + hash)
        b.push(EQUAL);
        b.push(VERIFY); // refund lands on the owner's token_unit P2SH
        b.push(DUP);
        b.push(OUTPUTCOVENANTID);
        b.push(TXINPUTINDEX);
        b.push(INPUTCOVENANTID);
        b.push(EQUAL);
        b.push(VERIFY); // refund carries THIS token's CovenantBinding
        b.push(TXOUTPUTAMOUNT); // consumes r
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY); // full refund
        // 11 items: cpend..dslope
        for _ in 0..5 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 2);
        b.push(LT);
        b.push(IF); // selector < 2 (fill or cancel)
        {
            e_num(&mut b, 1);
            b.push(EQUAL);
            b.push(IF); // selector == 1 -> FILL
            {
                emit_decay_sell_fill(&mut b);
            }
            b.push(ELSE); // selector == 0 -> CANCEL
            {
                emit_decay_sell_cancel(&mut b, false);
            }
            b.push(ENDIF);
        }
        b.push(ELSE); // selector >= 2 (IOC, partial, cancel-mark)
        {
            b.push(DUP);
            e_num(&mut b, 5);
            b.push(EQUAL);
            b.push(IF); // selector == 5 -> IOC FILL
            {
                b.push(DROP);
                emit_decay_sell_ioc(&mut b);
            }
            b.push(ELSE);
            {
                e_num(&mut b, 2);
                b.push(EQUAL);
                b.push(IF); // selector == 2 -> PARTIAL FILL
                {
                    emit_decay_sell_partial(&mut b);
                }
                b.push(ELSE); // selector == 3 -> CANCEL-MARK
                {
                    emit_decay_sell_cancel(&mut b, true);
                }
                b.push(ENDIF);
            }
            b.push(ENDIF);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);
    b.push(OP1);
    b
}

/// decay_sell FILL (selector 1). Sigscript:
/// `[0x01,koi][0x08 pnum_eff(L)][0x08 pden][Op1][pushData(RS)]`.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), t_end(9), t0(10),
///   dslope(11), pden_att(12), pnum_att(13), koi(14)
fn emit_decay_sell_fill(b: &mut Vec<u8>) {
    use ops::*;
    // time gate (v18 expiry semantics unchanged)
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);
    // exposure delay
    e_num(b, 50);
    b.push(CSV);
    // F5: cpend == 0
    b.push(OP0);
    b.push(EQUAL);
    b.push(VERIFY);
    // base(13): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //   otspkh(6), t_end(7), t0(8), dslope(9), pden_att(10), pnum_att(11),
    //   koi(12)
    // D1+D2: pnum_eff on top.
    emit_decay_pnum_eff(b, 7, 8, 9, 5);
    // D3: ATTESTATION pnum_att == pnum_eff (NUMEQUAL, not EQUAL — T6:
    // computed value vs 8B-padded push).
    b.push(DUP);
    e_pick(b, 13); // pnum_att (11 + 2 for pnum_eff + dup)
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // D4: pden_att == pden (both 8B pushes — byte EQUAL is safe)
    e_pick(b, 11); // pden_att (10 + 1)
    e_pick(b, 6); // pden (4 + 2)
    b.push(EQUAL);
    b.push(VERIFY);
    // D5: v18 price math with pnum_eff in place of the pnum pick.
    // expected_kas = token_in * pnum_eff / pden, >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // [pnum_eff, token_in]
    b.push(MUL); // consumes pnum_eff
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 5); // mfill (3 + 2)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= expected_kas
    e_pick(b, 13); // koi (12 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 12); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: per-input token conservation (Fix-3, byte-identical to v18)
    b.push(TXINPUTINDEX);
    b.push(OP0);
    b.push(AUTHOUTPUTIDX);
    b.push(DUP);
    b.push(OUTPUTCOVENANTID);
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(EQUAL);
    b.push(VERIFY);
    b.push(TXOUTPUTAMOUNT);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 13 items
    for _ in 0..6 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// decay_sell IOC FILL (selector 5). Sigscript:
/// `[0x01,koi][0x08 pnum_eff][0x08 pden][0x08 fta][Op5][pushData(RS)]`.
///
/// Entry (stale selector dropped): expiry(0)..otspkh(8), t_end(9), t0(10),
///   dslope(11), fta(12), pden_att(13), pnum_att(14), koi(15)
fn emit_decay_sell_ioc(b: &mut Vec<u8>) {
    use ops::*;
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);
    e_num(b, 50);
    b.push(CSV);
    b.push(OP0);
    b.push(EQUAL);
    b.push(VERIFY);
    // base(14): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //   otspkh(6), t_end(7), t0(8), dslope(9), fta(10), pden_att(11),
    //   pnum_att(12), koi(13)
    emit_decay_pnum_eff(b, 7, 8, 9, 5);
    // D3
    b.push(DUP);
    e_pick(b, 14); // pnum_att (12 + 2)
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // D4
    e_pick(b, 12); // pden_att (11 + 1)
    e_pick(b, 6); // pden (4 + 2)
    b.push(EQUAL);
    b.push(VERIFY);
    // fill_kas = fta * pnum_eff / pden, >= mfill
    e_pick(b, 11); // fta (10 + 1)
    b.push(MUL); // consumes pnum_eff
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 5); // mfill (3 + 2)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= fill_kas
    e_pick(b, 14); // koi (13 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 13); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: residual conservation (self-SPK continuation >= token_in - fta)
    b.push(TXINPUTINDEX);
    b.push(OP0);
    b.push(AUTHOUTPUTIDX);
    b.push(DUP);
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    b.push(TXOUTPUTAMOUNT);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 12); // fta (10 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 14 items
    for _ in 0..7 {
        b.push(TWO_DROP);
    }
}

/// decay_sell PARTIAL FILL (selector 2). Sigscript:
/// `[0x01,koi][0x08 pnum_eff][0x08 pden][0x08 fta][ri][Op2][pushData(RS)]`.
///
/// Entry (selector consumed): expiry(0)..otspkh(8), t_end(9), t0(10),
///   dslope(11), ri(12), fta(13), pden_att(14), pnum_att(15), koi(16)
fn emit_decay_sell_partial(b: &mut Vec<u8>) {
    use ops::*;
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);
    e_num(b, 50);
    b.push(CSV);
    b.push(OP0);
    b.push(EQUAL);
    b.push(VERIFY);
    // base(15): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //   otspkh(6), t_end(7), t0(8), dslope(9), ri(10), fta(11), pden_att(12),
    //   pnum_att(13), koi(14)
    emit_decay_pnum_eff(b, 7, 8, 9, 5);
    // D3
    b.push(DUP);
    e_pick(b, 15); // pnum_att (13 + 2)
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // D4
    e_pick(b, 13); // pden_att (12 + 1)
    e_pick(b, 6); // pden (4 + 2)
    b.push(EQUAL);
    b.push(VERIFY);
    // Keep a second pnum_eff copy for the residual-fill floor.
    b.push(DUP); // [pe_keep(1), pe(0)]
    // fill_kas = fta * pnum_eff / pden, >= mfill (keeps an fta copy on stack)
    e_pick(b, 13); // fta (11 + 2)
    b.push(DUP); // [pe_keep, pe, fta, fta]
    e_num(b, 2);
    b.push(ROLL); // pe -> top: [pe_keep, fta, fta, pe]
    b.push(MUL); // [pe_keep, fta, fta*pe]
    e_pick(b, 7); // pden (4 + 3)
    b.push(DIV); // [pe_keep, fta, fill_kas]
    b.push(DUP);
    e_pick(b, 7); // mfill (3 + 4)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= fill_kas
    e_pick(b, 17); // koi (14 + 3)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY); // [pe_keep, fta]
    // partial guard: token_in > fta
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 1); // fta copy
    b.push(GT);
    b.push(VERIFY);
    // residual output SPK == own SPK (D&R continuation)
    e_pick(b, 12); // ri (10 + 2)
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    // residual output value >= token_in - fta (consumes the fta copy)
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // [pe_keep, fta, token_in]
    e_roll(b, 1); // [pe_keep, token_in, fta]
    b.push(SUB);
    e_pick(b, 12); // ri (10 + 2)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY); // [pe_keep]
    // residual-fill floor: (token_in - fta) * pnum_eff / pden >= mfill
    // (pnum_eff substitution carried into the residual floor too — §2.3)
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // [pe, token_in]
    e_pick(b, 13); // fta (11 + 2)
    b.push(SUB); // [pe, residual_tokens]
    b.push(MUL); // consumes pe
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    e_pick(b, 4); // mfill (3 + 1)
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash on koi
    e_pick(b, 14); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4 (Fix-3): this input's auth[0] is a self-SPK residual token output
    // worth >= token_in - fta (byte-identical to v18 at shifted depths).
    b.push(TXINPUTINDEX);
    b.push(OP0);
    b.push(AUTHOUTPUTIDX);
    b.push(DUP);
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    b.push(TXOUTPUTAMOUNT);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 13); // fta (11 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 15 items
    for _ in 0..7 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// decay_sell CANCEL (0) / CANCEL-MARK (3) — owner signature, v18 shapes.
fn emit_decay_sell_cancel(b: &mut Vec<u8>, mark: bool) {
    use ops::*;
    // entry (selector consumed): expiry(0)..otspkh(8), t_end(9), t0(10),
    //   dslope(11), pk(12), sig(13)
    if mark {
        b.push(DROP); // expiry
        b.push(OP0);
        b.push(EQUAL);
        b.push(VERIFY); // cpend == 0 (can't re-mark)
    } else {
        b.push(TWO_DROP); // expiry + cpend
    }
    // stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //        otspkh(6), t_end(7), t0(8), dslope(9), pk(10), sig(11)
    e_pick(b, 10); // pk
    b.push(BLAKE2B);
    e_pick(b, 3); // ohash (2 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 11); // sig
    e_roll(b, 11); // pk
    b.push(CHECKSIG);
    b.push(VERIFY);
    // 10 items
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
}

/// Expected decay_sell body length (pinned at Stage-A freeze).
pub const DECAY_SELL_BODY_EXPECTED_LEN: usize = 450;

/// decay_sell state size: `[0x08 dslope][0x08 t0][0x08 t_end]` + v18 sell 145B.
pub const DECAY_SELL_STATE_SIZE: usize = 27 + 145;

/// Expected decay_sell redeemScript length (172B state + body).
pub const DECAY_SELL_RS_EXPECTED_LEN: usize =
    DECAY_SELL_STATE_SIZE + DECAY_SELL_BODY_EXPECTED_LEN;

/// Shared decay schedule validation (§2.2).
fn validate_decay_schedule(dslope: u64, t0: u64, t_end: u64, price_num: u64) -> crate::Result<()> {
    if dslope == 0 {
        return Err(crate::KobError::Contract("dslope must be >= 1 (plain behavior = deploy the v18 contract)".into()));
    }
    if !(t0 < t_end) {
        return Err(crate::KobError::Contract("t0 must be < t_end".into()));
    }
    if t_end >= LOCK_TIME_THRESHOLD {
        return Err(crate::KobError::Contract("t_end must be < LOCK_TIME_THRESHOLD (DAA domain)".into()));
    }
    let travel = dslope
        .checked_mul(t_end - t0)
        .ok_or_else(|| crate::KobError::Contract("dslope*(t_end-t0) overflows".into()))?;
    if travel > price_num.saturating_sub(1) {
        return Err(crate::KobError::Contract("dslope*(t_end-t0) must be <= price_num-1 (floor >= 1)".into()));
    }
    Ok(())
}

/// Build the decay_sell redeemScript (172B state + body).
///
/// State: `[0x08][dslope][0x08][t0][0x08][t_end]` then the v18 sell 145B
/// layout unchanged. The price pair is stored RAW (NOT gcd-normalized): the
/// decayed attestation compares against these exact bytes (freeze rule §2.6).
pub fn build_decay_sell_redeem_script(
    dslope: u64,
    t0: u64,
    t_end: u64,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    seller_spk_hash: &[u8; 32],
    owner_token_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num == 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den == 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    validate_decay_schedule(dslope, t0, t_end, price_num)?;
    let body = build_decay_sell_body();
    let mut rs = Vec::with_capacity(DECAY_SELL_STATE_SIZE + body.len());
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(dslope));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(t0));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(t_end));
    rs.push(0x20);
    rs.extend_from_slice(owner_token_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(seller_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_matcher_fee_bps));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.extend_from_slice(&body);
    debug_assert_eq!(rs.len(), DECAY_SELL_RS_EXPECTED_LEN);
    Ok(rs)
}

/// Append the RAW (non-gcd-normalized) canonical attestation prefix:
/// `[0x01,koi][0x08 pnum_eff 8LE][0x08 pden 8LE]` — pnum_eff at [3..11),
/// pden at [12..20). Builder freeze rule §2.6: decayed attestations need the
/// raw pair or the covenant D3/D4 checks fail.
fn push_decayed_attested_prefix(ss: &mut Vec<u8>, kas_output_idx: u16, pnum_eff: u64, pden: u64) {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for the canonical convention");
    ss.push(0x01);
    ss.push(kas_output_idx as u8);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pnum_eff));
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pden));
}

/// Build decay_sell fill sigscript (canonical layout, raw decayed pair):
/// `[0x01,koi][0x08 pnum_eff(L)][0x08 pden][Op1][pushData(RS)]`.
pub fn build_decay_sell_fill_sigscript(
    kas_output_idx: u16,
    pnum_eff: u64,
    pden: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(21 + redeem_script.len() + 3);
    push_decayed_attested_prefix(&mut ss, kas_output_idx, pnum_eff, pden);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build decay_sell IOC fill sigscript:
/// `[0x01,koi][0x08 pnum_eff][0x08 pden][0x08 fta][Op5][pushData(RS)]`.
pub fn build_decay_sell_ioc_fill_sigscript(
    kas_output_idx: u16,
    pnum_eff: u64,
    pden: u64,
    fill_token_amount: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(30 + redeem_script.len() + 3);
    push_decayed_attested_prefix(&mut ss, kas_output_idx, pnum_eff, pden);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(fill_token_amount));
    ss.push(0x55); // Op5 (selector = IOC fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build decay_sell partial fill sigscript:
/// `[0x01,koi][0x08 pnum_eff][0x08 pden][0x08 fta][ri][Op2][pushData(RS)]`.
pub fn build_decay_sell_partial_fill_sigscript(
    kas_output_idx: u16,
    pnum_eff: u64,
    pden: u64,
    fill_token_amount: u64,
    residual_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(33 + redeem_script.len() + 3);
    push_decayed_attested_prefix(&mut ss, kas_output_idx, pnum_eff, pden);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(fill_token_amount));
    push_index(&mut ss, residual_output_idx);
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// (decay_sell expire/cancel sigscripts are byte-identical in shape to the v18
// sell's — reuse `build_sell_expire_sigscript`, `build_sell_cancel_sigscript`
// and `build_sell_cancel_mark_sigscript` with the decay RS.)

// ============================================================================
// decay_buy body
// ============================================================================

/// Build the decay_buy body (deterministic given `BUY_ORDER_MAX_N`).
///
/// Stack after state push (13 items):
///   expiry(0), cpend(1), mmfee_bps(2), bspkh(3), ohash(4), mfill(5),
///   pden(6), pnum(7), tcid(8), okspkh(9), t_end(10), t0(11), dslope(12);
///   selector at depth 13 (v18 buy: 10).
///
/// Rising bid: the GTC floor `token_sum >= kas_in/pden*pnum` becomes
/// `token_sum >= kas_in/pden*pnum_eff` — fewer tokens demanded per KAS as L
/// grows. The fair-cap PASS 2 consumes the counterparty sells' attested
/// prices at the canonical offsets, v18-unchanged.
pub fn build_decay_buy_body() -> Vec<u8> {
    use ops::*;
    const MAX_N: usize = crate::contract::spot::order::BUY_ORDER_MAX_N;
    let mut b: Vec<u8> = Vec::with_capacity(2048);

    // ===== DISPATCH: selector (depth 13) to top =====
    e_num(&mut b, 13);
    b.push(ROLL);

    // selector == 4 -> EXPIRE (refund to the owner KAS seat)
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(NUMEQUAL);
    b.push(IF);
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0 (GTC guard)
        b.push(CLTV);
        // stack: cpend(0), mmfee(1), bspkh(2), ohash(3), mfill(4), pden(5),
        //        pnum(6), tcid(7), okspkh(8), t_end(9), t0(10), dslope(11)
        b.push(OP0);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 9); // okspkh (depth 8 + 1 for the hash)
        b.push(EQUAL);
        b.push(VERIFY);
        b.push(OP0);
        b.push(TXOUTPUTAMOUNT);
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY);
        // 12 items: cpend..dslope
        for _ in 0..6 {
            b.push(TWO_DROP);
        }
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 0);
        b.push(NUMEQUAL);
        b.push(IF); // selector == 0 -> CANCEL
        {
            b.push(DROP);
            emit_decay_buy_cancel(&mut b);
        }
        b.push(ELSE);
        {
            b.push(DUP);
            e_num(&mut b, 3);
            b.push(NUMEQUAL);
            b.push(IF); // selector == 3 -> CANCEL-MARK
            {
                b.push(DROP);
                emit_decay_buy_cancel(&mut b);
            }
            b.push(ELSE);
            {
                b.push(DUP);
                e_num(&mut b, 2);
                b.push(NUMEQUAL);
                b.push(IF); // selector == 2 -> PARTIAL-FILL
                {
                    b.push(DROP);
                    emit_decay_buy_partial(&mut b, MAX_N);
                }
                b.push(ELSE);
                {
                    // selector is 1 (fill) or 5 (IOC); selector on top.
                    emit_decay_buy_fill(&mut b, MAX_N);
                }
                b.push(ENDIF);
            }
            b.push(ENDIF);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);

    b.push(OP1);
    b
}

/// decay_buy CANCEL / CANCEL-MARK. Entry (selector dropped): expiry(0),
///   cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5), pden(6), pnum(7),
///   tcid(8), okspkh(9), t_end(10), t0(11), dslope(12), sig(13), pk(14)
fn emit_decay_buy_cancel(b: &mut Vec<u8>) {
    use ops::*;
    e_pick(b, 14); // pk
    b.push(BLAKE2B);
    e_pick(b, 5); // ohash (depth 4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 13); // sig -> top
    e_roll(b, 14); // pk -> top
    b.push(CHECKSIGVERIFY);
    // 13 items: expiry..dslope
    for _ in 0..6 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// decay_buy FILL (1) / IOC (5): v18 `emit_fill_body` with the GTC floor
/// computed from `pnum_eff` (D1+D2 at branch entry).
///
/// Entry (selector on top): selector(0), expiry(1), cpend(2), mmfee(3),
///   bspkh(4), ohash(5), mfill(6), pden(7), pnum(8), tcid(9), okspkh(10),
///   t_end(11), t0(12), dslope(13), N(14), tii_MAX_N(15),
///   tii_k(15 + MAX_N - k)
fn emit_decay_buy_fill(b: &mut Vec<u8>, max_n: usize) {
    use ops::*;

    // A) ioc_flag = (selector == 5), replacing selector at depth 0.
    e_num(b, 5);
    b.push(NUMEQUAL);
    // B0: ioc_flag(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), t_end(11), t0(12),
    //     dslope(13), N(14), tii_MAX_N(15), tii_k(15 + max_n - k)

    // D1+D2: pnum_eff on top (base depths at B0: t_end 11, t0 12, dslope 13,
    // pnum 8).
    emit_decay_pnum_eff(b, 11, 12, 13, 8);
    // B0': pnum_eff(0), ioc_flag(1), expiry(2), cpend(3), ..., N(15),
    //      tii_k(16 + max_n - k)

    // B) F5: cpend == 0.
    e_pick(b, 3);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(VERIFY);

    // C) time gate on expiry (copy; leaves stack unchanged).
    e_pick(b, 2);
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);

    // D) exposure delay (OP_CSV 50 DAA).
    e_num(b, 50);
    b.push(CSV);

    // Distinctness: tii_k < tii_{k+1} for active adjacent pairs.
    for k in 1..max_n {
        e_num(b, (k + 1) as u16); // guard: (k+1) <= N
        e_pick(b, 16); // N (depth 15 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let d = 16 + max_n - k; // tii_k depth at B0'
            e_pick(b, d); // tii_k
            e_pick(b, d); // tii_{k+1}
            b.push(LT);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // E) floor_value = ioc_flag ? mfill : expected, consuming ioc_flag and
    //    pnum_eff. expected = kas_in / pden * pnum_eff (v17/v18 division
    //    order, only the operand source changes).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in(0), pnum_eff(1), ioc_flag(2)
    e_pick(b, 9); // pden (depth 7 + 2)
    b.push(DIV); // q(0), pnum_eff(1), ioc_flag(2)
    b.push(MUL); // expected = q * pnum_eff, consuming pnum_eff
    b.push(DUP);
    e_pick(b, 8); // mfill (B0 depth 6 -> +2 after expected/dup)
    b.push(GTE);
    b.push(VERIFY); // expected >= mfill
    b.push(SWAP); // ioc_flag(0), expected(1)
    b.push(IF);
    {
        b.push(DROP); // drop expected
        e_pick(b, 5); // mfill as floor
    }
    b.push(ENDIF);
    // B1: floor_value(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), t_end(11), t0(12),
    //     dslope(13), N(14), tii_MAX_N(15), ...

    // F) token_sum = 0.
    b.push(OP0);
    // B2: token_sum(0), floor_value(1), expiry(2), cpend(3), mmfee(4),
    //     bspkh(5), ohash(6), mfill(7), pden(8), pnum(9), tcid(10),
    //     okspkh(11), t_end(12), t0(13), dslope(14), N(15), tii_MAX_N(16),
    //     tii_k(16 + max_n - k)

    // G) PASS 1: sum delivered tokens + per-term binding checks.
    for k in 1..=max_n {
        e_num(b, k as u16); // guard: k <= N
        e_pick(b, 16); // N (depth 15 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 16 + max_n - k; // tii_k depth at B2
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi = auth_outputs[tii][0]
            e_pick(b, tii + 1); // tii_k (+1 for toi)
            b.push(INPUTCOVENANTID);
            e_pick(b, 12); // tcid (depth 10, +2 for toi+covid)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(DUP);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(b, 7); // bspkh (depth 5, +2 for toi+hash)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(TXOUTPUTAMOUNT); // tokens_i (consumes toi)
            b.push(ADD); // token_sum += tokens_i
        }
        b.push(ENDIF);
    }

    // H) aggregate limit-price floor: token_sum >= floor_value.
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // B3: expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5),
    //     pden(6), pnum(7), tcid(8), okspkh(9), t_end(10), t0(11),
    //     dslope(12), N(13), tii_MAX_N(14), tii_k(14 + max_n - k)

    // I) fair_sum = 0.
    b.push(OP0);
    // B4: fair_sum(0), expiry(1), ..., N(14), tii_MAX_N(15),
    //     tii_k(15 + max_n - k)

    // PASS 2: sum fair_kas at each sell's own ATTESTED price ([3..11)/[12..20)).
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 15); // N (depth 14 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 15 + max_n - k; // tii_k depth at B4
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi
            b.push(TXOUTPUTAMOUNT); // tokens_i
            e_pick(b, tii + 1); // tii_k (+1 for tokens)
            e_num(b, 3);
            e_num(b, 11);
            b.push(TXINPUTSIGSUBSTR); // sell_pnum (canonical [3..11))
            e_pick(b, tii + 2); // tii_k (+2 for tokens + pnum)
            e_num(b, 12);
            e_num(b, 20);
            b.push(TXINPUTSIGSUBSTR); // sell_pden (canonical [12..20))
            e_num(b, 2);
            b.push(ROLL); // tokens -> top
            b.push(SWAP);
            b.push(DIV);
            b.push(SWAP);
            b.push(MUL); // fair_kas = tokens / sell_pden * sell_pnum
            b.push(ADD); // fair_sum += fair_kas
        }
        b.push(ENDIF);
    }

    // J) aggregate surplus cap (v18-unchanged).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(DUP);
    e_num(b, 2);
    b.push(ROLL);
    b.push(SUB); // surplus = kas_in - fair_sum
    b.push(SWAP);
    e_num(b, 10000);
    b.push(DIV);
    e_pick(b, 4); // mmfee_bps (depth 2, +2)
    b.push(MUL);
    b.push(LTE);
    b.push(VERIFY);
    // leftover: 13 state + N + max_n tii
    let leftover = 14 + max_n;
    for _ in 0..(leftover / 2) {
        b.push(TWO_DROP);
    }
    if leftover % 2 == 1 {
        b.push(DROP);
    }
}

/// decay_buy PARTIAL-FILL (selector 2): the v18 Op2 machinery with the
/// spent-based floor computed from `pnum_eff`.
///
/// Entry (selector dropped): expiry(0), cpend(1), mmfee(2), bspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), tcid(8), okspkh(9), t_end(10),
///   t0(11), dslope(12), ri(13), N(14), tii_MAX_N(15), tii_k(15 + MAX_N - k)
fn emit_decay_buy_partial(b: &mut Vec<u8>, max_n: usize) {
    use ops::*;

    // P1) F5: cpend == 0.
    e_pick(b, 1);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(VERIFY);

    // P2) time gate on expiry (copy; stack-neutral).
    e_pick(b, 0);
    b.push(DUP);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(NOTIF);
    b.push(DUP);
    b.push(TXLOCKTIME);
    b.push(GT);
    b.push(VERIFY);
    b.push(ENDIF);
    b.push(DROP);

    // P3) exposure delay (OP_CSV 50 DAA).
    e_num(b, 50);
    b.push(CSV);

    // P4) distinctness: tii_k < tii_{k+1} for active adjacent pairs.
    for k in 1..max_n {
        e_num(b, (k + 1) as u16);
        e_pick(b, 15); // N (depth 14 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let d = 15 + max_n - k;
            e_pick(b, d);
            e_pick(b, d);
            b.push(LT);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // P5) self-instance uniqueness guard (stack-neutral, v18-identical).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK); // own_spk
    b.push(OP0); // count = 0
    for i in 0..16u16 {
        e_num(b, i);
        b.push(TXINPUTCOUNT);
        b.push(LT);
        b.push(IF);
        {
            e_num(b, i);
            b.push(TXINPUTSPK); // spk_i
            e_pick(b, 2); // own_spk
            b.push(EQUAL);
            b.push(ADD); // count += (spk_i == own_spk)
        }
        b.push(ENDIF);
    }
    b.push(OP1);
    b.push(NUMEQUAL);
    b.push(VERIFY); // exactly one self-instance
    b.push(TXINPUTCOUNT);
    e_num(b, 16);
    b.push(LTE);
    b.push(VERIFY); // no input beyond the scanned range
    b.push(DROP); // drop own_spk

    // P6) residual continuation + spent = kas_in - residual.
    e_pick(b, 13); // ri
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY); // byte-exact self-SPK (same RS => same state)
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in
    e_pick(b, 14); // ri (depth 13 + 1)
    b.push(TXOUTPUTAMOUNT); // residual(0), kas_in(1)
    b.push(DUP);
    b.push(OP1);
    b.push(GTE);
    b.push(VERIFY); // residual >= 1
    b.push(SUB); // spent = kas_in - residual
    b.push(DUP);
    b.push(OP0);
    b.push(GTE);
    b.push(VERIFY); // spent >= 0
    // B1: spent(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), t_end(11), t0(12),
    //     dslope(13), ri(14), N(15), tii_MAX_N(16), tii_k(16 + max_n - k)

    // D1+D2: pnum_eff on top (base depths at B1: t_end 11, t0 12, dslope 13,
    // pnum 8).
    emit_decay_pnum_eff(b, 11, 12, 13, 8);

    // P7) floor_value = spent / pden * pnum_eff.
    e_pick(b, 1); // spent copy: [pnum_eff(1), spent_c(0)]
    e_pick(b, 9); // pden (depth 7 + 2)
    b.push(DIV); // q(0), pnum_eff(1)
    b.push(MUL); // floor = q * pnum_eff, consuming pnum_eff
    // B2: floor(0), spent(1), expiry(2), cpend(3), mmfee(4), bspkh(5),
    //     ohash(6), mfill(7), pden(8), pnum(9), tcid(10), okspkh(11),
    //     t_end(12), t0(13), dslope(14), ri(15), N(16), tii_MAX_N(17)

    // P8) token_sum = 0.
    b.push(OP0);
    // B3: token_sum(0), floor(1), spent(2), expiry(3), cpend(4), mmfee(5),
    //     bspkh(6), ohash(7), mfill(8), pden(9), pnum(10), tcid(11),
    //     okspkh(12), t_end(13), t0(14), dslope(15), ri(16), N(17),
    //     tii_MAX_N(18), tii_k(18 + max_n - k)

    // P9) PASS 1: sum delivered tokens + per-term binding checks.
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 18); // N (depth 17 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 18 + max_n - k; // tii_k depth at B3
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX);
            e_pick(b, tii + 1);
            b.push(INPUTCOVENANTID);
            e_pick(b, 13); // tcid (depth 11, +2 for toi+covid)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(DUP);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(b, 8); // bspkh (depth 6, +2 for toi+hash)
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(TXOUTPUTAMOUNT);
            b.push(ADD);
        }
        b.push(ENDIF);
    }

    // P10) floors: token_sum >= mfill (per event), token_sum >= floor.
    b.push(DUP);
    e_pick(b, 9); // mfill (depth 8 + 1)
    b.push(GTE);
    b.push(VERIFY);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // B4: spent(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), t_end(11), t0(12),
    //     dslope(13), ri(14), N(15), tii_MAX_N(16)

    // P11) fair_sum = 0.
    b.push(OP0);
    // B5: fair_sum(0), spent(1), expiry(2), cpend(3), mmfee(4), bspkh(5),
    //     ohash(6), mfill(7), pden(8), pnum(9), tcid(10), okspkh(11),
    //     t_end(12), t0(13), dslope(14), ri(15), N(16), tii_MAX_N(17),
    //     tii_k(17 + max_n - k)

    // P12) PASS 2: fair_sum at each sell's attested price.
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 17); // N (depth 16 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 17 + max_n - k; // tii_k depth at B5
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX);
            b.push(TXOUTPUTAMOUNT);
            e_pick(b, tii + 1);
            e_num(b, 3);
            e_num(b, 11);
            b.push(TXINPUTSIGSUBSTR);
            e_pick(b, tii + 2);
            e_num(b, 12);
            e_num(b, 20);
            b.push(TXINPUTSIGSUBSTR);
            e_num(b, 2);
            b.push(ROLL);
            b.push(SWAP);
            b.push(DIV);
            b.push(SWAP);
            b.push(MUL);
            b.push(ADD);
        }
        b.push(ENDIF);
    }

    // P13) spent-based surplus cap: (spent - fair_sum) <= spent/10000*mmfee.
    e_pick(b, 1); // spent copy
    b.push(DUP);
    e_num(b, 2);
    b.push(ROLL); // fair_sum -> top
    b.push(SUB); // surplus = spent - fair_sum
    b.push(SWAP);
    e_num(b, 10000);
    b.push(DIV);
    e_pick(b, 5); // mmfee_bps (depth 3, +2)
    b.push(MUL);
    b.push(LTE);
    b.push(VERIFY);
    // leftover: spent + 13 state + ri + N + max_n tii
    let leftover = 16 + max_n;
    for _ in 0..(leftover / 2) {
        b.push(TWO_DROP);
    }
    if leftover % 2 == 1 {
        b.push(DROP);
    }
}

/// Expected decay_buy body length (pinned at Stage-A freeze).
pub const DECAY_BUY_BODY_EXPECTED_LEN: usize = 1652;

/// decay_buy state size: `[0x08 dslope][0x08 t0][0x08 t_end]` + v18 buy 178B.
pub const DECAY_BUY_STATE_SIZE: usize = 27 + 178;

/// Expected decay_buy redeemScript length (205B state + body).
pub const DECAY_BUY_RS_EXPECTED_LEN: usize =
    DECAY_BUY_STATE_SIZE + DECAY_BUY_BODY_EXPECTED_LEN;

/// Build the decay_buy redeemScript (205B state + body).
///
/// State: `[0x08][dslope][0x08][t0][0x08][t_end]` then the v18 buy 178B
/// layout unchanged. The price pair is stored RAW (NOT gcd-normalized) so the
/// schedule acts on the user-declared numerator units.
pub fn build_decay_buy_redeem_script(
    dslope: u64,
    t0: u64,
    t_end: u64,
    token_covenant_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    buyer_spk_hash: &[u8; 32],
    owner_kas_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num == 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den == 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    validate_decay_schedule(dslope, t0, t_end, price_num)?;
    let body = build_decay_buy_body();
    let mut rs = Vec::with_capacity(DECAY_BUY_STATE_SIZE + body.len());
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(dslope));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(t0));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(t_end));
    rs.push(0x20);
    rs.extend_from_slice(owner_kas_spk_hash);
    rs.push(0x20);
    rs.extend_from_slice(token_covenant_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(buyer_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_matcher_fee_bps));
    if cancel_pending == 0 {
        rs.push(0x00);
    } else {
        rs.push(0x51);
    }
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));
    rs.extend_from_slice(&body);
    debug_assert_eq!(rs.len(), DECAY_BUY_RS_EXPECTED_LEN);
    Ok(rs)
}

// (decay_buy sigscripts carry no prices — reuse the v18 buy builders
// `build_buy_fill_sigscript`, `build_buy_partial_fill_sigscript`,
// `build_buy_expire_sigscript` and `build_buy_cancel_sigscript` with the
// decay_buy RS; the engine sets tx.lock_time = L.)
