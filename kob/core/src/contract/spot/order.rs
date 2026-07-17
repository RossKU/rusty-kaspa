use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::{gcd, push_index};

// ============================================================================
// Shared bytecode emission table + MAX_N (used by the v18 spot builders in
// this file, oco.rs, swap.rs and bracket.rs).
// ============================================================================

/// Maximum sells swept into one buy fill (compile-time slot count).
///
/// Justification (tx mass budget): each swept sell adds ~520B of input
/// (its canonical fill sigscript: `[0x01,koi][0x08 pnum][0x08 pden][sel]`
/// `[pushData(RS 515B)]`) + 2 outputs (seller KAS + buyer tokens). An N=8
/// sweep tx is well inside the post-Toccata block-fit bounds;
/// script-size/op-count limits (1e6) are nowhere near binding. A crossing
/// book with more than MAX_N same-token sells against one buy settles
/// MAX_N-at-a-time across sequential txs.
pub const BUY_ORDER_MAX_N: usize = 8;

// Opcode bytes (named for readability of the programmatic builders).
pub(crate) mod ops {
    pub const OP0: u8 = 0x00;
    pub const OP1: u8 = 0x51;
    pub const DUP: u8 = 0x76;
    pub const DROP: u8 = 0x75;
    pub const TWO_DROP: u8 = 0x6d;
    pub const SWAP: u8 = 0x7c;
    pub const PICK: u8 = 0x79;
    pub const ROLL: u8 = 0x7a;
    pub const IF: u8 = 0x63;
    pub const NOTIF: u8 = 0x64;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const VERIFY: u8 = 0x69;
    pub const EQUAL: u8 = 0x87;
    pub const LT: u8 = 0x9f;
    pub const NUMEQUAL: u8 = 0x9c;
    pub const ADD: u8 = 0x93;
    pub const SUB: u8 = 0x94;
    pub const MUL: u8 = 0x95;
    pub const DIV: u8 = 0x96;
    pub const GT: u8 = 0xa0;
    pub const LTE: u8 = 0xa1;
    pub const GTE: u8 = 0xa2;
    pub const BLAKE2B: u8 = 0xaa;
    pub const CHECKSIGVERIFY: u8 = 0xad;
    pub const CLTV: u8 = 0xb0;
    pub const CSV: u8 = 0xb1;
    pub const TXLOCKTIME: u8 = 0xb5;
    pub const TXINPUTINDEX: u8 = 0xb9;
    pub const TXINPUTSIGSUBSTR: u8 = 0xbc;
    pub const TXINPUTAMOUNT: u8 = 0xbe;
    pub const TXOUTPUTAMOUNT: u8 = 0xc2;
    pub const TXOUTPUTSPK: u8 = 0xc3;
    pub const AUTHOUTPUTIDX: u8 = 0xcc;
    pub const INPUTCOVENANTID: u8 = 0xcf;
    // Added for the v18 unified-spot generation (unused by v17 bodies).
    pub const TXINPUTCOUNT: u8 = 0xb3;
    pub const TXINPUTSPK: u8 = 0xbf;
    pub const CHECKSIG: u8 = 0xac;
    pub const OUTPUTCOVENANTID: u8 = 0xd5;
    // Added for the v18 bracket (entry-type dispatch on an 8-byte state push).
    pub const BIN2NUM: u8 = 0xce;
}

// Emit `OpPick(depth)`.
pub(crate) fn e_pick(b: &mut Vec<u8>, depth: usize) {
    push_index(b, depth as u16);
    b.push(ops::PICK);
}
// Emit `OpRoll(depth)`.
pub(crate) fn e_roll(b: &mut Vec<u8>, depth: usize) {
    push_index(b, depth as u16);
    b.push(ops::ROLL);
}
// Emit a numeric literal push.
pub(crate) fn e_num(b: &mut Vec<u8>, n: u16) {
    push_index(b, n);
}

// ============================================================================
// V18 UNIFIED SPOT CONTRACTS — buy + sell (see kob/V18_DESIGN.md)
// ============================================================================
//
// v18 unifies the whole spot matrix into one contract generation:
//   - Buy: v17 N:M fill/IOC semantics carried unchanged, plus a NEW Op2
//     partial-fill path (item C) with a byte-exact self-SPK residual, a
//     spent-based floor/cap, and a self-instance uniqueness guard.
//   - Sell: fill-family branches verify a sigscript price attestation
//     against the state price, and the partial F4 is upgraded from the
//     count-only `OpCovOutCount >= 2` to the per-input Fix-3 binding.
//
// CANONICAL PRICE ATTESTATION (all sweep-eligible sell-side fill sigscripts —
// plain sell fill, sell IOC, sell partial, OCO TP, OCO SL):
//
//   [0x01, koi]  [0x08, pnum 8LE]  [0x08, pden 8LE]  [branch extras]  [sel]  [RS]
//    bytes 0-1    2, 3..11          11, 12..20
//
// pnum always at sigscript [3..11), pden at [12..20); `koi` always a forced
// 2-byte push. Buys read the counterparty price ONLY at these offsets via
// `OpTxInputScriptSigSubstr` on the covenant-authenticated `tii`.
//
// DEVIATION from the frozen spec text: V18_DESIGN.md places branch extras
// (fta etc.) AFTER the RS push. The engine takes the P2SH redeem script from
// the TOP of the sigscript-produced stack (`execute_inner`, txscript lib.rs:
// `saved_stack` + `dstack.pop()`), so the RS MUST be the final push — extras
// after it would be popped as the "redeem script" and fail the P2SH hash.
// Extras therefore sit between the attested prices and the selector, which
// preserves the invariant the spec actually needs: the [3..11)/[12..20)
// prefix offsets never move across branches.

/// Build the v18 buy body (deterministic given `BUY_ORDER_MAX_N`).
///
/// State (178B): the v17 145B layout preceded by the owner KAS seat
/// (`okspkh` = blake2b of the owner's raw P2PK SPK, the EXPIRE refund
/// endpoint — `bspkh` is the token_unit delivery seat post-D2 and must not
/// receive plain KAS). Stack after the state pushes:
///   expiry(0), cpend(1), mmfee_bps(2), bspkh(3), ohash(4), mfill(5),
///   pden(6), pnum(7), tcid(8), okspkh(9), <sigscript items at depth 10+>
/// with the selector at depth 10 in every sigscript form.
///
/// Selector dispatch: 0=CANCEL, 1=FILL, 2=PARTIAL-FILL, 3=CANCEL-MARK,
/// 4=EXPIRE, 5=IOC.
pub fn build_buy_body() -> Vec<u8> {
    use ops::*;
    const MAX_N: usize = BUY_ORDER_MAX_N;
    let mut b: Vec<u8> = Vec::with_capacity(2048);

    // ===== DISPATCH: bring selector (depth 10) to top, branch on its value =====
    e_num(&mut b, 10);
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
        b.push(CLTV); // consumes expiry; requires expiry <= tx.lockTime
        b.push(OP0);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 9); // okspkh (depth 8 + 1 for the hash)
        b.push(EQUAL);
        b.push(VERIFY); // output[0] pays the OWNER KAS seat, not bspkh
        b.push(OP0);
        b.push(TXOUTPUTAMOUNT);
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY); // output[0].value >= input.value (full refund)
        // 9 items: cpend..okspkh
        for _ in 0..4 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 0);
        b.push(NUMEQUAL);
        b.push(IF); // selector == 0 -> CANCEL
        {
            b.push(DROP);
            emit_cancel_body(&mut b);
        }
        b.push(ELSE);
        {
            b.push(DUP);
            e_num(&mut b, 3);
            b.push(NUMEQUAL);
            b.push(IF); // selector == 3 -> CANCEL-MARK
            {
                b.push(DROP);
                emit_cancel_body(&mut b);
            }
            b.push(ELSE);
            {
                b.push(DUP);
                e_num(&mut b, 2);
                b.push(NUMEQUAL);
                b.push(IF); // selector == 2 -> PARTIAL-FILL (new in v18)
                {
                    b.push(DROP);
                    emit_partial_body(&mut b, MAX_N);
                }
                b.push(ELSE);
                {
                    // selector is 1 (fill) or 5 (IOC fill); selector on top.
                    emit_fill_body(&mut b, MAX_N);
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

/// v18 CANCEL / CANCEL-MARK owner-signature spend (okspkh-aware layout).
/// Entry (selector dropped): expiry(0), cpend(1), mmfee(2), bspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), tcid(8), okspkh(9), sig(10),
///   pk(11)
pub(crate) fn emit_cancel_body(b: &mut Vec<u8>) {
    use ops::*;
    e_pick(b, 11);
    b.push(BLAKE2B); // blake2b(pk)
    e_pick(b, 5); // ohash (depth 4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 10); // sig -> top
    e_roll(b, 11); // pk -> top
    b.push(CHECKSIGVERIFY);
    // 10 items: expiry..okspkh
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
}

/// v18 FILL (selector 1) / IOC FILL (selector 5): v17 `emit_fill_body`
/// semantics carried unchanged, EXCEPT the counterparty price reads move to
/// the canonical attestation offsets [3..11) / [12..20) (v17 read the price
/// out of the RS push at [7..15) / [16..24) — the layout the old fixed-offset
/// sell sigscripts had).
///
/// Entry (selector on top): selector(0), expiry(1), cpend(2), mmfee_bps(3),
///   bspkh(4), ohash(5), mfill(6), pden(7), pnum(8), tcid(9), okspkh(10),
///   N(11), tii_MAX_N(12), tii_k(12 + MAX_N - k), tii_1(11 + MAX_N)
pub(crate) fn emit_fill_body(b: &mut Vec<u8>, max_n: usize) {
    use ops::*;

    // A) ioc_flag = (selector == 5), replacing selector at depth 0.
    e_num(b, 5);
    b.push(NUMEQUAL);
    // B0: ioc_flag(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), N(11),
    //     tii_MAX_N(12), tii_k(12 + max_n - k)

    // B) F5: cpend == 0.
    e_pick(b, 2);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(VERIFY);

    // C) time gate on expiry (copy; leaves stack unchanged).
    e_pick(b, 1);
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
        e_pick(b, 12); // N (depth 11 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let d = 12 + max_n - k; // tii_k depth at B0
            e_pick(b, d); // tii_k
            e_pick(b, d); // tii_{k+1} (was d-1, +1 after the tii_k push)
            b.push(LT);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // E) floor_value = ioc_flag ? mfill : expected, consuming ioc_flag.
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in(0), ioc_flag(1)
    e_pick(b, 8); // pden (depth 7 + 1)
    b.push(DIV);
    e_pick(b, 9); // pnum (depth 8 + 1)
    b.push(MUL); // expected(0), ioc_flag(1)
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
    // B1: floor_value(0), expiry(1), ... tcid(9), okspkh(10), N(11),
    //     tii_MAX_N(12), ...

    // F) token_sum = 0.
    b.push(OP0);
    // B2: token_sum(0), floor_value(1), expiry(2), cpend(3), mmfee(4),
    //     bspkh(5), ohash(6), mfill(7), pden(8), pnum(9), tcid(10),
    //     okspkh(11), N(12), tii_MAX_N(13), tii_k(13 + max_n - k)

    // G) PASS 1: sum delivered tokens + per-term binding checks.
    for k in 1..=max_n {
        e_num(b, k as u16); // guard: k <= N
        e_pick(b, 13); // N (depth 12 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 13 + max_n - k; // tii_k depth at B2
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
    b.push(SWAP); // floor_value(0), token_sum(1)
    b.push(GTE); // pops [token_sum, floor_value] -> token_sum >= floor_value
    b.push(VERIFY);
    // B3: expiry(0), cpend(1), mmfee(2), bspkh(3), ohash(4), mfill(5),
    //     pden(6), pnum(7), tcid(8), okspkh(9), N(10), tii_MAX_N(11),
    //     tii_k(11 + max_n - k)

    // I) fair_sum = 0.
    b.push(OP0);
    // B4: fair_sum(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), N(11),
    //     tii_MAX_N(12), tii_k(12 + max_n - k)

    // PASS 2: sum fair_kas at each sell's own ATTESTED price, read at the
    // canonical offsets: pnum = sigscript[3..11), pden = sigscript[12..20).
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 12); // N (depth 11 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 12 + max_n - k; // tii_k depth at B4
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
            // fair_kas = tokens / sell_pden * sell_pnum, consuming temps.
            // stack: fair_sum, tokens, sell_pnum, sell_pden(top)
            e_num(b, 2);
            b.push(ROLL); // tokens -> top
            b.push(SWAP); // sell_pden on top, tokens below
            b.push(DIV); // tokens / sell_pden
            b.push(SWAP); // sell_pnum on top
            b.push(MUL); // -> fair_kas
            b.push(ADD); // fair_sum += fair_kas
        }
        b.push(ENDIF);
    }

    // J) aggregate surplus cap.
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in(0), fair_sum(1)
    b.push(DUP);
    e_num(b, 2);
    b.push(ROLL); // fair_sum -> top: fair_sum(0), kas_in(1), kas_in(2)
    b.push(SUB); // surplus = kas_in - fair_sum: surplus(0), kas_in(1)
    b.push(SWAP); // kas_in(0), surplus(1)
    e_num(b, 10000);
    b.push(DIV); // kas_in/10000(0), surplus(1)
    e_pick(b, 4); // mmfee_bps (depth 2, +2 for surplus + kas_in/10000)
    b.push(MUL); // max_surplus(0), surplus(1)
    b.push(LTE); // pops [surplus, max_surplus] -> surplus <= max_surplus
    b.push(VERIFY);
    // leftover: 10 state (incl. okspkh) + N + max_n tii
    let leftover = 11 + max_n;
    for _ in 0..(leftover / 2) {
        b.push(TWO_DROP);
    }
    if leftover % 2 == 1 {
        b.push(DROP);
    }
}

/// v18 PARTIAL-FILL (selector 2, item C): incremental buy consumption.
///
/// Sigscript: `[tii_1]...[tii_MAX_N][N][ri][Op2][pushData(RS)]`.
///
/// Semantics:
///   - Residual continuation: `OpTxOutputSpk(ri) == OpTxInputSpk(self)`
///     byte-exact (same RS => same 145B state carried; the remaining size
///     lives in the UTXO amount), `residual = OpTxOutputAmount(ri) >= 1`
///     (residual == 0 must use selector 1/5 — branch mutual exclusion).
///     The residual output carries NO covenant binding (plain KAS P2SH).
///   - Accounting on the spent portion only: `spent = kas_in - residual`
///     (with `spent >= 0` so a matcher cannot feed negative values into the
///     divisions); floor `token_sum >= spent/pden*pnum` AND
///     `token_sum >= mfill` (per-event, blocks dust-grind); cap
///     `(spent - fair_sum) <= spent/10000*mmfee_bps` (proportional =>
///     splitting one fill into k partials cannot increase total extraction:
///     floor(a/10000) + floor(b/10000) <= floor((a+b)/10000)).
///   - Same N:M sweep machinery as fill: per-term `OpAuthOutputIdx(tii,0)`
///     binding, covenant-id check, buyer-SPK check, strict-increasing tii.
///   - Self-instance uniqueness guard: exactly ONE tx input carries this
///     UTXO's SPK (unrolled i=0..15, each gated by `i < OpTxInputCount`;
///     `OpTxInputCount <= 16` so no input escapes the scan). Blocks two
///     identical-RS buy UTXOs sharing one residual output — buys carry no
///     covenant id, so the Fix-3 auth binding is unavailable to them.
///   - F5 `cpend == 0` enforced (no partial on cancel-pending).
///
/// Entry (selector dropped): expiry(0), cpend(1), mmfee(2), bspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), tcid(8), okspkh(9), ri(10),
///   N(11), tii_MAX_N(12), tii_k(12 + MAX_N - k), tii_1(11 + MAX_N)
pub(crate) fn emit_partial_body(b: &mut Vec<u8>, max_n: usize) {
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
    // (Without this, one sell's auth[0] could be double-counted into
    // token_sum/fair_sum — same anti-double-count guard as the fill path;
    // N/tii depths at entry are identical to the fill path's B0.)
    for k in 1..max_n {
        e_num(b, (k + 1) as u16);
        e_pick(b, 12); // N (depth 11 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let d = 12 + max_n - k;
            e_pick(b, d);
            e_pick(b, d);
            b.push(LT);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // P5) self-instance uniqueness guard (stack-neutral).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK); // own_spk
    b.push(OP0); // count = 0
    for i in 0..16u16 {
        e_num(b, i);
        b.push(TXINPUTCOUNT);
        b.push(LT); // i < input_count?  (OpTxInputSpk errors on OOB index,
        b.push(IF); //                    so every read must be gated)
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
    e_pick(b, 10); // ri
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY); // byte-exact self-SPK (same RS => same state)
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT); // kas_in
    e_pick(b, 11); // ri (depth 10 + 1)
    b.push(TXOUTPUTAMOUNT); // residual(0), kas_in(1)
    b.push(DUP);
    b.push(OP1);
    b.push(GTE);
    b.push(VERIFY); // residual >= 1
    b.push(SUB); // spent = kas_in - residual
    b.push(DUP);
    b.push(OP0);
    b.push(GTE);
    b.push(VERIFY); // spent >= 0 (no negative arithmetic downstream)
    // B1: spent(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), ri(11), N(12),
    //     tii_MAX_N(13), tii_k(13 + max_n - k)

    // P7) floor_value = spent / pden * pnum (v17 division order).
    b.push(DUP);
    e_pick(b, 8); // pden (depth 7 + 1)
    b.push(DIV);
    e_pick(b, 9); // pnum (depth 8 + 1)
    b.push(MUL);
    // B2: floor(0), spent(1), expiry(2), cpend(3), mmfee(4), bspkh(5),
    //     ohash(6), mfill(7), pden(8), pnum(9), tcid(10), okspkh(11),
    //     ri(12), N(13), tii_MAX_N(14)

    // P8) token_sum = 0.
    b.push(OP0);
    // B3: token_sum(0), floor(1), spent(2), expiry(3), cpend(4), mmfee(5),
    //     bspkh(6), ohash(7), mfill(8), pden(9), pnum(10), tcid(11),
    //     okspkh(12), ri(13), N(14), tii_MAX_N(15), tii_k(15 + max_n - k)

    // P9) PASS 1: sum delivered tokens + per-term binding checks.
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 15); // N (depth 14 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 15 + max_n - k; // tii_k depth at B3
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX); // toi = auth_outputs[tii][0]
            e_pick(b, tii + 1); // tii_k (+1 for toi)
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
            b.push(TXOUTPUTAMOUNT); // tokens_i (consumes toi)
            b.push(ADD);
        }
        b.push(ENDIF);
    }

    // P10) floors: token_sum >= mfill (per event), token_sum >= floor.
    b.push(DUP);
    e_pick(b, 9); // mfill (depth 8 + 1)
    b.push(GTE);
    b.push(VERIFY); // token_sum >= mfill
    b.push(SWAP); // floor(0), token_sum(1)
    b.push(GTE);
    b.push(VERIFY); // token_sum >= floor
    // B4: spent(0), expiry(1), cpend(2), mmfee(3), bspkh(4), ohash(5),
    //     mfill(6), pden(7), pnum(8), tcid(9), okspkh(10), ri(11), N(12),
    //     tii_MAX_N(13)

    // P11) fair_sum = 0.
    b.push(OP0);
    // B5: fair_sum(0), spent(1), expiry(2), cpend(3), mmfee(4), bspkh(5),
    //     ohash(6), mfill(7), pden(8), pnum(9), tcid(10), okspkh(11),
    //     ri(12), N(13), tii_MAX_N(14), tii_k(14 + max_n - k)

    // P12) PASS 2: fair_sum at each sell's attested price ([3..11)/[12..20)).
    for k in 1..=max_n {
        e_num(b, k as u16);
        e_pick(b, 14); // N (depth 13 + 1)
        b.push(LTE);
        b.push(IF);
        {
            let tii = 14 + max_n - k; // tii_k depth at B5
            e_pick(b, tii);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX);
            b.push(TXOUTPUTAMOUNT); // tokens_i
            e_pick(b, tii + 1);
            e_num(b, 3);
            e_num(b, 11);
            b.push(TXINPUTSIGSUBSTR); // sell_pnum
            e_pick(b, tii + 2);
            e_num(b, 12);
            e_num(b, 20);
            b.push(TXINPUTSIGSUBSTR); // sell_pden
            e_num(b, 2);
            b.push(ROLL); // tokens -> top
            b.push(SWAP);
            b.push(DIV);
            b.push(SWAP);
            b.push(MUL); // fair_kas = tokens / sell_pden * sell_pnum
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
    b.push(SWAP); // spent(0), surplus(1)
    e_num(b, 10000);
    b.push(DIV);
    e_pick(b, 5); // mmfee_bps (depth 3, +2 for surplus + quotient)
    b.push(MUL); // max_surplus
    b.push(LTE);
    b.push(VERIFY); // surplus <= max_surplus
    // leftover: spent + 10 state (incl. okspkh) + ri + N + max_n tii
    let leftover = 13 + max_n;
    for _ in 0..(leftover / 2) {
        b.push(TWO_DROP);
    }
    if leftover % 2 == 1 {
        b.push(DROP);
    }
}

/// Expected v18 buy body length (deterministic for `BUY_ORDER_MAX_N`=8).
pub const BUY_ORDER_BODY_EXPECTED_LEN: usize = 1542;

/// v18 buy state size: the v17 145B layout preceded by `[0x20][okspkh 32B]`.
pub const BUY_ORDER_STATE_SIZE: usize = 178;

/// Expected v18 buy redeemScript length (178B state + body).
pub const BUY_ORDER_RS_EXPECTED_LEN: usize =
    BUY_ORDER_STATE_SIZE + BUY_ORDER_BODY_EXPECTED_LEN;

/// Build the v18 buy_order redeemScript (178B state + v18 body).
///
/// State (178B):
///   `[0x20][okspkh 32B]` — owner KAS seat: blake2b of the owner's raw P2PK
///   SPK; the EXPIRE branch refunds here (plain KAS must not land on the
///   token_unit `bspkh` seat) — then the v17 145B layout unchanged:
///   `[0x20][tcid][0x08][pnum][0x08][pden][0x08][mfill][0x20][ohash]`
///   `[0x20][bspkh][0x08][mmfee_bps][cpend][0x08][expiry]`.
/// `max_matcher_fee_bps` is BPS.
pub fn build_buy_redeem_script(
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
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let body = build_buy_body();
    let mut rs = Vec::with_capacity(BUY_ORDER_STATE_SIZE + body.len());
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
    debug_assert_eq!(rs.len(), BUY_ORDER_RS_EXPECTED_LEN);
    Ok(rs)
}

/// Build a v18 buy fill sigscript for an N-sell sweep (GTC or IOC).
///
/// Layout: `[tii_1]...[tii_MAX_N][N][selector][pushData(RS)]` — always MAX_N
/// tii pushes (unused slots padded with 0, never read since guarded by k<=N).
pub fn build_buy_fill_sigscript(
    sell_input_indices: &[u16],
    ioc: bool,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(!sell_input_indices.is_empty(), "at least one sell required");
    assert!(
        sell_input_indices.len() <= BUY_ORDER_MAX_N,
        "at most MAX_N sells per sweep"
    );
    let n = sell_input_indices.len();
    let mut ss = Vec::with_capacity(BUY_ORDER_MAX_N + 4 + redeem_script.len() + 3);
    for i in 0..BUY_ORDER_MAX_N {
        let v = if i < n { sell_input_indices[i] } else { 0 };
        push_index(&mut ss, v);
    }
    push_index(&mut ss, n as u16);
    ss.push(if ioc { 0x55 } else { 0x51 });
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v18 buy PARTIAL-FILL sigscript.
///
/// Layout: `[tii_1]...[tii_MAX_N][N][ri][Op2][pushData(RS)]` where `ri` is the
/// residual output index (self-SPK continuation carrying the unspent KAS).
pub fn build_buy_partial_fill_sigscript(
    sell_input_indices: &[u16],
    residual_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    assert!(!sell_input_indices.is_empty(), "at least one sell required");
    assert!(
        sell_input_indices.len() <= BUY_ORDER_MAX_N,
        "at most MAX_N sells per sweep"
    );
    let n = sell_input_indices.len();
    let mut ss = Vec::with_capacity(BUY_ORDER_MAX_N + 6 + redeem_script.len() + 3);
    for i in 0..BUY_ORDER_MAX_N {
        let v = if i < n { sell_input_indices[i] } else { 0 };
        push_index(&mut ss, v);
    }
    push_index(&mut ss, n as u16);
    push_index(&mut ss, residual_output_idx);
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v18 buy expire sigscript: `[Op4][pushData(RS)]`.
pub fn build_buy_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54); // Op4
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build a v18 buy cancel/cancel-mark sigscript: `[pk][sig][selector][RS]`.
/// selector = Op0 (cancel) or Op3 (cancel-mark). Same layout as v17.
pub fn build_buy_cancel_sigscript(
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    mark: bool,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL
    let mut ss = Vec::with_capacity(2 + 32 + 66 + redeem_script.len() + 6);
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(if mark { 0x53 } else { 0x00 }); // Op3 / Op0
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// ============================================================================
// V18 SELL — 112B state unchanged; fill-family price attestation + Fix-3 F4
// ============================================================================

/// Build the v18 sell body.
///
/// Stack after state push (the v14 layout preceded by the owner token seat
/// `otspkh` = blake2b of the owner's token_unit P2SH SPK):
///   expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill(5), pden(6),
///   pnum(7), otspkh(8), <sigscript items at depth 9+> with the selector at
///   depth 9 in every sigscript form.
///
/// Changes vs the v14 sell body:
///   - FILL / IOC / PARTIAL verify the sigscript-attested (pnum, pden)
///     against the state price (the canonical attestation the buy reads at
///     fixed offsets [3..11)/[12..20)).
///   - PARTIAL F4 upgraded from count-only (`OpCovOutCount >= 2`) to Fix-3:
///     this input's auth[0] must be a self-SPK residual worth
///     `>= token_in - fta` (same per-input binding the IOC path already had).
///   - EXPIRE refunds the token escrow to `otspkh` as a covenant-bound
///     token_unit via the Fix-3 per-input binding (auth[0] of self), instead
///     of the v14 raw-P2PK `sspkh` refund that stripped the binding.
///   - mmfee is BPS uniformly (the v14 absolute-sompi semantics die with v14);
///     the sell body itself never reads mmfee — the cap lives on the buy side.
pub fn build_sell_body() -> Vec<u8> {
    use ops::*;
    let mut b: Vec<u8> = Vec::with_capacity(512);

    // ===== DISPATCH: selector (depth 9) to top =====
    e_roll(&mut b, 9);
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(EQUAL);
    b.push(IF); // selector == 4 -> EXPIRE
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0 (GTC guard)
        b.push(CLTV);
        // Fix-3 refund: this input's auth[0] must be a covenant-bound token
        // output on the OWNER TOKEN SEAT worth the full escrow.
        // stack: cpend(0), mmfee(1), sspkh(2), ohash(3), mfill(4), pden(5),
        //        pnum(6), otspkh(7)
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
        // 8 items: cpend..otspkh
        for _ in 0..4 {
            b.push(TWO_DROP);
        }
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
                emit_sell_fill(&mut b);
            }
            b.push(ELSE); // selector == 0 -> CANCEL
            {
                emit_sell_cancel(&mut b, false);
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
                emit_sell_ioc(&mut b);
            }
            b.push(ELSE);
            {
                e_num(&mut b, 2);
                b.push(EQUAL);
                b.push(IF); // selector == 2 -> PARTIAL FILL
                {
                    emit_sell_partial(&mut b);
                }
                b.push(ELSE); // selector == 3 -> CANCEL-MARK
                {
                    emit_sell_cancel(&mut b, true);
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

/// v18 sell FILL (selector 1). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][Op1][pushData(RS)]`.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), pden_att(9),
///   pnum_att(10), koi(11)
fn emit_sell_fill(b: &mut Vec<u8>) {
    use ops::*;
    // time gate
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
    // base(10): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //           otspkh(6), pden_att(7), pnum_att(8), koi(9)
    // ATTESTATION: attested pair == state pair
    e_pick(b, 8); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 7); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // price: expected_kas = token_in * pnum / pden, >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 5); // mfill (3 + 2)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= expected_kas (PARAMETERIZED: koi)
    e_pick(b, 10); // koi (9 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 9); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: per-input token conservation (Fix-3, unchanged from v14 fill)
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
    // cleanup: 10 items
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
}

/// v18 sell IOC FILL (selector 5). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][Op5][pushData(RS)]`.
///
/// Entry (stale selector dropped): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), fta(9), pden_att(10),
///   pnum_att(11), koi(12)
fn emit_sell_ioc(b: &mut Vec<u8>) {
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
    // base(11): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //           otspkh(6), fta(7), pden_att(8), pnum_att(9), koi(10)
    // ATTESTATION
    e_pick(b, 9); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 8); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // fill_kas = fta * pnum / pden, >= mfill
    e_pick(b, 7); // fta
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 5); // mfill (3 + 2)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= fill_kas
    e_pick(b, 11); // koi (10 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 10); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: residual conservation — auth[0] is a self-SPK continuation worth
    // >= token_in - fta (unchanged from the v14 IOC path).
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
    e_pick(b, 9); // fta (7 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 11 items
    for _ in 0..5 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// v18 sell PARTIAL FILL (selector 2). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][ri][Op2][pushData(RS)]`.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill(5), pden(6), pnum(7), otspkh(8), ri(9), fta(10),
///   pden_att(11), pnum_att(12), koi(13)
fn emit_sell_partial(b: &mut Vec<u8>) {
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
    // base(12): mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //           otspkh(6), ri(7), fta(8), pden_att(9), pnum_att(10), koi(11)
    // ATTESTATION
    e_pick(b, 10); // pnum_att
    e_pick(b, 6); // pnum (5 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 9); // pden_att
    e_pick(b, 5); // pden (4 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // fill_kas = fta * pnum / pden, >= mfill (keeps an fta copy on stack)
    e_pick(b, 8); // fta
    b.push(DUP);
    e_pick(b, 7); // pnum (5 + 2)
    b.push(MUL);
    e_pick(b, 6); // pden (4 + 2)
    b.push(DIV);
    b.push(DUP);
    e_pick(b, 6); // mfill (3 + 3)
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= fill_kas
    e_pick(b, 13); // koi (11 + 2)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // partial guard: token_in > fta
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 1); // fta copy
    b.push(GT);
    b.push(VERIFY);
    // residual output SPK == own SPK (D&R continuation)
    e_pick(b, 8); // ri (7 + 1)
    b.push(TXOUTPUTSPK);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    // residual output value >= token_in - fta (consumes the fta copy)
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_roll(b, 1);
    b.push(SUB);
    e_pick(b, 8); // ri (7 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // residual-fill floor: (token_in - fta) * pnum / pden >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, 9); // fta (8 + 1)
    b.push(SUB);
    e_pick(b, 6); // pnum (5 + 1)
    b.push(MUL);
    e_pick(b, 5); // pden (4 + 1)
    b.push(DIV);
    e_pick(b, 4); // mfill (3 + 1)
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash on koi
    e_pick(b, 11); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4 (Fix-3, upgraded from count-only `OpCovOutCount >= 2`): this input's
    // auth[0] must be a self-SPK residual token output worth >= token_in - fta.
    // The old shared count let another same-token input's outputs satisfy the
    // check; per-input binding closes that (same shape as the IOC F4).
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
    e_pick(b, 10); // fta (8 + 2)
    b.push(SUB);
    b.push(GTE);
    b.push(VERIFY);
    // cleanup: 12 items
    for _ in 0..6 {
        b.push(TWO_DROP);
    }
}

/// v18 sell CANCEL (selector 0) / CANCEL-MARK (selector 3) — owner signature.
/// Sigscript: `[sig][pk][Op0 or Op3][pushData(RS)]` (same shapes as v14).
fn emit_sell_cancel(b: &mut Vec<u8>, mark: bool) {
    use ops::*;
    if mark {
        b.push(DROP); // expiry
        b.push(OP0);
        b.push(EQUAL);
        b.push(VERIFY); // cpend == 0 (can't re-mark)
    } else {
        b.push(TWO_DROP); // expiry + cpend
    }
    // stack: mmfee(0), sspkh(1), ohash(2), mfill(3), pden(4), pnum(5),
    //        otspkh(6), pk(7), sig(8)
    e_pick(b, 7); // pk
    b.push(BLAKE2B);
    e_pick(b, 3); // ohash (2 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 8); // sig
    e_roll(b, 8); // pk
    b.push(CHECKSIG);
    b.push(VERIFY);
    // 7 items
    for _ in 0..3 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// Expected v18 sell body length.
pub const SELL_ORDER_BODY_EXPECTED_LEN: usize = 370;

/// v18 sell state size: the v14 112B layout preceded by `[0x20][otspkh 32B]`.
pub const SELL_ORDER_STATE_SIZE: usize = 145;

/// Expected v18 sell redeemScript length (145B state + body).
pub const SELL_ORDER_RS_EXPECTED_LEN: usize =
    SELL_ORDER_STATE_SIZE + SELL_ORDER_BODY_EXPECTED_LEN;

/// Build the v18 sell_order redeemScript (145B state + v18 body).
///
/// State (145B):
///   `[0x20][otspkh 32B]` — owner token seat: blake2b of the owner's
///   token_unit P2SH SPK (`compute_token_unit_spk_hash`); the EXPIRE branch
///   refunds the token escrow here as a covenant-bound token_unit — then
///   the v14 112B layout unchanged. `max_matcher_fee_bps` is BPS.
pub fn build_sell_redeem_script(
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
    let g = gcd(price_num, price_den);
    let price_num = if g > 0 { price_num / g } else { price_num };
    let price_den = if g > 0 { price_den / g } else { price_den };
    let body = build_sell_body();
    let mut rs = Vec::with_capacity(SELL_ORDER_STATE_SIZE + body.len());
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
    debug_assert_eq!(rs.len(), SELL_ORDER_RS_EXPECTED_LEN);
    Ok(rs)
}

/// Append the canonical v18 attestation prefix to a sigscript buffer:
/// `[0x01, koi][0x08, pnum 8LE][0x08, pden 8LE]` (pnum at [3..11), pden at
/// [12..20)). Prices are gcd-normalized so the attested bytes always equal
/// the state bytes the RS builder wrote.
fn push_attested_prefix(ss: &mut Vec<u8>, kas_output_idx: u16, price_num: u64, price_den: u64) {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for the canonical convention");
    let g = gcd(price_num, price_den);
    let pnum = if g > 0 { price_num / g } else { price_num };
    let pden = if g > 0 { price_den / g } else { price_den };
    ss.push(0x01); // forced 2-byte koi push
    ss.push(kas_output_idx as u8);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pnum));
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pden));
}

/// Build v18 sell fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum][0x08 pden][Op1][pushData(RS)]`.
pub fn build_sell_fill_sigscript(
    kas_output_idx: u16,
    price_num: u64,
    price_den: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(21 + redeem_script.len() + 3);
    push_attested_prefix(&mut ss, kas_output_idx, price_num, price_den);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell IOC fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][Op5][pushData(RS)]`.
pub fn build_sell_ioc_fill_sigscript(
    kas_output_idx: u16,
    price_num: u64,
    price_den: u64,
    fill_token_amount: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(30 + redeem_script.len() + 3);
    push_attested_prefix(&mut ss, kas_output_idx, price_num, price_den);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(fill_token_amount));
    ss.push(0x55); // Op5 (selector = IOC fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell partial fill sigscript (canonical attestation layout).
///
/// Layout: `[0x01,koi][0x08 pnum][0x08 pden][0x08 fta][ri][Op2][pushData(RS)]`.
pub fn build_sell_partial_fill_sigscript(
    kas_output_idx: u16,
    price_num: u64,
    price_den: u64,
    fill_token_amount: u64,
    residual_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(33 + redeem_script.len() + 3);
    push_attested_prefix(&mut ss, kas_output_idx, price_num, price_den);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(fill_token_amount));
    push_index(&mut ss, residual_output_idx);
    ss.push(0x52); // Op2 (selector = partial fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell expire sigscript: `[Op4][pushData(RS)]`.
pub fn build_sell_expire_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build v18 sell cancel-mark sigscript: `[sig][pk][Op3][pushData(RS)]`.
/// (Plain cancel reuses `build_sell_cancel_sigscript` — identical shape,
/// selector Op0.)
pub fn build_sell_cancel_mark_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);
    let mut ss = Vec::with_capacity(102 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x53); // Op3 (selector = cancel-mark)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
