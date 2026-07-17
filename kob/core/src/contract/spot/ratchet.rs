use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::push_index;
use crate::contract::spot::order::{e_num, e_pick, e_roll, ops};

// ============================================================================
// `ratchet_oco` — OCO sell with a permissionless trailing-SL ratchet branch
// (kob/TIME_CONTRACTS_DESIGN.md §4 — CONDITIONAL: ships ONLY with the four
//  mandatory guards G1–G4; ADDITIVE beside the frozen v18 OCO)
// ============================================================================
//
// Semantics (§4.1): anyone who can point at a genuine same-token settle *in
// the same tx* at attested price P may tighten the SL one step:
//
//   trigger:   P ≥ (pnum_sl + rstep + rgap) / pden_sl     (cross-multiplied)
//   mutation:  pnum_sl := pnum_sl + rstep                 (additive, exact)
//
// Steps are additive on the SAME pden_sl (zero rounding drift). TP is NOT
// moved. One step per spend (the splice enforces `new == old + rstep`
// exactly). Direction is one-way by construction (rstep ≥ 1 enforced
// in-branch; no branch decreases pnum_sl).
//
// Mandatory guards (§4.5):
//   G1 rate limit:  `rwin CSV` — ≤ 1 ratchet per rwin real DAA per order.
//   G2 volume:      `vol ≥ mrv` (R10) + settle-magnitude re-check (R12).
//   G3 travel cap:  SL may never reach TP (R13e).
//   G4 sibling auth: covenant id via self-reference (R6), canonical-shape
//                    bytes (R7), positivity (R9) — weakening any reopens a
//                    cheap-fake lane.
//
// Disclosure rule: the ratchet schedule is declared over PRINTS (on-chain
// settles of this token), not a "true market price" — KOB has no market-price
// concept; anyone can be both sides of a print at the cost of fees.
//
// State (208B = 36 + v18 OCO 172), new fields PREPENDED:
//   [0x08][rstep 8B][0x08][rgap 8B][0x08][rwin 8B][0x08][mrv 8B]
//   ‖ v18 OCO 172B layout unchanged
// stack at body start (16): expiry(0) … otspkh(11) mrv(12) rwin(13) rgap(14)
//   rstep(15); selector at 16 (v18 OCO: 12).
// RS byte offsets (all v18 OCO offsets +36): pnum_sl VALUE = [97..105) (its
//   0x08 prefix at 96 is inside the fixed prefix), pden_sl = [106..114),
//   pnum_tp = [70..78), cpend at 198, expiry value [200..208).
//
// Selector 3 = RATCHET (free in the v18 OCO map: 0=CANCEL, 1=TP, 2=SL,
// 4=EXPIRE; OCO has no cancel-mark). sigOpCount = 0 (permissionless).
//
//   ratchet sigscript: [pushData(new_rs)][pushData(old_rs)][sii][Op3][pushData(RS)]
//
// new_rs FIRST is deliberate: its pushData opcode for a ~700B RS is 0x4d, so
// a ratchet sigscript can never begin with 0x01 and can never impersonate a
// canonical settle when *itself* named as a sibling (closes the
// nested-ratchet fake for every sii encoding).
//
// TP/SL/cancel/expire sigscripts are byte-identical in shape to v18's ⇒ the
// canonical attestation offsets of the sweep-eligible branches do not move,
// and an unchanged v18 buy sweeps this contract's TP and SL branches.
//
// BUILDER FREEZE RULE: the ratchet_oco price pairs are stored RAW (NOT
// gcd-normalized) — `rstep` is declared in the user's own `pden_sl` units and
// the splice/attestation compare raw bytes. The TP/SL fill sigscript builders
// below are correspondingly non-normalizing.

/// pnum_sl VALUE window inside the ratchet_oco RS: bytes [97..105).
pub const RATCHET_PNUM_SL_OFFSET: usize = 97;
/// End of the pnum_sl VALUE window (exclusive).
pub const RATCHET_PNUM_SL_END: usize = 105;

// Extra opcode bytes not present in `order::ops`.
const OP_NOT: u8 = 0x91;
const OP_MIN: u8 = 0xa3;
const OP_CAT: u8 = 0x7e;
const OP_SUBSTR: u8 = 0x7f;
const OP_SIZE: u8 = 0x82;

/// Push the P2SH SPK template prefix `[0x00,0x00,0xaa,0x20]` (version u16 LE
/// + OpBlake2b + 32B push prefix) — DCA D&R template (T8).
fn push_p2sh_prefix(b: &mut Vec<u8>) {
    b.push(0x04);
    b.extend_from_slice(&[0x00, 0x00, 0xaa, 0x20]);
}

/// Push the P2SH SPK template suffix `[0x87]` (OpEqual).
fn push_p2sh_suffix(b: &mut Vec<u8>) {
    b.push(0x01);
    b.push(0x87);
}

/// Build the ratchet_oco body.
///
/// Stack after state push (16 items):
///   expiry(0), cpend(1), mmfee(2), sspkh(3), ohash(4), mfill_sl(5),
///   pden_sl(6), pnum_sl(7), mfill_tp(8), pden_tp(9), pnum_tp(10),
///   otspkh(11), mrv(12), rwin(13), rgap(14), rstep(15); selector at 16.
///
/// Selectors: 0=CANCEL, 1=TP FILL, 2=SL FILL, 3=RATCHET, 4=EXPIRE.
pub fn build_ratchet_oco_body() -> Vec<u8> {
    use ops::*;
    let mut b: Vec<u8> = Vec::with_capacity(768);

    e_roll(&mut b, 16);
    b.push(DUP);
    e_num(&mut b, 4);
    b.push(EQUAL);
    b.push(IF); // selector == 4 -> EXPIRE
    {
        b.push(DROP);
        b.push(DUP);
        b.push(VERIFY); // expiry != 0
        b.push(CLTV);
        // stack: cpend(0), mmfee(1), sspkh(2), ohash(3), mfill_sl(4),
        //        pden_sl(5), pnum_sl(6), mfill_tp(7), pden_tp(8), pnum_tp(9),
        //        otspkh(10), mrv(11), rwin(12), rgap(13), rstep(14)
        b.push(TXINPUTINDEX);
        b.push(OP0);
        b.push(AUTHOUTPUTIDX); // r = auth_outputs[self][0]
        b.push(DUP);
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 12); // otspkh (depth 10, +2 for r + hash)
        b.push(EQUAL);
        b.push(VERIFY);
        b.push(DUP);
        b.push(OUTPUTCOVENANTID);
        b.push(TXINPUTINDEX);
        b.push(INPUTCOVENANTID);
        b.push(EQUAL);
        b.push(VERIFY);
        b.push(TXOUTPUTAMOUNT); // consumes r
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT);
        b.push(GTE);
        b.push(VERIFY); // full refund
        // 15 items: cpend..rstep
        for _ in 0..7 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        b.push(DUP);
        e_num(&mut b, 2);
        b.push(LT);
        b.push(IF); // selector < 2 (TP fill or cancel)
        {
            e_num(&mut b, 1);
            b.push(EQUAL);
            b.push(IF); // selector == 1 -> TP FILL
            {
                emit_ratchet_oco_fill(&mut b, true);
            }
            b.push(ELSE); // selector == 0 -> CANCEL
            {
                emit_ratchet_oco_cancel(&mut b);
            }
            b.push(ENDIF);
        }
        b.push(ELSE); // selector >= 2 (SL fill or RATCHET)
        {
            b.push(DUP);
            e_num(&mut b, 2);
            b.push(EQUAL);
            b.push(IF); // selector == 2 -> SL FILL
            {
                b.push(DROP);
                emit_ratchet_oco_fill(&mut b, false);
            }
            b.push(ELSE); // selector == 3 -> RATCHET (permissionless)
            {
                e_num(&mut b, 3);
                b.push(EQUAL);
                b.push(VERIFY);
                emit_ratchet(&mut b);
            }
            b.push(ENDIF);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);
    b.push(OP1);
    b
}

/// ratchet_oco fill (TP when `tp`, else SL). Sigscript:
/// `[0x01,koi][0x08 pnum][0x08 pden][Op1|Op2][pushData(RS)]` (raw pair).
///
/// Entry (selector consumed): expiry(0)..otspkh(11), mrv(12), rwin(13),
///   rgap(14), rstep(15), pden_att(16), pnum_att(17), koi(18)
fn emit_ratchet_oco_fill(b: &mut Vec<u8>, tp: bool) {
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
    // base(17): mmfee(0), sspkh(1), ohash(2), mfill_sl(3), pden_sl(4),
    //   pnum_sl(5), mfill_tp(6), pden_tp(7), pnum_tp(8), otspkh(9), mrv(10),
    //   rwin(11), rgap(12), rstep(13), pden_att(14), pnum_att(15), koi(16)
    let (pnum_d, pden_d, mfill_d) = if tp { (8usize, 7usize, 6usize) } else { (5, 4, 3) };
    // ATTESTATION: attested pair == the EXECUTING branch's state pair
    e_pick(b, 15); // pnum_att
    e_pick(b, pnum_d + 1);
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 14); // pden_att
    e_pick(b, pden_d + 1);
    b.push(EQUAL);
    b.push(VERIFY);
    // price: expected_kas = token_in * pnum / pden, >= mfill
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    e_pick(b, pnum_d + 1);
    b.push(MUL);
    e_pick(b, pden_d + 1);
    b.push(DIV);
    b.push(DUP);
    e_pick(b, mfill_d + 2);
    b.push(GTE);
    b.push(VERIFY);
    // KAS output >= expected_kas
    e_pick(b, 17); // koi (16 + 1)
    b.push(TXOUTPUTAMOUNT);
    b.push(SWAP);
    b.push(GTE);
    b.push(VERIFY);
    // F2: seller SPK hash
    e_pick(b, 16); // koi
    b.push(TXOUTPUTSPK);
    b.push(BLAKE2B);
    e_pick(b, 2); // sspkh (1 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    // F4: per-input token conservation (Fix-3)
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
    // cleanup: 17 items
    for _ in 0..8 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// ratchet_oco CANCEL (selector 0) — owner signature, never rate-limited.
/// Sigscript: `[sig][pk][Op0][pushData(RS)]`.
fn emit_ratchet_oco_cancel(b: &mut Vec<u8>) {
    use ops::*;
    // entry: expiry(0)..otspkh(11), mrv(12), rwin(13), rgap(14), rstep(15),
    //        pk(16), sig(17)
    b.push(TWO_DROP); // expiry + cpend
    // mmfee(0)..otspkh(9), mrv(10), rwin(11), rgap(12), rstep(13), pk(14),
    // sig(15)
    e_pick(b, 14); // pk
    b.push(BLAKE2B);
    e_pick(b, 3); // ohash (2 + 1)
    b.push(EQUAL);
    b.push(VERIFY);
    e_roll(b, 15); // sig
    e_roll(b, 15); // pk
    b.push(CHECKSIG);
    b.push(VERIFY);
    // 14 items
    for _ in 0..7 {
        b.push(TWO_DROP);
    }
}

/// The permissionless RATCHET branch (selector 3) — R1..R14 of §4.4.
///
/// Entry (selector consumed): expiry(0), cpend(1), mmfee(2), sspkh(3),
///   ohash(4), mfill_sl(5), pden_sl(6), pnum_sl(7), mfill_tp(8), pden_tp(9),
///   pnum_tp(10), otspkh(11), mrv(12), rwin(13), rgap(14), rstep(15),
///   sii(16), old_rs(17), new_rs(18)
fn emit_ratchet(b: &mut Vec<u8>) {
    use ops::*;
    // R1: rstep >= 1 (builder enforces it; in-branch check kept as defense
    // vs hand-rolled RS).
    e_pick(b, 15);
    b.push(OP1);
    b.push(GTE);
    b.push(VERIFY);
    // R2 (F5): cpend == 0 — a deploy-marked OCO can't ratchet.
    e_pick(b, 1);
    b.push(OP0);
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // R3: v18 expiry time-gate, stack-neutral (parity with fill family;
    // ratchet never EXTENDS life: expiry bytes are in the fixed suffix).
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
    // R4 (G1): rwin CSV — rate limit on real UTXO age (rwin >= 50 at build
    // also covers the exposure delay).
    e_pick(b, 13);
    b.push(CSV);
    // R5: sii != self.
    e_pick(b, 16);
    b.push(TXINPUTINDEX);
    b.push(NUMEQUAL);
    b.push(OP_NOT);
    b.push(VERIFY);
    // R6: same token — OpInputCovenantId(sii) == OpInputCovenantId(self).
    // (self-reference IS the tcid; a non-covenant input yields ZERO_HASH
    //  != own id => fail-closed)
    e_pick(b, 16);
    b.push(INPUTCOVENANTID);
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(EQUAL);
    b.push(VERIFY);
    // R7: canonical-shape guard on the sibling's sigscript: byte 0 == 0x01,
    // byte 2 == 0x08, byte 11 == 0x08 (token_unit 0x41, cancels 0x41/0x20,
    // expire 0x54, ratchet 0x4d are all killed by byte 0).
    e_pick(b, 16);
    b.push(OP0);
    b.push(OP1);
    b.push(TXINPUTSIGSUBSTR);
    b.push(OP1); // pushes [0x01]
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 16);
    e_num(b, 2);
    e_num(b, 3);
    b.push(TXINPUTSIGSUBSTR);
    e_num(b, 8); // pushes [0x08]
    b.push(EQUAL);
    b.push(VERIFY);
    e_pick(b, 16);
    e_num(b, 11);
    e_num(b, 12);
    b.push(TXINPUTSIGSUBSTR);
    e_num(b, 8);
    b.push(EQUAL);
    b.push(VERIFY);
    // R8: print read at the canonical offsets.
    e_pick(b, 16);
    e_num(b, 3);
    e_num(b, 11);
    b.push(TXINPUTSIGSUBSTR); // pnum_att
    e_pick(b, 17); // sii (16 + 1)
    e_num(b, 12);
    e_num(b, 20);
    b.push(TXINPUTSIGSUBSTR); // pden_att
    // stack: pden_att(0), pnum_att(1), base(19) below
    // R9: positivity guards — WITHOUT these, a hand-rolled sibling whose 8th
    // price byte has the high bit set makes pden_att negative as i64 => the
    // R11 cross-mul RHS goes negative => trigger passes vacuously. Mandatory.
    b.push(DUP);
    b.push(OP1);
    b.push(GTE);
    b.push(VERIFY); // pden_att >= 1
    e_pick(b, 1);
    b.push(OP1);
    b.push(GTE);
    b.push(VERIFY); // pnum_att >= 1
    // R10 (G2): vol = token_in(sii); if sigscript[20] == 0x08 (IOC/partial)
    // then vol = min(vol, fta at [21..29)); require vol >= mrv.
    e_pick(b, 18); // sii (16 + 2)
    b.push(TXINPUTAMOUNT); // vol
    e_pick(b, 19); // sii (16 + 3)
    e_num(b, 20);
    e_num(b, 21);
    b.push(TXINPUTSIGSUBSTR);
    e_num(b, 8);
    b.push(EQUAL);
    b.push(IF);
    {
        e_pick(b, 19); // sii (16 + 3)
        e_num(b, 21);
        e_num(b, 29);
        b.push(TXINPUTSIGSUBSTR); // fta
        b.push(OP_MIN); // vol = min(vol, fta)
    }
    b.push(ENDIF);
    b.push(DUP);
    e_pick(b, 16); // mrv (12 + 4)
    b.push(GTE);
    b.push(VERIFY); // vol >= mrv
    // stack: vol(0), pden_att(1), pnum_att(2), base(19) below
    // R11: trigger, cross-multiplied (overflow => checked error =>
    // fail-closed, T7): pnum_att*pden_sl >= (pnum_sl+rstep+rgap)*pden_att.
    e_pick(b, 2); // pnum_att
    e_pick(b, 10); // pden_sl (6 + 4)
    b.push(MUL); // lhs
    e_pick(b, 11); // pnum_sl (7 + 4)
    e_pick(b, 20); // rstep (15 + 5)
    b.push(ADD);
    e_pick(b, 19); // rgap (14 + 5)
    b.push(ADD); // pnum_sl + rstep + rgap
    e_pick(b, 3); // pden_att (1 + 2 for lhs + sum)
    b.push(MUL); // rhs
    b.push(GTE);
    b.push(VERIFY); // lhs >= rhs
    // R12 (G2): settle-magnitude re-check: koi = num(sigscript[1..2));
    // OpTxOutputAmount(koi) * pden_att >= vol * pnum_att. (koi bytes >= 0x80
    // read negative => OOB => fail-closed — such siblings cannot serve as
    // prints, documented.)
    e_pick(b, 19); // sii (16 + 3)
    b.push(OP1);
    e_num(b, 2);
    b.push(TXINPUTSIGSUBSTR); // koi byte
    b.push(TXOUTPUTAMOUNT); // amt
    e_pick(b, 2); // pden_att (1 + 1)
    b.push(MUL); // lhs = amt * pden_att
    e_pick(b, 1); // vol
    e_pick(b, 4); // pnum_att (2 + 2)
    b.push(MUL); // rhs = vol * pnum_att
    b.push(GTE);
    b.push(VERIFY); // lhs >= rhs
    // Drop the R8/R10 temporaries (vol, pden_att, pnum_att).
    b.push(DROP);
    b.push(TWO_DROP);
    // back to base(19): expiry(0)..rstep(15), sii(16), old_rs(17), new_rs(18)
    // R13 (DCA splice template, T8; window = pnum_sl value bytes [97..105)):
    // R13a: old_rs authenticity: P2SH(blake2b(old_rs)) == OpTxInputSpk(self).
    e_pick(b, 17); // old_rs
    b.push(BLAKE2B);
    push_p2sh_prefix(b);
    b.push(SWAP);
    b.push(OP_CAT);
    push_p2sh_suffix(b);
    b.push(OP_CAT);
    b.push(TXINPUTINDEX);
    b.push(TXINPUTSPK);
    b.push(EQUAL);
    b.push(VERIFY);
    // R13b: prefix [0..97) byte-equal.
    e_pick(b, 17); // old_rs
    b.push(OP0);
    e_num(b, 97);
    b.push(OP_SUBSTR);
    e_pick(b, 19); // new_rs (18 + 1)
    b.push(OP0);
    e_num(b, 97);
    b.push(OP_SUBSTR);
    b.push(EQUAL);
    b.push(VERIFY);
    // R13c: suffix [105..size) byte-equal (EQUAL on unequal lengths fails =>
    // new_rs length is pinned = old's; the 8B window has no interior push
    // prefix to re-check).
    e_pick(b, 17); // old_rs
    b.push(OP_SIZE);
    e_num(b, 105);
    b.push(SWAP);
    b.push(OP_SUBSTR);
    e_pick(b, 19); // new_rs (18 + 1)
    b.push(OP_SIZE);
    e_num(b, 105);
    b.push(SWAP);
    b.push(OP_SUBSTR);
    b.push(EQUAL);
    b.push(VERIFY);
    // R13d: field: num(new[97..105)) == num(old[97..105)) + rstep (NUMEQUAL —
    // T6: computed sum vs 8B window bytes).
    e_pick(b, 18); // new_rs
    e_num(b, 97);
    e_num(b, 105);
    b.push(OP_SUBSTR);
    e_pick(b, 18); // old_rs (17 + 1)
    e_num(b, 97);
    e_num(b, 105);
    b.push(OP_SUBSTR);
    e_pick(b, 17); // rstep (15 + 2)
    b.push(ADD);
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // R13e (G3): travel cap: (pnum_sl_old + rstep) * pden_tp < pnum_tp *
    // pden_sl — SL may never reach TP.
    e_pick(b, 7); // pnum_sl (state = old value)
    e_pick(b, 16); // rstep (15 + 1)
    b.push(ADD);
    e_pick(b, 10); // pden_tp (9 + 1)
    b.push(MUL); // lhs
    e_pick(b, 11); // pnum_tp (10 + 1)
    e_pick(b, 8); // pden_sl (6 + 2)
    b.push(MUL); // rhs
    b.push(LT);
    b.push(VERIFY); // lhs < rhs
    // R13f: continuation: ci = OpAuthOutputIdx(self, 0) (Fix-3);
    //   OpTxOutputSpk(ci) == P2SH(blake2b(new_rs));
    //   OpOutputCovenantId(ci) == OpInputCovenantId(self) (binding kept);
    //   OpTxOutputAmount(ci) >= OpTxInputAmount(self) (full escrow).
    b.push(TXINPUTINDEX);
    b.push(OP0);
    b.push(AUTHOUTPUTIDX); // ci
    b.push(DUP);
    b.push(TXOUTPUTSPK); // spk(0), ci(1)
    e_pick(b, 20); // new_rs (18 + 2)
    b.push(BLAKE2B);
    push_p2sh_prefix(b);
    b.push(SWAP);
    b.push(OP_CAT);
    push_p2sh_suffix(b);
    b.push(OP_CAT); // expected P2SH SPK
    b.push(EQUAL);
    b.push(VERIFY); // ci(0)
    b.push(DUP);
    b.push(OUTPUTCOVENANTID);
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(EQUAL);
    b.push(VERIFY); // ci(0)
    b.push(TXOUTPUTAMOUNT); // consumes ci
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(GTE);
    b.push(VERIFY); // out >= full escrow
    // R14: cleanup — 19 items (16 state + sii + old_rs + new_rs).
    for _ in 0..9 {
        b.push(TWO_DROP);
    }
    b.push(DROP);
}

/// Expected ratchet_oco body length (pinned at Stage-A freeze).
pub const RATCHET_OCO_BODY_EXPECTED_LEN: usize = 525;

/// ratchet_oco state size:
/// `[0x08 rstep][0x08 rgap][0x08 rwin][0x08 mrv]` + v18 OCO 172B.
pub const RATCHET_OCO_STATE_SIZE: usize = 36 + 172;

/// Expected ratchet_oco redeemScript length (208B state + body).
pub const RATCHET_OCO_RS_EXPECTED_LEN: usize =
    RATCHET_OCO_STATE_SIZE + RATCHET_OCO_BODY_EXPECTED_LEN;

/// Build the ratchet_oco redeemScript (208B state + body).
///
/// State: `[0x08][rstep][0x08][rgap][0x08][rwin][0x08][mrv]` then the v18
/// OCO 172B layout unchanged. Price pairs are stored RAW (NOT gcd-normalized):
/// `rstep` is declared in the user's `pden_sl` units and the splice compares
/// raw bytes.
///
/// Builder validation (§4.2): `rstep ≥ 1 ∧ 50 ≤ rwin ≤ 0xFFFF_FFFF ∧ mrv ≥ 1
/// ∧ (pnum_sl + rstep)×pden_tp < pnum_tp×pden_sl` (initial headroom sanity).
pub fn build_ratchet_oco_redeem_script(
    rstep: u64,
    rgap: u64,
    rwin: u64,
    mrv: u64,
    price_num_tp: u64,
    price_den_tp: u64,
    min_fill_tp: u64,
    price_num_sl: u64,
    price_den_sl: u64,
    min_fill_sl: u64,
    owner_hash: &[u8; 32],
    seller_spk_hash: &[u8; 32],
    owner_token_spk_hash: &[u8; 32],
    max_matcher_fee_bps: u64,
    cancel_pending: u8,
    expiry_daa: u64,
) -> crate::Result<Vec<u8>> {
    if price_num_tp == 0 || price_den_tp == 0 {
        return Err(crate::KobError::Contract("TP price must be > 0".into()));
    }
    if price_num_sl == 0 || price_den_sl == 0 {
        return Err(crate::KobError::Contract("SL price must be > 0".into()));
    }
    if min_fill_tp == 0 || min_fill_sl == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0".into()));
    }
    if cancel_pending > 1 {
        return Err(crate::KobError::Contract("cancel_pending must be 0 or 1".into()));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    if rstep == 0 {
        return Err(crate::KobError::Contract("rstep must be >= 1 (plain behavior = deploy the v18 OCO)".into()));
    }
    if rwin < 50 {
        return Err(crate::KobError::Contract("rwin must be >= 50 (covers the exposure delay)".into()));
    }
    if rwin > 0xFFFF_FFFF {
        return Err(crate::KobError::Contract("rwin must fit the CSV 32-bit mask".into()));
    }
    if mrv == 0 {
        return Err(crate::KobError::Contract("mrv must be >= 1".into()));
    }
    let lhs = price_num_sl
        .checked_add(rstep)
        .and_then(|s| s.checked_mul(price_den_tp))
        .ok_or_else(|| crate::KobError::Contract("(pnum_sl+rstep)*pden_tp overflows".into()))?;
    let rhs = price_num_tp
        .checked_mul(price_den_sl)
        .ok_or_else(|| crate::KobError::Contract("pnum_tp*pden_sl overflows".into()))?;
    if lhs >= rhs {
        return Err(crate::KobError::Contract("(pnum_sl+rstep)*pden_tp must be < pnum_tp*pden_sl (initial ratchet headroom)".into()));
    }

    let body = build_ratchet_oco_body();
    let mut rs = Vec::with_capacity(RATCHET_OCO_STATE_SIZE + body.len());
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rstep));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rgap));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rwin));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(mrv));
    rs.push(0x20);
    rs.extend_from_slice(owner_token_spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num_tp));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den_tp));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill_tp));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num_sl));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den_sl));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill_sl));
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
    debug_assert_eq!(rs.len(), RATCHET_OCO_RS_EXPECTED_LEN);
    Ok(rs)
}

/// Append the RAW (non-gcd-normalized) canonical attestation prefix.
fn push_raw_attested_prefix(ss: &mut Vec<u8>, kas_output_idx: u16, pnum: u64, pden: u64) {
    assert!(kas_output_idx <= 255, "koi must fit in 1 byte for the canonical convention");
    ss.push(0x01);
    ss.push(kas_output_idx as u8);
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pnum));
    ss.push(0x08);
    ss.extend_from_slice(&u64_le(pden));
}

/// Build ratchet_oco TP fill sigscript (canonical layout, RAW pair):
/// `[0x01,koi][0x08 pnum_tp][0x08 pden_tp][Op1][pushData(RS)]`.
pub fn build_ratchet_oco_tp_fill_sigscript(
    kas_output_idx: u16,
    price_num_tp: u64,
    price_den_tp: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(21 + redeem_script.len() + 3);
    push_raw_attested_prefix(&mut ss, kas_output_idx, price_num_tp, price_den_tp);
    ss.push(0x51); // Op1 (selector = TP fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build ratchet_oco SL fill sigscript (canonical layout, RAW pair — pass the
/// CURRENT `pnum_sl` = deploy value + k×rstep after k ratchets):
/// `[0x01,koi][0x08 pnum_sl][0x08 pden_sl][Op2][pushData(RS)]`.
pub fn build_ratchet_oco_sl_fill_sigscript(
    kas_output_idx: u16,
    price_num_sl: u64,
    price_den_sl: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(21 + redeem_script.len() + 3);
    push_raw_attested_prefix(&mut ss, kas_output_idx, price_num_sl, price_den_sl);
    ss.push(0x52); // Op2 (selector = SL fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the ratchet sigscript (selector 3, permissionless):
/// `[pushData(new_rs)][pushData(old_rs)][sii][Op3][pushData(RS)]`.
///
/// `new_rs` FIRST is deliberate (§4.3): its pushData opcode for a ~700B RS is
/// 0x4d, so this sigscript can never begin with 0x01 and can never
/// impersonate a canonical settle when itself named as a sibling.
pub fn build_ratchet_oco_ratchet_sigscript(
    new_rs: &[u8],
    old_rs: &[u8],
    sibling_input_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss =
        Vec::with_capacity(new_rs.len() + old_rs.len() + redeem_script.len() + 12);
    ss.extend_from_slice(&push_data(new_rs));
    ss.extend_from_slice(&push_data(old_rs));
    push_index(&mut ss, sibling_input_idx);
    ss.push(0x53); // Op3 (selector = ratchet)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Derive the ratchet continuation RS: `old_rs` with the pnum_sl value window
/// [97..105) incremented by the RS's own `rstep` (bytes [1..9)). This is the
/// exact splice R13 enforces; the scanner derives watch addresses with it
/// (`new_rs(k) = old_rs with pnum_sl += k×rstep`, bounded by G3).
pub fn derive_ratchet_continuation_rs(old_rs: &[u8]) -> crate::Result<Vec<u8>> {
    if old_rs.len() != RATCHET_OCO_RS_EXPECTED_LEN || old_rs[0] != 0x08 || old_rs[96] != 0x08 {
        return Err(crate::KobError::Contract("not a ratchet_oco redeemScript".into()));
    }
    let rstep = u64::from_le_bytes(old_rs[1..9].try_into().expect("8B window"));
    let pnum_sl = u64::from_le_bytes(
        old_rs[RATCHET_PNUM_SL_OFFSET..RATCHET_PNUM_SL_END].try_into().expect("8B window"),
    );
    let new_pnum_sl = pnum_sl
        .checked_add(rstep)
        .ok_or_else(|| crate::KobError::Contract("pnum_sl + rstep overflows".into()))?;
    let mut new_rs = old_rs.to_vec();
    new_rs[RATCHET_PNUM_SL_OFFSET..RATCHET_PNUM_SL_END]
        .copy_from_slice(&u64_le(new_pnum_sl));
    Ok(new_rs)
}

// (ratchet_oco cancel/expire sigscripts are byte-identical in shape to the
// v18 OCO's — reuse `build_oco_sell_cancel_sigscript` and
// `build_oco_sell_expire_sigscript` with the ratchet RS.)
