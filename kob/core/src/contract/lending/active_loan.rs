use crate::primitives::{push_data, u64_le};

use super::DAA_PER_YEAR;

/// Convert integer 0..=16 to OpN opcode (local helper).
fn opn(n: u8) -> u8 {
    match n {
        0 => 0x00,
        1..=16 => 0x50 + n,
        _ => panic!("OpN index out of range: {} (must be 0..=16)", n),
    }
}

// active_loan — Active loan after matching (10 paths, selector dispatch)
//
// State (14 items, 222B):
//   [0x20][insurer_spk_hash 32B]    d13 — insurer's SPK hash (all-zero = uninsured)
//   [0x20][lender_spk_hash 32B]     d12 — lender's SPK hash
//   [0x20][borrower_spk_hash 32B]   d11 — borrower's SPK hash
//   [0x08][principal 8B]            d10 — loan principal (sompi)
//   [0x08][rate_num 8B]             d9  — annual rate numerator
//   [0x08][rate_den 8B]             d8  — annual rate denominator
//   [0x08][start_daa 8B]            d7  — loan start DAA score
//   [0x08][expiry_daa 8B]           d6  — repayment deadline DAA score
//   [0x20][collateral_cov_id 32B]   d5  — collateral token covenant ID
//   [0x08][rate_mode 8B]            d4  — 0=Fixed, 1=Variable
//   [0x08][rate_floor_num 8B]       d3  — variable rate floor (lender protection)
//   [0x08][rate_cap_num 8B]         d2  — variable rate cap (borrower protection)
//   [0x08][grace_daa 8B]            d1  — grace period after expiry for default claim
//   [0x08][liq_threshold 8B]        d0  — liquidation threshold (e.g. 15000=150%)
//
// State size: 4*(1+32) + 10*(1+8) = 132 + 90 = 222B
//
// Dispatch: selector-based (10 paths).
//   Selector is an OpN pushed before RS in sigscript.
//   Body uses Op14 OpRoll to bring selector to top (depth 14 = 14 state items).
//
// Paths:
//   sel=1:  Liquidate        (permissionless, LTV check enforced on-chain)
//   sel=2:  Default claim    (lender sig, CLTV after expiry + grace)
//                             + insurance branch: if insurer_spk_hash != 0,
//                               verify output[ioi].spk.blake2b == insurer_spk_hash
//   sel=3:  Repay            (borrower sig, pay lender principal+interest)
//   sel=4:  Partial Repay    (borrower sig, continuation with reduced principal)
//   sel=5:  Top-up Collateral(borrower sig, self-continuation, value up)
//   sel=6:  Extend           (2-of-2 lender+borrower, settle interest, new expiry)
//   sel=7:  Rebalance        (permissionless, variable rate only, update rate)
//   sel=8:  (REMOVED — was Redemption, permissionless collateral theft vector)
//   sel=9:  Partial Liquidation (permissionless, fractional liquidation with LTV check)
//   sel=10: Loan Transfer    (lender sig, transfer position to new lender)

/// active_loan state size: 4*(1+32) + 10*(1+8) = 132 + 90 = 222 bytes.
/// (4 hashes: insurer, lender, borrower, collateral_cov_id; 10 u64s)
pub const ACTIVE_LOAN_STATE_SIZE: usize = 4 * 33 + 10 * 9; // = 222

/// active_loan body bytecode (10-path selector dispatch).
///
/// State: [lender_spk_hash 32B][borrower_spk_hash 32B]
///        [principal 8B][rate_num 8B][rate_den 8B]
///        [start_daa 8B][expiry_daa 8B]
///        [collateral_cov_id 32B][rate_mode 8B]
///        [rate_floor_num 8B][rate_cap_num 8B][grace_daa 8B][liq_threshold 8B]
///        = 189B (13 items)
///
/// Dispatch: selector-based. Each sigscript contains [args...][OpN sel][pushData(RS)].
///   Op13 OpRoll brings selector from depth 13 (beneath 13 state items) to top.
///   Nested OpIf/OpElse branches to the correct path.
///
/// sel=1  Liquidate: permissionless. LTV check enforced on-chain.
///   Verifies not expired, lender gets >= principal, collateral*10000 < principal*liq_threshold.
///
/// sel=2  Default claim: lender sig + CLTV (expiry_daa + grace_daa).
///   After expiry+grace, lender takes all collateral.
///
/// sel=3  Repay: borrower sig. Lender output >= principal + interest.
///   Remaining collateral returns to borrower (TX construction).
///
/// sel=4  Partial Repay: borrower sig. Repays portion, continuation UTXO.
///   Lender gets repay_amount, continuation SPK == input SPK.
///
/// sel=5  Top-up: borrower sig. Self-continuation, output value > input value.
///
/// sel=6  Extend: 2-of-2 sigs. Settles accrued interest, resets start_daa, new expiry.
///
/// sel=7  Rebalance: permissionless, variable rate only. Updates rate from co-input.
///   Settles accrued interest, resets start_daa. rate_mode must be 1.
///
/// sel=8  REMOVED. Was Redemption (permissionless collateral theft vector).
///        sel=8 now rejected by PATH 7's Op7 OpEqual OpVerify.
///
/// sel=9  Partial Liquidation: permissionless. Fractional liquidation with LTV check.
///
/// sel=10 Loan Transfer: lender sig. New lender_spk_hash via continuation.
pub const ACTIVE_LOAN_BODY: &[u8] = &[
    // DISPATCH (6B)
    // stack (after RS state push): liq_th(0) grace(1) rcap(2) rfl(3) rm(4) ccid(5) exp(6)
    //   start(7) rd(8) rn(9) princ(10) borr(11) lend(12) insurer(13) [sel at d14 from sigscript]
    0x5e, 0x7a,                   // Op14 OpRoll -> sel to top                          [2B]
    // stack: sel(0) liq_th(1) grace(2) rcap(3) rfl(4) rm(5) ccid(6) exp(7) start(8) rd(9) rn(10)
    //        princ(11) borr(12) lend(13) insurer(14) [15 items]

    // --- Branch: sel < 4 ? (paths 1,2,3) vs sel >= 4 (paths 4-10) ---
    0x76,                         // OpDup                                              [1B]
    0x54, 0x9f,                   // Op4 OpLessThan (sel < 4?)                          [2B]
    0x63,                         // OpIf (sel in {1,2,3})                               [1B]

    // BRANCH A: sel < 4 (paths 1, 2, 3)
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) insurer(14) [15 items]

    // --- Sub-branch: sel < 2 ? (path 1) vs sel >= 2 (paths 2,3) ---
    0x76,                         // OpDup                                              [1B]
    0x52, 0x9f,                   // Op2 OpLessThan (sel < 2?)                          [2B]
    0x63,                         // OpIf (sel == 1 -> liquidate)                        [1B]

    // PATH 1: LIQUIDATE (56B)
    // Sigscript: [pi_opN][loi_opN][boi_opN][liqi_opN][Op1][pushData(RS)]
    // stack: sel(0) liq_th(1) grace(2) rcap(3) rfl(4) rm(5) ccid(6) exp(7) start(8) rd(9) rn(10)
    //        princ(11) borr(12) lend(13) insurer(14) liqi(15) boi(16) loi(17) pi(18) [19 items]
    0x51, 0x87, 0x69,             // Op1 OpEqual OpVerify (sel==1; sel consumed)         [3B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) liqi(14) boi(15) loi(16) pi(17) [18 items]
    //
    // Check not expired (liquidation is for pre-expiry only)
    0xb5,                         // OpTxLockTime -> lockTime                            [1B]
    // stack: lt(0) liq_th(1) ... pi(18) [19]
    0x57, 0x79,                   // Op7 OpPick -> exp (d7=exp after lt pushed)          [2B]
    // stack: exp_c(0) lt(1) liq_th(2) ... [20]
    0xa0, 0x69,                   // OpGreaterThan OpVerify (exp > lt)                   [2B]
    // stack: liq_th(0) grace(1) ... pi(17) [18]
    //
    // LTV CHECK: collateral_value * 10000 < principal * liq_threshold
    // collateral_value = input[this].value
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> collateral_value  [2B]
    // stack: coll(0) liq_th(1) grace(2) ... pi(18) [19]
    0x02, 0x10, 0x27,             // push 10000                                          [3B]
    0x95,                         // OpMul (coll * 10000)                                [1B]
    // stack: coll_scaled(0) liq_th(1) grace(2) ... pi(18) [19]
    0x5b, 0x79,                   // Op11 OpPick -> princ (d11: coll_scaled=0,liq_th=1,...princ=11) [2B]
    // stack: princ_c(0) coll_scaled(1) liq_th(2) ... [20]
    0x52, 0x79,                   // Op2 OpPick -> liq_th (d2=liq_th)                   [2B]
    // stack: lt_c(0) princ_c(1) coll_scaled(2) liq_th(3) ... [21]
    0x95,                         // OpMul (princ * liq_th)                              [1B]
    // stack: princ_threshold(0) coll_scaled(1) liq_th(2) ... [20]
    0x7c,                         // OpSwap                                              [1B]
    // stack: coll_scaled(0) princ_threshold(1) liq_th(2) ... [20]
    0x9f, 0x69,                   // OpLessThan OpVerify (coll_scaled < princ_threshold) [2B]
    // stack: liq_th(0) grace(1) ... pi(17) [18]
    //
    // Verify lender output: output[loi].spk.blake2b == lender_spk_hash
    0x60, 0x79, 0xc3, 0xaa,       // Op16 OpPick(loi) OpTxOutputSpk OpBlake2b           [4B]
    // stack: h(0) liq_th(1) ... pi(18) [19]
    0x5d, 0x79,                   // Op13 OpPick -> lend (d13=lend)                     [2B]
    // stack: lend_c(0) h(1) ... [20]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) grace(1) ... pi(17) [18]
    //
    // Verify lender gets at least principal
    0x60, 0x79, 0xc2,             // Op16 OpPick(loi) OpTxOutputAmount                  [3B]
    // stack: loi_val(0) liq_th(1) ... [19]
    0x5b, 0x79,                   // Op11 OpPick -> princ (d11: loi_val=0,...princ=11)   [2B]
    // stack: princ_c(0) loi_val(1) ... [20]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify (loi_val >= princ)           [3B]
    // stack: liq_th(0) grace(1) ... pi(17) [18]
    //
    // Cleanup: 14 state + 4 sigscript indices = 18 items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75,             // OpDrop x3 (18 total)                                [3B]

    // ELSE: sel >= 2 in {2,3}
    0x67,                         // OpElse                                               [1B]
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) [+ sigscript items]

    // --- Sub-branch: sel < 3 ? (path 2) vs sel == 3 (path 3) ---
    0x76,                         // OpDup                                              [1B]
    0x53, 0x9f,                   // Op3 OpLessThan (sel < 3?)                          [2B]
    0x63,                         // OpIf (sel == 2 -> default claim)                    [1B]

    // PATH 2: DEFAULT CLAIM (36B)
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][Op2][pushData(RS)]
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) insurer(14) pk(15) sig(16) [17 items]
    0x52, 0x87, 0x69,             // Op2 OpEqual OpVerify (sel==2; sel consumed)         [3B]
    // stack: liq_th(0) grace(1) rcap(2) rfl(3) rm(4) ccid(5) exp(6) start(7) rd(8) rn(9)
    //        princ(10) borr(11) lend(12) insurer(13) pk(14) sig(15) [16 items]
    //
    // CLTV: expiry_daa + grace_daa <= lockTime
    0x56, 0x79,                   // Op6 OpPick -> exp (d6=exp)                          [2B]
    // stack: exp_c(0) liq_th(1) ... sig(16) [17]
    0x52, 0x79,                   // Op2 OpPick -> grace_c (d2 after exp_c pushed: grace at 2) [2B]
    // stack: grace_c(0) exp_c(1) ... [18]
    0x93,                         // OpAdd -> exp + grace = deadline                     [1B]
    // stack: deadline(0) liq_th(1) ... sig(16) [17]
    0x76, 0x69,                   // OpDup OpVerify (deadline != 0)                      [2B]
    0xb0,                         // OpCheckLockTimeVerify (lockTime >= deadline)        [1B]
    0x75,                         // OpDrop (CLTV doesn't pop; drop deadline)            [1B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) pk(14) sig(15) [16]
    //
    // Lender auth: Blake2b(pk) == lender_spk_hash
    0x5e, 0x79,                   // Op14 OpPick -> pk copy (d14=pk)                    [2B]
    // stack: pk_c(0) liq_th(1) ... sig(16) [17]
    0xaa,                         // OpBlake2b                                           [1B]
    0x5d, 0x79,                   // Op13 OpPick -> lend (d13=lend)                     [2B]
    // stack: lend_c(0) h(1) liq_th(2) ... [18]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) pk(14) sig(15) [16]
    //
    // Sig verify
    0x5f, 0x7a,                   // Op15 OpRoll -> sig to top                          [2B]
    // stack: sig(0) liq_th(1) ... insurer(14) pk(15) [16]
    0x5f, 0x7a,                   // Op15 OpRoll -> pk to top                           [2B]
    // stack: pk(0) sig(1) liq_th(2) ... insurer(15) [16]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) [14]
    //
    // Insurance branch: if insurer_hash != 0, verify insurer output
    // Uninsured sigscript: [pushData(sig)][pushData(pk)][Op2][pushData(RS)]
    //   -> after checksigverify: liq_th(0)...insurer(13) [14 items]
    // Insured sigscript:   [ioi_opN][pushData(sig)][pushData(pk)][Op2][pushData(RS)]
    //   -> after checksigverify: liq_th(0)...insurer(13) ioi(14) [15 items]
    0x5d, 0x79,                   // Op13 OpPick -> insurer_hash copy                   [2B]
    0x00,                         // Op0                                                 [1B]
    0x87,                         // OpEqual                                              [1B]
    0x64,                         // OpNotIf (insurer != 0 -> insured path)              [1B]
    // stack (insured): liq_th(0)...insurer(13) ioi(14) [15 items]
    0x5e, 0x79, 0xc3, 0xaa,       // Op14 OpPick(ioi) OpTxOutputSpk OpBlake2b           [4B]
    // stack: h(0) liq_th(1)...insurer(14) ioi(15) [16]
    0x5e, 0x79,                   // Op14 OpPick -> insurer (d14=insurer)                [2B]
    // stack: ins_c(0) h(1) liq_th(2)...insurer(15) ioi(16) [17]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0)...insurer(13) ioi(14) [15]
    0x5e, 0x7a,                   // Op14 OpRoll -> ioi to top                           [2B]
    0x75,                         // OpDrop (drop ioi)                                    [1B]
    // stack: liq_th(0)...insurer(13) [14]
    0x68,                         // OpEndIf                                              [1B]
    // Both paths: 14 items
    //
    // Cleanup: 14 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (14 total)                                [4B]

    // PATH 3: REPAY (35B)
    0x67,                         // OpElse (sel == 3: repay)                             [1B]
    // Sigscript: [loi_opN][pushData(sig 65B)][pushData(pk 32B)][Op3][pushData(RS)]
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) insurer(14) pk(15) sig(16) loi(17) [18 items]
    0x53, 0x87, 0x69,             // Op3 OpEqual OpVerify (sel==3; sel consumed)         [3B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) pk(14) sig(15) loi(16) [17]
    //
    // Borrower auth: Blake2b(pk) == borrower_spk_hash
    0x5e, 0x79,                   // Op14 OpPick -> pk copy (d14=pk)                    [2B]
    // stack: pk_c(0) liq_th(1) ... loi(17) [18]
    0xaa,                         // OpBlake2b                                           [1B]
    0x5c, 0x79,                   // Op12 OpPick -> borr (d12=borr)                     [2B]
    // stack: borr_c(0) h(1) liq_th(2) ... [19]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) pk(14) sig(15) loi(16) [17]
    //
    // Sig verify
    0x5f, 0x7a,                   // Op15 OpRoll -> sig to top                          [2B]
    0x5f, 0x7a,                   // Op15 OpRoll -> pk to top                           [2B]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) loi(14) [15]
    //
    // Verify lender output: spk check
    0x5e, 0x79, 0xc3, 0xaa,       // Op14 OpPick(loi) OpTxOutputSpk OpBlake2b           [4B]
    0x5d, 0x79,                   // Op13 OpPick -> lend (d13=lend)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) loi(14) [15]
    //
    // Cleanup: 14 state + 1 loi = 15 items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5 (15 total)                               [5B]

    0x68,                         // OpEndIf (path 2 vs 3)                               [1B]
    0x68,                         // OpEndIf (path 1 vs {2,3})                           [1B]

    // BRANCH B: sel >= 4 (paths 4-10)
    0x67,                         // OpElse (sel >= 4)                                   [1B]
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) [+ sigscript items]

    // --- Sub-branch: sel < 7 ? (paths 4,5,6) vs sel >= 7 (paths 7-10) ---
    0x76,                         // OpDup                                              [1B]
    0x57, 0x9f,                   // Op7 OpLessThan (sel < 7?)                          [2B]
    0x63,                         // OpIf (sel in {4,5,6})                               [1B]

    // BRANCH B1: sel in {4,5,6}
    // --- Sub-branch: sel < 5 ? (path 4) vs sel >= 5 (paths 5,6) ---
    0x76,                         // OpDup                                              [1B]
    0x55, 0x9f,                   // Op5 OpLessThan (sel < 5?)                          [2B]
    0x63,                         // OpIf (sel == 4 -> partial repay)                    [1B]

    // PATH 4: PARTIAL REPAY (D&R pattern)
    // Sigscript: [pushData(new_rs)][pushData(old_rs)][loi_opN][pushData(repay_amount 8B)]
    //            [pushData(sig 65B)][pushData(pk 32B)][Op4][pushData(RS)]
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) insurer(14) pk(15) sig(16) repay_amt(17) loi(18) old_rs(19) new_rs(20) [21]
    0x54, 0x87, 0x69,             // Op4 OpEqual OpVerify (sel==4; sel consumed)         [3B]
    // stack: liq_th(0) ... lend(12) insurer(13) pk(14) sig(15) repay_amt(16) loi(17) old_rs(18) new_rs(19) [20]
    //
    // Borrower auth
    0x5e, 0x79,                   // Op14 OpPick -> pk copy (d14=pk)                    [2B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x5c, 0x79,                   // Op12 OpPick -> borr (d12=borr)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    //
    // Sig verify
    0x5f, 0x7a,                   // Op15 OpRoll -> sig                                  [2B]
    0x5f, 0x7a,                   // Op15 OpRoll -> pk                                   [2B]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: liq_th(0) ... lend(12) insurer(13) repay_amt(14) loi(15) old_rs(16) new_rs(17) [18]
    //
    // Verify repay_amount > 0
    0x5e, 0x79,                   // Op14 OpPick -> repay_amt copy (d14)                [2B]
    0x00, 0xa0, 0x69,             // Op0 OpGreaterThan OpVerify (repay_amt > 0)         [3B]
    //
    // Verify lender gets repay_amount: output[loi].value >= repay_amt
    0x5f, 0x79, 0xc2,             // Op15 OpPick(loi) OpTxOutputAmount                  [3B]
    0x5f, 0x79,                   // Op15 OpPick -> repay_amt (d15=repay_amt)           [2B]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify (loi_val >= ra)              [3B]
    // stack: liq_th(0) ... repay_amt(14) loi(15) old_rs(16) new_rs(17) [18]
    //
    // --- D&R Step 1: Verify old_rs authenticity ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy (d16)                   [2B]
    0xaa,                         // OpBlake2b -> rs_hash                                [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat -> [0xaa,0x20]||hash                          [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected P2SH SPK                          [1B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                        [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18] (back to base)
    //
    // --- D&R Step 2: Verify unchanged prefix [0..100) ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy                         [2B]
    0x00,                         // Op0 (begin=0)                                      [1B]
    0x01, 0x64,                   // push 100 (size)                                    [2B]
    0x7f,                         // OpSubstr -> old_prefix                              [1B]
    0x01, 0x12, 0x79,             // push(18) OpPick -> new_rs copy (d17+1=18)          [3B]
    0x00,                         // Op0                                                [1B]
    0x01, 0x64,                   // push 100                                           [2B]
    0x7f,                         // OpSubstr -> new_prefix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // --- D&R Step 3: Verify unchanged suffix [108..end) ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy                         [2B]
    0x82,                         // OpSize -> len (no pop)                              [1B]
    0x01, 0x6c,                   // push 108                                           [2B]
    0x94,                         // OpSub -> suffix_len                                 [1B]
    0x01, 0x6c,                   // push 108 (begin)                                   [2B]
    0x7c,                         // OpSwap -> suffix_len, 108, old_rs                   [1B]
    0x7f,                         // OpSubstr -> old_suffix                              [1B]
    0x01, 0x12, 0x79,             // push(18) OpPick -> new_rs copy                     [3B]
    0x82,                         // OpSize                                              [1B]
    0x01, 0x6c,                   // push 108                                           [2B]
    0x94,                         // OpSub                                               [1B]
    0x01, 0x6c,                   // push 108                                           [2B]
    0x7c,                         // OpSwap                                              [1B]
    0x7f,                         // OpSubstr -> new_suffix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // --- D&R Step 4: Transition (new_principal = old_principal - repay_amount, > 0) ---
    0x01, 0x11, 0x79,             // push(17) OpPick -> new_rs copy (d17)               [3B]
    0x01, 0x64,                   // push 100 (begin)                                   [2B]
    0x58,                         // Op8 (size=8)                                       [1B]
    0x7f,                         // OpSubstr -> new_principal                           [1B]
    0x76,                         // OpDup                                               [1B]
    0x00, 0xa0, 0x69,             // Op0 OpGreaterThan OpVerify (new_p > 0)             [3B]
    // stack: new_p(0) ... old_rs(17) new_rs(18) [19]
    0x01, 0x12, 0x79,             // push(18) OpPick -> old_rs copy (d18)               [3B]
    0x01, 0x64,                   // push 100                                           [2B]
    0x58,                         // Op8                                                [1B]
    0x7f,                         // OpSubstr -> old_principal                           [1B]
    // stack: old_p(0) new_p(1) ... repay_amt(16) ... [20]
    0x60, 0x79,                   // Op16 OpPick -> repay_amt (d16)                     [2B]
    0x94,                         // OpSub -> old_p - repay_amt                          [1B]
    0x9c, 0x69,                   // OpNumEqual OpVerify                                 [2B]
    // stack: [18]
    //
    // --- D&R Step 5: Verify output SPK ---
    0x01, 0x11, 0x79,             // push(17) OpPick -> new_rs copy (d17)               [3B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat                                               [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected output SPK                        [1B]
    0x00, 0xc3,                   // Op0 OpTxOutputSpk                                  [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // Cleanup: 14 state + 2 sigscript + 2 D&R = 18
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75,             // OpDrop x3 (18 total)                                [3B]

    // ELSE: sel >= 5 in {5,6}
    0x67,                         // OpElse                                               [1B]

    // --- Sub-branch: sel < 6 ? (path 5) vs sel == 6 (path 6) ---
    0x76,                         // OpDup                                              [1B]
    0x56, 0x9f,                   // Op6 OpLessThan (sel < 6?)                          [2B]
    0x63,                         // OpIf (sel == 5 -> top-up)                           [1B]

    // PATH 5: TOP-UP COLLATERAL (27B)
    // Sigscript: [ci_opN][pushData(sig 65B)][pushData(pk 32B)][Op5][pushData(RS)]
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) insurer(14) pk(15) sig(16) ci(17) [18 items]
    0x55, 0x87, 0x69,             // Op5 OpEqual OpVerify (sel==5; sel consumed)         [3B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) pk(14) sig(15) ci(16) [17]
    //
    // Borrower auth
    0x5e, 0x79,                   // Op14 OpPick -> pk copy (d14=pk)                    [2B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x5c, 0x79,                   // Op12 OpPick -> borr (d12=borr)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    //
    // Sig verify
    0x5f, 0x7a,                   // Op15 OpRoll -> sig                                  [2B]
    0x5f, 0x7a,                   // Op15 OpRoll -> pk                                   [2B]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) ci(14) [15]
    //
    // Self-continuation: output[ci].spk == input.spk
    0x5e, 0x79, 0xc3,             // Op14 OpPick(ci) OpTxOutputSpk                      [3B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                         [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) ci(14) [15]
    //
    // Cleanup: 14 state + 1 ci = 15
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5 (15 total)                               [5B]

    // PATH 6: EXTEND (D&R pattern)
    0x67,                         // OpElse (sel == 6: extend)                            [1B]
    // Sigscript: [pushData(new_rs)][pushData(old_rs)][loi_opN][pushData(new_expiry 8B)]
    //            [pushData(lender_sig 65B)][pushData(lender_pk 32B)]
    //            [pushData(borrower_sig 65B)][pushData(borrower_pk 32B)][Op6][pushData(RS)]
    // stack: sel(0) liq_th(1) ... lend(13) insurer(14) bpk(15) bsig(16) lpk(17) lsig(18) new_exp(19) loi(20) old_rs(21) new_rs(22) [23]
    0x56, 0x87, 0x69,             // Op6 OpEqual OpVerify (sel==6; sel consumed)         [3B]
    // stack: liq_th(0) ... lend(12) insurer(13) bpk(14) bsig(15) lpk(16) lsig(17) new_exp(18) loi(19) old_rs(20) new_rs(21) [22]
    //
    // Borrower auth
    0x5e, 0x79,                   // Op14 OpPick -> bpk copy (d14=bpk)                  [2B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x5c, 0x79,                   // Op12 OpPick -> borr (d12=borr)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    //
    // Borrower sig verify
    0x5f, 0x7a,                   // Op15 OpRoll -> bsig                                 [2B]
    0x5f, 0x7a,                   // Op15 OpRoll -> bpk                                  [2B]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: liq_th(0) ... lend(12) insurer(13) lpk(14) lsig(15) new_exp(16) loi(17) old_rs(18) new_rs(19) [20]
    //
    // Lender auth
    0x5e, 0x79,                   // Op14 OpPick -> lpk copy (d14=lpk)                  [2B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x5d, 0x79,                   // Op13 OpPick -> lend (d13=lend)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    //
    // Lender sig verify
    0x5f, 0x7a,                   // Op15 OpRoll -> lsig                                 [2B]
    0x5f, 0x7a,                   // Op15 OpRoll -> lpk                                  [2B]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: liq_th(0) ... lend(12) insurer(13) new_exp(14) loi(15) old_rs(16) new_rs(17) [18]
    //
    // --- D&R Step 1: Verify old_rs authenticity ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy (d16)                   [2B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat                                               [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected P2SH SPK                          [1B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                        [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // --- D&R Step 2: Verify unchanged prefix [0..127) ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy                         [2B]
    0x00,                         // Op0 (begin=0)                                      [1B]
    0x01, 0x7f,                   // push 127 (size)                                    [2B]
    0x7f,                         // OpSubstr -> old_prefix                              [1B]
    0x01, 0x12, 0x79,             // push(18) OpPick -> new_rs copy                     [3B]
    0x00,                         // Op0                                                [1B]
    0x01, 0x7f,                   // push 127                                           [2B]
    0x7f,                         // OpSubstr -> new_prefix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // --- D&R Step 3: Verify unchanged suffix [144..end) ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy                         [2B]
    0x82,                         // OpSize -> len                                       [1B]
    0x02, 0x90, 0x00,             // push 144                                           [3B]
    0x94,                         // OpSub -> suffix_len                                 [1B]
    0x02, 0x90, 0x00,             // push 144 (begin)                                   [3B]
    0x7c,                         // OpSwap                                              [1B]
    0x7f,                         // OpSubstr -> old_suffix                              [1B]
    0x01, 0x12, 0x79,             // push(18) OpPick -> new_rs copy                     [3B]
    0x82,                         // OpSize                                              [1B]
    0x02, 0x90, 0x00,             // push 144                                           [3B]
    0x94,                         // OpSub                                               [1B]
    0x02, 0x90, 0x00,             // push 144                                           [3B]
    0x7c,                         // OpSwap                                              [1B]
    0x7f,                         // OpSubstr -> new_suffix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // (No transition check — 2-of-2 auth ensures only authorized changes)
    //
    // --- D&R Step 5: Verify output SPK ---
    0x01, 0x11, 0x79,             // push(17) OpPick -> new_rs copy (d17)               [3B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat                                               [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected output SPK                        [1B]
    0x00, 0xc3,                   // Op0 OpTxOutputSpk                                  [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // Cleanup: 14 state + 2 sigscript + 2 D&R = 18
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75,             // OpDrop x3 (18 total)                                [3B]

    0x68,                         // OpEndIf (path 5 vs 6)                               [1B]
    0x68,                         // OpEndIf (path 4 vs {5,6})                           [1B]

    // BRANCH B2: sel >= 7 (paths 7-10)
    0x67,                         // OpElse (sel >= 7)                                   [1B]
    // stack: sel(0) liq_th(1) grace(2) ... lend(13) [+ sigscript items]

    // --- Sub-branch: sel < 9 ? (paths 7,8) vs sel >= 9 (paths 9,10) ---
    0x76,                         // OpDup                                              [1B]
    0x59, 0x9f,                   // Op9 OpLessThan (sel < 9?)                          [2B]
    0x63,                         // OpIf (sel in {7,8})                                 [1B]

    // PATH 7: REBALANCE (D&R pattern)
    // (sel=8 Redemption REMOVED — permissionless collateral theft vector)
    // Sigscript: [pushData(new_rs)][pushData(old_rs)][ri_opN][loi_opN][ci_opN][Op7][pushData(RS)]
    // stack: sel(0) liq_th(1) ... lend(13) insurer(14) ci(15) loi(16) ri(17) old_rs(18) new_rs(19) [20]
    0x57, 0x87, 0x69,             // Op7 OpEqual OpVerify (sel==7; sel consumed)         [3B]
    // stack: liq_th(0) ... lend(12) insurer(13) ci(14) loi(15) ri(16) old_rs(17) new_rs(18) [19]
    //
    // Verify rate_mode == 1 (variable rate only)
    0x54, 0x79,                   // Op4 OpPick -> rm (d4=rm)                            [2B]
    0x51, 0x87, 0x69,             // Op1 OpEqual OpVerify (rm == 1)                     [3B]
    // stack: liq_th(0) ... ri(16) old_rs(17) new_rs(18) [19]
    //
    // Verify lender output: output[loi].spk.blake2b == lender_spk_hash
    0x5f, 0x79, 0xc3, 0xaa,       // Op15 OpPick(loi) OpTxOutputSpk OpBlake2b           [4B]
    0x5d, 0x79,                   // Op13 OpPick -> lend (d13=lend)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) ... ri(16) old_rs(17) new_rs(18) [19]
    //
    // --- D&R Step 1: Verify old_rs authenticity ---
    0x01, 0x11, 0x79,             // push(17) OpPick -> old_rs copy (d17)               [3B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat                                               [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected P2SH SPK                          [1B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                        [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [19]
    //
    // --- D&R Step 2: Verify unchanged prefix [0..109) ---
    0x01, 0x11, 0x79,             // push(17) OpPick -> old_rs copy                     [3B]
    0x00,                         // Op0 (begin=0)                                      [1B]
    0x01, 0x6d,                   // push 109 (size)                                    [2B]
    0x7f,                         // OpSubstr -> old_prefix                              [1B]
    0x01, 0x13, 0x79,             // push(19) OpPick -> new_rs copy (d18+1=19)          [3B]
    0x00,                         // Op0                                                [1B]
    0x01, 0x6d,                   // push 109                                           [2B]
    0x7f,                         // OpSubstr -> new_prefix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [19]
    //
    // --- D&R Step 3: Verify unchanged suffix [117..end) ---
    0x01, 0x11, 0x79,             // push(17) OpPick -> old_rs copy                     [3B]
    0x82,                         // OpSize -> len                                       [1B]
    0x01, 0x75,                   // push 117                                           [2B]
    0x94,                         // OpSub -> suffix_len                                 [1B]
    0x01, 0x75,                   // push 117 (begin)                                   [2B]
    0x7c,                         // OpSwap                                              [1B]
    0x7f,                         // OpSubstr -> old_suffix                              [1B]
    0x01, 0x13, 0x79,             // push(19) OpPick -> new_rs copy                     [3B]
    0x82,                         // OpSize                                              [1B]
    0x01, 0x75,                   // push 117                                           [2B]
    0x94,                         // OpSub                                               [1B]
    0x01, 0x75,                   // push 117                                           [2B]
    0x7c,                         // OpSwap                                              [1B]
    0x7f,                         // OpSubstr -> new_suffix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [19]
    //
    // (No transition check — permissionless rebalance, rate bounds enforced by prefix/suffix match
    //  which preserves rate_floor and rate_cap in state. The matcher validates bounds off-chain.)
    //
    // --- D&R Step 5: Verify output SPK (output[ci]) ---
    0x01, 0x12, 0x79,             // push(18) OpPick -> new_rs copy (d18)               [3B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat                                               [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected output SPK                        [1B]
    0x5e, 0x79, 0xc3,             // Op14 OpPick(ci) OpTxOutputSpk                      [3B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [19]
    //
    // Cleanup: 14 state + 3 sigscript + 2 D&R = 19
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (19 total)                                [4B]

    // (PATH 8 REMOVED — sel=8 will fail at PATH 7's Op7 OpEqual OpVerify)

    // ELSE: sel >= 9 in {9,10}
    0x67,                         // OpElse (sel >= 9)                                   [1B]

    // --- Sub-branch: sel < 10 ? (path 9) vs sel == 10 (path 10) ---
    0x76,                         // OpDup                                              [1B]
    0x5a, 0x9f,                   // Op10 OpLessThan (sel < 10?)                        [2B]
    0x63,                         // OpIf (sel == 9 -> partial liquidation)               [1B]

    // PATH 9: PARTIAL LIQUIDATION (62B)
    // Sigscript: [pushData(liq_amount 8B)][pi_opN][loi_opN][liqi_opN][ci_opN][Op9][pushData(RS)]
    // After RS: stack is: liq_th(0)...lend(12) insurer(13) [sel=14] ci(15) liqi(16) loi(17) pi(18) liq_amt(19)
    // After OpRoll selector: sel consumed -> liq_th(0)...insurer(13) ci(14) liqi(15) loi(16) pi(17) liq_amt(18) [19]
    0x59, 0x87, 0x69,             // Op9 OpEqual OpVerify (sel==9; sel consumed)         [3B]
    // stack: liq_th(0) grace(1) ... lend(12) insurer(13) ci(14) liqi(15) loi(16) pi(17) liq_amt(18) [19]
    //
    // Check not expired
    0xb5,                         // OpTxLockTime -> lockTime                            [1B]
    0x57, 0x79,                   // Op7 OpPick -> exp (d7: lt=0,liq_th=1,...exp=7)      [2B]
    // stack: exp_c(0) lt(1) liq_th(2) ... liq_amt(20) [21]
    0xa0, 0x69,                   // OpGreaterThan OpVerify (exp > lt)                   [2B]
    // stack: liq_th(0) grace(1) ... liq_amt(18) [19]
    //
    // LTV CHECK: collateral_value * 10000 < principal * liq_threshold
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> collateral_value  [2B]
    // stack: coll(0) liq_th(1) grace(2) ... liq_amt(19) [20]
    0x02, 0x10, 0x27,             // push 10000                                          [3B]
    0x95,                         // OpMul (coll * 10000)                                [1B]
    // stack: coll_scaled(0) liq_th(1) ... liq_amt(19) [20]
    0x5b, 0x79,                   // Op11 OpPick -> princ (d11: coll_scaled=0,...princ=11) [2B]
    // stack: princ_c(0) coll_scaled(1) liq_th(2) ... [21]
    0x52, 0x79,                   // Op2 OpPick -> liq_th (d2=liq_th)                   [2B]
    // stack: lt_c(0) princ_c(1) coll_scaled(2) ... [22]
    0x95,                         // OpMul (princ * liq_th)                              [1B]
    // stack: princ_threshold(0) coll_scaled(1) liq_th(2) ... [21]
    0x7c,                         // OpSwap                                              [1B]
    0x9f, 0x69,                   // OpLessThan OpVerify (coll_scaled < princ_threshold) [2B]
    // stack: liq_th(0) grace(1) ... liq_amt(18) [19]
    //
    // Verify lender output: output[loi].spk.blake2b == lender_spk_hash
    0x60, 0x79, 0xc3, 0xaa,       // Op16 OpPick(loi) OpTxOutputSpk OpBlake2b           [4B]
    0x5d, 0x79,                   // Op13 OpPick -> lend (d13=lend)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) grace(1) ... liq_amt(18) [19]
    //
    // Verify liq_amount > 0
    0x01, 0x12, 0x79,             // push(18) OpPick -> liq_amt (d18)                   [3B]
    // stack: la_c(0) liq_th(1) ... liq_amt(19) [20]
    0x00, 0xa0, 0x69,             // Op0 OpGreaterThan OpVerify (la > 0)                [3B]
    // stack: liq_th(0) grace(1) ... liq_amt(18) [19]
    //
    // Self-continuation: output[ci].spk == input.spk
    0x5e, 0x79, 0xc3,             // Op14 OpPick(ci) OpTxOutputSpk                      [3B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                         [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: liq_th(0) grace(1) ... liq_amt(18) [19]
    //
    // Cleanup: 14 state + 5 = 19
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (19 total)                                [4B]

    // PATH 10: LOAN TRANSFER (D&R pattern)
    0x67,                         // OpElse (sel == 10: loan transfer)                    [1B]
    // Sigscript: [pushData(new_rs)][pushData(old_rs)][pushData(new_lender_hash 32B)][ci_opN]
    //            [pushData(sig 65B)][pushData(pk 32B)][Op10][pushData(RS)]
    // After OpRoll: sel consumed ->
    // stack: liq_th(0) ... lend(12) insurer(13) pk(14) sig(15) ci(16) nlh(17) old_rs(18) new_rs(19) [20]
    0x5a, 0x87, 0x69,             // Op10 OpEqual OpVerify (sel==10; sel consumed)       [3B]
    // stack: liq_th(0) ... lend(12) insurer(13) pk(14) sig(15) ci(16) nlh(17) old_rs(18) new_rs(19) [20]
    //
    // Lender auth
    0x5e, 0x79,                   // Op14 OpPick -> pk copy (d14=pk)                    [2B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x5d, 0x79,                   // Op13 OpPick -> lend (d13=lend)                     [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    //
    // Sig verify
    0x5f, 0x7a,                   // Op15 OpRoll -> sig                                  [2B]
    0x5f, 0x7a,                   // Op15 OpRoll -> pk                                   [2B]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: liq_th(0) ... lend(12) insurer(13) ci(14) nlh(15) old_rs(16) new_rs(17) [18]
    //
    // --- D&R Step 1: Verify old_rs authenticity ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy (d16)                   [2B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat                                               [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected P2SH SPK                          [1B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                        [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // --- D&R Step 2: Verify unchanged prefix [0..34) ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy                         [2B]
    0x00,                         // Op0 (begin=0)                                      [1B]
    0x01, 0x22,                   // push 34 (size)                                     [2B]
    0x7f,                         // OpSubstr -> old_prefix                              [1B]
    0x01, 0x12, 0x79,             // push(18) OpPick -> new_rs copy (d17+1=18)          [3B]
    0x00,                         // Op0                                                [1B]
    0x01, 0x22,                   // push 34                                            [2B]
    0x7f,                         // OpSubstr -> new_prefix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // --- D&R Step 3: Verify unchanged suffix [66..end) ---
    0x60, 0x79,                   // Op16 OpPick -> old_rs copy                         [2B]
    0x82,                         // OpSize -> len                                       [1B]
    0x01, 0x42,                   // push 66                                            [2B]
    0x94,                         // OpSub -> suffix_len                                 [1B]
    0x01, 0x42,                   // push 66 (begin)                                    [2B]
    0x7c,                         // OpSwap                                              [1B]
    0x7f,                         // OpSubstr -> old_suffix                              [1B]
    0x01, 0x12, 0x79,             // push(18) OpPick -> new_rs copy                     [3B]
    0x82,                         // OpSize                                              [1B]
    0x01, 0x42,                   // push 66                                            [2B]
    0x94,                         // OpSub                                               [1B]
    0x01, 0x42,                   // push 66                                            [2B]
    0x7c,                         // OpSwap                                              [1B]
    0x7f,                         // OpSubstr -> new_suffix                              [1B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // (No transition check — lender sig authorizes the transfer)
    //
    // --- D&R Step 5: Verify output SPK (output[ci]) ---
    0x01, 0x11, 0x79,             // push(17) OpPick -> new_rs copy (d17)               [3B]
    0xaa,                         // OpBlake2b                                           [1B]
    0x04, 0x00, 0x00, 0xaa, 0x20, // push [version_0(2B), 0xaa, 0x20]                    [5B]
    0x7c,                         // OpSwap                                              [1B]
    0x7e,                         // OpCat                                               [1B]
    0x01, 0x87,                   // push [0x87]                                        [2B]
    0x7e,                         // OpCat -> expected output SPK                        [1B]
    0x5e, 0x79, 0xc3,             // Op14 OpPick(ci) OpTxOutputSpk                      [3B]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: [18]
    //
    // Cleanup: 14 state + 2 sigscript + 2 D&R = 18
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75,             // OpDrop x3 (18 total)                                [3B]

    0x68,                         // OpEndIf (path 9 vs 10)                              [1B]
    0x68,                         // OpEndIf (paths {7,8} vs {9,10})                     [1B]
    0x68,                         // OpEndIf (paths {4,5,6} vs {7-10})                   [1B]
    0x68,                         // OpEndIf (paths {1,2,3} vs {4-10})                   [1B]
    0x51,                         // Op1 (TRUE)                                           [1B]
];

/// Expected body length for active_loan snapshot test.
#[cfg(test)]
const ACTIVE_LOAN_BODY_EXPECTED_LEN: usize = ACTIVE_LOAN_BODY.len();

// active_loan redeemScript builder

/// Build active_loan redeemScript (222B state + body).
///
/// # Arguments
/// * `lender_spk_hash`       - 32B Blake2b hash of lender's SPK
/// * `borrower_spk_hash`     - 32B Blake2b hash of borrower's SPK
/// * `principal`             - Loan principal (sompi)
/// * `rate_num`              - Annual rate numerator
/// * `rate_den`              - Annual rate denominator
/// * `start_daa`             - Loan start DAA score
/// * `expiry_daa`            - Repayment deadline DAA score
/// * `collateral_cov_id`     - 32B collateral token covenant ID (all-zero = KAS)
/// * `rate_mode`             - 0=Fixed, 1=Variable
/// * `rate_floor_num`        - Variable rate floor numerator (lender protection)
/// * `rate_cap_num`          - Variable rate cap numerator (borrower protection)
/// * `grace_daa`             - Grace period after expiry for default claim
/// * `liq_threshold`         - Liquidation threshold (e.g. 15000 = 150%). Liquidation
///                             allowed when collateral*10000 < principal*liq_threshold.
///
/// # Errors
/// Returns `KobError::Contract` on invalid parameters.
pub fn build_active_loan_redeem_script(
    insurer_spk_hash: &[u8; 32],
    lender_spk_hash: &[u8; 32],
    borrower_spk_hash: &[u8; 32],
    principal: u64,
    rate_num: u64,
    rate_den: u64,
    start_daa: u64,
    expiry_daa: u64,
    collateral_cov_id: &[u8; 32],
    rate_mode: u64,
    rate_floor_num: u64,
    rate_cap_num: u64,
    grace_daa: u64,
    liq_threshold: u64,
) -> crate::Result<Vec<u8>> {
    if principal == 0 {
        return Err(crate::KobError::Contract("principal must be > 0".into()));
    }
    if rate_den == 0 {
        return Err(crate::KobError::Contract("rate_den must be > 0".into()));
    }
    if expiry_daa == 0 {
        return Err(crate::KobError::Contract("expiry_daa must be > 0".into()));
    }
    if expiry_daa <= start_daa {
        return Err(crate::KobError::Contract("expiry_daa must be > start_daa".into()));
    }
    if rate_mode > 1 {
        return Err(crate::KobError::Contract("rate_mode must be 0 or 1".into()));
    }
    if rate_mode == 0 && (rate_floor_num > 0 || rate_cap_num > 0) {
        return Err(crate::KobError::Contract(
            "rate_floor_num and rate_cap_num must be 0 when rate_mode is fixed".into(),
        ));
    }
    if rate_mode == 1 && rate_floor_num > rate_cap_num && rate_cap_num > 0 {
        return Err(crate::KobError::Contract(
            "rate_floor_num must be <= rate_cap_num for variable rate".into(),
        ));
    }
    if grace_daa == 0 {
        return Err(crate::KobError::Contract("grace_daa must be > 0".into()));
    }
    if liq_threshold == 0 {
        return Err(crate::KobError::Contract("liq_threshold must be > 0".into()));
    }

    let body = ACTIVE_LOAN_BODY;
    let mut rs = Vec::with_capacity(ACTIVE_LOAN_STATE_SIZE + body.len());

    // State: pushed in order, first push = deepest on stack
    rs.push(0x20);
    rs.extend_from_slice(insurer_spk_hash);       // d13 (deepest)
    rs.push(0x20);
    rs.extend_from_slice(lender_spk_hash);        // d12
    rs.push(0x20);
    rs.extend_from_slice(borrower_spk_hash);      // d11
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(principal));      // d10
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_num));       // d9
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_den));       // d8
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(start_daa));      // d7
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));     // d6
    rs.push(0x20);
    rs.extend_from_slice(collateral_cov_id);       // d5
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_mode));      // d4
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_floor_num)); // d3
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_cap_num));   // d2
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(grace_daa));      // d1
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(liq_threshold));  // d0 (top)

    rs.extend_from_slice(body);
    Ok(rs)
}

// active_loan sigscript builders (10 paths)

/// Build active_loan liquidate sigscript (selector=1):
/// `[pi_opN][loi_opN][boi_opN][liqi_opN][Op1][pushData(RS)]`
///
/// Permissionless liquidation when LTV breached.
/// * `price_input_idx`      - Input index of price-feed UTXO (value-as-price)
/// * `lender_output_idx`    - Output index for lender's debt repayment
/// * `borrower_output_idx`  - Output index for borrower's remainder
/// * `liquidator_output_idx`- Output index for liquidator's bonus
pub fn build_active_loan_liquidate_sigscript(
    price_input_idx: u8,
    lender_output_idx: u8,
    borrower_output_idx: u8,
    liquidator_output_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(5 + redeem_script.len() + 3);
    ss.push(opn(price_input_idx));
    ss.push(opn(lender_output_idx));
    ss.push(opn(borrower_output_idx));
    ss.push(opn(liquidator_output_idx));
    ss.push(0x51); // Op1 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan default claim sigscript (selector=2):
/// `[pushData(sig 65B)][pushData(pk 32B)][Op2][pushData(RS)]`
///
/// Lender claims collateral after expiry + grace period.
pub fn build_active_loan_default_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(103 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x52); // Op2 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan repay sigscript (selector=3):
/// `[loi_opN][pushData(sig 65B)][pushData(pk 32B)][Op3][pushData(RS)]`
///
/// Borrower repays principal+interest to lender.
pub fn build_active_loan_repay_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    lender_output_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(103 + redeem_script.len() + 3);
    ss.push(opn(lender_output_idx));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x53); // Op3 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan partial repay sigscript (selector=4, D&R pattern):
/// `[pushData(new_rs)][pushData(old_rs)][loi_opN][pushData(repay_amount 8B)][pushData(sig 65B)][pushData(pk 32B)][Op4][pushData(RS)]`
///
/// Borrower repays portion of principal + accrued interest.
/// Continuation UTXO with reduced principal via Destroy-and-Recreate.
pub fn build_active_loan_partial_repay_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    lender_output_idx: u8,
    repay_amount: u64,
    redeem_script: &[u8],
    old_rs: &[u8],
    new_rs: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let ra = u64_le(repay_amount);

    let mut ss = Vec::with_capacity(113 + redeem_script.len() + old_rs.len() + new_rs.len() + 10);
    ss.extend_from_slice(&push_data(new_rs));
    ss.extend_from_slice(&push_data(old_rs));
    ss.push(opn(lender_output_idx));
    ss.extend_from_slice(&push_data(&ra));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x54); // Op4 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan top-up collateral sigscript (selector=5):
/// `[ci_opN][pushData(sig 65B)][pushData(pk 32B)][Op5][pushData(RS)]`
///
/// Borrower adds more collateral. Self-continuation, output value > input value.
pub fn build_active_loan_topup_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    continuation_output_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(103 + redeem_script.len() + 3);
    ss.push(opn(continuation_output_idx));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x55); // Op5 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan extend sigscript (selector=6, D&R pattern):
/// `[pushData(new_rs)][pushData(old_rs)][loi_opN][pushData(new_expiry_daa 8B)]
///  [pushData(lender_sig 65B)][pushData(lender_pk 32B)]
///  [pushData(borrower_sig 65B)][pushData(borrower_pk 32B)][Op6][pushData(RS)]`
///
/// Both parties agree to extend the loan term.
/// Settles accrued interest to lender, resets start_daa, sets new expiry_daa.
/// 2-of-2 signatures — sigOpCount=2.
pub fn build_active_loan_extend_sigscript(
    lender_sig: &[u8; 64],
    lender_pk: &[u8; 32],
    borrower_sig: &[u8; 64],
    borrower_pk: &[u8; 32],
    lender_output_idx: u8,
    new_expiry_daa: u64,
    redeem_script: &[u8],
    old_rs: &[u8],
    new_rs: &[u8],
) -> Vec<u8> {
    let mut lsig = Vec::with_capacity(65);
    lsig.extend_from_slice(lender_sig);
    lsig.push(0x01);
    let mut bsig = Vec::with_capacity(65);
    bsig.extend_from_slice(borrower_sig);
    bsig.push(0x01);

    let exp = u64_le(new_expiry_daa);

    let mut ss = Vec::with_capacity(210 + redeem_script.len() + old_rs.len() + new_rs.len() + 10);
    ss.extend_from_slice(&push_data(new_rs));
    ss.extend_from_slice(&push_data(old_rs));
    ss.push(opn(lender_output_idx));
    ss.extend_from_slice(&push_data(&exp));
    ss.extend_from_slice(&push_data(&lsig));
    ss.extend_from_slice(&push_data(lender_pk));
    ss.extend_from_slice(&push_data(&bsig));
    ss.extend_from_slice(&push_data(borrower_pk));
    ss.push(0x56); // Op6 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan rebalance sigscript (selector=7, D&R pattern):
/// `[pushData(new_rs)][pushData(old_rs)][ri_opN][loi_opN][ci_opN][Op7][pushData(RS)]`
///
/// Permissionless, variable rate only. Updates rate from co-input UTXO value.
/// Settles accrued interest to lender, resets start_daa.
pub fn build_active_loan_rebalance_sigscript(
    rate_input_idx: u8,
    lender_output_idx: u8,
    continuation_output_idx: u8,
    redeem_script: &[u8],
    old_rs: &[u8],
    new_rs: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(4 + redeem_script.len() + old_rs.len() + new_rs.len() + 10);
    ss.extend_from_slice(&push_data(new_rs));
    ss.extend_from_slice(&push_data(old_rs));
    ss.push(opn(rate_input_idx));
    ss.push(opn(lender_output_idx));
    ss.push(opn(continuation_output_idx));
    ss.push(0x57); // Op7 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan redemption sigscript (selector=8):
/// `[loi_opN][Op8][pushData(RS)]`
///
/// DEPRECATED: PATH 8 removed from covenant bytecode (permissionless collateral theft vector).
/// Kept for test compatibility only — this sigscript will be REJECTED on-chain.
#[deprecated(note = "PATH 8 removed from covenant — sel=8 rejected on-chain")]
pub fn build_active_loan_redemption_sigscript(
    lender_output_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(opn(lender_output_idx));
    ss.push(0x58); // Op8 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan partial liquidation sigscript (selector=9):
/// `[pushData(liq_amount 8B)][pi_opN][loi_opN][liqi_opN][ci_opN][Op9][pushData(RS)]`
///
/// Permissionless fractional liquidation when LTV > threshold.
pub fn build_active_loan_partial_liquidation_sigscript(
    price_input_idx: u8,
    lender_output_idx: u8,
    liquidator_output_idx: u8,
    continuation_output_idx: u8,
    liquidate_amount: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let la = u64_le(liquidate_amount);

    let mut ss = Vec::with_capacity(15 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&la));
    ss.push(opn(price_input_idx));
    ss.push(opn(lender_output_idx));
    ss.push(opn(liquidator_output_idx));
    ss.push(opn(continuation_output_idx));
    ss.push(0x59); // Op9 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build active_loan loan transfer sigscript (selector=10, D&R pattern):
/// `[pushData(new_rs)][pushData(old_rs)][pushData(new_lender_hash 32B)][ci_opN]
///  [pushData(sig 65B)][pushData(pk 32B)][Op10][pushData(RS)]`
///
/// Lender transfers their position to a new lender.
/// Continuation with new lender_spk_hash via Destroy-and-Recreate.
pub fn build_active_loan_loan_transfer_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    continuation_output_idx: u8,
    new_lender_hash: &[u8; 32],
    redeem_script: &[u8],
    old_rs: &[u8],
    new_rs: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(136 + redeem_script.len() + old_rs.len() + new_rs.len() + 10);
    ss.extend_from_slice(&push_data(new_rs));
    ss.extend_from_slice(&push_data(old_rs));
    ss.extend_from_slice(&push_data(new_lender_hash));
    ss.push(opn(continuation_output_idx));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x5a); // Op10 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// Helper: interest calculation (off-chain, for TX construction)

/// Calculate simple interest for a loan off-chain.
///
/// `interest = principal * rate_num * elapsed_daa / (rate_den * DAA_PER_YEAR)`
///
/// Returns `None` on overflow. Uses u128 intermediates for safety.
pub fn calculate_interest(
    principal: u64,
    rate_num: u64,
    rate_den: u64,
    elapsed_daa: u64,
) -> Option<u64> {
    if rate_den == 0 {
        return None;
    }
    let num = (principal as u128)
        .checked_mul(rate_num as u128)?
        .checked_mul(elapsed_daa as u128)?;
    let den = (rate_den as u128).checked_mul(DAA_PER_YEAR as u128)?;
    if den == 0 {
        return None;
    }
    let result = num / den;
    if result > u64::MAX as u128 {
        return None;
    }
    Some(result as u64)
}

/// Calculate total repayment amount: principal + interest.
///
/// Returns `None` on overflow.
pub fn calculate_repay_total(
    principal: u64,
    rate_num: u64,
    rate_den: u64,
    elapsed_daa: u64,
) -> Option<u64> {
    let interest = calculate_interest(principal, rate_num, rate_den, elapsed_daa)?;
    principal.checked_add(interest)
}
