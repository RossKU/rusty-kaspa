use crate::primitives::{push_data, u64_le};

// insurance_position — Locked coverage for a specific loan
//
// State (5 items, 117B):
//   [0x20][insurer_spk_hash 32B]    d4 — insurer's SPK hash (coverage owner)
//   [0x20][lender_spk_hash 32B]     d3 — lender's SPK hash (payout recipient)
//   [0x20][borrower_spk_hash 32B]   d2 — borrower's SPK hash (can release)
//   [0x08][expiry_daa 8B]           d1 — loan expiry (DAA score)
//   [0x08][grace_daa 8B]            d0 — grace period (DAA units)
//
// State size: 3*(1+32) + 2*(1+8) = 99 + 18 = 117B
//
// Dispatch: selector-based (4 paths).
//   Selector is an OpN pushed before RS in sigscript.
//   Body uses Op5 OpRoll to bring selector to top (depth 5 = 5 state items).
//
// Paths:
//   sel=1: Payout         (lender sig, CLTV after expiry + grace)
//                          Lender claims coverage on borrower default.
//   sel=2: Release        (borrower sig)
//                          Borrower releases coverage back to insurer after repay.
//   sel=3: Cancel         (insurer sig + lender sig, 2-of-2)
//                          Mutual early termination.
//   sel=4: Timeout        (insurer sig, CLTV after expiry + 2*grace)
//                          Fallback if nobody acts. Insurer reclaims.

/// insurance_position state size: 3*(1+32) + 2*(1+8) = 117 bytes.
pub const INSURANCE_POSITION_STATE_SIZE: usize = 3 * 33 + 2 * 9; // = 117

/// insurance_position body bytecode (4-path selector dispatch).
///
/// sel=1  Payout: lender sig + CLTV (expiry_daa + grace_daa).
///   After expiry+grace, lender takes coverage. Used when borrower defaults.
///
/// sel=2  Release: borrower sig. Output to insurer >= coverage.
///   Borrower releases after repaying loan. Insurer recovers funds.
///
/// sel=3  Cancel: 2-of-2 insurer+lender sig. Flexible outputs.
///   Mutual early termination (e.g., loan paid early, both agree).
///
/// sel=4  Timeout: insurer sig + CLTV (expiry + 2*grace).
///   Fallback reclaim. If loan was repaid but borrower didn't release,
///   insurer can reclaim after extended timeout.
pub const INSURANCE_POSITION_BODY: &[u8] = &[
    // DISPATCH (6B)
    // stack (after RS state push): grace(0) exp(1) borr(2) lend(3) ins(4)
    //   [sel at d5 from sigscript] [+ pk, sig, etc. from sigscript]
    0x55, 0x7a,                   // Op5 OpRoll -> sel to top                               [2B]
    // stack: sel(0) grace(1) exp(2) borr(3) lend(4) ins(5) [+ sigscript items]
    //
    // Branch: sel < 3 ? (paths 1,2) vs sel >= 3 (paths 3,4)
    0x76,                         // OpDup                                                   [1B]
    0x53, 0x9f,                   // Op3 OpLessThan (sel < 3?)                              [2B]
    0x63,                         // OpIf (sel in {1,2})                                     [1B]

    // BRANCH A: sel < 3 (paths 1, 2)
    // stack: sel(0) grace(1) exp(2) borr(3) lend(4) ins(5) [+ pk sig ...]

    // --- Sub-branch: sel < 2 ? (path 1) vs sel >= 2 (path 2) ---
    0x76,                         // OpDup                                                   [1B]
    0x52, 0x9f,                   // Op2 OpLessThan (sel < 2?)                              [2B]
    0x63,                         // OpIf (sel == 1 -> payout)                               [1B]

    // PATH 1: PAYOUT (29B)
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][Op1][pushData(RS)]
    // stack: sel(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0x51, 0x87, 0x69,             // Op1 OpEqual OpVerify (sel==1; sel consumed)             [3B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // CLTV: expiry_daa + grace_daa <= lockTime
    0x51, 0x79,                   // Op1 OpPick -> exp (d1=exp)                             [2B]
    // stack: exp_c(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0x51, 0x79,                   // Op1 OpPick -> grace (d1=grace after exp_c pushed)      [2B]
    // stack: grace_c(0) exp_c(1) grace(2) exp(3) borr(4) lend(5) ins(6) pk(7) sig(8) [9]
    0x93,                         // OpAdd -> exp + grace = deadline                         [1B]
    // stack: deadline(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0x76, 0x69,                   // OpDup OpVerify (deadline != 0)                          [2B]
    0xb0,                         // OpCheckLockTimeVerify                                   [1B]
    0x75,                         // OpDrop (CLTV doesn't pop; drop deadline)                [1B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // Lender auth: Blake2b(pk) == lender_spk_hash
    0x55, 0x79,                   // Op5 OpPick -> pk copy (d5=pk)                          [2B]
    // stack: pk_c(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0xaa,                         // OpBlake2b -> hash(pk)                                   [1B]
    0x54, 0x79,                   // Op4 OpPick -> lend (d4=lend after pk_c push)           [2B]
    // stack: lend_c(0) h(1) grace(2) ... sig(8) [9]
    0x87, 0x69,                   // OpEqual OpVerify (h == lend)                            [2B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // Sig verify
    0x56, 0x7a,                   // Op6 OpRoll -> sig to top                               [2B]
    // stack: sig(0) grace(1) ... ins(5) pk(6) [7]
    0x56, 0x7a,                   // Op6 OpRoll -> pk to top                                [2B]
    // stack: pk(0) sig(1) grace(2) ... ins(6) [7]
    0xad,                         // OpCheckSigVerify                                        [1B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) [5]
    //
    // Cleanup: 5 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                             [5B]

    // PATH 2: RELEASE (25B)
    0x67,                         // OpElse (sel == 2: release)                              [1B]
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][Op2][pushData(RS)]
    // stack: sel(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0x52, 0x87, 0x69,             // Op2 OpEqual OpVerify (sel==2; sel consumed)             [3B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // Borrower auth: Blake2b(pk) == borrower_spk_hash
    0x55, 0x79,                   // Op5 OpPick -> pk copy (d5=pk)                          [2B]
    // stack: pk_c(0) grace(1) ... sig(7) [8]
    0xaa,                         // OpBlake2b                                               [1B]
    0x53, 0x79,                   // Op3 OpPick -> borr (d3=borr after pk_c push)           [2B]
    // stack: borr_c(0) h(1) grace(2) ... sig(8) [9]
    0x87, 0x69,                   // OpEqual OpVerify                                        [2B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // Sig verify
    0x56, 0x7a,                   // Op6 OpRoll -> sig                                      [2B]
    0x56, 0x7a,                   // Op6 OpRoll -> pk                                       [2B]
    0xad,                         // OpCheckSigVerify                                        [1B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) [5]
    //
    // Verify output[0] goes to insurer: output[0].spk.blake2b == insurer_spk_hash
    0x00, 0xc3,                   // Op0 OpTxOutputSpk -> out0_spk                          [2B]
    // stack: spk(0) grace(1) exp(2) borr(3) lend(4) ins(5) [6]
    0xaa,                         // OpBlake2b                                               [1B]
    0x55, 0x79,                   // Op5 OpPick -> ins (d5=ins)                             [2B]
    // stack: ins_c(0) h(1) grace(2) ... [7]
    0x87, 0x69,                   // OpEqual OpVerify (h == ins)                             [2B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) [5]
    //
    // Cleanup: 5 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                             [5B]

    0x68,                         // OpEndIf (path 1 vs path 2)                             [1B]

    // BRANCH B: sel >= 3 (paths 3, 4)
    0x67,                         // OpElse (sel >= 3)                                       [1B]

    // --- Sub-branch: sel < 4 ? (path 3) vs sel >= 4 (path 4) ---
    0x76,                         // OpDup                                                   [1B]
    0x54, 0x9f,                   // Op4 OpLessThan (sel < 4?)                              [2B]
    0x63,                         // OpIf (sel == 3 -> cancel)                               [1B]

    // PATH 3: CANCEL (32B) — 2-of-2 insurer + lender
    // Sigscript: [pushData(sig_ins 65B)][pushData(pk_ins 32B)]
    //            [pushData(sig_lend 65B)][pushData(pk_lend 32B)][Op3][pushData(RS)]
    // stack: sel(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk_lend(6) sig_lend(7) pk_ins(8) sig_ins(9) [10]
    0x53, 0x87, 0x69,             // Op3 OpEqual OpVerify (sel==3; sel consumed)             [3B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk_lend(5) sig_lend(6) pk_ins(7) sig_ins(8) [9]
    //
    // Insurer auth: Blake2b(pk_ins) == insurer_spk_hash
    0x57, 0x79,                   // Op7 OpPick -> pk_ins copy (d7=pk_ins)                  [2B]
    // stack: pk_ins_c(0) grace(1) ... sig_ins(9) [10]
    0xaa,                         // OpBlake2b                                               [1B]
    0x55, 0x79,                   // Op5 OpPick -> ins (d5=ins after pk_ins_c push)         [2B]
    // stack: ins_c(0) h(1) grace(2) ... sig_ins(10) [11]
    0x87, 0x69,                   // OpEqual OpVerify                                        [2B]
    // stack: grace(0) ... pk_lend(5) sig_lend(6) pk_ins(7) sig_ins(8) [9]
    //
    // Lender auth: Blake2b(pk_lend) == lender_spk_hash
    0x55, 0x79,                   // Op5 OpPick -> pk_lend copy (d5=pk_lend)                [2B]
    // stack: pk_lend_c(0) grace(1) ... sig_ins(9) [10]
    0xaa,                         // OpBlake2b                                               [1B]
    0x54, 0x79,                   // Op4 OpPick -> lend (d4=lend after pk_lend_c push)      [2B]
    // stack: lend_c(0) h(1) grace(2) ... [11]
    0x87, 0x69,                   // OpEqual OpVerify                                        [2B]
    // stack: grace(0) ... pk_lend(5) sig_lend(6) pk_ins(7) sig_ins(8) [9]
    //
    // Sig verify insurer
    0x58, 0x7a,                   // Op8 OpRoll -> sig_ins                                  [2B]
    0x58, 0x7a,                   // Op8 OpRoll -> pk_ins                                   [2B]
    0xad,                         // OpCheckSigVerify                                        [1B]
    // stack: grace(0) ... ins(4) pk_lend(5) sig_lend(6) [7]
    //
    // Sig verify lender
    0x56, 0x7a,                   // Op6 OpRoll -> sig_lend                                 [2B]
    0x56, 0x7a,                   // Op6 OpRoll -> pk_lend                                  [2B]
    0xad,                         // OpCheckSigVerify                                        [1B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) [5]
    //
    // Cleanup: 5 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                             [5B]

    // PATH 4: TIMEOUT (33B)
    0x67,                         // OpElse (sel == 4: timeout)                              [1B]
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][Op4][pushData(RS)]
    // stack: sel(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0x54, 0x87, 0x69,             // Op4 OpEqual OpVerify (sel==4; sel consumed)             [3B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // CLTV: expiry + 2*grace <= lockTime
    0x51, 0x79,                   // Op1 OpPick -> exp (d1=exp)                             [2B]
    // stack: exp_c(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0x51, 0x79,                   // Op1 OpPick -> grace (d1=grace after exp_c push)        [2B]
    // stack: grace_c(0) exp_c(1) grace(2) exp(3) borr(4) ... sig(8) [9]
    0x76,                         // OpDup                                                   [1B]
    // stack: grace_c2(0) grace_c(1) exp_c(2) grace(3) ... [10]
    0x93,                         // OpAdd -> 2*grace                                        [1B]
    // stack: 2g(0) exp_c(1) grace(2) ... [9]
    0x93,                         // OpAdd -> exp + 2*grace = deadline                       [1B]
    // stack: deadline(0) grace(1) exp(2) borr(3) lend(4) ins(5) pk(6) sig(7) [8]
    0x76, 0x69,                   // OpDup OpVerify (deadline != 0)                          [2B]
    0xb0,                         // OpCheckLockTimeVerify                                   [1B]
    0x75,                         // OpDrop (CLTV doesn't pop)                               [1B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // Insurer auth: Blake2b(pk) == insurer_spk_hash
    0x55, 0x79,                   // Op5 OpPick -> pk copy (d5=pk)                          [2B]
    // stack: pk_c(0) grace(1) ... sig(7) [8]
    0xaa,                         // OpBlake2b                                               [1B]
    0x55, 0x79,                   // Op5 OpPick -> ins (d5=ins after pk_c push)             [2B]
    // stack: ins_c(0) h(1) grace(2) ... [9]
    0x87, 0x69,                   // OpEqual OpVerify                                        [2B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) pk(5) sig(6) [7]
    //
    // Sig verify
    0x56, 0x7a,                   // Op6 OpRoll -> sig                                      [2B]
    0x56, 0x7a,                   // Op6 OpRoll -> pk                                       [2B]
    0xad,                         // OpCheckSigVerify                                        [1B]
    // stack: grace(0) exp(1) borr(2) lend(3) ins(4) [5]
    //
    // Cleanup: 5 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                             [5B]

    0x68,                         // OpEndIf (path 3 vs path 4)                             [1B]
    0x68,                         // OpEndIf (branch A vs branch B)                         [1B]

    // CLOSING (1B)
    0x51,                         // Op1 (TRUE)                                              [1B]
];

/// Expected body length for snapshot test.
#[cfg(test)]
const INSURANCE_POSITION_BODY_EXPECTED_LEN: usize = 140;

// insurance_position redeemScript builder

/// Build insurance_position redeemScript (117B state + body).
///
/// # Arguments
/// * `insurer_spk_hash`  - 32B Blake2b hash of insurer's SPK
/// * `lender_spk_hash`   - 32B Blake2b hash of lender's SPK
/// * `borrower_spk_hash` - 32B Blake2b hash of borrower's SPK
/// * `expiry_daa`        - Loan expiry DAA score
/// * `grace_daa`         - Grace period in DAA units (must be > 0)
pub fn build_insurance_position_redeem_script(
    insurer_spk_hash: &[u8; 32],
    lender_spk_hash: &[u8; 32],
    borrower_spk_hash: &[u8; 32],
    expiry_daa: u64,
    grace_daa: u64,
) -> crate::Result<Vec<u8>> {
    if expiry_daa == 0 {
        return Err(crate::KobError::Contract("expiry_daa must be > 0".into()));
    }
    if grace_daa == 0 {
        return Err(crate::KobError::Contract("grace_daa must be > 0".into()));
    }
    let zero = [0u8; 32];
    if insurer_spk_hash == &zero {
        return Err(crate::KobError::Contract("insurer_spk_hash must be non-zero".into()));
    }
    if lender_spk_hash == &zero {
        return Err(crate::KobError::Contract("lender_spk_hash must be non-zero".into()));
    }
    if borrower_spk_hash == &zero {
        return Err(crate::KobError::Contract("borrower_spk_hash must be non-zero".into()));
    }

    let body = INSURANCE_POSITION_BODY;
    let mut rs = Vec::with_capacity(INSURANCE_POSITION_STATE_SIZE + body.len());

    // State: pushed in order, first push = deepest on stack
    rs.push(0x20);
    rs.extend_from_slice(insurer_spk_hash);                // d4 (deepest)
    rs.push(0x20);
    rs.extend_from_slice(lender_spk_hash);                 // d3
    rs.push(0x20);
    rs.extend_from_slice(borrower_spk_hash);               // d2
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(expiry_daa));             // d1
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(grace_daa));              // d0 (top)

    rs.extend_from_slice(body);
    Ok(rs)
}

// insurance_position sigscript builders

/// Build payout sigscript (PATH 1): lender claims on default.
pub fn build_insurance_position_payout_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(sig);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let rs_pd = push_data(redeem_script);
    let mut ss = Vec::with_capacity(66 + 33 + 1 + rs_pd.len());
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pk));
    ss.push(0x51); // Op1 (sel=1)
    ss.extend_from_slice(&rs_pd);
    ss
}

/// Build release sigscript (PATH 2): borrower releases to insurer.
pub fn build_insurance_position_release_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(sig);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let rs_pd = push_data(redeem_script);
    let mut ss = Vec::with_capacity(66 + 33 + 1 + rs_pd.len());
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pk));
    ss.push(0x52); // Op2 (sel=2)
    ss.extend_from_slice(&rs_pd);
    ss
}

/// Build cancel sigscript (PATH 3): 2-of-2 insurer + lender.
pub fn build_insurance_position_cancel_sigscript(
    sig_insurer: &[u8; 64],
    pk_insurer: &[u8; 32],
    sig_lender: &[u8; 64],
    pk_lender: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_ins_with_type = Vec::with_capacity(65);
    sig_ins_with_type.extend_from_slice(sig_insurer);
    sig_ins_with_type.push(0x01);
    let mut sig_lend_with_type = Vec::with_capacity(65);
    sig_lend_with_type.extend_from_slice(sig_lender);
    sig_lend_with_type.push(0x01);

    let rs_pd = push_data(redeem_script);
    let mut ss = Vec::with_capacity(2 * (66 + 33) + 1 + rs_pd.len());
    // Pushed first = deepest on stack: insurer items below lender items
    ss.extend_from_slice(&push_data(&sig_ins_with_type));
    ss.extend_from_slice(&push_data(pk_insurer));
    ss.extend_from_slice(&push_data(&sig_lend_with_type));
    ss.extend_from_slice(&push_data(pk_lender));
    ss.push(0x53); // Op3 (sel=3)
    ss.extend_from_slice(&rs_pd);
    ss
}

/// Build timeout sigscript (PATH 4): insurer reclaims after extended timeout.
pub fn build_insurance_position_timeout_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(sig);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let rs_pd = push_data(redeem_script);
    let mut ss = Vec::with_capacity(66 + 33 + 1 + rs_pd.len());
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pk));
    ss.push(0x54); // Op4 (sel=4)
    ss.extend_from_slice(&rs_pd);
    ss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::insurance::{build_insurance_payload, parse_insurance_payload};

    fn sample_hash(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    // InsurancePosition body snapshot

    #[test]
    fn insurance_position_body_exact_length() {
        assert_eq!(
            INSURANCE_POSITION_BODY.len(),
            INSURANCE_POSITION_BODY_EXPECTED_LEN,
            "body length changed — update INSURANCE_POSITION_BODY_EXPECTED_LEN"
        );
    }

    #[test]
    fn insurance_position_body_ends_with_true() {
        let body = INSURANCE_POSITION_BODY;
        assert_eq!(body[body.len() - 1], 0x51, "body must end with Op1 (TRUE)");
    }

    // InsurancePosition RS builder

    fn default_insurance_position_rs() -> Vec<u8> {
        build_insurance_position_redeem_script(
            &sample_hash(0xAA), // insurer
            &sample_hash(0xBB), // lender
            &sample_hash(0xCC), // borrower
            1_000_000,          // expiry
            10_000,             // grace
        ).unwrap()
    }

    #[test]
    fn insurance_position_rs_length() {
        let rs = default_insurance_position_rs();
        assert_eq!(rs.len(), INSURANCE_POSITION_STATE_SIZE + INSURANCE_POSITION_BODY.len());
    }

    #[test]
    fn insurance_position_total_rs_size() {
        let rs = default_insurance_position_rs();
        let expected = 117 + INSURANCE_POSITION_BODY.len();
        assert_eq!(rs.len(), expected,
            "total RS = state({}) + body({})",
            INSURANCE_POSITION_STATE_SIZE, INSURANCE_POSITION_BODY.len());
    }

    #[test]
    fn insurance_position_rs_deterministic() {
        let rs1 = default_insurance_position_rs();
        let rs2 = default_insurance_position_rs();
        assert_eq!(rs1, rs2);
    }

    #[test]
    fn insurance_position_rejects_zero_expiry() {
        let r = build_insurance_position_redeem_script(
            &sample_hash(0xAA), &sample_hash(0xBB), &sample_hash(0xCC), 0, 10000,
        );
        assert!(r.is_err());
    }

    #[test]
    fn insurance_position_rejects_zero_grace() {
        let r = build_insurance_position_redeem_script(
            &sample_hash(0xAA), &sample_hash(0xBB), &sample_hash(0xCC), 1000, 0,
        );
        assert!(r.is_err());
    }

    #[test]
    fn insurance_position_rejects_zero_insurer() {
        let r = build_insurance_position_redeem_script(
            &[0u8; 32], &sample_hash(0xBB), &sample_hash(0xCC), 1000, 10000,
        );
        assert!(r.is_err());
    }

    #[test]
    fn insurance_position_rejects_zero_lender() {
        let r = build_insurance_position_redeem_script(
            &sample_hash(0xAA), &[0u8; 32], &sample_hash(0xCC), 1000, 10000,
        );
        assert!(r.is_err());
    }

    #[test]
    fn insurance_position_rejects_zero_borrower() {
        let r = build_insurance_position_redeem_script(
            &sample_hash(0xAA), &sample_hash(0xBB), &[0u8; 32], 1000, 10000,
        );
        assert!(r.is_err());
    }

    // InsurancePosition sigscript builders

    #[test]
    fn insurance_position_payout_sigscript_size() {
        let rs = default_insurance_position_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];
        let ss = build_insurance_position_payout_sigscript(&fake_sig, &fake_pk, &rs);
        let rs_pd_len = push_data(&rs).len();
        // sig(66) + pk(33) + sel(1) + RS
        assert_eq!(ss.len(), 66 + 33 + 1 + rs_pd_len);
    }

    #[test]
    fn insurance_position_release_sigscript_size() {
        let rs = default_insurance_position_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];
        let ss = build_insurance_position_release_sigscript(&fake_sig, &fake_pk, &rs);
        let rs_pd_len = push_data(&rs).len();
        assert_eq!(ss.len(), 66 + 33 + 1 + rs_pd_len);
    }

    #[test]
    fn insurance_position_cancel_sigscript_size() {
        let rs = default_insurance_position_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];
        let ss = build_insurance_position_cancel_sigscript(
            &fake_sig, &fake_pk, &fake_sig, &fake_pk, &rs,
        );
        let rs_pd_len = push_data(&rs).len();
        // 2*(sig+pk) + sel + RS
        assert_eq!(ss.len(), 2 * (66 + 33) + 1 + rs_pd_len);
    }

    #[test]
    fn insurance_position_timeout_sigscript_size() {
        let rs = default_insurance_position_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];
        let ss = build_insurance_position_timeout_sigscript(&fake_sig, &fake_pk, &rs);
        let rs_pd_len = push_data(&rs).len();
        assert_eq!(ss.len(), 66 + 33 + 1 + rs_pd_len);
    }

    #[test]
    fn insurance_position_selectors_correct() {
        let rs = default_insurance_position_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];

        let ss1 = build_insurance_position_payout_sigscript(&fake_sig, &fake_pk, &rs);
        let ss2 = build_insurance_position_release_sigscript(&fake_sig, &fake_pk, &rs);
        let ss4 = build_insurance_position_timeout_sigscript(&fake_sig, &fake_pk, &rs);

        // Selector is the byte just before the RS pushData
        // sig_with_type(65B) → push_data = 66B, pk(32B) → push_data = 33B
        let sel_offset_single = 66 + 33; // after sig+pk push_data
        assert_eq!(ss1[sel_offset_single], 0x51, "payout sel must be Op1");
        assert_eq!(ss2[sel_offset_single], 0x52, "release sel must be Op2");
        assert_eq!(ss4[sel_offset_single], 0x54, "timeout sel must be Op4");
    }

    // InsurancePosition body opcode verification

    #[test]
    fn insurance_position_body_has_cltv() {
        let body = INSURANCE_POSITION_BODY;
        let cltv_count = body.iter().filter(|&&b| b == 0xb0).count();
        assert_eq!(cltv_count, 2, "exactly 2 CLTV expected (PATH 1 + PATH 4), got {cltv_count}");
    }

    #[test]
    fn insurance_position_body_cltv_has_opdrop() {
        let body = INSURANCE_POSITION_BODY;
        for (i, &b) in body.iter().enumerate() {
            if b == 0xb0 {
                assert!(i + 1 < body.len() && body[i + 1] == 0x75,
                    "CLTV at offset {i} must be followed by OpDrop");
            }
        }
    }

    #[test]
    fn insurance_position_body_has_checksigverify() {
        let body = INSURANCE_POSITION_BODY;
        let csv_count = body.iter().filter(|&&b| b == 0xad).count();
        // PATH 1: 1, PATH 2: 1, PATH 3: 2 (insurer+lender), PATH 4: 1 = 5 total
        assert_eq!(csv_count, 5, "exactly 5 CheckSigVerify expected, got {csv_count}");
    }

    #[test]
    fn insurance_position_body_has_blake2b_for_auth() {
        let body = INSURANCE_POSITION_BODY;
        let b2b_count = body.iter().filter(|&&b| b == 0xaa).count();
        // PATH 1: 1 (lender), PATH 2: 2 (borrower + insurer output),
        // PATH 3: 2 (insurer + lender), PATH 4: 1 (insurer) = 6 total
        assert_eq!(b2b_count, 6, "exactly 6 OpBlake2b expected, got {b2b_count}");
    }

    #[test]
    fn insurance_position_body_balanced_if_else_endif() {
        let body = INSURANCE_POSITION_BODY;
        let if_count = body.iter().filter(|&&b| b == 0x63).count();
        let else_count = body.iter().filter(|&&b| b == 0x67).count();
        let endif_count = body.iter().filter(|&&b| b == 0x68).count();
        assert_eq!(if_count, endif_count,
            "OpIf({if_count}) must equal OpEndIf({endif_count})");
        assert_eq!(else_count, if_count,
            "OpElse({else_count}) must equal OpIf({if_count})");
    }

    // InsurancePosition state field extraction

    #[test]
    fn insurance_position_state_fields_roundtrip() {
        let insurer = sample_hash(0x11);
        let lender = sample_hash(0x22);
        let borrower = sample_hash(0x33);
        let expiry: u64 = 5_000_000;
        let grace: u64 = 50_000;

        let rs = build_insurance_position_redeem_script(
            &insurer, &lender, &borrower, expiry, grace,
        ).unwrap();

        // Verify state bytes in RS
        // d4 (insurer): offset 1..33
        assert_eq!(&rs[1..33], &insurer);
        // d3 (lender): offset 34..66
        assert_eq!(&rs[34..66], &lender);
        // d2 (borrower): offset 67..99
        assert_eq!(&rs[67..99], &borrower);
        // d1 (expiry): offset 100..108
        let exp_bytes = u64::from_le_bytes(rs[100..108].try_into().unwrap());
        assert_eq!(exp_bytes, expiry);
        // d0 (grace): offset 109..117
        let grace_bytes = u64::from_le_bytes(rs[109..117].try_into().unwrap());
        assert_eq!(grace_bytes, grace);
    }

    // Payload compatibility

    #[test]
    fn insurance_payload_roundtrip() {
        let rs = default_insurance_position_rs();
        let payload = build_insurance_payload(&rs);
        assert!(payload.starts_with(b"KOB:I:"));
        let parsed = parse_insurance_payload(&payload).unwrap();
        assert_eq!(parsed, &rs[..]);
    }

    #[test]
    fn insurance_payload_rejects_wrong_prefix() {
        let payload = b"KOB:L:fake";
        assert!(parse_insurance_payload(payload).is_none());
    }

    // Stack depth verification

    /// Simulate bytecode execution tracking stack depth.
    /// Verifies all OpPick(N)/OpRoll(N) have N < stack_depth.
    fn verify_stack_depths(label: &str, bytecode: &[u8], initial_depth: usize) -> usize {
        let mut depth = initial_depth;
        let mut i = 0;
        while i < bytecode.len() {
            let op = bytecode[i];
            match op {
                // Push opcodes: 0x01-0x4e push N bytes
                0x01..=0x4b => {
                    let n = op as usize;
                    i += 1 + n;
                    depth += 1;
                    continue;
                }
                0x4c => {
                    // pushData1
                    let n = bytecode[i + 1] as usize;
                    i += 2 + n;
                    depth += 1;
                    continue;
                }
                0x4d => {
                    // pushData2
                    let n = u16::from_le_bytes([bytecode[i + 1], bytecode[i + 2]]) as usize;
                    i += 3 + n;
                    depth += 1;
                    continue;
                }
                // OpN (push small number)
                0x00 | 0x51..=0x60 => depth += 1,
                // OpDup
                0x76 => depth += 1,
                // OpDrop
                0x75 => {
                    assert!(depth > 0, "{label}: OpDrop at offset {i} with empty stack");
                    depth -= 1;
                }
                // Op2Drop
                0x6d => {
                    assert!(depth >= 2, "{label}: Op2Drop at offset {i} with depth {depth}");
                    depth -= 2;
                }
                // OpSwap: no change
                0x7c => {
                    assert!(depth >= 2, "{label}: OpSwap at offset {i} with depth {depth}");
                }
                // OpPick: pops index (-1), pushes copy (+1) = net 0
                // (OpN before it already pushed the index: +1)
                // So OpN + OpPick = net +1 (one copy added)
                0x79 => {
                    let n_op = bytecode[i - 1];
                    if (0x51..=0x60).contains(&n_op) {
                        let n = (n_op - 0x50) as usize;
                        assert!(n < depth, "{label}: OpPick({n}) at offset {i} but depth is {depth}");
                    }
                    // net 0: pop index, push copy
                }
                // OpRoll: pops index (-1), moves item to top (net 0 for the move) = net -1
                // (OpN before it pushed the index: +1)
                // So OpN + OpRoll = net 0 (item moved, index consumed)
                0x7a => {
                    let n_op = bytecode[i - 1];
                    if (0x51..=0x60).contains(&n_op) {
                        let n = (n_op - 0x50) as usize;
                        assert!(n < depth, "{label}: OpRoll({n}) at offset {i} but depth is {depth}");
                    }
                    depth -= 1; // index consumed
                }
                // Binary ops: pop 2, push 1 (net -1)
                0x87 | 0x93 | 0x94 | 0x95 | 0x96 | 0x9c |
                0x9f | 0xa0 | 0xa1 | 0xa2 => {
                    assert!(depth >= 2, "{label}: binary op 0x{op:02x} at offset {i} with depth {depth}");
                    depth -= 1;
                }
                // Unary ops: pop 1, push 1 (net 0)
                0x91 | 0xaa => {}
                // OpVerify: pop 1
                0x69 => {
                    assert!(depth > 0, "{label}: OpVerify at offset {i} with empty stack");
                    depth -= 1;
                }
                // OpCheckSigVerify: pop 2 (pk + sig)
                0xad => {
                    assert!(depth >= 2, "{label}: OpCheckSigVerify at offset {i} with depth {depth}");
                    depth -= 2;
                }
                // OpCheckLockTimeVerify: no change (doesn't pop)
                0xb0 => {}
                // TX introspection: push 1
                0xb3 | 0xb5 | 0xb9 => depth += 1,
                // TX introspection: pop index, push result (net 0)
                0xbe | 0xbf | 0xc2 | 0xc3 | 0xc9 | 0xcf => {}
                // Control flow: no stack change
                0x63 | 0x64 | 0x67 | 0x68 => {}
                _ => {}
            }
            i += 1;
        }
        depth
    }

    #[test]
    fn insurance_position_path1_stack_depth() {
        let body = INSURANCE_POSITION_BODY;
        // Find PATH 1: starts at "Op1 OpEqual OpVerify" (0x51, 0x87, 0x69)
        let path1_start = body.windows(3)
            .position(|w| w == [0x51, 0x87, 0x69])
            .expect("PATH 1 selector check not found");

        // PATH 1 ends at OpElse (0x67) for path 2
        let path1_end = body[path1_start..].iter()
            .position(|&b| b == 0x67)
            .expect("PATH 1 OpElse not found")
            + path1_start;

        let path1_bytes = &body[path1_start..path1_end];
        // After dispatch: sel(0) + 5 state + pk(6) sig(7) = 8 items on stack
        // sel is consumed by OpEqual OpVerify (-2) → 6 items (but OpEqual -1, OpVerify -1, net after match: 7-1=7 wait)
        // Actually, entering PATH 1: sel is on stack, 8 total
        // Op1 OpEqual: pops sel and Op1, pushes bool → 7. OpVerify: pops bool → 6
        // Wait no, Op1 pushes 1, OpEqual pops 2 pushes 1, OpVerify pops 1
        // So: 8 (start) + 1 (Op1) - 1 (OpEqual net: -2+1=-1) - 1 (OpVerify) = 7
        // That leaves grace(0)...ins(4) pk(5) sig(6) = 7 items
        let final_depth = verify_stack_depths("PATH 1 (payout)", path1_bytes, 8);
        assert_eq!(final_depth, 0, "PATH 1 must end with empty stack (got {final_depth})");
    }

    #[test]
    fn insurance_position_path2_stack_depth() {
        let body = INSURANCE_POSITION_BODY;
        // Find PATH 2: starts at "Op2 OpEqual OpVerify" (0x52, 0x87, 0x69)
        let path2_start = body.windows(3)
            .position(|w| w == [0x52, 0x87, 0x69])
            .expect("PATH 2 selector check not found");

        let path2_end = body[path2_start..].iter()
            .position(|&b| b == 0x68) // OpEndIf (path 1 vs path 2)
            .expect("PATH 2 OpEndIf not found")
            + path2_start;

        let path2_bytes = &body[path2_start..path2_end];
        // Same initial: 8 items (sel + 5 state + pk + sig)
        let final_depth = verify_stack_depths("PATH 2 (release)", path2_bytes, 8);
        assert_eq!(final_depth, 0, "PATH 2 must end with empty stack (got {final_depth})");
    }

    #[test]
    fn insurance_position_path4_stack_depth() {
        let body = INSURANCE_POSITION_BODY;
        // Find PATH 4: starts at "Op4 OpEqual OpVerify" (0x54, 0x87, 0x69)
        let path4_start = body.windows(3)
            .position(|w| w == [0x54, 0x87, 0x69])
            .expect("PATH 4 selector check not found");

        // PATH 4 ends at OpEndIf (0x68)
        let path4_end = body[path4_start..].iter()
            .position(|&b| b == 0x68)
            .expect("PATH 4 OpEndIf not found")
            + path4_start;

        let path4_bytes = &body[path4_start..path4_end];
        let final_depth = verify_stack_depths("PATH 4 (timeout)", path4_bytes, 8);
        assert_eq!(final_depth, 0, "PATH 4 must end with empty stack (got {final_depth})");
    }
}
