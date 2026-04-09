use crate::primitives::{push_data, u64_le};

// borrow_request — Borrower locks collateral with desired loan terms
//
// State (8 items, 120B):
//   [0x20][owner_spk_hash 32B]      d7 — borrower's SPK hash
//   [0x08][desired_amount 8B]       d6 — how much to borrow (sompi)
//   [0x08][max_rate_num 8B]         d5 — max acceptable annual rate
//   [0x08][max_rate_den 8B]         d4 — rate denominator
//   [0x08][min_duration_daa 8B]     d3 — minimum loan duration
//   [0x20][collateral_cov_id 32B]   d2 — what collateral type
//   [0x08][rate_mode 8B]            d1 — 0=fixed, 1=variable, 2=either
//   [0x08][rate_cap_num 8B]         d0 — variable rate cap (borrower protection)
//
// Dispatch: sigLen-based (3 paths).
//   sigLen < T1 (250)          -> Match (permissionless)
//   T1 <= sigLen < T2 (310)    -> Cancel (owner sig)
//   sigLen >= T2               -> Replace (owner sig, new rate params)

/// borrow_request state size: 2*(1+32) + 6*(1+8) = 66 + 54 = 120 bytes.
pub const BORROW_REQUEST_STATE_SIZE: usize = 2 * 33 + 6 * 9; // = 120

/// borrow_request body bytecode (82 bytes).
///
/// State: [owner_spk_hash 32B][desired_amount 8B][max_rate_num 8B]
///        [max_rate_den 8B][min_duration_daa 8B][collateral_cov_id 32B]
///        [rate_mode 8B][rate_cap_num 8B] = 120B (8 items)
///
/// Dispatch: sigLen-based (3 paths).
///   sigLen < T1 (250)          -> Match (permissionless, no sig)
///   T1 <= sigLen < T2 (310)    -> Cancel (owner sig)
///   sigLen >= T2               -> Replace (owner sig, new rate params)
///
/// Match: verifies output[0].value >= input value (collateral preserved).
///   Minimal — the LoanOffer and ActiveLoan covenants validate correctness.
///
/// Cancel: Blake2b(pk) == owner_spk_hash, then CheckSigVerify.
///
/// Replace: Same auth as cancel + self-continuation check.
///   output[0].spk == input.spk (RS template preserved).
///   Borrower can update max_rate_num and max_rate_den without cancelling.
pub const BORROW_REQUEST_BODY: &[u8] = &[
    // DISPATCH (13B)
    // stack: rcap(0) rm(1) ccid(2) mindur(3) mrd(4) mrn(5) da(6) owner(7)
    0xb9, 0xc9,                   // OpTxInputIndex, OpTxInputScriptSigLen -> sigLen   [2B]
    // stack: sigLen(0) rcap(1) rm(2) ccid(3) mindur(4) mrd(5) mrn(6) da(7) owner(8)
    0x76,                         // OpDup                                              [1B]
    0x02, 0x36, 0x01,             // push T2=310                                        [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                           [1B]
    0x63,                         // OpIf (match or cancel)                              [1B]
    // stack: sigLen(0) rcap(1) ... owner(8)
    0x02, 0xfa, 0x00,             // push T1=250                                        [3B]
    0x9f,                         // OpLessThan (sigLen < T1?)                           [1B]
    0x63,                         // OpIf (match)                                        [1B]

    // MATCH PATH (17B)
    // stack: rcap(0) rm(1) ccid(2) mindur(3) mrd(4) mrn(5) da(6) owner(7) [8 items]
    //
    // V1: output[0].value >= input value (collateral preserved in ActiveLoan)
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out0v                      [2B]
    // stack: out0v(0) rcap(1) ... owner(8) [9]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> in_val           [2B]
    // stack: in_val(0) out0v(1) rcap(2) ... [10]
    0x7c,                         // OpSwap -> out0v(0) in_val(1)                       [1B]
    0xa2, 0x69,                   // OpGTE OpVerify (out0v >= in_val)                   [2B]
    // stack: rcap(0) ... owner(7) [8]
    //
    // Cleanup: 8 state items
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4                                          [4B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (8 total)                                [4B]

    // CANCEL PATH (22B)
    0x67,                         // OpElse (T1 <= sigLen < T2: cancel)                  [1B]
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]
    // stack: rcap(0) rm(1) ccid(2) mindur(3) mrd(4) mrn(5) da(6) owner(7) pk(8) sig(9) [10]
    //
    // Owner auth: Blake2b(pk) == owner_spk_hash
    0x58, 0x79,                   // Op8 OpPick -> pk copy (d8=pk)                      [2B]
    // stack: pk_c(0) rcap(1) ... pk(9) sig(10) [11]
    0xaa,                         // OpBlake2b -> hash(pk)                               [1B]
    0x58, 0x79,                   // Op8 OpPick -> owner (d8=owner)                     [2B]
    // stack: owner_c(0) h(1) rcap(2) ... sig(11) [12]
    0x87, 0x69,                   // OpEqual OpVerify (h == owner)                       [2B]
    // stack: rcap(0) ... owner(7) pk(8) sig(9) [10]
    //
    // Signature verification
    0x59, 0x7a,                   // Op9 OpRoll -> sig to top                           [2B]
    // stack: sig(0) rcap(1) ... owner(8) pk(9) [10]
    0x59, 0x7a,                   // Op9 OpRoll -> pk to top                            [2B]
    // stack: pk(0) sig(1) rcap(2) ... owner(9) [10]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: rcap(0) ... owner(7) [8]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4                                          [4B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (8 total)                                [4B]

    // REPLACE PATH (31B)
    0x68,                         // OpEndIf (match vs cancel)                           [1B]
    0x67,                         // OpElse (sigLen >= T2: replace)                      [1B]
    // Sigscript: [pushData(new_mrn 8B)][pushData(new_mrd 8B)][pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]
    // stack: sigLen(0) rcap(1) rm(2) ccid(3) mindur(4) mrd(5) mrn(6) da(7) owner(8) pk(9) sig(10) new_mrd(11) new_mrn(12)
    0x75,                         // OpDrop (sigLen)                                     [1B]
    // stack: rcap(0) ... owner(7) pk(8) sig(9) new_mrd(10) new_mrn(11) [12]
    //
    // Owner auth: Blake2b(pk) == owner_spk_hash
    0x58, 0x79,                   // Op8 OpPick -> pk copy                               [2B]
    0xaa,                         // OpBlake2b                                            [1B]
    0x58, 0x79,                   // Op8 OpPick -> owner                                 [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                     [2B]
    // stack: rcap(0) ... owner(7) pk(8) sig(9) new_mrd(10) new_mrn(11) [12]
    //
    // Sig verify
    0x59, 0x7a,                   // Op9 OpRoll -> sig                                   [2B]
    0x59, 0x7a,                   // Op9 OpRoll -> pk                                    [2B]
    0xad,                         // OpCheckSigVerify                                     [1B]
    // stack: rcap(0) ... owner(7) new_mrd(8) new_mrn(9) [10]
    //
    // Self-continuation: output[0].spk == input.spk
    0x00, 0xc3,                   // Op0 OpTxOutputSpk                                   [2B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                         [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                     [2B]
    // stack: rcap(0) ... owner(7) new_mrd(8) new_mrn(9) [10]
    //
    // Cleanup: 8 state + 2 new params = 10 items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                          [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5 (10 total)                               [5B]

    // CLOSING (2B)
    0x68,                         // OpEndIf (outer)                                      [1B]
    0x51,                         // Op1 (TRUE)                                           [1B]
];

/// Expected body length for borrow_request snapshot test.
#[cfg(test)]
const BORROW_REQUEST_BODY_EXPECTED_LEN: usize = 82;

// borrow_request redeemScript builder

/// Build borrow_request redeemScript (120B state + body).
///
/// # Arguments
/// * `owner_spk_hash`     - 32B Blake2b hash of borrower's SPK
/// * `desired_amount`     - How much to borrow (sompi)
/// * `max_rate_num`       - Maximum acceptable annual rate numerator
/// * `max_rate_den`       - Rate denominator
/// * `min_duration_daa`   - Minimum loan duration in DAA score units
/// * `collateral_cov_id`  - 32B covenant ID of collateral token (all-zero = KAS)
/// * `rate_mode`          - 0=fixed, 1=variable, 2=either
/// * `rate_cap_num`       - Variable rate cap numerator (borrower protection)
///
/// # Errors
/// Returns `KobError::Contract` on invalid parameters.
pub fn build_borrow_request_redeem_script(
    owner_spk_hash: &[u8; 32],
    desired_amount: u64,
    max_rate_num: u64,
    max_rate_den: u64,
    min_duration_daa: u64,
    collateral_cov_id: &[u8; 32],
    rate_mode: u64,
    rate_cap_num: u64,
) -> crate::Result<Vec<u8>> {
    if desired_amount == 0 {
        return Err(crate::KobError::Contract("desired_amount must be > 0".into()));
    }
    if max_rate_den == 0 {
        return Err(crate::KobError::Contract("max_rate_den must be > 0".into()));
    }
    if rate_mode > 2 {
        return Err(crate::KobError::Contract("rate_mode must be 0, 1, or 2".into()));
    }
    if rate_mode == 0 && rate_cap_num > 0 {
        return Err(crate::KobError::Contract(
            "rate_cap_num must be 0 when rate_mode is fixed".into(),
        ));
    }

    let body = BORROW_REQUEST_BODY;
    let mut rs = Vec::with_capacity(BORROW_REQUEST_STATE_SIZE + body.len());

    // State: pushed in order, first push = deepest on stack
    rs.push(0x20);
    rs.extend_from_slice(owner_spk_hash);            // d7 (deepest)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(desired_amount));   // d6
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_rate_num));     // d5
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_rate_den));     // d4
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_duration_daa)); // d3
    rs.push(0x20);
    rs.extend_from_slice(collateral_cov_id);         // d2
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_mode));        // d1
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_cap_num));     // d0 (top)

    rs.extend_from_slice(body);
    Ok(rs)
}

// borrow_request sigscript builders

/// Build borrow_request match sigscript: `[pushData(RS)]`
///
/// SigLen < T1=250. Permissionless — matcher fills the request.
pub fn build_borrow_request_match_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    push_data(redeem_script)
}

/// Build borrow_request cancel sigscript:
/// `[pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]`
///
/// T1=250 <= sigLen < T2=310. Owner reclaims collateral.
pub fn build_borrow_request_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(102 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build borrow_request replace sigscript:
/// `[pushData(new_max_rate_num 8B)][pushData(new_max_rate_den 8B)][pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]`
///
/// SigLen >= T2=310. Owner changes max rate parameters. Self-continuation enforced.
pub fn build_borrow_request_replace_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    new_max_rate_num: u64,
    new_max_rate_den: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mrn = u64_le(new_max_rate_num);
    let mrd = u64_le(new_max_rate_den);

    let mut ss = Vec::with_capacity(120 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&mrn));
    ss.extend_from_slice(&push_data(&mrd));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
