//! Loan offer covenant for KOB P2P lending.

use crate::primitives::{push_data, u64_le};

/// Convert integer 0..=16 to OpN opcode (local helper).
#[allow(dead_code)]
fn opn(n: u8) -> u8 {
    match n {
        0 => 0x00,
        1..=16 => 0x50 + n,
        _ => panic!("OpN index out of range: {} (must be 0..=16)", n),
    }
}

// loan_offer — Lender locks principal KAS with rate/collateral terms
//
// State (9 items, 129B):
//   [0x20][owner_spk_hash 32B]              d8 — lender's SPK hash
//   [0x08][principal 8B]                    d7 — loan amount (sompi)
//   [0x08][rate_num 8B]                     d6 — annual rate numerator (e.g. 500=5.00%)
//   [0x08][rate_den 8B]                     d5 — annual rate denominator (e.g. 10000)
//   [0x08][min_collateral_ratio 8B]         d4 — e.g. 15000=150.00%
//   [0x08][max_duration_daa 8B]             d3 — max loan duration in DAA units
//   [0x20][accepted_collateral_cov_id 32B]  d2 — collateral token (0x00..00=KAS)
//   [0x08][rate_mode 8B]                    d1 — 0=fixed only, 1=variable ok
//   [0x08][rate_floor_num 8B]               d0 — variable rate floor
//
// Dispatch: sigLen-based (3 paths).
//   sigLen < T1 (250)          -> Match (permissionless)
//   T1 <= sigLen < T2 (330)    -> Cancel (owner sig, reclaim)
//   sigLen >= T2               -> Replace (owner sig, new rate)

/// loan_offer state size: 2*(1+32) + 7*(1+8) = 66 + 63 = 129 bytes.
///
/// Note: actual state encoding is 138B because of the length prefixes
/// within the Kaspa stack push format. The state_size constant reflects
/// the raw data footprint used for capacity pre-allocation.
pub const LOAN_OFFER_STATE_SIZE: usize = 2 * 33 + 7 * 9; // = 129

/// loan_offer body bytecode (85 bytes).
///
/// State: [owner_spk_hash 32B][principal 8B][rate_num 8B][rate_den 8B]
///        [min_collateral_ratio 8B][max_duration_daa 8B]
///        [accepted_collateral_cov_id 32B][rate_mode 8B][rate_floor_num 8B]
///        = 129B (9 items)
///
/// Dispatch: sigLen-based (3 paths).
///   sigLen < T1 (250)       -> Match (permissionless)
///   T1 <= sigLen < T2 (330) -> Cancel (owner sig)
///   sigLen >= T2            -> Replace (owner sig, new rate params)
///
/// Match: verifies output[0].value >= principal (funds flow correctly).
///   Minimal verification — the matching engine and ActiveLoan covenant
///   handle full correctness. This is the cooperative delegation model.
///
/// Cancel: Blake2b(pk) == owner_spk_hash, then CheckSigVerify.
///   Owner reclaims locked principal.
///
/// Replace: Same auth as cancel + self-continuation check.
///   output[0].spk == input.spk (RS template preserved).
pub const LOAN_OFFER_BODY: &[u8] = &[
    // DISPATCH (13B)
    // stack: rf(0) rm(1) acc(2) mdd(3) mcr(4) rd(5) rn(6) princ(7) owner(8)
    0xb9, 0xc9,                   // OpTxInputIndex, OpTxInputScriptSigLen -> sigLen   [2B]
    // stack: sigLen(0) rf(1) rm(2) acc(3) mdd(4) mcr(5) rd(6) rn(7) princ(8) owner(9)
    0x76,                         // OpDup                                              [1B]
    0x02, 0x4a, 0x01,             // push T2=330                                        [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                           [1B]
    0x63,                         // OpIf (match or cancel)                              [1B]
    // stack: sigLen(0) rf(1) rm(2) ... owner(9)
    0x02, 0xfa, 0x00,             // push T1=250                                        [3B]
    0x9f,                         // OpLessThan (sigLen < T1?)                           [1B]
    0x63,                         // OpIf (match)                                        [1B]

    // MATCH PATH (17B)
    // stack: rf(0) rm(1) acc(2) mdd(3) mcr(4) rd(5) rn(6) princ(7) owner(8) [9 items]
    //
    // V1: output[0].value >= principal
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out0v                      [2B]
    // stack: out0v(0) rf(1) rm(2) acc(3) mdd(4) mcr(5) rd(6) rn(7) princ(8) owner(9) [10]
    0x58, 0x79,                   // Op8 OpPick -> princ copy (d8=princ)                [2B]
    // stack: princ_c(0) out0v(1) rf(2) ... [11]
    0x7c,                         // OpSwap -> out0v(0) princ_c(1)                      [1B]
    0xa2, 0x69,                   // OpGTE OpVerify (out0v >= princ)                    [2B]
    // stack: rf(0) rm(1) acc(2) mdd(3) mcr(4) rd(5) rn(6) princ(7) owner(8) [9]
    //
    // Cleanup: 9 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (9 total)                                [4B]
    // stack: empty -> push TRUE at end

    // CANCEL PATH (22B)
    0x67,                         // OpElse (T1 <= sigLen < T2: cancel)                 [1B]
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]
    // stack: rf(0) rm(1) acc(2) mdd(3) mcr(4) rd(5) rn(6) princ(7) owner(8) pk(9) sig(10) [11]
    //
    // Owner auth: Blake2b(pk) == owner_spk_hash
    0x59, 0x79,                   // Op9 OpPick -> pk copy (d9=pk)                      [2B]
    // stack: pk_c(0) rf(1) ... pk(10) sig(11) [12]
    0xaa,                         // OpBlake2b -> hash(pk)                               [1B]
    0x59, 0x79,                   // Op9 OpPick -> owner (d9=owner)                     [2B]
    // stack: owner_c(0) h(1) rf(2) ... sig(12) [13]
    0x87, 0x69,                   // OpEqual OpVerify (h == owner)                       [2B]
    // stack: rf(0) ... owner(8) pk(9) sig(10) [11]
    //
    // Signature verification
    0x5a, 0x7a,                   // Op10 OpRoll -> sig to top                          [2B]
    // stack: sig(0) rf(1) ... owner(9) pk(10) [11]
    0x5a, 0x7a,                   // Op10 OpRoll -> pk to top                           [2B]
    // stack: pk(0) sig(1) rf(2) ... owner(10) [11]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: rf(0) ... owner(8) [9]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (9 total)                                [4B]

    // REPLACE PATH (31B)
    0x68,                         // OpEndIf (match vs cancel)                           [1B]
    0x67,                         // OpElse (sigLen >= T2: replace)                      [1B]
    // Sigscript: [pushData(new_rn 8B)][pushData(new_rd 8B)][pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]
    // stack: sigLen(0) rf(1) rm(2) acc(3) mdd(4) mcr(5) rd(6) rn(7) princ(8) owner(9) pk(10) sig(11) new_rd(12) new_rn(13)
    0x75,                         // OpDrop (sigLen)                                     [1B]
    // stack: rf(0) ... owner(8) pk(9) sig(10) new_rd(11) new_rn(12) [13]
    //
    // Owner auth: Blake2b(pk) == owner_spk_hash
    0x59, 0x79,                   // Op9 OpPick -> pk copy                               [2B]
    0xaa,                         // OpBlake2b                                            [1B]
    0x59, 0x79,                   // Op9 OpPick -> owner                                 [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                     [2B]
    // stack: rf(0) ... owner(8) pk(9) sig(10) new_rd(11) new_rn(12) [13]
    //
    // Sig verify
    0x5a, 0x7a,                   // Op10 OpRoll -> sig                                  [2B]
    0x5a, 0x7a,                   // Op10 OpRoll -> pk                                   [2B]
    0xad,                         // OpCheckSigVerify                                     [1B]
    // stack: rf(0) ... owner(8) new_rd(9) new_rn(10) [11]
    //
    // Self-continuation: output[0].spk == input.spk
    0x00, 0xc3,                   // Op0 OpTxOutputSpk                                   [2B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                         [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                     [2B]
    // stack: rf(0) ... owner(8) new_rd(9) new_rn(10) [11]
    //
    // Cleanup: 9 state + 2 new params = 11 items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                          [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                          [5B]
    0x75,                         // OpDrop x1 (11 total)                                 [1B]

    // CLOSING (2B)
    0x68,                         // OpEndIf (outer)                                      [1B]
    0x51,                         // Op1 (TRUE)                                           [1B]
];

/// Expected body length for loan_offer snapshot test.
#[cfg(test)]
const LOAN_OFFER_BODY_EXPECTED_LEN: usize = 85;

// loan_offer redeemScript builder

/// Build loan_offer redeemScript (129B state + 85B body = 214B).
///
/// # Arguments
/// * `owner_spk_hash`             - 32B Blake2b hash of lender's SPK
/// * `principal`                  - Loan amount in sompi (must match UTXO value)
/// * `rate_num`                   - Annual rate numerator (e.g. 500 for 5.00%)
/// * `rate_den`                   - Annual rate denominator (e.g. 10000)
/// * `min_collateral_ratio`       - Minimum collateral ratio (e.g. 15000 for 150%)
/// * `max_duration_daa`           - Maximum loan duration in DAA score units
/// * `accepted_collateral_cov_id` - 32B covenant ID of accepted collateral (all-zero = KAS)
/// * `rate_mode`                  - 0=fixed only, 1=variable ok
/// * `rate_floor_num`             - Variable rate floor numerator (lender protection)
///
/// # Errors
/// Returns `KobError::Contract` if rate_den is zero or principal is zero.
pub fn build_loan_offer_redeem_script(
    owner_spk_hash: &[u8; 32],
    principal: u64,
    rate_num: u64,
    rate_den: u64,
    min_collateral_ratio: u64,
    max_duration_daa: u64,
    accepted_collateral_cov_id: &[u8; 32],
    rate_mode: u64,
    rate_floor_num: u64,
) -> crate::Result<Vec<u8>> {
    if principal == 0 {
        return Err(crate::KobError::Contract("principal must be > 0".into()));
    }
    if rate_den == 0 {
        return Err(crate::KobError::Contract("rate_den must be > 0".into()));
    }
    if min_collateral_ratio == 0 {
        return Err(crate::KobError::Contract("min_collateral_ratio must be > 0".into()));
    }
    if max_duration_daa == 0 {
        return Err(crate::KobError::Contract("max_duration_daa must be > 0".into()));
    }
    if rate_mode > 1 {
        return Err(crate::KobError::Contract("rate_mode must be 0 (fixed) or 1 (variable)".into()));
    }
    if rate_mode == 0 && rate_floor_num > 0 {
        return Err(crate::KobError::Contract(
            "rate_floor_num must be 0 when rate_mode is fixed".into(),
        ));
    }

    let body = LOAN_OFFER_BODY;
    let mut rs = Vec::with_capacity(LOAN_OFFER_STATE_SIZE + body.len());

    // State: pushed in order, first push = deepest on stack
    rs.push(0x20);
    rs.extend_from_slice(owner_spk_hash);                 // d8 (deepest)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(principal));              // d7
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_num));               // d6
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_den));               // d5
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_collateral_ratio));   // d4
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_duration_daa));       // d3
    rs.push(0x20);
    rs.extend_from_slice(accepted_collateral_cov_id);      // d2
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_mode));              // d1
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(rate_floor_num));         // d0 (top)

    rs.extend_from_slice(body);
    Ok(rs)
}

// loan_offer sigscript builders

/// Build loan_offer match sigscript: `[pushData(RS)]`
///
/// SigLen < T1=250. Permissionless — matcher fills the offer.
pub fn build_loan_offer_match_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    push_data(redeem_script)
}

/// Build loan_offer cancel sigscript:
/// `[pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]`
///
/// T1=250 <= sigLen < T2=330. Owner reclaims principal.
pub fn build_loan_offer_cancel_sigscript(
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

/// Build loan_offer replace sigscript:
/// `[pushData(new_rate_num 8B)][pushData(new_rate_den 8B)][pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]`
///
/// SigLen >= T2=330. Owner changes rate parameters. Self-continuation enforced.
pub fn build_loan_offer_replace_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    new_rate_num: u64,
    new_rate_den: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let rn = u64_le(new_rate_num);
    let rd = u64_le(new_rate_den);

    let mut ss = Vec::with_capacity(120 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&rn));
    ss.extend_from_slice(&push_data(&rd));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

