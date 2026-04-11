//! Insurance covenants for KOB Lending (CDS — Credit Default Swap).
//!
//! Provides on-chain insurance for lending positions. Insurers lock
//! coverage KAS; on borrower default the lender claims the coverage.
//! On repay the borrower releases coverage back to the insurer.
//!
//! # Architecture
//!
//! Pure P2P insurance order book on Kaspa L1 covenants.
//! No oracle, no pool, no governance. Market-driven premium discovery.
//!
//! Two covenant types:
//! 1. **InsuranceOffer** — Insurer locks coverage with premium/term conditions.
//!    Order book entry. Matched by fee=0 miner.
//! 2. **InsurancePosition** — Locked coverage for a specific loan.
//!    Created when InsuranceOffer matches a loan. Payout/release/timeout paths.
//!
//! # Integration with ActiveLoan
//!
//! ActiveLoan v3's `insurer_spk_hash` field (d13) links to the insurer.
//! On default claim (PATH 2), the ActiveLoan covenant verifies an output
//! goes to the insurer's SPK. The InsurancePosition covenant independently
//! locks the coverage funds.
//!
//! # Flow
//!
//! ```text
//! Insurer deploys InsuranceOffer (locks coverage KAS)
//! Matcher pairs with a loan → creates InsurancePosition
//! Borrower pays premium (off-chain or in match TX)
//!
//! If borrower repays:
//!   Borrower releases InsurancePosition (PATH 2) → insurer gets coverage back
//!
//! If borrower defaults:
//!   Lender claims InsurancePosition (PATH 1) → lender gets coverage
//!   (simultaneous with ActiveLoan PATH 2 default claim)
//!
//! Timeout fallback:
//!   If nobody acts after expiry + 2*grace → insurer reclaims (PATH 4)
//! ```
//!
//! Opcode reference (Kaspa script):
//!   Op0=0x00  Op1=0x51  Op2=0x52  Op3=0x53  Op4=0x54
//!   Op5=0x55  Op6=0x56  Op7=0x57  Op8=0x58  Op9=0x59
//!   Op10=0x5a Op11=0x5b Op12=0x5c Op13=0x5d Op14=0x5e Op15=0x5f Op16=0x60
//!   OpDup=0x76   OpDrop=0x75   OpSwap=0x7c   OpPick=0x79   OpRoll=0x7a
//!   OpEqual=0x87 OpVerify=0x69 OpIf=0x63     OpElse=0x67   OpEndIf=0x68
//!   OpAdd=0x93   OpSub=0x94   OpMul=0x95    OpDiv=0x96
//!   OpLessThan=0x9f  OpGTE=0xa2  OpGreaterThan=0xa0
//!   OpBlake2b=0xaa   OpCheckSig=0xac   OpCheckSigVerify=0xad
//!   OpTxInputAmount=0xbe   OpInputCovenantId=0xcf
//!   OpTxOutputAmount=0xc2  OpTxOutputSpk=0xc3   OpTxInputSpk=0xbf
//!   OpTxLockTime=0xb5      OpCheckLockTimeVerify=0xb0
//!   OpTxInputIndex=0xb9    OpTxInputScriptSigLen=0xc9
//!   Op2Drop=0x6d  OpNot=0x91  OpNumEqual=0x9c  OpNotIf=0x64
//!   OpLTE=0xa1    OpInputCount=0xb3

use crate::primitives::{push_data, u64_le};

/// KOB insurance payload prefix: "KOB:I:" (6 bytes, ASCII).
pub const KOB_INSURANCE_PAYLOAD_PREFIX: &[u8] = b"KOB:I:";

/// Build a TX payload for an insurance covenant deploy.
pub fn build_insurance_payload(rs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KOB_INSURANCE_PAYLOAD_PREFIX.len() + rs.len());
    payload.extend_from_slice(KOB_INSURANCE_PAYLOAD_PREFIX);
    payload.extend_from_slice(rs);
    payload
}

/// Parse an insurance payload, returning the RS bytes.
pub fn parse_insurance_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.starts_with(KOB_INSURANCE_PAYLOAD_PREFIX) {
        Some(&payload[KOB_INSURANCE_PAYLOAD_PREFIX.len()..])
    } else {
        None
    }
}

// insurance_offer — Insurer locks coverage KAS with premium/term conditions
//
// State (5 items, 69B):
//   [0x20][owner_spk_hash 32B]     d4 — insurer's SPK hash
//   [0x08][premium_bps 8B]         d3 — premium in basis points (e.g. 200=2%)
//   [0x08][max_duration_daa 8B]    d2 — max loan duration they'll cover
//   [0x08][max_ltv 8B]             d1 — max LTV of insurable loans (e.g. 15000=150%)
//   [0x08][min_coverage 8B]        d0 — minimum coverage amount (sompi)
//
// Dispatch: sigLen-based (3 paths).
//   sigLen < T1 (200)          -> Match (permissionless)
//   T1 <= sigLen < T2 (255)    -> Cancel (owner sig, reclaim)
//   sigLen >= T2               -> Replace (owner sig, new premium)
//
// Sigscript sizes (RS ≈ 69+72=141B, pushData(141) = 143B):
//   Match:   143B                                  [pushData(RS)]
//   Cancel:  66+33+143 = 242B                     [sig, pk, pushData(RS)]
//   Replace: 9+66+33+143 = 251B                   [new_prem, sig, pk, pushData(RS)]
//
// T1=200 separates match(143) from cancel(242)
// T2=248 separates cancel(242) from replace(251)

/// insurance_offer state size: 1*(1+32) + 4*(1+8) = 33 + 36 = 69 bytes.
pub const INSURANCE_OFFER_STATE_SIZE: usize = 33 + 4 * 9; // = 69

/// insurance_offer body bytecode (72 bytes).
///
/// State: [owner_spk_hash 32B][premium_bps 8B][max_duration_daa 8B]
///        [max_ltv 8B][min_coverage 8B] = 69B (5 items)
///
/// Dispatch: sigLen-based (3 paths).
///   sigLen < T1 (200)       -> Match (permissionless)
///   T1 <= sigLen < T2 (248) -> Cancel (owner sig, reclaim)
///   sigLen >= T2            -> Replace (owner sig, update premium)
///
/// Match: verifies output[0].value >= input value (coverage preserved).
///   Minimal verification — matcher handles pairing with loan.
///
/// Cancel: Blake2b(pk) == owner_spk_hash, then CheckSigVerify.
///   Owner reclaims locked coverage.
///
/// Replace: Same auth as cancel + self-continuation check.
///   output[0].spk == input.spk (RS template preserved).
pub const INSURANCE_OFFER_BODY: &[u8] = &[
    // DISPATCH (13B)
    // stack: min_cov(0) max_ltv(1) max_dur(2) prem(3) owner(4) [+ sigscript items]
    0xb9, 0xc9,                   // OpTxInputIndex, OpTxInputScriptSigLen -> sigLen       [2B]
    // stack: sigLen(0) min_cov(1) max_ltv(2) max_dur(3) prem(4) owner(5) ...
    0x76,                         // OpDup                                                  [1B]
    0x02, 0xf8, 0x00,             // push T2=248                                            [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                               [1B]
    0x63,                         // OpIf (match or cancel)                                  [1B]
    // stack: sigLen(0) min_cov(1) max_ltv(2) max_dur(3) prem(4) owner(5) ...
    0x02, 0xc8, 0x00,             // push T1=200                                            [3B]
    0x9f,                         // OpLessThan (sigLen < T1?)                               [1B]
    0x63,                         // OpIf (match)                                            [1B]

    // MATCH PATH (12B)
    // stack: min_cov(0) max_ltv(1) max_dur(2) prem(3) owner(4) [5 items]
    //
    // V1: output[0].value >= input value (coverage preserved)
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out0_val                       [2B]
    // stack: out0_val(0) min_cov(1) max_ltv(2) max_dur(3) prem(4) owner(5) [6]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> in_val                [2B]
    // stack: in_val(0) out0_val(1) min_cov(2) ... owner(6) [7]
    0x7c,                         // OpSwap                                                  [1B]
    0xa2, 0x69,                   // OpGTE OpVerify (out0_val >= in_val)                     [2B]
    // stack: min_cov(0) max_ltv(1) max_dur(2) prem(3) owner(4) [5]
    //
    // Cleanup: 5 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                             [5B]

    // CANCEL PATH (18B)
    0x67,                         // OpElse (T1 <= sigLen < T2: cancel)                     [1B]
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]
    // stack: min_cov(0) max_ltv(1) max_dur(2) prem(3) owner(4) pk(5) sig(6) [7]
    //
    // Owner auth: Blake2b(pk) == owner_spk_hash
    0x55, 0x79,                   // Op5 OpPick -> pk copy (d5=pk)                          [2B]
    // stack: pk_c(0) min_cov(1) ... sig(7) [8]
    0xaa,                         // OpBlake2b -> hash(pk)                                   [1B]
    0x55, 0x79,                   // Op5 OpPick -> owner (d5=owner after pk_c)              [2B]
    // stack: owner_c(0) h(1) min_cov(2) ... sig(8) [9]
    0x87, 0x69,                   // OpEqual OpVerify                                        [2B]
    // stack: min_cov(0) ... owner(4) pk(5) sig(6) [7]
    //
    // Sig verify
    0x56, 0x7a,                   // Op6 OpRoll -> sig to top                               [2B]
    0x56, 0x7a,                   // Op6 OpRoll -> pk to top                                [2B]
    0xad,                         // OpCheckSigVerify                                        [1B]
    // stack: min_cov(0) ... owner(4) [5]
    //
    // Cleanup: 5 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                             [5B]

    // REPLACE PATH (27B)
    0x68,                         // OpEndIf (match vs cancel)                               [1B]
    0x67,                         // OpElse (sigLen >= T2: replace)                          [1B]
    // Sigscript: [pushData(new_prem 8B)][pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]
    // stack: sigLen(0) min_cov(1) max_ltv(2) max_dur(3) prem(4) owner(5) pk(6) sig(7) new_prem(8) [9]
    0x75,                         // OpDrop (sigLen)                                         [1B]
    // stack: min_cov(0) ... owner(4) pk(5) sig(6) new_prem(7) [8]
    //
    // Owner auth: Blake2b(pk) == owner_spk_hash
    0x55, 0x79,                   // Op5 OpPick -> pk copy (d5=pk)                          [2B]
    0xaa,                         // OpBlake2b                                               [1B]
    0x55, 0x79,                   // Op5 OpPick -> owner (d5=owner)                         [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                        [2B]
    // stack: min_cov(0) ... owner(4) pk(5) sig(6) new_prem(7) [8]
    //
    // Sig verify
    0x56, 0x7a,                   // Op6 OpRoll -> sig to top                               [2B]
    0x56, 0x7a,                   // Op6 OpRoll -> pk to top                                [2B]
    0xad,                         // OpCheckSigVerify                                        [1B]
    // stack: min_cov(0) ... owner(4) new_prem(5) [6]
    //
    // Self-continuation: output[0].spk == input.spk
    0x00, 0xc3,                   // Op0 OpTxOutputSpk                                      [2B]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                            [2B]
    0x87, 0x69,                   // OpEqual OpVerify                                        [2B]
    // stack: min_cov(0) ... owner(4) new_prem(5) [6]
    //
    // Cleanup: 5 state + 1 new param = 6 items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                             [5B]
    0x75,                         // OpDrop x1 (6 total)                                     [1B]

    // CLOSING (2B)
    0x68,                         // OpEndIf (outer)                                         [1B]
    0x51,                         // Op1 (TRUE)                                              [1B]
];

/// Expected body length for snapshot test.
#[cfg(test)]
const INSURANCE_OFFER_BODY_EXPECTED_LEN: usize = 72;

// insurance_offer redeemScript builder

/// Build insurance_offer redeemScript (69B state + 72B body = 141B).
///
/// # Arguments
/// * `owner_spk_hash` - 32B Blake2b hash of insurer's SPK
/// * `premium_bps`    - Premium in basis points (e.g. 200 for 2%)
/// * `max_duration_daa` - Max loan duration insurer will cover
/// * `max_ltv`        - Max LTV of loans insurer will cover (e.g. 15000=150%)
/// * `min_coverage`   - Minimum coverage amount in sompi
pub fn build_insurance_offer_redeem_script(
    owner_spk_hash: &[u8; 32],
    premium_bps: u64,
    max_duration_daa: u64,
    max_ltv: u64,
    min_coverage: u64,
) -> crate::Result<Vec<u8>> {
    if premium_bps == 0 {
        return Err(crate::KobError::Contract("premium_bps must be > 0".into()));
    }
    if max_duration_daa == 0 {
        return Err(crate::KobError::Contract("max_duration_daa must be > 0".into()));
    }
    if max_ltv == 0 {
        return Err(crate::KobError::Contract("max_ltv must be > 0".into()));
    }
    if min_coverage == 0 {
        return Err(crate::KobError::Contract("min_coverage must be > 0".into()));
    }

    let body = INSURANCE_OFFER_BODY;
    let mut rs = Vec::with_capacity(INSURANCE_OFFER_STATE_SIZE + body.len());

    // State: pushed in order, first push = deepest on stack
    rs.push(0x20);
    rs.extend_from_slice(owner_spk_hash);                 // d4 (deepest)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(premium_bps));            // d3
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_duration_daa));       // d2
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_ltv));                // d1
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_coverage));           // d0 (top)

    rs.extend_from_slice(body);
    Ok(rs)
}

// insurance_offer sigscript builders

/// Build match sigscript for insurance_offer.
pub fn build_insurance_offer_match_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    push_data(redeem_script)
}

/// Build cancel sigscript for insurance_offer.
pub fn build_insurance_offer_cancel_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(sig);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let rs_pd = push_data(redeem_script);
    let mut ss = Vec::with_capacity(66 + 33 + rs_pd.len());
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pk));
    ss.extend_from_slice(&rs_pd);
    ss
}

/// Build replace sigscript for insurance_offer.
pub fn build_insurance_offer_replace_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    new_premium_bps: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(sig);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let rs_pd = push_data(redeem_script);
    let new_prem_bytes = u64_le(new_premium_bps);
    let mut ss = Vec::with_capacity(9 + 66 + 33 + rs_pd.len());
    // Pushed first = deepest: new_prem is beneath sig/pk
    ss.extend_from_slice(&push_data(&new_prem_bytes));
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pk));
    ss.extend_from_slice(&rs_pd);
    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    // InsuranceOffer body snapshot

    #[test]
    fn insurance_offer_body_exact_length() {
        assert_eq!(
            INSURANCE_OFFER_BODY.len(),
            INSURANCE_OFFER_BODY_EXPECTED_LEN,
            "body length changed — update INSURANCE_OFFER_BODY_EXPECTED_LEN"
        );
    }

    #[test]
    fn insurance_offer_body_ends_with_true() {
        let body = INSURANCE_OFFER_BODY;
        assert_eq!(body[body.len() - 1], 0x51, "body must end with Op1 (TRUE)");
    }

    // InsuranceOffer RS builder

    fn default_insurance_offer_rs() -> Vec<u8> {
        build_insurance_offer_redeem_script(
            &sample_hash(0xAA),
            200,      // 2% premium
            1_000_000, // max duration
            15000,    // max 150% LTV
            100_000,  // min 100K sompi coverage
        ).unwrap()
    }

    #[test]
    fn insurance_offer_rs_length() {
        let rs = default_insurance_offer_rs();
        assert_eq!(rs.len(), INSURANCE_OFFER_STATE_SIZE + INSURANCE_OFFER_BODY.len());
    }

    #[test]
    fn insurance_offer_rs_deterministic() {
        let rs1 = default_insurance_offer_rs();
        let rs2 = default_insurance_offer_rs();
        assert_eq!(rs1, rs2);
    }

    #[test]
    fn insurance_offer_rejects_zero_premium() {
        let r = build_insurance_offer_redeem_script(&sample_hash(0xAA), 0, 1000, 15000, 100);
        assert!(r.is_err());
    }

    #[test]
    fn insurance_offer_rejects_zero_duration() {
        let r = build_insurance_offer_redeem_script(&sample_hash(0xAA), 200, 0, 15000, 100);
        assert!(r.is_err());
    }

    #[test]
    fn insurance_offer_rejects_zero_ltv() {
        let r = build_insurance_offer_redeem_script(&sample_hash(0xAA), 200, 1000, 0, 100);
        assert!(r.is_err());
    }

    #[test]
    fn insurance_offer_rejects_zero_coverage() {
        let r = build_insurance_offer_redeem_script(&sample_hash(0xAA), 200, 1000, 15000, 0);
        assert!(r.is_err());
    }

    // InsuranceOffer sigscript sizes

    #[test]
    fn insurance_offer_match_sigscript_size() {
        let rs = default_insurance_offer_rs();
        let ss = build_insurance_offer_match_sigscript(&rs);
        // RS <= 255 → pushData1: 2 + rs.len()
        assert_eq!(ss.len(), push_data(&rs).len());
        // Verify it's below T1=200? No, it's 141B → push is 143B < 200. Good.
        assert!(ss.len() < 200, "match sigscript must be < T1=200");
    }

    #[test]
    fn insurance_offer_cancel_sigscript_size() {
        let rs = default_insurance_offer_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];
        let ss = build_insurance_offer_cancel_sigscript(&fake_sig, &fake_pk, &rs);
        let rs_pd_len = push_data(&rs).len();
        assert_eq!(ss.len(), 66 + 33 + rs_pd_len);
        assert!(ss.len() >= 200 && ss.len() < 248, "cancel sigscript must be in [T1, T2)");
    }

    #[test]
    fn insurance_offer_replace_sigscript_size() {
        let rs = default_insurance_offer_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];
        let ss = build_insurance_offer_replace_sigscript(&fake_sig, &fake_pk, 300, &rs);
        let rs_pd_len = push_data(&rs).len();
        assert_eq!(ss.len(), 9 + 66 + 33 + rs_pd_len);
        assert!(ss.len() >= 248, "replace sigscript must be >= T2=248");
    }

    // InsuranceOffer dispatch thresholds

    #[test]
    fn insurance_offer_dispatch_thresholds_valid() {
        let rs = default_insurance_offer_rs();
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];

        let match_len = build_insurance_offer_match_sigscript(&rs).len();
        let cancel_len = build_insurance_offer_cancel_sigscript(&fake_sig, &fake_pk, &rs).len();
        let replace_len = build_insurance_offer_replace_sigscript(&fake_sig, &fake_pk, 300, &rs).len();

        // T1=200, T2=248
        assert!(match_len < 200, "match({match_len}) must be < T1=200");
        assert!(cancel_len >= 200 && cancel_len < 248,
            "cancel({cancel_len}) must be in [200, 248)");
        assert!(replace_len >= 248, "replace({replace_len}) must be >= T2=248");
    }
}
