//! Parse lending redeemScripts to extract on-chain state.

/// Lending order type: Offer (lender) or Request (borrower).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LendingOrderType {
    /// LoanOffer: lender locks principal KAS.
    Offer,
    /// BorrowRequest: borrower locks collateral.
    Request,
}

/// Parsed lending order from redeemScript.
#[derive(Debug, Clone)]
pub struct ParsedLendingOrder {
    pub order_type: LendingOrderType,
    pub value: u64,
    pub owner_spk_hash: [u8; 32],
    /// For Offer: principal. For Request: desired_amount.
    pub amount: u64,
    /// For Offer: rate_num. For Request: max_rate_num.
    pub rate_num: u64,
    /// For Offer: rate_den. For Request: max_rate_den.
    pub rate_den: u64,
    /// For Offer: min_collateral_ratio. For Request: 0.
    pub min_collateral_ratio: u64,
    /// For Offer: max_duration_daa. For Request: min_duration_daa.
    pub duration_daa: u64,
    /// Accepted/required collateral covenant ID (32 bytes).
    pub collateral_cov_id: [u8; 32],
    /// Rate mode: 0=fixed, 1=variable, 2=either (Request only).
    pub rate_mode: u64,
    /// For Offer: rate_floor_num (lender protection). For Request: 0.
    pub rate_floor_num: u64,
    /// For Request: rate_cap_num (borrower protection). For Offer: 0.
    pub rate_cap_num: u64,
    pub redeem_script: Vec<u8>,
    /// Owner's full scriptPublicKey (hex-encoded).
    /// Populated by the scanner after RS parsing, not by the parse function itself.
    pub owner_spk: Option<String>,
}

/// LoanOffer encoded state size (with push prefixes).
const LOAN_OFFER_STATE_SIZE: usize = 2 * 33 + 7 * 9; // = 129
/// LoanOffer body size.
const LOAN_OFFER_BODY_SIZE: usize = 85;
/// LoanOffer total RS size.
pub const LOAN_OFFER_RS_SIZE: usize = LOAN_OFFER_STATE_SIZE + LOAN_OFFER_BODY_SIZE; // 214

/// BorrowRequest encoded state size (with push prefixes).
const BORROW_REQUEST_STATE_SIZE: usize = 2 * 33 + 6 * 9; // = 120
/// BorrowRequest body size.
const BORROW_REQUEST_BODY_SIZE: usize = 82;
/// BorrowRequest total RS size.
pub const BORROW_REQUEST_RS_SIZE: usize = BORROW_REQUEST_STATE_SIZE + BORROW_REQUEST_BODY_SIZE; // 202

/// Parse a lending redeemScript (LoanOffer or BorrowRequest).
///
/// Distinguished by RS length:
///   - 214B = LoanOffer
///   - 202B = BorrowRequest
pub fn parse_lending_rs(rs: &[u8], value: u64) -> Option<ParsedLendingOrder> {
    match rs.len() {
        LOAN_OFFER_RS_SIZE => parse_loan_offer(rs, value),
        BORROW_REQUEST_RS_SIZE => parse_borrow_request(rs, value),
        _ => None,
    }
}

/// Parse LoanOffer state.
fn parse_loan_offer(rs: &[u8], value: u64) -> Option<ParsedLendingOrder> {
    let body_start = LOAN_OFFER_STATE_SIZE;
    if rs[body_start] != 0xb9 || rs[body_start + 1] != 0xc9 {
        return None;
    }

    if rs[0] != 0x20 { return None; }
    if rs[33] != 0x08 || rs[42] != 0x08 || rs[51] != 0x08 { return None; }
    if rs[60] != 0x08 || rs[69] != 0x08 { return None; }
    if rs[78] != 0x20 { return None; }
    if rs[111] != 0x08 || rs[120] != 0x08 { return None; }

    let mut owner_spk_hash = [0u8; 32];
    owner_spk_hash.copy_from_slice(&rs[1..33]);

    let principal = u64::from_le_bytes(rs[34..42].try_into().ok()?);
    let rate_num = u64::from_le_bytes(rs[43..51].try_into().ok()?);
    let rate_den = u64::from_le_bytes(rs[52..60].try_into().ok()?);
    let min_collateral_ratio = u64::from_le_bytes(rs[61..69].try_into().ok()?);
    let max_duration_daa = u64::from_le_bytes(rs[70..78].try_into().ok()?);

    let mut collateral_cov_id = [0u8; 32];
    collateral_cov_id.copy_from_slice(&rs[79..111]);

    let rate_mode = u64::from_le_bytes(rs[112..120].try_into().ok()?);
    let rate_floor_num = u64::from_le_bytes(rs[121..129].try_into().ok()?);

    if principal == 0 || rate_den == 0 {
        return None;
    }

    Some(ParsedLendingOrder {
        order_type: LendingOrderType::Offer,
        value,
        owner_spk_hash,
        amount: principal,
        rate_num,
        rate_den,
        min_collateral_ratio,
        duration_daa: max_duration_daa,
        collateral_cov_id,
        rate_mode,
        rate_floor_num,
        rate_cap_num: 0,
        redeem_script: rs.to_vec(),
        owner_spk: None,
    })
}

/// Parse BorrowRequest state.
fn parse_borrow_request(rs: &[u8], value: u64) -> Option<ParsedLendingOrder> {
    let body_start = BORROW_REQUEST_STATE_SIZE;
    if rs[body_start] != 0xb9 || rs[body_start + 1] != 0xc9 {
        return None;
    }

    if rs[0] != 0x20 { return None; }
    if rs[33] != 0x08 || rs[42] != 0x08 || rs[51] != 0x08 { return None; }
    if rs[60] != 0x08 { return None; }
    if rs[69] != 0x20 { return None; }
    if rs[102] != 0x08 || rs[111] != 0x08 { return None; }

    let mut owner_spk_hash = [0u8; 32];
    owner_spk_hash.copy_from_slice(&rs[1..33]);

    let desired_amount = u64::from_le_bytes(rs[34..42].try_into().ok()?);
    let max_rate_num = u64::from_le_bytes(rs[43..51].try_into().ok()?);
    let max_rate_den = u64::from_le_bytes(rs[52..60].try_into().ok()?);
    let min_duration_daa = u64::from_le_bytes(rs[61..69].try_into().ok()?);

    let mut collateral_cov_id = [0u8; 32];
    collateral_cov_id.copy_from_slice(&rs[70..102]);

    let rate_mode = u64::from_le_bytes(rs[103..111].try_into().ok()?);
    let rate_cap_num = u64::from_le_bytes(rs[112..120].try_into().ok()?);

    if desired_amount == 0 || max_rate_den == 0 {
        return None;
    }

    Some(ParsedLendingOrder {
        order_type: LendingOrderType::Request,
        value,
        owner_spk_hash,
        amount: desired_amount,
        rate_num: max_rate_num,
        rate_den: max_rate_den,
        min_collateral_ratio: 0,
        duration_daa: min_duration_daa,
        collateral_cov_id,
        rate_mode,
        rate_floor_num: 0,
        rate_cap_num,
        redeem_script: rs.to_vec(),
        owner_spk: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lending::{build_loan_offer_redeem_script, build_borrow_request_redeem_script};

    #[test]
    fn roundtrip_loan_offer() {
        let owner = [0xBB; 32];
        let collateral = [0x00; 32];
        let rs = build_loan_offer_redeem_script(
            &owner, 10_000_000, 500, 10_000, 15_000, 315_360_000, &collateral, 0, 0,
        ).unwrap();
        assert_eq!(rs.len(), LOAN_OFFER_RS_SIZE);

        let parsed = parse_lending_rs(&rs, 10_000_000).expect("should parse");
        assert_eq!(parsed.order_type, LendingOrderType::Offer);
        assert_eq!(parsed.owner_spk_hash, owner);
        assert_eq!(parsed.amount, 10_000_000);
        assert_eq!(parsed.rate_num, 500);
        assert_eq!(parsed.rate_den, 10_000);
        assert_eq!(parsed.min_collateral_ratio, 15_000);
        assert_eq!(parsed.duration_daa, 315_360_000);
        assert_eq!(parsed.collateral_cov_id, collateral);
    }

    #[test]
    fn roundtrip_borrow_request() {
        let owner = [0xCC; 32];
        let collateral = [0x00; 32];
        let rs = build_borrow_request_redeem_script(
            &owner, 5_000_000, 1_000, 10_000, 100_000, &collateral, 0, 0,
        ).unwrap();
        assert_eq!(rs.len(), BORROW_REQUEST_RS_SIZE);

        let parsed = parse_lending_rs(&rs, 8_000_000).expect("should parse");
        assert_eq!(parsed.order_type, LendingOrderType::Request);
        assert_eq!(parsed.amount, 5_000_000);
        assert_eq!(parsed.rate_num, 1_000);
        assert_eq!(parsed.rate_den, 10_000);
    }

    #[test]
    fn wrong_size_returns_none() {
        assert!(parse_lending_rs(&vec![0u8; 100], 0).is_none());
    }
}
