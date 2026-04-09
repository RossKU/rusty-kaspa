//! P2P Lending covenants for KOB (Kaspa Order Book).
//!
//! `loan_offer`: Lender locks principal KAS with rate/collateral terms.
//! `borrow_request`: Borrower locks collateral with desired loan terms.
//! `active_loan`: Matched loan — repay, default claim, liquidation paths.

pub mod loan_offer;
pub mod borrow_request;
pub mod active_loan;
pub mod parse;

pub use loan_offer::*;
pub use borrow_request::*;
pub use active_loan::*;
pub use parse::*;

/// DAA scores per year: 10 BPS * 86400 sec * 365 days.
pub const DAA_PER_YEAR: u64 = 315_360_000;

/// KOB lending payload prefix: "KOB:L:" (6 bytes, ASCII).
pub const KOB_LENDING_PAYLOAD_PREFIX: &[u8] = b"KOB:L:";

/// Build a TX payload for a lending covenant deploy.
///
/// Format: `KOB:L:` + redeemScript bytes.
pub fn build_lending_payload(rs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KOB_LENDING_PAYLOAD_PREFIX.len() + rs.len());
    payload.extend_from_slice(KOB_LENDING_PAYLOAD_PREFIX);
    payload.extend_from_slice(rs);
    payload
}

/// Parse a KOB lending payload, stripping the `KOB:L:` prefix.
///
/// Returns `None` if the payload doesn't start with the lending prefix.
pub fn parse_lending_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < KOB_LENDING_PAYLOAD_PREFIX.len() {
        return None;
    }
    if &payload[..KOB_LENDING_PAYLOAD_PREFIX.len()] != KOB_LENDING_PAYLOAD_PREFIX {
        return None;
    }
    Some(&payload[KOB_LENDING_PAYLOAD_PREFIX.len()..])
}

#[cfg(test)]
mod tests;
