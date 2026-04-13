//! Prediction market covenants for KOB (Kaspa Order Book).
//!
//! Tokenized binary prediction market on Kaspa L1 covenants.
//! Settlement secured by PoW consensus — no external oracle.

pub mod ballot_box;
pub mod parse;
pub mod redemption;
pub mod split_merge;
pub mod market;
pub mod vote_receipt;

pub use ballot_box::*;
pub use parse::*;
pub use redemption::*;
pub use split_merge::*;
pub use market::*;
pub use vote_receipt::*;

/// Minimum counting unit for BallotBox votes (2 sompi).
pub const VOTE_COUNTER_UNIT: u64 = 2;

/// Minimum total votes (across both BallotBoxes) for dispute-mode settlement.
/// At 10 BPS, 1024 votes ≈ 102 seconds of continuous voting.
pub const DISPUTE_THRESHOLD: u64 = 1024;

/// KOB prediction market payload prefix: "KOB:M:" (6 bytes, ASCII).
/// 'M' for Market. Distinguished from spot (KOB:2:) and perp (KOB:P:).
pub const KOB_PREDICTION_PAYLOAD_PREFIX: &[u8] = b"KOB:M:";

/// Build a TX payload for prediction market covenant deploy.
pub fn build_prediction_payload(rs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KOB_PREDICTION_PAYLOAD_PREFIX.len() + rs.len());
    payload.extend_from_slice(KOB_PREDICTION_PAYLOAD_PREFIX);
    payload.extend_from_slice(rs);
    payload
}

/// Parse a KOB prediction payload, stripping the `KOB:M:` prefix.
pub fn parse_prediction_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < KOB_PREDICTION_PAYLOAD_PREFIX.len() {
        return None;
    }
    if &payload[..KOB_PREDICTION_PAYLOAD_PREFIX.len()] != KOB_PREDICTION_PAYLOAD_PREFIX {
        return None;
    }
    Some(&payload[KOB_PREDICTION_PAYLOAD_PREFIX.len()..])
}

#[cfg(test)]
mod tests;
