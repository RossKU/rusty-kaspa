//! C-c: `TxSubmitter` three-lane submission abstraction
//! (kob/TIME_CONTRACTS_DESIGN.md §7 Stage-C addenda).
//!
//! Lanes:
//!   - `Urgent` — immediate fee-paying RPC submission (`submitTransaction`),
//!     the only lane with a live backend today;
//!   - `Free`   — the receiving port for the future miner-engine mode
//!     (fee-0 settles included in self-mined blocks). The mode itself is
//!     OUT of Stage C (separate track, touches node/mining code), so this
//!     lane reports `FreeLaneUnavailable` — callers selecting it explicitly
//!     get a typed error, never a silent fee-paying submit;
//!   - `Auto`   — per-tx default: falls back Urgent → Free. With the Free
//!     lane unavailable this resolves to Urgent, but the fallback ORDER is
//!     part of the frozen design (the miner-engine track plugs in behind
//!     the same call sites without touching them).
//!
//! Per-tx lane selection: every submit call names its lane. The engine
//! executor passes `AppConfig::submit_lane` (deployment default) per tx;
//! future callers (e.g. an owner-cancel path wanting Urgent while settles
//! ride Free) select per call.

use crate::rpc::{RpcClient, SubmitResult};

/// Submission lane for one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TxLane {
    /// Immediate fee-paying RPC submission.
    Urgent,
    /// Fee-0 settle via self-mined blocks (miner-engine mode; NOT live in
    /// Stage C — selecting it yields `FreeLaneUnavailable`).
    Free,
    /// Urgent → Free fallback (the default).
    #[default]
    Auto,
}

impl TxLane {
    /// Parse a lane name (config/env surface). Unknown names -> None.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "urgent" => Some(TxLane::Urgent),
            "free" => Some(TxLane::Free),
            "auto" => Some(TxLane::Auto),
            _ => None,
        }
    }
}

/// The error message returned when the Free lane is selected while the
/// miner-engine mode is not wired (kept greppable/stable for callers).
pub const FREE_LANE_UNAVAILABLE: &str =
    "FreeLaneUnavailable: miner-engine mode is not wired (separate track); \
     use lane=urgent or lane=auto";

/// Three-lane transaction submitter (stateless facade over `RpcClient`).
pub struct TxSubmitter;

impl TxSubmitter {
    /// Submit `payload` on `lane`.
    ///
    /// `Urgent`: one `submitTransaction` RPC call.
    /// `Free`: typed unavailability error (Stage-C scope boundary).
    /// `Auto`: try Urgent; if the urgent TRANSPORT fails (RPC-level `Err`,
    /// not a node-side tx rejection carried in `SubmitResult`), fall back to
    /// the Free lane — which, until the miner-engine track lands, reports
    /// unavailable, so the original urgent error is returned. A node-side
    /// rejection (`SubmitResult.ok == false`) is NOT retried on another
    /// lane: the tx itself is invalid/raced and lane-hopping cannot fix it.
    pub async fn submit(
        rpc: &RpcClient,
        payload: serde_json::Value,
        lane: TxLane,
    ) -> Result<SubmitResult, String> {
        match lane {
            TxLane::Urgent => rpc.submit_transaction(payload).await,
            TxLane::Free => Err(FREE_LANE_UNAVAILABLE.to_string()),
            TxLane::Auto => match rpc.submit_transaction(payload.clone()).await {
                Ok(r) => Ok(r),
                Err(urgent_err) => {
                    // Fallback Urgent -> Free (design C-c). The Free lane is
                    // not live yet, so surface the urgent error with the
                    // fallback outcome appended for the log trail.
                    Err(format!(
                        "{} (auto-fallback to free lane failed: {})",
                        urgent_err, FREE_LANE_UNAVAILABLE
                    ))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_parse_roundtrip() {
        assert_eq!(TxLane::parse("urgent"), Some(TxLane::Urgent));
        assert_eq!(TxLane::parse("FREE"), Some(TxLane::Free));
        assert_eq!(TxLane::parse("Auto"), Some(TxLane::Auto));
        assert_eq!(TxLane::parse("miner"), None);
        assert_eq!(TxLane::default(), TxLane::Auto);
    }
}
