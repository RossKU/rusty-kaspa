//! Generic chain-settlement plumbing: on-chain-existence cache, local
//! spent-outpoint tracking, wallet UTXO fetch, storage-mass pre-check, and
//! RPC transaction-payload builders. Zero order-book / covenant-order
//! domain logic — extracted from `kob-engine`'s chain executor and deploy
//! modules (the pieces with zero `kob_domain` references).
//!
//! Phase 2 adds `payment_observer` and `replay_store` alongside these.

pub mod cache;
pub mod deploy;

pub use cache::{
    CovenantCache, SpentEntry, SpentTracker,
    MempoolProbe, RpcMempoolProbe,
    fetch_wallet_utxos, check_mass_presubmit,
    FAILED_OUTPOINT_COOLDOWN_SECS, TRANSIENT_COOLDOWN_SECS, SPENT_PRUNE_AGE_SECS,
    SPENT_PRUNE_HARD_MAX_AGE_SECS, INVALID_COVENANT_TTL_SECS, COVENANT_CACHE_VALID_MAX,
};
