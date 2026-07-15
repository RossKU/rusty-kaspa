//! Generic on-chain-existence cache and local-spend tracker.
//!
//! Extracted from `kob-engine`'s chain executor (the covenant-order matching
//! loop). This piece is domain-free: `CovenantCache` just remembers which
//! 32-byte IDs have been seen to exist on-chain (originally used for KOB
//! token covenant IDs, but the check itself has no order-book coupling), and
//! `SpentTracker` just remembers which outpoints this process has already
//! consumed in a submitted-but-not-yet-confirmed transaction so it doesn't
//! double-spend against its own in-flight submissions. Both are reused by
//! the x402 facilitator's settlement path (Phase 2+).

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tracing::{error, info};

use crate::rpc::{RpcClient, RpcUtxo};

/// Default cooldown for permanently failed outpoints (seconds).
/// Script verification failures, mass violations, etc.
pub const FAILED_OUTPOINT_COOLDOWN_SECS: u64 = 30;

/// Cooldown for transient failures (seconds).
/// CSV sequence-lock rejections resolve after ~5s (50 DAA at 10 BPS).
/// Short cooldown prevents submit spam while allowing prompt retry.
pub const TRANSIENT_COOLDOWN_SECS: u64 = 6;

/// Spent-tracker prune threshold in seconds (H-1 safety net only).
///
/// The primary cleanup path is a caller-driven `remove_spent_for_txids()`
/// call as soon as a TX lands in a block (or gets reorged). This timeout
/// only matters for self-submitted TXs that drop out of the mempool without
/// ever confirming (e.g. fee too low, node rejection that wasn't caught).
pub const SPENT_PRUNE_AGE_SECS: u64 = 600;

/// Hard cap for spent-tracker entry age (seconds).
///
/// `prune_spent()` normally preserves aged entries whose associated
/// `submit_txid` is still in the mempool (preventing the scenario where a
/// 600s-dwelling TX gets its inputs pruned, the caller re-uses them, and the
/// node rejects with "already spent ... in the mempool"). If the RPC
/// mempool check continually reports "in mempool" for a given txid due to a
/// bug or malicious node, fall back to a hard cap so the tracker cannot grow
/// without bound.
///
/// 2 hours >> any realistic mempool dwell time; by this point the TX is
/// surely dead.
pub const SPENT_PRUNE_HARD_MAX_AGE_SECS: u64 = 7200;

/// TTL for entries in the invalid-ID cache (seconds).
///
/// Entities may come into existence after they're first looked up, so
/// invalid entries expire and trigger a fresh RPC re-check on the next
/// encounter.
pub const INVALID_COVENANT_TTL_SECS: u64 = 300; // 5 minutes

/// Maximum entries in the `CovenantCache` `valid` set before eviction.
/// When exceeded, the entire valid set is cleared and re-verified on demand
/// (cache miss -> pending -> RPC check).
pub const COVENANT_CACHE_VALID_MAX: usize = 50_000;

/// On-chain existence verification cache for 32-byte (hex-encoded) IDs —
/// e.g. covenant IDs.
///
/// Prevents a caller from accepting a reference to a fake/non-existent ID.
/// Once an ID is verified on-chain, it is permanently cached (`valid`).
/// Unverifiable IDs are cached with a TTL (`invalid`) so newly-created
/// entities can be picked up after the TTL expires.
///
/// Verification flow (async, driven by the caller):
///   1. The caller encounters an unknown ID and collects it into
///      `pending_checks` via `check()`.
///   2. After the synchronous pass completes, the caller queries the node
///      RPC (e.g., `getUtxosByAddresses`) to verify each pending ID.
///   3. Verified IDs are moved to `valid` via `mark_valid()`; unverifiable
///      ones go to `invalid` via `mark_invalid()`.
///   4. On the next pass, references with a now-valid ID pass through.
pub struct CovenantCache {
    /// IDs confirmed to exist on-chain. Permanent (on-chain entities don't
    /// get un-created).
    valid: HashSet<String>,
    /// IDs that failed on-chain verification, with expiry timestamp.
    /// Entries older than `INVALID_COVENANT_TTL_SECS` are pruned on access.
    invalid: HashMap<String, Instant>,
    /// IDs encountered during the current pass that are not in either
    /// cache. Populated by the synchronous caller, drained by the async
    /// verification step.
    pending_checks: Vec<String>,
}

impl Default for CovenantCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CovenantCache {
    pub fn new() -> Self {
        Self {
            valid: HashSet::new(),
            invalid: HashMap::new(),
            pending_checks: Vec::new(),
        }
    }

    /// Pre-seed a known-good ID (e.g., from config at startup).
    pub fn seed_valid(&mut self, cov_id: &str) {
        if cov_id.len() == 64 {
            if self.valid.len() >= COVENANT_CACHE_VALID_MAX {
                tracing::warn!(
                    "[COVENANT] Valid cache reached {} entries during seed, clearing (M8)",
                    self.valid.len()
                );
                self.valid.clear();
            }
            self.valid.insert(cov_id.to_string());
        }
    }

    /// Returns `true` if the ID is in the permanent valid set.
    pub fn is_valid(&self, cov_id: &str) -> bool {
        self.valid.contains(cov_id)
    }

    /// Number of entries in the permanent valid set (for logging/metrics).
    pub fn valid_len(&self) -> usize {
        self.valid.len()
    }

    /// Number of entries in the TTL'd invalid set (for logging/metrics).
    /// Not pruned by this call — includes expired entries until the next
    /// `prune_expired()`.
    pub fn invalid_len(&self) -> usize {
        self.invalid.len()
    }

    /// Returns `true` if the ID is in the invalid cache and the entry has
    /// not expired.
    pub fn is_invalid(&self, cov_id: &str) -> bool {
        if let Some(when) = self.invalid.get(cov_id) {
            when.elapsed().as_secs() < INVALID_COVENANT_TTL_SECS
        } else {
            false
        }
    }

    /// Check an ID against the cache. Returns:
    /// - `Some(true)` if known valid
    /// - `Some(false)` if known invalid (and not expired)
    /// - `None` if unknown (needs RPC verification)
    pub fn check(&mut self, cov_id: &str) -> Option<bool> {
        if self.valid.contains(cov_id) {
            return Some(true);
        }
        if self.is_invalid(cov_id) {
            return Some(false);
        }
        // Unknown: prune expired invalid entry if present, collect for async check
        self.invalid.remove(cov_id);
        if !self.pending_checks.iter().any(|id| id == cov_id) {
            self.pending_checks.push(cov_id.to_string());
        }
        None
    }

    /// Mark an ID as verified on-chain (permanent).
    ///
    /// If the valid cache exceeds `COVENANT_CACHE_VALID_MAX`, it is cleared
    /// first. This prevents unbounded growth (M8). Cleared entries will be
    /// re-verified on demand (cache miss -> pending_checks -> RPC).
    pub fn mark_valid(&mut self, cov_id: &str) {
        self.invalid.remove(cov_id);
        if self.valid.len() >= COVENANT_CACHE_VALID_MAX {
            tracing::warn!(
                "[COVENANT] Valid cache reached {} entries, clearing (M8)",
                self.valid.len()
            );
            self.valid.clear();
        }
        self.valid.insert(cov_id.to_string());
    }

    /// Mark an ID as not found on-chain (TTL-based).
    pub fn mark_invalid(&mut self, cov_id: &str) {
        self.invalid.insert(cov_id.to_string(), Instant::now());
    }

    /// Drain pending IDs that need async RPC verification.
    pub fn take_pending(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_checks)
    }

    /// Prune expired entries from the invalid cache.
    pub fn prune_expired(&mut self) {
        self.invalid.retain(|_, when| {
            when.elapsed().as_secs() < INVALID_COVENANT_TTL_SECS
        });
    }
}

/// Probes the node mempool to check whether a transaction is still pending.
///
/// Abstracted behind a trait so unit tests can inject a deterministic probe
/// without instantiating a full RpcClient + WebSocket.
pub trait MempoolProbe {
    /// Returns true if the given txid is currently in the node's mempool
    /// (or orphan pool). RPC errors are treated as "absent".
    fn is_in_mempool<'a>(
        &'a self,
        txid: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

/// Production mempool probe backed by a live `RpcClient`.
///
/// Calls `getMempoolEntry` with `includeOrphanPool=true`. Non-null
/// `mempoolEntry` in the response means the tx is still pending.
pub struct RpcMempoolProbe<'a> {
    pub rpc: &'a RpcClient,
}

impl<'b> MempoolProbe for RpcMempoolProbe<'b> {
    fn is_in_mempool<'a>(
        &'a self,
        txid: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self
                .rpc
                .call(
                    "getMempoolEntry",
                    serde_json::json!({
                        "transactionId": txid,
                        "includeOrphanPool": true,
                        "filterTransactionPool": false,
                    }),
                )
                .await
            {
                Ok(v) => {
                    // kaspad returns {"mempoolEntry": {...}} on hit, or an
                    // error when not found. Treat a non-null mempoolEntry
                    // as "in mempool". Some servers nest the entry under
                    // `entry` instead -- accept either.
                    let has_entry = v
                        .get("mempoolEntry")
                        .map(|e| !e.is_null())
                        .unwrap_or(false)
                        || v.get("entry")
                            .map(|e| !e.is_null())
                            .unwrap_or(false);
                    has_entry
                }
                Err(_) => false,
            }
        })
    }
}

/// An entry in the SpentTracker `spent` map.
#[derive(Debug, Clone)]
pub struct SpentEntry {
    /// Timestamp when the outpoint was first marked spent.
    pub when: Instant,
    /// The txid of the self-submitted transaction that spent this outpoint.
    ///
    /// Populated by `mark_submitted()` after a successful RPC submit.
    /// Empty string means "unknown" (entry inserted via `mark_spent()` only,
    /// which happens before the submit lands — in rare cases the submit
    /// may have failed between mark_spent and mark_submitted, or the entry
    /// came from an old-style call site that never learned its txid).
    /// Empty-txid entries are treated as "mempool-unverifiable" and are
    /// pruned purely by age.
    pub submit_txid: String,
}

/// Tracks outpoints that have been used locally (spent in submitted TXs)
/// to avoid selecting stale UTXOs before mempool catches up.
#[derive(Debug)]
pub struct SpentTracker {
    /// Outpoints (txid:index) that were used as inputs in recently submitted TXs,
    /// with the timestamp when they were marked spent and the submit txid
    /// (if known) to allow mempool-aware pruning.
    pub spent: HashMap<String, SpentEntry>,
    /// Outpoints (txid:index) that were created as outputs in recently submitted TXs.
    /// These may become available once the TX propagates.
    pub pending_outputs: Vec<(String, u64)>, // (outpoint_key, value)
    /// Outpoints that failed during TX submission, with cooldown expiry.
    /// These are temporarily excluded from re-use to prevent infinite retry loops.
    pub failed: HashMap<String, Instant>,
    /// Cooldown duration for failed outpoints.
    pub cooldown_secs: u64,
}

impl Default for SpentTracker {
    fn default() -> Self {
        Self {
            spent: HashMap::new(),
            pending_outputs: Vec::new(),
            failed: HashMap::new(),
            cooldown_secs: FAILED_OUTPOINT_COOLDOWN_SECS,
        }
    }
}

impl SpentTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a SpentTracker with a custom cooldown duration (for testing).
    pub fn with_cooldown(secs: u64) -> Self {
        Self {
            cooldown_secs: secs,
            ..Self::default()
        }
    }

    /// Mark an outpoint as spent (used as input in a submitted TX).
    ///
    /// The `submit_txid` field is left empty; callers that have the txid
    /// available (the common case — all spent outpoints are marked on the
    /// success path of `submit_transaction`) should call `mark_submitted()`
    /// afterwards to populate it. This two-step API keeps existing call
    /// sites unchanged.
    pub fn mark_spent(&mut self, outpoint_key: &str) {
        self.spent.insert(
            outpoint_key.to_string(),
            SpentEntry {
                when: Instant::now(),
                submit_txid: String::new(),
            },
        );
    }

    /// Associate a set of recently-marked outpoints with their submit txid.
    ///
    /// Called right after a successful `rpc.submit_transaction` that
    /// includes these outpoints as inputs. This enables `prune_spent()` to
    /// query the mempool and preserve entries whose TX is still pending
    /// (preventing the "already spent in mempool" re-submit loop when the
    /// 600s age-based prune fires on a still-dwelling TX).
    ///
    /// Keys that are not already in the spent map are inserted as a
    /// defensive measure. Keys already carrying a submit_txid are
    /// overwritten (idempotent across retries).
    pub fn mark_submitted(&mut self, submit_txid: &str, outpoint_keys: &[String]) {
        let now = Instant::now();
        for key in outpoint_keys {
            match self.spent.get_mut(key) {
                Some(entry) => {
                    entry.submit_txid = submit_txid.to_string();
                }
                None => {
                    // Defensive: caller associated a txid with a key that
                    // wasn't marked spent. Insert a fresh entry rather than
                    // silently dropping, so this path still benefits from
                    // mempool-aware pruning.
                    self.spent.insert(
                        key.clone(),
                        SpentEntry {
                            when: now,
                            submit_txid: submit_txid.to_string(),
                        },
                    );
                }
            }
        }
    }

    /// Mark an outpoint as permanently failed (TX submission rejected).
    /// The outpoint will be excluded from re-use for `cooldown_secs` seconds.
    pub fn mark_failed(&mut self, outpoint_key: &str) {
        self.failed.insert(
            outpoint_key.to_string(),
            Instant::now(),
        );
    }

    /// Mark an outpoint as transiently failed (e.g. CSV sequence-lock not yet met).
    /// Uses a short cooldown so a caller can retry soon.
    pub fn mark_transient(&mut self, outpoint_key: &str) {
        // Backdate the insertion so it expires after TRANSIENT_COOLDOWN_SECS
        // instead of the full cooldown_secs.
        let backdate = self.cooldown_secs.saturating_sub(TRANSIENT_COOLDOWN_SECS);
        self.failed.insert(
            outpoint_key.to_string(),
            Instant::now() - std::time::Duration::from_secs(backdate),
        );
    }

    /// Check if an outpoint is locally tracked as spent or under cooldown.
    pub fn is_spent(&self, outpoint_key: &str) -> bool {
        if self.spent.contains_key(outpoint_key) {
            return true;
        }
        self.is_failed(outpoint_key)
    }

    /// Check if an outpoint is under failure cooldown.
    pub fn is_failed(&self, outpoint_key: &str) -> bool {
        if let Some(when) = self.failed.get(outpoint_key) {
            when.elapsed().as_secs() < self.cooldown_secs
        } else {
            false
        }
    }

    /// Expire stale failure entries whose cooldown has elapsed.
    pub fn expire_failed(&mut self) {
        self.failed.retain(|_, when| when.elapsed().as_secs() < self.cooldown_secs);
    }

    /// Prune spent entries older than the given age (M-6).
    ///
    /// Mempool-aware variant: entries older than `max_age_secs` are inspected;
    /// for each unique `submit_txid` found among them, the mempool is queried
    /// (via `getMempoolEntry` with `includeOrphanPool=true`). If the TX is
    /// still pending, its associated spent-entries are retained -- pruning
    /// them would cause a caller to re-use those inputs, triggering
    /// "already spent ... in the mempool" rejections from kaspad in a
    /// retry loop until the TX eventually confirms (or the process exits).
    ///
    /// Entries with an empty `submit_txid` (old-style, or inserted without
    /// a follow-up `mark_submitted`) fall through to pure age-based pruning.
    ///
    /// Safety valve: entries older than `SPENT_PRUNE_HARD_MAX_AGE_SECS` are
    /// pruned unconditionally regardless of what the mempool reports. This
    /// protects against unbounded growth if the RPC is broken or lying.
    pub async fn prune_spent(&mut self, max_age_secs: u64, rpc: &RpcClient) {
        self.prune_spent_with_probe(max_age_secs, &RpcMempoolProbe { rpc })
            .await;
    }

    /// Testable variant of `prune_spent()` that accepts any mempool probe.
    ///
    /// Public so callers outside this crate (e.g. kob-engine's executor
    /// tests) can swap in a deterministic probe without needing a full
    /// RpcClient / WebSocket harness.
    pub async fn prune_spent_with_probe<P: MempoolProbe>(
        &mut self,
        max_age_secs: u64,
        probe: &P,
    ) {
        // 1. Collect aged entries and the unique txids they reference.
        let mut aged_keys: Vec<String> = Vec::new();
        let mut hard_expired_keys: Vec<String> = Vec::new();
        let mut aged_txids: HashSet<String> = HashSet::new();
        for (key, entry) in self.spent.iter() {
            let age = entry.when.elapsed().as_secs();
            if age >= SPENT_PRUNE_HARD_MAX_AGE_SECS {
                hard_expired_keys.push(key.clone());
            } else if age >= max_age_secs {
                aged_keys.push(key.clone());
                if !entry.submit_txid.is_empty() {
                    aged_txids.insert(entry.submit_txid.clone());
                }
            }
        }

        if aged_keys.is_empty() && hard_expired_keys.is_empty() {
            return;
        }

        // 2. Query mempool for each unique txid.
        //    tx still in mempool => retain its spent entries.
        let mut txids_in_mempool: HashSet<String> = HashSet::new();
        for txid in aged_txids.iter() {
            if probe.is_in_mempool(txid).await {
                txids_in_mempool.insert(txid.clone());
            }
        }

        // 3. Decide which aged entries to actually prune.
        let mut prune_keys: Vec<String> = hard_expired_keys;
        for key in aged_keys {
            if let Some(entry) = self.spent.get(&key) {
                // Retain if the submit_txid is known AND still in mempool.
                if !entry.submit_txid.is_empty()
                    && txids_in_mempool.contains(&entry.submit_txid)
                {
                    continue;
                }
            }
            prune_keys.push(key);
        }

        let pruned_count = prune_keys.len();
        for key in prune_keys {
            self.spent.remove(&key);
        }

        if pruned_count > 0 {
            info!(
                "[TRACKER] Pruned {} aged spent entries (>{} secs, {} mempool-retained), {} remaining (M-6 mempool-aware)",
                pruned_count,
                max_age_secs,
                txids_in_mempool.len(),
                self.spent.len(),
            );
        }
    }

    /// Pure age-based prune with no RPC dependency.
    ///
    /// Used by tests and by callers that have no RPC handle. Prefer
    /// `prune_spent()` in production.
    pub fn prune_spent_by_age(&mut self, max_age_secs: u64) {
        let before = self.spent.len();
        self.spent.retain(|_, entry| entry.when.elapsed().as_secs() < max_age_secs);
        let pruned = before - self.spent.len();
        if pruned > 0 {
            info!(
                "[TRACKER] Pruned {} aged spent entries by age only (>{} secs), {} remaining",
                pruned, max_age_secs, self.spent.len(),
            );
        }
    }

    /// Return all currently spent outpoint keys as a HashSet.
    /// Used to pass to matching functions so they can filter out entries
    /// that have been locally consumed but not yet removed from a book
    /// (deferred-removal design).
    pub fn spent_keys(&self) -> HashSet<String> {
        self.spent.keys().cloned().collect()
    }

    /// Clear all tracked state (e.g., after a confirmed block).
    pub fn clear(&mut self) {
        self.spent.clear();
        self.pending_outputs.clear();
        self.failed.clear();
    }

    /// Remove all spent entries whose outpoint keys belong to TXs in the given set.
    ///
    /// Used during reorg processing: when a block is removed, any outpoints that
    /// were marked as spent by TXs in that block should be un-spent so they become
    /// eligible for re-use again.
    pub fn remove_spent_for_txids(&mut self, txids: &HashSet<String>) {
        let before = self.spent.len();
        self.spent.retain(|outpoint_key, _| {
            // Extract txid from "txid:index" format
            if let Some(colon) = outpoint_key.find(':') {
                let txid = &outpoint_key[..colon];
                !txids.contains(txid)
            } else {
                true // Keep entries with unexpected format
            }
        });
        let removed = before - self.spent.len();
        if removed > 0 {
            info!(
                "[TRACKER] Removed {} spent entries for reorged TXs ({} txids)",
                removed, txids.len(),
            );
        }
    }
}

/// Fetch wallet UTXOs and extract the wallet SPK from the first entry.
///
/// Returns (utxos, spk_version, spk_script, spk_hex) or None on failure.
pub async fn fetch_wallet_utxos(
    rpc: &RpcClient,
    address: &str,
    label: &str,
) -> Option<(Vec<RpcUtxo>, u16, Vec<u8>, String)> {
    let utxos = match rpc.get_spendable_utxos(address, Some(0)).await {
        Ok(u) => u,
        Err(e) => {
            error!("[{}] Failed to get UTXOs: {}", label, e);
            return None;
        }
    };
    if utxos.is_empty() {
        error!("[{}] No wallet UTXOs available", label);
        return None;
    }
    let (spk_version, spk_script) = utxos[0].parse_spk();
    let spk_hex = hex::encode(&spk_script);
    Some((utxos, spk_version, spk_script, spk_hex))
}

/// Pre-check storage mass for a TX before submission.
///
/// Accepts `(value, plurality)` tuples for proper covenant-aware mass
/// calculation. Returns `Some(mass)` if within limits, or `None` if mass
/// exceeds the limit (logging an error).
pub fn check_mass_presubmit(
    inputs: &[(u64, u64)],
    outputs: &[(u64, u64)],
    label: &str,
) -> Option<u64> {
    match crate::check_storage_mass_ex(inputs, outputs) {
        Ok(mass) => {
            if mass > 0 {
                info!("[{}] Storage mass pre-check: {} (limit {})", label, mass, crate::MAX_TX_MASS);
            }
            Some(mass)
        }
        Err(e) => {
            error!(
                "[{}] TX rejected by storage mass pre-check: {}. \
                 Breakdown: {:?}",
                label, e, e.output_breakdown
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CovenantCache ---

    #[test]
    fn covenant_cache_unknown_id_goes_pending() {
        let mut cache = CovenantCache::new();
        assert_eq!(cache.check("deadbeef".repeat(8).as_str()), None);
        assert_eq!(cache.take_pending().len(), 1);
    }

    #[test]
    fn covenant_cache_mark_valid_then_check() {
        let mut cache = CovenantCache::new();
        let id = "ab".repeat(32);
        cache.mark_valid(&id);
        assert_eq!(cache.check(&id), Some(true));
        assert!(cache.is_valid(&id));
    }

    #[test]
    fn covenant_cache_mark_invalid_ttl() {
        let mut cache = CovenantCache::new();
        let id = "cd".repeat(32);
        cache.mark_invalid(&id);
        assert_eq!(cache.check(&id), Some(false));
        assert!(cache.is_invalid(&id));
    }

    #[test]
    fn covenant_cache_seed_valid_rejects_short_ids() {
        let mut cache = CovenantCache::new();
        cache.seed_valid("short");
        assert!(!cache.is_valid("short"));
    }

    // --- SpentTracker ---

    #[test]
    fn spent_tracker_mark_and_check() {
        let mut tracker = SpentTracker::new();
        assert!(!tracker.is_spent("txid:0"));
        tracker.mark_spent("txid:0");
        assert!(tracker.is_spent("txid:0"));
    }

    #[test]
    fn spent_tracker_failed_cooldown() {
        let mut tracker = SpentTracker::with_cooldown(60);
        tracker.mark_failed("txid:1");
        assert!(tracker.is_failed("txid:1"));
        assert!(tracker.is_spent("txid:1"));
    }

    #[test]
    fn spent_tracker_zero_cooldown_expires_immediately() {
        let mut tracker = SpentTracker::with_cooldown(0);
        tracker.mark_failed("txid:2");
        assert!(!tracker.is_failed("txid:2"));
    }

    #[test]
    fn spent_tracker_clear_resets_all_state() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("a:0");
        tracker.mark_failed("b:0");
        tracker.clear();
        assert!(!tracker.is_spent("a:0"));
        assert!(!tracker.is_failed("b:0"));
    }

    #[test]
    fn spent_tracker_remove_for_reorged_txids() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("deadbeef:0");
        tracker.mark_spent("deadbeef:1");
        tracker.mark_spent("other:0");
        let mut txids = HashSet::new();
        txids.insert("deadbeef".to_string());
        tracker.remove_spent_for_txids(&txids);
        assert!(!tracker.is_spent("deadbeef:0"));
        assert!(!tracker.is_spent("deadbeef:1"));
        assert!(tracker.is_spent("other:0"));
    }

    #[test]
    fn spent_tracker_prune_by_age() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("old:0");
        // age-0 threshold: everything looks "aged" immediately.
        tracker.prune_spent_by_age(0);
        assert!(!tracker.is_spent("old:0"));
    }

    struct FakeMempool {
        in_mempool: bool,
    }

    impl MempoolProbe for FakeMempool {
        fn is_in_mempool<'a>(
            &'a self,
            _txid: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            let v = self.in_mempool;
            Box::pin(async move { v })
        }
    }

    #[tokio::test]
    async fn spent_tracker_prune_with_probe_retains_mempool_pending() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("a:0");
        tracker.mark_submitted("txid-a", &["a:0".to_string()]);
        // Backdate so it's "aged".
        if let Some(entry) = tracker.spent.get_mut("a:0") {
            entry.when = Instant::now() - std::time::Duration::from_secs(1000);
        }
        tracker.prune_spent_with_probe(600, &FakeMempool { in_mempool: true }).await;
        assert!(tracker.is_spent("a:0"), "still-pending mempool tx must be retained");
    }

    #[tokio::test]
    async fn spent_tracker_prune_with_probe_drops_when_not_in_mempool() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("b:0");
        tracker.mark_submitted("txid-b", &["b:0".to_string()]);
        if let Some(entry) = tracker.spent.get_mut("b:0") {
            entry.when = Instant::now() - std::time::Duration::from_secs(1000);
        }
        tracker.prune_spent_with_probe(600, &FakeMempool { in_mempool: false }).await;
        assert!(!tracker.is_spent("b:0"));
    }

    #[test]
    fn check_mass_presubmit_reports_mass_for_valid_tx() {
        // A tiny 1-in/1-out TX is well within limits.
        let inputs = [(100_000_000u64, 1u64)];
        let outputs = [(99_900_000u64, 1u64)];
        assert!(check_mass_presubmit(&inputs, &outputs, "TEST").is_some());
    }
}
