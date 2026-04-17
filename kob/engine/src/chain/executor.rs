//! Atomic match transaction construction and continuous matching loop.

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

use crate::config::AppConfig;
use kob_core::MIN_UTXO_VALUE;
use crate::matcher::batch::OutputPurpose;
use crate::matcher::deploy;
use crate::matcher::matching::{self, MatchType};
use crate::matcher::order_book::{OrderBook, OrderSide};
use crate::matcher::persistence;
use crate::matcher::api::{AppState, WsEvent};
use crate::matcher::trades::{Trade, Side};
use crate::matcher::candle::Interval;
use crate::rpc::{RpcClient, RpcUtxo};
use crate::matcher::scanner::{
    BlockScanner, TransactionData, ScanResult,
    PerpDeploySide, LendingOrderType, PredictionItemType,
    BUY_RS_SIZE, SELL_RS_SIZE, BRACKET_RS_SIZE,
};

/// Default cooldown for permanently failed outpoints (seconds).
/// Script verification failures, mass violations, etc.
pub const FAILED_OUTPOINT_COOLDOWN_SECS: u64 = 30;

/// Cooldown for transient failures (seconds).
/// CSV sequence-lock rejections resolve after ~5s (50 DAA at 10 BPS).
/// Short cooldown prevents submit spam while allowing prompt retry.
const TRANSIENT_COOLDOWN_SECS: u64 = 6;

/// Maximum number of blocks to retain in the reorg tracker.
/// Kaspa's finality window is ~4 hours (~14,400 blocks at 10 BPS).
/// H2: 10_000 blocks (~17min at 10 BPS). Beyond any realistic reorg depth
/// but cheap to keep in memory; startup UTXO validation covers edge cases.
const REORG_TRACKER_MAX_BLOCKS: usize = 10_000;

/// Default matcher fee in basis points (0.30%).
pub const DEFAULT_FEE_BPS: u16 = 30;
/// Maximum allowed fee in basis points (1.00%). Prevents misconfiguration.
pub const MAX_FEE_BPS: u16 = 100;

/// Spent-tracker prune threshold in seconds (H-1 safety net only).
///
/// The primary cleanup path is `remove_spent_for_txids()` called in the
/// block-processing loop which fires as soon as a TX lands in a block
/// (or gets reorged). This timeout only matters for self-submitted TXs
/// that drop out of the mempool without ever confirming (e.g. fee too
/// low, node rejection that we didn't catch).
const SPENT_PRUNE_AGE_SECS: u64 = 600;

/// Hard cap for spent-tracker entry age (seconds).
///
/// `prune_spent()` normally preserves aged entries whose associated
/// `submit_txid` is still in the mempool (preventing the scenario where
/// a 600s-dwelling TX gets its inputs pruned, the matcher re-uses them,
/// and the node rejects with "already spent ... in the mempool").
/// If the RPC mempool check continually reports "in mempool" for a
/// given txid due to a bug or malicious node, we fall back to a hard
/// cap so the tracker cannot grow without bound.
///
/// 2 hours >> any realistic mempool dwell time; by this point the TX
/// is surely dead.
const SPENT_PRUNE_HARD_MAX_AGE_SECS: u64 = 7200;

/// TTL for entries in the invalid covenant ID cache (seconds).
///
/// Tokens may be deployed after an order is first seen, so invalid entries
/// expire and trigger a fresh RPC re-check on the next encounter.
const INVALID_COVENANT_TTL_SECS: u64 = 300; // 5 minutes

/// Maximum entries in the CovenantCache `valid` set before eviction (M8).
/// In practice a matcher only interacts with a limited set of tokens, so
/// 50,000 is generous headroom. When exceeded, the entire valid set is
/// cleared and re-verified on demand (cache miss → pending → RPC check).
const COVENANT_CACHE_VALID_MAX: usize = 50_000;

/// On-chain covenant ID verification cache.
///
/// Prevents the engine from accepting orders with fake/non-existent covenant
/// IDs into the order book. Once a covenant ID is verified on-chain, it is
/// permanently cached (`valid`). Unverifiable IDs are cached with a TTL
/// (`invalid`) so newly deployed tokens can be picked up after the TTL
/// expires.
///
/// Verification flow (async, performed by the main loop after block scan):
///   1. Block scanner encounters an unknown covenant ID and collects it into
///      `pending_checks`.
///   2. After the synchronous scan completes, the async caller queries the
///      node RPC (e.g., `getUtxosByAddresses`) to verify each pending ID.
///   3. Verified IDs are moved to `valid`; unverifiable ones go to `invalid`.
///   4. On the next scan cycle, orders with now-valid IDs pass through.
pub struct CovenantCache {
    /// Covenant IDs confirmed to exist on-chain. Permanent (tokens don't
    /// get un-created).
    valid: HashSet<String>,
    /// Covenant IDs that failed on-chain verification, with expiry timestamp.
    /// Entries older than `INVALID_COVENANT_TTL_SECS` are pruned on access.
    invalid: HashMap<String, Instant>,
    /// Covenant IDs encountered during the current scan cycle that are not
    /// in either cache. Populated by the synchronous scanner, drained by
    /// the async verification step.
    pending_checks: Vec<String>,
}

impl CovenantCache {
    pub fn new() -> Self {
        Self {
            valid: HashSet::new(),
            invalid: HashMap::new(),
            pending_checks: Vec::new(),
        }
    }

    /// Pre-seed a known-good covenant ID (e.g., from MM config at startup).
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

    /// Returns `true` if the covenant ID is in the permanent valid set.
    pub fn is_valid(&self, cov_id: &str) -> bool {
        self.valid.contains(cov_id)
    }

    /// Returns `true` if the covenant ID is in the invalid cache and the
    /// entry has not expired.
    pub fn is_invalid(&self, cov_id: &str) -> bool {
        if let Some(when) = self.invalid.get(cov_id) {
            when.elapsed().as_secs() < INVALID_COVENANT_TTL_SECS
        } else {
            false
        }
    }

    /// Check a covenant ID against the cache. Returns:
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

    /// Mark a covenant ID as verified on-chain (permanent).
    ///
    /// If the valid cache exceeds `COVENANT_CACHE_VALID_MAX`, it is cleared
    /// first. This prevents unbounded growth (M8). Cleared entries will be
    /// re-verified on demand (cache miss → pending_checks → RPC).
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

    /// Mark a covenant ID as not found on-chain (TTL-based).
    pub fn mark_invalid(&mut self, cov_id: &str) {
        self.invalid.insert(cov_id.to_string(), Instant::now());
    }

    /// Drain pending covenant IDs that need async RPC verification.
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
pub(crate) trait MempoolProbe {
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
pub(crate) struct RpcMempoolProbe<'a> {
    pub(crate) rpc: &'a RpcClient,
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
#[allow(dead_code)] // Fields used in tests
pub struct SpentTracker {
    /// Outpoints (txid:index) that were used as inputs in recently submitted TXs,
    /// with the timestamp when they were marked spent and the submit txid
    /// (if known) to allow mempool-aware pruning.
    pub spent: HashMap<String, SpentEntry>,
    /// Outpoints (txid:index) that were created as outputs in recently submitted TXs.
    /// These may become available once the TX propagates.
    pub pending_outputs: Vec<(String, u64)>, // (outpoint_key, value)
    /// Outpoints that failed during TX submission, with cooldown expiry.
    /// These are temporarily excluded from matching to prevent infinite retry loops.
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
    #[allow(dead_code)] // Used in tests
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
    /// The outpoint will be excluded from matching for `cooldown_secs` seconds.
    pub fn mark_failed(&mut self, outpoint_key: &str) {
        self.failed.insert(
            outpoint_key.to_string(),
            Instant::now(),
        );
    }

    /// Mark an outpoint as transiently failed (e.g. CSV sequence-lock not yet met).
    /// Uses a short cooldown: the order stays in the book and will retry soon.
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
    /// them would cause the matcher to re-use those inputs, triggering
    /// "already spent ... in the mempool" rejections from kaspad in a
    /// retry loop until the TX eventually confirms (or the script exits).
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
    /// Kept `pub(crate)` so unit tests can swap in a deterministic probe
    /// without needing a full RpcClient / WebSocket harness.
    pub(crate) async fn prune_spent_with_probe<P: MempoolProbe>(
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
    /// Used only by tests and by callers that have no RPC handle (none
    /// currently in production). Prefer `prune_spent()` in the main loop.
    #[cfg(test)]
    #[allow(dead_code)]
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
    /// Used to pass to matching functions so they can filter out
    /// orders that have been locally consumed but not yet removed
    /// from the order book (deferred-removal design).
    pub fn spent_keys(&self) -> HashSet<String> {
        self.spent.keys().cloned().collect()
    }

    /// Clear all tracked state (e.g., after a confirmed block).
    #[allow(dead_code)] // Used in tests
    pub fn clear(&mut self) {
        self.spent.clear();
        self.pending_outputs.clear();
        self.failed.clear();
    }

    /// Remove all spent entries whose outpoint keys belong to TXs in the given set.
    ///
    /// Used during reorg processing: when a block is removed, any outpoints that
    /// were marked as spent by TXs in that block should be un-spent so they become
    /// eligible for matching again.
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

// ---------------------------------------------------------------------------
// ReorgTracker: block-provenance tracking for chain reorganization handling
// ---------------------------------------------------------------------------

/// Records which orders were added/removed by each block so that reorgs
/// (removed blocks) can be rolled back.
///
/// For each block hash, we store:
/// - `orders_added`: BookOrders that were added from transactions in this block.
///   On reorg, these must be REMOVED from the order book.
/// - `orders_spent`: outpoint_keys of orders that were spent (filled/cancelled)
///   by transactions in this block, together with a snapshot of the order at
///   the time of removal. On reorg, these must be RESTORED to the order book.
/// - `txids`: all transaction IDs seen in this block, used to clean up the
///   SpentTracker.
///
/// The tracker maintains insertion order via a VecDeque and prunes old entries
/// when the block count exceeds REORG_TRACKER_MAX_BLOCKS.
pub struct ReorgTracker {
    /// Block hash -> provenance data, in insertion order (oldest first).
    blocks: std::collections::VecDeque<(String, BlockProvenance)>,
    /// Fast lookup: block_hash -> index in `blocks` VecDeque.
    index: HashMap<String, usize>,
}

/// Provenance data for a single block.
struct BlockProvenance {
    /// Orders that were added to the book from this block's transactions.
    /// On reorg, these must be removed.
    orders_added: Vec<crate::matcher::order_book::BookOrder>,
    /// Orders that were spent (removed from book) by this block's transactions.
    /// On reorg, these must be restored. Stored as (outpoint_key, order_snapshot).
    orders_spent: Vec<(String, crate::matcher::order_book::BookOrder)>,
    /// All TX IDs seen in this block (for SpentTracker cleanup).
    txids: HashSet<String>,
}

impl ReorgTracker {
    pub fn new() -> Self {
        Self {
            blocks: std::collections::VecDeque::new(),
            index: HashMap::new(),
        }
    }

    /// Record provenance for a block.
    ///
    /// `block_hash`: the block's hash.
    /// `orders_added`: orders that were added to the book from this block.
    /// `orders_spent`: orders that were spent (with snapshots for restoration).
    /// `txids`: all TX IDs in this block.
    pub fn record_block(
        &mut self,
        block_hash: String,
        orders_added: Vec<crate::matcher::order_book::BookOrder>,
        orders_spent: Vec<(String, crate::matcher::order_book::BookOrder)>,
        txids: HashSet<String>,
    ) {
        // Avoid duplicates (same block hash seen twice, e.g. from retransmission)
        if self.index.contains_key(&block_hash) {
            return;
        }

        let idx = self.blocks.len();
        self.blocks.push_back((block_hash.clone(), BlockProvenance {
            orders_added,
            orders_spent,
            txids,
        }));
        self.index.insert(block_hash, idx);

        // Prune oldest blocks if we exceed the limit
        while self.blocks.len() > REORG_TRACKER_MAX_BLOCKS {
            if let Some((old_hash, _)) = self.blocks.pop_front() {
                self.index.remove(&old_hash);
            }
            // After popping, all indices shift down by 1. Rebuild index.
            // This is O(N) but only happens once per block and N is bounded.
            self.rebuild_index();
        }
    }

    /// Process removed blocks during a reorg.
    ///
    /// For each removed block hash (in order):
    /// 1. Remove orders that were added by that block from the order book.
    /// 2. Restore orders that were spent by that block back to the order book.
    /// 3. Remove SpentTracker entries for TXs in that block.
    ///
    /// Returns `(orders_restored, orders_removed, blocks_handled, blocks_unknown)`.
    pub fn handle_removed_blocks(
        &mut self,
        removed_hashes: &[String],
        order_book: &mut crate::matcher::order_book::OrderBook,
        spent_tracker: &mut SpentTracker,
    ) -> (usize, usize, usize, usize) {
        let mut total_restored = 0usize;
        let mut total_removed = 0usize;
        let mut blocks_handled = 0usize;
        let mut blocks_unknown = 0usize;

        for block_hash in removed_hashes {
            // Find and remove the block from our tracker
            let provenance = if let Some(&idx) = self.index.get(block_hash) {
                self.index.remove(block_hash);
                // Remove from deque — we swap_remove for efficiency
                // but since ordering matters for future pruning,
                // we mark it as consumed and skip during future lookups.
                // Actually, for correctness in a reorg scenario the removed
                // blocks are processed once and then gone. Just extract it.
                //
                // Note: VecDeque doesn't have swap_remove. We'll remove by
                // index which is O(N), but reorgs are rare and N is bounded.
                let (_, prov) = self.blocks.remove(idx).unwrap();
                self.rebuild_index();
                Some(prov)
            } else {
                None
            };

            match provenance {
                Some(prov) => {
                    blocks_handled += 1;

                    // Step 1: Remove orders that were ADDED by this block.
                    // These orders no longer exist on-chain after the reorg.
                    for order in &prov.orders_added {
                        let key = order.outpoint_key();
                        if order_book.contains_outpoint(&key) {
                            order_book.remove_order(&key);
                            total_removed += 1;
                            warn!(
                                "[REORG] Removed order {} (added by reorged block {}...)",
                                &key[..key.len().min(20)],
                                &block_hash[..block_hash.len().min(16)],
                            );
                        }
                    }

                    // Step 2: Restore orders that were SPENT by this block.
                    // The spending TX is no longer valid, so the original order
                    // UTXO should reappear in the UTXO set.
                    for (outpoint_key, order_snapshot) in prov.orders_spent {
                        // Only restore if the order is not already in the book
                        // (defensive: another notification path may have re-added it)
                        if !order_book.contains_outpoint(&outpoint_key) {
                            // Also remove from matched_outpoints so the order
                            // is not immediately filtered out by dedup logic
                            order_book.matched_outpoints.remove(&outpoint_key);

                            match order_snapshot.side {
                                OrderSide::Buy => {
                                    order_book.add_buy_order(order_snapshot.clone());
                                }
                                OrderSide::Sell => {
                                    order_book.add_sell_order(order_snapshot.clone());
                                }
                            }
                            total_restored += 1;
                            warn!(
                                "[REORG] Restored order {} (spent by reorged block {}...)",
                                &outpoint_key[..outpoint_key.len().min(20)],
                                &block_hash[..block_hash.len().min(16)],
                            );
                        }
                    }

                    // Step 3: Clean up SpentTracker entries for TXs in this block.
                    spent_tracker.remove_spent_for_txids(&prov.txids);
                }
                None => {
                    blocks_unknown += 1;
                    warn!(
                        "[REORG] Removed block {}... has no provenance data (too old or not tracked). \
                         Orders from this block cannot be automatically rolled back. \
                         A UTXO validation sweep will be needed.",
                        &block_hash[..block_hash.len().min(16)],
                    );
                }
            }
        }

        (total_restored, total_removed, blocks_handled, blocks_unknown)
    }

    /// Number of blocks currently tracked.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Rebuild the hash->index lookup after structural changes to the deque.
    fn rebuild_index(&mut self) {
        self.index.clear();
        for (i, (hash, _)) in self.blocks.iter().enumerate() {
            self.index.insert(hash.clone(), i);
        }
    }
}

/// Result of a successful match execution.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct MatchResult {
    pub match_tx_id: String,
    pub match_type: MatchType,
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub receipt_tx_id: String,
    pub receipt_idx: u32,
    pub receipt_value: u64,
    pub token_cov_id: String,
    /// Price numerator used when building the receipt redeemScript.
    /// Needed to reconstruct the P2SH for receipt consumption.
    pub price_num: u64,
    /// Price denominator used when building the receipt redeemScript.
    pub price_den: u64,
}

/// IFD context passed to fill functions when a contingent order B should be
/// deployed as part of the fill TX.
#[derive(Debug, Clone)]
pub struct IfdFillContext {
    /// IFD rule ID (for marking triggered after success).
    pub rule_id: u64,
    /// Order B's redeem script bytes (hex-decoded).
    pub order_b_rs: Vec<u8>,
    /// Order B's P2SH address (hex, for logging).
    pub order_b_p2sh: String,
    /// Order B's expiry DAA score (0 = GTC, no expiry).
    pub expiry_daa: u64,
}

/// Fetch wallet UTXOs and extract the wallet SPK from the first entry.
///
/// Returns (utxos, spk_version, spk_script, spk_hex) or None on failure.
async fn fetch_wallet_utxos(
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


/// Compute UTXO plurality for a planned output.
///
/// Covenant outputs (BuyerTokens, SellRemainder) carry a 32-byte covenant ID
/// that increases storage occupancy.  The formula mirrors
/// `kaspa_consensus_core::mass::utxo_plurality`.
fn planned_output_plurality(out: &crate::matcher::batch::PlannedOutput) -> u64 {
    // UTXO fixed overhead: 32 (txid) + 4 (index) + 8 (amount) + 8 (daa) + 1 (coinbase) + 2 (spk ver) + 8 (spk len) = 63
    const UTXO_CONST_STORAGE: usize = 63;
    const UTXO_UNIT_SIZE: usize = 100;
    const COVENANT_HASH_SIZE: usize = 32;

    let has_covenant = matches!(
        out.purpose,
        OutputPurpose::BuyerTokens | OutputPurpose::SellRemainder
    );
    let total = UTXO_CONST_STORAGE
        + out.script_public_key.len()
        + if has_covenant { COVENANT_HASH_SIZE } else { 0 };
    total.div_ceil(UTXO_UNIT_SIZE) as u64
}

/// Pre-check storage mass for a match TX before submission.
///
/// Accepts `(value, plurality)` tuples for proper covenant-aware mass
/// calculation.  Returns `Some(mass)` if within limits, or `None` if mass
/// exceeds the limit (logging an error).
fn check_mass_presubmit(
    inputs: &[(u64, u64)],
    outputs: &[(u64, u64)],
    label: &str,
) -> Option<u64> {
    match kob_core::check_storage_mass_ex(inputs, outputs) {
        Ok(mass) => {
            if mass > 0 {
                info!("[{}] Storage mass pre-check: {} (limit {})", label, mass, kob_core::MAX_TX_MASS);
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


/// Result of a batch match execution.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct BatchMatchResult {
    /// Transaction ID of the submitted batch match TX.
    pub tx_id: String,
    /// Number of sell orders matched.
    pub sell_count: usize,
    /// Number of buy orders matched.
    pub buy_count: usize,
    /// Total KAS paid to sellers.
    pub total_seller_kas: u64,
    /// Matcher surplus captured.
    pub matcher_surplus: u64,
}

/// Trace all input sigscripts in a batch TX at debug level.
///
/// For each input, disassembles the sigscript into human-readable opcodes.
/// Covenant inputs show the full sigscript structure (args + selector + RS).
/// Wallet inputs show `P2PK(sig)`.
fn trace_batch_inputs(
    batch_tx: &crate::matcher::batch::BatchTx,
    plan: &crate::matcher::batch::BatchPlan,
) {
    use kob_core::contract::opcodes::format_script;

    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }

    let wallet_idx = if plan.wallet_input.is_some() {
        Some(batch_tx.inputs.len().saturating_sub(1))
    } else {
        None
    };

    debug!("[TRACE] ═══ Batch TX sigscript trace ({} inputs, {} outputs) ═══",
        batch_tx.inputs.len(), batch_tx.outputs.len());

    for (i, inp) in batch_tx.inputs.iter().enumerate() {
        let role = if i < plan.sells.len() {
            format!("sell[{}]", i)
        } else if i < plan.sells.len() + plan.buys.len() {
            format!("buy[{}]", i - plan.sells.len())
        } else if wallet_idx == Some(i) {
            "wallet".to_string()
        } else {
            format!("input[{}]", i)
        };

        let txid_short = &inp.tx_id[..inp.tx_id.len().min(12)];

        if wallet_idx == Some(i) {
            debug!("[TRACE]   {}  {}:{}  P2PK(sig={}B)",
                role, txid_short, inp.index, inp.sigscript.len());
            continue;
        }

        // Covenant input: disassemble sigscript
        let disasm = format_script(&inp.sigscript);

        // Split into args vs RS for readability
        // RS is always the last pushdata element (largest)
        let ss_len = inp.sigscript.len();
        debug!("[TRACE]   {}  {}:{}  sigscript({}B): {}",
            role, txid_short, inp.index, ss_len, disasm);
    }

    // Output summary
    for (i, out) in batch_tx.outputs.iter().enumerate() {
        let spk_hex = &hex::encode(&out.script_public_key);
        let spk_short = &spk_hex[..spk_hex.len().min(16)];
        debug!("[TRACE]   output[{}]  value={}  spk={}...({:?})",
            i, out.value, spk_short, out.purpose);
    }

    debug!("[TRACE] ═══ end trace ═══");
}

/// Execute an N:M batch match from a pre-built BatchPlan.
///
/// Builds the batch TX via `BatchPlan::build_tx()`, constructs a sighash TX
/// Convert a CrossingPair into (sell BatchOrder, buy BatchOrder).
/// Returns None if RS sizes are invalid or counterparty SPKs are missing.
pub(crate) fn pair_to_batch_orders(
    pair: &matching::CrossingPair,
    label: &str,
) -> Option<(crate::matcher::batch::BatchOrder, crate::matcher::batch::BatchOrder)> {
    let token_bytes: [u8; 32] = match hex::decode(&pair.sell.token_cov_id) {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => {
            warn!("[{}] Invalid token_cov_id hex, skipping pair", label);
            return None;
        }
    };

    let sell_rs = hex::decode(&pair.sell.redeem_script_hex).unwrap_or_default();
    let buy_rs = hex::decode(&pair.buy.redeem_script_hex).unwrap_or_default();

    // sell RS: v14=416, OCO=333; buy RS: v14=396, v15=479
    if sell_rs.len() != SELL_RS_SIZE && sell_rs.len() != kob_core::OCO_SELL_RS_SIZE {
        warn!("[{}] Unsupported sell RS size {}, skipping (v14={}, oco={})", label, sell_rs.len(), SELL_RS_SIZE, kob_core::OCO_SELL_RS_SIZE);
        return None;
    }
    if buy_rs.len() != BUY_RS_SIZE
        && buy_rs.len() != kob_core::contract::spot::order::BUY_ORDER_V15_RS_EXPECTED_LEN
        && buy_rs.len() != BRACKET_RS_SIZE
    {
        warn!("[{}] Unsupported buy RS size {}, skipping (v14={}, v15={}, bracket={})",
            label, buy_rs.len(), BUY_RS_SIZE,
            kob_core::contract::spot::order::BUY_ORDER_V15_RS_EXPECTED_LEN,
            BRACKET_RS_SIZE);
        return None;
    }

    let (seller_spk_ver, seller_spk) = match pair.sell.resolve_counterparty_spk() {
        Some(x) => x,
        None => {
            warn!("[{}] Sell order {} missing counterparty_spk, skipping", label, pair.sell.outpoint_key());
            return None;
        }
    };
    let (buyer_spk_ver, buyer_spk) = match pair.buy.resolve_counterparty_spk() {
        Some(x) => x,
        None => {
            warn!("[{}] Buy order {} missing counterparty_spk, skipping", label, pair.buy.outpoint_key());
            return None;
        }
    };

    let sell_order = crate::matcher::batch::BatchOrder {
        outpoint: (pair.sell.tx_id.clone(), pair.sell.index),
        order_type: crate::matcher::batch::OrderType::Sell,
        version: 14,
        token_cov_id: token_bytes,
        price_num: pair.sell.price_num,
        price_den: pair.sell.price_den,
        amount: pair.sell.value,
        redeem_script: sell_rs,
        utxo_value: pair.sell.value,
        counterparty_spk: seller_spk,
        counterparty_spk_version: seller_spk_ver,
        min_fill: pair.sell.min_fill,
        oco_path: pair.sell.oco_path,
        bracket_meta: None,
    };

    let buy_version = if buy_rs.len() == kob_core::contract::spot::order::BUY_ORDER_V15_RS_EXPECTED_LEN {
        15u8
    } else if buy_rs.len() == BRACKET_RS_SIZE {
        16u8
    } else {
        14u8
    };
    let bracket_meta = if buy_version == 16 {
        extract_bracket_meta(&buy_rs)
    } else {
        None
    };
    let buy_order = crate::matcher::batch::BatchOrder {
        outpoint: (pair.buy.tx_id.clone(), pair.buy.index),
        order_type: crate::matcher::batch::OrderType::Buy,
        version: buy_version,
        token_cov_id: token_bytes,
        price_num: pair.buy.price_num,
        price_den: pair.buy.price_den,
        amount: pair.buy.value,
        redeem_script: buy_rs,
        utxo_value: pair.buy.value,
        counterparty_spk: buyer_spk,
        counterparty_spk_version: buyer_spk_ver,
        min_fill: pair.buy.min_fill,
        oco_path: None,
        bracket_meta,
    };

    Some((sell_order, buy_order))
}

/// Convert a single BookOrder into a BatchOrder.
///
/// Returns None if the order has invalid token_cov_id hex, unsupported RS size,
/// or missing counterparty SPK.
pub(crate) fn book_order_to_batch_order(
    order: &crate::matcher::order_book::BookOrder,
    label: &str,
) -> Option<crate::matcher::batch::BatchOrder> {
    let token_bytes: [u8; 32] = match hex::decode(&order.token_cov_id) {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => {
            warn!("[{}] Invalid token_cov_id hex for {}, skipping", label, order.outpoint_key());
            return None;
        }
    };

    let rs = hex::decode(&order.redeem_script_hex).unwrap_or_default();

    // RS sizes: sell v14=416, OCO=333; buy v14=396, v15=479, bracket=365
    match order.side {
        crate::matcher::order_book::OrderSide::Sell => {
            if rs.len() != SELL_RS_SIZE && rs.len() != kob_core::OCO_SELL_RS_SIZE {
                warn!("[{}] Unsupported sell RS size {} for {}", label, rs.len(), order.outpoint_key());
                return None;
            }
        }
        crate::matcher::order_book::OrderSide::Buy => {
            if rs.len() != BUY_RS_SIZE
                && rs.len() != kob_core::contract::spot::order::BUY_ORDER_V15_RS_EXPECTED_LEN
                && rs.len() != BRACKET_RS_SIZE
            {
                warn!("[{}] Unsupported buy RS size {} for {}", label, rs.len(), order.outpoint_key());
                return None;
            }
        }
    }

    let (spk_ver, spk) = match order.resolve_counterparty_spk() {
        Some(x) => x,
        None => {
            warn!("[{}] Order {} missing counterparty_spk, skipping", label, order.outpoint_key());
            return None;
        }
    };

    let order_type = match order.side {
        crate::matcher::order_book::OrderSide::Buy => crate::matcher::batch::OrderType::Buy,
        crate::matcher::order_book::OrderSide::Sell => crate::matcher::batch::OrderType::Sell,
    };

    let version = if rs.len() == kob_core::contract::spot::order::BUY_ORDER_V15_RS_EXPECTED_LEN {
        15u8
    } else if rs.len() == BRACKET_RS_SIZE {
        16u8
    } else {
        14u8
    };
    let bracket_meta = if version == 16 {
        extract_bracket_meta(&rs)
    } else {
        None
    };
    Some(crate::matcher::batch::BatchOrder {
        outpoint: (order.tx_id.clone(), order.index),
        order_type,
        version,
        token_cov_id: token_bytes,
        price_num: order.price_num,
        price_den: order.price_den,
        amount: order.value,
        redeem_script: rs,
        utxo_value: order.value,
        counterparty_spk: spk,
        counterparty_spk_version: spk_ver,
        min_fill: order.min_fill,
        oco_path: order.oco_path,
        bracket_meta,
    })
}

/// Extract bracket metadata from a 365B bracket entry redeemScript.
///
/// State layout (224B):
///   [0x08][entry_type 8B]        = bytes 0..9
///   [0x20][token_cov_id 32B]     = bytes 9..42
///   [0x08][epnum 8B]             = bytes 42..51
///   [0x08][epden 8B]             = bytes 51..60
///   [0x25][oco_spk 37B]          = bytes 60..98
///   [0x08][oco_min_val 8B]       = bytes 98..107
///   [0x08][min_fill 8B]          = bytes 107..116
///   [0x08][min_receipt_val 8B]   = bytes 116..125
///   [0x20][receipt_cov_id 32B]   = bytes 125..158
fn extract_bracket_meta(rs: &[u8]) -> Option<crate::matcher::batch::BracketMeta> {
    if rs.len() != BRACKET_RS_SIZE {
        return None;
    }

    let entry_type = u64::from_le_bytes(rs[1..9].try_into().ok()?);

    // OCO SPK: 37 bytes at offset 61..98 (after 0x25 push prefix at byte 60)
    let oco_spk_version = u16::from_le_bytes([rs[61], rs[62]]);
    let oco_spk = rs[61..98].to_vec(); // full 37 bytes (version + script)

    // OCO min value: 8 bytes at offset 99..107 (after 0x08 push prefix at byte 98)
    let oco_min_val = u64::from_le_bytes(rs[99..107].try_into().ok()?);

    // Min receipt value: 8 bytes at offset 117..125 (after 0x08 push prefix at byte 116)
    let min_receipt_val = u64::from_le_bytes(rs[117..125].try_into().ok()?);

    // Receipt covenant ID: 32 bytes at offset 126..158 (after 0x20 push prefix at byte 125)
    let mut receipt_cov_id = [0u8; 32];
    receipt_cov_id.copy_from_slice(&rs[126..158]);

    Some(crate::matcher::batch::BracketMeta {
        receipt_cov_id,
        min_receipt_val,
        oco_spk,
        oco_spk_version,
        oco_min_val,
        entry_type,
    })
}

/// to sign the wallet input (P2PK, last input), then submits via RPC.
///
/// The wallet input is the LAST input in the batch TX and needs `sigOpCount: 1`
/// with a Schnorr signature. All covenant inputs (sells, buys)
/// use `sigOpCount: 0`.
///
/// TX version = 1 (required for covenant output bindings on buyer token outputs).
pub async fn execute_batch_match(
    rpc: &RpcClient,
    plan: &mut crate::matcher::batch::BatchPlan,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
    ifd_payload: Option<String>,
    // H1: wallet SPK from cycle-level cache.
    // All UTXOs for the same address share the same SPK, so re-fetching
    // per group was pure overhead (~1 RPC roundtrip per match).
    wallet_spk: (u16, &[u8]),
) -> Option<BatchMatchResult> {
    // Validate the plan before building
    if let Err(e) = plan.validate() {
        error!("[BATCH] Plan validation failed: {}", e);
        return None;
    }

    let batch_tx = match plan.build_tx() {
        Ok(tx) => tx,
        Err(e) => {
            error!("[BATCH] build_tx failed: {}", e);
            return None;
        }
    };

    info!("======================================================================");
    info!(
        "EXECUTING BATCH MATCH: {} sells + {} buys",
        plan.sells.len(),
        plan.buys.len(),
    );
    info!("======================================================================");
    debug!("  Total fee:       {}", plan.total_fee);
    debug!("  Matcher surplus: {}", plan.matcher_surplus);

    // Build RPC inputs from the batch TX (covenant inputs already have sigscripts)
    let wallet_input_idx = batch_tx.inputs.len().saturating_sub(1);
    let has_wallet = plan.wallet_input.is_some();

    // We need to sign the wallet input. Build a kob_core::tx::Transaction for sighash.
    // lock_time=50 required for OP_CSV(50) in covenant inputs.
    let mut sighash_tx = kob_core::tx::Transaction::new(1);
    sighash_tx.lock_time = 50;
    // IFD: set TX payload on sighash_tx so sighash computation includes it.
    // The payload is part of the sighash in Kaspa — adding it only at RPC
    // submission time would invalidate all pre-computed signatures.
    if let Some(ref payload_hex) = ifd_payload {
        if let Ok(payload_bytes) = hex::decode(payload_hex) {
            sighash_tx.payload = payload_bytes;
        }
    }

    // Reconstruct inputs for sighash computation.
    // For covenant inputs: use P2SH script from the order's p2sh
    // For the wallet input: use the wallet's SPK

    // Add sell order inputs (CSV=50 for BuySell covenant)
    for (sell, _input_idx) in &plan.sells {
        let p2sh = kob_core::build_p2sh(&sell.redeem_script);
        sighash_tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: sell.outpoint.0.clone(),
            prev_index: sell.outpoint.1,
            sequence: 50,
            sig_op_count: 0,
            script_version: p2sh.version,
            script_bytes: p2sh.script().to_vec(),
            value: sell.utxo_value,
        });
    }

    // Add buy order inputs (CSV=50 for BuySell covenant)
    for (buy, _input_idx) in &plan.buys {
        let p2sh = kob_core::build_p2sh(&buy.redeem_script);
        sighash_tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: buy.outpoint.0.clone(),
            prev_index: buy.outpoint.1,
            sequence: 50,
            sig_op_count: 0,
            script_version: p2sh.version,
            script_bytes: p2sh.script().to_vec(),
            value: buy.utxo_value,
        });
    }

    // Wallet sigscript — needed for compute mass check after signing
    let mut wallet_sigscript: Option<Vec<u8>> = None;

    // Add wallet input (P2PK, sigOpCount=1) if present
    if let Some((ref wallet_tx_id, wallet_index, wallet_value)) = plan.wallet_input {
        // H1: Use cycle-level cached wallet SPK. All UTXOs owned by the same
        // address share one SPK, so fetching again inside this function was
        // redundant (the original code already had a fallback acknowledging
        // "same wallet, same SPK").
        let (spk_version, spk_script_ref) = wallet_spk;

        sighash_tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: wallet_tx_id.clone(),
            prev_index: wallet_index,
            sequence: 0,
            sig_op_count: 1,
            script_version: spk_version,
            script_bytes: spk_script_ref.to_vec(),
            value: wallet_value,
        });
    }

    // Build RPC outputs and sighash TX outputs
    let mut rpc_outputs = Vec::new();
    let n = plan.sells.len();

    for (i, out) in batch_tx.outputs.iter().enumerate() {
        let spk_hex = hex::encode(&out.script_public_key);

        // BuyerTokens and SellRemainder outputs need covenant bindings
        // (sell covenant F4 checks: covenant_output_value >= sell_input_value)
        if out.purpose == OutputPurpose::BuyerTokens {
            // output[N+j] corresponds to buy[j]
            let buy_j = i.saturating_sub(n);
            if buy_j < plan.buys.len() {
                let (buy, _) = &plan.buys[buy_j];
                let token_hex = hex::encode(buy.token_cov_id);
                if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                    rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                        out.value,
                        out.spk_version,
                        &spk_hex,
                        tii as u16,
                        &token_hex,
                    ));
                    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), Some(kob_core::tx::CovenantBinding::new(tii as u16, kob_core::compat::parse_hash(&token_hex).unwrap()))));
                    continue;
                }
            }
            warn!("[BATCH] BuyerTokens output[{}] missing covenant binding", i);
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        } else if out.purpose == OutputPurpose::SellRemainder {
            // SellRemainder carries excess token value — needs covenant binding
            // to satisfy sell contract F4 (covenant output conservation).
            // Use the first sell's token_cov_id for the binding.
            if let Some((sell, _)) = plan.sells.first() {
                let token_hex = hex::encode(sell.token_cov_id);
                if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                    rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                        out.value,
                        out.spk_version,
                        &spk_hex,
                        tii as u16,
                        &token_hex,
                    ));
                    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), Some(kob_core::tx::CovenantBinding::new(tii as u16, kob_core::compat::parse_hash(&token_hex).unwrap()))));
                    continue;
                }
            }
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        } else {
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        }

        sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), None));
    }

    // Build RPC inputs
    // Covenant inputs (sell/buy) require sequence=50 for OP_CSV compliance.
    let mut rpc_inputs = Vec::new();
    for (i, inp) in batch_tx.inputs.iter().enumerate() {
        if has_wallet && i == wallet_input_idx {
            // Wallet input: needs signing — we'll replace the sigscript below
            continue;
        }
        rpc_inputs.push(deploy::build_rpc_input_with_sequence(
            &inp.tx_id,
            inp.index,
            &hex::encode(&inp.sigscript),
            inp.sig_op_count,
            50, // OP_CSV(50) compliance
        ));
    }

    // Phase 2: Exact fee convergence BEFORE signing.
    //
    // `calc_mass_with_sigscripts` reads sigscript LENGTHS only. P2PK wallet
    // sigscript is a constant 66 bytes regardless of signature content, so
    // we can converge the fee with a placeholder [0u8; 64] sig — yielding
    // post-convergence output values that the wallet will sign over ONCE
    // below, with no re-sign needed.
    //
    // This also makes the subsequent M1 mass check see the final output
    // values, matching the late check byte-exact (storage mass depends on
    // output values; apply_exact_fee raises one output by `delta`).
    {
        let placeholder_wallet_ss = if has_wallet {
            kob_core::contract::build_p2pk_sigscript(&[0u8; 64])
        } else {
            Vec::new()
        };
        let sigscripts_for_conv: Vec<Vec<u8>> = batch_tx.inputs.iter().enumerate().map(|(i, inp)| {
            if has_wallet && i == wallet_input_idx {
                placeholder_wallet_ss.clone()
            } else {
                inp.sigscript.clone()
            }
        }).collect();
        let (exact_fee, delta) = plan.converge_fee_exact(&sighash_tx, &sigscripts_for_conv);
        if delta > 0 {
            info!(
                "[BATCH] Phase 2 fee convergence: exact={}, delta={} (recovered)",
                exact_fee, delta
            );
            plan.apply_exact_fee(exact_fee);

            // Rebuild sighash_tx outputs and rpc_outputs from adjusted plan.
            sighash_tx.outputs.clear();
            rpc_outputs.clear();
            let n = plan.sells.len();
            for (i, out) in plan.outputs.iter().enumerate() {
                let spk_hex = hex::encode(&out.script_public_key);

                if out.purpose == OutputPurpose::BuyerTokens {
                    let buy_j = i.saturating_sub(n);
                    if buy_j < plan.buys.len() {
                        let (buy, _) = &plan.buys[buy_j];
                        let token_hex = hex::encode(buy.token_cov_id);
                        if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                            rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                                out.value, out.spk_version, &spk_hex,
                                tii as u16, &token_hex,
                            ));
                            sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                                out.value, out.spk_version, out.script_public_key.clone(),
                                Some(kob_core::tx::CovenantBinding::new(
                                    tii as u16,
                                    kob_core::compat::parse_hash(&token_hex).unwrap(),
                                )),
                            ));
                            continue;
                        }
                    }
                    rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
                } else if out.purpose == OutputPurpose::SellRemainder {
                    if let Some((sell, _)) = plan.sells.first() {
                        let token_hex = hex::encode(sell.token_cov_id);
                        if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                            rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                                out.value, out.spk_version, &spk_hex,
                                tii as u16, &token_hex,
                            ));
                            sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                                out.value, out.spk_version, out.script_public_key.clone(),
                                Some(kob_core::tx::CovenantBinding::new(
                                    tii as u16,
                                    kob_core::compat::parse_hash(&token_hex).unwrap(),
                                )),
                            ));
                            continue;
                        }
                    }
                    rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
                } else {
                    rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
                }

                sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                    out.value, out.spk_version, out.script_public_key.clone(), None,
                ));
            }
        }
    }

    // M1: Mass pre-check with placeholder wallet sigscript (post-convergence).
    //
    // Since Phase 2 already applied the exact fee, the values here are final.
    // The late check below will observe the same compute/storage mass
    // byte-exact (sigscript length 66B is constant between placeholder and
    // real Schnorr sig).
    //
    // Purpose: short-circuit `schnorr_sign` + privkey zeroize on
    // mass-violation.
    {
        // Input plurality: P2SH (35B SPK) and P2PK (33B SPK) both give p=1.
        let in_cells: Vec<(u64, u64)> = plan.sells.iter().map(|(s, _)| (s.utxo_value, 1u64)).chain(
            plan.buys.iter().map(|(b, _)| (b.utxo_value, 1u64))
        ).chain(
            plan.wallet_input.iter().map(|(_, _, val)| (*val, 1u64))
        ).collect();
        // Output plurality: covenant outputs (BuyerTokens/SellRemainder) get p>1.
        let out_cells: Vec<(u64, u64)> = plan.outputs.iter()
            .map(|o| (o.value, planned_output_plurality(o)))
            .collect();

        if check_mass_presubmit(&in_cells, &out_cells, "BATCH/early").is_none() {
            for (sell, _) in &plan.sells {
                spent_tracker.mark_failed(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1));
            }
            for (buy, _) in &plan.buys {
                spent_tracker.mark_failed(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1));
            }
            return None;
        }

        let placeholder_wallet_ss = if has_wallet {
            kob_core::contract::build_p2pk_sigscript(&[0u8; 64])
        } else {
            Vec::new()
        };
        let sigscripts_early: Vec<Vec<u8>> = batch_tx.inputs.iter().enumerate().map(|(i, inp)| {
            if has_wallet && i == wallet_input_idx {
                placeholder_wallet_ss.clone()
            } else {
                inp.sigscript.clone()
            }
        }).collect();
        let compute_mass_early = kob_core::mass::calc_mass_with_sigscripts(&sighash_tx, &sigscripts_early);
        let storage_mass_early = kob_core::mass::compute_storage_mass_ex(&in_cells, &out_cells);
        let effective_early = compute_mass_early.max(storage_mass_early);
        info!(
            "[BATCH] Mass check (early, placeholder): compute={}, storage={}, effective={}, limit={}",
            compute_mass_early, storage_mass_early, effective_early, kob_core::MAX_TX_MASS
        );
        if effective_early > kob_core::MAX_TX_MASS {
            error!(
                "[BATCH] Early effective mass {} exceeds limit {} — skipping wallet sign",
                effective_early, kob_core::MAX_TX_MASS
            );
            for (sell, _) in &plan.sells {
                spent_tracker.mark_failed(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1));
            }
            for (buy, _) in &plan.buys {
                spent_tracker.mark_failed(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1));
            }
            return None;
        }
    }

    // Sign the wallet input ONCE (post-convergence sighash).
    if has_wallet {
        let mut privkey = config.private_key_bytes();
        let sighash = kob_core::compute_sighash(&sighash_tx, wallet_input_idx).ok()?;
        let sig = match kob_core::schnorr_sign(&sighash, &privkey) {
            Ok(s) => s,
            Err(e) => {
                privkey.zeroize();
                error!("[BATCH] Wallet input signing failed: {}", e);
                return None;
            }
        };
        privkey.zeroize();
        let wallet_ss = kob_core::contract::build_p2pk_sigscript(&sig);

        let wallet_inp = &batch_tx.inputs[wallet_input_idx];
        rpc_inputs.push(deploy::build_rpc_input(
            &wallet_inp.tx_id,
            wallet_inp.index,
            &hex::encode(&wallet_ss),
            1, // sigOpCount = 1 for P2PK
        ));
        wallet_sigscript = Some(wallet_ss);
    }

    // Mass pre-check: storage mass + compute mass (with real sigscripts)
    {
        let in_cells: Vec<(u64, u64)> = plan.sells.iter().map(|(s, _)| (s.utxo_value, 1u64)).chain(
            plan.buys.iter().map(|(b, _)| (b.utxo_value, 1u64))
        ).chain(
            plan.wallet_input.iter().map(|(_, _, val)| (*val, 1u64))
        ).collect();
        let out_cells: Vec<(u64, u64)> = plan.outputs.iter()
            .map(|o| (o.value, planned_output_plurality(o)))
            .collect();

        // 1. Storage mass check
        if check_mass_presubmit(&in_cells, &out_cells, "BATCH").is_none() {
            for (sell, _) in &plan.sells {
                spent_tracker.mark_failed(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1));
            }
            for (buy, _) in &plan.buys {
                spent_tracker.mark_failed(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1));
            }
            return None;
        }

        // 2. Compute mass check (with real sigscripts)
        let sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter().enumerate().map(|(i, inp)| {
            if has_wallet && i == wallet_input_idx {
                wallet_sigscript.clone().unwrap_or_default()
            } else {
                inp.sigscript.clone()
            }
        }).collect();
        let compute_mass = kob_core::mass::calc_mass_with_sigscripts(&sighash_tx, &sigscripts);
        let storage_mass = kob_core::mass::compute_storage_mass_ex(&in_cells, &out_cells);
        let effective_mass = compute_mass.max(storage_mass);
        info!(
            "[BATCH] Mass check: compute={}, storage={}, effective={}, limit={}",
            compute_mass, storage_mass, effective_mass, kob_core::MAX_TX_MASS
        );
        if effective_mass > kob_core::MAX_TX_MASS {
            error!(
                "[BATCH] Effective mass {} exceeds limit {} — rejecting TX",
                effective_mass, kob_core::MAX_TX_MASS
            );
            for (sell, _) in &plan.sells {
                spent_tracker.mark_failed(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1));
            }
            for (buy, _) in &plan.buys {
                spent_tracker.mark_failed(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1));
            }
            return None;
        }
    }

    // Bytecode trace: disassemble all input sigscripts at debug level
    trace_batch_inputs(&batch_tx, plan);

    // === DEBUG: Dump full TX structure before submit ===
    info!("=== BATCH TX DEBUG DUMP ===");
    info!("  version=1, lockTime=50, inputs={}, outputs={}", rpc_inputs.len(), rpc_outputs.len());
    for (i, inp) in rpc_inputs.iter().enumerate() {
        let sig_hex = inp["signatureScript"].as_str().unwrap_or("");
        let seq = inp["sequence"].as_u64().unwrap_or(0);
        let soc = inp["sigOpCount"].as_u64().unwrap_or(0);
        let tx = inp["previousOutpoint"]["transactionId"].as_str().unwrap_or("?");
        let idx = inp["previousOutpoint"]["index"].as_u64().unwrap_or(0);
        info!("  INPUT[{}]: {}:{} seq={} sigOp={} ssLen={}", i, &tx[..8.min(tx.len())], idx, seq, soc, sig_hex.len()/2);
    }
    for (i, out) in rpc_outputs.iter().enumerate() {
        let val = out["value"].as_u64().unwrap_or(0);
        let spk = out["scriptPublicKey"]["script"].as_str().unwrap_or("?");
        let has_cov = out.get("covenant").is_some();
        let cov_info = if has_cov {
            let ai = out["covenant"]["authorizingInput"].as_u64().unwrap_or(999);
            let cid = out["covenant"]["covenantId"].as_str().unwrap_or("?");
            format!(" COV(ai={}, cid={}..)", ai, &cid[..16.min(cid.len())])
        } else {
            String::new()
        };
        info!("  OUTPUT[{}]: value={} spk={}..{}{}", i, val, &spk[..8.min(spk.len())], if spk.len() > 8 { &spk[spk.len()-4..] } else { "" }, cov_info);
    }
    // Also dump plan output purposes for cross-reference
    for (i, po) in plan.outputs.iter().enumerate() {
        info!("  PLAN_OUT[{}]: purpose={:?} value={}", i, po.purpose, po.value);
    }
    // Dump sigscript indices used
    for (i, (sell, input_idx)) in plan.sells.iter().enumerate() {
        info!("  SELL[{}]: input_idx={} outpoint={}:{} amount={} price={}/{}", i, input_idx, &sell.outpoint.0[..8], sell.outpoint.1, sell.amount, sell.price_num, sell.price_den);
    }
    for (i, (buy, input_idx)) in plan.buys.iter().enumerate() {
        let token_hex = hex::encode(buy.token_cov_id);
        let tii = plan.token_input_map.get(&token_hex).copied().unwrap_or(999);
        let toi = plan.sells.len() + i;
        info!("  BUY[{}]: input_idx={} toi={} tii={} outpoint={}:{} amount={} price={}/{}", i, input_idx, toi, tii, &buy.outpoint.0[..8], buy.outpoint.1, buy.amount, buy.price_num, buy.price_den);
    }
    info!("=== END DEBUG DUMP ===");

    // Submit via RPC (version=1 for covenant output bindings, lockTime=50 for OP_CSV)
    let payload = match ifd_payload {
        Some(ref hex) => deploy::build_submit_payload_with_tx_payload(1, rpc_inputs, rpc_outputs, hex, 50),
        None => deploy::build_submit_payload_with_lock_time(1, rpc_inputs, rpc_outputs, 50),
    };
    // Dump full payload JSON at debug level for manual replay
    if tracing::enabled!(tracing::Level::DEBUG) {
        info!("[BATCH] Full RPC payload (for manual replay):");
        info!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
    }
    let result = match rpc.submit_transaction(payload).await {
        Ok(r) => r,
        Err(e) => {
            let err_str = e.to_string();
            let is_transient = err_str.contains("sequence locks");
            if is_transient {
                warn!("[BATCH] CSV not yet mature (transient): {}", err_str);
            } else {
                error!("[BATCH] Submit failed: {}", err_str);
            }
            let mark = |key: &str, tracker: &mut SpentTracker| {
                if is_transient {
                    tracker.mark_transient(key);
                } else {
                    tracker.mark_failed(key);
                }
            };
            for (sell, _) in &plan.sells {
                mark(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1), spent_tracker);
            }
            for (buy, _) in &plan.buys {
                mark(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1), spent_tracker);
            }
            return None;
        }
    };

    if !result.ok {
        let err_str = result.error.unwrap_or_else(|| "Unknown error".to_string());
        let is_transient = err_str.contains("sequence locks");
        if is_transient {
            warn!("[BATCH] CSV not yet mature (transient): {}", err_str);
        } else {
            error!("[BATCH] FAILED: {}", err_str);
        }
        let mark = |key: &str, tracker: &mut SpentTracker| {
            if is_transient {
                tracker.mark_transient(key);
            } else {
                tracker.mark_failed(key);
            }
        };
        for (sell, _) in &plan.sells {
            mark(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1), spent_tracker);
        }
        for (buy, _) in &plan.buys {
            mark(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1), spent_tracker);
        }
        return None;
    }

    let tx_id = result.tx_id.unwrap_or_else(|| {
        warn!("[BATCH] Success response missing tx_id");
        String::new()
    });
    info!("[BATCH] SUCCESS! TXID: {}", tx_id);
    info!("  Sells matched: {}", plan.sells.len());
    info!("  Buys matched:  {}", plan.buys.len());

    // Track all spent outpoints, recording the submit txid so prune_spent
    // can detect mempool presence and avoid premature eviction.
    let mut marked_keys: Vec<String> = Vec::new();
    for (sell, _) in &plan.sells {
        let key = format!("{}:{}", sell.outpoint.0, sell.outpoint.1);
        spent_tracker.mark_spent(&key);
        marked_keys.push(key);
    }
    for (buy, _) in &plan.buys {
        let key = format!("{}:{}", buy.outpoint.0, buy.outpoint.1);
        spent_tracker.mark_spent(&key);
        marked_keys.push(key);
    }
    if let Some((ref wallet_tx_id, wallet_index, _)) = plan.wallet_input {
        let key = format!("{}:{}", wallet_tx_id, wallet_index);
        spent_tracker.mark_spent(&key);
        marked_keys.push(key);
    }
    if !tx_id.is_empty() {
        spent_tracker.mark_submitted(&tx_id, &marked_keys);
    }

    // Compute total seller KAS from outputs
    let total_seller_kas: u64 = plan.outputs.iter()
        .filter(|o| o.purpose == OutputPurpose::SellerKas)
        .map(|o| o.value)
        .sum();

    Some(BatchMatchResult {
        tx_id,
        sell_count: plan.sells.len(),
        buy_count: plan.buys.len(),
        total_seller_kas,
        matcher_surplus: plan.matcher_surplus,
    })
}

/// Execute a cross-pair swap fill: build and submit the atomic TX.
///
/// TX layout (defined by swap covenant in `swap.rs`):
///   Inputs:  [0] swap UTXO, [1] sell_target, [2] buy_source, [3] wallet
///   Outputs: [0] Token A → buyer, [1] Token B → swap owner, [2] KAS → seller, [3] change
///
/// The swap UTXO (input 0) carries the source token covenant binding.
/// The sell_target (input 1) carries the target token covenant binding.
/// Output[0] gets Token A covenant from input 0, output[1] gets Token B covenant from input 1.
pub async fn execute_swap_fill(
    rpc: &RpcClient,
    sg: &crate::matcher::matching::CrossSwapGroup,
    sell_target: &crate::matcher::batch::BatchOrder,
    buy_source: &crate::matcher::batch::BatchOrder,
    wallet_utxo: Option<(String, u32, u64)>,
    wallet_spk: &[u8],
    wallet_spk_version: u16,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
) -> Option<BatchMatchResult> {
    // Helper: mark the 3 participating outpoints as failed (permanent) so
    // Phase 3 does not retry this dead-end group.
    let keys_of = || [
        sg.swap.outpoint_key(),
        sg.buy_source.outpoint_key(),
        sg.sell_target.outpoint_key(),
    ];

    // --- Parse swap entry ---
    let swap_rs = match hex::decode(&sg.swap.redeem_script_hex) {
        Ok(rs) if !rs.is_empty() => rs,
        _ => {
            warn!("[SWAP-FILL] Failed to decode swap RS");
            for k in keys_of().iter() { spent_tracker.mark_failed(k); }
            return None;
        }
    };
    let swap_p2sh = kob_core::build_p2sh(&swap_rs);

    // Owner SPK (hex: 2B version LE + script bytes) for target token output
    let owner_spk_raw = match &sg.swap.owner_spk {
        Some(h) => match hex::decode(h) {
            Ok(v) if v.len() > 2 => v,
            _ => {
                warn!("[SWAP-FILL] Invalid owner_spk hex");
                for k in keys_of().iter() { spent_tracker.mark_failed(k); }
                return None;
            }
        },
        None => {
            // Missing owner_spk is transient: the L1 scanner may populate it
            // later by matching the SPK hash against observed TX outputs.
            // Don't permanently blacklist the orders.
            warn!("[SWAP-FILL] Missing owner_spk — cannot build fill (deferred)");
            for k in keys_of().iter() { spent_tracker.mark_transient(k); }
            return None;
        }
    };
    let owner_spk_version = u16::from_le_bytes([owner_spk_raw[0], owner_spk_raw[1]]);
    let owner_spk_script = &owner_spk_raw[2..];

    // --- Receipt input index (rii) ---
    // Swap covenant F1 checks: input[rii].covenant_id == receipt_cov_id.
    // Source cov_id lives on input 0 (swap UTXO), target on input 1 (sell_target).
    let rii: u16 = if sg.swap.receipt_cov_id == sg.swap.source_cov_id {
        0
    } else if sg.swap.receipt_cov_id == sg.sell_target.token_cov_id {
        1
    } else {
        warn!(
            "[SWAP-FILL] receipt_cov_id {} matches neither source {} nor target {} — skip",
            &sg.swap.receipt_cov_id[..16.min(sg.swap.receipt_cov_id.len())],
            &sg.swap.source_cov_id[..16.min(sg.swap.source_cov_id.len())],
            &sg.sell_target.token_cov_id[..16.min(sg.sell_target.token_cov_id.len())],
        );
        // Receipt mismatch is specific to this swap order's config — permanent.
        for k in keys_of().iter() { spent_tracker.mark_failed(k); }
        return None;
    };

    // V15 buy not supported in cross-pair swap (reads sell sigscript at sii)
    if buy_source.redeem_script.len()
        == kob_core::contract::spot::order::BUY_ORDER_V15_RS_EXPECTED_LEN
    {
        warn!("[SWAP-FILL] v15 buy not supported in cross-pair swap — skip");
        for k in keys_of().iter() { spent_tracker.mark_failed(k); }
        return None;
    }

    // --- Sigscripts ---
    // Input[0] swap:        [rii] [toi=1] [Op1] [pushData(RS)]
    let swap_ss = kob_core::contract::spot::swap::build_swap_fill_sigscript(rii, 1, &swap_rs);
    // Input[1] sell_target: [koi=2] [Op1] [pushData(RS)]
    let sell_ss = kob_core::contract::spot::order::build_sell_fill_sigscript(2, &sell_target.redeem_script);
    // Input[2] buy_source:  [toi=0] [tii=0] [coi=0] [Op1] [pushData(RS)]
    let buy_ss = kob_core::contract::spot::order::build_buy_fill_sigscript(0, 0, 0, &buy_source.redeem_script);

    // --- Wallet ---
    let wallet = match wallet_utxo {
        Some(w) => w,
        None => {
            // Transient: wallet may have UTXOs in the next cycle.
            warn!("[SWAP-FILL] No wallet UTXO (deferred)");
            for k in keys_of().iter() { spent_tracker.mark_transient(k); }
            return None;
        }
    };

    // --- Output values ---
    let source_token_amount = sg.swap.value;       // Token A → buyer
    let target_token_amount = sg.sell_target.value; // Token B → swap owner
    let kas_to_seller = sg.kas_flow;

    // Fee estimation: 4 inputs, 4 outputs, 1 sig_op (wallet)
    let estimated_fee = kob_core::mass::estimate_compute_mass(4, 4, 1);

    // Matcher change = surplus + wallet - fee
    // (token values cancel: swap.value → output[0], sell.value → output[1])
    let matcher_change = (sg.surplus + wallet.2).saturating_sub(estimated_fee);

    // Minimum value checks — these are a function of the price/amount
    // numbers on the orders themselves, so permanent for this triple.
    if kas_to_seller < MIN_UTXO_VALUE {
        warn!("[SWAP-FILL] KAS to seller {} below min {}", kas_to_seller, MIN_UTXO_VALUE);
        for k in keys_of().iter() { spent_tracker.mark_failed(k); }
        return None;
    }
    if matcher_change < MIN_UTXO_VALUE {
        warn!("[SWAP-FILL] Matcher change {} below min {}", matcher_change, MIN_UTXO_VALUE);
        for k in keys_of().iter() { spent_tracker.mark_failed(k); }
        return None;
    }

    // --- Build sighash TX ---
    let mut sighash_tx = kob_core::tx::Transaction::new(1);
    sighash_tx.lock_time = 50;

    // Input[0]: swap UTXO (covenant, CSV=50, sigOp=0)
    sighash_tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: sg.swap.tx_id.clone(),
        prev_index: sg.swap.index,
        sequence: 50, sig_op_count: 0,
        script_version: swap_p2sh.version,
        script_bytes: swap_p2sh.script().to_vec(),
        value: sg.swap.value,
    });
    // Input[1]: sell_target (covenant, CSV=50, sigOp=0)
    let sell_p2sh = kob_core::build_p2sh(&sell_target.redeem_script);
    sighash_tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: sell_target.outpoint.0.clone(),
        prev_index: sell_target.outpoint.1,
        sequence: 50, sig_op_count: 0,
        script_version: sell_p2sh.version,
        script_bytes: sell_p2sh.script().to_vec(),
        value: sell_target.utxo_value,
    });
    // Input[2]: buy_source (covenant, CSV=50, sigOp=0)
    let buy_p2sh = kob_core::build_p2sh(&buy_source.redeem_script);
    sighash_tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: buy_source.outpoint.0.clone(),
        prev_index: buy_source.outpoint.1,
        sequence: 50, sig_op_count: 0,
        script_version: buy_p2sh.version,
        script_bytes: buy_p2sh.script().to_vec(),
        value: buy_source.utxo_value,
    });
    // Input[3]: wallet (P2PK, seq=0, sigOp=1)
    let wallet_input_idx: usize = 3;
    sighash_tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: wallet.0.clone(),
        prev_index: wallet.1,
        sequence: 0, sig_op_count: 1,
        script_version: wallet_spk_version,
        script_bytes: wallet_spk.to_vec(),
        value: wallet.2,
    });

    // --- Outputs ---
    let source_cov_id = &sg.swap.source_cov_id;
    let target_cov_id = &sg.swap.target_cov_id;
    let source_hash = kob_core::compat::parse_hash(source_cov_id).unwrap();
    let target_hash = kob_core::compat::parse_hash(target_cov_id).unwrap();

    // Output[0]: Token A → buyer (covenant: source token, auth input 0)
    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
        source_token_amount, buy_source.counterparty_spk_version,
        buy_source.counterparty_spk.clone(),
        Some(kob_core::tx::CovenantBinding::new(0, source_hash)),
    ));
    // Output[1]: Token B → swap owner (covenant: target token, auth input 1)
    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
        target_token_amount, owner_spk_version,
        owner_spk_script.to_vec(),
        Some(kob_core::tx::CovenantBinding::new(1, target_hash)),
    ));
    // Output[2]: KAS → seller
    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
        kas_to_seller, sell_target.counterparty_spk_version,
        sell_target.counterparty_spk.clone(), None,
    ));
    // Output[3]: matcher change
    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
        matcher_change, wallet_spk_version,
        wallet_spk.to_vec(), None,
    ));

    // --- RPC outputs ---
    let buyer_spk_hex = hex::encode(&buy_source.counterparty_spk);
    let owner_spk_hex = hex::encode(owner_spk_script);
    let seller_spk_hex = hex::encode(&sell_target.counterparty_spk);
    let matcher_spk_hex = hex::encode(wallet_spk);

    let rpc_outputs = vec![
        deploy::build_rpc_output_with_covenant(
            source_token_amount, buy_source.counterparty_spk_version,
            &buyer_spk_hex, 0, source_cov_id,
        ),
        deploy::build_rpc_output_with_covenant(
            target_token_amount, owner_spk_version,
            &owner_spk_hex, 1, target_cov_id,
        ),
        deploy::build_rpc_output(
            kas_to_seller, sell_target.counterparty_spk_version, &seller_spk_hex,
        ),
        deploy::build_rpc_output(
            matcher_change, wallet_spk_version, &matcher_spk_hex,
        ),
    ];

    // --- RPC inputs (covenant inputs first, wallet last) ---
    let mut rpc_inputs = vec![
        deploy::build_rpc_input_with_sequence(
            &sg.swap.tx_id, sg.swap.index, &hex::encode(&swap_ss), 0, 50,
        ),
        deploy::build_rpc_input_with_sequence(
            &sell_target.outpoint.0, sell_target.outpoint.1,
            &hex::encode(&sell_ss), 0, 50,
        ),
        deploy::build_rpc_input_with_sequence(
            &buy_source.outpoint.0, buy_source.outpoint.1,
            &hex::encode(&buy_ss), 0, 50,
        ),
    ];

    // --- Sign wallet input ---
    let mut privkey = config.private_key_bytes();
    let sighash = match kob_core::compute_sighash(&sighash_tx, wallet_input_idx) {
        Ok(sh) => sh,
        Err(e) => {
            privkey.zeroize();
            error!("[SWAP-FILL] Sighash failed: {}", e);
            for k in keys_of().iter() { spent_tracker.mark_failed(k); }
            return None;
        }
    };
    let sig = match kob_core::schnorr_sign(&sighash, &privkey) {
        Ok(s) => s,
        Err(e) => {
            privkey.zeroize();
            error!("[SWAP-FILL] Signing failed: {}", e);
            for k in keys_of().iter() { spent_tracker.mark_failed(k); }
            return None;
        }
    };
    privkey.zeroize();
    let wallet_ss = kob_core::contract::build_p2pk_sigscript(&sig);
    rpc_inputs.push(deploy::build_rpc_input(
        &wallet.0, wallet.1, &hex::encode(&wallet_ss), 1,
    ));

    // --- Mass pre-check ---
    // Inputs: all P2SH (35B) → p=1.
    let in_cells: Vec<(u64, u64)> = vec![
        (sg.swap.value, 1), (sell_target.utxo_value, 1),
        (buy_source.utxo_value, 1), (wallet.2, 1),
    ];
    // Outputs: Token outputs carry covenant (p=2 for 33B P2PK + 32B cov);
    // KAS/change outputs have no covenant (p=1).
    let swap_out_plurality = |spk_len: usize, has_cov: bool| -> u64 {
        (63 + spk_len + if has_cov { 32 } else { 0 }).div_ceil(100) as u64
    };
    let out_cells: Vec<(u64, u64)> = vec![
        (source_token_amount, swap_out_plurality(buy_source.counterparty_spk.len(), true)),
        (target_token_amount, swap_out_plurality(owner_spk_script.len(), true)),
        (kas_to_seller, swap_out_plurality(sell_target.counterparty_spk.len(), false)),
        (matcher_change, swap_out_plurality(wallet_spk.len(), false)),
    ];
    if check_mass_presubmit(&in_cells, &out_cells, "SWAP-FILL").is_none() {
        for k in keys_of().iter() { spent_tracker.mark_failed(k); }
        return None;
    }

    // --- Debug dump ---
    info!("======================================================================");
    info!("EXECUTING SWAP FILL: swap → buy_source(Token A) + sell_target(Token B)");
    info!("======================================================================");
    info!("  swap={}:{} (src_tok={})", &sg.swap.tx_id[..16.min(sg.swap.tx_id.len())], sg.swap.index, sg.swap.value);
    info!("  sell_target={}:{} (tgt_tok={})", &sell_target.outpoint.0[..16.min(sell_target.outpoint.0.len())], sell_target.outpoint.1, sell_target.utxo_value);
    info!("  buy_source={}:{} (kas={})", &buy_source.outpoint.0[..16.min(buy_source.outpoint.0.len())], buy_source.outpoint.1, buy_source.utxo_value);
    info!("  kas_flow={} surplus={} fee={} matcher_change={} rii={}", kas_to_seller, sg.surplus, estimated_fee, matcher_change, rii);

    // --- Submit ---
    let payload = deploy::build_submit_payload_with_lock_time(1, rpc_inputs, rpc_outputs, 50);
    let result = match rpc.submit_transaction(payload).await {
        Ok(r) => r,
        Err(e) => {
            let err_str = e.to_string();
            let is_transient = err_str.contains("sequence locks");
            if is_transient {
                warn!("[SWAP-FILL] CSV not yet mature (transient): {}", err_str);
            } else {
                error!("[SWAP-FILL] Submit failed: {}", err_str);
            }
            // Mark the 3 participating outpoints so Phase 3's None branch
            // does NOT need to re-mark them (caller treats None uniformly).
            let mark_all = |tracker: &mut SpentTracker| {
                let keys = [
                    sg.swap.outpoint_key(),
                    sg.buy_source.outpoint_key(),
                    sg.sell_target.outpoint_key(),
                ];
                for k in &keys {
                    if is_transient {
                        tracker.mark_transient(k);
                    } else {
                        tracker.mark_failed(k);
                    }
                }
            };
            mark_all(spent_tracker);
            return None;
        }
    };
    if !result.ok {
        let err_str = result.error.clone().unwrap_or_else(|| "unknown".to_string());
        let is_transient = err_str.contains("sequence locks");
        if is_transient {
            warn!("[SWAP-FILL] CSV not yet mature (TX rejected, transient): {}", err_str);
        } else {
            error!("[SWAP-FILL] TX rejected: {}", err_str);
        }
        let keys = [
            sg.swap.outpoint_key(),
            sg.buy_source.outpoint_key(),
            sg.sell_target.outpoint_key(),
        ];
        for k in &keys {
            if is_transient {
                spent_tracker.mark_transient(k);
            } else {
                spent_tracker.mark_failed(k);
            }
        }
        return None;
    }

    let tx_id = result.tx_id.unwrap_or_default();
    info!("[SWAP-FILL] SUCCESS! TXID: {}", tx_id);

    Some(BatchMatchResult {
        tx_id,
        sell_count: 1,
        buy_count: 1,
        total_seller_kas: kas_to_seller,
        matcher_surplus: sg.surplus,
    })
}

// L1 Block Scanning — Order Discovery

/// Process a batch of transactions from a block notification.
///
/// For each transaction:
///   1. Check if any inputs spend known orders -> remove from book.
///   2. Check if the TX deploys a new KOB order (P2SH + payload) -> add to book.
///
/// Returns the number of orders added and removed.
///
/// When `ws_tx` is provided, emits `OrderDetected` and `OrderCancelled`
/// events for each new/removed order so that user-order WS subscribers
/// receive real-time notifications.
#[allow(dead_code)] // Used in tests
pub fn process_block_txs(
    txs: &[TransactionData],
    order_book: &mut OrderBook,
    scanner: &BlockScanner,
) -> (usize, usize) {
    process_block_txs_inner(txs, order_book, scanner, None)
}

fn process_block_txs_inner(
    txs: &[TransactionData],
    order_book: &mut OrderBook,
    scanner: &BlockScanner,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
) -> (usize, usize) {
    let mut added = 0;
    let mut removed = 0;

    for tx in txs {
        // Phase 1: Remove spent orders
        let spent_keys = BlockScanner::find_spent_orders(tx, order_book);
        for key in &spent_keys {
            info!("[SCANNER] Order spent: {}", &key[..key.len().min(20)]);

            // Capture order info before removal for WS event emission.
            if let Some(ws) = ws_tx {
                if let Some(order) = order_book.get_order(key) {
                    crate::matcher::api::emit_order_cancelled(
                        ws,
                        &order.owner_hash,
                        key,
                        &tx.tx_id,
                        &order.token_cov_id,
                    );
                }
            }

            order_book.remove_order(key);
            removed += 1;
        }

        // Phase 2: Detect new deploys
        if let Some((parsed, p2sh_idx, p2sh_value)) = scanner.scan_tx(tx) {
            // For buy orders, the token_cov_id is in the RS.
            // For sell orders, it's not in the RS — we need to determine it
            // from the UTXO's covenant ID. In practice, the sell deploy TX
            // must have a covenant input that identifies the token. For now,
            // sell orders without a known token_cov_id are skipped unless
            // the deploy TX structure provides it (e.g., a token input).
            //
            // NOTE: In the current L1 deploy flow, sell orders always have
            // a token_unit input whose covenant ID identifies the token.
            // We can extract this from the TX's inputs if covenant data
            // is available. For a fully permissionless scanner that only
            // sees block data without UTXO set context, the token_cov_id
            // must be provided in the TX payload or inferred from the deploy
            // pattern. This is a known limitation that can be resolved by:
            //   a) Querying the UTXO set for covenant IDs of the TX inputs
            //   b) Adding the token_cov_id to the TX payload
            //
            // For now, sell orders are added with a zero token_cov_id,
            // which will need to be resolved by the matcher via RPC.

            let book_order = BlockScanner::to_book_order_with_tx(
                &parsed,
                &tx.tx_id,
                p2sh_idx,
                p2sh_value,
                None, // Use parsed token_cov_id (correct for buy, zero for sell — sell now resolved from output covenant)
                Some(tx),
            );

            let order_type_str = match parsed.order_type {
                OrderSide::Buy => "BUY",
                OrderSide::Sell => "SELL",
            };

            // Skip orders with cancel_pending set
            if parsed.cpend != 0 {
                info!(
                    "[SCANNER] Skipping {} order (cancel_pending=1): {}:{}",
                    order_type_str, &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx
                );
                continue;
            }

            info!(
                "[SCANNER] Discovered {} v{} order: {}:{} value={} price={}/{}",
                order_type_str,
                parsed.version,
                &tx.tx_id[..tx.tx_id.len().min(16)],
                p2sh_idx,
                p2sh_value,
                parsed.price_num,
                parsed.price_den,
            );

            // M-7: Dedup check -- skip if outpoint already exists in any pair book.
            // This prevents duplicate orders when the same block notification is
            // received twice (e.g., during RPC reconnection).
            let outpoint_key = book_order.outpoint_key();
            if order_book.contains_outpoint(&outpoint_key) {
                info!(
                    "[SCANNER] Skipping duplicate {} order: {} (M-7)",
                    order_type_str,
                    &outpoint_key[..outpoint_key.len().min(20)]
                );
                continue;
            }

            match parsed.order_type {
                OrderSide::Buy => {
                    // Emit OrderDetected before adding (book_order will be moved)
                    if let Some(ws) = ws_tx {
                        crate::matcher::api::emit_order_detected(
                            ws,
                            &book_order.owner_hash,
                            &outpoint_key,
                            OrderSide::Buy,
                            book_order.price_num,
                            book_order.price_den,
                            book_order.value,
                            &book_order.token_cov_id,
                        );
                    }
                    order_book.add_buy_order(book_order);
                },
                OrderSide::Sell => {
                    // Sell RS does not embed the token covenant ID.
                    // If token_cov_id is all zeros, the token identity is unknown
                    // (requires RPC UTXO covenant context). Skip to prevent ghost orders.
                    if book_order.token_cov_id == "0".repeat(64) {
                        warn!(
                            "[SCANNER] Skipping SELL order with unknown token_cov_id (all zeros): {}:{}",
                            &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx
                        );
                        continue;
                    }
                    if let Some(ws) = ws_tx {
                        crate::matcher::api::emit_order_detected(
                            ws,
                            &book_order.owner_hash,
                            &outpoint_key,
                            OrderSide::Sell,
                            book_order.price_num,
                            book_order.price_den,
                            book_order.value,
                            &book_order.token_cov_id,
                        );
                    }
                    order_book.add_sell_order(book_order);
                }
            }
            added += 1;
        }
    }

    (added, removed)
}

// Multi-product block scanning (spot + perp + lending + prediction)

/// Counters returned by `process_block_txs_all`.
#[derive(Debug, Default)]
pub struct ScanCounters {
    pub spot_added: usize,
    pub spot_removed: usize,
    pub perp_added: usize,
    pub perp_removed: usize,
    pub lending_added: usize,
    pub lending_removed: usize,
    pub prediction_added: usize,
    pub prediction_removed: usize,
    pub dca_added: usize,
    pub dca_removed: usize,
    pub swap_added: usize,
    pub swap_removed: usize,
}

/// Process a batch of transactions using the multi-product scanner.
///
/// For each TX:
///   1. Remove spent orders from ALL books (spot, perp, lending, prediction).
///   2. Detect new deploys via `scan_tx_all()` and route to the appropriate book.
///
/// This is the unified replacement for `process_block_txs_inner` that handles
/// all four product types in a single pass.
/// Collects provenance data during block processing for reorg tracking.
///
/// When provided to `process_block_txs_all`, this accumulates:
/// - Orders added to the book (cloned snapshots)
/// - Orders spent from the book (with pre-removal snapshots)
/// - All TX IDs seen in the block
///
/// After processing, the caller can commit this data to the `ReorgTracker`.
struct ReorgCollector {
    orders_added: Vec<crate::matcher::order_book::BookOrder>,
    orders_spent: Vec<(String, crate::matcher::order_book::BookOrder)>,
    txids: HashSet<String>,
}

impl ReorgCollector {
    fn new() -> Self {
        Self {
            orders_added: Vec::new(),
            orders_spent: Vec::new(),
            txids: HashSet::new(),
        }
    }
}

/// Process-wide log-dedup for `[INDEXER] skipped unmatchable` warnings.
/// Capped at `UNMATCHABLE_LOGGED_MAX` entries to prevent unbounded growth (M7).
/// When the cap is reached, the set is cleared and re-populated organically.
static UNMATCHABLE_LOGGED: std::sync::LazyLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

/// Maximum entries in the UNMATCHABLE_LOGGED dedup set before it is cleared (M7).
const UNMATCHABLE_LOGGED_MAX: usize = 10_000;

/// Returns `true` when `order` has no populated `counterparty_spk` and
/// therefore can never match under the batch matcher (which requires the
/// counterparty SPK to build the fill TX). Emits a single `warn!` per
/// outpoint so re-scans do not spam the log.
///
/// Defense-in-depth pair for the per-offender cooldown: this prevents the
/// stale deploy from entering the book at all, avoiding the recycle cost
/// of re-triggering the planner every 30s via the cooldown path.
fn skip_if_no_counterparty_spk(order: &crate::matcher::order_book::BookOrder) -> bool {
    if order.counterparty_spk.as_deref().map_or(true, str::is_empty) {
        let key = order.outpoint_key();
        let first_time = UNMATCHABLE_LOGGED
            .lock()
            .map(|mut s| {
                // M7: Cap the dedup set to prevent unbounded growth.
                // Clearing is safe — worst case a few duplicated log lines.
                if s.len() >= UNMATCHABLE_LOGGED_MAX {
                    warn!(
                        "[INDEXER] UNMATCHABLE_LOGGED reached {} entries, clearing (M7)",
                        s.len()
                    );
                    s.clear();
                }
                s.insert(key.clone())
            })
            .unwrap_or(false);
        if first_time {
            warn!("[INDEXER] skipped unmatchable order {} (no counterparty_spk)", key);
        }
        return true;
    }
    false
}

fn process_block_txs_all(
    txs: &[TransactionData],
    order_book: &mut OrderBook,
    scanner: &BlockScanner,
    perp_book: &mut crate::matcher::perp_book::PerpOrderBook,
    lending_book: &mut crate::matcher::lending_book::LendingBook,
    prediction_book: &mut crate::matcher::prediction_book::PredictionBook,
    mut covenant_cache: Option<&mut CovenantCache>,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    current_daa: u64,
    mut ifd_book: Option<&mut crate::matcher::ifd::IfdBook>,
    mut dca_book: Option<&mut crate::matcher::dca_book::DcaBook>,
    mut swap_book: Option<&mut crate::matcher::swap_book::SwapBook>,
    mut reorg_collector: Option<&mut ReorgCollector>,
) -> ScanCounters {
    let mut counters = ScanCounters::default();

    // Collect perp/lending/prediction/swap outpoints for spent detection.
    let perp_outpoints: HashSet<String> = {
        let mut set = HashSet::new();
        for key in perp_book.all_outpoint_keys() {
            set.insert(key);
        }
        set
    };
    let lending_outpoints: HashSet<String> = lending_book.all_outpoint_keys();
    let prediction_outpoints: HashSet<String> = {
        let mut set = HashSet::new();
        for key in prediction_book.all_outpoint_keys() {
            set.insert(key);
        }
        set
    };
    let dca_outpoints: HashSet<String> = dca_book
        .as_ref()
        .map(|db| db.all_outpoint_keys())
        .unwrap_or_default();
    let swap_outpoints: HashSet<String> = swap_book
        .as_ref()
        .map(|sb| sb.all_outpoint_keys())
        .unwrap_or_default();

    for tx in txs {
        // Reorg tracking: record TX ID
        if let Some(ref mut rc) = reorg_collector {
            rc.txids.insert(tx.tx_id.clone());
        }

        // Passive covenant learning: any TX output with a covenant_id
        // proves that covenant exists on-chain (kaspad validates covenant
        // bindings at TX acceptance). Learn these before order parsing so
        // buy orders referencing the same covenant in the same block pass.
        if let Some(ref mut cache) = covenant_cache {
            for out in &tx.outputs {
                if let Some(cov_bytes) = &out.covenant_id {
                    let cov_hex = hex::encode(cov_bytes);
                    if !cache.is_valid(&cov_hex) {
                        cache.mark_valid(&cov_hex);
                        debug!(
                            "[COVENANT] Learned valid covenant {} from TX {}",
                            &cov_hex[..cov_hex.len().min(16)],
                            &tx.tx_id[..tx.tx_id.len().min(16)],
                        );
                    }
                }
            }
        }

        // Phase 1: Remove spent orders from ALL books

        // Spot book
        let spot_spent = BlockScanner::find_spent_orders(tx, order_book);
        for key in &spot_spent {
            info!("[SCANNER-ALL] Spot order spent: {}", &key[..key.len().min(20)]);

            // Reorg tracking: snapshot the order before removal so it can be
            // restored if this block is reorged out.
            if let Some(ref mut rc) = reorg_collector {
                if let Some(order) = order_book.get_order(key) {
                    rc.orders_spent.push((key.clone(), order.clone()));
                }
            }

            if let Some(ws) = ws_tx {
                if let Some(order) = order_book.get_order(key) {
                    crate::matcher::api::emit_order_cancelled(
                        ws,
                        &order.owner_hash,
                        key,
                        &tx.tx_id,
                        &order.token_cov_id,
                    );
                }
            }
            order_book.remove_order(key);
            counters.spot_removed += 1;
        }

        // Perp book
        let perp_spent = BlockScanner::find_spent_in_keys(tx, &perp_outpoints);
        for key in &perp_spent {
            info!("[SCANNER-ALL] Perp order spent: {}", &key[..key.len().min(20)]);
            perp_book.remove(key);
            counters.perp_removed += 1;
        }

        // Lending book
        let lending_spent = BlockScanner::find_spent_in_keys(tx, &lending_outpoints);
        for key in &lending_spent {
            info!("[SCANNER-ALL] Lending order spent: {}", &key[..key.len().min(20)]);
            lending_book.remove_by_outpoint(key);
            counters.lending_removed += 1;
        }

        // Prediction book
        let prediction_spent = BlockScanner::find_spent_in_keys(tx, &prediction_outpoints);
        for key in &prediction_spent {
            info!("[SCANNER-ALL] Prediction item spent: {}", &key[..key.len().min(20)]);
            prediction_book.remove_by_outpoint(key);
            counters.prediction_removed += 1;
        }

        // DCA book
        let dca_spent = BlockScanner::find_spent_in_keys(tx, &dca_outpoints);
        for key in &dca_spent {
            info!("[SCANNER-ALL] DCA order spent: {}", &key[..key.len().min(20)]);
            if let Some(ref mut db) = dca_book {
                db.remove(key);
            }
            counters.dca_removed += 1;
        }

        // Swap book
        let swap_spent = BlockScanner::find_spent_in_keys(tx, &swap_outpoints);
        for key in &swap_spent {
            info!("[SCANNER-ALL] Swap order spent: {}", &key[..key.len().min(20)]);
            if let Some(ref mut sb) = swap_book {
                sb.remove(key);
            }
            counters.swap_removed += 1;
        }

        // Phase 2: Detect new deploys (all products)
        let scan_hit = scanner.scan_tx_all(tx);
        let scan_hit = match scan_hit {
            Some(h) => h,
            None => continue,
        };

        match scan_hit {
            ScanResult::Spot(parsed, p2sh_idx, p2sh_value) => {
                // Delegate to existing spot logic
                if parsed.cpend != 0 {
                    info!(
                        "[SCANNER-ALL] Skipping spot order (cancel_pending=1): {}:{}",
                        &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    );
                    continue;
                }

                let mut book_order = BlockScanner::to_book_order_with_tx(
                    &parsed, &tx.tx_id, p2sh_idx, p2sh_value, None, Some(tx),
                );
                // FIFO: stamp with the DAA score at which this order was discovered.
                book_order.discovered_daa = current_daa;

                let outpoint_key = book_order.outpoint_key();
                if order_book.contains_outpoint(&outpoint_key) {
                    // Root-fix for counterparty_spk populate timing:
                    // when the first scan sees the deploy TX without fully
                    // resolved outputs, `extract_owner_spk` returns None. The
                    // subsequent rescan has the complete TX and produces
                    // Some(spk). Back-fill the existing order in that case so
                    // the unified batcher can include it.
                    if order_book.update_counterparty_spk_if_missing(
                        &outpoint_key,
                        &book_order.counterparty_spk,
                    ) {
                        info!(
                            "[SCANNER-ALL] Back-filled counterparty_spk on {}",
                            &outpoint_key[..outpoint_key.len().min(20)]
                        );
                    }
                    continue; // dedup
                }

                let order_type_str = match parsed.order_type {
                    OrderSide::Buy => "BUY",
                    OrderSide::Sell => "SELL",
                };
                info!(
                    "[SCANNER-ALL] Discovered {} v{} spot order: {}:{} value={} price={}/{}",
                    order_type_str, parsed.version,
                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    p2sh_value, parsed.price_num, parsed.price_den,
                );

                // IFD activation: check if this order's P2SH matches a pending IFD rule.
                // If so, set counterparty_spk from the IFD rule's order B P2SH data
                // (because bspkh points to order B's P2SH, not the owner's wallet).
                if let Some(ref mut ifd) = ifd_book {
                    let p2sh_hex = &book_order.p2sh_script_hex;
                    if let Some(rule) = ifd.find_by_a_p2sh(p2sh_hex) {
                        let rule_id = rule.id;
                        if rule.status == crate::matcher::ifd::IfdStatus::Pending {
                            // Compute order B's P2SH SPK as counterparty_spk
                            if let Ok(b_rs_bytes) = hex::decode(&rule.order_b_rs_hex) {
                                let b_p2sh_spk = kob_core::build_p2sh(&b_rs_bytes);
                                let mut spk_bytes = Vec::with_capacity(2 + b_p2sh_spk.script().len());
                                spk_bytes.extend_from_slice(&b_p2sh_spk.version.to_le_bytes());
                                spk_bytes.extend_from_slice(&b_p2sh_spk.script());
                                book_order.counterparty_spk = Some(hex::encode(&spk_bytes));
                            }
                            if ifd.activate(rule_id, &outpoint_key) {
                                info!(
                                    "[IFD] Activated rule #{} — order A detected at {}, counterparty_spk set to order B P2SH",
                                    rule_id, &outpoint_key[..outpoint_key.len().min(20)],
                                );
                            }
                        }
                    }
                }

                // Indexer filter: un-matchable orders (no counterparty_spk)
                // never enter the book. Stale v0-style deploys would otherwise
                // recycle through per-offender cooldown every 30s.
                if skip_if_no_counterparty_spk(&book_order) {
                    continue;
                }

                // Covenant ID on-chain verification (applies to both buy and sell).
                // Buy orders embed the covenant ID in their redeem script so it's
                // tamper-proof from a script perspective, but an attacker can still
                // deploy a buy order referencing a non-existent token to waste
                // matcher resources. Sell orders derive the covenant ID from the
                // UTXO output — a fake ID means the match TX would fail on-chain.
                //
                // Skip orders with unverified covenant IDs. They'll be re-discovered
                // on the next scan after async RPC verification completes.
                if book_order.token_cov_id != "0".repeat(64) {
                    if let Some(ref mut cache) = covenant_cache {
                        match cache.check(&book_order.token_cov_id) {
                            Some(true) => { /* known valid, proceed */ }
                            Some(false) => {
                                warn!(
                                    "[SCANNER-ALL] Skipping {} order with invalid covenant ID {}: {}:{}",
                                    match parsed.order_type { OrderSide::Buy => "BUY", OrderSide::Sell => "SELL" },
                                    &book_order.token_cov_id[..book_order.token_cov_id.len().min(16)],
                                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                                );
                                continue;
                            }
                            None => {
                                info!(
                                    "[SCANNER-ALL] Deferring {} order pending covenant verification {}: {}:{}",
                                    match parsed.order_type { OrderSide::Buy => "BUY", OrderSide::Sell => "SELL" },
                                    &book_order.token_cov_id[..book_order.token_cov_id.len().min(16)],
                                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                                );
                                continue;
                            }
                        }
                    }
                }

                match parsed.order_type {
                    OrderSide::Buy => {
                        if let Some(ws) = ws_tx {
                            crate::matcher::api::emit_order_detected(
                                ws, &book_order.owner_hash, &outpoint_key,
                                OrderSide::Buy, book_order.price_num, book_order.price_den,
                                book_order.value, &book_order.token_cov_id,
                            );
                        }
                        // Reorg tracking: snapshot the order before it's moved
                        if let Some(ref mut rc) = reorg_collector {
                            rc.orders_added.push(book_order.clone());
                        }
                        order_book.add_buy_order(book_order);
                    }
                    OrderSide::Sell => {
                        if book_order.token_cov_id == "0".repeat(64) {
                            warn!(
                                "[SCANNER-ALL] Skipping SELL order with unknown token_cov_id (all zeros): {}:{}",
                                &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                            );
                            continue;
                        }
                        if let Some(ws) = ws_tx {
                            crate::matcher::api::emit_order_detected(
                                ws, &book_order.owner_hash, &outpoint_key,
                                OrderSide::Sell, book_order.price_num, book_order.price_den,
                                book_order.value, &book_order.token_cov_id,
                            );
                        }
                        // Reorg tracking: snapshot the order before it's moved
                        if let Some(ref mut rc) = reorg_collector {
                            rc.orders_added.push(book_order.clone());
                        }
                        order_book.add_sell_order(book_order);
                    }
                }
                counters.spot_added += 1;
            }

            ScanResult::Perp(parsed, p2sh_idx, p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);
                if perp_book.contains(&outpoint_key) {
                    continue; // dedup
                }

                // Convert ParsedPerpOrder -> PerpOrder
                let side = match parsed.side {
                    PerpDeploySide::Long => crate::matcher::perp_book::PerpSide::Long,
                    PerpDeploySide::Short => crate::matcher::perp_book::PerpSide::Short,
                };
                let rs_hex = hex::encode(&parsed.redeem_script);
                let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);
                let p2sh_hex = hex::encode(&p2sh_spk.script());
                // Extract owner_spk from TX outputs (same pattern as lending)
                let owner_spk = crate::matcher::scanner::extract_owner_spk(tx, &parsed.owner_spk_hash);

                let perp_order = crate::matcher::perp_book::PerpOrder {
                    tx_id: tx.tx_id.clone(),
                    index: p2sh_idx,
                    side,
                    margin: p2sh_value,
                    leverage_num: 1,       // Default 1x; not encoded in deploy v1
                    leverage_den: 1,
                    price_num: parsed.price_num,
                    price_den: parsed.price_den,
                    owner_spk_hash: parsed.owner_spk_hash,
                    owner_spk,
                    redeem_script_hex: rs_hex,
                    p2sh_script_hex: p2sh_hex,
                    value: p2sh_value,
                    maint_pct_num: parsed.maint_pct_num,
                    maint_pct_den: parsed.maint_pct_den,
                    keeper_fee: parsed.keeper_fee,
                    discovered_daa: current_daa,
                    reduce_only: false,
                };

                let side_str = match perp_order.side {
                    crate::matcher::perp_book::PerpSide::Long => "LONG",
                    crate::matcher::perp_book::PerpSide::Short => "SHORT",
                };
                info!(
                    "[SCANNER-ALL] Discovered {} perp order: {}:{} margin={} price={}/{}",
                    side_str,
                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    p2sh_value, parsed.price_num, parsed.price_den,
                );

                perp_book.insert(perp_order);
                counters.perp_added += 1;
            }

            ScanResult::Lending(parsed, p2sh_idx, p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);

                // Build P2SH script from redeemScript
                let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);

                match parsed.order_type {
                    LendingOrderType::Offer => {
                        let offer = crate::matcher::lending_book::LendingOffer {
                            outpoint: outpoint_key.clone(),
                            value: p2sh_value,
                            rate_num: parsed.rate_num,
                            rate_den: parsed.rate_den,
                            min_collateral_pct: parsed.min_collateral_ratio,
                            max_duration_daa: parsed.duration_daa,
                            collateral_cov_id: parsed.collateral_cov_id,
                            rate_mode: parsed.rate_mode,
                            rate_floor: parsed.rate_floor_num,
                            owner_spk_hash: parsed.owner_spk_hash,
                            redeem_script: parsed.redeem_script.clone(),
                            p2sh_script: p2sh_spk.script().to_vec(),
                            owner_spk: parsed.owner_spk.clone(),
                            discovered_daa: current_daa,
                        };
                        info!(
                            "[SCANNER-ALL] Discovered lending OFFER: {} value={} rate={}/{}",
                            &outpoint_key[..outpoint_key.len().min(20)],
                            p2sh_value, parsed.rate_num, parsed.rate_den,
                        );
                        lending_book.add_offer(offer);
                    }
                    LendingOrderType::Request => {
                        let request = crate::matcher::lending_book::BorrowRequest {
                            outpoint: outpoint_key.clone(),
                            value: p2sh_value,
                            desired_principal: parsed.amount,
                            max_rate_num: parsed.rate_num,
                            max_rate_den: parsed.rate_den,
                            duration_daa: parsed.duration_daa,
                            rate_mode: parsed.rate_mode,
                            rate_cap: parsed.rate_cap_num,
                            collateral_cov_id: parsed.collateral_cov_id,
                            owner_spk_hash: parsed.owner_spk_hash,
                            redeem_script: parsed.redeem_script.clone(),
                            p2sh_script: p2sh_spk.script().to_vec(),
                            owner_spk: parsed.owner_spk.clone(),
                            discovered_daa: current_daa,
                        };
                        info!(
                            "[SCANNER-ALL] Discovered lending REQUEST: {} collateral={} desired={} max_rate={}/{}",
                            &outpoint_key[..outpoint_key.len().min(20)],
                            p2sh_value, parsed.amount, parsed.rate_num, parsed.rate_den,
                        );
                        lending_book.add_request(request);
                    }
                }
                counters.lending_added += 1;
            }

            ScanResult::Prediction(parsed, p2sh_idx, _p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);
                if prediction_book.contains_outpoint(&outpoint_key) {
                    continue; // dedup
                }

                let item_type_str = match parsed.item_type {
                    PredictionItemType::SplitMerge => "SplitMerge",
                    PredictionItemType::BallotBox => "BallotBox",
                    PredictionItemType::Redemption => "Redemption",
                };
                info!(
                    "[SCANNER-ALL] Discovered prediction {}: {}",
                    item_type_str,
                    &outpoint_key[..outpoint_key.len().min(20)],
                );
                // Prediction items require market-level context to properly route
                // (market_id, ballot side, etc.). Log for now; full routing requires
                // parsing the RS state fields which is done at the application layer.
                // The prediction_executor or API should call the specific
                // PredictionBook methods (add_market, update_ballot_box, etc.)
                // with the full parsed state.
                counters.prediction_added += 1;
            }
            ScanResult::OcoSell(parsed, p2sh_idx, p2sh_value) => {
                if parsed.cpend != 0 {
                    info!(
                        "[SCANNER-ALL] Skipping OCO sell (cancel_pending=1): {}:{}",
                        &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    );
                    continue;
                }

                let (mut tp_order, mut sl_order) = BlockScanner::oco_sell_to_book_orders(
                    &parsed, &tx.tx_id, p2sh_idx, p2sh_value, Some(tx),
                );
                // FIFO: stamp OCO orders with discovery DAA.
                tp_order.discovered_daa = current_daa;
                sl_order.discovered_daa = current_daa;

                let tp_key = tp_order.outpoint_key();
                let sl_key = sl_order.outpoint_key();

                if order_book.contains_outpoint(&tp_key) {
                    continue; // dedup (both keys share the same UTXO, checking one suffices)
                }

                if tp_order.token_cov_id == "0".repeat(64) {
                    warn!(
                        "[SCANNER-ALL] Skipping OCO sell with unknown token_cov_id: {}:{}",
                        &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    );
                    continue;
                }

                // Indexer filter: TP and SL share the same counterparty_spk
                // (extracted once from the deploy TX); checking tp_order is
                // sufficient to cover both virtual orders.
                if skip_if_no_counterparty_spk(&tp_order) {
                    continue;
                }

                info!(
                    "[SCANNER-ALL] Discovered OCO sell: {}:{} value={} TP={}/{} SL={}/{}",
                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    p2sh_value, parsed.price_num_tp, parsed.price_den_tp,
                    parsed.price_num_sl, parsed.price_den_sl,
                );

                if let Some(ws) = ws_tx {
                    crate::matcher::api::emit_order_detected(
                        ws, &tp_order.owner_hash, &tp_key,
                        OrderSide::Sell, tp_order.price_num, tp_order.price_den,
                        tp_order.value, &tp_order.token_cov_id,
                    );
                    crate::matcher::api::emit_order_detected(
                        ws, &sl_order.owner_hash, &sl_key,
                        OrderSide::Sell, sl_order.price_num, sl_order.price_den,
                        sl_order.value, &sl_order.token_cov_id,
                    );
                }

                // Reorg tracking: snapshot OCO orders before they're moved
                if let Some(ref mut rc) = reorg_collector {
                    rc.orders_added.push(tp_order.clone());
                    rc.orders_added.push(sl_order.clone());
                }

                order_book.add_sell_order(tp_order);
                order_book.add_sell_order(sl_order);
                counters.spot_added += 2;
            }
            ScanResult::Dca(parsed, p2sh_idx, p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);
                if let Some(ref mut db) = dca_book {
                    if db.contains(&outpoint_key) {
                        continue; // dedup
                    }
                    let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);
                    // Extract buyer SPK from the deploy TX outputs.
                    // The DCA contract stores buyer_spk_hash = blake2b(buyer_spk).
                    // We scan TX outputs for a non-P2SH output whose SPK hash matches.
                    let buyer_spk = crate::matcher::scanner::extract_owner_spk(tx, &parsed.buyer_spk_hash);
                    if buyer_spk.is_none() {
                        debug!(
                            "[DCA] buyer_spk not found in deploy TX for {}:{} — fill will be deferred",
                            &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                        );
                    }
                    let entry = crate::matcher::dca_book::DcaEntry {
                        tx_id: tx.tx_id.clone(),
                        index: p2sh_idx,
                        value: p2sh_value,
                        target_cov_id: hex::encode(parsed.target_cov_id),
                        price_num: parsed.price_num,
                        price_den: parsed.price_den,
                        amount_per_period: parsed.amount_per_period,
                        interval_daa: parsed.interval_daa,
                        next_execution_daa: parsed.next_execution_daa,
                        periods_remaining: parsed.periods_remaining,
                        owner_hash: hex::encode(parsed.owner_hash),
                        redeem_script_hex: hex::encode(&parsed.redeem_script),
                        p2sh_script_hex: hex::encode(&p2sh_spk.script()),
                        p2sh_version: p2sh_spk.version,
                        discovered_daa: current_daa,
                        buyer_spk,
                    };
                    info!(
                        "[SCANNER-ALL] Discovered DCA order: {} periods={} next_exec={} amt/period={}",
                        &outpoint_key[..outpoint_key.len().min(20)],
                        parsed.periods_remaining,
                        parsed.next_execution_daa,
                        parsed.amount_per_period,
                    );
                    db.add(entry);
                    counters.dca_added += 1;
                }
            }
            ScanResult::Swap(parsed, p2sh_idx, p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);
                if let Some(ref mut sb) = swap_book {
                    if sb.contains(&outpoint_key) {
                        continue; // dedup
                    }
                    let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);
                    // Extract owner SPK from the deploy TX outputs.
                    let owner_spk = crate::matcher::scanner::extract_owner_spk(tx, &parsed.owner_spk_hash);
                    if owner_spk.is_none() {
                        debug!(
                            "[SWAP] owner_spk not found in deploy TX for {}:{} — fill will be deferred",
                            &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                        );
                    }
                    let entry = crate::matcher::swap_book::SwapEntry {
                        tx_id: tx.tx_id.clone(),
                        index: p2sh_idx,
                        value: p2sh_value,
                        source_cov_id: hex::encode(parsed.source_token_cov_id),
                        target_cov_id: hex::encode(parsed.target_token_cov_id),
                        min_target_amount: parsed.min_target_amount,
                        owner_hash: hex::encode(parsed.owner_hash),
                        owner_spk_hash: hex::encode(parsed.owner_spk_hash),
                        receipt_cov_id: hex::encode(parsed.receipt_cov_id),
                        redeem_script_hex: hex::encode(&parsed.redeem_script),
                        p2sh_script_hex: hex::encode(&p2sh_spk.script()),
                        p2sh_version: p2sh_spk.version,
                        discovered_daa: current_daa,
                        owner_spk,
                    };
                    info!(
                        "[SCANNER-ALL] Discovered swap order: {} source={} target={} min_ta={}",
                        &outpoint_key[..outpoint_key.len().min(20)],
                        &entry.source_cov_id[..entry.source_cov_id.len().min(12)],
                        &entry.target_cov_id[..entry.target_cov_id.len().min(12)],
                        parsed.min_target_amount,
                    );
                    sb.add(entry);
                    counters.swap_added += 1;
                }
            }
        }
    }

    counters
}

/// Scan recent L1 blocks for new orders across all product types.
///
/// Polls the virtual selected parent chain for blocks added since
/// `last_chain_hash`, parses transactions, and routes detected orders
/// to the appropriate books via `process_block_txs_all`.
///
/// Returns the new chain tip hash to use as `last_chain_hash` on the next call.
async fn scan_new_blocks(
    rpc: &RpcClient,
    order_book: &mut OrderBook,
    perp_book: &mut crate::matcher::perp_book::PerpOrderBook,
    lending_book: &mut crate::matcher::lending_book::LendingBook,
    prediction_book: &mut crate::matcher::prediction_book::PredictionBook,
    last_chain_hash: &str,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    current_daa: u64,
) -> (String, ScanCounters) {
    let scanner = BlockScanner::new();
    let mut total_counters = ScanCounters::default();

    // Get virtual chain updates since last_chain_hash
    let chain_resp = match rpc.get_virtual_chain_from_block(last_chain_hash, true).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("[SCAN-BLOCKS] Failed to get virtual chain: {}", e);
            return (last_chain_hash.to_string(), total_counters);
        }
    };

    // Extract added block hashes
    let added_hashes: Vec<String> = chain_resp
        .get("addedChainBlockHashes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if added_hashes.is_empty() {
        return (last_chain_hash.to_string(), total_counters);
    }

    let new_tip = added_hashes.last().cloned().unwrap_or_else(|| last_chain_hash.to_string());

    info!(
        "[SCAN-BLOCKS] {} new chain block(s) since last scan",
        added_hashes.len(),
    );

    // H4: no cap. H1 persists the cursor so restart-side catchup may be large;
    // dropping older blocks would permanently miss orders.
    if added_hashes.len() > 2000 {
        warn!("[SCAN-BLOCKS] large catchup: {} blocks — this may take a while", added_hashes.len());
    }
    let blocks_to_scan = &added_hashes[..];

    // Track already-scanned block hashes to avoid duplicates (a merge set
    // block may appear in multiple chain blocks' merge sets).
    let mut scanned_blocks: HashSet<String> = HashSet::new();

    for block_hash in blocks_to_scan {
        let block_resp = match rpc.get_block(block_hash).await {
            Ok(b) => b,
            Err(e) => {
                warn!("[SCAN-BLOCKS] Failed to get block {}: {}", &block_hash[..block_hash.len().min(16)], e);
                continue;
            }
        };

        // Collect all block hashes to scan: the chain block itself + its merge set.
        // TXs from parallel DAG blocks get accepted by a chain block but are only
        // present in the merge set blocks, not in the chain block's transactions[].
        let mut hashes_to_scan: Vec<String> = vec![block_hash.clone()];
        let block_data = block_resp.get("block").unwrap_or(&block_resp);
        if let Some(vd) = block_data.get("verboseData") {
            for key in &["mergeSetBluesHashes", "mergeSetRedsHashes"] {
                if let Some(arr) = vd.get(*key).and_then(|v| v.as_array()) {
                    for h in arr {
                        if let Some(s) = h.as_str() {
                            // Skip the chain block itself (already in the list)
                            if s != block_hash {
                                hashes_to_scan.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }

        for scan_hash in &hashes_to_scan {
            if !scanned_blocks.insert(scan_hash.clone()) {
                continue; // already scanned
            }

            // For the chain block we already have the response; for merge set
            // blocks we need a separate getBlock call.
            let resp = if scan_hash == block_hash {
                block_resp.clone()
            } else {
                match rpc.get_block(scan_hash).await {
                    Ok(b) => b,
                    Err(e) => {
                        debug!("[SCAN-BLOCKS] Failed to get merge-set block {}: {}", &scan_hash[..scan_hash.len().min(16)], e);
                        continue;
                    }
                }
            };

            let bd = resp.get("block").unwrap_or(&resp);
            let txs: Vec<TransactionData> = bd
                .get("transactions")
                .and_then(|t| t.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(TransactionData::from_rpc_json)
                        .collect()
                })
                .unwrap_or_default();

            if txs.is_empty() {
                continue;
            }

            let counters = process_block_txs_all(
                &txs,
                order_book,
                &scanner,
                perp_book,
                lending_book,
                prediction_book,
                None, // No covenant cache in catchup path
                ws_tx,
                current_daa,
                None, // No IFD book in scan_new_blocks (unused path)
                None, // No DCA book in scan_new_blocks
                None, // No swap book in scan_new_blocks
                None, // No reorg collector in catchup path
            );

            total_counters.spot_added += counters.spot_added;
            total_counters.spot_removed += counters.spot_removed;
            total_counters.perp_added += counters.perp_added;
            total_counters.perp_removed += counters.perp_removed;
            total_counters.lending_added += counters.lending_added;
            total_counters.lending_removed += counters.lending_removed;
            total_counters.prediction_added += counters.prediction_added;
            total_counters.prediction_removed += counters.prediction_removed;
            total_counters.dca_added += counters.dca_added;
            total_counters.dca_removed += counters.dca_removed;
            total_counters.swap_added += counters.swap_added;
            total_counters.swap_removed += counters.swap_removed;
        }
    }

    let any_found = total_counters.spot_added > 0
        || total_counters.perp_added > 0
        || total_counters.lending_added > 0
        || total_counters.prediction_added > 0
        || total_counters.swap_added > 0;
    let any_removed = total_counters.spot_removed > 0
        || total_counters.perp_removed > 0
        || total_counters.lending_removed > 0
        || total_counters.prediction_removed > 0;

    if any_found || any_removed {
        info!(
            "[SCAN-BLOCKS] Scan results: spot(+{}/~{}), perp(+{}/~{}), lending(+{}/~{}), prediction(+{}/~{})",
            total_counters.spot_added, total_counters.spot_removed,
            total_counters.perp_added, total_counters.perp_removed,
            total_counters.lending_added, total_counters.lending_removed,
            total_counters.prediction_added, total_counters.prediction_removed,
        );
    }

    (new_tip, total_counters)
}

/// Parse block notification JSON into TransactionData list.
///
/// Handles the Kaspa wRPC `blockAddedNotification` format:
/// ```json
/// {
///   "BlockAdded": {
///     "block": {
///       "transactions": [{ ... }, ...]
///     }
///   }
/// }
/// ```
/// Also supports the simpler `{"block": {"transactions": [...]}}` form.
pub fn parse_block_notification(notification: &serde_json::Value) -> Vec<TransactionData> {
    // Try Kaspa wRPC format: params.BlockAdded.block.transactions
    let txs = notification
        .get("BlockAdded")
        .and_then(|ba| ba.get("block"))
        .and_then(|b| b.get("transactions"))
        .and_then(|t| t.as_array())
        // Fallback: params.block.transactions
        .or_else(|| {
            notification
                .get("block")
                .and_then(|b| b.get("transactions"))
                .and_then(|t| t.as_array())
        });

    match txs {
        Some(arr) => arr
            .iter()
            .filter_map(TransactionData::from_rpc_json)
            .collect(),
        None => Vec::new(),
    }
}

/// Record a trade to SharedState (trade_log + candle aggregator) and broadcast
/// WsEvent::Trade and WsEvent::Kline via the WebSocket broadcaster.
///
/// Called after every successful match TX submission to keep the REST API
/// `/trades` and `/klines` endpoints populated with live data.
async fn record_trade(
    shared_state: Option<&AppState>,
    txid: &str,
    token_cov_id: &str,
    price_num: u64,
    price_den: u64,
    quantity: u64,
    side: Side,
    routing: Option<crate::matcher::trades::RoutingInfo>,
) {
    let shared_state = match shared_state {
        Some(s) => s,
        None => return,
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pair_id = format!("{}/KAS", &token_cov_id[..token_cov_id.len().min(16)]);

    let trade = Trade {
        txid: txid.to_string(),
        pair_id: pair_id.clone(),
        price_num,
        price_den,
        quantity,
        side,
        daa_score: now_unix, // best-effort; exact DAA score not available in executor
        timestamp: now_unix,
        routing,
    };

    let mut state = shared_state.write().await;

    // Push to trade log (ring buffer + optional JSONL file)
    state.trade_log.push(trade.clone());

    // Update candle aggregator for all intervals
    state.candles.on_trade(&trade);

    // Persist M1 candle to SQLite (MT5 style: only M1 stored, higher TFs aggregated on read)
    if let Some(ref history) = state.history {
        if let Some(candle) = state.candles.latest_candle(&trade.pair_id, crate::matcher::candle::Interval::M1) {
            if let Err(e) = history.upsert_m1(&trade.pair_id, candle) {
                tracing::warn!("History DB M1 upsert failed: {}", e);
            }
        }
    }

    // Broadcast WsEvent::Trade
    let price_str = format!("{}/{}", price_num, price_den);
    let _ = state.ws_broadcaster.send(WsEvent::Trade {
        pair: pair_id.clone(),
        txid: txid.to_string(),
        price: price_str,
        qty: quantity.to_string(),
        side,
        daa_score: now_unix,
    });

    // Broadcast WsEvent::Kline for all intervals (latest candle state)
    for &interval in Interval::all() {
        let candles = state.candles.get_candles(&pair_id, interval, 1);
        if let Some(c) = candles.last() {
            let _ = state.ws_broadcaster.send(WsEvent::Kline {
                pair: pair_id.clone(),
                interval: interval.as_str().to_string(),
                o: format!("{}/{}", c.open.0, c.open.1),
                h: format!("{}/{}", c.high.0, c.high.1),
                l: format!("{}/{}", c.low.0, c.low.1),
                c: format!("{}/{}", c.close.0, c.close.1),
                v: c.volume.to_string(),
            });
        }
    }
}

// Expire TX builder for v14 GTD orders

/// Build and submit expire TXs for expired v14 orders.
///
/// v14 orders with `expiry_daa > 0` can be permissionlessly reclaimed after
/// the DAA score exceeds the expiry. The expire TX:
///   - Input: the expired order UTXO (P2SH, sigscript = expire sigscript)
///   - Output: owner's address (from bspkh/sspkh in the RS), value = input - fee
///   - lockTime = expiry_daa (required for CLTV to pass)
///
/// Anyone can submit this TX; no owner signature is needed.
async fn expire_orders(
    rpc: &RpcClient,
    expired_orders: &[crate::matcher::order_book::BookOrder],
    current_daa: u64,
    _wallet_prefix: &str,
) -> u32 {
    use crate::matcher::order_book::OrderSide;

    let mut expired_count = 0u32;

    for order in expired_orders {
        let expiry_daa = match order.expiry_daa {
            Some(e) if e > 0 && e <= current_daa => e,
            _ => continue,
        };

        let rs = order.redeem_script();
        if rs.is_empty() {
            warn!(
                "[EXPIRE] Empty RS for order {}, skipping",
                &order.outpoint_key()[..order.outpoint_key().len().min(20)],
            );
            continue;
        }

        // Build expire sigscript based on order side
        let expire_ss = match order.side {
            OrderSide::Buy => kob_core::contract::build_buy_expire_sigscript(&rs),
            OrderSide::Sell => kob_core::contract::build_sell_expire_sigscript(&rs),
        };

        // Owner's SPK hash is in spk_hash. We need the actual SPK bytes
        // to build the output. Try counterparty_spk (which for buy orders
        // is the buyer's SPK, for sell orders the seller's SPK).
        let owner_spk_hex = match &order.counterparty_spk {
            Some(spk) if !spk.is_empty() => spk.clone(),
            _ => {
                // If counterparty_spk is not available, we can't build the
                // expire output. The owner must self-expire via the CLI.
                warn!(
                    "[EXPIRE] No counterparty SPK for expired order {}, skipping (owner must self-expire)",
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                );
                continue;
            }
        };
        let _owner_spk = match hex::decode(&owner_spk_hex) {
            Ok(spk) => spk,
            Err(_) => continue,
        };

        // Deduct network fee from the order value (1 input, 1 output expire TX)
        let expire_miner_fee = kob_core::mass::estimate_compute_mass(1, 1, 0);
        let output_value = order.value.saturating_sub(expire_miner_fee);
        if output_value < MIN_UTXO_VALUE {
            warn!(
                "[EXPIRE] Expired order {} value too low ({} < min {}), skipping",
                &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                output_value,
                MIN_UTXO_VALUE,
            );
            continue;
        }

        // Build TX
        let input = deploy::build_rpc_input(
            &order.tx_id,
            order.index,
            &hex::encode(&expire_ss),
            0, // sigOpCount = 0 for covenant inputs
        );
        let output = deploy::build_rpc_output(
            output_value,
            0, // P2PK version
            &owner_spk_hex,
        );

        // lockTime must be >= expiry_daa for CLTV to pass.
        // Consensus enforces lockTime <= current_daa, so we use expiry_daa.
        let payload = deploy::build_submit_payload_with_lock_time(
            0,
            vec![input],
            vec![output],
            expiry_daa,
        );

        match rpc.submit_transaction(payload).await {
            Ok(result) if result.ok => {
                let tx_id = result.tx_id.unwrap_or_default();
                info!(
                    "[EXPIRE] Reclaimed expired {} order {} -> TX {}",
                    if order.side == OrderSide::Buy { "BUY" } else { "SELL" },
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                    &tx_id[..tx_id.len().min(20)],
                );
                expired_count += 1;
            }
            Ok(result) => {
                warn!(
                    "[EXPIRE] Failed to expire order {}: {:?}",
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                    result.error,
                );
            }
            Err(e) => {
                warn!(
                    "[EXPIRE] RPC error expiring order {}: {}",
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                    e,
                );
            }
        }
    }

    expired_count
}

/// Get the current virtual DAA score from the node.
async fn get_current_daa(rpc: &RpcClient) -> Option<u64> {
    match rpc.call("getBlockDagInfo", serde_json::json!({})).await {
        Ok(info) => {
            info.get("virtualDaaScore")
                .and_then(|v| v.as_u64())
        }
        Err(e) => {
            warn!("[EXPIRE] Failed to get DAA score: {}", e);
            None
        }
    }
}

/// Run one matching scan cycle.
///
/// Executes two phases:
///   1. Same-pair matches (existing logic): find crossing buy+sell within each token pair.
///   2. Cross-pair routes (v8): find Token A -> KAS -> Token B atomic routes.
///
/// Same-pair matches are prioritized. Cross-pair routes are executed only for
/// orders not already consumed by same-pair matches.
async fn run_scan_cycle(
    rpc: &RpcClient,
    order_book: &mut OrderBook,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
    _enable_cross_pair: bool,
    allow_self_trade: bool,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    shared_state: Option<&AppState>,
    ifd_book: &Arc<Mutex<crate::matcher::ifd::IfdBook>>,
    perp_book: &Arc<Mutex<crate::matcher::perp_book::PerpOrderBook>>,
    perp_tracker: &Arc<Mutex<crate::matcher::perp_tracker::PositionTracker>>,
    lending_book: &Arc<Mutex<crate::matcher::lending_book::LendingBook>>,
    loan_tracker: &Arc<Mutex<crate::matcher::lending_tracker::LoanTracker>>,
    prediction_book: &Arc<Mutex<crate::matcher::prediction_book::PredictionBook>>,
    market_tracker: &Arc<Mutex<crate::matcher::prediction_tracker::MarketTracker>>,
    dca_book: &Arc<Mutex<crate::matcher::dca_book::DcaBook>>,
    swap_book: &Arc<Mutex<crate::matcher::swap_book::SwapBook>>,
) -> Vec<MatchResult> {
    let mut results = Vec::new();

    // H-5: Expire cooldown entries from previous failed submissions
    spent_tracker.expire_failed();

    // Fetch current DAA score for CSV maturity checks.
    // Orders younger than CSV_MATURITY_DAA (50 DAA) are silently skipped
    // by match_book_direct — they stay in the book and become eligible
    // once enough DAA scores pass (typically ~5 seconds on mainnet).
    let current_daa = rpc.get_daa_score().await.unwrap_or(0);

    // F1: Phase 3 now runs BEFORE Phase 1.
    //
    // Background — the "Phase 3 starvation race" (see
    // phase3_race_investigation.md). When Phase 1 ran first, any
    // SellSweep / BuySweep whose planner failed would call
    // `spent_tracker.mark_failed(...)` on every participating order —
    // including orders that were the only viable `buy_source` or
    // `sell_target` candidate for an active cross-book swap route.
    // Because Phase 3 then read `swap_spent_keys` from the SAME live
    // `spent_tracker`, those just-poisoned outpoints were filtered out
    // → `match_swap_routes` returned empty → the `[SCAN] Found N
    // cross-book swap route(s)` log (guarded by `!is_empty()`) stayed
    // silent → P23 cross-pair swap could starve for as long as the
    // Phase 1 planner kept retrying the failing group each cooldown
    // cycle (~30 s). F3-partial + F5 already minimise the blast radius
    // of Phase 1 mark_failed, but F1 removes the ordering dependency
    // entirely: Phase 3 picks counterparties first, Phase 1 sees its
    // successes (via `mark_spent`) and plans around them.
    //
    // Option A chosen: Phase 3 runs FIRST using a snapshot of the
    // spent-tracker state at cycle entry. Phase 1 then runs with the
    // live tracker, observing any `mark_spent` that Phase 3's
    // successful swap routes emitted. The "snapshot" here is just the
    // plain `spent_keys() + failed-under-cooldown` collection
    // performed BEFORE Phase 1 mutates anything — since Phase 3 runs
    // first, nothing in the same cycle has had a chance to poison it.
    // No new SpentTracker type / snapshot() method required.
    {
        let swab = swap_book.lock().await;
        if !swab.is_empty() {
            // Snapshot currently spent / cooldown outpoints for exclusion.
            // Include failed outpoints under cooldown so we don't hammer
            // the node with transient-failure retries (e.g. CSV not yet
            // mature — the swap covenant has a 50-DAA OP_CSV gate, and
            // the plain buy/sell legs do too).
            let mut swap_spent_keys = spent_tracker.spent_keys();
            for (key, when) in &spent_tracker.failed {
                if when.elapsed().as_secs() < spent_tracker.cooldown_secs {
                    swap_spent_keys.insert(key.clone());
                }
            }
            let swap_groups = matching::match_swap_routes(
                order_book, &swab, Some(&swap_spent_keys), &std::collections::HashSet::new(),
            );
            drop(swab);

            if !swap_groups.is_empty() {
                info!(
                    "[SCAN] Found {} cross-book swap route(s)",
                    swap_groups.len(),
                );
            }

            for sg in &swap_groups {
                info!(
                    "[SWAP-ROUTE] swap={} buy_source={} sell_target={} kas_flow={} surplus={}",
                    &sg.swap.outpoint_key()[..sg.swap.outpoint_key().len().min(20)],
                    &sg.buy_source.outpoint_key()[..sg.buy_source.outpoint_key().len().min(20)],
                    &sg.sell_target.outpoint_key()[..sg.sell_target.outpoint_key().len().min(20)],
                    sg.kas_flow,
                    sg.surplus,
                );

                // Convert counterparty orders to BatchOrders
                let buy_source_batch = match book_order_to_batch_order(&sg.buy_source, "SWAP-BUY") {
                    Some(o) => o,
                    None => {
                        spent_tracker.mark_failed(&sg.buy_source.outpoint_key());
                        continue;
                    }
                };
                let sell_target_batch = match book_order_to_batch_order(&sg.sell_target, "SWAP-SELL") {
                    Some(o) => o,
                    None => {
                        spent_tracker.mark_failed(&sg.sell_target.outpoint_key());
                        continue;
                    }
                };

                // Acquire wallet UTXOs
                let utxos = match rpc
                    .get_spendable_utxos(&config.address, Some(0))
                    .await
                {
                    Ok(u) if !u.is_empty() => u,
                    Ok(_) => {
                        warn!("[SWAP-ROUTE] No wallet UTXOs available, skipping");
                        continue;
                    }
                    Err(e) => {
                        warn!("[SWAP-ROUTE] Failed to get wallet UTXOs: {}, skipping", e);
                        continue;
                    }
                };
                let (wallet_spk_version, wallet_spk_script) = utxos[0].parse_spk();
                let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
                let token_p2sh_hex = hex::encode(&token_p2sh.script());
                let wallet_utxo = utxos.iter()
                    .filter(|u| {
                        let (_, script) = u.parse_spk();
                        hex::encode(&script) != token_p2sh_hex
                            && !spent_tracker.is_spent(&u.outpoint_key())
                    })
                    .max_by_key(|u| u.utxo_entry.amount)
                    .map(|u| (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount));

                // Build and submit the swap atomic TX directly (not via plan_batch_match,
                // which can't handle cross-pair token routing).
                // execute_swap_fill marks participating outpoints as transient
                // (CSV not mature) or failed (permanent) on its own when it
                // returns None. The caller only marks on the success path.
                match execute_swap_fill(
                    rpc, sg, &sell_target_batch, &buy_source_batch,
                    wallet_utxo.clone(), &wallet_spk_script, wallet_spk_version, config,
                    spent_tracker,
                ).await {
                    Some(batch_result) => {
                        info!(
                            "[SWAP-ROUTE] SUCCESS: tx={} kas_flow={} surplus={}",
                            &batch_result.tx_id[..batch_result.tx_id.len().min(16)],
                            sg.kas_flow,
                            sg.surplus,
                        );

                        // Mark all 3 orders as spent
                        let swap_key = sg.swap.outpoint_key();
                        let buy_source_key = sg.buy_source.outpoint_key();
                        let sell_target_key = sg.sell_target.outpoint_key();
                        spent_tracker.mark_spent(&swap_key);
                        spent_tracker.mark_spent(&buy_source_key);
                        spent_tracker.mark_spent(&sell_target_key);
                        let mut swap_marked_keys: Vec<String> =
                            vec![swap_key, buy_source_key, sell_target_key];

                        // Emit events for counterparty orders
                        if let Some(ws) = ws_tx {
                            crate::matcher::api::emit_order_filled(
                                ws, &sg.buy_source.owner_hash, &sg.buy_source.outpoint_key(),
                                &batch_result.tx_id,
                                sg.buy_source.price_num, sg.buy_source.price_den,
                                sg.buy_source.value, OrderSide::Buy,
                                &sg.buy_source.token_cov_id,
                            );
                            crate::matcher::api::emit_order_filled(
                                ws, &sg.sell_target.owner_hash, &sg.sell_target.outpoint_key(),
                                &batch_result.tx_id,
                                sg.sell_target.price_num, sg.sell_target.price_den,
                                sg.sell_target.value, OrderSide::Sell,
                                &sg.sell_target.token_cov_id,
                            );
                        }

                        // Record trades for both legs
                        record_trade(
                            shared_state,
                            &batch_result.tx_id,
                            &sg.buy_source.token_cov_id,
                            sg.buy_source.price_num, sg.buy_source.price_den,
                            sg.buy_source.value,
                            Side::Buy,
                            None,
                        ).await;
                        record_trade(
                            shared_state,
                            &batch_result.tx_id,
                            &sg.sell_target.token_cov_id,
                            sg.sell_target.price_num, sg.sell_target.price_den,
                            sg.sell_target.value,
                            Side::Sell,
                            None,
                        ).await;

                        // Mark wallet outpoint as spent
                        if let Some(ref wu) = wallet_utxo {
                            let wk = format!("{}:{}", wu.0, wu.1);
                            spent_tracker.mark_spent(&wk);
                            swap_marked_keys.push(wk);
                        }

                        // Associate all 4 marked outpoints with the submit txid
                        // so the mempool-aware prune preserves them while the
                        // TX dwells in the mempool.
                        if !batch_result.tx_id.is_empty() {
                            spent_tracker.mark_submitted(
                                &batch_result.tx_id,
                                &swap_marked_keys,
                            );
                        }

                        // Push MatchResult for stop/trailing stop triggers
                        results.push(MatchResult {
                            match_tx_id: batch_result.tx_id.clone(),
                            match_type: MatchType::Full,
                            seller_kas: sg.kas_flow,
                            buyer_tokens: sg.sell_target.value,
                            receipt_tx_id: batch_result.tx_id.clone(),
                            receipt_idx: 0,
                            receipt_value: 0,
                            token_cov_id: sg.sell_target.token_cov_id.clone(),
                            price_num: sg.sell_target.price_num,
                            price_den: sg.sell_target.price_den,
                        });
                    }
                    None => {
                        // execute_swap_fill already marked the 3 outpoints
                        // (transient for CSV, failed for permanent) before
                        // returning. Just log here.
                        warn!("[SWAP-ROUTE] Execution returned no result (see [SWAP-FILL] log above)");
                    }
                }
            }
        } else {
            drop(swab);
        }
    }

    // Phase 1: Same-pair matches via direct book traversal.
    // Combine spent + failed outpoints into a single exclusion set so that
    // match_book_direct() skips orders consumed by prior cycles (deferred
    // removal, commit 2a346a5b) and orders under failure cooldown (H-5).
    // NOTE: Since F1, Phase 3 runs first. Outpoints that Phase 3 consumed
    // this cycle are already in `spent` via `mark_spent`, so the snapshot
    // below naturally excludes them from Phase 1 direct traversal.
    let mut spent_keys = spent_tracker.spent_keys();
    // H-5: also exclude outpoints under failure cooldown
    for (key, when) in &spent_tracker.failed {
        if when.elapsed().as_secs() < spent_tracker.cooldown_secs {
            spent_keys.insert(key.clone());
        }
    }

    let opt_groups = matching::match_book_direct(
        order_book, allow_self_trade, Some(&spent_keys), current_daa,
    );

    if opt_groups.is_empty() {
        let stats = order_book.stats();
        info!("[SCAN] No crossing orders found (direct traversal)");
        info!(
            "  Pairs tracked: {}, Bids: {}, Asks: {}",
            stats.pairs, stats.total_bids, stats.total_asks
        );
        for ps in &stats.by_pair {
            info!("    {}...: {} bids, {} asks", ps.token_cov_id, ps.bids, ps.asks);
        }
    } else {
        info!(
            "[SCAN] Executing {} group(s) via direct book traversal (FIFO-ordered)",
            opt_groups.len(),
        );
    }

    // H4 hoist: wallet UTXOs and token P2SH hex are cycle-level constants.
    // Fetching once per cycle and filtering via spent_tracker inside the loop
    // cuts RPC roundtrips from N (per group) to 1 (per cycle). Same wallet
    // address, same SPK; spent_tracker auto-marks consumed UTXOs on submit
    // so the per-iteration filter still picks fresh UTXOs between groups.
    let wallet_ctx: Option<(Vec<RpcUtxo>, u16, Vec<u8>)> = match rpc
        .get_spendable_utxos(&config.address, Some(0))
        .await
    {
        Ok(u) if !u.is_empty() => {
            let (v, s) = u[0].parse_spk();
            Some((u, v, s))
        }
        Ok(_) => {
            warn!("[UNIFIED] No wallet UTXOs available (cycle)");
            None
        }
        Err(e) => {
            warn!("[UNIFIED] Failed to get wallet UTXOs: {} (cycle)", e);
            None
        }
    };
    let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
    let token_p2sh_hex = hex::encode(&token_p2sh.script());

    for group in &opt_groups {
        info!(
            "[UNIFIED] Group kind={:?} sells={} buys={} surplus={}",
            group.kind, group.sells.len(), group.buys.len(), group.total_surplus,
        );

        // STP defense-in-depth: skip if all sells and buys share the same owner
        if !allow_self_trade {
            let self_trade = group.sells.iter().all(|s| {
                group.buys.iter().all(|b| b.owner_hash == s.owner_hash)
            });
            if self_trade {
                warn!("[STP] Blocked self-trade in unified matching");
                continue;
            }
        }

        // Convert BookOrders to BatchOrders.
        //
        // When a single order in the group cannot be converted (e.g., v0
        // payload-v1 BUY with no counterparty_spk, or unsupported RS size),
        // mark ONLY that order as failed and skip the group — don't drag
        // bystanders into 30s cooldown. Marking innocent buys/sells was the
        // root cause of the P02 "one external v0 BUY kills the whole
        // SellSweep" flake (Bug B counterparty_spk variant).
        let mut sells = Vec::new();
        let mut buys = Vec::new();
        let mut skip_group = false;

        for sell in &group.sells {
            match book_order_to_batch_order(sell, "UNIFIED") {
                Some(o) => sells.push(o),
                None => {
                    // Only the offender cools down. Other orders in the
                    // group are still fine and should remain eligible for
                    // other matches (incl. Phase 3 swap routes).
                    spent_tracker.mark_failed(&sell.outpoint_key());
                    skip_group = true;
                    break;
                }
            }
        }
        if skip_group {
            continue;
        }

        for buy in &group.buys {
            match book_order_to_batch_order(buy, "UNIFIED") {
                Some(o) => buys.push(o),
                None => {
                    spent_tracker.mark_failed(&buy.outpoint_key());
                    skip_group = true;
                    break;
                }
            }
        }
        if skip_group {
            continue;
        }

        if sells.is_empty() || buys.is_empty() {
            // Defensive: grouper should never emit an empty side. If it
            // happens, treat as a grouper bug and skip the group without
            // cooling down the individual orders — they may still match
            // in another group.
            warn!("[UNIFIED] Group had empty sells/buys after conversion, skipping without cooldown");
            continue;
        }

        // Pull wallet UTXOs + SPK from the cycle-level cache (hoisted above).
        // `token_p2sh_hex` is also hoisted — it's a compile-time constant built
        // from `kob_core::TOKEN_RS`, so no point recomputing per group.
        let (utxos, wallet_spk_version, wallet_spk_script) = match &wallet_ctx {
            Some((u, v, s)) => (u.as_slice(), *v, s.clone()),
            None => continue,
        };
        let wallet_utxo = utxos.iter()
            .filter(|u| {
                let (_, script) = u.parse_spk();
                hex::encode(&script) != token_p2sh_hex
                    && !spent_tracker.is_spent(&u.outpoint_key())
            })
            .max_by_key(|u| u.utxo_entry.amount)
            .map(|u| (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount));

        // Plan using the appropriate planner based on GroupKind
        let plan_result = match group.kind {
            matching::GroupKind::BuySweep => {
                // 1 buy (in buys[0]) sweeps N sells
                crate::matcher::batch::plan_ioc_match(
                    &sells, &buys[0], wallet_utxo,
                    &wallet_spk_script, wallet_spk_version, Some(config.fee_bps),
                )
            }
            matching::GroupKind::SellSweep => {
                // 1 sell (in sells[0]) sweeps N buys
                crate::matcher::batch::plan_sell_ioc_match(
                    &sells[0], &buys, wallet_utxo,
                    &wallet_spk_script, wallet_spk_version, Some(config.fee_bps),
                )
            }
            matching::GroupKind::PartialBuy => {
                // 1:1 partial buy: buy IOC sweeps 1 sell
                crate::matcher::batch::plan_ioc_match(
                    &sells, &buys[0], wallet_utxo,
                    &wallet_spk_script, wallet_spk_version, Some(config.fee_bps),
                )
            }
            matching::GroupKind::PartialSell => {
                // 1:1 partial sell: sell IOC sweeps 1 buy
                crate::matcher::batch::plan_sell_ioc_match(
                    &sells[0], &buys, wallet_utxo,
                    &wallet_spk_script, wallet_spk_version, Some(config.fee_bps),
                )
            }
            matching::GroupKind::Batch
            | matching::GroupKind::GtcBuyMultiFill
            | matching::GroupKind::GtcSellMultiFill => {
                // GTC multi-fill uses plan_batch_match (Op1 for the anchor)
                // just like a normal N:N batch.  The buy contract's F3 check
                // requires output[toi] >= exp_tok, which is satisfied because
                // the sweep grouper only emits GTC multi-fill when total
                // fill tokens >= expected_tokens.
                crate::matcher::batch::plan_batch_match(
                    &sells, &buys, wallet_utxo,
                    &wallet_spk_script, wallet_spk_version, Some(config.fee_bps),
                )
            }
            matching::GroupKind::CrossSwap => {
                // Cross-swap groups are handled in Phase 3, not here.
                warn!("[UNIFIED] Unexpected CrossSwap group in Phase 1, skipping");
                continue;
            }
        };

        let mut plan = match plan_result {
            Ok(p) => p,
            Err(ref e) if matches!(e, crate::matcher::batch::BatchError::MinFillViolation { .. }) => {
                // MinFillViolation is a pairing issue, not a permanent order fault.
                // The orders may match with a different counterparty, so don't
                // mark them as failed. Just skip this group.
                info!("[UNIFIED] MinFill violation (skipping, will retry): {}", e);
                continue;
            }
            Err(ref e) if matches!(e, crate::matcher::batch::BatchError::OcoRemainderUnsupported { .. }) => {
                // OCO v1 covenant has no IOC path. A sweep/batch that leaves
                // any OCO token remainder is structurally unexecutable — the
                // planner would otherwise emit a TX using selector=5, which
                // OCO's dispatch rejects with "script verification failed".
                //
                // Don't mark any order in the group as failed: the OCO UTXO
                // is fine, and the buys in this group should remain available
                // for other matches (including Phase 3 cross-pair swaps).
                // Marking them failed here was the root cause of the P23
                // Phase 3 starvation race (see phase3_race_investigation.md).
                info!("[UNIFIED] OCO remainder not supported (skipping group, no cooldown): {}", e);
                continue;
            }
            Err(e) => {
                warn!("[UNIFIED] Plan failed: {}, skipping group", e);
                for o in group.all_orders() {
                    spent_tracker.mark_failed(&o.outpoint_key());
                }
                continue;
            }
        };

        // IFD: check source_pairs for payload-based IFD, fall back to IfdBook
        let ifd_b_rs_hex = group.source_pairs.iter().find_map(|pair| {
            pair.buy.ifd_order_b_rs_hex.as_ref()
                .or(pair.sell.ifd_order_b_rs_hex.as_ref())
        });

        let (ifd_ctx, ifd_payload) = if let Some(b_rs_hex) = ifd_b_rs_hex {
            match hex::decode(b_rs_hex) {
                Ok(rs_bytes) => {
                    let b_expiry = kob_core::contract::spot::parse_redeem_script(&rs_bytes)
                        .and_then(|p| p.expiry_daa);
                    let kob_payload = kob_core::contract::build_order_payload_full(
                        &rs_bytes, false, b_expiry,
                    );
                    (None, Some(hex::encode(&kob_payload)))
                }
                Err(e) => {
                    warn!("[UNIFIED-IFD] Failed to decode order B RS: {}", e);
                    (None, None)
                }
            }
        } else {
            // Fallback: check IfdBook for engine-registered rules
            let ctx = {
                let ifd = ifd_book.lock().await;
                group.source_pairs.iter().find_map(|pair| {
                    let buy_outpoint = pair.buy.outpoint_key();
                    let sell_outpoint = pair.sell.outpoint_key();
                    let rule = ifd.find_by_a_outpoint(&buy_outpoint)
                        .or_else(|| ifd.find_by_a_outpoint(&sell_outpoint));
                    rule.and_then(|r| {
                        if r.status == crate::matcher::ifd::IfdStatus::Active {
                            match hex::decode(&r.order_b_rs_hex) {
                                Ok(rs_bytes) => Some(IfdFillContext {
                                    rule_id: r.id,
                                    order_b_rs: rs_bytes,
                                    order_b_p2sh: r.order_b_p2sh.clone(),
                                    expiry_daa: r.order_b.expiry_daa(),
                                }),
                                Err(e) => {
                                    warn!("[UNIFIED-IFD] Failed to decode RS for rule {}: {}", r.id, e);
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    })
                })
            };
            let payload = ctx.as_ref().map(|c| {
                let expiry = if c.expiry_daa > 0 { Some(c.expiry_daa) } else { None };
                let kob_payload = kob_core::contract::build_order_payload_full(
                    &c.order_b_rs, false, expiry,
                );
                hex::encode(&kob_payload)
            });
            (ctx, payload)
        };

        match execute_batch_match(rpc, &mut plan, config, spent_tracker, ifd_payload, (wallet_spk_version, &wallet_spk_script)).await {
            Some(batch_result) => {
                // IFD trigger
                if let Some(ctx) = &ifd_ctx {
                    let mut ifd = ifd_book.lock().await;
                    ifd.trigger(ctx.rule_id, &batch_result.tx_id);
                    drop(ifd);
                }

                info!(
                    "[UNIFIED] SUCCESS: kind={:?} tx={} sells={} buys={} surplus={}",
                    group.kind,
                    &batch_result.tx_id[..batch_result.tx_id.len().min(16)],
                    batch_result.sell_count,
                    batch_result.buy_count,
                    batch_result.matcher_surplus,
                );

                // Mark all sells as spent + emit events + record trades
                let mut unified_marked_keys: Vec<String> = Vec::new();
                for sell in &group.sells {
                    let sk = sell.outpoint_key();
                    if let Some(ws) = ws_tx {
                        crate::matcher::api::emit_order_filled(
                            ws, &sell.owner_hash, &sk,
                            &batch_result.tx_id,
                            sell.price_num, sell.price_den,
                            sell.value, OrderSide::Sell,
                            &sell.token_cov_id,
                        );
                    }
                    record_trade(
                        shared_state,
                        &batch_result.tx_id,
                        &sell.token_cov_id,
                        sell.price_num, sell.price_den,
                        sell.value,
                        Side::Sell,
                        None,
                    ).await;
                    // C5 fix: Use BookOrder clone partner key directly
                    let sell_oco_partner = sell.oco_partner_key.clone();
                    spent_tracker.mark_spent(&sk);
                    unified_marked_keys.push(sk);
                    if let Some(ref partner_key) = sell_oco_partner {
                        spent_tracker.mark_spent(partner_key);
                        unified_marked_keys.push(partner_key.clone());
                        info!("[OCO] Marked partner spent (pending): {}", partner_key);
                    }
                }

                // Mark all buys as spent + emit events + record trades
                for buy in &group.buys {
                    let bk = buy.outpoint_key();
                    if let Some(ws) = ws_tx {
                        crate::matcher::api::emit_order_filled(
                            ws, &buy.owner_hash, &bk,
                            &batch_result.tx_id,
                            buy.price_num, buy.price_den,
                            buy.value, OrderSide::Buy,
                            &buy.token_cov_id,
                        );
                    }
                    record_trade(
                        shared_state,
                        &batch_result.tx_id,
                        &buy.token_cov_id,
                        buy.price_num, buy.price_den,
                        buy.value,
                        Side::Buy,
                        None,
                    ).await;
                    spent_tracker.mark_spent(&bk);
                    unified_marked_keys.push(bk);
                }

                // Mark wallet outpoint as spent
                if let Some(ref wu) = plan.wallet_input {
                    let wk = format!("{}:{}", wu.0, wu.1);
                    spent_tracker.mark_spent(&wk);
                    unified_marked_keys.push(wk);
                }

                // Associate all marked outpoints with the submit txid so
                // prune_spent() can preserve them while the TX dwells in
                // the mempool.
                if !batch_result.tx_id.is_empty() {
                    spent_tracker.mark_submitted(
                        &batch_result.tx_id,
                        &unified_marked_keys,
                    );
                }

                // Push MatchResults for stop/trailing stop triggers
                if !group.source_pairs.is_empty() {
                    for pair in &group.source_pairs {
                        results.push(MatchResult {
                            match_tx_id: batch_result.tx_id.clone(),
                            match_type: pair.match_type.clone(),
                            seller_kas: pair.seller_kas,
                            buyer_tokens: pair.buy.value,
                            receipt_tx_id: batch_result.tx_id.clone(),
                            receipt_idx: 0,
                            receipt_value: 0,
                            token_cov_id: pair.token_cov_id.clone(),
                            price_num: pair.sell.price_num,
                            price_den: pair.sell.price_den,
                        });
                    }
                } else {
                    // Sweep groups: generate MatchResult per fill
                    let fills = if group.kind == matching::GroupKind::BuySweep
                        || group.kind == matching::GroupKind::GtcBuyMultiFill
                    {
                        &group.sells
                    } else {
                        &group.buys
                    };
                    for fill in fills {
                        // H-2: Guard against division by zero on price_den.
                        // A zero denominator indicates a malformed order that
                        // slipped past validation; skip it rather than panic.
                        if fill.price_den == 0 {
                            warn!(
                                "[UNIFIED] Skipping fill with price_den=0: {}...:{} (H-2)",
                                &fill.tx_id[..fill.tx_id.len().min(16)], fill.index,
                            );
                            continue;
                        }
                        let (seller_kas_val, buyer_tokens_val) = if group.kind == matching::GroupKind::BuySweep
                            || group.kind == matching::GroupKind::GtcBuyMultiFill
                        {
                            let kas_128 = fill.value as u128 * fill.price_num as u128
                                / fill.price_den as u128;
                            (kas_128 as u64, fill.value)
                        } else {
                            let tok_128 = fill.value as u128 * fill.price_num as u128
                                / fill.price_den as u128;
                            (fill.value, tok_128 as u64)
                        };
                        results.push(MatchResult {
                            match_tx_id: batch_result.tx_id.clone(),
                            match_type: MatchType::Full,
                            seller_kas: seller_kas_val,
                            buyer_tokens: buyer_tokens_val,
                            receipt_tx_id: batch_result.tx_id.clone(),
                            receipt_idx: 0,
                            receipt_value: 0,
                            token_cov_id: fill.token_cov_id.clone(),
                            price_num: fill.price_num,
                            price_den: fill.price_den,
                        });
                    }
                }
            }
            None => {
                warn!("[UNIFIED] Execution failed for group kind={:?}", group.kind);
                for o in group.all_orders() {
                    spent_tracker.mark_failed(&o.outpoint_key());
                }
            }
        }
    }


    // Phase 4: Perp matching
    {
        // A-3: Extract crossings under lock, then drop lock before async RPC calls.
        // A-1: Filter out crossings whose outpoints are spent or under failure cooldown.
        let crossings = {
            let pb = perp_book.lock().await;
            let raw = pb.find_crossing_pairs();
            raw.into_iter()
                .filter(|c| {
                    let lk = c.long_order.outpoint_key();
                    let sk = c.short_order.outpoint_key();
                    if spent_tracker.is_spent(&lk) || spent_tracker.is_spent(&sk) {
                        info!(
                            "[PERP] Skipping crossing (outpoint already spent): long={}... short={}...",
                            &lk[..lk.len().min(20)],
                            &sk[..sk.len().min(20)],
                        );
                        return false;
                    }
                    if spent_tracker.is_failed(&lk) || spent_tracker.is_failed(&sk) {
                        info!(
                            "[PERP] Skipping crossing (outpoint under cooldown): long={}... short={}...",
                            &lk[..lk.len().min(20)],
                            &sk[..sk.len().min(20)],
                        );
                        return false;
                    }
                    true
                })
                .collect::<Vec<_>>()
        }; // lock dropped here

        if !crossings.is_empty() {
            info!(
                "[PERP] Found {} crossing pair(s)",
                crossings.len(),
            );
            // Fetch wallet UTXOs for matcher change output
            let perp_wallet = fetch_wallet_utxos(rpc, &config.address, "PERP").await;
            // D-4: Guard against empty wallet SPK — skip phase if no wallet UTXOs.
            let perp_wallet_spk = match perp_wallet.as_ref().map(|(_, _, spk, _)| spk.clone()) {
                Some(spk) if !spk.is_empty() => spk,
                _ => {
                    warn!("[PERP] No wallet UTXOs available — skipping perp matching this cycle");
                    Vec::new()
                }
            };
            if perp_wallet_spk.is_empty() {
                // Skip all crossings — cannot construct valid TXs without matcher SPK
            } else {

            // B-3: Fetch current DAA score for position DAA fields.
            // grace_daa, maturity_daa, emergency_daa must be > 0 and ordered
            // (grace < maturity < emergency). Use current_daa as base offset.
            let perp_current_daa = get_current_daa(rpc).await.unwrap_or(0);
            // Default durations: grace=100 DAA (~100s), maturity=100_000 DAA (~1 day),
            // emergency=1_000_000 DAA (~10 days). These are safe defaults;
            // in production the deploy order should specify its own terms.
            let perp_grace_daa = perp_current_daa.saturating_add(100);
            let perp_maturity_daa = perp_current_daa.saturating_add(100_000);
            let perp_emergency_daa = perp_current_daa.saturating_add(1_000_000);

            // Compute matcher SPK hash for canonical settlement spot orders.
            let matcher_spk_hash = kob_core::compute_spk_hash(0, &perp_wallet_spk);

            // Get the token_cov_id from the spot order book (first tracked pair).
            // The perp book is single-instrument; the spot pair provides the underlying.
            let settlement_token_cov_id: Option<[u8; 32]> = order_book
                .pair_books
                .keys()
                .next()
                .and_then(|hex_id| {
                    let bytes = hex::decode(hex_id).ok()?;
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    } else {
                        None
                    }
                });

            if settlement_token_cov_id.is_none() {
                warn!("[PERP] No spot pair in order book — cannot compute settlement SPK hashes; skipping perp crossings");
            }

            for crossing in &crossings {
                info!(
                    "[PERP] Long {}:{} @ {}/{} x Short {}:{} @ {}/{} -> entry {}/{}",
                    &crossing.long_order.tx_id[..crossing.long_order.tx_id.len().min(12)],
                    crossing.long_order.index,
                    crossing.long_order.price_num, crossing.long_order.price_den,
                    &crossing.short_order.tx_id[..crossing.short_order.tx_id.len().min(12)],
                    crossing.short_order.index,
                    crossing.short_order.price_num, crossing.short_order.price_den,
                    crossing.entry_price_num, crossing.entry_price_den,
                );

                // Compute canonical settlement spot SPK hashes for atomic settle
                // paths (2,3,4). Uses deterministic buy/sell RSes with canonical
                // parameters (entry price, matcher as owner, no expiry).
                let (spot_sell_spkh, spot_buy_spkh) = match &settlement_token_cov_id {
                    Some(tcid) => {
                        match kob_core::perp::compute_settlement_spot_spk_hashes(
                            tcid,
                            crossing.entry_price_num,
                            crossing.entry_price_den,
                            &matcher_spk_hash,
                        ) {
                            Some(hashes) => hashes,
                            None => {
                                warn!(
                                    "[PERP] Failed to build settlement RS for entry={}/{}",
                                    crossing.entry_price_num, crossing.entry_price_den,
                                );
                                spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                                spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                                continue;
                            }
                        }
                    }
                    None => {
                        // No spot pair — already warned above; skip all crossings.
                        spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                        spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                        continue;
                    }
                };

                // Build open-position TX blueprint.
                // Size = minimum of both margins (equal-size matching).
                let size = crossing.long_order.margin.min(crossing.short_order.margin);
                let total_margin = crossing.long_order.margin.saturating_add(crossing.short_order.margin);
                let params = crate::matcher::perp_executor::OpenPositionParams::from_crossing_pair(
                    crossing,
                    size,
                    crossing.long_order.margin,        // split_num (long's share)
                    total_margin,                       // split_den
                    crossing.long_order.maint_pct_num,
                    crossing.long_order.maint_pct_den,
                    crossing.long_order.keeper_fee,
                    10_000,     // close_fee (default)
                    perp_grace_daa,       // grace_daa (B-3: must be > 0)
                    perp_maturity_daa,    // maturity_daa (B-3: must be > 0, > grace)
                    perp_emergency_daa,   // emergency_daa (B-3: must be > 0, > maturity)
                    0,          // min_price
                    u64::MAX,   // max_price
                    perp_wallet_spk.clone(), // matcher_script
                    spot_sell_spkh,
                    spot_buy_spkh,
                );

                match crate::matcher::perp_executor::build_open_position_tx(&params) {
                    Ok((mut blueprint, position_rs)) => {
                        info!(
                            "[PERP] Built open-position TX blueprint: {} inputs, {} outputs",
                            blueprint.inputs.len(), blueprint.outputs.len(),
                        );

                        // Build fill sigscripts for Long and Short order inputs.
                        // These are permissionless covenant spends (sigOpCount=0).
                        let long_rs_bytes = match hex::decode(&crossing.long_order.redeem_script_hex) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("[PERP] Failed to decode long RS hex: {}", e);
                                spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                                spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                                continue;
                            }
                        };
                        let short_rs_bytes = match hex::decode(&crossing.short_order.redeem_script_hex) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("[PERP] Failed to decode short RS hex: {}", e);
                                spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                                spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                                continue;
                            }
                        };

                        let long_fill_ss = kob_core::perp::build_perp_deploy_fill_sigscript(&long_rs_bytes);
                        let short_fill_ss = kob_core::perp::build_perp_deploy_fill_sigscript(&short_rs_bytes);

                        // Attach sigscripts to the blueprint inputs
                        blueprint.inputs[0].sig_script = long_fill_ss;
                        blueprint.inputs[1].sig_script = short_fill_ss;

                        // Convert blueprint to RPC JSON (use sequence from blueprint for OP_CSV)
                        let mut rpc_inputs = Vec::new();
                        for (i, inp) in blueprint.inputs.iter().enumerate() {
                            rpc_inputs.push(deploy::build_rpc_input_with_sequence(
                                &inp.prev_tx_id,
                                inp.prev_index,
                                &hex::encode(&inp.sig_script),
                                blueprint.sig_op_counts.get(i).copied().unwrap_or(0),
                                inp.sequence,
                            ));
                        }
                        let mut rpc_outputs = Vec::new();
                        for out in &blueprint.outputs {
                            rpc_outputs.push(deploy::build_rpc_output(
                                out.value,
                                out.script_version,
                                &hex::encode(&out.script),
                            ));
                        }

                        let payload_hex = hex::encode(&blueprint.payload);
                        let payload = if payload_hex.is_empty() {
                            deploy::build_submit_payload_with_lock_time(0, rpc_inputs, rpc_outputs, 50)
                        } else {
                            deploy::build_submit_payload_with_tx_payload(0, rpc_inputs, rpc_outputs, &payload_hex, 50)
                        };

                        let long_key = crossing.long_order.outpoint_key();
                        let short_key = crossing.short_order.outpoint_key();

                        match rpc.submit_transaction(payload).await {
                            Ok(result) if result.ok => {
                                let tx_id = result.tx_id.unwrap_or_else(|| {
                                    warn!("[PERP] Success response missing tx_id");
                                    String::new()
                                });
                                info!("[PERP] SUCCESS! Open-position TXID: {}", tx_id);
                                info!(
                                    "  Long:  {}... margin={}",
                                    &long_key[..long_key.len().min(20)],
                                    crossing.long_order.margin,
                                );
                                info!(
                                    "  Short: {}... margin={}",
                                    &short_key[..short_key.len().min(20)],
                                    crossing.short_order.margin,
                                );
                                info!(
                                    "  Entry: {}/{}, Size: {}",
                                    crossing.entry_price_num, crossing.entry_price_den, size,
                                );

                                // Create PerpPosition and add to tracker
                                let position = crate::matcher::perp_tracker::PerpPosition {
                                    tx_id: tx_id.clone(),
                                    index: 0, // Position is output[0]
                                    long_spk_hash: crossing.long_order.owner_spk_hash,
                                    short_spk_hash: crossing.short_order.owner_spk_hash,
                                    entry_num: crossing.entry_price_num,
                                    entry_den: crossing.entry_price_den,
                                    size,
                                    total_margin: crossing.long_order.margin.saturating_add(crossing.short_order.margin),
                                    split_num: crossing.long_order.margin,
                                    split_den: crossing.long_order.margin.saturating_add(crossing.short_order.margin),
                                    close_fee: 10_000,
                                    maint_pct_num: crossing.long_order.maint_pct_num,
                                    maint_pct_den: crossing.long_order.maint_pct_den,
                                    keeper_fee: crossing.long_order.keeper_fee,
                                    creation_daa: 0, // Set by scanner on next discovery
                                    grace_daa: 0,
                                    maturity_daa: 0,
                                    emergency_daa: 0,
                                    min_price: 0,
                                    max_price: u64::MAX,
                                    redeem_script_hex: hex::encode(&position_rs),
                                    long_spk: crossing.long_order.owner_spk.clone(),
                                    short_spk: crossing.short_order.owner_spk.clone(),
                                };
                                {
                                    let mut pt = perp_tracker.lock().await;
                                    pt.add(position);
                                    info!("[PERP] Position {}:0 added to tracker", &tx_id[..tx_id.len().min(16)]);
                                }

                                // Remove matched orders from perp book
                                {
                                    let mut pb = perp_book.lock().await;
                                    pb.remove(&long_key);
                                    pb.remove(&short_key);
                                }
                                spent_tracker.mark_spent(&long_key);
                                spent_tracker.mark_spent(&short_key);
                                if !tx_id.is_empty() {
                                    spent_tracker.mark_submitted(
                                        &tx_id,
                                        &[long_key.clone(), short_key.clone()],
                                    );
                                }
                            }
                            Ok(result) => {
                                let err_msg = result.error.unwrap_or_else(|| "Unknown error".to_string());
                                warn!("[PERP] TX submission FAILED: {}", err_msg);
                                spent_tracker.mark_failed(&long_key);
                                spent_tracker.mark_failed(&short_key);
                                warn!(
                                    "[PERP] Outpoints {}... and {}... cooldown for {}s",
                                    &long_key[..long_key.len().min(20)],
                                    &short_key[..short_key.len().min(20)],
                                    spent_tracker.cooldown_secs,
                                );
                            }
                            Err(e) => {
                                error!("[PERP] Submit RPC error: {}", e);
                                spent_tracker.mark_failed(&long_key);
                                spent_tracker.mark_failed(&short_key);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[PERP] Failed to build open-position TX: {:?}", e);
                        spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                        spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                    }
                }
            }
            } // end else (perp_wallet_spk non-empty)
        } else {
            let pb = perp_book.lock().await;
            if pb.total_count() > 0 {
                info!("[PERP] No crossing pairs (longs={}, shorts={})", pb.long_count(), pb.short_count());
            }
        }
    }

    // Phase 5: Lending matching
    {
        // A-2: Filter out matches whose outpoints are spent or under failure cooldown.
        let matches = {
            let lb = lending_book.lock().await;
            let raw = lb.find_matches();
            raw.into_iter()
                .filter(|m| {
                    let ok = m.offer.outpoint.as_str();
                    let rk = m.request.outpoint.as_str();
                    if spent_tracker.is_spent(ok) || spent_tracker.is_spent(rk) {
                        info!(
                            "[LENDING] Skipping match (outpoint already spent): offer={}... request={}...",
                            &ok[..ok.len().min(20)],
                            &rk[..rk.len().min(20)],
                        );
                        return false;
                    }
                    if spent_tracker.is_failed(ok) || spent_tracker.is_failed(rk) {
                        info!(
                            "[LENDING] Skipping match (outpoint under cooldown): offer={}... request={}...",
                            &ok[..ok.len().min(20)],
                            &rk[..rk.len().min(20)],
                        );
                        return false;
                    }
                    true
                })
                .collect::<Vec<_>>()
        }; // lock dropped here

        if !matches.is_empty() {
            info!("[LENDING] Found {} lending match(es)", matches.len());

            // Fetch wallet UTXOs for matcher change output
            let lending_wallet = fetch_wallet_utxos(rpc, &config.address, "LENDING").await;
            // D-4: Guard against empty wallet SPK — skip phase if no wallet UTXOs.
            let lending_wallet_spk = match lending_wallet.as_ref().map(|(_, _, spk, _)| spk.clone()) {
                Some(spk) if !spk.is_empty() => spk,
                _ => {
                    warn!("[LENDING] No wallet UTXOs available — skipping lending matching this cycle");
                    Vec::new()
                }
            };
            if lending_wallet_spk.is_empty() {
                // Skip all matches — cannot construct valid TXs without matcher SPK
            } else {

            // B-2: Fetch current DAA score for loan start_daa.
            // A malicious matcher cannot manipulate this because the covenant
            // validates start_daa <= current virtual DAA score at execution time.
            let lending_current_daa = match get_current_daa(rpc).await {
                Some(daa) if daa > 0 => daa,
                _ => {
                    warn!("[LENDING] Failed to get current DAA score — skipping lending this cycle");
                    0
                }
            };
            if lending_current_daa == 0 {
                // Skip: cannot build valid loans without a real DAA score
            } else {

            for lm in &matches {
                info!(
                    "[LENDING] Offer {} rate={}/{} x Request {} max_rate={}/{} -> principal={} duration={}",
                    &lm.offer.outpoint[..lm.offer.outpoint.len().min(16)],
                    lm.agreed_rate_num, lm.agreed_rate_den,
                    &lm.request.outpoint[..lm.request.outpoint.len().min(16)],
                    lm.request.max_rate_num, lm.request.max_rate_den,
                    lm.principal, lm.duration_daa,
                );

                // B-1: The borrower's actual SPK is needed for the principal delivery output.
                // The request's p2sh_script is the covenant address (aa 20 <hash> 87),
                // NOT the borrower's wallet address. Sending principal there would be
                // unspendable. We need the actual owner SPK, which must be stored
                // during scanning (similar to PerpOrder.owner_spk).
                //
                // TODO: Add owner_spk field to BorrowRequest (populated from TX payload
                // or UTXO query during scanning). Until then, skip matches where
                // borrower SPK is unavailable. The covenant's match path should also
                // verify output[1] destination against borrower_spk_hash for L1 safety.
                let borrower_spk = if let Some(ref spk_hex) = lm.request.owner_spk {
                    match hex::decode(spk_hex) {
                        // owner_spk is encoded as version_u16LE + script_bytes.
                        // Strip the 2-byte version prefix — the output script_version
                        // is set separately in the TX output construction.
                        Ok(spk) if spk.len() > 2 => spk[2..].to_vec(),
                        Ok(spk) if !spk.is_empty() => spk,
                        _ => {
                            warn!(
                                "[LENDING] B-1: Cannot decode borrower SPK for request {}... — skipping",
                                &lm.request.outpoint[..lm.request.outpoint.len().min(20)],
                            );
                            spent_tracker.mark_failed(&lm.offer.outpoint);
                            spent_tracker.mark_failed(&lm.request.outpoint);
                            continue;
                        }
                    }
                } else {
                    warn!(
                        "[LENDING] B-1: Borrower SPK not available for request {}... — skipping                          (owner_spk field must be populated during scanning)",
                        &lm.request.outpoint[..lm.request.outpoint.len().min(20)],
                    );
                    spent_tracker.mark_failed(&lm.offer.outpoint);
                    spent_tracker.mark_failed(&lm.request.outpoint);
                    continue;
                };

                // Build lending match params
                let lending_params = crate::matcher::lending_executor::LendingMatchParams::from_match(
                    lm,
                    lending_current_daa,                // B-2: real DAA score from RPC
                    lm.offer.rate_mode,                 // rate_mode from offer
                    lm.offer.rate_floor,                // rate_floor_num
                    lm.request.rate_cap,                // rate_cap_num
                    100,                                // grace_daa: 100 DAA (~100s grace period)
                    lm.offer.min_collateral_pct,        // liq_threshold
                    lending_wallet_spk.clone(),          // matcher_script
                    borrower_spk,                        // borrower_spk
                );

                match crate::matcher::lending_executor::build_lending_match_tx(&lending_params) {
                    Ok((blueprint, loan_rs)) => {
                        info!(
                            "[LENDING] Built match TX blueprint: {} inputs, {} outputs",
                            blueprint.inputs.len(), blueprint.outputs.len(),
                        );

                        // Convert blueprint to RPC JSON (use sequence from blueprint for OP_CSV)
                        let mut rpc_inputs = Vec::new();
                        for (i, inp) in blueprint.inputs.iter().enumerate() {
                            rpc_inputs.push(deploy::build_rpc_input_with_sequence(
                                &inp.prev_tx_id,
                                inp.prev_index,
                                &hex::encode(&inp.sig_script),
                                blueprint.sig_op_counts.get(i).copied().unwrap_or(0),
                                inp.sequence,
                            ));
                        }
                        let mut rpc_outputs = Vec::new();
                        for out in &blueprint.outputs {
                            rpc_outputs.push(deploy::build_rpc_output(
                                out.value,
                                out.script_version,
                                &hex::encode(&out.script),
                            ));
                        }

                        let payload_hex = hex::encode(&blueprint.payload);
                        let payload = if payload_hex.is_empty() {
                            deploy::build_submit_payload_with_lock_time(0, rpc_inputs, rpc_outputs, 50)
                        } else {
                            deploy::build_submit_payload_with_tx_payload(0, rpc_inputs, rpc_outputs, &payload_hex, 50)
                        };

                        let offer_key = lm.offer.outpoint.clone();
                        let request_key = lm.request.outpoint.clone();

                        match rpc.submit_transaction(payload).await {
                            Ok(result) if result.ok => {
                                let tx_id = result.tx_id.unwrap_or_else(|| {
                                    warn!("[LENDING] Success response missing tx_id");
                                    String::new()
                                });
                                info!("[LENDING] SUCCESS! Match TXID: {}", tx_id);
                                info!(
                                    "  Offer:     {}... principal={}",
                                    &offer_key[..offer_key.len().min(20)],
                                    lm.principal,
                                );
                                info!(
                                    "  Request:   {}... collateral={}",
                                    &request_key[..request_key.len().min(20)],
                                    lm.request.value,
                                );
                                info!(
                                    "  Rate: {}/{}, Duration: {} DAA",
                                    lm.agreed_rate_num, lm.agreed_rate_den, lm.duration_daa,
                                );

                                // Create LoanPosition and add to tracker
                                let loan = crate::matcher::lending_tracker::LoanPosition {
                                    outpoint: format!("{}:0", tx_id),
                                    principal: lm.principal,
                                    collateral: lm.request.value,
                                    rate_num: lm.agreed_rate_num,
                                    rate_den: lm.agreed_rate_den,
                                    start_daa: lending_current_daa,
                                    expiry_daa: lending_current_daa.saturating_add(lm.duration_daa),
                                    grace_daa: 100, // 100 DAA grace period (consistent with match params)
                                    lender_spk_hash: lm.offer.owner_spk_hash,
                                    borrower_spk_hash: lm.request.owner_spk_hash,
                                    rate_mode: lm.offer.rate_mode,
                                    rate_floor: lm.offer.rate_floor,
                                    rate_cap: lm.request.rate_cap,
                                    collateral_cov_id: lm.offer.collateral_cov_id,
                                    liq_threshold: lm.offer.min_collateral_pct,
                                    redeem_script: loan_rs,
                                };
                                {
                                    let mut lt = loan_tracker.lock().await;
                                    lt.add_loan(loan);
                                    info!("[LENDING] Loan {}:0 added to tracker", &tx_id[..tx_id.len().min(16)]);
                                }

                                // Remove matched orders from the lending book
                                let mut lb_mut = lending_book.lock().await;
                                lb_mut.remove_by_outpoint(&offer_key);
                                lb_mut.remove_by_outpoint(&request_key);
                                drop(lb_mut);

                                spent_tracker.mark_spent(&offer_key);
                                spent_tracker.mark_spent(&request_key);
                                if !tx_id.is_empty() {
                                    spent_tracker.mark_submitted(
                                        &tx_id,
                                        &[offer_key.clone(), request_key.clone()],
                                    );
                                }
                            }
                            Ok(result) => {
                                let err_msg = result.error.unwrap_or_else(|| "Unknown error".to_string());
                                warn!("[LENDING] TX submission FAILED: {}", err_msg);
                                spent_tracker.mark_failed(&lm.offer.outpoint);
                                spent_tracker.mark_failed(&lm.request.outpoint);
                                warn!(
                                    "[LENDING] Outpoints {}... and {}... cooldown for {}s",
                                    &lm.offer.outpoint[..lm.offer.outpoint.len().min(20)],
                                    &lm.request.outpoint[..lm.request.outpoint.len().min(20)],
                                    spent_tracker.cooldown_secs,
                                );
                            }
                            Err(e) => {
                                error!("[LENDING] Submit RPC error: {}", e);
                                spent_tracker.mark_failed(&lm.offer.outpoint);
                                spent_tracker.mark_failed(&lm.request.outpoint);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[LENDING] Failed to build match TX: {:?}", e);
                        spent_tracker.mark_failed(&lm.offer.outpoint);
                        spent_tracker.mark_failed(&lm.request.outpoint);
                    }
                }
            }
            } // end else (lending_current_daa > 0)
            } // end else (lending_wallet_spk non-empty)
        } else {
            let lb = lending_book.lock().await;
            if lb.offer_count() > 0 || lb.request_count() > 0 {
                info!(
                    "[LENDING] No matches (offers={}, requests={})",
                    lb.offer_count(), lb.request_count(),
                );
            }
        }
    }

    // Phase 6: Prediction market state tracking
    // Prediction markets are not a matching problem — the book tracks
    // market state (SplitMerge, BallotBoxes, Redemption) discovered by
    // the scanner. Settlement detection and expiry checking happen here.
    //
    // Note: Settlement (redeem) requires a winning token UTXO from a user,
    // and expire/refund paths require the creator's signature. These are
    // user-initiated operations, not matcher-automated. The matcher's role
    // is to detect and log actionable state so external services (API, keeper)
    // can trigger the appropriate TXs.
    {
        let pred = prediction_book.lock().await;
        if pred.market_count() > 0 {
            let snapshot = pred.to_snapshot();
            let mut mt = market_tracker.lock().await;

            // Check for settleable markets (both ballot boxes present, not yet settled)
            let settleable = pred.settleable_markets();
            if !settleable.is_empty() {
                info!(
                    "[PREDICTION] {} market(s) ready for settlement",
                    settleable.len(),
                );
                for market in &settleable {
                    let winner = market.leading_side();
                    let yes_val = market.yes_value();
                    let no_val = market.no_value();
                    let yes_votes = market.yes_votes();
                    let no_votes = market.no_votes();
                    info!(
                        "[PREDICTION] SETTLEABLE: {} — leader={:?}, YES={} votes (val={}), NO={} votes (val={}), TVL={}",
                        &market.market_id[..market.market_id.len().min(16)],
                        winner,
                        yes_votes, yes_val,
                        no_votes, no_val,
                        market.total_value_locked(),
                    );

                    // Update tracker with latest vote state
                    if let Some(tracked) = mt.get_mut(&market.market_id) {
                        tracked.yes_value = yes_val;
                        tracked.no_value = no_val;
                    }
                }
            }

            // Log active (unsettled) markets with votes
            for ms in &snapshot {
                if ms.settled {
                    continue;
                }
                // Skip settleable markets (already logged above)
                if settleable.iter().any(|m| m.market_id == ms.market_id) {
                    continue;
                }
                if ms.yes_votes > 0 || ms.no_votes > 0 {
                    info!(
                        "[PREDICTION] Market {} — YES={} votes, NO={} votes, TVL={}",
                        &ms.market_id[..ms.market_id.len().min(16)],
                        ms.yes_votes, ms.no_votes, ms.total_value_locked,
                    );
                }
            }

            // Check for expired ballot boxes that can be reclaimed by creators.
            // This is informational — actual reclaim requires the creator's signature.
            for market in pred.settled_markets().iter().chain(pred.settleable_markets().iter()) {
                if let Some(ref yes_box) = market.yes_box {
                    if yes_box.expiry_daa > 0 {
                        info!(
                            "[PREDICTION] BallotBox YES {} expiry_daa={} (creator can reclaim after expiry)",
                            &yes_box.outpoint[..yes_box.outpoint.len().min(16)],
                            yes_box.expiry_daa,
                        );
                    }
                }
                if let Some(ref no_box) = market.no_box {
                    if no_box.expiry_daa > 0 {
                        info!(
                            "[PREDICTION] BallotBox NO {} expiry_daa={} (creator can reclaim after expiry)",
                            &no_box.outpoint[..no_box.outpoint.len().min(16)],
                            no_box.expiry_daa,
                        );
                    }
                }
            }
        }
    }

    // DCA auto-fill: check for executable DCA orders and build fill TXs.
    //
    // A DCA fill TX spends the DCA UTXO + a matching sell order + a wallet UTXO,
    // producing: (0) token output to buyer, (1) KAS output to seller,
    // (2) DCA continuation UTXO if periods > 1, (3+) wallet change.
    //
    // The DCA UTXO uses CLTV (lock_time = next_execution_daa) while the sell
    // uses OP_CSV (sequence=50).  These are orthogonal per-input checks.
    {
        let current_daa = rpc.get_daa_score().await.unwrap_or(0);
        let executable = {
            let dcab = dca_book.lock().await;
            if dcab.is_empty() {
                Vec::new()
            } else {
                dcab.executable_entries(current_daa)
            }
        };
        if !executable.is_empty() {
            info!(
                "[DCA] {} executable DCA order(s) at DAA {}",
                executable.len(), current_daa,
            );
        }
        for entry in &executable {
            info!(
                "[DCA] Executable: {} token={} periods={} amt/period={} next_exec={}",
                &entry.outpoint_key()[..entry.outpoint_key().len().min(20)],
                &entry.target_cov_id[..entry.target_cov_id.len().min(12)],
                entry.periods_remaining,
                entry.amount_per_period,
                entry.next_execution_daa,
            );

            // Gate: buyer_spk must be known to construct the token output.
            let buyer_spk_hex = match entry.buyer_spk.as_ref() {
                Some(spk) if spk.len() >= 6 => spk, // version(4 hex) + min script
                _ => {
                    debug!(
                        "[DCA] buyer_spk unavailable for {} — cannot build fill TX",
                        &entry.outpoint_key()[..entry.outpoint_key().len().min(20)],
                    );
                    continue;
                }
            };
            let buyer_spk_raw = match hex::decode(buyer_spk_hex) {
                Ok(v) if v.len() > 2 => v,
                _ => {
                    warn!("[DCA] Invalid buyer_spk hex for {}", entry.outpoint_key());
                    continue;
                }
            };
            let buyer_spk_version = u16::from_le_bytes([buyer_spk_raw[0], buyer_spk_raw[1]]);
            let buyer_spk_script = &buyer_spk_raw[2..];

            // 1. Select best-priced sell order for the target token.
            let target_token = &entry.target_cov_id;
            let best_sell = order_book.pair_books.get(target_token).and_then(|pb| {
                // asks are sorted by price ASC (cheapest first).
                pb.asks.values().find(|sell| {
                    if sell.price_den == 0 || sell.price_num == 0 {
                        return false;
                    }
                    // Skip if the sell lacks counterparty_spk (matcher cannot route KAS).
                    if sell.counterparty_spk.is_none() {
                        return false;
                    }
                    // Skip expired sells (expiry_daa > 0 && expiry_daa <= lock_time would
                    // fail the sell contract's time gate: `expiry > lockTime`).
                    if let Some(exp) = sell.expiry_daa {
                        if exp > 0 && exp <= entry.next_execution_daa {
                            return false;
                        }
                    }
                    // Price match: sell price <= DCA limit price (both expressed as KAS/token).
                    // sell: price_num/price_den KAS per token
                    // DCA limit: price_den/price_num KAS per token (inverted from token/KAS)
                    // Condition: sell.pnum * dca.pnum <= dca.pden * sell.pden
                    let lhs = (sell.price_num as u128) * (entry.price_num as u128);
                    let rhs = (entry.price_den as u128) * (sell.price_den as u128);
                    lhs <= rhs
                })
            });

            let sell = match best_sell {
                Some(s) => s,
                None => {
                    debug!(
                        "[DCA] No price-compatible sell for token {}... — deferred",
                        &target_token[..target_token.len().min(12)],
                    );
                    continue;
                }
            };

            // Skip if sell is already spent or under cooldown.
            let sell_key = sell.outpoint_key();
            if spent_tracker.is_spent(&sell_key) {
                debug!("[DCA] Sell {} already spent, skipping", &sell_key[..sell_key.len().min(20)]);
                continue;
            }

            // Resolve seller SPK.
            let (seller_spk_ver, seller_spk_script) = match sell.resolve_counterparty_spk() {
                Some(x) => x,
                None => {
                    warn!("[DCA] Sell {} missing counterparty_spk", &sell_key[..sell_key.len().min(20)]);
                    continue;
                }
            };

            // 2. Compute expected token amount and seller KAS.
            //
            // The DCA contract checks output[0].value >= expected_tokens.
            // The sell contract's F4 checks covenant_output[0].value >= sell.value.
            // Therefore we must give ALL of the sell's tokens to the buyer:
            //   output[0].value = sell.value   (satisfies both if sell.value >= expected_tokens)
            //
            // Seller KAS is computed from the FULL sell amount at the sell's price.
            let expected_tokens = match entry.amount_per_period.checked_mul(entry.price_num) {
                Some(v) => v / entry.price_den,
                None => {
                    warn!("[DCA] u64 overflow in expected_tokens for {}", entry.outpoint_key());
                    continue;
                }
            };
            if expected_tokens < kob_core::MIN_UTXO_VALUE {
                debug!("[DCA] expected_tokens {} < MIN_UTXO_VALUE, skipping", expected_tokens);
                continue;
            }
            // Check that the sell has enough tokens for the DCA's expected minimum.
            if sell.value < expected_tokens {
                debug!(
                    "[DCA] Sell has {} tokens but DCA needs {} — skipping",
                    sell.value, expected_tokens,
                );
                continue;
            }
            // Token output value = sell.value (all tokens from the sell).
            // This satisfies sell F4 (covenant conservation) and DCA F3 (>= expected).
            let token_output_value = sell.value;

            // KAS that the seller expects for ALL their tokens at their price.
            let seller_kas = match sell.value.checked_mul(sell.price_num) {
                Some(v) => v / sell.price_den,
                None => {
                    warn!("[DCA] u64 overflow in seller_kas for {}", entry.outpoint_key());
                    continue;
                }
            };
            if seller_kas < kob_core::MIN_UTXO_VALUE {
                debug!("[DCA] seller_kas {} < MIN_UTXO_VALUE, skipping", seller_kas);
                continue;
            }
            // Ensure the DCA's amount_per_period covers the seller's KAS.
            // This can fail when sell.value > expected_tokens and the extra tokens
            // push seller_kas beyond the DCA's per-period budget.
            if entry.amount_per_period < seller_kas {
                debug!(
                    "[DCA] amt_per_period {} < seller_kas {} — sell too large",
                    entry.amount_per_period, seller_kas,
                );
                continue;
            }

            // 3. Acquire wallet UTXO for miner fee.
            let (utxos, wallet_spk_version, wallet_spk_script, _wallet_spk_hex) =
                match fetch_wallet_utxos(rpc, &config.address, "DCA").await {
                    Some(x) => x,
                    None => continue,
                };
            let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
            let token_p2sh_hex = hex::encode(&token_p2sh.script());
            let wallet_utxo = utxos.iter()
                .filter(|u| {
                    let (_, script) = u.parse_spk();
                    hex::encode(&script) != token_p2sh_hex
                        && !spent_tracker.is_spent(&u.outpoint_key())
                })
                .max_by_key(|u| u.utxo_entry.amount);
            let wallet_utxo = match wallet_utxo {
                Some(u) => u,
                None => {
                    warn!("[DCA] No suitable wallet UTXO for fee — skipping");
                    continue;
                }
            };

            // 4. Parse DCA RS and build continuation RS (D&R) if periods > 1.
            let dca_rs = match hex::decode(&entry.redeem_script_hex) {
                Ok(v) => v,
                Err(_) => {
                    warn!("[DCA] Failed to decode DCA RS hex");
                    continue;
                }
            };
            let sell_rs = match hex::decode(&sell.redeem_script_hex) {
                Ok(v) => v,
                Err(_) => {
                    warn!("[DCA] Failed to decode sell RS hex");
                    continue;
                }
            };

            let is_final_fill = entry.periods_remaining == 1;
            let (new_rs, continuation_output_idx) = if is_final_fill {
                // Final period: no continuation UTXO needed.
                (Vec::new(), 0u8)
            } else {
                // Build continuation RS with updated next_exec and periods.
                let parsed = match kob_core::parse_dca_order_rs(&dca_rs) {
                    Some(p) => p,
                    None => {
                        warn!("[DCA] Failed to parse DCA RS for {}", entry.outpoint_key());
                        continue;
                    }
                };
                let new_next_exec = parsed.next_execution_daa + parsed.interval_daa;
                let new_periods = parsed.periods_remaining - 1;
                match kob_core::build_dca_order_redeem_script(
                    &parsed.owner_hash,
                    &parsed.target_cov_id,
                    &parsed.buyer_spk_hash,
                    parsed.price_num,
                    parsed.price_den,
                    parsed.amount_per_period,
                    parsed.interval_daa,
                    new_next_exec,
                    new_periods,
                ) {
                    Ok(rs) => (rs, 2u8), // continuation at output[2]
                    Err(e) => {
                        warn!("[DCA] Failed to build continuation RS: {}", e);
                        continue;
                    }
                }
            };

            // 5. Build the fill TX.
            //
            // Input layout:
            //   [0] sell order  (sequence=50 for OP_CSV)
            //   [1] DCA order   (sequence=0, CLTV via lock_time)
            //   [2] wallet UTXO (sequence=0, P2PK signed)
            //
            // Output layout:
            //   [0] tokens to DCA buyer (DCA contract checks output[0])
            //   [1] KAS to seller (sell contract's koi=1)
            //   [2] DCA continuation (if periods > 1), P2SH(new_rs)
            //   [2/3] wallet change (remaining KAS)

            // Sell fill sigscript: [koi_opN][Op1][pushData(RS)]
            // koi=1 (seller KAS output is at index 1)
            let sell_fill_ss = kob_core::build_sell_fill_sigscript(1u16, &sell_rs);

            // DCA fill sigscript.
            // For non-final fills: old_rs and new_rs are the current and updated RS.
            // For final fill (periods==1): old_rs and new_rs are empty (the D&R
            // block is skipped, so they are pushed but never verified).
            let (fill_old_rs, fill_new_rs): (&[u8], &[u8]) = if is_final_fill {
                (&[], &[])
            } else {
                (&dca_rs, &new_rs)
            };
            let dca_fill_ss = kob_core::build_dca_order_fill_sigscript(
                continuation_output_idx,
                fill_old_rs,
                fill_new_rs,
                &dca_rs,  // redeem_script of the input being spent
            );

            // Fee estimate: 3 inputs, 3-4 outputs, 1 sig_op (wallet)
            let num_outputs = if is_final_fill { 3 } else { 4 }; // with or without continuation
            let est_fee = kob_core::mass::estimate_compute_mass(3, num_outputs, 0);

            // Continuation UTXO value: DCA value minus amount_per_period.
            let continuation_value = if is_final_fill {
                0
            } else {
                entry.value.saturating_sub(entry.amount_per_period)
            };
            if !is_final_fill && continuation_value < kob_core::MIN_UTXO_VALUE {
                warn!(
                    "[DCA] Continuation value {} < MIN_UTXO_VALUE — cannot fill",
                    continuation_value,
                );
                continue;
            }

            // Total KAS in: sell.value (tokens, part of covenant) + DCA.value + wallet.value
            // Total KAS out: expected_tokens (output[0]) + seller_kas (output[1])
            //                + continuation (output[2] if !final) + wallet_change + miner_fee
            let total_kas_in = entry.value + wallet_utxo.utxo_entry.amount;
            let kas_needed = seller_kas + continuation_value + est_fee;
            if total_kas_in < kas_needed {
                warn!(
                    "[DCA] Insufficient KAS: have {} (dca={} + wallet={}) need {} (seller={} + cont={} + fee={})",
                    total_kas_in, entry.value, wallet_utxo.utxo_entry.amount,
                    kas_needed, seller_kas, continuation_value, est_fee,
                );
                continue;
            }
            let wallet_change = total_kas_in - kas_needed;

            // Build sighash TX for wallet input signing.
            let sell_p2sh = kob_core::build_p2sh(&sell_rs);
            let dca_p2sh = kob_core::build_p2sh(&dca_rs);

            let mut sighash_tx = kob_core::tx::Transaction::new(1);
            sighash_tx.lock_time = entry.next_execution_daa;

            // Input[0]: sell order (sequence=50 for CSV)
            sighash_tx.inputs.push(kob_core::tx::TxInput {
                prev_tx_id: sell.tx_id.clone(),
                prev_index: sell.index,
                sequence: 50,
                sig_op_count: 0,
                script_version: sell_p2sh.version,
                script_bytes: sell_p2sh.script().to_vec(),
                value: sell.value,
            });
            // Input[1]: DCA order (sequence=0, CLTV)
            sighash_tx.inputs.push(kob_core::tx::TxInput {
                prev_tx_id: entry.tx_id.clone(),
                prev_index: entry.index,
                sequence: 0,
                sig_op_count: 0,
                script_version: dca_p2sh.version,
                script_bytes: dca_p2sh.script().to_vec(),
                value: entry.value,
            });
            // Input[2]: wallet UTXO (P2PK, sigOpCount=1)
            let (w_spk_version, w_spk_script) = wallet_utxo.parse_spk();
            sighash_tx.inputs.push(kob_core::tx::TxInput {
                prev_tx_id: wallet_utxo.outpoint.transaction_id.clone(),
                prev_index: wallet_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: w_spk_version,
                script_bytes: w_spk_script.clone(),
                value: wallet_utxo.utxo_entry.amount,
            });

            // Output[0]: tokens to DCA buyer (covenant binding from sell input[0])
            let sell_token_hex = &sell.token_cov_id;
            let sell_cov_hash = match kob_core::compat::parse_hash(sell_token_hex) {
                Ok(h) => h,
                Err(_) => {
                    warn!("[DCA] Invalid sell token_cov_id hex");
                    continue;
                }
            };
            sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                token_output_value,
                buyer_spk_version,
                buyer_spk_script.to_vec(),
                Some(kob_core::tx::CovenantBinding::new(0, sell_cov_hash)),
            ));
            // Output[1]: KAS to seller
            sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                seller_kas,
                seller_spk_ver,
                seller_spk_script.clone(),
                None,
            ));
            // Output[2]: DCA continuation (if periods > 1)
            if !is_final_fill {
                let cont_p2sh = kob_core::build_p2sh(&new_rs);
                sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                    continuation_value,
                    cont_p2sh.version,
                    cont_p2sh.script().to_vec(),
                    None,
                ));
            }
            // Wallet change output
            if wallet_change >= kob_core::MIN_UTXO_VALUE {
                sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                    wallet_change,
                    wallet_spk_version,
                    wallet_spk_script.clone(),
                    None,
                ));
            }

            // Sign wallet input (input[2]) — P2PK: sigscript = [sig 65B]
            let wallet_input_idx = 2usize;
            let sighash = match kob_core::compute_sighash(&sighash_tx, wallet_input_idx) {
                Ok(h) => h,
                Err(e) => {
                    error!("[DCA] Sighash computation failed: {}", e);
                    continue;
                }
            };
            let mut privkey = config.private_key_bytes();
            let sig = match kob_core::schnorr_sign(&sighash, &privkey) {
                Ok(s) => s,
                Err(e) => {
                    privkey.zeroize();
                    error!("[DCA] Wallet signing failed: {}", e);
                    continue;
                }
            };
            privkey.zeroize();
            let wallet_ss = kob_core::contract::build_p2pk_sigscript(&sig);

            // Build RPC inputs
            let rpc_inputs = vec![
                deploy::build_rpc_input_with_sequence(
                    &sell.tx_id, sell.index,
                    &hex::encode(&sell_fill_ss), 0, 50,
                ),
                deploy::build_rpc_input_with_sequence(
                    &entry.tx_id, entry.index,
                    &hex::encode(&dca_fill_ss), 0, 0,
                ),
                deploy::build_rpc_input_with_sequence(
                    &wallet_utxo.outpoint.transaction_id, wallet_utxo.outpoint.index,
                    &hex::encode(&wallet_ss), 1, 0,
                ),
            ];

            // Build RPC outputs
            let mut rpc_outputs = vec![
                // Output[0]: tokens to buyer (with covenant binding to sell input[0])
                deploy::build_rpc_output_with_covenant(
                    token_output_value,
                    buyer_spk_version,
                    &hex::encode(buyer_spk_script),
                    0, // auth input = sell at index 0
                    sell_token_hex,
                ),
                // Output[1]: KAS to seller
                deploy::build_rpc_output(seller_kas, seller_spk_ver, &hex::encode(&seller_spk_script)),
            ];
            if !is_final_fill {
                let cont_p2sh = kob_core::build_p2sh(&new_rs);
                rpc_outputs.push(deploy::build_rpc_output(
                    continuation_value,
                    cont_p2sh.version,
                    &hex::encode(cont_p2sh.script()),
                ));
            }
            if wallet_change >= kob_core::MIN_UTXO_VALUE {
                rpc_outputs.push(deploy::build_rpc_output(
                    wallet_change,
                    wallet_spk_version,
                    &hex::encode(&wallet_spk_script),
                ));
            }

            // 6. Submit TX (lock_time = next_execution_daa for CLTV).
            let payload = deploy::build_submit_payload_with_lock_time(
                1, rpc_inputs, rpc_outputs, entry.next_execution_daa,
            );
            match rpc.submit_transaction(payload).await {
                Ok(result) if result.ok => {
                    let tx_id = result.tx_id.unwrap_or_default();
                    info!(
                        "[DCA] FILL SUCCESS: {} -> TX {} (tokens={}, seller_kas={}, periods_left={})",
                        &entry.outpoint_key()[..entry.outpoint_key().len().min(20)],
                        &tx_id[..tx_id.len().min(16)],
                        token_output_value, seller_kas,
                        if is_final_fill { 0 } else { entry.periods_remaining - 1 },
                    );
                    // Mark inputs as spent.
                    let dca_entry_key = entry.outpoint_key();
                    let dca_wallet_key = wallet_utxo.outpoint_key();
                    spent_tracker.mark_spent(&dca_entry_key);
                    spent_tracker.mark_spent(&sell_key);
                    spent_tracker.mark_spent(&dca_wallet_key);
                    if !tx_id.is_empty() {
                        spent_tracker.mark_submitted(
                            &tx_id,
                            &[dca_entry_key.clone(), sell_key.clone(), dca_wallet_key],
                        );
                    }

                    // Remove the consumed DCA entry.  The continuation UTXO (if any)
                    // will be rediscovered by the scanner in a subsequent block and
                    // re-added to the DCA book with updated next_exec/periods.
                    {
                        let mut dcab = dca_book.lock().await;
                        dcab.remove(&entry.outpoint_key());
                    }
                }
                Ok(result) => {
                    let err_str = result.error.unwrap_or_else(|| "Unknown".to_string());
                    warn!(
                        "[DCA] FILL FAILED: {} — {}",
                        &entry.outpoint_key()[..entry.outpoint_key().len().min(20)],
                        err_str,
                    );
                    spent_tracker.mark_failed(&entry.outpoint_key());
                }
                Err(e) => {
                    error!("[DCA] RPC error for {}: {}", entry.outpoint_key(), e);
                    spent_tracker.mark_failed(&entry.outpoint_key());
                }
            }
        }
    }

    results
}

// Continuous Mode

/// Main continuous matcher loop with optional WS broadcaster for emitting
/// user-order lifecycle events (OrderFilled, OrderCancelled, etc.).
pub async fn run_continuous_with_ws(
    rpc: Arc<Mutex<RpcClient>>,
    order_book: Arc<Mutex<OrderBook>>,
    config: &AppConfig,
    interval_ms: u64,
    orderbook_path: &str,
    enable_cross_pair: bool,
    allow_self_trade: bool,
    ws_tx: Option<tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    shared_stop_book: Arc<Mutex<crate::matcher::stop_book::StopOrderBook>>,
    shared_trailing_stop_book: Arc<Mutex<crate::matcher::trailing_stop::TrailingStopBook>>,
    shared_state: Option<AppState>,
    shared_ifd_book: Arc<Mutex<crate::matcher::ifd::IfdBook>>,
    shared_perp_book: Arc<Mutex<crate::matcher::perp_book::PerpOrderBook>>,
    shared_perp_tracker: Arc<Mutex<crate::matcher::perp_tracker::PositionTracker>>,
    shared_lending_book: Arc<Mutex<crate::matcher::lending_book::LendingBook>>,
    shared_loan_tracker: Arc<Mutex<crate::matcher::lending_tracker::LoanTracker>>,
    shared_prediction_book: Arc<Mutex<crate::matcher::prediction_book::PredictionBook>>,
    shared_market_tracker: Arc<Mutex<crate::matcher::prediction_tracker::MarketTracker>>,
    shared_dca_book: Arc<Mutex<crate::matcher::dca_book::DcaBook>>,
    shared_swap_book: Arc<Mutex<crate::matcher::swap_book::SwapBook>>,
) {
    info!("======================================================================");
    info!("KOB MATCHER BOT -- CONTINUOUS MODE (HARDENED)");
    info!("======================================================================");
    info!("Wallet:   {}", config.address);
    info!("Node:     {}", config.node_url);
    info!("Interval: {}ms", interval_ms);
    info!("Cross-pair routing: {}", if enable_cross_pair { "ENABLED" } else { "disabled" });

    // Set up graceful shutdown with TX drain support.
    // Phase 1 (first signal): set shutdown flag, finish current scan cycle
    //   (including any in-flight RPC TX submissions), then persist and exit.
    // Phase 2 (second signal during drain): force-exit immediately.
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let force_exit = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let force_exit_clone = force_exit.clone();

    tokio::spawn(async move {
        // First signal: graceful shutdown
        tokio::signal::ctrl_c().await.ok();
        info!("[SHUTDOWN] Graceful shutdown requested -- draining in-flight TXs...");
        info!("[SHUTDOWN] Press Ctrl+C again to force immediate exit.");
        shutdown_clone.store(true, std::sync::atomic::Ordering::SeqCst);

        // Second signal: force exit
        tokio::signal::ctrl_c().await.ok();
        warn!("[SHUTDOWN] Force exit requested -- aborting immediately!");
        force_exit_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        // Give a moment for the log to flush, then hard-exit.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        std::process::exit(1);
    });

    // C3: share the shutdown flag with the RPC client so reconnect()'s backoff
    // sleep can be interrupted by Ctrl+C instead of waiting up to 60s.
    // C4: obtain a handle to the notification-dropped flag; checked each cycle
    // below to trigger a backfill scan when the reader task had to drop
    // notifications due to channel overflow.
    let notif_dropped_flag = {
        let mut rpc_lock = rpc.lock().await;
        rpc_lock.set_shutdown_flag(shutdown.clone());
        rpc_lock.notification_dropped_handle()
    };

    info!("Scanning for orders... Press Ctrl+C to stop.");

    // Stop/trailing stop/IFD persistence paths (alongside order book file).
    let stop_orders_path = format!("{}.stops.json", orderbook_path);
    let trailing_stops_path = format!("{}.trailing.jsonl", orderbook_path);
    let ifd_path = format!("{}.ifd.json", orderbook_path);
    let perp_book_path = format!("{}.perp.json", orderbook_path);
    let lending_book_path = format!("{}.lending.json", orderbook_path);
    let prediction_book_path = format!("{}.prediction.json", orderbook_path);
    let swap_book_path = format!("{}.swap.json", orderbook_path);
    let scan_state_path = format!("{}.scan.json", orderbook_path);

    let mut cycle = 0u64;
    let mut spent_tracker = SpentTracker::new();
    let mut reorg_tracker = ReorgTracker::new();
    let mut covenant_cache = CovenantCache::new();

    // Pre-seed covenant cache from existing pair book keys.
    // The order book's pair_books map is keyed by token_cov_id; any token
    // present in the persisted book was validated in a prior session.
    {
        let ob = order_book.lock().await;
        let zero_id = "0".repeat(64);
        for cov_id in ob.pair_books.keys() {
            if !cov_id.is_empty() && *cov_id != zero_id {
                covenant_cache.seed_valid(cov_id);
            }
        }
        let n = covenant_cache.valid.len();
        if n > 0 {
            info!("[COVENANT] Pre-seeded {} valid covenant ID(s) from persisted order book", n);
        }
    }

    // H1: prefer persisted cursor; fall back to current sink.
    let mut last_seen_hash: Option<String> = std::fs::read_to_string(&scan_state_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("last_seen_hash").and_then(|h| h.as_str()).map(String::from));
    if let Some(ref h) = last_seen_hash {
        info!("[H1] Resuming from persisted last_seen_hash={}...", &h[..h.len().min(16)]);
    } else {
        let rpc_lock = rpc.lock().await;
        match rpc_lock.get_sink_hash().await {
            Ok(h) => {
                info!("[H1] No cursor; initial last_seen_hash = {}...", &h[..h.len().min(16)]);
                last_seen_hash = Some(h);
            }
            Err(e) => warn!("[H1] Failed to get initial sink hash: {}", e),
        }
    }

    if let Some(ref hash) = last_seen_hash.clone() {
        let rpc_bf = rpc.lock().await;
        let current_daa = rpc_bf.get_daa_score().await.unwrap_or(0);
        let mut ob = order_book.lock().await;
        let mut pb = shared_perp_book.lock().await;
        let mut lb = shared_lending_book.lock().await;
        let mut pred = shared_prediction_book.lock().await;
        let (new_hash, counters) = scan_new_blocks(
            &*rpc_bf, &mut ob, &mut pb, &mut lb, &mut pred,
            hash, ws_tx.as_ref(), current_daa,
        ).await;
        if new_hash != *hash {
            info!(
                "[H1] startup catchup: tip {} (spot+{}, perp+{})",
                &new_hash[..new_hash.len().min(16)],
                counters.spot_added, counters.perp_added,
            );
            last_seen_hash = Some(new_hash);
        }
    }

    // Subscribe to BlockAdded and VirtualChainChanged notifications.
    //
    // BlockAdded: provides full block data (transactions) for order discovery.
    // VirtualChainChanged: provides removedChainBlockHashes for reorg detection.
    //   Without this, the engine would be unaware of chain reorganizations and
    //   could have phantom orders (from reorged-out blocks) or miss the
    //   restoration of orders whose spends were reorged out.
    info!("==========================================================");
    info!("  KOB Engine ready — listening for new blocks.");
    info!("  IMPORTANT: Deploy orders AFTER this message appears.");
    info!("  Orders deployed before the engine starts will NOT be");
    info!("  discovered (no full UTXO rescan on startup).");
    info!("==========================================================");
    let mut notif_rx = {
        let rpc_lock = rpc.lock().await;
        match rpc_lock.subscribe("BlockAdded").await {
            Ok(_) => info!("[SUBSCRIBE] Subscribed to BlockAdded notifications"),
            Err(e) => warn!("[SUBSCRIBE] Failed to subscribe to BlockAdded: {}. Will retry on reconnect.", e),
        }
        // Subscribe to VirtualChainChanged for reorg detection.
        // This notification fires whenever the selected parent chain changes,
        // providing both added and removed block hashes.
        match rpc_lock.subscribe("VirtualChainChanged").await {
            Ok(_) => info!("[SUBSCRIBE] Subscribed to VirtualChainChanged notifications (reorg detection)"),
            Err(e) => warn!("[SUBSCRIBE] Failed to subscribe to VirtualChainChanged: {}. Reorg detection disabled.", e),
        }
        rpc_lock.take_notification_receiver().await
            .expect("notification receiver already taken")
    };

    while !shutdown.load(std::sync::atomic::Ordering::SeqCst) {
        // BUG 1 fix: Check RPC connection health at the top of each cycle.
        // If the connection is dead, attempt reconnection before any RPC calls.
        // On reconnect, re-subscribe and take the new notification receiver.
        {
            let mut rpc_lock = rpc.lock().await;
            if rpc_lock.needs_reconnect() {
                warn!("[RPC] Connection dead, attempting reconnect...");
                if let Err(e) = rpc_lock.reconnect().await {
                    // C3: reconnect() returns Err("shutdown") when the shared
                    // shutdown flag is set — break the outer loop immediately
                    // so Ctrl+C does not have to wait 5s before the next check.
                    if e == "shutdown" || shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                        info!("[RPC] Reconnect aborted due to shutdown");
                        drop(rpc_lock);
                        break;
                    }
                    warn!("[RPC] Reconnect failed: {}, retrying in 5s...", e);
                    drop(rpc_lock);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                info!("[RPC] Reconnected successfully");
                // Re-subscribe after reconnect
                match rpc_lock.subscribe("BlockAdded").await {
                    Ok(_) => info!("[SUBSCRIBE] Re-subscribed to BlockAdded notifications"),
                    Err(e) => warn!("[SUBSCRIBE] Failed to re-subscribe to BlockAdded: {}", e),
                }
                match rpc_lock.subscribe("VirtualChainChanged").await {
                    Ok(_) => info!("[SUBSCRIBE] Re-subscribed to VirtualChainChanged notifications"),
                    Err(e) => warn!("[SUBSCRIBE] Failed to re-subscribe to VirtualChainChanged: {}", e),
                }
                if let Some(new_rx) = rpc_lock.take_notification_receiver().await {
                    notif_rx = new_rx;
                }

                // H2: Catch up on blocks missed during WS disconnect.
                // Uses the old polling-based scan_new_blocks (getVirtualChainFromBlock)
                // to discover and process any blocks added while we were disconnected.
                if let Some(ref hash) = last_seen_hash {
                    info!("[H2] Catching up from last_seen_hash={}...", &hash[..hash.len().min(16)]);
                    let current_daa = rpc_lock.get_daa_score().await.unwrap_or(0);
                    let catchup_hash = hash.clone();
                    drop(rpc_lock);
                    let rpc_catchup = rpc.lock().await;
                    let mut ob = order_book.lock().await;
                    let mut pb = shared_perp_book.lock().await;
                    let mut lb = shared_lending_book.lock().await;
                    let mut pred = shared_prediction_book.lock().await;
                    let (new_hash, counters) = scan_new_blocks(
                        &*rpc_catchup, &mut ob, &mut pb, &mut lb, &mut pred,
                        &catchup_hash, ws_tx.as_ref(), current_daa,
                    ).await;
                    if new_hash != catchup_hash {
                        info!(
                            "[H2] Catchup complete: {} new tip, spot(+{}), perp(+{})",
                            &new_hash[..new_hash.len().min(16)],
                            counters.spot_added, counters.perp_added,
                        );
                        last_seen_hash = Some(new_hash);
                    } else {
                        debug!("[H2] Catchup: no new blocks since disconnect");
                    }
                } else {
                    // No last_seen_hash: initialize from current sink
                    if let Ok(h) = rpc_lock.get_sink_hash().await {
                        last_seen_hash = Some(h);
                    }
                }
            }
        }

        cycle += 1;
        debug!("--- Scan cycle {} ---", cycle);

        // M-6 / H-1: Mempool-aware pruning of spent tracker entries every cycle.
        // Uses SPENT_PRUNE_AGE_SECS (600s) for the base age threshold, but
        // retains aged entries whose submit_txid is still in the mempool to
        // prevent "already spent ... in the mempool" rejections when a
        // self-submitted TX dwells past 600s before confirming. A hard cap
        // at SPENT_PRUNE_HARD_MAX_AGE_SECS (7200s) guards against unbounded
        // growth if the mempool RPC misbehaves.
        {
            let rpc_lock = rpc.lock().await;
            spent_tracker.prune_spent(SPENT_PRUNE_AGE_SECS, &*rpc_lock).await;
        }
        spent_tracker.expire_failed();

        // Phase 0: Process block notifications (event-driven).
        // Drain all pending notifications and process them.
        //
        // Two notification types are handled:
        //   - blockAddedNotification: new blocks with full TX data (primary path)
        //   - virtualChainChangedNotification: chain reorg signals with
        //     removedChainBlockHashes and addedChainBlockHashes
        //
        // Reorg handling: when removedChainBlockHashes are received, the
        // ReorgTracker rolls back orders added/spent by those blocks.
        // C4: if the WS reader task had to drop notifications due to channel
        // overflow during the last cycle, trigger a backfill scan from
        // last_seen_hash so orders in dropped blocks are still discovered.
        // swap(false) atomically consumes the flag, so a concurrent overflow
        // during the backfill will set the flag for the next cycle.
        if notif_dropped_flag.swap(false, std::sync::atomic::Ordering::SeqCst) {
            warn!("[NOTIFY] Notification channel overflow detected -- backfilling missed blocks");
            if let Some(ref hash) = last_seen_hash.clone() {
                let rpc_bf = rpc.lock().await;
                let current_daa = rpc_bf.get_daa_score().await.unwrap_or(0);
                let mut ob = order_book.lock().await;
                let mut pb = shared_perp_book.lock().await;
                let mut lb = shared_lending_book.lock().await;
                let mut pred = shared_prediction_book.lock().await;
                let (new_hash, counters) = scan_new_blocks(
                    &*rpc_bf, &mut ob, &mut pb, &mut lb, &mut pred,
                    hash, ws_tx.as_ref(), current_daa,
                ).await;
                if new_hash != *hash {
                    info!(
                        "[NOTIFY-BACKFILL] recovered tip {} (spot+{}, perp+{})",
                        &new_hash[..new_hash.len().min(16)],
                        counters.spot_added, counters.perp_added,
                    );
                    last_seen_hash = Some(new_hash);
                }
            }
        }

        {
            let scanner = BlockScanner::new();
            let mut blocks_processed = 0u64;
            let mut total_counters = ScanCounters::default();

            // Collect all queued block notifications first, then batch-process.
            // This avoids per-block RPC calls and lock contention.
            // Each entry is (block_hash, txs) so we can track provenance.
            let mut block_txs_batch: Vec<(Option<String>, Vec<TransactionData>)> = Vec::new();
            // Removed block hashes from virtualChainChangedNotification.
            let mut reorg_removed_hashes: Vec<String> = Vec::new();
            loop {
                match notif_rx.try_recv() {
                    Ok(notif) => {
                        let method = notif.get("method").and_then(|m| m.as_str()).unwrap_or("");

                        if method == "blockAddedNotification" {
                            // Extract block from params.BlockAdded.block
                            // Kaspa wRPC format: {"params": {"BlockAdded": {"block": {...}}}}
                            let block = match notif.get("params")
                                .and_then(|p| p.get("BlockAdded").or_else(|| p.get("block")))
                                .and_then(|ba| ba.get("block").or(Some(ba)))
                            {
                                Some(b) => b,
                                None => continue,
                            };
                            // H2: Extract block hash for catchup tracking + reorg provenance.
                            // Kaspa wRPC: block.verboseData.hash or block.header.hash
                            let block_hash = block
                                .get("verboseData").and_then(|vd| vd.get("hash"))
                                .or_else(|| block.get("header").and_then(|h| h.get("hash")))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            if let Some(ref bh) = block_hash {
                                last_seen_hash = Some(bh.clone());
                            }

                            let txs: Vec<TransactionData> = block
                                .get("transactions")
                                .and_then(|t| t.as_array())
                                .map(|arr| arr.iter().filter_map(TransactionData::from_rpc_json).collect())
                                .unwrap_or_default();

                            if !txs.is_empty() {
                                block_txs_batch.push((block_hash, txs));
                            }
                            blocks_processed += 1;
                        } else if method == "virtualChainChangedNotification" {
                            // Kaspa wRPC format:
                            // {"params": {"VirtualChainChanged": {
                            //   "removedChainBlockHashes": ["hash1", ...],
                            //   "addedChainBlockHashes": ["hash2", ...],
                            //   "acceptedTransactionIds": [...]
                            // }}}
                            let vcc = match notif.get("params")
                                .and_then(|p| p.get("VirtualChainChanged").or_else(|| p.get("virtualChainChanged")))
                            {
                                Some(v) => v,
                                None => continue,
                            };

                            // Collect removed block hashes for reorg processing
                            if let Some(removed) = vcc.get("removedChainBlockHashes")
                                .and_then(|v| v.as_array())
                            {
                                for hash_val in removed {
                                    if let Some(h) = hash_val.as_str() {
                                        reorg_removed_hashes.push(h.to_string());
                                    }
                                }
                            }

                            // Update last_seen_hash from added chain blocks
                            if let Some(added) = vcc.get("addedChainBlockHashes")
                                .and_then(|v| v.as_array())
                            {
                                if let Some(last) = added.last().and_then(|v| v.as_str()) {
                                    last_seen_hash = Some(last.to_string());
                                }
                            }
                        }
                        // Other notification types are silently skipped.
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        warn!("[NOTIFY] Notification channel disconnected");
                        break;
                    }
                }
            }

            // REORG HANDLING: Process removed blocks BEFORE adding new ones.
            //
            // When the virtual selected parent chain changes, blocks that were
            // previously in the chain may be removed. Any orders added by those
            // blocks must be removed from the book, and any orders spent by
            // those blocks must be restored.
            if !reorg_removed_hashes.is_empty() {
                warn!(
                    "[REORG] Chain reorganization detected: {} block(s) removed",
                    reorg_removed_hashes.len(),
                );
                for h in &reorg_removed_hashes {
                    warn!("[REORG]   removed block: {}...", &h[..h.len().min(16)]);
                }

                let mut ob = order_book.lock().await;
                let (restored, removed, handled, unknown) = reorg_tracker.handle_removed_blocks(
                    &reorg_removed_hashes,
                    &mut ob,
                    &mut spent_tracker,
                );

                if restored > 0 || removed > 0 {
                    warn!(
                        "[REORG] Rollback complete: {} order(s) restored, {} order(s) removed, \
                         {}/{} block(s) handled ({} unknown)",
                        restored, removed, handled, reorg_removed_hashes.len(), unknown,
                    );

                    // Persist the corrected order book immediately after a reorg
                    // to prevent data loss if the engine crashes.
                    if let Err(e) = persistence::save_order_book(orderbook_path, &ob) {
                        warn!("[REORG] Failed to persist order book after reorg: {}", e);
                    }
                }

                if unknown > 0 {
                    warn!(
                        "[REORG] {} block(s) had no provenance data. Running UTXO validation \
                         is recommended (restart the engine to trigger startup pruning).",
                        unknown,
                    );
                }
            }

            // Process all collected block TXs in one batch with a single DAA score fetch
            if !block_txs_batch.is_empty() {
                let rpc_lock = rpc.lock().await;
                let current_daa = rpc_lock.get_daa_score().await.unwrap_or(0);
                drop(rpc_lock);

                let mut ob = order_book.lock().await;
                let mut pb = shared_perp_book.lock().await;
                let mut lb = shared_lending_book.lock().await;
                let mut pred = shared_prediction_book.lock().await;
                let mut ib = shared_ifd_book.lock().await;
                let mut dcab = shared_dca_book.lock().await;
                let mut swab = shared_swap_book.lock().await;

                for (block_hash, txs) in &block_txs_batch {
                    // Create a ReorgCollector to track provenance for this block.
                    // Only collect if we have a block hash to index by.
                    let mut collector = block_hash.as_ref().map(|_| ReorgCollector::new());

                    let counters = process_block_txs_all(
                        txs, &mut ob, &scanner, &mut pb, &mut lb, &mut pred,
                        Some(&mut covenant_cache),
                        ws_tx.as_ref(), current_daa, Some(&mut ib),
                        Some(&mut dcab),
                        Some(&mut swab),
                        collector.as_mut(),
                    );

                    // Commit provenance data to the reorg tracker
                    if let (Some(bh), Some(rc)) = (block_hash, collector) {
                        // Primary SpentTracker cleanup: any of our self-submitted
                        // TXs that just landed are now confirmed on-chain, so
                        // their spent-input marks are no longer needed (kaspad
                        // will reject any attempt to re-spend those UTXOs
                        // anyway). This runs unconditionally per block, so
                        // stale bids can never resurface between our submit
                        // and the TX confirming — regardless of mempool dwell
                        // time (root-fix for P23 run24).
                        spent_tracker.remove_spent_for_txids(&rc.txids);

                        if !rc.orders_added.is_empty() || !rc.orders_spent.is_empty() {
                            reorg_tracker.record_block(
                                bh.clone(),
                                rc.orders_added,
                                rc.orders_spent,
                                rc.txids,
                            );
                        }
                    }

                    total_counters.spot_added += counters.spot_added;
                    total_counters.spot_removed += counters.spot_removed;
                    total_counters.perp_added += counters.perp_added;
                    total_counters.perp_removed += counters.perp_removed;
                    total_counters.lending_added += counters.lending_added;
                    total_counters.lending_removed += counters.lending_removed;
                    total_counters.prediction_added += counters.prediction_added;
                    total_counters.prediction_removed += counters.prediction_removed;
                    total_counters.dca_added += counters.dca_added;
                    total_counters.dca_removed += counters.dca_removed;
                    total_counters.swap_added += counters.swap_added;
                    total_counters.swap_removed += counters.swap_removed;
                }
            }

            // Post-block covenant verification: drain pending IDs that
            // weren't resolved by passive learning during this batch.
            // Mark them invalid (TTL-based) so they're rejected until the
            // next re-check window. Also prune expired invalid entries.
            {
                let pending = covenant_cache.take_pending();
                if !pending.is_empty() {
                    let mut resolved = 0usize;
                    let mut rejected = 0usize;
                    for cov_id in &pending {
                        if covenant_cache.is_valid(cov_id) {
                            // Passive learning resolved it during this batch
                            resolved += 1;
                        } else {
                            covenant_cache.mark_invalid(cov_id);
                            warn!(
                                "[COVENANT] Marking covenant {} invalid (not seen on-chain, TTL={}s)",
                                &cov_id[..cov_id.len().min(16)],
                                INVALID_COVENANT_TTL_SECS,
                            );
                            rejected += 1;
                        }
                    }
                    if resolved > 0 || rejected > 0 {
                        info!(
                            "[COVENANT] Verification: {} resolved, {} rejected (valid={}, invalid={})",
                            resolved, rejected,
                            covenant_cache.valid.len(),
                            covenant_cache.invalid.len(),
                        );
                    }
                }
                covenant_cache.prune_expired();
            }

            if blocks_processed > 0 {
                let any_found = total_counters.spot_added > 0
                    || total_counters.perp_added > 0
                    || total_counters.lending_added > 0
                    || total_counters.prediction_added > 0
                    || total_counters.dca_added > 0
                    || total_counters.swap_added > 0;
                if any_found {
                    info!(
                        "[NOTIFY] Processed {} block(s): spot(+{}), perp(+{}), lending(+{}), prediction(+{}), dca(+{}), swap(+{})",
                        blocks_processed,
                        total_counters.spot_added, total_counters.perp_added,
                        total_counters.lending_added, total_counters.prediction_added,
                        total_counters.dca_added, total_counters.swap_added,
                    );
                } else {
                    debug!("[NOTIFY] Processed {} block(s), no new orders", blocks_processed);
                }
            }
        }

        // F20: Prune stale matched_outpoints entries (time-based eviction).
        // Time-based pruning (10-min TTL) runs every 100 cycles.
        if cycle % 100 == 0 {
            let mut ob = order_book.lock().await;
            ob.prune_matched_outpoints();
        }

        let rpc_lock = rpc.lock().await;
        let scan_result = {
            let mut ob = order_book.lock().await;
            run_scan_cycle(&rpc_lock, &mut ob, config, &mut spent_tracker, enable_cross_pair, allow_self_trade, ws_tx.as_ref(), shared_state.as_ref(), &shared_ifd_book, &shared_perp_book, &shared_perp_tracker, &shared_lending_book, &shared_loan_tracker, &shared_prediction_book, &shared_market_tracker, &shared_dca_book, &shared_swap_book).await
        };

        // Receipt chaining: the receipt from the last successful match
        // is stored for reuse as fee input in the next trade. No separate
        // consume TX is needed.
        // (Receipt tracking state is managed by run_scan_cycle.)

        // Stop order and trailing stop processing
        // After each matching cycle, check if any trades triggered stop or
        // trailing stop orders. For each triggered order, broadcast the
        // pre-signed TX to L1.
        if !scan_result.is_empty() {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Collect triggered TX payloads under lock, then broadcast outside lock
            let mut stop_broadcasts: Vec<(u64, String)> = Vec::new();
            let mut trailing_broadcasts: Vec<(u64, String)> = Vec::new();

            {
                let sb = shared_stop_book.lock().await;
                let mut tb = shared_trailing_stop_book.lock().await;

                for mr in &scan_result {
                    let pair = &mr.token_cov_id;
                    let price_num = mr.price_num;
                    let price_den = mr.price_den;

                    // --- Stop orders ---
                    let triggered_ids = sb.check_triggers(pair, price_num, price_den);
                    for stop_id in triggered_ids {
                        let signed_tx_json = match sb.get(stop_id) {
                            Some(order) if !order.is_expired(now_unix) => {
                                order.signed_tx_json.clone()
                            }
                            _ => continue,
                        };
                        info!(
                            "[STOP] Triggered stop order #{} for pair [{}...] at price {}/{}",
                            stop_id, &pair[..pair.len().min(12)], price_num, price_den,
                        );
                        stop_broadcasts.push((stop_id, signed_tx_json));
                    }

                    // --- Trailing stop orders ---
                    let trailing_triggered = tb.on_price_update(pair, price_num, price_den);
                    for (trail_id, signed_tx_hex) in trailing_triggered {
                        info!(
                            "[TRAILING STOP] Triggered trailing stop #{} for pair [{}...] at price {}/{}",
                            trail_id, &pair[..pair.len().min(12)], price_num, price_den,
                        );
                        trailing_broadcasts.push((trail_id, signed_tx_hex));
                    }
                }
            }
            // Locks released; now broadcast triggered TXs via RPC

            // Broadcast stop order TXs
            for (stop_id, signed_tx_json) in &stop_broadcasts {
                match serde_json::from_str::<serde_json::Value>(signed_tx_json) {
                    Ok(tx_json) => {
                        match rpc_lock.submit_transaction(tx_json).await {
                            Ok(result) if result.ok => {
                                let tx_id = result.tx_id.unwrap_or_default();
                                info!("[STOP] Broadcast stop order #{} -> TX {}", stop_id, tx_id);
                                shared_stop_book.lock().await.mark_triggered(*stop_id, Some(tx_id));
                            }
                            Ok(result) => {
                                let err_str = result.error.as_deref().unwrap_or("");
                                let is_orphan = err_str.contains("orphan")
                                    || err_str.contains("missing")
                                    || err_str.contains("not found")
                                    || err_str.contains("MissingTxOut");
                                if is_orphan {
                                    // Fee UTXO was consumed — retry up to MAX_BROADCAST_RETRIES
                                    let mut sb = shared_stop_book.lock().await;
                                    let attempts = sb.increment_broadcast_attempts(*stop_id).unwrap_or(0);
                                    if attempts >= crate::matcher::stop_book::MAX_BROADCAST_RETRIES {
                                        warn!(
                                            "[STOP] Stop order #{} exhausted {} retries (fee UTXO stale: {}). Giving up.",
                                            stop_id, attempts, err_str,
                                        );
                                        sb.mark_triggered(*stop_id, None);
                                    } else {
                                        warn!(
                                            "[STOP] Stop order #{} broadcast failed (attempt {}/{}): {} — will retry",
                                            stop_id, attempts, crate::matcher::stop_book::MAX_BROADCAST_RETRIES, err_str,
                                        );
                                    }
                                } else {
                                    // Non-recoverable rejection (double-spend, bad signature, etc.)
                                    warn!("[STOP] Broadcast failed for stop order #{}: {:?}", stop_id, result.error);
                                    shared_stop_book.lock().await.mark_triggered(*stop_id, None);
                                }
                            }
                            Err(e) => {
                                warn!("[STOP] RPC error broadcasting stop order #{}: {}", stop_id, e);
                                // Don't mark triggered on RPC errors so it retries next cycle
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[STOP] Invalid TX JSON for stop order #{}: {}", stop_id, e);
                        shared_stop_book.lock().await.mark_triggered(*stop_id, None);
                    }
                }
            }

            // Broadcast trailing stop TXs
            for (trail_id, signed_tx_hex) in &trailing_broadcasts {
                match serde_json::from_str::<serde_json::Value>(signed_tx_hex) {
                    Ok(tx_json) => {
                        match rpc_lock.submit_transaction(tx_json).await {
                            Ok(result) if result.ok => {
                                info!("[TRAILING STOP] Broadcast trailing stop #{} -> TX {}", trail_id, result.tx_id.unwrap_or_default());
                            }
                            Ok(result) => {
                                warn!("[TRAILING STOP] Broadcast failed for trailing stop #{}: {:?}", trail_id, result.error);
                            }
                            Err(e) => {
                                warn!("[TRAILING STOP] RPC error for trailing stop #{}: {}", trail_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[TRAILING STOP] Invalid TX JSON for trailing stop #{}: {}", trail_id, e);
                    }
                }
            }

            // Cleanup expired/triggered stop orders
            let cleaned = shared_stop_book.lock().await.cleanup(now_unix);
            if cleaned > 0 {
                info!("[STOP] Cleaned up {} expired/triggered stop order(s)", cleaned);
            }
        }

        // Expire v14 GTD/IOC/FOK orders (every cycle)
        // Runs every cycle (not every 10) so that IOC/FOK orders with short
        // expiry_daa (~current_daa + 10 blocks) are expired promptly. The
        // get_current_daa RPC call is lightweight (single getBlockDagInfo).
        // Without per-cycle expiry, a CLI crash between deploy and cancel
        // leaves IOC/FOK orders sitting on the book as effectively GTC
        // until the next 10-cycle check.
        {
            if let Some(current_daa) = get_current_daa(&rpc_lock).await {
                let expired_orders = {
                    let mut ob = order_book.lock().await;
                    ob.remove_expired(current_daa)
                };
                if !expired_orders.is_empty() {
                    let prefix = config.address.split(':').next().unwrap_or("kaspa");
                    let count = expire_orders(&rpc_lock, &expired_orders, current_daa, prefix).await;
                    if count > 0 {
                        info!("[EXPIRE] Expired {} order(s) at DAA score {}", count, current_daa);
                    }
                }
            }
        }

        drop(rpc_lock);

        // H3: save every 2 cycles (~10s at default 5s interval) to reduce crash-loss window.
        if cycle % 2 == 0 {
            let ob = order_book.lock().await;
            if let Err(e) = persistence::save_order_book(orderbook_path, &ob) {
                warn!("Failed to save order book: {}", e);
            }
            {
                let sb = shared_stop_book.lock().await;
                if !sb.is_empty() {
                    if let Err(e) = crate::matcher::stop_book::save_stop_orders(&stop_orders_path, &sb) {
                        warn!("Failed to save stop orders: {}", e);
                    }
                }
            }
            {
                let tb = shared_trailing_stop_book.lock().await;
                if !tb.is_empty() {
                    if let Err(e) = tb.save_full(&trailing_stops_path) {
                        warn!("Failed to save trailing stops: {}", e);
                    }
                }
            }
            {
                let ib = shared_ifd_book.lock().await;
                if !ib.is_empty() {
                    if let Err(e) = crate::matcher::ifd::save_ifd_rules(&ifd_path, &ib) {
                        warn!("Failed to save IFD rules: {}", e);
                    }
                }
            }
            // A-5: Always save books (even when empty) to clear ghost orders on restart.
            {
                let pb = shared_perp_book.lock().await;
                if let Err(e) = persistence::save_perp_book(&perp_book_path, &pb) {
                    warn!("Failed to save perp book: {}", e);
                }
            }
            {
                let lb = shared_lending_book.lock().await;
                if let Err(e) = persistence::save_lending_book(&lending_book_path, &lb) {
                    warn!("Failed to save lending book: {}", e);
                }
            }
            {
                let pred = shared_prediction_book.lock().await;
                if let Err(e) = persistence::save_prediction_book(&prediction_book_path, &pred) {
                    warn!("Failed to save prediction book: {}", e);
                }
            }
            {
                let swab = shared_swap_book.lock().await;
                if let Err(e) = persistence::save_swap_book(&swap_book_path, &swab) {
                    warn!("Failed to save swap book: {}", e);
                }
            }
            if let Some(ref h) = last_seen_hash {
                let json = serde_json::json!({ "last_seen_hash": h });
                let _ = std::fs::write(&scan_state_path, json.to_string());
            }
        }

        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            info!("[SHUTDOWN] Scan cycle {} complete -- TX drain finished, persisting state...", cycle);
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
    }

    // Final save (A-5: always save, even if empty)
    let ob = order_book.lock().await;
    if let Err(e) = persistence::save_order_book(orderbook_path, &ob) {
        warn!("Failed to save order book on shutdown: {}", e);
    }
    {
        let sb = shared_stop_book.lock().await;
        if !sb.is_empty() {
            if let Err(e) = crate::matcher::stop_book::save_stop_orders(&stop_orders_path, &sb) {
                warn!("Failed to save stop orders on shutdown: {}", e);
            }
        }
    }
    {
        let tb = shared_trailing_stop_book.lock().await;
        if !tb.is_empty() {
            if let Err(e) = tb.save_full(&trailing_stops_path) {
                warn!("Failed to save trailing stops on shutdown: {}", e);
            }
        }
    }
    {
        let ib = shared_ifd_book.lock().await;
        if !ib.is_empty() {
            if let Err(e) = crate::matcher::ifd::save_ifd_rules(&ifd_path, &ib) {
                warn!("Failed to save IFD rules on shutdown: {}", e);
            }
        }
    }
    {
        let pb = shared_perp_book.lock().await;
        if let Err(e) = persistence::save_perp_book(&perp_book_path, &pb) {
            warn!("Failed to save perp book on shutdown: {}", e);
        }
    }
    {
        let lb = shared_lending_book.lock().await;
        if let Err(e) = persistence::save_lending_book(&lending_book_path, &lb) {
            warn!("Failed to save lending book on shutdown: {}", e);
        }
    }
    {
        let pred = shared_prediction_book.lock().await;
        if let Err(e) = persistence::save_prediction_book(&prediction_book_path, &pred) {
            warn!("Failed to save prediction book on shutdown: {}", e);
        }
    }
    {
        let swab = shared_swap_book.lock().await;
        if let Err(e) = persistence::save_swap_book(&swap_book_path, &swab) {
            warn!("Failed to save swap book on shutdown: {}", e);
        }
    }
    if let Some(ref h) = last_seen_hash {
        let json = serde_json::json!({ "last_seen_hash": h });
        let _ = std::fs::write(&scan_state_path, json.to_string());
    }
    info!("[SHUTDOWN] Complete. All books saved (spot, perp, lending, prediction, swap).");
}

// Dry-run Mode

#[allow(deprecated)]
pub async fn run_dry_run(
    rpc: Arc<Mutex<RpcClient>>,
    order_book: Arc<Mutex<OrderBook>>,
    config: &AppConfig,
) {
    info!("======================================================================");
    info!("KOB MATCHER BOT -- DRY RUN");
    info!("======================================================================");

    let rpc_lock = rpc.lock().await;
    let utxos = match rpc_lock
        .get_spendable_utxos(&config.address, Some(0))
        .await
    {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to get UTXOs: {}", e);
            return;
        }
    };
    drop(rpc_lock);

    info!("Wallet UTXOs: {}", utxos.len());
    let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
    info!(
        "Total balance: {} sompi ({:.8} KAS)",
        total,
        total as f64 / 1e8
    );

    let usable: Vec<_> = utxos
        .iter()
        .filter(|u| u.utxo_entry.amount >= MIN_UTXO_VALUE)
        .collect();
    info!("Usable UTXOs (>= {}): {}", MIN_UTXO_VALUE, usable.len());
    for (i, u) in usable.iter().enumerate() {
        info!(
            "  [{}] {} sompi  {}...:{}",
            i,
            u.utxo_entry.amount,
            &u.outpoint.transaction_id[..16.min(u.outpoint.transaction_id.len())],
            u.outpoint.index
        );
    }

    let ob = order_book.lock().await;
    let stats = ob.stats();
    info!("");
    info!("Order book:");
    info!("  Pairs:  {}", stats.pairs);
    info!("  Bids:   {}", stats.total_bids);
    info!("  Asks:   {}", stats.total_asks);
    for ps in &stats.by_pair {
        info!("    {}...: {} bids, {} asks", ps.token_cov_id, ps.bids, ps.asks);
    }

    let all_groups = matching::match_book_direct(&ob, false, None, u64::MAX);
    info!("  Same-pair batch groups: {}", all_groups.len());

    for (i, g) in all_groups.iter().enumerate() {
        info!(
            "  [{}] kind={:?} sells={} buys={} surplus={}",
            i,
            g.kind,
            g.sells.len(),
            g.buys.len(),
            g.total_surplus,
        );
        for (j, sell) in g.sells.iter().enumerate() {
            info!(
                "    sell[{}]: [{}...] {} tokens @ {}/{}",
                j,
                &sell.token_cov_id[..sell.token_cov_id.len().min(12)],
                sell.value,
                sell.price_num,
                sell.price_den,
            );
        }
        for (j, buy) in g.buys.iter().enumerate() {
            info!(
                "    buy[{}]: [{}...] {} KAS @ {}/{}",
                j,
                &buy.token_cov_id[..buy.token_cov_id.len().min(12)],
                buy.value,
                buy.price_num,
                buy.price_den,
            );
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use kob_core::RECEIPT_VALUE;

    #[test]
    fn spent_tracker_basic() {
        let mut tracker = SpentTracker::new();
        assert!(!tracker.is_spent("abc:0"));
        tracker.mark_spent("abc:0");
        assert!(tracker.is_spent("abc:0"));
        assert!(!tracker.is_spent("def:1"));
    }

    #[test]
    fn spent_tracker_clear() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("abc:0");
        tracker.mark_spent("def:1");
        assert_eq!(tracker.spent.len(), 2);
        tracker.clear();
        assert!(tracker.spent.is_empty());
        assert!(!tracker.is_spent("abc:0"));
    }

    #[test]
    fn spent_tracker_dedup() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("abc:0");
        tracker.mark_spent("abc:0");
        assert_eq!(tracker.spent.len(), 1);
    }

    /// F1 regression: reproduces the Phase 3 starvation race in a unit
    /// test that does NOT require the full match cycle plumbing.
    ///
    /// The race (pre-F1): Phase 1 runs first, its planner fails on a
    /// group, and `mark_failed` puts the group's outpoints into the
    /// shared `SpentTracker`. Phase 3 then builds its exclusion set
    /// from the SAME tracker and filters the just-poisoned outpoints
    /// out of `match_swap_routes`, starving any cross-pair swap route
    /// whose `buy_source` was inside the failing Phase 1 group.
    ///
    /// The fix (F1): Phase 3 runs FIRST, so its exclusion set is
    /// snapshotted before any `mark_failed` from the current cycle's
    /// Phase 1 execution can land. This test asserts the snapshot
    /// semantics by mirroring the exact code used by the match loop
    /// to build `swap_spent_keys` — a pre-Phase-1 snapshot must NOT
    /// observe a later `mark_failed` call.
    #[test]
    fn test_phase3_runs_first_survives_phase1_cooldown() {
        // Buy outpoint that, under the old ordering, Phase 1 would
        // drag into a failing SellSweep and mark_failed — starving
        // Phase 3. Under F1 the snapshot is taken first, so the
        // subsequent mark_failed does NOT appear in the snapshot set.
        let buy_source_op = "08de95db8db38eeb00000000000000000000000000000000000000000000:0";
        let mut tracker = SpentTracker::with_cooldown(30);

        // (Simulate a prior-cycle legitimate cooldown entry so we also
        // verify that pre-existing failed entries ARE observed — only
        // same-cycle fresh poison is meant to be excluded.)
        tracker.mark_failed("deadbeef:0");

        // Cycle entry: Phase 3 builds its snapshot BEFORE Phase 1.
        // Mirror the exact construction at the Phase 3 call site:
        //   let mut swap_spent_keys = spent_tracker.spent_keys();
        //   for (k, when) in &spent_tracker.failed { if cooldown-live
        //       { swap_spent_keys.insert(k); } }
        let mut phase3_snapshot = tracker.spent_keys();
        for (key, when) in &tracker.failed {
            if when.elapsed().as_secs() < tracker.cooldown_secs {
                phase3_snapshot.insert(key.clone());
            }
        }

        // Prior-cycle cooldown is visible (intended).
        assert!(phase3_snapshot.contains("deadbeef:0"));
        // The fresh outpoint is NOT yet in the snapshot — Phase 1
        // hasn't run yet and so cannot have poisoned it.
        assert!(!phase3_snapshot.contains(buy_source_op));

        // Now simulate Phase 1 executing AFTER Phase 3's snapshot was
        // taken: its failing SellSweep poisons the shared tracker.
        tracker.mark_failed(buy_source_op);

        // The live tracker now reflects the poison …
        assert!(tracker.is_failed(buy_source_op));
        // … but the Phase 3 snapshot (already computed above) does
        // NOT — this is the property F1 relies on. A subsequent call
        // to `match_swap_routes(&order_book, &swab, Some(&phase3_snapshot), ...)`
        // would still treat `buy_source_op` as an eligible candidate.
        assert!(!phase3_snapshot.contains(buy_source_op));

        // If Phase 3 had run AFTER Phase 1 (the old ordering), the
        // snapshot built at that later point would include the fresh
        // poison — the starvation path. Assert this contrapositive so
        // a future refactor that re-reverses the order re-trips the
        // test.
        let mut old_order_keys = tracker.spent_keys();
        for (key, when) in &tracker.failed {
            if when.elapsed().as_secs() < tracker.cooldown_secs {
                old_order_keys.insert(key.clone());
            }
        }
        assert!(
            old_order_keys.contains(buy_source_op),
            "If Phase 3's exclusion set were rebuilt AFTER Phase 1 \
             mark_failed, it would starve the cross-pair swap — the \
             exact race F1 prevents.",
        );
    }

    // L1 Scanner Integration Tests

    use crate::matcher::order_book::BookOrder;
    use crate::matcher::scanner::{TxInputData, TxOutputData};

    /// Build a mock deploy TX with P2SH + payload for a KOB order.
    fn make_deploy_tx(tx_id: &str, rs: &[u8], p2sh_value: u64) -> TransactionData {
        let hash = kob_core::blake2b_256(rs);
        // P2SH script
        let mut p2sh_script = Vec::with_capacity(35);
        p2sh_script.push(0xaa);
        p2sh_script.push(0x20);
        p2sh_script.extend_from_slice(&hash);
        p2sh_script.push(0x87);

        TransactionData {
            tx_id: tx_id.to_string(),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "0".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![
                TxOutputData {
                    value: p2sh_value,
                    script_version: 0,
                    script: p2sh_script,
                    covenant_id: None,
                },
            ],
            payload: kob_core::contract::build_order_payload(rs, false),
        }
    }

    #[test]
    fn process_block_txs_adds_buy_order() {
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 0, 0, 0,).unwrap();

        let tx_id = "a".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 10_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        let (added, removed) = process_block_txs(&[deploy_tx], &mut ob, &scanner);
        assert_eq!(added, 1);
        assert_eq!(removed, 0);
        assert_eq!(ob.stats().total_bids, 1);
        assert_eq!(ob.stats().total_asks, 0);
    }

    #[test]
    fn process_block_txs_adds_sell_order() {
        // H-3: Sell RSes do not embed token_cov_id (parsed as [0;32]).
        // process_block_txs skips such orders to prevent ghost entries.
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            5, 3, 2_000_000, &ohash, &sspkh, 0, 0, 0,).unwrap();

        let tx_id = "b".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 5_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        let (added, removed) = process_block_txs(&[deploy_tx], &mut ob, &scanner);
        // Sell order has zero token_cov_id -> skipped (H-3 fix)
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
        assert_eq!(ob.stats().total_asks, 0);
    }

    #[test]
    fn process_block_txs_removes_spent_order() {
        // First, add an order
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 0, 0, 0,).unwrap();

        let tx_id = "a".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 10_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        process_block_txs(&[deploy_tx], &mut ob, &scanner);
        assert_eq!(ob.stats().total_bids, 1);

        // Now create a TX that spends it
        let spend_tx = TransactionData {
            tx_id: "c".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: tx_id,
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![],
            payload: vec![],
        };

        let (added, removed) = process_block_txs(&[spend_tx], &mut ob, &scanner);
        assert_eq!(added, 0);
        assert_eq!(removed, 1);
        assert_eq!(ob.stats().total_bids, 0);
    }

    #[test]
    fn process_block_txs_skips_cpend_order() {
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        // cancel_pending = 1
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 0, 1, 0,).unwrap();

        let tx_id = "d".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 10_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        let (added, _removed) = process_block_txs(&[deploy_tx], &mut ob, &scanner);
        assert_eq!(added, 0, "cancel_pending orders should be skipped");
        assert_eq!(ob.stats().total_bids, 0);
    }

    #[test]
    fn process_block_txs_mixed_deploy_and_spend() {
        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        // Deploy a buy order
        let rs1 = kob_core::contract::build_buy_redeem_script(
            &[0xAA; 32], 3, 2, 1_000_000, &[0xBB; 32], &[0xCC; 32], 0, 0, 0,).unwrap();
        let deploy1 = make_deploy_tx(&"a".repeat(64), &rs1, 10_000_000);
        process_block_txs(&[deploy1], &mut ob, &scanner);
        assert_eq!(ob.stats().total_bids, 1);

        // In the same block: deploy a sell order AND spend the buy order
        let rs2 = kob_core::contract::build_sell_redeem_script(
            5, 3, 2_000_000, &[0xDD; 32], &[0xEE; 32], 0, 0, 0,).unwrap();
        let deploy2 = make_deploy_tx(&"b".repeat(64), &rs2, 5_000_000);

        let spend_tx = TransactionData {
            tx_id: "c".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "a".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![],
            payload: vec![],
        };

        let (added, removed) = process_block_txs(&[spend_tx, deploy2], &mut ob, &scanner);
        assert_eq!(removed, 1, "Buy order should be removed");
        // H-3: sell RS has no token_cov_id (zero) -> skipped by scanner
        assert_eq!(added, 0, "Sell order with zero token_cov_id must be skipped");
        assert_eq!(ob.stats().total_bids, 0);
        assert_eq!(ob.stats().total_asks, 0);
    }

    #[test]
    fn parse_block_notification_empty() {
        let json = serde_json::json!({
            "block": {
                "transactions": []
            }
        });
        let txs = parse_block_notification(&json);
        assert!(txs.is_empty());
    }

    #[test]
    fn parse_block_notification_no_block() {
        let json = serde_json::json!({});
        let txs = parse_block_notification(&json);
        assert!(txs.is_empty());
    }


    #[test]
    fn match_result_partial_types() {
        let mr_buy = MatchResult {
            match_tx_id: "abc".to_string(),
            match_type: MatchType::PartialBuy,
            seller_kas: 0,
            buyer_tokens: 5_000_000,
            receipt_tx_id: "abc".to_string(),
            receipt_idx: 2,
            receipt_value: RECEIPT_VALUE,
            token_cov_id: "aa".repeat(32),
            price_num: 1,
            price_den: 2,
        };
        assert_eq!(mr_buy.match_type, MatchType::PartialBuy);
        assert_eq!(mr_buy.receipt_idx, 2);

        let mr_sell = MatchResult {
            match_tx_id: "def".to_string(),
            match_type: MatchType::PartialSell,
            seller_kas: 5_000_000,
            buyer_tokens: 0,
            receipt_tx_id: "def".to_string(),
            receipt_idx: 2,
            receipt_value: RECEIPT_VALUE,
            token_cov_id: "aa".repeat(32),
            price_num: 1,
            price_den: 2,
        };
        assert_eq!(mr_sell.match_type, MatchType::PartialSell);
        assert_eq!(mr_sell.seller_kas, 5_000_000);
    }

    // H-3: Sell orders with zero token_cov_id are skipped in process_block_txs
    #[test]
    fn process_block_txs_skips_sell_with_zero_token_cov_id() {
        use crate::matcher::scanner::{BlockScanner, TransactionData, TxInputData, TxOutputData};

        // Build a real sell v13 RS (token_cov_id not in RS -> parsed as [0;32])
        let pnum: u64 = 5;
        let pden: u64 = 3;
        let mfill: u64 = 1_000_000;
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            pnum, pden, mfill, &ohash, &sspkh, 0, 0, 0,).unwrap();
        let _hash = kob_core::blake2b_256(&rs);
        let p2sh_spk = kob_core::build_p2sh(&rs);

        let tx = TransactionData {
            tx_id: "a".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "b".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: p2sh_spk.script().to_vec(),
                covenant_id: None,
            }],
            payload: kob_core::contract::build_order_payload(&rs, false),
        };

        // Verify the RS parses and returns token_cov_id = [0;32]
        let scanner = BlockScanner::new();
        let scan_result = scanner.scan_tx(&tx);
        assert!(scan_result.is_some(), "should detect sell deploy TX");
        let (parsed, _, _) = scan_result.unwrap();
        assert_eq!(parsed.token_cov_id, [0u8; 32], "sell RS has no token_cov_id");

        // process_block_txs should skip this sell order
        let mut ob = OrderBook::new();
        let (added, removed) = process_block_txs(&[tx], &mut ob, &scanner);
        assert_eq!(added, 0, "sell order with zero token_cov_id must be skipped");
        assert_eq!(removed, 0);
        assert_eq!(ob.stats().total_asks, 0, "order book must remain empty");
    }

    #[test]
    fn token_unit_sigscript_is_push_data_token_rs() {
        // Verify token_unit sigscript = pushData(TOKEN_RS) (no signature)
        let ss = kob_core::push_data(kob_core::TOKEN_RS);
        // TOKEN_RS is 7 bytes, so pushData = [7] + [7 bytes]
        assert_eq!(ss.len(), 8, "pushData(TOKEN_RS) = 1 length byte + 7 body bytes");
        assert_eq!(ss[0], 7, "length prefix for 7-byte TOKEN_RS");
        assert_eq!(&ss[1..], kob_core::TOKEN_RS);
    }

    // H-5: SpentTracker failure cooldown tests

    #[test]
    fn spent_tracker_mark_failed_basic() {
        let mut tracker = SpentTracker::with_cooldown(60);
        assert!(!tracker.is_failed("abc:0"));
        tracker.mark_failed("abc:0");
        assert!(tracker.is_failed("abc:0"));
        // is_spent should also return true for failed outpoints
        assert!(tracker.is_spent("abc:0"));
    }

    #[test]
    fn spent_tracker_failed_does_not_affect_unrelated() {
        let mut tracker = SpentTracker::with_cooldown(60);
        tracker.mark_failed("abc:0");
        assert!(!tracker.is_failed("def:1"));
        assert!(!tracker.is_spent("def:1"));
    }

    #[test]
    fn spent_tracker_expire_failed_removes_expired() {
        // Use 0-second cooldown so entries expire immediately
        let mut tracker = SpentTracker::with_cooldown(0);
        tracker.mark_failed("abc:0");
        // With 0s cooldown, the entry should already be expired
        tracker.expire_failed();
        assert!(tracker.failed.is_empty(), "expired entries should be removed");
    }

    #[test]
    fn spent_tracker_clear_removes_failed() {
        let mut tracker = SpentTracker::with_cooldown(60);
        tracker.mark_failed("abc:0");
        tracker.mark_failed("def:1");
        assert_eq!(tracker.failed.len(), 2);
        tracker.clear();
        assert!(tracker.failed.is_empty());
        assert!(!tracker.is_failed("abc:0"));
    }

    #[test]
    fn spent_tracker_failed_with_zero_cooldown_not_blocked() {
        let mut tracker = SpentTracker::with_cooldown(0);
        tracker.mark_failed("abc:0");
        // 0s cooldown means the entry is immediately expired
        assert!(!tracker.is_failed("abc:0"));
    }

    #[test]
    fn spent_tracker_failed_dedup() {
        let mut tracker = SpentTracker::with_cooldown(60);
        tracker.mark_failed("abc:0");
        tracker.mark_failed("abc:0");
        assert_eq!(tracker.failed.len(), 1);
    }

    #[test]
    fn spent_tracker_with_cooldown_constructor() {
        let tracker = SpentTracker::with_cooldown(120);
        assert_eq!(tracker.cooldown_secs, 120);
        assert!(tracker.spent.is_empty());
        assert!(tracker.failed.is_empty());
    }

    // Receipt consumption in continuous mode

    #[test]
    fn match_result_carries_price_for_receipt_consumption() {
        // Verify that MatchResult stores price_num/price_den needed to
        // reconstruct the receipt redeemScript during consumption.
        let mr = MatchResult {
            match_tx_id: "abc".to_string(),
            match_type: MatchType::Full,
            seller_kas: 10_000_000,
            buyer_tokens: 5_000_000,
            receipt_tx_id: "abc".to_string(),
            receipt_idx: 2,
            receipt_value: RECEIPT_VALUE,
            token_cov_id: "aa".repeat(32),
            price_num: 3,
            price_den: 7,
        };
        assert_eq!(mr.price_num, 3);
        assert_eq!(mr.price_den, 7);
        // A valid receipt_idx means consumption should be attempted
        assert_ne!(mr.receipt_idx, u32::MAX);
    }

    #[test]
    fn receipt_consumption_skipped_for_sentinel_idx() {
        // When receipt_idx == u32::MAX (sentinel from cross-pair with no receipt),
        // the continuous mode loop must skip consumption.
        let mr = MatchResult {
            match_tx_id: "tx99".to_string(),
            match_type: MatchType::Full,
            seller_kas: 10_000_000,
            buyer_tokens: 5_000_000,
            receipt_tx_id: "tx99".to_string(),
            receipt_idx: u32::MAX,
            receipt_value: 0,
            token_cov_id: "bb".repeat(32),
            price_num: 1,
            price_den: 1,
        };
        // The M-4 sentinel: receipt_idx == u32::MAX means no receipt was produced
        assert_eq!(mr.receipt_idx, u32::MAX, "sentinel must trigger skip");
    }

    // M-6: SpentTracker age-based pruning

    #[test]
    fn m6_spent_tracker_prune_removes_old_entries() {
        let mut tracker = SpentTracker::new();
        // Mark some outpoints as spent
        tracker.mark_spent("aaa:0");
        tracker.mark_spent("bbb:1");
        assert_eq!(tracker.spent.len(), 2);

        // Prune with a very large age -- nothing should be removed
        tracker.prune_spent_by_age(9999);
        assert_eq!(tracker.spent.len(), 2, "no entries should be pruned with large age");

        // Prune with age=0 -- everything should be removed
        tracker.prune_spent_by_age(0);
        assert_eq!(tracker.spent.len(), 0, "all entries should be pruned with age=0");
    }

    #[test]
    fn m6_spent_tracker_has_timestamps() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("tx1:0");
        // Verify the entry has a timestamp (HashMap<String, SpentEntry>)
        let entry = tracker.spent.get("tx1:0");
        assert!(entry.is_some(), "spent entry must have a timestamp");
        // The elapsed time should be very small (we just inserted it)
        assert!(entry.unwrap().when.elapsed().as_secs() < 2, "timestamp should be recent");
    }

    #[test]
    fn m6_spent_tracker_is_spent_works_with_hashmap() {
        let mut tracker = SpentTracker::new();
        assert!(!tracker.is_spent("tx1:0"), "should not be spent initially");
        tracker.mark_spent("tx1:0");
        assert!(tracker.is_spent("tx1:0"), "should be spent after marking");
        tracker.prune_spent_by_age(0);
        assert!(!tracker.is_spent("tx1:0"), "should not be spent after pruning");
    }

    // Mempool-aware prune: unit tests for prune_spent_with_probe

    /// Deterministic in-memory mempool probe for tests.
    struct FakeMempool {
        txids_in_mempool: HashSet<String>,
    }

    impl FakeMempool {
        fn new<I: IntoIterator<Item = String>>(txids: I) -> Self {
            Self {
                txids_in_mempool: txids.into_iter().collect(),
            }
        }
    }

    impl MempoolProbe for FakeMempool {
        fn is_in_mempool<'a>(
            &'a self,
            txid: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            let present = self.txids_in_mempool.contains(txid);
            Box::pin(async move { present })
        }
    }

    #[tokio::test]
    async fn mempool_prune_skips_entries_whose_txid_is_in_mempool() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("op_alive:0");
        tracker.mark_spent("op_alive:1");
        tracker.mark_submitted(
            "txid_alive",
            &["op_alive:0".to_string(), "op_alive:1".to_string()],
        );

        // Age-threshold = 0 forces both entries to be considered aged.
        let probe = FakeMempool::new(std::iter::once("txid_alive".to_string()));
        tracker.prune_spent_with_probe(0, &probe).await;

        assert_eq!(
            tracker.spent.len(),
            2,
            "entries whose submit_txid is in mempool must be retained",
        );
    }

    #[tokio::test]
    async fn mempool_prune_removes_entries_whose_txid_is_absent() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("op_dead:0");
        tracker.mark_submitted("txid_dead", &["op_dead:0".to_string()]);

        // Empty mempool: no txid is in mempool.
        let probe = FakeMempool::new(std::iter::empty::<String>());
        tracker.prune_spent_with_probe(0, &probe).await;

        assert!(
            tracker.spent.is_empty(),
            "entries whose submit_txid is absent from mempool must be pruned",
        );
    }

    #[tokio::test]
    async fn mempool_prune_handles_empty_submit_txid() {
        // Entries with an empty submit_txid (e.g. from an old-style call
        // site that never called mark_submitted) should be pruned purely
        // by age, with no mempool check.
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("op_unknown:0");
        // No mark_submitted -> submit_txid stays empty.

        let probe = FakeMempool::new(std::iter::empty::<String>());
        tracker.prune_spent_with_probe(0, &probe).await;

        assert!(
            tracker.spent.is_empty(),
            "entries with empty submit_txid should be pruned by age alone",
        );
    }

    #[tokio::test]
    async fn mempool_prune_retains_recent_entries() {
        // Entries younger than max_age must be retained regardless of
        // mempool status (we never probe them).
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("op_young:0");
        tracker.mark_submitted("txid_young", &["op_young:0".to_string()]);

        // Max age = 999999 -> nothing qualifies as aged.
        let probe = FakeMempool::new(std::iter::empty::<String>());
        tracker.prune_spent_with_probe(999_999, &probe).await;

        assert_eq!(
            tracker.spent.len(),
            1,
            "young entries must never be pruned",
        );
    }

    #[tokio::test]
    async fn mempool_prune_hard_cap_evicts_even_mempool_retained() {
        // Defense against a misbehaving mempool RPC that perpetually says
        // "in mempool": entries older than HARD_MAX_AGE must be evicted.
        let mut tracker = SpentTracker::new();

        // Build a manual SpentEntry that is artificially old (beyond the
        // hard cap). We can't actually wait 2 hours in a unit test, so we
        // backdate the Instant.
        let long_ago = Instant::now()
            .checked_sub(std::time::Duration::from_secs(
                SPENT_PRUNE_HARD_MAX_AGE_SECS + 60,
            ))
            .expect("should be able to backdate");
        tracker.spent.insert(
            "op_ancient:0".to_string(),
            SpentEntry {
                when: long_ago,
                submit_txid: "txid_liar".to_string(),
            },
        );

        // Probe lies: says the txid is still in mempool.
        let probe = FakeMempool::new(std::iter::once("txid_liar".to_string()));
        tracker.prune_spent_with_probe(0, &probe).await;

        assert!(
            tracker.spent.is_empty(),
            "hard cap must override mempool-retention",
        );
    }

    #[tokio::test]
    async fn mempool_prune_mixed_entries() {
        // A mix: one txid in mempool (retain), one absent (prune), one
        // with empty txid (prune by age).
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("op_a:0");
        tracker.mark_spent("op_b:0");
        tracker.mark_spent("op_c:0"); // will have empty txid
        tracker.mark_submitted("tx_alive", &["op_a:0".to_string()]);
        tracker.mark_submitted("tx_dead", &["op_b:0".to_string()]);

        let probe = FakeMempool::new(std::iter::once("tx_alive".to_string()));
        tracker.prune_spent_with_probe(0, &probe).await;

        assert!(tracker.is_spent("op_a:0"), "op_a (tx_alive) must be retained");
        assert!(!tracker.is_spent("op_b:0"), "op_b (tx_dead) must be pruned");
        assert!(!tracker.is_spent("op_c:0"), "op_c (empty txid) must be pruned by age");
    }

    #[tokio::test]
    async fn mark_submitted_populates_txid() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("op1:0");
        assert_eq!(tracker.spent.get("op1:0").unwrap().submit_txid, "");
        tracker.mark_submitted("my_tx", &["op1:0".to_string()]);
        assert_eq!(
            tracker.spent.get("op1:0").unwrap().submit_txid,
            "my_tx",
        );
    }

    #[tokio::test]
    async fn mark_submitted_inserts_missing_keys() {
        let mut tracker = SpentTracker::new();
        // Defensive path: mark_submitted for a key that was never
        // mark_spent'd. Should still insert the entry.
        tracker.mark_submitted("my_tx", &["op1:0".to_string()]);
        assert!(tracker.is_spent("op1:0"));
        assert_eq!(
            tracker.spent.get("op1:0").unwrap().submit_txid,
            "my_tx",
        );
    }

    // M-7: Scanner order dedup

    #[test]
    fn m7_process_block_txs_dedup_prevents_double_add() {
        use crate::matcher::scanner::{BlockScanner, TransactionData, TxInputData, TxOutputData};

        // Build a real buy v8 RS
        let tcid = [0xAA; 32];
        let pnum: u64 = 1;
        let pden: u64 = 2;
        let mfill: u64 = 1_000_000;
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, pnum, pden, mfill, &ohash, &bspkh, 0, 0, 0,).unwrap();
        let p2sh_spk = kob_core::build_p2sh(&rs);

        let tx = TransactionData {
            tx_id: "d".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "e".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: p2sh_spk.script().to_vec(),
                covenant_id: None,
            }],
            payload: kob_core::contract::build_order_payload(&rs, false),
        };

        let scanner = BlockScanner::new();
        let mut ob = OrderBook::new();

        // First pass: order should be added
        let (added1, _) = process_block_txs(&[tx.clone()], &mut ob, &scanner);
        assert_eq!(added1, 1, "first pass should add the order");
        assert_eq!(ob.stats().total_bids, 1);

        // Second pass (duplicate notification): order should be skipped
        let (added2, _) = process_block_txs(&[tx.clone()], &mut ob, &scanner);
        assert_eq!(added2, 0, "duplicate order must be skipped (M-7)");
        assert_eq!(ob.stats().total_bids, 1, "order book must still have exactly 1 bid");
    }

    #[test]
    fn m7_order_book_contains_outpoint() {
        let mut ob = OrderBook::new();
        let tcid = "aa".repeat(32);
        let outpoint = format!("{}:0", "b".repeat(64));

        assert!(!ob.contains_outpoint(&outpoint), "should not contain outpoint initially");

        ob.add_buy_order(BookOrder {
            tx_id: "b".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: tcid.clone(),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "dd".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None, discovered_daa: 0,
        });

        assert!(ob.contains_outpoint(&outpoint), "should contain outpoint after add");

        ob.remove_order(&outpoint);
        assert!(!ob.contains_outpoint(&outpoint), "should not contain outpoint after remove");
    }

    // Indexer filter: un-matchable orders (missing counterparty_spk) are
    // skipped at discovery so they never enter the book. This prevents
    // stale v0-style deploys from recycling through per-offender cooldown.
    #[test]
    fn indexer_filter_skips_order_without_counterparty_spk() {
        let make = |spk: Option<String>| crate::matcher::order_book::BookOrder {
            tx_id: "a".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: "aa".repeat(32),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "dd".repeat(32),
            counterparty_spk: spk,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            ifd_order_b_rs_hex: None,
            oco_path: None,
            oco_partner_key: None,
            discovered_daa: 0,
        };
        assert!(skip_if_no_counterparty_spk(&make(None)),
            "None counterparty_spk must be skipped");
        assert!(skip_if_no_counterparty_spk(&make(Some(String::new()))),
            "empty counterparty_spk must be skipped");
        assert!(!skip_if_no_counterparty_spk(&make(Some("deadbeef".into()))),
            "populated counterparty_spk must pass");
    }

    // Trade Bridge Tests (record_trade -> SharedState)

    #[tokio::test]
    async fn record_trade_populates_trade_log_and_candles() {
        use crate::matcher::api::SharedState;
        use crate::matcher::candle::Interval;
        use crate::matcher::order_book::OrderBook;
        use crate::matcher::stop_book::StopOrderBook;
        use crate::matcher::trailing_stop::TrailingStopBook;

        let (ws_tx, _ws_rx) = tokio::sync::broadcast::channel(100);
        let ob = Arc::new(Mutex::new(OrderBook::new()));
        let sb = Arc::new(Mutex::new(StopOrderBook::new()));
        let tb = Arc::new(Mutex::new(TrailingStopBook::new()));
        let shared: AppState = Arc::new(tokio::sync::RwLock::new(
            SharedState::new(ws_tx, ob, sb, tb),
        ));

        // Initially empty
        {
            let state = shared.read().await;
            assert_eq!(state.trade_log.recent_all(10).len(), 0);
            assert!(state.candles.get_candles("test_token/KAS", Interval::M1, 10).is_empty());
        }

        // Record a trade
        record_trade(
            Some(&shared),
            "abc123def456",
            "test_token_cov_id_hex_64chars_padded_to_be_long_enough_here000",
            100, 1,
            50_000,
            Side::Buy,
            None,
        ).await;

        // Verify trade_log has the entry
        {
            let state = shared.read().await;
            let trades = state.trade_log.recent_all(10);
            assert_eq!(trades.len(), 1);
            assert_eq!(trades[0].txid, "abc123def456");
            assert_eq!(trades[0].price_num, 100);
            assert_eq!(trades[0].price_den, 1);
            assert_eq!(trades[0].quantity, 50_000);
        }

        // Verify candle aggregator has an entry
        {
            let state = shared.read().await;
            let pair_id = &state.trade_log.recent_all(1)[0].pair_id;
            let candles = state.candles.get_candles(pair_id, Interval::M1, 10);
            assert_eq!(candles.len(), 1);
            assert_eq!(candles[0].volume, 50_000);
            assert_eq!(candles[0].trade_count, 1);
        }
    }

    #[tokio::test]
    async fn record_trade_broadcasts_ws_events() {
        use crate::matcher::api::SharedState;
        use crate::matcher::order_book::OrderBook;
        use crate::matcher::stop_book::StopOrderBook;
        use crate::matcher::trailing_stop::TrailingStopBook;

        let (ws_tx, mut ws_rx) = tokio::sync::broadcast::channel(100);
        let ob = Arc::new(Mutex::new(OrderBook::new()));
        let sb = Arc::new(Mutex::new(StopOrderBook::new()));
        let tb = Arc::new(Mutex::new(TrailingStopBook::new()));
        let shared: AppState = Arc::new(tokio::sync::RwLock::new(
            SharedState::new(ws_tx, ob, sb, tb),
        ));

        record_trade(
            Some(&shared),
            "tx_ws_test",
            "token_ws_test_64char_padding_000000000000000000000000000000",
            200, 3,
            10_000,
            Side::Sell,
            None,
        ).await;

        // Should have received WsEvent::Trade + 7 x WsEvent::Kline = 8 events
        // (one Kline per Interval variant: M1, M5, M15, H1, H4, D1, W1)
        let mut trade_count = 0;
        let mut kline_count = 0;
        while let Ok(event) = ws_rx.try_recv() {
            match event {
                WsEvent::Trade { .. } => trade_count += 1,
                WsEvent::Kline { .. } => kline_count += 1,
                _ => {}
            }
        }
        assert_eq!(trade_count, 1, "expected 1 WsEvent::Trade");
        assert_eq!(kline_count, 7, "expected 7 WsEvent::Kline (one per interval)");
    }

    #[tokio::test]
    async fn record_trade_noop_when_shared_state_is_none() {
        // Should not panic when shared_state is None
        record_trade(
            None,
            "tx_noop",
            "token_noop",
            1, 1,
            100,
            Side::Buy,
            None,
        ).await;
    }

    // IFD Integration Tests

    #[test]
    fn ifd_fill_context_creation_from_active_rule() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: hex::encode(&[0xde, 0xad, 0xbe, 0xef]),
            order_b_p2sh: "p2sh_b_target".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "txid_buy:0");

        // Look up by outpoint and create IfdFillContext
        let outpoint = "txid_buy:0";
        let found = book.find_by_a_outpoint(outpoint).unwrap();
        assert_eq!(found.status, IfdStatus::Active);

        let ctx = IfdFillContext {
            rule_id: found.id,
            order_b_rs: hex::decode(&found.order_b_rs_hex).unwrap(),
            order_b_p2sh: found.order_b_p2sh.clone(),
            expiry_daa: found.order_b.expiry_daa(),
        };

        assert_eq!(ctx.rule_id, id);
        assert_eq!(ctx.order_b_rs, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(ctx.order_b_p2sh, "p2sh_b_target");
    }

    #[test]
    fn ifd_fill_context_none_when_no_rule() {
        use crate::matcher::ifd::*;

        let book = IfdBook::new();
        let result = book.find_by_a_outpoint("nonexistent:0");
        assert!(result.is_none());
    }

    #[test]
    fn ifd_fill_context_none_when_pending() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: "deadbeef".to_string(),
            order_b_p2sh: "p2sh_b".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        book.register(rule).unwrap();

        // Pending rules have no outpoint, so lookup by outpoint returns None
        let result = book.find_by_a_outpoint("some_tx:0");
        assert!(result.is_none());
    }

    #[test]
    fn ifd_trigger_after_fill() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: hex::encode(&[0xaa; 50]),
            order_b_p2sh: "p2sh_b".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "fill_order_txid:1");

        // Simulate fill: look up, create context, then trigger
        let outpoint = "fill_order_txid:1";
        let found = book.find_by_a_outpoint(outpoint).unwrap();
        assert_eq!(found.status, IfdStatus::Active);

        let ctx = IfdFillContext {
            rule_id: found.id,
            order_b_rs: hex::decode(&found.order_b_rs_hex).unwrap(),
            order_b_p2sh: found.order_b_p2sh.clone(),
            expiry_daa: found.order_b.expiry_daa(),
        };

        // Trigger the rule
        let fill_tx_id = "match_tx_result_abc123";
        assert!(book.trigger(ctx.rule_id, fill_tx_id));

        // Verify state transition
        let triggered = book.get(id).unwrap();
        assert_eq!(triggered.status, IfdStatus::Triggered);
        assert_eq!(triggered.trigger_tx_id.as_deref(), Some(fill_tx_id));

        // Rule should no longer appear in active list
        assert_eq!(book.active_count(), 0);
    }

    #[test]
    fn ifd_payload_construction_v2() {
        // IFD order B must use v2 payload (KOB:2:) so the scanner accepts it.
        // Using v1 (KOB:1:) would cause the scanner to skip the order.
        let order_b_rs = vec![0x51u8; 100]; // Dummy RS

        // GTC order (expiry_daa=0): no expiry suffix
        let kob_payload = kob_core::contract::build_order_payload_full(
            &order_b_rs, false, None,
        );
        let kob_payload_hex = hex::encode(&kob_payload);

        // Payload should start with hex-encoded "KOB:2:" (4b4f423a323a)
        assert!(kob_payload_hex.starts_with("4b4f423a323a"),
            "IFD payload must use KOB:2: prefix, got: {}", &kob_payload_hex[..14.min(kob_payload_hex.len())]);

        // Flags byte = 0x00 (no post_only, no GTD)
        let prefix_hex = hex::encode(b"KOB:2:");
        let after_prefix = &kob_payload_hex[prefix_hex.len()..];
        assert!(after_prefix.starts_with("00"), "flags byte should be 0x00 for GTC");

        // RS bytes follow the flags byte
        let rs_hex_in_payload = &after_prefix[2..]; // skip "00" flags hex
        assert_eq!(rs_hex_in_payload, hex::encode(&order_b_rs));

        // GTD order (expiry_daa=12345): expiry suffix appended
        let kob_payload_gtd = kob_core::contract::build_order_payload_full(
            &order_b_rs, false, Some(12345),
        );
        let gtd_hex = hex::encode(&kob_payload_gtd);
        assert!(gtd_hex.starts_with("4b4f423a323a"),
            "IFD GTD payload must use KOB:2: prefix");
        let after_prefix_gtd = &gtd_hex[prefix_hex.len()..];
        // flags byte = 0x02 (GTD bit set)
        assert!(after_prefix_gtd.starts_with("02"), "flags byte should be 0x02 for GTD");
    }

    #[test]
    fn ifd_submit_payload_includes_tx_payload() {
        use crate::matcher::deploy;

        let rs_hex = hex::encode(&[0xde, 0xad]);
        let kob_payload = kob_core::contract::build_order_payload_full(
            &[0xde, 0xad], false, None,
        );
        let kob_payload_hex = hex::encode(&kob_payload);

        let outputs = vec![
            deploy::build_rpc_output(100_000, 0, &"aa".repeat(35)),
        ];
        let inputs = vec![
            deploy::build_rpc_input(&"bb".repeat(32), 0, &rs_hex, 0),
        ];

        let payload_json = deploy::build_submit_payload_with_tx_payload(
            0, inputs, outputs, &kob_payload_hex, 0,
        );

        // The TX payload field should contain the KOB payload hex
        let tx = payload_json.get("transaction").unwrap();
        let tx_payload = tx.get("payload").unwrap().as_str().unwrap();
        assert_eq!(tx_payload, &kob_payload_hex);
        assert!(!tx_payload.is_empty());
    }

    #[test]
    fn ifd_submit_payload_empty_when_no_ifd() {
        use crate::matcher::deploy;

        let outputs = vec![
            deploy::build_rpc_output(100_000, 0, &"aa".repeat(35)),
        ];
        let inputs = vec![
            deploy::build_rpc_input(&"bb".repeat(32), 0, "dead", 0),
        ];

        let payload_json = deploy::build_submit_payload(0, inputs, outputs);

        // Without IFD, payload should be empty string
        let tx = payload_json.get("transaction").unwrap();
        let tx_payload = tx.get("payload").unwrap().as_str().unwrap();
        assert_eq!(tx_payload, "");
    }

    #[test]
    fn ifd_fill_context_skips_triggered_rule() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: "deadbeef".to_string(),
            order_b_p2sh: "p2sh_b".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "txid:0");
        book.trigger(id, "old_fill_tx");

        // Rule is now Triggered. The executor should skip it.
        let found = book.find_by_a_outpoint("txid:0").unwrap();
        assert_eq!(found.status, IfdStatus::Triggered);
        // The executor code checks status == Active before creating IfdFillContext
        // so a triggered rule would NOT produce a context
        assert_ne!(found.status, IfdStatus::Active);
    }

    #[test]
    fn ifd_sell_side_lookup_by_outpoint() {
        use crate::matcher::ifd::*;

        // Test that IFD works for sell-side orders too (sell A -> buy B)
        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 500_000,
                min_fill: 50_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_sell_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 80,
                price_den: 1,
                amount: 0,
                min_fill: 50_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: hex::encode(&[0xbb; 60]),
            order_b_p2sh: "p2sh_buy_b".to_string(),
            order_b_spk_hash: "spkhash_buy_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 2000,
            owner_id: "bob".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "sell_txid:2");

        let found = book.find_by_a_outpoint("sell_txid:2").unwrap();
        assert_eq!(found.id, id);
        assert_eq!(found.status, IfdStatus::Active);

        let ctx = IfdFillContext {
            rule_id: found.id,
            order_b_rs: hex::decode(&found.order_b_rs_hex).unwrap(),
            order_b_p2sh: found.order_b_p2sh.clone(),
            expiry_daa: found.order_b.expiry_daa(),
        };
        assert_eq!(ctx.order_b_p2sh, "p2sh_buy_b");
    }

    // ===================================================================
    // ReorgTracker tests
    // ===================================================================

    #[test]
    fn reorg_tracker_basic_record_and_rollback() {
        use crate::matcher::order_book::{BookOrder, OrderBook, OrderSide};

        let mut tracker = ReorgTracker::new();
        let mut ob = OrderBook::new();
        let mut spent = SpentTracker::new();

        // Simulate: block "block_aaa" added order "tx1:0"
        let order = BookOrder {
            tx_id: "tx1".to_string(),
            index: 0,
            value: 100_000,
            token_cov_id: "abcd".repeat(16),
            price_num: 1,
            price_den: 1,
            min_fill: 0,
            owner_hash: "owner".to_string(),
            spk_hash: "spk".to_string(),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            ifd_order_b_rs_hex: None,
            oco_path: None,
            oco_partner_key: None,
            discovered_daa: 0,
        };

        // Add order to book and record provenance
        ob.add_buy_order(order.clone());
        assert!(ob.contains_outpoint("tx1:0"));

        let mut txids = HashSet::new();
        txids.insert("tx1".to_string());
        tracker.record_block(
            "block_aaa".to_string(),
            vec![order.clone()],
            vec![],
            txids,
        );

        // Simulate reorg: block_aaa is removed
        let (restored, removed, handled, unknown) =
            tracker.handle_removed_blocks(&["block_aaa".to_string()], &mut ob, &mut spent);

        assert_eq!(removed, 1, "order added by reorged block should be removed");
        assert_eq!(restored, 0, "no orders to restore");
        assert_eq!(handled, 1);
        assert_eq!(unknown, 0);
        assert!(!ob.contains_outpoint("tx1:0"), "order should be gone after reorg");
    }

    #[test]
    fn reorg_tracker_restores_spent_orders() {
        use crate::matcher::order_book::{BookOrder, OrderBook, OrderSide};

        let mut tracker = ReorgTracker::new();
        let mut ob = OrderBook::new();
        let mut spent = SpentTracker::new();

        // Pre-existing order in book
        let order = BookOrder {
            tx_id: "tx_preexisting".to_string(),
            index: 0,
            value: 50_000,
            token_cov_id: "abcd".repeat(16),
            price_num: 2,
            price_den: 1,
            min_fill: 0,
            owner_hash: "owner2".to_string(),
            spk_hash: "spk2".to_string(),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            ifd_order_b_rs_hex: None,
            oco_path: None,
            oco_partner_key: None,
            discovered_daa: 0,
        };
        ob.add_sell_order(order.clone());
        assert!(ob.contains_outpoint("tx_preexisting:0"));

        // Simulate: block "block_bbb" spent order "tx_preexisting:0"
        // (record the snapshot before removal)
        let spent_snapshot = vec![("tx_preexisting:0".to_string(), order.clone())];
        ob.remove_order("tx_preexisting:0");
        assert!(!ob.contains_outpoint("tx_preexisting:0"));

        // Also mark as spent in tracker
        spent.mark_spent("tx_preexisting:0");

        let mut txids = HashSet::new();
        txids.insert("tx_spend".to_string());
        tracker.record_block(
            "block_bbb".to_string(),
            vec![],
            spent_snapshot,
            txids,
        );

        // Simulate reorg: block_bbb is removed
        let (restored, removed, handled, _) =
            tracker.handle_removed_blocks(&["block_bbb".to_string()], &mut ob, &mut spent);

        assert_eq!(restored, 1, "spent order should be restored");
        assert_eq!(removed, 0);
        assert_eq!(handled, 1);
        assert!(ob.contains_outpoint("tx_preexisting:0"), "order should be back in book");
    }

    #[test]
    fn reorg_tracker_unknown_block_is_logged() {
        let mut tracker = ReorgTracker::new();
        let mut ob = OrderBook::new();
        let mut spent = SpentTracker::new();

        let (_, _, handled, unknown) =
            tracker.handle_removed_blocks(&["unknown_hash".to_string()], &mut ob, &mut spent);

        assert_eq!(handled, 0);
        assert_eq!(unknown, 1, "unknown block should be counted");
    }

    #[test]
    fn reorg_tracker_prunes_old_blocks() {
        let mut tracker = ReorgTracker::new();
        let mut ob = OrderBook::new();
        let mut spent = SpentTracker::new();

        // Fill tracker beyond the limit
        for i in 0..(REORG_TRACKER_MAX_BLOCKS + 100) {
            tracker.record_block(
                format!("block_{}", i),
                vec![],
                vec![],
                HashSet::new(),
            );
        }

        assert!(
            tracker.len() <= REORG_TRACKER_MAX_BLOCKS,
            "tracker should prune old blocks: {} > {}",
            tracker.len(), REORG_TRACKER_MAX_BLOCKS,
        );

        // First block should have been pruned
        let (_, _, handled, unknown) =
            tracker.handle_removed_blocks(&["block_0".to_string()], &mut ob, &mut spent);
        assert_eq!(handled, 0, "block_0 should have been pruned");
        assert_eq!(unknown, 1);
    }

    #[test]
    fn spent_tracker_remove_for_txids() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("tx_a:0");
        tracker.mark_spent("tx_a:1");
        tracker.mark_spent("tx_b:0");
        tracker.mark_spent("tx_c:2");
        assert_eq!(tracker.spent.len(), 4);

        let mut txids = HashSet::new();
        txids.insert("tx_a".to_string());
        tracker.remove_spent_for_txids(&txids);

        assert_eq!(tracker.spent.len(), 2, "tx_a entries should be removed");
        assert!(!tracker.is_spent("tx_a:0"));
        assert!(!tracker.is_spent("tx_a:1"));
        assert!(tracker.is_spent("tx_b:0"));
        assert!(tracker.is_spent("tx_c:2"));
    }

    #[test]
    fn reorg_tracker_dedup_block_hashes() {
        let mut tracker = ReorgTracker::new();

        tracker.record_block(
            "block_dup".to_string(),
            vec![],
            vec![],
            HashSet::new(),
        );
        tracker.record_block(
            "block_dup".to_string(),
            vec![],
            vec![],
            HashSet::new(),
        );

        assert_eq!(tracker.len(), 1, "duplicate block hash should be deduplicated");
    }

    #[test]
    fn reorg_tracker_deep_reorg_multiple_blocks() {
        use crate::matcher::order_book::{BookOrder, OrderBook, OrderSide};

        let mut tracker = ReorgTracker::new();
        let mut ob = OrderBook::new();
        let mut spent = SpentTracker::new();

        // Block 1: adds order A
        let order_a = BookOrder {
            tx_id: "txA".to_string(),
            index: 0,
            value: 10_000,
            token_cov_id: "aaaa".repeat(16),
            price_num: 1,
            price_den: 1,
            min_fill: 0,
            owner_hash: "ownerA".to_string(),
            spk_hash: "spkA".to_string(),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            ifd_order_b_rs_hex: None,
            oco_path: None,
            oco_partner_key: None,
            discovered_daa: 0,
        };
        ob.add_buy_order(order_a.clone());

        let mut txids1 = HashSet::new();
        txids1.insert("txA".to_string());
        tracker.record_block(
            "block_1".to_string(),
            vec![order_a.clone()],
            vec![],
            txids1,
        );

        // Block 2: adds order B, spends order A
        let order_b = BookOrder {
            tx_id: "txB".to_string(),
            index: 0,
            value: 20_000,
            token_cov_id: "bbbb".repeat(16),
            price_num: 3,
            price_den: 1,
            min_fill: 0,
            owner_hash: "ownerB".to_string(),
            spk_hash: "spkB".to_string(),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            ifd_order_b_rs_hex: None,
            oco_path: None,
            oco_partner_key: None,
            discovered_daa: 0,
        };
        ob.add_sell_order(order_b.clone());

        // Snapshot order A before removal
        let a_snapshot = vec![("txA:0".to_string(), order_a.clone())];
        ob.remove_order("txA:0");

        let mut txids2 = HashSet::new();
        txids2.insert("txB".to_string());
        txids2.insert("tx_spend_a".to_string());
        tracker.record_block(
            "block_2".to_string(),
            vec![order_b.clone()],
            a_snapshot,
            txids2,
        );

        // At this point: book has only order B
        assert!(!ob.contains_outpoint("txA:0"));
        assert!(ob.contains_outpoint("txB:0"));

        // Deep reorg: both blocks removed (in order)
        let (_restored, _removed, handled, _) = tracker.handle_removed_blocks(
            &["block_2".to_string(), "block_1".to_string()],
            &mut ob,
            &mut spent,
        );

        // Block 2 rollback: remove B (added), restore A (spent)
        // Block 1 rollback: remove A (added, but A was just restored — it gets removed)
        assert_eq!(handled, 2);
        // Net effect: both orders removed from book
        assert!(!ob.contains_outpoint("txB:0"), "B should be removed (added by block_2)");
        // A was restored by block_2 rollback, then removed by block_1 rollback
        assert!(!ob.contains_outpoint("txA:0"), "A should be removed (added by block_1)");
    }

}
