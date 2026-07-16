//! Trade history ring buffer with optional JSONL file persistence.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Maximum number of trades to keep in memory.
pub const DEFAULT_MAX_TRADES: usize = 10_000;

/// Maximum trade log file size before rotation (500 MB).
/// When the file exceeds this size, it is renamed to `.1` and a fresh file
/// is opened. Only one rotated file is kept to cap disk usage at ~1 GB.
const MAX_TRADE_LOG_FILE_SIZE: u64 = 500_000_000;

/// Side of the trade (taker side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Buy,
    Sell,
}

/// Routing information for a cross-pair trade.
///
/// When a trade is routed through an intermediate token (e.g., A/KAS + B/KAS
/// to achieve A -> B), this struct captures the routing path for transparency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingInfo {
    /// Token pair used for the sell leg (e.g., "TOKEN_A/KAS").
    pub sell_pair: String,
    /// Token pair used for the buy leg (e.g., "TOKEN_B/KAS").
    pub buy_pair: String,
    /// Intermediate token used for routing (always "KAS" for now).
    pub intermediate_token: String,
    /// KAS amount flowing through the route (from sell -> buy).
    pub kas_through: u64,
    /// Sell leg price: what the seller receives per token (num/den in KAS).
    pub sell_price_num: u64,
    pub sell_price_den: u64,
    /// Buy leg price: what the buyer pays per token (num/den in KAS).
    pub buy_price_num: u64,
    pub buy_price_den: u64,
    /// Surplus captured by the matcher (KAS).
    pub surplus: u64,
}

/// The single canonical pair-id scheme, used everywhere a trading pair is
/// identified: the order book (`OrderBook::pair_books` is keyed by the raw
/// `token_cov_id`), the trade log/durable ledger (`Trade::pair_id`), the
/// candle aggregator, and every API handler's `pair` query param
/// (`/pairs`, `/depth`, `/spread`, `/trades`, `/klines`, `/ticker`).
///
/// P0 fix: `record_trade` used to build a DIFFERENT key --
/// `format!("{}/KAS", &token_cov_id[..16])`, a truncated 16-hex-char prefix
/// plus a literal `/KAS` suffix -- while `/pairs`/`/depth`/`/spread` keyed by
/// the full 64-hex `token_cov_id`. No single `pair` value satisfied both, so
/// a client following `/pairs` -> `/trades?pair=...` got zero results. This
/// function is the single source of truth: the canonical pair-id IS the
/// full `token_cov_id`, unmodified, matching `OrderBook::pair_books`'s key
/// exactly. (A human-readable `TOKEN/KAS` display symbol is layered on top
/// by a future symbol registry -- out of scope here -- not baked into the
/// lookup key.)
pub fn canonical_pair_id(token_cov_id: &str) -> String {
    token_cov_id.to_string()
}

/// A single executed trade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub txid: String,
    /// P1 fix: disambiguates multiple trade records that share one
    /// settlement `txid` -- already true for cross-pair swaps (2 legs) and
    /// v17 N:M buy sweeps (up to 9 legs in one TX). `(txid, leg_index)` is
    /// the stable trade key everywhere (ledger + API); see `trade_id()`.
    /// Backward-compatible: absent in old JSON/JSONL rows deserializes as 0
    /// (correct for the pre-leg_index era, when every trade was 1 leg = 1 TX).
    #[serde(default)]
    pub leg_index: u32,
    pub pair_id: String,
    pub price_num: u64,
    pub price_den: u64,
    pub quantity: u64,
    pub side: Side,
    pub daa_score: u64,
    pub timestamp: u64,
    /// Present only for cross-pair routed trades.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingInfo>,
}

impl Trade {
    /// The stable, collision-free trade identifier: `(txid, leg_index)`.
    /// A plain `txid` is NOT sufficient once one settlement TX carries
    /// multiple fills (v17 N:M sweeps, cross-pair swaps).
    pub fn trade_id(&self) -> String {
        format!("{}:{}", self.txid, self.leg_index)
    }
}

/// In-memory trade history with per-pair indexing and optional file persistence.
pub struct TradeLog {
    trades: VecDeque<Trade>,
    /// pair_id -> global indices into `trades` (front = oldest)
    by_pair: HashMap<String, VecDeque<usize>>,
    /// Global insertion counter (monotonically increasing)
    next_idx: usize,
    /// Offset: how many trades have been evicted from the front
    evicted: usize,
    max_trades: usize,
    /// Optional file writer for JSONL persistence.
    writer: Option<BufWriter<File>>,
    /// Path to the persistence file (stored for diagnostics).
    file_path: Option<PathBuf>,
}

impl Default for TradeLog {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_TRADES)
    }
}

impl TradeLog {
    /// Create an in-memory-only trade log with default capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an in-memory-only trade log with a custom capacity.
    pub fn with_capacity(max_trades: usize) -> Self {
        TradeLog {
            trades: VecDeque::with_capacity(max_trades.min(1024)),
            by_pair: HashMap::new(),
            next_idx: 0,
            evicted: 0,
            max_trades,
            writer: None,
            file_path: None,
        }
    }

    /// Create a file-backed trade log. Loads existing trades from the file
    /// on startup and appends new trades as JSONL. Returns the loaded trades
    /// as a Vec so callers can replay them (e.g., into CandleAggregator).
    ///
    /// If the file does not exist, it will be created on the first write.
    /// If the file exists but contains corrupt lines, those lines are skipped
    /// with a warning.
    pub fn new_with_file(path: &str, capacity: usize) -> (Self, Vec<Trade>) {
        let file_path = PathBuf::from(path);
        let mut log = Self::with_capacity(capacity);
        log.file_path = Some(file_path.clone());

        // Load existing trades from file
        let loaded = Self::load_from_file(&file_path);
        let loaded_trades = loaded.clone();

        // Push loaded trades into the ring buffer (respects capacity)
        for trade in loaded {
            log.push_internal(trade);
        }

        // Open file for appending
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(file) => {
                log.writer = Some(BufWriter::new(file));
            }
            Err(e) => {
                warn!(
                    "Failed to open trades file for writing: {} — persistence disabled",
                    e
                );
            }
        }

        (log, loaded_trades)
    }

    /// Load trades from a JSONL file. Returns empty Vec on any file-level error.
    fn load_from_file(path: &Path) -> Vec<Trade> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Failed to open trades file for reading: {}", e);
                }
                return Vec::new();
            }
        };

        let reader = BufReader::new(file);
        let mut trades = Vec::new();
        let mut corrupt_count = 0u64;

        for (line_no, line) in reader.lines().enumerate() {
            match line {
                Ok(text) => {
                    let text = text.trim();
                    if text.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<Trade>(text) {
                        Ok(trade) => trades.push(trade),
                        Err(_) => {
                            corrupt_count += 1;
                            if corrupt_count <= 3 {
                                warn!(
                                    "Corrupt trade at line {} in {}: skipped",
                                    line_no + 1,
                                    path.display()
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    corrupt_count += 1;
                    if corrupt_count <= 3 {
                        warn!(
                            "IO error at line {} in {}: {}",
                            line_no + 1,
                            path.display(),
                            e
                        );
                    }
                }
            }
        }

        if corrupt_count > 3 {
            warn!(
                "... and {} more corrupt/unreadable lines in {}",
                corrupt_count - 3,
                path.display()
            );
        }

        trades
    }

    /// Internal push that does NOT write to file. Used during load.
    fn push_internal(&mut self, trade: Trade) {
        let pair_id = trade.pair_id.clone();
        let global_idx = self.next_idx;
        self.next_idx += 1;

        if self.trades.len() >= self.max_trades {
            if let Some(old) = self.trades.pop_front() {
                self.evicted += 1;
                if let Some(indices) = self.by_pair.get_mut(&old.pair_id) {
                    while let Some(&front) = indices.front() {
                        if front < self.evicted {
                            indices.pop_front();
                        } else {
                            break;
                        }
                    }
                    if indices.is_empty() {
                        self.by_pair.remove(&old.pair_id);
                    }
                }
            }
        }

        self.trades.push_back(trade);
        self.by_pair
            .entry(pair_id)
            .or_default()
            .push_back(global_idx);
    }

    /// Rotate the trade log file if it exceeds MAX_TRADE_LOG_FILE_SIZE.
    ///
    /// The current file is renamed to `<path>.1` (overwriting any previous
    /// rotation) and a fresh file is opened for appending. This caps total
    /// disk usage at roughly 2x MAX_TRADE_LOG_FILE_SIZE.
    fn maybe_rotate(&mut self) {
        let path = match &self.file_path {
            Some(p) => p.clone(),
            None => return,
        };

        let size = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(_) => return,
        };

        if size <= MAX_TRADE_LOG_FILE_SIZE {
            return;
        }

        // Close the current writer before renaming
        self.writer = None;

        let rotated = PathBuf::from(format!("{}.1", path.display()));
        if let Err(e) = std::fs::rename(&path, &rotated) {
            warn!(
                "Failed to rotate trade log {} -> {}: {}",
                path.display(),
                rotated.display(),
                e,
            );
        } else {
            tracing::info!(
                "[TRADE LOG] Rotated {} ({} bytes) -> {}",
                path.display(),
                size,
                rotated.display(),
            );
        }

        // Reopen (or create) the file for appending
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => {
                self.writer = Some(BufWriter::new(file));
            }
            Err(e) => {
                warn!(
                    "Failed to reopen trade log after rotation: {} — persistence disabled",
                    e,
                );
            }
        }
    }

    /// Push a new trade. If at capacity, the oldest trade is evicted.
    /// If file persistence is enabled, the trade is appended as a JSON line.
    /// The trade log file is rotated when it exceeds MAX_TRADE_LOG_FILE_SIZE.
    #[allow(dead_code)] // Used in tests
    pub fn push(&mut self, trade: Trade) {
        // Check file size and rotate if needed (best-effort)
        self.maybe_rotate();

        // Persist to file first (best-effort)
        if let Some(ref mut writer) = self.writer {
            match serde_json::to_string(&trade) {
                Ok(json) => {
                    if let Err(e) = writeln!(writer, "{}", json) {
                        warn!("Failed to write trade to file: {}", e);
                    } else if let Err(e) = writer.flush() {
                        warn!("Failed to flush trades file: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize trade: {}", e);
                }
            }
        }

        self.push_internal(trade);
    }

    /// Get the most recent `limit` trades for a given pair (newest first).
    pub fn recent(&self, pair_id: &str, limit: usize) -> Vec<&Trade> {
        if let Some(indices) = self.by_pair.get(pair_id) {
            indices
                .iter()
                .rev()
                .take(limit)
                .filter_map(|&idx| {
                    let offset = idx.checked_sub(self.evicted)?;
                    self.trades.get(offset)
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all trades for a pair since a given DAA score (inclusive).
    pub fn since(&self, pair_id: &str, daa_score: u64) -> Vec<&Trade> {
        if let Some(indices) = self.by_pair.get(pair_id) {
            indices
                .iter()
                .filter_map(|&idx| {
                    let offset = idx.checked_sub(self.evicted)?;
                    self.trades.get(offset)
                })
                .filter(|t| t.daa_score >= daa_score)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get the most recent `limit` trades across all pairs (newest first).
    #[allow(dead_code)] // Used in tests
    pub fn recent_all(&self, limit: usize) -> Vec<&Trade> {
        self.trades.iter().rev().take(limit).collect()
    }

    /// Get trades for a pair filtered by timestamp range (newest first), limited to `limit`.
    /// Returns trades where `timestamp >= start_time` and `timestamp <= end_time`.
    pub fn range(
        &self,
        pair_id: &str,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Vec<&Trade> {
        if let Some(indices) = self.by_pair.get(pair_id) {
            indices
                .iter()
                .rev()
                .filter_map(|&idx| {
                    let offset = idx.checked_sub(self.evicted)?;
                    self.trades.get(offset)
                })
                .filter(|t| {
                    if let Some(st) = start_time {
                        if t.timestamp < st {
                            return false;
                        }
                    }
                    if let Some(et) = end_time {
                        if t.timestamp > et {
                            return false;
                        }
                    }
                    true
                })
                .take(limit)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get the most recent `limit` cross-pair trades (newest first).
    ///
    /// Filters for trades that have routing info (i.e., cross-pair routed).
    pub fn recent_cross_pair(&self, limit: usize) -> Vec<&Trade> {
        self.trades
            .iter()
            .rev()
            .filter(|t| t.routing.is_some())
            .take(limit)
            .collect()
    }

    /// Total number of trades stored.
    #[allow(dead_code)] // Used in tests
    pub fn len(&self) -> usize {
        self.trades.len()
    }

    /// Total number of trades ever recorded (including evicted).
    pub fn total_count(&self) -> usize {
        self.next_idx
    }

    #[allow(dead_code)] // Used in tests
    pub fn is_empty(&self) -> bool {
        self.trades.is_empty()
    }
}

// Pending trades: submission-time staging for confirmation-time durable persistence

/// Default horizon after which a staged trade whose txid never confirmed is
/// dropped (mempool eviction / the TX was replaced or never mined).
pub const DEFAULT_PENDING_TRADE_MAX_AGE_SECS: u64 = 600;

/// Trades staged at TX-submission time, awaiting confirmation before being
/// written to the durable, query-indexed trade store.
///
/// `record_trade` (submission time) still pushes to the in-memory `TradeLog`
/// + candle aggregator immediately (unchanged low-latency hot path for
/// recent-data/WS), but ALSO stages a copy here. The block-scan loop
/// promotes staged trades to the durable store only once their txid is
/// actually observed in a confirmed block (`take_confirmed`); entries whose
/// txid never confirms are simply dropped (`expire_older_than`) and are
/// never written -- this is what makes the durable ledger "confirmation
/// time, not submission time", with reorg/mempool-eviction safety by
/// construction (nothing durable exists until real confirmation).
pub struct PendingTrades {
    /// txid -> (staged_at, trades staged under that txid).
    by_txid: HashMap<String, (std::time::Instant, Vec<Trade>)>,
}

impl Default for PendingTrades {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingTrades {
    pub fn new() -> Self {
        PendingTrades { by_txid: HashMap::new() }
    }

    /// Stage a trade under its txid, awaiting confirmation.
    pub fn stage(&mut self, trade: Trade) {
        self.by_txid
            .entry(trade.txid.clone())
            .or_insert_with(|| (std::time::Instant::now(), Vec::new()))
            .1
            .push(trade);
    }

    /// Remove and return every staged trade whose txid appears in
    /// `confirmed_txids` (the txid set of a just-processed confirmed block).
    /// Called from the block-scan loop; the caller is responsible for
    /// writing the returned trades to the durable store.
    pub fn take_confirmed(
        &mut self,
        confirmed_txids: &std::collections::HashSet<String>,
    ) -> Vec<Trade> {
        let mut out = Vec::new();
        let mut done: Vec<String> = Vec::new();
        for (txid, (_, trades)) in self.by_txid.iter_mut() {
            if confirmed_txids.contains(txid) {
                out.append(trades);
                done.push(txid.clone());
            }
        }
        for txid in done {
            self.by_txid.remove(&txid);
        }
        out
    }

    /// Drop (never persist) staged trades older than `max_age_secs` whose
    /// txid never confirmed -- the mempool-eviction / replaced-TX case.
    /// Returns the dropped trades for logging/metrics only; callers must
    /// NOT write them to the durable store (that's the point: they never
    /// confirmed).
    pub fn expire_older_than(&mut self, max_age_secs: u64) -> Vec<Trade> {
        let mut dropped = Vec::new();
        let mut expired: Vec<String> = Vec::new();
        for (txid, (staged_at, _)) in self.by_txid.iter() {
            if staged_at.elapsed().as_secs() >= max_age_secs {
                expired.push(txid.clone());
            }
        }
        for txid in expired {
            if let Some((_, trades)) = self.by_txid.remove(&txid) {
                dropped.extend(trades);
            }
        }
        dropped
    }

    /// Total number of staged (not yet confirmed or expired) trades.
    #[allow(dead_code)] // Used in tests
    pub fn len(&self) -> usize {
        self.by_txid.values().map(|(_, v)| v.len()).sum()
    }

    #[allow(dead_code)] // Used in tests
    pub fn is_empty(&self) -> bool {
        self.by_txid.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trade(txid: &str, pair: &str, price_num: u64, daa: u64) -> Trade {
        Trade {
            txid: txid.to_string(),
            leg_index: 0,
            pair_id: pair.to_string(),
            price_num,
            price_den: 1,
            quantity: 100,
            side: Side::Buy,
            daa_score: daa,
            timestamp: daa,
            routing: None,
        }
    }

    fn make_cross_pair_trade(txid: &str, daa: u64) -> Trade {
        Trade {
            txid: txid.to_string(),
            leg_index: 0,
            pair_id: "cross:TOKEN_A->TOKEN_B".to_string(),
            price_num: 1,
            price_den: 2,
            quantity: 10_000_000,
            side: Side::Buy,
            daa_score: daa,
            timestamp: daa,
            routing: Some(RoutingInfo {
                sell_pair: "TOKEN_A/KAS".to_string(),
                buy_pair: "TOKEN_B/KAS".to_string(),
                intermediate_token: "KAS".to_string(),
                kas_through: 5_000_000,
                sell_price_num: 1,
                sell_price_den: 2,
                buy_price_num: 1,
                buy_price_den: 3,
                surplus: 2_000_000,
            }),
        }
    }

    #[test]
    fn test_push_and_recent() {
        let mut log = TradeLog::new();
        log.push(make_trade("tx1", "pairA", 10, 100));
        log.push(make_trade("tx2", "pairA", 20, 101));
        log.push(make_trade("tx3", "pairB", 30, 102));

        let recent_a = log.recent("pairA", 10);
        assert_eq!(recent_a.len(), 2);
        assert_eq!(recent_a[0].txid, "tx2"); // newest first
        assert_eq!(recent_a[1].txid, "tx1");

        let recent_b = log.recent("pairB", 10);
        assert_eq!(recent_b.len(), 1);
        assert_eq!(recent_b[0].txid, "tx3");
    }

    #[test]
    fn test_recent_limit() {
        let mut log = TradeLog::new();
        for i in 0..10 {
            log.push(make_trade(&format!("tx{}", i), "pairA", i as u64, i as u64));
        }
        let recent = log.recent("pairA", 3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].txid, "tx9");
        assert_eq!(recent[1].txid, "tx8");
        assert_eq!(recent[2].txid, "tx7");
    }

    #[test]
    fn test_capacity_overflow() {
        let mut log = TradeLog::with_capacity(5);
        for i in 0..10 {
            log.push(make_trade(&format!("tx{}", i), "pairA", i as u64, i as u64));
        }
        assert_eq!(log.len(), 5);
        assert_eq!(log.total_count(), 10);

        let recent = log.recent("pairA", 10);
        // Should only have the last 5
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].txid, "tx9");
        assert_eq!(recent[4].txid, "tx5");
    }

    #[test]
    fn test_capacity_overflow_multi_pair() {
        let mut log = TradeLog::with_capacity(4);
        log.push(make_trade("tx0", "pairA", 10, 0));
        log.push(make_trade("tx1", "pairB", 20, 1));
        log.push(make_trade("tx2", "pairA", 30, 2));
        log.push(make_trade("tx3", "pairB", 40, 3));
        // Full, now push more
        log.push(make_trade("tx4", "pairA", 50, 4));
        log.push(make_trade("tx5", "pairB", 60, 5));

        assert_eq!(log.len(), 4);
        let a = log.recent("pairA", 10);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].txid, "tx4");
        assert_eq!(a[1].txid, "tx2");
    }

    #[test]
    fn test_since() {
        let mut log = TradeLog::new();
        log.push(make_trade("tx0", "pairA", 10, 100));
        log.push(make_trade("tx1", "pairA", 20, 200));
        log.push(make_trade("tx2", "pairA", 30, 300));

        let since_200 = log.since("pairA", 200);
        assert_eq!(since_200.len(), 2);
        assert_eq!(since_200[0].txid, "tx1");
        assert_eq!(since_200[1].txid, "tx2");
    }

    #[test]
    fn test_since_empty_pair() {
        let log = TradeLog::new();
        assert!(log.since("nonexistent", 0).is_empty());
    }

    #[test]
    fn test_recent_all() {
        let mut log = TradeLog::new();
        log.push(make_trade("tx0", "pairA", 10, 0));
        log.push(make_trade("tx1", "pairB", 20, 1));
        log.push(make_trade("tx2", "pairA", 30, 2));

        let all = log.recent_all(2);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].txid, "tx2");
        assert_eq!(all[1].txid, "tx1");
    }

    #[test]
    fn test_empty_log() {
        let log = TradeLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.total_count(), 0);
        assert!(log.recent("any", 10).is_empty());
    }

    #[test]
    fn test_recent_nonexistent_pair() {
        let mut log = TradeLog::new();
        log.push(make_trade("tx0", "pairA", 10, 0));
        assert!(log.recent("pairB", 10).is_empty());
    }

    #[test]
    fn test_side_serialization() {
        assert_eq!(serde_json::to_string(&Side::Buy).unwrap(), "\"buy\"");
        assert_eq!(serde_json::to_string(&Side::Sell).unwrap(), "\"sell\"");
    }

    // Cross-pair routing info tests

    #[test]
    fn test_recent_cross_pair_filter() {
        let mut log = TradeLog::new();
        log.push(make_trade("tx1", "pairA", 10, 100));
        log.push(make_cross_pair_trade("tx_cp1", 101));
        log.push(make_trade("tx2", "pairA", 20, 102));
        log.push(make_cross_pair_trade("tx_cp2", 103));
        log.push(make_trade("tx3", "pairB", 30, 104));

        let cp_trades = log.recent_cross_pair(10);
        assert_eq!(cp_trades.len(), 2, "Should find 2 cross-pair trades");
        assert_eq!(cp_trades[0].txid, "tx_cp2"); // newest first
        assert_eq!(cp_trades[1].txid, "tx_cp1");
    }

    #[test]
    fn test_recent_cross_pair_limit() {
        let mut log = TradeLog::new();
        for i in 0..5 {
            log.push(make_cross_pair_trade(&format!("tx_cp{}", i), i as u64));
        }
        let cp_trades = log.recent_cross_pair(3);
        assert_eq!(cp_trades.len(), 3);
        assert_eq!(cp_trades[0].txid, "tx_cp4");
    }

    #[test]
    fn test_recent_cross_pair_empty() {
        let mut log = TradeLog::new();
        log.push(make_trade("tx1", "pairA", 10, 100));
        let cp_trades = log.recent_cross_pair(10);
        assert!(cp_trades.is_empty());
    }

    #[test]
    fn test_routing_info_serialization() {
        let trade = make_cross_pair_trade("tx_cp1", 100);
        let json = serde_json::to_string(&trade).unwrap();
        assert!(json.contains("routing"));
        assert!(json.contains("sell_pair"));
        assert!(json.contains("buy_pair"));
        assert!(json.contains("intermediate_token"));
        assert!(json.contains("kas_through"));
        assert!(json.contains("surplus"));

        let parsed: Trade = serde_json::from_str(&json).unwrap();
        let routing = parsed.routing.unwrap();
        assert_eq!(routing.sell_pair, "TOKEN_A/KAS");
        assert_eq!(routing.buy_pair, "TOKEN_B/KAS");
        assert_eq!(routing.intermediate_token, "KAS");
        assert_eq!(routing.kas_through, 5_000_000);
        assert_eq!(routing.surplus, 2_000_000);
    }

    #[test]
    fn test_routing_none_not_serialized() {
        let trade = make_trade("tx1", "pairA", 10, 100);
        let json = serde_json::to_string(&trade).unwrap();
        // skip_serializing_if = "Option::is_none" should omit routing
        assert!(!json.contains("routing"));
    }

    #[test]
    fn test_routing_backward_compat_deserialization() {
        // Old-format trade JSON without routing field should deserialize fine
        let json = r#"{"txid":"tx1","pair_id":"pairA","price_num":10,"price_den":1,"quantity":100,"side":"buy","daa_score":100,"timestamp":100}"#;
        let parsed: Trade = serde_json::from_str(json).unwrap();
        assert!(parsed.routing.is_none());
        assert_eq!(parsed.txid, "tx1");
    }

    #[test]
    fn test_cross_pair_trade_file_roundtrip() {
        let path = temp_path("cross_pair_roundtrip.jsonl");
        cleanup(&path);

        {
            let (mut log, _) = TradeLog::new_with_file(&path, 100);
            log.push(make_trade("tx1", "pairA", 10, 100));
            log.push(make_cross_pair_trade("tx_cp1", 101));
        }

        {
            let (log, loaded) = TradeLog::new_with_file(&path, 100);
            assert_eq!(loaded.len(), 2);
            assert_eq!(log.len(), 2);
            // Verify cross-pair trade survived roundtrip
            let cp = log.recent_cross_pair(10);
            assert_eq!(cp.len(), 1);
            assert_eq!(cp[0].txid, "tx_cp1");
            let routing = cp[0].routing.as_ref().unwrap();
            assert_eq!(routing.sell_pair, "TOKEN_A/KAS");
            assert_eq!(routing.kas_through, 5_000_000);
        }

        cleanup(&path);
    }

    // File persistence tests

    fn temp_path(name: &str) -> String {
        std::env::temp_dir().join(format!("kob_trade_test_{}", name)).to_string_lossy().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_file_write_read_roundtrip() {
        let path = temp_path("roundtrip.jsonl");
        cleanup(&path);

        // Write trades
        {
            let (mut log, loaded) = TradeLog::new_with_file(&path, 100);
            assert!(loaded.is_empty());
            log.push(make_trade("tx1", "pairA", 10, 100));
            log.push(make_trade("tx2", "pairB", 20, 200));
            log.push(make_trade("tx3", "pairA", 30, 300));
        }

        // Read them back
        {
            let (log, loaded) = TradeLog::new_with_file(&path, 100);
            assert_eq!(loaded.len(), 3);
            assert_eq!(log.len(), 3);
            assert_eq!(log.recent("pairA", 10).len(), 2);
            assert_eq!(log.recent("pairB", 10).len(), 1);
            assert_eq!(log.recent("pairA", 10)[0].txid, "tx3");
            assert_eq!(loaded[0].txid, "tx1");
            assert_eq!(loaded[2].txid, "tx3");
        }

        cleanup(&path);
    }

    #[test]
    fn test_file_capacity_overflow_memory_bounded_file_unbounded() {
        let path = temp_path("overflow.jsonl");
        cleanup(&path);

        // Write 10 trades with capacity 5
        {
            let (mut log, _) = TradeLog::new_with_file(&path, 5);
            for i in 0..10 {
                log.push(make_trade(
                    &format!("tx{}", i),
                    "pairA",
                    i as u64,
                    i as u64,
                ));
            }
            assert_eq!(log.len(), 5); // memory capped at 5
        }

        // File should have all 10, but memory loads only last 5
        {
            let (log, loaded) = TradeLog::new_with_file(&path, 5);
            assert_eq!(loaded.len(), 10); // file has all 10
            assert_eq!(log.len(), 5); // memory still capped
            assert_eq!(log.recent("pairA", 10)[0].txid, "tx9");
            assert_eq!(log.recent("pairA", 10)[4].txid, "tx5");
        }

        cleanup(&path);
    }

    #[test]
    fn test_file_missing_starts_empty() {
        let path = temp_path("nonexistent_42.jsonl");
        cleanup(&path);

        let (log, loaded) = TradeLog::new_with_file(&path, 100);
        assert!(loaded.is_empty());
        assert!(log.is_empty());

        cleanup(&path);
    }

    #[test]
    fn test_file_corrupt_lines_skipped() {
        let path = temp_path("corrupt.jsonl");
        cleanup(&path);

        // Write a file with some corrupt lines
        {
            let mut f = File::create(&path).unwrap();
            let good = make_trade("tx_good", "pairA", 10, 100);
            writeln!(f, "{}", serde_json::to_string(&good).unwrap()).unwrap();
            writeln!(f, "NOT VALID JSON").unwrap();
            writeln!(f, "{{\"also\": \"bad\"}}").unwrap();
            let good2 = make_trade("tx_good2", "pairA", 20, 200);
            writeln!(f, "{}", serde_json::to_string(&good2).unwrap()).unwrap();
        }

        let (log, loaded) = TradeLog::new_with_file(&path, 100);
        assert_eq!(loaded.len(), 2);
        assert_eq!(log.len(), 2);
        assert_eq!(log.recent("pairA", 10)[0].txid, "tx_good2");

        cleanup(&path);
    }

    #[test]
    fn test_file_empty_lines_ignored() {
        let path = temp_path("empty_lines.jsonl");
        cleanup(&path);

        {
            let mut f = File::create(&path).unwrap();
            let t = make_trade("tx1", "pairA", 10, 100);
            writeln!(f, "{}", serde_json::to_string(&t).unwrap()).unwrap();
            writeln!(f).unwrap();
            writeln!(f, "  ").unwrap();
            let t2 = make_trade("tx2", "pairA", 20, 200);
            writeln!(f, "{}", serde_json::to_string(&t2).unwrap()).unwrap();
        }

        let (log, loaded) = TradeLog::new_with_file(&path, 100);
        assert_eq!(loaded.len(), 2);
        assert_eq!(log.len(), 2);

        cleanup(&path);
    }

    #[test]
    fn test_file_append_across_sessions() {
        let path = temp_path("append.jsonl");
        cleanup(&path);

        // Session 1: write 2 trades
        {
            let (mut log, _) = TradeLog::new_with_file(&path, 100);
            log.push(make_trade("tx1", "pairA", 10, 100));
            log.push(make_trade("tx2", "pairA", 20, 200));
        }

        // Session 2: load + write 1 more
        {
            let (mut log, loaded) = TradeLog::new_with_file(&path, 100);
            assert_eq!(loaded.len(), 2);
            log.push(make_trade("tx3", "pairA", 30, 300));
        }

        // Session 3: should see all 3
        {
            let (_log, loaded) = TradeLog::new_with_file(&path, 100);
            assert_eq!(loaded.len(), 3);
            assert_eq!(loaded[0].txid, "tx1");
            assert_eq!(loaded[1].txid, "tx2");
            assert_eq!(loaded[2].txid, "tx3");
        }

        cleanup(&path);
    }

    #[test]
    fn test_trade_deserialization() {
        let trade = make_trade("tx1", "pairA", 42, 999);
        let json = serde_json::to_string(&trade).unwrap();
        let parsed: Trade = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.txid, "tx1");
        assert_eq!(parsed.pair_id, "pairA");
        assert_eq!(parsed.price_num, 42);
        assert_eq!(parsed.daa_score, 999);
        assert_eq!(parsed.side, Side::Buy);
    }

    // E2E Integration: Trade log recording and querying

    /// E2E: Trade log records trades after simulated match execution.
    #[test]
    fn e2e_trade_log_records_after_match() {
        let mut log = TradeLog::new();

        // Simulate recording a trade after a successful match
        let trade = Trade {
            txid: "match_tx_001".to_string(),
            leg_index: 0,
            pair_id: "TOKEN_A/KAS".to_string(),
            price_num: 3,
            price_den: 2,
            quantity: 10_000_000,
            side: Side::Buy,
            daa_score: 12345,
            timestamp: 1700000000,
            routing: None,
        };
        log.push(trade);

        assert_eq!(log.len(), 1);
        assert_eq!(log.total_count(), 1);

        let recent = log.recent("TOKEN_A/KAS", 10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].txid, "match_tx_001");
        assert_eq!(recent[0].quantity, 10_000_000);
    }

    /// E2E: Trade log ring buffer evicts oldest trades when full.
    #[test]
    fn e2e_trade_log_ring_buffer_eviction() {
        let mut log = TradeLog::with_capacity(5);

        for i in 0..8 {
            log.push(make_trade(&format!("tx{}", i), "pairA", i as u64, i as u64));
        }

        assert_eq!(log.len(), 5, "should keep only 5 most recent");
        assert_eq!(log.total_count(), 8, "total_count tracks all insertions");

        // Most recent should be tx7
        let recent = log.recent_all(10);
        assert_eq!(recent[0].txid, "tx7");
        // Oldest in buffer should be tx3
        assert_eq!(recent[4].txid, "tx3");
    }

    /// E2E: Cross-pair trade with routing info is recorded and queryable.
    #[test]
    fn e2e_trade_log_cross_pair_routing() {
        let mut log = TradeLog::new();

        // Normal trades
        log.push(make_trade("tx_normal", "pairA", 1, 100));

        // Cross-pair trade
        let cp_trade = Trade {
            txid: "tx_cross".to_string(),
            leg_index: 0,
            pair_id: "cross:TOKEN_A->TOKEN_B".to_string(),
            price_num: 1,
            price_den: 1,
            quantity: 5_000_000,
            side: Side::Buy,
            daa_score: 200,
            timestamp: 200,
            routing: Some(RoutingInfo {
                sell_pair: "TOKEN_A/KAS".to_string(),
                buy_pair: "TOKEN_B/KAS".to_string(),
                intermediate_token: "KAS".to_string(),
                kas_through: 10_000_000,
                sell_price_num: 1,
                sell_price_den: 2,
                buy_price_num: 1,
                buy_price_den: 3,
                surplus: 3_000_000,
            }),
        };
        log.push(cp_trade);

        let cp_trades = log.recent_cross_pair(10);
        assert_eq!(cp_trades.len(), 1);
        assert_eq!(cp_trades[0].txid, "tx_cross");
        let routing = cp_trades[0].routing.as_ref().unwrap();
        assert_eq!(routing.kas_through, 10_000_000);
        assert_eq!(routing.surplus, 3_000_000);
    }

    /// E2E: Trade log per-pair DAA score query.
    #[test]
    fn e2e_trade_log_daa_score_filter() {
        let mut log = TradeLog::new();

        log.push(make_trade("tx1", "pairA", 1, 100));
        log.push(make_trade("tx2", "pairA", 2, 200));
        log.push(make_trade("tx3", "pairA", 3, 300));
        log.push(make_trade("tx4", "pairB", 4, 250));

        let since_200 = log.since("pairA", 200);
        assert_eq!(since_200.len(), 2, "should get trades with daa >= 200 in pairA");
        assert_eq!(since_200[0].txid, "tx2");
        assert_eq!(since_200[1].txid, "tx3");

        let since_301 = log.since("pairA", 301);
        assert!(since_301.is_empty(), "no pairA trades with daa >= 301");
    }

    /// E2E: Empty trade log queries return empty results.
    #[test]
    fn e2e_trade_log_empty_queries() {
        let log = TradeLog::new();
        assert!(log.recent("pairA", 10).is_empty());
        assert!(log.recent_all(10).is_empty());
        assert!(log.recent_cross_pair(10).is_empty());
        assert!(log.since("pairA", 0).is_empty());
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.total_count(), 0);
    }

    /// E2E: Trade log serialization round-trip for cross-pair trades.
    #[test]
    fn e2e_trade_log_cross_pair_serialization() {
        let trade = Trade {
            txid: "tx_cp".to_string(),
            leg_index: 0,
            pair_id: "cross:A->B".to_string(),
            price_num: 5,
            price_den: 3,
            quantity: 7_000_000,
            side: Side::Sell,
            daa_score: 500,
            timestamp: 500,
            routing: Some(RoutingInfo {
                sell_pair: "A/KAS".to_string(),
                buy_pair: "B/KAS".to_string(),
                intermediate_token: "KAS".to_string(),
                kas_through: 12_000_000,
                sell_price_num: 5,
                sell_price_den: 3,
                buy_price_num: 2,
                buy_price_den: 1,
                surplus: 4_000_000,
            }),
        };

        let json = serde_json::to_string(&trade).unwrap();
        let parsed: Trade = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.txid, "tx_cp");
        assert_eq!(parsed.side, Side::Sell);
        let routing = parsed.routing.unwrap();
        assert_eq!(routing.kas_through, 12_000_000);
        assert_eq!(routing.surplus, 4_000_000);
        assert_eq!(routing.sell_pair, "A/KAS");
        assert_eq!(routing.buy_pair, "B/KAS");
    }

    // Time range query tests

    fn make_trade_ts(txid: &str, pair: &str, ts: u64) -> Trade {
        Trade {
            txid: txid.to_string(),
            leg_index: 0,
            pair_id: pair.to_string(),
            price_num: 1,
            price_den: 1,
            quantity: 100,
            side: Side::Buy,
            daa_score: ts,
            timestamp: ts,
            routing: None,
        }
    }

    #[test]
    fn test_range_start_time() {
        let mut log = TradeLog::new();
        log.push(make_trade_ts("tx1", "pairA", 100));
        log.push(make_trade_ts("tx2", "pairA", 200));
        log.push(make_trade_ts("tx3", "pairA", 300));

        let result = log.range("pairA", Some(200), None, 100);
        assert_eq!(result.len(), 2);
        // newest first
        assert_eq!(result[0].txid, "tx3");
        assert_eq!(result[1].txid, "tx2");
    }

    #[test]
    fn test_range_end_time() {
        let mut log = TradeLog::new();
        log.push(make_trade_ts("tx1", "pairA", 100));
        log.push(make_trade_ts("tx2", "pairA", 200));
        log.push(make_trade_ts("tx3", "pairA", 300));

        let result = log.range("pairA", None, Some(200), 100);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].txid, "tx2");
        assert_eq!(result[1].txid, "tx1");
    }

    #[test]
    fn test_range_both_bounds() {
        let mut log = TradeLog::new();
        log.push(make_trade_ts("tx1", "pairA", 100));
        log.push(make_trade_ts("tx2", "pairA", 200));
        log.push(make_trade_ts("tx3", "pairA", 300));
        log.push(make_trade_ts("tx4", "pairA", 400));

        let result = log.range("pairA", Some(200), Some(300), 100);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].txid, "tx3");
        assert_eq!(result[1].txid, "tx2");
    }

    #[test]
    fn test_range_with_limit() {
        let mut log = TradeLog::new();
        for i in 0..10 {
            log.push(make_trade_ts(&format!("tx{}", i), "pairA", (i + 1) * 100));
        }
        let result = log.range("pairA", Some(0), None, 3);
        assert_eq!(result.len(), 3);
        // newest first
        assert_eq!(result[0].txid, "tx9");
    }

    #[test]
    fn test_range_empty_pair() {
        let log = TradeLog::new();
        let result = log.range("nonexistent", Some(0), Some(1000), 100);
        assert!(result.is_empty());
    }

    #[test]
    fn test_range_no_bounds_returns_all() {
        let mut log = TradeLog::new();
        log.push(make_trade_ts("tx1", "pairA", 100));
        log.push(make_trade_ts("tx2", "pairA", 200));

        let result = log.range("pairA", None, None, 100);
        assert_eq!(result.len(), 2);
    }

    // P0 fix: canonical_pair_id must match OrderBook::pair_books' key exactly

    #[test]
    fn canonical_pair_id_is_the_full_token_cov_id_unmodified() {
        let token_cov_id = "ab".repeat(32); // 64-hex, same shape as a real token_cov_id
        assert_eq!(canonical_pair_id(&token_cov_id), token_cov_id, "must be the identity transform");
        assert_eq!(canonical_pair_id(&token_cov_id).len(), 64, "must not truncate");
        assert!(!canonical_pair_id(&token_cov_id).contains("/KAS"), "must not append a display suffix");
    }

    // P1 fix: leg_index / Trade::trade_id()

    #[test]
    fn trade_id_combines_txid_and_leg_index() {
        let mut t = make_trade("sweep_tx", "pairA", 1, 100);
        t.leg_index = 0;
        assert_eq!(t.trade_id(), "sweep_tx:0");
        t.leg_index = 5;
        assert_eq!(t.trade_id(), "sweep_tx:5");
    }

    #[test]
    fn trade_id_distinguishes_legs_sharing_one_txid() {
        let legs: Vec<Trade> = (0..4)
            .map(|i| {
                let mut t = make_trade("shared_tx", "pairA", i as u64, 100);
                t.leg_index = i;
                t
            })
            .collect();
        let ids: std::collections::HashSet<String> = legs.iter().map(|t| t.trade_id()).collect();
        assert_eq!(ids.len(), 4, "each leg of the same txid must have a distinct trade_id");
        assert!(legs.iter().all(|t| t.txid == "shared_tx"));
    }

    #[test]
    fn leg_index_defaults_to_zero_on_backward_compat_deserialization() {
        // Pre-leg_index JSON (no "leg_index" field) must still deserialize.
        let json = r#"{"txid":"tx1","pair_id":"pairA","price_num":10,"price_den":1,"quantity":100,"side":"buy","daa_score":100,"timestamp":100}"#;
        let parsed: Trade = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.leg_index, 0);
        assert_eq!(parsed.trade_id(), "tx1:0");
    }

    // PendingTrades: submission-time staging for confirmation-time persistence

    #[test]
    fn pending_trades_new_is_empty() {
        let p = PendingTrades::new();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn pending_trades_stage_then_take_confirmed() {
        let mut p = PendingTrades::new();
        p.stage(make_trade("tx1", "pairA", 10, 100));
        p.stage(make_trade("tx2", "pairA", 20, 101));
        assert_eq!(p.len(), 2);

        let mut confirmed_txids = std::collections::HashSet::new();
        confirmed_txids.insert("tx1".to_string());

        let confirmed = p.take_confirmed(&confirmed_txids);
        assert_eq!(confirmed.len(), 1, "only tx1's staged trade should be confirmed");
        assert_eq!(confirmed[0].txid, "tx1");
        assert_eq!(p.len(), 1, "tx2 remains staged (not yet confirmed)");
    }

    #[test]
    fn pending_trades_take_confirmed_multiple_legs_same_txid() {
        // v17 N:M sweeps emit multiple trade records sharing one txid --
        // confirmation must promote ALL of them together.
        let mut p = PendingTrades::new();
        p.stage(make_trade("sweep_tx", "pairA", 1, 100));
        p.stage(make_trade("sweep_tx", "pairA", 2, 100));
        p.stage(make_trade("sweep_tx", "pairA", 3, 100));

        let mut confirmed_txids = std::collections::HashSet::new();
        confirmed_txids.insert("sweep_tx".to_string());
        let confirmed = p.take_confirmed(&confirmed_txids);
        assert_eq!(confirmed.len(), 3, "all legs sharing the txid must confirm together");
        assert!(p.is_empty());
    }

    #[test]
    fn pending_trades_take_confirmed_no_match_returns_empty_and_keeps_staged() {
        let mut p = PendingTrades::new();
        p.stage(make_trade("tx1", "pairA", 10, 100));

        let confirmed_txids = std::collections::HashSet::new(); // no txids confirmed
        let confirmed = p.take_confirmed(&confirmed_txids);
        assert!(confirmed.is_empty());
        assert_eq!(p.len(), 1, "unconfirmed trade must remain staged");
    }

    #[test]
    fn pending_trades_take_confirmed_is_idempotent() {
        let mut p = PendingTrades::new();
        p.stage(make_trade("tx1", "pairA", 10, 100));

        let mut confirmed_txids = std::collections::HashSet::new();
        confirmed_txids.insert("tx1".to_string());

        let first = p.take_confirmed(&confirmed_txids);
        assert_eq!(first.len(), 1);

        // A second call with the same confirmed set must find nothing --
        // the trade was already drained, proving no double-confirmation.
        let second = p.take_confirmed(&confirmed_txids);
        assert!(second.is_empty(), "already-confirmed trade must not be returned twice");
    }

    #[test]
    fn pending_trades_expire_older_than_drops_stale_unconfirmed() {
        let mut p = PendingTrades::new();
        p.stage(make_trade("tx_stale", "pairA", 10, 100));
        assert_eq!(p.len(), 1);

        // max_age_secs=0: anything staged (even microseconds ago) is stale.
        let dropped = p.expire_older_than(0);
        assert_eq!(dropped.len(), 1, "stale unconfirmed trade must be dropped (mempool eviction)");
        assert!(p.is_empty());
    }

    #[test]
    fn pending_trades_expire_older_than_keeps_fresh_entries() {
        let mut p = PendingTrades::new();
        p.stage(make_trade("tx_fresh", "pairA", 10, 100));

        // A large horizon must NOT expire a just-staged trade.
        let dropped = p.expire_older_than(3600);
        assert!(dropped.is_empty());
        assert_eq!(p.len(), 1, "fresh staged trade must survive a generous horizon");
    }
}
