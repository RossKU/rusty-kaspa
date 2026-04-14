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

/// A single executed trade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub txid: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trade(txid: &str, pair: &str, price_num: u64, daa: u64) -> Trade {
        Trade {
            txid: txid.to_string(),
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
}
