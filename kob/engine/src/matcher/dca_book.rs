//! DCA (Dollar-Cost Averaging) order tracker.
//!
//! Tracks on-chain DCA V2 UTXOs (315B RS) and exposes executable orders
//! to the scan cycle for permissionless auto-fill.
//!
//! Unlike spot orders, DCA orders don't participate in regular bid/ask
//! matching. They are time-gated (CLTV) and filled when
//! `next_execution_daa <= current_daa_score`.

use std::collections::HashMap;
use tracing::{debug, info};

/// A tracked DCA order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DcaEntry {
    /// Transaction ID of the DCA UTXO.
    pub tx_id: String,
    /// Output index.
    pub index: u32,
    /// UTXO value (sompi locked in the DCA contract).
    pub value: u64,
    /// Target token covenant ID (hex).
    pub target_cov_id: String,
    /// Price numerator.
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
    /// KAS to spend per period (sompi).
    pub amount_per_period: u64,
    /// DAA score interval between periods.
    pub interval_daa: u64,
    /// Earliest DAA score for next execution.
    pub next_execution_daa: u64,
    /// Number of periods remaining.
    pub periods_remaining: u64,
    /// Owner hash (hex).
    pub owner_hash: String,
    /// RedeemScript (hex).
    pub redeem_script_hex: String,
    /// P2SH script (hex, for address derivation).
    pub p2sh_script_hex: String,
    /// P2SH version.
    pub p2sh_version: u16,
    /// DAA score when this entry was discovered.
    pub discovered_daa: u64,
}

impl DcaEntry {
    /// Outpoint key in "txId:index" format.
    pub fn outpoint_key(&self) -> String {
        format!("{}:{}", self.tx_id, self.index)
    }

    /// Check if this DCA order is executable at the given DAA score.
    pub fn is_executable(&self, current_daa: u64) -> bool {
        self.periods_remaining > 0 && current_daa >= self.next_execution_daa
    }
}

/// In-memory DCA order tracker.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DcaBook {
    /// DCA entries keyed by outpoint ("txId:index").
    entries: HashMap<String, DcaEntry>,
}

impl DcaBook {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Add a DCA entry. Returns true if newly inserted.
    pub fn add(&mut self, entry: DcaEntry) -> bool {
        let key = entry.outpoint_key();
        if self.entries.contains_key(&key) {
            return false;
        }
        info!(
            "[DCA] Tracked DCA order: {} (periods={}, next_exec={}, amt/period={})",
            &key[..key.len().min(20)],
            entry.periods_remaining,
            entry.next_execution_daa,
            entry.amount_per_period,
        );
        self.entries.insert(key, entry);
        true
    }

    /// Remove a DCA entry by outpoint key.
    pub fn remove(&mut self, key: &str) -> Option<DcaEntry> {
        let removed = self.entries.remove(key);
        if removed.is_some() {
            debug!("[DCA] Removed DCA order: {}", &key[..key.len().min(20)]);
        }
        removed
    }

    /// Check if an outpoint is tracked.
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Get all outpoint keys (for spent detection).
    pub fn all_outpoint_keys(&self) -> std::collections::HashSet<String> {
        self.entries.keys().cloned().collect()
    }

    /// Return all DCA entries that are executable at the given DAA score.
    pub fn executable_entries(&self, current_daa: u64) -> Vec<DcaEntry> {
        self.entries
            .values()
            .filter(|e| e.is_executable(current_daa))
            .cloned()
            .collect()
    }

    /// Number of tracked DCA orders.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the book is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> DcaEntry {
        DcaEntry {
            tx_id: "abcd1234".to_string(),
            index: 0,
            value: 500_000_000,
            target_cov_id: "ff".repeat(32),
            price_num: 100,
            price_den: 1,
            amount_per_period: 100_000_000,
            interval_daa: 1000,
            next_execution_daa: 5000,
            periods_remaining: 5,
            owner_hash: "aa".repeat(32),
            redeem_script_hex: "00".repeat(315),
            p2sh_script_hex: "00".repeat(35),
            p2sh_version: 0,
            discovered_daa: 4000,
        }
    }

    #[test]
    fn add_and_remove() {
        let mut book = DcaBook::new();
        let e = sample_entry();
        assert!(book.add(e.clone()));
        assert!(!book.add(e.clone())); // dedup
        assert_eq!(book.len(), 1);
        assert!(book.contains("abcd1234:0"));
        book.remove("abcd1234:0");
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn executable_at_daa() {
        let mut book = DcaBook::new();
        let e = sample_entry();
        book.add(e);
        assert!(book.executable_entries(4999).is_empty());
        assert_eq!(book.executable_entries(5000).len(), 1);
        assert_eq!(book.executable_entries(6000).len(), 1);
    }

    #[test]
    fn not_executable_zero_periods() {
        let mut book = DcaBook::new();
        let mut e = sample_entry();
        e.periods_remaining = 0;
        book.add(e);
        assert!(book.executable_entries(9999).is_empty());
    }
}
