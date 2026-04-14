//! Swap order tracker.
//!
//! Tracks on-chain swap covenant UTXOs (243B RS) and exposes them to the
//! scan cycle for cross-book routing. Unlike spot orders, swap orders
//! do not participate in same-token bid/ask matching. They are routed
//! through TWO token books (source TOKEN/KAS and target TOKEN/KAS).

use std::collections::HashMap;
use tracing::{debug, info};

/// A tracked swap order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapEntry {
    /// Transaction ID of the swap UTXO.
    pub tx_id: String,
    /// Output index.
    pub index: u32,
    /// UTXO value (source tokens locked in the swap covenant).
    pub value: u64,
    /// Source token covenant ID (hex) — what the user is selling.
    pub source_cov_id: String,
    /// Target token covenant ID (hex) — what the user wants.
    pub target_cov_id: String,
    /// Minimum target tokens to receive.
    pub min_target_amount: u64,
    /// Owner hash (hex).
    pub owner_hash: String,
    /// Owner SPK hash (hex).
    pub owner_spk_hash: String,
    /// Receipt covenant ID (hex).
    pub receipt_cov_id: String,
    /// RedeemScript (hex).
    pub redeem_script_hex: String,
    /// P2SH script (hex, for address derivation).
    pub p2sh_script_hex: String,
    /// P2SH version.
    pub p2sh_version: u16,
    /// DAA score when this entry was discovered.
    pub discovered_daa: u64,
    /// Owner's actual scriptPublicKey (hex: 2B version LE + script bytes).
    ///
    /// Extracted from the swap deploy TX outputs by matching
    /// `compute_spk_hash(spk) == owner_spk_hash`. Required for building
    /// the target token output in the swap fill TX.
    pub owner_spk: Option<String>,
}

impl SwapEntry {
    /// Outpoint key in "txId:index" format.
    pub fn outpoint_key(&self) -> String {
        format!("{}:{}", self.tx_id, self.index)
    }
}

/// In-memory swap order tracker.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SwapBook {
    /// Swap entries keyed by outpoint ("txId:index").
    entries: HashMap<String, SwapEntry>,
}

impl SwapBook {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Add a swap entry. Returns true if newly inserted.
    pub fn add(&mut self, entry: SwapEntry) -> bool {
        let key = entry.outpoint_key();
        if self.entries.contains_key(&key) {
            return false;
        }
        info!(
            "[SWAP] Tracked swap order: {} (source={}, target={}, min_ta={})",
            &key[..key.len().min(20)],
            &entry.source_cov_id[..entry.source_cov_id.len().min(12)],
            &entry.target_cov_id[..entry.target_cov_id.len().min(12)],
            entry.min_target_amount,
        );
        self.entries.insert(key, entry);
        true
    }

    /// Remove a swap entry by outpoint key.
    pub fn remove(&mut self, key: &str) -> Option<SwapEntry> {
        let removed = self.entries.remove(key);
        if removed.is_some() {
            debug!("[SWAP] Removed swap order: {}", &key[..key.len().min(20)]);
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

    /// Return all swap entries (for routing iteration).
    pub fn all_entries(&self) -> Vec<&SwapEntry> {
        self.entries.values().collect()
    }

    /// Return entries by source token covenant ID.
    pub fn entries_by_source(&self, source_cov_id: &str) -> Vec<&SwapEntry> {
        self.entries
            .values()
            .filter(|e| e.source_cov_id == source_cov_id)
            .collect()
    }

    /// Number of tracked swap orders.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the book is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize to JSON value for persistence.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.entries).unwrap_or(serde_json::Value::Null)
    }

    /// Deserialize from JSON value.
    pub fn from_json(val: &serde_json::Value) -> Option<Self> {
        let entries: HashMap<String, SwapEntry> = serde_json::from_value(val.clone()).ok()?;
        Some(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> SwapEntry {
        SwapEntry {
            tx_id: "abcd1234".to_string(),
            index: 0,
            value: 500_000_000,
            source_cov_id: "aa".repeat(32),
            target_cov_id: "bb".repeat(32),
            min_target_amount: 1_000_000,
            owner_hash: "cc".repeat(32),
            owner_spk_hash: "dd".repeat(32),
            receipt_cov_id: "ee".repeat(32),
            redeem_script_hex: "00".repeat(243),
            p2sh_script_hex: "00".repeat(35),
            p2sh_version: 0,
            discovered_daa: 4000,
            owner_spk: None,
        }
    }

    #[test]
    fn add_and_remove() {
        let mut book = SwapBook::new();
        let e = sample_entry();
        assert!(book.add(e.clone()));
        assert!(!book.add(e.clone())); // dedup
        assert_eq!(book.len(), 1);
        assert!(book.contains("abcd1234:0"));
        book.remove("abcd1234:0");
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn entries_by_source() {
        let mut book = SwapBook::new();
        let e1 = sample_entry();
        let mut e2 = sample_entry();
        e2.tx_id = "ffff5678".to_string();
        e2.source_cov_id = "11".repeat(32);
        book.add(e1);
        book.add(e2);
        assert_eq!(book.entries_by_source(&"aa".repeat(32)).len(), 1);
        assert_eq!(book.entries_by_source(&"11".repeat(32)).len(), 1);
        assert_eq!(book.entries_by_source(&"99".repeat(32)).len(), 0);
    }

    #[test]
    fn json_roundtrip() {
        let mut book = SwapBook::new();
        book.add(sample_entry());
        let json = book.to_json();
        let loaded = SwapBook::from_json(&json).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains("abcd1234:0"));
    }
}
