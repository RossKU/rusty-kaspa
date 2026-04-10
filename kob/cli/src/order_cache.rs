//! Unified order cache for kob-cli.
//!
//! All commands that read or write `orders.json` use this single struct.
//! The on-disk format is `{"orders": [...]}` (wrapped), which is what
//! `OrderCache` serialises to.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A single cached order entry stored in orders.json.
///
/// Contains all parameters needed to reconstruct the redeemScript for
/// cancelling, matching, or querying an order.
///
/// Also carries cancel-specific fields (`token`, `version`, `expiry_daa`) so
/// that the same cache file can drive `cancel`, `cancel-all`, `auto-match`,
/// `my-orders`, `orderbook`, and `history` without format mismatches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderCacheEntry {
    pub outpoint: String,
    pub side: String,
    /// Pair identifier (token covenant ID hex, 64 chars).
    /// Defaults to empty string for legacy entries.
    #[serde(default)]
    pub pair_id: String,
    pub price_num: u64,
    pub price_den: u64,
    pub min_fill: u64,
    /// Blake2b-256 hash of the owner pubkey (hex).
    #[serde(default)]
    pub owner_hash: String,
    /// P2PK script-public-key hash of the owner (hex).
    #[serde(default)]
    pub spk_hash: String,
    /// P2SH script hash of the deployed order UTXO (hex).
    #[serde(default)]
    pub p2sh_hash: String,
    pub value: u64,
    /// Whether the order was marked for cancellation (cpend=1).
    /// Used as a heuristic: if cancel_pending was true when the order
    /// was spent, it was likely cancelled rather than filled.
    #[serde(default)]
    pub cancel_pending: bool,
    /// Token covenant ID (hex, 64 chars). Present for buy orders.
    /// Used by cancel and cancel-all to reconstruct the redeemScript.
    #[serde(default)]
    pub token: Option<String>,
    /// Contract version (only 13 supported).
    #[serde(default = "default_cache_version")]
    pub version: u8,
    /// Expiry DAA score (v13 only, 0 = GTC).
    #[serde(default)]
    pub expiry_daa: u64,
}

fn default_cache_version() -> u8 {
    13
}

/// Persistent order cache file.
///
/// On-disk format: `{"orders": [...]}`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrderCache {
    pub orders: Vec<OrderCacheEntry>,
}

impl OrderCache {
    /// Load order cache from a JSON file. Returns empty cache if file doesn't exist.
    ///
    /// Accepts two formats:
    /// - `{"orders": [...]}` (canonical `OrderCache` format)
    /// - `[...]` (legacy flat `CachedOrder` array written by older deploy)
    ///
    /// Legacy entries are converted on the fly; missing hash fields default to
    /// empty strings.
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        // Try canonical format first.
        if let Ok(cache) = serde_json::from_str::<OrderCache>(&contents) {
            return cache;
        }
        // Try legacy flat array of CachedOrder (from cancel_all module).
        if let Ok(legacy) = serde_json::from_str::<Vec<crate::cancel_all::CachedOrder>>(&contents) {
            return Self {
                orders: legacy.into_iter().map(OrderCacheEntry::from).collect(),
            };
        }
        Self::default()
    }

    /// Save order cache to a JSON file (wrapped format).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Build a lookup table: P2SH hash -> cache entry.
    pub fn by_p2sh_hash(&self) -> HashMap<String, &OrderCacheEntry> {
        self.orders.iter().map(|o| (o.p2sh_hash.clone(), o)).collect()
    }

    /// Remove entries for a given outpoint (order was matched or cancelled).
    #[allow(dead_code)] // Public API: used by auto-match loop
    pub fn remove_outpoint(&mut self, outpoint: &str) {
        self.orders.retain(|o| o.outpoint != outpoint);
    }
}

/// Convert a legacy `CachedOrder` into the unified `OrderCacheEntry`.
///
/// Hash fields (`owner_hash`, `spk_hash`, `p2sh_hash`) are left empty
/// because the legacy format doesn't carry them. They can be recomputed
/// from the wallet pubkey when needed.
impl From<crate::cancel_all::CachedOrder> for OrderCacheEntry {
    fn from(c: crate::cancel_all::CachedOrder) -> Self {
        Self {
            outpoint: c.outpoint,
            side: c.side,
            pair_id: c.token.clone().unwrap_or_else(|| "00".repeat(32)),
            price_num: c.price_num,
            price_den: c.price_den,
            min_fill: c.min_fill,
            owner_hash: String::new(),
            spk_hash: String::new(),
            p2sh_hash: String::new(),
            value: c.value,
            cancel_pending: false,
            token: c.token,
            version: c.version,
            expiry_daa: c.expiry_daa,
        }
    }
}

/// Derive the orders.json cache path from a wallet file path.
///
/// Returns `<wallet_dir>/orders.json`. If the wallet path has no parent
/// directory, falls back to `./orders.json`.
pub fn orders_cache_path(wallet_path: &Path) -> std::path::PathBuf {
    wallet_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("orders.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_cache_entry_serialization_roundtrip() {
        let entry = OrderCacheEntry {
            outpoint: "abc123:0".into(),
            side: "buy".into(),
            pair_id: "ff".repeat(32),
            price_num: 100,
            price_den: 1,
            min_fill: 1_000_000,
            owner_hash: "aa".repeat(32),
            spk_hash: "bb".repeat(32),
            p2sh_hash: "cc".repeat(32),
            value: 50_000_000,
            token: Some("ff".repeat(32)),
            version: 13,
            expiry_daa: 0,
            cancel_pending: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: OrderCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.outpoint, "abc123:0");
        assert_eq!(decoded.side, "buy");
        assert_eq!(decoded.price_num, 100);
        assert_eq!(decoded.version, 13);
    }

    #[test]
    fn order_cache_entry_default_version() {
        let json = r#"{
            "outpoint": "abc:0",
            "side": "sell",
            "price_num": 1,
            "price_den": 2,
            "min_fill": 100,
            "value": 5000000
        }"#;
        let entry: OrderCacheEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.version, 13, "default version must be 13");
    }

    #[test]
    fn order_cache_default_empty() {
        let cache = OrderCache::default();
        assert!(cache.orders.is_empty());
    }

    #[test]
    fn order_cache_load_nonexistent() {
        let cache = OrderCache::load(Path::new("/tmp/kob_nonexistent_cache.json"));
        assert!(cache.orders.is_empty());
    }

    #[test]
    fn order_cache_save_load_roundtrip() {
        let mut cache = OrderCache::default();
        cache.orders.push(OrderCacheEntry {
            outpoint: "aa".repeat(32) + ":0",
            side: "buy".to_string(),
            pair_id: "00".repeat(32),
            price_num: 1000,
            price_den: 1,
            min_fill: 3_000_000,
            owner_hash: "bb".repeat(32),
            spk_hash: "cc".repeat(32),
            p2sh_hash: "dd".repeat(32),
            value: 10_000_000,
            token: None,
            version: 13,
            expiry_daa: 0,
            cancel_pending: false,
        });

        let path = &std::env::temp_dir().join("kob_test_order_cache.json");
        cache.save(path).unwrap();

        let loaded = OrderCache::load(path);
        assert_eq!(loaded.orders.len(), 1);
        assert_eq!(loaded.orders[0].price_num, 1000);
        assert_eq!(loaded.orders[0].side, "buy");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn order_cache_load_legacy_flat_array() {
        let json = r#"[
            {
                "outpoint": "abc:0",
                "side": "buy",
                "price_num": 100,
                "price_den": 1,
                "min_fill": 1000,
                "value": 5000000,
                "token": null
            }
        ]"#;
        let path = &std::env::temp_dir().join("kob_test_legacy_flat_oc.json");
        std::fs::write(path, json).unwrap();

        let cache = OrderCache::load(path);
        assert_eq!(cache.orders.len(), 1);
        assert_eq!(cache.orders[0].outpoint, "abc:0");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn order_cache_by_p2sh_hash() {
        let mut cache = OrderCache::default();
        cache.orders.push(OrderCacheEntry {
            outpoint: "aa".repeat(32) + ":0",
            side: "buy".to_string(),
            pair_id: "00".repeat(32),
            price_num: 1000,
            price_den: 1,
            min_fill: 3_000_000,
            owner_hash: "bb".repeat(32),
            spk_hash: "cc".repeat(32),
            p2sh_hash: "dd".repeat(32),
            value: 10_000_000,
            token: None,
            version: 13,
            expiry_daa: 0,
            cancel_pending: false,
        });

        let lookup = cache.by_p2sh_hash();
        assert_eq!(lookup.len(), 1);
        assert!(lookup.contains_key(&"dd".repeat(32)));
    }

    #[test]
    fn order_cache_remove_outpoint() {
        let mut cache = OrderCache::default();
        let op = "aa".repeat(32) + ":0";
        cache.orders.push(OrderCacheEntry {
            outpoint: op.clone(),
            side: "buy".to_string(),
            pair_id: "00".repeat(32),
            price_num: 1000,
            price_den: 1,
            min_fill: 3_000_000,
            owner_hash: "bb".repeat(32),
            spk_hash: "cc".repeat(32),
            p2sh_hash: "dd".repeat(32),
            value: 10_000_000,
            token: None,
            version: 13,
            expiry_daa: 0,
            cancel_pending: false,
        });
        cache.orders.push(OrderCacheEntry {
            outpoint: "ee".repeat(32) + ":1",
            side: "sell".to_string(),
            pair_id: "00".repeat(32),
            price_num: 1100,
            price_den: 1,
            min_fill: 3_000_000,
            owner_hash: "bb".repeat(32),
            spk_hash: "cc".repeat(32),
            p2sh_hash: "ff".repeat(32),
            value: 10_000_000,
            token: None,
            version: 13,
            expiry_daa: 0,
            cancel_pending: false,
        });

        assert_eq!(cache.orders.len(), 2);
        cache.remove_outpoint(&op);
        assert_eq!(cache.orders.len(), 1);
        assert_eq!(cache.orders[0].side, "sell");
    }

    #[test]
    fn orders_cache_path_from_wallet() {
        let wallet = Path::new("/tmp/wallets/w0.json");
        let cache = orders_cache_path(wallet);
        assert_eq!(cache, Path::new("/tmp/wallets/orders.json"));
    }
}
