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
    /// Contract version (v18).
    #[serde(default = "default_cache_version")]
    pub version: u8,
    /// Expiry DAA score (0 = GTC).
    #[serde(default)]
    pub expiry_daa: u64,
    /// Max matcher fee cap embedded in the redeemScript (BPS in v18).
    #[serde(default = "default_max_matcher_fee")]
    pub max_matcher_fee: u64,
    /// The exact redeemScript bytes (hex) that were deployed on-chain, if
    /// known.
    ///
    /// Populated verbatim at deploy time from the same bytes used to build
    /// the on-chain P2SH output (`deploy.rs`), so it can never diverge from
    /// `p2sh_hash`. Reconstructing the redeemScript from this entry's other
    /// (decomposed) fields is lossy -- it hardcodes the owner batch cap
    /// (`--n-max`/`--batch-max`) and derives the E1 expire-seat SPK hash
    /// from the CURRENTLY RUNNING wallet, both of which can silently differ
    /// from what was actually deployed. Callers that need the real
    /// redeemScript (matching, spending) should prefer this field over
    /// reconstruction whenever it's present. `None` for cache entries
    /// written before this field existed, or by code paths that never had
    /// the exact bytes (e.g. `recover`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<String>,
}

fn default_cache_version() -> u8 {
    18
}

fn default_max_matcher_fee() -> u64 {
    crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS
}

/// Which source supplied the redeemScript bytes used for one side of a
/// match (or cancel/spend of any kind that reads the order cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsSource {
    /// An explicit CLI override (e.g. `--sell-rs`/`--buy-rs`). Always wins:
    /// the operator is asserting ground truth.
    Override,
    /// The cache entry's `redeem_script` field, recorded verbatim at deploy
    /// time. Cannot diverge from the on-chain script.
    Cached,
    /// Reconstructed from the cache entry's decomposed fields. See the
    /// `OrderCacheEntry::redeem_script` doc comment for why this can
    /// silently diverge from the deployed script.
    Reconstructed,
}

/// Resolve which RS source to use for one side of a match, given whether an
/// explicit override was supplied and whether the cache carries a
/// `redeem_script` for this entry.
///
/// Precedence: override > cached > reconstructed. `match-batch` has CLI
/// override flags (`--sell-rs`/`--buy-rs`); `match` (singular) has none, so
/// its callers always pass `has_override = false`.
pub fn select_rs_source(has_override: bool, has_cached: bool) -> RsSource {
    if has_override {
        RsSource::Override
    } else if has_cached {
        RsSource::Cached
    } else {
        RsSource::Reconstructed
    }
}

/// Verify that `rs`'s P2SH hash matches a cache-recorded `p2sh_hash` (hex).
///
/// `redeem_script` and `p2sh_hash` are written together at deploy time from
/// the same bytes and must never disagree; a mismatch means the cache entry
/// was hand-edited or corrupted some other way. Callers MUST treat a
/// mismatch as fatal rather than proceeding -- spending against the wrong
/// redeemScript either fails outright or, worse, succeeds against an
/// unrelated on-chain script.
pub fn verify_cached_rs_p2sh(rs: &[u8], p2sh_hash_hex: &str) -> anyhow::Result<()> {
    let computed = hex::encode(kob_core::p2sh::blake2b_256(rs));
    if !computed.eq_ignore_ascii_case(p2sh_hash_hex) {
        anyhow::bail!(
            "cached redeem_script's P2SH hash ({}) does not match cached p2sh_hash ({}) -- \
             corrupt orders.json cache entry",
            computed, p2sh_hash_hex
        );
    }
    Ok(())
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
            // v18 caches store BPS.
            max_matcher_fee: crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS,
            // Legacy format never carried the exact redeemScript bytes.
            redeem_script: None,
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
            version: 14,
            expiry_daa: 0,
            cancel_pending: false,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: OrderCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.outpoint, "abc123:0");
        assert_eq!(decoded.side, "buy");
        assert_eq!(decoded.price_num, 100);
        assert_eq!(decoded.version, 14);
    }

    #[test]
    fn order_cache_entry_redeem_script_roundtrip() {
        // Entry WITH redeem_script: hex round-trips and the field survives
        // serialize -> deserialize.
        let entry = OrderCacheEntry {
            outpoint: "abc123:0".into(),
            side: "sell".into(),
            pair_id: "ff".repeat(32),
            price_num: 100,
            price_den: 1,
            min_fill: 1_000_000,
            owner_hash: "aa".repeat(32),
            spk_hash: "bb".repeat(32),
            p2sh_hash: "cc".repeat(32),
            value: 50_000_000,
            token: None,
            version: 18,
            expiry_daa: 0,
            cancel_pending: false,
            max_matcher_fee: 10_000_000,
            redeem_script: Some("deadbeef".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("redeem_script"), "field must serialize when present");
        let decoded: OrderCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.redeem_script, Some("deadbeef".to_string()));
    }

    #[test]
    fn order_cache_entry_redeem_script_omitted_when_none() {
        // Entry WITHOUT redeem_script: the field is skipped on serialize
        // (compact cache files for entries that never had it) and
        // deserializes back to None.
        let entry = OrderCacheEntry {
            outpoint: "abc123:0".into(),
            side: "sell".into(),
            pair_id: "ff".repeat(32),
            price_num: 100,
            price_den: 1,
            min_fill: 1_000_000,
            owner_hash: "aa".repeat(32),
            spk_hash: "bb".repeat(32),
            p2sh_hash: "cc".repeat(32),
            value: 50_000_000,
            token: None,
            version: 18,
            expiry_daa: 0,
            cancel_pending: false,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("redeem_script"), "field must be omitted when None");
        let decoded: OrderCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.redeem_script, None);
    }

    #[test]
    fn order_cache_entry_old_format_json_without_redeem_script_field() {
        // A cache file written before this field existed must still parse,
        // with redeem_script defaulting to None.
        let json = r#"{
            "outpoint": "abc:0",
            "side": "sell",
            "price_num": 1,
            "price_den": 2,
            "min_fill": 100,
            "value": 5000000
        }"#;
        let entry: OrderCacheEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.redeem_script, None);
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
        assert_eq!(entry.version, 18, "default version must be 18");
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
            version: 14,
            expiry_daa: 0,
            cancel_pending: false,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
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
            version: 14,
            expiry_daa: 0,
            cancel_pending: false,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
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
            version: 14,
            expiry_daa: 0,
            cancel_pending: false,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
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
            version: 14,
            expiry_daa: 0,
            cancel_pending: false,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
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

    // ---- select_rs_source ----

    #[test]
    fn rs_source_override_wins_over_cached() {
        assert_eq!(select_rs_source(true, true), RsSource::Override);
    }

    #[test]
    fn rs_source_override_wins_when_nothing_cached() {
        assert_eq!(select_rs_source(true, false), RsSource::Override);
    }

    #[test]
    fn rs_source_cached_used_when_no_override() {
        assert_eq!(select_rs_source(false, true), RsSource::Cached);
    }

    #[test]
    fn rs_source_falls_back_to_reconstructed() {
        assert_eq!(select_rs_source(false, false), RsSource::Reconstructed);
    }

    // ---- verify_cached_rs_p2sh ----

    #[test]
    fn verify_cached_rs_p2sh_accepts_matching_hash() {
        let rs = b"some redeem script bytes".to_vec();
        let hash_hex = hex::encode(kob_core::p2sh::blake2b_256(&rs));
        assert!(verify_cached_rs_p2sh(&rs, &hash_hex).is_ok());
    }

    #[test]
    fn verify_cached_rs_p2sh_accepts_matching_hash_case_insensitively() {
        let rs = b"some redeem script bytes".to_vec();
        let hash_hex = hex::encode(kob_core::p2sh::blake2b_256(&rs)).to_uppercase();
        assert!(verify_cached_rs_p2sh(&rs, &hash_hex).is_ok());
    }

    #[test]
    fn verify_cached_rs_p2sh_rejects_mismatch() {
        let rs = b"some redeem script bytes".to_vec();
        let wrong_hash = "ff".repeat(32);
        let err = verify_cached_rs_p2sh(&rs, &wrong_hash).unwrap_err();
        assert!(err.to_string().contains("corrupt"));
    }
}
