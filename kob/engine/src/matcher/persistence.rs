//! Order book persistence (JSON serialization and L1 sync).

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::matcher::order_book::{BookOrder, OrderBook, OrderSide};
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};

/// Persistence format for a single order.
#[derive(Debug, Serialize, Deserialize)]
struct PersistOrder {
    #[serde(rename = "txId")]
    tx_id: String,
    index: u32,
    value: u64,
    #[serde(rename = "priceNum")]
    price_num: u64,
    #[serde(rename = "priceDen")]
    price_den: u64,
    #[serde(rename = "minFill")]
    min_fill: u64,
    #[serde(rename = "ownerHash")]
    owner_hash: String,
    /// Blake2b-256(counterparty SPK) embedded in the RS (hex, 64 chars).
    /// For buy orders: buyer's SPK hash (bspkh).
    /// For sell orders: seller's SPK hash (sspkh).
    #[serde(rename = "spkHash", default)]
    spk_hash: String,
    /// Actual counterparty SPK bytes (hex). Required for the matcher to build
    /// valid match TX outputs. Absent for orders deployed with payload v1.
    #[serde(rename = "counterpartySpk", default)]
    counterparty_spk: Option<String>,
    /// RedeemScript (hex)
    #[serde(rename = "redeemScript", default)]
    redeem_script: String,
    /// P2SH script (hex)
    #[serde(rename = "p2shScript", default)]
    p2sh_script: String,
    /// P2SH version
    #[serde(rename = "p2shVersion", default)]
    p2sh_version: u16,
    /// Post-only flag (Matcher-level policy, not in L1 covenant).
    #[serde(rename = "postOnly", default)]
    post_only: Option<bool>,
    /// GTD expiry DAA score. None/absent = GTC (no expiry).
    /// Backward-compatible: missing field in old JSON deserializes as None.
    #[serde(rename = "expiryDaa", default, skip_serializing_if = "Option::is_none")]
    expiry_daa: Option<u64>,
    /// True if order involves a freezable token (0xa6 in RS).
    /// Backward-compatible: defaults to false if absent in JSON.
    #[serde(rename = "isFreezable", default)]
    is_freezable: bool,
    /// Maximum matcher fee (sompi). Defaults to u64::MAX (unlimited) for
    /// backward compatibility with persisted orders that lack this field.
    #[serde(rename = "maxMatcherFee", default = "persist_default_mmfee")]
    max_matcher_fee: u64,
    #[serde(rename = "ifdOrderBRsHex", default, skip_serializing_if = "Option::is_none")]
    ifd_order_b_rs_hex: Option<String>,
}

fn persist_default_mmfee() -> u64 {
    u64::MAX
}

/// Persistence format for a pair book.
#[derive(Debug, Serialize, Deserialize)]
struct PersistPairBook {
    bids: HashMap<String, PersistOrder>,
    asks: HashMap<String, PersistOrder>,
}

/// Save the order book to a JSON file.
pub fn save_order_book(path: &str, order_book: &OrderBook) -> Result<(), String> {
    let mut data: HashMap<String, PersistPairBook> = HashMap::new();

    for (token_cov_id, book) in &order_book.pair_books {
        let mut bids = HashMap::new();
        for order in book.bids.values() {
            bids.insert(
                order.outpoint_key(),
                PersistOrder {
                    tx_id: order.tx_id.clone(),
                    index: order.index,
                    value: order.value,
                    price_num: order.price_num,
                    price_den: order.price_den,
                    min_fill: order.min_fill,
                    owner_hash: order.owner_hash.clone(),
                    spk_hash: order.spk_hash.clone(),
                    counterparty_spk: order.counterparty_spk.clone(),
                    redeem_script: order.redeem_script_hex.clone(),
                    p2sh_script: order.p2sh_script_hex.clone(),
                    p2sh_version: order.p2sh_version,
                    post_only: Some(order.post_only),
                    expiry_daa: order.expiry_daa,
                    is_freezable: order.is_freezable,
                    max_matcher_fee: order.max_matcher_fee,
                    ifd_order_b_rs_hex: order.ifd_order_b_rs_hex.clone(),
                },
            );
        }

        let mut asks = HashMap::new();
        for order in book.asks.values() {
            asks.insert(
                order.outpoint_key(),
                PersistOrder {
                    tx_id: order.tx_id.clone(),
                    index: order.index,
                    value: order.value,
                    price_num: order.price_num,
                    price_den: order.price_den,
                    min_fill: order.min_fill,
                    owner_hash: order.owner_hash.clone(),
                    spk_hash: order.spk_hash.clone(),
                    counterparty_spk: order.counterparty_spk.clone(),
                    redeem_script: order.redeem_script_hex.clone(),
                    p2sh_script: order.p2sh_script_hex.clone(),
                    p2sh_version: order.p2sh_version,
                    post_only: Some(order.post_only),
                    expiry_daa: order.expiry_daa,
                    is_freezable: order.is_freezable,
                    max_matcher_fee: order.max_matcher_fee,
                    ifd_order_b_rs_hex: order.ifd_order_b_rs_hex.clone(),
                },
            );
        }

        data.insert(token_cov_id.clone(), PersistPairBook { bids, asks });
    }

    let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;

    // Atomic write: write to temp file then rename (I-5 fix).
    // This prevents corruption if the process crashes mid-write.
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {} -> {}: {}", tmp_path, path, e))?;
    info!("[ORDER BOOK] Saved to disk ({})", path);
    Ok(())
}

/// Load the order book from a JSON file.
pub async fn load_order_book(
    path: &str,
    order_book: &Arc<Mutex<OrderBook>>,
) -> Result<(), String> {
    let path_ref = std::path::Path::new(path);
    if !path_ref.exists() {
        info!("[ORDER BOOK] No persisted file found at {}", path);
        return Ok(());
    }

    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;

    let data: HashMap<String, PersistPairBook> =
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse {}: {}", path, e))?;

    let mut ob = order_book.lock().await;
    let mut loaded = 0u32;

    for (token_cov_id, pair_book) in data {
        for (key, order) in pair_book.bids {
            if order.price_num == 0 || order.price_den == 0 {
                warn!(
                    "[ORDER BOOK] Skipping persisted BUY order {} with invalid price ({}/{})",
                    key, order.price_num, order.price_den
                );
                continue;
            }
            ob.add_buy_order(BookOrder {
                tx_id: order.tx_id,
                index: order.index,
                value: order.value,
                token_cov_id: token_cov_id.clone(),
                price_num: order.price_num,
                price_den: order.price_den,
                min_fill: order.min_fill,
                owner_hash: order.owner_hash,
                spk_hash: order.spk_hash,
                counterparty_spk: order.counterparty_spk,
                redeem_script_hex: order.redeem_script,
                p2sh_script_hex: order.p2sh_script,
                p2sh_version: order.p2sh_version,
                side: OrderSide::Buy,
                post_only: order.post_only.unwrap_or(false),
                expiry_daa: order.expiry_daa,
                is_freezable: order.is_freezable,
                max_matcher_fee: order.max_matcher_fee,
                ifd_order_b_rs_hex: order.ifd_order_b_rs_hex,
            });
            loaded += 1;
        }

        for (key, order) in pair_book.asks {
            if order.price_num == 0 || order.price_den == 0 {
                warn!(
                    "[ORDER BOOK] Skipping persisted SELL order {} with invalid price ({}/{})",
                    key, order.price_num, order.price_den
                );
                continue;
            }
            ob.add_sell_order(BookOrder {
                tx_id: order.tx_id,
                index: order.index,
                value: order.value,
                token_cov_id: token_cov_id.clone(),
                price_num: order.price_num,
                price_den: order.price_den,
                min_fill: order.min_fill,
                owner_hash: order.owner_hash,
                spk_hash: order.spk_hash,
                counterparty_spk: order.counterparty_spk,
                redeem_script_hex: order.redeem_script,
                p2sh_script_hex: order.p2sh_script,
                p2sh_version: order.p2sh_version,
                side: OrderSide::Sell,
                post_only: order.post_only.unwrap_or(false),
                expiry_daa: order.expiry_daa,
                is_freezable: order.is_freezable,
                max_matcher_fee: order.max_matcher_fee,
                ifd_order_b_rs_hex: order.ifd_order_b_rs_hex,
            });
            loaded += 1;
        }
    }

    info!("[ORDER BOOK] Loaded {} orders from disk ({})", loaded, path);
    Ok(())
}

/// Validate persisted orders against the live UTXO set and prune any whose
/// UTXOs no longer exist on-chain.
///
/// Called once at startup after `load_order_book`, before the matching loop
/// begins. Without this check a stale order whose UTXO was spent while the
/// matcher was offline would sit in the book forever: it would keep crossing
/// against a valid counterpart, `execute_match` would fail every cycle (the
/// node rejects the TX because one input doesn't exist), and the error would
/// be retried indefinitely generating noisy logs and wasted RPC traffic.
///
/// Strategy: batch all order P2SH addresses and query `getUtxosByAddresses`
/// in one RPC call. Any order whose outpoint is absent from the response is
/// dropped. The wallet address prefix ("kaspatest" / "kaspa") is inferred
/// from `wallet_address`.
pub async fn validate_and_prune_order_book(
    rpc: &RpcClient,
    order_book: &Arc<Mutex<OrderBook>>,
    wallet_address: &str,
) {
    let prefix = wallet_address
        .split(':')
        .next()
        .unwrap_or("kaspa")
        .to_string();

    // Collect all orders and their P2SH addresses.
    let orders: Vec<(String, String, String)> = {
        let ob = order_book.lock().await;
        let mut out = Vec::new();
        for book in ob.pair_books.values() {
            for order in book.bids.values() {
                let spk = order.p2sh_script();
                let addr = p2sh_to_address(&spk, &prefix);
                out.push((order.outpoint_key(), addr, order.tx_id.clone()));
            }
            for order in book.asks.values() {
                let spk = order.p2sh_script();
                let addr = p2sh_to_address(&spk, &prefix);
                out.push((order.outpoint_key(), addr, order.tx_id.clone()));
            }
        }
        out
    };

    if orders.is_empty() {
        return;
    }

    // Deduplicate addresses for a single batched RPC call.
    let mut addr_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, addr, _) in &orders {
        addr_set.insert(addr.clone());
    }
    let addr_refs: Vec<&str> = addr_set.iter().map(|s| s.as_str()).collect();

    info!(
        "[PRUNE] Validating {} persisted orders ({} P2SH addresses) against UTXO set ...",
        orders.len(),
        addr_refs.len()
    );

    let utxos = match rpc.get_utxos_by_addresses(&addr_refs).await {
        Ok(u) => u,
        Err(e) => {
            warn!(
                "[PRUNE] UTXO validation skipped (RPC error: {}). \
                 Persisted orders kept as-is; stale ones will fail on first match attempt.",
                e
            );
            return;
        }
    };

    // Build a set of live outpoint keys (txid:index).
    let live: std::collections::HashSet<String> = utxos
        .iter()
        .map(|u| format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index))
        .collect();

    // Prune orders not in the live set.
    let mut pruned = 0u32;
    {
        let mut ob = order_book.lock().await;
        for (outpoint_key, _, _) in &orders {
            if !live.contains(outpoint_key) {
                ob.remove_order(outpoint_key);
                warn!("[PRUNE] Removed stale persisted order: {}", &outpoint_key[..outpoint_key.len().min(20)]);
                pruned += 1;
            }
        }
    }

    info!(
        "[PRUNE] Validation complete: {} order(s) pruned, {} live",
        pruned,
        orders.len() as u32 - pruned
    );
}

// P2SH address helpers (inline hex fallback — no bech32 dependency).

fn p2sh_to_address(spk: &[u8], prefix: &str) -> String {
    format!("{}:p{}", prefix, hex::encode(spk))
}


// Perp book persistence

/// Save the perp order book to a JSON file (atomic write).
pub fn save_perp_book(path: &str, book: &crate::matcher::perp_book::PerpOrderBook) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&book.to_json()).map_err(|e| e.to_string())?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {} -> {}: {}", tmp_path, path, e))?;
    info!("[PERP BOOK] Saved to disk ({})", path);
    Ok(())
}

/// Load the perp order book from a JSON file.
pub fn load_perp_book(path: &str) -> Result<crate::matcher::perp_book::PerpOrderBook, String> {
    let path_ref = std::path::Path::new(path);
    if !path_ref.exists() {
        info!("[PERP BOOK] No persisted file found at {}", path);
        return Ok(crate::matcher::perp_book::PerpOrderBook::new());
    }
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse {}: {}", path, e))?;
    let book = crate::matcher::perp_book::PerpOrderBook::from_json(&json)
        .ok_or_else(|| format!("Invalid perp book JSON structure in {}", path))?;
    info!("[PERP BOOK] Loaded from {} ({} longs, {} shorts)", path, book.long_count(), book.short_count());
    Ok(book)
}

// Lending book persistence

/// Save the lending order book to a JSON file (atomic write).
pub fn save_lending_book(path: &str, book: &crate::matcher::lending_book::LendingBook) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&book.to_json()).map_err(|e| e.to_string())?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {} -> {}: {}", tmp_path, path, e))?;
    info!("[LENDING BOOK] Saved to disk ({})", path);
    Ok(())
}

/// Load the lending order book from a JSON file.
pub fn load_lending_book(path: &str) -> Result<crate::matcher::lending_book::LendingBook, String> {
    let path_ref = std::path::Path::new(path);
    if !path_ref.exists() {
        info!("[LENDING BOOK] No persisted file found at {}", path);
        return Ok(crate::matcher::lending_book::LendingBook::new());
    }
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse {}: {}", path, e))?;
    let book = crate::matcher::lending_book::LendingBook::from_json(&json)
        .ok_or_else(|| format!("Invalid lending book JSON structure in {}", path))?;
    info!("[LENDING BOOK] Loaded from {} ({} offers, {} requests)", path, book.offer_count(), book.request_count());
    Ok(book)
}

// Prediction book persistence

/// Save the prediction book to a JSON file (atomic write).
pub fn save_prediction_book(path: &str, book: &crate::matcher::prediction_book::PredictionBook) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&book.to_json()).map_err(|e| e.to_string())?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {} -> {}: {}", tmp_path, path, e))?;
    info!("[PREDICTION BOOK] Saved to disk ({})", path);
    Ok(())
}

/// Load the prediction book from a JSON file.
pub fn load_prediction_book(path: &str) -> Result<crate::matcher::prediction_book::PredictionBook, String> {
    let path_ref = std::path::Path::new(path);
    if !path_ref.exists() {
        info!("[PREDICTION BOOK] No persisted file found at {}", path);
        return Ok(crate::matcher::prediction_book::PredictionBook::new());
    }
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse {}: {}", path, e))?;
    let book = crate::matcher::prediction_book::PredictionBook::from_json(&json)
        .ok_or_else(|| format!("Invalid prediction book JSON structure in {}", path))?;
    info!("[PREDICTION BOOK] Loaded from {} ({} markets)", path, book.market_count());
    Ok(book)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_save_order_book_atomic_write() {
        // Verify that save_order_book uses atomic write (write tmp + rename).
        // After save, the .tmp file should NOT exist (renamed away).
        let dir = std::env::temp_dir();
        let path = dir.join("test_atomic_orderbook.json");
        let path_str = path.to_str().unwrap();
        let tmp_path = format!("{}.tmp", path_str);

        let order_book = OrderBook::new();
        save_order_book(path_str, &order_book).unwrap();

        // Main file should exist
        assert!(path.exists(), "orderbook file should exist");

        // Temp file should NOT exist (was renamed)
        assert!(
            !std::path::Path::new(&tmp_path).exists(),
            ".tmp file should not exist after atomic rename"
        );

        // File should be valid JSON
        let mut content = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.is_object());

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_save_order_book_overwrites_existing() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_atomic_overwrite.json");
        let path_str = path.to_str().unwrap();

        // Write initial content
        std::fs::write(&path, "old data").unwrap();

        let order_book = OrderBook::new();
        save_order_book(path_str, &order_book).unwrap();

        // Content should be new JSON, not "old data"
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with('{'), "should be JSON, got: {}", &content[..20.min(content.len())]);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
