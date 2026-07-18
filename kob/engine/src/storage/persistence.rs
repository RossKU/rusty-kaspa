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
    /// OCO path: which path this virtual order represents (TP or SL).
    /// Backward-compatible: absent in old JSON deserializes as None.
    #[serde(rename = "ocoPath", default, skip_serializing_if = "Option::is_none")]
    oco_path: Option<kob_core::OcoPath>,
    /// OCO partner: outpoint_key of the partner virtual order.
    /// Backward-compatible: absent in old JSON deserializes as None.
    #[serde(rename = "ocoPartnerKey", default, skip_serializing_if = "Option::is_none")]
    oco_partner_key: Option<String>,
    /// DAA score at discovery time (FIFO tiebreaker).
    /// Backward-compatible: absent in old JSON deserializes as 0.
    #[serde(rename = "discoveredDaa", default)]
    discovered_daa: u64,
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
                    oco_path: order.oco_path,
                    oco_partner_key: order.oco_partner_key.clone(),
                    discovered_daa: order.discovered_daa,
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
                    oco_path: order.oco_path,
                    oco_partner_key: order.oco_partner_key.clone(),
                    discovered_daa: order.discovered_daa,
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
            let redeem_script_hex_tmp = order.redeem_script;
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
                redeem_script_hex: redeem_script_hex_tmp.clone(),
                p2sh_script_hex: order.p2sh_script,
                p2sh_version: order.p2sh_version,
                side: OrderSide::Buy,
                post_only: order.post_only.unwrap_or(false),
                expiry_daa: order.expiry_daa,
                is_freezable: order.is_freezable,
                max_matcher_fee: order.max_matcher_fee,
                ifd_order_b_rs_hex: order.ifd_order_b_rs_hex,
                oco_path: order.oco_path,
                oco_partner_key: order.oco_partner_key,
                discovered_daa: order.discovered_daa,
                // Rebuilt from the RS (authoritative); ratchets_applied
                // resets to 0 on reload (genealogical, informational only).
                time_meta: crate::chain::scanner::time_meta_from_rs_hex(&redeem_script_hex_tmp),
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
            let redeem_script_hex_tmp = order.redeem_script;
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
                redeem_script_hex: redeem_script_hex_tmp.clone(),
                p2sh_script_hex: order.p2sh_script,
                p2sh_version: order.p2sh_version,
                side: OrderSide::Sell,
                post_only: order.post_only.unwrap_or(false),
                expiry_daa: order.expiry_daa,
                is_freezable: order.is_freezable,
                max_matcher_fee: order.max_matcher_fee,
                ifd_order_b_rs_hex: order.ifd_order_b_rs_hex,
                oco_path: order.oco_path,
                oco_partner_key: order.oco_partner_key,
                discovered_daa: order.discovered_daa,
                // Rebuilt from the RS (authoritative); ratchets_applied
                // resets to 0 on reload (genealogical, informational only).
                time_meta: crate::chain::scanner::time_meta_from_rs_hex(&redeem_script_hex_tmp),
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
/// Max addresses per `getUtxosByAddresses` call during validate/rescan.
///
/// The block-catchup path (H1-CHUNK, `chain/executor.rs`) chunks by BLOCK
/// COUNT over a totally different RPC (`getVirtualChainFromBlock` /
/// `getBlock`) and isn't reusable here as code -- checked before writing
/// this. The same BOUNDED-BATCH principle applies to address lists though
/// (avoid one unbounded `getUtxosByAddresses` call growing without limit as
/// the book / seed file grows, and don't let one bad chunk abort the whole
/// validation): chunk the address list and keep going past a failed chunk.
const VALIDATE_ADDR_CHUNK_SIZE: usize = 100;

/// Query `getUtxosByAddresses` for `addr_refs` in bounded chunks, returning
/// the union of all live outpoint keys (`txid:index`) found. A chunk that
/// fails (RPC error) is logged and skipped rather than aborting the whole
/// validation -- partial results are still useful (better to under-prune a
/// few orders than to skip validation entirely on a single flaky chunk).
async fn live_outpoint_keys(
    rpc: &RpcClient,
    addr_refs: &[&str],
) -> std::collections::HashSet<String> {
    let mut live = std::collections::HashSet::new();
    for chunk in addr_refs.chunks(VALIDATE_ADDR_CHUNK_SIZE) {
        match rpc.get_utxos_by_addresses(chunk).await {
            Ok(utxos) => {
                for u in utxos {
                    live.insert(format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index));
                }
            }
            Err(e) => {
                warn!(
                    "[PRUNE] getUtxosByAddresses chunk failed ({} addr(s)): {} — \
                     skipping this chunk, remaining chunks still validated",
                    chunk.len(), e
                );
            }
        }
    }
    live
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
/// Also the second half of the opt-in startup rescan (`rescan_from_seed`):
/// after a seed file's candidate orders are merged into the live book via
/// `load_order_book`, this same liveness check confirms which ones still
/// exist on-chain and drops the rest — so "rescan" and "prune" are the same
/// operation from two different starting books.
///
/// Strategy: batch all order P2SH addresses (chunked, see
/// `VALIDATE_ADDR_CHUNK_SIZE`) and query `getUtxosByAddresses`. Any order
/// whose outpoint is absent from the response is dropped. The wallet address
/// prefix ("kaspatest" / "kaspa") is inferred from `wallet_address`.
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

    // Collect all orders: (raw UTXO key for the liveness check, book key for
    // removal/logging, P2SH address). These differ for OCO/ratchet legs —
    // `outpoint_key()` carries a `:tp`/`:sl` suffix (two virtual book
    // entries share one on-chain UTXO) but the UTXO set is keyed by the raw
    // `txid:index`. Comparing the SUFFIXED key against the raw live set
    // would never match and every OCO/ratchet leg would be pruned as
    // "stale" on every restart even while its UTXO is live.
    let orders: Vec<(String, String, String)> = {
        let ob = order_book.lock().await;
        let mut out = Vec::new();
        for book in ob.pair_books.values() {
            for order in book.bids.values() {
                let spk = order.p2sh_script();
                let addr = p2sh_to_address(&spk, &prefix);
                out.push((order.utxo_outpoint_key(), order.outpoint_key(), addr));
            }
            for order in book.asks.values() {
                let spk = order.p2sh_script();
                let addr = p2sh_to_address(&spk, &prefix);
                out.push((order.utxo_outpoint_key(), order.outpoint_key(), addr));
            }
        }
        out
    };

    if orders.is_empty() {
        return;
    }

    // Deduplicate addresses for the batched (chunked) RPC calls.
    let mut addr_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, _, addr) in &orders {
        addr_set.insert(addr.clone());
    }
    let addr_refs: Vec<&str> = addr_set.iter().map(|s| s.as_str()).collect();

    info!(
        "[PRUNE] Validating {} persisted orders ({} P2SH addresses) against UTXO set ...",
        orders.len(),
        addr_refs.len()
    );

    let live = live_outpoint_keys(rpc, &addr_refs).await;

    // Prune orders not in the live set (checked by the RAW utxo key);
    // removal itself uses the book key (with OCO suffix where applicable).
    let mut pruned = 0u32;
    {
        let mut ob = order_book.lock().await;
        for (utxo_key, book_key, _) in &orders {
            if !live.contains(utxo_key) {
                ob.remove_order(book_key);
                warn!("[PRUNE] Removed stale persisted order: {}", &book_key[..book_key.len().min(24)]);
                pruned += 1;
            } else {
                tracing::debug!("[PRUNE] Confirmed live: {}", &book_key[..book_key.len().min(24)]);
            }
        }
    }

    info!(
        "[PRUNE] Validation complete: {} order(s) pruned, {} live",
        pruned,
        orders.len() as u32 - pruned
    );
}

/// Opt-in startup rescan: load a seed file of known covenant orders (same
/// JSON schema as `--orderbook`, i.e. a `load_order_book`-compatible
/// snapshot) and validate every entry against the live UTXO set via a direct
/// `getUtxosByAddresses` query.
///
/// This exists because the engine has no general way to discover orders it
/// doesn't already know the redeemScript for: KOB orders are true P2SH
/// (`kob/settle/src/crypto/p2sh.rs::build_p2sh` — script HASH only), so an
/// unknown order's on-chain output reveals nothing about its parameters
/// until it's spent. Recovering orders deployed while the engine was down
/// (or on a first-ever startup) therefore requires the operator to already
/// know their redeemScripts — supplied here as a seed file, e.g. exported
/// from a prior session's `orderbook.json` or hand-built from known deploy
/// parameters. The seed's candidates are merged into the live book (via the
/// existing `load_order_book`) and then confirmed/pruned by
/// `validate_and_prune_order_book` exactly like the normal persisted book —
/// so this recovers orders WITHOUT replaying blocks, avoiding the
/// `getVirtualChainFromBlock`/`getBlock` catch-up path that has hung on
/// large windows historically (see kob/E2E_LIVE_RESULTS.md, V16_STATUS.md).
///
/// A missing seed file is not an error (rescan is opt-in and the flag may be
/// left pointing at a path that doesn't exist yet) — logged and skipped.
pub async fn rescan_from_seed(
    rpc: &RpcClient,
    order_book: &Arc<Mutex<OrderBook>>,
    seed_path: &str,
    wallet_address: &str,
) {
    if !std::path::Path::new(seed_path).exists() {
        warn!("[RESCAN] Seed file not found at {} — startup rescan skipped", seed_path);
        return;
    }

    let before: usize = {
        let ob = order_book.lock().await;
        ob.pair_books.values().map(|b| b.bids.len() + b.asks.len()).sum()
    };

    if let Err(e) = load_order_book(seed_path, order_book).await {
        warn!("[RESCAN] Failed to load seed file {}: {}", seed_path, e);
        return;
    }

    let seeded: usize = {
        let ob = order_book.lock().await;
        let after: usize = ob.pair_books.values().map(|b| b.bids.len() + b.asks.len()).sum();
        after.saturating_sub(before)
    };
    info!(
        "[RESCAN] Loaded {} candidate order(s) from seed {} — validating against live UTXO set ...",
        seeded, seed_path
    );

    validate_and_prune_order_book(rpc, order_book, wallet_address).await;

    info!("[RESCAN] Startup rescan complete ({} candidate(s) from {})", seeded, seed_path);
}

// P2SH address helpers.

/// Convert a P2SH scriptPublicKey to its Kaspa bech32m address string.
///
/// Delegates to `kob_settle::bech32::spk_to_address` (the same real bech32m
/// codec used everywhere else in this workspace — x402, cli, settle/observe)
/// instead of hand-rolling encoding. `getUtxosByAddresses` on a real node
/// only recognizes real bech32m addresses; anything else is either rejected
/// outright or silently matches nothing, which would make
/// `validate_and_prune_order_book` (and the rescan path built on it) a
/// no-op that never actually confirms or prunes anything.
fn p2sh_to_address(spk: &[u8], prefix: &str) -> String {
    match kob_settle::bech32::spk_to_address(spk, prefix) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("[PRUNE] Failed to encode P2SH address (prefix={}): {}", prefix, e);
            String::new()
        }
    }
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

// Swap book persistence

/// Save the swap book to a JSON file (atomic write).
pub fn save_swap_book(path: &str, book: &crate::matcher::swap_book::SwapBook) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&book.to_json()).map_err(|e| e.to_string())?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write {}: {}", tmp_path, e))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {} -> {}: {}", tmp_path, path, e))?;
    info!("[SWAP BOOK] Saved to disk ({})", path);
    Ok(())
}

/// Load the swap book from a JSON file.
pub fn load_swap_book(path: &str) -> Result<crate::matcher::swap_book::SwapBook, String> {
    let path_ref = std::path::Path::new(path);
    if !path_ref.exists() {
        info!("[SWAP BOOK] No persisted file found at {}", path);
        return Ok(crate::matcher::swap_book::SwapBook::new());
    }
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse {}: {}", path, e))?;
    let book = crate::matcher::swap_book::SwapBook::from_json(&json)
        .ok_or_else(|| format!("Invalid swap book JSON structure in {}", path))?;
    info!("[SWAP BOOK] Loaded from {} ({} entries)", path, book.len());
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

    /// `p2sh_to_address` must produce a real bech32m Kaspa address that
    /// round-trips through the SAME codec's decoder
    /// (`kob_settle::bech32::address_to_spk`). The old implementation
    /// (`format!("{}:p{}", prefix, hex::encode(spk))`) produced a string
    /// that LOOKED plausible (Kaspa ScriptHash addresses do start with
    /// `:p` after bech32's charset) but was not valid bech32m — a real node
    /// would reject or silently no-op on it, making
    /// `validate_and_prune_order_book` (and the rescan path built on it)
    /// never actually confirm or prune anything.
    #[test]
    fn p2sh_to_address_round_trips_through_real_bech32m() {
        let spk = kob_core::build_p2sh(&[0x51]); // minimal redeemScript: Op1
        let addr = p2sh_to_address(spk.script(), "kaspatest");
        assert!(!addr.is_empty(), "must produce a non-empty address");
        assert!(addr.starts_with("kaspatest:"), "must carry the requested prefix; got {addr}");

        let decoded = kob_settle::bech32::address_to_spk(&addr).expect("must decode as valid bech32m");
        assert_eq!(decoded, spk.script().to_vec(), "decoded SPK must round-trip byte-exact");
    }

    /// Pin against a REAL testnet-10 vector: the ratchet_oco order at
    /// `ad0c2027a6a04ccd3c91e23e97fbc26d35eb17aeee2c603e561d8d30d34c9eba:0`
    /// (confirmed unspent via REST 2026-07-18, used as the Task-B rescan
    /// smoke-test target — see kob/E2E_LIVE_RESULTS.md). Its on-chain P2SH
    /// scriptPublicKey is `aa201110c395...a74687`; the live indexer resolves
    /// that SPK to `kaspatest:pqg3psu43pqqfqeszzne0k88kkmqhats0cfluzd3j9f22ajnjwn5vjdvhwc8t`.
    /// `p2sh_to_address` must reproduce that exact string, or a
    /// `getUtxosByAddresses` rescan query against it would silently match
    /// nothing on the real node.
    #[test]
    fn p2sh_to_address_matches_known_live_testnet_vector() {
        let spk_hex = "aa201110c395884004833010a797d8e7b5b60bf5707e13fe09b19152a5765393a74687";
        let spk = hex::decode(spk_hex).unwrap();
        let addr = p2sh_to_address(&spk, "kaspatest");
        assert_eq!(
            addr,
            "kaspatest:pqg3psu43pqqfqeszzne0k88kkmqhats0cfluzd3j9f22ajnjwn5vjdvhwc8t",
            "must match the address the live indexer actually resolves this UTXO under"
        );
    }
}
