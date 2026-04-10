//! `kob-cli cancel-all` -- Cancel all open orders owned by the wallet.
//!
//! Queries the wallet's known P2SH addresses from a local orders cache (orders.json),
//! finds all live order UTXOs, and builds cancel TXs for each.
//!
//! Since KOB orders are deployed to unique P2SH addresses derived from order parameters,
//! and we cannot reverse-engineer parameters from a P2SH hash alone, this command relies
//! on a local order cache file that records deployed orders.
//!
//! With `--dry-run`, previews orders that would be cancelled without submitting TXs.
//! With `--token <cov_id>`, filters cancellations to a specific token pair.

use crate::order_cache::{OrderCache, OrderCacheEntry};
use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use kob_core::mass::estimate_compute_mass;
use kob_core::MIN_UTXO_VALUE;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// A cached order entry stored in orders.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedOrder {
    /// Outpoint string "txid:index".
    pub outpoint: String,
    /// Side: "buy" or "sell".
    pub side: String,
    /// Token covenant ID (hex, 64 chars). Present for buy orders.
    pub token: Option<String>,
    /// Price numerator.
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
    /// Minimum fill amount.
    pub min_fill: u64,
    /// Deployed UTXO value in sompi.
    pub value: u64,
    /// Contract version (only 13 supported).
    #[serde(default = "default_version")]
    pub version: u8,
    /// Expiry DAA score (v13 only, 0 = GTC).
    #[serde(default)]
    pub expiry_daa: u64,
}

fn default_version() -> u8 {
    13
}

/// Result of a single cancel operation.
#[derive(Debug)]
#[allow(dead_code)] // Public API: fields used by cancel-all result reporting
pub struct CancelResult {
    pub outpoint: String,
    pub side: String,
    pub token: Option<String>,
    pub recovered_sompi: u64,
    pub tx_id: Option<String>,
}

/// Build a cancel transaction for a single order.
///
/// Returns the (Transaction, sigscripts, output_value) tuple on success.
///
/// Uses a two-pass fee calculation: first build the TX with an estimated fee,
/// then recompute using `calc_miner_fee` which takes `max(compute_mass,
/// storage_mass)`. This avoids the TN12 rejection where storage mass exceeds
/// the compute-only estimate.
pub fn build_cancel_tx(
    order: &OrderCacheEntry,
    pubkey: &[u8; 32],
    privkey: &[u8; 32],
    order_value: u64,
    fee_utxo_txid: &str,
    fee_utxo_index: u32,
    fee_utxo_value: u64,
    fee_utxo_spk_version: u16,
    fee_utxo_spk_bytes: &[u8],
) -> anyhow::Result<(Transaction, Vec<Vec<u8>>, u64)> {

    let redeem_script = build_redeem_script_for_order(order, pubkey)?;
    let p2sh = build_p2sh(&redeem_script);

    let total_in = order_value + fee_utxo_value;
    // First pass: estimate fee to build a tentative TX.
    let est_fee = kob_core::mass::estimate_compute_mass(2, 1, 0);
    let tentative_output = total_in - est_fee;

    let mut tx = Transaction::new(0);

    // Input 0: order UTXO (P2SH)
    let parts: Vec<&str> = order.outpoint.split(':').collect();
    let order_txid = parts[0].to_string();
    let order_index: u32 = parts[1].parse()?;

    tx.inputs.push(TxInput {
        prev_tx_id: order_txid,
        prev_index: order_index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo_txid.to_string(),
        prev_index: fee_utxo_index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo_spk_version,
        script_bytes: fee_utxo_spk_bytes.to_vec(),
        value: fee_utxo_value,
    });

    // Output 0: recovered funds to wallet
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo_spk_version, fee_utxo_spk_bytes.to_vec(), None));

    // Second pass: compute exact fee from built TX (max of compute and storage mass).
    let actual_fee = kob_core::mass::calc_miner_fee(&tx);
    let output_value = total_in - actual_fee;
    tx.outputs[0].value = output_value;

    // Sign input 0 (order cancel)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(privkey, &sighash_0)?;

    let cancel_sigscript = match order.side.as_str() {
        "buy" => contract::build_buy_cancel_sigscript(&sig_0, pubkey, &redeem_script),
        "sell" => contract::build_sell_cancel_sigscript(&sig_0, pubkey, &redeem_script),
        _ => anyhow::bail!("Unknown order side '{}'. Expected 'buy' or 'sell'.", order.side),
    };

    // Sign input 1 (fee UTXO)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    Ok((tx, vec![cancel_sigscript, fee_sigscript], output_value))
}

/// Load the orders cache from an orders.json file.
///
/// Accepts both the canonical `OrderCache` format (`{"orders": [...]}`) and
/// the legacy flat `CachedOrder` array. Returns unified `OrderCacheEntry` vec.
pub fn load_orders_cache(cache_path: &Path) -> anyhow::Result<Vec<OrderCacheEntry>> {
    let cache = OrderCache::load(cache_path);
    Ok(cache.orders)
}

/// Save the orders cache to an orders.json file (canonical `OrderCache` format).
pub fn save_orders_cache(cache_path: &Path, orders: &[OrderCacheEntry]) -> anyhow::Result<()> {
    let cache = OrderCache { orders: orders.to_vec() };
    cache.save(cache_path)
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

/// Run the cancel-all command.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    token_filter: Option<&str>,
    dry_run: bool,
    orders_file: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    println!("Cancel All Orders");
    println!("==================");
    println!("Owner:    {}", wallet.address);
    if let Some(token) = token_filter {
        println!("Filter:   token={}", token);
    }
    if dry_run {
        println!("Mode:     DRY RUN (no transactions will be submitted)");
    }
    println!();

    // Load orders cache
    let cache_path_str = orders_file.unwrap_or("orders.json");
    let cache_path = Path::new(cache_path_str);
    let orders = load_orders_cache(cache_path)?;

    if orders.is_empty() {
        println!("No orders found in cache file '{}'.", cache_path_str);
        println!();
        println!("The cancel-all command requires an orders.json cache file to know");
        println!("the parameters of deployed orders. Deploy orders with caching enabled,");
        println!("or use 'kob-cli cancel' for individual orders with explicit parameters.");
        return Ok(());
    }

    // Filter by token if specified
    let filtered: Vec<&OrderCacheEntry> = orders
        .iter()
        .filter(|o| {
            if let Some(token) = token_filter {
                match &o.token {
                    Some(t) => t == token,
                    None => false,
                }
            } else {
                true
            }
        })
        .collect();

    if filtered.is_empty() {
        println!("No orders match the filter criteria.");
        return Ok(());
    }

    println!("Found {} order(s) to cancel.", filtered.len());
    println!();

    // Connect to node
    info!(
        address = %wallet.address,
        count = filtered.len(),
        dry_run = dry_run,
        "cancel-all starting"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get wallet UTXOs for fee payment
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxos: Vec<_> = wallet_utxos
        .iter()
        .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= estimate_compute_mass(2, 1, 0) + MIN_UTXO_VALUE)
        .collect();

    if fee_utxos.is_empty() {
        anyhow::bail!(
            "No P2PK UTXOs with >= {} sompi for fee payment.",
            estimate_compute_mass(2, 1, 0) + MIN_UTXO_VALUE
        );
    }

    let mut results: Vec<CancelResult> = Vec::new();
    let mut total_recovered: u64 = 0;
    let mut fee_idx = 0;

    for order in &filtered {
        println!("---");
        println!(
            "Order: {} ({} {})",
            order.outpoint,
            order.side,
            order.token.as_deref().unwrap_or("KAS")
        );
        println!("  Value: {} sompi ({:.8} KAS)", order.value, order.value as f64 / 1e8);

        if fee_idx >= fee_utxos.len() {
            println!("  SKIP: No more fee UTXOs available.");
            continue;
        }

        let fee_utxo = fee_utxos[fee_idx];

        // Verify the order UTXO still exists on-chain
        let redeem_script = build_redeem_script_for_order(order, &pubkey)?;
        let p2sh = build_p2sh(&redeem_script);
        let p2sh_address = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 1, &p2sh.script()[2..34],
        );

        let parts: Vec<&str> = order.outpoint.split(':').collect();
        let order_txid = parts[0];
        let order_index: u32 = parts[1].parse()?;

        // Try to verify UTXO on-chain; fall back to cached value on query failure
        let order_value = match rpc.get_utxos_by_addresses(&[&p2sh_address]).await {
            Ok(order_utxos) => {
                let live_utxo = order_utxos.iter().find(|u| {
                    u.outpoint.transaction_id == order_txid && u.outpoint.index == order_index
                });
                match live_utxo {
                    Some(u) => u.utxo_entry.amount,
                    None => {
                        println!("  SKIP: Order UTXO not found on-chain (already cancelled/filled?).");
                        results.push(CancelResult {
                            outpoint: order.outpoint.clone(),
                            side: order.side.clone(),
                            token: order.token.clone(),
                            recovered_sompi: 0,
                            tx_id: None,
                        });
                        continue;
                    }
                }
            }
            Err(e) => {
                println!("  WARN: UTXO query failed ({}), using cached value {} sompi.", e, order.value);
                order.value
            }
        };

        let fee_spk_bytes = fee_utxo.script_bytes();
        // Cancel TX: 2 inputs (order + fee), 1 output.
        // Use max(compute_mass, storage_mass) to satisfy TN12 minimum fee.
        let in_vals = [order_value, fee_utxo.utxo_entry.amount];
        let est_out = order_value + fee_utxo.utxo_entry.amount
            - kob_core::mass::estimate_compute_mass(2, 1, 0);
        let storage_fee = kob_core::mass::compute_storage_mass(&in_vals, &[est_out]);
        let compute_fee = kob_core::mass::estimate_compute_mass(2, 1, 0);
        let cancel_fee = compute_fee.max(storage_fee);
        let output_value = order_value + fee_utxo.utxo_entry.amount - cancel_fee;

        println!("  Order Value: {} sompi", order_value);
        println!("  Fee UTXO:    {}:{} ({} sompi)",
            fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index,
            fee_utxo.utxo_entry.amount
        );
        println!("  Recovered:   {} sompi ({:.8} KAS)", output_value, output_value as f64 / 1e8);

        if dry_run {
            println!("  [DRY RUN] Would cancel this order.");
            total_recovered += output_value;
            results.push(CancelResult {
                outpoint: order.outpoint.clone(),
                side: order.side.clone(),
                token: order.token.clone(),
                recovered_sompi: output_value,
                tx_id: None,
            });
        } else {
            let (tx, sigscripts, recovered) = build_cancel_tx(
                order,
                &pubkey,
                &privkey,
                order_value,
                &fee_utxo.outpoint.transaction_id,
                fee_utxo.outpoint.index,
                fee_utxo.utxo_entry.amount,
                fee_utxo.utxo_entry.script_public_key.version,
                &fee_spk_bytes,
            )?;

            let payload = to_rpc_payload(&tx, &sigscripts);
            match rpc.submit_transaction(payload).await {
                Ok(tx_id) => {
                    println!("  SUCCESS: TXID={}", tx_id);
                    total_recovered += recovered;
                    fee_idx += 1;
                    results.push(CancelResult {
                        outpoint: order.outpoint.clone(),
                        side: order.side.clone(),
                        token: order.token.clone(),
                        recovered_sompi: recovered,
                        tx_id: Some(tx_id),
                    });
                }
                Err(e) => {
                    println!("  FAILED: {}", e);
                    results.push(CancelResult {
                        outpoint: order.outpoint.clone(),
                        side: order.side.clone(),
                        token: order.token.clone(),
                        recovered_sompi: 0,
                        tx_id: None,
                    });
                }
            }
        }
    }

    // Summary
    println!();
    println!("==================");
    println!("Cancel Summary");
    println!("==================");
    let cancelled = results.iter().filter(|r| r.recovered_sompi > 0).count();
    let skipped = results.iter().filter(|r| r.recovered_sompi == 0).count();
    println!("Total orders:    {}", results.len());
    println!("Cancelled:       {}", cancelled);
    println!("Skipped/Failed:  {}", skipped);
    println!(
        "Total recovered: {} sompi ({:.8} KAS)",
        total_recovered,
        total_recovered as f64 / 1e8
    );
    if dry_run {
        println!();
        println!("(DRY RUN -- no transactions were submitted)");
    }

    Ok(())
}

/// Build a redeemScript for a cached order (helper for verifying P2SH addresses).
pub fn build_redeem_script_for_order(
    order: &OrderCacheEntry,
    pubkey: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let owner_hash = blake2b_256(pubkey);
    let spk_hash = compute_p2pk_spk_hash(pubkey);


    if order.version != 13 {
        anyhow::bail!("Unsupported contract version {}. Only v13 is supported.", order.version);
    }

    match order.side.as_str() {
        "buy" => {
            let token_hex = order.token.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Buy order is missing its token covenant ID. The order may be malformed."))?;
            let token_bytes = hex::decode(token_hex)?;
            let mut tcid = [0u8; 32];
            tcid.copy_from_slice(&token_bytes);
            Ok(contract::build_buy_redeem_script(
                &tcid, order.price_num, order.price_den, order.min_fill,
                &owner_hash, &spk_hash, 0, 0, order.expiry_daa,)?)
        }
        "sell" => {
            Ok(contract::build_sell_redeem_script(
                order.price_num, order.price_den, order.min_fill,
                &owner_hash, &spk_hash, 0, 0, order.expiry_daa,)?)
        }
        _ => anyhow::bail!("Unknown order side '{}'. Expected 'buy' or 'sell'.", order.side),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_order_serialization_roundtrip() {
        let order = CachedOrder {
            outpoint: "abc123:0".into(),
            side: "buy".into(),
            token: Some("ff".repeat(32)),
            price_num: 100,
            price_den: 1,
            min_fill: 1_000_000,
            value: 50_000_000,
            version: 13,
            expiry_daa: 0,
        };
        let json = serde_json::to_string(&order).unwrap();
        let decoded: CachedOrder = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.outpoint, "abc123:0");
        assert_eq!(decoded.side, "buy");
        assert_eq!(decoded.price_num, 100);
        assert_eq!(decoded.version, 13);
    }

    #[test]
    fn cached_order_default_version() {
        let json = r#"{
            "outpoint": "abc:0",
            "side": "sell",
            "token": null,
            "price_num": 1,
            "price_den": 2,
            "min_fill": 100,
            "value": 5000000
        }"#;
        let order: CachedOrder = serde_json::from_str(json).unwrap();
        assert_eq!(order.version, 13, "default version must be 13");
    }

    #[test]
    fn load_orders_cache_empty_file() {
        let path = Path::new("/tmp/nonexistent_orders_test_cancel_all.json");
        let result = load_orders_cache(path).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn load_orders_cache_valid_json() {
        let path = &std::env::temp_dir().join("test_orders_cancel_all.json");
        let orders = vec![
            CachedOrder {
                outpoint: "aaa:0".into(),
                side: "buy".into(),
                token: Some("bb".repeat(32)),
                price_num: 10,
                price_den: 1,
                min_fill: 100_000,
                value: 10_000_000,
                version: 13,
                expiry_daa: 0,
            },
            CachedOrder {
                outpoint: "ccc:1".into(),
                side: "sell".into(),
                token: None,
                price_num: 5,
                price_den: 1,
                min_fill: 50_000,
                value: 5_000_000,
                version: 13,
                expiry_daa: 0,
            },
        ];
        let json = serde_json::to_string_pretty(&orders).unwrap();
        std::fs::write(path, &json).unwrap();

        let loaded = load_orders_cache(path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].side, "buy");
        assert_eq!(loaded[1].side, "sell");
        assert_eq!(loaded[1].version, 13);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn build_redeem_script_buy_v13() {
        let pubkey = [0x02u8; 32];
        let order = OrderCacheEntry::from(CachedOrder {
            outpoint: format!("{}:0", "ab".repeat(32)),
            side: "buy".into(),
            token: Some("ff".repeat(32)),
            price_num: 100,
            price_den: 1,
            min_fill: 1_000_000,
            value: 50_000_000,
            version: 13,
            expiry_daa: 0,
        });

        let rs = build_redeem_script_for_order(&order, &pubkey).unwrap();
        assert!(!rs.is_empty(), "redeemScript must not be empty");

        let p2sh = build_p2sh(&rs);
        assert_eq!(p2sh.script().len(), 35);
    }

    #[test]
    fn build_redeem_script_sell_v13() {
        let pubkey = [0x02u8; 32];
        let order = OrderCacheEntry::from(CachedOrder {
            outpoint: format!("{}:0", "cd".repeat(32)),
            side: "sell".into(),
            token: None,
            price_num: 5,
            price_den: 1,
            min_fill: 500_000,
            value: 20_000_000,
            version: 13,
            expiry_daa: 0,
        });

        let rs = build_redeem_script_for_order(&order, &pubkey).unwrap();
        assert!(!rs.is_empty());

        let p2sh = build_p2sh(&rs);
        assert_eq!(p2sh.script().len(), 35);
    }

    #[test]
    fn build_redeem_script_buy_requires_token() {
        let pubkey = [0x02u8; 32];
        let order = OrderCacheEntry::from(CachedOrder {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token: None,
            price_num: 1,
            price_den: 1,
            min_fill: 100,
            value: 1000,
            version: 13,
            expiry_daa: 0,
        });
        let result = build_redeem_script_for_order(&order, &pubkey);
        assert!(result.is_err(), "buy order without token must fail");
    }

    #[test]
    fn build_redeem_script_unknown_side() {
        let pubkey = [0x02u8; 32];
        let order = OrderCacheEntry::from(CachedOrder {
            outpoint: "abc:0".into(),
            side: "unknown".into(),
            token: None,
            price_num: 1,
            price_den: 1,
            min_fill: 100,
            value: 1000,
            version: 13,
            expiry_daa: 0,
        });
        let result = build_redeem_script_for_order(&order, &pubkey);
        assert!(result.is_err(), "unknown side must fail");
    }

    #[test]
    fn token_filter_logic() {
        let orders = vec![
            CachedOrder {
                outpoint: "a:0".into(), side: "buy".into(),
                token: Some("aa".repeat(32)),
                price_num: 1, price_den: 1, min_fill: 100, value: 1000, version: 13, expiry_daa: 0,
            },
            CachedOrder {
                outpoint: "b:0".into(), side: "sell".into(),
                token: Some("bb".repeat(32)),
                price_num: 1, price_den: 1, min_fill: 100, value: 2000, version: 13, expiry_daa: 0,
            },
            CachedOrder {
                outpoint: "c:0".into(), side: "sell".into(),
                token: None,
                price_num: 1, price_den: 1, min_fill: 100, value: 3000, version: 13, expiry_daa: 0,
            },
        ];

        let all: Vec<_> = orders.iter().collect();
        assert_eq!(all.len(), 3);

        let token_aa = "aa".repeat(32);
        let filtered: Vec<_> = orders.iter().filter(|o| {
            match &o.token {
                Some(t) => t == &token_aa,
                None => false,
            }
        }).collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].outpoint, "a:0");

        let token_xx = "xx".repeat(32);
        let empty: Vec<_> = orders.iter().filter(|o| {
            match &o.token {
                Some(t) => t == &token_xx,
                None => false,
            }
        }).collect();
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn cancel_result_fields() {
        let r = CancelResult {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token: Some("ff".repeat(32)),
            recovered_sompi: 49_990_000,
            tx_id: Some("tx123".into()),
        };
        assert_eq!(r.recovered_sompi, 49_990_000);
        assert!(r.tx_id.is_some());
    }

    #[test]
    fn summary_counting() {
        let results = vec![
            CancelResult { outpoint: "a:0".into(), side: "buy".into(), token: None, recovered_sompi: 100, tx_id: Some("t1".into()) },
            CancelResult { outpoint: "b:0".into(), side: "sell".into(), token: None, recovered_sompi: 0, tx_id: None },
            CancelResult { outpoint: "c:0".into(), side: "buy".into(), token: None, recovered_sompi: 200, tx_id: Some("t2".into()) },
        ];
        let cancelled = results.iter().filter(|r| r.recovered_sompi > 0).count();
        let skipped = results.iter().filter(|r| r.recovered_sompi == 0).count();
        let total: u64 = results.iter().map(|r| r.recovered_sompi).sum();
        assert_eq!(cancelled, 2);
        assert_eq!(skipped, 1);
        assert_eq!(total, 300);
    }

    #[test]
    fn buy_v12_redeem_script_differs_by_price() {
        let pubkey = [0x02u8; 32];
        let order1 = OrderCacheEntry::from(CachedOrder {
            outpoint: "a:0".into(), side: "buy".into(),
            token: Some("ff".repeat(32)),
            price_num: 100, price_den: 1, min_fill: 1_000_000, value: 50_000_000,
            version: 13, expiry_daa: 0,
        });
        let order2 = OrderCacheEntry { price_num: 200, ..order1.clone() };

        let rs1 = build_redeem_script_for_order(&order1, &pubkey).unwrap();
        let rs2 = build_redeem_script_for_order(&order2, &pubkey).unwrap();
        assert_ne!(rs1, rs2, "Different prices must produce different redeemScripts");
    }

    #[test]
    fn sell_v12_redeem_script_differs_by_price() {
        let pubkey = [0x02u8; 32];
        let order1 = OrderCacheEntry::from(CachedOrder {
            outpoint: "a:0".into(), side: "sell".into(),
            token: None,
            price_num: 5, price_den: 1, min_fill: 500_000, value: 20_000_000,
            version: 13, expiry_daa: 0,
        });
        let order2 = OrderCacheEntry { price_num: 10, ..order1.clone() };

        let rs1 = build_redeem_script_for_order(&order1, &pubkey).unwrap();
        let rs2 = build_redeem_script_for_order(&order2, &pubkey).unwrap();
        assert_ne!(rs1, rs2, "Different prices must produce different sell redeemScripts");
    }
}
