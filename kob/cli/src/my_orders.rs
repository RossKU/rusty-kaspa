//! `kob-cli my-orders` -- List all MY open orders across all pairs.
//!
//! Uses the local order cache (orders.json) to find orders deployed by this wallet,
//! then queries the chain to determine which are still live (UTXO unspent).
//!
//! For each live order, displays: outpoint, side (buy/sell), token_cov_id,
//! price, amount, age (DAA score delta), and status.

use crate::order_cache::OrderCache;
#[cfg(test)]
use crate::order_cache::OrderCacheEntry;
use crate::cancel::kaspa_address_encode;
use crate::node::NodeClient;
use crate::scan::extract_p2sh_hash;
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use std::path::Path;
use tracing::info;

/// A single order belonging to the wallet owner.
#[derive(Debug, Clone)]
pub struct MyOrder {
    pub outpoint: String,
    pub side: String,
    pub token_cov_id: String,
    pub price_num: u64,
    pub price_den: u64,
    pub value: u64,
    pub daa_score: u64,
    pub status: String,
}

impl MyOrder {
    pub fn price(&self) -> f64 {
        if self.price_den == 0 {
            return 0.0;
        }
        self.price_num as f64 / self.price_den as f64
    }

    pub fn value_kas(&self) -> f64 {
        self.value as f64 / 1e8
    }

    pub fn short_outpoint(&self) -> String {
        if let Some((txid, idx)) = self.outpoint.split_once(':') {
            let prefix = if txid.len() > 8 { &txid[..8] } else { txid };
            format!("{}..:{}", prefix, idx)
        } else {
            self.outpoint.clone()
        }
    }

    pub fn short_token(&self) -> String {
        if self.token_cov_id.len() > 16 {
            format!(
                "{}..{}",
                &self.token_cov_id[..8],
                &self.token_cov_id[self.token_cov_id.len() - 4..]
            )
        } else {
            self.token_cov_id.clone()
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "outpoint": self.outpoint,
            "side": self.side,
            "token_cov_id": self.token_cov_id,
            "price_num": self.price_num,
            "price_den": self.price_den,
            "price": self.price(),
            "value": self.value,
            "value_kas": self.value_kas(),
            "daa_score": self.daa_score,
            "status": self.status,
        })
    }
}

/// Collect my orders from cache + optional owner filtering.
pub fn collect_from_cache(cache: &OrderCache, owner_hash_filter: Option<&str>) -> Vec<MyOrder> {
    let mut orders = Vec::new();
    for entry in &cache.orders {
        if let Some(owner) = owner_hash_filter {
            if entry.owner_hash != owner {
                continue;
            }
        }
        orders.push(MyOrder {
            outpoint: entry.outpoint.clone(),
            side: entry.side.clone(),
            token_cov_id: entry.pair_id.clone(),
            price_num: entry.price_num,
            price_den: entry.price_den,
            value: entry.value,
            daa_score: 0,
            status: "CACHED".to_string(),
        });
    }
    orders
}

/// Run the `my-orders` command.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    json_output: bool,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;

    let network_prefix = match network {
        Network::Mainnet => "kaspa",
        Network::Testnet => "kaspatest",
    };

    // Load order cache
    let cache_path = wallet_path.with_file_name("orders.json");
    let cache = OrderCache::load(&cache_path);

    if cache.orders.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "orders": [],
                    "total": 0,
                    "note": "Order cache is empty. Deploy orders first.",
                })
            );
        } else {
            println!("My Orders");
            println!("==========");
            println!("Owner: {}", wallet.address);
            println!();
            println!("Order cache ({}) is empty.", cache_path.display());
            println!("Deploy orders via 'kob-cli deploy' to populate the cache.");
        }
        return Ok(());
    }

    info!(address = %wallet.address, "listing my orders from cache");

    // Compute owner hash from wallet to filter orders
    let pubkey = wallet.public_key_bytes()?;
    let owner_hash = hex::encode(kob_core::p2sh::blake2b_256(&pubkey));

    // Collect all cached orders for this owner
    let mut my_orders = collect_from_cache(&cache, Some(&owner_hash));

    // If no orders match the owner hash, show all cached orders
    if my_orders.is_empty() {
        my_orders = collect_from_cache(&cache, None);
    }

    // Try to verify live status via RPC
    let rpc_result = NodeClient::connect(node_url).await;
    let mut current_daa = 0u64;

    if let Ok(rpc) = &rpc_result {
        // Get current DAA score
        if let Ok(dag_info) = rpc.call("getBlockDagInfo", serde_json::json!({})).await {
            current_daa = dag_info
                .get("virtualDaaScore")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
        }

        // Collect P2SH addresses from cached orders
        let mut addrs = Vec::new();

        for order in &my_orders {
            if let Some(entry) = cache.orders.iter().find(|o| o.outpoint == order.outpoint) {
                let hash_bytes = hex::decode(&entry.p2sh_hash).unwrap_or_default();
                if hash_bytes.len() == 32 {
                    let addr = kaspa_address_encode(network_prefix, 8, &hash_bytes);
                    addrs.push(addr);
                }
            }
        }

        addrs.sort();
        addrs.dedup();
        let addr_refs: Vec<&str> = addrs.iter().map(|s| s.as_str()).collect();

        if !addr_refs.is_empty() {
            if let Ok(utxos) = rpc.get_utxos_by_addresses(&addr_refs).await {
                let live_outpoints: std::collections::HashSet<String> = utxos
                    .iter()
                    .map(|u| format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index))
                    .collect();

                let daa_map: std::collections::HashMap<String, u64> = utxos
                    .iter()
                    .map(|u| {
                        (
                            format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index),
                            u.utxo_entry.block_daa_score,
                        )
                    })
                    .collect();

                // Check for new UTXOs at same address (partial fills)
                let mut new_utxos = Vec::new();
                for utxo in &utxos {
                    let op =
                        format!("{}:{}", utxo.outpoint.transaction_id, utxo.outpoint.index);
                    if !my_orders.iter().any(|o| o.outpoint == op) {
                        if let Some(hash) = extract_p2sh_hash(
                            &utxo.utxo_entry.script_public_key.script,
                        ) {
                            if let Some(entry) =
                                cache.orders.iter().find(|o| o.p2sh_hash == hash)
                            {
                                new_utxos.push(MyOrder {
                                    outpoint: op,
                                    side: entry.side.clone(),
                                    token_cov_id: entry.pair_id.clone(),
                                    price_num: entry.price_num,
                                    price_den: entry.price_den,
                                    value: utxo.utxo_entry.amount,
                                    daa_score: utxo.utxo_entry.block_daa_score,
                                    status: "OPEN".to_string(),
                                });
                            }
                        }
                    }
                }

                for order in &mut my_orders {
                    if live_outpoints.contains(&order.outpoint) {
                        order.status = "OPEN".to_string();
                        if let Some(&daa) = daa_map.get(&order.outpoint) {
                            order.daa_score = daa;
                            if let Some(utxo) = utxos.iter().find(|u| {
                                format!(
                                    "{}:{}",
                                    u.outpoint.transaction_id, u.outpoint.index
                                ) == order.outpoint
                            }) {
                                order.value = utxo.utxo_entry.amount;
                            }
                        }
                    } else {
                        order.status = "SPENT".to_string();
                    }
                }

                my_orders.extend(new_utxos);
            }
        }
    }

    // Sort: OPEN first, then by value descending
    my_orders.sort_by(|a, b| {
        let status_ord = |s: &str| -> u8 {
            match s {
                "OPEN" => 0,
                "CACHED" => 1,
                _ => 2,
            }
        };
        status_ord(&a.status)
            .cmp(&status_ord(&b.status))
            .then(b.value.cmp(&a.value))
    });

    if json_output {
        let json_orders: Vec<serde_json::Value> =
            my_orders.iter().map(|o| o.to_json()).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "owner": wallet.address,
                "orders": json_orders,
                "total": my_orders.len(),
                "open": my_orders.iter().filter(|o| o.status == "OPEN").count(),
                "spent": my_orders.iter().filter(|o| o.status == "SPENT").count(),
                "current_daa_score": current_daa,
            }))?
        );
    } else {
        println!("My Orders");
        println!("==========");
        println!("Owner: {}", wallet.address);
        if current_daa > 0 {
            println!("DAA:   {}", current_daa);
        }
        println!();

        let open_count = my_orders.iter().filter(|o| o.status == "OPEN").count();
        let spent_count = my_orders.iter().filter(|o| o.status == "SPENT").count();
        let cached_count = my_orders.iter().filter(|o| o.status == "CACHED").count();

        println!(
            "Total: {} orders ({} open, {} spent, {} cached-only)",
            my_orders.len(),
            open_count,
            spent_count,
            cached_count,
        );
        println!();

        if my_orders.is_empty() {
            println!("(no orders found)");
        } else {
            println!(
                "{:<14}  {:>4}  {:<14}  {:>10}  {:>14}  {:>8}  {:<6}",
                "OUTPOINT", "SIDE", "TOKEN", "PRICE", "VALUE(KAS)", "AGE", "STATUS",
            );
            println!("{}", "-".repeat(80));

            for order in &my_orders {
                let age_str = if current_daa > 0 && order.daa_score > 0 {
                    let delta = current_daa.saturating_sub(order.daa_score);
                    format!("{}", delta)
                } else {
                    "-".to_string()
                };
                println!(
                    "{:<14}  {:>4}  {:<14}  {:>10.4}  {:>14.8}  {:>8}  {:<6}",
                    order.short_outpoint(),
                    order.side,
                    order.short_token(),
                    order.price(),
                    order.value_kas(),
                    age_str,
                    order.status,
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache_entry(
        side: &str,
        pair_id: &str,
        pnum: u64,
        pden: u64,
        value: u64,
        owner: &str,
        idx: u32,
    ) -> OrderCacheEntry {
        OrderCacheEntry {
            outpoint: format!("{}:{}", "aa".repeat(32), idx),
            side: side.to_string(),
            pair_id: pair_id.to_string(),
            price_num: pnum,
            price_den: pden,
            min_fill: 3_000_000,
            owner_hash: owner.to_string(),
            spk_hash: "cc".repeat(32),
            p2sh_hash: format!("{}{:02x}", "dd".repeat(31), idx),
            value,
            cancel_pending: false,
            token: None,
            version: 13,
            expiry_daa: 0,
            max_matcher_fee: 10_000_000,
        }
    }

    #[test]
    fn my_order_price_normal() {
        let order = MyOrder {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token_cov_id: "00".repeat(32),
            price_num: 3,
            price_den: 2,
            value: 10_000_000,
            daa_score: 100,
            status: "OPEN".into(),
        };
        assert!((order.price() - 1.5).abs() < 1e-10);
    }

    #[test]
    fn my_order_price_zero_den() {
        let order = MyOrder {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token_cov_id: "00".repeat(32),
            price_num: 3,
            price_den: 0,
            value: 10_000_000,
            daa_score: 0,
            status: "OPEN".into(),
        };
        assert_eq!(order.price(), 0.0);
    }

    #[test]
    fn my_order_value_kas() {
        let order = MyOrder {
            outpoint: "abc:0".into(),
            side: "sell".into(),
            token_cov_id: "ff".repeat(32),
            price_num: 1,
            price_den: 1,
            value: 100_000_000,
            daa_score: 0,
            status: "OPEN".into(),
        };
        assert!((order.value_kas() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn my_order_short_outpoint() {
        let order = MyOrder {
            outpoint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:2".into(),
            side: "buy".into(),
            token_cov_id: "00".repeat(32),
            price_num: 1,
            price_den: 1,
            value: 100,
            daa_score: 0,
            status: "OPEN".into(),
        };
        assert_eq!(order.short_outpoint(), "abcdef01..:2");
    }

    #[test]
    fn my_order_short_outpoint_short_txid() {
        let order = MyOrder {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token_cov_id: "00".repeat(32),
            price_num: 1,
            price_den: 1,
            value: 100,
            daa_score: 0,
            status: "OPEN".into(),
        };
        assert_eq!(order.short_outpoint(), "abc..:0");
    }

    #[test]
    fn my_order_short_token() {
        let order = MyOrder {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token_cov_id: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
            price_num: 1,
            price_den: 1,
            value: 100,
            daa_score: 0,
            status: "OPEN".into(),
        };
        assert_eq!(order.short_token(), "abcdef01..6789");
    }

    #[test]
    fn my_order_short_token_short_id() {
        let order = MyOrder {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token_cov_id: "abcd".into(),
            price_num: 1,
            price_den: 1,
            value: 100,
            daa_score: 0,
            status: "OPEN".into(),
        };
        assert_eq!(order.short_token(), "abcd");
    }

    #[test]
    fn my_order_to_json() {
        let order = MyOrder {
            outpoint: "abc:0".into(),
            side: "buy".into(),
            token_cov_id: "00".repeat(32),
            price_num: 10,
            price_den: 1,
            value: 50_000_000,
            daa_score: 1000,
            status: "OPEN".into(),
        };
        let json = order.to_json();
        assert_eq!(json["side"], "buy");
        assert_eq!(json["price_num"], 10);
        assert_eq!(json["price_den"], 1);
        assert_eq!(json["value"], 50_000_000);
        assert_eq!(json["status"], "OPEN");
        assert_eq!(json["daa_score"], 1000);
    }

    #[test]
    fn collect_from_cache_empty() {
        let cache = OrderCache::default();
        let orders = collect_from_cache(&cache, None);
        assert!(orders.is_empty());
    }

    #[test]
    fn collect_from_cache_no_filter() {
        let pair = "00".repeat(32);
        let owner = "aa".repeat(32);
        let mut cache = OrderCache::default();
        cache
            .orders
            .push(make_cache_entry("buy", &pair, 10, 1, 10_000_000, &owner, 0));
        cache
            .orders
            .push(make_cache_entry("sell", &pair, 12, 1, 8_000_000, &owner, 1));

        let orders = collect_from_cache(&cache, None);
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0].side, "buy");
        assert_eq!(orders[1].side, "sell");
    }

    #[test]
    fn collect_from_cache_with_owner_filter() {
        let pair = "00".repeat(32);
        let owner_a = "aa".repeat(32);
        let owner_b = "bb".repeat(32);
        let mut cache = OrderCache::default();
        cache
            .orders
            .push(make_cache_entry("buy", &pair, 10, 1, 10_000_000, &owner_a, 0));
        cache
            .orders
            .push(make_cache_entry("sell", &pair, 12, 1, 8_000_000, &owner_b, 1));

        let orders = collect_from_cache(&cache, Some(&owner_a));
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0].side, "buy");
    }

    #[test]
    fn collect_from_cache_owner_filter_no_match() {
        let pair = "00".repeat(32);
        let owner = "aa".repeat(32);
        let mut cache = OrderCache::default();
        cache
            .orders
            .push(make_cache_entry("buy", &pair, 10, 1, 10_000_000, &owner, 0));

        let orders = collect_from_cache(&cache, Some(&"ff".repeat(32)));
        assert!(orders.is_empty());
    }

    #[test]
    fn collect_preserves_fields() {
        let pair = "ab".repeat(32);
        let owner = "11".repeat(32);
        let mut cache = OrderCache::default();
        cache
            .orders
            .push(make_cache_entry("sell", &pair, 7, 3, 25_000_000, &owner, 5));

        let orders = collect_from_cache(&cache, None);
        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0].token_cov_id, pair);
        assert_eq!(orders[0].price_num, 7);
        assert_eq!(orders[0].price_den, 3);
        assert_eq!(orders[0].value, 25_000_000);
        assert_eq!(orders[0].status, "CACHED");
    }

    #[test]
    fn collect_multiple_tokens() {
        let pair_a = "aa".repeat(32);
        let pair_b = "bb".repeat(32);
        let owner = "11".repeat(32);
        let mut cache = OrderCache::default();
        cache
            .orders
            .push(make_cache_entry("buy", &pair_a, 10, 1, 10_000_000, &owner, 0));
        cache
            .orders
            .push(make_cache_entry("sell", &pair_b, 12, 1, 8_000_000, &owner, 1));
        cache
            .orders
            .push(make_cache_entry("buy", &pair_a, 5, 1, 5_000_000, &owner, 2));

        let orders = collect_from_cache(&cache, Some(&owner));
        assert_eq!(orders.len(), 3);
    }

    #[test]
    fn my_order_to_json_sell() {
        let order = MyOrder {
            outpoint: "xyz:1".into(),
            side: "sell".into(),
            token_cov_id: "ff".repeat(32),
            price_num: 5,
            price_den: 2,
            value: 30_000_000,
            daa_score: 500,
            status: "SPENT".into(),
        };
        let json = order.to_json();
        assert_eq!(json["side"], "sell");
        assert_eq!(json["status"], "SPENT");
        assert_eq!(json["outpoint"], "xyz:1");
        let price = json["price"].as_f64().unwrap();
        assert!((price - 2.5).abs() < 1e-10);
    }
}
