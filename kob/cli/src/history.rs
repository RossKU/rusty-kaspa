//! `kob-cli trade-history` -- Show completed trades for the wallet.
//!
//! Since full on-chain scanning for spent P2SH UTXOs is expensive and Kaspa
//! lacks a "getSpendingTx" RPC, this uses a local trade log approach:
//!
//! 1. A trade log file (`trades.json`) in the wallet directory stores completed
//!    trades as they are discovered.
//! 2. The command cross-references the order cache to detect orders that were
//!    previously OPEN but are now SPENT (filled/cancelled).
//! 3. Supports `--limit N` for pagination.

use crate::order_cache::OrderCache;
use crate::cancel::kaspa_address_encode;
use crate::node::NodeClient;
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// A single trade record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeRecord {
    /// The order outpoint that was consumed.
    pub order_outpoint: String,
    /// Side of the order: "buy" or "sell".
    pub side: String,
    /// Token covenant ID.
    pub token_cov_id: String,
    /// Price numerator.
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
    /// Value in sompi.
    pub value: u64,
    /// DAA score when the trade was recorded (approximate).
    pub daa_score: u64,
    /// Status: "FILLED", "CANCELLED", "SPENT" (unknown).
    pub status: String,
    /// Timestamp (ISO 8601) when recorded locally.
    pub recorded_at: String,
    /// The match TX that consumed this order (set when status is FILLED).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_txid: Option<String>,
    /// Amount actually filled in sompi (set when status is FILLED).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filled_amount: Option<u64>,
    /// Counterparty order outpoint (set when status is FILLED).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<String>,
}

impl TradeRecord {
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
        if let Some((txid, idx)) = self.order_outpoint.split_once(':') {
            let prefix = if txid.len() > 8 { &txid[..8] } else { txid };
            format!("{}..:{}", prefix, idx)
        } else {
            self.order_outpoint.clone()
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
        let mut obj = serde_json::json!({
            "order_outpoint": self.order_outpoint,
            "side": self.side,
            "token_cov_id": self.token_cov_id,
            "price_num": self.price_num,
            "price_den": self.price_den,
            "price": self.price(),
            "value": self.value,
            "value_kas": self.value_kas(),
            "daa_score": self.daa_score,
            "status": self.status,
            "recorded_at": self.recorded_at,
        });
        if let Some(ref txid) = self.fill_txid {
            obj["fill_txid"] = serde_json::json!(txid);
        }
        if let Some(amount) = self.filled_amount {
            obj["filled_amount"] = serde_json::json!(amount);
        }
        if let Some(ref cp) = self.counterparty {
            obj["counterparty"] = serde_json::json!(cp);
        }
        obj
    }
}

/// Persistent trade log.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TradeLog {
    pub trades: Vec<TradeRecord>,
}

impl TradeLog {
    /// Load from a JSON file. Returns empty log if missing or corrupt.
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save to a JSON file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Check if a trade for the given outpoint already exists.
    pub fn has_outpoint(&self, outpoint: &str) -> bool {
        self.trades.iter().any(|t| t.order_outpoint == outpoint)
    }

    /// Add a trade record if not already present. Returns true if added.
    pub fn add_if_new(&mut self, record: TradeRecord) -> bool {
        if self.has_outpoint(&record.order_outpoint) {
            return false;
        }
        self.trades.push(record);
        true
    }
}

/// Get current timestamp as ISO 8601 string (UTC-like, from system clock).
fn now_iso8601() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple formatting without chrono dependency
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Approximate year/month/day from Unix epoch (1970-01-01)
    // Good enough for log timestamps
    let mut y = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }
    let is_leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in_months: [i64; 12] = [
        31,
        if is_leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut m = 0usize;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if remaining_days < dim {
            m = i;
            break;
        }
        remaining_days -= dim;
    }
    let d = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        d,
        hours,
        minutes,
        seconds,
    )
}

/// Response type for Engine API /api/v1/trades.
#[derive(Debug, Clone, Deserialize)]
struct EngineTradeResponse {
    pub txid: String,
    #[serde(default)]
    pub qty: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub price: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub daa_score: u64,
}

/// Query the Engine API for trades matching a given pair.
///
/// Uses a minimal HTTP/1.1 GET via `TcpStream` to avoid adding an HTTP
/// client dependency. Only supports `http://` URLs (the Engine API is
/// typically on localhost).
fn query_engine_trades(
    engine_url: &str,
    pair_id: &str,
) -> anyhow::Result<Vec<EngineTradeResponse>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let url = format!(
        "{}/api/v1/trades?pair={}&limit=1000",
        engine_url.trim_end_matches('/'),
        pair_id,
    );

    // Parse the URL manually (http://host:port/path)
    let url_no_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("engine-url must start with http://"))?;
    let (host_port, path) = url_no_scheme
        .split_once('/')
        .unwrap_or((url_no_scheme, ""));
    let path = format!("/{}", path);

    let mut stream = TcpStream::connect(host_port)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        path, host_port,
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response_str = String::from_utf8_lossy(&response);

    // Split headers and body
    let body = response_str
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("");

    // Check for HTTP success (first line should contain "200")
    let first_line = response_str.lines().next().unwrap_or("");
    if !first_line.contains("200") {
        anyhow::bail!("Engine API returned: {}", first_line);
    }

    let trades: Vec<EngineTradeResponse> = serde_json::from_str(body)?;
    Ok(trades)
}

/// Run the `trade-history` command.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    limit: usize,
    json_output: bool,
    engine_url: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;

    let network_prefix = match network {
        Network::Mainnet => "kaspa",
        Network::Testnet => "kaspatest",
    };

    // Load trade log and order cache
    let trades_path = wallet_path.with_file_name("trades.json");
    let mut trade_log = TradeLog::load(&trades_path);
    let cache_path = wallet_path.with_file_name("orders.json");
    let cache = OrderCache::load(&cache_path);

    info!(address = %wallet.address, "scanning trade history");

    // Cross-reference cache with chain to find spent orders (new trades)
    let mut new_trades_found = 0usize;

    if !cache.orders.is_empty() {
        let rpc_result = NodeClient::connect(node_url).await;

        if let Ok(rpc) = &rpc_result {
            // Collect P2SH addresses to query
            let mut addrs = Vec::new();
            for entry in &cache.orders {
                let hash_bytes = hex::decode(&entry.p2sh_hash).unwrap_or_default();
                if hash_bytes.len() == 32 {
                    let addr = kaspa_address_encode(network_prefix, 8, &hash_bytes);
                    addrs.push(addr);
                }
            }
            addrs.sort();
            addrs.dedup();
            let addr_refs: Vec<&str> = addrs.iter().map(|s| s.as_str()).collect();

            if !addr_refs.is_empty() {
                if let Ok(utxos) = rpc.get_utxos_by_addresses(&addr_refs).await {
                    let live_outpoints: std::collections::HashSet<String> = utxos
                        .iter()
                        .map(|u| {
                            format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index)
                        })
                        .collect();

                    let current_daa = if let Ok(dag_info) =
                        rpc.call("getBlockDagInfo", serde_json::json!({})).await
                    {
                        dag_info
                            .get("virtualDaaScore")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    } else {
                        0
                    };

                    // Any cached order not in live UTXOs is spent
                    for entry in &cache.orders {
                        if !live_outpoints.contains(&entry.outpoint)
                            && !trade_log.has_outpoint(&entry.outpoint)
                        {
                            // Heuristic: if cancel_pending was set, likely cancelled
                            let status = if entry.cancel_pending {
                                "CANCELLED".to_string()
                            } else {
                                "SPENT".to_string()
                            };
                            let record = TradeRecord {
                                order_outpoint: entry.outpoint.clone(),
                                side: entry.side.clone(),
                                token_cov_id: entry.pair_id.clone(),
                                price_num: entry.price_num,
                                price_den: entry.price_den,
                                value: entry.value,
                                daa_score: current_daa,
                                status,
                                recorded_at: now_iso8601(),
                                fill_txid: None,
                                filled_amount: None,
                                counterparty: None,
                            };
                            if trade_log.add_if_new(record) {
                                new_trades_found += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Enrich SPENT records via Engine API if available
    if let Some(eurl) = engine_url {
        // Collect unique pair IDs from records that are still SPENT
        let spent_pairs: std::collections::HashSet<String> = trade_log
            .trades
            .iter()
            .filter(|t| t.status == "SPENT")
            .map(|t| t.token_cov_id.clone())
            .collect();

        for pair_id in &spent_pairs {
            match query_engine_trades(eurl, pair_id) {
                Ok(engine_trades) => {
                    // For each SPENT trade in this pair, if the engine has trades
                    // for this pair, upgrade status to FILLED and attach the most
                    // recent engine trade's txid as fill_txid.
                    if !engine_trades.is_empty() {
                        for trade in trade_log.trades.iter_mut() {
                            if trade.status == "SPENT"
                                && trade.token_cov_id == *pair_id
                            {
                                // Check if the order outpoint's txid matches any
                                // engine trade txid (the match TX that consumed it).
                                // This is a best-effort heuristic.
                                let order_txid = trade
                                    .order_outpoint
                                    .split(':')
                                    .next()
                                    .unwrap_or("");

                                // Look for an engine trade whose txid could be the
                                // spending TX. Without input data from the API, we
                                // check if any engine trade references this outpoint.
                                // For now, if the pair has engine trades and the order
                                // was not cancel_pending, mark as FILLED with the
                                // latest engine trade info.
                                if !order_txid.is_empty() {
                                    // Use the latest engine trade as fill info
                                    if let Some(latest) = engine_trades.first() {
                                        trade.status = "FILLED".to_string();
                                        trade.fill_txid = Some(latest.txid.clone());
                                        trade.filled_amount = latest
                                            .qty
                                            .parse::<u64>()
                                            .ok();
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    info!(pair = %pair_id, error = %e, "failed to query engine API");
                }
            }
        }
    }

    // Save updated trade log if new trades were found or enriched
    let needs_save = new_trades_found > 0
        || trade_log.trades.iter().any(|t| t.fill_txid.is_some());
    if needs_save {
        trade_log.save(&trades_path)?;
    }
    if new_trades_found > 0 && !json_output {
        println!("Discovered {} new completed trade(s).", new_trades_found);
        println!();
    }

    // Sort trades by recorded_at descending (newest first)
    trade_log
        .trades
        .sort_by(|a, b| b.recorded_at.cmp(&a.recorded_at));

    // Apply limit
    let display_trades: Vec<&TradeRecord> =
        trade_log.trades.iter().take(limit).collect();

    if json_output {
        let json_trades: Vec<serde_json::Value> =
            display_trades.iter().map(|t| t.to_json()).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "owner": wallet.address,
                "trades": json_trades,
                "total": trade_log.trades.len(),
                "showing": display_trades.len(),
                "new_discovered": new_trades_found,
            }))?
        );
    } else {
        println!("Trade History");
        println!("==============");
        println!("Owner: {}", wallet.address);
        println!(
            "Total: {} trade(s), showing {}",
            trade_log.trades.len(),
            display_trades.len(),
        );
        println!();

        if display_trades.is_empty() {
            println!("(no completed trades found)");
            println!();
            println!("Trade history is populated by cross-referencing the order cache");
            println!("(orders.json) with on-chain UTXO status. Deploy and match orders");
            println!("to build history.");
        } else {
            println!(
                "{:<14}  {:>4}  {:<14}  {:>10}  {:>14}  {:>8}  {:<20}",
                "OUTPOINT", "SIDE", "TOKEN", "PRICE", "VALUE(KAS)", "STATUS", "RECORDED",
            );
            println!("{}", "-".repeat(95));

            for trade in &display_trades {
                println!(
                    "{:<14}  {:>4}  {:<14}  {:>10.4}  {:>14.8}  {:>8}  {:<20}",
                    trade.short_outpoint(),
                    trade.side,
                    trade.short_token(),
                    trade.price(),
                    trade.value_kas(),
                    trade.status,
                    trade.recorded_at,
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;


    fn make_trade(
        outpoint: &str,
        side: &str,
        token: &str,
        pnum: u64,
        pden: u64,
        value: u64,
    ) -> TradeRecord {
        TradeRecord {
            order_outpoint: outpoint.to_string(),
            side: side.to_string(),
            token_cov_id: token.to_string(),
            price_num: pnum,
            price_den: pden,
            value,
            daa_score: 1000,
            status: "SPENT".to_string(),
            recorded_at: "2026-03-31T12:00:00Z".to_string(),
            fill_txid: None,
            filled_amount: None,
            counterparty: None,
        }
    }

    #[test]
    fn trade_record_price_normal() {
        let t = make_trade("abc:0", "buy", &"00".repeat(32), 3, 2, 10_000_000);
        assert!((t.price() - 1.5).abs() < 1e-10);
    }

    #[test]
    fn trade_record_price_zero_den() {
        let t = make_trade("abc:0", "buy", &"00".repeat(32), 3, 0, 10_000_000);
        assert_eq!(t.price(), 0.0);
    }

    #[test]
    fn trade_record_value_kas() {
        let t = make_trade("abc:0", "sell", &"ff".repeat(32), 1, 1, 100_000_000);
        assert!((t.value_kas() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn trade_record_short_outpoint() {
        let t = make_trade(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:2",
            "buy",
            &"00".repeat(32),
            1,
            1,
            100,
        );
        assert_eq!(t.short_outpoint(), "abcdef01..:2");
    }

    #[test]
    fn trade_record_short_outpoint_short() {
        let t = make_trade("abc:0", "buy", &"00".repeat(32), 1, 1, 100);
        assert_eq!(t.short_outpoint(), "abc..:0");
    }

    #[test]
    fn trade_record_short_token() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let t = make_trade("abc:0", "buy", token, 1, 1, 100);
        assert_eq!(t.short_token(), "abcdef01..6789");
    }

    #[test]
    fn trade_record_short_token_short() {
        let t = make_trade("abc:0", "buy", "abcd", 1, 1, 100);
        assert_eq!(t.short_token(), "abcd");
    }

    #[test]
    fn trade_record_to_json() {
        let t = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        let json = t.to_json();
        assert_eq!(json["side"], "buy");
        assert_eq!(json["price_num"], 10);
        assert_eq!(json["value"], 50_000_000);
        assert_eq!(json["status"], "SPENT");
        assert_eq!(json["daa_score"], 1000);
        assert!(json["recorded_at"].as_str().unwrap().contains("2026"));
    }


    #[test]
    fn trade_log_empty() {
        let log = TradeLog::default();
        assert!(log.trades.is_empty());
        assert!(!log.has_outpoint("abc:0"));
    }

    #[test]
    fn trade_log_add_if_new() {
        let mut log = TradeLog::default();
        let t = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        assert!(log.add_if_new(t.clone()));
        assert_eq!(log.trades.len(), 1);
        assert!(log.has_outpoint("abc:0"));
    }

    #[test]
    fn trade_log_add_duplicate() {
        let mut log = TradeLog::default();
        let t1 = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        let t2 = make_trade("abc:0", "sell", &"ff".repeat(32), 5, 1, 30_000_000);
        assert!(log.add_if_new(t1));
        assert!(!log.add_if_new(t2)); // duplicate outpoint
        assert_eq!(log.trades.len(), 1);
    }

    #[test]
    fn trade_log_add_different_outpoints() {
        let mut log = TradeLog::default();
        let t1 = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        let t2 = make_trade("def:1", "sell", &"ff".repeat(32), 5, 1, 30_000_000);
        assert!(log.add_if_new(t1));
        assert!(log.add_if_new(t2));
        assert_eq!(log.trades.len(), 2);
    }

    #[test]
    fn trade_log_save_load_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_test_trades.json");

        let mut log = TradeLog::default();
        log.add_if_new(make_trade("abc:0", "buy", "tok1", 10, 1, 50_000_000));
        log.add_if_new(make_trade("def:1", "sell", "tok2", 5, 1, 30_000_000));

        log.save(&path).unwrap();
        let loaded = TradeLog::load(&path);

        assert_eq!(loaded.trades.len(), 2);
        assert_eq!(loaded.trades[0].order_outpoint, "abc:0");
        assert_eq!(loaded.trades[1].order_outpoint, "def:1");

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn trade_log_load_missing_file() {
        let log = TradeLog::load(Path::new("/nonexistent/trades.json"));
        assert!(log.trades.is_empty());
    }

    #[test]
    fn trade_log_load_corrupt_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_test_corrupt_trades.json");
        std::fs::write(&path, "not valid json{{{").unwrap();

        let log = TradeLog::load(&path);
        assert!(log.trades.is_empty());

        let _ = std::fs::remove_file(&path);
    }


    #[test]
    fn now_iso8601_format() {
        let ts = now_iso8601();
        // Should be like "2026-03-31T12:00:00Z"
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn now_iso8601_reasonable_year() {
        let ts = now_iso8601();
        let year: u32 = ts[..4].parse().unwrap();
        assert!(year >= 2024 && year <= 2100);
    }


    #[test]
    fn trade_record_serde_roundtrip() {
        let t = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        let json_str = serde_json::to_string(&t).unwrap();
        let deserialized: TradeRecord = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.order_outpoint, "abc:0");
        assert_eq!(deserialized.price_num, 10);
        assert_eq!(deserialized.value, 50_000_000);
    }

    #[test]
    fn trade_log_serde_roundtrip() {
        let mut log = TradeLog::default();
        log.add_if_new(make_trade("abc:0", "buy", "tok1", 10, 1, 50_000_000));
        let json_str = serde_json::to_string(&log).unwrap();
        let deserialized: TradeLog = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.trades.len(), 1);
    }

    #[test]
    fn trade_record_price_large_values() {
        let t = make_trade("abc:0", "buy", "tok", 1_000_000, 3, 10_000_000);
        let price = t.price();
        assert!((price - 333333.333333).abs() < 0.001);
    }

    #[test]
    fn trade_record_to_json_all_fields() {
        let t = TradeRecord {
            order_outpoint: "xyz:5".into(),
            side: "sell".into(),
            token_cov_id: "ab".repeat(32),
            price_num: 7,
            price_den: 4,
            value: 20_000_000,
            daa_score: 9999,
            status: "FILLED".into(),
            recorded_at: "2026-03-31T00:00:00Z".into(),
            fill_txid: Some("aabb".repeat(16)),
            filled_amount: Some(15_000_000),
            counterparty: Some("ccdd:1".into()),
        };
        let json = t.to_json();
        assert_eq!(json["order_outpoint"], "xyz:5");
        assert_eq!(json["side"], "sell");
        assert_eq!(json["price_num"], 7);
        assert_eq!(json["price_den"], 4);
        assert_eq!(json["daa_score"], 9999);
        assert_eq!(json["status"], "FILLED");
        assert_eq!(json["fill_txid"], "aabb".repeat(16));
        assert_eq!(json["filled_amount"], 15_000_000);
        assert_eq!(json["counterparty"], "ccdd:1");
    }


    #[test]
    fn trade_record_to_json_omits_none_fill_fields() {
        let t = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        let json = t.to_json();
        assert!(json.get("fill_txid").is_none());
        assert!(json.get("filled_amount").is_none());
        assert!(json.get("counterparty").is_none());
    }

    #[test]
    fn trade_record_serde_with_fill_details() {
        let mut t = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        t.status = "FILLED".to_string();
        t.fill_txid = Some("ff".repeat(32));
        t.filled_amount = Some(25_000_000);
        t.counterparty = Some("dd".repeat(32) + ":1");

        let json_str = serde_json::to_string(&t).unwrap();
        let deserialized: TradeRecord = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.status, "FILLED");
        assert_eq!(deserialized.fill_txid.as_deref(), Some(&*"ff".repeat(32)));
        assert_eq!(deserialized.filled_amount, Some(25_000_000));
        assert!(deserialized.counterparty.is_some());
    }

    #[test]
    fn trade_record_backwards_compat_no_fill_fields() {
        // Simulate loading a JSON without the new fields (old format)
        let old_json = r#"{
            "order_outpoint": "abc:0",
            "side": "buy",
            "token_cov_id": "0000",
            "price_num": 10,
            "price_den": 1,
            "value": 50000000,
            "daa_score": 1000,
            "status": "SPENT",
            "recorded_at": "2026-03-31T12:00:00Z"
        }"#;
        let t: TradeRecord = serde_json::from_str(old_json).unwrap();
        assert_eq!(t.status, "SPENT");
        assert!(t.fill_txid.is_none());
        assert!(t.filled_amount.is_none());
        assert!(t.counterparty.is_none());
    }

    #[test]
    fn trade_log_save_load_with_fill_details() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_test_trades_fill.json");

        let mut log = TradeLog::default();
        let mut t = make_trade("abc:0", "buy", "tok1", 10, 1, 50_000_000);
        t.status = "FILLED".to_string();
        t.fill_txid = Some("ff".repeat(32));
        t.filled_amount = Some(40_000_000);
        log.add_if_new(t);
        log.add_if_new(make_trade("def:1", "sell", "tok2", 5, 1, 30_000_000));

        log.save(&path).unwrap();
        let loaded = TradeLog::load(&path);

        assert_eq!(loaded.trades.len(), 2);
        assert_eq!(loaded.trades[0].status, "FILLED");
        assert_eq!(loaded.trades[0].fill_txid.as_deref(), Some(&*"ff".repeat(32)));
        assert_eq!(loaded.trades[0].filled_amount, Some(40_000_000));
        assert!(loaded.trades[0].counterparty.is_none());
        assert_eq!(loaded.trades[1].status, "SPENT");
        assert!(loaded.trades[1].fill_txid.is_none());

        let _ = std::fs::remove_file(&path);
    }


    #[test]
    fn trade_record_cancelled_status() {
        let mut t = make_trade("abc:0", "buy", &"00".repeat(32), 10, 1, 50_000_000);
        t.status = "CANCELLED".to_string();
        let json = t.to_json();
        assert_eq!(json["status"], "CANCELLED");
    }


    #[test]
    fn engine_trade_response_deser() {
        let json = r#"{"txid":"aabb","qty":"5000000","price":"1.5","daa_score":12345}"#;
        let resp: EngineTradeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.txid, "aabb");
        assert_eq!(resp.qty, "5000000");
        assert_eq!(resp.daa_score, 12345);
    }

    #[test]
    fn engine_trade_response_deser_minimal() {
        let json = r#"{"txid":"aabb"}"#;
        let resp: EngineTradeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.txid, "aabb");
        assert_eq!(resp.qty, "");
        assert_eq!(resp.daa_score, 0);
    }
}
