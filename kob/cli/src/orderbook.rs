//! `kob-cli orderbook` and `kob-cli order-status` commands.
//!
//! **orderbook**: Query the on-chain order book for a token pair.
//!   - With `--cache-file`: loads from orders.json (fast, offline).
//!   - Without: scans recent blocks via RPC for KOB:1: payload TXs.
//!
//! **order-status**: Check whether a specific order UTXO is OPEN,
//!   FILLED, CANCELLED, or PARTIALLY_FILLED.

use crate::auto_match::OrderSide;
use crate::order_cache::{OrderCache, OrderCacheEntry};
use crate::cancel::kaspa_address_encode;
use crate::node::NodeClient;
use crate::scan::{extract_p2sh_hash, is_p2sh_utxo};
use kob_core::types::Network;
use std::path::Path;
use tracing::info;

// Data types

/// A single level in the order book display.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: fields used by orderbook display and SDK
pub struct OrderBookEntry {
    pub side: OrderSide,
    pub price_num: u64,
    pub price_den: u64,
    pub value: u64,
    pub outpoint: String,
    pub pair_id: String,
}

impl OrderBookEntry {
    /// Price as f64 (num/den).
    pub fn price(&self) -> f64 {
        if self.price_den == 0 {
            return 0.0;
        }
        self.price_num as f64 / self.price_den as f64
    }

    /// Value formatted as KAS (8 decimal places).
    pub fn value_kas(&self) -> f64 {
        self.value as f64 / 1e8
    }

    /// Short outpoint for display: first 8 chars of txid + :index.
    pub fn short_outpoint(&self) -> String {
        if let Some((txid, idx)) = self.outpoint.split_once(':') {
            let prefix = if txid.len() > 8 { &txid[..8] } else { txid };
            format!("{}..:{}", prefix, idx)
        } else {
            self.outpoint.clone()
        }
    }
}

/// The assembled order book for display.
#[derive(Debug, Default)]
pub struct OrderBookView {
    pub token: String,
    pub bids: Vec<OrderBookEntry>,
    pub asks: Vec<OrderBookEntry>,
}

impl OrderBookView {
    /// Sort bids descending by price, asks ascending by price.
    pub fn sort(&mut self) {
        self.bids.sort_by(|a, b| {
            let pa = a.price_num as u128 * b.price_den as u128;
            let pb = b.price_num as u128 * a.price_den as u128;
            pb.cmp(&pa)
        });
        self.asks.sort_by(|a, b| {
            let pa = a.price_num as u128 * b.price_den as u128;
            let pb = b.price_num as u128 * a.price_den as u128;
            pa.cmp(&pb)
        });
    }

    /// Truncate to top N levels per side.
    pub fn truncate(&mut self, depth: usize) {
        self.bids.truncate(depth);
        self.asks.truncate(depth);
    }

    /// Format as human-readable table.
    pub fn format_table(&self) -> String {
        let mut out = String::new();

        let label = if self.token.len() > 16 {
            format!("{}...", &self.token[..16])
        } else {
            self.token.clone()
        };

        out.push_str(&format!("=== Order Book: {} ===\n", label));
        out.push_str(&format!(
            "{:<14} {:>12} {:<14}   {:<14} {:>12} {:<14}\n",
            "BIDS", "Value(KAS)", "Outpoint", "ASKS", "Value(KAS)", "Outpoint",
        ));
        out.push_str(&format!("{}\n", "-".repeat(90)));

        let max_rows = self.bids.len().max(self.asks.len());
        for i in 0..max_rows {
            // Bid column
            if i < self.bids.len() {
                let b = &self.bids[i];
                out.push_str(&format!(
                    "{:<14.6} {:>12.8} {:<14}",
                    b.price(),
                    b.value_kas(),
                    b.short_outpoint(),
                ));
            } else {
                out.push_str(&format!("{:<14} {:>12} {:<14}", "", "", ""));
            }

            out.push_str("   ");

            // Ask column
            if i < self.asks.len() {
                let a = &self.asks[i];
                out.push_str(&format!(
                    "{:<14.6} {:>12.8} {:<14}",
                    a.price(),
                    a.value_kas(),
                    a.short_outpoint(),
                ));
            }

            out.push('\n');
        }

        if max_rows == 0 {
            out.push_str("  (no orders)\n");
        }

        out.push_str(&format!(
            "\nTotal: {} bid(s), {} ask(s)\n",
            self.bids.len(),
            self.asks.len()
        ));

        out
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let bids: Vec<serde_json::Value> = self
            .bids
            .iter()
            .map(|b| {
                serde_json::json!({
                    "side": "buy",
                    "price_num": b.price_num,
                    "price_den": b.price_den,
                    "price": b.price(),
                    "value": b.value,
                    "value_kas": b.value_kas(),
                    "outpoint": b.outpoint,
                })
            })
            .collect();

        let asks: Vec<serde_json::Value> = self
            .asks
            .iter()
            .map(|a| {
                serde_json::json!({
                    "side": "sell",
                    "price_num": a.price_num,
                    "price_den": a.price_den,
                    "price": a.price(),
                    "value": a.value,
                    "value_kas": a.value_kas(),
                    "outpoint": a.outpoint,
                })
            })
            .collect();

        serde_json::json!({
            "token": self.token,
            "bids": bids,
            "asks": asks,
            "bid_count": self.bids.len(),
            "ask_count": self.asks.len(),
        })
    }
}

// Order status types

/// Status of a single order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Public API: variants used by order-status query
pub enum OrderStatus {
    /// UTXO exists and is unspent.
    Open { value: u64 },
    /// UTXO was spent by a fill TX.
    Filled { spending_tx: String },
    /// UTXO was spent by a cancel TX.
    Cancelled { spending_tx: String },
    /// UTXO was spent -- spending TX found but path not determinable.
    Spent { spending_tx: String },
    /// UTXO was partially filled, residual order at a new outpoint.
    PartiallyFilled {
        spending_tx: String,
        residual_outpoint: String,
        residual_value: u64,
    },
    /// Could not determine status (UTXO not found, no spending TX).
    Unknown,
}

impl OrderStatus {
    pub fn label(&self) -> &'static str {
        match self {
            OrderStatus::Open { .. } => "OPEN",
            OrderStatus::Filled { .. } => "FILLED",
            OrderStatus::Cancelled { .. } => "CANCELLED",
            OrderStatus::Spent { .. } => "SPENT",
            OrderStatus::PartiallyFilled { .. } => "PARTIALLY_FILLED",
            OrderStatus::Unknown => "UNKNOWN",
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            OrderStatus::Open { value } => serde_json::json!({
                "status": "OPEN",
                "value": value,
                "value_kas": *value as f64 / 1e8,
            }),
            OrderStatus::Filled { spending_tx } => serde_json::json!({
                "status": "FILLED",
                "spending_tx": spending_tx,
            }),
            OrderStatus::Cancelled { spending_tx } => serde_json::json!({
                "status": "CANCELLED",
                "spending_tx": spending_tx,
            }),
            OrderStatus::Spent { spending_tx } => serde_json::json!({
                "status": "SPENT",
                "spending_tx": spending_tx,
            }),
            OrderStatus::PartiallyFilled {
                spending_tx,
                residual_outpoint,
                residual_value,
            } => serde_json::json!({
                "status": "PARTIALLY_FILLED",
                "spending_tx": spending_tx,
                "residual_outpoint": residual_outpoint,
                "residual_value": residual_value,
                "residual_value_kas": *residual_value as f64 / 1e8,
            }),
            OrderStatus::Unknown => serde_json::json!({
                "status": "UNKNOWN",
            }),
        }
    }
}

// Build order book from cache

/// Build an OrderBookView from the order cache, optionally filtered by token.
pub fn build_from_cache(cache: &OrderCache, token_filter: Option<&str>) -> Vec<OrderBookView> {
    use std::collections::BTreeMap;

    // Group by pair_id (token covenant ID)
    let mut groups: BTreeMap<String, Vec<&OrderCacheEntry>> = BTreeMap::new();
    for entry in &cache.orders {
        if let Some(filter) = token_filter {
            if entry.pair_id != filter {
                continue;
            }
        }
        groups.entry(entry.pair_id.clone()).or_default().push(entry);
    }

    let mut views = Vec::new();

    for (pair_id, entries) in groups {
        let mut view = OrderBookView {
            token: pair_id,
            bids: Vec::new(),
            asks: Vec::new(),
        };

        for entry in entries {
            let ob_entry = OrderBookEntry {
                side: if entry.side == "buy" {
                    OrderSide::Buy
                } else {
                    OrderSide::Sell
                },
                price_num: entry.price_num,
                price_den: entry.price_den,
                value: entry.value,
                outpoint: entry.outpoint.clone(),
                pair_id: entry.pair_id.clone(),
            };

            match ob_entry.side {
                OrderSide::Buy => view.bids.push(ob_entry),
                OrderSide::Sell => view.asks.push(ob_entry),
            }
        }

        view.sort();
        views.push(view);
    }

    views
}

/// Build an OrderBookView by scanning UTXOs at known P2SH addresses from cache.
///
/// This is the "live" mode: cache provides the parameter mapping, RPC confirms
/// which UTXOs still exist. Returns views with up-to-date values.
pub async fn build_live_from_cache(
    rpc: &NodeClient,
    cache: &OrderCache,
    token_filter: Option<&str>,
    network_prefix: &str,
) -> anyhow::Result<Vec<OrderBookView>> {
    use std::collections::{BTreeMap, HashSet};

    let cache_lookup = cache.by_p2sh_hash();

    // Collect unique P2SH addresses to query
    let mut p2sh_addresses: HashSet<String> = HashSet::new();
    for entry in &cache.orders {
        if let Some(filter) = token_filter {
            if entry.pair_id != filter {
                continue;
            }
        }
        let hash_bytes = hex::decode(&entry.p2sh_hash).unwrap_or_default();
        if hash_bytes.len() == 32 {
            let addr = kaspa_address_encode(network_prefix, 8, &hash_bytes);
            p2sh_addresses.insert(addr);
        }
    }

    if p2sh_addresses.is_empty() {
        return Ok(Vec::new());
    }

    // Query all addresses in a single RPC call
    let addr_refs: Vec<&str> = p2sh_addresses.iter().map(|s| s.as_str()).collect();
    let utxos = rpc.get_utxos_by_addresses(&addr_refs).await?;

    // Group live UTXOs by pair_id via the cache lookup
    let mut groups: BTreeMap<String, Vec<OrderBookEntry>> = BTreeMap::new();

    for utxo in &utxos {
        if !is_p2sh_utxo(utxo) {
            continue;
        }
        if let Some(hash) = extract_p2sh_hash(&utxo.utxo_entry.script_public_key.script) {
            if let Some(cached) = cache_lookup.get(&hash) {
                if let Some(filter) = token_filter {
                    if cached.pair_id != filter {
                        continue;
                    }
                }
                let side = if cached.side == "buy" {
                    OrderSide::Buy
                } else {
                    OrderSide::Sell
                };
                let outpoint = format!(
                    "{}:{}",
                    utxo.outpoint.transaction_id, utxo.outpoint.index
                );
                groups.entry(cached.pair_id.clone()).or_default().push(
                    OrderBookEntry {
                        side,
                        price_num: cached.price_num,
                        price_den: cached.price_den,
                        value: utxo.utxo_entry.amount,
                        outpoint,
                        pair_id: cached.pair_id.clone(),
                    },
                );
            }
        }
    }

    let mut views = Vec::new();
    for (pair_id, entries) in groups {
        let mut view = OrderBookView {
            token: pair_id,
            bids: Vec::new(),
            asks: Vec::new(),
        };
        for e in entries {
            match e.side {
                OrderSide::Buy => view.bids.push(e),
                OrderSide::Sell => view.asks.push(e),
            }
        }
        view.sort();
        views.push(view);
    }

    Ok(views)
}

// Determine order status via RPC

/// Determine the status of an order at a given outpoint.
///
/// Strategy:
///   1. Parse the outpoint string to get txid and index.
///   2. Attempt to find the UTXO on-chain via `getUtxosByAddresses` if we have
///      the P2SH address, or via a broader approach.
///   3. If a P2SH address is provided, check if the UTXO still exists (OPEN).
///   4. If not found, call `getTransaction` on the outpoint's txid to confirm
///      it existed, then search for the spending TX.
///
/// For simplicity, this uses a heuristic approach:
///   - If the UTXO exists at the address -> OPEN
///   - If not, the order was spent (filled/cancelled/partial).
///   - We attempt to classify by querying the spending TX when possible.
pub async fn determine_order_status(
    rpc: &NodeClient,
    outpoint_str: &str,
    p2sh_address: Option<&str>,
) -> anyhow::Result<OrderStatus> {
    let (txid, idx) = parse_outpoint(outpoint_str)?;

    // If we have a P2SH address, check if the UTXO still exists
    if let Some(addr) = p2sh_address {
        let utxos = rpc.get_utxos_by_addresses(&[addr]).await?;
        for utxo in &utxos {
            if utxo.outpoint.transaction_id == txid && utxo.outpoint.index == idx {
                return Ok(OrderStatus::Open {
                    value: utxo.utxo_entry.amount,
                });
            }
        }
    }

    // UTXO not found at address (or no address provided).
    // Check if the original TX exists at all.
    let tx_result = rpc
        .call(
            "getTransaction",
            serde_json::json!({
                "transactionId": txid,
                "includeVerboseData": true,
            }),
        )
        .await;

    match tx_result {
        Ok(resp) => {
            // TX exists. The output was spent.
            // Try to find the spending TX via acceptingBlockHash and scan.
            // For now, we classify based on what we can determine.
            let outputs = resp
                .get("transaction")
                .and_then(|t| t.get("outputs"))
                .and_then(|o| o.as_array());

            if let Some(outs) = outputs {
                if (idx as usize) < outs.len() {
                    // The output existed. If the UTXO query didn't find it,
                    // it was spent. Without a direct "getSpendingTx" RPC,
                    // we attempt mempool search or return Spent.
                    let spending_info =
                        try_find_spending_tx(rpc, &txid, idx).await;
                    return Ok(spending_info);
                }
            }

            // Output index out of range -- the outpoint is invalid
            Ok(OrderStatus::Unknown)
        }
        Err(_) => {
            // TX not found at all
            Ok(OrderStatus::Unknown)
        }
    }
}

/// Try to find a spending transaction for a given outpoint.
///
/// Kaspa RPC doesn't have a direct "getSpendingTx" method, so we use
/// heuristics:
///   1. Check mempool entries by the P2SH address
///   2. If the TX was accepted (not in mempool), we know it was spent
///      but cannot easily determine the spending TX without an indexer.
///
/// Returns the best-guess OrderStatus.
async fn try_find_spending_tx(
    rpc: &NodeClient,
    _txid: &str,
    _output_idx: u32,
) -> OrderStatus {
    // Kaspa doesn't have a direct "getSpendingTx" RPC.
    // The UTXO was not found, so it was spent. Without additional
    // indexer support, we return Spent with unknown details.
    //
    // Future enhancement: use block subscription or DAA score range
    // scanning to find the spending TX.
    let _ = rpc;
    OrderStatus::Spent {
        spending_tx: "unknown (no indexer)".to_string(),
    }
}

/// Parse an outpoint string "txid:index".
pub fn parse_outpoint(s: &str) -> anyhow::Result<(String, u32)> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid outpoint format '{}'. Expected format: TXID:INDEX (e.g., abc123...def:0)", s);
    }
    let txid = parts[0].to_string();
    let idx: u32 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid output index '{}' in outpoint. Must be a number (e.g., 0, 1, 2).", parts[1]))?;
    Ok((txid, idx))
}

// CLI entry points

/// Run the `orderbook` command.
#[allow(clippy::too_many_arguments)]
pub async fn run_orderbook(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    token_filter: Option<&str>,
    depth: usize,
    json_output: bool,
    cache_file: Option<&str>,
) -> anyhow::Result<()> {
    let network_prefix = match network {
        Network::Mainnet => "kaspa",
        Network::Testnet => "kaspatest",
    };

    // Determine cache path
    let cache_path = if let Some(cf) = cache_file {
        std::path::PathBuf::from(cf)
    } else {
        wallet_path.with_file_name("orders.json")
    };

    let cache = OrderCache::load(&cache_path);

    if cache.orders.is_empty() {
        if json_output {
            println!("{}", serde_json::json!({
                "error": "Order cache is empty",
                "cache_path": cache_path.display().to_string(),
            }));
        } else {
            println!("Order cache ({}) is empty.", cache_path.display());
            println!("Populate by deploying orders via 'kob-cli deploy' or run auto-match.");
        }
        return Ok(());
    }

    if let Some(cf) = cache_file {
        // Pure cache mode -- no RPC needed
        info!(cache = cf, "loading order book from cache");

        let mut views = build_from_cache(&cache, token_filter);
        for view in &mut views {
            view.truncate(depth);
        }

        if json_output {
            let json_views: Vec<serde_json::Value> =
                views.iter().map(|v| v.to_json()).collect();
            println!("{}", serde_json::to_string_pretty(&json_views)?);
        } else {
            if views.is_empty() {
                println!("No orders found for the specified filter.");
            }
            for view in &views {
                println!("{}", view.format_table());
            }
        }
    } else {
        // Live mode -- scan via RPC using cache for parameter mapping
        info!(node = node_url, "querying live order book via RPC");

        println!("Connecting to {}...", node_url);
        let rpc = NodeClient::connect(node_url).await?;

        let mut views =
            build_live_from_cache(&rpc, &cache, token_filter, network_prefix).await?;
        for view in &mut views {
            view.truncate(depth);
        }

        if json_output {
            let json_views: Vec<serde_json::Value> =
                views.iter().map(|v| v.to_json()).collect();
            println!("{}", serde_json::to_string_pretty(&json_views)?);
        } else {
            println!(
                "Order Book (live, {} cached entries, depth={})",
                cache.orders.len(),
                depth,
            );
            println!();
            if views.is_empty() {
                println!("No live orders found for the specified filter.");
            }
            for view in &views {
                println!("{}", view.format_table());
            }
        }
    }

    Ok(())
}

/// Run the `order-status` command.
pub async fn run_order_status(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    let network_prefix = match network {
        Network::Mainnet => "kaspa",
        Network::Testnet => "kaspatest",
    };

    // Try to find the P2SH address from the order cache
    let cache_path = wallet_path.with_file_name("orders.json");
    let cache = OrderCache::load(&cache_path);

    // Look up cached entry by outpoint
    let cached_entry = cache.orders.iter().find(|o| o.outpoint == outpoint_str);

    let p2sh_address = cached_entry.and_then(|entry| {
        let hash_bytes = hex::decode(&entry.p2sh_hash).ok()?;
        if hash_bytes.len() == 32 {
            Some(kaspa_address_encode(network_prefix, 8, &hash_bytes))
        } else {
            None
        }
    });

    if !json_output {
        println!("Order Status");
        println!("=============");
        println!("Outpoint:  {}", outpoint_str);
        if let Some(entry) = cached_entry {
            println!("Side:      {}", entry.side);
            println!("Pair ID:   {}", entry.pair_id);
            println!("Price:     {}/{}", entry.price_num, entry.price_den);
            println!("Min Fill:  {}", entry.min_fill);
        } else {
            println!("(not found in local cache -- limited status info available)");
        }
        if let Some(ref addr) = p2sh_address {
            let addr_display = if addr.len() > 24 {
                format!("{}...{}", &addr[..14], &addr[addr.len() - 6..])
            } else {
                addr.clone()
            };
            println!("P2SH Addr: {}", addr_display);
        }
        println!();
        println!("Connecting to {}...", node_url);
    }

    let rpc = NodeClient::connect(node_url).await?;
    let status =
        determine_order_status(&rpc, outpoint_str, p2sh_address.as_deref()).await?;

    if json_output {
        let mut json = status.to_json();
        if let Some(entry) = cached_entry {
            json["side"] = serde_json::json!(entry.side);
            json["pair_id"] = serde_json::json!(entry.pair_id);
            json["price_num"] = serde_json::json!(entry.price_num);
            json["price_den"] = serde_json::json!(entry.price_den);
        }
        json["outpoint"] = serde_json::json!(outpoint_str);
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("Status:    {}", status.label());
        match &status {
            OrderStatus::Open { value } => {
                println!(
                    "Value:     {} sompi ({:.8} KAS)",
                    value,
                    *value as f64 / 1e8,
                );
            }
            OrderStatus::Filled { spending_tx } => {
                println!("Spent by:  {}", spending_tx);
            }
            OrderStatus::Cancelled { spending_tx } => {
                println!("Spent by:  {}", spending_tx);
            }
            OrderStatus::Spent { spending_tx } => {
                println!("Spent by:  {}", spending_tx);
            }
            OrderStatus::PartiallyFilled {
                spending_tx,
                residual_outpoint,
                residual_value,
            } => {
                println!("Spent by:  {}", spending_tx);
                println!("Residual:  {}", residual_outpoint);
                println!(
                    "Residual:  {} sompi ({:.8} KAS)",
                    residual_value,
                    *residual_value as f64 / 1e8,
                );
            }
            OrderStatus::Unknown => {
                println!("  Order UTXO not found on-chain. It may not exist or may");
                println!("  have been spent before the node's pruning point.");
            }
        }
    }

    Ok(())
}

// Spread display

/// Compute spread information from an OrderBookView.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: spread display for CLI and SDK
pub struct SpreadInfo {
    pub token: String,
    pub best_bid: Option<(u64, u64)>,  // (num, den)
    pub best_ask: Option<(u64, u64)>,  // (num, den)
    pub best_bid_value: u64,
    pub best_ask_value: u64,
}

#[allow(dead_code)] // Public API: spread display methods
impl SpreadInfo {
    /// Build spread info from a sorted OrderBookView.
    pub fn from_view(view: &OrderBookView) -> Self {
        let best_bid = view.bids.first().map(|b| (b.price_num, b.price_den));
        let best_ask = view.asks.first().map(|a| (a.price_num, a.price_den));
        let best_bid_value = view.bids.first().map(|b| b.value).unwrap_or(0);
        let best_ask_value = view.asks.first().map(|a| a.value).unwrap_or(0);
        SpreadInfo {
            token: view.token.clone(),
            best_bid,
            best_ask,
            best_bid_value,
            best_ask_value,
        }
    }

    /// Best bid price as f64.
    pub fn bid_price(&self) -> Option<f64> {
        self.best_bid.map(|(n, d)| {
            if d == 0 { 0.0 } else { n as f64 / d as f64 }
        })
    }

    /// Best ask price as f64.
    pub fn ask_price(&self) -> Option<f64> {
        self.best_ask.map(|(n, d)| {
            if d == 0 { 0.0 } else { n as f64 / d as f64 }
        })
    }

    /// Absolute spread (ask - bid).
    pub fn spread_abs(&self) -> Option<f64> {
        match (self.bid_price(), self.ask_price()) {
            (Some(bid), Some(ask)) => Some(ask - bid),
            _ => None,
        }
    }

    /// Spread as percentage of midpoint: (ask - bid) / midpoint * 100.
    pub fn spread_pct(&self) -> Option<f64> {
        match (self.bid_price(), self.ask_price()) {
            (Some(bid), Some(ask)) => {
                let mid = (bid + ask) / 2.0;
                if mid == 0.0 {
                    None
                } else {
                    Some((ask - bid) / mid * 100.0)
                }
            }
            _ => None,
        }
    }

    /// Format as one-liner display string.
    pub fn format_oneliner(&self) -> String {
        let bid_str = self
            .bid_price()
            .map(|p| format!("{:.6}", p))
            .unwrap_or_else(|| "---".to_string());
        let ask_str = self
            .ask_price()
            .map(|p| format!("{:.6}", p))
            .unwrap_or_else(|| "---".to_string());
        let spread_str = match (self.spread_abs(), self.spread_pct()) {
            (Some(abs), Some(pct)) => format!("{:.6} ({:.2}%)", abs, pct),
            _ => "N/A".to_string(),
        };
        format!(
            "Best Bid: {} | Best Ask: {} | Spread: {}",
            bid_str, ask_str, spread_str,
        )
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "token": self.token,
            "best_bid": self.bid_price(),
            "best_bid_num": self.best_bid.map(|b| b.0),
            "best_bid_den": self.best_bid.map(|b| b.1),
            "best_bid_value": self.best_bid_value,
            "best_ask": self.ask_price(),
            "best_ask_num": self.best_ask.map(|a| a.0),
            "best_ask_den": self.best_ask.map(|a| a.1),
            "best_ask_value": self.best_ask_value,
            "spread_abs": self.spread_abs(),
            "spread_pct": self.spread_pct(),
        })
    }
}

/// Run the `spread` command.
#[allow(dead_code)] // Public API: CLI spread command
pub async fn run_spread(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    token_filter: &str,
    json_output: bool,
    cache_file: Option<&str>,
) -> anyhow::Result<()> {
    let network_prefix = match network {
        Network::Mainnet => "kaspa",
        Network::Testnet => "kaspatest",
    };

    let cache_path = if let Some(cf) = cache_file {
        std::path::PathBuf::from(cf)
    } else {
        wallet_path.with_file_name("orders.json")
    };

    let cache = OrderCache::load(&cache_path);

    if cache.orders.is_empty() {
        if json_output {
            println!("{}", serde_json::json!({
                "error": "Order cache is empty",
            }));
        } else {
            println!("Order cache is empty. Deploy orders or run auto-match first.");
        }
        return Ok(());
    }

    let views = if cache_file.is_some() {
        let mut vs = build_from_cache(&cache, Some(token_filter));
        for v in &mut vs {
            v.sort();
        }
        vs
    } else {
        info!(node = node_url, token = token_filter, "querying spread via RPC");
        let rpc = NodeClient::connect(node_url).await?;
        let mut vs =
            build_live_from_cache(&rpc, &cache, Some(token_filter), network_prefix).await?;
        for v in &mut vs {
            v.sort();
        }
        vs
    };

    if views.is_empty() {
        if json_output {
            println!("{}", serde_json::json!({
                "token": token_filter,
                "error": "No orders found for this token",
            }));
        } else {
            println!("No orders found for token {}.", token_filter);
        }
        return Ok(());
    }

    for view in &views {
        let spread = SpreadInfo::from_view(view);
        if json_output {
            println!("{}", serde_json::to_string_pretty(&spread.to_json())?);
        } else {
            let label = if view.token.len() > 16 {
                format!("{}...", &view.token[..16])
            } else {
                view.token.clone()
            };
            println!("[{}] {}", label, spread.format_oneliner());
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn parse_outpoint_valid() {
        let (txid, idx) = parse_outpoint("abcdef1234567890:0").unwrap();
        assert_eq!(txid, "abcdef1234567890");
        assert_eq!(idx, 0);
    }

    #[test]
    fn parse_outpoint_valid_index_nonzero() {
        let (txid, idx) = parse_outpoint("ff00:3").unwrap();
        assert_eq!(txid, "ff00");
        assert_eq!(idx, 3);
    }

    #[test]
    fn parse_outpoint_missing_colon() {
        assert!(parse_outpoint("abcdef1234567890").is_err());
    }

    #[test]
    fn parse_outpoint_bad_index() {
        assert!(parse_outpoint("abcdef1234567890:xyz").is_err());
    }

    #[test]
    fn parse_outpoint_empty() {
        assert!(parse_outpoint("").is_err());
    }

    #[test]
    fn parse_outpoint_colon_at_end() {
        // "abc:" -> index is empty string -> parse error
        assert!(parse_outpoint("abc:").is_err());
    }


    fn make_entry(side: OrderSide, pnum: u64, pden: u64, value: u64) -> OrderBookEntry {
        OrderBookEntry {
            side,
            price_num: pnum,
            price_den: pden,
            value,
            outpoint: "aa".repeat(32) + ":0",
            pair_id: "00".repeat(32),
        }
    }

    #[test]
    fn entry_price_normal() {
        let e = make_entry(OrderSide::Buy, 3, 2, 10_000_000);
        assert!((e.price() - 1.5).abs() < 1e-10);
    }

    #[test]
    fn entry_price_zero_den() {
        let e = make_entry(OrderSide::Buy, 3, 0, 10_000_000);
        assert_eq!(e.price(), 0.0);
    }

    #[test]
    fn entry_value_kas() {
        let e = make_entry(OrderSide::Buy, 1, 1, 100_000_000);
        assert!((e.value_kas() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn entry_short_outpoint() {
        let e = OrderBookEntry {
            side: OrderSide::Buy,
            price_num: 1,
            price_den: 1,
            value: 100,
            outpoint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:2".to_string(),
            pair_id: String::new(),
        };
        assert_eq!(e.short_outpoint(), "abcdef01..:2");
    }

    #[test]
    fn entry_short_outpoint_short_txid() {
        let e = OrderBookEntry {
            side: OrderSide::Sell,
            price_num: 1,
            price_den: 1,
            value: 100,
            outpoint: "abc:0".to_string(),
            pair_id: String::new(),
        };
        assert_eq!(e.short_outpoint(), "abc..:0");
    }


    #[test]
    fn view_sort_bids_descending() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![
                make_entry(OrderSide::Buy, 1, 1, 10_000_000), // price 1
                make_entry(OrderSide::Buy, 5, 1, 10_000_000), // price 5
                make_entry(OrderSide::Buy, 3, 1, 10_000_000), // price 3
            ],
            asks: vec![],
        };
        view.sort();
        assert_eq!(view.bids[0].price_num, 5);
        assert_eq!(view.bids[1].price_num, 3);
        assert_eq!(view.bids[2].price_num, 1);
    }

    #[test]
    fn view_sort_asks_ascending() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![],
            asks: vec![
                make_entry(OrderSide::Sell, 10, 1, 10_000_000), // price 10
                make_entry(OrderSide::Sell, 3, 1, 10_000_000),  // price 3
                make_entry(OrderSide::Sell, 7, 1, 10_000_000),  // price 7
            ],
        };
        view.sort();
        assert_eq!(view.asks[0].price_num, 3);
        assert_eq!(view.asks[1].price_num, 7);
        assert_eq!(view.asks[2].price_num, 10);
    }

    #[test]
    fn view_truncate() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![
                make_entry(OrderSide::Buy, 5, 1, 10_000_000),
                make_entry(OrderSide::Buy, 4, 1, 10_000_000),
                make_entry(OrderSide::Buy, 3, 1, 10_000_000),
            ],
            asks: vec![
                make_entry(OrderSide::Sell, 6, 1, 10_000_000),
                make_entry(OrderSide::Sell, 7, 1, 10_000_000),
            ],
        };
        view.truncate(2);
        assert_eq!(view.bids.len(), 2);
        assert_eq!(view.asks.len(), 2);
    }

    #[test]
    fn view_truncate_no_shrink() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 5, 1, 10_000_000)],
            asks: vec![],
        };
        view.truncate(10);
        assert_eq!(view.bids.len(), 1);
        assert_eq!(view.asks.len(), 0);
    }


    #[test]
    fn view_format_table_empty() {
        let view = OrderBookView {
            token: "TOKEN_ABC".to_string(),
            bids: vec![],
            asks: vec![],
        };
        let table = view.format_table();
        assert!(table.contains("TOKEN_ABC"));
        assert!(table.contains("(no orders)"));
    }

    #[test]
    fn view_format_table_with_entries() {
        let view = OrderBookView {
            token: "TESTTOKEN".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 3, 2, 15_000_000)],
            asks: vec![make_entry(OrderSide::Sell, 7, 4, 20_000_000)],
        };
        let table = view.format_table();
        assert!(table.contains("TESTTOKEN"));
        assert!(table.contains("1 bid(s)"));
        assert!(table.contains("1 ask(s)"));
    }


    #[test]
    fn view_to_json_structure() {
        let view = OrderBookView {
            token: "abc123".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 10, 1, 50_000_000)],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 30_000_000)],
        };
        let json = view.to_json();
        assert_eq!(json["token"], "abc123");
        assert_eq!(json["bid_count"], 1);
        assert_eq!(json["ask_count"], 1);
        assert!(json["bids"].is_array());
        assert!(json["asks"].is_array());
        assert_eq!(json["bids"][0]["side"], "buy");
        assert_eq!(json["asks"][0]["side"], "sell");
        assert_eq!(json["bids"][0]["price_num"], 10);
    }


    #[test]
    fn order_status_labels() {
        assert_eq!(OrderStatus::Open { value: 100 }.label(), "OPEN");
        assert_eq!(
            OrderStatus::Filled {
                spending_tx: "x".into()
            }
            .label(),
            "FILLED"
        );
        assert_eq!(
            OrderStatus::Cancelled {
                spending_tx: "x".into()
            }
            .label(),
            "CANCELLED"
        );
        assert_eq!(
            OrderStatus::Spent {
                spending_tx: "x".into()
            }
            .label(),
            "SPENT"
        );
        assert_eq!(
            OrderStatus::PartiallyFilled {
                spending_tx: "x".into(),
                residual_outpoint: "y:0".into(),
                residual_value: 50,
            }
            .label(),
            "PARTIALLY_FILLED"
        );
        assert_eq!(OrderStatus::Unknown.label(), "UNKNOWN");
    }

    #[test]
    fn order_status_to_json_open() {
        let s = OrderStatus::Open { value: 10_000_000 };
        let j = s.to_json();
        assert_eq!(j["status"], "OPEN");
        assert_eq!(j["value"], 10_000_000);
    }

    #[test]
    fn order_status_to_json_filled() {
        let s = OrderStatus::Filled {
            spending_tx: "tx123".into(),
        };
        let j = s.to_json();
        assert_eq!(j["status"], "FILLED");
        assert_eq!(j["spending_tx"], "tx123");
    }

    #[test]
    fn order_status_to_json_partial() {
        let s = OrderStatus::PartiallyFilled {
            spending_tx: "tx456".into(),
            residual_outpoint: "tx456:1".into(),
            residual_value: 5_000_000,
        };
        let j = s.to_json();
        assert_eq!(j["status"], "PARTIALLY_FILLED");
        assert_eq!(j["residual_outpoint"], "tx456:1");
        assert_eq!(j["residual_value"], 5_000_000);
    }


    fn make_cache_entry(
        side: &str,
        pair_id: &str,
        pnum: u64,
        pden: u64,
        value: u64,
        idx: u32,
    ) -> OrderCacheEntry {
        OrderCacheEntry {
            outpoint: format!("{}:{}", "aa".repeat(32), idx),
            side: side.to_string(),
            pair_id: pair_id.to_string(),
            price_num: pnum,
            price_den: pden,
            min_fill: 3_000_000,
            owner_hash: "bb".repeat(32),
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
    fn build_from_cache_empty() {
        let cache = OrderCache::default();
        let views = build_from_cache(&cache, None);
        assert!(views.is_empty());
    }

    #[test]
    fn build_from_cache_single_pair() {
        let pair = "00".repeat(32);
        let mut cache = OrderCache::default();
        cache.orders.push(make_cache_entry("buy", &pair, 10, 1, 10_000_000, 0));
        cache.orders.push(make_cache_entry("sell", &pair, 12, 1, 8_000_000, 1));

        let views = build_from_cache(&cache, None);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].bids.len(), 1);
        assert_eq!(views[0].asks.len(), 1);
    }

    #[test]
    fn build_from_cache_multiple_pairs() {
        let pair_a = "aa".repeat(32);
        let pair_b = "bb".repeat(32);
        let mut cache = OrderCache::default();
        cache.orders.push(make_cache_entry("buy", &pair_a, 10, 1, 10_000_000, 0));
        cache.orders.push(make_cache_entry("sell", &pair_b, 12, 1, 8_000_000, 1));

        let views = build_from_cache(&cache, None);
        assert_eq!(views.len(), 2);
    }

    #[test]
    fn build_from_cache_with_filter() {
        let pair_a = "aa".repeat(32);
        let pair_b = "bb".repeat(32);
        let mut cache = OrderCache::default();
        cache.orders.push(make_cache_entry("buy", &pair_a, 10, 1, 10_000_000, 0));
        cache.orders.push(make_cache_entry("sell", &pair_b, 12, 1, 8_000_000, 1));

        let views = build_from_cache(&cache, Some(&pair_a));
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].token, pair_a);
        assert_eq!(views[0].bids.len(), 1);
        assert_eq!(views[0].asks.len(), 0);
    }

    #[test]
    fn build_from_cache_sorted() {
        let pair = "00".repeat(32);
        let mut cache = OrderCache::default();
        cache.orders.push(make_cache_entry("buy", &pair, 1, 1, 10_000_000, 0));
        cache.orders.push(make_cache_entry("buy", &pair, 5, 1, 10_000_000, 1));
        cache.orders.push(make_cache_entry("buy", &pair, 3, 1, 10_000_000, 2));

        let views = build_from_cache(&cache, None);
        assert_eq!(views.len(), 1);
        // Bids sorted descending by price
        assert_eq!(views[0].bids[0].price_num, 5);
        assert_eq!(views[0].bids[1].price_num, 3);
        assert_eq!(views[0].bids[2].price_num, 1);
    }

    #[test]
    fn build_from_cache_filter_no_match() {
        let pair = "00".repeat(32);
        let mut cache = OrderCache::default();
        cache.orders.push(make_cache_entry("buy", &pair, 10, 1, 10_000_000, 0));

        let views = build_from_cache(&cache, Some("ff".repeat(32).as_str()));
        assert!(views.is_empty());
    }


    #[test]
    fn view_sort_rational_bids() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![
                make_entry(OrderSide::Buy, 3, 2, 10_000_000), // 1.5
                make_entry(OrderSide::Buy, 7, 5, 10_000_000), // 1.4
                make_entry(OrderSide::Buy, 2, 1, 10_000_000), // 2.0
            ],
            asks: vec![],
        };
        view.sort();
        // Descending: 2.0, 1.5, 1.4
        assert_eq!(view.bids[0].price_num, 2);
        assert_eq!(view.bids[0].price_den, 1);
        assert_eq!(view.bids[1].price_num, 3);
        assert_eq!(view.bids[1].price_den, 2);
        assert_eq!(view.bids[2].price_num, 7);
        assert_eq!(view.bids[2].price_den, 5);
    }

    #[test]
    fn view_sort_rational_asks() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![],
            asks: vec![
                make_entry(OrderSide::Sell, 7, 4, 10_000_000), // 1.75
                make_entry(OrderSide::Sell, 3, 2, 10_000_000), // 1.5
                make_entry(OrderSide::Sell, 2, 1, 10_000_000), // 2.0
            ],
        };
        view.sort();
        // Ascending: 1.5, 1.75, 2.0
        assert_eq!(view.asks[0].price_num, 3);
        assert_eq!(view.asks[0].price_den, 2);
        assert_eq!(view.asks[1].price_num, 7);
        assert_eq!(view.asks[1].price_den, 4);
        assert_eq!(view.asks[2].price_num, 2);
        assert_eq!(view.asks[2].price_den, 1);
    }


    #[test]
    fn order_status_eq() {
        assert_eq!(OrderStatus::Unknown, OrderStatus::Unknown);
        assert_eq!(
            OrderStatus::Open { value: 100 },
            OrderStatus::Open { value: 100 },
        );
        assert_ne!(
            OrderStatus::Open { value: 100 },
            OrderStatus::Open { value: 200 },
        );
    }


    #[test]
    fn spread_from_view_both_sides() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![
                make_entry(OrderSide::Buy, 10, 1, 50_000_000),
                make_entry(OrderSide::Buy, 8, 1, 30_000_000),
            ],
            asks: vec![
                make_entry(OrderSide::Sell, 12, 1, 40_000_000),
                make_entry(OrderSide::Sell, 15, 1, 20_000_000),
            ],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        assert_eq!(spread.best_bid, Some((10, 1)));
        assert_eq!(spread.best_ask, Some((12, 1)));
        assert!((spread.bid_price().unwrap() - 10.0).abs() < 1e-10);
        assert!((spread.ask_price().unwrap() - 12.0).abs() < 1e-10);
    }

    #[test]
    fn spread_abs_and_pct() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 10, 1, 50_000_000)],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 40_000_000)],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        assert!((spread.spread_abs().unwrap() - 2.0).abs() < 1e-10);
        // pct = (12-10)/11 * 100 = 18.18...
        assert!((spread.spread_pct().unwrap() - 18.181818).abs() < 0.001);
    }

    #[test]
    fn spread_no_bids() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 40_000_000)],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        assert!(spread.best_bid.is_none());
        assert!(spread.bid_price().is_none());
        assert!(spread.spread_abs().is_none());
        assert!(spread.spread_pct().is_none());
    }

    #[test]
    fn spread_no_asks() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 10, 1, 50_000_000)],
            asks: vec![],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        assert!(spread.best_ask.is_none());
        assert!(spread.ask_price().is_none());
        assert!(spread.spread_abs().is_none());
    }

    #[test]
    fn spread_empty_book() {
        let view = OrderBookView {
            token: "test".to_string(),
            bids: vec![],
            asks: vec![],
        };
        let spread = SpreadInfo::from_view(&view);
        assert!(spread.best_bid.is_none());
        assert!(spread.best_ask.is_none());
        assert!(spread.spread_abs().is_none());
        assert!(spread.spread_pct().is_none());
    }

    #[test]
    fn spread_format_oneliner_both() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 10, 1, 50_000_000)],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 40_000_000)],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        let line = spread.format_oneliner();
        assert!(line.contains("Best Bid:"));
        assert!(line.contains("Best Ask:"));
        assert!(line.contains("Spread:"));
        assert!(line.contains("%"));
    }

    #[test]
    fn spread_format_oneliner_no_bids() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 40_000_000)],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        let line = spread.format_oneliner();
        assert!(line.contains("---"));
        assert!(line.contains("N/A"));
    }

    #[test]
    fn spread_to_json_structure() {
        let mut view = OrderBookView {
            token: "abc123".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 10, 1, 50_000_000)],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 40_000_000)],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        let json = spread.to_json();
        assert_eq!(json["token"], "abc123");
        assert!(json["best_bid"].as_f64().is_some());
        assert!(json["best_ask"].as_f64().is_some());
        assert!(json["spread_abs"].as_f64().is_some());
        assert!(json["spread_pct"].as_f64().is_some());
    }

    #[test]
    fn spread_rational_prices() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 3, 2, 50_000_000)],  // 1.5
            asks: vec![make_entry(OrderSide::Sell, 7, 4, 40_000_000)], // 1.75
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        assert!((spread.bid_price().unwrap() - 1.5).abs() < 1e-10);
        assert!((spread.ask_price().unwrap() - 1.75).abs() < 1e-10);
        assert!((spread.spread_abs().unwrap() - 0.25).abs() < 1e-10);
    }

    #[test]
    fn spread_zero_den() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 10, 0, 50_000_000)],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 40_000_000)],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        // bid price is 0.0 due to zero den
        assert_eq!(spread.bid_price().unwrap(), 0.0);
    }

    #[test]
    fn spread_values_captured() {
        let mut view = OrderBookView {
            token: "test".to_string(),
            bids: vec![make_entry(OrderSide::Buy, 10, 1, 50_000_000)],
            asks: vec![make_entry(OrderSide::Sell, 12, 1, 40_000_000)],
        };
        view.sort();
        let spread = SpreadInfo::from_view(&view);
        assert_eq!(spread.best_bid_value, 50_000_000);
        assert_eq!(spread.best_ask_value, 40_000_000);
    }

}
