//! `kob-cli mm` -- Market Maker bot for continuous two-sided quoting.
//!
//! Deploys symmetric buy/sell orders around a reference mid-price, monitors
//! for fills, and re-deploys filled orders to maintain continuous liquidity.
//!
//! ## Strategy
//!
//! The bot maintains `levels` buy orders below mid and `levels` sell orders
//! above mid. Each level is offset by `spread_bps * level_index` basis points.
//! When a fill is detected (order UTXO disappears), the level is re-deployed.
//! When mid-price drifts beyond `requote_threshold_bps`, all orders are
//! cancelled and re-deployed around the new mid.
//!
//! ## State Persistence
//!
//! Active orders are tracked in `mm_state.json` so the bot can resume after
//! restart. Each entry stores the outpoint, side, level index, and price.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Configuration for the market maker bot.
#[derive(Debug, Clone)]
pub struct MmConfig {
    /// Token covenant ID (hex, 64 chars).
    pub token: String,
    /// Mid-price numerator.
    pub mid_price_num: u64,
    /// Mid-price denominator.
    pub mid_price_den: u64,
    /// Spread per level in basis points (100 = 1%).
    pub spread_bps: u64,
    /// Number of levels per side.
    pub levels: u32,
    /// KAS amount per order (sompi).
    pub amount: u64,
    /// Requote check interval in seconds.
    pub interval_secs: u64,
    /// Print orders without deploying.
    pub dry_run: bool,
    /// Contract version (v18 only — new quotes are always v18).
    pub version: u8,
    /// Min fill per order (sompi).
    pub min_fill: u64,
    /// Requote threshold: cancel all if mid drifts more than this many bps.
    pub requote_threshold_bps: u64,
    /// Delay between successive deploy TXs in seconds (H12).
    pub deploy_delay_secs: u64,
}

impl MmConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.token.len() != 64 {
            anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
        }
        if hex::decode(&self.token).is_err() {
            anyhow::bail!("token covenant ID must be valid hex");
        }
        if self.mid_price_num == 0 {
            anyhow::bail!("mid-price numerator must be > 0");
        }
        if self.mid_price_den == 0 {
            anyhow::bail!("mid-price denominator must be > 0");
        }
        if self.spread_bps == 0 {
            anyhow::bail!("spread_bps must be > 0");
        }
        if self.levels == 0 {
            anyhow::bail!("levels must be > 0");
        }
        if self.amount == 0 {
            anyhow::bail!("amount must be > 0");
        }
        if self.interval_secs == 0 {
            anyhow::bail!("interval must be > 0");
        }
        if self.version != 18 {
            anyhow::bail!("version must be 18 (new quotes deploy as v18 only)");
        }
        if self.min_fill == 0 {
            anyhow::bail!("min_fill must be > 0");
        }
        if self.amount < self.min_fill {
            anyhow::bail!("amount must be >= min_fill");
        }
        Ok(())
    }
}

/// A single price level for a market maker order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceLevel {
    /// Price numerator.
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
}

impl PriceLevel {
    pub fn as_f64(&self) -> f64 {
        self.price_num as f64 / self.price_den as f64
    }
}

/// Compute price levels for one side of the book.
///
/// For buy (bid) levels: price = mid * (1 - spread_bps * level / 10000)
/// For sell (ask) levels: price = mid * (1 + spread_bps * level / 10000)
///
/// Uses integer arithmetic to avoid floating-point rounding:
///   buy:  num = mid_num * (10000 - spread_bps * level), den = mid_den * 10000
///   sell: num = mid_num * (10000 + spread_bps * level), den = mid_den * 10000
///
/// Returns levels indexed 1..=count (level 0 is mid itself).
pub fn compute_price_levels(
    mid_num: u64,
    mid_den: u64,
    spread_bps: u64,
    levels: u32,
    side: &str,
) -> Vec<PriceLevel> {
    let mut result = Vec::with_capacity(levels as usize);
    for i in 1..=levels {
        let offset = spread_bps as u128 * i as u128;
        // Use u128 intermediate to avoid overflow on mid_num * (10000 +/- offset)
        let (num128, den128) = match side {
            "buy" => {
                if offset >= 10000 {
                    // Price would be zero or negative; skip
                    continue;
                }
                (mid_num as u128 * (10000 - offset), mid_den as u128 * 10000)
            }
            "sell" => (mid_num as u128 * (10000 + offset), mid_den as u128 * 10000),
            _ => continue,
        };
        // Simplify by GCD (in u128 space) then convert back to u64
        let g = gcd128(num128, den128);
        let num_reduced = num128 / g;
        let den_reduced = den128 / g;
        // If reduced values exceed u64, skip this level (extreme parameters)
        let Ok(num) = u64::try_from(num_reduced) else {
            warn!("[MM] Price level {} overflows u64 after GCD reduction, skipping", i);
            continue;
        };
        let Ok(den) = u64::try_from(den_reduced) else {
            warn!("[MM] Price level {} overflows u64 after GCD reduction, skipping", i);
            continue;
        };
        result.push(PriceLevel {
            price_num: num,
            price_den: den,
        });
    }
    result
}

/// Greatest common divisor (Euclidean algorithm).
#[allow(dead_code)] // Used in tests
pub fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Greatest common divisor for u128 values.
fn gcd128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Check whether mid-price has drifted beyond threshold.
///
/// Returns true if |new_mid - old_mid| / old_mid > threshold_bps / 10000.
/// Uses cross-multiplication to avoid floating point:
///   |new_num * old_den - old_num * new_den| * 10000 > threshold_bps * old_num * new_den
pub fn price_drifted(
    old_num: u64, old_den: u64,
    new_num: u64, new_den: u64,
    threshold_bps: u64,
) -> bool {
    // Use u128 to avoid overflow
    let old_cross = old_num as u128 * new_den as u128;
    let new_cross = new_num as u128 * old_den as u128;
    let diff = new_cross.abs_diff(old_cross);
    // diff / old_cross > threshold_bps / 10000
    // => diff * 10000 > threshold_bps * old_cross
    diff * 10000 > threshold_bps as u128 * old_cross
}

/// State of a single active MM order.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MmOrderState {
    /// Transaction ID of the deploy TX.
    pub tx_id: String,
    /// Output index (always 0 for deploys).
    pub index: u32,
    /// "buy" or "sell".
    pub side: String,
    /// Level index (1-based).
    pub level: u32,
    /// Price numerator.
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
    /// Amount in sompi.
    pub amount: u64,
    /// P2SH address of the deployed order (for fill detection).
    /// Added in v2; defaults to empty for legacy state files.
    #[serde(default)]
    pub p2sh_address: String,
}

impl MmOrderState {
    /// Outpoint string "txid:index".
    pub fn outpoint_str(&self) -> String {
        format!("{}:{}", self.tx_id, self.index)
    }
}

/// Full MM bot state persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MmState {
    /// Token covenant ID.
    pub token: String,
    /// Current mid-price numerator.
    pub mid_price_num: u64,
    /// Current mid-price denominator.
    pub mid_price_den: u64,
    /// Active orders.
    pub orders: Vec<MmOrderState>,
}

impl MmState {
    /// Load state from a JSON file. Returns default if file doesn't exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)?;
        let state: MmState = serde_json::from_str(&data)?;
        Ok(state)
    }

    /// Save state to a JSON file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Find orders that are missing from a set of live outpoints.
    /// Returns the indices into self.orders of filled/missing orders.
    pub fn find_filled_orders(&self, live_outpoints: &[String]) -> Vec<usize> {
        self.orders
            .iter()
            .enumerate()
            .filter(|(_, o)| !live_outpoints.contains(&o.outpoint_str()))
            .map(|(i, _)| i)
            .collect()
    }

    /// Get orders for a specific side.
    #[allow(dead_code)] // Used in tests
    pub fn orders_by_side(&self, side: &str) -> Vec<&MmOrderState> {
        self.orders.iter().filter(|o| o.side == side).collect()
    }

    /// Remove orders at given indices (sorted descending to preserve indices).
    pub fn remove_orders(&mut self, mut indices: Vec<usize>) {
        indices.sort_unstable_by(|a, b| b.cmp(a));
        for i in indices {
            if i < self.orders.len() {
                self.orders.remove(i);
            }
        }
    }

    /// Add an order to state.
    pub fn add_order(&mut self, order: MmOrderState) {
        self.orders.push(order);
    }
}

/// Plan for deploying MM orders. Used by dry-run and actual deployment.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct MmDeployPlan {
    pub buy_levels: Vec<PriceLevel>,
    pub sell_levels: Vec<PriceLevel>,
    pub amount_per_order: u64,
    pub min_fill: u64,
    pub total_orders: usize,
    pub total_kas_needed: u64,
}

/// Build the deployment plan for initial MM setup.
pub fn build_deploy_plan(config: &MmConfig) -> MmDeployPlan {
    let buy_levels = compute_price_levels(
        config.mid_price_num,
        config.mid_price_den,
        config.spread_bps,
        config.levels,
        "buy",
    );
    let sell_levels = compute_price_levels(
        config.mid_price_num,
        config.mid_price_den,
        config.spread_bps,
        config.levels,
        "sell",
    );

    let total_orders = buy_levels.len() + sell_levels.len();
    // Each order needs amount + estimated deploy fee (1 input, 2 outputs, ~200B payload)
    let deploy_fee_estimate = kob_core::mass::estimate_compute_mass(1, 2, 200);
    let total_kas_needed = match config.amount
        .checked_add(deploy_fee_estimate)
        .and_then(|per_order| per_order.checked_mul(total_orders as u64))
    {
        Some(v) => v,
        None => {
            eprintln!("[MM] WARNING: overflow computing total KAS needed; capping at u64::MAX");
            u64::MAX
        }
    };

    MmDeployPlan {
        buy_levels,
        sell_levels,
        amount_per_order: config.amount,
        min_fill: config.min_fill,
        total_orders,
        total_kas_needed,
    }
}

/// Print the deployment plan (used by both dry-run and actual deploy).
pub fn print_deploy_plan(config: &MmConfig, plan: &MmDeployPlan) {
    let mid_f = config.mid_price_num as f64 / config.mid_price_den as f64;
    println!("Market Maker Bot");
    println!("=================");
    println!("Token:          {}", config.token);
    println!(
        "Mid Price:      {}/{} ({:.8})",
        config.mid_price_num, config.mid_price_den, mid_f
    );
    println!("Spread:         {} bps ({:.2}%)", config.spread_bps, config.spread_bps as f64 / 100.0);
    println!("Levels:         {} per side", config.levels);
    println!(
        "Amount/Order:   {} sompi ({:.8} KAS)",
        config.amount,
        config.amount as f64 / 1e8
    );
    println!("Min Fill:       {} sompi", config.min_fill);
    println!("Version:        v{}", config.version);
    println!("Interval:       {}s", config.interval_secs);
    println!(
        "Requote:        {} bps drift triggers full requote",
        config.requote_threshold_bps
    );
    println!();

    println!("--- Buy Levels (Bids) ---");
    for (i, level) in plan.buy_levels.iter().enumerate() {
        println!(
            "  L{}: {}/{} ({:.8}) -- {} sompi",
            i + 1,
            level.price_num,
            level.price_den,
            level.as_f64(),
            plan.amount_per_order
        );
    }
    println!();

    println!("--- Sell Levels (Asks) ---");
    for (i, level) in plan.sell_levels.iter().enumerate() {
        println!(
            "  L{}: {}/{} ({:.8}) -- {} sompi",
            i + 1,
            level.price_num,
            level.price_den,
            level.as_f64(),
            plan.amount_per_order
        );
    }
    println!();

    println!("Total Orders:   {}", plan.total_orders);
    println!(
        "Total KAS:      {} sompi ({:.8} KAS)",
        plan.total_kas_needed,
        plan.total_kas_needed as f64 / 1e8
    );
}

/// Resolve the state file path next to the wallet file.
pub fn state_file_path(wallet_path: &Path) -> PathBuf {
    wallet_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("mm_state.json")
}

/// Sleep for `secs` seconds OR return early if `shutdown` is signaled.
/// Returns `true` if shutdown was triggered (caller should break out of its loop).
async fn interruptible_sleep(secs: u64, shutdown: &Arc<AtomicBool>) -> bool {
    let dur = std::time::Duration::from_secs(secs);
    let poll = std::time::Duration::from_millis(200);
    let deadline = std::time::Instant::now() + dur;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        tokio::time::sleep(remaining.min(poll)).await;
    }
}

/// Run the market maker bot (async entry point called from main).
///
/// In dry-run mode, prints the plan and exits.
/// In live mode, deploys initial orders and enters the monitor loop.
///
/// `cleanup_on_shutdown`: when true (default), Ctrl+C triggers a best-effort
/// cancel of every active order before exit. When false, orders are left
/// on-chain for manual cleanup or resume.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    _network: kob_core::types::Network,
    config: &MmConfig,
    cleanup_on_shutdown: bool,
) -> anyhow::Result<()> {
    config.validate()?;

    let plan = build_deploy_plan(config);
    print_deploy_plan(config, &plan);

    if config.dry_run {
        println!("[DRY RUN] No orders deployed.");
        return Ok(());
    }

    // Shutdown signaling: a background task watches for Ctrl+C and flips
    // `shutdown` so the bot can exit at the next checkpoint and run cleanup.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!();
                eprintln!("[MM] Shutdown signal received. Will exit at next checkpoint.");
                shutdown.store(true, Ordering::SeqCst);
            }
        });
    }

    println!("Starting market maker...");
    if cleanup_on_shutdown {
        println!("Press Ctrl+C to stop and cancel all active orders.");
    } else {
        println!("Press Ctrl+C to stop (orders will be left on-chain; --no-cleanup).");
    }
    println!();

    let state_path = state_file_path(wallet_path);
    let mut state = MmState::load(&state_path)?;

    // If we have existing state for this token, resume monitoring
    'init: {
        if !state.orders.is_empty() && state.token == config.token {
            println!(
                "Resuming with {} existing orders from state file.",
                state.orders.len()
            );
            break 'init;
        }
        // Deploy initial orders
        state.token = config.token.clone();
        state.mid_price_num = config.mid_price_num;
        state.mid_price_den = config.mid_price_den;
        state.orders.clear();

        println!("Deploying {} initial orders...", plan.total_orders);
        println!();

        // Deploy buy orders
        for (i, level) in plan.buy_levels.iter().enumerate() {
            if shutdown.load(Ordering::SeqCst) {
                break 'init;
            }
            println!(
                "Deploying buy L{}: {}/{} ({:.8})...",
                i + 1,
                level.price_num,
                level.price_den,
                level.as_f64()
            );
            match deploy_order(
                wallet_path,
                node_url,
                &config.token,
                "buy",
                level.price_num,
                level.price_den,
                config.min_fill,
                config.amount,
                config.version,
            )
            .await
            {
                Ok((tx_id, p2sh_address)) => {
                    println!("  TXID: {}", tx_id);
                    state.add_order(MmOrderState {
                        tx_id,
                        index: 0,
                        side: "buy".to_string(),
                        level: (i + 1) as u32,
                        price_num: level.price_num,
                        price_den: level.price_den,
                        amount: config.amount,
                        p2sh_address,
                    });
                    state.save(&state_path)?;
                }
                Err(e) => {
                    error!("  FAILED: {}", e);
                }
            }
            // Small delay between deploys to avoid UTXO contention
            if interruptible_sleep(config.deploy_delay_secs, &shutdown).await {
                break 'init;
            }
        }

        // Deploy sell orders
        for (i, level) in plan.sell_levels.iter().enumerate() {
            if shutdown.load(Ordering::SeqCst) {
                break 'init;
            }
            println!(
                "Deploying sell L{}: {}/{} ({:.8})...",
                i + 1,
                level.price_num,
                level.price_den,
                level.as_f64()
            );
            match deploy_order(
                wallet_path,
                node_url,
                &config.token,
                "sell",
                level.price_num,
                level.price_den,
                config.min_fill,
                config.amount,
                config.version,
            )
            .await
            {
                Ok((tx_id, p2sh_address)) => {
                    println!("  TXID: {}", tx_id);
                    state.add_order(MmOrderState {
                        tx_id,
                        index: 0,
                        side: "sell".to_string(),
                        level: (i + 1) as u32,
                        price_num: level.price_num,
                        price_den: level.price_den,
                        amount: config.amount,
                        p2sh_address,
                    });
                    state.save(&state_path)?;
                }
                Err(e) => {
                    error!("  FAILED: {}", e);
                }
            }
            if interruptible_sleep(config.deploy_delay_secs, &shutdown).await {
                break 'init;
            }
        }

        println!();
        println!(
            "Initial deployment complete. {} orders active.",
            state.orders.len()
        );
    }

    // Monitor loop
    println!();
    println!("Entering monitor loop (interval: {}s)...", config.interval_secs);

    while !shutdown.load(Ordering::SeqCst) {
        if interruptible_sleep(config.interval_secs, &shutdown).await {
            break;
        }

        // Check which orders are still live
        let rpc = match crate::rpc::RpcClient::connect(node_url).await {
            Ok(r) => r,
            Err(e) => {
                warn!("[MM] RPC connect failed: {}. Retrying next cycle.", e);
                continue;
            }
        };

        let wallet = match kob_core::wallet::WalletContext::load(wallet_path) {
            Ok(w) => w,
            Err(e) => {
                warn!("[MM] Wallet load failed: {}. Retrying next cycle.", e);
                continue;
            }
        };

        // Query P2SH UTXOs for our orders to detect fills.
        // Orders live at P2SH addresses, not the wallet address.
        // Collect unique P2SH addresses from active orders.
        let p2sh_addresses: Vec<String> = {
            let mut addrs: Vec<String> = state
                .orders
                .iter()
                .filter(|o| !o.p2sh_address.is_empty())
                .map(|o| o.p2sh_address.clone())
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            addrs
        };

        let live_outpoints = if p2sh_addresses.is_empty() {
            // Legacy state with no P2SH addresses -- fall back to wallet UTXOs
            // (will mis-detect fills, but at least doesn't panic)
            warn!("[MM] No P2SH addresses in state; legacy state file? Fill detection degraded.");
            let utxos = match rpc.get_spendable_utxos(&wallet.address, None).await {
                Ok(u) => u,
                Err(e) => {
                    warn!("[MM] UTXO query failed: {}. Retrying next cycle.", e);
                    continue;
                }
            };
            utxos
                .iter()
                .map(|u| format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index))
                .collect::<Vec<String>>()
        } else {
            // Query P2SH addresses in a single RPC call
            let addr_refs: Vec<&str> = p2sh_addresses.iter().map(|s| s.as_str()).collect();
            match rpc.get_utxos_by_addresses(&addr_refs).await {
                Ok(utxos) => utxos
                    .iter()
                    .map(|u| format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index))
                    .collect::<Vec<String>>(),
                Err(e) => {
                    warn!("[MM] P2SH UTXO query failed: {}. Retrying next cycle.", e);
                    continue;
                }
            }
        };

        let filled_indices = state.find_filled_orders(&live_outpoints);

        if !filled_indices.is_empty() {
            println!(
                "[MM] {} orders appear filled. Re-deploying...",
                filled_indices.len()
            );

            // Collect info about filled orders before removing them
            let filled_orders: Vec<MmOrderState> = filled_indices
                .iter()
                .filter_map(|&i| state.orders.get(i).cloned())
                .collect();

            // Remove filled orders from state
            state.remove_orders(filled_indices);

            // Re-deploy each filled order at the same level
            for order in &filled_orders {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                println!(
                    "[MM] Re-deploying {} L{} at {}/{}...",
                    order.side, order.level, order.price_num, order.price_den
                );
                match deploy_order(
                    wallet_path,
                    node_url,
                    &config.token,
                    &order.side,
                    order.price_num,
                    order.price_den,
                    config.min_fill,
                    order.amount,
                    config.version,
                )
                .await
                {
                    Ok((tx_id, p2sh_address)) => {
                        println!("[MM] Re-deployed: {}", tx_id);
                        state.add_order(MmOrderState {
                            tx_id,
                            index: 0,
                            side: order.side.clone(),
                            level: order.level,
                            price_num: order.price_num,
                            price_den: order.price_den,
                            amount: order.amount,
                            p2sh_address,
                        });
                    }
                    Err(e) => {
                        error!("[MM] Re-deploy FAILED: {}", e);
                    }
                }
                if interruptible_sleep(config.deploy_delay_secs, &shutdown).await {
                    break;
                }
            }

            state.save(&state_path)?;
        }

        // Check for price drift (atomic requote: deploy new BEFORE canceling old)
        if price_drifted(
            state.mid_price_num,
            state.mid_price_den,
            config.mid_price_num,
            config.mid_price_den,
            config.requote_threshold_bps,
        ) {
            println!(
                "[MM] Price drift detected! Old mid: {}/{}, New mid: {}/{}",
                state.mid_price_num, state.mid_price_den,
                config.mid_price_num, config.mid_price_den
            );
            println!("[MM] Atomic requote: deploying new orders BEFORE canceling old.");
            println!("[MM] Note: this temporarily doubles inventory exposure during requote.");
            println!("[MM]       Ensure wallet has 2x quote balance, or some new deploys will fail.");

            let new_plan = build_deploy_plan(config);
            let old_orders: Vec<MmOrderState> = state.orders.clone();

            // ----- Phase 1: deploy new orders at new prices -----
            // (old orders are still live on-chain — zero-exposure window eliminated)
            println!(
                "[MM] Phase 1: deploying {} new orders at new mid...",
                new_plan.total_orders
            );
            let mut new_tx_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut deploy_failures = 0u32;
            for (i, level) in new_plan.buy_levels.iter().enumerate() {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                println!(
                    "[MM] Phase 1 deploy buy L{}: {}/{}...",
                    i + 1, level.price_num, level.price_den
                );
                match deploy_order(
                    wallet_path,
                    node_url,
                    &config.token,
                    "buy",
                    level.price_num,
                    level.price_den,
                    config.min_fill,
                    config.amount,
                    config.version,
                )
                .await
                {
                    Ok((tx_id, p2sh_address)) => {
                        new_tx_ids.insert(tx_id.clone());
                        state.add_order(MmOrderState {
                            tx_id,
                            index: 0,
                            side: "buy".to_string(),
                            level: (i + 1) as u32,
                            price_num: level.price_num,
                            price_den: level.price_den,
                            amount: config.amount,
                            p2sh_address,
                        });
                        // Persist immediately so a crash mid-requote doesn't lose
                        // newly-deployed orders.
                        state.save(&state_path)?;
                    }
                    Err(e) => {
                        error!("[MM] Phase 1 buy L{} deploy failed: {}", i + 1, e);
                        deploy_failures += 1;
                    }
                }
                if interruptible_sleep(config.deploy_delay_secs, &shutdown).await {
                    break;
                }
            }
            for (i, level) in new_plan.sell_levels.iter().enumerate() {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                println!(
                    "[MM] Phase 1 deploy sell L{}: {}/{}...",
                    i + 1, level.price_num, level.price_den
                );
                match deploy_order(
                    wallet_path,
                    node_url,
                    &config.token,
                    "sell",
                    level.price_num,
                    level.price_den,
                    config.min_fill,
                    config.amount,
                    config.version,
                )
                .await
                {
                    Ok((tx_id, p2sh_address)) => {
                        new_tx_ids.insert(tx_id.clone());
                        state.add_order(MmOrderState {
                            tx_id,
                            index: 0,
                            side: "sell".to_string(),
                            level: (i + 1) as u32,
                            price_num: level.price_num,
                            price_den: level.price_den,
                            amount: config.amount,
                            p2sh_address,
                        });
                        state.save(&state_path)?;
                    }
                    Err(e) => {
                        error!("[MM] Phase 1 sell L{} deploy failed: {}", i + 1, e);
                        deploy_failures += 1;
                    }
                }
                if interruptible_sleep(config.deploy_delay_secs, &shutdown).await {
                    break;
                }
            }
            if deploy_failures > 0 {
                warn!(
                    "[MM] {} new deploys failed in phase 1; canceling old orders anyway to avoid stale quotes",
                    deploy_failures
                );
            }

            // ----- Phase 2: cancel old orders -----
            println!(
                "[MM] Phase 2: canceling {} old orders at old mid...",
                old_orders.len()
            );
            let mut cancelled_tx_ids: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            let mut cancel_failures = 0u32;
            for order in &old_orders {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                println!(
                    "[MM] Cancelling old {} L{} at {}:{}...",
                    order.side, order.level, order.tx_id, order.index
                );
                match cancel_order(
                    wallet_path,
                    node_url,
                    &config.token,
                    &order.side,
                    order.price_num,
                    order.price_den,
                    config.min_fill,
                    &order.tx_id,
                    order.index,
                    config.version,
                )
                .await
                {
                    Ok(()) => {
                        println!("[MM] Cancelled old {} L{}", order.side, order.level);
                        cancelled_tx_ids.insert(order.tx_id.clone());
                    }
                    Err(e) => {
                        // Order may already be filled/spent -- log and continue
                        warn!(
                            "[MM] Cancel old {} L{} failed (may already be filled): {}",
                            order.side, order.level, e
                        );
                        cancel_failures += 1;
                    }
                }
                if interruptible_sleep(config.deploy_delay_secs, &shutdown).await {
                    break;
                }
            }

            // ----- Phase 3: prune cancelled old orders, update state mid -----
            state.orders.retain(|o| !cancelled_tx_ids.contains(&o.tx_id));
            state.mid_price_num = config.mid_price_num;
            state.mid_price_den = config.mid_price_den;
            state.save(&state_path)?;

            if cancel_failures > 0 {
                warn!(
                    "[MM] {} cancel(s) failed; those old orders remain in state and will be retried next cycle",
                    cancel_failures
                );
            }
            println!(
                "[MM] Atomic requote complete. {} orders active ({} new + {} unsettled old).",
                state.orders.len(),
                new_tx_ids.len(),
                state.orders.len().saturating_sub(new_tx_ids.len())
            );
        }

        println!(
            "[MM] Cycle complete. {} orders active.",
            state.orders.len()
        );
    }

    // ===== C9: shutdown cleanup =====
    if cleanup_on_shutdown && !state.orders.is_empty() {
        println!();
        info!(
            "[MM] Shutdown cleanup: canceling {} active orders (use --no-cleanup to skip)...",
            state.orders.len()
        );
        let orders_snapshot: Vec<MmOrderState> = state.orders.clone();
        let mut cleanup_failures = 0u32;
        for order in &orders_snapshot {
            match cancel_order(
                wallet_path,
                node_url,
                &config.token,
                &order.side,
                order.price_num,
                order.price_den,
                config.min_fill,
                &order.tx_id,
                order.index,
                config.version,
            )
            .await
            {
                Ok(()) => {
                    println!("  Cancelled {} L{}", order.side, order.level);
                    state.orders.retain(|o| o.tx_id != order.tx_id);
                    let _ = state.save(&state_path);
                }
                Err(e) => {
                    warn!(
                        "  Cancel {} L{} failed (may already be filled): {}",
                        order.side, order.level, e
                    );
                    cleanup_failures += 1;
                }
            }
            // Small delay between cancels to avoid UTXO contention.
            // Not interruptible: the user already pressed Ctrl+C; a second
            // press should still terminate the process via the OS default.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        if cleanup_failures > 0 {
            warn!(
                "[MM] {} order(s) could not be cancelled during shutdown; remain in state",
                cleanup_failures
            );
        } else {
            println!("[MM] Cleanup complete. All orders cancelled.");
        }
    } else if !cleanup_on_shutdown && !state.orders.is_empty() {
        println!();
        info!(
            "[MM] Shutdown: {} orders left on-chain (--no-cleanup). Run `kob cancel-all` to clean up.",
            state.orders.len()
        );
    }

    Ok(())
}

/// Deploy a single order via the deploy module logic.
///
/// Returns (transaction_id, p2sh_address) on success.
async fn deploy_order(
    wallet_path: &Path,
    node_url: &str,
    token: &str,
    side: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    amount: u64,
    version: u8,
) -> anyhow::Result<(String, String)> {
    use crate::utils::p2sh_to_address;
    use crate::rpc::RpcClient;
    use crate::utils;
    use kob_core::contract;
    use kob_core::contract::build_order_payload;
    use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
    use kob_core::sighash::compute_sighash;
    use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
    use kob_core::wallet::WalletContext;
    use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
    use kob_core::MIN_UTXO_VALUE;
    use zeroize::Zeroize;

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let mut privkey = *wallet.privkey_bytes();
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);

    let token_bytes = hex::decode(token)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("Invalid token: expected 64 hex characters for the token covenant ID");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_bytes);

    if version != 18 {
        anyhow::bail!("Unsupported contract version {}. New quotes deploy as v18 only.", version);
    }
    let redeem_script = match side {
        // v18 delivery re-wrap: the buy's bspkh commits the owner's
        // token_unit P2SH SPK so fills deliver spendable KCC20 token_units.
        // The sell's sspkh stays raw P2PK (KAS proceeds). Must stay in
        // lockstep with cancel_order's reconstruction below.
        "buy" => contract::spot::order::build_buy_v18_redeem_script(
            &token_cov_id, price_num, price_den, min_fill,
            &owner_hash, &contract::compute_token_unit_spk_hash(&pubkey),
            &spk_hash, // okspkh: EXPIRE refunds KAS to the owner's raw P2PK
            crate::DEFAULT_MAX_MATCHER_FEE_BPS, 0, 0,)?,
        "sell" => contract::spot::order::build_sell_v18_redeem_script(
            price_num, price_den, min_fill, &owner_hash, &spk_hash,
            &contract::compute_token_unit_spk_hash(&pubkey), // otspkh: EXPIRE token refund seat
            crate::DEFAULT_MAX_MATCHER_FEE_BPS, 0, 0,)?,
        _ => anyhow::bail!("Unknown order side '{}'. Use 'buy' or 'sell'.", side),
    };

    let p2sh = build_p2sh(&redeem_script);
    // Compute the P2SH address for fill detection queries.
    let net_prefix = wallet.address.split(':').next().unwrap_or("kaspa");
    let p2sh_addr = p2sh_to_address(&p2sh.script(), net_prefix);

    let rpc = RpcClient::connect(node_url).await.map_err(|e| anyhow::anyhow!(e))?;
    let utxos = rpc.get_spendable_utxos(&wallet.address, None).await.map_err(|e| anyhow::anyhow!(e))?;
    let est_fee = estimate_compute_mass(1, 2, redeem_script.len()) + 500;
    let needed = amount + est_fee;

    let funding = utxos
        .iter()
        .find(|u| !u.utxo_entry.is_p2sh() && u.utxo_entry.amount >= needed)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for {} deploy",
                needed,
                side
            )
        })?;

    let tx_version = if side == "sell" { 1 } else { 0 };
    let mut tx = Transaction::new(tx_version);

    let spk_bytes = funding.utxo_entry.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: funding.outpoint.transaction_id.clone(),
        prev_index: funding.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: funding.utxo_entry.script_version(),
        script_bytes: spk_bytes,
        value: funding.utxo_entry.amount,
    });

    let covenant_binding = if side == "sell" {
        Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&token.to_string()).unwrap()))
    } else {
        None
    };

    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), covenant_binding));

    tx.payload = build_order_payload(&redeem_script, false);

    // Phase 1: converge fee
    let total_in = funding.utxo_entry.amount;
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    let tentative_change = total_in.saturating_sub(amount + est_fee);
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    if has_change {
        tx.outputs.push(TxOutput::new(tentative_change, funding.utxo_entry.script_version(), wallet_spk.clone(), None));
        let _ = converge_fee(&mut tx, total_in, 1, 0);
    }

    // Sign
    let sighash = compute_sighash(&tx, 0)?;
    let signature = utils::schnorr_sign(&privkey, &sighash)?;
    let sigscript = utils::build_p2pk_sigscript(&signature);

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &[sigscript.clone()]);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);
    let current_fee = total_in - tx.outputs.iter().map(|o| o.value).sum::<u64>();

    let sigscript = if exact_fee != current_fee {
        let adj_change = total_in.saturating_sub(amount + exact_fee);
        if adj_change >= MIN_UTXO_VALUE {
            if tx.outputs.len() > 1 { tx.outputs[1].value = adj_change; }
        } else if tx.outputs.len() > 1 {
            tx.outputs.pop();
        }
        let sighash = compute_sighash(&tx, 0)?;
        let signature = utils::schnorr_sign(&privkey, &sighash)?;
        utils::build_p2pk_sigscript(&signature)
    } else {
        sigscript
    };
    privkey.zeroize();

    let payload = to_rpc_payload(&tx, &[sigscript]);
    let result = rpc.submit_transaction(payload).await.map_err(|e| anyhow::anyhow!(e))?;
    if !result.ok {
        anyhow::bail!("submit_transaction failed: {}", result.error.unwrap_or_default());
    }
    let tx_id = result.tx_id.unwrap_or_default();

    Ok((tx_id, p2sh_addr))
}

/// Cancel a single order on-chain. Reconstructs the redeem script for the
/// given version, queries the order UTXO value, builds and submits a cancel TX.
///
/// Returns Ok(()) on success, Err if the order cannot be cancelled (e.g. already spent).
#[allow(clippy::too_many_arguments)]
async fn cancel_order(
    wallet_path: &Path,
    node_url: &str,
    token: &str,
    side: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    order_tx_id: &str,
    order_index: u32,
    version: u8,
) -> anyhow::Result<()> {
    use crate::utils::p2sh_to_address;
    use crate::rpc::RpcClient;
    use crate::utils;
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
    use kob_core::sighash::compute_sighash;
    use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
    use kob_core::wallet::WalletContext;
    use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
    use kob_core::MIN_UTXO_VALUE;
    use zeroize::Zeroize;

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let mut privkey = *wallet.privkey_bytes();
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);

    let token_bytes = hex::decode(token)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("Invalid token: expected 64 hex characters for the token covenant ID");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_bytes);

    // Reconstruct the redeem script (v18 only — matches deploy_order above;
    // the P2SH only resolves when the SAME builder + fee constant are used)
    if version != 18 {
        anyhow::bail!("Unsupported contract version {}. New quotes deploy as v18 only.", version);
    }
    let redeem_script = match side {
        // Buy bspkh = token_unit P2SH hash (v18 delivery re-wrap) -- byte-
        // exact match with deploy_order's builder args or the P2SH will not
        // resolve and the cancel scan finds nothing.
        "buy" => contract::spot::order::build_buy_v18_redeem_script(
            &token_cov_id, price_num, price_den, min_fill,
            &owner_hash, &contract::compute_token_unit_spk_hash(&pubkey),
            &spk_hash, // okspkh: EXPIRE refunds KAS to the owner's raw P2PK
            crate::DEFAULT_MAX_MATCHER_FEE_BPS, 0, 0,)?,
        "sell" => contract::spot::order::build_sell_v18_redeem_script(
            price_num, price_den, min_fill, &owner_hash, &spk_hash,
            &contract::compute_token_unit_spk_hash(&pubkey), // otspkh: EXPIRE token refund seat
            crate::DEFAULT_MAX_MATCHER_FEE_BPS, 0, 0,)?,
        _ => anyhow::bail!("Unknown order side '{}'. Use 'buy' or 'sell'.", side),
    };

    let p2sh = build_p2sh(&redeem_script);
    let net_prefix = wallet.address.split(':').next().unwrap_or("kaspa");
    let p2sh_address = p2sh_to_address(&p2sh.script(), net_prefix);

    let rpc = RpcClient::connect(node_url).await.map_err(|e| anyhow::anyhow!(e))?;

    // Query the order UTXO value from its P2SH address
    let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await.map_err(|e| anyhow::anyhow!(e))?;
    let order_utxo = order_utxos
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == order_tx_id
                && u.outpoint.index == order_index
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Order UTXO {}:{} not found at P2SH {}. Already spent/filled?",
                order_tx_id, order_index, p2sh_address
            )
        })?;
    let order_value = order_utxo.utxo_entry.amount;

    // Get a fee UTXO from the wallet
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address, None).await.map_err(|e| anyhow::anyhow!(e))?;
    let est_cancel_fee = estimate_compute_mass(2, 1, 0) + 500;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.utxo_entry.is_p2sh() && u.utxo_entry.amount >= est_cancel_fee + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for cancel fee",
                est_cancel_fee + MIN_UTXO_VALUE
            )
        })?;

    let total_in = order_value + fee_utxo.utxo_entry.amount;

    // Build the cancel transaction
    let mut tx = Transaction::new(0);

    // Input 0: order UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: order_tx_id.to_string(),
        prev_index: order_index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.utxo_entry.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_version(),
        script_bytes: fee_spk_bytes,
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: recovered funds to wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let tentative_output = total_in.saturating_sub(est_cancel_fee);
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_version(), wallet_spk, None));

    // Phase 1: converge fee
    let _ = converge_fee(&mut tx, total_in, 0, 0);

    // Sign input 0 (order cancel path)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = utils::schnorr_sign(&privkey, &sighash_0)?;
    // v18 buy cancel: [pk][sig][Op0][RS] (v17/v18 convention);
    // v18 sell cancel keeps the v14 [sig][pk][Op0][RS] shape.
    let cancel_sigscript = match side {
        "buy" => contract::spot::order::build_buy_v18_cancel_sigscript(&pubkey, &sig_0, false, &redeem_script),
        "sell" => contract::build_sell_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
        _ => unreachable!(),
    };

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = utils::schnorr_sign(&privkey, &sighash_1)?;
    let fee_sigscript = utils::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let sigscripts = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    let current_fee = total_in - tx.outputs.iter().map(|o| o.value).sum::<u64>();
    let (cancel_sigscript, fee_sigscript) = if exact_fee != current_fee {
        let adj_output = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = adj_output;
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = utils::schnorr_sign(&privkey, &sighash_0)?;
        let cancel_sigscript = match side {
            "buy" => contract::spot::order::build_buy_v18_cancel_sigscript(&pubkey, &sig_0, false, &redeem_script),
            "sell" => contract::build_sell_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
            _ => unreachable!(),
        };
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = utils::schnorr_sign(&privkey, &sighash_1)?;
        let fee_sigscript = utils::build_p2pk_sigscript(&sig_1);
        (cancel_sigscript, fee_sigscript)
    } else {
        (cancel_sigscript, fee_sigscript)
    };
    privkey.zeroize();

    let payload = to_rpc_payload(&tx, &[cancel_sigscript, fee_sigscript]);
    let result = rpc.submit_transaction(payload).await.map_err(|e| anyhow::anyhow!(e))?;
    if !result.ok {
        anyhow::bail!("cancel submit failed: {}", result.error.unwrap_or_default());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- GCD ---

    #[test]
    fn gcd_basic() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(100, 25), 25);
        assert_eq!(gcd(7, 13), 1);
    }

    #[test]
    fn gcd_one_zero() {
        assert_eq!(gcd(5, 0), 5);
        assert_eq!(gcd(0, 5), 5);
    }

    #[test]
    fn gcd_same() {
        assert_eq!(gcd(42, 42), 42);
    }

    #[test]
    fn gcd_coprime() {
        assert_eq!(gcd(17, 31), 1);
    }

    // --- Price Level Computation ---

    #[test]
    fn buy_levels_decrease_from_mid() {
        let levels = compute_price_levels(100, 1, 100, 3, "buy");
        assert_eq!(levels.len(), 3);
        // Level 1: 100 * (10000 - 100) / 10000 = 100 * 9900/10000 = 99
        assert_eq!(levels[0].as_f64(), 99.0);
        // Level 2: 100 * 9800/10000 = 98
        assert_eq!(levels[1].as_f64(), 98.0);
        // Level 3: 100 * 9700/10000 = 97
        assert_eq!(levels[2].as_f64(), 97.0);
    }

    #[test]
    fn sell_levels_increase_from_mid() {
        let levels = compute_price_levels(100, 1, 100, 3, "sell");
        assert_eq!(levels.len(), 3);
        // Level 1: 100 * 10100/10000 = 101
        assert_eq!(levels[0].as_f64(), 101.0);
        // Level 2: 102
        assert_eq!(levels[1].as_f64(), 102.0);
        // Level 3: 103
        assert_eq!(levels[2].as_f64(), 103.0);
    }

    #[test]
    fn levels_with_fractional_mid() {
        // Mid = 1/2 = 0.5, spread = 200 bps = 2%
        let buy = compute_price_levels(1, 2, 200, 2, "buy");
        assert_eq!(buy.len(), 2);
        // Level 1: (1 * 9800) / (2 * 10000) = 9800/20000 = 49/100 = 0.49
        assert!((buy[0].as_f64() - 0.49).abs() < 1e-10);
        // Level 2: (1 * 9600) / (2 * 10000) = 9600/20000 = 12/25 = 0.48
        assert!((buy[1].as_f64() - 0.48).abs() < 1e-10);

        let sell = compute_price_levels(1, 2, 200, 2, "sell");
        assert_eq!(sell.len(), 2);
        // Level 1: (1 * 10200) / (2 * 10000) = 10200/20000 = 51/100 = 0.51
        assert!((sell[0].as_f64() - 0.51).abs() < 1e-10);
        // Level 2: 0.52
        assert!((sell[1].as_f64() - 0.52).abs() < 1e-10);
    }

    #[test]
    fn levels_gcd_simplification() {
        // Mid = 100/1, spread = 500 bps (5%), 1 level
        let buy = compute_price_levels(100, 1, 500, 1, "buy");
        assert_eq!(buy.len(), 1);
        // Raw: 100 * 9500 / (1 * 10000) = 950000/10000 = 95/1
        assert_eq!(buy[0].price_num, 95);
        assert_eq!(buy[0].price_den, 1);
    }

    #[test]
    fn levels_symmetry() {
        // Buy L1 and Sell L1 should be equidistant from mid
        let mid_num = 1000u64;
        let mid_den = 1u64;
        let spread = 100u64; // 1%
        let buy = compute_price_levels(mid_num, mid_den, spread, 1, "buy");
        let sell = compute_price_levels(mid_num, mid_den, spread, 1, "sell");
        let mid_f = mid_num as f64 / mid_den as f64;
        let buy_dist = mid_f - buy[0].as_f64();
        let sell_dist = sell[0].as_f64() - mid_f;
        assert!((buy_dist - sell_dist).abs() < 1e-10);
    }

    #[test]
    fn buy_level_skip_negative_price() {
        // spread = 5000 bps (50%), 3 levels
        // Level 1: 50%, Level 2: 100% -> would be 0, Level 3: 150% -> negative
        let levels = compute_price_levels(100, 1, 5000, 3, "buy");
        // Only level 1 should be produced (offset < 10000)
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].as_f64(), 50.0);
    }

    #[test]
    fn sell_levels_large_spread() {
        // spread = 5000 bps (50%), 3 levels -- sell side always works
        let levels = compute_price_levels(100, 1, 5000, 3, "sell");
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0].as_f64(), 150.0);
        assert_eq!(levels[1].as_f64(), 200.0);
        assert_eq!(levels[2].as_f64(), 250.0);
    }

    #[test]
    fn zero_levels_returns_empty() {
        let levels = compute_price_levels(100, 1, 100, 0, "buy");
        assert!(levels.is_empty());
    }

    #[test]
    fn invalid_side_returns_empty() {
        let levels = compute_price_levels(100, 1, 100, 3, "invalid");
        assert!(levels.is_empty());
    }

    #[test]
    fn single_level_each_side() {
        let buy = compute_price_levels(50, 1, 200, 1, "buy");
        let sell = compute_price_levels(50, 1, 200, 1, "sell");
        assert_eq!(buy.len(), 1);
        assert_eq!(sell.len(), 1);
        // Buy: 50 * 9800/10000 = 49
        assert_eq!(buy[0].as_f64(), 49.0);
        // Sell: 50 * 10200/10000 = 51
        assert_eq!(sell[0].as_f64(), 51.0);
    }

    // --- Price Drift Detection ---

    #[test]
    fn no_drift_same_price() {
        assert!(!price_drifted(100, 1, 100, 1, 100));
    }

    #[test]
    fn drift_detected_above_threshold() {
        // Old: 100/1, New: 102/1, threshold: 100 bps (1%)
        // Drift = 2%, which is > 1%
        assert!(price_drifted(100, 1, 102, 1, 100));
    }

    #[test]
    fn no_drift_below_threshold() {
        // Old: 100/1, New: 100.5/1 = 201/2, threshold: 100 bps (1%)
        // Drift = 0.5%, which is < 1%
        assert!(!price_drifted(100, 1, 201, 2, 100));
    }

    #[test]
    fn drift_detected_downward() {
        // Old: 100/1, New: 97/1, threshold: 200 bps (2%)
        // Drift = 3%, which is > 2%
        assert!(price_drifted(100, 1, 97, 1, 200));
    }

    #[test]
    fn no_drift_at_exact_threshold() {
        // Old: 100/1, New: 101/1, threshold: 100 bps (1%)
        // Drift = exactly 1%, not strictly greater
        assert!(!price_drifted(100, 1, 101, 1, 100));
    }

    #[test]
    fn drift_with_fractional_prices() {
        // Old: 1/3 (~0.333), New: 1/2 (0.5), threshold: 100 bps
        // Drift = (0.5 - 0.333)/0.333 = ~50%, clearly above
        assert!(price_drifted(1, 3, 1, 2, 100));
    }

    #[test]
    fn drift_large_values_no_overflow() {
        // Use large values that would overflow u64 multiplication
        let old_num = 1_000_000_000u64;
        let old_den = 1u64;
        let new_num = 1_020_000_000u64;
        let new_den = 1u64;
        // 2% drift > 1% threshold
        assert!(price_drifted(old_num, old_den, new_num, new_den, 100));
    }

    // --- MmState ---

    #[test]
    fn state_default_is_empty() {
        let state = MmState::default();
        assert!(state.orders.is_empty());
        assert_eq!(state.token, "");
    }

    #[test]
    fn state_add_and_find_orders() {
        let mut state = MmState::default();
        state.add_order(MmOrderState {
            tx_id: "a".repeat(64),
            index: 0,
            side: "buy".to_string(),
            level: 1,
            price_num: 99,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        });
        state.add_order(MmOrderState {
            tx_id: "b".repeat(64),
            index: 0,
            side: "sell".to_string(),
            level: 1,
            price_num: 101,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        });
        assert_eq!(state.orders.len(), 2);
        assert_eq!(state.orders_by_side("buy").len(), 1);
        assert_eq!(state.orders_by_side("sell").len(), 1);
    }

    #[test]
    fn state_find_filled_orders() {
        let mut state = MmState::default();
        let tx_a = "a".repeat(64);
        let tx_b = "b".repeat(64);
        state.add_order(MmOrderState {
            tx_id: tx_a.clone(),
            index: 0,
            side: "buy".to_string(),
            level: 1,
            price_num: 99,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        });
        state.add_order(MmOrderState {
            tx_id: tx_b.clone(),
            index: 0,
            side: "sell".to_string(),
            level: 1,
            price_num: 101,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        });

        // Only tx_a is still live
        let live = vec![format!("{}:0", tx_a)];
        let filled = state.find_filled_orders(&live);
        assert_eq!(filled.len(), 1);
        assert_eq!(filled[0], 1); // tx_b at index 1 is filled
    }

    #[test]
    fn state_remove_orders() {
        let mut state = MmState::default();
        for i in 0..5 {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i),
                index: 0,
                side: "buy".to_string(),
                level: i as u32 + 1,
                price_num: 100 - i as u64,
                price_den: 1,
                amount: 10_000_000,
                ..Default::default()
            });
        }
        assert_eq!(state.orders.len(), 5);

        // Remove indices 1 and 3
        state.remove_orders(vec![1, 3]);
        assert_eq!(state.orders.len(), 3);
        // Remaining should be levels 1, 3, 5 (0-indexed original: 0, 2, 4)
        assert_eq!(state.orders[0].level, 1);
        assert_eq!(state.orders[1].level, 3);
        assert_eq!(state.orders[2].level, 5);
    }

    #[test]
    fn state_outpoint_str() {
        let order = MmOrderState {
            tx_id: "aa".repeat(32),
            index: 0,
            side: "buy".to_string(),
            level: 1,
            price_num: 99,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        };
        assert_eq!(order.outpoint_str(), format!("{}:0", "aa".repeat(32)));
    }

    #[test]
    fn state_save_and_load() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_mm_test_state.json");

        let state = MmState {
            token: "ff".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            orders: vec![MmOrderState {
                tx_id: "cc".repeat(32),
                index: 0,
                side: "buy".to_string(),
                level: 1,
                price_num: 99,
                price_den: 1,
                amount: 5_000_000,
            ..Default::default()
        }],
        };

        state.save(&path).unwrap();
        let loaded = MmState::load(&path).unwrap();
        assert_eq!(loaded.token, state.token);
        assert_eq!(loaded.mid_price_num, 100);
        assert_eq!(loaded.orders.len(), 1);
        assert_eq!(loaded.orders[0].side, "buy");
        assert_eq!(loaded.orders[0].level, 1);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_load_missing_file_returns_default() {
        let path = std::path::Path::new("/tmp/kob_mm_nonexistent_state.json");
        let state = MmState::load(path).unwrap();
        assert!(state.orders.is_empty());
    }

    #[test]
    fn state_orders_by_side_empty() {
        let state = MmState::default();
        assert!(state.orders_by_side("buy").is_empty());
        assert!(state.orders_by_side("sell").is_empty());
    }

    // --- MmConfig Validation ---

    #[test]
    fn config_validate_ok() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validate_bad_token() {
        let config = MmConfig {
            token: "short".to_string(),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_zero_spread() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 0,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_zero_levels() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 0,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_bad_version() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 7,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_amount_lt_min_fill() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 500_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_zero_mid_price() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 0,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_zero_interval() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 0,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    // --- Deploy Plan ---

    #[test]
    fn deploy_plan_correct_counts() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 5,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        assert_eq!(plan.buy_levels.len(), 5);
        assert_eq!(plan.sell_levels.len(), 5);
        assert_eq!(plan.total_orders, 10);
        // Each order: 10_000_000 + deploy fee estimate
        let deploy_fee = kob_core::mass::estimate_compute_mass(1, 2, 200);
        assert_eq!(plan.total_kas_needed, 10 * (10_000_000 + deploy_fee));
    }

    #[test]
    fn deploy_plan_skips_negative_buy_levels() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 3000, // 30% per level
            levels: 5,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        // Level 1: 70%, Level 2: 40%, Level 3: 10%, Level 4: -20% (skip), Level 5: -50% (skip)
        assert_eq!(plan.buy_levels.len(), 3);
        assert_eq!(plan.sell_levels.len(), 5); // Sell side always works
    }

    #[test]
    fn deploy_plan_total_kas_correct() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 50,
            mid_price_den: 1,
            spread_bps: 200,
            levels: 2,
            amount: 50_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        assert_eq!(plan.total_orders, 4); // 2 buy + 2 sell
        let deploy_fee = kob_core::mass::estimate_compute_mass(1, 2, 200);
        let expected = 4 * (50_000_000u64 + deploy_fee);
        assert_eq!(plan.total_kas_needed, expected);
    }

    // --- State File Path ---

    #[test]
    fn state_file_next_to_wallet() {
        let wallet = Path::new("/home/user/wallet.json");
        let state = state_file_path(wallet);
        assert_eq!(state, PathBuf::from("/home/user/mm_state.json"));
    }

    #[test]
    fn state_file_in_current_dir() {
        let wallet = Path::new("wallet.json");
        let state = state_file_path(wallet);
        // Parent of "wallet.json" is "" which becomes "." via unwrap_or
        // On some platforms this yields "mm_state.json" or "./mm_state.json"
        assert!(
            state == PathBuf::from("./mm_state.json")
                || state == PathBuf::from("mm_state.json"),
            "Expected mm_state.json next to wallet, got {:?}",
            state
        );
    }

    // --- Price Level Properties ---

    #[test]
    fn all_buy_levels_below_mid() {
        let mid = 100.0f64;
        let levels = compute_price_levels(100, 1, 50, 10, "buy");
        for level in &levels {
            assert!(level.as_f64() < mid, "Buy level {} >= mid {}", level.as_f64(), mid);
        }
    }

    #[test]
    fn all_sell_levels_above_mid() {
        let mid = 100.0f64;
        let levels = compute_price_levels(100, 1, 50, 10, "sell");
        for level in &levels {
            assert!(level.as_f64() > mid, "Sell level {} <= mid {}", level.as_f64(), mid);
        }
    }

    #[test]
    fn buy_levels_monotonically_decreasing() {
        let levels = compute_price_levels(100, 1, 100, 5, "buy");
        for i in 1..levels.len() {
            assert!(
                levels[i].as_f64() < levels[i - 1].as_f64(),
                "Buy levels not decreasing: L{} = {}, L{} = {}",
                i, levels[i - 1].as_f64(), i + 1, levels[i].as_f64()
            );
        }
    }

    #[test]
    fn sell_levels_monotonically_increasing() {
        let levels = compute_price_levels(100, 1, 100, 5, "sell");
        for i in 1..levels.len() {
            assert!(
                levels[i].as_f64() > levels[i - 1].as_f64(),
                "Sell levels not increasing: L{} = {}, L{} = {}",
                i, levels[i - 1].as_f64(), i + 1, levels[i].as_f64()
            );
        }
    }

    // --- Edge Cases ---

    #[test]
    fn one_bps_spread() {
        // 1 bps = 0.01% per level
        let buy = compute_price_levels(10000, 1, 1, 3, "buy");
        assert_eq!(buy.len(), 3);
        // L1: 10000 * 9999/10000 = 9999
        assert_eq!(buy[0].as_f64(), 9999.0);
        assert_eq!(buy[1].as_f64(), 9998.0);
        assert_eq!(buy[2].as_f64(), 9997.0);
    }

    #[test]
    fn max_bps_spread_buy() {
        // 9999 bps = 99.99%, only level 1 is valid for buy
        let buy = compute_price_levels(100, 1, 9999, 3, "buy");
        assert_eq!(buy.len(), 1);
        // L1: 100 * 1/10000 = 0.01
        assert!((buy[0].as_f64() - 0.01).abs() < 1e-10);
    }

    #[test]
    fn large_level_count() {
        let levels = compute_price_levels(100, 1, 10, 50, "sell");
        assert_eq!(levels.len(), 50);
        // Last level: 100 * (10000 + 10*50)/10000 = 100 * 10500/10000 = 105
        assert_eq!(levels[49].as_f64(), 105.0);
    }

    // Additional comprehensive offline tests

    // --- GCD edge cases ---

    #[test]
    fn gcd_both_zero() {
        // gcd(0,0) = 0 by Euclidean definition
        assert_eq!(gcd(0, 0), 0);
    }

    #[test]
    fn gcd_one_and_any() {
        assert_eq!(gcd(1, 999_999), 1);
        assert_eq!(gcd(999_999, 1), 1);
    }

    #[test]
    fn gcd_large_primes() {
        // Two large primes are coprime
        assert_eq!(gcd(104_729, 104_743), 1);
    }

    #[test]
    fn gcd_powers_of_two() {
        assert_eq!(gcd(1024, 256), 256);
        assert_eq!(gcd(65536, 4096), 4096);
    }

    #[test]
    fn gcd_large_values() {
        // gcd(2^63, 2^62) = 2^62
        let a = 1u64 << 63;
        let b = 1u64 << 62;
        assert_eq!(gcd(a, b), b);
    }

    #[test]
    fn gcd_consecutive_fibonacci_coprime() {
        // Consecutive Fibonacci numbers are coprime
        assert_eq!(gcd(89, 55), 1);
        assert_eq!(gcd(144, 89), 1);
    }

    #[test]
    fn gcd_commutative() {
        assert_eq!(gcd(48, 18), gcd(18, 48));
        assert_eq!(gcd(100, 75), gcd(75, 100));
    }

    // --- Price level computation: additional cases ---

    #[test]
    fn price_levels_unit_mid_price() {
        // Mid = 1/1
        let buy = compute_price_levels(1, 1, 100, 3, "buy");
        assert_eq!(buy.len(), 3);
        assert!((buy[0].as_f64() - 0.99).abs() < 1e-10);
        assert!((buy[1].as_f64() - 0.98).abs() < 1e-10);
        assert!((buy[2].as_f64() - 0.97).abs() < 1e-10);
    }

    #[test]
    fn price_levels_large_numerator_denominator() {
        // Mid = 1_000_000 / 1_000_000 = 1.0, spread 100 bps
        let buy = compute_price_levels(1_000_000, 1_000_000, 100, 1, "buy");
        assert_eq!(buy.len(), 1);
        assert!((buy[0].as_f64() - 0.99).abs() < 1e-10);
    }

    #[test]
    fn price_levels_gcd_reduces_properly() {
        // Mid = 200/2 = 100, spread 100 bps, 1 level
        // Raw buy: 200 * 9900 / (2 * 10000) = 1980000 / 20000 = 99/1
        let buy = compute_price_levels(200, 2, 100, 1, "buy");
        assert_eq!(buy[0].price_num, 99);
        assert_eq!(buy[0].price_den, 1);
    }

    #[test]
    fn price_levels_non_trivial_gcd_reduction() {
        // Mid = 3/4, spread = 250 bps (2.5%), 1 level
        // Buy L1: 3 * (10000 - 250) / (4 * 10000) = 3 * 9750 / 40000 = 29250/40000
        // gcd(29250, 40000) = 250 => 117/160
        let buy = compute_price_levels(3, 4, 250, 1, "buy");
        assert_eq!(buy[0].price_num, 117);
        assert_eq!(buy[0].price_den, 160);
        assert!((buy[0].as_f64() - 0.73125).abs() < 1e-10);
    }

    #[test]
    fn price_levels_exact_boundary_offset_10000() {
        // spread = 10000 bps (100%), 1 level => offset = 10000, skipped for buy
        let buy = compute_price_levels(100, 1, 10000, 1, "buy");
        assert!(buy.is_empty(), "Buy level at 100% offset should be skipped");
    }

    #[test]
    fn price_levels_sell_offset_10000() {
        // spread = 10000 bps, sell side works: price = mid * 2
        let sell = compute_price_levels(100, 1, 10000, 1, "sell");
        assert_eq!(sell.len(), 1);
        assert_eq!(sell[0].as_f64(), 200.0);
    }

    #[test]
    fn price_levels_many_levels_partial_skip() {
        // spread = 2500 bps (25%), 5 levels
        // Buy: L1=75%, L2=50%, L3=25%, L4=0% (skip), L5=-25% (skip)
        let buy = compute_price_levels(100, 1, 2500, 5, "buy");
        assert_eq!(buy.len(), 3);
        assert_eq!(buy[0].as_f64(), 75.0);
        assert_eq!(buy[1].as_f64(), 50.0);
        assert_eq!(buy[2].as_f64(), 25.0);
    }

    #[test]
    fn price_levels_uniform_spacing() {
        // Each level should be spread_bps apart in price terms
        let levels = compute_price_levels(1000, 1, 100, 5, "buy");
        for i in 1..levels.len() {
            let diff = levels[i - 1].as_f64() - levels[i].as_f64();
            // Each level is 1% of mid = 10.0 apart
            assert!((diff - 10.0).abs() < 1e-8, "Non-uniform spacing at level {}", i);
        }
    }

    #[test]
    fn sell_levels_uniform_spacing() {
        let levels = compute_price_levels(1000, 1, 100, 5, "sell");
        for i in 1..levels.len() {
            let diff = levels[i].as_f64() - levels[i - 1].as_f64();
            assert!((diff - 10.0).abs() < 1e-8, "Non-uniform sell spacing at level {}", i);
        }
    }

    // --- Price drift detection: additional cases ---

    #[test]
    fn drift_symmetric_up_and_down() {
        // 2% up should trigger same as 2% down
        let up = price_drifted(100, 1, 102, 1, 100);
        let down = price_drifted(100, 1, 98, 1, 100);
        assert_eq!(up, down);
    }

    #[test]
    fn drift_tiny_movement_below_1bps() {
        // Old: 10000/1, New: 10000.5 ~= 20001/2, threshold: 1 bps (0.01%)
        // Drift = 0.005% < 0.01%
        assert!(!price_drifted(10000, 1, 20001, 2, 1));
    }

    #[test]
    fn drift_just_above_threshold() {
        // Old: 10000/1, threshold: 100 bps (1%)
        // New: 10101/1 => drift = 1.01% > 1%
        assert!(price_drifted(10000, 1, 10101, 1, 100));
    }

    #[test]
    fn drift_zero_threshold_any_change_drifts() {
        // With 0 threshold, even tiny change triggers
        assert!(price_drifted(100, 1, 101, 1, 0));
    }

    #[test]
    fn drift_zero_threshold_same_price_no_drift() {
        assert!(!price_drifted(100, 1, 100, 1, 0));
    }

    #[test]
    fn drift_very_large_threshold_never_triggers() {
        // threshold = 10000 bps = 100%, so 50% drift should not trigger
        assert!(!price_drifted(100, 1, 150, 1, 10000));
    }

    #[test]
    fn drift_exactly_100pct_threshold_50pct_change() {
        // 50% drift < 100% threshold
        assert!(!price_drifted(100, 1, 150, 1, 10000));
    }

    #[test]
    fn drift_both_fractional_prices() {
        // Old: 3/7, New: 4/9
        // Old ≈ 0.42857, New ≈ 0.44444, drift ≈ 3.7%, threshold 300 bps (3%)
        assert!(price_drifted(3, 7, 4, 9, 300));
    }

    #[test]
    fn drift_u64_max_no_panic() {
        // Should not panic with large values
        let _ = price_drifted(u64::MAX, 1, u64::MAX - 1, 1, 100);
    }

    // --- Config validation: additional cases ---

    #[test]
    fn config_validate_zero_denominator() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 0,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_zero_amount() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 0,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_zero_min_fill() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 0,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_amount_equals_min_fill() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 1_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validate_invalid_hex_token() {
        // 64 chars but not valid hex (contains 'g')
        let config = MmConfig {
            token: "gg".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_all_valid_versions() {
        for v in [18] {
            let config = MmConfig {
                token: "aa".repeat(32),
                mid_price_num: 100,
                mid_price_den: 1,
                spread_bps: 100,
                levels: 3,
                amount: 10_000_000,
                interval_secs: 10,
                dry_run: false,
                version: v,
                min_fill: 1_000_000,
                requote_threshold_bps: 500,
                deploy_delay_secs: 0,
            };
            assert!(config.validate().is_ok(), "Version {} should be valid", v);
        }
    }

    #[test]
    fn config_validate_version_boundaries() {
        // Only version 18 is valid (new quotes are v18-only); all others fail
        for v in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 255] {
            let config = MmConfig {
                token: "aa".repeat(32),
                mid_price_num: 100,
                mid_price_den: 1,
                spread_bps: 100,
                levels: 3,
                amount: 10_000_000,
                interval_secs: 10,
                dry_run: false,
                version: v,
                min_fill: 1_000_000,
                requote_threshold_bps: 500,
                deploy_delay_secs: 0,
            };
            assert!(config.validate().is_err(), "Version {} should be invalid", v);
        }
    }

    #[test]
    fn config_validate_token_too_long() {
        let config = MmConfig {
            token: "aa".repeat(33), // 66 chars
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_dry_run_flag_does_not_affect_validation() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: true,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_ok());
    }

    // --- MmState: additional cases ---

    #[test]
    fn state_find_filled_all_missing() {
        let mut state = MmState::default();
        for i in 0..3 {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i),
                index: 0,
                side: "buy".to_string(),
                level: i as u32 + 1,
                price_num: 100 - i as u64,
                price_den: 1,
                amount: 10_000_000,
                ..Default::default()
            });
        }
        // No live outpoints => all are "filled"
        let filled = state.find_filled_orders(&[]);
        assert_eq!(filled.len(), 3);
        assert_eq!(filled, vec![0, 1, 2]);
    }

    #[test]
    fn state_find_filled_all_live() {
        let mut state = MmState::default();
        let mut live = Vec::new();
        for i in 0..3 {
            let tx_id = format!("{:064x}", i);
            live.push(format!("{}:0", tx_id));
            state.add_order(MmOrderState {
                tx_id,
                index: 0,
                side: "buy".to_string(),
                level: i as u32 + 1,
                price_num: 100 - i as u64,
                price_den: 1,
                amount: 10_000_000,
            ..Default::default()
        });
        }
        let filled = state.find_filled_orders(&live);
        assert!(filled.is_empty());
    }

    #[test]
    fn state_remove_orders_empty_indices() {
        let mut state = MmState::default();
        state.add_order(MmOrderState {
            tx_id: "a".repeat(64),
            index: 0,
            side: "buy".to_string(),
            level: 1,
            price_num: 99,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        });
        state.remove_orders(vec![]);
        assert_eq!(state.orders.len(), 1);
    }

    #[test]
    fn state_remove_orders_out_of_bounds_ignored() {
        let mut state = MmState::default();
        state.add_order(MmOrderState {
            tx_id: "a".repeat(64),
            index: 0,
            side: "buy".to_string(),
            level: 1,
            price_num: 99,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        });
        // Index 5 is out of bounds, should be ignored
        state.remove_orders(vec![5]);
        assert_eq!(state.orders.len(), 1);
    }

    #[test]
    fn state_remove_all_orders() {
        let mut state = MmState::default();
        for i in 0..4 {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i),
                index: 0,
                side: "buy".to_string(),
                level: i as u32 + 1,
                price_num: 100,
                price_den: 1,
                amount: 10_000_000,
                ..Default::default()
            });
        }
        state.remove_orders(vec![0, 1, 2, 3]);
        assert!(state.orders.is_empty());
    }

    #[test]
    fn state_remove_orders_preserves_order() {
        let mut state = MmState::default();
        // Add 6 orders with levels 1..6
        for i in 0..6 {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i),
                index: 0,
                side: if i % 2 == 0 { "buy" } else { "sell" }.to_string(),
                level: i as u32 + 1,
                price_num: 100,
                price_den: 1,
                amount: 10_000_000,
                ..Default::default()
            });
        }
        // Remove indices 0, 2, 4 (levels 1, 3, 5)
        state.remove_orders(vec![0, 2, 4]);
        assert_eq!(state.orders.len(), 3);
        assert_eq!(state.orders[0].level, 2);
        assert_eq!(state.orders[1].level, 4);
        assert_eq!(state.orders[2].level, 6);
    }

    #[test]
    fn state_orders_by_side_mixed() {
        let mut state = MmState::default();
        for i in 0..6 {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i),
                index: 0,
                side: if i < 3 { "buy" } else { "sell" }.to_string(),
                level: (i % 3) as u32 + 1,
                price_num: 100,
                price_den: 1,
                amount: 10_000_000,
                ..Default::default()
            });
        }
        assert_eq!(state.orders_by_side("buy").len(), 3);
        assert_eq!(state.orders_by_side("sell").len(), 3);
        assert!(state.orders_by_side("other").is_empty());
    }

    #[test]
    fn state_outpoint_str_with_nonzero_index() {
        let order = MmOrderState {
            tx_id: "bb".repeat(32),
            index: 3,
            side: "sell".to_string(),
            level: 2,
            price_num: 101,
            price_den: 1,
            amount: 5_000_000,
            ..Default::default()
        };
        assert_eq!(order.outpoint_str(), format!("{}:3", "bb".repeat(32)));
    }

    #[test]
    fn state_save_load_roundtrip_multiple_orders() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_mm_test_roundtrip.json");

        let state = MmState {
            token: "dd".repeat(32),
            mid_price_num: 500,
            mid_price_den: 3,
            orders: vec![
                MmOrderState {
                    tx_id: "a1".repeat(32),
                    index: 0,
                    side: "buy".to_string(),
                    level: 1,
                    price_num: 490,
                    price_den: 3,
                    amount: 1_000_000,
                    ..Default::default()
                },
                MmOrderState {
                    tx_id: "b2".repeat(32),
                    index: 0,
                    side: "buy".to_string(),
                    level: 2,
                    price_num: 480,
                    price_den: 3,
                    amount: 1_000_000,
                    ..Default::default()
                },
                MmOrderState {
                    tx_id: "c3".repeat(32),
                    index: 0,
                    side: "sell".to_string(),
                    level: 1,
                    price_num: 510,
                    price_den: 3,
                    amount: 2_000_000,
                    ..Default::default()
                },
            ],
        };

        state.save(&path).unwrap();
        let loaded = MmState::load(&path).unwrap();

        assert_eq!(loaded.token, state.token);
        assert_eq!(loaded.mid_price_num, 500);
        assert_eq!(loaded.mid_price_den, 3);
        assert_eq!(loaded.orders.len(), 3);
        assert_eq!(loaded.orders[0].side, "buy");
        assert_eq!(loaded.orders[0].level, 1);
        assert_eq!(loaded.orders[0].price_num, 490);
        assert_eq!(loaded.orders[1].side, "buy");
        assert_eq!(loaded.orders[1].level, 2);
        assert_eq!(loaded.orders[2].side, "sell");
        assert_eq!(loaded.orders[2].amount, 2_000_000);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_save_load_empty_orders() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_mm_test_empty.json");

        let state = MmState {
            token: "ee".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            orders: vec![],
        };

        state.save(&path).unwrap();
        let loaded = MmState::load(&path).unwrap();
        assert!(loaded.orders.is_empty());
        assert_eq!(loaded.token, state.token);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_load_corrupt_json_is_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_mm_test_corrupt.json");
        std::fs::write(&path, "not valid json{{{").unwrap();

        let result = MmState::load(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_save_overwrites_existing() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_mm_test_overwrite.json");

        let state1 = MmState {
            token: "11".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            orders: vec![],
        };
        state1.save(&path).unwrap();

        let state2 = MmState {
            token: "22".repeat(32),
            mid_price_num: 200,
            mid_price_den: 1,
            orders: vec![MmOrderState {
                tx_id: "ff".repeat(32),
                index: 0,
                side: "sell".to_string(),
                level: 1,
                price_num: 201,
                price_den: 1,
                amount: 5_000_000,
            ..Default::default()
        }],
        };
        state2.save(&path).unwrap();

        let loaded = MmState::load(&path).unwrap();
        assert_eq!(loaded.token, "22".repeat(32));
        assert_eq!(loaded.mid_price_num, 200);
        assert_eq!(loaded.orders.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    // --- Deploy plan: additional cases ---

    #[test]
    fn deploy_plan_single_level() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 1,
            amount: 5_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        assert_eq!(plan.buy_levels.len(), 1);
        assert_eq!(plan.sell_levels.len(), 1);
        assert_eq!(plan.total_orders, 2);
        assert_eq!(plan.amount_per_order, 5_000_000);
        assert_eq!(plan.min_fill, 1_000_000);
    }

    #[test]
    fn deploy_plan_amount_and_min_fill_preserved() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 50_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 5_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        assert_eq!(plan.amount_per_order, 50_000_000);
        assert_eq!(plan.min_fill, 5_000_000);
    }

    #[test]
    fn deploy_plan_buy_sell_symmetry() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 200,
            levels: 4,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        assert_eq!(plan.buy_levels.len(), plan.sell_levels.len());
        // Check each pair is equidistant from mid
        let mid = 100.0f64;
        for (b, s) in plan.buy_levels.iter().zip(plan.sell_levels.iter()) {
            let buy_dist = mid - b.as_f64();
            let sell_dist = s.as_f64() - mid;
            assert!((buy_dist - sell_dist).abs() < 1e-10);
        }
    }

    #[test]
    fn deploy_plan_all_spread_skipped_buy() {
        // spread so large that no buy level is valid
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 10000, // 100% per level, offset >= 10000 always
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        assert!(plan.buy_levels.is_empty());
        assert_eq!(plan.sell_levels.len(), 3);
        assert_eq!(plan.total_orders, 3); // only sell orders
    }

    // --- State file path: additional cases ---

    #[test]
    fn state_file_path_nested() {
        let wallet = Path::new("/a/b/c/d/wallet.json");
        let state = state_file_path(wallet);
        assert_eq!(state, PathBuf::from("/a/b/c/d/mm_state.json"));
    }

    #[test]
    fn state_file_path_root() {
        let wallet = Path::new("/wallet.json");
        let state = state_file_path(wallet);
        assert_eq!(state, PathBuf::from("/mm_state.json"));
    }

    // --- PriceLevel ---

    #[test]
    fn price_level_as_f64_small_fraction() {
        let pl = PriceLevel { price_num: 1, price_den: 3 };
        assert!((pl.as_f64() - 1.0 / 3.0).abs() < 1e-15);
    }

    #[test]
    fn price_level_as_f64_whole_number() {
        let pl = PriceLevel { price_num: 500, price_den: 1 };
        assert_eq!(pl.as_f64(), 500.0);
    }

    #[test]
    fn price_level_equality() {
        let a = PriceLevel { price_num: 99, price_den: 1 };
        let b = PriceLevel { price_num: 99, price_den: 1 };
        let c = PriceLevel { price_num: 99, price_den: 2 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn price_level_clone() {
        let a = PriceLevel { price_num: 42, price_den: 7 };
        let b = a;
        assert_eq!(a, b);
    }

    // --- Combined integration-style offline tests ---

    #[test]
    fn full_cycle_state_management() {
        // Simulate: create state, add orders, detect fills, remove, re-add
        let mut state = MmState {
            token: "ab".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            orders: vec![],
        };

        // Deploy 3 buy + 3 sell
        let buy_levels = compute_price_levels(100, 1, 100, 3, "buy");
        let sell_levels = compute_price_levels(100, 1, 100, 3, "sell");

        for (i, level) in buy_levels.iter().enumerate() {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i),
                index: 0,
                side: "buy".to_string(),
                level: (i + 1) as u32,
                price_num: level.price_num,
                price_den: level.price_den,
                amount: 10_000_000,
                ..Default::default()
            });
        }
        for (i, level) in sell_levels.iter().enumerate() {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i + 100),
                index: 0,
                side: "sell".to_string(),
                level: (i + 1) as u32,
                price_num: level.price_num,
                price_den: level.price_den,
                amount: 10_000_000,
                ..Default::default()
            });
        }

        assert_eq!(state.orders.len(), 6);
        assert_eq!(state.orders_by_side("buy").len(), 3);
        assert_eq!(state.orders_by_side("sell").len(), 3);

        // Simulate: buy L1 and sell L2 are filled (not in live outpoints)
        let live: Vec<String> = state
            .orders
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 0 && *i != 4) // skip buy L1 (idx 0) and sell L2 (idx 4)
            .map(|(_, o)| o.outpoint_str())
            .collect();

        let filled = state.find_filled_orders(&live);
        assert_eq!(filled.len(), 2);

        // Collect filled info before removing
        let filled_orders: Vec<MmOrderState> = filled
            .iter()
            .filter_map(|&i| state.orders.get(i).cloned())
            .collect();
        assert_eq!(filled_orders[0].side, "buy");
        assert_eq!(filled_orders[0].level, 1);
        assert_eq!(filled_orders[1].side, "sell");
        assert_eq!(filled_orders[1].level, 2);

        // Remove filled
        state.remove_orders(filled);
        assert_eq!(state.orders.len(), 4);

        // Re-add the filled orders with new tx_ids
        for order in &filled_orders {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", 999),
                index: 0,
                side: order.side.clone(),
                level: order.level,
                price_num: order.price_num,
                price_den: order.price_den,
                amount: order.amount,
                ..Default::default()
            });
        }
        assert_eq!(state.orders.len(), 6);
    }

    #[test]
    fn requote_scenario_drift_detection_and_new_levels() {
        // Simulate: old mid = 100/1, new mid = 105/1, threshold = 300 bps (3%)
        // Drift = 5% > 3% => should trigger requote
        assert!(price_drifted(100, 1, 105, 1, 300));

        // New levels at 105/1
        let new_buy = compute_price_levels(105, 1, 100, 3, "buy");
        let new_sell = compute_price_levels(105, 1, 100, 3, "sell");

        // Buy levels should be below 105
        for level in &new_buy {
            assert!(level.as_f64() < 105.0);
        }
        // Sell levels should be above 105
        for level in &new_sell {
            assert!(level.as_f64() > 105.0);
        }

        // L1 buy should be ~103.95 (105 * 0.99)
        assert!((new_buy[0].as_f64() - 103.95).abs() < 0.01);
        // L1 sell should be ~106.05 (105 * 1.01)
        assert!((new_sell[0].as_f64() - 106.05).abs() < 0.01);
    }

    #[test]
    fn no_requote_within_threshold() {
        // Old mid = 100/1, new mid = 102/1, threshold = 300 bps (3%)
        // Drift = 2% < 3% => no requote
        assert!(!price_drifted(100, 1, 102, 1, 300));
    }

    #[test]
    fn state_persistence_survives_fill_and_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join("kob_mm_test_fill_reload.json");

        // Initial state with 4 orders
        let mut state = MmState {
            token: "ab".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            orders: (0..4)
                .map(|i| MmOrderState {
                    tx_id: format!("{:064x}", i),
                    index: 0,
                    side: if i < 2 { "buy" } else { "sell" }.to_string(),
                    level: (i % 2 + 1) as u32,
                    price_num: if i < 2 { 99 - i as u64 } else { 101 + (i - 2) as u64 },
                    price_den: 1,
                    amount: 10_000_000,
                    ..Default::default()
                })
                .collect(),
        };

        state.save(&path).unwrap();

        // Simulate fill: remove order at index 1
        state.remove_orders(vec![1]);
        state.save(&path).unwrap();

        // Reload and verify
        let loaded = MmState::load(&path).unwrap();
        assert_eq!(loaded.orders.len(), 3);
        // Order at original index 0 (buy L1) should still be there
        assert_eq!(loaded.orders[0].side, "buy");
        assert_eq!(loaded.orders[0].level, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deploy_plan_large_level_count_consistency() {
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 1000,
            mid_price_den: 1,
            spread_bps: 10, // 0.1% per level
            levels: 100,
            amount: 1_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 100_000,
            requote_threshold_bps: 500,
            deploy_delay_secs: 0,
        };
        let plan = build_deploy_plan(&config);
        assert_eq!(plan.buy_levels.len(), 100);
        assert_eq!(plan.sell_levels.len(), 100);
        assert_eq!(plan.total_orders, 200);

        // Verify monotonicity
        for i in 1..plan.buy_levels.len() {
            assert!(plan.buy_levels[i].as_f64() < plan.buy_levels[i - 1].as_f64());
        }
        for i in 1..plan.sell_levels.len() {
            assert!(plan.sell_levels[i].as_f64() > plan.sell_levels[i - 1].as_f64());
        }
    }

    #[test]
    fn state_find_filled_with_nonzero_index() {
        let mut state = MmState::default();
        state.add_order(MmOrderState {
            tx_id: "aa".repeat(32),
            index: 2,
            side: "buy".to_string(),
            level: 1,
            price_num: 99,
            price_den: 1,
            amount: 10_000_000,
            ..Default::default()
        });

        // Live outpoint with wrong index
        let live = vec![format!("{}:0", "aa".repeat(32))];
        let filled = state.find_filled_orders(&live);
        assert_eq!(filled.len(), 1, "Different index should count as filled");

        // Correct index
        let live2 = vec![format!("{}:2", "aa".repeat(32))];
        let filled2 = state.find_filled_orders(&live2);
        assert!(filled2.is_empty(), "Matching outpoint should be live");
    }

    #[test]
    fn price_levels_tiny_spread_many_levels() {
        // 1 bps spread, 100 levels, mid = 1/1
        // Should produce 100 levels without overflow
        let buy = compute_price_levels(1, 1, 1, 100, "buy");
        // Level 100: offset = 100 bps = 1%, which is < 10000
        assert_eq!(buy.len(), 100);
        // L100: 1 * (10000 - 100) / 10000 = 9900/10000 = 99/100
        assert!((buy[99].as_f64() - 0.99).abs() < 1e-10);
    }

    #[test]
    fn config_validate_requote_threshold_zero_is_ok() {
        // Zero requote threshold is valid (means always requote)
        let config = MmConfig {
            token: "aa".repeat(32),
            mid_price_num: 100,
            mid_price_den: 1,
            spread_bps: 100,
            levels: 3,
            amount: 10_000_000,
            interval_secs: 10,
            dry_run: false,
            version: 18,
            min_fill: 1_000_000,
            requote_threshold_bps: 0,
            deploy_delay_secs: 0,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn state_remove_duplicate_indices() {
        let mut state = MmState::default();
        for i in 0..3 {
            state.add_order(MmOrderState {
                tx_id: format!("{:064x}", i),
                index: 0,
                side: "buy".to_string(),
                level: i as u32 + 1,
                price_num: 100,
                price_den: 1,
                amount: 10_000_000,
                ..Default::default()
            });
        }
        // Remove index 1 twice -- should only remove it once
        state.remove_orders(vec![1, 1]);
        // After first removal of index 1 => [level1, level3]
        // Second removal of index 1 => [level1]
        assert_eq!(state.orders.len(), 1);
        assert_eq!(state.orders[0].level, 1);
    }

    #[test]
    fn gcd_used_in_price_levels_is_correct() {
        // Verify that price_num / price_den is in lowest terms
        let levels = compute_price_levels(7, 3, 150, 5, "sell");
        for level in &levels {
            let g = gcd(level.price_num, level.price_den);
            assert_eq!(g, 1, "Level {}/{} not in lowest terms (gcd={})",
                level.price_num, level.price_den, g);
        }
    }

    #[test]
    fn gcd_used_in_buy_levels_is_correct() {
        let levels = compute_price_levels(7, 3, 150, 5, "buy");
        for level in &levels {
            let g = gcd(level.price_num, level.price_den);
            assert_eq!(g, 1, "Level {}/{} not in lowest terms (gcd={})",
                level.price_num, level.price_den, g);
        }
    }
}
