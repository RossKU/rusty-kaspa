//! `kob-cli auto-match` -- Automated continuous scanning and matching.
//!
//! Scans for P2SH UTXOs at known addresses, parses redeemScript parameters
//! to find crossing buy/sell pairs (buy price >= sell price), builds and
//! submits match TXs, then consumes resulting receipts. Loops with a
//! configurable interval.
//!
//! This is a mini-matcher in CLI form -- useful for single-pair operation.
//!
//! The matcher maintains an order cache (`orders.json`) that stores known
//! order parameters (price, min_fill, owner_hash, spk_hash) alongside their
//! P2SH script hashes. When scanning UTXOs, the cache allows the matcher
//! to identify which P2SH UTXOs correspond to known orders and reconstruct
//! the redeemScripts needed for matching.

use crate::node::NodeClient;
use crate::rpc::RpcUtxo;
use crate::scan::{extract_p2sh_hash, is_p2sh_utxo};
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, TxOutput};
use kob_core::types::Network;
// `OrderSide` is the shared, canonical type (kob-core's `types` module) --
// not redefined here. `orderbook.rs`/`tif.rs` import it from the same place.
use kob_core::OrderSide;
use kob_core::wallet::WalletContext;
use kob_core::MIN_UTXO_VALUE;
use kob_domain::batch::{plan_batch_match, BatchOrder, OrderType, OutputPurpose};

/// Conservative fee estimate (10,000 sompi) used for UTXO selection budgets
/// and pre-filter profitability checks where the TX is not yet built.
/// Actual miner fees are computed from TX mass after construction.
const FEE_BUDGET: u64 = 10_000;
pub use crate::order_cache::{OrderCache, OrderCacheEntry};
use std::path::Path;
use tracing::{info, warn};

/// Parameters for a detected order on-chain.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: fields used by SDK and matcher integration
pub struct DetectedOrder {
    pub txid: String,
    pub index: u32,
    pub value: u64,
    pub side: OrderSide,
    pub price_num: u64,
    pub price_den: u64,
    pub min_fill: u64,
    pub owner_hash: [u8; 32],
    pub spk_hash: [u8; 32],
    pub p2sh_hash: String,
    pub redeem_script: Vec<u8>,
    /// Token covenant ID (hex, 64 chars) from the order cache.
    /// For buy orders this is the token they want to receive;
    /// for sell orders it identifies the token they hold.
    /// Empty string if unknown (legacy v6 orders without pair metadata).
    pub token_cov_id: String,
    /// Contract version (14 or, for buy orders only, 16 -- the F6-fix
    /// contract; see V16_STATUS.md). Sell orders are always 14.
    pub version: u8,
    /// Max matcher fee embedded in the redeemScript: absolute sompi for
    /// v14, basis points for a v16 buy. Needed to reconstruct the exact
    /// on-chain redeemScript bytes (must match what the order was deployed
    /// with) and, for a v16 buy, to derive a safe default F6-cap `fee_bps`
    /// for the canonical planner (see `submit_match`).
    pub max_matcher_fee: u64,
}

/// A crossing pair ready to be matched.
#[derive(Debug)]
pub struct CrossingPair {
    pub buy: DetectedOrder,
    pub sell: DetectedOrder,
    pub spread: f64,
}

/// Configuration for auto-match.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: fields read by auto-match runner
pub struct AutoMatchConfig {
    pub pair_id: [u8; 32],
    pub pair_id_hex: String,
    pub interval_secs: u64,
    pub dry_run: bool,
    pub min_spread: f64,
    pub max_matches: u64,
}

impl AutoMatchConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.interval_secs == 0 {
            anyhow::bail!("Interval must be > 0 seconds");
        }
        if self.min_spread < 0.0 {
            anyhow::bail!("Minimum spread must be >= 0.0");
        }
        Ok(())
    }
}

/// Find crossing pairs from a set of detected orders.
///
/// A crossing pair exists when buy_price >= sell_price, meaning
/// the buyer is willing to pay at least what the seller is asking.
///
/// Price comparison: buy_price = buy_num/buy_den, sell_price = sell_num/sell_den
/// Crossing when: buy_num * sell_den >= sell_num * buy_den
pub fn find_crossing_pairs(orders: &[DetectedOrder], min_spread: f64) -> Vec<CrossingPair> {
    let buys: Vec<&DetectedOrder> = orders.iter().filter(|o| o.side == OrderSide::Buy).collect();
    let sells: Vec<&DetectedOrder> = orders.iter().filter(|o| o.side == OrderSide::Sell).collect();

    let mut pairs = Vec::new();

    for buy in &buys {
        for sell in &sells {
            // Cross-multiply to avoid floating point: buy_num * sell_den >= sell_num * buy_den
            let buy_cross = buy.price_num as u128 * sell.price_den as u128;
            let sell_cross = sell.price_num as u128 * buy.price_den as u128;

            if buy_cross >= sell_cross {
                let buy_price = buy.price_num as f64 / buy.price_den as f64;
                let sell_price = sell.price_num as f64 / sell.price_den as f64;
                let spread = buy_price - sell_price;

                if spread >= min_spread {
                    pairs.push(CrossingPair {
                        buy: (*buy).clone(),
                        sell: (*sell).clone(),
                        spread,
                    });
                }
            }
        }
    }

    // Sort by spread descending (best matches first)
    pairs.sort_by(|a, b| b.spread.partial_cmp(&a.spread).unwrap_or(std::cmp::Ordering::Equal));
    pairs
}

/// Result of a submitted match TX.
///
/// `receipt_index` is `None` for matches built by `submit_match` (the
/// canonical-planner path below does not emit a `trade_receipt` output --
/// neither does `match-batch`, the documented production match path; see
/// `matching.rs`'s module doc for the rationale). The partial-fill and
/// cross-pair paths in this file still emit a receipt and set this field.
#[derive(Debug)]
pub struct SubmitResult {
    pub tx_id: String,
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub receipt_index: Option<u32>,
}

/// Build and submit a full match TX for a crossing pair, routed through the
/// canonical kob-domain planner (`plan_batch_match` + `converge_fee_exact` /
/// `apply_exact_fee`) -- the same planner `match-batch` and `kob-cli match`
/// (see `matching.rs`) use, instead of the hand-rolled fee/output math this
/// function used before consolidation. This is what makes a v16 buy's F6
/// (matcher-fee-cap) check reliably pass: `fee_bps` defaults to the buy's
/// own `max_matcher_fee` (bps) when it's a v16 order, so the built tx never
/// asks for more matcher surplus than F6 allows.
///
/// Self-trade model (unchanged from before consolidation): both outputs are
/// sent to `wallet_spk` (this wallet's own P2PK SPK), not to a per-order
/// owner SPK -- `DetectedOrder` only carries owner/spk *hashes* (not full
/// SPK bytes, which aren't recoverable from a hash), so this function has
/// never been able to deliver funds to a third-party order owner. That
/// limitation is preserved as-is; changing it is out of scope here.
///
/// TX layout:
///   input[0]: sell_order (P2SH fill, sigOpCount=0)
///   input[1]: buy_order  (P2SH fill, sigOpCount=0)
///   input[2]: fee UTXO   (P2PK signed, sigOpCount=1)
///   output[0]: seller KAS
///   output[1]: buyer tokens
///   output[2]: matcher fee (optional, bps-capped)
#[allow(clippy::too_many_arguments)]
pub async fn submit_match(
    rpc: &NodeClient,
    buy: &DetectedOrder,
    sell: &DetectedOrder,
    privkey: &[u8; 32],
    fee_utxo: &RpcUtxo,
    fee_bps: Option<u16>,
) -> anyhow::Result<SubmitResult> {
    let token_bytes = hex::decode(&buy.token_cov_id)
        .map_err(|e| anyhow::anyhow!("Buy order token_cov_id is not valid hex: {}", e))?;
    if token_bytes.len() != 32 {
        anyhow::bail!("Buy order token_cov_id must be 64 hex characters (32 bytes)");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&token_bytes);

    let wallet_spk = fee_utxo.script_bytes();
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;

    // Buyer delivery SPK: MUST blake2b-hash to the buy's committed bspkh or
    // the covenant F2 check rejects the fill. Self-trade model: the buyer is
    // this wallet, so try the wallet P2PK SPK (pre-D2 orders) first, then the
    // wallet's token_unit P2SH SPK (D2 delivery re-wrap). The wallet pubkey
    // is recovered from the P2PK fee-UTXO script ([0x20][pk 32B][0xac]).
    let (buyer_spk, buyer_spk_version): (Vec<u8>, u16) =
        if kob_core::compute_spk_hash(wallet_spk_version, &wallet_spk) == buy.spk_hash {
            (wallet_spk.clone(), wallet_spk_version)
        } else if wallet_spk.len() == 34 && wallet_spk[0] == 0x20 && wallet_spk[33] == 0xac {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&wallet_spk[1..33]);
            if contract::compute_token_unit_spk_hash(&pk) == buy.spk_hash {
                let tu = contract::build_token_unit_p2sh_spk(&pk);
                (tu.script().to_vec(), tu.version)
            } else {
                anyhow::bail!(
                    "Buy order {}:{} commits a delivery SPK hash matching neither the \
                     wallet P2PK SPK nor its token_unit P2SH SPK.",
                    buy.txid, buy.index
                );
            }
        } else {
            anyhow::bail!(
                "Buy order {}:{} delivery SPK hash does not match the wallet SPK and \
                 the fee UTXO is not P2PK; cannot derive the token delivery SPK.",
                buy.txid, buy.index
            );
        };

    let buy_order = BatchOrder {
        outpoint: (buy.txid.clone(), buy.index),
        order_type: OrderType::Buy,
        version: buy.version,
        token_cov_id: tcid,
        price_num: buy.price_num,
        price_den: buy.price_den,
        amount: buy.value,
        redeem_script: buy.redeem_script.clone(),
        utxo_value: buy.value,
        counterparty_spk: buyer_spk,
        counterparty_spk_version: buyer_spk_version,
        min_fill: buy.min_fill,
        oco_path: None,
        bracket_meta: None,
    };
    let sell_order = BatchOrder {
        outpoint: (sell.txid.clone(), sell.index),
        order_type: OrderType::Sell,
        version: 14,
        token_cov_id: tcid,
        price_num: sell.price_num,
        price_den: sell.price_den,
        amount: sell.value,
        redeem_script: sell.redeem_script.clone(),
        utxo_value: sell.value,
        counterparty_spk: wallet_spk.clone(),
        counterparty_spk_version: wallet_spk_version,
        min_fill: sell.min_fill,
        oco_path: None,
        bracket_meta: None,
    };

    // Cap correctness: default to the buy's own embedded mmfee cap so the
    // built tx never asks for more matcher surplus than the covenant allows.
    let effective_fee_bps = fee_bps.or_else(|| Some(buy.max_matcher_fee.min(10_000) as u16));

    let wallet_utxo_info = (
        fee_utxo.outpoint.transaction_id.clone(),
        fee_utxo.outpoint.index,
        fee_utxo.utxo_entry.amount,
    );

    let mut plan = plan_batch_match(
        &[sell_order],
        &[buy_order],
        Some(wallet_utxo_info),
        &wallet_spk,
        wallet_spk_version,
        effective_fee_bps,
    )?;
    plan.validate()?;

    let mut tx = plan.to_transaction();
    if let Some(last_input) = tx.inputs.last_mut() {
        if plan.wallet_input.is_some() {
            last_input.script_bytes = fee_utxo.script_bytes();
            last_input.script_version = fee_utxo.utxo_entry.script_public_key.version;
        }
    }

    let token_hash = kob_core::compat::parse_hash(&buy.token_cov_id).unwrap();
    for (idx, planned) in plan.outputs.iter().enumerate() {
        if planned.purpose == OutputPurpose::BuyerTokens {
            let authorizing_input = plan.buy_seller_map.get(&idx).copied().unwrap_or(0) as u16;
            tx.outputs[idx].covenant = Some(CovenantBinding::new(authorizing_input, token_hash));
        }
    }

    let batch_tx = plan.build_tx()?;
    let mut sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter().map(|i| i.sigscript.clone()).collect();

    if plan.wallet_input.is_some() {
        let wallet_idx = tx.inputs.len() - 1;
        let sighash = compute_sighash(&tx, wallet_idx)?;
        let sig = signing::schnorr_sign(privkey, &sighash)?;
        sigscripts[wallet_idx] = signing::build_p2pk_sigscript(&sig);
    }

    let (exact_fee, delta) = plan.converge_fee_exact(&tx, &sigscripts);
    if delta > 0 {
        plan.apply_exact_fee(exact_fee);

        tx.outputs.clear();
        for planned in &plan.outputs {
            tx.outputs.push(TxOutput::new(
                planned.value,
                planned.spk_version,
                planned.script_public_key.clone(),
                None,
            ));
        }
        for (idx, planned) in plan.outputs.iter().enumerate() {
            if planned.purpose == OutputPurpose::BuyerTokens {
                let authorizing_input = plan.buy_seller_map.get(&idx).copied().unwrap_or(0) as u16;
                tx.outputs[idx].covenant = Some(CovenantBinding::new(authorizing_input, token_hash));
            }
        }

        if plan.wallet_input.is_some() {
            let wallet_idx = tx.inputs.len() - 1;
            let sighash = compute_sighash(&tx, wallet_idx)?;
            let sig = signing::schnorr_sign(privkey, &sighash)?;
            sigscripts[wallet_idx] = signing::build_p2pk_sigscript(&sig);
        }
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    Ok(SubmitResult {
        tx_id,
        seller_kas: tx.outputs[0].value,
        buyer_tokens: tx.outputs.get(1).map(|o| o.value).unwrap_or(0),
        receipt_index: None,
    })
}



/// Computed output amounts for a cross-pair match TX.
#[derive(Debug)]
pub struct CrossPairOutputs {
    /// KAS paid to seller (output[0]).
    pub seller_kas: u64,
    /// Tokens delivered to buyer (output[1]), using Token B from matcher inventory.
    pub buyer_tokens: u64,
    /// Token A forwarded to matcher (output[2]), from sell order.
    pub token_a_forward: u64,
    /// Receipt value (output[3], optional).
    pub receipt_value: u64,
    /// Matcher change in KAS (output[4], optional).
    pub matcher_change: u64,
    /// Whether a receipt output is included.
    pub include_receipt: bool,
    /// Execution amount for the receipt (= buyer_tokens).
    pub exec_amount: u64,
}



/// Determine if a crossing pair needs a partial fill based on value mismatch.
///
/// Returns `None` if a full fill is possible, `Some("buy")` if the buy order
/// is larger (needs buy partial fill), or `Some("sell")` if the sell order is
/// larger (needs sell partial fill).
#[allow(dead_code)] // Public API: used by auto-match partial fill logic
pub fn needs_partial_fill(buy: &DetectedOrder, sell: &DetectedOrder) -> Option<&'static str> {
    let expected_tokens = (buy.value as u128 * buy.price_num as u128 / buy.price_den as u128) as u64;
    let expected_kas = (sell.value as u128 * sell.price_num as u128 / sell.price_den as u128) as u64;
    let total_in = buy.value + sell.value;

    if expected_kas + expected_tokens > total_in {
        // Prices cross but values don't align for a full fill
        if buy.value > sell.value {
            Some("buy") // Buy order is larger, partial fill the buy
        } else {
            Some("sell") // Sell order is larger, partial fill the sell
        }
    } else {
        None // Full fill is possible
    }
}

/// Run the auto-match loop.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    pair_id_hex: &str,
    interval_secs: u64,
    dry_run: bool,
    min_spread: f64,
    max_matches: u64,
    cross_pair: bool,
) -> anyhow::Result<()> {
    // Parse and validate pair_id
    let pair_id_bytes = hex::decode(pair_id_hex)?;
    if pair_id_bytes.len() != 32 {
        anyhow::bail!("Invalid pair ID: expected 64 hex characters, got {}. Check the --pair-id value.", pair_id_hex.len());
    }
    let mut pair_id = [0u8; 32];
    pair_id.copy_from_slice(&pair_id_bytes);

    let config = AutoMatchConfig {
        pair_id,
        pair_id_hex: pair_id_hex.to_string(),
        interval_secs,
        dry_run,
        min_spread,
        max_matches,
    };
    config.validate()?;

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    println!("KOB Auto-Match");
    println!("===============");
    println!("Pair ID:      {}", pair_id_hex);
    println!("Interval:     {} seconds", interval_secs);
    println!("Dry Run:      {}", dry_run);
    println!("Min Spread:   {}", min_spread);
    println!("Max Matches:  {}", if max_matches == 0 { "unlimited".to_string() } else { max_matches.to_string() });
    println!("Cross-pair:   {}", if cross_pair { "removed (use v18 swap rings)" } else { "disabled" });
    println!("Matcher:      {}", wallet.address);
    println!();

    if dry_run {
        println!("[DRY RUN] Will show matches without submitting transactions.");
        println!();
    }

    let _owner_hash = blake2b_256(&pubkey);
    let _spk_hash = compute_p2pk_spk_hash(&pubkey);

    // Load order cache from the same directory as the wallet file
    let cache_path = wallet_path.with_file_name("orders.json");
    let order_cache = OrderCache::load(&cache_path);
    let cache_lookup = order_cache.by_p2sh_hash();

    if order_cache.orders.is_empty() {
        println!("  Order cache ({}) is empty.", cache_path.display());
        println!("  Populate it by deploying orders via 'kob-cli deploy' or manually.");
    } else {
        let pair_orders: Vec<_> = order_cache
            .orders
            .iter()
            .filter(|o| o.pair_id == pair_id_hex)
            .collect();
        println!(
            "  Order cache: {} total entries, {} for this pair.",
            order_cache.orders.len(),
            pair_orders.len()
        );
    }
    println!();

    info!(pair_id = %pair_id_hex, interval = interval_secs, max_matches = max_matches, "starting auto-match loop");

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let mut round = 0u64;
    let mut match_count = 0u64;

    loop {
        round += 1;
        println!();
        println!("--- Round {} (matches: {}) ---", round, match_count);

        // Check max_matches limit
        if max_matches > 0 && match_count >= max_matches {
            println!("  Reached max_matches limit ({}). Stopping.", max_matches);
            break;
        }

        // Scan wallet UTXOs for fee funding
        let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
        let fee_utxo = wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= FEE_BUDGET + MIN_UTXO_VALUE);

        if fee_utxo.is_none() && !dry_run {
            println!("  WARNING: No P2PK UTXO for fee payment. Skipping round.");
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            continue;
        }

        // Collect all known P2SH addresses from the order cache for this pair
        let cached_addresses: Vec<String> = order_cache
            .orders
            .iter()
            .filter(|o| o.pair_id == pair_id_hex)
            .filter_map(|o| {
                // Reconstruct the P2SH address from the cache entry
                // The P2SH hash is already stored -- we need the bech32 address
                let hash_bytes = hex::decode(&o.p2sh_hash).ok()?;
                if hash_bytes.len() != 32 {
                    return None;
                }
                Some(crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &hash_bytes))
            })
            .collect();

        // Also scan the wallet's own address
        let mut all_addresses: Vec<&str> = vec![wallet.address.as_str()];
        for addr in &cached_addresses {
            if !all_addresses.contains(&addr.as_str()) {
                all_addresses.push(addr.as_str());
            }
        }

        let utxos = rpc.get_utxos_by_addresses(&all_addresses).await?;
        let p2sh_utxos: Vec<&RpcUtxo> = utxos.iter().filter(|u| is_p2sh_utxo(u)).collect();

        println!("  Scanned {} addresses, {} UTXOs, {} P2SH covenant UTXOs",
            all_addresses.len(), utxos.len(), p2sh_utxos.len());

        if p2sh_utxos.is_empty() {
            println!("  No P2SH covenant UTXOs found. Waiting...");
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            continue;
        }

        // Identify known orders by matching P2SH hashes against the cache
        let mut detected_orders: Vec<DetectedOrder> = Vec::new();

        for utxo in &p2sh_utxos {
            if let Some(hash) = extract_p2sh_hash(&utxo.utxo_entry.script_public_key.script) {
                if let Some(cached) = cache_lookup.get(&hash) {
                    let side = match cached.side.as_str() {
                        "buy" => OrderSide::Buy,
                        "sell" => OrderSide::Sell,
                        _ => continue,
                    };

                    let owner_bytes = hex::decode(&cached.owner_hash).unwrap_or_default();
                    let spk_bytes = hex::decode(&cached.spk_hash).unwrap_or_default();
                    if owner_bytes.len() != 32 || spk_bytes.len() != 32 {
                        continue;
                    }
                    let mut owner_hash = [0u8; 32];
                    let mut spk_hash = [0u8; 32];
                    owner_hash.copy_from_slice(&owner_bytes);
                    spk_hash.copy_from_slice(&spk_bytes);

                    // Reconstruct the redeemScript from the cache's OWN
                    // recorded version/max_matcher_fee/expiry_daa -- not
                    // hardcoded defaults. `max_matcher_fee` is part of the
                    // 145B state that's hashed into the P2SH address for
                    // every version, so any order deployed with a
                    // non-default value (or expiry, or v16) previously
                    // failed this reconstruction silently (P2SH mismatch ->
                    // fell through to "Unknown P2SH UTXO" below).
                    // cancel_pending = 0 (active order; cancelled orders
                    // aren't scanned here).
                    let cached_version = cached.version;
                    let rs = match side {
                        OrderSide::Buy => {
                            let pair_bytes = hex::decode(&cached.pair_id).unwrap_or_default();
                            if pair_bytes.len() != 32 { continue; }
                            let mut tcid = [0u8; 32];
                            tcid.copy_from_slice(&pair_bytes);
                            if cached_version == 18 {
                                kob_core::contract::spot::order::build_buy_redeem_script(
                                    &tcid,
                                    cached.price_num,
                                    cached.price_den,
                                    cached.min_fill,
                                    &owner_hash,
                                    &spk_hash,
                                    &kob_core::compute_p2pk_spk_hash(&pubkey), // okspkh (E1 expire seat)
                                    cached.max_matcher_fee, // bps for v18
                                    0,
                                    cached.expiry_daa,
                                )?
                            } else {
                                anyhow::bail!(
                                    "Unsupported cached order version {} (pre-v18 generations were removed in Stage E)",
                                    cached_version
                                );
                            }
                        }
                        OrderSide::Sell => {
                            // Sells: v18 (unified spot) or the single legacy
                            // v14 layout.
                            if cached_version == 18 {
                                kob_core::contract::spot::order::build_sell_redeem_script(
                                    cached.price_num,
                                    cached.price_den,
                                    cached.min_fill,
                                    &owner_hash,
                                    &spk_hash,
                                    &kob_core::contract::compute_token_unit_spk_hash(&pubkey), // otspkh (E1 expire seat)
                                    cached.max_matcher_fee, // bps for v18
                                    0,
                                    cached.expiry_daa,
                                )?
                            } else {
                                anyhow::bail!(
                                    "Unsupported cached order version {} (pre-v18 generations were removed in Stage E)",
                                    cached_version
                                );
                            }
                        }
                    };

                    detected_orders.push(DetectedOrder {
                        txid: utxo.outpoint.transaction_id.clone(),
                        index: utxo.outpoint.index,
                        value: utxo.utxo_entry.amount,
                        side,
                        price_num: cached.price_num,
                        price_den: cached.price_den,
                        min_fill: cached.min_fill,
                        owner_hash,
                        spk_hash,
                        p2sh_hash: hash.clone(),
                        redeem_script: rs,
                        token_cov_id: cached.pair_id.clone(),
                        version: if side == OrderSide::Buy || cached_version == 18 { cached_version } else { 14 },
                        max_matcher_fee: cached.max_matcher_fee,
                    });

                    let side_str = match side {
                        OrderSide::Buy => "BUY",
                        OrderSide::Sell => "SELL",
                    };
                    println!(
                        "  Identified {} order: {}:{} ({} sompi) price={}/{}",
                        side_str,
                        &utxo.outpoint.transaction_id[..16],
                        utxo.outpoint.index,
                        utxo.utxo_entry.amount,
                        cached.price_num,
                        cached.price_den,
                    );
                } else {
                    println!(
                        "  Unknown P2SH UTXO: {}:{} ({} sompi) hash={}...",
                        utxo.outpoint.transaction_id,
                        utxo.outpoint.index,
                        utxo.utxo_entry.amount,
                        &hash[..16]
                    );
                }
            }
        }

        // Find crossing pairs
        let pairs = find_crossing_pairs(&detected_orders, min_spread);

        if pairs.is_empty() {
            println!("  No crossing pairs found. Waiting...");
        } else {
            println!("  Found {} crossing pair(s):", pairs.len());
            for (i, pair) in pairs.iter().enumerate() {
                let buy_price = pair.buy.price_num as f64 / pair.buy.price_den as f64;
                let sell_price = pair.sell.price_num as f64 / pair.sell.price_den as f64;
                println!(
                    "    [{}] buy@{:.4} ({}:{}) x sell@{:.4} ({}:{}) spread={:.4}",
                    i,
                    buy_price,
                    &pair.buy.txid[..8],
                    pair.buy.index,
                    sell_price,
                    &pair.sell.txid[..8],
                    pair.sell.index,
                    pair.spread,
                );

                // Rough pre-submit estimate for display only (no fee/cap
                // logic here -- the canonical planner inside `submit_match`
                // computes the real, F6-correct amounts).
                let est_tokens = (pair.buy.value as u128 * pair.buy.price_num as u128
                    / pair.buy.price_den as u128) as u64;
                let est_kas = (pair.sell.value as u128 * pair.sell.price_num as u128
                    / pair.sell.price_den as u128) as u64;
                println!(
                    "         seller_kas~={} buyer_tokens~={} (pre-fee estimate)",
                    est_kas, est_tokens,
                );

                if dry_run {
                    println!("         [DRY RUN] Would submit match TX via the canonical planner.");
                    match_count += 1;
                } else if let Some(fee) = fee_utxo {
                    // fee_bps=None: submit_match derives the F6-safe default
                    // from the buy's own max_matcher_fee when it's v16.
                    match submit_match(&rpc, &pair.buy, &pair.sell, &privkey, fee, None).await {
                        Ok(result) => {
                            println!("         MATCHED! TXID: {}", result.tx_id);
                            println!(
                                "         Seller received: {} sompi, Buyer received: {} sompi",
                                result.seller_kas, result.buyer_tokens
                            );
                        }
                        Err(e) => {
                            warn!("         Match TX failed: {}", e);
                            println!("         Cannot match: {}", e);
                            continue;
                        }
                    }
                    match_count += 1;
                } else {
                    println!("         SKIPPED: No fee UTXO available.");
                }

                // Check max_matches limit after each match
                if max_matches > 0 && match_count >= max_matches {
                    println!("  Reached max_matches limit ({}).", max_matches);
                    break;
                }
            }
        }

        // Cross-pair routing: the KAS-bridged v8/v14 route was removed in
        // Stage E — token<->token now settles as v18 swap rings (2-cycle /
        // triangle) via the engine's ring matcher or `kob-cli match-ring`.
        if cross_pair {
            println!("  Cross-pair KAS-bridged routing was removed; use v18 swap rings (match-ring / engine).");
        }

        // Check if we should stop
        if max_matches > 0 && match_count >= max_matches {
            println!();
            println!("Stopping: reached max_matches limit ({}).", max_matches);
            break;
        }

        // Wait for next round
        println!("  Sleeping {} seconds...", interval_secs);
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }

    println!();
    println!("Auto-match complete. {} matches found.", match_count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_order(side: OrderSide, price_num: u64, price_den: u64, value: u64) -> DetectedOrder {
        DetectedOrder {
            txid: "a".repeat(64),
            index: 0,
            value,
            side,
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: [0xAA; 32],
            spk_hash: [0xBB; 32],
            p2sh_hash: "00".repeat(32),
            redeem_script: vec![0x51],
            token_cov_id: "00".repeat(32),
            version: 14,
            max_matcher_fee: 10_000_000,
        }
    }

    #[test]
    fn find_crossing_pairs_simple_cross() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 10, 1, 10_000_000),  // buy at 10
            make_test_order(OrderSide::Sell, 8, 1, 10_000_000),  // sell at 8
        ];
        let pairs = find_crossing_pairs(&orders, 0.0);
        assert_eq!(pairs.len(), 1, "Should find one crossing pair");
        assert!(pairs[0].spread >= 2.0, "Spread should be >= 2.0");
    }

    #[test]
    fn find_crossing_pairs_no_cross() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 5, 1, 10_000_000),   // buy at 5
            make_test_order(OrderSide::Sell, 10, 1, 10_000_000),  // sell at 10
        ];
        let pairs = find_crossing_pairs(&orders, 0.0);
        assert_eq!(pairs.len(), 0, "Should find no crossing pairs");
    }

    #[test]
    fn find_crossing_pairs_exact_match() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 7, 1, 10_000_000),   // buy at 7
            make_test_order(OrderSide::Sell, 7, 1, 10_000_000),  // sell at 7
        ];
        let pairs = find_crossing_pairs(&orders, 0.0);
        assert_eq!(pairs.len(), 1, "Equal prices should cross");
    }

    #[test]
    fn find_crossing_pairs_min_spread_filter() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 11, 1, 10_000_000),  // buy at 11
            make_test_order(OrderSide::Sell, 10, 1, 10_000_000),  // sell at 10
        ];
        // Spread is 1.0, filter requires 2.0
        let pairs = find_crossing_pairs(&orders, 2.0);
        assert_eq!(pairs.len(), 0, "Spread 1.0 should be filtered by min_spread 2.0");

        // Same orders, lower min_spread
        let pairs = find_crossing_pairs(&orders, 0.5);
        assert_eq!(pairs.len(), 1, "Spread 1.0 should pass min_spread 0.5");
    }

    #[test]
    fn find_crossing_pairs_multiple() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 15, 1, 10_000_000),  // buy at 15
            make_test_order(OrderSide::Buy, 12, 1, 10_000_000),  // buy at 12
            make_test_order(OrderSide::Sell, 8, 1, 10_000_000),  // sell at 8
            make_test_order(OrderSide::Sell, 10, 1, 10_000_000), // sell at 10
        ];
        let pairs = find_crossing_pairs(&orders, 0.0);
        // buy@15 crosses sell@8 (spread 7) and sell@10 (spread 5)
        // buy@12 crosses sell@8 (spread 4) and sell@10 (spread 2)
        assert_eq!(pairs.len(), 4, "Should find 4 crossing pairs");
        // Sorted by spread descending
        assert!(pairs[0].spread >= pairs[1].spread);
        assert!(pairs[1].spread >= pairs[2].spread);
        assert!(pairs[2].spread >= pairs[3].spread);
    }

    #[test]
    fn find_crossing_pairs_rational_prices() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 3, 2, 10_000_000),   // buy at 1.5
            make_test_order(OrderSide::Sell, 7, 5, 10_000_000),  // sell at 1.4
        ];
        // 3/2 = 1.5 >= 7/5 = 1.4 -> crossing
        // Cross-multiply: 3*5 = 15 >= 7*2 = 14
        let pairs = find_crossing_pairs(&orders, 0.0);
        assert_eq!(pairs.len(), 1, "Rational prices 3/2 >= 7/5 should cross");
    }

    #[test]
    fn find_crossing_pairs_rational_no_cross() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 2, 3, 10_000_000),   // buy at 0.666
            make_test_order(OrderSide::Sell, 3, 4, 10_000_000),  // sell at 0.75
        ];
        // 2/3 = 0.666 < 3/4 = 0.75 -> no crossing
        // Cross-multiply: 2*4 = 8 < 3*3 = 9
        let pairs = find_crossing_pairs(&orders, 0.0);
        assert_eq!(pairs.len(), 0, "Rational prices 2/3 < 3/4 should not cross");
    }

    #[test]
    fn auto_match_config_validate_valid() {
        let config = AutoMatchConfig {
            pair_id: [0x01; 32],
            pair_id_hex: "01".repeat(32),
            interval_secs: 10,
            dry_run: false,
            min_spread: 0.0,
            max_matches: 0,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn auto_match_config_validate_zero_interval() {
        let config = AutoMatchConfig {
            pair_id: [0x01; 32],
            pair_id_hex: "01".repeat(32),
            interval_secs: 0,
            dry_run: false,
            min_spread: 0.0,
            max_matches: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn auto_match_config_validate_negative_spread() {
        let config = AutoMatchConfig {
            pair_id: [0x01; 32],
            pair_id_hex: "01".repeat(32),
            interval_secs: 10,
            dry_run: false,
            min_spread: -1.0,
            max_matches: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn auto_match_config_with_max_matches() {
        let config = AutoMatchConfig {
            pair_id: [0x01; 32],
            pair_id_hex: "01".repeat(32),
            interval_secs: 5,
            dry_run: true,
            min_spread: 0.0,
            max_matches: 10,
        };
        assert!(config.validate().is_ok());
        assert_eq!(config.max_matches, 10);
    }

    #[test]
    fn crossing_pair_sorted_by_spread() {
        let orders = vec![
            make_test_order(OrderSide::Buy, 20, 1, 10_000_000),  // buy at 20
            make_test_order(OrderSide::Sell, 5, 1, 10_000_000),  // sell at 5 (spread 15)
            make_test_order(OrderSide::Sell, 15, 1, 10_000_000), // sell at 15 (spread 5)
        ];
        let pairs = find_crossing_pairs(&orders, 0.0);
        assert_eq!(pairs.len(), 2);
        assert!(pairs[0].spread > pairs[1].spread, "First pair should have larger spread");
    }

    #[test]
    fn order_side_equality() {
        assert_eq!(OrderSide::Buy, OrderSide::Buy);
        assert_eq!(OrderSide::Sell, OrderSide::Sell);
        assert_ne!(OrderSide::Buy, OrderSide::Sell);
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
            cancel_pending: false,
            token: None,
            version: 13,
            expiry_daa: 0,
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
            cancel_pending: false,
            token: None,
            version: 13,
            expiry_daa: 0,
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
            cancel_pending: false,
            token: None,
            version: 13,
            expiry_daa: 0,
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
            cancel_pending: false,
            token: None,
            version: 13,
            expiry_daa: 0,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
        });

        assert_eq!(cache.orders.len(), 2);
        cache.remove_outpoint(&op);
        assert_eq!(cache.orders.len(), 1);
        assert_eq!(cache.orders[0].side, "sell");
    }

    #[test]
    fn order_cache_json_roundtrip() {
        let entry = OrderCacheEntry {
            outpoint: "aa".repeat(32) + ":0",
            side: "sell".to_string(),
            pair_id: "00".repeat(32),
            price_num: 500,
            price_den: 3,
            min_fill: 5_000_000,
            owner_hash: "11".repeat(32),
            spk_hash: "22".repeat(32),
            p2sh_hash: "33".repeat(32),
            value: 20_000_000,
            cancel_pending: false,
            token: None,
            version: 13,
            expiry_daa: 0,
            max_matcher_fee: 10_000_000,
            redeem_script: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: OrderCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.price_num, 500);
        assert_eq!(parsed.price_den, 3);
        assert_eq!(parsed.side, "sell");
    }

    #[test]
    fn needs_partial_fill_full_fill_possible() {
        // Same price, same value -> full fill
        let buy = make_test_order(OrderSide::Buy, 1, 2, 20_000_000);
        let sell = make_test_order(OrderSide::Sell, 1, 2, 20_000_000);
        assert_eq!(needs_partial_fill(&buy, &sell), None, "Equal values should allow full fill");
    }

    #[test]
    fn needs_partial_fill_buy_larger() {
        // buy at 5/1: expected_tokens = 50M * 5 / 1 = 250M (way more than sell has)
        let buy = make_test_order(OrderSide::Buy, 5, 1, 50_000_000);
        let sell = make_test_order(OrderSide::Sell, 5, 1, 10_000_000);
        // expected_tokens = 50M * 5 / 1 = 250M
        // expected_kas = 10M * 5 / 1 = 50M
        // total_in = 60M, sum = 300M > 60M -> partial fill needed
        let result = needs_partial_fill(&buy, &sell);
        assert_eq!(result, Some("buy"), "Buy larger -> partial buy fill");
    }

    #[test]
    fn needs_partial_fill_sell_larger() {
        let buy = make_test_order(OrderSide::Buy, 5, 1, 10_000_000);
        let sell = make_test_order(OrderSide::Sell, 5, 1, 50_000_000);
        // expected_tokens = 10M * 5 / 1 = 50M
        // expected_kas = 50M * 5 / 1 = 250M
        // total_in = 60M, sum = 300M > 60M -> partial fill needed
        let result = needs_partial_fill(&buy, &sell);
        assert_eq!(result, Some("sell"), "Sell larger -> partial sell fill");
    }

    #[test]
    fn submit_result_struct() {
        let result = SubmitResult {
            tx_id: "abc".to_string(),
            seller_kas: 5_000_000,
            buyer_tokens: 3_000_000,
            receipt_index: Some(2),
        };
        assert_eq!(result.tx_id, "abc");
        assert_eq!(result.seller_kas, 5_000_000);
        assert_eq!(result.buyer_tokens, 3_000_000);
        assert_eq!(result.receipt_index, Some(2));
    }


    fn make_cross_pair_order(
        side: OrderSide,
        price_num: u64,
        price_den: u64,
        value: u64,
        token_cov_id: &str,
    ) -> DetectedOrder {
        DetectedOrder {
            txid: "b".repeat(64),
            index: 0,
            value,
            side,
            price_num,
            price_den,
            min_fill: 1_000_000,
            owner_hash: [0xAA; 32],
            spk_hash: [0xBB; 32],
            p2sh_hash: "00".repeat(32),
            redeem_script: vec![0x51],
            token_cov_id: token_cov_id.to_string(),
            version: 14,
            max_matcher_fee: 10_000_000,
        }
    }

    #[test]
    fn detected_order_has_token_cov_id() {
        let order = make_cross_pair_order(OrderSide::Buy, 1, 1, 10_000_000, &"cc".repeat(32));
        assert_eq!(order.token_cov_id, "cc".repeat(32));
        assert_eq!(order.token_cov_id.len(), 64);
    }

}
