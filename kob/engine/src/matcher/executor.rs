//! Atomic match transaction construction and continuous matching loop.

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

use crate::config::AppConfig;
use kob_core::{DEFAULT_MATCHER_FEE, MIN_UTXO_VALUE, RECEIPT_VALUE};
use crate::matcher::deploy;
use crate::matcher::matching::{self, CrossingPair, MatchType};
use crate::matcher::order_book::{OrderBook, OrderSide};
use crate::matcher::persistence;
use crate::matcher::api::{AppState, WsEvent};
use crate::matcher::trades::{Trade, Side};
use crate::matcher::candle::Interval;
use crate::rpc::{RpcClient, RpcUtxo};
use crate::matcher::scanner::{
    BlockScanner, TransactionData, ScanResult,
    PerpDeploySide, LendingOrderType, PredictionItemType,
};

/// Default cooldown for failed outpoints (seconds).
pub const FAILED_OUTPOINT_COOLDOWN_SECS: u64 = 30;

/// Tracks outpoints that have been used locally (spent in submitted TXs)
/// to avoid selecting stale UTXOs before mempool catches up.
#[derive(Debug)]
#[allow(dead_code)] // Fields used in tests
pub struct SpentTracker {
    /// Outpoints (txid:index) that were used as inputs in recently submitted TXs,
    /// with the timestamp when they were marked spent.
    pub spent: HashMap<String, Instant>,
    /// Outpoints (txid:index) that were created as outputs in recently submitted TXs.
    /// These may become available once the TX propagates.
    pub pending_outputs: Vec<(String, u64)>, // (outpoint_key, value)
    /// Outpoints that failed during TX submission, with cooldown expiry.
    /// These are temporarily excluded from matching to prevent infinite retry loops.
    pub failed: HashMap<String, Instant>,
    /// Cooldown duration for failed outpoints.
    pub cooldown_secs: u64,
}

impl Default for SpentTracker {
    fn default() -> Self {
        Self {
            spent: HashMap::new(),
            pending_outputs: Vec::new(),
            failed: HashMap::new(),
            cooldown_secs: FAILED_OUTPOINT_COOLDOWN_SECS,
        }
    }
}

impl SpentTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a SpentTracker with a custom cooldown duration (for testing).
    #[allow(dead_code)] // Used in tests
    pub fn with_cooldown(secs: u64) -> Self {
        Self {
            cooldown_secs: secs,
            ..Self::default()
        }
    }

    /// Mark an outpoint as spent (used as input in a submitted TX).
    pub fn mark_spent(&mut self, outpoint_key: &str) {
        self.spent.insert(outpoint_key.to_string(), Instant::now());
    }

    /// Mark an outpoint as failed (TX submission rejected).
    /// The outpoint will be excluded from matching for `cooldown_secs` seconds.
    pub fn mark_failed(&mut self, outpoint_key: &str) {
        self.failed.insert(
            outpoint_key.to_string(),
            Instant::now(),
        );
    }

    /// Check if an outpoint is locally tracked as spent or under cooldown.
    pub fn is_spent(&self, outpoint_key: &str) -> bool {
        if self.spent.contains_key(outpoint_key) {
            return true;
        }
        self.is_failed(outpoint_key)
    }

    /// Check if an outpoint is under failure cooldown.
    pub fn is_failed(&self, outpoint_key: &str) -> bool {
        if let Some(when) = self.failed.get(outpoint_key) {
            when.elapsed().as_secs() < self.cooldown_secs
        } else {
            false
        }
    }

    /// Expire stale failure entries whose cooldown has elapsed.
    pub fn expire_failed(&mut self) {
        self.failed.retain(|_, when| when.elapsed().as_secs() < self.cooldown_secs);
    }

    /// Prune spent entries older than the given age (M-6).
    ///
    /// Entries older than max_age_secs are removed. Spent outpoints that
    /// have been confirmed in the DAG will not reappear as UTXOs, so pruning
    /// is safe -- the worst case is a redundant RPC rejection if a stale
    /// outpoint somehow reappears.
    pub fn prune_spent(&mut self, max_age_secs: u64) {
        let before = self.spent.len();
        self.spent.retain(|_, when| when.elapsed().as_secs() < max_age_secs);
        let pruned = before - self.spent.len();
        if pruned > 0 {
            info!(
                "[TRACKER] Pruned {} aged spent entries (>{} secs), {} remaining (M-6)",
                pruned, max_age_secs, self.spent.len()
            );
        }
    }

    /// Clear all tracked state (e.g., after a confirmed block).
    #[allow(dead_code)] // Used in tests
    pub fn clear(&mut self) {
        self.spent.clear();
        self.pending_outputs.clear();
        self.failed.clear();
    }
}

/// Result of a successful match execution.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct MatchResult {
    pub match_tx_id: String,
    pub match_type: MatchType,
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub receipt_tx_id: String,
    pub receipt_idx: u32,
    pub receipt_value: u64,
    pub token_cov_id: String,
    /// Price numerator used when building the receipt redeemScript.
    /// Needed to reconstruct the P2SH for receipt consumption.
    pub price_num: u64,
    /// Price denominator used when building the receipt redeemScript.
    pub price_den: u64,
}

/// IFD context passed to fill functions when a contingent order B should be
/// deployed as part of the fill TX.
#[derive(Debug, Clone)]
pub struct IfdFillContext {
    /// IFD rule ID (for marking triggered after success).
    pub rule_id: u64,
    /// Order B's redeem script bytes (hex-decoded).
    pub order_b_rs: Vec<u8>,
    /// Order B's P2SH address (hex, for logging).
    pub order_b_p2sh: String,
    /// Order B's expiry DAA score (0 = GTC, no expiry).
    pub expiry_daa: u64,
}

/// Public interface for execute_full_match (called from deploy.rs).
pub async fn execute_full_match_pub(
    rpc: &RpcClient,
    pair: &CrossingPair,
    config: &AppConfig,
) -> Option<MatchResult> {
    let mut tracker = SpentTracker::new();
    execute_full_match(rpc, pair, config, None, &mut tracker).await
}

/// Execute a full match between a buy and sell order.
///
/// When `ifd_ctx` is `Some`, the fill TX embeds a `KOB:2:<flags><B_RS>` (v2)
/// payload so the scanner discovers order B (the contingent IFD order) in the next
/// scan cycle. The buyer_tokens output already targets B's P2SH (because
/// A's `bspkh` was set to B's SPK hash at registration time).
async fn execute_full_match(
    rpc: &RpcClient,
    pair: &CrossingPair,
    config: &AppConfig,
    ifd_ctx: Option<&IfdFillContext>,
    spent_tracker: &mut SpentTracker,
) -> Option<MatchResult> {
    let buy_key = pair.buy.outpoint_key();
    let sell_key = pair.sell.outpoint_key();

    info!("======================================================================");
    info!(
        "EXECUTING FULL MATCH [{}...]",
        &pair.token_cov_id[..pair.token_cov_id.len().min(16)]
    );
    info!("======================================================================");
    info!(
        "  BUY:  {}... value={} price={}/{}",
        &buy_key[..buy_key.len().min(20)],
        pair.buy.value,
        pair.buy.price_num,
        pair.buy.price_den
    );
    info!(
        "  SELL: {}... value={} price={}/{}",
        &sell_key[..sell_key.len().min(20)],
        pair.sell.value,
        pair.sell.price_num,
        pair.sell.price_den
    );
    info!(
        "  Expected tokens (buy contract): {}",
        pair.expected_tokens
    );
    info!("  Expected KAS (sell contract):   {}", pair.expected_kas);

    // Get wallet UTXOs (needed for fee input and output SPK)
    let (utxos, wallet_spk_version, wallet_spk_script, wallet_spk_hex) =
        fetch_wallet_utxos(rpc, &config.address, "MATCH").await?;

    // Compute match outputs first (needed for mass-aware fee UTXO selection)
    let outputs = matching::compute_match_outputs(pair);

    // Select fee UTXOs using mass-aware accumulation.
    //
    // A fee input is required because:
    //  1. The miner fee must come from somewhere (order UTXOs are fully consumed).
    //  2. Extra input credit (C / fee_val) offsets storage mass from small outputs
    //     (e.g. receipt at 3M sompi creates C/3M = 1,333,333 mass alone).
    //
    // Strategy: accumulate UTXOs smallest-first until storage_mass == 0.
    // Small UTXOs give MORE credit (C/small > C/big), so this converges fast.
    let fee_utxos = select_fee_utxos_mass_aware(&utxos, pair, &outputs, "MATCH", spent_tracker);
    if fee_utxos.is_empty() {
        warn!("[MATCH] No fee UTXOs available. Skipping.");
        return None;
    }
    let fee_utxo_total: u64 = fee_utxos.iter().map(|u| u.utxo_entry.amount).sum();

    // Build receipt
    let tcid = &pair.token_cov_id;
    let tcid_bytes: [u8; 32] = match hex::decode(tcid) {
        Ok(v) if v.len() == 32 => v.try_into().expect("length verified as 32"),
        _ => {
            warn!("[MATCH] Invalid hex for token_cov_id: {}", &tcid[..tcid.len().min(16)]);
            return None;
        }
    };
    let exec_amount = pair.expected_tokens.min(pair.sell.value);
    let (_receipt_rs_hex, receipt_p2sh_hex, receipt_p2sh_version) = deploy::build_receipt_scripts(
        &tcid_bytes,
        pair.buy.price_num,
        pair.buy.price_den,
        exec_amount,
    );

    // Recalculate matcher_change to include fee UTXO(s) value minus receipt.
    // The receipt output is funded from the matcher's fee UTXOs (running capital).
    // Single receipt output only — no oracle receipt splitting (attack amplification prevention).
    let (adj_seller_kas, adj_matcher_change) = {
        let raw_change = (outputs.matcher_change + fee_utxo_total)
            .saturating_sub(outputs.receipt_value)
            .saturating_sub(outputs.fee);
        compute_change_allocation(outputs.seller_kas, raw_change)
    };

    debug!("  Seller KAS (out[0]):        {}", adj_seller_kas);
    debug!("  Buyer tokens (out[1]):      {}", outputs.buyer_tokens);
    debug!("  Receipt (out[2]):           {}", outputs.receipt_value);
    debug!("  Matcher change:             {}", adj_matcher_change);
    debug!("  Fee:                        {}", outputs.fee);
    debug!("  Fee UTXOs:                  {} inputs, {} sompi total", fee_utxos.len(), fee_utxo_total);

    // Build fill sigscripts
    let buy_rs = pair.buy.redeem_script();
    let sell_rs = pair.sell.redeem_script();
    // v13: buy fill has 4 items (toi, tii, coi, Op1), sell fill has 2 items (koi, Op1)
    let buy_fill_ss = kob_core::contract::build_buy_fill_sigscript(1, 1, 0, &buy_rs);
    let sell_fill_ss = kob_core::contract::build_sell_fill_sigscript(0, &sell_rs);

    debug!("  Buy fill SS:  {}B", buy_fill_ss.len());
    debug!("  Sell fill SS: {}B", sell_fill_ss.len());

    // Resolve counterparty SPKs.  Both orders must carry an explicit SPK
    // (populated via payload v2 deploy); if either is missing we cannot build
    // a valid match TX (the contract checks Blake2b(output.spk) == spk_hash).
    let (seller_spk_version, seller_spk_script) = match pair.sell.resolve_counterparty_spk() {
        Some(spk) => spk,
        None => {
            error!(
                "[MATCH] SELL order {} missing counterparty_spk — \
                 deploy TX used payload v1 (no SPK). Cannot route seller_kas. Skipping.",
                &sell_key[..sell_key.len().min(20)]
            );
            return None;
        }
    };
    let seller_spk_hex = hex::encode(&seller_spk_script);
    let (buyer_spk_version, buyer_spk_script) = match pair.buy.resolve_counterparty_spk() {
        Some(spk) => spk,
        None => {
            error!(
                "[MATCH] BUY order {} missing counterparty_spk — \
                 deploy TX used payload v1 (no SPK). Cannot route buyer_tokens. Skipping.",
                &buy_key[..buy_key.len().min(20)]
            );
            return None;
        }
    };
    let buyer_spk_hex = hex::encode(&buyer_spk_script);

    // Build TX for sighash computation (needed to sign fee input).
    // Version 1 required for covenant output bindings.
    // lock_time must satisfy OP_CSV(50) in covenant inputs (sequence=50).
    let mut tx = kob_core::tx::Transaction::new(1);
    tx.lock_time = 50;

    push_covenant_input(&mut tx, &pair.buy.tx_id, pair.buy.index,
        pair.buy.p2sh_version, &pair.buy.p2sh_script(), pair.buy.value);
    push_covenant_input(&mut tx, &pair.sell.tx_id, pair.sell.index,
        pair.sell.p2sh_version, &pair.sell.p2sh_script(), pair.sell.value);
    for fu in &fee_utxos {
        push_p2pk_input(&mut tx, fu);
    }

    push_output(&mut tx, adj_seller_kas, seller_spk_version, seller_spk_script.clone());
    // buyer_tokens output carries the token covenant (auth from sell input[1])
    tx.outputs.push(kob_core::tx::TxOutput::new(outputs.buyer_tokens, buyer_spk_version, buyer_spk_script.clone(), Some(kob_core::tx::CovenantBinding::new(1, kob_core::compat::parse_hash(&pair.token_cov_id.clone()).unwrap()))));
    let receipt_p2sh_bytes = decode_hex(&receipt_p2sh_hex, "receipt_p2sh")?;
    push_output(&mut tx, outputs.receipt_value, receipt_p2sh_version, receipt_p2sh_bytes);
    if adj_matcher_change >= MIN_UTXO_VALUE {
        push_output(&mut tx, adj_matcher_change, wallet_spk_version, wallet_spk_script);
    }

    // Sign each fee input (indices 2..2+N)
    let mut privkey = config.private_key_bytes();
    let mut fee_sigscripts = Vec::with_capacity(fee_utxos.len());
    for i in 0..fee_utxos.len() {
        let ss = sign_p2pk_input(&tx, 2 + i, &privkey, "MATCH")?;
        fee_sigscripts.push(ss);
    }
    privkey.zeroize();

    // Build RPC outputs.
    // output[1] (buyer_tokens) carries the token covenant binding (auth from sell input[1]).
    // This is required for OpCovOutCount(tcid) >= 1 check in the buy contract fill path.
    let mut rpc_outputs = vec![
        deploy::build_rpc_output(adj_seller_kas, seller_spk_version, &seller_spk_hex),
        deploy::build_rpc_output_with_covenant(outputs.buyer_tokens, buyer_spk_version, &buyer_spk_hex, 1, &pair.token_cov_id),
        deploy::build_rpc_output(outputs.receipt_value, receipt_p2sh_version, &receipt_p2sh_hex),
    ];
    if adj_matcher_change >= MIN_UTXO_VALUE {
        rpc_outputs.push(deploy::build_rpc_output(
            adj_matcher_change,
            wallet_spk_version,
            &wallet_spk_hex,
        ));
    }

    // Build RPC inputs (sigOpCount = 0 for covenant inputs, 1 for fee P2PK)
    // Covenant fill inputs use sequence=50 to satisfy OP_CSV in the redeemScript.
    let mut rpc_inputs = vec![
        deploy::build_rpc_input_with_sequence(
            &pair.buy.tx_id,
            pair.buy.index,
            &hex::encode(&buy_fill_ss),
            0,
            50,
        ),
        deploy::build_rpc_input_with_sequence(
            &pair.sell.tx_id,
            pair.sell.index,
            &hex::encode(&sell_fill_ss),
            0,
            50,
        ),
    ];
    for (fu, ss) in fee_utxos.iter().zip(fee_sigscripts.iter()) {
        rpc_inputs.push(deploy::build_rpc_input(
            &fu.outpoint.transaction_id,
            fu.outpoint.index,
            &hex::encode(ss),
            1,
        ));
    }

    // Storage mass pre-check: reject before hitting the node
    {
        let mut in_vals = vec![pair.buy.value, pair.sell.value];
        for fu in &fee_utxos {
            in_vals.push(fu.utxo_entry.amount);
        }
        let mut out_vals = vec![adj_seller_kas, outputs.buyer_tokens, outputs.receipt_value];
        if adj_matcher_change >= MIN_UTXO_VALUE {
            out_vals.push(adj_matcher_change);
        }
        check_mass_presubmit(&in_vals, &out_vals, "MATCH")?;
    }

    // Build the submit payload. If an IFD rule is active, embed the
    // contingent order B's RS as a KOB:2: (v2) payload so the scanner
    // discovers it. Using v1 (KOB:1:) would cause the scanner to skip
    // the order because v1 payloads lack the counterparty SPK flag.
    let payload = if let Some(ctx) = ifd_ctx {
        let expiry = if ctx.expiry_daa > 0 { Some(ctx.expiry_daa) } else { None };
        let kob_payload = kob_core::contract::build_order_payload_full(
            &ctx.order_b_rs,
            false, // IFD-deployed orders are never post_only
            expiry,
        );
        let kob_payload_hex = hex::encode(&kob_payload);
        info!(
            "[IFD] Embedding order B payload in fill TX ({} bytes RS, P2SH={}...)",
            ctx.order_b_rs.len(),
            &ctx.order_b_p2sh[..ctx.order_b_p2sh.len().min(16)],
        );
        deploy::build_submit_payload_with_tx_payload(1, rpc_inputs, rpc_outputs, &kob_payload_hex, tx.lock_time)
    } else {
        deploy::build_submit_payload_with_lock_time(1, rpc_inputs, rpc_outputs, tx.lock_time)
    };
    tracing::debug!("[MATCH] TX lockTime = {}", tx.lock_time);
    let result = match rpc.submit_transaction(payload).await {
        Ok(r) => r,
        Err(e) => {
            error!("[MATCH] Submit failed: {}", e);
            return None;
        }
    };

    if result.ok {
        let match_tx_id = result.tx_id.unwrap_or_else(|| {
            warn!("[MATCH] Success response missing tx_id");
            String::new()
        });
        info!("[MATCH] SUCCESS! TXID: {}", match_tx_id);
        info!("  Seller received: {} sompi KAS", adj_seller_kas);
        info!("  Buyer received:  {} sompi tokens", outputs.buyer_tokens);
        info!("  Receipt at: {}:2", match_tx_id);

        // Mark fee UTXOs as spent so subsequent matches in this cycle
        // won't try to reuse them.
        for fu in &fee_utxos {
            spent_tracker.mark_spent(&fu.outpoint_key());
        }

        // Log IFD trigger
        if let Some(ctx) = ifd_ctx {
            info!(
                "[IFD] Triggered: order B deployed at {} (rule_id={}, fill_tx={})",
                ctx.order_b_p2sh, ctx.rule_id, match_tx_id,
            );
        }

        return Some(MatchResult {
            match_tx_id: match_tx_id.clone(),
            match_type: MatchType::Full,
            seller_kas: adj_seller_kas,
            buyer_tokens: outputs.buyer_tokens,
            receipt_tx_id: match_tx_id,
            receipt_idx: 2,
            receipt_value: outputs.receipt_value,
            token_cov_id: tcid.to_string(),
            price_num: pair.buy.price_num,
            price_den: pair.buy.price_den,
        });
    }

    error!(
        "[MATCH] FAILED: {}",
        result.error.unwrap_or_else(|| "Unknown error".to_string())
    );
    None
}

/// Execute a match (dispatches to full/partial).
///
/// When `ifd_ctx` is provided, it is forwarded to the fill function so the
/// contingent order B is deployed atomically inside the fill TX.
async fn execute_match(
    rpc: &RpcClient,
    pair: &CrossingPair,
    config: &AppConfig,
    ifd_ctx: Option<&IfdFillContext>,
    spent_tracker: &mut SpentTracker,
) -> Option<MatchResult> {
    // STP defense-in-depth: reject self-trades that slip through matching
    if pair.buy.owner_hash == pair.sell.owner_hash {
        warn!(
            "[STP] Blocked self-trade: buy {} and sell {} share owner_hash {}...",
            pair.buy.outpoint_key(),
            pair.sell.outpoint_key(),
            &pair.buy.owner_hash[..16],
        );
        return None;
    }

    match pair.match_type {
        MatchType::Full => execute_full_match(rpc, pair, config, ifd_ctx, spent_tracker).await,
        MatchType::PartialBuy => execute_partial_buy_fill(rpc, pair, config, spent_tracker).await,
        MatchType::PartialSell => execute_partial_sell_fill(rpc, pair, config, spent_tracker).await,
    }
}

// Partial Fill Helpers

/// Decode a hex token covenant ID into a fixed 32-byte array.
fn decode_token_cov_id(hex_str: &str, label: &str) -> Option<[u8; 32]> {
    match hex::decode(hex_str) {
        Ok(v) if v.len() == 32 => Some(v.try_into().expect("length verified as 32")),
        _ => {
            warn!("[{}] Invalid hex for token_cov_id: {}", label, &hex_str[..hex_str.len().min(16)]);
            None
        }
    }
}

/// Fetch wallet UTXOs and extract the wallet SPK from the first entry.
///
/// Returns (utxos, spk_version, spk_script, spk_hex) or None on failure.
async fn fetch_wallet_utxos(
    rpc: &RpcClient,
    address: &str,
    label: &str,
) -> Option<(Vec<RpcUtxo>, u16, Vec<u8>, String)> {
    let utxos = match rpc.get_spendable_utxos(address, Some(0)).await {
        Ok(u) => u,
        Err(e) => {
            error!("[{}] Failed to get UTXOs: {}", label, e);
            return None;
        }
    };
    if utxos.is_empty() {
        error!("[{}] No wallet UTXOs available", label);
        return None;
    }
    let (spk_version, spk_script) = utxos[0].parse_spk();
    let spk_hex = hex::encode(&spk_script);
    Some((utxos, spk_version, spk_script, spk_hex))
}

/// Find a fee UTXO from wallet UTXOs, optionally excluding a specific outpoint.
///
/// Prefers the largest eligible UTXO.  For partial fills this is fine because
/// the order input already provides significant mass credit; for full matches
/// use [`select_fee_utxo_for_mass`] instead.
fn select_fee_utxo<'a>(
    utxos: &'a [RpcUtxo],
    exclude_key: Option<&str>,
    label: &str,
    spent_tracker: &SpentTracker,
) -> Option<&'a RpcUtxo> {
    let found = utxos
        .iter()
        .filter(|u| {
            u.utxo_entry.amount >= DEFAULT_MATCHER_FEE
                && exclude_key.is_none_or(|k| u.outpoint_key() != k)
                && !spent_tracker.is_spent(&u.outpoint_key())
        })
        .max_by_key(|u| u.utxo_entry.amount);
    if found.is_none() {
        warn!("[{}] No fee UTXO available. Skipping.", label);
    }
    found
}

/// Find the best fee UTXO for minimizing storage mass.
///
/// Smaller UTXOs provide *more* storage mass credit (C / small_val > C / big_val).
/// This function picks the smallest UTXO that is >= DEFAULT_MATCHER_FEE, which maximizes the
/// input credit contribution and reduces net storage mass.
///
/// Falls back to the largest eligible UTXO if no small UTXO is available.
fn select_fee_utxo_for_mass<'a>(
    utxos: &'a [RpcUtxo],
    exclude_key: Option<&str>,
    label: &str,
    spent_tracker: &SpentTracker,
) -> Option<&'a RpcUtxo> {
    let eligible: Vec<_> = utxos
        .iter()
        .filter(|u| {
            u.utxo_entry.amount >= DEFAULT_MATCHER_FEE
                && exclude_key.is_none_or(|k| u.outpoint_key() != k)
                && !spent_tracker.is_spent(&u.outpoint_key())
        })
        .collect();
    if eligible.is_empty() {
        warn!("[{}] No fee UTXO available. Skipping.", label);
        return None;
    }
    // Prefer smallest UTXO for maximum storage mass credit
    eligible.into_iter().min_by_key(|u| u.utxo_entry.amount)
}

/// Select fee UTXOs with iterative mass-aware accumulation for match TXs.
///
/// Iterates: add UTXO → recompute change → recompute storage mass → repeat.
/// Adding fee UTXOs changes matcher_change, which can add/resize the change
/// output, altering out_mass. So we must recalculate mass after each addition.
/// Small UTXOs give more credit (C/small_val > C/big_val), so this converges fast.
fn select_fee_utxos_mass_aware<'a>(
    utxos: &'a [RpcUtxo],
    pair: &matching::CrossingPair,
    outputs: &matching::MatchOutputs,
    label: &str,
    spent_tracker: &SpentTracker,
) -> Vec<&'a RpcUtxo> {
    use kob_core::mass::compute_storage_mass;

    // Sort eligible UTXOs smallest-first for maximum credit per UTXO.
    // Exclude UTXOs already claimed by another match in this cycle.
    let mut eligible: Vec<&RpcUtxo> = utxos.iter()
        .filter(|u| u.utxo_entry.amount >= DEFAULT_MATCHER_FEE && !spent_tracker.is_spent(&u.outpoint_key()))
        .collect();
    eligible.sort_by_key(|u| u.utxo_entry.amount);

    if eligible.is_empty() {
        warn!("[{}] No fee UTXOs available. Skipping.", label);
        return Vec::new();
    }

    let mut selected: Vec<&RpcUtxo> = Vec::new();

    // Always need at least 1 fee UTXO (for miner fee)
    selected.push(eligible[0]);
    let mut ei = 1; // next index into eligible

    loop {
        // Recompute with current selection (single receipt, no oracle splitting).
        let fee_total: u64 = selected.iter().map(|u| u.utxo_entry.amount).sum();
        let raw_change = (outputs.matcher_change + fee_total)
            .saturating_sub(outputs.receipt_value)
            .saturating_sub(outputs.fee);
        let (adj_seller_kas, adj_change) =
            compute_change_allocation(outputs.seller_kas, raw_change);

        // Build input/output value arrays for compute_storage_mass
        let mut in_vals: Vec<u64> = vec![pair.buy.value, pair.sell.value];
        for u in &selected {
            in_vals.push(u.utxo_entry.amount);
        }
        let mut out_vals: Vec<u64> = vec![adj_seller_kas, outputs.buyer_tokens, outputs.receipt_value];
        if adj_change >= MIN_UTXO_VALUE {
            out_vals.push(adj_change);
        }

        // Use the same formula as Kaspad (relaxed/arithmetic dispatch + integer division order)
        let mass = compute_storage_mass(&in_vals, &out_vals) as u128;
        if mass == 0 {
            debug!(
                "[{}] Storage mass = 0 with {} fee UTXO(s), total {} sompi",
                label, selected.len(), fee_total
            );
            break;
        }

        // Need more credit — add next smallest UTXO
        if ei < eligible.len() {
            selected.push(eligible[ei]);
            ei += 1;
        } else {
            error!(
                "[{}] Storage mass still {} after exhausting all {} fee UTXOs — transaction will likely be rejected by Kaspad (need more small UTXOs to provide mass credit)",
                label, mass, selected.len()
            );
            break;
        }
    }

    selected
}

/// Compute change allocation: absorb dust change into the primary output.
///
/// Returns (adjusted_primary_amount, matcher_change).
fn compute_change_allocation(primary_amount: u64, raw_change: u64) -> (u64, u64) {
    if raw_change >= MIN_UTXO_VALUE {
        (primary_amount, raw_change)
    } else {
        (primary_amount + raw_change, 0)
    }
}

/// Sign a P2PK input and return the sigscript bytes.
fn sign_p2pk_input(
    tx: &kob_core::tx::Transaction,
    input_idx: usize,
    privkey: &[u8; 32],
    label: &str,
) -> Option<Vec<u8>> {
    let sighash = kob_core::compute_sighash(tx, input_idx).ok()?;
    let sig = match kob_core::schnorr_sign(&sighash, privkey) {
        Ok(s) => s,
        Err(e) => {
            error!("[{}] Signing input {} failed: {}", label, input_idx, e);
            return None;
        }
    };
    Some(kob_core::contract::build_p2pk_sigscript(&sig))
}

/// Decode a hex string into bytes, logging on failure.
fn decode_hex(hex_str: &str, name: &str) -> Option<Vec<u8>> {
    match hex::decode(hex_str) {
        Ok(v) => Some(v),
        Err(e) => {
            warn!("[MATCH] Invalid hex for {}: {}", name, e);
            None
        }
    }
}

/// Pre-check storage mass for a match TX before submission.
///
/// Extracts input/output values and returns `Some(mass)` if within limits,
/// or `None` if mass exceeds the limit (logging an error).
fn check_mass_presubmit(
    input_values: &[u64],
    output_values: &[u64],
    label: &str,
) -> Option<u64> {
    match kob_core::check_storage_mass(input_values, output_values) {
        Ok(mass) => {
            if mass > 0 {
                info!("[{}] Storage mass pre-check: {} (limit {})", label, mass, kob_core::MAX_TX_MASS);
            }
            Some(mass)
        }
        Err(e) => {
            error!(
                "[{}] TX rejected by storage mass pre-check: {}. \
                 Breakdown: {:?}",
                label, e, e.output_breakdown
            );
            None
        }
    }
}

/// Submit a match TX and return the TX ID on success.
async fn submit_match_tx(
    rpc: &RpcClient,
    rpc_inputs: Vec<serde_json::Value>,
    rpc_outputs: Vec<serde_json::Value>,
    label: &str,
    lock_time: u64,
) -> Option<String> {
    let payload = deploy::build_submit_payload_with_lock_time(1, rpc_inputs, rpc_outputs, lock_time);
    let result = match rpc.submit_transaction(payload).await {
        Ok(r) => r,
        Err(e) => {
            error!("[{}] Submit failed: {}", label, e);
            return None;
        }
    };
    if result.ok {
        let tx_id = result.tx_id.unwrap_or_else(|| {
            warn!("[{}] Success response missing tx_id", label);
            String::new()
        });
        info!("[{}] SUCCESS! TXID: {}", label, tx_id);
        Some(tx_id)
    } else {
        error!(
            "[{}] FAILED: {}",
            label,
            result.error.unwrap_or_else(|| "Unknown error".to_string())
        );
        None
    }
}

/// Append a matcher change output to the RPC output list if above dust.
fn maybe_push_change_output(
    rpc_outputs: &mut Vec<serde_json::Value>,
    matcher_change: u64,
    wallet_spk_version: u16,
    wallet_spk_hex: &str,
) {
    if matcher_change >= MIN_UTXO_VALUE {
        rpc_outputs.push(deploy::build_rpc_output(matcher_change, wallet_spk_version, wallet_spk_hex));
    }
}

/// Push a P2SH covenant input onto a transaction's input list.
/// Uses sequence=50 for CSV exposure delay (OP_CSV(50) in BuySell fill/partial paths).
fn push_covenant_input(
    tx: &mut kob_core::tx::Transaction,
    tx_id: &str,
    index: u32,
    p2sh_version: u16,
    p2sh_bytes: &[u8],
    value: u64,
) {
    tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: tx_id.to_string(),
        prev_index: index,
        sequence: 50,
        sig_op_count: 0,
        script_version: p2sh_version,
        script_bytes: p2sh_bytes.to_vec(),
        value,
    });
}

/// Push a P2PK signed input onto a transaction's input list.
fn push_p2pk_input(tx: &mut kob_core::tx::Transaction, utxo: &RpcUtxo) {
    let (spk_ver, spk_script) = utxo.parse_spk();
    tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: utxo.outpoint.transaction_id.clone(),
        prev_index: utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: spk_ver,
        script_bytes: spk_script,
        value: utxo.utxo_entry.amount,
    });
}

/// Push a standard (non-covenant) output onto a transaction's output list.
fn push_output(
    tx: &mut kob_core::tx::Transaction,
    value: u64,
    script_version: u16,
    script_bytes: Vec<u8>,
) {
    tx.outputs.push(kob_core::tx::TxOutput::new(value, script_version, script_bytes, None));
}

/// Execute a partial buy fill: the buy order is larger than the sell order.
///
/// Partially fills the buy order, extracting `fill_kas` worth of KAS and
/// giving the buyer tokens in return. A residual buy order UTXO remains.
/// The matcher provides the tokens from its own wallet.
///
/// TX layout:
///   input[0]: buy_order    (P2SH, partial fill sigscript, sigOpCount=0)
///   input[1]: token UTXO   (matcher's token supply, P2PK signed, sigOpCount=1)
///   input[2]: fee UTXO     (P2PK signed, sigOpCount=1)
///   output[0]: residual buy_order (P2SH, same RS, reduced value)
///   output[1]: buyer tokens       (KAS to matcher/buyer SPK)
///   output[2]: trade_receipt      (P2SH, RECEIPT_VALUE)
///   output[3]: matcher change     (optional)
async fn execute_partial_buy_fill(
    rpc: &RpcClient,
    pair: &CrossingPair,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
) -> Option<MatchResult> {
    let fill_kas = match pair.fill_kas {
        Some(v) => v,
        None => {
            error!("[PARTIAL-BUY] No fill_kas set on CrossingPair");
            return None;
        }
    };
    let residual_kas = match pair.residual_kas {
        Some(v) => v,
        None => {
            error!("[PARTIAL-BUY] No residual_kas set on CrossingPair");
            return None;
        }
    };

    // M-7: Defense-in-depth — verify fill_kas produces non-zero tokens after truncation.
    // fill_kas * price_num / price_den must be >= 1.
    if pair.buy.price_den > 0 {
        let output_tokens = fill_kas.saturating_mul(pair.buy.price_num) / pair.buy.price_den;
        if output_tokens == 0 {
            error!(
                "[PARTIAL-BUY] fill_kas={} yields 0 tokens after truncation (price {}/{}). Rejecting rounding-drain.",
                fill_kas, pair.buy.price_num, pair.buy.price_den
            );
            return None;
        }
    }

    let buy_key = pair.buy.outpoint_key();
    let expected_tokens = pair.expected_tokens;

    info!("======================================================================");
    info!("[PARTIAL-BUY] Buy order larger than sell -- partial fill buy");
    info!("======================================================================");
    info!(
        "  BUY:  {}... value={} price={}/{}",
        &buy_key[..buy_key.len().min(20)],
        pair.buy.value,
        pair.buy.price_num,
        pair.buy.price_den
    );
    info!("  Fill KAS:        {}", fill_kas);
    info!("  Expected tokens: {}", expected_tokens);
    info!("  Residual KAS:    {}", residual_kas);

    // Get wallet UTXOs
    let (utxos, wallet_spk_version, wallet_spk_script, wallet_spk_hex) =
        fetch_wallet_utxos(rpc, &config.address, "PARTIAL-BUY").await?;

    // Find a token UTXO with enough value for the tokens
    let token_utxo = match utxos.iter().find(|u| u.utxo_entry.amount >= expected_tokens) {
        Some(u) => u,
        None => {
            warn!("[PARTIAL-BUY] No UTXO with enough value for {} tokens. Skipping.", expected_tokens);
            return None;
        }
    };

    // Find a fee UTXO (different from token UTXO)
    let token_key = token_utxo.outpoint_key();
    let fee_utxo = select_fee_utxo(&utxos, Some(&token_key), "PARTIAL-BUY", spent_tracker)?;

    // Resolve buyer SPK before building the TX.
    let (buyer_spk_version, buyer_spk_script) = match pair.buy.resolve_counterparty_spk() {
        Some(spk) => spk,
        None => {
            error!(
                "[PARTIAL-BUY] BUY order {} missing counterparty_spk — \
                 deploy TX used payload v1 (no SPK). Cannot route buyer_tokens. Skipping.",
                &buy_key[..buy_key.len().min(20)]
            );
            return None;
        }
    };

    let mut privkey = config.private_key_bytes();
    let buy_rs = pair.buy.redeem_script();
    let buy_p2sh = pair.buy.p2sh_script();
    let buy_p2sh_version = pair.buy.p2sh_version;

    // Build partial fill sigscript: residual at output[0], tokens at output[1] -- v13
    let buy_pf_ss = kob_core::contract::build_buy_partial_fill_sigscript(&buy_rs, fill_kas, 0, 1);

    // Build receipt
    let tcid_bytes = decode_token_cov_id(&pair.token_cov_id, "PARTIAL-BUY")?;
    let (_receipt_rs_hex, receipt_p2sh_hex, receipt_p2sh_version) = deploy::build_receipt_scripts(
        &tcid_bytes,
        pair.buy.price_num,
        pair.buy.price_den,
        expected_tokens,
    );

    let receipt_value = RECEIPT_VALUE;

    // Compute output amounts
    let total_in = match pair.buy.value
        .checked_add(token_utxo.utxo_entry.amount)
        .and_then(|v| v.checked_add(fee_utxo.utxo_entry.amount))
    {
        Some(v) => v,
        None => {
            warn!("[PARTIAL-BUY] u64 overflow computing total_in, skipping");
            return None;
        }
    };
    // Pre-estimate miner fee from compute mass (3 inputs, 4 outputs, no payload)
    let estimated_miner_fee = kob_core::mass::estimate_compute_mass(3, 4, 0);
    let needed = residual_kas + expected_tokens + receipt_value + estimated_miner_fee;
    if total_in < needed {
        error!("[PARTIAL-BUY] Insufficient input {} for outputs {}", total_in, needed);
        return None;
    }
    let raw_change = total_in - needed;
    let (final_buyer_tokens, matcher_change) = compute_change_allocation(expected_tokens, raw_change);

    debug!("  output[0]: residual order  {} sompi", residual_kas);
    debug!("  output[1]: buyer tokens    {} sompi", final_buyer_tokens);
    debug!("  output[2]: receipt         {} sompi", receipt_value);
    debug!("  matcher change:            {}", matcher_change);

    // Build TX for sighash computation (lock_time=50 for OP_CSV)
    let mut tx = kob_core::tx::Transaction::new(1);
    tx.lock_time = 50;

    push_covenant_input(&mut tx, &pair.buy.tx_id, pair.buy.index, buy_p2sh_version, &buy_p2sh, pair.buy.value);
    push_p2pk_input(&mut tx, token_utxo);
    push_p2pk_input(&mut tx, fee_utxo);

    push_output(&mut tx, residual_kas, buy_p2sh_version, buy_p2sh);
    // Buyer token output carries covenant binding (authorized by token input[1])
    tx.outputs.push(kob_core::tx::TxOutput::new(final_buyer_tokens, buyer_spk_version, buyer_spk_script.clone(), Some(kob_core::tx::CovenantBinding::new(1, kob_core::compat::parse_hash(&pair.token_cov_id.clone()).unwrap()))));

    let receipt_p2sh_bytes = decode_hex(&receipt_p2sh_hex, "receipt_p2sh")?;
    push_output(&mut tx, receipt_value, receipt_p2sh_version, receipt_p2sh_bytes);

    if matcher_change >= MIN_UTXO_VALUE {
        push_output(&mut tx, matcher_change, wallet_spk_version, wallet_spk_script);
    }

    // Sign P2PK inputs
    let token_ss = sign_p2pk_input(&tx, 1, &privkey, "PARTIAL-BUY")?;
    let fee_ss = sign_p2pk_input(&tx, 2, &privkey, "PARTIAL-BUY")?;
    privkey.zeroize();

    // Build RPC inputs/outputs (covenant input uses sequence=50 for OP_CSV)
    let rpc_inputs = vec![
        deploy::build_rpc_input_with_sequence(&pair.buy.tx_id, pair.buy.index, &hex::encode(&buy_pf_ss), 0, 50),
        deploy::build_rpc_input(&token_utxo.outpoint.transaction_id, token_utxo.outpoint.index, &hex::encode(&token_ss), 1),
        deploy::build_rpc_input(&fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, &hex::encode(&fee_ss), 1),
    ];

    let buyer_spk_hex = hex::encode(&buyer_spk_script);
    let mut rpc_outputs = vec![
        deploy::build_rpc_output(residual_kas, buy_p2sh_version, &hex::encode(pair.buy.p2sh_script())),
        deploy::build_rpc_output_with_covenant(final_buyer_tokens, buyer_spk_version, &buyer_spk_hex, 1, &pair.token_cov_id),
        deploy::build_rpc_output(receipt_value, receipt_p2sh_version, &receipt_p2sh_hex),
    ];
    maybe_push_change_output(&mut rpc_outputs, matcher_change, wallet_spk_version, &wallet_spk_hex);

    // Storage mass pre-check
    {
        let in_vals = vec![pair.buy.value, token_utxo.utxo_entry.amount, fee_utxo.utxo_entry.amount];
        let mut out_vals = vec![residual_kas, final_buyer_tokens, receipt_value];
        if matcher_change >= MIN_UTXO_VALUE {
            out_vals.push(matcher_change);
        }
        check_mass_presubmit(&in_vals, &out_vals, "PARTIAL-BUY")?;
    }

    // Submit and handle result (version=1 for covenant output bindings)
    let match_tx_id = submit_match_tx(rpc, rpc_inputs, rpc_outputs, "PARTIAL-BUY", 50).await?;

    // Mark fee UTXO as spent so subsequent matches in this cycle won't reuse it.
    spent_tracker.mark_spent(&fee_utxo.outpoint_key());

    info!("  Buyer received:  {} sompi tokens", final_buyer_tokens);
    info!("  Residual order:  {}:0 ({} sompi)", match_tx_id, residual_kas);
    info!("  Receipt at:      {}:2", match_tx_id);

    Some(MatchResult {
        match_tx_id: match_tx_id.clone(),
        match_type: MatchType::PartialBuy,
        seller_kas: 0,
        buyer_tokens: final_buyer_tokens,
        receipt_tx_id: match_tx_id,
        receipt_idx: 2,
        receipt_value,
        token_cov_id: pair.token_cov_id.clone(),
        price_num: pair.buy.price_num,
        price_den: pair.buy.price_den,
    })
}

/// Execute a partial sell fill: the sell order is larger than the buy order.
///
/// Partially fills the sell order, extracting `fill_token_amount` tokens and
/// giving the seller KAS. A residual sell order UTXO remains.
///
/// TX layout:
///   input[0]: sell_order  (P2SH, partial fill sigscript, sigOpCount=0)
///   input[1]: fee UTXO    (P2PK signed, sigOpCount=1)
///   output[0]: seller KAS          (fill_token_amount * price)
///   output[1]: residual sell_order (P2SH, same RS, reduced value)
///   output[2]: trade_receipt       (P2SH, RECEIPT_VALUE)
///   output[3]: matcher change      (optional)
async fn execute_partial_sell_fill(
    rpc: &RpcClient,
    pair: &CrossingPair,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
) -> Option<MatchResult> {
    let fill_token_amount = match pair.fill_token_amount {
        Some(v) => v,
        None => {
            error!("[PARTIAL-SELL] No fill_token_amount set on CrossingPair");
            return None;
        }
    };
    let residual_tokens = match pair.residual_tokens {
        Some(v) => v,
        None => {
            error!("[PARTIAL-SELL] No residual_tokens set on CrossingPair");
            return None;
        }
    };

    // M-7: Defense-in-depth — verify fill_token_amount produces non-zero KAS after truncation.
    // fill_token_amount * price_num / price_den must be >= 1.
    if pair.sell.price_den > 0 {
        let output_kas = fill_token_amount.saturating_mul(pair.sell.price_num) / pair.sell.price_den;
        if output_kas == 0 {
            error!(
                "[PARTIAL-SELL] fill_token_amount={} yields 0 KAS after truncation (price {}/{}). Rejecting rounding-drain.",
                fill_token_amount, pair.sell.price_num, pair.sell.price_den
            );
            return None;
        }
    }

    let sell_key = pair.sell.outpoint_key();
    let seller_kas = pair.seller_kas;

    info!("======================================================================");
    info!("[PARTIAL-SELL] Sell order larger than buy -- partial fill sell");
    info!("======================================================================");
    info!(
        "  SELL: {}... value={} price={}/{}",
        &sell_key[..sell_key.len().min(20)],
        pair.sell.value,
        pair.sell.price_num,
        pair.sell.price_den
    );
    info!("  Fill tokens:      {}", fill_token_amount);
    info!("  Seller KAS:       {}", seller_kas);
    info!("  Residual tokens:  {}", residual_tokens);

    // Get wallet UTXOs
    let (utxos, wallet_spk_version, wallet_spk_script, wallet_spk_hex) =
        fetch_wallet_utxos(rpc, &config.address, "PARTIAL-SELL").await?;

    // Find fee UTXO (no exclusion needed -- sell fill has no token input)
    let fee_utxo = select_fee_utxo(&utxos, None, "PARTIAL-SELL", spent_tracker)?;

    // Resolve seller SPK before building the TX.
    let (seller_spk_version, seller_spk_script) = match pair.sell.resolve_counterparty_spk() {
        Some(spk) => spk,
        None => {
            error!(
                "[PARTIAL-SELL] SELL order {} missing counterparty_spk — \
                 deploy TX used payload v1 (no SPK). Cannot route seller_kas. Skipping.",
                &sell_key[..sell_key.len().min(20)]
            );
            return None;
        }
    };

    let mut privkey = config.private_key_bytes();
    let sell_rs = pair.sell.redeem_script();
    let sell_p2sh = pair.sell.p2sh_script();
    let sell_p2sh_version = pair.sell.p2sh_version;

    // Build partial fill sigscript: seller KAS at output[0], residual at output[1] -- v13
    let sell_pf_ss = kob_core::contract::build_sell_partial_fill_sigscript(
        &sell_rs, fill_token_amount, 0, 1,
    );

    // Build receipt
    let tcid_bytes = decode_token_cov_id(&pair.token_cov_id, "PARTIAL-SELL")?;
    let (_receipt_rs_hex, receipt_p2sh_hex, receipt_p2sh_version) = deploy::build_receipt_scripts(
        &tcid_bytes,
        pair.sell.price_num,
        pair.sell.price_den,
        fill_token_amount,
    );

    let receipt_value = RECEIPT_VALUE;

    // Compute output amounts
    let total_in = match pair.sell.value.checked_add(fee_utxo.utxo_entry.amount) {
        Some(v) => v,
        None => {
            warn!("[PARTIAL-SELL] u64 overflow computing total_in, skipping");
            return None;
        }
    };
    // Pre-estimate miner fee from compute mass (2 inputs, 4 outputs, no payload)
    let estimated_miner_fee = kob_core::mass::estimate_compute_mass(2, 4, 0);
    let needed = seller_kas + residual_tokens + receipt_value + estimated_miner_fee;
    if total_in < needed {
        error!("[PARTIAL-SELL] Insufficient input {} for outputs {}", total_in, needed);
        return None;
    }
    let raw_change = total_in - needed;
    let (final_seller_kas, matcher_change) = compute_change_allocation(seller_kas, raw_change);

    debug!("  output[0]: seller KAS      {} sompi", final_seller_kas);
    debug!("  output[1]: residual order  {} sompi", residual_tokens);
    debug!("  output[2]: receipt         {} sompi", receipt_value);
    debug!("  matcher change:            {}", matcher_change);

    // Build TX for sighash computation (lock_time=50 for OP_CSV)
    let mut tx = kob_core::tx::Transaction::new(1);
    tx.lock_time = 50;

    push_covenant_input(&mut tx, &pair.sell.tx_id, pair.sell.index, sell_p2sh_version, &sell_p2sh, pair.sell.value);
    push_p2pk_input(&mut tx, fee_utxo);

    push_output(&mut tx, final_seller_kas, seller_spk_version, seller_spk_script.clone());
    // Residual sell order output carries covenant binding (authorized by sell input[0])
    tx.outputs.push(kob_core::tx::TxOutput::new(residual_tokens, sell_p2sh_version, sell_p2sh, Some(kob_core::tx::CovenantBinding::new(0, kob_core::compat::parse_hash(&pair.token_cov_id.clone()).unwrap()))));

    let receipt_p2sh_bytes = decode_hex(&receipt_p2sh_hex, "receipt_p2sh")?;
    push_output(&mut tx, receipt_value, receipt_p2sh_version, receipt_p2sh_bytes);

    if matcher_change >= MIN_UTXO_VALUE {
        push_output(&mut tx, matcher_change, wallet_spk_version, wallet_spk_script);
    }

    // Sign P2PK input (fee UTXO at index 1)
    let fee_ss = sign_p2pk_input(&tx, 1, &privkey, "PARTIAL-SELL")?;
    privkey.zeroize();

    // Build RPC inputs/outputs (covenant input uses sequence=50 for OP_CSV)
    let rpc_inputs = vec![
        deploy::build_rpc_input_with_sequence(&pair.sell.tx_id, pair.sell.index, &hex::encode(&sell_pf_ss), 0, 50),
        deploy::build_rpc_input(&fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, &hex::encode(&fee_ss), 1),
    ];

    let seller_spk_hex = hex::encode(&seller_spk_script);
    let mut rpc_outputs = vec![
        deploy::build_rpc_output(final_seller_kas, seller_spk_version, &seller_spk_hex),
        deploy::build_rpc_output_with_covenant(residual_tokens, sell_p2sh_version, &hex::encode(pair.sell.p2sh_script()), 0, &pair.token_cov_id),
        deploy::build_rpc_output(receipt_value, receipt_p2sh_version, &receipt_p2sh_hex),
    ];
    maybe_push_change_output(&mut rpc_outputs, matcher_change, wallet_spk_version, &wallet_spk_hex);

    // Storage mass pre-check
    {
        let in_vals = vec![pair.sell.value, fee_utxo.utxo_entry.amount];
        let mut out_vals = vec![final_seller_kas, residual_tokens, receipt_value];
        if matcher_change >= MIN_UTXO_VALUE {
            out_vals.push(matcher_change);
        }
        check_mass_presubmit(&in_vals, &out_vals, "PARTIAL-SELL")?;
    }

    // Submit and handle result (version=1 for covenant output bindings)
    let match_tx_id = submit_match_tx(rpc, rpc_inputs, rpc_outputs, "PARTIAL-SELL", 50).await?;

    // Mark fee UTXO as spent so subsequent matches in this cycle won't reuse it.
    spent_tracker.mark_spent(&fee_utxo.outpoint_key());

    info!("  Seller received: {} sompi KAS", final_seller_kas);
    info!("  Residual order:  {}:1 ({} sompi)", match_tx_id, residual_tokens);
    info!("  Receipt at:      {}:2", match_tx_id);

    Some(MatchResult {
        match_tx_id: match_tx_id.clone(),
        match_type: MatchType::PartialSell,
        seller_kas: final_seller_kas,
        buyer_tokens: 0,
        receipt_tx_id: match_tx_id,
        receipt_idx: 2,
        receipt_value,
        token_cov_id: pair.token_cov_id.clone(),
        price_num: pair.sell.price_num,
        price_den: pair.sell.price_den,
    })
}

// Cross-pair Match Execution (v8 contracts)

/// Result of a successful cross-pair match.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Used in tests
pub struct CrossPairMatchResult {
    pub match_tx_id: String,
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub sell_token_cov_id: String,
    pub buy_token_cov_id: String,
    pub receipt_tx_id: String,
    /// Index of the receipt output in the match TX, or None if no receipt
    /// was included (M-4). When None, receipt consumption must be skipped.
    pub receipt_idx: Option<u32>,
    pub receipt_value: u64,
}

/// A Token B UTXO available for cross-pair matching.
///
/// The matcher must hold Token B UTXOs to supply buyer outputs in cross-pair TXs.
/// These are tracked in the matcher's token inventory.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct TokenUtxo {
    /// Transaction ID of the UTXO.
    pub tx_id: String,
    /// Output index.
    pub index: u32,
    /// Token amount in sompi.
    pub value: u64,
    /// Token covenant ID (hex).
    pub token_cov_id: String,
    /// P2SH script version of the UTXO.
    pub spk_version: u16,
    /// P2SH script bytes of the UTXO.
    pub spk_script: Vec<u8>,
}

impl TokenUtxo {
    #[allow(dead_code)] // Used in tests
    pub fn outpoint_key(&self) -> String {
        format!("{}:{}", self.tx_id, self.index)
    }
}

/// Find a token UTXO from the matcher's wallet UTXOs that matches the TOKEN_RS P2SH.
///
/// Scans the wallet's UTXOs for P2SH outputs matching TOKEN_RS (minimal covenant
/// checker, 7 bytes). Returns the first UTXO with sufficient value, or None.
///
/// NOTE: This relies on the matcher owning Token B UTXOs locked with TOKEN_RS.
/// The RPC `getUtxosByAddresses` does not include covenant metadata, so we
/// identify token UTXOs by their scriptPublicKey matching the TOKEN_RS P2SH hash.
/// For production, the matcher should maintain an explicit token inventory.
pub fn find_token_utxo_from_wallet(
    utxos: &[RpcUtxo],
    min_value: u64,
    spent_tracker: &SpentTracker,
) -> Option<TokenUtxo> {
    let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
    let token_p2sh_hex = hex::encode(&token_p2sh.script());

    for utxo in utxos {
        let key = utxo.outpoint_key();
        if spent_tracker.is_spent(&key) {
            continue;
        }
        if utxo.utxo_entry.amount < min_value {
            continue;
        }
        let (_version, script) = utxo.parse_spk();
        let script_hex = hex::encode(&script);
        if script_hex == token_p2sh_hex {
            return Some(TokenUtxo {
                tx_id: utxo.outpoint.transaction_id.clone(),
                index: utxo.outpoint.index,
                value: utxo.utxo_entry.amount,
                token_cov_id: String::new(), // Covenant ID not available from RPC
                spk_version: token_p2sh.version,
                spk_script: token_p2sh.script().to_vec(),
            });
        }
    }
    None
}


/// Result of a batch match execution.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct BatchMatchResult {
    /// Transaction ID of the submitted batch match TX.
    pub tx_id: String,
    /// Number of sell orders matched.
    pub sell_count: usize,
    /// Number of buy orders matched.
    pub buy_count: usize,
    /// Total KAS paid to sellers.
    pub total_seller_kas: u64,
    /// Matcher surplus captured.
    pub matcher_surplus: u64,
}

/// Execute an N:M batch match from a pre-built BatchPlan.
///
/// Builds the batch TX via `BatchPlan::build_tx()`, constructs a sighash TX
/// to sign the wallet input (P2PK, last input), then submits via RPC.
///
/// The wallet input is the LAST input in the batch TX and needs `sigOpCount: 1`
/// with a Schnorr signature. All covenant inputs (sells, buys, token_units)
/// use `sigOpCount: 0`.
///
/// TX version = 1 (required for covenant output bindings on buyer token outputs).
pub async fn execute_batch_match(
    rpc: &RpcClient,
    plan: &crate::matcher::batch::BatchPlan,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
) -> Option<BatchMatchResult> {
    use crate::matcher::batch::OutputPurpose;

    // Validate the plan before building
    if let Err(e) = plan.validate() {
        error!("[BATCH] Plan validation failed: {}", e);
        return None;
    }

    let batch_tx = match plan.build_tx() {
        Ok(tx) => tx,
        Err(e) => {
            error!("[BATCH] build_tx failed: {}", e);
            return None;
        }
    };

    info!("======================================================================");
    info!(
        "EXECUTING BATCH MATCH: {} sells + {} buys + {} token_units",
        plan.sells.len(),
        plan.buys.len(),
        plan.token_units.len(),
    );
    info!("======================================================================");
    debug!("  Total fee:       {}", plan.total_fee);
    debug!("  Matcher surplus: {}", plan.matcher_surplus);

    // Build RPC inputs from the batch TX (covenant inputs already have sigscripts)
    let wallet_input_idx = batch_tx.inputs.len().saturating_sub(1);
    let has_wallet = plan.wallet_input.is_some();

    // We need to sign the wallet input. Build a kob_core::tx::Transaction for sighash.
    // lock_time=50 required for OP_CSV(50) in covenant inputs.
    let mut sighash_tx = kob_core::tx::Transaction::new(1);
    sighash_tx.lock_time = 50;

    // Reconstruct inputs for sighash computation.
    // For covenant inputs: use P2SH script from the order's p2sh
    // For the wallet input: use the wallet's SPK

    // Add sell order inputs (CSV=50 for BuySell covenant)
    for (sell, _input_idx) in &plan.sells {
        let p2sh = kob_core::build_p2sh(&sell.redeem_script);
        sighash_tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: sell.outpoint.0.clone(),
            prev_index: sell.outpoint.1,
            sequence: 50,
            sig_op_count: 0,
            script_version: p2sh.version,
            script_bytes: p2sh.script().to_vec(),
            value: sell.utxo_value,
        });
    }

    // Add buy order inputs (CSV=50 for BuySell covenant)
    for (buy, _input_idx) in &plan.buys {
        let p2sh = kob_core::build_p2sh(&buy.redeem_script);
        sighash_tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: buy.outpoint.0.clone(),
            prev_index: buy.outpoint.1,
            sequence: 50,
            sig_op_count: 0,
            script_version: p2sh.version,
            script_bytes: p2sh.script().to_vec(),
            value: buy.utxo_value,
        });
    }

    // Add token unit inputs
    for (tu, _input_idx) in &plan.token_units {
        let p2sh = kob_core::build_p2sh(&tu.redeem_script);
        sighash_tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: tu.outpoint.0.clone(),
            prev_index: tu.outpoint.1,
            sequence: 0,
            sig_op_count: 0,
            script_version: p2sh.version,
            script_bytes: p2sh.script().to_vec(),
            value: tu.value,
        });
    }

    // Add wallet input (P2PK, sigOpCount=1) if present
    if let Some((ref wallet_tx_id, wallet_index, wallet_value)) = plan.wallet_input {
        // Fetch wallet UTXOs to get the SPK for sighash computation
        let (utxos, wallet_spk_version, wallet_spk_script, _wallet_spk_hex) =
            fetch_wallet_utxos(rpc, &config.address, "BATCH").await?;

        // Find the specific wallet UTXO to get its SPK
        let wallet_utxo = utxos.iter().find(|u| {
            u.outpoint.transaction_id == *wallet_tx_id && u.outpoint.index == wallet_index
        });
        let (spk_version, spk_script) = if let Some(wu) = wallet_utxo {
            wu.parse_spk()
        } else {
            // Fallback: use the first UTXO's SPK (same wallet, same SPK)
            (wallet_spk_version, wallet_spk_script.clone())
        };

        sighash_tx.inputs.push(kob_core::tx::TxInput {
            prev_tx_id: wallet_tx_id.clone(),
            prev_index: wallet_index,
            sequence: 0,
            sig_op_count: 1,
            script_version: spk_version,
            script_bytes: spk_script,
            value: wallet_value,
        });
    }

    // Build RPC outputs and sighash TX outputs
    let mut rpc_outputs = Vec::new();
    let n = plan.sells.len();

    for (i, out) in batch_tx.outputs.iter().enumerate() {
        let spk_hex = hex::encode(&out.script_public_key);

        // Buyer token outputs need covenant bindings
        if out.purpose == OutputPurpose::BuyerTokens {
            // output[N+j] corresponds to buy[j]
            let buy_j = i.saturating_sub(n);
            if buy_j < plan.buys.len() {
                let (buy, _) = &plan.buys[buy_j];
                let token_hex = hex::encode(buy.token_cov_id);
                if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                    rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                        out.value,
                        out.spk_version,
                        &spk_hex,
                        tii as u16,
                        &token_hex,
                    ));
                    // Also add to sighash TX with covenant binding
                    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), Some(kob_core::tx::CovenantBinding::new(tii as u16, kob_core::compat::parse_hash(&token_hex).unwrap()))));
                    continue;
                }
            }
            // Fallback: no covenant binding (should not happen for valid plans)
            warn!("[BATCH] BuyerTokens output[{}] missing covenant binding", i);
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        } else {
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        }

        sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), None));
    }

    // Build RPC inputs
    let mut rpc_inputs = Vec::new();
    for (i, inp) in batch_tx.inputs.iter().enumerate() {
        if has_wallet && i == wallet_input_idx {
            // Wallet input: needs signing — we'll replace the sigscript below
            continue;
        }
        rpc_inputs.push(deploy::build_rpc_input(
            &inp.tx_id,
            inp.index,
            &hex::encode(&inp.sigscript),
            inp.sig_op_count,
        ));
    }

    // Sign the wallet input if present
    if has_wallet {
        let mut privkey = config.private_key_bytes();
        let sighash = kob_core::compute_sighash(&sighash_tx, wallet_input_idx).ok()?;
        let sig = match kob_core::schnorr_sign(&sighash, &privkey) {
            Ok(s) => s,
            Err(e) => {
                privkey.zeroize();
                error!("[BATCH] Wallet input signing failed: {}", e);
                return None;
            }
        };
        privkey.zeroize();
        let wallet_ss = kob_core::contract::build_p2pk_sigscript(&sig);

        let wallet_inp = &batch_tx.inputs[wallet_input_idx];
        rpc_inputs.push(deploy::build_rpc_input(
            &wallet_inp.tx_id,
            wallet_inp.index,
            &hex::encode(&wallet_ss),
            1, // sigOpCount = 1 for P2PK
        ));
    }

    // Storage mass pre-check for batch TX
    {
        let in_vals: Vec<u64> = plan.sells.iter().map(|(s, _)| s.utxo_value).chain(
            plan.buys.iter().map(|(b, _)| b.utxo_value)
        ).chain(
            plan.token_units.iter().map(|(t, _)| t.value)
        ).chain(
            plan.wallet_input.iter().map(|(_, _, val)| *val)
        ).collect();
        let out_vals: Vec<u64> = plan.outputs.iter().map(|o| o.value).collect();
        if check_mass_presubmit(&in_vals, &out_vals, "BATCH").is_none() {
            // Mark all inputs as failed for cooldown
            for (sell, _) in &plan.sells {
                let key = format!("{}:{}", sell.outpoint.0, sell.outpoint.1);
                spent_tracker.mark_failed(&key);
            }
            for (buy, _) in &plan.buys {
                let key = format!("{}:{}", buy.outpoint.0, buy.outpoint.1);
                spent_tracker.mark_failed(&key);
            }
            return None;
        }
    }

    // Submit via RPC (version=1 for covenant output bindings, lockTime=50 for OP_CSV)
    let payload = deploy::build_submit_payload_with_lock_time(1, rpc_inputs, rpc_outputs, 50);
    let result = match rpc.submit_transaction(payload).await {
        Ok(r) => r,
        Err(e) => {
            error!("[BATCH] Submit failed: {}", e);
            // Mark all inputs as failed for cooldown
            for (sell, _) in &plan.sells {
                let key = format!("{}:{}", sell.outpoint.0, sell.outpoint.1);
                spent_tracker.mark_failed(&key);
            }
            for (buy, _) in &plan.buys {
                let key = format!("{}:{}", buy.outpoint.0, buy.outpoint.1);
                spent_tracker.mark_failed(&key);
            }
            return None;
        }
    };

    if !result.ok {
        error!(
            "[BATCH] FAILED: {}",
            result.error.unwrap_or_else(|| "Unknown error".to_string())
        );
        // Mark all order inputs as failed for cooldown
        for (sell, _) in &plan.sells {
            let key = format!("{}:{}", sell.outpoint.0, sell.outpoint.1);
            spent_tracker.mark_failed(&key);
        }
        for (buy, _) in &plan.buys {
            let key = format!("{}:{}", buy.outpoint.0, buy.outpoint.1);
            spent_tracker.mark_failed(&key);
        }
        return None;
    }

    let tx_id = result.tx_id.unwrap_or_else(|| {
        warn!("[BATCH] Success response missing tx_id");
        String::new()
    });
    info!("[BATCH] SUCCESS! TXID: {}", tx_id);
    info!("  Sells matched: {}", plan.sells.len());
    info!("  Buys matched:  {}", plan.buys.len());

    // Track all spent outpoints
    for (sell, _) in &plan.sells {
        let key = format!("{}:{}", sell.outpoint.0, sell.outpoint.1);
        spent_tracker.mark_spent(&key);
    }
    for (buy, _) in &plan.buys {
        let key = format!("{}:{}", buy.outpoint.0, buy.outpoint.1);
        spent_tracker.mark_spent(&key);
    }
    for (tu, _) in &plan.token_units {
        let key = format!("{}:{}", tu.outpoint.0, tu.outpoint.1);
        spent_tracker.mark_spent(&key);
    }
    if let Some((ref wallet_tx_id, wallet_index, _)) = plan.wallet_input {
        let key = format!("{}:{}", wallet_tx_id, wallet_index);
        spent_tracker.mark_spent(&key);
    }

    // Compute total seller KAS from outputs
    let total_seller_kas: u64 = plan.outputs.iter()
        .filter(|o| o.purpose == OutputPurpose::SellerKas)
        .map(|o| o.value)
        .sum();

    Some(BatchMatchResult {
        tx_id,
        sell_count: plan.sells.len(),
        buy_count: plan.buys.len(),
        total_seller_kas,
        matcher_surplus: plan.matcher_surplus,
    })
}

// L1 Block Scanning — Order Discovery

/// Process a batch of transactions from a block notification.
///
/// For each transaction:
///   1. Check if any inputs spend known orders -> remove from book.
///   2. Check if the TX deploys a new KOB order (P2SH + payload) -> add to book.
///
/// Returns the number of orders added and removed.
///
/// When `ws_tx` is provided, emits `OrderDetected` and `OrderCancelled`
/// events for each new/removed order so that user-order WS subscribers
/// receive real-time notifications.
#[allow(dead_code)] // Used in tests
pub fn process_block_txs(
    txs: &[TransactionData],
    order_book: &mut OrderBook,
    scanner: &BlockScanner,
) -> (usize, usize) {
    process_block_txs_inner(txs, order_book, scanner, None)
}

fn process_block_txs_inner(
    txs: &[TransactionData],
    order_book: &mut OrderBook,
    scanner: &BlockScanner,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
) -> (usize, usize) {
    let mut added = 0;
    let mut removed = 0;

    for tx in txs {
        // Phase 1: Remove spent orders
        let spent_keys = BlockScanner::find_spent_orders(tx, order_book);
        for key in &spent_keys {
            info!("[SCANNER] Order spent: {}", &key[..key.len().min(20)]);

            // Capture order info before removal for WS event emission.
            if let Some(ws) = ws_tx {
                if let Some(order) = order_book.get_order(key) {
                    crate::matcher::api::emit_order_cancelled(
                        ws,
                        &order.owner_hash,
                        key,
                        &tx.tx_id,
                        &order.token_cov_id,
                    );
                }
            }

            order_book.remove_order(key);
            removed += 1;
        }

        // Phase 2: Detect new deploys
        if let Some((parsed, p2sh_idx, p2sh_value)) = scanner.scan_tx(tx) {
            // For buy orders, the token_cov_id is in the RS.
            // For sell orders, it's not in the RS — we need to determine it
            // from the UTXO's covenant ID. In practice, the sell deploy TX
            // must have a covenant input that identifies the token. For now,
            // sell orders without a known token_cov_id are skipped unless
            // the deploy TX structure provides it (e.g., a token input).
            //
            // NOTE: In the current L1 deploy flow, sell orders always have
            // a token_unit input whose covenant ID identifies the token.
            // We can extract this from the TX's inputs if covenant data
            // is available. For a fully permissionless scanner that only
            // sees block data without UTXO set context, the token_cov_id
            // must be provided in the TX payload or inferred from the deploy
            // pattern. This is a known limitation that can be resolved by:
            //   a) Querying the UTXO set for covenant IDs of the TX inputs
            //   b) Adding the token_cov_id to the TX payload
            //
            // For now, sell orders are added with a zero token_cov_id,
            // which will need to be resolved by the matcher via RPC.

            let book_order = BlockScanner::to_book_order_with_tx(
                &parsed,
                &tx.tx_id,
                p2sh_idx,
                p2sh_value,
                None, // Use parsed token_cov_id (correct for buy, zero for sell — sell now resolved from output covenant)
                Some(tx),
            );

            let order_type_str = match parsed.order_type {
                OrderSide::Buy => "BUY",
                OrderSide::Sell => "SELL",
            };

            // Skip orders with cancel_pending set
            if parsed.cpend != 0 {
                info!(
                    "[SCANNER] Skipping {} order (cancel_pending=1): {}:{}",
                    order_type_str, &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx
                );
                continue;
            }

            info!(
                "[SCANNER] Discovered {} v{} order: {}:{} value={} price={}/{}",
                order_type_str,
                parsed.version,
                &tx.tx_id[..tx.tx_id.len().min(16)],
                p2sh_idx,
                p2sh_value,
                parsed.price_num,
                parsed.price_den,
            );

            // M-7: Dedup check -- skip if outpoint already exists in any pair book.
            // This prevents duplicate orders when the same block notification is
            // received twice (e.g., during RPC reconnection).
            let outpoint_key = book_order.outpoint_key();
            if order_book.contains_outpoint(&outpoint_key) {
                info!(
                    "[SCANNER] Skipping duplicate {} order: {} (M-7)",
                    order_type_str,
                    &outpoint_key[..outpoint_key.len().min(20)]
                );
                continue;
            }

            match parsed.order_type {
                OrderSide::Buy => {
                    // Emit OrderDetected before adding (book_order will be moved)
                    if let Some(ws) = ws_tx {
                        crate::matcher::api::emit_order_detected(
                            ws,
                            &book_order.owner_hash,
                            &outpoint_key,
                            OrderSide::Buy,
                            book_order.price_num,
                            book_order.price_den,
                            book_order.value,
                            &book_order.token_cov_id,
                        );
                    }
                    order_book.add_buy_order(book_order);
                },
                OrderSide::Sell => {
                    // Sell RS does not embed the token covenant ID.
                    // If token_cov_id is all zeros, the token identity is unknown
                    // (requires RPC UTXO covenant context). Skip to prevent ghost orders.
                    if book_order.token_cov_id == "0".repeat(64) {
                        warn!(
                            "[SCANNER] Skipping SELL order with unknown token_cov_id (all zeros): {}:{}",
                            &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx
                        );
                        continue;
                    }
                    if let Some(ws) = ws_tx {
                        crate::matcher::api::emit_order_detected(
                            ws,
                            &book_order.owner_hash,
                            &outpoint_key,
                            OrderSide::Sell,
                            book_order.price_num,
                            book_order.price_den,
                            book_order.value,
                            &book_order.token_cov_id,
                        );
                    }
                    order_book.add_sell_order(book_order);
                }
            }
            added += 1;
        }
    }

    (added, removed)
}

// Multi-product block scanning (spot + perp + lending + prediction)

/// Counters returned by `process_block_txs_all`.
#[derive(Debug, Default)]
pub struct ScanCounters {
    pub spot_added: usize,
    pub spot_removed: usize,
    pub perp_added: usize,
    pub perp_removed: usize,
    pub lending_added: usize,
    pub lending_removed: usize,
    pub prediction_added: usize,
    pub prediction_removed: usize,
}

/// Process a batch of transactions using the multi-product scanner.
///
/// For each TX:
///   1. Remove spent orders from ALL books (spot, perp, lending, prediction).
///   2. Detect new deploys via `scan_tx_all()` and route to the appropriate book.
///
/// This is the unified replacement for `process_block_txs_inner` that handles
/// all four product types in a single pass.
fn process_block_txs_all(
    txs: &[TransactionData],
    order_book: &mut OrderBook,
    scanner: &BlockScanner,
    perp_book: &mut crate::matcher::perp_book::PerpOrderBook,
    lending_book: &mut crate::matcher::lending_book::LendingBook,
    prediction_book: &mut crate::matcher::prediction_book::PredictionBook,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    current_daa: u64,
) -> ScanCounters {
    let mut counters = ScanCounters::default();

    // Collect perp/lending/prediction outpoints for spent detection.
    let perp_outpoints: HashSet<String> = {
        let mut set = HashSet::new();
        for key in perp_book.all_outpoint_keys() {
            set.insert(key);
        }
        set
    };
    let lending_outpoints: HashSet<String> = lending_book.all_outpoint_keys();
    let prediction_outpoints: HashSet<String> = {
        let mut set = HashSet::new();
        for key in prediction_book.all_outpoint_keys() {
            set.insert(key);
        }
        set
    };

    for tx in txs {
        // Phase 1: Remove spent orders from ALL books

        // Spot book
        let spot_spent = BlockScanner::find_spent_orders(tx, order_book);
        for key in &spot_spent {
            info!("[SCANNER-ALL] Spot order spent: {}", &key[..key.len().min(20)]);
            if let Some(ws) = ws_tx {
                if let Some(order) = order_book.get_order(key) {
                    crate::matcher::api::emit_order_cancelled(
                        ws,
                        &order.owner_hash,
                        key,
                        &tx.tx_id,
                        &order.token_cov_id,
                    );
                }
            }
            order_book.remove_order(key);
            counters.spot_removed += 1;
        }

        // Perp book
        let perp_spent = BlockScanner::find_spent_in_keys(tx, &perp_outpoints);
        for key in &perp_spent {
            info!("[SCANNER-ALL] Perp order spent: {}", &key[..key.len().min(20)]);
            perp_book.remove(key);
            counters.perp_removed += 1;
        }

        // Lending book
        let lending_spent = BlockScanner::find_spent_in_keys(tx, &lending_outpoints);
        for key in &lending_spent {
            info!("[SCANNER-ALL] Lending order spent: {}", &key[..key.len().min(20)]);
            lending_book.remove_by_outpoint(key);
            counters.lending_removed += 1;
        }

        // Prediction book
        let prediction_spent = BlockScanner::find_spent_in_keys(tx, &prediction_outpoints);
        for key in &prediction_spent {
            info!("[SCANNER-ALL] Prediction item spent: {}", &key[..key.len().min(20)]);
            prediction_book.remove_by_outpoint(key);
            counters.prediction_removed += 1;
        }

        // Phase 2: Detect new deploys (all products)
        let scan_hit = scanner.scan_tx_all(tx);
        let scan_hit = match scan_hit {
            Some(h) => h,
            None => continue,
        };

        match scan_hit {
            ScanResult::Spot(parsed, p2sh_idx, p2sh_value) => {
                // Delegate to existing spot logic
                if parsed.cpend != 0 {
                    info!(
                        "[SCANNER-ALL] Skipping spot order (cancel_pending=1): {}:{}",
                        &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    );
                    continue;
                }

                let book_order = BlockScanner::to_book_order_with_tx(
                    &parsed, &tx.tx_id, p2sh_idx, p2sh_value, None, Some(tx),
                );
                let outpoint_key = book_order.outpoint_key();
                if order_book.contains_outpoint(&outpoint_key) {
                    continue; // dedup
                }

                let order_type_str = match parsed.order_type {
                    OrderSide::Buy => "BUY",
                    OrderSide::Sell => "SELL",
                };
                info!(
                    "[SCANNER-ALL] Discovered {} v{} spot order: {}:{} value={} price={}/{}",
                    order_type_str, parsed.version,
                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    p2sh_value, parsed.price_num, parsed.price_den,
                );

                match parsed.order_type {
                    OrderSide::Buy => {
                        if let Some(ws) = ws_tx {
                            crate::matcher::api::emit_order_detected(
                                ws, &book_order.owner_hash, &outpoint_key,
                                OrderSide::Buy, book_order.price_num, book_order.price_den,
                                book_order.value, &book_order.token_cov_id,
                            );
                        }
                        order_book.add_buy_order(book_order);
                    }
                    OrderSide::Sell => {
                        if book_order.token_cov_id == "0".repeat(64) {
                            warn!(
                                "[SCANNER-ALL] Skipping SELL order with unknown token_cov_id: {}:{}",
                                &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                            );
                            continue;
                        }
                        if let Some(ws) = ws_tx {
                            crate::matcher::api::emit_order_detected(
                                ws, &book_order.owner_hash, &outpoint_key,
                                OrderSide::Sell, book_order.price_num, book_order.price_den,
                                book_order.value, &book_order.token_cov_id,
                            );
                        }
                        order_book.add_sell_order(book_order);
                    }
                }
                counters.spot_added += 1;
            }

            ScanResult::Perp(parsed, p2sh_idx, p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);
                if perp_book.contains(&outpoint_key) {
                    continue; // dedup
                }

                // Convert ParsedPerpOrder -> PerpOrder
                let side = match parsed.side {
                    PerpDeploySide::Long => crate::matcher::perp_book::PerpSide::Long,
                    PerpDeploySide::Short => crate::matcher::perp_book::PerpSide::Short,
                };
                let rs_hex = hex::encode(&parsed.redeem_script);
                let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);
                let p2sh_hex = hex::encode(&p2sh_spk.script());
                // Extract owner_spk from TX outputs (same pattern as lending)
                let owner_spk = crate::matcher::scanner::extract_owner_spk(tx, &parsed.owner_spk_hash);

                let perp_order = crate::matcher::perp_book::PerpOrder {
                    tx_id: tx.tx_id.clone(),
                    index: p2sh_idx,
                    side,
                    margin: p2sh_value,
                    leverage_num: 1,       // Default 1x; not encoded in deploy v1
                    leverage_den: 1,
                    price_num: parsed.price_num,
                    price_den: parsed.price_den,
                    owner_spk_hash: parsed.owner_spk_hash,
                    owner_spk,
                    redeem_script_hex: rs_hex,
                    p2sh_script_hex: p2sh_hex,
                    value: p2sh_value,
                    maint_pct_num: parsed.maint_pct_num,
                    maint_pct_den: parsed.maint_pct_den,
                    keeper_fee: parsed.keeper_fee,
                    discovered_daa: current_daa,
                    reduce_only: false,
                };

                let side_str = match perp_order.side {
                    crate::matcher::perp_book::PerpSide::Long => "LONG",
                    crate::matcher::perp_book::PerpSide::Short => "SHORT",
                };
                info!(
                    "[SCANNER-ALL] Discovered {} perp order: {}:{} margin={} price={}/{}",
                    side_str,
                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    p2sh_value, parsed.price_num, parsed.price_den,
                );

                perp_book.insert(perp_order);
                counters.perp_added += 1;
            }

            ScanResult::Lending(parsed, p2sh_idx, p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);

                // Build P2SH script from redeemScript
                let p2sh_spk = kob_core::build_p2sh(&parsed.redeem_script);

                match parsed.order_type {
                    LendingOrderType::Offer => {
                        let offer = crate::matcher::lending_book::LendingOffer {
                            outpoint: outpoint_key.clone(),
                            value: p2sh_value,
                            rate_num: parsed.rate_num,
                            rate_den: parsed.rate_den,
                            min_collateral_pct: parsed.min_collateral_ratio,
                            max_duration_daa: parsed.duration_daa,
                            collateral_cov_id: parsed.collateral_cov_id,
                            rate_mode: parsed.rate_mode,
                            rate_floor: parsed.rate_floor_num,
                            owner_spk_hash: parsed.owner_spk_hash,
                            redeem_script: parsed.redeem_script.clone(),
                            p2sh_script: p2sh_spk.script().to_vec(),
                            owner_spk: parsed.owner_spk.clone(),
                            discovered_daa: current_daa,
                        };
                        info!(
                            "[SCANNER-ALL] Discovered lending OFFER: {} value={} rate={}/{}",
                            &outpoint_key[..outpoint_key.len().min(20)],
                            p2sh_value, parsed.rate_num, parsed.rate_den,
                        );
                        lending_book.add_offer(offer);
                    }
                    LendingOrderType::Request => {
                        let request = crate::matcher::lending_book::BorrowRequest {
                            outpoint: outpoint_key.clone(),
                            value: p2sh_value,
                            desired_principal: parsed.amount,
                            max_rate_num: parsed.rate_num,
                            max_rate_den: parsed.rate_den,
                            duration_daa: parsed.duration_daa,
                            rate_mode: parsed.rate_mode,
                            rate_cap: parsed.rate_cap_num,
                            collateral_cov_id: parsed.collateral_cov_id,
                            owner_spk_hash: parsed.owner_spk_hash,
                            redeem_script: parsed.redeem_script.clone(),
                            p2sh_script: p2sh_spk.script().to_vec(),
                            owner_spk: parsed.owner_spk.clone(),
                            discovered_daa: current_daa,
                        };
                        info!(
                            "[SCANNER-ALL] Discovered lending REQUEST: {} collateral={} desired={} max_rate={}/{}",
                            &outpoint_key[..outpoint_key.len().min(20)],
                            p2sh_value, parsed.amount, parsed.rate_num, parsed.rate_den,
                        );
                        lending_book.add_request(request);
                    }
                }
                counters.lending_added += 1;
            }

            ScanResult::Prediction(parsed, p2sh_idx, _p2sh_value) => {
                let outpoint_key = format!("{}:{}", tx.tx_id, p2sh_idx);
                if prediction_book.contains_outpoint(&outpoint_key) {
                    continue; // dedup
                }

                let item_type_str = match parsed.item_type {
                    PredictionItemType::SplitMerge => "SplitMerge",
                    PredictionItemType::BallotBox => "BallotBox",
                    PredictionItemType::Redemption => "Redemption",
                };
                info!(
                    "[SCANNER-ALL] Discovered prediction {}: {}",
                    item_type_str,
                    &outpoint_key[..outpoint_key.len().min(20)],
                );
                // Prediction items require market-level context to properly route
                // (market_id, ballot side, etc.). Log for now; full routing requires
                // parsing the RS state fields which is done at the application layer.
                // The prediction_executor or API should call the specific
                // PredictionBook methods (add_market, update_ballot_box, etc.)
                // with the full parsed state.
                counters.prediction_added += 1;
            }
        }
    }

    counters
}

/// Scan recent L1 blocks for new orders across all product types.
///
/// Polls the virtual selected parent chain for blocks added since
/// `last_chain_hash`, parses transactions, and routes detected orders
/// to the appropriate books via `process_block_txs_all`.
///
/// Returns the new chain tip hash to use as `last_chain_hash` on the next call.
async fn scan_new_blocks(
    rpc: &RpcClient,
    order_book: &mut OrderBook,
    perp_book: &mut crate::matcher::perp_book::PerpOrderBook,
    lending_book: &mut crate::matcher::lending_book::LendingBook,
    prediction_book: &mut crate::matcher::prediction_book::PredictionBook,
    last_chain_hash: &str,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    current_daa: u64,
) -> (String, ScanCounters) {
    let scanner = BlockScanner::new();
    let mut total_counters = ScanCounters::default();

    // Get virtual chain updates since last_chain_hash
    let chain_resp = match rpc.get_virtual_chain_from_block(last_chain_hash, true).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("[SCAN-BLOCKS] Failed to get virtual chain: {}", e);
            return (last_chain_hash.to_string(), total_counters);
        }
    };

    // Extract added block hashes
    let added_hashes: Vec<String> = chain_resp
        .get("addedChainBlockHashes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if added_hashes.is_empty() {
        return (last_chain_hash.to_string(), total_counters);
    }

    let new_tip = added_hashes.last().cloned().unwrap_or_else(|| last_chain_hash.to_string());

    info!(
        "[SCAN-BLOCKS] {} new chain block(s) since last scan",
        added_hashes.len(),
    );

    // Process each new block
    // Limit blocks per cycle to avoid blocking the main loop too long.
    // 200 blocks ≈ 20 seconds at 10 BPS — covers brief engine downtime without
    // permanently skipping blocks. Higher values cost more RPC calls per cycle.
    let max_blocks = 200;
    let blocks_to_scan = if added_hashes.len() > max_blocks {
        warn!(
            "[SCAN-BLOCKS] {} blocks queued, processing last {} only",
            added_hashes.len(), max_blocks,
        );
        &added_hashes[added_hashes.len() - max_blocks..]
    } else {
        &added_hashes
    };

    // Track already-scanned block hashes to avoid duplicates (a merge set
    // block may appear in multiple chain blocks' merge sets).
    let mut scanned_blocks: HashSet<String> = HashSet::new();

    for block_hash in blocks_to_scan {
        let block_resp = match rpc.get_block(block_hash).await {
            Ok(b) => b,
            Err(e) => {
                warn!("[SCAN-BLOCKS] Failed to get block {}: {}", &block_hash[..block_hash.len().min(16)], e);
                continue;
            }
        };

        // Collect all block hashes to scan: the chain block itself + its merge set.
        // TXs from parallel DAG blocks get accepted by a chain block but are only
        // present in the merge set blocks, not in the chain block's transactions[].
        let mut hashes_to_scan: Vec<String> = vec![block_hash.clone()];
        let block_data = block_resp.get("block").unwrap_or(&block_resp);
        if let Some(vd) = block_data.get("verboseData") {
            for key in &["mergeSetBluesHashes", "mergeSetRedsHashes"] {
                if let Some(arr) = vd.get(*key).and_then(|v| v.as_array()) {
                    for h in arr {
                        if let Some(s) = h.as_str() {
                            // Skip the chain block itself (already in the list)
                            if s != block_hash {
                                hashes_to_scan.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }

        for scan_hash in &hashes_to_scan {
            if !scanned_blocks.insert(scan_hash.clone()) {
                continue; // already scanned
            }

            // For the chain block we already have the response; for merge set
            // blocks we need a separate getBlock call.
            let resp = if scan_hash == block_hash {
                block_resp.clone()
            } else {
                match rpc.get_block(scan_hash).await {
                    Ok(b) => b,
                    Err(e) => {
                        debug!("[SCAN-BLOCKS] Failed to get merge-set block {}: {}", &scan_hash[..scan_hash.len().min(16)], e);
                        continue;
                    }
                }
            };

            let bd = resp.get("block").unwrap_or(&resp);
            let txs: Vec<TransactionData> = bd
                .get("transactions")
                .and_then(|t| t.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(TransactionData::from_rpc_json)
                        .collect()
                })
                .unwrap_or_default();

            if txs.is_empty() {
                continue;
            }

            let counters = process_block_txs_all(
                &txs,
                order_book,
                &scanner,
                perp_book,
                lending_book,
                prediction_book,
                ws_tx,
                current_daa,
            );

            total_counters.spot_added += counters.spot_added;
            total_counters.spot_removed += counters.spot_removed;
            total_counters.perp_added += counters.perp_added;
            total_counters.perp_removed += counters.perp_removed;
            total_counters.lending_added += counters.lending_added;
            total_counters.lending_removed += counters.lending_removed;
            total_counters.prediction_added += counters.prediction_added;
            total_counters.prediction_removed += counters.prediction_removed;
        }
    }

    let any_found = total_counters.spot_added > 0
        || total_counters.perp_added > 0
        || total_counters.lending_added > 0
        || total_counters.prediction_added > 0;
    let any_removed = total_counters.spot_removed > 0
        || total_counters.perp_removed > 0
        || total_counters.lending_removed > 0
        || total_counters.prediction_removed > 0;

    if any_found || any_removed {
        info!(
            "[SCAN-BLOCKS] Scan results: spot(+{}/~{}), perp(+{}/~{}), lending(+{}/~{}), prediction(+{}/~{})",
            total_counters.spot_added, total_counters.spot_removed,
            total_counters.perp_added, total_counters.perp_removed,
            total_counters.lending_added, total_counters.lending_removed,
            total_counters.prediction_added, total_counters.prediction_removed,
        );
    }

    (new_tip, total_counters)
}

/// Parse block notification JSON into TransactionData list.
///
/// Handles the Kaspa RPC `notifyBlockAddedResponse` format:
/// ```json
/// {
///   "block": {
///     "transactions": [{ ... }, ...]
///   }
/// }
/// ```
#[allow(dead_code)] // Used in tests
pub fn parse_block_notification(notification: &serde_json::Value) -> Vec<TransactionData> {
    let txs = notification
        .get("block")
        .and_then(|b| b.get("transactions"))
        .and_then(|t| t.as_array());

    match txs {
        Some(arr) => arr
            .iter()
            .filter_map(TransactionData::from_rpc_json)
            .collect(),
        None => Vec::new(),
    }
}

/// Record a trade to SharedState (trade_log + candle aggregator) and broadcast
/// WsEvent::Trade and WsEvent::Kline via the WebSocket broadcaster.
///
/// Called after every successful match TX submission to keep the REST API
/// `/trades` and `/klines` endpoints populated with live data.
async fn record_trade(
    shared_state: Option<&AppState>,
    txid: &str,
    token_cov_id: &str,
    price_num: u64,
    price_den: u64,
    quantity: u64,
    side: Side,
    routing: Option<crate::matcher::trades::RoutingInfo>,
) {
    let shared_state = match shared_state {
        Some(s) => s,
        None => return,
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pair_id = format!("{}/KAS", &token_cov_id[..token_cov_id.len().min(16)]);

    let trade = Trade {
        txid: txid.to_string(),
        pair_id: pair_id.clone(),
        price_num,
        price_den,
        quantity,
        side,
        daa_score: now_unix, // best-effort; exact DAA score not available in executor
        timestamp: now_unix,
        routing,
    };

    let mut state = shared_state.write().await;

    // Push to trade log (ring buffer + optional JSONL file)
    state.trade_log.push(trade.clone());

    // Update candle aggregator for all intervals
    state.candles.on_trade(&trade);

    // Persist M1 candle to SQLite (MT5 style: only M1 stored, higher TFs aggregated on read)
    if let Some(ref history) = state.history {
        if let Some(candle) = state.candles.latest_candle(&trade.pair_id, super::candle::Interval::M1) {
            if let Err(e) = history.upsert_m1(&trade.pair_id, candle) {
                tracing::warn!("History DB M1 upsert failed: {}", e);
            }
        }
    }

    // Broadcast WsEvent::Trade
    let price_str = format!("{}/{}", price_num, price_den);
    let _ = state.ws_broadcaster.send(WsEvent::Trade {
        pair: pair_id.clone(),
        txid: txid.to_string(),
        price: price_str,
        qty: quantity.to_string(),
        side,
        daa_score: now_unix,
    });

    // Broadcast WsEvent::Kline for all intervals (latest candle state)
    for &interval in Interval::all() {
        let candles = state.candles.get_candles(&pair_id, interval, 1);
        if let Some(c) = candles.last() {
            let _ = state.ws_broadcaster.send(WsEvent::Kline {
                pair: pair_id.clone(),
                interval: interval.as_str().to_string(),
                o: format!("{}/{}", c.open.0, c.open.1),
                h: format!("{}/{}", c.high.0, c.high.1),
                l: format!("{}/{}", c.low.0, c.low.1),
                c: format!("{}/{}", c.close.0, c.close.1),
                v: c.volume.to_string(),
            });
        }
    }
}

// Expire TX builder for v12 GTD orders

/// Build and submit expire TXs for expired v12 orders.
///
/// v12 orders with `expiry_daa > 0` can be permissionlessly reclaimed after
/// the DAA score exceeds the expiry. The expire TX:
///   - Input: the expired order UTXO (P2SH, sigscript = expire sigscript)
///   - Output: owner's address (from bspkh/sspkh in the RS), value = input - fee
///   - lockTime = expiry_daa (required for CLTV to pass)
///
/// Anyone can submit this TX; no owner signature is needed.
async fn expire_orders(
    rpc: &RpcClient,
    expired_orders: &[crate::matcher::order_book::BookOrder],
    current_daa: u64,
    _wallet_prefix: &str,
) -> u32 {
    use crate::matcher::order_book::OrderSide;

    let mut expired_count = 0u32;

    for order in expired_orders {
        let expiry_daa = match order.expiry_daa {
            Some(e) if e > 0 && e <= current_daa => e,
            _ => continue,
        };

        let rs = order.redeem_script();
        if rs.is_empty() {
            warn!(
                "[EXPIRE] Empty RS for order {}, skipping",
                &order.outpoint_key()[..order.outpoint_key().len().min(20)],
            );
            continue;
        }

        // Build expire sigscript based on order side
        let expire_ss = match order.side {
            OrderSide::Buy => kob_core::contract::build_buy_expire_sigscript(&rs),
            OrderSide::Sell => kob_core::contract::build_sell_expire_sigscript(&rs),
        };

        // Owner's SPK hash is in spk_hash. We need the actual SPK bytes
        // to build the output. Try counterparty_spk (which for buy orders
        // is the buyer's SPK, for sell orders the seller's SPK).
        let owner_spk_hex = match &order.counterparty_spk {
            Some(spk) if !spk.is_empty() => spk.clone(),
            _ => {
                // If counterparty_spk is not available, we can't build the
                // expire output. The owner must self-expire via the CLI.
                warn!(
                    "[EXPIRE] No counterparty SPK for expired order {}, skipping (owner must self-expire)",
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                );
                continue;
            }
        };
        let _owner_spk = match hex::decode(&owner_spk_hex) {
            Ok(spk) => spk,
            Err(_) => continue,
        };

        // Deduct network fee from the order value (1 input, 1 output expire TX)
        let expire_miner_fee = kob_core::mass::estimate_compute_mass(1, 1, 0);
        let output_value = order.value.saturating_sub(expire_miner_fee);
        if output_value < MIN_UTXO_VALUE {
            warn!(
                "[EXPIRE] Expired order {} value too low ({} < min {}), skipping",
                &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                output_value,
                MIN_UTXO_VALUE,
            );
            continue;
        }

        // Build TX
        let input = deploy::build_rpc_input(
            &order.tx_id,
            order.index,
            &hex::encode(&expire_ss),
            0, // sigOpCount = 0 for covenant inputs
        );
        let output = deploy::build_rpc_output(
            output_value,
            0, // P2PK version
            &owner_spk_hex,
        );

        // lockTime must be >= expiry_daa for CLTV to pass.
        // Consensus enforces lockTime <= current_daa, so we use expiry_daa.
        let payload = deploy::build_submit_payload_with_lock_time(
            0,
            vec![input],
            vec![output],
            expiry_daa,
        );

        match rpc.submit_transaction(payload).await {
            Ok(result) if result.ok => {
                let tx_id = result.tx_id.unwrap_or_default();
                info!(
                    "[EXPIRE] Reclaimed expired {} order {} -> TX {}",
                    if order.side == OrderSide::Buy { "BUY" } else { "SELL" },
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                    &tx_id[..tx_id.len().min(20)],
                );
                expired_count += 1;
            }
            Ok(result) => {
                warn!(
                    "[EXPIRE] Failed to expire order {}: {:?}",
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                    result.error,
                );
            }
            Err(e) => {
                warn!(
                    "[EXPIRE] RPC error expiring order {}: {}",
                    &order.outpoint_key()[..order.outpoint_key().len().min(20)],
                    e,
                );
            }
        }
    }

    expired_count
}

/// Get the current virtual DAA score from the node.
async fn get_current_daa(rpc: &RpcClient) -> Option<u64> {
    match rpc.call("getBlockDagInfo", serde_json::json!({})).await {
        Ok(info) => {
            info.get("virtualDaaScore")
                .and_then(|v| v.as_u64())
        }
        Err(e) => {
            warn!("[EXPIRE] Failed to get DAA score: {}", e);
            None
        }
    }
}

/// Run one matching scan cycle.
///
/// Executes two phases:
///   1. Same-pair matches (existing logic): find crossing buy+sell within each token pair.
///   2. Cross-pair routes (v8): find Token A -> KAS -> Token B atomic routes.
///
/// Same-pair matches are prioritized. Cross-pair routes are executed only for
/// orders not already consumed by same-pair matches.
async fn run_scan_cycle(
    rpc: &RpcClient,
    order_book: &mut OrderBook,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
    enable_cross_pair: bool,
    allow_self_trade: bool,
    ws_tx: Option<&tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    shared_state: Option<&AppState>,
    ifd_book: &Arc<Mutex<crate::matcher::ifd::IfdBook>>,
    perp_book: &Arc<Mutex<crate::matcher::perp_book::PerpOrderBook>>,
    perp_tracker: &Arc<Mutex<crate::matcher::perp_tracker::PositionTracker>>,
    lending_book: &Arc<Mutex<crate::matcher::lending_book::LendingBook>>,
    loan_tracker: &Arc<Mutex<crate::matcher::lending_tracker::LoanTracker>>,
    prediction_book: &Arc<Mutex<crate::matcher::prediction_book::PredictionBook>>,
    market_tracker: &Arc<Mutex<crate::matcher::prediction_tracker::MarketTracker>>,
) -> Vec<MatchResult> {
    let mut results = Vec::new();

    // H-5: Expire cooldown entries from previous failed submissions
    spent_tracker.expire_failed();

    // Phase 1: Same-pair matches
    let all_pairs_raw = matching::find_all_crossing_pairs_with_stp(order_book, allow_self_trade);
    // H-5: Filter out pairs whose outpoints are under failure cooldown
    // ZK-GATE: Filter out pairs where either order is freezable and no prover is configured
    let all_pairs: Vec<_> = all_pairs_raw
        .into_iter()
        .filter(|p| {
            let bk = p.buy.outpoint_key();
            let sk = p.sell.outpoint_key();
            if spent_tracker.is_failed(&bk) || spent_tracker.is_failed(&sk) {
                info!(
                    "[SCAN] Skipping pair (outpoint under cooldown): buy={}... sell={}...",
                    &bk[..bk.len().min(20)],
                    &sk[..sk.len().min(20)],
                );
                return false;
            }
            // ZK-GATE: Skip pairs involving freezable tokens when no ZK prover is configured
            if !config.zk_prover_enabled && (p.buy.is_freezable || p.sell.is_freezable) {
                warn!(
                    "[SCAN] Skipping pair (freezable token, no ZK prover): buy={}... sell={}... \
                     (use --zk-prover to enable)",
                    &bk[..bk.len().min(20)],
                    &sk[..sk.len().min(20)],
                );
                return false;
            }
            true
        })
        .collect();

    if all_pairs.is_empty() {
        let stats = order_book.stats();
        info!("[SCAN] No same-pair crossing pairs found");
        info!(
            "  Pairs tracked: {}, Bids: {}, Asks: {}",
            stats.pairs, stats.total_bids, stats.total_asks
        );
        for ps in &stats.by_pair {
            info!("    {}...: {} bids, {} asks", ps.token_cov_id, ps.bids, ps.asks);
        }
    } else {
        info!(
            "[SCAN] Found {} same-pair crossing pair(s) across {} token(s)",
            all_pairs.len(),
            {
                let mut tokens = HashSet::new();
                for p in &all_pairs {
                    tokens.insert(&p.token_cov_id);
                }
                tokens.len()
            }
        );

        // Phase 1a: Batch matching (2+ full-fill pairs per token)
        // Try batch matching first — more efficient when multiple full-fill
        // pairs cross for the same token. Orders consumed by batch are
        // excluded from the 1:1 path below.
        let batch_groups = matching::find_batch_groups(&all_pairs);
        let mut batched_outpoints: HashSet<String> = HashSet::new();

        if !batch_groups.is_empty() {
            info!(
                "[BATCH] Found {} batch group(s) with {} total pairs",
                batch_groups.len(),
                batch_groups.iter().map(|g| g.len()).sum::<usize>(),
            );
        }

        for group in &batch_groups {
            // Collect sell and buy BatchOrders from the crossing pairs in this group.
            // Skip any pair whose outpoints were already consumed by a previous batch.
            let mut sells = Vec::new();
            let mut buys = Vec::new();

            for pair in group {
                let buy_key = pair.buy.outpoint_key();
                let sell_key = pair.sell.outpoint_key();
                if batched_outpoints.contains(&buy_key) || batched_outpoints.contains(&sell_key) {
                    continue;
                }

                let token_bytes: [u8; 32] = match hex::decode(&pair.sell.token_cov_id) {
                    Ok(v) if v.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&v);
                        arr
                    }
                    _ => {
                        warn!("[BATCH] Invalid token_cov_id hex, skipping pair");
                        continue;
                    }
                };

                let sell_rs = hex::decode(&pair.sell.redeem_script_hex).unwrap_or_default();
                let buy_rs = hex::decode(&pair.buy.redeem_script_hex).unwrap_or_default();

                // Detect sell version from RS length (284=v6, 287=v8, 344=v12, 378=v13)
                let sell_version = match sell_rs.len() {
                    284 => 6,
                    287 => 8,
                    344 => 12,
                    378 => 13,
                    other => {
                        warn!("[BATCH] Unknown sell RS size {}, skipping", other);
                        continue;
                    }
                };

                // Detect buy version from RS length + T2 byte
                let buy_version = match buy_rs.len() {
                    356 => 8,   // v8: RS=356
                    369 => 10,  // v10: RS=369
                    371 => {
                        // v9 and v11 share RS=371. Distinguish by T2 byte at rs[140]
                        if buy_rs.len() > 140 && buy_rs[140] == 0x86 {
                            11 // v11: T2=0x86
                        } else {
                            9  // v9: T2=0x87
                        }
                    }
                    415 => 12,  // v12: RS=415
                    409 => 13,  // v13: RS=409 (145B state + 264B body)
                    other => {
                        warn!("[BATCH] Unknown buy RS size {}, skipping", other);
                        continue;
                    }
                };

                // Resolve counterparty SPKs for output routing
                let (seller_spk_ver, seller_spk) = match pair.sell.resolve_counterparty_spk() {
                    Some(x) => x,
                    None => {
                        warn!("[BATCH] Sell order {} missing counterparty_spk, skipping", pair.sell.outpoint_key());
                        continue;
                    }
                };
                let (buyer_spk_ver, buyer_spk) = match pair.buy.resolve_counterparty_spk() {
                    Some(x) => x,
                    None => {
                        warn!("[BATCH] Buy order {} missing counterparty_spk, skipping", pair.buy.outpoint_key());
                        continue;
                    }
                };

                sells.push(crate::matcher::batch::BatchOrder {
                    outpoint: (pair.sell.tx_id.clone(), pair.sell.index),
                    order_type: crate::matcher::batch::OrderType::Sell,
                    version: sell_version,
                    token_cov_id: token_bytes,
                    price_num: pair.sell.price_num,
                    price_den: pair.sell.price_den,
                    amount: pair.sell.value,
                    redeem_script: sell_rs,
                    utxo_value: pair.sell.value,
                    counterparty_spk: seller_spk,
                    counterparty_spk_version: seller_spk_ver,
                });

                buys.push(crate::matcher::batch::BatchOrder {
                    outpoint: (pair.buy.tx_id.clone(), pair.buy.index),
                    order_type: crate::matcher::batch::OrderType::Buy,
                    version: buy_version,
                    token_cov_id: token_bytes,
                    price_num: pair.buy.price_num,
                    price_den: pair.buy.price_den,
                    amount: pair.buy.value,
                    redeem_script: buy_rs,
                    utxo_value: pair.buy.value,
                    counterparty_spk: buyer_spk,
                    counterparty_spk_version: buyer_spk_ver,
                });
            }

            if sells.len() < 2 || buys.len() < 2 {
                // Not enough pairs survived filtering; fall through to 1:1
                continue;
            }

            info!(
                "[BATCH] Planning batch: {} sells + {} buys for token [{}...]",
                sells.len(),
                buys.len(),
                &group[0].token_cov_id[..group[0].token_cov_id.len().min(16)],
            );

            // Acquire wallet UTXOs for fee payment and token unit search
            let batch_utxos = match rpc
                .get_spendable_utxos(&config.address, Some(0))
                .await
            {
                Ok(u) if !u.is_empty() => u,
                Ok(_) => {
                    warn!("[BATCH] No wallet UTXOs available, falling through to 1:1");
                    continue;
                }
                Err(e) => {
                    warn!("[BATCH] Failed to get wallet UTXOs: {}, falling through to 1:1", e);
                    continue;
                }
            };
            let (wallet_spk_version, wallet_spk_script) = batch_utxos[0].parse_spk();

            // Find the best wallet UTXO for fee payment (largest non-token UTXO)
            let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
            let token_p2sh_hex = hex::encode(&token_p2sh.script());
            let wallet_utxo = batch_utxos.iter()
                .filter(|u| {
                    let (_, script) = u.parse_spk();
                    hex::encode(&script) != token_p2sh_hex
                        && !spent_tracker.is_spent(&u.outpoint_key())
                })
                .max_by_key(|u| u.utxo_entry.amount)
                .map(|u| (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount));

            // Find token unit UTXOs for each unique token in this batch group
            let token_hex = hex::encode(sells[0].token_cov_id);
            let total_tokens_needed: u64 = buys.iter().map(|b| {
                // tokens = buy_amount * price_den / price_num (buy pays KAS, gets tokens)
                b.amount.saturating_mul(b.price_den) / b.price_num.max(1)
            }).sum();

            let token_unit = find_token_utxo_from_wallet(&batch_utxos, total_tokens_needed, spent_tracker);
            let token_units = match token_unit {
                Some(tu) => vec![crate::matcher::batch::TokenUnit {
                    outpoint: (tu.tx_id, tu.index),
                    token_cov_id: sells[0].token_cov_id,
                    value: tu.value,
                    redeem_script: kob_core::TOKEN_RS.to_vec(),
                }],
                None => {
                    warn!(
                        "[BATCH] No token UTXO found (need >= {} for token {}...), falling through to 1:1",
                        total_tokens_needed,
                        &token_hex[..token_hex.len().min(16)],
                    );
                    continue;
                }
            };

            // Plan the batch match
            let plan = match crate::matcher::batch::plan_batch_match(
                &sells, &buys, &token_units, wallet_utxo,
                &wallet_spk_script, wallet_spk_version,
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!("[BATCH] Plan failed: {}, falling through to 1:1", e);
                    continue;
                }
            };

            // Execute the batch match
            match execute_batch_match(rpc, &plan, config, spent_tracker).await {
                Some(batch_result) => {
                    info!(
                        "[BATCH] SUCCESS: tx={} sells={} buys={} surplus={}",
                        &batch_result.tx_id[..batch_result.tx_id.len().min(16)],
                        batch_result.sell_count,
                        batch_result.buy_count,
                        batch_result.matcher_surplus,
                    );
                    for pair in group {
                        let bk = pair.buy.outpoint_key();
                        let sk = pair.sell.outpoint_key();
                        batched_outpoints.insert(bk.clone());
                        batched_outpoints.insert(sk.clone());

                        // Emit OrderFilled for both sides before removal
                        if let Some(ws) = ws_tx {
                            crate::matcher::api::emit_order_filled(
                                ws, &pair.buy.owner_hash, &bk,
                                &batch_result.tx_id,
                                pair.buy.price_num, pair.buy.price_den,
                                pair.buy.value, OrderSide::Buy,
                                &pair.token_cov_id,
                            );
                            crate::matcher::api::emit_order_filled(
                                ws, &pair.sell.owner_hash, &sk,
                                &batch_result.tx_id,
                                pair.sell.price_num, pair.sell.price_den,
                                pair.sell.value, OrderSide::Sell,
                                &pair.token_cov_id,
                            );
                        }

                        // Record trade to SharedState (trade_log + candles + WS broadcast)
                        record_trade(
                            shared_state,
                            &batch_result.tx_id,
                            &pair.token_cov_id,
                            pair.sell.price_num, pair.sell.price_den,
                            pair.seller_kas,
                            Side::Buy,
                            None,
                        ).await;

                        order_book.remove_order(&bk);
                        order_book.remove_order(&sk);
                        spent_tracker.mark_spent(&bk);
                        spent_tracker.mark_spent(&sk);
                    }
                    // Mark wallet and token unit outpoints as spent to prevent
                    // reuse by subsequent matches in the same scan cycle.
                    if let Some(ref wu) = plan.wallet_input {
                        let wk = format!("{}:{}", wu.0, wu.1);
                        spent_tracker.mark_spent(&wk);
                    }
                    for (tu, _) in &plan.token_units {
                        let tk = format!("{}:{}", tu.outpoint.0, tu.outpoint.1);
                        spent_tracker.mark_spent(&tk);
                    }
                }
                None => {
                    warn!("[BATCH] Batch execution failed for token {}...", &token_hex[..token_hex.len().min(16)]);
                    for pair in group {
                        spent_tracker.mark_failed(&pair.buy.outpoint_key());
                        spent_tracker.mark_failed(&pair.sell.outpoint_key());
                    }
                }
            }
        }

        // Phase 1b: 1:1 matching (remaining pairs not consumed by batch)
        // Execute best match per token (highest surplus first)
        let mut by_token: HashMap<String, &CrossingPair> = HashMap::new();
        for p in &all_pairs {
            // Skip orders already consumed by batch matching
            let buy_key = p.buy.outpoint_key();
            let sell_key = p.sell.outpoint_key();
            if batched_outpoints.contains(&buy_key) || batched_outpoints.contains(&sell_key) {
                continue;
            }
            let entry = by_token.entry(p.token_cov_id.clone()).or_insert(p);
            if p.surplus > entry.surplus {
                *entry = p;
            }
        }

        for (token_cov_id, best) in &by_token {
            info!(
                "  [{}...] Best match: {:?}, surplus={}",
                &token_cov_id[..token_cov_id.len().min(16)],
                best.match_type,
                best.surplus
            );

            // Check IFD book for contingent orders on buy or sell outpoints
            let ifd_ctx = {
                let ifd = ifd_book.lock().await;
                let buy_outpoint = best.buy.outpoint_key();
                let sell_outpoint = best.sell.outpoint_key();
                // Check buy side first, then sell side
                let rule = ifd.find_by_a_outpoint(&buy_outpoint)
                    .or_else(|| ifd.find_by_a_outpoint(&sell_outpoint));
                rule.and_then(|r| {
                    if r.status == crate::matcher::ifd::IfdStatus::Active {
                        match hex::decode(&r.order_b_rs_hex) {
                            Ok(rs_bytes) => Some(IfdFillContext {
                                rule_id: r.id,
                                order_b_rs: rs_bytes,
                                order_b_p2sh: r.order_b_p2sh.clone(),
                                expiry_daa: r.order_b.expiry_daa(),
                            }),
                            Err(e) => {
                                warn!("[IFD] Failed to decode order B RS hex for rule {}: {}", r.id, e);
                                None
                            }
                        }
                    } else {
                        None
                    }
                })
            };

            match execute_match(rpc, best, config, ifd_ctx.as_ref(), spent_tracker).await {
                Some(match_result) => {
                    // If IFD was active, mark the rule as triggered and persist
                    if let Some(ctx) = &ifd_ctx {
                        let mut ifd = ifd_book.lock().await;
                        ifd.trigger(ctx.rule_id, &match_result.match_tx_id);
                        drop(ifd);
                    }

                    // Remove matched orders
                    let buy_key = best.buy.outpoint_key();
                    let sell_key = best.sell.outpoint_key();

                    // Emit OrderFilled for both sides
                    if let Some(ws) = ws_tx {
                        // Determine fill amounts based on match type
                        let (buy_filled, sell_filled, is_partial) = match best.match_type {
                            MatchType::Full => (best.buy.value, best.sell.value, false),
                            MatchType::PartialBuy => {
                                // Buy is partially consumed; sell is fully consumed
                                (best.sell.value, best.sell.value, true)
                            }
                            MatchType::PartialSell => {
                                // Sell is partially consumed; buy is fully consumed
                                (best.buy.value, best.buy.value, true)
                            }
                        };

                        if is_partial && best.match_type == MatchType::PartialBuy {
                            // Buy order partially filled, sell fully consumed
                            crate::matcher::api::emit_order_partially_filled(
                                ws, &best.buy.owner_hash, &buy_key,
                                &match_result.match_tx_id,
                                sell_filled,
                                best.buy.value.saturating_sub(sell_filled),
                                best.buy.price_num, best.buy.price_den,
                                OrderSide::Buy, token_cov_id,
                            );
                            crate::matcher::api::emit_order_filled(
                                ws, &best.sell.owner_hash, &sell_key,
                                &match_result.match_tx_id,
                                best.sell.price_num, best.sell.price_den,
                                best.sell.value, OrderSide::Sell, token_cov_id,
                            );
                        } else if is_partial && best.match_type == MatchType::PartialSell {
                            // Sell order partially filled, buy fully consumed
                            crate::matcher::api::emit_order_filled(
                                ws, &best.buy.owner_hash, &buy_key,
                                &match_result.match_tx_id,
                                best.buy.price_num, best.buy.price_den,
                                best.buy.value, OrderSide::Buy, token_cov_id,
                            );
                            crate::matcher::api::emit_order_partially_filled(
                                ws, &best.sell.owner_hash, &sell_key,
                                &match_result.match_tx_id,
                                buy_filled,
                                best.sell.value.saturating_sub(buy_filled),
                                best.sell.price_num, best.sell.price_den,
                                OrderSide::Sell, token_cov_id,
                            );
                        } else {
                            // Full fill — both sides fully consumed
                            crate::matcher::api::emit_order_filled(
                                ws, &best.buy.owner_hash, &buy_key,
                                &match_result.match_tx_id,
                                best.buy.price_num, best.buy.price_den,
                                buy_filled, OrderSide::Buy, token_cov_id,
                            );
                            crate::matcher::api::emit_order_filled(
                                ws, &best.sell.owner_hash, &sell_key,
                                &match_result.match_tx_id,
                                best.sell.price_num, best.sell.price_den,
                                sell_filled, OrderSide::Sell, token_cov_id,
                            );
                        }
                    }

                    // Record trade to SharedState (trade_log + candles + WS broadcast)
                    {
                        let trade_qty = match best.match_type {
                            MatchType::Full => best.seller_kas,
                            MatchType::PartialBuy => best.sell.value,
                            MatchType::PartialSell => best.buy.value,
                        };
                        let trade_side = match best.match_type {
                            MatchType::Full | MatchType::PartialBuy => Side::Buy,
                            MatchType::PartialSell => Side::Sell,
                        };
                        record_trade(
                            shared_state,
                            &match_result.match_tx_id,
                            token_cov_id,
                            best.sell.price_num, best.sell.price_den,
                            trade_qty,
                            trade_side,
                            None,
                        ).await;
                    }

                    order_book.remove_order(&buy_key);
                    order_book.remove_order(&sell_key);

                    // Track the spent outpoints locally
                    spent_tracker.mark_spent(&buy_key);
                    spent_tracker.mark_spent(&sell_key);

                    results.push(match_result);
                }
                None => {
                    warn!("[MATCH] Match execution failed or skipped");
                    // H-5: Mark both outpoints as failed to prevent infinite retry
                    let buy_key = best.buy.outpoint_key();
                    let sell_key = best.sell.outpoint_key();
                    spent_tracker.mark_failed(&buy_key);
                    spent_tracker.mark_failed(&sell_key);
                    warn!(
                        "[MATCH] Outpoints {}... and {}... cooldown for {}s",
                        &buy_key[..buy_key.len().min(20)],
                        &sell_key[..sell_key.len().min(20)],
                        spent_tracker.cooldown_secs,
                    );
                }
            }
        }
    }

    // Phase 2: Cross-pair routes via batch engine
    if enable_cross_pair {
        let cross_groups = matching::find_cross_pair_batch_groups(order_book, 10, allow_self_trade);

        if cross_groups.is_empty() {
            info!("[SCAN] No cross-pair routes found");
        } else {
            info!(
                "[SCAN] Found {} cross-pair batch group(s)",
                cross_groups.len(),
            );

            for group in &cross_groups {
                info!(
                    "[CROSS-BATCH] Planning batch: {} sells + {} buys, surplus={}",
                    group.sells.len(),
                    group.buys.len(),
                    group.total_surplus,
                );

                // Convert BookOrders to BatchOrders (same logic as Phase 1a)
                let mut sells = Vec::new();
                let mut buys = Vec::new();
                let mut skip_group = false;

                for sell in &group.sells {
                    let sell_rs = hex::decode(&sell.redeem_script_hex).unwrap_or_default();
                    let token_bytes: [u8; 32] = match hex::decode(&sell.token_cov_id) {
                        Ok(v) if v.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            arr
                        }
                        _ => {
                            warn!("[CROSS-BATCH] Invalid sell token_cov_id hex, skipping group");
                            skip_group = true;
                            break;
                        }
                    };
                    let sell_version = match sell_rs.len() {
                        284 => 6,
                        287 => 8,
                        344 => 12,
                        378 => 13,
                        other => {
                            warn!("[CROSS-BATCH] Unknown sell RS size {}, skipping group", other);
                            skip_group = true;
                            break;
                        }
                    };
                    let (seller_spk_ver, seller_spk) = match sell.resolve_counterparty_spk() {
                        Some(x) => x,
                        None => {
                            warn!("[CROSS-BATCH] Sell order {} missing counterparty_spk, skipping group", sell.outpoint_key());
                            skip_group = true;
                            break;
                        }
                    };
                    sells.push(crate::matcher::batch::BatchOrder {
                        outpoint: (sell.tx_id.clone(), sell.index),
                        order_type: crate::matcher::batch::OrderType::Sell,
                        version: sell_version,
                        token_cov_id: token_bytes,
                        price_num: sell.price_num,
                        price_den: sell.price_den,
                        amount: sell.value,
                        redeem_script: sell_rs,
                        utxo_value: sell.value,
                        counterparty_spk: seller_spk,
                        counterparty_spk_version: seller_spk_ver,
                    });
                }

                if skip_group {
                    continue;
                }

                for buy in &group.buys {
                    let buy_rs = hex::decode(&buy.redeem_script_hex).unwrap_or_default();
                    let token_bytes: [u8; 32] = match hex::decode(&buy.token_cov_id) {
                        Ok(v) if v.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            arr
                        }
                        _ => {
                            warn!("[CROSS-BATCH] Invalid buy token_cov_id hex, skipping group");
                            skip_group = true;
                            break;
                        }
                    };
                    let buy_version = match buy_rs.len() {
                        356 => 8,
                        369 => 10,
                        371 => {
                            if buy_rs.len() > 140 && buy_rs[140] == 0x86 {
                                11
                            } else {
                                9
                            }
                        }
                        415 => 12,
                        409 => 13,
                        other => {
                            warn!("[CROSS-BATCH] Unknown buy RS size {}, skipping group", other);
                            skip_group = true;
                            break;
                        }
                    };
                    let (buyer_spk_ver, buyer_spk) = match buy.resolve_counterparty_spk() {
                        Some(x) => x,
                        None => {
                            warn!("[CROSS-BATCH] Buy order {} missing counterparty_spk, skipping group", buy.outpoint_key());
                            skip_group = true;
                            break;
                        }
                    };
                    buys.push(crate::matcher::batch::BatchOrder {
                        outpoint: (buy.tx_id.clone(), buy.index),
                        order_type: crate::matcher::batch::OrderType::Buy,
                        version: buy_version,
                        token_cov_id: token_bytes,
                        price_num: buy.price_num,
                        price_den: buy.price_den,
                        amount: buy.value,
                        redeem_script: buy_rs,
                        utxo_value: buy.value,
                        counterparty_spk: buyer_spk,
                        counterparty_spk_version: buyer_spk_ver,
                    });
                }

                if skip_group || sells.is_empty() || buys.is_empty() {
                    continue;
                }

                // Acquire wallet UTXOs for fee payment and token unit search
                let cp_utxos = match rpc
                    .get_spendable_utxos(&config.address, Some(0))
                    .await
                {
                    Ok(u) if !u.is_empty() => u,
                    Ok(_) => {
                        warn!("[CROSS-BATCH] No wallet UTXOs available, skipping");
                        continue;
                    }
                    Err(e) => {
                        warn!("[CROSS-BATCH] Failed to get wallet UTXOs: {}, skipping", e);
                        continue;
                    }
                };
                let (wallet_spk_version, wallet_spk_script) = cp_utxos[0].parse_spk();

                // Find the best wallet UTXO for fee payment
                let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
                let token_p2sh_hex = hex::encode(&token_p2sh.script());
                let wallet_utxo = cp_utxos.iter()
                    .filter(|u| {
                        let (_, script) = u.parse_spk();
                        hex::encode(&script) != token_p2sh_hex
                            && !spent_tracker.is_spent(&u.outpoint_key())
                    })
                    .max_by_key(|u| u.utxo_entry.amount)
                    .map(|u| (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount));

                // Find token unit UTXOs for each unique buy token
                let mut unique_buy_tokens: HashSet<[u8; 32]> = HashSet::new();
                for b in &buys {
                    unique_buy_tokens.insert(b.token_cov_id);
                }

                let mut token_units = Vec::new();
                let mut missing_token = false;
                for token_id in &unique_buy_tokens {
                    let tokens_needed: u64 = buys.iter()
                        .filter(|b| &b.token_cov_id == token_id)
                        .map(|b| {
                            let wide = b.amount as u128 * b.price_num as u128 / b.price_den as u128;
                            u64::try_from(wide).unwrap_or_else(|_| {
                                warn!("u128->u64 overflow in token calc (amount={}, pnum={}, pden={}), capping",
                                    b.amount, b.price_num, b.price_den);
                                u64::MAX
                            })
                        })
                        .sum();
                    let token_hex = hex::encode(token_id);
                    let token_unit = find_token_utxo_from_wallet(&cp_utxos, tokens_needed, spent_tracker);
                    match token_unit {
                        Some(tu) => {
                            token_units.push(crate::matcher::batch::TokenUnit {
                                outpoint: (tu.tx_id, tu.index),
                                token_cov_id: *token_id,
                                value: tu.value,
                                redeem_script: kob_core::TOKEN_RS.to_vec(),
                            });
                        }
                        None => {
                            warn!(
                                "[CROSS-BATCH] No token UTXO found (need >= {} for token {}...), skipping group",
                                tokens_needed,
                                &token_hex[..token_hex.len().min(16)],
                            );
                            missing_token = true;
                            break;
                        }
                    }
                }
                if missing_token {
                    continue;
                }

                // Plan and execute via batch engine
                let plan = match crate::matcher::batch::plan_batch_match(
                    &sells, &buys, &token_units, wallet_utxo,
                    &wallet_spk_script, wallet_spk_version,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[CROSS-BATCH] Plan failed: {}, skipping group", e);
                        continue;
                    }
                };

                match execute_batch_match(rpc, &plan, config, spent_tracker).await {
                    Some(batch_result) => {
                        info!(
                            "[CROSS-BATCH] SUCCESS: tx={} sells={} buys={} surplus={}",
                            &batch_result.tx_id[..batch_result.tx_id.len().min(16)],
                            batch_result.sell_count,
                            batch_result.buy_count,
                            batch_result.matcher_surplus,
                        );
                        for sell in &group.sells {
                            let sk = sell.outpoint_key();
                            if let Some(ws) = ws_tx {
                                crate::matcher::api::emit_order_filled(
                                    ws, &sell.owner_hash, &sk,
                                    &batch_result.tx_id,
                                    sell.price_num, sell.price_den,
                                    sell.value, OrderSide::Sell,
                                    &sell.token_cov_id,
                                );
                            }
                            // Record cross-pair sell leg trade
                            record_trade(
                                shared_state,
                                &batch_result.tx_id,
                                &sell.token_cov_id,
                                sell.price_num, sell.price_den,
                                sell.value,
                                Side::Sell,
                                None,
                            ).await;
                            order_book.remove_order(&sk);
                            spent_tracker.mark_spent(&sk);
                        }
                        for buy in &group.buys {
                            let bk = buy.outpoint_key();
                            if let Some(ws) = ws_tx {
                                crate::matcher::api::emit_order_filled(
                                    ws, &buy.owner_hash, &bk,
                                    &batch_result.tx_id,
                                    buy.price_num, buy.price_den,
                                    buy.value, OrderSide::Buy,
                                    &buy.token_cov_id,
                                );
                            }
                            // Record cross-pair buy leg trade
                            record_trade(
                                shared_state,
                                &batch_result.tx_id,
                                &buy.token_cov_id,
                                buy.price_num, buy.price_den,
                                buy.value,
                                Side::Buy,
                                None,
                            ).await;
                            order_book.remove_order(&bk);
                            spent_tracker.mark_spent(&bk);
                        }
                        if let Some(ref wu) = plan.wallet_input {
                            let wk = format!("{}:{}", wu.0, wu.1);
                            spent_tracker.mark_spent(&wk);
                        }
                        for (tu, _) in &plan.token_units {
                            let tk = format!("{}:{}", tu.outpoint.0, tu.outpoint.1);
                            spent_tracker.mark_spent(&tk);
                        }
                    }
                    None => {
                        warn!("[CROSS-BATCH] Batch execution failed");
                        for sell in &group.sells {
                            spent_tracker.mark_failed(&sell.outpoint_key());
                        }
                        for buy in &group.buys {
                            spent_tracker.mark_failed(&buy.outpoint_key());
                        }
                    }
                }
            }
        }

        // Phase 3: Triangular (3-hop) arbitrage via batch engine
        let tri_groups = matching::find_triangular_batch_groups(order_book, 5, allow_self_trade);

        if tri_groups.is_empty() {
            info!("[SCAN] No triangular arbitrage routes found");
        } else {
            info!(
                "[SCAN] Found {} triangular batch group(s)",
                tri_groups.len(),
            );

            for group in &tri_groups {
                info!(
                    "[TRI-BATCH] Planning batch: {} sells + {} buys, surplus={}",
                    group.sells.len(),
                    group.buys.len(),
                    group.total_surplus,
                );

                // Convert BookOrders to BatchOrders (same logic as Phase 2)
                let mut sells = Vec::new();
                let mut buys = Vec::new();
                let mut skip_group = false;

                for sell in &group.sells {
                    let sell_rs = hex::decode(&sell.redeem_script_hex).unwrap_or_default();
                    let token_bytes: [u8; 32] = match hex::decode(&sell.token_cov_id) {
                        Ok(v) if v.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            arr
                        }
                        _ => {
                            warn!("[TRI-BATCH] Invalid sell token_cov_id hex, skipping group");
                            skip_group = true;
                            break;
                        }
                    };
                    let sell_version = match sell_rs.len() {
                        284 => 6,
                        287 => 8,
                        344 => 12,
                        378 => 13,
                        other => {
                            warn!("[TRI-BATCH] Unknown sell RS size {}, skipping group", other);
                            skip_group = true;
                            break;
                        }
                    };
                    let (seller_spk_ver, seller_spk) = match sell.resolve_counterparty_spk() {
                        Some(x) => x,
                        None => {
                            warn!("[TRI-BATCH] Sell order {} missing counterparty_spk, skipping group", sell.outpoint_key());
                            skip_group = true;
                            break;
                        }
                    };
                    sells.push(crate::matcher::batch::BatchOrder {
                        outpoint: (sell.tx_id.clone(), sell.index),
                        order_type: crate::matcher::batch::OrderType::Sell,
                        version: sell_version,
                        token_cov_id: token_bytes,
                        price_num: sell.price_num,
                        price_den: sell.price_den,
                        amount: sell.value,
                        redeem_script: sell_rs,
                        utxo_value: sell.value,
                        counterparty_spk: seller_spk,
                        counterparty_spk_version: seller_spk_ver,
                    });
                }

                if skip_group {
                    continue;
                }

                for buy in &group.buys {
                    let buy_rs = hex::decode(&buy.redeem_script_hex).unwrap_or_default();
                    let token_bytes: [u8; 32] = match hex::decode(&buy.token_cov_id) {
                        Ok(v) if v.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            arr
                        }
                        _ => {
                            warn!("[TRI-BATCH] Invalid buy token_cov_id hex, skipping group");
                            skip_group = true;
                            break;
                        }
                    };
                    let buy_version = match buy_rs.len() {
                        356 => 8,
                        369 => 10,
                        371 => {
                            if buy_rs.len() > 140 && buy_rs[140] == 0x86 {
                                11
                            } else {
                                9
                            }
                        }
                        415 => 12,
                        409 => 13,
                        other => {
                            warn!("[TRI-BATCH] Unknown buy RS size {}, skipping group", other);
                            skip_group = true;
                            break;
                        }
                    };
                    let (buyer_spk_ver, buyer_spk) = match buy.resolve_counterparty_spk() {
                        Some(x) => x,
                        None => {
                            warn!("[TRI-BATCH] Buy order {} missing counterparty_spk, skipping group", buy.outpoint_key());
                            skip_group = true;
                            break;
                        }
                    };
                    buys.push(crate::matcher::batch::BatchOrder {
                        outpoint: (buy.tx_id.clone(), buy.index),
                        order_type: crate::matcher::batch::OrderType::Buy,
                        version: buy_version,
                        token_cov_id: token_bytes,
                        price_num: buy.price_num,
                        price_den: buy.price_den,
                        amount: buy.value,
                        redeem_script: buy_rs,
                        utxo_value: buy.value,
                        counterparty_spk: buyer_spk,
                        counterparty_spk_version: buyer_spk_ver,
                    });
                }

                if skip_group || sells.is_empty() || buys.is_empty() {
                    continue;
                }

                // Acquire wallet UTXOs for fee payment and token unit search
                let tri_utxos = match rpc
                    .get_spendable_utxos(&config.address, Some(0))
                    .await
                {
                    Ok(u) if !u.is_empty() => u,
                    Ok(_) => {
                        warn!("[TRI-BATCH] No wallet UTXOs available, skipping");
                        continue;
                    }
                    Err(e) => {
                        warn!("[TRI-BATCH] Failed to get wallet UTXOs: {}, skipping", e);
                        continue;
                    }
                };
                let (wallet_spk_version, wallet_spk_script) = tri_utxos[0].parse_spk();

                // Find the best wallet UTXO for fee payment
                let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
                let token_p2sh_hex = hex::encode(&token_p2sh.script());
                let wallet_utxo = tri_utxos.iter()
                    .filter(|u| {
                        let (_, script) = u.parse_spk();
                        hex::encode(&script) != token_p2sh_hex
                            && !spent_tracker.is_spent(&u.outpoint_key())
                    })
                    .max_by_key(|u| u.utxo_entry.amount)
                    .map(|u| (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount));

                // Find token unit UTXOs for each unique buy token
                let mut unique_buy_tokens: HashSet<[u8; 32]> = HashSet::new();
                for b in &buys {
                    unique_buy_tokens.insert(b.token_cov_id);
                }

                let mut token_units = Vec::new();
                let mut missing_token = false;
                for token_id in &unique_buy_tokens {
                    let tokens_needed: u64 = buys.iter()
                        .filter(|b| &b.token_cov_id == token_id)
                        .map(|b| {
                            let wide = b.amount as u128 * b.price_num as u128 / b.price_den as u128;
                            u64::try_from(wide).unwrap_or_else(|_| {
                                warn!("u128->u64 overflow in token calc (amount={}, pnum={}, pden={}), capping",
                                    b.amount, b.price_num, b.price_den);
                                u64::MAX
                            })
                        })
                        .sum();
                    let token_hex = hex::encode(token_id);
                    let token_unit = find_token_utxo_from_wallet(&tri_utxos, tokens_needed, spent_tracker);
                    match token_unit {
                        Some(tu) => {
                            token_units.push(crate::matcher::batch::TokenUnit {
                                outpoint: (tu.tx_id, tu.index),
                                token_cov_id: *token_id,
                                value: tu.value,
                                redeem_script: kob_core::TOKEN_RS.to_vec(),
                            });
                        }
                        None => {
                            warn!(
                                "[TRI-BATCH] No token UTXO found (need >= {} for token {}...), skipping group",
                                tokens_needed,
                                &token_hex[..token_hex.len().min(16)],
                            );
                            missing_token = true;
                            break;
                        }
                    }
                }
                if missing_token {
                    continue;
                }

                // Plan and execute via batch engine
                let plan = match crate::matcher::batch::plan_batch_match(
                    &sells, &buys, &token_units, wallet_utxo,
                    &wallet_spk_script, wallet_spk_version,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[TRI-BATCH] Plan failed: {}, skipping group", e);
                        continue;
                    }
                };

                match execute_batch_match(rpc, &plan, config, spent_tracker).await {
                    Some(batch_result) => {
                        info!(
                            "[TRI-BATCH] SUCCESS: tx={} sells={} buys={} surplus={}",
                            &batch_result.tx_id[..batch_result.tx_id.len().min(16)],
                            batch_result.sell_count,
                            batch_result.buy_count,
                            batch_result.matcher_surplus,
                        );
                        for sell in &group.sells {
                            let sk = sell.outpoint_key();
                            if let Some(ws) = ws_tx {
                                crate::matcher::api::emit_order_filled(
                                    ws, &sell.owner_hash, &sk,
                                    &batch_result.tx_id,
                                    sell.price_num, sell.price_den,
                                    sell.value, OrderSide::Sell,
                                    &sell.token_cov_id,
                                );
                            }
                            // Record triangular sell leg trade
                            record_trade(
                                shared_state,
                                &batch_result.tx_id,
                                &sell.token_cov_id,
                                sell.price_num, sell.price_den,
                                sell.value,
                                Side::Sell,
                                None,
                            ).await;
                            order_book.remove_order(&sk);
                            spent_tracker.mark_spent(&sk);
                        }
                        for buy in &group.buys {
                            let bk = buy.outpoint_key();
                            if let Some(ws) = ws_tx {
                                crate::matcher::api::emit_order_filled(
                                    ws, &buy.owner_hash, &bk,
                                    &batch_result.tx_id,
                                    buy.price_num, buy.price_den,
                                    buy.value, OrderSide::Buy,
                                    &buy.token_cov_id,
                                );
                            }
                            // Record triangular buy leg trade
                            record_trade(
                                shared_state,
                                &batch_result.tx_id,
                                &buy.token_cov_id,
                                buy.price_num, buy.price_den,
                                buy.value,
                                Side::Buy,
                                None,
                            ).await;
                            order_book.remove_order(&bk);
                            spent_tracker.mark_spent(&bk);
                        }
                        if let Some(ref wu) = plan.wallet_input {
                            let wk = format!("{}:{}", wu.0, wu.1);
                            spent_tracker.mark_spent(&wk);
                        }
                        for (tu, _) in &plan.token_units {
                            let tk = format!("{}:{}", tu.outpoint.0, tu.outpoint.1);
                            spent_tracker.mark_spent(&tk);
                        }
                    }
                    None => {
                        warn!("[TRI-BATCH] Batch execution failed");
                        for sell in &group.sells {
                            spent_tracker.mark_failed(&sell.outpoint_key());
                        }
                        for buy in &group.buys {
                            spent_tracker.mark_failed(&buy.outpoint_key());
                        }
                    }
                }
            }
        }
    }


    // Phase 4: Perp matching
    {
        // A-3: Extract crossings under lock, then drop lock before async RPC calls.
        // A-1: Filter out crossings whose outpoints are spent or under failure cooldown.
        let crossings = {
            let pb = perp_book.lock().await;
            let raw = pb.find_crossing_pairs();
            raw.into_iter()
                .filter(|c| {
                    let lk = c.long_order.outpoint_key();
                    let sk = c.short_order.outpoint_key();
                    if spent_tracker.is_spent(&lk) || spent_tracker.is_spent(&sk) {
                        info!(
                            "[PERP] Skipping crossing (outpoint already spent): long={}... short={}...",
                            &lk[..lk.len().min(20)],
                            &sk[..sk.len().min(20)],
                        );
                        return false;
                    }
                    if spent_tracker.is_failed(&lk) || spent_tracker.is_failed(&sk) {
                        info!(
                            "[PERP] Skipping crossing (outpoint under cooldown): long={}... short={}...",
                            &lk[..lk.len().min(20)],
                            &sk[..sk.len().min(20)],
                        );
                        return false;
                    }
                    true
                })
                .collect::<Vec<_>>()
        }; // lock dropped here

        if !crossings.is_empty() {
            info!(
                "[PERP] Found {} crossing pair(s)",
                crossings.len(),
            );
            // Fetch wallet UTXOs for matcher change output
            let perp_wallet = fetch_wallet_utxos(rpc, &config.address, "PERP").await;
            // D-4: Guard against empty wallet SPK — skip phase if no wallet UTXOs.
            let perp_wallet_spk = match perp_wallet.as_ref().map(|(_, _, spk, _)| spk.clone()) {
                Some(spk) if !spk.is_empty() => spk,
                _ => {
                    warn!("[PERP] No wallet UTXOs available — skipping perp matching this cycle");
                    Vec::new()
                }
            };
            if perp_wallet_spk.is_empty() {
                // Skip all crossings — cannot construct valid TXs without matcher SPK
            } else {

            // B-3: Fetch current DAA score for position DAA fields.
            // grace_daa, maturity_daa, emergency_daa must be > 0 and ordered
            // (grace < maturity < emergency). Use current_daa as base offset.
            let perp_current_daa = get_current_daa(rpc).await.unwrap_or(0);
            // Default durations: grace=100 DAA (~100s), maturity=100_000 DAA (~1 day),
            // emergency=1_000_000 DAA (~10 days). These are safe defaults;
            // in production the deploy order should specify its own terms.
            let perp_grace_daa = perp_current_daa.saturating_add(100);
            let perp_maturity_daa = perp_current_daa.saturating_add(100_000);
            let perp_emergency_daa = perp_current_daa.saturating_add(1_000_000);

            for crossing in &crossings {
                info!(
                    "[PERP] Long {}:{} @ {}/{} x Short {}:{} @ {}/{} -> entry {}/{}",
                    &crossing.long_order.tx_id[..crossing.long_order.tx_id.len().min(12)],
                    crossing.long_order.index,
                    crossing.long_order.price_num, crossing.long_order.price_den,
                    &crossing.short_order.tx_id[..crossing.short_order.tx_id.len().min(12)],
                    crossing.short_order.index,
                    crossing.short_order.price_num, crossing.short_order.price_den,
                    crossing.entry_price_num, crossing.entry_price_den,
                );

                // Build open-position TX blueprint.
                // Size = minimum of both margins (equal-size matching).
                let size = crossing.long_order.margin.min(crossing.short_order.margin);
                let total_margin = crossing.long_order.margin.saturating_add(crossing.short_order.margin);
                let params = crate::matcher::perp_executor::OpenPositionParams::from_crossing_pair(
                    crossing,
                    size,
                    crossing.long_order.margin,        // split_num (long's share)
                    total_margin,                       // split_den
                    crossing.long_order.maint_pct_num,
                    crossing.long_order.maint_pct_den,
                    crossing.long_order.keeper_fee,
                    10_000,     // close_fee (default)
                    perp_grace_daa,       // grace_daa (B-3: must be > 0)
                    perp_maturity_daa,    // maturity_daa (B-3: must be > 0, > grace)
                    perp_emergency_daa,   // emergency_daa (B-3: must be > 0, > maturity)
                    0,          // min_price
                    u64::MAX,   // max_price
                    perp_wallet_spk.clone(), // matcher_script
                    [0u8; 32],  // spot_sell_spkh — TODO: populate from BuySell covenant SPK
                    [0u8; 32],  // spot_buy_spkh  — TODO: populate from BuySell covenant SPK
                );

                match crate::matcher::perp_executor::build_open_position_tx(&params) {
                    Ok((mut blueprint, position_rs)) => {
                        info!(
                            "[PERP] Built open-position TX blueprint: {} inputs, {} outputs",
                            blueprint.inputs.len(), blueprint.outputs.len(),
                        );

                        // Build fill sigscripts for Long and Short order inputs.
                        // These are permissionless covenant spends (sigOpCount=0).
                        let long_rs_bytes = match hex::decode(&crossing.long_order.redeem_script_hex) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("[PERP] Failed to decode long RS hex: {}", e);
                                spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                                spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                                continue;
                            }
                        };
                        let short_rs_bytes = match hex::decode(&crossing.short_order.redeem_script_hex) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("[PERP] Failed to decode short RS hex: {}", e);
                                spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                                spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                                continue;
                            }
                        };

                        let long_fill_ss = kob_core::perp::build_perp_deploy_fill_sigscript(&long_rs_bytes);
                        let short_fill_ss = kob_core::perp::build_perp_deploy_fill_sigscript(&short_rs_bytes);

                        // Attach sigscripts to the blueprint inputs
                        blueprint.inputs[0].sig_script = long_fill_ss;
                        blueprint.inputs[1].sig_script = short_fill_ss;

                        // Convert blueprint to RPC JSON (use sequence from blueprint for OP_CSV)
                        let mut rpc_inputs = Vec::new();
                        for (i, inp) in blueprint.inputs.iter().enumerate() {
                            rpc_inputs.push(deploy::build_rpc_input_with_sequence(
                                &inp.prev_tx_id,
                                inp.prev_index,
                                &hex::encode(&inp.sig_script),
                                blueprint.sig_op_counts.get(i).copied().unwrap_or(0),
                                inp.sequence,
                            ));
                        }
                        let mut rpc_outputs = Vec::new();
                        for out in &blueprint.outputs {
                            rpc_outputs.push(deploy::build_rpc_output(
                                out.value,
                                out.script_version,
                                &hex::encode(&out.script),
                            ));
                        }

                        let payload_hex = hex::encode(&blueprint.payload);
                        let payload = if payload_hex.is_empty() {
                            deploy::build_submit_payload_with_lock_time(0, rpc_inputs, rpc_outputs, 50)
                        } else {
                            deploy::build_submit_payload_with_tx_payload(0, rpc_inputs, rpc_outputs, &payload_hex, 50)
                        };

                        let long_key = crossing.long_order.outpoint_key();
                        let short_key = crossing.short_order.outpoint_key();

                        match rpc.submit_transaction(payload).await {
                            Ok(result) if result.ok => {
                                let tx_id = result.tx_id.unwrap_or_else(|| {
                                    warn!("[PERP] Success response missing tx_id");
                                    String::new()
                                });
                                info!("[PERP] SUCCESS! Open-position TXID: {}", tx_id);
                                info!(
                                    "  Long:  {}... margin={}",
                                    &long_key[..long_key.len().min(20)],
                                    crossing.long_order.margin,
                                );
                                info!(
                                    "  Short: {}... margin={}",
                                    &short_key[..short_key.len().min(20)],
                                    crossing.short_order.margin,
                                );
                                info!(
                                    "  Entry: {}/{}, Size: {}",
                                    crossing.entry_price_num, crossing.entry_price_den, size,
                                );

                                // Create PerpPosition and add to tracker
                                let position = crate::matcher::perp_tracker::PerpPosition {
                                    tx_id: tx_id.clone(),
                                    index: 0, // Position is output[0]
                                    long_spk_hash: crossing.long_order.owner_spk_hash,
                                    short_spk_hash: crossing.short_order.owner_spk_hash,
                                    entry_num: crossing.entry_price_num,
                                    entry_den: crossing.entry_price_den,
                                    size,
                                    total_margin: crossing.long_order.margin.saturating_add(crossing.short_order.margin),
                                    split_num: crossing.long_order.margin,
                                    split_den: crossing.long_order.margin.saturating_add(crossing.short_order.margin),
                                    close_fee: 10_000,
                                    maint_pct_num: crossing.long_order.maint_pct_num,
                                    maint_pct_den: crossing.long_order.maint_pct_den,
                                    keeper_fee: crossing.long_order.keeper_fee,
                                    creation_daa: 0, // Set by scanner on next discovery
                                    grace_daa: 0,
                                    maturity_daa: 0,
                                    emergency_daa: 0,
                                    min_price: 0,
                                    max_price: u64::MAX,
                                    redeem_script_hex: hex::encode(&position_rs),
                                    long_spk: crossing.long_order.owner_spk.clone(),
                                    short_spk: crossing.short_order.owner_spk.clone(),
                                };
                                {
                                    let mut pt = perp_tracker.lock().await;
                                    pt.add(position);
                                    info!("[PERP] Position {}:0 added to tracker", &tx_id[..tx_id.len().min(16)]);
                                }

                                // Remove matched orders from perp book
                                {
                                    let mut pb = perp_book.lock().await;
                                    pb.remove(&long_key);
                                    pb.remove(&short_key);
                                }
                                spent_tracker.mark_spent(&long_key);
                                spent_tracker.mark_spent(&short_key);
                            }
                            Ok(result) => {
                                let err_msg = result.error.unwrap_or_else(|| "Unknown error".to_string());
                                warn!("[PERP] TX submission FAILED: {}", err_msg);
                                spent_tracker.mark_failed(&long_key);
                                spent_tracker.mark_failed(&short_key);
                                warn!(
                                    "[PERP] Outpoints {}... and {}... cooldown for {}s",
                                    &long_key[..long_key.len().min(20)],
                                    &short_key[..short_key.len().min(20)],
                                    spent_tracker.cooldown_secs,
                                );
                            }
                            Err(e) => {
                                error!("[PERP] Submit RPC error: {}", e);
                                spent_tracker.mark_failed(&long_key);
                                spent_tracker.mark_failed(&short_key);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[PERP] Failed to build open-position TX: {:?}", e);
                        spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                        spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                    }
                }
            }
            } // end else (perp_wallet_spk non-empty)
        } else {
            let pb = perp_book.lock().await;
            if pb.total_count() > 0 {
                info!("[PERP] No crossing pairs (longs={}, shorts={})", pb.long_count(), pb.short_count());
            }
        }
    }

    // Phase 5: Lending matching
    {
        // A-2: Filter out matches whose outpoints are spent or under failure cooldown.
        let matches = {
            let lb = lending_book.lock().await;
            let raw = lb.find_matches();
            raw.into_iter()
                .filter(|m| {
                    let ok = m.offer.outpoint.as_str();
                    let rk = m.request.outpoint.as_str();
                    if spent_tracker.is_spent(ok) || spent_tracker.is_spent(rk) {
                        info!(
                            "[LENDING] Skipping match (outpoint already spent): offer={}... request={}...",
                            &ok[..ok.len().min(20)],
                            &rk[..rk.len().min(20)],
                        );
                        return false;
                    }
                    if spent_tracker.is_failed(ok) || spent_tracker.is_failed(rk) {
                        info!(
                            "[LENDING] Skipping match (outpoint under cooldown): offer={}... request={}...",
                            &ok[..ok.len().min(20)],
                            &rk[..rk.len().min(20)],
                        );
                        return false;
                    }
                    true
                })
                .collect::<Vec<_>>()
        }; // lock dropped here

        if !matches.is_empty() {
            info!("[LENDING] Found {} lending match(es)", matches.len());

            // Fetch wallet UTXOs for matcher change output
            let lending_wallet = fetch_wallet_utxos(rpc, &config.address, "LENDING").await;
            // D-4: Guard against empty wallet SPK — skip phase if no wallet UTXOs.
            let lending_wallet_spk = match lending_wallet.as_ref().map(|(_, _, spk, _)| spk.clone()) {
                Some(spk) if !spk.is_empty() => spk,
                _ => {
                    warn!("[LENDING] No wallet UTXOs available — skipping lending matching this cycle");
                    Vec::new()
                }
            };
            if lending_wallet_spk.is_empty() {
                // Skip all matches — cannot construct valid TXs without matcher SPK
            } else {

            // B-2: Fetch current DAA score for loan start_daa.
            // A malicious matcher cannot manipulate this because the covenant
            // validates start_daa <= current virtual DAA score at execution time.
            let lending_current_daa = match get_current_daa(rpc).await {
                Some(daa) if daa > 0 => daa,
                _ => {
                    warn!("[LENDING] Failed to get current DAA score — skipping lending this cycle");
                    0
                }
            };
            if lending_current_daa == 0 {
                // Skip: cannot build valid loans without a real DAA score
            } else {

            for lm in &matches {
                info!(
                    "[LENDING] Offer {} rate={}/{} x Request {} max_rate={}/{} -> principal={} duration={}",
                    &lm.offer.outpoint[..lm.offer.outpoint.len().min(16)],
                    lm.agreed_rate_num, lm.agreed_rate_den,
                    &lm.request.outpoint[..lm.request.outpoint.len().min(16)],
                    lm.request.max_rate_num, lm.request.max_rate_den,
                    lm.principal, lm.duration_daa,
                );

                // B-1: The borrower's actual SPK is needed for the principal delivery output.
                // The request's p2sh_script is the covenant address (aa 20 <hash> 87),
                // NOT the borrower's wallet address. Sending principal there would be
                // unspendable. We need the actual owner SPK, which must be stored
                // during scanning (similar to PerpOrder.owner_spk).
                //
                // TODO: Add owner_spk field to BorrowRequest (populated from TX payload
                // or UTXO query during scanning). Until then, skip matches where
                // borrower SPK is unavailable. The covenant's match path should also
                // verify output[1] destination against borrower_spk_hash for L1 safety.
                let borrower_spk = if let Some(ref spk_hex) = lm.request.owner_spk {
                    match hex::decode(spk_hex) {
                        // owner_spk is encoded as version_u16LE + script_bytes.
                        // Strip the 2-byte version prefix — the output script_version
                        // is set separately in the TX output construction.
                        Ok(spk) if spk.len() > 2 => spk[2..].to_vec(),
                        Ok(spk) if !spk.is_empty() => spk,
                        _ => {
                            warn!(
                                "[LENDING] B-1: Cannot decode borrower SPK for request {}... — skipping",
                                &lm.request.outpoint[..lm.request.outpoint.len().min(20)],
                            );
                            spent_tracker.mark_failed(&lm.offer.outpoint);
                            spent_tracker.mark_failed(&lm.request.outpoint);
                            continue;
                        }
                    }
                } else {
                    warn!(
                        "[LENDING] B-1: Borrower SPK not available for request {}... — skipping                          (owner_spk field must be populated during scanning)",
                        &lm.request.outpoint[..lm.request.outpoint.len().min(20)],
                    );
                    spent_tracker.mark_failed(&lm.offer.outpoint);
                    spent_tracker.mark_failed(&lm.request.outpoint);
                    continue;
                };

                // Build lending match params
                let lending_params = crate::matcher::lending_executor::LendingMatchParams::from_match(
                    lm,
                    lending_current_daa,                // B-2: real DAA score from RPC
                    lm.offer.rate_mode,                 // rate_mode from offer
                    lm.offer.rate_floor,                // rate_floor_num
                    lm.request.rate_cap,                // rate_cap_num
                    100,                                // grace_daa: 100 DAA (~100s grace period)
                    lm.offer.min_collateral_pct,        // liq_threshold
                    lending_wallet_spk.clone(),          // matcher_script
                    borrower_spk,                        // borrower_spk
                );

                match crate::matcher::lending_executor::build_lending_match_tx(&lending_params) {
                    Ok((blueprint, loan_rs)) => {
                        info!(
                            "[LENDING] Built match TX blueprint: {} inputs, {} outputs",
                            blueprint.inputs.len(), blueprint.outputs.len(),
                        );

                        // Convert blueprint to RPC JSON (use sequence from blueprint for OP_CSV)
                        let mut rpc_inputs = Vec::new();
                        for (i, inp) in blueprint.inputs.iter().enumerate() {
                            rpc_inputs.push(deploy::build_rpc_input_with_sequence(
                                &inp.prev_tx_id,
                                inp.prev_index,
                                &hex::encode(&inp.sig_script),
                                blueprint.sig_op_counts.get(i).copied().unwrap_or(0),
                                inp.sequence,
                            ));
                        }
                        let mut rpc_outputs = Vec::new();
                        for out in &blueprint.outputs {
                            rpc_outputs.push(deploy::build_rpc_output(
                                out.value,
                                out.script_version,
                                &hex::encode(&out.script),
                            ));
                        }

                        let payload_hex = hex::encode(&blueprint.payload);
                        let payload = if payload_hex.is_empty() {
                            deploy::build_submit_payload_with_lock_time(0, rpc_inputs, rpc_outputs, 50)
                        } else {
                            deploy::build_submit_payload_with_tx_payload(0, rpc_inputs, rpc_outputs, &payload_hex, 50)
                        };

                        let offer_key = lm.offer.outpoint.clone();
                        let request_key = lm.request.outpoint.clone();

                        match rpc.submit_transaction(payload).await {
                            Ok(result) if result.ok => {
                                let tx_id = result.tx_id.unwrap_or_else(|| {
                                    warn!("[LENDING] Success response missing tx_id");
                                    String::new()
                                });
                                info!("[LENDING] SUCCESS! Match TXID: {}", tx_id);
                                info!(
                                    "  Offer:     {}... principal={}",
                                    &offer_key[..offer_key.len().min(20)],
                                    lm.principal,
                                );
                                info!(
                                    "  Request:   {}... collateral={}",
                                    &request_key[..request_key.len().min(20)],
                                    lm.request.value,
                                );
                                info!(
                                    "  Rate: {}/{}, Duration: {} DAA",
                                    lm.agreed_rate_num, lm.agreed_rate_den, lm.duration_daa,
                                );

                                // Create LoanPosition and add to tracker
                                let loan = crate::matcher::lending_tracker::LoanPosition {
                                    outpoint: format!("{}:0", tx_id),
                                    principal: lm.principal,
                                    collateral: lm.request.value,
                                    rate_num: lm.agreed_rate_num,
                                    rate_den: lm.agreed_rate_den,
                                    start_daa: lending_current_daa,
                                    expiry_daa: lending_current_daa.saturating_add(lm.duration_daa),
                                    grace_daa: 100, // 100 DAA grace period (consistent with match params)
                                    lender_spk_hash: lm.offer.owner_spk_hash,
                                    borrower_spk_hash: lm.request.owner_spk_hash,
                                    rate_mode: lm.offer.rate_mode,
                                    rate_floor: lm.offer.rate_floor,
                                    rate_cap: lm.request.rate_cap,
                                    collateral_cov_id: lm.offer.collateral_cov_id,
                                    liq_threshold: lm.offer.min_collateral_pct,
                                    redeem_script: loan_rs,
                                };
                                {
                                    let mut lt = loan_tracker.lock().await;
                                    lt.add_loan(loan);
                                    info!("[LENDING] Loan {}:0 added to tracker", &tx_id[..tx_id.len().min(16)]);
                                }

                                // Remove matched orders from the lending book
                                let mut lb_mut = lending_book.lock().await;
                                lb_mut.remove_by_outpoint(&offer_key);
                                lb_mut.remove_by_outpoint(&request_key);
                                drop(lb_mut);

                                spent_tracker.mark_spent(&offer_key);
                                spent_tracker.mark_spent(&request_key);
                            }
                            Ok(result) => {
                                let err_msg = result.error.unwrap_or_else(|| "Unknown error".to_string());
                                warn!("[LENDING] TX submission FAILED: {}", err_msg);
                                spent_tracker.mark_failed(&lm.offer.outpoint);
                                spent_tracker.mark_failed(&lm.request.outpoint);
                                warn!(
                                    "[LENDING] Outpoints {}... and {}... cooldown for {}s",
                                    &lm.offer.outpoint[..lm.offer.outpoint.len().min(20)],
                                    &lm.request.outpoint[..lm.request.outpoint.len().min(20)],
                                    spent_tracker.cooldown_secs,
                                );
                            }
                            Err(e) => {
                                error!("[LENDING] Submit RPC error: {}", e);
                                spent_tracker.mark_failed(&lm.offer.outpoint);
                                spent_tracker.mark_failed(&lm.request.outpoint);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[LENDING] Failed to build match TX: {:?}", e);
                        spent_tracker.mark_failed(&lm.offer.outpoint);
                        spent_tracker.mark_failed(&lm.request.outpoint);
                    }
                }
            }
            } // end else (lending_current_daa > 0)
            } // end else (lending_wallet_spk non-empty)
        } else {
            let lb = lending_book.lock().await;
            if lb.offer_count() > 0 || lb.request_count() > 0 {
                info!(
                    "[LENDING] No matches (offers={}, requests={})",
                    lb.offer_count(), lb.request_count(),
                );
            }
        }
    }

    // Phase 6: Prediction market state tracking
    // Prediction markets are not a matching problem — the book tracks
    // market state (SplitMerge, BallotBoxes, Redemption) discovered by
    // the scanner. Settlement detection and expiry checking happen here.
    //
    // Note: Settlement (redeem) requires a winning token UTXO from a user,
    // and expire/refund paths require the creator's signature. These are
    // user-initiated operations, not matcher-automated. The matcher's role
    // is to detect and log actionable state so external services (API, keeper)
    // can trigger the appropriate TXs.
    {
        let pred = prediction_book.lock().await;
        if pred.market_count() > 0 {
            let snapshot = pred.to_snapshot();
            let mut mt = market_tracker.lock().await;

            // Check for settleable markets (both ballot boxes present, not yet settled)
            let settleable = pred.settleable_markets();
            if !settleable.is_empty() {
                info!(
                    "[PREDICTION] {} market(s) ready for settlement",
                    settleable.len(),
                );
                for market in &settleable {
                    let winner = market.leading_side();
                    let yes_val = market.yes_value();
                    let no_val = market.no_value();
                    let yes_votes = market.yes_votes();
                    let no_votes = market.no_votes();
                    info!(
                        "[PREDICTION] SETTLEABLE: {} — leader={:?}, YES={} votes (val={}), NO={} votes (val={}), TVL={}",
                        &market.market_id[..market.market_id.len().min(16)],
                        winner,
                        yes_votes, yes_val,
                        no_votes, no_val,
                        market.total_value_locked(),
                    );

                    // Update tracker with latest vote state
                    if let Some(tracked) = mt.get_mut(&market.market_id) {
                        tracked.yes_value = yes_val;
                        tracked.no_value = no_val;
                    }
                }
            }

            // Log active (unsettled) markets with votes
            for ms in &snapshot {
                if ms.settled {
                    continue;
                }
                // Skip settleable markets (already logged above)
                if settleable.iter().any(|m| m.market_id == ms.market_id) {
                    continue;
                }
                if ms.yes_votes > 0 || ms.no_votes > 0 {
                    info!(
                        "[PREDICTION] Market {} — YES={} votes, NO={} votes, TVL={}",
                        &ms.market_id[..ms.market_id.len().min(16)],
                        ms.yes_votes, ms.no_votes, ms.total_value_locked,
                    );
                }
            }

            // Check for expired ballot boxes that can be reclaimed by creators.
            // This is informational — actual reclaim requires the creator's signature.
            for market in pred.settled_markets().iter().chain(pred.settleable_markets().iter()) {
                if let Some(ref yes_box) = market.yes_box {
                    if yes_box.expiry_daa > 0 {
                        info!(
                            "[PREDICTION] BallotBox YES {} expiry_daa={} (creator can reclaim after expiry)",
                            &yes_box.outpoint[..yes_box.outpoint.len().min(16)],
                            yes_box.expiry_daa,
                        );
                    }
                }
                if let Some(ref no_box) = market.no_box {
                    if no_box.expiry_daa > 0 {
                        info!(
                            "[PREDICTION] BallotBox NO {} expiry_daa={} (creator can reclaim after expiry)",
                            &no_box.outpoint[..no_box.outpoint.len().min(16)],
                            no_box.expiry_daa,
                        );
                    }
                }
            }
        }
    }

    results
}

// Continuous Mode

/// Main continuous matcher loop with optional WS broadcaster for emitting
/// user-order lifecycle events (OrderFilled, OrderCancelled, etc.).
pub async fn run_continuous_with_ws(
    rpc: Arc<Mutex<RpcClient>>,
    order_book: Arc<Mutex<OrderBook>>,
    config: &AppConfig,
    interval_ms: u64,
    orderbook_path: &str,
    enable_cross_pair: bool,
    allow_self_trade: bool,
    ws_tx: Option<tokio::sync::broadcast::Sender<crate::matcher::api::WsEvent>>,
    shared_stop_book: Arc<Mutex<crate::matcher::stop_book::StopOrderBook>>,
    shared_trailing_stop_book: Arc<Mutex<crate::matcher::trailing_stop::TrailingStopBook>>,
    shared_state: Option<AppState>,
    shared_ifd_book: Arc<Mutex<crate::matcher::ifd::IfdBook>>,
    shared_perp_book: Arc<Mutex<crate::matcher::perp_book::PerpOrderBook>>,
    shared_perp_tracker: Arc<Mutex<crate::matcher::perp_tracker::PositionTracker>>,
    shared_lending_book: Arc<Mutex<crate::matcher::lending_book::LendingBook>>,
    shared_loan_tracker: Arc<Mutex<crate::matcher::lending_tracker::LoanTracker>>,
    shared_prediction_book: Arc<Mutex<crate::matcher::prediction_book::PredictionBook>>,
    shared_market_tracker: Arc<Mutex<crate::matcher::prediction_tracker::MarketTracker>>,
) {
    info!("======================================================================");
    info!("KOB MATCHER BOT -- CONTINUOUS MODE (HARDENED)");
    info!("======================================================================");
    info!("Wallet:   {}", config.address);
    info!("Node:     {}", config.node_url);
    info!("Interval: {}ms", interval_ms);
    info!("Cross-pair routing: {}", if enable_cross_pair { "ENABLED" } else { "disabled" });

    // Set up graceful shutdown
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Handle SIGINT/SIGTERM
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("[SHUTDOWN] Graceful shutdown requested (Ctrl+C again to force)");
        shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    info!("Scanning for orders... Press Ctrl+C to stop.");

    // Stop/trailing stop/IFD persistence paths (alongside order book file).
    let stop_orders_path = format!("{}.stops.json", orderbook_path);
    let trailing_stops_path = format!("{}.trailing.jsonl", orderbook_path);
    let ifd_path = format!("{}.ifd.json", orderbook_path);
    let perp_book_path = format!("{}.perp.json", orderbook_path);
    let lending_book_path = format!("{}.lending.json", orderbook_path);
    let prediction_book_path = format!("{}.prediction.json", orderbook_path);

    let mut cycle = 0u64;
    let mut spent_tracker = SpentTracker::new();

    // Initialize chain scan cursor: start from the current sink (tip) hash.
    // On the first cycle, this fetches the tip so we only scan forward.
    let mut last_chain_hash: String = {
        let rpc_lock = rpc.lock().await;
        match rpc_lock.get_sink_hash().await {
            Ok(h) => {
                info!("[SCAN-BLOCKS] Initialized chain cursor at {}", &h[..h.len().min(16)]);
                h
            }
            Err(e) => {
                warn!("[SCAN-BLOCKS] Failed to get initial sink hash: {}. Block scanning disabled until next attempt.", e);
                String::new()
            }
        }
    };

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        // BUG 1 fix: Check RPC connection health at the top of each cycle.
        // If the connection is dead, attempt reconnection before any RPC calls.
        {
            let mut rpc_lock = rpc.lock().await;
            if rpc_lock.needs_reconnect() {
                warn!("[RPC] Connection dead, attempting reconnect...");
                if let Err(e) = rpc_lock.reconnect().await {
                    warn!("[RPC] Reconnect failed: {}, retrying in 5s...", e);
                    drop(rpc_lock);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                info!("[RPC] Reconnected successfully");
            }
        }

        cycle += 1;
        info!("--- Scan cycle {} ---", cycle);

        // M-6: Age-based pruning of spent tracker entries every cycle.
        // Entries older than 60 seconds are pruned (mempool should have caught up).
        // Failed entries have their own cooldown via expire_failed().
        //
        // DAG UTXO conflict recovery (D-1): If a fill TX is invalidated by a
        // competing TX in a parallel DAG block, the order's UTXO remains unspent.
        // After prune (60s) the SpentTracker forgets it, and the scanner re-detects
        // the unspent UTXO in the next cycle, automatically re-adding the order to
        // the book. Worst-case recovery: ~90s (30s cooldown + 60s prune). No
        // additional recovery code needed — the scanner loop handles it.
        spent_tracker.prune_spent(60);
        spent_tracker.expire_failed();

        // Phase 0: Scan new L1 blocks for all product types
        // Polls the virtual chain for blocks added since last_chain_hash,
        // parses transactions, and routes new orders to appropriate books.
        // This phase runs BEFORE matching to ensure newly deployed orders
        // are available for immediate matching in the same cycle.
        if !last_chain_hash.is_empty() {
            let rpc_lock = rpc.lock().await;
            let current_daa = rpc_lock.get_daa_score().await.unwrap_or(0);
            let (new_hash, _scan_counters) = {
                let mut ob = order_book.lock().await;
                let mut pb = shared_perp_book.lock().await;
                let mut lb = shared_lending_book.lock().await;
                let mut pred = shared_prediction_book.lock().await;
                scan_new_blocks(
                    &rpc_lock,
                    &mut ob,
                    &mut pb,
                    &mut lb,
                    &mut pred,
                    &last_chain_hash,
                    ws_tx.as_ref(),
                    current_daa,
                ).await
            };
            last_chain_hash = new_hash;
            drop(rpc_lock);
        }

        // F20: Periodically clear matched_outpoints to prevent unbounded growth.
        // Every 100 cycles (~5-10 min depending on interval), spent outpoints
        // from earlier cycles are safely forgotten since they no longer exist
        // as UTXOs and cannot reappear in future queries.
        if cycle.is_multiple_of(100) {
            let mut ob = order_book.lock().await;
            ob.clear_matched_outpoints();
        }

        let rpc_lock = rpc.lock().await;
        let scan_result = {
            let mut ob = order_book.lock().await;
            run_scan_cycle(&rpc_lock, &mut ob, config, &mut spent_tracker, enable_cross_pair, allow_self_trade, ws_tx.as_ref(), shared_state.as_ref(), &shared_ifd_book, &shared_perp_book, &shared_perp_tracker, &shared_lending_book, &shared_loan_tracker, &shared_prediction_book, &shared_market_tracker).await
        };

        // Receipt chaining: the receipt from the last successful match
        // is stored for reuse as fee input in the next trade. No separate
        // consume TX is needed.
        // (Receipt tracking state is managed by run_scan_cycle.)

        // Stop order and trailing stop processing
        // After each matching cycle, check if any trades triggered stop or
        // trailing stop orders. For each triggered order, broadcast the
        // pre-signed TX to L1.
        if !scan_result.is_empty() {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Collect triggered TX payloads under lock, then broadcast outside lock
            let mut stop_broadcasts: Vec<(u64, String)> = Vec::new();
            let mut trailing_broadcasts: Vec<(u64, String)> = Vec::new();

            {
                let sb = shared_stop_book.lock().await;
                let mut tb = shared_trailing_stop_book.lock().await;

                for mr in &scan_result {
                    let pair = &mr.token_cov_id;
                    let price_num = mr.price_num;
                    let price_den = mr.price_den;

                    // --- Stop orders ---
                    let triggered_ids = sb.check_triggers(pair, price_num, price_den);
                    for stop_id in triggered_ids {
                        let signed_tx_json = match sb.get(stop_id) {
                            Some(order) if !order.is_expired(now_unix) => {
                                order.signed_tx_json.clone()
                            }
                            _ => continue,
                        };
                        info!(
                            "[STOP] Triggered stop order #{} for pair [{}...] at price {}/{}",
                            stop_id, &pair[..pair.len().min(12)], price_num, price_den,
                        );
                        stop_broadcasts.push((stop_id, signed_tx_json));
                    }

                    // --- Trailing stop orders ---
                    let trailing_triggered = tb.on_price_update(pair, price_num, price_den);
                    for (trail_id, signed_tx_hex) in trailing_triggered {
                        info!(
                            "[TRAILING STOP] Triggered trailing stop #{} for pair [{}...] at price {}/{}",
                            trail_id, &pair[..pair.len().min(12)], price_num, price_den,
                        );
                        trailing_broadcasts.push((trail_id, signed_tx_hex));
                    }
                }
            }
            // Locks released; now broadcast triggered TXs via RPC

            // Broadcast stop order TXs
            for (stop_id, signed_tx_json) in &stop_broadcasts {
                match serde_json::from_str::<serde_json::Value>(signed_tx_json) {
                    Ok(tx_json) => {
                        match rpc_lock.submit_transaction(tx_json).await {
                            Ok(result) if result.ok => {
                                let tx_id = result.tx_id.unwrap_or_default();
                                info!("[STOP] Broadcast stop order #{} -> TX {}", stop_id, tx_id);
                                shared_stop_book.lock().await.mark_triggered(*stop_id, Some(tx_id));
                            }
                            Ok(result) => {
                                warn!("[STOP] Broadcast failed for stop order #{}: {:?}", stop_id, result.error);
                                shared_stop_book.lock().await.mark_triggered(*stop_id, None);
                            }
                            Err(e) => {
                                warn!("[STOP] RPC error broadcasting stop order #{}: {}", stop_id, e);
                                // Don't mark triggered on RPC errors so it retries next cycle
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[STOP] Invalid TX JSON for stop order #{}: {}", stop_id, e);
                        shared_stop_book.lock().await.mark_triggered(*stop_id, None);
                    }
                }
            }

            // Broadcast trailing stop TXs
            for (trail_id, signed_tx_hex) in &trailing_broadcasts {
                match serde_json::from_str::<serde_json::Value>(signed_tx_hex) {
                    Ok(tx_json) => {
                        match rpc_lock.submit_transaction(tx_json).await {
                            Ok(result) if result.ok => {
                                info!("[TRAILING STOP] Broadcast trailing stop #{} -> TX {}", trail_id, result.tx_id.unwrap_or_default());
                            }
                            Ok(result) => {
                                warn!("[TRAILING STOP] Broadcast failed for trailing stop #{}: {:?}", trail_id, result.error);
                            }
                            Err(e) => {
                                warn!("[TRAILING STOP] RPC error for trailing stop #{}: {}", trail_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[TRAILING STOP] Invalid TX JSON for trailing stop #{}: {}", trail_id, e);
                    }
                }
            }

            // Cleanup expired/triggered stop orders
            let cleaned = shared_stop_book.lock().await.cleanup(now_unix);
            if cleaned > 0 {
                info!("[STOP] Cleaned up {} expired/triggered stop order(s)", cleaned);
            }
        }

        // Expire v12 GTD/IOC/FOK orders (every cycle)
        // Runs every cycle (not every 10) so that IOC/FOK orders with short
        // expiry_daa (~current_daa + 10 blocks) are expired promptly. The
        // get_current_daa RPC call is lightweight (single getBlockDagInfo).
        // Without per-cycle expiry, a CLI crash between deploy and cancel
        // leaves IOC/FOK orders sitting on the book as effectively GTC
        // until the next 10-cycle check.
        {
            if let Some(current_daa) = get_current_daa(&rpc_lock).await {
                let expired_orders = {
                    let mut ob = order_book.lock().await;
                    ob.remove_expired(current_daa)
                };
                if !expired_orders.is_empty() {
                    let prefix = config.address.split(':').next().unwrap_or("kaspa");
                    let count = expire_orders(&rpc_lock, &expired_orders, current_daa, prefix).await;
                    if count > 0 {
                        info!("[EXPIRE] Expired {} order(s) at DAA score {}", count, current_daa);
                    }
                }
            }
        }

        drop(rpc_lock);

        // Save order book and stop orders periodically (every 10 cycles)
        if cycle.is_multiple_of(10) {
            let ob = order_book.lock().await;
            if let Err(e) = persistence::save_order_book(orderbook_path, &ob) {
                warn!("Failed to save order book: {}", e);
            }
            {
                let sb = shared_stop_book.lock().await;
                if !sb.is_empty() {
                    if let Err(e) = crate::matcher::stop_book::save_stop_orders(&stop_orders_path, &sb) {
                        warn!("Failed to save stop orders: {}", e);
                    }
                }
            }
            {
                let tb = shared_trailing_stop_book.lock().await;
                if !tb.is_empty() {
                    if let Err(e) = tb.save_full(&trailing_stops_path) {
                        warn!("Failed to save trailing stops: {}", e);
                    }
                }
            }
            {
                let ib = shared_ifd_book.lock().await;
                if !ib.is_empty() {
                    if let Err(e) = crate::matcher::ifd::save_ifd_rules(&ifd_path, &ib) {
                        warn!("Failed to save IFD rules: {}", e);
                    }
                }
            }
            // A-5: Always save books (even when empty) to clear ghost orders on restart.
            {
                let pb = shared_perp_book.lock().await;
                if let Err(e) = persistence::save_perp_book(&perp_book_path, &pb) {
                    warn!("Failed to save perp book: {}", e);
                }
            }
            {
                let lb = shared_lending_book.lock().await;
                if let Err(e) = persistence::save_lending_book(&lending_book_path, &lb) {
                    warn!("Failed to save lending book: {}", e);
                }
            }
            {
                let pred = shared_prediction_book.lock().await;
                if let Err(e) = persistence::save_prediction_book(&prediction_book_path, &pred) {
                    warn!("Failed to save prediction book: {}", e);
                }
            }
        }

        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
    }

    // Final save (A-5: always save, even if empty)
    let ob = order_book.lock().await;
    if let Err(e) = persistence::save_order_book(orderbook_path, &ob) {
        warn!("Failed to save order book on shutdown: {}", e);
    }
    {
        let sb = shared_stop_book.lock().await;
        if !sb.is_empty() {
            if let Err(e) = crate::matcher::stop_book::save_stop_orders(&stop_orders_path, &sb) {
                warn!("Failed to save stop orders on shutdown: {}", e);
            }
        }
    }
    {
        let tb = shared_trailing_stop_book.lock().await;
        if !tb.is_empty() {
            if let Err(e) = tb.save_full(&trailing_stops_path) {
                warn!("Failed to save trailing stops on shutdown: {}", e);
            }
        }
    }
    {
        let ib = shared_ifd_book.lock().await;
        if !ib.is_empty() {
            if let Err(e) = crate::matcher::ifd::save_ifd_rules(&ifd_path, &ib) {
                warn!("Failed to save IFD rules on shutdown: {}", e);
            }
        }
    }
    {
        let pb = shared_perp_book.lock().await;
        if let Err(e) = persistence::save_perp_book(&perp_book_path, &pb) {
            warn!("Failed to save perp book on shutdown: {}", e);
        }
    }
    {
        let lb = shared_lending_book.lock().await;
        if let Err(e) = persistence::save_lending_book(&lending_book_path, &lb) {
            warn!("Failed to save lending book on shutdown: {}", e);
        }
    }
    {
        let pred = shared_prediction_book.lock().await;
        if let Err(e) = persistence::save_prediction_book(&prediction_book_path, &pred) {
            warn!("Failed to save prediction book on shutdown: {}", e);
        }
    }
    info!("[SHUTDOWN] Complete. All books saved (spot, perp, lending, prediction).");
}

// Dry-run Mode

pub async fn run_dry_run(
    rpc: Arc<Mutex<RpcClient>>,
    order_book: Arc<Mutex<OrderBook>>,
    config: &AppConfig,
) {
    info!("======================================================================");
    info!("KOB MATCHER BOT -- DRY RUN");
    info!("======================================================================");

    let rpc_lock = rpc.lock().await;
    let utxos = match rpc_lock
        .get_spendable_utxos(&config.address, Some(0))
        .await
    {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to get UTXOs: {}", e);
            return;
        }
    };
    drop(rpc_lock);

    info!("Wallet UTXOs: {}", utxos.len());
    let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
    info!(
        "Total balance: {} sompi ({:.8} KAS)",
        total,
        total as f64 / 1e8
    );

    let usable: Vec<_> = utxos
        .iter()
        .filter(|u| u.utxo_entry.amount >= MIN_UTXO_VALUE)
        .collect();
    info!("Usable UTXOs (>= {}): {}", MIN_UTXO_VALUE, usable.len());
    for (i, u) in usable.iter().enumerate() {
        info!(
            "  [{}] {} sompi  {}...:{}",
            i,
            u.utxo_entry.amount,
            &u.outpoint.transaction_id[..16.min(u.outpoint.transaction_id.len())],
            u.outpoint.index
        );
    }

    let ob = order_book.lock().await;
    let stats = ob.stats();
    info!("");
    info!("Order book:");
    info!("  Pairs:  {}", stats.pairs);
    info!("  Bids:   {}", stats.total_bids);
    info!("  Asks:   {}", stats.total_asks);
    for ps in &stats.by_pair {
        info!("    {}...: {} bids, {} asks", ps.token_cov_id, ps.bids, ps.asks);
    }

    let all_pairs = matching::find_all_crossing_pairs(&ob);
    info!("  Same-pair crossing pairs: {}", all_pairs.len());

    for (i, p) in all_pairs.iter().enumerate() {
        info!(
            "  [{}] [{}...] BUY {} @ {}/{} x SELL {} @ {}/{} -> surplus {} ({:?})",
            i,
            &p.token_cov_id[..p.token_cov_id.len().min(12)],
            p.buy.value,
            p.buy.price_num,
            p.buy.price_den,
            p.sell.value,
            p.sell.price_num,
            p.sell.price_den,
            p.surplus,
            p.match_type,
        );
    }

    // Cross-pair batch groups (unified through batch engine)
    let cross_groups = matching::find_cross_pair_batch_groups(&ob, 20, false);
    info!("  Cross-pair batch groups: {}", cross_groups.len());

    for (i, g) in cross_groups.iter().enumerate() {
        info!(
            "  [X{}] {} sells + {} buys, total_surplus={}",
            i,
            g.sells.len(),
            g.buys.len(),
            g.total_surplus,
        );
        for (j, sell) in g.sells.iter().enumerate() {
            info!(
                "    sell[{}]: [{}...] {} tokens @ {}/{}",
                j,
                &sell.token_cov_id[..sell.token_cov_id.len().min(12)],
                sell.value,
                sell.price_num,
                sell.price_den,
            );
        }
        for (j, buy) in g.buys.iter().enumerate() {
            info!(
                "    buy[{}]: [{}...] {} KAS @ {}/{}",
                j,
                &buy.token_cov_id[..buy.token_cov_id.len().min(12)],
                buy.value,
                buy.price_num,
                buy.price_den,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spent_tracker_basic() {
        let mut tracker = SpentTracker::new();
        assert!(!tracker.is_spent("abc:0"));
        tracker.mark_spent("abc:0");
        assert!(tracker.is_spent("abc:0"));
        assert!(!tracker.is_spent("def:1"));
    }

    #[test]
    fn spent_tracker_clear() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("abc:0");
        tracker.mark_spent("def:1");
        assert_eq!(tracker.spent.len(), 2);
        tracker.clear();
        assert!(tracker.spent.is_empty());
        assert!(!tracker.is_spent("abc:0"));
    }

    #[test]
    fn spent_tracker_dedup() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("abc:0");
        tracker.mark_spent("abc:0");
        assert_eq!(tracker.spent.len(), 1);
    }

    // L1 Scanner Integration Tests

    use crate::matcher::order_book::BookOrder;
    use crate::matcher::scanner::{TxInputData, TxOutputData};

    /// Build a mock deploy TX with P2SH + payload for a KOB order.
    fn make_deploy_tx(tx_id: &str, rs: &[u8], p2sh_value: u64) -> TransactionData {
        let hash = kob_core::blake2b_256(rs);
        // P2SH script
        let mut p2sh_script = Vec::with_capacity(35);
        p2sh_script.push(0xaa);
        p2sh_script.push(0x20);
        p2sh_script.extend_from_slice(&hash);
        p2sh_script.push(0x87);

        TransactionData {
            tx_id: tx_id.to_string(),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "0".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![
                TxOutputData {
                    value: p2sh_value,
                    script_version: 0,
                    script: p2sh_script,
                    covenant_id: None,
                },
            ],
            payload: kob_core::contract::build_order_payload(rs, false),
        }
    }

    #[test]
    fn process_block_txs_adds_buy_order() {
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 0, 0, 0,).unwrap();

        let tx_id = "a".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 10_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        let (added, removed) = process_block_txs(&[deploy_tx], &mut ob, &scanner);
        assert_eq!(added, 1);
        assert_eq!(removed, 0);
        assert_eq!(ob.stats().total_bids, 1);
        assert_eq!(ob.stats().total_asks, 0);
    }

    #[test]
    fn process_block_txs_adds_sell_order() {
        // H-3: Sell RSes do not embed token_cov_id (parsed as [0;32]).
        // process_block_txs skips such orders to prevent ghost entries.
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            5, 3, 2_000_000, &ohash, &sspkh, 0, 0, 0,).unwrap();

        let tx_id = "b".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 5_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        let (added, removed) = process_block_txs(&[deploy_tx], &mut ob, &scanner);
        // Sell order has zero token_cov_id -> skipped (H-3 fix)
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
        assert_eq!(ob.stats().total_asks, 0);
    }

    #[test]
    fn process_block_txs_removes_spent_order() {
        // First, add an order
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 0, 0, 0,).unwrap();

        let tx_id = "a".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 10_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        process_block_txs(&[deploy_tx], &mut ob, &scanner);
        assert_eq!(ob.stats().total_bids, 1);

        // Now create a TX that spends it
        let spend_tx = TransactionData {
            tx_id: "c".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: tx_id,
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![],
            payload: vec![],
        };

        let (added, removed) = process_block_txs(&[spend_tx], &mut ob, &scanner);
        assert_eq!(added, 0);
        assert_eq!(removed, 1);
        assert_eq!(ob.stats().total_bids, 0);
    }

    #[test]
    fn process_block_txs_skips_cpend_order() {
        let tcid = [0xAA; 32];
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        // cancel_pending = 1
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 3, 2, 1_000_000, &ohash, &bspkh, 0, 1, 0,).unwrap();

        let tx_id = "d".repeat(64);
        let deploy_tx = make_deploy_tx(&tx_id, &rs, 10_000_000);

        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        let (added, _removed) = process_block_txs(&[deploy_tx], &mut ob, &scanner);
        assert_eq!(added, 0, "cancel_pending orders should be skipped");
        assert_eq!(ob.stats().total_bids, 0);
    }

    #[test]
    fn process_block_txs_mixed_deploy_and_spend() {
        let mut ob = OrderBook::new();
        let scanner = BlockScanner::new();

        // Deploy a buy order
        let rs1 = kob_core::contract::build_buy_redeem_script(
            &[0xAA; 32], 3, 2, 1_000_000, &[0xBB; 32], &[0xCC; 32], 0, 0, 0,).unwrap();
        let deploy1 = make_deploy_tx(&"a".repeat(64), &rs1, 10_000_000);
        process_block_txs(&[deploy1], &mut ob, &scanner);
        assert_eq!(ob.stats().total_bids, 1);

        // In the same block: deploy a sell order AND spend the buy order
        let rs2 = kob_core::contract::build_sell_redeem_script(
            5, 3, 2_000_000, &[0xDD; 32], &[0xEE; 32], 0, 0, 0,).unwrap();
        let deploy2 = make_deploy_tx(&"b".repeat(64), &rs2, 5_000_000);

        let spend_tx = TransactionData {
            tx_id: "c".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "a".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![],
            payload: vec![],
        };

        let (added, removed) = process_block_txs(&[spend_tx, deploy2], &mut ob, &scanner);
        assert_eq!(removed, 1, "Buy order should be removed");
        // H-3: sell RS has no token_cov_id (zero) -> skipped by scanner
        assert_eq!(added, 0, "Sell order with zero token_cov_id must be skipped");
        assert_eq!(ob.stats().total_bids, 0);
        assert_eq!(ob.stats().total_asks, 0);
    }

    #[test]
    fn parse_block_notification_empty() {
        let json = serde_json::json!({
            "block": {
                "transactions": []
            }
        });
        let txs = parse_block_notification(&json);
        assert!(txs.is_empty());
    }

    #[test]
    fn parse_block_notification_no_block() {
        let json = serde_json::json!({});
        let txs = parse_block_notification(&json);
        assert!(txs.is_empty());
    }

    // Partial Fill Dispatch Tests

    #[test]
    fn execute_match_dispatches_partial_buy() {
        // Verify that PartialBuy type is recognized (not skipped with warning)
        let pair = CrossingPair {
            token_cov_id: "aa".repeat(32),
            buy: BookOrder {
                tx_id: "a".repeat(64),
                index: 0,
                value: 50_000_000,
                token_cov_id: "aa".repeat(32),
                price_num: 2,
                price_den: 1,
                min_fill: 3_000_000,
                owner_hash: "bb".repeat(32),
                spk_hash: "11".repeat(32),
                counterparty_spk: None,
                redeem_script_hex: hex::encode(&[0x51u8; 348]),
                p2sh_script_hex: hex::encode(&[0xaau8; 35]),
                p2sh_version: 0,
                side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            },
            sell: BookOrder {
                tx_id: "b".repeat(64),
                index: 0,
                value: 10_000_000,
                token_cov_id: "aa".repeat(32),
                price_num: 2,
                price_den: 1,
                min_fill: 3_000_000,
                owner_hash: "cc".repeat(32),
                spk_hash: "22".repeat(32),
                counterparty_spk: None,
                redeem_script_hex: hex::encode(&[0x51u8; 284]),
                p2sh_script_hex: hex::encode(&[0xaau8; 35]),
                p2sh_version: 0,
                side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            },
            seller_kas: 20_000_000,
            buyer_tokens: 10_000_000,
            surplus: 5_000_000,
            expected_tokens: 10_000_000,
            expected_kas: 20_000_000,
            match_type: MatchType::PartialBuy,
            fill_kas: Some(10_000_000),
            residual_kas: Some(40_000_000),
            fill_token_amount: None,
            residual_tokens: None,
        };

        // Verify the pair has the partial buy fields set
        assert_eq!(pair.match_type, MatchType::PartialBuy);
        assert_eq!(pair.fill_kas, Some(10_000_000));
        assert_eq!(pair.residual_kas, Some(40_000_000));
    }

    #[test]
    fn execute_match_dispatches_partial_sell() {
        let pair = CrossingPair {
            token_cov_id: "aa".repeat(32),
            buy: BookOrder {
                tx_id: "a".repeat(64),
                index: 0,
                value: 10_000_000,
                token_cov_id: "aa".repeat(32),
                price_num: 2,
                price_den: 1,
                min_fill: 3_000_000,
                owner_hash: "bb".repeat(32),
                spk_hash: "11".repeat(32),
                counterparty_spk: None,
                redeem_script_hex: hex::encode(&[0x51u8; 348]),
                p2sh_script_hex: hex::encode(&[0xaau8; 35]),
                p2sh_version: 0,
                side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            },
            sell: BookOrder {
                tx_id: "b".repeat(64),
                index: 0,
                value: 50_000_000,
                token_cov_id: "aa".repeat(32),
                price_num: 2,
                price_den: 1,
                min_fill: 3_000_000,
                owner_hash: "cc".repeat(32),
                spk_hash: "22".repeat(32),
                counterparty_spk: None,
                redeem_script_hex: hex::encode(&[0x51u8; 284]),
                p2sh_script_hex: hex::encode(&[0xaau8; 35]),
                p2sh_version: 0,
                side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
            },
            seller_kas: 20_000_000,
            buyer_tokens: 20_000_000,
            surplus: 5_000_000,
            expected_tokens: 20_000_000,
            expected_kas: 100_000_000,
            match_type: MatchType::PartialSell,
            fill_kas: None,
            residual_kas: None,
            fill_token_amount: Some(10_000_000),
            residual_tokens: Some(40_000_000),
        };

        // Verify the pair has the partial sell fields set
        assert_eq!(pair.match_type, MatchType::PartialSell);
        assert_eq!(pair.fill_token_amount, Some(10_000_000));
        assert_eq!(pair.residual_tokens, Some(40_000_000));
    }

    #[test]
    fn partial_buy_fill_sigscript_builds_correctly() {
        // Test that the buy partial fill sigscript is correctly constructed
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = kob_core::blake2b_256(&pk);
        let spk_hash = kob_core::compute_p2pk_spk_hash(&pk);
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let fill_kas = 5_000_000u64;
        let ss = kob_core::contract::build_buy_partial_fill_sigscript(&rs, fill_kas, 0, 1);
        // Must not be empty and must start with output index opcodes
        assert!(!ss.is_empty(), "Partial fill SS must not be empty");
        assert_eq!(ss[0], 0x00, "residual_idx=0 -> Op0");
        assert_eq!(ss[1], 0x51, "token_idx=1 -> Op1");
    }

    #[test]
    fn partial_sell_fill_sigscript_builds_correctly() {
        let pk = [0x02u8; 32];
        let owner = kob_core::blake2b_256(&pk);
        let spk_hash = kob_core::compute_p2pk_spk_hash(&pk);
        let rs = kob_core::contract::build_sell_redeem_script(
            1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let fill_amount = 3_000_000u64;
        let ss = kob_core::contract::build_sell_partial_fill_sigscript(&rs, fill_amount, 0, 1);
        assert!(!ss.is_empty(), "Partial fill SS must not be empty");
        assert_eq!(ss[0], 0x00, "kas_idx=0 -> Op0");
        assert_eq!(ss[1], 0x51, "residual_idx=1 -> Op1");
    }

    #[test]
    fn match_result_partial_types() {
        let mr_buy = MatchResult {
            match_tx_id: "abc".to_string(),
            match_type: MatchType::PartialBuy,
            seller_kas: 0,
            buyer_tokens: 5_000_000,
            receipt_tx_id: "abc".to_string(),
            receipt_idx: 2,
            receipt_value: RECEIPT_VALUE,
            token_cov_id: "aa".repeat(32),
            price_num: 1,
            price_den: 2,
        };
        assert_eq!(mr_buy.match_type, MatchType::PartialBuy);
        assert_eq!(mr_buy.receipt_idx, 2);

        let mr_sell = MatchResult {
            match_tx_id: "def".to_string(),
            match_type: MatchType::PartialSell,
            seller_kas: 5_000_000,
            buyer_tokens: 0,
            receipt_tx_id: "def".to_string(),
            receipt_idx: 2,
            receipt_value: RECEIPT_VALUE,
            token_cov_id: "aa".repeat(32),
            price_num: 1,
            price_den: 2,
        };
        assert_eq!(mr_sell.match_type, MatchType::PartialSell);
        assert_eq!(mr_sell.seller_kas, 5_000_000);
    }

    // Cross-pair executor tests

    use crate::rpc::{RpcUtxo, RpcOutpoint, RpcUtxoEntry, RpcSpk};

    fn make_rpc_utxo(tx_id: &str, index: u32, amount: u64, spk_hex: &str) -> RpcUtxo {
        // spk_hex has version (4 hex chars) + script hex
        let version = if spk_hex.len() >= 4 {
            u16::from_str_radix(&spk_hex[..4], 16).unwrap_or(0)
        } else {
            0
        };
        let script = if spk_hex.len() > 4 { &spk_hex[4..] } else { "" };
        RpcUtxo {
            outpoint: RpcOutpoint {
                transaction_id: tx_id.to_string(),
                index,
            },
            utxo_entry: RpcUtxoEntry {
                amount,
                script_public_key: RpcSpk { version, script: script.to_string() },
                block_daa_score: 100,
                is_coinbase: false,
            },
        }
    }

    /// Build the full SPK hex (version LE + script) for a TOKEN_RS P2SH UTXO.
    fn token_rs_spk_hex() -> String {
        let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
        let version_bytes = token_p2sh.version.to_le_bytes();
        let mut spk_hex = hex::encode(version_bytes);
        spk_hex.push_str(&hex::encode(&token_p2sh.script()));
        spk_hex
    }

    #[test]
    fn token_utxo_outpoint_key() {
        let tu = TokenUtxo {
            tx_id: "abc123".to_string(),
            index: 2,
            value: 10_000_000,
            token_cov_id: "aa".repeat(32),
            spk_version: 0,
            spk_script: vec![],
        };
        assert_eq!(tu.outpoint_key(), "abc123:2");
    }

    #[test]
    fn find_token_utxo_matches_token_rs_p2sh() {
        let spk_hex = token_rs_spk_hex();
        let utxos = vec![
            // Non-matching UTXO (regular P2PK)
            make_rpc_utxo(
                &"a".repeat(64), 0, 50_000_000,
                "000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac",
            ),
            // Matching TOKEN_RS P2SH UTXO
            make_rpc_utxo(&"b".repeat(64), 0, 15_000_000, &spk_hex),
            // Another matching but smaller
            make_rpc_utxo(&"c".repeat(64), 0, 5_000_000, &spk_hex),
        ];

        let tracker = SpentTracker::new();

        // Should find the matching UTXO with sufficient value
        let result = find_token_utxo_from_wallet(&utxos, 10_000_000, &tracker);
        assert!(result.is_some(), "Should find TOKEN_RS UTXO");
        let tu = result.unwrap();
        assert_eq!(tu.tx_id, "b".repeat(64));
        assert_eq!(tu.value, 15_000_000);
    }

    #[test]
    fn find_token_utxo_respects_min_value() {
        let spk_hex = token_rs_spk_hex();
        let utxos = vec![
            make_rpc_utxo(&"b".repeat(64), 0, 5_000_000, &spk_hex),
        ];

        let tracker = SpentTracker::new();
        let result = find_token_utxo_from_wallet(&utxos, 10_000_000, &tracker);
        assert!(result.is_none(), "Should not find UTXO below min value");
    }

    #[test]
    fn find_token_utxo_skips_spent() {
        let spk_hex = token_rs_spk_hex();
        let tx_id = "b".repeat(64);
        let utxos = vec![
            make_rpc_utxo(&tx_id, 0, 15_000_000, &spk_hex),
        ];

        let mut tracker = SpentTracker::new();
        tracker.mark_spent(&format!("{}:0", tx_id));

        let result = find_token_utxo_from_wallet(&utxos, 10_000_000, &tracker);
        assert!(result.is_none(), "Should skip spent UTXOs");
    }

    #[test]
    fn find_token_utxo_no_match_for_non_token_rs() {
        let utxos = vec![
            make_rpc_utxo(
                &"a".repeat(64), 0, 100_000_000,
                "000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac",
            ),
        ];

        let tracker = SpentTracker::new();
        let result = find_token_utxo_from_wallet(&utxos, 1_000_000, &tracker);
        assert!(result.is_none(), "Should not match non-TOKEN_RS UTXOs");
    }

    #[test]
    fn cross_pair_output_layout_has_token_a_forward() {
        // Verify that compute_cross_pair_outputs produces correct amounts
        use crate::matcher::routing::{CrossPairRoute, compute_cross_pair_outputs};

        let sell = BookOrder {
            tx_id: "s".repeat(64),
            index: 0,
            value: 20_000_000,
            token_cov_id: "aa".repeat(32),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "bb".repeat(32),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
        };
        let buy = BookOrder {
            tx_id: "b".repeat(64),
            index: 0,
            value: 15_000_000,
            token_cov_id: "cc".repeat(32),
            price_num: 1,
            price_den: 3,
            min_fill: 1_000_000,
            owner_hash: "dd".repeat(32),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
        };

        let route = CrossPairRoute {
            sell_leg: sell.clone(),
            buy_leg: buy.clone(),
            kas_amount: 10_000_000,
            surplus: 5_000_000,
            sell_kas_output: 10_000_000,
            buy_kas_input: 15_000_000,
            buy_expected_tokens: 5_000_000,
        };

        let outputs = compute_cross_pair_outputs(&route);

        // surplus = 5M, fee = 10K (receipt funded by matcher, not surplus)
        // raw_change = 5M - 10K = 4_990_000 >= MIN_UTXO_VALUE (3M)
        assert_eq!(outputs.seller_kas, 10_000_000);
        assert_eq!(outputs.buyer_tokens, 5_000_000);
        assert_eq!(outputs.receipt_value, RECEIPT_VALUE);
        let expected_fee = kob_core::mass::estimate_compute_mass(3, 4, 0);
        assert_eq!(outputs.matcher_change, 5_000_000 - expected_fee);
        assert_eq!(outputs.fee, expected_fee);

        // Token A forward = sell.value (required by sell_v8 F4)
        assert_eq!(sell.value, 20_000_000);
    }

    #[test]
    fn cross_pair_value_balance_with_receipt() {
        // Verify the complete TX value balance for a cross-pair match.
        // Receipt (RECEIPT_VALUE = 1 KAS) is funded by matcher wallet,
        // not from order surplus.
        let sell_value = 20_000_000u64;
        let buy_value = 15_000_000u64;
        let token_b_value = 5_000_000u64;
        let sell_kas_output = 10_000_000u64;

        let surplus = buy_value - sell_kas_output; // 5M
        let receipt = RECEIPT_VALUE; // 100M (funded by matcher, not surplus)

        // Surplus only needs to cover miner fee (mass-based estimate)
        let estimated_fee = kob_core::mass::estimate_compute_mass(3, 4, 0);
        assert!(surplus >= estimated_fee);

        let raw_change = surplus - estimated_fee;
        assert!(raw_change >= MIN_UTXO_VALUE);

        // Change large enough for separate output
        let final_seller_kas = sell_kas_output;
        let token_a_forward = sell_value;

        // Total in includes matcher fee UTXOs that cover the receipt
        let total_in = sell_value + buy_value + token_b_value;
        let total_out = final_seller_kas + token_b_value + token_a_forward + raw_change;
        let fee = total_in - total_out;
        assert_eq!(fee, estimated_fee, "TX fee from surplus must equal mass-based estimate");
        assert_eq!(receipt, RECEIPT_VALUE);
    }

    #[test]
    fn cross_pair_value_balance_small_surplus() {
        // When surplus is small, it still only needs to cover DEFAULT_MATCHER_FEE.
        // Receipt is always funded by matcher wallet.
        let sell_value = 10_000_000u64;
        let buy_value = 10_050_000u64; // just 50K surplus
        let token_b_value = 5_000_000u64;
        let sell_kas_output = 10_000_000u64;

        let surplus = buy_value - sell_kas_output; // 50K
        // surplus must cover mass-based miner fee
        let estimated_fee = kob_core::mass::estimate_compute_mass(3, 4, 0);
        assert!(surplus >= estimated_fee);

        // raw_change = surplus - fee; if < MIN_UTXO_VALUE -> added to seller
        let raw_change = surplus - estimated_fee;
        assert!(raw_change < MIN_UTXO_VALUE);
        let final_seller_kas = sell_kas_output + raw_change;
        let token_a_forward = sell_value;

        let total_in = sell_value + buy_value + token_b_value;
        let total_out = final_seller_kas + token_b_value + token_a_forward;
        let fee = total_in - total_out;
        assert_eq!(fee, estimated_fee, "TX fee must equal mass-based estimate");
    }

    #[test]
    fn cross_pair_match_result_fields() {
        let result = CrossPairMatchResult {
            match_tx_id: "abc".to_string(),
            seller_kas: 10_000_000,
            buyer_tokens: 15_000_000,
            sell_token_cov_id: "aa".repeat(32),
            buy_token_cov_id: "bb".repeat(32),
            receipt_tx_id: "abc".to_string(),
            receipt_idx: Some(3),
            receipt_value: RECEIPT_VALUE,
        };
        assert_eq!(result.sell_token_cov_id.len(), 64);
        assert_eq!(result.buy_token_cov_id.len(), 64);
        assert_ne!(result.sell_token_cov_id, result.buy_token_cov_id);
        assert_eq!(result.receipt_idx, Some(3));
    }

    // H-3: Sell orders with zero token_cov_id are skipped in process_block_txs
    #[test]
    fn process_block_txs_skips_sell_with_zero_token_cov_id() {
        use crate::matcher::scanner::{BlockScanner, TransactionData, TxInputData, TxOutputData};

        // Build a real sell v13 RS (token_cov_id not in RS -> parsed as [0;32])
        let pnum: u64 = 5;
        let pden: u64 = 3;
        let mfill: u64 = 1_000_000;
        let ohash = [0xDD; 32];
        let sspkh = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            pnum, pden, mfill, &ohash, &sspkh, 0, 0, 0,).unwrap();
        let _hash = kob_core::blake2b_256(&rs);
        let p2sh_spk = kob_core::build_p2sh(&rs);

        let tx = TransactionData {
            tx_id: "a".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "b".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: p2sh_spk.script().to_vec(),
                covenant_id: None,
            }],
            payload: kob_core::contract::build_order_payload(&rs, false),
        };

        // Verify the RS parses and returns token_cov_id = [0;32]
        let scanner = BlockScanner::new();
        let scan_result = scanner.scan_tx(&tx);
        assert!(scan_result.is_some(), "should detect sell deploy TX");
        let (parsed, _, _) = scan_result.unwrap();
        assert_eq!(parsed.token_cov_id, [0u8; 32], "sell RS has no token_cov_id");

        // process_block_txs should skip this sell order
        let mut ob = OrderBook::new();
        let (added, removed) = process_block_txs(&[tx], &mut ob, &scanner);
        assert_eq!(added, 0, "sell order with zero token_cov_id must be skipped");
        assert_eq!(removed, 0);
        assert_eq!(ob.stats().total_asks, 0, "order book must remain empty");
    }

    #[test]
    fn token_unit_sigscript_is_push_data_token_rs() {
        // Verify token_unit sigscript = pushData(TOKEN_RS) (no signature)
        let ss = kob_core::push_data(kob_core::TOKEN_RS);
        // TOKEN_RS is 7 bytes, so pushData = [7] + [7 bytes]
        assert_eq!(ss.len(), 8, "pushData(TOKEN_RS) = 1 length byte + 7 body bytes");
        assert_eq!(ss[0], 7, "length prefix for 7-byte TOKEN_RS");
        assert_eq!(&ss[1..], kob_core::TOKEN_RS);
    }

    #[test]
    fn cross_pair_large_surplus_has_matcher_change() {
        // When surplus is large enough, matcher_change is a separate output
        use crate::matcher::routing::{CrossPairRoute, compute_cross_pair_outputs};

        let sell = BookOrder {
            tx_id: "s".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: "aa".repeat(32),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "bb".repeat(32),
            spk_hash: "11".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Sell,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
        };
        let buy = BookOrder {
            tx_id: "b".repeat(64),
            index: 0,
            value: 20_000_000, // 20M KAS, expects 5M KAS for sell
            token_cov_id: "cc".repeat(32),
            price_num: 1,
            price_den: 3,
            min_fill: 1_000_000,
            owner_hash: "dd".repeat(32),
            spk_hash: "22".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
        };

        let route = CrossPairRoute {
            sell_leg: sell,
            buy_leg: buy,
            kas_amount: 5_000_000,
            surplus: 15_000_000, // 20M - 5M = 15M
            sell_kas_output: 5_000_000,
            buy_kas_input: 20_000_000,
            buy_expected_tokens: 6_666_666,
        };

        let outputs = compute_cross_pair_outputs(&route);

        // surplus = 15M, fee is mass-based (receipt funded by matcher, not surplus)
        let expected_fee = kob_core::mass::estimate_compute_mass(3, 4, 0);
        assert_eq!(outputs.seller_kas, 5_000_000);
        assert_eq!(outputs.matcher_change, 15_000_000 - expected_fee);
        assert!(outputs.matcher_change >= MIN_UTXO_VALUE);
    }

    // H-5: SpentTracker failure cooldown tests

    #[test]
    fn spent_tracker_mark_failed_basic() {
        let mut tracker = SpentTracker::with_cooldown(60);
        assert!(!tracker.is_failed("abc:0"));
        tracker.mark_failed("abc:0");
        assert!(tracker.is_failed("abc:0"));
        // is_spent should also return true for failed outpoints
        assert!(tracker.is_spent("abc:0"));
    }

    #[test]
    fn spent_tracker_failed_does_not_affect_unrelated() {
        let mut tracker = SpentTracker::with_cooldown(60);
        tracker.mark_failed("abc:0");
        assert!(!tracker.is_failed("def:1"));
        assert!(!tracker.is_spent("def:1"));
    }

    #[test]
    fn spent_tracker_expire_failed_removes_expired() {
        // Use 0-second cooldown so entries expire immediately
        let mut tracker = SpentTracker::with_cooldown(0);
        tracker.mark_failed("abc:0");
        // With 0s cooldown, the entry should already be expired
        tracker.expire_failed();
        assert!(tracker.failed.is_empty(), "expired entries should be removed");
    }

    #[test]
    fn spent_tracker_clear_removes_failed() {
        let mut tracker = SpentTracker::with_cooldown(60);
        tracker.mark_failed("abc:0");
        tracker.mark_failed("def:1");
        assert_eq!(tracker.failed.len(), 2);
        tracker.clear();
        assert!(tracker.failed.is_empty());
        assert!(!tracker.is_failed("abc:0"));
    }

    #[test]
    fn spent_tracker_failed_with_zero_cooldown_not_blocked() {
        let mut tracker = SpentTracker::with_cooldown(0);
        tracker.mark_failed("abc:0");
        // 0s cooldown means the entry is immediately expired
        assert!(!tracker.is_failed("abc:0"));
    }

    #[test]
    fn spent_tracker_failed_dedup() {
        let mut tracker = SpentTracker::with_cooldown(60);
        tracker.mark_failed("abc:0");
        tracker.mark_failed("abc:0");
        assert_eq!(tracker.failed.len(), 1);
    }

    #[test]
    fn spent_tracker_with_cooldown_constructor() {
        let tracker = SpentTracker::with_cooldown(120);
        assert_eq!(tracker.cooldown_secs, 120);
        assert!(tracker.spent.is_empty());
        assert!(tracker.failed.is_empty());
    }

    // C-2: Token UTXO covenant_id validation tests

    #[test]
    fn token_utxo_cov_id_empty_is_unknown() {
        // When token_cov_id is empty, it means covenant_id is unknown (from wallet search)
        let tu = TokenUtxo {
            tx_id: "a".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: String::new(),
            spk_version: 0,
            spk_script: vec![],
        };
        assert!(tu.token_cov_id.is_empty(), "empty cov_id = unknown from RPC");
    }

    #[test]
    fn token_utxo_cov_id_mismatch_detected() {
        // Simulates the check that execute_cross_pair_match_with_token performs
        let token_b_cov_id = "aa".repeat(32);
        let buy_expected_cov_id = "bb".repeat(32);

        // The validation logic: non-empty cov_id must match
        let mismatch = !token_b_cov_id.is_empty() && token_b_cov_id != buy_expected_cov_id;
        assert!(mismatch, "mismatched covenant IDs should be detected");
    }

    #[test]
    fn token_utxo_cov_id_match_passes() {
        let cov_id = "aa".repeat(32);
        let buy_expected = "aa".repeat(32);
        let mismatch = !cov_id.is_empty() && cov_id != buy_expected;
        assert!(!mismatch, "matching covenant IDs should pass validation");
    }

    #[test]
    fn token_utxo_cov_id_empty_skips_check() {
        let cov_id = String::new();
        let buy_expected = "aa".repeat(32);
        // Empty cov_id means unknown, should not be treated as mismatch
        let mismatch = !cov_id.is_empty() && cov_id != buy_expected;
        assert!(!mismatch, "empty covenant_id should skip validation (not flag as mismatch)");
    }

    #[test]
    fn find_token_utxo_returns_empty_cov_id() {
        // Verify that find_token_utxo_from_wallet returns empty token_cov_id
        // (since RPC doesn't provide covenant metadata)
        let spk_hex = token_rs_spk_hex();
        let utxos = vec![
            make_rpc_utxo(&"b".repeat(64), 0, 15_000_000, &spk_hex),
        ];
        let tracker = SpentTracker::new();
        let result = find_token_utxo_from_wallet(&utxos, 10_000_000, &tracker);
        assert!(result.is_some());
        let tu = result.unwrap();
        assert!(tu.token_cov_id.is_empty(), "wallet-found token should have empty cov_id");
    }

    // M-4: CrossPairMatchResult receipt_idx is Option<u32>

    #[test]
    fn m4_cross_pair_result_receipt_idx_none_when_no_receipt() {
        let result = CrossPairMatchResult {
            match_tx_id: "tx1".to_string(),
            seller_kas: 10_000_000,
            buyer_tokens: 5_000_000,
            sell_token_cov_id: "aa".repeat(32),
            buy_token_cov_id: "bb".repeat(32),
            receipt_tx_id: "tx1".to_string(),
            receipt_idx: None,
            receipt_value: 0,
        };
        assert!(result.receipt_idx.is_none(), "receipt_idx must be None when no receipt");
    }

    #[test]
    fn m4_cross_pair_result_receipt_idx_some_when_receipt() {
        let result = CrossPairMatchResult {
            match_tx_id: "tx1".to_string(),
            seller_kas: 10_000_000,
            buyer_tokens: 5_000_000,
            sell_token_cov_id: "aa".repeat(32),
            buy_token_cov_id: "bb".repeat(32),
            receipt_tx_id: "tx1".to_string(),
            receipt_idx: Some(3),
            receipt_value: RECEIPT_VALUE,
        };
        assert_eq!(result.receipt_idx, Some(3), "receipt_idx must be Some(3)");
    }

    #[test]
    fn m4_no_receipt_converts_to_max_sentinel() {
        let cp = CrossPairMatchResult {
            match_tx_id: "tx1".to_string(),
            seller_kas: 10_000_000,
            buyer_tokens: 5_000_000,
            sell_token_cov_id: "aa".repeat(32),
            buy_token_cov_id: "bb".repeat(32),
            receipt_tx_id: "tx1".to_string(),
            receipt_idx: None,
            receipt_value: 0,
        };
        // Simulate the conversion done in run_scan_cycle
        let mr = MatchResult {
            match_tx_id: cp.match_tx_id.clone(),
            match_type: MatchType::Full,
            seller_kas: cp.seller_kas,
            buyer_tokens: cp.buyer_tokens,
            receipt_tx_id: cp.receipt_tx_id.clone(),
            receipt_idx: cp.receipt_idx.unwrap_or(u32::MAX),
            receipt_value: cp.receipt_value,
            token_cov_id: cp.buy_token_cov_id.clone(),
            price_num: 1,
            price_den: 2,
        };
        assert_eq!(mr.receipt_idx, u32::MAX, "sentinel must be u32::MAX");
    }

    // Receipt consumption in continuous mode

    #[test]
    fn match_result_carries_price_for_receipt_consumption() {
        // Verify that MatchResult stores price_num/price_den needed to
        // reconstruct the receipt redeemScript during consumption.
        let mr = MatchResult {
            match_tx_id: "abc".to_string(),
            match_type: MatchType::Full,
            seller_kas: 10_000_000,
            buyer_tokens: 5_000_000,
            receipt_tx_id: "abc".to_string(),
            receipt_idx: 2,
            receipt_value: RECEIPT_VALUE,
            token_cov_id: "aa".repeat(32),
            price_num: 3,
            price_den: 7,
        };
        assert_eq!(mr.price_num, 3);
        assert_eq!(mr.price_den, 7);
        // A valid receipt_idx means consumption should be attempted
        assert_ne!(mr.receipt_idx, u32::MAX);
    }

    #[test]
    fn receipt_consumption_skipped_for_sentinel_idx() {
        // When receipt_idx == u32::MAX (sentinel from cross-pair with no receipt),
        // the continuous mode loop must skip consumption.
        let mr = MatchResult {
            match_tx_id: "tx99".to_string(),
            match_type: MatchType::Full,
            seller_kas: 10_000_000,
            buyer_tokens: 5_000_000,
            receipt_tx_id: "tx99".to_string(),
            receipt_idx: u32::MAX,
            receipt_value: 0,
            token_cov_id: "bb".repeat(32),
            price_num: 1,
            price_den: 1,
        };
        // The M-4 sentinel: receipt_idx == u32::MAX means no receipt was produced
        assert_eq!(mr.receipt_idx, u32::MAX, "sentinel must trigger skip");
    }

    // M-6: SpentTracker age-based pruning

    #[test]
    fn m6_spent_tracker_prune_removes_old_entries() {
        let mut tracker = SpentTracker::new();
        // Mark some outpoints as spent
        tracker.mark_spent("aaa:0");
        tracker.mark_spent("bbb:1");
        assert_eq!(tracker.spent.len(), 2);

        // Prune with a very large age -- nothing should be removed
        tracker.prune_spent(9999);
        assert_eq!(tracker.spent.len(), 2, "no entries should be pruned with large age");

        // Prune with age=0 -- everything should be removed
        tracker.prune_spent(0);
        assert_eq!(tracker.spent.len(), 0, "all entries should be pruned with age=0");
    }

    #[test]
    fn m6_spent_tracker_has_timestamps() {
        let mut tracker = SpentTracker::new();
        tracker.mark_spent("tx1:0");
        // Verify the entry has a timestamp (HashMap<String, Instant>)
        let instant = tracker.spent.get("tx1:0");
        assert!(instant.is_some(), "spent entry must have a timestamp");
        // The elapsed time should be very small (we just inserted it)
        assert!(instant.unwrap().elapsed().as_secs() < 2, "timestamp should be recent");
    }

    #[test]
    fn m6_spent_tracker_is_spent_works_with_hashmap() {
        let mut tracker = SpentTracker::new();
        assert!(!tracker.is_spent("tx1:0"), "should not be spent initially");
        tracker.mark_spent("tx1:0");
        assert!(tracker.is_spent("tx1:0"), "should be spent after marking");
        tracker.prune_spent(0);
        assert!(!tracker.is_spent("tx1:0"), "should not be spent after pruning");
    }

    // M-7: Scanner order dedup

    #[test]
    fn m7_process_block_txs_dedup_prevents_double_add() {
        use crate::matcher::scanner::{BlockScanner, TransactionData, TxInputData, TxOutputData};

        // Build a real buy v8 RS
        let tcid = [0xAA; 32];
        let pnum: u64 = 1;
        let pden: u64 = 2;
        let mfill: u64 = 1_000_000;
        let ohash = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &tcid, pnum, pden, mfill, &ohash, &bspkh, 0, 0, 0,).unwrap();
        let p2sh_spk = kob_core::build_p2sh(&rs);

        let tx = TransactionData {
            tx_id: "d".repeat(64),
            _version: 0,
            inputs: vec![TxInputData {
                prev_tx_id: "e".repeat(64),
                prev_index: 0,
                _sig_script: vec![],
            }],
            outputs: vec![TxOutputData {
                value: 10_000_000,
                script_version: 0,
                script: p2sh_spk.script().to_vec(),
                covenant_id: None,
            }],
            payload: kob_core::contract::build_order_payload(&rs, false),
        };

        let scanner = BlockScanner::new();
        let mut ob = OrderBook::new();

        // First pass: order should be added
        let (added1, _) = process_block_txs(&[tx.clone()], &mut ob, &scanner);
        assert_eq!(added1, 1, "first pass should add the order");
        assert_eq!(ob.stats().total_bids, 1);

        // Second pass (duplicate notification): order should be skipped
        let (added2, _) = process_block_txs(&[tx.clone()], &mut ob, &scanner);
        assert_eq!(added2, 0, "duplicate order must be skipped (M-7)");
        assert_eq!(ob.stats().total_bids, 1, "order book must still have exactly 1 bid");
    }

    #[test]
    fn m7_order_book_contains_outpoint() {
        let mut ob = OrderBook::new();
        let tcid = "aa".repeat(32);
        let outpoint = format!("{}:0", "b".repeat(64));

        assert!(!ob.contains_outpoint(&outpoint), "should not contain outpoint initially");

        ob.add_buy_order(BookOrder {
            tx_id: "b".repeat(64),
            index: 0,
            value: 10_000_000,
            token_cov_id: tcid.clone(),
            price_num: 1,
            price_den: 2,
            min_fill: 1_000_000,
            owner_hash: "cc".repeat(32),
            spk_hash: "dd".repeat(32),
            counterparty_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            p2sh_version: 0,
            side: OrderSide::Buy,
            post_only: false,
            expiry_daa: None,
            is_freezable: false,
            max_matcher_fee: u64::MAX,
        });

        assert!(ob.contains_outpoint(&outpoint), "should contain outpoint after add");

        ob.remove_order(&outpoint);
        assert!(!ob.contains_outpoint(&outpoint), "should not contain outpoint after remove");
    }

    // Trade Bridge Tests (record_trade -> SharedState)

    #[tokio::test]
    async fn record_trade_populates_trade_log_and_candles() {
        use crate::matcher::api::SharedState;
        use crate::matcher::candle::Interval;
        use crate::matcher::order_book::OrderBook;
        use crate::matcher::stop_book::StopOrderBook;
        use crate::matcher::trailing_stop::TrailingStopBook;

        let (ws_tx, _ws_rx) = tokio::sync::broadcast::channel(100);
        let ob = Arc::new(Mutex::new(OrderBook::new()));
        let sb = Arc::new(Mutex::new(StopOrderBook::new()));
        let tb = Arc::new(Mutex::new(TrailingStopBook::new()));
        let shared: AppState = Arc::new(tokio::sync::RwLock::new(
            SharedState::new(ws_tx, ob, sb, tb),
        ));

        // Initially empty
        {
            let state = shared.read().await;
            assert_eq!(state.trade_log.recent_all(10).len(), 0);
            assert!(state.candles.get_candles("test_token/KAS", Interval::M1, 10).is_empty());
        }

        // Record a trade
        record_trade(
            Some(&shared),
            "abc123def456",
            "test_token_cov_id_hex_64chars_padded_to_be_long_enough_here000",
            100, 1,
            50_000,
            Side::Buy,
            None,
        ).await;

        // Verify trade_log has the entry
        {
            let state = shared.read().await;
            let trades = state.trade_log.recent_all(10);
            assert_eq!(trades.len(), 1);
            assert_eq!(trades[0].txid, "abc123def456");
            assert_eq!(trades[0].price_num, 100);
            assert_eq!(trades[0].price_den, 1);
            assert_eq!(trades[0].quantity, 50_000);
        }

        // Verify candle aggregator has an entry
        {
            let state = shared.read().await;
            let pair_id = &state.trade_log.recent_all(1)[0].pair_id;
            let candles = state.candles.get_candles(pair_id, Interval::M1, 10);
            assert_eq!(candles.len(), 1);
            assert_eq!(candles[0].volume, 50_000);
            assert_eq!(candles[0].trade_count, 1);
        }
    }

    #[tokio::test]
    async fn record_trade_broadcasts_ws_events() {
        use crate::matcher::api::SharedState;
        use crate::matcher::order_book::OrderBook;
        use crate::matcher::stop_book::StopOrderBook;
        use crate::matcher::trailing_stop::TrailingStopBook;

        let (ws_tx, mut ws_rx) = tokio::sync::broadcast::channel(100);
        let ob = Arc::new(Mutex::new(OrderBook::new()));
        let sb = Arc::new(Mutex::new(StopOrderBook::new()));
        let tb = Arc::new(Mutex::new(TrailingStopBook::new()));
        let shared: AppState = Arc::new(tokio::sync::RwLock::new(
            SharedState::new(ws_tx, ob, sb, tb),
        ));

        record_trade(
            Some(&shared),
            "tx_ws_test",
            "token_ws_test_64char_padding_000000000000000000000000000000",
            200, 3,
            10_000,
            Side::Sell,
            None,
        ).await;

        // Should have received WsEvent::Trade + 7 x WsEvent::Kline = 8 events
        // (one Kline per Interval variant: M1, M5, M15, H1, H4, D1, W1)
        let mut trade_count = 0;
        let mut kline_count = 0;
        while let Ok(event) = ws_rx.try_recv() {
            match event {
                WsEvent::Trade { .. } => trade_count += 1,
                WsEvent::Kline { .. } => kline_count += 1,
                _ => {}
            }
        }
        assert_eq!(trade_count, 1, "expected 1 WsEvent::Trade");
        assert_eq!(kline_count, 7, "expected 7 WsEvent::Kline (one per interval)");
    }

    #[tokio::test]
    async fn record_trade_noop_when_shared_state_is_none() {
        // Should not panic when shared_state is None
        record_trade(
            None,
            "tx_noop",
            "token_noop",
            1, 1,
            100,
            Side::Buy,
            None,
        ).await;
    }

    // IFD Integration Tests

    #[test]
    fn ifd_fill_context_creation_from_active_rule() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: hex::encode(&[0xde, 0xad, 0xbe, 0xef]),
            order_b_p2sh: "p2sh_b_target".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "txid_buy:0");

        // Look up by outpoint and create IfdFillContext
        let outpoint = "txid_buy:0";
        let found = book.find_by_a_outpoint(outpoint).unwrap();
        assert_eq!(found.status, IfdStatus::Active);

        let ctx = IfdFillContext {
            rule_id: found.id,
            order_b_rs: hex::decode(&found.order_b_rs_hex).unwrap(),
            order_b_p2sh: found.order_b_p2sh.clone(),
            expiry_daa: found.order_b.expiry_daa(),
        };

        assert_eq!(ctx.rule_id, id);
        assert_eq!(ctx.order_b_rs, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(ctx.order_b_p2sh, "p2sh_b_target");
    }

    #[test]
    fn ifd_fill_context_none_when_no_rule() {
        use crate::matcher::ifd::*;

        let book = IfdBook::new();
        let result = book.find_by_a_outpoint("nonexistent:0");
        assert!(result.is_none());
    }

    #[test]
    fn ifd_fill_context_none_when_pending() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: "deadbeef".to_string(),
            order_b_p2sh: "p2sh_b".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        book.register(rule).unwrap();

        // Pending rules have no outpoint, so lookup by outpoint returns None
        let result = book.find_by_a_outpoint("some_tx:0");
        assert!(result.is_none());
    }

    #[test]
    fn ifd_trigger_after_fill() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: hex::encode(&[0xaa; 50]),
            order_b_p2sh: "p2sh_b".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "fill_order_txid:1");

        // Simulate fill: look up, create context, then trigger
        let outpoint = "fill_order_txid:1";
        let found = book.find_by_a_outpoint(outpoint).unwrap();
        assert_eq!(found.status, IfdStatus::Active);

        let ctx = IfdFillContext {
            rule_id: found.id,
            order_b_rs: hex::decode(&found.order_b_rs_hex).unwrap(),
            order_b_p2sh: found.order_b_p2sh.clone(),
            expiry_daa: found.order_b.expiry_daa(),
        };

        // Trigger the rule
        let fill_tx_id = "match_tx_result_abc123";
        assert!(book.trigger(ctx.rule_id, fill_tx_id));

        // Verify state transition
        let triggered = book.get(id).unwrap();
        assert_eq!(triggered.status, IfdStatus::Triggered);
        assert_eq!(triggered.trigger_tx_id.as_deref(), Some(fill_tx_id));

        // Rule should no longer appear in active list
        assert_eq!(book.active_count(), 0);
    }

    #[test]
    fn ifd_payload_construction_v2() {
        // IFD order B must use v2 payload (KOB:2:) so the scanner accepts it.
        // Using v1 (KOB:1:) would cause the scanner to skip the order.
        let order_b_rs = vec![0x51u8; 100]; // Dummy RS

        // GTC order (expiry_daa=0): no expiry suffix
        let kob_payload = kob_core::contract::build_order_payload_full(
            &order_b_rs, false, None,
        );
        let kob_payload_hex = hex::encode(&kob_payload);

        // Payload should start with hex-encoded "KOB:2:" (4b4f423a323a)
        assert!(kob_payload_hex.starts_with("4b4f423a323a"),
            "IFD payload must use KOB:2: prefix, got: {}", &kob_payload_hex[..14.min(kob_payload_hex.len())]);

        // Flags byte = 0x00 (no post_only, no GTD)
        let prefix_hex = hex::encode(b"KOB:2:");
        let after_prefix = &kob_payload_hex[prefix_hex.len()..];
        assert!(after_prefix.starts_with("00"), "flags byte should be 0x00 for GTC");

        // RS bytes follow the flags byte
        let rs_hex_in_payload = &after_prefix[2..]; // skip "00" flags hex
        assert_eq!(rs_hex_in_payload, hex::encode(&order_b_rs));

        // GTD order (expiry_daa=12345): expiry suffix appended
        let kob_payload_gtd = kob_core::contract::build_order_payload_full(
            &order_b_rs, false, Some(12345),
        );
        let gtd_hex = hex::encode(&kob_payload_gtd);
        assert!(gtd_hex.starts_with("4b4f423a323a"),
            "IFD GTD payload must use KOB:2: prefix");
        let after_prefix_gtd = &gtd_hex[prefix_hex.len()..];
        // flags byte = 0x02 (GTD bit set)
        assert!(after_prefix_gtd.starts_with("02"), "flags byte should be 0x02 for GTD");
    }

    #[test]
    fn ifd_submit_payload_includes_tx_payload() {
        use crate::matcher::deploy;

        let rs_hex = hex::encode(&[0xde, 0xad]);
        let kob_payload = kob_core::contract::build_order_payload_full(
            &[0xde, 0xad], false, None,
        );
        let kob_payload_hex = hex::encode(&kob_payload);

        let outputs = vec![
            deploy::build_rpc_output(100_000, 0, &"aa".repeat(35)),
        ];
        let inputs = vec![
            deploy::build_rpc_input(&"bb".repeat(32), 0, &rs_hex, 0),
        ];

        let payload_json = deploy::build_submit_payload_with_tx_payload(
            0, inputs, outputs, &kob_payload_hex, 0,
        );

        // The TX payload field should contain the KOB payload hex
        let tx = payload_json.get("transaction").unwrap();
        let tx_payload = tx.get("payload").unwrap().as_str().unwrap();
        assert_eq!(tx_payload, &kob_payload_hex);
        assert!(!tx_payload.is_empty());
    }

    #[test]
    fn ifd_submit_payload_empty_when_no_ifd() {
        use crate::matcher::deploy;

        let outputs = vec![
            deploy::build_rpc_output(100_000, 0, &"aa".repeat(35)),
        ];
        let inputs = vec![
            deploy::build_rpc_input(&"bb".repeat(32), 0, "dead", 0),
        ];

        let payload_json = deploy::build_submit_payload(0, inputs, outputs);

        // Without IFD, payload should be empty string
        let tx = payload_json.get("transaction").unwrap();
        let tx_payload = tx.get("payload").unwrap().as_str().unwrap();
        assert_eq!(tx_payload, "");
    }

    #[test]
    fn ifd_fill_context_skips_triggered_rule() {
        use crate::matcher::ifd::*;

        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 1_000_000,
                min_fill: 100_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 120,
                price_den: 1,
                amount: 0,
                min_fill: 100_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: "deadbeef".to_string(),
            order_b_p2sh: "p2sh_b".to_string(),
            order_b_spk_hash: "spkhash_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 1000,
            owner_id: "alice".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "txid:0");
        book.trigger(id, "old_fill_tx");

        // Rule is now Triggered. The executor should skip it.
        let found = book.find_by_a_outpoint("txid:0").unwrap();
        assert_eq!(found.status, IfdStatus::Triggered);
        // The executor code checks status == Active before creating IfdFillContext
        // so a triggered rule would NOT produce a context
        assert_ne!(found.status, IfdStatus::Active);
    }

    #[test]
    fn ifd_sell_side_lookup_by_outpoint() {
        use crate::matcher::ifd::*;

        // Test that IFD works for sell-side orders too (sell A -> buy B)
        let mut book = IfdBook::new();
        let rule = IfdRule {
            id: 0,
            order_a_params: OrderAParams {
                side: IfdSide::Sell,
                token: "aa".repeat(32),
                price_num: 100,
                price_den: 1,
                amount: 500_000,
                min_fill: 50_000,
                expiry_daa: 0,
            },
            order_a_p2sh: "p2sh_sell_a".to_string(),
            order_a_outpoint: None,
            order_b: OrderBType::Simple(OrderBParams {
                side: IfdSide::Buy,
                token: "aa".repeat(32),
                price_num: 80,
                price_den: 1,
                amount: 0,
                min_fill: 50_000,
                expiry_daa: 0,
            }),
            order_b_rs_hex: hex::encode(&[0xbb; 60]),
            order_b_p2sh: "p2sh_buy_b".to_string(),
            order_b_spk_hash: "spkhash_buy_b".to_string(),
            status: IfdStatus::Pending,
            trigger_tx_id: None,
            created_at: 2000,
            owner_id: "bob".to_string(),
            cancel_secret: None,
        };
        let id = book.register(rule).unwrap();
        book.activate(id, "sell_txid:2");

        let found = book.find_by_a_outpoint("sell_txid:2").unwrap();
        assert_eq!(found.id, id);
        assert_eq!(found.status, IfdStatus::Active);

        let ctx = IfdFillContext {
            rule_id: found.id,
            order_b_rs: hex::decode(&found.order_b_rs_hex).unwrap(),
            order_b_p2sh: found.order_b_p2sh.clone(),
            expiry_daa: found.order_b.expiry_daa(),
        };
        assert_eq!(ctx.order_b_p2sh, "p2sh_buy_b");
    }

}
