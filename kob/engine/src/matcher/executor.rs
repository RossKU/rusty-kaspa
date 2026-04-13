//! Atomic match transaction construction and continuous matching loop.

use std::collections::{HashMap, HashSet};
use std::time::Instant;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

use crate::config::AppConfig;
use kob_core::MIN_UTXO_VALUE;
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

/// Trace all input sigscripts in a batch TX at debug level.
///
/// For each input, disassembles the sigscript into human-readable opcodes.
/// Covenant inputs show the full sigscript structure (args + selector + RS).
/// Wallet inputs show `P2PK(sig)`.
fn trace_batch_inputs(
    batch_tx: &crate::matcher::batch::BatchTx,
    plan: &crate::matcher::batch::BatchPlan,
) {
    use kob_core::contract::opcodes::format_script;

    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }

    let wallet_idx = if plan.wallet_input.is_some() {
        Some(batch_tx.inputs.len().saturating_sub(1))
    } else {
        None
    };

    debug!("[TRACE] ═══ Batch TX sigscript trace ({} inputs, {} outputs) ═══",
        batch_tx.inputs.len(), batch_tx.outputs.len());

    for (i, inp) in batch_tx.inputs.iter().enumerate() {
        let role = if i < plan.sells.len() {
            format!("sell[{}]", i)
        } else if i < plan.sells.len() + plan.buys.len() {
            format!("buy[{}]", i - plan.sells.len())
        } else if wallet_idx == Some(i) {
            "wallet".to_string()
        } else {
            format!("input[{}]", i)
        };

        let txid_short = &inp.tx_id[..inp.tx_id.len().min(12)];

        if wallet_idx == Some(i) {
            debug!("[TRACE]   {}  {}:{}  P2PK(sig={}B)",
                role, txid_short, inp.index, inp.sigscript.len());
            continue;
        }

        // Covenant input: disassemble sigscript
        let disasm = format_script(&inp.sigscript);

        // Split into args vs RS for readability
        // RS is always the last pushdata element (largest)
        let ss_len = inp.sigscript.len();
        debug!("[TRACE]   {}  {}:{}  sigscript({}B): {}",
            role, txid_short, inp.index, ss_len, disasm);
    }

    // Output summary
    for (i, out) in batch_tx.outputs.iter().enumerate() {
        let spk_hex = &hex::encode(&out.script_public_key);
        let spk_short = &spk_hex[..spk_hex.len().min(16)];
        debug!("[TRACE]   output[{}]  value={}  spk={}...({:?})",
            i, out.value, spk_short, out.purpose);
    }

    debug!("[TRACE] ═══ end trace ═══");
}

/// Execute an N:M batch match from a pre-built BatchPlan.
///
/// Builds the batch TX via `BatchPlan::build_tx()`, constructs a sighash TX
/// Convert a CrossingPair into (sell BatchOrder, buy BatchOrder).
/// Returns None if RS sizes are invalid or counterparty SPKs are missing.
pub(crate) fn pair_to_batch_orders(
    pair: &matching::CrossingPair,
    label: &str,
) -> Option<(crate::matcher::batch::BatchOrder, crate::matcher::batch::BatchOrder)> {
    let token_bytes: [u8; 32] = match hex::decode(&pair.sell.token_cov_id) {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => {
            warn!("[{}] Invalid token_cov_id hex, skipping pair", label);
            return None;
        }
    };

    let sell_rs = hex::decode(&pair.sell.redeem_script_hex).unwrap_or_default();
    let buy_rs = hex::decode(&pair.buy.redeem_script_hex).unwrap_or_default();

    // v14 only: sell RS=416 (112+304), OCO sell RS=333 (139+194), buy RS=396 (145+251)
    if sell_rs.len() != 416 && sell_rs.len() != kob_core::OCO_SELL_RS_SIZE {
        warn!("[{}] Unsupported sell RS size {}, skipping (v14=416, oco={})", label, sell_rs.len(), kob_core::OCO_SELL_RS_SIZE);
        return None;
    }
    if buy_rs.len() != 396 {
        warn!("[{}] Unsupported buy RS size {}, skipping (v14=396)", label, buy_rs.len());
        return None;
    }

    let (seller_spk_ver, seller_spk) = match pair.sell.resolve_counterparty_spk() {
        Some(x) => x,
        None => {
            warn!("[{}] Sell order {} missing counterparty_spk, skipping", label, pair.sell.outpoint_key());
            return None;
        }
    };
    let (buyer_spk_ver, buyer_spk) = match pair.buy.resolve_counterparty_spk() {
        Some(x) => x,
        None => {
            warn!("[{}] Buy order {} missing counterparty_spk, skipping", label, pair.buy.outpoint_key());
            return None;
        }
    };

    let sell_order = crate::matcher::batch::BatchOrder {
        outpoint: (pair.sell.tx_id.clone(), pair.sell.index),
        order_type: crate::matcher::batch::OrderType::Sell,
        version: 14,
        token_cov_id: token_bytes,
        price_num: pair.sell.price_num,
        price_den: pair.sell.price_den,
        amount: pair.sell.value,
        redeem_script: sell_rs,
        utxo_value: pair.sell.value,
        counterparty_spk: seller_spk,
        counterparty_spk_version: seller_spk_ver,
        oco_path: pair.sell.oco_path,
    };

    let buy_order = crate::matcher::batch::BatchOrder {
        outpoint: (pair.buy.tx_id.clone(), pair.buy.index),
        order_type: crate::matcher::batch::OrderType::Buy,
        version: 14,
        token_cov_id: token_bytes,
        price_num: pair.buy.price_num,
        price_den: pair.buy.price_den,
        amount: pair.buy.value,
        redeem_script: buy_rs,
        utxo_value: pair.buy.value,
        counterparty_spk: buyer_spk,
        counterparty_spk_version: buyer_spk_ver,
        oco_path: None,
    };

    Some((sell_order, buy_order))
}

/// to sign the wallet input (P2PK, last input), then submits via RPC.
///
/// The wallet input is the LAST input in the batch TX and needs `sigOpCount: 1`
/// with a Schnorr signature. All covenant inputs (sells, buys)
/// use `sigOpCount: 0`.
///
/// TX version = 1 (required for covenant output bindings on buyer token outputs).
pub async fn execute_batch_match(
    rpc: &RpcClient,
    plan: &mut crate::matcher::batch::BatchPlan,
    config: &AppConfig,
    spent_tracker: &mut SpentTracker,
    ifd_payload: Option<String>,
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
        "EXECUTING BATCH MATCH: {} sells + {} buys",
        plan.sells.len(),
        plan.buys.len(),
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
    // IFD: set TX payload on sighash_tx so sighash computation includes it.
    // The payload is part of the sighash in Kaspa — adding it only at RPC
    // submission time would invalidate all pre-computed signatures.
    if let Some(ref payload_hex) = ifd_payload {
        if let Ok(payload_bytes) = hex::decode(payload_hex) {
            sighash_tx.payload = payload_bytes;
        }
    }

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

    // Wallet sigscript — needed for compute mass check after signing
    let mut wallet_sigscript: Option<Vec<u8>> = None;

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

        // BuyerTokens and SellRemainder outputs need covenant bindings
        // (sell covenant F4 checks: covenant_output_value >= sell_input_value)
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
                    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), Some(kob_core::tx::CovenantBinding::new(tii as u16, kob_core::compat::parse_hash(&token_hex).unwrap()))));
                    continue;
                }
            }
            warn!("[BATCH] BuyerTokens output[{}] missing covenant binding", i);
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        } else if out.purpose == OutputPurpose::SellRemainder {
            // SellRemainder carries excess token value — needs covenant binding
            // to satisfy sell contract F4 (covenant output conservation).
            // Use the first sell's token_cov_id for the binding.
            if let Some((sell, _)) = plan.sells.first() {
                let token_hex = hex::encode(sell.token_cov_id);
                if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                    rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                        out.value,
                        out.spk_version,
                        &spk_hex,
                        tii as u16,
                        &token_hex,
                    ));
                    sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), Some(kob_core::tx::CovenantBinding::new(tii as u16, kob_core::compat::parse_hash(&token_hex).unwrap()))));
                    continue;
                }
            }
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        } else {
            rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
        }

        sighash_tx.outputs.push(kob_core::tx::TxOutput::new(out.value, out.spk_version, out.script_public_key.clone(), None));
    }

    // Build RPC inputs
    // Covenant inputs (sell/buy) require sequence=50 for OP_CSV compliance.
    let mut rpc_inputs = Vec::new();
    for (i, inp) in batch_tx.inputs.iter().enumerate() {
        if has_wallet && i == wallet_input_idx {
            // Wallet input: needs signing — we'll replace the sigscript below
            continue;
        }
        rpc_inputs.push(deploy::build_rpc_input_with_sequence(
            &inp.tx_id,
            inp.index,
            &hex::encode(&inp.sigscript),
            inp.sig_op_count,
            50, // OP_CSV(50) compliance
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
        wallet_sigscript = Some(wallet_ss);
    }

    // Phase 2: exact fee convergence with real sigscripts.
    // The plan's estimated fee (from estimate_compute_mass) is conservative.
    // Compute exact mass from real sigscripts and reclaim the overpayment.
    {
        let sigscripts_for_conv: Vec<Vec<u8>> = batch_tx.inputs.iter().enumerate().map(|(i, inp)| {
            if has_wallet && i == wallet_input_idx {
                wallet_sigscript.clone().unwrap_or_default()
            } else {
                inp.sigscript.clone()
            }
        }).collect();
        let (exact_fee, delta) = plan.converge_fee_exact(&sighash_tx, &sigscripts_for_conv);
        if delta > 0 {
            info!(
                "[BATCH] Phase 2 fee convergence: exact={}, delta={} (recovered)",
                exact_fee, delta
            );
            plan.apply_exact_fee(exact_fee);

            // Rebuild sighash_tx outputs from adjusted plan
            sighash_tx.outputs.clear();
            rpc_outputs.clear();
            let n = plan.sells.len();
            for (i, out) in plan.outputs.iter().enumerate() {
                let spk_hex = hex::encode(&out.script_public_key);

                if out.purpose == OutputPurpose::BuyerTokens {
                    let buy_j = i.saturating_sub(n);
                    if buy_j < plan.buys.len() {
                        let (buy, _) = &plan.buys[buy_j];
                        let token_hex = hex::encode(buy.token_cov_id);
                        if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                            rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                                out.value, out.spk_version, &spk_hex,
                                tii as u16, &token_hex,
                            ));
                            sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                                out.value, out.spk_version, out.script_public_key.clone(),
                                Some(kob_core::tx::CovenantBinding::new(
                                    tii as u16,
                                    kob_core::compat::parse_hash(&token_hex).unwrap(),
                                )),
                            ));
                            continue;
                        }
                    }
                    rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
                } else if out.purpose == OutputPurpose::SellRemainder {
                    if let Some((sell, _)) = plan.sells.first() {
                        let token_hex = hex::encode(sell.token_cov_id);
                        if let Some(&tii) = plan.token_input_map.get(&token_hex) {
                            rpc_outputs.push(deploy::build_rpc_output_with_covenant(
                                out.value, out.spk_version, &spk_hex,
                                tii as u16, &token_hex,
                            ));
                            sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                                out.value, out.spk_version, out.script_public_key.clone(),
                                Some(kob_core::tx::CovenantBinding::new(
                                    tii as u16,
                                    kob_core::compat::parse_hash(&token_hex).unwrap(),
                                )),
                            ));
                            continue;
                        }
                    }
                    rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
                } else {
                    rpc_outputs.push(deploy::build_rpc_output(out.value, out.spk_version, &spk_hex));
                }

                sighash_tx.outputs.push(kob_core::tx::TxOutput::new(
                    out.value, out.spk_version, out.script_public_key.clone(), None,
                ));
            }

            // Re-sign wallet input (outputs changed -> sighash changed)
            if has_wallet {
                // Remove old wallet rpc_input (last one) and re-sign
                rpc_inputs.pop();
                let mut privkey = config.private_key_bytes();
                let sighash = kob_core::compute_sighash(&sighash_tx, wallet_input_idx).ok()?;
                let sig = match kob_core::schnorr_sign(&sighash, &privkey) {
                    Ok(s) => s,
                    Err(e) => {
                        privkey.zeroize();
                        error!("[BATCH] Phase 2 wallet re-sign failed: {}", e);
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
                    1,
                ));
                wallet_sigscript = Some(wallet_ss);
            }
        }
    }

    // Mass pre-check: storage mass + compute mass (with real sigscripts)
    {
        let in_vals: Vec<u64> = plan.sells.iter().map(|(s, _)| s.utxo_value).chain(
            plan.buys.iter().map(|(b, _)| b.utxo_value)
        ).chain(
            plan.wallet_input.iter().map(|(_, _, val)| *val)
        ).collect();
        let out_vals: Vec<u64> = plan.outputs.iter().map(|o| o.value).collect();

        // 1. Storage mass check
        if check_mass_presubmit(&in_vals, &out_vals, "BATCH").is_none() {
            for (sell, _) in &plan.sells {
                spent_tracker.mark_failed(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1));
            }
            for (buy, _) in &plan.buys {
                spent_tracker.mark_failed(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1));
            }
            return None;
        }

        // 2. Compute mass check (with real sigscripts)
        let sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter().enumerate().map(|(i, inp)| {
            if has_wallet && i == wallet_input_idx {
                wallet_sigscript.clone().unwrap_or_default()
            } else {
                inp.sigscript.clone()
            }
        }).collect();
        let compute_mass = kob_core::mass::calc_mass_with_sigscripts(&sighash_tx, &sigscripts);
        let storage_mass = kob_core::mass::compute_storage_mass(&in_vals, &out_vals);
        let effective_mass = compute_mass.max(storage_mass);
        info!(
            "[BATCH] Mass check: compute={}, storage={}, effective={}, limit={}",
            compute_mass, storage_mass, effective_mass, kob_core::MAX_TX_MASS
        );
        if effective_mass > kob_core::MAX_TX_MASS {
            error!(
                "[BATCH] Effective mass {} exceeds limit {} — rejecting TX",
                effective_mass, kob_core::MAX_TX_MASS
            );
            for (sell, _) in &plan.sells {
                spent_tracker.mark_failed(&format!("{}:{}", sell.outpoint.0, sell.outpoint.1));
            }
            for (buy, _) in &plan.buys {
                spent_tracker.mark_failed(&format!("{}:{}", buy.outpoint.0, buy.outpoint.1));
            }
            return None;
        }
    }

    // Bytecode trace: disassemble all input sigscripts at debug level
    trace_batch_inputs(&batch_tx, plan);

    // Submit via RPC (version=1 for covenant output bindings, lockTime=50 for OP_CSV)
    let payload = match ifd_payload {
        Some(ref hex) => deploy::build_submit_payload_with_tx_payload(1, rpc_inputs, rpc_outputs, hex, 50),
        None => deploy::build_submit_payload_with_lock_time(1, rpc_inputs, rpc_outputs, 50),
    };
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
    mut ifd_book: Option<&mut crate::matcher::ifd::IfdBook>,
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

                let mut book_order = BlockScanner::to_book_order_with_tx(
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

                // IFD activation: check if this order's P2SH matches a pending IFD rule.
                // If so, set counterparty_spk from the IFD rule's order B P2SH data
                // (because bspkh points to order B's P2SH, not the owner's wallet).
                if let Some(ref mut ifd) = ifd_book {
                    let p2sh_hex = &book_order.p2sh_script_hex;
                    if let Some(rule) = ifd.find_by_a_p2sh(p2sh_hex) {
                        let rule_id = rule.id;
                        if rule.status == crate::matcher::ifd::IfdStatus::Pending {
                            // Compute order B's P2SH SPK as counterparty_spk
                            if let Ok(b_rs_bytes) = hex::decode(&rule.order_b_rs_hex) {
                                let b_p2sh_spk = kob_core::build_p2sh(&b_rs_bytes);
                                let mut spk_bytes = Vec::with_capacity(2 + b_p2sh_spk.script().len());
                                spk_bytes.extend_from_slice(&b_p2sh_spk.version.to_le_bytes());
                                spk_bytes.extend_from_slice(&b_p2sh_spk.script());
                                book_order.counterparty_spk = Some(hex::encode(&spk_bytes));
                            }
                            if ifd.activate(rule_id, &outpoint_key) {
                                info!(
                                    "[IFD] Activated rule #{} — order A detected at {}, counterparty_spk set to order B P2SH",
                                    rule_id, &outpoint_key[..outpoint_key.len().min(20)],
                                );
                            }
                        }
                    }
                }

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
            ScanResult::OcoSell(parsed, p2sh_idx, p2sh_value) => {
                if parsed.cpend != 0 {
                    info!(
                        "[SCANNER-ALL] Skipping OCO sell (cancel_pending=1): {}:{}",
                        &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    );
                    continue;
                }

                let (tp_order, sl_order) = BlockScanner::oco_sell_to_book_orders(
                    &parsed, &tx.tx_id, p2sh_idx, p2sh_value, Some(tx),
                );
                let tp_key = tp_order.outpoint_key();
                let sl_key = sl_order.outpoint_key();

                if order_book.contains_outpoint(&tp_key) {
                    continue; // dedup (both keys share the same UTXO, checking one suffices)
                }

                if tp_order.token_cov_id == "0".repeat(64) {
                    warn!(
                        "[SCANNER-ALL] Skipping OCO sell with unknown token_cov_id: {}:{}",
                        &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    );
                    continue;
                }

                info!(
                    "[SCANNER-ALL] Discovered OCO sell: {}:{} value={} TP={}/{} SL={}/{}",
                    &tx.tx_id[..tx.tx_id.len().min(16)], p2sh_idx,
                    p2sh_value, parsed.price_num_tp, parsed.price_den_tp,
                    parsed.price_num_sl, parsed.price_den_sl,
                );

                if let Some(ws) = ws_tx {
                    crate::matcher::api::emit_order_detected(
                        ws, &tp_order.owner_hash, &tp_key,
                        OrderSide::Sell, tp_order.price_num, tp_order.price_den,
                        tp_order.value, &tp_order.token_cov_id,
                    );
                    crate::matcher::api::emit_order_detected(
                        ws, &sl_order.owner_hash, &sl_key,
                        OrderSide::Sell, sl_order.price_num, sl_order.price_den,
                        sl_order.value, &sl_order.token_cov_id,
                    );
                }

                order_book.add_sell_order(tp_order);
                order_book.add_sell_order(sl_order);
                counters.spot_added += 2;
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
                None, // No IFD book in scan_new_blocks (unused path)
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
/// Handles the Kaspa wRPC `blockAddedNotification` format:
/// ```json
/// {
///   "BlockAdded": {
///     "block": {
///       "transactions": [{ ... }, ...]
///     }
///   }
/// }
/// ```
/// Also supports the simpler `{"block": {"transactions": [...]}}` form.
pub fn parse_block_notification(notification: &serde_json::Value) -> Vec<TransactionData> {
    // Try Kaspa wRPC format: params.BlockAdded.block.transactions
    let txs = notification
        .get("BlockAdded")
        .and_then(|ba| ba.get("block"))
        .and_then(|b| b.get("transactions"))
        .and_then(|t| t.as_array())
        // Fallback: params.block.transactions
        .or_else(|| {
            notification
                .get("block")
                .and_then(|b| b.get("transactions"))
                .and_then(|t| t.as_array())
        });

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
        // excluded from the remaining-pair path below.
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

                if let Some((sell_order, buy_order)) = pair_to_batch_orders(pair, "BATCH") {
                    sells.push(sell_order);
                    buys.push(buy_order);
                }
            }

            if sells.is_empty() || buys.is_empty() {
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
                    warn!("[BATCH] No wallet UTXOs available, skipping batch group");
                    continue;
                }
                Err(e) => {
                    warn!("[BATCH] Failed to get wallet UTXOs: {}, skipping batch group", e);
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

            // Plan the batch match (sell inputs provide covenant lineage directly)
            let mut plan = match crate::matcher::batch::plan_batch_match(
                &sells, &buys, wallet_utxo,
                &wallet_spk_script, wallet_spk_version,
                None,
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!("[BATCH] Plan failed: {}, skipping batch group", e);
                    continue;
                }
            };

            // IFD: scan batch group for the first order with ifd_order_b_rs_hex
            let batch_ifd_b_rs_hex: Option<&String> = group.iter().find_map(|pair| {
                pair.buy.ifd_order_b_rs_hex.as_ref()
                    .or(pair.sell.ifd_order_b_rs_hex.as_ref())
            });

            let (batch_ifd_ctx, batch_ifd_payload) = if let Some(b_rs_hex) = batch_ifd_b_rs_hex {
                // Payload-based IFD: order B RS came from deploy TX payload
                match hex::decode(b_rs_hex) {
                    Ok(rs_bytes) => {
                        let b_expiry = kob_core::contract::spot::parse_redeem_script(&rs_bytes)
                            .and_then(|p| p.expiry_daa);
                        let kob_payload = kob_core::contract::build_order_payload_full(
                            &rs_bytes, false, b_expiry,
                        );
                        (None, Some(hex::encode(&kob_payload)))
                    }
                    Err(e) => {
                        warn!("[BATCH-IFD] Failed to decode order B RS from BookOrder: {}", e);
                        (None, None)
                    }
                }
            } else {
                // Fallback: check IfdBook for engine-registered rules
                let ctx = {
                    let ifd = ifd_book.lock().await;
                    group.iter().find_map(|pair| {
                        let buy_outpoint = pair.buy.outpoint_key();
                        let sell_outpoint = pair.sell.outpoint_key();
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
                                        warn!("[BATCH-IFD] Failed to decode order B RS hex for rule {}: {}", r.id, e);
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        })
                    })
                };
                let payload = ctx.as_ref().map(|c| {
                    let expiry = if c.expiry_daa > 0 { Some(c.expiry_daa) } else { None };
                    let kob_payload = kob_core::contract::build_order_payload_full(
                        &c.order_b_rs, false, expiry,
                    );
                    hex::encode(&kob_payload)
                });
                (ctx, payload)
            };

            // Execute the batch match
            match execute_batch_match(rpc, &mut plan, config, spent_tracker, batch_ifd_payload).await {
                Some(batch_result) => {
                    // IFD trigger: mark rule as triggered after successful batch
                    if let Some(ctx) = &batch_ifd_ctx {
                        let mut ifd = ifd_book.lock().await;
                        ifd.trigger(ctx.rule_id, &batch_result.tx_id);
                        drop(ifd);
                    }

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

                        // Look up OCO partner key while order is still in book
                        let sell_oco_partner = order_book.get_order(&sk)
                            .and_then(|o| o.oco_partner_key.clone());

                        // Mark as spent to prevent re-matching; scanner will
                        // do the actual order_book removal upon block confirmation.
                        spent_tracker.mark_spent(&bk);
                        spent_tracker.mark_spent(&sk);

                        // Mark OCO partner as spent so it cannot match while pending
                        if let Some(ref partner_key) = sell_oco_partner {
                            spent_tracker.mark_spent(partner_key);
                            info!("[OCO] Marked partner spent (pending): {}", partner_key);
                        }

                        // Push MatchResult for stop/trailing stop trigger
                        results.push(MatchResult {
                            match_tx_id: batch_result.tx_id.clone(),
                            match_type: pair.match_type.clone(),
                            seller_kas: pair.seller_kas,
                            buyer_tokens: pair.buy.value,
                            receipt_tx_id: batch_result.tx_id.clone(),
                            receipt_idx: 0,
                            receipt_value: 0,
                            token_cov_id: pair.token_cov_id.clone(),
                            price_num: pair.sell.price_num,
                            price_den: pair.sell.price_den,
                        });
                    }
                    // Mark wallet outpoint as spent to prevent
                    // reuse by subsequent matches in the same scan cycle.
                    if let Some(ref wu) = plan.wallet_input {
                        let wk = format!("{}:{}", wu.0, wu.1);
                        spent_tracker.mark_spent(&wk);
                    }
                }
                None => {
                    warn!("[BATCH] Batch execution failed");
                    for pair in group {
                        spent_tracker.mark_failed(&pair.buy.outpoint_key());
                        spent_tracker.mark_failed(&pair.sell.outpoint_key());
                    }
                }
            }
        }

        // Phase 1b: Remaining pairs (partials + failed-batch fallback) via IOC/batch
        let mut remaining_by_token: HashMap<String, &CrossingPair> = HashMap::new();
        for p in &all_pairs {
            let bk = p.buy.outpoint_key();
            let sk = p.sell.outpoint_key();
            if batched_outpoints.contains(&bk) || batched_outpoints.contains(&sk) {
                continue;
            }
            let entry = remaining_by_token.entry(p.token_cov_id.clone()).or_insert(p);
            if p.surplus > entry.surplus {
                *entry = p;
            }
        }

        for (token_cov_id, best) in &remaining_by_token {
            info!(
                "  [{}...] Remaining match: {:?}, surplus={}",
                &token_cov_id[..token_cov_id.len().min(16)],
                best.match_type,
                best.surplus
            );

            // STP defense-in-depth
            if !allow_self_trade && best.buy.owner_hash == best.sell.owner_hash {
                warn!("[STP] Blocked self-trade in remaining-pair path");
                continue;
            }

            let (sell_order, buy_order) = match pair_to_batch_orders(best, "REMAINING") {
                Some(pair) => pair,
                None => continue,
            };

            // Fetch wallet UTXOs
            let rem_utxos = match rpc
                .get_spendable_utxos(&config.address, Some(0))
                .await
            {
                Ok(u) if !u.is_empty() => u,
                Ok(_) => {
                    warn!("[REMAINING] No wallet UTXOs available, skipping");
                    continue;
                }
                Err(e) => {
                    warn!("[REMAINING] Failed to get wallet UTXOs: {}, skipping", e);
                    continue;
                }
            };
            let (wallet_spk_version, wallet_spk_script) = rem_utxos[0].parse_spk();
            let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
            let token_p2sh_hex = hex::encode(&token_p2sh.script());
            let wallet_utxo = rem_utxos.iter()
                .filter(|u| {
                    let (_, script) = u.parse_spk();
                    hex::encode(&script) != token_p2sh_hex
                        && !spent_tracker.is_spent(&u.outpoint_key())
                })
                .max_by_key(|u| u.utxo_entry.amount)
                .map(|u| (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount));

            // IFD: check BookOrder payload first, fall back to IfdBook
            let ifd_b_rs_hex = best.buy.ifd_order_b_rs_hex.as_ref()
                .or(best.sell.ifd_order_b_rs_hex.as_ref());

            let (ifd_ctx, ifd_payload) = if let Some(b_rs_hex) = ifd_b_rs_hex {
                // Payload-based IFD: order B RS came from deploy TX payload
                match hex::decode(b_rs_hex) {
                    Ok(rs_bytes) => {
                        // Extract expiry from order B's redeemScript state bytes.
                        // Use spot::parse directly to avoid ambiguous glob reexport.
                        let b_expiry = kob_core::contract::spot::parse_redeem_script(&rs_bytes)
                            .and_then(|p| p.expiry_daa);
                        let kob_payload = kob_core::contract::build_order_payload_full(
                            &rs_bytes, false, b_expiry,
                        );
                        (None, Some(hex::encode(&kob_payload)))
                    }
                    Err(e) => {
                        warn!("[IFD] Failed to decode order B RS from BookOrder: {}", e);
                        (None, None)
                    }
                }
            } else {
                // Fallback: check IfdBook for engine-registered rules
                let ctx = {
                    let ifd = ifd_book.lock().await;
                    let buy_outpoint = best.buy.outpoint_key();
                    let sell_outpoint = best.sell.outpoint_key();
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
                let payload = ctx.as_ref().map(|c| {
                    let expiry = if c.expiry_daa > 0 { Some(c.expiry_daa) } else { None };
                    let kob_payload = kob_core::contract::build_order_payload_full(
                        &c.order_b_rs, false, expiry,
                    );
                    hex::encode(&kob_payload)
                });
                (ctx, payload)
            };

            // Plan based on match type
            let plan_result = match best.match_type {
                MatchType::PartialBuy => {
                    // Buy > Sell: buy IOC sweeps 1 sell
                    crate::matcher::batch::plan_ioc_match(
                        &[sell_order], &buy_order, wallet_utxo,
                        &wallet_spk_script, wallet_spk_version, None,
                    )
                }
                MatchType::PartialSell => {
                    // Sell > Buy: sell IOC sweeps 1 buy
                    crate::matcher::batch::plan_sell_ioc_match(
                        &sell_order, &[buy_order], wallet_utxo,
                        &wallet_spk_script, wallet_spk_version, None,
                    )
                }
                MatchType::Full => {
                    // Fallback full pair (failed batch grouping)
                    crate::matcher::batch::plan_batch_match(
                        &[sell_order], &[buy_order], wallet_utxo,
                        &wallet_spk_script, wallet_spk_version, None,
                    )
                }
            };

            let mut plan = match plan_result {
                Ok(p) => p,
                Err(e) => {
                    warn!("[REMAINING] Plan failed for [{}...]: {}", &token_cov_id[..token_cov_id.len().min(16)], e);
                    spent_tracker.mark_failed(&best.buy.outpoint_key());
                    spent_tracker.mark_failed(&best.sell.outpoint_key());
                    continue;
                }
            };

            match execute_batch_match(rpc, &mut plan, config, spent_tracker, ifd_payload).await {
                Some(batch_result) => {
                    // IFD trigger
                    if let Some(ctx) = &ifd_ctx {
                        let mut ifd = ifd_book.lock().await;
                        ifd.trigger(ctx.rule_id, &batch_result.tx_id);
                        drop(ifd);
                    }

                    let buy_key = best.buy.outpoint_key();
                    let sell_key = best.sell.outpoint_key();

                    // WS events — both sides fully consumed via batch/IOC
                    if let Some(ws) = ws_tx {
                        crate::matcher::api::emit_order_filled(
                            ws, &best.buy.owner_hash, &buy_key,
                            &batch_result.tx_id,
                            best.buy.price_num, best.buy.price_den,
                            best.buy.value, OrderSide::Buy, token_cov_id,
                        );
                        crate::matcher::api::emit_order_filled(
                            ws, &best.sell.owner_hash, &sell_key,
                            &batch_result.tx_id,
                            best.sell.price_num, best.sell.price_den,
                            best.sell.value, OrderSide::Sell, token_cov_id,
                        );
                    }

                    // Record trade
                    let trade_qty = best.seller_kas;
                    record_trade(
                        shared_state,
                        &batch_result.tx_id,
                        token_cov_id,
                        best.sell.price_num, best.sell.price_den,
                        trade_qty,
                        Side::Buy,
                        None,
                    ).await;

                    // Look up OCO partner key while order is still in book
                    let sell_oco_partner = order_book.get_order(&sell_key)
                        .and_then(|o| o.oco_partner_key.clone());

                    // Mark as spent to prevent re-matching; scanner will
                    // do the actual order_book removal upon block confirmation.
                    spent_tracker.mark_spent(&buy_key);
                    spent_tracker.mark_spent(&sell_key);

                    // Mark OCO partner as spent so it cannot match while pending
                    if let Some(ref partner_key) = sell_oco_partner {
                        spent_tracker.mark_spent(partner_key);
                        info!("[OCO] Marked partner spent (pending): {}", partner_key);
                    }

                    if let Some(ref wu) = plan.wallet_input {
                        let wk = format!("{}:{}", wu.0, wu.1);
                        spent_tracker.mark_spent(&wk);
                    }

                    // Push MatchResult for stop/trailing stop trigger
                    results.push(MatchResult {
                        match_tx_id: batch_result.tx_id.clone(),
                        match_type: best.match_type.clone(),
                        seller_kas: best.seller_kas,
                        buyer_tokens: best.buy.value,
                        receipt_tx_id: batch_result.tx_id.clone(),
                        receipt_idx: 0,
                        receipt_value: 0,
                        token_cov_id: token_cov_id.clone(),
                        price_num: best.sell.price_num,
                        price_den: best.sell.price_den,
                    });
                }
                None => {
                    let buy_key = best.buy.outpoint_key();
                    let sell_key = best.sell.outpoint_key();
                    spent_tracker.mark_failed(&buy_key);
                    spent_tracker.mark_failed(&sell_key);
                    warn!(
                        "[REMAINING] Execution failed for {}... and {}...",
                        &buy_key[..buy_key.len().min(20)],
                        &sell_key[..sell_key.len().min(20)],
                    );
                }
            }
        }
    }

    // Phase 2: Cross-pair batch — combine same-pair crossings from different
    // tokens into one atomic TX for fee efficiency.
    // The BATCH path (Phase 1a) and REMAINING path (Phase 1b) already called
    // spent_tracker.mark_spent() for all claimed outpoints, so passing
    // spent_tracker.spent is sufficient to avoid double-matching.
    if enable_cross_pair {
        let cross_spent: HashSet<String> = spent_tracker.spent.keys().cloned().collect();
        let cross_groups = matching::find_cross_pair_batch_groups(
            order_book, 10, allow_self_trade, Some(&cross_spent),
        );

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
                    if sell_rs.len() != 416 && sell_rs.len() != kob_core::OCO_SELL_RS_SIZE {
                        warn!("[CROSS-BATCH] Unsupported sell RS size {}, skipping group (v14=416, oco={})", sell_rs.len(), kob_core::OCO_SELL_RS_SIZE);
                        skip_group = true;
                        break;
                    }
                    let sell_version = 14u8;
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
                        oco_path: sell.oco_path,
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
                    if buy_rs.len() != 396 {
                        warn!("[CROSS-BATCH] Unsupported buy RS size {}, skipping group (v14=396)", buy_rs.len());
                        skip_group = true;
                        break;
                    }
                    let buy_version = 14u8;
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
                        oco_path: None,
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

                // Plan and execute via batch engine (sell inputs provide covenant lineage)
                let mut plan = match crate::matcher::batch::plan_batch_match(
                    &sells, &buys, wallet_utxo,
                    &wallet_spk_script, wallet_spk_version,
                    None,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[CROSS-BATCH] Plan failed: {}, skipping group", e);
                        continue;
                    }
                };

                match execute_batch_match(rpc, &mut plan, config, spent_tracker, None).await {
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
                            // Look up OCO partner key while order is still in book
                            let sell_oco_partner = order_book.get_order(&sk)
                                .and_then(|o| o.oco_partner_key.clone());
                            // Mark as spent; scanner removes on confirmation
                            spent_tracker.mark_spent(&sk);
                            // Mark OCO partner as spent so it cannot match while pending
                            if let Some(ref partner_key) = sell_oco_partner {
                                spent_tracker.mark_spent(partner_key);
                                info!("[OCO] Marked partner spent (pending): {}", partner_key);
                            }
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
                            // Mark as spent; scanner removes on confirmation
                            spent_tracker.mark_spent(&bk);
                        }
                        if let Some(ref wu) = plan.wallet_input {
                            let wk = format!("{}:{}", wu.0, wu.1);
                            spent_tracker.mark_spent(&wk);
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
                    if sell_rs.len() != 416 && sell_rs.len() != kob_core::OCO_SELL_RS_SIZE {
                        warn!("[TRI-BATCH] Unsupported sell RS size {}, skipping group (v14=416, oco={})", sell_rs.len(), kob_core::OCO_SELL_RS_SIZE);
                        skip_group = true;
                        break;
                    }
                    let sell_version = 14u8;
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
                        oco_path: sell.oco_path,
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
                    if buy_rs.len() != 396 {
                        warn!("[TRI-BATCH] Unsupported buy RS size {}, skipping group (v14=396)", buy_rs.len());
                        skip_group = true;
                        break;
                    }
                    let buy_version = 14u8;
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
                        oco_path: None,
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

                // Plan and execute via batch engine (sell inputs provide covenant lineage)
                let mut plan = match crate::matcher::batch::plan_batch_match(
                    &sells, &buys, wallet_utxo,
                    &wallet_spk_script, wallet_spk_version,
                    None,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[TRI-BATCH] Plan failed: {}, skipping group", e);
                        continue;
                    }
                };

                match execute_batch_match(rpc, &mut plan, config, spent_tracker, None).await {
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
                            // Look up OCO partner key while order is still in book
                            let sell_oco_partner = order_book.get_order(&sk)
                                .and_then(|o| o.oco_partner_key.clone());
                            // Mark as spent; scanner removes on confirmation
                            spent_tracker.mark_spent(&sk);
                            // Mark OCO partner as spent so it cannot match while pending
                            if let Some(ref partner_key) = sell_oco_partner {
                                spent_tracker.mark_spent(partner_key);
                                info!("[OCO] Marked partner spent (pending): {}", partner_key);
                            }
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
                            // Mark as spent; scanner removes on confirmation
                            spent_tracker.mark_spent(&bk);
                        }
                        if let Some(ref wu) = plan.wallet_input {
                            let wk = format!("{}:{}", wu.0, wu.1);
                            spent_tracker.mark_spent(&wk);
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

            // Compute matcher SPK hash for canonical settlement spot orders.
            let matcher_spk_hash = kob_core::compute_spk_hash(0, &perp_wallet_spk);

            // Get the token_cov_id from the spot order book (first tracked pair).
            // The perp book is single-instrument; the spot pair provides the underlying.
            let settlement_token_cov_id: Option<[u8; 32]> = order_book
                .pair_books
                .keys()
                .next()
                .and_then(|hex_id| {
                    let bytes = hex::decode(hex_id).ok()?;
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    } else {
                        None
                    }
                });

            if settlement_token_cov_id.is_none() {
                warn!("[PERP] No spot pair in order book — cannot compute settlement SPK hashes; skipping perp crossings");
            }

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

                // Compute canonical settlement spot SPK hashes for atomic settle
                // paths (2,3,4). Uses deterministic buy/sell RSes with canonical
                // parameters (entry price, matcher as owner, no expiry).
                let (spot_sell_spkh, spot_buy_spkh) = match &settlement_token_cov_id {
                    Some(tcid) => {
                        match kob_core::perp::compute_settlement_spot_spk_hashes(
                            tcid,
                            crossing.entry_price_num,
                            crossing.entry_price_den,
                            &matcher_spk_hash,
                        ) {
                            Some(hashes) => hashes,
                            None => {
                                warn!(
                                    "[PERP] Failed to build settlement RS for entry={}/{}",
                                    crossing.entry_price_num, crossing.entry_price_den,
                                );
                                spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                                spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                                continue;
                            }
                        }
                    }
                    None => {
                        // No spot pair — already warned above; skip all crossings.
                        spent_tracker.mark_failed(&crossing.long_order.outpoint_key());
                        spent_tracker.mark_failed(&crossing.short_order.outpoint_key());
                        continue;
                    }
                };

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
                    spot_sell_spkh,
                    spot_buy_spkh,
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

    // Subscribe to BlockAdded notifications for event-driven scanning.
    // This replaces the old getVirtualChainFromBlock polling loop.
    let mut notif_rx = {
        let rpc_lock = rpc.lock().await;
        match rpc_lock.subscribe("BlockAdded").await {
            Ok(_) => info!("[SUBSCRIBE] Subscribed to BlockAdded notifications"),
            Err(e) => warn!("[SUBSCRIBE] Failed to subscribe to BlockAdded: {}. Will retry on reconnect.", e),
        }
        rpc_lock.take_notification_receiver().await
            .expect("notification receiver already taken")
    };

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        // BUG 1 fix: Check RPC connection health at the top of each cycle.
        // If the connection is dead, attempt reconnection before any RPC calls.
        // On reconnect, re-subscribe and take the new notification receiver.
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
                // Re-subscribe after reconnect
                match rpc_lock.subscribe("BlockAdded").await {
                    Ok(_) => info!("[SUBSCRIBE] Re-subscribed to BlockAdded notifications"),
                    Err(e) => warn!("[SUBSCRIBE] Failed to re-subscribe: {}", e),
                }
                if let Some(new_rx) = rpc_lock.take_notification_receiver().await {
                    notif_rx = new_rx;
                }
            }
        }

        cycle += 1;
        debug!("--- Scan cycle {} ---", cycle);

        // M-6: Age-based pruning of spent tracker entries every cycle.
        spent_tracker.prune_spent(60);
        spent_tracker.expire_failed();

        // Phase 0: Process block notifications (event-driven).
        // Drain all pending blockAddedNotification messages and process
        // their transactions. This replaces the old getVirtualChainFromBlock
        // polling approach, reducing latency from 5s+ to sub-second.
        {
            let scanner = BlockScanner::new();
            let mut blocks_processed = 0u64;
            let mut total_counters = ScanCounters::default();

            // Collect all queued block notifications first, then batch-process.
            // This avoids per-block RPC calls and lock contention.
            let mut block_txs_batch: Vec<Vec<TransactionData>> = Vec::new();
            loop {
                match notif_rx.try_recv() {
                    Ok(notif) => {
                        let method = notif.get("method").and_then(|m| m.as_str()).unwrap_or("");
                        if method != "blockAddedNotification" {
                            continue;
                        }
                        // Extract block from params.BlockAdded.block
                        // Kaspa wRPC format: {"params": {"BlockAdded": {"block": {...}}}}
                        let block = match notif.get("params")
                            .and_then(|p| p.get("BlockAdded").or_else(|| p.get("block")))
                            .and_then(|ba| ba.get("block").or(Some(ba)))
                        {
                            Some(b) => b,
                            None => continue,
                        };
                        let txs: Vec<TransactionData> = block
                            .get("transactions")
                            .and_then(|t| t.as_array())
                            .map(|arr| arr.iter().filter_map(TransactionData::from_rpc_json).collect())
                            .unwrap_or_default();

                        if !txs.is_empty() {
                            block_txs_batch.push(txs);
                        }
                        blocks_processed += 1;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        warn!("[NOTIFY] Notification channel disconnected");
                        break;
                    }
                }
            }

            // Process all collected block TXs in one batch with a single DAA score fetch
            if !block_txs_batch.is_empty() {
                let rpc_lock = rpc.lock().await;
                let current_daa = rpc_lock.get_daa_score().await.unwrap_or(0);
                drop(rpc_lock);

                let mut ob = order_book.lock().await;
                let mut pb = shared_perp_book.lock().await;
                let mut lb = shared_lending_book.lock().await;
                let mut pred = shared_prediction_book.lock().await;
                let mut ib = shared_ifd_book.lock().await;

                for txs in &block_txs_batch {
                    let counters = process_block_txs_all(
                        txs, &mut ob, &scanner, &mut pb, &mut lb, &mut pred,
                        ws_tx.as_ref(), current_daa, Some(&mut ib),
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

            if blocks_processed > 0 {
                let any_found = total_counters.spot_added > 0
                    || total_counters.perp_added > 0
                    || total_counters.lending_added > 0
                    || total_counters.prediction_added > 0;
                if any_found {
                    info!(
                        "[NOTIFY] Processed {} block(s): spot(+{}), perp(+{}), lending(+{}), prediction(+{})",
                        blocks_processed,
                        total_counters.spot_added, total_counters.perp_added,
                        total_counters.lending_added, total_counters.prediction_added,
                    );
                } else {
                    debug!("[NOTIFY] Processed {} block(s), no new orders", blocks_processed);
                }
            }
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
                                let err_str = result.error.as_deref().unwrap_or("");
                                let is_orphan = err_str.contains("orphan")
                                    || err_str.contains("missing")
                                    || err_str.contains("not found")
                                    || err_str.contains("MissingTxOut");
                                if is_orphan {
                                    // Fee UTXO was consumed — retry up to MAX_BROADCAST_RETRIES
                                    let mut sb = shared_stop_book.lock().await;
                                    let attempts = sb.increment_broadcast_attempts(*stop_id).unwrap_or(0);
                                    if attempts >= crate::matcher::stop_book::MAX_BROADCAST_RETRIES {
                                        warn!(
                                            "[STOP] Stop order #{} exhausted {} retries (fee UTXO stale: {}). Giving up.",
                                            stop_id, attempts, err_str,
                                        );
                                        sb.mark_triggered(*stop_id, None);
                                    } else {
                                        warn!(
                                            "[STOP] Stop order #{} broadcast failed (attempt {}/{}): {} — will retry",
                                            stop_id, attempts, crate::matcher::stop_book::MAX_BROADCAST_RETRIES, err_str,
                                        );
                                    }
                                } else {
                                    // Non-recoverable rejection (double-spend, bad signature, etc.)
                                    warn!("[STOP] Broadcast failed for stop order #{}: {:?}", stop_id, result.error);
                                    shared_stop_book.lock().await.mark_triggered(*stop_id, None);
                                }
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
    let cross_groups = matching::find_cross_pair_batch_groups(&ob, 20, false, None);
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
    use kob_core::RECEIPT_VALUE;

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
            max_matcher_fee: u64::MAX, ifd_order_b_rs_hex: None, oco_path: None, oco_partner_key: None,
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
