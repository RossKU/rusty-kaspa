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
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletFile;
use kob_core::{DEFAULT_MATCHER_FEE, MIN_UTXO_VALUE, RECEIPT_DUST, RECEIPT_VALUE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderSide {
    Buy,
    Sell,
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

/// Order cache entry for parameter-based matching.
///
/// Stored in `orders.json` alongside the wallet file. Each entry records the
/// known parameters of a deployed order so the matcher can reconstruct the
/// redeemScript when the order's P2SH UTXO is found on-chain.
///
/// Also carries cancel-specific fields (`token`, `version`, `expiry_daa`) so
/// that the same cache file can drive `cancel`, `cancel-all`, `auto-match`,
/// `my-orders`, `orderbook`, and `history` without format mismatches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderCacheEntry {
    pub outpoint: String,
    pub side: String,
    /// Pair identifier (token covenant ID hex, 64 chars).
    /// Defaults to empty string for legacy entries.
    #[serde(default)]
    pub pair_id: String,
    pub price_num: u64,
    pub price_den: u64,
    pub min_fill: u64,
    /// Blake2b-256 hash of the owner pubkey (hex).
    #[serde(default)]
    pub owner_hash: String,
    /// P2PK script-public-key hash of the owner (hex).
    #[serde(default)]
    pub spk_hash: String,
    /// P2SH script hash of the deployed order UTXO (hex).
    #[serde(default)]
    pub p2sh_hash: String,
    pub value: u64,
    /// Whether the order was marked for cancellation (cpend=1).
    /// Used as a heuristic: if cancel_pending was true when the order
    /// was spent, it was likely cancelled rather than filled.
    #[serde(default)]
    pub cancel_pending: bool,
    /// Token covenant ID (hex, 64 chars). Present for buy orders.
    /// Used by cancel and cancel-all to reconstruct the redeemScript.
    #[serde(default)]
    pub token: Option<String>,
    /// Contract version (only 13 supported).
    #[serde(default = "default_cache_version")]
    pub version: u8,
    /// Expiry DAA score (v13 only, 0 = GTC).
    #[serde(default)]
    pub expiry_daa: u64,
}

fn default_cache_version() -> u8 {
    13
}

/// Persistent order cache file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrderCache {
    pub orders: Vec<OrderCacheEntry>,
}

impl OrderCache {
    /// Load order cache from a JSON file. Returns empty cache if file doesn't exist.
    ///
    /// Accepts two formats:
    /// - `{"orders": [...]}` (canonical `OrderCache` format)
    /// - `[...]` (legacy flat `CachedOrder` array written by older deploy)
    ///
    /// Legacy entries are converted on the fly; missing hash fields default to
    /// empty strings.
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        // Try canonical format first.
        if let Ok(cache) = serde_json::from_str::<OrderCache>(&contents) {
            return cache;
        }
        // Try legacy flat array of CachedOrder (from cancel_all module).
        if let Ok(legacy) = serde_json::from_str::<Vec<crate::cancel_all::CachedOrder>>(&contents) {
            return Self {
                orders: legacy.into_iter().map(OrderCacheEntry::from).collect(),
            };
        }
        Self::default()
    }

    /// Save order cache to a JSON file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Build a lookup table: P2SH hash -> cache entry.
    pub fn by_p2sh_hash(&self) -> HashMap<String, &OrderCacheEntry> {
        self.orders.iter().map(|o| (o.p2sh_hash.clone(), o)).collect()
    }

    /// Remove entries for a given outpoint (order was matched or cancelled).
    #[allow(dead_code)] // Public API: used by auto-match loop
    pub fn remove_outpoint(&mut self, outpoint: &str) {
        self.orders.retain(|o| o.outpoint != outpoint);
    }
}

/// Convert a legacy `CachedOrder` into the unified `OrderCacheEntry`.
///
/// Hash fields (`owner_hash`, `spk_hash`, `p2sh_hash`) are left empty
/// because the legacy format doesn't carry them. They can be recomputed
/// from the wallet pubkey when needed.
impl From<crate::cancel_all::CachedOrder> for OrderCacheEntry {
    fn from(c: crate::cancel_all::CachedOrder) -> Self {
        Self {
            outpoint: c.outpoint,
            side: c.side,
            pair_id: c.token.clone().unwrap_or_else(|| "00".repeat(32)),
            price_num: c.price_num,
            price_den: c.price_den,
            min_fill: c.min_fill,
            owner_hash: String::new(),
            spk_hash: String::new(),
            p2sh_hash: String::new(),
            value: c.value,
            cancel_pending: false,
            token: c.token,
            version: c.version,
            expiry_daa: c.expiry_daa,
        }
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

/// Compute expected match outputs for a crossing pair.
pub fn compute_match_outputs(
    buy: &DetectedOrder,
    sell: &DetectedOrder,
) -> anyhow::Result<MatchOutputs> {
    let expected_tokens = (buy.value as u128 * buy.price_num as u128 / buy.price_den as u128) as u64;
    let expected_kas = (sell.value as u128 * sell.price_num as u128 / sell.price_den as u128) as u64;

    let total_in = buy.value + sell.value;

    if expected_kas + expected_tokens > total_in {
        anyhow::bail!(
            "Orders cannot be matched: combined output ({} + {} = {} sompi) exceeds combined input ({} sompi). \
             The buy and sell prices do not overlap.",
            expected_kas,
            expected_tokens,
            expected_kas + expected_tokens,
            total_in
        );
    }

    let surplus = total_in - expected_kas - expected_tokens;

    if surplus < DEFAULT_MATCHER_FEE {
        anyhow::bail!(
            "Match surplus too small: {} sompi available, but need {} sompi for fee. \
             Try matching orders with a larger price spread.",
            surplus,
            DEFAULT_MATCHER_FEE
        );
    }

    if expected_kas < MIN_UTXO_VALUE {
        anyhow::bail!("Seller's KAS output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.", expected_kas, MIN_UTXO_VALUE);
    }
    if expected_tokens < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Buyer's token output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.",
            expected_tokens,
            MIN_UTXO_VALUE
        );
    }

    // Receipt value (1 KAS) funded by matcher wallet, not from surplus
    let receipt_value = RECEIPT_VALUE;
    let raw_change = surplus - DEFAULT_MATCHER_FEE;
    let (final_seller_kas, matcher_change) = if raw_change >= MIN_UTXO_VALUE {
        (expected_kas, raw_change)
    } else {
        (expected_kas + raw_change, 0u64)
    };

    Ok(MatchOutputs {
        seller_kas: final_seller_kas,
        buyer_tokens: expected_tokens,
        receipt_value,
        matcher_change,
        exec_amount: expected_tokens.min(sell.value),
    })
}

/// Computed output amounts for a match TX.
#[derive(Debug)]
pub struct MatchOutputs {
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub receipt_value: u64,
    pub matcher_change: u64,
    pub exec_amount: u64,
}

/// Result of a submitted match TX.
#[derive(Debug)]
pub struct SubmitResult {
    pub tx_id: String,
    pub seller_kas: u64,
    pub buyer_tokens: u64,
    pub receipt_index: u32,
}

/// Build and submit a full match TX for a crossing pair.
///
/// Both covenant inputs use fill sigscripts (sigOpCount=0, permissionless).
/// Only the fee input requires signing.
///
/// TX layout:
///   input[0]: buy_order  (P2SH fill, sigOpCount=0)
///   input[1]: sell_order (P2SH fill, sigOpCount=0)
///   input[2]: fee UTXO   (P2PK signed, sigOpCount=1)
///   output[0]: seller KAS
///   output[1]: buyer tokens
///   output[2]: trade_receipt (P2SH)
///   output[3]: matcher change (optional)
#[allow(clippy::too_many_arguments)]
#[allow(deprecated)]
pub async fn submit_match(
    rpc: &NodeClient,
    buy: &DetectedOrder,
    sell: &DetectedOrder,
    outputs: &MatchOutputs,
    pair_id_hex: &str,
    _wallet: &WalletFile,
    privkey: &[u8; 32],
    fee_utxo: &RpcUtxo,
) -> anyhow::Result<SubmitResult> {
    let buy_p2sh = build_p2sh(&buy.redeem_script);
    let sell_p2sh = build_p2sh(&sell.redeem_script);

    // Build fill sigscripts (permissionless, no signature needed) -- v13 only
    if buy.redeem_script.len() != 416 {
        anyhow::bail!("Unsupported buy RS length {}. Only v13 (416B) is supported.", buy.redeem_script.len());
    }
    if sell.redeem_script.len() != 389 {
        anyhow::bail!("Unsupported sell RS length {}. Only v13 (389B) is supported.", sell.redeem_script.len());
    }
    let buy_fill_ss = contract::build_buy_fill_sigscript(1, 1, 0, &buy.redeem_script);
    let sell_fill_ss = contract::build_sell_fill_sigscript(0, &sell.redeem_script);

    // Build receipt redeemScript
    let pair_bytes = hex::decode(pair_id_hex)?;
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&pair_bytes);
    let receipt_rs = contract::build_receipt_redeem_script(
        &tcid,
        buy.price_num,
        buy.price_den,
        outputs.exec_amount,
        RECEIPT_DUST,
        &buy.spk_hash,
    )?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    // Get wallet SPK from the fee UTXO (it's a P2PK UTXO from the wallet)
    let wallet_spk = fee_utxo.script_bytes();
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;
    let fee_spk_bytes = fee_utxo.script_bytes();
    let fee_value = fee_utxo.utxo_entry.amount;

    // Recompute output amounts including the fee UTXO value
    let total_in = buy.value + sell.value + fee_value;
    let seller_kas_base = outputs.seller_kas;
    let buyer_tokens = outputs.buyer_tokens;
    let receipt_value = outputs.receipt_value;
    let new_surplus = total_in - seller_kas_base - buyer_tokens;
    let raw_change = new_surplus - receipt_value - DEFAULT_MATCHER_FEE;
    let (final_seller_kas, matcher_change) = if raw_change >= MIN_UTXO_VALUE {
        (seller_kas_base, raw_change)
    } else {
        (seller_kas_base + raw_change, 0u64)
    };

    // Build transaction
    let mut tx = Transaction::new(0);

    // Input 0: buy_order (fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: buy.txid.clone(),
        prev_index: buy.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: buy_p2sh.version,
        script_bytes: buy_p2sh.script().to_vec(),
        value: buy.value,
    });

    // Input 1: sell_order (fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: sell.txid.clone(),
        prev_index: sell.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: sell_p2sh.version,
        script_bytes: sell_p2sh.script().to_vec(),
        value: sell.value,
    });

    // Input 2: fee UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: seller KAS
    tx.outputs.push(TxOutput::new(final_seller_kas, wallet_spk_version, wallet_spk.clone(), None));

    // Output 1: buyer tokens
    tx.outputs.push(TxOutput::new(buyer_tokens, wallet_spk_version, wallet_spk.clone(), None));

    // Output 2: trade receipt
    tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));

    // Output 3: matcher change (optional)
    if matcher_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(matcher_change, wallet_spk_version, wallet_spk, None));
    }

    // Sign fee input (index 2)
    let sighash = compute_sighash(&tx, 2)?;
    let sig = signing::schnorr_sign(privkey, &sighash)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig);

    let sigscripts = vec![buy_fill_ss, sell_fill_ss, fee_ss];
    let payload = to_rpc_payload(&tx, &sigscripts);

    let tx_id = rpc.submit_transaction(payload).await?;

    Ok(SubmitResult {
        tx_id,
        seller_kas: final_seller_kas,
        buyer_tokens,
        receipt_index: 2,
    })
}

/// Build and submit a partial fill TX for a buy order that is larger than a
/// crossing sell order.
///
/// Buy partial fill TX layout:
///   input[0]: buy_order UTXO (P2SH, partial fill sigscript, sigOpCount=0)
///   input[1]: fee UTXO       (P2PK, signed, sigOpCount=1)
///   output[0]: residual buy_order (P2SH, reduced value, same RS)
///   output[1]: buyer tokens       (fill amount worth of tokens)
///   output[2]: trade_receipt      (P2SH, RECEIPT_VALUE)
///   output[3]: matcher change     (optional)
///
/// Note: For a buy partial fill, the "token" that the buyer receives comes from
/// the sell order being fully consumed. The fill_kas = sell.value (all tokens from
/// the sell side). A separate sell full-fill + buy partial in one TX would require
/// a more complex layout. Instead, this uses the simpler single-order partial fill
/// where the matcher provides tokens via a separate UTXO.
///
/// However, for crossing pairs where buy > sell, the natural approach is:
///   - Fully fill the sell order (seller gets KAS)
///   - Partially fill the buy order (buyer gets tokens, residual remains)
///
/// This is done as TWO TXs: first a sell full fill (using partial fill on buy),
/// or as a single TX by using the sell order as the "token source" for the buy
/// partial fill. But the covenant scripts don't support mixing full+partial in
/// one TX, so we execute it as a partial fill on the LARGER order.
///
/// For buy_value > sell_value: partial fill the buy (fill_kas = tokens from sell)
/// For sell_value > buy_value: partial fill the sell (fill_tokens = KAS from buy)
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // Public API: partial fill path for auto-match
#[allow(deprecated)]
pub async fn submit_partial_buy_fill(
    rpc: &NodeClient,
    buy: &DetectedOrder,
    sell: &DetectedOrder,
    pair_id_hex: &str,
    privkey: &[u8; 32],
    fee_utxo: &RpcUtxo,
    token_utxo: &RpcUtxo,
) -> anyhow::Result<SubmitResult> {
    // The buy order is larger. We fill it partially with fill_kas = amount matching
    // what the sell order can provide.
    // fill_kas determines how much KAS is extracted from the buy order.
    // expected_tokens = fill_kas * price_num / price_den
    let fill_kas = sell.value;
    let expected_tokens = (fill_kas as u128 * buy.price_num as u128 / buy.price_den as u128) as u64;
    let residual_value = buy.value - fill_kas;

    if residual_value < MIN_UTXO_VALUE {
        anyhow::bail!("Remaining order value ({} sompi) would be below the minimum UTXO value. \
             Use a full fill instead of a partial fill.", residual_value);
    }
    if expected_tokens < MIN_UTXO_VALUE {
        anyhow::bail!("Token output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the fill amount.", expected_tokens, MIN_UTXO_VALUE);
    }
    if fill_kas < buy.min_fill {
        anyhow::bail!("Fill amount ({} sompi) is below the order's minimum fill ({} sompi). \
             Increase the fill amount or use a different order.", fill_kas, buy.min_fill);
    }

    let buy_p2sh = build_p2sh(&buy.redeem_script);

    // Build partial fill sigscript
    // output[0] = residual order, output[1] = buyer tokens
    // v13 only partial fill
    let buy_pf_ss = contract::build_buy_partial_fill_sigscript(&buy.redeem_script, fill_kas, 0, 1);

    // Build receipt
    let pair_bytes = hex::decode(pair_id_hex)?;
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&pair_bytes);
    let receipt_rs = contract::build_receipt_redeem_script(&tcid, buy.price_num, buy.price_den, expected_tokens, RECEIPT_DUST, &buy.spk_hash)?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    let wallet_spk = fee_utxo.script_bytes();
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;
    let token_spk_bytes = token_utxo.script_bytes();
    let token_value = token_utxo.utxo_entry.amount;
    let fee_spk_bytes = fee_utxo.script_bytes();
    let fee_value = fee_utxo.utxo_entry.amount;

    let receipt_value = RECEIPT_VALUE;
    let total_in = buy.value + token_value + fee_value;
    let needed = residual_value + expected_tokens + receipt_value + DEFAULT_MATCHER_FEE;
    if total_in < needed {
        anyhow::bail!("Insufficient funds: total input ({} sompi) cannot cover required outputs ({} sompi). \
             Add more funding UTXOs or reduce the fill amount.", total_in, needed);
    }
    let raw_change = total_in - needed;
    let (final_buyer_tokens, matcher_change) = if raw_change >= MIN_UTXO_VALUE {
        (expected_tokens, raw_change)
    } else {
        (expected_tokens + raw_change, 0u64)
    };

    let mut tx = Transaction::new(0);

    // Input 0: buy_order (partial fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: buy.txid.clone(),
        prev_index: buy.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: buy_p2sh.version,
        script_bytes: buy_p2sh.script().to_vec(),
        value: buy.value,
    });

    // Input 1: token UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: token_utxo.outpoint.transaction_id.clone(),
        prev_index: token_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: token_utxo.utxo_entry.script_public_key.version,
        script_bytes: token_spk_bytes,
        value: token_value,
    });

    // Input 2: fee UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: residual buy order (same P2SH)
    tx.outputs.push(TxOutput::new(residual_value, buy_p2sh.version, buy_p2sh.script().to_vec(), None));

    // Output 1: buyer tokens
    tx.outputs.push(TxOutput::new(final_buyer_tokens, wallet_spk_version, wallet_spk.clone(), None));

    // Output 2: trade receipt
    tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));

    // Output 3: matcher change (optional)
    if matcher_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(matcher_change, wallet_spk_version, wallet_spk, None));
    }

    // Sign input 1 (token UTXO)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(privkey, &sighash_1)?;
    let token_ss = signing::build_p2pk_sigscript(&sig_1);

    // Sign input 2 (fee UTXO)
    let sighash_2 = compute_sighash(&tx, 2)?;
    let sig_2 = signing::schnorr_sign(privkey, &sighash_2)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_2);

    let sigscripts = vec![buy_pf_ss, token_ss, fee_ss];
    let payload = to_rpc_payload(&tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    Ok(SubmitResult {
        tx_id,
        seller_kas: 0, // Buy partial fill doesn't produce seller KAS in this TX
        buyer_tokens: final_buyer_tokens,
        receipt_index: 2,
    })
}

/// Build and submit a partial fill TX for a sell order that is larger than a
/// crossing buy order.
///
/// Sell partial fill TX layout:
///   input[0]: sell_order UTXO (P2SH, partial fill sigscript, sigOpCount=0)
///   input[1]: fee UTXO        (P2PK, signed, sigOpCount=1)
///   output[0]: seller KAS         (fill_tokens * price KAS)
///   output[1]: residual sell_order (P2SH, reduced value, same RS)
///   output[2]: trade_receipt       (P2SH, RECEIPT_VALUE)
///   output[3]: matcher change      (optional)
#[allow(clippy::too_many_arguments)]
#[allow(dead_code, deprecated)] // Public API: partial fill path for auto-match
pub async fn submit_partial_sell_fill(
    rpc: &NodeClient,
    buy: &DetectedOrder,
    sell: &DetectedOrder,
    pair_id_hex: &str,
    privkey: &[u8; 32],
    fee_utxo: &RpcUtxo,
) -> anyhow::Result<SubmitResult> {
    // The sell order is larger. We partially fill it with fill_token_amount = buy.value
    // (all KAS from the buy side buys tokens from the sell order).
    // seller_kas = fill_token_amount * price_num / price_den
    let fill_token_amount = buy.value;
    let seller_kas = (fill_token_amount as u128 * sell.price_num as u128 / sell.price_den as u128) as u64;
    let residual_value = sell.value - fill_token_amount;

    if residual_value < MIN_UTXO_VALUE {
        anyhow::bail!("Remaining order value ({} sompi) would be below the minimum UTXO value. \
             Use a full fill instead of a partial fill.", residual_value);
    }
    if seller_kas < MIN_UTXO_VALUE {
        anyhow::bail!("Seller's KAS output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the fill amount.", seller_kas, MIN_UTXO_VALUE);
    }
    if fill_token_amount < sell.min_fill {
        anyhow::bail!("Fill amount ({} sompi) is below the order's minimum fill ({} sompi). \
             Increase the fill amount or use a different order.", fill_token_amount, sell.min_fill);
    }

    let sell_p2sh = build_p2sh(&sell.redeem_script);

    // Build partial fill sigscript
    // output[0] = seller KAS, output[1] = residual order
    let sell_pf_ss = contract::build_sell_partial_fill_sigscript(&sell.redeem_script, fill_token_amount, 0, 1);

    // Build receipt
    let pair_bytes = hex::decode(pair_id_hex)?;
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&pair_bytes);
    let receipt_rs = contract::build_receipt_redeem_script(&tcid, sell.price_num, sell.price_den, fill_token_amount, RECEIPT_DUST, &buy.spk_hash)?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    let wallet_spk = fee_utxo.script_bytes();
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;
    let fee_spk_bytes = fee_utxo.script_bytes();
    let fee_value = fee_utxo.utxo_entry.amount;

    let receipt_value = RECEIPT_VALUE;
    let total_in = sell.value + fee_value;
    let needed = seller_kas + residual_value + receipt_value + DEFAULT_MATCHER_FEE;
    if total_in < needed {
        anyhow::bail!("Insufficient funds: total input ({} sompi) cannot cover required outputs ({} sompi). \
             Add more funding UTXOs or reduce the fill amount.", total_in, needed);
    }
    let raw_change = total_in - needed;
    let (final_seller_kas, matcher_change) = if raw_change >= MIN_UTXO_VALUE {
        (seller_kas, raw_change)
    } else {
        (seller_kas + raw_change, 0u64)
    };

    let mut tx = Transaction::new(0);

    // Input 0: sell_order (partial fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: sell.txid.clone(),
        prev_index: sell.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: sell_p2sh.version,
        script_bytes: sell_p2sh.script().to_vec(),
        value: sell.value,
    });

    // Input 1: fee UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: seller KAS
    tx.outputs.push(TxOutput::new(final_seller_kas, wallet_spk_version, wallet_spk.clone(), None));

    // Output 1: residual sell order (same P2SH)
    tx.outputs.push(TxOutput::new(residual_value, sell_p2sh.version, sell_p2sh.script().to_vec(), None));

    // Output 2: trade receipt
    tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));

    // Output 3: matcher change (optional)
    if matcher_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(matcher_change, wallet_spk_version, wallet_spk, None));
    }

    // Sign input 1 (fee UTXO)
    let sighash = compute_sighash(&tx, 1)?;
    let sig = signing::schnorr_sign(privkey, &sighash)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig);

    let sigscripts = vec![sell_pf_ss, fee_ss];
    let payload = to_rpc_payload(&tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    Ok(SubmitResult {
        tx_id,
        seller_kas: final_seller_kas,
        buyer_tokens: 0, // Sell partial fill doesn't produce buyer tokens directly
        receipt_index: 2,
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

/// Compute expected outputs for a cross-pair match.
///
/// Cross-pair match: sell order (Token A) + buy order (KAS -> Token B).
/// KAS flows from the buy order to the seller. Token A flows from the sell
/// order to the matcher. Token B flows from the matcher inventory to the buyer.
///
/// Value balance:
///   Input KAS: buy.value (buy order UTXO holds KAS)
///   Output KAS: seller_kas + receipt + matcher_change + fee
///   Token A: sell.value -> token_a_forward (1:1, required by sell_v8 F4)
///   Token B: token_b_value -> buyer_tokens (from matcher inventory)
pub fn compute_cross_pair_outputs(
    sell: &DetectedOrder,
    buy: &DetectedOrder,
    sell_kas_out: u64,
    buy_tokens: u64,
) -> anyhow::Result<CrossPairOutputs> {
    // Seller KAS = sell.value * sell.price_num / sell.price_den
    // This is the KAS the seller demands for their Token A.
    if sell_kas_out < MIN_UTXO_VALUE {
        anyhow::bail!("Seller's KAS output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.", sell_kas_out, MIN_UTXO_VALUE);
    }
    if buy_tokens < MIN_UTXO_VALUE {
        anyhow::bail!("Buyer's token output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.", buy_tokens, MIN_UTXO_VALUE);
    }

    // Token A forward = sell.value (the full sell order UTXO value)
    let token_a_forward = sell.value;

    // KAS surplus from the buy order after paying the seller
    // buy.value = seller_kas + surplus
    if buy.value < sell_kas_out {
        anyhow::bail!(
            "Buy order value ({} sompi) is less than the seller's KAS requirement ({} sompi). \
             The buy and sell prices do not overlap.",
            buy.value, sell_kas_out,
        );
    }
    let surplus = buy.value - sell_kas_out;

    if surplus < DEFAULT_MATCHER_FEE {
        anyhow::bail!(
            "Match surplus too small: {} sompi available, but need {} sompi for fee. \
             Try matching orders with a larger price spread.",
            surplus, DEFAULT_MATCHER_FEE,
        );
    }

    // Receipt value (1 KAS) funded by matcher wallet, not from surplus.
    // Receipt is always included now (no conditional).
    let receipt_value = RECEIPT_VALUE;
    let include_receipt = true;

    let raw_change = surplus.saturating_sub(DEFAULT_MATCHER_FEE);
    let (final_seller_kas, matcher_change) = if raw_change >= MIN_UTXO_VALUE {
        (sell_kas_out, raw_change)
    } else {
        // Fold dust change into seller output
        (sell_kas_out + raw_change, 0)
    };

    Ok(CrossPairOutputs {
        seller_kas: final_seller_kas,
        buyer_tokens: buy_tokens,
        token_a_forward,
        receipt_value,
        matcher_change,
        include_receipt,
        exec_amount: buy_tokens,
    })
}

/// Build and submit a cross-pair match TX (v8 contracts).
///
/// Cross-pair matching routes Token A from a sell order to the matcher,
/// and delivers Token B from the matcher's inventory to a buy order's buyer.
/// KAS flows from the buy order to the seller.
///
/// TX layout (version=1 for covenant bindings):
///   input[0]: sell_order_v8 (Token A, P2SH fill, sigOpCount=0)
///   input[1]: buy_order_v8  (KAS -> Token B, P2SH fill, sigOpCount=0)
///   input[2]: token_unit    (Token B from matcher, TOKEN_RS P2SH, sigOpCount=0)
///   input[3]: fee UTXO      (P2PK signed, sigOpCount=1) [optional]
///   output[0]: seller KAS         (no covenant)
///   output[1]: buyer Token B      (covenant: authInput=2, Token B cov_id)
///   output[2]: Token A forward    (covenant: authInput=0, Token A cov_id)
///   output[3]: trade receipt      (P2SH, optional)
///   output[4]: matcher change     (optional)
///   output[5]: fee UTXO change    (optional)
#[allow(clippy::too_many_arguments, deprecated)]
pub async fn submit_cross_pair_match(
    rpc: &NodeClient,
    sell: &DetectedOrder,
    buy: &DetectedOrder,
    outputs: &CrossPairOutputs,
    _wallet: &WalletFile,
    privkey: &[u8; 32],
    fee_utxo: &RpcUtxo,
    token_b_utxo: &RpcUtxo,
) -> anyhow::Result<SubmitResult> {
    let sell_p2sh = build_p2sh(&sell.redeem_script);
    let buy_p2sh = build_p2sh(&buy.redeem_script);

    // Token B P2SH (TOKEN_RS)
    let token_p2sh = build_p2sh(kob_core::TOKEN_RS);

    // Build v13 fill sigscripts
    // Sell fill: kas_output_idx=0 (seller KAS at output[0])
    let sell_fill_ss = contract::build_sell_fill_sigscript(0, &sell.redeem_script);
    // Buy fill: token_output_idx=1, token_input_idx=2, cov_output_idx=0
    let buy_fill_ss = contract::build_buy_fill_sigscript(1, 2, 0, &buy.redeem_script);
    // Token unit sigscript: just pushData(TOKEN_RS)
    let token_ss = kob_core::push_data(kob_core::TOKEN_RS);

    // Wallet SPK (for change outputs and seller/buyer routing in CLI mode)
    let wallet_spk = fee_utxo.script_bytes();
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;
    let fee_spk_bytes = fee_utxo.script_bytes();
    let fee_value = fee_utxo.utxo_entry.amount;

    let token_b_value = token_b_utxo.utxo_entry.amount;

    // Token A covenant ID = sell order's token_cov_id
    let sell_token_cov_id = &sell.token_cov_id;
    if sell_token_cov_id.len() != 64 {
        anyhow::bail!("Sell order is missing its token covenant ID. The order may be malformed or use an unsupported version.");
    }
    // Token B covenant ID = buy order's token_cov_id
    let buy_token_cov_id = &buy.token_cov_id;
    if buy_token_cov_id.len() != 64 {
        anyhow::bail!("Buy order is missing its token covenant ID. The order may be malformed or use an unsupported version.");
    }

    // Token A P2SH for the forward output (matcher receives Token A)
    let token_a_p2sh = build_p2sh(kob_core::TOKEN_RS);

    // Build receipt
    let buy_tcid_bytes = hex::decode(buy_token_cov_id)?;
    if buy_tcid_bytes.len() != 32 {
        anyhow::bail!("Buy order has an invalid token covenant ID (expected 64 hex chars). The order may be malformed.");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&buy_tcid_bytes);
    let receipt_rs = contract::build_receipt_redeem_script(
        &tcid,
        buy.price_num,
        buy.price_den,
        outputs.exec_amount,
        RECEIPT_DUST,
        &buy.spk_hash,
    )?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    // Recompute totals with fee UTXO
    let total_in = sell.value + buy.value + token_b_value + fee_value;
    let total_out = outputs.seller_kas
        + outputs.buyer_tokens.max(token_b_value) // buyer gets all of token_b
        + outputs.token_a_forward
        + outputs.receipt_value
        + outputs.matcher_change;
    if total_in < total_out + DEFAULT_MATCHER_FEE {
        anyhow::bail!(
            "Insufficient funds: total input ({} sompi) cannot cover outputs ({} sompi) + fee ({} sompi). \
             Add more funding UTXOs.",
            total_in, total_out, DEFAULT_MATCHER_FEE,
        );
    }
    let fee_change = total_in - total_out - DEFAULT_MATCHER_FEE;

    // Buyer gets all of token_b (buy_v8 checks >=, so giving more is fine)
    let buyer_tokens_final = token_b_value;

    // --- Build transaction (version=1 for covenant bindings) ---
    let mut tx = Transaction::new(1);

    // Input 0: sell_order_v8 (Token A, fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: sell.txid.clone(),
        prev_index: sell.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: sell_p2sh.version,
        script_bytes: sell_p2sh.script().to_vec(),
        value: sell.value,
    });

    // Input 1: buy_order_v8 (KAS -> Token B, fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: buy.txid.clone(),
        prev_index: buy.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: buy_p2sh.version,
        script_bytes: buy_p2sh.script().to_vec(),
        value: buy.value,
    });

    // Input 2: token_unit (Token B from matcher inventory, sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: token_b_utxo.outpoint.transaction_id.clone(),
        prev_index: token_b_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 0,
        script_version: token_p2sh.version,
        script_bytes: token_p2sh.script().to_vec(),
        value: token_b_value,
    });

    // Input 3: fee UTXO (P2PK signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: seller KAS (no covenant)
    tx.outputs.push(TxOutput::new(outputs.seller_kas, wallet_spk_version, wallet_spk.clone(), None));

    // Output 1: buyer Token B (covenant: authorizingInput=2, Token B cov_id)
    tx.outputs.push(TxOutput::new(buyer_tokens_final, wallet_spk_version, wallet_spk.clone(), Some(kob_core::tx::CovenantBinding::new(2, kob_core::compat::parse_hash(&buy_token_cov_id.clone()).unwrap()))));

    // Output 2: Token A forward to matcher (covenant: authorizingInput=0, Token A cov_id)
    tx.outputs.push(TxOutput::new(outputs.token_a_forward, token_a_p2sh.version, token_a_p2sh.script().to_vec(), Some(kob_core::tx::CovenantBinding::new(0, kob_core::compat::parse_hash(&sell_token_cov_id.clone()).unwrap()))));

    // Output 3: trade receipt (optional)
    let receipt_index = if outputs.include_receipt {
        tx.outputs.push(TxOutput::new(outputs.receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));
        tx.outputs.len() as u32 - 1
    } else {
        0
    };

    // Output 4: matcher change (optional)
    if outputs.matcher_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(outputs.matcher_change, wallet_spk_version, wallet_spk.clone(), None));
    }

    // Output 5: fee UTXO change (optional)
    if fee_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(fee_change, wallet_spk_version, wallet_spk, None));
    }

    // Sign fee input (index 3)
    let sighash = compute_sighash(&tx, 3)?;
    let sig = signing::schnorr_sign(privkey, &sighash)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig);

    let sigscripts = vec![sell_fill_ss, buy_fill_ss, token_ss, fee_ss];
    let payload = to_rpc_payload(&tx, &sigscripts);

    let tx_id = rpc.submit_transaction(payload).await?;

    Ok(SubmitResult {
        tx_id,
        seller_kas: outputs.seller_kas,
        buyer_tokens: buyer_tokens_final,
        receipt_index,
    })
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

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    println!("KOB Auto-Match");
    println!("===============");
    println!("Pair ID:      {}", pair_id_hex);
    println!("Interval:     {} seconds", interval_secs);
    println!("Dry Run:      {}", dry_run);
    println!("Min Spread:   {}", min_spread);
    println!("Max Matches:  {}", if max_matches == 0 { "unlimited".to_string() } else { max_matches.to_string() });
    println!("Cross-pair:   {}", if cross_pair { "ENABLED (v8)" } else { "disabled" });
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
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= DEFAULT_MATCHER_FEE + MIN_UTXO_VALUE);

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

                    // Reconstruct the redeemScript (v6 canonical contracts)
                    // cancel_pending = 0 (active order).
                    // max_matcher_fee = 10_000_000 sompi (matches deploy default).
                    let rs = match side {
                        OrderSide::Buy => {
                            let pair_bytes = hex::decode(&cached.pair_id).unwrap_or_default();
                            if pair_bytes.len() != 32 { continue; }
                            let mut tcid = [0u8; 32];
                            tcid.copy_from_slice(&pair_bytes);
                            kob_core::contract::build_buy_redeem_script(
                                &tcid,
                                cached.price_num,
                                cached.price_den,
                                cached.min_fill,
                                &owner_hash,
                                &spk_hash,
                                0, // max_matcher_fee
                                0,
                                0, // expiry_daa = 0 (GTC)
                            )?
                        }
                        OrderSide::Sell => {
                            kob_core::contract::build_sell_redeem_script(
                                cached.price_num,
                                cached.price_den,
                                cached.min_fill,
                                &owner_hash,
                                &spk_hash,
                                0, // max_matcher_fee
                                0,
                                0, // expiry_daa = 0 (GTC)
                            )?
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

                match compute_match_outputs(&pair.buy, &pair.sell) {
                    Ok(outputs) => {
                        println!(
                            "         seller_kas={} buyer_tokens={} receipt={} change={}",
                            outputs.seller_kas,
                            outputs.buyer_tokens,
                            outputs.receipt_value,
                            outputs.matcher_change,
                        );

                        if dry_run {
                            println!("         [DRY RUN] Would submit match TX.");
                        } else if let Some(fee) = fee_utxo {
                            match submit_match(
                                &rpc,
                                &pair.buy,
                                &pair.sell,
                                &outputs,
                                pair_id_hex,
                                &wallet,
                                &privkey,
                                fee,
                            )
                            .await
                            {
                                Ok(result) => {
                                    println!(
                                        "         MATCHED! TXID: {}",
                                        result.tx_id
                                    );
                                    println!(
                                        "         Seller received: {} sompi, Buyer received: {} sompi",
                                        result.seller_kas, result.buyer_tokens
                                    );
                                    println!(
                                        "         Receipt at: {}:{}",
                                        result.tx_id, result.receipt_index
                                    );
                                }
                                Err(e) => {
                                    warn!("         Match TX failed: {}", e);
                                }
                            }
                        } else {
                            println!("         SKIPPED: No fee UTXO available.");
                        }

                        match_count += 1;

                        // Check max_matches limit after each match
                        if max_matches > 0 && match_count >= max_matches {
                            println!("  Reached max_matches limit ({}).", max_matches);
                            break;
                        }
                    }
                    Err(e) => {
                        println!("         Cannot match: {}", e);
                    }
                }
            }
        }

        // Cross-pair route scanning (v8)
        if cross_pair && !(max_matches > 0 && match_count >= max_matches) {
            // Build a simplified order list from ALL detected orders across pairs.
            // Cross-pair routes match sells in one pair with buys in another.
            let buys: Vec<&DetectedOrder> = detected_orders.iter()
                .filter(|o| o.side == OrderSide::Buy)
                .collect();
            let sells: Vec<&DetectedOrder> = detected_orders.iter()
                .filter(|o| o.side == OrderSide::Sell)
                .collect();

            let mut cross_routes = Vec::new();

            for sell in &sells {
                let sell_kas_out = (sell.value as u128 * sell.price_num as u128
                    / sell.price_den as u128) as u64;
                if sell_kas_out < MIN_UTXO_VALUE {
                    continue;
                }

                for buy in &buys {
                    // Only match across different "effective pairs"
                    // (different p2sh_hash implies different contract/pair)
                    if sell.p2sh_hash == buy.p2sh_hash {
                        continue;
                    }

                    let buy_kas_in = buy.value;
                    let buy_tokens = (buy_kas_in as u128 * buy.price_num as u128
                        / buy.price_den as u128) as u64;
                    if buy_tokens < MIN_UTXO_VALUE {
                        continue;
                    }
                    if buy_kas_in < sell_kas_out {
                        continue;
                    }
                    let surplus = buy_kas_in - sell_kas_out;
                    if surplus < DEFAULT_MATCHER_FEE {
                        continue;
                    }

                    cross_routes.push((sell, buy, surplus, sell_kas_out, buy_tokens));
                }
            }

            cross_routes.sort_by(|a, b| b.2.cmp(&a.2));

            if !cross_routes.is_empty() {
                println!("  Cross-pair routes (v8): {}", cross_routes.len());
                for (i, &(sell, buy, surplus, sell_kas, buy_tokens)) in cross_routes.iter().enumerate() {
                    println!(
                        "    [X{}] SELL {}:{} ({} sompi) -> BUY {}:{} ({} sompi) surplus={}",
                        i,
                        &sell.txid[..8], sell.index,
                        sell.value,
                        &buy.txid[..8], buy.index,
                        buy.value,
                        surplus,
                    );
                    println!(
                        "         seller_kas={} buyer_tokens={}",
                        sell_kas, buy_tokens,
                    );

                    if dry_run {
                        println!("         [DRY RUN] Would submit cross-pair match TX (v8).");
                        match_count += 1;
                        if max_matches > 0 && match_count >= max_matches {
                            println!("  Reached max_matches limit ({}).", max_matches);
                            break;
                        }
                    } else if let Some(fee) = fee_utxo {
                        // Compute cross-pair output amounts
                        match compute_cross_pair_outputs(sell, buy, sell_kas, buy_tokens) {
                            Ok(cp_outputs) => {
                                // Find Token B UTXO from wallet (TOKEN_RS P2SH with sufficient value)
                                let token_p2sh = build_p2sh(kob_core::TOKEN_RS);
                                let token_p2sh_hex = hex::encode(&token_p2sh.script());
                                let token_b_utxo = wallet_utxos.iter().find(|u| {
                                    let script_hex = &u.utxo_entry.script_public_key.script;
                                    script_hex.contains(&token_p2sh_hex)
                                        && u.utxo_entry.amount >= buy_tokens
                                        && u.outpoint_key() != fee.outpoint_key()
                                });

                                match token_b_utxo {
                                    Some(tb) => {
                                        match submit_cross_pair_match(
                                            &rpc,
                                            sell,
                                            buy,
                                            &cp_outputs,
                                            &wallet,
                                            &privkey,
                                            fee,
                                            tb,
                                        )
                                        .await
                                        {
                                            Ok(result) => {
                                                println!(
                                                    "         CROSS-PAIR MATCHED! TXID: {}",
                                                    result.tx_id
                                                );
                                                println!(
                                                    "         Seller received: {} sompi KAS",
                                                    result.seller_kas,
                                                );
                                                println!(
                                                    "         Buyer received: {} sompi tokens",
                                                    result.buyer_tokens,
                                                );
                                                println!(
                                                    "         Token A forwarded: {} sompi -> matcher",
                                                    cp_outputs.token_a_forward,
                                                );
                                                if cp_outputs.include_receipt {
                                                    println!(
                                                        "         Receipt at: {}:{}",
                                                        result.tx_id, result.receipt_index
                                                    );
                                                }
                                                match_count += 1;
                                            }
                                            Err(e) => {
                                                warn!("         Cross-pair match TX failed: {}", e);
                                            }
                                        }
                                    }
                                    None => {
                                        println!(
                                            "         SKIPPED: No Token B UTXO (TOKEN_RS P2SH >= {} sompi) in wallet.",
                                            buy_tokens,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!("         Cannot compute cross-pair outputs: {}", e);
                            }
                        }
                    } else {
                        println!("         SKIPPED: No fee UTXO available.");
                    }
                }
            }
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
    fn compute_match_outputs_basic() {
        let buy = make_test_order(OrderSide::Buy, 1, 2, 20_000_000);
        let sell = make_test_order(OrderSide::Sell, 1, 2, 20_000_000);
        let outputs = compute_match_outputs(&buy, &sell).unwrap();
        // expected_tokens = 20M * 1 / 2 = 10M
        // expected_kas = 20M * 1 / 2 = 10M
        // total_in = 40M, surplus = 40M - 10M - 10M = 20M
        assert_eq!(outputs.buyer_tokens, 10_000_000);
        assert_eq!(outputs.receipt_value, RECEIPT_VALUE);
        assert!(outputs.seller_kas >= 10_000_000);
    }

    #[test]
    fn compute_match_outputs_no_crossing() {
        let buy = make_test_order(OrderSide::Buy, 1, 10, 10_000_000);
        let sell = make_test_order(OrderSide::Sell, 5, 1, 10_000_000);
        let result = compute_match_outputs(&buy, &sell);
        assert!(result.is_err(), "Non-crossing prices should fail");
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
            receipt_index: 2,
        };
        assert_eq!(result.tx_id, "abc");
        assert_eq!(result.seller_kas, 5_000_000);
        assert_eq!(result.buyer_tokens, 3_000_000);
        assert_eq!(result.receipt_index, 2);
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
        }
    }

    #[test]
    fn cross_pair_outputs_basic() {
        // Sell: 10M tokens of Token A at price 2/1 -> wants 20M KAS
        let sell = make_cross_pair_order(OrderSide::Sell, 2, 1, 10_000_000, &"aa".repeat(32));
        // Buy: 30M KAS for Token B at price 1/1 -> wants 30M tokens
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 30_000_000, &"bb".repeat(32));

        let sell_kas = 20_000_000u64; // sell.value * sell.price_num / sell.price_den
        let buy_tokens = 30_000_000u64; // buy.value * buy.price_num / buy.price_den

        let outputs = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens).unwrap();

        assert_eq!(outputs.token_a_forward, 10_000_000, "Token A forward = sell.value");
        assert!(outputs.seller_kas >= 20_000_000, "Seller gets at least sell_kas");
        assert_eq!(outputs.buyer_tokens, 30_000_000);
        assert!(outputs.include_receipt, "Receipt always included");
        // surplus = 30M - 20M = 10M; fee = 10K; change = ~10M (receipt funded by matcher)
        assert!(outputs.matcher_change > 0, "Should have matcher change");
        assert_eq!(outputs.exec_amount, buy_tokens);
    }

    #[test]
    fn cross_pair_outputs_minimal_surplus() {
        // Sell: 10M at price 1/1 -> wants 10M KAS
        let sell = make_cross_pair_order(OrderSide::Sell, 1, 1, 10_000_000, &"aa".repeat(32));
        // Buy: 10_010_000 KAS (surplus = 10_000 = DEFAULT_MATCHER_FEE exactly)
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 10_010_000, &"bb".repeat(32));

        let sell_kas = 10_000_000u64;
        let buy_tokens = 10_010_000u64;

        let outputs = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens).unwrap();

        assert!(outputs.include_receipt);
        assert_eq!(outputs.receipt_value, RECEIPT_VALUE);
        // surplus = 10_000 = DEFAULT_MATCHER_FEE; raw_change = 0
        // raw_change < MIN_UTXO_VALUE, so folded into seller_kas
        assert_eq!(outputs.matcher_change, 0, "Dust change folded into seller");
        assert_eq!(outputs.seller_kas, sell_kas, "No dust to fold when raw_change=0");
    }

    #[test]
    fn cross_pair_outputs_insufficient_surplus() {
        let sell = make_cross_pair_order(OrderSide::Sell, 1, 1, 10_000_000, &"aa".repeat(32));
        // Buy: 10_005_000 KAS -> surplus = 5_000 < DEFAULT_MATCHER_FEE (10_000)
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 10_005_000, &"bb".repeat(32));

        let sell_kas = 10_000_000u64;
        let buy_tokens = 10_005_000u64;

        let result = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens);
        assert!(result.is_err(), "Should fail with insufficient surplus");
    }

    #[test]
    fn cross_pair_outputs_prices_dont_cross() {
        let sell = make_cross_pair_order(OrderSide::Sell, 1, 1, 10_000_000, &"aa".repeat(32));
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 5_000_000, &"bb".repeat(32));

        let sell_kas = 10_000_000u64;
        let buy_tokens = 5_000_000u64;

        // buy.value (5M) < sell_kas (10M) -> should fail
        let result = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens);
        assert!(result.is_err(), "Should fail when buy value < seller kas");
    }

    #[test]
    fn cross_pair_outputs_seller_kas_below_min() {
        let sell = make_cross_pair_order(OrderSide::Sell, 1, 1, 10_000_000, &"aa".repeat(32));
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 50_000_000, &"bb".repeat(32));

        // seller_kas = 1M < MIN_UTXO_VALUE (3M)
        let result = compute_cross_pair_outputs(&sell, &buy, 1_000_000, 50_000_000);
        assert!(result.is_err(), "Should fail when seller_kas < MIN_UTXO_VALUE");
    }

    #[test]
    fn cross_pair_outputs_buyer_tokens_below_min() {
        let sell = make_cross_pair_order(OrderSide::Sell, 1, 1, 10_000_000, &"aa".repeat(32));
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 50_000_000, &"bb".repeat(32));

        // buyer_tokens = 1M < MIN_UTXO_VALUE (3M)
        let result = compute_cross_pair_outputs(&sell, &buy, 10_000_000, 1_000_000);
        assert!(result.is_err(), "Should fail when buyer_tokens < MIN_UTXO_VALUE");
    }

    #[test]
    fn cross_pair_outputs_value_balance() {
        // Verify the surplus balance: buy.value = seller_kas + change + fee
        // (Receipt is funded by matcher wallet, not from buy surplus)
        let sell = make_cross_pair_order(OrderSide::Sell, 3, 1, 5_000_000, &"aa".repeat(32));
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 25_000_000, &"bb".repeat(32));

        let sell_kas = 15_000_000u64; // 5M * 3/1
        let buy_tokens = 25_000_000u64;

        let outputs = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens).unwrap();

        // Surplus balance: buy.value = seller_kas + change + fee
        let surplus_total = outputs.seller_kas + outputs.matcher_change + DEFAULT_MATCHER_FEE;
        assert_eq!(surplus_total, buy.value, "KAS surplus must balance: buy.value = seller_kas + change + fee");

        // Token A conservation
        assert_eq!(outputs.token_a_forward, sell.value, "Token A forward = sell.value");
    }

    #[test]
    fn cross_pair_outputs_large_surplus_has_change() {
        let sell = make_cross_pair_order(OrderSide::Sell, 1, 1, 10_000_000, &"aa".repeat(32));
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 100_000_000, &"bb".repeat(32));

        let sell_kas = 10_000_000u64;
        let buy_tokens = 100_000_000u64;

        let outputs = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens).unwrap();

        // surplus = 90M; fee = 10K; change = 89_990_000 (receipt funded by matcher, not surplus)
        assert!(outputs.matcher_change >= MIN_UTXO_VALUE, "Large surplus should produce change");
        assert!(outputs.include_receipt);

        // Verify surplus balance: seller_kas + matcher_change + DEFAULT_MATCHER_FEE = buy.value
        // (Receipt value comes from fee UTXOs, not from surplus)
        let surplus_total = outputs.seller_kas + outputs.matcher_change + DEFAULT_MATCHER_FEE;
        assert_eq!(surplus_total, buy.value);
    }

    #[test]
    fn cross_pair_outputs_struct_fields() {
        let sell = make_cross_pair_order(OrderSide::Sell, 2, 1, 10_000_000, &"aa".repeat(32));
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 2, 50_000_000, &"bb".repeat(32));

        let sell_kas = 20_000_000u64;
        let buy_tokens = 25_000_000u64;

        let outputs = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens).unwrap();

        // CrossPairOutputs should have all expected fields
        let _ = outputs.seller_kas;
        let _ = outputs.buyer_tokens;
        let _ = outputs.token_a_forward;
        let _ = outputs.receipt_value;
        let _ = outputs.matcher_change;
        let _ = outputs.include_receipt;
        let _ = outputs.exec_amount;
    }

    #[test]
    fn detected_order_has_token_cov_id() {
        let order = make_cross_pair_order(OrderSide::Buy, 1, 1, 10_000_000, &"cc".repeat(32));
        assert_eq!(order.token_cov_id, "cc".repeat(32));
        assert_eq!(order.token_cov_id.len(), 64);
    }

    #[test]
    fn cross_pair_outputs_dust_change_folded() {
        // Set up so that raw_change is between 0 and MIN_UTXO_VALUE
        let sell = make_cross_pair_order(OrderSide::Sell, 1, 1, 10_000_000, &"aa".repeat(32));
        // surplus = buy.value - sell_kas = 1_010_000
        // fee = 10K; raw_change = 1_000_000 < MIN_UTXO_VALUE (3M)
        let buy = make_cross_pair_order(OrderSide::Buy, 1, 1, 11_010_000, &"bb".repeat(32));

        let sell_kas = 10_000_000u64;
        let buy_tokens = 11_010_000u64;

        let outputs = compute_cross_pair_outputs(&sell, &buy, sell_kas, buy_tokens).unwrap();

        assert_eq!(outputs.matcher_change, 0, "Dust change should be folded");
        // raw_change (1M) is added to seller_kas
        assert_eq!(outputs.seller_kas, sell_kas + 1_000_000, "Dust folded into seller_kas");

        // Surplus balance check (receipt from fee UTXOs, not surplus)
        let surplus_total = outputs.seller_kas + outputs.matcher_change + DEFAULT_MATCHER_FEE;
        assert_eq!(surplus_total, buy.value);
    }
}
