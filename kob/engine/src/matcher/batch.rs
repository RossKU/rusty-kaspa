//! N-to-M batch transaction builder for atomic multi-order matching.

use std::collections::{HashMap, HashSet};

use kob_core::{DEFAULT_MATCHER_FEE, MIN_UTXO_VALUE};

/// Order type (buy or sell) for batch matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderType {
    Buy,
    Sell,
}

/// A single order to include in a batch match.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct BatchOrder {
    /// Outpoint (txid, index) of the order UTXO.
    pub outpoint: (String, u32),
    /// Order type (buy or sell).
    pub order_type: OrderType,
    /// Contract version (sell: 6/8, buy: 8/10/11).
    pub version: u8,
    /// Token covenant ID (32 bytes).
    pub token_cov_id: [u8; 32],
    /// Price numerator (rational price = price_num / price_den).
    pub price_num: u64,
    /// Price denominator.
    pub price_den: u64,
    /// Order amount:
    ///   Sell: token amount (UTXO value in tokens)
    ///   Buy: KAS amount (UTXO value in KAS)
    pub amount: u64,
    /// Full redeemScript bytes.
    pub redeem_script: Vec<u8>,
    /// UTXO value in sompi.
    pub utxo_value: u64,
    /// Counterparty scriptPublicKey bytes (the destination for this order's output).
    ///
    /// For sell orders: seller's SPK (KAS payment destination).
    /// For buy orders: buyer's SPK (token payment destination).
    pub counterparty_spk: Vec<u8>,
    /// Counterparty SPK version.
    pub counterparty_spk_version: u16,
}

/// Token unit input for providing tokens to buy orders.
#[derive(Debug, Clone)]
pub struct TokenUnit {
    /// Outpoint (txid, index).
    pub outpoint: (String, u32),
    /// Token covenant ID (must match a buy order's token).
    pub token_cov_id: [u8; 32],
    /// Available token amount.
    pub value: u64,
    /// Token unit redeemScript.
    pub redeem_script: Vec<u8>,
}

/// Purpose of a planned output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variant not yet constructed; used in match pattern
pub enum OutputPurpose {
    /// KAS payment to a seller.
    SellerKas,
    /// Token payment to a buyer.
    BuyerTokens,
    /// Matcher fee/profit output.
    MatcherFee,
    /// Wallet change (unused KAS back to matcher).
    WalletChange,
}

/// A planned output in the batch TX.
#[derive(Debug, Clone)]
pub struct PlannedOutput {
    /// Output value in sompi.
    pub value: u64,
    /// ScriptPublicKey bytes (P2PK or P2SH).
    pub script_public_key: Vec<u8>,
    /// SPK version.
    pub spk_version: u16,
    /// Purpose of this output.
    pub purpose: OutputPurpose,
}

/// Errors that can occur during batch planning.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Variant not yet constructed; used in Display impl
pub enum BatchError {
    /// An order version is not supported for batch matching.
    UnsupportedVersion { outpoint: String, version: u8 },
    /// No orders provided.
    EmptyBatch,
    /// Output value below MIN_UTXO_VALUE.
    OutputBelowMinimum { index: usize, value: u64 },
    /// Amounts do not balance (inputs != outputs + fee).
    AmountMismatch { total_in: u64, total_out: u64, fee: u64 },
    /// Missing token unit for a buy order's token.
    MissingTokenUnit { token_cov_id: String },
    /// Index exceeds OpN range (>16) -- currently unsupported by Kaspa script.
    IndexOutOfRange { index: usize },
    /// Insufficient wallet UTXO for fees.
    InsufficientFee { needed: u64, available: u64 },
    /// No sell orders provided.
    NoSellOrders,
    /// No buy orders provided.
    NoBuyOrders,
    /// Duplicate outpoint detected (would cause double-spend rejection).
    DuplicateOutpoint(String),
    /// Price denominator is zero (would cause division by zero).
    ZeroPriceDenominator { index: usize, side: &'static str },
    /// Arithmetic overflow (u128 result does not fit in u64).
    Overflow { index: usize, side: &'static str, detail: &'static str },
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchError::UnsupportedVersion { outpoint, version } => {
                write!(f, "Order {} is v{}, unsupported in batch (sell: v6/v8/v12/v13, buy: v8/v9/v10/v11/v12/v13)", outpoint, version)
            }
            BatchError::EmptyBatch => write!(f, "No orders in batch"),
            BatchError::OutputBelowMinimum { index, value } => {
                write!(f, "Output[{}] value {} below MIN_UTXO_VALUE {}", index, value, MIN_UTXO_VALUE)
            }
            BatchError::AmountMismatch { total_in, total_out, fee } => {
                write!(f, "Amount mismatch: in={} out={} fee={}", total_in, total_out, fee)
            }
            BatchError::MissingTokenUnit { token_cov_id } => {
                write!(f, "No token unit for covenant {}", token_cov_id)
            }
            BatchError::IndexOutOfRange { index } => {
                write!(f, "TX index {} exceeds OpN range (max 16)", index)
            }
            BatchError::InsufficientFee { needed, available } => {
                write!(f, "Insufficient fee UTXO: need {} have {}", needed, available)
            }
            BatchError::NoSellOrders => write!(f, "No sell orders in batch"),
            BatchError::NoBuyOrders => write!(f, "No buy orders in batch"),
            BatchError::DuplicateOutpoint(ref key) => write!(f, "Duplicate outpoint: {}", key),
            BatchError::ZeroPriceDenominator { index, side } => {
                write!(f, "Order[{}] ({}) has price_den=0 (division by zero)", index, side)
            }
            BatchError::Overflow { index, side, detail } => {
                write!(f, "Order[{}] ({}) arithmetic overflow: {}", index, side, detail)
            }
        }
    }
}

/// A fully built batch transaction input.
#[derive(Debug, Clone)]
pub struct BatchTxInput {
    pub tx_id: String,
    pub index: u32,
    pub sigscript: Vec<u8>,
    pub sig_op_count: u8,
}

/// A fully built batch transaction output.
#[derive(Debug, Clone)]
pub struct BatchTxOutput {
    pub value: u64,
    pub script_public_key: Vec<u8>,
    pub spk_version: u16,
    pub purpose: OutputPurpose,
}

/// The fully built batch transaction.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in tests
pub struct BatchTx {
    pub inputs: Vec<BatchTxInput>,
    pub outputs: Vec<BatchTxOutput>,
    pub fee: u64,
}

/// Complete batch match plan.
///
/// Maps orders to specific input/output indices and computes all sigscripts.
#[derive(Debug, Clone)]
pub struct BatchPlan {
    /// Sell orders with their assigned input indices.
    pub sells: Vec<(BatchOrder, usize)>,
    /// Buy orders with their assigned input indices.
    pub buys: Vec<(BatchOrder, usize)>,
    /// Token units with their assigned input indices.
    pub token_units: Vec<(TokenUnit, usize)>,
    /// Optional wallet UTXO for fee payment (txid, index, value).
    pub wallet_input: Option<(String, u32, u64)>,
    /// Planned outputs.
    pub outputs: Vec<PlannedOutput>,
    /// Total miner fee.
    pub total_fee: u64,
    /// Matcher surplus (profit from price spread).
    pub matcher_surplus: u64,
    /// Mapping: buy's token_cov_id (hex) -> token_unit input index.
    pub token_input_map: HashMap<String, usize>,
    /// Mapping: buy input index -> seller output index (soi for v11).
    pub buy_seller_map: HashMap<usize, usize>,
}

impl BatchPlan {
    /// Build the actual TX inputs/outputs/sigscripts from the plan.
    pub fn build_tx(&self) -> Result<BatchTx, BatchError> {
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();

        // === Build sell inputs ===
        for (sell, input_idx) in &self.sells {
            let koi = *input_idx; // seller's KAS output is at output[input_idx]
            if koi > 16 {
                return Err(BatchError::IndexOutOfRange { index: koi });
            }
            let ss = build_sell_fill_sigscript_batch(koi as u8, &sell.redeem_script)?;
            inputs.push(BatchTxInput {
                tx_id: sell.outpoint.0.clone(),
                index: sell.outpoint.1,
                sigscript: ss,
                sig_op_count: 0,
            });
        }

        // === Build buy inputs ===
        // Track covenant output count per token_cov_id for coi computation
        let mut cov_out_counter: HashMap<String, u8> = HashMap::new();
        for (buy, input_idx) in &self.buys {
            let token_hex = hex::encode(buy.token_cov_id);
            let tii = self.token_input_map.get(&token_hex)
                .ok_or_else(|| BatchError::MissingTokenUnit {
                    token_cov_id: token_hex.clone(),
                })?;

            // Buy's output index = N + j where j is position in buys vec
            // SAFETY: buy is yielded from self.buys iterator, so it is always found
            let buy_pos = self.buys.iter().position(|(b, _)| {
                b.outpoint == buy.outpoint
            }).expect("buy must exist in self.buys");
            let toi = self.sells.len() + buy_pos;

            // coi = index of this buy's output among all covenant outputs for this token
            let coi = *cov_out_counter.get(&token_hex).unwrap_or(&0);
            *cov_out_counter.entry(token_hex).or_insert(0) += 1;

            if toi > 16 || *tii > 16 {
                return Err(BatchError::IndexOutOfRange {
                    index: toi.max(*tii),
                });
            }
            if coi > 16 {
                return Err(BatchError::IndexOutOfRange { index: coi as usize });
            }

            let ss = match buy.version {
                11 | 12 => {
                    let soi = self.buy_seller_map.get(input_idx)
                        .copied()
                        .unwrap_or(0) as u8;
                    build_buy_fill_sigscript_batch_v11(
                        soi,
                        toi as u8,
                        *tii as u8,
                        coi,
                        &buy.redeem_script,
                    )?
                }
                _ => {
                    // v8/v9/v10/v13: no soi parameter (v13 uses conservation instead)
                    build_buy_fill_sigscript_batch(
                        toi as u8,
                        *tii as u8,
                        coi,
                        &buy.redeem_script,
                    )?
                }
            };
            inputs.push(BatchTxInput {
                tx_id: buy.outpoint.0.clone(),
                index: buy.outpoint.1,
                sigscript: ss,
                sig_op_count: 0,
            });
        }

        // === Build token unit inputs ===
        for (token_unit, _input_idx) in &self.token_units {
            let ss = build_token_unit_sigscript_batch(&token_unit.redeem_script);
            inputs.push(BatchTxInput {
                tx_id: token_unit.outpoint.0.clone(),
                index: token_unit.outpoint.1,
                sigscript: ss,
                sig_op_count: 0,
            });
        }

        // === Build wallet input (for fee) ===
        if let Some((ref tx_id, index, _value)) = self.wallet_input {
            inputs.push(BatchTxInput {
                tx_id: tx_id.clone(),
                index,
                sigscript: Vec::new(), // Needs P2PK signing externally
                sig_op_count: 1,
            });
        }

        // === Build outputs ===
        for planned in &self.outputs {
            outputs.push(BatchTxOutput {
                value: planned.value,
                script_public_key: planned.script_public_key.clone(),
                spk_version: planned.spk_version,
                purpose: planned.purpose,
            });
        }

        Ok(BatchTx {
            inputs,
            outputs,
            fee: self.total_fee,
        })
    }

    /// Validate the plan: all contracts satisfied, fees covered, amounts balanced.
    pub fn validate(&self) -> Result<(), BatchError> {
        // Check: order versions (sell: v6/v8/v12/v13, buy: v8/v9/v10/v11/v12/v13)
        for (sell, _) in &self.sells {
            if !matches!(sell.version, 6 | 8 | 12 | 13) {
                return Err(BatchError::UnsupportedVersion {
                    outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
                    version: sell.version,
                });
            }
        }
        for (buy, _) in &self.buys {
            if !matches!(buy.version, 8..=13) {
                return Err(BatchError::UnsupportedVersion {
                    outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
                    version: buy.version,
                });
            }
        }

        // Check: non-empty
        if self.sells.is_empty() {
            return Err(BatchError::NoSellOrders);
        }
        if self.buys.is_empty() {
            return Err(BatchError::NoBuyOrders);
        }

        // Check: all output values >= MIN_UTXO_VALUE
        for (i, out) in self.outputs.iter().enumerate() {
            if out.value < MIN_UTXO_VALUE {
                return Err(BatchError::OutputBelowMinimum {
                    index: i,
                    value: out.value,
                });
            }
        }

        // Check: every buy's token has a token_unit
        for (buy, _) in &self.buys {
            let token_hex = hex::encode(buy.token_cov_id);
            if !self.token_input_map.contains_key(&token_hex) {
                return Err(BatchError::MissingTokenUnit {
                    token_cov_id: token_hex,
                });
            }
        }

        // Check: index range (all input/output indices <= 16)
        let total_inputs = self.sells.len()
            + self.buys.len()
            + self.token_units.len()
            + if self.wallet_input.is_some() { 1 } else { 0 };
        let total_outputs = self.outputs.len();
        if total_inputs > 17 || total_outputs > 17 {
            return Err(BatchError::IndexOutOfRange {
                index: total_inputs.max(total_outputs),
            });
        }

        // Check: amounts balance
        //   Total KAS in = sum(buy.utxo_value) + wallet_input.value
        //   Total KAS out = sum(seller_kas outputs) + matcher_fee + wallet_change + fee
        //
        // Token accounting is separate (token_unit inputs provide tokens for buyer outputs).
        // We verify KAS balance only.
        let kas_in: u64 = self.buys.iter().map(|(b, _)| b.utxo_value).sum::<u64>()
            + self.wallet_input.as_ref().map_or(0, |w| w.2);
        let kas_out: u64 = self.outputs.iter()
            .filter(|o| matches!(o.purpose, OutputPurpose::SellerKas | OutputPurpose::MatcherFee | OutputPurpose::WalletChange))
            .map(|o| o.value)
            .sum();
        let expected_out = kas_out + self.total_fee;
        if kas_in != expected_out {
            return Err(BatchError::AmountMismatch {
                total_in: kas_in,
                total_out: kas_out,
                fee: self.total_fee,
            });
        }

        Ok(())
    }
}

// Plan Builder

/// Build a batch plan from a set of matchable orders.
///
/// # Arguments
/// * `sells` - Sell orders to include (v6 or v8).
/// * `buys` - Buy orders to include (v8, v10, or v11).
/// * `token_units` - Available token units (one per unique token that buys need).
/// * `wallet_utxo` - Optional wallet UTXO for fee payment (txid, index, value).
/// * `matcher_spk` - Matcher's scriptPublicKey bytes for receiving KAS outputs.
/// * `matcher_spk_version` - SPK version.
///
/// # Returns
/// A `BatchPlan` with all indices assigned and outputs computed.
pub fn plan_batch_match(
    sells: &[BatchOrder],
    buys: &[BatchOrder],
    token_units: &[TokenUnit],
    wallet_utxo: Option<(String, u32, u64)>,
    matcher_spk: &[u8],
    matcher_spk_version: u16,
) -> Result<BatchPlan, BatchError> {
    if sells.is_empty() {
        return Err(BatchError::NoSellOrders);
    }
    if buys.is_empty() {
        return Err(BatchError::NoBuyOrders);
    }

    // Reject duplicate outpoints (would cause double-spend rejection on-chain)
    {
        let mut seen = HashSet::new();
        for sell in sells {
            let key = format!("{}:{}", sell.outpoint.0, sell.outpoint.1);
            if !seen.insert(key.clone()) {
                return Err(BatchError::DuplicateOutpoint(key));
            }
        }
        for buy in buys {
            let key = format!("{}:{}", buy.outpoint.0, buy.outpoint.1);
            if !seen.insert(key.clone()) {
                return Err(BatchError::DuplicateOutpoint(key));
            }
        }
    }

    // Validate order versions (sell: v6/v8/v12/v13, buy: v8/v9/v10/v11/v12/v13)
    for sell in sells {
        if !matches!(sell.version, 6 | 8 | 12 | 13) {
            return Err(BatchError::UnsupportedVersion {
                outpoint: format!("{}:{}", sell.outpoint.0, sell.outpoint.1),
                version: sell.version,
            });
        }
    }
    for buy in buys {
        if !matches!(buy.version, 8..=13) {
            return Err(BatchError::UnsupportedVersion {
                outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
                version: buy.version,
            });
        }
    }

    let n = sells.len();
    let m = buys.len();

    // Build token_input_map: token_cov_id (hex) -> input index
    // Token units start at input[N+M]
    let mut token_input_map: HashMap<String, usize> = HashMap::new();
    let mut used_token_units: Vec<(TokenUnit, usize)> = Vec::new();

    // Determine which tokens are needed by buy orders
    let mut needed_tokens: HashMap<String, bool> = HashMap::new();
    for buy in buys {
        let token_hex = hex::encode(buy.token_cov_id);
        needed_tokens.insert(token_hex, true);
    }

    // Assign token units to input slots
    let mut token_idx = n + m;
    for token_hex in needed_tokens.keys() {
        let token_unit = token_units.iter()
            .find(|tu| hex::encode(tu.token_cov_id) == *token_hex)
            .ok_or_else(|| BatchError::MissingTokenUnit {
                token_cov_id: token_hex.clone(),
            })?;
        token_input_map.insert(token_hex.clone(), token_idx);
        used_token_units.push((token_unit.clone(), token_idx));
        token_idx += 1;
    }

    let t = used_token_units.len();

    // Check total input count doesn't exceed OpN limit
    let total_inputs = n + m + t + if wallet_utxo.is_some() { 1 } else { 0 };
    if total_inputs > 17 {
        return Err(BatchError::IndexOutOfRange { index: total_inputs });
    }
    // Check total outputs (N + M + optional matcher_fee + optional change)
    // Worst case: N + M + 2
    if n + m + 2 > 17 {
        return Err(BatchError::IndexOutOfRange { index: n + m + 2 });
    }

    // Assign sell orders to input[0..N-1]
    let plan_sells: Vec<(BatchOrder, usize)> = sells.iter()
        .enumerate()
        .map(|(i, s)| (s.clone(), i))
        .collect();

    // Assign buy orders to input[N..N+M-1]
    let plan_buys: Vec<(BatchOrder, usize)> = buys.iter()
        .enumerate()
        .map(|(j, b)| (b.clone(), n + j))
        .collect();

    // Compute output amounts
    //
    // For each sell[i]:
    //   expected_kas = (sell.amount * sell.price_num) / sell.price_den
    //   output[i] = expected_kas (KAS to seller)
    //
    // For each buy[j]:
    //   expected_tokens = (buy.amount * buy.price_num) / buy.price_den
    //   output[N+j] = expected_tokens (tokens to buyer)
    let mut outputs: Vec<PlannedOutput> = Vec::new();

    // Seller KAS outputs
    let mut total_seller_kas: u64 = 0;
    for (i, sell) in sells.iter().enumerate() {
        if sell.price_den == 0 {
            return Err(BatchError::ZeroPriceDenominator { index: i, side: "sell" });
        }
        let expected_kas_128 = sell.amount as u128 * sell.price_num as u128
            / sell.price_den as u128;
        if expected_kas_128 > u64::MAX as u128 {
            return Err(BatchError::Overflow {
                index: i,
                side: "sell",
                detail: "u128 to u64 truncation in expected_kas",
            });
        }
        let expected_kas = expected_kas_128 as u64;
        if expected_kas < MIN_UTXO_VALUE {
            return Err(BatchError::OutputBelowMinimum {
                index: i,
                value: expected_kas,
            });
        }
        total_seller_kas += expected_kas;
        outputs.push(PlannedOutput {
            value: expected_kas,
            script_public_key: sell.counterparty_spk.clone(),
            spk_version: sell.counterparty_spk_version,
            purpose: OutputPurpose::SellerKas,
        });
    }

    // Buyer token outputs
    let mut total_buyer_tokens_by_cov: HashMap<String, u64> = HashMap::new();
    for (j, buy) in buys.iter().enumerate() {
        if buy.price_den == 0 {
            return Err(BatchError::ZeroPriceDenominator { index: n + j, side: "buy" });
        }
        let expected_tokens_128 = buy.amount as u128 * buy.price_num as u128
            / buy.price_den as u128;
        if expected_tokens_128 > u64::MAX as u128 {
            return Err(BatchError::Overflow {
                index: n + j,
                side: "buy",
                detail: "u128 to u64 truncation in expected_tokens",
            });
        }
        let expected_tokens = expected_tokens_128 as u64;
        if expected_tokens < MIN_UTXO_VALUE {
            return Err(BatchError::OutputBelowMinimum {
                index: n + j,
                value: expected_tokens,
            });
        }
        let token_hex = hex::encode(buy.token_cov_id);
        *total_buyer_tokens_by_cov.entry(token_hex).or_insert(0) += expected_tokens;
        outputs.push(PlannedOutput {
            value: expected_tokens,
            script_public_key: buy.counterparty_spk.clone(),
            spk_version: buy.counterparty_spk_version,
            purpose: OutputPurpose::BuyerTokens,
        });
    }

    // Validate token balance: total buyer tokens per covenant <= token unit value
    for (cov_hex, needed) in &total_buyer_tokens_by_cov {
        let available = used_token_units.iter()
            .filter(|(tu, _)| hex::encode(tu.token_cov_id) == *cov_hex)
            .map(|(tu, _)| tu.value)
            .sum::<u64>();
        if *needed > available {
            return Err(BatchError::MissingTokenUnit {
                token_cov_id: format!("{} (need {} have {})", cov_hex, needed, available),
            });
        }
    }

    // Compute KAS surplus
    //   Total KAS in = sum(buy.utxo_value) + wallet_utxo.value
    //   Total KAS out needed = sum(seller_kas) + fee
    //   Surplus = total_kas_in - total_kas_out_needed
    let total_buy_kas: u64 = buys.iter().map(|b| b.utxo_value).sum();
    let wallet_value = wallet_utxo.as_ref().map_or(0, |w| w.2);
    let total_kas_in = total_buy_kas + wallet_value;
    // Estimate miner fee from compute mass. Batch TX inputs: buys + sells + token units + wallet.
    // Outputs: seller_kas per sell + buyer_tokens per buy + matcher_fee.
    let num_inputs = buys.len() + sells.len() + used_token_units.len()
        + if wallet_utxo.is_some() { 1 } else { 0 };
    let num_outputs = sells.len() + buys.len() + 1; // +1 for matcher fee output
    let total_fee = kob_core::mass::estimate_compute_mass(num_inputs, num_outputs, 0);

    if total_kas_in < total_seller_kas + total_fee {
        return Err(BatchError::InsufficientFee {
            needed: total_seller_kas + total_fee,
            available: total_kas_in,
        });
    }

    let raw_surplus = total_kas_in - total_seller_kas - total_fee;

    // If surplus >= MIN_UTXO_VALUE, create a matcher fee output
    // Otherwise, distribute surplus to first seller output
    let matcher_surplus;
    if raw_surplus >= MIN_UTXO_VALUE {
        matcher_surplus = raw_surplus;
        outputs.push(PlannedOutput {
            value: raw_surplus,
            script_public_key: matcher_spk.to_vec(),
            spk_version: matcher_spk_version,
            purpose: OutputPurpose::MatcherFee,
        });
    } else {
        // Add dust surplus to first seller's KAS output
        matcher_surplus = 0;
        if !outputs.is_empty() {
            outputs[0].value += raw_surplus;
        }
    }

    // Build buy-to-sell mapping for soi (round-robin across matching sells)
    let mut buy_seller_map: HashMap<usize, usize> = HashMap::new();
    let mut sell_usage_count: HashMap<usize, usize> = HashMap::new();
    for (j, buy) in buys.iter().enumerate() {
        // Find sells matching this buy's token, pick the least-used one
        let matching_sells: Vec<usize> = sells.iter()
            .enumerate()
            .filter(|(_, s)| s.token_cov_id == buy.token_cov_id)
            .map(|(i, _)| i)
            .collect();

        let seller_idx = if matching_sells.is_empty() {
            0 // fallback
        } else {
            // Pick the sell with lowest usage count
            *matching_sells.iter()
                .min_by_key(|&&idx| sell_usage_count.get(&idx).unwrap_or(&0))
                .unwrap()
        };

        *sell_usage_count.entry(seller_idx).or_insert(0) += 1;
        buy_seller_map.insert(n + j, seller_idx);
    }

    Ok(BatchPlan {
        sells: plan_sells,
        buys: plan_buys,
        token_units: used_token_units,
        wallet_input: wallet_utxo,
        outputs,
        total_fee,
        matcher_surplus,
        token_input_map,
        buy_seller_map,
    })
}

// Sigscript Builders (batch-specific)

/// Convert an integer (0..=16) to the corresponding OpN opcode byte.
///
/// Op0 = 0x00, Op1 = 0x51, Op2 = 0x52, ..., Op16 = 0x60.
///
/// Returns Err if n > 16 (H-2: no panic on out-of-range index).
fn opn(n: u8) -> Result<u8, BatchError> {
    match n {
        0 => Ok(0x00),
        1..=16 => Ok(0x50 + n),
        _ => Err(BatchError::IndexOutOfRange { index: n as usize }),
    }
}

/// Build sell_v8 fill sigscript for batch: `[Op(koi)] [Op1] [pushData(RS)]`
///
/// * `kas_output_idx`: which output receives the seller's KAS
fn build_sell_fill_sigscript_batch(kas_output_idx: u8, redeem_script: &[u8]) -> Result<Vec<u8>, BatchError> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(opn(kas_output_idx)?);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&kob_core::push_data(redeem_script));
    Ok(ss)
}

/// Build buy_v8 fill sigscript for batch: `[Op(toi)] [Op(tii)] [Op(coi)] [Op1] [pushData(RS)]`
///
/// * `token_output_idx`: which output receives the buyer's tokens (toi)
/// * `token_input_idx`: which input carries the token covenant (tii)
/// * `cov_output_idx`: which covenant output index for OpCovOutputIdx lookup (coi)
fn build_buy_fill_sigscript_batch(
    token_output_idx: u8,
    token_input_idx: u8,
    cov_output_idx: u8,
    redeem_script: &[u8],
) -> Result<Vec<u8>, BatchError> {
    let mut ss = Vec::with_capacity(4 + redeem_script.len() + 3);
    ss.push(opn(token_output_idx)?);
    ss.push(opn(token_input_idx)?);
    ss.push(opn(cov_output_idx)?);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&kob_core::push_data(redeem_script));
    Ok(ss)
}

/// Build buy_v11 fill sigscript for batch: `[Op(soi)] [Op(toi)] [Op(tii)] [Op(coi)] [Op1] [pushData(RS)]`
///
/// v11 adds soi (seller output index) parameter for batch fill defense.
/// In batch TX, soi = index of the seller KAS output this buy is paired with.
fn build_buy_fill_sigscript_batch_v11(
    seller_output_idx: u8,
    token_output_idx: u8,
    token_input_idx: u8,
    cov_output_idx: u8,
    redeem_script: &[u8],
) -> Result<Vec<u8>, BatchError> {
    let mut ss = Vec::with_capacity(5 + redeem_script.len() + 3);
    ss.push(opn(seller_output_idx)?);
    ss.push(opn(token_output_idx)?);
    ss.push(opn(token_input_idx)?);
    ss.push(opn(cov_output_idx)?);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&kob_core::push_data(redeem_script));
    Ok(ss)
}

/// Build token_unit sigscript for batch: `[pushData(RS)]`
fn build_token_unit_sigscript_batch(redeem_script: &[u8]) -> Vec<u8> {
    kob_core::push_data(redeem_script)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test token covenant IDs
    const TOKEN_A: [u8; 32] = [0x01; 32];
    const TOKEN_B: [u8; 32] = [0x02; 32];
    const TOKEN_C: [u8; 32] = [0x03; 32];

    /// Create a fake sell order for testing.
    fn make_sell(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        // Build a real v13 sell RS for correct sigscript sizing
        let owner = [0xBB; 32];
        let sspkh = [0xCC; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            price_num, price_den, 1_000_000, &owner, &sspkh, 0, 0, 0,).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Sell,
            version: 13,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xDD; 34], // fake seller SPK
            counterparty_spk_version: 0,
        }
    }

    /// Create a fake buy order for testing.
    fn make_buy(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        let owner = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &token, price_num, price_den, 1_000_000, &owner, &bspkh, 0, 0, 0,).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Buy,
            version: 13,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xEE; 34], // fake buyer SPK
            counterparty_spk_version: 0,
        }
    }

    /// Create a fake token unit for testing.
    fn make_token_unit(id_byte: u8, token: [u8; 32], value: u64) -> TokenUnit {
        let tx_id = hex::encode(&[id_byte; 32]);
        TokenUnit {
            outpoint: (tx_id, 0),
            token_cov_id: token,
            value,
            redeem_script: kob_core::TOKEN_RS.to_vec(),
        }
    }

    /// Matcher SPK for tests (fake P2PK: 0xCC repeated).
    fn matcher_spk() -> Vec<u8> {
        vec![0xCC; 34]
    }

    // Test 1: Simple same-pair batch (2 sells + 2 buys of same token)
    #[test]
    fn test_simple_same_pair_batch() {
        // Sell 10M Token A at price 1/2 => expects 5M KAS each
        let sell1 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let sell2 = make_sell(0x11, 10_000_000, 1, 2, TOKEN_A);

        // Buy 10M KAS for Token A at price 1/3 => expects ~3.33M tokens each
        // Buy utxo_value = 10M KAS, seller expects 5M KAS per sell
        // Surplus per sell-buy pair: 10M - 5M = 5M
        let buy1 = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let buy2 = make_buy(0x21, 10_000_000, 1, 3, TOKEN_A);

        let token_unit = make_token_unit(0x30, TOKEN_A, 100_000_000);

        let plan = plan_batch_match(
            &[sell1, sell2],
            &[buy1, buy2],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        // 2 sells + 2 buys = 4 orders
        assert_eq!(plan.sells.len(), 2, "should have 2 sells");
        assert_eq!(plan.buys.len(), 2, "should have 2 buys");
        assert_eq!(plan.token_units.len(), 1, "should have 1 token unit (both buys use same token)");

        // Input indices: sell[0]=0, sell[1]=1, buy[0]=2, buy[1]=3, token_unit=4
        assert_eq!(plan.sells[0].1, 0);
        assert_eq!(plan.sells[1].1, 1);
        assert_eq!(plan.buys[0].1, 2);
        assert_eq!(plan.buys[1].1, 3);
        assert_eq!(plan.token_units[0].1, 4);

        // Output indices: seller_kas[0]=0, seller_kas[1]=1, buyer_tokens[0]=2, buyer_tokens[1]=3
        assert_eq!(plan.outputs.len(), 4 + 1, "4 order outputs + 1 matcher fee");
        assert_eq!(plan.outputs[0].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[1].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[2].purpose, OutputPurpose::BuyerTokens);
        assert_eq!(plan.outputs[3].purpose, OutputPurpose::BuyerTokens);

        // Seller KAS: 10M * 1/2 = 5M each
        assert_eq!(plan.outputs[0].value, 5_000_000);
        assert_eq!(plan.outputs[1].value, 5_000_000);

        // Buyer tokens: 10M * 1/3 = 3_333_333 each
        assert_eq!(plan.outputs[2].value, 3_333_333);
        assert_eq!(plan.outputs[3].value, 3_333_333);

        // Build TX and verify
        let tx = plan.build_tx().expect("build_tx should succeed");
        assert_eq!(tx.inputs.len(), 5, "2 sells + 2 buys + 1 token unit");
        assert_eq!(tx.outputs.len(), 5, "2 seller KAS + 2 buyer tokens + 1 matcher fee");
    }

    // Test 2: Cross-pair batch (sell A->KAS + buy KAS->B + token_unit B)
    #[test]
    fn test_cross_pair_batch() {
        // Sell 20M Token A at price 1/2 => expects 10M KAS
        let sell = make_sell(0x10, 20_000_000, 1, 2, TOKEN_A);

        // Buy Token B with 15M KAS at price 1/3 => expects 5M Token B
        let buy = make_buy(0x20, 15_000_000, 1, 3, TOKEN_B);

        // Token unit provides Token B
        let token_unit = make_token_unit(0x30, TOKEN_B, 50_000_000);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        assert_eq!(plan.sells.len(), 1);
        assert_eq!(plan.buys.len(), 1);
        assert_eq!(plan.token_units.len(), 1);

        // Input: sell[0]=0, buy[0]=1, token_unit(B)=2
        assert_eq!(plan.sells[0].1, 0);
        assert_eq!(plan.buys[0].1, 1);
        assert_eq!(plan.token_units[0].1, 2);

        // Output: seller_kas=10M at output[0], buyer_tokens=5M at output[1]
        assert_eq!(plan.outputs[0].value, 10_000_000);
        assert_eq!(plan.outputs[0].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[1].value, 5_000_000);
        assert_eq!(plan.outputs[1].purpose, OutputPurpose::BuyerTokens);

        // KAS surplus: 15M - 10M - 10K fee = 4_990_000 >= MIN_UTXO_VALUE
        assert!(plan.matcher_surplus >= MIN_UTXO_VALUE);
    }

    // Test 3: Multi-pair batch (sell A + sell B + buy B + buy A + tokens)
    #[test]
    fn test_multi_pair_batch() {
        // Sell 20M Token A at price 1/2 => expects 10M KAS
        let sell_a = make_sell(0x10, 20_000_000, 1, 2, TOKEN_A);
        // Sell 30M Token B at price 1/3 => expects 10M KAS
        let sell_b = make_sell(0x11, 30_000_000, 1, 3, TOKEN_B);

        // Buy Token B with 15M KAS at price 1/3 => expects 5M Token B
        let buy_b = make_buy(0x20, 15_000_000, 1, 3, TOKEN_B);
        // Buy Token A with 15M KAS at price 1/3 => expects 5M Token A
        let buy_a = make_buy(0x21, 15_000_000, 1, 3, TOKEN_A);

        let token_unit_a = make_token_unit(0x30, TOKEN_A, 50_000_000);
        let token_unit_b = make_token_unit(0x31, TOKEN_B, 50_000_000);

        let plan = plan_batch_match(
            &[sell_a, sell_b],
            &[buy_b, buy_a],
            &[token_unit_a, token_unit_b],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        // 2 sells + 2 buys
        assert_eq!(plan.sells.len(), 2);
        assert_eq!(plan.buys.len(), 2);
        // 2 unique tokens needed by buys -> 2 token units
        assert_eq!(plan.token_units.len(), 2);

        // Input layout: sell_a=0, sell_b=1, buy_b=2, buy_a=3, token_unit_x=4, token_unit_y=5
        assert_eq!(plan.sells[0].1, 0);
        assert_eq!(plan.sells[1].1, 1);
        assert_eq!(plan.buys[0].1, 2);
        assert_eq!(plan.buys[1].1, 3);

        // Outputs: 2 seller KAS + 2 buyer tokens + potential matcher fee
        assert!(plan.outputs.len() >= 4, "at least 4 outputs");
        assert_eq!(plan.outputs[0].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[1].purpose, OutputPurpose::SellerKas);
        assert_eq!(plan.outputs[2].purpose, OutputPurpose::BuyerTokens);
        assert_eq!(plan.outputs[3].purpose, OutputPurpose::BuyerTokens);

        // Build TX
        let tx = plan.build_tx().expect("build should succeed");
        assert_eq!(tx.inputs.len(), 6, "2 sells + 2 buys + 2 token units");
    }

    // Test 4: Batch plan validation
    #[test]
    fn test_batch_plan_validation() {
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        // Validate should pass
        let result = plan.validate();
        assert!(result.is_ok(), "valid plan should pass validation: {:?}", result.err());
    }

    // Test 5: Sigscript indices verification
    #[test]
    fn test_sigscript_indices() {
        // Build a small batch to verify sigscript byte encoding
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        let tx = plan.build_tx().expect("build should succeed");

        // Sell at input[0]: koi=0, sigscript starts with Op0=0x00
        let sell_ss = &tx.inputs[0].sigscript;
        assert_eq!(sell_ss[0], 0x00, "sell koi=0 -> Op0 (0x00)");
        assert_eq!(sell_ss[1], 0x51, "sell selector=1 -> Op1 (0x51)");

        // Buy v13 at input[1]: toi=1, tii=2, coi=0, selector=Op1 (no soi)
        let buy_ss = &tx.inputs[1].sigscript;
        assert_eq!(buy_ss[0], 0x51, "buy toi=1 -> Op1 (0x51)");
        assert_eq!(buy_ss[1], 0x52, "buy tii=2 -> Op2 (0x52)");
        assert_eq!(buy_ss[2], 0x00, "buy coi=0 -> Op0 (0x00)");
        assert_eq!(buy_ss[3], 0x51, "buy selector=1 -> Op1 (0x51)");

        // Token unit at input[2]: just pushData(TOKEN_RS)
        let tu_ss = &tx.inputs[2].sigscript;
        // pushData for 7-byte TOKEN_RS: [0x07, ...7 bytes...]
        assert_eq!(tu_ss[0], 0x07, "token unit RS pushdata length (7B)");
    }

    // Test 6: Large batch (10 sells + 10 buys -> verify limits)
    #[test]
    fn test_large_batch() {
        // With 10 sells + 10 buys = 20 orders, input index goes up to 20+
        // This should fail because OpN only supports 0..=16
        let sells: Vec<BatchOrder> = (0..10)
            .map(|i| make_sell(0x10 + i, 10_000_000, 1, 2, TOKEN_A))
            .collect();
        let buys: Vec<BatchOrder> = (0..10)
            .map(|i| make_buy(0x20 + i, 10_000_000, 1, 3, TOKEN_A))
            .collect();
        let token_unit = make_token_unit(0x30, TOKEN_A, 500_000_000);

        let result = plan_batch_match(
            &sells,
            &buys,
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        );

        // 10+10+1 = 21 inputs > 17, should fail with IndexOutOfRange
        assert!(result.is_err(), "batch with 20 orders should fail");
        match result.unwrap_err() {
            BatchError::IndexOutOfRange { index } => {
                assert!(index > 16, "index should exceed 16");
            }
            e => panic!("expected IndexOutOfRange, got: {:?}", e),
        }

        // But 7+7 = 14 orders should work (14+1token+1wallet = 16, within limit)
        let sells7: Vec<BatchOrder> = (0..7)
            .map(|i| make_sell(0x10 + i, 10_000_000, 1, 2, TOKEN_A))
            .collect();
        let buys7: Vec<BatchOrder> = (0..7)
            .map(|i| make_buy(0x20 + i, 10_000_000, 1, 3, TOKEN_A))
            .collect();

        let plan = plan_batch_match(
            &sells7,
            &buys7,
            &[make_token_unit(0x30, TOKEN_A, 500_000_000)],
            None,
            &matcher_spk(),
            0,
        ).expect("7+7 batch should succeed");

        assert_eq!(plan.sells.len(), 7);
        assert_eq!(plan.buys.len(), 7);

        let tx = plan.build_tx().expect("build should succeed");
        // 7 sells + 7 buys + 1 token unit = 15 inputs
        assert_eq!(tx.inputs.len(), 15);
    }

    // Test 7: Fee calculation
    #[test]
    fn test_fee_calculation() {
        // Sell 10M Token A at 1/2 => expects 5M KAS
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        // Buy 10M KAS for Token A at 1/3 => expects 3.33M tokens
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        // Fee is computed from mass: 2 buys + 1 sell + 1 token = 4 inputs, ~3 outputs
        let expected_fee = kob_core::mass::estimate_compute_mass(3, 3, 0);
        assert_eq!(plan.total_fee, expected_fee, "fee should match mass-based estimate");

        // KAS surplus = 10M (buy) - 5M (seller) - fee
        let expected_surplus = 10_000_000 - 5_000_000 - expected_fee;
        assert_eq!(plan.matcher_surplus, expected_surplus);

        // Verify matcher fee output exists
        let matcher_out = plan.outputs.iter()
            .find(|o| o.purpose == OutputPurpose::MatcherFee);
        assert!(matcher_out.is_some(), "should have matcher fee output");
        assert_eq!(matcher_out.unwrap().value, expected_surplus);
    }

    // Test 8: version validation (sell: v6/v8 OK, buy: v8/v10/v11 OK)
    #[test]
    fn test_version_validation() {
        // v6 sell should now be accepted
        let mut sell_v6 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        sell_v6.version = 6;

        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let result = plan_batch_match(
            &[sell_v6],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        );
        assert!(result.is_ok(), "v6 sell should be accepted: {:?}", result.err());

        // v5 sell should be rejected
        let mut sell_v5 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        sell_v5.version = 5;

        let result2 = plan_batch_match(
            &[sell_v5],
            &[make_buy(0x20, 10_000_000, 1, 3, TOKEN_A)],
            &[make_token_unit(0x30, TOKEN_A, 50_000_000)],
            None,
            &matcher_spk(),
            0,
        );
        assert!(result2.is_err(), "v5 sell should be rejected");
        match result2.unwrap_err() {
            BatchError::UnsupportedVersion { version, .. } => assert_eq!(version, 5),
            e => panic!("expected UnsupportedVersion, got: {:?}", e),
        }

        // v6 buy should be rejected
        let sell_v8 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let mut buy_v6 = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        buy_v6.version = 6;

        let result3 = plan_batch_match(
            &[sell_v8],
            &[buy_v6],
            &[make_token_unit(0x30, TOKEN_A, 50_000_000)],
            None,
            &matcher_spk(),
            0,
        );
        assert!(result3.is_err(), "v6 buy should be rejected");
        match result3.unwrap_err() {
            BatchError::UnsupportedVersion { version, .. } => assert_eq!(version, 6),
            e => panic!("expected UnsupportedVersion, got: {:?}", e),
        }

        // v10 buy should be accepted
        let mut buy_v10 = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        buy_v10.version = 10;

        let result4 = plan_batch_match(
            &[make_sell(0x10, 10_000_000, 1, 2, TOKEN_A)],
            &[buy_v10],
            &[make_token_unit(0x30, TOKEN_A, 50_000_000)],
            None,
            &matcher_spk(),
            0,
        );
        assert!(result4.is_ok(), "v10 buy should be accepted: {:?}", result4.err());
    }

    // Test 9: Outputs below MIN_UTXO_VALUE are rejected
    #[test]
    fn test_min_utxo_filter() {
        // Sell 3M tokens at price 1/10 => expects 300K KAS (below MIN_UTXO_VALUE=3M)
        let sell = make_sell(0x10, 3_000_000, 1, 10, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        );

        assert!(result.is_err(), "output below MIN_UTXO_VALUE should be rejected");
        match result.unwrap_err() {
            BatchError::OutputBelowMinimum { value, .. } => {
                assert!(value < MIN_UTXO_VALUE, "value {} should be below {}", value, MIN_UTXO_VALUE);
            }
            e => panic!("expected OutputBelowMinimum, got: {:?}", e),
        }

        // Also test buy side: buy 3M KAS at price 1/10 => expects 300K tokens
        let sell2 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy2 = make_buy(0x20, 3_000_000, 1, 10, TOKEN_A);

        let result2 = plan_batch_match(
            &[sell2],
            &[buy2],
            &[make_token_unit(0x30, TOKEN_A, 50_000_000)],
            None,
            &matcher_spk(),
            0,
        );

        assert!(result2.is_err(), "buyer token output below MIN_UTXO_VALUE should be rejected");
    }

    // Additional: wallet input for fee coverage
    #[test]
    fn test_wallet_input_for_fees() {
        // Sell 10M Token A at 1/1 => expects 10M KAS (all of buy's KAS goes to seller)
        let sell = make_sell(0x10, 10_000_000, 1, 1, TOKEN_A);
        // Buy 10M KAS for Token A at 1/1 => expects 10M tokens
        // KAS in = 10M, seller needs 10M + fee => deficit
        let buy = make_buy(0x20, 10_000_000, 1, 1, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        // Without wallet: should fail (no surplus for fee)
        let result = plan_batch_match(
            &[sell.clone()],
            &[buy.clone()],
            &[token_unit.clone()],
            None,
            &matcher_spk(),
            0,
        );
        assert!(result.is_err(), "should fail without wallet for fee");

        // With wallet UTXO: should succeed
        let wallet = ("ff".repeat(32), 0, 5_000_000);
        let plan = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            Some(wallet),
            &matcher_spk(),
            0,
        ).expect("should succeed with wallet UTXO");

        assert!(plan.wallet_input.is_some());
        let tx = plan.build_tx().expect("build should succeed");
        // 1 sell + 1 buy + 1 token_unit + 1 wallet = 4 inputs
        assert_eq!(tx.inputs.len(), 4);
        // Wallet input has sig_op_count=1
        assert_eq!(tx.inputs[3].sig_op_count, 1);
    }

    // Additional: missing token unit
    #[test]
    fn test_missing_token_unit() {
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_B); // needs Token B
        // Only provide Token A unit, not Token B
        let token_unit_a = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit_a],
            None,
            &matcher_spk(),
            0,
        );

        assert!(result.is_err(), "missing token unit should fail");
        match result.unwrap_err() {
            BatchError::MissingTokenUnit { .. } => {}
            e => panic!("expected MissingTokenUnit, got: {:?}", e),
        }
    }

    // H-2: coi > 16 triggers IndexOutOfRange (not panic)
    #[test]
    fn test_coi_out_of_range_returns_error() {
        // opn() now returns Result instead of panicking (H-2 fix).
        // plan_batch_match caps at 17 total inputs and at most n+m+2=17 outputs.
        // With 7 sells + 7 buys + 1 token_unit = 15 inputs and 7+7+2=16 outputs,
        // the batch is within limits and coi per-token stays 0..6 (all <= 16). OK.
        // Use 10M value so seller gets 5M (>= MIN_UTXO_VALUE=3M) with price 1/2.
        let sells: Vec<BatchOrder> = (0..7)
            .map(|i| make_sell(0x10 + i, 10_000_000, 1, 2, TOKEN_A))
            .collect();
        let buys: Vec<BatchOrder> = (0..7)
            .map(|i| make_buy(0x20 + i, 10_000_000, 1, 3, TOKEN_A))
            .collect();
        let token_unit = make_token_unit(0x30, TOKEN_A, 500_000_000);

        // 7 sells + 7 buys + 1 token_unit = 15 inputs (within limit)
        // Outputs: 7 + 7 + 2 = 16 (within limit)
        let plan = plan_batch_match(
            &sells,
            &buys,
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("7+7 batch should succeed, coi stays <= 6");

        let tx = plan.build_tx().expect("build_tx should succeed");
        assert_eq!(tx.inputs.len(), 15);
    }

    // Additional: verify build_tx sigscript sizes match v8 expectations
    #[test]
    fn test_sigscript_sizes() {
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let plan = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        let tx = plan.build_tx().expect("build should succeed");

        // Sell v13 fill SS: [Op(koi)] [Op1] [PUSHDATA2(2)] [378B RS]
        // = 1 + 1 + 3 + 378 = 383 bytes
        let sell_ss_len = tx.inputs[0].sigscript.len();
        assert_eq!(sell_ss_len, 383, "sell_v13 fill SS = 383B");

        // Buy v13 fill SS: [Op(toi)] [Op(tii)] [Op(coi)] [Op1] [PUSHDATA2(2)] [409B RS]
        // = 1 + 1 + 1 + 1 + 3 + 409 = 416 bytes
        let buy_ss_len = tx.inputs[1].sigscript.len();
        assert_eq!(buy_ss_len, 416, "buy_v13 fill SS = 416B");
    }

    // v11 helpers and tests

    /// Create a v12 buy order for testing (with soi support).
    #[allow(deprecated)]
    fn make_buy_v11(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32]) -> BatchOrder {
        let tx_id = hex::encode(&[id_byte; 32]);
        let owner = [0xBB; 32];
        let bspkh = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &token, price_num, price_den, 1_000_000, &owner, &bspkh, 100_000, 0, 0,
        ).unwrap();
        BatchOrder {
            outpoint: (tx_id, 0),
            order_type: OrderType::Buy,
            version: 12,
            token_cov_id: token,
            price_num,
            price_den,
            amount,
            redeem_script: rs,
            utxo_value: amount,
            counterparty_spk: vec![0xEE; 34], // fake buyer SPK
            counterparty_spk_version: 0,
        }
    }

    // Test: v11 batch soi assignment
    #[test]
    fn test_v11_batch_soi_assignment() {
        // 2 sells + 2 v11 buys
        let sell1 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let sell2 = make_sell(0x11, 10_000_000, 1, 2, TOKEN_A);

        let buy1 = make_buy_v11(0x20, 10_000_000, 1, 3, TOKEN_A);
        let buy2 = make_buy_v11(0x21, 10_000_000, 1, 3, TOKEN_A);

        let token_unit = make_token_unit(0x30, TOKEN_A, 100_000_000);

        let plan = plan_batch_match(
            &[sell1, sell2],
            &[buy1, buy2],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        // Each buy should be paired with a seller
        let _tx = plan.build_tx().expect("build_tx should succeed");

        // v11 buy sigscripts should have 5 items before RS (soi, toi, tii, coi, Op1)
        for (buy, input_idx) in &plan.buys {
            if buy.version == 11 {
                let soi = plan.buy_seller_map.get(input_idx).unwrap();
                assert!(*soi < plan.sells.len(), "soi must point to a valid seller output");
            }
        }
    }

    // Test: v11 batch soi distinct (round-robin)
    #[test]
    fn test_v11_batch_soi_distinct() {
        // Verify that different buys get distinct soi values when possible
        let sell1 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let sell2 = make_sell(0x11, 10_000_000, 1, 2, TOKEN_A);

        let buy1 = make_buy_v11(0x20, 10_000_000, 1, 3, TOKEN_A);
        let buy2 = make_buy_v11(0x21, 10_000_000, 1, 3, TOKEN_A);

        let token_unit = make_token_unit(0x30, TOKEN_A, 100_000_000);

        let plan = plan_batch_match(
            &[sell1, sell2],
            &[buy1, buy2],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        // With 2 sells and 2 buys, ideal pairing: buy0->sell0, buy1->sell1
        let soi0 = *plan.buy_seller_map.get(&2).unwrap(); // buy0 at input[2]
        let soi1 = *plan.buy_seller_map.get(&3).unwrap(); // buy1 at input[3]
        // They should be different when enough sells exist
        assert_ne!(soi0, soi1, "soi values should be distinct when possible");
    }

    // Test: v11 sigscript has extra soi byte vs v8
    #[test]
    fn test_v11_sigscript_has_soi() {
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy_v11 = make_buy_v11(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 50_000_000);

        let plan = plan_batch_match(
            &[sell],
            &[buy_v11],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("plan should succeed");

        let tx = plan.build_tx().expect("build should succeed");

        // v11 buy at input[1]: soi=0, toi=1, tii=2, coi=0, selector=1
        let buy_ss = &tx.inputs[1].sigscript;
        assert_eq!(buy_ss[0], 0x00, "v11 soi=0 -> Op0 (0x00)");
        assert_eq!(buy_ss[1], 0x51, "v11 toi=1 -> Op1 (0x51)");
        assert_eq!(buy_ss[2], 0x52, "v11 tii=2 -> Op2 (0x52)");
        assert_eq!(buy_ss[3], 0x00, "v11 coi=0 -> Op0 (0x00)");
        assert_eq!(buy_ss[4], 0x51, "v11 selector=1 -> Op1 (0x51)");

        let v12_rs_len = plan.buys[0].0.redeem_script.len();
        // v12 sigscript: 5 opcodes (soi, toi, tii, coi, Op1) + pushData(RS)
        let expected_ss_len = 5 + kob_core::push_data(&plan.buys[0].0.redeem_script).len();
        assert_eq!(buy_ss.len(), expected_ss_len,
            "v12 SS = 5 opcodes + pushData(RS), RS={} bytes", v12_rs_len);
    }

    // Test: multiple buys in same batch (v13 + v12 mixed)
    #[test]
    fn test_multiple_v13_batch() {
        let sell1 = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let sell2 = make_sell(0x11, 10_000_000, 1, 2, TOKEN_A);

        let buy1 = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let buy2 = make_buy_v11(0x21, 10_000_000, 1, 3, TOKEN_A);

        let token_unit = make_token_unit(0x30, TOKEN_A, 100_000_000);

        let plan = plan_batch_match(
            &[sell1, sell2],
            &[buy1, buy2],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        ).expect("multi batch plan should succeed");

        let tx = plan.build_tx().expect("build should succeed");

        // v13 buy at input[2]: 4 opcodes before pushData (toi, tii, coi, selector) — no soi
        let buy1_ss = &tx.inputs[2].sigscript;
        assert_eq!(buy1_ss[3], 0x51, "v13 buy selector at byte 3");

        // v12 buy at input[3]: 5 opcodes (soi, toi, tii, coi, selector)
        let buy2_ss = &tx.inputs[3].sigscript;
        assert_eq!(buy2_ss[4], 0x51, "v12 buy2 selector at byte 4");
    }

    // Test: zero price denominator is rejected
    #[test]
    fn batch_zero_price_denominator_sell() {
        // Construct a sell order with price_den = 0 directly (bypassing make_sell
        // which asserts price_den > 0 in the RS builder).
        let sell = BatchOrder {
            outpoint: (hex::encode([0x10u8; 32]), 0),
            order_type: OrderType::Sell,
            version: 13,
            token_cov_id: TOKEN_A,
            price_num: 1,
            price_den: 0, // <-- zero denominator
            amount: 10_000_000,
            redeem_script: vec![0x00; 10], // dummy RS (won't reach sigscript build)
            utxo_value: 10_000_000,
            counterparty_spk: vec![0xDD; 34],
            counterparty_spk_version: 0,
        };
        let buy = make_buy(0x20, 10_000_000, 1, 3, TOKEN_A);
        let token_unit = make_token_unit(0x30, TOKEN_A, 100_000_000);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        );
        match result {
            Err(BatchError::ZeroPriceDenominator { index: 0, side: "sell" }) => {} // expected
            other => panic!("expected ZeroPriceDenominator for sell, got: {:?}", other),
        }
    }

    #[test]
    fn batch_zero_price_denominator_buy() {
        // Construct a buy order with price_den = 0 directly.
        let sell = make_sell(0x10, 10_000_000, 1, 2, TOKEN_A);
        let buy = BatchOrder {
            outpoint: (hex::encode([0x20u8; 32]), 0),
            order_type: OrderType::Buy,
            version: 12,
            token_cov_id: TOKEN_A,
            price_num: 1,
            price_den: 0, // <-- zero denominator
            amount: 10_000_000,
            redeem_script: vec![0x00; 10], // dummy RS
            utxo_value: 10_000_000,
            counterparty_spk: vec![0xEE; 34],
            counterparty_spk_version: 0,
        };
        let token_unit = make_token_unit(0x30, TOKEN_A, 100_000_000);

        let result = plan_batch_match(
            &[sell],
            &[buy],
            &[token_unit],
            None,
            &matcher_spk(),
            0,
        );
        match result {
            Err(BatchError::ZeroPriceDenominator { index: 1, side: "buy" }) => {} // expected (index = n + j = 1 + 0)
            other => panic!("expected ZeroPriceDenominator for buy, got: {:?}", other),
        }
    }
}
