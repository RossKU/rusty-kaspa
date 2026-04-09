//! Perpetual position transaction construction (open, close, liquidate, settle).

use crate::matcher::perp_book::{PerpCrossingPair, PerpOrder};
use crate::matcher::perp_tracker::{LiquidatablePosition, PerpPosition};

#[cfg(test)]
use crate::matcher::perp_tracker::LiquidatedSide;

use kob_core::MIN_UTXO_VALUE;

/// A constructed (unsigned) transaction ready for submission.
///
/// This is a lightweight representation matching the Kaspa RPC submit format.
/// Fields are hex-encoded where noted for consistency with the spot executor.
#[derive(Debug, Clone)]
pub struct PerpTxBlueprint {
    /// Transaction inputs.
    pub inputs: Vec<PerpTxInput>,
    /// Transaction outputs.
    pub outputs: Vec<PerpTxOutput>,
    /// TX payload bytes (e.g., KOB:P:<RS> for position deploys).
    pub payload: Vec<u8>,
    /// Lock time (0 for normal TXs, >0 for CLTV-gated paths).
    pub lock_time: u64,
    /// sigOpCount for each input (needed for Kaspa RPC submission).
    pub sig_op_counts: Vec<u8>,
}

/// A transaction input referencing a previous UTXO.
#[derive(Debug, Clone)]
pub struct PerpTxInput {
    /// Previous TX ID (hex, 64 chars).
    pub prev_tx_id: String,
    /// Previous output index.
    pub prev_index: u32,
    /// SigScript bytes (built by the appropriate sigscript builder).
    pub sig_script: Vec<u8>,
    /// Sequence number (0 for Kaspa covenants).
    pub sequence: u64,
}

/// A transaction output.
#[derive(Debug, Clone)]
pub struct PerpTxOutput {
    /// Value in sompi.
    pub value: u64,
    /// ScriptPublicKey version (0 for P2PK and P2SH).
    pub script_version: u16,
    /// ScriptPublicKey bytes.
    pub script: Vec<u8>,
}

/// Error type for TX construction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerpTxError {
    /// Input value is too low to cover outputs + fee.
    InsufficientFunds { available: u64, required: u64 },
    /// An output would be below the minimum UTXO value.
    OutputBelowMinimum { output_idx: usize, value: u64 },
    /// Arithmetic overflow during computation.
    Overflow(String),
    /// Missing data required for TX construction (e.g., SPK bytes).
    MissingData(String),
}

impl std::fmt::Display for PerpTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientFunds { available, required } => {
                write!(f, "insufficient funds: have {available}, need {required}")
            }
            Self::OutputBelowMinimum { output_idx, value } => {
                write!(
                    f,
                    "output[{output_idx}] value {value} below minimum {MIN_UTXO_VALUE}"
                )
            }
            Self::Overflow(msg) => write!(f, "arithmetic overflow: {msg}"),
            Self::MissingData(msg) => write!(f, "missing data: {msg}"),
        }
    }
}

// Open Position TX

/// Parameters for building an open-position TX.
///
/// Created from a PerpCrossingPair after the matcher selects a Long+Short match.
#[derive(Debug, Clone)]
pub struct OpenPositionParams {
    /// Matched Long order.
    pub long_order: PerpOrder,
    /// Matched Short order.
    pub short_order: PerpOrder,
    /// Agreed entry price numerator.
    pub entry_price_num: u64,
    /// Agreed entry price denominator.
    pub entry_price_den: u64,
    /// Position size in sompi (minimum of both orders' effective sizes).
    pub size: u64,
    /// Long's margin share numerator (split_num / split_den = long fraction).
    pub split_num: u64,
    /// Total margin denominator.
    pub split_den: u64,
    /// Maintenance margin percentage numerator.
    pub maint_pct_num: u64,
    /// Maintenance margin percentage denominator.
    pub maint_pct_den: u64,
    /// Keeper fee for liquidation (sompi). Must be >= MIN_MARGIN_SOMPI.
    pub keeper_fee: u64,
    /// Close fee (fixed amount, sompi).
    pub close_fee: u64,
    /// Grace DAA score: liquidation CLTV threshold.
    pub grace_daa: u64,
    /// Maturity DAA score: maturity settle CLTV threshold.
    pub maturity_daa: u64,
    /// Emergency DAA score: emergency timeout CLTV threshold.
    pub emergency_daa: u64,
    /// Minimum price feed value.
    pub min_price: u64,
    /// Maximum price feed value.
    pub max_price: u64,
    /// Matcher's P2PK script for change/fee output.
    pub matcher_script: Vec<u8>,
    /// Blake2b-256 hash of the BuySell v13 sell redeemScript SPK (for atomic settlement).
    pub spot_sell_spkh: [u8; 32],
    /// Blake2b-256 hash of the BuySell v13 buy redeemScript SPK (for atomic settlement).
    pub spot_buy_spkh: [u8; 32],
}

impl OpenPositionParams {
    /// Convenience constructor from a PerpCrossingPair.
    pub fn from_crossing_pair(
        pair: &PerpCrossingPair,
        size: u64,
        split_num: u64,
        split_den: u64,
        maint_pct_num: u64,
        maint_pct_den: u64,
        keeper_fee: u64,
        close_fee: u64,
        grace_daa: u64,
        maturity_daa: u64,
        emergency_daa: u64,
        min_price: u64,
        max_price: u64,
        matcher_script: Vec<u8>,
        spot_sell_spkh: [u8; 32],
        spot_buy_spkh: [u8; 32],
    ) -> Self {
        Self {
            long_order: pair.long_order.clone(),
            short_order: pair.short_order.clone(),
            entry_price_num: pair.entry_price_num,
            entry_price_den: pair.entry_price_den,
            size,
            split_num,
            split_den,
            maint_pct_num,
            maint_pct_den,
            keeper_fee,
            close_fee,
            grace_daa,
            maturity_daa,
            emergency_daa,
            min_price,
            max_price,
            matcher_script,
            spot_sell_spkh,
            spot_buy_spkh,
        }
    }
}

/// Build an open-position TX that creates a perp_position covenant.
///
/// Inputs:
///   [0] Long order UTXO
///   [1] Short order UTXO
///
/// Outputs:
///   [0] perp_position covenant UTXO (value = margin_long + margin_short)
///   [1] Change to matcher (if surplus > MIN_UTXO_VALUE)
///
/// The position covenant RS is built using kob_core::perp functions.
/// The TX payload contains KOB:P:<RS> for L1 discovery.
///
/// Note: The actual sigscripts for the Long/Short order inputs depend on
/// the order contract type and are NOT filled in here. The caller must
/// build and attach sigscripts appropriate for the order contracts being spent.
/// This function sets sig_script to empty and returns the blueprint.
pub fn build_open_position_tx(
    params: &OpenPositionParams,
) -> Result<(PerpTxBlueprint, Vec<u8>), PerpTxError> {
    let margin_long = params.long_order.margin;
    let margin_short = params.short_order.margin;

    // Build the perp position redeemScript (v7: owner + spot_sell/buy + direction)
    // Long party is the position owner; direction=1 (long)
    let rs: Vec<u8> = kob_core::perp::build_perp_position_redeem_script(
        &params.long_order.owner_spk_hash,
        &params.spot_sell_spkh,
        &params.spot_buy_spkh,
        1, // direction: 1=long
        params.size,
        params.entry_price_num,
        params.entry_price_den,
        params.maint_pct_num,
        params.maint_pct_den,
        params.keeper_fee,
        params.close_fee,
        params.grace_daa,
        params.maturity_daa,
        params.emergency_daa,
        params.min_price,
        params.max_price,
    );

    // Compute P2SH script for the covenant output
    let p2sh_spk = kob_core::build_p2sh(&rs);

    // Position value = both margins combined
    let position_value = margin_long
        .checked_add(margin_short)
        .ok_or_else(|| PerpTxError::Overflow("margin_long + margin_short".to_string()))?;

    if position_value < MIN_UTXO_VALUE {
        return Err(PerpTxError::OutputBelowMinimum {
            output_idx: 0,
            value: position_value,
        });
    }

    // Total input value
    let total_input = params
        .long_order
        .value
        .checked_add(params.short_order.value)
        .ok_or_else(|| PerpTxError::Overflow("long_value + short_value".to_string()))?;

    // Required: position_value + miner fee (estimated from compute mass)
    let miner_fee = kob_core::mass::estimate_compute_mass(2, 2, 100);
    let required = position_value
        .checked_add(miner_fee)
        .ok_or_else(|| PerpTxError::Overflow("position_value + fee".to_string()))?;

    if total_input < required {
        return Err(PerpTxError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    let change = total_input - required;

    // Build payload for L1 discovery
    let payload = kob_core::perp::build_perp_order_payload(&rs);

    // Outputs
    let mut outputs = vec![PerpTxOutput {
        value: position_value,
        script_version: 0,
        script: p2sh_spk.script().to_vec(),
    }];

    // Change output to matcher (only if above minimum)
    if change >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: change,
            script_version: 0,
            script: params.matcher_script.clone(),
        });
    }

    let blueprint = PerpTxBlueprint {
        inputs: vec![
            PerpTxInput {
                prev_tx_id: params.long_order.tx_id.clone(),
                prev_index: params.long_order.index,
                sig_script: Vec::new(), // Caller fills in
                sequence: 0,
            },
            PerpTxInput {
                prev_tx_id: params.short_order.tx_id.clone(),
                prev_index: params.short_order.index,
                sig_script: Vec::new(), // Caller fills in
                sequence: 0,
            },
        ],
        outputs,
        payload,
        lock_time: 0,
        sig_op_counts: vec![0, 0], // Covenant inputs
    };

    Ok((blueprint, rs))
}

// Cooperative Close TX (Path 1)

/// Parameters for building a cooperative close TX.
///
/// Both parties must sign; the split is arbitrary (agreed off-chain).
#[derive(Debug, Clone)]
pub struct CooperativeCloseParams {
    /// The position being closed.
    pub position: PerpPosition,
    /// Long party's payout (sompi).
    pub long_payout: u64,
    /// Short party's payout (sompi).
    pub short_payout: u64,
    /// Long party's signature (64 bytes Schnorr).
    pub sig_long: [u8; 64],
    /// Long party's public key (32 bytes x-only).
    pub pk_long: [u8; 32],
    /// Short party's signature (64 bytes Schnorr).
    pub sig_short: [u8; 64],
    /// Short party's public key (32 bytes x-only).
    pub pk_short: [u8; 32],
    /// Long party's actual SPK bytes (for output construction).
    pub long_spk: Vec<u8>,
    /// Short party's actual SPK bytes (for output construction).
    pub short_spk: Vec<u8>,
}

/// Build a cooperative close TX (selector=1, 2-of-2 signatures).
///
/// Inputs:
///   [0] Position UTXO
///
/// Outputs:
///   [0] Long party payout
///   [1] Short party payout
///
/// Both parties must sign the TX. The split is arbitrary and does not
/// require a price input.
pub fn build_cooperative_close_tx(
    params: &CooperativeCloseParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    let position = &params.position;

    let rs = hex::decode(&position.redeem_script_hex).map_err(|e| {
        PerpTxError::MissingData(format!("invalid redeem_script_hex: {e}"))
    })?;

    // v7: Cooperative close (2-of-2) was removed. Path 1 = cancel (owner reclaim).
    // Use build_perp_cancel_sigscript for single-owner cancel instead.
    // For bilateral close, each party cancels their own position UTXO independently.
    let sigscript = kob_core::perp::build_perp_cancel_sigscript(
        &params.sig_long,
        &params.pk_long,
        &rs,
    );

    // Validate payouts
    let total_payout = params
        .long_payout
        .checked_add(params.short_payout)
        .ok_or_else(|| PerpTxError::Overflow("long_payout + short_payout".to_string()))?;

    // Cooperative close: 1 position input, 2-3 outputs
    let coop_miner_fee = kob_core::mass::estimate_compute_mass(1, 3, 0);
    let total_with_fee = total_payout
        .checked_add(coop_miner_fee)
        .ok_or_else(|| PerpTxError::Overflow("total_payout + fee".to_string()))?;

    let position_value = position.total_margin;
    if position_value < total_with_fee {
        return Err(PerpTxError::InsufficientFunds {
            available: position_value,
            required: total_with_fee,
        });
    }

    let mut outputs = Vec::new();

    if params.long_payout > 0 {
        if params.long_payout < MIN_UTXO_VALUE {
            return Err(PerpTxError::OutputBelowMinimum {
                output_idx: 0,
                value: params.long_payout,
            });
        }
        outputs.push(PerpTxOutput {
            value: params.long_payout,
            script_version: 0,
            script: params.long_spk.clone(),
        });
    }

    if params.short_payout > 0 {
        if params.short_payout < MIN_UTXO_VALUE {
            return Err(PerpTxError::OutputBelowMinimum {
                output_idx: outputs.len(),
                value: params.short_payout,
            });
        }
        outputs.push(PerpTxOutput {
            value: params.short_payout,
            script_version: 0,
            script: params.short_spk.clone(),
        });
    }

    Ok(PerpTxBlueprint {
        inputs: vec![PerpTxInput {
            prev_tx_id: position.tx_id.clone(),
            prev_index: position.index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![1], // v7 cancel: 1 sig (owner only)
    })
}

// Unilateral Close TX (Path 2)

/// Parameters for building a unilateral close TX.
#[derive(Debug, Clone)]
pub struct UnilateralCloseParams {
    /// The position being closed.
    pub position: PerpPosition,
    /// Closer's signature (64 bytes Schnorr).
    pub sig: [u8; 64],
    /// Closer's public key (32 bytes x-only).
    pub pk: [u8; 32],
    /// Price UTXO transaction ID (input[1]).
    pub price_tx_id: String,
    /// Price UTXO output index.
    pub price_index: u32,
    /// Price UTXO sigscript (for spending the price input as input[1]).
    pub price_sig_script: Vec<u8>,
    /// Long party's payout (computed from PnL off-chain).
    pub long_payout: u64,
    /// Short party's payout.
    pub short_payout: u64,
    /// Long party's SPK bytes.
    pub long_spk: Vec<u8>,
    /// Short party's SPK bytes.
    pub short_spk: Vec<u8>,
    /// Close fee recipient script (matcher/keeper). Required when close_fee > 0.
    pub close_fee_script: Vec<u8>,
}

/// Build a unilateral close TX (selector=2, price feed + 1 sig).
///
/// Inputs:
///   [0] Position UTXO
///   [1] Price UTXO (value = current price)
///
/// Outputs:
///   [0] Long party payout
///   [1] Short party payout
///   [2] Close fee (if > 0)
pub fn build_unilateral_close_tx(
    params: &UnilateralCloseParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    let position = &params.position;

    let rs = hex::decode(&position.redeem_script_hex).map_err(|e| {
        PerpTxError::MissingData(format!("invalid redeem_script_hex: {e}"))
    })?;

    let sigscript = kob_core::perp::build_perp_unilateral_close_sigscript(
        &params.sig,
        &params.pk,
        &rs,
    );

    let position_value = position.total_margin;
    let total_payout = params
        .long_payout
        .checked_add(params.short_payout)
        .ok_or_else(|| PerpTxError::Overflow("long_payout + short_payout".to_string()))?;

    // Forced/maturity close: 1 input, 2-3 outputs
    let close_miner_fee = kob_core::mass::estimate_compute_mass(1, 3, 0);
    let total_with_fee = total_payout
        .checked_add(close_miner_fee)
        .ok_or_else(|| PerpTxError::Overflow("total_payout + fee".to_string()))?;

    if position_value < total_with_fee {
        return Err(PerpTxError::InsufficientFunds {
            available: position_value,
            required: total_with_fee,
        });
    }

    let mut outputs = Vec::new();

    if params.long_payout >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: params.long_payout,
            script_version: 0,
            script: params.long_spk.clone(),
        });
    }

    if params.short_payout >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: params.short_payout,
            script_version: 0,
            script: params.short_spk.clone(),
        });
    }

    // output[2]: close fee (covenant checks output[2].value >= close_fee when close_fee > 0)
    let close_fee = position.close_fee;
    if close_fee > 0 {
        outputs.push(PerpTxOutput {
            value: close_fee,
            script_version: 0,
            script: params.close_fee_script.clone(),
        });
    }

    Ok(PerpTxBlueprint {
        inputs: vec![
            PerpTxInput {
                prev_tx_id: position.tx_id.clone(),
                prev_index: position.index,
                sig_script: sigscript,
                sequence: 0,
            },
            PerpTxInput {
                prev_tx_id: params.price_tx_id.clone(),
                prev_index: params.price_index,
                sig_script: params.price_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![1, 1], // position=1 sig, price=1 sig
    })
}

// Liquidation TX (Path 3)

/// Parameters for building a liquidation TX.
#[derive(Debug, Clone)]
pub struct LiquidationParams {
    /// The position being liquidated.
    pub position: PerpPosition,
    /// Price UTXO transaction ID (input[1]).
    pub price_tx_id: String,
    /// Price UTXO output index.
    pub price_index: u32,
    /// Price UTXO value (= current price).
    pub price_value: u64,
    /// Price UTXO sigscript (for spending the price input as input[1]).
    pub price_sig_script: Vec<u8>,
    /// Keeper's P2PK script (receives the keeper fee).
    pub keeper_script: Vec<u8>,
    /// Liquidation check result (contains which side is underwater).
    pub liquidation: LiquidatablePosition,
    /// Actual SPK bytes (hex-decoded) for the solvent party's output.
    pub solvent_spk: Vec<u8>,
}

/// Build a liquidation TX for a position where one side is below maintenance margin.
///
/// Inputs:
///   [0] Position UTXO (perp_position covenant)
///   [1] Price UTXO (value = current price)
///
/// Outputs:
///   [0] Solvent party payout (value = total_margin - keeper_fee - close_fee - fee)
///   [1] Keeper fee output
///
/// The position input sigscript uses selector=3 (liquidation path, permissionless).
/// TX lock_time must be >= grace_daa (enforced by CLTV in covenant).
pub fn build_liquidation_tx(
    params: &LiquidationParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    let position = &params.position;

    let rs = hex::decode(&position.redeem_script_hex).map_err(|e| {
        PerpTxError::MissingData(format!("invalid redeem_script_hex: {e}"))
    })?;

    // Build liquidation sigscript (permissionless, no sig needed)
    let liq_sigscript = kob_core::perp::build_perp_liquidation_sigscript(&rs);

    // Compute payout: total value minus keeper fee, close fee, and network fee
    let position_value = position.total_margin;
    let keeper_fee = position.keeper_fee;
    let close_fee = position.close_fee;

    let deductions = keeper_fee
        .checked_add(close_fee)
        .and_then(|v| v.checked_add(kob_core::mass::estimate_compute_mass(1, 3, 0)))
        .ok_or_else(|| PerpTxError::Overflow("keeper_fee + close_fee + fee".to_string()))?;

    let solvent_payout = position_value
        .checked_sub(deductions)
        .ok_or_else(|| PerpTxError::InsufficientFunds {
            available: position_value,
            required: deductions,
        })?;

    if solvent_payout < MIN_UTXO_VALUE {
        return Err(PerpTxError::OutputBelowMinimum {
            output_idx: 0,
            value: solvent_payout,
        });
    }
    if keeper_fee < MIN_UTXO_VALUE && keeper_fee > 0 {
        return Err(PerpTxError::OutputBelowMinimum {
            output_idx: 1,
            value: keeper_fee,
        });
    }

    let mut outputs = vec![
        // output[0]: solvent party
        PerpTxOutput {
            value: solvent_payout,
            script_version: 0,
            script: params.solvent_spk.clone(),
        },
    ];

    // output[1]: keeper fee (only if non-zero and above minimum)
    if keeper_fee >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: keeper_fee,
            script_version: 0,
            script: params.keeper_script.clone(),
        });
    }

    Ok(PerpTxBlueprint {
        inputs: vec![
            // input[0]: position UTXO
            PerpTxInput {
                prev_tx_id: position.tx_id.clone(),
                prev_index: position.index,
                sig_script: liq_sigscript,
                sequence: 0,
            },
            // input[1]: price UTXO
            PerpTxInput {
                prev_tx_id: params.price_tx_id.clone(),
                prev_index: params.price_index,
                sig_script: params.price_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: position.grace_daa, // CLTV: must be >= grace_daa
        sig_op_counts: vec![0, 1], // position=covenant(0, permissionless), price=1 sig
    })
}

// Maturity Settle TX (Path 4)

/// Parameters for building a maturity settle TX.
#[derive(Debug, Clone)]
pub struct MaturitySettleParams {
    /// The position being settled.
    pub position: PerpPosition,
    /// Price UTXO transaction ID (input[1]).
    pub price_tx_id: String,
    /// Price UTXO output index.
    pub price_index: u32,
    /// Price UTXO sigscript.
    pub price_sig_script: Vec<u8>,
    /// Long party's payout (computed from PnL off-chain).
    pub long_payout: u64,
    /// Short party's payout.
    pub short_payout: u64,
    /// Long party's SPK bytes.
    pub long_spk: Vec<u8>,
    /// Short party's SPK bytes.
    pub short_spk: Vec<u8>,
    /// Close fee recipient script (matcher/keeper). Required when close_fee > 0.
    pub close_fee_script: Vec<u8>,
}

/// Build a maturity settle TX (selector=4, CLTV >= maturity_daa + price feed).
///
/// Inputs:
///   [0] Position UTXO
///   [1] Price UTXO (value = current price)
///
/// Outputs:
///   [0] Long party payout
///   [1] Short party payout
pub fn build_maturity_settle_tx(
    params: &MaturitySettleParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    let position = &params.position;

    let rs = hex::decode(&position.redeem_script_hex).map_err(|e| {
        PerpTxError::MissingData(format!("invalid redeem_script_hex: {e}"))
    })?;

    let sigscript = kob_core::perp::build_perp_maturity_settle_sigscript(&rs);

    let position_value = position.total_margin;
    let total_payout = params
        .long_payout
        .checked_add(params.short_payout)
        .ok_or_else(|| PerpTxError::Overflow("long_payout + short_payout".to_string()))?;

    // Forced/maturity close: 1 input, 2-3 outputs
    let close_miner_fee = kob_core::mass::estimate_compute_mass(1, 3, 0);
    let total_with_fee = total_payout
        .checked_add(close_miner_fee)
        .ok_or_else(|| PerpTxError::Overflow("total_payout + fee".to_string()))?;

    if position_value < total_with_fee {
        return Err(PerpTxError::InsufficientFunds {
            available: position_value,
            required: total_with_fee,
        });
    }

    let mut outputs = Vec::new();

    if params.long_payout >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: params.long_payout,
            script_version: 0,
            script: params.long_spk.clone(),
        });
    }

    if params.short_payout >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: params.short_payout,
            script_version: 0,
            script: params.short_spk.clone(),
        });
    }

    // output[2]: close fee (covenant checks output[2].value >= close_fee when close_fee > 0)
    let close_fee = position.close_fee;
    if close_fee > 0 {
        outputs.push(PerpTxOutput {
            value: close_fee,
            script_version: 0,
            script: params.close_fee_script.clone(),
        });
    }

    Ok(PerpTxBlueprint {
        inputs: vec![
            PerpTxInput {
                prev_tx_id: position.tx_id.clone(),
                prev_index: position.index,
                sig_script: sigscript,
                sequence: 0,
            },
            PerpTxInput {
                prev_tx_id: params.price_tx_id.clone(),
                prev_index: params.price_index,
                sig_script: params.price_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: position.maturity_daa, // CLTV: must be >= maturity_daa
        sig_op_counts: vec![0, 1],
    })
}

// Add Margin TX (Path 5)

/// Parameters for building an add margin TX.
#[derive(Debug, Clone)]
pub struct AddMarginParams {
    /// The position to add margin to.
    pub position: PerpPosition,
    /// Owner's signature (64 bytes Schnorr).
    pub sig: [u8; 64],
    /// Owner's public key (32 bytes x-only).
    pub pk: [u8; 32],
    /// Additional margin amount (sompi).
    pub additional_margin: u64,
    /// Funding UTXO tx_id.
    pub funding_tx_id: String,
    /// Funding UTXO output index.
    pub funding_index: u32,
    /// Funding UTXO value.
    pub funding_value: u64,
    /// Funding UTXO sigscript.
    pub funding_sig_script: Vec<u8>,
}

/// Build an add margin TX (selector=5, self-continuation with value increase).
///
/// Inputs:
///   [0] Position UTXO (self-continuation)
///   [1] Funding UTXO (provides additional margin)
///
/// Outputs:
///   [0] New position UTXO (same P2SH, value = old + additional)
///   [1] Change from funding (if any)
pub fn build_add_margin_tx(
    params: &AddMarginParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    let position = &params.position;

    let rs = hex::decode(&position.redeem_script_hex).map_err(|e| {
        PerpTxError::MissingData(format!("invalid redeem_script_hex: {e}"))
    })?;

    let sigscript = kob_core::perp::build_perp_add_margin_sigscript(
        &params.sig,
        &params.pk,
        &rs,
    );

    let p2sh_spk = kob_core::build_p2sh(&rs);

    let new_position_value = position
        .total_margin
        .checked_add(params.additional_margin)
        .ok_or_else(|| PerpTxError::Overflow("position + additional_margin".to_string()))?;

    let total_input = position
        .total_margin
        .checked_add(params.funding_value)
        .ok_or_else(|| PerpTxError::Overflow("position + funding".to_string()))?;

    // Margin add: 2 inputs (position + funding), 1-2 outputs
    let margin_miner_fee = kob_core::mass::estimate_compute_mass(2, 2, 0);
    let required = new_position_value
        .checked_add(margin_miner_fee)
        .ok_or_else(|| PerpTxError::Overflow("new_value + fee".to_string()))?;

    if total_input < required {
        return Err(PerpTxError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    let change = total_input - required;

    let mut outputs = vec![PerpTxOutput {
        value: new_position_value,
        script_version: 0,
        script: p2sh_spk.script().to_vec(),
    }];

    if change >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: change,
            script_version: 0,
            script: Vec::new(), // Caller should set this to funding owner's SPK
        });
    }

    Ok(PerpTxBlueprint {
        inputs: vec![
            PerpTxInput {
                prev_tx_id: position.tx_id.clone(),
                prev_index: position.index,
                sig_script: sigscript,
                sequence: 0,
            },
            PerpTxInput {
                prev_tx_id: params.funding_tx_id.clone(),
                prev_index: params.funding_index,
                sig_script: params.funding_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![1, 1],
    })
}

// Withdraw Margin TX (Path 6)

/// Parameters for building a withdraw margin TX.
#[derive(Debug, Clone)]
pub struct WithdrawMarginParams {
    /// The position to withdraw margin from.
    pub position: PerpPosition,
    /// Owner's signature (64 bytes Schnorr).
    pub sig: [u8; 64],
    /// Owner's public key (32 bytes x-only).
    pub pk: [u8; 32],
    /// Amount to withdraw (sompi).
    pub withdraw_amount: u64,
    /// Withdrawal destination SPK.
    pub withdraw_spk: Vec<u8>,
    /// Price UTXO transaction ID (input[1], required for safety check).
    pub price_tx_id: String,
    /// Price UTXO output index.
    pub price_index: u32,
    /// Price UTXO sigscript.
    pub price_sig_script: Vec<u8>,
}

/// Build a withdraw margin TX (selector=6, self-continuation with value decrease).
///
/// Inputs:
///   [0] Position UTXO (self-continuation)
///   [1] Price UTXO (for safety check)
///
/// Outputs:
///   [0] New position UTXO (same P2SH, reduced value)
///   [1] Withdrawal output
pub fn build_withdraw_margin_tx(
    params: &WithdrawMarginParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    // v7: Withdraw margin path was removed. Use cancel (path 1) to reclaim
    // the entire position, then re-deploy with reduced margin if needed.
    let _ = params;
    Err(PerpTxError::MissingData(
        "withdraw margin is not available in v7 position covenant; \
         use cancel (path 1) to reclaim margin and re-deploy".to_string()
    ))
}

// Emergency Close TX (Path 7)

/// Parameters for building an emergency close TX.
#[derive(Debug, Clone)]
pub struct EmergencyCloseParams {
    /// The position being emergency-closed.
    pub position: PerpPosition,
    /// Long party's SPK bytes.
    pub long_spk: Vec<u8>,
    /// Short party's SPK bytes.
    pub short_spk: Vec<u8>,
}

/// Build an emergency close TX (selector=7, CLTV >= emergency_daa).
///
/// Inputs:
///   [0] Position UTXO
///
/// Outputs:
///   [0] Long party (proportional to split_num/split_den)
///   [1] Short party (remainder)
///
/// No price input needed; margins returned proportionally based on split ratio.
pub fn build_emergency_close_tx(
    params: &EmergencyCloseParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    let position = &params.position;

    let rs = hex::decode(&position.redeem_script_hex).map_err(|e| {
        PerpTxError::MissingData(format!("invalid redeem_script_hex: {e}"))
    })?;

    let sigscript = kob_core::perp::build_perp_emergency_sigscript(&rs);

    let position_value = position.total_margin;

    // Path 7 covenant computes ml = tm * sn / sd and ms = tm - ml from the FULL
    // input value (tm), then checks output[0] >= ml and output[1] >= ms.
    // Since ml + ms = tm, the outputs must sum to tm exactly, leaving zero for
    // network fee.  The emergency path has only one input (the position UTXO),
    // so the implicit network fee is 0.
    let long_payout = if position.split_den > 0 {
        ((position_value as u128) * (position.split_num as u128)
            / (position.split_den as u128)) as u64
    } else {
        position_value / 2
    };
    let short_payout = position_value.saturating_sub(long_payout);

    let mut outputs = Vec::new();

    if long_payout >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: long_payout,
            script_version: 0,
            script: params.long_spk.clone(),
        });
    }

    if short_payout >= MIN_UTXO_VALUE {
        outputs.push(PerpTxOutput {
            value: short_payout,
            script_version: 0,
            script: params.short_spk.clone(),
        });
    }

    Ok(PerpTxBlueprint {
        inputs: vec![PerpTxInput {
            prev_tx_id: position.tx_id.clone(),
            prev_index: position.index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs,
        payload: Vec::new(),
        lock_time: position.emergency_daa, // CLTV: must be >= emergency_daa
        sig_op_counts: vec![0], // Permissionless
    })
}

// Partial Close TX (Path 8)

/// Parameters for building a partial close TX.
///
/// Path 8 now requires 2-of-2 signatures (CRITICAL-2 fix).
#[derive(Debug, Clone)]
pub struct PartialCloseParams {
    /// The position being partially closed.
    pub position: PerpPosition,
    /// Long party's signature (64 bytes Schnorr).
    pub sig_long: [u8; 64],
    /// Long party's public key (32 bytes x-only).
    pub pk_long: [u8; 32],
    /// Short party's signature (64 bytes Schnorr).
    pub sig_short: [u8; 64],
    /// Short party's public key (32 bytes x-only).
    pub pk_short: [u8; 32],
    /// New (reduced) size for the remaining position.
    pub new_size: u64,
    /// Price UTXO transaction ID (input[1]).
    pub price_tx_id: String,
    /// Price UTXO output index.
    pub price_index: u32,
    /// Price UTXO sigscript.
    pub price_sig_script: Vec<u8>,
    /// Long party's payout from closed portion.
    pub long_payout: u64,
    /// Short party's payout from closed portion.
    pub short_payout: u64,
    /// Remaining position UTXO value.
    pub remaining_value: u64,
    /// Long party's SPK bytes.
    pub long_spk: Vec<u8>,
    /// Short party's SPK bytes.
    pub short_spk: Vec<u8>,
}

/// Build a partial close TX (selector=8, price input + proportional PnL).
///
/// Inputs:
///   [0] Position UTXO
///   [1] Price UTXO (value = current price)
///
/// Outputs:
///   [0] Remaining position UTXO (new RS with reduced size, same P2SH)
///   [1] Long payout from closed portion
///   [2] Short payout from closed portion
pub fn build_partial_close_tx(
    params: &PartialCloseParams,
) -> Result<PerpTxBlueprint, PerpTxError> {
    // v7: Partial close path was removed. In the v7 atomic settlement model,
    // position size is fixed at creation. To reduce exposure, cancel the
    // position (path 1) and open a new one with smaller size.
    let _ = params;
    Err(PerpTxError::MissingData(
        "partial close is not available in v7 position covenant; \
         cancel the position and re-open with reduced size".to_string()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::perp_book::PerpSide;

    fn make_long_order(margin: u64, value: u64) -> PerpOrder {
        PerpOrder {
            tx_id: "long_tx".to_string(),
            index: 0,
            side: PerpSide::Long,
            margin,
            leverage_num: 10,
            leverage_den: 1,
            price_num: 100,
            price_den: 1,
            owner_spk_hash: [1; 32],
            owner_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            value,
            maint_pct_num: 5,
            maint_pct_den: 100,
            keeper_fee: 3_000_000,
            discovered_daa: 1000,
            reduce_only: false,
        }
    }

    fn make_short_order(margin: u64, value: u64) -> PerpOrder {
        PerpOrder {
            tx_id: "short_tx".to_string(),
            index: 0,
            side: PerpSide::Short,
            margin,
            leverage_num: 10,
            leverage_den: 1,
            price_num: 100,
            price_den: 1,
            owner_spk_hash: [2; 32],
            owner_spk: None,
            redeem_script_hex: String::new(),
            p2sh_script_hex: String::new(),
            value,
            maint_pct_num: 5,
            maint_pct_den: 100,
            keeper_fee: 3_000_000,
            discovered_daa: 1000,
            reduce_only: false,
        }
    }

    /// Default v6 open position params for tests.
    fn default_open_params(
        long_margin: u64,
        long_value: u64,
        short_margin: u64,
        short_value: u64,
    ) -> OpenPositionParams {
        OpenPositionParams {
            long_order: make_long_order(long_margin, long_value),
            short_order: make_short_order(short_margin, short_value),
            entry_price_num: 100,
            entry_price_den: 1,
            size: 1_000_000,
            split_num: long_margin,
            split_den: long_margin + short_margin,
            maint_pct_num: 5,
            maint_pct_den: 100,
            keeper_fee: 3_000_000,
            close_fee: 10_000,
            grace_daa: 100,
            maturity_daa: 10_000,
            emergency_daa: 100_000,
            min_price: 1,
            max_price: 1_000,
            matcher_script: [vec![0x20], vec![0xbb; 32]].concat(),
            spot_sell_spkh: [3; 32],
            spot_buy_spkh: [4; 32],
        }
    }

    fn make_position() -> PerpPosition {
        // v7 position RS: owner, spot_sell, spot_buy, direction, size, entry_num, entry_den, ...
        let rs = kob_core::perp::build_perp_position_redeem_script(
            &[1; 32],  // owner_spk_hash
            &[3; 32],  // spot_sell_spkh
            &[4; 32],  // spot_buy_spkh
            1,         // direction (1=long)
            1_000_000, // size
            100,       // entry_num
            1,         // entry_den
            5,         // maint_pct_num
            100,       // maint_pct_den
            3_000_000, // keeper_fee
            10_000,    // close_fee
            100,       // grace_daa
            10_000,    // maturity_daa
            100_000,   // emergency_daa
            1,         // min_price
            1_000,     // max_price
        );
        PerpPosition {
            tx_id: "pos_tx".to_string(),
            index: 0,
            long_spk_hash: [1; 32],
            short_spk_hash: [2; 32],
            entry_num: 100,
            entry_den: 1,
            size: 1_000_000,
            split_num: 1,
            split_den: 2,
            maint_pct_num: 5,
            maint_pct_den: 100,
            keeper_fee: 3_000_000,
            close_fee: 10_000,
            grace_daa: 100,
            maturity_daa: 10_000,
            emergency_daa: 100_000,
            min_price: 1,
            max_price: 1_000,
            total_margin: 10_000_000,
            creation_daa: 1000,
            redeem_script_hex: hex::encode(&rs),
            long_spk: None,
            short_spk: None,
        }
    }

    // --- Open Position TX ---

    #[test]
    fn open_position_basic() {
        let params = default_open_params(5_000_000, 5_100_000, 5_000_000, 5_100_000);

        let (blueprint, rs) = build_open_position_tx(&params).unwrap();

        // Should have 2 inputs (long + short)
        assert_eq!(blueprint.inputs.len(), 2);
        assert_eq!(blueprint.inputs[0].prev_tx_id, "long_tx");
        assert_eq!(blueprint.inputs[1].prev_tx_id, "short_tx");

        // Output[0] = position covenant (10M sompi)
        assert_eq!(blueprint.outputs[0].value, 10_000_000);

        // RS should be non-empty
        assert!(!rs.is_empty());

        // Payload should start with KOB:P:
        assert_eq!(&blueprint.payload[..6], b"KOB:P:");
    }

    #[test]
    fn open_position_with_change() {
        let params = default_open_params(5_000_000, 10_000_000, 5_000_000, 10_000_000);

        let (blueprint, _) = build_open_position_tx(&params).unwrap();

        // Total input = 20M, position = 10M, fee = mass-based, change = remainder
        let miner_fee = kob_core::mass::estimate_compute_mass(2, 2, 100);
        assert_eq!(blueprint.outputs.len(), 2);
        assert_eq!(blueprint.outputs[0].value, 10_000_000);
        assert_eq!(blueprint.outputs[1].value, 20_000_000 - 10_000_000 - miner_fee);
    }

    #[test]
    fn open_position_insufficient_funds() {
        let params = default_open_params(5_000_000, 5_000_000, 5_000_000, 5_000_000);

        let result = build_open_position_tx(&params);
        assert!(matches!(result, Err(PerpTxError::InsufficientFunds { .. })));
    }

    #[test]
    fn open_position_no_change_when_small_surplus() {
        // Surplus = 100 (below MIN_UTXO_VALUE) -> no change output
        let params = default_open_params(5_000_000, 5_005_050, 5_000_000, 5_005_050);

        let (blueprint, _) = build_open_position_tx(&params).unwrap();
        // Total = 10_010_100, position = 10M, fee = 10k, surplus = 100 < 3M
        assert_eq!(blueprint.outputs.len(), 1);
    }

    #[test]
    fn open_position_sig_op_counts() {
        let params = default_open_params(5_000_000, 5_100_000, 5_000_000, 5_100_000);

        let (blueprint, _) = build_open_position_tx(&params).unwrap();
        assert_eq!(blueprint.sig_op_counts, vec![0, 0]);
        assert_eq!(blueprint.lock_time, 0);
    }

    #[test]
    fn open_position_payload_contains_rs() {
        let params = default_open_params(5_000_000, 5_100_000, 5_000_000, 5_100_000);

        let (blueprint, rs) = build_open_position_tx(&params).unwrap();

        // Parse the payload and verify RS matches
        let parsed_rs = kob_core::perp::parse_perp_payload(&blueprint.payload);
        assert!(parsed_rs.is_some());
        assert_eq!(parsed_rs.unwrap(), rs.as_slice());
    }

    // --- Cooperative Close TX ---

    #[test]
    fn cooperative_close_basic() {
        let position = make_position();

        let params = CooperativeCloseParams {
            position,
            long_payout: 6_000_000,
            short_payout: 3_990_000, // total=9_990_000 + 10k fee = 10M
            sig_long: [0xaa; 64],
            pk_long: [1; 32],
            sig_short: [0xbb; 64],
            pk_short: [2; 32],
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
        };

        let blueprint = build_cooperative_close_tx(&params).unwrap();

        // 1 input: position
        assert_eq!(blueprint.inputs.len(), 1);
        assert_eq!(blueprint.inputs[0].prev_tx_id, "pos_tx");

        // 2 outputs: long + short
        assert_eq!(blueprint.outputs.len(), 2);
        assert_eq!(blueprint.outputs[0].value, 6_000_000);
        assert_eq!(blueprint.outputs[1].value, 3_990_000);

        assert!(!blueprint.inputs[0].sig_script.is_empty());
        assert_eq!(blueprint.sig_op_counts, vec![1]); // v7 cancel: 1 sig (owner only)
    }

    #[test]
    fn cooperative_close_insufficient_funds() {
        let position = make_position();

        let params = CooperativeCloseParams {
            position,
            long_payout: 6_000_000,
            short_payout: 5_000_000, // total=11M > 10M position
            sig_long: [0xaa; 64],
            pk_long: [1; 32],
            sig_short: [0xbb; 64],
            pk_short: [2; 32],
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
        };

        let result = build_cooperative_close_tx(&params);
        assert!(matches!(result, Err(PerpTxError::InsufficientFunds { .. })));
    }

    #[test]
    fn cooperative_close_one_party_zero() {
        let position = make_position();

        let params = CooperativeCloseParams {
            position,
            long_payout: 9_990_000, // 10M - 10k fee
            short_payout: 0,
            sig_long: [0xaa; 64],
            pk_long: [1; 32],
            sig_short: [0xbb; 64],
            pk_short: [2; 32],
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
        };

        let blueprint = build_cooperative_close_tx(&params).unwrap();
        assert_eq!(blueprint.outputs.len(), 1);
        assert_eq!(blueprint.outputs[0].value, 9_990_000);
    }

    #[test]
    fn cooperative_close_below_minimum_payout() {
        let position = make_position();

        let params = CooperativeCloseParams {
            position,
            long_payout: 1000, // Below MIN_UTXO_VALUE
            short_payout: 9_989_000,
            sig_long: [0xaa; 64],
            pk_long: [1; 32],
            sig_short: [0xbb; 64],
            pk_short: [2; 32],
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
        };

        let result = build_cooperative_close_tx(&params);
        assert!(matches!(result, Err(PerpTxError::OutputBelowMinimum { .. })));
    }

    // --- Unilateral Close TX ---

    #[test]
    fn unilateral_close_basic() {
        let position = make_position();

        let params = UnilateralCloseParams {
            position,
            sig: [0xaa; 64],
            pk: [1; 32],
            price_tx_id: "price_tx".to_string(),
            price_index: 0,
            price_sig_script: vec![0x51],
            long_payout: 6_000_000,
            short_payout: 3_990_000,
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
            close_fee_script: [vec![0x20], vec![0xcc; 32]].concat(),
        };

        let blueprint = build_unilateral_close_tx(&params).unwrap();

        assert_eq!(blueprint.inputs.len(), 2);
        assert_eq!(blueprint.inputs[0].prev_tx_id, "pos_tx");
        assert_eq!(blueprint.inputs[1].prev_tx_id, "price_tx");
        // 3 outputs: long payout + short payout + close_fee (10_000)
        assert_eq!(blueprint.outputs.len(), 3);
        assert_eq!(blueprint.outputs[0].value, 6_000_000);
        assert_eq!(blueprint.outputs[1].value, 3_990_000);
        assert_eq!(blueprint.outputs[2].value, 10_000); // close_fee
        assert_eq!(blueprint.sig_op_counts, vec![1, 1]);
    }

    // --- Liquidation TX ---

    #[test]
    fn liquidation_long_underwater() {
        let position = make_position();
        let mtm = crate::matcher::perp_tracker::PositionTracker::mark_to_market(&position, 50)
            .unwrap();

        let params = LiquidationParams {
            position: position.clone(),
            price_tx_id: "price_tx".to_string(),
            price_index: 0,
            price_value: 50,
            price_sig_script: vec![0x51, 0x00], // placeholder
            keeper_script: [vec![0x20], vec![0xcc; 32]].concat(),
            liquidation: LiquidatablePosition {
                outpoint_key: "pos_tx:0".to_string(),
                side: LiquidatedSide::Long,
                mtm,
            },
            solvent_spk: [vec![0x20], vec![0xdd; 32]].concat(), // short's SPK
        };

        let blueprint = build_liquidation_tx(&params).unwrap();

        // 2 inputs: position + price
        assert_eq!(blueprint.inputs.len(), 2);
        assert_eq!(blueprint.inputs[0].prev_tx_id, "pos_tx");
        assert_eq!(blueprint.inputs[1].prev_tx_id, "price_tx");

        // Position sigscript should use selector=3 (Op3 = 0x53)
        assert_eq!(blueprint.inputs[0].sig_script[0], 0x53);

        // output[0] = solvent party, output[1] = keeper fee
        assert_eq!(blueprint.outputs.len(), 2);

        // Solvent payout = 10M - 3M keeper - 10k close_fee - miner_fee
        let miner_fee = kob_core::mass::estimate_compute_mass(1, 3, 0);
        assert_eq!(blueprint.outputs[0].value, 10_000_000 - 3_000_000 - 10_000 - miner_fee);
        // Keeper fee = 3M
        assert_eq!(blueprint.outputs[1].value, 3_000_000);

        assert_eq!(blueprint.sig_op_counts, vec![0, 1]);

        // lock_time must be >= grace_daa
        assert_eq!(blueprint.lock_time, 100);
    }

    #[test]
    fn liquidation_keeper_fee_below_minimum() {
        let mut position = make_position();
        position.keeper_fee = 1000; // Below MIN_UTXO_VALUE

        let mtm = crate::matcher::perp_tracker::PositionTracker::mark_to_market(&position, 50)
            .unwrap();

        let params = LiquidationParams {
            position: position.clone(),
            price_tx_id: "price_tx".to_string(),
            price_index: 0,
            price_value: 50,
            price_sig_script: vec![0x51],
            keeper_script: [vec![0x20], vec![0xcc; 32]].concat(),
            liquidation: LiquidatablePosition {
                outpoint_key: "pos_tx:0".to_string(),
                side: LiquidatedSide::Long,
                mtm,
            },
            solvent_spk: [vec![0x20], vec![0xdd; 32]].concat(),
        };

        let result = build_liquidation_tx(&params);
        assert!(matches!(result, Err(PerpTxError::OutputBelowMinimum { .. })));
    }

    #[test]
    fn liquidation_empty_payload() {
        let position = make_position();
        let mtm = crate::matcher::perp_tracker::PositionTracker::mark_to_market(&position, 50)
            .unwrap();

        let params = LiquidationParams {
            position,
            price_tx_id: "price_tx".to_string(),
            price_index: 0,
            price_value: 50,
            price_sig_script: vec![0x51],
            keeper_script: [vec![0x20], vec![0xcc; 32]].concat(),
            liquidation: LiquidatablePosition {
                outpoint_key: "pos_tx:0".to_string(),
                side: LiquidatedSide::Long,
                mtm,
            },
            solvent_spk: [vec![0x20], vec![0xdd; 32]].concat(),
        };

        let blueprint = build_liquidation_tx(&params).unwrap();
        assert!(blueprint.payload.is_empty());
    }

    // --- Maturity Settle TX ---

    #[test]
    fn maturity_settle_basic() {
        let position = make_position();

        let params = MaturitySettleParams {
            position: position.clone(),
            price_tx_id: "price_tx".to_string(),
            price_index: 0,
            price_sig_script: vec![0x51],
            long_payout: 6_000_000,
            short_payout: 3_990_000,
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
            close_fee_script: [vec![0x20], vec![0xcc; 32]].concat(),
        };

        let blueprint = build_maturity_settle_tx(&params).unwrap();

        assert_eq!(blueprint.inputs.len(), 2);
        // 3 outputs: long payout + short payout + close_fee (10_000)
        assert_eq!(blueprint.outputs.len(), 3);
        assert_eq!(blueprint.outputs[0].value, 6_000_000);
        assert_eq!(blueprint.outputs[1].value, 3_990_000);
        assert_eq!(blueprint.outputs[2].value, 10_000); // close_fee
        // lock_time must be >= maturity_daa
        assert_eq!(blueprint.lock_time, position.maturity_daa);
        // Sigscript should start with Op4 (0x54)
        assert_eq!(blueprint.inputs[0].sig_script[0], 0x54);
    }

    // --- Add Margin TX ---

    #[test]
    fn add_margin_basic() {
        let position = make_position();

        let params = AddMarginParams {
            position: position.clone(),
            sig: [0xaa; 64],
            pk: [1; 32],
            additional_margin: 5_000_000,
            funding_tx_id: "fund_tx".to_string(),
            funding_index: 0,
            funding_value: 6_000_000,
            funding_sig_script: vec![0x51],
        };

        let blueprint = build_add_margin_tx(&params).unwrap();

        assert_eq!(blueprint.inputs.len(), 2);
        assert_eq!(blueprint.inputs[0].prev_tx_id, "pos_tx");
        assert_eq!(blueprint.inputs[1].prev_tx_id, "fund_tx");

        // New position value = 10M + 5M = 15M
        assert_eq!(blueprint.outputs[0].value, 15_000_000);

        // Change = (10M + 6M) - 15M - 10k = 990_000 (below MIN_UTXO) ... wait
        // total_input = 10M + 6M = 16M
        // required = 15M + 10k = 15_010_000
        // change = 990_000 (below MIN_UTXO_VALUE = 3M)
        // So no change output
        assert_eq!(blueprint.outputs.len(), 1);
        assert_eq!(blueprint.sig_op_counts, vec![1, 1]);
    }

    // --- Withdraw Margin TX ---

    #[test]
    fn withdraw_margin_removed_in_v7() {
        let position = make_position();

        let params = WithdrawMarginParams {
            position: position.clone(),
            sig: [0xaa; 64],
            pk: [1; 32],
            withdraw_amount: 3_000_000,
            withdraw_spk: [vec![0x20], vec![0x11; 32]].concat(),
            price_tx_id: "price_tx".to_string(),
            price_index: 0,
            price_sig_script: vec![0x51],
        };

        // v7: withdraw margin path was removed
        let result = build_withdraw_margin_tx(&params);
        assert!(matches!(result, Err(PerpTxError::MissingData(_))));
        assert!(result.unwrap_err().to_string().contains("withdraw margin"));
    }

    // --- Emergency Close TX ---

    #[test]
    fn emergency_close_basic() {
        let position = make_position();

        let params = EmergencyCloseParams {
            position: position.clone(),
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
        };

        let blueprint = build_emergency_close_tx(&params).unwrap();

        assert_eq!(blueprint.inputs.len(), 1);
        // lock_time must be >= emergency_daa
        assert_eq!(blueprint.lock_time, 100_000);
        // Sigscript should start with Op7 (0x57)
        assert_eq!(blueprint.inputs[0].sig_script[0], 0x57);

        // Covenant uses full input value (tm=10M) for split, fee=0.
        // Long (split=1/2) = 5_000_000
        // Short = 10_000_000 - 5_000_000 = 5_000_000
        assert_eq!(blueprint.outputs.len(), 2);
        assert_eq!(blueprint.outputs[0].value, 5_000_000);
        assert_eq!(blueprint.outputs[1].value, 5_000_000);
        assert_eq!(blueprint.sig_op_counts, vec![0]);
    }

    // --- Partial Close TX ---

    #[test]
    fn partial_close_removed_in_v7() {
        let position = make_position();

        let params = PartialCloseParams {
            position: position.clone(),
            sig_long: [0xaa; 64],
            pk_long: [1; 32],
            sig_short: [0xbb; 64],
            pk_short: [2; 32],
            new_size: 500_000,
            price_tx_id: "price_tx".to_string(),
            price_index: 0,
            price_sig_script: vec![0x51],
            long_payout: 3_000_000,
            short_payout: 3_000_000,
            remaining_value: 3_980_000,
            long_spk: [vec![0x20], vec![0x11; 32]].concat(),
            short_spk: [vec![0x20], vec![0x22; 32]].concat(),
        };

        // v7: partial close path was removed
        let result = build_partial_close_tx(&params);
        assert!(matches!(result, Err(PerpTxError::MissingData(_))));
        assert!(result.unwrap_err().to_string().contains("partial close"));
    }

    // --- Error Display ---

    #[test]
    fn perp_tx_error_display() {
        let e = PerpTxError::InsufficientFunds {
            available: 100,
            required: 200,
        };
        assert!(e.to_string().contains("100"));
        assert!(e.to_string().contains("200"));

        let e = PerpTxError::OutputBelowMinimum {
            output_idx: 0,
            value: 500,
        };
        assert!(e.to_string().contains("500"));

        let e = PerpTxError::Overflow("test".to_string());
        assert!(e.to_string().contains("test"));

        let e = PerpTxError::MissingData("foo".to_string());
        assert!(e.to_string().contains("foo"));
    }
}
