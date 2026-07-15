//! P2P lending transaction construction (match, repay, liquidate, extend).

use crate::lending_book::{BorrowRequest, LendingMatch, LendingOffer};
use crate::lending_tracker::LoanPosition;

use kob_core::mass::estimate_compute_mass;
use kob_core::MIN_UTXO_VALUE;

/// A constructed (unsigned) lending transaction ready for submission.
///
/// Matches the Kaspa RPC submit format.
#[derive(Debug, Clone)]
pub struct LendingTxBlueprint {
    /// Transaction inputs.
    pub inputs: Vec<LendingTxInput>,
    /// Transaction outputs.
    pub outputs: Vec<LendingTxOutput>,
    /// TX payload bytes (e.g., KOB:L:<RS> for active loan deploys).
    pub payload: Vec<u8>,
    /// Lock time (0 for normal TXs, >0 for CLTV-gated paths).
    pub lock_time: u64,
    /// sigOpCount for each input.
    pub sig_op_counts: Vec<u8>,
}

/// A transaction input referencing a previous UTXO.
#[derive(Debug, Clone)]
pub struct LendingTxInput {
    /// Previous TX ID (hex, 64 chars).
    pub prev_tx_id: String,
    /// Previous output index.
    pub prev_index: u32,
    /// SigScript bytes.
    pub sig_script: Vec<u8>,
    /// Sequence number (0 for Kaspa covenants).
    pub sequence: u64,
}

/// A transaction output.
#[derive(Debug, Clone)]
pub struct LendingTxOutput {
    /// Value in sompi.
    pub value: u64,
    /// ScriptPublicKey version.
    pub script_version: u16,
    /// ScriptPublicKey bytes.
    pub script: Vec<u8>,
}

/// Error type for lending TX construction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LendingTxError {
    /// Input value is too low to cover outputs + fee.
    InsufficientFunds { available: u64, required: u64 },
    /// An output would be below the minimum UTXO value.
    OutputBelowMinimum { output_idx: usize, value: u64 },
    /// Arithmetic overflow during computation.
    Overflow(String),
    /// Missing data required for TX construction.
    MissingData(String),
    /// Interest calculation failed.
    InterestError(String),
}

impl std::fmt::Display for LendingTxError {
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
            Self::InterestError(msg) => write!(f, "interest error: {msg}"),
        }
    }
}

// Match TX — LoanOffer + BorrowRequest -> ActiveLoan

/// Parameters for building a lending match TX.
#[derive(Debug, Clone)]
pub struct LendingMatchParams {
    /// The matched lending offer.
    pub offer: LendingOffer,
    /// The matched borrow request.
    pub request: BorrowRequest,
    /// Agreed rate numerator.
    pub agreed_rate_num: u64,
    /// Agreed rate denominator.
    pub agreed_rate_den: u64,
    /// Actual principal amount (min of offer.value, request.desired_principal).
    pub principal: u64,
    /// Agreed loan duration in DAA units.
    pub duration_daa: u64,
    /// Current DAA score (used as start_daa for the active loan).
    pub current_daa: u64,
    /// Rate mode: 0=fixed, 1=variable.
    pub rate_mode: u64,
    /// Rate floor numerator (lender protection for variable).
    pub rate_floor_num: u64,
    /// Rate cap numerator (borrower protection for variable).
    pub rate_cap_num: u64,
    /// Grace period in DAA after expiry for default claim.
    pub grace_daa: u64,
    /// Liquidation threshold (e.g. 15000 = 150%). Set from lender's
    /// min_collateral_ratio in the loan offer.
    pub liq_threshold: u64,
    /// Collateral covenant ID (all-zero for KAS).
    pub collateral_cov_id: [u8; 32],
    /// Matcher's P2PK script for fee/change output.
    pub matcher_script: Vec<u8>,
    /// Borrower's actual SPK bytes (for principal delivery output).
    pub borrower_spk: Vec<u8>,
}

impl LendingMatchParams {
    /// Convenience constructor from a LendingMatch.
    pub fn from_match(
        m: &LendingMatch,
        current_daa: u64,
        rate_mode: u64,
        rate_floor_num: u64,
        rate_cap_num: u64,
        grace_daa: u64,
        liq_threshold: u64,
        matcher_script: Vec<u8>,
        borrower_spk: Vec<u8>,
    ) -> Self {
        Self {
            offer: m.offer.clone(),
            request: m.request.clone(),
            agreed_rate_num: m.agreed_rate_num,
            agreed_rate_den: m.agreed_rate_den,
            principal: m.principal,
            duration_daa: m.duration_daa,
            current_daa,
            rate_mode,
            rate_floor_num,
            rate_cap_num,
            grace_daa,
            liq_threshold,
            collateral_cov_id: m.offer.collateral_cov_id,
            matcher_script,
            borrower_spk,
        }
    }
}

/// Build a lending match TX that creates an active_loan_v3 covenant.
///
/// Inputs:
///   [0] Loan offer UTXO (principal)
///   [1] Borrow request UTXO (collateral)
///
/// Outputs:
///   [0] active_loan_v3 covenant UTXO (value = collateral)
///   [1] Borrower receives principal
///   [2] Matcher change (if surplus > MIN_UTXO_VALUE)
pub fn build_lending_match_tx(
    params: &LendingMatchParams,
) -> Result<(LendingTxBlueprint, Vec<u8>), LendingTxError> {
    let start_daa = params.current_daa;
    let expiry_daa = start_daa
        .checked_add(params.duration_daa)
        .ok_or_else(|| LendingTxError::Overflow("start_daa + duration_daa".to_string()))?;

    // Build active_loan_v3 redeemScript
    let rs = kob_core::lending::build_active_loan_redeem_script(
        &[0u8; 32], // no insurer (v3 insurance placeholder)
        &params.offer.owner_spk_hash,
        &params.request.owner_spk_hash,
        params.principal,
        params.agreed_rate_num,
        params.agreed_rate_den,
        start_daa,
        expiry_daa,
        &params.collateral_cov_id,
        params.rate_mode,
        params.rate_floor_num,
        params.rate_cap_num,
        params.grace_daa,
        params.liq_threshold,
    )
    .map_err(|e| LendingTxError::MissingData(format!("RS build error: {e}")))?;

    // Compute P2SH script for the covenant output
    let p2sh_spk = kob_core::build_p2sh(&rs);

    // Active loan UTXO holds the collateral
    let loan_value = params.request.value;
    if loan_value < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: loan_value,
        });
    }

    // Principal delivery to borrower
    if params.principal < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 1,
            value: params.principal,
        });
    }

    // Total input = offer.value + request.value
    let total_input = params
        .offer
        .value
        .checked_add(params.request.value)
        .ok_or_else(|| LendingTxError::Overflow("offer.value + request.value".to_string()))?;

    // Build payload for L1 discovery (needed for fee estimation)
    let payload = kob_core::lending::build_lending_payload(&rs);

    // Required = loan_value (collateral) + principal (to borrower) + fee
    // Estimate fee from compute mass: 2 inputs, up to 3 outputs (loan + principal + change).
    // This blueprint is submitted directly by the engine matcher with no
    // Phase-2 post-sign convergence, so the post-Toccata min-relay floor
    // must be applied here or the match TX underpays by 100x and the node
    // rejects it as non-standard.
    let est_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(2, 3, payload.len()));
    let required = loan_value
        .checked_add(params.principal)
        .and_then(|v| v.checked_add(est_fee))
        .ok_or_else(|| LendingTxError::Overflow("loan_value + principal + fee".to_string()))?;

    if total_input < required {
        return Err(LendingTxError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    let change = total_input - required;

    // Build sigscripts for the offer and request inputs
    let offer_sigscript =
        kob_core::lending::build_loan_offer_match_sigscript(&params.offer.redeem_script);
    let request_sigscript =
        kob_core::lending::build_borrow_request_match_sigscript(&params.request.redeem_script);

    // Outputs
    let mut outputs = vec![
        // [0] Active loan covenant (holds collateral)
        LendingTxOutput {
            value: loan_value,
            script_version: 0,
            script: p2sh_spk.script().to_vec(),
        },
        // [1] Borrower receives principal
        LendingTxOutput {
            value: params.principal,
            script_version: 0,
            script: params.borrower_spk.clone(),
        },
    ];

    // [2] Matcher change (if above minimum)
    if change >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: change,
            script_version: 0,
            script: params.matcher_script.clone(),
        });
    }

    let blueprint = LendingTxBlueprint {
        inputs: vec![
            LendingTxInput {
                prev_tx_id: params.offer.outpoint.split(':').next().unwrap_or("").to_string(),
                prev_index: params
                    .offer
                    .outpoint
                    .split(':')
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                sig_script: offer_sigscript,
                sequence: 0,
            },
            LendingTxInput {
                prev_tx_id: params.request.outpoint.split(':').next().unwrap_or("").to_string(),
                prev_index: params
                    .request
                    .outpoint
                    .split(':')
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                sig_script: request_sigscript,
                sequence: 0,
            },
        ],
        outputs,
        payload,
        lock_time: 0,
        sig_op_counts: vec![0, 0], // Permissionless match
    };

    Ok((blueprint, rs))
}

// Helper: parse outpoint

fn parse_outpoint(outpoint: &str) -> (String, u32) {
    let parts: Vec<&str> = outpoint.split(':').collect();
    let tx_id = parts.first().map(|s| s.to_string()).unwrap_or_default();
    let index = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (tx_id, index)
}

// Liquidation TX (sel=1, permissionless)

/// Parameters for building a liquidation TX.
#[derive(Debug, Clone)]
pub struct LoanLiquidationParams {
    /// The active loan being liquidated.
    pub loan: LoanPosition,
    /// Lender's actual SPK bytes (for debt repayment output).
    pub lender_spk: Vec<u8>,
    /// Borrower's actual SPK bytes (for remainder output).
    pub borrower_spk: Vec<u8>,
    /// Liquidator's P2PK script (for bonus output).
    pub liquidator_script: Vec<u8>,
    /// Amount to pay the lender (at least principal).
    pub lender_payout: u64,
    /// Amount returned to borrower (remainder).
    pub borrower_payout: u64,
    /// Liquidator bonus.
    pub liquidator_payout: u64,
}

/// Build a liquidation TX (selector=1, permissionless).
///
/// Inputs:
///   [0] Active loan UTXO
///
/// Outputs:
///   [0] Lender receives debt repayment
///   [1] Borrower receives remainder (if any)
///   [2] Liquidator receives bonus
pub fn build_liquidation_tx(
    params: &LoanLiquidationParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    // Build output indices for sigscript
    // outputs: [0]=lender, [1]=borrower (if >= MIN), [next]=liquidator
    //
    // The covenant's sel=1 only checks loi (lender output). boi and liqi are
    // passed in sigscript but not validated by bytecode. However, indices must
    // not collide to avoid ambiguity in TX construction and future covenant
    // upgrades.
    let lender_output_idx: u8 = 0;
    let mut next_idx: u8 = 1;
    let borrower_output_idx: u8 = if params.borrower_payout >= MIN_UTXO_VALUE {
        let idx = next_idx;
        next_idx += 1;
        idx
    } else {
        // Borrower gets nothing; use a dummy index that won't collide with
        // actual outputs. We use next_idx and still advance it.
        let idx = next_idx;
        next_idx += 1;
        idx
    };
    let liquidator_output_idx: u8 = next_idx;

    // Price input is not required for v3 liquidation (value-as-price via co-input
    // is used in full liquidation). For simplicity, we use price_input_idx=0
    // meaning no separate price input (the loan UTXO itself is input[0]).
    // In practice, the keeper provides a price UTXO as input[1].
    let price_input_idx: u8 = 0; // Will be overridden by caller if needed

    let sigscript = kob_core::lending::build_active_loan_liquidate_sigscript(
        price_input_idx,
        lender_output_idx,
        borrower_output_idx,
        liquidator_output_idx,
        &rs,
    );

    let loan_value = loan.collateral;
    let total_payout = params
        .lender_payout
        .checked_add(params.borrower_payout)
        .and_then(|v| v.checked_add(params.liquidator_payout))
        .ok_or_else(|| LendingTxError::Overflow("total payout".to_string()))?;

    // Estimate fee from compute mass: 1 input, up to 3 outputs, no payload.
    let est_fee = estimate_compute_mass(1, 3, 0);
    let total_with_fee = total_payout
        .checked_add(est_fee)
        .ok_or_else(|| LendingTxError::Overflow("total + fee".to_string()))?;

    if loan_value < total_with_fee {
        return Err(LendingTxError::InsufficientFunds {
            available: loan_value,
            required: total_with_fee,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    let mut outputs = Vec::new();

    if params.lender_payout >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: params.lender_payout,
            script_version: 0,
            script: params.lender_spk.clone(),
        });
    }

    if params.borrower_payout >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: params.borrower_payout,
            script_version: 0,
            script: params.borrower_spk.clone(),
        });
    }

    if params.liquidator_payout >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: params.liquidator_payout,
            script_version: 0,
            script: params.liquidator_script.clone(),
        });
    }

    Ok(LendingTxBlueprint {
        inputs: vec![LendingTxInput {
            prev_tx_id: tx_id,
            prev_index: index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![0], // Permissionless
    })
}

// Default Claim TX (sel=2, lender sig + CLTV)

/// Parameters for building a default claim TX.
#[derive(Debug, Clone)]
pub struct DefaultClaimParams {
    /// The defaulted loan.
    pub loan: LoanPosition,
    /// Lender's signature (64 bytes Schnorr).
    pub lender_sig: [u8; 64],
    /// Lender's public key (32 bytes x-only).
    pub lender_pk: [u8; 32],
    /// Lender's actual SPK bytes.
    pub lender_spk: Vec<u8>,
}

/// Build a default claim TX (selector=2, CLTV after expiry + grace).
///
/// Inputs:
///   [0] Active loan UTXO
///
/// Outputs:
///   [0] Lender receives all collateral (minus fee)
pub fn build_default_claim_tx(
    params: &DefaultClaimParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    let sigscript = kob_core::lending::build_active_loan_default_sigscript(
        &params.lender_sig,
        &params.lender_pk,
        &rs,
    );

    let loan_value = loan.collateral;
    // Estimate fee from compute mass: 1 input (1 sig), 1 output, no payload.
    let est_fee = estimate_compute_mass(1, 1, 0);
    let payout = loan_value.saturating_sub(est_fee);
    if payout < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: payout,
        });
    }

    // Lock time = expiry_daa + grace_daa (CLTV threshold)
    let lock_time = loan
        .expiry_daa
        .checked_add(loan.grace_daa)
        .ok_or_else(|| LendingTxError::Overflow("expiry + grace".to_string()))?;

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    Ok(LendingTxBlueprint {
        inputs: vec![LendingTxInput {
            prev_tx_id: tx_id,
            prev_index: index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs: vec![LendingTxOutput {
            value: payout,
            script_version: 0,
            script: params.lender_spk.clone(),
        }],
        payload: Vec::new(),
        lock_time,
        sig_op_counts: vec![1], // 1 sig
    })
}

// Repay TX (sel=3, borrower sig)

/// Parameters for building a full repayment TX.
#[derive(Debug, Clone)]
pub struct RepayParams {
    /// The active loan being repaid.
    pub loan: LoanPosition,
    /// Borrower's signature (64 bytes Schnorr).
    pub borrower_sig: [u8; 64],
    /// Borrower's public key (32 bytes x-only).
    pub borrower_pk: [u8; 32],
    /// Lender's actual SPK bytes.
    pub lender_spk: Vec<u8>,
    /// Borrower's actual SPK bytes (for collateral return).
    pub borrower_spk: Vec<u8>,
    /// Additional KAS input TX ID (for interest payment if collateral alone
    /// doesn't cover it). Empty if not needed.
    pub funding_tx_id: Option<String>,
    /// Additional KAS input index.
    pub funding_index: Option<u32>,
    /// Additional KAS input value.
    pub funding_value: Option<u64>,
    /// Additional KAS input sigscript.
    pub funding_sig_script: Option<Vec<u8>>,
    /// Current DAA score (for interest calculation).
    pub current_daa: u64,
}

/// Build a full repayment TX (selector=3, borrower sig).
///
/// Inputs:
///   [0] Active loan UTXO (collateral)
///   [1] Optional: funding UTXO (borrower's KAS for repayment)
///
/// Outputs:
///   [0] Lender receives principal + interest
///   [1] Borrower receives remaining collateral
pub fn build_repay_tx(
    params: &RepayParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    // Calculate interest
    let elapsed_daa = params.current_daa.saturating_sub(loan.start_daa);
    let interest = kob_core::lending::calculate_interest(
        loan.principal,
        loan.rate_num,
        loan.rate_den,
        elapsed_daa,
    )
    .ok_or_else(|| LendingTxError::InterestError("interest calculation overflow".to_string()))?;

    let lender_amount = loan
        .principal
        .checked_add(interest)
        .ok_or_else(|| LendingTxError::Overflow("principal + interest".to_string()))?;

    // Lender output index = 0 (always first output in repay TX)
    let lender_output_idx: u8 = 0;

    let sigscript = kob_core::lending::build_active_loan_repay_sigscript(
        &params.borrower_sig,
        &params.borrower_pk,
        lender_output_idx,
        &rs,
    );

    // Total input value
    let funding_value = params.funding_value.unwrap_or(0);
    let total_input = loan
        .collateral
        .checked_add(funding_value)
        .ok_or_else(|| LendingTxError::Overflow("collateral + funding".to_string()))?;

    // Required: lender_amount + fee (borrower gets remainder)
    // Estimate fee from compute mass: 1-2 inputs, up to 2 outputs, no payload.
    let num_inputs = if params.funding_tx_id.is_some() { 2 } else { 1 };
    let est_fee = estimate_compute_mass(num_inputs, 2, 0);
    let required = lender_amount
        .checked_add(est_fee)
        .ok_or_else(|| LendingTxError::Overflow("lender_amount + fee".to_string()))?;

    if total_input < required {
        return Err(LendingTxError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    let borrower_return = total_input - required;

    if lender_amount < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: lender_amount,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    let mut inputs = vec![LendingTxInput {
        prev_tx_id: tx_id,
        prev_index: index,
        sig_script: sigscript,
        sequence: 0,
    }];

    let mut sig_op_counts = vec![1u8]; // borrower sig

    // Optional funding input
    if let (Some(ftx), Some(fi), Some(fss)) = (
        &params.funding_tx_id,
        params.funding_index,
        &params.funding_sig_script,
    ) {
        inputs.push(LendingTxInput {
            prev_tx_id: ftx.clone(),
            prev_index: fi,
            sig_script: fss.clone(),
            sequence: 0,
        });
        sig_op_counts.push(1);
    }

    let mut outputs = vec![LendingTxOutput {
        value: lender_amount,
        script_version: 0,
        script: params.lender_spk.clone(),
    }];

    if borrower_return >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: borrower_return,
            script_version: 0,
            script: params.borrower_spk.clone(),
        });
    }

    Ok(LendingTxBlueprint {
        inputs,
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts,
    })
}

// Partial Repay TX (sel=4, borrower sig, continuation)

/// Parameters for building a partial repayment TX.
#[derive(Debug, Clone)]
pub struct PartialRepayParams {
    /// The active loan.
    pub loan: LoanPosition,
    /// Borrower's signature (64 bytes Schnorr).
    pub borrower_sig: [u8; 64],
    /// Borrower's public key (32 bytes x-only).
    pub borrower_pk: [u8; 32],
    /// Lender's actual SPK bytes.
    pub lender_spk: Vec<u8>,
    /// Repayment amount (sompi) — portion of principal + accrued interest.
    pub repay_amount: u64,
}

/// Build a partial repayment TX (selector=4, borrower sig, continuation).
///
/// Inputs:
///   [0] Active loan UTXO
///
/// Outputs:
///   [0] Continuation active loan UTXO (same P2SH, reduced value)
///   [1] Lender receives repay_amount
pub fn build_partial_repay_tx(
    params: &PartialRepayParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    if params.repay_amount == 0 {
        return Err(LendingTxError::MissingData("repay_amount must be > 0".to_string()));
    }

    // Build new RS with reduced principal for D&R continuation
    let new_principal = loan.principal.checked_sub(params.repay_amount)
        .ok_or_else(|| LendingTxError::Overflow("principal - repay_amount underflow".to_string()))?;
    if new_principal == 0 {
        return Err(LendingTxError::MissingData("partial repay cannot reduce principal to zero".to_string()));
    }
    let new_rs = kob_core::lending::build_active_loan_redeem_script(
        &[0u8; 32], // no insurer
        &loan.lender_spk_hash,
        &loan.borrower_spk_hash,
        new_principal,
        loan.rate_num,
        loan.rate_den,
        loan.start_daa,
        loan.expiry_daa,
        &loan.collateral_cov_id,
        loan.rate_mode,
        loan.rate_floor,
        loan.rate_cap,
        loan.grace_daa,
        loan.liq_threshold,
    ).map_err(|e| LendingTxError::MissingData(format!("new RS build: {e}")))?;

    // P2SH from NEW rs — the covenant's D&R Step 5 verifies output[0].spk == P2SH(new_rs)
    let p2sh_spk = kob_core::build_p2sh(&new_rs);

    // Lender output index = 1 (continuation is output[0])
    let lender_output_idx: u8 = 1;

    let sigscript = kob_core::lending::build_active_loan_partial_repay_sigscript(
        &params.borrower_sig,
        &params.borrower_pk,
        lender_output_idx,
        params.repay_amount,
        &rs,
        &rs,
        &new_rs,
    );

    let loan_value = loan.collateral;
    // Estimate fee from compute mass: 1 input, 2 outputs (continuation + lender), no payload.
    let est_fee = estimate_compute_mass(1, 2, 0);
    let required = params
        .repay_amount
        .checked_add(est_fee)
        .ok_or_else(|| LendingTxError::Overflow("repay + fee".to_string()))?;

    if loan_value < required {
        return Err(LendingTxError::InsufficientFunds {
            available: loan_value,
            required,
        });
    }

    let continuation_value = loan_value - required;
    if continuation_value < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: continuation_value,
        });
    }
    if params.repay_amount < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 1,
            value: params.repay_amount,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    Ok(LendingTxBlueprint {
        inputs: vec![LendingTxInput {
            prev_tx_id: tx_id,
            prev_index: index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs: vec![
            LendingTxOutput {
                value: continuation_value,
                script_version: 0,
                script: p2sh_spk.script().to_vec(),
            },
            LendingTxOutput {
                value: params.repay_amount,
                script_version: 0,
                script: params.lender_spk.clone(),
            },
        ],
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![1],
    })
}

// Top-up Collateral TX (sel=5, borrower sig, self-continuation)

/// Parameters for building a top-up collateral TX.
#[derive(Debug, Clone)]
pub struct TopUpParams {
    /// The active loan.
    pub loan: LoanPosition,
    /// Borrower's signature (64 bytes Schnorr).
    pub borrower_sig: [u8; 64],
    /// Borrower's public key (32 bytes x-only).
    pub borrower_pk: [u8; 32],
    /// Additional collateral to add (sompi).
    pub additional_collateral: u64,
    /// Funding UTXO TX ID (borrower's additional KAS).
    pub funding_tx_id: String,
    /// Funding UTXO output index.
    pub funding_index: u32,
    /// Funding UTXO value.
    pub funding_value: u64,
    /// Funding UTXO sigscript.
    pub funding_sig_script: Vec<u8>,
}

/// Build a top-up collateral TX (selector=5, borrower sig).
///
/// Inputs:
///   [0] Active loan UTXO
///   [1] Funding UTXO (additional collateral)
///
/// Outputs:
///   [0] Continuation active loan UTXO (same P2SH, increased value)
pub fn build_topup_tx(
    params: &TopUpParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    let p2sh_spk = kob_core::build_p2sh(&rs);

    // Continuation output index = 0
    let continuation_output_idx: u8 = 0;

    let sigscript = kob_core::lending::build_active_loan_topup_sigscript(
        &params.borrower_sig,
        &params.borrower_pk,
        continuation_output_idx,
        &rs,
    );

    let total_input = loan
        .collateral
        .checked_add(params.funding_value)
        .ok_or_else(|| LendingTxError::Overflow("collateral + funding".to_string()))?;

    let new_value = loan
        .collateral
        .checked_add(params.additional_collateral)
        .ok_or_else(|| LendingTxError::Overflow("collateral + additional".to_string()))?;

    // Estimate fee from compute mass: 2 inputs, 1 output (continuation), no payload.
    let est_fee = estimate_compute_mass(2, 1, 0);
    let required = new_value
        .checked_add(est_fee)
        .ok_or_else(|| LendingTxError::Overflow("new_value + fee".to_string()))?;

    if total_input < required {
        return Err(LendingTxError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    if new_value < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: new_value,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    Ok(LendingTxBlueprint {
        inputs: vec![
            LendingTxInput {
                prev_tx_id: tx_id,
                prev_index: index,
                sig_script: sigscript,
                sequence: 0,
            },
            LendingTxInput {
                prev_tx_id: params.funding_tx_id.clone(),
                prev_index: params.funding_index,
                sig_script: params.funding_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs: vec![LendingTxOutput {
            value: new_value,
            script_version: 0,
            script: p2sh_spk.script().to_vec(),
        }],
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![1, 1],
    })
}

// Extend TX (sel=6, 2-of-2 sigs)

/// Parameters for building an extend TX.
#[derive(Debug, Clone)]
pub struct ExtendParams {
    /// The active loan.
    pub loan: LoanPosition,
    /// Lender's signature (64 bytes Schnorr).
    pub lender_sig: [u8; 64],
    /// Lender's public key (32 bytes x-only).
    pub lender_pk: [u8; 32],
    /// Borrower's signature (64 bytes Schnorr).
    pub borrower_sig: [u8; 64],
    /// Borrower's public key (32 bytes x-only).
    pub borrower_pk: [u8; 32],
    /// Lender's actual SPK bytes.
    pub lender_spk: Vec<u8>,
    /// New expiry DAA score.
    pub new_expiry_daa: u64,
    /// Interest payment amount to lender (accrued so far).
    pub interest_payment: u64,
}

/// Build an extend TX (selector=6, both sigs, settle interest, new expiry).
///
/// Inputs:
///   [0] Active loan UTXO
///
/// Outputs:
///   [0] Continuation active loan UTXO (same P2SH, reduced by interest)
///   [1] Lender receives interest payment
///
/// Note: The covenant enforces `output[0].spk == input.spk` (self-continuation),
/// so the RS is NOT rebuilt with new state. The on-chain RS (including start_daa,
/// expiry_daa) stays identical. State changes (new expiry, reset start) are
/// tracked off-chain by the engine's LoanTracker.
pub fn build_extend_tx(
    params: &ExtendParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    // Build new RS with updated start_daa and expiry_daa for D&R continuation.
    // The covenant's D&R prefix [0..94) locks everything up to start_daa's data,
    // and suffix [111..end) locks everything from collateral_cov_id onward.
    // The mutable zone [94..111) covers: start_daa data (8B) + push_byte (1B) + expiry_daa data (8B).
    // We reset start_daa to old expiry (interest settled up to that point) and set new expiry.
    let new_start_daa = loan.expiry_daa; // Reset start to old expiry
    let new_rs = kob_core::lending::build_active_loan_redeem_script(
        &[0u8; 32], // no insurer
        &loan.lender_spk_hash,
        &loan.borrower_spk_hash,
        loan.principal,
        loan.rate_num,
        loan.rate_den,
        new_start_daa,
        params.new_expiry_daa,
        &loan.collateral_cov_id,
        loan.rate_mode,
        loan.rate_floor,
        loan.rate_cap,
        loan.grace_daa,
        loan.liq_threshold,
    ).map_err(|e| LendingTxError::MissingData(format!("new RS build: {e}")))?;

    // P2SH from NEW rs — the covenant's D&R Step 5 verifies output[0].spk == P2SH(new_rs)
    let p2sh_spk = kob_core::build_p2sh(&new_rs);

    // Lender output index = 1 (continuation is output[0])
    let lender_output_idx: u8 = 1;

    let sigscript = kob_core::lending::build_active_loan_extend_sigscript(
        &params.lender_sig,
        &params.lender_pk,
        &params.borrower_sig,
        &params.borrower_pk,
        lender_output_idx,
        params.new_expiry_daa,
        &rs,
        &rs,
        &new_rs,
    );

    let loan_value = loan.collateral;
    // Estimate fee from compute mass: 1 input (2 sigs), up to 2 outputs, no payload.
    let est_fee = estimate_compute_mass(1, 2, 0);
    let required = params
        .interest_payment
        .checked_add(est_fee)
        .ok_or_else(|| LendingTxError::Overflow("interest + fee".to_string()))?;

    if loan_value < required {
        return Err(LendingTxError::InsufficientFunds {
            available: loan_value,
            required,
        });
    }

    let continuation_value = loan_value - required;
    if continuation_value < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: continuation_value,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    let mut outputs = vec![LendingTxOutput {
        value: continuation_value,
        script_version: 0,
        script: p2sh_spk.script().to_vec(),
    }];

    if params.interest_payment >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: params.interest_payment,
            script_version: 0,
            script: params.lender_spk.clone(),
        });
    }

    Ok(LendingTxBlueprint {
        inputs: vec![LendingTxInput {
            prev_tx_id: tx_id,
            prev_index: index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![2], // 2-of-2
    })
}

// Rebalance TX (sel=7, permissionless, variable rate only)

/// Parameters for building a rebalance TX.
#[derive(Debug, Clone)]
pub struct RebalanceParams {
    /// The active loan (must be variable rate).
    pub loan: LoanPosition,
    /// Rate input UTXO TX ID (value encodes new rate).
    pub rate_tx_id: String,
    /// Rate input UTXO index.
    pub rate_index: u32,
    /// Rate input UTXO sigscript.
    pub rate_sig_script: Vec<u8>,
    /// Lender's actual SPK bytes.
    pub lender_spk: Vec<u8>,
    /// Signature (with sighash type suffix) for the rebalance input.
    pub sig_with_type: Vec<u8>,
    /// Public key corresponding to the signature.
    pub pubkey: Vec<u8>,
    /// Interest payment to lender (accrued so far).
    pub interest_payment: u64,
    /// New rate numerator for the rebalanced loan (D&R state update).
    pub new_rate_num: u64,
    /// New start DAA (reset after interest settlement).
    pub new_start_daa: u64,
}

/// Build a rebalance TX (selector=7, permissionless, variable rate only).
///
/// Inputs:
///   [0] Active loan UTXO
///   [1] Rate UTXO (value = new rate numerator)
///
/// Outputs:
///   [0] Continuation active loan UTXO (same P2SH, value reduced by interest)
///   [1] Lender receives accrued interest
pub fn build_rebalance_tx(
    params: &RebalanceParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    if loan.rate_mode != 1 {
        return Err(LendingTxError::MissingData(
            "rebalance requires variable rate mode (rate_mode=1)".to_string(),
        ));
    }

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    // Build new RS with updated rate_num for D&R continuation.
    // The covenant's D&R prefix [0..76) locks everything up to rate_num's data,
    // and suffix [84..end) locks rate_den and everything after it (including start_daa).
    // Only rate_num data bytes [76..84) can change. start_daa is immutable on-chain;
    // interest settlement is handled off-chain by the LoanTracker.
    let new_rs = kob_core::lending::build_active_loan_redeem_script(
        &[0u8; 32], // no insurer
        &loan.lender_spk_hash,
        &loan.borrower_spk_hash,
        loan.principal,
        params.new_rate_num,
        loan.rate_den,
        loan.start_daa, // Must match old RS — covenant suffix locks this field
        loan.expiry_daa,
        &loan.collateral_cov_id,
        loan.rate_mode,
        loan.rate_floor,
        loan.rate_cap,
        loan.grace_daa,
        loan.liq_threshold,
    ).map_err(|e| LendingTxError::MissingData(format!("new RS build: {e}")))?;

    // P2SH from NEW rs — the covenant's D&R Step 5 verifies output[ci].spk == P2SH(new_rs)
    let p2sh_spk = kob_core::build_p2sh(&new_rs);

    // Indices: rate_input=1, lender_output=1, continuation=0
    let rate_input_idx: u8 = 1;
    let lender_output_idx: u8 = 1;
    let continuation_output_idx: u8 = 0;

    let sigscript = kob_core::lending::build_active_loan_rebalance_sigscript(
        rate_input_idx,
        lender_output_idx,
        continuation_output_idx,
        &rs,
        &rs,
        &new_rs,
    );

    let loan_value = loan.collateral;
    // Estimate fee from compute mass: 2 inputs, up to 2 outputs, no payload.
    let est_fee = estimate_compute_mass(2, 2, 0);
    let required = params
        .interest_payment
        .checked_add(est_fee)
        .ok_or_else(|| LendingTxError::Overflow("interest + fee".to_string()))?;

    if loan_value < required {
        return Err(LendingTxError::InsufficientFunds {
            available: loan_value,
            required,
        });
    }

    let continuation_value = loan_value - required;
    if continuation_value < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: continuation_value,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    let mut outputs = vec![LendingTxOutput {
        value: continuation_value,
        script_version: 0,
        script: p2sh_spk.script().to_vec(),
    }];

    if params.interest_payment >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: params.interest_payment,
            script_version: 0,
            script: params.lender_spk.clone(),
        });
    }

    Ok(LendingTxBlueprint {
        inputs: vec![
            LendingTxInput {
                prev_tx_id: tx_id,
                prev_index: index,
                sig_script: sigscript,
                sequence: 0,
            },
            LendingTxInput {
                prev_tx_id: params.rate_tx_id.clone(),
                prev_index: params.rate_index,
                sig_script: params.rate_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![0, 0], // Permissionless
    })
}

// Partial Liquidation TX (sel=9, permissionless)

/// Parameters for building a partial liquidation TX.
#[derive(Debug, Clone)]
pub struct PartialLiquidationParams {
    /// The active loan.
    pub loan: LoanPosition,
    /// Amount being liquidated (sompi).
    pub liquidate_amount: u64,
    /// Lender's actual SPK bytes.
    pub lender_spk: Vec<u8>,
    /// Liquidator's P2PK script.
    pub liquidator_script: Vec<u8>,
    /// Lender payout.
    pub lender_payout: u64,
    /// Liquidator payout.
    pub liquidator_payout: u64,
}

/// Build a partial liquidation TX (selector=9, permissionless, continuation).
///
/// Inputs:
///   [0] Active loan UTXO
///
/// Outputs:
///   [0] Continuation active loan UTXO (reduced value)
///   [1] Lender receives debt portion
///   [2] Liquidator receives bonus
pub fn build_partial_liquidation_tx(
    params: &PartialLiquidationParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    if params.liquidate_amount == 0 {
        return Err(LendingTxError::MissingData("liquidate_amount must be > 0".to_string()));
    }

    let p2sh_spk = kob_core::build_p2sh(&rs);

    // Indices: price_input=0 (self), lender_output=1, liquidator_output=2, continuation=0
    let price_input_idx: u8 = 0;
    let lender_output_idx: u8 = 1;
    let liquidator_output_idx: u8 = 2;
    let continuation_output_idx: u8 = 0;

    let sigscript = kob_core::lending::build_active_loan_partial_liquidation_sigscript(
        price_input_idx,
        lender_output_idx,
        liquidator_output_idx,
        continuation_output_idx,
        params.liquidate_amount,
        &rs,
    );

    let loan_value = loan.collateral;
    let total_payout = params
        .lender_payout
        .checked_add(params.liquidator_payout)
        .ok_or_else(|| LendingTxError::Overflow("lender + liquidator payout".to_string()))?;
    // Estimate fee from compute mass: 1 input, up to 3 outputs, no payload.
    let est_fee = estimate_compute_mass(1, 3, 0);
    let required = total_payout
        .checked_add(est_fee)
        .ok_or_else(|| LendingTxError::Overflow("payout + fee".to_string()))?;

    if loan_value < required {
        return Err(LendingTxError::InsufficientFunds {
            available: loan_value,
            required,
        });
    }

    let continuation_value = loan_value - required;
    if continuation_value < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: continuation_value,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    let mut outputs = vec![LendingTxOutput {
        value: continuation_value,
        script_version: 0,
        script: p2sh_spk.script().to_vec(),
    }];

    if params.lender_payout >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: params.lender_payout,
            script_version: 0,
            script: params.lender_spk.clone(),
        });
    }

    if params.liquidator_payout >= MIN_UTXO_VALUE {
        outputs.push(LendingTxOutput {
            value: params.liquidator_payout,
            script_version: 0,
            script: params.liquidator_script.clone(),
        });
    }

    Ok(LendingTxBlueprint {
        inputs: vec![LendingTxInput {
            prev_tx_id: tx_id,
            prev_index: index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![0], // Permissionless
    })
}

// Loan Transfer TX (sel=10, lender sig)

/// Parameters for building a loan transfer TX.
#[derive(Debug, Clone)]
pub struct LoanTransferParams {
    /// The active loan.
    pub loan: LoanPosition,
    /// Current lender's signature (64 bytes Schnorr).
    pub lender_sig: [u8; 64],
    /// Current lender's public key (32 bytes x-only).
    pub lender_pk: [u8; 32],
    /// New lender's SPK hash (32 bytes Blake2b).
    pub new_lender_hash: [u8; 32],
}

/// Build a loan transfer TX (selector=10, lender sig, D&R continuation with new lender).
///
/// Inputs:
///   [0] Active loan UTXO
///
/// Outputs:
///   [0] Continuation active loan UTXO (new P2SH with new lender_spk_hash)
///
/// Uses D&R pattern: the new RS has updated lender_spk_hash while all other
/// state fields remain unchanged. The covenant verifies prefix/suffix match
/// and the lender's signature authorizes the transfer.
pub fn build_loan_transfer_tx(
    params: &LoanTransferParams,
) -> Result<LendingTxBlueprint, LendingTxError> {
    let loan = &params.loan;

    let rs = loan.redeem_script.clone();
    if rs.is_empty() {
        return Err(LendingTxError::MissingData("empty redeem_script".to_string()));
    }

    // Build new RS with updated lender_spk_hash for D&R
    let new_rs = kob_core::lending::build_active_loan_redeem_script(
        &[0u8; 32], // no insurer
        &params.new_lender_hash,
        &loan.borrower_spk_hash,
        loan.principal,
        loan.rate_num,
        loan.rate_den,
        loan.start_daa,
        loan.expiry_daa,
        &loan.collateral_cov_id,
        loan.rate_mode,
        loan.rate_floor,
        loan.rate_cap,
        loan.grace_daa,
        loan.liq_threshold,
    ).map_err(|e| LendingTxError::MissingData(format!("new RS build: {e}")))?;

    let p2sh_spk = kob_core::build_p2sh(&new_rs);

    // Continuation output index = 0
    let continuation_output_idx: u8 = 0;

    let sigscript = kob_core::lending::build_active_loan_loan_transfer_sigscript(
        &params.lender_sig,
        &params.lender_pk,
        continuation_output_idx,
        &params.new_lender_hash,
        &rs,
        &rs,
        &new_rs,
    );

    let loan_value = loan.collateral;
    // Estimate fee from compute mass: 1 input (1 sig), 1 output, no payload.
    let est_fee = estimate_compute_mass(1, 1, 0);
    let payout = loan_value.saturating_sub(est_fee);
    if payout < MIN_UTXO_VALUE {
        return Err(LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: payout,
        });
    }

    let (tx_id, index) = parse_outpoint(&loan.outpoint);

    Ok(LendingTxBlueprint {
        inputs: vec![LendingTxInput {
            prev_tx_id: tx_id,
            prev_index: index,
            sig_script: sigscript,
            sequence: 0,
        }],
        outputs: vec![LendingTxOutput {
            value: payout,
            script_version: 0,
            script: p2sh_spk.script().to_vec(),
        }],
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lending_book::LendingOffer;

    fn make_offer(value: u64) -> LendingOffer {
        LendingOffer {
            outpoint: "offer_tx:0".to_string(),
            value,
            rate_num: 500,
            rate_den: 10000,
            min_collateral_pct: 15000,
            max_duration_daa: 63_000_000,
            collateral_cov_id: [0u8; 32],
            rate_mode: 0,
            rate_floor: 0,
            owner_spk_hash: [1; 32],
            redeem_script: Vec::new(),
            p2sh_script: Vec::new(),
            owner_spk: None,
            discovered_daa: 1000,
        }
    }

    fn make_request(value: u64, desired_principal: u64) -> BorrowRequest {
        BorrowRequest {
            outpoint: "request_tx:0".to_string(),
            value,
            desired_principal,
            max_rate_num: 800,
            max_rate_den: 10000,
            duration_daa: 31_000_000,
            rate_mode: 0,
            rate_cap: 0,
            collateral_cov_id: [0u8; 32],
            owner_spk_hash: [2; 32],
            redeem_script: Vec::new(),
            p2sh_script: Vec::new(),
            owner_spk: None,
            discovered_daa: 1000,
        }
    }

    fn make_loan(principal: u64, collateral: u64) -> LoanPosition {
        // Build a real RS for testing
        let rs = kob_core::lending::build_active_loan_redeem_script(
            &[0u8; 32],          // no insurer
            &[1; 32],            // lender
            &[2; 32],            // borrower
            principal,
            500,                 // rate_num (5%)
            10000,               // rate_den
            1_000_000,           // start_daa
            32_000_000,          // expiry_daa
            &[0u8; 32],         // KAS collateral
            0,                   // fixed rate
            0,                   // rate_floor
            0,                   // rate_cap
            1_000_000,           // grace_daa
            15000,               // liq_threshold (150%)
        )
        .unwrap();

        LoanPosition {
            outpoint: "loan_tx:0".to_string(),
            principal,
            collateral,
            rate_num: 500,
            rate_den: 10000,
            start_daa: 1_000_000,
            expiry_daa: 32_000_000,
            grace_daa: 1_000_000,
            lender_spk_hash: [1; 32],
            borrower_spk_hash: [2; 32],
            rate_mode: 0,
            rate_floor: 0,
            rate_cap: 0,
            collateral_cov_id: [0u8; 32],
            liq_threshold: 15000,
            redeem_script: rs,
        }
    }

    fn make_variable_loan(principal: u64, collateral: u64) -> LoanPosition {
        let rs = kob_core::lending::build_active_loan_redeem_script(
            &[0u8; 32],          // no insurer
            &[1; 32],
            &[2; 32],
            principal,
            500,
            10000,
            1_000_000,
            32_000_000,
            &[0u8; 32],
            1,    // variable rate
            300,  // rate_floor
            800,  // rate_cap
            1_000_000,
            15000,               // liq_threshold (150%)
        )
        .unwrap();

        LoanPosition {
            outpoint: "loan_tx:0".to_string(),
            principal,
            collateral,
            rate_num: 500,
            rate_den: 10000,
            start_daa: 1_000_000,
            expiry_daa: 32_000_000,
            grace_daa: 1_000_000,
            lender_spk_hash: [1; 32],
            borrower_spk_hash: [2; 32],
            rate_mode: 1,
            rate_floor: 300,
            rate_cap: 800,
            collateral_cov_id: [0u8; 32],
            liq_threshold: 15000,
            redeem_script: rs,
        }
    }

    fn dummy_sig() -> [u8; 64] {
        [0xAA; 64]
    }

    fn dummy_pk() -> [u8; 32] {
        [0xBB; 32]
    }

    fn dummy_spk() -> Vec<u8> {
        [vec![0x20], vec![0xCC; 32]].concat()
    }

    fn matcher_spk() -> Vec<u8> {
        [vec![0x20], vec![0xDD; 32]].concat()
    }

    // Match TX tests

    #[test]
    fn match_tx_basic() {
        let mut offer = make_offer(10_600_000); // enough to cover mass-based fee
        // Build real RS for the offer
        offer.redeem_script = kob_core::lending::build_loan_offer_redeem_script(
            &[1; 32], 10_600_000, 500, 10000, 15000, 63_000_000, &[0u8; 32], 0, 0,
        ).unwrap();
        let mut request = make_request(20_000_000, 10_000_000);
        request.redeem_script = kob_core::lending::build_borrow_request_redeem_script(
            &[2; 32], 10_000_000, 800, 10000, 31_000_000, &[0u8; 32], 0, 0,
        ).unwrap();

        let params = LendingMatchParams {
            offer,
            request,
            agreed_rate_num: 500,
            agreed_rate_den: 10000,
            principal: 10_000_000,
            duration_daa: 31_000_000,
            current_daa: 1_000_000,
            rate_mode: 0,
            rate_floor_num: 0,
            rate_cap_num: 0,
            grace_daa: 1_000_000,
            collateral_cov_id: [0u8; 32],
            matcher_script: matcher_spk(),
            borrower_spk: dummy_spk(),
            liq_threshold: 15000,
        };

        let (blueprint, rs) = build_lending_match_tx(&params).unwrap();
        assert!(!rs.is_empty());
        assert_eq!(blueprint.inputs.len(), 2);
        assert!(blueprint.outputs.len() >= 2); // loan + principal
        assert_eq!(blueprint.outputs[0].value, 20_000_000); // collateral
        assert_eq!(blueprint.outputs[1].value, 10_000_000); // principal to borrower
        assert!(!blueprint.payload.is_empty());
    }

    #[test]
    fn match_tx_insufficient_funds() {
        let mut offer = make_offer(3_000_000); // Only 3M
        offer.redeem_script = kob_core::lending::build_loan_offer_redeem_script(
            &[1; 32], 3_000_000, 500, 10000, 15000, 63_000_000, &[0u8; 32], 0, 0,
        ).unwrap();
        // Request collateral = 4M, desired_principal = 10M -> principal = min(3M, 10M) = 3M
        // Required: 4M (collateral) + 3M (principal) + fee > 7M
        // Available: 3M + 4M = 7M < required
        let mut request = make_request(4_000_000, 10_000_000);
        request.redeem_script = kob_core::lending::build_borrow_request_redeem_script(
            &[2; 32], 10_000_000, 800, 10000, 31_000_000, &[0u8; 32], 0, 0,
        ).unwrap();

        let params = LendingMatchParams {
            offer,
            request,
            agreed_rate_num: 500,
            agreed_rate_den: 10000,
            principal: 3_000_000,
            duration_daa: 31_000_000,
            current_daa: 1_000_000,
            rate_mode: 0,
            rate_floor_num: 0,
            rate_cap_num: 0,
            grace_daa: 1_000_000,
            collateral_cov_id: [0u8; 32],
            matcher_script: matcher_spk(),
            borrower_spk: dummy_spk(),
            liq_threshold: 15000,
        };

        let result = build_lending_match_tx(&params);
        assert!(matches!(result, Err(LendingTxError::InsufficientFunds { .. })));
    }

    #[test]
    fn match_tx_with_change() {
        let mut offer = make_offer(15_000_000); // 15M principal, but only lending 10M
        offer.redeem_script = kob_core::lending::build_loan_offer_redeem_script(
            &[1; 32], 15_000_000, 500, 10000, 15000, 63_000_000, &[0u8; 32], 0, 0,
        ).unwrap();
        let mut request = make_request(20_000_000, 10_000_000);
        request.redeem_script = kob_core::lending::build_borrow_request_redeem_script(
            &[2; 32], 10_000_000, 800, 10000, 31_000_000, &[0u8; 32], 0, 0,
        ).unwrap();

        let params = LendingMatchParams {
            offer,
            request,
            agreed_rate_num: 500,
            agreed_rate_den: 10000,
            principal: 10_000_000,
            duration_daa: 31_000_000,
            current_daa: 1_000_000,
            rate_mode: 0,
            rate_floor_num: 0,
            rate_cap_num: 0,
            grace_daa: 1_000_000,
            collateral_cov_id: [0u8; 32],
            matcher_script: matcher_spk(),
            borrower_spk: dummy_spk(),
            liq_threshold: 15000,
        };

        let (blueprint, _) = build_lending_match_tx(&params).unwrap();
        // Change: 15M + 20M - 20M(coll) - 10M(principal) - est_fee -> output[2]
        assert_eq!(blueprint.outputs.len(), 3);
        let change = blueprint.outputs[2].value;
        let est_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(2, 3, blueprint.payload.len()));
        assert_eq!(change, 5_000_000 - est_fee);
    }

    // Liquidation TX tests

    #[test]
    fn liquidation_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = LoanLiquidationParams {
            loan,
            lender_spk: dummy_spk(),
            borrower_spk: dummy_spk(),
            liquidator_script: dummy_spk(),
            lender_payout: 10_000_000,
            borrower_payout: 5_000_000,
            liquidator_payout: 4_000_000,
        };

        let blueprint = build_liquidation_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 1);
        assert_eq!(blueprint.outputs.len(), 3);
        assert_eq!(blueprint.sig_op_counts, vec![0]); // Permissionless
    }

    #[test]
    fn liquidation_tx_insufficient_funds() {
        let loan = make_loan(10_000_000, 15_000_000);
        let params = LoanLiquidationParams {
            loan,
            lender_spk: dummy_spk(),
            borrower_spk: dummy_spk(),
            liquidator_script: dummy_spk(),
            lender_payout: 10_000_000,
            borrower_payout: 3_000_000,
            liquidator_payout: 3_000_000,
        };

        let result = build_liquidation_tx(&params);
        assert!(matches!(result, Err(LendingTxError::InsufficientFunds { .. })));
    }

    #[test]
    fn liquidation_tx_no_borrower_return() {
        let loan = make_loan(10_000_000, 15_000_000);
        let params = LoanLiquidationParams {
            loan,
            lender_spk: dummy_spk(),
            borrower_spk: dummy_spk(),
            liquidator_script: dummy_spk(),
            lender_payout: 10_000_000,
            borrower_payout: 0, // No borrower return
            liquidator_payout: 4_000_000,
        };

        let blueprint = build_liquidation_tx(&params).unwrap();
        // Only lender + liquidator outputs
        assert_eq!(blueprint.outputs.len(), 2);
    }

    // Default Claim TX tests

    #[test]
    fn default_claim_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = DefaultClaimParams {
            loan: loan.clone(),
            lender_sig: dummy_sig(),
            lender_pk: dummy_pk(),
            lender_spk: dummy_spk(),
        };

        let blueprint = build_default_claim_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 1);
        assert_eq!(blueprint.outputs.len(), 1);
        let est_fee = estimate_compute_mass(1, 1, 0);
        assert_eq!(blueprint.outputs[0].value, 20_000_000 - est_fee);
        // lock_time = expiry + grace = 32M + 1M = 33M
        assert_eq!(blueprint.lock_time, 33_000_000);
        assert_eq!(blueprint.sig_op_counts, vec![1]);
    }

    #[test]
    fn default_claim_tx_empty_rs_fails() {
        let mut loan = make_loan(10_000_000, 20_000_000);
        loan.redeem_script = Vec::new();
        let params = DefaultClaimParams {
            loan,
            lender_sig: dummy_sig(),
            lender_pk: dummy_pk(),
            lender_spk: dummy_spk(),
        };

        assert!(matches!(
            build_default_claim_tx(&params),
            Err(LendingTxError::MissingData(_))
        ));
    }

    // Repay TX tests

    #[test]
    fn repay_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = RepayParams {
            loan: loan.clone(),
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            borrower_spk: dummy_spk(),
            funding_tx_id: None,
            funding_index: None,
            funding_value: None,
            funding_sig_script: None,
            current_daa: 2_000_000, // 1M DAA elapsed
        };

        let blueprint = build_repay_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 1);
        // Lender gets principal + interest
        // interest = 10M * 500 * 1M / (10000 * 315360000) = ~1587 sompi
        assert!(blueprint.outputs[0].value > 10_000_000);
        // Borrower gets remainder
        assert!(blueprint.outputs.len() >= 1);
    }

    #[test]
    fn repay_tx_with_funding() {
        let loan = make_loan(10_000_000, 15_000_000);
        let params = RepayParams {
            loan: loan.clone(),
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            borrower_spk: dummy_spk(),
            funding_tx_id: Some("funding_tx".to_string()),
            funding_index: Some(0),
            funding_value: Some(5_000_000),
            funding_sig_script: Some(vec![0x00]),
            current_daa: 2_000_000,
        };

        let blueprint = build_repay_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 2); // loan + funding
    }

    #[test]
    fn repay_tx_insufficient_funds() {
        let loan = make_loan(10_000_000, 5_000_000); // Only 5M collateral
        let params = RepayParams {
            loan,
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            borrower_spk: dummy_spk(),
            funding_tx_id: None,
            funding_index: None,
            funding_value: None,
            funding_sig_script: None,
            current_daa: 2_000_000,
        };

        // 5M < 10M principal + interest + fee
        let result = build_repay_tx(&params);
        assert!(matches!(result, Err(LendingTxError::InsufficientFunds { .. })));
    }

    // Partial Repay TX tests

    #[test]
    fn partial_repay_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = PartialRepayParams {
            loan,
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            repay_amount: 5_000_000,
        };

        let blueprint = build_partial_repay_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 1);
        assert_eq!(blueprint.outputs.len(), 2); // continuation + lender
        // Continuation: 20M - 5M - est_fee
        let est_fee = estimate_compute_mass(1, 2, 0);
        assert_eq!(blueprint.outputs[0].value, 15_000_000 - est_fee);
        assert_eq!(blueprint.outputs[1].value, 5_000_000);
    }

    #[test]
    fn partial_repay_tx_zero_amount_fails() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = PartialRepayParams {
            loan,
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            repay_amount: 0,
        };

        assert!(matches!(
            build_partial_repay_tx(&params),
            Err(LendingTxError::MissingData(_))
        ));
    }

    #[test]
    fn partial_repay_insufficient_for_continuation() {
        let loan = make_loan(10_000_000, 6_000_000); // Only 6M collateral
        let params = PartialRepayParams {
            loan,
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            repay_amount: 5_000_000,
        };

        // Continuation = 6M - 5M - est_fee < MIN_UTXO (3M)
        let result = build_partial_repay_tx(&params);
        assert!(matches!(result, Err(LendingTxError::OutputBelowMinimum { .. })));
    }

    // Top-up TX tests

    #[test]
    fn topup_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = TopUpParams {
            loan,
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            additional_collateral: 5_000_000,
            funding_tx_id: "funding_tx".to_string(),
            funding_index: 0,
            funding_value: 5_100_000, // enough for additional + mass-based fee
            funding_sig_script: vec![0x00],
        };

        let blueprint = build_topup_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 2); // loan + funding
        assert_eq!(blueprint.outputs.len(), 1); // continuation
        assert_eq!(blueprint.outputs[0].value, 25_000_000); // 20M + 5M
    }

    #[test]
    fn topup_tx_insufficient_funding() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = TopUpParams {
            loan,
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            additional_collateral: 5_000_000,
            funding_tx_id: "funding_tx".to_string(),
            funding_index: 0,
            funding_value: 4_000_000, // Not enough
            funding_sig_script: vec![0x00],
        };

        let result = build_topup_tx(&params);
        assert!(matches!(result, Err(LendingTxError::InsufficientFunds { .. })));
    }

    // Extend TX tests

    #[test]
    fn extend_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = ExtendParams {
            loan,
            lender_sig: dummy_sig(),
            lender_pk: dummy_pk(),
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            new_expiry_daa: 64_000_000,
            interest_payment: 3_000_000,
        };

        let blueprint = build_extend_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 1);
        assert_eq!(blueprint.outputs.len(), 2); // continuation + interest
        // Continuation: 20M - 3M - est_fee
        let est_fee = estimate_compute_mass(1, 2, 0);
        assert_eq!(blueprint.outputs[0].value, 17_000_000 - est_fee);
        assert_eq!(blueprint.outputs[1].value, 3_000_000);
        assert_eq!(blueprint.sig_op_counts, vec![2]); // 2-of-2
    }

    #[test]
    fn extend_tx_insufficient_for_interest() {
        let loan = make_loan(10_000_000, 5_000_000);
        let params = ExtendParams {
            loan,
            lender_sig: dummy_sig(),
            lender_pk: dummy_pk(),
            borrower_sig: dummy_sig(),
            borrower_pk: dummy_pk(),
            lender_spk: dummy_spk(),
            new_expiry_daa: 64_000_000,
            interest_payment: 5_000_000, // = collateral, no room for fee
        };

        let result = build_extend_tx(&params);
        assert!(matches!(result, Err(LendingTxError::InsufficientFunds { .. })));
    }

    // Rebalance TX tests

    #[test]
    fn rebalance_tx_basic() {
        let loan = make_variable_loan(10_000_000, 20_000_000);
        let params = RebalanceParams {
            loan,
            rate_tx_id: "rate_tx".to_string(),
            rate_index: 0,
            rate_sig_script: vec![0x00],
            lender_spk: dummy_spk(),
            sig_with_type: vec![0u8; 65],
            pubkey: vec![0u8; 32],
            interest_payment: 3_000_000,
            new_rate_num: 600,
            new_start_daa: 2_000_000, // must be < expiry_daa (32_000_000)
        };

        let blueprint = build_rebalance_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 2); // loan + rate
        assert_eq!(blueprint.outputs.len(), 2); // continuation + interest
        assert_eq!(blueprint.sig_op_counts, vec![0, 0]); // Permissionless
    }

    #[test]
    fn rebalance_tx_fixed_rate_fails() {
        let loan = make_loan(10_000_000, 20_000_000); // rate_mode = 0
        let params = RebalanceParams {
            loan,
            rate_tx_id: "rate_tx".to_string(),
            rate_index: 0,
            rate_sig_script: vec![0x00],
            lender_spk: dummy_spk(),
            sig_with_type: vec![0u8; 65],
            pubkey: vec![0u8; 32],
            interest_payment: 3_000_000,
            new_rate_num: 600,
            new_start_daa: 200_000_000,
        };

        let result = build_rebalance_tx(&params);
        assert!(matches!(result, Err(LendingTxError::MissingData(_))));
    }

    // Partial Liquidation TX tests

    #[test]
    fn partial_liquidation_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = PartialLiquidationParams {
            loan,
            liquidate_amount: 3_000_000,
            lender_spk: dummy_spk(),
            liquidator_script: dummy_spk(),
            lender_payout: 5_000_000,
            liquidator_payout: 3_000_000,
        };

        let blueprint = build_partial_liquidation_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 1);
        assert_eq!(blueprint.outputs.len(), 3); // continuation + lender + liquidator
        // Continuation: 20M - 5M - 3M - est_fee
        let est_fee = estimate_compute_mass(1, 3, 0);
        assert_eq!(blueprint.outputs[0].value, 12_000_000 - est_fee);
    }

    #[test]
    fn partial_liquidation_zero_amount_fails() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = PartialLiquidationParams {
            loan,
            liquidate_amount: 0,
            lender_spk: dummy_spk(),
            liquidator_script: dummy_spk(),
            lender_payout: 5_000_000,
            liquidator_payout: 3_000_000,
        };

        assert!(matches!(
            build_partial_liquidation_tx(&params),
            Err(LendingTxError::MissingData(_))
        ));
    }

    // Loan Transfer TX tests

    #[test]
    fn loan_transfer_tx_basic() {
        let loan = make_loan(10_000_000, 20_000_000);
        let params = LoanTransferParams {
            loan,
            lender_sig: dummy_sig(),
            lender_pk: dummy_pk(),
            new_lender_hash: [3; 32],
        };

        let blueprint = build_loan_transfer_tx(&params).unwrap();
        assert_eq!(blueprint.inputs.len(), 1);
        assert_eq!(blueprint.outputs.len(), 1); // continuation with new lender
        let est_fee = estimate_compute_mass(1, 1, 0);
        assert_eq!(blueprint.outputs[0].value, 20_000_000 - est_fee);
        assert_eq!(blueprint.sig_op_counts, vec![1]);
    }

    #[test]
    fn loan_transfer_tx_empty_rs_fails() {
        let mut loan = make_loan(10_000_000, 20_000_000);
        loan.redeem_script = Vec::new();
        let params = LoanTransferParams {
            loan,
            lender_sig: dummy_sig(),
            lender_pk: dummy_pk(),
            new_lender_hash: [3; 32],
        };

        assert!(matches!(
            build_loan_transfer_tx(&params),
            Err(LendingTxError::MissingData(_))
        ));
    }

    // Helper: parse_outpoint

    #[test]
    fn parse_outpoint_basic() {
        let (tx_id, index) = parse_outpoint("abc123:5");
        assert_eq!(tx_id, "abc123");
        assert_eq!(index, 5);
    }

    #[test]
    fn parse_outpoint_zero_index() {
        let (tx_id, index) = parse_outpoint("abc123:0");
        assert_eq!(tx_id, "abc123");
        assert_eq!(index, 0);
    }

    #[test]
    fn parse_outpoint_no_colon() {
        let (tx_id, index) = parse_outpoint("abc123");
        assert_eq!(tx_id, "abc123");
        assert_eq!(index, 0); // default
    }

    // Error display

    #[test]
    fn error_display() {
        let e1 = LendingTxError::InsufficientFunds {
            available: 100,
            required: 200,
        };
        assert!(format!("{e1}").contains("100"));
        assert!(format!("{e1}").contains("200"));

        let e2 = LendingTxError::OutputBelowMinimum {
            output_idx: 0,
            value: 1000,
        };
        assert!(format!("{e2}").contains("1000"));

        let e3 = LendingTxError::Overflow("test".to_string());
        assert!(format!("{e3}").contains("test"));

        let e4 = LendingTxError::MissingData("missing".to_string());
        assert!(format!("{e4}").contains("missing"));

        let e5 = LendingTxError::InterestError("bad".to_string());
        assert!(format!("{e5}").contains("bad"));
    }

    // Payload construction

    #[test]
    fn match_tx_payload_starts_with_prefix() {
        let mut offer = make_offer(10_600_000); // enough to cover mass-based fee
        offer.redeem_script = kob_core::lending::build_loan_offer_redeem_script(
            &[1; 32], 10_600_000, 500, 10000, 15000, 63_000_000, &[0u8; 32], 0, 0,
        ).unwrap();
        let mut request = make_request(20_000_000, 10_000_000);
        request.redeem_script = kob_core::lending::build_borrow_request_redeem_script(
            &[2; 32], 10_000_000, 800, 10000, 31_000_000, &[0u8; 32], 0, 0,
        ).unwrap();

        let params = LendingMatchParams {
            offer,
            request,
            agreed_rate_num: 500,
            agreed_rate_den: 10000,
            principal: 10_000_000,
            duration_daa: 31_000_000,
            current_daa: 1_000_000,
            rate_mode: 0,
            rate_floor_num: 0,
            rate_cap_num: 0,
            grace_daa: 1_000_000,
            collateral_cov_id: [0u8; 32],
            matcher_script: matcher_spk(),
            borrower_spk: dummy_spk(),
            liq_threshold: 15000,
        };

        let (blueprint, _) = build_lending_match_tx(&params).unwrap();
        assert!(blueprint.payload.starts_with(b"KOB:L:"));
    }

    // Interest calculation cross-check

    #[test]
    fn repay_interest_amount_matches_core() {
        let principal = 10_000_000u64;
        let rate_num = 500u64;
        let rate_den = 10000u64;
        let elapsed_daa = 31_536_000u64; // ~1 year

        let interest =
            kob_core::lending::calculate_interest(principal, rate_num, rate_den, elapsed_daa)
                .unwrap();

        // 5% of 10M for 1 year (31536000 / 315360000 = 0.1 year)
        // = 10M * 500 * 31536000 / (10000 * 315360000)
        // = 10M * 0.05 * 0.1 = 50000
        assert_eq!(interest, 50_000);
    }

    #[test]
    fn interest_zero_elapsed() {
        let interest =
            kob_core::lending::calculate_interest(10_000_000, 500, 10000, 0).unwrap();
        assert_eq!(interest, 0);
    }

    #[test]
    fn interest_zero_rate() {
        let interest =
            kob_core::lending::calculate_interest(10_000_000, 0, 10000, 31_536_000).unwrap();
        assert_eq!(interest, 0);
    }
}
