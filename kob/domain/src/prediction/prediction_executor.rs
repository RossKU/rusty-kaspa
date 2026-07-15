//! Prediction market transaction construction (create, vote, split, merge, settle, redeem).
#![allow(deprecated)]

use crate::prediction_book::{
    BallotBoxEntry, BallotSide, RedemptionEntry, SplitMergeEntry,
};

use kob_core::mass::estimate_compute_mass;
use kob_core::MIN_UTXO_VALUE;

/// A constructed (unsigned) transaction ready for submission.
#[derive(Debug, Clone)]
pub struct PredictionTxBlueprint {
    /// Transaction inputs.
    pub inputs: Vec<PredictionTxInput>,
    /// Transaction outputs.
    pub outputs: Vec<PredictionTxOutput>,
    /// TX payload bytes (e.g., KOB:M:<RS>).
    pub payload: Vec<u8>,
    /// Lock time (0 for normal TXs, >0 for CLTV-gated paths).
    pub lock_time: u64,
    /// sigOpCount for each input.
    pub sig_op_counts: Vec<u8>,
}

/// A transaction input.
#[derive(Debug, Clone)]
pub struct PredictionTxInput {
    /// Previous TX ID (hex, 64 chars).
    pub prev_tx_id: String,
    /// Previous output index.
    pub prev_index: u32,
    /// SigScript bytes.
    pub sig_script: Vec<u8>,
    /// Sequence number.
    pub sequence: u64,
}

/// A transaction output.
#[derive(Debug, Clone)]
pub struct PredictionTxOutput {
    /// Value in sompi.
    pub value: u64,
    /// ScriptPublicKey version.
    pub script_version: u16,
    /// ScriptPublicKey bytes.
    pub script: Vec<u8>,
    /// Wire-level covenant binding `(authorizing_input, covenant_id)`, if
    /// this output is a covenant genesis or continuation. Distinct from the
    /// P2SH script hash: this is what `OpInputCovenantId`/`OpCovInputCount`/
    /// `OpCovOutputCount` actually track on-chain (see
    /// `kob_core::compute_covenant_id`); most prediction outputs (change,
    /// receipts, non-covenant payouts) leave this `None`.
    pub covenant: Option<(u16, [u8; 32])>,
}

/// Error type for TX construction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredictionTxError {
    /// Input value too low.
    InsufficientFunds { available: u64, required: u64 },
    /// Output below dust threshold.
    OutputBelowMinimum { output_idx: usize, value: u64 },
    /// Arithmetic overflow.
    Overflow(String),
    /// Missing required data.
    MissingData(String),
    /// Invalid state for the operation.
    InvalidState(String),
}

impl std::fmt::Display for PredictionTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientFunds { available, required } => {
                write!(f, "insufficient funds: have {available}, need {required}")
            }
            Self::OutputBelowMinimum { output_idx, value } => {
                write!(f, "output[{output_idx}] value {value} below minimum {MIN_UTXO_VALUE}")
            }
            Self::Overflow(msg) => write!(f, "arithmetic overflow: {msg}"),
            Self::MissingData(msg) => write!(f, "missing data: {msg}"),
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
        }
    }
}

// 1. Create Market TX

/// Parameters for creating a new prediction market.
#[derive(Debug, Clone)]
pub struct CreateMarketParams {
    /// Market ID (32 bytes, Blake2b hash of market parameters).
    pub market_id: [u8; 32],
    /// Creator's public key (32 bytes x-only Schnorr).
    pub creator_pubkey: [u8; 32],
    /// Creator's pubkey hash (Blake2b-256).
    pub creator_pkh: [u8; 32],
    /// YES token covenant ID (32 bytes).
    pub yes_token_cid: [u8; 32],
    /// NO token covenant ID (32 bytes).
    pub no_token_cid: [u8; 32],
    /// Reward per vote (sompi).
    pub reward_per_vote: u64,
    /// DAA score when voting begins.
    pub start_daa: u64,
    /// DAA score when voting ends (cooling period begins).
    pub end_daa: u64,
    /// DAA score when market expires.
    pub expiry_daa: u64,
    /// Unit value for SplitMerge (KAS per token pair).
    pub unit_value: u64,
    /// Payout per winning token (sompi).
    pub payout_per_token: u64,
    /// Threshold value for Redemption settlement.
    pub threshold_value: u64,
    /// Initial value for each BallotBox (pool for miner rewards).
    pub ballot_box_initial_value: u64,
    /// Initial value for SplitMerge pool.
    pub split_merge_initial_value: u64,
    /// Initial value for Redemption pool.
    pub redemption_initial_value: u64,
    /// Funding UTXO: TX ID (hex).
    pub funding_tx_id: String,
    /// Funding UTXO: output index.
    pub funding_index: u32,
    /// Funding UTXO: value (sompi).
    pub funding_value: u64,
    /// Funding UTXO: sigscript (caller builds, e.g., P2PK sig).
    pub funding_sig_script: Vec<u8>,
    /// Funding UTXO: sigOpCount.
    pub funding_sig_op_count: u8,
    /// Change output script (creator's P2PK).
    pub change_script: Vec<u8>,
}

/// Compute the shared BallotBox covenant ID.
///
/// YES and NO BallotBox are the SAME covenant (identical redeemScript --
/// `build_ballot_box_redeem_script` is called with identical params for
/// both), distinguished only by output position and UTXO value, so they
/// share ONE wire-level `covenant_id` rather than having two distinct ones
/// (confirmed by `build_redemption_redeem_script` taking a single
/// `ballot_cid` state field consumed by BOTH sides' `OpCovInputIdx` lookups
/// in the receipt/token redeem paths). That id is `hashing::covenant_id`
/// over the funding input's outpoint plus BOTH ballot box outputs together
/// (a 2-output genesis auth group) -- see `kob_core::compute_covenant_id`.
/// Callable independently at any later step (vote, settle, redemption
/// deploy) since it only needs public, already-known data: no wallet or
/// signing required.
pub fn compute_ballot_cid(
    funding_tx_id: &str,
    funding_index: u32,
    yes_p2sh_script: &[u8],
    no_p2sh_script: &[u8],
    ballot_box_value: u64,
) -> Result<[u8; 32], PredictionTxError> {
    let auth_outputs = [
        kob_core::tx::AuthOutput { index: 0, value: ballot_box_value, spk_version: 0, spk_script: yes_p2sh_script.to_vec() },
        kob_core::tx::AuthOutput { index: 1, value: ballot_box_value, spk_version: 0, spk_script: no_p2sh_script.to_vec() },
    ];
    kob_core::compute_covenant_id(funding_tx_id, funding_index, &auth_outputs)
        .map_err(|e| PredictionTxError::MissingData(format!("compute_ballot_cid: {e}")))
}

/// Build a market creation TX (step 1 of 2-step deployment).
///
/// Step 1 deploys BallotBoxes + SplitMerge:
///   Output[0]: YES BallotBox (v5)
///   Output[1]: NO BallotBox (v5)
///   Output[2]: SplitMerge (v2)
///   Output[3]: Change (if sufficient)
///
/// Both BallotBox outputs carry a genesis `CovenantBinding` sharing ONE
/// covenant id (`compute_ballot_cid`), authorized by input[0] (the funding
/// input). Without this, `OpInputCovenantId` reads `None` on the funding
/// UtxoEntry once these UTXOs are later spent, and every covenant-count
/// check in the vote/settle paths (V0/V0b in `BALLOT_BOX_BODY`) fails closed
/// -- confirmed against the real engine
/// (`kob/core/tests/prediction_vote_repro.rs`).
///
/// After this TX is confirmed, the caller extracts the BallotBox covenant IDs
/// and calls `build_deploy_redemption_tx()` for step 2.
///
/// **P-F05 fix**: Redemption is NOT deployed here because BallotBox covenant
/// IDs are derived from this TX's hash (unknown until confirmation). Previous
/// versions used placeholder `[0;32]` CIDs which broke settlement verification.
pub fn build_create_market_tx(
    params: &CreateMarketParams,
) -> Result<PredictionTxBlueprint, PredictionTxError> {
    // Validate parameters
    if params.ballot_box_initial_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: params.ballot_box_initial_value,
        });
    }
    if params.split_merge_initial_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 2,
            value: params.split_merge_initial_value,
        });
    }
    if params.redemption_initial_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 3,
            value: params.redemption_initial_value,
        });
    }

    // Build BallotBox v5 redeemScripts (settlement-compatible)
    let yes_ballot_rs = kob_core::prediction::build_ballot_box_redeem_script(
        &params.market_id,
        params.reward_per_vote,
        params.start_daa,
        params.end_daa,
        params.expiry_daa,
    ).map_err(|e| PredictionTxError::MissingData(format!("YES BallotBox RS: {e}")))?;

    let no_ballot_rs = kob_core::prediction::build_ballot_box_redeem_script(
        &params.market_id,
        params.reward_per_vote,
        params.start_daa,
        params.end_daa,
        params.expiry_daa,
    ).map_err(|e| PredictionTxError::MissingData(format!("NO BallotBox RS: {e}")))?;

    // Build SplitMerge v2 redeemScript
    let sm_rs = kob_core::prediction::build_split_merge_redeem_script(
        &params.market_id,
        &params.yes_token_cid,
        &params.no_token_cid,
        &params.creator_pkh,
        params.unit_value,
        params.expiry_daa,
    ).map_err(|e| PredictionTxError::MissingData(format!("SplitMerge RS: {e}")))?;

    // Compute P2SH scripts
    let yes_p2sh = kob_core::build_p2sh(&yes_ballot_rs);
    let no_p2sh = kob_core::build_p2sh(&no_ballot_rs);
    let sm_p2sh = kob_core::build_p2sh(&sm_rs);

    // Shared BallotBox covenant id (genesis, authorized by input[0]).
    let ballot_cid = compute_ballot_cid(
        &params.funding_tx_id,
        params.funding_index,
        yes_p2sh.script(),
        no_p2sh.script(),
        params.ballot_box_initial_value,
    )?;

    // P-F05 fix: Redemption is NOT deployed in step 1.
    // BallotBox covenant IDs are derived from the deploy TX hash, so they
    // are unknown until step 1 is confirmed on-chain. Redemption (which
    // needs real BallotBox CIDs) is deployed in a separate step 2 TX via
    // build_deploy_redemption_tx(). This eliminates the placeholder [0;32]
    // vulnerability where Redemption could never verify BallotBox identity.

    // Build payload with all redeemScripts concatenated (needed for fee estimate)
    let payload = kob_core::prediction::build_prediction_payload(&yes_ballot_rs);

    // Total required value (step 1: BallotBoxes + SplitMerge only, no Redemption)
    let total_output = params.ballot_box_initial_value
        .checked_add(params.ballot_box_initial_value)
        .and_then(|v| v.checked_add(params.split_merge_initial_value))
        .ok_or_else(|| PredictionTxError::Overflow("total output sum".to_string()))?;

    // Mass-based fee estimate: 1 input, 4 outputs (3 covenants + change)
    let estimated_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(1, 4, payload.len()));

    let total_required = total_output
        .checked_add(estimated_fee)
        .ok_or_else(|| PredictionTxError::Overflow("total + fee".to_string()))?;

    if params.funding_value < total_required {
        return Err(PredictionTxError::InsufficientFunds {
            available: params.funding_value,
            required: total_required,
        });
    }

    let change = params.funding_value - total_required;

    // Outputs (step 1: BallotBoxes + SplitMerge only)
    // Redemption is deployed in step 2 after BallotBox covenant IDs are known.
    let mut outputs = vec![
        PredictionTxOutput {
            value: params.ballot_box_initial_value,
            script_version: 0,
            covenant: Some((0, ballot_cid)),
            script: yes_p2sh.script().to_vec(),
        },
        PredictionTxOutput {
            value: params.ballot_box_initial_value,
            script_version: 0,
            covenant: Some((0, ballot_cid)),
            script: no_p2sh.script().to_vec(),
        },
        PredictionTxOutput {
            value: params.split_merge_initial_value,
            script_version: 0,
            covenant: None,
            script: sm_p2sh.script().to_vec(),
        },
    ];

    if change >= MIN_UTXO_VALUE {
        outputs.push(PredictionTxOutput {
            value: change,
            script_version: 0,
            covenant: None,
            script: params.change_script.clone(),
        });
    }

    Ok(PredictionTxBlueprint {
        inputs: vec![PredictionTxInput {
            prev_tx_id: params.funding_tx_id.clone(),
            prev_index: params.funding_index,
            sig_script: params.funding_sig_script.clone(),
            sequence: 0,
        }],
        outputs,
        payload,
        lock_time: 0,
        sig_op_counts: vec![params.funding_sig_op_count],
    })
}

// 1b. Deploy Redemption TX (step 2)

/// Parameters for deploying the Redemption covenant (step 2).
///
/// Called after the step 1 TX (BallotBoxes + SplitMerge) is confirmed and
/// the BallotBox covenant IDs are known.
#[derive(Debug, Clone)]
pub struct DeployRedemptionParams {
    /// Market ID (32 bytes).
    pub market_id: [u8; 32],
    /// YES BallotBox covenant ID (extracted from step 1 TX).
    pub yes_ballot_cid: [u8; 32],
    /// NO BallotBox covenant ID (extracted from step 1 TX).
    pub no_ballot_cid: [u8; 32],
    /// YES token covenant ID.
    pub yes_token_cid: [u8; 32],
    /// NO token covenant ID.
    pub no_token_cid: [u8; 32],
    /// Payout per winning token (sompi).
    pub payout_per_token: u64,
    /// Threshold value for settlement validation.
    pub threshold_value: u64,
    /// Creator's pubkey hash (Blake2b-256).
    pub creator_pkh: [u8; 32],
    /// Expiry DAA score.
    pub expiry_daa: u64,
    /// Initial value for Redemption pool.
    pub redemption_initial_value: u64,
    /// Funding UTXO: TX ID (hex).
    pub funding_tx_id: String,
    /// Funding UTXO: output index.
    pub funding_index: u32,
    /// Funding UTXO: value (sompi).
    pub funding_value: u64,
    /// Funding UTXO: sigscript.
    pub funding_sig_script: Vec<u8>,
    /// Funding UTXO: sigOpCount.
    pub funding_sig_op_count: u8,
    /// Change output script.
    pub change_script: Vec<u8>,
}

/// Build the Redemption deployment TX (step 2 of 2-step deployment).
///
/// Deploys Redemption v4 with REAL BallotBox covenant IDs.
///
///   Output[0]: Redemption (v4) — with verified BallotBox CIDs
///   Output[1]: Change (if sufficient)
///
/// **P-F05 fix**: This is called after step 1 BallotBoxes are deployed and
/// their covenant IDs are known.
pub fn build_deploy_redemption_tx(
    params: &DeployRedemptionParams,
) -> Result<PredictionTxBlueprint, PredictionTxError> {
    if params.redemption_initial_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: params.redemption_initial_value,
        });
    }

    // Validate BallotBox CIDs are not placeholders
    if params.yes_ballot_cid == [0u8; 32] {
        return Err(PredictionTxError::MissingData(
            "yes_ballot_cid is zero — deploy BallotBoxes first (step 1)".to_string()
        ));
    }
    if params.no_ballot_cid == [0u8; 32] {
        return Err(PredictionTxError::MissingData(
            "no_ballot_cid is zero — deploy BallotBoxes first (step 1)".to_string()
        ));
    }

    // Build Redemption redeemScript with real BallotBox CIDs
    let redemption_rs = kob_core::prediction::build_redemption_redeem_script(
        &params.market_id,
        &params.yes_ballot_cid,
        &params.yes_token_cid,
        &params.no_token_cid,
        params.payout_per_token,
        params.threshold_value,
        &params.creator_pkh,
        params.expiry_daa,
        1,             // reward_per_receipt placeholder
        &[0u8; 32],    // yes_receipt_cid placeholder
        &[0u8; 32],    // no_receipt_cid placeholder
    ).map_err(|e| PredictionTxError::MissingData(format!("Redemption RS: {e}")))?;
    let redemption_p2sh = kob_core::build_p2sh(&redemption_rs);
    let payload = kob_core::prediction::build_prediction_payload(&redemption_rs);

    // Mass-based fee estimate: 1 input, 2 outputs (redemption + change)
    let estimated_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(1, 2, payload.len()));

    let total_required = params.redemption_initial_value
        .checked_add(estimated_fee)
        .ok_or_else(|| PredictionTxError::Overflow("redemption + fee".to_string()))?;

    if params.funding_value < total_required {
        return Err(PredictionTxError::InsufficientFunds {
            available: params.funding_value,
            required: total_required,
        });
    }

    let change = params.funding_value - total_required;

    let mut outputs = vec![
        PredictionTxOutput {
            value: params.redemption_initial_value,
            script_version: 0,
            covenant: None,
            script: redemption_p2sh.script().to_vec(),
        },
    ];

    if change >= MIN_UTXO_VALUE {
        outputs.push(PredictionTxOutput {
            value: change,
            script_version: 0,
            covenant: None,
            script: params.change_script.clone(),
        });
    }

    Ok(PredictionTxBlueprint {
        inputs: vec![PredictionTxInput {
            prev_tx_id: params.funding_tx_id.clone(),
            prev_index: params.funding_index,
            sig_script: params.funding_sig_script.clone(),
            sequence: 0,
        }],
        outputs,
        payload,
        lock_time: 0,
        sig_op_counts: vec![params.funding_sig_op_count],
    })
}

// 2. Vote TX (BallotBox VoteReceipt-enabled -- 3-in/4-out)

/// Parameters for a vote transaction.
#[derive(Debug, Clone)]
pub struct VoteParams {
    /// BallotBox being voted on (its value decreases by `reward_per_vote`).
    pub ballot_box: BallotBoxEntry,
    /// The OTHER side's BallotBox (read-only co-input; self-continues
    /// unchanged). Required by the deployed contract's V0/V0b covenant-count
    /// checks (exactly 2 co-inputs / 2 continuations sharing `ballot_cid`).
    pub other_box: BallotBoxEntry,
    /// Shared BallotBox covenant id (see `compute_ballot_cid`). YES and NO
    /// BallotBox are one covenant, distinguished only by position/value, so
    /// this is the SAME value for both sides.
    pub ballot_cid: [u8; 32],
    /// Miner's UTXO TX ID (hex).
    pub miner_tx_id: String,
    /// Miner's UTXO output index.
    pub miner_index: u32,
    /// Miner's UTXO value (sompi).
    pub miner_value: u64,
    /// Miner's UTXO sigscript (P2PK sig or empty for miner-constructed TX).
    pub miner_sig_script: Vec<u8>,
    /// Miner's sigOpCount.
    pub miner_sig_op_count: u8,
    /// Miner's change output script.
    pub miner_change_script: Vec<u8>,
    /// Current DAA score (for CLTV start/end gate validation).
    pub current_daa: u64,
}

/// Build a vote TX for the deployed VoteReceipt-enabled BallotBox.
///
/// The deployed `BALLOT_BOX_BODY` vote path requires exactly 3 inputs / 4
/// outputs (V5/V7), with BOTH BallotBox inputs at positions 0/1 (V0: exactly
/// 2 co-inputs sharing `ballot_cid`) and their self-continuations at
/// `output[input_idx + 1]` (V2/V3/V4 read `output[myidx+1]`, NOT
/// `output[myidx]` -- the top-of-file doc comment in `ballot_box.rs`
/// describing `Output[0]: BallotBox A continuation` is stale/misleading;
/// trust the bytecode). `Output[3]` is a fixed absolute index (V8) reserved
/// for the VoteReceipt. This layout is derived and confirmed against the
/// real engine in `kob/core/tests/prediction_vote_repro.rs`:
///
///   Input[0]: BallotBox being voted (value decreases by reward_per_vote)
///   Input[1]: Other side's BallotBox (read-only witness, unchanged)
///   Input[2]: Miner's UTXO
///   Output[0]: Miner change
///   Output[1]: BallotBox[0] continuation (== input[0].spk)
///   Output[2]: BallotBox[1] continuation (== input[1].spk, unchanged value)
///   Output[3]: VoteReceipt (P2SH, bearer; value >= RECEIPT_DUST_FLOOR)
///
/// Fee == 0 (V6): `in[0]+in[1]+in[2] == out[0]+out[1]+out[2]+out[3]`. Since
/// only the voted box's value changes and the witness box is unchanged, the
/// miner's own in/out delta must absorb BOTH the reward gain and the new
/// receipt's cost: `miner_change = miner_value + reward_per_vote -
/// RECEIPT_DUST_FLOOR` (can be negative-in-effect if `reward_per_vote <
/// RECEIPT_DUST_FLOOR`, in which case the miner fronts the difference from
/// their own `miner_value` -- the receipt is a bearer token they can
/// immediately re-spend, so nothing is actually lost, just relocated).
pub fn build_vote_tx(params: &VoteParams) -> Result<PredictionTxBlueprint, PredictionTxError> {
    let bb = &params.ballot_box;
    let other = &params.other_box;

    // Validate voting window: start_daa <= current_daa < end_daa.
    if params.current_daa < bb.start_daa {
        return Err(PredictionTxError::InvalidState(format!(
            "voting not started: current_daa {} < start_daa {}",
            params.current_daa, bb.start_daa
        )));
    }
    if params.current_daa >= bb.end_daa {
        return Err(PredictionTxError::InvalidState(format!(
            "voting ended: current_daa {} >= end_daa {}",
            params.current_daa, bb.end_daa
        )));
    }
    if other.side == bb.side {
        return Err(PredictionTxError::InvalidState(
            "other_box must be the OPPOSITE side of the box being voted".to_string(),
        ));
    }

    // Validate BallotBox has enough value for one more vote
    let new_box_value = bb.value
        .checked_sub(bb.reward_per_vote)
        .ok_or_else(|| PredictionTxError::InvalidState(
            "ballot box value too low for another vote".to_string()
        ))?;

    if new_box_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 1,
            value: new_box_value,
        });
    }
    if other.value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 2,
            value: other.value,
        });
    }

    let receipt_value = kob_core::prediction::RECEIPT_DUST_FLOOR;

    // Miner change = miner_value + reward_per_vote - receipt_value (fee == 0)
    let miner_change = params.miner_value
        .checked_add(bb.reward_per_vote)
        .and_then(|v| v.checked_sub(receipt_value))
        .ok_or_else(|| PredictionTxError::Overflow("miner_value + reward - receipt".to_string()))?;

    if miner_change < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: miner_change,
        });
    }

    // Both BallotBox inputs dispatch into the vote path (selector=1),
    // including the read-only witness -- it independently runs the same
    // V0..V8 checks (trivially satisfied: its own decrease is 0).
    let vote_sig = kob_core::prediction::build_ballot_box_vote_sigscript(&bb.redeem_script);
    let other_vote_sig = kob_core::prediction::build_ballot_box_vote_sigscript(&other.redeem_script);

    let vote_side: u8 = match bb.side {
        BallotSide::Yes => 1,
        BallotSide::No => 0,
    };
    let receipt_rs = kob_core::prediction::build_vote_receipt_redeem_script(&params.ballot_cid, vote_side);
    let receipt_p2sh = kob_core::build_p2sh(&receipt_rs);

    let outputs = vec![
        PredictionTxOutput {
            value: miner_change,
            script_version: 0,
            covenant: None,
            script: params.miner_change_script.clone(),
        },
        PredictionTxOutput {
            value: new_box_value,
            script_version: 0,
            covenant: Some((0, params.ballot_cid)),
            script: bb.p2sh_script.clone(),
        },
        PredictionTxOutput {
            value: other.value,
            script_version: 0,
            covenant: Some((1, params.ballot_cid)),
            script: other.p2sh_script.clone(),
        },
        PredictionTxOutput {
            value: receipt_value,
            script_version: 0,
            covenant: None,
            script: receipt_p2sh.script().to_vec(),
        },
    ];

    let (bb_tx_id, bb_index) = parse_outpoint(&bb.outpoint)?;
    let (other_tx_id, other_index) = parse_outpoint(&other.outpoint)?;

    Ok(PredictionTxBlueprint {
        inputs: vec![
            PredictionTxInput {
                prev_tx_id: bb_tx_id,
                prev_index: bb_index,
                sig_script: vote_sig,
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: other_tx_id,
                prev_index: other_index,
                sig_script: other_vote_sig,
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: params.miner_tx_id.clone(),
                prev_index: params.miner_index,
                sig_script: params.miner_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: params.current_daa, // Must be in [start_daa, end_daa) for CLTV
        sig_op_counts: vec![0, 0, params.miner_sig_op_count],
    })
}

// 3. Split TX (SplitMerge v2)

/// Parameters for a split transaction.
#[derive(Debug, Clone)]
pub struct SplitParams {
    /// SplitMerge covenant UTXO.
    pub split_merge: SplitMergeEntry,
    /// User's funding UTXO TX ID (hex).
    pub user_tx_id: String,
    /// User's funding UTXO index.
    pub user_index: u32,
    /// User's funding UTXO value.
    pub user_value: u64,
    /// User's sigscript.
    pub user_sig_script: Vec<u8>,
    /// User's sigOpCount.
    pub user_sig_op_count: u8,
    /// YES token output script (P2SH of YES token covenant).
    pub yes_token_script: Vec<u8>,
    /// NO token output script (P2SH of NO token covenant).
    pub no_token_script: Vec<u8>,
    /// Token value (unit_value per token).
    pub token_value: u64,
    /// User's change script.
    pub change_script: Vec<u8>,
}

/// Build a split TX.
///
/// Split TX:
///   Input[0]: SplitMerge UTXO (pool)
///   Input[1]: User's KAS UTXO (deposit)
///   Output[0]: YES token UTXO
///   Output[1]: NO token UTXO
///   Output[2]: SplitMerge continuation (pool + deposit)
///   Output[3]: User change (if any)
pub fn build_split_tx(params: &SplitParams) -> Result<PredictionTxBlueprint, PredictionTxError> {
    let sm = &params.split_merge;

    // Build payload early (needed for fee estimate)
    let payload = kob_core::prediction::build_prediction_payload(&sm.redeem_script);

    // Each token gets token_value
    let token_output_total = params.token_value
        .checked_mul(2)
        .ok_or_else(|| PredictionTxError::Overflow("token_value * 2".to_string()))?;

    // Continuation pool value: sm.value + user_deposit
    // user_deposit = token_output_total + fee (roughly)
    // Actually: total_in = sm.value + user.value
    // total_out = yes_token + no_token + continuation + change + fee
    // continuation must > sm.value (pool grows)

    let total_input = sm.value
        .checked_add(params.user_value)
        .ok_or_else(|| PredictionTxError::Overflow("sm + user value".to_string()))?;

    // continuation = sm.value + unit_value (pool grows by unit_value per split)
    let continuation_value = sm.value
        .checked_add(sm.unit_value)
        .ok_or_else(|| PredictionTxError::Overflow("sm + unit_value".to_string()))?;

    // Mass-based fee estimate: 2 inputs, 4 outputs (yes + no + continuation + change)
    let estimated_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(2, 4, payload.len()));

    let required = token_output_total
        .checked_add(continuation_value)
        .and_then(|v| v.checked_add(estimated_fee))
        .ok_or_else(|| PredictionTxError::Overflow("outputs + fee".to_string()))?;

    // Ensure user provides enough (sm provides sm.value, user provides the rest)
    if total_input < required {
        return Err(PredictionTxError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    let change = total_input - required;

    // Build sigscript for SplitMerge (selector=2 for split)
    let sm_sig = kob_core::prediction::build_split_merge_split_sigscript(&sm.redeem_script);

    let (sm_tx_id, sm_index) = parse_outpoint(&sm.outpoint)?;

    let mut outputs = vec![
        PredictionTxOutput {
            value: params.token_value,
            script_version: 0,
            covenant: None,
            script: params.yes_token_script.clone(),
        },
        PredictionTxOutput {
            value: params.token_value,
            script_version: 0,
            covenant: None,
            script: params.no_token_script.clone(),
        },
        PredictionTxOutput {
            value: continuation_value,
            script_version: 0,
            covenant: None,
            script: sm.p2sh_script.clone(),
        },
    ];

    if change >= MIN_UTXO_VALUE {
        outputs.push(PredictionTxOutput {
            value: change,
            script_version: 0,
            covenant: None,
            script: params.change_script.clone(),
        });
    }

    Ok(PredictionTxBlueprint {
        inputs: vec![
            PredictionTxInput {
                prev_tx_id: sm_tx_id,
                prev_index: sm_index,
                sig_script: sm_sig,
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: params.user_tx_id.clone(),
                prev_index: params.user_index,
                sig_script: params.user_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload,
        lock_time: 0,
        sig_op_counts: vec![0, params.user_sig_op_count],
    })
}

// 4. Merge TX (SplitMerge v2)

/// Parameters for a merge transaction.
#[derive(Debug, Clone)]
pub struct MergeParams {
    /// SplitMerge covenant UTXO.
    pub split_merge: SplitMergeEntry,
    /// YES token UTXO TX ID.
    pub yes_token_tx_id: String,
    /// YES token UTXO index.
    pub yes_token_index: u32,
    /// YES token UTXO value.
    pub yes_token_value: u64,
    /// YES token sigscript.
    pub yes_token_sig_script: Vec<u8>,
    /// YES token sigOpCount.
    pub yes_token_sig_op_count: u8,
    /// NO token UTXO TX ID.
    pub no_token_tx_id: String,
    /// NO token UTXO index.
    pub no_token_index: u32,
    /// NO token UTXO value.
    pub no_token_value: u64,
    /// NO token sigscript.
    pub no_token_sig_script: Vec<u8>,
    /// NO token sigOpCount.
    pub no_token_sig_op_count: u8,
    /// User's KAS output script (receives unit_value KAS).
    pub user_output_script: Vec<u8>,
}

/// Build a merge TX.
///
/// Merge TX:
///   Input[0]: SplitMerge UTXO (pool)
///   Input[1]: YES token UTXO
///   Input[2]: NO token UTXO
///   Output[0]: KAS to user (unit_value)
///   Output[1]: SplitMerge continuation (pool - unit_value)
pub fn build_merge_tx(params: &MergeParams) -> Result<PredictionTxBlueprint, PredictionTxError> {
    let sm = &params.split_merge;

    // Output[0] = unit_value to user
    if sm.unit_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: sm.unit_value,
        });
    }

    // Continuation = pool - unit_value
    let continuation_value = sm.value
        .checked_sub(sm.unit_value)
        .ok_or_else(|| PredictionTxError::InvalidState(
            "pool value less than unit_value".to_string()
        ))?;

    if continuation_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 1,
            value: continuation_value,
        });
    }

    // Total input must cover outputs + fee
    let total_input = sm.value
        .checked_add(params.yes_token_value)
        .and_then(|v| v.checked_add(params.no_token_value))
        .ok_or_else(|| PredictionTxError::Overflow("total inputs".to_string()))?;

    // Mass-based fee estimate: 3 inputs, 2 outputs, no payload
    let estimated_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(3, 2, 0));

    let total_output = sm.unit_value
        .checked_add(continuation_value)
        .and_then(|v| v.checked_add(estimated_fee))
        .ok_or_else(|| PredictionTxError::Overflow("total outputs + fee".to_string()))?;

    if total_input < total_output {
        return Err(PredictionTxError::InsufficientFunds {
            available: total_input,
            required: total_output,
        });
    }

    let sm_sig = kob_core::prediction::build_split_merge_merge_sigscript(&sm.redeem_script);
    let (sm_tx_id, sm_index) = parse_outpoint(&sm.outpoint)?;

    let outputs = vec![
        PredictionTxOutput {
            value: sm.unit_value,
            script_version: 0,
            covenant: None,
            script: params.user_output_script.clone(),
        },
        PredictionTxOutput {
            value: continuation_value,
            script_version: 0,
            covenant: None,
            script: sm.p2sh_script.clone(),
        },
    ];

    Ok(PredictionTxBlueprint {
        inputs: vec![
            PredictionTxInput {
                prev_tx_id: sm_tx_id,
                prev_index: sm_index,
                sig_script: sm_sig,
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: params.yes_token_tx_id.clone(),
                prev_index: params.yes_token_index,
                sig_script: params.yes_token_sig_script.clone(),
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: params.no_token_tx_id.clone(),
                prev_index: params.no_token_index,
                sig_script: params.no_token_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![0, params.yes_token_sig_op_count, params.no_token_sig_op_count],
    })
}

// 5. Settle TX (Redemption v3 redeem path)

/// Parameters for a settlement TX (on-chain winner determination).
#[derive(Debug, Clone)]
pub struct SettleParams {
    /// Redemption covenant UTXO.
    pub redemption: RedemptionEntry,
    /// YES BallotBox UTXO (co-input for value comparison).
    pub yes_box: BallotBoxEntry,
    /// NO BallotBox UTXO (co-input for value comparison).
    pub no_box: BallotBoxEntry,
    /// Winning token UTXO TX ID (must match winning side's token CID).
    pub winning_token_tx_id: String,
    /// Winning token UTXO index.
    pub winning_token_index: u32,
    /// Winning token UTXO value.
    pub winning_token_value: u64,
    /// Winning token sigscript.
    pub winning_token_sig_script: Vec<u8>,
    /// Winning token sigOpCount.
    pub winning_token_sig_op_count: u8,
    /// Payout recipient script.
    pub payout_script: Vec<u8>,
}

/// Build a settlement/redeem TX (v4 architecture with read-only BallotBox witnesses).
///
/// Settlement TX:
///   Input[0]: Redemption UTXO (pool)
///   Input[1]: YES_BallotBox UTXO (read-only, self-continues)
///   Input[2]: NO_BallotBox UTXO (read-only, self-continues)
///   Input[3]: Winning token UTXO (co-input proof)
///   Output[0]: KAS payout to token holder
///   Output[1]: Redemption continuation (pool - payout)
///   Output[2]: YES BallotBox continuation (value preserved)
///   Output[3]: NO BallotBox continuation (value preserved)
///
/// BallotBox UTXOs self-continue with preserved value, so they remain
/// available for unlimited future redemptions (P-F03 fix).
pub fn build_settle_tx(params: &SettleParams) -> Result<PredictionTxBlueprint, PredictionTxError> {
    let r = &params.redemption;

    // P-F11 fix: Verify winning side matches ballot values
    // In decrease model, lower value = more votes = winner
    if params.yes_box.value == params.no_box.value {
        return Err(PredictionTxError::InvalidState(
            "tied ballot values — no winner can be determined".to_string()
        ));
    }
    let actual_winner = if params.yes_box.value < params.no_box.value {
        BallotSide::Yes
    } else {
        BallotSide::No
    };
    if actual_winner != params.redemption.winning_side {
        return Err(PredictionTxError::InvalidState(format!(
            "winning_side mismatch: declared {:?} but ballot values show {:?} \
             (yes_val={}, no_val={})",
            params.redemption.winning_side, actual_winner,
            params.yes_box.value, params.no_box.value
        )));
    }

    // Payout check
    if r.payout_per_token < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: r.payout_per_token,
        });
    }

    // Continuation = pool - payout
    let continuation_value = r.value
        .checked_sub(r.payout_per_token)
        .ok_or_else(|| PredictionTxError::InvalidState(
            "redemption pool less than payout_per_token".to_string()
        ))?;

    if continuation_value < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 1,
            value: continuation_value,
        });
    }

    // Build Redemption v4 redeem sigscript
    let redeem_sig = kob_core::prediction::build_redemption_token_sigscript(&r.redeem_script);

    // Build BallotBox v5 settle sigscripts (read-only witnesses, self-continue)
    let yes_sig = kob_core::prediction::build_ballot_box_settle_sigscript(&params.yes_box.redeem_script);
    let no_sig = kob_core::prediction::build_ballot_box_settle_sigscript(&params.no_box.redeem_script);

    let (r_tx_id, r_index) = parse_outpoint(&r.outpoint)?;
    let (yes_tx_id, yes_index) = parse_outpoint(&params.yes_box.outpoint)?;
    let (no_tx_id, no_index) = parse_outpoint(&params.no_box.outpoint)?;

    let outputs = vec![
        PredictionTxOutput {
            value: r.payout_per_token,
            script_version: 0,
            covenant: None,
            script: params.payout_script.clone(),
        },
        PredictionTxOutput {
            value: continuation_value,
            script_version: 0,
            covenant: None,
            script: r.p2sh_script.clone(),
        },
        // BallotBox continuations (value preserved) — P-F02/P-F03 fix
        PredictionTxOutput {
            value: params.yes_box.value,
            script_version: 0,
            covenant: None,
            script: params.yes_box.p2sh_script.clone(),
        },
        PredictionTxOutput {
            value: params.no_box.value,
            script_version: 0,
            covenant: None,
            script: params.no_box.p2sh_script.clone(),
        },
    ];

    Ok(PredictionTxBlueprint {
        inputs: vec![
            PredictionTxInput {
                prev_tx_id: r_tx_id,
                prev_index: r_index,
                sig_script: redeem_sig,
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: yes_tx_id,
                prev_index: yes_index,
                sig_script: yes_sig,
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: no_tx_id,
                prev_index: no_index,
                sig_script: no_sig,
                sequence: 0,
            },
            PredictionTxInput {
                prev_tx_id: params.winning_token_tx_id.clone(),
                prev_index: params.winning_token_index,
                sig_script: params.winning_token_sig_script.clone(),
                sequence: 0,
            },
        ],
        outputs,
        payload: Vec::new(),
        lock_time: 0,
        sig_op_counts: vec![0, 0, 0, params.winning_token_sig_op_count],
    })
}

// 6. Redeem TX (subsequent payouts from Redemption pool)

/// Parameters for a token redemption TX (subsequent payouts).
#[derive(Debug, Clone)]
pub struct RedeemParams {
    /// Redemption covenant UTXO (continuation from previous redeem/settle).
    pub redemption: RedemptionEntry,
    /// YES BallotBox UTXO (co-input for covenant verification).
    pub yes_box: BallotBoxEntry,
    /// NO BallotBox UTXO (co-input for covenant verification).
    pub no_box: BallotBoxEntry,
    /// Winning token UTXO TX ID.
    pub token_tx_id: String,
    /// Winning token UTXO index.
    pub token_index: u32,
    /// Winning token UTXO value.
    pub token_value: u64,
    /// Winning token sigscript.
    pub token_sig_script: Vec<u8>,
    /// Winning token sigOpCount.
    pub token_sig_op_count: u8,
    /// Payout recipient script.
    pub payout_script: Vec<u8>,
}

/// Build a redeem TX (same structure as settle — BallotBox witnesses self-continue).
///
/// In v4 architecture, every redemption includes BallotBox read-only witnesses.
/// This is identical to settle: the Redemption covenant re-verifies the vote
/// result on-chain each time. BallotBoxes self-continue with preserved value.
pub fn build_redeem_tx(params: &RedeemParams) -> Result<PredictionTxBlueprint, PredictionTxError> {
    build_settle_tx(&SettleParams {
        redemption: params.redemption.clone(),
        yes_box: params.yes_box.clone(),
        no_box: params.no_box.clone(),
        winning_token_tx_id: params.token_tx_id.clone(),
        winning_token_index: params.token_index,
        winning_token_value: params.token_value,
        winning_token_sig_script: params.token_sig_script.clone(),
        winning_token_sig_op_count: params.token_sig_op_count,
        payout_script: params.payout_script.clone(),
    })
}

// 7. Expire BallotBox TX

/// Parameters for expiring a BallotBox (creator reclaims after expiry).
#[derive(Debug, Clone)]
pub struct ExpireBallotParams {
    /// BallotBox to expire.
    pub ballot_box: BallotBoxEntry,
    /// Creator's signature (64 bytes Schnorr).
    pub signature: [u8; 64],
    /// Creator's public key (32 bytes).
    pub pubkey: [u8; 32],
    /// Creator's output script (receives reclaimed funds).
    pub creator_script: Vec<u8>,
    /// Current DAA score (must be >= expiry_daa).
    pub current_daa: u64,
}

/// Build an expire BallotBox TX.
///
///   Input[0]: BallotBox UTXO
///   Output[0]: KAS to creator
pub fn build_expire_ballot_tx(
    params: &ExpireBallotParams,
) -> Result<PredictionTxBlueprint, PredictionTxError> {
    let bb = &params.ballot_box;

    if params.current_daa < bb.expiry_daa {
        return Err(PredictionTxError::InvalidState(format!(
            "not expired: current_daa {} < expiry_daa {}",
            params.current_daa, bb.expiry_daa
        )));
    }

    // Mass-based fee: 1 input, 1 output, no payload
    let estimated_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(1, 1, 0));

    let payout = bb.value.checked_sub(estimated_fee).ok_or_else(|| {
        PredictionTxError::InsufficientFunds {
            available: bb.value,
            required: estimated_fee,
        }
    })?;

    if payout < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: payout,
        });
    }

    let expire_sig = kob_core::prediction::build_ballot_box_expire_sigscript(
        &params.signature,
        &params.pubkey,
        &bb.redeem_script,
    );

    let (bb_tx_id, bb_index) = parse_outpoint(&bb.outpoint)?;

    Ok(PredictionTxBlueprint {
        inputs: vec![PredictionTxInput {
            prev_tx_id: bb_tx_id,
            prev_index: bb_index,
            sig_script: expire_sig,
            sequence: 0,
        }],
        outputs: vec![PredictionTxOutput {
            value: payout,
            script_version: 0,
            covenant: None,
            script: params.creator_script.clone(),
        }],
        payload: Vec::new(),
        lock_time: params.current_daa,
        sig_op_counts: vec![1],
    })
}

// 8. Refund SplitMerge TX

/// Parameters for refunding a SplitMerge pool (creator reclaims after expiry).
#[derive(Debug, Clone)]
pub struct RefundSplitMergeParams {
    /// SplitMerge covenant UTXO.
    pub split_merge: SplitMergeEntry,
    /// Creator's signature (64 bytes Schnorr).
    pub signature: [u8; 64],
    /// Creator's public key (32 bytes).
    pub pubkey: [u8; 32],
    /// Creator's output script.
    pub creator_script: Vec<u8>,
    /// Current DAA score.
    pub current_daa: u64,
}

/// Build a refund SplitMerge TX.
pub fn build_refund_split_merge_tx(
    params: &RefundSplitMergeParams,
) -> Result<PredictionTxBlueprint, PredictionTxError> {
    let sm = &params.split_merge;

    if params.current_daa < sm.expiry_daa {
        return Err(PredictionTxError::InvalidState(format!(
            "not expired: current_daa {} < expiry_daa {}",
            params.current_daa, sm.expiry_daa
        )));
    }

    // Mass-based fee: 1 input, 1 output, no payload
    let estimated_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(1, 1, 0));

    let payout = sm.value.checked_sub(estimated_fee).ok_or_else(|| {
        PredictionTxError::InsufficientFunds {
            available: sm.value,
            required: estimated_fee,
        }
    })?;

    if payout < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: payout,
        });
    }

    let refund_sig = kob_core::prediction::build_split_merge_refund_sigscript(
        &params.signature,
        &params.pubkey,
        &sm.redeem_script,
    );

    let (sm_tx_id, sm_index) = parse_outpoint(&sm.outpoint)?;

    Ok(PredictionTxBlueprint {
        inputs: vec![PredictionTxInput {
            prev_tx_id: sm_tx_id,
            prev_index: sm_index,
            sig_script: refund_sig,
            sequence: 0,
        }],
        outputs: vec![PredictionTxOutput {
            value: payout,
            script_version: 0,
            covenant: None,
            script: params.creator_script.clone(),
        }],
        payload: Vec::new(),
        lock_time: params.current_daa,
        sig_op_counts: vec![1],
    })
}

// 9. Refund Redemption TX

/// Parameters for refunding a Redemption pool (creator reclaims after expiry).
#[derive(Debug, Clone)]
pub struct RefundRedemptionParams {
    /// Redemption covenant UTXO.
    pub redemption: RedemptionEntry,
    /// Creator's signature (64 bytes Schnorr).
    pub signature: [u8; 64],
    /// Creator's public key (32 bytes).
    pub pubkey: [u8; 32],
    /// Creator's output script.
    pub creator_script: Vec<u8>,
    /// Current DAA score (must be >= expiry_daa).
    pub current_daa: u64,
}

/// Build a refund Redemption TX.
pub fn build_refund_redemption_tx(
    params: &RefundRedemptionParams,
) -> Result<PredictionTxBlueprint, PredictionTxError> {
    let r = &params.redemption;

    if params.current_daa < r.expiry_daa {
        return Err(PredictionTxError::InvalidState(format!(
            "not expired: current_daa {} < expiry_daa {}",
            params.current_daa, r.expiry_daa
        )));
    }

    // Mass-based fee: 1 input, 1 output, no payload
    let estimated_fee = kob_core::mass::min_relay_fee(estimate_compute_mass(1, 1, 0));

    let payout = r.value.checked_sub(estimated_fee).ok_or_else(|| {
        PredictionTxError::InsufficientFunds {
            available: r.value,
            required: estimated_fee,
        }
    })?;

    if payout < MIN_UTXO_VALUE {
        return Err(PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: payout,
        });
    }

    let refund_sig = kob_core::prediction::build_redemption_refund_sigscript(
        &params.signature,
        &params.pubkey,
        &r.redeem_script,
    );

    let (r_tx_id, r_index) = parse_outpoint(&r.outpoint)?;

    Ok(PredictionTxBlueprint {
        inputs: vec![PredictionTxInput {
            prev_tx_id: r_tx_id,
            prev_index: r_index,
            sig_script: refund_sig,
            sequence: 0,
        }],
        outputs: vec![PredictionTxOutput {
            value: payout,
            script_version: 0,
            covenant: None,
            script: params.creator_script.clone(),
        }],
        payload: Vec::new(),
        lock_time: params.current_daa,
        sig_op_counts: vec![1],
    })
}

/// Parse an outpoint string "txId:index" into (tx_id, index).
fn parse_outpoint(outpoint: &str) -> Result<(String, u32), PredictionTxError> {
    let parts: Vec<&str> = outpoint.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(PredictionTxError::MissingData(format!(
            "invalid outpoint format: {outpoint}"
        )));
    }
    let index: u32 = parts[1].parse().map_err(|e| {
        PredictionTxError::MissingData(format!("invalid outpoint index: {e}"))
    })?;
    Ok((parts[0].to_string(), index))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ballot_box(side: BallotSide, value: u64) -> BallotBoxEntry {
        let market_id = [0xaa; 32];
        let rs = kob_core::prediction::build_ballot_box_redeem_script(
            &market_id, 100_000, 1000, 50_000, 100_000,
        ).unwrap();
        let p2sh = kob_core::build_p2sh(&rs);
        BallotBoxEntry {
            outpoint: format!("bb_{side}:0"),
            value,
            side,
            redeem_script: rs,
            p2sh_script: p2sh.script().to_vec(),
            reward_per_vote: 100_000,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            initial_value: 100_000_000,
        }
    }

    fn dummy_split_merge() -> SplitMergeEntry {
        let market_id = [0xaa; 32];
        let rs = kob_core::prediction::build_split_merge_redeem_script(
            &market_id,
            &[0xbb; 32],
            &[0xcc; 32],
            &[0xdd; 32],
            100_000_000,
            100_000,
        ).unwrap();
        let p2sh = kob_core::build_p2sh(&rs);
        SplitMergeEntry {
            outpoint: "sm:0".to_string(),
            value: 500_000_000,
            redeem_script: rs,
            p2sh_script: p2sh.script().to_vec(),
            yes_token_cid: [0xbb; 32],
            no_token_cid: [0xcc; 32],
            unit_value: 100_000_000,
            creator_pkh: [0xdd; 32],
            expiry_daa: 100_000,
        }
    }

    fn dummy_redemption(value: u64) -> RedemptionEntry {
        let market_id = [0xaa; 32];
        let rs = kob_core::prediction::build_redemption_redeem_script(
            &market_id,
            &[0x11; 32],
            &[0x33; 32],
            &[0x44; 32],
            100_000_000,
            1001,
            &[0xdd; 32],
            100_000,
            1,             // reward_per_receipt placeholder
            &[0u8; 32],    // yes_receipt_cid placeholder
            &[0u8; 32],    // no_receipt_cid placeholder
        ).unwrap();
        let p2sh = kob_core::build_p2sh(&rs);
        RedemptionEntry {
            outpoint: "redeem:0".to_string(),
            value,
            winning_side: BallotSide::Yes,
            yes_final_value: 80_000_000,
            no_final_value: 90_000_000,
            payout_per_token: 100_000_000,
            redeem_script: rs,
            p2sh_script: p2sh.script().to_vec(),
            expiry_daa: 100_000,
        }
    }

    // --- Parse outpoint ---

    #[test]
    fn parse_outpoint_valid() {
        let (tx_id, index) = parse_outpoint("abc123:2").unwrap();
        assert_eq!(tx_id, "abc123");
        assert_eq!(index, 2);
    }

    #[test]
    fn parse_outpoint_invalid() {
        assert!(parse_outpoint("no_colon").is_err());
    }

    #[test]
    fn parse_outpoint_bad_index() {
        assert!(parse_outpoint("tx:abc").is_err());
    }

    // --- Vote TX ---

    #[test]
    fn build_vote_tx_basic() {
        let bb = dummy_ballot_box(BallotSide::Yes, 50_000_000);
        let other = dummy_ballot_box(BallotSide::No, 80_000_000);
        let params = VoteParams {
            ballot_box: bb,
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "miner_tx".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![0x01],
            miner_sig_op_count: 1,
            miner_change_script: vec![0x02],
            current_daa: 2000,
        };
        let result = build_vote_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.inputs.len(), 3);
        assert_eq!(bp.outputs.len(), 4);
        // Fee == 0: total_in == total_out
        let total_in = 50_000_000u64 + 80_000_000 + 10_000_000;
        let total_out: u64 = bp.outputs.iter().map(|o| o.value).sum();
        assert_eq!(total_in, total_out);
    }

    #[test]
    fn vote_tx_before_start_daa() {
        let bb = dummy_ballot_box(BallotSide::Yes, 50_000_000);
        let other = dummy_ballot_box(BallotSide::No, 80_000_000);
        let params = VoteParams {
            ballot_box: bb,
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "miner_tx".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![],
            miner_sig_op_count: 0,
            miner_change_script: vec![0x02],
            current_daa: 500, // < start_daa=1000
        };
        let result = build_vote_tx(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            PredictionTxError::InvalidState(msg) => assert!(msg.contains("not started")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn vote_tx_after_end_daa() {
        let bb = dummy_ballot_box(BallotSide::Yes, 50_000_000);
        let other = dummy_ballot_box(BallotSide::No, 80_000_000);
        let params = VoteParams {
            ballot_box: bb,
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "miner_tx".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![],
            miner_sig_op_count: 0,
            miner_change_script: vec![0x02],
            current_daa: 60_000, // >= end_daa=50_000
        };
        let result = build_vote_tx(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            PredictionTxError::InvalidState(msg) => assert!(msg.contains("ended")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn vote_tx_rejects_same_side_witness() {
        let bb = dummy_ballot_box(BallotSide::Yes, 50_000_000);
        let other = dummy_ballot_box(BallotSide::Yes, 80_000_000); // wrong: same side
        let params = VoteParams {
            ballot_box: bb,
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "miner_tx".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![],
            miner_sig_op_count: 0,
            miner_change_script: vec![0x02],
            current_daa: 2000,
        };
        let result = build_vote_tx(&params);
        assert!(result.is_err());
    }

    #[test]
    fn vote_tx_box_value_too_low() {
        let bb = dummy_ballot_box(BallotSide::Yes, MIN_UTXO_VALUE + 50_000);
        let other = dummy_ballot_box(BallotSide::No, 80_000_000);
        let params = VoteParams {
            ballot_box: bb,
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "miner_tx".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![],
            miner_sig_op_count: 0,
            miner_change_script: vec![0x02],
            current_daa: 2000,
        };
        let result = build_vote_tx(&params);
        assert!(result.is_err());
    }

    #[test]
    fn vote_tx_output_values_correct() {
        let bb = dummy_ballot_box(BallotSide::No, 80_000_000);
        let other = dummy_ballot_box(BallotSide::Yes, 90_000_000);
        let params = VoteParams {
            ballot_box: bb.clone(),
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "miner_tx".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![],
            miner_sig_op_count: 0,
            miner_change_script: vec![0x02],
            current_daa: 2000,
        };
        let bp = build_vote_tx(&params).unwrap();
        let receipt_floor = kob_core::prediction::RECEIPT_DUST_FLOOR;
        assert_eq!(bp.outputs[0].value, 10_000_000 + 100_000 - receipt_floor); // miner + reward - receipt
        assert_eq!(bp.outputs[1].value, 80_000_000 - 100_000); // voted box - reward
        assert_eq!(bp.outputs[2].value, 90_000_000); // witness box unchanged
        assert_eq!(bp.outputs[3].value, receipt_floor); // receipt
        assert_eq!(bp.outputs[1].covenant, Some((0, [0xee; 32])));
        assert_eq!(bp.outputs[2].covenant, Some((1, [0xee; 32])));
        assert_eq!(bp.outputs[0].covenant, None);
        assert_eq!(bp.outputs[3].covenant, None);
    }

    #[test]
    fn vote_tx_lock_time_set() {
        let bb = dummy_ballot_box(BallotSide::Yes, 50_000_000);
        let other = dummy_ballot_box(BallotSide::No, 80_000_000);
        let params = VoteParams {
            ballot_box: bb,
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "m:0".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![],
            miner_sig_op_count: 0,
            miner_change_script: vec![],
            current_daa: 5000,
        };
        let bp = build_vote_tx(&params).unwrap();
        assert_eq!(bp.lock_time, 5000);
    }

    // --- Split TX ---

    #[test]
    fn build_split_tx_basic() {
        let sm = dummy_split_merge();
        let params = SplitParams {
            split_merge: sm,
            user_tx_id: "user_tx".to_string(),
            user_index: 0,
            user_value: 200_000_000 + kob_core::mass::min_relay_fee(estimate_compute_mass(2, 4, 100)) + MIN_UTXO_VALUE,
            user_sig_script: vec![0x01],
            user_sig_op_count: 1,
            yes_token_script: vec![0xaa],
            no_token_script: vec![0xbb],
            token_value: MIN_UTXO_VALUE,
            change_script: vec![0xcc],
        };
        let result = build_split_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.inputs.len(), 2);
        assert!(bp.outputs.len() >= 3); // yes + no + continuation + maybe change
    }

    #[test]
    fn split_tx_pool_grows() {
        let sm = dummy_split_merge();
        let original_pool = sm.value;
        let unit = sm.unit_value;
        let params = SplitParams {
            split_merge: sm,
            user_tx_id: "user_tx".to_string(),
            user_index: 0,
            user_value: 500_000_000,
            user_sig_script: vec![],
            user_sig_op_count: 0,
            yes_token_script: vec![0xaa],
            no_token_script: vec![0xbb],
            token_value: MIN_UTXO_VALUE,
            change_script: vec![0xcc],
        };
        let bp = build_split_tx(&params).unwrap();
        // Output[2] is continuation
        assert_eq!(bp.outputs[2].value, original_pool + unit);
    }

    #[test]
    fn split_tx_insufficient_funds() {
        let sm = dummy_split_merge();
        let params = SplitParams {
            split_merge: sm,
            user_tx_id: "user_tx".to_string(),
            user_index: 0,
            user_value: 1_000, // too little
            user_sig_script: vec![],
            user_sig_op_count: 0,
            yes_token_script: vec![],
            no_token_script: vec![],
            token_value: MIN_UTXO_VALUE,
            change_script: vec![],
        };
        let result = build_split_tx(&params);
        assert!(result.is_err());
    }

    // --- Merge TX ---

    #[test]
    fn build_merge_tx_basic() {
        let sm = dummy_split_merge();
        let params = MergeParams {
            split_merge: sm,
            yes_token_tx_id: "yes_tok".to_string(),
            yes_token_index: 0,
            yes_token_value: MIN_UTXO_VALUE,
            yes_token_sig_script: vec![],
            yes_token_sig_op_count: 0,
            no_token_tx_id: "no_tok".to_string(),
            no_token_index: 0,
            no_token_value: MIN_UTXO_VALUE,
            no_token_sig_script: vec![],
            no_token_sig_op_count: 0,
            user_output_script: vec![0xaa],
        };
        let result = build_merge_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.inputs.len(), 3);
        assert_eq!(bp.outputs.len(), 2);
        assert_eq!(bp.outputs[0].value, 100_000_000); // unit_value
    }

    #[test]
    fn merge_tx_pool_shrinks() {
        let sm = dummy_split_merge();
        let original_pool = sm.value;
        let unit = sm.unit_value;
        let params = MergeParams {
            split_merge: sm,
            yes_token_tx_id: "yes_tok".to_string(),
            yes_token_index: 0,
            yes_token_value: MIN_UTXO_VALUE,
            yes_token_sig_script: vec![],
            yes_token_sig_op_count: 0,
            no_token_tx_id: "no_tok".to_string(),
            no_token_index: 0,
            no_token_value: MIN_UTXO_VALUE,
            no_token_sig_script: vec![],
            no_token_sig_op_count: 0,
            user_output_script: vec![0xaa],
        };
        let bp = build_merge_tx(&params).unwrap();
        assert_eq!(bp.outputs[1].value, original_pool - unit);
    }

    #[test]
    fn merge_tx_pool_too_small() {
        let mut sm = dummy_split_merge();
        sm.value = 50_000_000; // Less than unit_value (100M)
        let params = MergeParams {
            split_merge: sm,
            yes_token_tx_id: "y".to_string(),
            yes_token_index: 0,
            yes_token_value: MIN_UTXO_VALUE,
            yes_token_sig_script: vec![],
            yes_token_sig_op_count: 0,
            no_token_tx_id: "n".to_string(),
            no_token_index: 0,
            no_token_value: MIN_UTXO_VALUE,
            no_token_sig_script: vec![],
            no_token_sig_op_count: 0,
            user_output_script: vec![],
        };
        assert!(build_merge_tx(&params).is_err());
    }

    // --- Settle TX ---

    #[test]
    fn build_settle_tx_basic() {
        let redemption = dummy_redemption(500_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = SettleParams {
            redemption,
            yes_box,
            no_box,
            winning_token_tx_id: "win_tok".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        let result = build_settle_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.inputs.len(), 4);
        // 4 outputs: payout + redemption continuation + YES bb cont + NO bb cont
        assert_eq!(bp.outputs.len(), 4);
        assert_eq!(bp.outputs[0].value, 100_000_000); // payout_per_token
        // BallotBox continuations preserve value
        assert_eq!(bp.outputs[2].value, 80_000_000); // YES box preserved
        assert_eq!(bp.outputs[3].value, 90_000_000); // NO box preserved
    }

    #[test]
    fn settle_tx_continuation_value() {
        let redemption = dummy_redemption(500_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = SettleParams {
            redemption: redemption.clone(),
            yes_box,
            no_box,
            winning_token_tx_id: "w".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        let bp = build_settle_tx(&params).unwrap();
        assert_eq!(bp.outputs[1].value, 500_000_000 - 100_000_000);
    }

    #[test]
    fn settle_tx_pool_too_small() {
        let redemption = dummy_redemption(50_000_000); // < payout_per_token
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = SettleParams {
            redemption,
            yes_box,
            no_box,
            winning_token_tx_id: "w".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        assert!(build_settle_tx(&params).is_err());
    }

    // --- Redeem TX ---

    #[test]
    fn build_redeem_tx_basic() {
        let redemption = dummy_redemption(400_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = RedeemParams {
            redemption,
            yes_box,
            no_box,
            token_tx_id: "tok".to_string(),
            token_index: 0,
            token_value: MIN_UTXO_VALUE,
            token_sig_script: vec![],
            token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        assert!(build_redeem_tx(&params).is_ok());
    }

    // --- Expire BallotBox TX ---

    #[test]
    fn build_expire_ballot_tx_basic() {
        let bb = dummy_ballot_box(BallotSide::Yes, 10_000_000);
        let params = ExpireBallotParams {
            ballot_box: bb,
            signature: [0x55; 64],
            pubkey: [0x66; 32],
            creator_script: vec![0xaa],
            current_daa: 200_000, // >= expiry_daa=100_000
        };
        let result = build_expire_ballot_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.inputs.len(), 1);
        assert_eq!(bp.outputs.len(), 1);
        assert_eq!(bp.outputs[0].value, 10_000_000 - kob_core::mass::min_relay_fee(estimate_compute_mass(1, 1, 0)));
        assert_eq!(bp.lock_time, 200_000);
        assert_eq!(bp.sig_op_counts[0], 1);
    }

    #[test]
    fn expire_ballot_not_expired() {
        let bb = dummy_ballot_box(BallotSide::Yes, 10_000_000);
        let params = ExpireBallotParams {
            ballot_box: bb,
            signature: [0x55; 64],
            pubkey: [0x66; 32],
            creator_script: vec![],
            current_daa: 50_000, // < expiry_daa=100_000
        };
        assert!(build_expire_ballot_tx(&params).is_err());
    }

    #[test]
    fn expire_ballot_value_too_low() {
        let mut bb = dummy_ballot_box(BallotSide::Yes, estimate_compute_mass(1, 1, 0) + 1000);
        bb.expiry_daa = 1;
        let params = ExpireBallotParams {
            ballot_box: bb,
            signature: [0x55; 64],
            pubkey: [0x66; 32],
            creator_script: vec![],
            current_daa: 200_000,
        };
        assert!(build_expire_ballot_tx(&params).is_err());
    }

    // --- Refund SplitMerge TX ---

    #[test]
    fn build_refund_sm_tx_basic() {
        let sm = dummy_split_merge();
        let params = RefundSplitMergeParams {
            split_merge: sm,
            signature: [0x55; 64],
            pubkey: [0x66; 32],
            creator_script: vec![0xaa],
            current_daa: 200_000,
        };
        let result = build_refund_split_merge_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.outputs[0].value, 500_000_000 - kob_core::mass::min_relay_fee(estimate_compute_mass(1, 1, 0)));
        assert_eq!(bp.lock_time, 200_000);
    }

    #[test]
    fn refund_sm_not_expired() {
        let sm = dummy_split_merge();
        let params = RefundSplitMergeParams {
            split_merge: sm,
            signature: [0x55; 64],
            pubkey: [0x66; 32],
            creator_script: vec![],
            current_daa: 50_000, // < expiry_daa=100_000
        };
        assert!(build_refund_split_merge_tx(&params).is_err());
    }

    // --- Refund Redemption TX ---

    #[test]
    fn build_refund_redemption_tx_basic() {
        let r = dummy_redemption(500_000_000);
        let params = RefundRedemptionParams {
            redemption: r,
            signature: [0x55; 64],
            pubkey: [0x66; 32],
            creator_script: vec![0xaa],
            current_daa: 200_000,
        };
        let result = build_refund_redemption_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.outputs[0].value, 500_000_000 - kob_core::mass::min_relay_fee(estimate_compute_mass(1, 1, 0)));
    }

    #[test]
    fn refund_redemption_not_expired() {
        let r = dummy_redemption(500_000_000);
        let params = RefundRedemptionParams {
            redemption: r,
            signature: [0x55; 64],
            pubkey: [0x66; 32],
            creator_script: vec![],
            current_daa: 50_000,
        };
        assert!(build_refund_redemption_tx(&params).is_err());
    }

    // --- Create Market TX ---

    #[test]
    fn build_create_market_tx_basic() {
        let params = CreateMarketParams {
            market_id: [0xaa; 32],
            creator_pubkey: [0xbb; 32],
            creator_pkh: [0xcc; 32],
            yes_token_cid: [0xdd; 32],
            no_token_cid: [0xee; 32],
            reward_per_vote: 100_000,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            unit_value: 100_000_000,
            payout_per_token: 100_000_000,
            threshold_value: 1001,
            ballot_box_initial_value: 100_000_000,
            split_merge_initial_value: 100_000_000,
            redemption_initial_value: 500_000_000,
            funding_tx_id: "aa".repeat(32),
            funding_index: 0,
            funding_value: 1_000_000_000,
            funding_sig_script: vec![0x01],
            funding_sig_op_count: 1,
            change_script: vec![0x02],
        };
        let result = build_create_market_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.inputs.len(), 1);
        // Step 1: yes_bb + no_bb + sm (no redemption — deployed in step 2)
        assert!(bp.outputs.len() >= 3);
        assert!(bp.outputs.len() <= 4); // + optional change
    }

    #[test]
    fn create_market_insufficient_funds() {
        let params = CreateMarketParams {
            market_id: [0xaa; 32],
            creator_pubkey: [0xbb; 32],
            creator_pkh: [0xcc; 32],
            yes_token_cid: [0xdd; 32],
            no_token_cid: [0xee; 32],
            reward_per_vote: 100_000,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            unit_value: 100_000_000,
            payout_per_token: 100_000_000,
            threshold_value: 1001,
            ballot_box_initial_value: 100_000_000,
            split_merge_initial_value: 100_000_000,
            redemption_initial_value: 500_000_000,
            funding_tx_id: "aa".repeat(32),
            funding_index: 0,
            funding_value: 100_000, // way too little
            funding_sig_script: vec![],
            funding_sig_op_count: 0,
            change_script: vec![],
        };
        assert!(build_create_market_tx(&params).is_err());
    }

    #[test]
    fn create_market_ballot_below_minimum() {
        let params = CreateMarketParams {
            market_id: [0xaa; 32],
            creator_pubkey: [0xbb; 32],
            creator_pkh: [0xcc; 32],
            yes_token_cid: [0xdd; 32],
            no_token_cid: [0xee; 32],
            reward_per_vote: 100_000,
            start_daa: 1000,
            end_daa: 50_000,
            expiry_daa: 100_000,
            unit_value: 100_000_000,
            payout_per_token: 100_000_000,
            threshold_value: 1001,
            ballot_box_initial_value: 1000, // below minimum
            split_merge_initial_value: 100_000_000,
            redemption_initial_value: 500_000_000,
            funding_tx_id: "aa".repeat(32),
            funding_index: 0,
            funding_value: 1_000_000_000,
            funding_sig_script: vec![],
            funding_sig_op_count: 0,
            change_script: vec![],
        };
        assert!(build_create_market_tx(&params).is_err());
    }

    // --- Error Display ---

    #[test]
    fn error_display() {
        let e = PredictionTxError::InsufficientFunds {
            available: 100,
            required: 200,
        };
        assert!(format!("{e}").contains("insufficient"));

        let e = PredictionTxError::OutputBelowMinimum {
            output_idx: 0,
            value: 100,
        };
        assert!(format!("{e}").contains("below minimum"));

        let e = PredictionTxError::Overflow("test".to_string());
        assert!(format!("{e}").contains("overflow"));

        let e = PredictionTxError::MissingData("test".to_string());
        assert!(format!("{e}").contains("missing"));

        let e = PredictionTxError::InvalidState("test".to_string());
        assert!(format!("{e}").contains("invalid state"));
    }

    // --- Sig op counts ---

    #[test]
    fn vote_tx_sig_op_counts() {
        let bb = dummy_ballot_box(BallotSide::Yes, 50_000_000);
        let other = dummy_ballot_box(BallotSide::No, 80_000_000);
        let params = VoteParams {
            ballot_box: bb,
            other_box: other,
            ballot_cid: [0xee; 32],
            miner_tx_id: "m".to_string(),
            miner_index: 0,
            miner_value: 10_000_000,
            miner_sig_script: vec![],
            miner_sig_op_count: 1,
            miner_change_script: vec![],
            current_daa: 2000,
        };
        let bp = build_vote_tx(&params).unwrap();
        assert_eq!(bp.sig_op_counts, vec![0, 0, 1]);
    }

    #[test]
    fn settle_tx_sig_op_counts() {
        let r = dummy_redemption(500_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = SettleParams {
            redemption: r,
            yes_box,
            no_box,
            winning_token_tx_id: "w".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 1,
            payout_script: vec![],
        };
        let bp = build_settle_tx(&params).unwrap();
        assert_eq!(bp.sig_op_counts, vec![0, 0, 0, 1]);
    }

    // --- P-F05: Deploy Redemption (step 2) ---

    #[test]
    fn build_deploy_redemption_tx_basic() {
        let params = DeployRedemptionParams {
            market_id: [0xaa; 32],
            yes_ballot_cid: [0x11; 32],
            no_ballot_cid: [0x22; 32],
            yes_token_cid: [0x33; 32],
            no_token_cid: [0x44; 32],
            payout_per_token: 100_000_000,
            threshold_value: 1001,
            creator_pkh: [0xdd; 32],
            expiry_daa: 100_000,
            redemption_initial_value: 500_000_000,
            funding_tx_id: "fund2".to_string(),
            funding_index: 0,
            funding_value: 600_000_000,
            funding_sig_script: vec![0x01],
            funding_sig_op_count: 1,
            change_script: vec![0x02],
        };
        let result = build_deploy_redemption_tx(&params);
        assert!(result.is_ok());
        let bp = result.unwrap();
        assert_eq!(bp.inputs.len(), 1);
        assert!(bp.outputs.len() >= 1); // redemption + optional change
        assert_eq!(bp.outputs[0].value, 500_000_000);
    }

    #[test]
    fn deploy_redemption_rejects_zero_ballot_cid() {
        let params = DeployRedemptionParams {
            market_id: [0xaa; 32],
            yes_ballot_cid: [0u8; 32], // zero = placeholder
            no_ballot_cid: [0x22; 32],
            yes_token_cid: [0x33; 32],
            no_token_cid: [0x44; 32],
            payout_per_token: 100_000_000,
            threshold_value: 1001,
            creator_pkh: [0xdd; 32],
            expiry_daa: 100_000,
            redemption_initial_value: 500_000_000,
            funding_tx_id: "fund2".to_string(),
            funding_index: 0,
            funding_value: 600_000_000,
            funding_sig_script: vec![],
            funding_sig_op_count: 0,
            change_script: vec![],
        };
        assert!(build_deploy_redemption_tx(&params).is_err());
    }

    #[test]
    fn deploy_redemption_insufficient_funds() {
        let params = DeployRedemptionParams {
            market_id: [0xaa; 32],
            yes_ballot_cid: [0x11; 32],
            no_ballot_cid: [0x22; 32],
            yes_token_cid: [0x33; 32],
            no_token_cid: [0x44; 32],
            payout_per_token: 100_000_000,
            threshold_value: 1001,
            creator_pkh: [0xdd; 32],
            expiry_daa: 100_000,
            redemption_initial_value: 500_000_000,
            funding_tx_id: "fund2".to_string(),
            funding_index: 0,
            funding_value: 1_000, // too little
            funding_sig_script: vec![],
            funding_sig_op_count: 0,
            change_script: vec![],
        };
        assert!(build_deploy_redemption_tx(&params).is_err());
    }

    // --- P-F11: Winning side verification ---

    #[test]
    fn settle_tx_rejects_wrong_winner() {
        let mut redemption = dummy_redemption(500_000_000);
        redemption.winning_side = BallotSide::No; // declared NO
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        // But actual winner is YES (80M < 90M, lower = more votes)
        let params = SettleParams {
            redemption,
            yes_box,
            no_box,
            winning_token_tx_id: "w".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        let result = build_settle_tx(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            PredictionTxError::InvalidState(msg) => assert!(msg.contains("winning_side mismatch")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn settle_tx_rejects_tied_values() {
        let redemption = dummy_redemption(500_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 85_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 85_000_000); // tied
        let params = SettleParams {
            redemption,
            yes_box,
            no_box,
            winning_token_tx_id: "w".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        let result = build_settle_tx(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            PredictionTxError::InvalidState(msg) => assert!(msg.contains("tied")),
            other => panic!("unexpected error: {other}"),
        }
    }

    // --- P-F02/P-F03: BallotBox continuations in settle TX ---

    #[test]
    fn settle_tx_preserves_ballot_box_values() {
        let redemption = dummy_redemption(500_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = SettleParams {
            redemption,
            yes_box: yes_box.clone(),
            no_box: no_box.clone(),
            winning_token_tx_id: "w".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        let bp = build_settle_tx(&params).unwrap();
        // Output[2] = YES BallotBox continuation
        assert_eq!(bp.outputs[2].value, yes_box.value);
        assert_eq!(bp.outputs[2].script, yes_box.p2sh_script);
        // Output[3] = NO BallotBox continuation
        assert_eq!(bp.outputs[3].value, no_box.value);
        assert_eq!(bp.outputs[3].script, no_box.p2sh_script);
    }

    #[test]
    fn settle_tx_uses_v5_settle_sigscript() {
        let redemption = dummy_redemption(500_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = SettleParams {
            redemption,
            yes_box: yes_box.clone(),
            no_box: no_box.clone(),
            winning_token_tx_id: "w".to_string(),
            winning_token_index: 0,
            winning_token_value: MIN_UTXO_VALUE,
            winning_token_sig_script: vec![],
            winning_token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        let bp = build_settle_tx(&params).unwrap();
        // BallotBox sigscripts should use settle selector (OP_2=0x52)
        let yes_expected = kob_core::prediction::build_ballot_box_settle_sigscript(&yes_box.redeem_script);
        assert_eq!(bp.inputs[1].sig_script, yes_expected);
        let no_expected = kob_core::prediction::build_ballot_box_settle_sigscript(&no_box.redeem_script);
        assert_eq!(bp.inputs[2].sig_script, no_expected);
    }

    #[test]
    fn redeem_tx_also_preserves_ballot_boxes() {
        // Verify that build_redeem_tx (subsequent payouts) also includes
        // BallotBox continuations — fixing P-F03.
        let redemption = dummy_redemption(400_000_000);
        let yes_box = dummy_ballot_box(BallotSide::Yes, 80_000_000);
        let no_box = dummy_ballot_box(BallotSide::No, 90_000_000);
        let params = RedeemParams {
            redemption,
            yes_box: yes_box.clone(),
            no_box: no_box.clone(),
            token_tx_id: "tok".to_string(),
            token_index: 0,
            token_value: MIN_UTXO_VALUE,
            token_sig_script: vec![],
            token_sig_op_count: 0,
            payout_script: vec![0xaa],
        };
        let bp = build_redeem_tx(&params).unwrap();
        assert_eq!(bp.outputs.len(), 4);
        assert_eq!(bp.outputs[2].value, yes_box.value);
        assert_eq!(bp.outputs[3].value, no_box.value);
    }
}
