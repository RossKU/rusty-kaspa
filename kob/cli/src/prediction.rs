//! `kob-cli prediction` -- Prediction market lifecycle commands.
//!
//! Subcommands:
//!   create    -- Deploy a new prediction market (2-step: BallotBoxes+SplitMerge, then Redemption)
//!   vote      -- Vote YES or NO on a market (BallotBox self-continuation)
//!   split     -- Split KAS into YES+NO tokens via SplitMerge
//!   merge     -- Merge YES+NO tokens back into KAS via SplitMerge
//!   settle    -- Settle a market (determine winner on-chain via Redemption)
//!   redeem    -- Redeem winning tokens for KAS payout
//!   expire    -- Expire a BallotBox after expiry DAA (creator reclaims)
//!   refund    -- Refund SplitMerge or Redemption pool after expiry (creator reclaims)
//!   markets   -- List known prediction markets

use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::p2sh::{blake2b_256, build_p2sh};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletContext;
use kob_core::mass::estimate_compute_mass;
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

use kob_engine::matcher::prediction_book::{
    BallotBoxEntry, BallotSide, RedemptionEntry, SplitMergeEntry,
};
use kob_engine::matcher::prediction_executor::{
    build_create_market_tx, build_deploy_redemption_tx, build_expire_ballot_tx,
    build_merge_tx, build_redeem_tx, build_refund_redemption_tx,
    build_refund_split_merge_tx, build_settle_tx, build_split_tx, build_vote_tx,
    compute_ballot_cid, CreateMarketParams, DeployRedemptionParams, ExpireBallotParams,
    MergeParams, PredictionTxBlueprint, RedeemParams, RefundRedemptionParams,
    RefundSplitMergeParams, SettleParams, SplitParams, VoteParams,
};

/// SOMPI_PER_KAS: 1 KAS = 100_000_000 sompi.
const SOMPI_PER_KAS: u64 = 100_000_000;

/// Prediction market subcommands.
#[derive(Subcommand, Debug)]
pub enum PredictionCommand {
    /// Create a new prediction market (2-step deployment).
    ///
    /// Step 1: Deploy BallotBox(YES) + BallotBox(NO) + SplitMerge.
    /// Step 2: After step 1 confirms, deploy Redemption with real BallotBox CIDs.
    Create {
        /// Market question (encoded in payload).
        #[arg(long)]
        question: String,

        /// Betting deadline as DAA score offset from current DAA.
        /// Votes accepted from now until current_daa + bet_deadline_daa.
        #[arg(long)]
        bet_deadline_daa: u64,

        /// Vote deadline as DAA score offset from current DAA.
        /// Market expires at current_daa + vote_deadline_daa.
        #[arg(long)]
        vote_deadline_daa: u64,

        /// Unit value in sompi (KAS per token pair for SplitMerge).
        #[arg(long)]
        unit_value: u64,

        /// Reward per vote in sompi (default: 2 = VOTE_COUNTER_UNIT).
        #[arg(long, default_value = "2")]
        reward_per_vote: u64,

        /// Initial BallotBox value in sompi (default: 10 KAS).
        #[arg(long, default_value = "1000000000")]
        ballot_box_value: u64,

        /// Initial SplitMerge pool value in sompi (default: 10 KAS).
        #[arg(long, default_value = "1000000000")]
        split_merge_value: u64,

        /// Initial Redemption pool value in sompi (default: 10 KAS).
        #[arg(long, default_value = "1000000000")]
        redemption_value: u64,

        /// Payout per winning token in sompi. Should be <= unit_value.
        #[arg(long)]
        payout_per_token: u64,
    },

    /// Vote YES or NO on a prediction market.
    ///
    /// Spends from a BallotBox covenant. The box value decreases by reward_per_vote,
    /// and the voter (miner) receives the reward. Fee = 0 (proves miner authorship).
    Vote {
        /// Market ID (hex, 64 chars).
        #[arg(long)]
        market_id: String,

        /// Vote side: "yes" or "no".
        #[arg(long)]
        side: String,

        /// BallotBox outpoint (txid:index).
        #[arg(long)]
        ballot_outpoint: String,

        /// BallotBox current value in sompi.
        #[arg(long)]
        ballot_value: u64,

        /// BallotBox initial value in sompi.
        #[arg(long)]
        ballot_initial_value: u64,

        /// BallotBox redeemScript (hex). Shared by both YES and NO (same
        /// covenant); also used as the OTHER side's redeemScript.
        #[arg(long)]
        ballot_rs: String,

        /// Shared BallotBox covenant ID (hex, 64 chars) -- printed by
        /// `create` step 2 ("BallotBox CID (shared by YES+NO)").
        #[arg(long)]
        ballot_cid: String,

        /// The OTHER side's BallotBox outpoint (txid:index). The deployed
        /// contract requires both BallotBoxes as co-inputs (one voted, one
        /// read-only witness) -- see kob/SECURITY_FIXES.md / E2E_LIVE_RESULTS.md.
        #[arg(long)]
        other_ballot_outpoint: String,

        /// The OTHER side's BallotBox current value in sompi.
        #[arg(long)]
        other_ballot_value: u64,

        /// Reward per vote in sompi.
        #[arg(long, default_value = "2")]
        reward_per_vote: u64,

        /// Start DAA score (voting begins).
        #[arg(long)]
        start_daa: u64,

        /// End DAA score (voting ends).
        #[arg(long)]
        end_daa: u64,

        /// Expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        /// Miner UTXO outpoint (txid:index). Auto-selected if omitted.
        #[arg(long)]
        miner_utxo: Option<String>,
    },

    /// Split KAS into YES + NO tokens via SplitMerge covenant.
    Split {
        /// Market ID (hex, 64 chars).
        #[arg(long)]
        market_id: String,

        /// SplitMerge outpoint (txid:index).
        #[arg(long)]
        sm_outpoint: String,

        /// SplitMerge current value in sompi.
        #[arg(long)]
        sm_value: u64,

        /// SplitMerge redeemScript (hex).
        #[arg(long)]
        sm_rs: String,

        /// Unit value in sompi (KAS per token pair).
        #[arg(long)]
        unit_value: u64,

        /// YES token covenant ID (hex, 64 chars).
        #[arg(long)]
        yes_token_cid: String,

        /// NO token covenant ID (hex, 64 chars).
        #[arg(long)]
        no_token_cid: String,

        /// Creator pubkey hash (hex, 64 chars).
        #[arg(long)]
        creator_pkh: String,

        /// Expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        /// Funding UTXO outpoint (txid:index). Auto-selected if omitted.
        #[arg(long)]
        funding_utxo: Option<String>,
    },

    /// Merge YES + NO tokens back into KAS via SplitMerge.
    Merge {
        /// Market ID (hex, 64 chars).
        #[arg(long)]
        market_id: String,

        /// SplitMerge outpoint (txid:index).
        #[arg(long)]
        sm_outpoint: String,

        /// SplitMerge current value in sompi.
        #[arg(long)]
        sm_value: u64,

        /// SplitMerge redeemScript (hex).
        #[arg(long)]
        sm_rs: String,

        /// Unit value in sompi.
        #[arg(long)]
        unit_value: u64,

        /// YES token covenant ID (hex, 64 chars).
        #[arg(long)]
        yes_token_cid: String,

        /// NO token covenant ID (hex, 64 chars).
        #[arg(long)]
        no_token_cid: String,

        /// Creator pubkey hash (hex, 64 chars).
        #[arg(long)]
        creator_pkh: String,

        /// Expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        /// YES token UTXO outpoint (txid:index).
        #[arg(long)]
        yes_token_outpoint: String,

        /// YES token UTXO value in sompi.
        #[arg(long)]
        yes_token_value: u64,

        /// NO token UTXO outpoint (txid:index).
        #[arg(long)]
        no_token_outpoint: String,

        /// NO token UTXO value in sompi.
        #[arg(long)]
        no_token_value: u64,
    },

    /// Settle a prediction market (determine winner on-chain).
    ///
    /// Requires Redemption + both BallotBox UTXOs + a winning token as co-input.
    /// BallotBoxes self-continue (value preserved). Lower value = more votes = winner.
    Settle {
        /// Market ID (hex, 64 chars).
        #[arg(long)]
        market_id: String,

        /// Redemption outpoint (txid:index).
        #[arg(long)]
        redemption_outpoint: String,

        /// Redemption current value in sompi.
        #[arg(long)]
        redemption_value: u64,

        /// Redemption redeemScript (hex).
        #[arg(long)]
        redemption_rs: String,

        /// Payout per winning token in sompi.
        #[arg(long)]
        payout_per_token: u64,

        /// Expiry DAA score (Redemption).
        #[arg(long)]
        expiry_daa: u64,

        /// YES BallotBox outpoint (txid:index).
        #[arg(long)]
        yes_outpoint: String,

        /// YES BallotBox current value in sompi.
        #[arg(long)]
        yes_value: u64,

        /// YES BallotBox redeemScript (hex).
        #[arg(long)]
        yes_rs: String,

        /// YES BallotBox initial value in sompi.
        #[arg(long)]
        yes_initial_value: u64,

        /// NO BallotBox outpoint (txid:index).
        #[arg(long)]
        no_outpoint: String,

        /// NO BallotBox current value in sompi.
        #[arg(long)]
        no_value: u64,

        /// NO BallotBox redeemScript (hex).
        #[arg(long)]
        no_rs: String,

        /// NO BallotBox initial value in sompi.
        #[arg(long)]
        no_initial_value: u64,

        /// Reward per vote in sompi (for BallotBox entries).
        #[arg(long, default_value = "2")]
        reward_per_vote: u64,

        /// BallotBox start DAA score.
        #[arg(long)]
        start_daa: u64,

        /// BallotBox end DAA score.
        #[arg(long)]
        end_daa: u64,

        /// BallotBox expiry DAA score.
        #[arg(long)]
        ballot_expiry_daa: u64,

        /// Winning token UTXO outpoint (txid:index).
        #[arg(long)]
        token_outpoint: String,

        /// Winning token UTXO value in sompi.
        #[arg(long)]
        token_value: u64,
    },

    /// Redeem winning tokens for KAS payout.
    ///
    /// Same TX structure as settle (BallotBox witnesses self-continue).
    /// Each redemption pays out payout_per_token from the Redemption pool.
    Redeem {
        /// Market ID (hex, 64 chars).
        #[arg(long)]
        market_id: String,

        /// Redemption outpoint (txid:index).
        #[arg(long)]
        redemption_outpoint: String,

        /// Redemption current value in sompi.
        #[arg(long)]
        redemption_value: u64,

        /// Redemption redeemScript (hex).
        #[arg(long)]
        redemption_rs: String,

        /// Payout per winning token in sompi.
        #[arg(long)]
        payout_per_token: u64,

        /// Expiry DAA score (Redemption).
        #[arg(long)]
        expiry_daa: u64,

        /// Winning side: "yes" or "no".
        #[arg(long)]
        winning_side: String,

        /// YES BallotBox final value in sompi.
        #[arg(long)]
        yes_final_value: u64,

        /// NO BallotBox final value in sompi.
        #[arg(long)]
        no_final_value: u64,

        /// YES BallotBox outpoint (txid:index).
        #[arg(long)]
        yes_outpoint: String,

        /// YES BallotBox current value in sompi.
        #[arg(long)]
        yes_value: u64,

        /// YES BallotBox redeemScript (hex).
        #[arg(long)]
        yes_rs: String,

        /// YES BallotBox initial value in sompi.
        #[arg(long)]
        yes_initial_value: u64,

        /// NO BallotBox outpoint (txid:index).
        #[arg(long)]
        no_outpoint: String,

        /// NO BallotBox current value in sompi.
        #[arg(long)]
        no_value: u64,

        /// NO BallotBox redeemScript (hex).
        #[arg(long)]
        no_rs: String,

        /// NO BallotBox initial value in sompi.
        #[arg(long)]
        no_initial_value: u64,

        /// Reward per vote in sompi.
        #[arg(long, default_value = "2")]
        reward_per_vote: u64,

        /// BallotBox start DAA score.
        #[arg(long)]
        start_daa: u64,

        /// BallotBox end DAA score.
        #[arg(long)]
        end_daa: u64,

        /// BallotBox expiry DAA score.
        #[arg(long)]
        ballot_expiry_daa: u64,

        /// Winning token UTXO outpoint (txid:index).
        #[arg(long)]
        token_outpoint: String,

        /// Winning token UTXO value in sompi.
        #[arg(long)]
        token_value: u64,
    },

    /// Expire a BallotBox after expiry DAA score (creator reclaims remaining funds).
    Expire {
        /// BallotBox outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// BallotBox current value in sompi.
        #[arg(long)]
        value: u64,

        /// BallotBox side: "yes" or "no".
        #[arg(long)]
        side: String,

        /// BallotBox redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Reward per vote in sompi.
        #[arg(long, default_value = "2")]
        reward_per_vote: u64,

        /// Start DAA score.
        #[arg(long)]
        start_daa: u64,

        /// End DAA score.
        #[arg(long)]
        end_daa: u64,

        /// Expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        /// Initial value in sompi.
        #[arg(long)]
        initial_value: u64,
    },

    /// Refund SplitMerge or Redemption pool after expiry (creator reclaims).
    Refund {
        /// Covenant type: "splitmerge" or "redemption".
        #[arg(long, name = "type")]
        cov_type: String,

        /// Covenant outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Covenant current value in sompi.
        #[arg(long)]
        value: u64,

        /// Covenant redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Expiry DAA score.
        #[arg(long)]
        expiry_daa: u64,

        // -- SplitMerge-specific fields --

        /// YES token covenant ID (hex, 64 chars). Required for splitmerge.
        #[arg(long)]
        yes_token_cid: Option<String>,

        /// NO token covenant ID (hex, 64 chars). Required for splitmerge.
        #[arg(long)]
        no_token_cid: Option<String>,

        /// Unit value in sompi. Required for splitmerge.
        #[arg(long)]
        unit_value: Option<u64>,

        /// Creator pubkey hash (hex, 64 chars). Required for splitmerge.
        #[arg(long)]
        creator_pkh: Option<String>,

        // -- Redemption-specific fields --

        /// Winning side: "yes" or "no". Required for redemption.
        #[arg(long)]
        winning_side: Option<String>,

        /// YES BallotBox final value in sompi. Required for redemption.
        #[arg(long)]
        yes_final_value: Option<u64>,

        /// NO BallotBox final value in sompi. Required for redemption.
        #[arg(long)]
        no_final_value: Option<u64>,

        /// Payout per winning token in sompi. Required for redemption.
        #[arg(long)]
        payout_per_token: Option<u64>,
    },

    /// List prediction markets (from engine API or local state).
    Markets {
        /// Engine API URL (e.g. http://localhost:8080).
        #[arg(long)]
        engine_url: Option<String>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

// Dispatch

/// Dispatch prediction subcommand.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    _fee: u64,
    cmd: &PredictionCommand,
) -> anyhow::Result<()> {
    match cmd {
        PredictionCommand::Create {
            question,
            bet_deadline_daa,
            vote_deadline_daa,
            unit_value,
            reward_per_vote,
            ballot_box_value,
            split_merge_value,
            redemption_value,
            payout_per_token,
        } => {
            create_market(
                wallet_path,
                node_url,
                network,
                question,
                *bet_deadline_daa,
                *vote_deadline_daa,
                *unit_value,
                *reward_per_vote,
                *ballot_box_value,
                *split_merge_value,
                *redemption_value,
                *payout_per_token,
            )
            .await
        }
        PredictionCommand::Vote {
            market_id,
            side,
            ballot_outpoint,
            ballot_value,
            ballot_initial_value,
            ballot_rs,
            ballot_cid,
            other_ballot_outpoint,
            other_ballot_value,
            reward_per_vote,
            start_daa,
            end_daa,
            expiry_daa,
            miner_utxo,
        } => {
            vote(
                wallet_path,
                node_url,
                network,
                market_id,
                side,
                ballot_outpoint,
                *ballot_value,
                *ballot_initial_value,
                ballot_rs,
                ballot_cid,
                other_ballot_outpoint,
                *other_ballot_value,
                *reward_per_vote,
                *start_daa,
                *end_daa,
                *expiry_daa,
                miner_utxo.as_deref(),
            )
            .await
        }
        PredictionCommand::Split {
            market_id,
            sm_outpoint,
            sm_value,
            sm_rs,
            unit_value,
            yes_token_cid,
            no_token_cid,
            creator_pkh,
            expiry_daa,
            funding_utxo,
        } => {
            split(
                wallet_path,
                node_url,
                network,
                market_id,
                sm_outpoint,
                *sm_value,
                sm_rs,
                *unit_value,
                yes_token_cid,
                no_token_cid,
                creator_pkh,
                *expiry_daa,
                funding_utxo.as_deref(),
            )
            .await
        }
        PredictionCommand::Merge {
            market_id,
            sm_outpoint,
            sm_value,
            sm_rs,
            unit_value,
            yes_token_cid,
            no_token_cid,
            creator_pkh,
            expiry_daa,
            yes_token_outpoint,
            yes_token_value,
            no_token_outpoint,
            no_token_value,
        } => {
            merge(
                wallet_path,
                node_url,
                network,
                market_id,
                sm_outpoint,
                *sm_value,
                sm_rs,
                *unit_value,
                yes_token_cid,
                no_token_cid,
                creator_pkh,
                *expiry_daa,
                yes_token_outpoint,
                *yes_token_value,
                no_token_outpoint,
                *no_token_value,
            )
            .await
        }
        PredictionCommand::Settle {
            market_id,
            redemption_outpoint,
            redemption_value,
            redemption_rs,
            payout_per_token,
            expiry_daa,
            yes_outpoint,
            yes_value,
            yes_rs,
            yes_initial_value,
            no_outpoint,
            no_value,
            no_rs,
            no_initial_value,
            reward_per_vote,
            start_daa,
            end_daa,
            ballot_expiry_daa,
            token_outpoint,
            token_value,
        } => {
            settle(
                wallet_path,
                node_url,
                network,
                market_id,
                redemption_outpoint,
                *redemption_value,
                redemption_rs,
                *payout_per_token,
                *expiry_daa,
                yes_outpoint,
                *yes_value,
                yes_rs,
                *yes_initial_value,
                no_outpoint,
                *no_value,
                no_rs,
                *no_initial_value,
                *reward_per_vote,
                *start_daa,
                *end_daa,
                *ballot_expiry_daa,
                token_outpoint,
                *token_value,
            )
            .await
        }
        PredictionCommand::Redeem {
            market_id,
            redemption_outpoint,
            redemption_value,
            redemption_rs,
            payout_per_token,
            expiry_daa,
            winning_side,
            yes_final_value,
            no_final_value,
            yes_outpoint,
            yes_value,
            yes_rs,
            yes_initial_value,
            no_outpoint,
            no_value,
            no_rs,
            no_initial_value,
            reward_per_vote,
            start_daa,
            end_daa,
            ballot_expiry_daa,
            token_outpoint,
            token_value,
        } => {
            redeem(
                wallet_path,
                node_url,
                network,
                market_id,
                redemption_outpoint,
                *redemption_value,
                redemption_rs,
                *payout_per_token,
                *expiry_daa,
                winning_side,
                *yes_final_value,
                *no_final_value,
                yes_outpoint,
                *yes_value,
                yes_rs,
                *yes_initial_value,
                no_outpoint,
                *no_value,
                no_rs,
                *no_initial_value,
                *reward_per_vote,
                *start_daa,
                *end_daa,
                *ballot_expiry_daa,
                token_outpoint,
                *token_value,
            )
            .await
        }
        PredictionCommand::Expire {
            outpoint,
            value,
            side,
            rs,
            reward_per_vote,
            start_daa,
            end_daa,
            expiry_daa,
            initial_value,
        } => {
            expire_ballot(
                wallet_path,
                node_url,
                network,
                outpoint,
                *value,
                side,
                rs,
                *reward_per_vote,
                *start_daa,
                *end_daa,
                *expiry_daa,
                *initial_value,
            )
            .await
        }
        PredictionCommand::Refund {
            cov_type,
            outpoint,
            value,
            rs,
            expiry_daa,
            yes_token_cid,
            no_token_cid,
            unit_value,
            creator_pkh,
            winning_side,
            yes_final_value,
            no_final_value,
            payout_per_token,
        } => {
            refund_pool(
                wallet_path,
                node_url,
                network,
                cov_type,
                outpoint,
                *value,
                rs,
                *expiry_daa,
                yes_token_cid.as_deref(),
                no_token_cid.as_deref(),
                *unit_value,
                creator_pkh.as_deref(),
                winning_side.as_deref(),
                *yes_final_value,
                *no_final_value,
                *payout_per_token,
            )
            .await
        }
        PredictionCommand::Markets { engine_url, json } => {
            list_markets(engine_url.as_deref(), *json).await
        }
    }
}

/// Parse a hex string to a fixed 32-byte array.
fn parse_hex32(hex_str: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| anyhow::anyhow!("{} is not valid hex: {}", label, e))?;
    if bytes.len() != 32 {
        anyhow::bail!("{} must be 64 hex characters (32 bytes), got {}", label, bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a BallotSide from a string.
fn parse_side(s: &str) -> anyhow::Result<BallotSide> {
    match s.to_lowercase().as_str() {
        "yes" => Ok(BallotSide::Yes),
        "no" => Ok(BallotSide::No),
        other => anyhow::bail!("Unknown side '{}'. Use 'yes' or 'no'.", other),
    }
}

/// Parse an outpoint string "txid:index" into (txid, index).
fn parse_outpoint_parts(s: &str) -> anyhow::Result<(String, u32)> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid outpoint format '{}'. Expected 'txid:index'.", s);
    }
    let tx_id = parts[0].to_string();
    let index: u32 = parts[1].parse()
        .map_err(|e| anyhow::anyhow!("Invalid outpoint index '{}': {}", parts[1], e))?;
    Ok((tx_id, index))
}

/// Build the 36-byte owner SPK: [version_u16_le(2B)] [0x20] [pubkey(32B)] [0xac]
/// Build a standard P2PK scriptPublicKey's SCRIPT bytes (34 bytes: push32 +
/// pubkey + OpCheckSig) for `pubkey`.
///
/// Every call site plugs this into a domain `*TxOutput` alongside its OWN
/// separately-tracked `script_version: 0` field (e.g.
/// `PredictionTxOutput { script_version, script }` in
/// `prediction_executor.rs`), matching the rest of the codebase's convention
/// (version and script bytes are always separate fields -- see e.g.
/// `RpcUtxo::script_bytes()`, which likewise returns script-only with no
/// version prefix). This used to return 36 bytes with an extra leading 2-byte
/// zeroed "version" placeholder baked INTO the script itself, double-counting
/// the version and producing a malformed scriptPublicKey once combined with
/// the output's own `script_version` field. Confirmed live: the node rejected
/// an `expire_ballot` reclaim tx built this way as
/// "non-standard script form" (testnet-10). Every one of this function's 8
/// call sites (vote/split/merge/settle/redeem/expire/refund, all *_script /
/// *_spk locals) shares this exact `script_version: 0` + `script: ...` shape,
/// so fixing the helper fixes all of them uniformly.
fn build_owner_spk(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut spk = vec![0u8; 34];
    spk[0] = 0x20; // push 32 bytes
    spk[1..33].copy_from_slice(pubkey);
    spk[33] = 0xac; // OpCheckSig
    spk
}

/// Convert a PredictionTxBlueprint to a Transaction for signing and submission.
fn blueprint_to_tx(bp: &PredictionTxBlueprint) -> Transaction {
    // `Transaction::new` takes the tx VERSION (always 1 elsewhere in this
    // codebase, for covenant-output/OpTxLockTime support), not the
    // blueprint's `lock_time` (an absolute DAA-score gate value, often in
    // the hundreds of millions on testnet-10). This used to pass
    // `bp.lock_time as u16` straight in as the version, truncating a DAA
    // score into a bogus version number -- confirmed live: the node
    // rejected an `expire_ballot` reclaim tx with "transaction version
    // 32820 is unknown". `lock_time` was never actually applied to the
    // built tx at all.
    let mut tx = Transaction::new(1);
    tx.lock_time = bp.lock_time;
    tx.payload = bp.payload.clone();
    for (i, input) in bp.inputs.iter().enumerate() {
        let soc = bp.sig_op_counts.get(i).copied().unwrap_or(0);
        tx.inputs.push(TxInput {
            prev_tx_id: input.prev_tx_id.clone(),
            prev_index: input.prev_index,
            sequence: input.sequence,
            sig_op_count: soc,
            script_version: 0,
            script_bytes: Vec::new(),
            value: 0,
        });
    }
    for output in &bp.outputs {
        let covenant = output.covenant.map(|(authorizing_input, cid)| {
            CovenantBinding::new(authorizing_input, kob_core::compat::parse_hash(&hex::encode(cid)).expect("32-byte covenant id"))
        });
        tx.outputs.push(TxOutput::new(output.value, output.script_version, output.script.clone(), covenant));
    }
    tx
}

/// Submit a blueprint TX (with a single P2PK funding input that needs signing).
async fn submit_blueprint(
    rpc: &NodeClient,
    bp: &PredictionTxBlueprint,
    funding_input_idx: usize,
    funding_spk: &[u8],
    funding_value: u64,
    privkey: &kob_core::wallet::SecureKey,
) -> anyhow::Result<String> {
    let mut tx = blueprint_to_tx(bp);

    // Fill in the funding input's script and value for sighash computation
    if funding_input_idx < tx.inputs.len() {
        tx.inputs[funding_input_idx].script_bytes = funding_spk.to_vec();
        tx.inputs[funding_input_idx].value = funding_value;
    }

    // Sign the funding input
    let sighash = compute_sighash(&tx, funding_input_idx)?;
    let signature = signing::schnorr_sign_secure(privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    // Build sigscripts array: all from blueprint except the funding input
    let mut sigscripts: Vec<Vec<u8>> = bp.inputs.iter().map(|i| i.sig_script.clone()).collect();
    sigscripts[funding_input_idx] = sigscript;
    let payload = to_rpc_payload(&tx, &sigscripts);
    rpc.submit_transaction(payload).await
}

/// Format sompi as "X sompi (Y.ZZZZZZZZ KAS)".
fn fmt_sompi(v: u64) -> String {
    format!("{} sompi ({:.8} KAS)", v, v as f64 / SOMPI_PER_KAS as f64)
}

// 1. Create Market

#[allow(clippy::too_many_arguments)]
#[allow(deprecated)]
async fn create_market(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    question: &str,
    bet_deadline_daa: u64,
    vote_deadline_daa: u64,
    unit_value: u64,
    reward_per_vote: u64,
    ballot_box_value: u64,
    split_merge_value: u64,
    redemption_value: u64,
    payout_per_token: u64,
) -> anyhow::Result<()> {
    if unit_value < MIN_UTXO_VALUE {
        anyhow::bail!("unit_value {} < MIN_UTXO_VALUE {}", unit_value, MIN_UTXO_VALUE);
    }
    if payout_per_token < MIN_UTXO_VALUE {
        anyhow::bail!("payout_per_token {} < MIN_UTXO_VALUE {}", payout_per_token, MIN_UTXO_VALUE);
    }
    if payout_per_token > unit_value {
        anyhow::bail!("payout_per_token {} > unit_value {} (creator spread would be negative)", payout_per_token, unit_value);
    }

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();
    let creator_pkh = blake2b_256(&pubkey);

    // Connect and get current DAA
    info!("connecting to {}", node_url);
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;
    let current_daa = rpc.get_daa_score().await?;

    let start_daa = current_daa;
    let end_daa = current_daa + bet_deadline_daa;
    let expiry_daa = current_daa + vote_deadline_daa;

    if end_daa >= expiry_daa {
        anyhow::bail!(
            "bet_deadline_daa ({}) must be < vote_deadline_daa ({})",
            bet_deadline_daa, vote_deadline_daa
        );
    }

    // Compute market_id = Blake2b-256( question || start_daa || end_daa || creator_pkh )
    let mut market_preimage = Vec::new();
    market_preimage.extend_from_slice(question.as_bytes());
    market_preimage.extend_from_slice(&start_daa.to_le_bytes());
    market_preimage.extend_from_slice(&end_daa.to_le_bytes());
    market_preimage.extend_from_slice(&creator_pkh);
    let market_id = blake2b_256(&market_preimage);

    // Derive YES/NO token CIDs from market_id + side indicator
    let mut yes_preimage = market_id.to_vec();
    yes_preimage.push(0x01); // YES marker
    let yes_token_cid = blake2b_256(&yes_preimage);

    let mut no_preimage = market_id.to_vec();
    no_preimage.push(0x00); // NO marker
    let no_token_cid = blake2b_256(&no_preimage);

    println!();
    println!("Create Prediction Market");
    println!("========================");
    println!("Question:        {}", question);
    println!("Market ID:       {}", hex::encode(market_id));
    println!("Creator PKH:     {}", hex::encode(creator_pkh));
    println!("Current DAA:     {}", current_daa);
    println!("Start DAA:       {} (now)", start_daa);
    println!("End DAA:         {} (+{})", end_daa, bet_deadline_daa);
    println!("Expiry DAA:      {} (+{})", expiry_daa, vote_deadline_daa);
    println!("Unit value:      {}", fmt_sompi(unit_value));
    println!("Payout/token:    {}", fmt_sompi(payout_per_token));
    println!("Reward/vote:     {} sompi", reward_per_vote);
    println!("YES token CID:   {}", hex::encode(yes_token_cid));
    println!("NO token CID:    {}", hex::encode(no_token_cid));
    println!();

    println!("Step 1: Deploying BallotBoxes + SplitMerge...");

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    // Estimate fee: 1-in, ~4-out TX (2 BallotBoxes + SplitMerge + change)
    let step1_est_fee = estimate_compute_mass(1, 4, 0);
    let step1_total = ballot_box_value
        .checked_mul(2).ok_or_else(|| anyhow::anyhow!("overflow"))?
        .checked_add(split_merge_value).ok_or_else(|| anyhow::anyhow!("overflow"))?
        .checked_add(step1_est_fee).ok_or_else(|| anyhow::anyhow!("overflow"))?;

    let funding = utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= step1_total)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for step 1 ({} UTXOs available)",
                step1_total,
                utxos.len()
            )
        })?;

    println!("  Funding UTXO: {}:{} ({})", funding.outpoint.transaction_id, funding.outpoint.index, fmt_sompi(funding.utxo_entry.amount));

    let funding_spk = funding.script_bytes();
    let change_script = hex::decode(&funding.utxo_entry.script_public_key.script)?;

    let params = CreateMarketParams {
        market_id,
        creator_pubkey: pubkey,
        creator_pkh,
        yes_token_cid,
        no_token_cid,
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa,
        unit_value,
        payout_per_token,
        threshold_value: 4096, // DISPUTE_THRESHOLD(1024) * VOTE_COUNTER_UNIT(2) * 2
        ballot_box_initial_value: ballot_box_value,
        split_merge_initial_value: split_merge_value,
        redemption_initial_value: redemption_value,
        funding_tx_id: funding.outpoint.transaction_id.clone(),
        funding_index: funding.outpoint.index,
        funding_value: funding.utxo_entry.amount,
        funding_sig_script: Vec::new(), // filled during submission
        funding_sig_op_count: 1,
        change_script: change_script.clone(),
    };

    let bp = build_create_market_tx(&params)
        .map_err(|e| anyhow::anyhow!("build_create_market_tx failed: {}", e))?;

    let tx_id = submit_blueprint(&rpc, &bp, 0, &funding_spk, funding.utxo_entry.amount, &privkey).await?;

    println!();
    println!("  Step 1 SUCCESS!");
    println!("  TXID: {}", tx_id);
    println!("  YES BallotBox: {}:0 ({})", tx_id, fmt_sompi(ballot_box_value));
    println!("  NO BallotBox:  {}:1 ({})", tx_id, fmt_sompi(ballot_box_value));
    println!("  SplitMerge:    {}:2 ({})", tx_id, fmt_sompi(split_merge_value));
    println!();

    // Derive BallotBox covenant IDs from step 1 outputs
    let yes_ballot_rs = kob_core::prediction::build_ballot_box_redeem_script(
        &market_id,
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa,
    )?;
    let no_ballot_rs = kob_core::prediction::build_ballot_box_redeem_script(
        &market_id,
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa,
    )?;
    let yes_ballot_p2sh = build_p2sh(&yes_ballot_rs);
    let no_ballot_p2sh = build_p2sh(&no_ballot_rs);
    // YES and NO BallotBox are ONE covenant (identical redeemScript, shared
    // wire-level covenant id) authorized together by step 1's single funding
    // input -- NOT `blake2b(p2sh_script)` (that's the P2SH SPK hash, a
    // different value the engine never reads for OpInputCovenantId/
    // OpCovInputCount/OpCovOutputCount). See `compute_ballot_cid`.
    let ballot_cid = compute_ballot_cid(
        &funding.outpoint.transaction_id,
        funding.outpoint.index,
        yes_ballot_p2sh.script(),
        no_ballot_p2sh.script(),
        ballot_box_value,
    ).map_err(|e| anyhow::anyhow!("compute_ballot_cid failed: {}", e))?;
    let (yes_ballot_cid, no_ballot_cid) = (ballot_cid, ballot_cid);

    println!("Step 2: Deploying Redemption with real BallotBox CID...");
    println!("  BallotBox CID (shared by YES+NO): {}", hex::encode(ballot_cid));

    // Verify step 1 outputs exist in the UTXO set before proceeding.
    // Query the P2SH address of the YES BallotBox (output 0) as confirmation.
    let yes_p2sh_addr = crate::cancel::p2sh_to_address(&yes_ballot_p2sh.script(), network.address_prefix());
    println!("  Verifying step 1 confirmation (polling up to 30s)...");
    let mut step1_confirmed = false;
    for attempt in 1..=10 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        match rpc.get_utxos_by_addresses(&[&yes_p2sh_addr]).await {
            Ok(utxos) => {
                if utxos.iter().any(|u| u.outpoint.transaction_id == tx_id && u.outpoint.index == 0) {
                    println!("  Step 1 confirmed (attempt {}/10).", attempt);
                    step1_confirmed = true;
                    break;
                }
            }
            Err(e) => {
                info!("Step 1 UTXO query attempt {}/10 failed: {}", attempt, e);
            }
        }
        if attempt < 10 {
            println!("  Waiting... (attempt {}/10)", attempt);
        }
    }
    if !step1_confirmed {
        anyhow::bail!(
            "Step 1 TX {} not confirmed after 30s. The TX may have been orphaned or rejected. \
             Do NOT proceed — verify the TX status on a block explorer and retry if needed.",
            tx_id
        );
    }

    let utxos2 = rpc.get_spendable_utxos(&wallet.address).await?;
    // Estimate fee: 1-in, ~2-out TX (Redemption + change)
    let step2_est_fee = estimate_compute_mass(1, 2, 0);
    let step2_total = redemption_value
        .checked_add(step2_est_fee).ok_or_else(|| anyhow::anyhow!("overflow"))?;

    let funding2 = utxos2
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= step2_total)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for step 2. Step 1 change may not be confirmed yet. \
                 Re-run step 2 manually after confirmation.",
                step2_total,
            )
        })?;

    println!("  Funding UTXO: {}:{} ({})", funding2.outpoint.transaction_id, funding2.outpoint.index, fmt_sompi(funding2.utxo_entry.amount));

    let funding2_spk = funding2.script_bytes();
    let change_script2 = hex::decode(&funding2.utxo_entry.script_public_key.script)?;

    let redemption_params = DeployRedemptionParams {
        market_id,
        yes_ballot_cid,
        no_ballot_cid,
        yes_token_cid,
        no_token_cid,
        payout_per_token,
        threshold_value: 4096, // DISPUTE_THRESHOLD(1024) * VOTE_COUNTER_UNIT(2) * 2
        creator_pkh,
        expiry_daa,
        redemption_initial_value: redemption_value,
        funding_tx_id: funding2.outpoint.transaction_id.clone(),
        funding_index: funding2.outpoint.index,
        funding_value: funding2.utxo_entry.amount,
        funding_sig_script: Vec::new(),
        funding_sig_op_count: 1,
        change_script: change_script2,
    };

    let bp2 = build_deploy_redemption_tx(&redemption_params)
        .map_err(|e| anyhow::anyhow!("build_deploy_redemption_tx failed: {}", e))?;

    let tx_id2 = submit_blueprint(&rpc, &bp2, 0, &funding2_spk, funding2.utxo_entry.amount, &privkey).await?;

    println!();
    println!("  Step 2 SUCCESS!");
    println!("  TXID: {}", tx_id2);
    println!("  Redemption: {}:0 ({})", tx_id2, fmt_sompi(redemption_value));
    println!();
    println!("Market fully deployed!");
    println!("======================");
    println!("Market ID:       {}", hex::encode(market_id));
    println!("YES BallotBox:   {}:0", tx_id);
    println!("NO BallotBox:    {}:1", tx_id);
    println!("SplitMerge:      {}:2", tx_id);
    println!("Redemption:      {}:0", tx_id2);
    println!("YES token CID:   {}", hex::encode(yes_token_cid));
    println!("NO token CID:    {}", hex::encode(no_token_cid));
    println!("BallotBox CID:   {}", hex::encode(ballot_cid));
    println!("BallotBox RS:    {}", hex::encode(&yes_ballot_rs));
    // Reconstruct the SplitMerge + Redemption redeemScripts so the `refund`
    // command (which needs `--rs`) has a source for them -- they are built
    // inside the domain layer and were otherwise never surfaced.
    let sm_rs = kob_core::prediction::build_split_merge_redeem_script(
        &market_id, &yes_token_cid, &no_token_cid, &creator_pkh, unit_value, expiry_daa,
    )?;
    // Same placeholders build_deploy_redemption_tx uses (threshold 4096,
    // reward_per_receipt 1, receipt CIDs zero).
    let redemption_rs = kob_core::prediction::build_redemption_redeem_script(
        &market_id, &ballot_cid, &yes_token_cid, &no_token_cid,
        payout_per_token, 4096, &creator_pkh, expiry_daa, 1, &[0u8; 32], &[0u8; 32],
    )?;
    println!("SplitMerge RS:   {}", hex::encode(&sm_rs));
    println!("Redemption RS:   {}", hex::encode(&redemption_rs));

    Ok(())
}

// 2. Vote

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn vote(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    market_id: &str,
    side: &str,
    ballot_outpoint: &str,
    ballot_value: u64,
    ballot_initial_value: u64,
    ballot_rs_hex: &str,
    ballot_cid_hex: &str,
    other_ballot_outpoint: &str,
    other_ballot_value: u64,
    reward_per_vote: u64,
    start_daa: u64,
    end_daa: u64,
    expiry_daa: u64,
    miner_utxo_str: Option<&str>,
) -> anyhow::Result<()> {
    let _side = parse_side(side)?;
    let other_side = match _side {
        BallotSide::Yes => BallotSide::No,
        BallotSide::No => BallotSide::Yes,
    };
    let ballot_cid = parse_hex32(ballot_cid_hex, "ballot_cid")?;
    let redeem_script = hex::decode(ballot_rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;
    let current_daa = rpc.get_daa_score().await?;

    // Validate voting window
    if current_daa < start_daa {
        anyhow::bail!(
            "Voting has not started yet. Current DAA {} < start DAA {}. Wait {} more DAA scores.",
            current_daa, start_daa, start_daa - current_daa
        );
    }
    if current_daa >= end_daa {
        anyhow::bail!(
            "Voting period has ended. Current DAA {} >= end DAA {}. The ballot box is closed.",
            current_daa, end_daa
        );
    }

    // Select miner UTXO
    let (miner_tx_id, miner_index, miner_value, miner_spk) = if let Some(mo) = miner_utxo_str {
        let (tx_id, idx) = parse_outpoint_parts(mo)?;
        let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
        let u = utxos.iter()
            .find(|u| u.outpoint.transaction_id == tx_id && u.outpoint.index == idx)
            .ok_or_else(|| anyhow::anyhow!("Miner UTXO {} not found", mo))?;
        (tx_id, idx, u.utxo_entry.amount, u.script_bytes())
    } else {
        let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
        let u = utxos.iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= MIN_UTXO_VALUE)
            .ok_or_else(|| anyhow::anyhow!("No P2PK UTXO >= {} sompi for miner input", MIN_UTXO_VALUE))?;
        (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount, u.script_bytes())
    };

    let miner_change_script = build_owner_spk(&pubkey);

    // Both BallotBoxes share the SAME redeemScript/P2SH (one covenant,
    // distinguished only by outpoint/value) -- see `compute_ballot_cid`.
    let bb_entry = BallotBoxEntry {
        outpoint: ballot_outpoint.to_string(),
        value: ballot_value,
        side: _side,
        redeem_script: redeem_script.clone(),
        p2sh_script: p2sh.script().to_vec(),
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa,
        initial_value: ballot_initial_value,
    };
    let other_entry = BallotBoxEntry {
        outpoint: other_ballot_outpoint.to_string(),
        value: other_ballot_value,
        side: other_side,
        redeem_script: redeem_script.clone(),
        p2sh_script: p2sh.script().to_vec(),
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa,
        initial_value: ballot_initial_value,
    };

    let params = VoteParams {
        ballot_box: bb_entry,
        other_box: other_entry,
        ballot_cid,
        miner_tx_id: miner_tx_id.clone(),
        miner_index,
        miner_value,
        miner_sig_script: Vec::new(),
        miner_sig_op_count: 1,
        miner_change_script: miner_change_script.clone(),
        current_daa,
    };

    println!();
    println!("Vote on Prediction Market");
    println!("=========================");
    println!("Market ID:    {}", market_id);
    println!("Side:         {}", _side);
    println!("BallotBox:    {}", ballot_outpoint);
    println!("Box value:    {}", fmt_sompi(ballot_value));
    println!("Other side:   {} ({})", other_ballot_outpoint, fmt_sompi(other_ballot_value));
    println!("Reward:       {} sompi", reward_per_vote);
    println!("Current DAA:  {}", current_daa);
    println!("Miner UTXO:   {}:{} ({})", miner_tx_id, miner_index, fmt_sompi(miner_value));
    println!();

    let bp = build_vote_tx(&params)
        .map_err(|e| anyhow::anyhow!("build_vote_tx failed: {}", e))?;

    // Vote TX: input[0] = voted BallotBox, input[1] = other BallotBox
    // (read-only witness), input[2] = miner (needs P2PK sig). Outputs:
    // [0] miner change, [1] voted box continuation, [2] other box
    // continuation, [3] VoteReceipt.
    let tx_id = submit_blueprint(&rpc, &bp, 2, &miner_spk, miner_value, &privkey).await?;

    println!("SUCCESS! Vote submitted.");
    println!("TXID:         {}", tx_id);
    println!("New box:      {}:1 ({})", tx_id, fmt_sompi(ballot_value - reward_per_vote));
    println!("Other box:    {}:2 ({})", tx_id, fmt_sompi(other_ballot_value));
    println!("VoteReceipt:  {}:3", tx_id);
    println!("Reward:       {} sompi -> miner (net of the receipt's dust-floor cost)", reward_per_vote);

    Ok(())
}

// 3. Split

#[allow(clippy::too_many_arguments)]
async fn split(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    market_id: &str,
    sm_outpoint: &str,
    sm_value: u64,
    sm_rs_hex: &str,
    unit_value: u64,
    yes_token_cid_hex: &str,
    no_token_cid_hex: &str,
    creator_pkh_hex: &str,
    expiry_daa: u64,
    funding_utxo_str: Option<&str>,
) -> anyhow::Result<()> {
    let yes_token_cid = parse_hex32(yes_token_cid_hex, "yes_token_cid")?;
    let no_token_cid = parse_hex32(no_token_cid_hex, "no_token_cid")?;
    let creator_pkh = parse_hex32(creator_pkh_hex, "creator_pkh")?;
    let redeem_script = hex::decode(sm_rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Token output scripts (P2PK to wallet)
    let wallet_spk = build_owner_spk(&pubkey);
    let token_value = unit_value;

    let sm_entry = SplitMergeEntry {
        outpoint: sm_outpoint.to_string(),
        value: sm_value,
        redeem_script: redeem_script.clone(),
        p2sh_script: p2sh.script().to_vec(),
        yes_token_cid,
        no_token_cid,
        unit_value,
        creator_pkh,
        expiry_daa,
    };

    // Find funding UTXO
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    // Split TX deposits unit_value into the pool, plus miner fee, plus dust margin.
    // Estimate fee: 2-in (SM + funding), ~4-out TX (yes_token + no_token + continuation + change)
    let split_est_fee = estimate_compute_mass(2, 4, 0);
    let needed = unit_value
        .checked_add(split_est_fee).ok_or_else(|| anyhow::anyhow!("overflow"))?
        .checked_add(MIN_UTXO_VALUE).ok_or_else(|| anyhow::anyhow!("overflow"))?;

    let (user_tx_id, user_index, user_value, user_spk) = if let Some(fo) = funding_utxo_str {
        let (tx_id, idx) = parse_outpoint_parts(fo)?;
        let u = utxos.iter()
            .find(|u| u.outpoint.transaction_id == tx_id && u.outpoint.index == idx)
            .ok_or_else(|| anyhow::anyhow!("Funding UTXO {} not found", fo))?;
        (tx_id, idx, u.utxo_entry.amount, u.script_bytes())
    } else {
        let u = utxos.iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= needed)
            .ok_or_else(|| anyhow::anyhow!("No P2PK UTXO >= {} sompi for split", needed))?;
        (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount, u.script_bytes())
    };

    let params = SplitParams {
        split_merge: sm_entry,
        user_tx_id: user_tx_id.clone(),
        user_index,
        user_value,
        user_sig_script: Vec::new(),
        user_sig_op_count: 1,
        yes_token_script: wallet_spk.clone(),
        no_token_script: wallet_spk.clone(),
        token_value,
        change_script: wallet_spk.clone(),
    };

    println!();
    println!("Split KAS -> YES + NO tokens");
    println!("============================");
    println!("Market ID:    {}", market_id);
    println!("SplitMerge:   {}", sm_outpoint);
    println!("Token value:  {}", fmt_sompi(token_value));
    println!("User UTXO:    {}:{} ({})", user_tx_id, user_index, fmt_sompi(user_value));
    println!();

    let bp = build_split_tx(&params)
        .map_err(|e| anyhow::anyhow!("build_split_tx failed: {}", e))?;

    // Split TX: input[0] = SplitMerge (covenant), input[1] = user (needs P2PK sig)
    let tx_id = submit_blueprint(&rpc, &bp, 1, &user_spk, user_value, &privkey).await?;

    println!("SUCCESS! Split completed.");
    println!("TXID:        {}", tx_id);
    println!("YES token:   {}:0 ({})", tx_id, fmt_sompi(token_value));
    println!("NO token:    {}:1 ({})", tx_id, fmt_sompi(token_value));
    println!("SplitMerge:  {}:2 (continuation)", tx_id);

    Ok(())
}

// 4. Merge

#[allow(clippy::too_many_arguments)]
async fn merge(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    market_id: &str,
    sm_outpoint: &str,
    sm_value: u64,
    sm_rs_hex: &str,
    unit_value: u64,
    yes_token_cid_hex: &str,
    no_token_cid_hex: &str,
    creator_pkh_hex: &str,
    expiry_daa: u64,
    yes_token_outpoint: &str,
    yes_token_value: u64,
    no_token_outpoint: &str,
    no_token_value: u64,
) -> anyhow::Result<()> {
    let yes_token_cid = parse_hex32(yes_token_cid_hex, "yes_token_cid")?;
    let no_token_cid = parse_hex32(no_token_cid_hex, "no_token_cid")?;
    let creator_pkh = parse_hex32(creator_pkh_hex, "creator_pkh")?;
    let redeem_script = hex::decode(sm_rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let wallet_spk = build_owner_spk(&pubkey);

    let sm_entry = SplitMergeEntry {
        outpoint: sm_outpoint.to_string(),
        value: sm_value,
        redeem_script: redeem_script.clone(),
        p2sh_script: p2sh.script().to_vec(),
        yes_token_cid,
        no_token_cid,
        unit_value,
        creator_pkh,
        expiry_daa,
    };

    let (yes_tx_id, yes_idx) = parse_outpoint_parts(yes_token_outpoint)?;
    let (no_tx_id, no_idx) = parse_outpoint_parts(no_token_outpoint)?;

    let params = MergeParams {
        split_merge: sm_entry,
        yes_token_tx_id: yes_tx_id.clone(),
        yes_token_index: yes_idx,
        yes_token_value,
        yes_token_sig_script: Vec::new(),
        yes_token_sig_op_count: 1,
        no_token_tx_id: no_tx_id.clone(),
        no_token_index: no_idx,
        no_token_value,
        no_token_sig_script: Vec::new(),
        no_token_sig_op_count: 1,
        user_output_script: wallet_spk.clone(),
    };

    println!();
    println!("Merge YES + NO tokens -> KAS");
    println!("============================");
    println!("Market ID:    {}", market_id);
    println!("SplitMerge:   {}", sm_outpoint);
    println!("YES token:    {} ({})", yes_token_outpoint, fmt_sompi(yes_token_value));
    println!("NO token:     {} ({})", no_token_outpoint, fmt_sompi(no_token_value));
    println!("Payout:       {}", fmt_sompi(unit_value));
    println!();

    let bp = build_merge_tx(&params)
        .map_err(|e| anyhow::anyhow!("build_merge_tx failed: {}", e))?;

    // Merge TX: input[0] = SplitMerge (covenant), input[1] = YES token, input[2] = NO token
    // Sign inputs 1 and 2 (both user-owned token UTXOs).
    let mut tx = blueprint_to_tx(&bp);

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    let yes_utxo = utxos.iter()
        .find(|u| u.outpoint.transaction_id == yes_tx_id && u.outpoint.index == yes_idx)
        .ok_or_else(|| anyhow::anyhow!("YES token UTXO {} not found in wallet UTXOs", yes_token_outpoint))?;
    let yes_spk = yes_utxo.script_bytes();

    let no_utxo = utxos.iter()
        .find(|u| u.outpoint.transaction_id == no_tx_id && u.outpoint.index == no_idx)
        .ok_or_else(|| anyhow::anyhow!("NO token UTXO {} not found in wallet UTXOs", no_token_outpoint))?;
    let no_spk = no_utxo.script_bytes();

    tx.inputs[1].script_bytes = yes_spk;
    tx.inputs[1].value = yes_token_value;
    tx.inputs[2].script_bytes = no_spk;
    tx.inputs[2].value = no_token_value;

    let sighash1 = compute_sighash(&tx, 1)?;
    let sig1 = signing::schnorr_sign_secure(&privkey, &sighash1)?;
    let ss1 = signing::build_p2pk_sigscript(&sig1);

    let sighash2 = compute_sighash(&tx, 2)?;
    let sig2 = signing::schnorr_sign_secure(&privkey, &sighash2)?;
    let ss2 = signing::build_p2pk_sigscript(&sig2);

    let sigscripts: Vec<Vec<u8>> = vec![
        bp.inputs[0].sig_script.clone(), // SplitMerge covenant sigscript
        ss1,
        ss2,
    ];
    let payload = to_rpc_payload(&tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    println!("SUCCESS! Merge completed.");
    println!("TXID:        {}", tx_id);
    println!("KAS payout:  {}:0 ({})", tx_id, fmt_sompi(unit_value));
    println!("SplitMerge:  {}:1 (continuation)", tx_id);

    Ok(())
}

// 5. Settle

#[allow(clippy::too_many_arguments)]
async fn settle(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    market_id: &str,
    redemption_outpoint: &str,
    redemption_value: u64,
    redemption_rs_hex: &str,
    payout_per_token: u64,
    expiry_daa: u64,
    yes_outpoint: &str,
    yes_value: u64,
    yes_rs_hex: &str,
    yes_initial_value: u64,
    no_outpoint: &str,
    no_value: u64,
    no_rs_hex: &str,
    no_initial_value: u64,
    reward_per_vote: u64,
    start_daa: u64,
    end_daa: u64,
    ballot_expiry_daa: u64,
    token_outpoint: &str,
    token_value: u64,
) -> anyhow::Result<()> {
    let redemption_rs = hex::decode(redemption_rs_hex)?;
    let redemption_p2sh = build_p2sh(&redemption_rs);
    let yes_rs = hex::decode(yes_rs_hex)?;
    let yes_p2sh = build_p2sh(&yes_rs);
    let no_rs = hex::decode(no_rs_hex)?;
    let no_p2sh = build_p2sh(&no_rs);

    // Determine winner: lower value = more votes = winner
    let winning_side = if yes_value < no_value {
        BallotSide::Yes
    } else if no_value < yes_value {
        BallotSide::No
    } else {
        anyhow::bail!("Tied ballot values ({} == {}) -- no winner can be determined", yes_value, no_value);
    };

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();
    let wallet_spk = build_owner_spk(&pubkey);

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let r_entry = RedemptionEntry {
        outpoint: redemption_outpoint.to_string(),
        value: redemption_value,
        winning_side,
        yes_final_value: yes_value,
        no_final_value: no_value,
        payout_per_token,
        redeem_script: redemption_rs.clone(),
        p2sh_script: redemption_p2sh.script().to_vec(),
        expiry_daa,
    };

    let yes_entry = BallotBoxEntry {
        outpoint: yes_outpoint.to_string(),
        value: yes_value,
        side: BallotSide::Yes,
        redeem_script: yes_rs.clone(),
        p2sh_script: yes_p2sh.script().to_vec(),
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa: ballot_expiry_daa,
        initial_value: yes_initial_value,
    };

    let no_entry = BallotBoxEntry {
        outpoint: no_outpoint.to_string(),
        value: no_value,
        side: BallotSide::No,
        redeem_script: no_rs.clone(),
        p2sh_script: no_p2sh.script().to_vec(),
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa: ballot_expiry_daa,
        initial_value: no_initial_value,
    };

    let (token_tx_id, token_idx) = parse_outpoint_parts(token_outpoint)?;

    let params = SettleParams {
        redemption: r_entry,
        yes_box: yes_entry,
        no_box: no_entry,
        winning_token_tx_id: token_tx_id.clone(),
        winning_token_index: token_idx,
        winning_token_value: token_value,
        winning_token_sig_script: Vec::new(),
        winning_token_sig_op_count: 1,
        payout_script: wallet_spk.clone(),
    };

    println!();
    println!("Settle Prediction Market");
    println!("========================");
    println!("Market ID:     {}", market_id);
    let yes_votes_str = if reward_per_vote > 0 {
        format!("{}", (yes_initial_value - yes_value) / reward_per_vote)
    } else {
        "N/A".to_string()
    };
    let no_votes_str = if reward_per_vote > 0 {
        format!("{}", (no_initial_value - no_value) / reward_per_vote)
    } else {
        "N/A".to_string()
    };
    println!("YES votes:     {} (value: {})", yes_votes_str, fmt_sompi(yes_value));
    println!("NO votes:      {} (value: {})", no_votes_str, fmt_sompi(no_value));
    println!("Winner:        {}", winning_side);
    println!("Payout/token:  {}", fmt_sompi(payout_per_token));
    println!("Token input:   {} ({})", token_outpoint, fmt_sompi(token_value));
    println!();

    let bp = build_settle_tx(&params)
        .map_err(|e| anyhow::anyhow!("build_settle_tx failed: {}", e))?;

    // Settle TX: input[0]=Redemption, input[1]=YES BB, input[2]=NO BB, input[3]=winning token
    // Only input[3] (token) needs a P2PK signature
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let token_utxo = utxos.iter()
        .find(|u| u.outpoint.transaction_id == token_tx_id && u.outpoint.index == token_idx)
        .ok_or_else(|| anyhow::anyhow!("Token UTXO {} not found", token_outpoint))?;
    let token_spk = token_utxo.script_bytes();

    let tx_id = submit_blueprint(&rpc, &bp, 3, &token_spk, token_value, &privkey).await?;

    println!("SUCCESS! Market settled.");
    println!("TXID:        {}", tx_id);
    println!("Payout:      {}:0 ({})", tx_id, fmt_sompi(payout_per_token));
    println!("Redemption:  {}:1 (continuation)", tx_id);
    println!("YES BB:      {}:2 (preserved)", tx_id);
    println!("NO BB:       {}:3 (preserved)", tx_id);

    Ok(())
}

// 6. Redeem

#[allow(clippy::too_many_arguments)]
async fn redeem(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    market_id: &str,
    redemption_outpoint: &str,
    redemption_value: u64,
    redemption_rs_hex: &str,
    payout_per_token: u64,
    expiry_daa: u64,
    winning_side_str: &str,
    yes_final_value: u64,
    no_final_value: u64,
    yes_outpoint: &str,
    yes_value: u64,
    yes_rs_hex: &str,
    yes_initial_value: u64,
    no_outpoint: &str,
    no_value: u64,
    no_rs_hex: &str,
    no_initial_value: u64,
    reward_per_vote: u64,
    start_daa: u64,
    end_daa: u64,
    ballot_expiry_daa: u64,
    token_outpoint: &str,
    token_value: u64,
) -> anyhow::Result<()> {
    let winning_side = parse_side(winning_side_str)?;
    let redemption_rs = hex::decode(redemption_rs_hex)?;
    let redemption_p2sh = build_p2sh(&redemption_rs);
    let yes_rs = hex::decode(yes_rs_hex)?;
    let yes_p2sh = build_p2sh(&yes_rs);
    let no_rs = hex::decode(no_rs_hex)?;
    let no_p2sh = build_p2sh(&no_rs);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();
    let wallet_spk = build_owner_spk(&pubkey);

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let r_entry = RedemptionEntry {
        outpoint: redemption_outpoint.to_string(),
        value: redemption_value,
        winning_side,
        yes_final_value,
        no_final_value,
        payout_per_token,
        redeem_script: redemption_rs.clone(),
        p2sh_script: redemption_p2sh.script().to_vec(),
        expiry_daa,
    };

    let yes_entry = BallotBoxEntry {
        outpoint: yes_outpoint.to_string(),
        value: yes_value,
        side: BallotSide::Yes,
        redeem_script: yes_rs.clone(),
        p2sh_script: yes_p2sh.script().to_vec(),
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa: ballot_expiry_daa,
        initial_value: yes_initial_value,
    };

    let no_entry = BallotBoxEntry {
        outpoint: no_outpoint.to_string(),
        value: no_value,
        side: BallotSide::No,
        redeem_script: no_rs.clone(),
        p2sh_script: no_p2sh.script().to_vec(),
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa: ballot_expiry_daa,
        initial_value: no_initial_value,
    };

    let (token_tx_id, token_idx) = parse_outpoint_parts(token_outpoint)?;

    let params = RedeemParams {
        redemption: r_entry,
        yes_box: yes_entry,
        no_box: no_entry,
        token_tx_id: token_tx_id.clone(),
        token_index: token_idx,
        token_value,
        token_sig_script: Vec::new(),
        token_sig_op_count: 1,
        payout_script: wallet_spk.clone(),
    };

    println!();
    println!("Redeem Winning Token");
    println!("====================");
    println!("Market ID:     {}", market_id);
    println!("Winning side:  {}", winning_side);
    println!("Payout/token:  {}", fmt_sompi(payout_per_token));
    println!("Token input:   {} ({})", token_outpoint, fmt_sompi(token_value));
    println!("Pool:          {}", fmt_sompi(redemption_value));
    println!();

    let bp = build_redeem_tx(&params)
        .map_err(|e| anyhow::anyhow!("build_redeem_tx failed: {}", e))?;

    // Redeem TX: same layout as settle. input[3] = winning token (needs sig)
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let token_utxo = utxos.iter()
        .find(|u| u.outpoint.transaction_id == token_tx_id && u.outpoint.index == token_idx)
        .ok_or_else(|| anyhow::anyhow!("Token UTXO {} not found", token_outpoint))?;
    let token_spk = token_utxo.script_bytes();

    let tx_id = submit_blueprint(&rpc, &bp, 3, &token_spk, token_value, &privkey).await?;

    println!("SUCCESS! Token redeemed.");
    println!("TXID:        {}", tx_id);
    println!("Payout:      {}:0 ({})", tx_id, fmt_sompi(payout_per_token));
    println!("Redemption:  {}:1 (continuation)", tx_id);

    Ok(())
}

// 7. Expire BallotBox

#[allow(clippy::too_many_arguments)]
async fn expire_ballot(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    outpoint: &str,
    value: u64,
    side_str: &str,
    rs_hex: &str,
    reward_per_vote: u64,
    start_daa: u64,
    end_daa: u64,
    expiry_daa: u64,
    initial_value: u64,
) -> anyhow::Result<()> {
    let side = parse_side(side_str)?;
    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();
    let creator_script = build_owner_spk(&pubkey);

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;
    let current_daa = rpc.get_daa_score().await?;

    let bb_entry = BallotBoxEntry {
        outpoint: outpoint.to_string(),
        value,
        side,
        redeem_script: redeem_script.clone(),
        p2sh_script: p2sh.script().to_vec(),
        reward_per_vote,
        start_daa,
        end_daa,
        expiry_daa,
        initial_value,
    };

    println!();
    println!("Expire BallotBox");
    println!("================");
    println!("Outpoint:    {}", outpoint);
    println!("Side:        {}", side);
    println!("Value:       {}", fmt_sompi(value));
    println!("Expiry DAA:  {} (current: {})", expiry_daa, current_daa);
    println!();

    // Build with dummy sig to get TX structure, compute sighash, then rebuild with real sig
    let dummy_sig = [0u8; 64];
    let dummy_params = ExpireBallotParams {
        ballot_box: bb_entry.clone(),
        signature: dummy_sig,
        pubkey,
        creator_script: creator_script.clone(),
        current_daa,
    };

    let bp = build_expire_ballot_tx(&dummy_params)
        .map_err(|e| anyhow::anyhow!("build_expire_ballot_tx failed: {}", e))?;

    let mut tx = blueprint_to_tx(&bp);
    tx.inputs[0].script_bytes = p2sh.script().to_vec();
    tx.inputs[0].value = value;

    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;

    let real_params = ExpireBallotParams {
        ballot_box: bb_entry,
        signature,
        pubkey,
        creator_script,
        current_daa,
    };

    let real_bp = build_expire_ballot_tx(&real_params)
        .map_err(|e| anyhow::anyhow!("build_expire_ballot_tx (real sig) failed: {}", e))?;

    let mut real_tx = blueprint_to_tx(&real_bp);
    let mut sigscripts: Vec<Vec<u8>> = real_bp.inputs.iter().map(|i| i.sig_script.clone()).collect();

    // Phase 2: exact fee from the real sigscript size; adjust payout + re-sign
    // if it differs from build_expire_ballot_tx's rough fee estimate
    // (kob_core::mass::estimate_compute_mass, ~100 bytes/sig-op). expire's
    // sigscript embeds the FULL BallotBox redeemScript (~190B) on top of the
    // signature and pubkey pushes, which the generic estimate doesn't
    // account for -- live-confirmed via a rejected on-chain expire tx:
    // "has 166900 fees which is under the required amount of 186500 for
    // compute mass 1865". Same Phase-1-estimate/Phase-2-exact-recompute
    // pattern as partial_fill.rs (kob/SECURITY_FIXES.md Phase 4).
    real_tx.inputs[0].script_bytes = p2sh.script().to_vec();
    real_tx.inputs[0].value = value;
    let exact_mass = kob_core::mass::calc_mass_with_sigscripts(&real_tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);
    let domain_fee = value.saturating_sub(real_bp.outputs.first().map(|o| o.value).unwrap_or(0));
    if exact_fee > domain_fee {
        let new_payout = value.checked_sub(exact_fee).ok_or_else(|| {
            anyhow::anyhow!(
                "BallotBox value {} too small to cover the exact fee {} (compute mass {})",
                value, exact_fee, exact_mass
            )
        })?;
        real_tx.outputs[0].value = new_payout;
        let sighash2 = compute_sighash(&real_tx, 0)?;
        let signature2 = signing::schnorr_sign_secure(&privkey, &sighash2)?;
        sigscripts[0] = kob_core::prediction::build_ballot_box_expire_sigscript(
            &signature2, &pubkey, &redeem_script,
        );
    }

    let payload = to_rpc_payload(&real_tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    let payout = real_tx.outputs.first().map(|o| o.value).unwrap_or(0);
    println!("SUCCESS! BallotBox expired.");
    println!("TXID:    {}", tx_id);
    println!("Reclaimed: {}:0 ({})", tx_id, fmt_sompi(payout));

    Ok(())
}

// 8. Refund Pool (SplitMerge or Redemption)

#[allow(clippy::too_many_arguments)]
async fn refund_pool(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    cov_type: &str,
    outpoint: &str,
    value: u64,
    rs_hex: &str,
    expiry_daa: u64,
    yes_token_cid_hex: Option<&str>,
    no_token_cid_hex: Option<&str>,
    unit_value: Option<u64>,
    creator_pkh_hex: Option<&str>,
    winning_side_str: Option<&str>,
    yes_final_value: Option<u64>,
    no_final_value: Option<u64>,
    payout_per_token: Option<u64>,
) -> anyhow::Result<()> {
    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();
    let creator_script = build_owner_spk(&pubkey);

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;
    let current_daa = rpc.get_daa_score().await?;

    println!();
    println!("Refund {} Pool", cov_type);
    println!("========================");
    println!("Outpoint:    {}", outpoint);
    println!("Value:       {}", fmt_sompi(value));
    println!("Expiry DAA:  {} (current: {})", expiry_daa, current_daa);
    println!();

    match cov_type.to_lowercase().as_str() {
        "splitmerge" => {
            let yes_cid = parse_hex32(
                yes_token_cid_hex.ok_or_else(|| anyhow::anyhow!("--yes-token-cid required for splitmerge refund"))?,
                "yes_token_cid",
            )?;
            let no_cid = parse_hex32(
                no_token_cid_hex.ok_or_else(|| anyhow::anyhow!("--no-token-cid required for splitmerge refund"))?,
                "no_token_cid",
            )?;
            let uv = unit_value.ok_or_else(|| anyhow::anyhow!("--unit-value required for splitmerge refund"))?;
            let cpkh = parse_hex32(
                creator_pkh_hex.ok_or_else(|| anyhow::anyhow!("--creator-pkh required for splitmerge refund"))?,
                "creator_pkh",
            )?;

            let sm_entry = SplitMergeEntry {
                outpoint: outpoint.to_string(),
                value,
                redeem_script: redeem_script.clone(),
                p2sh_script: p2sh.script().to_vec(),
                yes_token_cid: yes_cid,
                no_token_cid: no_cid,
                unit_value: uv,
                creator_pkh: cpkh,
                expiry_daa,
            };

            let dummy_sig = [0u8; 64];
            let dummy_params = RefundSplitMergeParams {
                split_merge: sm_entry.clone(),
                signature: dummy_sig,
                pubkey,
                creator_script: creator_script.clone(),
                current_daa,
            };

            let bp = build_refund_split_merge_tx(&dummy_params)
                .map_err(|e| anyhow::anyhow!("build_refund_split_merge_tx failed: {}", e))?;

            let mut tx = blueprint_to_tx(&bp);
            tx.inputs[0].script_bytes = p2sh.script().to_vec();
            tx.inputs[0].value = value;

            let sighash = compute_sighash(&tx, 0)?;
            let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;

            let real_params = RefundSplitMergeParams {
                split_merge: sm_entry,
                signature,
                pubkey,
                creator_script,
                current_daa,
            };

            let real_bp = build_refund_split_merge_tx(&real_params)
                .map_err(|e| anyhow::anyhow!("build_refund_split_merge_tx (real) failed: {}", e))?;

            let real_tx = blueprint_to_tx(&real_bp);
            let sigscripts: Vec<Vec<u8>> = real_bp.inputs.iter().map(|i| i.sig_script.clone()).collect();
            let payload = to_rpc_payload(&real_tx, &sigscripts);
            let tx_id = rpc.submit_transaction(payload).await?;

            let payout = real_bp.outputs.first().map(|o| o.value).unwrap_or(0);
            println!("SUCCESS! SplitMerge pool refunded.");
            println!("TXID:    {}", tx_id);
            println!("Reclaimed: {}:0 ({})", tx_id, fmt_sompi(payout));
        }
        "redemption" => {
            let ws = parse_side(
                winning_side_str.ok_or_else(|| anyhow::anyhow!("--winning-side required for redemption refund"))?,
            )?;
            let yfv = yes_final_value.ok_or_else(|| anyhow::anyhow!("--yes-final-value required for redemption refund"))?;
            let nfv = no_final_value.ok_or_else(|| anyhow::anyhow!("--no-final-value required for redemption refund"))?;
            let ppt = payout_per_token.ok_or_else(|| anyhow::anyhow!("--payout-per-token required for redemption refund"))?;

            let r_entry = RedemptionEntry {
                outpoint: outpoint.to_string(),
                value,
                winning_side: ws,
                yes_final_value: yfv,
                no_final_value: nfv,
                payout_per_token: ppt,
                redeem_script: redeem_script.clone(),
                p2sh_script: p2sh.script().to_vec(),
                expiry_daa,
            };

            let dummy_sig = [0u8; 64];
            let dummy_params = RefundRedemptionParams {
                redemption: r_entry.clone(),
                signature: dummy_sig,
                pubkey,
                creator_script: creator_script.clone(),
                current_daa,
            };

            let bp = build_refund_redemption_tx(&dummy_params)
                .map_err(|e| anyhow::anyhow!("build_refund_redemption_tx failed: {}", e))?;

            let mut tx = blueprint_to_tx(&bp);
            tx.inputs[0].script_bytes = p2sh.script().to_vec();
            tx.inputs[0].value = value;

            let sighash = compute_sighash(&tx, 0)?;
            let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;

            let real_params = RefundRedemptionParams {
                redemption: r_entry,
                signature,
                pubkey,
                creator_script,
                current_daa,
            };

            let real_bp = build_refund_redemption_tx(&real_params)
                .map_err(|e| anyhow::anyhow!("build_refund_redemption_tx (real) failed: {}", e))?;

            let real_tx = blueprint_to_tx(&real_bp);
            let sigscripts: Vec<Vec<u8>> = real_bp.inputs.iter().map(|i| i.sig_script.clone()).collect();
            let payload = to_rpc_payload(&real_tx, &sigscripts);
            let tx_id = rpc.submit_transaction(payload).await?;

            let payout = real_bp.outputs.first().map(|o| o.value).unwrap_or(0);
            println!("SUCCESS! Redemption pool refunded.");
            println!("TXID:    {}", tx_id);
            println!("Reclaimed: {}:0 ({})", tx_id, fmt_sompi(payout));
        }
        other => {
            anyhow::bail!("Unknown covenant type '{}'. Use 'splitmerge' or 'redemption'.", other);
        }
    }

    Ok(())
}

// 9. List Markets

async fn list_markets(
    engine_url: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    if let Some(url) = engine_url {
        let endpoint = format!("{}/prediction/markets", url.trim_end_matches('/'));
        println!("Querying engine at {}...", endpoint);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        let resp = client.get(&endpoint).send().await
            .map_err(|e| anyhow::anyhow!("Failed to query engine: {}", e))?;

        if !resp.status().is_success() {
            anyhow::bail!("Engine returned status {}", resp.status());
        }

        let body = resp.text().await?;
        if json {
            println!("{}", body);
        } else {
            if let Ok(markets) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                if markets.is_empty() {
                    println!("No active prediction markets found.");
                    return Ok(());
                }
                println!("Active Prediction Markets");
                println!("=========================");
                for m in &markets {
                    let id = m.get("market_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let settled = m.get("settled").and_then(|v| v.as_bool()).unwrap_or(false);
                    let tvl = m.get("total_value_locked").and_then(|v| v.as_u64()).unwrap_or(0);
                    let status = if settled { "SETTLED" } else { "ACTIVE" };
                    println!("  {} [{}] TVL: {}", id, status, fmt_sompi(tvl));
                }
                println!();
                println!("{} market(s) found.", markets.len());
            } else {
                println!("{}", body);
            }
        }
    } else {
        println!("Prediction Markets");
        println!("==================");
        println!("No engine URL provided. Use --engine-url to query an engine API.");
        println!();
        println!("Example:");
        println!("  kob-cli prediction markets --engine-url http://localhost:8080");
    }

    Ok(())
}
