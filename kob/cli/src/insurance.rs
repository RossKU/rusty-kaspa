//! `kob-cli insurance` -- Insurance lifecycle commands.
//!
//! Subcommands:
//!   deploy-offer   -- Insurer deploys an insurance offer (locks coverage KAS)
//!   cancel-offer   -- Insurer cancels an unmatched offer
//!   replace-offer  -- Insurer updates premium on an existing offer
//!   claim          -- Lender claims payout on borrower default (PATH 1)
//!   release        -- Borrower releases coverage after repay (PATH 2)
//!   mutual-cancel  -- 2-of-2 insurer+lender cancel (PATH 3)
//!   timeout        -- Insurer reclaims after grace period (PATH 4)

use crate::cancel::p2sh_to_address;
use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::insurance::{
    build_insurance_offer_cancel_sigscript, build_insurance_offer_redeem_script,
    build_insurance_offer_replace_sigscript, build_insurance_payload,
    build_insurance_position_cancel_sigscript, build_insurance_position_payout_sigscript,
    build_insurance_position_release_sigscript, build_insurance_position_timeout_sigscript,
};
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, converge_fee, estimate_compute_mass, MAX_TX_MASS};
use kob_core::p2sh::{build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{select_utxos_mass_aware, to_rpc_payload, CoinSelection, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint, UtxoEntry};
use kob_core::wallet::WalletFile;
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

/// Insurance subcommands.
#[derive(Subcommand, Debug)]
pub enum InsuranceCommand {
    /// Deploy an insurance offer (insurer locks coverage KAS with premium/term conditions).
    DeployOffer {
        /// Premium in basis points (e.g. 200 for 2%).
        #[arg(long)]
        premium_bps: u64,

        /// Maximum loan duration the insurer will cover (DAA units).
        #[arg(long)]
        max_duration_daa: u64,

        /// Maximum LTV of insurable loans (e.g. 15000 for 150%).
        #[arg(long)]
        max_ltv: u64,

        /// Minimum coverage amount in sompi.
        #[arg(long)]
        min_coverage: u64,

        /// Coverage amount to lock (sompi).
        #[arg(long)]
        value: u64,
    },

    /// Cancel an unmatched insurance offer (owner reclaims coverage).
    CancelOffer {
        /// Outpoint of the insurance offer UTXO (txid:index).
        #[arg(long)]
        outpoint: String,

        /// RedeemScript (hex). If omitted, reconstructed from offer params.
        #[arg(long)]
        rs: Option<String>,

        /// Premium in basis points (required if --rs is omitted).
        #[arg(long)]
        premium_bps: Option<u64>,

        /// Max duration DAA (required if --rs is omitted).
        #[arg(long)]
        max_duration_daa: Option<u64>,

        /// Max LTV (required if --rs is omitted).
        #[arg(long)]
        max_ltv: Option<u64>,

        /// Min coverage sompi (required if --rs is omitted).
        #[arg(long)]
        min_coverage: Option<u64>,

        /// UTXO value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        order_value: Option<u64>,
    },

    /// Replace (update) the premium on an existing insurance offer.
    ReplaceOffer {
        /// Outpoint of the insurance offer UTXO (txid:index).
        #[arg(long)]
        outpoint: String,

        /// New premium in basis points.
        #[arg(long)]
        new_premium_bps: u64,

        /// RedeemScript (hex). If omitted, reconstructed from offer params.
        #[arg(long)]
        rs: Option<String>,

        /// Current premium in basis points (required if --rs is omitted).
        #[arg(long)]
        premium_bps: Option<u64>,

        /// Max duration DAA (required if --rs is omitted).
        #[arg(long)]
        max_duration_daa: Option<u64>,

        /// Max LTV (required if --rs is omitted).
        #[arg(long)]
        max_ltv: Option<u64>,

        /// Min coverage sompi (required if --rs is omitted).
        #[arg(long)]
        min_coverage: Option<u64>,

        /// UTXO value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        order_value: Option<u64>,
    },

    /// Lender claims payout on borrower default (PATH 1).
    ///
    /// Requires CLTV: lockTime >= expiry_daa + grace_daa.
    Claim {
        /// Insurance position outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Position redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// UTXO value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        order_value: Option<u64>,

        /// Lock time for CLTV (DAA score). Must be >= expiry + grace.
        #[arg(long)]
        lock_time: u64,
    },

    /// Borrower releases coverage after repay (PATH 2).
    ///
    /// Output[0] must go to insurer with value >= insured_amount.
    Release {
        /// Insurance position outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Position redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// UTXO value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        order_value: Option<u64>,

        /// Insurer destination address (kaspa:... or kaspatest:...).
        /// Coverage funds are sent here.
        #[arg(long)]
        insurer_address: String,
    },

    /// Mutual cancel: 2-of-2 insurer + lender (PATH 3).
    ///
    /// Both parties must provide pre-computed signatures.
    MutualCancel {
        /// Insurance position outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Insurer signature (hex, 128 chars = 64 bytes).
        #[arg(long)]
        insurer_sig: String,

        /// Insurer public key (hex, 64 chars = 32 bytes).
        #[arg(long)]
        insurer_pk: String,

        /// Lender signature (hex, 128 chars = 64 bytes).
        #[arg(long)]
        lender_sig: String,

        /// Lender public key (hex, 64 chars = 32 bytes).
        #[arg(long)]
        lender_pk: String,

        /// Position redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// UTXO value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        order_value: Option<u64>,
    },

    /// Insurer reclaims coverage after timeout (PATH 4).
    ///
    /// Requires CLTV: lockTime >= expiry_daa + 2*grace_daa.
    Timeout {
        /// Insurance position outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Position redeemScript (hex).
        #[arg(long)]
        rs: String,

        /// UTXO value override (sompi). Queried from chain if omitted.
        #[arg(long)]
        order_value: Option<u64>,

        /// Lock time for CLTV (DAA score). Must be >= expiry + 2*grace.
        #[arg(long)]
        lock_time: u64,
    },
}

// Top-level dispatcher

pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    fee: u64,
    cmd: &InsuranceCommand,
) -> anyhow::Result<()> {
    match cmd {
        InsuranceCommand::DeployOffer {
            premium_bps,
            max_duration_daa,
            max_ltv,
            min_coverage,
            value,
        } => {
            deploy_offer(
                wallet_path, node_url, network, *premium_bps, *max_duration_daa,
                *max_ltv, *min_coverage, *value, fee,
            )
            .await
        }
        InsuranceCommand::CancelOffer {
            outpoint,
            rs,
            premium_bps,
            max_duration_daa,
            max_ltv,
            min_coverage,
            order_value,
        } => {
            cancel_offer(
                wallet_path, node_url, network, outpoint, rs.as_deref(),
                *premium_bps, *max_duration_daa, *max_ltv, *min_coverage,
                *order_value, fee,
            )
            .await
        }
        InsuranceCommand::ReplaceOffer {
            outpoint,
            new_premium_bps,
            rs,
            premium_bps,
            max_duration_daa,
            max_ltv,
            min_coverage,
            order_value,
        } => {
            replace_offer(
                wallet_path, node_url, network, outpoint, *new_premium_bps,
                rs.as_deref(), *premium_bps, *max_duration_daa, *max_ltv,
                *min_coverage, *order_value, fee,
            )
            .await
        }
        InsuranceCommand::Claim {
            outpoint,
            rs,
            order_value,
            lock_time,
        } => {
            claim_payout(wallet_path, node_url, network, outpoint, rs, *order_value, *lock_time, fee).await
        }
        InsuranceCommand::Release {
            outpoint,
            rs,
            order_value,
            insurer_address,
        } => {
            release(wallet_path, node_url, network, outpoint, rs, *order_value, insurer_address, fee).await
        }
        InsuranceCommand::MutualCancel {
            outpoint,
            insurer_sig,
            insurer_pk,
            lender_sig,
            lender_pk,
            rs,
            order_value,
        } => {
            mutual_cancel(
                wallet_path, node_url, network, outpoint, insurer_sig,
                insurer_pk, lender_sig, lender_pk, rs, *order_value, fee,
            )
            .await
        }
        InsuranceCommand::Timeout {
            outpoint,
            rs,
            order_value,
            lock_time,
        } => {
            timeout(wallet_path, node_url, network, outpoint, rs, *order_value, *lock_time, fee).await
        }
    }
}

// deploy-offer

#[allow(clippy::too_many_arguments)]
async fn deploy_offer(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    premium_bps: u64,
    max_duration_daa: u64,
    max_ltv: u64,
    min_coverage: u64,
    value: u64,
    fee: u64,
) -> anyhow::Result<()> {
    if value == 0 {
        anyhow::bail!("value must be > 0");
    }

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let spk_hash = kob_core::blake2b_256(&pubkey);

    let redeem_script = build_insurance_offer_redeem_script(
        &spk_hash, premium_bps, max_duration_daa, max_ltv, min_coverage,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Insurance Offer (v1)");
    println!("============================");
    println!("Premium:            {} bps ({:.2}%)", premium_bps, premium_bps as f64 / 100.0);
    println!("Max Duration:       {} DAA", max_duration_daa);
    println!("Max LTV:            {} ({:.2}%)", max_ltv, max_ltv as f64 / 100.0);
    println!("Min Coverage:       {} sompi ({:.8} KAS)", min_coverage, min_coverage as f64 / 1e8);
    println!("Coverage Value:     {} sompi ({:.8} KAS)", value, value as f64 / 1e8);
    println!("Owner:              {}", wallet.public_key);
    println!();
    println!("RedeemScript:       {} bytes", redeem_script.len());
    println!("P2SH SPK:           {}", hex::encode(&p2sh.script()));
    println!();

    info!(address = %wallet.address, value = value, "deploying insurance offer");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let rpc_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let p2pk_rpc: Vec<_> = rpc_utxos.iter().filter(|u| !u.is_p2sh()).collect();
    let core_utxos: Vec<UtxoEntry> = p2pk_rpc
        .iter()
        .map(|u| UtxoEntry {
            outpoint: Outpoint {
                transaction_id: u.outpoint.transaction_id.clone(),
                index: u.outpoint.index,
            },
            value: u.utxo_entry.amount,
            script_public_key: format!(
                "{:04x}{}",
                u.utxo_entry.script_public_key.version,
                u.utxo_entry.script_public_key.script
            ),
        })
        .collect();

    let coin_sel: CoinSelection =
        select_utxos_mass_aware(&core_utxos, value, fee, 2).map_err(|e| {
            anyhow::anyhow!(
                "UTXO selection failed: {}. {} P2PK UTXOs available.",
                e,
                core_utxos.len()
            )
        })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    println!(
        "Selected {} funding UTXOs (total {} sompi)",
        selected_utxos.len(),
        total_input
    );
    for u in selected_utxos {
        println!(
            "  {}:{} ({} sompi)",
            &u.outpoint.transaction_id[..16],
            u.outpoint.index,
            u.value
        );
    }
    if !coin_sel.penalty_free {
        println!(
            "  Warning: storage mass penalty {}/{} (run `kob wallet consolidate` to reduce)",
            coin_sel.storage_mass,
            kob_core::MAX_TX_MASS
        );
    }

    let mut tx = Transaction::new(0);

    for sel in selected_utxos {
        let rpc_utxo = p2pk_rpc
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == sel.outpoint.transaction_id
                    && u.outpoint.index == sel.outpoint.index
            })
            .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
        tx.inputs.push(TxInput {
            prev_tx_id: rpc_utxo.outpoint.transaction_id.clone(),
            prev_index: rpc_utxo.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: rpc_utxo.utxo_entry.script_public_key.version,
            script_bytes: rpc_utxo.script_bytes(),
            value: rpc_utxo.utxo_entry.amount,
        });
    }

    // Output 0: P2SH covenant (insurance offer)
    tx.outputs.push(TxOutput::new(value, 0, p2sh.script().to_vec(), None));

    // Payload: KOB:I:<RS>
    tx.payload = build_insurance_payload(&redeem_script);

    // Output 1: tentative change
    let tent_change = total_input.saturating_sub(value + fee);
    let first_rpc = p2pk_rpc
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                && u.outpoint.index == selected_utxos[0].outpoint.index
        })
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
    if tent_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_change, first_rpc.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change = tx.outputs.len() > 1;
    let change_idx = tx.outputs.len().saturating_sub(1);
    let (est_fee, _) = if has_change {
        converge_fee(&mut tx, total_input - value, change_idx, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };
    if has_change && tx.outputs[change_idx].value < MIN_UTXO_VALUE {
        let cv = tx.outputs[change_idx].value;
        tx.outputs.pop();
        if cv > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", cv); }
    } else if !has_change && tent_change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", tent_change);
    }

    // Sign inputs (phase 1)
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let storage_mass_val = {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        compute_storage_mass(&in_vals, &out_vals)
    };
    let exact_fee = exact_mass.max(storage_mass_val).max(min_fee_override);
    let actual_fee = if exact_fee > est_fee && tx.outputs.len() > 1 {
        let ci = tx.outputs.len() - 1;
        let nc = total_input.saturating_sub(value + exact_fee);
        if nc >= MIN_UTXO_VALUE { tx.outputs[ci].value = nc; } else {
            tx.outputs.pop();
            if nc > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", nc); }
        }
        sigscripts.clear();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(&tx, i)?;
            let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
            sigscripts.push(signing::build_p2pk_sigscript(&signature));
        }
        exact_fee
    } else { est_fee };

    println!("Signed {} input(s)", sigscripts.len());
    println!();

    // Storage mass pre-check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected by node: {}. \
             Increase the coverage amount or use a larger funding UTXO.",
            e
        );
    }

    // Fee transparency
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Insurance offer deployed.");
    println!("TXID: {}", tx_id);
    println!("RedeemScript (hex): {}", hex::encode(&redeem_script));

    Ok(())
}

// cancel-offer

/// Resolve the offer redeemScript from --rs or from individual params.
fn resolve_offer_rs(
    wallet_path: &Path,
    rs_hex: Option<&str>,
    premium_bps: Option<u64>,
    max_duration_daa: Option<u64>,
    max_ltv: Option<u64>,
    min_coverage: Option<u64>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(hex_str) = rs_hex {
        return Ok(hex::decode(hex_str)?);
    }
    let premium_bps = premium_bps.ok_or_else(|| anyhow::anyhow!("--premium-bps required when --rs is omitted"))?;
    let max_duration_daa = max_duration_daa.ok_or_else(|| anyhow::anyhow!("--max-duration-daa required when --rs is omitted"))?;
    let max_ltv = max_ltv.ok_or_else(|| anyhow::anyhow!("--max-ltv required when --rs is omitted"))?;
    let min_coverage = min_coverage.ok_or_else(|| anyhow::anyhow!("--min-coverage required when --rs is omitted"))?;

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let spk_hash = kob_core::blake2b_256(&pubkey);
    Ok(build_insurance_offer_redeem_script(
        &spk_hash, premium_bps, max_duration_daa, max_ltv, min_coverage,
    )?)
}

#[allow(clippy::too_many_arguments)]
async fn cancel_offer(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: Option<&str>,
    premium_bps: Option<u64>,
    max_duration_daa: Option<u64>,
    max_ltv: Option<u64>,
    min_coverage: Option<u64>,
    order_value_override: Option<u64>,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    let redeem_script = resolve_offer_rs(
        wallet_path, rs_hex, premium_bps, max_duration_daa, max_ltv, min_coverage,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Cancel Insurance Offer");
    println!("=======================");
    println!("Outpoint:      {}", outpoint);
    println!("Owner:         {}", wallet.public_key);
    println!("RedeemScript:  {} bytes", redeem_script.len());
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, "cancelling insurance offer");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "UTXO {} not found at P2SH address. It may be spent or use --order-value.",
                    outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("UTXO Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 1, 0) + 500;

    // Get fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates
            .first()
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!("No P2PK UTXO with >= {} sompi for fee payment", est_fee + MIN_UTXO_VALUE)
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build TX with tentative output value
    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in - est_fee;
    let mut tx = Transaction::new(0);

    // Input 0: insurance offer UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: recovered funds to wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output 0
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, min_fee_override);

    // Sign input 0 (cancel path)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let cancel_sigscript = build_insurance_offer_cancel_sigscript(&sig_0, &pubkey, &redeem_script);

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let sigscripts_cancel = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_cancel);
    let storage_mass_cancel = {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        compute_storage_mass(&in_vals, &out_vals)
    };
    let exact_fee = exact_mass.max(storage_mass_cancel).max(min_fee_override);

    let (cancel_sigscript, fee_sigscript, actual_fee) = if exact_fee > est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
        let cancel_sigscript = build_insurance_offer_cancel_sigscript(&sig_0, &pubkey, &redeem_script);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);
        (cancel_sigscript, fee_sigscript, exact_fee)
    } else {
        (cancel_sigscript, fee_sigscript, est_fee)
    };

    let output_value = tx.outputs[0].value;
    println!("Cancel SigScript: {} bytes", cancel_sigscript.len());
    println!("Output Value:  {} sompi", output_value);
    println!();

    // Fee transparency
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[cancel_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        let surplus = fee_utxo.utxo_entry.amount.saturating_sub(actual_fee);
        if surplus > 0 && surplus < MIN_UTXO_VALUE {
            println!("Surplus:          {:>9} sompi (donated as fee)", surplus);
        }
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_sigscript, fee_sigscript]);
    println!("Submitting cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Insurance offer cancelled.");
    println!("TXID: {}", tx_id);
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

// replace-offer

#[allow(clippy::too_many_arguments)]
async fn replace_offer(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    new_premium_bps: u64,
    rs_hex: Option<&str>,
    premium_bps: Option<u64>,
    max_duration_daa: Option<u64>,
    max_ltv: Option<u64>,
    min_coverage: Option<u64>,
    order_value_override: Option<u64>,
    fee: u64,
) -> anyhow::Result<()> {
    if new_premium_bps == 0 {
        anyhow::bail!("new_premium_bps must be > 0");
    }

    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    let redeem_script = resolve_offer_rs(
        wallet_path, rs_hex, premium_bps, max_duration_daa, max_ltv, min_coverage,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Replace Insurance Offer Premium");
    println!("================================");
    println!("Outpoint:          {}", outpoint);
    println!("New Premium:       {} bps ({:.2}%)", new_premium_bps, new_premium_bps as f64 / 100.0);
    println!("Owner:             {}", wallet.public_key);
    println!("RedeemScript:      {} bytes", redeem_script.len());
    println!("P2SH SPK:         {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, new_premium_bps = new_premium_bps, "replacing insurance offer premium");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "UTXO {} not found at P2SH address. It may be spent or use --order-value.",
                    outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("UTXO Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 2, 0) + 500;

    // Fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates
            .first()
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!("No P2PK UTXO with >= {} sompi for fee payment", est_fee + MIN_UTXO_VALUE)
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Replace is self-continuation: output[0] must be the same P2SH address with same value
    // Build TX with tentative change, then refine with exact mass
    let tentative_change = fee_utxo.utxo_entry.amount - est_fee;

    // Build TX
    let mut tx = Transaction::new(0);

    // Input 0: insurance offer UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: self-continuation (same P2SH, same value)
    tx.outputs.push(TxOutput::new(order_value, 0, p2sh.script().to_vec(), None));

    // Output 1: tentative change from fee UTXO
    let wallet_spk_for_change = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, fee_utxo.utxo_entry.script_public_key.version, wallet_spk_for_change.clone(), None));
    }

    // Phase 1: converge fee on change output (index 1)
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change_rep = tx.outputs.len() > 1;
    let change_idx_rep = tx.outputs.len().saturating_sub(1);
    let (est_fee_rep, _) = if has_change_rep {
        converge_fee(&mut tx, fee_utxo.utxo_entry.amount, change_idx_rep, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };
    if has_change_rep && tx.outputs[change_idx_rep].value < MIN_UTXO_VALUE {
        let cv = tx.outputs[change_idx_rep].value;
        tx.outputs.pop();
        if cv > 0 { println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", cv); }
    }

    // Sign input 0 (replace path)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let replace_sigscript = build_insurance_offer_replace_sigscript(
        &sig_0, &pubkey, new_premium_bps, &redeem_script,
    );

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let sigscripts_rep = vec![replace_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_rep);
    let storage_mass_rep = {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        compute_storage_mass(&in_vals, &out_vals)
    };
    let exact_fee = exact_mass.max(storage_mass_rep).max(min_fee_override);

    let (replace_sigscript, fee_sigscript, actual_fee) = if exact_fee > est_fee_rep && tx.outputs.len() > 1 {
        let ci = tx.outputs.len() - 1;
        let nc = fee_utxo.utxo_entry.amount.saturating_sub(exact_fee);
        if nc >= MIN_UTXO_VALUE { tx.outputs[ci].value = nc; } else {
            tx.outputs.pop();
            if nc > 0 { println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", nc); }
        }
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
        let replace_sigscript = build_insurance_offer_replace_sigscript(&sig_0, &pubkey, new_premium_bps, &redeem_script);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);
        (replace_sigscript, fee_sigscript, exact_fee)
    } else {
        (replace_sigscript, fee_sigscript, est_fee_rep)
    };

    println!("Replace SigScript: {} bytes", replace_sigscript.len());
    println!();

    // Fee transparency
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[replace_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[replace_sigscript, fee_sigscript]);
    println!("Submitting replace transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Insurance offer premium updated.");
    println!("TXID: {}", tx_id);
    println!("New premium: {} bps", new_premium_bps);

    Ok(())
}

// claim (PATH 1) — lender claims payout on default

#[allow(clippy::too_many_arguments)]
async fn claim_payout(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    order_value_override: Option<u64>,
    lock_time: u64,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Insurance Claim Payout (PATH 1)");
    println!("================================");
    println!("Outpoint:      {}", outpoint);
    println!("Lender:        {}", wallet.public_key);
    println!("Lock Time:     {} DAA", lock_time);
    println!("RedeemScript:  {} bytes", redeem_script.len());
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, "claiming insurance payout (PATH 1)");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "UTXO {} not found at P2SH address. It may be spent or use --order-value.",
                    outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("UTXO Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 1, 0) + 500;

    // Fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates
            .first()
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!("No P2PK UTXO with >= {} sompi for fee payment", est_fee + MIN_UTXO_VALUE)
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build TX with tentative output value
    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in - est_fee;

    // Build TX with lockTime for CLTV
    let mut tx = Transaction::new(0);
    tx.lock_time = lock_time;

    // Input 0: insurance position UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: payout to lender (wallet)
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output 0
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee_po, _) = converge_fee(&mut tx, total_in, 0, min_fee_override);

    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let payout_sigscript = build_insurance_position_payout_sigscript(&sig_0, &pubkey, &redeem_script);
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let ss = vec![payout_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &ss);
    let sm = { let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect(); let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect(); compute_storage_mass(&iv, &ov) };
    let exact_fee = exact_mass.max(sm).max(min_fee_override);
    let (payout_sigscript, fee_sigscript, actual_fee) = if exact_fee > est_fee_po {
        tx.outputs[0].value = total_in.saturating_sub(exact_fee);
        let sh0 = compute_sighash(&tx, 0)?; let s0 = signing::schnorr_sign_secure(&privkey, &sh0)?;
        let ps = build_insurance_position_payout_sigscript(&s0, &pubkey, &redeem_script);
        let sh1 = compute_sighash(&tx, 1)?; let s1 = signing::schnorr_sign_secure(&privkey, &sh1)?;
        (ps, signing::build_p2pk_sigscript(&s1), exact_fee)
    } else { (payout_sigscript, fee_sigscript, est_fee_po) };

    let output_value = tx.outputs[0].value;
    println!("Payout SigScript: {} bytes", payout_sigscript.len());
    println!("Output Value:  {} sompi", output_value);
    println!();

    // Fee transparency
    {
        let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&iv, &ov);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[payout_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!("Storage mass:     {:>9} / {:>9} ({})", storage_mass, MAX_TX_MASS, if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" });
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[payout_sigscript, fee_sigscript]);
    println!("Submitting claim transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Insurance payout claimed.");
    println!("TXID: {}", tx_id);
    println!("Payout {} sompi to lender.", output_value);

    Ok(())
}

// release (PATH 2) — borrower releases coverage after repay

#[allow(clippy::too_many_arguments)]
async fn release(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    order_value_override: Option<u64>,
    insurer_address: &str,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Insurance Release (PATH 2)");
    println!("==========================");
    println!("Outpoint:          {}", outpoint);
    println!("Borrower:          {}", wallet.public_key);
    println!("Insurer Address:   {}", insurer_address);
    println!("RedeemScript:      {} bytes", redeem_script.len());
    println!("P2SH SPK:         {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, "releasing insurance coverage (PATH 2)");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "UTXO {} not found at P2SH address. It may be spent or use --order-value.",
                    outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("UTXO Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 2, 0) + 500;

    // Fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates
            .first()
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!("No P2PK UTXO with >= {} sompi for fee payment", est_fee + MIN_UTXO_VALUE)
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Resolve insurer's SPK from address
    // Address format: prefix:payload (bech32)
    let insurer_spk = kob_core::bech32::address_to_spk(insurer_address)
        .map_err(|e| anyhow::anyhow!(e))?;

    // Build TX with tentative change
    let tentative_change = fee_utxo.utxo_entry.amount - est_fee;
    let mut tx = Transaction::new(0);

    // Input 0: insurance position UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: insurer receives coverage (must match insurer_spk_hash in covenant)
    tx.outputs.push(TxOutput::new(order_value, 0, insurer_spk, None));

    // Output 1: tentative change from fee UTXO
    let wallet_spk_for_change = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, fee_utxo.utxo_entry.script_public_key.version, wallet_spk_for_change.clone(), None));
    }

    // Phase 1: converge fee on change output
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change_rel = tx.outputs.len() > 1;
    let change_idx_rel = tx.outputs.len().saturating_sub(1);
    let (est_fee_rel, _) = if has_change_rel {
        converge_fee(&mut tx, fee_utxo.utxo_entry.amount, change_idx_rel, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };
    if has_change_rel && tx.outputs[change_idx_rel].value < MIN_UTXO_VALUE {
        let cv = tx.outputs[change_idx_rel].value;
        tx.outputs.pop();
        if cv > 0 { println!("Fee change {} sompi below MIN_UTXO_VALUE, donated as fee.", cv); }
    }

    let fee_change = if tx.outputs.len() > 1 { tx.outputs[1].value } else { 0 };
    println!("Output[0] (insurer): {} sompi", order_value);
    println!("Output[1] (change):  {} sompi", fee_change);
    println!();

    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let release_sigscript = build_insurance_position_release_sigscript(&sig_0, &pubkey, &redeem_script);
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let ss = vec![release_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &ss);
    let sm = { let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect(); let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect(); compute_storage_mass(&iv, &ov) };
    let exact_fee = exact_mass.max(sm).max(min_fee_override);
    let (release_sigscript, fee_sigscript, actual_fee) = if exact_fee > est_fee_rel && tx.outputs.len() > 1 {
        let ci = tx.outputs.len() - 1;
        let nc = fee_utxo.utxo_entry.amount.saturating_sub(exact_fee);
        if nc >= MIN_UTXO_VALUE { tx.outputs[ci].value = nc; } else { tx.outputs.pop(); }
        let sh0 = compute_sighash(&tx, 0)?; let s0 = signing::schnorr_sign_secure(&privkey, &sh0)?;
        let rs = build_insurance_position_release_sigscript(&s0, &pubkey, &redeem_script);
        let sh1 = compute_sighash(&tx, 1)?; let s1 = signing::schnorr_sign_secure(&privkey, &sh1)?;
        (rs, signing::build_p2pk_sigscript(&s1), exact_fee)
    } else { (release_sigscript, fee_sigscript, est_fee_rel) };

    println!("Release SigScript: {} bytes", release_sigscript.len());

    // Fee transparency
    {
        let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&iv, &ov);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[release_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!("Storage mass:     {:>9} / {:>9} ({})", storage_mass, MAX_TX_MASS, if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" });
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[release_sigscript, fee_sigscript]);
    println!("Submitting release transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Insurance coverage released to insurer.");
    println!("TXID: {}", tx_id);
    println!("Released {} sompi to insurer.", order_value);

    Ok(())
}

// mutual-cancel (PATH 3) — 2-of-2 insurer + lender

#[allow(clippy::too_many_arguments)]
async fn mutual_cancel(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    insurer_sig_hex: &str,
    insurer_pk_hex: &str,
    lender_sig_hex: &str,
    lender_pk_hex: &str,
    rs_hex: &str,
    order_value_override: Option<u64>,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    // Parse signatures and public keys
    let insurer_sig_bytes = hex::decode(insurer_sig_hex)?;
    if insurer_sig_bytes.len() != 64 {
        anyhow::bail!("insurer_sig must be 128 hex chars (64 bytes), got {}", insurer_sig_hex.len());
    }
    let mut insurer_sig = [0u8; 64];
    insurer_sig.copy_from_slice(&insurer_sig_bytes);

    let insurer_pk_bytes = hex::decode(insurer_pk_hex)?;
    if insurer_pk_bytes.len() != 32 {
        anyhow::bail!("insurer_pk must be 64 hex chars (32 bytes), got {}", insurer_pk_hex.len());
    }
    let mut insurer_pk = [0u8; 32];
    insurer_pk.copy_from_slice(&insurer_pk_bytes);

    let lender_sig_bytes = hex::decode(lender_sig_hex)?;
    if lender_sig_bytes.len() != 64 {
        anyhow::bail!("lender_sig must be 128 hex chars (64 bytes), got {}", lender_sig_hex.len());
    }
    let mut lender_sig = [0u8; 64];
    lender_sig.copy_from_slice(&lender_sig_bytes);

    let lender_pk_bytes = hex::decode(lender_pk_hex)?;
    if lender_pk_bytes.len() != 32 {
        anyhow::bail!("lender_pk must be 64 hex chars (32 bytes), got {}", lender_pk_hex.len());
    }
    let mut lender_pk = [0u8; 32];
    lender_pk.copy_from_slice(&lender_pk_bytes);

    println!("Insurance Mutual Cancel (PATH 3)");
    println!("=================================");
    println!("Outpoint:      {}", outpoint);
    println!("Insurer PK:    {}", insurer_pk_hex);
    println!("Lender PK:     {}", lender_pk_hex);
    println!("RedeemScript:  {} bytes", redeem_script.len());
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, "mutual cancel insurance position (PATH 3)");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "UTXO {} not found at P2SH address. It may be spent or use --order-value.",
                    outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("UTXO Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 1, 0) + 500;

    // Fee UTXO from wallet
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates
            .first()
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!("No P2PK UTXO with >= {} sompi for fee payment", est_fee + MIN_UTXO_VALUE)
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build TX with tentative output value
    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in - est_fee;
    let mut tx = Transaction::new(0);

    // Input 0: insurance position UTXO (P2SH)
    // PATH 3 executes OpCheckSigVerify twice (insurer + lender), so sig_op_count = 2
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 2,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: funds to wallet (cancel recipient is flexible in PATH 3)
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output 0
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee_mc, _) = converge_fee(&mut tx, total_in, 0, min_fee_override);

    let cancel_sigscript = build_insurance_position_cancel_sigscript(
        &insurer_sig, &insurer_pk, &lender_sig, &lender_pk, &redeem_script,
    );
    let privkey = wallet.secure_key()?;
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let ss = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &ss);
    let sm = { let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect(); let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect(); compute_storage_mass(&iv, &ov) };
    let exact_fee = exact_mass.max(sm).max(min_fee_override);
    let (cancel_sigscript, fee_sigscript, actual_fee) = if exact_fee > est_fee_mc {
        tx.outputs[0].value = total_in.saturating_sub(exact_fee);
        // cancel_sigscript doesn't depend on sighash, only fee input needs re-sign
        let sh1 = compute_sighash(&tx, 1)?; let s1 = signing::schnorr_sign_secure(&privkey, &sh1)?;
        (cancel_sigscript, signing::build_p2pk_sigscript(&s1), exact_fee)
    } else { (cancel_sigscript, fee_sigscript, est_fee_mc) };

    let output_value = tx.outputs[0].value;
    println!("Mutual Cancel SigScript: {} bytes", cancel_sigscript.len());
    println!("Output Value:  {} sompi", output_value);
    println!();

    // Fee transparency
    {
        let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&iv, &ov);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[cancel_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!("Storage mass:     {:>9} / {:>9} ({})", storage_mass, MAX_TX_MASS, if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" });
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_sigscript, fee_sigscript]);
    println!("Submitting mutual cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Insurance position mutually cancelled.");
    println!("TXID: {}", tx_id);
    println!("Recovered {} sompi.", output_value);

    Ok(())
}

// timeout (PATH 4) — insurer reclaims after grace period

#[allow(clippy::too_many_arguments)]
async fn timeout(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    order_value_override: Option<u64>,
    lock_time: u64,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let redeem_script = hex::decode(rs_hex)?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Insurance Timeout Reclaim (PATH 4)");
    println!("===================================");
    println!("Outpoint:      {}", outpoint);
    println!("Insurer:       {}", wallet.public_key);
    println!("Lock Time:     {} DAA", lock_time);
    println!("RedeemScript:  {} bytes", redeem_script.len());
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, "timeout reclaim insurance position (PATH 4)");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "UTXO {} not found at P2SH address. It may be spent or use --order-value.",
                    outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("UTXO Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 1, 0) + 500;

    // Fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates
            .first()
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!("No P2PK UTXO with >= {} sompi for fee payment", est_fee + MIN_UTXO_VALUE)
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build TX with tentative output value
    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in - est_fee;

    // Build TX with lockTime for CLTV
    let mut tx = Transaction::new(0);
    tx.lock_time = lock_time;

    // Input 0: insurance position UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: recovered funds to insurer (wallet)
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output 0
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee_to, _) = converge_fee(&mut tx, total_in, 0, min_fee_override);

    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let timeout_sigscript = build_insurance_position_timeout_sigscript(&sig_0, &pubkey, &redeem_script);
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let ss = vec![timeout_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &ss);
    let sm = { let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect(); let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect(); compute_storage_mass(&iv, &ov) };
    let exact_fee = exact_mass.max(sm).max(min_fee_override);
    let (timeout_sigscript, fee_sigscript, actual_fee) = if exact_fee > est_fee_to {
        tx.outputs[0].value = total_in.saturating_sub(exact_fee);
        let sh0 = compute_sighash(&tx, 0)?; let s0 = signing::schnorr_sign_secure(&privkey, &sh0)?;
        let ts = build_insurance_position_timeout_sigscript(&s0, &pubkey, &redeem_script);
        let sh1 = compute_sighash(&tx, 1)?; let s1 = signing::schnorr_sign_secure(&privkey, &sh1)?;
        (ts, signing::build_p2pk_sigscript(&s1), exact_fee)
    } else { (timeout_sigscript, fee_sigscript, est_fee_to) };

    let output_value = tx.outputs[0].value;
    println!("Timeout SigScript: {} bytes", timeout_sigscript.len());
    println!("Output Value:  {} sompi", output_value);
    println!();

    // Fee transparency
    {
        let iv: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let ov: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&iv, &ov);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[timeout_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!("Storage mass:     {:>9} / {:>9} ({})", storage_mass, MAX_TX_MASS, if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" });
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[timeout_sigscript, fee_sigscript]);
    println!("Submitting timeout reclaim transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Insurance position reclaimed after timeout.");
    println!("TXID: {}", tx_id);
    println!("Recovered {} sompi to insurer.", output_value);

    Ok(())
}
