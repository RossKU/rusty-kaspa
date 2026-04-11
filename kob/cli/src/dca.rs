//! `kob-cli dca` -- Deploy, fill, and cancel DCA (Dollar-Cost Averaging) orders.
//!
//! Subcommands:
//!   deploy  -- Deploy a DCA schedule (dca_order_v2: 315B RS)
//!   fill    -- Fill one period (permissionless, anyone can call)
//!   cancel  -- Owner cancels remaining schedule
//!
//! ## DCA Order V2
//!
//! Owner locks total KAS (amount_per_period * periods + dust margin).
//! Each period, a permissionless filler executes one tranche at the specified
//! price, purchasing tokens on behalf of the owner.
//!
//! RS = 315B (120B state + 195B body)
//! State: [owner_hash 32B][target_cov_id 32B][price_num 8B][price_den 8B]
//!        [amount_per_period 8B][interval_daa 8B][next_execution_daa 8B][periods_remaining 8B]
//!
//! Fill sigscript (D&R):  [pushData(new_rs)][pushData(old_rs)][ci_opN][Op1][pushData(RS)]
//! Cancel sigscript:      [pushData(sig+type 65B)][pushData(pk 32B)][Op0][pushData(RS)]

use crate::cancel::p2sh_to_address;
use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::contract;
use kob_core::contract::build_order_payload;
use kob_core::p2sh::{blake2b_256, build_p2sh};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletFile;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

#[derive(Subcommand, Debug)]
pub enum DcaCommand {
    /// Deploy a DCA schedule (dca_order_v2).
    ///
    /// Locks total KAS = amount_per_period * periods (plus dust margin)
    /// into a P2SH covenant. Each period, any filler can execute one tranche
    /// at the specified limit price.
    Deploy {
        /// Target token covenant ID (hex, 64 chars).
        #[arg(long)]
        target_cov_id: String,

        /// Limit price numerator (tokens per KAS).
        #[arg(long)]
        price_num: u64,

        /// Limit price denominator (tokens per KAS).
        #[arg(long)]
        price_den: u64,

        /// Amount of KAS to spend per period (sompi).
        #[arg(long)]
        amount_per_period: u64,

        /// Interval between periods in DAA scores.
        #[arg(long)]
        interval_daa: u64,

        /// Number of periods (tranches).
        #[arg(long)]
        periods: u64,

        /// Total KAS to lock (sompi). Defaults to amount_per_period * periods.
        #[arg(long)]
        value: Option<u64>,

        /// First execution DAA score. Defaults to current DAA + interval_daa.
        #[arg(long)]
        next_execution_daa: Option<u64>,
    },

    /// Fill one DCA period (permissionless).
    ///
    /// Reads the current RS, parses state, builds the continuation RS
    /// (next_exec += interval, periods -= 1) for D&R enforcement.
    /// If periods == 1, this is the final fill with no continuation output.
    Fill {
        /// DCA order outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// RedeemScript of the DCA order (hex).
        #[arg(long)]
        rs: String,

        /// Continuation output index for D&R (default: 0).
        #[arg(long, default_value_t = 0)]
        continuation_output_idx: u8,

        /// DCA UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,
    },

    /// Cancel a DCA schedule (owner recovers remaining funds).
    Cancel {
        /// DCA order outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// RedeemScript of the DCA order (hex).
        #[arg(long)]
        rs: String,

        /// DCA UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,
    },
}

/// Dispatch DCA subcommand.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    cmd: &DcaCommand,
) -> anyhow::Result<()> {
    match cmd {
        DcaCommand::Deploy {
            target_cov_id,
            price_num,
            price_den,
            amount_per_period,
            interval_daa,
            periods,
            value,
            next_execution_daa,
        } => {
            deploy(
                wallet_path,
                node_url,
                network,
                target_cov_id,
                *price_num,
                *price_den,
                *amount_per_period,
                *interval_daa,
                *periods,
                *value,
                *next_execution_daa,
            )
            .await
        }
        DcaCommand::Fill {
            outpoint,
            rs,
            continuation_output_idx,
            order_value,
        } => {
            fill(
                wallet_path,
                node_url,
                network,
                outpoint,
                rs,
                *continuation_output_idx,
                *order_value,
            )
            .await
        }
        DcaCommand::Cancel {
            outpoint,
            rs,
            order_value,
        } => cancel(wallet_path, node_url, network, outpoint, rs, *order_value).await,
    }
}

// State parsing helpers

/// DCA V2 RS state layout (120B, with push-prefix bytes):
///
///   [0x20](1) [owner_hash](32) [0x20](1) [target_cov_id](32)
///   [0x08](1) [price_num](8)   [0x08](1) [price_den](8)
///   [0x08](1) [amount_per_period](8)
///   [0x08](1) [interval_daa](8)
///   [0x08](1) [next_execution_daa](8)
///   [0x08](1) [periods_remaining](8)
const DCA_V2_STATE_LEN: usize = 120;

fn parse_u64_le(rs: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&rs[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

fn parse_owner_hash(rs: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(&rs[1..33]);
    h
}

fn parse_target_cov_id(rs: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(&rs[34..66]);
    h
}

fn parse_price_num(rs: &[u8]) -> u64 {
    parse_u64_le(rs, 67)
}

fn parse_price_den(rs: &[u8]) -> u64 {
    parse_u64_le(rs, 76)
}

fn parse_amount_per_period(rs: &[u8]) -> u64 {
    parse_u64_le(rs, 85)
}

fn parse_interval_daa(rs: &[u8]) -> u64 {
    parse_u64_le(rs, 94)
}

fn parse_next_execution_daa(rs: &[u8]) -> u64 {
    parse_u64_le(rs, 103)
}

fn parse_periods_remaining(rs: &[u8]) -> u64 {
    parse_u64_le(rs, 112)
}

// UTXO query helper

async fn query_dca_utxo_value(
    rpc: &NodeClient,
    outpoint: &Outpoint,
    rs: &[u8],
    prefix: &str,
) -> anyhow::Result<u64> {
    let p2sh = build_p2sh(rs);
    let addr = p2sh_to_address(&p2sh.script(), prefix);
    let utxos = rpc.get_utxos_by_addresses(&[&addr]).await?;
    let utxo = utxos
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == outpoint.transaction_id
                && u.outpoint.index == outpoint.index
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "DCA UTXO {} not found at P2SH address {}",
                outpoint,
                addr
            )
        })?;
    Ok(utxo.utxo_entry.amount)
}

// dca deploy

#[allow(clippy::too_many_arguments)]
async fn deploy(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    target_cov_id_hex: &str,
    price_num: u64,
    price_den: u64,
    amount_per_period: u64,
    interval_daa: u64,
    periods: u64,
    value_override: Option<u64>,
    next_exec_override: Option<u64>,
) -> anyhow::Result<()> {
    if periods == 0 {
        anyhow::bail!("periods must be > 0");
    }
    if amount_per_period == 0 {
        anyhow::bail!("amount_per_period must be > 0");
    }
    if interval_daa == 0 {
        anyhow::bail!("interval_daa must be > 0");
    }
    if price_num == 0 || price_den == 0 {
        anyhow::bail!("price_num and price_den must be > 0");
    }

    // Parse target covenant ID
    let tcid_bytes = hex::decode(target_cov_id_hex)?;
    if tcid_bytes.len() != 32 {
        anyhow::bail!("target_cov_id must be 64 hex characters (32 bytes)");
    }
    let mut target_cov_id = [0u8; 32];
    target_cov_id.copy_from_slice(&tcid_bytes);

    // Load wallet
    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    // owner_hash = blake2b_256(pubkey)
    let owner_hash = blake2b_256(&pubkey);

    // Total value to lock
    let total_value = value_override.unwrap_or(amount_per_period.saturating_mul(periods));
    let required = amount_per_period.saturating_mul(periods);
    if total_value < required {
        anyhow::bail!(
            "value {} sompi too small for {} periods * {} sompi/period = {} sompi",
            total_value,
            periods,
            amount_per_period,
            required
        );
    }
    if total_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "total value {} sompi too small (min {})",
            total_value,
            MIN_UTXO_VALUE
        );
    }

    // Determine next_execution_daa
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let next_execution_daa = match next_exec_override {
        Some(v) => v,
        None => {
            let current_daa = rpc.get_daa_score().await?;
            current_daa + interval_daa
        }
    };

    // Build RS
    let redeem_script = contract::build_dca_order_redeem_script(
        &owner_hash,
        &target_cov_id,
        price_num,
        price_den,
        amount_per_period,
        interval_daa,
        next_execution_daa,
        periods,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy dca_order_v2");
    println!("====================");
    println!("Owner Hash:          {}", hex::encode(owner_hash));
    println!("Target Cov ID:       {}", target_cov_id_hex);
    println!("Price:               {}/{}", price_num, price_den);
    println!(
        "Amount per Period:   {} sompi ({:.8} KAS)",
        amount_per_period,
        amount_per_period as f64 / 1e8
    );
    println!("Interval:            {} DAA scores", interval_daa);
    println!("Periods:             {}", periods);
    println!("Next Execution DAA:  {}", next_execution_daa);
    println!(
        "Total Value:         {} sompi ({:.8} KAS)",
        total_value,
        total_value as f64 / 1e8
    );
    println!();
    println!("RedeemScript:        {} bytes", redeem_script.len());
    println!("RS hex:              {}", hex::encode(&redeem_script));
    println!("P2SH SPK:            {}", hex::encode(&p2sh.script()));
    println!();

    info!(
        periods = periods,
        amount_per_period = amount_per_period,
        total = total_value,
        "deploying dca_order_v2"
    );

    // Find funding UTXO
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee = estimate_compute_mass(1, 2, redeem_script.len() + 2);
    let needed = total_value + est_fee;
    let funding = utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= needed)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi found ({} UTXOs available)",
                needed,
                utxos.len()
            )
        })?;

    println!(
        "Funding UTXO: {}:{} ({} sompi)",
        funding.outpoint.transaction_id, funding.outpoint.index, funding.utxo_entry.amount
    );

    let mut tx = Transaction::new(0);

    let spk_bytes = funding.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: funding.outpoint.transaction_id.clone(),
        prev_index: funding.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: funding.utxo_entry.script_public_key.version,
        script_bytes: spk_bytes,
        value: funding.utxo_entry.amount,
    });

    // Output 0: DCA P2SH
    tx.outputs.push(TxOutput::new(total_value, 0, p2sh.script().to_vec(), None));

    // TX payload
    tx.payload = build_order_payload(&redeem_script, false);

    // Output 1: tentative change
    let tentative_change = funding.utxo_entry.amount.saturating_sub(total_value + est_fee);
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output (output 0 = P2SH is fixed)
    let has_change = tx.outputs.len() > 1;
    let (phase1_fee, _) = if has_change {
        let change_idx = tx.outputs.len() - 1;
        converge_fee(&mut tx, funding.utxo_entry.amount, change_idx, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };

    let change = if has_change {
        tx.outputs[tx.outputs.len() - 1].value
    } else {
        funding.utxo_entry.amount.saturating_sub(total_value + phase1_fee)
    };

    // Remove change output if below MIN_UTXO_VALUE
    if has_change && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
    } else if !has_change && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    } else if !has_change && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Sign (phase 1)
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&privkey, &sighash)?;
    let mut sigscripts = vec![signing::build_p2pk_sigscript(&signature)];

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = exact_mass;

    if exact_fee != phase1_fee && tx.outputs.len() > 1 {
        let cidx = tx.outputs.len() - 1;
        let residual = funding.utxo_entry.amount.saturating_sub(total_value);
        let new_change = residual.saturating_sub(exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[cidx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        // Re-sign
        let sighash = compute_sighash(&tx, 0)?;
        let signature = signing::schnorr_sign(&privkey, &sighash)?;
        sigscripts = vec![signing::build_p2pk_sigscript(&signature)];
    }

    let deploy_exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
    let deploy_actual_fee = exact_fee;
    println!("Compute mass:     {:>9} (exact, post-sign)", deploy_exact_compute);
    println!("Miner fee:        {:>9} sompi", deploy_actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting DCA deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! dca_order_v2 deployed.");
    println!("TXID:   {}", tx_id);
    println!();
    println!("DCA Order: {}:0 ({} sompi)", tx_id, total_value);
    println!("RS:        {}", hex::encode(&redeem_script));
    println!();
    println!("Fill command (anyone):");
    println!(
        "  kob-cli dca fill --outpoint {}:0 --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );
    println!();
    println!("Cancel command (owner):");
    println!(
        "  kob-cli dca cancel --outpoint {}:0 --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );

    Ok(())
}

// dca fill

#[allow(clippy::too_many_arguments)]
async fn fill(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    continuation_output_idx: u8,
    order_value_override: Option<u64>,
) -> anyhow::Result<()> {
    let outpoint = Outpoint::parse(outpoint_str)?;
    let old_rs = hex::decode(rs_hex)?;

    // Validate RS length: 120B state + body
    if old_rs.len() < DCA_V2_STATE_LEN {
        anyhow::bail!(
            "Invalid DCA RS: expected at least {} bytes (state), got {}",
            DCA_V2_STATE_LEN,
            old_rs.len()
        );
    }

    // Parse state from current RS
    let owner_hash = parse_owner_hash(&old_rs);
    let target_cov_id = parse_target_cov_id(&old_rs);
    let price_num = parse_price_num(&old_rs);
    let price_den = parse_price_den(&old_rs);
    let amount_per_period = parse_amount_per_period(&old_rs);
    let interval_daa = parse_interval_daa(&old_rs);
    let next_execution_daa = parse_next_execution_daa(&old_rs);
    let periods_remaining = parse_periods_remaining(&old_rs);

    let is_final_fill = periods_remaining == 1;

    println!("Fill dca_order_v2 (period {})", if is_final_fill { "FINAL" } else { "continuation" });
    println!("==============================");
    println!("Outpoint:            {}", outpoint);
    println!("Owner Hash:          {}", hex::encode(owner_hash));
    println!("Target Cov ID:       {}", hex::encode(target_cov_id));
    println!("Price:               {}/{}", price_num, price_den);
    println!(
        "Amount per Period:   {} sompi ({:.8} KAS)",
        amount_per_period,
        amount_per_period as f64 / 1e8
    );
    println!("Interval:            {} DAA", interval_daa);
    println!("Next Execution DAA:  {}", next_execution_daa);
    println!("Periods Remaining:   {}", periods_remaining);
    println!();

    let p2sh = build_p2sh(&old_rs);

    let wallet = WalletFile::load(wallet_path)?;
    let privkey = wallet.private_key_bytes()?;

    info!(
        outpoint = %outpoint,
        periods_remaining = periods_remaining,
        is_final = is_final_fill,
        "filling DCA period"
    );
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get DCA UTXO value
    let order_value = match order_value_override {
        Some(v) => v,
        None => {
            println!("Querying DCA UTXO value...");
            query_dca_utxo_value(&rpc, &outpoint, &old_rs, network.address_prefix()).await?
        }
    };
    println!("Order Value: {} sompi", order_value);

    // Build new RS for continuation (if not final fill)
    let new_rs = if is_final_fill {
        Vec::new()
    } else {
        let new_next_exec = next_execution_daa + interval_daa;
        let new_periods = periods_remaining - 1;
        contract::build_dca_order_redeem_script(
            &owner_hash,
            &target_cov_id,
            price_num,
            price_den,
            amount_per_period,
            interval_daa,
            new_next_exec,
            new_periods,
        )?
    };

    // Need a fee UTXO (estimate: 2-in, 2-out TX)
    let fill_est_fee = estimate_compute_mass(2, 2, 0);
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= fill_est_fee + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                fill_est_fee + MIN_UTXO_VALUE
            )
        })?;

    println!(
        "Fee UTXO:     {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build TX
    let mut tx = Transaction::new(0);

    // Input 0: DCA UTXO
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_utxo.utxo_entry.amount,
    });

    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;

    // Determine filler output index for converge_fee
    let filler_output_idx: usize;

    if is_final_fill {
        // Final fill: no continuation. All funds to filler (minus fee).
        // Use tentative value; converge_fee will adjust.
        let tentative_value = total_in.saturating_sub(fill_est_fee);
        tx.outputs.push(TxOutput::new(tentative_value, fee_utxo.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
        filler_output_idx = 0;
    } else {
        // Continuation: D&R pattern
        let new_p2sh = build_p2sh(&new_rs);
        let continuation_value = order_value - amount_per_period;
        if continuation_value < MIN_UTXO_VALUE {
            anyhow::bail!(
                "Continuation value {} sompi below MIN_UTXO_VALUE ({}). \
                 Remaining funds insufficient for continued DCA.",
                continuation_value,
                MIN_UTXO_VALUE
            );
        }

        // Tentative filler value (adjusted by converge_fee)
        let tentative_filler = total_in.saturating_sub(continuation_value + fill_est_fee);

        if continuation_output_idx == 0 {
            // Output 0: continuation (fixed)
            tx.outputs.push(TxOutput::new(continuation_value, 0, new_p2sh.script().to_vec(), None));
            // Output 1: filler payment (adjustable)
            if tentative_filler >= MIN_UTXO_VALUE {
                tx.outputs.push(TxOutput::new(tentative_filler, fee_utxo.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
                filler_output_idx = 1;
            } else {
                filler_output_idx = 0; // no filler output, fee absorbs all
            }
        } else {
            // Output 0: filler payment (adjustable)
            if tentative_filler >= MIN_UTXO_VALUE {
                tx.outputs.push(TxOutput::new(tentative_filler, fee_utxo.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
            } else {
                anyhow::bail!(
                    "Filler value {} sompi below dust threshold {}. \
                     Use continuation_output_idx=0 or increase fee UTXO.",
                    tentative_filler, MIN_UTXO_VALUE
                );
            }
            // Output at continuation_output_idx: continuation (fixed)
            tx.outputs.push(TxOutput::new(continuation_value, 0, new_p2sh.script().to_vec(), None));
            filler_output_idx = 0;
        }
    }

    // Phase 1: converge fee on filler output
    let (phase1_fee, _) = if filler_output_idx < tx.outputs.len() {
        converge_fee(&mut tx, total_in, filler_output_idx, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };

    if !is_final_fill {
        let continuation_value = order_value - amount_per_period;
        let filler_value = if filler_output_idx < tx.outputs.len() {
            tx.outputs[filler_output_idx].value
        } else {
            0
        };
        println!("Continuation value: {} sompi", continuation_value);
        println!("Filler value:       {} sompi", filler_value);
        println!("New next_exec DAA:  {}", next_execution_daa + interval_daa);
        println!("New periods:        {}", periods_remaining - 1);
        println!("New RS:             {}", hex::encode(&new_rs));
    } else {
        println!("Final fill output:  {} sompi", tx.outputs[0].value);
    }
    println!();

    // Build fill sigscript for input 0
    let fill_ss = contract::build_dca_order_fill_sigscript(
        continuation_output_idx,
        &old_rs,
        &new_rs,
        &old_rs,
    );

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_check = vec![fill_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_check);
    let exact_fee = exact_mass;

    let (fill_ss_final, fee_ss_final) = if exact_fee != phase1_fee && filler_output_idx < tx.outputs.len() {
        // Re-adjust filler output
        let fixed_sum: u64 = tx.outputs.iter().enumerate()
            .filter(|(i, _)| *i != filler_output_idx)
            .map(|(_, o)| o.value)
            .sum();
        let new_filler = total_in.saturating_sub(fixed_sum + exact_fee);
        if new_filler >= MIN_UTXO_VALUE {
            tx.outputs[filler_output_idx].value = new_filler;
        } else if new_filler > 0 {
            println!("Filler value {} sompi below dust after fee adjustment, donated as fee.", new_filler);
            tx.outputs[filler_output_idx].value = 0;
        }
        // Re-build sigscripts (sighash changed)
        let fill_ss2 = contract::build_dca_order_fill_sigscript(
            continuation_output_idx,
            &old_rs,
            &new_rs,
            &old_rs,
        );
        let sighash_1b = compute_sighash(&tx, 1)?;
        let sig_1b = signing::schnorr_sign(&privkey, &sighash_1b)?;
        let fee_ss2 = signing::build_p2pk_sigscript(&sig_1b);
        (fill_ss2, fee_ss2)
    } else {
        (fill_ss, fee_ss)
    };

    let fill_exact_compute = calc_mass_with_sigscripts(&tx, &[fill_ss_final.clone(), fee_ss_final.clone()]);
    println!("Compute mass:     {:>9} (exact, post-sign)", fill_exact_compute);
    println!("Miner fee:        {:>9} sompi", exact_fee);
    println!("Fill SS:  {} bytes", fill_ss_final.len());
    println!("Fee SS:   {} bytes", fee_ss_final.len());
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[fill_ss_final, fee_ss_final]);
    println!("Submitting DCA fill transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!(
        "SUCCESS! DCA period filled ({}).",
        if is_final_fill { "final" } else { "continuation" }
    );
    println!("TXID: {}", tx_id);

    if !is_final_fill {
        println!();
        println!("Next fill command:");
        println!(
            "  kob-cli dca fill --outpoint {}:{} --rs {}",
            tx_id,
            continuation_output_idx,
            hex::encode(&new_rs),
        );
    }

    Ok(())
}

// dca cancel

async fn cancel(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    order_value_override: Option<u64>,
) -> anyhow::Result<()> {
    let outpoint = Outpoint::parse(outpoint_str)?;
    let redeem_script = hex::decode(rs_hex)?;

    if redeem_script.len() < DCA_V2_STATE_LEN {
        anyhow::bail!(
            "Invalid DCA RS: expected at least {} bytes, got {}",
            DCA_V2_STATE_LEN,
            redeem_script.len()
        );
    }

    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    let periods = parse_periods_remaining(&redeem_script);

    println!("Cancel dca_order_v2 (owner recovers funds)");
    println!("============================================");
    println!("Outpoint:           {}", outpoint);
    println!("Periods Remaining:  {}", periods);
    println!("RS:                 {} bytes", redeem_script.len());
    println!("P2SH SPK:           {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, periods = periods, "cancelling DCA order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get DCA UTXO value
    let order_value = match order_value_override {
        Some(v) => v,
        None => {
            println!("Querying DCA UTXO value...");
            query_dca_utxo_value(&rpc, &outpoint, &redeem_script, network.address_prefix()).await?
        }
    };
    println!("Order Value: {} sompi", order_value);

    // Need a fee UTXO (estimate: 2-in, 1-out cancel TX)
    let cancel_est_fee = estimate_compute_mass(2, 1, 0);
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= cancel_est_fee + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                cancel_est_fee + MIN_UTXO_VALUE
            )
        })?;

    println!(
        "Fee UTXO:     {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = order_value + fee_utxo.utxo_entry.amount;

    // Cancel TX layout:
    //   input[0]: DCA UTXO (sigOpCount=1, cancel sigscript)
    //   input[1]: fee UTXO (P2PK, signed)
    //   output[0]: recovered funds to wallet
    let mut tx = Transaction::new(0);

    // Input 0: DCA UTXO
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO
    let fee_spk_bytes = fee_utxo.script_bytes();
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: all recovered funds to wallet (tentative, adjusted by converge_fee)
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let tentative_output = total_in.saturating_sub(cancel_est_fee);
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output 0
    let (phase1_fee, _) = converge_fee(&mut tx, total_in, 0, 0);
    let output_value = tx.outputs[0].value;

    println!("Output Value: {} sompi", output_value);
    println!();

    // Sign input 0 (cancel sigscript)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
    let mut owner_sig = [0u8; 64];
    owner_sig.copy_from_slice(&sig_0);

    let cancel_ss = contract::build_dca_order_cancel_sigscript(
        &owner_sig,
        &pubkey,
        &redeem_script,
    );

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_check = vec![cancel_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_check);
    let exact_fee = exact_mass;

    let (cancel_ss_final, fee_ss_final) = if exact_fee != phase1_fee {
        // Re-adjust output
        let new_output = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = new_output;
        // Re-sign
        let sighash_0b = compute_sighash(&tx, 0)?;
        let sig_0b = signing::schnorr_sign(&privkey, &sighash_0b)?;
        let mut owner_sig2 = [0u8; 64];
        owner_sig2.copy_from_slice(&sig_0b);
        let cancel_ss2 = contract::build_dca_order_cancel_sigscript(
            &owner_sig2,
            &pubkey,
            &redeem_script,
        );
        let sighash_1b = compute_sighash(&tx, 1)?;
        let sig_1b = signing::schnorr_sign(&privkey, &sighash_1b)?;
        let fee_ss2 = signing::build_p2pk_sigscript(&sig_1b);
        (cancel_ss2, fee_ss2)
    } else {
        (cancel_ss, fee_ss)
    };

    let cancel_exact_compute = calc_mass_with_sigscripts(&tx, &[cancel_ss_final.clone(), fee_ss_final.clone()]);
    println!("Compute mass:     {:>9} (exact, post-sign)", cancel_exact_compute);
    println!("Miner fee:        {:>9} sompi", exact_fee);
    println!("Cancel SS:  {} bytes", cancel_ss_final.len());
    println!("Fee SS:     {} bytes", fee_ss_final.len());
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_ss_final, fee_ss_final]);
    println!("Submitting DCA cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! DCA order cancelled.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", tx.outputs[0].value);

    Ok(())
}
