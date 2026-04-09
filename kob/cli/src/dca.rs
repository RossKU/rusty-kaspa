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
use kob_core::{DEFAULT_MATCHER_FEE, MIN_UTXO_VALUE};
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
    let needed = total_value + DEFAULT_MATCHER_FEE;
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

    let change = funding.utxo_entry.amount - total_value - DEFAULT_MATCHER_FEE;

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

    // Output 1: change
    if change >= MIN_UTXO_VALUE {
        let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(change, funding.utxo_entry.script_public_key.version, wallet_spk, None));
    } else if change > 0 {
        println!(
            "Change {} sompi below MIN_UTXO_VALUE, donated as fee.",
            change
        );
    }

    // Sign
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    println!("Sighash:    {}", hex::encode(sighash));
    println!("Signature:  {}...", &hex::encode(signature)[..32]);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript]);
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

    // Need a fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= DEFAULT_MATCHER_FEE + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                DEFAULT_MATCHER_FEE + MIN_UTXO_VALUE
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

    if is_final_fill {
        // Final fill: no continuation. All funds to filler (minus fee).
        let output_value = total_in - DEFAULT_MATCHER_FEE;
        tx.outputs.push(TxOutput::new(output_value, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));
        println!("Final fill output:  {} sompi", output_value);
    } else {
        // Continuation: D&R pattern
        // Output[continuation_output_idx]: continuation UTXO with new RS
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

        // Filler receives amount_per_period + fee change
        let filler_value = amount_per_period + fee_utxo.utxo_entry.amount - DEFAULT_MATCHER_FEE;

        if continuation_output_idx == 0 {
            // Output 0: continuation
            tx.outputs.push(TxOutput::new(continuation_value, 0, new_p2sh.script().to_vec(), None));
            // Output 1: filler payment
            if filler_value >= MIN_UTXO_VALUE {
                tx.outputs.push(TxOutput::new(filler_value, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));
            }
        } else {
            // Output 0: filler payment
            if filler_value >= MIN_UTXO_VALUE {
                tx.outputs.push(TxOutput::new(filler_value, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));
            } else {
                // Filler value below dust — continuation index shifts.
                // Reject to avoid output index mismatch with sigscript.
                anyhow::bail!(
                    "Filler value {} sompi below dust threshold {}. \
                     Use continuation_output_idx=0 or increase fee UTXO.",
                    filler_value, MIN_UTXO_VALUE
                );
            }
            // Output at continuation_output_idx: continuation
            tx.outputs.push(TxOutput::new(continuation_value, 0, new_p2sh.script().to_vec(), None));
        }

        println!("Continuation value: {} sompi", continuation_value);
        println!("Filler value:       {} sompi", filler_value);
        println!("New next_exec DAA:  {}", next_execution_daa + interval_daa);
        println!("New periods:        {}", periods_remaining - 1);
        println!("New RS:             {}", hex::encode(&new_rs));
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

    println!("Fill SS:  {} bytes", fill_ss.len());
    println!("Fee SS:   {} bytes", fee_ss.len());
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[fill_ss, fee_ss]);
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

    // Need a fee UTXO
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= DEFAULT_MATCHER_FEE + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                DEFAULT_MATCHER_FEE + MIN_UTXO_VALUE
            )
        })?;

    println!(
        "Fee UTXO:     {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let output_value = total_in - DEFAULT_MATCHER_FEE;

    println!("Output Value: {} sompi", output_value);
    println!();

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

    // Output 0: all recovered funds to wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(output_value, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

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

    println!("Cancel SS:  {} bytes", cancel_ss.len());
    println!("Fee SS:     {} bytes", fee_ss.len());
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_ss, fee_ss]);
    println!("Submitting DCA cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! DCA order cancelled.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}
