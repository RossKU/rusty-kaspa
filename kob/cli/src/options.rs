//! `kob-cli option` -- Deploy, exercise, cancel, and expire option contracts.
//!
//! Subcommands:
//!   deploy-call  -- Deploy a call option (call_option_v2: 133B RS)
//!   deploy-put   -- Deploy a put option (put_option_v3: 179B RS)
//!   exercise     -- Exercise an option (holder buys/sells at strike)
//!   cancel       -- Cancel an option (writer recovers collateral, v2/v3 anytime)
//!   expire       -- Expire an option (writer reclaims after expiry, v3/v4 CLTV-enforced)
//!
//! ## Call Option (call_option_v2)
//!
//! Writer locks collateral (tokens). Holder has the right to BUY tokens at
//! strike_kas. On exercise, holder pays >= strike_kas to writer (verified by
//! output[0].value + SPK destination check), and receives the token collateral.
//!
//! RS = 133B (108B state + 25B body)
//! State: [writer_pk 32B][holder_pk 32B][strike_kas 8B][writer_spk_hash 32B]
//!
//! Exercise sigscript: [pushData(sig_h 65B)][Op1][pushData(RS 133B)]
//! Cancel sigscript:   [pushData(sig_w 65B)][Op0][pushData(RS 133B)]
//!
//! ## Put Option (put_option_v3)
//!
//! Writer locks collateral (KAS). Holder has the right to SELL tokens at
//! strike_kas. On exercise, holder delivers tokens (OpCovInputCount >= 1),
//! and receives >= strike_kas from the UTXO. Writer receives both the KAS
//! payment (output[0]) and the delivered tokens (output[1]) -- both destinations
//! verified via writer_spk_hash.
//!
//! RS = 179B (141B state + 38B body)
//! State: [writer_pk 32B][holder_pk 32B][strike_kas 8B][token_cov_id 32B][writer_spk_hash 32B]
//!
//! Exercise sigscript: [pushData(sig_h 65B)][Op1][pushData(RS 179B)]
//! Cancel sigscript:   [pushData(sig_w 65B)][Op0][pushData(RS 179B)]

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
pub enum OptionCommand {
    /// Deploy a call option (call_option_v2). Writer locks token collateral.
    DeployCall {
        /// Writer's public key (hex, 64 chars). Defaults to wallet pubkey.
        #[arg(long)]
        writer_pk: Option<String>,

        /// Holder's public key (hex, 64 chars). The party who can exercise.
        #[arg(long)]
        holder_pk: String,

        /// Strike price in sompi (KAS amount holder pays on exercise).
        #[arg(long)]
        strike: u64,

        /// Amount of collateral to lock in the option UTXO (sompi).
        #[arg(long)]
        amount: u64,

        /// Start DAA score (exercise window opens). 0 = immediately exercisable.
        #[arg(long, default_value_t = 0)]
        start_daa: u64,

        /// Expiry DAA score (exercise window closes). Default = no expiry.
        #[arg(long, default_value_t = u64::MAX)]
        expiry_daa: u64,
    },

    /// Deploy a put option (put_option_v3). Writer locks KAS collateral.
    DeployPut {
        /// Writer's public key (hex, 64 chars). Defaults to wallet pubkey.
        #[arg(long)]
        writer_pk: Option<String>,

        /// Holder's public key (hex, 64 chars). The party who can exercise.
        #[arg(long)]
        holder_pk: String,

        /// Strike price in sompi (KAS amount writer pays on exercise).
        #[arg(long)]
        strike: u64,

        /// Token covenant ID (hex, 64 chars). Tokens holder must deliver on exercise.
        #[arg(long)]
        token_cov_id: String,

        /// Amount of KAS collateral to lock (sompi).
        #[arg(long)]
        amount: u64,

        /// Start DAA score (exercise window opens). 0 = immediately exercisable.
        #[arg(long, default_value_t = 0)]
        start_daa: u64,

        /// Expiry DAA score (exercise window closes). Default = no expiry.
        #[arg(long, default_value_t = u64::MAX)]
        expiry_daa: u64,
    },

    /// Exercise an option (holder path). Requires holder's wallet.
    Exercise {
        /// Option UTXO outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Option type: "call" or "put".
        #[arg(long, name = "type")]
        option_type: String,

        /// RedeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Option UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        option_value: Option<u64>,
    },

    /// Cancel an option (writer path). Writer recovers collateral.
    Cancel {
        /// Option UTXO outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Option type: "call" or "put".
        #[arg(long, name = "type")]
        option_type: String,

        /// RedeemScript (hex).
        #[arg(long)]
        rs: String,

        /// Option UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        option_value: Option<u64>,
    },

    /// Expire an option (writer reclaims collateral after expiry).
    ///
    /// For call_option_v3 (RS=159B) and put_option_v4 (RS=205B) contracts that
    /// enforce an on-chain exercise window. The cancel path uses CLTV to ensure
    /// expiry_daa <= tx.lockTime, so the TX is only valid after the option expires.
    ///
    /// If --lock-time is omitted, the current virtual DAA score is used.
    Expire {
        /// Option UTXO outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Option type: "call" or "put".
        #[arg(long, name = "type")]
        option_type: String,

        /// RedeemScript (hex). Must be 159B (call_option_v3) or 205B (put_option_v4).
        #[arg(long)]
        rs: String,

        /// Option UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        option_value: Option<u64>,

        /// TX lockTime (DAA score). Must be >= expiry_daa encoded in the RS.
        /// Defaults to the current virtual DAA score if omitted.
        #[arg(long)]
        lock_time: Option<u64>,
    },
}

/// Build the 36-byte owner SPK: [version_u16_le(2B)] [0x20] [pubkey(32B)] [0xac]
fn build_owner_spk(pubkey: &[u8; 32]) -> [u8; 36] {
    let mut spk = [0u8; 36];
    // version = 0 as u16 LE (already zeroed)
    spk[2] = 0x20; // push 32 bytes
    spk[3..35].copy_from_slice(pubkey);
    spk[35] = 0xac; // OpCheckSig
    spk
}

/// Dispatch option subcommand.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    cmd: &OptionCommand,
) -> anyhow::Result<()> {
    match cmd {
        OptionCommand::DeployCall {
            writer_pk,
            holder_pk,
            strike,
            amount,
            start_daa,
            expiry_daa,
        } => {
            deploy_call(
                wallet_path,
                node_url,
                network,
                writer_pk.as_deref(),
                holder_pk,
                *strike,
                *amount,
                *start_daa,
                *expiry_daa,
            )
            .await
        }
        OptionCommand::DeployPut {
            writer_pk,
            holder_pk,
            strike,
            token_cov_id,
            amount,
            start_daa,
            expiry_daa,
        } => {
            deploy_put(
                wallet_path,
                node_url,
                network,
                writer_pk.as_deref(),
                holder_pk,
                *strike,
                token_cov_id,
                *amount,
                *start_daa,
                *expiry_daa,
            )
            .await
        }
        OptionCommand::Exercise {
            outpoint,
            option_type,
            rs,
            option_value,
        } => {
            exercise(
                wallet_path,
                node_url,
                network,
                outpoint,
                option_type,
                rs,
                *option_value,
            )
            .await
        }
        OptionCommand::Cancel {
            outpoint,
            option_type,
            rs,
            option_value,
        } => {
            cancel(
                wallet_path,
                node_url,
                network,
                outpoint,
                option_type,
                rs,
                *option_value,
            )
            .await
        }
        OptionCommand::Expire {
            outpoint,
            option_type,
            rs,
            option_value,
            lock_time,
        } => {
            expire(
                wallet_path,
                node_url,
                network,
                outpoint,
                option_type,
                rs,
                *option_value,
                *lock_time,
            )
            .await
        }
    }
}

// option deploy-call

#[allow(clippy::too_many_arguments)]
async fn deploy_call(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    writer_pk_hex: Option<&str>,
    holder_pk_hex: &str,
    strike: u64,
    amount: u64,
    start_daa: u64,
    expiry_daa: u64,
) -> anyhow::Result<()> {
    if strike == 0 {
        anyhow::bail!("strike must be > 0");
    }
    if amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "amount {} sompi too small (min {})",
            amount,
            MIN_UTXO_VALUE
        );
    }

    // Parse holder pubkey
    let holder_bytes = hex::decode(holder_pk_hex)?;
    if holder_bytes.len() != 32 {
        anyhow::bail!("holder_pk must be 64 hex characters (32 bytes)");
    }
    let mut holder_pk = [0u8; 32];
    holder_pk.copy_from_slice(&holder_bytes);

    // Load wallet
    let wallet = WalletFile::load(wallet_path)?;
    let wallet_pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    // Writer PK: use provided or default to wallet
    let writer_pk = if let Some(wpk_hex) = writer_pk_hex {
        let wpk_bytes = hex::decode(wpk_hex)?;
        if wpk_bytes.len() != 32 {
            anyhow::bail!("writer_pk must be 64 hex characters (32 bytes)");
        }
        let mut wpk = [0u8; 32];
        wpk.copy_from_slice(&wpk_bytes);
        wpk
    } else {
        wallet_pubkey
    };

    // Writer SPK hash = Blake2b-256( [version 2B] [0x20] [writer_pk 32B] [0xac] )
    let writer_spk = build_owner_spk(&writer_pk);
    let writer_spk_hash = blake2b_256(&writer_spk);

    // Build call_option redeemScript (149B)
    let redeem_script = contract::build_call_option_redeem_script(
        &writer_pk,
        &holder_pk,
        strike,
        &writer_spk_hash,
        start_daa,
        expiry_daa,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy call_option_v2");
    println!("======================");
    println!("Writer PK:       {}", hex::encode(writer_pk));
    println!("Holder PK:       {}", holder_pk_hex);
    println!(
        "Strike:          {} sompi ({:.8} KAS)",
        strike,
        strike as f64 / 1e8
    );
    println!(
        "Amount:          {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    println!("Writer SPK Hash: {}", hex::encode(writer_spk_hash));
    println!();
    println!("RedeemScript:    {} bytes", redeem_script.len());
    println!("RS hex:          {}", hex::encode(&redeem_script));
    println!("P2SH SPK:        {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and deploy
    info!(strike = strike, amount = amount, "deploying call_option_v2");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee_budget = estimate_compute_mass(1, 2, 0) + 500;
    let needed = amount + est_fee_budget;
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

    let total_input = funding.utxo_entry.amount;

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

    // Output 0: call_option_v2 P2SH
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

    // TX payload
    tx.payload = build_order_payload(&redeem_script, false);

    // Output 1: tentative change for mass calculation
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    let tentative_change = total_input.saturating_sub(amount + est_fee_budget);
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };
    let (est_fee, _) = if has_change {
        converge_fee(&mut tx, total_input, change_idx, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };
    let change = if has_change { tx.outputs[change_idx].value } else { total_input.saturating_sub(amount + est_fee) };
    if has_change && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change); }
    } else if !has_change && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    } else if !has_change && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Phase 1: sign
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    // Phase 2: exact mass check
    let sigscripts_vec = vec![sigscript];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_vec);
    let exact_fee = exact_mass;
    let sigscript = if exact_fee > est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE { tx.outputs[change_idx].value = new_change; }
        else {
            tx.outputs.pop();
            if new_change > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change); }
        }
        let sighash = compute_sighash(&tx, 0)?;
        let signature = signing::schnorr_sign(&privkey, &sighash)?;
        signing::build_p2pk_sigscript(&signature)
    } else {
        sigscripts_vec.into_iter().next().unwrap()
    };

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting call option deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! call_option_v2 deployed.");
    println!("TXID:   {}", tx_id);
    println!();
    println!("Option: {}:0 ({} sompi)", tx_id, amount);
    println!("RS:     {}", hex::encode(&redeem_script));
    println!();
    println!("Exercise command (holder):");
    println!(
        "  kob-cli option exercise --outpoint {}:0 --option-type call --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );
    println!();
    println!("Cancel command (writer):");
    println!(
        "  kob-cli option cancel --outpoint {}:0 --option-type call --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );

    Ok(())
}

// option deploy-put

#[allow(clippy::too_many_arguments)]
async fn deploy_put(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    writer_pk_hex: Option<&str>,
    holder_pk_hex: &str,
    strike: u64,
    token_cov_id_hex: &str,
    amount: u64,
    start_daa: u64,
    expiry_daa: u64,
) -> anyhow::Result<()> {
    if strike == 0 {
        anyhow::bail!("strike must be > 0");
    }
    if amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "amount {} sompi too small (min {})",
            amount,
            MIN_UTXO_VALUE
        );
    }

    // Parse holder pubkey
    let holder_bytes = hex::decode(holder_pk_hex)?;
    if holder_bytes.len() != 32 {
        anyhow::bail!("holder_pk must be 64 hex characters (32 bytes)");
    }
    let mut holder_pk = [0u8; 32];
    holder_pk.copy_from_slice(&holder_bytes);

    // Parse token covenant ID
    let tcid_bytes = hex::decode(token_cov_id_hex)?;
    if tcid_bytes.len() != 32 {
        anyhow::bail!("token_cov_id must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&tcid_bytes);

    // Load wallet
    let wallet = WalletFile::load(wallet_path)?;
    let wallet_pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    // Writer PK
    let writer_pk = if let Some(wpk_hex) = writer_pk_hex {
        let wpk_bytes = hex::decode(wpk_hex)?;
        if wpk_bytes.len() != 32 {
            anyhow::bail!("writer_pk must be 64 hex characters (32 bytes)");
        }
        let mut wpk = [0u8; 32];
        wpk.copy_from_slice(&wpk_bytes);
        wpk
    } else {
        wallet_pubkey
    };

    // Writer SPK hash
    let writer_spk = build_owner_spk(&writer_pk);
    let writer_spk_hash = blake2b_256(&writer_spk);

    // Build put_option redeemScript (197B)
    let redeem_script = contract::build_put_option_redeem_script(
        &writer_pk,
        &holder_pk,
        strike,
        &token_cov_id,
        &writer_spk_hash,
        start_daa,
        expiry_daa,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy put_option_v3");
    println!("=====================");
    println!("Writer PK:       {}", hex::encode(writer_pk));
    println!("Holder PK:       {}", holder_pk_hex);
    println!(
        "Strike:          {} sompi ({:.8} KAS)",
        strike,
        strike as f64 / 1e8
    );
    println!("Token Cov ID:    {}", token_cov_id_hex);
    println!(
        "Amount:          {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    println!("Writer SPK Hash: {}", hex::encode(writer_spk_hash));
    println!();
    println!("RedeemScript:    {} bytes", redeem_script.len());
    println!("RS hex:          {}", hex::encode(&redeem_script));
    println!("P2SH SPK:        {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and deploy
    info!(strike = strike, amount = amount, "deploying put_option_v3");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee_budget = estimate_compute_mass(1, 2, 0) + 500;
    let needed = amount + est_fee_budget;
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

    let total_input = funding.utxo_entry.amount;

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

    // Output 0: put_option_v3 P2SH
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

    // TX payload
    tx.payload = build_order_payload(&redeem_script, false);

    // Output 1: tentative change for mass calculation
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    let tentative_change = total_input.saturating_sub(amount + est_fee_budget);
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };
    let (est_fee, _) = if has_change {
        converge_fee(&mut tx, total_input, change_idx, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };
    let change = if has_change { tx.outputs[change_idx].value } else { total_input.saturating_sub(amount + est_fee) };
    if has_change && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change); }
    } else if !has_change && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    } else if !has_change && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Phase 1: sign
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    // Phase 2: exact mass check
    let sigscripts_vec = vec![sigscript];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_vec);
    let exact_fee = exact_mass;
    let sigscript = if exact_fee > est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE { tx.outputs[change_idx].value = new_change; }
        else {
            tx.outputs.pop();
            if new_change > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change); }
        }
        let sighash = compute_sighash(&tx, 0)?;
        let signature = signing::schnorr_sign(&privkey, &sighash)?;
        signing::build_p2pk_sigscript(&signature)
    } else {
        sigscripts_vec.into_iter().next().unwrap()
    };

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting put option deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! put_option_v3 deployed.");
    println!("TXID:   {}", tx_id);
    println!();
    println!("Option: {}:0 ({} sompi)", tx_id, amount);
    println!("RS:     {}", hex::encode(&redeem_script));
    println!();
    println!("Exercise command (holder):");
    println!(
        "  kob-cli option exercise --outpoint {}:0 --option-type put --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );
    println!();
    println!("Cancel command (writer):");
    println!(
        "  kob-cli option cancel --outpoint {}:0 --option-type put --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );

    Ok(())
}

// option exercise

/// Query a P2SH UTXO value by outpoint.
async fn query_option_utxo_value(
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
                "Option UTXO {} not found at P2SH address {}",
                outpoint,
                addr
            )
        })?;
    Ok(utxo.utxo_entry.amount)
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    option_type: &str,
    rs_hex: &str,
    option_value_override: Option<u64>,
) -> anyhow::Result<()> {
    if option_type != "call" && option_type != "put" {
        anyhow::bail!("option type must be 'call' or 'put', got '{}'", option_type);
    }

    let outpoint = Outpoint::parse(outpoint_str)?;
    let redeem_script = hex::decode(rs_hex)?;

    // Validate RS size
    let expected_rs_len = if option_type == "call" { 159 } else { 205 };
    if redeem_script.len() != expected_rs_len {
        anyhow::bail!(
            "Invalid {} option: redeemScript must be {} bytes, but got {}. \
             Check that the --rs value matches the option type and contract version.",
            option_type,
            expected_rs_len,
            redeem_script.len()
        );
    }

    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletFile::load(wallet_path)?;
    let privkey = wallet.private_key_bytes()?;

    println!("Exercise {} option", option_type);
    println!("========================");
    println!("Outpoint:  {}", outpoint);
    println!("Type:      {}", option_type);
    println!("RS:        {} bytes", redeem_script.len());
    println!("P2SH SPK:  {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, option_type = option_type, "exercising option");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get option UTXO value
    let option_value = match option_value_override {
        Some(v) => v,
        None => {
            println!("Querying option UTXO value...");
            query_option_utxo_value(&rpc, &outpoint, &redeem_script, network.address_prefix()).await?
        }
    };
    println!("Option Value: {} sompi", option_value);

    // Need a fee UTXO (must cover strike_kas for call exercise + miner fee)
    let est_fee_budget = estimate_compute_mass(2, 3, 0) + 500;
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_budget + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee + exercise payment",
                est_fee_budget + MIN_UTXO_VALUE
            )
        })?;

    println!(
        "Fee UTXO:     {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build exercise TX
    // For call option exercise:
    //   input[0]: call_option UTXO (sigOpCount=1, exercise sigscript)
    //   input[1]: fee/payment UTXO (P2PK, signed)
    //   output[0]: writer receives >= strike_kas (enforced by contract)
    //   output[1]: holder receives option UTXO value (token collateral)
    //   output[2]: change (optional)
    //
    // For put option exercise:
    //   input[0]: put_option UTXO (sigOpCount=1, exercise sigscript)
    //   input[1]: token UTXO (covenant token delivery, sigOpCount=1)
    //   input[2]: fee UTXO (P2PK, signed)
    //   output[0]: writer receives >= strike_kas (enforced by contract)
    //   output[1]: writer receives tokens (enforced by v3 contract)
    //   output[2]: holder receives remaining KAS
    //   output[3]: change (optional)
    //
    // NOTE: For a full production exercise, the holder needs to arrange proper
    // output values. Here we build a basic exercise TX structure. For call options,
    // the fee UTXO must cover strike_kas payment to writer. For put options,
    // a token input is needed (not fully handled here -- requires token UTXO selection).

    // Extract strike_kas from RS state
    let strike_bytes: [u8; 8] = redeem_script[67..75]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid option contract: the redeemScript is too short to contain a valid strike price. \
             Check that the --rs value is correct."))?;
    let strike_kas = u64::from_le_bytes(strike_bytes);

    println!("Strike:       {} sompi ({:.8} KAS)", strike_kas, strike_kas as f64 / 1e8);

    // Extract writer_spk_hash from RS to determine writer destination
    let writer_spk_hash_offset = if option_type == "call" { 76 } else { 109 };
    let _writer_spk_hash = &redeem_script[writer_spk_hash_offset..writer_spk_hash_offset + 32];

    // For call exercise: holder pays strike_kas, receives collateral
    // For put exercise: holder delivers tokens, receives KAS
    if option_type == "call" {
        // Call exercise TX
        let total_in = option_value + fee_utxo.utxo_entry.amount;
        if fee_utxo.utxo_entry.amount < strike_kas + est_fee_budget {
            anyhow::bail!(
                "Fee UTXO ({} sompi) insufficient to cover strike ({}) + estimated fee ({}). Need >= {} sompi.",
                fee_utxo.utxo_entry.amount,
                strike_kas,
                est_fee_budget,
                strike_kas + est_fee_budget
            );
        }

        let holder_receives = option_value; // collateral tokens/value
        let fixed_out = strike_kas + holder_receives;

        let mut tx = Transaction::new(0);

        // Input 0: option UTXO (sigOpCount=1 for exercise path)
        tx.inputs.push(TxInput {
            prev_tx_id: outpoint.transaction_id.clone(),
            prev_index: outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: p2sh.version,
            script_bytes: p2sh.script().to_vec(),
            value: option_value,
        });

        // Input 1: fee/payment UTXO
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

        // Output 0: writer receives strike_kas
        let writer_pk = &redeem_script[1..33];
        let writer_spk_full = {
            let mut spk = Vec::with_capacity(34);
            spk.push(0x20);
            spk.extend_from_slice(writer_pk);
            spk.push(0xac);
            spk
        };
        tx.outputs.push(TxOutput::new(strike_kas, 0, writer_spk_full, None));

        // Output 1: holder receives collateral
        let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(holder_receives, 0, wallet_spk.clone(), None));

        // Output 2: tentative change for mass calculation
        let tentative_change = total_in.saturating_sub(fixed_out + est_fee_budget);
        if tentative_change >= MIN_UTXO_VALUE {
            tx.outputs.push(TxOutput::new(tentative_change, fee_utxo.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
        }

        // Phase 1: converge fee on change output (if present)
        let has_change = tentative_change >= MIN_UTXO_VALUE;
        let (est_fee, _) = if has_change {
            let change_idx = tx.outputs.len() - 1;
            converge_fee(&mut tx, total_in, change_idx, 0)
        } else {
            let f = kob_core::mass::calc_miner_fee(&tx);
            (f, 0)
        };

        let change = if has_change { tx.outputs.last().unwrap().value } else { total_in.saturating_sub(fixed_out + est_fee) };
        if has_change && change < MIN_UTXO_VALUE {
            tx.outputs.pop();
            if change > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change); }
        } else if !has_change && change >= MIN_UTXO_VALUE {
            tx.outputs.push(TxOutput::new(change, fee_utxo.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
        } else if !has_change && change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }

        println!();
        println!("TX Layout:");
        println!("  input[0]:  call_option UTXO ({} sompi)", option_value);
        println!("  input[1]:  fee/payment UTXO ({} sompi)", fee_utxo.utxo_entry.amount);
        println!("  output[0]: writer receives {} sompi (strike)", strike_kas);
        println!("  output[1]: holder receives {} sompi (collateral)", holder_receives);
        if change >= MIN_UTXO_VALUE {
            println!("  output[2]: change {} sompi", change);
        }
        println!();

        // Sign input 0 (exercise sigscript)
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let mut holder_sig = [0u8; 64];
        holder_sig.copy_from_slice(&sig_0);
        let exercise_ss =
            contract::build_call_option_exercise_sigscript(&holder_sig, &redeem_script);

        // Sign input 1 (fee UTXO, P2PK)
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_ss = signing::build_p2pk_sigscript(&sig_1);

        // Phase 2: exact mass check with real sigscripts
        let sigscripts_ex = vec![exercise_ss.clone(), fee_ss.clone()];
        let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_ex);
        let exact_fee = exact_mass;

        let (exercise_ss, fee_ss, actual_fee) = if exact_fee > est_fee {
            // Re-adjust change output
            if tx.outputs.len() > 2 {
                let change_idx = tx.outputs.len() - 1;
                let new_change = total_in.saturating_sub(fixed_out + exact_fee);
                if new_change >= MIN_UTXO_VALUE { tx.outputs[change_idx].value = new_change; }
                else {
                    tx.outputs.pop();
                    if new_change > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change); }
                }
            }
            // Re-sign
            let sighash_0 = compute_sighash(&tx, 0)?;
            let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
            let mut holder_sig = [0u8; 64];
            holder_sig.copy_from_slice(&sig_0);
            let exercise_ss = contract::build_call_option_exercise_sigscript(&holder_sig, &redeem_script);
            let sighash_1 = compute_sighash(&tx, 1)?;
            let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
            let fee_ss = signing::build_p2pk_sigscript(&sig_1);
            (exercise_ss, fee_ss, exact_fee)
        } else {
            (exercise_ss, fee_ss, est_fee)
        };

        println!("Exercise SS: {} bytes", exercise_ss.len());
        println!("Fee SS:      {} bytes", fee_ss.len());
        println!("Miner fee:   {} sompi", actual_fee);
        println!();

        // Submit
        let payload = to_rpc_payload(&tx, &[exercise_ss, fee_ss]);
        println!("Submitting call option exercise transaction...");
        let tx_id = rpc.submit_transaction(payload).await?;

        println!();
        println!("SUCCESS! Call option exercised.");
        println!("TXID: {}", tx_id);
        println!();
        println!("Writer received: {}:0 ({} sompi, strike payment)", tx_id, strike_kas);
        println!("Holder received: {}:1 ({} sompi, collateral)", tx_id, holder_receives);
    } else {
        // Put exercise TX -- requires token input
        // For now, build the basic structure. The holder needs to provide a token UTXO.
        anyhow::bail!(
            "Put option exercise requires a token UTXO input (covenant token delivery). \
             Use the transaction builder directly or provide --token-outpoint in a future release. \
             The put_option_v3 exercise TX must include a covenant token input at input[1] \
             matching token_cov_id from the RS state."
        );
    }

    Ok(())
}

// option cancel

#[allow(clippy::too_many_arguments)]
async fn cancel(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    option_type: &str,
    rs_hex: &str,
    option_value_override: Option<u64>,
) -> anyhow::Result<()> {
    if option_type != "call" && option_type != "put" {
        anyhow::bail!("option type must be 'call' or 'put', got '{}'", option_type);
    }

    let outpoint = Outpoint::parse(outpoint_str)?;
    let redeem_script = hex::decode(rs_hex)?;

    // Validate RS size
    let expected_rs_len = if option_type == "call" { 159 } else { 205 };
    if redeem_script.len() != expected_rs_len {
        anyhow::bail!(
            "Invalid {} option: redeemScript must be {} bytes, but got {}. \
             Check that the --rs value matches the option type and contract version.",
            option_type,
            expected_rs_len,
            redeem_script.len()
        );
    }

    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletFile::load(wallet_path)?;
    let privkey = wallet.private_key_bytes()?;

    println!("Cancel {} option (writer recovers collateral)", option_type);
    println!("================================================");
    println!("Outpoint:  {}", outpoint);
    println!("Type:      {}", option_type);
    println!("RS:        {} bytes", redeem_script.len());
    println!("P2SH SPK:  {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, option_type = option_type, "cancelling option");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get option UTXO value
    let option_value = match option_value_override {
        Some(v) => v,
        None => {
            println!("Querying option UTXO value...");
            query_option_utxo_value(&rpc, &outpoint, &redeem_script, network.address_prefix()).await?
        }
    };
    println!("Option Value: {} sompi", option_value);

    // Need a fee UTXO
    let est_fee_budget = estimate_compute_mass(2, 1, 0) + 500;
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_budget + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                est_fee_budget + MIN_UTXO_VALUE
            )
        })?;

    println!(
        "Fee UTXO:     {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = option_value + fee_utxo.utxo_entry.amount;

    // Extract expiry_daa from RS state to set tx.lock_time (CLTV on cancel path)
    let expiry_offset = if option_type == "call" { 118 } else { 151 };
    let expiry_bytes: [u8; 8] = redeem_script[expiry_offset..expiry_offset + 8]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid RS: cannot extract expiry_daa"))?;
    let expiry_daa = u64::from_le_bytes(expiry_bytes);
    println!("Expiry DAA:   {}", expiry_daa);

    // Cancel TX layout:
    //   input[0]: option UTXO (sigOpCount=1, cancel sigscript)
    //   input[1]: fee UTXO (P2PK, signed)
    //   output[0]: recovered funds to wallet
    let mut tx = Transaction::new(0);
    tx.lock_time = expiry_daa;

    // Input 0: option UTXO (sigOpCount=1 for cancel path)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: option_value,
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
    let tentative_output = total_in.saturating_sub(est_fee_budget);
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output[0]
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, 0);

    // Sign input 0 (cancel sigscript)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
    let mut writer_sig = [0u8; 64];
    writer_sig.copy_from_slice(&sig_0);

    let cancel_ss = if option_type == "call" {
        contract::build_call_option_cancel_sigscript(&writer_sig, &redeem_script)
    } else {
        contract::build_put_option_cancel_sigscript(&writer_sig, &redeem_script)
    };

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_cancel = vec![cancel_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_cancel);
    let exact_fee = exact_mass;

    let (cancel_ss, fee_ss, actual_fee) = if exact_fee > est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let mut writer_sig = [0u8; 64];
        writer_sig.copy_from_slice(&sig_0);
        let cancel_ss = if option_type == "call" {
            contract::build_call_option_cancel_sigscript(&writer_sig, &redeem_script)
        } else {
            contract::build_put_option_cancel_sigscript(&writer_sig, &redeem_script)
        };
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_ss = signing::build_p2pk_sigscript(&sig_1);

        (cancel_ss, fee_ss, exact_fee)
    } else {
        (cancel_ss, fee_ss, est_fee)
    };

    let output_value = tx.outputs[0].value;

    println!("Cancel SS:  {} bytes", cancel_ss.len());
    println!("Fee SS:     {} bytes", fee_ss.len());
    println!("Output Value: {} sompi", output_value);
    println!("Miner fee:    {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_ss, fee_ss]);
    println!("Submitting option cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! {} option cancelled.", option_type);
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

// option expire

#[allow(clippy::too_many_arguments)]
async fn expire(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    option_type: &str,
    rs_hex: &str,
    option_value_override: Option<u64>,
    lock_time_override: Option<u64>,
) -> anyhow::Result<()> {
    if option_type != "call" && option_type != "put" {
        anyhow::bail!("option type must be 'call' or 'put', got '{}'", option_type);
    }

    let outpoint = Outpoint::parse(outpoint_str)?;
    let redeem_script = hex::decode(rs_hex)?;

    // Validate RS size — expire targets v3 call (159B) / v4 put (205B) contracts
    let expected_rs_len = if option_type == "call" { 159 } else { 205 };
    if redeem_script.len() != expected_rs_len {
        anyhow::bail!(
            "Invalid {} option for expire: redeemScript must be {} bytes ({}), but got {}. \
             Expire requires call_option_v3 (159B) or put_option_v4 (205B) contracts \
             with on-chain exercise window enforcement. \
             For v2/v3 contracts without exercise windows, use 'cancel' instead.",
            option_type,
            expected_rs_len,
            if option_type == "call" { "call_option_v3" } else { "put_option_v4" },
            redeem_script.len()
        );
    }

    // Extract expiry_daa from RS state.
    // call_option_v3 state: [0x20][wp 32B][0x20][hp 32B][0x08][sk 8B][0x20][wsh 32B][0x08][start 8B][0x08][expiry 8B]
    //   expiry offset: 1+32+1+32+1+8+1+32+1+8+1 = 118..126
    // put_option_v4 state: [0x20][wp 32B][0x20][hp 32B][0x08][sk 8B][0x20][tcid 32B][0x20][wsh 32B][0x08][start 8B][0x08][expiry 8B]
    //   expiry offset: 1+32+1+32+1+8+1+32+1+32+1+8+1 = 151..159
    let expiry_offset = if option_type == "call" { 118 } else { 151 };
    let expiry_bytes: [u8; 8] = redeem_script[expiry_offset..expiry_offset + 8]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to extract expiry_daa from RS"))?;
    let expiry_daa = u64::from_le_bytes(expiry_bytes);

    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletFile::load(wallet_path)?;
    let privkey = wallet.private_key_bytes()?;

    println!("Expire {} option (writer reclaims collateral after expiry)", option_type);
    println!("=============================================================");
    println!("Outpoint:    {}", outpoint);
    println!("Type:        {}", option_type);
    println!("RS:          {} bytes", redeem_script.len());
    println!("P2SH SPK:    {}", hex::encode(&p2sh.script()));
    println!("Expiry DAA:  {}", expiry_daa);
    println!();

    info!(outpoint = %outpoint, option_type = option_type, expiry_daa = expiry_daa, "expiring option");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine lock_time: must be >= expiry_daa for CLTV to pass
    let lock_time = match lock_time_override {
        Some(lt) => {
            if lt < expiry_daa {
                anyhow::bail!(
                    "lock-time {} is less than expiry_daa {}. \
                     The CLTV check requires lockTime >= expiry_daa.",
                    lt,
                    expiry_daa
                );
            }
            lt
        }
        None => {
            let current_daa = rpc.get_daa_score().await?;
            println!("Current DAA: {}", current_daa);
            if current_daa < expiry_daa {
                anyhow::bail!(
                    "Option has not expired yet. Current DAA score {} < expiry_daa {}. \
                     The option will be expirable after DAA score {}.",
                    current_daa,
                    expiry_daa,
                    expiry_daa
                );
            }
            current_daa
        }
    };
    println!("Lock Time:   {}", lock_time);

    // Get option UTXO value
    let option_value = match option_value_override {
        Some(v) => v,
        None => {
            println!("Querying option UTXO value...");
            query_option_utxo_value(&rpc, &outpoint, &redeem_script, network.address_prefix()).await?
        }
    };
    println!("Option Value: {} sompi", option_value);

    // Need a fee UTXO
    let est_fee_budget = estimate_compute_mass(2, 1, 0) + 500;
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_budget + MIN_UTXO_VALUE)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                est_fee_budget + MIN_UTXO_VALUE
            )
        })?;

    println!(
        "Fee UTXO:     {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = option_value + fee_utxo.utxo_entry.amount;

    // Expire TX layout (same as cancel, but with lock_time set):
    //   input[0]: option UTXO (sigOpCount=1, cancel/expire sigscript with Op0 selector)
    //   input[1]: fee UTXO (P2PK, signed)
    //   output[0]: recovered funds to wallet
    let mut tx = Transaction::new(0);
    tx.lock_time = lock_time;

    // Input 0: option UTXO (sigOpCount=1 for cancel/expire path)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: option_value,
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
    let tentative_output = total_in.saturating_sub(est_fee_budget);
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output[0]
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, 0);

    // Sign input 0 (cancel/expire sigscript -- Op0 selector, same as cancel)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
    let mut writer_sig = [0u8; 64];
    writer_sig.copy_from_slice(&sig_0);

    let expire_ss = if option_type == "call" {
        contract::build_call_option_cancel_sigscript(&writer_sig, &redeem_script)
    } else {
        contract::build_put_option_cancel_sigscript(&writer_sig, &redeem_script)
    };

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_expire = vec![expire_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_expire);
    let exact_fee = exact_mass;

    let (expire_ss, fee_ss, actual_fee) = if exact_fee > est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let mut writer_sig = [0u8; 64];
        writer_sig.copy_from_slice(&sig_0);
        let expire_ss = if option_type == "call" {
            contract::build_call_option_cancel_sigscript(&writer_sig, &redeem_script)
        } else {
            contract::build_put_option_cancel_sigscript(&writer_sig, &redeem_script)
        };
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_ss = signing::build_p2pk_sigscript(&sig_1);

        (expire_ss, fee_ss, exact_fee)
    } else {
        (expire_ss, fee_ss, est_fee)
    };

    let output_value = tx.outputs[0].value;

    println!("Expire SS:  {} bytes", expire_ss.len());
    println!("Fee SS:     {} bytes", fee_ss.len());
    println!("Output Value: {} sompi", output_value);
    println!("Miner fee:    {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[expire_ss, fee_ss]);
    println!("Submitting option expire transaction (lockTime={})...", lock_time);
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! {} option expired.", option_type);
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, build_p2sh};

    fn dummy_keys() -> ([u8; 32], [u8; 32]) {
        let writer_pk = [0xAAu8; 32];
        let holder_pk = [0xBBu8; 32];
        (writer_pk, holder_pk)
    }

    fn dummy_writer_spk_hash(writer_pk: &[u8; 32]) -> [u8; 32] {
        let spk = build_owner_spk(writer_pk);
        blake2b_256(&spk)
    }

    // call_option_v2 tests

    #[test]
    fn call_option_v2_rs_is_133_bytes() {
        let (writer_pk, holder_pk) = dummy_keys();
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &wsh,
            0, u64::MAX,
        ).unwrap();
        assert_eq!(rs.len(), 159, "call_option v3 RS must be 159 bytes");
    }

    #[test]
    fn call_option_v2_p2sh_is_35_byte_script() {
        let (writer_pk, holder_pk) = dummy_keys();
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            5_000_000,
            &wsh,
            0, u64::MAX,
        ).unwrap();
        let p2sh = build_p2sh(&rs);
        // P2SH script: [0xaa][0x20][hash 32B][0x87] = 35 bytes
        assert_eq!(p2sh.script().len(), 35, "P2SH script must be 35 bytes");
        assert_eq!(p2sh.script()[0], 0xaa, "P2SH starts with OpBlake2b");
        assert_eq!(p2sh.script()[1], 0x20, "P2SH push 32 bytes");
        assert_eq!(p2sh.script()[34], 0x87, "P2SH ends with OpEqual");
    }

    #[test]
    fn call_option_v2_exercise_sigscript_structure() {
        let (writer_pk, holder_pk) = dummy_keys();
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        let sig = [0xCCu8; 64];
        let ss = contract::build_call_option_exercise_sigscript(&sig, &rs);

        // Structure: [pushData(sig+type 65B)][Op1][pushData(RS 133B)]
        // pushData(65B) = [0x41][65 bytes] = 66 bytes
        // Op1 = 0x51 = 1 byte
        // pushData(133B) = [0x4c][0x85][133 bytes] = 135 bytes (OP_PUSHDATA1 for 76..255)
        // Total: 66 + 1 + 135 = 202 bytes
        assert_eq!(ss.len(), 228, "call exercise sigscript must be 228 bytes");

        // Verify selector Op1 is at offset 66
        assert_eq!(ss[66], 0x51, "exercise selector must be Op1");
    }

    #[test]
    fn call_option_v2_cancel_sigscript_structure() {
        let (writer_pk, holder_pk) = dummy_keys();
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        let sig = [0xDDu8; 64];
        let ss = contract::build_call_option_cancel_sigscript(&sig, &rs);

        // Structure: [pushData(sig+type 65B)][Op0][pushData(RS)]
        // Same total as exercise: 202 bytes
        assert_eq!(ss.len(), 228, "call cancel sigscript must be 228 bytes");

        // Verify selector Op0 at offset 66
        assert_eq!(ss[66], 0x00, "cancel selector must be Op0");
    }

    #[test]
    fn call_option_v2_state_fields_extractable() {
        let (writer_pk, holder_pk) = dummy_keys();
        let strike: u64 = 50_000_000_000; // 500 KAS
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            strike,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        // Extract writer_pk from RS
        assert_eq!(rs[0], 0x20);
        assert_eq!(&rs[1..33], &writer_pk);

        // Extract holder_pk
        assert_eq!(rs[33], 0x20);
        assert_eq!(&rs[34..66], &holder_pk);

        // Extract strike_kas
        assert_eq!(rs[66], 0x08);
        let extracted_strike = u64::from_le_bytes(rs[67..75].try_into().unwrap());
        assert_eq!(extracted_strike, strike);

        // Extract writer_spk_hash
        assert_eq!(rs[75], 0x20);
        assert_eq!(&rs[76..108], &wsh);
    }

    // put_option_v3 tests

    #[test]
    fn put_option_v3_rs_is_179_bytes() {
        let (writer_pk, holder_pk) = dummy_keys();
        let tcid = [0x01u8; 32];
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_put_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &tcid,
            &wsh,
            0, u64::MAX,
        ).unwrap();
        assert_eq!(rs.len(), 205, "put_option v4 RS must be 205 bytes");
    }

    #[test]
    fn put_option_v3_p2sh_is_35_byte_script() {
        let (writer_pk, holder_pk) = dummy_keys();
        let tcid = [0x01u8; 32];
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_put_option_redeem_script(
            &writer_pk,
            &holder_pk,
            5_000_000,
            &tcid,
            &wsh,
            0, u64::MAX,
        ).unwrap();
        let p2sh = build_p2sh(&rs);
        assert_eq!(p2sh.script().len(), 35, "P2SH script must be 35 bytes");
    }

    #[test]
    fn put_option_v3_exercise_sigscript_structure() {
        let (writer_pk, holder_pk) = dummy_keys();
        let tcid = [0x01u8; 32];
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_put_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &tcid,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        let sig = [0xCCu8; 64];
        let ss = contract::build_put_option_exercise_sigscript(&sig, &rs);

        // pushData(65B) = 66B, Op1 = 1B, pushData(179B) = [0x4c][0xb3][179B] = 181B
        // Total: 66 + 1 + 181 = 248 bytes
        assert_eq!(ss.len(), 274, "put exercise sigscript must be 274 bytes");
        assert_eq!(ss[66], 0x51, "exercise selector must be Op1");
    }

    #[test]
    fn put_option_v3_cancel_sigscript_structure() {
        let (writer_pk, holder_pk) = dummy_keys();
        let tcid = [0x01u8; 32];
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_put_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &tcid,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        let sig = [0xDDu8; 64];
        let ss = contract::build_put_option_cancel_sigscript(&sig, &rs);

        assert_eq!(ss.len(), 274, "put cancel sigscript must be 274 bytes");
        assert_eq!(ss[66], 0x00, "cancel selector must be Op0");
    }

    #[test]
    fn put_option_v3_state_fields_extractable() {
        let (writer_pk, holder_pk) = dummy_keys();
        let strike: u64 = 100_000_000_000; // 1000 KAS
        let tcid = [0xEEu8; 32];
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_put_option_redeem_script(
            &writer_pk,
            &holder_pk,
            strike,
            &tcid,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        // writer_pk at [1..33]
        assert_eq!(&rs[1..33], &writer_pk);
        // holder_pk at [34..66]
        assert_eq!(&rs[34..66], &holder_pk);
        // strike_kas at [67..75]
        let extracted = u64::from_le_bytes(rs[67..75].try_into().unwrap());
        assert_eq!(extracted, strike);
        // token_cov_id at [76..108]
        assert_eq!(&rs[76..108], &tcid);
        // writer_spk_hash at [109..141] (push prefix 0x20 at offset 108)
        assert_eq!(&rs[109..141], &wsh);
    }

    #[test]
    fn call_and_put_different_p2sh() {
        let (writer_pk, holder_pk) = dummy_keys();
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let tcid = [0x01u8; 32];

        let call_rs = contract::build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &wsh,
            0, u64::MAX,
        ).unwrap();
        let put_rs = contract::build_put_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &tcid,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        let call_p2sh = build_p2sh(&call_rs);
        let put_p2sh = build_p2sh(&put_rs);

        assert_ne!(
            call_p2sh.script(), put_p2sh.script(),
            "Call and put P2SH must differ"
        );
    }

    #[test]
    fn owner_spk_is_36_bytes_with_correct_structure() {
        let pk = [0x02u8; 32];
        let spk = build_owner_spk(&pk);
        assert_eq!(spk.len(), 36);
        assert_eq!(spk[0], 0x00); // version LE low byte
        assert_eq!(spk[1], 0x00); // version LE high byte
        assert_eq!(spk[2], 0x20); // push 32
        assert_eq!(&spk[3..35], &pk);
        assert_eq!(spk[35], 0xac); // OpCheckSig
    }

    #[test]
    fn exercise_and_cancel_selectors_differ() {
        let (writer_pk, holder_pk) = dummy_keys();
        let wsh = dummy_writer_spk_hash(&writer_pk);
        let rs = contract::build_call_option_redeem_script(
            &writer_pk,
            &holder_pk,
            1_000_000,
            &wsh,
            0, u64::MAX,
        ).unwrap();

        let sig = [0xAAu8; 64];
        let exercise_ss = contract::build_call_option_exercise_sigscript(&sig, &rs);
        let cancel_ss = contract::build_call_option_cancel_sigscript(&sig, &rs);

        // Selector at offset 66
        assert_eq!(exercise_ss[66], 0x51, "exercise = Op1");
        assert_eq!(cancel_ss[66], 0x00, "cancel = Op0");
        assert_ne!(exercise_ss, cancel_ss, "exercise and cancel SS must differ");
    }
}
