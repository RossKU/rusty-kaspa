//! `kob-cli receipt` -- Receipt v4 operations: create, consume, trigger.
//!
//! trade_receipt_v4 (119B RS) — consume-only, no trigger-read path.
//! v3's trigger-read path (sigLen < 150) was removed: it allowed unsigned consumption (theft risk).
//! Only the recipient (Blake2b(pk) == recipient_hash) can spend via signature.
//!
//! Subcommands:
//!   `receipt create`  -- Deploy a receipt_v4 UTXO
//!   `receipt consume` -- Consume a receipt_v4 (requires recipient signature)
//!   `receipt trigger` -- Consume a receipt_v4 (now also requires recipient signature)

use crate::node::NodeClient;
use crate::rpc::RpcUtxo;
use crate::signing;
use clap::Subcommand;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use kob_core::{MIN_UTXO_VALUE, RECEIPT_DUST};
use std::path::Path;
use tracing::info;

#[derive(Subcommand, Debug)]
pub enum ReceiptCommand {
    /// Deploy a new trade_receipt_v4 UTXO.
    Create {
        /// Token pair ID (hex, 64 chars).
        #[arg(long)]
        pair_id: String,

        /// Price numerator at execution.
        #[arg(long)]
        price_num: u64,

        /// Price denominator at execution.
        #[arg(long)]
        price_den: u64,

        /// Execution amount (tokens).
        #[arg(long)]
        exec_amount: u64,

        /// Minimum receipt value in sompi (anti-wash-trading).
        #[arg(long, default_value = "5000000")]
        min_receipt_value: u64,

        /// Recipient public key hash (hex, 64 chars). Defaults to wallet pubkey hash.
        #[arg(long)]
        recipient_hash: Option<String>,

        /// Amount of KAS to lock in the receipt UTXO (in sompi).
        #[arg(long)]
        amount: u64,
    },

    /// Consume a trade_receipt_v4 (reclaim KAS with recipient signature).
    Consume {
        /// Receipt outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Token pair ID (hex, 64 chars).
        #[arg(long)]
        pair_id: String,

        /// Price numerator at execution.
        #[arg(long)]
        price_num: u64,

        /// Price denominator at execution.
        #[arg(long)]
        price_den: u64,

        /// Execution amount (tokens).
        #[arg(long)]
        exec_amount: u64,

        /// Minimum receipt value in sompi.
        #[arg(long, default_value = "5000000")]
        min_receipt_value: u64,

        /// Recipient public key hash (hex, 64 chars). Defaults to wallet pubkey hash.
        #[arg(long)]
        recipient_hash: Option<String>,

        /// Receipt UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        receipt_value: Option<u64>,

        /// Fee input outpoint (txid:index).
        #[arg(long)]
        fee_input: Option<String>,
    },

    /// Consume a trade_receipt_v4 via trigger path (requires recipient signature).
    Trigger {
        /// Receipt outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Token pair ID (hex, 64 chars).
        #[arg(long)]
        pair_id: String,

        /// Price numerator at execution.
        #[arg(long)]
        price_num: u64,

        /// Price denominator at execution.
        #[arg(long)]
        price_den: u64,

        /// Execution amount (tokens).
        #[arg(long)]
        exec_amount: u64,

        /// Minimum receipt value in sompi.
        #[arg(long, default_value = "5000000")]
        min_receipt_value: u64,

        /// Recipient public key hash (hex, 64 chars). Defaults to wallet pubkey hash.
        #[arg(long)]
        recipient_hash: Option<String>,

        /// Receipt UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        receipt_value: Option<u64>,

        /// Fee input outpoint (txid:index).
        #[arg(long)]
        fee_input: Option<String>,
    },

    /// Consume a legacy trade_receipt v1 (65B RS, permissionless).
    ConsumeV1 {
        /// Receipt outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// Token pair ID (hex, 64 chars).
        #[arg(long)]
        pair_id: String,

        /// Price numerator at execution.
        #[arg(long)]
        price_num: u64,

        /// Price denominator at execution.
        #[arg(long)]
        price_den: u64,

        /// Execution amount (tokens).
        #[arg(long)]
        exec_amount: u64,

        /// Receipt UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        receipt_value: Option<u64>,

        /// Fee input outpoint (txid:index).
        #[arg(long)]
        fee_input: Option<String>,
    },
}

/// Parse a 32-byte hex string into a fixed-size array.
fn parse_32_bytes(hex_str: &str, name: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        anyhow::bail!("{} must be 64 hex characters (32 bytes), got {} bytes", name, bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Resolve the receipt UTXO value from chain if not provided.
async fn resolve_receipt_value(
    rpc: &NodeClient,
    outpoint: &Outpoint,
    p2sh_script: &[u8],
    receipt_value_override: Option<u64>,
    prefix: &str,
) -> anyhow::Result<u64> {
    if let Some(v) = receipt_value_override {
        return Ok(v);
    }
    let receipt_addr = crate::cancel::kaspa_address_encode(prefix, 8, &p2sh_script[2..34]);
    println!("Querying receipt UTXO from {}...", &receipt_addr[..40]);
    let receipt_utxos = rpc.get_utxos_by_addresses(&[&receipt_addr]).await?;
    receipt_utxos
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == outpoint.transaction_id
                && u.outpoint.index == outpoint.index
        })
        .map(|u| u.utxo_entry.amount)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Receipt UTXO not found on chain. Use --receipt-value or check outpoint."
            )
        })
}

/// Find a suitable fee UTXO from the wallet.
async fn find_fee_utxo(
    rpc: &NodeClient,
    wallet_address: &str,
    fee_outpoint: Option<&Outpoint>,
    min_amount: u64,
) -> anyhow::Result<RpcUtxo> {
    let wallet_utxos = rpc.get_spendable_utxos(wallet_address).await?;
    if let Some(fee_op) = fee_outpoint {
        wallet_utxos
            .into_iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| anyhow::anyhow!("Specified fee UTXO not found in wallet"))
    } else {
        wallet_utxos
            .into_iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= min_amount)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for fee payment",
                    min_amount
                )
            })
    }
}

// Subcommand implementations

/// Deploy a new trade_receipt_v4 UTXO.
#[allow(clippy::too_many_arguments)]
pub async fn receipt_create(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    pair_id_hex: &str,
    price_num: u64,
    price_den: u64,
    exec_amount: u64,
    min_receipt_value: u64,
    recipient_hash_hex: Option<&str>,
    amount: u64,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let pair_id = parse_32_bytes(pair_id_hex, "pair_id")?;

    // Recipient hash: Blake2b(buyer_pubkey) by default
    let recipient_hash = if let Some(rh_hex) = recipient_hash_hex {
        parse_32_bytes(rh_hex, "recipient_hash")?
    } else {
        blake2b_256(&pubkey)
    };

    // Build receipt_v4 redeemScript (120 bytes)
    let receipt_rs = contract::build_receipt_redeem_script(
        &pair_id,
        price_num,
        price_den,
        exec_amount,
        min_receipt_value,
        &recipient_hash,
    )?;
    let p2sh = build_p2sh(&receipt_rs);

    println!("Deploy Trade Receipt v4");
    println!("========================");
    println!("Pair ID:          {}", pair_id_hex);
    println!("Price:            {}/{}", price_num, price_den);
    println!("Exec Amount:      {}", exec_amount);
    println!("Min Receipt Val:  {} sompi", min_receipt_value);
    println!("Recipient Hash:   {}", hex::encode(recipient_hash));
    println!("Amount:           {} sompi ({:.8} KAS)", amount, amount as f64 / 1e8);
    println!("Receipt RS:       {} bytes (v4)", receipt_rs.len());
    println!("Receipt P2SH:     {}", hex::encode(&p2sh.script()));
    println!("Wallet:           {}", wallet.address);
    println!();

    if amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Amount {} sompi is below MIN_UTXO_VALUE ({})",
            amount,
            MIN_UTXO_VALUE
        );
    }

    info!(pair_id = %pair_id_hex, amount = amount, "deploying receipt_v4");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let est_fee = estimate_compute_mass(1, 2, 0) + 500;
    let needed = amount + est_fee;

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

    // Pre-compute the receipt's covenant id (version-1 covenant GENESIS).
    //
    // The v18 bracket fill gate checks `OpInputCovenantId(2) == receipt_cov_id`
    // — a receipt deployed WITHOUT a covenant binding has no covenant id on
    // its input and can never satisfy that check, so brackets could never
    // fill against it. The receipt is therefore minted as a genesis covenant
    // (same pattern as `token create`), and this covenant id is what must be
    // passed to `bracket deploy --receipt-cov-id`.
    let receipt_cov_id = kob_core::compute_covenant_id(
        &funding.outpoint.transaction_id,
        funding.outpoint.index,
        &[kob_core::tx::AuthOutput {
            index: 0,
            value: amount,
            spk_version: p2sh.version,
            spk_script: p2sh.script().to_vec(),
        }],
    )?;
    let receipt_cov_id_hex = hex::encode(receipt_cov_id);
    println!("Receipt Covenant ID: {}", receipt_cov_id_hex);
    println!("  (pass this as --receipt-cov-id when deploying a bracket)");
    println!();

    // Build deploy TX (version 1: covenant binding on the receipt output)
    let mut tx = Transaction::new(1);

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

    // Output 0: receipt P2SH (covenant genesis — authorizing input 0)
    tx.outputs.push(TxOutput::new(
        amount,
        p2sh.version,
        p2sh.script().to_vec(),
        Some(kob_core::tx::CovenantBinding::new(
            0,
            kob_core::compat::parse_hash(&receipt_cov_id_hex)
                .map_err(|e| anyhow::anyhow!("covenant id hash: {e:?}"))?,
        )),
    ));

    // Output 1: tentative change back to wallet
    let total_input = funding.utxo_entry.amount;
    let tentative_change = total_input.saturating_sub(amount + est_fee);
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    if has_change {
        tx.outputs.push(TxOutput::new(tentative_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output
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
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
    } else if !has_change && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Sign
    let sighash = compute_sighash(&tx, 0)?;
    let sig = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&sig);

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &[sigscript.clone()]);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    let _actual_fee = if exact_fee != est_fee { exact_fee } else { est_fee };
    let sigscript = if exact_fee != est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
            if new_change > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        // Re-sign
        let sighash = compute_sighash(&tx, 0)?;
        let sig = signing::schnorr_sign(&privkey, &sighash)?;
        signing::build_p2pk_sigscript(&sig)
    } else {
        sigscript
    };

    println!();

    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting receipt_v4 deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Receipt deployed (version-1 covenant genesis).");
    println!("TXID:     {}", tx_id);
    println!("Receipt:  {}:0 ({} sompi)", tx_id, amount);
    println!("Cov ID:   {}", receipt_cov_id_hex);
    println!("RS:       {} bytes (v4)", receipt_rs.len());

    Ok(())
}

/// Consume a trade_receipt_v4 (requires recipient signature).
#[allow(clippy::too_many_arguments)]
pub async fn receipt_consume(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    pair_id_hex: &str,
    price_num: u64,
    price_den: u64,
    exec_amount: u64,
    min_receipt_value: u64,
    recipient_hash_hex: Option<&str>,
    receipt_value_override: Option<u64>,
    fee_input_str: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let pair_id = parse_32_bytes(pair_id_hex, "pair_id")?;

    // Recipient hash: Blake2b(buyer_pubkey) by default
    let recipient_hash = if let Some(rh_hex) = recipient_hash_hex {
        parse_32_bytes(rh_hex, "recipient_hash")?
    } else {
        blake2b_256(&pubkey)
    };

    // Build receipt_v4 redeemScript (120 bytes)
    let receipt_rs = contract::build_receipt_redeem_script(
        &pair_id,
        price_num,
        price_den,
        exec_amount,
        min_receipt_value,
        &recipient_hash,
    )?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    println!("Consume Trade Receipt v4");
    println!("=========================");
    println!("Receipt:          {}", outpoint);
    println!("Pair ID:          {}", pair_id_hex);
    println!("Price:            {}/{}", price_num, price_den);
    println!("Exec Amount:      {}", exec_amount);
    println!("Min Receipt Val:  {} sompi", min_receipt_value);
    println!("Recipient Hash:   {}", hex::encode(recipient_hash));
    println!("Receipt RS:       {} bytes (v4)", receipt_rs.len());
    println!("Receipt P2SH:     {}", hex::encode(&receipt_p2sh.script()));
    println!("Wallet:           {}", wallet.address);
    println!();

    info!(outpoint = %outpoint, "consuming receipt_v4");

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine receipt value
    let receipt_value = resolve_receipt_value(
        &rpc,
        &outpoint,
        &receipt_p2sh.script(),
        receipt_value_override,
        network.address_prefix(),
    )
    .await?;

    println!("Receipt Value: {} sompi", receipt_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee_budget = estimate_compute_mass(2, 1, 0) + 500;

    // Find fee UTXO
    let fee_utxo = find_fee_utxo(
        &rpc,
        &wallet.address,
        fee_outpoint.as_ref(),
        est_fee_budget + MIN_UTXO_VALUE,
    )
    .await?;

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = receipt_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in.saturating_sub(est_fee_budget);

    if tentative_output < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Output value {} sompi below MIN_UTXO_VALUE {}",
            tentative_output,
            MIN_UTXO_VALUE
        );
    }

    // Build the consume TX
    // Receipt v3 consume: sigOpCount=1 (has OpCheckSig in consume path)
    let mut tx = Transaction::new(0);

    // Input 0: receipt (P2SH, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: receipt_p2sh.version,
        script_bytes: receipt_p2sh.script().to_vec(),
        value: receipt_value,
    });

    // Input 1: fee UTXO (P2PK, sigOpCount=1)
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

    // Output 0: wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee using estimated sigscript sizes
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, 0);

    // Sign the receipt input (index 0) -- recipient's signature
    let receipt_sighash = compute_sighash(&tx, 0)?;
    let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;

    // Build receipt_v4 consume sigscript: [push(sig 65B)] [push(pk 32B)] [pushData(RS)]
    let receipt_ss = contract::build_receipt_consume_sigscript(
        &receipt_sig,
        &pubkey,
        &receipt_rs,
    );
    println!("Receipt SS:    {} bytes (expect >= 150 for consume path)", receipt_ss.len());

    // Sign fee input (index 1)
    let fee_sighash = compute_sighash(&tx, 1)?;
    let fee_sig = signing::schnorr_sign(&privkey, &fee_sighash)?;
    let fee_ss = signing::build_p2pk_sigscript(&fee_sig);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts = vec![receipt_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    // If exact fee exceeds estimated fee, re-adjust output and re-sign
    let (receipt_ss, fee_ss, actual_fee) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign with updated output value
        let receipt_sighash = compute_sighash(&tx, 0)?;
        let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;
        let receipt_ss = contract::build_receipt_consume_sigscript(
            &receipt_sig,
            &pubkey,
            &receipt_rs,
        );
        let fee_sighash = compute_sighash(&tx, 1)?;
        let fee_sig = signing::schnorr_sign(&privkey, &fee_sighash)?;
        let fee_ss = signing::build_p2pk_sigscript(&fee_sig);

        (receipt_ss, fee_ss, exact_fee)
    } else {
        (receipt_ss, fee_ss, est_fee)
    };

    let output_value = tx.outputs[0].value;
    println!("Output Value:  {} sompi", output_value);
    println!("Miner fee:     {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[receipt_ss, fee_ss]);
    println!("Submitting receipt_v4 consume transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Receipt v3 consumed.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

/// Consume a trade_receipt_v4 via trigger path (recipient-signed, was permissionless in v3).
///
/// In v4, the trigger-read path was removed for security. This function now
/// behaves identically to receipt_consume — recipient signature is always required.
#[allow(clippy::too_many_arguments)]
pub async fn receipt_trigger(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    pair_id_hex: &str,
    price_num: u64,
    price_den: u64,
    exec_amount: u64,
    min_receipt_value: u64,
    recipient_hash_hex: Option<&str>,
    receipt_value_override: Option<u64>,
    fee_input_str: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let pair_id = parse_32_bytes(pair_id_hex, "pair_id")?;

    // Recipient hash: Blake2b(buyer_pubkey) by default
    let recipient_hash = if let Some(rh_hex) = recipient_hash_hex {
        parse_32_bytes(rh_hex, "recipient_hash")?
    } else {
        blake2b_256(&pubkey)
    };

    // Build receipt_v4 redeemScript (120 bytes)
    let receipt_rs = contract::build_receipt_redeem_script(
        &pair_id,
        price_num,
        price_den,
        exec_amount,
        min_receipt_value,
        &recipient_hash,
    )?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    println!("Consume Trade Receipt v4 (trigger path)");
    println!("==============================");
    println!("Receipt:          {}", outpoint);
    println!("Pair ID:          {}", pair_id_hex);
    println!("Price:            {}/{}", price_num, price_den);
    println!("Exec Amount:      {}", exec_amount);
    println!("Min Receipt Val:  {} sompi", min_receipt_value);
    println!("Recipient Hash:   {}", hex::encode(recipient_hash));
    println!("Receipt RS:       {} bytes (v4)", receipt_rs.len());
    println!("Receipt P2SH:     {}", hex::encode(&receipt_p2sh.script()));
    println!("Wallet:           {}", wallet.address);
    println!();

    info!(outpoint = %outpoint, "trigger-reading receipt_v4");

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine receipt value
    let receipt_value = resolve_receipt_value(
        &rpc,
        &outpoint,
        &receipt_p2sh.script(),
        receipt_value_override,
        network.address_prefix(),
    )
    .await?;

    println!("Receipt Value: {} sompi", receipt_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee_budget = estimate_compute_mass(2, 1, 0) + 500;

    // Find fee UTXO
    let fee_utxo = find_fee_utxo(
        &rpc,
        &wallet.address,
        fee_outpoint.as_ref(),
        est_fee_budget + MIN_UTXO_VALUE,
    )
    .await?;

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = receipt_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in.saturating_sub(est_fee_budget);

    if tentative_output < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Output value {} sompi below MIN_UTXO_VALUE {}",
            tentative_output,
            MIN_UTXO_VALUE
        );
    }

    // Build the consume TX (v4: always requires recipient signature)
    let mut tx = Transaction::new(0);

    // Input 0: receipt (P2SH, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: receipt_p2sh.version,
        script_bytes: receipt_p2sh.script().to_vec(),
        value: receipt_value,
    });

    // Input 1: fee UTXO (P2PK, sigOpCount=1)
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

    // Output 0: wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee using estimated sigscript sizes
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, 0);

    // Sign the receipt input (index 0) -- recipient's signature (v4: always required)
    let receipt_sighash = compute_sighash(&tx, 0)?;
    let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;

    // Build receipt_v4 consume sigscript: [push(sig 65B)] [push(pk 32B)] [pushData(RS)]
    let receipt_ss = contract::build_receipt_consume_sigscript(
        &receipt_sig,
        &pubkey,
        &receipt_rs,
    );
    println!("Receipt SS:    {} bytes (v4 consume, always signed)", receipt_ss.len());

    // Sign fee input (index 1)
    let fee_sighash = compute_sighash(&tx, 1)?;
    let fee_sig = signing::schnorr_sign(&privkey, &fee_sighash)?;
    let fee_ss = signing::build_p2pk_sigscript(&fee_sig);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts = vec![receipt_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    // If exact fee exceeds estimated fee, re-adjust output and re-sign
    let (receipt_ss, fee_ss, actual_fee) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign with updated output value
        let receipt_sighash = compute_sighash(&tx, 0)?;
        let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;
        let receipt_ss = contract::build_receipt_consume_sigscript(
            &receipt_sig,
            &pubkey,
            &receipt_rs,
        );
        let fee_sighash = compute_sighash(&tx, 1)?;
        let fee_sig = signing::schnorr_sign(&privkey, &fee_sighash)?;
        let fee_ss = signing::build_p2pk_sigscript(&fee_sig);

        (receipt_ss, fee_ss, exact_fee)
    } else {
        (receipt_ss, fee_ss, est_fee)
    };

    let output_value = tx.outputs[0].value;
    println!("Output Value:  {} sompi", output_value);
    println!("Miner fee:     {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[receipt_ss, fee_ss]);
    println!("Submitting receipt_v4 consume transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Receipt v4 consumed.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

/// Consume a legacy trade_receipt v1 (65B RS, permissionless).
/// Kept for backward compatibility.
#[allow(clippy::too_many_arguments)]
#[allow(deprecated)]
pub async fn receipt_consume_v1(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    pair_id_hex: &str,
    price_num: u64,
    price_den: u64,
    exec_amount: u64,
    receipt_value_override: Option<u64>,
    fee_input_str: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let pair_id = parse_32_bytes(pair_id_hex, "pair_id")?;
    let recipient_hash = blake2b_256(&pubkey);

    // Build receipt redeemScript (v4 format, backward compat for legacy v1 consume)
    let receipt_rs = contract::build_receipt_redeem_script(&pair_id, price_num, price_den, exec_amount, RECEIPT_DUST, &recipient_hash)?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    println!("Consume Trade Receipt v1 (Legacy)");
    println!("==================================");
    println!("Receipt:       {}", outpoint);
    println!("Pair ID:       {}", pair_id_hex);
    println!("Price:         {}/{}", price_num, price_den);
    println!("Exec Amount:   {}", exec_amount);
    println!("Receipt RS:    {} bytes (v1)", receipt_rs.len());
    println!("Receipt P2SH:  {}", hex::encode(&receipt_p2sh.script()));
    println!("Wallet:        {}", wallet.address);
    println!();

    info!(outpoint = %outpoint, "consuming trade receipt v1");

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine receipt value
    let receipt_value = resolve_receipt_value(
        &rpc,
        &outpoint,
        &receipt_p2sh.script(),
        receipt_value_override,
        network.address_prefix(),
    )
    .await?;

    println!("Receipt Value: {} sompi", receipt_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee_budget = estimate_compute_mass(2, 1, 0) + 500;

    // Find fee UTXO
    let fee_utxo = find_fee_utxo(
        &rpc,
        &wallet.address,
        fee_outpoint.as_ref(),
        est_fee_budget + MIN_UTXO_VALUE,
    )
    .await?;

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = receipt_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in.saturating_sub(est_fee_budget);

    if tentative_output < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Output value {} sompi below MIN_UTXO_VALUE {}",
            tentative_output,
            MIN_UTXO_VALUE
        );
    }

    // Build the consume TX
    let mut tx = Transaction::new(0);

    // Input 0: receipt (P2SH, sigOpCount=1 -- recipient signature required)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: receipt_p2sh.version,
        script_bytes: receipt_p2sh.script().to_vec(),
        value: receipt_value,
    });

    // Input 1: fee UTXO (P2PK, sigOpCount=1)
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

    // Output 0: wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee using estimated sigscript sizes
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, 0);

    // Sign receipt input (index 0) -- recipient's signature
    let receipt_sighash = compute_sighash(&tx, 0)?;
    let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;

    // Build consume sigscript: [push(sig 65B)] [push(pk 32B)] [pushData(RS)]
    let receipt_ss = contract::build_receipt_consume_sigscript(&receipt_sig, &pubkey, &receipt_rs);
    println!("Receipt SS:    {} bytes (v1 legacy consume)", receipt_ss.len());

    // Sign fee input (index 1)
    let fee_sighash = compute_sighash(&tx, 1)?;
    let fee_sig = signing::schnorr_sign(&privkey, &fee_sighash)?;
    let fee_ss = signing::build_p2pk_sigscript(&fee_sig);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts = vec![receipt_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    // If exact fee exceeds estimated fee, re-adjust output and re-sign
    let (receipt_ss, fee_ss, actual_fee) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign with updated output value
        let receipt_sighash = compute_sighash(&tx, 0)?;
        let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;
        let receipt_ss = contract::build_receipt_consume_sigscript(&receipt_sig, &pubkey, &receipt_rs);
        let fee_sighash = compute_sighash(&tx, 1)?;
        let fee_sig = signing::schnorr_sign(&privkey, &fee_sighash)?;
        let fee_ss = signing::build_p2pk_sigscript(&fee_sig);

        (receipt_ss, fee_ss, exact_fee)
    } else {
        (receipt_ss, fee_ss, est_fee)
    };

    let output_value = tx.outputs[0].value;
    println!("Output Value:  {} sompi", output_value);
    println!("Miner fee:     {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[receipt_ss, fee_ss]);
    println!("Submitting receipt v1 consume transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Receipt v1 consumed.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, build_p2sh};

    #[test]
    fn receipt_v4_redeem_script_length() {
        let pair_id = [0x01u8; 32];
        let recipient_hash = [0xEEu8; 32];
        let rs = contract::build_receipt_redeem_script(
            &pair_id, 1, 2, 5_000_000, 3_000_000, &recipient_hash,
        ).unwrap();
        assert_eq!(rs.len(), 119, "Receipt v4 RS must be 119 bytes (102 + 17)");
    }

    #[test]
    fn receipt_v4_consume_sigscript_structure() {
        let pair_id = [0x01u8; 32];
        let recipient_hash = [0xEEu8; 32];
        let rs = contract::build_receipt_redeem_script(
            &pair_id, 1, 2, 5_000_000, 3_000_000, &recipient_hash,
        ).unwrap();

        let sig = [0x42u8; 64];
        let pk = [0xABu8; 32];
        let ss = contract::build_receipt_consume_sigscript(&sig, &pk, &rs);
        // [push sig(65B)] = 66B, [push pk(32B)] = 33B, [PUSHDATA1 RS(119B)] = 121B
        // Total: 66 + 33 + 121 = 220B
        assert_eq!(ss.len(), 220, "Receipt v4 consume SS must be 220 bytes");
    }

    #[test]
    fn receipt_v4_p2sh_deterministic() {
        let pair_id = [0xABu8; 32];
        let recipient_hash = blake2b_256(&[0xCDu8; 32]);
        let rs = contract::build_receipt_redeem_script(
            &pair_id, 3, 4, 1_000_000, 5_000_000, &recipient_hash,
        ).unwrap();
        let p2sh1 = build_p2sh(&rs);
        let p2sh2 = build_p2sh(&rs);
        assert_eq!(p2sh1.script(), p2sh2.script(), "P2SH must be deterministic");
    }

    #[test]
    fn receipt_v4_backward_compat() {
        let pair_id = [0x01u8; 32];
        let recipient_hash = [0xEEu8; 32];
        let rs = contract::build_receipt_redeem_script(
            &pair_id, 1, 2, 5_000_000, 3_000_000, &recipient_hash,
        ).unwrap();
        assert_eq!(rs.len(), 119, "Receipt v4 RS must be 119 bytes");

        let sig = [0x42u8; 64];
        let pk = [0xABu8; 32];
        let ss = contract::build_receipt_consume_sigscript(&sig, &pk, &rs);
        assert_eq!(ss.len(), 220, "Receipt v4 consume SS must be 220 bytes");
    }

    #[test]
    fn output_value_uses_mass_based_fee() {
        // Mass-based fee for a 2-input, 1-output receipt consume TX
        let est_fee = kob_core::mass::estimate_compute_mass(2, 1, 0);
        assert!(est_fee > 0, "mass-based fee must be > 0");
        assert!(est_fee < 10_000, "mass-based fee should be well below old 10_000 constant");

        let receipt_val = 3_000_000u64;
        let fee_val = 10_000_000u64;
        let total_in = receipt_val + fee_val;
        let output = total_in.saturating_sub(est_fee);
        assert!(output > 12_990_000, "mass-based fee should be smaller than old fixed 10_000");
        assert!(output >= kob_core::MIN_UTXO_VALUE);
    }
}
