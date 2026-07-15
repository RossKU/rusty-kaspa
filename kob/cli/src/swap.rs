//! `kob-cli swap` -- Deploy, cancel, and inspect cross-token swap orders.
//!
//! Subcommands:
//!   deploy  -- Deploy a swap order (swap_order: 243B RS)
//!   cancel  -- Owner cancels a swap order (recover locked tokens)
//!   info    -- Display parsed swap order state from a redeemScript
//!
//! ## Swap Order
//!
//! The user locks source tokens (e.g. USDT) in a swap covenant UTXO and specifies
//! a target token (e.g. BTC) and minimum receive amount. A matcher finds
//! counterparties on both TOKEN/KAS books and builds one atomic batch TX where
//! KAS flows internally without the user touching it.
//!
//! RS = 243B (174B state + 69B body)
//! State: [source_token_cov_id 32B][target_token_cov_id 32B][min_target_amount 8B]
//!        [owner_hash 32B][owner_spk_hash 32B][receipt_cov_id 32B]
//!
//! Cancel sigscript: `[pushData(sig+type 65B)] [pushData(pk 32B)] [Op0] [pushData(RS)]`
//!   sigOpCount = 1 for this input.

use crate::cancel::p2sh_to_address;
use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::contract;
use kob_core::contract::build_order_payload;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

#[derive(Subcommand, Debug)]
pub enum SwapCommand {
    /// Deploy a cross-token swap order.
    ///
    /// Locks source tokens in a P2SH covenant. A matcher routes through
    /// KAS-denominated order books to deliver target tokens to the user.
    Deploy {
        /// Source token covenant ID (hex, 64 chars). The token being sold.
        #[arg(long)]
        source_token: String,

        /// Target token covenant ID (hex, 64 chars). The token to receive.
        #[arg(long)]
        target_token: String,

        /// Amount of source tokens to lock (in sompi).
        #[arg(long)]
        amount: u64,

        /// Minimum target tokens to receive (in sompi).
        #[arg(long)]
        min_receive: u64,

        /// Receipt covenant ID (hex, 64 chars). For N4 verification.
        #[arg(long)]
        receipt_cov_id: String,

        /// Source token UTXO outpoint (txid:index) for covenant lineage.
        /// Auto-discovered from token_mint/token_unit P2SH if omitted.
        #[arg(long)]
        token_utxo: Option<String>,

        /// Fee UTXO outpoint (txid:index). Auto-selected from wallet if omitted.
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Cancel a swap order (owner recovers locked tokens).
    Cancel {
        /// Swap order outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// RedeemScript of the swap order (hex). Printed by deploy.
        #[arg(long)]
        rs: String,

        /// Swap UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,

        /// Fee UTXO outpoint (txid:index). Auto-selected from wallet if omitted.
        #[arg(long)]
        fee_utxo: Option<String>,
    },

    /// Display parsed swap order info from a redeemScript.
    ///
    /// Parses the RS to show source/target tokens, min receive, owner, and
    /// checks whether the UTXO is still live on-chain.
    Info {
        /// Swap order outpoint (txid:index).
        #[arg(long)]
        outpoint: String,

        /// RedeemScript of the swap order (hex). Printed by deploy.
        #[arg(long)]
        rs: String,
    },
}

/// Dispatch swap subcommand.
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    cmd: &SwapCommand,
) -> anyhow::Result<()> {
    match cmd {
        SwapCommand::Deploy {
            source_token,
            target_token,
            amount,
            min_receive,
            receipt_cov_id,
            token_utxo,
            fee_utxo,
        } => {
            crate::deploy::validate_amount_not_dust(*amount, "--amount")?;
            deploy(
                wallet_path,
                node_url,
                network,
                source_token,
                target_token,
                *amount,
                *min_receive,
                receipt_cov_id,
                token_utxo.as_deref(),
                fee_utxo.as_deref(),
            )
            .await
        }
        SwapCommand::Cancel {
            outpoint,
            rs,
            order_value,
            fee_utxo,
        } => {
            cancel(
                wallet_path,
                node_url,
                network,
                outpoint,
                rs,
                *order_value,
                fee_utxo.as_deref(),
            )
            .await
        }
        SwapCommand::Info { outpoint, rs } => {
            info_cmd(wallet_path, node_url, network, outpoint, rs).await
        }
    }
}

// Helpers

/// Parse a 32-byte hex covenant ID.
fn parse_cov_id(hex_str: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        anyhow::bail!("{} must be 64 hex characters (32 bytes), got {} chars", label, hex_str.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Query a swap UTXO value by scanning the P2SH address derived from the RS.
async fn query_swap_utxo_value(
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
                "Swap UTXO {} not found at P2SH address {}",
                outpoint,
                addr
            )
        })?;
    Ok(utxo.utxo_entry.amount)
}

// swap deploy

#[allow(clippy::too_many_arguments)]
async fn deploy(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    source_token_hex: &str,
    target_token_hex: &str,
    amount: u64,
    min_receive: u64,
    receipt_cov_id_hex: &str,
    token_utxo_str: Option<&str>,
    fee_utxo_str: Option<&str>,
) -> anyhow::Result<()> {
    // Input validation
    if amount == 0 {
        anyhow::bail!("amount must be > 0");
    }
    if min_receive == 0 {
        anyhow::bail!("min_receive must be > 0 (zero allows empty fill)");
    }

    // Parse covenant IDs
    let source_tcid = parse_cov_id(source_token_hex, "source-token")?;
    let target_tcid = parse_cov_id(target_token_hex, "target-token")?;
    let receipt_cid = parse_cov_id(receipt_cov_id_hex, "receipt-cov-id")?;

    if source_tcid == target_tcid {
        anyhow::bail!("source-token and target-token must be different");
    }

    // Load wallet
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    // owner_hash = blake2b_256(pubkey)
    let owner_hash = blake2b_256(&pubkey);
    // owner_spk_hash = blake2b_256(P2PK SPK) -- where target tokens are sent
    let owner_spk_hash = compute_p2pk_spk_hash(&pubkey);

    // Build RS
    let redeem_script = contract::build_swap_redeem_script(
        &source_tcid,
        &target_tcid,
        min_receive,
        &owner_hash,
        &owner_spk_hash,
        &receipt_cid,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Swap Order");
    println!("==================");
    println!("Source Token: {}", source_token_hex);
    println!("Target Token: {}", target_token_hex);
    println!("Amount:       {} sompi ({:.8} KAS)", amount, amount as f64 / 1e8);
    println!("Min Receive:  {} sompi", min_receive);
    println!("Receipt Cov:  {}", receipt_cov_id_hex);
    println!("Owner:        {}", wallet.pubkey_hex());
    println!("Owner Hash:   {}", hex::encode(owner_hash));
    println!("Owner SPK Hash: {}", hex::encode(owner_spk_hash));
    println!();
    println!("RedeemScript: {} bytes", redeem_script.len());
    println!("RS hex:       {}", hex::encode(&redeem_script));
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    info!(amount = amount, min_receive = min_receive, "deploying swap order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let rpc_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let p2pk_rpc: Vec<_> = rpc_utxos.iter().filter(|u| !u.is_p2sh()).collect();

    // Swap order locks source tokens -- needs covenant binding (TX version 1)
    let mut tx = Transaction::new(1);

    // Token UTXO as input[0] for covenant lineage
    let mut token_input_value: u64 = 0;
    let token_input_idx: u32 = 0;

    if let Some(token_op_str) = token_utxo_str {
        let token_op = Outpoint::parse(token_op_str)?;
        let found_utxo = rpc_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == token_op.transaction_id && u.outpoint.index == token_op.index)
            .cloned();

        let mut found = found_utxo;
        let extra_utxos;
        if found.is_none() {
            // Query token_mint and token_unit P2SH addresses
            let mint_rs = kob_core::contract::build_token_mint_redeem_script(&pubkey);
            let mint_p2sh = build_p2sh(&mint_rs);
            let mint_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &mint_p2sh.script()[2..34]);
            let unit_rs = kob_core::contract::build_token_unit_redeem_script(&pubkey);
            let unit_p2sh = build_p2sh(&unit_rs);
            let unit_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &unit_p2sh.script()[2..34]);
            println!("Token UTXO not in wallet. Querying P2SH addresses...");
            extra_utxos = rpc.get_utxos_by_addresses(&[&mint_addr, &unit_addr]).await?;
            found = extra_utxos
                .iter()
                .find(|u| u.outpoint.transaction_id == token_op.transaction_id && u.outpoint.index == token_op.index)
                .cloned();
        }

        let token_utxo = found
            .ok_or_else(|| anyhow::anyhow!(
                "Token UTXO {} not found. It may be spent or not belong to this wallet.",
                token_op_str
            ))?;
        token_input_value = token_utxo.utxo_entry.amount;
        println!("Token UTXO: {}:{} ({} sompi)",
            &token_utxo.outpoint.transaction_id[..16],
            token_utxo.outpoint.index,
            token_input_value,
        );
        tx.inputs.push(TxInput {
            prev_tx_id: token_utxo.outpoint.transaction_id.clone(),
            prev_index: token_utxo.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: token_utxo.utxo_entry.script_public_key.version,
            script_bytes: token_utxo.script_bytes(),
            value: token_input_value,
        });
    } else {
        // Auto-discover token UTXO from mint/unit P2SH addresses
        let mint_rs = kob_core::contract::build_token_mint_redeem_script(&pubkey);
        let mint_p2sh = build_p2sh(&mint_rs);
        let mint_addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &mint_p2sh.script()[2..34],
        );
        println!("Auto-discovering token UTXO at mint address {}...", &mint_addr[..40]);
        let mint_utxos = rpc.get_utxos_by_addresses(&[&mint_addr]).await?;

        let unit_rs = kob_core::contract::build_token_unit_redeem_script(&pubkey);
        let unit_p2sh = build_p2sh(&unit_rs);
        let unit_addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &unit_p2sh.script()[2..34],
        );
        let unit_utxos = rpc.get_utxos_by_addresses(&[&unit_addr]).await?;

        let all_token_utxos: Vec<_> = mint_utxos.iter().chain(unit_utxos.iter()).collect();
        if let Some(token_utxo) = all_token_utxos.first() {
            token_input_value = token_utxo.utxo_entry.amount;
            println!("Token UTXO: {}:{} ({} sompi)",
                &token_utxo.outpoint.transaction_id[..16],
                token_utxo.outpoint.index,
                token_input_value,
            );
            tx.inputs.push(TxInput {
                prev_tx_id: token_utxo.outpoint.transaction_id.clone(),
                prev_index: token_utxo.outpoint.index,
                sequence: 0,
                sig_op_count: 1,
                script_version: token_utxo.utxo_entry.script_public_key.version,
                script_bytes: token_utxo.script_bytes(),
                value: token_input_value,
            });
        } else {
            println!("WARNING: No token UTXO found at mint or unit P2SH addresses.");
            println!("  Deploying without covenant input (TX version 0).");
            tx.version = 0;
        }
    }

    // Select fee/funding UTXO(s)
    let est_fee = estimate_compute_mass(2, 3, 100);
    let needed = if token_input_value >= amount + est_fee {
        est_fee
    } else {
        amount + est_fee - token_input_value
    };

    let fee_utxo_rpc = if let Some(fee_op_str) = fee_utxo_str {
        let fee_op = Outpoint::parse(fee_op_str)?;
        let found = p2pk_rpc
            .iter()
            .find(|u| u.outpoint.transaction_id == fee_op.transaction_id && u.outpoint.index == fee_op.index)
            .ok_or_else(|| anyhow::anyhow!(
                "Fee UTXO {} not found in wallet P2PK UTXOs.",
                fee_op_str
            ))?;
        println!("Fee UTXO:   {}:{} ({} sompi)",
            &found.outpoint.transaction_id[..16], found.outpoint.index, found.utxo_entry.amount);
        vec![*found]
    } else {
        // Auto-select: smallest P2PK UTXO that covers needed
        let mut candidates: Vec<_> = p2pk_rpc.iter().filter(|u| u.utxo_entry.amount >= needed).collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        let fee_entry = candidates.into_iter().next()
            .ok_or_else(|| anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee. {} available.",
                needed, p2pk_rpc.len()
            ))?;
        println!("Selected fee UTXO: {}:{} ({} sompi)",
            &fee_entry.outpoint.transaction_id[..16], fee_entry.outpoint.index, fee_entry.utxo_entry.amount);
        vec![*fee_entry]
    };

    // Add P2PK funding inputs
    let mut total_p2pk_input: u64 = 0;
    for u in &fee_utxo_rpc {
        total_p2pk_input += u.utxo_entry.amount;
        tx.inputs.push(TxInput {
            prev_tx_id: u.outpoint.transaction_id.clone(),
            prev_index: u.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: u.utxo_entry.script_public_key.version,
            script_bytes: u.script_bytes(),
            value: u.utxo_entry.amount,
        });
    }

    let total_input = token_input_value + total_p2pk_input;

    // Output 0: P2SH swap order (with covenant binding for source token)
    let covenant_binding = kob_core::tx::CovenantBinding::new(
        token_input_idx as u16,
        kob_core::compat::parse_hash(&source_token_hex.to_string()).unwrap(),
    );
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), Some(covenant_binding)));

    // Output 1 (if needed): token remainder back to token_unit P2SH
    let token_remainder = token_input_value.saturating_sub(amount);
    if token_remainder >= MIN_UTXO_VALUE {
        let unit_rs = kob_core::contract::build_token_unit_redeem_script(&pubkey);
        let unit_p2sh = build_p2sh(&unit_rs);
        let remainder_binding = kob_core::tx::CovenantBinding::new(
            token_input_idx as u16,
            kob_core::compat::parse_hash(&source_token_hex.to_string()).unwrap(),
        );
        tx.outputs.push(TxOutput::new(token_remainder, 0, unit_p2sh.script().to_vec(), Some(remainder_binding)));
        println!("Token remainder: {} sompi -> token_unit P2SH", token_remainder);
    } else if token_remainder > 0 && token_remainder < MIN_UTXO_VALUE {
        println!("WARNING: Token remainder {} sompi below MIN_UTXO_VALUE, lost as dust.", token_remainder);
    }

    // TX payload: RS for matcher L1 discovery
    tx.payload = build_order_payload(&redeem_script, false);

    // KAS change output
    let wallet_spk = if let Some(u) = fee_utxo_rpc.first() {
        hex::decode(&u.utxo_entry.script_public_key.script)?
    } else {
        let mut spk = Vec::with_capacity(34);
        spk.push(0x20);
        spk.extend_from_slice(&pubkey);
        spk.push(0xac);
        spk
    };

    // Calculate fixed output sum for fee convergence
    let fixed_output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let tentative_change = total_input.saturating_sub(fixed_output_sum + est_fee);
    let has_token_remainder = token_remainder >= MIN_UTXO_VALUE;
    if tentative_change >= MIN_UTXO_VALUE {
        let script_version = fee_utxo_rpc.first()
            .map(|u| u.utxo_entry.script_public_key.version)
            .unwrap_or(0);
        tx.outputs.push(TxOutput::new(tentative_change, script_version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output (last output if it exists)
    let num_fixed = 1 + if has_token_remainder { 1 } else { 0 };
    let has_change = tx.outputs.len() > num_fixed;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };

    let (phase1_fee, _) = if has_change {
        converge_fee(&mut tx, total_input, change_idx, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx);
        (f, 0)
    };

    // Remove change output if below MIN_UTXO_VALUE
    if has_change {
        let change_val = tx.outputs[change_idx].value;
        if change_val < MIN_UTXO_VALUE {
            tx.outputs.pop();
            if change_val > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change_val);
            }
        }
    }

    // Sign all inputs (phase 1)
    // Input 0 may be a P2SH token UTXO (mint or unit) — needs covenant sigscript.
    let sign_all_inputs = |tx: &Transaction, privkey: &kob_core::wallet::SecureKey, pubkey: &[u8; 32], token_input_value: u64| -> anyhow::Result<Vec<Vec<u8>>> {
        let mut sigscripts: Vec<Vec<u8>> = Vec::new();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(tx, i)?;
            let signature = signing::schnorr_sign_secure(privkey, &sighash)?;
            if token_input_value > 0 && i == 0 {
                let mint_rs = kob_core::contract::build_token_mint_redeem_script(pubkey);
                let unit_rs = kob_core::contract::build_token_unit_redeem_script(pubkey);
                let is_mint = tx.inputs[0].script_bytes == build_p2sh(&mint_rs).script();
                if is_mint {
                    sigscripts.push(contract::build_token_mint_sigscript(&signature, &mint_rs));
                } else {
                    sigscripts.push(contract::build_token_unit_sigscript(&signature, &unit_rs));
                }
            } else {
                sigscripts.push(signing::build_p2pk_sigscript(&signature));
            }
        }
        Ok(sigscripts)
    };
    let mut sigscripts = sign_all_inputs(&tx, privkey, &pubkey, token_input_value)?;

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    let actual_fee = if exact_fee != phase1_fee {
        let can_adjust = has_change && change_idx < tx.outputs.len();
        if can_adjust {
            let fixed_sum: u64 = tx.outputs.iter().enumerate()
                .filter(|(i, _)| *i != change_idx)
                .map(|(_, o)| o.value)
                .sum();
            let new_change = total_input.saturating_sub(fixed_sum + exact_fee);
            if new_change >= MIN_UTXO_VALUE {
                tx.outputs[change_idx].value = new_change;
            } else {
                tx.outputs.pop();
                if new_change > 0 {
                    println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
                }
            }
        }
        // Re-sign
        sigscripts = sign_all_inputs(&tx, privkey, &pubkey, token_input_value)?;
        exact_fee
    } else {
        phase1_fee
    };

    println!("Signed {} input(s)", sigscripts.len());
    println!();

    // Fee transparency summary
    let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
    println!("Fee Summary");
    println!("-----------");
    println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
    println!("Miner fee:        {:>9} sompi", actual_fee);
    println!("Net order value:  {:>9} sompi", amount);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting swap deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Swap order deployed.");
    println!("TXID:   {}", tx_id);
    println!();
    println!("Swap Order: {}:0 ({} sompi)", tx_id, amount);
    println!("RS:         {}", hex::encode(&redeem_script));
    println!();
    println!("Cancel command (owner):");
    println!(
        "  kob-cli swap cancel --outpoint {}:0 --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );
    println!();
    println!("Info command:");
    println!(
        "  kob-cli swap info --outpoint {}:0 --rs {}",
        tx_id,
        hex::encode(&redeem_script),
    );

    Ok(())
}

// swap cancel

#[allow(clippy::too_many_arguments)]
async fn cancel(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: &str,
    order_value_override: Option<u64>,
    fee_utxo_str: Option<&str>,
) -> anyhow::Result<()> {
    let outpoint = Outpoint::parse(outpoint_str)?;
    let redeem_script = hex::decode(rs_hex)?;

    // Parse and validate the RS
    let parsed = contract::parse_swap_order_rs(&redeem_script)
        .ok_or_else(|| anyhow::anyhow!(
            "Invalid swap order RS: expected {} bytes, got {}",
            contract::SWAP_RS_SIZE,
            redeem_script.len(),
        ))?;

    let p2sh = build_p2sh(&redeem_script);

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    // Verify owner_hash matches this wallet
    let expected_owner_hash = blake2b_256(&pubkey);
    if parsed.owner_hash != expected_owner_hash {
        anyhow::bail!(
            "Owner hash mismatch. This swap order was not deployed by this wallet.\n\
             Expected: {}\n\
             Got:      {}",
            hex::encode(expected_owner_hash),
            hex::encode(parsed.owner_hash),
        );
    }

    println!("Cancel Swap Order");
    println!("==================");
    println!("Outpoint:     {}", outpoint);
    println!("Source Token: {}", hex::encode(parsed.source_token_cov_id));
    println!("Target Token: {}", hex::encode(parsed.target_token_cov_id));
    println!("Min Receive:  {} sompi", parsed.min_target_amount);
    println!("RS:           {} bytes", redeem_script.len());
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    info!(outpoint = %outpoint, "cancelling swap order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Get swap UTXO value
    let order_value = match order_value_override {
        Some(v) => v,
        None => {
            println!("Querying swap UTXO value...");
            query_swap_utxo_value(&rpc, &outpoint, &redeem_script, network.address_prefix()).await?
        }
    };
    println!("Order Value:  {} sompi", order_value);

    // Need a fee UTXO
    let cancel_est_fee = estimate_compute_mass(2, 1, 0);
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    let fee_utxo = if let Some(fee_op_str) = fee_utxo_str {
        let fee_op = Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh()
                && u.outpoint.transaction_id == fee_op.transaction_id
                && u.outpoint.index == fee_op.index)
            .ok_or_else(|| anyhow::anyhow!(
                "Fee UTXO {} not found in wallet P2PK UTXOs.",
                fee_op_str
            ))?
    } else {
        wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= cancel_est_fee + MIN_UTXO_VALUE)
            .ok_or_else(|| anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for fee payment",
                cancel_est_fee + MIN_UTXO_VALUE
            ))?
    };

    println!(
        "Fee UTXO:     {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = order_value + fee_utxo.utxo_entry.amount;

    // Cancel TX layout:
    //   input[0]: Swap UTXO (sigOpCount=1, cancel sigscript)
    //   input[1]: fee UTXO (P2PK, signed)
    //   output[0]: recovered funds to wallet
    let mut tx = Transaction::new(0);

    // Input 0: Swap UTXO
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
    tx.outputs.push(TxOutput::new(
        tentative_output,
        fee_utxo.utxo_entry.script_public_key.version,
        wallet_spk,
        None,
    ));

    // Phase 1: converge fee on output 0
    let (phase1_fee, _) = converge_fee(&mut tx, total_in, 0, 0);
    println!("Output Value: {} sompi", tx.outputs[0].value);
    println!();

    // Sign input 0 (cancel sigscript)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(privkey, &sighash_0)?;
    let cancel_ss = contract::build_swap_cancel_sigscript(
        &sig_0,
        &pubkey,
        &redeem_script,
    );

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(privkey, &sighash_1)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_check = vec![cancel_ss.clone(), fee_ss.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_check);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    let (cancel_ss_final, fee_ss_final) = if exact_fee != phase1_fee {
        // Re-adjust output
        let new_output = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = new_output;
        // Re-sign
        let sighash_0b = compute_sighash(&tx, 0)?;
        let sig_0b = signing::schnorr_sign_secure(privkey, &sighash_0b)?;
        let cancel_ss2 = contract::build_swap_cancel_sigscript(
            &sig_0b,
            &pubkey,
            &redeem_script,
        );
        let sighash_1b = compute_sighash(&tx, 1)?;
        let sig_1b = signing::schnorr_sign_secure(privkey, &sighash_1b)?;
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
    println!("Submitting swap cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Swap order cancelled.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", tx.outputs[0].value);

    Ok(())
}

// swap info

async fn info_cmd(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    rs_hex: &str,
) -> anyhow::Result<()> {
    let outpoint = Outpoint::parse(outpoint_str)?;
    let redeem_script = hex::decode(rs_hex)?;

    let parsed = contract::parse_swap_order_rs(&redeem_script)
        .ok_or_else(|| anyhow::anyhow!(
            "Invalid swap order RS: expected {} bytes, got {}",
            contract::SWAP_RS_SIZE,
            redeem_script.len(),
        ))?;

    println!("Swap Order Info");
    println!("================");
    println!("Outpoint:     {}", outpoint);
    println!();

    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Check if the UTXO is still live
    let utxo_result = query_swap_utxo_value(&rpc, &outpoint, &redeem_script, network.address_prefix()).await;
    let (status, value) = match utxo_result {
        Ok(v) => ("OPEN (UTXO exists)", v),
        Err(_) => ("SPENT (filled or cancelled)", 0),
    };

    // Check if this wallet owns the order
    let wallet = WalletContext::load(wallet_path).ok();
    let is_mine = if let Some(ref w) = wallet {
        let my_hash = blake2b_256(&w.pubkey);
        my_hash == parsed.owner_hash
    } else {
        false
    };

    println!("Status:       {}", status);
    if value > 0 {
        println!("Value:        {} sompi ({:.8} KAS)", value, value as f64 / 1e8);
    }
    println!("Source Token: {}", hex::encode(parsed.source_token_cov_id));
    println!("Target Token: {}", hex::encode(parsed.target_token_cov_id));
    println!("Min Receive:  {} sompi", parsed.min_target_amount);
    println!("Owner Hash:   {}", hex::encode(parsed.owner_hash));
    println!("Owner SPK:    {}", hex::encode(parsed.owner_spk_hash));
    println!("Receipt Cov:  {}", hex::encode(parsed.receipt_cov_id));
    println!("RS Size:      {} bytes", redeem_script.len());
    println!("Mine:         {}", if is_mine { "YES" } else { "no" });

    Ok(())
}
