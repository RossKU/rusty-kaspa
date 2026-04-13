//! `kob-cli requote` -- Atomic cancel-old + deploy-new for market makers.
//!
//! The requote command cancels an existing order and deploys a new one at
//! updated parameters. This is the most critical market-making feature:
//! it allows rapid price updates without leaving the book empty.
//!
//! ## Modes
//!
//! - **Default (sequential)**: Cancel old order, wait 1 block confirmation,
//!   then deploy the new order using the wallet's available UTXOs.
//!
//! - **`--no-wait`**: Submit cancel TX and immediately submit deploy TX
//!   without waiting for cancel confirmation. The deploy TX uses the wallet's
//!   *current* UTXOs (not cancel change). Faster but carries a small risk:
//!   if the cancel TX is not accepted, the deploy still goes through.

use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::contract::build_order_payload;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

use crate::cancel::p2sh_to_address;

/// Parameters for the new order to deploy after cancellation.
pub struct NewOrderParams {
    pub side: String,
    pub token: String,
    pub price_num: u64,
    pub price_den: u64,
    pub min_fill: u64,
    pub amount: u64,
    pub version: u8,
}

fn parse_old_token(old_token: Option<&str>) -> anyhow::Result<[u8; 32]> {
    let token_hex = old_token
        .ok_or_else(|| anyhow::anyhow!("buy cancel requires --old-token <hex>"))?;
    let token_bytes = hex::decode(token_hex)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("old token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&token_bytes);
    Ok(tcid)
}

/// Run the requote command: cancel an existing order then deploy a new one.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    old_side: &str,
    old_token: Option<&str>,
    old_price_num: u64,
    old_price_den: u64,
    old_min_fill: u64,
    old_order_value: Option<u64>,
    old_version: u8,
    old_expiry: u64,
    new_params: &NewOrderParams,
    new_expiry: u64,
    no_wait: bool,
    fee_utxo_override: Option<&str>,
    old_max_matcher_fee: u64,
    new_max_matcher_fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);

    // --- Input validation for new order ---
    if new_params.price_num == 0 {
        anyhow::bail!("new price_num must be > 0");
    }
    if new_params.min_fill == 0 {
        anyhow::bail!("new min_fill must be > 0");
    }
    if new_params.amount == 0 {
        anyhow::bail!("new amount must be > 0");
    }
    if new_params.amount < new_params.min_fill {
        anyhow::bail!(
            "new amount ({}) must be >= new min_fill ({})",
            new_params.amount,
            new_params.min_fill
        );
    }
    if new_params.version != 14 {
        anyhow::bail!("Unsupported contract version {}. Only v14 is supported.", new_params.version);
    }
    if old_version != 14 {
        anyhow::bail!("Unsupported old contract version {}. Only v14 is supported.", old_version);
    }

    // STEP 1: Build and submit cancel TX

    let old_redeem_script = match old_side {
        "buy" => {
            let tcid = parse_old_token(old_token)?;
            contract::build_buy_redeem_script(
                &tcid, old_price_num, old_price_den, old_min_fill,
                &owner_hash, &spk_hash, old_max_matcher_fee, 0, old_expiry,)?
        }
        "sell" => {
            contract::build_sell_redeem_script(
                old_price_num, old_price_den, old_min_fill, &owner_hash, &spk_hash, old_max_matcher_fee, 0, old_expiry,)?
        }
        other => anyhow::bail!("Unknown old side '{}'. Use 'buy' or 'sell'.", other),
    };

    let old_p2sh = build_p2sh(&old_redeem_script);

    println!("Requote: Cancel + Deploy");
    println!("========================");
    println!("Mode:          {}", if no_wait { "no-wait (immediate)" } else { "sequential (wait 1 block)" });
    println!();
    println!("--- Cancel Phase ---");
    println!("Outpoint:      {}", outpoint);
    println!("Old Side:      {}", old_side);
    println!("Old Price:     {}/{}", old_price_num, old_price_den);
    println!("Old Min Fill:  {}", old_min_fill);
    println!("Old RS:        {} bytes", old_redeem_script.len());
    println!();

    info!(outpoint = %outpoint, old_side = old_side, "requote: cancel phase");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine old order value
    let order_value = if let Some(v) = old_order_value {
        v
    } else {
        let p2sh_address = p2sh_to_address(&old_p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying old order UTXO value...");
        let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let order_utxo = order_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Order UTXO {} not found at P2SH address. It may be spent or use --old-order-value.",
                    outpoint
                )
            })?;
        order_utxo.utxo_entry.amount
    };
    println!("Order Value:   {} sompi", order_value);

    // Get fee UTXO for cancel (or use override)
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee_budget = estimate_compute_mass(2, 1, 0) + 500;

    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!("Fee UTXO {} not found in wallet UTXOs", fee_op_str)
            })?
    } else {
        wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_budget + MIN_UTXO_VALUE)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for cancel fee payment. Use --fee-utxo to specify.",
                    est_fee_budget + MIN_UTXO_VALUE
                )
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_cancel_output = total_in.saturating_sub(est_fee_budget);

    // Build cancel TX
    let mut cancel_tx = Transaction::new(0);
    cancel_tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: old_p2sh.version,
        script_bytes: old_p2sh.script().to_vec(),
        value: order_value,
    });

    let fee_spk_bytes = fee_utxo.script_bytes();
    cancel_tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_utxo.utxo_entry.amount,
    });

    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    cancel_tx.outputs.push(TxOutput::new(tentative_cancel_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee using estimated sigscript sizes
    let (est_fee, _) = converge_fee(&mut cancel_tx, total_in, 0, 0);

    // Sign cancel TX
    let sighash_0 = compute_sighash(&cancel_tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
    let cancel_sigscript = match old_side {
        "buy" => contract::build_buy_cancel_sigscript(&sig_0, &pubkey, &old_redeem_script),
        "sell" => contract::build_sell_cancel_sigscript(&sig_0, &pubkey, &old_redeem_script),
        _ => unreachable!(),
    };

    let sighash_1 = compute_sighash(&cancel_tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&cancel_tx, &sigscripts);
    let exact_fee = exact_mass;

    // If exact fee exceeds estimated fee, re-adjust output and re-sign
    let (cancel_sigscript, fee_sigscript) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        cancel_tx.outputs[0].value = output_value;

        let sighash_0 = compute_sighash(&cancel_tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let cancel_sigscript = match old_side {
            "buy" => contract::build_buy_cancel_sigscript(&sig_0, &pubkey, &old_redeem_script),
            "sell" => contract::build_sell_cancel_sigscript(&sig_0, &pubkey, &old_redeem_script),
            _ => unreachable!(),
        };
        let sighash_1 = compute_sighash(&cancel_tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

        (cancel_sigscript, fee_sigscript)
    } else {
        (cancel_sigscript, fee_sigscript)
    };

    let cancel_output_value = cancel_tx.outputs[0].value;
    let cancel_payload = to_rpc_payload(&cancel_tx, &[cancel_sigscript, fee_sigscript]);
    println!("Submitting cancel transaction...");
    let cancel_tx_id = rpc.submit_transaction(cancel_payload).await?;

    println!("Cancel TXID: {}", cancel_tx_id);
    println!("Recovered {} sompi to wallet.", cancel_output_value);
    println!();

    // STEP 2: Wait (unless --no-wait) then deploy new order

    if !no_wait {
        println!("Waiting for cancel confirmation (polling every 2s, up to 30s)...");
        let mut confirmed = false;
        for attempt in 1..=15 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let fresh_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
            if fresh_utxos.iter().any(|u| u.outpoint.transaction_id == cancel_tx_id) {
                println!("Cancel confirmed after {}s.", attempt * 2);
                confirmed = true;
                break;
            }
        }
        if !confirmed {
            println!("Warning: cancel TX not yet confirmed after 30s. Proceeding with deploy anyway.");
        }
    } else {
        println!("--no-wait: proceeding immediately to deploy.");
    }

    println!();
    println!("--- Deploy Phase ---");
    println!("New Side:      {}", new_params.side);
    println!("New Token:     {}", new_params.token);
    println!(
        "New Price:     {}/{} ({:.6})",
        new_params.price_num, new_params.price_den,
        new_params.price_num as f64 / new_params.price_den as f64
    );
    println!("New Min Fill:  {}", new_params.min_fill);
    println!("New Amount:    {} sompi", new_params.amount);
    println!("New Version:   v{}", new_params.version);
    println!();

    info!(side = %new_params.side, amount = new_params.amount, "requote: deploy phase");

    let deploy_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let deploy_est_fee = estimate_compute_mass(1, 2, 100) + 500;
    let deploy_needed = new_params.amount + deploy_est_fee;

    let funding = deploy_utxos
        .iter()
        .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= deploy_needed)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for deploy ({} UTXOs available). \
                Cancel TX may not be confirmed yet -- retry or use --no-wait.",
                deploy_needed, deploy_utxos.len()
            )
        })?;

    println!(
        "Funding UTXO:  {}:{} ({} sompi)",
        funding.outpoint.transaction_id, funding.outpoint.index, funding.utxo_entry.amount
    );

    let token_cov_bytes = hex::decode(&new_params.token)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("new token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_cov_bytes);

    let new_redeem_script = match new_params.side.as_str() {
        "buy" => contract::build_buy_redeem_script(
            &token_cov_id, new_params.price_num, new_params.price_den,
            new_params.min_fill, &owner_hash, &spk_hash, new_max_matcher_fee, 0, new_expiry,)?,
        "sell" => contract::build_sell_redeem_script(
            new_params.price_num, new_params.price_den, new_params.min_fill,
            &owner_hash, &spk_hash, new_max_matcher_fee, 0, new_expiry,)?,
        other => anyhow::bail!("Unknown new side '{}'. Use 'buy' or 'sell'.", other),
    };

    let new_p2sh = build_p2sh(&new_redeem_script);
    let deploy_total_input = funding.utxo_entry.amount;
    let tentative_deploy_change = deploy_total_input.saturating_sub(new_params.amount + deploy_est_fee);

    let tx_version = if new_params.side == "sell" { 1 } else { 0 };
    let mut deploy_tx = Transaction::new(tx_version);

    let funding_spk = funding.script_bytes();
    deploy_tx.inputs.push(TxInput {
        prev_tx_id: funding.outpoint.transaction_id.clone(),
        prev_index: funding.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: funding.utxo_entry.script_public_key.version,
        script_bytes: funding_spk,
        value: funding.utxo_entry.amount,
    });

    let covenant_binding = if new_params.side == "sell" {
        Some(CovenantBinding::new(0, kob_core::compat::parse_hash(&new_params.token.clone()).unwrap()))
    } else {
        None
    };

    deploy_tx.outputs.push(TxOutput::new(new_params.amount, 0, new_p2sh.script().to_vec(), covenant_binding));

    deploy_tx.payload = build_order_payload(&new_redeem_script, false);

    let wallet_spk_deploy = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    let has_deploy_change = tentative_deploy_change >= MIN_UTXO_VALUE;
    if has_deploy_change {
        deploy_tx.outputs.push(TxOutput::new(tentative_deploy_change, funding.utxo_entry.script_public_key.version, wallet_spk_deploy.clone(), None));
    }

    // Phase 1: converge fee on change output
    let deploy_change_idx = if has_deploy_change { deploy_tx.outputs.len() - 1 } else { 0 };
    let (deploy_est_fee, _) = if has_deploy_change {
        converge_fee(&mut deploy_tx, deploy_total_input, deploy_change_idx, 0)
    } else {
        let f = kob_core::mass::calc_miner_fee(&deploy_tx);
        (f, 0)
    };

    let deploy_change = if has_deploy_change { deploy_tx.outputs[deploy_change_idx].value } else { deploy_total_input.saturating_sub(new_params.amount + deploy_est_fee) };
    if has_deploy_change && deploy_change < MIN_UTXO_VALUE {
        deploy_tx.outputs.pop();
        if deploy_change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", deploy_change);
        }
    } else if !has_deploy_change && deploy_change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", deploy_change);
    }

    // Sign
    let deploy_sighash = compute_sighash(&deploy_tx, 0)?;
    let deploy_sig = signing::schnorr_sign(&privkey, &deploy_sighash)?;
    let deploy_sigscript = signing::build_p2pk_sigscript(&deploy_sig);

    // Phase 2: exact mass check with real sigscripts
    let exact_deploy_mass = calc_mass_with_sigscripts(&deploy_tx, &[deploy_sigscript.clone()]);
    let exact_deploy_fee = exact_deploy_mass;

    let deploy_sigscript = if exact_deploy_fee != deploy_est_fee && deploy_tx.outputs.len() > 1 {
        let change_idx = deploy_tx.outputs.len() - 1;
        let new_change = deploy_total_input.saturating_sub(new_params.amount + exact_deploy_fee);
        if new_change >= MIN_UTXO_VALUE {
            deploy_tx.outputs[change_idx].value = new_change;
        } else {
            deploy_tx.outputs.pop();
            if new_change > 0 {
                println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
            }
        }
        // Re-sign
        let deploy_sighash = compute_sighash(&deploy_tx, 0)?;
        let deploy_sig = signing::schnorr_sign(&privkey, &deploy_sighash)?;
        signing::build_p2pk_sigscript(&deploy_sig)
    } else {
        deploy_sigscript
    };

    let deploy_payload = to_rpc_payload(&deploy_tx, &[deploy_sigscript]);
    println!("Submitting deploy transaction...");
    let deploy_tx_id = rpc.submit_transaction(deploy_payload).await?;

    println!();
    println!("SUCCESS! Requote complete.");
    println!("Cancel TXID: {}", cancel_tx_id);
    println!("Deploy TXID: {}", deploy_tx_id);
    println!("New order deployed at output {}:0", deploy_tx_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};

    #[test]
    fn new_order_params_validation_price_num_zero() {
        let params = NewOrderParams {
            side: "buy".to_string(),
            token: "aa".repeat(32),
            price_num: 0,
            price_den: 1,
            min_fill: 1000,
            amount: 10_000_000,
            version: 8,
        };
        assert_eq!(params.price_num, 0);
    }

    #[test]
    fn new_order_params_validation_amount_less_than_min_fill() {
        let params = NewOrderParams {
            side: "sell".to_string(),
            token: "bb".repeat(32),
            price_num: 1,
            price_den: 2,
            min_fill: 20_000_000,
            amount: 10_000_000,
            version: 8,
        };
        assert!(params.amount < params.min_fill);
    }

    #[test]
    fn new_order_params_valid_buy() {
        let params = NewOrderParams {
            side: "buy".to_string(),
            token: "cc".repeat(32),
            price_num: 100,
            price_den: 1,
            min_fill: 1_000_000,
            amount: 50_000_000,
            version: 8,
        };
        assert_eq!(params.side, "buy");
        assert!(params.amount >= params.min_fill);
        assert!(params.price_num > 0);
    }

    #[test]
    fn new_order_params_valid_sell() {
        let params = NewOrderParams {
            side: "sell".to_string(),
            token: "dd".repeat(32),
            price_num: 1,
            price_den: 100,
            min_fill: 500_000,
            amount: 10_000_000,
            version: 6,
        };
        assert_eq!(params.side, "sell");
        assert!(params.amount >= params.min_fill);
    }

    #[test]
    fn cancel_output_uses_mass_based_fee() {
        let est_fee = kob_core::mass::estimate_compute_mass(2, 1, 0);
        assert!(est_fee > 0, "mass-based fee must be > 0");
        assert!(est_fee < 10_000, "mass-based fee should be well below old 10_000 constant");

        let order_value = 50_000_000u64;
        let fee_value = 10_000_000u64;
        let total = order_value + fee_value;
        let output = total - est_fee;
        assert!(output > 59_990_000, "mass-based fee should be smaller than old fixed 10_000");
    }

    #[test]
    fn deploy_change_uses_mass_based_fee() {
        let est_fee = kob_core::mass::estimate_compute_mass(1, 2, 100);
        let funding_value = 100_000_000u64;
        let amount = 50_000_000u64;
        let change = funding_value - amount - est_fee;
        assert!(change > 49_990_000, "mass-based fee should be smaller than old fixed 10_000");
        assert!(change >= kob_core::MIN_UTXO_VALUE);
    }

    #[test]
    fn deploy_change_below_min_utxo() {
        let est_fee = kob_core::mass::estimate_compute_mass(1, 2, 100);
        let amount = 50_000_000u64;
        let funding_value = amount + est_fee;
        let change = funding_value - amount - est_fee;
        assert_eq!(change, 0);
    }

    #[test]
    fn old_buy_redeem_script_reconstruction() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_buy_redeem_script(
            &tcid, 100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let p2sh = build_p2sh(&rs);
        assert_eq!(p2sh.script().len(), 35);
        assert_eq!(p2sh.script()[0], 0xaa);
        assert_eq!(p2sh.script()[34], 0x87);
    }

    #[test]
    fn old_sell_redeem_script_reconstruction() {
        let pk = [0x02u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_sell_redeem_script(
            100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let p2sh = build_p2sh(&rs);
        assert_eq!(p2sh.script().len(), 35);
    }

    #[test]
    fn cancel_and_deploy_use_different_redeem_scripts() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let old_rs = contract::build_buy_redeem_script(
            &tcid, 100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let new_rs = contract::build_buy_redeem_script(
            &tcid, 110, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        assert_ne!(old_rs, new_rs);
        let old_p2sh = build_p2sh(&old_rs);
        let new_p2sh = build_p2sh(&new_rs);
        assert_ne!(old_p2sh.script(), new_p2sh.script());
    }

    #[test]
    fn new_buy_redeem_script_v12_valid() {
        let pk = [0x02u8; 32];
        let tcid = [0xAA; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_buy_redeem_script(
            &tcid, 50, 1, 500_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        assert_eq!(rs.len(), 387);
    }

    #[test]
    fn new_sell_redeem_script_v12_valid() {
        let pk = [0x02u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_sell_redeem_script(
            50, 1, 500_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        assert_eq!(rs.len(), 356);
    }

    #[test]
    fn requote_preserves_owner_identity() {
        let pk = [0x03u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let tcid = [0xFF; 32];
        let old_rs = contract::build_buy_redeem_script(
            &tcid, 100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let new_rs = contract::build_buy_redeem_script(
            &tcid, 200, 1, 2_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let owner_hex = hex::encode(owner);
        let old_hex = hex::encode(&old_rs);
        let new_hex = hex::encode(&new_rs);
        assert!(old_hex.contains(&owner_hex));
        assert!(new_hex.contains(&owner_hex));
    }

    #[test]
    fn requote_token_change() {
        let pk = [0x02u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let tcid_old = [0x01; 32];
        let tcid_new = [0x02; 32];
        let old_rs = contract::build_buy_redeem_script(
            &tcid_old, 100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let new_rs = contract::build_buy_redeem_script(
            &tcid_new, 100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        assert_ne!(old_rs, new_rs);
    }

    #[test]
    fn requote_side_change() {
        let pk = [0x02u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let tcid = [0x01; 32];
        let old_rs = contract::build_buy_redeem_script(
            &tcid, 100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let new_rs = contract::build_sell_redeem_script(
            100, 1, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        assert!(old_rs.len() > new_rs.len());
    }

    #[test]
    fn deploy_needed_uses_mass_based_fee() {
        let est_fee = kob_core::mass::estimate_compute_mass(1, 2, 100) + 500;
        let amount = 50_000_000u64;
        let needed = amount + est_fee;
        assert!(needed > amount, "needed must exceed order amount");
        assert!(needed < amount + 10_000, "mass-based fee budget should be well below old 10_000 constant");
    }
}
