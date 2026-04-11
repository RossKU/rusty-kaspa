//! `kob-cli lending` -- P2P lending commands.
//!
//! Supports:
//!   - `lending offer`:         Deploy a loan offer (lender locks principal KAS)
//!   - `lending request`:       Deploy a borrow request (borrower locks collateral)
//!   - `lending cancel`:        Cancel an unmatched offer or request
//!   - `lending repay`:         Repay an active loan (borrower)
//!   - `lending claim-default`: Claim collateral after loan default (lender)
//!   - `lending liquidate`:     Liquidate undercollateralized loan (permissionless)
//!   - `lending loans`:         List active loans (via engine REST API)

use crate::cancel::p2sh_to_address;
use crate::node::NodeClient;
use crate::signing;
use kob_core::lending::{
    build_active_loan_default_sigscript, build_active_loan_liquidate_sigscript,
    build_active_loan_repay_sigscript, build_borrow_request_cancel_sigscript,
    build_borrow_request_redeem_script, build_lending_payload,
    build_loan_offer_cancel_sigscript, build_loan_offer_redeem_script,
    calculate_interest,
};
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, converge_fee, estimate_compute_mass, MAX_TX_MASS};
use kob_core::p2sh::build_p2sh;
use kob_core::sighash::compute_sighash;
use kob_core::tx::{select_utxos_mass_aware, to_rpc_payload, CoinSelection, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint, UtxoEntry};
use kob_core::wallet::WalletFile;
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

// lending offer — deploy a loan offer

/// Deploy a loan offer (lender locks principal KAS with rate/collateral terms).
///
/// TX structure:
///   inputs:  wallet P2PK UTXOs (funding)
///   output[0]: P2SH covenant (loan_offer)
///   output[1]: change (if any)
///   payload: KOB:L:<RS>
#[allow(clippy::too_many_arguments)]
pub async fn deploy_offer(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    amount: u64,
    rate_num: u64,
    rate_den: u64,
    duration_daa: u64,
    min_collateral_ratio: u64,
    token: &str,
    fee: u64,
    rate_mode: u64,
    rate_floor_num: u64,
) -> anyhow::Result<String> {
    // Input validation
    if amount == 0 {
        anyhow::bail!("amount must be > 0");
    }
    if rate_num == 0 {
        anyhow::bail!("rate_num must be > 0");
    }
    if rate_den == 0 {
        anyhow::bail!("rate_den must be > 0");
    }
    if duration_daa == 0 {
        anyhow::bail!("duration_daa must be > 0");
    }
    if min_collateral_ratio == 0 {
        anyhow::bail!("min_collateral_ratio must be > 0 (e.g. 15000 for 150%)");
    }

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    // Parse collateral token covenant ID
    let token_bytes = hex::decode(token)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut collateral_cov_id = [0u8; 32];
    collateral_cov_id.copy_from_slice(&token_bytes);

    let spk_hash = kob_core::blake2b_256(&pubkey);

    let redeem_script = build_loan_offer_redeem_script(
        &spk_hash,
        amount,
        rate_num,
        rate_den,
        min_collateral_ratio,
        duration_daa,
        &collateral_cov_id,
        rate_mode,
        rate_floor_num,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Loan Offer (v3)");
    println!("=======================");
    println!(
        "Principal:          {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    println!(
        "Rate:               {}/{} ({:.4}%)",
        rate_num,
        rate_den,
        rate_num as f64 / rate_den as f64 * 100.0
    );
    println!("Max Duration:       {} DAA", duration_daa);
    println!(
        "Min Collateral:     {} ({:.2}%)",
        min_collateral_ratio,
        min_collateral_ratio as f64 / 100.0
    );
    println!("Collateral Token:   {}", token);
    println!(
        "Rate Mode:          {}",
        if rate_mode == 0 { "fixed" } else { "variable" }
    );
    if rate_mode == 1 {
        println!("Rate Floor:         {}", rate_floor_num);
    }
    println!("Owner:              {}", wallet.public_key);
    println!();
    println!(
        "RedeemScript:       {} bytes",
        redeem_script.len()
    );
    println!("P2SH SPK:           {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch UTXOs
    info!(address = %wallet.address, amount = amount, "deploying loan offer");
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
        select_utxos_mass_aware(&core_utxos, amount, fee, 2).map_err(|e| {
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

    // Build transaction
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

    // Output 0: P2SH covenant (loan offer)
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

    // TX payload: KOB:L:<RS> for matcher L1 discovery
    tx.payload = build_lending_payload(&redeem_script);

    // Output 1: tentative change
    let tent_change = total_input.saturating_sub(amount + fee);
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
        converge_fee(&mut tx, total_input, change_idx, min_fee_override)
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
    let exact_fee = exact_mass.max(min_fee_override);
    let actual_fee = if exact_fee != est_fee { exact_fee } else { est_fee };
    if exact_fee != est_fee && tx.outputs.len() > 1 {
        let ci = tx.outputs.len() - 1;
        let nc = total_input.saturating_sub(amount + exact_fee);
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
    }

    println!("Signed {} input(s)", sigscripts.len());
    println!();

    // Storage mass pre-check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected by node: {}. \
             Increase the offer amount or use a larger funding UTXO.",
            e
        );
    }

    // Fee transparency summary
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
    println!("SUCCESS! Loan offer deployed.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Offer deployed at output {}:0", tx_id);

    Ok(tx_id)
}

// lending request — deploy a borrow request

/// Deploy a borrow request (borrower locks collateral).
///
/// TX structure:
///   inputs:  wallet P2PK UTXOs (funding collateral)
///   output[0]: P2SH covenant (borrow_request)
///   output[1]: change (if any)
///   payload: KOB:L:<RS>
#[allow(clippy::too_many_arguments)]
pub async fn deploy_request(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    collateral: u64,
    max_rate_num: u64,
    max_rate_den: u64,
    amount_requested: u64,
    duration_daa: u64,
    token: &str,
    fee: u64,
    rate_mode: u64,
    rate_cap_num: u64,
) -> anyhow::Result<String> {
    // Input validation
    if collateral == 0 {
        anyhow::bail!("collateral must be > 0");
    }
    if max_rate_num == 0 {
        anyhow::bail!("max_rate_num must be > 0");
    }
    if max_rate_den == 0 {
        anyhow::bail!("max_rate_den must be > 0");
    }
    if amount_requested == 0 {
        anyhow::bail!("amount_requested must be > 0");
    }
    if duration_daa == 0 {
        anyhow::bail!("duration_daa must be > 0");
    }

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    // Parse collateral token covenant ID
    let token_bytes = hex::decode(token)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut collateral_cov_id = [0u8; 32];
    collateral_cov_id.copy_from_slice(&token_bytes);

    let spk_hash = kob_core::blake2b_256(&pubkey);

    let redeem_script = build_borrow_request_redeem_script(
        &spk_hash,
        amount_requested,
        max_rate_num,
        max_rate_den,
        duration_daa,
        &collateral_cov_id,
        rate_mode,
        rate_cap_num,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Borrow Request (v3)");
    println!("===========================");
    println!(
        "Collateral:         {} sompi ({:.8} KAS)",
        collateral,
        collateral as f64 / 1e8
    );
    println!(
        "Amount Requested:   {} sompi ({:.8} KAS)",
        amount_requested,
        amount_requested as f64 / 1e8
    );
    println!(
        "Max Rate:           {}/{} ({:.4}%)",
        max_rate_num,
        max_rate_den,
        max_rate_num as f64 / max_rate_den as f64 * 100.0
    );
    println!("Duration:           {} DAA", duration_daa);
    println!("Collateral Token:   {}", token);
    println!(
        "Rate Mode:          {}",
        match rate_mode {
            0 => "fixed",
            1 => "variable",
            _ => "either",
        }
    );
    if rate_mode >= 1 {
        println!("Rate Cap:           {}", rate_cap_num);
    }
    println!("Owner:              {}", wallet.public_key);
    println!();
    println!(
        "RedeemScript:       {} bytes",
        redeem_script.len()
    );
    println!("P2SH SPK:           {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch UTXOs
    info!(address = %wallet.address, collateral = collateral, "deploying borrow request");
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
        select_utxos_mass_aware(&core_utxos, collateral, fee, 2).map_err(|e| {
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

    // Build transaction
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

    // Output 0: P2SH covenant (borrow request)
    tx.outputs.push(TxOutput::new(collateral, 0, p2sh.script().to_vec(), None));

    // TX payload: KOB:L:<RS> for matcher L1 discovery
    tx.payload = build_lending_payload(&redeem_script);

    // Output 1: tentative change
    let tent_change_req = total_input.saturating_sub(collateral + fee);
    let first_rpc = p2pk_rpc
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                && u.outpoint.index == selected_utxos[0].outpoint.index
        })
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
    let wallet_spk_req = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
    if tent_change_req >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tent_change_req, first_rpc.utxo_entry.script_public_key.version, wallet_spk_req.clone(), None));
    }

    // Phase 1: converge fee
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change = tx.outputs.len() > 1;
    let change_idx = tx.outputs.len().saturating_sub(1);
    let (est_fee, _) = if has_change {
        converge_fee(&mut tx, total_input, change_idx, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    if has_change && tx.outputs[change_idx].value < MIN_UTXO_VALUE {
        let cv = tx.outputs[change_idx].value;
        tx.outputs.pop();
        if cv > 0 { println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", cv); }
    } else if !has_change && tent_change_req > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", tent_change_req);
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
    let exact_fee = exact_mass.max(min_fee_override);
    let actual_fee = if exact_fee != est_fee { exact_fee } else { est_fee };
    if exact_fee != est_fee && tx.outputs.len() > 1 {
        let ci = tx.outputs.len() - 1;
        let nc = total_input.saturating_sub(collateral + exact_fee);
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
    }

    println!("Signed {} input(s)", sigscripts.len());
    println!();

    // Storage mass pre-check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected by node: {}. \
             Increase the collateral amount or use a larger funding UTXO.",
            e
        );
    }

    // Fee transparency summary
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
    println!("SUCCESS! Borrow request deployed.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Request deployed at output {}:0", tx_id);

    Ok(tx_id)
}

// lending cancel — cancel an unmatched offer or request

/// Cancel an unmatched loan offer or borrow request.
///
/// TX structure:
///   input[0]: lending UTXO (P2SH, cancel sigscript)
///   input[1]: fee UTXO (P2PK, signed)
///   output[0]: recovered funds to wallet
#[allow(clippy::too_many_arguments)]
pub async fn cancel(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    side: &str,
    // Offer params (used only when side = "offer")
    offer_principal: u64,
    offer_rate_num: u64,
    offer_rate_den: u64,
    offer_min_collateral_ratio: u64,
    offer_max_duration_daa: u64,
    offer_rate_mode: u64,
    offer_rate_floor_num: u64,
    // Request params (used only when side = "request")
    req_desired_amount: u64,
    req_max_rate_num: u64,
    req_max_rate_den: u64,
    req_min_duration_daa: u64,
    req_rate_mode: u64,
    req_rate_cap_num: u64,
    // Common params
    token: &str,
    order_value_override: Option<u64>,
    fee: u64,
    fee_utxo_override: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let spk_hash = kob_core::blake2b_256(&pubkey);

    // Parse token covenant ID
    let token_bytes = hex::decode(token)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut cov_id = [0u8; 32];
    cov_id.copy_from_slice(&token_bytes);

    // Reconstruct the redeemScript based on side
    let redeem_script = match side {
        "offer" => build_loan_offer_redeem_script(
            &spk_hash,
            offer_principal,
            offer_rate_num,
            offer_rate_den,
            offer_min_collateral_ratio,
            offer_max_duration_daa,
            &cov_id,
            offer_rate_mode,
            offer_rate_floor_num,
        )?,
        "request" => build_borrow_request_redeem_script(
            &spk_hash,
            req_desired_amount,
            req_max_rate_num,
            req_max_rate_den,
            req_min_duration_daa,
            &cov_id,
            req_rate_mode,
            req_rate_cap_num,
        )?,
        other => anyhow::bail!("Unknown side '{}'. Use 'offer' or 'request'.", other),
    };

    let p2sh = build_p2sh(&redeem_script);

    println!("Cancel Lending {}", if side == "offer" { "Offer" } else { "Request" });
    println!("======================");
    println!("Outpoint:      {}", outpoint);
    println!("Side:          {}", side);
    println!("Owner:         {}", wallet.public_key);
    println!("RedeemScript:  {} bytes", redeem_script.len());
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    // Connect to node
    info!(outpoint = %outpoint, side = side, "cancelling lending order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine the UTXO value
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

    // Get a fee UTXO from the wallet
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Fee UTXO {} not found in wallet UTXOs.",
                    fee_op_str
                )
            })?
    } else {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates
            .first()
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for fee payment",
                    est_fee + MIN_UTXO_VALUE
                )
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build the cancel transaction with tentative output value
    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in - est_fee;
    let mut tx = Transaction::new(0);

    // Input 0: lending UTXO (P2SH)
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

    let cancel_sigscript = match side {
        "offer" => build_loan_offer_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
        "request" => build_borrow_request_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
        _ => unreachable!(),
    };

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check
    let sigscripts_cancel = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_cancel);
    let exact_fee = exact_mass.max(min_fee_override);

    let (cancel_sigscript, fee_sigscript, actual_fee) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
        let cancel_sigscript = match side {
            "offer" => build_loan_offer_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
            "request" => build_borrow_request_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
            _ => unreachable!(),
        };
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
    println!("SUCCESS! Cancel transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

// lending repay — repay an active loan

/// Repay an active loan (borrower signs, returns principal + interest to lender).
///
/// TX structure:
///   input[0]: active_loan UTXO (P2SH, repay sigscript with selector=3)
///   input[1]: funding UTXO (borrower's P2PK, covers repayment + fee)
///   output[0]: lender receives principal + interest
///   output[1]: borrower receives remaining collateral
///
/// The borrower must know the loan's RS parameters to reconstruct it.
#[allow(clippy::too_many_arguments)]
pub async fn repay(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    loan_outpoint_str: &str,
    // Active loan RS state (14 fields)
    insurer_spk_hash: &[u8; 32],
    lender_spk_hash: &[u8; 32],
    principal: u64,
    rate_num: u64,
    rate_den: u64,
    start_daa: u64,
    expiry_daa: u64,
    collateral_cov_id: &[u8; 32],
    rate_mode: u64,
    rate_floor_num: u64,
    rate_cap_num: u64,
    grace_daa: u64,
    liq_threshold: u64,
    // Lender destination SPK
    lender_spk_hex: &str,
    // Collateral value (queried if None)
    collateral_override: Option<u64>,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let loan_outpoint = Outpoint::parse(loan_outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;
    let borrower_spk_hash = kob_core::blake2b_256(&pubkey);

    // Reconstruct the active_loan RS
    let redeem_script = kob_core::lending::build_active_loan_redeem_script(
        insurer_spk_hash,
        lender_spk_hash,
        &borrower_spk_hash,
        principal,
        rate_num,
        rate_den,
        start_daa,
        expiry_daa,
        collateral_cov_id,
        rate_mode,
        rate_floor_num,
        rate_cap_num,
        grace_daa,
        liq_threshold,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    // Get current DAA score from node
    info!(outpoint = %loan_outpoint, "repaying loan");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let current_daa = rpc.get_daa_score().await?;
    let elapsed_daa = current_daa.saturating_sub(start_daa);

    let interest = calculate_interest(principal, rate_num, rate_den, elapsed_daa)
        .ok_or_else(|| anyhow::anyhow!("Interest calculation overflow"))?;
    let repay_total = principal
        .checked_add(interest)
        .ok_or_else(|| anyhow::anyhow!("principal + interest overflow"))?;

    println!("Repay Active Loan");
    println!("==================");
    println!("Loan Outpoint:     {}", loan_outpoint);
    println!(
        "Principal:         {} sompi ({:.8} KAS)",
        principal,
        principal as f64 / 1e8
    );
    println!(
        "Rate:              {}/{} ({})",
        rate_num,
        rate_den,
        if rate_den > 0 { format!("{:.4}%", rate_num as f64 / rate_den as f64 * 100.0) } else { "N/A".to_string() }
    );
    println!("Elapsed DAA:       {}", elapsed_daa);
    println!(
        "Interest:          {} sompi ({:.8} KAS)",
        interest,
        interest as f64 / 1e8
    );
    println!(
        "Repay Total:       {} sompi ({:.8} KAS)",
        repay_total,
        repay_total as f64 / 1e8
    );
    println!("RedeemScript:      {} bytes", redeem_script.len());
    println!();

    // Query collateral value from chain
    let collateral = if let Some(v) = collateral_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying loan UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == loan_outpoint.transaction_id
                    && u.outpoint.index == loan_outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Loan UTXO {} not found. It may be spent or use --collateral.",
                    loan_outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("Collateral:        {} sompi", collateral);

    // Determine if we need extra funding from wallet
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    let needs_funding = repay_total + fee > collateral;
    let funding_needed = if needs_funding {
        repay_total + fee - collateral
    } else {
        0
    };

    let lender_spk_bytes = hex::decode(lender_spk_hex)?;

    let mut tx = Transaction::new(0);

    // Input 0: active loan UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: loan_outpoint.transaction_id.clone(),
        prev_index: loan_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: collateral,
    });

    // Input 1: funding UTXO (if needed)
    let funding_utxo = if needs_funding {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= funding_needed + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        let fu = candidates.first().copied().ok_or_else(|| {
            anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for repayment funding. \
                 Need {} sompi above collateral to cover principal + interest + fee.",
                funding_needed + MIN_UTXO_VALUE,
                funding_needed
            )
        })?;

        println!(
            "Funding UTXO:      {}:{} ({} sompi)",
            fu.outpoint.transaction_id, fu.outpoint.index, fu.utxo_entry.amount
        );

        tx.inputs.push(TxInput {
            prev_tx_id: fu.outpoint.transaction_id.clone(),
            prev_index: fu.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: fu.utxo_entry.script_public_key.version,
            script_bytes: fu.script_bytes(),
            value: fu.utxo_entry.amount,
        });

        Some(fu)
    } else {
        None
    };

    let total_in = collateral + funding_utxo.map_or(0, |u| u.utxo_entry.amount);

    // Output 0: lender receives principal + interest
    tx.outputs.push(TxOutput::new(repay_total, 0, lender_spk_bytes, None));

    // Output 1: borrower receives remaining collateral (tentative)
    let tent_borrower_return = total_in.saturating_sub(repay_total + fee);
    let _borrower_spk = if tent_borrower_return >= MIN_UTXO_VALUE {
        let spk = hex::decode(
            &wallet_utxos
                .iter()
                .find(|u| !u.is_p2sh())
                .map(|u| u.utxo_entry.script_public_key.script.clone())
                .unwrap_or_else(|| wallet.public_key.clone()),
        )?;
        tx.outputs.push(TxOutput::new(tent_borrower_return, 0, spk.clone(), None));
        Some(spk)
    } else {
        if tent_borrower_return > 0 {
            println!("Borrower return {} sompi below MIN_UTXO_VALUE, donated as fee.", tent_borrower_return);
        }
        None
    };

    // Phase 1: converge fee on borrower return output
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_borrower_out = tx.outputs.len() > 1;
    let change_idx_repay = tx.outputs.len().saturating_sub(1);
    let (est_fee_repay, _) = if has_borrower_out {
        converge_fee(&mut tx, total_in, change_idx_repay, min_fee_override)
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    if has_borrower_out && tx.outputs[change_idx_repay].value < MIN_UTXO_VALUE {
        let cv = tx.outputs[change_idx_repay].value;
        tx.outputs.pop();
        if cv > 0 { println!("Borrower return {} sompi below MIN_UTXO_VALUE, donated as fee.", cv); }
    }

    let borrower_return = if tx.outputs.len() > 1 { tx.outputs[1].value } else { 0 };

    println!("Lender receives:   {} sompi", repay_total);
    println!("Borrower return:   {} sompi", borrower_return);
    println!();

    // Helper: sign all inputs for repay
    let sign_repay = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let sighash_0 = compute_sighash(tx, 0)?;
        let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
        let lender_output_idx: u8 = 0;
        let repay_sigscript = build_active_loan_repay_sigscript(&sig_0, &pubkey, lender_output_idx, &redeem_script);
        let mut sigscripts = vec![repay_sigscript];
        if funding_utxo.is_some() {
            let sighash_1 = compute_sighash(tx, 1)?;
            let sig_1 = signing::schnorr_sign_secure(&privkey, &sighash_1)?;
            sigscripts.push(signing::build_p2pk_sigscript(&sig_1));
        }
        Ok(sigscripts)
    };

    let mut sigscripts = sign_repay(&tx)?;

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = exact_mass.max(min_fee_override);

    let actual_fee = if exact_fee != est_fee_repay { exact_fee } else { est_fee_repay };
    if exact_fee != est_fee_repay && tx.outputs.len() > 1 {
        let ci = tx.outputs.len() - 1;
        let nc = total_in.saturating_sub(repay_total + exact_fee);
        if nc >= MIN_UTXO_VALUE { tx.outputs[ci].value = nc; } else {
            tx.outputs.pop();
            if nc > 0 { println!("Borrower return {} sompi below MIN_UTXO_VALUE, donated as fee.", nc); }
        }
        sigscripts = sign_repay(&tx)?;
    }

    println!("Repay SigScript:   {} bytes", sigscripts[0].len());
    println!();

    // Fee transparency
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Repay TX mass:    {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting repay transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Repay transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!(
        "Lender received {} sompi (principal {} + interest {}).",
        repay_total, principal, interest
    );
    println!("Borrower received {} sompi (remaining collateral).", borrower_return);

    Ok(())
}

// lending claim-default — lender claims collateral after expiry+grace

/// Claim defaulted loan collateral (lender).
///
/// TX structure:
///   input[0]:  active loan UTXO (P2SH)
///   output[0]: lender receives collateral (minus fee)
///
/// The lender signs with selector=2 (default claim path).
/// Only valid after expiry_daa + grace_daa has passed.
#[allow(clippy::too_many_arguments)]
pub async fn claim_default(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    loan_outpoint_str: &str,
    // Active loan RS state (14 fields)
    insurer_spk_hash: &[u8; 32],
    lender_spk_hash: &[u8; 32],
    borrower_spk_hash: &[u8; 32],
    principal: u64,
    rate_num: u64,
    rate_den: u64,
    start_daa: u64,
    expiry_daa: u64,
    collateral_cov_id: &[u8; 32],
    rate_mode: u64,
    rate_floor_num: u64,
    rate_cap_num: u64,
    grace_daa: u64,
    liq_threshold: u64,
    // Collateral value (queried if None)
    collateral_override: Option<u64>,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let loan_outpoint = Outpoint::parse(loan_outpoint_str)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    // Verify the caller is the lender
    let caller_spk_hash = kob_core::blake2b_256(&pubkey);
    if &caller_spk_hash != lender_spk_hash {
        anyhow::bail!(
            "Wallet public key does not match lender_spk_hash. \
             Only the lender can claim a defaulted loan."
        );
    }

    // Reconstruct the active_loan RS
    let redeem_script = kob_core::lending::build_active_loan_redeem_script(
        insurer_spk_hash,
        lender_spk_hash,
        borrower_spk_hash,
        principal,
        rate_num,
        rate_den,
        start_daa,
        expiry_daa,
        collateral_cov_id,
        rate_mode,
        rate_floor_num,
        rate_cap_num,
        grace_daa,
        liq_threshold,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    info!(outpoint = %loan_outpoint, "claiming defaulted loan");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Verify we are past expiry + grace
    let current_daa = rpc.get_daa_score().await?;
    let default_daa = expiry_daa.saturating_add(grace_daa);
    if current_daa < default_daa {
        anyhow::bail!(
            "Loan not yet in default. Current DAA={}, default threshold={} (expiry {} + grace {}). \
             Wait {} more DAA.",
            current_daa,
            default_daa,
            expiry_daa,
            grace_daa,
            default_daa.saturating_sub(current_daa),
        );
    }

    // Query collateral value from chain
    let collateral = if let Some(v) = collateral_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying loan UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == loan_outpoint.transaction_id
                    && u.outpoint.index == loan_outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Loan UTXO {} not found. It may be spent or use --collateral.",
                    loan_outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    println!("Claim Default");
    println!("==============");
    println!("Loan Outpoint:     {}", loan_outpoint);
    println!(
        "Collateral:        {} sompi ({:.8} KAS)",
        collateral,
        collateral as f64 / 1e8
    );
    println!("Current DAA:       {}", current_daa);
    println!("Default Threshold: {} (expiry {} + grace {})", default_daa, expiry_daa, grace_daa);
    println!("RedeemScript:      {} bytes", redeem_script.len());
    println!();

    // Build transaction -- lock_time must be >= expiry + grace for CLTV
    let mut tx = Transaction::new(0);
    tx.lock_time = current_daa;

    // Input 0: active loan UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: loan_outpoint.transaction_id.clone(),
        prev_index: loan_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: collateral,
    });

    // Output 0: lender receives collateral minus fee (tentative)
    let lender_spk = {
        let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
        hex::decode(
            &wallet_utxos
                .iter()
                .find(|u| !u.is_p2sh())
                .map(|u| u.utxo_entry.script_public_key.script.clone())
                .unwrap_or_else(|| wallet.public_key.clone()),
        )?
    };
    let tent_claim = collateral.saturating_sub(estimate_compute_mass(1, 1, 0));
    tx.outputs.push(TxOutput::new(tent_claim, 0, lender_spk, None));

    // Phase 1: converge fee on output 0
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee_claim, _) = converge_fee(&mut tx, collateral, 0, min_fee_override);

    let claim_amount = tx.outputs[0].value;
    if claim_amount < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Collateral {} sompi minus fee {} sompi = {} sompi, below MIN_UTXO_VALUE.",
            collateral, est_fee_claim, claim_amount,
        );
    }

    println!("Claim Amount:      {} sompi ({:.8} KAS)", claim_amount, claim_amount as f64 / 1e8);

    // Sign input 0 (default claim path: selector=2, lender sig)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
    let default_sigscript = build_active_loan_default_sigscript(&sig_0, &pubkey, &redeem_script);

    // Phase 2: exact mass check
    let sigscripts_claim = vec![default_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_claim);
    let exact_fee = exact_mass.max(min_fee_override);

    let (sigscripts, actual_fee) = if exact_fee != est_fee_claim {
        let new_claim = collateral.saturating_sub(exact_fee);
        tx.outputs[0].value = new_claim;
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;
        let ss = build_active_loan_default_sigscript(&sig_0, &pubkey, &redeem_script);
        (vec![ss], exact_fee)
    } else {
        (sigscripts_claim, est_fee_claim)
    };

    println!("Default SigScript: {} bytes", sigscripts[0].len());

    // Fee transparency
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Claim TX mass:    {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting claim-default transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Default claim transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!(
        "Lender claimed {} sompi from defaulted loan.",
        claim_amount
    );

    Ok(())
}

// lending liquidate — permissionless liquidation of undercollateralized loan

/// Liquidate an undercollateralized active loan (permissionless).
///
/// TX structure:
///   input[0]:  price oracle input (provides current price data)
///   input[1]:  active loan UTXO (P2SH)
///   input[2]:  funding UTXO (liquidator's P2PK, covers lender repayment)
///   output[0]: lender receives outstanding debt
///   output[1]: borrower receives remaining collateral
///   output[2]: liquidator receives bonus
///   output[3]: change (if any)
///
/// Selector=1 (liquidate path). No signature on the covenant input;
/// the covenant script validates price feed + collateral ratio.
#[allow(clippy::too_many_arguments)]
pub async fn liquidate(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    loan_outpoint_str: &str,
    // Active loan RS state (14 fields)
    insurer_spk_hash: &[u8; 32],
    lender_spk_hash: &[u8; 32],
    borrower_spk_hash: &[u8; 32],
    principal: u64,
    rate_num: u64,
    rate_den: u64,
    start_daa: u64,
    expiry_daa: u64,
    collateral_cov_id: &[u8; 32],
    rate_mode: u64,
    rate_floor_num: u64,
    rate_cap_num: u64,
    grace_daa: u64,
    liq_threshold: u64,
    // Lender destination SPK
    lender_spk_hex: &str,
    // Borrower destination SPK
    borrower_spk_hex: &str,
    // Price oracle input outpoint
    price_outpoint_str: &str,
    // Liquidator bonus (sompi) — paid from collateral surplus
    liquidator_bonus: u64,
    // Collateral value (queried if None)
    collateral_override: Option<u64>,
    fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let loan_outpoint = Outpoint::parse(loan_outpoint_str)?;
    let price_outpoint = Outpoint::parse(price_outpoint_str)?;
    let _pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    // Reconstruct the active_loan RS
    let redeem_script = kob_core::lending::build_active_loan_redeem_script(
        insurer_spk_hash,
        lender_spk_hash,
        borrower_spk_hash,
        principal,
        rate_num,
        rate_den,
        start_daa,
        expiry_daa,
        collateral_cov_id,
        rate_mode,
        rate_floor_num,
        rate_cap_num,
        grace_daa,
        liq_threshold,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    info!(outpoint = %loan_outpoint, "liquidating loan");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let current_daa = rpc.get_daa_score().await?;
    let elapsed_daa = current_daa.saturating_sub(start_daa);

    let interest = calculate_interest(principal, rate_num, rate_den, elapsed_daa)
        .ok_or_else(|| anyhow::anyhow!("Interest calculation overflow"))?;
    let debt = principal
        .checked_add(interest)
        .ok_or_else(|| anyhow::anyhow!("principal + interest overflow"))?;

    // Query collateral value from chain
    let collateral = if let Some(v) = collateral_override {
        v
    } else {
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying loan UTXO value from chain...");
        let utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let utxo = utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == loan_outpoint.transaction_id
                    && u.outpoint.index == loan_outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Loan UTXO {} not found. It may be spent or use --collateral.",
                    loan_outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };

    let lender_spk_bytes = hex::decode(lender_spk_hex)?;
    let borrower_spk_bytes = hex::decode(borrower_spk_hex)?;

    // Borrower remainder = collateral - debt - bonus - fee (can be 0)
    let borrower_return = collateral
        .saturating_sub(debt)
        .saturating_sub(liquidator_bonus)
        .saturating_sub(fee);

    println!("Liquidate Active Loan");
    println!("=====================");
    println!("Loan Outpoint:     {}", loan_outpoint);
    println!("Price Outpoint:    {}", price_outpoint);
    println!(
        "Principal:         {} sompi ({:.8} KAS)",
        principal,
        principal as f64 / 1e8
    );
    println!(
        "Accrued Interest:  {} sompi ({:.8} KAS)",
        interest,
        interest as f64 / 1e8
    );
    println!(
        "Total Debt:        {} sompi ({:.8} KAS)",
        debt,
        debt as f64 / 1e8
    );
    println!(
        "Collateral:        {} sompi ({:.8} KAS)",
        collateral,
        collateral as f64 / 1e8
    );
    println!(
        "Liq Threshold:     {} ({:.2}%)",
        liq_threshold,
        liq_threshold as f64 / 100.0
    );
    println!(
        "Liquidator Bonus:  {} sompi ({:.8} KAS)",
        liquidator_bonus,
        liquidator_bonus as f64 / 1e8
    );
    println!(
        "Borrower Return:   {} sompi ({:.8} KAS)",
        borrower_return,
        borrower_return as f64 / 1e8
    );
    println!("RedeemScript:      {} bytes", redeem_script.len());
    println!();

    // Build transaction
    let mut tx = Transaction::new(0);

    // Input 0: price oracle input
    // The price oracle UTXO provides price data validated by the covenant.
    // We query it from the chain to get its value and script.
    let price_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let price_utxo_entry = price_utxos
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == price_outpoint.transaction_id
                && u.outpoint.index == price_outpoint.index
        });

    // If the price outpoint is not in our wallet, we still add it as input
    // but the covenant validates it based on its structure.
    let (price_value, price_script_version, price_script_bytes) = match price_utxo_entry {
        Some(u) => (u.utxo_entry.amount, u.utxo_entry.script_public_key.version, u.script_bytes()),
        None => {
            // Attempt to resolve from chain by address lookup
            anyhow::bail!(
                "Price oracle UTXO {} not found in wallet UTXOs. \
                 The price oracle input must be spendable by the liquidator.",
                price_outpoint
            );
        }
    };

    tx.inputs.push(TxInput {
        prev_tx_id: price_outpoint.transaction_id.clone(),
        prev_index: price_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: price_script_version,
        script_bytes: price_script_bytes,
        value: price_value,
    });

    // Input 1: active loan UTXO (P2SH)
    tx.inputs.push(TxInput {
        prev_tx_id: loan_outpoint.transaction_id.clone(),
        prev_index: loan_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: collateral,
    });

    // Output 0: lender receives outstanding debt
    tx.outputs.push(TxOutput::new(debt, 0, lender_spk_bytes, None));

    // Output 1: borrower receives remaining collateral
    if borrower_return >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(borrower_return, 0, borrower_spk_bytes, None));
    } else if borrower_return > 0 {
        println!(
            "Borrower return {} sompi below MIN_UTXO_VALUE, donated as fee.",
            borrower_return
        );
    }

    // Output 2: liquidator receives bonus
    let liquidator_spk = {
        let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
        hex::decode(
            &wallet_utxos
                .iter()
                .find(|u| !u.is_p2sh())
                .map(|u| u.utxo_entry.script_public_key.script.clone())
                .unwrap_or_else(|| wallet.public_key.clone()),
        )?
    };
    if liquidator_bonus >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(liquidator_bonus, 0, liquidator_spk, None));
    }

    let lender_output_idx: u8 = 0;
    let borrower_output_idx: u8 = if borrower_return >= MIN_UTXO_VALUE { 1 } else { 0 };
    let liquidator_output_idx: u8 = tx.outputs.len().saturating_sub(1) as u8;
    let price_input_idx: u8 = 0;

    // Sign input 0 (price oracle, P2PK)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign_secure(&privkey, &sighash_0)?;

    // Input 1 sigscript: liquidate path (selector=1, no sig on covenant)
    let liquidate_sigscript = build_active_loan_liquidate_sigscript(
        price_input_idx,
        lender_output_idx,
        borrower_output_idx,
        liquidator_output_idx,
        &redeem_script,
    );

    println!("Liquidate SigScript: {} bytes", liquidate_sigscript.len());

    let sigscripts = vec![
        signing::build_p2pk_sigscript(&sig_0), // input 0: price oracle
        liquidate_sigscript,                     // input 1: covenant
    ];

    // Phase 2 check: verify fee covers exact mass
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = exact_mass;
    let total_in_liq: u64 = tx.inputs.iter().map(|i| i.value).sum();
    let total_out_liq: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let implicit_fee = total_in_liq.saturating_sub(total_out_liq);
    if exact_fee != implicit_fee {
        println!("WARNING: Exact mass fee {} differs from implicit fee {}. TX may be rejected.", exact_fee, implicit_fee);
    }

    // Fee transparency
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass_display = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Liquidate TX mass: {:>9} / {:>9} ({})",
            storage_mass_display, MAX_TX_MASS,
            if storage_mass_display <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:      {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:         {:>9} sompi", implicit_fee);
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting liquidation transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Liquidation transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Lender received {} sompi (outstanding debt).", debt);
    println!("Borrower received {} sompi (remaining collateral).", borrower_return);
    println!("Liquidator received {} sompi (bonus).", liquidator_bonus);

    Ok(())
}

// lending loans — list active loans

/// List active loans from the engine REST API.
///
/// If no engine URL is provided, prints a message about how to query.
pub async fn list_loans(engine_url: Option<&str>) -> anyhow::Result<()> {
    let url = match engine_url {
        Some(u) => u,
        None => {
            println!("Lending Loans");
            println!("=============");
            println!();
            println!("No --engine-url provided. Active loans are tracked by the lending engine.");
            println!();
            println!("Usage:");
            println!("  kob lending loans --engine-url http://localhost:8080");
            println!();
            println!("The engine exposes /api/lending/loans for active loan queries.");
            return Ok(());
        }
    };

    println!("Querying lending engine at {}...", url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = client
        .get(format!("{}/api/lending/loans", url.trim_end_matches('/')))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Engine returned HTTP {}. Is the lending engine running?",
            resp.status()
        );
    }

    let body: serde_json::Value = resp.json().await?;

    if let Some(loans) = body.as_array() {
        println!();
        println!("Active Loans: {}", loans.len());
        println!("{}", "-".repeat(80));
        for loan in loans {
            print_loan_entry(loan);
        }
    } else if let Some(obj) = body.as_object() {
        if let Some(loans) = obj.get("loans").and_then(|v| v.as_array()) {
            println!();
            println!("Active Loans: {}", loans.len());
            println!("{}", "-".repeat(80));
            for loan in loans {
                print_loan_entry(loan);
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&body)?);
    }

    Ok(())
}

/// Print a single loan entry from the engine JSON response.
fn print_loan_entry(loan: &serde_json::Value) {
    let outpoint = loan["outpoint"].as_str().unwrap_or("?");
    let principal = loan["principal"].as_u64().unwrap_or(0);
    let collateral = loan["collateral"].as_u64().unwrap_or(0);
    let rate_num = loan["rate_num"].as_u64().unwrap_or(0);
    let rate_den = loan["rate_den"].as_u64().unwrap_or(1);
    let start = loan["start_daa"].as_u64().unwrap_or(0);
    let expiry = loan["expiry_daa"].as_u64().unwrap_or(0);

    println!(
        "  {} | principal={} | collateral={} | rate={}/{} ({}) | DAA {}-{}",
        outpoint,
        principal,
        collateral,
        rate_num,
        rate_den,
        if rate_den > 0 { format!("{:.4}%", rate_num as f64 / rate_den as f64 * 100.0) } else { "N/A".to_string() },
        start,
        expiry,
    );
}
