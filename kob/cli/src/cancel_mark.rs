//! `kob-cli cancel-mark` -- Step 1 of a safe 2-step cancel.
//!
//! Flips the order's cancel_pending flag from 0 to 1 by producing a new UTXO
//! with the same parameters at a new P2SH address (cpend=1 in the redeemScript).
//! Once marked, new fills and partial fills are blocked by the covenant, so the
//! order cannot race an incoming match. The owner then runs `kob-cli cancel`
//! (step 2) on the new outpoint to recover the KAS.
//!
//! Use this when the order's locked value is large enough that losing it to a
//! mempool race during a one-shot cancel would matter. For small orders, the
//! one-shot `cancel` path is fine.
//!
//! Cancel-mark TX structure:
//!   input[0]: order UTXO (P2SH, cancel-mark sigscript, sigOpCount=1)
//!   input[1]: fee UTXO   (P2PK, signed, sigOpCount=1)
//!
//!   output[0]: same order, cpend=1 (P2SH, new RS with cpend=Op1)
//!   output[1]: change to wallet (optional, from fee UTXO surplus)
//!
//! IMPORTANT:
//!   - Buy order cancel-mark selector: Op1 (0x51) -- MINIMALIF requires exactly [0x01]
//!   - Sell order cancel-mark selector: Op3 (0x53) -- OpEqual dispatch, Op3 is safe

use crate::cancel;
use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    side: &str,
    token_cov_id: Option<&str>,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    order_value_override: Option<u64>,
    fee: u64,
    version: u8,
    expiry_daa: u64,
    fee_utxo_override: Option<&str>,
    max_matcher_fee: u64,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);

    // Helper: parse token covenant ID for buy orders
    let parse_tcid = |token_cov_id: Option<&str>| -> anyhow::Result<[u8; 32]> {
        let token_hex = token_cov_id
            .ok_or_else(|| anyhow::anyhow!("Buy cancel-mark requires --token with the token covenant ID (64 hex chars)."))?;
        let token_bytes = hex::decode(token_hex)?;
        if token_bytes.len() != 32 {
            anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
        }
        let mut tcid = [0u8; 32];
        tcid.copy_from_slice(&token_bytes);
        Ok(tcid)
    };

    if version != 14 && version != 16 && version != 17 {
        anyhow::bail!("Unsupported contract version {}. Only v14, v16, and v17 are supported.", version);
    }
    if version == 17 && side != "buy" {
        anyhow::bail!("v17 is a buy-only contract; sell orders are single-version.");
    }

    // Reconstruct the current redeemScript (cpend=0, the active order)
    let current_rs = match side {
        "buy" => {
            let tcid = parse_tcid(token_cov_id)?;
            if version == 17 {
                contract::build_buy_v17_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 0, expiry_daa)?
            } else if version == 16 {
                contract::build_buy_v16_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 0, expiry_daa)?
            } else {
                contract::build_buy_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 0, expiry_daa)?
            }
        }
        "sell" => contract::build_sell_redeem_script(price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 0, expiry_daa)?,
        _ => anyhow::bail!("Unknown side '{}'. Use 'buy' or 'sell'.", side),
    };

    // Build the target redeemScript (cpend=1)
    let target_rs = match side {
        "buy" => {
            let tcid = parse_tcid(token_cov_id)?;
            if version == 17 {
                contract::build_buy_v17_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 1, expiry_daa)?
            } else if version == 16 {
                contract::build_buy_v16_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 1, expiry_daa)?
            } else {
                contract::build_buy_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 1, expiry_daa)?
            }
        }
        "sell" => contract::build_sell_redeem_script(price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, 1, expiry_daa)?,
        _ => unreachable!(),
    };

    let current_p2sh = build_p2sh(&current_rs);
    let target_p2sh = build_p2sh(&target_rs);

    println!("Cancel-Mark Order (cpend 0 -> 1)");
    println!("=================================");
    println!("Outpoint:       {}", outpoint);
    println!("Side:           {}", side);
    println!("Price:          {}/{}", price_num, price_den);
    println!("Min Fill:       {}", min_fill);
    println!("Owner:          {}", wallet.pubkey_hex());
    println!("Current RS:     {} bytes (cpend=0)", current_rs.len());
    println!("Target RS:      {} bytes (cpend=1)", target_rs.len());
    println!("Current P2SH:   {}", hex::encode(&current_p2sh.script()));
    println!("Target P2SH:    {}", hex::encode(&target_p2sh.script()));
    println!();

    // Connect to node
    info!(outpoint = %outpoint, side = side, "cancel-mark order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine the order UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = cancel::p2sh_to_address(&current_p2sh.script(), network.address_prefix());
        println!("P2SH Address:   {}", p2sh_address);
        println!("Querying order UTXO value from chain...");
        let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        order_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Order UTXO {} not found at P2SH address. Use --order-value.",
                    outpoint
                )
            })?
    };

    println!("Order Value:    {} sompi", order_value);

    // Estimate fee for UTXO selection
    let est_fee = estimate_compute_mass(2, 2, 0) + 500;

    // Get a fee UTXO from the wallet (or use override)
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
                    "Fee UTXO {} not found in wallet UTXOs",
                    fee_op_str
                )
            })?
    } else {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates.first().copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for fee payment. Use --fee-utxo to specify.",
                    est_fee + MIN_UTXO_VALUE
                )
            })?
    };

    println!(
        "Fee UTXO:       {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let fee_value = fee_utxo.utxo_entry.amount;
    let fee_spk_bytes = fee_utxo.script_bytes();
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;

    // Build the cancel-mark transaction with tentative output values
    let total_in = order_value + fee_value;
    let tentative_change = fee_value.saturating_sub(est_fee);
    let mut tx = Transaction::new(0);

    // Input 0: order UTXO (P2SH, cancel-mark sigscript, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1, // cancel-mark path has CheckSig
        script_version: current_p2sh.version,
        script_bytes: current_p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: order with cpend=1 (new P2SH address) — value stays the same
    tx.outputs.push(TxOutput::new(order_value, target_p2sh.version, target_p2sh.script().to_vec(), None));

    // Output 1: fee change (if above dust threshold)
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, wallet_spk_version, wallet_spk, None));
    }

    // Phase 1: converge fee on change output
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let (est_fee, _) = if has_change {
        let change_idx = tx.outputs.len() - 1;
        converge_fee(&mut tx, total_in, change_idx, min_fee_override)
    } else {
        // No change output — fee is total_in - order_value
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        (f, 0)
    };

    let change = if has_change { tx.outputs[tx.outputs.len() - 1].value } else { 0 };

    // Remove change output if below MIN_UTXO_VALUE
    if has_change && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
    }

    println!();
    println!("Cancel-Mark TX Outputs:");
    println!("  output[0]: order (cpend=1) {} sompi (P2SH)", tx.outputs[0].value);
    if tx.outputs.len() > 1 {
        println!("  output[1]: fee change      {} sompi", tx.outputs[1].value);
    }
    println!("  fee (est):                 {} sompi", est_fee);
    println!();

    // Sign input 0 (order cancel-mark -- requires owner signature)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;

    // Build the cancel-mark sigscript (inlined -- kob-core no longer exports these)
    let cancel_mark_sigscript = match side {
        "buy" if version == 17 => {
            // v17 buy cancel-mark: [pk] [sig] [Op3] [pushData(RS)] (selector at
            // stack depth 9, so pk/sig go BELOW the selector -- see order.rs).
            contract::build_buy_v17_cancel_sigscript(&pubkey, &sig_0, true, &current_rs)
        }
        "buy" => {
            // buy cancel-mark: [Op1] [pushData(sig65)] [pushData(pk32)] [pushData(RS)]
            let mut ss = Vec::new();
            ss.push(0x51); // Op1 selector
            let mut sig_typed = sig_0.to_vec();
            sig_typed.push(0x01); // sighash type
            ss.push(sig_typed.len() as u8);
            ss.extend_from_slice(&sig_typed);
            ss.push(pubkey.len() as u8);
            ss.extend_from_slice(&pubkey);
            ss.extend_from_slice(&kob_core::push_data(&current_rs));
            ss
        }
        "sell" => {
            // sell cancel-mark: [pushData(sig65)] [pushData(pk32)] [Op3] [pushData(RS)]
            let mut ss = Vec::new();
            let mut sig_typed = sig_0.to_vec();
            sig_typed.push(0x01); // sighash type
            ss.push(sig_typed.len() as u8);
            ss.extend_from_slice(&sig_typed);
            ss.push(pubkey.len() as u8);
            ss.extend_from_slice(&pubkey);
            ss.push(0x53); // Op3 selector
            ss.extend_from_slice(&kob_core::push_data(&current_rs));
            ss
        }
        _ => unreachable!(),
    };

    println!("Cancel-Mark SigScript: {} bytes", cancel_mark_sigscript.len());
    if side == "buy" && version == 17 {
        println!("  (v17 buy cancel-mark uses Op3 selector; pk/sig below the selector)");
    } else if side == "buy" {
        println!("  (buy cancel-mark uses Op1 selector for MINIMALIF compliance)");
    } else {
        println!("  (sell cancel-mark uses Op3 selector via OpEqual dispatch)");
    }

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts = vec![cancel_mark_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass).max(min_fee_override);

    // If exact fee exceeds estimated fee, re-adjust and re-sign
    let (cancel_mark_sigscript, fee_sigscript, actual_fee) = if exact_fee != est_fee {
        // Re-adjust change output or absorb into fee
        if tx.outputs.len() > 1 {
            let change_idx = tx.outputs.len() - 1;
            let new_change = total_in.saturating_sub(order_value + exact_fee);
            if new_change >= MIN_UTXO_VALUE {
                tx.outputs[change_idx].value = new_change;
            } else {
                tx.outputs.pop();
                if new_change > 0 {
                    println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", new_change);
                }
            }
        }

        // Re-sign with updated output values
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let cancel_mark_sigscript = match side {
            "buy" if version == 17 => {
                contract::build_buy_v17_cancel_sigscript(&pubkey, &sig_0, true, &current_rs)
            }
            "buy" => {
                let mut ss = Vec::new();
                ss.push(0x51);
                let mut sig_typed = sig_0.to_vec();
                sig_typed.push(0x01);
                ss.push(sig_typed.len() as u8);
                ss.extend_from_slice(&sig_typed);
                ss.push(pubkey.len() as u8);
                ss.extend_from_slice(&pubkey);
                ss.extend_from_slice(&kob_core::push_data(&current_rs));
                ss
            }
            "sell" => {
                let mut ss = Vec::new();
                let mut sig_typed = sig_0.to_vec();
                sig_typed.push(0x01);
                ss.push(sig_typed.len() as u8);
                ss.extend_from_slice(&sig_typed);
                ss.push(pubkey.len() as u8);
                ss.extend_from_slice(&pubkey);
                ss.push(0x53);
                ss.extend_from_slice(&kob_core::push_data(&current_rs));
                ss
            }
            _ => unreachable!(),
        };
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);
        (cancel_mark_sigscript, fee_sigscript, exact_fee)
    } else {
        (cancel_mark_sigscript, fee_sigscript, est_fee)
    };

    let order_out_value = tx.outputs[0].value;
    println!("Compute mass:   {}", actual_fee);
    println!("Miner fee:      {} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_mark_sigscript, fee_sigscript]);
    println!("Submitting cancel-mark transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Cancel-mark transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Order transitioned to cpend=1 at {}:0", tx_id);
    println!("Order value: {} sompi", order_out_value);
    println!();
    println!("Next step: cancel the order with `kob-cli cancel` using the new outpoint.");
    println!("  Note: Reconstruct RS with cpend=1 for the cancel (same params, different P2SH address).");

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};

    #[test]
    fn cancel_mark_produces_different_p2sh() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);

        let rs_0 = contract::build_buy_redeem_script(
            &tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let rs_1 = contract::build_buy_redeem_script(
            &tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 1, 0,).unwrap();

        let p2sh_0 = build_p2sh(&rs_0);
        let p2sh_1 = build_p2sh(&rs_1);

        // cpend change must produce a different P2SH address
        assert_ne!(
            p2sh_0.script(), p2sh_1.script(),
            "cpend=0 and cpend=1 must have different P2SH scripts"
        );

        // Both RS should have the same length (cpend=0 uses Op0, cpend=1 uses Op1, both 1 byte)
        assert_eq!(
            rs_0.len(),
            rs_1.len(),
            "RS length must be same for cpend=0 and cpend=1"
        );
    }

    #[test]
    fn buy_cancel_mark_sigscript_uses_op1() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_buy_redeem_script(
            &tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        // Inline buy cancel-mark sigscript: [Op1] [pushData(sig65)] [pushData(pk32)] [pushData(RS)]
        let sig = [0xAA; 64];
        let mut ss = Vec::new();
        ss.push(0x51); // Op1 selector
        let mut sig_typed = sig.to_vec();
        sig_typed.push(0x01);
        ss.push(sig_typed.len() as u8);
        ss.extend_from_slice(&sig_typed);
        ss.push(pk.len() as u8);
        ss.extend_from_slice(&pk);
        ss.extend_from_slice(&kob_core::push_data(&rs));
        assert_eq!(ss[0], 0x51, "Buy cancel-mark must start with Op1 (0x51)");
    }

    #[test]
    fn sell_cancel_mark_sigscript_uses_op3() {
        let pk = [0x02u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_sell_redeem_script(1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();
        // Inline sell cancel-mark sigscript: [pushData(sig65)] [pushData(pk32)] [Op3] [pushData(RS)]
        let sig = [0xAA; 64];
        let mut ss = Vec::new();
        let mut sig_typed = sig.to_vec();
        sig_typed.push(0x01);
        ss.push(sig_typed.len() as u8);
        ss.extend_from_slice(&sig_typed);
        ss.push(pk.len() as u8);
        ss.extend_from_slice(&pk);
        ss.push(0x53); // Op3 selector
        ss.extend_from_slice(&kob_core::push_data(&rs));
        assert_eq!(ss[99], 0x53, "Sell cancel-mark selector must be Op3 (0x53) at byte 99");
    }
}
