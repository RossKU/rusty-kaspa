//! `kob-cli partial-fill` -- Partially fill a buy or sell order.
//!
//! Builds and submits a partial fill TX that fills a portion of an order,
//! leaving a residual order UTXO with reduced value.
//!
//! Buy partial fill TX layout:
//!   input[0]: buy_order UTXO (P2SH, partial fill sigscript, sigOpCount=0)
//!   input[1]: token UTXO     (token_unit for the buyer, sigOpCount=1)
//!   input[2]: fee UTXO       (P2PK, signed, sigOpCount=1)
//!
//!   output[0]: residual buy_order (P2SH, reduced value, same RS)
//!   output[1]: buyer tokens       (fill_amount worth of tokens to buyer SPK)
//!   output[2]: trade_receipt      (P2SH, RECEIPT_VALUE sompi)
//!   output[3]: matcher change     (optional)
//!
//! Sell partial fill TX layout:
//!   input[0]: sell_order UTXO (P2SH, partial fill sigscript, sigOpCount=0)
//!   input[1]: fee UTXO        (P2PK, signed, sigOpCount=1)
//!
//!   output[0]: seller KAS         (fill_amount * price KAS to seller SPK)
//!   output[1]: residual sell_order (P2SH, reduced value, same RS)
//!   output[2]: trade_receipt       (P2SH, RECEIPT_VALUE sompi)
//!   output[3]: matcher change      (optional)

use crate::cancel;
use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::mass::{compute_storage_mass, MAX_TX_MASS};
use kob_core::{MIN_UTXO_VALUE, RECEIPT_DUST, RECEIPT_VALUE};
use std::path::Path;
use tracing::info;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    side: &str,
    token_cov_id_hex: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    fill_amount: u64,
    order_value_override: Option<u64>,
    owner_hash_hex: Option<&str>,
    spk_hash_hex: Option<&str>,
    token_outpoint_str: Option<&str>,
    fee_input_str: Option<&str>,
    version: u8,
    fee: u64,
    expiry_daa: u64,
    max_matcher_fee: u64,
) -> anyhow::Result<()> {
    if version != 14 {
        anyhow::bail!("Unsupported contract version {}. Only v14 is supported.", version);
    }
    let wallet = WalletContext::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    // Validate side
    if side != "buy" && side != "sell" {
        anyhow::bail!("Unknown side '{}'. Use 'buy' or 'sell'.", side);
    }

    // Parse token covenant ID
    let token_bytes = hex::decode(token_cov_id_hex)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&token_bytes);

    // Determine owner/spk hashes
    let default_owner_hash = blake2b_256(&pubkey);
    let default_spk_hash = compute_p2pk_spk_hash(&pubkey);

    let owner_hash: [u8; 32] = if let Some(h) = owner_hash_hex {
        let bytes = hex::decode(h)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid --owner-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        default_owner_hash
    };
    let spk_hash: [u8; 32] = if let Some(h) = spk_hash_hex {
        let bytes = hex::decode(h)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid --spk-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        default_spk_hash
    };

    // Reconstruct redeemScript (v13 only, cpend=0 -- partial fill only works on active orders)
    let redeem_script = match side {
        "buy" => contract::build_buy_redeem_script(
            &tcid,
            price_num,
            price_den,
            min_fill,
            &owner_hash,
            &spk_hash, max_matcher_fee,
            0, // cancel_pending = 0
            expiry_daa,)?,
        "sell" => contract::build_sell_redeem_script(
            price_num,
            price_den,
            min_fill,
            &owner_hash,
            &spk_hash, max_matcher_fee,
            0, // cancel_pending = 0
            expiry_daa,)?,
        _ => unreachable!(),
    };

    let p2sh = build_p2sh(&redeem_script);

    println!("Partial Fill Order (v{})", version);
    println!("===================");
    println!("Outpoint:      {}", outpoint);
    println!("Side:          {}", side);
    println!("Token:         {}", token_cov_id_hex);
    println!("Price:         {}/{}", price_num, price_den);
    println!("Min Fill:      {}", min_fill);
    println!("Fill Amount:   {}", fill_amount);
    println!("RedeemScript:  {} bytes (v{})", redeem_script.len(), version);
    println!("P2SH SPK:      {}", hex::encode(&p2sh.script()));
    println!();

    // Connect
    info!(outpoint = %outpoint, side = side, fill_amount = fill_amount, "partial fill");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine order UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_address = cancel::p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
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

    println!("Order Value:   {} sompi", order_value);

    // Get wallet UTXOs
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let wallet_spk_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh())
        .ok_or_else(|| anyhow::anyhow!("No spendable UTXOs in wallet. Fund the wallet first or run `kob wallet consolidate`."))?;
    let wallet_spk = wallet_spk_utxo.script_bytes();
    let wallet_spk_version = wallet_spk_utxo.utxo_entry.script_public_key.version;

    match side {
        "buy" => {
            run_buy_partial_fill(
                &rpc,
                &wallet,
                &pubkey,
                &privkey,
                &outpoint,
                &tcid,
                token_cov_id_hex,
                price_num,
                price_den,
                min_fill,
                fill_amount,
                order_value,
                &owner_hash,
                &spk_hash,
                &redeem_script,
                &p2sh,
                &wallet_utxos,
                &wallet_spk,
                wallet_spk_version,
                token_outpoint_str,
                fee_input_str,
                version,
                fee,
            )
            .await
        }
        "sell" => {
            run_sell_partial_fill(
                &rpc,
                &wallet,
                &pubkey,
                &privkey,
                &outpoint,
                &tcid,
                token_cov_id_hex,
                price_num,
                price_den,
                min_fill,
                fill_amount,
                order_value,
                &owner_hash,
                &spk_hash,
                &redeem_script,
                &p2sh,
                &wallet_utxos,
                &wallet_spk,
                wallet_spk_version,
                fee_input_str,
                version,
                fee,
            )
            .await
        }
        _ => unreachable!(),
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(deprecated)]
async fn run_buy_partial_fill(
    rpc: &NodeClient,
    _wallet: &WalletContext,
    _pubkey: &[u8; 32],
    privkey: &[u8; 32],
    outpoint: &Outpoint,
    tcid: &[u8; 32],
    token_cov_id_hex: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    fill_kas: u64,
    order_value: u64,
    _owner_hash: &[u8; 32],
    _spk_hash: &[u8; 32],
    redeem_script: &[u8],
    p2sh: &kob_core::types::ScriptPublicKey,
    wallet_utxos: &[crate::rpc::RpcUtxo],
    wallet_spk: &[u8],
    wallet_spk_version: u16,
    token_outpoint_str: Option<&str>,
    fee_input_str: Option<&str>,
    version: u8,
    fee: u64,
) -> anyhow::Result<()> {
    // Buy partial fill:
    //   fill_kas = amount of KAS from the order to fill
    //   expected_tokens = fill_kas * price_num / price_den
    //   residual_value = order_value - fill_kas
    //
    // The buyer gets expected_tokens worth of tokens.
    // The residual order keeps the remaining KAS.
    //
    // Token input is required -- the matcher provides tokens.

    let token_outpoint_str = token_outpoint_str
        .ok_or_else(|| anyhow::anyhow!("--token-outpoint is required for buy partial fill. \
             Provide the UTXO containing the tokens to deliver to the buyer."))?;
    let token_outpoint = Outpoint::parse(token_outpoint_str)?;

    let expected_tokens = fill_kas
        .checked_mul(price_num)
        .ok_or_else(|| anyhow::anyhow!(
            "Price calculation overflow: fill amount ({}) * price numerator ({}) is too large. \
             Reduce the fill amount or use a smaller price ratio.",
            fill_kas, price_num
        ))? / price_den;
    let residual_value = order_value
        .checked_sub(fill_kas)
        .ok_or_else(|| anyhow::anyhow!("Fill amount ({} sompi) exceeds the order value ({} sompi). Use a smaller fill amount or do a full fill.", fill_kas, order_value))?;

    if fill_kas < min_fill {
        anyhow::bail!(
            "Fill amount ({} sompi) is below the order's minimum fill ({} sompi). \
             The on-chain contract will reject this transaction.",
            fill_kas,
            min_fill
        );
    }
    if residual_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Remaining order value ({} sompi) would be below the minimum UTXO value ({}). \
             Use a full fill instead of a partial fill.",
            residual_value,
            MIN_UTXO_VALUE
        );
    }
    if expected_tokens < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Token output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the fill amount.",
            expected_tokens,
            MIN_UTXO_VALUE
        );
    }

    println!("Buy Partial Fill:");
    println!("  Fill KAS:        {} sompi", fill_kas);
    println!("  Expected Tokens: {}", expected_tokens);
    println!("  Residual Value:  {} sompi", residual_value);
    println!("  Token Input:     {}", token_outpoint);
    println!();

    // Build the partial fill sigscript
    // output[0] = residual order (index 0)
    // output[1] = buyer tokens   (index 1)
    let buy_pf_ss = contract::build_buy_partial_fill_sigscript(redeem_script, fill_kas, 0, 1);
    println!("Partial Fill SS:  {} bytes (v{})", buy_pf_ss.len(), version);

    // Build receipt
    let receipt_rs = contract::build_receipt_redeem_script(tcid, price_num, price_den, expected_tokens, RECEIPT_DUST, _spk_hash)?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    // Find the token UTXO (from wallet's UTXOs or query)
    // For now, we look for it in the wallet's UTXO set
    let token_utxo = wallet_utxos
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == token_outpoint.transaction_id
                && u.outpoint.index == token_outpoint.index
        })
        .ok_or_else(|| {
            anyhow::anyhow!("Token UTXO {} not found in wallet. It may have been spent or the TXID:INDEX is incorrect.", token_outpoint)
        })?;

    let token_spk_bytes = token_utxo.script_bytes();
    let token_value = token_utxo.utxo_entry.amount;

    println!("Token UTXO:       {}:{} ({} sompi)", token_utxo.outpoint.transaction_id, token_utxo.outpoint.index, token_value);

    // Fee UTXO
    let fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let fee_utxo = if let Some(ref fee_op) = fee_outpoint {
        wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| anyhow::anyhow!("The specified --fee-input UTXO was not found in the wallet. It may have been spent already."))?
    } else {
        wallet_utxos
            .iter()
            .find(|u| {
                !u.is_p2sh()
                    && u.utxo_entry.amount >= fee + MIN_UTXO_VALUE
                    && !(u.outpoint.transaction_id == token_outpoint.transaction_id
                        && u.outpoint.index == token_outpoint.index)
            })
            .ok_or_else(|| anyhow::anyhow!("No spendable UTXO available for the transaction fee. Fund the wallet or specify --fee-input."))?
    };

    let fee_spk_bytes = fee_utxo.script_bytes();
    let fee_value = fee_utxo.utxo_entry.amount;

    println!(
        "Fee UTXO:         {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_value
    );

    // Compute output amounts
    // total_in = order_value + token_value + fee_value
    // outputs: residual_order + buyer_tokens + receipt + change
    let total_in = order_value.checked_add(token_value)
        .and_then(|s| s.checked_add(fee_value))
        .ok_or_else(|| anyhow::anyhow!(
            "Arithmetic overflow: order ({}) + token ({}) + fee ({}) values are too large to process.",
            order_value, token_value, fee_value
        ))?;
    let receipt_value = RECEIPT_VALUE;
    let needed = residual_value + expected_tokens + receipt_value + fee;

    if total_in < needed {
        anyhow::bail!(
            "Insufficient funds: total input ({} sompi) cannot cover outputs ({} sompi) + fee ({} sompi). \
             Add more funding UTXOs or reduce the fill amount.",
            total_in,
            needed - fee,
            fee
        );
    }

    let raw_change = total_in - needed;
    let (final_buyer_tokens, matcher_change) = if raw_change >= MIN_UTXO_VALUE {
        (expected_tokens, raw_change)
    } else {
        // Add small change to buyer output
        (expected_tokens + raw_change, 0u64)
    };

    println!();
    println!("Partial Fill TX Outputs:");
    println!("  output[0]: residual order  {} sompi (P2SH)", residual_value);
    println!("  output[1]: buyer tokens    {} sompi", final_buyer_tokens);
    println!("  output[2]: trade_receipt   {} sompi", receipt_value);
    if matcher_change > 0 {
        println!("  output[3]: matcher change  {} sompi", matcher_change);
    }
    println!("  fee:                       {} sompi", fee);
    println!();

    // Build transaction
    let mut tx = Transaction::new(0);

    // Input 0: buy_order (P2SH, partial fill, sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 0,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: token UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: token_outpoint.transaction_id.clone(),
        prev_index: token_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: token_utxo.utxo_entry.script_public_key.version,
        script_bytes: token_spk_bytes,
        value: token_value,
    });

    // Input 2: fee UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: residual order (same P2SH address)
    tx.outputs.push(TxOutput::new(residual_value, p2sh.version, p2sh.script().to_vec(), None));

    // Output 1: buyer tokens
    tx.outputs.push(TxOutput::new(final_buyer_tokens, wallet_spk_version, wallet_spk.to_vec(), None));

    // Output 2: trade receipt
    tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));

    // Output 3: matcher change (optional)
    if matcher_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(matcher_change, wallet_spk_version, wallet_spk.to_vec(), None));
    }

    // Sign input 1 (token UTXO)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(privkey, &sighash_1)?;
    let token_ss = signing::build_p2pk_sigscript(&sig_1);

    // Sign input 2 (fee UTXO)
    let sighash_2 = compute_sighash(&tx, 2)?;
    let sig_2 = signing::schnorr_sign(privkey, &sighash_2)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_2);

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let total_out: u64 = out_vals.iter().sum();
        let total_in_actual: u64 = in_vals.iter().sum();
        let actual_surplus = total_in_actual.saturating_sub(total_out);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Partial fill mass: {:>8} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Miner fee:        {:>9} sompi", fee);
        println!("Surplus:          {:>9} sompi", actual_surplus);
        println!();
    }

    // Submit
    let sigscripts = vec![buy_pf_ss, token_ss, fee_ss];
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting partial fill transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Buy partial fill transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("  Residual order: {}:0 ({} sompi)", tx_id, residual_value);
    println!("  Buyer received: {} sompi tokens at {}:1", final_buyer_tokens, tx_id);
    println!("  Receipt at:     {}:2", tx_id);
    println!();
    println!("Receipt params for consumption:");
    println!(
        "  --pair-id {}  --price-num {}  --price-den {}  --exec-amount {}",
        token_cov_id_hex, price_num, price_den, expected_tokens
    );

    Ok(())
}

#[allow(clippy::too_many_arguments, deprecated)]
async fn run_sell_partial_fill(
    rpc: &NodeClient,
    _wallet: &WalletContext,
    _pubkey: &[u8; 32],
    privkey: &[u8; 32],
    outpoint: &Outpoint,
    tcid: &[u8; 32],
    token_cov_id_hex: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    fill_token_amount: u64,
    order_value: u64,
    _owner_hash: &[u8; 32],
    _spk_hash: &[u8; 32],
    redeem_script: &[u8],
    p2sh: &kob_core::types::ScriptPublicKey,
    wallet_utxos: &[crate::rpc::RpcUtxo],
    wallet_spk: &[u8],
    wallet_spk_version: u16,
    fee_input_str: Option<&str>,
    version: u8,
    fee: u64,
) -> anyhow::Result<()> {
    // Sell partial fill:
    //   fill_token_amount = amount of tokens (from the order) being filled
    //   seller_kas = fill_token_amount * price_num / price_den (KAS seller receives)
    //   residual_value = order_value - fill_token_amount (remaining token value in order)
    //
    // The seller receives KAS; residual order keeps remaining tokens.

    let seller_kas = fill_token_amount
        .checked_mul(price_num)
        .ok_or_else(|| anyhow::anyhow!(
            "Price calculation overflow: fill amount ({}) * price numerator ({}) is too large. \
             Reduce the fill amount or use a smaller price ratio.",
            fill_token_amount, price_num
        ))? / price_den;
    let residual_value = order_value
        .checked_sub(fill_token_amount)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Fill amount ({} sompi) exceeds the order value ({} sompi). Use a smaller fill amount or do a full fill.",
                fill_token_amount,
                order_value
            )
        })?;

    if fill_token_amount < min_fill {
        anyhow::bail!(
            "Fill amount ({} sompi) is below the order's minimum fill ({} sompi). \
             The on-chain contract will reject this transaction.",
            fill_token_amount,
            min_fill
        );
    }
    if residual_value < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Remaining order value ({} sompi) would be below the minimum UTXO value ({}). \
             Use a full fill instead of a partial fill.",
            residual_value,
            MIN_UTXO_VALUE
        );
    }
    if seller_kas < MIN_UTXO_VALUE {
        anyhow::bail!(
            "Seller's KAS output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the fill amount.",
            seller_kas,
            MIN_UTXO_VALUE
        );
    }

    println!("Sell Partial Fill:");
    println!("  Fill Tokens:     {} sompi", fill_token_amount);
    println!("  Seller KAS:      {} sompi", seller_kas);
    println!("  Residual Value:  {} sompi", residual_value);
    println!();

    // Build the partial fill sigscript
    // output[0] = seller KAS      (index 0)
    // output[1] = residual order  (index 1)
    let sell_pf_ss = contract::build_sell_partial_fill_sigscript(redeem_script, fill_token_amount, 0, 1);
    println!("Partial Fill SS:  {} bytes (v{})", sell_pf_ss.len(), version);

    // Build receipt (buyer = wallet/matcher for sell partial fill)
    let buyer_spk_hash = compute_p2pk_spk_hash(_pubkey);
    let receipt_rs =
        contract::build_receipt_redeem_script(tcid, price_num, price_den, fill_token_amount, RECEIPT_DUST, &buyer_spk_hash)?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    // Fee UTXO
    let fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let fee_utxo = if let Some(ref fee_op) = fee_outpoint {
        wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fee_op.transaction_id
                    && u.outpoint.index == fee_op.index
            })
            .ok_or_else(|| anyhow::anyhow!("The specified --fee-input UTXO was not found in the wallet. It may have been spent already."))?
    } else {
        wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= fee + MIN_UTXO_VALUE)
            .ok_or_else(|| anyhow::anyhow!("No spendable UTXO available for the transaction fee. Fund the wallet or specify --fee-input."))?
    };

    let fee_spk_bytes = fee_utxo.script_bytes();
    let fee_value = fee_utxo.utxo_entry.amount;

    println!(
        "Fee UTXO:         {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_value
    );

    // Compute output amounts
    let total_in = order_value.checked_add(fee_value)
        .ok_or_else(|| anyhow::anyhow!(
            "Arithmetic overflow: order value ({}) + fee value ({}) is too large to process.",
            order_value, fee_value
        ))?;
    let receipt_value = RECEIPT_VALUE;
    let needed = seller_kas + residual_value + receipt_value + fee;

    if total_in < needed {
        anyhow::bail!(
            "Insufficient funds: total input ({} sompi) cannot cover outputs ({} sompi) + fee ({} sompi). \
             Add more funding UTXOs or reduce the fill amount.",
            total_in,
            needed - fee,
            fee
        );
    }

    let raw_change = total_in - needed;
    let (final_seller_kas, matcher_change) = if raw_change >= MIN_UTXO_VALUE {
        (seller_kas, raw_change)
    } else {
        // Add small change to seller output
        (seller_kas + raw_change, 0u64)
    };

    println!();
    println!("Partial Fill TX Outputs:");
    println!("  output[0]: seller KAS      {} sompi", final_seller_kas);
    println!("  output[1]: residual order  {} sompi (P2SH)", residual_value);
    println!("  output[2]: trade_receipt   {} sompi", receipt_value);
    if matcher_change > 0 {
        println!("  output[3]: matcher change  {} sompi", matcher_change);
    }
    println!("  fee:                       {} sompi", fee);
    println!();

    // Build transaction
    let mut tx = Transaction::new(0);

    // Input 0: sell_order (P2SH, partial fill, sigOpCount=0)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 0,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: fee UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: seller KAS
    tx.outputs.push(TxOutput::new(final_seller_kas, wallet_spk_version, wallet_spk.to_vec(), None));

    // Output 1: residual order (same P2SH address)
    tx.outputs.push(TxOutput::new(residual_value, p2sh.version, p2sh.script().to_vec(), None));

    // Output 2: trade receipt
    tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));

    // Output 3: matcher change (optional)
    if matcher_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(matcher_change, wallet_spk_version, wallet_spk.to_vec(), None));
    }

    // Sign input 1 (fee UTXO)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(privkey, &sighash_1)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_1);

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let total_out: u64 = out_vals.iter().sum();
        let total_in_actual: u64 = in_vals.iter().sum();
        let actual_surplus = total_in_actual.saturating_sub(total_out);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Partial fill mass: {:>8} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Miner fee:        {:>9} sompi", fee);
        println!("Surplus:          {:>9} sompi", actual_surplus);
        println!();
    }

    // Submit
    let sigscripts = vec![sell_pf_ss, fee_ss];
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting partial fill transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Sell partial fill transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("  Seller received: {} sompi KAS at {}:0", final_seller_kas, tx_id);
    println!("  Residual order:  {}:1 ({} sompi)", tx_id, residual_value);
    println!("  Receipt at:      {}:2", tx_id);
    println!();
    println!("Receipt params for consumption:");
    println!(
        "  --pair-id {}  --price-num {}  --price-den {}  --exec-amount {}",
        token_cov_id_hex, price_num, price_den, fill_token_amount
    );

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, compute_p2pk_spk_hash};

    #[test]
    fn buy_partial_fill_sigscript_v12() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_buy_redeem_script(
            &tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0,).unwrap();
        let ss = contract::build_buy_partial_fill_sigscript(&rs, 5_000_000, 0, 1);
        assert!(!ss.is_empty(), "Buy v12 partial fill SS must not be empty");
        assert_eq!(ss[0], 0x00, "residual_idx=0 -> Op0");
        assert_eq!(ss[1], 0x51, "token_idx=1 -> Op1");
    }

    #[test]
    fn sell_partial_fill_sigscript_v12() {
        let pk = [0x02u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_sell_redeem_script(1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();
        let ss = contract::build_sell_partial_fill_sigscript(&rs, 3_000_000, 0, 1);
        assert!(!ss.is_empty());
        assert_eq!(ss[0], 0x00, "kas_idx=0 -> Op0");
        assert_eq!(ss[1], 0x51, "residual_idx=1 -> Op1");
    }
}
