//! `kob-cli match` -- Execute a match between a buy and sell order.
//!
//! Builds and submits a match TX that fills both orders simultaneously.
//! Both covenant inputs use fill sigscripts (no signature needed, sigOpCount=0).
//! Only the fee input requires signing.
//!
//! Standard Match TX layout (same token pair):
//!   input[0]: buy_order  (P2SH, fill sigscript, sigOpCount=0)
//!   input[1]: sell_order (P2SH, fill sigscript, sigOpCount=0)
//!   input[2]: fee UTXO   (P2PK, signed, sigOpCount=1)  [optional if surplus covers fee]
//!
//!   output[0]: seller KAS     (>= expected_kas from sell contract)
//!   output[1]: buyer tokens   (>= expected_tokens from buy contract)
//!   output[2]: trade_receipt  (P2SH, RECEIPT_VALUE sompi)
//!   output[3]: change to matcher wallet (optional)
//!
//! Cross-Pair Match TX layout (--cross-pair, v8 only):
//!   input[0]: sell_order  (Token A, P2SH fill, sigOpCount=0)
//!   input[1]: buy_order   (Token B, P2SH fill, sigOpCount=0)
//!   input[2]: token UTXO  (Token B, P2PK signed, sigOpCount=1)
//!   input[3]: fee UTXO    (P2PK signed, sigOpCount=1)
//!
//!   output[0]: seller KAS       (sell_v8 SS: kas_output_idx=0)
//!   output[1]: buyer Token B    (buy_v8 SS: token_output_idx=1, token_input_idx=2)
//!   output[2]: trade_receipt    (P2SH, RECEIPT_VALUE sompi)
//!   output[3]: matcher change   (optional)

use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletFile;
use kob_core::mass::{calc_miner_fee, calc_compute_mass, compute_storage_mass, MAX_TX_MASS};
use kob_core::{MIN_UTXO_VALUE, RECEIPT_DUST, RECEIPT_VALUE};
use std::path::Path;
use tracing::info;

#[allow(clippy::too_many_arguments)]
#[allow(deprecated)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    buy_outpoint_str: &str,
    sell_outpoint_str: &str,
    token_cov_id_hex: &str,
    buy_price_num: u64,
    buy_price_den: u64,
    buy_min_fill: u64,
    buy_value_override: Option<u64>,
    buy_owner_hash_hex: Option<&str>,
    buy_spk_hash_hex: Option<&str>,
    sell_price_num: u64,
    sell_price_den: u64,
    sell_min_fill: u64,
    sell_value_override: Option<u64>,
    sell_owner_hash_hex: Option<&str>,
    sell_spk_hash_hex: Option<&str>,
    buyer_pubkey_hex: &str,
    seller_pubkey_hex: &str,
    fee_input_str: Option<&str>,
    version: u8,
    fee: u64,
    buy_expiry: u64,
    sell_expiry: u64,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let buy_outpoint = Outpoint::parse(buy_outpoint_str)?;
    let sell_outpoint = Outpoint::parse(sell_outpoint_str)?;
    let _fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let _pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    // Parse buyer/seller public keys and build their P2PK SPKs
    let buyer_pk_bytes = hex::decode(buyer_pubkey_hex)?;
    if buyer_pk_bytes.len() != 32 {
        anyhow::bail!("--buyer-pubkey must be 64 hex characters (32 bytes)");
    }
    let mut buyer_pubkey = [0u8; 32];
    buyer_pubkey.copy_from_slice(&buyer_pk_bytes);

    let seller_pk_bytes = hex::decode(seller_pubkey_hex)?;
    if seller_pk_bytes.len() != 32 {
        anyhow::bail!("--seller-pubkey must be 64 hex characters (32 bytes)");
    }
    let mut seller_pubkey = [0u8; 32];
    seller_pubkey.copy_from_slice(&seller_pk_bytes);

    // Build P2PK SPK: [0x20] ++ pubkey ++ [0xac] (34 bytes, version 0)
    let mut buyer_spk = Vec::with_capacity(34);
    buyer_spk.push(0x20);
    buyer_spk.extend_from_slice(&buyer_pubkey);
    buyer_spk.push(0xac);

    let mut seller_spk = Vec::with_capacity(34);
    seller_spk.push(0x20);
    seller_spk.extend_from_slice(&seller_pubkey);
    seller_spk.push(0xac);

    // Parse token covenant ID
    let token_bytes = hex::decode(token_cov_id_hex)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&token_bytes);

    // Covenant binding for buyer token output — authorized by sell order input (index 1).
    let token_covenant_binding = CovenantBinding::new(1, kob_core::compat::parse_hash(&token_cov_id_hex.to_string()).unwrap());

    // Determine owner hashes (default: derive from buyer/seller pubkeys)
    let buy_owner_hash: [u8; 32] = if let Some(h) = buy_owner_hash_hex {
        let bytes = hex::decode(h)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid --buy-owner-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        blake2b_256(&buyer_pubkey)
    };
    let buy_spk_hash: [u8; 32] = if let Some(h) = buy_spk_hash_hex {
        let bytes = hex::decode(h)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid --buy-spk-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        compute_p2pk_spk_hash(&buyer_pubkey)
    };
    let sell_owner_hash: [u8; 32] = if let Some(h) = sell_owner_hash_hex {
        let bytes = hex::decode(h)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid --sell-owner-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        blake2b_256(&seller_pubkey)
    };
    let sell_spk_hash: [u8; 32] = if let Some(h) = sell_spk_hash_hex {
        let bytes = hex::decode(h)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid --sell-spk-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        compute_p2pk_spk_hash(&seller_pubkey)
    };

    // Reconstruct redeemScripts (v6 or v8 depending on version flag).
    // max_matcher_fee default matches the deploy default (10_000_000 sompi).
    // cancel_pending = 0 (active, not pending cancel).
    if version < 13 {
        anyhow::bail!(
            "Contract version {} is deprecated. Versions prior to v13 cannot be matched \
             via this command. Use --version 13.",
            version
        );
    }
    if version != 13 {
        anyhow::bail!("Unsupported contract version {}. Only v13 is supported.", version);
    }
    let buy_rs = contract::build_buy_redeem_script(
        &tcid,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &buy_owner_hash,
        &buy_spk_hash, 0,
        0,
        buy_expiry,)?;
    let sell_rs = contract::build_sell_redeem_script(
        sell_price_num,
        sell_price_den,
        sell_min_fill,
        &sell_owner_hash,
        &sell_spk_hash, 0,
        0,
        sell_expiry,)?;

    let buy_p2sh = build_p2sh(&buy_rs);
    let sell_p2sh = build_p2sh(&sell_rs);

    println!("Execute Match");
    println!("==============");
    println!("Buy Order:    {}", buy_outpoint);
    println!("Sell Order:   {}", sell_outpoint);
    println!("Token:        {}", token_cov_id_hex);
    println!("Buy Price:    {}/{}", buy_price_num, buy_price_den);
    println!("Sell Price:   {}/{}", sell_price_num, sell_price_den);
    println!("Buy RS:       {} bytes", buy_rs.len());
    println!("Sell RS:      {} bytes", sell_rs.len());
    println!("Matcher:      {}", wallet.address);
    println!();

    // Connect
    info!(buy = %buy_outpoint, sell = %sell_outpoint, "executing match");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine order values (query from chain if not provided)
    let buy_value = if let Some(v) = buy_value_override {
        v
    } else {
        let buy_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &buy_p2sh.script()[2..34]);
        println!("Querying buy order value from {}...", &buy_addr[..40]);
        let buy_utxos = rpc.get_utxos_by_addresses(&[&buy_addr]).await?;
        buy_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == buy_outpoint.transaction_id
                    && u.outpoint.index == buy_outpoint.index
            })
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("Buy order UTXO not found on chain. Use --buy-value."))?
    };

    let sell_value = if let Some(v) = sell_value_override {
        v
    } else {
        let sell_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &sell_p2sh.script()[2..34]);
        println!("Querying sell order value from {}...", &sell_addr[..40]);
        let sell_utxos = rpc.get_utxos_by_addresses(&[&sell_addr]).await?;
        sell_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == sell_outpoint.transaction_id
                    && u.outpoint.index == sell_outpoint.index
            })
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("Sell order UTXO not found on chain. Use --sell-value."))?
    };

    println!("Buy Value:    {} sompi", buy_value);
    println!("Sell Value:   {} sompi", sell_value);

    // Compute expected amounts (checked to prevent silent overflow)
    let expected_tokens = buy_value
        .checked_mul(buy_price_num)
        .ok_or_else(|| anyhow::anyhow!(
            "Price calculation overflow: buy value ({}) * price numerator ({}) is too large. \
             Reduce the order value or use a smaller price ratio.",
            buy_value, buy_price_num
        ))? / buy_price_den;
    let expected_kas = sell_value
        .checked_mul(sell_price_num)
        .ok_or_else(|| anyhow::anyhow!(
            "Price calculation overflow: sell value ({}) * price numerator ({}) is too large. \
             Reduce the order value or use a smaller price ratio.",
            sell_value, sell_price_num
        ))? / sell_price_den;

    println!("Expected Tokens (buy contract):  {}", expected_tokens);
    println!("Expected KAS (sell contract):    {}", expected_kas);

    // Check price compatibility
    let total_in = buy_value.checked_add(sell_value)
        .ok_or_else(|| anyhow::anyhow!(
            "Arithmetic overflow: buy value ({}) + sell value ({}) is too large to process.",
            buy_value, sell_value
        ))?;
    let seller_kas = expected_kas;
    let buyer_tokens = expected_tokens;

    if seller_kas.saturating_add(buyer_tokens) > total_in {
        anyhow::bail!(
            "Orders cannot be matched: combined output ({} + {} = {} sompi) exceeds combined input ({} sompi). \
             The buy and sell prices do not overlap.",
            seller_kas,
            buyer_tokens,
            seller_kas.saturating_add(buyer_tokens),
            total_in
        );
    }

    let surplus = total_in - seller_kas - buyer_tokens;
    println!("Surplus:      {} sompi", surplus);

    if surplus < fee {
        anyhow::bail!(
            "Match surplus too small: {} sompi available, but need {} sompi for fee. \
             Try matching orders with a larger price spread.",
            surplus,
            fee
        );
    }

    if seller_kas < MIN_UTXO_VALUE {
        anyhow::bail!("Seller's KAS output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.", seller_kas, MIN_UTXO_VALUE);
    }
    if buyer_tokens < MIN_UTXO_VALUE {
        anyhow::bail!("Buyer's token output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.", buyer_tokens, MIN_UTXO_VALUE);
    }

    // Compute output amounts
    // Receipt value (1 KAS) is funded by matcher wallet, not from surplus.
    let receipt_value = RECEIPT_VALUE;
    let raw_matcher_change = surplus - fee;
    let (final_seller_kas, matcher_change) = if raw_matcher_change >= MIN_UTXO_VALUE {
        (seller_kas, raw_matcher_change)
    } else {
        // Add small change to seller rather than creating a dust output
        (seller_kas + raw_matcher_change, 0u64)
    };

    println!();
    println!("Match TX Outputs:");
    println!("  output[0]: seller KAS      {} sompi", final_seller_kas);
    println!("  output[1]: buyer tokens    {} sompi", buyer_tokens);
    println!("  output[2]: trade_receipt   {} sompi", receipt_value);
    if matcher_change > 0 {
        println!("  output[3]: matcher change  {} sompi", matcher_change);
    }
    println!("  fee:                       {} sompi", fee);
    println!();

    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let wallet_spk_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh())
        .ok_or_else(|| anyhow::anyhow!("No spendable UTXOs in wallet. Fund the wallet first or run `kob wallet consolidate`."))?;
    let wallet_spk = wallet_spk_utxo.script_bytes();
    let wallet_spk_version = wallet_spk_utxo.utxo_entry.script_public_key.version;

    // Build fill sigscripts (no signature needed -- permissionless matching)
    // Standard same-pair match layout:
    //   input[0]: buy_order   output[0]: seller KAS
    //   input[1]: sell_order  output[1]: buyer tokens
    //   input[2]: fee         output[2]: receipt
    // v8 indices: buy(token_output_idx=1, token_input_idx=1), sell(kas_output_idx=0)
    let buy_fill_ss = contract::build_buy_fill_sigscript(1, 1, 0, &buy_rs);
    let sell_fill_ss = contract::build_sell_fill_sigscript(0, &sell_rs);

    println!("Buy fill SS:  {} bytes (v{})", buy_fill_ss.len(), version);
    println!("Sell fill SS: {} bytes (v{})", sell_fill_ss.len(), version);

    // Build receipt redeemScript
    let exec_amount = expected_tokens.min(sell_value);
    let receipt_rs = contract::build_receipt_redeem_script(
        &tcid,
        buy_price_num,
        buy_price_den,
        exec_amount,
        RECEIPT_DUST,
        &buy_spk_hash,
    )?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    // Determine if we need a fee input
    // If surplus covers everything, no fee input needed. But typically we include one.
    let need_fee_input = true; // Always include for safety

    // Build transaction (version 1 for covenant-aware token matching)
    let mut tx = Transaction::new(1);

    // Input 0: buy_order (fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: buy_outpoint.transaction_id,
        prev_index: buy_outpoint.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: buy_p2sh.version,
        script_bytes: buy_p2sh.script().to_vec(),
        value: buy_value,
    });

    // Input 1: sell_order (fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: sell_outpoint.transaction_id,
        prev_index: sell_outpoint.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: sell_p2sh.version,
        script_bytes: sell_p2sh.script().to_vec(),
        value: sell_value,
    });

    // Sigscripts array starts with the two fills
    let mut sigscripts: Vec<Vec<u8>> = vec![buy_fill_ss, sell_fill_ss];

    // Optionally add fee input
    if need_fee_input {
        let fee_utxo = if let Some(ref fee_op) = _fee_outpoint {
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
                .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= fee)
                .ok_or_else(|| anyhow::anyhow!("No spendable UTXO available for the transaction fee. Fund the wallet or specify --fee-input."))?
        };

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

        // Add fee UTXO value to outputs
        // Recalculate: total_in now includes fee UTXO
        let fee_utxo_value = fee_utxo.utxo_entry.amount;
        let new_total_in = total_in + fee_utxo_value;
        let new_surplus = new_total_in - seller_kas - buyer_tokens;
        // Build with tentative change (fee=0 initially, will adjust after mass calc)
        let tentative_change = new_surplus - receipt_value;
        let (tentative_seller_kas, tentative_matcher_change) = if tentative_change >= MIN_UTXO_VALUE {
            (seller_kas, tentative_change)
        } else {
            (seller_kas + tentative_change, 0u64)
        };

        // Rebuild outputs with tentative values
        tx.outputs.clear();
        tx.outputs.push(TxOutput::new(tentative_seller_kas, 0, seller_spk.clone(), None));
        tx.outputs.push(TxOutput::new(buyer_tokens, 0, buyer_spk.clone(), Some(token_covenant_binding.clone())));
        tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));
        if tentative_matcher_change >= MIN_UTXO_VALUE {
            tx.outputs.push(TxOutput::new(tentative_matcher_change, wallet_spk_version, wallet_spk.clone(), None));
        }

        // Compute mass-based miner fee from the tentative TX
        let mass_fee = calc_miner_fee(&tx);
        let actual_fee = if fee > 0 { fee.max(mass_fee) } else { mass_fee };

        // Adjust change to deduct the miner fee
        let adj_change = tentative_change.saturating_sub(actual_fee);
        let (adj_seller_kas, adj_matcher_change) = if adj_change >= MIN_UTXO_VALUE {
            (seller_kas, adj_change)
        } else {
            // Fold small change into seller KAS to avoid dust
            (seller_kas + adj_change, 0u64)
        };

        // Update outputs with final values
        tx.outputs[0].value = adj_seller_kas;
        // Handle change output: add, update, or remove
        let has_change_output = tx.outputs.len() > 3;
        if adj_matcher_change >= MIN_UTXO_VALUE {
            if has_change_output {
                tx.outputs[3].value = adj_matcher_change;
            } else {
                tx.outputs.push(TxOutput::new(adj_matcher_change, wallet_spk_version, wallet_spk.clone(), None));
            }
        } else if has_change_output {
            tx.outputs.pop(); // Remove dust change output
        }

        // Sign fee input (index 2) -- must sign AFTER final output adjustment
        let sighash_fee = compute_sighash(&tx, 2)?;
        let sig_fee = signing::schnorr_sign(&privkey, &sighash_fee)?;
        let fee_ss = signing::build_p2pk_sigscript(&sig_fee);
        sigscripts.push(fee_ss);

        println!();
        println!("Fee UTXO:     {}:{} ({} sompi)", fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo_value);
        println!("Adjusted seller KAS:   {}", adj_seller_kas);
        println!("Adjusted change:       {}", adj_matcher_change);
        println!("Mass-based miner fee:  {}", actual_fee);
    } else {
        // No fee input, build outputs from surplus only
        tx.outputs.push(TxOutput::new(final_seller_kas, 0, seller_spk.clone(), None));
        tx.outputs.push(TxOutput::new(buyer_tokens, 0, buyer_spk.clone(), Some(token_covenant_binding.clone())));
        tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));
        if matcher_change >= MIN_UTXO_VALUE {
            tx.outputs.push(TxOutput::new(matcher_change, wallet_spk_version, wallet_spk, None));
        }
    }

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let compute_mass = calc_compute_mass(&tx);
        let total_out: u64 = out_vals.iter().sum();
        let total_in_actual: u64 = in_vals.iter().sum();
        let actual_fee = total_in_actual.saturating_sub(total_out);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9}", compute_mass);
        println!("Miner fee:        {:>9} sompi (mass: {})", actual_fee, actual_fee.max(storage_mass));
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!();
    println!("Submitting match transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Match transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("  Seller received: {} sompi KAS", tx.outputs[0].value);
    println!("  Buyer received:  {} sompi tokens", tx.outputs[1].value);
    println!("  Receipt at:      {}:2", tx_id);
    println!();
    println!("Receipt params for consumption:");
    println!("  --pair-id {}  --price-num {}  --price-den {}  --exec-amount {}",
        token_cov_id_hex, buy_price_num, buy_price_den, exec_amount);

    Ok(())
}

/// Cross-pair match: match a sell order (Token A) against a buy order (Token B)
/// with a bridging token UTXO.
///
/// TX layout:
///   input[0]: sell_order  (Token A, P2SH fill, sigOpCount=0)
///   input[1]: buy_order   (Token B, P2SH fill, sigOpCount=0)
///   input[2]: token UTXO  (Token B, P2PK signed, sigOpCount=1) — provides Token B to buyer
///   input[3]: fee UTXO    (P2PK signed, sigOpCount=1)
///
///   output[0]: seller KAS       (>= expected_kas from sell contract)
///   output[1]: buyer Token B    (>= expected_tokens from buy contract)
///   output[2]: trade_receipt    (P2SH, RECEIPT_VALUE sompi)
///   output[3]: matcher change   (optional)
///
/// v8 sigscript indices:
///   sell_v8 fill SS: kas_output_idx=0
///   buy_v8 fill SS:  token_output_idx=1, token_input_idx=2
#[allow(clippy::too_many_arguments, deprecated)]
pub async fn run_cross_pair(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    buy_outpoint_str: &str,
    sell_outpoint_str: &str,
    sell_token_cov_id_hex: &str,
    buy_token_cov_id_hex: Option<&str>,
    buy_price_num: u64,
    buy_price_den: u64,
    buy_min_fill: u64,
    buy_value_override: Option<u64>,
    buy_owner_hash_hex: Option<&str>,
    buy_spk_hash_hex: Option<&str>,
    sell_price_num: u64,
    sell_price_den: u64,
    sell_min_fill: u64,
    sell_value_override: Option<u64>,
    sell_owner_hash_hex: Option<&str>,
    sell_spk_hash_hex: Option<&str>,
    buyer_pubkey_hex: &str,
    seller_pubkey_hex: &str,
    token_outpoint_str: &str,
    fee_input_str: Option<&str>,
    version: u8,
    fee: u64,
    buy_expiry: u64,
    sell_expiry: u64,
) -> anyhow::Result<()> {
    if version != 8 && version != 9 && version != 11 && version != 12 && version != 13 {
        anyhow::bail!("Cross-pair matching requires contract version 8 or later. This order uses v{}. \
             Redeploy the order with --version 13 or higher.", version);
    }

    let wallet = WalletFile::load(wallet_path)?;
    let buy_outpoint = Outpoint::parse(buy_outpoint_str)?;
    let sell_outpoint = Outpoint::parse(sell_outpoint_str)?;
    let token_outpoint = Outpoint::parse(token_outpoint_str)?;
    let _fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let _pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.private_key_bytes()?;

    // Parse buyer/seller public keys and build their P2PK SPKs
    let buyer_pk_bytes = hex::decode(buyer_pubkey_hex)?;
    if buyer_pk_bytes.len() != 32 {
        anyhow::bail!("--buyer-pubkey must be 64 hex characters (32 bytes)");
    }
    let mut buyer_pubkey = [0u8; 32];
    buyer_pubkey.copy_from_slice(&buyer_pk_bytes);

    let seller_pk_bytes = hex::decode(seller_pubkey_hex)?;
    if seller_pk_bytes.len() != 32 {
        anyhow::bail!("--seller-pubkey must be 64 hex characters (32 bytes)");
    }
    let mut seller_pubkey = [0u8; 32];
    seller_pubkey.copy_from_slice(&seller_pk_bytes);

    // Build P2PK SPK: [0x20] ++ pubkey ++ [0xac] (34 bytes, version 0)
    let mut buyer_spk = Vec::with_capacity(34);
    buyer_spk.push(0x20);
    buyer_spk.extend_from_slice(&buyer_pubkey);
    buyer_spk.push(0xac);

    let mut seller_spk = Vec::with_capacity(34);
    seller_spk.push(0x20);
    seller_spk.extend_from_slice(&seller_pubkey);
    seller_spk.push(0xac);

    // Parse sell token covenant ID (Token A -- what the sell order carries)
    let sell_token_bytes = hex::decode(sell_token_cov_id_hex)?;
    if sell_token_bytes.len() != 32 {
        anyhow::bail!("Invalid --sell-token: expected 64 hex characters for the token covenant ID");
    }
    let mut sell_tcid = [0u8; 32];
    sell_tcid.copy_from_slice(&sell_token_bytes);

    // Parse buy token covenant ID (Token B -- what the buy order wants)
    let buy_token_hex = buy_token_cov_id_hex.unwrap_or(sell_token_cov_id_hex);
    let buy_token_bytes = hex::decode(buy_token_hex)?;
    if buy_token_bytes.len() != 32 {
        anyhow::bail!("Invalid --buy-token: expected 64 hex characters for the token covenant ID");
    }
    let mut buy_tcid = [0u8; 32];
    buy_tcid.copy_from_slice(&buy_token_bytes);

    // Determine owner hashes (default: derive from buyer/seller pubkeys)
    let buy_owner_hash: [u8; 32] = if let Some(h) = buy_owner_hash_hex {
        let bytes = hex::decode(h)?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid --buy-owner-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        blake2b_256(&buyer_pubkey)
    };
    let buy_spk_hash: [u8; 32] = if let Some(h) = buy_spk_hash_hex {
        let bytes = hex::decode(h)?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid --buy-spk-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        compute_p2pk_spk_hash(&buyer_pubkey)
    };
    let sell_owner_hash: [u8; 32] = if let Some(h) = sell_owner_hash_hex {
        let bytes = hex::decode(h)?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid --sell-owner-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        blake2b_256(&seller_pubkey)
    };
    let sell_spk_hash: [u8; 32] = if let Some(h) = sell_spk_hash_hex {
        let bytes = hex::decode(h)?;
        bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid --sell-spk-hash: must be exactly 64 hex characters (32 bytes)"))?
    } else {
        compute_p2pk_spk_hash(&seller_pubkey)
    };

    // Reconstruct redeemScripts (v13 only)
    if version < 13 {
        anyhow::bail!(
            "Contract version {} is deprecated. Versions prior to v13 cannot be matched. \
             Use --version 13.",
            version
        );
    }
    if version != 13 {
        anyhow::bail!("Unsupported contract version {}. Only v13 is supported.", version);
    }
    let buy_rs = contract::build_buy_redeem_script(
        &buy_tcid,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &buy_owner_hash,
        &buy_spk_hash, 0,
        0,
        buy_expiry,)?;
    let sell_rs = contract::build_sell_redeem_script(
        sell_price_num,
        sell_price_den,
        sell_min_fill,
        &sell_owner_hash,
        &sell_spk_hash, 0,
        0,
        sell_expiry,)?;

    let buy_p2sh = build_p2sh(&buy_rs);
    let sell_p2sh = build_p2sh(&sell_rs);

    println!("Cross-Pair Match (v{})", version);
    println!("======================");
    println!("Sell Order:   {} (Token A: {})", sell_outpoint, sell_token_cov_id_hex);
    println!("Buy Order:    {} (Token B: {})", buy_outpoint, buy_token_hex);
    println!("Token UTXO:   {} (provides Token B)", token_outpoint);
    println!("Sell Price:   {}/{}", sell_price_num, sell_price_den);
    println!("Buy Price:    {}/{}", buy_price_num, buy_price_den);
    println!("Sell RS:      {} bytes", sell_rs.len());
    println!("Buy RS:       {} bytes", buy_rs.len());
    println!("Matcher:      {}", wallet.address);
    println!();
    println!("TX Structure:");
    println!("  input[0]:  sell_order (Token A)   -> output[0]: seller KAS");
    println!("  input[1]:  buy_order  (Token B)   -> output[1]: buyer Token B");
    println!("  input[2]:  token UTXO (Token B)      output[2]: trade_receipt");
    println!("  input[3]:  fee UTXO                  output[3]: matcher change");
    println!();

    // Connect
    info!(sell = %sell_outpoint, buy = %buy_outpoint, token = %token_outpoint, "executing cross-pair match");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine order values (query from chain if not provided)
    let buy_value = if let Some(v) = buy_value_override {
        v
    } else {
        let buy_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &buy_p2sh.script()[2..34]);
        println!("Querying buy order value from {}...", &buy_addr[..40]);
        let buy_utxos = rpc.get_utxos_by_addresses(&[&buy_addr]).await?;
        buy_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == buy_outpoint.transaction_id && u.outpoint.index == buy_outpoint.index)
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("Buy order UTXO not found on chain. Use --buy-value."))?
    };

    let sell_value = if let Some(v) = sell_value_override {
        v
    } else {
        let sell_addr = crate::cancel::kaspa_address_encode(network.address_prefix(), 8, &sell_p2sh.script()[2..34]);
        println!("Querying sell order value from {}...", &sell_addr[..40]);
        let sell_utxos = rpc.get_utxos_by_addresses(&[&sell_addr]).await?;
        sell_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == sell_outpoint.transaction_id && u.outpoint.index == sell_outpoint.index)
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("Sell order UTXO not found on chain. Use --sell-value."))?
    };

    println!("Buy Value:    {} sompi", buy_value);
    println!("Sell Value:   {} sompi", sell_value);

    // Compute expected amounts (checked to prevent silent overflow)
    let expected_tokens = buy_value
        .checked_mul(buy_price_num)
        .ok_or_else(|| anyhow::anyhow!(
            "Overflow: buy_value ({}) * buy_price_num ({}) exceeds u64",
            buy_value, buy_price_num
        ))? / buy_price_den;
    let expected_kas = sell_value
        .checked_mul(sell_price_num)
        .ok_or_else(|| anyhow::anyhow!(
            "Overflow: sell_value ({}) * sell_price_num ({}) exceeds u64",
            sell_value, sell_price_num
        ))? / sell_price_den;

    println!("Expected Tokens (buy contract):  {}", expected_tokens);
    println!("Expected KAS (sell contract):    {}", expected_kas);

    // In cross-pair, the buy and sell are in different token pairs.
    // The sell order releases Token A and wants KAS.
    // The buy order locks KAS and wants Token B.
    // The matcher provides Token B via token_outpoint.
    //
    // Value flow:
    //   sell_value (Token A as KAS-denominated) -> seller gets expected_kas in KAS
    //   buy_value (KAS) -> buyer gets expected_tokens in Token B
    //   token_outpoint provides Token B

    let seller_kas = expected_kas;
    let buyer_tokens = expected_tokens;

    // Check that buy order has enough KAS to cover seller's KAS expectation
    if seller_kas > buy_value {
        anyhow::bail!(
            "Sell order expects {} sompi KAS but buy order only has {} sompi",
            seller_kas,
            buy_value
        );
    }

    if seller_kas < MIN_UTXO_VALUE {
        anyhow::bail!("Seller's KAS output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.", seller_kas, MIN_UTXO_VALUE);
    }
    if buyer_tokens < MIN_UTXO_VALUE {
        anyhow::bail!("Buyer's token output ({} sompi) is below the minimum UTXO value ({}). \
             Increase the order size or adjust the price.", buyer_tokens, MIN_UTXO_VALUE);
    }

    let receipt_value = RECEIPT_VALUE;

    println!();
    println!("Cross-Pair Match TX Outputs:");
    println!("  output[0]: seller KAS      {} sompi", seller_kas);
    println!("  output[1]: buyer Token B   {} sompi", buyer_tokens);
    println!("  output[2]: trade_receipt   {} sompi", receipt_value);
    println!("  fee:                       {} sompi", fee);
    println!();

    // Get wallet SPK for outputs
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let wallet_spk_utxo = wallet_utxos
        .iter()
        .find(|u| !u.is_p2sh())
        .ok_or_else(|| anyhow::anyhow!("No spendable UTXOs in wallet. Fund the wallet first or run `kob wallet consolidate`."))?;
    let wallet_spk = wallet_spk_utxo.script_bytes();
    let wallet_spk_version = wallet_spk_utxo.utxo_entry.script_public_key.version;

    // Build fill sigscripts with cross-pair indices
    // sell at input[0]: kas_output_idx = 0
    let sell_fill_ss = contract::build_sell_fill_sigscript(0, &sell_rs);
    // buy at input[1]: token_output_idx = 1, token_input_idx = 2, cov_output_idx = 0
    let buy_fill_ss = contract::build_buy_fill_sigscript(1, 2, 0, &buy_rs);

    println!("Sell fill SS: {} bytes (v8, kas_out=0)", sell_fill_ss.len());
    println!("Buy fill SS:  {} bytes (v{}, tok_out=1, tok_in=2)", buy_fill_ss.len(), version);

    // Build receipt redeemScript
    let exec_amount = expected_tokens.min(sell_value);
    let receipt_rs = contract::build_receipt_redeem_script(
        &buy_tcid,
        buy_price_num,
        buy_price_den,
        exec_amount,
        RECEIPT_DUST,
        &buy_spk_hash,
    )?;
    let receipt_p2sh = build_p2sh(&receipt_rs);

    // Find the token UTXO
    let token_utxo = wallet_utxos
        .iter()
        .find(|u| u.outpoint.transaction_id == token_outpoint.transaction_id && u.outpoint.index == token_outpoint.index)
        .ok_or_else(|| anyhow::anyhow!("Token UTXO {} not found in wallet. It may have been spent or the TXID:INDEX is incorrect.", token_outpoint))?;
    let token_spk_bytes = token_utxo.script_bytes();
    let token_value = token_utxo.utxo_entry.amount;

    println!("Token UTXO:   {}:{} ({} sompi)", token_utxo.outpoint.transaction_id, token_utxo.outpoint.index, token_value);

    // Fee UTXO
    let fee_utxo = if let Some(ref fee_op) = _fee_outpoint {
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == fee_op.transaction_id && u.outpoint.index == fee_op.index)
            .ok_or_else(|| anyhow::anyhow!("The specified --fee-input UTXO was not found in the wallet. It may have been spent already."))?
    } else {
        wallet_utxos
            .iter()
            .find(|u| {
                !u.is_p2sh()
                    && u.utxo_entry.amount >= fee
                    && !(u.outpoint.transaction_id == token_outpoint.transaction_id
                        && u.outpoint.index == token_outpoint.index)
            })
            .ok_or_else(|| anyhow::anyhow!("No spendable UTXO available for the fee (must be separate from the token UTXO). Fund the wallet with more UTXOs."))?
    };

    let fee_spk_bytes = fee_utxo.script_bytes();
    let fee_value = fee_utxo.utxo_entry.amount;

    println!("Fee UTXO:     {}:{} ({} sompi)", fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_value);

    // Compute total input and outputs (tentative, fee=0 initially)
    let total_in = sell_value + buy_value + token_value + fee_value;
    let needed_out = seller_kas + buyer_tokens + receipt_value;

    if total_in < needed_out {
        anyhow::bail!(
            "Insufficient total input ({}) for outputs ({})",
            total_in,
            needed_out
        );
    }

    let tentative_change = total_in - needed_out;
    let (tentative_seller_kas, tentative_matcher_change) = if tentative_change >= MIN_UTXO_VALUE {
        (seller_kas, tentative_change)
    } else {
        (seller_kas + tentative_change, 0u64)
    };

    // Build transaction (version 1 for covenant-aware token matching)
    let mut tx = Transaction::new(1);

    // Input 0: sell_order (P2SH, fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: sell_outpoint.transaction_id,
        prev_index: sell_outpoint.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: sell_p2sh.version,
        script_bytes: sell_p2sh.script().to_vec(),
        value: sell_value,
    });

    // Input 1: buy_order (P2SH, fill, sigOpCount=0, CSV=50)
    tx.inputs.push(TxInput {
        prev_tx_id: buy_outpoint.transaction_id,
        prev_index: buy_outpoint.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: buy_p2sh.version,
        script_bytes: buy_p2sh.script().to_vec(),
        value: buy_value,
    });

    // Input 2: token UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: token_outpoint.transaction_id,
        prev_index: token_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: token_utxo.utxo_entry.script_public_key.version,
        script_bytes: token_spk_bytes,
        value: token_value,
    });

    // Input 3: fee UTXO (P2PK, signed, sigOpCount=1)
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_spk_bytes,
        value: fee_value,
    });

    // Output 0: seller KAS (sent to seller's address)
    tx.outputs.push(TxOutput::new(tentative_seller_kas, 0, seller_spk.clone(), None));

    // Output 1: buyer tokens (covenant-bound, sent to buyer's address)
    tx.outputs.push(TxOutput::new(buyer_tokens, 0, buyer_spk.clone(), Some(CovenantBinding::new(2, kob_core::compat::parse_hash(&buy_token_hex.to_string()).unwrap()))));

    // Output 2: trade receipt
    tx.outputs.push(TxOutput::new(receipt_value, receipt_p2sh.version, receipt_p2sh.script().to_vec(), None));

    // Output 3: matcher change (tentative, optional)
    if tentative_matcher_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_matcher_change, wallet_spk_version, wallet_spk.clone(), None));
    }

    // Compute mass-based miner fee from the tentative TX
    let mass_fee = calc_miner_fee(&tx);
    let actual_fee = if fee > 0 { fee.max(mass_fee) } else { mass_fee };

    // Adjust change to deduct the miner fee
    let adj_change = tentative_change.saturating_sub(actual_fee);
    let (final_seller_kas, matcher_change) = if adj_change >= MIN_UTXO_VALUE {
        (seller_kas, adj_change)
    } else {
        (seller_kas + adj_change, 0u64)
    };

    // Update outputs with final values
    tx.outputs[0].value = final_seller_kas;
    let has_change_output = tx.outputs.len() > 3;
    if matcher_change >= MIN_UTXO_VALUE {
        if has_change_output {
            tx.outputs[3].value = matcher_change;
        } else {
            tx.outputs.push(TxOutput::new(matcher_change, wallet_spk_version, wallet_spk, None));
        }
    } else if has_change_output {
        tx.outputs.pop();
    }

    // Sign input 2 (token UTXO) -- must sign AFTER final output adjustment
    let sighash_2 = compute_sighash(&tx, 2)?;
    let sig_2 = signing::schnorr_sign(&privkey, &sighash_2)?;
    let token_ss = signing::build_p2pk_sigscript(&sig_2);

    // Sign input 3 (fee UTXO)
    let sighash_3 = compute_sighash(&tx, 3)?;
    let sig_3 = signing::schnorr_sign(&privkey, &sighash_3)?;
    let fee_ss = signing::build_p2pk_sigscript(&sig_3);

    // Sigscripts: [sell_fill, buy_fill, token_sign, fee_sign]
    let sigscripts = vec![sell_fill_ss, buy_fill_ss, token_ss, fee_ss];

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let compute_mass = calc_compute_mass(&tx);
        let total_out: u64 = out_vals.iter().sum();
        let total_in_actual: u64 = in_vals.iter().sum();
        let actual_miner_fee = total_in_actual.saturating_sub(total_out);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9}", compute_mass);
        println!("Miner fee:        {:>9} sompi (mass: {})", actual_miner_fee, actual_miner_fee.max(storage_mass));
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!();
    println!("Submitting cross-pair match transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Cross-pair match transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("  Seller received: {} sompi KAS (output[0])", tx.outputs[0].value);
    println!("  Buyer received:  {} sompi Token B (output[1])", tx.outputs[1].value);
    println!("  Receipt at:      {}:2", tx_id);
    if matcher_change > 0 {
        println!("  Matcher change:  {} sompi (output[3])", matcher_change);
    }
    println!();
    println!("Receipt params for consumption:");
    println!("  --pair-id {}  --price-num {}  --price-den {}  --exec-amount {}",
        buy_token_hex, buy_price_num, buy_price_den, exec_amount);

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, compute_p2pk_spk_hash};

    #[test]
    fn fill_sigscripts_v12() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let buy_rs = contract::build_buy_redeem_script(&tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();
        let sell_rs = contract::build_sell_redeem_script(1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();

        let buy_ss = contract::build_buy_fill_sigscript(1, 1, 0, &buy_rs);
        let sell_ss = contract::build_sell_fill_sigscript(0, &sell_rs);

        // Buy v13 RS must be 409 bytes (129B state + 280B body)
        assert_eq!(buy_rs.len(), 409, "Buy v13 RS must be 409 bytes");
        // Sell v13 RS must be 378 bytes (92B state + 286B body)
        assert_eq!(sell_rs.len(), 378, "Sell v13 RS must be 378 bytes");
        // Fill sigscripts should be non-empty
        assert!(!buy_ss.is_empty(), "Buy fill SS must not be empty");
        assert!(!sell_ss.is_empty(), "Sell fill SS must not be empty");
        // Sell fill uses Op1 selector (fill path) at index 1 (after kas_output_idx)
        assert_eq!(sell_ss[1], 0x51, "Sell fill selector must be Op1");
    }

    #[test]
    fn price_crossing_check() {
        // buy at 1/2, sell at 1/2 -> crossing
        let buy_value = 10_000_000u64;
        let sell_value = 10_000_000u64;
        let expected_tokens = (buy_value * 1) / 2; // 5M
        let expected_kas = (sell_value * 1) / 2; // 5M
        let total = buy_value + sell_value;
        let surplus = total - expected_tokens - expected_kas;
        assert_eq!(surplus, 10_000_000);
        assert!(surplus >= kob_core::DEFAULT_MATCHER_FEE);
    }

    #[test]
    fn price_not_crossing() {
        // buy at 1/10, sell at 5/1 -> not crossing
        let buy_value = 10_000_000u64;
        let sell_value = 10_000_000u64;
        let expected_tokens = (buy_value * 1) / 10; // 1M
        let expected_kas = (sell_value * 5) / 1; // 50M
        // seller_kas + buyer_tokens = 51M > total 20M
        assert!(expected_kas + expected_tokens > buy_value + sell_value);
    }

    #[test]
    fn match_output_small_change_goes_to_seller() {
        let seller_kas = 5_000_000u64;
        let _buyer_tokens = 5_000_000u64;
        let surplus = 500_000u64; // surplus only needs to cover fee
        let fee = kob_core::DEFAULT_MATCHER_FEE; // 10K
        // Receipt funded by matcher wallet, not from surplus
        let raw_change = surplus - fee; // 490K < MIN_UTXO(3M)
        assert!(raw_change < kob_core::MIN_UTXO_VALUE);
        let final_seller = seller_kas + raw_change;
        assert_eq!(final_seller, 5_490_000);
    }

    #[test]
    fn receipt_redeem_script_size() {
        let tcid = [0x01u8; 32];
        let recipient_hash = [0xEEu8; 32];
        let rs = contract::build_receipt_redeem_script(&tcid, 1, 2, 5_000_000, 3_000_000, &recipient_hash).unwrap();
        assert_eq!(rs.len(), 119);
    }

    #[test]
    fn v12_fill_sigscripts_structure() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let buy_rs = contract::build_buy_redeem_script(&tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();
        let sell_rs = contract::build_sell_redeem_script(1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();

        let buy_ss = contract::build_buy_fill_sigscript(1, 1, 0, &buy_rs);
        let sell_ss = contract::build_sell_fill_sigscript(0, &sell_rs);

        // Buy v13 fill: [tok_out_idx=Op1] [tok_in_idx=Op1] [cov_out_idx=Op0] [Op1 selector] [pushData(RS)]
        assert_eq!(buy_ss[0], 0x51, "token_output_idx=1 -> Op1");
        assert_eq!(buy_ss[1], 0x51, "token_input_idx=1 -> Op1");
        assert_eq!(buy_ss[2], 0x00, "cov_output_idx=0 -> Op0");
        assert_eq!(buy_ss[3], 0x51, "selector=1 -> Op1 (fill)");

        // Sell v13 fill: [kas_out_idx=Op0] [Op1 selector] [pushData(RS)]
        assert_eq!(sell_ss[0], 0x00, "kas_output_idx=0 -> Op0");
        assert_eq!(sell_ss[1], 0x51, "selector=1 -> Op1 (fill)");
    }

    #[test]
    fn v12_cross_pair_fill_sigscripts_indices() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let buy_rs = contract::build_buy_redeem_script(&tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();
        let sell_rs = contract::build_sell_redeem_script(1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();

        // Cross-pair: sell[0] buy[1] token[2] fee[3]
        let sell_ss = contract::build_sell_fill_sigscript(0, &sell_rs);
        let buy_ss = contract::build_buy_fill_sigscript(1, 2, 0, &buy_rs);

        assert_eq!(sell_ss[0], 0x00, "cross-pair sell: kas_out=0 -> Op0");
        // v13 buy fill: [tok_out] [tok_in] [cov_out] [selector]
        assert_eq!(buy_ss[0], 0x51, "cross-pair buy: tok_out=1 -> Op1");
        assert_eq!(buy_ss[1], 0x52, "cross-pair buy: tok_in=2 -> Op2");
        assert_eq!(buy_ss[2], 0x00, "cross-pair buy: cov_out=0 -> Op0");
        assert_eq!(buy_ss[3], 0x51, "cross-pair buy: selector=1 (fill)");
    }
}
