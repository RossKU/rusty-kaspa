//! `kob-cli bracket` -- Deploy, fill, and cancel bracket_order_v4 contracts.
//!
//! A bracket order is a single UTXO (bracket_order_v4) that encodes:
//! - Entry price (buy or sell)
//! - Take-profit (TP) exit order SPK + min value
//! - Stop-loss (SL) exit order SPK + min value
//! - Receipt covenant ID for fill verification
//! - Owner hash for cancel authorization
//!
//! bracket_order_v4 RS = 238B state + 142B body = 380B
//!
//! Fill TX layout (3 inputs, 4+ outputs):
//!   input[0]: bracket_order_v4 (sigscript: [Op1][pushData(RS 380B)] = 384B < 420)
//!   input[1]: P2PK funding/payment UTXO
//!   input[2]: trade_receipt UTXO (must have correct covenant_id AND value >= min)
//!   output[0]: seller KAS (for sell entry) or buyer KAS (for buy entry)
//!   output[1]: buyer tokens (for buy entry) or seller tokens (for sell entry)
//!   output[2]: TP oco_pair P2SH (SPK must match tp_spk, value >= tp_min_value)
//!   output[3]: SL oco_pair P2SH (SPK must match sl_spk, value >= sl_min_value)
//!   output[4+]: change (optional)
//!
//! Cancel TX layout (2 inputs, 1 output):
//!   input[0]: bracket_order_v4 (sigscript: [Op0][sig+type 65B][pk 32B][pushData(RS)] = 483B >= 420)
//!   input[1]: fee UTXO (P2PK, signed)
//!   output[0]: recovered funds to wallet
//!
//! Dispatch boundary: 420 (fill < 420, cancel >= 420)

use crate::cancel::p2sh_to_address;
use crate::node::NodeClient;
use crate::signing;
use clap::Subcommand;
use kob_core::contract;
use kob_core::contract::build_order_payload;
use kob_core::p2sh::{blake2b_256, build_p2sh};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint, Price};
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

#[derive(Subcommand, Debug)]
pub enum BracketCommand {
    /// Deploy a bracket_order_v4 (single UTXO with entry + TP/SL exit SPKs).
    Deploy {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Entry type: 0 = buy, 1 = sell.
        #[arg(long, default_value = "0")]
        entry_type: u64,

        /// Entry price numerator.
        #[arg(long)]
        entry_num: u64,

        /// Entry price denominator.
        #[arg(long)]
        entry_den: u64,

        /// Take-profit P2SH SPK (hex, 74 chars = 37 bytes: version u16LE + P2SH script). The full
        /// scriptPublicKey bytes of the TP oco_pair contract.
        #[arg(long)]
        tp_spk: String,

        /// Minimum value for TP output (sompi).
        #[arg(long)]
        tp_min_value: u64,

        /// Stop-loss P2SH SPK (hex, 74 chars = 37 bytes: version u16LE + P2SH script). The full
        /// scriptPublicKey bytes of the SL oco_pair contract.
        #[arg(long)]
        sl_spk: String,

        /// Minimum value for SL output (sompi).
        #[arg(long)]
        sl_min_value: u64,

        /// Minimum fill amount.
        #[arg(long)]
        min_fill: u64,

        /// Receipt covenant ID (hex, 64 chars). The Kaspa CovenantID of the
        /// trade_receipt contract that will be used at input[2] during fill.
        #[arg(long)]
        receipt_cov_id: String,

        /// Amount of KAS to lock (in sompi).
        #[arg(long)]
        amount: u64,
    },

    /// Fill a bracket_order_v4 (execute the entry trade).
    Fill {
        /// Bracket order outpoint (txid:index).
        #[arg(long)]
        order: String,

        /// Bracket order UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,

        /// RedeemScript of the bracket order (hex).
        #[arg(long)]
        rs: String,

        /// Receipt UTXO outpoint (txid:index).
        #[arg(long)]
        receipt: String,

        /// Receipt UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        receipt_value: Option<u64>,

        /// Seller KAS output value (sompi).
        #[arg(long)]
        seller_kas: u64,

        /// Buyer token output value (sompi, represents token units).
        #[arg(long)]
        buyer_tokens: u64,

        /// TP output value (sompi, must be >= tp_min_value in contract).
        #[arg(long)]
        tp_value: u64,

        /// SL output value (sompi, must be >= sl_min_value in contract).
        #[arg(long)]
        sl_value: u64,

        /// Receipt redeemScript (hex). Required to spend the receipt P2SH
        /// input. The receipt contract evaluates its script, so the full
        /// redeemScript must be provided as `[pushData(receipt_RS)]`.
        #[arg(long)]
        receipt_rs: String,

        /// Fee input outpoint (txid:index). Auto-selected from wallet if omitted.
        #[arg(long)]
        fee_input: Option<String>,
    },

    /// Cancel a bracket_order_v4 (owner signature).
    Cancel {
        /// Bracket order outpoint (txid:index).
        #[arg(long)]
        order: String,

        /// Bracket order UTXO value in sompi (queried from chain if omitted).
        #[arg(long)]
        order_value: Option<u64>,

        /// RedeemScript of the bracket order (hex).
        #[arg(long)]
        rs: String,
    },
}

// bracket deploy

/// Deploy a bracket_order_v4 contract as a single P2SH UTXO.
#[allow(clippy::too_many_arguments)]
pub async fn deploy_bracket_v4(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    token_hex: &str,
    entry_type: u64,
    entry_num: u64,
    entry_den: u64,
    tp_spk_hex: &str,
    tp_min_value: u64,
    sl_spk_hex: &str,
    sl_min_value: u64,
    min_fill: u64,
    receipt_cov_id_hex: &str,
    amount: u64,
) -> anyhow::Result<()> {
    // Validate entry type
    if entry_type > 1 {
        anyhow::bail!("Invalid entry type. Use 0 for buy or 1 for sell.");
    }

    let _entry_price = Price::new(entry_num, entry_den)?;
    if min_fill == 0 {
        anyhow::bail!("min_fill must be > 0");
    }
    if amount < MIN_UTXO_VALUE {
        anyhow::bail!("Amount is too small. Minimum order size is {} sompi.", MIN_UTXO_VALUE);
    }

    // Parse token covenant ID
    let token_bytes = hex::decode(token_hex)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_bytes);

    // Parse TP SPK (37 bytes: version u16LE + 35-byte P2SH script)
    let tp_spk_bytes = hex::decode(tp_spk_hex)?;
    if tp_spk_bytes.len() != 37 {
        anyhow::bail!("Invalid take-profit script: expected 74 hex characters (37 bytes), got {} characters. \
             Provide the version + P2SH script of the take-profit order.", tp_spk_hex.len());
    }
    let mut tp_spk = [0u8; 37];
    tp_spk.copy_from_slice(&tp_spk_bytes);

    // Parse SL SPK (37 bytes)
    let sl_spk_bytes = hex::decode(sl_spk_hex)?;
    if sl_spk_bytes.len() != 37 {
        anyhow::bail!("Invalid stop-loss script: expected 74 hex characters (37 bytes), got {} characters. \
             Provide the version + P2SH script of the stop-loss order.", sl_spk_hex.len());
    }
    let mut sl_spk = [0u8; 37];
    sl_spk.copy_from_slice(&sl_spk_bytes);

    // Parse receipt covenant ID
    let rcid_bytes = hex::decode(receipt_cov_id_hex)?;
    if rcid_bytes.len() != 32 {
        anyhow::bail!("Invalid receipt covenant ID: expected 64 hex characters.");
    }
    let mut receipt_cov_id = [0u8; 32];
    receipt_cov_id.copy_from_slice(&rcid_bytes);

    // Load wallet
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();
    let owner_hash = blake2b_256(&pubkey);

    // Build bracket_order_v4 redeemScript (380B)
    let redeem_script = contract::build_bracket_redeem_script(
        entry_type,
        &token_cov_id,
        entry_num,
        entry_den,
        &tp_spk,
        tp_min_value,
        &sl_spk,
        sl_min_value,
        min_fill,
        0, // min_receipt_value (receipt value check is secondary to cov_id check)
        &receipt_cov_id,
        &owner_hash,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy bracket_order_v4");
    println!("========================");
    println!("Token:           {}", token_hex);
    println!("Entry Type:      {} ({})", entry_type, if entry_type == 0 { "buy" } else { "sell" });
    println!("Entry Price:     {}/{} ({:.6})", entry_num, entry_den, entry_num as f64 / entry_den as f64);
    println!("TP SPK:          {}...{}", &tp_spk_hex[..16], &tp_spk_hex[tp_spk_hex.len()-8..]);
    println!("TP Min Value:    {} sompi", tp_min_value);
    println!("SL SPK:          {}...{}", &sl_spk_hex[..16], &sl_spk_hex[sl_spk_hex.len()-8..]);
    println!("SL Min Value:    {} sompi", sl_min_value);
    println!("Min Fill:        {}", min_fill);
    println!("Receipt Cov ID:  {}...", &receipt_cov_id_hex[..16]);
    println!("Amount:          {} sompi ({:.8} KAS)", amount, amount as f64 / 1e8);
    println!("Owner:           {}", wallet.pubkey_hex());
    println!("Owner Hash:      {}", hex::encode(owner_hash));
    println!();
    println!("RedeemScript:    {} bytes (bracket_order_v4)", redeem_script.len());
    println!("RS hex:          {}", hex::encode(&redeem_script));
    println!("P2SH SPK:        {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch UTXOs
    info!(amount = amount, "deploying bracket_order_v4");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    // Conservative budget: estimate_compute_mass for 1-in/2-out + headroom
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

    // Build TX version 0 (no covenant binding needed on bracket deploy)
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

    // Output 0: bracket_order_v4 P2SH
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

    // TX payload: RS for matcher L1 discovery (replaces OP_RETURN)
    tx.payload = build_order_payload(&redeem_script, false);

    // Output 1: tentative change for mass calculation
    let wallet_spk = hex::decode(&funding.utxo_entry.script_public_key.script)?;
    let tentative_change = total_input.saturating_sub(amount + est_fee_budget);
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output
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
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
    } else if !has_change && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, funding.utxo_entry.script_public_key.version, wallet_spk.clone(), None));
    } else if !has_change && change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Phase 1: sign
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_vec = vec![sigscript];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_vec);
    let exact_fee = exact_mass;

    let (sigscript, actual_fee) = if exact_fee != est_fee {
        if tx.outputs.len() > 1 {
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
            let signature = signing::schnorr_sign(&privkey, &sighash)?;
            (signing::build_p2pk_sigscript(&signature), exact_fee)
        } else {
            (sigscripts_vec.into_iter().next().unwrap(), exact_fee)
        }
    } else {
        (sigscripts_vec.into_iter().next().unwrap(), est_fee)
    };

    let deploy_exact_compute = calc_mass_with_sigscripts(&tx, &[sigscript.clone()]);
    println!("Compute mass:  {:>9} (exact, post-sign)", deploy_exact_compute);
    println!("Miner fee:     {:>9} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting bracket deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! bracket_order_v4 deployed.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Order:  {}:0 ({} sompi)", tx_id, amount);
    println!("RS:     {} ({}B)", hex::encode(&redeem_script), redeem_script.len());
    println!();
    println!("Fill command:");
    println!("  kob-cli bracket fill \\");
    println!("    --order {}:0 \\", tx_id);
    println!("    --rs {} \\", hex::encode(&redeem_script));
    println!("    --receipt <receipt_txid>:0 \\");
    println!("    --receipt-rs <receipt_redeem_script_hex> \\");
    println!("    --seller-kas <amount> --buyer-tokens <amount> \\");
    println!("    --tp-value {} --sl-value {}", tp_min_value, sl_min_value);
    println!();
    println!("Cancel command:");
    println!("  kob-cli bracket cancel \\");
    println!("    --order {}:0 \\", tx_id);
    println!("    --rs {}", hex::encode(&redeem_script));

    Ok(())
}

// bracket fill

/// Fill a bracket_order_v4 (execute the entry trade).
///
/// Fill TX is version 0 (no covenant binding on the fill TX itself).
/// The bracket contract verifies:
/// - output[2].SPK == tp_spk and output[2].value >= tp_min_value
/// - output[3].SPK == sl_spk and output[3].value >= sl_min_value
/// - input[2].value >= min_receipt_value
/// - input[2].covenant_id == receipt_cov_id (N4 check)
/// - Entry price arithmetic on output[0]/output[1]
#[allow(clippy::too_many_arguments)]
pub async fn fill_bracket_v4(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    order_str: &str,
    order_value_override: Option<u64>,
    rs_hex: &str,
    receipt_str: &str,
    receipt_value_override: Option<u64>,
    seller_kas: u64,
    buyer_tokens: u64,
    tp_value: u64,
    sl_value: u64,
    receipt_rs_hex: &str,
    fee_input_str: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let order_outpoint = Outpoint::parse(order_str)?;
    let receipt_outpoint = Outpoint::parse(receipt_str)?;

    // Parse redeemScript
    let redeem_script = hex::decode(rs_hex)?;
    if redeem_script.len() != 380 {
        anyhow::bail!(
            "bracket_order_v4 RS must be 380 bytes, got {}",
            redeem_script.len()
        );
    }
    let p2sh = build_p2sh(&redeem_script);

    // Extract TP SPK (37B starting at offset: 9+33+9+9 = 60, then +1 push prefix = byte 61..98)
    // State layout: [0x08][etype 8B][0x20][tcid 32B][0x08][epnum 8B][0x08][epden 8B]
    //               [0x25][tp_spk 37B][0x08][tp_mv 8B][0x25][sl_spk 37B]...
    // Offset of tp_spk push prefix: 9+33+9+9 = 60 -> tp_spk data at 61..98
    let tp_spk_version = u16::from_le_bytes([redeem_script[61], redeem_script[62]]);
    let tp_spk_script = &redeem_script[63..98]; // 35 bytes

    // Offset of SL SPK: 60+1+37+9 = 107 -> sl_spk data at 108..145
    let sl_spk_version = u16::from_le_bytes([redeem_script[108], redeem_script[109]]);
    let sl_spk_script = &redeem_script[110..145]; // 35 bytes

    println!("Fill bracket_order_v4");
    println!("======================");
    println!("Order:          {}", order_outpoint);
    println!("Receipt:        {}", receipt_outpoint);
    println!("RS:             {} bytes", redeem_script.len());
    println!("P2SH SPK:       {}", hex::encode(&p2sh.script()));
    println!();
    println!("Output layout:");
    println!("  [0] seller KAS:   {} sompi", seller_kas);
    println!("  [1] buyer tokens: {} sompi", buyer_tokens);
    println!("  [2] TP exit:      {} sompi", tp_value);
    println!("  [3] SL exit:      {} sompi", sl_value);
    println!();

    // Connect
    info!(order = %order_outpoint, "filling bracket_order_v4");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Resolve order value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_addr = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("Querying bracket order value...");
        let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_addr]).await?;
        let utxo = order_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == order_outpoint.transaction_id
                    && u.outpoint.index == order_outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Bracket order {} not found. It may be spent or use --order-value.",
                    order_outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };
    println!("Order Value:    {} sompi", order_value);

    // Resolve receipt UTXO details via getTransaction RPC.
    // We always need the receipt SPK for sighash computation.
    let receipt_value: u64;
    let receipt_spk_script: Vec<u8>;
    let receipt_spk_version: u16;

    println!("Querying receipt UTXO via transaction lookup...");
    let tx_data = rpc.call(
        "getTransaction",
        serde_json::json!({
            "transactionId": receipt_outpoint.transaction_id,
            "includeVerboseData": true,
        }),
    ).await;

    match tx_data {
        Ok(resp) => {
            let outputs = resp.get("transaction")
                .and_then(|t| t.get("outputs"))
                .and_then(|o| o.as_array());
            if let Some(outs) = outputs {
                let idx = receipt_outpoint.index as usize;
                if idx >= outs.len() {
                    anyhow::bail!("Receipt output index {} is out of range (transaction has {} outputs). \
                                  Check the receipt TXID and index.",
                                  idx, outs.len());
                }
                let out = &outs[idx];
                receipt_value = if let Some(rv) = receipt_value_override {
                    rv
                } else {
                    out.get("value")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| anyhow::anyhow!("Cannot read receipt output value from the node. The transaction may not be confirmed yet."))?
                };
                let spk = out.get("scriptPublicKey")
                    .ok_or_else(|| anyhow::anyhow!("Receipt output is missing script data. The transaction may be malformed."))?;
                receipt_spk_version = spk.get("version")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16;
                receipt_spk_script = hex::decode(
                    spk.get("script")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("Receipt output is missing the script field. The transaction may be malformed."))?
                )?;
            }
            else {
                anyhow::bail!("Cannot read receipt transaction outputs from the node. Verify the receipt TXID.");
            }
        }
        Err(e) => {
            anyhow::bail!(
                "Failed to query receipt TX {}: {}. Ensure the TX is confirmed.",
                receipt_outpoint.transaction_id, e
            );
        }
    }

    println!("Receipt Value:  {} sompi", receipt_value);

    // Get funding UTXO
    // Conservative fee estimate for 3-in/5-out bracket fill TX
    let est_fee_budget = estimate_compute_mass(3, 5, 0) + 500;
    let total_fixed_out = seller_kas + buyer_tokens + tp_value + sl_value;
    let total_inputs_min = order_value + receipt_value;
    let extra_funding_needed = if total_fixed_out + est_fee_budget > total_inputs_min {
        total_fixed_out + est_fee_budget - total_inputs_min
    } else {
        est_fee_budget // still need a fee UTXO for signing
    };

    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    let fee_utxo = if let Some(fi) = fee_input_str {
        let fi_outpoint = Outpoint::parse(fi)?;
        wallet_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == fi_outpoint.transaction_id
                    && u.outpoint.index == fi_outpoint.index
            })
            .ok_or_else(|| anyhow::anyhow!("The specified fee input {} was not found in the wallet. It may have been spent already.", fi))?
    } else {
        wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= extra_funding_needed)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No UTXO with at least {} sompi available for funding ({} UTXOs in wallet). \
                     Fund the wallet or run `kob wallet consolidate`.",
                    extra_funding_needed,
                    wallet_utxos.len()
                )
            })?
    };

    println!(
        "Fee UTXO:       {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = order_value + fee_utxo.utxo_entry.amount + receipt_value;
    let total_out = seller_kas + buyer_tokens + tp_value + sl_value;

    // Build fill TX (version 0)
    let mut tx = Transaction::new(0);

    // Input 0: bracket_order_v4 UTXO (sigOpCount = 0 for fill path)
    tx.inputs.push(TxInput {
        prev_tx_id: order_outpoint.transaction_id.clone(),
        prev_index: order_outpoint.index,
        sequence: 0,
        sig_op_count: 0, // fill path has no CheckSig
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });

    // Input 1: P2PK funding UTXO (sigOpCount = 1)
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

    // Input 2: trade_receipt UTXO (sigOpCount = 1, v4 always requires recipient signature)
    tx.inputs.push(TxInput {
        prev_tx_id: receipt_outpoint.transaction_id.clone(),
        prev_index: receipt_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: receipt_spk_version,
        script_bytes: receipt_spk_script,
        value: receipt_value,
    });

    // Wallet SPK for seller/buyer outputs
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;

    // Output 0: seller KAS
    tx.outputs.push(TxOutput::new(seller_kas, wallet_spk_version, wallet_spk.clone(), None));

    // Output 1: buyer tokens
    tx.outputs.push(TxOutput::new(buyer_tokens, wallet_spk_version, wallet_spk.clone(), None));

    // Output 2: TP oco_pair P2SH (SPK extracted from RS)
    tx.outputs.push(TxOutput::new(tp_value, tp_spk_version, tp_spk_script.to_vec(), None));

    // Output 3: SL oco_pair P2SH (SPK extracted from RS)
    tx.outputs.push(TxOutput::new(sl_value, sl_spk_version, sl_spk_script.to_vec(), None));

    // Output 4: tentative change for mass calculation
    let tentative_change = total_in.saturating_sub(total_out + est_fee_budget);
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, wallet_spk_version, wallet_spk.clone(), None));
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

    let change = if has_change {
        tx.outputs.last().unwrap().value
    } else {
        total_in.saturating_sub(total_out + est_fee)
    };

    if total_in < total_out + est_fee {
        anyhow::bail!(
            "Insufficient total inputs ({}) for outputs ({}) + fee ({})",
            total_in, total_out, est_fee
        );
    }

    if has_change && change < MIN_UTXO_VALUE {
        tx.outputs.pop();
        if change > 0 {
            tx.outputs[0].value += change;
            println!("Change {} sompi below MIN_UTXO_VALUE, added to seller output.", change);
        }
    } else if !has_change && change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, wallet_spk_version, wallet_spk.clone(), None));
    } else if !has_change && change > 0 {
        tx.outputs[0].value += change;
        println!("Change {} sompi below MIN_UTXO_VALUE, added to seller output.", change);
    }

    println!("Total In:       {} sompi", total_in);
    println!("Total Out:      {} sompi + {} fee", total_out, est_fee);
    if change >= MIN_UTXO_VALUE {
        println!("Change:         {} sompi", change);
    }
    println!();

    // Build sigscripts
    // Input 0: bracket fill sigscript [Op1][pushData(RS)]
    let bracket_fill_ss = contract::build_bracket_fill_sigscript(&redeem_script);
    println!("Fill SigScript:  {} bytes (< 420: {})", bracket_fill_ss.len(), bracket_fill_ss.len() < 420);

    // Input 1: P2PK signature
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Input 2: receipt sigscript [push(sig 65B)] [push(pk 32B)] [pushData(receiptRS)]
    // Receipt v4: always requires recipient signature (no trigger-read path).
    let receipt_rs_bytes = hex::decode(receipt_rs_hex)?;
    if receipt_rs_bytes.is_empty() {
        anyhow::bail!("--receipt-rs cannot be empty. Provide the receipt redeemScript hex value.");
    }
    let receipt_sighash = compute_sighash(&tx, 2)?;
    let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;
    let receipt_sigscript = contract::build_receipt_consume_sigscript(
        &receipt_sig,
        &pubkey,
        &receipt_rs_bytes,
    );
    println!("Receipt SS:      {} bytes (v4 consume, signed)", receipt_sigscript.len());

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_fill = vec![bracket_fill_ss.clone(), fee_sigscript.clone(), receipt_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_fill);
    let exact_fee = exact_mass;

    let (bracket_fill_ss, fee_sigscript, receipt_sigscript, actual_fee) = if exact_fee != est_fee {
        // Re-adjust change or seller output
        if tx.outputs.len() > 4 {
            let change_idx = tx.outputs.len() - 1;
            let new_change = total_in.saturating_sub(total_out + exact_fee);
            if new_change >= MIN_UTXO_VALUE {
                tx.outputs[change_idx].value = new_change;
            } else {
                tx.outputs.pop();
                if new_change > 0 {
                    tx.outputs[0].value += new_change;
                }
            }
        }
        // Re-sign inputs 1 and 2
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);
        let receipt_sighash = compute_sighash(&tx, 2)?;
        let receipt_sig = signing::schnorr_sign(&privkey, &receipt_sighash)?;
        let receipt_sigscript = contract::build_receipt_consume_sigscript(
            &receipt_sig,
            &pubkey,
            &receipt_rs_bytes,
        );
        // Input 0 sigscript is data-only (no signature), no re-sign needed
        (bracket_fill_ss, fee_sigscript, receipt_sigscript, exact_fee)
    } else {
        (bracket_fill_ss, fee_sigscript, receipt_sigscript, est_fee)
    };

    let fill_exact_compute = calc_mass_with_sigscripts(&tx, &[bracket_fill_ss.clone(), fee_sigscript.clone(), receipt_sigscript.clone()]);
    println!("Compute mass:   {:>9} (exact, post-sign)", fill_exact_compute);
    println!("Miner fee:      {:>9} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[bracket_fill_ss, fee_sigscript, receipt_sigscript]);
    println!("Submitting bracket fill transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Bracket order filled.");
    println!("TXID: {}", tx_id);
    println!();
    println!("  [0] seller KAS:    {} sompi", tx.outputs[0].value);
    println!("  [1] buyer tokens:  {} sompi", buyer_tokens);
    println!("  [2] TP exit:       {} sompi at {}:2", tp_value, tx_id);
    println!("  [3] SL exit:       {} sompi at {}:3", sl_value, tx_id);

    Ok(())
}

// bracket cancel

/// Cancel a bracket_order_v4 (owner signature).
pub async fn cancel_bracket_v4(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    order_str: &str,
    order_value_override: Option<u64>,
    rs_hex: &str,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let order_outpoint = Outpoint::parse(order_str)?;

    // Parse redeemScript
    let redeem_script = hex::decode(rs_hex)?;
    if redeem_script.len() != 380 {
        anyhow::bail!(
            "bracket_order_v4 RS must be 380 bytes, got {}",
            redeem_script.len()
        );
    }
    let p2sh = build_p2sh(&redeem_script);

    println!("Cancel bracket_order_v4");
    println!("========================");
    println!("Order:         {}", order_outpoint);
    println!("RS:            {} bytes", redeem_script.len());
    println!("P2SH SPK:      {}", hex::encode(&p2sh.script()));
    println!("Owner:         {}", wallet.pubkey_hex());
    println!();

    // Connect
    info!(order = %order_outpoint, "cancelling bracket_order_v4");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Resolve order value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_addr = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_addr);
        println!("Querying bracket order value...");
        let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_addr]).await?;
        let utxo = order_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == order_outpoint.transaction_id
                    && u.outpoint.index == order_outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Bracket order {} not found. It may be spent or use --order-value.",
                    order_outpoint
                )
            })?;
        utxo.utxo_entry.amount
    };
    println!("Order Value:   {} sompi", order_value);

    // Get fee UTXO from wallet
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
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    let total_in = order_value + fee_utxo.utxo_entry.amount;

    // Build cancel TX (version 0)
    let mut tx = Transaction::new(0);

    // Input 0: bracket_order_v4 UTXO (sigOpCount = 1 for cancel path -- has CheckSigVerify)
    tx.inputs.push(TxInput {
        prev_tx_id: order_outpoint.transaction_id.clone(),
        prev_index: order_outpoint.index,
        sequence: 0,
        sig_op_count: 1, // cancel path has CheckSigVerify
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
        script_bytes: fee_spk_bytes,
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: recovered funds to wallet (tentative, adjusted by converge_fee)
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let tentative_output = total_in.saturating_sub(est_fee_budget);
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee on output[0]
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, 0);

    // Sign input 0 (cancel path signature)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;

    // Build cancel sigscript: [Op0][pushData(sig+type 65B)][pushData(pk 32B)][pushData(RS 380B)]
    let cancel_sigscript = contract::build_bracket_cancel_sigscript(&sig_0, &pubkey, &redeem_script);

    println!("Cancel SigScript: {} bytes (>= 420: {})", cancel_sigscript.len(), cancel_sigscript.len() >= 420);

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_cancel = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_cancel);
    let exact_fee = exact_mass;

    let (cancel_sigscript, fee_sigscript, actual_fee) = if exact_fee != est_fee {
        let output_value = total_in.saturating_sub(exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign with updated output value
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let cancel_sigscript = contract::build_bracket_cancel_sigscript(&sig_0, &pubkey, &redeem_script);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

        (cancel_sigscript, fee_sigscript, exact_fee)
    } else {
        (cancel_sigscript, fee_sigscript, est_fee)
    };

    let output_value = tx.outputs[0].value;
    println!("Output Value:  {} sompi", output_value);
    let cancel_exact_compute = calc_mass_with_sigscripts(&tx, &[cancel_sigscript.clone(), fee_sigscript.clone()]);
    println!("Compute mass:  {:>9} (exact, post-sign)", cancel_exact_compute);
    println!("Miner fee:     {:>9} sompi", actual_fee);
    println!();

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_sigscript, fee_sigscript]);
    println!("Submitting bracket cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Bracket order cancelled.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

// Legacy bracket deploy (top-level `kob-cli bracket` command) -- retained
// for backward compat but now calls deploy_bracket_v4_simple.

/// Legacy bracket deploy (simple: builds TP/SL oco_pair RS internally).
///
/// This is the backward-compatible entry point for the top-level `bracket`
/// command. It constructs the TP/SL oco_pair redeemScripts from the provided
/// prices, then deploys a bracket_order_v4.
///
/// Because the receipt_cov_id depends on the receipt's genesis TX (which
/// doesn't exist yet at bracket deploy time), this command requires the
/// receipt to already be deployed and the covenant ID to be known.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // Public API: legacy bracket deploy command
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    pair_id_hex: &str,
    entry_price_num: u64,
    entry_price_den: u64,
    tp_price_num: u64,
    tp_price_den: u64,
    sl_price_num: u64,
    sl_price_den: u64,
    amount: u64,
    min_receipt_value: u64,
    receipt_cov_id_hex: &str,
) -> anyhow::Result<()> {
    // Parse pair_id
    let pair_id_bytes = hex::decode(pair_id_hex)?;
    if pair_id_bytes.len() != 32 {
        anyhow::bail!("Invalid pair ID: expected 64 hex characters. Check the --pair-id value.");
    }
    let mut pair_id = [0u8; 32];
    pair_id.copy_from_slice(&pair_id_bytes);

    let entry_price = Price::new(entry_price_num, entry_price_den)?;
    let tp_price = Price::new(tp_price_num, tp_price_den)?;
    let sl_price = Price::new(sl_price_num, sl_price_den)?;

    let params = BracketParams {
        pair_id,
        pair_id_hex: pair_id_hex.to_string(),
        entry_price,
        tp_price,
        sl_price,
        amount,
        min_receipt_value,
    };
    params.validate()?;

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let owner_hash = blake2b_256(&pubkey);
    // Build TP / SL oco_pair redeemScripts to get their P2SH SPKs.
    // Using oco_pair_v4 which adds CBP value floor + input count = 2 checks.
    // v4 has the same state layout as v3 (181B), no circular dependency.
    let nonce: [u8; 32] = {
        // Deterministic nonce from pair_id + entry_price to avoid randomness
        // In production, use a true random nonce
        let mut h = kob_core::p2sh::Blake2bSimple::new_keyed(b"BracketNonce");
        h.update(&pair_id);
        h.update(&entry_price_num.to_le_bytes());
        h.update(&entry_price_den.to_le_bytes());
        h.update(&pubkey);
        h.finalize()
    };

    // Owner SPK (36 bytes: version u16LE + script 34B for P2PK)
    let mut owner_spk = [0u8; 36];
    owner_spk[0..2].copy_from_slice(&0u16.to_le_bytes()); // version 0
    owner_spk[2] = 0x20; // push 32 bytes
    owner_spk[3..35].copy_from_slice(&pubkey);
    owner_spk[35] = 0xac; // OpCheckSig

    let tp_rs = contract::build_oco_pair_redeem_script(
        &nonce,
        1, // role = sell (TP exit is a sell)
        &pair_id,
        0, // token_amount (not used for sell role in bracket context)
        tp_price_num,
        tp_price_den,
        MIN_UTXO_VALUE,
        &owner_hash,
        &owner_spk,
    )?;

    let sl_rs = contract::build_oco_pair_redeem_script(
        &nonce,
        1, // role = sell (SL exit is also a sell)
        &pair_id,
        0,
        sl_price_num,
        sl_price_den,
        MIN_UTXO_VALUE,
        &owner_hash,
        &owner_spk,
    )?;

    let tp_p2sh = build_p2sh(&tp_rs);
    let sl_p2sh = build_p2sh(&sl_rs);

    // Build 37-byte SPK bytes (version u16LE + P2SH script 35B)
    let mut tp_spk = [0u8; 37];
    tp_spk[0..2].copy_from_slice(&tp_p2sh.version.to_le_bytes());
    tp_spk[2..37].copy_from_slice(&tp_p2sh.script());

    let mut sl_spk = [0u8; 37];
    sl_spk[0..2].copy_from_slice(&sl_p2sh.version.to_le_bytes());
    sl_spk[2..37].copy_from_slice(&sl_p2sh.script());

    // Parse receipt covenant ID (required for N4 security check)
    let rcid_bytes = hex::decode(receipt_cov_id_hex)?;
    if rcid_bytes.len() != 32 {
        anyhow::bail!(
            "receipt_cov_id must be 64 hex characters (32 bytes), got {} bytes",
            rcid_bytes.len()
        );
    }
    let mut receipt_cov_id = [0u8; 32];
    receipt_cov_id.copy_from_slice(&rcid_bytes);

    // Build bracket_order_v4 redeemScript
    let redeem_script = contract::build_bracket_redeem_script(
        0, // entry_type = buy
        &pair_id,
        entry_price_num,
        entry_price_den,
        &tp_spk,
        MIN_UTXO_VALUE,
        &sl_spk,
        MIN_UTXO_VALUE,
        MIN_UTXO_VALUE,
        min_receipt_value,
        &receipt_cov_id,
        &owner_hash,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Bracket Order (bracket_order_v4)");
    println!("========================================");
    println!("Pair ID:        {}", pair_id_hex);
    println!("Entry Price:    {} ({:.6})", entry_price, entry_price.as_f64());
    println!("Take Profit:    {} ({:.6})", tp_price, tp_price.as_f64());
    println!("Stop Loss:      {} ({:.6})", sl_price, sl_price.as_f64());
    println!(
        "Amount:         {} sompi ({:.8} KAS)",
        amount,
        amount as f64 / 1e8
    );
    if min_receipt_value > 0 {
        println!("Min Receipt:    {} sompi", min_receipt_value);
    }
    println!("Owner:          {}", wallet.pubkey_hex());
    println!("Owner Hash:     {}", hex::encode(owner_hash));
    println!();
    println!("bracket_order_v4 RS: {} bytes", redeem_script.len());
    println!("TP oco_pair RS:      {} bytes", tp_rs.len());
    println!("SL oco_pair RS:      {} bytes", sl_rs.len());
    println!("Receipt Cov ID:      {}", receipt_cov_id_hex);
    println!("P2SH SPK:            {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch UTXOs
    info!(pair_id = %pair_id_hex, amount = amount, "deploying bracket_order_v4");
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

    // Build transaction (version 0)
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

    // Output 0: bracket_order_v4 P2SH
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

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
        if change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
        }
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

    let (sigscript, _actual_fee) = if exact_fee != est_fee {
        if tx.outputs.len() > 1 {
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
            let sighash = compute_sighash(&tx, 0)?;
            let signature = signing::schnorr_sign(&privkey, &sighash)?;
            (signing::build_p2pk_sigscript(&signature), exact_fee)
        } else {
            (sigscripts_vec.into_iter().next().unwrap(), exact_fee)
        }
    } else {
        (sigscripts_vec.into_iter().next().unwrap(), est_fee)
    };

    // Submit
    let payload = to_rpc_payload(&tx, &[sigscript]);
    println!("Submitting bracket deploy transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! bracket_order_v4 deployed.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Order: {}:0 ({} sompi)", tx_id, amount);
    println!("RS:    {} ({}B)", hex::encode(&redeem_script), redeem_script.len());
    println!();
    println!("Cancel command:");
    println!("  kob-cli bracket cancel \\");
    println!("    --order {}:0 \\", tx_id);
    println!("    --rs {}", hex::encode(&redeem_script));

    Ok(())
}

/// Bracket order parameters (for legacy `run` command validation).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API: used by legacy bracket deploy
pub struct BracketParams {
    pub pair_id: [u8; 32],
    pub pair_id_hex: String,
    pub entry_price: Price,
    pub tp_price: Price,
    pub sl_price: Price,
    pub amount: u64,
    pub min_receipt_value: u64,
}

impl BracketParams {
    /// Validate the bracket order parameters.
    #[allow(dead_code)] // Public API: used by legacy bracket deploy
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.amount < MIN_UTXO_VALUE {
            anyhow::bail!(
                "Amount {} sompi too small (need >= {})",
                self.amount,
                MIN_UTXO_VALUE
            );
        }

        let entry_f = self.entry_price.as_f64();
        let tp_f = self.tp_price.as_f64();
        let sl_f = self.sl_price.as_f64();

        if tp_f <= entry_f {
            println!(
                "  WARNING: Take-profit price ({:.6}) <= entry price ({:.6})",
                tp_f, entry_f
            );
        }
        if sl_f >= entry_f {
            println!(
                "  WARNING: Stop-loss price ({:.6}) >= entry price ({:.6})",
                sl_f, entry_f
            );
        }
        if sl_f >= tp_f {
            anyhow::bail!(
                "Stop-loss price ({:.6}) must be < take-profit price ({:.6})",
                sl_f,
                tp_f
            );
        }

        if self.min_receipt_value > 0 && self.min_receipt_value < MIN_UTXO_VALUE {
            anyhow::bail!(
                "min_receipt_value {} sompi below MIN_UTXO_VALUE {}",
                self.min_receipt_value,
                MIN_UTXO_VALUE
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bracket_v4_rs_length() {
        let token_cov_id = [0x01u8; 32];
        let tp_spk = [0xAA; 37];
        let sl_spk = [0xBB; 37];
        let receipt_cov_id = [0xCC; 32];
        let owner_hash = [0xDD; 32];

        let rs = contract::build_bracket_redeem_script(
            0, &token_cov_id, 1, 2,
            &tp_spk, 5_000_000,
            &sl_spk, 5_000_000,
            100_000,
            5_000_000,
            &receipt_cov_id,
            &owner_hash,
        ).unwrap();
        assert_eq!(rs.len(), 380, "bracket_order_v4 RS must be 380 bytes");
    }

    #[test]
    fn bracket_v4_fill_sigscript_below_threshold() {
        let rs = vec![0u8; 380]; // dummy 380B RS
        let ss = contract::build_bracket_fill_sigscript(&rs);
        // Fill: [Op1(1B)] + [pushData(380B) = 3+380 = 383B] = 384B
        assert_eq!(ss.len(), 384, "fill sigscript must be 384 bytes");
        assert!(ss.len() < 420, "fill sigscript must be < 420 threshold");
    }

    #[test]
    fn bracket_v4_cancel_sigscript_above_threshold() {
        let sig = [0xAA; 64];
        let pk = [0xBB; 32];
        let rs = vec![0u8; 380]; // dummy 380B RS
        let ss = contract::build_bracket_cancel_sigscript(&sig, &pk, &rs);
        // Cancel: [Op0(1B)] + [pushData(sig65) = 66B] + [pushData(pk32) = 33B]
        //         + [pushData(RS380) = 3+380 = 383B] = 1+66+33+383 = 483B
        assert_eq!(ss.len(), 483, "cancel sigscript must be 483 bytes");
        assert!(ss.len() >= 420, "cancel sigscript must be >= 420 threshold");
    }

    #[test]
    fn bracket_params_validate_valid() {
        let params = BracketParams {
            pair_id: [0x01; 32],
            pair_id_hex: "01".repeat(32),
            entry_price: Price::new(1000, 1).unwrap(),
            tp_price: Price::new(1200, 1).unwrap(),
            sl_price: Price::new(800, 1).unwrap(),
            amount: 30_000_000,
            min_receipt_value: 0,
        };
        assert!(params.validate().is_ok());
    }

    #[test]
    fn bracket_params_validate_sl_above_tp() {
        let params = BracketParams {
            pair_id: [0x01; 32],
            pair_id_hex: "01".repeat(32),
            entry_price: Price::new(1000, 1).unwrap(),
            tp_price: Price::new(800, 1).unwrap(),
            sl_price: Price::new(1200, 1).unwrap(), // SL > TP
            amount: 30_000_000,
            min_receipt_value: 0,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn bracket_v4_tp_sl_spk_extraction() {
        // Build a real RS and verify we can extract TP/SL SPK at the correct offsets
        let token_cov_id = [0x01u8; 32];
        let mut tp_spk = [0u8; 37];
        tp_spk[0..2].copy_from_slice(&0u16.to_le_bytes());
        tp_spk[2] = 0xaa; tp_spk[3] = 0x20;
        for i in 4..36 { tp_spk[i] = 0xAA; }
        tp_spk[36] = 0x87;

        let mut sl_spk = [0u8; 37];
        sl_spk[0..2].copy_from_slice(&0u16.to_le_bytes());
        sl_spk[2] = 0xaa; sl_spk[3] = 0x20;
        for i in 4..36 { sl_spk[i] = 0xBB; }
        sl_spk[36] = 0x87;

        let receipt_cov_id = [0xCC; 32];
        let owner_hash = [0xDD; 32];

        let rs = contract::build_bracket_redeem_script(
            0, &token_cov_id, 1, 2,
            &tp_spk, 5_000_000,
            &sl_spk, 5_000_000,
            100_000, 5_000_000,
            &receipt_cov_id, &owner_hash,
        ).unwrap();

        // Verify TP SPK extraction at offset 61..98
        assert_eq!(&rs[61..98], &tp_spk[..], "TP SPK must be at RS[61..98]");

        // Verify SL SPK extraction at offset 108..145
        assert_eq!(&rs[108..145], &sl_spk[..], "SL SPK must be at RS[108..145]");
    }
}
