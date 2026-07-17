//! `kob-cli bracket` -- Deploy, fill, and cancel bracket_order_v6 contracts.
//!
//! A bracket order is a single UTXO (bracket_order_v6) that encodes:
//! - Entry price (buy or sell)
//! - Single oco_sell exit order SPK + min value (encodes both TP and SL paths)
//! - Receipt covenant ID for fill verification
//! - Trade output SPK hash (N5: prevents matcher from stealing traded value)
//! - Owner hash for cancel authorization
//!
//! bracket_order_v6 RS = 224B state + 141B body = 365B
//!
//! Fill TX layout (3 inputs, 3+ outputs):
//!   input[0]: bracket_order_v6 (sigscript: [Op1][pushData(RS 365B)] = 369B < 400)
//!   input[1]: P2PK funding/payment UTXO
//!   input[2]: trade_receipt UTXO (must have correct covenant_id AND value >= min)
//!   output[0]: seller KAS (for sell entry) or buyer KAS (for buy entry)
//!   output[1]: buyer tokens (for buy entry) or seller tokens (for sell entry)
//!   output[2]: oco_sell P2SH (single UTXO with TP + SL paths)
//!   output[3+]: change (optional)
//!
//! Cancel TX layout (2 inputs, 1 output):
//!   input[0]: bracket_order_v6 (sigscript: [Op0][sig+type 65B][pk 32B][pushData(RS)] = 468B >= 400)
//!   input[1]: fee UTXO (P2PK, signed)
//!   output[0]: recovered funds to wallet
//!
//! Dispatch boundary: 400 (fill < 400, cancel >= 400)

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
    /// Deploy a bracket_order_v6 (single UTXO with entry + oco_sell exit SPK).
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

        /// OCO sell P2SH SPK (hex, 74 chars = 37 bytes: version u16LE + P2SH script).
        /// The full scriptPublicKey bytes of the single oco_sell exit contract
        /// that encodes both TP and SL paths.
        #[arg(long)]
        oco_spk: String,

        /// Minimum value for the oco_sell output (sompi).
        #[arg(long)]
        oco_min_value: u64,

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

    /// Fill a bracket_order_v6 (execute the entry trade).
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

        /// OCO sell output value (sompi, must be >= oco_min_value in contract).
        #[arg(long)]
        oco_value: u64,

        /// Receipt redeemScript (hex). Required to spend the receipt P2SH
        /// input. The receipt contract evaluates its script, so the full
        /// redeemScript must be provided as `[pushData(receipt_RS)]`.
        #[arg(long)]
        receipt_rs: String,

        /// Fee input outpoint (txid:index). Auto-selected from wallet if omitted.
        #[arg(long)]
        fee_input: Option<String>,

        /// Matcher token UTXO outpoint (txid:index) supplying the tokens for
        /// a v18 BUY-entry fill (delivery output[1] + OCO spawn output[2]
        /// both carry the token CovenantBinding authorized by this input).
        /// Required for v18 buy-entry fills; ignored for v1 and sell entries.
        #[arg(long)]
        token_utxo: Option<String>,
    },

    /// Cancel a bracket_order_v6 (owner signature).
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

/// Deploy a bracket_order_v6 contract as a single P2SH UTXO.
#[allow(clippy::too_many_arguments)]
pub async fn deploy_bracket_v4(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    token_hex: &str,
    entry_type: u64,
    entry_num: u64,
    entry_den: u64,
    oco_spk_hex: &str,
    oco_min_value: u64,
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

    // Parse OCO sell SPK (37 bytes: version u16LE + 35-byte P2SH script)
    let oco_spk_bytes = hex::decode(oco_spk_hex)?;
    if oco_spk_bytes.len() != 37 {
        anyhow::bail!("Invalid oco_sell script: expected 74 hex characters (37 bytes), got {} characters. \
             Provide the version + P2SH script of the oco_sell exit order.", oco_spk_hex.len());
    }
    let mut oco_spk = [0u8; 37];
    oco_spk.copy_from_slice(&oco_spk_bytes);

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

    // Compute trade_spk_hash: the SPK that must appear on the trade output
    // (output[0] for sell, output[1] for buy), preventing a malicious matcher
    // from redirecting funds.
    // - BUY entry: the trade output is a TOKEN delivery -> commit the owner's
    //   token_unit P2SH SPK (KCC20 delivery re-wrap; the fill lands a
    //   spendable token_unit, not a bare P2PK output).
    // - SELL entry: the trade output is KAS proceeds -> keep the raw P2PK SPK.
    let trade_spk_hash = if entry_type == 0 {
        contract::compute_token_unit_spk_hash(&pubkey)
    } else {
        // P2PK SPK = version(2B) + OP_DATA_32(1B) + pubkey(32B) + OP_CHECKSIG(1B) = 36B
        let mut wallet_spk_for_hash = Vec::with_capacity(36);
        wallet_spk_for_hash.extend_from_slice(&0u16.to_le_bytes()); // version 0
        wallet_spk_for_hash.push(0x20); // push 32 bytes
        wallet_spk_for_hash.extend_from_slice(&pubkey);
        wallet_spk_for_hash.push(0xac); // OpCheckSig
        blake2b_256(&wallet_spk_for_hash)
    };

    // Build v18 bracket redeemScript (372B: 224B state identical to v1 +
    // v18 body — receipt-gated fill with CSV(50) exposure delay; the OCO
    // spawn must carry genuine token covenant on a buy entry).
    let redeem_script = contract::spot::bracket::build_bracket_redeem_script(
        entry_type,
        &token_cov_id,
        entry_num,
        entry_den,
        &oco_spk,
        oco_min_value,
        min_fill,
        0, // min_receipt_value (receipt value check is secondary to cov_id check)
        &receipt_cov_id,
        &trade_spk_hash,
        &owner_hash,
    )?;
    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy bracket v18");
    println!("========================");
    println!("Token:           {}", token_hex);
    println!("Entry Type:      {} ({})", entry_type, if entry_type == 0 { "buy" } else { "sell" });
    println!("Entry Price:     {}/{} ({:.6})", entry_num, entry_den, entry_num as f64 / entry_den as f64);
    println!("OCO SPK:         {}...{}", &oco_spk_hex[..16], &oco_spk_hex[oco_spk_hex.len()-8..]);
    println!("OCO Min Value:   {} sompi", oco_min_value);
    println!("Min Fill:        {}", min_fill);
    println!("Receipt Cov ID:  {}...", &receipt_cov_id_hex[..16]);
    println!("Trade SPK Hash:  {}", hex::encode(trade_spk_hash));
    println!("Amount:          {} sompi ({:.8} KAS)", amount, amount as f64 / 1e8);
    println!("Owner:           {}", wallet.pubkey_hex());
    println!("Owner Hash:      {}", hex::encode(owner_hash));
    println!();
    println!("RedeemScript:    {} bytes (bracket v18)", redeem_script.len());
    println!("RS hex:          {}", hex::encode(&redeem_script));
    println!("P2SH SPK:        {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch UTXOs
    info!(amount = amount, "deploying bracket_order_v6");
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

    // Output 0: bracket_order_v6 P2SH
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
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

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
    println!("SUCCESS! bracket_order_v6 deployed.");
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
    println!("    --oco-value {}", oco_min_value);
    println!();
    println!("Cancel command:");
    println!("  kob-cli bracket cancel \\");
    println!("    --order {}:0 \\", tx_id);
    println!("    --rs {}", hex::encode(&redeem_script));

    Ok(())
}

// bracket fill

/// Fill a bracket_order_v6 (execute the entry trade).
///
/// Fill TX is version 0 (no covenant binding on the fill TX itself).
/// The bracket contract verifies:
/// - output[2].SPK == oco_spk and output[2].value >= oco_min_value
/// - input[2].value >= min_receipt_value
/// - input[2].covenant_id == receipt_cov_id (N4 check)
/// - blake2b(output[0].spk) == trade_spk_hash for SELL (N5 check)
/// - blake2b(output[1].spk) == trade_spk_hash for BUY (N5 check)
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
    oco_value: u64,
    receipt_rs_hex: &str,
    fee_input_str: Option<&str>,
    token_utxo_str: Option<&str>,
) -> anyhow::Result<()> {
    // Parse redeemScript: v18 only (372B).
    let redeem_script = hex::decode(rs_hex)?;
    if redeem_script.len() == contract::spot::bracket::BRACKET_RS_SIZE {
        return fill_bracket_inner(
            wallet_path, node_url, network,
            order_str, order_value_override, &redeem_script,
            receipt_str, receipt_value_override,
            seller_kas, buyer_tokens, oco_value,
            receipt_rs_hex, fee_input_str, token_utxo_str,
        ).await;
    }

    anyhow::bail!(
        "bracket RS must be {} bytes (v18); pre-v18 brackets were removed in Stage E (got {})",
        contract::spot::bracket::BRACKET_RS_SIZE,
        redeem_script.len()
    );
}

/// Fill a v18 bracket (372B RS).
///
/// v18 differences vs the v1 fill:
///   - TX version 1 with covenant bindings: on a BUY entry, output[1]
///     (token delivery) and output[2] (OCO spawn) must hold GENUINE tokens
///     of the bracket's `token_cov_id`, authorized by the matcher's token
///     input at input[3] (`--token-utxo`); on a SELL entry the bracket's own
///     token input authorizes the F4 conservation output at auth slot 0.
///   - CSV(50) exposure gate: the bracket input uses sequence 50 and the TX
///     lock_time is 50 (fill-family parity with every other v18 contract).
///   - Fill sigscript `[Op1][pushData(RS)]` via the v18 builder.
///
/// Layout (buy entry):
///   inputs:  [0] bracket (KAS, seq 50), [1] fee P2PK, [2] receipt,
///            [3] matcher token UTXO (token_unit P2SH)
///   outputs: [0] matcher KAS (= seller_kas), [1] token delivery -> trade SPK
///            (cov auth 3), [2] OCO spawn (cov auth 3), [3] token change ->
///            token_unit (cov auth 3)?, [4] KAS change?
#[allow(clippy::too_many_arguments)]
async fn fill_bracket_inner(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    order_str: &str,
    order_value_override: Option<u64>,
    redeem_script: &[u8],
    receipt_str: &str,
    receipt_value_override: Option<u64>,
    seller_kas: u64,
    buyer_tokens: u64,
    oco_value: u64,
    receipt_rs_hex: &str,
    fee_input_str: Option<&str>,
    token_utxo_str: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let order_outpoint = Outpoint::parse(order_str)?;
    let receipt_outpoint = Outpoint::parse(receipt_str)?;
    let p2sh = build_p2sh(redeem_script);

    // State fields (224B layout identical to v1):
    //   [0x08][entry_type 8B] = 0..9, [0x20][tcid 32B] = 9..42,
    //   [0x25][oco_spk 37B] at 60..98.
    let entry_type = u64::from_le_bytes(redeem_script[1..9].try_into().unwrap());
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&redeem_script[10..42]);
    let token_cov_hex = hex::encode(token_cov_id);
    let oco_spk_version = u16::from_le_bytes([redeem_script[61], redeem_script[62]]);
    let oco_spk_script = &redeem_script[63..98];
    let is_buy_entry = entry_type == 0;

    println!("Fill bracket v18 ({} entry)", if is_buy_entry { "buy" } else { "sell" });
    println!("=============================");
    println!("Order:          {}", order_outpoint);
    println!("Receipt:        {}", receipt_outpoint);
    println!("Token:          {}", token_cov_hex);
    println!("RS:             {} bytes (v18)", redeem_script.len());
    println!();
    println!("Output layout:");
    println!("  [0] seller KAS:   {} sompi", seller_kas);
    println!("  [1] buyer tokens: {} sompi (token covenant)", buyer_tokens);
    println!("  [2] oco spawn:    {} sompi{}", oco_value, if is_buy_entry { " (token covenant)" } else { "" });
    println!();

    info!(order = %order_outpoint, "filling bracket v18");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Resolve order value.
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        let p2sh_addr = p2sh_to_address(&p2sh.script(), network.address_prefix());
        let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_addr]).await?;
        order_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == order_outpoint.transaction_id
                    && u.outpoint.index == order_outpoint.index
            })
            .map(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!(
                "Bracket order {} not found. It may be spent or use --order-value.",
                order_outpoint
            ))?
    };
    println!("Order Value:    {} sompi", order_value);

    // Resolve receipt UTXO details via the receipt P2SH address (derived from
    // --receipt-rs). This avoids `getTransaction`, which some public nodes do
    // not serve, and doubles as an unspent-ness check.
    let (receipt_value, receipt_spk_version, receipt_spk_script) = {
        let receipt_rs_probe = hex::decode(receipt_rs_hex)?;
        if receipt_rs_probe.is_empty() {
            anyhow::bail!("--receipt-rs cannot be empty.");
        }
        let rp2sh = build_p2sh(&receipt_rs_probe);
        let raddr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &rp2sh.script()[2..34],
        );
        let rutxos = rpc.get_utxos_by_addresses(&[&raddr]).await?;
        let ru = rutxos
            .iter()
            .find(|u| u.outpoint.transaction_id == receipt_outpoint.transaction_id
                && u.outpoint.index == receipt_outpoint.index)
            .ok_or_else(|| anyhow::anyhow!(
                "Receipt UTXO {} not found at the P2SH of --receipt-rs (spent, unconfirmed, or wrong RS).",
                receipt_outpoint
            ))?;
        let value = receipt_value_override.unwrap_or(ru.utxo_entry.amount);
        (
            value,
            ru.utxo_entry.script_public_key.version,
            hex::decode(&ru.utxo_entry.script_public_key.script)?,
        )
    };
    println!("Receipt Value:  {} sompi", receipt_value);

    // Matcher token UTXO (buy entry): supplies delivery + OCO spawn tokens.
    let token_unit_rs = kob_core::contract::build_token_unit_redeem_script(&pubkey);
    let token_unit_p2sh = build_p2sh(&token_unit_rs);
    let token_utxo = if is_buy_entry {
        let token_op_str = token_utxo_str.ok_or_else(|| anyhow::anyhow!(
            "--token-utxo is required for a v18 buy-entry fill (the matcher must \
             supply the tokens for the delivery and the OCO spawn)."
        ))?;
        let token_op = Outpoint::parse(token_op_str)?;
        let unit_addr = crate::cancel::kaspa_address_encode(
            network.address_prefix(), 8, &token_unit_p2sh.script()[2..34],
        );
        let token_utxos = rpc.get_utxos_by_addresses(&[&unit_addr]).await?;
        let u = token_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == token_op.transaction_id
                && u.outpoint.index == token_op.index)
            .ok_or_else(|| anyhow::anyhow!(
                "Token UTXO {} not found at this wallet's token_unit P2SH address.",
                token_op_str
            ))?;
        let need = buyer_tokens + oco_value;
        if u.utxo_entry.amount < need {
            anyhow::bail!(
                "Token UTXO holds {} token sompi but the fill needs {} (delivery {} + OCO {}).",
                u.utxo_entry.amount, need, buyer_tokens, oco_value,
            );
        }
        println!("Token UTXO:     {}:{} ({} token sompi)", &u.outpoint.transaction_id[..16], u.outpoint.index, u.utxo_entry.amount);
        Some(u.clone())
    } else {
        None
    };

    // Fee UTXO.
    let num_inputs = if is_buy_entry { 4 } else { 3 };
    let est_fee_budget = estimate_compute_mass(num_inputs, 5, 0) + 500;
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(fi) = fee_input_str {
        let fi_outpoint = Outpoint::parse(fi)?;
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == fi_outpoint.transaction_id
                && u.outpoint.index == fi_outpoint.index)
            .ok_or_else(|| anyhow::anyhow!("The specified fee input {} was not found in the wallet.", fi))?
    } else {
        wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee_budget + MIN_UTXO_VALUE)
            .ok_or_else(|| anyhow::anyhow!(
                "No P2PK UTXO with >= {} sompi for the fee input.",
                est_fee_budget + MIN_UTXO_VALUE
            ))?
    };
    println!("Fee UTXO:       {}:{} ({} sompi)", fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount);

    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let wallet_spk_version = fee_utxo.utxo_entry.script_public_key.version;

    // --- Build the fill TX (version 1, lock_time 50 for the CSV gate) ---
    let mut tx = Transaction::new(1);
    tx.lock_time = 50;

    // Input 0: bracket (covenant spend, CSV(50) -> sequence 50, sigOp 0).
    tx.inputs.push(TxInput {
        prev_tx_id: order_outpoint.transaction_id.clone(),
        prev_index: order_outpoint.index,
        sequence: 50,
        sig_op_count: 0,
        script_version: p2sh.version,
        script_bytes: p2sh.script().to_vec(),
        value: order_value,
    });
    // Input 1: fee P2PK.
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: wallet_spk_version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_utxo.utxo_entry.amount,
    });
    // Input 2: receipt (contract-pinned index; recipient signature).
    tx.inputs.push(TxInput {
        prev_tx_id: receipt_outpoint.transaction_id.clone(),
        prev_index: receipt_outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: receipt_spk_version,
        script_bytes: receipt_spk_script,
        value: receipt_value,
    });
    // Input 3: matcher token UTXO (buy entry only).
    if let Some(ref tu) = token_utxo {
        tx.inputs.push(TxInput {
            prev_tx_id: tu.outpoint.transaction_id.clone(),
            prev_index: tu.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: tu.utxo_entry.script_public_key.version,
            script_bytes: tu.script_bytes(),
            value: tu.utxo_entry.amount,
        });
    }

    let token_hash = kob_core::compat::parse_hash(&token_cov_hex)
        .map_err(|e| anyhow::anyhow!("token covenant hash: {e:?}"))?;

    // Outputs.
    // [0] seller/matcher KAS (buy entry: the matcher's KAS proceeds; sell
    //     entry: blake2b(spk) must equal trade_spk_hash -> this wallet).
    tx.outputs.push(TxOutput::new(seller_kas, wallet_spk_version, wallet_spk.clone(), None));
    if is_buy_entry {
        // [1] token delivery -> trade SPK (this wallet, N5) + token covenant
        //     authorized by the token input (index 3).
        tx.outputs.push(TxOutput::new(
            buyer_tokens, wallet_spk_version, wallet_spk.clone(),
            Some(kob_core::tx::CovenantBinding::new(3, token_hash)),
        ));
        // [2] OCO spawn: byte-exact oco_spk, genuine tokens.
        tx.outputs.push(TxOutput::new(
            oco_value, oco_spk_version, oco_spk_script.to_vec(),
            Some(kob_core::tx::CovenantBinding::new(3, token_hash)),
        ));
        // [3] token change back to the token_unit P2SH (same covenant).
        let token_in = token_utxo.as_ref().map(|u| u.utxo_entry.amount).unwrap_or(0);
        let token_change = token_in - (buyer_tokens + oco_value);
        if token_change >= MIN_UTXO_VALUE {
            tx.outputs.push(TxOutput::new(
                token_change, token_unit_p2sh.version, token_unit_p2sh.script().to_vec(),
                Some(kob_core::tx::CovenantBinding::new(3, token_hash)),
            ));
        } else if token_change > 0 {
            // Dust token change: fold into the delivery (contract check is >=).
            tx.outputs[1].value += token_change;
        }
    } else {
        // Sell entry: F4 conserves the bracket's own tokens to its auth
        // slot 0 -> the FIRST output bound to input 0 must hold >= token_in.
        let delivery = buyer_tokens.max(order_value);
        tx.outputs.push(TxOutput::new(
            delivery, wallet_spk_version, wallet_spk.clone(),
            Some(kob_core::tx::CovenantBinding::new(0, token_hash)),
        ));
        // [2] OCO spawn (sell entry: re-buy leg, plain KAS).
        tx.outputs.push(TxOutput::new(oco_value, oco_spk_version, oco_spk_script.to_vec(), None));
    }

    // KAS accounting: kas_in = bracket (buy entry) + fee utxo; kas_out =
    // seller_kas (+ oco_value on a sell entry). Token sompi conserves
    // separately through the covenant outputs.
    let kas_in = if is_buy_entry { order_value } else { 0 } + fee_utxo.utxo_entry.amount;
    let kas_out = seller_kas + if is_buy_entry { 0 } else { oco_value };
    if kas_in < kas_out + est_fee_budget {
        anyhow::bail!(
            "Insufficient KAS: inputs {} < outputs {} + fee budget {}",
            kas_in, kas_out, est_fee_budget
        );
    }
    let kas_change = kas_in - kas_out - est_fee_budget;
    let kas_change_idx = if kas_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(kas_change, wallet_spk_version, wallet_spk.clone(), None));
        Some(tx.outputs.len() - 1)
    } else {
        None
    };

    // Sign inputs 1..n (input 0 is data-only).
    let sign_all = |tx: &Transaction| -> anyhow::Result<Vec<Vec<u8>>> {
        let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(tx.inputs.len());
        // [0] bracket fill sigscript (v18 builder; no signature).
        sigs.push(contract::spot::bracket::build_bracket_fill_sigscript(redeem_script));
        // [1] fee P2PK.
        let sh1 = compute_sighash(tx, 1)?;
        sigs.push(signing::build_p2pk_sigscript(&signing::schnorr_sign(&privkey, &sh1)?));
        // [2] receipt consume (recipient signature).
        let receipt_rs_bytes = hex::decode(receipt_rs_hex)?;
        if receipt_rs_bytes.is_empty() {
            anyhow::bail!("--receipt-rs cannot be empty.");
        }
        let sh2 = compute_sighash(tx, 2)?;
        sigs.push(contract::build_receipt_consume_sigscript(
            &signing::schnorr_sign(&privkey, &sh2)?, &pubkey, &receipt_rs_bytes,
        ));
        // [3] token_unit (owner signature) — buy entry only.
        if tx.inputs.len() > 3 {
            let sh3 = compute_sighash(tx, 3)?;
            sigs.push(kob_core::contract::build_token_unit_sigscript(
                &signing::schnorr_sign(&privkey, &sh3)?, &token_unit_rs,
            ));
        }
        Ok(sigs)
    };

    // Phase 1 sign -> exact fee -> adjust change -> re-sign.
    let sigscripts = sign_all(&tx)?;
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);
    let sigscripts = if exact_fee != est_fee_budget {
        if let Some(ci) = kas_change_idx {
            let new_change = kas_in - kas_out - exact_fee;
            if new_change >= MIN_UTXO_VALUE {
                tx.outputs[ci].value = new_change;
            } else {
                tx.outputs.remove(ci);
            }
        }
        sign_all(&tx)?
    } else {
        sigscripts
    };

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("Fill TX would be rejected by node: {}", e);
    }

    let fill_exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
    println!("Compute mass:   {:>9} (exact, post-sign)", fill_exact_compute);
    println!("Miner fee:      {:>9} sompi", exact_fee);
    println!();

    // Submit.
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting v18 bracket fill transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! v18 bracket filled.");
    println!("TXID: {}", tx_id);
    println!();
    println!("  [0] seller KAS:    {} sompi", tx.outputs[0].value);
    println!("  [1] token delivery: {} sompi (covenant-bound)", tx.outputs[1].value);
    println!("  [2] OCO spawn:     {} sompi at {}:2 — LIVE v18 OCO done-leg", oco_value, tx_id);

    Ok(())
}

// bracket cancel

/// Cancel a bracket_order_v6 (owner signature).
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

    // Parse redeemScript (365B = v1, 372B = v18)
    let redeem_script = hex::decode(rs_hex)?;
    if redeem_script.len() != contract::spot::bracket::BRACKET_RS_SIZE {
        anyhow::bail!(
            "bracket RS must be {} bytes (v18); pre-v18 brackets were removed in Stage E (got {})",
            contract::spot::bracket::BRACKET_RS_SIZE,
            redeem_script.len()
        );
    }
    let p2sh = build_p2sh(&redeem_script);

    println!("Cancel bracket (v18)");
    println!("========================");
    println!("Order:         {}", order_outpoint);
    println!("RS:            {} bytes", redeem_script.len());
    println!("P2SH SPK:      {}", hex::encode(&p2sh.script()));
    println!("Owner:         {}", wallet.pubkey_hex());
    println!();

    // Connect
    info!(order = %order_outpoint, "cancelling bracket_order_v6");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Resolve order value (and covenant binding: a SELL-entry bracket's
    // escrow is tokens -- the refund must stay a token_unit, not be burned
    // into plain KAS).
    let (order_value, order_cov_id): (u64, Option<String>) = if let Some(v) = order_value_override {
        (v, None)
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
        (utxo.utxo_entry.amount, utxo.utxo_entry.covenant_id.clone())
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

    // Build cancel TX (version 1 when the token escrow's binding is carried
    // into a token_unit refund -- D2 refund re-wrap; version 0 otherwise)
    let mut tx = Transaction::new(if order_cov_id.is_some() { 1 } else { 0 });

    // Input 0: bracket_order_v6 UTXO (sigOpCount = 1 for cancel path -- has CheckSigVerify)
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

    // Outputs. Token-escrow bracket (sell entry): output 0 = token_unit
    // refund (fixed at order_value, binding preserved), output 1 = fee
    // change. KAS-escrow bracket (buy entry): single output 0 to the wallet.
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    let tentative_output = total_in.saturating_sub(est_fee_budget);
    let fee_change_idx: usize = if let Some(ref cov_hex) = order_cov_id {
        let token_unit_spk = contract::build_token_unit_p2sh_spk(&pubkey);
        let binding = kob_core::compat::covenant_binding_from_hex(0, cov_hex)
            .map_err(|e| anyhow::anyhow!("invalid covenant id on bracket UTXO: {}", e))?;
        println!("Token refund:  {} sompi -> token_unit P2SH {}", order_value, hex::encode(token_unit_spk.script()));
        tx.outputs.push(TxOutput::new(
            order_value,
            token_unit_spk.version,
            token_unit_spk.script().to_vec(),
            Some(binding),
        ));
        tx.outputs.push(TxOutput::new(
            fee_utxo.utxo_entry.amount.saturating_sub(est_fee_budget),
            fee_utxo.utxo_entry.script_public_key.version,
            wallet_spk,
            None,
        ));
        1
    } else {
        tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));
        0
    };

    // Phase 1: converge fee on the fee-change slot
    let (est_fee, _) = converge_fee(&mut tx, total_in, fee_change_idx, 0);

    // Sign input 0 (cancel path signature)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;

    // Build cancel sigscript.
    // v1:  [Op0][pushData(sig+type)][pushData(pk)][pushData(RS)]
    // v18: [pushData(sig+type)][pushData(pk)][Op0][pushData(RS)] (selector
    //      sits directly below the state, v17/v18 convention)
    let cancel_sigscript =
        contract::spot::bracket::build_bracket_cancel_sigscript(&sig_0, &pubkey, &redeem_script);

    println!("Cancel SigScript: {} bytes (>= 400: {})", cancel_sigscript.len(), cancel_sigscript.len() >= 400);

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts_cancel = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts_cancel);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

    let (cancel_sigscript, fee_sigscript, actual_fee) = if exact_fee != est_fee {
        // Fixed outputs (the token refund, when present) keep their value;
        // only the fee-change slot absorbs the fee delta.
        let fixed_sum: u64 = tx
            .outputs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != fee_change_idx)
            .map(|(_, o)| o.value)
            .sum();
        let output_value = total_in.saturating_sub(fixed_sum + exact_fee);
        tx.outputs[fee_change_idx].value = output_value;

        // Re-sign with updated output value
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let cancel_sigscript =
            contract::spot::bracket::build_bracket_cancel_sigscript(&sig_0, &pubkey, &redeem_script);
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

        (cancel_sigscript, fee_sigscript, exact_fee)
    } else {
        (cancel_sigscript, fee_sigscript, est_fee)
    };

    let output_value = tx.outputs[fee_change_idx].value;
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
    if order_cov_id.is_some() {
        println!(
            "Refunded {} sompi of tokens to the wallet's token_unit P2SH ({}:0) and {} sompi KAS change.",
            order_value, tx_id, output_value
        );
    } else {
        println!("Recovered {} sompi to wallet.", output_value);
    }

    Ok(())
}

// Legacy bracket deploy (top-level `kob-cli bracket` command) -- retained
// for backward compat but now calls deploy_bracket_v4_simple.

/// Legacy bracket deploy (simple: builds TP/SL oco_sell RS internally).
///
/// This is the backward-compatible entry point for the top-level `bracket`
/// command. It constructs the oco_sell redeemScript from the provided
/// TP/SL prices, then deploys a bracket_order_v6 with a single oco_sell
/// output at output[2].
///
/// Because the receipt_cov_id depends on the receipt's genesis TX (which
/// doesn't exist yet at bracket deploy time), this command requires the
/// receipt to already be deployed and the covenant ID to be known.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    pair_id_hex: &str,
    side: &str,
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
    let entry_type: u64 = match side {
        "buy" => 0,
        "sell" => 1,
        _ => anyhow::bail!("Invalid side '{}'. Use 'buy' or 'sell'.", side),
    };
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

    // Build oco_sell redeemScript with TP/SL prices.
    // Single UTXO: spending one path naturally cancels the other.
    let seller_spk_hash = kob_core::p2sh::compute_p2pk_spk_hash(&pubkey);

    // v18 OCO done-leg: both TP and SL branches are sweep-eligible via the
    // canonical price attestation, so the spawned exit order settles under
    // the normal v18 planners with no special-casing.
    let oco_sell_rs = contract::spot::oco::build_oco_sell_redeem_script(
        tp_price_num,
        tp_price_den,
        MIN_UTXO_VALUE,     // min_fill_tp
        sl_price_num,
        sl_price_den,
        MIN_UTXO_VALUE,     // min_fill_sl
        &owner_hash,
        &seller_spk_hash,
        &contract::compute_token_unit_spk_hash(&pubkey), // otspkh (E1 expire seat)
        crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS,
        0, // cancel_pending
        0, // expiry_daa (GTC)
    )?;

    let oco_sell_p2sh = build_p2sh(&oco_sell_rs);

    // Build oco_sell SPK (37 bytes: version u16LE + 35-byte P2SH script)
    let mut oco_spk = [0u8; 37];
    oco_spk[0..2].copy_from_slice(&oco_sell_p2sh.version.to_le_bytes());
    oco_spk[2..37].copy_from_slice(&oco_sell_p2sh.script());

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

    // Compute trade_spk_hash (N5 fix). BUY entry: the trade output is a TOKEN
    // delivery -> commit the owner's token_unit P2SH SPK (KCC20 delivery
    // re-wrap). SELL entry: KAS proceeds -> keep the raw P2PK SPK.
    let trade_spk_hash = if entry_type == 0 {
        contract::compute_token_unit_spk_hash(&pubkey)
    } else {
        let mut owner_spk = [0u8; 36];
        owner_spk[0..2].copy_from_slice(&0u16.to_le_bytes()); // version 0
        owner_spk[2] = 0x20; // push 32 bytes
        owner_spk[3..35].copy_from_slice(&pubkey);
        owner_spk[35] = 0xac; // OpCheckSig
        blake2b_256(&owner_spk)
    };

    // Build v18 bracket redeemScript (single v18 oco_sell at output[2])
    let redeem_script = contract::spot::bracket::build_bracket_redeem_script(
        entry_type,
        &pair_id,
        entry_price_num,
        entry_price_den,
        &oco_spk,
        MIN_UTXO_VALUE,
        MIN_UTXO_VALUE,
        min_receipt_value,
        &receipt_cov_id,
        &trade_spk_hash,
        &owner_hash,
    )?;

    let p2sh = build_p2sh(&redeem_script);

    println!("Deploy Bracket Order (v18)");
    println!("========================================");
    println!("Pair ID:        {}", pair_id_hex);
    println!("Side:           {}", side);
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
    println!("bracket v18 RS:      {} bytes", redeem_script.len());
    println!("oco_sell v18 RS:     {} bytes", oco_sell_rs.len());
    println!("Receipt Cov ID:      {}", receipt_cov_id_hex);
    println!("P2SH SPK:            {}", hex::encode(&p2sh.script()));
    println!();

    // Connect and fetch UTXOs
    info!(pair_id = %pair_id_hex, amount = amount, "deploying bracket_order_v6");
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

    // Output 0: bracket_order_v6 P2SH
    tx.outputs.push(TxOutput::new(amount, 0, p2sh.script().to_vec(), None));

    // TX payload: RS for engine L1 discovery (same as deploy_bracket_v4)
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
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass);

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
    println!("SUCCESS! bracket_order_v6 deployed.");
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
    fn bracket_rs_length_and_sigscripts() {
        let token_cov_id = [0x01u8; 32];
        let oco_spk = [0xAA; 37];
        let receipt_cov_id = [0xCC; 32];
        let trade_spk_hash = [0x11; 32];
        let owner_hash = [0xDD; 32];

        let rs = contract::spot::bracket::build_bracket_redeem_script(
            0, &token_cov_id, 1, 2,
            &oco_spk, 5_000_000,
            100_000,
            5_000_000,
            &receipt_cov_id,
            &trade_spk_hash,
            &owner_hash,
        ).unwrap();
        assert_eq!(
            rs.len(),
            contract::spot::bracket::BRACKET_RS_SIZE,
            "v18 bracket RS must be {} bytes",
            contract::spot::bracket::BRACKET_RS_SIZE,
        );
        assert_eq!(rs.len(), 372, "v18 bracket RS is 372 bytes (224B state + 148B body)");

        // Fill sigscript: [Op1][pushData(RS)] (selector dispatch, no sigLen
        // threshold in v18).
        let fill_ss = contract::spot::bracket::build_bracket_fill_sigscript(&rs);
        assert_eq!(fill_ss[0], 0x51, "fill selector is Op1");
        assert_eq!(fill_ss.len(), 1 + 3 + rs.len(), "Op1 + pushData2 header + RS");

        // Cancel sigscript: [sig+type][pk][Op0][RS] — selector below state.
        let cancel_ss = contract::spot::bracket::build_bracket_cancel_sigscript(
            &[0u8; 64], &[0u8; 32], &rs,
        );
        assert_eq!(cancel_ss[0] as usize, 65, "first push is sig+type (65B)");
        assert_eq!(cancel_ss[66] as usize, 32, "second push is pk (32B)");
        assert_eq!(cancel_ss[99], 0x00, "selector Op0 sits after pk, before RS");

        // State offsets identical to v1: entry_type at [1..9), tcid at
        // [10..42), oco_spk at [61..98) — what the CLI fill parser reads.
        assert_eq!(u64::from_le_bytes(rs[1..9].try_into().unwrap()), 0);
        assert_eq!(&rs[10..42], &token_cov_id);
        assert_eq!(&rs[61..98], &oco_spk);
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

}
