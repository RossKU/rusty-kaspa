//! `kob deploy ifd` / `kob deploy ifo` -- Deploy IFD (If Done) and IFO (If Done + OCO) orders.
//!
//! An IFD order couples two limit orders: when order A fills, order B is
//! automatically deployed as an extra output in the fill TX.
//!
//! An IFO order is the same concept but B is an OCO (One-Cancels-Other) pair:
//! take-profit + stop-loss.
//!
//! Workflow:
//!   1. CLI sends order params to Matcher's `/api/v1/ifd` (or `/api/v1/ifo`)
//!   2. Matcher pre-computes B's RS + P2SH and returns A's deploy address
//!      (with bspkh = B's SPK hash for buy->sell token flow)
//!   3. CLI deploys order A to L1 (standard deploy TX)
//!   4. Matcher detects A, links it to the IFD rule, and on A's fill adds B

use crate::deploy;
use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee};
use kob_core::tx::{to_rpc_payload, select_utxos_mass_aware, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint, UtxoEntry};
use kob_core::wallet::WalletContext;
use kob_core::MIN_UTXO_VALUE;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

// HTTP helper (stdlib-only, no reqwest)

/// POST JSON to a Matcher API endpoint and return the parsed response.
fn http_post_json(
    matcher_url: &str,
    api_path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let url_str = if !matcher_url.starts_with("http://") {
        format!("http://{}", matcher_url)
    } else {
        matcher_url.to_string()
    };
    let without_scheme = url_str.strip_prefix("http://").expect("url_str always has http:// prefix");
    let (host_port, _) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };
    let (host, port) = match host_port.find(':') {
        Some(idx) => (
            &host_port[..idx],
            host_port[idx + 1..].parse::<u16>().unwrap_or(80),
        ),
        None => (host_port, 80u16),
    };

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid Matcher address '{}': {}", addr, e))?,
        Duration::from_secs(5),
    )
    .map_err(|e| {
        anyhow::anyhow!("Could not connect to Matcher at {}: {}", matcher_url, e)
    })?;

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let body_str = serde_json::to_string(body)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        api_path,
        host_port,
        body_str.len(),
        body_str,
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let response_str = String::from_utf8_lossy(&response);

    let http_body = response_str
        .find("\r\n\r\n")
        .map(|idx| &response_str[idx + 4..])
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response from Matcher"))?;

    let status_line = response_str.lines().next().unwrap_or("");
    // Accept 2xx status codes
    let status_ok = status_line.contains("200") || status_line.contains("201");

    // Handle chunked encoding
    let body_final = if response_str.contains("Transfer-Encoding: chunked") {
        decode_chunked(http_body)?
    } else {
        http_body.to_string()
    };

    let parsed: serde_json::Value = serde_json::from_str(&body_final).map_err(|e| {
        anyhow::anyhow!("Failed to parse Matcher response: {}. Body: {}", e, &body_final[..body_final.len().min(200)])
    })?;

    if !status_ok {
        let err_msg = parsed["error"].as_str().unwrap_or(status_line);
        anyhow::bail!("Matcher rejected request: {}", err_msg);
    }

    Ok(parsed)
}

/// Decode HTTP chunked transfer encoding.
fn decode_chunked(body: &str) -> anyhow::Result<String> {
    let mut result = String::new();
    let mut remaining = body;
    loop {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }
        let line_end = remaining.find("\r\n").unwrap_or(remaining.len());
        let size_str = &remaining[..line_end];
        let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        remaining = &remaining[line_end + 2..];
        if remaining.len() < size {
            result.push_str(remaining);
            break;
        }
        result.push_str(&remaining[..size]);
        remaining = &remaining[size..];
        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
        }
    }
    Ok(result)
}

// IFD deploy

/// Deploy an IFD order: buy A at entry price, auto-deploy sell B at exit price.
///
/// Payload-based IFD: both order RSs are embedded in the deploy TX payload.
/// No Matcher API registration needed. Fully trustless.
///
/// Steps:
///   1. Build Order B's RS (sell) with owner's SPK hash as bspkh
///   2. Build Order A's RS (buy) with bspkh = blake2b(Order B's P2SH SPK)
///   3. Build IFD payload: KOB:2:<flags|0x04><a_len><order_a_rs><order_b_rs>
///   4. Deploy Order A to L1 with IFD payload
#[allow(clippy::too_many_arguments)]
pub async fn deploy_ifd(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    // Order A params
    buy_token: &str,
    buy_price_num: u64,
    buy_price_den: u64,
    buy_amount: u64,
    buy_min_fill: u64,
    // Order B params
    sell_price_num: u64,
    sell_price_den: u64,
    sell_min_fill: u64,
    sell_expiry_daa: u64,
    // Common
    fee: u64,
) -> anyhow::Result<String> {
    // Validation
    if buy_price_num == 0 || buy_price_den == 0 {
        anyhow::bail!("buy price numerator and denominator must be > 0");
    }
    if sell_price_num == 0 || sell_price_den == 0 {
        anyhow::bail!("sell price numerator and denominator must be > 0");
    }
    if buy_min_fill == 0 || sell_min_fill == 0 {
        anyhow::bail!("min_fill must be > 0");
    }
    if buy_amount == 0 {
        anyhow::bail!("buy amount must be > 0");
    }

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let owner_hash = blake2b_256(&pubkey);
    let owner_spk_hash = compute_p2pk_spk_hash(&pubkey);

    let token_cov_bytes = hex::decode(buy_token)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_cov_bytes);

    // Step 1: Build Order B (sell) RS first — need its P2SH for Order A's bspkh.
    // Both legs are v18 (V18_DESIGN.md "IFD / IFO — MANDATORY"): the done-leg
    // sell is automatically sweep/batch-eligible under the v18 planners.
    println!("Building IFD order pair (v18)...");
    let order_b_rs = contract::spot::order::build_sell_redeem_script(
        sell_price_num,
        sell_price_den,
        sell_min_fill,
        &owner_hash,
        &owner_spk_hash, // sell proceeds go back to owner's wallet
        &contract::compute_token_unit_spk_hash(&pubkey), // otspkh (E1 expire seat)
        crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS,
        0, // cancel_pending
        sell_expiry_daa,
    )?;

    // Compute Order B's P2SH SPK hash for Order A's bspkh
    let b_p2sh_spk = build_p2sh(&order_b_rs);
    // bspkh = blake2b(version_LE_2B + script_bytes) — matches OpTxOutputSpk output
    let mut b_spk_full = Vec::with_capacity(2 + b_p2sh_spk.script().len());
    b_spk_full.extend_from_slice(&b_p2sh_spk.version.to_le_bytes());
    b_spk_full.extend_from_slice(&b_p2sh_spk.script());
    let buyer_spk_hash = blake2b_256(&b_spk_full);

    println!("  Order B (sell) RS: {} bytes", order_b_rs.len());
    println!("  Order B P2SH:     {}", hex::encode(&b_p2sh_spk.script()));
    println!("  Order A bspkh:    {}", hex::encode(&buyer_spk_hash));

    // Step 2: Build Order A (buy) RS with bspkh pointing to Order B
    let order_a_rs = contract::spot::order::build_buy_redeem_script(
        &token_cov_id,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &owner_hash,
        &buyer_spk_hash,
        &compute_p2pk_spk_hash(&pubkey), // okspkh (E1 expire seat)
        crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS,
        0, // cancel_pending
        0, // GTC for entry order
    )?;

    let p2sh_spk = build_p2sh(&order_a_rs);
    println!("  Order A (buy) RS: {} bytes", order_a_rs.len());
    println!("  Order A P2SH:     {}", hex::encode(&p2sh_spk.script()));

    // Step 3: Build IFD payload
    let ifd_payload = contract::build_ifd_order_payload(
        &order_a_rs, &order_b_rs, false, None,
    )?;

    // Connect and fetch UTXOs
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

    let min_fee_override = fee;

    // When fee=0 (auto), request a fee buffer so UTXO selection always leaves
    // room for the miner fee. Without this, an exact-match UTXO leaves 0 excess
    // and the TX fails with "Insufficient funds for fee" (the deploy fee gap bug).
    let selection_fee = if min_fee_override == 0 { 5000 } else { min_fee_override };

    let coin_sel = select_utxos_mass_aware(&core_utxos, buy_amount, selection_fee, 2).map_err(|e| {
        anyhow::anyhow!(
            "UTXO selection failed: {}. {} P2PK UTXOs available.",
            e,
            core_utxos.len()
        )
    })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    let tentative_change = total_input.saturating_sub(buy_amount).saturating_sub(min_fee_override);

    println!(
        "Selected {} funding UTXOs (total {} sompi)",
        selected_utxos.len(),
        total_input
    );

    // Build transaction
    let mut tx = Transaction::new(0);

    let first_rpc = p2pk_rpc
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                && u.outpoint.index == selected_utxos[0].outpoint.index
        })
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
    let wallet_spk_version = first_rpc.utxo_entry.script_public_key.version;

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

    // Output 0: P2SH order
    tx.outputs.push(TxOutput::new(buy_amount, 0, p2sh_spk.script().to_vec(), None));

    // IFD payload (contains both order A + order B RS)
    tx.payload = ifd_payload;

    // Tentative change output for fee convergence
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, wallet_spk_version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output.
    // CRITICAL: output[0] (the P2SH order) MUST remain exactly buy_amount.
    // The fee is always absorbed by the change output or donated as excess fee.
    // Never reduce the order output -- the matcher expects the full buy_amount.
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };

    let est_fee = if has_change {
        let (f, _) = converge_fee(&mut tx, total_input, change_idx, min_fee_override);
        // Restore order output in case converge_fee touched it (it shouldn't for change_idx != 0)
        tx.outputs[0].value = buy_amount;
        f
    } else {
        // No change output -- order stays at buy_amount, all excess is miner fee.
        // Verify we have enough to cover order + minimum fee.
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        let excess = total_input.saturating_sub(buy_amount);
        if excess < f {
            anyhow::bail!(
                "Insufficient funds for fee: need {} sompi fee but only {} excess above buy_amount {}. \
                 Fund the wallet with a larger UTXO or consolidate UTXOs.",
                f, excess, buy_amount
            );
        }
        // Order output stays at buy_amount; excess beyond fee is donated.
        f
    };

    // Remove change output if below MIN_UTXO_VALUE
    if has_change && tx.outputs[change_idx].value < MIN_UTXO_VALUE {
        let small_change = tx.outputs[change_idx].value;
        tx.outputs.pop();
        if small_change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", small_change);
        }
    }

    // Sign (phase 1)
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass).max(min_fee_override);
    if exact_fee != est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(buy_amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
        }
        // Re-sign with adjusted outputs
        sigscripts.clear();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(&tx, i)?;
            let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
            sigscripts.push(signing::build_p2pk_sigscript(&signature));
        }
    }

    // Storage mass check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected: {}. Increase amount or consolidate UTXOs.",
            e
        );
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let txid = rpc.submit_transaction(payload).await?;

    println!();
    println!("IFD Summary (payload-based, trustless)");
    println!("======================================");
    println!("  Order A (buy):   deployed, txid={}", txid);
    println!("  Order B (sell):  embedded in payload, auto-deploy on A fill");
    println!("  Entry price:     {}/{}", buy_price_num, buy_price_den);
    println!("  Exit price:      {}/{}", sell_price_num, sell_price_den);
    println!("  Order B P2SH:    {}", hex::encode(&b_p2sh_spk.script()));

    Ok(txid)
}


// IFO deploy (trustless, payload-based)

/// Deploy a trustless IFO (bracket) order: buy A at entry, auto-deploy
/// OCO sell (TP+SL) when A fills. Fully on-chain via IFD payload --
/// no Matcher API registration required.
///
/// Order A = buy RS with bspkh pointing to OCO sell P2SH.
/// Order B = OCO sell RS (TP + SL paths in a single UTXO, 333B).
///
/// When Order A fills, the executor constructs Order B's UTXO from the
/// fill TX output. The scanner discovers Order B as an OCO sell
/// (333B -> `scan_oco_sell` path) and inserts TP/SL virtual orders
/// into the order book.
#[allow(clippy::too_many_arguments)]
pub async fn deploy_ifo_trustless(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    // Order A params
    buy_token: &str,
    buy_price_num: u64,
    buy_price_den: u64,
    buy_amount: u64,
    buy_min_fill: u64,
    // OCO sell B params
    tp_price_num: u64,
    tp_price_den: u64,
    tp_min_fill: u64,
    sl_price_num: u64,
    sl_price_den: u64,
    sl_min_fill: u64,
    // Common
    expiry_daa: u64,
    max_matcher_fee: u64,
    fee: u64,
) -> anyhow::Result<String> {
    // Validation
    if buy_price_num == 0 || buy_price_den == 0 {
        anyhow::bail!("buy price numerator and denominator must be > 0");
    }
    if tp_price_num == 0 || tp_price_den == 0 {
        anyhow::bail!("TP price numerator and denominator must be > 0");
    }
    if sl_price_num == 0 || sl_price_den == 0 {
        anyhow::bail!("SL price numerator and denominator must be > 0");
    }
    if buy_min_fill == 0 || tp_min_fill == 0 || sl_min_fill == 0 {
        anyhow::bail!("min_fill must be > 0");
    }
    if buy_amount == 0 {
        anyhow::bail!("buy amount must be > 0");
    }

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let owner_hash = blake2b_256(&pubkey);
    let owner_spk_hash = compute_p2pk_spk_hash(&pubkey);

    let token_cov_bytes = hex::decode(buy_token)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_cov_bytes);

    // Step 1: Build Order B (v18 OCO sell) RS -- need its P2SH for Order A's
    // bspkh. This is the v18 SOFT path: the entry is a plain v18 buy whose
    // bspkh pins the OCO's P2SH, so the buy fill's token delivery (which
    // carries the token CovenantBinding under the v18 planners) lands
    // directly on the OCO address as a LIVE, sweep-eligible v18 OCO sell —
    // no receipt gating and no engine-side trigger. (The receipt-gated HARD
    // path is the separate `bracket` command / compute_bracket_scripts.)
    println!("Building IFO trustless order pair (v18 soft path)...");
    let oco_bps = if max_matcher_fee <= 10_000 {
        max_matcher_fee
    } else {
        crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS
    };
    let order_b_rs = contract::spot::oco::build_oco_sell_redeem_script(
        tp_price_num,
        tp_price_den,
        tp_min_fill,
        sl_price_num,
        sl_price_den,
        sl_min_fill,
        &owner_hash,
        &owner_spk_hash, // sell proceeds go back to owner's wallet
        &contract::compute_token_unit_spk_hash(&pubkey), // otspkh (E1 expire seat)
        oco_bps,
        0, // cancel_pending
        expiry_daa,
    )?;

    // Compute Order B's P2SH SPK hash for Order A's bspkh
    let b_p2sh_spk = build_p2sh(&order_b_rs);
    // bspkh = blake2b(version_LE_2B + script_bytes) -- matches OpTxOutputSpk output
    let mut b_spk_full = Vec::with_capacity(2 + b_p2sh_spk.script().len());
    b_spk_full.extend_from_slice(&b_p2sh_spk.version.to_le_bytes());
    b_spk_full.extend_from_slice(&b_p2sh_spk.script());
    let buyer_spk_hash = blake2b_256(&b_spk_full);

    println!("  Order B (OCO sell) RS: {} bytes", order_b_rs.len());
    println!("  Order B P2SH:         {}", hex::encode(&b_p2sh_spk.script()));
    println!("  Order A bspkh:        {}", hex::encode(&buyer_spk_hash));

    // Step 2: Build Order A (v18 buy) RS with bspkh pointing to OCO sell P2SH
    let order_a_rs = contract::spot::order::build_buy_redeem_script(
        &token_cov_id,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &owner_hash,
        &buyer_spk_hash,
        &compute_p2pk_spk_hash(&pubkey), // okspkh (E1 expire seat)
        oco_bps,
        0, // cancel_pending
        0, // GTC for entry order
    )?;

    let p2sh_spk = build_p2sh(&order_a_rs);
    println!("  Order A (buy) RS:     {} bytes", order_a_rs.len());
    println!("  Order A P2SH:         {}", hex::encode(&p2sh_spk.script()));

    // Step 3: Build IFD payload (embeds both Order A and Order B RS)
    let ifd_payload = contract::build_ifd_order_payload(
        &order_a_rs, &order_b_rs, false, None,
    )?;

    // Connect and fetch UTXOs
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

    let min_fee_override = fee;
    let selection_fee = if min_fee_override == 0 { 5000 } else { min_fee_override };

    let coin_sel = select_utxos_mass_aware(&core_utxos, buy_amount, selection_fee, 2).map_err(|e| {
        anyhow::anyhow!(
            "UTXO selection failed: {}. {} P2PK UTXOs available.",
            e,
            core_utxos.len()
        )
    })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    let tentative_change = total_input.saturating_sub(buy_amount).saturating_sub(min_fee_override);

    println!(
        "Selected {} funding UTXOs (total {} sompi)",
        selected_utxos.len(),
        total_input
    );

    // Build transaction
    let mut tx = Transaction::new(0);

    let first_rpc = p2pk_rpc
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                && u.outpoint.index == selected_utxos[0].outpoint.index
        })
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
    let wallet_spk_version = first_rpc.utxo_entry.script_public_key.version;

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

    // Output 0: P2SH order
    tx.outputs.push(TxOutput::new(buy_amount, 0, p2sh_spk.script().to_vec(), None));

    // IFD payload (contains both order A + order B RS)
    tx.payload = ifd_payload;

    // Tentative change output for fee convergence
    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, wallet_spk_version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output.
    // CRITICAL: output[0] (the P2SH order) MUST remain exactly buy_amount.
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };

    let est_fee = if has_change {
        let (f, _) = converge_fee(&mut tx, total_input, change_idx, min_fee_override);
        tx.outputs[0].value = buy_amount;
        f
    } else {
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        let excess = total_input.saturating_sub(buy_amount);
        if excess < f {
            anyhow::bail!(
                "Insufficient funds for fee: need {} sompi fee but only {} excess above buy_amount {}.                  Fund the wallet with a larger UTXO or consolidate UTXOs.",
                f, excess, buy_amount
            );
        }
        f
    };

    // Remove change output if below MIN_UTXO_VALUE
    if has_change && tx.outputs[change_idx].value < MIN_UTXO_VALUE {
        let small_change = tx.outputs[change_idx].value;
        tx.outputs.pop();
        if small_change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", small_change);
        }
    }

    // Sign (phase 1)
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass).max(min_fee_override);
    if exact_fee != est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(buy_amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
        }
        sigscripts.clear();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(&tx, i)?;
            let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
            sigscripts.push(signing::build_p2pk_sigscript(&signature));
        }
    }

    // Storage mass check
    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!(
            "Deploy TX would be rejected: {}. Increase amount or consolidate UTXOs.",
            e
        );
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let txid = rpc.submit_transaction(payload).await?;

    println!();
    println!("IFO Trustless Bracket Summary");
    println!("=============================");
    println!("  Order A (buy):           deployed, txid={}", txid);
    println!("  Order B (OCO sell):      embedded in payload, auto-deploy on A fill");
    println!("  Entry price:             {}/{}", buy_price_num, buy_price_den);
    println!("  Take-profit price:       {}/{}", tp_price_num, tp_price_den);
    println!("  Stop-loss price:         {}/{}", sl_price_num, sl_price_den);
    println!("  Order B RS size:         {} bytes (OCO sell)", order_b_rs.len());
    println!("  Order B P2SH:            {}", hex::encode(&b_p2sh_spk.script()));

    Ok(txid)
}

// IFO deploy (Matcher-registered)

/// Deploy an IFO order: buy A at entry, auto-deploy OCO (TP+SL) when A fills.
#[allow(clippy::too_many_arguments)]
pub async fn deploy_ifo(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    matcher_url: &str,
    // Order A params
    buy_token: &str,
    buy_price_num: u64,
    buy_price_den: u64,
    buy_amount: u64,
    buy_min_fill: u64,
    // OCO B params
    tp_price_num: u64,
    tp_price_den: u64,
    tp_min_fill: u64,
    sl_price_num: u64,
    sl_price_den: u64,
    sl_min_fill: u64,
    // Common
    fee: u64,
) -> anyhow::Result<String> {
    if buy_price_num == 0 || buy_price_den == 0 {
        anyhow::bail!("buy price must be > 0");
    }
    if tp_price_num == 0 || tp_price_den == 0 || sl_price_num == 0 || sl_price_den == 0 {
        anyhow::bail!("TP/SL price must be > 0");
    }
    if buy_min_fill == 0 || tp_min_fill == 0 || sl_min_fill == 0 {
        anyhow::bail!("min_fill must be > 0");
    }
    if buy_amount == 0 {
        anyhow::bail!("buy amount must be > 0");
    }

    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let owner_hash = blake2b_256(&pubkey);
    let owner_hash_hex = hex::encode(owner_hash);

    // Build owner SPK (36 bytes: version_u16_LE + script_34B)
    let mut owner_spk = [0u8; 36];
    // version = 0 (2 LE bytes, already zero)
    owner_spk[2] = 0x20;
    owner_spk[3..35].copy_from_slice(&pubkey);
    owner_spk[35] = 0xac;
    let owner_spk_hex = hex::encode(owner_spk);

    let owner_id = owner_hash_hex.clone();

    println!("Registering IFO rule with matcher at {}...", matcher_url);

    let ifo_req = serde_json::json!({
        "order_a": {
            "side": "buy",
            "token": buy_token,
            "price_num": buy_price_num,
            "price_den": buy_price_den,
            "amount": buy_amount,
            "min_fill": buy_min_fill,
            "expiry_daa": 0,
        },
        "token": buy_token,
        "amount": 0,
        "expiry_daa": 0,
        "tp_side": "sell",
        "tp_price_num": tp_price_num,
        "tp_price_den": tp_price_den,
        "tp_min_fill": tp_min_fill,
        "sl_side": "sell",
        "sl_price_num": sl_price_num,
        "sl_price_den": sl_price_den,
        "sl_min_fill": sl_min_fill,
        "owner_id": owner_id,
        "owner_hash": owner_hash_hex,
        "owner_spk": owner_spk_hex,
    });

    let ifo_resp = http_post_json(matcher_url, "/api/v1/ifo", &ifo_req)?;
    let ifo_id = ifo_resp["ifo_id"].as_u64().unwrap_or(0);
    let a_bspkh = ifo_resp["order_a_bspkh"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing order_a_bspkh"))?;

    println!("IFO registered: id={}", ifo_id);
    println!("  TP P2SH: {}", ifo_resp["tp_p2sh"].as_str().unwrap_or("?"));
    println!("  SL P2SH: {}", ifo_resp["sl_p2sh"].as_str().unwrap_or("?"));

    // Deploy order A
    println!("Deploying order A (buy) to L1...");

    let token_cov_bytes = hex::decode(buy_token)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_cov_bytes);

    let bspkh_bytes = hex::decode(a_bspkh)?;
    if bspkh_bytes.len() != 32 {
        anyhow::bail!("bspkh must be 64 hex characters (32 bytes)");
    }
    let mut buyer_spk_hash = [0u8; 32];
    buyer_spk_hash.copy_from_slice(&bspkh_bytes);

    let rs = contract::spot::order::build_buy_redeem_script(
        &token_cov_id,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &owner_hash,
        &buyer_spk_hash,
        &compute_p2pk_spk_hash(&pubkey), // okspkh (E1 expire seat)
        crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS,
        0, // cancel_pending
        0, // GTC
    )?;

    let p2sh_spk = build_p2sh(&rs);
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

    let min_fee_override = fee;

    // Same fee-gap fix as deploy_ifd: ensure UTXO selection leaves room for fee.
    let selection_fee = if min_fee_override == 0 { 5000 } else { min_fee_override };

    let coin_sel = select_utxos_mass_aware(&core_utxos, buy_amount, selection_fee, 2).map_err(|e| {
        anyhow::anyhow!("UTXO selection failed: {}", e)
    })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    let tentative_change = total_input.saturating_sub(buy_amount).saturating_sub(min_fee_override);

    let mut tx = Transaction::new(0);

    let first_rpc = p2pk_rpc
        .iter()
        .find(|u| {
            u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                && u.outpoint.index == selected_utxos[0].outpoint.index
        })
        .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
    let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
    let wallet_spk_version = first_rpc.utxo_entry.script_public_key.version;

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

    tx.outputs.push(TxOutput::new(buy_amount, 0, p2sh_spk.script().to_vec(), None));

    tx.payload = deploy::build_payload_auto(&rs, false);

    if tentative_change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(tentative_change, wallet_spk_version, wallet_spk.clone(), None));
    }

    // Phase 1: converge fee on change output.
    // CRITICAL: output[0] (the P2SH order) MUST remain exactly buy_amount.
    // The fee is always absorbed by the change output or donated as excess fee.
    // Never reduce the order output -- the matcher expects the full buy_amount.
    let has_change = tentative_change >= MIN_UTXO_VALUE;
    let change_idx = if has_change { tx.outputs.len() - 1 } else { 0 };

    let est_fee = if has_change {
        let (f, _) = converge_fee(&mut tx, total_input, change_idx, min_fee_override);
        // Restore order output in case converge_fee touched it (it shouldn't for change_idx != 0)
        tx.outputs[0].value = buy_amount;
        f
    } else {
        // No change output -- order stays at buy_amount, all excess is miner fee.
        // Verify we have enough to cover order + minimum fee.
        let f = kob_core::mass::calc_miner_fee(&tx).max(min_fee_override);
        let excess = total_input.saturating_sub(buy_amount);
        if excess < f {
            anyhow::bail!(
                "Insufficient funds for fee: need {} sompi fee but only {} excess above buy_amount {}. \
                 Fund the wallet with a larger UTXO or consolidate UTXOs.",
                f, excess, buy_amount
            );
        }
        // Order output stays at buy_amount; excess beyond fee is donated.
        f
    };

    if has_change && tx.outputs[change_idx].value < MIN_UTXO_VALUE {
        let small_change = tx.outputs[change_idx].value;
        tx.outputs.pop();
        if small_change > 0 {
            println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", small_change);
        }
    }

    // Sign (phase 1)
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    // Phase 2: exact mass check
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = kob_core::mass::min_relay_fee(exact_mass).max(min_fee_override);
    if exact_fee != est_fee && tx.outputs.len() > 1 {
        let change_idx = tx.outputs.len() - 1;
        let new_change = total_input.saturating_sub(buy_amount + exact_fee);
        if new_change >= MIN_UTXO_VALUE {
            tx.outputs[change_idx].value = new_change;
        } else {
            tx.outputs.pop();
        }
        sigscripts.clear();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(&tx, i)?;
            let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
            sigscripts.push(signing::build_p2pk_sigscript(&signature));
        }
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("Deploy TX would be rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    println!("Submitting transaction...");
    let txid = rpc.submit_transaction(payload).await?;

    println!();
    println!("IFO Summary");
    println!("===========");
    println!("  IFO ID:              {}", ifo_id);
    println!("  Order A (buy):       deployed, txid={}", txid);
    println!("  Take-profit (sell):  auto-deploy when A fills");
    println!("  Stop-loss (sell):    auto-deploy when A fills (OCO partner)");
    println!("  Entry price:         {}/{}", buy_price_num, buy_price_den);
    println!("  TP price:            {}/{}", tp_price_num, tp_price_den);
    println!("  SL price:            {}/{}", sl_price_num, sl_price_den);

    Ok(txid)
}
