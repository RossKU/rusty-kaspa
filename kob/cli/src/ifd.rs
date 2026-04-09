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
use kob_core::tx::{to_rpc_payload, select_utxos_mass_aware, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint, UtxoEntry};
use kob_core::wallet::WalletFile;
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
/// Steps:
///   1. POST to Matcher `/api/v1/ifd` with both order params
///   2. Get back A's P2SH (with bspkh set for token flow to B)
///   3. Deploy A to L1
#[allow(clippy::too_many_arguments)]
pub async fn deploy_ifd(
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

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

    let owner_hash = blake2b_256(&pubkey);
    let owner_spk_hash = compute_p2pk_spk_hash(&pubkey);

    let owner_hash_hex = hex::encode(owner_hash);
    let owner_spk_hash_hex = hex::encode(owner_spk_hash);
    let owner_id = owner_hash_hex.clone();

    // Step 1: Register IFD rule with the Matcher
    println!("Registering IFD rule with matcher at {}...", matcher_url);

    let ifd_req = serde_json::json!({
        "order_a": {
            "side": "buy",
            "token": buy_token,
            "price_num": buy_price_num,
            "price_den": buy_price_den,
            "amount": buy_amount,
            "min_fill": buy_min_fill,
            "expiry_daa": 0,
        },
        "order_b": {
            "side": "sell",
            "token": buy_token,
            "price_num": sell_price_num,
            "price_den": sell_price_den,
            "amount": 0,
            "min_fill": sell_min_fill,
            "expiry_daa": sell_expiry_daa,
        },
        "owner_id": owner_id,
        "owner_hash": owner_hash_hex,
        "owner_spk_hash": owner_spk_hash_hex,
    });

    let ifd_resp = http_post_json(matcher_url, "/api/v1/ifd", &ifd_req)?;
    let ifd_id = ifd_resp["ifd_id"].as_u64().unwrap_or(0);
    let a_bspkh = ifd_resp["order_a_bspkh"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing order_a_bspkh in response"))?;
    let b_p2sh = ifd_resp["order_b_p2sh"].as_str().unwrap_or("unknown");

    println!("IFD registered: id={}", ifd_id);
    println!("  Order A bspkh (tokens -> B): {}", a_bspkh);
    println!("  Order B P2SH: {}", b_p2sh);

    // Step 2: Deploy order A to L1 with modified bspkh
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

    let rs = contract::build_buy_redeem_script(
        &token_cov_id,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &owner_hash,
        &buyer_spk_hash,
        crate::deploy::DEFAULT_MAX_MATCHER_FEE,
        0, // cancel_pending
        0, // GTC for entry order
    )?;

    let p2sh_spk = build_p2sh(&rs);
    println!("  Buy RS length: {} bytes", rs.len());
    println!("  P2SH SPK:      {}", hex::encode(&p2sh_spk.script()));

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

    let coin_sel = select_utxos_mass_aware(&core_utxos, buy_amount, fee, 2).map_err(|e| {
        anyhow::anyhow!(
            "UTXO selection failed: {}. {} P2PK UTXOs available.",
            e,
            core_utxos.len()
        )
    })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    let change = total_input - buy_amount - fee;

    println!(
        "Selected {} funding UTXOs (total {} sompi)",
        selected_utxos.len(),
        total_input
    );

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

    // Output 0: P2SH order
    tx.outputs.push(TxOutput::new(buy_amount, 0, p2sh_spk.script().to_vec(), None));

    // Payload
    tx.payload = deploy::build_payload_auto(&rs, false);

    // Change
    if change >= MIN_UTXO_VALUE {
        let first_rpc = p2pk_rpc
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                    && u.outpoint.index == selected_utxos[0].outpoint.index
            })
            .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
        let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk, None));
    } else if change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    // Sign
    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
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
    println!("IFD Summary");
    println!("===========");
    println!("  IFD ID:          {}", ifd_id);
    println!("  Order A (buy):   deployed, txid={}", txid);
    println!("  Order B (sell):  will auto-deploy when A fills");
    println!("  Entry price:     {}/{}", buy_price_num, buy_price_den);
    println!("  Exit price:      {}/{}", sell_price_num, sell_price_den);

    Ok(txid)
}

// IFO deploy

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

    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let privkey = wallet.secure_key()?;

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

    let rs = contract::build_buy_redeem_script(
        &token_cov_id,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &owner_hash,
        &buyer_spk_hash,
        crate::deploy::DEFAULT_MAX_MATCHER_FEE,
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

    let coin_sel = select_utxos_mass_aware(&core_utxos, buy_amount, fee, 2).map_err(|e| {
        anyhow::anyhow!("UTXO selection failed: {}", e)
    })?;

    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    let change = total_input - buy_amount - fee;

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

    tx.outputs.push(TxOutput::new(buy_amount, 0, p2sh_spk.script().to_vec(), None));

    tx.payload = deploy::build_payload_auto(&rs, false);

    if change >= MIN_UTXO_VALUE {
        let first_rpc = p2pk_rpc
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == selected_utxos[0].outpoint.transaction_id
                    && u.outpoint.index == selected_utxos[0].outpoint.index
            })
            .ok_or_else(|| anyhow::anyhow!("UTXO spent during TX construction, please retry."))?;
        let wallet_spk = hex::decode(&first_rpc.utxo_entry.script_public_key.script)?;
        tx.outputs.push(TxOutput::new(change, first_rpc.utxo_entry.script_public_key.version, wallet_spk, None));
    } else if change > 0 {
        println!("Change {} sompi below MIN_UTXO_VALUE, donated as fee.", change);
    }

    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
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
