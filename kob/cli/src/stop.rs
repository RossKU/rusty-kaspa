//! `kob stop` / `kob trailing-stop` -- CLI commands for stop orders and
//! trailing stops managed by the Engine (Matcher).
//!
//! Stop orders hold a pre-signed deploy TX that the Matcher broadcasts when
//! the market price crosses the stop price. These are NOT on-chain orders;
//! they live in the Matcher's memory and are broadcast to L1 upon trigger.
//!
//! Workflow:
//!   1. CLI builds and signs a deploy TX (same as `kob deploy buy/sell`)
//!   2. CLI POSTs the raw TX JSON + stop params to the Matcher REST API
//!   3. Matcher holds the TX; broadcasts it when the stop condition is met
//!
//! See `kob-engine/src/matcher/stop_book.rs` and `trailing_stop.rs` for the
//! Engine-side logic.

use crate::deploy;
use crate::node::NodeClient;
use crate::signing;
use crate::token;
use clap::Subcommand;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{select_utxos_mass_aware, to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint, UtxoEntry};
use kob_core::wallet::WalletContext;
use kob_core::MIN_UTXO_VALUE;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

// CLI subcommands

/// Subcommands for `kob stop`.
#[derive(Subcommand, Debug)]
pub enum StopCommand {
    /// Deploy a stop-limit or stop-market buy order via the Matcher.
    ///
    /// Builds a signed buy deploy TX locally, then POSTs it to the Matcher
    /// as a conditional stop order. The Matcher broadcasts it when the
    /// market price crosses the stop price.
    DeployBuy {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Limit price numerator (the price of the order that gets deployed).
        #[arg(long)]
        price_num: u64,

        /// Limit price denominator.
        #[arg(long)]
        price_den: u64,

        /// Amount of KAS to lock (in sompi).
        #[arg(long)]
        amount: u64,

        /// Minimum fill amount in token units.
        #[arg(long)]
        min_fill: u64,

        /// Stop trigger price numerator.
        #[arg(long)]
        stop_price_num: u64,

        /// Stop trigger price denominator.
        #[arg(long)]
        stop_price_den: u64,

        /// Matcher API URL (e.g. http://localhost:8080).
        #[arg(long)]
        matcher_url: String,

        /// Stop order type: stop-limit or stop-market.
        #[arg(long, default_value = "stop-limit")]
        r#type: String,

        /// Optional expiry (unix timestamp). Omit for GTC.
        #[arg(long)]
        expires_at: Option<u64>,
    },

    /// Deploy a stop-limit or stop-market sell order via the Matcher.
    DeploySell {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Limit price numerator (the price of the order that gets deployed).
        #[arg(long)]
        price_num: u64,

        /// Limit price denominator.
        #[arg(long)]
        price_den: u64,

        /// Amount of tokens to lock (in sompi value).
        #[arg(long)]
        amount: u64,

        /// Minimum fill amount in sompi.
        #[arg(long)]
        min_fill: u64,

        /// Stop trigger price numerator.
        #[arg(long)]
        stop_price_num: u64,

        /// Stop trigger price denominator.
        #[arg(long)]
        stop_price_den: u64,

        /// Matcher API URL (e.g. http://localhost:8080).
        #[arg(long)]
        matcher_url: String,

        /// Stop order type: stop-limit or stop-market.
        #[arg(long, default_value = "stop-limit")]
        r#type: String,

        /// Optional expiry (unix timestamp). Omit for GTC.
        #[arg(long)]
        expires_at: Option<u64>,
    },

    /// Cancel a stop order by ID.
    Cancel {
        /// Stop order ID (assigned by the Matcher).
        #[arg(long)]
        id: u64,

        /// Owner ID (defaults to wallet public key hash).
        #[arg(long)]
        owner_id: Option<String>,

        /// Matcher API URL (e.g. http://localhost:8080).
        #[arg(long)]
        matcher_url: String,
    },

    /// List active stop orders.
    List {
        /// Token covenant ID to filter by (hex, 64 chars).
        #[arg(long)]
        token: Option<String>,

        /// Matcher API URL (e.g. http://localhost:8080).
        #[arg(long)]
        matcher_url: String,
    },
}

/// Subcommands for `kob trailing-stop`.
#[derive(Subcommand, Debug)]
pub enum TrailingStopCommand {
    /// Deploy a trailing stop order via the Matcher.
    ///
    /// The Matcher tracks the market price and adjusts the stop price
    /// dynamically. When the price reverses by the trail distance,
    /// the pre-signed TX is broadcast.
    Deploy {
        /// Token covenant ID (hex, 64 chars).
        #[arg(long)]
        token: String,

        /// Order side: buy or sell.
        #[arg(long)]
        side: String,

        /// Limit price numerator (the price of the order that gets deployed).
        #[arg(long)]
        price_num: u64,

        /// Limit price denominator.
        #[arg(long)]
        price_den: u64,

        /// Amount to lock (in sompi).
        #[arg(long)]
        amount: u64,

        /// Minimum fill amount.
        #[arg(long)]
        min_fill: u64,

        /// Trail distance numerator (absolute). Mutually exclusive with --trail-pct.
        #[arg(long)]
        trail_distance_num: Option<u64>,

        /// Trail distance denominator (absolute). Required with --trail-distance-num.
        #[arg(long)]
        trail_distance_den: Option<u64>,

        /// Trail distance as a percentage (e.g. 5.0 = 5%). Mutually exclusive with --trail-distance-num.
        #[arg(long)]
        trail_pct: Option<f64>,

        /// Initial market price numerator (used to compute initial stop price).
        #[arg(long)]
        initial_price_num: u64,

        /// Initial market price denominator.
        #[arg(long)]
        initial_price_den: u64,

        /// Matcher API URL (e.g. http://localhost:8080).
        #[arg(long)]
        matcher_url: String,
    },

    /// Cancel a trailing stop order by ID.
    Cancel {
        /// Trailing stop order ID (assigned by the Matcher).
        #[arg(long)]
        id: u64,

        /// Owner ID (defaults to wallet public key hash).
        #[arg(long)]
        owner_id: Option<String>,

        /// Matcher API URL (e.g. http://localhost:8080).
        #[arg(long)]
        matcher_url: String,
    },

    /// List active trailing stop orders.
    List {
        /// Matcher API URL (e.g. http://localhost:8080).
        #[arg(long)]
        matcher_url: String,
    },
}

// HTTP helpers (stdlib-only, no reqwest — same pattern as ifd.rs)

/// Parse a matcher URL into (host, port) for TCP connection.
fn parse_matcher_url(matcher_url: &str) -> anyhow::Result<(String, u16)> {
    let url_str = if !matcher_url.starts_with("http://") {
        format!("http://{}", matcher_url)
    } else {
        matcher_url.to_string()
    };
    let without_scheme = url_str.strip_prefix("http://").expect("url_str always has http:// prefix");
    let host_port = match without_scheme.find('/') {
        Some(idx) => &without_scheme[..idx],
        None => without_scheme,
    };
    let (host, port) = match host_port.find(':') {
        Some(idx) => (
            &host_port[..idx],
            host_port[idx + 1..].parse::<u16>().unwrap_or(80),
        ),
        None => (host_port, 80u16),
    };
    Ok((host.to_string(), port))
}

/// POST JSON to a Matcher API endpoint and return the parsed response.
fn http_post_json(
    matcher_url: &str,
    api_path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let (host, port) = parse_matcher_url(matcher_url)?;
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid Matcher address '{}': {}", addr, e))?,
        Duration::from_secs(5),
    )
    .map_err(|e| anyhow::anyhow!("Could not connect to Matcher at {}: {}", matcher_url, e))?;

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let body_str = serde_json::to_string(body)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        api_path, host, port, body_str.len(), body_str,
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    parse_http_response(&response, matcher_url)
}

/// GET from a Matcher API endpoint and return the parsed response.
fn http_get_json(
    matcher_url: &str,
    api_path: &str,
) -> anyhow::Result<serde_json::Value> {
    let (host, port) = parse_matcher_url(matcher_url)?;
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid Matcher address '{}': {}", addr, e))?,
        Duration::from_secs(5),
    )
    .map_err(|e| anyhow::anyhow!("Could not connect to Matcher at {}: {}", matcher_url, e))?;

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        api_path, host, port,
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    parse_http_response(&response, matcher_url)
}

/// Parse an HTTP response (handles chunked encoding).
fn parse_http_response(response: &[u8], matcher_url: &str) -> anyhow::Result<serde_json::Value> {
    let response_str = String::from_utf8_lossy(response);

    let http_body = response_str
        .find("\r\n\r\n")
        .map(|idx| &response_str[idx + 4..])
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response from Matcher"))?;

    let status_line = response_str.lines().next().unwrap_or("");
    let status_ok = status_line.contains("200") || status_line.contains("201");

    let body_final = if response_str.contains("Transfer-Encoding: chunked") {
        decode_chunked(http_body)?
    } else {
        http_body.to_string()
    };

    let parsed: serde_json::Value = serde_json::from_str(&body_final).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse Matcher response: {}. Body: {}",
            e,
            &body_final[..body_final.len().min(200)]
        )
    })?;

    if !status_ok {
        let err_msg = parsed["error"]
            .as_str()
            .unwrap_or(status_line);
        anyhow::bail!("Matcher rejected request ({}): {}", matcher_url, err_msg);
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

// Build a signed deploy TX and serialize as submitTransaction JSON payload

/// Build a signed deploy buy TX and return the serialized JSON payload string
/// (suitable for `submitTransaction` RPC or the stop order `signed_tx_json`).
#[allow(clippy::too_many_arguments)]
async fn build_signed_buy_tx_json(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    token: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    amount: u64,
    fee: u64,
) -> anyhow::Result<String> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let owner_hash = blake2b_256(&pubkey);
    // v18 delivery re-wrap: the triggered buy's bspkh commits the owner's
    // token_unit P2SH SPK so its fill delivers a spendable KCC20 token_unit.
    let buyer_spk_hash = contract::compute_token_unit_spk_hash(&pubkey);

    let token_cov_bytes = hex::decode(token)?;
    if token_cov_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut token_cov_id = [0u8; 32];
    token_cov_id.copy_from_slice(&token_cov_bytes);

    let rs = contract::spot::order::build_buy_redeem_script(
        &token_cov_id,
        price_num,
        price_den,
        min_fill,
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

    let coin_sel = select_utxos_mass_aware(&core_utxos, amount, fee, 2)?;
    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    let change = total_input - amount - fee;

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

    tx.outputs.push(TxOutput::new(amount, 0, p2sh_spk.script().to_vec(), None));

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
    }

    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX would be rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    let json_str = serde_json::to_string(&payload)?;
    Ok(json_str)
}

/// Build a signed deploy sell TX and return the serialized JSON payload string.
///
/// Mirrors `deploy::deploy_sell` v14 logic: P2PK UTXOs fund the order,
/// covenant binding tags the output for token tracking.
#[allow(clippy::too_many_arguments)]
async fn build_signed_sell_tx_json(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    token: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    amount: u64,
    fee: u64,
) -> anyhow::Result<String> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = wallet.privkey();

    let owner_hash = blake2b_256(&pubkey);
    let seller_spk_hash = compute_p2pk_spk_hash(&pubkey);

    let rs = contract::spot::order::build_sell_redeem_script(
        price_num,
        price_den,
        min_fill,
        &owner_hash,
        &seller_spk_hash,
        &contract::compute_token_unit_spk_hash(&pubkey), // otspkh (E1 expire seat)
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

    let coin_sel = select_utxos_mass_aware(&core_utxos, amount, fee, 2)?;
    let selected_utxos = &coin_sel.utxos;
    let total_input = coin_sel.total;
    let change = total_input - amount - fee;

    // Sell orders with covenant binding use TX version 1
    let mut tx = Transaction::new(1);

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

    // Output 0: P2SH sell order with covenant binding
    let covenant_binding = Some(kob_core::tx::CovenantBinding::new(0, kob_core::compat::parse_hash(&token.to_string()).unwrap()));
    tx.outputs.push(TxOutput::new(amount, 0, p2sh_spk.script().to_vec(), covenant_binding));

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
    }

    let mut sigscripts: Vec<Vec<u8>> = Vec::new();
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign_secure(&privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    if let Err(e) = kob_core::check_tx_storage_mass(&tx) {
        anyhow::bail!("TX would be rejected: {}", e);
    }

    let payload = to_rpc_payload(&tx, &sigscripts);
    let json_str = serde_json::to_string(&payload)?;
    Ok(json_str)
}

// Stop order dispatch

/// Execute a stop order subcommand.
pub async fn run_stop(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    fee: u64,
    cmd: &StopCommand,
) -> anyhow::Result<()> {
    match cmd {
        StopCommand::DeployBuy {
            token,
            price_num,
            price_den,
            amount,
            min_fill,
            stop_price_num,
            stop_price_den,
            matcher_url,
            r#type,
            expires_at,
        } => {
            let token = &token::resolve_token(token, None)?;
            if *price_num == 0 || *price_den == 0 {
                anyhow::bail!("price numerator and denominator must be > 0");
            }
            if *stop_price_num == 0 || *stop_price_den == 0 {
                anyhow::bail!("stop price numerator and denominator must be > 0");
            }
            if *amount == 0 || *min_fill == 0 {
                anyhow::bail!("amount and min_fill must be > 0");
            }

            let order_type = parse_stop_type(r#type)?;
            let wallet = WalletContext::load(wallet_path)?;
            let pubkey = wallet.pubkey;
            let owner_id = hex::encode(blake2b_256(&pubkey));

            println!("Building signed buy TX for stop order...");
            let signed_tx_json = build_signed_buy_tx_json(
                wallet_path, node_url, network, token,
                *price_num, *price_den, *min_fill, *amount, fee,
            ).await?;

            println!("Submitting stop order to Matcher at {}...", matcher_url);
            let req = serde_json::json!({
                "pair": token,
                "side": "buy",
                "stop_price_num": stop_price_num,
                "stop_price_den": stop_price_den,
                "order_type": order_type,
                "signed_tx_json": signed_tx_json,
                "owner_id": owner_id,
                "expires_at": expires_at,
            });

            let resp = http_post_json(matcher_url, "/api/v1/stop-orders", &req)?;
            let id = resp["id"].as_u64().unwrap_or(0);
            println!();
            println!("Stop order accepted:");
            println!("  ID:         {}", id);
            println!("  Type:       {}", r#type);
            println!("  Side:       BUY");
            println!("  Stop price: {}/{}", stop_price_num, stop_price_den);
            println!("  Order price:{}/{}", price_num, price_den);
            println!("  Amount:     {} sompi", amount);
            println!("  Token:      {}...", &token[..token.len().min(16)]);
        }

        StopCommand::DeploySell {
            token,
            price_num,
            price_den,
            amount,
            min_fill,
            stop_price_num,
            stop_price_den,
            matcher_url,
            r#type,
            expires_at,
        } => {
            let token = &token::resolve_token(token, None)?;
            if *price_num == 0 || *price_den == 0 {
                anyhow::bail!("price numerator and denominator must be > 0");
            }
            if *stop_price_num == 0 || *stop_price_den == 0 {
                anyhow::bail!("stop price numerator and denominator must be > 0");
            }
            if *amount == 0 || *min_fill == 0 {
                anyhow::bail!("amount and min_fill must be > 0");
            }

            let order_type = parse_stop_type(r#type)?;
            let wallet = WalletContext::load(wallet_path)?;
            let pubkey = wallet.pubkey;
            let owner_id = hex::encode(blake2b_256(&pubkey));

            println!("Building signed sell TX for stop order...");
            let signed_tx_json = build_signed_sell_tx_json(
                wallet_path, node_url, network, token,
                *price_num, *price_den, *min_fill, *amount, fee,
            ).await?;

            println!("Submitting stop order to Matcher at {}...", matcher_url);
            let req = serde_json::json!({
                "pair": token,
                "side": "sell",
                "stop_price_num": stop_price_num,
                "stop_price_den": stop_price_den,
                "order_type": order_type,
                "signed_tx_json": signed_tx_json,
                "owner_id": owner_id,
                "expires_at": expires_at,
            });

            let resp = http_post_json(matcher_url, "/api/v1/stop-orders", &req)?;
            let id = resp["id"].as_u64().unwrap_or(0);
            println!();
            println!("Stop order accepted:");
            println!("  ID:         {}", id);
            println!("  Type:       {}", r#type);
            println!("  Side:       SELL");
            println!("  Stop price: {}/{}", stop_price_num, stop_price_den);
            println!("  Order price:{}/{}", price_num, price_den);
            println!("  Amount:     {} sompi", amount);
            println!("  Token:      {}...", &token[..token.len().min(16)]);
        }

        StopCommand::Cancel {
            id,
            owner_id,
            matcher_url,
        } => {
            let resolved_owner = match owner_id {
                Some(oid) => oid.clone(),
                None => {
                    let wallet = WalletContext::load(wallet_path)?;
                    let pubkey = wallet.pubkey;
                    hex::encode(blake2b_256(&pubkey))
                }
            };

            let req = serde_json::json!({
                "id": id,
                "owner_id": resolved_owner,
            });

            let resp = http_post_json(matcher_url, "/api/v1/stop-orders/cancel", &req)?;
            println!("Stop order #{} cancelled: {}", id, resp["status"].as_str().unwrap_or("ok"));
        }

        StopCommand::List { token, matcher_url } => {
            let query = match token {
                Some(t) => format!("/api/v1/stop-orders?pair={}", token::resolve_token(t, None)?),
                None => "/api/v1/stop-orders".to_string(),
            };
            let resp = http_get_json(matcher_url, &query)?;

            if let Some(orders) = resp["orders"].as_array() {
                if orders.is_empty() {
                    println!("No active stop orders.");
                } else {
                    println!("{:<6} {:<6} {:<16} {:<12} {:<10}", "ID", "SIDE", "STOP PRICE", "TYPE", "PAIR");
                    println!("{}", "-".repeat(60));
                    for o in orders {
                        let id = o["id"].as_u64().unwrap_or(0);
                        let side = o["side"].as_str().unwrap_or("?");
                        let sn = o["stop_price_num"].as_u64().unwrap_or(0);
                        let sd = o["stop_price_den"].as_u64().unwrap_or(1);
                        let otype = o["order_type"].as_str().unwrap_or("?");
                        let pair = o["pair"].as_str().unwrap_or("?");
                        let pair_short = &pair[..pair.len().min(12)];
                        println!("{:<6} {:<6} {:<16} {:<12} {}...", id, side, format!("{}/{}", sn, sd), otype, pair_short);
                    }
                }
            } else {
                // Summary mode (no filter)
                let total = resp["total"].as_u64().unwrap_or(0);
                let pairs = resp["pairs"].as_u64().unwrap_or(0);
                println!("Stop orders: {} total across {} pairs", total, pairs);
                println!("Use --token <covenant_id> to list orders for a specific pair.");
            }
        }
    }
    Ok(())
}

// Trailing stop dispatch

/// Execute a trailing stop subcommand.
pub async fn run_trailing_stop(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    fee: u64,
    cmd: &TrailingStopCommand,
) -> anyhow::Result<()> {
    match cmd {
        TrailingStopCommand::Deploy {
            token,
            side,
            price_num,
            price_den,
            amount,
            min_fill,
            trail_distance_num,
            trail_distance_den,
            trail_pct,
            initial_price_num,
            initial_price_den,
            matcher_url,
        } => {
            let token = &token::resolve_token(token, None)?;
            if *price_num == 0 || *price_den == 0 {
                anyhow::bail!("price numerator and denominator must be > 0");
            }
            if *initial_price_num == 0 || *initial_price_den == 0 {
                anyhow::bail!("initial price numerator and denominator must be > 0");
            }
            if *amount == 0 || *min_fill == 0 {
                anyhow::bail!("amount and min_fill must be > 0");
            }

            let trail_spec = match (trail_distance_num, trail_distance_den, trail_pct) {
                (Some(num), Some(den), None) => {
                    if *den == 0 {
                        anyhow::bail!("trail-distance-den must be > 0");
                    }
                    serde_json::json!({"amount": {"num": num, "den": den}})
                }
                (None, None, Some(pct)) => {
                    if *pct <= 0.0 || *pct >= 100.0 {
                        anyhow::bail!("trail-pct must be between 0 and 100 (exclusive)");
                    }
                    serde_json::json!({"percent": pct})
                }
                (Some(_), None, None) => {
                    anyhow::bail!("--trail-distance-den is required with --trail-distance-num");
                }
                (None, Some(_), None) => {
                    anyhow::bail!("--trail-distance-num is required with --trail-distance-den");
                }
                _ => {
                    anyhow::bail!(
                        "Specify either --trail-distance-num/--trail-distance-den or --trail-pct (not both)"
                    );
                }
            };

            let ts_side = match side.to_lowercase().as_str() {
                "buy" => "buy",
                "sell" => "sell",
                other => anyhow::bail!("Invalid side '{}', expected 'buy' or 'sell'", other),
            };

            let wallet = WalletContext::load(wallet_path)?;
            let pubkey = wallet.pubkey;
            let owner_id = hex::encode(blake2b_256(&pubkey));

            println!("Building signed {} TX for trailing stop...", ts_side);
            let signed_tx_json = match ts_side {
                "buy" => {
                    build_signed_buy_tx_json(
                        wallet_path, node_url, network, token,
                        *price_num, *price_den, *min_fill, *amount, fee,
                    ).await?
                }
                "sell" => {
                    build_signed_sell_tx_json(
                        wallet_path, node_url, network, token,
                        *price_num, *price_den, *min_fill, *amount, fee,
                    ).await?
                }
                _ => unreachable!(),
            };

            println!("Submitting trailing stop to Matcher at {}...", matcher_url);
            let req = serde_json::json!({
                "pair_id": token,
                "side": ts_side,
                "trail_spec": trail_spec,
                "signed_tx_hex": signed_tx_json,
                "initial_price_num": initial_price_num,
                "initial_price_den": initial_price_den,
                "owner_id": owner_id,
                "created_at_daa": 0,
            });

            let resp = http_post_json(matcher_url, "/api/v1/trailing-stops", &req)?;
            let id = resp["id"].as_u64().unwrap_or(0);
            println!();
            println!("Trailing stop accepted:");
            println!("  ID:            {}", id);
            println!("  Side:          {}", ts_side.to_uppercase());
            println!("  Order price:   {}/{}", price_num, price_den);
            println!("  Trail spec:    {}", trail_spec);
            println!("  Initial price: {}/{}", initial_price_num, initial_price_den);
            println!("  Token:         {}...", &token[..token.len().min(16)]);
        }

        TrailingStopCommand::Cancel {
            id,
            owner_id,
            matcher_url,
        } => {
            let resolved_owner = match owner_id {
                Some(oid) => oid.clone(),
                None => {
                    let wallet = WalletContext::load(wallet_path)?;
                    let pubkey = wallet.pubkey;
                    hex::encode(blake2b_256(&pubkey))
                }
            };

            let req = serde_json::json!({
                "id": id,
                "owner_id": resolved_owner,
            });

            let resp = http_post_json(matcher_url, "/api/v1/trailing-stops/cancel", &req)?;
            println!(
                "Trailing stop #{} cancelled: {}",
                id,
                resp["status"].as_str().unwrap_or("ok")
            );
        }

        TrailingStopCommand::List { matcher_url } => {
            let resp = http_get_json(matcher_url, "/api/v1/trailing-stops")?;

            let total = resp["total"].as_u64().unwrap_or(0);
            if let Some(orders) = resp["orders"].as_array() {
                if orders.is_empty() {
                    println!("No active trailing stop orders.");
                } else {
                    println!("{} active trailing stop order(s):", total);
                    println!();
                    println!(
                        "{:<6} {:<6} {:<16} {:<16} {:<16}",
                        "ID", "SIDE", "PEAK PRICE", "CURRENT STOP", "PAIR"
                    );
                    println!("{}", "-".repeat(70));
                    for o in orders {
                        let id = o["id"].as_u64().unwrap_or(0);
                        let side = o["side"].as_str().unwrap_or("?");
                        let ppn = o["peak_price_num"].as_u64().unwrap_or(0);
                        let ppd = o["peak_price_den"].as_u64().unwrap_or(1);
                        let csn = o["current_stop_num"].as_u64().unwrap_or(0);
                        let csd = o["current_stop_den"].as_u64().unwrap_or(1);
                        let pair = o["pair_id"].as_str().unwrap_or("?");
                        let pair_short = &pair[..pair.len().min(12)];
                        println!(
                            "{:<6} {:<6} {:<16} {:<16} {}...",
                            id,
                            side,
                            format!("{}/{}", ppn, ppd),
                            format!("{}/{}", csn, csd),
                            pair_short,
                        );
                    }
                }
            } else {
                println!("Trailing stops: {} total", total);
            }
        }
    }
    Ok(())
}

fn parse_stop_type(s: &str) -> anyhow::Result<&'static str> {
    match s.to_lowercase().as_str() {
        "stop-limit" | "stoplimit" => Ok("stop-limit"),
        "stop-market" | "stopmarket" => Ok("stop-market"),
        other => anyhow::bail!(
            "Invalid stop type '{}'. Use 'stop-limit' or 'stop-market'.",
            other
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stop_type_accepts_valid() {
        assert_eq!(parse_stop_type("stop-limit").unwrap(), "stop-limit");
        assert_eq!(parse_stop_type("stop-market").unwrap(), "stop-market");
        assert_eq!(parse_stop_type("StopLimit").unwrap(), "stop-limit");
        assert_eq!(parse_stop_type("StopMarket").unwrap(), "stop-market");
    }

    #[test]
    fn parse_stop_type_rejects_invalid() {
        assert!(parse_stop_type("limit").is_err());
        assert!(parse_stop_type("").is_err());
    }

    #[test]
    fn parse_matcher_url_with_scheme() {
        let (host, port) = parse_matcher_url("http://localhost:8080").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_matcher_url_without_scheme() {
        let (host, port) = parse_matcher_url("127.0.0.1:9090").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9090);
    }

    #[test]
    fn parse_matcher_url_default_port() {
        let (host, port) = parse_matcher_url("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_matcher_url_with_path() {
        let (host, port) = parse_matcher_url("http://myhost:3000/some/path").unwrap();
        assert_eq!(host, "myhost");
        assert_eq!(port, 3000);
    }

    #[test]
    fn decode_chunked_basic() {
        let chunked = "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(chunked).unwrap(), "helloworld");
    }

    #[test]
    fn decode_chunked_empty() {
        let chunked = "0\r\n\r\n";
        assert_eq!(decode_chunked(chunked).unwrap(), "");
    }

    #[test]
    fn decode_chunked_single() {
        let chunked = "a\r\n{\"id\": 42}\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(chunked).unwrap(), "{\"id\": 42}");
    }
}
