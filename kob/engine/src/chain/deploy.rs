//! Order deployment transaction construction.

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::AppConfig;
use kob_core::{MIN_UTXO_VALUE, SUBNETWORK_ID};
use crate::matcher::executor;
use crate::matcher::matching;
use crate::matcher::order_book::{BookOrder, OrderBook, OrderSide};
use crate::rpc::RpcClient;

/// Build the RPC transaction JSON for submitting.
pub fn build_submit_payload(
    version: u16,
    inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "transaction": {
            "version": version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": 0u64,
            "subnetworkId": SUBNETWORK_ID,
            "gas": 0u64,
            "payload": "",
            "mass": 0u64,
        },
        "allowOrphan": false,
    })
}

/// Build the RPC transaction JSON with a custom TX-level payload.
///
/// Used by IFD fill TXs that embed a `KOB:1:<B_RS>` payload so the scanner
/// discovers the contingent order B deployed by the fill.
pub fn build_submit_payload_with_tx_payload(
    version: u16,
    inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
    tx_payload_hex: &str,
    lock_time: u64,
) -> serde_json::Value {
    serde_json::json!({
        "transaction": {
            "version": version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": lock_time,
            "subnetworkId": SUBNETWORK_ID,
            "gas": 0u64,
            "payload": tx_payload_hex,
            "mass": 0u64,
        },
        "allowOrphan": false,
    })
}

/// Build the RPC transaction JSON for submitting, with a custom lockTime.
///
/// Used by expire TXs where lockTime must be >= expiry_daa for CLTV to pass.
pub fn build_submit_payload_with_lock_time(
    version: u16,
    inputs: Vec<serde_json::Value>,
    outputs: Vec<serde_json::Value>,
    lock_time: u64,
) -> serde_json::Value {
    serde_json::json!({
        "transaction": {
            "version": version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": lock_time,
            "subnetworkId": SUBNETWORK_ID,
            "gas": 0u64,
            "payload": "",
            "mass": 0u64,
        },
        "allowOrphan": false,
    })
}

/// Build an RPC input JSON.
pub fn build_rpc_input(tx_id: &str, index: u32, sig_script_hex: &str, sig_op_count: u8) -> serde_json::Value {
    build_rpc_input_with_sequence(tx_id, index, sig_script_hex, sig_op_count, 0)
}

/// Build an RPC input JSON with a custom sequence number.
///
/// Covenant fill inputs require sequence=50 for OP_CSV compliance.
pub fn build_rpc_input_with_sequence(tx_id: &str, index: u32, sig_script_hex: &str, sig_op_count: u8, sequence: u64) -> serde_json::Value {
    serde_json::json!({
        "previousOutpoint": {
            "transactionId": tx_id,
            "index": index,
        },
        "signatureScript": sig_script_hex,
        "sequence": sequence,
        "sigOpCount": sig_op_count,
    })
}

/// Build an RPC output JSON (without covenant).
pub fn build_rpc_output(value: u64, spk_version: u16, spk_script_hex: &str) -> serde_json::Value {
    serde_json::json!({
        "value": value,
        "scriptPublicKey": {
            "version": spk_version,
            "script": spk_script_hex,
        },
    })
}

/// Build an RPC output JSON with covenant binding.
pub fn build_rpc_output_with_covenant(
    value: u64,
    spk_version: u16,
    spk_script_hex: &str,
    auth_input: u16,
    covenant_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "value": value,
        "scriptPublicKey": {
            "version": spk_version,
            "script": spk_script_hex,
        },
        "covenant": {
            "authorizingInput": auth_input,
            "covenantId": covenant_id,
        },
    })
}

/// Create a BookOrder from deployment parameters.
///
/// `counterparty_spk_hex`: hex-encoded actual SPK bytes of the deployer
/// (buyer SPK for buy orders, seller SPK for sell orders). This is required
/// for the matcher to build valid match TX outputs. Pass `None` for orders
/// deployed with the legacy payload v1 format ("KOB:1:") which does not
/// include the SPK; such orders will be skipped at match time.
pub fn create_book_order(
    tx_id: &str,
    index: u32,
    value: u64,
    token_cov_id: &str,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &str,
    spk_hash: &str,
    counterparty_spk_hex: Option<String>,
    side: OrderSide,
    rs_hex: &str,
    p2sh_script_hex: &str,
    p2sh_version: u16,
) -> BookOrder {
    BookOrder {
        tx_id: tx_id.to_string(),
        index,
        value,
        token_cov_id: token_cov_id.to_string(),
        price_num,
        price_den,
        min_fill,
        owner_hash: owner_hash.to_string(),
        spk_hash: spk_hash.to_string(),
        counterparty_spk: counterparty_spk_hex,
        redeem_script_hex: rs_hex.to_string(),
        p2sh_script_hex: p2sh_script_hex.to_string(),
        p2sh_version,
        side,
        post_only: false,
        expiry_daa: None,
        is_freezable: false,
        max_matcher_fee: 0, ifd_order_b_rs_hex: None,
        oco_path: None,
        oco_partner_key: None,
        discovered_daa: 0,
    }
}

/// Build buy_order v12 redeemScript and P2SH.
pub fn build_buy_order_scripts(
    token_cov_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    buyer_spk_hash: &[u8; 32],
    max_matcher_fee: u64,
) -> (String, String, u16) {
    let rs = kob_core::contract::build_buy_redeem_script(
        token_cov_id, price_num, price_den, min_fill, owner_hash, buyer_spk_hash, max_matcher_fee,
        0, 0,).unwrap();
    let rs_hex = hex::encode(&rs);
    let spk = kob_core::build_p2sh(&rs);
    let p2sh_hex = hex::encode(&spk.script());
    (rs_hex, p2sh_hex, spk.version)
}

/// Build sell_order v12 redeemScript and P2SH.
pub fn build_sell_order_scripts(
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    seller_spk_hash: &[u8; 32],
    max_matcher_fee: u64,
) -> (String, String, u16) {
    let rs = kob_core::contract::build_sell_redeem_script(
        price_num, price_den, min_fill, owner_hash, seller_spk_hash, max_matcher_fee, 0, 0,).unwrap();
    let rs_hex = hex::encode(&rs);
    let spk = kob_core::build_p2sh(&rs);
    let p2sh_hex = hex::encode(&spk.script());
    (rs_hex, p2sh_hex, spk.version)
}

/// Build trade_receipt redeemScript and P2SH.
#[allow(deprecated)]
pub fn build_receipt_scripts(
    pair_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    exec_amount: u64,
) -> (String, String, u16) {
    let dummy_recipient: [u8; 32] = [0u8; 32];
    let rs = kob_core::contract::build_receipt_redeem_script(
        pair_id, price_num, price_den, exec_amount,
        kob_core::RECEIPT_DUST, &dummy_recipient,
    ).expect("build_receipt_redeem_script failed in test");
    let rs_hex = hex::encode(&rs);
    let spk = kob_core::build_p2sh(&rs);
    let p2sh_hex = hex::encode(&spk.script());
    (rs_hex, p2sh_hex, spk.version)
}

// Deploy a single test pair (token + buy + sell)
// Returns (deploy_tx_id, covenant_id_hex, buy_rs_hex, buy_p2sh_hex, buy_p2sh_ver,
//          sell_rs_hex, sell_p2sh_hex, sell_p2sh_ver) or None

struct DeployResult {
    deploy_tx_id: String,
    covenant_id_hex: String,
    buy_rs_hex: String,
    buy_p2sh_hex: String,
    buy_p2sh_ver: u16,
    sell_rs_hex: String,
    sell_p2sh_hex: String,
    sell_p2sh_ver: u16,
    buy_value: u64,
    sell_value: u64,
    /// Hex-encoded Blake2b-256(buyer SPK) embedded in the buy RS
    buyer_spk_hash_hex: String,
    /// Hex-encoded Blake2b-256(seller SPK) embedded in the sell RS
    seller_spk_hash_hex: String,
    /// Hex-encoded actual SPK bytes of the deployer wallet (buyer = seller in test mode).
    /// Stored so the matcher can route match TX outputs to the correct counterparty.
    counterparty_spk_hex: String,
}

async fn deploy_test_pair(
    rpc: &RpcClient,
    utxos: &[crate::rpc::RpcUtxo],
    config: &AppConfig,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    token_cov_id: &str,
    token_utxo_str: &str,
) -> Option<DeployResult> {
    let owner_hash = config.owner_hash();
    let privkey = config.private_key_bytes();

    let buy_value = 30_000_000u64;  // 0.3 KAS
    let sell_value = 30_000_000u64; // 0.3 KAS
    // Estimate miner fee for deploy TX (1 input, 2 outputs, ~100 byte payload)
    let estimated_fee = kob_core::mass::estimate_compute_mass(1, 2, 100);
    let kas_needed = buy_value + estimated_fee;

    if utxos.is_empty() {
        error!("No UTXOs available");
        return None;
    }
    let (wallet_spk_version, wallet_spk_script) = utxos[0].parse_spk();
    let wallet_spk_hex = hex::encode(&wallet_spk_script);

    // Parse token UTXO outpoint (format: "txid:index")
    let (token_tx_id, token_index) = {
        let parts: Vec<&str> = token_utxo_str.split(':').collect();
        if parts.len() != 2 {
            error!("Invalid --token-utxo format. Expected txid:index");
            return None;
        }
        let idx: u32 = match parts[1].parse() {
            Ok(i) => i,
            Err(_) => {
                error!("Invalid --token-utxo index: {}", parts[1]);
                return None;
            }
        };
        (parts[0].to_string(), idx)
    };

    // Find the token UTXO. It's a token_unit P2SH (owner pubkey embedded).
    let pubkey: [u8; 32] = match config.public_key.clone().try_into() {
        Ok(pk) => pk,
        Err(_) => {
            error!("[DEPLOY] public_key is not 32 bytes (got {})", config.public_key.len());
            return None;
        }
    };
    let token_unit_rs = kob_core::contract::build_token_unit_redeem_script(&pubkey);
    let token_unit_spk = kob_core::build_p2sh(&token_unit_rs);
    let token_unit_spk_hex = hex::encode(&token_unit_spk.script());

    // Query the token_unit P2SH address
    let token_p2sh_addr = {
        let prefix = if config.address.starts_with("kaspatest:") {
            "kaspatest"
        } else {
            "kaspa"
        };
        kob_core::bech32::bech32_encode(prefix, 8, &token_unit_spk.script()[2..34])
    };
    info!("  Querying token_unit P2SH: {}", &token_p2sh_addr[..50.min(token_p2sh_addr.len())]);
    let token_utxos = match rpc.get_utxos_by_addresses(&[&token_p2sh_addr]).await {
        Ok(u) => u,
        Err(e) => {
            error!("[DEPLOY] Failed to query token UTXOs: {}", e);
            return None;
        }
    };
    info!("  Found {} UTXOs at token_unit address", token_utxos.len());
    let token_utxo = token_utxos.iter().find(|u| {
        u.outpoint.transaction_id == token_tx_id && u.outpoint.index == token_index
    });
    let token_utxo = match token_utxo {
        Some(u) => u,
        None => {
            error!("[DEPLOY] Token UTXO {}:{} not found at address {}",
                &token_tx_id[..16.min(token_tx_id.len())], token_index,
                &token_p2sh_addr[..40.min(token_p2sh_addr.len())]);
            return None;
        }
    };
    let token_input_value = token_utxo.utxo_entry.amount;
    if token_input_value < sell_value {
        error!("[DEPLOY] Token UTXO value {} < sell_value {}", token_input_value, sell_value);
        return None;
    }
    let token_change = token_input_value - sell_value;

    info!("Token UTXO: {}:{} ({} sompi, covenant {}...)",
        &token_tx_id[..16.min(token_tx_id.len())], token_index,
        token_input_value, &token_cov_id[..16.min(token_cov_id.len())]);

    let covenant_id_hex = token_cov_id.to_string();

    // Compute SPK hashes (both sides are matcher's wallet in test mode)
    let buyer_spk_hash = kob_core::compute_spk_hash(wallet_spk_version, &wallet_spk_script);
    let seller_spk_hash = buyer_spk_hash;

    // Build order scripts
    let cov_id_bytes: [u8; 32] = match hex::decode(&covenant_id_hex) {
        Ok(v) if v.len() == 32 => v.try_into().expect("len 32"),
        _ => { error!("Invalid covenant ID hex"); return None; }
    };
    let (buy_rs_hex, buy_p2sh_hex, buy_p2sh_ver) =
        build_buy_order_scripts(&cov_id_bytes, price_num, price_den, min_fill, &owner_hash, &buyer_spk_hash, 0);
    let (sell_rs_hex, sell_p2sh_hex, sell_p2sh_ver) =
        build_sell_order_scripts(price_num, price_den, min_fill, &owner_hash, &seller_spk_hash, 0);

    // Find a wallet UTXO for the buy order + fee
    let wallet_utxo = utxos.iter().find(|u| u.utxo_entry.amount >= kas_needed);
    let wallet_utxo = match wallet_utxo {
        Some(u) => u,
        None => {
            error!("[DEPLOY] No wallet UTXO with >= {} sompi", kas_needed);
            return None;
        }
    };
    let wallet_in = wallet_utxo.utxo_entry.amount;
    let kas_change = wallet_in - kas_needed;

    info!("Wallet UTXO: {}:{} ({} sompi)",
        &wallet_utxo.outpoint.transaction_id[..16.min(wallet_utxo.outpoint.transaction_id.len())],
        wallet_utxo.outpoint.index, wallet_in);

    // Build TX for sighash (version 1 for covenant outputs)
    let mut tx = kob_core::tx::Transaction::new(1);

    // Input 0: token_unit UTXO (covenant + owner sig, sigOpCount=1)
    tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: token_tx_id.clone(),
        prev_index: token_index,
        sequence: 0,
        sig_op_count: 1,
        script_version: token_unit_spk.version,
        script_bytes: token_unit_spk.script().to_vec(),
        value: token_input_value,
    });

    // Input 1: wallet UTXO (P2PK, sigOpCount=1)
    let (wv, ws) = wallet_utxo.parse_spk();
    tx.inputs.push(kob_core::tx::TxInput {
        prev_tx_id: wallet_utxo.outpoint.transaction_id.clone(),
        prev_index: wallet_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: wv,
        script_bytes: ws,
        value: wallet_in,
    });

    // Output 0: buy order (no covenant)
    let buy_p2sh_bytes = hex::decode(&buy_p2sh_hex).ok()?;
    tx.outputs.push(kob_core::tx::TxOutput::new(buy_value, buy_p2sh_ver, buy_p2sh_bytes, None));

    // Output 1: sell order (covenant binding from token input[0])
    let sell_p2sh_bytes = hex::decode(&sell_p2sh_hex).ok()?;
    tx.outputs.push(kob_core::tx::TxOutput::new(sell_value, sell_p2sh_ver, sell_p2sh_bytes, Some(kob_core::tx::CovenantBinding::new(0, kob_core::compat::parse_hash(&covenant_id_hex.clone()).unwrap()))));

    // Output 2: token change (return remaining tokens, covenant binding from input[0])
    if token_change >= MIN_UTXO_VALUE {
        tx.outputs.push(kob_core::tx::TxOutput::new(token_change, token_unit_spk.version, token_unit_spk.script().to_vec(), Some(kob_core::tx::CovenantBinding::new(0, kob_core::compat::parse_hash(&covenant_id_hex.clone()).unwrap()))));
    }

    // Output 3: KAS change
    if kas_change >= MIN_UTXO_VALUE {
        tx.outputs.push(kob_core::tx::TxOutput::new(kas_change, wallet_spk_version, wallet_spk_script.clone(), None));
    }

    // Sign token input (input 0) — token_unit requires owner signature
    let token_sighash = kob_core::compute_sighash(&tx, 0).ok()?;
    debug!("  Token sighash: {}", hex::encode(token_sighash));
    let token_sig = match kob_core::schnorr_sign(&token_sighash, &privkey) {
        Ok(s) => s,
        Err(e) => {
            error!("Token signing failed: {}", e);
            return None;
        }
    };
    let token_sigscript = kob_core::contract::build_token_unit_sigscript(&token_sig, &token_unit_rs);

    // Sign wallet input (input 1)
    let wallet_sighash = kob_core::compute_sighash(&tx, 1).ok()?;
    debug!("  Wallet sighash: {}", hex::encode(wallet_sighash));
    let wallet_sig = match kob_core::schnorr_sign(&wallet_sighash, &privkey) {
        Ok(s) => s,
        Err(e) => {
            error!("Wallet signing failed: {}", e);
            return None;
        }
    };
    let wallet_sigscript = kob_core::contract::build_p2pk_sigscript(&wallet_sig);

    // Build RPC inputs
    let rpc_inputs = vec![
        build_rpc_input(&token_tx_id, token_index, &hex::encode(&token_sigscript), 1),
        build_rpc_input(
            &wallet_utxo.outpoint.transaction_id,
            wallet_utxo.outpoint.index,
            &hex::encode(&wallet_sigscript),
            1,
        ),
    ];

    // Build RPC outputs
    let mut rpc_outputs = vec![
        build_rpc_output(buy_value, buy_p2sh_ver, &buy_p2sh_hex),
        build_rpc_output_with_covenant(sell_value, sell_p2sh_ver, &sell_p2sh_hex, 0, &covenant_id_hex),
    ];
    if token_change >= MIN_UTXO_VALUE {
        rpc_outputs.push(build_rpc_output_with_covenant(
            token_change, token_unit_spk.version, &token_unit_spk_hex, 0, &covenant_id_hex,
        ));
    }
    if kas_change >= MIN_UTXO_VALUE {
        rpc_outputs.push(build_rpc_output(kas_change, wallet_spk_version, &wallet_spk_hex));
    }

    let payload = build_submit_payload(1, rpc_inputs, rpc_outputs);

    info!("  Submitting deploy TX (version 1, 2 inputs, {} outputs)...", tx.outputs.len());
    let result = match rpc.submit_transaction(payload).await {
        Ok(r) => r,
        Err(e) => {
            error!("  Submit failed: {}", e);
            return None;
        }
    };

    if result.ok {
        let deploy_tx_id = result.tx_id.unwrap_or_else(|| {
            warn!("[DEPLOY] Success response missing tx_id");
            String::new()
        });
        info!("[DEPLOY] SUCCESS! TXID: {}", deploy_tx_id);
        info!("  Covenant ID: {}", covenant_id_hex);
        info!("  Buy: {}:0  Sell: {}:1", deploy_tx_id, deploy_tx_id);
        if token_change >= MIN_UTXO_VALUE {
            info!("  Token change: {}:2 ({} sompi)", deploy_tx_id, token_change);
        }
        return Some(DeployResult {
            deploy_tx_id,
            covenant_id_hex,
            buy_rs_hex,
            buy_p2sh_hex,
            buy_p2sh_ver,
            sell_rs_hex,
            sell_p2sh_hex,
            sell_p2sh_ver,
            buy_value,
            sell_value,
            buyer_spk_hash_hex: hex::encode(buyer_spk_hash),
            seller_spk_hash_hex: hex::encode(seller_spk_hash),
            counterparty_spk_hex: wallet_spk_hex.clone(),
        });
    }

    let err_msg = result.error.unwrap_or_else(|| "Unknown".to_string());
    error!("[DEPLOY] FAILED: {}", err_msg);
    None
}

// Deploy-test mode (single pair)

pub async fn run_deploy_test(
    rpc: Arc<Mutex<RpcClient>>,
    order_book: Arc<Mutex<OrderBook>>,
    config: &AppConfig,
    token_cov_id: &str,
    token_utxo: &str,
) {
    info!("======================================================================");
    info!("KOB MATCHER BOT -- DEPLOY + MATCH TEST (SINGLE PAIR)");
    info!("======================================================================");

    let price_num = 1u64;
    let price_den = 2u64;
    let min_fill = 1_000_000u64;
    let owner_hash = config.owner_hash();
    let owner_hash_hex = hex::encode(owner_hash);

    info!("Wallet:   {}", config.address);
    info!("Price:    {}/{}", price_num, price_den);
    info!("Min fill: {}", min_fill);

    // Get UTXOs
    let rpc_lock = rpc.lock().await;
    let utxos = match rpc_lock.get_spendable_utxos(&config.address, Some(MIN_UTXO_VALUE)).await {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to get UTXOs: {}", e);
            return;
        }
    };

    info!("Available UTXOs (>= {}): {}", MIN_UTXO_VALUE, utxos.len());
    for (i, u) in utxos.iter().take(5).enumerate() {
        info!(
            "  [{}] {} sompi  {}...:{}", i, u.utxo_entry.amount,
            &u.outpoint.transaction_id[..16.min(u.outpoint.transaction_id.len())],
            u.outpoint.index
        );
    }

    if utxos.is_empty() {
        error!("FATAL: No usable UTXOs");
        drop(rpc_lock);
        return;
    }

    // STEP 1: DEPLOY
    info!("======================================================================");
    info!("STEP 1: DEPLOY BUY + SELL ORDERS (using existing token)");
    info!("======================================================================");

    let dr = match deploy_test_pair(&rpc_lock, &utxos, config, price_num, price_den, min_fill, token_cov_id, token_utxo).await {
        Some(d) => d,
        None => {
            drop(rpc_lock);
            return;
        }
    };
    drop(rpc_lock);

    // Add orders to the book.
    // counterparty_spk_hex is the matcher's own SPK (both sides are the matcher in
    // test mode), required so the executor can route match TX outputs.
    let buy_order = create_book_order(
        &dr.deploy_tx_id, 0, dr.buy_value,
        &dr.covenant_id_hex, price_num, price_den, min_fill,
        &owner_hash_hex, &dr.buyer_spk_hash_hex,
        Some(dr.counterparty_spk_hex.clone()),
        OrderSide::Buy,
        &dr.buy_rs_hex, &dr.buy_p2sh_hex, dr.buy_p2sh_ver,
    );
    let sell_order = create_book_order(
        &dr.deploy_tx_id, 1, dr.sell_value,
        &dr.covenant_id_hex, price_num, price_den, min_fill,
        &owner_hash_hex, &dr.seller_spk_hash_hex,
        Some(dr.counterparty_spk_hex.clone()),
        OrderSide::Sell,
        &dr.sell_rs_hex, &dr.sell_p2sh_hex, dr.sell_p2sh_ver,
    );

    {
        let mut ob = order_book.lock().await;
        ob.add_buy_order(buy_order);
        ob.add_sell_order(sell_order);
    }

    // STEP 2: MATCH
    info!("======================================================================");
    info!("STEP 2: MATCH BUY + SELL");
    info!("======================================================================");

    // OP_CSV(50) requires 50 DAA blocks (~50s at 1 BPS) after deploy.
    info!("Waiting 55s for deploy TX propagation + OP_CSV maturity...");
    tokio::time::sleep(std::time::Duration::from_secs(55)).await;

    let groups = {
        let ob = order_book.lock().await;
        info!("  Order book state: {} pairs, {} total bids, {} total asks",
            ob.pair_books.len(),
            ob.pair_books.values().map(|b| b.bids.len()).sum::<usize>(),
            ob.pair_books.values().map(|b| b.asks.len()).sum::<usize>(),
        );
        for (cov_id, book) in &ob.pair_books {
            info!("  Pair [{}...]: {} bids, {} asks",
                &cov_id[..cov_id.len().min(16)], book.bids.len(), book.asks.len());
            for (_k, b) in &book.bids {
                info!("    BID val={} price={}/{} owner={}...", b.value, b.price_num, b.price_den, &b.owner_hash[..b.owner_hash.len().min(16)]);
            }
            for (_k, a) in &book.asks {
                info!("    ASK val={} price={}/{} owner={}...", a.value, a.price_num, a.price_den, &a.owner_hash[..a.owner_hash.len().min(16)]);
            }
        }
        matching::match_book_direct(&ob, true, None, u64::MAX)
    };

    if groups.is_empty() {
        warn!("No matching groups found after deploy. (debug: allow_self_trade=true)");
        return;
    }

    info!("Found {} matching group(s)", groups.len());
    let best = &groups[0];
    info!(
        "  Best: kind={:?} sells={} buys={} surplus={}",
        best.kind, best.sells.len(), best.buys.len(), best.total_surplus
    );

    // Convert to batch orders and execute via batch engine
    let sell_order = match executor::book_order_to_batch_order(&best.sells[0], "DEPLOY-TEST") {
        Some(o) => o,
        None => {
            warn!("Failed to convert sell to batch order");
            return;
        }
    };
    let buy_order = match executor::book_order_to_batch_order(&best.buys[0], "DEPLOY-TEST") {
        Some(o) => o,
        None => {
            warn!("Failed to convert buy to batch order");
            return;
        }
    };

    let rpc_lock = rpc.lock().await;

    // Get wallet UTXOs for fee input
    let batch_utxos = match rpc_lock.get_spendable_utxos(&config.address, Some(0)).await {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to get UTXOs for batch: {}", e);
            drop(rpc_lock);
            return;
        }
    };
    if batch_utxos.is_empty() {
        error!("No wallet UTXOs for batch match");
        drop(rpc_lock);
        return;
    }
    let (wallet_spk_version, wallet_spk_script) = batch_utxos[0].parse_spk();

    // Find the best wallet UTXO for fee payment (largest non-token UTXO)
    let token_p2sh = kob_core::build_p2sh(kob_core::TOKEN_RS);
    let token_p2sh_hex = hex::encode(&token_p2sh.script());
    let wallet_utxo = batch_utxos.iter()
        .filter(|u| {
            let (_, script) = u.parse_spk();
            hex::encode(&script) != token_p2sh_hex
        })
        .max_by_key(|u| u.utxo_entry.amount)
        .map(|u| (u.outpoint.transaction_id.clone(), u.outpoint.index, u.utxo_entry.amount));

    let mut plan = match crate::matcher::batch::plan_batch_match(
        &[sell_order], &[buy_order], wallet_utxo,
        &wallet_spk_script, wallet_spk_version,
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!("Batch plan failed: {}", e);
            drop(rpc_lock);
            return;
        }
    };

    let mut spent_tracker = executor::SpentTracker::new();
    let batch_result = executor::execute_batch_match(&rpc_lock, &mut plan, config, &mut spent_tracker, None, (wallet_spk_version, &wallet_spk_script)).await;
    drop(rpc_lock);

    match batch_result {
        Some(br) => {
            // Remove matched orders
            {
                let mut ob = order_book.lock().await;
                for buy in &best.buys {
                    ob.remove_order(&buy.outpoint_key());
                }
                for sell in &best.sells {
                    ob.remove_order(&sell.outpoint_key());
                }
            }

            info!("======================================================================");
            info!("DEPLOY-TEST COMPLETE");
            info!("======================================================================");
            info!("  Deploy TX:    {}", dr.deploy_tx_id);
            info!("  Match TX:     {}", br.tx_id);
        }
        None => {
            warn!("Match execution failed.");
        }
    }
}

// Deploy-test-multi mode (two pairs)

pub async fn run_deploy_test_multi(
    rpc: Arc<Mutex<RpcClient>>,
    _order_book: Arc<Mutex<OrderBook>>,
    config: &AppConfig,
) {
    info!("======================================================================");
    info!("KOB MATCHER BOT -- MULTI-PAIR DEPLOY + MATCH TEST");
    info!("======================================================================");

    info!("Wallet:   {}", config.address);
    info!("Pair A:   price 1/2");
    info!("Pair B:   price 1/3");

    let rpc_lock = rpc.lock().await;
    let utxos = match rpc_lock.get_spendable_utxos(&config.address, Some(MIN_UTXO_VALUE)).await {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to get UTXOs: {}", e);
            return;
        }
    };
    drop(rpc_lock);

    info!("Available UTXOs (>= {}): {}", MIN_UTXO_VALUE, utxos.len());
    warn!("Multi-pair deploy-test not yet implemented. Use --mode deploy-test for single pair.");
}
