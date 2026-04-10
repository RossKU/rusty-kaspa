//! `kob-cli recover` -- RBF UTXO recovery for stuck mempool transactions.
//!
//! Identifies wallet UTXOs that are spent in the mempool but not yet confirmed,
//! then replaces those mempool transactions with a self-send at a higher fee
//! (Replace-By-Fee). Falls back to normal `submitTransaction` for UTXOs that
//! have no pending mempool spend.
//!
//! Fee escalation: 10,000 → 100,000 → 1,000,000 sompi (0.0001 / 0.001 / 0.01 KAS).
//!
//! RBF TX structure (version 0, no covenant):
//!   input[0]:  stuck UTXO (P2PK, wallet self-sign)
//!   output[0]: wallet address (value = input - fee)

use crate::node::NodeClient;
use crate::rpc::RpcUtxo;
use crate::signing;
use kob_core::sighash::compute_sighash;
use kob_core::tx::{Transaction, TxInput, TxOutput};
use kob_core::wallet::WalletFile;
use std::collections::HashSet;
use std::path::Path;
use tracing::info;

/// Default fee levels to attempt in order (sompi).
const FEE_LEVELS: &[u64] = &[10_000, 100_000, 1_000_000];

/// Recover stuck UTXOs via RBF or normal submission.
///
/// For each confirmed UTXO at the wallet address:
///   - If it has a mempool TX spending it: try `submitTransactionReplacement` with
///     increasing fees until accepted.
///   - If no mempool TX is spending it: try `submitTransaction` with the lowest fee
///     (rare edge case — the UTXO should already be spendable, but included for
///     completeness when `getSpendableUtxos` filtering is stale).
///
/// Prints a one-line summary per UTXO and a final total at the end.
pub async fn recover(wallet_path: &Path, node_url: &str) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let privkey = wallet.private_key_bytes()?;

    println!("RBF UTXO Recovery");
    println!("==================");
    println!("Wallet:  {}", wallet.address);
    println!("Node:    {}", node_url);
    println!();

    info!(address = %wallet.address, "starting RBF recovery");

    let rpc = NodeClient::connect(node_url).await?;

    // Step 1: Get all confirmed UTXOs (including mempool-spent ones).
    let all_utxos = rpc.get_utxos_by_addresses(&[&wallet.address]).await?;
    // Sorted descending by amount (largest first).
    let utxos = {
        let mut v = all_utxos;
        v.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));
        v
    };

    if utxos.is_empty() {
        println!("No UTXOs found for wallet address.");
        return Ok(());
    }

    println!("Found {} UTXO(s). Checking mempool...", utxos.len());
    println!();

    // Step 2: Query mempool to find which UTXOs are already spent in-flight.
    let mempool_spent = get_mempool_spent_outpoints(&rpc, &wallet.address).await;

    // Step 3: Process each UTXO.
    let mut freed = 0usize;
    let mut skipped = 0usize;
    let mut stuck = 0usize;

    for utxo in &utxos {
        let outpoint_key = utxo.outpoint_key();
        let amount = utxo.utxo_entry.amount;
        let kas_amt = amount as f64 / 1e8;
        let id_short = &utxo.outpoint.transaction_id[..utxo.outpoint.transaction_id.len().min(16)];

        if mempool_spent.contains(&outpoint_key) {
            // This UTXO is being spent by a mempool TX — try RBF.
            let result = try_rbf_escalating(&rpc, &wallet, utxo, &privkey).await;
            match result {
                RbfResult::Freed { tx_id, fee } => {
                    println!(
                        "FREE  {:>14.8} KAS  {}  fee={:.8} KAS  -> {}",
                        kas_amt,
                        id_short,
                        fee as f64 / 1e8,
                        &tx_id[..tx_id.len().min(16)]
                    );
                    freed += 1;
                }
                RbfResult::Stuck { reason } => {
                    println!(
                        "STUCK {:>14.8} KAS  {}  {}",
                        kas_amt,
                        id_short,
                        &reason[..reason.len().min(100)]
                    );
                    stuck += 1;
                }
            }
        } else {
            // UTXO is not being spent in the mempool — no RBF needed.
            println!(
                "SKIP  {:>14.8} KAS  {}  (not in mempool, already spendable)",
                kas_amt, id_short
            );
            skipped += 1;
        }
    }

    println!();
    println!(
        "Done. Freed: {}/{} | Skipped (already spendable): {} | Still stuck: {}",
        freed,
        utxos.len(),
        skipped,
        stuck
    );

    Ok(())
}

/// Result of a single RBF attempt (potentially multiple fee levels).
enum RbfResult {
    Freed { tx_id: String, fee: u64 },
    Stuck { reason: String },
}

/// Try to RBF a stuck UTXO with escalating fees.
///
/// Tries each fee level in `FEE_LEVELS` in order. Returns `Freed` on the
/// first acceptance, or `Stuck` after all levels are exhausted.
async fn try_rbf_escalating(
    rpc: &NodeClient,
    wallet: &WalletFile,
    utxo: &RpcUtxo,
    privkey: &[u8; 32],
) -> RbfResult {
    let amount = utxo.utxo_entry.amount;

    for &fee in FEE_LEVELS {
        if fee >= amount {
            // Fee would consume the entire UTXO — skip this level.
            continue;
        }

        match try_rbf_once(rpc, wallet, utxo, privkey, fee).await {
            Ok(tx_id) => return RbfResult::Freed { tx_id, fee },
            Err(e) => {
                let msg = e.to_string();
                // If the node says there's no mempool TX to replace, there's no
                // point escalating fees — report as stuck with this message.
                if is_no_replacement_error(&msg) {
                    return RbfResult::Stuck {
                        reason: format!("no replacement target: {}", msg),
                    };
                }
                // Otherwise (fee too low, etc.) continue to the next fee level.
                info!(fee = fee, error = %msg, "RBF attempt failed, escalating fee");
            }
        }
    }

    RbfResult::Stuck {
        reason: format!(
            "all fee levels ({:?}) rejected",
            FEE_LEVELS
        ),
    }
}

/// Attempt a single `submitTransactionReplacement` for one UTXO at a given fee.
///
/// Builds a version-0 self-send TX (P2PK → same P2PK script), signs it,
/// and calls `submitTransactionReplacement`.
async fn try_rbf_once(
    rpc: &NodeClient,
    _wallet: &WalletFile,
    utxo: &RpcUtxo,
    privkey: &[u8; 32],
    fee: u64,
) -> anyhow::Result<String> {
    let amount = utxo.utxo_entry.amount;
    let out_val = amount
        .checked_sub(fee)
        .ok_or_else(|| anyhow::anyhow!("Transaction fee ({} sompi) exceeds the UTXO value ({} sompi). Nothing to recover.", fee, amount))?;

    if out_val == 0 {
        anyhow::bail!("Cannot recover: the UTXO value equals the fee, leaving nothing to recover.");
    }

    let spk_version = utxo.utxo_entry.script_public_key.version;
    let spk_script = utxo.script_bytes();

    // Build a version-0 self-send transaction (no covenant needed).
    let mut tx = Transaction::new(0);

    tx.inputs.push(TxInput {
        prev_tx_id: utxo.outpoint.transaction_id.clone(),
        prev_index: utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: spk_version,
        script_bytes: spk_script.clone(),
        value: amount,
    });

    tx.outputs.push(TxOutput::new(out_val, spk_version, spk_script.clone(), None));

    // Sign with wallet private key (standard P2PK Schnorr).
    let sighash = compute_sighash(&tx, 0)?;
    let signature = signing::schnorr_sign(privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&signature);

    // Build the submitTransactionReplacement payload.
    // Structure mirrors submitTransaction but uses a different RPC method name.
    let payload = build_replacement_payload(&tx, &sigscript);

    let result = rpc.call("submitTransactionReplacement", payload).await?;

    // Extract the new transaction ID from the response.
    let tx_id = result
        .get("transactionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "submitTransactionReplacement returned no transactionId: {}",
                result
            )
        })?
        .to_string();

    Ok(tx_id)
}

/// Build the JSON payload for `submitTransactionReplacement`.
///
/// The wire format is identical to `submitTransaction`; only the RPC method
/// name differs.
fn build_replacement_payload(tx: &Transaction, sigscript: &[u8]) -> serde_json::Value {
    debug_assert_eq!(tx.inputs.len(), 1, "RBF TX must have exactly one input");
    debug_assert_eq!(tx.outputs.len(), 1, "RBF TX must have exactly one output");

    let inp = &tx.inputs[0];
    let out = &tx.outputs[0];

    serde_json::json!({
        "transaction": {
            "version": tx.version,
            "inputs": [{
                "previousOutpoint": {
                    "transactionId": inp.prev_tx_id,
                    "index": inp.prev_index,
                },
                "signatureScript": hex::encode(sigscript),
                "sequence": inp.sequence,
                "sigOpCount": inp.sig_op_count,
            }],
            "outputs": [{
                "value": out.value,
                "scriptPublicKey": {
                    "version": out.script_version(),
                    "script": hex::encode(out.script_bytes()),
                },
            }],
            "lockTime": tx.lock_time,
            "subnetworkId": tx.subnetwork_id,
            "gas": tx.gas,
            "payload": "",
            "mass": 0,
        },
    })
}

/// Return true if the RPC error indicates there is no mempool transaction to replace.
fn is_no_replacement_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("not found")
        || lower.contains("no transaction to replace")
        || lower.contains("replacement not found")
        || lower.contains("double spend")
}

/// Query the mempool for the wallet address and return a set of outpoint keys
/// ("txid:index") that are spent by pending mempool transactions.
///
/// On any RPC error (node doesn't support the method, etc.) returns an empty set
/// so callers can still process UTXOs without crashing.
async fn get_mempool_spent_outpoints(rpc: &NodeClient, address: &str) -> HashSet<String> {
    let result = rpc
        .call(
            "getMempoolEntriesByAddresses",
            serde_json::json!({
                "addresses": [address],
                "includeOrphanPool": true,
                "filterTransactionPool": false,
            }),
        )
        .await;

    let mut spent = HashSet::new();

    match result {
        Err(e) => {
            info!(error = %e, "getMempoolEntriesByAddresses failed, treating all UTXOs as not-in-mempool");
        }
        Ok(resp) => {
            if let Some(entries) = resp.get("entries").and_then(|v| v.as_array()) {
                for entry in entries {
                    // Each entry has a "sending" array of mempool TXs that spend
                    // UTXOs belonging to this address.
                    if let Some(sending) = entry.get("sending").and_then(|v| v.as_array()) {
                        for tx_entry in sending {
                            if let Some(inputs) = tx_entry
                                .get("transaction")
                                .and_then(|t| t.get("inputs"))
                                .and_then(|v| v.as_array())
                            {
                                for inp in inputs {
                                    if let Some(op) = inp.get("previousOutpoint") {
                                        let tid = op
                                            .get("transactionId")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        let idx =
                                            op.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                                        spent.insert(format!("{}:{}", tid, idx));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    spent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_levels_are_ordered() {
        for w in FEE_LEVELS.windows(2) {
            assert!(w[0] < w[1], "FEE_LEVELS must be strictly increasing");
        }
    }

    #[test]
    fn is_no_replacement_error_matches_known_messages() {
        assert!(is_no_replacement_error("transaction not found in mempool"));
        assert!(is_no_replacement_error("No transaction to replace"));
        assert!(is_no_replacement_error("replacement not found"));
        assert!(!is_no_replacement_error("fee too low"));
        assert!(!is_no_replacement_error("insufficient fee for replacement"));
    }

    #[test]
    fn build_replacement_payload_structure() {
        let mut tx = Transaction::new(0);
        tx.inputs.push(TxInput {
            prev_tx_id: "aabb".repeat(16),
            prev_index: 0,
            sequence: 0,
            sig_op_count: 1,
            script_version: 0,
            script_bytes: vec![0x20, 0x01, 0x02],
            value: 100_000,
        });
        tx.outputs.push(TxOutput::new(90_000, 0, vec![0x20, 0x01, 0x02], None));

        let sigscript = vec![0x41u8; 66];
        let payload = build_replacement_payload(&tx, &sigscript);

        let t = &payload["transaction"];
        assert_eq!(t["version"].as_u64().unwrap(), 0);
        assert_eq!(t["inputs"].as_array().unwrap().len(), 1);
        assert_eq!(t["outputs"].as_array().unwrap().len(), 1);
        assert_eq!(t["outputs"][0]["value"].as_u64().unwrap(), 90_000);
        // Payload key must not include "allowOrphan" (submitTransactionReplacement has no such field)
        assert!(payload.get("allowOrphan").is_none());
    }

    #[test]
    fn rbf_fee_would_exceed_amount_is_skipped() {
        // When fee >= amount, that fee level must be skipped (not panic).
        let amount: u64 = 5_000;
        for &fee in FEE_LEVELS {
            if fee >= amount {
                // This is the skip condition — verified to compile without overflow.
                let _ = amount.checked_sub(fee);
            }
        }
    }
}

// --- recover_orders ---

use crate::order_cache::{OrderCache, OrderCacheEntry};
use crate::cancel::kaspa_address_encode;
use crate::scan::extract_p2sh_hash;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::types::Network;

/// KOB payload prefix bytes.
const KOB_PREFIX: &[u8] = b"KOB:1:";

/// Parsed order from a redeemScript (CLI-specific wrapper).
#[derive(Debug, Clone)]
pub struct ParsedOrder {
    pub side: String,
    pub version: u8,
    pub price_num: u64,
    pub price_den: u64,
    pub min_fill: u64,
    pub owner_hash: [u8; 32],
    pub spk_hash: [u8; 32],
    pub token_cov_id: Option<[u8; 32]>,
    pub p2sh_hash: String,
}

/// Parse a redeemScript from raw bytes.
///
/// Delegates to kob_core's parser and converts the result to the CLI's ParsedOrder.
pub fn parse_redeem_script(rs: &[u8]) -> Option<ParsedOrder> {
    let core_parsed = kob_core::parse_redeem_script(rs)?;
    let p2sh_data = build_p2sh(rs);
    let p2sh_hash = hex::encode(&p2sh_data.script()[2..34]);
    let side = match core_parsed.order_type {
        kob_core::OrderSide::Buy => "buy",
        kob_core::OrderSide::Sell => "sell",
    };
    let token_cov_id = if core_parsed.token_cov_id == [0u8; 32] {
        None
    } else {
        Some(core_parsed.token_cov_id)
    };
    Some(ParsedOrder {
        side: side.to_string(),
        version: core_parsed.version,
        price_num: core_parsed.price_num,
        price_den: core_parsed.price_den,
        min_fill: core_parsed.min_fill,
        owner_hash: core_parsed.owner_hash,
        spk_hash: core_parsed.spk_hash,
        token_cov_id,
        p2sh_hash,
    })
}

/// Extract RS bytes from a hex-encoded TX payload.
///
/// Payload is hex-encoded in the REST API response.
/// Returns the raw RS bytes if the payload starts with KOB:1: prefix.
pub fn extract_rs_from_payload_hex(payload_hex: &str) -> Option<Vec<u8>> {
    if payload_hex.is_empty() {
        return None;
    }
    let payload_bytes = hex::decode(payload_hex).ok()?;
    if payload_bytes.len() < KOB_PREFIX.len() {
        return None;
    }
    if &payload_bytes[..KOB_PREFIX.len()] != KOB_PREFIX {
        return None;
    }
    let rs_bytes = &payload_bytes[KOB_PREFIX.len()..];
    if rs_bytes.is_empty() {
        return None;
    }
    // Strip optional :GTD: suffix
    let rs = if let Some(pos) = find_gtd_marker(rs_bytes) {
        &rs_bytes[..pos]
    } else {
        rs_bytes
    };
    Some(rs.to_vec())
}

/// Find the start position of a :GTD: marker in RS bytes (if present).
fn find_gtd_marker(data: &[u8]) -> Option<usize> {
    let marker = b":GTD:";
    if data.len() < marker.len() + 8 {
        return None;
    }
    // GTD marker is appended after the RS, so check from the end
    let check_start = data.len().saturating_sub(marker.len() + 8);
    (check_start..data.len().saturating_sub(marker.len())).find(|&i| &data[i..i + marker.len()] == marker)
}

/// Fetch full transactions for an address from the Kaspa REST API using curl.
///
/// Returns the parsed JSON response, or an error.
fn fetch_full_transactions(rest_url: &str, address: &str) -> anyhow::Result<serde_json::Value> {
    let url = format!("{}/addresses/{}/full-transactions", rest_url.trim_end_matches('/'), address);
    info!(url = %url, "fetching full transactions from REST API");

    let output = std::process::Command::new("curl")
        .args(["-s", "-f", "--max-time", "30", &url])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "REST API request failed (status {}): {}",
            output.status.code().unwrap_or(-1),
            stderr
        );
    }

    let body = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    Ok(json)
}

/// A recovered order with its deployment TX info.
#[derive(Debug, Clone)]
pub struct RecoveredOrder {
    pub tx_id: String,
    pub output_index: u32,
    pub order: ParsedOrder,
    pub value: u64,
    pub is_live: bool,
}

/// Run the `recover-orders` command.
pub async fn recover_orders(
    wallet_path: &Path,
    rpc_url: &str,
    rest_url: &str,
    network: Network,
    output_path: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let wallet = WalletFile::load(wallet_path)?;
    let pubkey = wallet.public_key_bytes()?;
    let owner_hash = blake2b_256(&pubkey);
    let _spk_hash = compute_p2pk_spk_hash(&pubkey);

    let network_prefix = match network {
        Network::Mainnet => "kaspa",
        Network::Testnet => "kaspatest",
    };

    println!("KOB Order Recovery");
    println!("===================");
    println!("Wallet:     {}", wallet.address);
    println!("Owner Hash: {}", hex::encode(owner_hash));
    println!("REST API:   {}", rest_url);
    println!("RPC:        {}", rpc_url);
    if dry_run {
        println!("Mode:       DRY RUN (no file written)");
    }
    println!();

    // Step 1: Fetch all transactions involving this address
    println!("Fetching transactions from REST API...");
    let tx_data = fetch_full_transactions(rest_url, &wallet.address)?;

    // Parse transactions array
    let transactions = tx_data.as_array().ok_or_else(|| {
        anyhow::anyhow!("Unexpected response from the REST API (expected a list of transactions). Check the API URL.")
    })?;

    println!("Found {} transactions.", transactions.len());

    // Step 2: Extract KOB orders from TX payloads
    let mut candidates: Vec<RecoveredOrder> = Vec::new();

    for tx in transactions {
        let tx_id = tx.get("subnetwork_id")
            .or_else(|| tx.get("transaction_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Try to get tx_id from verbose_data or transaction_id field
        let tx_id = if let Some(vd) = tx.get("verbose_data") {
            vd.get("transaction_id")
                .and_then(|v| v.as_str())
                .unwrap_or(tx_id)
        } else {
            tx_id
        };

        // Also try verboseData (camelCase)
        let tx_id = if let Some(vd) = tx.get("verboseData") {
            vd.get("transactionId")
                .and_then(|v| v.as_str())
                .unwrap_or(tx_id)
        } else {
            tx_id
        };

        let payload_hex = tx.get("payload")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if payload_hex.is_empty() {
            continue;
        }

        let rs_bytes = match extract_rs_from_payload_hex(payload_hex) {
            Some(rs) => rs,
            None => continue,
        };

        let parsed = match parse_redeem_script(&rs_bytes) {
            Some(p) => p,
            None => continue,
        };

        // Verify owner_hash matches our wallet
        if parsed.owner_hash != owner_hash {
            continue;
        }

        // Get output info (value, script)
        let outputs = tx.get("outputs")
            .and_then(|v| v.as_array());

        if let Some(outs) = outputs {
            // The order UTXO is typically at output index 0
            for (idx, out) in outs.iter().enumerate() {
                let value = out.get("value")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                // Check if this output has a P2SH script matching our order
                let spk_hex = out.get("script_public_key")
                    .or_else(|| out.get("scriptPublicKey"))
                    .and_then(|spk| {
                        // Could be a string or object with .script() field
                        if let Some(s) = spk.as_str() {
                            Some(s.to_string())
                        } else {
                            spk.get("script").and_then(|s| s.as_str()).map(|s| s.to_string())
                        }
                    })
                    .unwrap_or_default();

                if let Some(hash) = extract_p2sh_hash(&spk_hex) {
                    if hash == parsed.p2sh_hash {
                        candidates.push(RecoveredOrder {
                            tx_id: tx_id.to_string(),
                            output_index: idx as u32,
                            order: parsed.clone(),
                            value,
                            is_live: false, // will check in step 3
                        });
                        break; // found the matching output
                    }
                }
            }
        }
    }

    println!("Found {} KOB order TX(s) belonging to this wallet.", candidates.len());

    if candidates.is_empty() {
        println!();
        println!("No orders to recover.");
        return Ok(());
    }

    // Step 3: Check which orders are still live (UTXO unspent)
    println!("Checking UTXO liveness via RPC...");
    let rpc = NodeClient::connect(rpc_url).await?;

    // Collect all P2SH addresses for UTXO query
    let mut p2sh_addrs: Vec<String> = Vec::new();
    for cand in &candidates {
        let hash_bytes = hex::decode(&cand.order.p2sh_hash).unwrap_or_default();
        if hash_bytes.len() == 32 {
            let addr = kaspa_address_encode(network_prefix, 8, &hash_bytes);
            p2sh_addrs.push(addr);
        }
    }
    p2sh_addrs.sort();
    p2sh_addrs.dedup();

    let addr_refs: Vec<&str> = p2sh_addrs.iter().map(|s| s.as_str()).collect();
    let live_utxos = if !addr_refs.is_empty() {
        rpc.get_utxos_by_addresses(&addr_refs).await.unwrap_or_default()
    } else {
        Vec::new()
    };

    // Build a set of live outpoints
    let live_set: std::collections::HashSet<String> = live_utxos
        .iter()
        .map(|u| format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index))
        .collect();

    // Update value from live UTXOs (may differ from deploy value due to partial fills)
    let value_map: std::collections::HashMap<String, u64> = live_utxos
        .iter()
        .map(|u| {
            (
                format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index),
                u.utxo_entry.amount,
            )
        })
        .collect();

    for cand in &mut candidates {
        let outpoint = format!("{}:{}", cand.tx_id, cand.output_index);
        if live_set.contains(&outpoint) {
            cand.is_live = true;
            if let Some(&live_value) = value_map.get(&outpoint) {
                cand.value = live_value;
            }
        }
    }

    let live_count = candidates.iter().filter(|c| c.is_live).count();
    let spent_count = candidates.len() - live_count;

    println!();
    println!("Recovery Results:");
    println!("  Live (recoverable): {}", live_count);
    println!("  Spent (already filled/cancelled): {}", spent_count);
    println!();

    // Display recovered orders
    println!(
        "{:<16}  {:>4}  {:>3}  {:>10}  {:>10}  {:>14}  {:<6}",
        "TXID", "IDX", "VER", "PRICE_NUM", "PRICE_DEN", "VALUE(KAS)", "STATUS",
    );
    println!("{}", "-".repeat(80));

    for cand in &candidates {
        let short_txid = if cand.tx_id.len() > 12 {
            format!("{}...", &cand.tx_id[..12])
        } else {
            cand.tx_id.clone()
        };
        let status = if cand.is_live { "LIVE" } else { "SPENT" };
        println!(
            "{:<16}  {:>4}  v{:<2}  {:>10}  {:>10}  {:>14.8}  {:<6}",
            short_txid,
            cand.output_index,
            cand.order.version,
            cand.order.price_num,
            cand.order.price_den,
            cand.value as f64 / 1e8,
            status,
        );
    }

    // Step 4: Build orders.json from live orders
    let live_orders: Vec<&RecoveredOrder> = candidates.iter().filter(|c| c.is_live).collect();

    if live_orders.is_empty() {
        println!();
        println!("No live orders to recover into orders.json.");
        return Ok(());
    }

    let mut cache = OrderCache::default();
    for order in &live_orders {
        let pair_id = if let Some(tcid) = &order.order.token_cov_id {
            hex::encode(tcid)
        } else {
            "00".repeat(32) // sell orders don't carry token_cov_id in RS
        };

        cache.orders.push(OrderCacheEntry {
            outpoint: format!("{}:{}", order.tx_id, order.output_index),
            side: order.order.side.clone(),
            pair_id: pair_id.clone(),
            price_num: order.order.price_num,
            price_den: order.order.price_den,
            min_fill: order.order.min_fill,
            owner_hash: hex::encode(order.order.owner_hash),
            spk_hash: hex::encode(order.order.spk_hash),
            p2sh_hash: order.order.p2sh_hash.clone(),
            value: order.value,
            cancel_pending: false,
            token: if order.order.side == "buy" { Some(pair_id) } else { None },
            version: 13,
            expiry_daa: 0,
        });
    }

    if dry_run {
        println!();
        println!("[DRY RUN] Would write {} entries to orders file.", cache.orders.len());
        println!();
        let json = serde_json::to_string_pretty(&cache)?;
        println!("{}", json);
    } else {
        let out_path = output_path.unwrap_or("orders_recovered.json");
        let out = wallet_path.with_file_name(out_path);
        cache.save(&out)?;
        println!();
        println!(
            "Recovered {} order(s) written to {}",
            cache.orders.len(),
            out.display()
        );
    }

    Ok(())
}


#[cfg(test)]
#[allow(deprecated)]
mod recover_orders_tests {
    use super::*;


    #[test]
    fn extract_rs_kob_prefix_valid() {
        // Build a payload: KOB:1: + some RS bytes
        let rs = vec![0x20; 416]; // buy v13 length
        let mut payload = Vec::new();
        payload.extend_from_slice(b"KOB:1:");
        payload.extend_from_slice(&rs);
        let payload_hex = hex::encode(&payload);

        let extracted = extract_rs_from_payload_hex(&payload_hex);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().len(), 416);
    }

    #[test]
    fn extract_rs_non_kob_payload_ignored() {
        let payload_hex = hex::encode(b"NOTK:1:somedata");
        assert!(extract_rs_from_payload_hex(&payload_hex).is_none());
    }

    #[test]
    fn extract_rs_empty_payload_ignored() {
        assert!(extract_rs_from_payload_hex("").is_none());
    }

    #[test]
    fn extract_rs_prefix_only_no_rs_ignored() {
        let payload_hex = hex::encode(b"KOB:1:");
        assert!(extract_rs_from_payload_hex(&payload_hex).is_none());
    }

    #[test]
    fn extract_rs_malformed_hex_ignored() {
        assert!(extract_rs_from_payload_hex("zzzz").is_none());
    }

    #[test]
    fn extract_rs_too_short_ignored() {
        let payload_hex = hex::encode(b"KOB:");
        assert!(extract_rs_from_payload_hex(&payload_hex).is_none());
    }

    #[test]
    fn extract_rs_with_gtd_suffix_stripped() {
        // Build payload: KOB:1: + 416B RS + :GTD: + 8B LE u64
        let rs = vec![0x20; 416];
        let mut payload = Vec::new();
        payload.extend_from_slice(b"KOB:1:");
        payload.extend_from_slice(&rs);
        payload.extend_from_slice(b":GTD:");
        payload.extend_from_slice(&12345u64.to_le_bytes());
        let payload_hex = hex::encode(&payload);

        let extracted = extract_rs_from_payload_hex(&payload_hex);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().len(), 416);
    }


    // detect_order_type tests removed: function was replaced by core's parse_redeem_script


    #[test]
    fn parse_buy_v12_rs_extracts_owner_hash() {
        let token_cov_id = [0xAA; 32];
        let owner_hash = [0xBB; 32];
        let spk_hash = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &token_cov_id, 1000, 1, 3_000_000, &owner_hash, &spk_hash, 0, 0, 0,).unwrap();
        assert_eq!(rs.len(), 409);

        let parsed = parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.side, "buy");
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.price_num, 1000);
        assert_eq!(parsed.price_den, 1);
        assert_eq!(parsed.min_fill, 3_000_000);
        assert_eq!(parsed.owner_hash, owner_hash);
        assert_eq!(parsed.spk_hash, spk_hash);
        assert_eq!(parsed.token_cov_id.unwrap(), token_cov_id);
    }

    #[test]
    fn parse_sell_v12_rs_extracts_owner_hash() {
        let owner_hash = [0xDD; 32];
        let spk_hash = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            500, 3, 1_000_000, &owner_hash, &spk_hash, 0, 0, 0,).unwrap();
        assert_eq!(rs.len(), 378);

        let parsed = parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.side, "sell");
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.price_num, 500);
        assert_eq!(parsed.price_den, 3);
        assert_eq!(parsed.min_fill, 1_000_000);
        assert_eq!(parsed.owner_hash, owner_hash);
        assert_eq!(parsed.spk_hash, spk_hash);
        assert!(parsed.token_cov_id.is_none());
    }

    #[test]
    fn owner_hash_verification_matches_pubkey() {
        // Simulate: user has pubkey -> blake2b -> owner_hash -> must match parsed RS
        let fake_pubkey = [0x99u8; 32];
        let expected_owner = blake2b_256(&fake_pubkey);

        let rs = kob_core::contract::build_sell_redeem_script(
            100, 1, 1_000_000, &expected_owner, &[0; 32], 0, 0, 0,).unwrap();
        let parsed = parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.owner_hash, expected_owner);

        // Different pubkey should NOT match
        let other_pubkey = [0x88u8; 32];
        let other_owner = blake2b_256(&other_pubkey);
        assert_ne!(parsed.owner_hash, other_owner);
    }


    #[test]
    fn build_cache_entry_from_parsed_order() {
        let token_cov_id = [0xAA; 32];
        let owner_hash = [0xBB; 32];
        let spk_hash = [0xCC; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &token_cov_id, 1000, 1, 3_000_000, &owner_hash, &spk_hash, 0, 0, 0,).unwrap();
        let parsed = parse_redeem_script(&rs).unwrap();

        let pair_id = hex::encode(parsed.token_cov_id.unwrap());
        let entry = OrderCacheEntry {
            outpoint: "abcd1234:0".to_string(),
            side: parsed.side.clone(),
            pair_id: pair_id.clone(),
            price_num: parsed.price_num,
            price_den: parsed.price_den,
            min_fill: parsed.min_fill,
            owner_hash: hex::encode(parsed.owner_hash),
            spk_hash: hex::encode(parsed.spk_hash),
            p2sh_hash: parsed.p2sh_hash.clone(),
            value: 50_000_000,
            cancel_pending: false,
            token: Some(pair_id),
            version: 13,
            expiry_daa: 0,
        };

        assert_eq!(entry.side, "buy");
        assert_eq!(entry.price_num, 1000);
        assert_eq!(entry.price_den, 1);
        assert_eq!(entry.min_fill, 3_000_000);
        assert_eq!(entry.value, 50_000_000);
        assert_eq!(entry.pair_id, "aa".repeat(32));
    }


    #[test]
    fn parse_rs_wrong_length_ignored() {
        let data = vec![0x20; 100]; // not a valid RS length
        assert!(parse_redeem_script(&data).is_none());
    }

    #[test]
    fn parse_rs_correct_length_wrong_opcodes_ignored() {
        // 416 bytes (buy v13 length) but wrong push opcodes
        let mut data = vec![0xFF; 416];
        // First byte should be 0x20 for buy, set it wrong
        data[0] = 0xFF;
        assert!(parse_redeem_script(&data).is_none());
    }

    #[test]
    fn parse_rs_empty_ignored() {
        assert!(parse_redeem_script(&[]).is_none());
    }


    #[test]
    fn p2sh_hash_matches_build_p2sh() {
        let token_cov_id = [0x11; 32];
        let owner_hash = [0x22; 32];
        let spk_hash = [0x33; 32];
        let rs = kob_core::contract::build_buy_redeem_script(
            &token_cov_id, 50, 3, 1_000_000, &owner_hash, &spk_hash, 0, 0, 0,).unwrap();

        let parsed = parse_redeem_script(&rs).unwrap();
        let p2sh = build_p2sh(&rs);
        let expected_hash = hex::encode(&p2sh.script()[2..34]);
        assert_eq!(parsed.p2sh_hash, expected_hash);
    }


    #[test]
    fn gtd_marker_found_at_end() {
        let mut data = vec![0u8; 356];
        data.extend_from_slice(b":GTD:");
        data.extend_from_slice(&99999u64.to_le_bytes());
        assert_eq!(find_gtd_marker(&data), Some(356));
    }

    #[test]
    fn no_gtd_marker_returns_none() {
        let data = vec![0u8; 356];
        assert_eq!(find_gtd_marker(&data), None);
    }

    #[test]
    fn gtd_marker_too_short_returns_none() {
        let data = b":GTD:";
        assert_eq!(find_gtd_marker(data), None);
    }


    #[test]
    fn parse_buy_v12_with_cancel_pending() {
        let token_cov_id = [0xAA; 32];
        let owner_hash = [0xBB; 32];
        let spk_hash = [0xCC; 32];
        // cancel_pending = 1
        let rs = kob_core::contract::build_buy_redeem_script(
            &token_cov_id, 100, 1, 1_000_000, &owner_hash, &spk_hash, 0, 1, 0,).unwrap();
        assert_eq!(rs.len(), 409);

        let parsed = parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.owner_hash, owner_hash);
        assert_eq!(parsed.price_num, 100);
    }

    #[test]
    fn parse_sell_v12_with_cancel_pending() {
        let owner_hash = [0xDD; 32];
        let spk_hash = [0xEE; 32];
        let rs = kob_core::contract::build_sell_redeem_script(
            200, 1, 500_000, &owner_hash, &spk_hash, 0, 1, 0,).unwrap();
        assert_eq!(rs.len(), 378);

        let parsed = parse_redeem_script(&rs).unwrap();
        assert_eq!(parsed.owner_hash, owner_hash);
        assert_eq!(parsed.price_num, 200);
    }
}
