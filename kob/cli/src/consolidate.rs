//! `kob-cli wallet consolidate` and `wallet utxos` -- UTXO management commands.
//!
//! `consolidate`: Merges many small UTXOs into fewer larger ones, reducing storage
//! mass costs. Groups UTXOs into batches of `max_inputs` and builds a self-send TX
//! per batch.
//!
//! `utxos`: Lists wallet UTXOs with detailed metadata (outpoint, value, type, age,
//! mass estimate).

use crate::node::NodeClient;
use crate::rpc::RpcUtxo;
use crate::signing;
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::Network;
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, converge_fee, estimate_compute_mass};
use std::path::Path;
use tracing::info;

/// Storage mass constant C = 10^12 (KIP-0009, same as kob_core::mass::STORAGE_MASS_PARAMETER).
const STORAGE_MASS_C: u64 = 1_000_000_000_000;

/// Default maximum inputs per consolidation TX (Kaspa mass limit).
#[allow(dead_code)] // Public API: used by CLI consolidate command
pub const DEFAULT_MAX_INPUTS: usize = 84;

/// Default target output count.
#[allow(dead_code)] // Public API: used by CLI consolidate command
pub const DEFAULT_TARGET_COUNT: usize = 1;


/// Sort order for UTXO listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoSortOrder {
    Value,
    Age,
}

impl UtxoSortOrder {
    pub fn parse_order(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "value" => Ok(Self::Value),
            "age" => Ok(Self::Age),
            other => Err(anyhow::anyhow!(
                "Unknown sort order '{}'. Use 'value' or 'age'.",
                other
            )),
        }
    }
}

/// Classify a UTXO script type from the script hex.
fn classify_script(script_hex: &str) -> &'static str {
    if script_hex.starts_with("aa20") && script_hex.ends_with("87") {
        "P2SH"
    } else if script_hex.starts_with("20") && script_hex.ends_with("ac") {
        "P2PK"
    } else {
        "OTHER"
    }
}

/// Estimate storage mass for a UTXO value.
/// mass = C / value (integer division). Returns u64::MAX for value=0.
pub fn storage_mass_estimate(value: u64) -> u64 {
    if value == 0 {
        return u64::MAX;
    }
    STORAGE_MASS_C / value
}

/// Format a UTXO entry as a display line.
fn format_utxo_line(u: &RpcUtxo, current_daa: u64) -> String {
    let kind = classify_script(&u.utxo_entry.script_public_key.script);
    let age = if current_daa > 0 && u.utxo_entry.block_daa_score > 0 {
        current_daa.saturating_sub(u.utxo_entry.block_daa_score)
    } else {
        0
    };
    let mass = storage_mass_estimate(u.utxo_entry.amount);
    let mass_str = if mass > 1_000_000 {
        format!("{}M", mass / 1_000_000)
    } else if mass > 1_000 {
        format!("{}K", mass / 1_000)
    } else {
        format!("{}", mass)
    };

    format!(
        "{}:{:<2}  {:>14}  {:>6}  {:>10}  {:>8}",
        u.outpoint.transaction_id,
        u.outpoint.index,
        u.utxo_entry.amount,
        kind,
        age,
        mass_str,
    )
}

/// Format a UTXO as a JSON object.
fn utxo_to_json(u: &RpcUtxo, current_daa: u64) -> serde_json::Value {
    let kind = classify_script(&u.utxo_entry.script_public_key.script);
    let age = if current_daa > 0 && u.utxo_entry.block_daa_score > 0 {
        current_daa.saturating_sub(u.utxo_entry.block_daa_score)
    } else {
        0
    };
    let mass = storage_mass_estimate(u.utxo_entry.amount);

    serde_json::json!({
        "outpoint": format!("{}:{}", u.outpoint.transaction_id, u.outpoint.index),
        "value": u.utxo_entry.amount,
        "type": kind,
        "age_daa": age,
        "mass_estimate": mass,
        "block_daa_score": u.utxo_entry.block_daa_score,
        "is_coinbase": u.utxo_entry.is_coinbase,
    })
}

/// Run the `wallet utxos` command.
///
/// Lists UTXOs with: outpoint, value, type (P2PK/P2SH), age (DAA delta), mass estimate.
pub async fn cmd_utxos(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    address_filter: Option<&str>,
    min_value: Option<u64>,
    sort: UtxoSortOrder,
    json_output: bool,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let query_address = address_filter.unwrap_or(&wallet.address);

    let rpc = NodeClient::connect(node_url).await?;

    // Get current DAA score for age calculation
    let node_info = rpc.call("getInfo", serde_json::json!({})).await.ok();
    let current_daa = node_info
        .as_ref()
        .and_then(|v| v.get("virtualDaaScore"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut utxos = rpc.get_utxos_by_addresses(&[query_address]).await?;

    // Apply min_value filter
    if let Some(min_val) = min_value {
        utxos.retain(|u| u.utxo_entry.amount >= min_val);
    }

    // Sort
    match sort {
        UtxoSortOrder::Value => {
            utxos.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));
        }
        UtxoSortOrder::Age => {
            utxos.sort_by(|a, b| {
                a.utxo_entry
                    .block_daa_score
                    .cmp(&b.utxo_entry.block_daa_score)
            });
        }
    }

    if json_output {
        let arr: Vec<serde_json::Value> =
            utxos.iter().map(|u| utxo_to_json(u, current_daa)).collect();
        let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
        let out = serde_json::json!({
            "address": query_address,
            "count": utxos.len(),
            "total_value": total,
            "current_daa_score": current_daa,
            "utxos": arr,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    // Table output
    let total: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
    let p2sh_count = utxos.iter().filter(|u| u.is_p2sh()).count();
    let p2pk_count = utxos.len() - p2sh_count;

    println!("Wallet UTXOs");
    println!("==================");
    println!("Address:  {}", query_address);
    println!(
        "Balance:  {} sompi ({:.8} KAS)",
        total,
        total as f64 / 1e8
    );
    println!(
        "UTXOs:    {} total ({} P2PK, {} P2SH)",
        utxos.len(),
        p2pk_count,
        p2sh_count
    );
    if current_daa > 0 {
        println!("DAA Score: {}", current_daa);
    }
    println!();

    if utxos.is_empty() {
        println!("(no UTXOs found)");
        return Ok(());
    }

    println!(
        "{:<68}  {:>14}  {:>6}  {:>10}  {:>8}",
        "OUTPOINT", "VALUE", "TYPE", "AGE(DAA)", "MASS"
    );
    println!("{}", "-".repeat(114));

    for u in &utxos {
        println!("{}", format_utxo_line(u, current_daa));
    }

    println!("{}", "-".repeat(114));
    println!(
        "{:<68}  {:>14}",
        format!("TOTAL ({} UTXOs)", utxos.len()),
        total,
    );

    // Storage mass summary
    let total_mass: u64 = utxos
        .iter()
        .map(|u| storage_mass_estimate(u.utxo_entry.amount))
        .fold(0u64, |acc, m| acc.saturating_add(m));
    println!();
    println!("Total storage mass estimate: {}", total_mass);
    if total > 0 {
        let consolidated_mass = storage_mass_estimate(total);
        if total_mass > consolidated_mass {
            println!(
                "If consolidated to 1 UTXO: {} (saves {})",
                consolidated_mass,
                total_mass - consolidated_mass
            );
        }
    }

    Ok(())
}


/// A batch of UTXOs to consolidate into a single transaction.
#[derive(Debug, Clone)]
pub struct ConsolidationBatch {
    /// The UTXO indices (into the original sorted list) included in this batch.
    pub utxo_indices: Vec<usize>,
    /// Total input value of all UTXOs in the batch.
    pub total_input: u64,
    /// Fee for this consolidation TX.
    pub fee: u64,
    /// Output value (total_input - fee).
    pub output_value: u64,
    /// Storage mass saved by this consolidation.
    pub mass_saved: u64,
}

/// Plan consolidation by grouping UTXOs into batches.
///
/// - Filters out excluded transaction IDs (stale-avoidance).
/// - Sorts eligible UTXOs by value ascending (smallest first).
/// - Groups into batches of `max_inputs`.
/// - Each batch produces `target_count` outputs (value split evenly, remainder on first).
/// - Returns empty vec if nothing to consolidate.
pub fn plan_consolidation(
    utxos: &[RpcUtxo],
    target_count: usize,
    min_value: Option<u64>,
    max_inputs: usize,
) -> Vec<ConsolidationBatch> {
    plan_consolidation_filtered(utxos, target_count, min_value, max_inputs, &[])
}

/// Plan consolidation with an explicit exclusion list of transaction IDs.
///
/// Any UTXO whose `outpoint.transaction_id` matches an entry in `exclude_txids`
/// is skipped. This lets callers avoid UTXOs stuck in a stale mempool.
pub fn plan_consolidation_filtered(
    utxos: &[RpcUtxo],
    target_count: usize,
    min_value: Option<u64>,
    max_inputs: usize,
    exclude_txids: &[String],
) -> Vec<ConsolidationBatch> {
    let target_count = target_count.max(1);
    let max_inputs = max_inputs.max(2); // need at least 2 inputs to consolidate

    // Filter: only P2PK UTXOs, optionally below min_value, exclude stale txids
    let mut eligible: Vec<(usize, &RpcUtxo)> = utxos
        .iter()
        .enumerate()
        .filter(|(_, u)| {
            // Only consolidate P2PK UTXOs (not covenant/P2SH UTXOs)
            !u.is_p2sh()
        })
        .filter(|(_, u)| {
            // Skip UTXOs from excluded (stale) transactions
            !exclude_txids.iter().any(|ex| ex == &u.outpoint.transaction_id)
        })
        .filter(|(_, u)| {
            if let Some(max_val) = min_value {
                u.utxo_entry.amount <= max_val
            } else {
                true
            }
        })
        .collect();

    // Need at least 2 UTXOs to consolidate
    if eligible.len() < 2 {
        return Vec::new();
    }

    // Sort by value ascending (smallest first — consolidate the dust first)
    eligible.sort_by(|a, b| a.1.utxo_entry.amount.cmp(&b.1.utxo_entry.amount));

    let mut batches = Vec::new();

    for chunk in eligible.chunks(max_inputs) {
        if chunk.len() < 2 {
            // Single UTXO, nothing to consolidate
            continue;
        }

        let total_input: u64 = chunk.iter().map(|(_, u)| u.utxo_entry.amount).sum();
        let fee = compute_consolidation_fee(chunk.len(), target_count);

        if total_input <= fee {
            // Not enough value to cover the fee
            continue;
        }

        let output_value = total_input - fee;

        // Check that each output would be above MIN_UTXO_VALUE
        let per_output = output_value / target_count as u64;
        if per_output < kob_core::MIN_UTXO_VALUE {
            continue;
        }

        // Calculate mass savings
        let input_mass: u64 = chunk
            .iter()
            .map(|(_, u)| storage_mass_estimate(u.utxo_entry.amount))
            .fold(0u64, |acc, m| acc.saturating_add(m));

        let output_mass = if target_count == 1 {
            storage_mass_estimate(output_value)
        } else {
            (0..target_count)
                .map(|i| {
                    let val = if i == 0 {
                        output_value - per_output * (target_count as u64 - 1)
                    } else {
                        per_output
                    };
                    storage_mass_estimate(val)
                })
                .fold(0u64, |acc, m| acc.saturating_add(m))
        };

        let mass_saved = input_mass.saturating_sub(output_mass);

        batches.push(ConsolidationBatch {
            utxo_indices: chunk.iter().map(|(i, _)| *i).collect(),
            total_input,
            fee,
            output_value,
            mass_saved,
        });
    }

    batches
}

/// Compute the estimated fee for a consolidation TX based on mass.
///
/// Uses `estimate_compute_mass` for compute mass, plus per-output storage mass
/// estimate. The actual fee is finalized with `converge_fee` at submission time.
pub fn compute_consolidation_fee(num_inputs: usize, num_outputs: usize) -> u64 {
    let compute_mass = estimate_compute_mass(num_inputs, num_outputs, 0);
    // Storage mass estimate: for N-to-1 consolidation, storage mass is typically
    // dominated by output term (C / out_value), which we cannot know here.
    // Use compute mass as the planning estimate; converge_fee corrects at submission.
    compute_mass
}

/// Run the `wallet consolidate` command.
///
/// Fetches UTXOs, plans consolidation batches, optionally executes them.
/// `exclude_txids` allows skipping UTXOs from specific transactions (stale-avoidance).
#[allow(clippy::too_many_arguments)]
pub async fn cmd_consolidate(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    target_count: usize,
    min_value: Option<u64>,
    max_inputs: usize,
    dry_run: bool,
    exclude_txids: &[String],
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let privkey = *wallet.privkey_bytes();

    println!("UTXO Consolidation{}", if dry_run { " (DRY RUN)" } else { "" });
    println!("==================");
    println!("Address:      {}", wallet.address);
    println!("Target count: {}", target_count);
    println!("Max inputs:   {}", max_inputs);
    if let Some(min_val) = min_value {
        println!(
            "Min value:    {} sompi ({:.8} KAS) -- only UTXOs at or below this value",
            min_val,
            min_val as f64 / 1e8
        );
    }
    println!();

    info!(address = %wallet.address, dry_run = dry_run, "consolidation starting");

    let rpc = NodeClient::connect(node_url).await?;
    let utxos = rpc.get_spendable_utxos(&wallet.address).await?;

    let p2pk_count = utxos.iter().filter(|u| !u.is_p2sh()).count();
    let p2sh_count = utxos.len() - p2pk_count;
    let total_value: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();

    println!(
        "Found {} UTXOs ({} P2PK, {} P2SH) totaling {} sompi ({:.8} KAS)",
        utxos.len(),
        p2pk_count,
        p2sh_count,
        total_value,
        total_value as f64 / 1e8,
    );

    // Report excluded txids (stale-avoidance)
    if !exclude_txids.is_empty() {
        let excluded_count = utxos.iter()
            .filter(|u| exclude_txids.iter().any(|ex| ex == &u.outpoint.transaction_id))
            .count();
        println!(
            "Excluding {} UTXO(s) from {} transaction ID(s) (--exclude-txid)",
            excluded_count,
            exclude_txids.len(),
        );
    }

    let batches = plan_consolidation_filtered(&utxos, target_count, min_value, max_inputs, exclude_txids);

    if batches.is_empty() {
        println!();
        println!("Nothing to consolidate. Need at least 2 eligible P2PK UTXOs.");
        return Ok(());
    }

    let total_inputs: usize = batches.iter().map(|b| b.utxo_indices.len()).sum();
    let total_fees: u64 = batches.iter().map(|b| b.fee).sum();
    let total_mass_saved: u64 = batches.iter().map(|b| b.mass_saved).sum();

    println!();
    println!(
        "Plan: {} batch(es), merging {} UTXOs into {} output(s) each",
        batches.len(),
        total_inputs,
        target_count
    );
    println!(
        "Total fees:       {} sompi ({:.8} KAS)",
        total_fees,
        total_fees as f64 / 1e8
    );
    println!("Mass savings est: {}", total_mass_saved);
    println!();

    // Show batch details
    for (batch_idx, batch) in batches.iter().enumerate() {
        println!(
            "Batch {}: {} inputs, {} sompi -> {} sompi (fee {} sompi, mass saved {})",
            batch_idx + 1,
            batch.utxo_indices.len(),
            batch.total_input,
            batch.output_value,
            batch.fee,
            batch.mass_saved,
        );
    }

    if dry_run {
        println!();
        println!("DRY RUN complete. No transactions submitted.");
        return Ok(());
    }

    println!();
    println!("Submitting consolidation transactions...");
    println!();

    let mut success_count = 0usize;
    let mut fail_count = 0usize;

    for (batch_idx, batch) in batches.iter().enumerate() {
        // Brief delay between batches to let mempool settle and avoid
        // referencing UTXOs that the node hasn't yet indexed as spent.
        if batch_idx > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        let batch_utxos: Vec<&RpcUtxo> =
            batch.utxo_indices.iter().map(|&i| &utxos[i]).collect();

        match submit_consolidation_tx(
            &rpc,
            &wallet,
            &privkey,
            &batch_utxos,
            target_count,
            batch.fee,
        )
        .await
        {
            Ok(tx_id) => {
                println!(
                    "Batch {}: SUCCESS -- {} inputs -> {} outputs, TXID: {}",
                    batch_idx + 1,
                    batch.utxo_indices.len(),
                    target_count,
                    tx_id,
                );
                success_count += 1;
            }
            Err(e) => {
                println!(
                    "Batch {}: FAILED -- {} inputs, error: {}",
                    batch_idx + 1,
                    batch.utxo_indices.len(),
                    e,
                );
                fail_count += 1;
            }
        }
    }

    println!();
    println!(
        "Done. {} succeeded, {} failed out of {} batches.",
        success_count,
        fail_count,
        batches.len()
    );

    Ok(())
}

/// Build and submit a single consolidation transaction.
///
/// TX structure (version 0, no covenants):
///   inputs:  N P2PK UTXOs (all from the same wallet address)
///   outputs: target_count P2PK outputs to the same wallet address
///
/// Uses 2-phase sign + converge_fee for exact mass-based fee.
async fn submit_consolidation_tx(
    rpc: &NodeClient,
    _wallet: &WalletContext,
    privkey: &[u8; 32],
    input_utxos: &[&RpcUtxo],
    target_count: usize,
    _est_fee: u64,
) -> anyhow::Result<String> {
    let total_input: u64 = input_utxos.iter().map(|u| u.utxo_entry.amount).sum();

    // Use the SPK from the first UTXO (they are all the same wallet address)
    let wallet_spk_version = input_utxos[0].utxo_entry.script_public_key.version;
    let wallet_spk_bytes = input_utxos[0].script_bytes();

    // Build transaction
    let mut tx = Transaction::new(0);

    for utxo in input_utxos {
        tx.inputs.push(TxInput {
            prev_tx_id: utxo.outpoint.transaction_id.clone(),
            prev_index: utxo.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: utxo.utxo_entry.script_public_key.version,
            script_bytes: utxo.script_bytes(),
            value: utxo.utxo_entry.amount,
        });
    }

    // Create tentative outputs (split evenly, adjusted by converge_fee)
    let tentative_fee = estimate_compute_mass(input_utxos.len(), target_count, 0);
    let tentative_output = total_input.saturating_sub(tentative_fee);
    if tentative_output == 0 {
        anyhow::bail!("Cannot consolidate: the combined UTXO value is too small to cover the fee. Add more UTXOs.");
    }

    let per_output = tentative_output / target_count as u64;
    let remainder = tentative_output - per_output * target_count as u64;

    for i in 0..target_count {
        let val = if i == 0 {
            per_output + remainder
        } else {
            per_output
        };
        tx.outputs.push(TxOutput::new(val, wallet_spk_version, wallet_spk_bytes.clone(), None));
    }

    // Phase 1: converge fee on the first output (it absorbs the remainder)
    let (est_fee, _) = converge_fee(&mut tx, total_input, 0, 0);

    // Re-split: output[0] got adjusted by converge_fee; redistribute evenly
    if target_count > 1 {
        let actual_output = total_input.saturating_sub(est_fee);
        let per_out = actual_output / target_count as u64;
        let rem = actual_output - per_out * target_count as u64;
        for i in 0..target_count {
            tx.outputs[i].value = if i == 0 { per_out + rem } else { per_out };
        }
    }

    // Verify outputs are above dust
    for (i, out) in tx.outputs.iter().enumerate() {
        if out.value < kob_core::MIN_UTXO_VALUE {
            anyhow::bail!(
                "Consolidation output {} value {} sompi below MIN_UTXO_VALUE. The UTXOs are too small to consolidate.",
                i, out.value
            );
        }
    }

    // Sign each input (phase 1)
    let mut sigscripts = Vec::with_capacity(tx.inputs.len());
    for i in 0..tx.inputs.len() {
        let sighash = compute_sighash(&tx, i)?;
        let signature = signing::schnorr_sign(privkey, &sighash)?;
        sigscripts.push(signing::build_p2pk_sigscript(&signature));
    }

    // Phase 2: exact mass check with real sigscripts
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = exact_mass;

    if exact_fee != est_fee {
        // Re-adjust outputs
        let actual_output = total_input.saturating_sub(exact_fee);
        let per_out = actual_output / target_count as u64;
        let rem = actual_output - per_out * target_count as u64;
        for i in 0..target_count {
            tx.outputs[i].value = if i == 0 { per_out + rem } else { per_out };
        }
        // Re-sign
        sigscripts.clear();
        for i in 0..tx.inputs.len() {
            let sighash = compute_sighash(&tx, i)?;
            let signature = signing::schnorr_sign(privkey, &sighash)?;
            sigscripts.push(signing::build_p2pk_sigscript(&signature));
        }
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    let tx_id = rpc.submit_transaction(payload).await?;

    Ok(tx_id)
}

/// Format the dry-run summary for a consolidation plan.
#[allow(dead_code)] // Public API: used by CLI consolidate --dry-run
pub fn format_dry_run_summary(
    batches: &[ConsolidationBatch],
    utxos: &[RpcUtxo],
    target_count: usize,
) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Consolidation Plan: {} batch(es), {} target output(s) each",
        batches.len(),
        target_count
    ));
    lines.push(String::new());

    for (i, batch) in batches.iter().enumerate() {
        lines.push(format!("Batch {}:", i + 1));
        lines.push(format!("  Inputs: {} UTXOs", batch.utxo_indices.len()));
        for &idx in &batch.utxo_indices {
            let u = &utxos[idx];
            lines.push(format!(
                "    {}:{} = {} sompi",
                &u.outpoint.transaction_id[..16],
                u.outpoint.index,
                u.utxo_entry.amount
            ));
        }
        lines.push(format!("  Total input:  {} sompi", batch.total_input));
        lines.push(format!("  Fee:          {} sompi", batch.fee));
        lines.push(format!("  Output value: {} sompi", batch.output_value));
        lines.push(format!("  Mass saved:   {}", batch.mass_saved));
        lines.push(String::new());
    }

    let total_inputs: usize = batches.iter().map(|b| b.utxo_indices.len()).sum();
    let total_outputs = batches.len() * target_count;
    let total_fees: u64 = batches.iter().map(|b| b.fee).sum();
    let total_mass_saved: u64 = batches.iter().map(|b| b.mass_saved).sum();

    lines.push(format!(
        "Summary: Merge {} UTXOs into {} output(s)",
        total_inputs, total_outputs
    ));
    lines.push(format!(
        "Total fees: {} sompi ({:.8} KAS)",
        total_fees,
        total_fees as f64 / 1e8
    ));
    lines.push(format!("Total mass savings: {}", total_mass_saved));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{RpcOutpoint, RpcSpk, RpcUtxo, RpcUtxoEntry};

    /// Helper to create a mock P2PK UTXO.
    fn mock_utxo(txid: &str, index: u32, amount: u64) -> RpcUtxo {
        RpcUtxo {
            outpoint: RpcOutpoint {
                transaction_id: txid.to_string(),
                index,
            },
            utxo_entry: RpcUtxoEntry {
                amount,
                script_public_key: RpcSpk {
                    version: 0,
                    // P2PK script: 0x20 + 32 bytes pubkey + 0xac
                    script: format!("20{}ac", "aa".repeat(32)),
                },
                block_daa_score: 100_000,
                is_coinbase: false,
            },
        }
    }

    /// Helper to create a mock P2SH UTXO.
    fn mock_p2sh_utxo(txid: &str, index: u32, amount: u64) -> RpcUtxo {
        RpcUtxo {
            outpoint: RpcOutpoint {
                transaction_id: txid.to_string(),
                index,
            },
            utxo_entry: RpcUtxoEntry {
                amount,
                script_public_key: RpcSpk {
                    version: 0,
                    // P2SH script: 0xaa + 0x20 + 32 bytes hash + 0x87
                    script: format!("aa20{}87", "bb".repeat(32)),
                },
                block_daa_score: 100_000,
                is_coinbase: false,
            },
        }
    }


    #[test]
    fn storage_mass_zero_value() {
        assert_eq!(storage_mass_estimate(0), u64::MAX);
    }

    #[test]
    fn storage_mass_large_value() {
        // 100 KAS = 10_000_000_000 sompi
        let mass = storage_mass_estimate(10_000_000_000);
        assert_eq!(mass, 100); // 1e12 / 1e10 = 100
    }

    #[test]
    fn storage_mass_small_value() {
        // 0.04 KAS = 4_000_000 sompi
        let mass = storage_mass_estimate(4_000_000);
        assert_eq!(mass, 250_000); // 1e12 / 4e6 = 250,000
    }

    #[test]
    fn storage_mass_dust_value() {
        // 1000 sompi -- extremely high mass
        let mass = storage_mass_estimate(1_000);
        assert_eq!(mass, 1_000_000_000); // 1e12 / 1e3 = 1e9
    }


    #[test]
    fn fee_single_input_single_output() {
        let fee = compute_consolidation_fee(1, 1);
        let expected = estimate_compute_mass(1, 1, 0);
        assert_eq!(fee, expected);
    }

    #[test]
    fn fee_many_inputs_single_output() {
        let fee = compute_consolidation_fee(84, 1);
        let expected = estimate_compute_mass(84, 1, 0);
        assert_eq!(fee, expected);
        // More inputs => higher fee
        assert!(fee > compute_consolidation_fee(1, 1));
    }

    #[test]
    fn fee_many_inputs_multiple_outputs() {
        let fee = compute_consolidation_fee(10, 3);
        let expected = estimate_compute_mass(10, 3, 0);
        assert_eq!(fee, expected);
        // More outputs => higher fee than same inputs with 1 output
        assert!(fee > compute_consolidation_fee(10, 1));
    }


    #[test]
    fn plan_empty_utxos() {
        let utxos: Vec<RpcUtxo> = Vec::new();
        let batches = plan_consolidation(&utxos, 1, None, 84);
        assert!(batches.is_empty());
    }

    #[test]
    fn plan_single_utxo_no_consolidation() {
        let utxos = vec![mock_utxo(&"a".repeat(64), 0, 10_000_000)];
        let batches = plan_consolidation(&utxos, 1, None, 84);
        assert!(batches.is_empty(), "single UTXO cannot be consolidated");
    }

    #[test]
    fn plan_two_utxos_basic() {
        let utxos = vec![
            mock_utxo(&"a".repeat(64), 0, 5_000_000),
            mock_utxo(&"b".repeat(64), 0, 5_000_000),
        ];
        let batches = plan_consolidation(&utxos, 1, None, 84);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].utxo_indices.len(), 2);
        assert_eq!(batches[0].total_input, 10_000_000);
        // fee = estimate_compute_mass(2, 1, 0)
        let expected_fee = compute_consolidation_fee(2, 1);
        assert_eq!(batches[0].fee, expected_fee);
        assert_eq!(batches[0].output_value, 10_000_000 - expected_fee);
    }

    #[test]
    fn plan_respects_max_inputs() {
        // Create 10 UTXOs, max 5 per batch
        let utxos: Vec<RpcUtxo> = (0..10)
            .map(|i| {
                let txid = format!("{:0>64}", format!("{:x}", i));
                mock_utxo(&txid, 0, 5_000_000)
            })
            .collect();

        let batches = plan_consolidation(&utxos, 1, None, 5);
        assert_eq!(batches.len(), 2, "10 UTXOs / 5 max = 2 batches");
        assert_eq!(batches[0].utxo_indices.len(), 5);
        assert_eq!(batches[1].utxo_indices.len(), 5);
    }

    #[test]
    fn plan_filters_p2sh() {
        let utxos = vec![
            mock_utxo(&"a".repeat(64), 0, 5_000_000),
            mock_p2sh_utxo(&"b".repeat(64), 0, 5_000_000),
            mock_utxo(&"c".repeat(64), 0, 5_000_000),
        ];
        let batches = plan_consolidation(&utxos, 1, None, 84);
        assert_eq!(batches.len(), 1);
        // Only the 2 P2PK UTXOs should be included
        assert_eq!(batches[0].utxo_indices.len(), 2);
    }

    #[test]
    fn plan_min_value_filter() {
        let utxos = vec![
            mock_utxo(&"a".repeat(64), 0, 5_000_000),      // small
            mock_utxo(&"b".repeat(64), 0, 100_000_000),     // large (1 KAS)
            mock_utxo(&"c".repeat(64), 0, 4_000_000),       // small
        ];
        // Only consolidate UTXOs <= 10_000_000 sompi
        let batches = plan_consolidation(&utxos, 1, Some(10_000_000), 84);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].utxo_indices.len(), 2);
        // The 100_000_000 UTXO should be excluded
        assert_eq!(batches[0].total_input, 9_000_000);
    }

    #[test]
    fn plan_exclude_txids() {
        let txid_a = "a".repeat(64);
        let txid_b = "b".repeat(64);
        let txid_c = "c".repeat(64);
        let utxos = vec![
            mock_utxo(&txid_a, 0, 5_000_000),
            mock_utxo(&txid_b, 0, 5_000_000),
            mock_utxo(&txid_c, 0, 5_000_000),
        ];
        // Exclude txid_b -- should leave only txid_a and txid_c
        let excluded = vec![txid_b.clone()];
        let batches = plan_consolidation_filtered(&utxos, 1, None, 84, &excluded);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].utxo_indices.len(), 2);
        assert_eq!(batches[0].total_input, 10_000_000);
    }

    #[test]
    fn plan_exclude_all_leaves_nothing() {
        let txid_a = "a".repeat(64);
        let txid_b = "b".repeat(64);
        let utxos = vec![
            mock_utxo(&txid_a, 0, 5_000_000),
            mock_utxo(&txid_b, 0, 5_000_000),
        ];
        let excluded = vec![txid_a.clone(), txid_b.clone()];
        let batches = plan_consolidation_filtered(&utxos, 1, None, 84, &excluded);
        assert!(batches.is_empty(), "all UTXOs excluded, nothing to consolidate");
    }

    #[test]
    fn plan_dust_utxos_too_small() {
        // Two UTXOs so tiny their total is less than the fee
        let utxos = vec![
            mock_utxo(&"a".repeat(64), 0, 500),
            mock_utxo(&"b".repeat(64), 0, 500),
        ];
        let batches = plan_consolidation(&utxos, 1, None, 84);
        assert!(
            batches.is_empty(),
            "total 1000 sompi < fee, should produce no batches"
        );
    }

    #[test]
    fn plan_target_count_multiple_outputs() {
        let utxos: Vec<RpcUtxo> = (0..5)
            .map(|i| {
                let txid = format!("{:0>64}", format!("{:x}", i));
                mock_utxo(&txid, 0, 10_000_000)
            })
            .collect();

        let batches = plan_consolidation(&utxos, 2, None, 84);
        assert_eq!(batches.len(), 1);
        // Each of 2 outputs should be above MIN_UTXO_VALUE
        let per_output = batches[0].output_value / 2;
        assert!(
            per_output >= kob_core::MIN_UTXO_VALUE,
            "per_output {} must be >= MIN_UTXO_VALUE",
            per_output
        );
    }

    #[test]
    fn plan_mass_savings_positive() {
        // Many small UTXOs have high mass; consolidated into 1 has low mass
        let utxos: Vec<RpcUtxo> = (0..10)
            .map(|i| {
                let txid = format!("{:0>64}", format!("{:x}", i));
                mock_utxo(&txid, 0, 4_000_000) // high mass each
            })
            .collect();

        let batches = plan_consolidation(&utxos, 1, None, 84);
        assert_eq!(batches.len(), 1);
        assert!(
            batches[0].mass_saved > 0,
            "consolidating high-mass UTXOs should save mass"
        );
    }


    #[test]
    fn classify_p2pk() {
        let script = format!("20{}ac", "aa".repeat(32));
        assert_eq!(classify_script(&script), "P2PK");
    }

    #[test]
    fn classify_p2sh() {
        let script = format!("aa20{}87", "bb".repeat(32));
        assert_eq!(classify_script(&script), "P2SH");
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify_script("0014abcd"), "OTHER");
    }


    #[test]
    fn dry_run_summary_format() {
        let utxos = vec![
            mock_utxo(&"a".repeat(64), 0, 5_000_000),
            mock_utxo(&"b".repeat(64), 0, 5_000_000),
        ];
        let batches = plan_consolidation(&utxos, 1, None, 84);
        let summary = format_dry_run_summary(&batches, &utxos, 1);
        assert!(summary.contains("Batch 1:"));
        assert!(summary.contains("Inputs: 2 UTXOs"));
        assert!(summary.contains("Summary:"));
        assert!(summary.contains("Merge 2 UTXOs"));
    }


    #[test]
    fn utxo_json_format() {
        let utxo = mock_utxo(&"a".repeat(64), 0, 10_000_000);
        let json = utxo_to_json(&utxo, 200_000);
        assert_eq!(json["value"], 10_000_000);
        assert_eq!(json["type"], "P2PK");
        assert_eq!(json["age_daa"], 100_000); // 200_000 - 100_000
        assert!(json["outpoint"].as_str().unwrap().contains(":0"));
    }

    #[test]
    fn utxo_json_no_daa() {
        let utxo = mock_utxo(&"a".repeat(64), 0, 10_000_000);
        let json = utxo_to_json(&utxo, 0);
        assert_eq!(json["age_daa"], 0);
    }
}
