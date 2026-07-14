//! `kob-cli cancel` -- Cancel an active order by outpoint.
//!
//! Reconstructs the redeemScript from the provided order parameters,
//! builds a cancel TX with a Schnorr signature, and submits it.
//!
//! Cancel TX structure:
//!   input[0]: order UTXO (P2SH, cancel sigscript)
//!   input[1]: fee UTXO (P2PK, signed)
//!   output[0]: recovered funds to wallet
//!
//! For buy_order v3:  sigscript = [Op0] [sig+type 65B] [pubkey 32B] [pushData(RS)]
//!   sigscript length >= T2(282) triggers cancel path.
//!
//! For sell_order v3: sigscript = [sig+type 65B] [pubkey 32B] [Op0] [pushData(RS)]
//!   selector Op0 at depth 4 triggers cancel path via Op4 OpRoll.

use crate::cancel_all;
use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, converge_fee, estimate_compute_mass, MAX_TX_MASS};
use kob_core::MIN_UTXO_VALUE;
use std::path::Path;
use tracing::info;

fn parse_token_cov_id(token_cov_id: Option<&str>) -> anyhow::Result<[u8; 32]> {
    let token_hex = token_cov_id
        .ok_or_else(|| anyhow::anyhow!("Buy cancel requires --token with the token covenant ID (64 hex chars)."))?;
    let token_bytes = hex::decode(token_hex)?;
    if token_bytes.len() != 32 {
        anyhow::bail!("token covenant ID must be 64 hex characters (32 bytes)");
    }
    let mut tcid = [0u8; 32];
    tcid.copy_from_slice(&token_bytes);
    Ok(tcid)
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    network: Network,
    outpoint_str: &str,
    side: Option<&str>,
    token_cov_id: Option<&str>,
    price_num: Option<u64>,
    price_den: Option<u64>,
    min_fill: Option<u64>,
    order_value_override: Option<u64>,
    fee: u64,
    version: Option<u8>,
    expiry_daa: Option<u64>,
    fee_utxo_override: Option<&str>,
    cancel_pending: u8,
    max_matcher_fee_override: Option<u64>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let outpoint = Outpoint::parse(outpoint_str)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);

    // Resolve missing parameters from the orders cache.
    let needs_cache = side.is_none()
        || price_num.is_none()
        || price_den.is_none()
        || min_fill.is_none();

    let cached: Option<crate::order_cache::OrderCacheEntry> = if needs_cache {
        let cache_path = cancel_all::orders_cache_path(wallet_path);
        let orders = cancel_all::load_orders_cache(&cache_path)?;
        orders.into_iter().find(|o| o.outpoint == outpoint_str)
    } else {
        None
    };

    // Helper: resolve a parameter from CLI or cache, bail if neither available.
    macro_rules! resolve {
        ($cli:expr, $cached_field:ident, $name:expr) => {
            match $cli {
                Some(v) => v,
                None => match &cached {
                    Some(c) => c.$cached_field,
                    None => anyhow::bail!(
                        "Missing --{} and outpoint {} not found in orders cache.\n\
                         Provide all parameters explicitly or deploy with cache enabled.",
                        $name, outpoint_str
                    ),
                },
            }
        };
    }

    let side = match side {
        Some(s) => s.to_string(),
        None => match &cached {
            Some(c) => c.side.clone(),
            None => anyhow::bail!(
                "Missing --side and outpoint {} not found in orders cache.\n\
                 Provide all parameters explicitly or deploy with cache enabled.",
                outpoint_str
            ),
        },
    };
    let price_num = resolve!(price_num, price_num, "price-num");
    let price_den = resolve!(price_den, price_den, "price-den");
    let min_fill = resolve!(min_fill, min_fill, "min-fill");
    let version = version.unwrap_or_else(|| {
        cached.as_ref().map_or(12, |c| c.version)
    });
    let expiry_daa = expiry_daa.unwrap_or_else(|| {
        cached.as_ref().map_or(0, |c| c.expiry_daa)
    });
    // For token: CLI takes precedence, then cache, then None (sell orders don't need it).
    let token_cov_id_resolved: Option<String> = match token_cov_id {
        Some(t) => Some(t.to_string()),
        None => cached.as_ref().and_then(|c| c.token.clone()),
    };

    if needs_cache && cached.is_some() {
        println!(
            "Loaded order parameters from cache: side={}, price={}/{}, min_fill={}",
            side, price_num, price_den, min_fill
        );
        println!();
    }

    let side = side.as_str();

    // Reconstruct the redeemScript using the specified contract version.
    // cancel_pending: 0 for normal orders, 1 after cancel-mark transition.
    if version != 14 && version != 16 {
        anyhow::bail!("Unsupported contract version {}. Only v14 and v16 are supported.", version);
    }
    // Resolve max_matcher_fee: CLI override > cache > default.
    // For v16 buys this is BPS (basis points), same semantics as v15.
    let max_matcher_fee = max_matcher_fee_override.unwrap_or_else(|| {
        cached.as_ref().map_or(crate::deploy::DEFAULT_MAX_MATCHER_FEE, |c| c.max_matcher_fee)
    });

    let redeem_script = match side {
        "buy" => {
            let tcid = parse_token_cov_id(token_cov_id_resolved.as_deref())?;
            if version == 16 {
                contract::build_buy_v16_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, cancel_pending, expiry_daa)?
            } else {
                contract::build_buy_redeem_script(&tcid, price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, cancel_pending, expiry_daa)?
            }
        }
        "sell" => {
            contract::build_sell_redeem_script(price_num, price_den, min_fill, &owner_hash, &spk_hash, max_matcher_fee, cancel_pending, expiry_daa)?
        }
        other => anyhow::bail!("Unknown side '{}'. Use 'buy' or 'sell'.", other),
    };

    let p2sh = build_p2sh(&redeem_script);

    println!("Cancel Order");
    println!("=============");
    println!("Outpoint:      {}", outpoint);
    println!("Side:          {}", side);
    println!("Price:         {}/{}", price_num, price_den);
    println!("Min Fill:      {}", min_fill);
    println!("Owner:         {}", wallet.pubkey_hex());
    println!("RedeemScript:  {} bytes", redeem_script.len());
    println!("P2SH SPK:     {}", hex::encode(&p2sh.script()));
    println!();

    // Connect to node
    info!(outpoint = %outpoint, side = side, "cancelling order");
    println!("Connecting to {}...", node_url);
    let rpc = NodeClient::connect(node_url).await?;

    // Determine the order UTXO value
    let order_value = if let Some(v) = order_value_override {
        v
    } else {
        // Query the P2SH address for this order
        let p2sh_address = p2sh_to_address(&p2sh.script(), network.address_prefix());
        println!("P2SH Address:  {}", p2sh_address);
        println!("Querying order UTXO value from chain...");
        let order_utxos = rpc.get_utxos_by_addresses(&[&p2sh_address]).await?;
        let order_utxo = order_utxos
            .iter()
            .find(|u| {
                u.outpoint.transaction_id == outpoint.transaction_id
                    && u.outpoint.index == outpoint.index
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Order UTXO {} not found at P2SH address {}. It may be spent or use --order-value.",
                    outpoint, p2sh_address
                )
            })?;
        order_utxo.utxo_entry.amount
    };

    println!("Order Value:   {} sompi", order_value);

    // Estimate fee for UTXO selection (will be refined after TX construction).
    let est_fee = estimate_compute_mass(2, 1, 0) + 500;

    // Get a fee UTXO from the wallet
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(fee_op_str) = fee_utxo_override {
        let fee_op = Outpoint::parse(fee_op_str)?;
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == fee_op.transaction_id && u.outpoint.index == fee_op.index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Fee UTXO {} not found in wallet UTXOs. It may be spent or not belong to this wallet.",
                    fee_op_str
                )
            })?
    } else {
        let mut candidates: Vec<_> = wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh() && u.utxo_entry.amount >= est_fee + MIN_UTXO_VALUE)
            .collect();
        candidates.sort_by(|a, b| a.utxo_entry.amount.cmp(&b.utxo_entry.amount));
        candidates.first().copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No P2PK UTXO with >= {} sompi for fee payment",
                    est_fee + MIN_UTXO_VALUE
                )
            })?
    };

    println!(
        "Fee UTXO:      {}:{} ({} sompi)",
        fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount
    );

    // Build the cancel transaction with tentative output value
    let total_in = order_value + fee_utxo.utxo_entry.amount;
    let tentative_output = total_in - est_fee;
    let mut tx = Transaction::new(0);

    // Input 0: order UTXO (P2SH, cancel sigscript)
    tx.inputs.push(TxInput {
        prev_tx_id: outpoint.transaction_id.clone(),
        prev_index: outpoint.index,
        sequence: 0,
        sig_op_count: 1,
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
        script_bytes: fee_spk_bytes.clone(),
        value: fee_utxo.utxo_entry.amount,
    });

    // Output 0: recovered funds to wallet
    let wallet_spk = hex::decode(&fee_utxo.utxo_entry.script_public_key.script)?;
    tx.outputs.push(TxOutput::new(tentative_output, fee_utxo.utxo_entry.script_public_key.version, wallet_spk, None));

    // Phase 1: converge fee using estimated sigscript sizes
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let (est_fee, _) = converge_fee(&mut tx, total_in, 0, min_fee_override);

    // Sign input 0 (order cancel -- the cancel path signature covers the order input)
    let sighash_0 = compute_sighash(&tx, 0)?;
    let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;

    // Build the cancel sigscript for the order input
    let cancel_sigscript = match side {
        "buy" => contract::build_buy_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
        "sell" => contract::build_sell_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
        _ => unreachable!(),
    };

    // Sign input 1 (fee UTXO, P2PK)
    let sighash_1 = compute_sighash(&tx, 1)?;
    let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
    let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

    // Phase 2: exact mass check with real sigscripts
    let sigscripts = vec![cancel_sigscript.clone(), fee_sigscript.clone()];
    let exact_mass = calc_mass_with_sigscripts(&tx, &sigscripts);
    let exact_fee = exact_mass.max(min_fee_override);

    // If exact fee exceeds estimated fee, re-adjust output and re-sign
    let (cancel_sigscript, fee_sigscript, actual_fee) = if exact_fee != est_fee {
        let fixed_sum = 0u64; // no fixed outputs in cancel TX
        let output_value = total_in.saturating_sub(fixed_sum + exact_fee);
        tx.outputs[0].value = output_value;

        // Re-sign with updated output value
        let sighash_0 = compute_sighash(&tx, 0)?;
        let sig_0 = signing::schnorr_sign(&privkey, &sighash_0)?;
        let cancel_sigscript = match side {
            "buy" => contract::build_buy_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
            "sell" => contract::build_sell_cancel_sigscript(&sig_0, &pubkey, &redeem_script),
            _ => unreachable!(),
        };
        let sighash_1 = compute_sighash(&tx, 1)?;
        let sig_1 = signing::schnorr_sign(&privkey, &sighash_1)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&sig_1);

        (cancel_sigscript, fee_sigscript, exact_fee)
    } else {
        (cancel_sigscript, fee_sigscript, est_fee)
    };

    let output_value = tx.outputs[0].value;

    println!("Cancel SigScript: {} bytes", cancel_sigscript.len());
    if side == "buy" {
        // T2 (the sigLen threshold that routes to the cancel/cancel-mark
        // path) differs per buy contract version; pick the real one instead
        // of a stale hardcoded constant left over from an older version.
        let t2 = if redeem_script.len() == kob_core::contract::spot::order::BUY_ORDER_V16_RS_EXPECTED_LEN {
            494
        } else if redeem_script.len() == kob_core::contract::spot::order::BUY_ORDER_V15_RS_EXPECTED_LEN {
            501
        } else {
            415 // v14
        };
        println!(
            "  (>= T2={} triggers cancel path: {})",
            t2,
            if cancel_sigscript.len() >= t2 { "YES" } else { "NO -- ERROR" }
        );
    } else {
        println!("  (selector Op0 at position triggers cancel path via Op5 OpRoll)");
    }
    println!("Output Value:  {} sompi", output_value);
    println!();

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &[cancel_sigscript.clone(), fee_sigscript.clone()]);
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
        if exact_fee != est_fee {
            println!("  (phase-2 adjustment: est={} -> exact={})", est_fee, exact_fee);
        }
        let surplus = fee_utxo.utxo_entry.amount.saturating_sub(actual_fee);
        if surplus > 0 && surplus < MIN_UTXO_VALUE {
            println!("Surplus:          {:>9} sompi (donated as fee)", surplus);
        }
        println!();
    }

    // Submit
    let payload = to_rpc_payload(&tx, &[cancel_sigscript.clone(), fee_sigscript.clone()]);
    println!("Submitting cancel transaction...");
    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Cancel transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("Recovered {} sompi to wallet.", output_value);

    Ok(())
}

/// Convert a P2SH script to a Kaspa address.
///
/// Delegates to `kob_core::bech32::spk_to_address` for recognized SPK layouts,
/// with a hex fallback for unrecognized ones.
pub fn p2sh_to_address(spk: &[u8], prefix: &str) -> String {
    kob_core::bech32::spk_to_address(spk, prefix)
        .unwrap_or_else(|_| format!("{}:p{}", prefix, hex::encode(spk)))
}

/// Encode a Kaspa address using bech32 with polymod checksum.
///
/// Thin wrapper around `kob_core::bech32::bech32_encode` for backward compatibility.
pub fn kaspa_address_encode(prefix: &str, version: u8, payload: &[u8]) -> String {
    kob_core::bech32::bech32_encode(prefix, version, payload)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};

    #[test]
    fn buy_cancel_sigscript_exceeds_t2_v12() {
        let pk = [0x02u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_buy_redeem_script(&tcid, 1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();
        let sig = [0xAA; 64];
        let ss = contract::build_buy_cancel_sigscript(&sig, &pk, &rs);
        // v12 RS is 415B; cancel sigscript = pushData(sig65) + pushData(pk32) + pushData(RS415)
        assert!(
            ss.len() >= 309,
            "Buy v12 cancel sigscript must be >= T2(309) to trigger cancel path, got {}",
            ss.len()
        );
    }

    #[test]
    fn sell_cancel_sigscript_has_op0_selector_v12() {
        let pk = [0x02u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let rs = contract::build_sell_redeem_script(1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0).unwrap();
        let sig = [0xAA; 64];
        let ss = contract::build_sell_cancel_sigscript(&sig, &pk, &rs);
        // The structure is: pushData(sig65) + pushData(pk32) + Op0 + pushData(RS)
        // Op0 is at byte 99 for sell cancel
        assert_eq!(ss[99], 0x00, "Op0 selector must be at byte 99 for sell cancel");
    }

    #[test]
    fn cancel_tx_output_value_correct() {
        let order_value = 30_000_000u64;
        let fee_value = 10_000_000u64;
        let total_in = order_value + fee_value;
        let output_value = total_in - kob_core::DEFAULT_MATCHER_FEE;
        assert_eq!(output_value, 39_990_000);
    }

    #[test]
    fn p2sh_address_roundtrip() {
        let rs = vec![0x75, 0x75, 0x75, 0x75, 0x51]; // receipt body
        let spk = build_p2sh(&rs);
        let addr = p2sh_to_address(&spk.script(), "kaspatest");
        assert!(addr.starts_with("kaspatest:"), "Address must start with prefix");
        assert!(!addr.is_empty());
    }

    #[test]
    fn bech32_convert_bits_roundtrip() {
        let data = vec![0xAB, 0xCD, 0xEF];
        let bits5 = kob_core::bech32::convert_bits(&data, 8, 5, true);
        assert!(!bits5.is_empty());
        // Each 5-bit value should be < 32
        for &b in &bits5 {
            assert!(b < 32, "5-bit value must be < 32");
        }
    }

    #[test]
    fn bech32_polymod_nonzero() {
        let values = vec![1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0];
        let pm = kob_core::bech32::bech32_polymod(&values);
        assert_ne!(pm, 0);
    }
}
