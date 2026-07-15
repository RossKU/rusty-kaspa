//! `kob-cli match` -- Execute a match between a buy and sell order.
//!
//! The non-tamper path delegates transaction construction to the canonical
//! kob-domain planner (`kob_domain::batch::plan_batch_match` +
//! `converge_fee_exact` / `apply_exact_fee`) -- the same planner `match-batch`
//! and the engine's executor use. This guarantees the base match tx is
//! F6-correct: matcher surplus is capped via the planner's `fee_bps`
//! mechanism instead of the matcher folding 100% of the price spread into
//! its own change output, so a v16 buy order's on-chain
//! `max_surplus = kas/10000*mmfee_bps` check is respected by construction
//! (see `apply_bps_cap` in kob-domain's `spot/batch.rs`) rather than merely
//! hoped for.
//!
//! CLI-specific glue that stays here (not delegated): outpoint/pubkey
//! parsing, RPC value lookup, RPC submission, and the unique `TamperMode`
//! adversarial-test mutation, which is applied AFTER the canonical tx is
//! built (see `apply_tamper`) so the covenant-rejection test capability
//! keeps exercising real consensus bytecode on top of a correctly-built tx.
//!
//! Note: unlike the pre-consolidation implementation, this path does not
//! emit a `trade_receipt` output -- neither does `match-batch` (the
//! documented production match path; see `E2E_MATRIX.md`/`V16_STATUS.md`),
//! and receipts are no longer part of the v16-era match flow. Use
//! `kob-cli receipt create` directly if a receipt is needed downstream.
//!
//! Standard Match TX layout (same token pair, no wallet-fee UTXO needed
//! when the trade surplus alone covers the fee):
//!   input[0]: sell_order (P2SH, fill sigscript, sigOpCount=0)
//!   input[1]: buy_order  (P2SH, fill sigscript, sigOpCount=0)
//!   input[2]: fee UTXO   (P2PK, signed, sigOpCount=1)  [when a wallet UTXO
//!                         is available; the planner always uses one here
//!                         so the matcher fee output is deterministic]
//!
//!   output[0]: seller KAS     (>= expected_kas from sell contract)
//!   output[1]: buyer tokens   (>= expected_tokens from buy contract)
//!   output[2]: matcher fee    (optional; bps-capped when --fee-bps or a
//!                              v16 buy's --mmfee-bps is in effect)
//!
//! Cross-Pair Match TX layout (--cross-pair, v8-v13 only) is unchanged and
//! documented on `run_cross_pair` below -- it is NOT routed through the
//! canonical planner; see that function's doc comment for why.

use crate::node::NodeClient;
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, MAX_TX_MASS};
use kob_core::{MIN_UTXO_VALUE, RECEIPT_DUST, RECEIPT_VALUE};
use kob_domain::batch::{plan_batch_match, BatchOrder, OrderType, OutputPurpose};
use std::path::Path;
use tracing::info;

/// Adversarial tamper modes for security testing.
///
/// These modes deliberately construct invalid match TXs to verify that the
/// covenant bytecode (enforced at consensus level) rejects them.
/// ONLY for testing. The node MUST reject every tampered TX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperMode {
    /// A01-1: Replace seller's KAS output SPK with attacker address.
    /// Violates F2: output[0].spk.blake2b != sspkh baked in sell redeem script.
    F2RedirectSeller,
    /// A01-2: Replace buyer's token output SPK with attacker address.
    /// Violates F2: output[1].spk.blake2b != bspkh baked in buy redeem script.
    F2RedirectBuyer,
    /// A02-1: Remove covenant binding from buyer token output.
    /// Violates F4: covenant output count check fails.
    F4RemoveBinding,
    /// A02-2: Reduce buyer token output value to 1 sompi below expected.
    /// Violates F4: covenant_output.value < expected_tokens.
    F4ReduceValue,
}

impl TamperMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "f2-redirect-seller" => Some(Self::F2RedirectSeller),
            "f2-redirect-buyer" => Some(Self::F2RedirectBuyer),
            "f4-remove-binding" => Some(Self::F4RemoveBinding),
            "f4-reduce-value" => Some(Self::F4ReduceValue),
            _ => None,
        }
    }
}

/// Apply an adversarial `TamperMode` mutation to an already-built match tx.
///
/// Mutates `tx.outputs` in place. Callers MUST re-sign any signed input
/// (the wallet fee input) after calling this, since its signature covers
/// the outputs. This is intentionally the ONLY place that touches outputs
/// after the canonical planner has built them -- everything else about the
/// tx (amounts, covenant bindings, fee) is exactly what `plan_batch_match`
/// computed.
fn apply_tamper(tx: &mut Transaction, mode: &TamperMode) {
    match mode {
        TamperMode::F2RedirectSeller => {
            // Replace output[0] (seller KAS) SPK with a fake P2PK address.
            // The sell covenant F2 checks: output[koi].spk.blake2b == sspkh.
            // sspkh is baked into the redeem script and matches the real seller.
            // This fake SPK will fail that blake2b comparison.
            let mut fake_spk = vec![0x20]; // OP_DATA_32
            fake_spk.extend_from_slice(&[0xDE; 32]); // fake pubkey
            fake_spk.push(0xac); // OP_CHECKSIG
            println!("TAMPER [F2-redirect-seller]: Replacing output[0] SPK with attacker address");
            println!("  Original SPK: {}", hex::encode(tx.outputs[0].script_bytes()));
            tx.outputs[0] = TxOutput::new(tx.outputs[0].value, 0, fake_spk, None);
            println!("  Tampered SPK: {}", hex::encode(tx.outputs[0].script_bytes()));
        }
        TamperMode::F2RedirectBuyer => {
            // Replace output[1] (buyer tokens) SPK with a fake P2PK address.
            // The buy covenant F2 checks: output[toi].spk.blake2b == bspkh.
            // bspkh is baked into the buy redeem script.
            if tx.outputs.len() > 1 {
                let mut fake_spk = vec![0x20]; // OP_DATA_32
                fake_spk.extend_from_slice(&[0xBE; 32]); // fake pubkey
                fake_spk.push(0xac); // OP_CHECKSIG
                // Preserve covenant binding from original output
                let orig_covenant = tx.outputs[1].covenant.clone();
                println!("TAMPER [F2-redirect-buyer]: Replacing output[1] SPK with attacker address");
                println!("  Original SPK: {}", hex::encode(tx.outputs[1].script_bytes()));
                tx.outputs[1] = TxOutput::new(tx.outputs[1].value, 0, fake_spk, orig_covenant);
                println!("  Tampered SPK: {}", hex::encode(tx.outputs[1].script_bytes()));
            }
        }
        TamperMode::F4RemoveBinding => {
            // Remove the covenant binding from output[1] (buyer tokens).
            // F4 checks CovOutCount(T) >= 1 -- without the binding, the
            // covenant output count for this token is 0, violating F4.
            if tx.outputs.len() > 1 {
                println!("TAMPER [F4-remove-binding]: Removing covenant binding from output[1]");
                println!("  Original binding: {:?}", tx.outputs[1].covenant);
                tx.outputs[1] = TxOutput::new(
                    tx.outputs[1].value,
                    tx.outputs[1].script_version(),
                    tx.outputs[1].script_bytes().to_vec(),
                    None, // No covenant binding
                );
                println!("  Tampered binding: None");
            }
        }
        TamperMode::F4ReduceValue => {
            // Reduce output[1] (buyer tokens) value by 1 sompi.
            // F4 full fill checks: covenant_output.value >= expected_tokens.
            // Reducing by 1 makes it strictly less than expected.
            if tx.outputs.len() > 1 {
                let orig_val = tx.outputs[1].value;
                let tampered_val = orig_val.saturating_sub(1);
                println!("TAMPER [F4-reduce-value]: Reducing output[1] value by 1 sompi");
                println!("  Original value: {}", orig_val);
                println!("  Tampered value: {}", tampered_val);
                tx.outputs[1] = TxOutput::new(
                    tampered_val,
                    tx.outputs[1].script_version(),
                    tx.outputs[1].script_bytes().to_vec(),
                    tx.outputs[1].covenant.clone(),
                );
                // Add the stolen sompi to output[0] to keep total balanced
                // (otherwise miner fee changes and mass check might fail).
                tx.outputs[0] = TxOutput::new(
                    tx.outputs[0].value + 1,
                    tx.outputs[0].script_version(),
                    tx.outputs[0].script_bytes().to_vec(),
                    tx.outputs[0].covenant.clone(),
                );
            }
        }
    }
}

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
    // Superseded by the canonical planner's own mass-based fee model
    // (`plan_batch_match` / `converge_fee_exact`, same as `match-batch`).
    // Kept for CLI signature/menu parity with the global `--fee-rate` flag
    // that `dispatch()` threads through every subcommand.
    _fee: u64,
    buy_expiry: u64,
    sell_expiry: u64,
    max_matcher_fee: u64,
    mmfee_bps: Option<u64>,
    fee_bps: Option<u16>,
    tamper: Option<TamperMode>,
) -> anyhow::Result<()> {
    if let Some(ref mode) = tamper {
        println!("!!! ADVERSARIAL TEST MODE: {:?} !!!", mode);
        println!("!!! This TX is INTENTIONALLY INVALID and MUST be rejected by the node !!!");
        println!();
    }

    let wallet = WalletContext::load(wallet_path)?;
    let buy_outpoint = Outpoint::parse(buy_outpoint_str)?;
    let sell_outpoint = Outpoint::parse(sell_outpoint_str)?;
    let fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

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

    // Reconstruct redeemScripts. v13/v14 share a layout (build_buy_redeem_script);
    // v16 is the F6-fix buy contract (mmfee_bps semantics, see V16_STATUS.md).
    // There is no v16 sell contract -- sell is always v14.
    if version != 13 && version != 14 && version != 16 {
        anyhow::bail!("Unsupported contract version {}. Supported: 13, 14 (legacy alias of 14), 16.", version);
    }
    let buy_version: u8 = if version == 16 { 16 } else { 14 };
    let buy_rs = if buy_version == 16 {
        contract::build_buy_v16_redeem_script(
            &tcid,
            buy_price_num,
            buy_price_den,
            buy_min_fill,
            &buy_owner_hash,
            &buy_spk_hash,
            mmfee_bps.unwrap_or(crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS),
            0,
            buy_expiry,
        )?
    } else {
        contract::build_buy_redeem_script(
            &tcid,
            buy_price_num,
            buy_price_den,
            buy_min_fill,
            &buy_owner_hash,
            &buy_spk_hash,
            max_matcher_fee,
            0,
            buy_expiry,
        )?
    };
    let sell_rs = contract::build_sell_redeem_script(
        sell_price_num,
        sell_price_den,
        sell_min_fill,
        &sell_owner_hash,
        &sell_spk_hash,
        max_matcher_fee,
        0,
        sell_expiry,
    )?;

    let buy_p2sh = build_p2sh(&buy_rs);
    let sell_p2sh = build_p2sh(&sell_rs);

    println!("Execute Match");
    println!("==============");
    println!("Buy Order:    {}", buy_outpoint);
    println!("Sell Order:   {}", sell_outpoint);
    println!("Token:        {}", token_cov_id_hex);
    println!("Buy Price:    {}/{}", buy_price_num, buy_price_den);
    println!("Sell Price:   {}/{}", sell_price_num, sell_price_den);
    println!("Buy RS:       {} bytes (v{})", buy_rs.len(), buy_version);
    println!("Sell RS:      {} bytes (v14)", sell_rs.len());
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

    // ---- Build BatchOrders for the canonical planner ----
    let buy_order = BatchOrder {
        outpoint: (buy_outpoint.transaction_id.clone(), buy_outpoint.index),
        order_type: OrderType::Buy,
        version: buy_version,
        token_cov_id: tcid,
        price_num: buy_price_num,
        price_den: buy_price_den,
        amount: buy_value,
        redeem_script: buy_rs,
        utxo_value: buy_value,
        counterparty_spk: buyer_spk,
        counterparty_spk_version: 0,
        min_fill: buy_min_fill,
        oco_path: None,
        bracket_meta: None,
    };
    let sell_order = BatchOrder {
        outpoint: (sell_outpoint.transaction_id.clone(), sell_outpoint.index),
        order_type: OrderType::Sell,
        version: 14,
        token_cov_id: tcid,
        price_num: sell_price_num,
        price_den: sell_price_den,
        amount: sell_value,
        redeem_script: sell_rs,
        utxo_value: sell_value,
        counterparty_spk: seller_spk,
        counterparty_spk_version: 0,
        min_fill: sell_min_fill,
        oco_path: None,
        bracket_meta: None,
    };

    // Matcher = this wallet's own P2PK SPK (self-funds the fee UTXO and
    // receives surplus, same model as `match-batch`).
    let mut matcher_spk = Vec::with_capacity(34);
    matcher_spk.push(0x20);
    matcher_spk.extend_from_slice(&pubkey);
    matcher_spk.push(0xac);

    // F6 correctness: a v16 buy's on-chain F6 check enforces
    // `surplus <= buy.utxo_value/10000 * mmfee_bps`. Default the planner's
    // own bps cap (applied to total_seller_kas <= buy.utxo_value) to the
    // SAME mmfee_bps so the built tx never asks for more matcher surplus
    // than F6 allows -- this is always a conservative subset of F6's
    // allowance, never an over-cap. --fee-bps lets the operator choose a
    // tighter cap; for a v14 buy (no on-chain F6 at all) the default stays
    // uncapped, matching v14's existing "matcher takes the full spread"
    // semantics.
    let effective_fee_bps = fee_bps.or_else(|| {
        if buy_version == 16 {
            Some(mmfee_bps.unwrap_or(crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS) as u16)
        } else {
            None
        }
    });

    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(ref op) = fee_outpoint {
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == op.transaction_id && u.outpoint.index == op.index)
            .ok_or_else(|| anyhow::anyhow!("The specified --fee-input UTXO was not found in the wallet. It may have been spent already."))?
    } else {
        wallet_utxos
            .iter()
            .find(|u| !u.is_p2sh())
            .ok_or_else(|| anyhow::anyhow!("No spendable UTXOs in wallet. Fund the wallet first or run `kob wallet consolidate`."))?
    };
    let wallet_utxo_info = (
        fee_utxo.outpoint.transaction_id.clone(),
        fee_utxo.outpoint.index,
        fee_utxo.utxo_entry.amount,
    );

    println!();
    println!("Fee UTXO:     {}:{} ({} sompi)", wallet_utxo_info.0, wallet_utxo_info.1, wallet_utxo_info.2);
    if let Some(bps) = effective_fee_bps {
        println!("Fee cap:      {} bps ({:.2}%)", bps, bps as f64 / 100.0);
    }

    // ---- Phase 1: plan with estimated fee ----
    let mut plan = plan_batch_match(
        &[sell_order],
        &[buy_order],
        Some(wallet_utxo_info),
        &matcher_spk,
        0,
        effective_fee_bps,
    )?;
    plan.validate()?;

    println!();
    println!("Phase 1 Plan:");
    println!("  Estimated fee:    {} sompi", plan.total_fee);
    println!("  Matcher surplus:  {} sompi", plan.matcher_surplus);
    println!("  Outputs:          {}", plan.outputs.len());

    // Build transaction from plan
    let mut tx = plan.to_transaction();

    // Fix wallet input SPK (to_transaction uses a placeholder)
    if let Some(last_input) = tx.inputs.last_mut() {
        if plan.wallet_input.is_some() {
            last_input.script_bytes = fee_utxo.script_bytes();
            last_input.script_version = fee_utxo.utxo_entry.script_public_key.version;
        }
    }

    // Set covenant bindings on the buyer-tokens output. Mirrors
    // `match-batch`'s covenant-binding step exactly.
    let token_hash = kob_core::compat::parse_hash(&token_cov_id_hex.to_string()).unwrap();
    for (idx, planned) in plan.outputs.iter().enumerate() {
        if planned.purpose == OutputPurpose::BuyerTokens {
            let authorizing_input = plan.buy_seller_map.get(&idx).copied().unwrap_or(0) as u16;
            tx.outputs[idx].covenant = Some(CovenantBinding::new(authorizing_input, token_hash));
        }
    }

    // Build sigscripts from plan (sell fill + buy fill; F6 for a v16 buy
    // reads its price data straight from the sell input's fixed-offset
    // sigscript -- exactly what build_tx() emits).
    let batch_tx = plan.build_tx()?;
    let mut sigscripts: Vec<Vec<u8>> = batch_tx.inputs.iter().map(|i| i.sigscript.clone()).collect();

    // Sign wallet input (last input, if present)
    if plan.wallet_input.is_some() {
        let wallet_idx = tx.inputs.len() - 1;
        let sighash = compute_sighash(&tx, wallet_idx)?;
        let sig = signing::schnorr_sign(&privkey, &sighash)?;
        sigscripts[wallet_idx] = signing::build_p2pk_sigscript(&sig);
    }

    // ---- Phase 2: exact mass with real sigscripts ----
    let (exact_fee, delta) = plan.converge_fee_exact(&tx, &sigscripts);
    println!();
    println!("Phase 2 Convergence:");
    println!("  Exact compute fee: {} sompi", exact_fee);
    println!("  Fee delta:         {} sompi (recovered)", delta);

    if delta > 0 {
        plan.apply_exact_fee(exact_fee);

        tx.outputs.clear();
        for planned in &plan.outputs {
            tx.outputs.push(TxOutput::new(
                planned.value,
                planned.spk_version,
                planned.script_public_key.clone(),
                None,
            ));
        }
        for (idx, planned) in plan.outputs.iter().enumerate() {
            if planned.purpose == OutputPurpose::BuyerTokens {
                let authorizing_input = plan.buy_seller_map.get(&idx).copied().unwrap_or(0) as u16;
                tx.outputs[idx].covenant = Some(CovenantBinding::new(authorizing_input, token_hash));
            }
        }

        if plan.wallet_input.is_some() {
            let wallet_idx = tx.inputs.len() - 1;
            let sighash = compute_sighash(&tx, wallet_idx)?;
            let sig = signing::schnorr_sign(&privkey, &sighash)?;
            sigscripts[wallet_idx] = signing::build_p2pk_sigscript(&sig);
        }
    }

    // ---- ADVERSARIAL TAMPERING (CLI-specific, layered on top) ----
    // Applied AFTER the canonically-built + fee-converged tx, then the
    // wallet input is re-signed so its signature covers the tampered
    // outputs (a valid signature over an invalid tx) -- the covenant
    // bytecode (F2/F4/F6) must still reject it at consensus.
    if let Some(ref mode) = tamper {
        apply_tamper(&mut tx, mode);
        if plan.wallet_input.is_some() {
            let wallet_idx = tx.inputs.len() - 1;
            let sighash = compute_sighash(&tx, wallet_idx)?;
            let sig = signing::schnorr_sign(&privkey, &sighash)?;
            sigscripts[wallet_idx] = signing::build_p2pk_sigscript(&sig);
        }
    }

    // Fee transparency summary
    {
        let in_vals: Vec<u64> = tx.inputs.iter().map(|i| i.value).collect();
        let out_vals: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let storage_mass = compute_storage_mass(&in_vals, &out_vals);
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
        let total_out: u64 = out_vals.iter().sum();
        let total_in: u64 = in_vals.iter().sum();
        let actual_fee = total_in.saturating_sub(total_out);

        println!();
        println!("Fee Summary");
        println!("-----------");
        println!(
            "Storage mass:     {:>9} / {:>9} ({})",
            storage_mass, MAX_TX_MASS,
            if storage_mass <= MAX_TX_MASS { "OK" } else { "OVER" }
        );
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_fee);
    }

    // Submit
    let payload = to_rpc_payload(&tx, &sigscripts);
    println!();
    println!("Submitting match transaction...");

    if tamper.is_some() {
        // In tamper mode, we EXPECT the node to reject.
        match rpc.submit_transaction(payload).await {
            Ok(tx_id) => {
                // The tampered TX was accepted -- this means the covenant
                // did NOT catch the tampering. This is a security failure.
                println!();
                println!("SECURITY FAILURE: Tampered TX was ACCEPTED!");
                println!("TXID: {}", tx_id);
                println!("The covenant did NOT reject the tampered transaction.");
                anyhow::bail!("ADVERSARIAL_ACCEPTED: tampered TX {} accepted by node", tx_id);
            }
            Err(e) => {
                let err_msg = format!("{}", e);
                println!();
                println!("EXPECTED REJECTION: Node rejected the tampered TX.");
                println!("Error: {}", err_msg);
                // Output machine-parseable result line for E2E script
                println!("ADVERSARIAL_REJECTED: {:?}", tamper.unwrap());
                return Ok(());
            }
        }
    }

    let tx_id = rpc.submit_transaction(payload).await?;

    println!();
    println!("SUCCESS! Match transaction submitted.");
    println!("TXID: {}", tx_id);
    println!();
    println!("  Seller received: {} sompi KAS (output[0])", tx.outputs[0].value);
    println!("  Buyer received:  {} sompi tokens (output[1])", tx.outputs[1].value);
    if plan.matcher_surplus > 0 {
        println!("  Matcher surplus: {} sompi", plan.matcher_surplus);
    }

    Ok(())
}

/// Cross-pair match: match a sell order (Token A) against a buy order (Token B)
/// with a bridging token UTXO.
///
/// NOT routed through the canonical planner (`plan_batch_match`), by design:
///
/// 1. It is version-gated to v8-v13 (`--version 14`/`16` are rejected below).
///    Those pre-date the F6 (matcher-fee-cap) mechanism entirely -- v14/v15/v16
///    "F6 REMOVED"/"F6 fixed" only exists on the same-pair fill path -- so
///    there is no F6-correctness gap for this function to close.
/// 2. `BatchOrder`/`plan_batch_match` model covenant lineage for buyer token
///    outputs as flowing from a SELL input's own covenant_id (see
///    `kob/domain/src/spot/batch.rs` module doc: "Sell inputs carry
///    covenant_id ... provides covenant lineage for buyer token outputs
///    directly"). Cross-pair's Token B comes from a SEPARATE P2PK
///    `token_outpoint` input instead -- a shape `BatchOrder` cannot express.
///    `kob-engine`'s own executor makes the identical call for cross-pair /
///    swap fills: `chain/executor.rs` builds those "directly (not via
///    plan_batch_match ...)" (see the comment at that call site).
///
/// TX layout:
///   input[0]: sell_order  (Token A, P2SH fill, sigOpCount=0)
///   input[1]: buy_order   (Token B, P2SH fill, sigOpCount=0)
///   input[2]: token UTXO  (Token B, P2PK signed, sigOpCount=1) -- provides Token B to buyer
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
             Redeploy the order with --version 14.", version);
    }

    let wallet = WalletContext::load(wallet_path)?;
    let buy_outpoint = Outpoint::parse(buy_outpoint_str)?;
    let sell_outpoint = Outpoint::parse(sell_outpoint_str)?;
    let token_outpoint = Outpoint::parse(token_outpoint_str)?;
    let _fee_outpoint = fee_input_str.map(Outpoint::parse).transpose()?;
    let _pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

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

    // Reconstruct redeemScripts (v14; same builder layout as v13).
    if version != 13 && version != 14 {
        anyhow::bail!("Unsupported contract version {}. Only v14 is supported.", version);
    }
    let buy_rs = contract::build_buy_redeem_script(
        &buy_tcid,
        buy_price_num,
        buy_price_den,
        buy_min_fill,
        &buy_owner_hash,
        &buy_spk_hash,
        crate::deploy::DEFAULT_MAX_MATCHER_FEE,
        0,
        buy_expiry,)?;
    let sell_rs = contract::build_sell_redeem_script(
        sell_price_num,
        sell_price_den,
        sell_min_fill,
        &sell_owner_hash,
        &sell_spk_hash,
        crate::deploy::DEFAULT_MAX_MATCHER_FEE,
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

    // Single-sign fee convergence via placeholder P2PK sigscripts (66 B each,
    // matches the real signed sigscript length byte-for-byte).
    // Inputs 2 (token) and 3 (fee) are both P2PK, so two placeholders suffice.
    // One pass of exact mass → one adjustment → two signs (no re-signs).
    let min_fee_override = if fee > 0 { fee } else { 0 };
    let placeholder_ss = signing::build_p2pk_sigscript(&[0u8; 64]);
    let sigscripts_probe: Vec<Vec<u8>> = vec![
        sell_fill_ss.clone(),
        buy_fill_ss.clone(),
        placeholder_ss.clone(),
        placeholder_ss,
    ];
    let mass1 = calc_mass_with_sigscripts(&tx, &sigscripts_probe);
    let fee1 = mass1.max(min_fee_override);
    let has_change_output = tx.outputs.len() > 3;
    let (final_seller_kas, matcher_change) = if has_change_output {
        let adj_change1 = tentative_change.saturating_sub(fee1);
        if adj_change1 >= MIN_UTXO_VALUE {
            (seller_kas, adj_change1)
        } else {
            // Drop change output; recompute mass with 3-output structure.
            tx.outputs.pop();
            let mass2 = calc_mass_with_sigscripts(&tx, &sigscripts_probe);
            let fee2 = mass2.max(min_fee_override);
            let adj_change2 = tentative_change.saturating_sub(fee2);
            (seller_kas + adj_change2, 0u64)
        }
    } else {
        let adj_change1 = tentative_change.saturating_sub(fee1);
        (seller_kas + adj_change1, 0u64)
    };

    tx.outputs[0].value = final_seller_kas;
    if tx.outputs.len() > 3 {
        tx.outputs[3].value = matcher_change;
    }

    // Sign inputs 2 (token) and 3 (fee) — once each over post-convergence outputs.
    let sighash_2 = compute_sighash(&tx, 2)?;
    let sig_2 = signing::schnorr_sign(&privkey, &sighash_2)?;
    let token_ss = signing::build_p2pk_sigscript(&sig_2);

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
        let exact_compute = calc_mass_with_sigscripts(&tx, &sigscripts);
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
        println!("Compute mass:     {:>9} (exact, post-sign)", exact_compute);
        println!("Miner fee:        {:>9} sompi", actual_miner_fee);
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
    use kob_domain::batch::{plan_batch_match, BatchOrder, OrderType};

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

        // Buy v14 RS must be 396 bytes (145B state + 251B body; the v14 body
        // is +9B over v13's 242B for the IOC fill sub-dispatch). Matches
        // kob-core parse::BUY_RS_SIZE.
        assert_eq!(buy_rs.len(), 396, "Buy v14 RS must be 396 bytes");
        // Sell v14 RS must be 416 bytes (112B state + 304B body; +60B over
        // v13's 244B for the v14 IOC fill path). Matches kob-core parse::SELL_RS_SIZE.
        assert_eq!(sell_rs.len(), 416, "Sell v14 RS must be 416 bytes");
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

    /// Build a token-conserving v16-buy + v14-sell pair (the exact shape
    /// `matching::run` now constructs, and the same 30M/30M shape the
    /// `toccata_fill_repro` on-chain harness uses): sell has 30M tokens @ 1/2
    /// (wants 15M KAS), buy has 30M KAS @ 1/1 (wants 30M tokens). The buyer's
    /// 30M token output is fully backed by the sell's 30M token input; the
    /// intrinsic spread is 30M - 15M = 15M KAS.
    fn make_pair(buy_mmfee_bps: u64) -> (BatchOrder, BatchOrder) {
        let pk = [0x03u8; 32];
        let tcid = [0x01u8; 32];
        let owner = blake2b_256(&pk);
        let spk_hash = compute_p2pk_spk_hash(&pk);
        let buy_rs = contract::build_buy_v16_redeem_script(
            &tcid, 1, 1, 1_000_000, &owner, &spk_hash, buy_mmfee_bps, 0, 0,
        ).unwrap();
        let sell_rs = contract::build_sell_redeem_script(
            1, 2, 1_000_000, &owner, &spk_hash, 0, 0, 0,
        ).unwrap();
        let buy = BatchOrder {
            outpoint: (hex::encode([0x20u8; 32]), 0),
            order_type: OrderType::Buy,
            version: 16,
            token_cov_id: tcid,
            price_num: 1,
            price_den: 1,
            amount: 30_000_000,
            redeem_script: buy_rs,
            utxo_value: 30_000_000,
            counterparty_spk: vec![0xEE; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        };
        let sell = BatchOrder {
            outpoint: (hex::encode([0x10u8; 32]), 0),
            order_type: OrderType::Sell,
            version: 14,
            token_cov_id: tcid,
            price_num: 1,
            price_den: 2,
            amount: 30_000_000,
            redeem_script: sell_rs,
            utxo_value: 30_000_000,
            counterparty_spk: vec![0xDD; 34],
            counterparty_spk_version: 0,
            min_fill: 1_000_000,
            oco_path: None,
            bracket_meta: None,
        };
        (buy, sell)
    }

    /// The CLI-level half of the F6 guarantee: the canonical planner caps the
    /// matcher's take at the buy's `mmfee_bps` and refunds the rest of the
    /// price spread to the buyer, instead of the pre-consolidation
    /// hand-rolled matcher dumping the entire 15M spread into matcher change.
    /// (The on-chain half — F6 rejecting an over-cap spread outright — is
    /// proved in `kob-core/tests/toccata_fill_repro.rs`.)
    #[test]
    fn v16_match_matcher_surplus_is_capped_not_full_spread() {
        // Intrinsic spread is 15M KAS. With a 30 bps cap on total_seller_kas
        // (15M), the matcher may keep at most 15M*30/10000 = 45K -- below
        // MIN_UTXO_VALUE, so it is dropped to the miner fee and the matcher
        // output is 0. The ~14.95M remainder must be refunded to the buyer.
        let (buy, sell) = make_pair(30);
        let matcher_spk = vec![0xCC; 34];
        let plan = plan_batch_match(&[sell], &[buy], None, &matcher_spk, 0, Some(30))
            .expect("plan should succeed");
        plan.validate().expect("plan should validate (balanced, all outputs >= MIN_UTXO)");

        assert!(
            plan.matcher_surplus <= 45_000,
            "matcher surplus {} must be capped at the buy's mmfee_bps allowance (<=45_000), \
             not the full 15M spread",
            plan.matcher_surplus,
        );

        // The excess spread must be refunded to the buyer as change, not
        // pocketed by the matcher and not folded into the seller output.
        let refunded: u64 = plan.outputs.iter()
            .filter(|o| o.purpose == kob_domain::batch::OutputPurpose::BuyerChange)
            .map(|o| o.value)
            .sum();
        assert!(
            refunded >= 14_000_000,
            "the bulk of the 15M spread ({} refunded) must go back to the buyer",
            refunded,
        );
    }

    /// Sanity floor: with a wide enough cap, the matcher legitimately keeps
    /// the spread (no refund) -- proving the cap is a real bound, not an
    /// unconditional refund. mmfee_bps large enough that 15M spread fits.
    #[test]
    fn v16_match_within_cap_matcher_keeps_spread() {
        // cap = total_seller_kas(15M) * 9000/10000 = 13.5M. The 15M spread is
        // still slightly above that, so most is kept and only a little
        // refunded. Use a full 10000 bps (100%) so nothing is refunded.
        let (buy, sell) = make_pair(10_000);
        let matcher_spk = vec![0xCC; 34];
        let plan = plan_batch_match(&[sell], &[buy], None, &matcher_spk, 0, Some(10_000))
            .expect("plan should succeed");
        plan.validate().expect("plan should validate");
        let refunded: u64 = plan.outputs.iter()
            .filter(|o| o.purpose == kob_domain::batch::OutputPurpose::BuyerChange)
            .map(|o| o.value)
            .sum();
        assert_eq!(refunded, 0, "with a 100% cap the matcher keeps the spread; no buyer refund");
        assert!(plan.matcher_surplus > 10_000_000, "matcher keeps the bulk of the 15M spread");
    }
}
