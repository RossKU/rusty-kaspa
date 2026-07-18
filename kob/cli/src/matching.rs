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
use crate::order_cache::{self, OrderCache};
use crate::signing;
use kob_core::contract;
use kob_core::p2sh::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::mass::{calc_mass_with_sigscripts, compute_storage_mass, MAX_TX_MASS};
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

/// Resolve the effective max_matcher_fee (BPS) for ONE side of a match.
///
/// Precedence: an explicit `--mmfee-bps` CLI flag (applies uniformly to
/// both sides, matching the flag's documented behavior) wins; otherwise
/// the order-cache entry's recorded `max_matcher_fee` for that specific
/// outpoint (if the outpoint is cached) is used; otherwise the global
/// default. Buy and sell orders can be deployed with different BPS caps,
/// so callers MUST invoke this independently per side -- reusing one
/// side's result for the other reconstructs the wrong redeemScript (wrong
/// P2SH hash -> "UTXO not found on chain" at best, a mismatched/rejected
/// spend at worst).
fn resolve_side_mmfee_bps(explicit: Option<u64>, cached: Option<u64>) -> u64 {
    explicit
        .or(cached)
        .unwrap_or(crate::deploy::DEFAULT_MAX_MATCHER_FEE_BPS)
}

/// Resolve the canonical planner's matcher-surplus BPS cap from the two
/// sides' resolved mmfee_bps values.
///
/// An explicit `--fee-bps` override always wins. Otherwise the
/// CONSERVATIVE (tighter, i.e. min) of the two sides binds: the built tx
/// spends both orders in the same transaction, so matcher surplus must
/// stay within whichever side's on-chain F6 check is stricter -- capping
/// to the looser side would let the tx be rejected by the tighter one.
fn resolve_planner_fee_bps_cap(fee_bps: Option<u16>, buy_mmfee_bps: u64, sell_mmfee_bps: u64) -> Option<u16> {
    fee_bps.or_else(|| Some(buy_mmfee_bps.min(sell_mmfee_bps) as u16))
}

/// Decide whether an optional `KOB_FEE_FLOOR` (sompi, read from the
/// environment) should raise the fee above `current_fee`, and to what value.
///
/// Mirrors the decision `match-batch` makes inline (`cli/src/match_batch.rs`)
/// and what `BatchPlan::apply_fee_floor` re-checks internally: the floor
/// binds only when it is STRICTLY GREATER than the fee already reached
/// (Phase 2's exact compute fee) -- an unset env var, a floor at/below the
/// current fee, or an explicit floor of `0` are all no-ops. Kept separate
/// from `BatchPlan::apply_fee_floor` (which does the actual output-value
/// surgery) so the "should we bump, and to what" decision is unit-testable
/// without constructing a full `BatchPlan`.
fn resolve_fee_floor_bump(current_fee: u64, floor: Option<u64>) -> Option<u64> {
    let floor = floor?;
    (floor > current_fee).then_some(floor)
}

/// Resolve the cached redeemScript bytes for one side of a match, if the
/// cache entry has one and it passes the p2sh_hash sanity check.
///
/// `match` (singular) has no `--sell-rs`/`--buy-rs` override flags, so this
/// is the whole precedence: cached (ground truth, recorded verbatim at
/// deploy time) beats reconstruction from the CLI-supplied price/hash
/// arguments, which -- like `match-batch`'s reconstruction path -- hardcodes
/// the owner batch cap and derives the E1 expire-seat SPK hash from the
/// currently running wallet. Returns `Ok(None)` when there's nothing cached
/// (the reconstruction fallback applies); `Err` when a cached entry exists
/// but its `redeem_script` doesn't hash to its own `p2sh_hash` (corrupt
/// cache).
fn resolve_cached_rs(entry: Option<&order_cache::OrderCacheEntry>, op_str: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(entry) = entry else { return Ok(None) };
    let Some(hex_rs) = &entry.redeem_script else { return Ok(None) };
    let bytes = hex::decode(hex_rs)
        .map_err(|e| anyhow::anyhow!("Order {} cache redeem_script not valid hex: {}", op_str, e))?;
    order_cache::verify_cached_rs_p2sh(&bytes, &entry.p2sh_hash)
        .map_err(|e| anyhow::anyhow!("Order {}: {}", op_str, e))?;
    Ok(Some(bytes))
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
    // that `dispatch()` threads through every subcommand. This parameter is
    // INERT -- it is never read below. The supported floor override is the
    // `KOB_FEE_FLOOR` env var (sompi), honored the same way `match-batch`
    // and the engine executor honor it (see the Phase 2 block below).
    _fee: u64,
    buy_expiry: u64,
    sell_expiry: u64,
    _max_matcher_fee: u64,
    mmfee_bps: Option<u64>,
    fee_bps: Option<u16>,
    tamper: Option<TamperMode>,
    dry_run: bool,
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
    } else if version == 18 {
        // v18 delivery re-wrap: v18 buys commit the buyer's token_unit P2SH
        // hash (fills deliver spendable KCC20 token_units).
        contract::compute_token_unit_spk_hash(&buyer_pubkey)
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

    // Buyer delivery SPK: must blake2b-hash to the buy's committed bspkh or
    // the covenant F2 check rejects the fill. Candidates: the raw P2PK SPK
    // (pre-D2 orders) and the token_unit P2SH SPK (D2 delivery re-wrap).
    let (buyer_spk, buyer_spk_version): (Vec<u8>, u16) =
        if kob_core::compute_spk_hash(0, &buyer_spk) == buy_spk_hash {
            (buyer_spk, 0)
        } else if contract::compute_token_unit_spk_hash(&buyer_pubkey) == buy_spk_hash {
            let tu = contract::build_token_unit_p2sh_spk(&buyer_pubkey);
            (tu.script().to_vec(), tu.version)
        } else {
            anyhow::bail!(
                "The buy order's committed delivery SPK hash matches neither the buyer's \
                 P2PK SPK nor their token_unit P2SH SPK. Cannot construct the token \
                 delivery output."
            );
        };

    // Per-side mmfee_bps resolution: buy and sell orders can be deployed
    // with different max_matcher_fee BPS caps, so a single --mmfee-bps
    // value must not be blindly reused for both redeemScript rebuilds (a
    // wrong guess produces the wrong P2SH, which then either fails the
    // "UTXO not found on chain" lookup below or -- if it happens to match
    // some other live UTXO by coincidence -- builds against the wrong
    // order entirely). Precedence per side: explicit --mmfee-bps flag >
    // that outpoint's orders.json cache entry > the global default. This
    // mirrors `match-batch`, which always rebuilds each side's RS from its
    // own cache entry's `max_matcher_fee` (see match_batch.rs).
    let cache_path = order_cache::orders_cache_path(wallet_path);
    let cache = OrderCache::load(&cache_path);
    let buy_op_str = format!("{}:{}", buy_outpoint.transaction_id, buy_outpoint.index);
    let sell_op_str = format!("{}:{}", sell_outpoint.transaction_id, sell_outpoint.index);
    let buy_cached_entry = cache.orders.iter().find(|e| e.outpoint == buy_op_str);
    let sell_cached_entry = cache.orders.iter().find(|e| e.outpoint == sell_op_str);
    let buy_cached_mmfee = buy_cached_entry.map(|e| e.max_matcher_fee);
    let sell_cached_mmfee = sell_cached_entry.map(|e| e.max_matcher_fee);
    let buy_mmfee_bps = resolve_side_mmfee_bps(mmfee_bps, buy_cached_mmfee);
    let sell_mmfee_bps = resolve_side_mmfee_bps(mmfee_bps, sell_cached_mmfee);
    if buy_mmfee_bps != sell_mmfee_bps {
        println!(
            "Note: buy and sell resolved to different mmfee_bps (buy={}, sell={}) -- \
             each side's redeemScript uses its own value.",
            buy_mmfee_bps, sell_mmfee_bps
        );
    }

    // Resolve redeemScripts. Precedence per side (no CLI override flags
    // exist for `match`, singular): cached entry.redeem_script (recorded
    // verbatim at deploy time) > reconstruct from the price/hash arguments
    // above. v13/v14 share a layout (build_buy_redeem_script); v16 is the
    // F6-fix buy contract (mmfee_bps semantics, see V16_STATUS.md); v18 is
    // the unified spot generation (BOTH sides v18, BPS-uniform, canonical
    // price attestation — see V18_DESIGN.md).
    if version != 18 {
        anyhow::bail!("Unsupported contract version {}. Only v18 is supported (pre-v18 removed in Stage E).", version);
    }
    let buy_version: u8 = 18;
    let buy_cached_rs = resolve_cached_rs(buy_cached_entry, &buy_op_str)?;
    let buy_rs = if let Some(bytes) = buy_cached_rs {
        bytes
    } else if buy_version == 18 {
        eprintln!(
            "warning: buy order {} cache predates redeem-script storage; reconstructing from \
             the supplied price/hash arguments. This may diverge from the deployed script for \
             orders deployed with a custom --n-max or from a different wallet.",
            buy_op_str
        );
        contract::spot::order::build_buy_redeem_script(
            &tcid,
            buy_price_num,
            buy_price_den,
            buy_min_fill,
            &buy_owner_hash,
            &buy_spk_hash,
            &kob_core::compute_p2pk_spk_hash(&buyer_pubkey), // okspkh (E1 expire seat)
            buy_mmfee_bps,
            0,
            buy_expiry,
        )?
    } else {
        anyhow::bail!("Unsupported buy version {} (pre-v18 removed in Stage E)", buy_version);
    };
    let sell_cached_rs = resolve_cached_rs(sell_cached_entry, &sell_op_str)?;
    let sell_rs = if let Some(bytes) = sell_cached_rs {
        bytes
    } else if version == 18 {
        eprintln!(
            "warning: sell order {} cache predates redeem-script storage; reconstructing from \
             the supplied price/hash arguments. This may diverge from the deployed script for \
             orders deployed with a custom --batch-max or from a different wallet.",
            sell_op_str
        );
        contract::spot::order::build_sell_redeem_script(
            sell_price_num,
            sell_price_den,
            sell_min_fill,
            &sell_owner_hash,
            &sell_spk_hash,
            &contract::compute_token_unit_spk_hash(&seller_pubkey), // otspkh (E1 expire seat)
            sell_mmfee_bps,
            0,
            sell_expiry,
        )?
    } else {
        anyhow::bail!("Unsupported sell version {} (pre-v18 removed in Stage E)", version);
    };

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
    println!("Sell RS:      {} bytes (v{})", sell_rs.len(), if version == 18 { 18 } else { 14 });
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
        counterparty_spk_version: buyer_spk_version,
        min_fill: buy_min_fill,
        oco_path: None,
        bracket_meta: None,
    };
    let sell_order = BatchOrder {
        outpoint: (sell_outpoint.transaction_id.clone(), sell_outpoint.index),
        order_type: OrderType::Sell,
        version: if version == 18 { 18 } else { 14 },
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

    // F6 correctness: the buy's on-chain F6 check enforces
    // `surplus <= buy.utxo_value/10000 * buy_mmfee_bps`, and (v18) the sell
    // side carries its own analogous cap at sell_mmfee_bps. Default the
    // planner's own bps cap (applied to total_seller_kas <= buy.utxo_value)
    // to the CONSERVATIVE (tighter) of the two resolved sides so the built
    // tx never asks for more matcher surplus than either order's own
    // on-chain check allows -- this is always a subset of what's permitted,
    // never an over-cap. --fee-bps lets the operator choose an even
    // tighter cap explicitly.
    let effective_fee_bps = resolve_planner_fee_bps_cap(fee_bps, buy_mmfee_bps, sell_mmfee_bps);

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

    // Optional fee floor override (sompi): the node's transient-mass floor
    // (byte-proportional, e.g. a v18 buy's 5,655B redeemScript) can exceed
    // the compute-mass fee estimate above -- KOB_FEE_FLOOR lets the operator
    // force a higher floor. Identical mechanism to `match-batch` / the
    // engine executor (`engine/src/chain/executor.rs`): the bump is absorbed
    // from the matcher-side outputs via `BatchPlan::apply_fee_floor` (never
    // seller/buyer). This MUST be decided and applied here, before the
    // tx.outputs rebuild below, so the floor reaches the actually-submitted
    // tx -- not just Phase 2's printed "recovered" number, which the stale
    // Phase-1 tx would otherwise ship unchanged.
    let fee_floor_env = std::env::var("KOB_FEE_FLOOR").ok().and_then(|v| v.parse::<u64>().ok());
    let fee_floor_bump = resolve_fee_floor_bump(exact_fee, fee_floor_env);
    if let Some(floor) = fee_floor_bump {
        println!("  Fee floor override: {} sompi (KOB_FEE_FLOOR)", floor);
    }

    if delta > 0 || fee_floor_bump.is_some() {
        plan.apply_exact_fee(exact_fee);
        if let Some(floor) = fee_floor_bump {
            let bumped = plan.apply_fee_floor(floor);
            if bumped > 0 {
                println!("  Fee floor applied:  +{} sompi -> {} sompi total", bumped, plan.total_fee);
            }
        }

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

    if dry_run {
        println!();
        println!("[DRY RUN] Match transaction built and validated. Not submitted.");
        return Ok(());
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


#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use kob_core::contract;
    use kob_core::p2sh::{blake2b_256, compute_p2pk_spk_hash};
    use kob_domain::batch::{plan_batch_match, BatchOrder, OrderType};

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

    // ---- resolve_side_mmfee_bps ----

    #[test]
    fn side_mmfee_explicit_flag_wins() {
        // --mmfee-bps overrides even when the outpoint is cached at a
        // different value.
        assert_eq!(super::resolve_side_mmfee_bps(Some(50), Some(10)), 50);
    }

    #[test]
    fn side_mmfee_cache_hit_used_when_no_flag() {
        assert_eq!(super::resolve_side_mmfee_bps(None, Some(10)), 10);
    }

    #[test]
    fn side_mmfee_falls_back_to_default() {
        assert_eq!(
            super::resolve_side_mmfee_bps(None, None),
            kob_domain::DEFAULT_MAX_MATCHER_FEE_BPS
        );
    }

    #[test]
    fn side_mmfee_sides_can_differ_from_cache_alone() {
        // No explicit flag: each side resolves independently from its own
        // cache entry, so buy and sell can legitimately land on different
        // BPS values (this is the bug this fix addresses -- previously a
        // single value was reused for both sides).
        let buy = super::resolve_side_mmfee_bps(None, Some(10));
        let sell = super::resolve_side_mmfee_bps(None, Some(50));
        assert_ne!(buy, sell);
        assert_eq!(buy, 10);
        assert_eq!(sell, 50);
    }

    // ---- resolve_planner_fee_bps_cap ----

    #[test]
    fn planner_cap_explicit_fee_bps_wins() {
        assert_eq!(super::resolve_planner_fee_bps_cap(Some(5), 10, 50), Some(5));
    }

    #[test]
    fn planner_cap_uses_conservative_min_of_sides() {
        assert_eq!(super::resolve_planner_fee_bps_cap(None, 10, 50), Some(10));
        assert_eq!(super::resolve_planner_fee_bps_cap(None, 50, 10), Some(10));
    }

    #[test]
    fn planner_cap_equal_sides() {
        assert_eq!(super::resolve_planner_fee_bps_cap(None, 30, 30), Some(30));
    }

    // ---- resolve_fee_floor_bump ----

    #[test]
    fn fee_floor_binds_when_above_current_fee() {
        // Live bug scenario: Phase 2's exact compute-mass fee (1_000) is well
        // under the node's real transient-mass floor (1_600_000) on a
        // covenant-heavy v18 shape -- KOB_FEE_FLOOR must bind.
        assert_eq!(super::resolve_fee_floor_bump(1_000, Some(1_600_000)), Some(1_600_000));
    }

    #[test]
    fn fee_floor_does_not_bind_at_or_below_current_fee() {
        // Floor equal to the current fee: already satisfied, no bump.
        assert_eq!(super::resolve_fee_floor_bump(1_600_000, Some(1_600_000)), None);
        // Floor below the current fee: the converged fee already clears it.
        assert_eq!(super::resolve_fee_floor_bump(2_000_000, Some(1_600_000)), None);
    }

    #[test]
    fn fee_floor_zero_never_binds() {
        // An explicit KOB_FEE_FLOOR=0 (or a zero current fee) must never
        // raise the fee -- 0 can't be strictly greater than anything u64.
        assert_eq!(super::resolve_fee_floor_bump(5_000, Some(0)), None);
        assert_eq!(super::resolve_fee_floor_bump(0, Some(0)), None);
    }

    #[test]
    fn fee_floor_unset_env_is_noop() {
        assert_eq!(super::resolve_fee_floor_bump(5_000, None), None);
    }

    // ---- resolve_cached_rs ----

    fn make_order_cache_entry(redeem_script: Option<&[u8]>, p2sh_hash: &str) -> crate::order_cache::OrderCacheEntry {
        crate::order_cache::OrderCacheEntry {
            outpoint: "aa".repeat(32) + ":0",
            side: "buy".to_string(),
            pair_id: "00".repeat(32),
            price_num: 1,
            price_den: 1,
            min_fill: 1,
            owner_hash: String::new(),
            spk_hash: String::new(),
            p2sh_hash: p2sh_hash.to_string(),
            value: 1,
            cancel_pending: false,
            token: None,
            version: 18,
            expiry_daa: 0,
            max_matcher_fee: 30,
            redeem_script: redeem_script.map(hex::encode),
        }
    }

    #[test]
    fn resolve_cached_rs_none_when_no_entry() {
        assert_eq!(super::resolve_cached_rs(None, "op").unwrap(), None);
    }

    #[test]
    fn resolve_cached_rs_none_when_entry_has_no_redeem_script() {
        let entry = make_order_cache_entry(None, &"cc".repeat(32));
        assert_eq!(super::resolve_cached_rs(Some(&entry), "op").unwrap(), None);
    }

    #[test]
    fn resolve_cached_rs_returns_bytes_when_hash_matches() {
        let rs = vec![0x51u8, 0x52, 0x53];
        let hash_hex = hex::encode(blake2b_256(&rs));
        let entry = make_order_cache_entry(Some(&rs), &hash_hex);
        let result = super::resolve_cached_rs(Some(&entry), "op").unwrap();
        assert_eq!(result, Some(rs));
    }

    #[test]
    fn resolve_cached_rs_errors_on_p2sh_mismatch() {
        // Corrupt cache: redeem_script present but doesn't hash to the
        // entry's own p2sh_hash -- must error out loudly, not proceed.
        let rs = vec![0x51u8, 0x52, 0x53];
        let wrong_hash = "ff".repeat(32);
        let entry = make_order_cache_entry(Some(&rs), &wrong_hash);
        let err = super::resolve_cached_rs(Some(&entry), "op").unwrap_err();
        assert!(err.to_string().contains("corrupt"));
    }
}
