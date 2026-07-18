//! `kob-cli ratchet-tamper-live` -- RT-2 LIVE adversarial tooling.
//!
//! Additive sibling to `cli/src/ratchet_tamper.rs` (the OFFLINE-only tool)
//! and `core/src/contract/spot/ratchet_tamper.rs` (the single source of
//! truth for the 21-case catalog + mutation logic, proven offline against
//! the real `kaspa-txscript` `TxScriptEngine` by
//! `core/tests/ratchet_tamper_repro.rs`). This module ports that same
//! mutation logic to a REAL testnet-10 node: given a genuinely deployed
//! `ratchet_oco` UTXO + a genuine sibling sell UTXO (the "print"), it builds
//! the honest ratchet-advance tx shape, applies one `RatchetTamperCase`
//! mutation (or none, for the honest control), signs the real fee input,
//! and submits to the node -- capturing the ACTUAL node verdict.
//!
//! Design notes (see also the report handed back to the operator):
//!   - `RatchetTamperCase::apply()` is reused UNCHANGED for every case except
//!     `RateLimit(TravelCapExhausted)`, whose offline `apply()` rebuilds an
//!     entirely different DEV_PUBKEY-identity precursor scenario (not usable
//!     live). For a live fire of that case, the caller instead points
//!     `--ratchet-outpoint`/`--ratchet-rs` at an ALREADY-one-step-advanced
//!     real ratchet_oco and `--sibling-*` at a qualifying-price print for the
//!     NEXT (G3-violating) step, and selects `--case rate-travel-cap` with
//!     `--no-apply` semantics baked in below -- the natural next splice IS
//!     the travel-cap violation, no extra mutation needed.
//!   - `L2GarbagePrint(NonCovenantSibling)` / `(WrongTokenSibling)` need a
//!     sibling UTXO with a DIFFERENT covenant setup than the genuine print
//!     (no binding / wrong token) -- `--sibling-noncov-outpoint` /
//!     `--sibling-wrongtoken-outpoint` select those.
//!   - `L2GarbagePrint(CancelShapeSibling)` upgrades the offline harness's
//!     fake signature (`[0x11; 64]`, meaningless for a real node) to a
//!     GENUINE wallet-signed cancel of the sibling sell -- this isolates the
//!     live rejection to the ratchet branch's own R7 check instead of also
//!     failing on a bogus signature, matching the offline proof's isolation
//!     more closely.
//!   - Every OTHER sibling-shape/price mutation case (L1, L3, L4-*) reuses
//!     the ONE genuine sibling UTXO with a corrupted sigscript; because that
//!     UTXO's own committed price is fixed, the sibling's OWN covenant also
//!     independently fails for most of these -- the resulting node rejection
//!     is therefore not perfectly isolated to the ratchet branch the way the
//!     offline proof isolates it (which deliberately executes ONLY the
//!     ratchet input). This is flagged explicitly in the report; it does not
//!     weaken the core live claim (the node rejects the malformed tx
//!     end-to-end).

use crate::node::NodeClient;
use crate::signing;
use kob_core::contract::{build_sell_cancel_sigscript, build_sell_fill_sigscript, build_sell_ioc_fill_sigscript};
use kob_core::contract::spot::ratchet::{build_ratchet_oco_ratchet_sigscript, derive_ratchet_continuation_rs};
use kob_core::contract::spot::ratchet_tamper::{L2Variant, RateLimitVariant, RatchetAdvanceScenario, RatchetTamperCase, SiblingPrint};
use kob_core::p2sh::build_p2sh;
use kob_core::sighash::compute_sighash;
use kob_core::tx::{to_rpc_payload, CovenantBinding, Transaction, TxInput, TxOutput};
use kob_core::types::{Network, Outpoint};
use kob_core::wallet::WalletContext;
use kob_core::{push_data, MIN_UTXO_VALUE};
use std::path::Path;

/// Which real sibling UTXO a case should spend at input[0].
enum SiblingSlot {
    Genuine,
    NonCov,
    WrongToken,
}

fn sibling_slot_for(case: RatchetTamperCase) -> SiblingSlot {
    match case {
        RatchetTamperCase::L2GarbagePrint(L2Variant::NonCovenantSibling) => SiblingSlot::NonCov,
        RatchetTamperCase::L2GarbagePrint(L2Variant::WrongTokenSibling) => SiblingSlot::WrongToken,
        _ => SiblingSlot::Genuine,
    }
}

/// Build the sibling (input[0]) sigscript for a scenario, given the resolved
/// real sibling redeemScript bytes. Mirrors
/// `RatchetAdvanceScenario::build_tx()`'s sibling match arm exactly, except
/// `CancelShape` is upgraded to a genuine wallet signature (see module doc).
/// `ratchet_rs`/`ratchet_new_rs` are the SCENARIO's own ratchet rs/new_rs
/// (`scn.rs`/`scn.new_rs`), needed ONLY for `RatchetShape` -- mirrors the
/// offline module's `SiblingPrint::RatchetShape => build_ratchet_oco_ratchet_sigscript(&self.new_rs, &self.rs, 1, &self.rs)`
/// exactly (the nested-ratchet probe impersonates THIS ratchet, not the
/// sibling's own redeemScript).
fn build_sibling_sigscript(
    sibling: &SiblingPrint,
    sibling_rs: &[u8],
    ratchet_rs: &[u8],
    ratchet_new_rs: &[u8],
    cancel_sig: Option<[u8; 64]>,
    pubkey: &[u8; 32],
) -> Vec<u8> {
    match sibling {
        SiblingPrint::SellFill { pnum, pden } => build_sell_fill_sigscript(0, *pnum, *pden, sibling_rs),
        SiblingPrint::SellIoc { pnum, pden, fta } => build_sell_ioc_fill_sigscript(0, *pnum, *pden, *fta, sibling_rs),
        SiblingPrint::RawShape { pnum, pden } => {
            let mut ss = vec![0x01, 0x00, 0x08];
            ss.extend_from_slice(pnum);
            ss.push(0x08);
            ss.extend_from_slice(pden);
            ss.push(0x51); // full-fill selector shape
            ss.extend_from_slice(&push_data(sibling_rs));
            ss
        }
        SiblingPrint::CancelShape => {
            let sig = cancel_sig.expect("CancelShape requires a real signature to be computed first");
            build_sell_cancel_sigscript(&sig, pubkey, sibling_rs)
        }
        SiblingPrint::RatchetShape => build_ratchet_oco_ratchet_sigscript(ratchet_new_rs, ratchet_rs, 1, ratchet_rs),
    }
}

fn wallet_p2pk_spk(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(pubkey);
    s.push(0xac);
    s
}

#[allow(clippy::too_many_arguments)]
pub async fn prep_noncov(
    wallet_path: &Path,
    node_url: &str,
    sibling_rs_hex: &str,
    amount: u64,
    fee_utxo_str: Option<&str>,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();
    let sibling_rs = hex::decode(sibling_rs_hex)?;
    let dest_spk = build_p2sh(&sibling_rs);

    println!("Prep: fund a NO-COVENANT UTXO at P2SH(sibling_rs) = {}", hex::encode(dest_spk.script()));

    let rpc = NodeClient::connect(node_url).await?;
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(op_str) = fee_utxo_str {
        let op = Outpoint::parse(op_str)?;
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == op.transaction_id && u.outpoint.index == op.index)
            .ok_or_else(|| anyhow::anyhow!("--fee-utxo not found"))?
    } else {
        wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh())
            .max_by_key(|u| u.utxo_entry.amount)
            .ok_or_else(|| anyhow::anyhow!("No spendable P2PK UTXOs in wallet"))?
    };
    let fee_val = fee_utxo.utxo_entry.amount;
    let target_fee = 2_000_000u64;
    if fee_val < amount + target_fee {
        anyhow::bail!("Fee UTXO {} sompi too small for amount {} + fee {}", fee_val, amount, target_fee);
    }
    let change = fee_val - amount - target_fee;

    let mut tx = Transaction::new(0);
    tx.inputs.push(TxInput {
        prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
        prev_index: fee_utxo.outpoint.index,
        sequence: 0,
        sig_op_count: 1,
        script_version: fee_utxo.utxo_entry.script_public_key.version,
        script_bytes: fee_utxo.script_bytes(),
        value: fee_val,
    });
    tx.outputs.push(TxOutput::new(amount, dest_spk.version, dest_spk.script().to_vec(), None));
    if change >= MIN_UTXO_VALUE {
        tx.outputs.push(TxOutput::new(change, 0, wallet_p2pk_spk(&pubkey), None));
    }

    let sighash = compute_sighash(&tx, 0)?;
    let sig = signing::schnorr_sign(&privkey, &sighash)?;
    let sigscript = signing::build_p2pk_sigscript(&sig);

    let payload = to_rpc_payload(&tx, &[sigscript]);
    let tx_id = rpc.submit_transaction(payload).await?;
    println!("SUCCESS: no-covenant sibling funded. Outpoint: {}:0 ({} sompi)", tx_id, amount);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    wallet_path: &Path,
    node_url: &str,
    _network: Network,
    case_str: &str,
    ratchet_outpoint_str: &str,
    ratchet_rs_hex: &str,
    escrow: u64,
    rwin: u64,
    sibling_outpoint_str: &str,
    sibling_rs_hex: &str,
    sibling_price_num: u64,
    sibling_price_den: u64,
    sibling_tokens: u64,
    sibling_noncov_outpoint_str: Option<&str>,
    sibling_wrongtoken_outpoint_str: Option<&str>,
    token_hex: &str,
    wrong_token_hex: Option<&str>,
    fee_utxo_str: Option<&str>,
    fee_floor: Option<u64>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let wallet = WalletContext::load(wallet_path)?;
    let pubkey = wallet.pubkey;
    let privkey = *wallet.privkey_bytes();

    let ratchet_outpoint = Outpoint::parse(ratchet_outpoint_str)?;
    let sibling_outpoint = Outpoint::parse(sibling_outpoint_str)?;
    let ratchet_rs = hex::decode(ratchet_rs_hex)?;
    let sibling_rs = hex::decode(sibling_rs_hex)?;
    let token_hash = kob_core::compat::parse_hash(token_hex)?;
    let wrong_token_hash = wrong_token_hex.map(kob_core::compat::parse_hash).transpose()?;

    let noncov_outpoint = sibling_noncov_outpoint_str.map(Outpoint::parse).transpose()?;
    let wrongtoken_outpoint = sibling_wrongtoken_outpoint_str.map(Outpoint::parse).transpose()?;

    let ratchet_p2sh = build_p2sh(&ratchet_rs);
    let sibling_p2sh = build_p2sh(&sibling_rs);

    let rpc = NodeClient::connect(node_url).await?;
    let wallet_utxos = rpc.get_spendable_utxos(&wallet.address).await?;
    let fee_utxo = if let Some(op_str) = fee_utxo_str {
        let op = Outpoint::parse(op_str)?;
        wallet_utxos
            .iter()
            .find(|u| u.outpoint.transaction_id == op.transaction_id && u.outpoint.index == op.index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("--fee-utxo not found"))?
    } else {
        wallet_utxos
            .iter()
            .filter(|u| !u.is_p2sh())
            .max_by_key(|u| u.utxo_entry.amount)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No spendable P2PK UTXOs in wallet"))?
    };
    println!("Fee UTXO: {}:{} ({} sompi)", fee_utxo.outpoint.transaction_id, fee_utxo.outpoint.index, fee_utxo.utxo_entry.amount);

    // Resolve the case list.
    let cases: Vec<Option<RatchetTamperCase>> = match case_str {
        "honest" => vec![None],
        // "all" fires every case that can share the single genuine sibling
        // UTXO + `--sibling-tokens` value passed to THIS invocation.
        // NonCovenantSibling / WrongTokenSibling need a differently-valued
        // real UTXO (their own dedicated deploy) and TravelCapExhausted
        // needs an already-advanced precursor -- fire those three as their
        // own separate `--case` invocations with matching `--sibling-tokens`.
        "all" => RatchetTamperCase::all()
            .into_iter()
            .filter(|c| {
                !matches!(
                    c,
                    RatchetTamperCase::RateLimit(RateLimitVariant::TravelCapExhausted)
                        | RatchetTamperCase::L2GarbagePrint(L2Variant::NonCovenantSibling)
                        | RatchetTamperCase::L2GarbagePrint(L2Variant::WrongTokenSibling)
                )
            })
            .map(Some)
            .collect(),
        "rate-travel-cap" => vec![Some(RatchetTamperCase::RateLimit(RateLimitVariant::TravelCapExhausted))],
        other => vec![Some(RatchetTamperCase::parse(other).ok_or_else(|| {
            anyhow::anyhow!("Unknown --case '{}'. Use a RatchetTamperCase id, 'honest', 'all', or 'rate-travel-cap'.", other)
        })?)],
    };

    let mut results: Vec<(String, String)> = Vec::new();

    for case_opt in cases {
        let label = case_opt.map(|c| format!("{} [{}]", c.id(), c.category())).unwrap_or_else(|| "HONEST".to_string());

        // Base scenario from REAL live data.
        let mut scn = RatchetAdvanceScenario {
            rs: ratchet_rs.clone(),
            new_rs: derive_ratchet_continuation_rs(&ratchet_rs)?,
            sibling: SiblingPrint::SellFill { pnum: sibling_price_num, pden: sibling_price_den },
            sibling_cov: (true, true),
            sibling_tokens,
            print_kas: sibling_tokens * sibling_price_num / sibling_price_den,
            escrow,
            continuation_value: escrow,
            continuation_bound: true,
            forge_continuation_spk: false,
            sequence: rwin,
            sii: 0,
            lock_time: 0,
        };

        let mut sib_slot = SiblingSlot::Genuine;
        if let Some(case) = case_opt {
            if matches!(case, RatchetTamperCase::RateLimit(RateLimitVariant::TravelCapExhausted)) {
                // Bypass apply(): the caller already points rs/sibling-* at
                // the already-advanced precursor + the next (G3-violating)
                // qualifying print. The natural, otherwise-honest splice IS
                // the tamper here -- see module doc.
            } else {
                sib_slot = sibling_slot_for(case);
                case.apply(&mut scn);
            }
        }

        let sib_outpoint = match sib_slot {
            SiblingSlot::Genuine => sibling_outpoint.clone(),
            SiblingSlot::NonCov => noncov_outpoint
                .clone()
                .ok_or_else(|| anyhow::anyhow!("case {} needs --sibling-noncov-outpoint", label))?,
            SiblingSlot::WrongToken => wrongtoken_outpoint
                .clone()
                .ok_or_else(|| anyhow::anyhow!("case {} needs --sibling-wrongtoken-outpoint", label))?,
        };

        // ---- Build outputs ----
        let token_hash_for_output1 = match scn.sibling_cov {
            (true, true) => Some(CovenantBinding::new(0, token_hash)),
            (true, false) => Some(CovenantBinding::new(
                0,
                wrong_token_hash.ok_or_else(|| anyhow::anyhow!("case {} needs --wrong-token", label))?,
            )),
            (false, _) => None,
        };
        let cont_rs_for_spk = if scn.forge_continuation_spk { &scn.rs } else { &scn.new_rs };
        let cont_spk = build_p2sh(cont_rs_for_spk);

        let total_in = sibling_tokens + escrow + fee_utxo.utxo_entry.amount;
        let total_out_fixed = scn.print_kas + scn.sibling_tokens + scn.continuation_value;
        let target_fee = fee_floor.unwrap_or(2_000_000);
        let change = total_in.saturating_sub(total_out_fixed + target_fee);
        let has_change = change >= MIN_UTXO_VALUE;

        let mut tx = Transaction::new(1);
        // Input[0]: sibling print.
        let sib_sig_op_count: u8 = if matches!(scn.sibling, SiblingPrint::CancelShape) { 1 } else { 0 };
        tx.inputs.push(TxInput {
            prev_tx_id: sib_outpoint.transaction_id.clone(),
            prev_index: sib_outpoint.index,
            sequence: 50, // sell fill's own CSV(50) exposure delay
            sig_op_count: sib_sig_op_count,
            script_version: sibling_p2sh.version,
            script_bytes: sibling_p2sh.script().to_vec(),
            value: sibling_tokens,
        });
        // Input[1]: ratchet.
        tx.inputs.push(TxInput {
            prev_tx_id: ratchet_outpoint.transaction_id.clone(),
            prev_index: ratchet_outpoint.index,
            sequence: scn.sequence,
            sig_op_count: 1, // RT-1 fix: composed shape needs the extra script-units budget headroom
            script_version: ratchet_p2sh.version,
            script_bytes: ratchet_p2sh.script().to_vec(),
            value: escrow,
        });
        // Input[2]: fee (P2PK, signed).
        tx.inputs.push(TxInput {
            prev_tx_id: fee_utxo.outpoint.transaction_id.clone(),
            prev_index: fee_utxo.outpoint.index,
            sequence: 0,
            sig_op_count: 1,
            script_version: fee_utxo.utxo_entry.script_public_key.version,
            script_bytes: fee_utxo.script_bytes(),
            value: fee_utxo.utxo_entry.amount,
        });

        tx.outputs.push(TxOutput::new(scn.print_kas, 0, wallet_p2pk_spk(&pubkey), None));
        tx.outputs.push(TxOutput::new(scn.sibling_tokens, 0, wallet_p2pk_spk(&pubkey), token_hash_for_output1));
        tx.outputs.push(TxOutput::new(
            scn.continuation_value,
            cont_spk.version,
            cont_spk.script().to_vec(),
            if scn.continuation_bound { Some(CovenantBinding::new(1, token_hash)) } else { None },
        ));
        if has_change {
            tx.outputs.push(TxOutput::new(change, 0, wallet_p2pk_spk(&pubkey), None));
        }

        // ---- Sigscripts ----
        let ratchet_sigscript = build_ratchet_oco_ratchet_sigscript(&scn.new_rs, &scn.rs, scn.sii, &scn.rs);

        let cancel_sig = if matches!(scn.sibling, SiblingPrint::CancelShape) {
            let sighash0 = compute_sighash(&tx, 0)?;
            Some(signing::schnorr_sign(&privkey, &sighash0)?)
        } else {
            None
        };
        let sib_sigscript = build_sibling_sigscript(&scn.sibling, &sibling_rs, &scn.rs, &scn.new_rs, cancel_sig, &pubkey);

        let sighash_fee = compute_sighash(&tx, 2)?;
        let fee_sig = signing::schnorr_sign(&privkey, &sighash_fee)?;
        let fee_sigscript = signing::build_p2pk_sigscript(&fee_sig);

        let sigscripts = vec![sib_sigscript, ratchet_sigscript, fee_sigscript];

        println!();
        println!("=== case: {} ===", label);
        println!("  sibling outpoint: {} (sequence=50, sig_op_count={})", sib_outpoint, sib_sig_op_count);
        println!("  ratchet outpoint: {} (sequence={}, sig_op_count=1)", ratchet_outpoint, scn.sequence);
        println!("  output[0] print_kas={}  output[1] sibling_tokens={} cov={:?}", scn.print_kas, scn.sibling_tokens, scn.sibling_cov);
        println!("  output[2] continuation_value={} bound={} forged_spk={}", scn.continuation_value, scn.continuation_bound, scn.forge_continuation_spk);

        if dry_run {
            println!("  [DRY RUN] not submitted.");
            results.push((label, "DRY_RUN".to_string()));
            continue;
        }

        let payload = to_rpc_payload(&tx, &sigscripts);
        match rpc.submit_transaction(payload).await {
            Ok(tx_id) => {
                println!("  VERDICT: ACCEPTED  TXID={}", tx_id);
                results.push((label, format!("ACCEPTED {}", tx_id)));
            }
            Err(e) => {
                let msg = format!("{}", e);
                println!("  VERDICT: REJECTED  {}", msg);
                results.push((label, format!("REJECTED: {}", msg)));
            }
        }
    }

    println!();
    println!("=== Summary ===");
    for (label, verdict) in &results {
        println!("{:<40} {}", label, verdict);
    }

    Ok(())
}
