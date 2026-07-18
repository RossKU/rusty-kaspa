//! `kob-cli ratchet-tamper` -- RT-2 adversarial tooling (hidden/dev
//! subcommand): construct a malformed `ratchet_oco` RATCHET-branch (advance)
//! transaction from the honest baseline, one mutation at a time.
//!
//! This mirrors the plain-fill `match --tamper` design
//! (`crate::matching::{TamperMode, apply_tamper}`): a case selector picks a
//! single, well-documented corruption of an otherwise-valid tx, built by
//! mutating ONE field of the honest baseline scenario so the resulting tx
//! differs from a real advance in exactly one way.
//!
//! Unlike `match --tamper`, this command does NOT submit anything to a node
//! in this build -- it only constructs the malformed transaction and prints
//! it (the tx shape, the mutated field, and the guard expected to catch it).
//! The covenant-rejection PROOF for every case lives in kob-core's own
//! offline `TxScriptEngine` harness (`core/tests/ratchet_tamper_repro.rs`),
//! which calls the exact same `RatchetTamperCase::scenario().build_tx()`
//! code path used here. Live submission (RPC payload conversion, outpoint
//! resolution against a real resting ratchet_oco + sibling order) is a
//! later task -- this tool is deliberately offline-only for now.

use kob_core::contract::spot::ratchet_tamper::{RatchetAdvanceScenario, RatchetTamperCase};

fn print_catalog() {
    println!("RT-2 ratchet-advance adversarial catalog (8 categories, {} selectors):", RatchetTamperCase::all().len());
    println!();
    println!("{:<22} {:<6} {}", "CASE ID", "CAT", "EXPECTED GUARD");
    println!("{}", "-".repeat(72));
    for case in RatchetTamperCase::all() {
        println!("{:<22} {:<6} {}", case.id(), case.category(), case.expected_guard());
    }
    println!();
    println!("Use --case <CASE ID> to construct that malformed advance tx (offline, no submission).");
}

fn print_tx_summary(case: &RatchetTamperCase, scn: &RatchetAdvanceScenario) {
    let (tx, entries) = scn.build_tx();
    println!("!!! ADVERSARIAL TEST MODE (ratchet-advance): {} [{}] !!!", case.id(), case.category());
    println!("!!! This TX is INTENTIONALLY INVALID and MUST be rejected by the ratchet covenant !!!");
    println!("!!! Expected guard: {} !!!", case.expected_guard());
    println!();
    println!("Scenario:");
    println!("  rs.len()            = {}", scn.rs.len());
    println!("  new_rs.len()        = {}", scn.new_rs.len());
    println!("  sibling             = {:?}", scn.sibling);
    println!("  sibling_cov         = {:?}", scn.sibling_cov);
    println!("  sibling_tokens      = {}", scn.sibling_tokens);
    println!("  print_kas           = {}", scn.print_kas);
    println!("  escrow              = {}", scn.escrow);
    println!("  continuation_value  = {}", scn.continuation_value);
    println!("  continuation_bound  = {}", scn.continuation_bound);
    println!("  forge_continuation_spk = {}", scn.forge_continuation_spk);
    println!("  sequence (nSeq)     = {}", scn.sequence);
    println!("  sii                 = {}", scn.sii);
    println!();
    println!("Transaction (offline construction only -- not submitted):");
    println!("  version = {}, lock_time = {}", tx.version, tx.lock_time);
    for (i, input) in tx.inputs.iter().enumerate() {
        println!(
            "  input[{i}]  outpoint={}:{} sequence={} sig_op_count={:?} sigscript_len={}",
            input.previous_outpoint.transaction_id,
            input.previous_outpoint.index,
            input.sequence,
            input.compute_commit.sig_op_count(),
            input.signature_script.len(),
        );
    }
    for (i, output) in tx.outputs.iter().enumerate() {
        println!(
            "  output[{i}] value={} spk_len={} covenant={:?}",
            output.value,
            output.script_public_key.script().len(),
            output.covenant,
        );
    }
    println!();
    println!("UTXO entries backing the inputs above ({} entries).", entries.len());
    println!();
    println!(
        "This build does not submit ratchet-advance transactions to a node. \
         The offline covenant-rejection proof for this exact code path is \
         `cargo test -p kob-core --test ratchet_tamper_repro`. Live firing is a later task."
    );
}

/// Entry point for `kob-cli ratchet-tamper`.
pub fn run(case: Option<String>, list: bool) -> anyhow::Result<()> {
    if list || case.is_none() {
        print_catalog();
        return Ok(());
    }
    let case_str = case.unwrap();
    let case = RatchetTamperCase::parse(&case_str).ok_or_else(|| {
        let valid: Vec<&str> = RatchetTamperCase::all().iter().map(|c| c.id()).collect();
        anyhow::anyhow!(
            "Unknown --case '{}'. Valid: {}\nRun `kob-cli ratchet-tamper --list` for the full catalog.",
            case_str,
            valid.join(", ")
        )
    })?;
    let scn = case.scenario();
    print_tx_summary(&case, &scn);
    Ok(())
}
