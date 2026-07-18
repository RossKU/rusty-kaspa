//! RT-2 offline proof: the `ratchet_tamper` tool's own build path
//! (`kob_core::contract::spot::ratchet_tamper`), run through the real
//! post-Toccata `kaspa-txscript` `TxScriptEngine` (`covenants_enabled =
//! true`) without any live node.
//!
//! This is deliberately NOT a parallel hand-rolled harness: every tx here is
//! constructed by `RatchetTamperCase::scenario().build_tx()` -- the exact
//! code path a later live-fire CLI command will call. Proving rejection
//! through the tool's own output is what makes that later live run
//! trustworthy (a bug in a separate test-only tx builder would prove
//! nothing about the tool).
//!
//! Coverage:
//!   - the HONEST baseline (`RatchetAdvanceScenario::honest_baseline()`,
//!     i.e. no tamper case applied) passes BOTH the sibling's own covenant
//!     (input[0]) and the ratchet branch (input[1]) -- proving the malformed
//!     cases below fail for the intended reason, not because the baseline
//!     itself is broken;
//!   - all 21 concrete tamper selectors (`RatchetTamperCase::all()`,
//!     covering the 8 L1/L2/L3/L4/L8/L10/L11/RATE categories) reject on
//!     input[1] (the ratchet branch) -- mirroring the unit-level harness in
//!     `time_contracts.rs`, which likewise executes ONLY the ratchet input
//!     for the adversarial cases (an attacker's sibling sigscript need not
//!     pass its OWN covenant to probe what the ratchet branch itself reads
//!     via `TxInputSigSubstr`);
//!   - `RatchetTamperCase::all()` / `id()` / `parse()` round-trip and stay
//!     at exactly 21 selectors across the 8 categories (drift guard).

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, UtxoEntry, VerifiableTransaction};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::engine_context::EngineCtx;
use kaspa_txscript::{EngineFlags, TxScriptEngine};

use kob_core::contract::spot::ratchet_tamper::{RatchetAdvanceScenario, RatchetTamperCase};

/// Execute the scripts of the selected input indices; results parallel `idxs`.
fn exec_selected(tx: &Transaction, entries: Vec<UtxoEntry>, idxs: &[usize]) -> Vec<Result<(), String>> {
    let populated = PopulatedTransaction::new(tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!("ctx: {e:?}")); idxs.len()],
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let mut results = Vec::new();
    for &idx in idxs {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        results.push(vm.execute().map_err(|e| format!("{e:?}")));
    }
    results
}

/// The honest baseline (no tamper case applied) must pass BOTH the
/// sibling's own covenant and the ratchet branch -- the control that proves
/// the malformed cases below fail for the intended reason.
#[test]
fn honest_baseline_accepts_real_engine() {
    let scn = RatchetAdvanceScenario::honest_baseline();
    let (tx, entries) = scn.build_tx();
    let r = exec_selected(&tx, entries, &[0, 1]);
    assert!(r[0].is_ok(), "honest baseline: sibling's own covenant must pass: {:?}", r[0]);
    assert!(r[1].is_ok(), "honest baseline: ratchet branch must pass: {:?}", r[1]);
}

/// Every one of the 8-category / 19-selector RT-2 adversarial catalog must
/// be rejected by the real engine on the ratchet input -- built via the
/// tool's own `RatchetTamperCase::scenario().build_tx()` path.
#[test]
fn all_tamper_cases_rejected_real_engine() {
    let cases = RatchetTamperCase::all();
    assert_eq!(cases.len(), 21, "RT-2 catalog drift: expected 21 concrete selectors");

    let mut failures = Vec::new();
    for case in &cases {
        let scn = case.scenario();
        let (tx, entries) = scn.build_tx();
        let r = exec_selected(&tx, entries, &[1]).remove(0);
        if r.is_ok() {
            failures.push(format!(
                "{} [{}] (expected {}) was ACCEPTED -- covenant did NOT reject",
                case.id(),
                case.category(),
                case.expected_guard()
            ));
        }
    }
    assert!(failures.is_empty(), "adversarial cases accepted by the real engine:\n{}", failures.join("\n"));
}

/// Drift guard: every case's selector string round-trips through `parse`,
/// and the 8-category catalog is exactly {L1, L2, L3, L4, L8, L10, L11, RATE}.
#[test]
fn catalog_ids_round_trip_and_cover_eight_categories() {
    use std::collections::BTreeSet;
    let cases = RatchetTamperCase::all();
    let mut categories = BTreeSet::new();
    for case in &cases {
        assert_eq!(
            RatchetTamperCase::parse(case.id()),
            Some(*case),
            "selector '{}' does not round-trip through parse()",
            case.id()
        );
        categories.insert(case.category());
    }
    let expected: BTreeSet<&str> =
        ["L1", "L2", "L3", "L4", "L8", "L10", "L11", "RATE"].into_iter().collect();
    assert_eq!(categories, expected, "RT-2 8-case catalog drift");
}
