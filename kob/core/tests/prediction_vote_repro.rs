//! Off-chain reproduction of the BallotBox VOTE path (VoteReceipt-enabled)
//! against the real post-Toccata `kaspa-txscript` engine.
//!
//! Purpose: derive/verify the exact 3-in/4-out layout the currently-deployed
//! `BALLOT_BOX_BODY` vote path requires (see `kob/core/src/contract/prediction/
//! ballot_box.rs`), BEFORE wiring a domain builder and spending real testnet
//! KAS on a guess. Also proves/disproves whether BallotBox needs an explicit
//! `CovenantBinding` at deploy time for the vote path's `OpCovInputCount`/
//! `OpCovOutputCount` checks (V0/V0b) to pass -- `kob/domain/src/prediction/
//! prediction_executor.rs::build_create_market_tx` currently emits BallotBox
//! outputs with `covenant: None` (via `kob/cli/src/prediction.rs::blueprint_to_tx`
//! hardcoding `None` on every prediction output).

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::engine_context::EngineCtx;
use kaspa_txscript::{EngineFlags, TxScriptEngine};

use kob_core::build_p2sh;
use kob_core::prediction::{build_ballot_box_redeem_script, build_ballot_box_vote_sigscript};

fn op(b: u8, i: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes([b; 32]), i)
}
fn p2pk_spk(pubkey: &[u8; 32]) -> ScriptPublicKey {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(pubkey);
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}

const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";

/// Build a candidate vote tx and execute BOTH BallotBox covenant inputs
/// (index 0 and 1) through the real engine. Returns per-input results.
///
/// Layout under test (derived from the bytecode's `myidx+1`
/// self-continuation offset used in V2/V3/V4, NOT the (misleading) doc
/// comment at the top of ballot_box.rs):
///   Input[0]: BallotBox A (voted, value decreases by reward_per_vote)
///   Input[1]: BallotBox B (witness, value unchanged)
///   Input[2]: Miner funding
///   Output[0]: Miner change
///   Output[1]: BallotBox A continuation (== input[0].spk, per V2 offset+1)
///   Output[2]: BallotBox B continuation (== input[1].spk, per V2 offset+1)
///   Output[3]: VoteReceipt (V8: absolute index, value >= dust floor only)
#[allow(clippy::too_many_arguments)]
fn run_vote_tx(scenario: &str, ballot_covenant_id: Option<Hash>, cont_covenant_id: Option<Hash>) -> Vec<(usize, String)> {
    let pubkey: [u8; 32] = hex::decode(PUBKEY_HEX).unwrap().try_into().unwrap();
    let wallet_spk = p2pk_spk(&pubkey);

    let market_id = [0x11u8; 32];
    let reward_per_vote = 4_000_000u64; // even, per parity rule; must exceed the receipt dust floor for the miner to net a gain
    let start_daa = 100u64;
    let end_daa = 1_000_000_000u64;
    let expiry_daa = 2_000_000_000u64;

    let rs = build_ballot_box_redeem_script(&market_id, reward_per_vote, start_daa, end_daa, expiry_daa).unwrap();
    let p2sh = build_p2sh(&rs);
    let vote_ss = build_ballot_box_vote_sigscript(&rs);

    let box_value = 500_000_000u64;
    let new_box_value = box_value - reward_per_vote;
    let miner_value = 10_000_000u64;
    let receipt_value = 3_000_000u64;
    // V6 (fee==0): in[0]+in[1]+in[2] == out[0]+out[1]+out[2]+out[3]. in[0]+in[1]
    // == out[1]+out[2] (box_value*2 - reward_per_vote, since only A decreases),
    // so the miner's in/out delta must absorb BOTH the reward AND the new
    // receipt output: miner_change = miner_value + reward_per_vote - receipt_value.
    let miner_change = miner_value + reward_per_vote - receipt_value;

    let inputs = vec![
        TransactionInput::new(op(0x10, 0), vote_ss.clone(), 0, 0), // BallotBox A
        TransactionInput::new(op(0x11, 0), vote_ss.clone(), 0, 0), // BallotBox B (witness)
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),  // Miner funding (not executed)
    ];

    let cont_binding = |authorizing_input: u16| cont_covenant_id.map(|cid| CovenantBinding::new(authorizing_input, cid));

    let outputs = vec![
        TransactionOutput::with_covenant(miner_change, wallet_spk.clone(), None), // [0] miner change
        TransactionOutput::with_covenant(new_box_value, p2sh.clone(), cont_binding(0)), // [1] A cont
        TransactionOutput::with_covenant(box_value, p2sh.clone(), cont_binding(1)), // [2] B cont (unchanged)
        TransactionOutput::with_covenant(receipt_value, wallet_spk.clone(), None), // [3] receipt (SPK content unchecked on-chain)
    ];

    // lockTime must satisfy start_daa <= lockTime < end_daa.
    let tx = Transaction::new(1, inputs, outputs, start_daa, Default::default(), 0, vec![]);

    let entries = vec![
        UtxoEntry { amount: box_value, script_public_key: p2sh.clone(), block_daa_score: 0, is_coinbase: false, covenant_id: ballot_covenant_id },
        UtxoEntry { amount: box_value, script_public_key: p2sh.clone(), block_daa_score: 0, is_coinbase: false, covenant_id: ballot_covenant_id },
        UtxoEntry { amount: miner_value, script_public_key: wallet_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];

    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[{scenario}] CovenantsContext::from_tx FAILED -> {e:?}");
            return vec![(usize::MAX, format!("{e:?}"))];
        }
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };

    let mut results = Vec::new();
    for idx in [0usize, 1usize] {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut log: Vec<u8> = Vec::new();
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags)
            .with_opcode_execution_log_buffer(&mut log);
        let res = vm.execute();
        drop(vm);
        match res {
            Ok(()) => {
                eprintln!("[{scenario}] input[{idx}] script: OK");
                results.push((idx, "OK".to_string()));
            }
            Err(e) => {
                eprintln!("[{scenario}] input[{idx}] script: FAILED -> {e:?}");
                let text = String::from_utf8_lossy(&log);
                let lines: Vec<&str> = text.lines().collect();
                let start = lines.len().saturating_sub(16);
                for l in &lines[start..] {
                    eprintln!("  {l}");
                }
                results.push((idx, format!("{e:?}")));
            }
        }
    }
    results
}

/// Reproduces the CURRENT deploy bug: `build_create_market_tx` emits BallotBox
/// outputs with `covenant: None` (see `blueprint_to_tx` in
/// `kob/cli/src/prediction.rs`), so the funding UtxoEntry's `covenant_id` is
/// `None` on-chain -- V0 (`OpCovInputCount == 2`) must then fail, since
/// `OpInputCovenantId` on a `None` entry pushes `ZERO_HASH`, which has zero
/// registered covenant inputs (a `None`-covenant UTXO is never added to
/// `shared_ctxs` at all, not even under `ZERO_HASH`).
#[test]
fn vote_fails_when_deploy_never_attached_a_covenant_binding() {
    let results = run_vote_tx("no-covenant-binding (current deploy bug)", None, None);
    let failed = results.iter().any(|(_, r)| r != "OK");
    assert!(failed, "expected the vote tx to FAIL when BallotBox has no covenant_id (reproduces the deploy gap)");
}

/// With a properly-shared `covenant_id` on both BallotBox inputs (as if
/// `build_create_market_tx` attached a genesis `CovenantBinding` covering
/// BOTH the YES and NO outputs together, per `compute_covenant_id`) AND the
/// derived 3-in/4-out layout (MinerChange@0, ContA@1, ContB@2, Receipt@3),
/// the vote path's covenant checks (V0/V0b/V2/V3/V4/V5/V6/V7/V8) all pass.
#[test]
fn vote_passes_with_shared_covenant_binding_and_derived_layout() {
    let cid = Hash::from_bytes([0xABu8; 32]);
    let results = run_vote_tx("shared-covenant-binding + derived layout", Some(cid), Some(cid));
    for (idx, r) in &results {
        assert_eq!(r, "OK", "input[{idx}] must pass: {r}");
    }
}
