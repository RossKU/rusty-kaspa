//! KCC20 `transfer` / `transfer_delegator` (kob/core/src/contract/kcc20/transfer.rs)
//! exercised against the real post-Toccata `kaspa-txscript` `TxScriptEngine`
//! (`covenants_enabled = true`), the same style as
//! `kob/core/tests/x402_borrow_covenant.rs` and `spot_contracts.rs`.
//!
//! This is where "does it actually run" surfaced several holes not visible
//! from reading the spec alone -- see the accompanying implementation report
//! for the full ISSUE list. Notably:
//!
//! - the KCC1 `int` state payload (8-byte, non-minimal, signed-magnitude) is
//!   accepted DIRECTLY by `OpAdd`/`OpSub` only because `covenants_enabled`
//!   disables minimal-encoding enforcement in this engine
//!   (`crypto/txscript/src/data_stack.rs`'s `pop_items` uses
//!   `!self.covenants_enabled` as `enforce_minimal`) -- this is an engine
//!   behavior kcc-0001 itself never documents, and a script relying on it
//!   under a hypothetical future engine that DOES enforce minimality here
//!   would silently break;
//! - `transfer_delegator()`'s declared zero arguments cannot actually carry
//!   zero bytes in a working implementation (see `transfer.rs` module doc);
//! - signing a KCC20 `transfer`/`transfer_delegator` invocation requires
//!   computing a real per-input Schnorr sighash
//!   (`calc_schnorr_signature_hash`) -- nothing in kcc-0001/kcc-0020 says
//!   which `SigHashType` a KCC20 owner signature should use; this test suite
//!   (like every other pre-existing signing sigScript in this crate) assumes
//!   `SIG_HASH_ALL`, but that is KOB's own convention, not something kcc-0020
//!   specifies.

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
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

use kob_core::contract::kcc20::{
    build_kcc20_token_redeem_script, build_sigscript, build_transfer_delegator_sigscript,
    build_transfer_leader_sigscript, identifier_type, Entrypoint, Kcc20State, KCC20_TRANSFER_MAX_N,
};
use kob_core::primitives::push_data;
use kob_core::{build_p2sh, get_public_key, schnorr_sign};

const DIGEST: [u8; 32] = [0u8; 32];
const OTHER_DIGEST: [u8; 32] = [0xEE; 32];
const OUTPUT_KAS_VALUE: u64 = 10_000_000;

fn privkey(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn pubkey(seed: u8) -> [u8; 32] {
    get_public_key(&privkey(seed)).unwrap()
}

fn hash32(b: u8) -> Hash {
    Hash::from_bytes([b; 32])
}

fn kcc20_state(owner: [u8; 32], amount: u64, digest: [u8; 32]) -> Kcc20State {
    Kcc20State::new(owner, identifier_type::PUBKEY, amount, digest)
}

fn outpoint(b: u8, i: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes([b; 32]), i)
}

fn new_rs_slots(active: &[Vec<u8>]) -> [Vec<u8>; KCC20_TRANSFER_MAX_N] {
    let mut slots: [Vec<u8>; KCC20_TRANSFER_MAX_N] =
        [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    assert!(active.len() <= KCC20_TRANSFER_MAX_N);
    for (i, rs) in active.iter().enumerate() {
        slots[i] = rs.clone();
    }
    slots
}

/// One covenant input in a transfer scenario: `privkey_seed` derives BOTH the
/// `owner_identifier` baked into the consumed state AND (normally) the
/// signing key; `sign_seed` lets a test sign with a DIFFERENT key than the
/// state's true owner (adversarial "wrong signature" cases).
struct InSpec {
    privkey_seed: u8,
    sign_seed: u8,
    amount: u64,
    digest: [u8; 32],
}

impl InSpec {
    fn honest(seed: u8, amount: u64) -> Self {
        InSpec { privkey_seed: seed, sign_seed: seed, amount, digest: DIGEST }
    }
}

/// One successor (covenant output) slot.
struct OutSpec {
    recipient_seed: u8,
    amount: u64,
    digest: [u8; 32],
}

impl OutSpec {
    fn honest(seed: u8, amount: u64) -> Self {
        OutSpec { recipient_seed: seed, amount, digest: DIGEST }
    }
}

struct Built {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    n_inputs: usize,
}

/// Build a fully assembled, honestly-signed KCC20 transfer transaction: the
/// leader is input 0 (`ins[0]`); `ins[1..]` are delegators, all sharing
/// `cov_id`. Successor outputs are `outs`, each covenant-bound to the leader
/// (`authorizing_input = 0`).
fn build_transfer(cov_id: Hash, ins: &[InSpec], outs: &[OutSpec]) -> Built {
    let input_states: Vec<Kcc20State> =
        ins.iter().map(|i| kcc20_state(pubkey(i.privkey_seed), i.amount, i.digest)).collect();
    let input_rs: Vec<Vec<u8>> =
        input_states.iter().map(|s| build_kcc20_token_redeem_script(s).unwrap()).collect();
    let input_spks: Vec<ScriptPublicKey> = input_rs.iter().map(|rs| build_p2sh(rs)).collect();

    let output_states: Vec<Kcc20State> =
        outs.iter().map(|o| kcc20_state(pubkey(o.recipient_seed), o.amount, o.digest)).collect();
    let output_rs: Vec<Vec<u8>> =
        output_states.iter().map(|s| build_kcc20_token_redeem_script(s).unwrap()).collect();
    let output_spks: Vec<ScriptPublicKey> = output_rs.iter().map(|rs| build_p2sh(rs)).collect();

    let tx_outputs: Vec<TransactionOutput> = output_spks
        .iter()
        .map(|spk| {
            TransactionOutput::with_covenant(
                OUTPUT_KAS_VALUE,
                spk.clone(),
                Some(CovenantBinding::new(0, cov_id)),
            )
        })
        .collect();

    let entries: Vec<UtxoEntry> = input_spks
        .iter()
        .zip(ins.iter())
        .map(|(spk, i)| UtxoEntry {
            amount: i.amount,
            script_public_key: spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(cov_id),
        })
        .collect();

    let placeholder_inputs: Vec<TransactionInput> =
        (0..ins.len()).map(|idx| TransactionInput::new(outpoint(0x10 + idx as u8, 0), vec![], 0, 0)).collect();
    let skeleton_tx = Transaction::new(0, placeholder_inputs, tx_outputs.clone(), 0, Default::default(), 0, vec![]);
    let populated_skeleton = PopulatedTransaction::new(&skeleton_tx, entries.clone());

    let sigs: Vec<[u8; 64]> = (0..ins.len())
        .map(|idx| {
            let reused = SigHashReusedValuesUnsync::new();
            let hash = calc_schnorr_signature_hash(&populated_skeleton, idx, SIG_HASH_ALL, &reused);
            schnorr_sign(&hash.as_bytes(), &privkey(ins[idx].sign_seed)).unwrap()
        })
        .collect();

    let final_inputs: Vec<TransactionInput> = (0..ins.len())
        .map(|idx| {
            let ss = if idx == 0 {
                let slots = new_rs_slots(&output_rs);
                build_transfer_leader_sigscript(&input_rs[0], &slots, &sigs[0], &input_rs[0])
            } else {
                build_transfer_delegator_sigscript(&sigs[idx], &input_rs[idx])
            };
            TransactionInput::new(outpoint(0x10 + idx as u8, 0), ss, 0, 0)
        })
        .collect();

    let tx = Transaction::new(0, final_inputs, tx_outputs, 0, Default::default(), 0, vec![]);
    Built { tx, entries, n_inputs: ins.len() }
}

/// Re-sign input 0 (the leader) of an already-built transaction with a
/// DIFFERENT private key than the true owner's, keeping everything else
/// (including the true owner's `owner_identifier` baked into the consumed
/// state) unchanged.
fn resign_leader_wrong_key(built: &mut Built, self_rs: &[u8], new_rs: &[Vec<u8>], wrong_privkey_seed: u8) {
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
    let wrong_sig = schnorr_sign(&hash.as_bytes(), &privkey(wrong_privkey_seed)).unwrap();
    let slots = new_rs_slots(new_rs);
    built.tx.inputs[0].signature_script = build_transfer_leader_sigscript(self_rs, &slots, &wrong_sig, self_rs);
}

fn run(built: &Built) -> Vec<Result<(), String>> {
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!("ctx: {e:?}")); built.n_inputs],
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    (0..built.n_inputs)
        .map(|idx| {
            let reused = SigHashReusedValuesUnsync::new();
            let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
            let (input, entry) = populated.populated_input(idx);
            let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
            vm.execute().map_err(|e| format!("{e:?}"))
        })
        .collect()
}

// ============================================================================
// Happy paths
// ============================================================================

#[test]
fn single_input_transfer_happy_path() {
    let cov_id = hash32(0xA0);
    let ins = vec![InSpec::honest(1, 5_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let built = build_transfer(cov_id, &ins, &outs);
    let results = run(&built);
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok(), "single-input honest transfer must pass: {:?}", results[0]);
}

#[test]
fn two_input_consolidation_happy_path() {
    // leader (input0) 3M + sibling (input1) 2M -> one successor with 5M,
    // same extended_state_digest throughout.
    let cov_id = hash32(0xA1);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let built = build_transfer(cov_id, &ins, &outs);
    let results = run(&built);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(), "leader (consolidation) must pass: {:?}", results[0]);
    assert!(results[1].is_ok(), "delegator (consolidation) must pass: {:?}", results[1]);
}

#[test]
fn one_input_split_into_two_outputs_happy_path() {
    let cov_id = hash32(0xA2);
    let ins = vec![InSpec::honest(1, 7_000_000)];
    let outs = vec![OutSpec::honest(2, 3_000_000), OutSpec::honest(4, 4_000_000)];
    let built = build_transfer(cov_id, &ins, &outs);
    let results = run(&built);
    assert!(results[0].is_ok(), "1-in/2-out split must pass: {:?}", results[0]);
}

// ============================================================================
// Adversarial: amount / digest
// ============================================================================

#[test]
fn amount_mismatch_rejected() {
    let cov_id = hash32(0xB0);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    // Successor claims 5_000_001, one sompi more than conserved -- must fail.
    let outs = vec![OutSpec::honest(2, 5_000_001)];
    let built = build_transfer(cov_id, &ins, &outs);
    let results = run(&built);
    assert!(results[0].is_err(), "amount-inflating transfer must be rejected by the leader");
}

#[test]
fn amount_mismatch_deficit_also_rejected() {
    // Under-delivery (burning value) must ALSO fail: transfer requires EXACT
    // conservation, not merely "no inflation".
    let cov_id = hash32(0xB1);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    let outs = vec![OutSpec::honest(2, 4_999_999)];
    let built = build_transfer(cov_id, &ins, &outs);
    let results = run(&built);
    assert!(results[0].is_err(), "amount-deficit transfer must be rejected by the leader");
}

#[test]
fn digest_mismatch_rejected() {
    let cov_id = hash32(0xB2);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    let mut outs = vec![OutSpec::honest(2, 5_000_000)];
    outs[0].digest = OTHER_DIGEST; // successor carries a DIFFERENT extended_state_digest
    let built = build_transfer(cov_id, &ins, &outs);
    let results = run(&built);
    assert!(results[0].is_err(), "successor with mismatched extended_state_digest must be rejected");
}

#[test]
fn sibling_digest_mismatch_rejected() {
    // Consolidation where the SIBLING (not the leader) carries a different
    // extended_state_digest than the leader/successor.
    let cov_id = hash32(0xB3);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec { privkey_seed: 3, sign_seed: 3, amount: 2_000_000, digest: OTHER_DIGEST }];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let built = build_transfer(cov_id, &ins, &outs);
    let results = run(&built);
    assert!(results[0].is_err(), "sibling with a different extended_state_digest must be rejected by the leader");
}

// ============================================================================
// Adversarial: dispatch tag
// ============================================================================

#[test]
fn leader_wrong_dispatch_tag_rejected() {
    let cov_id = hash32(0xC0);
    let ins = vec![InSpec::honest(1, 5_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer(cov_id, &ins, &outs);

    // Rebuild input 0's sigScript with the SAME leader-shaped arguments but
    // the `transfer_delegator` dispatch tag instead of `transfer`'s.
    let input_state = kcc20_state(pubkey(1), 5_000_000, DIGEST);
    let input_rs = build_kcc20_token_redeem_script(&input_state).unwrap();
    let output_state = kcc20_state(pubkey(2), 5_000_000, DIGEST);
    let output_rs = build_kcc20_token_redeem_script(&output_state).unwrap();

    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
    let sig = schnorr_sign(&hash.as_bytes(), &privkey(1)).unwrap();
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(&sig);
    sig_with_type.push(0x01);

    let mut args = Vec::new();
    args.extend_from_slice(&push_data(&input_rs)); // self_rs
    args.extend_from_slice(&push_data(&output_rs)); // new_rs_1
    for _ in 0..(KCC20_TRANSFER_MAX_N - 1) {
        args.extend_from_slice(&push_data(&[])); // unused new_rs slots
    }
    args.extend_from_slice(&push_data(&sig_with_type));

    built.tx.inputs[0].signature_script = build_sigscript(Entrypoint::TransferDelegator, &args, &input_rs);

    let results = run(&built);
    assert!(results[0].is_err(), "leader-shaped invocation under the WRONG dispatch tag must be rejected");
}

// ============================================================================
// Adversarial: ownership authorization
// ============================================================================

#[test]
fn leader_missing_owner_signature_rejected() {
    let cov_id = hash32(0xD0);
    let ins = vec![InSpec::honest(1, 5_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer(cov_id, &ins, &outs);

    let input_state = kcc20_state(pubkey(1), 5_000_000, DIGEST);
    let input_rs = build_kcc20_token_redeem_script(&input_state).unwrap();
    let output_state = kcc20_state(pubkey(2), 5_000_000, DIGEST);
    let output_rs = build_kcc20_token_redeem_script(&output_state).unwrap();

    // Sign with an unrelated key (seed 99), not the true owner (seed 1).
    resign_leader_wrong_key(&mut built, &input_rs, &[output_rs], 99);

    let results = run(&built);
    assert!(results[0].is_err(), "leader transfer signed by the WRONG key must be rejected");
}

#[test]
fn delegator_missing_owner_signature_rejected() {
    let cov_id = hash32(0xD1);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer(cov_id, &ins, &outs);

    // Re-sign the SIBLING (input 1) with the wrong key; leader stays honest.
    let sibling_state = kcc20_state(pubkey(3), 2_000_000, DIGEST);
    let sibling_rs = build_kcc20_token_redeem_script(&sibling_state).unwrap();
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, 1, SIG_HASH_ALL, &reused);
    let wrong_sig = schnorr_sign(&hash.as_bytes(), &privkey(77)).unwrap();
    built.tx.inputs[1].signature_script = build_transfer_delegator_sigscript(&wrong_sig, &sibling_rs);

    let results = run(&built);
    assert!(results[0].is_ok(), "leader path is independent of a sibling's own auth failure: {:?}", results[0]);
    assert!(results[1].is_err(), "delegator transfer signed by the WRONG key must be rejected");
}

// ============================================================================
// Adversarial: leader/delegator role
// ============================================================================

#[test]
fn delegator_running_leader_body_rejected() {
    // A non-leader (higher-indexed) covenant input tries to invoke `transfer`
    // (the leader entrypoint) instead of `transfer_delegator`. kcc-0001 §9.1
    // rule 1: "Each path MUST reject the opposite position."
    let cov_id = hash32(0xE0);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer(cov_id, &ins, &outs);

    let sibling_state = kcc20_state(pubkey(3), 2_000_000, DIGEST);
    let sibling_rs = build_kcc20_token_redeem_script(&sibling_state).unwrap();
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, 1, SIG_HASH_ALL, &reused);
    let sig = schnorr_sign(&hash.as_bytes(), &privkey(3)).unwrap();
    // Input 1 invokes `transfer` (leader entrypoint) using ITSELF as self_rs,
    // with no real successors -- it is not the leader (input0 is), so this
    // must be rejected by the leader-position check regardless of anything
    // else in the body.
    let slots = new_rs_slots(&[]);
    built.tx.inputs[1].signature_script = build_transfer_leader_sigscript(&sibling_rs, &slots, &sig, &sibling_rs);

    let results = run(&built);
    assert!(results[1].is_err(), "a non-leader input invoking `transfer` must be rejected");
}

#[test]
fn leader_running_delegator_body_rejected() {
    // The (true) leader input tries to invoke `transfer_delegator` instead of
    // validating the shared transition. Must be rejected: the leader path
    // requires being at covenant-input position 0, and here the DELEGATOR
    // check requires NOT being the leader -- input0 IS the leader, so the
    // delegator's "reject the opposite position" check must fail it.
    let cov_id = hash32(0xE1);
    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer(cov_id, &ins, &outs);

    let leader_state = kcc20_state(pubkey(1), 3_000_000, DIGEST);
    let leader_rs = build_kcc20_token_redeem_script(&leader_state).unwrap();
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
    let sig = schnorr_sign(&hash.as_bytes(), &privkey(1)).unwrap();
    built.tx.inputs[0].signature_script = build_transfer_delegator_sigscript(&sig, &leader_rs);

    let results = run(&built);
    assert!(results[0].is_err(), "the leader input invoking `transfer_delegator` must be rejected");
}

// ============================================================================
// Adversarial: successor template / binding forgery
// ============================================================================

#[test]
fn successor_wrong_template_rejected() {
    // The successor's redeem script preserves the correct amount/digest
    // PREFIX bytes but swaps in a completely different (foreign) suffix --
    // i.e. the same attack kcc-0001 §8.5 template authentication exists to
    // block: reconstructing a same-shaped state while locking the successor
    // under a different program.
    let cov_id = hash32(0xF0);
    let ins = vec![InSpec::honest(1, 5_000_000)];

    let input_state = kcc20_state(pubkey(1), 5_000_000, DIGEST);
    let input_rs = build_kcc20_token_redeem_script(&input_state).unwrap();

    let output_state = kcc20_state(pubkey(2), 5_000_000, DIGEST);
    let honest_output_rs = build_kcc20_token_redeem_script(&output_state).unwrap();
    // Forge: same 77-byte state prefix, foreign suffix (a single OP_1 body
    // instead of the real dispatch skeleton).
    let mut forged_output_rs = honest_output_rs[..Kcc20State::ENCODED_LEN].to_vec();
    forged_output_rs.push(0x51); // OP_1 -- foreign "always true" body

    let forged_spk = build_p2sh(&forged_output_rs);
    let tx_outputs = vec![TransactionOutput::with_covenant(OUTPUT_KAS_VALUE, forged_spk, Some(CovenantBinding::new(0, cov_id)))];
    let entries = vec![UtxoEntry {
        amount: 5_000_000,
        script_public_key: build_p2sh(&input_rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cov_id),
    }];
    let placeholder_inputs = vec![TransactionInput::new(outpoint(0x10, 0), vec![], 0, 0)];
    let skeleton_tx = Transaction::new(0, placeholder_inputs, tx_outputs.clone(), 0, Default::default(), 0, vec![]);
    let populated_skeleton = PopulatedTransaction::new(&skeleton_tx, entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated_skeleton, 0, SIG_HASH_ALL, &reused);
    let sig = schnorr_sign(&hash.as_bytes(), &privkey(ins[0].privkey_seed)).unwrap();
    let slots = new_rs_slots(&[forged_output_rs]);
    let ss = build_transfer_leader_sigscript(&input_rs, &slots, &sig, &input_rs);
    let final_inputs = vec![TransactionInput::new(outpoint(0x10, 0), ss, 0, 0)];
    let tx = Transaction::new(0, final_inputs, tx_outputs, 0, Default::default(), 0, vec![]);
    let built = Built { tx, entries, n_inputs: 1 };

    let results = run(&built);
    assert!(results[0].is_err(), "a successor with a foreign (non-template) suffix must be rejected");
}

#[test]
fn successor_output_spk_does_not_match_claimed_new_rs_rejected() {
    // The leader's `new_rs_1` argument is honest, but the ACTUAL output SPK
    // locks to something else entirely (a plain P2PK, say) -- the claimed
    // successor and the real output must be provably the same script.
    let cov_id = hash32(0xF1);
    let ins = vec![InSpec::honest(1, 5_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer(cov_id, &ins, &outs);

    // Swap the real output's scriptPublicKey for an unrelated one, while
    // leaving the covenant binding (and thus its classification as this
    // covenant's continuation output) intact.
    let mut attacker_spk_script = vec![0x20u8];
    attacker_spk_script.extend_from_slice(&pubkey(66));
    attacker_spk_script.push(0xac);
    built.tx.outputs[0].script_public_key = ScriptPublicKey::new(0, attacker_spk_script.into());

    let results = run(&built);
    assert!(results[0].is_err(), "output SPK not matching the claimed new_rs must be rejected");
}

// ============================================================================
// Adversarial: cardinality / unrelated covenant input
// ============================================================================

#[test]
fn unrelated_covenant_id_input_is_not_absorbed_into_the_group() {
    // A third input carries a DIFFERENT covenant_id (a different token
    // entirely). It must not be countable as this transfer's sibling, and
    // must not affect the honest 2-input consolidation's own validity.
    let cov_id = hash32(0x90);
    let other_cov_id = hash32(0x91);

    let ins = vec![InSpec::honest(1, 3_000_000), InSpec::honest(3, 2_000_000)];
    let outs = vec![OutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer(cov_id, &ins, &outs);

    // Append a THIRD input carrying an unrelated covenant_id, spending an
    // unrelated (also KCC20-shaped, but different token) UTXO, with its own
    // valid delegator-shaped self-authorization for ITS OWN covenant. Since
    // it does not share `cov_id`, it must be invisible to this transfer's
    // `OpCovInputCount`/`OpCovInputIdx(cov_id, ..)` enumeration.
    let other_state = kcc20_state(pubkey(5), 1_000_000, DIGEST);
    let other_rs = build_kcc20_token_redeem_script(&other_state).unwrap();
    built.entries.push(UtxoEntry {
        amount: 1_000_000,
        script_public_key: build_p2sh(&other_rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(other_cov_id),
    });
    built.tx.inputs.push(TransactionInput::new(outpoint(0x20, 0), vec![], 0, 0));
    built.n_inputs = 3;

    // Re-sign inputs 0/1 (their sighash changed: a new input was added to
    // the transaction) and sign the new input 2 for its OWN transfer as the
    // leader of `other_cov_id`.
    let input0_state = kcc20_state(pubkey(1), 3_000_000, DIGEST);
    let input0_rs = build_kcc20_token_redeem_script(&input0_state).unwrap();
    let input1_state = kcc20_state(pubkey(3), 2_000_000, DIGEST);
    let input1_rs = build_kcc20_token_redeem_script(&input1_state).unwrap();
    let output_state = kcc20_state(pubkey(2), 5_000_000, DIGEST);
    let output_rs = build_kcc20_token_redeem_script(&output_state).unwrap();

    let other_output_state = kcc20_state(pubkey(6), 1_000_000, DIGEST);
    let other_output_rs = build_kcc20_token_redeem_script(&other_output_state).unwrap();
    let other_output_spk = build_p2sh(&other_output_rs);
    built.tx.outputs.push(TransactionOutput::with_covenant(
        OUTPUT_KAS_VALUE,
        other_output_spk,
        Some(CovenantBinding::new(2, other_cov_id)),
    ));

    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let sig0 = schnorr_sign(
        &calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused).as_bytes(),
        &privkey(1),
    )
    .unwrap();
    let sig1 = schnorr_sign(
        &calc_schnorr_signature_hash(&populated, 1, SIG_HASH_ALL, &reused).as_bytes(),
        &privkey(3),
    )
    .unwrap();
    let sig2 = schnorr_sign(
        &calc_schnorr_signature_hash(&populated, 2, SIG_HASH_ALL, &reused).as_bytes(),
        &privkey(5),
    )
    .unwrap();

    let slots0 = new_rs_slots(&[output_rs]);
    built.tx.inputs[0].signature_script = build_transfer_leader_sigscript(&input0_rs, &slots0, &sig0, &input0_rs);
    built.tx.inputs[1].signature_script = build_transfer_delegator_sigscript(&sig1, &input1_rs);
    let slots2 = new_rs_slots(&[other_output_rs]);
    built.tx.inputs[2].signature_script = build_transfer_leader_sigscript(&other_rs, &slots2, &sig2, &other_rs);

    let results = run(&built);
    assert!(results[0].is_ok(), "leader of cov_id must still pass with an unrelated covenant_id input present: {:?}", results[0]);
    assert!(results[1].is_ok(), "delegator of cov_id must still pass: {:?}", results[1]);
    assert!(results[2].is_ok(), "the unrelated covenant_id's own (independent) leader transfer must pass on its own: {:?}", results[2]);
}
