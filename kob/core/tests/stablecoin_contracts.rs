//! KCC-0020 stablecoin covenant — Phase I "Liquid AMP"-equivalent
//! authorized-transfer model — exercised against the real post-Toccata
//! `kaspa-txscript` `TxScriptEngine` (`covenants_enabled = true`), in the same
//! harness style as `kob/core/tests/kcc20_contracts.rs`.
//!
//! This proves the TRANSFER (`op_type = 0x00`) branch actually runs on the
//! real engine, and — the load-bearing property — that the off-chain
//! attestation message ([`build_attestation_message`]) and the on-chain
//! `body`'s introspection-reconstructed `msg_hash` agree **byte-for-byte**.
//! The happy path passing on the real engine is the proof that round-trip
//! closes; the adversarial cases prove the TRANSFER invariants (owner auth,
//! OPS attestation, `frozen_flag == 0`, successor `role_registry_root`/`epoch`
//! continuity, replay binding, cross-branch `op_type` binding) are each
//! actually enforced, not just documented.
//!
//! # Superseded case-A test file (migration note)
//!
//! This file previously targeted the case-A single-mode covenant (a 2-arg
//! `build_stablecoin_redeem_script(owner_pubkey, issuer_pubkey)`, a 5-arg
//! `build_attestation_message`, and `build_stablecoin_sigscript`), before the
//! covenant was extended in place to the Phase I op_type-dispatch / mutable
//! state-header model documented in `contract::stablecoin::{body, state,
//! attestation}`. That API no longer exists (6-arg redeem-script builder,
//! 7-arg attestation message, renamed `build_stablecoin_transfer_sigscript`),
//! so the old tests could not compile as-is.
//!
//! Migrated as-is (reshaped to the new signatures): the single "happy path"
//! acceptance test (`happy_freeze_off_accepts` -> [`happy_transfer_accepts`]).
//!
//! Dropped (no direct 1:1 counterpart under the new model; each is a
//! case-A-only concept and/or required hand-assembling a non-64-byte
//! "issuer_sig" push that the new fixed-size sigscript builder no longer
//! accommodates without bypassing it entirely — reported here rather than
//! silently discarded):
//! - `freeze_no_attestation_empty_issuer_sig_rejected` (0-byte issuer sig —
//!   case-A's "freeze" was a standalone toggle; Phase I has no equivalent
//!   "just omit the signature" spend shape once the sigscript builder fixes
//!   `issuer_sig` at 64 bytes).
//! - `freeze_zero_issuer_sig_rejected` (well-formed all-zero 64B forged sig —
//!   same case-A freeze-toggle framing; the *forged/wrong-key* variant of
//!   this idea is exercised for Phase I by [`transfer_wrong_ops_key_rejected`]
//!   below).
//! - `freeze_wrong_key_issuer_sig_rejected` — superseded by
//!   [`transfer_wrong_ops_key_rejected`].
//! - `conformance_shifted_outpoint_index_in_attestation_rejected` — same
//!   replay-binding property as [`transfer_attestation_replay_other_outpoint_rejected`]
//!   below, just on a different bound field (index vs. txid); not respecified
//!   separately per the Phase I test plan.
//! - `replay_attestation_for_other_outpoint_rejected` — superseded by
//!   [`transfer_attestation_replay_other_outpoint_rejected`].
//! - `recipient_substitution_rejected`, `amount_tamper_rejected`,
//!   `owner_wrong_key_rejected`, `cross_token_attestation_rejected`,
//!   `cross_token_control_same_covenant_accepts` — case-A adversarial
//!   coverage of invariants that Phase I still enforces via the same
//!   introspection-bound preimage, but are out of scope for this pass's
//!   TRANSFER adversarial batch (see module doc list below); not carried
//!   forward to keep this migration bounded to what was specified.

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::engine_context::EngineCtx;
use kaspa_txscript::{EngineFlags, TxScriptEngine};

use kob_core::contract::stablecoin::attestation::op_type;
use kob_core::contract::stablecoin::state::frozen_flag;
use kob_core::contract::stablecoin::{
    build_attestation_message, build_freeze_attestation_message, build_migrate_attestation_message, build_seize_attestation_message,
    build_stablecoin_burn_sigscript, build_stablecoin_freeze_sigscript, build_stablecoin_migrate_sigscript,
    build_stablecoin_redeem_script, build_stablecoin_seize_sigscript, build_stablecoin_transfer_sigscript, BURN_SINK_SCRIPT,
};
use kob_core::contract::token::identifier_type as id_type;
use kob_core::{build_p2sh, get_public_key, push_data, schnorr_sign};

const IN_AMOUNT: u64 = 5_000_000;
const ROOT: [u8; 32] = [0xEE; 32];
// Fixed FREEZE-role pubkey seed baked into every TRANSFER-scenario redeem
// script in this file (both `rs` and `new_rs`) -- TRANSFER's own adversarial
// batch doesn't exercise the FREEZE branch or key at all, so a single shared
// constant (rather than a new `Cfg` field) keeps that batch's existing
// field list/`..Cfg::honest()` call sites untouched.
const TRANSFER_SCENARIO_FREEZE_SEED: u8 = 9;
// Fixed SEIZE-role pubkey seeds baked into every redeem script in this file
// built by a scenario that does NOT itself exercise the SEIZE branch
// (TRANSFER's `Cfg::build` and FREEZE's `build_freeze_scenario`) -- neither
// batch tests the SEIZE key/branch, so a single shared constant (rather than
// new fields on each `Cfg`) keeps those batches' existing field
// lists/`..Cfg::honest()` call sites untouched, mirroring
// `TRANSFER_SCENARIO_FREEZE_SEED` above.
const UNRELATED_SEIZE_SEEDS: [u8; 3] = [90, 91, 92];
// Fixed MINT-role pubkey seed baked into every redeem script in this file
// built by a scenario that does NOT itself exercise the BURN branch
// (TRANSFER's `Cfg::build`, FREEZE's `build_freeze_scenario`, SEIZE's
// `build_seize`) -- none of those batches test the MINT key/branch, so a
// single shared constant (rather than new fields on each `Cfg`) keeps those
// batches' existing field lists/`..Cfg::honest()` call sites untouched,
// mirroring `TRANSFER_SCENARIO_FREEZE_SEED`/`UNRELATED_SEIZE_SEEDS` above.
const UNRELATED_MINT_SEED: u8 = 95;

fn unrelated_seize_pubkeys() -> [[u8; 32]; 3] {
    [pubkey(UNRELATED_SEIZE_SEEDS[0]), pubkey(UNRELATED_SEIZE_SEEDS[1]), pubkey(UNRELATED_SEIZE_SEEDS[2])]
}

fn unrelated_mint_pubkey() -> [u8; 32] {
    pubkey(UNRELATED_MINT_SEED)
}

/// The `ScriptPublicKey` for the canonical BURN sink (§8): the P2SH wrapping
/// of [`BURN_SINK_SCRIPT`] (a bare `OpReturn` REDEEM script) -- the honest
/// BURN successor. A bare-`OpReturn` LOCKING script is non-standard on Kaspa
/// (rejected by the mempool as "non-standard script form"); P2SH-wrapping it
/// makes the output standard/relayable while keeping it exactly as
/// unspendable (see `kob_core::contract::stablecoin::BURN_SINK_SCRIPT`'s doc).
fn burn_sink_spk() -> ScriptPublicKey {
    build_p2sh(&BURN_SINK_SCRIPT)
}

fn privkey(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn pubkey(seed: u8) -> [u8; 32] {
    get_public_key(&privkey(seed)).unwrap()
}

fn hash32(b: u8) -> Hash {
    Hash::from_bytes([b; 32])
}

fn outpoint(seed: u8, index: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes([seed; 32]), index)
}

/// Reproduce the (crate-private) `SpkEncoding::to_bytes` form the engine's
/// `OpTxOutputSpk` pushes before the body's `OpBlake3`: the 2-byte big-endian
/// version followed by the script. The off-chain attestation encoder must hash
/// exactly these bytes for `successor_spk_hash` to match on-chain.
fn spk_to_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut v = spk.version().to_be_bytes().to_vec();
    v.extend_from_slice(spk.script());
    v
}

/// One TRANSFER scenario. `honest()` yields a fully valid 1:1 transfer; each
/// adversarial test mutates exactly one lever.
#[derive(Clone)]
struct Cfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,
    owner_seed: u8, // owner pubkey baked into the state header AND the key that signs owner_sig
    ops_seed: u8,   // OPS pubkey baked into the body (TRANSFER's OpCheckSigFromStack key)
    root: [u8; 32], // this coin's role_registry_root
    epoch: u32,     // this coin's epoch
    frozen_flag: u8, // this coin's frozen_flag
    in_amount: u64,
    recipient_seed: u8, // successor owner (its P2SH == the real output SPK)
    out_value: u64,     // successor output native value

    // Successor (new_rs) overrides. `None` == carried forward truthfully
    // (matching this coin's own `root`/`epoch` -- the honest case).
    successor_root: Option<[u8; 32]>,
    successor_epoch: Option<u32>,
    /// Role keys baked into the SUCCESSOR body. `None` == this covenant's own
    /// (the honest case). Setting it is the audit-2026-07-20-section-E attack:
    /// a successor that keeps every state field this branch compares while
    /// swapping the role set out from under the issuer.
    successor_role_seeds: Option<(u8, u8, [u8; 3], u8)>,
    /// `frozen_flag` written into the SUCCESSOR. `None` == CLEAR (the honest
    /// case, and the only value TRANSFER may produce).
    successor_frozen_flag: Option<u8>,

    // Overrides for what the OPS role actually SIGNS over (None/default ==
    // truthful, matching the real spend). A disagreeing value is the
    // forgery/replay/cross-branch-replay being tested.
    attest_ops_seed: u8, // key that produces issuer_sig (honest == ops_seed)
    attest_op_type: u8,  // op_type byte inside the SIGNED preimage
    attest_outpoint_txid_seed: Option<u8>, // outpoint txid inside the SIGNED preimage
}

impl Cfg {
    fn honest() -> Self {
        Cfg {
            input_cov_id: hash32(0xC0),
            outpoint_txid_seed: 0x10,
            outpoint_index: 0,
            owner_seed: 1,
            ops_seed: 2,
            root: ROOT,
            epoch: 7,
            frozen_flag: frozen_flag::CLEAR,
            in_amount: IN_AMOUNT,
            recipient_seed: 3,
            out_value: IN_AMOUNT,
            successor_root: None,
            successor_epoch: None,
            successor_role_seeds: None,
            successor_frozen_flag: None,
            attest_ops_seed: 2, // == ops_seed
            attest_op_type: op_type::TRANSFER,
            attest_outpoint_txid_seed: None,
        }
    }
}

struct Built {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

fn build(cfg: &Cfg) -> Built {
    let owner_pub = pubkey(cfg.owner_seed);
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(TRANSFER_SCENARIO_FREEZE_SEED);
    let seize_pubs = unrelated_seize_pubkeys();
    let mint_pub = unrelated_mint_pubkey();
    let rs = build_stablecoin_redeem_script(
        &owner_pub,
        id_type::PUBKEY,
        &cfg.root,
        cfg.frozen_flag,
        cfg.epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let input_spk = build_p2sh(&rs);

    // 1:1 successor: the covenant reads the output at the SAME index as the
    // gated input (index 0).
    let recipient_pub = pubkey(cfg.recipient_seed);
    let successor_root = cfg.successor_root.unwrap_or(cfg.root);
    let successor_epoch = cfg.successor_epoch.unwrap_or(cfg.epoch);
    let (s_ops, s_freeze, s_seize, s_mint) = match cfg.successor_role_seeds {
        None => (ops_pub, freeze_pub, seize_pubs, mint_pub),
        Some((o, f, sz, m)) => (
            pubkey(o),
            pubkey(f),
            [pubkey(sz[0]), pubkey(sz[1]), pubkey(sz[2])],
            pubkey(m),
        ),
    };
    let new_rs = build_stablecoin_redeem_script(
        &recipient_pub,
        id_type::PUBKEY,
        &successor_root,
        cfg.successor_frozen_flag.unwrap_or(frozen_flag::CLEAR),
        successor_epoch,
        &s_ops,
        &s_freeze,
        &s_seize,
        &s_mint,
    );
    let out_spk = build_p2sh(&new_rs);

    let output = TransactionOutput::with_covenant(cfg.out_value, out_spk.clone(), Some(CovenantBinding::new(0, cfg.input_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.in_amount,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // --- Issuer (OPS) attestation (off-chain "Writer" side) ---
    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let msg_txid_seed = cfg.attest_outpoint_txid_seed.unwrap_or(cfg.outpoint_txid_seed);
    let msg_txid_bytes: [u8; 32] = [msg_txid_seed; 32];
    let spk_bytes = spk_to_bytes(&out_spk);
    let attest_msg = build_attestation_message(
        &cov_bytes,
        cfg.attest_op_type,
        cfg.epoch,
        &msg_txid_bytes,
        cfg.outpoint_index,
        &spk_bytes,
        cfg.in_amount,
    );
    let issuer_sig: [u8; 64] = schnorr_sign(&attest_msg, &privkey(cfg.attest_ops_seed)).unwrap();

    // --- Owner authorization (SIGHASH_ALL over the tx) ---
    // Compute the sighash on a skeleton with an empty sig script (SIGHASH_ALL
    // does not commit the signature scripts), then assemble the real input.
    let skeleton_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), vec![], 0, 2);
    let skeleton_tx = Transaction::new(0, vec![skeleton_input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let populated_skeleton = PopulatedTransaction::new(&skeleton_tx, entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&populated_skeleton, 0, SIG_HASH_ALL, &reused);
    let owner_sig: [u8; 64] = schnorr_sign(&sighash.as_bytes(), &privkey(cfg.owner_seed)).unwrap();

    let ss = build_stablecoin_transfer_sigscript(&owner_sig, &issuer_sig, &new_rs, &rs);
    // sig_op_count = 2: one OpCheckSigVerify (owner) + one OpCheckSigFromStack (OPS).
    let final_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), ss, 0, 2);
    let tx = Transaction::new(0, vec![final_input], vec![output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

fn run(built: &Built) -> Result<(), String> {
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| format!("ctx: {e:?}"))?;
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 0, entry, ctx, flags);
    vm.execute().map_err(|e| format!("{e:?}"))
}

/// Assert the run was rejected, and that the failure is the *intended*
/// verification failure (its Debug rendering contains `needle`), not a generic
/// parse / stack error.
fn assert_rejected_with(res: &Result<(), String>, needle: &str) {
    match res {
        Ok(()) => panic!("expected reject via {needle}, but the transfer was ACCEPTED"),
        Err(e) => assert!(e.contains(needle), "expected reject via `{needle}`, got a different failure: {e}"),
    }
}

// ============================================================================
// 1. Happy path + conformance round-trip proof (migrated from case-A's
//    `happy_freeze_off_accepts`)
// ============================================================================

#[test]
fn happy_transfer_accepts() {
    // A correctly owner-signed, correctly OPS-attested 1:1 TRANSFER, with the
    // successor carrying forward the same role_registry_root/epoch.
    //
    // That this passes on the real engine IS the conformance proof: the OPS
    // role signed `build_attestation_message(...)` off-chain, and the body
    // recomputed the identical 32-byte msg_hash from transaction introspection
    // (covenant_id / op_type / epoch / outpoint / successor_spk_hash / amount)
    // -- if any field or width disagreed, OpCheckSigFromStack would return
    // false and OpVerify would abort. Acceptance here means the off-chain and
    // on-chain pre-images are byte-identical.
    let res = run(&build(&Cfg::honest()));
    assert!(res.is_ok(), "honest attested TRANSFER must be accepted: {res:?}");
}

// ============================================================================
// 2. TRANSFER adversarial batch
// ============================================================================

#[test]
fn transfer_frozen_flag_set_rejected() {
    // §4's new TRANSFER invariant: frozen_flag must be 0 (CLEAR). An
    // otherwise fully honest transfer on a frozen coin must still be rejected
    // -- fail-closed, independent of the OPS attestation being valid.
    let cfg = Cfg { frozen_flag: frozen_flag::SET, ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_wrong_ops_key_rejected() {
    // The attestation is a valid signature over the correct message, but from
    // the WRONG key (not the OPS key baked into the body). Only the real OPS
    // role can attest.
    let cfg = Cfg { attest_ops_seed: 99, ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_successor_swapping_the_role_set_rejected() {
    // Audit 2026-07-20 section E, the CRITICAL one. Everything here is honest
    // except the successor's BODY: same owner-transfer, same role_registry_root,
    // same epoch, same frozen_flag, correctly OPS-attested, paying exactly the
    // output whose P2SH the branch checks. Only the baked role pubkeys differ.
    //
    // Before template authentication this was ACCEPTED, which meant owner plus a
    // stolen HOT ops key could move the coin into a covenant the real issuer
    // holds no keys for -- the same governance exit the MIGRATE cold-quorum gate
    // was added to close, reachable without touching MIGRATE.
    let cfg = Cfg { successor_role_seeds: Some((40, 41, [42, 43, 44], 45)), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_successor_swapping_only_the_ops_key_rejected() {
    // The narrowest form: every role key carried forward honestly except OPS
    // (seed 50 instead of the covenant's own 2).
    // A suffix comparison catches it the same way it catches a full swap --
    // there is no "small enough to slip through" version of this attack.
    let cfg = Cfg { successor_role_seeds: Some((50, TRANSFER_SCENARIO_FREEZE_SEED, UNRELATED_SEIZE_SEEDS, UNRELATED_MINT_SEED)), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_successor_with_identical_role_set_still_accepts() {
    // Guard on the other side: template authentication must not break the
    // honest path it wraps. Spelling the role seeds out explicitly (rather than
    // relying on the None default) proves the comparison is by VALUE.
    let cfg = Cfg {
        successor_role_seeds: Some((2, TRANSFER_SCENARIO_FREEZE_SEED, UNRELATED_SEIZE_SEEDS, UNRELATED_MINT_SEED)),
        ..Cfg::honest()
    };
    let res = run(&build(&cfg));
    assert!(res.is_ok(), "an unchanged role set must still transfer: {res:?}");
}

#[test]
fn transfer_cannot_freeze_the_successor() {
    // Final-round audit fix. TRANSFER gates on THIS coin's frozen_flag being 0
    // but left the successor's byte unconstrained, so owner + OPS -- neither of
    // them the FREEZE role -- could hand the coin forward already frozen.
    let cfg = Cfg { successor_frozen_flag: Some(frozen_flag::SET), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_cannot_write_an_out_of_domain_successor_flag() {
    // The worse half: an out-of-domain byte is neither "clear" to any owner
    // branch's bytewise compare against [0x00] nor the 0x01 tooling reads as
    // frozen, so the coin would be stuck until the FREEZE key or the SEIZE
    // quorum intervened. FREEZE's own domain gate never applied here.
    let cfg = Cfg { successor_frozen_flag: Some(0x02), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_successor_role_root_altered_rejected() {
    // §4's invariant: the successor MUST carry the same role_registry_root.
    // The candidate `new_rs` genuinely hashes to the real output's SPK (the
    // spender fully controls new_rs's plaintext), but its embedded root
    // differs from this coin's own -- the extracted-field comparison must
    // reject it.
    let cfg = Cfg { successor_root: Some([0xFFu8; 32]), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_successor_epoch_altered_rejected() {
    // §4's invariant: the successor MUST carry the same epoch. Same shape as
    // the role-root case, on the epoch field instead.
    let cfg = Cfg { successor_epoch: Some(8), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_attestation_replay_other_outpoint_rejected() {
    // The quorum attested for outpoint txid seed 0x77, but the input
    // actually spends the outpoint with txid seed 0x10 (Cfg::honest()'s
    // default). The on-chain OpOutpointTxId binds the REAL spend, so the
    // recomputed msg_hash differs from what was signed -- the 0x77 attestation
    // is worthless here (replay protection).
    let cfg = Cfg { attest_outpoint_txid_seed: Some(0x77), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn transfer_wrong_op_type_in_message_rejected() {
    // Cross-branch replay protection (attestation.rs §6): an attestation
    // minted for a DIFFERENT op_type (here, FREEZE's 0x01) must not be
    // replayable as a TRANSFER. The sigscript's op_type_selector is still
    // 0x00 (TRANSFER is the only wired branch), so execution reaches the
    // TRANSFER body, which reconstructs the preimage with a HARDCODED
    // op_type literal (0x00) -- this necessarily disagrees with the
    // attacker's 0x01-tagged signed message, so the attestation fails to
    // verify.
    let cfg = Cfg { attest_op_type: op_type::FREEZE, ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 3. FREEZE (`op_type = 0x01`, Phase II branch 1) -- happy path + adversarial
//    batch. No owner signature is involved at all: the FREEZE role's
//    `OpCheckSigFromStack` attestation is the ONLY authorization, and the
//    successor must be byte-identical to the input's redeem script except
//    for the `frozen_flag` byte (`STABLECOIN_ROBUST_DESIGN.md` §4/§5,
//    per-branch detail for `0x01 FREEZE`). Because there is no owner
//    signature to commit output amounts "for free" (unlike TRANSFER), the
//    branch also enforces successor-value continuity via
//    `dr_value_continuity_check` (`contract::dr`) --
//    `freeze_successor_reduces_value_rejected` /
//    `freeze_successor_inflates_value_rejected` below are the regression
//    tests for that fix; `honest_freeze()`'s `out_value == in_amount` is the
//    happy-path proof that an honest 1:1 spend still passes it.
// ============================================================================

/// One FREEZE scenario. `honest_freeze()`/`honest_unfreeze()` yield fully
/// valid spends (0->1 and 1->0 respectively); each adversarial test mutates
/// exactly one lever.
#[derive(Clone)]
struct FreezeCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,
    owner_seed: u8,  // owner pubkey baked into the state header (FREEZE does NOT sign for it)
    ops_seed: u8,    // OPS pubkey baked into the body (irrelevant to the FREEZE branch itself)
    freeze_seed: u8, // FREEZE pubkey baked into the body (this branch's OpCheckSigFromStack key)
    root: [u8; 32],  // this coin's role_registry_root
    epoch: u32,      // this coin's epoch
    frozen_flag: u8, // this coin's CURRENT frozen_flag, before the spend
    in_amount: u64,
    out_value: u64,

    new_frozen_flag: u8, // the attested/pushed target value (both signed over AND
                          // used to build the successor's frozen_flag, in the honest case)

    // Successor (new_rs) overrides. `None` == carried forward truthfully
    // (matching this coin's own owner/root/epoch, or `new_frozen_flag` for
    // frozen_flag -- the honest case).
    successor_owner_seed: Option<u8>,
    successor_root: Option<[u8; 32]>,
    successor_epoch: Option<u32>,
    successor_frozen_flag: Option<u8>,

    // Key that actually produces issuer_sig (honest == freeze_seed). A
    // disagreeing value is the forgery being tested.
    attest_freeze_seed: u8,
}

impl FreezeCfg {
    fn honest_freeze() -> Self {
        FreezeCfg {
            input_cov_id: hash32(0xF0),
            outpoint_txid_seed: 0x20,
            outpoint_index: 0,
            owner_seed: 11,
            ops_seed: 12,
            freeze_seed: 13,
            root: ROOT,
            epoch: 4,
            frozen_flag: frozen_flag::CLEAR,
            in_amount: IN_AMOUNT,
            out_value: IN_AMOUNT,
            new_frozen_flag: frozen_flag::SET, // freeze: 0 -> 1
            successor_owner_seed: None,
            successor_root: None,
            successor_epoch: None,
            successor_frozen_flag: None,
            attest_freeze_seed: 13, // == freeze_seed
        }
    }

    fn honest_unfreeze() -> Self {
        FreezeCfg { frozen_flag: frozen_flag::SET, new_frozen_flag: frozen_flag::CLEAR, ..FreezeCfg::honest_freeze() }
    }
}

/// Build a FREEZE scenario. `raw_issuer_sig`, when `Some`, bypasses
/// [`build_stablecoin_freeze_sigscript`]'s fixed 64-byte `issuer_sig` and
/// hand-assembles the sigscript with the given (possibly non-64-byte,
/// including empty) bytes instead -- this is the only way to exercise a
/// missing/malformed attestation, since the normal builder's `&[u8; 64]`
/// parameter can't express "absent".
fn build_freeze_scenario(cfg: &FreezeCfg, raw_issuer_sig: Option<&[u8]>) -> Built {
    let owner_pub = pubkey(cfg.owner_seed);
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = unrelated_seize_pubkeys();
    let mint_pub = unrelated_mint_pubkey();
    let rs = build_stablecoin_redeem_script(
        &owner_pub,
        id_type::PUBKEY,
        &cfg.root,
        cfg.frozen_flag,
        cfg.epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let input_spk = build_p2sh(&rs);

    // 1:1 successor: the covenant reads the output at the SAME index as the
    // gated input (index 0). Identical to the input EXCEPT frozen_flag,
    // unless a test overrides one of the other fields to probe the
    // successor-continuity checks.
    let successor_owner_pub = cfg.successor_owner_seed.map(pubkey).unwrap_or(owner_pub);
    let successor_root = cfg.successor_root.unwrap_or(cfg.root);
    let successor_epoch = cfg.successor_epoch.unwrap_or(cfg.epoch);
    let successor_frozen_flag = cfg.successor_frozen_flag.unwrap_or(cfg.new_frozen_flag);
    let new_rs = build_stablecoin_redeem_script(
        &successor_owner_pub,
        id_type::PUBKEY,
        &successor_root,
        successor_frozen_flag,
        successor_epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let out_spk = build_p2sh(&new_rs);

    let output = TransactionOutput::with_covenant(cfg.out_value, out_spk.clone(), Some(CovenantBinding::new(0, cfg.input_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.in_amount,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // --- FREEZE role attestation (off-chain "Writer" side) ---
    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let txid_bytes: [u8; 32] = [cfg.outpoint_txid_seed; 32];
    let spk_bytes = spk_to_bytes(&out_spk);
    let attest_msg = build_freeze_attestation_message(
        &cov_bytes,
        cfg.epoch,
        &txid_bytes,
        cfg.outpoint_index,
        &spk_bytes,
        cfg.in_amount,
        cfg.new_frozen_flag,
    );
    let issuer_sig: [u8; 64] = schnorr_sign(&attest_msg, &privkey(cfg.attest_freeze_seed)).unwrap();

    // No owner authorization at all -- FREEZE gates alone (§4).
    let ss = match raw_issuer_sig {
        Some(raw) => {
            let mut ss = Vec::new();
            // self_rs (deepest) -- the template-authentication copy the branch
            // proves against this input's own SPK. Present in every honest
            // sigscript, so a hand-assembled one must supply it too or the
            // branch's picks land on the wrong items.
            ss.extend_from_slice(&push_data(&rs));
            ss.extend_from_slice(&push_data(raw));
            ss.extend_from_slice(&push_data(&new_rs));
            ss.extend_from_slice(&push_data(&[cfg.new_frozen_flag]));
            ss.extend_from_slice(&push_data(&[op_type::FREEZE]));
            ss.extend_from_slice(&push_data(&rs));
            ss
        }
        None => build_stablecoin_freeze_sigscript(&issuer_sig, cfg.new_frozen_flag, &new_rs, &rs),
    };
    // sig_op_count = 1: one OpCheckSigFromStack (FREEZE role); no owner sig.
    let final_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), ss, 0, 1);
    let tx = Transaction::new(0, vec![final_input], vec![output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

fn build_freeze(cfg: &FreezeCfg) -> Built {
    build_freeze_scenario(cfg, None)
}

#[test]
fn freeze_sets_flag_accepts() {
    // FREEZE key alone (no owner sig) attests new_frozen_flag = 1 on a
    // currently-clear coin; the successor carries frozen_flag = 1 and is
    // otherwise byte-identical. Round-trip proof: the FREEZE role signed
    // `build_freeze_attestation_message(...)` off-chain, and the body
    // recomputed the identical 32-byte msg_hash on-chain.
    let res = run(&build_freeze(&FreezeCfg::honest_freeze()));
    assert!(res.is_ok(), "honest FREEZE (0->1) must be accepted: {res:?}");
}

#[test]
fn unfreeze_clears_flag_accepts() {
    // Same mechanism, opposite direction: new_frozen_flag = 0 on a
    // currently-frozen coin must also be accepted -- the FREEZE branch has no
    // gate on the coin's OWN current frozen_flag (unlike TRANSFER's
    // frozen_flag == 0 invariant), since FREEZE must work from either
    // starting state.
    let res = run(&build_freeze(&FreezeCfg::honest_unfreeze()));
    assert!(res.is_ok(), "honest UNFREEZE (1->0) must be accepted: {res:?}");
}

#[test]
fn freeze_wrong_key_rejected() {
    // A valid-shaped signature over the correct message, but from a key that
    // is NOT the FREEZE role baked into the body. Only the real FREEZE role
    // can freeze/unfreeze.
    let cfg = FreezeCfg { attest_freeze_seed: 77, ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn freeze_successor_alters_owner_rejected() {
    // Task spec invariant: the successor MUST carry the same owner_pubkey --
    // FREEZE cannot also redirect ownership. The candidate `new_rs` genuinely
    // hashes to the real output's SPK, but its embedded owner differs from
    // this coin's own -- the extracted-field comparison must reject it.
    let cfg = FreezeCfg { successor_owner_seed: Some(99), ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn freeze_successor_alters_role_root_or_epoch_rejected() {
    // Task spec invariant: the successor MUST carry the same
    // role_registry_root AND the same epoch -- FREEZE is scoped to the
    // frozen_flag byte only. Exercise both levers independently.
    let root_cfg = FreezeCfg { successor_root: Some([0xFFu8; 32]), ..FreezeCfg::honest_freeze() };
    assert_rejected_with(&run(&build_freeze(&root_cfg)), "VerifyError");

    let epoch_cfg = FreezeCfg { successor_epoch: Some(999), ..FreezeCfg::honest_freeze() };
    assert_rejected_with(&run(&build_freeze(&epoch_cfg)), "VerifyError");
}

#[test]
fn freeze_missing_attestation_rejected() {
    // An empty issuer_sig (no attestation at all) cannot parse as a Schnorr
    // signature -- `OpCheckSigFromStack` fails at signature PARSING
    // (`TxScriptError::InvalidSignature`), before it would even get to
    // compare against the FREEZE pubkey. This is a distinct failure mode from
    // the wrong-key case above (which parses fine and fails verification),
    // so it gets its own needle rather than reusing "VerifyError".
    let cfg = FreezeCfg::honest_freeze();
    let res = run(&build_freeze_scenario(&cfg, Some(&[])));
    assert_rejected_with(&res, "InvalidSignature");
}

#[test]
fn freeze_flag_mismatch_message_vs_successor_rejected() {
    // The FREEZE role's signature is genuinely valid over new_frozen_flag =
    // 1 (both signed and pushed), but the successor's ACTUAL frozen_flag byte
    // is 0 -- a captured, honestly-signed freeze-attestation replayed against
    // a successor that doesn't actually carry the attested value. The
    // on-chain successor-frozen_flag-equality check must reject this
    // independently of the signature check succeeding.
    let cfg = FreezeCfg { successor_frozen_flag: Some(frozen_flag::CLEAR), ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn freeze_out_of_domain_flag_rejected() {
    // Audit fix 2026-07-20 (§B4): the FREEZE key must not be able to write an
    // arbitrary byte into the successor's frozen_flag slot. Everything here is
    // otherwise honest -- the attestation genuinely signs new_frozen_flag =
    // 0x02 and the successor genuinely carries 0x02, so both the signature
    // check and the successor-equality check would pass -- yet the branch must
    // still abort on the domain gate. Without it, 0x02 is an undefined third
    // state: TRANSFER/BURN/MIGRATE all compare bytewise against [0x00] and
    // abort, while no tooling recognizes it as frozen.
    let cfg = FreezeCfg { new_frozen_flag: 0x02, ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn freeze_high_bit_flag_rejected() {
    // Same gate, exercised with a byte whose numeric reading (0x80 == script
    // number -0) differs from its bytewise one -- the gate is bytewise, so
    // this must reject regardless of numeric interpretation.
    let cfg = FreezeCfg { new_frozen_flag: 0x80, ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn freeze_successor_reduces_value_rejected() {
    // Security-fix regression test: FREEZE has no owner SIGHASH_ALL signature
    // (unlike TRANSFER, where the owner's signature commits every output's
    // amount "for free"), so nothing else on this path pins the successor
    // covenant output's native value to the input's -- without the
    // `dr_value_continuity_check` fix, a holder of only the FREEZE key could
    // shave sompi off the coin while freezing/unfreezing it. Everything else
    // here (attestation, successor owner/root/epoch/frozen_flag) is fully
    // honest; only `out_value` is under-funded relative to `in_amount`.
    let cfg = FreezeCfg { out_value: IN_AMOUNT - 1, ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn freeze_successor_inflates_value_rejected() {
    // Same invariant, opposite direction: the fix enforces EXACT equality (a
    // 1:1 covenant), so an over-funded successor must be rejected too, not
    // just an under-funded one.
    let cfg = FreezeCfg { out_value: IN_AMOUNT + 1, ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 4. SEIZE (`op_type = 0x02`, Phase II branch 3) -- happy path + adversarial
//    batch. No owner signature is involved at all (the issuer force-moves
//    the coin without the holder, `STABLECOIN_ROBUST_DESIGN.md` §1/§4/§7):
//    authorization is a 2-of-3 threshold over three BAKED SEIZE pubkeys,
//    built from three `OpCheckSigFromStack` calls at FIXED positional slots
//    (see `build_seize_branch`, `core/src/contract/stablecoin/body.rs`, for
//    why this reuses the codebase's established OpCheckSigFromStack idiom
//    rather than native `OpCheckMultiSig`, which this engine hard-wires to
//    the tx's own sighash and has no stack-message form). The successor must
//    carry the ATTESTED `new_owner_pubkey` in place of `owner_pubkey`, with
//    `role_registry_root`/`epoch`/`identifier_type` unchanged, and (this
//    implementation's judgment call, flagged for human review in
//    `build_seize_branch`'s doc) `frozen_flag` PRESERVED unchanged. Because
//    there is no owner signature (and no tx-sighash-bound multisig either),
//    the branch also enforces successor-value continuity via
//    `dr_value_continuity_check` (`contract::dr`) --
//    `seize_value_reduced_rejected` below is the regression test for that;
//    `honest()`'s `out_value == in_amount` is the happy-path proof that an
//    honest 1:1 spend still passes it.
// ============================================================================

/// A 64-byte value that is NOT a signature from any of the three baked SEIZE
/// keys -- stands in for "no signature supplied" in a fixed positional slot.
/// `OpCheckSigFromStack` parses this fine as a structurally-valid Schnorr
/// signature (any 64 bytes parse) and simply evaluates to `false` against a
/// non-matching pubkey (see `build_seize_branch`'s doc).
const SEIZE_GARBAGE_SIG: [u8; 64] = [0u8; 64];

/// One SEIZE scenario. `honest()` yields a fully valid 2-of-3-signed forced
/// move; each adversarial test mutates exactly one lever.
#[derive(Clone)]
struct SeizeCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,
    owner_seed: u8,     // this coin's CURRENT owner (irrelevant to the SEIZE branch itself)
    ops_seed: u8,       // OPS pubkey baked into the body (irrelevant to the SEIZE branch itself)
    freeze_seed: u8,    // FREEZE pubkey baked into the body (irrelevant to the SEIZE branch itself)
    seize_seeds: [u8; 3], // the three baked SEIZE pubkey seeds (2-of-3 quorum)
    root: [u8; 32],     // this coin's role_registry_root
    epoch: u32,         // this coin's epoch
    frozen_flag: u8,    // this coin's CURRENT frozen_flag, before the spend
    in_amount: u64,
    out_value: u64,

    new_owner_seed: u8, // the attested target owner (both signed over AND, in
                        // the honest case, the successor's actual owner_pubkey)

    // Successor (new_rs) overrides. `None` == carried forward truthfully
    // (matching the attested new_owner_seed, or this coin's own
    // root/epoch/frozen_flag -- the honest case).
    successor_owner_seed: Option<u8>,
    successor_root: Option<[u8; 32]>,
    successor_epoch: Option<u32>,
    successor_frozen_flag: Option<u8>,

    // Override for what is actually SIGNED (None == truthful, matching the
    // real spend). A disagreeing value is the replay being tested.
    attest_outpoint_txid_seed: Option<u8>,

    // Which seed actually signs each of the 3 fixed sigscript slots
    // (`Some(seed)`) vs. an arbitrary non-signature placeholder (`None`).
    // Honest == all three slots signed by `seize_seeds` in order.
    signer_seeds: [Option<u8>; 3],
}

impl SeizeCfg {
    fn honest() -> Self {
        SeizeCfg {
            input_cov_id: hash32(0xE0),
            outpoint_txid_seed: 0x30,
            outpoint_index: 0,
            owner_seed: 21,
            ops_seed: 22,
            freeze_seed: 23,
            seize_seeds: [31, 32, 33],
            root: ROOT,
            epoch: 5,
            frozen_flag: frozen_flag::CLEAR,
            in_amount: IN_AMOUNT,
            out_value: IN_AMOUNT,
            new_owner_seed: 40,
            successor_owner_seed: None,
            successor_root: None,
            successor_epoch: None,
            successor_frozen_flag: None,
            attest_outpoint_txid_seed: None,
            signer_seeds: [Some(31), Some(32), Some(33)],
        }
    }
}

/// Build a SEIZE scenario.
fn build_seize(cfg: &SeizeCfg) -> Built {
    let owner_pub = pubkey(cfg.owner_seed);
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = [pubkey(cfg.seize_seeds[0]), pubkey(cfg.seize_seeds[1]), pubkey(cfg.seize_seeds[2])];
    let mint_pub = unrelated_mint_pubkey();
    let rs = build_stablecoin_redeem_script(
        &owner_pub,
        id_type::PUBKEY,
        &cfg.root,
        cfg.frozen_flag,
        cfg.epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let input_spk = build_p2sh(&rs);

    // 1:1 successor: the covenant reads the output at the SAME index as the
    // gated input (index 0). Owner REPLACED by the attested new_owner_seed;
    // root/epoch/frozen_flag carried forward truthfully unless a test
    // overrides one to probe the successor-continuity checks.
    let new_owner_pub = pubkey(cfg.new_owner_seed);
    let successor_owner_pub = cfg.successor_owner_seed.map(pubkey).unwrap_or(new_owner_pub);
    let successor_root = cfg.successor_root.unwrap_or(cfg.root);
    let successor_epoch = cfg.successor_epoch.unwrap_or(cfg.epoch);
    let successor_frozen_flag = cfg.successor_frozen_flag.unwrap_or(cfg.frozen_flag); // preserve (see body.rs doc)
    let new_rs = build_stablecoin_redeem_script(
        &successor_owner_pub,
        id_type::PUBKEY,
        &successor_root,
        successor_frozen_flag,
        successor_epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let out_spk = build_p2sh(&new_rs);

    let output = TransactionOutput::with_covenant(cfg.out_value, out_spk.clone(), Some(CovenantBinding::new(0, cfg.input_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.in_amount,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // --- SEIZE quorum attestation (off-chain "Writer" side) ---
    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let msg_txid_seed = cfg.attest_outpoint_txid_seed.unwrap_or(cfg.outpoint_txid_seed);
    let msg_txid_bytes: [u8; 32] = [msg_txid_seed; 32];
    let spk_bytes = spk_to_bytes(&out_spk);
    let attest_msg =
        build_seize_attestation_message(&cov_bytes, cfg.epoch, &msg_txid_bytes, cfg.outpoint_index, &spk_bytes, cfg.in_amount, &new_owner_pub);

    let sig_for = |slot: usize| -> [u8; 64] {
        match cfg.signer_seeds[slot] {
            Some(seed) => schnorr_sign(&attest_msg, &privkey(seed)).unwrap(),
            None => SEIZE_GARBAGE_SIG,
        }
    };
    let sig1 = sig_for(0);
    let sig2 = sig_for(1);
    let sig3 = sig_for(2);

    // No owner authorization at all -- the SEIZE 2-of-3 quorum gates alone (§4/§7).
    let ss = build_stablecoin_seize_sigscript(&sig1, &sig2, &sig3, &new_owner_pub, &new_rs, &rs);
    // sig_op_count = 3: three OpCheckSigFromStack calls (2-of-3 SEIZE quorum).
    let final_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), ss, 0, 3);
    let tx = Transaction::new(0, vec![final_input], vec![output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

#[test]
fn seize_2of3_accepts() {
    // A correctly 2-of-3-signed SEIZE, with the successor carrying the
    // attested new_owner_pubkey and everything else (root/epoch/frozen_flag)
    // unchanged, and value preserved.
    //
    // That this passes on the real engine IS the conformance proof: two of
    // the three SEIZE-role signers signed `build_seize_attestation_message(...)`
    // off-chain, and the body recomputed the identical 32-byte msg_hash from
    // transaction introspection -- if any field or width disagreed,
    // `OpCheckSigFromStack` would return false for each check and the summed
    // threshold would fall below 2.
    let res = run(&build_seize(&SeizeCfg::honest()));
    assert!(res.is_ok(), "honest 2-of-3 SEIZE must be accepted: {res:?}");
}

#[test]
fn seize_1of3_insufficient_rejected() {
    // Only ONE of the three signature slots is genuinely signed by a baked
    // SEIZE key; the other two are arbitrary placeholders. The summed
    // threshold (1) is below the required 2-of-3, so the branch must reject
    // even though the single supplied signature is perfectly valid.
    let cfg = SeizeCfg { signer_seeds: [Some(31), None, None], ..SeizeCfg::honest() };
    let res = run(&build_seize(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn seize_wrong_keys_rejected() {
    // All three signature slots are genuine, correctly-formed signatures
    // over the correct attested message, but from keys that are NOT among
    // the three baked SEIZE pubkeys. Only the real SEIZE quorum can seize.
    let cfg = SeizeCfg { signer_seeds: [Some(91), Some(92), Some(93)], ..SeizeCfg::honest() };
    let res = run(&build_seize(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn seize_successor_owner_mismatch_rejected() {
    // The SEIZE quorum genuinely attested new_owner_seed = 40, but the
    // successor's ACTUAL owner_pubkey belongs to a different key (99) -- a
    // captured, honestly-signed seize-attestation replayed against a
    // successor that doesn't actually carry the attested recipient. The
    // on-chain successor-owner-equality check must reject this independently
    // of the 2-of-3 signature check succeeding.
    let cfg = SeizeCfg { successor_owner_seed: Some(99), ..SeizeCfg::honest() };
    let res = run(&build_seize(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn seize_value_reduced_rejected() {
    // Security-fix regression test (§4 cross-branch invariant, mirrors
    // FREEZE's `freeze_successor_reduces_value_rejected`): SEIZE has no owner
    // SIGHASH_ALL signature (and its 2-of-3 quorum is built from
    // OpCheckSigFromStack, not a tx-sighash-bound signature either), so
    // nothing else on this path pins the successor covenant output's native
    // value to the input's -- without `dr_value_continuity_check`, the SEIZE
    // quorum could shave sompi off the coin while force-moving it. Everything
    // else here (attestation, successor owner/root/epoch/frozen_flag) is
    // fully honest; only `out_value` is under-funded relative to `in_amount`.
    let cfg = SeizeCfg { out_value: IN_AMOUNT - 1, ..SeizeCfg::honest() };
    let res = run(&build_seize(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn seize_role_root_or_epoch_altered_rejected() {
    // Task spec invariant: the successor MUST carry the same
    // role_registry_root AND the same epoch -- SEIZE is scoped to replacing
    // owner_pubkey only. Exercise both levers independently.
    let root_cfg = SeizeCfg { successor_root: Some([0xFFu8; 32]), ..SeizeCfg::honest() };
    assert_rejected_with(&run(&build_seize(&root_cfg)), "VerifyError");

    let epoch_cfg = SeizeCfg { successor_epoch: Some(999), ..SeizeCfg::honest() };
    assert_rejected_with(&run(&build_seize(&epoch_cfg)), "VerifyError");
}

#[test]
fn seize_replay_other_outpoint_rejected() {
    // The SEIZE quorum attested for outpoint txid seed 0x77, but the input
    // actually spends the outpoint with txid seed 0x30 (SeizeCfg::honest()'s
    // default). The on-chain OpOutpointTxId binds the REAL spend, so the
    // recomputed msg_hash differs from what was signed -- the 0x77
    // attestation's signatures fail to verify against it (replay protection).
    let cfg = SeizeCfg { attest_outpoint_txid_seed: Some(0x77), ..SeizeCfg::honest() };
    let res = run(&build_seize(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 5. BURN (`op_type = 0x03`, Phase II branch 4) -- happy path + adversarial
//    batch. Two-of-two authorization, the SAME shape as TRANSFER (owner
//    `OpCheckSigVerify`, SIGHASH_ALL, PLUS an `OpCheckSigFromStack`
//    attestation), but the attesting role is MINT (the mint-authority's
//    supply key, §2/§9/§4) rather than OPS, and there is NO `new_rs` field at
//    all: the successor is a FIXED canonical unspendable sink -- the P2SH
//    wrapping of `BURN_SINK_SCRIPT` (`burn_sink_spk`/`burn_sink_spk_bytes`,
//    `core/src/contract/stablecoin/body.rs`), not a spender-supplied
//    candidate covenant. Because the owner
//    signs SIGHASH_ALL, value handling is owner-committed -- BURN
//    deliberately does NOT call `dr_value_continuity_check` (§4: "canonical-
//    sink successor, not a value-carrying one"); see
//    `build_burn_branch`'s doc (`body.rs`) for the full rationale.
// ============================================================================

/// One BURN scenario. `honest()` yields a fully valid owner+MINT burn to the
/// canonical sink; each adversarial test mutates exactly one lever.
#[derive(Clone)]
struct BurnCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,
    owner_seed: u8,        // owner pubkey baked into the state header AND the key that signs owner_sig
    ops_seed: u8,          // OPS pubkey baked into the body (irrelevant to BURN itself)
    freeze_seed: u8,       // FREEZE pubkey baked into the body (irrelevant to BURN itself)
    seize_seeds: [u8; 3],  // SEIZE pubkeys baked into the body (irrelevant to BURN itself)
    mint_seed: u8,         // MINT pubkey baked into the body (this branch's OpCheckSigFromStack key)
    root: [u8; 32],        // this coin's role_registry_root (unread/uncompared by BURN, but still part of the state header)
    epoch: u32,            // this coin's epoch (bound into the MINT attestation preimage)
    frozen_flag: u8,       // this coin's CURRENT frozen_flag (BURN is not frozen-gated, see body.rs doc)
    in_amount: u64,

    // Key that actually produces issuer_sig (honest == mint_seed). A
    // disagreeing value is the wrong-MINT-key forgery being tested.
    attest_mint_seed: u8,
    // Override for what the MINT attestation actually signs as the outpoint
    // txid (None == truthful, matching the real spend). A disagreeing value
    // is the replay being tested.
    attest_outpoint_txid_seed: Option<u8>,

    // Successor lever: honest (false) == the canonical unspendable burn sink;
    // true == point the successor at a trivially-spendable P2SH instead (an
    // OP_TRUE redeem script), to prove the sink-pin check rejects a redirect.
    successor_not_sink: bool,
}

impl BurnCfg {
    fn honest() -> Self {
        BurnCfg {
            input_cov_id: hash32(0xB0),
            outpoint_txid_seed: 0x40,
            outpoint_index: 0,
            owner_seed: 51,
            ops_seed: 52,
            freeze_seed: 53,
            seize_seeds: [61, 62, 63],
            mint_seed: 54,
            root: ROOT,
            epoch: 6,
            frozen_flag: frozen_flag::CLEAR,
            in_amount: IN_AMOUNT,
            attest_mint_seed: 54, // == mint_seed
            attest_outpoint_txid_seed: None,
            successor_not_sink: false,
        }
    }
}

/// Build a BURN scenario. `raw_owner_sig`/`raw_issuer_sig`, when `Some`,
/// bypass [`build_stablecoin_burn_sigscript`]'s fixed 64-byte signature
/// parameters and hand-assemble the sigscript with the given (possibly
/// non-64-byte, including empty) bytes instead -- this is the only way to
/// exercise a missing/malformed signature, since the normal builder's
/// `&[u8; 64]` parameters can't express "absent" (mirrors FREEZE's
/// `build_freeze_scenario` escape hatch, extended to BURN's two independent
/// signature slots).
///
/// LIVE-FAITHFUL SHAPE (2026-07-20 bisection): this mirrors
/// `cli/src/bin/kob_stablecoin_e2e.rs`'s `op_burn` EXACTLY -- 2 inputs (the
/// covenant coin + a plain P2PK fee input), 2 outputs (the P2SH sink +
/// P2PK change), transaction version 1, and the owner's SIGHASH_ALL
/// signature computed over the FULL (both-input, both-output) transaction --
/// NOT the single-input/single-output shape this scenario used before. A
/// single-input/single-output/version-0 reproduction (the shape this
/// function had until this bisection) still ACCEPTS the honest case, so it
/// was not sufficient by itself to prove/disprove the live-only "verification
/// failed" report; this shape closes every "test doesn't match the wire tx"
/// gap named in the bisection task (output serialization, the MINT
/// attestation's `successor_spk_hash`, the fee-input shape, and the output
/// set the owner's SIGHASH_ALL commits to). It still ACCEPTS -- see the FINAL
/// REPORT for what that does (and doesn't) establish.
fn build_burn_scenario(cfg: &BurnCfg, raw_owner_sig: Option<&[u8]>, raw_issuer_sig: Option<&[u8]>) -> Built {
    let owner_pub = pubkey(cfg.owner_seed);
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = [pubkey(cfg.seize_seeds[0]), pubkey(cfg.seize_seeds[1]), pubkey(cfg.seize_seeds[2])];
    let mint_pub = pubkey(cfg.mint_seed);
    let rs = build_stablecoin_redeem_script(
        &owner_pub,
        id_type::PUBKEY,
        &cfg.root,
        cfg.frozen_flag,
        cfg.epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let input_spk = build_p2sh(&rs);

    // Successor: honest == the canonical unspendable burn sink (§8); the
    // adversarial lever points it at a trivially-spendable P2SH instead (an
    // OP_TRUE (`0x51`) redeem script -- anyone could reveal it and spend it)
    // to prove the on-chain sink-pin check rejects a redirect to spendable
    // value. Either way, this is NOT a covenant continuation (the coin's
    // covenant life ends here) -- no `CovenantBinding`, unlike
    // TRANSFER/FREEZE/SEIZE's same-covenant-id successors.
    let out_spk = if cfg.successor_not_sink { build_p2sh(&[0x51]) } else { burn_sink_spk() };
    let sink_output = TransactionOutput::new(cfg.in_amount, out_spk.clone());

    // Plain P2PK fee input/change output -- the SAME shape `op_burn` pairs
    // with every covenant spend (a separate wallet UTXO funds the fee/tx
    // mass so the burn amount always destroys the coin's FULL native value).
    const FEE_SEED: u8 = 111;
    let fee_pub = pubkey(FEE_SEED);
    let mut fee_script = Vec::with_capacity(34);
    fee_script.push(0x20);
    fee_script.extend_from_slice(&fee_pub);
    fee_script.push(0xac);
    let fee_spk = ScriptPublicKey::new(0, fee_script.into());
    const FEE_IN_AMOUNT: u64 = 300_000;
    const FEE_CHANGE: u64 = 250_000;
    let fee_outpoint = outpoint(0x99, 0);
    let change_output = TransactionOutput::new(FEE_CHANGE, fee_spk.clone());

    let entries = vec![
        UtxoEntry {
            amount: cfg.in_amount,
            script_public_key: input_spk,
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(cfg.input_cov_id),
        },
        UtxoEntry { amount: FEE_IN_AMOUNT, script_public_key: fee_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];

    // --- MINT role attestation (off-chain "Writer" side) ---
    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let msg_txid_seed = cfg.attest_outpoint_txid_seed.unwrap_or(cfg.outpoint_txid_seed);
    let msg_txid_bytes: [u8; 32] = [msg_txid_seed; 32];
    let spk_bytes = spk_to_bytes(&out_spk);
    let attest_msg = build_attestation_message(
        &cov_bytes,
        op_type::BURN,
        cfg.epoch,
        &msg_txid_bytes,
        cfg.outpoint_index,
        &spk_bytes,
        cfg.in_amount,
    );
    let issuer_sig: [u8; 64] = schnorr_sign(&attest_msg, &privkey(cfg.attest_mint_seed)).unwrap();

    // --- Owner authorization: SIGHASH_ALL over the FULL 2-input/2-output,
    // version-1 tx (matches `op_burn`'s `Transaction::new(1)` + fee input --
    // NOT just this coin's own input/output in isolation). ---
    let covenant_outpoint = outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index);
    let skeleton_inputs = vec![
        TransactionInput::new(covenant_outpoint, vec![], 0, 2),
        TransactionInput::new(fee_outpoint, vec![], 0, 1),
    ];
    let skeleton_tx = Transaction::new(
        1,
        skeleton_inputs,
        vec![sink_output.clone(), change_output.clone()],
        0,
        Default::default(),
        0,
        vec![],
    );
    let populated_skeleton = PopulatedTransaction::new(&skeleton_tx, entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&populated_skeleton, 0, SIG_HASH_ALL, &reused);
    let owner_sig: [u8; 64] = schnorr_sign(&sighash.as_bytes(), &privkey(cfg.owner_seed)).unwrap();

    let ss0 = match (raw_owner_sig, raw_issuer_sig) {
        (None, None) => build_stablecoin_burn_sigscript(&owner_sig, &issuer_sig, &rs),
        (owner_override, issuer_override) => {
            let owner_sig_with_type: Vec<u8> = match owner_override {
                Some(raw) => raw.to_vec(),
                None => {
                    let mut v = owner_sig.to_vec();
                    v.push(0x01); // SIGHASH_ALL
                    v
                }
            };
            let issuer_bytes: Vec<u8> = issuer_override.map(<[u8]>::to_vec).unwrap_or_else(|| issuer_sig.to_vec());
            let mut ss = Vec::new();
            // Emitted first -> ends up deepest: the MINT attestation sig.
            ss.extend_from_slice(&push_data(&issuer_bytes));
            ss.extend_from_slice(&push_data(&owner_sig_with_type));
            ss.extend_from_slice(&push_data(&[op_type::BURN]));
            ss.extend_from_slice(&push_data(&rs));
            ss
        }
    };
    // sig_op_count = 2: one OpCheckSigVerify (owner) + one OpCheckSigFromStack (MINT).
    // The fee input's own sigscript is irrelevant to `run()` (it only
    // verifies input 0), so it's left empty here (never executed).
    let final_inputs = vec![TransactionInput::new(covenant_outpoint, ss0, 0, 2), TransactionInput::new(fee_outpoint, vec![], 0, 1)];
    let tx = Transaction::new(1, final_inputs, vec![sink_output, change_output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

fn build_burn(cfg: &BurnCfg) -> Built {
    build_burn_scenario(cfg, None, None)
}

#[test]
fn burn_owner_plus_mint_accepts() {
    // A correctly owner-signed, correctly MINT-attested BURN to the canonical
    // sink. That this passes on the real engine IS the conformance proof: the
    // MINT role signed `build_attestation_message(..., op_type::BURN, ...)`
    // off-chain, and the body recomputed the identical 32-byte msg_hash from
    // transaction introspection -- if any field or width disagreed,
    // `OpCheckSigFromStack` would return false and `OpVerify` would abort.
    let res = run(&build_burn(&BurnCfg::honest()));
    assert!(res.is_ok(), "honest owner+MINT BURN to the canonical sink must be accepted: {res:?}");
}

#[test]
fn burn_missing_owner_sig_rejected() {
    // Empty owner_sig (0 bytes): `OpCheckSig`'s hash-type-byte pop sees
    // nothing and evaluates to `false` with no parse error at all (it never
    // even attempts to parse the empty buffer as a Schnorr signature), so
    // `OpCheckSigVerify` aborts with `VerifyError` -- a different failure
    // shape from the missing-MINT-attestation case below, which fails at
    // Schnorr signature PARSING (`OpCheckSigFromStack` requires exactly 64
    // raw bytes with no hash-type convention to fall back on).
    let cfg = BurnCfg::honest();
    let res = run(&build_burn_scenario(&cfg, Some(&[]), None));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn burn_missing_mint_attestation_rejected() {
    // Empty issuer_sig (0 bytes): `OpCheckSigFromStack` tries to parse it as
    // a 64-byte Schnorr signature and fails at parsing, before any key
    // comparison is even attempted.
    let cfg = BurnCfg::honest();
    let res = run(&build_burn_scenario(&cfg, None, Some(&[])));
    assert_rejected_with(&res, "InvalidSignature");
}

#[test]
fn burn_wrong_mint_key_rejected() {
    // The attestation is a valid signature over the correct message, but from
    // the WRONG key (not the MINT key baked into the body). Only the real
    // MINT role can authorize a burn.
    let cfg = BurnCfg { attest_mint_seed: 99, ..BurnCfg::honest() };
    let res = run(&build_burn(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn burn_successor_not_canonical_sink_rejected() {
    // The successor SPK is a trivially-spendable P2SH instead of the
    // canonical unspendable sink. The MINT role attested over the ACTUAL
    // (dishonest) successor SPK -- so the attestation itself is internally
    // consistent and would verify fine -- but the separate, structural
    // sink-pin check (`OpTxOutputSpk == burn_sink_spk_bytes()`) must still
    // reject it: attestation validity alone must never be enough to redirect
    // a burn to spendable value.
    let cfg = BurnCfg { successor_not_sink: true, ..BurnCfg::honest() };
    let res = run(&build_burn(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn burn_replay_other_outpoint_rejected() {
    // The MINT role attested for outpoint txid seed 0x77, but the input
    // actually spends the outpoint with txid seed 0x40 (BurnCfg::honest()'s
    // default). The on-chain OpOutpointTxId binds the REAL spend, so the
    // recomputed msg_hash differs from what was signed -- the 0x77
    // attestation is worthless here (replay protection).
    let cfg = BurnCfg { attest_outpoint_txid_seed: Some(0x77), ..BurnCfg::honest() };
    let res = run(&build_burn(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn burn_of_frozen_coin_rejected() {
    // Audit fix (MEDIUM): "freeze == total owner immobility" -- a frozen coin
    // must not be burnable by its owner, even with an otherwise fully honest
    // owner + MINT co-signature. Only the issuer's SEIZE branch (no owner
    // signature, no frozen gate) may act on a frozen coin.
    let cfg = BurnCfg { frozen_flag: frozen_flag::SET, ..BurnCfg::honest() };
    let res = run(&build_burn(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn burn_of_unfrozen_coin_accepts() {
    // Regression guard: the new frozen_flag gate must not disturb the
    // existing happy path -- an unfrozen coin's owner + MINT co-signed BURN
    // still accepts (same scenario as `burn_owner_plus_mint_accepts`, named
    // to pair explicitly with `burn_of_frozen_coin_rejected` above).
    let cfg = BurnCfg { frozen_flag: frozen_flag::CLEAR, ..BurnCfg::honest() };
    let res = run(&build_burn(&cfg));
    assert!(res.is_ok(), "honest owner+MINT BURN of an UNFROZEN coin must be accepted: {res:?}");
}

// ============================================================================
// 6. MIGRATE (`op_type = 0x06`, Phase II final branch) -- happy path +
//    adversarial batch. Two-of-two authorization, the SAME shape as
//    TRANSFER/BURN (owner `OpCheckSigVerify`, SIGHASH_ALL, PLUS an
//    `OpCheckSigFromStack` attestation) -- but the attesting role here is OPS
//    (§4's MIGRATE authorization is "OWNER + (ROTATE or OPS)"; since ROTATE
//    (`0x05`) is deferred to post-Live -- see `build_migrate_branch`'s doc,
//    `core/src/contract/stablecoin/body.rs` -- OPS stands in as the
//    authorizer for the initial Live; post-Live, once ROTATE/
//    root-verification land, MIGRATE authorization may move to the ROTATE
//    role instead). The successor is a WHOLLY DIFFERENT covenant template
//    (not a same-template state mutation like TRANSFER/FREEZE/SEIZE/BURN):
//    the body doesn't read/compare any fields inside it, it only checks that
//    the successor output's SPK Blake3-hashes to the OPS-attested
//    `new_template_hash` -- there is no `new_rs` sigscript field at all
//    (unlike TRANSFER/FREEZE/SEIZE). Because the owner signs SIGHASH_ALL,
//    value handling is owner-committed -- MIGRATE deliberately does NOT call
//    `dr_value_continuity_check` (mirrors BURN's rationale); see
//    `build_migrate_branch`'s doc (`body.rs`).
// ============================================================================

/// One MIGRATE scenario. `honest()` yields a fully valid owner+OPS migration
/// to a distinct, non-stablecoin successor template (a plain OP_TRUE P2SH --
/// proving MIGRATE doesn't validate the target's shape at all, per task
/// spec); each adversarial test mutates exactly one lever.
#[derive(Clone)]
struct MigrateCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,
    owner_seed: u8,        // owner pubkey baked into the state header AND the key that signs owner_sig
    ops_seed: u8,          // OPS pubkey baked into the body (irrelevant to MIGRATE since Decision 2026-07-20)
    freeze_seed: u8,       // FREEZE pubkey baked into the body (irrelevant to MIGRATE itself)
    seize_seeds: [u8; 3],  // the three baked SEIZE pubkey seeds -- MIGRATE's cold 2-of-3 quorum
    mint_seed: u8,         // MINT pubkey baked into the body (irrelevant to MIGRATE itself)
    root: [u8; 32],        // this coin's role_registry_root (unread/uncompared by MIGRATE)
    epoch: u32,            // this coin's epoch (bound into the OPS attestation preimage)
    frozen_flag: u8,       // this coin's CURRENT frozen_flag (MIGRATE is not frozen-gated, see body.rs doc)
    in_amount: u64,
    out_value: u64,        // successor (new-template) output native value -- owner-chosen, SIGHASH_ALL-committed

    // Which seed actually signs each of the 3 fixed quorum sigscript slots
    // (`Some(seed)`) vs. an arbitrary non-signature placeholder (`None`).
    // Honest == all three slots signed by `seize_seeds` in order. Mirrors
    // `SeizeCfg::signer_seeds` exactly (same shared quorum bytecode).
    signer_seeds: [Option<u8>; 3],
    // Override for what the OPS attestation actually signs as the outpoint
    // txid (None == truthful, matching the real spend). A disagreeing value
    // is the replay being tested.
    attest_outpoint_txid_seed: Option<u8>,

    // Successor-template lever: honest (false) == the OPS-attested
    // new_template_hash genuinely matches the REAL successor output's SPK
    // hash; true == the attestation is for a DIFFERENT template than the one
    // actually paid to (a captured, honestly-signed migrate-attestation
    // replayed against a substituted successor).
    successor_template_mismatch: bool,
}

impl MigrateCfg {
    fn honest() -> Self {
        MigrateCfg {
            input_cov_id: hash32(0xD0),
            outpoint_txid_seed: 0x50,
            outpoint_index: 0,
            owner_seed: 71,
            ops_seed: 72,
            freeze_seed: 73,
            seize_seeds: [81, 82, 83],
            mint_seed: 84,
            root: ROOT,
            epoch: 8,
            frozen_flag: frozen_flag::CLEAR,
            in_amount: IN_AMOUNT,
            out_value: IN_AMOUNT,
            signer_seeds: [Some(81), Some(82), Some(83)], // == seize_seeds
            attest_outpoint_txid_seed: None,
            successor_template_mismatch: false,
        }
    }
}

/// Build a MIGRATE scenario. `raw_owner_sig`/`raw_issuer_sig`, when `Some`,
/// bypass [`build_stablecoin_migrate_sigscript`]'s fixed 64-byte signature
/// parameters and hand-assemble the sigscript with the given (possibly
/// non-64-byte, including empty) bytes instead -- mirrors BURN's
/// `build_burn_scenario` escape hatch.
fn build_migrate_scenario(cfg: &MigrateCfg, raw_owner_sig: Option<&[u8]>, raw_issuer_sig: Option<&[u8]>) -> Built {
    let owner_pub = pubkey(cfg.owner_seed);
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = [pubkey(cfg.seize_seeds[0]), pubkey(cfg.seize_seeds[1]), pubkey(cfg.seize_seeds[2])];
    let mint_pub = pubkey(cfg.mint_seed);
    let rs = build_stablecoin_redeem_script(
        &owner_pub,
        id_type::PUBKEY,
        &cfg.root,
        cfg.frozen_flag,
        cfg.epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let input_spk = build_p2sh(&rs);

    // The REAL successor: a trivially-spendable OP_TRUE P2SH -- a wholly
    // different, non-stablecoin template, proving MIGRATE doesn't validate
    // the target's shape at all (task spec). No `CovenantBinding` -- this
    // coin's covenant life under THIS template ends here, mirroring BURN's
    // plain-output successor.
    let actual_new_rs: &[u8] = &[0x51]; // OP_TRUE
    let actual_out_spk = build_p2sh(actual_new_rs);
    let output = TransactionOutput::new(cfg.out_value, actual_out_spk.clone());

    let entries = vec![UtxoEntry {
        amount: cfg.in_amount,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // The ATTESTED new_template_hash: honest == Blake3(the REAL successor's
    // SPK bytes); mismatch lever == Blake3 of a DIFFERENT template's SPK
    // bytes (the OPS role attested a target the spend doesn't actually pay
    // to -- everything else about the attestation is genuinely valid).
    let attested_spk_bytes = if cfg.successor_template_mismatch {
        let other_rs: &[u8] = &[0x51, 0x51]; // a distinct redeem script -> distinct P2SH
        spk_to_bytes(&build_p2sh(other_rs))
    } else {
        spk_to_bytes(&actual_out_spk)
    };
    let new_template_hash: [u8; 32] = *blake3::hash(&attested_spk_bytes).as_bytes();

    // --- OPS role attestation (off-chain "Writer" side) ---
    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let msg_txid_seed = cfg.attest_outpoint_txid_seed.unwrap_or(cfg.outpoint_txid_seed);
    let msg_txid_bytes: [u8; 32] = [msg_txid_seed; 32];
    let real_spk_bytes = spk_to_bytes(&actual_out_spk);
    let attest_msg = build_migrate_attestation_message(
        &cov_bytes,
        cfg.epoch,
        &msg_txid_bytes,
        cfg.outpoint_index,
        &real_spk_bytes,
        cfg.in_amount,
        &new_template_hash,
    );
    let sig_for = |slot: usize| -> [u8; 64] {
        match cfg.signer_seeds[slot] {
            Some(seed) => schnorr_sign(&attest_msg, &privkey(seed)).unwrap(),
            None => SEIZE_GARBAGE_SIG,
        }
    };
    let quorum_sigs = [sig_for(0), sig_for(1), sig_for(2)];

    // --- Owner authorization (SIGHASH_ALL over the tx) ---
    // `sig_op_count` is committed by Kaspa's sighash, so the skeleton must
    // declare the SAME count as the final input (4 since Decision 2026-07-20:
    // one OpCheckSigVerify + three quorum OpCheckSigFromStack).
    let skeleton_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), vec![], 0, 4);
    let skeleton_tx = Transaction::new(0, vec![skeleton_input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let populated_skeleton = PopulatedTransaction::new(&skeleton_tx, entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&populated_skeleton, 0, SIG_HASH_ALL, &reused);
    let owner_sig: [u8; 64] = schnorr_sign(&sighash.as_bytes(), &privkey(cfg.owner_seed)).unwrap();

    let ss = match (raw_owner_sig, raw_issuer_sig) {
        (None, None) => build_stablecoin_migrate_sigscript(
            &owner_sig,
            &quorum_sigs[0],
            &quorum_sigs[1],
            &quorum_sigs[2],
            &new_template_hash,
            &rs,
        ),
        (owner_override, issuer_override) => {
            let owner_sig_with_type: Vec<u8> = match owner_override {
                Some(raw) => raw.to_vec(),
                None => {
                    let mut v = owner_sig.to_vec();
                    v.push(0x01); // SIGHASH_ALL
                    v
                }
            };
            // `issuer_override` replaces the FIRST quorum slot's bytes (the
            // only slot a "missing/malformed attestation" test needs to
            // perturb); the other two slots keep their honest signatures.
            let sig1_bytes: Vec<u8> = issuer_override.map(<[u8]>::to_vec).unwrap_or_else(|| quorum_sigs[0].to_vec());
            let mut ss = Vec::new();
            // Emitted first -> ends up deepest: the three quorum sigs.
            ss.extend_from_slice(&push_data(&sig1_bytes));
            ss.extend_from_slice(&push_data(&quorum_sigs[1]));
            ss.extend_from_slice(&push_data(&quorum_sigs[2]));
            ss.extend_from_slice(&push_data(&new_template_hash));
            ss.extend_from_slice(&push_data(&owner_sig_with_type));
            ss.extend_from_slice(&push_data(&[op_type::MIGRATE]));
            ss.extend_from_slice(&push_data(&rs));
            ss
        }
    };
    // sig_op_count = 4: one OpCheckSigVerify (owner) + three OpCheckSigFromStack
    // (the cold 2-of-3 quorum).
    let final_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), ss, 0, 4);
    let tx = Transaction::new(0, vec![final_input], vec![output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

fn build_migrate(cfg: &MigrateCfg) -> Built {
    build_migrate_scenario(cfg, None, None)
}

#[test]
fn migrate_owner_plus_2of3_quorum_accepts() {
    // A correctly owner-signed, correctly quorum-attested MIGRATE to a
    // distinct (non-stablecoin) successor template. That this passes on the
    // real engine IS the conformance proof: the SEIZE-quorum members signed
    // `build_migrate_attestation_message(...)` off-chain, and the body
    // recomputed the identical 32-byte msg_hash from transaction
    // introspection -- if any field or width disagreed, `OpCheckSigFromStack`
    // would return false for every slot and the summed threshold would fall
    // below 2.
    let res = run(&build_migrate(&MigrateCfg::honest()));
    assert!(res.is_ok(), "honest owner+2-of-3 MIGRATE to a distinct template must be accepted: {res:?}");
}

#[test]
fn migrate_exactly_2of3_accepts() {
    // Decision 2026-07-20: the quorum is 2-of-3, not 3-of-3 -- one absent
    // signer must not block a legitimate migration.
    let cfg = MigrateCfg { signer_seeds: [Some(81), Some(82), None], ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert!(res.is_ok(), "MIGRATE with exactly 2 of 3 quorum signatures must be accepted: {res:?}");
}

#[test]
fn migrate_1of3_insufficient_rejected() {
    // Only ONE quorum slot is genuinely signed; the other two are arbitrary
    // placeholders. The summed threshold (1) is below the required 2, so the
    // branch must reject even though the supplied signature is perfectly
    // valid. This is the governance-exit hole that Decision 2026-07-20
    // closed: before it, a single hot OPS signature was enough.
    let cfg = MigrateCfg { signer_seeds: [Some(81), None, None], ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_ops_key_alone_cannot_authorize() {
    // The hot OPS key was MIGRATE's sole authorizer before Decision
    // 2026-07-20. Even signing all three quorum slots with it must now fail:
    // it is not one of the three baked cold SEIZE keys.
    let cfg = MigrateCfg { signer_seeds: [Some(72), Some(72), Some(72)], ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_missing_owner_sig_rejected() {
    // Empty owner_sig (0 bytes): `OpCheckSig`'s hash-type-byte pop sees
    // nothing and evaluates to `false` with no parse error at all, so
    // `OpCheckSigVerify` aborts with `VerifyError` -- mirrors
    // `burn_missing_owner_sig_rejected`'s failure shape exactly (same owner-
    // authorization mechanics).
    let cfg = MigrateCfg::honest();
    let res = run(&build_migrate_scenario(&cfg, Some(&[]), None));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_missing_quorum_attestation_rejected() {
    // Empty sig in the first quorum slot (0 bytes): `OpCheckSigFromStack`
    // tries to parse it as a 64-byte Schnorr signature and fails at parsing,
    // before any key comparison is even attempted -- mirrors
    // `burn_missing_mint_attestation_rejected`'s failure shape.
    let cfg = MigrateCfg::honest();
    let res = run(&build_migrate_scenario(&cfg, None, Some(&[])));
    assert_rejected_with(&res, "InvalidSignature");
}

#[test]
fn migrate_wrong_quorum_keys_rejected() {
    // Every attestation is a valid signature over the correct message, but
    // from keys that are NOT the baked cold SEIZE keys. Only the real quorum
    // members can authorize a migration.
    let cfg = MigrateCfg { signer_seeds: [Some(97), Some(98), Some(99)], ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_successor_template_mismatch_rejected() {
    // The quorum genuinely attested a new_template_hash for one candidate
    // template, but the successor output ACTUALLY paid to hashes to a
    // DIFFERENT template -- the attestation itself is internally consistent
    // (OpCheckSigFromStack would pass), but the SEPARATE on-chain check
    // (real OpTxOutputSpk-derived hash == attested new_template_hash) must
    // still reject it: attestation validity alone must never be enough to
    // redirect a migration to an unapproved target.
    let cfg = MigrateCfg { successor_template_mismatch: true, ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_replay_other_outpoint_rejected() {
    // The quorum attested for outpoint txid seed 0x77, but the input
    // actually spends the outpoint with txid seed 0x50 (MigrateCfg::honest()'s
    // default). The on-chain OpOutpointTxId binds the REAL spend, so the
    // recomputed msg_hash differs from what was signed -- the 0x77
    // attestation is worthless here (replay protection).
    let cfg = MigrateCfg { attest_outpoint_txid_seed: Some(0x77), ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_of_frozen_coin_rejected() {
    // Audit fix (MEDIUM): "freeze == total owner immobility" -- a frozen
    // (sanctioned) coin must not be migratable to an arbitrary successor
    // template by its owner, even with an otherwise fully honest owner +
    // 2-of-3 quorum -- that would let a frozen coin escape governance
    // entirely. Only the issuer's SEIZE branch (no owner signature, no frozen
    // gate) may act on a frozen coin.
    let cfg = MigrateCfg { frozen_flag: frozen_flag::SET, ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_of_unfrozen_coin_accepts() {
    // Regression guard: the new frozen_flag gate must not disturb the
    // existing happy path -- an unfrozen coin's owner + quorum co-signed
    // MIGRATE still accepts (same scenario as the happy-path test, named
    // to pair explicitly with `migrate_of_frozen_coin_rejected` above).
    let cfg = MigrateCfg { frozen_flag: frozen_flag::CLEAR, ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert!(res.is_ok(), "honest owner+quorum MIGRATE of an UNFROZEN coin must be accepted: {res:?}");
}
