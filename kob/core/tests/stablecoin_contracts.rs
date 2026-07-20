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
use kob_core::contract::stablecoin::state::{
    EPOCH_OPCODE_OFFSET, FROZEN_FLAG_OPCODE_OFFSET, IDENTIFIER_TYPE_OPCODE_OFFSET, OWNER_PUBKEY_OPCODE_OFFSET,
    ROLE_REGISTRY_ROOT_OPCODE_OFFSET,
};
use kob_core::contract::stablecoin::{
    build_attestation_message, build_freeze_attestation_message, build_migrate_attestation_message, build_seize_attestation_message,
    build_stablecoin_burn_sigscript, build_stablecoin_freeze_sigscript, build_stablecoin_migrate_sigscript,
    build_stablecoin_redeem_script, build_stablecoin_seize_sigscript, build_stablecoin_transfer_nm_delegator_sigscript,
    build_stablecoin_transfer_nm_leader_sigscript, build_stablecoin_transfer_sigscript, build_transfer_nm_attestation_message,
    fold_transfer_nm_inputs_digest, fold_transfer_nm_outputs_digest, BURN_SINK_SCRIPT, TRANSFER_NM_MAX_N,
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

// Fixed RECOVERY-role pubkey seeds baked into every redeem script in this
// file built by a scenario that does NOT itself exercise the MIGRATE branch
// (TRANSFER's `Cfg::build`, FREEZE's `build_freeze_scenario`, SEIZE's
// `build_seize`, BURN's `build_burn_scenario`) -- none of those batches test
// the recovery key/branch, so a single shared constant (rather than new
// fields on each `Cfg`) keeps those batches' existing field
// lists/`..Cfg::honest()` call sites untouched, mirroring
// `UNRELATED_SEIZE_SEEDS`/`UNRELATED_MINT_SEED` above. Decision
// 2026-07-20-G0: `recovery_pubkeys` is now an INDEPENDENT cold set from
// `seize_pubkeys`, gating MIGRATE alone.
const UNRELATED_RECOVERY_SEEDS: [u8; 3] = [96, 97, 98];

fn unrelated_seize_pubkeys() -> [[u8; 32]; 3] {
    [pubkey(UNRELATED_SEIZE_SEEDS[0]), pubkey(UNRELATED_SEIZE_SEEDS[1]), pubkey(UNRELATED_SEIZE_SEEDS[2])]
}

fn unrelated_recovery_pubkeys() -> [[u8; 32]; 3] {
    [pubkey(UNRELATED_RECOVERY_SEEDS[0]), pubkey(UNRELATED_RECOVERY_SEEDS[1]), pubkey(UNRELATED_RECOVERY_SEEDS[2])]
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
    /// Corrupt ONE byte of the successor `new_rs` at `(offset, value)`, applied
    /// AFTER the honest script is built but BEFORE its P2SH/attestation are
    /// derived from it -- so `dr_output_spk_check` and the OPS attestation stay
    /// self-consistent with the corrupted script, exactly as the real §6.2
    /// header-opcode attack would. `None` == honest.
    successor_header_opcode_corrupt: Option<(usize, u8)>,

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
            successor_header_opcode_corrupt: None,
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
        &unrelated_recovery_pubkeys(),
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
    let mut new_rs = build_stablecoin_redeem_script(
        &recipient_pub,
        id_type::PUBKEY,
        &successor_root,
        cfg.successor_frozen_flag.unwrap_or(frozen_flag::CLEAR),
        successor_epoch,
        &s_ops,
        &s_freeze,
        &s_seize,
        &unrelated_recovery_pubkeys(),
        &s_mint,
    );
    if let Some((off, val)) = cfg.successor_header_opcode_corrupt {
        new_rs[off] = val;
    }
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
    /// Role keys baked into the SUCCESSOR body (§6.3 role-swap guard). `None`
    /// == this covenant's own role set (honest). `(ops, freeze, [seize x3],
    /// mint)`. The §E template-authentication guard is wired into FREEZE too,
    /// but until now only TRANSFER had a regression test exercising it.
    successor_role_seeds: Option<(u8, u8, [u8; 3], u8)>,
    /// Corrupt ONE byte of the successor `new_rs` before its P2SH/attestation
    /// are derived (§6.2 header-opcode attack). `None` == honest.
    successor_header_opcode_corrupt: Option<(usize, u8)>,

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
            successor_role_seeds: None,
            successor_header_opcode_corrupt: None,
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
        &unrelated_recovery_pubkeys(),
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
    let (s_ops, s_freeze, s_seize, s_mint) = match cfg.successor_role_seeds {
        None => (ops_pub, freeze_pub, seize_pubs, mint_pub),
        Some((o, f, sz, m)) => (pubkey(o), pubkey(f), [pubkey(sz[0]), pubkey(sz[1]), pubkey(sz[2])], pubkey(m)),
    };
    let mut new_rs = build_stablecoin_redeem_script(
        &successor_owner_pub,
        id_type::PUBKEY,
        &successor_root,
        successor_frozen_flag,
        successor_epoch,
        &s_ops,
        &s_freeze,
        &s_seize,
        &unrelated_recovery_pubkeys(),
        &s_mint,
    );
    if let Some((off, val)) = cfg.successor_header_opcode_corrupt {
        new_rs[off] = val;
    }
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
    /// Role keys baked into the SUCCESSOR body (§6.3 role-swap guard). `None`
    /// == this covenant's own role set (honest). `(ops, freeze, [seize x3],
    /// mint)`. The §E template-authentication guard is wired into SEIZE too,
    /// but until now only TRANSFER had a regression test exercising it.
    successor_role_seeds: Option<(u8, u8, [u8; 3], u8)>,
    /// Corrupt ONE byte of the successor `new_rs` before its P2SH/attestation
    /// are derived (§6.2 header-opcode attack). `None` == honest.
    successor_header_opcode_corrupt: Option<(usize, u8)>,

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
            successor_role_seeds: None,
            successor_header_opcode_corrupt: None,
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
        &unrelated_recovery_pubkeys(),
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
    let (s_ops, s_freeze, s_seize, s_mint) = match cfg.successor_role_seeds {
        None => (ops_pub, freeze_pub, seize_pubs, mint_pub),
        Some((o, f, sz, m)) => (pubkey(o), pubkey(f), [pubkey(sz[0]), pubkey(sz[1]), pubkey(sz[2])], pubkey(m)),
    };
    let mut new_rs = build_stablecoin_redeem_script(
        &successor_owner_pub,
        id_type::PUBKEY,
        &successor_root,
        successor_frozen_flag,
        successor_epoch,
        &s_ops,
        &s_freeze,
        &s_seize,
        &unrelated_recovery_pubkeys(),
        &s_mint,
    );
    if let Some((off, val)) = cfg.successor_header_opcode_corrupt {
        new_rs[off] = val;
    }
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
        &unrelated_recovery_pubkeys(),
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
//    `OpCheckSigFromStack` attestation) -- but the attesting quorum here is
//    MIGRATE's OWN independent cold 2-of-3 `recovery_pubkeys` (Decision
//    2026-07-20-G0). §4's original branch table specified MIGRATE
//    authorization as "OWNER + (ROTATE or OPS)"; ROTATE (`0x05`) is deferred
//    to post-Live (see `build_migrate_branch`'s doc,
//    `core/src/contract/stablecoin/body.rs`). Decision 2026-07-20 first
//    replaced the initial-Live OPS stand-in with the SAME cold 2-of-3 quorum
//    SEIZE uses (`seize_pubkeys`); Decision 2026-07-20-G0 (this fix) then
//    found that sharing key material with SEIZE meant a SEIZE-key leak also
//    destroyed the recovery path, so MIGRATE now uses its OWN independent
//    `recovery_pubkeys` cold set instead, pairwise-distinct from
//    `seize_pubkeys`. The successor is a WHOLLY DIFFERENT covenant template
//    (not a same-template state mutation like TRANSFER/FREEZE/SEIZE/BURN):
//    the body doesn't read/compare any fields inside it, it only checks that
//    the successor output's SPK Blake3-hashes to the attested
//    `new_template_hash` -- there is no `new_rs` sigscript field at all
//    (unlike TRANSFER/FREEZE/SEIZE). Because the owner signs SIGHASH_ALL,
//    value handling is owner-committed -- MIGRATE deliberately does NOT call
//    `dr_value_continuity_check` (mirrors BURN's rationale); see
//    `build_migrate_branch`'s doc (`body.rs`).
// ============================================================================

/// One MIGRATE scenario. `honest()` yields a fully valid owner+recovery-quorum
/// migration to a distinct, non-stablecoin successor template (a plain
/// OP_TRUE P2SH -- proving MIGRATE doesn't validate the target's shape at
/// all, per task spec); each adversarial test mutates exactly one lever.
#[derive(Clone)]
struct MigrateCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,
    owner_seed: u8,        // owner pubkey baked into the state header AND the key that signs owner_sig
    ops_seed: u8,          // OPS pubkey baked into the body (irrelevant to MIGRATE since Decision 2026-07-20)
    freeze_seed: u8,       // FREEZE pubkey baked into the body (irrelevant to MIGRATE itself)
    seize_seeds: [u8; 3],  // the three baked SEIZE pubkey seeds -- SEIZE's own cold 2-of-3 quorum,
                           // genuinely unrelated to MIGRATE since Decision 2026-07-20-G0 (see
                           // `migrate_rejects_genuine_seize_quorum_signatures` below)
    recovery_seeds: [u8; 3], // the three baked RECOVERY pubkey seeds -- MIGRATE's OWN independent
                              // cold 2-of-3 quorum (Decision 2026-07-20-G0), pairwise-distinct from
                              // `seize_seeds`
    mint_seed: u8,         // MINT pubkey baked into the body (irrelevant to MIGRATE itself)
    root: [u8; 32],        // this coin's role_registry_root (unread/uncompared by MIGRATE)
    epoch: u32,            // this coin's epoch (bound into the OPS attestation preimage)
    frozen_flag: u8,       // this coin's CURRENT frozen_flag (MIGRATE is not frozen-gated, see body.rs doc)
    in_amount: u64,
    out_value: u64,        // successor (new-template) output native value -- owner-chosen, SIGHASH_ALL-committed

    // Which seed actually signs each of the 3 fixed quorum sigscript slots
    // (`Some(seed)`) vs. an arbitrary non-signature placeholder (`None`).
    // Honest == all three slots signed by `recovery_seeds` in order (NOT
    // `seize_seeds` -- Decision 2026-07-20-G0 made the two quorums
    // independent; the shared bytecode SHAPE with `SeizeCfg::signer_seeds`
    // remains, the key material does not).
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
            recovery_seeds: [101, 102, 103],
            mint_seed: 84,
            root: ROOT,
            epoch: 8,
            frozen_flag: frozen_flag::CLEAR,
            in_amount: IN_AMOUNT,
            out_value: IN_AMOUNT,
            signer_seeds: [Some(101), Some(102), Some(103)], // == recovery_seeds, NOT seize_seeds
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
    let recovery_pubs = [pubkey(cfg.recovery_seeds[0]), pubkey(cfg.recovery_seeds[1]), pubkey(cfg.recovery_seeds[2])];
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
        &recovery_pubs,
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
    // real engine IS the conformance proof: the independent recovery-quorum
    // members signed `build_migrate_attestation_message(...)` off-chain, and the body
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
    // signer must not block a legitimate migration. Signed with the
    // independent recovery quorum (Decision 2026-07-20-G0), not seize_seeds.
    let cfg = MigrateCfg { signer_seeds: [Some(101), Some(102), None], ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert!(res.is_ok(), "MIGRATE with exactly 2 of 3 quorum signatures must be accepted: {res:?}");
}

#[test]
fn migrate_1of3_insufficient_rejected() {
    // Only ONE quorum slot is genuinely signed; the other two are arbitrary
    // placeholders. The summed threshold (1) is below the required 2, so the
    // branch must reject even though the supplied signature is perfectly
    // valid. This is the governance-exit hole that Decision 2026-07-20
    // closed: before it, a single hot OPS signature was enough. Signed with
    // the independent recovery quorum (Decision 2026-07-20-G0).
    let cfg = MigrateCfg { signer_seeds: [Some(101), None, None], ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_ops_key_alone_cannot_authorize() {
    // The hot OPS key was MIGRATE's sole authorizer before Decision
    // 2026-07-20. Even signing all three quorum slots with it must now fail:
    // it is not one of the three baked cold recovery keys (Decision
    // 2026-07-20-G0).
    let cfg = MigrateCfg { signer_seeds: [Some(72), Some(72), Some(72)], ..MigrateCfg::honest() };
    let res = run(&build_migrate(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn migrate_rejects_genuine_seize_quorum_signatures() {
    // G0 regression guard: the coin's REAL SEIZE-role signers (seize_seeds
    // = [81,82,83], which genuinely authorize SEIZE on this coin) must NOT
    // be able to authorize MIGRATE any more. Pre-fix this was accepted.
    let cfg = MigrateCfg { signer_seeds: [Some(81), Some(82), Some(83)], ..MigrateCfg::honest() };
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

// ============================================================================
// 6. Audit 2026-07-20 §6.2 -- successor header PUSH-OPCODE authentication
//    (the "new HIGH"), and §6.3 -- FREEZE/SEIZE successor role-swap regression
//    coverage the earlier audit round left to TRANSFER alone.
//
//    §6.2: `dr_suffix_check` pins the successor BODY ([STATE_HEADER_LEN..]) and
//    each `dr_field_extract` pins a field's PAYLOAD, but the five header
//    push-opcode bytes (offsets 0/33/35/68/70 == 0x20 0x01 0x20 0x01 0x04)
//    were read by nothing. A spender who can satisfy a successor-producing
//    branch -- in the worst case the single FREEZE key -- could corrupt one,
//    passing every on-chain check yet committing the coin's P2SH to a header
//    that re-parses at a different stack depth: permanently unspendable
//    (griefing/destruction, effectively CRITICAL). `body.rs`'s shared
//    `emit_header_opcode_authentication` now pins all five in every branch.
// ============================================================================

#[test]
fn transfer_successor_header_opcode_corruption_rejected() {
    // All five header opcode offsets, corrupted one at a time to 0xff (which
    // differs from every canonical opcode 0x20/0x01/0x04). Each must reject --
    // pre-fix, every one of these was ACCEPTED (see the pre-fix confirmation
    // note in the audit; toggling the three `emit_header_opcode_authentication`
    // calls off makes this test's cases pass acceptance again).
    for off in [
        OWNER_PUBKEY_OPCODE_OFFSET,
        IDENTIFIER_TYPE_OPCODE_OFFSET,
        ROLE_REGISTRY_ROOT_OPCODE_OFFSET,
        FROZEN_FLAG_OPCODE_OFFSET,
        EPOCH_OPCODE_OFFSET,
    ] {
        let cfg = Cfg { successor_header_opcode_corrupt: Some((off, 0xff)), ..Cfg::honest() };
        let res = run(&build(&cfg));
        assert_rejected_with(&res, "VerifyError");
    }
}

#[test]
fn freeze_successor_header_opcode_corruption_rejected() {
    // The dangerous capability: a SINGLE FREEZE key. Corrupting the epoch
    // push-opcode (offset 70) of the successor must now reject rather than
    // brick the coin. Swept across all five offsets for parity with TRANSFER.
    for off in [
        OWNER_PUBKEY_OPCODE_OFFSET,
        IDENTIFIER_TYPE_OPCODE_OFFSET,
        ROLE_REGISTRY_ROOT_OPCODE_OFFSET,
        FROZEN_FLAG_OPCODE_OFFSET,
        EPOCH_OPCODE_OFFSET,
    ] {
        let cfg = FreezeCfg { successor_header_opcode_corrupt: Some((off, 0xff)), ..FreezeCfg::honest_freeze() };
        let res = run(&build_freeze(&cfg));
        assert_rejected_with(&res, "VerifyError");
    }
}

#[test]
fn seize_successor_header_opcode_corruption_rejected() {
    // Same, on the SEIZE branch (cold 2-of-3 quorum path).
    for off in [
        OWNER_PUBKEY_OPCODE_OFFSET,
        IDENTIFIER_TYPE_OPCODE_OFFSET,
        ROLE_REGISTRY_ROOT_OPCODE_OFFSET,
        FROZEN_FLAG_OPCODE_OFFSET,
        EPOCH_OPCODE_OFFSET,
    ] {
        let cfg = SeizeCfg { successor_header_opcode_corrupt: Some((off, 0xff)), ..SeizeCfg::honest() };
        let res = run(&build_seize(&cfg));
        assert_rejected_with(&res, "VerifyError");
    }
}

#[test]
fn freeze_successor_swapping_the_role_set_rejected() {
    // §6.3: the §E template-authentication guard IS wired into FREEZE
    // (`body.rs`'s `dr_suffix_check`), but only TRANSFER had a regression test
    // for it. A FREEZE that keeps every state field but bakes a different role
    // set into the successor -- moving the coin into a covenant the real issuer
    // holds no keys for -- must be rejected by the suffix compare.
    let cfg = FreezeCfg { successor_role_seeds: Some((60, 61, [62, 63, 64], 65)), ..FreezeCfg::honest_freeze() };
    let res = run(&build_freeze(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn seize_successor_swapping_the_role_set_rejected() {
    // §6.3, SEIZE branch. Same property: an honest 2-of-3 quorum cannot hand
    // the coin a successor with a swapped role set.
    let cfg = SeizeCfg { successor_role_seeds: Some((60, 61, [62, 63, 64], 65)), ..SeizeCfg::honest() };
    let res = run(&build_seize(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// TRANSFER_NM (op_type = 0x07 leader / 0x08 delegator) -- N:M transfer (G1,
// split/merge), item 1 of this wave. Harness style follows
// `kob/core/tests/kcc20_contracts.rs`'s `InSpec`/`OutSpec`/`build_transfer`/
// `run` N-in/M-out pattern (the closest existing precedent for exactly this
// leader/delegator group shape), adapted to this covenant's native-value
// amount mapping and its own attestation preimage
// (`build_transfer_nm_attestation_message`).
//
// Scope reminder (see `body.rs`'s `build_transfer_nm_branch` doc): N:M works
// WITHIN one MINT lineage (one shared `covenant_id`) -- arbitrary-amount
// payment + change + self-consolidation, not a merge across independent MINT
// events.
// ============================================================================

const NM_ROOT: [u8; 32] = [0xFEu8; 32];
const NM_EPOCH: u32 = 3;
const NM_OPS_SEED: u8 = 150;
const NM_FREEZE_SEED: u8 = 151;
const NM_SEIZE_SEEDS: [u8; 3] = [152, 153, 154];
const NM_RECOVERY_SEEDS: [u8; 3] = [155, 156, 157];
const NM_MINT_SEED: u8 = 158;
/// Base txid seed for NM scenario inputs (`outpoint(NM_TXID_BASE + idx, 0)`);
/// kept in its own range so NM tests can never collide with an unrelated
/// covenant_id input the way `kcc20_contracts.rs`'s
/// `unrelated_covenant_id_input_is_not_absorbed_into_the_group` deliberately
/// does (not exercised by this batch, but keeping the seed space disjoint
/// avoids any accidental aliasing).
const NM_TXID_BASE: u8 = 0x40;

fn nm_role_pubkeys() -> ([u8; 32], [u8; 32], [[u8; 32]; 3], [[u8; 32]; 3], [u8; 32]) {
    (
        pubkey(NM_OPS_SEED),
        pubkey(NM_FREEZE_SEED),
        [pubkey(NM_SEIZE_SEEDS[0]), pubkey(NM_SEIZE_SEEDS[1]), pubkey(NM_SEIZE_SEEDS[2])],
        [pubkey(NM_RECOVERY_SEEDS[0]), pubkey(NM_RECOVERY_SEEDS[1]), pubkey(NM_RECOVERY_SEEDS[2])],
        pubkey(NM_MINT_SEED),
    )
}

/// Build one coin's redeem script for the NM scenario. `role_override`
/// (`Some((ops, freeze, seize_seeds, recovery_seeds, mint))`) is the
/// audit-2026-07-20-section-E attack lever (§6.3, ported to TRANSFER_NM): a
/// successor that keeps every state field this branch compares while baking
/// a different role set out from under the issuer. `None` uses the group's
/// shared honest roles.
fn nm_redeem_script(owner_seed: u8, root: [u8; 32], frozen: u8, epoch: u32, role_override: Option<(u8, u8, [u8; 3], [u8; 3], u8)>) -> Vec<u8> {
    let (ops, freeze, seize, recovery, mint) = match role_override {
        None => nm_role_pubkeys(),
        Some((o, f, sz, rc, m)) => {
            (pubkey(o), pubkey(f), [pubkey(sz[0]), pubkey(sz[1]), pubkey(sz[2])], [pubkey(rc[0]), pubkey(rc[1]), pubkey(rc[2])], pubkey(m))
        }
    };
    build_stablecoin_redeem_script(&pubkey(owner_seed), id_type::PUBKEY, &root, frozen, epoch, &ops, &freeze, &seize, &recovery, &mint)
}

/// One covenant input in an N:M scenario (leader == `ins[0]`, every other
/// entry is a delegator/sibling). `owner_seed` derives BOTH the coin's
/// `owner_pubkey` and (normally) the signing key; `sign_seed` lets a test
/// sign with a DIFFERENT key. Every input in a group shares `NM_ROOT`/
/// `NM_EPOCH` (the design's sibling pass does not itself check a sibling's
/// root/epoch against the leader's -- see `build_transfer_nm_branch`'s
/// per-step derivation; only `covenant_id` -- hash-derived at MINT genesis,
/// carried structurally by every coin in one lineage -- ties the group
/// together on-chain).
#[derive(Clone)]
struct NmInSpec {
    owner_seed: u8,
    sign_seed: u8,
    amount: u64,
    frozen_flag: u8,
}

impl NmInSpec {
    fn honest(seed: u8, amount: u64) -> Self {
        NmInSpec { owner_seed: seed, sign_seed: seed, amount, frozen_flag: frozen_flag::CLEAR }
    }
}

/// One successor (covenant output) slot in an N:M scenario.
#[derive(Clone)]
struct NmOutSpec {
    recipient_seed: u8,
    amount: u64,
    frozen_flag: u8,
    root: [u8; 32],
    epoch: u32,
    role_override: Option<(u8, u8, [u8; 3], [u8; 3], u8)>,
    /// Corrupt ONE byte of this successor's redeem script at `(offset,
    /// value)`, applied AFTER the honest script is built but BEFORE its
    /// P2SH/digest are derived from it -- ports the §6.2 header-opcode
    /// corruption regression to a TRANSFER_NM successor slot.
    header_opcode_corrupt: Option<(usize, u8)>,
}

impl NmOutSpec {
    fn honest(seed: u8, amount: u64) -> Self {
        NmOutSpec {
            recipient_seed: seed,
            amount,
            frozen_flag: frozen_flag::CLEAR,
            root: NM_ROOT,
            epoch: NM_EPOCH,
            role_override: None,
            header_opcode_corrupt: None,
        }
    }
}

/// Pad/truncate `active` (in ascending successor-slot order) into the fixed
/// `TRANSFER_NM_MAX_N`-length sigscript array (mirrors
/// `kcc20_contracts.rs`'s `new_rs_slots`). Slots beyond `active.len()` are
/// left empty (never read on-chain, guarded by `j <= OpCovOutputCount`);
/// slots beyond `TRANSFER_NM_MAX_N` are silently dropped (used by the
/// cardinality-overflow test, where the ACTUAL tx has more outputs than the
/// leader can unroll -- rejection must come from the on-chain cardinality
/// cap, not from this test helper).
fn nm_new_rs_slots(active: &[Vec<u8>]) -> [Vec<u8>; TRANSFER_NM_MAX_N] {
    let mut slots: [Vec<u8>; TRANSFER_NM_MAX_N] = Default::default();
    for (i, rs) in active.iter().take(TRANSFER_NM_MAX_N).enumerate() {
        slots[i] = rs.clone();
    }
    slots
}

struct NmBuilt {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    n_inputs: usize,
}

/// Build a fully assembled, honestly-signed TRANSFER_NM transaction. The
/// leader is `ins[0]`; `ins[1..]` are delegators, all sharing `cov_id`.
/// Successor outputs are `outs`, each covenant-bound to the leader
/// (`authorizing_input = 0`, matching `kcc20_contracts.rs`'s convention).
///
/// `attest_outs` is what the OPS attestation is computed FOR (its redeem
/// scripts feed `outputs_digest`) -- separate from `outs` (what the tx
/// ACTUALLY pays) so the attestation-replay test can honestly attest one
/// output set and then swap in a different one. Every other test passes
/// `attest_outs == outs`.
fn build_transfer_nm(cov_id: Hash, ins: &[NmInSpec], outs: &[NmOutSpec], attest_outs: &[NmOutSpec]) -> NmBuilt {
    let input_rs: Vec<Vec<u8>> = ins.iter().map(|i| nm_redeem_script(i.owner_seed, NM_ROOT, i.frozen_flag, NM_EPOCH, None)).collect();
    let input_spks: Vec<ScriptPublicKey> = input_rs.iter().map(|rs| build_p2sh(rs)).collect();

    let build_output_rs = |o: &NmOutSpec| -> Vec<u8> {
        let mut rs = nm_redeem_script(o.recipient_seed, o.root, o.frozen_flag, o.epoch, o.role_override);
        if let Some((off, val)) = o.header_opcode_corrupt {
            rs[off] = val;
        }
        rs
    };
    let output_rs: Vec<Vec<u8>> = outs.iter().map(build_output_rs).collect();
    let output_spks: Vec<ScriptPublicKey> = output_rs.iter().map(|rs| build_p2sh(rs)).collect();

    let tx_outputs: Vec<TransactionOutput> = outs
        .iter()
        .zip(output_spks.iter())
        .map(|(o, spk)| TransactionOutput::with_covenant(o.amount, spk.clone(), Some(CovenantBinding::new(0, cov_id))))
        .collect();

    let entries: Vec<UtxoEntry> = input_spks
        .iter()
        .zip(ins.iter())
        .map(|(spk, i)| UtxoEntry { amount: i.amount, script_public_key: spk.clone(), block_daa_score: 0, is_coinbase: false, covenant_id: Some(cov_id) })
        .collect();

    // sig_op_count is committed into SIGHASH_ALL (`sig_op_counts_hash`,
    // consensus/core/src/hashing/sighash.rs) -- the skeleton's placeholder
    // inputs MUST carry the SAME sig_op_count as the real inputs below, or
    // every owner signature computed here would sign a DIFFERENT hash than
    // the one the engine reconstructs at verification time.
    let placeholder_inputs: Vec<TransactionInput> = (0..ins.len())
        .map(|idx| TransactionInput::new(outpoint(NM_TXID_BASE + idx as u8, 0), vec![], 0, if idx == 0 { 2 } else { 1 }))
        .collect();
    let skeleton_tx = Transaction::new(0, placeholder_inputs, tx_outputs.clone(), 0, Default::default(), 0, vec![]);
    let populated_skeleton = PopulatedTransaction::new(&skeleton_tx, entries.clone());

    // Owner signatures for EVERY input (leader + every delegator), SIGHASH_ALL.
    let sigs: Vec<[u8; 64]> = (0..ins.len())
        .map(|idx| {
            let reused = SigHashReusedValuesUnsync::new();
            let hash = calc_schnorr_signature_hash(&populated_skeleton, idx, SIG_HASH_ALL, &reused);
            schnorr_sign(&hash.as_bytes(), &privkey(ins[idx].sign_seed)).unwrap()
        })
        .collect();

    // --- Issuer (OPS) attestation over the WHOLE group, one signature ---
    // (see `attestation.rs`'s `build_transfer_nm_attestation_preimage` doc:
    // n_in/n_out are the ACTUAL OpCovInputCount/OpCovOutputCount values,
    // i.e. n_in counts the leader too).
    let cov_bytes: [u8; 32] = cov_id.as_bytes();
    let n_in = ins.len() as u8;
    let n_out = attest_outs.len() as u8;
    // Siblings only (s = 1..), matching the on-chain leader's sibling pass --
    // the leader's OWN outpoint/amount are deliberately excluded (see the
    // attestation module doc).
    let siblings: Vec<([u8; 32], u32, u64)> =
        (1..ins.len()).map(|s| ([NM_TXID_BASE + s as u8; 32], 0u32, ins[s].amount)).collect();
    let inputs_digest = fold_transfer_nm_inputs_digest(&siblings);
    let attest_output_rs: Vec<Vec<u8>> = attest_outs.iter().map(build_output_rs).collect();
    let attest_output_spk_bytes: Vec<Vec<u8>> = attest_output_rs.iter().map(|rs| spk_to_bytes(&build_p2sh(rs))).collect();
    let outputs_digest = fold_transfer_nm_outputs_digest(&attest_output_spk_bytes);
    let attest_msg = build_transfer_nm_attestation_message(&cov_bytes, NM_EPOCH, n_in, n_out, &inputs_digest, &outputs_digest);
    let issuer_sig: [u8; 64] = schnorr_sign(&attest_msg, &privkey(NM_OPS_SEED)).unwrap();

    let final_inputs: Vec<TransactionInput> = (0..ins.len())
        .map(|idx| {
            let ss = if idx == 0 {
                let slots = nm_new_rs_slots(&output_rs);
                build_stablecoin_transfer_nm_leader_sigscript(&input_rs[0], &issuer_sig, &slots, &sigs[0], &input_rs[0])
            } else {
                build_stablecoin_transfer_nm_delegator_sigscript(&sigs[idx], &input_rs[idx])
            };
            // sig_op_count: leader = 2 (owner CheckSigVerify + OPS
            // CheckSigFromStack), delegator = 1 (owner CheckSigVerify only).
            TransactionInput::new(outpoint(NM_TXID_BASE + idx as u8, 0), ss, 0, if idx == 0 { 2 } else { 1 })
        })
        .collect();

    let tx = Transaction::new(0, final_inputs, tx_outputs, 0, Default::default(), 0, vec![]);
    NmBuilt { tx, entries, n_inputs: ins.len() }
}

/// Re-sign delegator input `idx` (>=1) with the LEADER's sigscript shape
/// instead of the delegator's -- proves a non-leader position invoking the
/// leader entrypoint is rejected regardless of anything else in the body.
fn nm_resign_as_leader(built: &mut NmBuilt, idx: usize, self_rs: &[u8], issuer_sig: &[u8; 64], new_rs: &[Vec<u8>], sign_seed: u8) {
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, idx, SIG_HASH_ALL, &reused);
    let sig = schnorr_sign(&hash.as_bytes(), &privkey(sign_seed)).unwrap();
    let slots = nm_new_rs_slots(new_rs);
    built.tx.inputs[idx].signature_script = build_stablecoin_transfer_nm_leader_sigscript(self_rs, issuer_sig, &slots, &sig, self_rs);
}

fn run_nm(built: &NmBuilt) -> Vec<Result<(), String>> {
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

// ---- 1. Happy paths -------------------------------------------------------

#[test]
fn transfer_nm_2in_1out_merge_accepts() {
    let cov_id = hash32(0x60);
    let ins = vec![NmInSpec::honest(1, 3_000_000), NmInSpec::honest(3, 2_000_000)];
    let outs = vec![NmOutSpec::honest(2, 5_000_000)];
    let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
    let results = run_nm(&built);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(), "leader (merge) must pass: {:?}", results[0]);
    assert!(results[1].is_ok(), "delegator (merge) must pass: {:?}", results[1]);
}

#[test]
fn transfer_nm_1in_2out_split_with_change_accepts() {
    // The core G1 case: pay X + keep change Y.
    let cov_id = hash32(0x61);
    let ins = vec![NmInSpec::honest(1, 7_000_000)];
    let outs = vec![NmOutSpec::honest(2, 3_000_000), NmOutSpec::honest(4, 4_000_000)];
    let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
    let results = run_nm(&built);
    assert!(results[0].is_ok(), "1-in/2-out split must pass: {:?}", results[0]);
}

#[test]
fn transfer_nm_happy_all_slots_active_accepts() {
    // Full unroll: N_in = MAX_N+1 (leader + every sibling slot), N_out =
    // MAX_N (every successor slot) -- proves padding/guards work all the way
    // to the last iteration, not just the first.
    let cov_id = hash32(0x62);
    let ins: Vec<NmInSpec> = (0..=TRANSFER_NM_MAX_N).map(|i| NmInSpec::honest(10 + i as u8, 1_000_000)).collect();
    let total: u64 = ins.iter().map(|i| i.amount).sum();
    let per_out = total / TRANSFER_NM_MAX_N as u64;
    let mut outs: Vec<NmOutSpec> = (0..TRANSFER_NM_MAX_N).map(|j| NmOutSpec::honest(20 + j as u8, per_out)).collect();
    // Fix up rounding so Σout == Σin exactly.
    let out_sum: u64 = outs.iter().map(|o| o.amount).sum();
    outs[0].amount += total - out_sum;

    let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
    let results = run_nm(&built);
    assert_eq!(results.len(), TRANSFER_NM_MAX_N + 1);
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "input {i} (full unroll, N_in=MAX_N+1, N_out=MAX_N) must pass: {r:?}");
    }
}

// ---- 2. Conservation / cardinality ----------------------------------------

#[test]
fn transfer_nm_conservation_violated_rejected() {
    let cov_id = hash32(0x63);
    let ins = vec![NmInSpec::honest(1, 3_000_000), NmInSpec::honest(3, 2_000_000)];
    // Successor claims one sompi MORE than conserved.
    let outs_over = vec![NmOutSpec::honest(2, 5_000_001)];
    let built = build_transfer_nm(cov_id, &ins, &outs_over, &outs_over);
    let results = run_nm(&built);
    assert!(results[0].is_err(), "amount-inflating N:M transfer must be rejected by the leader");

    // Under-delivery (burning value) must ALSO fail: exact conservation, not
    // merely "no inflation".
    let cov_id2 = hash32(0x64);
    let outs_under = vec![NmOutSpec::honest(2, 4_999_999)];
    let built2 = build_transfer_nm(cov_id2, &ins, &outs_under, &outs_under);
    let results2 = run_nm(&built2);
    assert!(results2[0].is_err(), "amount-deficit N:M transfer must be rejected by the leader");
}

#[test]
fn transfer_nm_cardinality_over_max_n_rejected() {
    // N_out = MAX_N+1: one more successor than the leader can unroll. Must
    // be rejected at the cardinality-cap gate BEFORE any per-successor
    // validation runs (the whole point of the cap: extra covenant members
    // beyond MAX_N must not silently escape the conservation loop).
    let cov_id = hash32(0x65);
    let ins = vec![NmInSpec::honest(1, TRANSFER_NM_MAX_N as u64 + 1)];
    let outs: Vec<NmOutSpec> = (0..=TRANSFER_NM_MAX_N).map(|j| NmOutSpec::honest(20 + j as u8, 1)).collect();
    let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
    let results = run_nm(&built);
    assert!(results[0].is_err(), "N_out = MAX_N+1 must be rejected by the leader's cardinality cap");
}

// ---- 3. Per-successor-slot adversarial (not just slot 0) ------------------

#[test]
fn transfer_nm_successor_role_swap_rejected() {
    // A 2-successor split where slot 2 (NOT slot 1) keeps every state field
    // this branch compares while baking a DIFFERENT role set -- the
    // audit-2026-07-20-section-E attack, ported to prove EVERY successor
    // slot's loop iteration performs template authentication, not just the
    // first.
    let cov_id = hash32(0x66);
    let ins = vec![NmInSpec::honest(1, 5_000_000)];
    let mut outs = vec![NmOutSpec::honest(2, 2_000_000), NmOutSpec::honest(4, 3_000_000)];
    outs[1].role_override = Some((60, 61, [62, 63, 64], NM_RECOVERY_SEEDS, 65));
    let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
    let results = run_nm(&built);
    assert!(results[0].is_err(), "successor slot 2 with a swapped role set must be rejected");
}

#[test]
fn transfer_nm_successor_frozen_flag_set_rejected() {
    // Same slot-2 targeting, this time the successor's OWN frozen_flag byte
    // (must always be CLEAR out of TRANSFER_NM, mirrors TRANSFER's invariant).
    let cov_id = hash32(0x67);
    let ins = vec![NmInSpec::honest(1, 5_000_000)];
    let mut outs = vec![NmOutSpec::honest(2, 2_000_000), NmOutSpec::honest(4, 3_000_000)];
    outs[1].frozen_flag = frozen_flag::SET;
    let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
    let results = run_nm(&built);
    assert!(results[0].is_err(), "successor slot 2 carrying frozen_flag=SET must be rejected");
}

// ---- 4. Delegator adversarial ----------------------------------------------

#[test]
fn transfer_nm_delegator_frozen_input_rejected() {
    // One delegator's OWN frozen_flag == SET (leader and the other delegator
    // stay honest) -- the delegator's OWN script run must fail, proving
    // per-coin freeze survives grouping (the leader's sibling pass never
    // reads a sibling's frozen_flag at all -- only the sibling's OWN
    // delegator branch enforces it). The tx as a whole is invalid because
    // Kaspa requires EVERY input's script to succeed, even though the
    // leader's OWN isolated run succeeds.
    let cov_id = hash32(0x68);
    let ins = vec![
        NmInSpec::honest(1, 3_000_000),
        NmInSpec { owner_seed: 3, sign_seed: 3, amount: 2_000_000, frozen_flag: frozen_flag::SET },
    ];
    let outs = vec![NmOutSpec::honest(2, 5_000_000)];
    let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
    let results = run_nm(&built);
    assert!(results[0].is_ok(), "leader path is independent of a sibling's own freeze state: {:?}", results[0]);
    assert!(results[1].is_err(), "the FROZEN delegator's own script run must be rejected");
}

#[test]
fn transfer_nm_delegator_impersonating_leader_rejected() {
    // A non-leader (higher-indexed) covenant input invokes the LEADER
    // entrypoint (TRANSFER_NM) instead of TRANSFER_NM_DELEGATOR. Must be
    // rejected: the leader-position check requires own_idx ==
    // OpCovInputIdx(covenant_id, 0), which fails for input index 1.
    let cov_id = hash32(0x69);
    let ins = vec![NmInSpec::honest(1, 3_000_000), NmInSpec::honest(3, 2_000_000)];
    let outs = vec![NmOutSpec::honest(2, 5_000_000)];
    let mut built = build_transfer_nm(cov_id, &ins, &outs, &outs);

    let sibling_rs = nm_redeem_script(3, NM_ROOT, frozen_flag::CLEAR, NM_EPOCH, None);
    // A structurally-valid (but never-honestly-attestable) issuer_sig --
    // this must be rejected on the LEADER-POSITION check alone, before the
    // attestation is even reconstructed, so any 64 bytes suffice.
    let placeholder_issuer_sig = [0x11u8; 64];
    nm_resign_as_leader(&mut built, 1, &sibling_rs, &placeholder_issuer_sig, &[], 3);

    let results = run_nm(&built);
    assert!(results[1].is_err(), "a non-leader input invoking the TRANSFER_NM leader entrypoint must be rejected");
}

// ---- 5. Header-opcode tamper (item-00 regression, ported to a successor) --

#[test]
fn transfer_nm_header_opcode_tamper_rejected() {
    // Port the §6.2 corruption to a successor slot: regression-guards that
    // item-00's emit_header_opcode_authentication is actually wired into
    // TRANSFER_NM's per-successor loop, not skipped the way the
    // pre-item-00 pattern skipped it.
    let cov_id_base = 0x6Au8;
    for (i, off) in
        [OWNER_PUBKEY_OPCODE_OFFSET, IDENTIFIER_TYPE_OPCODE_OFFSET, ROLE_REGISTRY_ROOT_OPCODE_OFFSET, FROZEN_FLAG_OPCODE_OFFSET, EPOCH_OPCODE_OFFSET]
            .into_iter()
            .enumerate()
    {
        let cov_id = hash32(cov_id_base.wrapping_add(i as u8));
        let ins = vec![NmInSpec::honest(1, 5_000_000)];
        let mut outs = vec![NmOutSpec::honest(2, 5_000_000)];
        outs[0].header_opcode_corrupt = Some((off, 0xff));
        let built = build_transfer_nm(cov_id, &ins, &outs, &outs);
        let results = run_nm(&built);
        assert!(results[0].is_err(), "successor header-opcode corruption at offset {off} must be rejected");
    }
}

// ---- 6. Attestation replay ------------------------------------------------

#[test]
fn transfer_nm_attestation_replay_different_output_set_rejected() {
    // The OPS attestation is honestly computed for a 1-successor output set,
    // then the transaction's ACTUAL output is swapped for a DIFFERENT
    // (same-total-value, still individually honest) successor -- the
    // captured attestation's outputs_digest no longer matches the real
    // outputs_acc the leader folds on-chain, so this must be rejected.
    let cov_id = hash32(0x6F);
    let ins = vec![NmInSpec::honest(1, 5_000_000)];
    let attested_outs = vec![NmOutSpec::honest(2, 5_000_000)];
    let actual_outs = vec![NmOutSpec::honest(4, 5_000_000)]; // different recipient => different SPK => different outputs_digest
    let built = build_transfer_nm(cov_id, &ins, &actual_outs, &attested_outs);
    let results = run_nm(&built);
    assert!(results[0].is_err(), "an attestation captured for a different output set must be rejected");
}

#[test]
fn transfer_nm_delegator_decoy_attack_is_rejected() {
    // CRITICAL regression (audit 2026-07-20): the delegator OPS-gate bypass.
    // The attack: covenant-position 0 = an honest single TRANSFER (0x00) of
    // coin B (carrying B's OWN narrow OPS attestation, for B's transfer only);
    // position 1 = TRANSFER_NM_DELEGATOR (0x08) moving coin A's full value to
    // a plain output with ONLY A's owner signature -- no group OPS attestation,
    // and no verification that a real 0x07 leader ran. Pre-fix BOTH inputs'
    // scripts returned Ok, so A left the covenant with zero issuer visibility.
    // The single-input covenant guard now makes B's TRANSFER reject because a
    // same-lineage sibling covenant input is present (OpCovInputCount == 2),
    // killing the whole transaction and the bypass.
    let cov_id = hash32(0x71);
    let (b_seed, b_recip, a_seed) = (1u8, 2u8, 3u8);
    let (b_amount, a_amount) = (1_000_000u64, 5_000_000u64);

    let rs_b = nm_redeem_script(b_seed, NM_ROOT, frozen_flag::CLEAR, NM_EPOCH, None);
    let rs_a = nm_redeem_script(a_seed, NM_ROOT, frozen_flag::CLEAR, NM_EPOCH, None);
    let spk_b = build_p2sh(&rs_b);
    let spk_a = build_p2sh(&rs_a);
    let new_rs_b = nm_redeem_script(b_recip, NM_ROOT, frozen_flag::CLEAR, NM_EPOCH, None);
    let out_spk_b = build_p2sh(&new_rs_b);
    let attacker_spk = build_p2sh(&[0x51u8]); // arbitrary plain payout for A's value

    let tx_outputs = vec![
        TransactionOutput::with_covenant(b_amount, out_spk_b.clone(), Some(CovenantBinding::new(0, cov_id))),
        TransactionOutput::new(a_amount, attacker_spk),
    ];
    let entries = vec![
        UtxoEntry { amount: b_amount, script_public_key: spk_b, block_daa_score: 0, is_coinbase: false, covenant_id: Some(cov_id) },
        UtxoEntry { amount: a_amount, script_public_key: spk_a, block_daa_score: 0, is_coinbase: false, covenant_id: Some(cov_id) },
    ];

    // SIGHASH_ALL skeleton (sig_op_count: TRANSFER=2, delegator=1).
    let placeholder_inputs = vec![
        TransactionInput::new(outpoint(0x71, 0), vec![], 0, 2),
        TransactionInput::new(outpoint(0x72, 0), vec![], 0, 1),
    ];
    let skeleton = Transaction::new(0, placeholder_inputs, tx_outputs.clone(), 0, Default::default(), 0, vec![]);
    let pop_skel = PopulatedTransaction::new(&skeleton, entries.clone());
    let reused0 = SigHashReusedValuesUnsync::new();
    let owner_b_sig = schnorr_sign(&calc_schnorr_signature_hash(&pop_skel, 0, SIG_HASH_ALL, &reused0).as_bytes(), &privkey(b_seed)).unwrap();
    let reused1 = SigHashReusedValuesUnsync::new();
    let owner_a_sig = schnorr_sign(&calc_schnorr_signature_hash(&pop_skel, 1, SIG_HASH_ALL, &reused1).as_bytes(), &privkey(a_seed)).unwrap();

    // B's own single-transfer OPS attestation (op_type 0x00) -- covers only B.
    let cov_bytes: [u8; 32] = cov_id.as_bytes();
    let attest_b = build_attestation_message(&cov_bytes, op_type::TRANSFER, NM_EPOCH, &[0x71u8; 32], 0, &spk_to_bytes(&out_spk_b), b_amount);
    let issuer_sig_b = schnorr_sign(&attest_b, &privkey(NM_OPS_SEED)).unwrap();

    let ss_b = build_stablecoin_transfer_sigscript(&owner_b_sig, &issuer_sig_b, &new_rs_b, &rs_b);
    let ss_a = build_stablecoin_transfer_nm_delegator_sigscript(&owner_a_sig, &rs_a);
    let final_inputs = vec![
        TransactionInput::new(outpoint(0x71, 0), ss_b, 0, 2),
        TransactionInput::new(outpoint(0x72, 0), ss_a, 0, 1),
    ];
    let tx = Transaction::new(0, final_inputs, tx_outputs, 0, Default::default(), 0, vec![]);
    let results = run_nm(&NmBuilt { tx, entries, n_inputs: 2 });

    // Position-0 decoy TRANSFER is rejected by the single-input guard.
    assert_rejected_with(&results[0], "VerifyError");
}
