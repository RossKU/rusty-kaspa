//! KCC-0020 native-value stablecoin (Plan A) covenant exercised against the
//! real post-Toccata `kaspa-txscript` `TxScriptEngine` (`covenants_enabled =
//! true`), in the same harness style as `kob/core/tests/kcc20_contracts.rs`.
//!
//! This is WU-F: it proves the issuer-attestation *freeze* gate actually runs
//! on the real engine, and — the load-bearing property — that the off-chain
//! attestation message ([`build_attestation_message`]) and the on-chain
//! `body`'s introspection-reconstructed `msg_hash` agree **byte-for-byte**.
//! The whole design hinges on that round-trip: a single field of drift makes
//! every honest transfer fail `OpCheckSigFromStack` (a self-inflicted freeze).
//! The happy path passing on the real engine is the proof that the round-trip
//! closes; the adversarial cases prove that any *deliberate* drift (replay,
//! recipient/amount/covenant substitution, missing/forged issuer signature)
//! is rejected — and rejected by the *intended* verification failure, not a
//! generic parse error.

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

use kob_core::contract::stablecoin::{build_attestation_message, build_stablecoin_redeem_script, build_stablecoin_sigscript};
use kob_core::primitives::push_data;
use kob_core::{build_p2sh, get_public_key, schnorr_sign};

const IN_AMOUNT: u64 = 5_000_000;

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

/// The successor's stablecoin P2SH SPK for a given recipient owner seed (the
/// issuer key is shared across a token's UTXOs).
fn successor_spk(recipient_seed: u8, issuer_seed: u8) -> ScriptPublicKey {
    let rs = build_stablecoin_redeem_script(&pubkey(recipient_seed), &pubkey(issuer_seed));
    build_p2sh(&rs)
}

/// How the issuer attestation signature is produced (the freeze lever).
#[derive(Clone)]
enum AttestMode {
    /// Sign the (possibly-overridden) message with `privkey(seed)`.
    SignedBy(u8),
    /// Push an empty (0-byte) issuer signature — "no attestation".
    Empty,
    /// Push a 64-byte all-zero "signature" (parses, but never verifies).
    ZeroSig,
}

/// One transfer scenario. `honest()` yields a fully valid 1:1 transfer; each
/// adversarial test mutates exactly one lever.
#[derive(Clone)]
struct Cfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,
    owner_seed: u8,      // owner pubkey baked into the state header
    owner_sign_seed: u8, // key that actually produces owner_sig
    issuer_seed: u8,     // issuer pubkey baked into the body
    in_amount: u64,      // input native value (bound by the attestation)
    recipient_seed: u8,  // successor owner (its P2SH == the real output SPK)
    out_value: u64,      // successor output native value

    attest: AttestMode,
    // Overrides for the fields the issuer actually SIGNS over (None = truthful,
    // i.e. matching the real spend). A non-None value that disagrees with the
    // real spend is the substitution/replay/tamper being tested.
    msg_cov_id: Option<Hash>,
    msg_outpoint_txid_seed: Option<u8>,
    msg_outpoint_index: Option<u32>,
    msg_amount: Option<u64>,
    msg_successor_spk: Option<Vec<u8>>,
}

impl Cfg {
    fn honest() -> Self {
        Cfg {
            input_cov_id: hash32(0xC0),
            outpoint_txid_seed: 0x10,
            outpoint_index: 0,
            owner_seed: 1,
            owner_sign_seed: 1,
            issuer_seed: 2,
            in_amount: IN_AMOUNT,
            recipient_seed: 3,
            out_value: IN_AMOUNT,
            attest: AttestMode::SignedBy(2), // == issuer_seed
            msg_cov_id: None,
            msg_outpoint_txid_seed: None,
            msg_outpoint_index: None,
            msg_amount: None,
            msg_successor_spk: None,
        }
    }
}

struct Built {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

/// Assemble the push-only sigscript. The honest / 64-byte issuer-sig cases go
/// through the real WU-B builder under test; the empty-attestation freeze case
/// (a non-64-byte issuer push) is assembled by hand in the identical layout.
fn assemble_sigscript(owner_sig: &[u8; 64], issuer_sig: &[u8], rs: &[u8]) -> Vec<u8> {
    if let Ok(arr) = <[u8; 64]>::try_from(issuer_sig) {
        return build_stablecoin_sigscript(owner_sig, &arr, rs);
    }
    let mut owner_with_type = owner_sig.to_vec();
    owner_with_type.push(0x01);
    let mut ss = Vec::new();
    ss.extend_from_slice(&push_data(issuer_sig));
    ss.extend_from_slice(&push_data(&owner_with_type));
    ss.extend_from_slice(&push_data(rs));
    ss
}

fn build(cfg: &Cfg) -> Built {
    let owner_pub = pubkey(cfg.owner_seed);
    let issuer_pub = pubkey(cfg.issuer_seed);
    let rs = build_stablecoin_redeem_script(&owner_pub, &issuer_pub);
    let input_spk = build_p2sh(&rs);

    // 1:1 successor: the covenant reads the output at the SAME index as the
    // gated input (index 0). Bind it as a continuation of this covenant.
    let out_spk = successor_spk(cfg.recipient_seed, cfg.issuer_seed);
    let output =
        TransactionOutput::with_covenant(cfg.out_value, out_spk.clone(), Some(CovenantBinding::new(0, cfg.input_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.in_amount,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // --- Issuer attestation (off-chain "Writer" side) ---
    // Start from the truthful spend fields; apply any per-field override.
    let msg_cov = cfg.msg_cov_id.unwrap_or(cfg.input_cov_id);
    let msg_txid_seed = cfg.msg_outpoint_txid_seed.unwrap_or(cfg.outpoint_txid_seed);
    let msg_idx = cfg.msg_outpoint_index.unwrap_or(cfg.outpoint_index);
    let msg_amount = cfg.msg_amount.unwrap_or(cfg.in_amount);
    let msg_spk_bytes = cfg.msg_successor_spk.clone().unwrap_or_else(|| spk_to_bytes(&out_spk));

    let cov_bytes: [u8; 32] = msg_cov.as_bytes();
    let txid_bytes: [u8; 32] = [msg_txid_seed; 32];
    let attest_msg = build_attestation_message(&cov_bytes, &txid_bytes, msg_idx, &msg_spk_bytes, msg_amount);

    let issuer_sig: Vec<u8> = match cfg.attest {
        AttestMode::SignedBy(seed) => schnorr_sign(&attest_msg, &privkey(seed)).unwrap().to_vec(),
        AttestMode::Empty => Vec::new(),
        AttestMode::ZeroSig => vec![0u8; 64],
    };

    // --- Owner authorization (SIGHASH_ALL over the tx) ---
    // Compute the sighash on a skeleton with empty sig scripts (SIGHASH_ALL
    // does not commit the signature scripts), then assemble the real input.
    let skeleton_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), vec![], 0, 2);
    let skeleton_tx = Transaction::new(0, vec![skeleton_input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let populated_skeleton = PopulatedTransaction::new(&skeleton_tx, entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&populated_skeleton, 0, SIG_HASH_ALL, &reused);
    let owner_sig = schnorr_sign(&sighash.as_bytes(), &privkey(cfg.owner_sign_seed)).unwrap();

    let ss = assemble_sigscript(&owner_sig, &issuer_sig, &rs);
    // sig_op_count = 2: one OpCheckSigVerify (owner) + one OpCheckSigFromStack (issuer).
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
// 1. Happy path (freeze OFF) + conformance round-trip proof
// ============================================================================

#[test]
fn happy_freeze_off_accepts() {
    // A correctly owner-signed, correctly issuer-attested 1:1 transfer.
    //
    // That this passes on the real engine IS the conformance proof: the
    // issuer signed `build_attestation_message(...)` off-chain, and the body
    // recomputed the identical 32-byte msg_hash from transaction introspection
    // (covenant_id / outpoint / successor_spk_hash / amount) — if any field or
    // width disagreed, OpCheckSigFromStack would return false and OpVerify
    // would abort. Acceptance here means the off-chain and on-chain pre-images
    // are byte-identical.
    let res = run(&build(&Cfg::honest()));
    assert!(res.is_ok(), "honest attested transfer must be accepted: {res:?}");
}

// ============================================================================
// 2. Freeze (the whole point): missing / empty / forged issuer attestation
// ============================================================================

#[test]
fn freeze_no_attestation_empty_issuer_sig_rejected() {
    // No issuer signature at all (empty push). The engine cannot parse a
    // 0-byte Schnorr signature -> hard abort at OpCheckSigFromStack. This is
    // the freeze in its rawest form: without the issuer's fresh attestation,
    // the token simply cannot move.
    let cfg = Cfg { attest: AttestMode::Empty, ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "InvalidSignature");
}

#[test]
fn freeze_zero_issuer_sig_rejected() {
    // A well-formed-length (64B) but bogus all-zero signature parses, then
    // fails verification -> OpCheckSigFromStack pushes false -> OpVerify fails.
    let cfg = Cfg { attest: AttestMode::ZeroSig, ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn freeze_wrong_key_issuer_sig_rejected() {
    // A valid signature over the correct message, but from the WRONG key (not
    // the issuer baked into the body). Verification against the issuer's
    // x-only key fails -> OpVerify fails. Only the issuer can unfreeze.
    let cfg = Cfg { attest: AttestMode::SignedBy(9), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 3. Conformance: a single deliberately-shifted field must reject
// ============================================================================

#[test]
fn conformance_shifted_outpoint_index_in_attestation_rejected() {
    // The issuer attests to outpoint_index+1 while the input really spends
    // index 0. One field of drift -> recomputed msg_hash differs -> reject.
    // (Mirror image of the happy path's byte-exact success.)
    let cfg = Cfg { msg_outpoint_index: Some(1), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 4. Replay: an attestation minted for a different outpoint
// ============================================================================

#[test]
fn replay_attestation_for_other_outpoint_rejected() {
    // Issuer attested for outpoint X (txid seed 0x77), but the input actually
    // spends outpoint Y (txid seed 0x10). The on-chain OpOutpointTxId binds Y,
    // so the msg_hash differs and the X-attestation is worthless here.
    let cfg = Cfg { msg_outpoint_txid_seed: Some(0x77), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 5. Recipient substitution: attested successor != real successor
// ============================================================================

#[test]
fn recipient_substitution_rejected() {
    // Issuer attests to a successor SPK for recipient 7, but the real output
    // pays recipient 3. OpTxOutputSpk reads the REAL output at input index ->
    // successor_spk_hash mismatch -> reject.
    let attested_for_7 = spk_to_bytes(&successor_spk(7, 2));
    let cfg = Cfg { recipient_seed: 3, msg_successor_spk: Some(attested_for_7), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 6. Amount tamper: attested amount != input native value
// ============================================================================

#[test]
fn amount_tamper_rejected() {
    // Issuer attests to a different amount than the input's real native value.
    // OpTxInputAmount binds the true value -> mismatch -> reject.
    let cfg = Cfg { in_amount: IN_AMOUNT, out_value: IN_AMOUNT, msg_amount: Some(IN_AMOUNT + 1), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 7. Owner authorization: wrong signing key
// ============================================================================

#[test]
fn owner_wrong_key_rejected() {
    // Owner auth is signed by an unrelated key (seed 99), not the state's
    // owner_identifier (seed 1). OpCheckSigVerify fails before the attestation
    // is even considered.
    let cfg = Cfg { owner_seed: 1, owner_sign_seed: 99, ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 8. Cross-token: a covenant C1 attestation used on a C2 input
// ============================================================================

#[test]
fn cross_token_attestation_rejected() {
    // The input carries covenant_id C2; the issuer attestation was minted for
    // covenant_id C1. OpInputCovenantId binds C2 into the recomputed message,
    // so the C1 attestation does not verify. (An honest-in-every-other-respect
    // transfer, frozen purely by the covenant-id binding.)
    let c1 = hash32(0xC1);
    let c2 = hash32(0xC2);
    let cfg = Cfg { input_cov_id: c2, msg_cov_id: Some(c1), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 9. Sanity: the same transfer with the RIGHT covenant id is accepted
//    (guards against the freeze tests passing for an unrelated reason).
// ============================================================================

#[test]
fn cross_token_control_same_covenant_accepts() {
    // Identical shape to the cross-token case, but the attestation's covenant
    // id matches the input's. Must accept — proving the cross-token rejection
    // is specifically the covenant-id mismatch, not some incidental failure.
    let c2 = hash32(0xC2);
    let cfg = Cfg { input_cov_id: c2, msg_cov_id: Some(c2), ..Cfg::honest() };
    let res = run(&build(&cfg));
    assert!(res.is_ok(), "same-covenant attested transfer must be accepted: {res:?}");
}
