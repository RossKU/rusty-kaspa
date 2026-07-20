//! Mint-authority contract (`STABLECOIN_ROBUST_DESIGN.md` §9 "Mint + Supply
//! Cap") — both `MINT` (`op_type = 0x00`) and `RAISE_CAP` (`op_type = 0x01`)
//! exercised against the real post-Toccata `kaspa-txscript` `TxScriptEngine`
//! (`covenants_enabled = true`), in the same harness style as
//! `kob/core/tests/stablecoin_contracts.rs`.
//!
//! MINT section: this proves (1) the self-continuation D&R shape (mirroring
//! `spot::dca`'s D&R block via `crate::contract::dr`'s composable helpers)
//! actually authenticates `old_rs`/`new_rs` and enforces the running-supply
//! arithmetic + supply-cap invariants on the real engine; (2) the coin-shape
//! reconstruction (rebuilding the ENTIRE emitted stablecoin coin's
//! redeemScript on-chain from baked role constants) really pins the emitted
//! coin's shape, closing the "anti-backdoor" gap; and (3) the
//! recipient-binding security fix (`recipient_spk_hash` derived fresh from
//! the ACTUAL output[1] via introspection, never a separately-suppliable
//! claim) really closes the §9 replay gap where an attestation could be
//! redirected to a different recipient.
//!
//! RAISE_CAP section: this proves (1) the cold 2-of-3 `cap_authority`
//! threshold gates the branch (mirroring `stablecoin_contracts.rs`'s own
//! SEIZE 2-of-3 test shape); (2) `running_supply` is carried forward
//! byte-identical while `current_cap` is the only field allowed to change;
//! (3) the new ceiling must be a STRICT increase over the old one; (4) the
//! successor's `current_cap` must match the attested `new_cap` exactly; and
//! (5) no coin is emitted (self-continuation output only, at output[0]).

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
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

use kob_core::contract::stablecoin::body::build_stablecoin_redeem_script;
use kob_core::contract::stablecoin::mint_authority::attestation::{build_mint_attestation_message, build_raise_cap_attestation_message};
use kob_core::contract::stablecoin::mint_authority::body::{build_mint_authority_body, build_mint_authority_redeem_script};
use kob_core::contract::stablecoin::mint_authority::sigscript::{build_mint_authority_mint_sigscript, build_mint_authority_raise_cap_sigscript};
use kob_core::contract::stablecoin::mint_authority::state::MintAuthorityStateHeader;
use kob_core::contract::stablecoin::mint_authority::DOMAIN_TAG_MINT;
use kob_core::contract::stablecoin::state::frozen_flag;
use kob_core::contract::token::identifier_type as id_type;
use kob_core::{build_p2sh, get_public_key, schnorr_sign};

const IN_AMOUNT: u64 = 10_000;

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
/// `OpTxOutputSpk` pushes: the 2-byte big-endian version followed by the
/// script. Mirrors `stablecoin_contracts.rs`'s helper of the same name.
fn spk_to_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut v = spk.version().to_be_bytes().to_vec();
    v.extend_from_slice(spk.script());
    v
}

/// One MINT scenario. `honest()` yields a fully valid mint (running_supply
/// incremented by `mint_amount`, well under `current_cap`, emitting a
/// well-formed coin to `recipient_seed`); each adversarial test mutates
/// exactly one lever.
#[derive(Clone)]
struct MintCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,

    // Baked role constants (mint-authority + reconstructed stablecoin body).
    mint_seed: u8,
    cap_authority_seeds: [u8; 3],
    ops_seed: u8,
    freeze_seed: u8,
    seize_seeds: [u8; 3],
    role_registry_root: [u8; 32],
    identifier_type: u8,

    // This coin's own current mutable state.
    running_supply: u64,
    current_cap: u64,

    // The mint itself.
    mint_amount: u64,
    recipient_seed: u8,

    // Mint-authority contract's own operating balance (not a token value;
    // see the final report's design-ambiguity note on value continuity).
    self_in_value: u64,
    self_out_value: u64,

    // Successor (new_rs) overrides. `None` == carried forward honestly.
    successor_running_supply: Option<u64>, // None == running_supply + mint_amount
    successor_cap: Option<u64>,            // None == current_cap (unchanged)
    successor_ops_seed: Option<u8>,        // None == ops_seed (tampers the baked body/suffix)

    // Emitted coin (output[1]) shape overrides -- malform the ACTUAL coin
    // relative to what the mint-authority's own baked constants expect.
    coin_role_root: Option<[u8; 32]>, // None == role_registry_root
    coin_frozen_flag: Option<u8>,     // None == frozen_flag::CLEAR
    coin_epoch: Option<u32>,          // None == 0

    // Output[1] native value actually placed in the tx (None == mint_amount).
    output_amount_override: Option<u64>,

    // What the MINT attestation actually signs over/is produced by (None
    // levers == honest/matching the real spend).
    attest_recipient_seed: u8, // recipient whose coin-spk mint_sig is signed for (honest == recipient_seed)
    attest_mint_seed: u8,      // key that actually produces mint_sig (honest == mint_seed)

    // Raw override for the sigscript's recipient_pubkey push (SUB-FIX A
    // regression). None == the real 32-byte recipient_pub (honest). Lets
    // `mint_oversized_recipient_rejected` push a >32-byte value in that slot,
    // which `MintCfg`'s normal `recipient_seed: u8` (always a real 32-byte
    // key) can't express.
    sigscript_recipient_bytes_override: Option<Vec<u8>>,

    // Genesis covenant_id G baked into BOTH old_rs and new_rs (SUB-FIX B).
    // None == honest/matching: G == input_cov_id (the UTXO entry's real,
    // consensus-tracked covenant_id) -- i.e. a genuine authority whose own
    // genesis this is. `genesis_covenant_id_mismatch_rejected` sets this to
    // an arbitrary DIFFERENT value, simulating a fake parallel authority
    // deployment that bakes the same public role keys but a different
    // genesis.
    baked_genesis_cov_id: Option<[u8; 32]>,
}

impl MintCfg {
    fn honest() -> Self {
        MintCfg {
            input_cov_id: hash32(0xA0),
            outpoint_txid_seed: 0x30,
            outpoint_index: 0,
            mint_seed: 21,
            cap_authority_seeds: [70, 71, 72],
            ops_seed: 22,
            freeze_seed: 23,
            seize_seeds: [24, 25, 26],
            role_registry_root: [0xEE; 32],
            identifier_type: id_type::PUBKEY,
            running_supply: 10_000,
            current_cap: 1_000_000,
            mint_amount: 50_000,
            recipient_seed: 30,
            self_in_value: IN_AMOUNT,
            self_out_value: IN_AMOUNT,
            successor_running_supply: None,
            successor_cap: None,
            successor_ops_seed: None,
            coin_role_root: None,
            coin_frozen_flag: None,
            coin_epoch: None,
            output_amount_override: None,
            attest_recipient_seed: 30, // == recipient_seed
            attest_mint_seed: 21,      // == mint_seed
            sigscript_recipient_bytes_override: None,
            baked_genesis_cov_id: None,
        }
    }
}

struct Built {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

fn build(cfg: &MintCfg) -> Built {
    let mint_pub = pubkey(cfg.mint_seed);
    let cap_pubs = [pubkey(cfg.cap_authority_seeds[0]), pubkey(cfg.cap_authority_seeds[1]), pubkey(cfg.cap_authority_seeds[2])];
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = [pubkey(cfg.seize_seeds[0]), pubkey(cfg.seize_seeds[1]), pubkey(cfg.seize_seeds[2])];

    // Genesis covenant_id G baked into this authority (SUB-FIX B). Honest ==
    // matches the UTXO entry's real covenant_id (`cfg.input_cov_id`) below --
    // i.e. this really is that genesis's authority.
    let genesis_cov_id: [u8; 32] = cfg.baked_genesis_cov_id.unwrap_or_else(|| cfg.input_cov_id.as_bytes());

    let old_rs = build_mint_authority_redeem_script(
        cfg.running_supply,
        cfg.current_cap,
        &mint_pub,
        &cap_pubs,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
    );
    let input_spk = build_p2sh(&old_rs);

    let honest_new_running_supply = cfg.running_supply + cfg.mint_amount;
    let new_running_supply = cfg.successor_running_supply.unwrap_or(honest_new_running_supply);
    let successor_cap = cfg.successor_cap.unwrap_or(cfg.current_cap);
    let successor_ops_pub = cfg.successor_ops_seed.map(pubkey).unwrap_or(ops_pub);
    let new_rs = build_mint_authority_redeem_script(
        new_running_supply,
        successor_cap,
        &mint_pub,
        &cap_pubs,
        &successor_ops_pub,
        &freeze_pub,
        &seize_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
    );
    let self_out_spk = build_p2sh(&new_rs);

    // The ACTUAL emitted coin (output[1]).
    let recipient_pub = pubkey(cfg.recipient_seed);
    let coin_role_root = cfg.coin_role_root.unwrap_or(cfg.role_registry_root);
    let coin_frozen_flag = cfg.coin_frozen_flag.unwrap_or(frozen_flag::CLEAR);
    let coin_epoch = cfg.coin_epoch.unwrap_or(0);
    let coin_rs = build_stablecoin_redeem_script(
        &recipient_pub,
        cfg.identifier_type,
        &coin_role_root,
        coin_frozen_flag,
        coin_epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub, // mint_pubkey reused as the stablecoin covenant's own MINT-role key
    );
    let coin_spk = build_p2sh(&coin_rs);
    let output_amount = cfg.output_amount_override.unwrap_or(cfg.mint_amount);

    // Self-continuation output (index 0): continuation case -- same
    // covenant_id as the spent input.
    let self_output = TransactionOutput::with_covenant(cfg.self_out_value, self_out_spk, Some(CovenantBinding::new(0, cfg.input_cov_id)));

    // Emitted-coin output (index 1): genesis case -- its covenant_id MUST be
    // the recomputed genesis id (`CovenantsContext::from_tx` validates this
    // against the authorizing input's outpoint + this exact output).
    let mint_outpoint = outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index);
    let coin_output_bare = TransactionOutput::new(output_amount, coin_spk.clone());
    let coin_cov_id =
        kaspa_consensus_core::hashing::covenant_id::covenant_id(mint_outpoint, std::iter::once((1u32, &coin_output_bare)));
    let coin_output = TransactionOutput::with_covenant(output_amount, coin_spk.clone(), Some(CovenantBinding::new(0, coin_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.self_in_value,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // --- MINT attestation (off-chain "Writer" side) ---
    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let txid_bytes: [u8; 32] = [cfg.outpoint_txid_seed; 32];
    // The coin the signer believes they are attesting for -- honest ==
    // recipient_seed's real coin (attest_recipient_seed lets the
    // recipient-swap-replay test sign for a DIFFERENT recipient's coin while
    // the tx actually emits to cfg.recipient_seed).
    let attest_recipient_pub = pubkey(cfg.attest_recipient_seed);
    let attest_coin_rs = build_stablecoin_redeem_script(
        &attest_recipient_pub,
        cfg.identifier_type,
        &coin_role_root,
        coin_frozen_flag,
        coin_epoch,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &mint_pub,
    );
    let attest_coin_spk = build_p2sh(&attest_coin_rs);
    let attest_recipient_spk_bytes = spk_to_bytes(&attest_coin_spk);

    let msg = build_mint_attestation_message(&cov_bytes, &txid_bytes, cfg.outpoint_index, cfg.mint_amount, new_running_supply, &attest_recipient_spk_bytes);
    let mint_sig: [u8; 64] = schnorr_sign(&msg, &privkey(cfg.attest_mint_seed)).unwrap();

    let sigscript_recipient: Vec<u8> = cfg.sigscript_recipient_bytes_override.clone().unwrap_or_else(|| recipient_pub.to_vec());
    // Real-engine proof that the sigscript builder produces engine-accepted
    // bytes: this is the same builder `kob_core::contract::stablecoin::mint_authority::sigscript`
    // ships (mint_sig deepest, then old_rs, then new_rs, then
    // mint_amount(8B LE), then recipient_pubkey, then the op_type_selector
    // (0x00), then the redeem script last).
    let ss = build_mint_authority_mint_sigscript(&mint_sig, &old_rs, &new_rs, cfg.mint_amount, &sigscript_recipient, &old_rs);
    // sig_op_count = 1: a single OpCheckSigFromStack (MINT role); no owner sig.
    let final_input = TransactionInput::new(mint_outpoint, ss, 0, 1);
    let tx = Transaction::new(0, vec![final_input], vec![self_output, coin_output], 0, Default::default(), 0, vec![]);
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
/// verification failure (its Debug rendering contains `needle`), not a
/// generic parse / stack error.
fn assert_rejected_with(res: &Result<(), String>, needle: &str) {
    match res {
        Ok(()) => panic!("expected reject via {needle}, but the MINT was ACCEPTED"),
        Err(e) => assert!(e.contains(needle), "expected reject via `{needle}`, got a different failure: {e}"),
    }
}

// ============================================================================
// 1. Happy path + conformance round-trip proof
// ============================================================================

#[test]
fn mint_accepts() {
    // A correctly MINT-attested spend: running_supply incremented by exactly
    // mint_amount, current_cap carried forward unchanged, the emitted coin's
    // shape reconstructed on-chain matches the actual output[1], and the
    // recipient is bound. That this passes on the real engine IS the
    // round-trip proof: the MINT role signed
    // build_mint_attestation_message(...) off-chain, and the body
    // recomputed the identical 32-byte msg_hash from transaction
    // introspection (covenant_id / outpoint / mint_amount / new_running_supply /
    // recipient_spk_hash) -- if any field or width disagreed,
    // OpCheckSigFromStack would return false and OpVerify would abort.
    let res = run(&build(&MintCfg::honest()));
    assert!(res.is_ok(), "honest attested MINT must be accepted: {res:?}");
}

// ============================================================================
// 2. MINT adversarial batch
// ============================================================================

#[test]
fn mint_at_cap_boundary_accepts() {
    // new_running_supply == current_cap exactly must be ACCEPTED (the cap
    // check is <=, not <).
    let mut cfg = MintCfg::honest();
    cfg.current_cap = cfg.running_supply + cfg.mint_amount;
    let res = run(&build(&cfg));
    assert!(res.is_ok(), "MINT landing exactly on the supply cap must be accepted: {res:?}");
}

#[test]
fn mint_over_cap_rejected() {
    // new_running_supply == current_cap + 1 must be REJECTED.
    let mut cfg = MintCfg::honest();
    cfg.current_cap = cfg.running_supply + cfg.mint_amount - 1;
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_wrong_mint_key_rejected() {
    // A structurally valid signature over the CORRECT message, but from the
    // WRONG key (not the MINT key baked into the body).
    let cfg = MintCfg { attest_mint_seed: 99, ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_supply_not_incremented_rejected() {
    // The successor's embedded running_supply disagrees with
    // old_running_supply + mint_amount (independently re-derived on-chain) --
    // must be rejected regardless of what the attestation claims.
    let honest = MintCfg::honest();
    let cfg = MintCfg { successor_running_supply: Some(honest.running_supply + honest.mint_amount + 1), ..honest };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_current_cap_altered_rejected() {
    // The successor's current_cap differs from this coin's own -- MINT must
    // carry current_cap forward unchanged (only the stubbed RAISE_CAP op may
    // rewrite it).
    let honest = MintCfg::honest();
    let cfg = MintCfg { successor_cap: Some(honest.current_cap + 1), ..honest };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_emitted_coin_malformed_rejected() {
    // The actual emitted coin (output[1]) disagrees with the on-chain
    // reconstruction (which always assumes the baked role_registry_root,
    // frozen_flag == 0, epoch == 0) -- three independent single-lever
    // variants, each must be rejected.
    let root_cfg = MintCfg { coin_role_root: Some([0xFFu8; 32]), ..MintCfg::honest() };
    assert_rejected_with(&run(&build(&root_cfg)), "VerifyError");

    let frozen_cfg = MintCfg { coin_frozen_flag: Some(frozen_flag::SET), ..MintCfg::honest() };
    assert_rejected_with(&run(&build(&frozen_cfg)), "VerifyError");

    let epoch_cfg = MintCfg { coin_epoch: Some(1), ..MintCfg::honest() };
    assert_rejected_with(&run(&build(&epoch_cfg)), "VerifyError");
}

#[test]
fn mint_output_amount_mismatch_rejected() {
    // output[1]'s actual native value disagrees with the attested
    // mint_amount.
    let honest = MintCfg::honest();
    let cfg = MintCfg { output_amount_override: Some(honest.mint_amount + 1), ..honest };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_recipient_swap_replay_rejected() {
    // Security-fix regression test: the MINT attestation is genuinely valid
    // -- but signed for a DIFFERENT recipient (seed 31) than the one the tx
    // actually mints to (seed 30, Cfg::honest()'s recipient_seed). The
    // coin-shape reconstruction (Step 8) independently passes (the actual
    // output[1] is genuinely, self-consistently, recipient 30's coin), so
    // WITHOUT the recipient-binding fix this replay would otherwise succeed
    // -- recipient_spk_hash being derived fresh from the ACTUAL output[1]
    // means the recomputed message disagrees with what was signed, and
    // OpCheckSigFromStack must reject.
    let cfg = MintCfg { attest_recipient_seed: 31, ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_baked_body_tampered_rejected() {
    // Any baked field changed in the successor (here: ops_pubkey, which
    // feeds into the embedded `fixed_mid` blob) changes the successor's
    // ENTIRE body bytes -- the suffix check (covering current_cap + the
    // whole baked body as one contiguous region) must catch this.
    let cfg = MintCfg { successor_ops_seed: Some(199), ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn genesis_covenant_id_mismatch_rejected() {
    // SUB-FIX B regression: this authority bakes a genesis covenant_id G that
    // does NOT match the spending input's ACTUAL, consensus-tracked
    // covenant_id -- simulating a fake parallel authority deployment that
    // baked the SAME PUBLIC mint_pubkey/role constants (public keys aren't
    // secrets) but a DIFFERENT genesis. Before this fix, nothing checked
    // covenant_id against a fixed baked value at all (it was only folded into
    // the attestation message, which the honest mint_pubkey holder can sign
    // for ANY covenant_id), so this scenario would have been ACCEPTED.
    // Everything else about this spend is honest (the attestation genuinely
    // matches this transaction's real fields) -- only the baked G disagrees
    // with the input's real covenant_id.
    let cfg = MintCfg { baked_genesis_cov_id: Some([0xFEu8; 32]), ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_oversized_recipient_rejected() {
    // SUB-FIX A regression: pre-fix, the spender-supplied recipient_pubkey
    // was OpCat'd directly after the fixed `[0x20]` owner_pubkey push opcode
    // with NO length check -- an oversized recipient push would inject extra,
    // attacker-chosen bytes into the emitted coin's reconstructed
    // redeemScript past the intended 32-byte owner_pubkey field (a
    // governance-less backdoor coin, since everything after that field is
    // otherwise a build-time constant). `MintCfg`'s normal recipient lever is
    // always a real 32-byte pubkey, so this test hand-rolls a 33-byte
    // (one-byte-over) push in the same sigscript slot via
    // `sigscript_recipient_bytes_override`, leaving a genuinely valid
    // mint_sig and an honest output[1] untouched -- isolating exactly the new
    // OpSize/OpNumEqual length check (every earlier step in the branch --
    // self-continuation, supply arithmetic, supply-cap -- is satisfied by the
    // honest baseline, so this is the first check the oversized push hits).
    let mut oversized_recipient = pubkey(30).to_vec(); // honest recipient's real 32B key...
    oversized_recipient.push(0xAA); // ...plus one extra byte -> 33B.
    assert_eq!(oversized_recipient.len(), 33);
    let cfg = MintCfg { sigscript_recipient_bytes_override: Some(oversized_recipient), ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_authority_output_value_drained_rejected() {
    // SUB-FIX D regression: pre-fix, output[0]'s (the self-continuation
    // successor's) native value was never pinned to the spending input's
    // native value -- MINT's authorization is a single OpCheckSigFromStack
    // over the hot mint_pubkey (no owner SIGHASH_ALL signature at all, so
    // nothing else in the branch commits to every output's amount), so a hot
    // mint_pubkey holder could quietly drain the authority UTXO's operating
    // balance on every honest mint. Everything else about this spend is
    // honest (correct supply arithmetic, correct coin emission, valid
    // attestation) -- only self_out_value is shaved by 1 sompi below
    // self_in_value, isolating exactly the new value-continuity check.
    let honest = MintCfg::honest();
    let cfg = MintCfg { self_out_value: honest.self_in_value - 1, ..honest };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 3. RAISE_CAP (`op_type = 0x01`) -- happy path + adversarial batch.
//    Authorization is a cold 2-of-3 threshold over the three baked
//    `cap_authority_pubkeys` (the SAME fixed-position `OpCheckSigFromStack`
//    idiom `build_seize_branch` uses, `core/src/contract/stablecoin/body.rs`
//    -- see `stablecoin_contracts.rs`'s own SEIZE section). No `mint_pubkey`/
//    owner involvement at all. The successor must carry `running_supply`
//    forward UNCHANGED, `current_cap` strictly increased to exactly the
//    attested `new_cap`, and the baked body unchanged; RAISE_CAP emits NO
//    coin (self-continuation output only, at output[0]).
// ============================================================================

/// A 64-byte value that is NOT a signature from any of the three baked
/// `cap_authority` keys -- stands in for "no signature supplied" in a fixed
/// positional slot, mirroring `stablecoin_contracts.rs`'s `SEIZE_GARBAGE_SIG`.
const RAISE_CAP_GARBAGE_SIG: [u8; 64] = [0u8; 64];

/// One RAISE_CAP scenario. `honest()` yields a fully valid 3-of-3-signed cap
/// raise (running_supply unchanged, current_cap strictly increased to
/// exactly the attested new_cap); each adversarial test mutates exactly one
/// lever.
#[derive(Clone)]
struct RaiseCapCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,

    // Baked role constants (mint-authority + reconstructed stablecoin body;
    // the stablecoin-side ones are irrelevant to RAISE_CAP itself but still
    // baked into the body/P2SH).
    mint_seed: u8,
    cap_authority_seeds: [u8; 3],
    ops_seed: u8,
    freeze_seed: u8,
    seize_seeds: [u8; 3],
    role_registry_root: [u8; 32],
    identifier_type: u8,

    // This coin's own current mutable state.
    running_supply: u64,
    current_cap: u64,

    // The raise itself: the new ceiling both pushed via the sigscript and
    // folded into the attested pre-image.
    new_cap: u64,

    // Mint-authority contract's own operating balance (not a token value).
    self_in_value: u64,
    self_out_value: u64,

    // Successor (new_rs) overrides. `None` == carried forward honestly.
    successor_running_supply: Option<u64>, // None == running_supply (unchanged)
    successor_cap: Option<u64>,            // None == new_cap (the honest raise)
    successor_ops_seed: Option<u8>,        // None == ops_seed (tampers the baked body/suffix)

    // What the RAISE_CAP attestation actually signs the outpoint txid as
    // (None == truthful, matching the real spend). A disagreeing value is
    // the replay being tested.
    attest_outpoint_txid_seed: Option<u8>,

    // Which seed actually signs each of the 3 fixed sigscript slots
    // (`Some(seed)`) vs. an arbitrary non-signature placeholder (`None`).
    // Honest == all three slots signed by `cap_authority_seeds` in order.
    signer_seeds: [Option<u8>; 3],

    // Genesis covenant_id G baked into BOTH old_rs and new_rs (SUB-FIX B).
    // None == honest/matching: G == input_cov_id.
    baked_genesis_cov_id: Option<[u8; 32]>,
}

impl RaiseCapCfg {
    fn honest() -> Self {
        RaiseCapCfg {
            input_cov_id: hash32(0xC0),
            outpoint_txid_seed: 0x50,
            outpoint_index: 0,
            mint_seed: 21,
            cap_authority_seeds: [70, 71, 72],
            ops_seed: 22,
            freeze_seed: 23,
            seize_seeds: [24, 25, 26],
            role_registry_root: [0xEE; 32],
            identifier_type: id_type::PUBKEY,
            running_supply: 10_000,
            current_cap: 1_000_000,
            new_cap: 2_000_000,
            self_in_value: IN_AMOUNT,
            self_out_value: IN_AMOUNT,
            successor_running_supply: None,
            successor_cap: None,
            successor_ops_seed: None,
            attest_outpoint_txid_seed: None,
            signer_seeds: [Some(70), Some(71), Some(72)], // all 3 of cap_authority_seeds
            baked_genesis_cov_id: None,
        }
    }
}

/// Build a RAISE_CAP scenario.
fn build_raise_cap(cfg: &RaiseCapCfg) -> Built {
    let mint_pub = pubkey(cfg.mint_seed);
    let cap_pubs = [pubkey(cfg.cap_authority_seeds[0]), pubkey(cfg.cap_authority_seeds[1]), pubkey(cfg.cap_authority_seeds[2])];
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = [pubkey(cfg.seize_seeds[0]), pubkey(cfg.seize_seeds[1]), pubkey(cfg.seize_seeds[2])];

    // Genesis covenant_id G baked into this authority (SUB-FIX B). Honest ==
    // matches the UTXO entry's real covenant_id (`cfg.input_cov_id`) below.
    let genesis_cov_id: [u8; 32] = cfg.baked_genesis_cov_id.unwrap_or_else(|| cfg.input_cov_id.as_bytes());

    let old_rs = build_mint_authority_redeem_script(
        cfg.running_supply,
        cfg.current_cap,
        &mint_pub,
        &cap_pubs,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
    );
    let input_spk = build_p2sh(&old_rs);

    // 1:1 successor: running_supply carried forward UNCHANGED (unless a test
    // overrides it), current_cap raised to new_cap (unless a test overrides
    // it), the baked body untouched (unless a test overrides ops_pubkey to
    // probe the suffix check).
    let successor_running_supply = cfg.successor_running_supply.unwrap_or(cfg.running_supply);
    let successor_cap = cfg.successor_cap.unwrap_or(cfg.new_cap);
    let successor_ops_pub = cfg.successor_ops_seed.map(pubkey).unwrap_or(ops_pub);
    let new_rs = build_mint_authority_redeem_script(
        successor_running_supply,
        successor_cap,
        &mint_pub,
        &cap_pubs,
        &successor_ops_pub,
        &freeze_pub,
        &seize_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
    );
    let self_out_spk = build_p2sh(&new_rs);

    // Self-continuation output (index 0): continuation case -- same
    // covenant_id as the spent input. RAISE_CAP emits NO other output.
    let self_output = TransactionOutput::with_covenant(cfg.self_out_value, self_out_spk, Some(CovenantBinding::new(0, cfg.input_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.self_in_value,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // --- RAISE_CAP quorum attestation (off-chain "Writer" side) ---
    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let msg_txid_seed = cfg.attest_outpoint_txid_seed.unwrap_or(cfg.outpoint_txid_seed);
    let txid_bytes: [u8; 32] = [msg_txid_seed; 32];
    let attest_msg = build_raise_cap_attestation_message(&cov_bytes, &txid_bytes, cfg.outpoint_index, cfg.new_cap);

    let sig_for = |slot: usize| -> [u8; 64] {
        match cfg.signer_seeds[slot] {
            Some(seed) => schnorr_sign(&attest_msg, &privkey(seed)).unwrap(),
            None => RAISE_CAP_GARBAGE_SIG,
        }
    };
    let sig1 = sig_for(0);
    let sig2 = sig_for(1);
    let sig3 = sig_for(2);

    // No mint_pubkey/owner authorization at all -- the cap_authority 2-of-3
    // quorum gates alone (§9). Real-engine proof that the sigscript builder
    // produces engine-accepted bytes: this is the same builder
    // `kob_core::contract::stablecoin::mint_authority::sigscript` ships
    // (sig1 deepest, then sig2, then sig3, then old_rs, then new_rs, then
    // new_cap(8B LE), then the op_type_selector (0x01), then the redeem
    // script last).
    let ss = build_mint_authority_raise_cap_sigscript(&sig1, &sig2, &sig3, &old_rs, &new_rs, cfg.new_cap, &old_rs);
    // sig_op_count = 3: three OpCheckSigFromStack calls (2-of-3 cap_authority
    // quorum).
    let final_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), ss, 0, 3);
    let tx = Transaction::new(0, vec![final_input], vec![self_output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

#[test]
fn raise_cap_2of3_accepts() {
    // Exactly 2 of the 3 cap_authority signature slots genuinely signed
    // (the third is an arbitrary placeholder): the summed threshold is
    // exactly 2, which must be ACCEPTED. running_supply is carried forward
    // unchanged, current_cap strictly increases to exactly the attested
    // new_cap, and the tx emits no coin. That this passes on the real engine
    // IS the round-trip proof: two of the three cap_authority signers signed
    // `build_raise_cap_attestation_message(...)` off-chain, and the body
    // recomputed the identical 32-byte msg_hash from transaction
    // introspection.
    let cfg = RaiseCapCfg { signer_seeds: [Some(70), Some(71), None], ..RaiseCapCfg::honest() };
    let res = run(&build_raise_cap(&cfg));
    assert!(res.is_ok(), "honest 2-of-3 RAISE_CAP must be accepted: {res:?}");
}

#[test]
fn raise_cap_3of3_accepts() {
    // All three cap_authority signers sign -- a full quorum trivially clears
    // the 2-of-3 threshold and must also be accepted.
    let res = run(&build_raise_cap(&RaiseCapCfg::honest()));
    assert!(res.is_ok(), "honest 3-of-3 RAISE_CAP must be accepted: {res:?}");
}

#[test]
fn raise_cap_1of3_insufficient_rejected() {
    // Only ONE of the three signature slots is genuinely signed by a baked
    // cap_authority key; the other two are arbitrary placeholders. The
    // summed threshold (1) is below the required 2-of-3, so the branch must
    // reject even though the single supplied signature is perfectly valid.
    let cfg = RaiseCapCfg { signer_seeds: [Some(70), None, None], ..RaiseCapCfg::honest() };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_wrong_keys_rejected() {
    // All three signature slots are genuine, correctly-formed signatures
    // over the correct attested message, but from keys that are NOT among
    // the three baked cap_authority pubkeys -- including the hot
    // mint_pubkey, which must NOT be able to substitute for the cold
    // cap_authority quorum (§9: "NO mint_pubkey/owner involvement").
    let cfg = RaiseCapCfg { signer_seeds: [Some(RaiseCapCfg::honest().mint_seed), Some(91), Some(92)], ..RaiseCapCfg::honest() };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_not_strictly_increased_rejected() {
    // new_cap == current_cap (no-op "raise") must be rejected -- RAISE_CAP
    // requires a STRICT increase.
    let honest = RaiseCapCfg::honest();
    let eq_cfg = RaiseCapCfg { new_cap: honest.current_cap, ..honest.clone() };
    assert_rejected_with(&run(&build_raise_cap(&eq_cfg)), "VerifyError");

    // new_cap < current_cap (an attempted lowering) must also be rejected --
    // nothing ever decreases the cap (§9).
    let lower_cfg = RaiseCapCfg { new_cap: honest.current_cap - 1, ..honest };
    assert_rejected_with(&run(&build_raise_cap(&lower_cfg)), "VerifyError");
}

#[test]
fn raise_cap_running_supply_altered_rejected() {
    // The successor's embedded running_supply disagrees with this coin's own
    // -- RAISE_CAP must carry running_supply forward UNCHANGED (only MINT
    // may increment it).
    let honest = RaiseCapCfg::honest();
    let cfg = RaiseCapCfg { successor_running_supply: Some(honest.running_supply + 1), ..honest };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_new_cap_mismatch_attestation_rejected() {
    // The cap_authority quorum genuinely attested (and the sigscript
    // genuinely pushes) new_cap = 2_000_000, but the successor's ACTUAL
    // current_cap field is a DIFFERENT value -- a captured, honestly-signed
    // raise-attestation replayed against a successor that doesn't actually
    // carry the attested ceiling. The on-chain successor-current_cap
    // equality check must reject this independently of the 2-of-3 signature
    // check succeeding.
    let honest = RaiseCapCfg::honest();
    let cfg = RaiseCapCfg { successor_cap: Some(honest.new_cap + 1), ..honest };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_baked_body_tampered_rejected() {
    // Any baked field changed in the successor (here: ops_pubkey, which
    // feeds into the baked body bytes) changes the successor's ENTIRE body
    // -- the suffix check (covering the whole baked body region, excluding
    // only current_cap) must catch this.
    let cfg = RaiseCapCfg { successor_ops_seed: Some(199), ..RaiseCapCfg::honest() };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_genesis_covenant_id_mismatch_rejected() {
    // SUB-FIX B regression (RAISE_CAP side): same fake-parallel-authority
    // scenario as `genesis_covenant_id_mismatch_rejected`, but exercising the
    // RAISE_CAP branch's own baked-G check -- a fake authority sharing the
    // real one's cap_authority_pubkeys (public keys) but a different genesis
    // must not be able to raise its own cap either.
    let cfg = RaiseCapCfg { baked_genesis_cov_id: Some([0xFEu8; 32]), ..RaiseCapCfg::honest() };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_output_value_drained_rejected() {
    // SUB-FIX D regression: pre-fix, output[0]'s native value was never
    // pinned to the spending input's native value -- RAISE_CAP's
    // authorization is a cold 2-of-3 cap_authority quorum via
    // OpCheckSigFromStack (no owner SIGHASH_ALL signature either), so nothing
    // else in the branch committed to every output's amount. A cap_authority
    // holder could drain the authority UTXO's operating balance while
    // raising the cap. Everything else about this spend is honest -- only
    // self_out_value is shaved by 1 sompi below self_in_value.
    let honest = RaiseCapCfg::honest();
    let cfg = RaiseCapCfg { self_out_value: honest.self_in_value - 1, ..honest };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_replay_other_outpoint_rejected() {
    // The cap_authority quorum attested for outpoint txid seed 0x77, but the
    // input actually spends the outpoint with txid seed 0x50 (honest()'s
    // default). The on-chain OpOutpointTxId binds the REAL spend, so the
    // recomputed msg_hash differs from what was signed -- the 0x77
    // attestation's signatures fail to verify against it (replay
    // protection).
    let cfg = RaiseCapCfg { attest_outpoint_txid_seed: Some(0x77), ..RaiseCapCfg::honest() };
    let res = run(&build_raise_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn raise_cap_new_cap_at_or_above_2pow63_rejected() {
    // SUB-FIX E on-chain regression, PLUS this module's exploitability
    // finding (see the final report for the full writeup): the literal DoS
    // this audit finding named -- RAISE_CAP jumping `current_cap` to >= 2^63
    // to permanently brick MINT's `new_supply <= current_cap` check -- turns
    // out NOT to be reachable via a single strict-increase RAISE_CAP call in
    // the first place. Kaspa script numbers are sign-magnitude LE; a raw
    // 8-byte encoding of exactly `1u64 << 63` has its sign bit set with a
    // ZERO magnitude, so the engine's arithmetic decodes it as script-number
    // `0` -- Step 7's PRE-EXISTING strict `new_cap > current_cap` check
    // already rejects that (`0` is never greater than a sane positive
    // `current_cap`). This test proves the transaction is rejected either
    // way: the NEW Step 0b bound check (`new_cap >= 0`) actually lets this
    // *specific* boundary value THROUGH (it also decodes to `0`, which is
    // `>= 0` -- an inherent sign-magnitude aliasing between "raw 2^63" and
    // "raw 0" that no purely-numeric on-chain check can resolve), so it is
    // Step 7 that ends up rejecting it here; Step 0b's own added value is
    // rejecting the wider (2^63, 2^64) range where the decoded magnitude is
    // nonzero (confirmed separately while developing this fix, by disabling
    // Step 7 and observing Step 0b alone reject those values -- not asserted
    // here since Step 7 cannot be selectively disabled from this harness).
    //
    // Hand-rolled rather than routed through `build_raise_cap`/
    // `build_raise_cap_attestation_message`/`MintAuthorityStateHeader::new`:
    // those now debug_assert this exact numeric domain (SUB-FIX E's
    // off-chain half, `check_numeric_domain`) -- a real attacker never calls
    // any Rust helper at all, they craft the raw wire bytes directly, which
    // is what this test reproduces by constructing `MintAuthorityStateHeader`
    // via its public fields directly and hand-building the RAISE_CAP
    // attestation preimage.
    let input_cov_id = hash32(0xC7);
    let outpoint_txid_seed = 0x59u8;
    let outpoint_index = 0u32;
    let mint_seed = 21u8;
    let cap_authority_seeds = [70u8, 71, 72];
    let ops_seed = 22u8;
    let freeze_seed = 23u8;
    let seize_seeds = [24u8, 25, 26];
    let role_registry_root = [0xEEu8; 32];
    let identifier_type = id_type::PUBKEY;
    let running_supply = 10_000u64;
    let current_cap = 1_000_000u64;
    let new_cap_raw: u64 = 1u64 << 63;

    let mint_pub = pubkey(mint_seed);
    let cap_pubs = [pubkey(cap_authority_seeds[0]), pubkey(cap_authority_seeds[1]), pubkey(cap_authority_seeds[2])];
    let ops_pub = pubkey(ops_seed);
    let freeze_pub = pubkey(freeze_seed);
    let seize_pubs = [pubkey(seize_seeds[0]), pubkey(seize_seeds[1]), pubkey(seize_seeds[2])];
    let genesis_cov_id: [u8; 32] = input_cov_id.as_bytes(); // honest: G == this UTXO's real covenant_id

    let old_rs = build_mint_authority_redeem_script(
        running_supply, current_cap, &mint_pub, &cap_pubs, &ops_pub, &freeze_pub, &seize_pubs, &role_registry_root, identifier_type, &genesis_cov_id,
    );
    let input_spk = build_p2sh(&old_rs);

    // new_rs: running_supply carried forward unchanged, current_cap set to
    // the raw 2^63 pattern under test -- constructed directly via
    // `MintAuthorityStateHeader`'s public fields, bypassing `new`'s
    // debug_assert (mirrors a real attacker crafting raw wire bytes).
    let new_state = MintAuthorityStateHeader { running_supply, current_cap: new_cap_raw };
    let mut new_rs = new_state.encode_script();
    new_rs.extend_from_slice(&build_mint_authority_body(&mint_pub, &cap_pubs, &ops_pub, &freeze_pub, &seize_pubs, &role_registry_root, identifier_type, &genesis_cov_id));
    let self_out_spk = build_p2sh(&new_rs);

    let self_output = TransactionOutput::with_covenant(IN_AMOUNT, self_out_spk, Some(CovenantBinding::new(0, input_cov_id)));
    let entries = vec![UtxoEntry {
        amount: IN_AMOUNT,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(input_cov_id),
    }];

    // Hand-rolled 84B RAISE_CAP attestation preimage (bypasses
    // `build_raise_cap_attestation_message`'s debug_assert on `new_cap`).
    let cov_bytes: [u8; 32] = input_cov_id.as_bytes();
    let txid_bytes: [u8; 32] = [outpoint_txid_seed; 32];
    let mut preimage = Vec::with_capacity(84);
    preimage.extend_from_slice(&DOMAIN_TAG_MINT);
    preimage.extend_from_slice(&cov_bytes);
    preimage.extend_from_slice(&txid_bytes);
    preimage.extend_from_slice(&outpoint_index.to_le_bytes());
    preimage.extend_from_slice(&new_cap_raw.to_le_bytes());
    assert_eq!(preimage.len(), 84);
    let attest_msg: [u8; 32] = *blake3::hash(&preimage).as_bytes();

    let sig1 = schnorr_sign(&attest_msg, &privkey(cap_authority_seeds[0])).unwrap();
    let sig2 = schnorr_sign(&attest_msg, &privkey(cap_authority_seeds[1])).unwrap();
    let sig3 = schnorr_sign(&attest_msg, &privkey(cap_authority_seeds[2])).unwrap();

    // build_mint_authority_raise_cap_sigscript performs no numeric-domain
    // validation itself (that lives in MintAuthorityStateHeader::new_checked/
    // check_numeric_domain) -- it faithfully pushes whatever raw u64 it is
    // given, so routing through the real builder here still reproduces a
    // real attacker crafting the raw 2^63 boundary value directly.
    let ss = build_mint_authority_raise_cap_sigscript(&sig1, &sig2, &sig3, &old_rs, &new_rs, new_cap_raw, &old_rs);
    let final_input = TransactionInput::new(outpoint(outpoint_txid_seed, outpoint_index), ss, 0, 3);
    let tx = Transaction::new(0, vec![final_input], vec![self_output], 0, Default::default(), 0, vec![]);
    let built = Built { tx, entries };

    let res = run(&built);
    assert_rejected_with(&res, "VerifyError");
}
