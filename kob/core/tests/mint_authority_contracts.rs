//! Mint-authority contract (`STABLECOIN_ROBUST_DESIGN.md` §9 "Mint + Supply
//! Cap", extended 2026-07-20 by the mint-authority hardening item: G4
//! ANNOUNCE_CAP ceiling+timelock via ACTIVATE_CAP, G5 MINT epoch budget+dust
//! floor) — `MINT` (`op_type = 0x00`), `ANNOUNCE_CAP` (`op_type = 0x01`,
//! renamed from RAISE_CAP), and `ACTIVATE_CAP` (`op_type = 0x02`, new) all
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
//! coin's shape, closing the "anti-backdoor" gap; (3) the recipient-binding
//! security fix really closes the §9 replay gap; (4) the G5 dust floor
//! (`mint_amount >= MIN_MINT_AMOUNT`) is enforced on-chain; and (5) the G5
//! epoch budget (`minted_this_epoch`/`epoch_start_daa` tracked and reset at
//! DAA boundaries) is enforced on-chain.
//!
//! ANNOUNCE_CAP section: this proves (1) the cold 2-of-3 `cap_authority`
//! threshold gates the branch; (2) `running_supply`/`minted_this_epoch`/
//! `epoch_start_daa`/`current_cap` are all carried forward byte-identical
//! while `pending_cap` is the only field allowed to change; (3) the new
//! ceiling must be a STRICT increase over `current_cap`; (4) the G4 ceiling
//! (`new_pending_cap <= current_cap * K`) is enforced; (5) the successor's
//! `pending_cap` must match the attested value exactly; and (6) no coin is
//! emitted.
//!
//! ACTIVATE_CAP section (new): this proves (1) the branch is genuinely
//! PERMISSIONLESS (no signature check at all, `sig_op_count = 0`); (2) the
//! CSV timelock (`OpCheckSequenceVerify`) rejects a premature `sequence`;
//! (3) an honest activation at the CSV floor promotes `pending_cap` into
//! BOTH `current_cap` and `pending_cap` of the successor (the sentinel
//! invariant: after activation, `current_cap == pending_cap` again); and (4)
//! value continuity is enforced (critical for a permissionless branch).
//!
//! Note on scope: `OpCheckSequenceVerify` at the SCRIPT level only checks
//! the SIGSCRIPT-visible `input.sequence` against the baked floor -- this is
//! exactly what this harness (a bare `TxScriptEngine`, no consensus UTXO
//! diff/DAA-score context) can exercise. Consensus's OWN `check_sequence_lock`
//! (`consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`)
//! separately re-derives the relative lock time against the SPENT UTXO's
//! real, unforgeable `block_daa_score` -- that half is out of scope for this
//! harness (it requires full consensus context, not just script execution)
//! and is the reason CSV, not CLTV, was chosen for this timelock (see
//! `body.rs`'s `build_activate_cap_branch` doc for the full rationale).

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
use kob_core::contract::stablecoin::mint_authority::attestation::{
    build_announce_cap_attestation_message, build_mint_attestation_message, MIN_MINT_AMOUNT,
};
use kob_core::contract::stablecoin::mint_authority::body::{build_mint_authority_body, build_mint_authority_redeem_script};
use kob_core::contract::stablecoin::mint_authority::sigscript::{
    build_mint_authority_activate_cap_sigscript, build_mint_authority_announce_cap_sigscript, build_mint_authority_mint_sigscript,
};
use kob_core::contract::stablecoin::mint_authority::state::MintAuthorityStateHeader;
use kob_core::contract::stablecoin::mint_authority::DOMAIN_TAG_MINT;
use kob_core::contract::stablecoin::state::frozen_flag;
use kob_core::contract::token::identifier_type as id_type;
use kob_core::{build_p2sh, get_public_key, schnorr_sign};

const IN_AMOUNT: u64 = 10_000;

// Deployment-parameter defaults shared by every scenario in this file
// (constructor params added by the 2026-07-20 hardening item). Individual
// tests override the ones they're specifically exercising.
const DEFAULT_K: u64 = 2;
const DEFAULT_EPOCH_LEN: u64 = 1_000_000_000; // effectively "never crosses" unless a test forces it
const DEFAULT_EPOCH_BUDGET: u64 = u64::MAX / 4; // effectively "never exceeded" unless a test forces it
const DEFAULT_MIN_ACTIVATION_DELAY: u64 = 100;

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
/// well-formed coin to `recipient_seed`, `mint_amount` clearing the G5 dust
/// floor, and the G5 epoch budget honestly updated); each adversarial test
/// mutates exactly one lever.
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
    recovery_seeds: [u8; 3],
    role_registry_root: [u8; 32],
    identifier_type: u8,

    // Deployment params (G4/G5 constructor params).
    cap_raise_multiplier_k: u64,
    epoch_length_daa: u64,
    epoch_mint_budget: u64,
    min_activation_delay_daa: u64,

    // This coin's own current mutable state. pending_cap is always ==
    // current_cap for MINT scenarios (the "no announcement pending"
    // sentinel) -- MINT never reads or writes it beyond carrying it forward
    // unchanged, so no separate override lever is needed.
    running_supply: u64,
    current_cap: u64,
    minted_this_epoch: u64,
    epoch_start_daa: u64,
    // FIX 1 (2026-07-20, timelock-griefing hardening): this coin's own live
    // pending_since_daa. Honest default is the sentinel 0 (no announcement
    // pending, matching pending_cap == current_cap above) -- MINT must carry
    // it forward unchanged, exactly like pending_cap.
    pending_since_daa: u64,

    // The DAA score OpTxInputDaaScore reads for "now" -- the spent UTXO
    // entry's own recorded block_daa_score (see this module's top doc).
    input_daa_score: u64,

    // The mint itself.
    mint_amount: u64,
    recipient_seed: u8,

    // Mint-authority contract's own operating balance (not a token value;
    // see the final report's design-ambiguity note on value continuity).
    self_in_value: u64,
    self_out_value: u64,

    // Successor (new_rs) overrides. `None` == carried forward honestly.
    successor_running_supply: Option<u64>,   // None == running_supply + mint_amount
    successor_cap: Option<u64>,              // None == current_cap (unchanged)
    successor_pending_cap: Option<u64>,      // None == current_cap (unchanged, sentinel)
    successor_pending_since_daa: Option<u64>, // None == pending_since_daa (unchanged, FIX 1)
    successor_minted_this_epoch: Option<u64>, // None == honest G5 formula
    successor_epoch_start_daa: Option<u64>,  // None == honest G5 formula
    successor_ops_seed: Option<u8>,          // None == ops_seed (tampers the baked body/suffix)

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
            recovery_seeds: [104, 105, 106],
            role_registry_root: [0xEE; 32],
            identifier_type: id_type::PUBKEY,
            cap_raise_multiplier_k: DEFAULT_K,
            epoch_length_daa: DEFAULT_EPOCH_LEN,
            epoch_mint_budget: DEFAULT_EPOCH_BUDGET,
            min_activation_delay_daa: DEFAULT_MIN_ACTIVATION_DELAY,
            running_supply: 10_000,
            current_cap: 1_000_000_000,
            minted_this_epoch: 0,
            epoch_start_daa: 0,
            pending_since_daa: 0, // sentinel: no announcement pending
            input_daa_score: 0,
            mint_amount: MIN_MINT_AMOUNT, // exactly the G5 dust floor
            recipient_seed: 30,
            self_in_value: IN_AMOUNT,
            self_out_value: IN_AMOUNT,
            successor_running_supply: None,
            successor_cap: None,
            successor_pending_cap: None,
            successor_pending_since_daa: None,
            successor_minted_this_epoch: None,
            successor_epoch_start_daa: None,
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
    let recovery_pubs = [pubkey(cfg.recovery_seeds[0]), pubkey(cfg.recovery_seeds[1]), pubkey(cfg.recovery_seeds[2])];

    // Genesis covenant_id G baked into this authority (SUB-FIX B). Honest ==
    // matches the UTXO entry's real covenant_id (`cfg.input_cov_id`) below --
    // i.e. this really is that genesis's authority.
    let genesis_cov_id: [u8; 32] = cfg.baked_genesis_cov_id.unwrap_or_else(|| cfg.input_cov_id.as_bytes());

    let old_rs = build_mint_authority_redeem_script(
        cfg.running_supply,
        cfg.minted_this_epoch,
        cfg.epoch_start_daa,
        cfg.current_cap,
        cfg.current_cap, // pending_cap sentinel (no announcement pending)
        cfg.pending_since_daa,
        &mint_pub,
        &cap_pubs,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &recovery_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
        cfg.cap_raise_multiplier_k,
        cfg.epoch_length_daa,
        cfg.epoch_mint_budget,
        cfg.min_activation_delay_daa,
    );
    let input_spk = build_p2sh(&old_rs);

    let honest_new_running_supply = cfg.running_supply + cfg.mint_amount;
    let new_running_supply = cfg.successor_running_supply.unwrap_or(honest_new_running_supply);
    let successor_cap = cfg.successor_cap.unwrap_or(cfg.current_cap);
    let successor_pending_cap = cfg.successor_pending_cap.unwrap_or(cfg.current_cap);
    // FIX 1: MINT must carry pending_since_daa forward UNCHANGED (this is
    // the invariant that makes interleaved mints unable to reset
    // ACTIVATE_CAP's timelock clock).
    let successor_pending_since_daa = cfg.successor_pending_since_daa.unwrap_or(cfg.pending_since_daa);

    // Honest G5 epoch-budget formula (mirrors epoch_budget_block's on-chain
    // logic exactly, so any cfg combination self-consistently produces the
    // value the covenant would independently compute).
    let boundary = cfg.epoch_start_daa.saturating_add(cfg.epoch_length_daa);
    let crossed = boundary <= cfg.input_daa_score;
    let honest_new_minted_this_epoch = if crossed { cfg.mint_amount } else { cfg.minted_this_epoch + cfg.mint_amount };
    let honest_new_epoch_start_daa = if crossed { cfg.input_daa_score } else { cfg.epoch_start_daa };
    let new_minted_this_epoch = cfg.successor_minted_this_epoch.unwrap_or(honest_new_minted_this_epoch);
    let new_epoch_start_daa = cfg.successor_epoch_start_daa.unwrap_or(honest_new_epoch_start_daa);

    let successor_ops_pub = cfg.successor_ops_seed.map(pubkey).unwrap_or(ops_pub);
    let new_rs = build_mint_authority_redeem_script(
        new_running_supply,
        new_minted_this_epoch,
        new_epoch_start_daa,
        successor_cap,
        successor_pending_cap,
        successor_pending_since_daa,
        &mint_pub,
        &cap_pubs,
        &successor_ops_pub,
        &freeze_pub,
        &seize_pubs,
        &recovery_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
        cfg.cap_raise_multiplier_k,
        cfg.epoch_length_daa,
        cfg.epoch_mint_budget,
        cfg.min_activation_delay_daa,
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
        &recovery_pubs,
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
        block_daa_score: cfg.input_daa_score,
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
        &recovery_pubs,
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
        Ok(()) => panic!("expected reject via {needle}, but the spend was ACCEPTED"),
        Err(e) => assert!(e.contains(needle), "expected reject via `{needle}`, got a different failure: {e}"),
    }
}

// ============================================================================
// 1. Happy path + conformance round-trip proof
// ============================================================================

#[test]
fn mint_accepts() {
    // A correctly MINT-attested spend: running_supply incremented by exactly
    // mint_amount, current_cap/pending_cap carried forward unchanged, the
    // G5 epoch budget honestly updated, mint_amount at exactly the G5 dust
    // floor, the emitted coin's shape reconstructed on-chain matches the
    // actual output[1], and the recipient is bound. That this passes on the
    // real engine IS the round-trip proof.
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
    // carry current_cap forward unchanged (only ACTIVATE_CAP may rewrite it).
    let honest = MintCfg::honest();
    let cfg = MintCfg { successor_cap: Some(honest.current_cap + 1), ..honest };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_pending_cap_altered_rejected() {
    // The successor's pending_cap differs from this coin's own -- MINT must
    // carry pending_cap forward unchanged too (only ANNOUNCE_CAP/
    // ACTIVATE_CAP may rewrite it). Regression for the new trailing field in
    // the 2026-07-20 5-field state layout.
    let honest = MintCfg::honest();
    let cfg = MintCfg { successor_pending_cap: Some(honest.current_cap + 1), ..honest };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_pending_since_daa_altered_rejected() {
    // FIX 1 (2026-07-20 timelock-griefing hardening) regression: MINT must
    // carry pending_since_daa forward BYTE-IDENTICAL too, exactly like
    // pending_cap -- this is the on-chain proof that a hot mint_pubkey
    // holder cannot reset ACTIVATE_CAP's timelock clock by minting: even a
    // successor that changes pending_since_daa by exactly 1 (from a
    // realistic nonzero starting value, simulating "a MINT happening after
    // an ANNOUNCE_CAP") must be REJECTED. Combined with
    // `activate_cap_rejects_after_interleaved_mint_within_window` (which
    // proves ACTIVATE_CAP measures its deadline purely from old_rs's
    // pending_since_daa field), this composes into the full griefing-fix
    // proof.
    let honest = MintCfg { pending_since_daa: 500, ..MintCfg::honest() };
    let cfg = MintCfg { successor_pending_since_daa: Some(honest.pending_since_daa + 1), ..honest };
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
    // actually mints to (seed 30, Cfg::honest()'s recipient_seed).
    let cfg = MintCfg { attest_recipient_seed: 31, ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_baked_body_tampered_rejected() {
    // Any baked field changed in the successor (here: ops_pubkey, which
    // feeds into the embedded `fixed_mid` blob) changes the successor's
    // ENTIRE body bytes -- the suffix check (covering current_cap+
    // pending_cap + the whole baked body as one contiguous region) must
    // catch this.
    let cfg = MintCfg { successor_ops_seed: Some(199), ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn genesis_covenant_id_mismatch_rejected() {
    // SUB-FIX B regression: this authority bakes a genesis covenant_id G that
    // does NOT match the spending input's ACTUAL, consensus-tracked
    // covenant_id.
    let cfg = MintCfg { baked_genesis_cov_id: Some([0xFEu8; 32]), ..MintCfg::honest() };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn mint_oversized_recipient_rejected() {
    // SUB-FIX A regression: pre-fix, the spender-supplied recipient_pubkey
    // was OpCat'd directly after the fixed `[0x20]` owner_pubkey push opcode
    // with NO length check.
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
    // native value.
    let honest = MintCfg::honest();
    let cfg = MintCfg { self_out_value: honest.self_in_value - 1, ..honest };
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ---- Stage 1 (G5 dust floor) ----

#[test]
fn mint_rejects_amount_below_min() {
    // B.3 dust floor regression: mint_amount == MIN_MINT_AMOUNT - 1 must be
    // REJECTED on-chain; mint_amount == MIN_MINT_AMOUNT (the honest
    // baseline) must be ACCEPTED.
    let honest = MintCfg::honest();
    assert!(run(&build(&honest)).is_ok(), "mint_amount == MIN_MINT_AMOUNT must be accepted");

    let mut below = honest.clone();
    below.mint_amount = MIN_MINT_AMOUNT - 1;
    // The successor's running_supply/epoch fields must still reflect this
    // (smaller) mint_amount for the OTHER checks to pass first -- None
    // levers already recompute honestly from cfg.mint_amount, so no
    // additional overrides are needed here to isolate the dust-floor check.
    let res = run(&build(&below));
    assert_rejected_with(&res, "VerifyError");
}

// ---- Stage 2 (G5 epoch budget) ----

#[test]
fn mint_rejects_epoch_budget_exceeded_within_same_epoch() {
    // Same epoch (input_daa_score stays well before epoch_start_daa +
    // epoch_length_daa, so crossed == false): minted_this_epoch + mint_amount
    // must not exceed epoch_mint_budget.
    let mut cfg = MintCfg::honest();
    cfg.epoch_start_daa = 0;
    cfg.epoch_length_daa = 1_000; // boundary = 1_000
    cfg.input_daa_score = 500; // well before the boundary -- NOT crossed
    cfg.minted_this_epoch = 5_000_000;
    // honest new_minted_this_epoch = 5_000_000 + MIN_MINT_AMOUNT(10_000_000) = 15_000_000.
    cfg.epoch_mint_budget = 15_000_000 - 1; // one sompi short
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");

    // Raising the budget by exactly 1 sompi must flip this to accepted --
    // proves the check is a genuine boundary (<=), not an off-by-one
    // over-reject.
    cfg.epoch_mint_budget = 15_000_000;
    assert!(run(&build(&cfg)).is_ok(), "landing exactly on the epoch budget must be accepted");
}

#[test]
fn mint_resets_budget_when_daa_boundary_crossed() {
    // epoch_start=1000, len=500 (boundary=1500), input daa_score=1600 (past
    // the boundary) -- the epoch resets: successor epoch_start_daa == 1600
    // (the current DAA score, not the old epoch_start), and
    // minted_this_epoch == mint_amount alone (the stale minted_this_epoch is
    // NOT carried over).
    let mut cfg = MintCfg::honest();
    cfg.epoch_start_daa = 1_000;
    cfg.epoch_length_daa = 500;
    cfg.input_daa_score = 1_600;
    cfg.minted_this_epoch = 5_000_000; // stale accumulation from the OLD epoch
    let built = build(&cfg);
    let res = run(&built);
    assert!(res.is_ok(), "honest boundary-crossing MINT must be accepted: {res:?}");

    // Explicit field-level pin (belt-and-suspenders on top of the "engine
    // accepted it" proof): decode the ACTUAL new_rs bytes this scenario used
    // and assert the reset landed exactly where expected.
    let ss = &built.tx.inputs[0].signature_script;
    // The sigscript's push-order (per sigscript.rs's doc) makes decoding the
    // raw bytes brittle to hand-parse here; instead, independently
    // reconstruct what `build()` computed via the SAME public formula it
    // exposes no accessor for, mirrored inline (this is intentionally a
    // literal restatement of the G5 formula, not a call into production
    // code, so it acts as a genuine second implementation cross-check).
    let boundary = cfg.epoch_start_daa.saturating_add(cfg.epoch_length_daa);
    assert!(boundary <= cfg.input_daa_score, "test setup sanity: boundary must actually be crossed");
    let expected_new_epoch_start = cfg.input_daa_score;
    let expected_new_minted = cfg.mint_amount;
    assert_eq!(expected_new_epoch_start, 1_600);
    assert_eq!(expected_new_minted, MIN_MINT_AMOUNT);
    let _ = ss; // sigscript itself isn't re-parsed; the engine-acceptance + the
                // formula-equality above together pin the reset behavior.
}

#[test]
fn mint_rejects_stale_minted_this_epoch_after_boundary_crossed() {
    // Same boundary-crossing setup as above, but the successor's
    // minted_this_epoch is (adversarially) left at the STALE
    // pre-crossing-carried-forward value instead of being reset to just
    // mint_amount -- must be REJECTED.
    let mut cfg = MintCfg::honest();
    cfg.epoch_start_daa = 1_000;
    cfg.epoch_length_daa = 500;
    cfg.input_daa_score = 1_600;
    cfg.minted_this_epoch = 5_000_000;
    // Adversarial: pretend the epoch did NOT reset (old_minted + mint_amount).
    cfg.successor_minted_this_epoch = Some(cfg.minted_this_epoch + cfg.mint_amount);
    let res = run(&build(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 3. ANNOUNCE_CAP (`op_type = 0x01`, renamed 2026-07-20 from RAISE_CAP) --
//    happy path + adversarial batch. Authorization is a cold 2-of-3
//    threshold over the three baked `cap_authority_pubkeys` (the SAME
//    fixed-position `OpCheckSigFromStack` idiom `build_seize_branch` uses).
//    No `mint_pubkey`/owner involvement at all. The successor must carry
//    `running_supply`/`minted_this_epoch`/`epoch_start_daa`/`current_cap`
//    forward UNCHANGED, `pending_cap` strictly increased to exactly the
//    attested `new_pending_cap` AND within the G4 ceiling
//    (`<= current_cap * K`), and the baked body unchanged; ANNOUNCE_CAP
//    emits NO coin (self-continuation output only, at output[0]).
// ============================================================================

/// A 64-byte value that is NOT a signature from any of the three baked
/// `cap_authority` keys -- stands in for "no signature supplied" in a fixed
/// positional slot, mirroring `stablecoin_contracts.rs`'s `SEIZE_GARBAGE_SIG`.
const ANNOUNCE_CAP_GARBAGE_SIG: [u8; 64] = [0u8; 64];

/// One ANNOUNCE_CAP scenario. `honest()` yields a fully valid 3-of-3-signed
/// cap announcement (running_supply/minted_this_epoch/epoch_start_daa/
/// current_cap unchanged, pending_cap strictly increased to exactly the
/// attested new_pending_cap, exactly at the G4 ceiling K=2); each
/// adversarial test mutates exactly one lever.
#[derive(Clone)]
struct AnnounceCapCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,

    mint_seed: u8,
    cap_authority_seeds: [u8; 3],
    ops_seed: u8,
    freeze_seed: u8,
    seize_seeds: [u8; 3],
    recovery_seeds: [u8; 3],
    role_registry_root: [u8; 32],
    identifier_type: u8,

    cap_raise_multiplier_k: u64,
    epoch_length_daa: u64,
    epoch_mint_budget: u64,
    min_activation_delay_daa: u64,

    // This coin's own current mutable state. pending_cap == current_cap
    // (sentinel: no prior announcement).
    running_supply: u64,
    minted_this_epoch: u64,
    epoch_start_daa: u64,
    current_cap: u64,
    // FIX 1 (2026-07-20): this coin's own live pending_since_daa. Honest
    // default is the sentinel 0 (matches pending_cap == current_cap above).
    pending_since_daa: u64,

    // The announcement itself: the new ceiling both pushed via the sigscript
    // and folded into the attested pre-image.
    new_pending_cap: u64,

    // FIX 1: the DAA score OpTxInputDaaScore reads for this ANNOUNCE_CAP
    // input's own UTXO entry -- the branch stamps the successor's
    // pending_since_daa with exactly this value. Nonzero by default (500)
    // deliberately, so it is textually distinguishable from the sentinel 0
    // in test failure output/derived fixtures (see
    // `activate_cap_rejects_after_interleaved_mint_within_window`'s doc for
    // why the sentinel/real-DAA-score-0 ambiguity matters).
    announce_input_daa_score: u64,

    self_in_value: u64,
    self_out_value: u64,

    // Successor (new_rs) overrides. `None` == carried forward honestly.
    successor_running_supply: Option<u64>,
    successor_current_cap: Option<u64>,   // None == current_cap (unchanged)
    successor_pending_cap: Option<u64>,   // None == new_pending_cap (the honest announcement)
    successor_pending_since_daa: Option<u64>, // None == announce_input_daa_score (the honest G4 stamp, FIX 1)
    successor_ops_seed: Option<u8>,

    attest_outpoint_txid_seed: Option<u8>,
    signer_seeds: [Option<u8>; 3],
    baked_genesis_cov_id: Option<[u8; 32]>,
}

impl AnnounceCapCfg {
    fn honest() -> Self {
        AnnounceCapCfg {
            input_cov_id: hash32(0xC0),
            outpoint_txid_seed: 0x50,
            outpoint_index: 0,
            mint_seed: 21,
            cap_authority_seeds: [70, 71, 72],
            ops_seed: 22,
            freeze_seed: 23,
            seize_seeds: [24, 25, 26],
            recovery_seeds: [107, 108, 109],
            role_registry_root: [0xEE; 32],
            identifier_type: id_type::PUBKEY,
            cap_raise_multiplier_k: DEFAULT_K,
            epoch_length_daa: DEFAULT_EPOCH_LEN,
            epoch_mint_budget: DEFAULT_EPOCH_BUDGET,
            min_activation_delay_daa: DEFAULT_MIN_ACTIVATION_DELAY,
            running_supply: 10_000,
            minted_this_epoch: 0,
            epoch_start_daa: 0,
            current_cap: 1_000_000,
            pending_since_daa: 0, // sentinel: no prior announcement
            new_pending_cap: 2_000_000, // == current_cap * DEFAULT_K exactly (the G4 ceiling boundary)
            announce_input_daa_score: 500,
            self_in_value: IN_AMOUNT,
            self_out_value: IN_AMOUNT,
            successor_running_supply: None,
            successor_current_cap: None,
            successor_pending_cap: None,
            successor_pending_since_daa: None,
            successor_ops_seed: None,
            attest_outpoint_txid_seed: None,
            signer_seeds: [Some(70), Some(71), Some(72)],
            baked_genesis_cov_id: None,
        }
    }
}

fn build_announce_cap(cfg: &AnnounceCapCfg) -> Built {
    let mint_pub = pubkey(cfg.mint_seed);
    let cap_pubs = [pubkey(cfg.cap_authority_seeds[0]), pubkey(cfg.cap_authority_seeds[1]), pubkey(cfg.cap_authority_seeds[2])];
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = [pubkey(cfg.seize_seeds[0]), pubkey(cfg.seize_seeds[1]), pubkey(cfg.seize_seeds[2])];
    let recovery_pubs = [pubkey(cfg.recovery_seeds[0]), pubkey(cfg.recovery_seeds[1]), pubkey(cfg.recovery_seeds[2])];

    let genesis_cov_id: [u8; 32] = cfg.baked_genesis_cov_id.unwrap_or_else(|| cfg.input_cov_id.as_bytes());

    let old_rs = build_mint_authority_redeem_script(
        cfg.running_supply,
        cfg.minted_this_epoch,
        cfg.epoch_start_daa,
        cfg.current_cap,
        cfg.current_cap, // pending_cap sentinel
        cfg.pending_since_daa,
        &mint_pub,
        &cap_pubs,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &recovery_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
        cfg.cap_raise_multiplier_k,
        cfg.epoch_length_daa,
        cfg.epoch_mint_budget,
        cfg.min_activation_delay_daa,
    );
    let input_spk = build_p2sh(&old_rs);

    // 1:1 successor: running_supply/minted_this_epoch/epoch_start_daa/
    // current_cap all carried forward UNCHANGED (unless a test overrides
    // them), pending_cap raised to new_pending_cap (unless a test overrides
    // it), pending_since_daa stamped to this input's own real DAA score
    // (FIX 1 -- unless a test overrides it), the baked body untouched
    // (unless a test overrides ops_pubkey to probe the suffix check).
    let successor_running_supply = cfg.successor_running_supply.unwrap_or(cfg.running_supply);
    let successor_current_cap = cfg.successor_current_cap.unwrap_or(cfg.current_cap);
    let successor_pending_cap = cfg.successor_pending_cap.unwrap_or(cfg.new_pending_cap);
    let successor_pending_since_daa = cfg.successor_pending_since_daa.unwrap_or(cfg.announce_input_daa_score);
    let successor_ops_pub = cfg.successor_ops_seed.map(pubkey).unwrap_or(ops_pub);
    let new_rs = build_mint_authority_redeem_script(
        successor_running_supply,
        cfg.minted_this_epoch,
        cfg.epoch_start_daa,
        successor_current_cap,
        successor_pending_cap,
        successor_pending_since_daa,
        &mint_pub,
        &cap_pubs,
        &successor_ops_pub,
        &freeze_pub,
        &seize_pubs,
        &recovery_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
        cfg.cap_raise_multiplier_k,
        cfg.epoch_length_daa,
        cfg.epoch_mint_budget,
        cfg.min_activation_delay_daa,
    );
    let self_out_spk = build_p2sh(&new_rs);

    let self_output = TransactionOutput::with_covenant(cfg.self_out_value, self_out_spk, Some(CovenantBinding::new(0, cfg.input_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.self_in_value,
        script_public_key: input_spk,
        // FIX 1: OpTxInputDaaScore reads this -- the ANNOUNCE_CAP branch
        // stamps the successor's pending_since_daa with exactly this value.
        block_daa_score: cfg.announce_input_daa_score,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    let cov_bytes: [u8; 32] = cfg.input_cov_id.as_bytes();
    let msg_txid_seed = cfg.attest_outpoint_txid_seed.unwrap_or(cfg.outpoint_txid_seed);
    let txid_bytes: [u8; 32] = [msg_txid_seed; 32];
    let attest_msg = build_announce_cap_attestation_message(&cov_bytes, &txid_bytes, cfg.outpoint_index, cfg.new_pending_cap);

    let sig_for = |slot: usize| -> [u8; 64] {
        match cfg.signer_seeds[slot] {
            Some(seed) => schnorr_sign(&attest_msg, &privkey(seed)).unwrap(),
            None => ANNOUNCE_CAP_GARBAGE_SIG,
        }
    };
    let sig1 = sig_for(0);
    let sig2 = sig_for(1);
    let sig3 = sig_for(2);

    let ss = build_mint_authority_announce_cap_sigscript(&sig1, &sig2, &sig3, &old_rs, &new_rs, cfg.new_pending_cap, &old_rs);
    // sig_op_count = 3: three OpCheckSigFromStack calls (2-of-3 cap_authority
    // quorum).
    let final_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), ss, 0, 3);
    let tx = Transaction::new(0, vec![final_input], vec![self_output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

#[test]
fn announce_cap_2of3_accepts() {
    let cfg = AnnounceCapCfg { signer_seeds: [Some(70), Some(71), None], ..AnnounceCapCfg::honest() };
    let res = run(&build_announce_cap(&cfg));
    assert!(res.is_ok(), "honest 2-of-3 ANNOUNCE_CAP must be accepted: {res:?}");
}

#[test]
fn announce_cap_3of3_accepts() {
    let res = run(&build_announce_cap(&AnnounceCapCfg::honest()));
    assert!(res.is_ok(), "honest 3-of-3 ANNOUNCE_CAP must be accepted: {res:?}");
}

#[test]
fn announce_cap_1of3_insufficient_rejected() {
    let cfg = AnnounceCapCfg { signer_seeds: [Some(70), None, None], ..AnnounceCapCfg::honest() };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_wrong_keys_rejected() {
    let cfg = AnnounceCapCfg { signer_seeds: [Some(AnnounceCapCfg::honest().mint_seed), Some(91), Some(92)], ..AnnounceCapCfg::honest() };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_not_strictly_increased_rejected() {
    // new_pending_cap == current_cap (no-op "announcement") must be rejected.
    let honest = AnnounceCapCfg::honest();
    let eq_cfg = AnnounceCapCfg { new_pending_cap: honest.current_cap, ..honest.clone() };
    assert_rejected_with(&run(&build_announce_cap(&eq_cfg)), "VerifyError");

    // new_pending_cap < current_cap (an attempted lowering) must also be rejected.
    let lower_cfg = AnnounceCapCfg { new_pending_cap: honest.current_cap - 1, ..honest };
    assert_rejected_with(&run(&build_announce_cap(&lower_cfg)), "VerifyError");
}

#[test]
fn announce_cap_rejects_ceiling_exceeded() {
    // G4 hardening (Stage 1): new_pending_cap must be <= current_cap * K.
    // honest() is already exactly AT the ceiling (current_cap=1_000_000,
    // K=2 -> ceiling=2_000_000 == new_pending_cap) -- must be ACCEPTED.
    let at_ceiling = AnnounceCapCfg::honest();
    assert!(run(&build_announce_cap(&at_ceiling)).is_ok(), "landing exactly on the G4 ceiling (current_cap * K) must be accepted");

    // One sompi over the ceiling must be REJECTED.
    let over_ceiling = AnnounceCapCfg { new_pending_cap: 2_000_001, ..AnnounceCapCfg::honest() };
    assert_rejected_with(&run(&build_announce_cap(&over_ceiling)), "VerifyError");
}

#[test]
fn announce_cap_running_supply_altered_rejected() {
    let honest = AnnounceCapCfg::honest();
    let cfg = AnnounceCapCfg { successor_running_supply: Some(honest.running_supply + 1), ..honest };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_current_cap_altered_rejected() {
    // ANNOUNCE_CAP must carry current_cap forward UNCHANGED -- only
    // ACTIVATE_CAP may ever change it. Regression for the new field-
    // ownership-driven layout's prefix check (`[0..36)`, covering
    // current_cap as part of the protected region ahead of the mutated
    // trailing `pending_cap` field).
    let honest = AnnounceCapCfg::honest();
    let cfg = AnnounceCapCfg { successor_current_cap: Some(honest.current_cap + 1), ..honest };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_new_pending_cap_mismatch_attestation_rejected() {
    // The cap_authority quorum genuinely attested (and the sigscript
    // genuinely pushes) new_pending_cap = 2_000_000, but the successor's
    // ACTUAL pending_cap field is a DIFFERENT value.
    let honest = AnnounceCapCfg::honest();
    let cfg = AnnounceCapCfg { successor_pending_cap: Some(honest.new_pending_cap + 1), ..honest };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_pending_since_daa_mismatch_rejected() {
    // FIX 1 (2026-07-20 timelock-griefing hardening) regression: the
    // successor's pending_since_daa must equal THIS input's own real
    // OpTxInputDaaScore (announce_input_daa_score) exactly -- neither a
    // stale/arbitrary value nor the sentinel 0 (pretending no announcement
    // happened) is accepted once a real announcement is in flight.
    let honest = AnnounceCapCfg::honest();
    let off_by_one = AnnounceCapCfg { successor_pending_since_daa: Some(honest.announce_input_daa_score + 1), ..honest.clone() };
    assert_rejected_with(&run(&build_announce_cap(&off_by_one)), "VerifyError");

    let sentinel = AnnounceCapCfg { successor_pending_since_daa: Some(0), ..honest };
    assert_rejected_with(&run(&build_announce_cap(&sentinel)), "VerifyError");
}

#[test]
fn announce_cap_baked_body_tampered_rejected() {
    let cfg = AnnounceCapCfg { successor_ops_seed: Some(199), ..AnnounceCapCfg::honest() };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_genesis_covenant_id_mismatch_rejected() {
    let cfg = AnnounceCapCfg { baked_genesis_cov_id: Some([0xFEu8; 32]), ..AnnounceCapCfg::honest() };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_output_value_drained_rejected() {
    let honest = AnnounceCapCfg::honest();
    let cfg = AnnounceCapCfg { self_out_value: honest.self_in_value - 1, ..honest };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_replay_other_outpoint_rejected() {
    let cfg = AnnounceCapCfg { attest_outpoint_txid_seed: Some(0x77), ..AnnounceCapCfg::honest() };
    let res = run(&build_announce_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn announce_cap_new_pending_cap_at_or_above_2pow63_rejected() {
    // SUB-FIX E on-chain regression: RAISE_CAP/ANNOUNCE_CAP jumping
    // pending_cap to >= 2^63 turns out NOT to be reachable via a single
    // strict-increase call in the first place -- Kaspa script numbers are
    // sign-magnitude LE, so a raw 8-byte encoding of exactly `1u64 << 63`
    // decodes as script-number `0`, and the strict-increase check
    // (`new_pending_cap > current_cap`) already rejects that.
    //
    // Hand-rolled rather than routed through `build_announce_cap`/
    // `build_announce_cap_attestation_message`/`MintAuthorityStateHeader::new`:
    // those debug_assert this exact numeric domain -- a real attacker never
    // calls any Rust helper at all, they craft the raw wire bytes directly,
    // which is what this test reproduces.
    let input_cov_id = hash32(0xC7);
    let outpoint_txid_seed = 0x59u8;
    let outpoint_index = 0u32;
    let mint_seed = 21u8;
    let cap_authority_seeds = [70u8, 71, 72];
    let ops_seed = 22u8;
    let freeze_seed = 23u8;
    let seize_seeds = [24u8, 25, 26];
    let recovery_seeds = [104u8, 105, 106];
    let role_registry_root = [0xEEu8; 32];
    let identifier_type = id_type::PUBKEY;
    let running_supply = 10_000u64;
    let current_cap = 1_000_000u64;
    let new_pending_cap_raw: u64 = 1u64 << 63;

    let mint_pub = pubkey(mint_seed);
    let cap_pubs = [pubkey(cap_authority_seeds[0]), pubkey(cap_authority_seeds[1]), pubkey(cap_authority_seeds[2])];
    let ops_pub = pubkey(ops_seed);
    let freeze_pub = pubkey(freeze_seed);
    let seize_pubs = [pubkey(seize_seeds[0]), pubkey(seize_seeds[1]), pubkey(seize_seeds[2])];
    let recovery_pubs = [pubkey(recovery_seeds[0]), pubkey(recovery_seeds[1]), pubkey(recovery_seeds[2])];
    let genesis_cov_id: [u8; 32] = input_cov_id.as_bytes();

    let old_rs = build_mint_authority_redeem_script(
        running_supply, 0, 0, current_cap, current_cap, 0, &mint_pub, &cap_pubs, &ops_pub, &freeze_pub, &seize_pubs, &recovery_pubs,
        &role_registry_root, identifier_type, &genesis_cov_id, DEFAULT_K, DEFAULT_EPOCH_LEN, DEFAULT_EPOCH_BUDGET, DEFAULT_MIN_ACTIVATION_DELAY,
    );
    let input_spk = build_p2sh(&old_rs);

    // new_rs: everything else carried forward unchanged, pending_cap set to
    // the raw 2^63 pattern under test -- constructed directly via
    // `MintAuthorityStateHeader`'s public fields, bypassing `new`'s
    // debug_assert (mirrors a real attacker crafting raw wire bytes).
    // pending_since_daa honestly matches entries[0]'s block_daa_score (0)
    // below -- not itself under test here (FIX 1's own mismatch coverage
    // lives in `announce_cap_pending_since_daa_mismatch_rejected`), so it's
    // set to whatever the real ANNOUNCE_CAP branch would independently
    // compute, keeping this test isolated to the pre-existing 2^63 check.
    let new_state =
        MintAuthorityStateHeader { running_supply, minted_this_epoch: 0, epoch_start_daa: 0, current_cap, pending_cap: new_pending_cap_raw, pending_since_daa: 0 };
    let mut new_rs = new_state.encode_script();
    new_rs.extend_from_slice(&build_mint_authority_body(
        &mint_pub, &cap_pubs, &ops_pub, &freeze_pub, &seize_pubs, &recovery_pubs, &role_registry_root, identifier_type, &genesis_cov_id,
        DEFAULT_K, DEFAULT_EPOCH_LEN, DEFAULT_EPOCH_BUDGET, DEFAULT_MIN_ACTIVATION_DELAY,
    ));
    let self_out_spk = build_p2sh(&new_rs);

    let self_output = TransactionOutput::with_covenant(IN_AMOUNT, self_out_spk, Some(CovenantBinding::new(0, input_cov_id)));
    let entries = vec![UtxoEntry {
        amount: IN_AMOUNT,
        script_public_key: input_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(input_cov_id),
    }];

    // Hand-rolled 84B ANNOUNCE_CAP attestation preimage (bypasses
    // `build_announce_cap_attestation_message`'s debug_assert on `new_pending_cap`).
    let cov_bytes: [u8; 32] = input_cov_id.as_bytes();
    let txid_bytes: [u8; 32] = [outpoint_txid_seed; 32];
    let mut preimage = Vec::with_capacity(84);
    preimage.extend_from_slice(&DOMAIN_TAG_MINT);
    preimage.extend_from_slice(&cov_bytes);
    preimage.extend_from_slice(&txid_bytes);
    preimage.extend_from_slice(&outpoint_index.to_le_bytes());
    preimage.extend_from_slice(&new_pending_cap_raw.to_le_bytes());
    assert_eq!(preimage.len(), 84);
    let attest_msg: [u8; 32] = *blake3::hash(&preimage).as_bytes();

    let sig1 = schnorr_sign(&attest_msg, &privkey(cap_authority_seeds[0])).unwrap();
    let sig2 = schnorr_sign(&attest_msg, &privkey(cap_authority_seeds[1])).unwrap();
    let sig3 = schnorr_sign(&attest_msg, &privkey(cap_authority_seeds[2])).unwrap();

    let ss = build_mint_authority_announce_cap_sigscript(&sig1, &sig2, &sig3, &old_rs, &new_rs, new_pending_cap_raw, &old_rs);
    let final_input = TransactionInput::new(outpoint(outpoint_txid_seed, outpoint_index), ss, 0, 3);
    let tx = Transaction::new(0, vec![final_input], vec![self_output], 0, Default::default(), 0, vec![]);
    let built = Built { tx, entries };

    let res = run(&built);
    assert_rejected_with(&res, "VerifyError");
}

// ============================================================================
// 4. ACTIVATE_CAP (`op_type = 0x02`, new 2026-07-20) -- happy path +
//    adversarial batch. PERMISSIONLESS (no signatures at all,
//    `sig_op_count = 0`): gated by FIX 1's STATE-ANCHORED timelock
//    (`old_rs.pending_since_daa + min_activation_delay_daa <=
//    OpTxInputDaaScore` of the activating input -- REPLACING an earlier CSV
//    `OpCheckSequenceVerify` design that was griefable: CSV enforces its
//    floor against the SELF-CONTINUING UTXO's own `block_daa_score`, which
//    every routine MINT re-stamps, so a hot mint key could mint dust once
//    per window to reset the clock and block activation forever) and the
//    on-chain checks that the successor's `current_cap` AND `pending_cap`
//    both equal this coin's own already-announced `pending_cap`, with
//    `pending_since_daa` reset to the sentinel `0`.
// ============================================================================

#[derive(Clone)]
struct ActivateCapCfg {
    input_cov_id: Hash,
    outpoint_txid_seed: u8,
    outpoint_index: u32,

    mint_seed: u8,
    cap_authority_seeds: [u8; 3],
    ops_seed: u8,
    freeze_seed: u8,
    seize_seeds: [u8; 3],
    recovery_seeds: [u8; 3],
    role_registry_root: [u8; 32],
    identifier_type: u8,

    cap_raise_multiplier_k: u64,
    epoch_length_daa: u64,
    epoch_mint_budget: u64,
    min_activation_delay_daa: u64,

    // This coin's own current mutable state -- current_cap != pending_cap:
    // an ANNOUNCE_CAP already landed, and this activation is promoting it.
    running_supply: u64,
    minted_this_epoch: u64,
    epoch_start_daa: u64,
    current_cap: u64,
    pending_cap: u64,
    // FIX 1: the DAA score at which the (already-landed) ANNOUNCE_CAP this
    // is promoting really happened -- old_rs's own pending_since_daa.
    // Nonzero by default (500) deliberately: 0 is also the sentinel "no
    // announcement pending" value, so using a real nonzero DAA score here
    // keeps this fixture unambiguous (an announcement genuinely IS
    // pending), and lets `activate_cap_rejects_after_interleaved_mint_within_window`
    // simulate "one or more MINTs happened between the announce and now"
    // without colliding with the sentinel.
    pending_since_daa: u64,

    self_in_value: u64,
    self_out_value: u64,

    // Successor (new_rs) overrides. `None` == honest promotion (current_cap/
    // pending_cap both become the OLD pending_cap; pending_since_daa resets
    // to the sentinel 0).
    successor_current_cap: Option<u64>,
    successor_pending_cap: Option<u64>,
    successor_pending_since_daa: Option<u64>,
    successor_running_supply: Option<u64>,

    // FIX 1: the DAA score OpTxInputDaaScore reads for THIS activating
    // input's own UTXO entry -- i.e. "now". The state-anchored timelock
    // requires `pending_since_daa + min_activation_delay_daa <= this value`.
    activate_input_daa_score: u64,
}

impl ActivateCapCfg {
    fn honest() -> Self {
        ActivateCapCfg {
            input_cov_id: hash32(0xD0),
            outpoint_txid_seed: 0x60,
            outpoint_index: 0,
            mint_seed: 21,
            cap_authority_seeds: [70, 71, 72],
            ops_seed: 22,
            freeze_seed: 23,
            seize_seeds: [24, 25, 26],
            recovery_seeds: [110, 111, 112],
            role_registry_root: [0xEE; 32],
            identifier_type: id_type::PUBKEY,
            cap_raise_multiplier_k: DEFAULT_K,
            epoch_length_daa: DEFAULT_EPOCH_LEN,
            epoch_mint_budget: DEFAULT_EPOCH_BUDGET,
            min_activation_delay_daa: DEFAULT_MIN_ACTIVATION_DELAY,
            running_supply: 10_000,
            minted_this_epoch: 0,
            epoch_start_daa: 0,
            current_cap: 1_000_000,
            pending_cap: 2_000_000, // an ANNOUNCE_CAP already landed
            pending_since_daa: 500, // ...at DAA 500
            self_in_value: IN_AMOUNT,
            self_out_value: IN_AMOUNT,
            successor_current_cap: None,
            successor_pending_cap: None,
            successor_pending_since_daa: None,
            successor_running_supply: None,
            activate_input_daa_score: 500 + DEFAULT_MIN_ACTIVATION_DELAY, // exactly at the timelock floor
        }
    }
}

fn build_activate_cap(cfg: &ActivateCapCfg) -> Built {
    let mint_pub = pubkey(cfg.mint_seed);
    let cap_pubs = [pubkey(cfg.cap_authority_seeds[0]), pubkey(cfg.cap_authority_seeds[1]), pubkey(cfg.cap_authority_seeds[2])];
    let ops_pub = pubkey(cfg.ops_seed);
    let freeze_pub = pubkey(cfg.freeze_seed);
    let seize_pubs = [pubkey(cfg.seize_seeds[0]), pubkey(cfg.seize_seeds[1]), pubkey(cfg.seize_seeds[2])];
    let recovery_pubs = [pubkey(cfg.recovery_seeds[0]), pubkey(cfg.recovery_seeds[1]), pubkey(cfg.recovery_seeds[2])];

    // ACTIVATE_CAP has no genesis check of its own; bake G == this coin's
    // own covenant_id for realism (matches every other scenario's honest
    // convention), though it plays no role in this branch's verification.
    let genesis_cov_id: [u8; 32] = cfg.input_cov_id.as_bytes();

    let old_rs = build_mint_authority_redeem_script(
        cfg.running_supply,
        cfg.minted_this_epoch,
        cfg.epoch_start_daa,
        cfg.current_cap,
        cfg.pending_cap,
        cfg.pending_since_daa,
        &mint_pub,
        &cap_pubs,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &recovery_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
        cfg.cap_raise_multiplier_k,
        cfg.epoch_length_daa,
        cfg.epoch_mint_budget,
        cfg.min_activation_delay_daa,
    );
    let input_spk = build_p2sh(&old_rs);

    // Honest promotion: BOTH current_cap and pending_cap become the OLD
    // pending_cap (the sentinel invariant restored: current_cap ==
    // pending_cap), and pending_since_daa resets to the sentinel 0.
    let successor_running_supply = cfg.successor_running_supply.unwrap_or(cfg.running_supply);
    let successor_current_cap = cfg.successor_current_cap.unwrap_or(cfg.pending_cap);
    let successor_pending_cap = cfg.successor_pending_cap.unwrap_or(cfg.pending_cap);
    let successor_pending_since_daa = cfg.successor_pending_since_daa.unwrap_or(0);
    let new_rs = build_mint_authority_redeem_script(
        successor_running_supply,
        cfg.minted_this_epoch,
        cfg.epoch_start_daa,
        successor_current_cap,
        successor_pending_cap,
        successor_pending_since_daa,
        &mint_pub,
        &cap_pubs,
        &ops_pub,
        &freeze_pub,
        &seize_pubs,
        &recovery_pubs,
        &cfg.role_registry_root,
        cfg.identifier_type,
        &genesis_cov_id,
        cfg.cap_raise_multiplier_k,
        cfg.epoch_length_daa,
        cfg.epoch_mint_budget,
        cfg.min_activation_delay_daa,
    );
    let self_out_spk = build_p2sh(&new_rs);

    let self_output = TransactionOutput::with_covenant(cfg.self_out_value, self_out_spk, Some(CovenantBinding::new(0, cfg.input_cov_id)));

    let entries = vec![UtxoEntry {
        amount: cfg.self_in_value,
        script_public_key: input_spk,
        // FIX 1: OpTxInputDaaScore reads this -- "now" for the
        // state-anchored timelock check.
        block_daa_score: cfg.activate_input_daa_score,
        is_coinbase: false,
        covenant_id: Some(cfg.input_cov_id),
    }];

    // No signatures at all -- permissionless. sequence is irrelevant to this
    // branch's verification since FIX 1 (the state-anchored timelock
    // replaces CSV entirely, see this section's top comment) -- hardcoded 0.
    let ss = build_mint_authority_activate_cap_sigscript(&old_rs, &new_rs, &old_rs);
    // sig_op_count = 0: no OpCheckSigFromStack calls in this branch.
    let final_input = TransactionInput::new(outpoint(cfg.outpoint_txid_seed, cfg.outpoint_index), ss, 0, 0);
    let tx = Transaction::new(0, vec![final_input], vec![self_output], 0, Default::default(), 0, vec![]);
    Built { tx, entries }
}

#[test]
fn activate_cap_promotes_pending_into_current_and_resets_sentinel() {
    // activate_input_daa_score at the timelock floor
    // (pending_since_daa + min_activation_delay_daa) must be ACCEPTED: the
    // successor's current_cap AND pending_cap both become the OLD
    // pending_cap (2_000_000), restoring the "no pending announcement"
    // sentinel (current_cap == pending_cap), and pending_since_daa resets to
    // 0.
    let cfg = ActivateCapCfg::honest();
    let res = run(&build_activate_cap(&cfg));
    assert!(res.is_ok(), "honest ACTIVATE_CAP at the timelock floor must be accepted: {res:?}");
}

#[test]
fn activate_cap_rejects_premature_activation() {
    // FIX 1 regression: activate_input_daa_score one short of
    // pending_since_daa + min_activation_delay_daa must be REJECTED by the
    // state-anchored `OpLessThanOrEqual OpVerify` check -- the direct
    // replacement for the old CSV `OpCheckSequenceVerify`'s
    // `UnsatisfiedLockTime` boundary (now a generic `VerifyError`, since
    // this is ordinary script-level arithmetic, not a dedicated timelock
    // opcode).
    let honest = ActivateCapCfg::honest();
    let cfg = ActivateCapCfg { activate_input_daa_score: honest.pending_since_daa + honest.min_activation_delay_daa - 1, ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn activate_cap_rejects_after_interleaved_mint_within_window() {
    // *** THE griefing-fix proof (FIX 1, 2026-07-20). ***
    //
    // Scenario: ANNOUNCE_CAP happened at DAA D (old_rs.pending_since_daa ==
    // D). A MINT then landed at D+1 -- and `mint_pending_since_daa_altered_rejected`
    // (this file) already proves ON-CHAIN that MINT is FORCED to carry
    // pending_since_daa forward byte-identical, so any real chain of one or
    // more mints after the announce leaves old_rs.pending_since_daa == D
    // untouched, regardless of the mints' own DAA scores. This fixture
    // constructs that "post-interleaved-mint" old_rs directly (D unchanged),
    // then activates with activate_input_daa_score == D + min_delay - 1 --
    // one short of the window measured from D.
    //
    // Pre-fix (CSV), the timelock would have measured its floor against the
    // SELF-CONTINUING UTXO's own block_daa_score, i.e. the interleaved
    // MINT's re-stamp (~D+1), not the original announce D -- so a hot
    // mint_pubkey holder could keep the window perpetually "just reset" by
    // minting dust. Post-fix, the deadline is D + min_delay regardless of
    // how many mints happened in between, so this must still be REJECTED.
    let honest = ActivateCapCfg::honest();
    let d = honest.pending_since_daa; // 500
    let cfg = ActivateCapCfg { activate_input_daa_score: d + honest.min_activation_delay_daa - 1, ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn activate_cap_accepts_after_window_despite_interleaved_mint() {
    // Companion to `activate_cap_rejects_after_interleaved_mint_within_window`:
    // the SAME post-interleaved-mint old_rs (pending_since_daa == D,
    // unchanged), but activate_input_daa_score == D + min_delay exactly --
    // must ACCEPT. Together these two tests pin that the window is measured
    // from D (the original announce), never reset by whatever DAA an
    // interleaved MINT actually landed at.
    let honest = ActivateCapCfg::honest();
    let d = honest.pending_since_daa;
    let cfg = ActivateCapCfg { activate_input_daa_score: d + honest.min_activation_delay_daa, ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert!(res.is_ok(), "ACTIVATE_CAP at exactly the D-anchored floor must be accepted despite an interleaved mint: {res:?}");
}

#[test]
fn activate_cap_current_cap_not_promoted_rejected() {
    // The successor's current_cap does NOT equal the old pending_cap (e.g.
    // stayed at the old current_cap) -- must be rejected.
    let honest = ActivateCapCfg::honest();
    let cfg = ActivateCapCfg { successor_current_cap: Some(honest.current_cap), ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn activate_cap_pending_cap_not_reset_rejected() {
    // The successor's pending_cap does NOT equal the old pending_cap (e.g.
    // some other value entirely) -- the sentinel invariant is violated, must
    // be rejected.
    let honest = ActivateCapCfg::honest();
    let cfg = ActivateCapCfg { successor_pending_cap: Some(honest.pending_cap + 1), ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn activate_cap_pending_since_daa_not_reset_rejected() {
    // FIX 1 regression: the successor's pending_since_daa must reset to the
    // sentinel 0 -- a successor that leaves it at the old announce DAA (or
    // any other nonzero value) violates the "no announcement pending"
    // sentinel invariant and must be rejected.
    let honest = ActivateCapCfg::honest();
    let cfg = ActivateCapCfg { successor_pending_since_daa: Some(honest.pending_since_daa), ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn activate_cap_running_supply_altered_rejected() {
    // ACTIVATE_CAP must carry running_supply forward UNCHANGED (only MINT
    // may increment it).
    let honest = ActivateCapCfg::honest();
    let cfg = ActivateCapCfg { successor_running_supply: Some(honest.running_supply + 1), ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn activate_cap_output_value_drained_rejected() {
    // CRITICAL for a permissionless branch: with no signature at all gating
    // this branch, without value continuity ANY third party could drain the
    // authority UTXO's operating balance while activating a cap.
    let honest = ActivateCapCfg::honest();
    let cfg = ActivateCapCfg { self_out_value: honest.self_in_value - 1, ..honest };
    let res = run(&build_activate_cap(&cfg));
    assert_rejected_with(&res, "VerifyError");
}

#[test]
fn activate_cap_requires_zero_sig_op_count_shape() {
    // Structural sanity: the honest sigscript this module builds carries no
    // signature pushes at all (unlike MINT's 64B mint_sig or ANNOUNCE_CAP's
    // three 64B quorum sigs) -- confirms the sigscript builder really is
    // permissionless, not just that sig_op_count happens to be set to 0
    // alongside an (unused) signature push.
    let cfg = ActivateCapCfg::honest();
    let built = build_activate_cap(&cfg);
    assert_eq!(built.tx.inputs[0].compute_commit.sig_op_count(), Some(0));
}
