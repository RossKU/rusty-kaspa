//! Budget-limited engine-repro regression (script-units hole detection).
//!
//! `planner_engine_repro.rs` proves the planners' tx shapes pass the real
//! `kaspa-txscript` engine, but it runs every covenant input under an
//! effectively UNLIMITED script-units budget
//! (`TxScriptEngine::from_transaction_input`, `ScriptUnits(u64::MAX)`). That
//! is not what the node enforces: consensus caps each input's script
//! execution at `ComputeCommit::allowed_script_units()` --
//! `sig_op_count * SCRIPT_UNITS_PER_SIGOP_COUNT_UNIT` (v0 tx) plus a fixed
//! free allowance of 9,999 script units per input (`free_script_units_per_input`,
//! `consensus/core/src/mass/units.rs`) -- and enforces it PER INPUT exactly
//! as `check_scripts` does in
//! `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`:
//! `let script_units_limit = input.compute_commit.allowed_script_units();`
//! followed by `TxScriptEngine::from_transaction_input_with_script_units_limit`.
//!
//! This gap is exactly what let the 2026-07-18 live bug through:
//! `plan_ratchet_advance` (`kob/domain/src/spot/time_planner.rs`) built its
//! RATCHET-branch input with `sig_op_count: 0` (0 free script units above the
//! 9,999 base), while the composed settle+advance tx's splice+introspection
//! work measured 10,311 script units on that input on testnet-10 -- over
//! budget by 312 units. Every existing engine-repro test still passed
//! (unlimited budget hides the shortfall); only the live node rejected it
//! ("script units exceeded the amount committed in the input"). Fixed by
//! `sig_op_count: 1` (109,999 free units).
//!
//! This file closes that hole: `exec_covenant_inputs_budgeted` mirrors the
//! node's own per-input accounting exactly (`input.compute_commit.allowed_script_units()`
//! fed to `from_transaction_input_with_script_units_limit`), and
//! `run_spot_plan_budgeted` builds each input's `sig_op_count` from the
//! PLANNER'S OWN OUTPUT (`BatchTxInput::sig_op_count`) instead of hardcoding
//! it -- so a future regression that under-commits any composed shape's
//! budget fails HERE the same way it fails on a live node, without needing a
//! testnet round-trip to find out.
//!
//! Two-directional proof (recorded here, not re-run every `cargo test`): with
//! `time_planner.rs`'s `sig_op_count: 1` (current, fixed) the
//! `settle_plus_ratchet_advance_budgeted_passes_real_node_accounting` test
//! below PASSES; temporarily reverting that one field to `sig_op_count: 0`
//! (the historical bug) makes it FAIL with `ExceededCommittedScriptUnits`
//! (verified manually, then reverted -- see kob/E2E_LIVE_RESULTS.md).
//! `settle_plus_ratchet_advance_budgeted_FAILS_when_underbudgeted` pins the
//! same failure mode permanently by constructing the underbudgeted input
//! directly, independent of the production source's current state.

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

use kob_domain::batch::{
    plan_batch_match, plan_batch_match_at, plan_ioc_match, BatchOrder, BatchPlan, OrderType,
    OutputPurpose,
};
use kob_domain::time_planner::{compose_settle_and_ratchet, plan_ratchet_advance, RatchetOrderRef};

const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";
const TOKEN_HEX: &str = "0c113120cb56668a5aa984752496f8cc4ac65e9044f2fa85d64e7bbcb5fc6039";

fn arr32(hex: &str) -> [u8; 32] {
    let b = hex::decode(hex).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}
fn p2pk_spk_bytes(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(pubkey);
    s.push(0xac);
    s
}

/// Execute covenant inputs `0..covenant_count` under the SAME per-input
/// script-units budget the node commits at consensus: `EngineFlags` carries
/// no override here (default free allowance), and each input's limit is
/// `input.compute_commit.allowed_script_units()` -- i.e. whatever
/// `sig_op_count` the tx itself carries, exactly as
/// `tx_validation_in_utxo_context::check_scripts` computes it. This is the
/// ONE difference from `planner_engine_repro.rs`'s
/// `exec_covenant_inputs`, which runs every input at `ScriptUnits(u64::MAX)`.
fn exec_covenant_inputs_budgeted(
    tx: &Transaction,
    entries: Vec<UtxoEntry>,
    covenant_count: usize,
) -> Vec<(usize, String)> {
    let populated = PopulatedTransaction::new(tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext::from_tx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let mut failures = Vec::new();
    for idx in 0..covenant_count {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        // Node accounting, verbatim: allowed_script_units() = ScriptUnits::from(compute_commit)
        // + free_script_units_per_input() (9,999).
        let script_units_limit = input.compute_commit.allowed_script_units();
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            input,
            idx,
            entry,
            ctx,
            flags,
            script_units_limit,
        );
        if let Err(e) = vm.execute() {
            failures.push((idx, format!("{e:?}")));
        }
    }
    failures
}

fn make_sell(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32], owner: &[u8; 32], sspkh: &[u8; 32]) -> BatchOrder {
    let rs = kob_core::contract::spot::order::build_sell_redeem_script(
        price_num, price_den, 1_000_000, owner, sspkh, &[0xDD; 32], 30, 0, 0,
    ).unwrap();
    BatchOrder {
        outpoint: (hex::encode([id_byte; 32]), 0),
        order_type: OrderType::Sell,
        version: 18,
        token_cov_id: token,
        price_num,
        price_den,
        amount,
        redeem_script: rs,
        utxo_value: amount,
        counterparty_spk: p2pk_spk_bytes(&arr32(PUBKEY_HEX)),
        counterparty_spk_version: 0,
        min_fill: 1_000_000,
        oco_path: None,
        bracket_meta: None,
    }
}

fn make_oco_sell(id_byte: u8, amount: u64, tp: (u64, u64), sl: (u64, u64), path: kob_core::OcoPath, token: [u8; 32], owner: &[u8; 32], sspkh: &[u8; 32]) -> BatchOrder {
    let rs = kob_core::contract::spot::oco::build_oco_sell_redeem_script(
        tp.0, tp.1, 1, sl.0, sl.1, 1, owner, sspkh, &[0xDD; 32], 30, 0, 0,
    ).unwrap();
    let (pn, pd) = match path {
        kob_core::OcoPath::TakeProfit => tp,
        kob_core::OcoPath::StopLoss => sl,
    };
    BatchOrder {
        outpoint: (hex::encode([id_byte; 32]), 0),
        order_type: OrderType::Sell,
        version: 18,
        token_cov_id: token,
        price_num: pn,
        price_den: pd,
        amount,
        redeem_script: rs,
        utxo_value: amount,
        counterparty_spk: p2pk_spk_bytes(&arr32(PUBKEY_HEX)),
        counterparty_spk_version: 0,
        min_fill: 1,
        oco_path: Some(path),
        bracket_meta: None,
    }
}

fn make_buy(id_byte: u8, amount: u64, price_num: u64, price_den: u64, min_fill: u64, token: [u8; 32], owner: &[u8; 32], bspkh: &[u8; 32], mmfee_bps: u64) -> BatchOrder {
    let rs = kob_core::contract::spot::order::build_buy_redeem_script(
        &token, price_num, price_den, min_fill, owner, bspkh, &[0xDD; 32], mmfee_bps, 0, 0,
    ).unwrap();
    BatchOrder {
        outpoint: (hex::encode([id_byte; 32]), 0),
        order_type: OrderType::Buy,
        version: 18,
        token_cov_id: token,
        price_num,
        price_den,
        amount,
        redeem_script: rs,
        utxo_value: amount,
        counterparty_spk: p2pk_spk_bytes(&arr32(PUBKEY_HEX)),
        counterparty_spk_version: 0,
        min_fill,
        oco_path: None,
        bracket_meta: None,
    }
}

fn make_decay_sell(id_byte: u8, amount: u64, token: [u8; 32], owner: &[u8; 32], sspkh: &[u8; 32]) -> BatchOrder {
    let rs = kob_core::contract::spot::decay::build_decay_sell_redeem_script(
        1000, 1000, 2000, 2_000_000, 1_000_000, 1_000_000, owner, sspkh, &[0xDD; 32], 30, 0, 0,
    ).unwrap();
    let mut o = make_sell(id_byte, amount, 2_000_000, 1_000_000, token, owner, sspkh);
    o.redeem_script = rs;
    o
}

fn make_twap_sell(id_byte: u8, amount: u64, twin: u64, mpw: u64, price: (u64, u64), token: [u8; 32], owner: &[u8; 32], sspkh: &[u8; 32]) -> BatchOrder {
    let rs = kob_core::contract::spot::twap::build_twap_sell_redeem_script(
        twin, mpw, price.0, price.1, 1_000_000, owner, sspkh, &[0xDD; 32], 30, 0, 0,
    ).unwrap();
    let mut o = make_sell(id_byte, amount, price.0, price.1, token, owner, sspkh);
    o.redeem_script = rs;
    o
}

fn make_ratchet_tp_sell(id_byte: u8, amount: u64, token: [u8; 32], owner: &[u8; 32], sspkh: &[u8; 32]) -> BatchOrder {
    let rs = kob_core::contract::spot::ratchet::build_ratchet_oco_redeem_script(
        1, 0, 60, 1_000_000, 5, 1, 1, 2, 1, 1, owner, sspkh, &[0xDD; 32], 30, 0, 0,
    ).unwrap();
    let mut o = make_sell(id_byte, amount, 5, 1, token, owner, sspkh);
    o.redeem_script = rs;
    o.oco_path = Some(kob_core::OcoPath::TakeProfit);
    o.min_fill = 1;
    o
}

/// Reconstruct the on-chain tx from a spot `BatchPlan`, using the PLAN'S OWN
/// `sig_op_count` per input (not a hardcoded stand-in) so the budgeted
/// engine run enforces exactly what the node would commit for this tx.
fn run_spot_plan_budgeted(plan: &BatchPlan, wallet_value: u64) -> Vec<(usize, String)> {
    let token_cov_id = Hash::from_bytes(plan.sells[0].0.token_cov_id);
    let wallet_spk = ScriptPublicKey::new(0, p2pk_spk_bytes(&arr32(PUBKEY_HEX)).into());
    let batch_tx = plan.build_tx().expect("build_tx");

    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for ((order, _idx), batch_input) in plan.sells.iter().zip(batch_tx.inputs.iter()) {
        let outpoint = TransactionOutpoint::new(
            kob_core::parse_hash(&batch_input.tx_id).unwrap(),
            batch_input.index,
        );
        inputs.push(TransactionInput::new(
            outpoint,
            batch_input.sigscript.clone(),
            batch_input.sequence,
            batch_input.sig_op_count,
        ));
        entries.push(UtxoEntry {
            amount: order.utxo_value,
            script_public_key: kob_core::build_p2sh(&order.redeem_script),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token_cov_id),
        });
    }
    let buy = &plan.buys[0].0;
    let buy_batch_input = &batch_tx.inputs[plan.sells.len()];
    let buy_outpoint = TransactionOutpoint::new(
        kob_core::parse_hash(&buy_batch_input.tx_id).unwrap(),
        buy_batch_input.index,
    );
    inputs.push(TransactionInput::new(
        buy_outpoint,
        buy_batch_input.sigscript.clone(),
        buy_batch_input.sequence,
        buy_batch_input.sig_op_count,
    ));
    entries.push(UtxoEntry {
        amount: buy.utxo_value,
        script_public_key: kob_core::build_p2sh(&buy.redeem_script),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });
    // Wallet placeholder input (not executed; sig_op_count irrelevant).
    inputs.push(TransactionInput::new(
        TransactionOutpoint::new(Hash::from_bytes([0x30; 32]), 0),
        vec![0x41; 66],
        0,
        1,
    ));
    entries.push(UtxoEntry {
        amount: wallet_value,
        script_public_key: wallet_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });

    let mut outputs = Vec::new();
    for (i, o) in plan.outputs.iter().enumerate() {
        let spk = ScriptPublicKey::new(o.spk_version, o.script_public_key.clone().into());
        let covenant = if o.purpose == OutputPurpose::BuyerTokens {
            plan.output_auth_input
                .get(&i)
                .map(|&auth| CovenantBinding::new(auth, token_cov_id))
        } else {
            None
        };
        outputs.push(TransactionOutput::with_covenant(o.value, spk, covenant));
    }

    let tx = Transaction::new(1, inputs, outputs, plan.lock_time, Default::default(), 0, vec![]);
    let covenant_count = plan.sells.len() + 1;
    exec_covenant_inputs_budgeted(&tx, entries, covenant_count)
}

// ── Primary shapes: production sig_op_count, real node budget ──

#[test]
fn gtc_sweep_budgeted_passes_real_node_accounting() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);

    let sells = vec![
        make_sell(0x10, 10_000_000, 99, 100, token, &owner_hash, &spk_hash),
        make_sell(0x11, 20_000_000, 99, 100, token, &owner_hash, &spk_hash),
    ];
    let buys = vec![make_buy(0x20, 30_000_000, 1, 1, 1_000_000, token, &owner_hash, &spk_hash, 2000)];
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));

    let plan = plan_batch_match(&sells, &buys, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("v18 GTC sweep must plan");
    let failures = run_spot_plan_budgeted(&plan, 5_000_000);
    assert!(failures.is_empty(), "GTC sweep must pass under the node's real per-input budget; failures: {failures:?}");
}

#[test]
fn ioc_sweep_budgeted_passes_real_node_accounting() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);

    let sell1 = make_sell(0x10, 10_000_000, 1, 1, token, &owner_hash, &spk_hash);
    let sell2 = make_sell(0x11, 10_000_000, 1, 1, token, &owner_hash, &spk_hash);
    let buy = make_buy(0x20, 20_400_000, 1, 1, 1_000_000, token, &owner_hash, &spk_hash, 2000);
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));

    let plan = plan_ioc_match(&[sell1, sell2], &buy, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("v18 IOC sweep must plan");
    let failures = run_spot_plan_budgeted(&plan, 5_000_000);
    assert!(failures.is_empty(), "IOC sweep must pass under the node's real per-input budget; failures: {failures:?}");
}

#[test]
fn oco_sl_sweep_budgeted_passes_real_node_accounting() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);

    let sells = vec![
        make_sell(0x10, 10_000_000, 99, 100, token, &owner_hash, &spk_hash),
        make_oco_sell(
            0x11, 10_000_000, (3, 1), (99, 100), kob_core::OcoPath::StopLoss,
            token, &owner_hash, &spk_hash,
        ),
    ];
    let buys = vec![make_buy(0x20, 20_000_000, 1, 1, 1_000_000, token, &owner_hash, &spk_hash, 2000)];
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));

    let plan = plan_batch_match(&sells, &buys, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("v18 GTC sweep with OCO-SL term must plan");
    let failures = run_spot_plan_budgeted(&plan, 5_000_000);
    assert!(failures.is_empty(), "OCO-SL sweep must pass under the node's real per-input budget; failures: {failures:?}");
}

#[test]
fn decay_sweep_budgeted_passes_real_node_accounting() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));

    for (l, kas, price) in [
        (0u64, 20_000_000u64, (1u64, 2u64)),
        (1500, 15_000_000, (2, 3)),
        (2500, 10_000_000, (1, 1)),
    ] {
        let sells = vec![make_decay_sell(0x10, 10_000_000, token, &owner_hash, &spk_hash)];
        let buys = vec![make_buy(0x20, kas, price.0, price.1, 1_000_000, token, &owner_hash, &spk_hash, 2000)];
        let plan = plan_batch_match_at(&sells, &buys, wallet.clone(), &p2pk_spk_bytes(&pubkey), 0, Some(2000), l)
            .expect("decay sweep must plan at every schedule point");
        let failures = run_spot_plan_budgeted(&plan, 5_000_000);
        assert!(failures.is_empty(), "decay sweep at L={l} must pass under the node's real per-input budget; failures: {failures:?}");
    }
}

#[test]
fn twap_sweep_budgeted_passes_real_node_accounting() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);

    let sells = vec![
        make_twap_sell(0x10, 10_000_000, 100, 10_000_000, (1, 1), token, &owner_hash, &spk_hash),
        make_sell(0x11, 10_000_000, 99, 100, token, &owner_hash, &spk_hash),
    ];
    let buys = vec![make_buy(0x20, 19_900_000, 1, 1, 1_000_000, token, &owner_hash, &spk_hash, 2000)];
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));
    let plan = plan_batch_match(&sells, &buys, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("CP-2 twap sweep must plan");
    let failures = run_spot_plan_budgeted(&plan, 5_000_000);
    assert!(failures.is_empty(), "twap sweep must pass under the node's real per-input budget; failures: {failures:?}");
}

#[test]
fn cp3_ratchet_tp_sweep_budgeted_passes_real_node_accounting() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);

    let sells = vec![
        make_ratchet_tp_sell(0x10, 5_000_000, token, &owner_hash, &spk_hash),
        make_sell(0x11, 10_000_000, 99, 100, token, &owner_hash, &spk_hash),
    ];
    let buys = vec![make_buy(0x20, 34_900_000, 3, 7, 1_000_000, token, &owner_hash, &spk_hash, 2000)];
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));
    let plan = plan_batch_match(&sells, &buys, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("CP-3 ratchet-TP sweep must plan");
    let failures = run_spot_plan_budgeted(&plan, 5_000_000);
    assert!(failures.is_empty(), "CP-3 ratchet-TP sweep must pass under the node's real per-input budget; failures: {failures:?}");
}

// ── The actual 2026-07-18 regression shape: settle + ratchet advance ──

/// Build the composed settle+ratchet tx (inputs/entries/outputs) exactly as
/// `settle_plus_ratchet_combined_tx_real_engine` does in
/// `planner_engine_repro.rs`, but return the pieces so both the "as-planned"
/// (positive) and "forced sig_op_count=0" (negative) variants can share the
/// construction.
struct ComposedRatchetTx {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

fn build_settle_plus_ratchet(sig_op_count_override: Option<u8>) -> ComposedRatchetTx {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let token_hash = Hash::from_bytes(token);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = ScriptPublicKey::new(0, p2pk_spk_bytes(&pubkey).into());

    let sells = vec![make_sell(0x10, 10_000_000, 3, 1, token, &owner_hash, &spk_hash)];
    let buys = vec![make_buy(0x20, 30_000_000, 1, 3, 1_000_000, token, &owner_hash, &spk_hash, 2000)];
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));
    let plan = plan_batch_match(&sells, &buys, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("settle must plan");

    let ratchet_rs = kob_core::contract::spot::ratchet::build_ratchet_oco_redeem_script(
        1, 0, 60, 1_000_000, 5, 1, 1, 2, 1, 1, &owner_hash, &spk_hash, &[0xDD; 32], 30, 0, 0,
    ).unwrap();
    let oco = RatchetOrderRef {
        outpoint: (hex::encode([0x40u8; 32]), 0),
        redeem_script: ratchet_rs.clone(),
        escrow: 5_000_000,
        utxo_daa_score: 0,
        token_cov_id: token,
    };
    let mut adv = plan_ratchet_advance(&oco, &plan, 100).expect("ratchet advance must plan");
    if let Some(soc) = sig_op_count_override {
        // Force the ratchet input's committed budget directly -- this is the
        // 2026-07-18 bug shape (sig_op_count=0, i.e. only the 9,999-unit free
        // allowance) reproduced without touching production source.
        adv.input.sig_op_count = soc;
    }
    let composed = compose_settle_and_ratchet(&plan, &adv).expect("compose");

    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for bi in &composed.inputs {
        let outpoint = TransactionOutpoint::new(kob_core::parse_hash(&bi.tx_id).unwrap(), bi.index);
        let ss = if bi.sigscript.is_empty() { vec![0x41; 66] } else { bi.sigscript.clone() };
        inputs.push(TransactionInput::new(outpoint, ss, bi.sequence, bi.sig_op_count));
    }
    entries.push(UtxoEntry {
        amount: 10_000_000,
        script_public_key: kob_core::build_p2sh(&plan.sells[0].0.redeem_script),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(token_hash),
    });
    entries.push(UtxoEntry {
        amount: 30_000_000,
        script_public_key: kob_core::build_p2sh(&plan.buys[0].0.redeem_script),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });
    entries.push(UtxoEntry {
        amount: 5_000_000,
        script_public_key: kob_core::build_p2sh(&ratchet_rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(token_hash),
    });
    entries.push(UtxoEntry {
        amount: 5_000_000,
        script_public_key: wallet_spk,
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });

    let mut outputs = Vec::new();
    for (i, o) in composed.outputs.iter().enumerate() {
        let spk = ScriptPublicKey::new(o.spk_version, o.script_public_key.clone().into());
        let covenant = match o.purpose {
            OutputPurpose::BuyerTokens => plan
                .output_auth_input
                .get(&i)
                .map(|&auth| CovenantBinding::new(auth, token_hash)),
            OutputPurpose::RatchetContinuation => {
                Some(CovenantBinding::new(adv.input_position as u16, token_hash))
            }
            _ => None,
        };
        outputs.push(TransactionOutput::with_covenant(o.value, spk, covenant));
    }

    let tx = Transaction::new(1, inputs, outputs, plan.lock_time, Default::default(), 0, vec![]);
    ComposedRatchetTx { tx, entries }
}

/// THE regression: the composed settle+ratchet-advance tx, executed under
/// the node's real per-input budget (not unlimited), with the PRODUCTION
/// `plan_ratchet_advance` sig_op_count (currently 1, fixed 2026-07-18). Must
/// pass -- this is the exact shape that failed live before the fix.
#[test]
fn settle_plus_ratchet_advance_budgeted_passes_real_node_accounting() {
    let built = build_settle_plus_ratchet(None); // production sig_op_count (1)
    let failures = exec_covenant_inputs_budgeted(&built.tx, built.entries, 3); // sell + buy + ratchet
    assert!(
        failures.is_empty(),
        "settle+ratchet-advance must pass under the node's real per-input script-units budget \
         (production sig_op_count); failures: {failures:?}"
    );
}

/// Negative control, independent of production source state: force the
/// ratchet input's committed budget back to the historical bug value
/// (sig_op_count=0, i.e. only the 9,999-unit free allowance) and confirm the
/// budgeted engine rejects it with `ExceededCommittedScriptUnits` -- proving
/// this harness actually detects the hole rather than passing vacuously.
#[test]
fn settle_plus_ratchet_advance_budgeted_fails_when_underbudgeted() {
    let built = build_settle_plus_ratchet(Some(0)); // historical bug: sig_op_count=0
    let failures = exec_covenant_inputs_budgeted(&built.tx, built.entries, 3);
    assert!(
        !failures.is_empty(),
        "sig_op_count=0 on the ratchet input must fail under the node's real budget \
         (9,999 free units vs ~10,311 measured live usage) -- got no failures, budget \
         enforcement is not actually wired"
    );
    let (idx, msg) = &failures[0];
    assert_eq!(*idx, 2, "the ratchet input (position 2: sell, buy, ratchet) must be the one that fails");
    assert!(
        msg.contains("ExceededCommittedScriptUnits"),
        "must fail specifically on the script-units budget, not some other cause; got: {msg}"
    );
}
