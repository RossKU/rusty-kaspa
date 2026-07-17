//! v18 planners -- prove the ACTUAL `BatchPlan::build_tx()` /
//! `RingPlan::build_tx()` output (not a hand-built stand-in) round-trips
//! through the real post-Toccata `kaspa-txscript` `TxScriptEngine` for every
//! new v18 planner: GTC N:1 sweep (incl. an OCO-SL term), IOC N:1 sweep,
//! Op2 partial (two chained events), and 2-/3-cycle rings. The contract
//! bytecode itself is engine-proven adversarially in `kob-core`'s
//! `tests/v18_spot.rs`; this file closes the remaining gap -- that the
//! PLANNERS compose the honest tx shapes those tests assume.

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
    plan_batch_match, plan_ioc_match, plan_partial_match, plan_ring_match, BatchOrder,
    BatchPlan, OrderType, OutputPurpose, RingLegOrder,
};

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

/// Execute all covenant inputs (`0..covenant_count`) of a populated tx.
fn exec_covenant_inputs(
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
        let mut vm =
            TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
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

/// Reconstruct the on-chain tx from a spot BatchPlan (inputs: sells.., buy,
/// wallet; outputs: per plan with BuyerTokens covenant bindings) and run all
/// covenant inputs through the engine.
fn run_spot_plan(plan: &BatchPlan, wallet_value: u64) -> Vec<(usize, String)> {
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
        inputs.push(TransactionInput::new(outpoint, batch_input.sigscript.clone(), 50, 0));
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
    inputs.push(TransactionInput::new(buy_outpoint, buy_batch_input.sigscript.clone(), 50, 0));
    entries.push(UtxoEntry {
        amount: buy.utxo_value,
        script_public_key: kob_core::build_p2sh(&buy.redeem_script),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });
    // Wallet placeholder input (not executed).
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
            None // SellerKas / BuyResidual / BuyerChange / MatcherFee: plain
        };
        outputs.push(TransactionOutput::with_covenant(o.value, spk, covenant));
    }

    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let covenant_count = plan.sells.len() + 1; // sells + buy
    exec_covenant_inputs(&tx, entries, covenant_count)
}

/// v18 GTC N:1 sweep planned by `plan_batch_match` (v18 dispatch), executed
/// end-to-end against the real engine.
#[test]
fn gtc_planner_sweep_passes_real_engine() {
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
    assert_eq!(plan.sells.len(), 2);
    let failures = run_spot_plan(&plan, 5_000_000);
    assert!(failures.is_empty(), "v18 GTC planner tx must pass the real engine; failures: {failures:?}");
}

/// D2 delivery re-wrap: a v18 buy whose bspkh commits the buyer's token_unit
/// P2SH SPK (the production deploy shape after D2) plans, delivers every
/// BuyerTokens output on exactly that P2SH, and passes the real engine.
#[test]
fn gtc_planner_token_unit_delivery_passes_real_engine() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let sell_spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);

    // Buyer delivery endpoint: token_unit P2SH (KCC20 Standard State Header).
    let buy_spk_hash = kob_core::contract::compute_token_unit_spk_hash(&pubkey);
    let token_unit_spk = kob_core::contract::build_token_unit_p2sh_spk(&pubkey);

    let sells = vec![
        make_sell(0x10, 10_000_000, 99, 100, token, &owner_hash, &sell_spk_hash),
        make_sell(0x11, 20_000_000, 99, 100, token, &owner_hash, &sell_spk_hash),
    ];
    let mut buy = make_buy(0x20, 30_000_000, 1, 1, 1_000_000, token, &owner_hash, &buy_spk_hash, 2000);
    buy.counterparty_spk = token_unit_spk.script().to_vec();
    buy.counterparty_spk_version = token_unit_spk.version();
    let buys = vec![buy];
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));

    let plan = plan_batch_match(&sells, &buys, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("v18 GTC sweep with token_unit delivery must plan");
    assert_eq!(plan.sells.len(), 2);

    // Every BuyerTokens output must land on the buyer's token_unit P2SH and
    // hash to the committed bspkh.
    let mut buyer_token_outputs = 0;
    for o in &plan.outputs {
        if o.purpose == OutputPurpose::BuyerTokens {
            buyer_token_outputs += 1;
            assert_eq!(o.script_public_key, token_unit_spk.script().to_vec(), "delivery SPK must be the token_unit P2SH");
            assert_eq!(o.spk_version, token_unit_spk.version(), "delivery SPK version");
            assert_eq!(
                kob_core::p2sh::compute_spk_hash(o.spk_version, &o.script_public_key),
                buy_spk_hash,
                "delivery SPK must hash to the committed bspkh"
            );
        }
    }
    assert!(buyer_token_outputs >= 1, "plan must contain BuyerTokens outputs");

    let failures = run_spot_plan(&plan, 5_000_000);
    assert!(failures.is_empty(), "v18 token_unit delivery tx must pass the real engine; failures: {failures:?}");
}

/// v18 GTC sweep with an OCO-SL term (OCO sweep enablement, the historic
/// blocker): the OCO input executes its SL branch at the attested SL price.
#[test]
fn gtc_planner_oco_sl_sweep_passes_real_engine() {
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
    let failures = run_spot_plan(&plan, 5_000_000);
    assert!(failures.is_empty(), "v18 OCO-SL sweep tx must pass the real engine; failures: {failures:?}");
}

/// v18 IOC sweep planned by `plan_ioc_match`, executed end-to-end.
#[test]
fn ioc_planner_sweep_passes_real_engine() {
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
    assert_eq!(plan.sells.len(), 2, "both sells swept");
    let failures = run_spot_plan(&plan, 5_000_000);
    assert!(failures.is_empty(), "v18 IOC planner tx must pass the real engine; failures: {failures:?}");
}

/// v18 Op2 partial planned by `plan_partial_match` — TWO chained events:
/// event 2 spends the residual UTXO (same RS, new amount) as a normal v18
/// buy again, proving cross-tx chaining with the planner's own shapes.
#[test]
fn partial_planner_chains_two_events_real_engine() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);
    let matcher = p2pk_spk_bytes(&pubkey);
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));

    // Event 1: 30M buy spends 10M against a 10M-token sell, keeps 20M.
    let sell1 = make_sell(0x10, 10_000_000, 99, 100, token, &owner_hash, &spk_hash);
    let buy1 = make_buy(0x20, 30_000_000, 1, 1, 1_000_000, token, &owner_hash, &spk_hash, 2000);
    let plan1 = plan_partial_match(&[sell1], &buy1, wallet.clone(), &matcher, 0, None)
        .expect("partial event 1 must plan");
    let &(spent1, ri1, _) = plan1.buy_partial_fills.get(&0).expect("partial entry");
    let residual1 = plan1.outputs[ri1 as usize].value;
    assert_eq!(spent1, 10_000_000);
    assert_eq!(residual1, 20_000_000);
    let failures = run_spot_plan(&plan1, 5_000_000);
    assert!(failures.is_empty(), "partial event 1 must pass the real engine; failures: {failures:?}");

    // Event 2: the residual UTXO (same RS => same P2SH) is a normal v18 buy
    // again; spend 15M of it against a 15M-token sell, keep 5M.
    let sell2 = make_sell(0x11, 15_000_000, 99, 100, token, &owner_hash, &spk_hash);
    let mut buy2 = make_buy(0x21, residual1, 1, 1, 1_000_000, token, &owner_hash, &spk_hash, 2000);
    buy2.redeem_script = buy1.redeem_script.clone(); // byte-exact continuation
    let plan2 = plan_partial_match(&[sell2], &buy2, wallet, &matcher, 0, None)
        .expect("partial event 2 must plan on the residual");
    let &(spent2, ri2, _) = plan2.buy_partial_fills.get(&0).expect("partial entry");
    assert_eq!(spent2, 15_000_000);
    assert_eq!(plan2.outputs[ri2 as usize].value, 5_000_000);
    let failures = run_spot_plan(&plan2, 5_000_000);
    assert!(failures.is_empty(), "partial event 2 (chained) must pass the real engine; failures: {failures:?}");
}

// ── Rings ──

fn ring_owner_spk(seed: u8) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(&[seed; 32]);
    s.push(0xac);
    s
}

fn make_ring_leg(id_byte: u8, source: [u8; 32], target: [u8; 32], amount: u64, min_target: u64, mmfee_bps: u64, owner_seed: u8) -> RingLegOrder {
    let owner_spk = ring_owner_spk(owner_seed);
    let owner_spk_hash = kob_core::p2sh::compute_spk_hash(0, &owner_spk);
    let rs = kob_core::contract::spot::swap::build_swap_redeem_script(
        &source, &target, min_target, &[0xBB; 32], &owner_spk_hash, &[0xEE; 32], mmfee_bps,
    ).unwrap();
    RingLegOrder {
        outpoint: (hex::encode([id_byte; 32]), 0),
        redeem_script: rs,
        utxo_value: amount,
        owner_spk,
        owner_spk_version: 0,
    }
}

/// Reconstruct the on-chain ring tx from a RingPlan and run all leg inputs.
fn run_ring_plan(legs: &[RingLegOrder], wallet_value: u64) -> Vec<(usize, String)> {
    let pubkey = arr32(PUBKEY_HEX);
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, wallet_value));
    let plan = plan_ring_match(legs, wallet, &p2pk_spk_bytes(&pubkey), 0)
        .expect("ring must plan");
    plan.validate().expect("ring plan must balance");
    let batch_tx = plan.build_tx().expect("ring build_tx");

    let n = legs.len();
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for (i, leg) in legs.iter().enumerate() {
        let outpoint = TransactionOutpoint::new(
            kob_core::parse_hash(&batch_tx.inputs[i].tx_id).unwrap(),
            batch_tx.inputs[i].index,
        );
        inputs.push(TransactionInput::new(outpoint, batch_tx.inputs[i].sigscript.clone(), 50, 0));
        entries.push(UtxoEntry {
            amount: leg.utxo_value,
            script_public_key: kob_core::build_p2sh(&leg.redeem_script),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(Hash::from_bytes(plan.leg_source_tokens[i])),
        });
    }
    // Wallet placeholder (not executed).
    inputs.push(TransactionInput::new(
        TransactionOutpoint::new(Hash::from_bytes([0x30; 32]), 0),
        vec![0x41; 66],
        0,
        1,
    ));
    entries.push(UtxoEntry {
        amount: wallet_value,
        script_public_key: ScriptPublicKey::new(0, p2pk_spk_bytes(&pubkey).into()),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });

    let mut outputs = Vec::new();
    for (i, o) in plan.outputs.iter().enumerate() {
        let spk = ScriptPublicKey::new(o.spk_version, o.script_public_key.clone().into());
        let covenant = plan.output_auth_input.get(&i).map(|&auth| {
            CovenantBinding::new(auth, Hash::from_bytes(plan.leg_source_tokens[auth as usize]))
        });
        outputs.push(TransactionOutput::with_covenant(o.value, spk, covenant));
    }

    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    exec_covenant_inputs(&tx, entries, n)
}

const RING_A: [u8; 32] = [0xA1; 32];
const RING_B: [u8; 32] = [0xA2; 32];
const RING_C: [u8; 32] = [0xA3; 32];

/// 2-cycle token<->token ring planned by `plan_ring_match` (with matcher
/// skims at the per-leg F4 cap), executed end-to-end.
#[test]
fn ring_planner_2cycle_passes_real_engine() {
    let (a0, a1) = (1_000_000_000u64, 2_000_000_000u64);
    let fee = |a: u64| a / 10000 * 100;
    let legs = vec![
        make_ring_leg(0x60, RING_A, RING_B, a0, a1 - fee(a1), 100, 0xF0),
        make_ring_leg(0x61, RING_B, RING_A, a1, a0 - fee(a0), 100, 0xF1),
    ];
    let failures = run_ring_plan(&legs, 5_000_000);
    assert!(failures.is_empty(), "2-cycle ring planner tx must pass the real engine; failures: {failures:?}");
}

/// 3-cycle triangle ring planned by `plan_ring_match`, executed end-to-end.
#[test]
fn ring_planner_3cycle_passes_real_engine() {
    let amounts = [1_000_000_000u64, 2_000_000_000, 3_000_000_000];
    let fee = |a: u64| a / 10000 * 100;
    let legs = vec![
        make_ring_leg(0x60, RING_A, RING_B, amounts[0], amounts[1] - fee(amounts[1]), 100, 0xF0),
        make_ring_leg(0x61, RING_B, RING_C, amounts[1], amounts[2] - fee(amounts[2]), 100, 0xF1),
        make_ring_leg(0x62, RING_C, RING_A, amounts[2], amounts[0] - fee(amounts[0]), 100, 0xF2),
    ];
    let failures = run_ring_plan(&legs, 5_000_000);
    assert!(failures.is_empty(), "3-cycle ring planner tx must pass the real engine; failures: {failures:?}");
}
