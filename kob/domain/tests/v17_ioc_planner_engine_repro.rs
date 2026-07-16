//! v17 IOC N:M sweep planner (`plan_ioc_match_v17`) -- proves the ACTUAL
//! `BatchPlan::build_tx()` output (not a hand-built stand-in) round-trips
//! through the real post-Toccata `kaspa-txscript` `TxScriptEngine`. The
//! contract bytecode itself is unchanged and already adversarially proven in
//! `kob-core`'s `tests/v17_nm_buy.rs` (`m15_ioc_within_cap_passes` /
//! `m15b_ioc_underdelivery_theft_rejected`); this test closes the remaining
//! gap -- that the PLANNER composes the honest tx shape those tests assume.

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

use kob_domain::batch::{plan_ioc_match_v17, BatchOrder, OrderType, OutputPurpose};

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

fn make_sell(id_byte: u8, amount: u64, price_num: u64, price_den: u64, token: [u8; 32], owner: &[u8; 32], sspkh: &[u8; 32]) -> BatchOrder {
    let tx_id = hex::encode([id_byte; 32]);
    let rs = kob_core::contract::build_sell_redeem_script(
        price_num, price_den, 1_000_000, owner, sspkh, 10_000_000, 0, 0,
    ).unwrap();
    BatchOrder {
        outpoint: (tx_id, 0),
        order_type: OrderType::Sell,
        version: 14,
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

fn make_buy_v17(id_byte: u8, amount: u64, price_num: u64, price_den: u64, min_fill: u64, token: [u8; 32], owner: &[u8; 32], bspkh: &[u8; 32], mmfee_bps: u64) -> BatchOrder {
    let tx_id = hex::encode([id_byte; 32]);
    let rs = kob_core::contract::spot::order::build_buy_v17_redeem_script(
        &token, price_num, price_den, min_fill, owner, bspkh, mmfee_bps, 0, 0,
    ).unwrap();
    BatchOrder {
        outpoint: (tx_id, 0),
        order_type: OrderType::Buy,
        version: 17,
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

/// Honest v17 IOC sweep, planned by `plan_ioc_match_v17`, built by
/// `BatchPlan::build_tx()`, executed against the real engine end to end.
#[test]
fn v17_ioc_planner_honest_sweep_passes_real_engine() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let token_cov_id = Hash::from_bytes(token);
    let owner_hash = kob_core::blake2b_256(&pubkey);
    let spk_hash = kob_core::compute_p2pk_spk_hash(&pubkey);

    // Buy affords sell1 (10M) + sell2 (10M) exactly, at price 1/1 with a
    // small 2000bps (20%) cap headroom via a slight KAS surplus.
    let sell1 = make_sell(0x10, 10_000_000, 1, 1, token, &owner_hash, &spk_hash);
    let sell2 = make_sell(0x11, 10_000_000, 1, 1, token, &owner_hash, &spk_hash);
    let buy = make_buy_v17(0x20, 20_400_000, 1, 1, 1_000_000, token, &owner_hash, &spk_hash, 2000);
    let wallet = Some((hex::encode([0x30u8; 32]), 0u32, 5_000_000u64));

    let plan = plan_ioc_match_v17(&[sell1, sell2], &buy, wallet, &p2pk_spk_bytes(&pubkey), 0, Some(2000))
        .expect("v17 IOC sweep must plan");
    assert_eq!(plan.sells.len(), 2, "both sells should be swept");

    let batch_tx = plan.build_tx().expect("build_tx");

    // Reconstruct the on-chain tx: inputs [sell1, sell2, buy, wallet],
    // outputs per the plan, with covenant bindings for BuyerTokens.
    // Outpoints come straight from build_tx()'s own tx_id/index (parsed via
    // kob_core's own hex<->Hash helper), so this is byte-for-byte the same
    // input identity the planner produced -- no hand-reconstruction drift.
    let wallet_spk = ScriptPublicKey::new(0, p2pk_spk_bytes(&pubkey).into());

    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for (sell, batch_input) in plan.sells.iter().zip(batch_tx.inputs.iter()) {
        let (order, _idx) = sell;
        let p2sh = kob_core::build_p2sh(&order.redeem_script);
        let outpoint = TransactionOutpoint::new(kob_core::parse_hash(&batch_input.tx_id).unwrap(), batch_input.index);
        inputs.push(TransactionInput::new(outpoint, batch_input.sigscript.clone(), 50, 0));
        entries.push(UtxoEntry { amount: order.utxo_value, script_public_key: p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) });
    }
    let buy_batch_input = &batch_tx.inputs[plan.sells.len()];
    let buy_p2sh = kob_core::build_p2sh(&buy.redeem_script);
    let buy_outpoint = TransactionOutpoint::new(kob_core::parse_hash(&buy_batch_input.tx_id).unwrap(), buy_batch_input.index);
    inputs.push(TransactionInput::new(buy_outpoint, buy_batch_input.sigscript.clone(), 50, 0));
    entries.push(UtxoEntry { amount: buy.utxo_value, script_public_key: buy_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: None });
    // wallet placeholder input (not executed)
    let wallet_outpoint = TransactionOutpoint::new(Hash::from_bytes([0x30; 32]), 0);
    inputs.push(TransactionInput::new(wallet_outpoint, vec![0x41; 66], 0, 1));
    entries.push(UtxoEntry { amount: 5_000_000, script_public_key: wallet_spk.clone(), block_daa_score: 0, is_coinbase: false, covenant_id: None });

    let mut outputs = Vec::new();
    for (i, o) in plan.outputs.iter().enumerate() {
        let spk = ScriptPublicKey::new(o.spk_version, o.script_public_key.clone().into());
        let covenant = if o.purpose == OutputPurpose::BuyerTokens {
            plan.output_auth_input.get(&i).map(|&auth| CovenantBinding::new(auth, token_cov_id))
        } else {
            None
        };
        outputs.push(TransactionOutput::with_covenant(o.value, spk, covenant));
    }

    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext::from_tx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };

    let wallet_idx = populated.inputs().len() - 1; // wallet: not a covenant script
    let mut failures = Vec::new();
    for idx in 0..wallet_idx {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        if let Err(e) = vm.execute() {
            failures.push((idx, format!("{e:?}")));
        }
    }
    assert!(failures.is_empty(), "v17 IOC planner's honest sweep must pass the real engine; failures: {failures:?}");
}
