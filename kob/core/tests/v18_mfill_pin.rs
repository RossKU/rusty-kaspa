//! Pin: the v18 buy `min_fill` is a floor on TOKENS, not KAS.
//!
//! Section E of `emit_fill_body_v18` verifies `expected >= mfill` where
//! `expected = kas_in / pden * pnum` (tokens at the buy limit). A GTC buy
//! whose min_fill exceeds its own full expected-token count can never fill
//! (first hit live on testnet-10, 2026-07-16: a 30M-KAS buy at 3/4 with
//! min_fill=30M — expected tokens 22.5M < 30M — was correctly rejected by
//! the node in an OCO-SL sweep; same shape passes once min_fill is a valid
//! token floor). The multi-sell OCO-SL sweep shape itself is fine.

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

use kob_core::contract::spot::oco::{
    build_oco_sell_v18_redeem_script, build_oco_sell_v18_sl_fill_sigscript,
};
use kob_core::contract::spot::order::{
    build_buy_v18_fill_sigscript, build_buy_v18_redeem_script, build_sell_v18_fill_sigscript,
    build_sell_v18_redeem_script,
};
use kob_core::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};

const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";
const TOKEN_HEX: &str = "eab5c99a1f23b29629f5e5e6808ea386cae522d8b9d122a3f1378b189bb5a4b4";

fn hash32(hex: &str) -> Hash {
    let b = hex::decode(hex).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Hash::from_bytes(a)
}
fn arr32(hex: &str) -> [u8; 32] {
    let b = hex::decode(hex).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}
fn p2pk_spk(pubkey: &[u8; 32]) -> ScriptPublicKey {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(pubkey);
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}

fn exec_inputs(
    tx: &Transaction,
    entries: Vec<UtxoEntry>,
    last_idx: usize,
) -> Vec<Result<(), String>> {
    let populated = PopulatedTransaction::new(tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!("ctx: {e:?}")); last_idx + 1],
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let mut results = Vec::new();
    for idx in 0..=last_idx {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm =
            TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        results.push(vm.execute().map_err(|e| format!("{e:?}")));
    }
    results
}

/// min_fill above the buy's own expected tokens -> the buy input rejects.
#[test]
fn buy_mfill_above_expected_tokens_rejects() {
    run_case(3, 4, 30_000_000, 2000, false);
}

/// Same sweep with valid token floors passes on every branch combination.
#[test]
fn oco_sl_sweep_passes_with_valid_token_floor() {
    run_case(2, 1, 30_000_000, 2000, true);
    run_case(1, 1, 30_000_000, 2000, true);
    run_case(3, 4, 22_500_000, 2000, true);
    run_case(3, 4, 1_000_000, 2000, true);
}

fn run_case(buy_pn: u64, buy_pd: u64, buy_mfill: u64, buy_bps: u64, expect_buy_ok: bool) {
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let oco_rs = build_oco_sell_v18_redeem_script(
        2, 1, 10_000_000, 1, 2, 10_000_000, &owner_hash, &spk_hash,
        &spk_hash, 30, 0, 0,
    )
    .unwrap();
    let plain_rs =
        build_sell_v18_redeem_script(1, 2, 10_000_000, &owner_hash, &spk_hash, &spk_hash, 30, 0, 0).unwrap();
    let buy_rs = build_buy_v18_redeem_script(
        &arr32(TOKEN_HEX),
        buy_pn,
        buy_pd,
        buy_mfill,
        &owner_hash,
        &spk_hash,
        &spk_hash,
        buy_bps,
        0,
        0,
    )
    .unwrap();

    let oco_ss = build_oco_sell_v18_sl_fill_sigscript(0, 1, 2, &oco_rs);
    let plain_ss = build_sell_v18_fill_sigscript(0, 1, 2, &plain_rs);
    let buy_ss = build_buy_v18_fill_sigscript(&[0, 1], false, &buy_rs);

    let inputs = vec![
        TransactionInput::new(op(0x10, 0), oco_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), plain_ss, 50, 0),
        TransactionInput::new(op(0x30, 0), buy_ss, 50, 0),
        TransactionInput::new(op(0x40, 0), vec![0x41; 66], 0, 1),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            30_000_000,
            wallet_spk.clone(),
            Some(CovenantBinding::new(0, token)),
        ),
        TransactionOutput::with_covenant(
            30_000_000,
            wallet_spk.clone(),
            Some(CovenantBinding::new(1, token)),
        ),
    ];
    let entries = vec![
        UtxoEntry {
            amount: 30_000_000,
            script_public_key: build_p2sh(&oco_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token),
        },
        UtxoEntry {
            amount: 30_000_000,
            script_public_key: build_p2sh(&plain_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token),
        },
        UtxoEntry {
            amount: 30_000_000,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        UtxoEntry {
            amount: 5_000_000,
            script_public_key: wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let res = exec_inputs(&tx, entries, 2);
    for (i, r) in res.iter().enumerate() {
        eprintln!("input[{i}]: {:?}", r);
    }
    assert!(res[0].is_ok(), "OCO SL fill failed: {:?}", res[0]);
    assert!(res[1].is_ok(), "plain sell fill failed: {:?}", res[1]);
    if expect_buy_ok {
        assert!(res[2].is_ok(), "buy sweep failed: {:?}", res[2]);
    } else {
        assert!(res[2].is_err(), "buy with mfill > expected tokens must reject");
    }
}
