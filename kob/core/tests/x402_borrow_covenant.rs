//! Off-chain proof of the x402 KIP-10 additive borrow covenant: run the redeem
//! script through the post-Toccata `kaspa-txscript` engine and assert it PASSES
//! for a valid additive spend (continuation >= min to the merchant) and FAILS
//! for under-value / wrong-recipient continuations — no node round-trip.

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::engine_context::EngineCtx;
use kaspa_txscript::{EngineFlags, TxScriptEngine};

use kob_core::compute_spk_hash;
use kob_core::contract::x402_borrow::{
    build_x402_borrow_redeem_script, build_x402_borrow_spend_sigscript,
};
use kob_core::build_p2sh;

fn p2pk_spk(pubkey: &[u8; 32]) -> ScriptPublicKey {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(pubkey);
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}

/// Execute the borrow covenant (input 0) of a tx whose output `cont_idx` returns
/// `cont_value` to `cont_spk`, with covenant `min_continuation`. Returns the
/// script result.
fn run_borrow(
    borrow_amount: u64,
    min_continuation: u64,
    cont_idx: u16,
    cont_value: u64,
    cont_spk: ScriptPublicKey,
    merchant_spk: ScriptPublicKey,
) -> Result<(), String> {
    let merchant_hash = compute_spk_hash(merchant_spk.version(), merchant_spk.script());
    let rs = build_x402_borrow_redeem_script(&merchant_hash, min_continuation);
    let borrow_p2sh = build_p2sh(&rs);
    let ss = build_x402_borrow_spend_sigscript(cont_idx, &rs);
    let payer = [0x11u8; 32];
    let payer_spk = p2pk_spk(&payer);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    // input0 = borrow outpoint (spent via additive path); input1 = payer funds.
    let inputs = vec![
        TransactionInput::new(op(0xb0, 0), ss, 0, 0),
        TransactionInput::new(op(0xf0, 0), vec![0x41; 66], 0, 1),
    ];
    // output0 = payment placeholder; output1 = continuation (by default cont_idx=1).
    let outputs = vec![
        TransactionOutput::with_covenant(1_000_000, payer_spk.clone(), None),
        TransactionOutput::with_covenant(cont_value, cont_spk, None),
    ];
    let tx = Transaction::new(0, inputs, outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: borrow_amount, script_public_key: borrow_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: None },
        UtxoEntry { amount: 500_000_000, script_public_key: payer_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];

    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 0, entry, ctx, flags);
    vm.execute().map_err(|e| format!("{e:?}"))
}

#[test]
fn additive_spend_passes_when_continuation_meets_min_to_merchant() {
    let merchant = [0x22u8; 32];
    let merchant_spk = p2pk_spk(&merchant);
    // borrow 100M, threshold 3000 -> min_continuation 100_003_000; continuation
    // pays exactly that to the merchant. Must PASS.
    let r = run_borrow(100_000_000, 100_003_000, 1, 100_003_000, merchant_spk.clone(), merchant_spk);
    assert!(r.is_ok(), "valid additive spend must pass: {:?}", r);
}

#[test]
fn passes_when_continuation_exceeds_min() {
    let merchant = [0x22u8; 32];
    let merchant_spk = p2pk_spk(&merchant);
    let r = run_borrow(100_000_000, 100_003_000, 1, 100_010_000, merchant_spk.clone(), merchant_spk);
    assert!(r.is_ok(), "over-min continuation must pass: {:?}", r);
}

#[test]
fn rejects_continuation_under_min() {
    let merchant = [0x22u8; 32];
    let merchant_spk = p2pk_spk(&merchant);
    // Continuation returns less than min -> the additive rule fails.
    let r = run_borrow(100_000_000, 100_003_000, 1, 100_000_000, merchant_spk.clone(), merchant_spk);
    assert!(r.is_err(), "under-min continuation must be rejected");
}

#[test]
fn rejects_wrong_recipient_continuation() {
    let merchant = [0x22u8; 32];
    let merchant_spk = p2pk_spk(&merchant);
    let attacker_spk = p2pk_spk(&[0x33u8; 32]);
    // Continuation value is fine, but it pays the attacker, not the merchant.
    let r = run_borrow(100_000_000, 100_003_000, 1, 100_003_000, attacker_spk, merchant_spk);
    assert!(r.is_err(), "continuation to wrong recipient must be rejected");
}
