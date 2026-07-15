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

/// Spend two borrow UTXOs in one tx, sharing a single continuation output at
/// `cont_idx`, with per-covenant merchant SPKs `merchant_a`/`merchant_b`.
/// Returns (covenant_A_result, covenant_B_result). The shared continuation
/// output pays `cont_value` to `cont_spk`.
fn run_two_borrows(
    merchant_a: ScriptPublicKey,
    merchant_b: ScriptPublicKey,
    cont_value: u64,
    cont_spk: ScriptPublicKey,
) -> (Result<(), String>, Result<(), String>) {
    let min_continuation = 100_003_000u64;
    let borrow_amount = 100_000_000u64;
    let hash_a = compute_spk_hash(merchant_a.version(), merchant_a.script());
    let hash_b = compute_spk_hash(merchant_b.version(), merchant_b.script());
    let rs_a = build_x402_borrow_redeem_script(&hash_a, min_continuation);
    let rs_b = build_x402_borrow_redeem_script(&hash_b, min_continuation);
    let p2sh_a = build_p2sh(&rs_a);
    let p2sh_b = build_p2sh(&rs_b);
    // Both borrow inputs point their continuation at the SAME output index 2.
    let ss_a = build_x402_borrow_spend_sigscript(2, &rs_a);
    let ss_b = build_x402_borrow_spend_sigscript(2, &rs_b);
    let payer = [0x11u8; 32];
    let payer_spk = p2pk_spk(&payer);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let inputs = vec![
        TransactionInput::new(op(0xb0, 0), ss_a, 0, 0), // borrow A
        TransactionInput::new(op(0xb1, 0), ss_b, 0, 0), // borrow B
        TransactionInput::new(op(0xf0, 0), vec![0x41; 66], 0, 1), // payer funds
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(1_000_000, payer_spk.clone(), None),        // out0
        TransactionOutput::with_covenant(1_000_000, payer_spk.clone(), None),        // out1
        TransactionOutput::with_covenant(cont_value, cont_spk, None),                // out2: shared continuation
    ];
    let tx = Transaction::new(0, inputs, outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: borrow_amount, script_public_key: p2sh_a, block_daa_score: 0, is_coinbase: false, covenant_id: None },
        UtxoEntry { amount: borrow_amount, script_public_key: p2sh_b, block_daa_score: 0, is_coinbase: false, covenant_id: None },
        UtxoEntry { amount: 500_000_000, script_public_key: payer_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let run = |idx: usize| {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        vm.execute().map_err(|e| format!("{e:?}"))
    };
    (run(0), run(1))
}

/// **Fix 8 (aggregate-inputs drain): the vulnerability requires a SHARED
/// merchant continuation target.**
///
/// If two concurrent borrow UTXOs share a merchant_spk_hash (what the provider
/// now forbids), one continuation output satisfies BOTH covenants — the payer
/// spends both borrow UTXOs but returns min_continuation only once and pockets
/// the other. This test documents the drain the provider fix prevents.
#[test]
fn same_merchant_aggregate_shares_one_continuation() {
    let merchant_spk = p2pk_spk(&[0x22u8; 32]);
    // Both borrows use the SAME merchant; one continuation output to that
    // merchant satisfies both — the drain.
    let (ra, rb) = run_two_borrows(merchant_spk.clone(), merchant_spk.clone(), 100_003_000, merchant_spk);
    assert!(ra.is_ok() && rb.is_ok(),
        "shared merchant target lets one continuation satisfy both covenants (the drain): {:?} {:?}", ra, rb);
}

/// **Fix 8: with DISTINCT merchant targets (what the provider now guarantees),
/// one shared continuation output canNOT satisfy both covenants.**
///
/// The provider rejects reusing a merchant_spk_hash, so two live borrow UTXOs
/// always have distinct continuation targets. An aggregate spend that pays a
/// single continuation output can match at most one covenant's merchant_hash;
/// the other FAILS. To satisfy both the payer must produce two full
/// continuation outputs — i.e. pay both merchants in full, no drain.
#[test]
fn distinct_merchant_aggregate_cannot_share_continuation() {
    let merchant_a = p2pk_spk(&[0x22u8; 32]);
    let merchant_b = p2pk_spk(&[0x44u8; 32]);
    // Single continuation output pays merchant A. Covenant A passes; B must fail.
    let (ra, rb) = run_two_borrows(merchant_a.clone(), merchant_b, 100_003_000, merchant_a);
    assert!(ra.is_ok(), "covenant A (its target is the shared output) must pass: {:?}", ra);
    assert!(rb.is_err(),
        "covenant B MUST FAIL: the shared continuation pays merchant A, not B — distinct targets \
         make the aggregate-inputs drain impossible");
}
