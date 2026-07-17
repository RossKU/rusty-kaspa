//! Listing PATH 6 (english-auction settle) covenant repro against the real
//! post-Toccata `kaspa-txscript` engine (ported from the retired
//! toccata_fill_repro suite — the only coverage there that does not concern
//! the deleted pre-v18 spot generations).

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_hashes::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::engine_context::EngineCtx;
use kaspa_txscript::{EngineFlags, TxScriptEngine};

use kob_core::listing::{build_listing_redeem_script, build_listing_settle_sigscript};
use kob_core::{build_p2sh, compute_p2pk_spk_hash};

const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";

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

/// Run a listing PATH 6 (settle english auction) script with the seller paid
/// `seller_out_value` at output[1], against an accrued listing UTXO worth
/// `accrued`. Returns the raw execute() result of the listing covenant input.
fn listing_settle_result(accrued: u64, seller_out_value: u64) -> Result<(), String> {
    let pubkey = arr32(PUBKEY_HEX);
    let mut seller_spk_script = Vec::with_capacity(34);
    seller_spk_script.push(0x20);
    seller_spk_script.extend_from_slice(&pubkey);
    seller_spk_script.push(0xac);
    let mut seller_spk_arr = [0u8; 34];
    seller_spk_arr.copy_from_slice(&seller_spk_script);
    let seller_spk_hash = compute_p2pk_spk_hash(&pubkey);
    let seller_spk = p2pk_spk(&pubkey);

    // english listing, expiry 100_000; settle requires lockTime >= expiry.
    let rs = build_listing_redeem_script(&seller_spk_hash, &seller_spk_arr, 1_000_000, 2, 100_000, 100_000);
    let listing_p2sh = build_p2sh(&rs);
    let settle_ss = build_listing_settle_sigscript(&rs);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let inputs = vec![
        TransactionInput::new(op(0x40, 0), settle_ss, 0, 0),
        TransactionInput::new(op(0x41, 0), vec![0x41; 66], 0, 1), // fee placeholder (not executed)
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(1_000, p2pk_spk(&pubkey), None),          // output[0] (unused by PATH6)
        TransactionOutput::with_covenant(seller_out_value, seller_spk, None),      // output[1] seller payment
    ];
    let tx = Transaction::new(1, inputs, outputs, 200_000, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: accrued, script_public_key: listing_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: None },
        UtxoEntry { amount: 10_000_000, script_public_key: p2pk_spk(&pubkey), block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];

    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext::from_tx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 0, entry, ctx, flags);
    vm.execute().map_err(|e| format!("{e:?}"))
}

/// **Fix 5 (listing PATH 6): the settle-skim theft now FAILS.**
///
/// An english-auction settle is permissionless (no signature). Before the fix
/// PATH 6 checked only that output[1] went to the seller's address, not its
/// value, so a settler could pay the seller dust and pocket the accrued bid.
/// PATH 6 now requires output[1].value >= the accrued UTXO value.
#[test]
fn listing_settle_dust_skim_rejected() {
    // Accrued bid 100M in the UTXO; settler tries to pay the seller only 1 sompi.
    let res = listing_settle_result(100_000_000, 1);
    assert!(
        res.is_err(),
        "listing PATH6 MUST reject a settle that underpays the seller vs the accrued bid; got Ok"
    );
}

/// Companion: an honest settle that returns the full accrued bid to the seller
/// still passes.
#[test]
fn listing_settle_full_payment_passes() {
    let res = listing_settle_result(100_000_000, 100_000_000);
    assert!(
        res.is_ok(),
        "listing PATH6 must ACCEPT a settle that pays the seller the full accrued bid; got {res:?}"
    );
}

