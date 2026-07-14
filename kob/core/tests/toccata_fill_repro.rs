//! Off-chain reproduction of the v16 buy + v14 sell FILL/match covenant scripts
//! against the real post-Toccata `kaspa-txscript` engine.
//!
//! On testnet-10 the engine's match tx is rejected with "script ran, but
//! verification failed" — a txscript OpVerify/clean-stack failure that the
//! node's RPC reports only generically. This test reconstructs an equivalent
//! v16 match tx (same bytecode paths) and executes each covenant input's script
//! through `TxScriptEngine` with `covenants_enabled = true`, printing the exact
//! `TxScriptError` so the failing opcode can be pinpointed and iterated on with
//! NO rebuild / NO on-chain round-trip.

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

use kob_core::contract::spot::order::{
    build_buy_v16_fill_sigscript, build_buy_v16_ioc_fill_sigscript, build_buy_v16_redeem_script,
    build_sell_fill_sigscript_fixed_offset, build_sell_redeem_script,
};
use kob_core::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};

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

// Wallet + token identity from the live testnet-10 run (self-trade: buyer,
// seller and matcher are the same wallet — all outputs share one P2PK SPK).
const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";
const TOKEN_HEX: &str = "0c113120cb56668a5aa984752496f8cc4ac65e9044f2fa85d64e7bbcb5fc6039";

/// Build a 1:1 full-fill v16 buy + v14 sell match tx with the given fill
/// sigscripts, then execute the two covenant input scripts (sell=0, buy=1)
/// through the post-Toccata engine. Panics with the failing opcode trace if
/// any OpVerify fails.
fn run_full_fill_match(scenario: &str, sell_ss: Vec<u8>, buy_ss: Vec<u8>, buy_rs: &[u8], sell_rs: &[u8]) {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let sell_p2sh = build_p2sh(sell_rs);
    let buy_p2sh = build_p2sh(buy_rs);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sell_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), buy_ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1), // wallet placeholder (not executed)
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(29_940_000, wallet_spk.clone(), None), // SellerKas
        TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), Some(CovenantBinding::new(0, token_cov_id))), // BuyerTokens
        TransactionOutput::with_covenant(200_000_000, wallet_spk.clone(), None), // BuyerChange
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: 30_000_000, script_public_key: sell_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: 30_000_000, script_public_key: buy_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: None },
        UtxoEntry { amount: 260_000_000, script_public_key: wallet_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];

    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext::from_tx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };

    let mut failures = Vec::new();
    for idx in [0usize, 1usize] {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut log: Vec<u8> = Vec::new();
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags)
            .with_opcode_execution_log_buffer(&mut log);
        let res = vm.execute();
        drop(vm);
        let name = if idx == 0 { "sell fill" } else { "buy v16" };
        match res {
            Ok(()) => eprintln!("[{scenario}] input[{idx}] ({name}) script: OK"),
            Err(e) => {
                eprintln!("[{scenario}] input[{idx}] ({name}) script: FAILED -> {e:?}");
                let text = String::from_utf8_lossy(&log);
                let lines: Vec<&str> = text.lines().collect();
                let start = lines.len().saturating_sub(14);
                for l in &lines[start..] {
                    eprintln!("  {l}");
                }
                failures.push((idx, format!("{e:?}")));
            }
        }
    }
    assert!(failures.is_empty(), "[{scenario}] covenant scripts must pass; failures: {failures:?}");
}

/// v16 buy FILL + v14 sell FILL (the engine's 1:1 full-fill match — the E2E path).
#[test]
fn v16_full_fill_match_scripts_pass() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let buy_rs = build_buy_v16_redeem_script(&token, 1, 1, 8_000_000, &owner_hash, &spk_hash, 2000, 0, 0).unwrap();
    let sell_rs = build_sell_redeem_script(499, 500, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_ss = build_sell_fill_sigscript_fixed_offset(0, &sell_rs);
    let buy_ss = build_buy_v16_fill_sigscript(1, 0, 0, &buy_rs); // [toi=1, tii=0, coi=0, Op1]
    run_full_fill_match("buy-fill/sell-fill", sell_ss, buy_ss, &buy_rs, &sell_rs);
}

/// v16 buy IOC (Op5 selector) + v14 sell FILL. IOC routes to the same fill body
/// (relaxed token check) and the same F6 cap — verifies the IOC sub-dispatch and
/// F6 both pass in the post-Toccata engine.
#[test]
fn v16_buy_ioc_match_scripts_pass() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let buy_rs = build_buy_v16_redeem_script(&token, 1, 1, 8_000_000, &owner_hash, &spk_hash, 2000, 0, 0).unwrap();
    let sell_rs = build_sell_redeem_script(499, 500, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_ss = build_sell_fill_sigscript_fixed_offset(0, &sell_rs);
    let buy_ss = build_buy_v16_ioc_fill_sigscript(1, 0, 0, &buy_rs); // [toi=1, tii=0, coi=0, Op5]
    run_full_fill_match("buy-ioc/sell-fill", sell_ss, buy_ss, &buy_rs, &sell_rs);
}
