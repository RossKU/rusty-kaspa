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
    build_sell_fill_sigscript, build_sell_fill_sigscript_fixed_offset,
    build_sell_ioc_fill_sigscript, build_sell_redeem_script,
};
use kob_core::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};
use kob_core::listing::{build_listing_redeem_script, build_listing_settle_sigscript};

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

/// Execute the v16 buy covenant script (input[1]) of a 1:1 full-fill match and
/// return the raw `execute()` result. Same tx shape as `run_full_fill_match`
/// but returns the buy-script result instead of asserting success, so callers
/// can assert either PASS (within cap) or REJECT (over cap).
fn buy_script_result(
    sell_ss: Vec<u8>,
    buy_ss: Vec<u8>,
    buy_rs: &[u8],
    sell_rs: &[u8],
    buy_kas_in: u64,
    seller_kas_out: u64,
    buyer_tokens_out: u64,
) -> Result<(), String> {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let sell_p2sh = build_p2sh(sell_rs);
    let buy_p2sh = build_p2sh(buy_rs);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sell_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), buy_ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(seller_kas_out, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(buyer_tokens_out, wallet_spk.clone(), Some(CovenantBinding::new(0, token_cov_id))),
        TransactionOutput::with_covenant(200_000_000, wallet_spk.clone(), None),
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: buyer_tokens_out, script_public_key: sell_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: buy_kas_in, script_public_key: buy_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: None },
        UtxoEntry { amount: 260_000_000, script_public_key: wallet_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];

    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext::from_tx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };

    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(1);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 1, entry, ctx, flags);
    vm.execute().map_err(|e| format!("{e:?}"))
}

/// **The F6-cap enforcement proof for the consolidated CLI `match` path.**
///
/// The CLI now builds the base match tx through the canonical planner, which
/// caps the *matcher's take* at the buy's `mmfee_bps`. This test proves the
/// on-chain backstop: the v16 buy covenant's F6 check *rejects* any match
/// whose intrinsic price spread exceeds `mmfee_bps`, regardless of how the
/// outputs are allocated — so a matcher can never sneak an over-cap trade
/// through the CLI (or a raw hand-crafted tx) the way the pre-consolidation
/// v14-only matcher did (v14 has no F6 at all).
///
/// Shape: buy @ 1/1 (30M KAS wants 30M tokens), sell @ 1/2 (30M tokens wants
/// 15M KAS) — a 15M KAS intrinsic spread (50%). With `mmfee_bps = 30` (0.30%)
/// the cap is 30M/10000*30 = 90K, far below 15M, so F6 must abort.
#[test]
fn v16_over_cap_spread_rejected_by_f6() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    // Tight cap (0.30%) but a wide 50% spread -> F6 must reject.
    let buy_rs = build_buy_v16_redeem_script(&token, 1, 1, 8_000_000, &owner_hash, &spk_hash, 30, 0, 0).unwrap();
    let sell_rs = build_sell_redeem_script(1, 2, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_ss = build_sell_fill_sigscript_fixed_offset(0, &sell_rs);
    let buy_ss = build_buy_v16_fill_sigscript(1, 0, 0, &buy_rs); // [toi=1, tii=0, coi=0, Op1]

    // buy_kas_in=30M, seller gets fair_kas=15M, buyer gets 30M tokens.
    let res = buy_script_result(sell_ss, buy_ss, &buy_rs, &sell_rs, 30_000_000, 15_000_000, 30_000_000);
    assert!(
        res.is_err(),
        "v16 buy F6 MUST reject an over-cap spread (surplus 15M > max_surplus 90K); got Ok — \
         the CLI match path would be able to settle a trade the buyer's mmfee_bps forbids"
    );
}

/// Companion to the above: the SAME wide 50% spread, but with `mmfee_bps`
/// widened to 6000 (60%) so the cap (30M/10000*6000 = 18M) now covers the
/// 15M spread. F6 must PASS. Together these two tests bracket the F6 cap:
/// reject when spread > cap, accept when spread <= cap.
#[test]
fn v16_within_cap_wide_spread_passes_f6() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let buy_rs = build_buy_v16_redeem_script(&token, 1, 1, 8_000_000, &owner_hash, &spk_hash, 6000, 0, 0).unwrap();
    let sell_rs = build_sell_redeem_script(1, 2, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_ss = build_sell_fill_sigscript_fixed_offset(0, &sell_rs);
    let buy_ss = build_buy_v16_fill_sigscript(1, 0, 0, &buy_rs);

    let res = buy_script_result(sell_ss, buy_ss, &buy_rs, &sell_rs, 30_000_000, 15_000_000, 30_000_000);
    assert!(
        res.is_ok(),
        "v16 buy F6 must ACCEPT a spread within the cap (surplus 15M <= max_surplus 18M); got {res:?}"
    );
}

/// **Fix 4 (v16 IOC F6): the theft tx now FAILS.**
///
/// IOC (Op5) relaxes the buyer's token-output floor to `mfill`. Before the fix,
/// F6 computed the surplus against the FULL hypothetical token quantity
/// (kas_in * buy_price), so a matcher could consume the whole kas_in while
/// delivering only `mfill` tokens and F6 saw ~zero surplus. F6 now reads the
/// ACTUAL delivered amount at output[toi], so the pocketed kas is caught.
///
/// Shape: buy @ 1/1, kas_in=30M, mfill=8M, mmfee_bps=30 (0.30%). Sell @ 1/1.
/// Matcher delivers only 8M tokens (== mfill, IOC floor passes) but keeps the
/// other 22M KAS. actual surplus = 30M - 8M(fair @1/1) = 22M > cap 90k -> abort.
#[test]
fn v16_ioc_partial_delivery_theft_rejected_by_f6() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let buy_rs = build_buy_v16_redeem_script(&token, 1, 1, 8_000_000, &owner_hash, &spk_hash, 30, 0, 0).unwrap();
    let sell_rs = build_sell_redeem_script(1, 1, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_ss = build_sell_fill_sigscript_fixed_offset(0, &sell_rs);
    let buy_ss = build_buy_v16_ioc_fill_sigscript(1, 0, 0, &buy_rs); // Op5 IOC

    // buy_kas_in=30M, matcher delivers only 8M tokens (== mfill), pockets 22M.
    let res = buy_script_result(sell_ss, buy_ss, &buy_rs, &sell_rs, 30_000_000, 8_000_000, 8_000_000);
    assert!(
        res.is_err(),
        "v16 IOC F6 MUST reject partial delivery that pockets kas (surplus 22M > cap 90k); got Ok — \
         F6 is still basing the cap on the full hypothetical quantity instead of the delivered output[toi]"
    );
}

/// Companion: honest IOC partial delivery WITHIN the cap still passes. Same
/// 8M delivery but mmfee_bps widened to 8000 (cap = 30M/10000*8000 = 24M >=
/// 22M surplus) so F6 accepts. Brackets the fix against the reject above.
#[test]
fn v16_ioc_partial_delivery_within_cap_passes_f6() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let buy_rs = build_buy_v16_redeem_script(&token, 1, 1, 8_000_000, &owner_hash, &spk_hash, 8000, 0, 0).unwrap();
    let sell_rs = build_sell_redeem_script(1, 1, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_ss = build_sell_fill_sigscript_fixed_offset(0, &sell_rs);
    let buy_ss = build_buy_v16_ioc_fill_sigscript(1, 0, 0, &buy_rs);

    let res = buy_script_result(sell_ss, buy_ss, &buy_rs, &sell_rs, 30_000_000, 8_000_000, 8_000_000);
    assert!(
        res.is_ok(),
        "v16 IOC F6 must ACCEPT a partial delivery within the widened cap (surplus 22M <= 24M); got {res:?}"
    );
}

/// **Fix 3 (sell F4 per-input binding): the shared-output drain now FAILS,
/// honest delivery still passes.**
///
/// Two sellers (A, B) of the SAME token in one batch. Before the fix each
/// checked the transaction-wide shared covenant-output-0, so a matcher could
/// deliver ONE token output (satisfying both) and drain the second seller's
/// tokens out as KAS. F4 now checks the 0th output THIS input authorized; each
/// output has exactly one authorizing_input. The matcher makes only output[2]
/// (authorized by seller A) hold tokens; seller B authorizes no output.
///
/// Runs both sell scripts: A (input 0, has its authorized token output) must
/// PASS; B (input 1, whose tokens were drained to KAS) must FAIL.
#[test]
fn sell_f4_shared_output_drain_rejected_honest_passes() {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);

    // Both sellers price 1/1; A has 30M tokens, B has 20M.
    let sell_rs = build_sell_redeem_script(1, 1, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_p2sh = build_p2sh(&sell_rs);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    // A pays KAS at output[0]; B pays KAS at output[1]; the single token output
    // is output[2], authorized by input 0 (seller A) ONLY.
    let ss_a = build_sell_fill_sigscript(0, &sell_rs);
    let ss_b = build_sell_fill_sigscript(1, &sell_rs);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), ss_a, 50, 0),           // seller A (token 30M)
        TransactionInput::new(op(0x11, 0), ss_b, 50, 0),           // seller B (token 20M)
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),  // buyer/fee placeholder
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), None),                                   // A's KAS
        TransactionOutput::with_covenant(20_000_000, wallet_spk.clone(), None),                                   // B's KAS
        TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), Some(CovenantBinding::new(0, token_cov_id))), // tokens, auth by A only
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: 30_000_000, script_public_key: sell_p2sh.clone(), block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: 20_000_000, script_public_key: sell_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: 260_000_000, script_public_key: wallet_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("CovenantsContext::from_tx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };

    let run = |idx: usize| {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        vm.execute().map_err(|e| format!("{e:?}"))
    };

    assert!(run(0).is_ok(), "seller A (has its own authorized token output) must PASS; got {:?}", run(0));
    assert!(
        run(1).is_err(),
        "seller B MUST FAIL: its tokens were drained to KAS with no output authorized by input 1, \
         but F4 is still accepting the shared covenant-output-0"
    );
}

/// Run the IOC-sell (Op5) covenant with token_in=30M, fta=20M (partial), and a
/// residual self-continuation output at output[0] worth `residual_value` (SPK
/// = the sell P2SH => auth[0] of the sell input). `residual_bound` controls
/// whether output[0] carries the sell's covenant binding (authorizing_input=0);
/// when false the residual isn't a covenant continuation of the sell input, so
/// OpAuthOutputIdx finds nothing. Returns the sell script result.
fn run_sell_ioc(residual_value: u64, residual_bound: bool) -> Result<(), String> {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);

    let token_in = 30_000_000u64;
    let fta = 20_000_000u64; // partial fill; residual should be token_in - fta = 10M
    let sell_rs = build_sell_redeem_script(1, 1, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_p2sh = build_p2sh(&sell_rs);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    // koi = 1 (seller KAS at output[1]); IOC selector (Op5) + fta.
    let sell_ss = build_sell_ioc_fill_sigscript(1, fta, &sell_rs);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sell_ss, 50, 0),       // sell (token 30M)
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1), // fee placeholder
    ];
    // output[0] = residual self-continuation to the sell P2SH; output[1] = seller KAS.
    let residual_cov = if residual_bound { Some(CovenantBinding::new(0, token_cov_id)) } else { None };
    let residual_p2sh = ScriptPublicKey::new(sell_p2sh.version(), sell_p2sh.script().into());
    let outputs = vec![
        TransactionOutput::with_covenant(residual_value, residual_p2sh, residual_cov), // residual -> seller
        TransactionOutput::with_covenant(fta, wallet_spk.clone(), None),               // fill_kas 20M -> seller
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: token_in, script_public_key: sell_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: 260_000_000, script_public_key: wallet_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
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

/// **Fix 1 (sell IOC residual conservation): the residual-drain now FAILS,
/// honest partial IOC still passes.**
///
/// IOC-sell prices only `fta` of the seller's `token_in` and (before the fix)
/// only checked a covenant output exists — so the `token_in - fta` unsold
/// tokens could be drained out as KAS. F4 now requires that residual to return
/// to the seller via a self-continuation output bound to THIS input.
#[test]
fn sell_ioc_residual_drain_rejected() {
    // Matcher returns only 5M (< token_in - fta = 10M) to the seller and pockets
    // the other 5M -> residual conservation FAILS.
    let short = run_sell_ioc(5_000_000, true);
    assert!(short.is_err(), "under-returned residual must be rejected; got Ok");
    // Matcher returns the residual to a NON-covenant output (drains it as plain
    // KAS): the sell input then authorizes no continuation output -> FAILS.
    let unbound = run_sell_ioc(10_000_000, false);
    assert!(unbound.is_err(), "residual not bound to this input as a continuation must be rejected; got Ok");
}

#[test]
fn sell_ioc_honest_residual_passes() {
    // Full residual (token_in - fta = 10M) returned to the seller via the sell's
    // own P2SH self-continuation -> passes.
    let r = run_sell_ioc(10_000_000, true);
    assert!(r.is_ok(), "honest IOC partial with the residual returned must pass; got {r:?}");
}

/// Run the IOC-sell script against the EXACT output layout the honest match
/// builder (`kob_domain::batch::plan_sell_ioc_match`) now emits:
///   output[0] = seller KAS  (koi=0, non-covenant)
///   output[1] = residual self-continuation to the sell P2SH (covenant, auth=0)
///   output[2] = buyer tokens (covenant, auth=0)
/// The buyer-tokens output is ALSO a covenant continuation authorized by the
/// (single) sell input, so this proves the F4 `OpTxInputIndex Op0
/// OpAuthOutputIdx` resolves to the residual (output[1], the lowest-indexed
/// authorized output) and NOT the buyer output at output[2] -- the exact
/// ordering constraint the builder wiring has to honour. `residual_first`
/// swaps outputs[1] and [2] to show that if the buyer output preceded the
/// residual, auth[0] would land on the buyer output and the self-continuation
/// SPK check would fail.
fn run_sell_ioc_builder_layout(residual_first: bool) -> Result<(), String> {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);

    let token_in = 30_000_000u64;
    let fta = 20_000_000u64; // partial: residual = token_in - fta = 10M
    let sell_rs = build_sell_redeem_script(1, 1, 8_000_000, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell_p2sh = build_p2sh(&sell_rs);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    // koi = 0 (seller KAS at output[0]), matching the builder.
    let sell_ss = build_sell_ioc_fill_sigscript(0, fta, &sell_rs);
    let buyer_spk = p2pk_spk(&arr32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sell_ss, 50, 0),       // sell (token 30M)
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1), // fee placeholder (not executed)
    ];
    let residual_p2sh = ScriptPublicKey::new(sell_p2sh.version(), sell_p2sh.script().into());
    // Both residual and buyer are covenant continuations authorized by input 0.
    let residual_out = TransactionOutput::with_covenant(10_000_000, residual_p2sh, Some(CovenantBinding::new(0, token_cov_id)));
    let buyer_out = TransactionOutput::with_covenant(fta, buyer_spk, Some(CovenantBinding::new(0, token_cov_id)));
    let (out1, out2) = if residual_first { (residual_out, buyer_out) } else { (buyer_out, residual_out) };
    let outputs = vec![
        TransactionOutput::with_covenant(fta, wallet_spk.clone(), None), // [0] seller KAS 20M (koi=0)
        out1,                                                            // [1]
        out2,                                                            // [2]
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: token_in, script_public_key: sell_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: 260_000_000, script_public_key: wallet_spk, block_daa_score: 0, is_coinbase: false, covenant_id: None },
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

/// The honest match-builder layout (residual at output[1], before buyer tokens)
/// passes the real engine; swapping the residual behind the buyer output makes
/// auth[0] resolve to the buyer output and the self-continuation check fail.
#[test]
fn sell_ioc_builder_layout_residual_at_auth0_passes() {
    let ok = run_sell_ioc_builder_layout(true);
    assert!(ok.is_ok(), "builder layout (residual is the sell input's auth[0]) must pass; got {ok:?}");
    let bad = run_sell_ioc_builder_layout(false);
    assert!(bad.is_err(), "if a buyer output precedes the residual, auth[0] misresolves and the sell script must fail");
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
