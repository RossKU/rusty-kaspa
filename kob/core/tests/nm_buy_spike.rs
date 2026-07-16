//! Feasibility spike (Phase 1): can a single buy input SUM N per-sell token
//! outputs (each already bound to its own sell input via the sell's per-input
//! F4) and cap the surplus against that sum?
//!
//! This does NOT touch the production v16 buy contract (`order.rs`). It is a
//! standalone, fixed-arity (N=2) prototype covenant, hand-built with
//! `ScriptBuilder` and run through the real post-Toccata `TxScriptEngine`
//! (`covenants_enabled = true`), to prove the mechanism before it is folded
//! into a real, general-N contract. See `kob/NM_BUY_DESIGN.md` for the full
//! writeup this spike backs.
//!
//! Mechanism under test, per summed term i:
//!   1. `toi_i = OpAuthOutputIdx(tii_i, 0)` -- the output is DERIVED from the
//!      sell input, not taken as a free sigscript parameter, so a decoy /
//!      unauthorized output can never be substituted.
//!   2. `OpInputCovenantId(tii_i) == tcid` -- tii_i must really be a sell of
//!      the token being bought (rejects splicing in a different token's sell).
//!   3. buyer SPK check on toi_i (rejects tokens routed away from the buyer).
//!   4. `fair_kas_i = amount(toi_i) / sell_pden_i * sell_pnum_i`, using THAT
//!      sell's own price read off its sigscript (the existing v16 fixed-offset
//!      convention, reused unmodified).
//! Plus a pre-check that `tii_1 < tii_2` (strict), so the two summation terms
//! cannot alias the same sell input and double-count its one authorized
//! output. Final check: caps `sum(fair_kas_i)`'s surplus against `kas_in`,
//! bounded by `mmfee_bps`, exactly like v16 F6.

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
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineFlags, TxScriptEngine};

use kob_core::contract::spot::order::{build_sell_fill_sigscript_fixed_offset, build_sell_redeem_script};
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

const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";
const TOKEN_HEX: &str = "0c113120cb56668a5aa984752496f8cc4ac65e9044f2fa85d64e7bbcb5fc6039";

// -- tiny ScriptBuilder helpers, purely to keep the term-processing block
// readable; each just forwards to add_i64/add_op and unwraps (script
// construction here can't exceed the size limit at these lengths). --
fn pick(sb: &mut ScriptBuilder, depth: i64) {
    sb.add_i64(depth).unwrap();
    sb.add_op(OpPick).unwrap();
}
fn roll(sb: &mut ScriptBuilder, depth: i64) {
    sb.add_i64(depth).unwrap();
    sb.add_op(OpRoll).unwrap();
}
fn op(sb: &mut ScriptBuilder, code: u8) {
    sb.add_op(code).unwrap();
}
fn num(sb: &mut ScriptBuilder, n: i64) {
    sb.add_i64(n).unwrap();
}

/// One summation term: derive `toi = OpAuthOutputIdx(tii_depth, 0)`, verify
/// `OpInputCovenantId(tii) == tcid`, verify the buyer SPK on `toi`, then push
/// `fair_kas = amount(toi) / sell_pden * sell_pnum` (sell price read off
/// `tii`'s sigscript at the existing v16 fixed-offset convention).
///
/// `tii_depth`/`tcid_depth`/`bspkh_depth` are the CURRENT depths (from top,
/// depth0=top) of tii, tcid and bspkh going in. Leaves `fair_kas` on top with
/// everything else the term produced (pnum/pden/tokens temporaries) still on
/// the stack below it, uncleaned -- matching the production F6 style of
/// cleaning up in one final bulk drop rather than per-step.
fn term(sb: &mut ScriptBuilder, tii_depth: i64, tcid_depth: i64, bspkh_depth: i64) {
    // toi = OpAuthOutputIdx(tii, 0)
    pick(sb, tii_depth);
    num(sb, 0);
    op(sb, OpAuthOutputIdx);

    // OpInputCovenantId(tii) == tcid. tii is re-picked at tii_depth+1 (shifted
    // by the toi push); tcid is picked at tcid_depth+2 (shifted by BOTH the
    // toi push above AND this block's own tii re-pick, which happens before
    // the tcid pick executes).
    pick(sb, tii_depth + 1);
    op(sb, OpInputCovenantId);
    pick(sb, tcid_depth + 2);
    op(sb, OpEqual);
    op(sb, OpVerify);

    // blake2b(OpTxOutputSpk(toi)) == bspkh. toi sits at depth0 (untouched by
    // the covid check above, which only used copies); bspkh is picked at
    // bspkh_depth+2 for the same reason as tcid above.
    pick(sb, 0);
    op(sb, OpTxOutputSpk);
    op(sb, OpBlake2b);
    pick(sb, bspkh_depth + 2);
    op(sb, OpEqual);
    op(sb, OpVerify);

    // tokens = amount(toi) (consumes toi, sitting at depth0)
    op(sb, OpTxOutputAmount);

    // sell_pnum = tii.sigscript[7..15)
    pick(sb, tii_depth + 1);
    num(sb, 7);
    num(sb, 15);
    op(sb, OpTxInputScriptSigSubstr);

    // sell_pden = tii.sigscript[16..24)
    pick(sb, tii_depth + 2);
    num(sb, 16);
    num(sb, 24);
    op(sb, OpTxInputScriptSigSubstr);

    // fair_kas = tokens / sell_pden * sell_pnum  (div-first, overflow-safe)
    pick(sb, 2);
    pick(sb, 1);
    op(sb, OpDiv);
    pick(sb, 2);
    op(sb, OpMul);
}

/// N=2 prototype buy redeemScript.
///
/// State (72B): `[tcid 32B][bspkh 32B][mmfee_bps 8B]`.
/// Sigscript: `[tii_1][tii_2][pushData(RS)]`, `tii_1 < tii_2` required (proves
/// distinctness cheaply -- no O(N^2) pairwise check needed).
///
/// Stack after state push: mmfee_bps(0), bspkh(1), tcid(2), tii_2(3), tii_1(4).
fn build_nm2_buy_redeem_script(tcid: &[u8; 32], bspkh: &[u8; 32], mmfee_bps: u64) -> Vec<u8> {
    let mut sb = ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() });
    sb.add_data(tcid).unwrap();
    sb.add_data(bspkh).unwrap();
    sb.add_data(&mmfee_bps.to_le_bytes()).unwrap();

    // DISTINCTNESS: tii_1 < tii_2. Defeats double-counting one sell's output
    // by supplying the same tii twice.
    pick(&mut sb, 4);
    pick(&mut sb, 4);
    op(&mut sb, OpLessThan);
    op(&mut sb, OpVerify);

    // TERM 1 (tii_1 at depth4). Leaves the 9-item block
    // [fair_kas_1, sell_pden_1, sell_pnum_1, tokens_1, mmfee_bps, bspkh, tcid, tii_2, tii_1]
    term(&mut sb, 4, 2, 1);

    // TERM 2 (tii_2, now at depth7 -- shifted by term 1's 4 leftover temps).
    // Leaves a 13-item stack: [fair_kas_2, ...term2 temps..., ...term1 leftovers..., mmfee_bps, bspkh, tcid, tii_2, tii_1]
    term(&mut sb, 7, 6, 5);

    // sum = fair_kas_1 + fair_kas_2 (fair_kas_1 currently at depth4)
    roll(&mut sb, 4);
    op(&mut sb, OpAdd);

    // kas_in = this buy input's own amount, duplicated (needed for both the
    // surplus subtraction and the max_surplus computation below).
    op(&mut sb, OpTxInputIndex);
    op(&mut sb, OpTxInputAmount);
    op(&mut sb, OpDup);

    // surplus = kas_in - sum  (sum currently at depth2)
    roll(&mut sb, 2);
    op(&mut sb, OpSub);

    // max_surplus = kas_in / 10000 * mmfee_bps  (div-first, overflow-safe;
    // kas_in copy at depth1, mmfee_bps at depth9 at this point)
    pick(&mut sb, 1);
    num(&mut sb, 10000);
    op(&mut sb, OpDiv);
    pick(&mut sb, 9);
    op(&mut sb, OpMul);

    // surplus <= max_surplus (stack: [max_surplus(top), surplus] -> OpLTE)
    op(&mut sb, OpLessThanOrEqual);
    op(&mut sb, OpVerify);

    // cleanup: 12 leftover temps, then TRUE
    for _ in 0..6 {
        op(&mut sb, Op2Drop);
    }
    op(&mut sb, Op1);

    sb.drain()
}

fn build_nm2_buy_sigscript(tii_1: u16, tii_2: u16, redeem_script: &[u8]) -> Vec<u8> {
    let mut sb = ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() });
    sb.add_i64(tii_1 as i64).unwrap();
    sb.add_i64(tii_2 as i64).unwrap();
    sb.add_data(redeem_script).unwrap();
    sb.drain()
}

/// Build a 2-sells -> 1-buy sweep tx (sell1=input0, sell2=input1, buy=input2)
/// with DISTINCT per-sell prices, and execute all three covenant scripts
/// through the real engine. Returns each input's raw result (index-aligned).
fn run_nm2_buy(
    tii_1: u16,
    tii_2: u16,
    kas_in: u64,
    mmfee_bps: u64,
    sell1_price: (u64, u64),
    sell2_price: (u64, u64),
    sell1_tokens: u64,
    sell2_tokens: u64,
) -> Vec<Result<(), String>> {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let tcid_arr = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);

    let sell1_rs = build_sell_redeem_script(sell1_price.0, sell1_price.1, 1, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell2_rs = build_sell_redeem_script(sell2_price.0, sell2_price.1, 1, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let sell1_p2sh = build_p2sh(&sell1_rs);
    let sell2_p2sh = build_p2sh(&sell2_rs);
    let sell1_ss = build_sell_fill_sigscript_fixed_offset(0, &sell1_rs);
    let sell2_ss = build_sell_fill_sigscript_fixed_offset(1, &sell2_rs);

    let buy_rs = build_nm2_buy_redeem_script(&tcid_arr, &spk_hash, mmfee_bps);
    let buy_p2sh = build_p2sh(&buy_rs);
    let buy_ss = build_nm2_buy_sigscript(tii_1, tii_2, &buy_rs);

    let op_ = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let inputs = vec![
        TransactionInput::new(op_(0x10, 0), sell1_ss, 50, 0),
        TransactionInput::new(op_(0x11, 0), sell2_ss, 50, 0),
        TransactionInput::new(op_(0x20, 0), buy_ss, 50, 0),
    ];
    let sell1_kas = sell1_tokens * sell1_price.0 / sell1_price.1;
    let sell2_kas = sell2_tokens * sell2_price.0 / sell2_price.1;
    let outputs = vec![
        TransactionOutput::with_covenant(sell1_kas, wallet_spk.clone(), None), // SellerKas 1
        TransactionOutput::with_covenant(sell2_kas, wallet_spk.clone(), None), // SellerKas 2
        TransactionOutput::with_covenant(sell1_tokens, wallet_spk.clone(), Some(CovenantBinding::new(0, token_cov_id))), // BuyerTokens (from sell1)
        TransactionOutput::with_covenant(sell2_tokens, wallet_spk.clone(), Some(CovenantBinding::new(1, token_cov_id))), // BuyerTokens (from sell2)
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry { amount: sell1_tokens, script_public_key: sell1_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: sell2_tokens, script_public_key: sell2_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: Some(token_cov_id) },
        UtxoEntry { amount: kas_in, script_public_key: buy_p2sh, block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];

    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!("{e:?}")); 3],
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };

    let mut results = Vec::with_capacity(3);
    for idx in [0usize, 1, 2] {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        results.push(vm.execute().map_err(|e| format!("{e:?}")));
    }
    results
}

/// **Go/no-go: an honest 2-sells -> 1-buy sweep, with DIFFERENT per-sell
/// prices, verifies in the real post-Toccata engine.**
///
/// sell1 @ 1/1 (30M tokens -> 30M KAS), sell2 @ 1/2 (20M tokens -> 10M KAS).
/// fair sum = 40M. Buyer pays 41M (1M surplus), mmfee_bps=2000 (cap 8.2M) ->
/// within cap.
#[test]
fn nm2_honest_sweep_passes() {
    let results = run_nm2_buy(0, 1, 41_000_000, 2000, (1, 1), (1, 2), 30_000_000, 20_000_000);
    assert!(results[0].is_ok(), "sell1 must pass: {:?}", results[0]);
    assert!(results[1].is_ok(), "sell2 must pass: {:?}", results[1]);
    assert!(results[2].is_ok(), "N:M buy (summation F6) must pass an honest 2-sell sweep: {:?}", results[2]);
}

/// **Adversarial: duplicate `tii` (double-counting one sell's output) is
/// rejected.**
///
/// tii_1 = tii_2 = 0: the sigscript points BOTH summation terms at the SAME
/// sell input. Without the strict `tii_1 < tii_2` distinctness check, this
/// would let a matcher "deliver" one real sell's tokens once but have the
/// buy script count them twice toward the sum -- inflating apparent fair_kas
/// and letting a matcher pocket real surplus while a genuine second sell
/// either doesn't exist or is left undelivered.
#[test]
fn nm2_duplicate_sell_input_double_count_rejected() {
    let results = run_nm2_buy(0, 0, 41_000_000, 2000, (1, 1), (1, 2), 30_000_000, 20_000_000);
    assert!(
        results[2].is_err(),
        "duplicate tii (double-counted sell output) must be rejected by the distinctness check; got {:?}",
        results[2]
    );
}

/// **Adversarial: over-cap N:M spread is rejected.**
///
/// Same two honest, distinct sells (fair sum = 40M) but the buyer's kas_in is
/// 100M (60M surplus) against a tight 0.30% cap (300K) -- mirrors the
/// existing 1:1 `v16_over_cap_spread_rejected_by_f6` test, generalized to a
/// summed N:M cap.
#[test]
fn nm2_over_cap_spread_rejected() {
    let results = run_nm2_buy(0, 1, 100_000_000, 30, (1, 1), (1, 2), 30_000_000, 20_000_000);
    assert!(results[2].is_err(), "over-cap N:M spread must be rejected; got {:?}", results[2]);
}
