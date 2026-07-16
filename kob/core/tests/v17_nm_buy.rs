//! v17 N:M buy contract — adversarial matrix against the real post-Toccata
//! `kaspa-txscript` `TxScriptEngine` (`covenants_enabled = true`).
//!
//! Builds an N-sells:1-buy sweep tx: inputs [sell_1 .. sell_N, buy, fee], where
//! every sell uses the UNMODIFIED fixed-offset fill sigscript
//! (`build_sell_fill_sigscript_fixed_offset`) and each buyer-token output is a
//! covenant continuation authorized by its own sell input. Executes every
//! covenant input's script and returns the per-input results.

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
    build_buy_v17_fill_sigscript, build_buy_v17_redeem_script,
    build_sell_fill_sigscript_fixed_offset, build_sell_redeem_script, build_buy_v17_body,
    BUY_ORDER_V17_MAX_N,
};
use kob_core::{blake2b_256, build_p2sh, compute_p2pk_spk_hash};

const PUBKEY_HEX: &str = "b40c46552bc5fcf450d7026e8933b78b6f32b6812c9a94bcbf075cfcb4c249e0";
const TOKEN_HEX: &str = "0c113120cb56668a5aa984752496f8cc4ac65e9044f2fa85d64e7bbcb5fc6039";

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

/// A single sell in the sweep.
#[derive(Clone)]
struct Sell {
    price_num: u64,
    price_den: u64,
    tokens: u64, // token_in (fully delivered to the buyer)
}

/// How the buyer-token output for a sell is emitted (for adversarial variants).
#[derive(Clone)]
enum TokenOut {
    /// Honest: value=tokens, spk=buyer, covenant bound to authorizing_input=sell.
    Honest,
    /// Deliver fewer tokens than the sell holds.
    Amount(u64),
    /// Route tokens to a non-buyer SPK.
    WrongSpk,
    /// No covenant binding (plain output) — sell authorizes nothing.
    NoCovenant,
    /// Bind the covenant to a different authorizing input.
    AuthInput(u16),
    /// A different (decoy) token covenant id (exercised via m4's custom tx).
    #[allow(dead_code)]
    WrongTokenId,
}

struct Scenario {
    sells: Vec<Sell>,
    token_outs: Vec<TokenOut>,
    // Sell input indices the buy sigscript references (defaults 0..N).
    tii: Vec<u16>,
    ioc: bool,
    buy_price_num: u64,
    buy_price_den: u64,
    buy_mfill: u64,
    buy_mmfee_bps: u64,
    buy_kas_in: u64,
    // Extra decoy outputs appended after the standard layout.
    extra_token_outputs: Vec<(u64, bool)>, // (value, to_buyer_spk); covenant bound to sell 0
}

/// Standard sweep-tx builder. Layout:
///   inputs:  [sell_0 .. sell_{N-1}, buy, fee]
///   outputs: [sellerKas_0 .. sellerKas_{N-1}, buyerTokens_0 .. buyerTokens_{N-1}, change]
/// Returns (results-per-covenant-input, buy_input_index).
fn run(scn: &Scenario) -> (Vec<Result<(), String>>, usize) {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let tcid_arr = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let decoy_spk = p2pk_spk(&[0xcc; 32]);
    let other_token = Hash::from_bytes([0xff; 32]);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    // Build sells.
    let mut sell_rss = Vec::new();
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for (i, s) in scn.sells.iter().enumerate() {
        let rs = build_sell_redeem_script(
            s.price_num, s.price_den, 1, &owner_hash, &spk_hash, 10_000_000, 0, 0,
        )
        .unwrap();
        // koi = seller KAS output index = i (first N outputs are seller KAS).
        let ss = build_sell_fill_sigscript_fixed_offset(i as u16, &rs);
        inputs.push(TransactionInput::new(op(0x10 + i as u8, 0), ss, 50, 0));
        entries.push(UtxoEntry {
            amount: s.tokens,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token_cov_id),
        });
        sell_rss.push(rs);
    }

    // Buy input.
    let buy_rs = build_buy_v17_redeem_script(
        &tcid_arr, scn.buy_price_num, scn.buy_price_den, scn.buy_mfill, &owner_hash,
        &spk_hash, scn.buy_mmfee_bps, 0, 0,
    )
    .unwrap();
    let buy_ss = build_buy_v17_fill_sigscript(&scn.tii, scn.ioc, &buy_rs);
    let buy_idx = inputs.len();
    inputs.push(TransactionInput::new(op(0x20, 0), buy_ss, 50, 0));
    entries.push(UtxoEntry {
        amount: scn.buy_kas_in,
        script_public_key: build_p2sh(&buy_rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });

    // Fee/change placeholder input (not executed).
    inputs.push(TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1));
    entries.push(UtxoEntry {
        amount: 1_000_000_000,
        script_public_key: wallet_spk.clone(),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });

    // Outputs: seller KAS (N), then buyer tokens (N), then change.
    let mut outputs = Vec::new();
    for s in &scn.sells {
        let kas = s.tokens * s.price_num / s.price_den;
        outputs.push(TransactionOutput::with_covenant(kas, wallet_spk.clone(), None));
    }
    for (i, s) in scn.sells.iter().enumerate() {
        let to = &scn.token_outs[i];
        let (val, spk, cov) = match to {
            TokenOut::Honest => (
                s.tokens,
                wallet_spk.clone(),
                Some(CovenantBinding::new(i as u16, token_cov_id)),
            ),
            TokenOut::Amount(v) => (
                *v,
                wallet_spk.clone(),
                Some(CovenantBinding::new(i as u16, token_cov_id)),
            ),
            TokenOut::WrongSpk => (
                s.tokens,
                decoy_spk.clone(),
                Some(CovenantBinding::new(i as u16, token_cov_id)),
            ),
            TokenOut::NoCovenant => (s.tokens, wallet_spk.clone(), None),
            TokenOut::AuthInput(a) => (
                s.tokens,
                wallet_spk.clone(),
                Some(CovenantBinding::new(*a, token_cov_id)),
            ),
            TokenOut::WrongTokenId => (
                s.tokens,
                wallet_spk.clone(),
                Some(CovenantBinding::new(i as u16, other_token)),
            ),
        };
        outputs.push(TransactionOutput::with_covenant(val, spk, cov));
    }
    for (val, to_buyer) in &scn.extra_token_outputs {
        let spk = if *to_buyer { wallet_spk.clone() } else { decoy_spk.clone() };
        outputs.push(TransactionOutput::with_covenant(
            *val,
            spk,
            Some(CovenantBinding::new(0, token_cov_id)),
        ));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, wallet_spk.clone(), None)); // change

    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        // A malformed covenant graph (e.g. WrongTokenId genesis) fails context
        // construction — treat as rejection of every covenant input.
        Err(e) => return (vec![Err(format!("ctx: {e:?}")); buy_idx + 1], buy_idx),
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };

    let mut results = Vec::new();
    for idx in 0..=buy_idx {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm = TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        results.push(vm.execute().map_err(|e| format!("{e:?}")));
    }
    (results, buy_idx)
}

/// Honest N-sell sweep. Sells price at 99/100 (slightly cheaper than the buy's
/// 1/1 limit), so the matcher earns the ~1% spread as surplus, within cap.
/// Buyer pays kas_in = total_tokens (buy price 1/1), so the limit-price floor
/// (token_sum >= kas_in) holds exactly.
fn honest(n: usize) -> Scenario {
    let sells: Vec<Sell> = (0..n)
        .map(|i| Sell { price_num: 99, price_den: 100, tokens: 10_000_000 * (i as u64 + 1) })
        .collect();
    let total_tokens: u64 = sells.iter().map(|s| s.tokens).sum();
    let token_outs = vec![TokenOut::Honest; n];
    Scenario {
        tii: (0..n as u16).collect(),
        ioc: false,
        buy_price_num: 1,
        buy_price_den: 1,
        buy_mfill: 1_000_000,
        buy_mmfee_bps: 2000,
        buy_kas_in: total_tokens,
        token_outs,
        sells,
        extra_token_outputs: vec![],
    }
}

#[test]
fn v17_body_size_and_rs() {
    let body = build_buy_v17_body();
    eprintln!(
        "v17 body = {}B, RS = {}B (MAX_N={})",
        body.len(),
        145 + body.len(),
        BUY_ORDER_V17_MAX_N
    );
}

#[test]
fn honest_2_sell_sweep_passes() {
    let (res, buy) = run(&honest(2));
    for (i, r) in res.iter().enumerate() {
        eprintln!("input[{i}] -> {r:?}");
    }
    assert!(res[buy].is_ok(), "v17 buy must pass honest 2-sell sweep: {:?}", res[buy]);
    for i in 0..buy {
        assert!(res[i].is_ok(), "sell {i} must pass: {:?}", res[i]);
    }
}

// ======================= FULL ADVERSARIAL MATRIX =======================
// Each test drives a real sweep tx through the post-Toccata TxScriptEngine.
// `buy` is the buy input index; res[buy] is the v17 buy covenant result.

/// #13 — N=1 parity: a single-sell sweep fills the buy (v16 1:1 semantics).
#[test]
fn m13_n1_parity() {
    let (res, buy) = run(&honest(1));
    assert!(res[buy].is_ok(), "N=1 buy must pass: {:?}", res[buy]);
    assert!(res[0].is_ok(), "sell must pass: {:?}", res[0]);
}

/// Honest sweeps across arities 2..=MAX_N all pass.
#[test]
fn honest_sweeps_all_arities_pass() {
    for n in 2..=BUY_ORDER_V17_MAX_N {
        let (res, buy) = run(&honest(n));
        assert!(res[buy].is_ok(), "N={n} buy must pass: {:?}", res[buy]);
        for i in 0..buy {
            assert!(res[i].is_ok(), "N={n} sell {i} must pass: {:?}", res[i]);
        }
    }
}

/// #14 — N=MAX_N boundary succeeds; N=MAX_N+1 cannot be expressed (the builder
/// panics, i.e. the sigscript shape has no slot for it — fails closed).
#[test]
fn m14_max_n_boundary() {
    let (res, buy) = run(&honest(BUY_ORDER_V17_MAX_N));
    assert!(res[buy].is_ok(), "N=MAX_N buy must pass: {:?}", res[buy]);
    let over = std::panic::catch_unwind(|| {
        build_buy_v17_fill_sigscript(&vec![0u16; BUY_ORDER_V17_MAX_N + 1], false, &[0u8; 10])
    });
    assert!(over.is_err(), "N>MAX_N must be unrepresentable (builder must reject)");
}

/// #1 — duplicate tii (adjacent) double-count is rejected by the distinctness
/// (strictly-increasing tii) check.
#[test]
fn m1_duplicate_tii_adjacent_rejected() {
    let mut scn = honest(2);
    scn.tii = vec![0, 0]; // both terms point at sell 0
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "duplicate adjacent tii must be rejected; got {:?}", res[buy]);
}

/// #2 — duplicate tii non-adjacent (slots 0 and 2 collide, slot 1 between).
#[test]
fn m2_duplicate_tii_nonadjacent_rejected() {
    let mut scn = honest(3);
    scn.tii = vec![0, 1, 0]; // not strictly increasing
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "non-adjacent duplicate tii must be rejected; got {:?}", res[buy]);
}

/// #3 — tii points at a non-covenant input (the fee/change input): OpAuthOutputIdx
/// finds zero authorized outputs -> the buy script errors.
#[test]
fn m3_tii_points_at_noncovenant_input_rejected() {
    let mut scn = honest(2);
    // fee input index = buy_idx + 1 = 3 (sells 0,1 + buy 2 + fee 3).
    scn.tii = vec![0, 3];
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "tii at a non-covenant input must be rejected; got {:?}", res[buy]);
}

/// #4 — a summation term references a genuine covenant input of a DIFFERENT
/// token; the per-term OpInputCovenantId(tii)==tcid check rejects it. The second
/// "sell" carries a different covenant id both on its input and its output.
#[test]
fn m4_wrong_token_sell_term_rejected() {
    // Build a bespoke tx: sell_0 is the real token, sell_1 is a DIFFERENT token.
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let other = Hash::from_bytes([0xab; 32]);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let s0 = build_sell_redeem_script(99, 100, 1, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let s1 = build_sell_redeem_script(99, 100, 1, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let ss0 = build_sell_fill_sigscript_fixed_offset(0, &s0);
    let ss1 = build_sell_fill_sigscript_fixed_offset(1, &s1);
    let buy_rs = build_buy_v17_redeem_script(&arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &spk_hash, 2000, 0, 0).unwrap();
    let buy_ss = build_buy_v17_fill_sigscript(&[0, 1], false, &buy_rs);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), ss0, 50, 0),
        TransactionInput::new(op(0x11, 0), ss1, 50, 0),
        TransactionInput::new(op(0x20, 0), buy_ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(9_900_000, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(9_900_000, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(10_000_000, wallet_spk.clone(), Some(CovenantBinding::new(0, token))),
        TransactionOutput::with_covenant(10_000_000, wallet_spk.clone(), Some(CovenantBinding::new(1, other))),
        TransactionOutput::with_covenant(500_000_000, wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry { amount: 10_000_000, script_public_key: build_p2sh(&s0), block_daa_score: 0, is_coinbase: false, covenant_id: Some(token) },
        UtxoEntry { amount: 10_000_000, script_public_key: build_p2sh(&s1), block_daa_score: 0, is_coinbase: false, covenant_id: Some(other) },
        UtxoEntry { amount: 20_000_000, script_public_key: build_p2sh(&buy_rs), block_daa_score: 0, is_coinbase: false, covenant_id: None },
        UtxoEntry { amount: 1_000_000_000, script_public_key: wallet_spk.clone(), block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("ctx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(2);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 2, entry, ctx, flags);
    let r = vm.execute();
    assert!(r.is_err(), "a term referencing a different token's sell must be rejected; got {r:?}");
}

/// #5 — the v17 fill sigscript has NO free toi/coi field; the delivered output
/// is always DERIVED via OpAuthOutputIdx. Assert the sigscript shape: it carries
/// only [MAX_N tii][N][selector][pushData(RS)] — no per-output index.
#[test]
fn m5_no_free_output_index_in_sigscript() {
    let rs = build_buy_v17_redeem_script(&arr32(TOKEN_HEX), 1, 1, 1, &[0u8; 32], &[0u8; 32], 100, 0, 0).unwrap();
    let ss = build_buy_v17_fill_sigscript(&[0, 1], false, &rs);
    // Expected length: MAX_N index pushes (0..=16 => 1 byte each here) + N push
    // + 1 selector + pushData(RS) (PUSHDATA2 => 3 + rs.len()).
    let idx_bytes = BUY_ORDER_V17_MAX_N + 1; // MAX_N tii (small) + N (small), all 1-byte
    let expected = idx_bytes + 1 /*selector*/ + 3 + rs.len();
    assert_eq!(ss.len(), expected, "sigscript must carry no output-index field beyond the tii list");
}

/// #7 — under-delivery: a term's token output is correctly authorized/priced but
/// routed to a non-buyer SPK. The per-term buyer-SPK check rejects it.
#[test]
fn m7_wrong_spk_underdelivery_rejected() {
    let mut scn = honest(2);
    scn.token_outs[1] = TokenOut::WrongSpk;
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "tokens routed away from the buyer must be rejected; got {:?}", res[buy]);
}

/// #9 — per-sell F4 rejects aggregate-drain in the N:M shape: a sell's tokens are
/// drained (its buyer-token output is a plain, non-covenant output), so that sell
/// authorizes nothing. The DRAINED sell's own script fails closed.
#[test]
fn m9_per_sell_f4_rejects_drain() {
    let mut scn = honest(2);
    scn.token_outs[1] = TokenOut::NoCovenant; // sell 1 authorizes no output
    let (res, buy) = run(&scn);
    assert!(res[1].is_err(), "drained sell must fail its own F4; got {:?}", res[1]);
    let _ = buy;
}

/// #6 — over-cap sweep: buyer pays far above the sells' fair value; surplus cap
/// rejects (mirrors v16's over-cap test, generalized to the sum).
#[test]
fn m6_over_cap_sweep_rejected() {
    let mut scn = honest(2);
    // Sells at 1/2 (fair = 0.5*tokens), buy 1/1, tight cap 30bps -> big surplus.
    scn.sells = vec![
        Sell { price_num: 1, price_den: 2, tokens: 10_000_000 },
        Sell { price_num: 1, price_den: 2, tokens: 20_000_000 },
    ];
    scn.buy_mmfee_bps = 30;
    scn.buy_kas_in = 30_000_000; // token_sum=30M >= floor(30M); surplus=15M >> cap
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "over-cap N:M sweep must be rejected; got {:?}", res[buy]);
}

/// Companion to #6: the SAME wide spread within a widened cap passes.
#[test]
fn m6b_within_cap_wide_spread_passes() {
    let mut scn = honest(2);
    scn.sells = vec![
        Sell { price_num: 1, price_den: 2, tokens: 10_000_000 },
        Sell { price_num: 1, price_den: 2, tokens: 20_000_000 },
    ];
    scn.buy_mmfee_bps = 6000; // cap = 30M/10000*6000 = 18M >= 15M surplus
    scn.buy_kas_in = 30_000_000;
    let (res, buy) = run(&scn);
    assert!(res[buy].is_ok(), "wide spread within cap must pass; got {:?}", res[buy]);
}

/// #11 — limit-price floor: sells priced WORSE than the buyer's limit (buyer
/// would receive fewer tokens than kas_in/buy_price), even within the spread
/// cap, must be rejected by the aggregate floor.
#[test]
fn m11_limit_price_floor_violation_rejected() {
    let mut scn = honest(2);
    // Buy limit 1/1 (pays 30M, wants >=30M tokens). Sells deliver only 20M total
    // but priced so the matcher's surplus is tiny (sells at 3/2, fair=1.5*tokens).
    scn.sells = vec![
        Sell { price_num: 3, price_den: 2, tokens: 8_000_000 },
        Sell { price_num: 3, price_den: 2, tokens: 12_000_000 },
    ];
    scn.buy_mmfee_bps = 10000; // cap wide open; only the floor should bite
    scn.buy_kas_in = 30_000_000; // expected floor = 30M tokens, but only 20M delivered
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "limit-price floor violation must be rejected; got {:?}", res[buy]);
}

/// #12 — mixed-price dilution: a cheap sell + an at-cap-violating expensive sell.
/// Surplus is summed in absolute KAS (not price-averaged), so the aggregate cap
/// still bites. Buyer pays 30M, sells fair-value sums below cap boundary.
#[test]
fn m12_mixed_price_over_cap_rejected() {
    let mut scn = honest(2);
    scn.sells = vec![
        Sell { price_num: 1, price_den: 10, tokens: 10_000_000 }, // very cheap (fair 1M)
        Sell { price_num: 1, price_den: 2, tokens: 20_000_000 },  // fair 10M
    ];
    // fair sum = 1M + 10M = 11M; buyer pays 30M -> surplus 19M. floor: token_sum
    // 30M >= 30M ok. cap 30bps=90k -> reject on surplus.
    scn.buy_mmfee_bps = 30;
    scn.buy_kas_in = 30_000_000;
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "mixed-price over-cap must be rejected; got {:?}", res[buy]);
}

/// #15 — IOC + N:M: honest IOC partial delivery within cap passes.
#[test]
fn m15_ioc_within_cap_passes() {
    let mut scn = honest(2);
    scn.ioc = true;
    // IOC relaxes the floor to mfill; buyer still pays fair + capped surplus.
    let (res, buy) = run(&scn);
    assert!(res[buy].is_ok(), "honest IOC sweep must pass; got {:?}", res[buy]);
}

/// #15b — IOC theft: matcher consumes all kas_in but delivers only `mfill`
/// tokens (IOC floor), pocketing the rest. The surplus cap (on delivered fair
/// value) rejects it.
#[test]
fn m15b_ioc_underdelivery_theft_rejected() {
    let mut scn = honest(2);
    scn.ioc = true;
    // Deliver far less than fair: sells hold 10M/20M but only tiny outputs given.
    scn.token_outs = vec![TokenOut::Amount(1_000_000), TokenOut::Amount(2_000_000)];
    scn.buy_mmfee_bps = 30; // tight cap
    scn.buy_kas_in = 30_000_000; // pays full, delivers ~3M -> huge surplus
    let (res, buy) = run(&scn);
    assert!(res[buy].is_err(), "IOC under-delivery theft must be rejected; got {:?}", res[buy]);
}

/// #8 — a term's delivered output value exceeds the sell's own token_in. This is
/// bounded by the sell's own F4 (>=), not by the buy; the buy adds no new
/// exposure. Here the sell over-delivers to the buyer (more tokens than it held)
/// which only helps the buyer — the buy still passes, the invariant being that
/// the buy never LOSES on extra delivery.
#[test]
fn m8_over_delivery_no_new_exposure() {
    let mut scn = honest(2);
    // sell 1 holds 20M but 25M is delivered to the buyer (over-delivery).
    scn.token_outs[1] = TokenOut::Amount(25_000_000);
    // widen cap so the extra fair value (priced at sell 1's 99/100) stays under.
    scn.buy_mmfee_bps = 10000;
    let (res, buy) = run(&scn);
    // Over-delivery raises fair_sum above kas_in -> surplus goes negative, cap
    // trivially satisfied; floor satisfied. The buy passes (no new exposure).
    assert!(res[buy].is_ok(), "over-delivery must not create buy-side exposure; got {:?}", res[buy]);
}

/// A decoy extra token output (bound to sell 0 as its auth[1], to the buyer)
/// does NOT inflate the summed delivery: the buy counts only auth[0] of each
/// referenced sell. The honest sweep still passes and the surplus is unchanged.
#[test]
fn decoy_extra_token_output_not_counted() {
    let mut scn = honest(2);
    scn.extra_token_outputs = vec![(50_000_000, true)]; // big decoy to the buyer
    let (res, buy) = run(&scn);
    // The decoy is auth[1] of sell 0, never read; token_sum/fair_sum unchanged,
    // so the honest sweep verifies exactly as without it.
    assert!(res[buy].is_ok(), "decoy token output must not affect the buy; got {:?}", res[buy]);
}

/// #10 — a forged sell price is structurally impossible: the sell's P2SH commits
/// its redeemScript (incl. price bytes). Embedding a different-priced RS in the
/// sell sigscript makes the sell input's own P2SH hash check fail. Here sell 0's
/// UTXO commits a 99/100 RS but the sigscript embeds a forged 1/2 RS.
#[test]
fn m10_forged_sell_price_rejected() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let real_rs = build_sell_redeem_script(99, 100, 1, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    let forged_rs = build_sell_redeem_script(1, 2, 1, &owner_hash, &spk_hash, 10_000_000, 0, 0).unwrap();
    // sigscript embeds the FORGED rs; the UTXO SPK commits the REAL rs.
    let ss = build_sell_fill_sigscript_fixed_offset(0, &forged_rs);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(9_900_000, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(10_000_000, wallet_spk.clone(), Some(CovenantBinding::new(0, token))),
    ];
    let entries = vec![
        UtxoEntry { amount: 10_000_000, script_public_key: build_p2sh(&real_rs), block_daa_score: 0, is_coinbase: false, covenant_id: Some(token) },
        UtxoEntry { amount: 1_000_000_000, script_public_key: wallet_spk.clone(), block_daa_score: 0, is_coinbase: false, covenant_id: None },
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).expect("ctx");
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 0, entry, ctx, flags);
    let r = vm.execute();
    assert!(r.is_err(), "a forged-price sell sigscript must fail the P2SH commitment; got {r:?}");
}

/// A sell's token output is bound to the WRONG authorizing input (sell 1's
/// tokens are authorized by input 0, not input 1). Sell 1 then authorizes no
/// auth[0], so the buy's OpAuthOutputIdx(1,0) has nothing to resolve AND sell 1
/// fails its own F4 — the sweep is rejected on both sides.
#[test]
fn wrong_auth_input_binding_rejected() {
    let mut scn = honest(2);
    scn.token_outs[1] = TokenOut::AuthInput(0); // bind sell 1's tokens to input 0
    let (res, buy) = run(&scn);
    assert!(
        res[buy].is_err() || res[1].is_err(),
        "mis-authorized token output must be rejected; buy={:?} sell1={:?}",
        res[buy], res[1]
    );
}

/// #16 (part) — v17 body/RS length matches the pinned constants, and the RS
/// size is DISTINCT from every other spot-contract dispatch length (no sigLen
/// collision that could misroute a v17 order through another parser).
#[test]
fn v17_lengths_and_no_collision() {
    use kob_core::contract::spot::order::{
        BUY_ORDER_V17_BODY_EXPECTED_LEN, BUY_ORDER_V17_RS_EXPECTED_LEN,
        BUY_ORDER_BODY_EXPECTED_LEN, BUY_ORDER_V16_RS_EXPECTED_LEN,
        SELL_ORDER_RS_EXPECTED_LEN,
    };
    let body = build_buy_v17_body();
    assert_eq!(body.len(), BUY_ORDER_V17_BODY_EXPECTED_LEN, "v17 body length pin");
    let rs = build_buy_v17_redeem_script(&arr32(TOKEN_HEX), 1, 1, 1, &[0u8; 32], &[0u8; 32], 100, 0, 0).unwrap();
    assert_eq!(rs.len(), BUY_ORDER_V17_RS_EXPECTED_LEN, "v17 RS length pin");
    // Distinct from v14 buy (145+251=396), v16 buy (476), sell (427).
    let v14_rs = 145 + BUY_ORDER_BODY_EXPECTED_LEN;
    assert_ne!(rs.len(), v14_rs);
    assert_ne!(rs.len(), BUY_ORDER_V16_RS_EXPECTED_LEN);
    assert_ne!(rs.len(), SELL_ORDER_RS_EXPECTED_LEN);
    // First body byte is the selector dispatch (Op9 = 0x59), distinguishing it
    // from v14/v16 (0xb9 length dispatch).
    assert_eq!(rs[145], 0x59, "v17 body must start with Op9 (selector dispatch)");
}


// ===== Lifecycle paths (expire / cancel) =====

use kob_core::contract::spot::order::{
    build_buy_v17_expire_sigscript, build_buy_v17_cancel_sigscript,
};

/// v17 EXPIRE: after expiry, the buyer reclaims their locked KAS (output[0] to
/// the buyer's SPK, value >= input). Verifies the selector-dispatched expire path.
#[test]
fn v17_expire_refund_passes() {
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let buy_rs = build_buy_v17_redeem_script(&arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &spk_hash, 30, 0, 1000).unwrap();
    let ss = build_buy_v17_expire_sigscript(&buy_rs);
    // tx.lockTime = 2000 >= expiry 1000; input sequence != MAX (0).
    let inputs = vec![TransactionInput::new(op(0x20, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), None)];
    let entries = vec![UtxoEntry { amount: 30_000_000, script_public_key: build_p2sh(&buy_rs), block_daa_score: 0, is_coinbase: false, covenant_id: None }];
    let tx = Transaction::new(1, inputs, outputs, 2000, Default::default(), 0, vec![]);
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).unwrap();
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 0, entry, ctx, flags);
    let r = vm.execute();
    assert!(r.is_ok(), "v17 expire refund must pass; got {r:?}");
}

/// v17 EXPIRE before expiry is rejected (CLTV: expiry > lockTime).
#[test]
fn v17_expire_before_expiry_rejected() {
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let buy_rs = build_buy_v17_redeem_script(&arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &spk_hash, 30, 0, 5000).unwrap();
    let ss = build_buy_v17_expire_sigscript(&buy_rs);
    let inputs = vec![TransactionInput::new(op(0x20, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), None)];
    let entries = vec![UtxoEntry { amount: 30_000_000, script_public_key: build_p2sh(&buy_rs), block_daa_score: 0, is_coinbase: false, covenant_id: None }];
    let tx = Transaction::new(1, inputs, outputs, 1000, Default::default(), 0, vec![]); // lockTime 1000 < expiry 5000
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).unwrap();
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 0, entry, ctx, flags);
    assert!(vm.execute().is_err(), "expire before expiry_daa must be rejected");
}

/// v17 CANCEL structural check: with the REAL owner pubkey, the blake2b(pk)==ohash
/// gate passes and execution reaches OpCheckSigVerify (which fails on the dummy
/// signature). A stack bug before that point would surface a different error
/// class; a clean signature-failure confirms the cancel stack choreography.
#[test]
fn v17_cancel_reaches_checksig() {
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let buy_rs = build_buy_v17_redeem_script(&arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &spk_hash, 30, 0, 0).unwrap();
    // dummy 64-byte sig — well-formed length but invalid signature.
    let sig = [0x11u8; 64];
    let ss = build_buy_v17_cancel_sigscript(&pubkey, &sig, false, &buy_rs);
    let inputs = vec![TransactionInput::new(op(0x20, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), None)];
    let entries = vec![UtxoEntry { amount: 30_000_000, script_public_key: build_p2sh(&buy_rs), block_daa_score: 0, is_coinbase: false, covenant_id: None }];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).unwrap();
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
    let (input, entry) = populated.populated_input(0);
    let mut vm = TxScriptEngine::from_transaction_input(&populated, input, 0, entry, ctx, flags);
    let e = format!("{:?}", vm.execute().unwrap_err());
    // Must be a signature-class failure (reached OpCheckSigVerify), not a stack
    // or number error from a mis-counted pick.
    assert!(
        e.contains("Sig") || e.contains("sig") || e.contains("Verify") || e.contains("Null") || e.contains("Schnorr"),
        "cancel must reach OpCheckSigVerify (signature failure), got a different error: {e}"
    );
    assert!(
        !e.contains("NumberTooBig") && !e.contains("InvalidStack") && !e.contains("pick"),
        "cancel must not have a stack/number error before the signature check: {e}"
    );
}
