//! v18 unified spot contracts — adversarial matrix against the real
//! post-Toccata `kaspa-txscript` `TxScriptEngine` (`covenants_enabled = true`).
//!
//! Covers (Stage A, kob/V18_DESIGN.md):
//!   - buy v18 N:M GTC/IOC happy paths + duplicate-tii + decoy price input,
//!   - sell v18 canonical price attestation (mismatch fails) + partial Fix-3,
//!   - buy v18 Op2 partial: happy path multi-event, residual-SPK forgery,
//!     same-RS dual-buy uniqueness guard, residual==0, spent-based floor/cap
//!     boundaries, mfill boundary, cpend=1 reject, 17-input guard reject,
//!     grind-split non-increase arithmetic,
//!   - OCO v18: SL swept at SL price passes / at TP price fails,
//!   - swap v18: 2-cycle + 3-cycle ring settle, slot-0 theft, giver decoy,
//!     F4 conservation-cap boundary.

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
    build_oco_sell_expire_sigscript, build_oco_sell_redeem_script,
    build_oco_sell_sl_fill_sigscript, build_oco_sell_tp_fill_sigscript,
};
use kob_core::contract::spot::order::{
    build_buy_cancel_sigscript, build_buy_expire_sigscript,
    build_buy_fill_sigscript, build_buy_partial_fill_sigscript,
    build_buy_redeem_script, build_buy_redeem_script_with_caps,
    build_sell_expire_sigscript, build_sell_fill_sigscript,
    build_sell_ioc_fill_sigscript, build_sell_partial_fill_sigscript,
    build_sell_redeem_script, build_sell_redeem_script_with_caps,
    BUY_GUARD_INPUTS, BUY_ORDER_MAX_N,
};
use kob_core::contract::spot::swap::{build_swap_fill_sigscript, build_swap_redeem_script};
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

/// Execute the scripts of inputs `0..=last_idx` and return per-input results.
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

// ===========================================================================
// Buy v18 sweep harness (GTC / IOC / Op2 partial)
// ===========================================================================

#[derive(Clone)]
enum TokenOut {
    /// value = sell's tokens, spk = buyer wallet, covenant auth = the sell.
    Honest,
    /// Deliver a specific amount instead.
    Amount(u64),
    /// Route the tokens to a non-buyer SPK.
    WrongSpk,
    /// No covenant binding at all (plain output).
    NoCovenant,
}

#[derive(Clone)]
struct SellSpec {
    price_num: u64,
    price_den: u64,
    tokens: u64,
    /// Attested (pnum, pden) in the sigscript; None = the state price.
    attested: Option<(u64, u64)>,
    token_out: TokenOut,
    /// Owner batch cap in the sell state (LIMITS re-freeze).
    batch_max: u8,
}

impl SellSpec {
    fn honest(price_num: u64, price_den: u64, tokens: u64) -> Self {
        SellSpec {
            price_num,
            price_den,
            tokens,
            attested: None,
            token_out: TokenOut::Honest,
            batch_max: 255,
        }
    }
}

#[derive(Clone)]
enum BuyMode {
    Fill { ioc: bool },
    /// Op2 partial with the given residual amount on the residual output.
    Partial { residual: u64 },
}

#[derive(Clone)]
struct Scn {
    sells: Vec<SellSpec>,
    /// Sell input indices the buy sigscript references (default 0..N).
    tii: Vec<u16>,
    mode: BuyMode,
    buy_price_num: u64,
    buy_price_den: u64,
    buy_mfill: u64,
    buy_mmfee_bps: u64,
    buy_kas_in: u64,
    buy_cpend: u8,
    /// Add a second identical-RS buy input (uniqueness-guard tests).
    dual_buy: bool,
    /// Pad the tx with extra (non-executed) wallet inputs.
    extra_wallet_inputs: usize,
    /// Residual output carries a DIFFERENT buy RS's P2SH (forgery test).
    forge_residual_spk: bool,
    /// Owner batch cap in the buy state (LIMITS re-freeze).
    buy_n_max: u8,
    /// Hand-roll the fill sigscript with this N instead of tii.len()
    /// (bypasses the builder assert for over-MAX_N adversarial shapes).
    force_n: Option<u16>,
}

impl Scn {
    fn gtc(sells: Vec<SellSpec>, kas_in: u64) -> Self {
        let n = sells.len();
        Scn {
            sells,
            tii: (0..n as u16).collect(),
            mode: BuyMode::Fill { ioc: false },
            buy_price_num: 1,
            buy_price_den: 1,
            buy_mfill: 1_000_000,
            buy_mmfee_bps: 2000,
            buy_kas_in: kas_in,
            buy_cpend: 0,
            dual_buy: false,
            extra_wallet_inputs: 0,
            forge_residual_spk: false,
            buy_n_max: BUY_ORDER_MAX_N as u8,
            force_n: None,
        }
    }
}

/// Honest N-sell GTC sweep: sells at 99/100, buy limit 1/1, kas_in = tokens.
fn honest(n: usize) -> Scn {
    let sells: Vec<SellSpec> =
        (0..n).map(|i| SellSpec::honest(99, 100, 10_000_000 * (i as u64 + 1))).collect();
    let total: u64 = sells.iter().map(|s| s.tokens).sum();
    Scn::gtc(sells, total)
}

/// Standard sweep-tx builder. Layout:
///   inputs:  [sell_0 .. sell_{N-1}, buy, (buy2), fee, extra...]
///   outputs: [sellerKas_0 .. sellerKas_{N-1}, buyerTokens_0 .. _{N-1},
///             (residual), change]
/// Returns (results for inputs 0..=buy, buy input index).
fn run_sweep(scn: &Scn) -> (Vec<Result<(), String>>, usize) {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let tcid_arr = arr32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let decoy_spk = p2pk_spk(&[0xcc; 32]);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let n = scn.sells.len();

    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for (i, s) in scn.sells.iter().enumerate() {
        let rs = build_sell_redeem_script_with_caps(
            s.batch_max, s.price_num, s.price_den, 1, &owner_hash, &spk_hash,
            &spk_hash, 30, 0, 0,
        )
        .unwrap();
        let (att_pn, att_pd) = s.attested.unwrap_or((s.price_num, s.price_den));
        let ss = build_sell_fill_sigscript(i as u16, att_pn, att_pd, &rs);
        inputs.push(TransactionInput::new(op(0x10 + i as u8, 0), ss, 50, 0));
        entries.push(UtxoEntry {
            amount: s.tokens,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token_cov_id),
        });
    }

    let buy_rs = build_buy_redeem_script_with_caps(
        scn.buy_n_max,
        &tcid_arr,
        scn.buy_price_num,
        scn.buy_price_den,
        scn.buy_mfill,
        &owner_hash,
        &spk_hash,
        &spk_hash,
        scn.buy_mmfee_bps,
        scn.buy_cpend,
        0,
    )
    .unwrap();
    let residual_idx = (2 * n) as u16;
    let buy_ss = match (&scn.mode, scn.force_n) {
        (BuyMode::Fill { ioc }, None) => build_buy_fill_sigscript(&scn.tii, *ioc, &buy_rs),
        (BuyMode::Fill { ioc }, Some(forced)) => {
            // Hand-rolled fill sigscript with a forged N (the builder
            // asserts N <= MAX_N, so adversarial N=33 must be assembled
            // manually): [tii_1..tii_MAX_N][N][selector][pushData(RS)].
            let mut ss = Vec::new();
            for i in 0..BUY_ORDER_MAX_N {
                let v = scn.tii.get(i).copied().unwrap_or(0);
                kob_core::contract::helpers::push_index(&mut ss, v);
            }
            kob_core::contract::helpers::push_index(&mut ss, forced);
            ss.push(if *ioc { 0x55 } else { 0x51 });
            ss.extend_from_slice(&kob_core::primitives::push_data(&buy_rs));
            ss
        }
        (BuyMode::Partial { .. }, _) => {
            build_buy_partial_fill_sigscript(&scn.tii, residual_idx, &buy_rs)
        }
    };
    let buy_idx = inputs.len();
    inputs.push(TransactionInput::new(op(0xA0, 0), buy_ss, 50, 0));
    entries.push(UtxoEntry {
        amount: scn.buy_kas_in,
        script_public_key: build_p2sh(&buy_rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });

    if scn.dual_buy {
        // A second UTXO with the SAME redeem script (same P2SH SPK). Its own
        // script is not executed here; its mere presence must trip the
        // spending buy's uniqueness guard.
        inputs.push(TransactionInput::new(op(0xA1, 0), vec![0x01, 0x00], 50, 0));
        entries.push(UtxoEntry {
            amount: scn.buy_kas_in,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        });
    }

    // Fee/change placeholder input (not executed).
    inputs.push(TransactionInput::new(op(0xB0, 0), vec![0x41; 66], 0, 1));
    entries.push(UtxoEntry {
        amount: 1_000_000_000,
        script_public_key: wallet_spk.clone(),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });
    for j in 0..scn.extra_wallet_inputs {
        inputs.push(TransactionInput::new(op(0xC0 + j as u8, 0), vec![0x41; 66], 0, 1));
        entries.push(UtxoEntry {
            amount: 1_000_000,
            script_public_key: wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        });
    }

    // Outputs.
    let mut outputs = Vec::new();
    for s in &scn.sells {
        let kas = s.tokens * s.price_num / s.price_den;
        outputs.push(TransactionOutput::with_covenant(kas, wallet_spk.clone(), None));
    }
    for (i, s) in scn.sells.iter().enumerate() {
        let (val, spk, cov) = match &s.token_out {
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
        };
        outputs.push(TransactionOutput::with_covenant(val, spk, cov));
    }
    if let BuyMode::Partial { residual } = &scn.mode {
        let res_spk = if scn.forge_residual_spk {
            // A buy RS with a different state (price 3/1) — different P2SH.
            let other = build_buy_redeem_script(
                &tcid_arr, 3, 1, scn.buy_mfill, &owner_hash, &spk_hash,
                &spk_hash, scn.buy_mmfee_bps, 0, 0,
            )
            .unwrap();
            build_p2sh(&other)
        } else {
            build_p2sh(&buy_rs)
        };
        outputs.push(TransactionOutput::with_covenant(*residual, res_spk, None));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, wallet_spk.clone(), None));

    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let results = exec_inputs(&tx, entries, buy_idx);
    (results, buy_idx)
}

// ===========================================================================
// N:M GTC / IOC happy paths + core sweep adversarial cases
// ===========================================================================

#[test]
fn gtc_sweeps_all_arities_pass() {
    // Representative arities incl. both boundaries of the re-frozen
    // MAX_N=32 slot table (1..=8 = the pre-refreeze range, 31/32 = the new
    // top slots; every slot k is exercised by some N >= k in this set).
    for n in [1usize, 2, 3, 4, 5, 6, 7, 8, 15, 16, 31, 32] {
        let (res, buy) = run_sweep(&honest(n));
        assert!(res[buy].is_ok(), "N={n} v18 buy must pass: {:?}", res[buy]);
        for i in 0..buy {
            assert!(res[i].is_ok(), "N={n} v18 sell {i} must pass: {:?}", res[i]);
        }
    }
}

#[test]
fn ioc_sweep_passes() {
    let mut scn = honest(2);
    scn.mode = BuyMode::Fill { ioc: true };
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_ok(), "IOC sweep must pass: {:?}", res[buy]);
    for i in 0..buy {
        assert!(res[i].is_ok(), "sell {i} must pass: {:?}", res[i]);
    }
}

#[test]
fn duplicate_tii_adjacent_rejected() {
    let mut scn = honest(2);
    scn.tii = vec![0, 0];
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "duplicate adjacent tii must be rejected; got {:?}", res[buy]);
}

#[test]
fn duplicate_tii_nonadjacent_rejected() {
    let mut scn = honest(3);
    scn.tii = vec![0, 1, 0];
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "non-adjacent duplicate tii must be rejected; got {:?}", res[buy]);
}

/// Decoy price input: the buy's price reads happen on the covenant-
/// authenticated `tii` only. A matcher-controlled plain-KAS input carrying a
/// canonical-looking sigscript prefix (forged cheap price at [3..11)/[12..20))
/// must NOT be usable as a summation term: `OpInputCovenantId(tii) != tcid`.
#[test]
fn decoy_price_input_rejected() {
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let sell_rs =
        build_sell_redeem_script(99, 100, 1, &owner_hash, &spk_hash, &spk_hash, 30, 0, 0).unwrap();
    let sell_ss = build_sell_fill_sigscript(0, 99, 100, &sell_rs);
    let buy_rs = build_buy_redeem_script(
        &arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &spk_hash,
        &spk_hash, 2000, 0, 0,
    )
    .unwrap();
    // Decoy wallet input whose sigscript mimics the canonical attested prefix
    // with an absurdly cheap forged price (1/1000000).
    let decoy_ss = build_sell_fill_sigscript(0, 1, 1_000_000, &sell_rs);
    // The buy references the decoy (input 1) as its second term.
    let buy_ss = build_buy_fill_sigscript(&[0, 1], false, &buy_rs);

    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sell_ss, 50, 0),
        TransactionInput::new(op(0x11, 0), decoy_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), buy_ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(9_900_000, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            10_000_000,
            wallet_spk.clone(),
            Some(CovenantBinding::new(0, token)),
        ),
        TransactionOutput::with_covenant(500_000_000, wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry {
            amount: 10_000_000,
            script_public_key: build_p2sh(&sell_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token),
        },
        UtxoEntry {
            amount: 1_000_000,
            script_public_key: wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None, // decoy has NO covenant id
        },
        UtxoEntry {
            amount: 20_000_000,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        UtxoEntry {
            amount: 1_000_000_000,
            script_public_key: wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    let res = exec_inputs(&tx, entries, 2);
    assert!(res[2].is_err(), "decoy price input must be rejected; got {:?}", res[2]);
}

#[test]
fn limit_price_floor_violation_rejected() {
    let mut scn = honest(2);
    // Sells priced worse than the buyer's 1/1 limit; cap wide open.
    scn.sells = vec![SellSpec::honest(3, 2, 8_000_000), SellSpec::honest(3, 2, 12_000_000)];
    scn.buy_mmfee_bps = 10000;
    scn.buy_kas_in = 30_000_000; // floor 30M tokens, only 20M delivered
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "limit floor violation must be rejected; got {:?}", res[buy]);
}

#[test]
fn over_cap_sweep_rejected() {
    let mut scn = honest(2);
    scn.sells = vec![SellSpec::honest(1, 2, 10_000_000), SellSpec::honest(1, 2, 20_000_000)];
    scn.buy_mmfee_bps = 30;
    scn.buy_kas_in = 30_000_000; // fair 15M, surplus 15M >> cap
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "over-cap sweep must be rejected; got {:?}", res[buy]);
}

/// IOC theft: the matcher consumes the full kas_in but delivers only dust
/// (above nothing but the IOC floor). The surplus cap on the DELIVERED fair
/// value rejects it.
#[test]
fn ioc_underdelivery_theft_rejected() {
    let mut scn = honest(2);
    scn.mode = BuyMode::Fill { ioc: true };
    scn.sells[0].token_out = TokenOut::Amount(1_000_000);
    scn.sells[1].token_out = TokenOut::Amount(2_000_000);
    scn.buy_mmfee_bps = 30;
    scn.buy_kas_in = 30_000_000;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "IOC under-delivery theft must be rejected; got {:?}", res[buy]);
}

/// A term's output is correctly priced/authorized but routed to a non-buyer
/// SPK: the per-term buyer-SPK check rejects the sweep.
#[test]
fn wrong_spk_delivery_rejected() {
    let mut scn = honest(2);
    scn.sells[1].token_out = TokenOut::WrongSpk;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "tokens routed away from the buyer must be rejected; got {:?}", res[buy]);
}

/// A drained sell (its tokens leave the covenant entirely) fails its OWN F4.
#[test]
fn drained_sell_fails_own_f4() {
    let mut scn = honest(2);
    scn.sells[1].token_out = TokenOut::NoCovenant;
    let (res, _buy) = run_sweep(&scn);
    assert!(res[1].is_err(), "drained sell must fail its own F4; got {:?}", res[1]);
}

// ===========================================================================
// Sell v18 attestation
// ===========================================================================

/// A plain sell whose sigscript attests a DIFFERENT price than its state must
/// fail its own script (the attestation equality), even though the sell's own
/// price calc uses the state price.
#[test]
fn sell_attestation_mismatch_rejected() {
    let mut scn = honest(2);
    // Sell 1 attests 1/2 while its state says 99/100. Give the sweep a wide
    // cap so the (cheaper) attested price could only HELP the buy — the sell
    // itself must be the one that rejects.
    scn.sells[1].attested = Some((1, 2));
    scn.buy_mmfee_bps = 10000;
    let (res, _buy) = run_sweep(&scn);
    assert!(res[1].is_err(), "attestation mismatch must fail the sell; got {:?}", res[1]);
}

/// Companion: honest attestation passes (covered by the happy path, pinned
/// here at N=1 for a minimal repro).
#[test]
fn sell_attestation_honest_passes() {
    let (res, buy) = run_sweep(&honest(1));
    assert!(res[0].is_ok(), "honest attested sell must pass: {:?}", res[0]);
    assert!(res[buy].is_ok(), "buy must pass: {:?}", res[buy]);
}

// ===========================================================================
// Buy v18 Op2 partial fill
// ===========================================================================

/// Event 1 of a partial chain: buy holds 30M KAS, spends 10M against one
/// 10M-token sell at 99/100, keeps a 20M self-SPK residual.
fn partial_event(kas_in: u64, residual: u64, tokens: u64) -> Scn {
    let mut scn = Scn::gtc(vec![SellSpec::honest(99, 100, tokens)], kas_in);
    scn.mode = BuyMode::Partial { residual };
    scn
}

#[test]
fn partial_happy_path_multi_event() {
    // Event 1: 30M -> spend 10M, residual 20M (10M tokens delivered).
    let (res, buy) = run_sweep(&partial_event(30_000_000, 20_000_000, 10_000_000));
    assert!(res[buy].is_ok(), "partial event 1 must pass: {:?}", res[buy]);
    assert!(res[0].is_ok(), "event-1 sell must pass: {:?}", res[0]);
    // Event 2: the residual UTXO (20M) spends 15M, keeps 5M.
    let (res, buy) = run_sweep(&partial_event(20_000_000, 5_000_000, 15_000_000));
    assert!(res[buy].is_ok(), "partial event 2 must pass: {:?}", res[buy]);
    assert!(res[0].is_ok(), "event-2 sell must pass: {:?}", res[0]);
}

#[test]
fn partial_multi_sell_passes() {
    // One partial event sweeping TWO sells at once.
    let mut scn = Scn::gtc(
        vec![SellSpec::honest(99, 100, 4_000_000), SellSpec::honest(99, 100, 6_000_000)],
        30_000_000,
    );
    scn.mode = BuyMode::Partial { residual: 20_000_000 };
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_ok(), "multi-sell partial must pass: {:?}", res[buy]);
    for i in 0..buy {
        assert!(res[i].is_ok(), "sell {i} must pass: {:?}", res[i]);
    }
}

/// Residual-SPK forgery: the residual output pays a DIFFERENT buy RS (other
/// state, e.g. a worse price). Byte-exact SPK equality must reject it.
#[test]
fn partial_residual_spk_forgery_rejected() {
    let mut scn = partial_event(30_000_000, 20_000_000, 10_000_000);
    scn.forge_residual_spk = true;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "forged residual SPK must be rejected; got {:?}", res[buy]);
}

/// Two identical-RS buy UTXOs in one tx sharing one residual output: the
/// self-instance uniqueness guard (count == 1) must fail the spend.
#[test]
fn partial_same_rs_dual_buy_rejected() {
    let mut scn = partial_event(30_000_000, 20_000_000, 10_000_000);
    scn.dual_buy = true;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "same-RS dual buy must be rejected; got {:?}", res[buy]);
}

/// residual == 0 must use selector 1/5; Op2 rejects it (residual >= 1).
#[test]
fn partial_zero_residual_rejected() {
    // Sell delivers the full 30M-worth so the floor would hold if this were
    // a fill; the zero residual alone must kill the Op2 path.
    let (res, buy) = run_sweep(&partial_event(30_000_000, 0, 30_000_000));
    assert!(res[buy].is_err(), "zero residual on Op2 must be rejected; got {:?}", res[buy]);
}

/// Spent-based floor boundary: token_sum == spent/pden*pnum passes; one token
/// less fails. (buy 1/1, spent = 10M.)
#[test]
fn partial_floor_boundary() {
    // Exactly at the floor: 10M tokens for 10M spent.
    let (res, buy) = run_sweep(&partial_event(30_000_000, 20_000_000, 10_000_000));
    assert!(res[buy].is_ok(), "at-floor partial must pass: {:?}", res[buy]);
    // One below: sell holds (and fully delivers) 9_999_999 tokens.
    let (res, buy) = run_sweep(&partial_event(30_000_000, 20_000_000, 9_999_999));
    assert!(res[buy].is_err(), "one-below-floor partial must fail; got {:?}", res[buy]);
}

/// Per-event mfill floor: token_sum >= mfill even when the spent-based floor
/// is lower (blocks dust-grind events).
#[test]
fn partial_mfill_boundary() {
    // buy 1/1, mfill 5M. spent = 3M -> spent-floor 3M < mfill.
    // Sell at 1/2 (cheap) delivering 5M tokens: passes (== mfill).
    let mk = |tokens: u64| {
        let mut scn = Scn::gtc(vec![SellSpec::honest(1, 2, tokens)], 30_000_000);
        scn.buy_mfill = 5_000_000;
        scn.mode = BuyMode::Partial { residual: 27_000_000 }; // spent = 3M
        scn
    };
    let (res, buy) = run_sweep(&mk(5_000_000));
    assert!(res[buy].is_ok(), "token_sum == mfill must pass: {:?}", res[buy]);
    let (res, buy) = run_sweep(&mk(4_999_999));
    assert!(res[buy].is_err(), "token_sum < mfill must fail; got {:?}", res[buy]);
}

/// Spent-based surplus cap boundary: surplus == spent/10000*mmfee passes; one
/// sompi more fails. (buy 9/10 so the limit floor isn't the binding check.)
#[test]
fn partial_cap_boundary() {
    let mk = |tokens: u64| {
        // Sell at 1/1: fair = tokens. spent = 10M, cap(100bps) = 100_000.
        let mut scn = Scn::gtc(vec![SellSpec::honest(1, 1, tokens)], 30_000_000);
        scn.buy_price_num = 9;
        scn.buy_price_den = 10; // spent-floor = 9M
        scn.buy_mmfee_bps = 100;
        scn.mode = BuyMode::Partial { residual: 20_000_000 }; // spent = 10M
        scn
    };
    // surplus = 10M - 9_900_000 = 100_000 == cap -> pass.
    let (res, buy) = run_sweep(&mk(9_900_000));
    assert!(res[buy].is_ok(), "surplus == cap must pass: {:?}", res[buy]);
    // surplus = 100_001 > cap -> fail (floor 9M still satisfied).
    let (res, buy) = run_sweep(&mk(9_899_999));
    assert!(res[buy].is_err(), "surplus > cap must fail; got {:?}", res[buy]);
}

/// Grind-split non-increase (pure arithmetic, mirrors the covenant's integer
/// ops): splitting one fill into k partial events cannot increase the total
/// extractable surplus, because floor division is superadditive-compatible:
/// sum(floor(x_i/10000)*bps) <= floor(sum(x_i)/10000)*bps.
#[test]
fn partial_grind_split_no_extra_extraction() {
    let cap = |spent: u64, bps: u64| spent / 10000 * bps;
    let cases: &[(&[u64], u64)] = &[
        (&[10_000_000], 30),
        (&[5_000_000, 5_000_000], 30),
        (&[3_333_333, 3_333_333, 3_333_334], 30),
        (&[9_999, 9_999, 9_980_002], 30), // sub-10000 dust events cap at 0
        (&[1, 1, 1, 9_999_997], 250),
        (&[123_456, 654_321, 9_222_223], 250),
    ];
    for (parts, bps) in cases {
        let total: u64 = parts.iter().sum();
        let whole_cap = cap(total, *bps);
        let split_cap: u64 = parts.iter().map(|p| cap(*p, *bps)).sum();
        assert!(
            split_cap <= whole_cap,
            "split extraction {split_cap} must not exceed whole-fill cap {whole_cap} ({parts:?})"
        );
    }
}

/// cpend == 1 (cancel-pending) must reject Op2 partial (F5).
#[test]
fn partial_cpend_rejected() {
    let mut scn = partial_event(30_000_000, 20_000_000, 10_000_000);
    scn.buy_cpend = 1;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "cpend=1 partial must be rejected; got {:?}", res[buy]);
}

/// Uniqueness-guard boundary at the DERIVED bound (BUY_GUARD_INPUTS =
/// MAX_N + 2 = 34): the scan covers i=0..33 and requires
/// OpTxInputCount <= 34 — a 35th input (which could hide a second identical
/// buy beyond the scan) fails the spend. 34 inputs exactly still pass.
#[test]
fn partial_input_count_guard() {
    assert_eq!(BUY_GUARD_INPUTS, 34, "derived guard bound = MAX_N + 2");
    // sells(1) + buy + fee = 3 inputs; pad to exactly 34 -> pass.
    let mut scn = partial_event(30_000_000, 20_000_000, 10_000_000);
    scn.extra_wallet_inputs = BUY_GUARD_INPUTS - 3;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_ok(), "34-input partial must pass: {:?}", res[buy]);
    // Pad to 35 -> guard rejects.
    let mut scn = partial_event(30_000_000, 20_000_000, 10_000_000);
    scn.extra_wallet_inputs = BUY_GUARD_INPUTS - 2;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "35-input partial must be rejected; got {:?}", res[buy]);
}

// ===========================================================================
// LIMITS re-freeze — owner batch caps (n_max / batch_max) + MAX_N boundary
// ===========================================================================

/// N=33 rejected BY THE COVENANT: the fill sigscript carries only MAX_N=32
/// tii slots, and the in-body owner cap `N <= n_max` (n_max <= 32 enforced
/// at build) kills any forged N above the slot table. Hand-rolled sigscript
/// because the builder asserts N <= MAX_N.
#[test]
fn fill_n_33_rejected_by_covenant() {
    let mut scn = honest(32);
    scn.force_n = Some(33);
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "N=33 must be rejected by the covenant; got {:?}", res[buy]);
    // Control: the same 32-sell shape with the honest N=32 passes.
    let (res, buy) = run_sweep(&honest(32));
    assert!(res[buy].is_ok(), "honest N=32 control must pass: {:?}", res[buy]);
}

/// Owner cap beats matcher: a buy deployed with n_max=4 rejects an N=5
/// sweep even though the slot table (MAX_N=32) could carry it; N=4 passes.
#[test]
fn fill_n_above_n_max_rejected() {
    let mut scn = honest(5);
    scn.buy_n_max = 4;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "N=5 > n_max=4 must be rejected; got {:?}", res[buy]);
    let mut scn = honest(4);
    scn.buy_n_max = 4;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_ok(), "N=4 == n_max must pass: {:?}", res[buy]);
}

/// n_max=1 buy behaves as a strict 1:1 order: single-sell fill passes,
/// any 2-sell sweep is rejected — on the fill AND the partial path.
#[test]
fn n_max_1_strict_one_to_one() {
    let mut scn = honest(1);
    scn.buy_n_max = 1;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_ok(), "n_max=1 with N=1 must pass: {:?}", res[buy]);
    let mut scn = honest(2);
    scn.buy_n_max = 1;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "n_max=1 with N=2 must be rejected; got {:?}", res[buy]);
    // Partial path honors the same cap.
    let mut scn = Scn::gtc(
        vec![SellSpec::honest(99, 100, 4_000_000), SellSpec::honest(99, 100, 6_000_000)],
        30_000_000,
    );
    scn.mode = BuyMode::Partial { residual: 20_000_000 };
    scn.buy_n_max = 1;
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "n_max=1 partial with N=2 must be rejected; got {:?}", res[buy]);
}

/// Sell-side owner batch cap: in a batch of k=3 same-token sells, the sell
/// deployed with batch_max=2 rejects ITS OWN branch (OpCovInputCount = 3 >
/// 2) while the batch_max=255 sells and the buy pass — exactly the shape a
/// planner must exclude that sell from.
#[test]
fn sell_batch_max_below_batch_size_rejected() {
    let mut scn = honest(3);
    scn.sells[1].batch_max = 2;
    let (res, buy) = run_sweep(&scn);
    assert!(res[1].is_err(), "batch_max=2 sell in a 3-batch must reject; got {:?}", res[1]);
    assert!(res[0].is_ok(), "uncapped sell 0 must pass: {:?}", res[0]);
    assert!(res[2].is_ok(), "uncapped sell 2 must pass: {:?}", res[2]);
    assert!(res[buy].is_ok(), "buy must pass (per-input isolation): {:?}", res[buy]);
    // Boundary: batch_max == k passes.
    let mut scn = honest(3);
    scn.sells[1].batch_max = 3;
    let (res, _) = run_sweep(&scn);
    assert!(res[1].is_ok(), "batch_max=3 sell in a 3-batch must pass: {:?}", res[1]);
    // batch_max=1 solo sell still fills (count = 1).
    let mut scn = honest(1);
    scn.sells[0].batch_max = 1;
    let (res, buy) = run_sweep(&scn);
    assert!(res[0].is_ok(), "batch_max=1 solo sell must pass: {:?}", res[0]);
    assert!(res[buy].is_ok(), "buy must pass: {:?}", res[buy]);
}

/// The partial path also carries the anti-double-count guard.
#[test]
fn partial_duplicate_tii_rejected() {
    let mut scn = Scn::gtc(
        vec![SellSpec::honest(99, 100, 4_000_000), SellSpec::honest(99, 100, 6_000_000)],
        30_000_000,
    );
    scn.mode = BuyMode::Partial { residual: 20_000_000 };
    scn.tii = vec![0, 0];
    let (res, buy) = run_sweep(&scn);
    assert!(res[buy].is_err(), "partial duplicate tii must be rejected; got {:?}", res[buy]);
}

// ===========================================================================
// Sell v18 partial (Fix-3 F4)
// ===========================================================================

/// Build a solo sell-partial tx: sell input (token_in), fee input; outputs:
/// [0] seller KAS (fta*pnum/pden), [1] residual token continuation.
/// `residual_cfg`: (bind_to_self, spk_is_self, value).
fn run_sell_partial(
    token_in: u64,
    fta: u64,
    residual_cfg: (bool, bool, u64),
) -> Vec<Result<(), String>> {
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let (pnum, pden) = (99u64, 100u64);
    let rs = build_sell_redeem_script(pnum, pden, 1, &owner_hash, &spk_hash, &spk_hash, 30, 0, 0).unwrap();
    let ss = build_sell_partial_fill_sigscript(0, pnum, pden, fta, 1, &rs);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),
    ];
    let (bind_self, spk_self, value) = residual_cfg;
    let res_spk = if spk_self { build_p2sh(&rs) } else { wallet_spk.clone() };
    let res_cov = if bind_self { Some(CovenantBinding::new(0, token)) } else { None };
    let outputs = vec![
        TransactionOutput::with_covenant(fta * pnum / pden, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(value, res_spk, res_cov),
        TransactionOutput::with_covenant(500_000_000, wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry {
            amount: token_in,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token),
        },
        UtxoEntry {
            amount: 1_000_000_000,
            script_public_key: wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    exec_inputs(&tx, entries, 0)
}

#[test]
fn sell_partial_fix3_honest_passes() {
    // 10M tokens, fill 4M -> residual 6M, covenant-bound to the sell input,
    // self-SPK continuation.
    let res = run_sell_partial(10_000_000, 4_000_000, (true, true, 6_000_000));
    assert!(res[0].is_ok(), "honest Fix-3 sell partial must pass: {:?}", res[0]);
}

#[test]
fn sell_partial_fix3_unbound_residual_rejected() {
    // Residual output not covenant-bound to the sell (the old count-only F4
    // could be satisfied by ANOTHER input's outputs; Fix-3 demands OWN auth).
    let res = run_sell_partial(10_000_000, 4_000_000, (false, true, 6_000_000));
    assert!(res[0].is_err(), "unbound residual must fail Fix-3 F4; got {:?}", res[0]);
}

#[test]
fn sell_partial_fix3_wrong_spk_residual_rejected() {
    // Residual bound to the sell but routed to a non-self SPK (drain).
    let res = run_sell_partial(10_000_000, 4_000_000, (true, false, 6_000_000));
    assert!(res[0].is_err(), "wrong-SPK residual must fail; got {:?}", res[0]);
}

#[test]
fn sell_partial_fix3_short_residual_rejected() {
    // Residual value below token_in - fta.
    let res = run_sell_partial(10_000_000, 4_000_000, (true, true, 5_999_999));
    assert!(res[0].is_err(), "short residual must fail; got {:?}", res[0]);
}

// ===========================================================================
// OCO v18: sweep-eligible on both branches
// ===========================================================================

/// Build a 1-OCO-sell : 1-buy sweep. `sl_branch` picks the OCO selector;
/// `attest_wrong` attests the OTHER branch's price pair (must fail the
/// attestation). Prices: TP 2/1, SL 1/2. Buy limit adapts per branch.
fn run_oco_sweep(sl_branch: bool, attest_wrong: bool) -> (Vec<Result<(), String>>, usize) {
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let (pn_tp, pd_tp, pn_sl, pd_sl) = (2u64, 1u64, 1u64, 2u64);
    let tokens = 10_000_000u64;
    let oco_rs = build_oco_sell_redeem_script(
        pn_tp, pd_tp, 1, pn_sl, pd_sl, 1, &owner_hash, &spk_hash,
        &spk_hash, 30, 0, 0,
    )
    .unwrap();
    let branch_pair = if sl_branch { (pn_sl, pd_sl) } else { (pn_tp, pd_tp) };
    let other_pair = if sl_branch { (pn_tp, pd_tp) } else { (pn_sl, pd_sl) };
    let (att_pn, att_pd) = if attest_wrong { other_pair } else { branch_pair };
    let oco_ss = if sl_branch {
        build_oco_sell_sl_fill_sigscript(0, att_pn, att_pd, &oco_rs)
    } else {
        build_oco_sell_tp_fill_sigscript(0, att_pn, att_pd, &oco_rs)
    };
    // Seller KAS at the executing branch's price (sell convention: KAS/token).
    let branch_price = if sl_branch { (pn_sl, pd_sl) } else { (pn_tp, pd_tp) };
    let seller_kas = tokens * branch_price.0 / branch_price.1;
    // Buy limit at the same rate. Buy convention is tokens/KAS, i.e. the
    // sell price inverted: floor = kas_in/pden*pnum == tokens exactly.
    let buy_rs = build_buy_redeem_script(
        &arr32(TOKEN_HEX),
        branch_price.1,
        branch_price.0,
        1_000_000,
        &owner_hash,
        &spk_hash,
        &spk_hash,
        2000,
        0,
        0,
    )
    .unwrap();
    let buy_ss = build_buy_fill_sigscript(&[0], false, &buy_rs);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), oco_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), buy_ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(seller_kas, wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            tokens,
            wallet_spk.clone(),
            Some(CovenantBinding::new(0, token)),
        ),
        TransactionOutput::with_covenant(500_000_000, wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry {
            amount: tokens,
            script_public_key: build_p2sh(&oco_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token),
        },
        UtxoEntry {
            amount: seller_kas,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        UtxoEntry {
            amount: 1_000_000_000,
            script_public_key: wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
    ];
    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    (exec_inputs(&tx, entries, 1), 1)
}

/// OCO SL swept at the SL price: both the OCO sell (SL branch, SL attestation)
/// and the sweeping buy pass — the historic OCO-SL sweep blocker is gone.
#[test]
fn oco_sl_swept_at_sl_price_passes() {
    let (res, buy) = run_oco_sweep(true, false);
    assert!(res[0].is_ok(), "OCO SL fill must pass: {:?}", res[0]);
    assert!(res[buy].is_ok(), "buy sweeping OCO SL must pass: {:?}", res[buy]);
}

/// OCO SL branch with the TP price attested: the attestation check (attested
/// pair == the EXECUTING branch's pair) must fail the OCO input.
#[test]
fn oco_sl_swept_at_tp_price_rejected() {
    let (res, _buy) = run_oco_sweep(true, true);
    assert!(res[0].is_err(), "SL fill attesting the TP price must fail; got {:?}", res[0]);
}

/// TP branch happy path (attested TP pair) for completeness.
#[test]
fn oco_tp_swept_at_tp_price_passes() {
    let (res, buy) = run_oco_sweep(false, false);
    assert!(res[0].is_ok(), "OCO TP fill must pass: {:?}", res[0]);
    assert!(res[buy].is_ok(), "buy sweeping OCO TP must pass: {:?}", res[buy]);
}

/// TP branch with the SL price attested must fail the attestation too
/// (mismatch is symmetric — attested pair must equal the EXECUTING branch's).
#[test]
fn oco_tp_swept_at_sl_price_rejected() {
    let (res, _buy) = run_oco_sweep(false, true);
    assert!(res[0].is_err(), "TP fill attesting the SL price must fail; got {:?}", res[0]);
}

// ===========================================================================
// Swap v18 rings
// ===========================================================================

/// Build an n-cycle ring: swap leg i gives token T_i and receives T_{i+1 mod n}.
/// Each leg's slot-0 delivery is output i (bound to input i) which is leg
/// (i-1 mod n)'s target... concretely: output[i] carries token T_i to the
/// owner, authorized by input i; leg j receives T_{j+1} via output[j+1 mod n].
///
/// Knobs:
///   * `theft_slot0`: route output[0] (leg 1's target) to the matcher SPK.
///   * `giver_override`: per-leg giver index override (decoy tests).
///   * `slot0_value_delta`: subtract from output[0]'s value (F4 boundary on
///     leg 0's own delivery... note output[0] is authorized by input 0).
fn run_ring(
    n: usize,
    mmfee_bps: u64,
    theft_slot0: bool,
    giver_override: Option<Vec<u16>>,
    slot0_value_delta: u64,
) -> Vec<Result<(), String>> {
    assert!(n >= 2 && n <= 3);
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let decoy_spk = p2pk_spk(&[0xcc; 32]);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    // n distinct tokens; leg i holds amounts[i] of token i.
    let tokens: Vec<Hash> = (0..n).map(|i| Hash::from_bytes([0xd0 + i as u8; 32])).collect();
    let token_arrs: Vec<[u8; 32]> = (0..n).map(|i| [0xd0 + i as u8; 32]).collect();
    let amounts: Vec<u64> = (0..n).map(|i| 10_000_000 * (i as u64 + 1)).collect();

    // Leg i: source = token i, target = token (i+1) % n.
    // Output j carries token j (amount j, possibly minus fee skim) to the
    // owner wallet, authorized by input j. Leg i's target output index is
    // (i + 1) % n; its giver is input (i + 1) % n.
    let fee = |amt: u64| amt / 10000 * mmfee_bps;
    let mut rss = Vec::new();
    for i in 0..n {
        let tgt = (i + 1) % n;
        let min_target = amounts[tgt] - fee(amounts[tgt]);
        let rs = build_swap_redeem_script(
            &token_arrs[i],
            &token_arrs[tgt],
            min_target,
            &owner_hash,
            &spk_hash,
            &[0xee; 32],
            mmfee_bps,
        )
        .unwrap();
        rss.push(rs);
    }
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for i in 0..n {
        let tgt = (i + 1) % n;
        let giver = giver_override
            .as_ref()
            .map(|g| g[i])
            .unwrap_or(tgt as u16);
        let ss = build_swap_fill_sigscript(giver, tgt as u16, &rss[i]);
        inputs.push(TransactionInput::new(op(0x60 + i as u8, 0), ss, 50, 0));
        entries.push(UtxoEntry {
            amount: amounts[i],
            script_public_key: build_p2sh(&rss[i]),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(tokens[i]),
        });
    }
    // Matcher input (not executed).
    inputs.push(TransactionInput::new(op(0x70, 0), vec![0x41; 66], 0, 1));
    entries.push(UtxoEntry {
        amount: 1_000_000_000,
        script_public_key: wallet_spk.clone(),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    });

    let mut outputs = Vec::new();
    for j in 0..n {
        let spk = if j == 0 && theft_slot0 { decoy_spk.clone() } else { wallet_spk.clone() };
        let val = if j == 0 { amounts[j] - slot0_value_delta } else { amounts[j] };
        outputs.push(TransactionOutput::with_covenant(
            val,
            spk,
            Some(CovenantBinding::new(j as u16, tokens[j])),
        ));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, wallet_spk.clone(), None));

    let tx = Transaction::new(1, inputs, outputs, 50, Default::default(), 0, vec![]);
    exec_inputs(&tx, entries, n - 1)
}

#[test]
fn ring_2cycle_settles() {
    let res = run_ring(2, 100, false, None, 0);
    for (i, r) in res.iter().enumerate() {
        assert!(r.is_ok(), "2-cycle leg {i} must pass: {r:?}");
    }
}

#[test]
fn ring_3cycle_settles() {
    let res = run_ring(3, 100, false, None, 0);
    for (i, r) in res.iter().enumerate() {
        assert!(r.is_ok(), "3-cycle leg {i} must pass: {r:?}");
    }
}

/// Slot-0 theft: output[0] (token 0, leg 0's own delivery = leg n-1's target)
/// is routed to the matcher's SPK. The RECEIVER leg (n-1) must fail its F3
/// owner-SPK check on the derived slot-0 output.
#[test]
fn ring_slot0_theft_rejected() {
    let res = run_ring(2, 100, true, None, 0);
    assert!(
        res[1].is_err(),
        "receiver must reject a slot-0 delivery routed to the matcher; got {:?}",
        res[1]
    );
}

/// Giver-idx decoy: leg 0 claims its giver is input 0 (its own input — token
/// 0, not its target token 1). `OpInputCovenantId(giver) == target_tcid`
/// must reject it.
#[test]
fn ring_giver_decoy_rejected() {
    let res = run_ring(2, 100, false, Some(vec![0, 0]), 0);
    assert!(res[0].is_err(), "wrong-covenant giver must be rejected; got {:?}", res[0]);
}

/// Giver-idx decoy pointing at a NON-covenant input (the matcher's wallet
/// input): covenant id reads as zero and the giver auth fails.
#[test]
fn ring_giver_noncovenant_decoy_rejected() {
    // In a 2-ring, input 2 is the matcher wallet input.
    let res = run_ring(2, 100, false, Some(vec![2, 0]), 0);
    assert!(res[0].is_err(), "non-covenant giver must be rejected; got {:?}", res[0]);
}

/// F4 conservation-cap boundary: leg 0's own slot-0 delivery may be skimmed
/// down to exactly source_in - source_in/10000*mmfee_bps; one sompi more
/// fails leg 0's F4. (The receiver's min_target is set at the floor, so the
/// at-floor case still satisfies its F2.)
#[test]
fn ring_f4_cap_boundary() {
    // amounts[0] = 10M, 100bps -> fee 100_000, floor 9_900_000.
    let res = run_ring(2, 100, false, None, 100_000);
    for (i, r) in res.iter().enumerate() {
        assert!(r.is_ok(), "at-cap skim leg {i} must pass: {r:?}");
    }
    let res = run_ring(2, 100, false, None, 100_001);
    assert!(res[0].is_err(), "over-cap skim must fail the giver's F4; got {:?}", res[0]);
}

// ===========================================================================
// Buy v18 lifecycle sanity (dispatch integrity of the new 6-way selector)
// ===========================================================================

#[test]
fn buy_expire_refund_passes_and_early_expire_rejected() {
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    for (lock_time, expect_ok) in [(2000u64, true), (500u64, false)] {
        let buy_rs = build_buy_redeem_script(
            &arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &spk_hash,
        &spk_hash, 30, 0, 1000,
        )
        .unwrap();
        let ss = build_buy_expire_sigscript(&buy_rs);
        let inputs = vec![TransactionInput::new(op(0x20, 0), ss, 0, 0)];
        let outputs =
            vec![TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), None)];
        let entries = vec![UtxoEntry {
            amount: 30_000_000,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        }];
        let tx = Transaction::new(1, inputs, outputs, lock_time, Default::default(), 0, vec![]);
        let res = exec_inputs(&tx, entries, 0);
        assert_eq!(
            res[0].is_ok(),
            expect_ok,
            "expire at lockTime {lock_time} expected ok={expect_ok}, got {:?}",
            res[0]
        );
    }
}

#[test]
fn buy_cancel_reaches_checksig() {
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    for mark in [false, true] {
        let buy_rs = build_buy_redeem_script(
            &arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &spk_hash,
        &spk_hash, 30, 0, 0,
        )
        .unwrap();
        let sig = [0x11u8; 64];
        let ss = build_buy_cancel_sigscript(&pubkey, &sig, mark, &buy_rs);
        let inputs = vec![TransactionInput::new(op(0x20, 0), ss, 0, 0)];
        let outputs =
            vec![TransactionOutput::with_covenant(30_000_000, wallet_spk.clone(), None)];
        let entries = vec![UtxoEntry {
            amount: 30_000_000,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        }];
        let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        let res = exec_inputs(&tx, entries, 0);
        let e = res[0].as_ref().unwrap_err();
        assert!(
            e.contains("Sig") || e.contains("sig") || e.contains("Verify") || e.contains("Null")
                || e.contains("Schnorr"),
            "cancel(mark={mark}) must reach OpCheckSigVerify, got: {e}"
        );
        assert!(
            !e.contains("NumberTooBig") && !e.contains("InvalidStack") && !e.contains("pick"),
            "cancel(mark={mark}) must not stack-error before the signature check: {e}"
        );
    }
}

// ===========================================================================
// Bracket v18 — receipt-gated IFD/IFO hard path
// ===========================================================================
//
// The bracket's entry fill is its own rigid tx (never a sweep member):
//   inputs:  [0] bracket, [1] matcher funding, [2] trade receipt,
//            [3] matcher token inventory (buy entry only)
//   outputs: [0] KAS leg, [1] token leg, [2] spawned done-leg (OCO), [3] change
// Only the bracket input's script is executed here; funding/receipt/token
// inputs are wallet-side (signature) inputs whose UTXO facts (covenant id,
// value) are what the bracket verifies.

/// Knobs for the buy-entry bracket harness. Defaults are the happy path.
struct BracketBuyScn {
    kas_in: u64,
    mfill: u64,
    /// Receipt input: (covenant id present?, wrong covenant?, value).
    receipt_cov: Option<bool>, // Some(true)=correct rcid, Some(false)=wrong id, None=no covenant
    receipt_value: u64,
    /// output[1] token delivery: (value, to_buyer?, token_bound?).
    out1_value: u64,
    out1_to_buyer: bool,
    out1_token_bound: bool,
    /// output[2] OCO spawn: (spk_is_oco?, value, token_bound?).
    out2_oco_spk: bool,
    out2_value: u64,
    out2_token_bound: bool,
    /// Bracket input sequence (CSV(50) gate).
    sequence: u64,
    /// Selector byte for the bracket sigscript (0x51 = fill).
    selector: u8,
}

impl Default for BracketBuyScn {
    fn default() -> Self {
        BracketBuyScn {
            kas_in: 10_000_000,
            mfill: 1_000_000,
            receipt_cov: Some(true),
            receipt_value: 5_000_000,
            out1_value: 10_000_000, // et = kas_in at 1/1
            out1_to_buyer: true,
            out1_token_bound: true,
            out2_oco_spk: true,
            out2_value: 1_000_000,
            out2_token_bound: true,
            sequence: 50,
            selector: 0x51,
        }
    }
}

const MIN_RECEIPT_VALUE: u64 = 5_000_000;
const OCO_MIN_VALUE: u64 = 1_000_000;

/// Build the v18 OCO done-leg RS + its 37B SPK (version u16LE + P2SH script).
fn bracket_oco_leg(owner_hash: &[u8; 32], spk_hash: &[u8; 32]) -> (Vec<u8>, [u8; 37]) {
    let oco_rs = build_oco_sell_redeem_script(
        2, 1, 1, // TP 2/1
        1, 2, 1, // SL 1/2
        owner_hash, spk_hash,
        &spk_hash, 30, 0, 0,
    )
    .unwrap();
    assert_eq!(
        oco_rs.len(),
        kob_core::contract::spot::oco::OCO_SELL_RS_SIZE,
        "done-leg must be a v18 OCO sell"
    );
    let p2sh = build_p2sh(&oco_rs);
    let mut spk37 = [0u8; 37];
    spk37[0..2].copy_from_slice(&p2sh.version.to_le_bytes());
    spk37[2..37].copy_from_slice(p2sh.script());
    (oco_rs, spk37)
}

/// Run a buy-entry bracket fill; returns the bracket input's script result.
fn run_bracket_buy(scn: &BracketBuyScn) -> Result<(), String> {
    use kob_core::contract::spot::bracket::{
        build_bracket_fill_sigscript, build_bracket_redeem_script, BRACKET_RS_SIZE,
    };
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let receipt_cov = Hash::from_bytes([0xE1; 32]);
    let wrong_cov = Hash::from_bytes([0xE2; 32]);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let matcher_spk = p2pk_spk(&[0xcc; 32]);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let (_oco_rs, oco_spk37) = bracket_oco_leg(&owner_hash, &spk_hash);

    // Buy entry at 1/1: et = kas_in.
    let rs = build_bracket_redeem_script(
        0,
        &arr32(TOKEN_HEX),
        1,
        1,
        &oco_spk37,
        OCO_MIN_VALUE,
        scn.mfill,
        MIN_RECEIPT_VALUE,
        &[0xE1; 32],
        &spk_hash,
        &owner_hash,
    )
    .unwrap();
    assert_eq!(rs.len(), BRACKET_RS_SIZE);
    let mut ss = build_bracket_fill_sigscript(&rs);
    ss[0] = scn.selector;

    let inputs = vec![
        TransactionInput::new(op(0x80, 0), ss, scn.sequence, 0),
        TransactionInput::new(op(0x81, 0), vec![0x41; 66], 0, 1), // matcher funding
        TransactionInput::new(op(0x82, 0), vec![0x41; 66], 0, 1), // receipt
        TransactionInput::new(op(0x83, 0), vec![0x41; 66], 0, 1), // matcher token inventory
    ];
    let entries = vec![
        UtxoEntry {
            amount: scn.kas_in,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        UtxoEntry {
            amount: 100_000_000,
            script_public_key: matcher_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        UtxoEntry {
            amount: scn.receipt_value,
            script_public_key: matcher_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: match scn.receipt_cov {
                Some(true) => Some(receipt_cov),
                Some(false) => Some(wrong_cov),
                None => None,
            },
        },
        UtxoEntry {
            amount: 50_000_000,
            script_public_key: matcher_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token),
        },
    ];

    let oco_spk_full = ScriptPublicKey::new(
        u16::from_le_bytes([oco_spk37[0], oco_spk37[1]]),
        oco_spk37[2..37].to_vec().into(),
    );
    let out1_spk = if scn.out1_to_buyer { wallet_spk.clone() } else { matcher_spk.clone() };
    let out2_spk = if scn.out2_oco_spk { oco_spk_full } else { matcher_spk.clone() };
    let outputs = vec![
        // [0] matcher takes the KAS (unconstrained for buy entry).
        TransactionOutput::with_covenant(scn.kas_in, matcher_spk.clone(), None),
        // [1] token delivery to the buyer.
        TransactionOutput::with_covenant(
            scn.out1_value,
            out1_spk,
            if scn.out1_token_bound { Some(CovenantBinding::new(3, token)) } else { None },
        ),
        // [2] spawned done-leg OCO holding tokens.
        TransactionOutput::with_covenant(
            scn.out2_value,
            out2_spk,
            if scn.out2_token_bound { Some(CovenantBinding::new(3, token)) } else { None },
        ),
        // [3] change.
        TransactionOutput::with_covenant(30_000_000, matcher_spk.clone(), None),
    ];

    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    exec_inputs(&tx, entries, 0).remove(0)
}

/// Knobs for the sell-entry bracket harness.
struct BracketSellScn {
    token_in: u64,
    /// output[0] KAS proceeds: (value, to_seller?).
    out0_value: u64,
    out0_to_seller: bool,
    /// F4 residual token output: (bound_to_bracket?, value). None = drained.
    token_out: Option<(bool, u64)>,
}

impl Default for BracketSellScn {
    fn default() -> Self {
        BracketSellScn {
            token_in: 10_000_000,
            out0_value: 5_000_000, // ek = token_in * 1/2
            out0_to_seller: true,
            token_out: Some((true, 10_000_000)),
        }
    }
}

/// Run a sell-entry bracket fill (entry price 1/2: ek = token_in / 2).
/// The sell-entry done-leg at output[2] is a v18 BUY P2SH holding the KAS
/// re-buy budget (generation-agnostic oco_spk slot).
fn run_bracket_sell(scn: &BracketSellScn) -> Result<(), String> {
    use kob_core::contract::spot::bracket::{
        build_bracket_fill_sigscript, build_bracket_redeem_script,
    };
    let pubkey = arr32(PUBKEY_HEX);
    let token = hash32(TOKEN_HEX);
    let receipt_cov = Hash::from_bytes([0xE1; 32]);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let matcher_spk = p2pk_spk(&[0xcc; 32]);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    // Done-leg for a sell entry: a v18 buy (re-buy lower) funded with KAS.
    let buy_leg_rs = build_buy_redeem_script(
        &arr32(TOKEN_HEX), 1, 4, 1, &owner_hash, &spk_hash,
        &spk_hash, 30, 0, 0,
    )
    .unwrap();
    let leg_p2sh = build_p2sh(&buy_leg_rs);
    let mut oco_spk37 = [0u8; 37];
    oco_spk37[0..2].copy_from_slice(&leg_p2sh.version.to_le_bytes());
    oco_spk37[2..37].copy_from_slice(leg_p2sh.script());

    let rs = build_bracket_redeem_script(
        1,
        &arr32(TOKEN_HEX),
        1,
        2,
        &oco_spk37,
        OCO_MIN_VALUE,
        1_000_000,
        MIN_RECEIPT_VALUE,
        &[0xE1; 32],
        &spk_hash,
        &owner_hash,
    )
    .unwrap();
    let ss = build_bracket_fill_sigscript(&rs);

    let inputs = vec![
        TransactionInput::new(op(0x90, 0), ss, 50, 0),
        TransactionInput::new(op(0x91, 0), vec![0x41; 66], 0, 1), // matcher funding
        TransactionInput::new(op(0x92, 0), vec![0x41; 66], 0, 1), // receipt
    ];
    let entries = vec![
        UtxoEntry {
            amount: scn.token_in,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token),
        },
        UtxoEntry {
            amount: 100_000_000,
            script_public_key: matcher_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        UtxoEntry {
            amount: MIN_RECEIPT_VALUE,
            script_public_key: matcher_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(receipt_cov),
        },
    ];

    let out0_spk = if scn.out0_to_seller { wallet_spk.clone() } else { matcher_spk.clone() };
    let leg_spk_full = ScriptPublicKey::new(
        leg_p2sh.version,
        leg_p2sh.script().to_vec().into(),
    );
    let mut outputs = vec![
        // [0] seller KAS proceeds.
        TransactionOutput::with_covenant(scn.out0_value, out0_spk, None),
        // [1] tokens to the matcher (F4: bound to the bracket input, slot 0).
        match scn.token_out {
            Some((bound, value)) => TransactionOutput::with_covenant(
                value,
                matcher_spk.clone(),
                if bound { Some(CovenantBinding::new(0, token)) } else { None },
            ),
            None => TransactionOutput::with_covenant(1_000, matcher_spk.clone(), None),
        },
        // [2] spawned done-leg (v18 buy P2SH, KAS re-buy budget).
        TransactionOutput::with_covenant(OCO_MIN_VALUE, leg_spk_full, None),
    ];
    outputs.push(TransactionOutput::with_covenant(30_000_000, matcher_spk.clone(), None));

    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    exec_inputs(&tx, entries, 0).remove(0)
}

/// Happy path: buy-entry bracket fill spawning a token-funded v18 OCO.
#[test]
fn bracket_buy_entry_fill_spawns_oco_passes() {
    let res = run_bracket_buy(&BracketBuyScn::default());
    assert!(res.is_ok(), "buy-entry bracket fill must pass: {res:?}");
}

/// Happy path: sell-entry bracket fill (KAS proceeds + Fix-3 conservation +
/// v18 buy done-leg spawned).
#[test]
fn bracket_sell_entry_fill_passes() {
    let res = run_bracket_sell(&BracketSellScn::default());
    assert!(res.is_ok(), "sell-entry bracket fill must pass: {res:?}");
}

/// Receipt forgery: input[2] with NO covenant id (a plain wallet input posing
/// as a receipt) must fail the N4 covenant check.
#[test]
fn bracket_receipt_absent_rejected() {
    let scn = BracketBuyScn { receipt_cov: None, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "missing receipt covenant must be rejected; got {res:?}");
}

/// Receipt forgery: input[2] carrying a DIFFERENT covenant id.
#[test]
fn bracket_receipt_wrong_covenant_rejected() {
    let scn = BracketBuyScn { receipt_cov: Some(false), ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "wrong receipt covenant must be rejected; got {res:?}");
}

/// Receipt stake boundary: value == min_receipt_val passes (default), one
/// sompi below fails.
#[test]
fn bracket_receipt_undervalue_rejected() {
    let scn = BracketBuyScn { receipt_value: MIN_RECEIPT_VALUE - 1, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "receipt below min_receipt_val must be rejected; got {res:?}");
}

/// Wrong oco_spk: output[2] routed to a non-OCO SPK.
#[test]
fn bracket_wrong_oco_spk_rejected() {
    let scn = BracketBuyScn { out2_oco_spk: false, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "non-OCO output[2] SPK must be rejected; got {res:?}");
}

/// OCO spawn value boundary: one below oco_min_val fails.
#[test]
fn bracket_oco_undervalue_rejected() {
    let scn = BracketBuyScn { out2_value: OCO_MIN_VALUE - 1, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "OCO spawn below oco_min_val must be rejected; got {res:?}");
}

/// Dead-done-leg trap (v18 addition): output[2] at the right SPK and value
/// but holding plain KAS (no token covenant) would be an OCO that can never
/// execute — must be rejected on a buy entry.
#[test]
fn bracket_buy_oco_not_token_bound_rejected() {
    let scn = BracketBuyScn { out2_token_bound: false, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "plain-KAS OCO spawn must be rejected; got {res:?}");
}

/// Wrong-asset delivery (v18 addition): output[1] pays the right value to the
/// right SPK but is NOT covenant-bound tokens.
#[test]
fn bracket_buy_delivery_not_token_bound_rejected() {
    let scn = BracketBuyScn { out1_token_bound: false, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "plain-KAS token delivery must be rejected; got {res:?}");
}

/// Conservation: token delivery below et = kas_in/epden*epnum.
#[test]
fn bracket_buy_underdelivery_rejected() {
    let scn = BracketBuyScn { out1_value: 9_999_999, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "token under-delivery must be rejected; got {res:?}");
}

/// N5: tokens routed to a non-buyer SPK.
#[test]
fn bracket_buy_delivery_wrong_spk_rejected() {
    let scn = BracketBuyScn { out1_to_buyer: false, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "delivery to a non-buyer SPK must be rejected; got {res:?}");
}

/// mfill floor: et < mfill rejected; et == mfill passes.
#[test]
fn bracket_mfill_boundary() {
    // et = kas_in = 10M; mfill 10M passes.
    let scn = BracketBuyScn { mfill: 10_000_000, ..Default::default() };
    assert!(run_bracket_buy(&scn).is_ok(), "et == mfill must pass");
    // mfill 10M + 1 fails.
    let scn = BracketBuyScn { mfill: 10_000_001, ..Default::default() };
    assert!(run_bracket_buy(&scn).is_err(), "et < mfill must fail");
}

/// CSV(50) exposure delay: an immature bracket input (sequence < 50) cannot
/// be filled.
#[test]
fn bracket_csv_immature_rejected() {
    let scn = BracketBuyScn { sequence: 10, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "fill before the CSV(50) delay must be rejected; got {res:?}");
}

/// Unknown selector falls into the cancel branch and dies (fail-closed).
#[test]
fn bracket_unknown_selector_rejected() {
    let scn = BracketBuyScn { selector: 0x53, ..Default::default() };
    let res = run_bracket_buy(&scn);
    assert!(res.is_err(), "unknown selector must be rejected; got {res:?}");
}

/// Sell entry: KAS proceeds below ek = token_in*epnum/epden.
#[test]
fn bracket_sell_kas_underpaid_rejected() {
    let scn = BracketSellScn { out0_value: 4_999_999, ..Default::default() };
    let res = run_bracket_sell(&scn);
    assert!(res.is_err(), "KAS proceeds below ek must be rejected; got {res:?}");
}

/// Sell entry N5: KAS proceeds routed to a non-seller SPK.
#[test]
fn bracket_sell_kas_wrong_spk_rejected() {
    let scn = BracketSellScn { out0_to_seller: false, ..Default::default() };
    let res = run_bracket_sell(&scn);
    assert!(res.is_err(), "proceeds to a non-seller SPK must be rejected; got {res:?}");
}

/// Sell entry F4 (Fix-3): tokens drained (no covenant continuation at all).
#[test]
fn bracket_sell_f4_drain_rejected() {
    let scn = BracketSellScn { token_out: None, ..Default::default() };
    let res = run_bracket_sell(&scn);
    assert!(res.is_err(), "token drain must fail the bracket's F4; got {res:?}");
}

/// Sell entry F4 (Fix-3): token continuation short of token_in.
#[test]
fn bracket_sell_f4_short_rejected() {
    let scn = BracketSellScn { token_out: Some((true, 9_999_999)), ..Default::default() };
    let res = run_bracket_sell(&scn);
    assert!(res.is_err(), "short token continuation must fail F4; got {res:?}");
}

/// Cancel path: reaches the owner signature check (and no earlier stack
/// error), mirroring the other v18 cancel dispatch-integrity tests.
#[test]
fn bracket_cancel_reaches_checksig() {
    use kob_core::contract::spot::bracket::{
        build_bracket_cancel_sigscript, build_bracket_redeem_script,
    };
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let (_oco_rs, oco_spk37) = bracket_oco_leg(&owner_hash, &spk_hash);
    let rs = build_bracket_redeem_script(
        0, &arr32(TOKEN_HEX), 1, 1, &oco_spk37, OCO_MIN_VALUE, 1_000_000,
        MIN_RECEIPT_VALUE, &[0xE1; 32], &spk_hash, &owner_hash,
    )
    .unwrap();
    let sig = [0x11u8; 64];
    let ss = build_bracket_cancel_sigscript(&sig, &pubkey, &rs);
    let inputs = vec![TransactionInput::new(op(0x80, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(10_000_000, wallet_spk.clone(), None)];
    let entries = vec![UtxoEntry {
        amount: 10_000_000,
        script_public_key: build_p2sh(&rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    }];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let res = exec_inputs(&tx, entries, 0);
    let e = res[0].as_ref().unwrap_err();
    assert!(
        e.contains("Sig") || e.contains("sig") || e.contains("Verify") || e.contains("Null")
            || e.contains("Schnorr"),
        "v18 bracket cancel must reach OpCheckSig, got: {e}"
    );
    assert!(
        !e.contains("NumberTooBig") && !e.contains("InvalidStack") && !e.contains("pick"),
        "v18 bracket cancel must not stack-error before the signature check: {e}"
    );
}

/// Cancel authorization: a pk whose hash does NOT match owner_hash dies on
/// the owner-hash equality, regardless of the signature.
#[test]
fn bracket_cancel_wrong_owner_rejected() {
    use kob_core::contract::spot::bracket::{
        build_bracket_cancel_sigscript, build_bracket_redeem_script,
    };
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let (_oco_rs, oco_spk37) = bracket_oco_leg(&owner_hash, &spk_hash);
    let rs = build_bracket_redeem_script(
        0, &arr32(TOKEN_HEX), 1, 1, &oco_spk37, OCO_MIN_VALUE, 1_000_000,
        MIN_RECEIPT_VALUE, &[0xE1; 32], &spk_hash, &owner_hash,
    )
    .unwrap();
    let sig = [0x11u8; 64];
    let intruder = [0x99u8; 32];
    let ss = build_bracket_cancel_sigscript(&sig, &intruder, &rs);
    let inputs = vec![TransactionInput::new(op(0x80, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(10_000_000, wallet_spk.clone(), None)];
    let entries = vec![UtxoEntry {
        amount: 10_000_000,
        script_public_key: build_p2sh(&rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    }];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let res = exec_inputs(&tx, entries, 0);
    assert!(res[0].is_err(), "non-owner cancel must be rejected; got {:?}", res[0]);
}

#[test]
fn sell_cancel_reaches_checksig() {
    use kob_core::contract::spot::receipt::build_sell_cancel_sigscript;
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let token = hash32(TOKEN_HEX);
    let rs = build_sell_redeem_script(99, 100, 1, &owner_hash, &spk_hash, &spk_hash, 30, 0, 0).unwrap();
    let sig = [0x11u8; 64];
    let ss = build_sell_cancel_sigscript(&sig, &pubkey, &rs);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(
        10_000_000,
        wallet_spk.clone(),
        Some(CovenantBinding::new(0, token)),
    )];
    let entries = vec![UtxoEntry {
        amount: 10_000_000,
        script_public_key: build_p2sh(&rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(token),
    }];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let res = exec_inputs(&tx, entries, 0);
    let e = res[0].as_ref().unwrap_err();
    assert!(
        e.contains("Sig") || e.contains("sig") || e.contains("Verify") || e.contains("Null")
            || e.contains("Schnorr"),
        "v18 sell cancel must reach OpCheckSig, got: {e}"
    );
}

// ===========================================================================
// E1 expire-seat fixes — buy EXPIRE refunds to the owner KAS seat (okspkh),
// sell/OCO EXPIRE refunds the token escrow to the owner token seat (otspkh)
// as a covenant-bound token_unit (Fix-3 per-input binding).
// ===========================================================================

/// A stand-in "token_unit P2SH" SPK, distinct from the wallet P2PK.
fn token_unit_spk() -> ScriptPublicKey {
    let mut s = Vec::with_capacity(35);
    s.push(0xaa); // OpBlake2b
    s.push(0x20);
    s.extend_from_slice(&[0x77; 32]);
    s.push(0x87); // OpEqual
    ScriptPublicKey::new(0, s.into())
}

fn spk_hash_of(spk: &ScriptPublicKey) -> [u8; 32] {
    kob_core::p2sh::compute_spk_hash(spk.version(), spk.script())
}

/// Buy expire: okspkh (wallet P2PK) != bspkh (token_unit delivery seat).
/// A refund landing on the token_unit seat — the pre-E1 behavior that parked
/// binding-less KAS at the shared token address — must FAIL; the owner KAS
/// seat must PASS.
#[test]
fn buy_expire_wrong_seat_rejected() {
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let okspkh = compute_p2pk_spk_hash(&pubkey);
    let tu_spk = token_unit_spk();
    let bspkh = spk_hash_of(&tu_spk);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    for (refund_spk, expect_ok) in [(wallet_spk.clone(), true), (tu_spk.clone(), false)] {
        let buy_rs = build_buy_redeem_script(
            &arr32(TOKEN_HEX), 1, 1, 1_000_000, &owner_hash, &bspkh, &okspkh, 30, 0, 1000,
        )
        .unwrap();
        let ss = build_buy_expire_sigscript(&buy_rs);
        let inputs = vec![TransactionInput::new(op(0x20, 0), ss, 0, 0)];
        let outputs = vec![TransactionOutput::with_covenant(30_000_000, refund_spk, None)];
        let entries = vec![UtxoEntry {
            amount: 30_000_000,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        }];
        let tx = Transaction::new(1, inputs, outputs, 2000, Default::default(), 0, vec![]);
        let res = exec_inputs(&tx, entries, 0);
        assert_eq!(
            res[0].is_ok(),
            expect_ok,
            "buy expire refund seat (to_token_unit={}): {:?}",
            !expect_ok,
            res[0]
        );
    }
}

/// Sell/OCO expire harness. input[0] = the order UTXO (token covenant);
/// output[0] = the refund, with knobs for its SPK, binding, and value.
fn run_sell_expire(
    oco: bool,
    to_token_seat: bool,
    bound: bool,
    amount: u64,
    lock_time: u64,
) -> Result<(), String> {
    let pubkey = arr32(PUBKEY_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let sspkh = compute_p2pk_spk_hash(&pubkey); // KAS-proceeds seat (raw P2PK)
    let wallet_spk = p2pk_spk(&pubkey);
    let tu_spk = token_unit_spk();
    let otspkh = spk_hash_of(&tu_spk); // owner token seat
    let token = hash32(TOKEN_HEX);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);
    let (rs, ss) = if oco {
        let rs = build_oco_sell_redeem_script(
            99, 100, 1, 1, 2, 1, &owner_hash, &sspkh, &otspkh, 30, 0, 1000,
        )
        .unwrap();
        let ss = build_oco_sell_expire_sigscript(&rs);
        (rs, ss)
    } else {
        let rs = build_sell_redeem_script(
            99, 100, 1, &owner_hash, &sspkh, &otspkh, 30, 0, 1000,
        )
        .unwrap();
        let ss = build_sell_expire_sigscript(&rs);
        (rs, ss)
    };
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0)];
    let refund_spk = if to_token_seat { tu_spk.clone() } else { wallet_spk.clone() };
    let cov = if bound { Some(CovenantBinding::new(0, token)) } else { None };
    let outputs = vec![TransactionOutput::with_covenant(amount, refund_spk, cov)];
    let entries = vec![UtxoEntry {
        amount: 30_000_000,
        script_public_key: build_p2sh(&rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(token),
    }];
    let tx = Transaction::new(1, inputs, outputs, lock_time, Default::default(), 0, vec![]);
    exec_inputs(&tx, entries, 0).remove(0)
}

#[test]
fn sell_expire_token_seat_bound_passes() {
    for oco in [false, true] {
        let r = run_sell_expire(oco, true, true, 30_000_000, 2000);
        assert!(r.is_ok(), "expire (oco={oco}) to bound token seat must pass: {r:?}");
    }
}

#[test]
fn sell_expire_to_sspkh_wrong_seat_rejected() {
    // Pre-E1 behavior: token refund to the raw-P2PK sspkh (binding target
    // mismatch with otspkh) must fail even when covenant-bound.
    for oco in [false, true] {
        let r = run_sell_expire(oco, false, true, 30_000_000, 2000);
        assert!(r.is_err(), "expire (oco={oco}) to the raw P2PK seat must fail");
    }
}

#[test]
fn sell_expire_without_binding_rejected() {
    // Binding stripped (token burned to plain KAS): auth[0] of the order
    // input does not exist, the Fix-3 read must fail.
    for oco in [false, true] {
        let r = run_sell_expire(oco, true, false, 30_000_000, 2000);
        assert!(r.is_err(), "expire (oco={oco}) without CovenantBinding must fail");
    }
}

#[test]
fn sell_expire_short_refund_rejected() {
    for oco in [false, true] {
        let r = run_sell_expire(oco, true, true, 29_999_999, 2000);
        assert!(r.is_err(), "expire (oco={oco}) with a short refund must fail");
    }
}

#[test]
fn sell_expire_early_rejected() {
    for oco in [false, true] {
        let r = run_sell_expire(oco, true, true, 30_000_000, 500);
        assert!(r.is_err(), "expire (oco={oco}) before expiry_daa must fail (CLTV)");
    }
}

// ===========================================================================
// Sell IOC F4 residual conservation + builder output-ordering (ported from
// the retired toccata_fill_repro suite to v18 shapes).
// ===========================================================================

/// Direct v18 sell IOC spend: sell (token 30M) + fee input; outputs =
/// [0] seller KAS (koi=0), then residual/buyer token outputs in the given
/// order (both covenant-bound to the sell input). `residual_value` lets the
/// drain case short the self-continuation.
fn run_sell_ioc(residual_first: bool, residual_value: u64) -> Result<(), String> {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);

    let token_in = 30_000_000u64;
    let fta = 20_000_000u64; // residual = 10M
    let sell_rs = build_sell_redeem_script(
        1, 1, 8_000_000, &owner_hash, &spk_hash, &spk_hash, 30, 0, 0,
    )
    .unwrap();
    let sell_p2sh = build_p2sh(&sell_rs);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let sell_ss = build_sell_ioc_fill_sigscript(0, 1, 1, fta, &sell_rs);
    let buyer_spk = p2pk_spk(&[0xcc; 32]);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sell_ss, 50, 0),
        TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1), // fee (not executed)
    ];
    let residual_out = TransactionOutput::with_covenant(
        residual_value,
        ScriptPublicKey::new(sell_p2sh.version(), sell_p2sh.script().into()),
        Some(CovenantBinding::new(0, token_cov_id)),
    );
    let buyer_out = TransactionOutput::with_covenant(
        fta,
        buyer_spk,
        Some(CovenantBinding::new(0, token_cov_id)),
    );
    let (out1, out2) = if residual_first { (residual_out, buyer_out) } else { (buyer_out, residual_out) };
    let outputs = vec![
        TransactionOutput::with_covenant(fta, wallet_spk.clone(), None), // [0] seller KAS (koi=0)
        out1,
        out2,
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let entries = vec![
        UtxoEntry {
            amount: token_in,
            script_public_key: sell_p2sh,
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(token_cov_id),
        },
        UtxoEntry {
            amount: 260_000_000,
            script_public_key: wallet_spk,
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
    ];
    exec_inputs(&tx, entries, 0).remove(0)
}

/// Honest IOC residual (auth[0] = self-continuation worth token_in - fta)
/// passes; a matcher shorting the residual (drain) is rejected by F4.
#[test]
fn sell_ioc_residual_drain_rejected_honest_passes() {
    let ok = run_sell_ioc(true, 10_000_000);
    assert!(ok.is_ok(), "honest IOC residual must pass: {ok:?}");
    let drained = run_sell_ioc(true, 9_999_999);
    assert!(drained.is_err(), "shorted IOC residual must be rejected by F4");
}

/// Builder ordering: the residual must be the sell input's auth[0] (first
/// covenant output it authorizes). If the buyer output precedes it, auth[0]
/// misresolves onto the buyer SPK and the self-continuation check fails.
#[test]
fn sell_ioc_builder_layout_residual_at_auth0() {
    let bad = run_sell_ioc(false, 10_000_000);
    assert!(bad.is_err(), "buyer output before the residual must fail the self-SPK check");
}

/// OCO fill F4 drain (ported): the OCO seller's own authorized token output
/// underfunded below token_in must be rejected by the per-input F4.
#[test]
fn oco_fill_underfunded_f4_rejected() {
    let pubkey = arr32(PUBKEY_HEX);
    let token_cov_id = hash32(TOKEN_HEX);
    let owner_hash = blake2b_256(&pubkey);
    let spk_hash = compute_p2pk_spk_hash(&pubkey);
    let wallet_spk = p2pk_spk(&pubkey);
    let op = |b: u8, i: u32| TransactionOutpoint::new(Hash::from_bytes([b; 32]), i);

    let token_in = 30_000_000u64;
    let oco_rs = build_oco_sell_redeem_script(
        99, 100, 1, 1, 2, 1, &owner_hash, &spk_hash, &spk_hash, 30, 0, 0,
    )
    .unwrap();
    for (delivered, expect_ok) in [(token_in, true), (token_in - 1, false)] {
        let ss = build_oco_sell_tp_fill_sigscript(0, 99, 100, &oco_rs);
        let inputs = vec![
            TransactionInput::new(op(0x10, 0), ss, 50, 0),
            TransactionInput::new(op(0x30, 0), vec![0x41; 66], 0, 1),
        ];
        let outputs = vec![
            TransactionOutput::with_covenant(
                token_in * 99 / 100,
                wallet_spk.clone(),
                None,
            ), // [0] seller KAS (koi=0)
            TransactionOutput::with_covenant(
                delivered,
                p2pk_spk(&[0xcc; 32]),
                Some(CovenantBinding::new(0, token_cov_id)),
            ), // [1] buyer tokens = auth[0] of the OCO input
        ];
        let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        let entries = vec![
            UtxoEntry {
                amount: token_in,
                script_public_key: build_p2sh(&oco_rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(token_cov_id),
            },
            UtxoEntry {
                amount: 260_000_000,
                script_public_key: wallet_spk.clone(),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
        ];
        let res = exec_inputs(&tx, entries, 0).remove(0);
        assert_eq!(
            res.is_ok(),
            expect_ok,
            "OCO fill delivered={delivered} expected ok={expect_ok}: {res:?}"
        );
    }
}
