//! Time-contracts family (kob/TIME_CONTRACTS_DESIGN.md) — Stage-A adversarial
//! matrix against the real post-Toccata `kaspa-txscript` `TxScriptEngine`
//! (`covenants_enabled = true`), plus the v18 zero-diff pin.
//!
//! Covers:
//!   - v18 zero-diff pin (§0): the frozen v18 spot bodies + length consts are
//!     byte-identical before/after this work lands,
//!   - decay_sell/decay_buy (§2.8): happy fills across the schedule, L=0
//!     default, unix-ms-type L kill (D1), stale/wrong attestation (D3/D4),
//!     backdated-L self-harm economics, expiry parity, IOC/partial decayed,
//!   - twap_sell (§3.6): CSV twin gating on ALL fill-family branches
//!     (full-fill bypass pin), vol<=mpw boundaries, owner branches ungated,
//!     the §3.2 clock-lag burst documentation test, chained fills with real
//!     DAA spacing (consensus formula mirrored),
//!   - ratchet_oco (§4.6): happy one-step ratchet with genuine settle
//!     evidence, L1-L4/L8/L10/L11 fakes (R5-R12 guards incl. the R9
//!     negative-encoding pin), splice pins, travel cap G3, rwin G1, one-way
//!     monotonicity, ratchet-then-fill economics, cancel/expire interplay,
//!   - composition CP-1..CP-4: an UNCHANGED v18 buy sweeps each new sell
//!     variant; an unchanged v18 sell settles against a decay_buy.

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

use kob_core::contract::spot::decay::{
    build_decay_buy_redeem_script, build_decay_sell_fill_sigscript,
    build_decay_sell_ioc_fill_sigscript, build_decay_sell_partial_fill_sigscript,
    build_decay_sell_redeem_script, decay_effective_pnum, DECAY_BUY_RS_EXPECTED_LEN,
    DECAY_SELL_RS_EXPECTED_LEN, LOCK_TIME_THRESHOLD,
};
use kob_core::contract::spot::oco::{
    build_oco_sell_cancel_sigscript, build_oco_sell_expire_sigscript,
};
use kob_core::contract::spot::order::{
    build_buy_fill_sigscript, build_buy_partial_fill_sigscript, build_buy_redeem_script,
    build_sell_expire_sigscript, build_sell_fill_sigscript,
    build_sell_ioc_fill_sigscript, build_sell_partial_fill_sigscript,
    build_sell_redeem_script,
};
use kob_core::contract::spot::receipt::build_sell_cancel_sigscript;
use kob_core::contract::spot::parse::{
    parse_decay_buy_redeem_script, parse_decay_sell_redeem_script,
    parse_ratchet_oco_redeem_script, parse_redeem_script, parse_twap_sell_redeem_script,
};
use kob_core::contract::spot::ratchet::{
    build_ratchet_oco_body, build_ratchet_oco_ratchet_sigscript,
    build_ratchet_oco_redeem_script, build_ratchet_oco_sl_fill_sigscript,
    build_ratchet_oco_tp_fill_sigscript, derive_ratchet_continuation_rs,
    RATCHET_OCO_RS_EXPECTED_LEN, RATCHET_PNUM_SL_OFFSET,
};
use kob_core::contract::spot::twap::{
    build_twap_sell_redeem_script, TWAP_SELL_RS_EXPECTED_LEN,
};
use kob_core::{blake2b_256, build_p2sh, compute_p2pk_spk_hash, u64_le};

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
fn op(b: u8, i: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes([b; 32]), i)
}

/// Execute the scripts of the selected input indices; results parallel `idxs`.
fn exec_selected(
    tx: &Transaction,
    entries: Vec<UtxoEntry>,
    idxs: &[usize],
) -> Vec<Result<(), String>> {
    let populated = PopulatedTransaction::new(tx, entries);
    let cov_ctx = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!("ctx: {e:?}")); idxs.len()],
    };
    let cache = Cache::new(1000);
    let flags = EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() };
    let mut results = Vec::new();
    for &idx in idxs {
        let reused = SigHashReusedValuesUnsync::new();
        let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov_ctx).with_reused(&reused);
        let (input, entry) = populated.populated_input(idx);
        let mut vm =
            TxScriptEngine::from_transaction_input(&populated, input, idx, entry, ctx, flags);
        results.push(vm.execute().map_err(|e| format!("{e:?}")));
    }
    results
}

struct Ctx {
    pubkey: [u8; 32],
    token: Hash,
    owner_hash: [u8; 32],
    spk_hash: [u8; 32],
    wallet_spk: ScriptPublicKey,
}
fn ctx() -> Ctx {
    let pubkey = arr32(PUBKEY_HEX);
    Ctx {
        pubkey,
        token: hash32(TOKEN_HEX),
        owner_hash: blake2b_256(&pubkey),
        spk_hash: compute_p2pk_spk_hash(&pubkey),
        wallet_spk: p2pk_spk(&pubkey),
    }
}
fn wallet_input(b: u8) -> (TransactionInput, UtxoEntry) {
    let c = ctx();
    (
        TransactionInput::new(op(b, 0), vec![0x41; 66], 0, 1),
        UtxoEntry {
            amount: 1_000_000_000,
            script_public_key: c.wallet_spk.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
    )
}

// ===========================================================================
// Freeze pin. History: the original Stage-A zero-diff pin proved the time-
// contracts stage did not touch v18 bytecode. The LIMITS re-freeze then
// DELIBERATELY re-froze buy/sell (MAX_N=32 + owner n_max/batch_max caps) —
// this pin is the POST-change freeze: buy/sell pinned at their new bytes,
// OCO/swap/bracket byte-identical to the original v18 freeze. The pre-change
// live proofs for the changed contracts are void; re-proof is planned in the
// combined live stage.
// ===========================================================================

#[test]
fn v18_zero_diff_pin() {
    use kob_core::contract::spot::bracket::{
        build_bracket_body, BRACKET_BODY_EXPECTED_LEN, BRACKET_RS_SIZE, BRACKET_STATE_SIZE,
    };
    use kob_core::contract::spot::dca::{DCA_ORDER_BODY, DCA_V2_BODY_SIZE, DCA_V2_RS_SIZE, DCA_V2_STATE_SIZE};
    use kob_core::contract::spot::oco::{
        build_oco_sell_body, OCO_SELL_BODY_EXPECTED_LEN, OCO_SELL_RS_SIZE, OCO_SELL_STATE_SIZE,
    };
    use kob_core::contract::spot::order::{
        build_buy_body, build_sell_body, BUY_ORDER_BODY_EXPECTED_LEN, BUY_ORDER_RS_EXPECTED_LEN,
        BUY_ORDER_STATE_SIZE, SELL_ORDER_BODY_EXPECTED_LEN, SELL_ORDER_RS_EXPECTED_LEN,
        SELL_ORDER_STATE_SIZE,
    };
    use kob_core::contract::spot::swap::{
        build_swap_body, SWAP_BODY_EXPECTED_LEN, SWAP_RS_SIZE, SWAP_STATE_SIZE,
    };
    // Bodies byte-identical (blake2b) to the LIMITS re-freeze pins
    // (buy/sell) and to the original v18 pins (OCO/swap/bracket).
    let pins: &[(&str, Vec<u8>, &str)] = &[
        ("BUY_ORDER", build_buy_body(),
         "f8d3162f72b0b5af3a96bf26fa987948f4a1985952f9e3178917253198c6f568"),
        ("SELL_ORDER", build_sell_body(),
         "86d9bf28ffd94c87ab32a82c9ea8aac7a221d9f807bd4b4812a021056e6e9af5"),
        ("OCO_SELL", build_oco_sell_body(),
         "2a750d668ead305605b79dd9f574cd5832a5c7d010d510411cdc7eec0388a40c"),
        ("SWAP_ORDER", build_swap_body(),
         "47552d56319a3b8a523ae4d467192db1496347ff4243f1eae5b31e36729eb0b3"),
        ("BRACKET", build_bracket_body(),
         "169cdae3e31dcb11ea3f958611222dc0d59136f5c8b1d03d08ec5de7df5f1c3f"),
    ];
    for (name, body, expected_hex) in pins {
        assert_eq!(
            hex::encode(blake2b_256(body)),
            *expected_hex,
            "v18 {name} body changed — the freeze pin is violated"
        );
    }
    // Length consts pinned at the LIMITS re-freeze values (buy/sell) and
    // the frozen v18 values (everything else).
    assert_eq!(BUY_ORDER_RS_EXPECTED_LEN, 5655);
    assert_eq!(BUY_ORDER_STATE_SIZE, 180);
    assert_eq!(BUY_ORDER_BODY_EXPECTED_LEN, 5475);
    assert_eq!(SELL_ORDER_RS_EXPECTED_LEN, 542);
    assert_eq!(SELL_ORDER_STATE_SIZE, 148);
    assert_eq!(SELL_ORDER_BODY_EXPECTED_LEN, 394);
    assert_eq!(OCO_SELL_RS_SIZE, 397);
    assert_eq!(OCO_SELL_STATE_SIZE, 172);
    assert_eq!(OCO_SELL_BODY_EXPECTED_LEN, 225);
    assert_eq!(SWAP_RS_SIZE, 260);
    assert_eq!(SWAP_STATE_SIZE, 183);
    assert_eq!(SWAP_BODY_EXPECTED_LEN, 77);
    assert_eq!(BRACKET_RS_SIZE, 372);
    assert_eq!(BRACKET_STATE_SIZE, 224);
    assert_eq!(BRACKET_BODY_EXPECTED_LEN, 148);
    assert_eq!(DCA_V2_RS_SIZE, 374);
    assert_eq!(DCA_V2_STATE_SIZE, 153);
    assert_eq!(DCA_V2_BODY_SIZE, 221);
    assert_eq!(DCA_ORDER_BODY.len(), 221);
}

/// Realized time-contract RS lengths (LIMITS re-freeze: +batch_max/n_max
/// state and guards; decay_buy additionally inherits MAX_N=32).
#[test]
fn time_contract_rs_lengths_frozen() {
    assert_eq!(TWAP_SELL_RS_EXPECTED_LEN, 596); // pre-refreeze 569
    assert_eq!(DECAY_SELL_RS_EXPECTED_LEN, 649); // pre-refreeze 622
    assert_eq!(RATCHET_OCO_RS_EXPECTED_LEN, 760); // pre-refreeze 733
    assert_eq!(DECAY_BUY_RS_EXPECTED_LEN, 5895); // pre-refreeze 1857
}

// ===========================================================================
// Builders + parse roundtrips + canonical offsets
// ===========================================================================

fn std_decay_sell_rs(expiry: u64) -> Vec<u8> {
    let c = ctx();
    build_decay_sell_redeem_script(
        1000, 1000, 2000, 2_000_000, 1_000_000, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash,
        30, 0, expiry,
    )
    .unwrap()
}

#[test]
fn builders_validate_and_roundtrip() {
    let c = ctx();
    let t = &c.owner_hash;
    // decay_sell: schedule invariants.
    assert!(build_decay_sell_redeem_script(0, 1000, 2000, 10, 1, 1, t, t, t, 0, 0, 0).is_err(), "dslope=0");
    assert!(build_decay_sell_redeem_script(1, 2000, 1000, 10, 1, 1, t, t, t, 0, 0, 0).is_err(), "t0>=t_end");
    assert!(build_decay_sell_redeem_script(1, 1000, LOCK_TIME_THRESHOLD, u64::MAX / 2, 1, 1, t, t, t, 0, 0, 0).is_err(), "t_end >= threshold");
    assert!(build_decay_sell_redeem_script(1, 0, 10, 10, 1, 1, t, t, t, 0, 0, 0).is_err(), "slope*range > pnum-1");
    // twap_sell.
    assert!(build_twap_sell_redeem_script(49, 10, 1, 1, 1, t, t, t, 0, 0, 0).is_err(), "twin<50");
    assert!(build_twap_sell_redeem_script(0x1_0000_0000, 10, 1, 1, 1, t, t, t, 0, 0, 0).is_err(), "twin>u32");
    assert!(build_twap_sell_redeem_script(50, 0, 1, 1, 1, t, t, t, 0, 0, 0).is_err(), "mpw=0");
    assert!(build_twap_sell_redeem_script(50, 10, 1, 1, 100, t, t, t, 0, 0, 0).is_err(), "mpw*p < mfill");
    // ratchet_oco.
    assert!(build_ratchet_oco_redeem_script(0, 0, 60, 1, 5, 1, 1, 2, 1, 1, t, t, t, 0, 0, 0).is_err(), "rstep=0");
    assert!(build_ratchet_oco_redeem_script(1, 0, 49, 1, 5, 1, 1, 2, 1, 1, t, t, t, 0, 0, 0).is_err(), "rwin<50");
    assert!(build_ratchet_oco_redeem_script(1, 0, 0x1_0000_0000, 1, 5, 1, 1, 2, 1, 1, t, t, t, 0, 0, 0).is_err(), "rwin>u32");
    assert!(build_ratchet_oco_redeem_script(1, 0, 60, 0, 5, 1, 1, 2, 1, 1, t, t, t, 0, 0, 0).is_err(), "mrv=0");
    assert!(build_ratchet_oco_redeem_script(3, 0, 60, 1, 5, 1, 1, 2, 1, 1, t, t, t, 0, 0, 0).is_err(), "headroom: (2+3) >= 5");

    // Roundtrips (RS-length dispatch + field identity; version reports 18).
    let rs = std_decay_sell_rs(777);
    assert_eq!(rs.len(), DECAY_SELL_RS_EXPECTED_LEN);
    let p = parse_decay_sell_redeem_script(&rs).expect("decay_sell parses");
    assert_eq!((p.dslope, p.t0, p.t_end), (1000, 1000, 2000));
    assert_eq!(p.order.version, 18);
    // Raw (non-gcd) price pair preserved: 2_000_000/1_000_000 stays as-is.
    assert_eq!((p.order.price_num, p.order.price_den), (2_000_000, 1_000_000));
    assert_eq!(p.order.expiry_daa, Some(777));
    let po = parse_redeem_script(&rs).expect("dispatches by length");
    assert_eq!(po.order_type, kob_core::types::OrderSide::Sell);

    let rs = build_decay_buy_redeem_script(
        1000, 1000, 2000, &arr32(TOKEN_HEX), 2_000_000, 1_000_000, 1, &c.owner_hash,
        &c.spk_hash, &c.spk_hash, 10000, 0, 0,
    )
    .unwrap();
    assert_eq!(rs.len(), DECAY_BUY_RS_EXPECTED_LEN);
    let p = parse_decay_buy_redeem_script(&rs).expect("decay_buy parses");
    assert_eq!(p.order.order_type, kob_core::types::OrderSide::Buy);
    assert_eq!(p.order.token_cov_id, arr32(TOKEN_HEX));
    assert_eq!((p.order.price_num, p.order.price_den), (2_000_000, 1_000_000));
    assert!(parse_redeem_script(&rs).is_some());

    let rs = build_twap_sell_redeem_script(
        100, 10_000_000, 99, 100, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash, 30, 0, 555,
    )
    .unwrap();
    assert_eq!(rs.len(), TWAP_SELL_RS_EXPECTED_LEN);
    let p = parse_twap_sell_redeem_script(&rs).expect("twap parses");
    assert_eq!((p.twin, p.mpw), (100, 10_000_000));
    assert_eq!(p.order.expiry_daa, Some(555));
    assert!(parse_redeem_script(&rs).is_some());

    let rs = std_ratchet_rs(1, 0, 60, 1_000_000, 0, 0);
    assert_eq!(rs.len(), RATCHET_OCO_RS_EXPECTED_LEN);
    let p = parse_ratchet_oco_redeem_script(&rs).expect("ratchet parses");
    assert_eq!((p.rstep, p.rgap, p.rwin, p.mrv), (1, 0, 60, 1_000_000));
    assert_eq!((p.oco.price_num_tp, p.oco.price_num_sl), (5, 2));
    // Continuation derivation: pnum_sl += rstep, everything else identical.
    let cont = derive_ratchet_continuation_rs(&rs).unwrap();
    let pc = parse_ratchet_oco_redeem_script(&cont).expect("continuation parses");
    assert_eq!(pc.oco.price_num_sl, 3);
    assert_eq!(&cont[..RATCHET_PNUM_SL_OFFSET], &rs[..RATCHET_PNUM_SL_OFFSET]);
    assert_eq!(&cont[RATCHET_PNUM_SL_OFFSET + 8..], &rs[RATCHET_PNUM_SL_OFFSET + 8..]);
}

/// Canonical attestation offsets for the new sell-side fill builders: pnum at
/// sigscript [3..11), pden at [12..20) — the exact offsets an unchanged v18
/// buy reads. The decay builder must write the RAW effective pair (no gcd).
#[test]
fn canonical_offsets_and_no_gcd_freeze_rule() {
    let rs = std_decay_sell_rs(0);
    let pe = decay_effective_pnum(2_000_000, 1000, 1000, 2000, 1500);
    assert_eq!(pe, 1_500_000);
    let cases = vec![
        ("decay fill", build_decay_sell_fill_sigscript(7, pe, 1_000_000, &rs)),
        ("decay ioc", build_decay_sell_ioc_fill_sigscript(7, pe, 1_000_000, 55, &rs)),
        ("decay partial", build_decay_sell_partial_fill_sigscript(7, pe, 1_000_000, 55, 2, &rs)),
    ];
    for (name, ss) in cases {
        assert_eq!(ss[0], 0x01, "{name}: koi forced 2-byte push");
        assert_eq!(ss[1], 7, "{name}: koi value");
        assert_eq!(ss[2], 0x08, "{name}: pnum push prefix");
        // 1_500_000/1_000_000 would gcd-normalize to 3/2 — the RAW pair must
        // be written instead (freeze rule §2.6).
        assert_eq!(&ss[3..11], &u64_le(pe), "{name}: RAW pnum_eff at [3..11)");
        assert_eq!(ss[11], 0x08, "{name}: pden push prefix");
        assert_eq!(&ss[12..20], &u64_le(1_000_000), "{name}: RAW pden at [12..20)");
    }
    // Ratchet TP/SL builders are raw too.
    let rrs = std_ratchet_rs(1, 0, 60, 1, 0, 0);
    let ss = build_ratchet_oco_tp_fill_sigscript(0, 5, 1, &rrs);
    assert_eq!(&ss[3..11], &u64_le(5));
    let ss = build_ratchet_oco_sl_fill_sigscript(0, 2, 1, &rrs);
    assert_eq!(&ss[3..11], &u64_le(2));
    assert_eq!(&ss[12..20], &u64_le(1));
}

// ===========================================================================
// decay_sell — §2.8 adversarial matrix at the VM level
// ===========================================================================

/// One decay_sell GTC fill: tokens in, attested pair, seller KAS at koi=0.
fn run_decay_sell_fill(
    lock_time: u64,
    attested: (u64, u64),
    tokens: u64,
    seller_kas: u64,
    expiry: u64,
) -> Result<(), String> {
    let c = ctx();
    let rs = std_decay_sell_rs(expiry);
    let ss = build_decay_sell_fill_sigscript(0, attested.0, attested.1, &rs);
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 50, 0), fi];
    let outputs = vec![
        TransactionOutput::with_covenant(seller_kas, c.wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            tokens,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        ),
        TransactionOutput::with_covenant(500_000_000, c.wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry {
            amount: tokens,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, lock_time, Default::default(), 0, vec![]);
    exec_selected(&tx, entries, &[0]).remove(0)
}

/// f(L) for the standard schedule (dslope 1000, t0 1000, t_end 2000, pnum 2M).
fn f(l: u64) -> u64 {
    decay_effective_pnum(2_000_000, 1000, 1000, 2000, l)
}
/// Expected KAS for `tokens` at f(L) with pden 1M.
fn kas_at(l: u64, tokens: u64) -> u64 {
    tokens * f(l) / 1_000_000
}

/// Happy fills across the schedule: mid, at t0, past t_end (floor), L=0.
#[test]
fn decay_sell_fill_schedule_points_pass() {
    let tokens = 10_000_000;
    // Mid-schedule: f(1500) = 1_500_000.
    assert_eq!(f(1500), 1_500_000);
    let r = run_decay_sell_fill(1500, (f(1500), 1_000_000), tokens, kas_at(1500, tokens), 0);
    assert!(r.is_ok(), "mid-schedule fill must pass: {r:?}");
    // At t0: start price.
    let r = run_decay_sell_fill(1000, (f(1000), 1_000_000), tokens, kas_at(1000, tokens), 0);
    assert!(r.is_ok(), "t0 fill must pass: {r:?}");
    // Understated L < t0 clamps to t0 (start price).
    let r = run_decay_sell_fill(500, (2_000_000, 1_000_000), tokens, 20_000_000, 0);
    assert!(r.is_ok(), "L<t0 clamp to start price must pass: {r:?}");
    // Past t_end: floor price (VM level; minability until DAA>L is consensus).
    assert_eq!(f(3000), 1_000_000);
    let r = run_decay_sell_fill(3000, (1_000_000, 1_000_000), tokens, 10_000_000, 0);
    assert!(r.is_ok(), "post-t_end floor fill must pass: {r:?}");
    // L=0 (Finalized type): clamp => eff = t0 => START price (worst-for-taker
    // default, matrix item 3).
    let r = run_decay_sell_fill(0, (2_000_000, 1_000_000), tokens, 20_000_000, 0);
    assert!(r.is_ok(), "L=0 must default to the start price: {r:?}");
    // ...and L=0 attesting the decayed price must fail (D3).
    let r = run_decay_sell_fill(0, (1_500_000, 1_000_000), tokens, 20_000_000, 0);
    assert!(r.is_err(), "L=0 with a decayed attestation must fail (D3)");
}

/// T6 pin: the covenant-computed pnum_eff has a MINIMAL on-stack encoding
/// while the attestation is an 8B zero-padded push — byte-EQUAL would reject
/// the honest pair; D3's NUMEQUAL accepts it (proven by the passing fills
/// above). This test pins the encoding divergence that forces NUMEQUAL.
#[test]
fn decay_attestation_numequal_not_equal_encoding_pin() {
    let pe = f(1500);
    let minimal = kob_core::primitives::minimal_script_encode(pe);
    assert_ne!(minimal.as_slice(), &u64_le(pe)[..], "encodings must differ (minimal vs 8B)");
    assert!(minimal.len() < 8);
    // And the schedule math itself is division-free/exact at every point.
    assert_eq!(f(1999), 1_001_000);
    assert_eq!(f(2000), 1_000_000);
}

/// Stale/wrong attestations (matrix item 6 + DK-2): attesting the start price
/// after decay has run, or any pair off by one step in either direction.
#[test]
fn decay_sell_wrong_attestation_rejected() {
    let tokens = 10_000_000;
    // Start price attested mid-schedule (pays MORE KAS — still rejected: the
    // attestation must equal f(L) exactly, both directions).
    let r = run_decay_sell_fill(1500, (2_000_000, 1_000_000), tokens, 20_000_000, 0);
    assert!(r.is_err(), "stale start-price attestation must fail (D3)");
    // One decay step below f(L).
    let r = run_decay_sell_fill(1500, (f(1500) - 1000, 1_000_000), tokens, kas_at(1500, tokens), 0);
    assert!(r.is_err(), "below-f(L) attestation must fail (D3)");
    // One above f(L).
    let r = run_decay_sell_fill(1500, (f(1500) + 1000, 1_000_000), tokens, 20_000_000, 0);
    assert!(r.is_err(), "above-f(L) attestation must fail (D3)");
    // Wrong pden (D4) — gcd-normalized pair (3/2 of 1.5M/1M) must fail too.
    let r = run_decay_sell_fill(1500, (3, 2), tokens, kas_at(1500, tokens), 0);
    assert!(r.is_err(), "gcd-normalized attestation must fail (D3/D4 raw-bytes rule)");
    // Underpaid KAS at a correct attestation.
    let r = run_decay_sell_fill(1500, (f(1500), 1_000_000), tokens, kas_at(1500, tokens) - 1, 0);
    assert!(r.is_err(), "KAS below tokens*f(L)/pden must fail");
}

/// Matrix item 4 (the one genuinely dangerous vector): unix-ms-type L
/// fast-forwards the schedule while being minable now — killed by D1.
#[test]
fn decay_sell_unix_ms_locktime_rejected() {
    let tokens = 10_000_000;
    for l in [LOCK_TIME_THRESHOLD, 1_752_000_000_000] {
        // Attest the floor (what the attacker wants) — D1 must kill it first.
        let r = run_decay_sell_fill(l, (1_000_000, 1_000_000), tokens, 20_000_000, 0);
        assert!(r.is_err(), "unix-ms-type L={l} must be rejected (D1)");
    }
}

/// Matrix item 1: a backdated (understated) L is self-defeating — it executes
/// at an OLDER schedule point that pays the SELLER more. Economics pinned.
#[test]
fn decay_sell_backdated_l_self_harm() {
    let tokens = 10_000_000;
    let (l_actual, l_back) = (1800, 1200);
    assert!(kas_at(l_back, tokens) > kas_at(l_actual, tokens), "older point must cost the taker more");
    // Backdated fill passes — but only at the backdated (worse for taker) price.
    let r = run_decay_sell_fill(l_back, (f(l_back), 1_000_000), tokens, kas_at(l_back, tokens), 0);
    assert!(r.is_ok(), "backdated fill at its own f(L) must pass: {r:?}");
    // Paying the actual-time (cheaper) KAS against the backdated L fails.
    let r = run_decay_sell_fill(l_back, (f(l_back), 1_000_000), tokens, kas_at(l_actual, tokens), 0);
    assert!(r.is_err(), "backdated L cannot buy at the newer cheaper price");
}

/// Expiry parity (matrix item 9 + GTD retention): the v18 time gate and the
/// EXPIRE branch work unchanged on the decay layout.
#[test]
fn decay_sell_expiry_still_works() {
    let tokens = 10_000_000;
    // Fill with L < expiry passes.
    let r = run_decay_sell_fill(1500, (f(1500), 1_000_000), tokens, kas_at(1500, tokens), 1800);
    assert!(r.is_ok(), "fill before expiry must pass: {r:?}");
    // Fill with L >= expiry rejected by the time gate.
    let r = run_decay_sell_fill(1900, (f(1900), 1_000_000), tokens, kas_at(1900, tokens), 1800);
    assert!(r.is_err(), "fill at/after expiry must fail the time gate");
    // EXPIRE branch: Fix-3 refund to the owner token seat.
    let c = ctx();
    for (lock_time, expect_ok) in [(2000u64, true), (500u64, false)] {
        let rs = std_decay_sell_rs(1000);
        let ss = build_sell_expire_sigscript(&rs);
        let (fi, fe) = wallet_input(0x30);
        let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0), fi];
        let outputs = vec![TransactionOutput::with_covenant(
            tokens,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        )];
        let entries = vec![
            UtxoEntry {
                amount: tokens,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(c.token),
            },
            fe,
        ];
        let tx = Transaction::new(1, inputs, outputs, lock_time, Default::default(), 0, vec![]);
        let r = exec_selected(&tx, entries, &[0]).remove(0);
        assert_eq!(r.is_ok(), expect_ok, "decay expire at lock_time {lock_time}: {r:?}");
    }
    // CANCEL reaches the signature check (dispatch integrity at new depths).
    let rs = std_decay_sell_rs(0);
    let sig = [0x11u8; 64];
    let ss = build_sell_cancel_sigscript(&sig, &c.pubkey, &rs);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(
        tokens,
        c.wallet_spk.clone(),
        Some(CovenantBinding::new(0, c.token)),
    )];
    let entries = vec![UtxoEntry {
        amount: tokens,
        script_public_key: build_p2sh(&rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(c.token),
    }];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries, &[0]).remove(0);
    let e = r.unwrap_err();
    assert!(
        e.contains("Sig") || e.contains("sig") || e.contains("Verify") || e.contains("Null")
            || e.contains("Schnorr"),
        "decay_sell cancel must reach OpCheckSig, got: {e}"
    );
}

/// IOC + PARTIAL decayed forms: happy at f(L), wrong attestation rejected,
/// residual re-pricing is automatic (matrix item 10 — the residual is
/// byte-identical state; each event re-evaluates f at ITS tx's L).
#[test]
fn decay_sell_ioc_and_partial_decayed() {
    let c = ctx();
    let token_in = 30_000_000u64;
    let fta = 10_000_000u64;
    let run = |l: u64, att: (u64, u64), kas: u64, partial: bool| -> Result<(), String> {
        let rs = std_decay_sell_rs(0);
        let ss = if partial {
            build_decay_sell_partial_fill_sigscript(0, att.0, att.1, fta, 1, &rs)
        } else {
            build_decay_sell_ioc_fill_sigscript(0, att.0, att.1, fta, &rs)
        };
        let (fi, fe) = wallet_input(0x30);
        let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 50, 0), fi];
        let outputs = vec![
            TransactionOutput::with_covenant(kas, c.wallet_spk.clone(), None),
            // Residual self-SPK continuation = auth[0] of the sell input.
            TransactionOutput::with_covenant(
                token_in - fta,
                build_p2sh(&rs),
                Some(CovenantBinding::new(0, c.token)),
            ),
            TransactionOutput::with_covenant(
                fta,
                c.wallet_spk.clone(),
                Some(CovenantBinding::new(0, c.token)),
            ),
        ];
        let entries = vec![
            UtxoEntry {
                amount: token_in,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(c.token),
            },
            fe,
        ];
        let tx = Transaction::new(1, inputs, outputs, l, Default::default(), 0, vec![]);
        exec_selected(&tx, entries, &[0]).remove(0)
    };
    for partial in [false, true] {
        let name = if partial { "partial" } else { "IOC" };
        let r = run(1500, (f(1500), 1_000_000), fta * f(1500) / 1_000_000, partial);
        assert!(r.is_ok(), "decayed {name} at f(L) must pass: {r:?}");
        let r = run(1500, (2_000_000, 1_000_000), fta * 2, partial);
        assert!(r.is_err(), "decayed {name} attesting the start price must fail");
        // Event 2 on the (byte-identical) residual at a LATER L re-prices.
        let r = run(1900, (f(1900), 1_000_000), fta * f(1900) / 1_000_000, partial);
        assert!(r.is_ok(), "residual re-pricing at a later L must pass: {r:?}");
        // Unix-ms L kills IOC/partial too (D1 in every fill-family branch).
        let r = run(LOCK_TIME_THRESHOLD + 5, (1_000_000, 1_000_000), fta, partial);
        assert!(r.is_err(), "unix-ms L must fail decayed {name}");
    }
}

// ===========================================================================
// decay_buy — rising bid (DB-1/DB-2 at VM level) + CP-4 composition
// ===========================================================================

/// decay_buy sweeping ONE unchanged v18 sell (this shape IS CP-4).
/// Returns (sell result, buy result).
fn run_decay_buy(
    lock_time: u64,
    kas_in: u64,
    sell_tokens: u64,
    partial_residual: Option<u64>,
) -> (Result<(), String>, Result<(), String>) {
    let c = ctx();
    // Unchanged v18 sell at 1/2 KAS per token.
    let sell_rs =
        build_sell_redeem_script(1, 2, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash, 30, 0, 0)
            .unwrap();
    let sell_ss = build_sell_fill_sigscript(0, 1, 2, &sell_rs);
    // decay_buy: standard schedule; tokens-per-KAS numerator falls with L.
    let buy_rs = build_decay_buy_redeem_script(
        1000, 1000, 2000, &arr32(TOKEN_HEX), 2_000_000, 1_000_000, 1, &c.owner_hash,
        &c.spk_hash, &c.spk_hash, 10000, 0, 0,
    )
    .unwrap();
    let buy_ss = match partial_residual {
        None => build_buy_fill_sigscript(&[0], false, &buy_rs),
        Some(_) => build_buy_partial_fill_sigscript(&[0], 2, &buy_rs),
    };
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sell_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), buy_ss, 50, 0),
        fi,
    ];
    let mut outputs = vec![
        // [0] seller KAS at the sell's own price.
        TransactionOutput::with_covenant(sell_tokens / 2, c.wallet_spk.clone(), None),
        // [1] buyer tokens (auth[0] of the sell).
        TransactionOutput::with_covenant(
            sell_tokens,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        ),
    ];
    if let Some(residual) = partial_residual {
        outputs.push(TransactionOutput::with_covenant(residual, build_p2sh(&buy_rs), None));
    }
    outputs.push(TransactionOutput::with_covenant(500_000_000, c.wallet_spk.clone(), None));
    let entries = vec![
        UtxoEntry {
            amount: sell_tokens,
            script_public_key: build_p2sh(&sell_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        UtxoEntry {
            amount: kas_in,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, lock_time, Default::default(), 0, vec![]);
    let mut r = exec_selected(&tx, entries, &[0, 1]);
    let buy = r.remove(1);
    (r.remove(0), buy)
}

/// DB-1: fill at a risen bid — token floor demanded = kas_in/pden*pnum_eff(L)
/// (fewer tokens than at deploy); one token below fails; L=0 demands the
/// start-price token count; unix-ms L rejected. This doubles as CP-4 (the
/// counterparty is a byte-frozen v18 sell).
#[test]
fn decay_buy_fill_and_cp4_composition() {
    let kas_in = 10_000_000u64;
    // Floor at L=1500: 10 * 1_500_000 = 15M tokens.
    let (s, b) = run_decay_buy(1500, kas_in, 15_000_000, None);
    assert!(s.is_ok(), "unchanged v18 sell settled by decay_buy must pass (CP-4): {s:?}");
    assert!(b.is_ok(), "decay_buy fill at f(L) floor must pass: {b:?}");
    // One token below the risen-bid floor fails.
    let (_, b) = run_decay_buy(1500, kas_in, 14_999_999, None);
    assert!(b.is_err(), "under-delivery vs pnum_eff floor must fail");
    // L=0 defaults to the start bid: 20M tokens demanded.
    let (_, b) = run_decay_buy(0, kas_in, 20_000_000, None);
    assert!(b.is_ok(), "L=0 start-bid delivery must pass: {b:?}");
    let (_, b) = run_decay_buy(0, kas_in, 15_000_000, None);
    assert!(b.is_err(), "L=0 with only the decayed token count must fail");
    // Unix-ms-type L rejected (D1 in the buy fill family too).
    let (_, b) = run_decay_buy(LOCK_TIME_THRESHOLD + 5, kas_in, 20_000_000, None);
    assert!(b.is_err(), "unix-ms L must fail the decay_buy fill");
}

/// DB-2: partial fill + residual re-priced at the next event's L (the
/// spent-based floor consumes pnum_eff).
#[test]
fn decay_buy_partial_repriced() {
    // Event: kas_in 30M, residual 20M => spent 10M; floor at L=1500 = 15M.
    let (s, b) = run_decay_buy(1500, 30_000_000, 15_000_000, Some(20_000_000));
    assert!(s.is_ok(), "sell leg must pass: {s:?}");
    assert!(b.is_ok(), "decay_buy partial at f(L) floor must pass: {b:?}");
    let (_, b) = run_decay_buy(1500, 30_000_000, 14_999_999, Some(20_000_000));
    assert!(b.is_err(), "partial under-delivery vs pnum_eff floor must fail");
    // Later event on the (byte-identical) residual state re-prices: at
    // L=1900, floor = 10 * 1_100_000 = 11M.
    let (_, b) = run_decay_buy(1900, 20_000_000, 11_000_000, Some(10_000_000));
    assert!(b.is_ok(), "residual re-pricing at a later L must pass: {b:?}");
    let (_, b) = run_decay_buy(1900, 20_000_000, 10_999_999, Some(10_000_000));
    assert!(b.is_err(), "residual re-priced floor must bind");
}

/// LIMITS re-freeze parity: decay_buy carries the same MAX_N=32 slot table
/// as the plain buy. A full 32-sell sweep settles against one decay_buy at
/// the f(L) floor, and the pnum_eff floor still binds exactly at N=32
/// (one token below rejects).
#[test]
fn decay_buy_max_n_32_parity() {
    let c = ctx();
    let n = 32usize;
    let kas_in = 10_000_000u64;
    // Floor at L=1500: kas_in/pden * pnum_eff = 10 * 1_500_000 = 15M tokens.
    let per_sell_exact = 15_000_000u64 / n as u64; // 468_750, divides evenly
    assert_eq!(per_sell_exact * n as u64, 15_000_000);
    let run = |short: u64| -> Vec<Result<(), String>> {
        let sell_rs = build_sell_redeem_script(
            1, 2, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash, 30, 0, 0,
        )
        .unwrap();
        let buy_rs = build_decay_buy_redeem_script(
            1000, 1000, 2000, &arr32(TOKEN_HEX), 2_000_000, 1_000_000, 1,
            &c.owner_hash, &c.spk_hash, &c.spk_hash, 10000, 0, 0,
        )
        .unwrap();
        let mut inputs = Vec::new();
        let mut entries = Vec::new();
        for i in 0..n {
            let ss = build_sell_fill_sigscript(i as u16, 1, 2, &sell_rs);
            inputs.push(TransactionInput::new(op(0x40 + i as u8, 0), ss, 50, 0));
            entries.push(UtxoEntry {
                amount: per_sell_exact,
                script_public_key: build_p2sh(&sell_rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(c.token),
            });
        }
        let buy_idx = inputs.len();
        let tii: Vec<u16> = (0..n as u16).collect();
        inputs.push(TransactionInput::new(
            op(0xA0, 0),
            build_buy_fill_sigscript(&tii, false, &buy_rs),
            50,
            0,
        ));
        entries.push(UtxoEntry {
            amount: kas_in,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        });
        let (fi, fe) = wallet_input(0x30);
        inputs.push(fi);
        entries.push(fe);
        let mut outputs = Vec::new();
        for _ in 0..n {
            outputs.push(TransactionOutput::with_covenant(
                per_sell_exact / 2,
                c.wallet_spk.clone(),
                None,
            ));
        }
        for i in 0..n {
            // Delivery bound to sell i; the `short` run under-delivers on
            // the LAST term (fails the buy floor at exactly one token).
            let amt = if i == n - 1 { per_sell_exact - short } else { per_sell_exact };
            outputs.push(TransactionOutput::with_covenant(
                amt,
                c.wallet_spk.clone(),
                Some(CovenantBinding::new(i as u16, c.token)),
            ));
        }
        outputs.push(TransactionOutput::with_covenant(500_000_000, c.wallet_spk.clone(), None));
        let tx = Transaction::new(1, inputs, outputs, 1500, Default::default(), 0, vec![]);
        exec_selected(&tx, entries, &[buy_idx])
    };
    let r = run(0).remove(0);
    assert!(r.is_ok(), "decay_buy 32-sweep at the f(L) floor must pass: {r:?}");
    let r = run(1).remove(0);
    assert!(r.is_err(), "decay_buy 32-sweep one token below the f(L) floor must fail");
}

// ===========================================================================
// twap_sell — §3.6 adversarial matrix at the VM level
// ===========================================================================

const TWIN: u64 = 100;
const MPW: u64 = 10_000_000;

fn std_twap_rs(expiry: u64) -> Vec<u8> {
    let c = ctx();
    build_twap_sell_redeem_script(
        TWIN, MPW, 1, 1, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash, 30, 0, expiry,
    )
    .unwrap()
}

enum TwapMode {
    Fill,
    Ioc { fta: u64 },
    Partial { fta: u64 },
}

fn run_twap(token_in: u64, sequence: u64, mode: TwapMode) -> Result<(), String> {
    let c = ctx();
    let rs = std_twap_rs(0);
    let (ss, kas, residual) = match &mode {
        TwapMode::Fill => (build_sell_fill_sigscript(0, 1, 1, &rs), token_in, None),
        TwapMode::Ioc { fta } => (
            build_sell_ioc_fill_sigscript(0, 1, 1, *fta, &rs),
            *fta,
            Some(token_in - fta),
        ),
        TwapMode::Partial { fta } => (
            build_sell_partial_fill_sigscript(0, 1, 1, *fta, 1, &rs),
            *fta,
            Some(token_in - fta),
        ),
    };
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, sequence, 0), fi];
    let mut outputs = vec![TransactionOutput::with_covenant(kas, c.wallet_spk.clone(), None)];
    match residual {
        Some(r) => {
            outputs.push(TransactionOutput::with_covenant(
                r,
                build_p2sh(&rs),
                Some(CovenantBinding::new(0, c.token)),
            ));
            outputs.push(TransactionOutput::with_covenant(
                token_in - r,
                c.wallet_spk.clone(),
                Some(CovenantBinding::new(0, c.token)),
            ));
        }
        None => outputs.push(TransactionOutput::with_covenant(
            token_in,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        )),
    }
    let entries = vec![
        UtxoEntry {
            amount: token_in,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    exec_selected(&tx, entries, &[0]).remove(0)
}

/// Sequence games (matrix item 2): seq >= twin passes; seq < twin fails the
/// CSV opcode; the disabled bit fails; larger seq only waits longer.
#[test]
fn twap_sequence_gates() {
    let r = run_twap(MPW, TWIN, TwapMode::Fill);
    assert!(r.is_ok(), "sequence == twin must pass: {r:?}");
    let r = run_twap(MPW, TWIN + 500, TwapMode::Fill);
    assert!(r.is_ok(), "sequence > twin must pass (just waits longer): {r:?}");
    let r = run_twap(MPW, TWIN - 1, TwapMode::Fill);
    assert!(r.is_err(), "sequence < twin must fail the twin CSV");
    let r = run_twap(MPW, 49, TwapMode::Fill);
    assert!(r.is_err(), "sequence < 50 must fail the exposure CSV too");
    let r = run_twap(MPW, TWIN | (1 << 63), TwapMode::Fill);
    assert!(r.is_err(), "disabled-bit sequence must fail CSV");
}

/// Volume caps (matrix items 3+5): vol == mpw passes on every fill-family
/// branch; vol > mpw fails — INCLUDING the full FILL (bypass pin) and IOC.
#[test]
fn twap_volume_caps_all_branches() {
    // FILL: vol = token_in.
    let r = run_twap(MPW, TWIN, TwapMode::Fill);
    assert!(r.is_ok(), "full fill at mpw must pass: {r:?}");
    let r = run_twap(MPW + 1, TWIN, TwapMode::Fill);
    assert!(r.is_err(), "full fill above mpw must fail (no full-fill bypass)");
    // IOC: vol = fta.
    let r = run_twap(MPW + 5_000_000, TWIN, TwapMode::Ioc { fta: MPW });
    assert!(r.is_ok(), "IOC at fta == mpw must pass: {r:?}");
    let r = run_twap(MPW + 5_000_000, TWIN, TwapMode::Ioc { fta: MPW + 1 });
    assert!(r.is_err(), "IOC above mpw must fail");
    // PARTIAL: vol = fta.
    let r = run_twap(MPW + 5_000_000, TWIN, TwapMode::Partial { fta: MPW });
    assert!(r.is_ok(), "partial at fta == mpw must pass: {r:?}");
    let r = run_twap(MPW + 5_000_000, TWIN, TwapMode::Partial { fta: MPW + 1 });
    assert!(r.is_err(), "partial above mpw must fail");
}

/// v18 checks survive at the shifted depths: attestation + partial Fix-3.
#[test]
fn twap_v18_checks_carry_over() {
    let c = ctx();
    let rs = std_twap_rs(0);
    // Attestation mismatch fails.
    let ss = build_sell_fill_sigscript(0, 3, 1, &rs);
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, TWIN, 0), fi];
    let outputs = vec![
        TransactionOutput::with_covenant(MPW * 3, c.wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            MPW,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        ),
    ];
    let entries = vec![
        UtxoEntry {
            amount: MPW,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries, &[0]).remove(0);
    assert!(r.is_err(), "twap attestation mismatch must fail");
    // Partial residual short by one fails Fix-3 F4 (matrix item 4 regression:
    // per-input binding carried unchanged into this body).
    let run_short = |short: u64| -> Result<(), String> {
        let rs = std_twap_rs(0);
        let ss = build_sell_partial_fill_sigscript(0, 1, 1, 4_000_000, 1, &rs);
        let (fi, fe) = wallet_input(0x30);
        let inputs = vec![TransactionInput::new(op(0x10, 0), ss, TWIN, 0), fi];
        let outputs = vec![
            TransactionOutput::with_covenant(4_000_000, c.wallet_spk.clone(), None),
            TransactionOutput::with_covenant(
                6_000_000 - short,
                build_p2sh(&rs),
                Some(CovenantBinding::new(0, c.token)),
            ),
            TransactionOutput::with_covenant(
                4_000_000 + short,
                c.wallet_spk.clone(),
                Some(CovenantBinding::new(0, c.token)),
            ),
        ];
        let entries = vec![
            UtxoEntry {
                amount: 10_000_000,
                script_public_key: build_p2sh(&rs),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(c.token),
            },
            fe,
        ];
        let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        exec_selected(&tx, entries, &[0]).remove(0)
    };
    assert!(run_short(0).is_ok(), "honest twap partial residual must pass");
    assert!(run_short(1).is_err(), "short twap partial residual must fail Fix-3 F4");
}

/// Owner branches are NOT rate-gated (matrix item 6): cancel/expire work with
/// sequence 0 (no CSV in the owner paths).
#[test]
fn twap_owner_branches_ungated() {
    let c = ctx();
    // EXPIRE with sequence 0 (< twin) passes once expiry <= lock_time.
    let rs = std_twap_rs(1000);
    let ss = build_sell_expire_sigscript(&rs);
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0), fi];
    let outputs = vec![TransactionOutput::with_covenant(
        MPW,
        c.wallet_spk.clone(),
        Some(CovenantBinding::new(0, c.token)),
    )];
    let entries = vec![
        UtxoEntry {
            amount: MPW,
            script_public_key: build_p2sh(&rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, 2000, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries, &[0]).remove(0);
    assert!(r.is_ok(), "twap expire must not be rate-gated: {r:?}");
    // CANCEL with sequence 0 reaches the signature check.
    let rs = std_twap_rs(0);
    let sig = [0x11u8; 64];
    let ss = build_sell_cancel_sigscript(&sig, &c.pubkey, &rs);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(
        MPW,
        c.wallet_spk.clone(),
        Some(CovenantBinding::new(0, c.token)),
    )];
    let entries = vec![UtxoEntry {
        amount: MPW,
        script_public_key: build_p2sh(&rs),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(c.token),
    }];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries, &[0]).remove(0);
    let e = r.unwrap_err();
    assert!(
        e.contains("Sig") || e.contains("sig") || e.contains("Verify") || e.contains("Null")
            || e.contains("Schnorr"),
        "twap cancel must reach OpCheckSig (not a CSV error), got: {e}"
    );
}

/// Consensus relative-lock rule (tx_validation_in_utxo_context.rs:136),
/// mirrored: an input without the disabled bit is spendable only when
/// `utxo.block_daa_score + (sequence & MASK) - 1 < pov_daa_score`.
fn consensus_csv_ok(utxo_daa: u64, sequence: u64, pov_daa: u64) -> bool {
    utxo_daa + (sequence & 0xFFFF_FFFF) - 1 < pov_daa
}

/// §3.2 burst DOCUMENTATION test: the rejected stored-clock design (3.1)
/// admits the 10-window burst; the frozen CSV design kills it.
#[test]
fn twap_clock_lag_burst_documentation() {
    let (r0, delta) = (1_000_000u64, 1000u64);
    // --- Simulated 3.1 contract: state carries `last_fill_daa`; the branch
    // checks `L >= last + delta` (CLTV: L <= actual) and splices last := L.
    let real_now = r0 + 10 * delta; // order idle for 10 windows
    let mut last = r0;
    let mut accepted = 0;
    let mut real = real_now;
    for k in 1..=10u64 {
        let l = r0 + k * delta; // lagged claimed clock, <= real => minable NOW
        let cltv_ok = l <= real;
        let window_ok = l >= last + delta;
        if cltv_ok && window_ok {
            accepted += 1;
            last = l; // splice records the CLAIMED clock
            real += 1; // one real DAA per block
        }
    }
    assert_eq!(
        accepted, 10,
        "3.1 stored-clock design banks the idle allowance: 10 maximal fills in ~10 real DAA"
    );
    // --- Frozen CSV design: age resets to 0 at every fill; fill#2 one block
    // later violates the consensus age rule regardless of any claimed L.
    let d1 = real_now; // fill#1 acceptance DAA = residual creation DAA
    assert!(!consensus_csv_ok(d1, delta, d1 + 1), "fill#2 next block must be rejected");
    assert!(!consensus_csv_ok(d1, delta, d1 + delta - 1), "still rejected one DAA early");
    assert!(consensus_csv_ok(d1, delta, d1 + delta), "eligible exactly at creation+twin");
    // And at the VM level the opcode side of the same lock rejects any
    // attempt to weaken the declared sequence below twin:
    let r = run_twap(MPW, TWIN - 1, TwapMode::Fill);
    assert!(r.is_err(), "engine-level: sequence < twin fails the CSV opcode");
}

/// Chained fills with real DAA spacing: each event passes the VM with
/// sequence = twin, and the consensus age formula forces >= twin real DAA
/// between consecutive events on the lineage.
#[test]
fn twap_chained_fills_real_daa_spacing() {
    // Event 1: partial 10M of 30M (VM).
    let r = run_twap(30_000_000, TWIN, TwapMode::Partial { fta: MPW });
    assert!(r.is_ok(), "event 1 must pass: {r:?}");
    // Event 2 runs on the residual (byte-identical RS, 20M in) — VM passes
    // with the same twin sequence.
    let r = run_twap(20_000_000, TWIN, TwapMode::Partial { fta: MPW });
    assert!(r.is_ok(), "event 2 must pass: {r:?}");
    // Real spacing (consensus formula on the lineage's creation scores):
    let d0 = 5_000u64; // deploy UTXO creation
    let d1 = d0 + TWIN; // earliest acceptance of event 1 = residual creation
    let d2 = d1 + TWIN; // earliest acceptance of event 2
    assert!(consensus_csv_ok(d0, TWIN, d1));
    assert!(!consensus_csv_ok(d1, TWIN, d2 - 1), "event 2 cannot land earlier");
    assert!(consensus_csv_ok(d1, TWIN, d2));
    // Long-run rate <= mpw/twin: k events need k*twin real DAA.
    assert_eq!(d2 - d0, 2 * TWIN);
}

// ===========================================================================
// ratchet_oco — §4.6 grief-tree leaves at the VM level
// ===========================================================================

/// Standard ratchet_oco: TP 5/1, SL 2/1 (+ overrides), raw pairs.
fn std_ratchet_rs(rstep: u64, rgap: u64, rwin: u64, mrv: u64, cpend: u8, expiry: u64) -> Vec<u8> {
    let c = ctx();
    build_ratchet_oco_redeem_script(
        rstep, rgap, rwin, mrv, 5, 1, 1, 2, 1, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash,
        30, cpend, expiry,
    )
    .unwrap()
}

/// Sibling print variants for the ratchet harness.
enum Sibling {
    /// Genuine v18 sell fill at price (pnum, pden), full-fill shape.
    SellFill { pnum: u64, pden: u64 },
    /// v18 sell IOC shape (fta at [21..29), byte 20 = 0x08).
    SellIoc { pnum: u64, pden: u64, fta: u64 },
    /// Hand-rolled canonical-shaped sigscript with raw price bytes.
    RawShape { pnum: [u8; 8], pden: [u8; 8] },
    /// Owner-cancel-shaped sigscript (byte 0 = 0x41).
    CancelShape,
    /// A nested ratchet sigscript (byte 0 = 0x4d).
    RatchetShape,
}

struct RatchetScn {
    rs: Vec<u8>,
    new_rs: Vec<u8>,
    sibling: Sibling,
    /// Sibling entry: (covenant id present, correct token).
    sibling_cov: (bool, bool),
    sibling_tokens: u64,
    /// Output[0] = the print's KAS leg (koi=0 in the sibling sigscript).
    print_kas: u64,
    escrow: u64,
    continuation_value: u64,
    continuation_bound: bool,
    /// Continuation SPK: None = P2SH(new_rs) (honest).
    forge_continuation_spk: bool,
    sequence: u64,
    sii: u16,
    lock_time: u64,
}

impl RatchetScn {
    fn happy() -> Self {
        let rs = std_ratchet_rs(1, 0, 60, 1_000_000, 0, 0);
        let new_rs = derive_ratchet_continuation_rs(&rs).unwrap();
        RatchetScn {
            rs,
            new_rs,
            sibling: Sibling::SellFill { pnum: 3, pden: 1 },
            sibling_cov: (true, true),
            sibling_tokens: 10_000_000,
            print_kas: 30_000_000,
            escrow: 5_000_000,
            continuation_value: 5_000_000,
            continuation_bound: true,
            forge_continuation_spk: false,
            sequence: 60,
            sii: 0,
            lock_time: 0,
        }
    }
}

/// Run a ratchet attempt. Input layout: [0] sibling, [1] ratchet_oco,
/// [2] fee. Outputs: [0] print KAS leg, [1] sibling token delivery,
/// [2] ratchet continuation, [3] change. Executes ONLY the ratchet input.
fn run_ratchet(scn: &RatchetScn) -> Result<(), String> {
    let c = ctx();
    let token2 = Hash::from_bytes([0xd7; 32]);
    // Sibling sigscript + a plausible entry SPK.
    let sib_sell_rs =
        build_sell_redeem_script(3, 1, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash, 30, 0, 0)
            .unwrap();
    let sib_ss = match &scn.sibling {
        Sibling::SellFill { pnum, pden } => build_sell_fill_sigscript(0, *pnum, *pden, &sib_sell_rs),
        Sibling::SellIoc { pnum, pden, fta } => {
            build_sell_ioc_fill_sigscript(0, *pnum, *pden, *fta, &sib_sell_rs)
        }
        Sibling::RawShape { pnum, pden } => {
            let mut ss = vec![0x01, 0x00, 0x08];
            ss.extend_from_slice(pnum);
            ss.push(0x08);
            ss.extend_from_slice(pden);
            ss.push(0x51); // full-fill selector shape
            ss.extend_from_slice(&kob_core::push_data(&sib_sell_rs));
            ss
        }
        Sibling::CancelShape => {
            build_sell_cancel_sigscript(&[0x11; 64], &c.pubkey, &sib_sell_rs)
        }
        Sibling::RatchetShape => build_ratchet_oco_ratchet_sigscript(
            &scn.new_rs,
            &scn.rs,
            1,
            &scn.rs,
        ),
    };
    let ratchet_ss = build_ratchet_oco_ratchet_sigscript(&scn.new_rs, &scn.rs, scn.sii, &scn.rs);
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sib_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), ratchet_ss, scn.sequence, 0),
        fi,
    ];
    let cont_spk = if scn.forge_continuation_spk {
        build_p2sh(&scn.rs) // old RS's address, not the spliced one
    } else {
        build_p2sh(&scn.new_rs)
    };
    let outputs = vec![
        // [0] the print's KAS leg (koi=0).
        TransactionOutput::with_covenant(scn.print_kas, c.wallet_spk.clone(), None),
        // [1] sibling token delivery (auth[0] of the sibling when bound).
        TransactionOutput::with_covenant(
            scn.sibling_tokens,
            c.wallet_spk.clone(),
            match scn.sibling_cov {
                (true, true) => Some(CovenantBinding::new(0, c.token)),
                (true, false) => Some(CovenantBinding::new(0, token2)),
                (false, _) => None,
            },
        ),
        // [2] the ratchet continuation (auth[0] of the ratchet input when
        // bound).
        TransactionOutput::with_covenant(
            scn.continuation_value,
            cont_spk,
            if scn.continuation_bound { Some(CovenantBinding::new(1, c.token)) } else { None },
        ),
        TransactionOutput::with_covenant(500_000_000, c.wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry {
            amount: scn.sibling_tokens,
            script_public_key: build_p2sh(&sib_sell_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: match scn.sibling_cov {
                (true, true) => Some(c.token),
                (true, false) => Some(token2),
                (false, _) => None,
            },
        },
        UtxoEntry {
            amount: scn.escrow,
            script_public_key: build_p2sh(&scn.rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, scn.lock_time, Default::default(), 0, vec![]);
    exec_selected(&tx, entries, &[1]).remove(0)
}

/// RT-1 (VM analog): happy one-step ratchet with GENUINE settle evidence —
/// the sibling sell's own covenant passes in the same tx, and the ratchet
/// accepts it. Continuation = derived splice.
#[test]
fn ratchet_happy_one_step_with_genuine_settle() {
    let scn = RatchetScn::happy();
    // The sibling's own script must be genuinely valid too (both inputs).
    let c = ctx();
    let sib_sell_rs =
        build_sell_redeem_script(3, 1, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash, 30, 0, 0)
            .unwrap();
    let sib_ss = build_sell_fill_sigscript(0, 3, 1, &sib_sell_rs);
    let ratchet_ss = build_ratchet_oco_ratchet_sigscript(&scn.new_rs, &scn.rs, 0, &scn.rs);
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), sib_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), ratchet_ss, 60, 0),
        fi,
    ];
    let outputs = vec![
        TransactionOutput::with_covenant(30_000_000, c.wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            10_000_000,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        ),
        TransactionOutput::with_covenant(
            5_000_000,
            build_p2sh(&scn.new_rs),
            Some(CovenantBinding::new(1, c.token)),
        ),
        TransactionOutput::with_covenant(500_000_000, c.wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry {
            amount: 10_000_000,
            script_public_key: build_p2sh(&sib_sell_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        UtxoEntry {
            amount: 5_000_000,
            script_public_key: build_p2sh(&scn.rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries, &[0, 1]);
    assert!(r[0].is_ok(), "genuine sibling settle must pass its own covenant: {:?}", r[0]);
    assert!(r[1].is_ok(), "happy one-step ratchet must pass: {:?}", r[1]);
    // The continuation is exactly the spliced RS (scanner derivation).
    assert_eq!(
        parse_ratchet_oco_redeem_script(&scn.new_rs).unwrap().oco.price_num_sl,
        3
    );
}

/// L1: print below the trigger threshold — R11 rejects.
#[test]
fn ratchet_print_below_threshold_rejected() {
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::SellFill { pnum: 2, pden: 1 }; // threshold = 3/1
    scn.print_kas = 20_000_000;
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "below-threshold print must fail R11; got {r:?}");
}

/// L2: garbage prints — cancel-shaped sigscript (byte 0 = 0x41) and a
/// non-covenant wallet sibling. R7/R6 reject.
#[test]
fn ratchet_garbage_prints_rejected() {
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::CancelShape;
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "cancel-shaped sibling must fail R7; got {r:?}");
    // Non-covenant sibling (canonical-looking bytes on a wallet input):
    // OpInputCovenantId = ZERO_HASH != own id => R6.
    let mut scn = RatchetScn::happy();
    scn.sibling_cov = (false, true);
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "non-covenant sibling must fail R6; got {r:?}");
    // Wrong-token sibling: R6.
    let mut scn = RatchetScn::happy();
    scn.sibling_cov = (true, false);
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "wrong-covenant sibling must fail R6; got {r:?}");
}

/// L3: nested-ratchet print — a ratchet sigscript named as sibling begins
/// 0x4d (new_rs pushData), killed by R7 byte 0.
#[test]
fn ratchet_nested_ratchet_print_rejected() {
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::RatchetShape;
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "nested-ratchet sibling must fail R7; got {r:?}");
}

/// L4 (the R9 pin, found during the design round): a hand-rolled sibling with
/// a high-bit 8th price byte reads NEGATIVE as i64 — without R9 the R11
/// cross-mul RHS goes negative and the trigger passes vacuously.
#[test]
fn ratchet_negative_encoding_print_rejected() {
    // pden_att negative (high bit set).
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::RawShape {
        pnum: u64_le(3),
        pden: [0, 0, 0, 0, 0, 0, 0, 0x80],
    };
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "negative pden_att must fail R9; got {r:?}");
    // pnum_att negative.
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::RawShape {
        pnum: [0, 0, 0, 0, 0, 0, 0, 0x80],
        pden: u64_le(1),
    };
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "negative pnum_att must fail R9; got {r:?}");
    // Zero prices are floored too (>= 1).
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::RawShape { pnum: u64_le(3), pden: u64_le(0) };
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "zero pden_att must fail R9; got {r:?}");
}

/// L8: self-reference (sii = the ratchet's own input) — R5 rejects.
#[test]
fn ratchet_self_reference_rejected() {
    let mut scn = RatchetScn::happy();
    scn.sii = 1; // the ratchet input's own index
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "sii == self must fail R5; got {r:?}");
}

/// G2 volume floor: sub-mrv sibling volume rejected (R10), full-fill and IOC
/// forms; the IOC fta (min path) is what counts, not token_in.
#[test]
fn ratchet_volume_floor() {
    // Full-fill sibling below mrv.
    let mut scn = RatchetScn::happy();
    scn.sibling_tokens = 999_999; // mrv = 1_000_000
    scn.print_kas = 3 * 999_999;
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "sub-mrv full-fill print must fail R10; got {r:?}");
    // IOC sibling: token_in large but fta below mrv => vol = min(...) fails.
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::SellIoc { pnum: 3, pden: 1, fta: 999_999 };
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "sub-mrv IOC fta must fail R10 (min path); got {r:?}");
    // IOC sibling at fta >= mrv passes (print_kas covers fta * 3).
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::SellIoc { pnum: 3, pden: 1, fta: 2_000_000 };
    scn.print_kas = 6_000_000;
    let r = run_ratchet(&scn);
    assert!(r.is_ok(), "IOC print at fta >= mrv must pass: {r:?}");
}

/// G2 settle-magnitude re-check (R12): the print's KAS leg must be worth
/// vol * P — a canonical-shaped sibling whose output[koi] is short fails.
#[test]
fn ratchet_settle_magnitude_recheck() {
    let mut scn = RatchetScn::happy();
    scn.print_kas = 29_999_999; // vol 10M * pnum 3 / pden 1 = 30M
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "short KAS leg must fail R12; got {r:?}");
}

/// L10: splice pins — wrong step, no step, decreased pnum_sl (one-way
/// monotonicity), any mutated byte outside the window, shortened new_rs.
#[test]
fn ratchet_splice_pins() {
    let base = RatchetScn::happy();
    // Wrong step: += 2*rstep.
    let mut scn = RatchetScn::happy();
    scn.new_rs = derive_ratchet_continuation_rs(&base.new_rs).unwrap();
    assert!(run_ratchet(&scn).is_err(), "double-step splice must fail R13d");
    // No step: new == old.
    let mut scn = RatchetScn::happy();
    scn.new_rs = scn.rs.clone();
    assert!(run_ratchet(&scn).is_err(), "no-step splice must fail R13d");
    // Decreased pnum_sl (one-way monotonicity): 2 -> 1.
    let mut scn = RatchetScn::happy();
    let mut down = scn.rs.clone();
    down[RATCHET_PNUM_SL_OFFSET..RATCHET_PNUM_SL_OFFSET + 8].copy_from_slice(&u64_le(1));
    scn.new_rs = down;
    assert!(run_ratchet(&scn).is_err(), "SL decrease must fail (no branch lowers pnum_sl)");
    // Mutated prefix byte (rgap value at RS[10..18)).
    let mut scn = RatchetScn::happy();
    let mut m = derive_ratchet_continuation_rs(&scn.rs).unwrap();
    m[10] ^= 1;
    scn.new_rs = m;
    assert!(run_ratchet(&scn).is_err(), "mutated prefix byte must fail R13b");
    // Mutated suffix byte (expiry value at RS[200..208)) — a ratchet can
    // never extend the order's life.
    let mut scn = RatchetScn::happy();
    let mut m = derive_ratchet_continuation_rs(&scn.rs).unwrap();
    m[200] ^= 1;
    scn.new_rs = m;
    assert!(run_ratchet(&scn).is_err(), "mutated expiry byte must fail R13c");
    // Mutated cpend byte (RS[198]).
    let mut scn = RatchetScn::happy();
    let mut m = derive_ratchet_continuation_rs(&scn.rs).unwrap();
    m[198] = 0x51;
    scn.new_rs = m;
    assert!(run_ratchet(&scn).is_err(), "mutated cpend byte must fail R13c");
    // Shortened new_rs (length pinned by the suffix EQUAL).
    let mut scn = RatchetScn::happy();
    let mut m = derive_ratchet_continuation_rs(&scn.rs).unwrap();
    m.pop();
    scn.new_rs = m;
    assert!(run_ratchet(&scn).is_err(), "shortened new_rs must fail R13c");
}

/// L11: escrow skim via the continuation — short value, forged SPK, or a
/// missing covenant binding all fail R13f.
#[test]
fn ratchet_continuation_escrow_pins() {
    let mut scn = RatchetScn::happy();
    scn.continuation_value = 4_999_999;
    assert!(run_ratchet(&scn).is_err(), "short continuation escrow must fail R13f");
    let mut scn = RatchetScn::happy();
    scn.forge_continuation_spk = true;
    assert!(run_ratchet(&scn).is_err(), "continuation at the OLD address must fail R13f");
    let mut scn = RatchetScn::happy();
    scn.continuation_bound = false;
    assert!(run_ratchet(&scn).is_err(), "unbound continuation must fail (no auth[0])");
}

/// G1 rate limit: sequence < rwin fails the CSV; == rwin passes.
#[test]
fn ratchet_rwin_rate_limit() {
    let mut scn = RatchetScn::happy();
    scn.sequence = 59; // rwin = 60
    assert!(run_ratchet(&scn).is_err(), "sequence < rwin must fail G1");
    let scn = RatchetScn::happy();
    assert!(run_ratchet(&scn).is_ok(), "sequence == rwin must pass");
}

/// G3 travel cap: with TP 4/1, SL 2/1, rstep 1 the first ratchet (SL 2->3)
/// passes; the second (3->4 == TP) is rejected — the SL can never reach TP.
#[test]
fn ratchet_travel_cap() {
    let c = ctx();
    let rs0 = build_ratchet_oco_redeem_script(
        1, 0, 60, 1_000_000, 4, 1, 1, 2, 1, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash,
        30, 0, 0,
    )
    .unwrap();
    let rs1 = derive_ratchet_continuation_rs(&rs0).unwrap();
    // Step 1 (2 -> 3): (2+1)*1 < 4*1 — passes.
    let mut scn = RatchetScn::happy();
    scn.rs = rs0;
    scn.new_rs = rs1.clone();
    assert!(run_ratchet(&scn).is_ok(), "first ratchet inside the cap must pass");
    // Step 2 (3 -> 4 = TP): (3+1)*1 < 4*1 is false — G3 rejects. The print
    // must clear the higher trigger (4/1) so only the cap can be the failure.
    let mut scn = RatchetScn::happy();
    scn.sibling = Sibling::SellFill { pnum: 5, pden: 1 };
    scn.print_kas = 50_000_000;
    scn.rs = rs1.clone();
    scn.new_rs = derive_ratchet_continuation_rs(&rs1).unwrap();
    assert!(run_ratchet(&scn).is_err(), "ratchet reaching TP must fail G3");
}

/// L5a economics pin: filling the ratcheted SL pays the owner strictly MORE
/// than the pre-ratchet floor — and the ratcheted-SL fill actually executes
/// (RT-1 part 2: SL fill on the continuation at the new price).
#[test]
fn ratchet_then_fill_pays_owner_more() {
    let c = ctx();
    let rs0 = std_ratchet_rs(1, 0, 60, 1_000_000, 0, 0);
    let rs1 = derive_ratchet_continuation_rs(&rs0).unwrap();
    let escrow = 5_000_000u64;
    let (old_sl_kas, new_sl_kas) = (escrow * 2, escrow * 3);
    assert!(new_sl_kas > old_sl_kas, "economics: ratchet raises the owner's floor");
    // SL fill of the continuation at the ratcheted price 3/1.
    let ss = build_ratchet_oco_sl_fill_sigscript(0, 3, 1, &rs1);
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 50, 0), fi];
    let outputs = vec![
        TransactionOutput::with_covenant(new_sl_kas, c.wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            escrow,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        ),
    ];
    let entries = vec![
        UtxoEntry {
            amount: escrow,
            script_public_key: build_p2sh(&rs1),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries.clone(), &[0]).remove(0);
    assert!(r.is_ok(), "ratcheted SL fill at the new price must pass: {r:?}");
    // Paying only the OLD floor against the continuation fails.
    let ss = build_ratchet_oco_sl_fill_sigscript(0, 3, 1, &rs1);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 50, 0), wallet_input(0x30).0];
    let outputs = vec![
        TransactionOutput::with_covenant(old_sl_kas, c.wallet_spk.clone(), None),
        TransactionOutput::with_covenant(
            escrow,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        ),
    ];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries, &[0]).remove(0);
    assert!(r.is_err(), "old-floor payment against the ratcheted SL must fail");
}

/// R1 defense-in-depth: a hand-rolled RS with rstep = 0 (bypassing the
/// builder) cannot ratchet.
#[test]
fn ratchet_handrolled_rstep_zero_rejected() {
    let c = ctx();
    // Assemble the state manually (builder would reject rstep = 0).
    let mut rs = Vec::new();
    rs.push(0x02); // batch_max = 255 (default encoding)
    rs.push(0xff);
    rs.push(0x00);
    for v in [0u64, 0, 60, 1_000_000] {
        rs.push(0x08);
        rs.extend_from_slice(&u64_le(v));
    }
    rs.push(0x20);
    rs.extend_from_slice(&c.spk_hash);
    for v in [5u64, 1, 1, 2, 1, 1] {
        rs.push(0x08);
        rs.extend_from_slice(&u64_le(v));
    }
    rs.push(0x20);
    rs.extend_from_slice(&c.owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(&c.spk_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(30));
    rs.push(0x00);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(0));
    rs.extend_from_slice(&build_ratchet_oco_body());
    assert_eq!(rs.len(), RATCHET_OCO_RS_EXPECTED_LEN);
    let mut scn = RatchetScn::happy();
    scn.new_rs = rs.clone(); // rstep 0: new == old is the "correct" splice
    scn.rs = rs;
    let r = run_ratchet(&scn);
    assert!(r.is_err(), "hand-rolled rstep=0 must fail R1; got {r:?}");
}

/// §4.8 interplay: a cancel-pending deploy can't ratchet (R2); EXPIRE works
/// identically on a ratcheted continuation (expiry bytes are in the fixed
/// suffix); CANCEL reaches the owner signature check on the continuation.
#[test]
fn ratchet_cancel_expire_interplay() {
    let c = ctx();
    // cpend = 1 freezes ratcheting.
    let rs = std_ratchet_rs(1, 0, 60, 1_000_000, 1, 0);
    let mut scn = RatchetScn::happy();
    scn.new_rs = derive_ratchet_continuation_rs(&rs).unwrap();
    scn.rs = rs;
    assert!(run_ratchet(&scn).is_err(), "cpend=1 must fail R2");
    // EXPIRE on the CONTINUATION of an expiring ratchet_oco.
    let rs0 = std_ratchet_rs(1, 0, 60, 1_000_000, 0, 1000);
    let rs1 = derive_ratchet_continuation_rs(&rs0).unwrap();
    for (lock_time, expect_ok) in [(2000u64, true), (500, false)] {
        let ss = build_oco_sell_expire_sigscript(&rs1);
        let (fi, fe) = wallet_input(0x30);
        let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0), fi];
        let outputs = vec![TransactionOutput::with_covenant(
            5_000_000,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        )];
        let entries = vec![
            UtxoEntry {
                amount: 5_000_000,
                script_public_key: build_p2sh(&rs1),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: Some(c.token),
            },
            fe,
        ];
        let tx = Transaction::new(1, inputs, outputs, lock_time, Default::default(), 0, vec![]);
        let r = exec_selected(&tx, entries, &[0]).remove(0);
        assert_eq!(r.is_ok(), expect_ok, "continuation expire at {lock_time}: {r:?}");
    }
    // CANCEL on the continuation reaches the signature check with the
    // ORIGINAL key material (ohash preserved by the splice).
    let ss = build_oco_sell_cancel_sigscript(&[0x11; 64], &c.pubkey, &rs1);
    let inputs = vec![TransactionInput::new(op(0x10, 0), ss, 0, 0)];
    let outputs = vec![TransactionOutput::with_covenant(
        5_000_000,
        c.wallet_spk.clone(),
        Some(CovenantBinding::new(0, c.token)),
    )];
    let entries = vec![UtxoEntry {
        amount: 5_000_000,
        script_public_key: build_p2sh(&rs1),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: Some(c.token),
    }];
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let r = exec_selected(&tx, entries, &[0]).remove(0);
    let e = r.unwrap_err();
    assert!(
        e.contains("Sig") || e.contains("sig") || e.contains("Verify") || e.contains("Null")
            || e.contains("Schnorr"),
        "continuation cancel must reach OpCheckSig, got: {e}"
    );
}

// ===========================================================================
// Composition proofs CP-1..CP-3 (CP-4 lives in decay_buy_fill_and_cp4_...):
// an UNCHANGED v18 buy sweeps each new sell variant at the VM level.
// ===========================================================================

/// Shared sweep: v18 buy consumes [variant sell (input 0), plain v18 sell
/// (input 1)] in ONE tx. Returns per-input results [variant, plain, buy].
fn run_cp_sweep(
    variant_rs: Vec<u8>,
    variant_ss: Vec<u8>,
    variant_tokens: u64,
    variant_kas: u64,
    variant_sequence: u64,
    buy_price: (u64, u64),
    lock_time: u64,
) -> Vec<Result<(), String>> {
    let c = ctx();
    let plain_rs =
        build_sell_redeem_script(99, 100, 1, &c.owner_hash, &c.spk_hash, &c.spk_hash, 30, 0, 0)
            .unwrap();
    let plain_tokens = 10_000_000u64;
    let plain_kas = plain_tokens * 99 / 100;
    let plain_ss = build_sell_fill_sigscript(1, 99, 100, &plain_rs);
    let kas_in = variant_kas + plain_kas;
    let buy_rs = build_buy_redeem_script(
        &arr32(TOKEN_HEX), buy_price.0, buy_price.1, 1_000_000, &c.owner_hash, &c.spk_hash,
        &c.spk_hash, 10000, 0, 0,
    )
    .unwrap();
    let buy_ss = build_buy_fill_sigscript(&[0, 1], false, &buy_rs);
    let (fi, fe) = wallet_input(0x30);
    let inputs = vec![
        TransactionInput::new(op(0x10, 0), variant_ss, variant_sequence, 0),
        TransactionInput::new(op(0x11, 0), plain_ss, 50, 0),
        TransactionInput::new(op(0x20, 0), buy_ss, 50, 0),
        fi,
    ];
    let outputs = vec![
        // [0] variant seller KAS (koi=0), [1] plain seller KAS (koi=1).
        TransactionOutput::with_covenant(variant_kas, c.wallet_spk.clone(), None),
        TransactionOutput::with_covenant(plain_kas, c.wallet_spk.clone(), None),
        // [2]/[3] buyer token deliveries (auth[0] of inputs 0/1).
        TransactionOutput::with_covenant(
            variant_tokens,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(0, c.token)),
        ),
        TransactionOutput::with_covenant(
            plain_tokens,
            c.wallet_spk.clone(),
            Some(CovenantBinding::new(1, c.token)),
        ),
        TransactionOutput::with_covenant(500_000_000, c.wallet_spk.clone(), None),
    ];
    let entries = vec![
        UtxoEntry {
            amount: variant_tokens,
            script_public_key: build_p2sh(&variant_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        UtxoEntry {
            amount: plain_tokens,
            script_public_key: build_p2sh(&plain_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: Some(c.token),
        },
        UtxoEntry {
            amount: kas_in,
            script_public_key: build_p2sh(&buy_rs),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        },
        fe,
    ];
    let tx = Transaction::new(1, inputs, outputs, lock_time, Default::default(), 0, vec![]);
    exec_selected(&tx, entries, &[0, 1, 2])
}

/// CP-1: unchanged v18 buy sweeps a decay_sell + a plain v18 sell in ONE tx —
/// the buy's fair_sum consumes f(L) at the canonical offsets next to a static
/// price; one tx = one L for every schedule in the sweep.
#[test]
fn cp1_v18_buy_sweeps_decay_sell() {
    let l = 1500u64;
    let tokens = 10_000_000u64;
    let rs = std_decay_sell_rs(0);
    let ss = build_decay_sell_fill_sigscript(0, f(l), 1_000_000, &rs);
    // kas_in = 15M + 9.9M = 24.9M; buy 4/5: floor = 24.9M/5*4 = 19.92M <= 20M.
    let res = run_cp_sweep(rs, ss, tokens, kas_at(l, tokens), 50, (4, 5), l);
    assert!(res[0].is_ok(), "decay_sell leg must pass: {:?}", res[0]);
    assert!(res[1].is_ok(), "plain sell leg must pass: {:?}", res[1]);
    assert!(res[2].is_ok(), "UNCHANGED v18 buy must sweep the mix (CP-1): {:?}", res[2]);
}

/// CP-2: unchanged v18 buy sweeps a twap_sell (+ plain sell) in one tx, the
/// twap input carrying sequence = twin.
#[test]
fn cp2_v18_buy_sweeps_twap_sell() {
    let rs = std_twap_rs(0);
    let ss = build_sell_fill_sigscript(0, 1, 1, &rs);
    // kas_in = 10M + 9.9M = 19.9M; buy 1/1: floor 19.9M <= 20M.
    let res = run_cp_sweep(rs.clone(), ss, MPW, MPW, TWIN, (1, 1), 0);
    assert!(res[0].is_ok(), "twap_sell leg must pass: {:?}", res[0]);
    assert!(res[2].is_ok(), "UNCHANGED v18 buy must sweep the twap (CP-2): {:?}", res[2]);
    // ...and the same sweep with the twap input's sequence below twin fails
    // only the twap leg (composition preserves the rate limit).
    let ss = build_sell_fill_sigscript(0, 1, 1, &rs);
    let res = run_cp_sweep(rs, ss, MPW, MPW, TWIN - 1, (1, 1), 0);
    assert!(res[0].is_err(), "immature twap leg must still fail inside a sweep");
}

/// CP-3: unchanged v18 buy sweeps a ratchet_oco on the TP branch.
#[test]
fn cp3_v18_buy_sweeps_ratchet_tp() {
    let rs = std_ratchet_rs(1, 0, 60, 1_000_000, 0, 0);
    let tokens = 5_000_000u64;
    let kas = tokens * 5; // TP 5/1
    let ss = build_ratchet_oco_tp_fill_sigscript(0, 5, 1, &rs);
    // kas_in = 25M + 9.9M = 34.9M; buy 3/7: floor = 34.9M/7*3 = 14.957M <= 15M.
    let res = run_cp_sweep(rs, ss, tokens, kas, 50, (3, 7), 0);
    assert!(res[0].is_ok(), "ratchet_oco TP leg must pass: {:?}", res[0]);
    assert!(res[2].is_ok(), "UNCHANGED v18 buy must sweep the ratchet TP (CP-3): {:?}", res[2]);
}
