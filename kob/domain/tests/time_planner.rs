//! Time-contracts Stage-B planner tests (pure, no engine): sweep admission
//! for twap_sell / decay_sell / ratchet_oco branches, the decay lock-time
//! feasibility solver, the decay_buy planners, the TWAP pacing helper, the
//! ratchet advance planner (incl. the R12 divisible-print selection), and
//! the owner-cap interplay on mixed batches. The same shapes are proven
//! against the real TxScriptEngine in `planner_engine_repro.rs`.

use kob_core::contract::spot::decay::{
    build_decay_buy_redeem_script, build_decay_sell_redeem_script,
};
use kob_core::contract::spot::order::{
    build_buy_redeem_script, build_buy_redeem_script_with_caps, build_sell_redeem_script,
};
use kob_core::contract::spot::ratchet::{
    build_ratchet_oco_redeem_script, derive_ratchet_continuation_rs,
};
use kob_core::contract::spot::twap::{
    build_twap_sell_redeem_script, build_twap_sell_redeem_script_with_caps,
};
use kob_core::u64_le;

use kob_domain::batch::{
    plan_batch_match, plan_batch_match_at, plan_decay_buy_ioc_match, plan_decay_buy_match,
    plan_ioc_match, plan_partial_match_at, BatchError, BatchOrder, OrderType, OutputPurpose,
};
use kob_domain::time_planner::{
    compose_settle_and_ratchet, plan_ratchet_advance, solve_batch_lock_time,
    twap_fill_schedule, RatchetOrderRef,
};

const TOKEN: [u8; 32] = [0x77; 32];
const OWNER: [u8; 32] = [0xAA; 32];
const SPKH: [u8; 32] = [0xBB; 32];
const SEAT: [u8; 32] = [0xCC; 32];

fn matcher_spk() -> Vec<u8> {
    let mut s = vec![0x20];
    s.extend_from_slice(&[0xEE; 32]);
    s.push(0xac);
    s
}

fn order_from_rs(id: u8, side: OrderType, rs: Vec<u8>, amount: u64, pnum: u64, pden: u64, min_fill: u64) -> BatchOrder {
    BatchOrder {
        outpoint: (hex::encode([id; 32]), 0),
        order_type: side,
        version: 18,
        token_cov_id: TOKEN,
        price_num: pnum,
        price_den: pden,
        amount,
        redeem_script: rs,
        utxo_value: amount,
        counterparty_spk: matcher_spk(),
        counterparty_spk_version: 0,
        min_fill,
        oco_path: None,
        bracket_meta: None,
    }
}

fn plain_sell(id: u8, amount: u64, pnum: u64, pden: u64) -> BatchOrder {
    let rs = build_sell_redeem_script(pnum, pden, 1, &OWNER, &SPKH, &SEAT, 30, 0, 0).unwrap();
    order_from_rs(id, OrderType::Sell, rs, amount, pnum, pden, 1)
}

fn twap_sell(id: u8, amount: u64, twin: u64, mpw: u64, pnum: u64, pden: u64) -> BatchOrder {
    let rs = build_twap_sell_redeem_script(twin, mpw, pnum, pden, 1, &OWNER, &SPKH, &SEAT, 30, 0, 0)
        .unwrap();
    order_from_rs(id, OrderType::Sell, rs, amount, pnum, pden, 1)
}

/// Standard decay schedule: pnum 2M -> 1M over DAA 1000..2000, pden 1M.
fn decay_sell(id: u8, amount: u64, min_fill: u64, expiry: u64) -> BatchOrder {
    let rs = build_decay_sell_redeem_script(
        1000, 1000, 2000, 2_000_000, 1_000_000, min_fill, &OWNER, &SPKH, &SEAT, 30, 0, expiry,
    )
    .unwrap();
    // Book view carries the START pair; the planner re-parses the schedule.
    order_from_rs(id, OrderType::Sell, rs, amount, 2_000_000, 1_000_000, min_fill)
}

fn ratchet_tp_sell(id: u8, amount: u64, tp: (u64, u64)) -> BatchOrder {
    let rs = build_ratchet_oco_redeem_script(
        1, 0, 60, 1_000_000, tp.0, tp.1, 1, 2, 1, 1, &OWNER, &SPKH, &SEAT, 30, 0, 0,
    )
    .unwrap();
    let mut o = order_from_rs(id, OrderType::Sell, rs, amount, tp.0, tp.1, 1);
    o.oco_path = Some(kob_core::OcoPath::TakeProfit);
    o
}

fn plain_buy(id: u8, kas: u64, pnum: u64, pden: u64, mmfee: u64) -> BatchOrder {
    let rs = build_buy_redeem_script(&TOKEN, pnum, pden, 1_000_000, &OWNER, &SPKH, &SEAT, mmfee, 0, 0)
        .unwrap();
    order_from_rs(id, OrderType::Buy, rs, kas, pnum, pden, 1_000_000)
}

/// Standard decay_buy: tokens-per-KAS numerator 2M -> 1M over 1000..2000.
fn decay_buy(id: u8, kas: u64, min_fill: u64) -> BatchOrder {
    let rs = build_decay_buy_redeem_script(
        1000, 1000, 2000, &TOKEN, 2_000_000, 1_000_000, min_fill, &OWNER, &SPKH, &SEAT, 10000, 0, 0,
    )
    .unwrap();
    order_from_rs(id, OrderType::Buy, rs, kas, 2_000_000, 1_000_000, min_fill)
}

fn wallet() -> Option<(String, u32, u64)> {
    Some((hex::encode([0x30u8; 32]), 0, 5_000_000))
}

// ── twap admission ──

/// Admission wires `sequence = twin` on the twap input (the planner does NOT
/// gate on UTXO age — consensus enforces the real-age CSV; a premature tx
/// simply waits/rejects at the node) and respects the mpw full-fill bound.
#[test]
fn twap_admission_sequence_and_mpw() {
    let sells = vec![twap_sell(0x10, 10_000_000, 100, 10_000_000, 1, 1)];
    let buys = vec![plain_buy(0x20, 10_000_000, 1, 1, 2000)];
    let plan = plan_batch_match(&sells, &buys, wallet(), &matcher_spk(), 0, None)
        .expect("twap sweep must plan");
    let tx = plan.build_tx().unwrap();
    assert_eq!(tx.inputs[0].sequence, 100, "twap input carries sequence = twin");
    assert_eq!(tx.inputs[1].sequence, 50, "buy input keeps the exposure delay");
    // Attestation shape = plain v18 (state price pair).
    assert_eq!(&tx.inputs[0].sigscript[3..11], &u64_le(1));

    // Whole-UTXO volume above mpw cannot full-fill: typed rejection.
    let sells = vec![twap_sell(0x10, 12_000_000, 100, 10_000_000, 1, 1)];
    let buys = vec![plain_buy(0x20, 12_000_000, 1, 1, 2000)];
    match plan_batch_match(&sells, &buys, wallet(), &matcher_spk(), 0, None) {
        Err(BatchError::TwapVolumeExceedsMpw { amount, mpw, .. }) => {
            assert_eq!((amount, mpw), (12_000_000, 10_000_000));
        }
        other => panic!("expected TwapVolumeExceedsMpw, got {other:?}"),
    }

    // The greedy IOC planner SKIPS the oversized twap and fills the plain.
    let sells = vec![
        twap_sell(0x10, 12_000_000, 100, 10_000_000, 1, 1),
        plain_sell(0x11, 10_000_000, 1, 1),
    ];
    let buy = plain_buy(0x20, 10_400_000, 1, 1, 2000);
    let plan = plan_ioc_match(&sells, &buy, wallet(), &matcher_spk(), 0, None)
        .expect("IOC must plan around the oversized twap");
    assert_eq!(plan.sells.len(), 1);
    assert_eq!(plan.sells[0].0.outpoint.0, hex::encode([0x11u8; 32]));
}

// ── decay admission ──

/// A decay_sell is priced at f(L) of the lock_time the plan carries; the
/// built sigscript attests the RAW effective pair (no gcd — 1.5M/1M would
/// normalize to 3/2 and fail D3 on-chain).
#[test]
fn decay_admission_prices_at_lock_time() {
    // L = 1500 (mid-schedule): pnum_eff = 1.5M -> 15M sompi for 10M tokens.
    let sells = vec![decay_sell(0x10, 10_000_000, 1, 0)];
    let buys = vec![plain_buy(0x20, 15_000_000, 2, 3, 10000)];
    let plan = plan_batch_match_at(&sells, &buys, wallet(), &matcher_spk(), 0, None, 1500)
        .expect("decay sweep must plan at L=1500");
    assert_eq!(plan.lock_time, 1500);
    assert_eq!(plan.outputs[0].value, 15_000_000, "seller KAS = f(1500)");
    let tx = plan.build_tx().unwrap();
    assert_eq!(&tx.inputs[0].sigscript[3..11], &u64_le(1_500_000), "RAW pnum_eff at [3..11)");
    assert_eq!(&tx.inputs[0].sigscript[12..20], &u64_le(1_000_000), "RAW pden at [12..20)");

    // Legacy entry point (L=0): the clamp maps to the start price.
    let buys = vec![plain_buy(0x20, 20_000_000, 1, 2, 10000)];
    let plan = plan_batch_match(&sells, &buys, wallet(), &matcher_spk(), 0, None)
        .expect("decay sweep must plan at L=0 (start price)");
    assert_eq!(plan.outputs[0].value, 20_000_000);

    // Past t_end: the floor price.
    let buys = vec![plain_buy(0x20, 10_000_000, 1, 1, 10000)];
    let plan = plan_batch_match_at(&sells, &buys, wallet(), &matcher_spk(), 0, None, 2500)
        .expect("decay sweep must plan at the floor");
    assert_eq!(plan.outputs[0].value, 10_000_000);
}

/// A member whose fill time-gate cannot pass at the planned L is a typed
/// rejection (GTC explicit batch = hard error).
#[test]
fn decay_expiry_gate_at_lock_time() {
    let sells = vec![decay_sell(0x10, 10_000_000, 1, 1200)];
    let buys = vec![plain_buy(0x20, 15_000_000, 2, 3, 10000)];
    match plan_batch_match_at(&sells, &buys, wallet(), &matcher_spk(), 0, None, 1500) {
        Err(BatchError::LockTimePastExpiry { expiry, lock_time, .. }) => {
            assert_eq!((expiry, lock_time), (1200, 1500));
        }
        other => panic!("expected LockTimePastExpiry, got {other:?}"),
    }
}

/// The buy-partial planner admits decay sells at f(L): the spent KAS and the
/// residual reflect the effective price, and the built sigscript attests it.
#[test]
fn decay_admission_in_buy_partial() {
    // Buy 30M spends f(1500)·10M = 15M against the decay sell, keeps 15M.
    let sells = vec![decay_sell(0x10, 10_000_000, 1, 0)];
    let buy = plain_buy(0x20, 30_000_000, 1, 3, 10000); // floor: spent/3*1 <= 10M tokens
    let plan = plan_partial_match_at(&sells, &buy, wallet(), &matcher_spk(), 0, Some(0), 1500)
        .expect("decay partial must plan at L=1500");
    assert_eq!(plan.lock_time, 1500);
    let &(spent, ri, _) = plan.buy_partial_fills.get(&0).expect("partial entry");
    assert_eq!(spent, 15_000_000, "spent = f(1500) seller KAS (fee_bps 0 => no surplus)");
    assert_eq!(plan.outputs[ri as usize].value, 15_000_000, "residual = kas_in - spent");
    let tx = plan.build_tx().unwrap();
    assert_eq!(&tx.inputs[0].sigscript[3..11], &u64_le(1_500_000));
}

// ── lock-time feasibility solver ──

#[test]
fn solver_window_and_typed_rejections() {
    // decay_buy 10M KAS: floor(L) = 10 * pnum_eff(L) tokens; 15M tokens on
    // offer become sufficient once pnum_eff <= 1.5M, i.e. L >= 1500.
    let sells = vec![plain_sell(0x10, 15_000_000, 1, 2)];
    let buy = decay_buy(0x20, 10_000_000, 1);
    let win = solve_batch_lock_time(&sells, &buy, 1500).expect("feasible at 1500");
    assert_eq!(win.earliest, 1500, "floor first reachable at L=1500");
    assert_eq!(win.chosen, 1500);

    // Too early: typed error NAMES the earliest feasible L.
    match solve_batch_lock_time(&sells, &buy, 1499) {
        Err(BatchError::LockTimeTooEarly { earliest, now }) => {
            assert_eq!((earliest, now), (1500, 1499));
        }
        other => panic!("expected LockTimeTooEarly, got {other:?}"),
    }

    // Upper-bound failure at every L (a decay sell whose min_fill exceeds
    // even its start-price KAS): empty window.
    let sells = vec![decay_sell(0x10, 10_000_000, 25_000_000, 0)];
    let buy = plain_buy(0x20, 20_000_000, 1, 2, 10000);
    match solve_batch_lock_time(&sells, &buy, 1500) {
        Err(BatchError::LockTimeWindowEmpty { latest, .. }) => assert_eq!(latest, 0),
        other => panic!("expected LockTimeWindowEmpty, got {other:?}"),
    }

    // Floor unreachable at every schedule point: empty window (earliest =
    // the u64::MAX sentinel).
    let sells = vec![plain_sell(0x10, 9_000_000, 1, 2)]; // < 10M even at the floor
    let buy = decay_buy(0x20, 10_000_000, 1);
    match solve_batch_lock_time(&sells, &buy, 5000) {
        Err(BatchError::LockTimeWindowEmpty { earliest, .. }) => assert_eq!(earliest, u64::MAX),
        other => panic!("expected LockTimeWindowEmpty, got {other:?}"),
    }
}

// ── decay_buy planners ──

#[test]
fn decay_buy_planner_floor_and_lock_time() {
    // Exactly at the risen-bid floor: 15M tokens vs floor 10 * 1.5M = 15M.
    let sells = vec![plain_sell(0x10, 15_000_000, 1, 2)];
    let buy = decay_buy(0x20, 10_000_000, 1);
    let plan = plan_decay_buy_match(&sells, &buy, 1500, wallet(), &matcher_spk(), 0, None)
        .expect("decay_buy sweep must plan at the f(L) floor");
    assert_eq!(plan.lock_time, 1500);
    assert_eq!(plan.outputs[0].value, 7_500_000, "seller KAS at the sell's own price");
    let tokens: u64 = plan
        .outputs
        .iter()
        .filter(|o| o.purpose == OutputPurpose::BuyerTokens)
        .map(|o| o.value)
        .sum();
    assert_eq!(tokens, 15_000_000);

    // One token short: the window opens one DAA later — typed, names it.
    let sells = vec![plain_sell(0x10, 14_999_999, 1, 2)];
    match plan_decay_buy_match(&sells, &buy, 1500, wallet(), &matcher_spk(), 0, None) {
        Err(BatchError::LockTimeTooEarly { earliest, now }) => {
            // pnum_eff(1501) = 1_499_000 -> floor 14_990_000 <= 14_999_999.
            assert_eq!((earliest, now), (1501, 1500));
        }
        other => panic!("expected LockTimeTooEarly, got {other:?}"),
    }

    // IOC variant: floor relaxes to the buy's own min_fill; L = now.
    let sells = vec![plain_sell(0x10, 8_000_000, 1, 2)];
    let buy = decay_buy(0x21, 10_000_000, 1_000_000);
    let plan = plan_decay_buy_ioc_match(&sells, &buy, 1700, wallet(), &matcher_spk(), 0, None)
        .expect("decay_buy IOC must plan");
    assert_eq!(plan.lock_time, 1700);
    assert!(plan.ioc_mode.is_some());
}

// ── TWAP pacing helper ──

#[test]
fn twap_pacing_splits_target_across_events() {
    let events = twap_fill_schedule(100, 10_000_000, 500, 25_000_000);
    assert_eq!(events.len(), 3, "vol > mpw splits across events");
    assert_eq!(
        events.iter().map(|e| e.volume).collect::<Vec<_>>(),
        vec![10_000_000, 10_000_000, 5_000_000]
    );
    assert!(events.iter().all(|e| e.sequence == 100), "sequence = twin per event");
    assert_eq!(
        events.iter().map(|e| e.earliest_daa).collect::<Vec<_>>(),
        vec![600, 700, 800],
        "one window per event from the UTXO's creation score"
    );
    assert!(twap_fill_schedule(100, 10_000_000, 0, 0).is_empty());
}

// ── ratchet advance planner ──

fn ratchet_ref(rs: Vec<u8>, utxo_daa: u64) -> RatchetOrderRef {
    RatchetOrderRef {
        outpoint: (hex::encode([0x40u8; 32]), 0),
        redeem_script: rs,
        escrow: 5_000_000,
        utxo_daa_score: utxo_daa,
        token_cov_id: TOKEN,
    }
}

fn std_ratchet_rs(rstep: u64, mrv: u64) -> Vec<u8> {
    // TP 5/1, SL 2/1, rgap 0, rwin 60.
    build_ratchet_oco_redeem_script(
        rstep, 0, 60, mrv, 5, 1, 1, 2, 1, 1, &OWNER, &SPKH, &SEAT, 30, 0, 0,
    )
    .unwrap()
}

/// A settle of one 3/1 sell (divisible print: 10M x 3 / 1 exact) against a
/// 30M buy — the standard print witness for the tests below.
fn print_settle(price: (u64, u64), amount: u64, buy_kas: u64, buy_price: (u64, u64)) -> kob_domain::batch::BatchPlan {
    let sells = vec![plain_sell(0x10, amount, price.0, price.1)];
    let buys = vec![plain_buy(0x20, buy_kas, buy_price.0, buy_price.1, 2000)];
    plan_batch_match(&sells, &buys, wallet(), &matcher_spk(), 0, None).expect("settle must plan")
}

#[test]
fn ratchet_advance_happy_path_and_compose() {
    let settle = print_settle((3, 1), 10_000_000, 30_000_000, (1, 3));
    let rs = std_ratchet_rs(1, 1_000_000);
    let adv = plan_ratchet_advance(&ratchet_ref(rs.clone(), 0), &settle, 100)
        .expect("ratchet advance must plan (trigger 3/1 met by the 3/1 print)");
    assert_eq!(adv.input.sequence, 60, "G1: sequence = rwin");
    assert_eq!(
        adv.input.sig_op_count, 1,
        "permissionless branch, but sig_op_count=1 buys the extra computeBudget \
         (RT-1 live finding: settle+advance composition needs >9,999 free script units)"
    );
    assert_eq!(adv.input_position, 2, "after the buy, sii indices stable");
    assert_eq!(adv.sibling_input_idx, 0);
    assert_eq!(adv.continuation.value, 5_000_000, "full escrow rides through");
    assert_eq!(adv.new_rs, derive_ratchet_continuation_rs(&rs).unwrap());

    let tx = compose_settle_and_ratchet(&settle, &adv).expect("compose");
    assert_eq!(tx.inputs[2].sequence, 60);
    assert_eq!(
        tx.outputs.last().unwrap().purpose,
        OutputPurpose::RatchetContinuation,
        "continuation appended"
    );
    // Escrow-neutral composition: inputs and outputs grew by the same value.
    assert_eq!(tx.outputs.last().unwrap().value, 5_000_000);
}

#[test]
fn ratchet_advance_typed_rejections() {
    let settle = print_settle((3, 1), 10_000_000, 30_000_000, (1, 3));

    // G1: rwin not elapsed.
    match plan_ratchet_advance(&ratchet_ref(std_ratchet_rs(1, 1_000_000), 41), &settle, 100) {
        Err(BatchError::RatchetWindowNotElapsed { eligible_at_daa, tip_daa }) => {
            assert_eq!((eligible_at_daa, tip_daa), (101, 100));
        }
        other => panic!("expected RatchetWindowNotElapsed, got {other:?}"),
    }

    // G3: travel cap — after one rstep=2 ratchet (SL 2 -> 4), the next step
    // would reach TP 5: exhausted on the continuation.
    let rs = std_ratchet_rs(2, 1_000_000);
    let cont = derive_ratchet_continuation_rs(&rs).unwrap();
    match plan_ratchet_advance(&ratchet_ref(cont, 0), &settle, 100) {
        Err(BatchError::RatchetTravelCapExhausted { pnum_sl, rstep, .. }) => {
            assert_eq!((pnum_sl, rstep), (4, 2));
        }
        other => panic!("expected RatchetTravelCapExhausted, got {other:?}"),
    }

    // R11: print below the trigger (2/1 print vs threshold 3/1).
    let below = print_settle((2, 1), 10_000_000, 20_000_000, (1, 2));
    match plan_ratchet_advance(&ratchet_ref(std_ratchet_rs(1, 1_000_000), 0), &below, 100) {
        Err(BatchError::RatchetNoQualifyingPrint { threshold_num, threshold_den, .. }) => {
            assert_eq!((threshold_num, threshold_den), (3, 1));
        }
        other => panic!("expected RatchetNoQualifyingPrint, got {other:?}"),
    }

    // R10: volume below mrv.
    match plan_ratchet_advance(&ratchet_ref(std_ratchet_rs(1, 20_000_000), 0), &settle, 100) {
        Err(BatchError::RatchetNoQualifyingPrint { mrv, .. }) => assert_eq!(mrv, 20_000_000),
        other => panic!("expected RatchetNoQualifyingPrint (mrv), got {other:?}"),
    }

    // R12 sharp edge: an INDIVISIBLE print (7/2 x odd volume) floor-rounds
    // its KAS leg one short of the ceil-side re-check — rejected; the even
    // (divisible) volume qualifies.
    let odd = print_settle((7, 2), 3_000_001, 12_000_000, (1, 4));
    match plan_ratchet_advance(&ratchet_ref(std_ratchet_rs(1, 1_000_000), 0), &odd, 100) {
        Err(BatchError::RatchetNoQualifyingPrint { .. }) => {}
        other => panic!("expected RatchetNoQualifyingPrint (indivisible), got {other:?}"),
    }
    let even = print_settle((7, 2), 3_000_000, 12_000_000, (1, 4));
    plan_ratchet_advance(&ratchet_ref(std_ratchet_rs(1, 1_000_000), 0), &even, 100)
        .expect("divisible print must qualify");
}

// ── caps interplay on mixed batches ──

#[test]
fn mixed_batch_caps_interplay() {
    // A twap_sell carrying batch_max=2 rejects a 3-sell batch.
    let twap_rs = build_twap_sell_redeem_script_with_caps(
        2, 100, 10_000_000, 1, 1, 1, &OWNER, &SPKH, &SEAT, 30, 0, 0,
    )
    .unwrap();
    let capped_twap = order_from_rs(0x11, OrderType::Sell, twap_rs, 10_000_000, 1, 1, 1);
    let sells = vec![
        plain_sell(0x10, 10_000_000, 1, 1),
        capped_twap.clone(),
        decay_sell(0x12, 10_000_000, 1, 0),
    ];
    let buys = vec![plain_buy(0x20, 40_000_000, 1, 1, 10000)];
    match plan_batch_match(&sells, &buys, wallet(), &matcher_spk(), 0, None) {
        Err(BatchError::BatchCapExceeded { batch_max, batch_size, .. }) => {
            assert_eq!((batch_max, batch_size), (2, 3));
        }
        other => panic!("expected BatchCapExceeded, got {other:?}"),
    }

    // The buy's owner n_max caps the sweep jointly.
    let buy_rs = build_buy_redeem_script_with_caps(
        2, &TOKEN, 1, 1, 1_000_000, &OWNER, &SPKH, &SEAT, 10000, 0, 0,
    )
    .unwrap();
    let capped_buy = order_from_rs(0x21, OrderType::Buy, buy_rs, 40_000_000, 1, 1, 1_000_000);
    match plan_batch_match(&sells, &[capped_buy], wallet(), &matcher_spk(), 0, None) {
        Err(BatchError::TooManySells { count, max }) => assert_eq!((count, max), (3, 2)),
        other => panic!("expected TooManySells (n_max), got {other:?}"),
    }

    // MAX_N = 32 hard ceiling.
    let many: Vec<BatchOrder> = (0..33u8).map(|i| plain_sell(0x80 + i, 10_000_000, 1, 1)).collect();
    let buys = vec![plain_buy(0x20, 330_000_000, 1, 1, 10000)];
    match plan_batch_match(&many, &buys, wallet(), &matcher_spk(), 0, None) {
        Err(BatchError::TooManySells { count, max }) => assert_eq!((count, max), (33, 32)),
        other => panic!("expected TooManySells (MAX_N), got {other:?}"),
    }

    // Mixed plain + time variants within every cap plans fine (CP-1..3
    // shape at the plan level): plain + twap + decay + ratchet TP.
    let sells = vec![
        plain_sell(0x10, 10_000_000, 1, 1),
        twap_sell(0x11, 10_000_000, 100, 10_000_000, 1, 1),
        decay_sell(0x12, 10_000_000, 1, 0),
        ratchet_tp_sell(0x13, 4_000_000, (5, 1)),
    ];
    // Seller KAS at L=1500: 10M + 10M + 15M + 20M = 55M.
    let buys = vec![plain_buy(0x20, 55_000_000, 1, 2, 10000)];
    let plan = plan_batch_match_at(&sells, &buys, wallet(), &matcher_spk(), 0, None, 1500)
        .expect("mixed batch must plan");
    assert_eq!(plan.sells.len(), 4);
    let tx = plan.build_tx().unwrap();
    assert_eq!(tx.inputs[1].sequence, 100, "twap member sequence");
    assert_eq!(&tx.inputs[2].sigscript[3..11], &u64_le(1_500_000), "decay member attests f(L)");
    // Ratchet TP branch attests its RAW branch pair via the ratchet builder.
    assert_eq!(&tx.inputs[3].sigscript[3..11], &u64_le(5));
    assert_eq!(tx.inputs[3].sigscript[11], 0x08);
}

// ── Stage C: sell-anchored admission gates (Stage-B residuals 1+2) ──

/// The anchor's fill time-gate is a HARD error at the plan's lock_time (the
/// anchor cannot be greedily skipped like sweep members).
#[test]
fn sell_anchored_expiry_gate_typed() {
    let sell = decay_sell(0x10, 10_000_000, 1_000_000, 1200);
    let buys = vec![plain_buy(0x20, 15_000_000, 2, 3, 2000)];
    let err = kob_domain::batch::plan_sell_ioc_match_at(
        &sell, &buys, wallet(), &[0x20; 34], 0, None, 1500,
    )
    .unwrap_err();
    assert!(
        matches!(err, BatchError::LockTimePastExpiry { expiry: 1200, lock_time: 1500, .. }),
        "anchor past expiry must reject typed; got {err}"
    );
}

/// The D1 domain guard rejects a unix-ms-type lock_time at plan time.
#[test]
fn sell_anchored_d1_threshold_guard() {
    let sell = decay_sell(0x10, 10_000_000, 1_000_000, 0);
    let buys = vec![plain_buy(0x20, 15_000_000, 2, 3, 2000)];
    let err = kob_domain::batch::plan_sell_ioc_match_at(
        &sell, &buys, wallet(), &[0x20; 34], 0, None, 500_000_000_000,
    )
    .unwrap_err();
    assert!(
        matches!(err, BatchError::LockTimeWindowEmpty { .. }),
        "unix-ms-type L must reject typed; got {err}"
    );
}

/// Expiry-dead candidate buys are SKIPPED (greedy), not hard errors: the
/// anchor settles against the next eligible buy.
#[test]
fn sell_anchored_skips_expired_buys() {
    let sell = decay_sell(0x10, 10_000_000, 1_000_000, 0);
    // First buy expires at 1400 (< L=1500) — skipped; second absorbs.
    let rs_expired = build_buy_redeem_script(&TOKEN, 2, 3, 1_000_000, &OWNER, &SPKH, &SEAT, 2000, 0, 1400).unwrap();
    let expired = order_from_rs(0x20, OrderType::Buy, rs_expired, 15_000_000, 2, 3, 1_000_000);
    let live = plain_buy(0x21, 15_000_000, 2, 3, 2000);
    let plan = kob_domain::batch::plan_sell_ioc_match_at(
        &sell, &[expired, live], wallet(), &[0x20; 34], 0, None, 1500,
    )
    .expect("second buy must absorb");
    assert_eq!(plan.buys[0].0.outpoint.0, hex::encode([0x21u8; 32]), "expired buy skipped");
    assert_eq!(plan.lock_time, 1500);
}

/// The legacy entry point stays byte-stable: `plan_sell_ioc_match` ==
/// `plan_sell_ioc_match_at(..., 0)` (decay anchors clamp to the start price).
#[test]
fn sell_anchored_legacy_delegates_at_zero() {
    let sell = decay_sell(0x10, 10_000_000, 1_000_000, 0);
    // At L=0 the clamp yields the start price 2M/1M -> seller KAS 20M.
    let buys = vec![plain_buy(0x20, 20_000_000, 1, 2, 2000)];
    let legacy = kob_domain::batch::plan_sell_ioc_match(
        &sell, &buys, wallet(), &[0x20; 34], 0, None,
    )
    .expect("legacy path plans");
    assert_eq!(legacy.lock_time, 0);
    assert_eq!(legacy.outputs[0].value, 20_000_000, "start-price clamp at L=0");
}
