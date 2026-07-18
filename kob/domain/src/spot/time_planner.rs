//! Time-contracts domain planners (kob/TIME_CONTRACTS_DESIGN.md, Stage B):
//!
//!   - the decay lock-time feasibility solver (§2.7 batching constraint
//!     solver): find the L window where every decay leg's effective price
//!     keeps the batch feasible (floors + caps + expiry gates), pick
//!     `L = now` clamped into it, and reject with typed errors naming the
//!     earliest feasible L when now is too early;
//!   - the TWAP pacing helper (§3.5): a pure fill schedule — one event per
//!     `twin` real DAA, `vol <= mpw` per event — the engine paces it;
//!   - `plan_ratchet_advance` (§4.7): given a ratchet_oco and a same-tcid
//!     settle plan, build the permissionless RATCHET-branch spend + the
//!     spliced continuation output, selecting a print that satisfies R10
//!     (volume >= mrv), R11 (trigger at the ATTESTED pair) and R12 (the
//!     settle-magnitude re-check — the KAS leg must cover the print value on
//!     the CEIL side, so only divisible prints qualify), plus G1 rwin
//!     spacing and the G3 travel cap; `compose_settle_and_ratchet` merges it
//!     with the settle's `build_tx()` so ONE tx settles and ratchets.
//!
//! The sweep-admission logic for the time-sell variants themselves lives in
//! `batch.rs` (`plan_batch_match_at` / `plan_ioc_match_at` /
//! `plan_partial_match_at`, plus the decay_buy planners).

use kob_core::MIN_UTXO_VALUE;
use kob_core::contract::spot::decay::{decay_effective_pnum, LOCK_TIME_THRESHOLD};
use kob_core::contract::spot::parse::{
    parse_decay_buy_redeem_script, parse_ratchet_oco_redeem_script,
};
use kob_core::contract::spot::ratchet::{
    build_ratchet_oco_ratchet_sigscript, derive_ratchet_continuation_rs,
};

use super::batch::{
    attested_sell_pair, buy_mmfee_bps_any, classify_sell, effective_sell_pair,
    order_expiry_daa, BatchError, BatchOrder, BatchPlan, BatchTx, BatchTxInput,
    OutputPurpose, PlannedOutput, SellVariant,
};

// Contract-order fair value (duplicated tiny helper; the buy's PASS 2 order).
fn fair_kas(tokens: u64, pnum: u64, pden: u64) -> u128 {
    (tokens as u128 / pden as u128) * pnum as u128
}

// ═════════════════════════════════════════════════════════════════════════
// Lock-time feasibility solver (design §2.7)
// ═════════════════════════════════════════════════════════════════════════

/// Solved lock-time window for a decay-bearing batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockTimeWindow {
    /// Smallest feasible tx lock_time (0 = feasible immediately).
    pub earliest: u64,
    /// Largest feasible tx lock_time (bounded by member expiries, the D1
    /// threshold and the sells' effective-price floors/caps).
    pub latest: u64,
    /// The L the planner should carry: `now` clamped into
    /// `[earliest, latest]` (never above `latest` — understating L is always
    /// minable and only under-uses the schedules).
    pub chosen: u64,
}

/// Find the tx lock_time window in which a full-fill N:1 sweep of `sells`
/// against `buy` is feasible, and choose `L = now_daa` clamped into it.
///
/// Feasibility at L (all in exact contract integer order):
///   - every member's fill time-gate: `expiry > L` (expiry-carrying members);
///   - per decay_sell: `amount * pnum_eff(L) / pden >= max(MIN_UTXO, mfill)`;
///   - the buy's aggregate token floor: `Σ amount >= kas_in/pden*pnum(_eff)`
///     (decay_buy consumes its own schedule at the same L);
///   - the buy's surplus cap: `kas_in - fair_sum(L) <= kas_in/10000*mmfee`.
///
/// Monotonicity (schedules are monotone in L, §2.1) makes the feasible set
/// an interval: the buy floor only RELAXES as L grows (rising bid = fewer
/// tokens demanded) — a lower bound; the sells' KAS floors and the surplus
/// cap only TIGHTEN as L grows (falling asks) — upper bounds. Both sides are
/// found by binary search over the schedule breakpoint range (all schedules
/// freeze at their `t_end`).
///
/// Typed rejections: `LockTimeTooEarly { earliest, now }` when the window
/// opens after `now` (retry at `earliest`); `LockTimeWindowEmpty` when no L
/// works (split the batch or wait for different counterparties).
pub fn solve_batch_lock_time(
    sells: &[BatchOrder],
    buy: &BatchOrder,
    now_daa: u64,
) -> Result<LockTimeWindow, BatchError> {
    // Domain cap: D1 type guard + every member's fill time-gate.
    let mut h: u64 = LOCK_TIME_THRESHOLD - 1;
    for s in sells {
        if let Some(e) = order_expiry_daa(&s.redeem_script) {
            h = h.min(e.saturating_sub(1));
        }
    }
    if let Some(e) = order_expiry_daa(&buy.redeem_script) {
        h = h.min(e.saturating_sub(1));
    }

    // Schedule plateau: every decay schedule freezes at its t_end, so
    // feasibility is constant beyond the largest one — search [0, s_cap].
    let buy_decay = parse_decay_buy_redeem_script(&buy.redeem_script);
    let mut smax: u64 = 0;
    for s in sells {
        if let SellVariant::Decay { t_end, .. } = classify_sell(s) {
            smax = smax.max(t_end);
        }
    }
    if let Some(p) = &buy_decay {
        smax = smax.max(p.t_end);
    }
    let s_cap = smax.min(h);

    let total_tokens: u128 = sells.iter().map(|s| s.amount as u128).sum();
    let kas_in = buy.utxo_value as u128;
    let mmfee_bps = buy_mmfee_bps_any(&buy.redeem_script)
        .ok_or_else(|| BatchError::UnsupportedVersion {
            outpoint: format!("{}:{}", buy.outpoint.0, buy.outpoint.1),
            version: buy.version,
        })? as u128;

    // Lower-bound side (non-decreasing in L): the buy's aggregate token
    // floor at f(L), exact contract order (buy body E/H: kas/pden DIV, MUL).
    let lower_ok = |l: u64| -> bool {
        let floor = match &buy_decay {
            Some(p) => {
                let pe = decay_effective_pnum(p.order.price_num, p.dslope, p.t0, p.t_end, l);
                (kas_in / p.order.price_den as u128) * pe as u128
            }
            None => {
                if buy.price_den == 0 {
                    return false;
                }
                (kas_in / buy.price_den as u128) * buy.price_num as u128
            }
        };
        total_tokens >= floor
    };

    // Upper-bound side (non-increasing in L): per-sell KAS floors + the
    // buy's surplus cap at fair_sum(L).
    let upper_ok = |l: u64| -> bool {
        let mut fair: u128 = 0;
        for s in sells {
            let (pn, pd) = effective_sell_pair(s, l);
            if pd == 0 {
                return false;
            }
            let kas = s.amount as u128 * pn as u128 / pd as u128;
            if kas > u64::MAX as u128 {
                return false;
            }
            if (kas as u64) < MIN_UTXO_VALUE || (kas as u64) < s.min_fill {
                return false;
            }
            fair += fair_kas(s.amount, pn, pd);
        }
        kas_in.saturating_sub(fair) <= (kas_in / 10000) * mmfee_bps
    };

    let earliest = if lower_ok(0) {
        0
    } else if !lower_ok(s_cap) {
        // The floor is unreachable at EVERY schedule point in the domain.
        return Err(BatchError::LockTimeWindowEmpty { earliest: u64::MAX, latest: h });
    } else {
        // Binary search: min l in (0, s_cap] with lower_ok.
        let (mut lo, mut hi) = (0u64, s_cap); // !lower_ok(lo), lower_ok(hi)
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if lower_ok(mid) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    };

    if !upper_ok(0) {
        // The sells' floors / the cap fail even at the schedule start.
        return Err(BatchError::LockTimeWindowEmpty { earliest, latest: 0 });
    }
    let latest = if upper_ok(s_cap) {
        h // constant beyond the plateau, feasible up to the domain cap
    } else {
        // Binary search: max l in [0, s_cap) with upper_ok.
        let (mut lo, mut hi) = (0u64, s_cap); // upper_ok(lo), !upper_ok(hi)
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if upper_ok(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    };

    if earliest > latest {
        return Err(BatchError::LockTimeWindowEmpty { earliest, latest });
    }
    if now_daa < earliest {
        return Err(BatchError::LockTimeTooEarly { earliest, now: now_daa });
    }
    Ok(LockTimeWindow { earliest, latest, chosen: now_daa.min(latest) })
}

// ═════════════════════════════════════════════════════════════════════════
// TWAP pacing helper (design §3.5) — pure; the engine paces it
// ═════════════════════════════════════════════════════════════════════════

/// One planned TWAP fill event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwapFillEvent {
    /// Tokens this event moves (`<= mpw`; FILL = token_in, IOC/PARTIAL = fta).
    pub volume: u64,
    /// Sequence the order input must carry: `max(50, twin)` (the twin CSV
    /// real-age gate; the builder enforces twin >= 50 so this is twin).
    pub sequence: u64,
    /// BEST-CASE earliest acceptance DAA: consensus admits the k-th event no
    /// earlier than `utxo_daa + (k+1)*twin` because each event's residual is
    /// created at (>=) the previous event's acceptance score and must age
    /// `twin` again (T3: `utxo.daa + seq - 1 < pov`). Real spacing can only
    /// be wider.
    pub earliest_daa: u64,
}

/// Emit the fill schedule that moves `target_volume` tokens through a
/// twap_sell at the declared rate: `ceil(target/mpw)` events, each
/// `volume <= mpw`, each carrying `sequence = twin`, spaced `twin` real DAA
/// apart from the order UTXO's creation score. Pure function — no I/O, no
/// book state; the engine's scheduler queues each event at `earliest_daa`
/// (a natural fit for the auto-expire loop, §3.5).
pub fn twap_fill_schedule(
    twin: u64,
    mpw: u64,
    utxo_daa_score: u64,
    target_volume: u64,
) -> Vec<TwapFillEvent> {
    let mut events = Vec::new();
    if mpw == 0 {
        return events; // malformed (builder rejects mpw=0); nothing to pace
    }
    let mut remaining = target_volume;
    let mut k: u64 = 0;
    while remaining > 0 {
        let volume = remaining.min(mpw);
        events.push(TwapFillEvent {
            volume,
            sequence: twin.max(50),
            earliest_daa: utxo_daa_score.saturating_add(twin.saturating_mul(k + 1)),
        });
        remaining -= volume;
        k += 1;
    }
    events
}

// ═════════════════════════════════════════════════════════════════════════
// Ratchet advance planner (design §4.7)
// ═════════════════════════════════════════════════════════════════════════

/// A resting ratchet_oco UTXO the matcher wants to advance.
#[derive(Debug, Clone)]
pub struct RatchetOrderRef {
    /// Outpoint (txid, index) of the ratchet_oco UTXO.
    pub outpoint: (String, u32),
    /// CURRENT redeemScript (deploy RS, or a derived continuation after k
    /// ratchets — the scanner tracks these, §4.7).
    pub redeem_script: Vec<u8>,
    /// UTXO value (token escrow; the continuation must carry >= this, R13f).
    pub escrow: u64,
    /// The UTXO's creation DAA score (consensus real-age clock for G1).
    pub utxo_daa_score: u64,
    /// The escrow token's covenant id (must equal the print's — R6 sibling
    /// authentication is by covenant id).
    pub token_cov_id: [u8; 32],
}

/// A planned RATCHET-branch spend, ready to be composed with a settle tx.
#[derive(Debug, Clone)]
pub struct RatchetAdvancePlan {
    /// The ratchet input: sigscript
    /// `[pushData(new_rs)][pushData(old_rs)][sii][Op3][pushData(RS)]`,
    /// sig_op_count 0 (permissionless), sequence = rwin (G1).
    pub input: BatchTxInput,
    /// Where the input goes in the settle tx built by
    /// `compose_settle_and_ratchet`: after the buy, before receipt/wallet
    /// (= `settle.sells.len() + 1`), so the sells' sii indices are stable.
    pub input_position: usize,
    /// Index into `settle.sells` of the chosen print witness.
    pub sibling_sell: usize,
    /// The print's tx INPUT index (= what the sigscript's `sii` names).
    pub sibling_input_idx: u16,
    /// The continuation output: P2SH(new_rs), value = full escrow. The
    /// executor MUST attach `CovenantBinding(input_position, token)` so it
    /// is auth slot 0 of the ratchet input (R13f / Fix-3).
    pub continuation: PlannedOutput,
    /// The spliced continuation RS (`old_rs` with pnum_sl += rstep) — the
    /// scanner watches P2SH(new_rs) for the next lifecycle step.
    pub new_rs: Vec<u8>,
}

/// Plan a permissionless ratchet advance riding a same-token settle plan
/// (usually a `plan_batch_match*` product — CP-style composition: one tx
/// settles AND ratchets).
///
/// Guard enforcement at plan time (mirrors R1–R13):
///   - R2: cpend == 0; R3: expiry gate at the settle's lock_time;
///   - G1 (R4): `tip_daa >= utxo_daa + rwin`, and the input carries
///     `sequence = rwin`;
///   - G3 (R13e): `(pnum_sl + rstep)*pden_tp < pnum_tp*pden_sl`;
///   - print selection (R6/R10/R11/R12): scan the settle's sells for a
///     same-token FULL-FILL term whose ATTESTED pair (gcd-normalized for
///     plain/twap/OCO, raw effective f(L) for decay, raw branch pair for
///     ratchet branches) satisfies the trigger, whose volume >= mrv, and
///     whose planned KAS output covers `vol × pnum_att / pden_att` on the
///     CEIL side (`amt × pden_att >= vol × pnum_att` — R12's sharp edge:
///     the sell covenant only forces the FLOOR side, so an indivisible
///     print under-covers by one and is rejected on-chain; the planner
///     therefore selects divisible prints).
pub fn plan_ratchet_advance(
    oco: &RatchetOrderRef,
    settle: &BatchPlan,
    tip_daa: u64,
) -> Result<RatchetAdvancePlan, BatchError> {
    let outpoint = format!("{}:{}", oco.outpoint.0, oco.outpoint.1);
    let p = parse_ratchet_oco_redeem_script(&oco.redeem_script).ok_or_else(|| {
        BatchError::RatchetIneligible {
            outpoint: outpoint.clone(),
            reason: "not a ratchet_oco redeemScript",
        }
    })?;

    // R2: a deploy-marked OCO can't ratchet.
    if p.oco.cpend != 0 {
        return Err(BatchError::RatchetIneligible {
            outpoint,
            reason: "cancel-pending (cpend=1) — R2 rejects",
        });
    }
    // R3: the ratchet branch runs the same expiry time-gate as the fills.
    if let Some(e) = p.oco.expiry_daa {
        if settle.lock_time >= e {
            return Err(BatchError::LockTimePastExpiry {
                outpoint,
                expiry: e,
                lock_time: settle.lock_time,
            });
        }
    }
    // G1 (R4): rwin CSV — consensus admits the spend once
    // `utxo_daa + rwin - 1 < tip`, i.e. tip >= utxo_daa + rwin.
    let eligible_at = oco.utxo_daa_score.saturating_add(p.rwin);
    if tip_daa < eligible_at {
        return Err(BatchError::RatchetWindowNotElapsed {
            eligible_at_daa: eligible_at,
            tip_daa,
        });
    }
    // G3 (R13e): the post-ratchet SL must stay strictly below TP.
    let lhs = (p.oco.price_num_sl as u128 + p.rstep as u128) * p.oco.price_den_tp as u128;
    let rhs = p.oco.price_num_tp as u128 * p.oco.price_den_sl as u128;
    if lhs >= rhs {
        return Err(BatchError::RatchetTravelCapExhausted {
            outpoint,
            pnum_sl: p.oco.price_num_sl,
            rstep: p.rstep,
        });
    }

    // Print selection: R6 same token, R10 volume, R11 trigger, R12
    // settle-magnitude (divisibility), plus the R12 koi single-byte read
    // (output index <= 127 stays positive as i64).
    let thr_num = p.oco.price_num_sl as u128 + p.rstep as u128 + p.rgap as u128;
    let thr_den = p.oco.price_den_sl as u128;
    let mut chosen: Option<(usize, u16)> = None;
    for (i, (sell, input_idx)) in settle.sells.iter().enumerate() {
        if sell.token_cov_id != oco.token_cov_id {
            continue; // R6: OpInputCovenantId(sii) must equal own id
        }
        // Full-fill terms only (the v18 sweep planners are full-fill-only;
        // a residual-keeping sell would carry the IOC shape and its fta).
        if settle
            .sell_fill_amounts
            .get(i)
            .map_or(false, |&fta| fta < sell.utxo_value)
        {
            continue;
        }
        let vol = sell.amount;
        if vol < p.mrv {
            continue; // R10
        }
        let (pn_att, pd_att) = attested_sell_pair(sell, settle.lock_time);
        if pn_att == 0 || pd_att == 0 {
            continue; // R9 would reject; malformed anyway
        }
        // R11 trigger: pnum_att × pden_sl >= (pnum_sl + rstep + rgap) × pden_att.
        if (pn_att as u128) * thr_den < thr_num * (pd_att as u128) {
            continue;
        }
        // R12: OpTxOutputAmount(koi) × pden_att >= vol × pnum_att.
        let Some(&koi) = settle.sell_output_idx.get(i) else { continue };
        if koi > 127 {
            continue; // koi byte >= 0x80 reads negative in R12 — fail-closed
        }
        let Some(out) = settle.outputs.get(koi) else { continue };
        if (out.value as u128) * (pd_att as u128) < (vol as u128) * (pn_att as u128) {
            continue; // indivisible print: floor-side KAS under-covers
        }
        let sii = *input_idx as u16;
        chosen = Some((i, sii));
        break;
    }
    let Some((sibling_sell, sibling_input_idx)) = chosen else {
        return Err(BatchError::RatchetNoQualifyingPrint {
            threshold_num: thr_num.min(u64::MAX as u128) as u64,
            threshold_den: p.oco.price_den_sl,
            mrv: p.mrv,
        });
    };

    // Splice: new_rs = old_rs with pnum_sl += rstep (exactly what R13d
    // enforces); continuation = P2SH(new_rs), full escrow, binding kept.
    let new_rs = derive_ratchet_continuation_rs(&oco.redeem_script).map_err(|_| {
        BatchError::RatchetIneligible {
            outpoint: format!("{}:{}", oco.outpoint.0, oco.outpoint.1),
            reason: "continuation derivation failed (pnum_sl + rstep overflows)",
        }
    })?;
    let sigscript = build_ratchet_oco_ratchet_sigscript(
        &new_rs,
        &oco.redeem_script,
        sibling_input_idx,
        &oco.redeem_script,
    );
    let cont_spk = kob_core::p2sh::build_p2sh(&new_rs);

    Ok(RatchetAdvancePlan {
        input: BatchTxInput {
            tx_id: oco.outpoint.0.clone(),
            index: oco.outpoint.1,
            sigscript,
            // permissionless branch: no real CheckSig executes. sig_op_count
            // is reused post-Toccata to commit a per-input computeBudget
            // (`compute_budget_for_sig_ops` in kob/settle/src/tx.rs), not a
            // literal opcode count. RT-1 live finding (2026-07-18, testnet-10):
            // the splice+introspection work of a composed settle+advance
            // measured 10,311 script units on this input, over the node's
            // 9,999 free per-input allowance ("script units exceeded the
            // amount committed in the input") — the settle+advance shape is
            // heavier than the standalone ratchet fill this budget was sized
            // for. sig_op_count=1 buys 10 budget units (100,000 script units,
            // same headroom trick as kob_batch_lab.rs's buy input) so total
            // allowance is 109,999, comfortably covering the measured usage.
            sig_op_count: 1,
            sequence: p.rwin, // G1
        },
        input_position: settle.sells.len() + 1,
        sibling_sell,
        sibling_input_idx,
        continuation: PlannedOutput {
            value: oco.escrow,
            script_public_key: cont_spk.script().to_vec(),
            spk_version: cont_spk.version(),
            purpose: OutputPurpose::RatchetContinuation,
        },
        new_rs,
    })
}

/// Compose a settle plan with a planned ratchet advance into ONE tx shape:
/// the ratchet input is inserted after the buy (sell sii indices stable,
/// wallet/receipt shift by one) and the continuation output is appended.
/// The escrow rides through in full (inputs and outputs grow by the same
/// value), so the settle's fee accounting is untouched. The executor must
/// bind the continuation to the ratchet input
/// (`CovenantBinding(adv.input_position, token)`) and set the ratchet
/// input's sequence from `adv.input.sequence`.
pub fn compose_settle_and_ratchet(
    settle: &BatchPlan,
    adv: &RatchetAdvancePlan,
) -> Result<BatchTx, BatchError> {
    let mut tx = settle.build_tx()?;
    let pos = adv.input_position.min(tx.inputs.len());
    tx.inputs.insert(pos, adv.input.clone());
    tx.outputs.push(super::batch::BatchTxOutput {
        value: adv.continuation.value,
        script_public_key: adv.continuation.script_public_key.clone(),
        spk_version: adv.continuation.spk_version,
        purpose: adv.continuation.purpose,
    });
    Ok(tx)
}
