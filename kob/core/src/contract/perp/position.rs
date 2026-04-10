use crate::primitives::{push_data, u64_le};

/// Compute greatest common divisor (for price normalization).
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

// perp_position — Atomic Settlement via Spot Co-Spend
//
// Atomic co-spend against real spot BuySell covenants. Exit price = spot
// output ratio. No external oracle.
//
// Two independent UTXOs (one per party) instead of one combined UTXO.
// Each UTXO value = that party's margin.
//
// Atomic Settlement TX Structure:
//   Input 0:  perp_long      (perp_position, direction=1)
//   Input 1:  perp_short     (perp_position, direction=2)
//   Input 2:  buy_order      (BuySell buy covenant)
//   Input 3:  sell_order     (BuySell sell covenant)
//   Output 0: long_payout    (to long owner_spk_hash)
//   Output 1: short_payout   (to short owner_spk_hash)
//   Output 2: seller_kas     (spot: seller receives KAS)
//   Output 3: buyer_tokens   (spot: buyer receives tokens)
//   Output 4+: token_change, miner_spread, etc.
//
// State layout (16 items, 216B):
//   d0  = max_price          (8B)    d1  = min_price        (8B)
//   d2  = emergency_daa      (8B)    d3  = maturity_daa     (8B)
//   d4  = grace_daa          (8B)    d5  = close_fee        (8B)
//   d6  = keeper_fee         (8B)    d7  = maint_pct_den    (8B)
//   d8  = maint_pct_num      (8B)    d9  = entry_den        (8B)
//   d10 = entry_num          (8B)    d11 = size             (8B)
//   d12 = direction          (8B)    d13 = owner_spk_hash   (32B)
//   d14 = spot_buy_spkh      (32B)   d15 = spot_sell_spkh   (32B)
//
// 7 paths (selectors 1-7; 6 fails):
//   1. Cancel (owner reclaim)        — owner sig
//   2. Unilateral close              — owner sig + spot co-spend
//   3. Liquidation                   — permissionless + spot co-spend + CLTV(grace)
//   4. Maturity settle               — permissionless + spot co-spend + CLTV(maturity)
//   5. Add margin (self-continuation) — owner sig
//   7. Emergency timeout             — permissionless + CLTV(emergency)
//   6 → immediate fail
//
// Abbreviations in stack traces:
//   mp=max_price  minp=min_price  ed_daa=emergency_daa  mat_daa=maturity_daa
//   grace=grace_daa  cf=close_fee  kf=keeper_fee  md=maint_pct_den
//   mn=maint_pct_num  ed=entry_den  en=entry_num  sz=size
//   dir=direction  owner=owner_spk_hash  buy_spkh=spot_buy_spkh  sell_spkh=spot_sell_spkh
//   sk=seller_kas  bt=buyer_tokens  mm=my_margin  cm=counter_margin
//   pnl=profit_and_loss  pay=my_payout
//
// PnL formula (2 OpDiv):
//   step 1: sk_scaled = sk * entry_den
//   step 2: oracle_scaled = sk_scaled / bt        (first OpDiv)
//   step 3: delta = oracle_scaled - entry_num     (long) or entry_num - oracle_scaled (short)
//   step 4: pnl_raw = delta * size
//   step 5: pnl = pnl_raw / entry_den            (second OpDiv)

/// State size for perp_position: 3*(1+32) + 13*(1+8) = 99 + 117 = 216 bytes.
pub const PERP_POSITION_STATE_SIZE: usize = 33 * 3 + 9 * 13; // = 216

/// Expected body length for position snapshot test.
#[cfg(test)]
const PERP_BODY_EXPECTED_LEN: usize = 381;

/// perp_position body bytecode.
///
/// Dispatch: push(1, 0x10=16) OpRoll to bring selector to top of 16-item state,
/// then nested if/else cascade.
///
/// Layout:
///   [dispatch 10B]
///   sel==1: path 1 cancel [~20B]
///   OpElse:
///     [shared atomic settle ~136B] (spot verify + price bounds + PnL + clamp)
///     sel==3 check: path 3 liquidation [~50B]
///     OpElse: paths 2/4
///       [shared output verify ~25B]
///       sel==2: path 2 unilateral [~28B]
///       OpElse: sel==4 path 4 maturity [~14B]
///       OpEndIf
///     OpEndIf
///   OpEndIf
///   sel==5: path 5 add margin [~40B]
///   OpElse:
///     sel==7: path 7 emergency [~32B]
///     OpElse: fail [2B]
///   OpEndIf x3 [3B]
pub const PERP_POSITION_BODY: &[u8] = &[
    // DISPATCH (10B)
    // Initial stack (after RS state pushes + selector from sigscript):
    //   sel(deepest) mp(0) minp(1) ed_daa(2) mat_daa(3) grace(4) cf(5) kf(6) md(7) mn(8) ed(9) en(10) sz(11) dir(12) owner(13) buy_spkh(14) sell_spkh(15)
    // Roll sel from depth 16 to top:
    0x01, 0x10, 0x7a,             // push(1, 0x10=16) OpRoll -> sel to top       [3B]
    // stack: sel(0) mp(1) minp(2) ed_daa(3) mat_daa(4) grace(5) cf(6) kf(7) md(8) mn(9) ed(10) en(11) sz(12) dir(13) owner(14) buy_spkh(15) sell_spkh(16) [17 items]
    0x76,                         // OpDup                                        [1B]
    0x52, 0x9f,                   // Op2 OpLessThan (sel < 2?)                    [2B]
    // stack: bool(0) sel(1) mp(2) ... sell_spkh(17) [18 items]
    0x63,                         // OpIf (sel < 2 -> cancel path)                [1B]
    // stack: sel(0) mp(1) ... sell_spkh(16) [17 items]
    0x51, 0x87, 0x69,             // Op1 OpEqual OpVerify (sel==1)                [3B]
    // stack: mp(0) minp(1) ... sell_spkh(15) [16 items]

    // PATH 1: CANCEL — Owner reclaims margin (20B)
    // Sigscript: [sig 65B][pk 32B][Op1][pushData(RS)]
    // After RS exec + dispatch: mp(0) ... sell_spkh(15) pk(16) sig(17) [18 items]
    //
    // Identity: Blake2b(pk) == owner_spk_hash (d13 in 16-item state = d14 with pk,sig below)
    // pk is at d16, owner is at d14 (after sel consumed, pk/sig are deepest)
    // Wait: after sel==1 consumed: stack is [mp(0)..sell_spkh(15)] = 16 state items
    // pk and sig are BELOW state (pushed first in sigscript, so deepest)
    // So pk is at d16, sig is at d17
    0x01, 0x10, 0x79,             // push(1,16) OpPick -> pk copy (d16)           [3B]
    // stack: pk_c(0) mp(1) ... sell_spkh(16) pk(17) sig(18) [19 items]
    0xaa,                         // OpBlake2b -> hash(pk)                        [1B]
    // stack: h(0) mp(1) ... sell_spkh(16) pk(17) sig(18) [19 items]
    0x5e, 0x79,                   // Op14 OpPick -> owner (d14 in 0-indexed = state item 13)  [2B]
    // stack: owner_c(0) h(1) mp(2) ... sell_spkh(17) pk(18) sig(19) [20 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: mp(0) ... sell_spkh(15) pk(16) sig(17) [18 items]

    // Sig: Roll sig and pk to top, CheckSigVerify, then cleanup
    0x01, 0x11, 0x7a,             // push(1,17) OpRoll -> sig to top              [3B]
    // stack: sig(0) mp(1) ... sell_spkh(16) pk(17) [18 items]
    0x01, 0x11, 0x7a,             // push(1,17) OpRoll -> pk to top               [3B]
    // stack: pk(0) sig(1) mp(2) ... sell_spkh(17) [18 items]
    0xad,                         // OpCheckSigVerify                             [1B]
    // stack: mp(0) ... sell_spkh(15) [16 items]
    // Cleanup: drop 16 state items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8                [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8 (total 16)     [8B]

    // DISPATCH ELSE: sel >= 2 (paths 2,3,4,5,7 + fail)
    0x67,                         // OpElse                                       [1B]
    // stack: sel(0) mp(1) minp(2) ed_daa(3) mat_daa(4) grace(5) cf(6) kf(7) md(8) mn(9) ed(10) en(11) sz(12) dir(13) owner(14) buy_spkh(15) sell_spkh(16) [17 items]

    // Check sel < 5 to branch into atomic settle paths (2,3,4) vs paths 5,7
    0x76,                         // OpDup                                        [1B]
    0x55, 0x9f,                   // Op5 OpLessThan (sel < 5?)                    [2B]
    // stack: bool(0) sel(1) ... [18 items]
    0x63,                         // OpIf (sel < 5 -> atomic settle paths 2,3,4)  [1B]
    // stack: sel(0) mp(1) ... sell_spkh(16) [17 items]

    // SHARED ATOMIC SETTLE BLOCK (paths 2,3,4) — ~136B
    // sel is still on stack top. Save it for later path dispatch.
    // We need sel available after the shared block for path branching.

    // --- Spot Verification (16B) ---
    // Verify input[2].spk hash == spot_buy_spkh (d15 in 17-item stack)
    0x52, 0xbf,                   // Op2 OpTxInputSpk                             [2B]
    // stack: spk2(0) sel(1) mp(2) ... sell_spkh(17) [18 items]
    0xaa,                         // OpBlake2b                                    [1B]
    // stack: h2(0) sel(1) mp(2) ... sell_spkh(17) [18 items]
    0x01, 0x10, 0x79,             // push(1,16) OpPick -> buy_spkh (d15+1 = d16)  [3B]
    // stack: buy_c(0) h2(1) sel(2) ... sell_spkh(18) [19 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: sel(0) mp(1) ... sell_spkh(16) [17 items]

    // Verify input[3].spk hash == spot_sell_spkh (d16 in 17-item stack)
    0x53, 0xbf,                   // Op3 OpTxInputSpk                             [2B]
    // stack: spk3(0) sel(1) mp(2) ... sell_spkh(17) [18 items]
    0xaa,                         // OpBlake2b                                    [1B]
    // stack: h3(0) sel(1) mp(2) ... sell_spkh(17) [18 items]
    0x01, 0x11, 0x79,             // push(1,17) OpPick -> sell_spkh (d16+1 = d17) [3B]
    // stack: sell_c(0) h3(1) sel(2) ... sell_spkh(18) [19 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: sel(0) mp(1) ... sell_spkh(16) [17 items]

    // --- Read spot outputs (4B) ---
    0x52, 0xc2,                   // Op2 OpTxOutputAmount -> sk (seller_kas)      [2B]
    // stack: sk(0) sel(1) mp(2) ... [18 items]
    0x53, 0xc2,                   // Op3 OpTxOutputAmount -> bt (buyer_tokens)    [2B]
    // stack: bt(0) sk(1) sel(2) mp(3) ... [19 items]

    // --- Price bounds check (22B) ---
    // Verify min_price * bt <= sk  (cross-multiply: sk >= min_price * bt)
    // min_price is at d3 in original state = now d3+3 = d6 (sel,sk,bt above) ... no.
    // Let me recount stack: bt(0) sk(1) sel(2) mp(3) minp(4) ed_daa(5) ...
    // So minp is at d4, mp at d3.

    // Check: sk >= min_price * bt
    0x51, 0x79,                   // Op1 OpPick -> sk copy                        [2B]
    // stack: sk_c(0) bt(1) sk(2) sel(3) mp(4) minp(5) ... [20 items]
    0x55, 0x79,                   // Op5 OpPick -> minp (d5)                      [2B]
    // stack: minp_c(0) sk_c(1) bt(2) sk(3) sel(4) mp(5) minp(6) ... [21 items]
    0x52, 0x79,                   // Op2 OpPick -> bt copy                        [2B]
    // stack: bt_c(0) minp_c(1) sk_c(2) bt(3) ... [22 items]
    0x95,                         // OpMul -> minp * bt                           [1B]
    // stack: (minp*bt)(0) sk_c(1) bt(2) sk(3) ... [21 items]
    // GTE: pops b=(minp*bt), a=sk_c -> sk_c >= minp*bt
    0xa2, 0x69,                   // OpGTE OpVerify                               [2B]
    // stack: bt(0) sk(1) sel(2) mp(3) minp(4) ... [19 items]

    // Check: sk <= max_price * bt  (i.e., max_price * bt >= sk)
    0x51, 0x79,                   // Op1 OpPick -> sk copy                        [2B]
    // stack: sk_c(0) bt(1) sk(2) sel(3) mp(4) minp(5) ... [20 items]
    0x54, 0x79,                   // Op4 OpPick -> mp (d4)                        [2B]
    // stack: mp_c(0) sk_c(1) bt(2) sk(3) sel(4) mp(5) ... [21 items]
    0x52, 0x79,                   // Op2 OpPick -> bt copy                        [2B]
    // stack: bt_c(0) mp_c(1) sk_c(2) bt(3) ... [22 items]
    0x95,                         // OpMul -> mp * bt                             [1B]
    // stack: (mp*bt)(0) sk_c(1) bt(2) sk(3) ... [21 items]
    0x7c,                         // OpSwap                                       [1B]
    // stack: sk_c(0) (mp*bt)(1) bt(2) sk(3) ... [21 items]
    // GTE: pops b=sk_c, a=(mp*bt) -> mp*bt >= sk_c
    0xa2, 0x69,                   // OpGTE OpVerify                               [2B]
    // stack: bt(0) sk(1) sel(2) mp(3) minp(4) ... [19 items]

    // --- My margin (2B) ---
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> mm         [2B]
    // stack: mm(0) bt(1) sk(2) sel(3) mp(4) minp(5) ... [20 items]

    // --- Counter margin (5B) ---
    0xb9,                         // OpTxInputIndex -> self_idx                   [1B]
    // stack: si(0) mm(1) bt(2) sk(3) sel(4) ... [21 items]
    0x51, 0x7c, 0x94,             // Op1 OpSwap OpSub -> counter_idx = 1 - si     [3B]
    // stack: ci(0) mm(1) bt(2) sk(3) sel(4) ... [21 items]
    0xbe,                         // OpTxInputAmount -> cm                        [1B]
    // stack: cm(0) mm(1) bt(2) sk(3) sel(4) mp(5) minp(6) ed_daa(7) mat_daa(8) grace(9) cf(10) kf(11) md(12) mn(13) ed(14) en(15) sz(16) dir(17) owner(18) buy_spkh(19) sell_spkh(20) [21 items]

    // --- PnL computation (35B, 2 OpDiv) ---
    // Step 1: sk * ed
    0x53, 0x79,                   // Op3 OpPick -> sk (d3)                        [2B]
    // stack: sk_c(0) cm(1) mm(2) bt(3) sk(4) ... ed(15) ... [22 items]
    0x5f, 0x79,                   // Op15 OpPick -> ed (d14+1 = d15)              [2B]
    // stack: ed_c(0) sk_c(1) cm(2) mm(3) bt(4) ... [23 items]
    0x95,                         // OpMul -> sk * ed                             [1B]
    // stack: (sk*ed)(0) cm(1) mm(2) bt(3) sk(4) ... [22 items]

    // Step 2: en * bt
    0x01, 0x10, 0x79,             // push(1,16) OpPick -> en (original d10, now at d16)  [3B]
    // stack: en_c(0) (sk*ed)(1) cm(2) mm(3) bt(4) ... [23 items]
    0x54, 0x79,                   // Op4 OpPick -> bt (d4)                        [2B]
    // stack: bt_c(0) en_c(1) (sk*ed)(2) cm(3) mm(4) bt(5) ... [24 items]
    0x95,                         // OpMul -> en * bt                             [1B]
    // stack: (en*bt)(0) (sk*ed)(1) cm(2) mm(3) bt(4) ... [23 items]

    // Step 3: sk*ed - en*bt  (always in this order, negate for short)
    0x94,                         // OpSub -> (sk*ed) - (en*bt) = delta_raw       [1B]
    // stack: delta_raw(0) cm(1) mm(2) bt(3) sk(4) ... [22 items]
    // Direction branch: if short (dir==2), negate delta
    0x01, 0x12, 0x79,             // push(1,18) OpPick -> dir (original d12, now at d18 with 6 working items above)  [3B]
    // stack: dir(0) delta_raw(1) cm(2) ... [23 items]
    0x52, 0x87,                   // Op2 OpEqual (dir==2? short)                  [2B]
    // stack: bool(0) delta_raw(1) cm(2) ... [23 items]
    0x63,                         // OpIf (short)                                 [1B]
    0x00, 0x7c, 0x94,             // Op0 OpSwap OpSub -> negate delta             [3B]
    0x68,                         // OpEndIf                                      [1B]
    // stack: delta(0) cm(1) mm(2) bt(3) sk(4) sel(5) ... [22 items]

    // Step 4: delta / bt (first OpDiv)
    0x53, 0x79,                   // Op3 OpPick -> bt (d3)                        [2B]
    // stack: bt_c(0) delta(1) cm(2) mm(3) bt(4) ... [23 items]
    0x7c,                         // OpSwap                                       [1B]
    // stack: delta(0) bt_c(1) cm(2) mm(3) bt(4) ... [23 items]
    0x96,                         // OpDiv -> delta / bt = pnl_partial            [1B]
    // stack: pp(0) cm(1) mm(2) bt(3) sk(4) sel(5) ... [22 items]

    // Step 5: pnl_partial * sz
    0x01, 0x11, 0x79,             // push(1,17) OpPick -> sz (original d11, now at d17) [3B]
    // stack: sz_c(0) pp(1) cm(2) mm(3) bt(4) ... [23 items]
    0x95,                         // OpMul -> pp * sz                             [1B]
    // stack: (pp*sz)(0) cm(1) mm(2) bt(3) sk(4) sel(5) ... [22 items]

    // Step 6: / ed (second OpDiv)
    0x5f, 0x79,                   // Op15 OpPick -> ed (d14+1 = d15)              [2B]
    // stack: ed_c(0) (pp*sz)(1) cm(2) mm(3) ... [23 items]
    0x7c,                         // OpSwap                                       [1B]
    // stack: (pp*sz)(0) ed_c(1) cm(2) mm(3) ... [23 items]
    0x96,                         // OpDiv -> pnl = pp * sz / ed                  [1B]
    // stack: pnl(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) minp(7) ... [22 items]

    // --- Payout with floor/ceiling clamp (17B) ---
    // my_payout_raw = mm + pnl
    0x52, 0x79,                   // Op2 OpPick -> mm (d2)                        [2B]
    // stack: mm_c(0) pnl(1) cm(2) mm(3) bt(4) ... [23 items]
    0x93,                         // OpAdd -> mm + pnl = pay_raw                  [1B]
    // stack: pay_raw(0) cm(1) mm(2) bt(3) sk(4) sel(5) ... [22 items]

    // Floor clamp: max(0, pay_raw)
    // OpDup Op0 OpLessThan OpIf OpDrop Op0 OpEndIf
    0x76,                         // OpDup                                        [1B]
    0x00, 0x9f,                   // Op0 OpLessThan (pay_raw < 0?)                [2B]
    // stack: bool(0) pay_raw(1) cm(2) mm(3) ... [23 items]
    0x63, 0x75, 0x00, 0x68,       // OpIf OpDrop Op0 OpEndIf                      [4B]
    // stack: pay_clamped(0) cm(1) mm(2) bt(3) sk(4) sel(5) ... [22 items]

    // Ceiling clamp: min(pay, mm + cm - close_fee)
    // total_avail = mm + cm - cf
    0x51, 0x79,                   // Op1 OpPick -> cm (d1)                        [2B]
    // stack: cm_c(0) pay(1) cm(2) mm(3) bt(4) sk(5) sel(6) ... cf(12) ... [23 items]
    0x53, 0x79,                   // Op3 OpPick -> mm (d3)                        [2B]
    // stack: mm_c(0) cm_c(1) pay(2) cm(3) mm(4) ... cf(12) ... [24 items]
    0x93,                         // OpAdd -> cm + mm                             [1B]
    // stack: (cm+mm)(0) pay(1) cm(2) mm(3) bt(4) sk(5) sel(6) mp(7) minp(8) ... cf(12) ... [23 items]
    0x5c, 0x79,                   // Op12 OpPick -> cf (d12)                      [2B]
    // stack: cf_c(0) (cm+mm)(1) pay(2) ... [24 items]
    0x94,                         // OpSub -> total_avail = cm + mm - cf          [1B]
    // stack: avail(0) pay(1) cm(2) mm(3) bt(4) sk(5) sel(6) ... [23 items]
    // If pay > avail, use avail
    // OpDup Op2 OpPick OpGreaterThan OpIf OpSwap OpEndIf OpDrop
    0x76,                         // OpDup                                        [1B]
    // stack: avail(0) avail(1) pay(2) ... [24 items]
    0x52, 0x79,                   // Op2 OpPick -> pay copy                       [2B]
    // stack: pay_c(0) avail(1) avail(2) pay(3) ... [25 items]
    // If pay > avail -> swap so we pick avail
    0xa0,                         // OpGreaterThan (pay > avail?)                 [1B]
    // stack: bool(0) avail(1) pay(2) ... [24 items]
    0x63,                         // OpIf (pay > avail: ceiling hit)              [1B]
    0x7c,                         // OpSwap (put avail on top of pay)             [1B]
    0x68,                         // OpEndIf                                      [1B]
    // stack: result(0) discard(1) cm(2) mm(3) bt(4) sk(5) sel(6) ... [24 items]
    // result is min(pay, avail). Drop the other.
    0x7c, 0x75,                   // OpSwap OpDrop                                [2B]
    // stack: my_payout(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... [23 items]

    // Stack: my_payout(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) minp(7) ed_daa(8) mat_daa(9) grace(10) cf(11) kf(12) md(13) mn(14) ed(15) en(16) sz(17) dir(18) owner(19) buy_spkh(20) sell_spkh(21) [22 items]
    // Plus potential sig/pk below for path 2.

    // --- Path 3 dispatch (liquidation) ---
    0x55, 0x79,                   // Op5 OpPick -> sel (d5)                       [2B]
    // stack: sel_c(0) pay(1) cm(2) mm(3) bt(4) sk(5) sel(6) ... [23 items]
    0x53, 0x87,                   // Op3 OpEqual (sel==3?)                        [2B]
    // stack: bool(0) pay(1) cm(2) ... [23 items]
    0x63,                         // OpIf (path 3: liquidation)                   [1B]

    // PATH 3: LIQUIDATION (~50B)
    // Permissionless. Requires CLTV(grace_daa) and margin < threshold.
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) minp(7) ed_daa(8) mat_daa(9) grace(10) cf(11) kf(12) md(13) mn(14) ed(15) en(16) sz(17) dir(18) owner(19) buy_spkh(20) sell_spkh(21) [22 items]

    // CLTV: lockTime >= grace_daa
    0x5a, 0x79,                   // Op10 OpPick -> grace_daa (d10)               [2B]
    // stack: grace(0) pay(1) ... [23 items]
    0xb0,                         // OpCheckLockTimeVerify                        [1B]
    0x75,                         // OpDrop                                       [1B]
    // stack: pay(0) cm(1) mm(2) ... [22 items]

    // Threshold check: my_margin + pnl < threshold
    // threshold = (mm + cm) * maint_num / maint_den
    // We already have pay = mm + pnl (clamped). For threshold, we need
    // the unclamped remaining = mm + pnl. But pay IS the floor-clamped version.
    // Liquidation should check that the PRE-clamp value is below threshold.
    // The pre-clamp remaining = mm + pnl. If pay == 0 (floor clamped), remaining was negative -> definitely underwater.
    // If pay > 0, pay = remaining (no floor clamp was applied), so we check pay < threshold.
    // Actually: if floor clamp applied, pay=0 which is always < threshold (since threshold > 0).
    // So checking pay < threshold is valid in all cases.

    // Compute threshold = (mm + cm) * mn / md
    0x52, 0x79,                   // Op2 OpPick -> mm (d2)                        [2B]
    // stack: mm_c(0) pay(1) cm(2) mm(3) ... [23 items]
    0x52, 0x79,                   // Op2 OpPick -> cm (d2 after mm_c pushed)      [2B]
    // stack: cm_c(0) mm_c(1) pay(2) cm(3) mm(4) ... [24 items]
    0x93,                         // OpAdd -> mm + cm = total_margin              [1B]
    // stack: tm(0) pay(1) cm(2) mm(3) ... md(14) mn(15) ... [23 items]
    0x5f, 0x79,                   // Op15 OpPick -> mn (d15)                      [2B]
    // stack: mn_c(0) tm(1) pay(2) ... [24 items]
    0x95,                         // OpMul -> tm * mn                             [1B]
    // stack: (tm*mn)(0) pay(1) ... [23 items]
    0x5e, 0x79,                   // Op14 OpPick -> md (d14)                      [2B]
    // stack: md_c(0) (tm*mn)(1) pay(2) ... [24 items]
    0x96,                         // OpDiv -> threshold = tm * mn / md            [1B]
    // stack: thr(0) pay(1) cm(2) mm(3) ... [23 items]

    // Verify pay < threshold (party is underwater)
    // OpSwap OpLessThan OpVerify
    0x7c,                         // OpSwap                                       [1B]
    // stack: pay(0) thr(1) cm(2) mm(3) ... [23 items]
    0x9f, 0x69,                   // OpLessThan OpVerify (pay < threshold)        [2B]
    // stack: cm(0) mm(1) bt(2) sk(3) sel(4) mp(5) ... kf(11) ... [21 items]
    // (pay and thr both consumed)

    // Keeper fee output: keeper gets keeper_fee, rest goes to counterparty
    // Actually each UTXO is independent. Liquidation means this party
    // is underwater. The payout (after floor clamp) is 0 or very small.
    // The covenant doesn't need to route funds to the counterparty (the
    // counterparty's own covenant handles their payout).
    // Just verify output[self] >= 0 (trivially true for UTXOs).
    // But we DO need to verify the payout output exists and pays correctly.
    // Pay was already clamped to [0, avail]. For liquidation, pay ~ 0.
    // The covenant should just verify the output pays at least the clamped amount.

    // Output verification for liquidation:
    // output[self_idx].value >= my_payout (which is 0 or near-0)
    // Wait, payout was consumed above. Let me re-trace.
    // After pay < threshold verified, pay and thr are consumed.
    // We need to verify the output. But pay is gone!
    // Solution: before the threshold check, dup pay for output verification.

    // Actually, for liquidation the payout is effectively 0 (the party is
    // underwater). The important thing is that the covenant ALLOWS the spend.
    // Output verification is not needed for the liquidated party -- their
    // funds go to the counterparty via the counterparty's covenant.
    // The counterparty's covenant verifies THEIR payout >= their margin + |pnl|.

    // So for path 3: just verify underwater + CLTV, then cleanup. No output check needed.
    // Cleanup: 21 items remaining (cm, mm, bt, sk, sel, + 16 state items)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75,                      // OpDrop x5 (21 total) [5B]

    // PATHS 2 and 4 (after path 3 OpElse)
    0x67,                         // OpElse (not path 3 -> paths 2 or 4)         [1B]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... [22 items]
    // For path 2: pk(22) sig(23) below state
    // For path 4: nothing extra below state

    // --- Shared output verification for paths 2 and 4 (25B) ---
    // Verify output[self_idx].value >= my_payout
    0xb9, 0xc2,                   // OpTxInputIndex OpTxOutputAmount -> out_val   [2B]
    // stack: out_val(0) pay(1) cm(2) mm(3) bt(4) sk(5) sel(6) ... [23 items]
    0x51, 0x79,                   // Op1 OpPick -> pay copy                       [2B]
    // stack: pay_c(0) out_val(1) pay(2) cm(3) ... [24 items]
    // GTE: pops b=pay_c, a=out_val -> out_val >= pay_c
    0x7c,                         // OpSwap                                       [1B]
    // stack: out_val(0) pay_c(1) pay(2) cm(3) ... [24 items]
    0xa2, 0x69,                   // OpGTE OpVerify                               [2B]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... owner(19) ... [22 items]

    // Verify output[self_idx].spk hash == owner_spk_hash
    0xb9, 0xc3,                   // OpTxInputIndex OpTxOutputSpk                 [2B]
    // stack: out_spk(0) pay(1) cm(2) ... owner(20) ... [23 items]
    0xaa,                         // OpBlake2b                                    [1B]
    // stack: h_out(0) pay(1) cm(2) ... owner(20) ... [23 items]
    // owner is at d19+1=d20 (19 in 22-item stack + 1 for h_out)
    0x01, 0x14, 0x79,             // push(1,20) OpPick -> owner (d20)             [3B]
    // stack: owner_c(0) h_out(1) pay(2) cm(3) ... [24 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... [22 items]

    // --- Path 2 vs Path 4 dispatch ---
    0x55, 0x79,                   // Op5 OpPick -> sel (d5)                       [2B]
    // stack: sel_c(0) pay(1) cm(2) ... [23 items]
    0x52, 0x87,                   // Op2 OpEqual (sel==2?)                        [2B]
    // stack: bool(0) pay(1) cm(2) ... [23 items]
    0x63,                         // OpIf (path 2: unilateral close)              [1B]

    // PATH 2: UNILATERAL CLOSE (~28B)
    // Owner sig required. Sigscript: [sig 65B][pk 32B][Op2][pushData(RS)]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... sell_spkh(21) pk(22) sig(23) [24 items]
    //
    // Identity: Blake2b(pk) == owner_spk_hash
    // owner at d19 in 22-item stack. pk at d22 in 24-item stack.
    // From current perspective (22 items + 2 sigscript below = 24 effective):
    // Wait: pay(0)..sell_spkh(21) = 22 items. pk is at d22, sig at d23.
    0x01, 0x16, 0x79,             // push(1,22) OpPick -> pk (d22)                [3B]
    // stack: pk_c(0) pay(1) ... pk(23) sig(24) [25 items]
    0xaa,                         // OpBlake2b -> hash(pk)                        [1B]
    // stack: h(0) pay(1) ... [25 items]
    // owner: pay(1) cm(2) mm(3) bt(4) sk(5) sel(6) mp(7) minp(8) ed_daa(9) mat_daa(10) grace(11) cf(12) kf(13) md(14) mn(15) ed(16) en(17) sz(18) dir(19) owner(20)
    // d20 in 25-item stack
    0x01, 0x14, 0x79,             // push(1,20) OpPick -> owner (d20)             [3B]
    // stack: owner_c(0) h(1) pay(2) ... [26 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... sell_spkh(21) pk(22) sig(23) [24 items]

    // Sig check: roll sig and pk to top
    0x01, 0x17, 0x7a,             // push(1,23) OpRoll -> sig to top              [3B]
    // stack: sig(0) pay(1) ... sell_spkh(22) pk(23) [24 items]
    0x01, 0x17, 0x7a,             // push(1,23) OpRoll -> pk to top               [3B]
    // stack: pk(0) sig(1) pay(2) ... sell_spkh(23) [24 items]
    0xad,                         // OpCheckSigVerify                             [1B]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... sell_spkh(21) [22 items]

    // Cleanup: 22 items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,               // OpDrop x6 (22 total) [6B]

    // PATH 4: MATURITY SETTLE (~14B)
    0x67,                         // OpElse (path 4)                              [1B]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) minp(7) ed_daa(8) mat_daa(9) grace(10) cf(11) kf(12) ... sell_spkh(21) [22 items]
    // sel should be 4 (verified below for safety, but actually dispatch already ensures sel is 2 or 4 here)

    // CLTV: lockTime >= maturity_daa
    // mat_daa is at d9
    0x59, 0x79,                   // Op9 OpPick -> mat_daa (d9)                   [2B]
    // stack: mat(0) pay(1) ... [23 items]
    0xb0,                         // OpCheckLockTimeVerify                        [1B]
    0x75,                         // OpDrop                                       [1B]
    // stack: pay(0) cm(1) mm(2) bt(3) sk(4) sel(5) mp(6) ... sell_spkh(21) [22 items]

    // Cleanup: 22 items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,               // OpDrop x6 (22 total) [6B]

    0x68,                         // OpEndIf (path 2 vs 4)                        [1B]
    0x68,                         // OpEndIf (path 3 vs 2/4)                      [1B]

    // DISPATCH ELSE: sel >= 5 (paths 5, 7 + fail)
    0x67,                         // OpElse (sel >= 5: paths 5, 7, fail)          [1B]
    // Stack: sel(0) mp(1) ... sell_spkh(16) [17 items]
    // Paths 2/3/4 took the IF branch and cleaned up; this ELSE branch
    // is only reached when sel >= 5.

    // Check sel == 5 (add margin)
    0x76,                         // OpDup                                        [1B]
    0x55, 0x87,                   // Op5 OpEqual (sel==5?)                        [2B]
    // stack: bool(0) sel(1) mp(2) ... [18 items]
    0x63,                         // OpIf (path 5: add margin)                    [1B]
    0x75,                         // OpDrop (sel)                                 [1B]
    // stack: mp(0) minp(1) ed_daa(2) mat_daa(3) grace(4) cf(5) kf(6) md(7) mn(8) ed(9) en(10) sz(11) dir(12) owner(13) buy_spkh(14) sell_spkh(15) [16 items]
    // Sigscript: [sig 65B][pk 32B][Op5][pushData(RS)]
    // pk at d16, sig at d17

    // PATH 5: ADD MARGIN — self-continuation (40B)
    // V1: Self-continuation: output[0].spk == input[self].spk
    0x00, 0xc3,                   // Op0 OpTxOutputSpk                            [2B]
    // stack: out_spk(0) mp(1) ... sell_spkh(16) pk(17) sig(18) [19 items]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk                  [2B]
    // stack: in_spk(0) out_spk(1) mp(2) ... [20 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: mp(0) ... sell_spkh(15) pk(16) sig(17) [18 items]

    // V2: Value increase: output[0].value >= input[self].value
    0x00, 0xc2,                   // Op0 OpTxOutputAmount                         [2B]
    // stack: out_val(0) mp(1) ... pk(17) sig(18) [19 items]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount               [2B]
    // stack: in_val(0) out_val(1) mp(2) ... [20 items]
    // GTE: pops b=in_val, a=out_val -> out_val >= in_val
    0xa2, 0x69,                   // OpGTE OpVerify                               [2B]
    // stack: mp(0) ... sell_spkh(15) pk(16) sig(17) [18 items]

    // Identity: Blake2b(pk) == owner_spk_hash
    0x01, 0x10, 0x79,             // push(1,16) OpPick -> pk (d16)                [3B]
    // stack: pk_c(0) mp(1) ... sell_spkh(16) pk(17) sig(18) [19 items]
    0xaa,                         // OpBlake2b                                    [1B]
    // stack: h(0) mp(1) ... [19 items]
    0x5e, 0x79,                   // Op14 OpPick -> owner (d13+1=d14)             [2B]
    // stack: owner_c(0) h(1) mp(2) ... [20 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: mp(0) ... sell_spkh(15) pk(16) sig(17) [18 items]

    // Sig check: roll sig and pk to top
    0x01, 0x11, 0x7a,             // push(1,17) OpRoll -> sig to top              [3B]
    // stack: sig(0) mp(1) ... sell_spkh(16) pk(17) [18 items]
    0x01, 0x11, 0x7a,             // push(1,17) OpRoll -> pk to top               [3B]
    // stack: pk(0) sig(1) mp(2) ... sell_spkh(17) [18 items]
    0xad,                         // OpCheckSigVerify                             [1B]
    // stack: mp(0) ... sell_spkh(15) [16 items]

    // Cleanup: 16 state items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8 (16 total) [8B]

    // PATH 7 + FAIL PATHS
    0x67,                         // OpElse (sel != 5)                            [1B]
    // stack: sel(0) mp(1) ... sell_spkh(16) [17 items]
    0x76,                         // OpDup                                        [1B]
    0x57, 0x87,                   // Op7 OpEqual (sel==7?)                        [2B]
    // stack: bool(0) sel(1) mp(2) ... [18 items]
    0x63,                         // OpIf (path 7: emergency timeout)             [1B]
    0x75,                         // OpDrop (sel)                                 [1B]
    // stack: mp(0) ... sell_spkh(15) [16 items]

    // PATH 7: EMERGENCY TIMEOUT (~32B)
    // CLTV: lockTime >= emergency_daa (d2)
    0x52, 0x79,                   // Op2 OpPick -> emergency_daa (d2)             [2B]
    // stack: ed_daa(0) mp(1) ... [17 items]
    0xb0,                         // OpCheckLockTimeVerify                        [1B]
    0x75,                         // OpDrop                                       [1B]
    // stack: mp(0) ... sell_spkh(15) [16 items]

    // Verify output[self_idx].value >= input[self_idx].value
    0xb9, 0xc2,                   // OpTxInputIndex OpTxOutputAmount              [2B]
    // stack: out_val(0) mp(1) ... [17 items]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount               [2B]
    // stack: in_val(0) out_val(1) mp(2) ... [18 items]
    // GTE: pops b=in_val, a=out_val -> out_val >= in_val
    0xa2, 0x69,                   // OpGTE OpVerify                               [2B]
    // stack: mp(0) ... sell_spkh(15) [16 items]

    // Verify output[self_idx].spk hash == owner_spk_hash
    0xb9, 0xc3,                   // OpTxInputIndex OpTxOutputSpk                 [2B]
    // stack: out_spk(0) mp(1) ... owner(14) ... [17 items]
    0xaa,                         // OpBlake2b                                    [1B]
    // stack: h(0) mp(1) ... owner(14) ... [17 items]
    0x5e, 0x79,                   // Op14 OpPick -> owner (d13+1=d14)             [2B]
    // stack: owner_c(0) h(1) mp(2) ... [18 items]
    0x87, 0x69,                   // OpEqual OpVerify                             [2B]
    // stack: mp(0) ... sell_spkh(15) [16 items]

    // Cleanup: 16 state items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8            [8B]
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8 (16 total) [8B]

    // FAIL PATHS (sel 6, 8, 9 or anything else)
    0x67,                         // OpElse (sel != 7 -> fail)                    [1B]
    0x00, 0x69,                   // Op0 OpVerify -> immediate fail               [2B]

    // CLOSING: EndIf cascade + Op1
    0x68,                         // OpEndIf (sel==7 vs fail)                     [1B]
    0x68,                         // OpEndIf (sel==5 vs rest)                     [1B]
    0x68,                         // OpEndIf (sel<5 vs >=5)                       [1B]
    0x68,                         // OpEndIf (sel<2 vs >=2)                       [1B]
    0x51,                         // Op1 (TRUE)                                   [1B]
];

// perp_position redeemScript builder

/// Build perp_position redeemScript (216B state + body).
///
/// # Arguments
/// * `owner_spk_hash`  - 32B Blake2b hash of owner's SPK
/// * `spot_sell_spkh`  - 32B Blake2b hash of BuySell v13 sell RS SPK
/// * `spot_buy_spkh`   - 32B Blake2b hash of BuySell v13 buy RS SPK
/// * `direction`       - 1 = long, 2 = short
/// * `size`            - Position size (units depend on pair configuration)
/// * `entry_num`       - Entry price numerator (GCD-normalized with entry_den)
/// * `entry_den`       - Entry price denominator
/// * `maint_pct_num`   - Maintenance margin % numerator
/// * `maint_pct_den`   - Maintenance margin % denominator
/// * `keeper_fee`      - Keeper fee for liquidation incentive (sompi)
/// * `close_fee`       - Fixed close fee (sompi)
/// * `grace_daa`       - Absolute DAA score after which liquidation is allowed
/// * `maturity_daa`    - DAA score at which maturity settle becomes available
/// * `emergency_daa`   - DAA score after which emergency close is allowed
/// * `min_price`       - Minimum price bound (cross-multiplied with bt)
/// * `max_price`       - Maximum price bound
///
/// # Panics
/// Panics on invalid parameters.
pub fn build_perp_position_redeem_script(
    owner_spk_hash: &[u8; 32],
    spot_sell_spkh: &[u8; 32],
    spot_buy_spkh: &[u8; 32],
    direction: u64,
    size: u64,
    entry_num: u64,
    entry_den: u64,
    maint_pct_num: u64,
    maint_pct_den: u64,
    keeper_fee: u64,
    close_fee: u64,
    grace_daa: u64,
    maturity_daa: u64,
    emergency_daa: u64,
    min_price: u64,
    max_price: u64,
) -> Vec<u8> {
    assert!(direction == 1 || direction == 2, "direction must be 1 (long) or 2 (short)");
    assert!(entry_num > 0, "entry_num must be > 0");
    assert!(entry_den > 0, "entry_den must be > 0");
    assert!(size > 0, "size must be > 0");
    assert!(maint_pct_num > 0, "maint_pct_num must be > 0");
    assert!(maint_pct_den > 0, "maint_pct_den must be > 0");
    assert!(
        maint_pct_num * 2 < maint_pct_den,
        "maintenance percentage must be < 50% (maint_pct_num * 2 must be < maint_pct_den)"
    );
    assert!(grace_daa > 0, "grace_daa must be > 0");
    assert!(maturity_daa > 0, "maturity_daa must be > 0");
    assert!(emergency_daa > 0, "emergency_daa must be > 0");
    assert!(grace_daa < maturity_daa, "grace_daa must be < maturity_daa");
    assert!(maturity_daa < emergency_daa, "maturity_daa must be < emergency_daa");
    assert!(min_price > 0, "min_price must be > 0");
    assert!(max_price > 0, "max_price must be > 0");
    assert!(min_price <= max_price, "min_price must be <= max_price");
    assert!(
        (max_price as i128).checked_mul(size as i128).is_some_and(|v| v <= i64::MAX as i128),
        "max_price * size would overflow i64 — reduce max_price or position size"
    );
    assert!(
        (max_price as i128).checked_mul(entry_den as i128).is_some_and(|v| v <= i64::MAX as i128),
        "max_price * entry_den would overflow i64 — reduce values"
    );

    // GCD-normalize entry price
    let g = gcd(entry_num, entry_den);
    let en = entry_num / g;
    let ed = entry_den / g;

    // GCD-normalize maintenance percentage
    let gm = gcd(maint_pct_num, maint_pct_den);
    let mn = maint_pct_num / gm;
    let md = maint_pct_den / gm;

    let body = PERP_POSITION_BODY;
    let mut rs = Vec::with_capacity(PERP_POSITION_STATE_SIZE + body.len());

    // State: pushed in order, first push = deepest on stack
    // d15 = spot_sell_spkh (deepest)
    rs.push(0x20);
    rs.extend_from_slice(spot_sell_spkh);      // d15
    // d14 = spot_buy_spkh
    rs.push(0x20);
    rs.extend_from_slice(spot_buy_spkh);       // d14
    // d13 = owner_spk_hash
    rs.push(0x20);
    rs.extend_from_slice(owner_spk_hash);      // d13
    // d12 = direction
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(direction));   // d12
    // d11 = size
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(size));        // d11
    // d10 = entry_num (GCD-normalized)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(en));          // d10
    // d9 = entry_den (GCD-normalized)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(ed));          // d9
    // d8 = maint_pct_num (GCD-normalized)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(mn));          // d8
    // d7 = maint_pct_den (GCD-normalized)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(md));          // d7
    // d6 = keeper_fee
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(keeper_fee));  // d6
    // d5 = close_fee
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(close_fee));   // d5
    // d4 = grace_daa
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(grace_daa));   // d4
    // d3 = maturity_daa
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(maturity_daa)); // d3
    // d2 = emergency_daa
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(emergency_daa)); // d2
    // d1 = min_price
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_price));   // d1
    // d0 = max_price (top of stack)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_price));   // d0

    rs.extend_from_slice(body);
    rs
}

// perp_position sigscript builders

/// Build perp_position cancel sigscript (selector=1):
/// `[sig 65B][pk 32B][Op1][pushData(RS)]`
///
/// Owner reclaims margin. No co-spend required.
pub fn build_perp_cancel_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_hashtype = Vec::with_capacity(65);
    sig_with_hashtype.extend_from_slice(sig);
    sig_with_hashtype.push(0x01);

    let mut ss = Vec::with_capacity(100 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_hashtype));
    ss.extend_from_slice(&push_data(pk));
    ss.push(0x51); // Op1 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build perp_position unilateral close sigscript (selector=2):
/// `[sig 65B][pk 32B][Op2][pushData(RS)]`
///
/// Atomic settle with spot co-spend. Owner signature required.
pub fn build_perp_unilateral_close_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_hashtype = Vec::with_capacity(65);
    sig_with_hashtype.extend_from_slice(sig);
    sig_with_hashtype.push(0x01);

    let mut ss = Vec::with_capacity(100 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_hashtype));
    ss.extend_from_slice(&push_data(pk));
    ss.push(0x52); // Op2 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build perp_position liquidation sigscript (selector=3):
/// `[Op3][pushData(RS)]`
///
/// Permissionless. TX lockTime >= grace_daa required.
pub fn build_perp_liquidation_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x53); // Op3 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build perp_position maturity settle sigscript (selector=4):
/// `[Op4][pushData(RS)]`
///
/// Permissionless. TX lockTime >= maturity_daa required.
pub fn build_perp_maturity_settle_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x54); // Op4 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build perp_position add margin sigscript (selector=5):
/// `[sig 65B][pk 32B][Op5][pushData(RS)]`
///
/// Self-continuation. Output[0] value must be >= input value.
pub fn build_perp_add_margin_sigscript(
    sig: &[u8; 64],
    pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_hashtype = Vec::with_capacity(65);
    sig_with_hashtype.extend_from_slice(sig);
    sig_with_hashtype.push(0x01);

    let mut ss = Vec::with_capacity(100 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_hashtype));
    ss.extend_from_slice(&push_data(pk));
    ss.push(0x55); // Op5 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build perp_position emergency timeout sigscript (selector=7):
/// `[Op7][pushData(RS)]`
///
/// Permissionless. TX lockTime >= emergency_daa required.
pub fn build_perp_emergency_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x57); // Op7 = selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Compute deterministic SPK hashes for the canonical settlement spot orders.
///
/// The perp position RS embeds `spot_sell_spkh` and `spot_buy_spkh` so that
/// atomic settlement paths (2, 3, 4) can verify co-spent spot order UTXOs.
/// These hashes must match the P2SH SPK of the spot buy/sell orders that
/// will be co-spent at settlement time.
///
/// The matcher creates "settlement spot orders" with canonical, deterministic
/// parameters at settlement time. Since the RS construction is deterministic,
/// the SPK hashes can be computed at position-open time and embedded in the
/// position RS. At settlement, the matcher deploys (or reuses) spot orders
/// built with the same canonical parameters.
///
/// # Arguments
/// * `token_cov_id`    - 32B covenant ID of the token being traded
/// * `entry_price_num` - Entry price numerator (will be GCD-normalized)
/// * `entry_price_den` - Entry price denominator
/// * `matcher_spk_hash`- 32B Blake2b hash of the matcher's SPK
///
/// # Returns
/// `(spot_sell_spkh, spot_buy_spkh)` — both are `[u8; 32]`.
///
/// Returns `None` if the canonical RS construction fails (e.g., zero price).
pub fn compute_settlement_spot_spk_hashes(
    token_cov_id: &[u8; 32],
    entry_price_num: u64,
    entry_price_den: u64,
    matcher_spk_hash: &[u8; 32],
) -> Option<([u8; 32], [u8; 32])> {
    // Canonical parameters for settlement spot orders:
    //   - price = entry price (matches the position's entry)
    //   - min_fill = 1 (minimal, allows any fill amount)
    //   - owner_hash = matcher (matcher controls the settlement orders)
    //   - buyer/seller_spk_hash = matcher (matcher receives proceeds)
    //   - max_matcher_fee = u64::MAX (no fee restriction)
    //   - cancel_pending = 0 (fillable)
    //   - expiry_daa = 0 (GTC, no expiry)
    use crate::contract::spot::order::{build_buy_redeem_script, build_sell_redeem_script};

    let buy_rs = build_buy_redeem_script(
        token_cov_id,
        entry_price_num,
        entry_price_den,
        1,                  // min_fill
        matcher_spk_hash,   // owner_hash
        matcher_spk_hash,   // buyer_spk_hash
        u64::MAX,           // max_matcher_fee
        0,                  // cancel_pending
        0,                  // expiry_daa
    ).ok()?;

    let sell_rs = build_sell_redeem_script(
        entry_price_num,
        entry_price_den,
        1,                  // min_fill
        matcher_spk_hash,   // owner_hash
        matcher_spk_hash,   // seller_spk_hash
        u64::MAX,           // max_matcher_fee
        0,                  // cancel_pending
        0,                  // expiry_daa
    ).ok()?;

    let buy_p2sh = crate::build_p2sh(&buy_rs);
    let sell_p2sh = crate::build_p2sh(&sell_rs);

    let spot_buy_spkh = crate::compute_spk_hash(0, buy_p2sh.script());
    let spot_sell_spkh = crate::compute_spk_hash(0, sell_p2sh.script());

    Some((spot_sell_spkh, spot_buy_spkh))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero32() -> [u8; 32] {
        [0u8; 32]
    }

    fn sample_hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// push_data overhead: 1B for <=75, 2B for <=255, 3B for >255.
    fn push_overhead(data_len: usize) -> usize {
        if data_len <= 75 { 1 }
        else if data_len <= 255 { 2 }
        else { 3 }
    }

    // perp_position tests

    fn default_position_rs() -> Vec<u8> {
        build_perp_position_redeem_script(
            &sample_hash(0xAA),     // owner_spk_hash
            &sample_hash(0xBB),     // spot_sell_spkh
            &sample_hash(0xCC),     // spot_buy_spkh
            1,                      // direction = long
            1_000_000,              // size
            100, 1,                 // entry_num/den
            5, 100,                 // maint 5%
            3_000_000,              // keeper_fee
            0,                      // close_fee
            200_000,                // grace_daa
            500_000,                // maturity_daa
            1_000_000,              // emergency_daa
            1,                      // min_price
            10_000,                 // max_price
        )
    }

    // --- Body snapshot & structure ---

    #[test]
    fn perp_position_body_snapshot_length() {
        let len = PERP_POSITION_BODY.len();
        assert_eq!(len, PERP_BODY_EXPECTED_LEN,
            "position body length changed from expected {PERP_BODY_EXPECTED_LEN} to {len}");
    }

    #[test]
    fn perp_position_body_reasonable_size() {
        let len = PERP_POSITION_BODY.len();
        assert!(len > 200, "position body too small: {len}");
        assert!(len < 500, "position body too large: {len}");
    }

    #[test]
    fn perp_position_body_starts_with_dispatch() {
        assert_eq!(PERP_POSITION_BODY[0], 0x01, "position dispatch: push(1,...) = 0x01");
        assert_eq!(PERP_POSITION_BODY[1], 0x10, "position dispatch: 0x10 = 16 state items");
        assert_eq!(PERP_POSITION_BODY[2], 0x7a, "position dispatch: OpRoll");
    }

    #[test]
    fn perp_position_body_ends_with_true() {
        let body = PERP_POSITION_BODY;
        let len = body.len();
        assert_eq!(body[len - 1], 0x51, "last byte must be Op1 (TRUE)");
    }

    #[test]
    fn perp_position_body_if_else_endif_balanced() {
        let body = PERP_POSITION_BODY;
        let ifs = body.iter().filter(|&&b| b == 0x63).count();
        let endifs = body.iter().filter(|&&b| b == 0x68).count();
        assert_eq!(ifs, endifs, "OpIf count ({ifs}) must equal OpEndIf count ({endifs})");
    }

    #[test]
    fn perp_position_body_contains_two_opdiv() {
        let body = PERP_POSITION_BODY;
        let div_count = body.iter().filter(|&&b| b == 0x96).count();
        // PnL: 2 OpDiv (sk*ed/bt, then *sz/ed) + liquidation threshold: 1 OpDiv = 3 total
        assert!(div_count >= 2, "position must have >= 2 OpDiv for PnL computation, got {div_count}");
    }

    #[test]
    fn perp_position_body_contains_two_cltv() {
        let body = PERP_POSITION_BODY;
        let cltv_count = body.iter().filter(|&&b| b == 0xb0).count();
        // Path 3 (grace_daa) + Path 4 (maturity_daa) + Path 7 (emergency_daa) = 3
        assert_eq!(cltv_count, 3, "position must have exactly 3 OpCheckLockTimeVerify, got {cltv_count}");
    }

    #[test]
    fn perp_position_body_contains_checksigverify() {
        let body = PERP_POSITION_BODY;
        let csv_count = body.iter().filter(|&&b| b == 0xad).count();
        // Path 1 (cancel) + Path 2 (unilateral) + Path 5 (add margin) = 3
        assert_eq!(csv_count, 3, "position must have exactly 3 OpCheckSigVerify, got {csv_count}");
    }

    #[test]
    fn perp_position_body_contains_blake2b() {
        let body = PERP_POSITION_BODY;
        let blake_count = body.iter().filter(|&&b| b == 0xaa).count();
        // Spot verify: 2 (input[2].spk, input[3].spk)
        // Path 1 cancel identity: 1
        // Shared output verify: 1
        // Path 2 identity: 1
        // Path 5 identity: 1
        // Path 7 output verify: 1
        assert!(blake_count >= 7, "position must have >= 7 OpBlake2b, got {blake_count}");
    }

    #[test]
    fn perp_position_body_contains_self_continuation() {
        let body = PERP_POSITION_BODY;
        // Path 5 self-continuation: Op0 OpTxOutputSpk OpTxInputIndex OpTxInputSpk OpEqual OpVerify
        let pattern = [0x00, 0xc3, 0xb9, 0xbf, 0x87, 0x69];
        let count = body.windows(pattern.len()).filter(|w| *w == pattern).count();
        assert_eq!(count, 1, "position must have exactly 1 self-continuation (path 5), got {count}");
    }

    #[test]
    fn perp_position_body_contains_fail_path() {
        let body = PERP_POSITION_BODY;
        // Op0 OpVerify (immediate fail) pattern
        let fail_pattern = [0x00, 0x69];
        let found = body.windows(2).any(|w| w == fail_pattern);
        assert!(found, "position must contain Op0 OpVerify for fail paths (sel 6,8,9)");
    }

    // --- Position State size & RS tests ---

    #[test]
    fn perp_position_state_size_computation() {
        // 3 hashes: 3 * (1 + 32) = 99
        // 13 u64s: 13 * (1 + 8)  = 117
        // Total: 216
        assert_eq!(33 * 3 + 9 * 13, 216);
        assert_eq!(PERP_POSITION_STATE_SIZE, 216);
    }

    #[test]
    fn perp_position_rs_length() {
        let rs = default_position_rs();
        let expected = PERP_POSITION_STATE_SIZE + PERP_POSITION_BODY.len();
        assert_eq!(rs.len(), expected,
            "position RS = {PERP_POSITION_STATE_SIZE}B state + {}B body = {expected}B, got {}",
            PERP_POSITION_BODY.len(), rs.len());
    }

    #[test]
    fn perp_position_rs_body_appended_correctly() {
        let rs = default_position_rs();
        assert_eq!(&rs[PERP_POSITION_STATE_SIZE..], PERP_POSITION_BODY);
    }

    #[test]
    fn perp_position_rs_state_layout() {
        let owner = sample_hash(0xAA);
        let sell_spkh = sample_hash(0xBB);
        let buy_spkh = sample_hash(0xCC);
        let rs = build_perp_position_redeem_script(
            &owner, &sell_spkh, &buy_spkh,
            2,                   // direction = short
            500_000,             // size
            200, 2,              // entry_num/den (GCD -> 100/1)
            5, 100,              // maint 5%
            3_000_000,           // keeper_fee
            100_000,             // close_fee
            100_000,             // grace_daa
            3_000_000,           // maturity_daa
            5_000_000,           // emergency_daa
            50,                  // min_price
            1_000_000_000,       // max_price
        );

        let mut off = 0;
        // d15 = spot_sell_spkh
        assert_eq!(rs[off], 0x20); off += 1;
        assert_eq!(&rs[off..off + 32], &sell_spkh); off += 32;
        // d14 = spot_buy_spkh
        assert_eq!(rs[off], 0x20); off += 1;
        assert_eq!(&rs[off..off + 32], &buy_spkh); off += 32;
        // d13 = owner_spk_hash
        assert_eq!(rs[off], 0x20); off += 1;
        assert_eq!(&rs[off..off + 32], &owner); off += 32;
        // d12 = direction
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 2); off += 8;
        // d11 = size
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 500_000); off += 8;
        // d10 = entry_num (GCD: 200/2 -> 100/1)
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 100); off += 8;
        // d9 = entry_den
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 1); off += 8;
        // d8 = maint_pct_num (5/100 -> 1/20)
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 1); off += 8;
        // d7 = maint_pct_den
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 20); off += 8;
        // d6 = keeper_fee
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 3_000_000); off += 8;
        // d5 = close_fee
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 100_000); off += 8;
        // d4 = grace_daa
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 100_000); off += 8;
        // d3 = maturity_daa
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 3_000_000); off += 8;
        // d2 = emergency_daa
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 5_000_000); off += 8;
        // d1 = min_price
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 50); off += 8;
        // d0 = max_price
        assert_eq!(rs[off], 0x08); off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off + 8].try_into().unwrap()), 1_000_000_000); off += 8;
        // Body starts
        assert_eq!(off, PERP_POSITION_STATE_SIZE);
        assert_eq!(&rs[off..], PERP_POSITION_BODY);
    }

    // --- GCD normalization ---

    #[test]
    fn perp_position_rs_gcd_normalization() {
        let z = zero32();
        let rs1 = build_perp_position_redeem_script(
            &z, &z, &z, 1, 1_000_000, 600, 300, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1, 1_000_000_000,
        );
        let rs2 = build_perp_position_redeem_script(
            &z, &z, &z, 1, 1_000_000, 2, 1, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1, 1_000_000_000,
        );
        assert_eq!(rs1, rs2, "GCD normalization: 600/300 == 2/1");
    }

    // --- Builder validation ---

    #[test]
    #[should_panic(expected = "direction must be 1 (long) or 2 (short)")]
    fn perp_position_rejects_bad_direction() {
        let z = zero32();
        build_perp_position_redeem_script(
            &z, &z, &z, 3, 1_000_000, 100, 1, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1, 10_000,
        );
    }

    #[test]
    #[should_panic(expected = "entry_num must be > 0")]
    fn perp_position_rejects_zero_entry_num() {
        let z = zero32();
        build_perp_position_redeem_script(
            &z, &z, &z, 1, 1_000_000, 0, 1, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1, 10_000,
        );
    }

    #[test]
    #[should_panic(expected = "size must be > 0")]
    fn perp_position_rejects_zero_size() {
        let z = zero32();
        build_perp_position_redeem_script(
            &z, &z, &z, 1, 0, 100, 1, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1, 10_000,
        );
    }

    #[test]
    #[should_panic(expected = "grace_daa must be < maturity_daa")]
    fn perp_position_rejects_grace_equals_maturity() {
        let z = zero32();
        build_perp_position_redeem_script(
            &z, &z, &z, 1, 1_000_000, 100, 1, 5, 100, 3_000_000,
            0, 500_000, 500_000, 1_000_000, 1, 10_000,
        );
    }

    #[test]
    #[should_panic(expected = "min_price must be <= max_price")]
    fn perp_position_rejects_min_exceeds_max_price() {
        let z = zero32();
        build_perp_position_redeem_script(
            &z, &z, &z, 1, 1_000_000, 100, 1, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1000, 999,
        );
    }

    #[test]
    fn perp_position_accepts_both_directions() {
        let z = zero32();
        let rs_long = build_perp_position_redeem_script(
            &z, &z, &z, 1, 1_000_000, 100, 1, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1, 10_000,
        );
        let rs_short = build_perp_position_redeem_script(
            &z, &z, &z, 2, 1_000_000, 100, 1, 5, 100, 3_000_000,
            0, 100, 500_000, 1_000_000, 1, 10_000,
        );
        // Same body, different state (direction differs)
        assert_eq!(&rs_long[PERP_POSITION_STATE_SIZE..], &rs_short[PERP_POSITION_STATE_SIZE..],
            "long and short should share the same body");
        assert_ne!(rs_long, rs_short, "long and short RS should differ (direction)");
    }

    // --- Sigscript tests ---

    #[test]
    fn perp_position_cancel_sigscript_structure() {
        let sig = [0xAAu8; 64];
        let pk = [0xBBu8; 32];
        let rs = default_position_rs();
        let ss = build_perp_cancel_sigscript(&sig, &pk, &rs);
        assert_eq!(ss[0], 65); // sig push prefix
        assert_eq!(ss[65], 0x01); // sighash
        assert_eq!(ss[66], 32); // pk push prefix
        assert_eq!(&ss[67..99], &pk);
        assert_eq!(ss[99], 0x51, "cancel selector must be Op1");
    }

    #[test]
    fn perp_position_unilateral_sigscript_structure() {
        let sig = [0xAAu8; 64];
        let pk = [0xBBu8; 32];
        let rs = default_position_rs();
        let ss = build_perp_unilateral_close_sigscript(&sig, &pk, &rs);
        assert_eq!(ss[0], 65);
        assert_eq!(ss[65], 0x01);
        assert_eq!(ss[66], 32);
        assert_eq!(&ss[67..99], &pk);
        assert_eq!(ss[99], 0x52, "unilateral selector must be Op2");
    }

    #[test]
    fn perp_position_liquidation_sigscript_structure() {
        let rs = default_position_rs();
        let ss = build_perp_liquidation_sigscript(&rs);
        assert_eq!(ss[0], 0x53, "liquidation selector must be Op3");
    }

    #[test]
    fn perp_position_maturity_sigscript_structure() {
        let rs = default_position_rs();
        let ss = build_perp_maturity_settle_sigscript(&rs);
        assert_eq!(ss[0], 0x54, "maturity selector must be Op4");
    }

    #[test]
    fn perp_position_add_margin_sigscript_structure() {
        let sig = [0xAAu8; 64];
        let pk = [0xBBu8; 32];
        let rs = default_position_rs();
        let ss = build_perp_add_margin_sigscript(&sig, &pk, &rs);
        assert_eq!(ss[0], 65);
        assert_eq!(ss[65], 0x01);
        assert_eq!(ss[66], 32);
        assert_eq!(ss[99], 0x55, "add margin selector must be Op5");
    }

    #[test]
    fn perp_position_emergency_sigscript_structure() {
        let rs = default_position_rs();
        let ss = build_perp_emergency_sigscript(&rs);
        assert_eq!(ss[0], 0x57, "emergency selector must be Op7");
    }

    #[test]
    fn perp_position_sigscript_lengths() {
        let rs = default_position_rs();
        let sig = [0u8; 64];
        let pk = [0u8; 32];

        let cancel = build_perp_cancel_sigscript(&sig, &pk, &rs);
        let expected_signed = 66 + 33 + 1 + push_overhead(rs.len()) + rs.len();
        assert_eq!(cancel.len(), expected_signed, "cancel sigscript length");

        let unilateral = build_perp_unilateral_close_sigscript(&sig, &pk, &rs);
        assert_eq!(unilateral.len(), expected_signed, "unilateral sigscript length");

        let add_margin = build_perp_add_margin_sigscript(&sig, &pk, &rs);
        assert_eq!(add_margin.len(), expected_signed, "add margin sigscript length");

        let expected_permissionless = 1 + push_overhead(rs.len()) + rs.len();
        let liq = build_perp_liquidation_sigscript(&rs);
        assert_eq!(liq.len(), expected_permissionless, "liquidation sigscript length");

        let maturity = build_perp_maturity_settle_sigscript(&rs);
        assert_eq!(maturity.len(), expected_permissionless, "maturity sigscript length");

        let emergency = build_perp_emergency_sigscript(&rs);
        assert_eq!(emergency.len(), expected_permissionless, "emergency sigscript length");
    }

    // --- Body + RS size ---

    #[test]
    fn perp_position_body_and_rs_sizes() {
        let body_len = PERP_POSITION_BODY.len();
        let rs = default_position_rs();
        let rs_len = rs.len();
        assert_eq!(rs_len, PERP_POSITION_STATE_SIZE + body_len);
        eprintln!("PERP position: body={}B, state={}B, RS={}B", body_len, PERP_POSITION_STATE_SIZE, rs_len);
    }

    #[test]
    fn perp_position_rs_smaller_than_700b() {
        let rs = default_position_rs();
        assert!(rs.len() <= 700,
            "position RS ({}) should be <= 700B", rs.len());
    }

    // --- Hex snapshot ---

    #[test]
    fn perp_position_body_hex_snapshot() {
        let hex: String = PERP_POSITION_BODY.iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert!(hex.starts_with("01107a76529f"), "position dispatch prefix");
        assert!(hex.ends_with("68686851"), "position must end with 3 OpEndIf + Op1");
    }

    // --- Atomic settle stack trace test ---

    #[test]
    fn perp_position_pnl_computation_opcodes_present() {
        let body = PERP_POSITION_BODY;
        // PnL block should contain:
        // OpMul (0x95) for sk*ed, en*bt, delta*sz
        let mul_count = body.iter().filter(|&&b| b == 0x95).count();
        assert!(mul_count >= 5, "position must have >= 5 OpMul (PnL + price bounds + threshold), got {mul_count}");

        // OpDiv (0x96) for delta/bt and pnl_raw/ed + threshold
        let div_count = body.iter().filter(|&&b| b == 0x96).count();
        assert!(div_count >= 3, "position must have >= 3 OpDiv (2 PnL + 1 threshold), got {div_count}");

        // OpSub (0x94) for delta computation + counter_idx + ceiling clamp close_fee
        let sub_count = body.iter().filter(|&&b| b == 0x94).count();
        assert!(sub_count >= 3, "position must have >= 3 OpSub, got {sub_count}");
    }

    #[test]
    fn perp_position_direction_branch_present() {
        let body = PERP_POSITION_BODY;
        // Direction check: Op2 OpEqual ... OpIf ... Op0 OpSwap OpSub ... OpEndIf
        // Look for the short negate pattern: Op0 OpSwap OpSub = [0x00, 0x7c, 0x94]
        let negate_pattern = [0x00, 0x7c, 0x94];
        let found = body.windows(3).any(|w| w == negate_pattern);
        assert!(found, "position must contain Op0 OpSwap OpSub (short direction negate)");
    }

    #[test]
    fn perp_position_floor_clamp_present() {
        let body = PERP_POSITION_BODY;
        // Floor clamp: OpDup Op0 OpLessThan OpIf OpDrop Op0 OpEndIf
        // = [0x76, 0x00, 0x9f, 0x63, 0x75, 0x00, 0x68]
        let floor_pattern = [0x76, 0x00, 0x9f, 0x63, 0x75, 0x00, 0x68];
        let found = body.windows(7).any(|w| w == floor_pattern);
        assert!(found, "position must contain floor clamp pattern (OpDup Op0 LT If Drop Op0 EndIf)");
    }

    #[test]
    fn perp_position_ceiling_clamp_present() {
        let body = PERP_POSITION_BODY;
        // Ceiling uses OpGreaterThan (0xa0)
        assert!(body.contains(&0xa0), "position must contain OpGreaterThan for ceiling clamp");
    }

    #[test]
    fn perp_position_spot_verify_present() {
        let body = PERP_POSITION_BODY;
        // Spot verification: Op2 OpTxInputSpk = [0x52, 0xbf] and Op3 OpTxInputSpk = [0x53, 0xbf]
        let buy_verify = body.windows(2).any(|w| w == [0x52, 0xbf]);
        let sell_verify = body.windows(2).any(|w| w == [0x53, 0xbf]);
        assert!(buy_verify, "position must verify input[2].spk (spot buy)");
        assert!(sell_verify, "position must verify input[3].spk (spot sell)");
    }

    #[test]
    fn perp_position_reads_spot_outputs() {
        let body = PERP_POSITION_BODY;
        // Op2 OpTxOutputAmount = [0x52, 0xc2] for sk
        // Op3 OpTxOutputAmount = [0x53, 0xc2] for bt
        let sk_read = body.windows(2).any(|w| w == [0x52, 0xc2]);
        let bt_read = body.windows(2).any(|w| w == [0x53, 0xc2]);
        assert!(sk_read, "position must read output[2].value (seller_kas)");
        assert!(bt_read, "position must read output[3].value (buyer_tokens)");
    }

    #[test]
    fn perp_position_counter_margin_read() {
        let body = PERP_POSITION_BODY;
        // Counter margin: Op1 OpSwap OpSub = [0x51, 0x7c, 0x94] for counter_idx = 1 - self
        let counter_pattern = [0x51, 0x7c, 0x94];
        let found = body.windows(3).any(|w| w == counter_pattern);
        assert!(found, "position must compute counter_idx = 1 - self_idx");
    }

    #[test]
    fn perp_position_expected_len_is_hardcoded() {
        assert_eq!(PERP_POSITION_BODY.len(), PERP_BODY_EXPECTED_LEN,
            "expected length constant must match actual body length");
    }

    #[test]
    fn perp_position_dispatch_sel_check_values() {
        let body = PERP_POSITION_BODY;
        // sel==1 check: Op1 OpEqual OpVerify = [0x51, 0x87, 0x69]
        let sel1 = body.windows(3).any(|w| w == [0x51, 0x87, 0x69]);
        assert!(sel1, "position must check sel==1");
        // sel==3 check: Op3 OpEqual = [0x53, 0x87]
        let sel3 = body.windows(2).any(|w| w == [0x53, 0x87]);
        assert!(sel3, "position must check sel==3");
        // sel==2 check: Op2 OpEqual = [0x52, 0x87]
        let sel2 = body.windows(2).any(|w| w == [0x52, 0x87]);
        assert!(sel2, "position must check sel==2 (in path 2/direction branch)");
        // sel==5 check: Op5 OpEqual = [0x55, 0x87]
        let sel5 = body.windows(2).any(|w| w == [0x55, 0x87]);
        assert!(sel5, "position must check sel==5");
        // sel==7 check: Op7 OpEqual = [0x57, 0x87]
        let sel7 = body.windows(2).any(|w| w == [0x57, 0x87]);
        assert!(sel7, "position must check sel==7");
    }
}
