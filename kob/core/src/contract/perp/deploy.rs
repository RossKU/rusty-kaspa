//! Perpetual position covenant for KOB (Kaspa Order Book).
//!
//! Two covenant types:
//!
//! **Deploy covenant** (`build_perp_deploy_redeem_script`):
//! User deploys a Long or Short order with their margin. The matcher fills it
//! (fully or partially) against a counter-party, creating a position covenant.
//! Dispatch: sigLen-based (3 paths: full fill, partial fill, cancel).
//!
//! **Position covenant** (`build_perp_position_redeem_script`):
//! Atomic settlement via Buy/Sell co-inputs at input[2]/input[3]. Trustless —
//! price is determined by the spot match itself, not by an external oracle.
//!
//! Position paths (7 selectors):
//!   1. Cancel             (selector=1): owner reclaims margin (pre-fill only)
//!   2. Unilateral close   (selector=2): spot co-input price, PnL split, closer signs
//!   3. Liquidation        (selector=3): spot co-input price, margin < threshold
//!   4. Maturity settle    (selector=4): CLTV + spot co-input price, carry cost
//!   5. Add margin         (selector=5): self-continuation, value increase, owner sig
//!   6. Reserved           (selector=6): fails immediately
//!   7. Emergency timeout  (selector=7): CLTV fallback, return margins proportionally
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

/// KOB perp payload prefix: "KOB:P:" (6 bytes, ASCII).
///
/// Perp positions use a distinct prefix from spot orders (KOB:1:/KOB:2:)
/// so the matcher can distinguish perp deployments during block scanning.
pub const KOB_PERP_PAYLOAD_PREFIX: &[u8] = b"KOB:P:";

/// Build a TX payload for a perp position deploy.
///
/// Side byte for Long deploy orders.
pub const PERP_SIDE_LONG: u8 = 0x01;

/// Side byte for Short deploy orders.
pub const PERP_SIDE_SHORT: u8 = 0x02;

/// Format: `KOB:P:<side><RS>`
///
/// The matcher scans L1 blocks for this prefix pattern to discover
/// new perp positions, similar to `build_order_payload()` for spot orders.
pub fn build_perp_deploy_payload(rs: &[u8], side: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KOB_PERP_PAYLOAD_PREFIX.len() + 1 + rs.len());
    payload.extend_from_slice(KOB_PERP_PAYLOAD_PREFIX);
    payload.push(side);
    payload.extend_from_slice(rs);
    payload
}

/// Parse the side byte and RS from payload data after the `KOB:P:` prefix.
///
/// Returns `(side_byte, rs_data)` or `None` if empty.
pub fn parse_perp_deploy_side(after_prefix: &[u8]) -> Option<(u8, &[u8])> {
    if after_prefix.is_empty() {
        return None;
    }
    Some((after_prefix[0], &after_prefix[1..]))
}

/// Build a TX payload without side byte (legacy format: `KOB:P:<RS>`).
pub fn build_perp_order_payload(rs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KOB_PERP_PAYLOAD_PREFIX.len() + rs.len());
    payload.extend_from_slice(KOB_PERP_PAYLOAD_PREFIX);
    payload.extend_from_slice(rs);
    payload
}

/// Parse a KOB perp payload, stripping the `KOB:P:` prefix.
///
/// Returns the raw RS bytes after the prefix, or `None` if the payload
/// doesn't start with the KOB perp prefix.
pub fn parse_perp_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < KOB_PERP_PAYLOAD_PREFIX.len() {
        return None;
    }
    if &payload[..KOB_PERP_PAYLOAD_PREFIX.len()] != KOB_PERP_PAYLOAD_PREFIX {
        return None;
    }
    Some(&payload[KOB_PERP_PAYLOAD_PREFIX.len()..])
}
// Opcode reference (Kaspa script)
//
// Opcode reference (Kaspa script):
//   Op0=0x00  Op1=0x51  Op2=0x52  Op3=0x53  Op4=0x54
//   Op5=0x55  Op6=0x56  Op7=0x57  Op8=0x58  Op9=0x59
//   Op10=0x5a Op11=0x5b Op12=0x5c Op13=0x5d Op14=0x5e Op15=0x5f Op16=0x60
//   OpDup=0x76   OpDrop=0x75   OpSwap=0x7c   OpPick=0x79   OpRoll=0x7a
//   OpEqual=0x87 OpVerify=0x69 OpIf=0x63     OpElse=0x67   OpEndIf=0x68
//   OpAdd=0x93   OpSub=0x94   OpMul=0x95    OpDiv=0x96
//   OpLessThan=0x9f  OpGTE=0xa2  OpGreaterThan=0xa0
//   OpBlake2b=0xaa   OpCheckSig=0xac   OpCheckSigVerify=0xad
//   OpTxInputAmount=0xbe   OpInputCovenantId=0xcf
//   OpTxOutputAmount=0xc2  OpTxOutputSpk=0xc3
//   OpTxLockTime=0xb5      OpCheckLockTimeVerify=0xb0


pub const MIN_MARGIN_SOMPI: u64 = 3_000_000;

// Pair unit configuration
//
// Kaspa script arithmetic is i64 only. For high-value pairs (BTC/USDT),
// the intermediate product `max_price * size * split_num` must fit i64.
// Solution: use scaled base units (mBTC, cBTC) instead of native units
// (satoshi). The covenant doesn't know or care about "real" units.
//
// Example configurations:
//
//   KAS/USDT:  base_unit = KAS,  price_unit = cents
//              price=10 ($0.10), size=1000 (KAS), max_price=1000 ($10)
//
//   BTC/USDT:  base_unit = mBTC, price_unit = USD
//              price=100 ($100k/BTC=$100/mBTC), size=1000 (1 BTC), max_price=500 ($500k)
//
//   ETH/USDT:  base_unit = ETH,  price_unit = USD
//              price=3500, size=100 (ETH), max_price=20000
//
// The engine translates between display units and covenant units.
// Users see "1.5 BTC", engine sends size=1500 (mBTC) to the covenant.

/// Check whether a (max_price, size, split_num) triple fits i64 arithmetic.
///
/// Returns `true` if `max_price * size * split_num <= i64::MAX`.
/// Use this to validate pair parameters before building a position.
pub fn perp_params_fit_i64(max_price: u64, size: u64, split_num: u64) -> bool {
    (max_price as u128)
        .checked_mul(size as u128)
        .and_then(|v| v.checked_mul(split_num as u128))
        .is_some_and(|v| v <= i64::MAX as u128)
}

/// Compute the maximum safe position size for a given pair configuration.
///
/// Returns the largest `size` such that `max_price * size * split_num <= i64::MAX`.
pub fn perp_max_safe_size(max_price: u64, split_num: u64) -> u64 {
    if max_price == 0 || split_num == 0 {
        return u64::MAX;
    }
    let limit = i64::MAX as u128;
    let denom = (max_price as u128) * (split_num as u128);
    if denom == 0 {
        return u64::MAX;
    }
    let max_size = limit / denom;
    max_size.min(u64::MAX as u128) as u64
}

// perp_deploy — Deploy order covenant for perpetual futures
//
// When a user wants to go Long or Short, they deploy a perp_deploy UTXO
// with their margin. The matcher fills it against a counter-party's deploy
// UTXO, creating a perp_position UTXO.
//
// Dispatch: sigLen-based (3 paths):
//   sigLen < T1 (223)          -> full fill
//   T1 <= sigLen < T2 (251)    -> partial fill
//   sigLen >= T2               -> cancel (owner sig)
//
// State (9 items, 105B):
//   [0x20][owner_spk_hash 32B]   d8 — Blake2b of owner SPK
//   [0x08][price_num 8B]         d7 — limit price numerator
//   [0x08][price_den 8B]         d6 — limit price denominator
//   [0x08][maint_pct_num 8B]     d5 — maintenance margin %
//   [0x08][maint_pct_den 8B]     d4
//   [0x08][keeper_fee 8B]        d3 — keeper fee for resulting position
//   [0x08][emergency_daa 8B]     d2 — emergency timeout for resulting position
//   [0x08][min_fill 8B]          d1 — minimum fill amount (anti-dust)
//   [0x08][max_matcher_fee 8B]   d0 — maximum fee matcher can take (sompi)

/// perp_deploy state size: 1*(1+32) + 8*(1+8) = 33 + 72 = 105 bytes.
pub const PERP_DEPLOY_STATE_SIZE: usize = 33 * 1 + 9 * 8; // = 105

/// perp_deploy body bytecode (107 bytes).
///
/// State: [owner_spk_hash 32B][price_num 8B][price_den 8B]
///        [maint_pct_num 8B][maint_pct_den 8B][keeper_fee 8B][emergency_daa 8B]
///        [min_fill 8B][max_matcher_fee 8B] = 105B
///
/// Dispatch: sigLen-based (3 paths).
///   sigLen < T1 (223)          -> full fill
///   T1 <= sigLen < T2 (251)    -> partial fill
///   sigLen >= T2               -> cancel (owner sig)
///
/// Sigscript lengths (RS = 212B, pushData(212) = 214B):
///   Fill:    214B                    ([pushData(RS)])
///   Partial: 1+9+214 = 224B         ([ri_opN, pushData(fk 8B), pushData(RS)])
///   Cancel:  66+33+214 = 313B       ([pushData(sig 65B), pushData(pk 32B), pushData(RS)])
///
/// T1=223: separates fill(214) from partial(224)
/// T2=251: separates partial(224) from cancel(313)
///
/// Full fill: verifies output[0] value >= input - max_matcher_fee and
/// output[0].spk matches owner. Prevents fund theft during fill.
///
/// Partial fill: verifies fill_kas >= min_fill, residual SPK == input SPK
/// (self-continuation), residual value >= input - fill_kas, residual >= min_fill.
///
/// Cancel: Blake2b(pk) == owner_spk_hash, then CheckSigVerify.
pub const PERP_DEPLOY_BODY: &[u8] = &[
    // DISPATCH (13B)
    // stack: mmfee(0) mfill(1) ed_daa(2) kf(3) md(4) mn(5) pden(6) pnum(7) owner(8) [sigscript items below]
    0xb9, 0xc9,                   // OpTxInputIndex, OpTxInputScriptSigLen -> sigLen   [2B]
    // stack: sigLen(0) mmfee(1) mfill(2) ed_daa(3) kf(4) md(5) mn(6) pden(7) pnum(8) owner(9)
    0x76,                         // OpDup                                              [1B]
    0x02, 0xfb, 0x00,             // push T2=251                                        [3B]
    0x9f,                         // OpLessThan (sigLen < T2?)                           [1B]
    0x63,                         // OpIf (fill or partial)                              [1B]
    // stack: sigLen(0) mmfee(1) ... owner(9) [+sigscript items below]
    0x02, 0xdf, 0x00,             // push T1=223                                        [3B]
    0x9f,                         // OpLessThan (sigLen < T1?)                           [1B]
    0x63,                         // OpIf (full fill)                                    [1B]

    // FULL FILL PATH (28B)
    // stack: mmfee(0) mfill(1) ed_daa(2) kf(3) md(4) mn(5) pden(6) pnum(7) owner(8) [9 items]
    //
    // V1: output[0].spk.blake2b == owner_spk_hash (funds go to owner)
    0x00, 0xc3,                   // Op0 OpTxOutputSpk                                  [2B]
    // stack: spk0(0) mmfee(1) mfill(2) ... owner(9) [10 items]
    0xaa,                         // OpBlake2b -> h0                                     [1B]
    // stack: h0(0) mmfee(1) mfill(2) ... owner(9) [10 items]
    0x59, 0x79,                   // Op9 OpPick -> d9=owner                             [2B]
    // stack: owner_c(0) h0(1) mmfee(2) ... owner(10) [11 items]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: mmfee(0) mfill(1) ... owner(8) [9 items]
    //
    // V2: output[0].value >= input_value - max_matcher_fee
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> out0v                      [2B]
    // stack: out0v(0) mmfee(1) mfill(2) ... owner(9) [10 items]
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> in_val           [2B]
    // stack: in_val(0) out0v(1) mmfee(2) mfill(3) ... [11 items]
    0x52, 0x79,                   // Op2 OpPick -> d2=mmfee                             [2B]
    // stack: mmfee_c(0) in_val(1) out0v(2) ... [12 items]
    0x94,                         // OpSub -> in_val - mmfee_c = min_out                [1B]
    // stack: min_out(0) out0v(1) mmfee(2) ... [11 items]
    // GTE: pops b=min_out, a=out0v -> (out0v >= min_out)
    0xa2, 0x69,                   // OpGTE OpVerify (out0v >= min_out)                  [2B]
    // stack: mmfee(0) mfill(1) ... owner(8) [9 items]
    //
    // Cleanup: 9 state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (total 9 state items)                    [4B]

    // PARTIAL FILL PATH (45B)
    0x67,                         // OpElse (sigLen >= T1: partial fill)                 [1B]
    // Sigscript: [ri_opN][pushData(fill_kas 8B)][pushData(RS)]
    // stack: mmfee(0) mfill(1) ed_daa(2) kf(3) md(4) mn(5) pden(6) pnum(7) owner(8) fk(9) ri(10) [11 items]

    // --- P1: fill_kas >= min_fill ---
    0x59, 0x79,                   // Op9 OpPick -> fk copy (d9=fk)                      [2B]
    // stack: fk_c(0) mmfee(1) ... fk(10) ri(11) [12]
    0x52, 0x79,                   // Op2 OpPick -> mfill (d2=mfill)                     [2B]
    // stack: mf_c(0) fk_c(1) mmfee(2) mfill(3) ... [13]
    // GTE: pops b=mf_c, a=fk_c -> (fk_c >= mf_c)
    0xa2, 0x69,                   // OpGTE OpVerify (fk_c >= mf_c)                      [2B]
    // stack: mmfee(0) ... owner(8) fk(9) ri(10) [11]

    // --- P2: residual output SPK == this input SPK (self-continuation) ---
    0x5a, 0x79, 0xc3,             // Op10 OpPick(ri) OpTxOutputSpk -> res_spk           [3B]
    // stack: res_spk(0) mmfee(1) ... ri(11) [12]
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk -> in_spk              [2B]
    // stack: in_spk(0) res_spk(1) mmfee(2) ... [13]
    0x87, 0x69,                   // OpEqual OpVerify                                    [2B]
    // stack: mmfee(0) ... owner(8) fk(9) ri(10) [11]

    // --- P3: residual value >= input_value - fill_kas ---
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> in_val           [2B]
    // stack: in_val(0) mmfee(1) ... fk(10) ri(11) [12]
    0x5a, 0x79,                   // Op10 OpPick -> fk copy (d10=fk)                    [2B]
    // stack: fk_c(0) in_val(1) mmfee(2) ... fk(11) ri(12) [13]
    0x94,                         // OpSub -> in_val - fk_c = expected_residual         [1B]
    // stack: exp(0) mmfee(1) ... fk(10) ri(11) [12]
    0x5b, 0x79, 0xc2,             // Op11 OpPick(ri at d11) OpTxOutputAmount            [3B]
    // stack: res_val(0) exp(1) mmfee(2) ... ri(12) [13]
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify (res_val >= exp)             [3B]
    // stack: mmfee(0) ... owner(8) fk(9) ri(10) [11]

    // --- P4: residual value >= min_fill (residual must be fillable) ---
    0x5a, 0x79, 0xc2,             // Op10 OpPick(ri at d10) OpTxOutputAmount            [3B]
    // stack: res_val2(0) mmfee(1) mfill(2) ... ri(11) [12]
    0x52, 0x79,                   // Op2 OpPick -> mfill (d2=mfill)                     [2B]
    // stack: mf_c(0) res_val2(1) mmfee(2) mfill(3) ... [13]
    // GTE: pops b=mf_c, a=res_val2 -> (res_val2 >= mf_c)
    0xa2, 0x69,                   // OpGTE OpVerify (res_val2 >= mf_c)                  [2B]
    // stack: mmfee(0) ... owner(8) fk(9) ri(10) [11]

    // --- Cleanup: 9 state + 2 sigscript = 11 items ---
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75,                         // OpDrop x1 (11 total)                                [1B]

    // --- FILL/PARTIAL END ---
    0x68,                         // OpEndIf (fill vs partial)                           [1B]

    // CANCEL PATH (23B)
    0x67,                         // OpElse (sigLen >= T2: cancel)                       [1B]
    // Sigscript: [pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]
    // After RS: sig(deepest), pk, then 9 state items
    // stack: sigLen(0) mmfee(1) mfill(2) ed_daa(3) kf(4) md(5) mn(6) pden(7) pnum(8) owner(9) pk(10) sig(11)
    0x75,                         // OpDrop (sigLen)                                     [1B]
    // stack: mmfee(0) ... owner(8) pk(9) sig(10) [11]

    // --- Owner auth: Blake2b(pk) == owner_spk_hash ---
    0x59, 0x79,                   // Op9 OpPick -> pk copy (d9=pk)                      [2B]
    // stack: pk_c(0) mmfee(1) ... owner(9) pk(10) sig(11) [12]
    0xaa,                         // OpBlake2b -> hash(pk)                               [1B]
    // stack: h(0) mmfee(1) ... owner(9) pk(10) sig(11) [12]
    0x59, 0x79,                   // Op9 OpPick -> owner (d9=owner)                     [2B]
    // stack: owner_c(0) h(1) mmfee(2) ... owner(10) pk(11) sig(12) [13]
    0x87, 0x69,                   // OpEqual OpVerify (h == owner)                       [2B]
    // stack: mmfee(0) ... owner(8) pk(9) sig(10) [11]

    // --- Signature verification ---
    0x5a, 0x7a,                   // Op10 OpRoll -> sig to top                          [2B]
    // stack: sig(0) mmfee(1) ... owner(9) pk(10) [11]
    0x5a, 0x7a,                   // Op10 OpRoll -> pk to top                           [2B]
    // stack: pk(0) sig(1) mmfee(2) ... owner(10) [11]
    0xad,                         // OpCheckSigVerify                                    [1B]
    // stack: mmfee(0) ... owner(8) [9]
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5                                         [5B]
    0x75, 0x75, 0x75, 0x75,       // OpDrop x4 (9 total)                                [4B]

    // CLOSING (2B)
    0x68,                         // OpEndIf (outer: fill/partial vs cancel)             [1B]
    0x51,                         // Op1 (TRUE)                                          [1B]
];

/// Expected body length for perp_deploy snapshot test.
#[cfg(test)]
const PERP_DEPLOY_BODY_EXPECTED_LEN: usize = 107;

/// Build perp_deploy redeemScript (105B state + 107B body = 212B).
///
/// # Arguments
/// * `owner_spk_hash`  - 32B Blake2b hash of owner's scriptPublicKey (for cancel)
/// * `price_num`       - Limit price numerator (GCD-normalized with price_den)
/// * `price_den`       - Limit price denominator
/// * `maint_pct_num`   - Maintenance margin % numerator for resulting position
/// * `maint_pct_den`   - Maintenance margin % denominator
/// * `keeper_fee`      - Keeper fee for the resulting position (sompi)
/// * `emergency_daa`   - Emergency timeout for the resulting position
/// * `min_fill`        - Minimum fill amount in sompi (anti-dust)
/// * `max_matcher_fee` - Maximum fee matcher can take from margin (sompi)
///
/// # Panics
/// Panics if price_den, maint_pct_den, or min_fill is 0.
/// Panics if maint_pct_num is 0 or >= maint_pct_den.
/// Panics if emergency_daa is 0.
pub fn build_perp_deploy_redeem_script(
    owner_spk_hash: &[u8; 32],
    price_num: u64,
    price_den: u64,
    maint_pct_num: u64,
    maint_pct_den: u64,
    keeper_fee: u64,
    emergency_daa: u64,
    min_fill: u64,
    max_matcher_fee: u64,
) -> Vec<u8> {
    assert!(price_den > 0, "price_den must be > 0");
    assert!(maint_pct_den > 0, "maint_pct_den must be > 0");
    assert!(
        maint_pct_num * 2 < maint_pct_den,
        "maintenance percentage must be < 50% (maint_pct_num * 2 must be < maint_pct_den)"
    );
    assert!(min_fill > 0, "min_fill must be > 0");
    assert!(maint_pct_num > 0, "maint_pct_num must be > 0 (otherwise liquidation is impossible)");
    assert!(
        maint_pct_num < maint_pct_den,
        "maint_pct_num must be < maint_pct_den (maintenance ratio must be < 100%)"
    );
    assert!(emergency_daa > 0, "emergency_daa must be > 0");

    // GCD-normalize limit price
    let g = gcd(price_num, price_den);
    let pn = price_num / g;
    let pd = price_den / g;

    let body = PERP_DEPLOY_BODY;
    let mut rs = Vec::with_capacity(PERP_DEPLOY_STATE_SIZE + body.len());

    // State: pushed in order, first push = deepest on stack
    rs.push(0x20);
    rs.extend_from_slice(owner_spk_hash);    // stack[8] (deepest)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(pn));        // stack[7] price_num
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(pd));        // stack[6] price_den
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(maint_pct_num)); // stack[5]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(maint_pct_den)); // stack[4]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(keeper_fee));     // stack[3]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(emergency_daa));  // stack[2]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));       // stack[1]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_matcher_fee)); // stack[0] (top)

    rs.extend_from_slice(body);
    rs
}

/// Convert integer 0..=16 to OpN opcode (local helper for perp_deploy).
fn perp_opn(n: u8) -> u8 {
    match n {
        0 => 0x00,
        1..=16 => 0x50 + n,
        _ => panic!("OpN index out of range: {} (must be 0..=16)", n),
    }
}

/// Build perp_deploy full fill sigscript: `[pushData(RS)]`
///
/// SigLen < T1=223. Matcher consumes entire deploy UTXO margin.
pub fn build_perp_deploy_fill_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build perp_deploy partial fill sigscript:
/// `[ri_opN][pushData(fill_kas 8B)][pushData(RS)]`
///
/// SigLen: T1=223 <= x < T2=251.
/// * `fill_kas`     - amount of margin being filled (sompi)
/// * `residual_idx` - output index of the residual deploy UTXO (0..=16)
pub fn build_perp_deploy_partial_fill_sigscript(
    fill_kas: u64,
    residual_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let fk = u64_le(fill_kas);
    let mut ss = Vec::with_capacity(12 + redeem_script.len() + 3);
    ss.push(perp_opn(residual_idx)); // ri (OpN)
    ss.extend_from_slice(&push_data(&fk));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build perp_deploy cancel sigscript:
/// `[pushData(sig 65B)][pushData(pk 32B)][pushData(RS)]`
///
/// SigLen >= T2=251. Owner reclaims margin.
pub fn build_perp_deploy_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(102 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
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

    /// Find all OpRoll (0x7a) opcodes in body and return (offset, depth) pairs.
    fn find_rolls(body: &[u8]) -> Vec<(usize, u8)> {
        let mut rolls = Vec::new();
        for i in 1..body.len() {
            if body[i] == 0x7a {
                rolls.push((i, body[i - 1]));
            }
        }
        rolls
    }


    // GCD unit tests

    #[test]
    fn gcd_basic() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(100, 75), 25);
        assert_eq!(gcd(17, 13), 1);
        assert_eq!(gcd(0, 5), 5);
        assert_eq!(gcd(5, 0), 5);
        assert_eq!(gcd(0, 0), 0);
        assert_eq!(gcd(1, 1), 1);
        assert_eq!(gcd(u64::MAX, 1), 1);
    }


    // perp_deploy tests

    fn default_deploy_rs() -> Vec<u8> {
        build_perp_deploy_redeem_script(
            &sample_hash(0xAA), // owner_spk_hash
            100, 1,             // price_num/den
            5, 100,             // maint_pct 5%
            1_000_000,          // keeper_fee
            5_000_000,          // emergency_daa
            3_000_000,          // min_fill
            500_000,            // max_matcher_fee
        )
    }

    // --- Body snapshot & structure ---

    #[test]
    fn perp_deploy_body_snapshot_length() {
        let len = PERP_DEPLOY_BODY.len();
        assert_eq!(len, PERP_DEPLOY_BODY_EXPECTED_LEN,
            "body length changed from expected {PERP_DEPLOY_BODY_EXPECTED_LEN} to {len}");
    }

    #[test]
    fn perp_deploy_body_reasonable_size() {
        let len = PERP_DEPLOY_BODY.len();
        assert!(len > 50, "body too small: {len}");
        assert!(len < 200, "body too large: {len}");
    }

    #[test]
    fn perp_deploy_body_starts_with_dispatch() {
        assert_eq!(PERP_DEPLOY_BODY[0], 0xb9, "must start with OpTxInputIndex");
        assert_eq!(PERP_DEPLOY_BODY[1], 0xc9, "second byte: OpTxInputScriptSigLen");
        assert_eq!(PERP_DEPLOY_BODY[2], 0x76, "third byte: OpDup");
    }

    #[test]
    fn perp_deploy_body_ends_with_true() {
        let body = PERP_DEPLOY_BODY;
        let len = body.len();
        assert_eq!(body[len - 1], 0x51, "last byte must be Op1 (TRUE)");
        assert_eq!(body[len - 2], 0x68, "second-to-last must be OpEndIf");
    }

    #[test]
    fn perp_deploy_body_has_checksigverify() {
        assert!(PERP_DEPLOY_BODY.contains(&0xad),
            "body must contain OpCheckSigVerify for cancel path");
    }

    #[test]
    fn perp_deploy_body_has_blake2b() {
        assert!(PERP_DEPLOY_BODY.contains(&0xaa),
            "body must contain OpBlake2b for owner auth");
    }

    #[test]
    fn perp_deploy_body_has_self_continuation() {
        // OpTxInputSpk (0xbf) for residual SPK match
        assert!(PERP_DEPLOY_BODY.contains(&0xbf),
            "body must contain OpTxInputSpk for self-continuation check");
    }

    // --- State size ---

    #[test]
    fn perp_deploy_state_size() {
        // 1 hash:  1 * (1 + 32) = 33
        // 8 u64:   8 * (1 + 8)  = 72
        // Total: 105
        assert_eq!(PERP_DEPLOY_STATE_SIZE, 105);
    }

    #[test]
    fn perp_deploy_rs_size() {
        let rs = default_deploy_rs();
        assert_eq!(rs.len(), PERP_DEPLOY_STATE_SIZE + PERP_DEPLOY_BODY.len());
        assert_eq!(rs.len(), PERP_DEPLOY_STATE_SIZE + PERP_DEPLOY_BODY.len(),
            "RS must be state + body");
    }

    // --- RS builder validation ---

    #[test]
    #[should_panic(expected = "price_den must be > 0")]
    fn perp_deploy_rejects_zero_price_den() {
        let z = zero32();
        build_perp_deploy_redeem_script(&z, 100, 0, 5, 100, 0, 1_000_000, 1_000_000, 500_000);
    }

    #[test]
    #[should_panic(expected = "maint_pct_den must be > 0")]
    fn perp_deploy_rejects_zero_maint_pct_den() {
        let z = zero32();
        build_perp_deploy_redeem_script(&z, 100, 1, 5, 0, 0, 1_000_000, 1_000_000, 500_000);
    }

    #[test]
    #[should_panic(expected = "min_fill must be > 0")]
    fn perp_deploy_rejects_zero_min_fill() {
        let z = zero32();
        build_perp_deploy_redeem_script(&z, 100, 1, 5, 100, 0, 1_000_000, 0, 500_000);
    }

    #[test]
    #[should_panic(expected = "maint_pct_num must be > 0")]
    fn perp_deploy_rejects_zero_maint_pct_num() {
        let z = zero32();
        build_perp_deploy_redeem_script(&z, 100, 1, 0, 100, 0, 1_000_000, 1_000_000, 500_000);
    }

    #[test]
    #[should_panic(expected = "maintenance percentage must be < 50%")]
    fn perp_deploy_rejects_maint_pct_equals_den() {
        let z = zero32();
        build_perp_deploy_redeem_script(&z, 100, 1, 100, 100, 0, 1_000_000, 1_000_000, 500_000);
    }

    #[test]
    #[should_panic(expected = "maintenance percentage must be < 50%")]
    fn perp_deploy_rejects_maint_pct_exceeds_den() {
        let z = zero32();
        build_perp_deploy_redeem_script(&z, 100, 1, 150, 100, 0, 1_000_000, 1_000_000, 500_000);
    }

    #[test]
    #[should_panic(expected = "emergency_daa must be > 0")]
    fn perp_deploy_rejects_zero_emergency_daa() {
        let z = zero32();
        build_perp_deploy_redeem_script(&z, 100, 1, 5, 100, 0, 0, 1_000_000, 500_000);
    }

    #[test]
    fn perp_deploy_accepts_valid_params() {
        let rs = build_perp_deploy_redeem_script(
            &sample_hash(0x11),
            100, 1, 5, 100, 500_000, 1_000_000, 3_000_000,
            100_000, // max_matcher_fee
        );
        assert!(rs.len() > PERP_DEPLOY_STATE_SIZE, "RS must include state + body");
    }

    // --- State field extraction ---

    #[test]
    fn perp_deploy_state_field_extraction() {
        let owner = sample_hash(0x11);
        let rs = build_perp_deploy_redeem_script(
            &owner, 200, 2, 10, 200, 888_888, 7_777_777, 5_000_000,
            100_000, // max_matcher_fee
        );

        // owner_spk_hash at [0]: 0x20 + 32B
        assert_eq!(rs[0], 0x20);
        assert_eq!(&rs[1..33], &owner);
        // price_num at [33]: GCD(200,2)=2, so 100/1
        assert_eq!(rs[33], 0x08);
        assert_eq!(u64::from_le_bytes(rs[34..42].try_into().unwrap()), 100);
        // price_den at [42]
        assert_eq!(rs[42], 0x08);
        assert_eq!(u64::from_le_bytes(rs[43..51].try_into().unwrap()), 1);
        // maint_pct_num at [51]
        assert_eq!(rs[51], 0x08);
        assert_eq!(u64::from_le_bytes(rs[52..60].try_into().unwrap()), 10);
        // maint_pct_den at [60]
        assert_eq!(rs[60], 0x08);
        assert_eq!(u64::from_le_bytes(rs[61..69].try_into().unwrap()), 200);
        // keeper_fee at [69]
        assert_eq!(rs[69], 0x08);
        assert_eq!(u64::from_le_bytes(rs[70..78].try_into().unwrap()), 888_888);
        // emergency_daa at [78]
        assert_eq!(rs[78], 0x08);
        assert_eq!(u64::from_le_bytes(rs[79..87].try_into().unwrap()), 7_777_777);
        // min_fill at [87]
        assert_eq!(rs[87], 0x08);
        assert_eq!(u64::from_le_bytes(rs[88..96].try_into().unwrap()), 5_000_000);
        // max_matcher_fee at [96]
        assert_eq!(rs[96], 0x08);
        assert_eq!(u64::from_le_bytes(rs[97..105].try_into().unwrap()), 100_000);
        // body starts at [105]
        assert_eq!(&rs[105..], PERP_DEPLOY_BODY);
    }

    // --- GCD normalization ---

    #[test]
    fn perp_deploy_gcd_normalization() {
        let z = zero32();
        let rs1 = build_perp_deploy_redeem_script(&z, 600, 300, 5, 100, 0, 100, 1_000_000, 500_000);
        let rs2 = build_perp_deploy_redeem_script(&z, 2, 1, 5, 100, 0, 100, 1_000_000, 500_000);
        assert_eq!(rs1, rs2, "GCD normalization: 600/300 == 2/1");
    }

    #[test]
    fn perp_deploy_price_num_zero() {
        let z = zero32();
        let rs = build_perp_deploy_redeem_script(&z, 0, 1, 5, 100, 0, 100, 1_000_000, 500_000);
        let pn = u64::from_le_bytes(rs[34..42].try_into().unwrap());
        assert_eq!(pn, 0, "price_num=0 should be preserved");
    }

    // --- Sigscript threshold verification ---

    #[test]
    fn perp_deploy_sigscript_thresholds() {
        let rs = default_deploy_rs();

        // Fill sigscript: pushData(RS)
        let fill_ss = build_perp_deploy_fill_sigscript(&rs);
        // Partial fill sigscript
        let partial_ss = build_perp_deploy_partial_fill_sigscript(5_000_000, 1, &rs);
        // Cancel sigscript
        let fake_sig = [0u8; 64];
        let fake_pk = [0u8; 32];
        let cancel_ss = build_perp_deploy_cancel_sigscript(&fake_sig, &fake_pk, &rs);

        // Verify actual sigscript lengths
        let fill_len = fill_ss.len();
        let partial_len = partial_ss.len();
        let cancel_len = cancel_ss.len();

        // T1=223, T2=251
        assert!(fill_len < 223, "fill({fill_len}) must be < T1(223)");
        assert!(partial_len >= 223, "partial({partial_len}) must be >= T1(223)");
        assert!(partial_len < 251, "partial({partial_len}) must be < T2(251)");
        assert!(cancel_len >= 251, "cancel({cancel_len}) must be >= T2(251)");

        // Verify exact expected sizes (RS = 212B, pushData(212) = 214B)
        assert_eq!(fill_len, 214, "fill = pushData(212B RS) = 214B");
        assert_eq!(partial_len, 224, "partial = 1(ri) + 9(fk) + 214(RS) = 224B");
        assert_eq!(cancel_len, 313, "cancel = 66(sig) + 33(pk) + 214(RS) = 313B");
    }

    // --- Fill sigscript structure ---

    #[test]
    fn perp_deploy_fill_sigscript_structure() {
        let rs = default_deploy_rs();
        let ss = build_perp_deploy_fill_sigscript(&rs);
        // pushData(212B): 0x4c prefix + 0xD4 len + data
        assert_eq!(ss[0], 0x4c, "pushdata1 prefix for 212B RS");
        assert_eq!(ss[1], 212, "RS length byte");
        assert_eq!(&ss[2..], &rs[..], "RS data must follow");
    }

    // --- Partial fill sigscript structure ---

    #[test]
    fn perp_deploy_partial_fill_sigscript_structure() {
        let rs = default_deploy_rs();
        let ss = build_perp_deploy_partial_fill_sigscript(5_000_000, 2, &rs);
        // ri = Op2 (0x52)
        assert_eq!(ss[0], 0x52, "ri must be Op2 for index 2");
        // fk push: 0x08 prefix + 8B LE
        assert_eq!(ss[1], 0x08, "fk push prefix");
        assert_eq!(&ss[2..10], &u64_le(5_000_000));
        // RS follows
        assert_eq!(ss[10], 0x4c, "pushdata1 for RS");
    }

    #[test]
    fn perp_deploy_partial_fill_ri_zero() {
        let rs = default_deploy_rs();
        let ss = build_perp_deploy_partial_fill_sigscript(1_000_000, 0, &rs);
        assert_eq!(ss[0], 0x00, "ri=0 must be Op0 (0x00)");
    }

    // --- Cancel sigscript structure ---

    #[test]
    fn perp_deploy_cancel_sigscript_structure() {
        let fake_sig = [0xAA; 64];
        let fake_pk = [0xBB; 32];
        let rs = default_deploy_rs();
        let ss = build_perp_deploy_cancel_sigscript(&fake_sig, &fake_pk, &rs);

        // Sig: pushData(65B) = 0x41 prefix + 64B sig + 0x01 sighash
        assert_eq!(ss[0], 0x41, "sig push prefix must be 65");
        assert_eq!(&ss[1..65], &fake_sig[..], "sig data");
        assert_eq!(ss[65], 0x01, "sighash type");
        // PK: pushData(32B) = 0x20 prefix + 32B
        assert_eq!(ss[66], 0x20, "pk push prefix must be 32");
        assert_eq!(&ss[67..99], &fake_pk[..], "pk data");
        // RS follows
        assert_eq!(ss[99], 0x4c, "pushdata1 for RS");
    }

    // --- Opcode count checks ---

    #[test]
    fn perp_deploy_opif_endif_balance() {
        let body = PERP_DEPLOY_BODY;
        let opif_count = body.iter().filter(|&&b| b == 0x63).count();
        let opendif_count = body.iter().filter(|&&b| b == 0x68).count();
        assert_eq!(opif_count, opendif_count,
            "OpIf({opif_count}) must equal OpEndIf({opendif_count})");
    }

    #[test]
    fn perp_deploy_drop_count_sanity() {
        let body = PERP_DEPLOY_BODY;
        let drop_count = body.iter().filter(|&&b| b == 0x75).count();
        // Full fill: 9 drops, partial fill: 11 drops, cancel: 1(sigLen)+9 = 10 drops
        // Total: 9 + 11 + 10 = 30... but partial=11, cancel has 1+9=10, fill=9 => 30
        // After oracle removal: fill=9, partial=9+2=11, cancel=1+9=10 => 30
        assert!(drop_count >= 25, "must have enough OpDrop for cleanup, got {drop_count}");
    }

    // --- Payload ---

    #[test]
    fn perp_deploy_payload_roundtrip() {
        let rs = default_deploy_rs();
        let payload = build_perp_deploy_payload(&rs, PERP_SIDE_LONG);
        let after_prefix = parse_perp_payload(&payload).unwrap();
        let (side, rs_data) = parse_perp_deploy_side(after_prefix).unwrap();
        assert_eq!(side, PERP_SIDE_LONG, "side must roundtrip");
        assert_eq!(rs_data, &rs[..], "payload roundtrip must preserve RS");
    }

    // --- Body hex snapshot ---

    #[test]
    fn perp_deploy_body_hex_snapshot() {
        let hex: String = PERP_DEPLOY_BODY.iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        // Dispatch starts with OpTxInputIndex OpTxInputScriptSigLen OpDup
        assert!(hex.starts_with("b9c976"), "dispatch prefix must be b9c976");
        // Ends with OpEndIf Op1
        assert!(hex.ends_with("6851"), "must end with OpEndIf+Op1");
    }

    // --- RS body correctly appended ---

    #[test]
    fn perp_deploy_rs_body_appended_correctly() {
        let rs = default_deploy_rs();
        let body = PERP_DEPLOY_BODY;
        let rs_body = &rs[PERP_DEPLOY_STATE_SIZE..];
        assert_eq!(rs_body, body, "body must be appended after state");
    }

    // --- Edge cases ---

    #[test]
    fn perp_deploy_keeper_fee_zero() {
        let z = zero32();
        let rs = build_perp_deploy_redeem_script(&z, 100, 1, 5, 100, 0, 100, 1_000_000, 500_000);
        let kf = u64::from_le_bytes(rs[70..78].try_into().unwrap());
        assert_eq!(kf, 0, "keeper_fee=0 should be valid");
    }

    #[test]
    fn perp_deploy_large_keeper_fee() {
        let z = zero32();
        let rs = build_perp_deploy_redeem_script(&z, 100, 1, 5, 100, u64::MAX, 100, 1_000_000, 500_000);
        let kf = u64::from_le_bytes(rs[70..78].try_into().unwrap());
        assert_eq!(kf, u64::MAX);
    }

    #[test]
    fn perp_deploy_min_emergency_daa() {
        let z = zero32();
        let rs = build_perp_deploy_redeem_script(&z, 100, 1, 5, 100, 0, 1, 1_000_000, 500_000);
        let ed = u64::from_le_bytes(rs[79..87].try_into().unwrap());
        assert_eq!(ed, 1, "emergency_daa=1 is min valid");
    }

    #[test]
    fn perp_deploy_maint_pct_boundary() {
        let z = zero32();
        // 1/100 = 1% (min)
        let _rs = build_perp_deploy_redeem_script(&z, 100, 1, 1, 100, 0, 100, 1_000_000, 500_000);
        // 49/100 = 49% (max valid under <50% rule)
        let _rs = build_perp_deploy_redeem_script(&z, 100, 1, 49, 100, 0, 100, 1_000_000, 500_000);
    }

    // --- Body length hardcoded constant ---

    #[test]
    fn perp_deploy_expected_len_is_hardcoded() {
        assert_eq!(PERP_DEPLOY_BODY.len(), 107,
            "body length must be exactly 107 bytes");
        assert_eq!(PERP_DEPLOY_BODY_EXPECTED_LEN, 107,
            "expected length constant must be hardcoded to 107");
    }

    // Issue 1: Deploy full-fill path output verification tests

    #[test]
    fn perp_deploy_fill_path_has_output_spk_check() {
        // The full-fill path must verify output[0].spk matches owner_spk_hash.
        // This manifests as Op0 OpTxOutputSpk OpBlake2b (0x00 0xc3 0xaa) in the body.
        let body = PERP_DEPLOY_BODY;
        let spk_check = [0x00, 0xc3, 0xaa]; // Op0 OpTxOutputSpk OpBlake2b
        assert!(
            body.windows(3).any(|w| w == spk_check),
            "full-fill path must verify output[0].spk via OpTxOutputSpk + OpBlake2b"
        );
    }

    #[test]
    fn perp_deploy_fill_path_has_output_value_check() {
        // The full-fill path must verify output[0].value >= input_value - max_matcher_fee.
        // This requires Op0 OpTxOutputAmount (0x00 0xc2) and
        // OpTxInputIndex OpTxInputAmount (0xb9 0xbe) in the body.
        let body = PERP_DEPLOY_BODY;
        let out_amount = [0x00, 0xc2]; // Op0 OpTxOutputAmount
        let in_amount = [0xb9, 0xbe]; // OpTxInputIndex OpTxInputAmount
        assert!(
            body.windows(2).any(|w| w == out_amount),
            "full-fill path must check output[0] amount"
        );
        assert!(
            body.windows(2).any(|w| w == in_amount),
            "full-fill path must read input amount for fee verification"
        );
    }

    #[test]
    fn perp_deploy_fill_path_not_just_true() {
        // Regression: the old body just dropped state and returned TRUE.
        // The new body must NOT have a simple drop-all-true pattern in the fill path.
        // Specifically, after the dispatch (13B), the fill path must contain
        // output verification opcodes before the cleanup drops.
        let body = PERP_DEPLOY_BODY;
        // After dispatch (13B), the fill path starts. Find OpBlake2b (0xaa)
        // which is part of the SPK verification.
        let fill_start = 13; // dispatch is 13B
        let fill_section = &body[fill_start..];
        // Must contain OpBlake2b for SPK hash check
        assert!(
            fill_section.contains(&0xaa),
            "fill path must contain OpBlake2b for SPK verification"
        );
        // Must contain OpGTE (0xa2) for value comparison
        assert!(
            fill_section.contains(&0xa2),
            "fill path must contain OpGTE for value verification"
        );
    }

    #[test]
    fn perp_deploy_max_matcher_fee_in_state() {
        let z = zero32();
        let rs = build_perp_deploy_redeem_script(
            &z, 100, 1, 5, 100, 0, 100, 1_000_000, 777_777,
        );
        // max_matcher_fee is the last state field at offset [96]
        assert_eq!(rs[96], 0x08);
        let mmfee = u64::from_le_bytes(rs[97..105].try_into().unwrap());
        assert_eq!(mmfee, 777_777, "max_matcher_fee must be stored in state");
    }

}
