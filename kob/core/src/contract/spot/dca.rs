use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::opn;

/// dca_order body bytecode (195 bytes).
///
/// Purpose: Periodic buy order with on-chain D&R (Destroy & Recreate) enforcement.
/// Prevents malicious fillers from manipulating state transitions.
///
/// State (120B):
///   [0x20][owner_hash 32B][0x20][target_cov_id 32B][0x08][price_num 8B]
///   [0x08][price_den 8B][0x08][amount_per_period 8B][0x08][interval_daa 8B]
///   [0x08][next_execution_daa 8B][0x08][periods_remaining 8B]
///
/// D&R zone layout (for prefix/suffix matching):
///   Prefix = [0..103)   = 103B locked (owner_hash, tcid, pnum, pden, amt_pp, interval, push prefix)
///   Mutable = [103..120) = 17B (next_exec value 8B + push_prefix 1B + periods value 8B)
///   Suffix = [120..end) = body locked
///
/// Stack after state pushes (8 items, depth 0 = top):
///   periods(0), next_exec(1), interval(2), amt_pp(3), pden(4), pnum(5), tcid(6), ohash(7)
///
/// Dispatch: Op8 OpRoll selector.
///   selector > 0 (truthy) -> fill
///   selector == 0 (falsy) -> cancel (owner sig)
///
/// Fill path:
///   1. CLTV: verify next_execution_daa <= tx.lockTime
///   2. Verify periods_remaining > 0
///   3. expected_tokens = (amount_per_period * price_num) / price_den
///   4. Verify output[0].value >= expected_tokens
///   5. If periods > 1: D&R enforcement
///      a. Verify old_rs authenticity (Blake2b -> P2SH SPK match)
///      b. Verify prefix [0..103) unchanged
///      c. Verify suffix [120..end) unchanged
///      d. Verify push prefix at byte 111 == 0x08
///      e. Verify new_next_exec == old_next_exec + interval
///      f. Verify new_periods == old_periods - 1
///      g. Verify output[ci].spk == P2SH(new_rs)
///      h. Verify output[ci].value >= input[self].value - amt_per_period
///   6. If periods == 1: final fill, no continuation needed
///
/// Cancel path:
///   1. Verify Blake2b(pubkey) == owner_hash
///   2. CheckSig
///
/// Fill sigscript:   [pushData(new_rs)][pushData(old_rs)][ci_opN][Op1][pushData(RS)]
///   For final fill (periods==1): new_rs and old_rs can be Op0 (empty/dummy).
/// Cancel sigscript: [pushData(sig+type 65B)][pushData(pk 32B)][Op0][pushData(RS)]
///
/// Body = 195B, RS = 120 + 195 = 315 bytes.
pub const DCA_ORDER_BODY: &[u8] = &[
    // --- DISPATCH (5B) ---
    0x58, 0x7a,       // Op8 OpRoll -> selector to top
    0x00, 0xa0,       // Op0 OpGreaterThan -> clean boolean
    0x63,             // OpIf (truthy = fill)

    // --- FILL PATH ---
    // Stack (11): periods(0), next_exec(1), interval(2), amt_pp(3), pden(4), pnum(5),
    //             tcid(6), ohash(7), ci(8), old_rs(9), new_rs(10)

    // CLTV: next_execution_daa <= tx.lockTime (3B)
    // NOTE: Kaspa CLTV pops the top value. No OpDrop needed.
    0x51, 0x79,       // Op1 OpPick -> next_exec copy
    0xb0,             // OpCheckLockTimeVerify (pops next_exec copy)

    // Verify periods > 0, preserve periods for branching (4B)
    0x76,             // OpDup -> periods copy
    0x00, 0xa0, 0x69, // Op0 OpGreaterThan OpVerify

    // expected_tokens = (amt_pp * pnum) / pden (13B)
    0x53, 0x79,       // Op3 OpPick -> amt_pp copy
    0x56, 0x79, 0x95, // Op6 OpPick(pnum) OpMul
    0x55, 0x79, 0x96, // Op5 OpPick(pden) OpDiv -> expected_tokens
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0x7c,             // OpSwap
    0xa2, 0x69,       // OpGTE OpVerify (out0 >= expected_tokens)
    // Stack (11): periods(0), ...

    // Branch: periods > 1 -> D&R, periods == 1 -> final fill (3B)
    0x51, 0xa0,       // Op1 OpGreaterThan (periods > 1? consumes periods)
    0x63,             // OpIf (D&R block)

    // D&R BLOCK (periods > 1)
    // Stack (10): next_exec(0), interval(1), amt_pp(2), pden(3), pnum(4),
    //             tcid(5), ohash(6), ci(7), old_rs(8), new_rs(9)

    // --- D&R Step 1: Verify old_rs authenticity (15B) ---
    0x58, 0x79,       // Op8 OpPick -> old_rs copy (d8)
    0xaa,             // OpBlake2b -> rs_hash
    0x02, 0xaa, 0x20, // push [0xaa, 0x20]
    0x7c,             // OpSwap
    0x7e,             // OpCat -> [0xaa,0x20]||hash
    0x01, 0x87,       // push [0x87]
    0x7e,             // OpCat -> expected P2SH SPK
    0xb9, 0xbf,       // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,       // OpEqual OpVerify
    // Stack: [10] (back to base)

    // --- D&R Step 2: Verify unchanged prefix [0..103) (14B) ---
    0x58, 0x79,       // Op8 OpPick -> old_rs copy                         [2B]
    0x00,             // Op0 (begin=0)                                     [1B]
    0x01, 0x67,       // push 103 (size)                                   [2B]
    0x7f,             // OpSubstr -> old_prefix                             [1B]
    // old_rs at d9, new_rs at d10
    0x5a, 0x79,       // Op10 OpPick -> new_rs copy (d9+1=d10)             [2B]
    0x00,             // Op0                                               [1B]
    0x01, 0x67,       // push 103                                          [2B]
    0x7f,             // OpSubstr -> new_prefix                             [1B]
    0x87, 0x69,       // OpEqual OpVerify                                   [2B]
    // Stack: [10]

    // --- D&R Step 3: Verify unchanged suffix [120..end) (22B) ---
    0x58, 0x79,       // Op8 OpPick -> old_rs copy                         [2B]
    0x82,             // OpSize -> len (no pop)                             [1B]
    0x01, 0x78,       // push 120                                          [2B]
    0x94,             // OpSub -> suffix_len                                [1B]
    0x01, 0x78,       // push 120 (begin)                                  [2B]
    0x7c,             // OpSwap                                             [1B]
    0x7f,             // OpSubstr -> old_suffix                             [1B]
    0x5a, 0x79,       // Op10 OpPick -> new_rs copy                        [2B]
    0x82,             // OpSize                                             [1B]
    0x01, 0x78,       // push 120                                          [2B]
    0x94,             // OpSub                                              [1B]
    0x01, 0x78,       // push 120                                          [2B]
    0x7c,             // OpSwap                                             [1B]
    0x7f,             // OpSubstr -> new_suffix                             [1B]
    0x87, 0x69,       // OpEqual OpVerify                                   [2B]
    // Stack: [10]

    // --- D&R Step 4: Verify push prefix at new_rs[111] == 0x08 (10B) ---
    0x59, 0x79,       // Op9 OpPick -> new_rs copy (d9)                    [2B]
    0x01, 0x6f,       // push 111                                          [2B]
    0x51,             // Op1 (size=1)                                       [1B]
    0x7f,             // OpSubstr -> 1-byte at offset 111                   [1B]
    0x01, 0x08,       // push [0x08]                                        [2B]
    0x87, 0x69,       // OpEqual OpVerify                                   [2B]
    // Stack: [10]

    // --- D&R Step 5: Verify new_next_exec == old_next_exec + interval (17B) ---
    // Extract new_next_exec from new_rs[103..111)
    0x59, 0x79,       // Op9 OpPick -> new_rs copy (d9)                    [2B]
    0x01, 0x67,       // push 103                                          [2B]
    0x58,             // Op8 (size=8)                                       [1B]
    0x7f,             // OpSubstr -> new_next_exec                          [1B]
    // Stack (11): new_nex(0), next_exec(1), interval(2), ... old_rs(9), new_rs(10)
    // Extract old_next_exec from old_rs[103..111)
    0x59, 0x79,       // Op9 OpPick -> old_rs (d8+1=d9)                    [2B]
    0x01, 0x67,       // push 103                                          [2B]
    0x58,             // Op8                                                [1B]
    0x7f,             // OpSubstr -> old_next_exec                          [1B]
    // Stack (12): old_nex(0), new_nex(1), next_exec(2), interval(3), ...
    // Get interval from state stack (d3)
    0x53, 0x79,       // Op3 OpPick -> interval copy                       [2B]
    0x93,             // OpAdd -> old_next_exec + interval                  [1B]
    0x9c, 0x69,       // OpNumEqual OpVerify (== new_next_exec)            [2B]
    // Stack: [10]

    // --- D&R Step 6: Verify new_periods == old_periods - 1 (16B) ---
    // Extract new_periods from new_rs[112..120)
    0x59, 0x79,       // Op9 OpPick -> new_rs copy (d9)                    [2B]
    0x01, 0x70,       // push 112                                          [2B]
    0x58,             // Op8 (size=8)                                       [1B]
    0x7f,             // OpSubstr -> new_periods                            [1B]
    // Stack (11)
    // Extract old_periods from old_rs[112..120)
    0x59, 0x79,       // Op9 OpPick -> old_rs (d8+1=d9)                    [2B]
    0x01, 0x70,       // push 112                                          [2B]
    0x58,             // Op8                                                [1B]
    0x7f,             // OpSubstr -> old_periods                            [1B]
    // Stack (12): old_per(0), new_per(1), ...
    0x51, 0x94,       // Op1 OpSub -> old_periods - 1                      [2B]
    0x9c, 0x69,       // OpNumEqual OpVerify (== new_periods)              [2B]
    // Stack: [10]

    // --- D&R Step 7: Verify output[ci].spk == P2SH(new_rs) (16B) ---
    0x59, 0x79,       // Op9 OpPick -> new_rs copy (d9)                    [2B]
    0xaa,             // OpBlake2b                                          [1B]
    0x02, 0xaa, 0x20, // push [0xaa, 0x20]                                 [3B]
    0x7c,             // OpSwap                                             [1B]
    0x7e,             // OpCat                                              [1B]
    0x01, 0x87,       // push [0x87]                                        [2B]
    0x7e,             // OpCat -> expected output SPK                       [1B]
    // Stack (11): expected_spk(0), ...ci(8)...
    0x58, 0x79,       // Op8 OpPick -> ci (d8)                             [2B]
    0xc3,             // OpTxOutputSpk -> output[ci].spk                   [1B]
    0x87, 0x69,       // OpEqual OpVerify                                   [2B]
    // Stack: [10]

    // --- D&R Step 8: Value conservation (11B) ---
    // Ensure continuation UTXO keeps at least (input_value - amt_per_period).
    // Stack (10): next_exec(0), interval(1), amt_pp(2), pden(3), pnum(4),
    //             tcid(5), ohash(6), ci(7), old_rs(8), new_rs(9)
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount -> self_value          [2B]
    0x53, 0x79,       // Op3 OpPick -> amt_pp (at d2+1=d3)                     [2B]
    0x94,             // OpSub -> min_value = self_value - amt_pp              [1B]
    0x58, 0x79,       // Op8 OpPick -> ci (at d7+1=d8)                         [2B]
    0xc2,             // OpTxOutputAmount -> output[ci].value                   [1B]
    0x7c,             // OpSwap -> [output_val, min_value]                      [1B]
    0xa2, 0x69,       // OpGTE OpVerify (output_val >= min_value)              [2B]
    // Stack: [10]

    // D&R cleanup: 7 state + 1 ci + 2 D&R (old_rs, new_rs) = 10 items (10B)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,

    // --- FINAL FILL (periods == 1, no continuation) ---
    0x67,             // OpElse
    // Stack (10): next_exec(0), interval(1), amt_pp(2), pden(3), pnum(4),
    //             tcid(5), ohash(6), ci(7), old_rs(8), new_rs(9)
    // No continuation needed — just cleanup
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x10
    0x68,             // OpEndIf (periods branch)

    // --- CANCEL PATH (22B) ---
    0x67,             // OpElse
    // Stack: periods(0), next_exec(1), interval(2), amt_pp(3), pden(4), pnum(5),
    //        tcid(6), ohash(7), pk(8), sig(9)

    // Verify Blake2b(pk) == owner_hash
    0x58, 0x79,       // Op8 OpPick -> pk copy
    0xaa,             // OpBlake2b
    0x58, 0x79,       // Op8 OpPick -> ohash (d8 in 11-item stack)
    0x87, 0x69,       // OpEqual OpVerify

    // CheckSig
    0x59, 0x7a,       // Op9 OpRoll -> sig to top
    0x59, 0x7a,       // Op9 OpRoll -> pk to top
    0xac, 0x69,       // OpCheckSig OpVerify

    // Cleanup: 8 state items remaining
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x8

    // --- END (2B) ---
    0x68,             // OpEndIf
    0x51,             // Op1 (TRUE)
];

/// Build dca_order redeemScript (315 bytes).
///
/// State (120B):
///   [0x20][owner_hash 32B][0x20][target_cov_id 32B][0x08][price_num 8B]
///   [0x08][price_den 8B][0x08][amount_per_period 8B][0x08][interval_daa 8B]
///   [0x08][next_execution_daa 8B][0x08][periods_remaining 8B]
/// Body (195B): DCA_ORDER_BODY
///
/// # Arguments
/// * `owner_hash` - Blake2b-256 of the owner's Schnorr public key
/// * `target_cov_id` - 32-byte CovenantID of target token to buy
/// * `price_num` - Price numerator
/// * `price_den` - Price denominator
/// * `amount_per_period` - KAS to spend per DCA execution
/// * `interval_daa` - DAA blocks between executions (on-chain enforced)
/// * `next_execution_daa` - Earliest DAA score for next execution (CLTV)
/// * `periods_remaining` - How many periods left (must be > 0 at fill time)
///
/// # Errors
/// Returns error if `price_num`, `price_den`, `amount_per_period`, or `periods_remaining` is 0.
pub fn build_dca_order_redeem_script(
    owner_hash: &[u8; 32],
    target_cov_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    amount_per_period: u64,
    interval_daa: u64,
    next_execution_daa: u64,
    periods_remaining: u64,
) -> crate::Result<Vec<u8>> {
    if price_num == 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den == 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if amount_per_period == 0 {
        return Err(crate::KobError::Contract("amount_per_period must be > 0".into()));
    }
    if periods_remaining == 0 {
        return Err(crate::KobError::Contract("periods_remaining must be > 0".into()));
    }
    if interval_daa == 0 {
        return Err(crate::KobError::Contract("interval_daa must be > 0".into()));
    }
    let mut rs = Vec::with_capacity(305);
    // State (120 bytes) — interval before next_exec and periods
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(target_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(amount_per_period));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(interval_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(next_execution_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(periods_remaining));
    // Body
    rs.extend_from_slice(DCA_ORDER_BODY);
    Ok(rs)
}

/// Build dca_order fill sigscript:
/// `[pushData(new_rs)][pushData(old_rs)][ci_opN][Op1][pushData(RS)]`
///
/// For final fill (periods_remaining == 1 in the consumed UTXO), `old_rs` and `new_rs`
/// can be empty slices — they are pushed but ignored by the script (cleanup only).
///
/// * `continuation_output_idx` - Output index for the continuation UTXO (0..=16)
/// * `old_rs` - The current redeemScript being consumed (for D&R verification)
/// * `new_rs` - The new redeemScript with updated next_exec and periods (for D&R)
/// * `redeem_script` - The redeemScript of the input being spent (same as old_rs)
pub fn build_dca_order_fill_sigscript(
    continuation_output_idx: u8,
    old_rs: &[u8],
    new_rs: &[u8],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(
        3 + old_rs.len() + new_rs.len() + redeem_script.len() + 12,
    );
    ss.extend_from_slice(&push_data(new_rs));
    ss.extend_from_slice(&push_data(old_rs));
    ss.push(opn(continuation_output_idx));
    ss.push(0x51); // Op1 (fill selector)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build dca_order cancel sigscript:
/// `[pushData(sig+type 65B)][pushData(pk 32B)][Op0][pushData(RS)]`
///
/// Owner-initiated cancel.
pub fn build_dca_order_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = [0u8; 65];
    sig_with_type[..64].copy_from_slice(signature);
    sig_with_type[64] = 0x01;

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00); // Op0 (cancel selector)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
