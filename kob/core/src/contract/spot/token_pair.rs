use crate::primitives::u64_le;

/// token_pair_order body bytecode (61 bytes).
///
/// Purpose: Trade Token A for Token B directly (no KAS intermediary).
/// The UTXO holds Token A; on fill, the taker delivers Token B to the owner.
///
/// State (168B):
///   [0x20][pair_id 32B][0x20][owner_hash 32B][0x20][token_a_cov_id 32B]
///   [0x20][token_b_cov_id 32B][0x08][price_num 8B][0x08][price_den 8B]
///   [0x08][min_fill 8B][0x08][amount 8B]
///
/// Stack after state pushes (8 items, depth 0 = top):
///   amount(0), min_fill(1), pden(2), pnum(3), tb_cov(4), ta_cov(5), ohash(6), pid(7)
///
/// Dispatch: Op8 OpRoll selector.
///   selector > 0 (truthy) -> fill
///   selector == 0 (falsy) -> cancel (owner sig)
///
/// Fill path:
///   1. Verify OpInputCovenantId(self) == token_a_cov_id
///   2. expected_b = (input_amount * price_num) / price_den
///   3. Verify expected_b >= min_fill
///   4. Verify output[0].value >= expected_b
///
/// Cancel path:
///   1. Verify Blake2b(pubkey) == owner_hash
///   2. CheckSig
///
/// Fill sigscript:   [Op1] [pushData(RS)]
/// Cancel sigscript: [pushData(sig+type 65B)] [pushData(pk 32B)] [Op0] [pushData(RS)]
///
/// Body = 61B, RS = 168 + 61 = 229 bytes.
pub const TOKEN_PAIR_ORDER_BODY: &[u8] = &[
    // --- DISPATCH (5B) ---
    0x58, 0x7a,       // Op8 OpRoll -> selector to top
    0x00, 0xa0,       // Op0 OpGreaterThan -> clean boolean
    0x63,             // OpIf (truthy = fill)

    // --- FILL PATH (32B) ---
    // Stack: amount(0), mfill(1), pden(2), pnum(3), tb(4), ta(5), ohash(6), pid(7)

    // Verify input covenant == token_a_cov_id
    0xb9, 0xcf,       // OpTxInputIndex, OpInputCovenantId -> my_cov_id
    0x56, 0x79,       // Op6 OpPick -> ta_cov
    0x87, 0x69,       // OpEqual OpVerify (my_cov == ta)

    // expected_b = (input_amount * pnum) / pden
    0xb9, 0xbe,       // OpTxInputIndex, OpTxInputAmount -> fill_amount
    0x54, 0x79, 0x95, // Op4 OpPick(pnum) OpMul
    0x53, 0x79, 0x96, // Op3 OpPick(pden) OpDiv -> expected_b

    // Verify expected_b >= min_fill
    0x76,             // OpDup
    0x53, 0x79,       // Op3 OpPick -> min_fill (d3 in 10-item stack after dup)
    0xa2, 0x69,       // OpGTE OpVerify (expected_b >= min_fill)

    // Verify output[0].value >= expected_b
    0x00, 0xc2,       // Op0 OpTxOutputAmount -> output[0].value
    0x7c,             // OpSwap
    0xa2, 0x69,       // OpGTE OpVerify (out0 >= expected_b)

    // Cleanup: 8 items remaining
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x8

    // --- CANCEL PATH (22B) ---
    0x67,             // OpElse
    // Stack: amount(0), mfill(1), pden(2), pnum(3), tb(4), ta(5), ohash(6), pid(7), pk(8), sig(9)

    // Verify Blake2b(pk) == owner_hash
    0x58, 0x79,       // Op8 OpPick -> pk copy
    0xaa,             // OpBlake2b
    0x57, 0x79,       // Op7 OpPick -> ohash (d7 in 11-item stack after blake2b)
    0x87, 0x69,       // OpEqual OpVerify

    // CheckSig
    0x59, 0x7a,       // Op9 OpRoll -> sig to top
    0x59, 0x7a,       // Op9 OpRoll -> pk to top
    0xac, 0x69,       // OpCheckSig OpVerify

    // Cleanup: 8 items remaining
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x8

    // --- END (2B) ---
    0x68,             // OpEndIf
    0x51,             // Op1 (TRUE)
];

/// Build token_pair_order redeemScript (229 bytes).
///
/// State (168B):
///   [0x20][pair_id 32B][0x20][owner_hash 32B][0x20][token_a_cov_id 32B]
///   [0x20][token_b_cov_id 32B][0x08][price_num 8B][0x08][price_den 8B]
///   [0x08][min_fill 8B][0x08][amount 8B]
/// Body (61B): TOKEN_PAIR_ORDER_BODY
/// # Arguments
/// * `pair_id` - 32-byte hash: blake2b(min(cov_a, cov_b) || max(cov_a, cov_b))
/// * `owner_hash` - Blake2b-256 of the owner's Schnorr public key
/// * `token_a_cov_id` - 32-byte CovenantID of token A (offered)
/// * `token_b_cov_id` - 32-byte CovenantID of token B (wanted)
/// * `price_num` - Price numerator (token_b per token_a)
/// * `price_den` - Price denominator
/// * `min_fill` - Minimum fill amount in token_b units
/// * `amount` - Total token_a amount offered
///
/// # Panics
/// Panics if `price_num`, `price_den`, `min_fill`, or `amount` is 0.
pub fn build_token_pair_order_redeem_script(
    pair_id: &[u8; 32],
    owner_hash: &[u8; 32],
    token_a_cov_id: &[u8; 32],
    token_b_cov_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    amount: u64,
) -> crate::Result<Vec<u8>> {
    if price_num <= 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den <= 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill <= 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0 (zero allows dust griefing)".into()));
    }
    if amount <= 0 {
        return Err(crate::KobError::Contract("amount must be > 0".into()));
    }
    let mut rs = Vec::with_capacity(229);
    // State (168 bytes)
    rs.push(0x20);
    rs.extend_from_slice(pair_id);
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(token_a_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(token_b_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(amount));
    // Body (61 bytes)
    rs.extend_from_slice(TOKEN_PAIR_ORDER_BODY);
    Ok(rs)
}
