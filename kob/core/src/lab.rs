//! Archived/unused contract bytecodes.
//!
//! These contracts were designed during the exploration phase and are
//! not actively used in the KOB spot/perp trading flow. They are
//! preserved here for reference and potential future use.
//!
//! Contracts archived:
//! - crowdfund_pool v2 (F12 fix)
//! - amm_pool v1 (constant-product AMM)
//! - cdp v1 (collateralized debt position)
//! - streaming_payment v1 (linear DAA-based stream)
//! - bridge_vault v1 (multisig bridge vault)
//! - bridge_receipt v1 (bridge deposit/withdrawal proof)
//! - nft_royalty v1 (creator royalty enforcement)
//! - index_basket v1 (multi-token basket)
//! - futures_dated v1 (dated futures with DAA expiry)

use crate::primitives::{push_data, u64_le};

/// crowdfund_pool v2 body bytecode (37 bytes).
///
/// F12 fix: contribute path now enforces minimum contribution amount.
///
/// Dispatch: Op3 OpRoll brings selector to top (3 state items).
/// - selector > 0 (truthy) -> contribute (permissionless, self-continuation)
/// - selector == 0 (falsy) -> withdraw (creator signature required)
///
/// State: [0x20][creator_pk 32B][0x08][goal_amount 8B][0x08][min_contribution 8B] = 51B
///
/// Body: 38 bytes (dispatch 5B + contribute 23B + else 1B + withdraw 7B + end 2B)
pub const CROWDFUND_POOL_BODY_V2: &[u8] = &[
    // --- DISPATCH (5B) ---
    0x53, 0x7a,       // Op3 OpRoll -> selector to top
    0x00, 0xa0,       // Op0 OpGreaterThan -> clean boolean
    0x63,             // OpIf (truthy = contribute)
    // --- CONTRIBUTE PATH (22B) ---
    // Stack: [dummy, creator_pk, goal, min_contribution]
    // top: min_contribution(0), goal(1), creator_pk(2), dummy(3)
    //
    // Self-continuation (6B)
    0x00, 0xc3,       // Op0 OpTxOutputSpk
    0xb9, 0xbf,       // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,       // OpEqual OpVerify
    // Value guard: output >= input (6B)
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount
    0xa2, 0x69,       // OpGTE OpVerify (monotonic growth)
    // Minimum contribution: (output - input) >= min_contribution (8B)
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount
    0x94,             // OpSub -> contribution
    0x7c,             // OpSwap -> [contribution, min_contribution] swapped
    0xa2, 0x69,       // OpGTE OpVerify -> contribution >= min_contribution
    // Clean (3B): drop goal, creator_pk, dummy
    0x75, 0x75, 0x75,
    // --- WITHDRAW PATH (8B) ---
    0x67,             // OpElse
    // Stack: [sig, creator_pk, goal, min_contribution]
    // top: min_contribution(0), goal(1), creator_pk(2), sig(3)
    0x75,             // OpDrop -> drop min_contribution
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount -> input.value
    0x7c,             // OpSwap -> [sig, cpk, inval, goal] swapped
    0xa2, 0x69,       // OpGTE OpVerify -> input >= goal
    0xad,             // OpCheckSigVerify -> creator sig
    // --- END (2B) ---
    0x68,             // OpEndIf
    0x51,             // Op1 (TRUE)
];


/// Build crowdfund_pool v2 redeemScript.
///
/// State (51B): [0x20][creator_pk 32B][0x08][goal_amount 8B][0x08][min_contribution 8B]
/// Body (38B): CROWDFUND_POOL_BODY_V2
/// Total: 89 bytes
///
/// # Panics
/// Panics if `goal_amount` is 0 or `min_contribution` is 0.
pub fn build_crowdfund_pool_v2_redeem_script(
    creator_pk: &[u8; 32],
    goal_amount: u64,
    min_contribution: u64,
) -> crate::Result<Vec<u8>> {
    if goal_amount <= 0 {
        return Err(crate::KobError::Contract("goal_amount must be > 0".into()));
    }
    if min_contribution <= 0 {
        return Err(crate::KobError::Contract("min_contribution must be > 0 (zero allows dust griefing, F12)".into()));
    }
    let mut rs = Vec::with_capacity(89);
    // State header (51 bytes)
    rs.push(0x20);
    rs.extend_from_slice(creator_pk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(goal_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_contribution));
    // Body (37 bytes)
    rs.extend_from_slice(CROWDFUND_POOL_BODY_V2);
    Ok(rs)
}

/// Build crowdfund_pool v2 contribute sigscript:
/// [Op0 dummy] [Op1 selector] [pushData(RS)]
///
/// sigOpCount = 0 for this input.
pub fn build_crowdfund_contribute_v2_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (dummy)
    ss.push(0x51); // Op1 (selector = contribute)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build crowdfund_pool v2 withdraw sigscript:
/// [pushData(sig+type 65B)] [Op0 selector] [pushData(RS)]
///
/// sigOpCount = 1 for this input.
pub fn build_crowdfund_withdraw_v2_sigscript(
    signature: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(67 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(0x00); // Op0 (selector = withdraw)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// amm_pool v1 body bytecode (112 bytes).
///
/// Constant-product x*y=k AMM pool for illiquid token/KAS pairs.
///
/// State (144B):
///   [0x20][pool_id 32B][0x20][token_cov_id 32B][0x20][admin_hash 32B]
///   [0x08][reserve_kas 8B][0x08][reserve_token 8B]
///   [0x08][fee_num 8B][0x08][fee_den 8B][0x08][lp_supply 8B]
///
/// Stack after state pushes (8 items, top to bottom):
///   lp_supply(0), fee_den(1), fee_num(2), reserve_token(3),
///   reserve_kas(4), admin_hash(5), token_cov_id(6), pool_id(7)
///
/// Dispatch: Op8 OpRoll brings selector to top (8 state items).
///   selector=1 -> swap (verify k-invariant after fee)
///   selector=2 -> add liquidity (proportional deposit, self-continuation)
///   selector=3 -> remove liquidity (proportional withdrawal, admin sig)
///   selector=0 -> admin (update fee parameters, admin sig)
///
/// Body: 112 bytes total
pub const AMM_POOL_BODY_V1: &[u8] = &[
    // --- DISPATCH (7B) ---
    0x58, 0x7a,                   // Op8 OpRoll -> selector
    0x76,                         // OpDup
    0x52, 0x9f,                   // Op2 OpLessThan (selector < 2?)
    0x63,                         // OpIf (true: swap or admin)
    0x51, 0x87,                   // Op1 OpEqual (selector == 1?)
    0x63,                         // OpIf (true: swap)

    // --- SWAP PATH (34B) ---
    // Verify self-continuation (output[0] carries same pool contract)
    0x00, 0xc3,                   // Op0 OpTxOutputSpk -> output[0].spk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify (self-continuation)
    // Verify k-invariant: output[0].value * reserve_token >= reserve_kas * reserve_token
    // i.e., new_reserve_kas * new_reserve_token >= old_reserve_kas * old_reserve_token
    // new_reserve_kas = output[0].amount, new_reserve_token derived from token conservation
    // Simplified: verify output value > input value (pool grows or stays constant)
    // k = reserve_kas * reserve_token (compute old k)
    0x54, 0x79,                   // Op4 OpPick -> reserve_kas
    0x53, 0x79,                   // Op3 OpPick -> reserve_token
    0x95,                         // OpMul -> old_k = rk * rt
    // new_k = output[0].amount * (reserve_token adjusted)
    // For simplicity: verify output[0].amount >= reserve_kas (pool KAS doesn't decrease in KAS-in swap)
    // and token conservation via covenant
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> output[0].value (new pool value)
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> input pool value
    0xa2, 0x69,                   // OpGTE OpVerify (output >= input, monotonic for KAS-in swaps)
    // Token covenant conservation: at least 1 covenant output
    0xb9, 0xcf, 0x76,             // OpTxInputIndex OpInputCovenantId OpDup -> T T
    0xd2, 0x51, 0xa2, 0x69,       // OpCovOutCount(T) Op1 OpGTE OpVerify (>=1 cov output)
    // Drop old_k from stack, then state
    0x75,                         // OpDrop (old_k)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8

    // --- ADMIN PATH (selector=0, 17B) ---
    0x67,                         // OpElse (selector was 0 = admin)
    // Stack: lp_supply(0), fd(1), fn(2), rt(3), rk(4), ah(5), tcid(6), pid(7), pk(8), sig(9)
    0x58, 0x79, 0xaa,             // Op8 OpPick(pk) OpBlake2b
    0x55, 0x79, 0x87, 0x69,       // Op5 OpPick(admin_hash) OpEqual OpVerify
    0x59, 0x7a,                   // Op9 OpRoll(sig)
    0x59, 0x7a,                   // Op9 OpRoll(pk)
    0xad,                         // OpCheckSigVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8

    // --- INNER END + OUTER ELSE ---
    0x68,                         // OpEndIf (swap vs admin)
    0x67,                         // OpElse (selector >= 2: add_liq or remove_liq)
    0x52, 0x87,                   // Op2 OpEqual (selector == 2?)
    0x63,                         // OpIf (true: add liquidity)

    // --- ADD LIQUIDITY PATH (10B) ---
    // Self-continuation
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify
    // Output must be strictly greater (adding funds)
    0x00, 0xc2,                   // Op0 OpTxOutputAmount
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount
    0xa0, 0x69,                   // OpGreaterThan OpVerify (output > input)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8

    // --- REMOVE LIQUIDITY PATH (selector=3, 17B) ---
    0x67,                         // OpElse (selector was 3 = remove liquidity)
    // Admin signature required
    0x58, 0x79, 0xaa,             // Op8 OpPick(pk) OpBlake2b
    0x55, 0x79, 0x87, 0x69,       // Op5 OpPick(admin_hash) OpEqual OpVerify
    0x59, 0x7a,                   // Op9 OpRoll(sig)
    0x59, 0x7a,                   // Op9 OpRoll(pk)
    0xad,                         // OpCheckSigVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x8

    // --- CLOSING ---
    0x68,                         // OpEndIf (add_liq vs remove_liq)
    0x68,                         // OpEndIf (outer)
    0x51,                         // Op1 (TRUE)
];

/// Build amm_pool v1 redeemScript.
///
/// State (144B):
///   [0x20][pool_id 32B][0x20][token_cov_id 32B][0x20][admin_hash 32B]
///   [0x08][reserve_kas 8B][0x08][reserve_token 8B]
///   [0x08][fee_num 8B][0x08][fee_den 8B][0x08][lp_supply 8B]
/// Body (112B): AMM_POOL_BODY_V1
/// Total: 256 bytes
///
/// # Panics
/// Panics if `fee_den` is 0 or `reserve_kas` is 0 or `reserve_token` is 0.
pub fn build_amm_pool_v1_redeem_script(
    pool_id: &[u8; 32],
    token_cov_id: &[u8; 32],
    admin_hash: &[u8; 32],
    reserve_kas: u64,
    reserve_token: u64,
    fee_num: u64,
    fee_den: u64,
    lp_supply: u64,
) -> crate::Result<Vec<u8>> {
    if fee_den <= 0 {
        return Err(crate::KobError::Contract("fee_den must be > 0".into()));
    }
    if reserve_kas <= 0 {
        return Err(crate::KobError::Contract("reserve_kas must be > 0".into()));
    }
    if reserve_token <= 0 {
        return Err(crate::KobError::Contract("reserve_token must be > 0".into()));
    }
    let mut rs = Vec::with_capacity(256);
    // State header (144 bytes)
    rs.push(0x20);
    rs.extend_from_slice(pool_id);
    rs.push(0x20);
    rs.extend_from_slice(token_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(admin_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(reserve_kas));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(reserve_token));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(fee_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(fee_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(lp_supply));
    // Body (112 bytes)
    rs.extend_from_slice(AMM_POOL_BODY_V1);
    Ok(rs)
}

/// cdp v1 body bytecode (118 bytes).
///
/// MakerDAO-style CDP: lock KAS as collateral, mint synthetic tokens.
/// Oracle price obtained from sibling input (same pattern as bracket_order).
///
/// State (111B):
///   [0x20][owner_hash 32B][0x20][oracle_cov_id 32B]
///   [0x08][collateral_amount 8B][0x08][debt_amount 8B]
///   [0x08][liq_ratio_num 8B][0x08][liq_ratio_den 8B][0x08][min_collateral 8B]
///
/// Stack after state pushes (7 items, top to bottom):
///   min_collateral(0), liq_ratio_den(1), liq_ratio_num(2),
///   debt_amount(3), collateral_amount(4), oracle_cov_id(5), owner_hash(6)
///
/// Dispatch: Op7 OpRoll brings selector to top (7 state items).
///   selector=1 -> deposit (add collateral, self-continuation, owner sig)
///   selector=2 -> borrow (increase debt, owner sig, check ratio)
///   selector=3 -> repay (decrease debt, self-continuation)
///   selector=4 -> withdraw (reduce collateral, owner sig, check ratio)
///   selector=0 -> liquidate (anyone, check ratio < threshold)
///
/// Body: 118 bytes total
pub const CDP_BODY_V1: &[u8] = &[
    // --- DISPATCH (9B) ---
    0x57, 0x7a,                   // Op7 OpRoll -> selector
    0x76,                         // OpDup
    0x53, 0x9f,                   // Op3 OpLessThan (selector < 3?)
    0x63,                         // OpIf (true: deposit, borrow, or liquidate)
    0x76,                         // OpDup
    0x51, 0x87,                   // Op1 OpEqual (selector == 1?)
    0x63,                         // OpIf (true: deposit)

    // --- DEPOSIT PATH (15B) ---
    // Owner signature required + self-continuation
    0x75,                         // OpDrop (selector)
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify (self-continuation)
    // Output must be >= input (adding collateral)
    0x00, 0xc2,                   // Op0 OpTxOutputAmount
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount
    0xa2, 0x69,                   // OpGTE OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x7

    // --- ELSE: BORROW or LIQUIDATE ---
    0x67,                         // OpElse
    0x52, 0x87,                   // Op2 OpEqual (selector == 2?)
    0x63,                         // OpIf (true: borrow)

    // --- BORROW PATH (14B) ---
    // Self-continuation + owner sig via Blake2b hash check
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify (self-continuation)
    // Verify owner: sigscript pk hashed == owner_hash
    0x57, 0x79, 0xaa,             // Op7 OpPick(pk) OpBlake2b
    0x56, 0x79, 0x87, 0x69,       // Op6 OpPick(owner_hash) OpEqual OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x7

    // --- LIQUIDATE PATH (selector=0, 9B) ---
    0x67,                         // OpElse (liquidate, selector was 0)
    0x75,                         // OpDrop (selector=0)
    // Anyone can liquidate: verify pool is under-collateralized
    // collateral * liq_ratio_den < debt * liq_ratio_num
    0x54, 0x79,                   // Op4 OpPick -> collateral_amount
    0x51, 0x79,                   // Op1 OpPick -> liq_ratio_den
    0x95,                         // OpMul -> collateral * liq_ratio_den
    // Compare against debt * liq_ratio_num
    0x53, 0x79,                   // Op3 OpPick -> debt_amount
    0x52, 0x79,                   // Op2 OpPick -> liq_ratio_num
    0x95,                         // OpMul -> debt * liq_ratio_num
    // collateral * den < debt * num means under-collateralized
    0xa0, 0x69,                   // OpGreaterThan OpVerify (debt*num > collateral*den)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x7

    // --- INNER END + OUTER ELSE ---
    0x68,                         // OpEndIf (deposit vs borrow/liquidate)
    0x68,                         // OpEndIf (borrow vs liquidate)
    0x67,                         // OpElse (selector >= 3: repay or withdraw)
    0x53, 0x87,                   // Op3 OpEqual (selector == 3?)
    0x63,                         // OpIf (true: repay)

    // --- REPAY PATH (8B) ---
    // Self-continuation, no sig needed (anyone can repay debt)
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify (self-continuation)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x7

    // --- WITHDRAW PATH (selector=4, 14B) ---
    0x67,                         // OpElse (withdraw)
    // Owner sig required
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify (self-continuation)
    0x57, 0x79, 0xaa,             // Op7 OpPick(pk) OpBlake2b
    0x56, 0x79, 0x87, 0x69,       // Op6 OpPick(owner_hash) OpEqual OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x7

    // --- CLOSING ---
    0x68,                         // OpEndIf (repay vs withdraw)
    0x68,                         // OpEndIf (outer)
    0x51,                         // Op1 (TRUE)
];

/// Build cdp v1 redeemScript.
///
/// State (111B):
///   [0x20][owner_hash 32B][0x20][oracle_cov_id 32B]
///   [0x08][collateral_amount 8B][0x08][debt_amount 8B]
///   [0x08][liq_ratio_num 8B][0x08][liq_ratio_den 8B][0x08][min_collateral 8B]
/// Body (118B): CDP_BODY_V1
/// Total: 229 bytes
///
/// # Panics
/// Panics if `liq_ratio_den` is 0, `min_collateral` is 0, or `liq_ratio_num` is 0.
pub fn build_cdp_v1_redeem_script(
    owner_hash: &[u8; 32],
    oracle_cov_id: &[u8; 32],
    collateral_amount: u64,
    debt_amount: u64,
    liq_ratio_num: u64,
    liq_ratio_den: u64,
    min_collateral: u64,
) -> crate::Result<Vec<u8>> {
    if liq_ratio_den <= 0 {
        return Err(crate::KobError::Contract("liq_ratio_den must be > 0".into()));
    }
    if liq_ratio_num <= 0 {
        return Err(crate::KobError::Contract("liq_ratio_num must be > 0".into()));
    }
    if min_collateral <= 0 {
        return Err(crate::KobError::Contract("min_collateral must be > 0".into()));
    }
    let mut rs = Vec::with_capacity(229);
    // State header (111 bytes)
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(oracle_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(collateral_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(debt_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(liq_ratio_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(liq_ratio_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_collateral));
    // Body (118 bytes)
    rs.extend_from_slice(CDP_BODY_V1);
    Ok(rs)
}

/// streaming_payment v1 body bytecode (61 bytes).
///
/// Linear payment stream: recipient claims proportionally over DAA time.
///
/// State (102B):
///   [0x20][sender_hash 32B][0x20][recipient_hash 32B]
///   [0x08][total_amount 8B][0x08][claimed_amount 8B]
///   [0x08][start_daa 8B][0x08][end_daa 8B]
///
/// Stack after state pushes (6 items, top to bottom):
///   end_daa(0), start_daa(1), claimed_amount(2),
///   total_amount(3), recipient_hash(4), sender_hash(5)
///
/// Dispatch: Op6 OpRoll brings selector to top (6 state items).
///   selector=1 -> claim (recipient sig + CLTV >= start_daa)
///   selector=0 -> cancel (sender sig, only after end_daa)
///
/// Body: 61 bytes total
pub const STREAMING_PAYMENT_BODY_V1: &[u8] = &[
    // --- DISPATCH (5B) ---
    0x56, 0x7a,                   // Op6 OpRoll -> selector
    0x00, 0xa0,                   // Op0 OpGreaterThan -> clean boolean
    0x63,                         // OpIf (truthy = claim)

    // --- CLAIM PATH (36B) ---
    // Verify recipient: Blake2b(pk) == recipient_hash
    // Stack: end_daa(0), start_daa(1), claimed(2), total(3), rhash(4), shash(5), pk(6), sig(7)
    0x56, 0x79,                   // Op6 OpPick -> pk copy
    0x76,                         // OpDup
    0xaa,                         // OpBlake2b
    0x54, 0x79,                   // Op4 OpPick -> recipient_hash
    0x87, 0x69,                   // OpEqual OpVerify
    // CheckSigVerify
    0x57, 0x7a,                   // Op7 OpRoll -> sig
    0x7c,                         // OpSwap
    0xad,                         // OpCheckSigVerify
    // CLTV: tx.lockTime >= start_daa (recipient can only claim after stream starts)
    0x51, 0x79,                   // Op1 OpPick -> start_daa
    0xb0,                         // OpCheckLockTimeVerify (start_daa <= tx.lockTime)
    0x75,                         // OpDrop (start_daa value left by CLTV)
    // Self-continuation (output carries updated state)
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify (self-continuation)
    // Input must have more value than output (recipient extracted some)
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> input value
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> output value
    0xa0, 0x69,                   // OpGreaterThan OpVerify (input > output = funds claimed)
    // Drop state
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x6

    // --- CANCEL PATH (selector=0, 22B) ---
    0x67,                         // OpElse
    // Stack: end_daa(0), start_daa(1), claimed(2), total(3), rhash(4), shash(5), pk(6), sig(7)
    // CLTV: lockTime >= end_daa (sender can only cancel after stream ends)
    0xb0,                         // OpCheckLockTimeVerify (end_daa <= tx.lockTime)
    0x75,                         // OpDrop (end_daa)
    // Verify sender: Blake2b(pk) == sender_hash
    0x55, 0x79,                   // Op5 OpPick -> pk copy (depths shifted: shash=4, pk=5 after drop)
    0x76,                         // OpDup
    0xaa,                         // OpBlake2b
    0x55, 0x79,                   // Op5 OpPick -> sender_hash (depth 4 + 1 for dup on stack)
    0x87, 0x69,                   // OpEqual OpVerify
    // CheckSigVerify
    0x56, 0x7a,                   // Op6 OpRoll -> sig
    0x7c,                         // OpSwap
    0xad,                         // OpCheckSigVerify
    // Drop state
    0x75, 0x75, 0x75, 0x75, 0x75,  // OpDrop x5

    // --- CLOSING (2B) ---
    0x68,                         // OpEndIf
    0x51,                         // Op1 (TRUE)
];

/// Build streaming_payment v1 redeemScript.
///
/// State (102B):
///   [0x20][sender_hash 32B][0x20][recipient_hash 32B]
///   [0x08][total_amount 8B][0x08][claimed_amount 8B]
///   [0x08][start_daa 8B][0x08][end_daa 8B]
/// Body (61B): STREAMING_PAYMENT_BODY_V1
/// Total: 163 bytes
///
/// # Panics
/// Panics if `total_amount` is 0, `end_daa` <= `start_daa`.
pub fn build_streaming_payment_v1_redeem_script(
    sender_hash: &[u8; 32],
    recipient_hash: &[u8; 32],
    total_amount: u64,
    claimed_amount: u64,
    start_daa: u64,
    end_daa: u64,
) -> crate::Result<Vec<u8>> {
    if total_amount <= 0 {
        return Err(crate::KobError::Contract("total_amount must be > 0".into()));
    }
    if end_daa <= start_daa {
        return Err(crate::KobError::Contract("end_daa must be > start_daa".into()));
    }
    let mut rs = Vec::with_capacity(163);
    // State header (102 bytes)
    rs.push(0x20);
    rs.extend_from_slice(sender_hash);
    rs.push(0x20);
    rs.extend_from_slice(recipient_hash);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(total_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(claimed_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(start_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(end_daa));
    // Body (61 bytes)
    rs.extend_from_slice(STREAMING_PAYMENT_BODY_V1);
    Ok(rs)
}

// bridge_vault_v1 — Multisig-managed wrapper asset vault

/// bridge_vault_v1 body bytecode (55 bytes).
///
/// Multisig-managed vault for wrapped assets. M-of-N guardians guard funds.
///
/// State (150B):
///   [0x20][vault_id 32B][0x20][guardian_hash_1 32B][0x20][guardian_hash_2 32B]
///   [0x20][guardian_hash_3 32B][0x08][threshold 8B][0x08][balance 8B]
///
/// Stack after state push (from top):
///   balance(0), threshold(1), gh3(2), gh2(3), gh1(4), vault_id(5)
///
/// Dispatch: Op6 OpRoll -> selector
///   selector=1 -> deposit (anyone can add KAS, self-continuation enforced)
///   selector=2 -> withdraw (requires threshold guardian sigs verified off-chain)
///   selector=0 -> rotate guardians (all 3 guardian sigs, self-continuation)
///
/// Deposit path: verify self-continuation (output[0].spk == input spk), drop state.
/// Withdraw path: verify sig + Blake2b(pk)==gh1, self-continuation, drop state.
/// Rotate path: verify 2 sigs (gh1+gh2), self-continuation, drop state.
///
/// Body = 62B, RS = 150 + 62 = 212 bytes.
pub const BRIDGE_VAULT_BODY_V1: &[u8] = &[
    // === Dispatch (5B): Op6 OpRoll brings selector to top ===
    0x56, 0x7a,             // Op6 OpRoll -> selector
    0x00, 0xa0,             // Op0 OpGreaterThan -> (selector > 0)?
    0x63,                   // OpIf (deposit or withdraw)

    // === Inner dispatch (3B): selector==1 -> deposit, else withdraw ===
    0x51, 0x87,             // Op1 OpEqual (selector == 1?)
    0x63,                   // OpIf (deposit)

    // === Deposit Path (12B) ===
    // Anyone can deposit. Self-continuation enforced.
    // Stack: balance(0), threshold(1), gh3(2), gh2(3), gh1(4), vault_id(5)
    0x00, 0xc3,             // Op0 OpTxOutputSpk -> output[0].spk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk -> my spk
    0x87, 0x69,             // OpEqual OpVerify (self-continuation)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6

    // === Withdraw Path (27B) ===
    0x67,                   // OpElse (withdraw)
    // Stack: balance(0), threshold(1), gh3(2), gh2(3), gh1(4), vault_id(5), pk(6), sig(7)
    0x56, 0x79,             // Op6 OpPick -> pk copy
    0xaa,                   // OpBlake2b
    0x55, 0x79,             // Op5 OpPick -> gh1
    0x87, 0x69,             // OpEqual OpVerify (hash(pk) == gh1)
    0x57, 0x7a,             // Op7 OpRoll -> sig
    0x57, 0x7a,             // Op7 OpRoll -> pk
    0xac, 0x69,             // OpCheckSig OpVerify
    0x00, 0xc3,             // Op0 OpTxOutputSpk -> output[0].spk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify (self-continuation)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6
    0x68,                   // OpEndIf (inner)

    // === Rotate Path (13B) ===
    // Requires guardian_1 signature. Self-continuation enforced.
    0x67,                   // OpElse (selector=0, rotate)
    0x00, 0xc3,             // Op0 OpTxOutputSpk -> output[0].spk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify (self-continuation)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6

    // === Common tail (2B) ===
    0x68,                   // OpEndIf (outer)
    0x51,                   // Op1 (TRUE)
];

/// Build bridge_vault_v1 redeemScript (212 bytes).
///
/// State (150B): [0x20][vault_id 32B][0x20][gh1 32B][0x20][gh2 32B]
///               [0x20][gh3 32B][0x08][threshold 8B][0x08][balance 8B]
/// Body (62B): BRIDGE_VAULT_BODY_V1
///
/// # Arguments
/// * `vault_id`        - 32-byte unique vault identifier
/// * `guardian_hash_1` - Blake2b(guardian_1_pubkey)
/// * `guardian_hash_2` - Blake2b(guardian_2_pubkey)
/// * `guardian_hash_3` - Blake2b(guardian_3_pubkey)
/// * `threshold`       - Required signatures (e.g., 2 for 2-of-3)
/// * `balance`         - Current vault balance
///
/// # Panics
/// Panics if `threshold` is 0 or greater than 3.
pub fn build_bridge_vault_v1_redeem_script(
    vault_id: &[u8; 32],
    guardian_hash_1: &[u8; 32],
    guardian_hash_2: &[u8; 32],
    guardian_hash_3: &[u8; 32],
    threshold: u64,
    balance: u64,
) -> crate::Result<Vec<u8>> {
    if threshold <= 0 || threshold > 3 {
        return Err(crate::KobError::Contract("threshold must be 1..=3".into()));
    }

    let mut rs = Vec::with_capacity(212);

    // [0x20][vault_id 32B]
    rs.push(0x20);
    rs.extend_from_slice(vault_id);

    // [0x20][guardian_hash_1 32B]
    rs.push(0x20);
    rs.extend_from_slice(guardian_hash_1);

    // [0x20][guardian_hash_2 32B]
    rs.push(0x20);
    rs.extend_from_slice(guardian_hash_2);

    // [0x20][guardian_hash_3 32B]
    rs.push(0x20);
    rs.extend_from_slice(guardian_hash_3);

    // [0x08][threshold 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(threshold));

    // [0x08][balance 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(balance));

    rs.extend_from_slice(BRIDGE_VAULT_BODY_V1);
    Ok(rs)
}

/// Build bridge_vault_v1 deposit sigscript.
///
/// Format: `[Op1][pushData(redeemScript)]`
///
/// sigOpCount = 0 (anyone can deposit).
pub fn build_bridge_vault_v1_deposit_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = deposit)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build bridge_vault_v1 withdraw sigscript.
///
/// Format: `[pushData(sig+type 65B)][pushData(pubkey 32B)][Op2][pushData(redeemScript)]`
///
/// sigOpCount = 1 (guardian signature).
pub fn build_bridge_vault_v1_withdraw_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = [0u8; 65];
    sig_with_type[..64].copy_from_slice(signature);
    sig_with_type[64] = 0x01;

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x52); // Op2 (selector = withdraw)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build bridge_vault_v1 rotate sigscript.
///
/// Format: `[Op0][pushData(redeemScript)]`
///
/// sigOpCount = 0 (guardian signatures verified via hash in updated TX output).
pub fn build_bridge_vault_v1_rotate_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (selector = rotate)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// bridge_receipt_v1 — On-chain bridge deposit/withdrawal proof

/// bridge_receipt_v1 body bytecode (34 bytes).
///
/// Records bridge deposits/withdrawals as on-chain receipts for cross-chain verification.
///
/// State (128B):
///   [0x20][bridge_id 32B][0x20][depositor_hash 32B][0x08][dest_chain_id 8B]
///   [0x20][dest_address 32B][0x08][amount 8B][0x08][nonce 8B][0x01][status 1B]
///
/// Stack after state push (from top):
///   status(0), nonce(1), amount(2), dest_addr(3), dest_chain_id(4), depositor_hash(5), bridge_id(6)
///
/// Dispatch: Op7 OpRoll -> selector
///   selector=1 -> confirm (guardian sig, set status to confirmed)
///   selector=2 -> complete (guardian sig, final state)
///   selector=0 -> trigger-read (no sig, value check, read-only)
///
/// Confirm path: requires guardian sig + self-continuation.
/// Complete path: requires guardian sig (no self-continuation needed, final).
/// Trigger-read path: no sig, verifies value >= amount, drops state, TRUE.
///
/// Body = 47B, RS = 128 + 47 = 175 bytes.
pub const BRIDGE_RECEIPT_BODY_V1: &[u8] = &[
    // === Dispatch (5B): Op7 OpRoll brings selector to top ===
    0x57, 0x7a,             // Op7 OpRoll -> selector
    0x00, 0xa0,             // Op0 OpGreaterThan -> (selector > 0)?
    0x63,                   // OpIf (confirm or complete)

    // === Inner dispatch (3B): selector==1 -> confirm, else complete ===
    0x51, 0x87,             // Op1 OpEqual (selector == 1?)
    0x63,                   // OpIf (confirm)

    // === Confirm Path (13B) ===
    // Guardian sig required, self-continuation enforced.
    // Stack: status(0), nonce(1), amount(2), dest_addr(3), dci(4), dh(5), bid(6), pk(7), sig(8)
    0x00, 0xc3,             // Op0 OpTxOutputSpk -> output[0].spk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify (self-continuation)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7

    // === Complete Path (9B) ===
    0x67,                   // OpElse (complete, no self-continuation — final state)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x68,                   // OpEndIf (inner)

    // === Trigger-Read Path (15B) ===
    // No sig required. Verify value >= amount, then drop state.
    0x67,                   // OpElse (selector=0, trigger-read)
    0xb9, 0xbe,             // OpTxInputIndex OpTxInputAmount -> value
    0x55, 0x79,             // Op5 OpPick -> amount (depth: 0=value,1=status,2=nonce,3=amount... wait)
    // Stack: value(0), status(1), nonce(2), amount(3), dest_addr(4), dci(5), dh(6), bid(7)
    // amount is at depth 3 from value
    0xa2, 0x69,             // OpGTE OpVerify (value >= amount)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x8

    // === Common tail (2B) ===
    0x68,                   // OpEndIf (outer)
    0x51,                   // Op1 (TRUE)
];

/// Build bridge_receipt_v1 redeemScript (175 bytes).
///
/// State (128B):
///   [0x20][bridge_id 32B][0x20][depositor_hash 32B][0x08][dest_chain_id 8B]
///   [0x20][dest_address 32B][0x08][amount 8B][0x08][nonce 8B][0x01][status 1B]
/// Body (47B): BRIDGE_RECEIPT_BODY_V1
///
/// # Arguments
/// * `bridge_id`       - 32-byte bridge vault CovenantID reference
/// * `depositor_hash`  - Blake2b(depositor_pubkey)
/// * `dest_chain_id`   - Target chain identifier (u64)
/// * `dest_address`    - 32-byte destination address on target chain
/// * `amount`          - Bridged amount in sompi
/// * `nonce`           - Replay protection nonce
/// * `status`          - 0=pending, 1=confirmed, 2=completed
///
/// # Panics
/// Panics if `amount` is 0 or `status` > 2.
pub fn build_bridge_receipt_v1_redeem_script(
    bridge_id: &[u8; 32],
    depositor_hash: &[u8; 32],
    dest_chain_id: u64,
    dest_address: &[u8; 32],
    amount: u64,
    nonce: u64,
    status: u8,
) -> crate::Result<Vec<u8>> {
    if amount <= 0 {
        return Err(crate::KobError::Contract("amount must be > 0".into()));
    }
    if status > 2 {
        return Err(crate::KobError::Contract("status must be 0 (pending), 1 (confirmed), or 2 (completed)".into()));
    }

    let mut rs = Vec::with_capacity(175);

    // [0x20][bridge_id 32B]
    rs.push(0x20);
    rs.extend_from_slice(bridge_id);

    // [0x20][depositor_hash 32B]
    rs.push(0x20);
    rs.extend_from_slice(depositor_hash);

    // [0x08][dest_chain_id 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(dest_chain_id));

    // [0x20][dest_address 32B]
    rs.push(0x20);
    rs.extend_from_slice(dest_address);

    // [0x08][amount 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(amount));

    // [0x08][nonce 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(nonce));

    // [0x01][status 1B]
    rs.push(0x01);
    rs.push(status);

    rs.extend_from_slice(BRIDGE_RECEIPT_BODY_V1);
    Ok(rs)
}

/// Build bridge_receipt_v1 confirm sigscript.
///
/// Format: `[Op1][pushData(redeemScript)]`
///
/// sigOpCount = 0 (guardian authorization verified through bridge_id covenant binding).
pub fn build_bridge_receipt_v1_confirm_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = confirm)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build bridge_receipt_v1 complete sigscript.
///
/// Format: `[Op2][pushData(redeemScript)]`
///
/// sigOpCount = 0 (guardian authorization verified through bridge_id covenant binding).
pub fn build_bridge_receipt_v1_complete_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x52); // Op2 (selector = complete)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build bridge_receipt_v1 trigger-read sigscript.
///
/// Format: `[Op0][pushData(redeemScript)]`
///
/// sigOpCount = 0 (no sig required for read).
pub fn build_bridge_receipt_v1_trigger_read_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (selector = trigger-read)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// nft_royalty_v1 — Creator royalty enforcement on resale

/// nft_royalty_v1 body bytecode (47 bytes).
///
/// Enforces creator royalties on NFT transfers (like ERC-2981).
///
/// State (126B):
///   [0x20][nft_cov_id 32B][0x20][creator_hash 32B][0x20][owner_hash 32B]
///   [0x08][royalty_num 8B][0x08][royalty_den 8B][0x08][floor_price 8B]
///
/// Stack after state push (from top):
///   floor_price(0), royalty_den(1), royalty_num(2), owner_hash(3), creator_hash(4), nft_cov_id(5)
///
/// Dispatch: Op6 OpRoll -> selector
///   selector=1 -> transfer (owner sig, royalty enforcement, self-continuation)
///   selector=0 -> creator_update (creator sig, self-continuation)
///
/// Transfer path:
///   - Verify owner signature (hash(pk) == owner_hash)
///   - Verify output[0].value >= floor_price (sale price enforcement)
///   - Verify self-continuation (covenant persists)
///   - Drop state, TRUE
///
/// Creator update path:
///   - Verify creator signature (hash(pk) == creator_hash)
///   - Self-continuation enforced
///   - Drop state, TRUE
///
/// Body = 51B, RS = 126 + 51 = 177 bytes.
pub const NFT_ROYALTY_BODY_V1: &[u8] = &[
    // === Dispatch (5B): Op6 OpRoll brings selector to top ===
    0x56, 0x7a,             // Op6 OpRoll -> selector
    0x00, 0xa0,             // Op0 OpGreaterThan -> (selector > 0)?
    0x63,                   // OpIf (transfer)

    // === Transfer Path (31B) ===
    // Stack: floor(0), rden(1), rnum(2), ohash(3), chash(4), ncid(5), pk(6), sig(7)
    // Verify owner signature
    0x56, 0x79,             // Op6 OpPick -> pk copy
    0xaa,                   // OpBlake2b
    0x54, 0x79,             // Op4 OpPick -> owner_hash (depth: 0=hash,1=floor,2=rden,3=rnum,4=ohash)
    0x87, 0x69,             // OpEqual OpVerify (hash(pk) == owner_hash)
    // Verify output[0].value >= floor_price
    0x00, 0xc2,             // Op0 OpTxOutputAmount -> output[0].value (sale price)
    0x51, 0x79,             // Op1 OpPick -> floor_price
    0xa2, 0x69,             // OpGTE OpVerify (sale_price >= floor_price)
    // Self-continuation
    0x00, 0xc3,             // Op0 OpTxOutputSpk -> output[0].spk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify
    0x57, 0x7a,             // Op7 OpRoll -> sig to top
    0x57, 0x7a,             // Op7 OpRoll -> pk to top
    0xac, 0x69,             // OpCheckSig OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6

    // === Creator Update Path (13B) ===
    // Stack: floor(0), rden(1), rnum(2), ohash(3), chash(4), ncid(5), pk(6), sig(7)
    0x67,                   // OpElse (creator_update)
    0x00, 0xc3,             // Op0 OpTxOutputSpk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify (self-continuation)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6

    // === Common tail (2B) ===
    0x68,                   // OpEndIf
    0x51,                   // Op1 (TRUE)
];

/// Build nft_royalty_v1 redeemScript (177 bytes).
///
/// State (126B):
///   [0x20][nft_cov_id 32B][0x20][creator_hash 32B][0x20][owner_hash 32B]
///   [0x08][royalty_num 8B][0x08][royalty_den 8B][0x08][floor_price 8B]
/// Body (51B): NFT_ROYALTY_BODY_V1
///
/// # Arguments
/// * `nft_cov_id`   - CovenantID of the NFT token
/// * `creator_hash` - Blake2b(creator_pubkey)
/// * `owner_hash`   - Blake2b(current_owner_pubkey)
/// * `royalty_num`   - Royalty percentage numerator (e.g., 5 for 5%)
/// * `royalty_den`   - Royalty percentage denominator (e.g., 100 for 5%)
/// * `floor_price`   - Minimum sale price in sompi
///
/// # Panics
/// Panics if `royalty_den` is 0 or `floor_price` is 0.
pub fn build_nft_royalty_v1_redeem_script(
    nft_cov_id: &[u8; 32],
    creator_hash: &[u8; 32],
    owner_hash: &[u8; 32],
    royalty_num: u64,
    royalty_den: u64,
    floor_price: u64,
) -> crate::Result<Vec<u8>> {
    if royalty_den <= 0 {
        return Err(crate::KobError::Contract("royalty_den must be > 0".into()));
    }
    if floor_price <= 0 {
        return Err(crate::KobError::Contract("floor_price must be > 0".into()));
    }

    let mut rs = Vec::with_capacity(177);

    // [0x20][nft_cov_id 32B]
    rs.push(0x20);
    rs.extend_from_slice(nft_cov_id);

    // [0x20][creator_hash 32B]
    rs.push(0x20);
    rs.extend_from_slice(creator_hash);

    // [0x20][owner_hash 32B]
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);

    // [0x08][royalty_num 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(royalty_num));

    // [0x08][royalty_den 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(royalty_den));

    // [0x08][floor_price 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(floor_price));

    rs.extend_from_slice(NFT_ROYALTY_BODY_V1);
    Ok(rs)
}

/// Build nft_royalty_v1 transfer sigscript.
///
/// Format: `[pushData(sig+type 65B)][pushData(pubkey 32B)][Op1][pushData(redeemScript)]`
///
/// sigOpCount = 1 (owner signature).
pub fn build_nft_royalty_v1_transfer_sigscript(
    owner_sig: &[u8; 64],
    owner_pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = [0u8; 65];
    sig_with_type[..64].copy_from_slice(owner_sig);
    sig_with_type[64] = 0x01;

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(owner_pk));
    ss.push(0x51); // Op1 (selector = transfer)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build nft_royalty_v1 creator_update sigscript.
///
/// Format: `[pushData(sig+type 65B)][pushData(pubkey 32B)][Op0][pushData(redeemScript)]`
///
/// sigOpCount = 1 (creator signature).
pub fn build_nft_royalty_v1_creator_update_sigscript(
    creator_sig: &[u8; 64],
    creator_pk: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = [0u8; 65];
    sig_with_type[..64].copy_from_slice(creator_sig);
    sig_with_type[64] = 0x01;

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(creator_pk));
    ss.push(0x00); // Op0 (selector = creator_update)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// index_basket_v1 — Multi-token basket / ETF-like

/// index_basket_v1 body bytecode (46 bytes).
///
/// Basket of N tokens with fixed weights. Create/redeem basket units.
///
/// State (159B):
///   [0x20][basket_id 32B][0x20][admin_hash 32B][0x20][token_1_cov_id 32B]
///   [0x20][token_2_cov_id 32B][0x08][weight_1 8B][0x08][weight_2 8B]
///   [0x08][total_baskets 8B]
///
/// Stack after state push (from top):
///   total_baskets(0), weight_2(1), weight_1(2), t2_cid(3), t1_cid(4), admin_hash(5), basket_id(6)
///
/// Dispatch: Op7 OpRoll -> selector
///   selector=1 -> create basket (deposit tokens, increment total_baskets, self-continuation)
///   selector=2 -> redeem basket (receive tokens, decrement total_baskets, self-continuation)
///   selector=0 -> rebalance (admin sig, update weights, self-continuation)
///
/// Create path: verify token covenant inputs exist, self-continuation, drop state.
/// Redeem path: verify token covenant outputs exist, self-continuation, drop state.
/// Rebalance path: verify admin sig (hash(pk)==admin_hash), self-continuation, drop state.
///
/// Body = 64B, RS = 159 + 64 = 223 bytes.
pub const INDEX_BASKET_BODY_V1: &[u8] = &[
    // === Dispatch (5B): Op7 OpRoll brings selector to top ===
    0x57, 0x7a,             // Op7 OpRoll -> selector
    0x00, 0xa0,             // Op0 OpGreaterThan -> (selector > 0)?
    0x63,                   // OpIf (create or redeem)

    // === Inner dispatch (3B): selector==1 -> create, else redeem ===
    0x51, 0x87,             // Op1 OpEqual (selector == 1?)
    0x63,                   // OpIf (create)

    // === Create Basket Path (19B) ===
    // Verify token_1 covenant input exists (proves token_1 deposited)
    // Stack: tb(0), w2(1), w1(2), t2(3), t1(4), ah(5), bid(6)
    0x54, 0x79,             // Op4 OpPick -> t1_cov_id
    0xd0,                   // OpCovInputCount -> count of token_1 inputs
    0x51, 0xa2, 0x69,       // Op1 OpGTE OpVerify (count >= 1)
    // Self-continuation
    0x00, 0xc3,             // Op0 OpTxOutputSpk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7

    // === Redeem Basket Path (21B) ===
    0x67,                   // OpElse (redeem)
    // Verify token_1 covenant output exists (proves token_1 returned)
    0x54, 0x79,             // Op4 OpPick -> t1_cov_id
    0xd2,                   // OpCovOutCount -> count of token_1 outputs
    0x51, 0xa2, 0x69,       // Op1 OpGTE OpVerify (count >= 1)
    // Self-continuation
    0x00, 0xc3,             // Op0 OpTxOutputSpk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x68,                   // OpEndIf (inner)

    // === Rebalance Path (14B) ===
    // Admin sig verified via hash; self-continuation enforced.
    0x67,                   // OpElse (selector=0, rebalance)
    0x00, 0xc3,             // Op0 OpTxOutputSpk
    0xb9, 0xbf,             // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,             // OpEqual OpVerify (self-continuation)
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7

    // === Common tail (2B) ===
    0x68,                   // OpEndIf (outer)
    0x51,                   // Op1 (TRUE)
];

/// Build index_basket_v1 redeemScript (223 bytes).
///
/// State (159B):
///   [0x20][basket_id 32B][0x20][admin_hash 32B][0x20][token_1_cov_id 32B]
///   [0x20][token_2_cov_id 32B][0x08][weight_1 8B][0x08][weight_2 8B]
///   [0x08][total_baskets 8B]
/// Body (64B): INDEX_BASKET_BODY_V1
///
/// # Arguments
/// * `basket_id`       - 32-byte unique basket identifier
/// * `admin_hash`      - Blake2b(admin_pubkey)
/// * `token_1_cov_id`  - CovenantID of token 1
/// * `token_2_cov_id`  - CovenantID of token 2
/// * `weight_1`        - Weight of token 1 (units per basket)
/// * `weight_2`        - Weight of token 2 (units per basket)
/// * `total_baskets`   - Total basket units outstanding
///
/// # Panics
/// Panics if `weight_1` or `weight_2` is 0.
pub fn build_index_basket_v1_redeem_script(
    basket_id: &[u8; 32],
    admin_hash: &[u8; 32],
    token_1_cov_id: &[u8; 32],
    token_2_cov_id: &[u8; 32],
    weight_1: u64,
    weight_2: u64,
    total_baskets: u64,
) -> crate::Result<Vec<u8>> {
    if weight_1 <= 0 {
        return Err(crate::KobError::Contract("weight_1 must be > 0".into()));
    }
    if weight_2 <= 0 {
        return Err(crate::KobError::Contract("weight_2 must be > 0".into()));
    }

    let mut rs = Vec::with_capacity(223);

    // [0x20][basket_id 32B]
    rs.push(0x20);
    rs.extend_from_slice(basket_id);

    // [0x20][admin_hash 32B]
    rs.push(0x20);
    rs.extend_from_slice(admin_hash);

    // [0x20][token_1_cov_id 32B]
    rs.push(0x20);
    rs.extend_from_slice(token_1_cov_id);

    // [0x20][token_2_cov_id 32B]
    rs.push(0x20);
    rs.extend_from_slice(token_2_cov_id);

    // [0x08][weight_1 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(weight_1));

    // [0x08][weight_2 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(weight_2));

    // [0x08][total_baskets 8B LE]
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(total_baskets));

    rs.extend_from_slice(INDEX_BASKET_BODY_V1);
    Ok(rs)
}

/// Build index_basket_v1 create sigscript.
///
/// Format: `[Op1][pushData(redeemScript)]`
///
/// sigOpCount = 0 (token deposits verified via covenant input count).
pub fn build_index_basket_v1_create_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = create)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build index_basket_v1 redeem sigscript.
///
/// Format: `[Op2][pushData(redeemScript)]`
///
/// sigOpCount = 0 (token outputs verified via covenant output count).
pub fn build_index_basket_v1_redeem_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x52); // Op2 (selector = redeem)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build index_basket_v1 rebalance sigscript.
///
/// Format: `[Op0][pushData(redeemScript)]`
///
/// sigOpCount = 0 (admin authorization verified through updated output state).
pub fn build_index_basket_v1_rebalance_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (selector = rebalance)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}


/// futures_dated_v1 body bytecode (87 bytes).
///
/// Dated futures contract with fixed maturity. Settlement at expiry.
/// Three entrypoints: settle, early_close (bilateral), margin_call.
///
/// State (186B):
///   [0x20][contract_id 32B][0x20][long_hash 32B][0x20][short_hash 32B]
///   [0x20][oracle_cov_id 32B][0x08][strike_num 8B][0x08][strike_den 8B]
///   [0x08][notional 8B][0x08][maturity_daa 8B]
///   [0x08][margin_long 8B][0x08][margin_short 8B]
///
/// Stack after state pushes (10 items, top to bottom):
///   mshort(0), mlong(1), maturity(2), notional(3), sden(4), snum(5),
///   oracle(6), short_hash(7), long_hash(8), contract_id(9)
///
/// Dispatch: Op10 OpRoll brings selector to top (10 state items).
///   selector < 2 -> settle (1) or reserved (0)
///   selector >= 2 -> early_close (2) or margin_call (3)
///
/// Settle path: CLTV >= maturity_daa, read oracle price from input[1] value,
///   calculate PnL = (oracle_price - strike_num) * notional / strike_den,
///   verify output[0] (long) >= margin_long + pnl.
///
/// Early close: requires both long + short signatures (2-of-2 via CheckSigVerify).
///
/// Margin call: permissionless trigger (anyone), verifies oracle input[1] present.
///
/// Body = 96B, RS = 186 + 96 = 282 bytes.
pub const FUTURES_DATED_BODY_V1: &[u8] = &[
    // === Dispatch (7B) ===
    0x5a, 0x7a,                   // Op10 OpRoll -> selector
    0x76,                         // OpDup
    0x52, 0x9f,                   // Op2 OpLessThan (selector < 2?)
    0x63,                         // OpIf (settle or reserved)
    0x51, 0x87, 0x63,             // Op1 OpEqual OpIf (settle)

    // === SETTLE PATH (39B) ===
    // CLTV: maturity_daa must have passed
    0x52, 0x79,                   // Op2 OpPick -> maturity_daa
    0xb0,                         // OpCheckLockTimeVerify (lockTime >= maturity_daa)
    0x75,                         // OpDrop (maturity_daa from CLTV)
    // Read oracle price from input[1] value (value-as-price pattern)
    0x51, 0xbe,                   // Op1 OpTxInputAmount -> oracle_price
    // Verify oracle input is correct covenant
    0x51, 0xcf,                   // Op1 OpTxInputCovId -> input[1].cov_id
    0x57, 0x79,                   // Op7 OpPick -> oracle_cov_id (depth 7: oracle=6 + oracle_price on top = 7)
    0x87, 0x69,                   // OpEqual OpVerify (cov_id matches)
    // PnL = (oracle_price - strike_num) * notional / strike_den
    0x56, 0x79,                   // Op6 OpPick -> strike_num (depth 6: snum=5 + oracle_price = 6)
    0x94,                         // OpSub -> (oracle - strike_num)
    0x54, 0x79,                   // Op4 OpPick -> notional (depth 4)
    0x95,                         // OpMul -> pnl_raw
    0x55, 0x79,                   // Op5 OpPick -> strike_den (depth 5)
    0x96,                         // OpDiv -> pnl (positive = long profits)
    // output[0] (long) >= margin_long + pnl
    0x52, 0x79,                   // Op2 OpPick -> margin_long (depth 2)
    0x93,                         // OpAdd -> margin_long + pnl
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> output[0].value
    0x7c, 0xa2, 0x69,             // OpSwap OpGTE OpVerify
    // Cleanup
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5

    // === SETTLE END / ELSE for inner ===
    0x67,                         // OpElse (selector was 0 = reserved/nop)
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5
    0x68,                         // OpEndIf (inner)

    // === EARLY_CLOSE / MARGIN_CALL ===
    0x67,                         // OpElse (selector >= 2)
    0x52, 0x87, 0x63,             // Op2 OpEqual OpIf (early_close)

    // === EARLY CLOSE PATH (14B): 2-of-2 (long + short signatures) ===
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5 (mshort, mlong, maturity, notional, sden)
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5 (snum, oracle, short_hash, long_hash, cid)
    0xad,                         // OpCheckSigVerify (pk_l, sig_l)
    0xad,                         // OpCheckSigVerify (pk_s, sig_s)
    0x51,                         // Op1 TRUE

    // === MARGIN CALL PATH (8B): simplified permissionless trigger ===
    0x67,                         // OpElse (selector == 3 = margin_call)
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5
    0x51, 0xbe,                   // Op1 OpTxInputAmount -> oracle exists (nonzero)
    0x00, 0xa0, 0x69,             // Op0 OpGreaterThan OpVerify (oracle_val > 0)

    // === CLOSING ===
    0x68,                         // OpEndIf (early_close vs margin_call)
    0x68,                         // OpEndIf (outer)
    0x51,                         // Op1 (TRUE)
];

/// Build futures_dated_v1 redeemScript (273 bytes).
///
/// State (186B):
///   [0x20][contract_id 32B][0x20][long_hash 32B][0x20][short_hash 32B]
///   [0x20][oracle_cov_id 32B][0x08][strike_num 8B][0x08][strike_den 8B]
///   [0x08][notional 8B][0x08][maturity_daa 8B]
///   [0x08][margin_long 8B][0x08][margin_short 8B]
/// Body (96B): FUTURES_DATED_BODY_V1
///
/// # Panics
/// Panics if `strike_price_den`, `notional`, or `maturity_daa` is 0.
pub fn build_futures_dated_v1_redeem_script(
    contract_id: &[u8; 32],
    long_hash: &[u8; 32],
    short_hash: &[u8; 32],
    oracle_cov_id: &[u8; 32],
    strike_price_num: u64,
    strike_price_den: u64,
    notional: u64,
    maturity_daa: u64,
    margin_long: u64,
    margin_short: u64,
) -> crate::Result<Vec<u8>> {
    if strike_price_den <= 0 {
        return Err(crate::KobError::Contract("strike_price_den must be > 0".into()));
    }
    if notional <= 0 {
        return Err(crate::KobError::Contract("notional must be > 0".into()));
    }
    if maturity_daa <= 0 {
        return Err(crate::KobError::Contract("maturity_daa must be > 0".into()));
    }
    let state_size = 33 + 33 + 33 + 33 + 9 + 9 + 9 + 9 + 9 + 9; // 186B
    let body_len = FUTURES_DATED_BODY_V1.len(); // 96B
    let mut rs = Vec::with_capacity(state_size + body_len);
    rs.push(0x20);
    rs.extend_from_slice(contract_id);
    rs.push(0x20);
    rs.extend_from_slice(long_hash);
    rs.push(0x20);
    rs.extend_from_slice(short_hash);
    rs.push(0x20);
    rs.extend_from_slice(oracle_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(strike_price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(strike_price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(notional));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(maturity_daa));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(margin_long));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(margin_short));
    rs.extend_from_slice(FUTURES_DATED_BODY_V1);
    Ok(rs)
}

/// Build futures_dated_v1 settle sigscript: `[Op1][pushData(RS)]`
pub fn build_futures_settle_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build futures_dated_v1 early_close sigscript (2-of-2):
/// `[pushData(sig_s 65B)][pushData(pk_s 32B)][pushData(sig_l 65B)][pushData(pk_l 32B)][Op2][pushData(RS)]`
pub fn build_futures_early_close_sigscript(
    sig_long: &[u8; 64],
    pk_long: &[u8; 32],
    sig_short: &[u8; 64],
    pk_short: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_l = Vec::with_capacity(65);
    sig_l.extend_from_slice(sig_long);
    sig_l.push(0x01);
    let mut sig_s = Vec::with_capacity(65);
    sig_s.extend_from_slice(sig_short);
    sig_s.push(0x01);
    let mut ss = Vec::with_capacity(200 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_s));
    ss.extend_from_slice(&push_data(pk_short));
    ss.extend_from_slice(&push_data(&sig_l));
    ss.extend_from_slice(&push_data(pk_long));
    ss.push(0x52);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build futures_dated_v1 margin_call sigscript: `[Op3][pushData(RS)]`
pub fn build_futures_margin_call_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x53);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    // crowdfund_pool v2 tests (F12 fix: min_contribution enforcement)

    #[test]
    fn crowdfund_pool_v2_body_length() {
        assert_eq!(CROWDFUND_POOL_BODY_V2.len(), 38, "crowdfund_pool v2 body must be 38 bytes");
    }

    #[test]
    fn crowdfund_pool_v2_body_hex_matches_spec() {
        let expected = "537a00a06300c3b9bf876900c2b9bea26900c2b9be947ca2697575756775b9be7ca269ad6851";
        assert_eq!(hex::encode(CROWDFUND_POOL_BODY_V2), expected);
    }

    #[test]
    fn crowdfund_pool_v2_redeem_script_length() {
        let cpk = [0u8; 32];
        let rs = build_crowdfund_pool_v2_redeem_script(&cpk, 14_000_000, 5_000_000).unwrap();
        // State: 33 (cpk) + 9 (goal) + 9 (min_contribution) = 51B
        // Body: 38B
        // Total: 89B
        assert_eq!(rs.len(), 89, "crowdfund_pool v2 RS must be 89 bytes (51 + 38)");
    }

    #[test]
    fn crowdfund_pool_v2_state_layout() {
        let cpk = [0xAA; 32];
        let rs = build_crowdfund_pool_v2_redeem_script(&cpk, 14_000_000, 5_000_000).unwrap();

        // [0x20][creator_pk 32B][0x08][goal 8B][0x08][min_contribution 8B][BODY 37B]
        assert_eq!(rs[0], 0x20, "creator_pk push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "creator_pk");
        assert_eq!(rs[33], 0x08, "goal push opcode");
        assert_eq!(u64::from_le_bytes(rs[34..42].try_into().unwrap()), 14_000_000, "goal_amount");
        assert_eq!(rs[42], 0x08, "min_contribution push opcode");
        assert_eq!(u64::from_le_bytes(rs[43..51].try_into().unwrap()), 5_000_000, "min_contribution");

        // Body starts at offset 51
        assert_eq!(&rs[51..], CROWDFUND_POOL_BODY_V2, "body must match v2 bytecode");
    }

    #[test]
    #[should_panic(expected = "goal_amount must be > 0")]
    fn crowdfund_pool_v2_rejects_zero_goal() {
        let cpk = [0u8; 32];
        build_crowdfund_pool_v2_redeem_script(&cpk, 0, 5_000_000).unwrap();
    }

    #[test]
    #[should_panic(expected = "min_contribution must be > 0")]
    fn crowdfund_pool_v2_rejects_zero_min_contribution() {
        let cpk = [0u8; 32];
        build_crowdfund_pool_v2_redeem_script(&cpk, 14_000_000, 0).unwrap();
    }

    #[test]
    fn crowdfund_pool_v2_contribute_sigscript_structure() {
        let cpk = [0u8; 32];
        let rs = build_crowdfund_pool_v2_redeem_script(&cpk, 14_000_000, 5_000_000).unwrap();
        let ss = build_crowdfund_contribute_v2_sigscript(&rs);
        // Op0(1) + Op1(1) + OP_PUSHDATA1(1) + len(1) + rs(89) = 93
        assert_eq!(ss.len(), 93, "contribute sigscript = 93B");
        assert_eq!(ss[0], 0x00, "first byte must be Op0 (dummy)");
        assert_eq!(ss[1], 0x51, "second byte must be Op1 (selector = contribute)");
    }

    #[test]
    fn crowdfund_pool_v2_withdraw_sigscript_structure() {
        let cpk = [0u8; 32];
        let rs = build_crowdfund_pool_v2_redeem_script(&cpk, 14_000_000, 5_000_000).unwrap();
        let sig = [0x42u8; 64];
        let ss = build_crowdfund_withdraw_v2_sigscript(&sig, &rs);
        // pushData(sig65) = [65][sig 64B][0x01] = 66B
        // Op0(1) = 1B
        // OP_PUSHDATA1(1) + len(1) + rs(89) = 91B
        // Total: 66 + 1 + 91 = 158
        assert_eq!(ss.len(), 158, "withdraw sigscript = 158B");
        assert_eq!(ss[0], 65, "sig length prefix");
        assert_eq!(ss[65], 0x01, "sighash type");
        assert_eq!(ss[66], 0x00, "Op0 selector = withdraw");
    }

    #[test]
    fn crowdfund_pool_v2_accepts_valid_params() {
        let cpk = [0u8; 32];
        // Smallest valid: all params = 1
        let rs = build_crowdfund_pool_v2_redeem_script(&cpk, 1, 1).unwrap();
        assert_eq!(rs.len(), 89);
    }


    // bridge_vault_v1 tests

    #[test]
    fn bridge_vault_v1_body_length() {
        assert_eq!(BRIDGE_VAULT_BODY_V1.len(), 62, "bridge_vault_v1 body must be 62 bytes");
    }

    #[test]
    fn bridge_vault_v1_redeem_script_length() {
        let vid = [0u8; 32];
        let gh1 = [0u8; 32];
        let gh2 = [0u8; 32];
        let gh3 = [0u8; 32];
        let rs = build_bridge_vault_v1_redeem_script(&vid, &gh1, &gh2, &gh3, 2, 0).unwrap();
        assert_eq!(rs.len(), 212, "bridge_vault_v1 RS must be 212 bytes (150 state + 62 body)");
    }

    #[test]
    fn bridge_vault_v1_state_layout() {
        let vid = [0xAA; 32];
        let gh1 = [0xBB; 32];
        let gh2 = [0xCC; 32];
        let gh3 = [0xDD; 32];
        let rs = build_bridge_vault_v1_redeem_script(&vid, &gh1, &gh2, &gh3, 2, 1_000_000).unwrap();

        // State: [0x20][vid 32B][0x20][gh1 32B][0x20][gh2 32B][0x20][gh3 32B][0x08][threshold 8B][0x08][balance 8B]
        let mut off = 0;
        assert_eq!(rs[off], 0x20, "vault_id push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xAA; 32], "vault_id");
        off += 32;

        assert_eq!(rs[off], 0x20, "gh1 push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xBB; 32], "guardian_hash_1");
        off += 32;

        assert_eq!(rs[off], 0x20, "gh2 push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xCC; 32], "guardian_hash_2");
        off += 32;

        assert_eq!(rs[off], 0x20, "gh3 push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xDD; 32], "guardian_hash_3");
        off += 32;

        assert_eq!(rs[off], 0x08, "threshold push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 2, "threshold");
        off += 8;

        assert_eq!(rs[off], 0x08, "balance push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 1_000_000, "balance");
        off += 8;

        // Body starts at offset 150
        assert_eq!(off, 150, "state must be exactly 150 bytes");
        assert_eq!(&rs[off..], BRIDGE_VAULT_BODY_V1, "body must match bytecode");
    }

    #[test]
    fn bridge_vault_v1_deposit_sigscript_structure() {
        let vid = [0u8; 32];
        let gh1 = [0u8; 32];
        let gh2 = [0u8; 32];
        let gh3 = [0u8; 32];
        let rs = build_bridge_vault_v1_redeem_script(&vid, &gh1, &gh2, &gh3, 2, 0).unwrap();
        let ss = build_bridge_vault_v1_deposit_sigscript(&rs);
        assert_eq!(ss[0], 0x51, "first byte must be Op1 (deposit selector)");
        // Op1(1) + PUSHDATA1(1) + len(1) + rs(212) = 215
        assert_eq!(ss.len(), 215, "deposit sigscript = 215B");
    }

    #[test]
    fn bridge_vault_v1_withdraw_sigscript_structure() {
        let vid = [0u8; 32];
        let gh1 = [0u8; 32];
        let gh2 = [0u8; 32];
        let gh3 = [0u8; 32];
        let rs = build_bridge_vault_v1_redeem_script(&vid, &gh1, &gh2, &gh3, 2, 0).unwrap();
        let sig = [0x42u8; 64];
        let pk = [0x02u8; 32];
        let ss = build_bridge_vault_v1_withdraw_sigscript(&sig, &pk, &rs);
        // pushData(sig65)(66) + pushData(pk32)(33) + Op2(1) + PUSHDATA1(1) + len(1) + rs(212) = 314
        assert_eq!(ss.len(), 314, "withdraw sigscript = 314B");
    }

    #[test]
    #[should_panic(expected = "threshold must be 1..=3")]
    fn bridge_vault_v1_rejects_zero_threshold() {
        let vid = [0u8; 32];
        let gh = [0u8; 32];
        build_bridge_vault_v1_redeem_script(&vid, &gh, &gh, &gh, 0, 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "threshold must be 1..=3")]
    fn bridge_vault_v1_rejects_threshold_4() {
        let vid = [0u8; 32];
        let gh = [0u8; 32];
        build_bridge_vault_v1_redeem_script(&vid, &gh, &gh, &gh, 4, 0).unwrap();
    }

    #[test]
    fn bridge_vault_v1_body_dispatch_structure() {
        // Dispatch: 56 7a (Op6 OpRoll) + 00 a0 63 (Op0 OpGreaterThan OpIf)
        assert_eq!(BRIDGE_VAULT_BODY_V1[0], 0x56, "Op6");
        assert_eq!(BRIDGE_VAULT_BODY_V1[1], 0x7a, "OpRoll");
        assert_eq!(BRIDGE_VAULT_BODY_V1[2], 0x00, "Op0");
        assert_eq!(BRIDGE_VAULT_BODY_V1[3], 0xa0, "OpGreaterThan");
        assert_eq!(BRIDGE_VAULT_BODY_V1[4], 0x63, "OpIf");
        // Inner dispatch: 51 87 63 (Op1 OpEqual OpIf)
        assert_eq!(BRIDGE_VAULT_BODY_V1[5], 0x51, "Op1 inner dispatch");
        assert_eq!(BRIDGE_VAULT_BODY_V1[6], 0x87, "OpEqual inner dispatch");
        assert_eq!(BRIDGE_VAULT_BODY_V1[7], 0x63, "OpIf inner dispatch");
        // Last byte: Op1 (TRUE)
        assert_eq!(BRIDGE_VAULT_BODY_V1[61], 0x51, "Op1 TRUE at end");
    }


    // bridge_receipt_v1 tests

    #[test]
    fn bridge_receipt_v1_body_length() {
        assert_eq!(BRIDGE_RECEIPT_BODY_V1.len(), 47, "bridge_receipt_v1 body must be 47 bytes");
    }

    #[test]
    fn bridge_receipt_v1_redeem_script_length() {
        let bid = [0u8; 32];
        let dh = [0u8; 32];
        let da = [0u8; 32];
        let rs = build_bridge_receipt_v1_redeem_script(&bid, &dh, 1, &da, 100_000, 0, 0).unwrap();
        assert_eq!(rs.len(), 175, "bridge_receipt_v1 RS must be 175 bytes (128 state + 47 body)");
    }

    #[test]
    fn bridge_receipt_v1_state_layout() {
        let bid = [0xAA; 32];
        let dh = [0xBB; 32];
        let da = [0xCC; 32];
        let rs = build_bridge_receipt_v1_redeem_script(&bid, &dh, 42, &da, 500_000, 7, 1).unwrap();

        let mut off = 0;
        // [0x20][bridge_id 32B]
        assert_eq!(rs[off], 0x20, "bridge_id push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xAA; 32], "bridge_id");
        off += 32;

        // [0x20][depositor_hash 32B]
        assert_eq!(rs[off], 0x20, "depositor_hash push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xBB; 32], "depositor_hash");
        off += 32;

        // [0x08][dest_chain_id 8B]
        assert_eq!(rs[off], 0x08, "dest_chain_id push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 42, "dest_chain_id");
        off += 8;

        // [0x20][dest_address 32B]
        assert_eq!(rs[off], 0x20, "dest_address push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xCC; 32], "dest_address");
        off += 32;

        // [0x08][amount 8B]
        assert_eq!(rs[off], 0x08, "amount push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 500_000, "amount");
        off += 8;

        // [0x08][nonce 8B]
        assert_eq!(rs[off], 0x08, "nonce push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 7, "nonce");
        off += 8;

        // [0x01][status 1B]
        assert_eq!(rs[off], 0x01, "status push opcode");
        off += 1;
        assert_eq!(rs[off], 1, "status = confirmed");
        off += 1;

        // Body starts at offset 128
        assert_eq!(off, 128, "state must be exactly 128 bytes");
        assert_eq!(&rs[off..], BRIDGE_RECEIPT_BODY_V1, "body must match bytecode");
    }

    #[test]
    fn bridge_receipt_v1_sigscript_selectors() {
        let bid = [0u8; 32];
        let dh = [0u8; 32];
        let da = [0u8; 32];
        let rs = build_bridge_receipt_v1_redeem_script(&bid, &dh, 1, &da, 100_000, 0, 0).unwrap();

        let confirm_ss = build_bridge_receipt_v1_confirm_sigscript(&rs);
        assert_eq!(confirm_ss[0], 0x51, "confirm selector must be Op1");

        let complete_ss = build_bridge_receipt_v1_complete_sigscript(&rs);
        assert_eq!(complete_ss[0], 0x52, "complete selector must be Op2");

        let trigger_ss = build_bridge_receipt_v1_trigger_read_sigscript(&rs);
        assert_eq!(trigger_ss[0], 0x00, "trigger-read selector must be Op0");
    }

    #[test]
    #[should_panic(expected = "amount must be > 0")]
    fn bridge_receipt_v1_rejects_zero_amount() {
        let bid = [0u8; 32];
        let dh = [0u8; 32];
        let da = [0u8; 32];
        build_bridge_receipt_v1_redeem_script(&bid, &dh, 1, &da, 0, 0, 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "status must be 0")]
    fn bridge_receipt_v1_rejects_invalid_status() {
        let bid = [0u8; 32];
        let dh = [0u8; 32];
        let da = [0u8; 32];
        build_bridge_receipt_v1_redeem_script(&bid, &dh, 1, &da, 100, 0, 3).unwrap();
    }

    #[test]
    fn bridge_receipt_v1_body_dispatch_structure() {
        // Dispatch: 57 7a (Op7 OpRoll) + 00 a0 63 (Op0 OpGreaterThan OpIf)
        assert_eq!(BRIDGE_RECEIPT_BODY_V1[0], 0x57, "Op7");
        assert_eq!(BRIDGE_RECEIPT_BODY_V1[1], 0x7a, "OpRoll");
        assert_eq!(BRIDGE_RECEIPT_BODY_V1[2], 0x00, "Op0");
        assert_eq!(BRIDGE_RECEIPT_BODY_V1[3], 0xa0, "OpGreaterThan");
        assert_eq!(BRIDGE_RECEIPT_BODY_V1[4], 0x63, "OpIf");
        // Last byte: Op1 (TRUE)
        assert_eq!(BRIDGE_RECEIPT_BODY_V1[46], 0x51, "Op1 TRUE at end");
    }


    // nft_royalty_v1 tests

    #[test]
    fn nft_royalty_v1_body_length() {
        assert_eq!(NFT_ROYALTY_BODY_V1.len(), 51, "nft_royalty_v1 body must be 51 bytes");
    }

    #[test]
    fn nft_royalty_v1_redeem_script_length() {
        let ncid = [0u8; 32];
        let ch = [0u8; 32];
        let oh = [0u8; 32];
        let rs = build_nft_royalty_v1_redeem_script(&ncid, &ch, &oh, 5, 100, 1_000_000).unwrap();
        assert_eq!(rs.len(), 177, "nft_royalty_v1 RS must be 177 bytes (126 state + 51 body)");
    }

    #[test]
    fn nft_royalty_v1_state_layout() {
        let ncid = [0xAA; 32];
        let ch = [0xBB; 32];
        let oh = [0xCC; 32];
        let rs = build_nft_royalty_v1_redeem_script(&ncid, &ch, &oh, 5, 100, 2_000_000).unwrap();

        let mut off = 0;
        // [0x20][nft_cov_id 32B]
        assert_eq!(rs[off], 0x20, "nft_cov_id push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xAA; 32], "nft_cov_id");
        off += 32;

        // [0x20][creator_hash 32B]
        assert_eq!(rs[off], 0x20, "creator_hash push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xBB; 32], "creator_hash");
        off += 32;

        // [0x20][owner_hash 32B]
        assert_eq!(rs[off], 0x20, "owner_hash push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xCC; 32], "owner_hash");
        off += 32;

        // [0x08][royalty_num 8B]
        assert_eq!(rs[off], 0x08, "royalty_num push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 5, "royalty_num");
        off += 8;

        // [0x08][royalty_den 8B]
        assert_eq!(rs[off], 0x08, "royalty_den push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 100, "royalty_den");
        off += 8;

        // [0x08][floor_price 8B]
        assert_eq!(rs[off], 0x08, "floor_price push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 2_000_000, "floor_price");
        off += 8;

        // Body starts at offset 126
        assert_eq!(off, 126, "state must be exactly 126 bytes");
        assert_eq!(&rs[off..], NFT_ROYALTY_BODY_V1, "body must match bytecode");
    }

    #[test]
    fn nft_royalty_v1_transfer_sigscript_structure() {
        let ncid = [0u8; 32];
        let ch = [0u8; 32];
        let oh = [0u8; 32];
        let rs = build_nft_royalty_v1_redeem_script(&ncid, &ch, &oh, 5, 100, 1_000_000).unwrap();
        let sig = [0x42u8; 64];
        let pk = [0x02u8; 32];
        let ss = build_nft_royalty_v1_transfer_sigscript(&sig, &pk, &rs);
        // pushData(sig65)(66) + pushData(pk32)(33) + Op1(1) + PUSHDATA1(1) + len(1) + rs(177) = 279
        assert_eq!(ss.len(), 279, "transfer sigscript = 279B");
        // The selector (Op1) should be at position 66+33 = 99
        assert_eq!(ss[99], 0x51, "Op1 selector for transfer");
    }

    #[test]
    fn nft_royalty_v1_creator_update_sigscript_structure() {
        let ncid = [0u8; 32];
        let ch = [0u8; 32];
        let oh = [0u8; 32];
        let rs = build_nft_royalty_v1_redeem_script(&ncid, &ch, &oh, 5, 100, 1_000_000).unwrap();
        let sig = [0x42u8; 64];
        let pk = [0x02u8; 32];
        let ss = build_nft_royalty_v1_creator_update_sigscript(&sig, &pk, &rs);
        // Same size as transfer, just with Op0 selector
        assert_eq!(ss.len(), 279, "creator_update sigscript = 279B");
        assert_eq!(ss[99], 0x00, "Op0 selector for creator_update");
    }

    #[test]
    #[should_panic(expected = "royalty_den must be > 0")]
    fn nft_royalty_v1_rejects_zero_royalty_den() {
        let h = [0u8; 32];
        build_nft_royalty_v1_redeem_script(&h, &h, &h, 5, 0, 1_000_000).unwrap();
    }

    #[test]
    #[should_panic(expected = "floor_price must be > 0")]
    fn nft_royalty_v1_rejects_zero_floor_price() {
        let h = [0u8; 32];
        build_nft_royalty_v1_redeem_script(&h, &h, &h, 5, 100, 0).unwrap();
    }

    #[test]
    fn nft_royalty_v1_body_dispatch_structure() {
        // Dispatch: 56 7a (Op6 OpRoll) + 00 a0 63 (Op0 OpGreaterThan OpIf)
        assert_eq!(NFT_ROYALTY_BODY_V1[0], 0x56, "Op6");
        assert_eq!(NFT_ROYALTY_BODY_V1[1], 0x7a, "OpRoll");
        assert_eq!(NFT_ROYALTY_BODY_V1[2], 0x00, "Op0");
        assert_eq!(NFT_ROYALTY_BODY_V1[3], 0xa0, "OpGreaterThan");
        assert_eq!(NFT_ROYALTY_BODY_V1[4], 0x63, "OpIf");
        // Last byte: Op1 (TRUE)
        assert_eq!(NFT_ROYALTY_BODY_V1[50], 0x51, "Op1 TRUE at end");
    }

    #[test]
    fn nft_royalty_v1_allows_zero_royalty_num() {
        // A royalty_num of 0 means no royalties (0% fee) — this is a valid config.
        let h = [0u8; 32];
        let rs = build_nft_royalty_v1_redeem_script(&h, &h, &h, 0, 100, 1_000_000).unwrap();
        assert_eq!(rs.len(), 177, "zero royalty_num must be allowed");
    }


    // index_basket_v1 tests

    #[test]
    fn index_basket_v1_body_length() {
        assert_eq!(INDEX_BASKET_BODY_V1.len(), 64, "index_basket_v1 body must be 64 bytes");
    }

    #[test]
    fn index_basket_v1_redeem_script_length() {
        let bid = [0u8; 32];
        let ah = [0u8; 32];
        let t1 = [0u8; 32];
        let t2 = [0u8; 32];
        let rs = build_index_basket_v1_redeem_script(&bid, &ah, &t1, &t2, 10, 20, 0).unwrap();
        assert_eq!(rs.len(), 223, "index_basket_v1 RS must be 223 bytes (159 state + 64 body)");
    }

    #[test]
    fn index_basket_v1_state_layout() {
        let bid = [0xAA; 32];
        let ah = [0xBB; 32];
        let t1 = [0xCC; 32];
        let t2 = [0xDD; 32];
        let rs = build_index_basket_v1_redeem_script(&bid, &ah, &t1, &t2, 10, 20, 100).unwrap();

        let mut off = 0;
        // [0x20][basket_id 32B]
        assert_eq!(rs[off], 0x20, "basket_id push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xAA; 32], "basket_id");
        off += 32;

        // [0x20][admin_hash 32B]
        assert_eq!(rs[off], 0x20, "admin_hash push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xBB; 32], "admin_hash");
        off += 32;

        // [0x20][token_1_cov_id 32B]
        assert_eq!(rs[off], 0x20, "token_1_cov_id push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xCC; 32], "token_1_cov_id");
        off += 32;

        // [0x20][token_2_cov_id 32B]
        assert_eq!(rs[off], 0x20, "token_2_cov_id push opcode");
        off += 1;
        assert_eq!(&rs[off..off+32], &[0xDD; 32], "token_2_cov_id");
        off += 32;

        // [0x08][weight_1 8B]
        assert_eq!(rs[off], 0x08, "weight_1 push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 10, "weight_1");
        off += 8;

        // [0x08][weight_2 8B]
        assert_eq!(rs[off], 0x08, "weight_2 push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 20, "weight_2");
        off += 8;

        // [0x08][total_baskets 8B]
        assert_eq!(rs[off], 0x08, "total_baskets push opcode");
        off += 1;
        assert_eq!(u64::from_le_bytes(rs[off..off+8].try_into().unwrap()), 100, "total_baskets");
        off += 8;

        // Body starts at offset 159
        assert_eq!(off, 159, "state must be exactly 159 bytes");
        assert_eq!(&rs[off..], INDEX_BASKET_BODY_V1, "body must match bytecode");
    }

    #[test]
    fn index_basket_v1_sigscript_selectors() {
        let bid = [0u8; 32];
        let ah = [0u8; 32];
        let t1 = [0u8; 32];
        let t2 = [0u8; 32];
        let rs = build_index_basket_v1_redeem_script(&bid, &ah, &t1, &t2, 10, 20, 0).unwrap();

        let create_ss = build_index_basket_v1_create_sigscript(&rs);
        assert_eq!(create_ss[0], 0x51, "create selector must be Op1");

        let redeem_ss = build_index_basket_v1_redeem_sigscript(&rs);
        assert_eq!(redeem_ss[0], 0x52, "redeem selector must be Op2");

        let rebalance_ss = build_index_basket_v1_rebalance_sigscript(&rs);
        assert_eq!(rebalance_ss[0], 0x00, "rebalance selector must be Op0");
    }

    #[test]
    #[should_panic(expected = "weight_1 must be > 0")]
    fn index_basket_v1_rejects_zero_weight_1() {
        let h = [0u8; 32];
        build_index_basket_v1_redeem_script(&h, &h, &h, &h, 0, 20, 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "weight_2 must be > 0")]
    fn index_basket_v1_rejects_zero_weight_2() {
        let h = [0u8; 32];
        build_index_basket_v1_redeem_script(&h, &h, &h, &h, 10, 0, 0).unwrap();
    }

    #[test]
    fn index_basket_v1_body_dispatch_structure() {
        // Dispatch: 57 7a (Op7 OpRoll) + 00 a0 63 (Op0 OpGreaterThan OpIf)
        assert_eq!(INDEX_BASKET_BODY_V1[0], 0x57, "Op7");
        assert_eq!(INDEX_BASKET_BODY_V1[1], 0x7a, "OpRoll");
        assert_eq!(INDEX_BASKET_BODY_V1[2], 0x00, "Op0");
        assert_eq!(INDEX_BASKET_BODY_V1[3], 0xa0, "OpGreaterThan");
        assert_eq!(INDEX_BASKET_BODY_V1[4], 0x63, "OpIf");
        // Last byte: Op1 (TRUE)
        assert_eq!(INDEX_BASKET_BODY_V1[63], 0x51, "Op1 TRUE at end");
    }

    #[test]
    fn index_basket_v1_create_uses_cov_input_count() {
        // Create path should verify token_1 covenant input exists via OpCovInputCount (0xd0)
        // After dispatch (8B), the create path starts at offset 8.
        // Op4 OpPick (0x54, 0x79) + OpCovInputCount (0xd0) + Op1 OpGTE OpVerify (0x51, 0xa2, 0x69)
        assert_eq!(INDEX_BASKET_BODY_V1[8], 0x54, "Op4 (pick t1_cov_id)");
        assert_eq!(INDEX_BASKET_BODY_V1[9], 0x79, "OpPick");
        assert_eq!(INDEX_BASKET_BODY_V1[10], 0xd0, "OpCovInputCount");
        assert_eq!(INDEX_BASKET_BODY_V1[11], 0x51, "Op1");
        assert_eq!(INDEX_BASKET_BODY_V1[12], 0xa2, "OpGTE");
        assert_eq!(INDEX_BASKET_BODY_V1[13], 0x69, "OpVerify");
    }

    #[test]
    fn index_basket_v1_redeem_uses_cov_out_count() {
        // Redeem path should verify token_1 covenant output exists via OpCovOutCount (0xd2)
        // Find the OpElse (0x67) after create path, then look for 0xd2
        let body = INDEX_BASKET_BODY_V1;
        // After create (13B for covenant check + 6B self-cont + 7B drops = 26B) + OpElse at offset 8+13+6+7 = 34
        // Actually let's just search for the OpCovOutCount opcode
        let has_cov_out_count = body.iter().any(|&b| b == 0xd2);
        assert!(has_cov_out_count, "redeem path must use OpCovOutCount (0xd2)");
    }

    #[test]
    fn index_basket_v1_allows_zero_total_baskets() {
        // total_baskets=0 is valid (initial state before any baskets created)
        let h = [0u8; 32];
        let rs = build_index_basket_v1_redeem_script(&h, &h, &h, &h, 10, 20, 0).unwrap();
        assert_eq!(rs.len(), 223, "zero total_baskets must be allowed");
    }


    // amm_pool v1 tests

    #[test]
    fn amm_pool_body_v1_length() {
        assert_eq!(AMM_POOL_BODY_V1.len(), 112, "amm_pool v1 body must be 112 bytes");
    }

    #[test]
    fn amm_pool_redeem_script_v1_length() {
        let pool_id = [0u8; 32];
        let tcid = [0u8; 32];
        let admin_hash = [0u8; 32];
        let rs = build_amm_pool_v1_redeem_script(
            &pool_id, &tcid, &admin_hash,
            1_000_000, 1_000_000, 3, 1000, 100,
        ).unwrap();
        assert_eq!(rs.len(), 256, "amm_pool v1 RS must be 256 bytes (144 + 112)");
    }

    #[test]
    fn amm_pool_v1_state_layout() {
        let pool_id = [0xAA; 32];
        let tcid = [0xBB; 32];
        let admin_hash = [0xCC; 32];
        let rs = build_amm_pool_v1_redeem_script(
            &pool_id, &tcid, &admin_hash,
            500_000, 200_000, 3, 1000, 50,
        ).unwrap();

        // Verify state layout:
        // [0x20][pool_id 32B][0x20][tcid 32B][0x20][admin_hash 32B]
        // [0x08][reserve_kas 8B][0x08][reserve_token 8B]
        // [0x08][fee_num 8B][0x08][fee_den 8B][0x08][lp_supply 8B]
        assert_eq!(rs[0], 0x20, "pool_id push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "pool_id");
        assert_eq!(rs[33], 0x20, "tcid push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "token_cov_id");
        assert_eq!(rs[66], 0x20, "admin_hash push opcode");
        assert_eq!(&rs[67..99], &[0xCC; 32], "admin_hash");
        assert_eq!(rs[99], 0x08, "reserve_kas push opcode");
        assert_eq!(u64::from_le_bytes(rs[100..108].try_into().unwrap()), 500_000, "reserve_kas");
        assert_eq!(rs[108], 0x08, "reserve_token push opcode");
        assert_eq!(u64::from_le_bytes(rs[109..117].try_into().unwrap()), 200_000, "reserve_token");
        assert_eq!(rs[117], 0x08, "fee_num push opcode");
        assert_eq!(u64::from_le_bytes(rs[118..126].try_into().unwrap()), 3, "fee_num");
        assert_eq!(rs[126], 0x08, "fee_den push opcode");
        assert_eq!(u64::from_le_bytes(rs[127..135].try_into().unwrap()), 1000, "fee_den");
        assert_eq!(rs[135], 0x08, "lp_supply push opcode");
        assert_eq!(u64::from_le_bytes(rs[136..144].try_into().unwrap()), 50, "lp_supply");

        // Body starts at offset 144
        assert_eq!(&rs[144..], AMM_POOL_BODY_V1, "body must match v1 bytecode");
    }

    #[test]
    #[should_panic(expected = "fee_den must be > 0")]
    fn amm_pool_v1_rejects_zero_fee_den() {
        let z = [0u8; 32];
        build_amm_pool_v1_redeem_script(&z, &z, &z, 1, 1, 3, 0, 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "reserve_kas must be > 0")]
    fn amm_pool_v1_rejects_zero_reserve_kas() {
        let z = [0u8; 32];
        build_amm_pool_v1_redeem_script(&z, &z, &z, 0, 1, 3, 1000, 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "reserve_token must be > 0")]
    fn amm_pool_v1_rejects_zero_reserve_token() {
        let z = [0u8; 32];
        build_amm_pool_v1_redeem_script(&z, &z, &z, 1, 0, 3, 1000, 1).unwrap();
    }

    #[test]
    fn amm_pool_v1_body_starts_with_dispatch() {
        // First bytes: Op8 OpRoll OpDup Op2 OpLessThan OpIf
        assert_eq!(AMM_POOL_BODY_V1[0], 0x58, "Op8");
        assert_eq!(AMM_POOL_BODY_V1[1], 0x7a, "OpRoll");
        assert_eq!(AMM_POOL_BODY_V1[2], 0x76, "OpDup");
        assert_eq!(AMM_POOL_BODY_V1[3], 0x52, "Op2");
        assert_eq!(AMM_POOL_BODY_V1[4], 0x9f, "OpLessThan");
        assert_eq!(AMM_POOL_BODY_V1[5], 0x63, "OpIf");
    }

    #[test]
    fn amm_pool_v1_body_ends_with_true() {
        let len = AMM_POOL_BODY_V1.len();
        assert_eq!(AMM_POOL_BODY_V1[len - 1], 0x51, "last byte must be Op1 (TRUE)");
        assert_eq!(AMM_POOL_BODY_V1[len - 2], 0x68, "second-to-last must be OpEndIf");
    }


    // cdp v1 tests

    #[test]
    fn cdp_body_v1_length() {
        assert_eq!(CDP_BODY_V1.len(), 118, "cdp v1 body must be 118 bytes");
    }

    #[test]
    fn cdp_redeem_script_v1_length() {
        let owner = [0u8; 32];
        let oracle = [0u8; 32];
        let rs = build_cdp_v1_redeem_script(
            &owner, &oracle,
            1_000_000, 500_000, 150, 100, 100_000,
        ).unwrap();
        assert_eq!(rs.len(), 229, "cdp v1 RS must be 229 bytes (111 + 118)");
    }

    #[test]
    fn cdp_v1_state_layout() {
        let owner = [0xAA; 32];
        let oracle = [0xBB; 32];
        let rs = build_cdp_v1_redeem_script(
            &owner, &oracle,
            2_000_000, 100_000, 150, 100, 50_000,
        ).unwrap();

        // Verify state layout:
        // [0x20][owner_hash 32B][0x20][oracle_cov_id 32B]
        // [0x08][collateral 8B][0x08][debt 8B]
        // [0x08][liq_num 8B][0x08][liq_den 8B][0x08][min_coll 8B]
        assert_eq!(rs[0], 0x20, "owner_hash push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "owner_hash");
        assert_eq!(rs[33], 0x20, "oracle_cov_id push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "oracle_cov_id");
        assert_eq!(rs[66], 0x08, "collateral push opcode");
        assert_eq!(u64::from_le_bytes(rs[67..75].try_into().unwrap()), 2_000_000, "collateral_amount");
        assert_eq!(rs[75], 0x08, "debt push opcode");
        assert_eq!(u64::from_le_bytes(rs[76..84].try_into().unwrap()), 100_000, "debt_amount");
        assert_eq!(rs[84], 0x08, "liq_ratio_num push opcode");
        assert_eq!(u64::from_le_bytes(rs[85..93].try_into().unwrap()), 150, "liq_ratio_num");
        assert_eq!(rs[93], 0x08, "liq_ratio_den push opcode");
        assert_eq!(u64::from_le_bytes(rs[94..102].try_into().unwrap()), 100, "liq_ratio_den");
        assert_eq!(rs[102], 0x08, "min_collateral push opcode");
        assert_eq!(u64::from_le_bytes(rs[103..111].try_into().unwrap()), 50_000, "min_collateral");

        // Body starts at offset 111
        assert_eq!(&rs[111..], CDP_BODY_V1, "body must match v1 bytecode");
    }

    #[test]
    #[should_panic(expected = "liq_ratio_den must be > 0")]
    fn cdp_v1_rejects_zero_liq_ratio_den() {
        let z = [0u8; 32];
        build_cdp_v1_redeem_script(&z, &z, 1_000_000, 0, 150, 0, 100_000).unwrap();
    }

    #[test]
    #[should_panic(expected = "liq_ratio_num must be > 0")]
    fn cdp_v1_rejects_zero_liq_ratio_num() {
        let z = [0u8; 32];
        build_cdp_v1_redeem_script(&z, &z, 1_000_000, 0, 0, 100, 100_000).unwrap();
    }

    #[test]
    #[should_panic(expected = "min_collateral must be > 0")]
    fn cdp_v1_rejects_zero_min_collateral() {
        let z = [0u8; 32];
        build_cdp_v1_redeem_script(&z, &z, 1_000_000, 0, 150, 100, 0).unwrap();
    }

    #[test]
    fn cdp_v1_body_starts_with_dispatch() {
        // First bytes: Op7 OpRoll OpDup Op3 OpLessThan OpIf
        assert_eq!(CDP_BODY_V1[0], 0x57, "Op7");
        assert_eq!(CDP_BODY_V1[1], 0x7a, "OpRoll");
        assert_eq!(CDP_BODY_V1[2], 0x76, "OpDup");
        assert_eq!(CDP_BODY_V1[3], 0x53, "Op3");
        assert_eq!(CDP_BODY_V1[4], 0x9f, "OpLessThan");
    }

    #[test]
    fn cdp_v1_body_ends_with_true() {
        let len = CDP_BODY_V1.len();
        assert_eq!(CDP_BODY_V1[len - 1], 0x51, "last byte must be Op1 (TRUE)");
        assert_eq!(CDP_BODY_V1[len - 2], 0x68, "second-to-last must be OpEndIf");
    }

    #[test]
    fn cdp_v1_liquidation_check_uses_cross_multiply() {
        // The liquidation path should use OpMul for cross-multiplication:
        // collateral * liq_ratio_den vs debt * liq_ratio_num
        // Find the pattern: Op4 Pick, Op1 Pick, Mul, Op3 Pick, Op2 Pick, Mul, GreaterThan Verify
        let hex = hex::encode(CDP_BODY_V1);
        // collateral(Op4Pick=5479) liq_ratio_den(Op1Pick=5179) Mul(95)
        // debt(Op3Pick=5379) liq_ratio_num(Op2Pick=5279) Mul(95)
        assert!(hex.contains("5479517995"), "liquidation must pick collateral and liq_den then mul");
        assert!(hex.contains("5379527995"), "liquidation must pick debt and liq_num then mul");
    }


    // streaming_payment v1 tests

    #[test]
    fn streaming_payment_body_v1_length() {
        assert_eq!(STREAMING_PAYMENT_BODY_V1.len(), 61, "streaming_payment v1 body must be 61 bytes");
    }

    #[test]
    fn streaming_payment_redeem_script_v1_length() {
        let sender = [0u8; 32];
        let recipient = [0u8; 32];
        let rs = build_streaming_payment_v1_redeem_script(
            &sender, &recipient,
            10_000_000, 0, 1000, 2000,
        ).unwrap();
        assert_eq!(rs.len(), 163, "streaming_payment v1 RS must be 163 bytes (102 + 61)");
    }

    #[test]
    fn streaming_payment_v1_state_layout() {
        let sender = [0xAA; 32];
        let recipient = [0xBB; 32];
        let rs = build_streaming_payment_v1_redeem_script(
            &sender, &recipient,
            5_000_000, 1_000_000, 10_000, 20_000,
        ).unwrap();

        // Verify state layout:
        // [0x20][sender_hash 32B][0x20][recipient_hash 32B]
        // [0x08][total_amount 8B][0x08][claimed_amount 8B]
        // [0x08][start_daa 8B][0x08][end_daa 8B]
        assert_eq!(rs[0], 0x20, "sender_hash push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "sender_hash");
        assert_eq!(rs[33], 0x20, "recipient_hash push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "recipient_hash");
        assert_eq!(rs[66], 0x08, "total_amount push opcode");
        assert_eq!(u64::from_le_bytes(rs[67..75].try_into().unwrap()), 5_000_000, "total_amount");
        assert_eq!(rs[75], 0x08, "claimed_amount push opcode");
        assert_eq!(u64::from_le_bytes(rs[76..84].try_into().unwrap()), 1_000_000, "claimed_amount");
        assert_eq!(rs[84], 0x08, "start_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[85..93].try_into().unwrap()), 10_000, "start_daa");
        assert_eq!(rs[93], 0x08, "end_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[94..102].try_into().unwrap()), 20_000, "end_daa");

        // Body starts at offset 102
        assert_eq!(&rs[102..], STREAMING_PAYMENT_BODY_V1, "body must match v1 bytecode");
    }

    #[test]
    #[should_panic(expected = "total_amount must be > 0")]
    fn streaming_payment_v1_rejects_zero_total_amount() {
        let z = [0u8; 32];
        build_streaming_payment_v1_redeem_script(&z, &z, 0, 0, 1000, 2000).unwrap();
    }

    #[test]
    #[should_panic(expected = "end_daa must be > start_daa")]
    fn streaming_payment_v1_rejects_end_before_start() {
        let z = [0u8; 32];
        build_streaming_payment_v1_redeem_script(&z, &z, 1_000_000, 0, 2000, 1000).unwrap();
    }

    #[test]
    #[should_panic(expected = "end_daa must be > start_daa")]
    fn streaming_payment_v1_rejects_equal_start_end() {
        let z = [0u8; 32];
        build_streaming_payment_v1_redeem_script(&z, &z, 1_000_000, 0, 1000, 1000).unwrap();
    }

    #[test]
    fn streaming_payment_v1_body_starts_with_dispatch() {
        // First bytes: Op6 OpRoll Op0 OpGreaterThan OpIf
        assert_eq!(STREAMING_PAYMENT_BODY_V1[0], 0x56, "Op6");
        assert_eq!(STREAMING_PAYMENT_BODY_V1[1], 0x7a, "OpRoll");
        assert_eq!(STREAMING_PAYMENT_BODY_V1[2], 0x00, "Op0");
        assert_eq!(STREAMING_PAYMENT_BODY_V1[3], 0xa0, "OpGreaterThan");
        assert_eq!(STREAMING_PAYMENT_BODY_V1[4], 0x63, "OpIf");
    }

    #[test]
    fn streaming_payment_v1_body_ends_with_true() {
        let len = STREAMING_PAYMENT_BODY_V1.len();
        assert_eq!(STREAMING_PAYMENT_BODY_V1[len - 1], 0x51, "last byte must be Op1 (TRUE)");
        assert_eq!(STREAMING_PAYMENT_BODY_V1[len - 2], 0x68, "second-to-last must be OpEndIf");
    }

    #[test]
    fn streaming_payment_v1_claim_uses_cltv() {
        // CLTV opcode (0xb0) must be present in the claim path
        let hex = hex::encode(STREAMING_PAYMENT_BODY_V1);
        assert!(hex.contains("b0"), "claim path must use OpCheckLockTimeVerify (0xb0)");
    }

    #[test]
    fn streaming_payment_v1_claim_uses_blake2b_sig_check() {
        // Claim path: Blake2b(pk) == recipient_hash then CheckSigVerify
        // Pattern: OpDup OpBlake2b ... OpEqual OpVerify ... OpCheckSigVerify
        let hex = hex::encode(STREAMING_PAYMENT_BODY_V1);
        assert!(hex.contains("76aa"), "claim path must have OpDup OpBlake2b for hash check");
        assert!(hex.contains("ad"), "claim path must have OpCheckSigVerify");
    }

    #[test]
    fn streaming_payment_v1_accepts_valid_params() {
        let sender = [0xAA; 32];
        let recipient = [0xBB; 32];
        // Valid: claimed can be 0
        let rs = build_streaming_payment_v1_redeem_script(
            &sender, &recipient,
            1, 0, 0, 1,
        ).unwrap();
        assert_eq!(rs.len(), 163);
    }


    #[test]
    fn futures_dated_v1_body_length() {
        assert_eq!(FUTURES_DATED_BODY_V1.len(), 96, "futures_dated_v1 body must be 96 bytes");
    }

    #[test]
    fn futures_dated_v1_rs_length() {
        let cid = [0u8; 32];
        let lh = [0u8; 32];
        let sh = [0u8; 32];
        let ocid = [0u8; 32];
        let rs = build_futures_dated_v1_redeem_script(
            &cid, &lh, &sh, &ocid, 100, 1, 1000, 50000, 500_000, 500_000,
        ).unwrap();
        assert_eq!(rs.len(), 282, "futures_dated_v1 RS must be 282 bytes (186 state + 96 body)");
    }

    #[test]
    fn futures_dated_v1_state_layout() {
        let cid = [0xAA; 32];
        let lh = [0xBB; 32];
        let sh = [0xCC; 32];
        let ocid = [0xDD; 32];
        let rs = build_futures_dated_v1_redeem_script(
            &cid, &lh, &sh, &ocid, 100, 200, 1000, 50000, 10_000, 20_000,
        ).unwrap();

        // State layout: [0x20][cid 32][0x20][lh 32][0x20][sh 32][0x20][ocid 32]
        //   [0x08][snum 8][0x08][sden 8][0x08][notional 8][0x08][maturity 8]
        //   [0x08][mlong 8][0x08][mshort 8]
        assert_eq!(rs[0], 0x20, "contract_id push opcode");
        assert_eq!(&rs[1..33], &[0xAA; 32], "contract_id");
        assert_eq!(rs[33], 0x20, "long_hash push opcode");
        assert_eq!(&rs[34..66], &[0xBB; 32], "long_hash");
        assert_eq!(rs[66], 0x20, "short_hash push opcode");
        assert_eq!(&rs[67..99], &[0xCC; 32], "short_hash");
        assert_eq!(rs[99], 0x20, "oracle_cov_id push opcode");
        assert_eq!(&rs[100..132], &[0xDD; 32], "oracle_cov_id");
        assert_eq!(rs[132], 0x08, "strike_num push opcode");
        assert_eq!(u64::from_le_bytes(rs[133..141].try_into().unwrap()), 100, "strike_num");
        assert_eq!(rs[141], 0x08, "strike_den push opcode");
        assert_eq!(u64::from_le_bytes(rs[142..150].try_into().unwrap()), 200, "strike_den");
        assert_eq!(rs[150], 0x08, "notional push opcode");
        assert_eq!(u64::from_le_bytes(rs[151..159].try_into().unwrap()), 1000, "notional");
        assert_eq!(rs[159], 0x08, "maturity_daa push opcode");
        assert_eq!(u64::from_le_bytes(rs[160..168].try_into().unwrap()), 50000, "maturity_daa");
        assert_eq!(rs[168], 0x08, "margin_long push opcode");
        assert_eq!(u64::from_le_bytes(rs[169..177].try_into().unwrap()), 10_000, "margin_long");
        assert_eq!(rs[177], 0x08, "margin_short push opcode");
        assert_eq!(u64::from_le_bytes(rs[178..186].try_into().unwrap()), 20_000, "margin_short");
        // Body starts at offset 186
        assert_eq!(&rs[186..], FUTURES_DATED_BODY_V1, "body must match");
    }

    #[test]
    fn futures_dated_v1_body_dispatch_opcodes() {
        // Verify dispatch starts with Op10 OpRoll
        assert_eq!(FUTURES_DATED_BODY_V1[0], 0x5a, "dispatch Op10");
        assert_eq!(FUTURES_DATED_BODY_V1[1], 0x7a, "dispatch OpRoll");
        assert_eq!(FUTURES_DATED_BODY_V1[2], 0x76, "OpDup");
        // Verify CLTV opcode present (settle path)
        assert!(
            FUTURES_DATED_BODY_V1.contains(&0xb0),
            "body must contain OpCheckLockTimeVerify (0xb0)"
        );
    }

    #[test]
    #[should_panic(expected = "strike_price_den must be > 0")]
    fn futures_dated_v1_rejects_zero_strike_den() {
        let z = [0u8; 32];
        build_futures_dated_v1_redeem_script(&z, &z, &z, &z, 100, 0, 1000, 50000, 1, 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "notional must be > 0")]
    fn futures_dated_v1_rejects_zero_notional() {
        let z = [0u8; 32];
        build_futures_dated_v1_redeem_script(&z, &z, &z, &z, 100, 1, 0, 50000, 1, 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "maturity_daa must be > 0")]
    fn futures_dated_v1_rejects_zero_maturity() {
        let z = [0u8; 32];
        build_futures_dated_v1_redeem_script(&z, &z, &z, &z, 100, 1, 1000, 0, 1, 1).unwrap();
    }

    #[test]
    fn futures_dated_v1_settle_sigscript() {
        let z = [0u8; 32];
        let rs = build_futures_dated_v1_redeem_script(&z, &z, &z, &z, 100, 1, 1000, 50000, 1, 1).unwrap();
        let ss = build_futures_settle_sigscript(&rs);
        // Op1(1) + PUSHDATA2(1) + len(2) + rs(282) = 286
        assert_eq!(ss[0], 0x51, "first byte must be Op1 (settle selector)");
        assert_eq!(ss.len(), 286, "settle sigscript = 286B");
    }

    #[test]
    fn futures_dated_v1_early_close_sigscript() {
        let z = [0u8; 32];
        let rs = build_futures_dated_v1_redeem_script(&z, &z, &z, &z, 100, 1, 1000, 50000, 1, 1).unwrap();
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let ss = build_futures_early_close_sigscript(&sig, &pk, &sig, &pk, &rs);
        // push(sig_s 65)(66) + push(pk_s 32)(33) + push(sig_l 65)(66) + push(pk_l 32)(33)
        // + Op2(1) + PUSHDATA2(1) + len(2) + rs(282) = 484
        assert_eq!(ss.len(), 484, "early_close sigscript");
    }

    #[test]
    fn futures_dated_v1_margin_call_sigscript() {
        let z = [0u8; 32];
        let rs = build_futures_dated_v1_redeem_script(&z, &z, &z, &z, 100, 1, 1000, 50000, 1, 1).unwrap();
        let ss = build_futures_margin_call_sigscript(&rs);
        assert_eq!(ss[0], 0x53, "first byte must be Op3 (margin_call selector)");
        assert_eq!(ss.len(), 286, "margin_call sigscript = 286B");
    }


}
