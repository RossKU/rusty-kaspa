use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::push_index;

/// swap_order body bytecode (69 bytes).
///
/// Purpose: Cross-token atomic swap routed through KAS-denominated order books.
///
/// The user locks source tokens (e.g. USDT) in a swap covenant UTXO and specifies
/// a target token (e.g. BTC) and minimum amount. A matcher finds counterparties on
/// both TOKEN/KAS books and builds one atomic batch TX where KAS flows internally
/// without the user touching it.
///
/// Example atomic TX:
///   Inputs:
///     [0] Swap UTXO (this covenant -- user's source tokens)
///     [1] Buy-source order (counterparty on SOURCE/KAS book, has KAS)
///     [2] Sell-target order (counterparty on TARGET/KAS book, has target tokens)
///     [3] Matcher wallet UTXO
///   Outputs:
///     [0] Source tokens -> counterparty who bought them
///     [1] Target tokens -> user (swap covenant verifies THIS)
///     [2] KAS -> counterparty who sold target tokens
///     [3] Change -> matcher
///
/// The covenant does NOT encode KAS prices or exchange rates. It only verifies:
///   "I receive >= min_target_amount of target_token at my address."
/// Price discovery happens entirely on the KAS-denominated books.
///
/// State layout (174B):
///   [0x20][source_token_cov_id 32B]  -- what the user is selling
///   [0x20][target_token_cov_id 32B]  -- what the user wants to receive
///   [0x08][min_target_amount 8B]     -- minimum tokens to receive
///   [0x20][owner_hash 32B]           -- blake2b(pubkey), cancel authorization
///   [0x20][owner_spk_hash 32B]       -- blake2b(user's SPK), output destination check
///   [0x20][receipt_cov_id 32B]       -- N4: expected receipt covenant_id
///
/// Stack after state push (6 items, depth 0 = top):
///   rcid(0), ospkh(1), ohash(2), min_ta(3), target_tcid(4), source_tcid(5)
///
/// Dispatch: Op6 OpRoll selector from sigscript.
///   Truthy (Op1) -> fill path
///   Falsy  (Op0) -> cancel path
///
/// Fill sigscript pushes [rii, toi] under state, plus selector consumed by roll:
///   Full stack after selector roll (8): rcid(0), ospkh(1), ohash(2), min_ta(3),
///     target_tcid(4), source_tcid(5), toi(6), rii(7)
///
/// Cancel sigscript pushes [sig, pk] under state, plus selector consumed by roll:
///   Full stack after selector roll (8): rcid(0), ospkh(1), ohash(2), min_ta(3),
///     target_tcid(4), source_tcid(5), pk(6), sig(7)
///
/// Fill sigscript:  `[rii] [toi] [Op1] [pushData(RS)]`
///   sigOpCount = 0 for this input.
///
/// Cancel sigscript: `[pushData(sig+type 65B)] [pushData(pk 32B)] [Op0] [pushData(RS)]`
///   sigOpCount = 1 for this input.
///
/// Body = 69B. RS = 174 + 69 = 243 bytes.
pub const SWAP_ORDER_BODY: &[u8] = &[
    // === DISPATCH (5B): roll selector, branch on truthy ===
    // Sigscript executes first, pushing items onto the stack. Then the
    // redeemScript state pushes execute (source_tcid first, rcid last).
    // Result (fill): rcid(0), ospkh(1), ohash(2), min_ta(3), target_tcid(4),
    //                source_tcid(5), toi(6), rii(7), selector(8)
    // The selector is at depth 8 (bottom). After Op8 OpRoll, it's on top.
    // Wait: 6 state + 2 sigscript + 1 selector = 9 items. selector at depth 8.
    // Actually: sigscript pushes [rii, toi, selector(Op1)]. Then state pushes
    // go on top. Stack (top to bottom):
    //   rcid, ospkh, ohash, min_ta, target_tcid, source_tcid, Op1, toi, rii
    // depths: rcid=0, ospkh=1, ohash=2, min_ta=3, target_tcid=4,
    //         source_tcid=5, selector=6, toi=7, rii=8
    // selector is at depth 6 (6 state items above it).
    0x56, 0x7a,                     // Op6 OpRoll -> selector to top (from depth 6)
    0x00, 0xa0,                     // Op0 OpGreaterThan -> clean boolean
    0x63,                           // OpIf (fill path)

    // === FILL PATH (45B) ===
    // Stack (8 items after selector consumed):
    //   rcid(0), ospkh(1), ohash(2), min_ta(3), target_tcid(4),
    //   source_tcid(5), toi(6), rii(7)

    // --- F1: Receipt input covenant_id check (7B) ---
    // N4 fix: ensures input[rii] IS a genuine trade_receipt contract.
    0x57, 0x79,                     // Op7 OpPick -> rii (depth 7)
    0xcf,                           // OpInputCovenantId -> input[rii].covenant_id
    // Stack(9): cov_id(0), rcid(1), ospkh(2), ..., rii(8)
    0x51, 0x79,                     // Op1 OpPick -> rcid (depth 1)
    0x87, 0x69,                     // OpEqual OpVerify (input[rii].cov_id == rcid)
    // Stack(8): back to base

    // --- F2: Target token output amount check (7B) ---
    // Verify output[toi].value >= min_target_amount.
    0x56, 0x79,                     // Op6 OpPick -> toi (depth 6)
    0xc2,                           // OpTxOutputAmount -> output[toi].value
    // Stack(9): out_val(0), rcid(1), ospkh(2), ohash(3), min_ta(4), ..., rii(8)
    0x54, 0x79,                     // Op4 OpPick -> min_ta (depth 4)
    0xa2, 0x69,                     // OpGTE OpVerify (output[toi].value >= min_ta)
    // Stack(8): back to base

    // --- F3: Owner SPK hash check on target output (8B) ---
    // Verify blake2b(output[toi].spk) == owner_spk_hash.
    // Ensures target tokens go to the user's address.
    0x56, 0x79,                     // Op6 OpPick -> toi (depth 6)
    0xc3,                           // OpTxOutputSpk -> output[toi].spk
    0xaa,                           // OpBlake2b -> hash
    // Stack(9): hash(0), rcid(1), ospkh(2), ..., rii(8)
    0x52, 0x79,                     // Op2 OpPick -> ospkh (depth 2)
    0x87, 0x69,                     // OpEqual OpVerify
    // Stack(8): back to base

    // --- F4: Source token covenant output conservation (6B) ---
    // Verify at least 1 covenant output for this input's token type.
    0xb9, 0xcf,                     // OpTxInputIndex OpInputCovenantId -> cov_id T
    0xd2,                           // OpCovOutCount(T)
    0x51, 0xa2, 0x69,               // Op1 OpGTE OpVerify (>= 1 covenant output)
    // Stack(8): back to base

    // --- F5: Target token covenant binding check (13B) ---
    // Verify output[toi] is a covenant output for target_token_cov_id.
    // Step 1: target_tcid must have >= 1 output.
    0x54, 0x79,                     // Op4 OpPick -> target_tcid (depth 4)
    0x76,                           // OpDup -> [target_tcid, target_tcid, ...]
    // Stack(10): tcid_dup(0), tcid_ref(1), rcid(2), ospkh(3), ohash(4), min_ta(5),
    //            target_tcid(6), source_tcid(7), toi(8), rii(9)
    0xd2,                           // OpCovOutCount(tcid_dup) -> count
    0x51, 0xa2, 0x69,               // Op1 OpGTE OpVerify (>= 1 target output)
    // Stack(9): tcid_ref(0), rcid(1), ..., toi(7), rii(8)
    // Step 2: verify cov_output_idx(target_tcid, 0) == toi.
    // OpCovOutputIdx takes the covenant_id from stack and a script-level index.
    // It returns the TX output index of the i-th covenant output for that token.
    // We use Op0 to get the 0-th covenant output.
    0x00,                           // Op0 (covenant output index 0)
    0xd3,                           // OpCovOutputIdx(tcid_ref, 0) -> tx_out_idx
    // Stack(9): tx_out_idx(0), rcid(1), ..., toi(7), rii(8)
    0x57, 0x79,                     // Op7 OpPick -> toi (depth 7)
    0x87, 0x69,                     // OpEqual OpVerify (cov_output_0 == toi)
    // Stack(8): back to base

    // --- Cleanup: 8 items = Op2Drop x4 (4B) ---
    0x6d, 0x6d, 0x6d, 0x6d,        // Op2Drop x4

    // === CANCEL PATH (17B) ===
    0x67,                           // OpElse (cancel: selector was falsy)
    // Stack (8): rcid(0), ospkh(1), ohash(2), min_ta(3), target_tcid(4),
    //            source_tcid(5), pk(6), sig(7)

    // --- Cancel auth: blake2b(pk) == owner_hash (7B) ---
    0x56, 0x79,                     // Op6 OpPick -> pk (depth 6)
    0xaa,                           // OpBlake2b -> hash(pk)
    // Stack(9): hash(0), rcid(1), ospkh(2), ohash(3), ..., sig(8)
    0x53, 0x79,                     // Op3 OpPick -> ohash (depth 3)
    0x87, 0x69,                     // OpEqual OpVerify (blake2b(pk) == ohash)
    // Stack(8): back to base

    // --- CheckSig (6B) ---
    0x57, 0x7a,                     // Op7 OpRoll -> sig (depth 7, roll to top)
    0x57, 0x7a,                     // Op7 OpRoll -> pk (was at depth 6, now 7 after roll)
    0xac, 0x69,                     // OpCheckSig OpVerify
    // Stack(6): rcid, ospkh, ohash, min_ta, target_tcid, source_tcid

    // --- Cleanup: 6 items = Op2Drop x3 (3B) ---
    0x6d, 0x6d, 0x6d,              // Op2Drop x3

    // === END (2B) ===
    0x68,                           // OpEndIf
    0x51,                           // Op1 (TRUE)
];

/// Swap order state size (174 bytes).
///
/// State layout:
///   [0x20][source_token_cov_id 32B]  = 33B
///   [0x20][target_token_cov_id 32B]  = 33B
///   [0x08][min_target_amount 8B]     =  9B
///   [0x20][owner_hash 32B]           = 33B
///   [0x20][owner_spk_hash 32B]       = 33B
///   [0x20][receipt_cov_id 32B]       = 33B
///   Total: 33 + 33 + 9 + 33 + 33 + 33 = 174B
pub const SWAP_STATE_SIZE: usize = 174;

/// Swap order body size.
pub const SWAP_BODY_SIZE: usize = SWAP_ORDER_BODY.len();

/// Swap order redeemScript size (174B state + body).
pub const SWAP_RS_SIZE: usize = SWAP_STATE_SIZE + SWAP_BODY_SIZE;

/// Parsed swap order state fields.
#[derive(Debug, Clone)]
pub struct ParsedSwapOrder {
    /// Source token covenant ID (what the user is selling).
    pub source_token_cov_id: [u8; 32],
    /// Target token covenant ID (what the user wants to receive).
    pub target_token_cov_id: [u8; 32],
    /// Minimum target tokens to receive.
    pub min_target_amount: u64,
    /// Blake2b-256 of owner's public key (for cancel authorization).
    pub owner_hash: [u8; 32],
    /// Blake2b-256 of owner's SPK (for output destination verification).
    pub owner_spk_hash: [u8; 32],
    /// Receipt covenant ID (N4 verification).
    pub receipt_cov_id: [u8; 32],
    /// Full redeemScript bytes.
    pub redeem_script: Vec<u8>,
}

/// Parse a swap order redeemScript.
///
/// Returns `None` if the RS length doesn't match or push-prefix markers are wrong.
///
/// State layout:
///   [0x20][source_tcid 32B]    = bytes 0..33
///   [0x20][target_tcid 32B]    = bytes 33..66
///   [0x08][min_ta 8B]          = bytes 66..75
///   [0x20][owner_hash 32B]     = bytes 75..108
///   [0x20][owner_spk_hash 32B] = bytes 108..141
///   [0x20][receipt_cov_id 32B] = bytes 141..174
pub fn parse_swap_order_rs(rs: &[u8]) -> Option<ParsedSwapOrder> {
    if rs.len() != SWAP_RS_SIZE {
        return None;
    }
    // Verify push-prefix markers at field boundaries
    if rs[0] != 0x20 || rs[33] != 0x20 || rs[66] != 0x08
        || rs[75] != 0x20 || rs[108] != 0x20 || rs[141] != 0x20
    {
        return None;
    }
    // Body signature: first two bytes = 0x56 0x7a (Op6 OpRoll)
    if rs[SWAP_STATE_SIZE] != 0x56 || rs[SWAP_STATE_SIZE + 1] != 0x7a {
        return None;
    }

    let mut source_tcid = [0u8; 32];
    source_tcid.copy_from_slice(&rs[1..33]);

    let mut target_tcid = [0u8; 32];
    target_tcid.copy_from_slice(&rs[34..66]);

    let min_ta = u64::from_le_bytes(rs[67..75].try_into().ok()?);

    let mut owner_hash = [0u8; 32];
    owner_hash.copy_from_slice(&rs[76..108]);

    let mut owner_spk_hash = [0u8; 32];
    owner_spk_hash.copy_from_slice(&rs[109..141]);

    let mut receipt_cov_id = [0u8; 32];
    receipt_cov_id.copy_from_slice(&rs[142..174]);

    if min_ta == 0 {
        return None;
    }

    Some(ParsedSwapOrder {
        source_token_cov_id: source_tcid,
        target_token_cov_id: target_tcid,
        min_target_amount: min_ta,
        owner_hash,
        owner_spk_hash,
        receipt_cov_id,
        redeem_script: rs.to_vec(),
    })
}

/// Build swap_order redeemScript.
///
/// State (174B):
///   [0x20][source_token_cov_id 32B][0x20][target_token_cov_id 32B]
///   [0x08][min_target_amount 8B]
///   [0x20][owner_hash 32B][0x20][owner_spk_hash 32B]
///   [0x20][receipt_cov_id 32B]
/// Body: SWAP_ORDER_BODY
///
/// # Arguments
/// * `source_token_cov_id` - 32-byte CovenantID of the token being sold
/// * `target_token_cov_id` - 32-byte CovenantID of the token to receive
/// * `min_target_amount` - Minimum amount of target tokens to receive
/// * `owner_hash` - Blake2b-256 of owner's Schnorr public key (cancel auth)
/// * `owner_spk_hash` - Blake2b-256 of owner's SPK (output[toi] destination check)
/// * `receipt_cov_id` - 32-byte CovenantID of the expected trade_receipt contract.
///   IMPORTANT: This is the Kaspa CovenantID = Blake2b(key="CovenantID",
///   genesis_outpoint + auth_outputs), NOT blake2b(redeemScript). The receipt
///   must be deployed as a version=1 TX with CovenantBinding.
///
/// # Errors
/// Returns error if `min_target_amount` is 0.
pub fn build_swap_redeem_script(
    source_token_cov_id: &[u8; 32],
    target_token_cov_id: &[u8; 32],
    min_target_amount: u64,
    owner_hash: &[u8; 32],
    owner_spk_hash: &[u8; 32],
    receipt_cov_id: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if min_target_amount == 0 {
        return Err(crate::KobError::Contract(
            "min_target_amount must be > 0 (zero allows empty fill)".into(),
        ));
    }
    let mut rs = Vec::with_capacity(SWAP_RS_SIZE);
    // State (174 bytes)
    rs.push(0x20);
    rs.extend_from_slice(source_token_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(target_token_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_target_amount));
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(owner_spk_hash);
    rs.push(0x20);
    rs.extend_from_slice(receipt_cov_id);
    // Body
    rs.extend_from_slice(SWAP_ORDER_BODY);
    debug_assert_eq!(rs.len(), SWAP_RS_SIZE);
    Ok(rs)
}

/// Build swap_order fill sigscript.
///
/// Layout: `[rii] [toi] [Op1] [pushData(RS)]`
///
/// * `receipt_input_idx` - Input index of the trade_receipt
/// * `target_output_idx` - Output index where user receives target tokens
/// * `redeem_script` - The swap order redeemScript being spent
///
/// sigOpCount = 0 for this input.
pub fn build_swap_fill_sigscript(
    receipt_input_idx: u16,
    target_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(5 + redeem_script.len() + 3);
    push_index(&mut ss, receipt_input_idx);
    push_index(&mut ss, target_output_idx);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build swap_order cancel sigscript.
///
/// Layout: `[pushData(sig+type 65B)] [pushData(pk 32B)] [Op0] [pushData(RS)]`
///
/// * `signature` - 64-byte Schnorr signature
/// * `pubkey` - 32-byte Schnorr public key (blake2b must match owner_hash)
/// * `redeem_script` - The swap order redeemScript being spent
///
/// sigOpCount = 1 for this input.
pub fn build_swap_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = [0u8; 65];
    sig_with_type[..64].copy_from_slice(signature);
    sig_with_type[64] = 0x01;

    let mut ss = Vec::with_capacity(66 + 34 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_and_rs_sizes() {
        // Verify body length is consistent with constants.
        assert_eq!(SWAP_ORDER_BODY.len(), SWAP_BODY_SIZE);
        assert_eq!(SWAP_RS_SIZE, SWAP_STATE_SIZE + SWAP_BODY_SIZE);
    }

    #[test]
    fn roundtrip_swap() {
        let source_tcid = [0xAA; 32];
        let target_tcid = [0xBB; 32];
        let ohash = [0xCC; 32];
        let ospkh = [0xDD; 32];
        let rcid = [0xEE; 32];

        let rs = build_swap_redeem_script(
            &source_tcid,
            &target_tcid,
            5_000_000,
            &ohash,
            &ospkh,
            &rcid,
        )
        .unwrap();
        assert_eq!(rs.len(), SWAP_RS_SIZE);

        let parsed = parse_swap_order_rs(&rs).expect("should parse swap");
        assert_eq!(parsed.source_token_cov_id, source_tcid);
        assert_eq!(parsed.target_token_cov_id, target_tcid);
        assert_eq!(parsed.min_target_amount, 5_000_000);
        assert_eq!(parsed.owner_hash, ohash);
        assert_eq!(parsed.owner_spk_hash, ospkh);
        assert_eq!(parsed.receipt_cov_id, rcid);
        assert_eq!(parsed.redeem_script.len(), SWAP_RS_SIZE);
    }

    #[test]
    fn zero_min_target_rejected() {
        let t = [0u8; 32];
        let result = build_swap_redeem_script(&t, &t, 0, &t, &t, &t);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_size_returns_none() {
        assert!(parse_swap_order_rs(&vec![0x51; 100]).is_none());
    }

    #[test]
    fn wrong_body_signature_returns_none() {
        // Right size but wrong body signature
        let mut fake = vec![0x20; SWAP_RS_SIZE];
        // Set push prefixes correctly
        fake[33] = 0x20;
        fake[66] = 0x08;
        fake[75] = 0x20;
        fake[108] = 0x20;
        fake[141] = 0x20;
        // Wrong body signature
        fake[SWAP_STATE_SIZE] = 0x58; // should be 0x56
        fake[SWAP_STATE_SIZE + 1] = 0x7a;
        assert!(parse_swap_order_rs(&fake).is_none());
    }

    #[test]
    fn fill_sigscript_structure() {
        let t = [0u8; 32];
        let rs = build_swap_redeem_script(&t, &t, 1, &t, &t, &t).unwrap();
        let ss = build_swap_fill_sigscript(2, 1, &rs);
        // [rii=Op2(0x52)] [toi=Op1(0x51)] [Op1(selector)] [pushData(RS)]
        assert_eq!(ss[0], 0x52); // Op2 (rii=2)
        assert_eq!(ss[1], 0x51); // Op1 (toi=1)
        assert_eq!(ss[2], 0x51); // Op1 (selector = fill)
    }

    #[test]
    fn cancel_sigscript_structure() {
        let sig = [0xAA; 64];
        let pk = [0xBB; 32];
        let t = [0u8; 32];
        let rs = build_swap_redeem_script(&t, &t, 1, &t, &t, &t).unwrap();
        let ss = build_swap_cancel_sigscript(&sig, &pk, &rs);
        // [push(65B sig+type)] [push(32B pk)] [Op0] [pushData(RS)]
        assert_eq!(ss[0], 65); // pushdata length = 65
        assert_eq!(ss[65], 0x01); // sighash type
        assert_eq!(ss[66], 32); // pushdata length for pk
        let op0_pos = 66 + 33; // after sig_push(66) + pk_push(33)
        assert_eq!(ss[op0_pos], 0x00); // Op0 (selector = cancel)
    }

    #[test]
    fn fill_sigscript_with_large_indices() {
        let t = [0u8; 32];
        let rs = build_swap_redeem_script(&t, &t, 1, &t, &t, &t).unwrap();
        // Use indices > 16 to test push_index encoding
        let ss = build_swap_fill_sigscript(20, 18, &rs);
        // rii=20: [0x01, 0x14] (2 bytes)
        assert_eq!(ss[0], 0x01);
        assert_eq!(ss[1], 20);
        // toi=18: [0x01, 0x12] (2 bytes)
        assert_eq!(ss[2], 0x01);
        assert_eq!(ss[3], 18);
        // Op1 selector
        assert_eq!(ss[4], 0x51);
    }
}
