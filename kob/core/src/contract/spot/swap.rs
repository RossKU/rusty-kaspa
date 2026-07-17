use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::push_index;

/// Swap v1 state size (174B); the v18 state appends `[0x08][mmfee_bps 8B]`.
pub const SWAP_CORE_STATE_SIZE: usize = 174;

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

// ============================================================================
// V18 SWAP — ring legs (cross-pair + triangle), closes Fix-7 locally
// ============================================================================
//
// v18 (see kob/V18_DESIGN.md) replaces the KAS-bridged swap composition with
// purely local ring legs (token<->token = 2-cycle, triangle = 3-cycle):
//
//   - State: v1's 174B + `mmfee_bps` 8B (with push prefix: +9B => 183B).
//   - F2 (target floor) and F3 (owner SPK on the target output) kept.
//   - F5 replaced: `toi == OpAuthOutputIdx(giver_idx, 0)` where `giver_idx`
//     is sigscript-supplied and authenticated by
//     `OpInputCovenantId(giver_idx) == target_tcid` (sii-safe; replaces the
//     colliding global `OpCovOutputIdx(target, 0)` read, which broke when two
//     ring legs shared a target token).
//   - F4 replaced (conservation cap): this input's own slot-0 delivery
//     (`OpTxInputIndex Op0 OpAuthOutputIdx`) must carry
//     `value >= source_in - source_in/10000*mmfee_bps`. The receiver leg pins
//     slot 0 by SPK/floor (its F5/F3/F2); the giver pins the slot-0 value;
//     the matcher skim is capped and can only sit at slots >= 1. Both ends of
//     every ring edge are pinned, so the ring is safe with local checks only.
//   - The old F1 receipt check (`rii`/receipt_cov_id) is dropped from the
//     fill path: rings carry no receipts — the giver-side covenant-id
//     authentication replaces it. `receipt_cov_id` stays in the state layout
//     (spec keeps the 174B prefix) but is no longer read by the fill branch.
//   - All-or-nothing legs only (no ring partial — documented limitation).

/// Swap v18 state size: 174B (v1 fields) + 9B (`[0x08][mmfee_bps 8B]`).
pub const SWAP_STATE_SIZE: usize = SWAP_CORE_STATE_SIZE + 9;

/// Expected v18 swap body length.
pub const SWAP_BODY_EXPECTED_LEN: usize = 77;

/// Swap v18 redeemScript size (183B state + v18 body).
pub const SWAP_RS_SIZE: usize = SWAP_STATE_SIZE + SWAP_BODY_EXPECTED_LEN;

/// Build the v18 swap body.
///
/// Stack after state push (7 items, depth 0 = top):
///   mmfee_bps(0), rcid(1), ospkh(2), ohash(3), min_ta(4), target_tcid(5),
///   source_tcid(6)
/// with the selector at depth 7 in every sigscript form.
///
/// Fill sigscript:   `[giver_idx][toi][Op1][pushData(RS)]`
/// Cancel sigscript: `[pushData(sig+type 65B)][pushData(pk 32B)][Op0][pushData(RS)]`
pub fn build_swap_body() -> Vec<u8> {
    use crate::contract::spot::order::{e_num, e_pick, e_roll, ops::*};
    let mut b: Vec<u8> = Vec::with_capacity(128);

    e_roll(&mut b, 7); // selector
    b.push(OP0);
    b.push(GT); // truthy -> fill
    b.push(IF);
    {
        // FILL: mmfee(0), rcid(1), ospkh(2), ohash(3), min_ta(4),
        //       target_tcid(5), source_tcid(6), toi(7), giver(8)
        //
        // F5-auth: giver really is an input of the TARGET token.
        e_pick(&mut b, 8); // giver
        b.push(INPUTCOVENANTID);
        e_pick(&mut b, 6); // target_tcid (5 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        // F5-bind: toi is the giver's slot-0 delivery (derived, not free).
        e_pick(&mut b, 8); // giver
        b.push(OP0);
        b.push(AUTHOUTPUTIDX);
        e_pick(&mut b, 8); // toi (7 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        // F2: output[toi].value >= min_target_amount.
        e_pick(&mut b, 7); // toi
        b.push(TXOUTPUTAMOUNT);
        e_pick(&mut b, 5); // min_ta (4 + 1)
        b.push(GTE);
        b.push(VERIFY);
        // F3: blake2b(output[toi].spk) == owner_spk_hash.
        e_pick(&mut b, 7); // toi
        b.push(TXOUTPUTSPK);
        b.push(BLAKE2B);
        e_pick(&mut b, 3); // ospkh (2 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        // F4 (conservation cap): own slot-0 delivery value >=
        //   source_in - source_in/10000*mmfee_bps.
        b.push(TXINPUTINDEX);
        b.push(OP0);
        b.push(AUTHOUTPUTIDX);
        b.push(TXOUTPUTAMOUNT); // out_val
        b.push(TXINPUTINDEX);
        b.push(TXINPUTAMOUNT); // source_in
        b.push(DUP);
        e_num(&mut b, 10000);
        b.push(DIV);
        e_pick(&mut b, 3); // mmfee_bps (0 + 3 temporaries)
        b.push(MUL); // fee = source_in/10000*mmfee_bps
        b.push(SUB); // floor = source_in - fee
        b.push(GTE);
        b.push(VERIFY); // out_val >= floor
        // cleanup: 9 items
        for _ in 0..4 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        // CANCEL: mmfee(0), rcid(1), ospkh(2), ohash(3), min_ta(4),
        //         target_tcid(5), source_tcid(6), pk(7), sig(8)
        e_pick(&mut b, 7); // pk
        b.push(BLAKE2B);
        e_pick(&mut b, 4); // ohash (3 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        e_roll(&mut b, 8); // sig
        e_roll(&mut b, 8); // pk
        b.push(CHECKSIG);
        b.push(VERIFY);
        // cleanup: 7 items
        for _ in 0..3 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ENDIF);
    b.push(OP1);
    b
}

/// Parsed v18 swap order state fields.
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
    /// Receipt covenant ID (kept in the state layout; unused by v18 fill).
    pub receipt_cov_id: [u8; 32],
    /// Max matcher fee in basis points (per-leg conservation cap).
    pub mmfee_bps: u64,
    /// Full redeemScript bytes.
    pub redeem_script: Vec<u8>,
}

/// Parse a v18 swap order redeemScript.
///
/// State layout: v1's 174B prefix (same offsets), then
///   `[0x08][mmfee_bps 8B]` = bytes 174..183.
pub fn parse_swap_order_rs(rs: &[u8]) -> Option<ParsedSwapOrder> {
    if rs.len() != SWAP_RS_SIZE {
        return None;
    }
    if rs[0] != 0x20 || rs[33] != 0x20 || rs[66] != 0x08
        || rs[75] != 0x20 || rs[108] != 0x20 || rs[141] != 0x20
        || rs[174] != 0x08
    {
        return None;
    }
    // Body signature: Op7 OpRoll (0x57 0x7a) — distinct from v1 (0x56 0x7a).
    if rs[SWAP_STATE_SIZE] != 0x57 || rs[SWAP_STATE_SIZE + 1] != 0x7a {
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
    let mmfee_bps = u64::from_le_bytes(rs[175..183].try_into().ok()?);

    if min_ta == 0 || mmfee_bps > 10000 {
        return None;
    }

    Some(ParsedSwapOrder {
        source_token_cov_id: source_tcid,
        target_token_cov_id: target_tcid,
        min_target_amount: min_ta,
        owner_hash,
        owner_spk_hash,
        receipt_cov_id,
        mmfee_bps,
        redeem_script: rs.to_vec(),
    })
}

/// Build the v18 swap_order redeemScript (183B state + v18 body).
pub fn build_swap_redeem_script(
    source_token_cov_id: &[u8; 32],
    target_token_cov_id: &[u8; 32],
    min_target_amount: u64,
    owner_hash: &[u8; 32],
    owner_spk_hash: &[u8; 32],
    receipt_cov_id: &[u8; 32],
    max_matcher_fee_bps: u64,
) -> crate::Result<Vec<u8>> {
    if min_target_amount == 0 {
        return Err(crate::KobError::Contract(
            "min_target_amount must be > 0 (zero allows empty fill)".into(),
        ));
    }
    if max_matcher_fee_bps > 10000 {
        return Err(crate::KobError::Contract("max_matcher_fee_bps must be <= 10000".into()));
    }
    let body = build_swap_body();
    let mut rs = Vec::with_capacity(SWAP_STATE_SIZE + body.len());
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
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_matcher_fee_bps));
    rs.extend_from_slice(&body);
    debug_assert_eq!(rs.len(), SWAP_RS_SIZE);
    Ok(rs)
}

/// Build v18 swap fill sigscript.
///
/// Layout: `[giver_idx][toi][Op1][pushData(RS)]`
///
/// * `giver_input_idx` — tx-input index of the ring leg delivering THIS
///   swap's target tokens (its covenant id must equal `target_tcid`).
/// * `target_output_idx` — output index where the owner receives target
///   tokens; must equal the giver's slot-0 authorized output.
pub fn build_swap_fill_sigscript(
    giver_input_idx: u16,
    target_output_idx: u16,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(5 + redeem_script.len() + 3);
    push_index(&mut ss, giver_input_idx);
    push_index(&mut ss, target_output_idx);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
