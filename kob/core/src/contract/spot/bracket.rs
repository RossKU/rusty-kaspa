use crate::primitives::{push_data, u64_le};
use crate::contract::spot::order::{e_num, e_pick, e_roll, v17op};

/// bracket_order body bytecode (141 bytes).
///
/// **N6 (single oco_sell)**: The bracket contract now creates 1 oco_sell UTXO
/// at output[2] instead of 2 oco_pair UTXOs at output[2]+output[3].
/// The state no longer contains separate tp_spk/sl_spk; it stores a single
/// `oco_spk` (the P2SH SPK of the oco_sell contract) and `oco_min_val`.
///
/// Includes N5 fix (trade_spk_hash) and N4 fix (receipt_cov_id).
///
/// - SELL fill: `blake2b(output[0].spk) == trade_spk_hash`
/// - BUY fill:  `blake2b(output[1].spk) == trade_spk_hash`
///
/// State layout (224B):
///   [0x08][entry_type 8B][0x20][token_cov_id 32B][0x08][epnum 8B]
///   [0x08][epden 8B][0x25][oco_spk 37B][0x08][oco_min_val 8B]
///   [0x08][min_fill 8B][0x08][min_receipt_val 8B][0x20][receipt_cov_id 32B]
///   [0x20][trade_spk_hash 32B][0x20][owner_hash 32B]
///
/// Fill stack (12 items, bottom->top):
///   selector, etype, tcid, epnum, epden, oco_spk, oco_mv,
///   mfill, mrv, rcid, trade_spk_hash, owner_hash
///
/// Dispatch threshold: 400 (fill sigscript=369B, cancel=468B).
/// Body = 141B. RS = 224 + 141 = 365 bytes.
///
/// OpPick depths (12-item fill stack, from top):
///   owner_hash=0, trade_spk_hash=1, rcid=2, mrv=3, mfill=4,
///   oco_mv=5, oco_spk=6, epden=7, epnum=8, tcid=9, etype=10, selector=11
///
/// Cancel stack (14 items): Op0, sig, pk + 11 state items.
///   pk=11, sig=12, Op0=13 (from top of 14-item stack)
pub const BRACKET_ORDER_BODY: &[u8] = &[
    // === Dispatch (7B): sigLen < 400 -> fill, >= 400 -> cancel ===
    0xb9, 0xc9,                         // OpTxInputIndex, OpTxInputScriptSigLen -> sigLen
    0x02, 0x90, 0x01,                   // push 400 (0x0190 LE)
    0x9f, 0x63,                         // OpLessThan, OpIf (fill path)

    // === OCO output SPK check (6B) ===
    // Stack(12): push out2.spk -> 13 items, Op7 picks oco_spk (depth 7)
    0x52, 0xc3,                         // Op2 OpTxOutputSpk -> output[2].spk
    0x57, 0x79,                         // Op7 OpPick -> oco_spk
    0x87, 0x69,                         // OpEqual OpVerify

    // === OCO output value check (6B) ===
    // Stack(12): push out2.amt -> 13 items, Op6 picks oco_mv (depth 6)
    0x52, 0xc2,                         // Op2 OpTxOutputAmount -> output[2].value
    0x56, 0x79,                         // Op6 OpPick -> oco_min_value
    0xa2, 0x69,                         // OpGTE OpVerify

    // === Receipt value check (6B) ===
    // Stack(12): push in2.amt -> 13 items, Op4 picks mrv (depth 4)
    0x52, 0xbe,                         // Op2 OpTxInputAmount -> input[2].amount
    0x54, 0x79,                         // Op4 OpPick -> min_receipt_value
    0xa2, 0x69,                         // OpGTE OpVerify (amount >= min_receipt_value)

    // === Receipt covenant id check (6B) ===
    // Stack(12): push in2.cov_id -> 13 items, Op3 picks rcid (depth 3)
    // N4 fix: ensures input[2] IS a genuine trade_receipt contract.
    0x52, 0xcf,                         // Op2 OpInputCovenantId -> input[2].covenant_id
    0x53, 0x79,                         // Op3 OpPick -> receipt_cov_id (depth 3)
    0x87, 0x69,                         // OpEqual OpVerify (cov_id must match expected)

    // === Entry type dispatch (4B) ===
    // Stack(12): Op10 picks etype (depth 10), OpBin2Num, OpIf
    0x5a, 0x79,                         // Op10 OpPick -> entry_type
    0xce, 0x63,                         // OpBin2Num, OpIf (truthy = sell entry)

    // === SELL ENTRY (38B) ===
    // Stack starts at 12. Push my_val -> 13. All picks relative to current stack.
    0xb9, 0xbe,                         // OpTxInputIndex OpTxInputAmount -> my_val
    // Stack(13): 0=my_val, ..., epnum at depth 9
    0x59, 0x79,                         // Op9 OpPick -> epnum
    0x95,                               // OpMul -> my_val * epnum
    // Stack(13): 0=my_val*epnum, ..., epden at depth 8
    0x58, 0x79,                         // Op8 OpPick -> epden
    0x96,                               // OpDiv -> ek = my_val * epnum / epden
    // Stack(13): 0=ek, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x76,                               // OpDup -> [14 items: ek, ek, ...]
    // Stack(14): 0=ek, 1=ek, 2=owner_hash, 3=trade_spk_hash, 4=rcid, 5=mrv, 6=mfill
    0x56, 0x79,                         // Op6 OpPick -> mfill
    0xa2, 0x69,                         // OpGTE OpVerify (ek >= mfill)
    // Stack(13): 0=ek, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x00, 0xc2,                         // Op0 OpTxOutputAmount -> output[0].value
    // Stack(14): 0=out0.val, 1=ek, ...
    0x7c,                               // OpSwap
    0xa2, 0x69,                         // OpGTE OpVerify (output[0] >= ek)
    // Stack(12): 0=owner_hash, 1=trade_spk_hash, 2=rcid, ...
    // === N5: verify output[0].spk matches trade_spk_hash (7B) ===
    0x00, 0xc3,                         // Op0 OpTxOutputSpk -> output[0].spk
    0xaa,                               // OpBlake2b -> blake2b(output[0].spk)
    // Stack(13): 0=hash, 1=owner_hash, 2=trade_spk_hash, ...
    0x52, 0x79,                         // Op2 OpPick -> trade_spk_hash (depth 2)
    0x87, 0x69,                         // OpEqual OpVerify
    // Stack(12) remaining: selector, etype, tcid, epnum, epden, oco_spk, oco_mv,
    //   mfill, mrv, rcid, trade_spk_hash, owner_hash
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6 (total 12 drops)
    0x51,                               // Op1 TRUE

    // === BUY ENTRY (39B) ===
    0x67,                               // OpElse (buy path)
    // Stack starts at 12. Push kas -> 13.
    0xb9, 0xbe,                         // OpTxInputIndex OpTxInputAmount -> kas
    // Stack(13): 0=kas, ..., epden at depth 8
    0x58, 0x79,                         // Op8 OpPick -> epden
    0x96,                               // OpDiv -> kas / epden
    // Stack(13): 0=kas/epden, ..., epnum at depth 9
    0x59, 0x79,                         // Op9 OpPick -> epnum
    0x95,                               // OpMul -> et = kas / epden * epnum
    // Stack(13): 0=et, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x76,                               // OpDup -> [14 items: et, et, ...]
    // Stack(14): 0=et, 1=et, 2=owner_hash, 3=trade_spk_hash, 4=rcid, 5=mrv, 6=mfill
    0x56, 0x79,                         // Op6 OpPick -> mfill
    0xa2, 0x69,                         // OpGTE OpVerify (et >= mfill)
    // Stack(13): 0=et, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x51, 0xc2,                         // Op1 OpTxOutputAmount -> output[1].value
    // Stack(14): 0=out1.val, 1=et, ...
    0x7c,                               // OpSwap
    0xa2, 0x69,                         // OpGTE OpVerify (output[1] >= et)
    // Stack(12): 0=owner_hash, 1=trade_spk_hash, 2=rcid, ...
    // === N5: verify output[1].spk matches trade_spk_hash (7B) ===
    0x51, 0xc3,                         // Op1 OpTxOutputSpk -> output[1].spk
    0xaa,                               // OpBlake2b -> blake2b(output[1].spk)
    // Stack(13): 0=hash, 1=owner_hash, 2=trade_spk_hash, ...
    0x52, 0x79,                         // Op2 OpPick -> trade_spk_hash (depth 2)
    0x87, 0x69,                         // OpEqual OpVerify
    // Stack(12) remaining: same 12 items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6 (total 12 drops)
    0x51,                               // Op1 TRUE
    0x68,                               // OpEndIf (entry type)

    // === CANCEL (28B) ===
    0x67,                               // OpElse (cancel path, sigLen >= 400)
    // Cancel stack (14 items): Op0, sig, pk, etype, tcid, epnum, epden,
    //   oco_spk, oco_mv, mfill, mrv, rcid, trade_spk_hash, owner_hash
    // Depths: 0=owner_hash, 1=trade_spk_hash, 2=rcid, ..., 11=pk, 12=sig, 13=Op0
    0x5b, 0x79,                         // Op11 OpPick -> pk (depth 11)
    0x76,                               // OpDup
    0xaa,                               // OpBlake2b -> hash(pk)
    // Stack(16): 0=hash(pk), 1=pk_copy, 2=owner_hash, 3=trade_spk_hash, ...
    0x52, 0x79,                         // Op2 OpPick -> owner_hash (depth 2)
    0x87, 0x69,                         // OpEqual OpVerify (blake2b(pk) == owner_hash)
    // Stack(15): 0=pk_copy, 1=owner_hash, 2=trade_spk_hash, ..., 12=pk, 13=sig, 14=Op0
    0x5d, 0x7a,                         // Op13 OpRoll -> sig (depth 13)
    0x7c,                               // OpSwap -> [sig, pk_copy]
    0xad,                               // OpCheckSigVerify (consumes sig and pk_copy)
    // Stack(13) remaining: Op0, pk, etype, tcid, epnum, epden, oco_spk, oco_mv,
    //   mfill, mrv, rcid, trade_spk_hash, owner_hash
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,       // OpDrop x6 (total 13 drops)
    0x51,                               // Op1 TRUE
    0x68,                               // OpEndIf (dispatch)
];

/// Build bracket_order redeemScript.
///
/// N6 (single oco_sell): State now stores a single `oco_spk` + `oco_min_val`
/// for the exit order at output[2], replacing the previous tp_spk/sl_spk pair.
///
/// Includes N5 (trade_spk_hash) and N4 (receipt_cov_id) fixes.
///
/// State (224B):
///   [0x08][entry_type 8B][0x20][token_cov_id 32B][0x08][epnum 8B]
///   [0x08][epden 8B][0x25][oco_spk 37B][0x08][oco_min_val 8B]
///   [0x08][min_fill 8B][0x08][min_receipt_val 8B][0x20][receipt_cov_id 32B]
///   [0x20][trade_spk_hash 32B][0x20][owner_hash 32B]
/// Body (141B): BRACKET_ORDER_BODY
/// Total: 365 bytes
///
/// # Arguments
/// * `entry_type` - 0 = buy entry, 1 = sell entry
/// * `token_cov_id` - 32-byte token covenant ID
/// * `entry_price_num` - Entry price numerator
/// * `entry_price_den` - Entry price denominator
/// * `oco_spk` - 37-byte oco_sell P2SH SPK (version 2B + script 35B).
///   This is the SPK of the single oco_sell UTXO at output[2].
/// * `oco_min_value` - Minimum value for the oco_sell output (sompi)
/// * `min_fill` - Minimum fill amount (sompi)
/// * `min_receipt_value` - Minimum value of receipt input (sompi)
/// * `receipt_cov_id` - 32-byte covenant_id of the expected trade_receipt contract.
///   IMPORTANT: This is the Kaspa CovenantID = Blake2b(key="CovenantID",
///   genesis_outpoint + auth_outputs), NOT blake2b(redeemScript). The receipt
///   must be deployed as a version=1 TX with CovenantBinding.
/// * `trade_spk_hash` - Blake2b hash of the trade output's scriptPublicKey.
///   For SELL entry: blake2b(output[0].spk) must match (KAS destination).
///   For BUY entry:  blake2b(output[1].spk) must match (token destination).
///   This prevents an adversarial matcher from redirecting traded value.
/// * `owner_hash` - Blake2b hash of owner pubkey (for cancel authorization)
///
/// # Panics
/// Panics if `entry_price_num`, `entry_price_den`, or `min_fill` is 0.
pub fn build_bracket_redeem_script(
    entry_type: u64,
    token_cov_id: &[u8; 32],
    entry_price_num: u64,
    entry_price_den: u64,
    oco_spk: &[u8; 37],
    oco_min_value: u64,
    min_fill: u64,
    min_receipt_value: u64,
    receipt_cov_id: &[u8; 32],
    trade_spk_hash: &[u8; 32],
    owner_hash: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if entry_price_num <= 0 {
        return Err(crate::KobError::Contract("entry_price_num must be > 0".into()));
    }
    if entry_price_den <= 0 {
        return Err(crate::KobError::Contract("entry_price_den must be > 0".into()));
    }
    if min_fill <= 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0 (zero allows dust griefing)".into()));
    }
    let mut rs = Vec::with_capacity(365);
    // State (224 bytes)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_type));
    rs.push(0x20);
    rs.extend_from_slice(token_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_den));
    rs.push(0x25);
    rs.extend_from_slice(oco_spk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(oco_min_value));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_receipt_value));
    rs.push(0x20);
    rs.extend_from_slice(receipt_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(trade_spk_hash);
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    // Body (141 bytes)
    rs.extend_from_slice(BRACKET_ORDER_BODY);
    Ok(rs)
}

/// Build bracket_order fill sigscript: `[Op1][pushData(redeemScript)]`
///
/// sigOpCount = 0 for this input.
/// sigscript length = 369B (< 400 threshold -> fill path).
pub fn build_bracket_fill_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build bracket_order cancel sigscript:
/// `[Op0][pushData(sig+type 65B)][pushData(pk 32B)][pushData(redeemScript)]`
///
/// sigOpCount = 1 for this input.
/// sigscript length = 468B (>= 400 threshold -> cancel path).
pub fn build_bracket_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(1 + 66 + 33 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

// ============================================================================
// V18 BRACKET — receipt-gated IFD/IFO hard path (see kob/V18_DESIGN.md,
// "IFD / IFO — MANDATORY")
// ============================================================================
//
// The v18 bracket keeps the v1 224B state layout byte-for-byte (the embedded
// `oco_spk` is a generation-agnostic 37B SPK, so it pins a v18 OCO P2SH with
// no layout change) and the same receipt-gated fill structure, with these
// v18 changes:
//
//   1. SELECTOR DISPATCH (Op1 = fill, Op0 = cancel) replaces the v1
//      sigLen<400 split. The v18 body is longer than v1's 141B, which pushes
//      the fill sigscript (`[sel][pushData(RS)]` = RS+4) past the fixed 400
//      threshold — a length-based dispatch cannot survive a body-size change,
//      selector dispatch is also the v18 house style throughout.
//   2. CSV(50) exposure delay on the fill path (v18 fill-family parity; the
//      cancel path stays immediate, as everywhere else in the generation).
//   3. TOKEN-BINDING checks (the Fix-3-analog for the bracket's rigid shape;
//      the bracket input itself is the only covenant-capable input it can
//      derive indices from, so fixed output indices + `OpOutputCovenantId`
//      carry the same guarantee the sweep contracts get from
//      `OpAuthOutputIdx`):
//        - BUY entry: `OpOutputCovenantId(1) == tcid` — the delivery output
//          must be GENUINE tokens of the stated covenant. v1 only checked
//          value+SPK, so a matcher could satisfy the entry with plain KAS
//          labeled as tokens (wrong-asset delivery).
//        - BUY entry: `OpOutputCovenantId(2) == tcid` — the spawned OCO must
//          hold genuine tokens, i.e. the done-leg is a LIVE v18 OCO sell
//          (its fill paths need a token-covenant input); v1 allowed a
//          plain-KAS "OCO" that could never execute (dead done-leg trap).
//        - SELL entry: `OpInputCovenantId(self) == tcid` plus the standard
//          v18 Fix-3 F4 (`OpTxInputIndex Op0 OpAuthOutputIdx` → own token
//          output, covenant == own, value >= token_in) — identical to the
//          v18 sell/OCO conservation form.
//
// RIGID TX SHAPE (input[2] = receipt, outputs[0..3) = KAS/token/OCO) is kept
// deliberately: the bracket's counterparty is the receipt-holding matcher,
// not book orders, so the entry fill is its own tx and never a sweep member.
// The v18 sweep-shape machinery (canonical price attestation offsets,
// per-term tii lists) is therefore not applicable — the bracket reads no
// counterparty sigscript at all; its price is its own state (epnum/epden).
//
// No mmfee field: as in v1, the matcher's compensation is the entry spread
// (the entry price fully allocates kas_in/token_in), so there is no fee
// deduction for a BPS cap to bound.
//
// Sigscripts:
//   Fill:   [Op1] [pushData(RS)]                        sigOpCount = 0
//   Cancel: [pushData(sig+type 65B)] [pushData(pk 32B)] [Op0] [pushData(RS)]
//                                                       sigOpCount = 1
//
// Stack after state push (11 items, depth from top):
//   owner_hash(0), trade_spk_hash(1), rcid(2), mrv(3), mfill(4),
//   oco_mv(5), oco_spk(6), epden(7), epnum(8), tcid(9), etype(10)
// with the selector at depth 11 in every sigscript form.

/// Bracket state size (224B, shared by v1 and v18).
pub const BRACKET_V18_STATE_SIZE: usize = 224;

/// Expected v18 bracket body length (deterministic; pinned in tests).
pub const BRACKET_V18_BODY_EXPECTED_LEN: usize = 148;

/// v18 bracket redeemScript size (224B state + v18 body).
pub const BRACKET_V18_RS_SIZE: usize = BRACKET_V18_STATE_SIZE + BRACKET_V18_BODY_EXPECTED_LEN;

/// Build the v18 bracket body.
///
/// Selectors: 1 = FILL (entry execution), 0 = CANCEL (owner signature).
/// Any other selector falls into the cancel branch and dies on the
/// signature check (fail-closed).
pub fn build_bracket_v18_body() -> Vec<u8> {
    use v17op::*;
    let mut b: Vec<u8> = Vec::with_capacity(256);

    // ===== DISPATCH: selector (depth 11) == 1 -> fill, else cancel =====
    e_roll(&mut b, 11);
    e_num(&mut b, 1);
    b.push(EQUAL);
    b.push(IF);
    {
        // ===== FILL PATH =====
        // Exposure delay (v18 fill-family parity).
        e_num(&mut b, 50);
        b.push(CSV);
        // Receipt value: input[2].amount >= min_receipt_val.
        e_num(&mut b, 2);
        b.push(TXINPUTAMOUNT);
        e_pick(&mut b, 4); // mrv (3 + 1)
        b.push(GTE);
        b.push(VERIFY);
        // Receipt covenant: OpInputCovenantId(2) == receipt_cov_id (N4).
        e_num(&mut b, 2);
        b.push(INPUTCOVENANTID);
        e_pick(&mut b, 3); // rcid (2 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        // OCO spawn SPK: output[2].spk == oco_spk (byte-exact 37B).
        e_num(&mut b, 2);
        b.push(TXOUTPUTSPK);
        e_pick(&mut b, 7); // oco_spk (6 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        // OCO spawn value: output[2].value >= oco_min_val.
        e_num(&mut b, 2);
        b.push(TXOUTPUTAMOUNT);
        e_pick(&mut b, 6); // oco_mv (5 + 1)
        b.push(GTE);
        b.push(VERIFY);
        // Entry-type dispatch (truthy = sell entry).
        e_pick(&mut b, 10); // etype
        b.push(BIN2NUM);
        b.push(IF);
        {
            // ===== SELL ENTRY =====
            // The bracket UTXO must hold the STATED token.
            b.push(TXINPUTINDEX);
            b.push(INPUTCOVENANTID);
            e_pick(&mut b, 10); // tcid (9 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // ek = token_in * epnum / epden; ek >= mfill.
            b.push(TXINPUTINDEX);
            b.push(TXINPUTAMOUNT);
            e_pick(&mut b, 9); // epnum (8 + 1)
            b.push(MUL);
            e_pick(&mut b, 8); // epden (7 + 1)
            b.push(DIV);
            b.push(DUP);
            e_pick(&mut b, 6); // mfill (4 + 2)
            b.push(GTE);
            b.push(VERIFY);
            // output[0].value >= ek (seller's KAS proceeds).
            b.push(OP0);
            b.push(TXOUTPUTAMOUNT);
            b.push(SWAP);
            b.push(GTE);
            b.push(VERIFY);
            // blake2b(output[0].spk) == trade_spk_hash (N5).
            b.push(OP0);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(&mut b, 2); // trade_spk_hash (1 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // F4 (Fix-3): own tokens conserved to the own authorized output.
            b.push(TXINPUTINDEX);
            b.push(OP0);
            b.push(AUTHOUTPUTIDX);
            b.push(DUP);
            b.push(OUTPUTCOVENANTID);
            b.push(TXINPUTINDEX);
            b.push(INPUTCOVENANTID);
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(TXOUTPUTAMOUNT);
            b.push(TXINPUTINDEX);
            b.push(TXINPUTAMOUNT);
            b.push(GTE);
            b.push(VERIFY);
        }
        b.push(ELSE);
        {
            // ===== BUY ENTRY =====
            // et = kas_in / epden * epnum; et >= mfill.
            b.push(TXINPUTINDEX);
            b.push(TXINPUTAMOUNT);
            e_pick(&mut b, 8); // epden (7 + 1)
            b.push(DIV);
            e_pick(&mut b, 9); // epnum (8 + 1)
            b.push(MUL);
            b.push(DUP);
            e_pick(&mut b, 6); // mfill (4 + 2)
            b.push(GTE);
            b.push(VERIFY);
            // output[1].value >= et (buyer's token delivery).
            e_num(&mut b, 1);
            b.push(TXOUTPUTAMOUNT);
            b.push(SWAP);
            b.push(GTE);
            b.push(VERIFY);
            // blake2b(output[1].spk) == trade_spk_hash (N5).
            e_num(&mut b, 1);
            b.push(TXOUTPUTSPK);
            b.push(BLAKE2B);
            e_pick(&mut b, 2); // trade_spk_hash (1 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // Delivery must be GENUINE tokens of tcid (wrong-asset guard).
            e_num(&mut b, 1);
            b.push(OUTPUTCOVENANTID);
            e_pick(&mut b, 10); // tcid (9 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
            // Spawned OCO must hold genuine tokens (live v18 done-leg).
            e_num(&mut b, 2);
            b.push(OUTPUTCOVENANTID);
            e_pick(&mut b, 10); // tcid (9 + 1)
            b.push(EQUAL);
            b.push(VERIFY);
        }
        b.push(ENDIF);
        // Cleanup: 11 state items.
        for _ in 0..5 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ELSE);
    {
        // ===== CANCEL PATH =====
        // Sigscript [sig][pk][Op0][RS] -> stack: owner_hash(0) .. etype(10),
        // pk(11), sig(12).
        e_pick(&mut b, 11); // pk
        b.push(BLAKE2B);
        e_pick(&mut b, 1); // owner_hash (0 + 1)
        b.push(EQUAL);
        b.push(VERIFY);
        e_roll(&mut b, 12); // sig
        e_roll(&mut b, 12); // pk
        b.push(CHECKSIG);
        b.push(VERIFY);
        // Cleanup: 11 state items.
        for _ in 0..5 {
            b.push(TWO_DROP);
        }
        b.push(DROP);
    }
    b.push(ENDIF);
    b.push(OP1);
    b
}

/// Build the v18 bracket redeemScript (224B state + v18 body).
///
/// State layout identical to v1 (`build_bracket_redeem_script`); `oco_spk`
/// must be the 37B SPK (version u16LE + 35B P2SH script) of a **v18 OCO
/// sell** for a buy-entry IFO (the fill path enforces that the spawned
/// output holds genuine `token_cov_id` tokens, so only a token-selling
/// done-leg is functional), or of a v18 buy for a sell-entry re-buy leg.
///
/// See `build_bracket_redeem_script` for the argument docs; entry price is
/// NOT gcd-normalized (v1 parity — the bracket price is never read through
/// the canonical attestation offsets by other contracts).
pub fn build_bracket_v18_redeem_script(
    entry_type: u64,
    token_cov_id: &[u8; 32],
    entry_price_num: u64,
    entry_price_den: u64,
    oco_spk: &[u8; 37],
    oco_min_value: u64,
    min_fill: u64,
    min_receipt_value: u64,
    receipt_cov_id: &[u8; 32],
    trade_spk_hash: &[u8; 32],
    owner_hash: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if entry_type > 1 {
        return Err(crate::KobError::Contract("entry_type must be 0 (buy) or 1 (sell)".into()));
    }
    if entry_price_num == 0 {
        return Err(crate::KobError::Contract("entry_price_num must be > 0".into()));
    }
    if entry_price_den == 0 {
        return Err(crate::KobError::Contract("entry_price_den must be > 0".into()));
    }
    if min_fill == 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0 (zero allows dust griefing)".into()));
    }
    let body = build_bracket_v18_body();
    let mut rs = Vec::with_capacity(BRACKET_V18_STATE_SIZE + body.len());
    // State (224 bytes, identical layout to v1)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_type));
    rs.push(0x20);
    rs.extend_from_slice(token_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_den));
    rs.push(0x25);
    rs.extend_from_slice(oco_spk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(oco_min_value));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_receipt_value));
    rs.push(0x20);
    rs.extend_from_slice(receipt_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(trade_spk_hash);
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.extend_from_slice(&body);
    debug_assert_eq!(rs.len(), BRACKET_V18_RS_SIZE);
    Ok(rs)
}

/// Build the v18 bracket fill sigscript: `[Op1][pushData(RS)]`.
///
/// sigOpCount = 0. The fill input's sequence must be >= 50 (CSV exposure
/// delay, v18 fill-family parity).
pub fn build_bracket_v18_fill_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = fill)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the v18 bracket cancel sigscript:
/// `[pushData(sig+type 65B)][pushData(pk 32B)][Op0][pushData(RS)]`.
///
/// sigOpCount = 1. Note the ordering differs from the v1 bracket cancel
/// (`[Op0][sig][pk][RS]`): the v18 selector must sit directly below the
/// state (depth 11), so sig/pk go BELOW the selector (v17/v18 convention).
pub fn build_bracket_v18_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

