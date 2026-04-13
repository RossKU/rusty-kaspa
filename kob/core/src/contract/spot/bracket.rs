use crate::primitives::{push_data, u64_le};

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

