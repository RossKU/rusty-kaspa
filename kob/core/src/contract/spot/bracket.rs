use crate::primitives::{push_data, u64_le};

/// bracket_order body bytecode (159 bytes).
///
/// **N5 fix**: Adds `trade_spk_hash` to state and verifies the trade output
/// SPK in both SELL and BUY fill paths, preventing an adversarial matcher
/// from redirecting traded KAS/tokens to their own address.
///
/// - SELL fill: `blake2b(output[0].spk) == trade_spk_hash`
/// - BUY fill:  `blake2b(output[1].spk) == trade_spk_hash`
///
/// Also includes N4 fix: `input[2].covenant_id == receipt_cov_id`.
///
/// State layout (271B):
///   [0x08][entry_type 8B][0x20][token_cov_id 32B][0x08][epnum 8B]
///   [0x08][epden 8B][0x25][tp_spk 37B][0x08][tp_min_val 8B]
///   [0x25][sl_spk 37B][0x08][sl_min_val 8B][0x08][min_fill 8B]
///   [0x08][min_receipt_val 8B][0x20][receipt_cov_id 32B]
///   [0x20][trade_spk_hash 32B]  <- NEW (N5)
///   [0x20][owner_hash 32B]
///
/// Fill stack (14 items, bottom->top):
///   selector, etype, tcid, epnum, epden, tp_spk, tp_mv, sl_spk,
///   sl_mv, mfill, mrv, rcid, trade_spk_hash, owner_hash
///
/// Dispatch threshold: 480 (fill sigscript=434B, cancel=533B).
/// Body = 159B. RS = 271 + 159 = 430 bytes.
///
/// OpPick depths (trade_spk_hash field shifts +1 from N4):
///   TP SPK: Op8->Op9, TP val: Op7->Op8, SL SPK: Op6->Op7, SL val: Op5->Op6
///   Receipt val: Op3->Op4, Receipt cov: Op2->Op3
///   Entry type: Op11->Op12
///   SELL/BUY epnum: Op10->Op11, epden: Op9->Op10, mfill: Op5->Op6
///   CANCEL pk: Op12->Op13, sig: Op14->Op15 (roll)
///   Drops: SELL/BUY 13->14, CANCEL 14->15
pub const BRACKET_ORDER_BODY: &[u8] = &[
    // === Dispatch (7B): sigLen < 480 -> fill, >= 480 -> cancel ===
    0xb9, 0xc9,                         // OpTxInputIndex, OpTxInputScriptSigLen -> sigLen
    0x02, 0xe0, 0x01,                   // push 480 (0x01E0 LE)
    0x9f, 0x63,                         // OpLessThan, OpIf (fill path)

    // === TP output SPK check (6B) ===
    // Stack(14): push out2.spk, Op9 picks tp_spk (depth 9), Equal+Verify
    0x52, 0xc3,                         // Op2 OpTxOutputSpk -> output[2].spk
    0x59, 0x79,                         // Op9 OpPick -> tp_spk
    0x87, 0x69,                         // OpEqual OpVerify

    // === TP output value check (6B) ===
    // Stack(14): push out2.amt, Op8 picks tp_mv (depth 8), GTE+Verify
    0x52, 0xc2,                         // Op2 OpTxOutputAmount -> output[2].value
    0x58, 0x79,                         // Op8 OpPick -> tp_min_value
    0xa2, 0x69,                         // OpGTE OpVerify

    // === SL output SPK check (6B) ===
    // Stack(14): push out3.spk, Op7 picks sl_spk (depth 7), Equal+Verify
    0x53, 0xc3,                         // Op3 OpTxOutputSpk -> output[3].spk
    0x57, 0x79,                         // Op7 OpPick -> sl_spk
    0x87, 0x69,                         // OpEqual OpVerify

    // === SL output value check (6B) ===
    // Stack(14): push out3.amt, Op6 picks sl_mv (depth 6), GTE+Verify
    0x53, 0xc2,                         // Op3 OpTxOutputAmount -> output[3].value
    0x56, 0x79,                         // Op6 OpPick -> sl_min_value
    0xa2, 0x69,                         // OpGTE OpVerify

    // === Receipt value check (6B) ===
    // Stack(14): push in2.amt, Op4 picks mrv (depth 4), GTE+Verify
    0x52, 0xbe,                         // Op2 OpTxInputAmount -> input[2].amount
    0x54, 0x79,                         // Op4 OpPick -> min_receipt_value
    0xa2, 0x69,                         // OpGTE OpVerify (amount >= min_receipt_value)

    // === Receipt covenant id check (6B) ===
    // Stack(14): push in2.cov_id, Op3 picks rcid (depth 3), Equal+Verify
    // N4 fix: ensures input[2] IS a genuine trade_receipt contract.
    0x52, 0xcf,                         // Op2 OpInputCovenantId -> input[2].covenant_id
    0x53, 0x79,                         // Op3 OpPick -> receipt_cov_id (depth 3)
    0x87, 0x69,                         // OpEqual OpVerify (cov_id must match expected)

    // === Entry type dispatch (4B) ===
    // Stack(14): Op12 picks etype (depth 12), OpBin2Num, OpIf
    0x5c, 0x79,                         // Op12 OpPick -> entry_type
    0xce, 0x63,                         // OpBin2Num, OpIf (truthy = sell entry)

    // === SELL ENTRY (40B) ===
    // Stack starts at 14. Push my_val -> 15. All picks relative to current stack.
    0xb9, 0xbe,                         // OpTxInputIndex OpTxInputAmount -> my_val
    // Stack(15): 0=my_val, ..., 11=epnum (depths after my_val push)
    0x5b, 0x79,                         // Op11 OpPick -> epnum
    0x95,                               // OpMul -> my_val * epnum
    // Stack(15): 0=my_val*epnum, ..., 10=epden
    0x5a, 0x79,                         // Op10 OpPick -> epden
    0x96,                               // OpDiv -> ek = my_val * epnum / epden
    // Stack(15): 0=ek, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x76,                               // OpDup -> [16 items: ek, ek, ...]
    // Stack(16): 0=ek, 1=ek, 2=owner_hash, 3=trade_spk_hash, 4=rcid, 5=mrv, 6=mfill
    0x56, 0x79,                         // Op6 OpPick -> mfill
    0xa2, 0x69,                         // OpGTE OpVerify (ek >= mfill)
    // Stack(15): 0=ek, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x00, 0xc2,                         // Op0 OpTxOutputAmount -> output[0].value
    // Stack(16): 0=out0.val, 1=ek, ...
    0x7c,                               // OpSwap
    0xa2, 0x69,                         // OpGTE OpVerify (output[0] >= ek)
    // Stack(14): 0=owner_hash, 1=trade_spk_hash, 2=rcid, ...
    // === N5: verify output[0].spk matches trade_spk_hash (7B) ===
    0x00, 0xc3,                         // Op0 OpTxOutputSpk -> output[0].spk
    0xaa,                               // OpBlake2b -> blake2b(output[0].spk)
    // Stack(15): 0=hash, 1=owner_hash, 2=trade_spk_hash, ...
    0x52, 0x79,                         // Op2 OpPick -> trade_spk_hash (depth 2)
    0x87, 0x69,                         // OpEqual OpVerify
    // Stack(14) remaining: selector, etype, tcid, epnum, epden, tp_spk, tp_mv,
    //   sl_spk, sl_mv, mfill, mrv, rcid, trade_spk_hash, owner_hash
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7 (total 14 drops)
    0x51,                               // Op1 TRUE

    // === BUY ENTRY (41B) ===
    0x67,                               // OpElse (buy path)
    // Stack starts at 14. Push kas -> 15.
    0xb9, 0xbe,                         // OpTxInputIndex OpTxInputAmount -> kas
    // Stack(15): 0=kas, ..., 10=epden
    0x5a, 0x79,                         // Op10 OpPick -> epden
    0x96,                               // OpDiv -> kas / epden
    // Stack(15): 0=kas/epden, ..., 11=epnum
    0x5b, 0x79,                         // Op11 OpPick -> epnum
    0x95,                               // OpMul -> et = kas / epden * epnum
    // Stack(15): 0=et, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x76,                               // OpDup -> [16 items: et, et, ...]
    // Stack(16): 0=et, 1=et, 2=owner_hash, 3=trade_spk_hash, 4=rcid, 5=mrv, 6=mfill
    0x56, 0x79,                         // Op6 OpPick -> mfill
    0xa2, 0x69,                         // OpGTE OpVerify (et >= mfill)
    // Stack(15): 0=et, 1=owner_hash, 2=trade_spk_hash, 3=rcid, 4=mrv, 5=mfill, ...
    0x51, 0xc2,                         // Op1 OpTxOutputAmount -> output[1].value
    // Stack(16): 0=out1.val, 1=et, ...
    0x7c,                               // OpSwap
    0xa2, 0x69,                         // OpGTE OpVerify (output[1] >= et)
    // Stack(14): 0=owner_hash, 1=trade_spk_hash, 2=rcid, ...
    // === N5: verify output[1].spk matches trade_spk_hash (7B) ===
    0x51, 0xc3,                         // Op1 OpTxOutputSpk -> output[1].spk
    0xaa,                               // OpBlake2b -> blake2b(output[1].spk)
    // Stack(15): 0=hash, 1=owner_hash, 2=trade_spk_hash, ...
    0x52, 0x79,                         // Op2 OpPick -> trade_spk_hash (depth 2)
    0x87, 0x69,                         // OpEqual OpVerify
    // Stack(14) remaining: same 14 items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7 (total 14 drops)
    0x51,                               // Op1 TRUE
    0x68,                               // OpEndIf (entry type)

    // === CANCEL (30B) ===
    0x67,                               // OpElse (cancel path, sigLen >= 480)
    // Cancel stack (16 items): Op0, sig, pk, etype, tcid, epnum, epden,
    //   tp_spk, tp_mv, sl_spk, sl_mv, mfill, mrv, rcid, trade_spk_hash, owner_hash
    // Depths: 0=owner_hash, 1=trade_spk_hash, 2=rcid, 3=mrv, ..., 13=pk, 14=sig, 15=Op0
    0x5d, 0x79,                         // Op13 OpPick -> pk (depth 13)
    0x76,                               // OpDup
    0xaa,                               // OpBlake2b -> hash(pk)
    // Stack(19): 0=hash(pk), 1=pk_copy, 2=owner_hash, 3=trade_spk_hash, ...
    0x52, 0x79,                         // Op2 OpPick -> owner_hash (depth 2, unchanged)
    0x87, 0x69,                         // OpEqual OpVerify (blake2b(pk) == owner_hash)
    // Stack(17): 0=pk_copy, 1=owner_hash, 2=trade_spk_hash, ..., 14=pk, 15=sig, 16=Op0
    0x5f, 0x7a,                         // Op15 OpRoll -> sig (depth 15)
    0x7c,                               // OpSwap -> [sig, pk_copy]
    0xad,                               // OpCheckSigVerify (consumes sig and pk_copy)
    // Stack(15) remaining: Op0, pk, etype, tcid, epnum, epden, tp_spk, tp_mv,
    //   sl_spk, sl_mv, mfill, mrv, rcid, trade_spk_hash, owner_hash
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75,                                       // OpDrop x1 (total 15 drops)
    0x51,                               // Op1 TRUE
    0x68,                               // OpEndIf (dispatch)
];

/// Build bracket_order redeemScript.
///
/// N5: Adds `trade_spk_hash` to state and verifies trade output SPK in fill
/// paths, preventing an adversarial matcher from stealing KAS/tokens.
///
/// State (271B):
///   [0x08][entry_type 8B][0x20][token_cov_id 32B][0x08][epnum 8B]
///   [0x08][epden 8B][0x25][tp_spk 37B][0x08][tp_min_val 8B]
///   [0x25][sl_spk 37B][0x08][sl_min_val 8B][0x08][min_fill 8B]
///   [0x08][min_receipt_val 8B][0x20][receipt_cov_id 32B]
///   [0x20][trade_spk_hash 32B][0x20][owner_hash 32B]
/// Body (159B): BRACKET_ORDER_BODY
/// Total: 430 bytes
///
/// # Arguments
/// * `entry_type` - 0 = buy entry, 1 = sell entry
/// * `token_cov_id` - 32-byte token covenant ID
/// * `entry_price_num` - Entry price numerator
/// * `entry_price_den` - Entry price denominator
/// * `tp_spk` - 37-byte TP exit order P2SH SPK (version 2B + script 35B)
/// * `tp_min_value` - Minimum value for TP output (sompi)
/// * `sl_spk` - 37-byte SL exit order P2SH SPK
/// * `sl_min_value` - Minimum value for SL output (sompi)
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
    tp_spk: &[u8; 37],
    tp_min_value: u64,
    sl_spk: &[u8; 37],
    sl_min_value: u64,
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
    let mut rs = Vec::with_capacity(430);
    // State (271 bytes)
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_type));
    rs.push(0x20);
    rs.extend_from_slice(token_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(entry_price_den));
    rs.push(0x25);
    rs.extend_from_slice(tp_spk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(tp_min_value));
    rs.push(0x25);
    rs.extend_from_slice(sl_spk);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(sl_min_value));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_receipt_value));
    rs.push(0x20);
    rs.extend_from_slice(receipt_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(trade_spk_hash);    // NEW: trade_spk_hash (N5)
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    // Body (159 bytes)
    rs.extend_from_slice(BRACKET_ORDER_BODY);
    Ok(rs)
}

/// Build bracket_order fill sigscript: `[Op1][pushData(redeemScript)]`
///
/// sigOpCount = 0 for this input.
/// sigscript length = 434B (< 480 threshold -> fill path).
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
/// sigscript length = 533B (>= 480 threshold -> cancel path).
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

