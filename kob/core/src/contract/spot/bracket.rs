use crate::primitives::{push_data, u64_le};

/// bracket_order body bytecode (142 bytes).
///
/// **N4 fix**: Adds `OpInputCovenantId(2) == receipt_cov_id` check.
/// Verifies `input[2].covenant_id` matches `receipt_cov_id` to ensure
/// input[2] is actually a trade_receipt contract, not an arbitrary UTXO
/// to match a known `receipt_cov_id` stored in state.
///
/// State layout (238B):
///   [0x08][entry_type 8B][0x20][token_cov_id 32B][0x08][epnum 8B]
///   [0x08][epden 8B][0x25][tp_spk 37B][0x08][tp_min_val 8B]
///   [0x25][sl_spk 37B][0x08][sl_min_val 8B][0x08][min_fill 8B]
///   [0x08][min_receipt_val 8B][0x20][receipt_cov_id 32B]  <- NEW
///   [0x20][owner_hash 32B]
///
/// Fill stack (13 items, bottom->top):
///   selector, etype, tcid, epnum, epden, tp_spk, tp_mv, sl_spk,
///   sl_mv, mfill, mrv, rcid, owner_hash
///
/// Dispatch threshold: 420 (fill sigscript=384B, cancel=483B).
/// Body = 142B. RS = 238 + 142 = 380 bytes.
///
/// OpPick depths (rcid field shifts +1 from base):
///   TP SPK: Op7->Op8, TP val: Op6->Op7, SL SPK: Op5->Op6, SL val: Op4->Op5
///   Receipt val: Op2->Op3, Entry type: Op10->Op11
///   SELL/BUY epnum: Op9->Op10, epden: Op8->Op9, mfill: Op4->Op5
///   CANCEL pk: Op11->Op12, sig: Op13->Op14 (roll)
///   Drops: SELL/BUY 12->13, CANCEL 13->14
pub const BRACKET_ORDER_BODY: &[u8] = &[
    // === Dispatch (7B): sigLen < 420 -> fill, >= 420 -> cancel ===
    0xb9, 0xc9,                         // OpTxInputIndex, OpTxInputScriptSigLen -> sigLen
    0x02, 0xa4, 0x01,                   // push 420 (0x01A4 LE)
    0x9f, 0x63,                         // OpLessThan, OpIf (fill path)

    // === TP output SPK check (6B) ===
    // Stack(14): push out2.spk, Op8 picks tp_spk (depth 8), Equal+Verify
    0x52, 0xc3,                         // Op2 OpTxOutputSpk -> output[2].spk
    0x58, 0x79,                         // Op8 OpPick -> tp_spk
    0x87, 0x69,                         // OpEqual OpVerify

    // === TP output value check (6B) ===
    // Stack(14): push out2.amt, Op7 picks tp_mv (depth 7), GTE+Verify
    0x52, 0xc2,                         // Op2 OpTxOutputAmount -> output[2].value
    0x57, 0x79,                         // Op7 OpPick -> tp_min_value
    0xa2, 0x69,                         // OpGTE OpVerify

    // === SL output SPK check (6B) ===
    // Stack(14): push out3.spk, Op6 picks sl_spk (depth 6), Equal+Verify
    0x53, 0xc3,                         // Op3 OpTxOutputSpk -> output[3].spk
    0x56, 0x79,                         // Op6 OpPick -> sl_spk
    0x87, 0x69,                         // OpEqual OpVerify

    // === SL output value check (6B) ===
    // Stack(14): push out3.amt, Op5 picks sl_mv (depth 5), GTE+Verify
    0x53, 0xc2,                         // Op3 OpTxOutputAmount -> output[3].value
    0x55, 0x79,                         // Op5 OpPick -> sl_min_value
    0xa2, 0x69,                         // OpGTE OpVerify

    // === Receipt value check (6B) ===
    // Stack(14): push in2.amt, Op3 picks mrv (depth 3), GTE+Verify
    0x52, 0xbe,                         // Op2 OpTxInputAmount -> input[2].amount
    0x53, 0x79,                         // Op3 OpPick -> min_receipt_value
    0xa2, 0x69,                         // OpGTE OpVerify (amount >= min_receipt_value)

    // === Receipt covenant id check (6B, NEW) ===
    // Stack(14): push in2.cov_id, Op2 picks rcid (depth 2), Equal+Verify
    // This is the N4 fix: ensures input[2] IS a genuine trade_receipt contract.
    0x52, 0xcf,                         // Op2 OpInputCovenantId -> input[2].covenant_id
    0x52, 0x79,                         // Op2 OpPick -> receipt_cov_id (depth 2)
    0x87, 0x69,                         // OpEqual OpVerify (cov_id must match expected)

    // === Entry type dispatch (4B) ===
    // Stack(13): Op11 picks etype (depth 11), OpBin2Num, OpIf
    0x5b, 0x79,                         // Op11 OpPick -> entry_type
    0xce, 0x63,                         // OpBin2Num, OpIf (truthy = sell entry)

    // === SELL ENTRY (32B) ===
    // Stack starts at 13. Push my_val -> 14. All picks relative to current stack.
    0xb9, 0xbe,                         // OpTxInputIndex OpTxInputAmount -> my_val
    // Stack(14): 0=my_val, ..., 10=epnum, 9=epden (depths after my_val push)
    0x5a, 0x79,                         // Op10 OpPick -> epnum
    0x95,                               // OpMul -> my_val * epnum
    // Stack(14): 0=my_val*epnum, ..., 9=epden
    0x59, 0x79,                         // Op9 OpPick -> epden
    0x96,                               // OpDiv -> ek = my_val * epnum / epden
    // Stack(14): 0=ek, 1=owner_hash, 2=rcid, 3=mrv, 4=mfill, ...
    0x76,                               // OpDup -> [15 items: ek, ek, ...]
    // Stack(15): 0=ek, 1=ek, 2=owner_hash, 3=rcid, 4=mrv, 5=mfill
    0x55, 0x79,                         // Op5 OpPick -> mfill
    0xa2, 0x69,                         // OpGTE OpVerify (ek >= mfill)
    // Stack(14): 0=ek, 1=owner_hash, 2=rcid, 3=mrv, 4=mfill, ...
    0x00, 0xc2,                         // Op0 OpTxOutputAmount -> output[0].value
    // Stack(15): 0=out0.val, 1=ek, ...
    0x7c,                               // OpSwap
    0xa2, 0x69,                         // OpGTE OpVerify (output[0] >= ek)
    // Stack(13) remaining: selector, etype, tcid, epnum, epden, tp_spk, tp_mv, sl_spk, sl_mv, mfill, mrv, rcid, owner_hash
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,        // OpDrop x6 (total 13 drops)
    0x51,                               // Op1 TRUE

    // === BUY ENTRY (33B) ===
    0x67,                               // OpElse (buy path)
    // Stack starts at 13. Push kas -> 14.
    0xb9, 0xbe,                         // OpTxInputIndex OpTxInputAmount -> kas
    // Stack(14): 0=kas, ..., 9=epden
    0x59, 0x79,                         // Op9 OpPick -> epden
    0x96,                               // OpDiv -> kas / epden
    // Stack(14): 0=kas/epden, ..., 10=epnum
    0x5a, 0x79,                         // Op10 OpPick -> epnum
    0x95,                               // OpMul -> et = kas / epden * epnum
    // Stack(14): 0=et, 1=owner_hash, 2=rcid, 3=mrv, 4=mfill, ...
    0x76,                               // OpDup -> [15 items: et, et, ...]
    // Stack(15): 0=et, 1=et, 2=owner_hash, 3=rcid, 4=mrv, 5=mfill
    0x55, 0x79,                         // Op5 OpPick -> mfill
    0xa2, 0x69,                         // OpGTE OpVerify (et >= mfill)
    // Stack(14): 0=et, 1=owner_hash, 2=rcid, 3=mrv, 4=mfill, ...
    0x51, 0xc2,                         // Op1 OpTxOutputAmount -> output[1].value
    // Stack(15): 0=out1.val, 1=et, ...
    0x7c,                               // OpSwap
    0xa2, 0x69,                         // OpGTE OpVerify (output[1] >= et)
    // Stack(13) remaining: same 13 items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,        // OpDrop x6 (total 13 drops)
    0x51,                               // Op1 TRUE
    0x68,                               // OpEndIf (entry type)

    // === CANCEL (29B) ===
    0x67,                               // OpElse (cancel path, sigLen >= 420)
    // Cancel stack (15 items): Op0, sig, pk, etype, tcid, epnum, epden,
    //   tp_spk, tp_mv, sl_spk, sl_mv, mfill, mrv, rcid, owner_hash
    // Depths: 0=owner_hash, 1=rcid, 2=mrv, 3=mfill, ..., 12=pk, 13=sig, 14=Op0
    0x5c, 0x79,                         // Op12 OpPick -> pk (depth 12)
    0x76,                               // OpDup
    0xaa,                               // OpBlake2b -> [17 items: ..., pk_copy, hash(pk)]
    // Op2 OpPick: after blake2b, stack(17): 0=hash, 1=pk_copy, 2=owner_hash
    0x52, 0x79,                         // Op2 OpPick -> owner_hash  [unchanged]
    0x87, 0x69,                         // OpEqual OpVerify (blake2b(pk) == owner_hash)
    // Stack(16): ..., pk_copy on top
    // Depths now: 0=pk_copy, 1=owner_hash, 2=rcid, ..., 13=pk, 14=sig, 15=Op0... wait
    // After equal+verify from 18-item stack: 16 items remain
    // depth: 0=pk_copy, 1=owner_hash, 2=rcid, 3=mrv, ..., 12=etype, 13=pk, 14=sig, 15=Op0
    0x5e, 0x7a,                         // Op14 OpRoll -> sig (depth 14)
    0x7c,                               // OpSwap -> [sig, pk_copy]
    0xad,                               // OpCheckSigVerify (consumes sig and pk_copy)
    // Stack(14) remaining: Op0, pk, etype, tcid, epnum, epden, tp_spk, tp_mv,
    //                       sl_spk, sl_mv, mfill, mrv, rcid, owner_hash
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x7 (total 14 drops)
    0x51,                               // Op1 TRUE
    0x68,                               // OpEndIf (dispatch)
];

/// Build bracket_order redeemScript.
///
/// Adds `receipt_cov_id` to state and verifies `input[2].covenant_id`
/// matches, preventing any arbitrary UTXO from serving as a fake receipt input.
///
/// State (238B):
///   [0x08][entry_type 8B][0x20][token_cov_id 32B][0x08][epnum 8B]
///   [0x08][epden 8B][0x25][tp_spk 37B][0x08][tp_min_val 8B]
///   [0x25][sl_spk 37B][0x08][sl_min_val 8B][0x08][min_fill 8B]
///   [0x08][min_receipt_val 8B][0x20][receipt_cov_id 32B][0x20][owner_hash 32B]
/// Body (142B): BRACKET_ORDER_BODY
/// Total: 380 bytes
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
    let mut rs = Vec::with_capacity(380);
    // State (238 bytes)
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
    rs.extend_from_slice(receipt_cov_id);    // NEW: receipt_cov_id
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    // Body (142 bytes)
    rs.extend_from_slice(BRACKET_ORDER_BODY);
    Ok(rs)
}

/// Build bracket_order fill sigscript: `[Op1][pushData(redeemScript)]`
///
/// sigOpCount = 0 for this input.
/// sigscript length = 384B (< 420 threshold -> fill path).
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
/// sigscript length = 483B (>= 420 threshold -> cancel path).
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

