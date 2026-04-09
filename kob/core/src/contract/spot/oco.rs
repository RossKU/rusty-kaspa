use crate::primitives::{push_data, u64_le};
use crate::contract::helpers::opn;

/// oco_pair body bytecode (147 bytes).
///
/// **OCO2-F3 fix**: cancel_by_partner (CBP) path now has two critical guards:
/// 1. Value floor: output[my_idx].value >= input_value - 10000 sompi (fee allowance)
///    Prevents attacker from redirecting funds to dust while stealing the rest.
/// 2. Input count = 2: exactly 2 inputs required for CBP (self + partner)
///    Prevents multi-input attack variants.
///
/// State layout (181B). No partner_spk_hash field.
/// This avoids the circular dependency that partner_spk_hash would create
/// (each leg's RS would need the other's P2SH hash, but RS determines the hash).
///
/// OpPick/OpRoll depths use a 10-item state stack.
///
/// Dispatch: sigLen < 350 -> non-cancel (fill or CBP), >= 350 -> cancel.
/// RS = 181 + 147 = 328 bytes.
///
/// Sigscript lengths (RS=328):
///   Fill:   Op1(1) + OpN(1) + PUSHDATA2(3) + RS(328) = 333B  (< 350)
///   CBP:    Op2(1) + OpN(1) + PUSHDATA2(3) + RS(328) = 333B  (< 350)
///   Cancel: Op0(1) + push(sig65)(66) + push(pk32)(33) + PUSHDATA2(3) + RS(328) = 431B (>= 350)
pub const OCO_PAIR_BODY: &[u8] = &[
    // --- Level 1 dispatch: sigLen < 350 (7B) ---
    0xb9, 0xc9,                   // OpTxInputIndex, OpTxInputScriptSigLen
    0x02, 0x5e, 0x01,             // push 350 (0x015e LE)
    0x9f, 0x63,                   // OpLessThan, OpIf
    // --- Partner nonce verification (10B) ---
    0x59, 0x79,                   // Op9 OpPick -> pidx
    0x56,                         // Op6 (start=6)
    0x01, 0x26,                   // push 38 (end=6+32)
    0xbc,                         // OpTxInputScriptSigSubstr -> partner_nonce [6..38)
    0x59, 0x79,                   // Op9 OpPick -> our nonce
    0x87, 0x69,                   // OpEqual OpVerify
    // --- Level 2 dispatch (5B) ---
    0x5a, 0x7a,                   // Op10 OpRoll -> selector
    0x51, 0x87, 0x63,             // Op1 OpEqual OpIf (fill)
    // --- Fill: role dispatch (5B) ---
    0x57, 0x79,                   // Op7 OpPick -> role (8-byte LE integer)
    0x51, 0x9c, 0x63,             // Op1 OpNumEqual OpIf (sell if role==1)
    // --- SELL fill (29B): multiply-first ---
    0x55, 0x79,                   // Op5 OpPick -> tamt
    0x55, 0x79,                   // Op5 OpPick -> pnum
    0x95,                         // OpMul
    0x54, 0x79,                   // Op4 OpPick -> pden
    0x96,                         // OpDiv -> expected_kas
    0x76,                         // OpDup
    0x54, 0x79, 0xa2, 0x69,       // Op4 OpPick(mfill) OpGTE OpVerify
    0x00, 0xc2, 0x7c, 0xa2, 0x69, // Op0 TxOutputAmount OpSwap OpGTE OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x10
    0x51,                         // Op1
    // --- BUY fill (31B): MULTIPLY-FIRST ---
    0x67,                         // OpElse (buy)
    0xb9, 0xbe,                   // OpTxInputIndex, OpTxInputAmount -> kas
    0x55, 0x79, 0x95,             // Op5 OpPick(pnum) OpMul
    0x54, 0x79, 0x96,             // Op4 OpPick(pden) OpDiv
    0x76,                         // OpDup
    0x54, 0x79, 0xa2, 0x69,       // Op4 OpPick(mfill) OpGTE OpVerify
    0x51, 0xc2, 0x7c, 0xa2, 0x69, // Op1 TxOutputAmount OpSwap OpGTE OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x10
    0x51, 0x68,                   // Op1 OpEndIf(role)
    // --- cancel_by_partner (34B, OCO2-F3 fix: value floor + input count) ---
    0x67,                         // OpElse (cbp)
    // F9 refund SPK check
    0xb9, 0xc3,                   // OpTxInputIndex, OpTxOutputSpk
    0x51, 0x79,                   // Op1 OpPick -> ospk
    0x87, 0x69,                   // OpEqual OpVerify
    // OCO2-F3a: Value floor — output[my_idx] >= input_value - 10000 sompi (12B)
    0xb9, 0xbe,                   // OpTxInputIndex, OpTxInputAmount -> V
    0x02, 0x10, 0x27,             // push 10000 (0x2710 LE, fee allowance)
    0x94,                         // OpSub -> V - 10000
    0xb9, 0xc2,                   // OpTxInputIndex, OpTxOutputAmount -> output[my_idx].value
    0x7c,                         // OpSwap
    0xa2, 0x69,                   // OpGTE OpVerify (output >= V - 10000)
    // OCO2-F3b: Input count = 2 (4B)
    0xb3,                         // OpTxInputCount
    0x52,                         // Op2
    0x87, 0x69,                   // OpEqual OpVerify
    // Cleanup
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x10
    0x51, 0x68,                   // Op1 OpEndIf(fill/cbp)
    // --- Cancel path (26B) ---
    0x67,                         // OpElse (cancel)
    0x59, 0x79,                   // Op9 OpPick -> pk
    0x76, 0xaa,                   // OpDup OpBlake2b
    0x53, 0x79, 0x87, 0x69,       // Op3 OpPick(ohash) OpEqual OpVerify
    0x5b, 0x7a,                   // Op11 OpRoll -> sig
    0x7c, 0xad,                   // OpSwap OpCheckSigVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x11
    0x51, 0x68,                   // Op1 OpEndIf(level1)
];

/// Build oco_pair redeemScript (OCO2-F3: CBP value floor + input count).
///
/// State layout (181B):
///   [0x20][nonce 32B][0x08][role 8B][0x20][tcid 32B][0x08][tamt 8B]
///   [0x08][pnum 8B][0x08][pden 8B][0x08][mfill 8B][0x20][ohash 32B]
///   [0x24][ospk 36B]
/// Body (147B): OCO_PAIR_BODY
/// Total: 328 bytes
///
/// # Arguments
/// * `nonce` - 32-byte random nonce linking the OCO pair
/// * `role` - 0 = buy, 1 = sell
/// * `token_cov_id` - 32-byte token covenant ID
/// * `token_amount` - Token amount for sell side (0 for buy)
/// * `price_num` - Price numerator
/// * `price_den` - Price denominator
/// * `min_fill` - Minimum fill amount
/// * `owner_hash` - Blake2b hash of owner pubkey
/// * `owner_spk` - Owner's scriptPublicKey (36 bytes: version 2B + script 34B)
///
/// # Panics
/// Panics if `price_num`, `price_den`, or `min_fill` is 0, or `role` > 1.
pub fn build_oco_pair_redeem_script(
    nonce: &[u8; 32],
    role: u64,
    token_cov_id: &[u8; 32],
    token_amount: u64,
    price_num: u64,
    price_den: u64,
    min_fill: u64,
    owner_hash: &[u8; 32],
    owner_spk: &[u8; 36],
) -> crate::Result<Vec<u8>> {
    if price_num <= 0 {
        return Err(crate::KobError::Contract("price_num must be > 0".into()));
    }
    if price_den <= 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if min_fill <= 0 {
        return Err(crate::KobError::Contract("min_fill must be > 0 (zero allows dust griefing, A6)".into()));
    }
    if role > 1 {
        return Err(crate::KobError::Contract("role must be 0 (buy) or 1 (sell)".into()));
    }
    let mut rs = Vec::with_capacity(328);
    // State header (181 bytes)
    rs.push(0x20);
    rs.extend_from_slice(nonce);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(role));
    rs.push(0x20);
    rs.extend_from_slice(token_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(token_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_fill));
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x24);
    rs.extend_from_slice(owner_spk);
    // Body (147 bytes)
    rs.extend_from_slice(OCO_PAIR_BODY);
    Ok(rs)
}

/// Build oco_pair fill sigscript:
/// `[Op1 sel] [OpN partner_idx] [pushData(RS)]`
///
/// sigOpCount = 0 for this input.
pub fn build_oco_pair_fill_sigscript(
    partner_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(0x51); // Op1 (selector = fill)
    ss.push(opn(partner_idx));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build oco_pair cancel_by_partner sigscript:
/// `[Op2 sel] [OpN partner_idx] [pushData(RS)]`
///
/// sigOpCount = 0 for this input.
pub fn build_oco_pair_cbp_sigscript(
    partner_idx: u8,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + redeem_script.len() + 3);
    ss.push(0x52); // Op2 (selector = cancel_by_partner)
    ss.push(opn(partner_idx));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build oco_pair cancel sigscript:
/// `[Op0] [pushData(sig+type 65B)] [pushData(pubkey 32B)] [pushData(RS)]`
///
/// sigOpCount = 1 for this input.
pub fn build_oco_pair_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(101 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
