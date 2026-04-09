use crate::primitives::{push_data, u64_le};

/// Receipt body: consume-only (17 bytes).
///
/// Only the recipient (Blake2b(pk) == recipient_hash) can spend via signature.
///
/// State: [pair_id 32B][pnum 8B][pden 8B][amt 8B][mrv 8B][rhash 32B] = 102B prefix
pub const RECEIPT_BODY: &[u8] = &[
    // Stack on entry: sig(7), pk(6), pair_id(5), pnum(4), pden(3), amt(2), mrv(1), rhash(0)
    // (rhash on top, sig at bottom)

    // 1. Verify Blake2b(pk) == recipient_hash
    0x56, 0x79,                   // Op6 OpPick -> pk copy (depth 6 from top)
    0xaa,                         // OpBlake2b -> hash(pk)
    0x87, 0x69,                   // OpEqual OpVerify (rhash == hash(pk))
    // Stack: sig(6), pk(5), pair_id(4), pnum(3), pden(2), amt(1), mrv(0)

    // 2. Signature check
    0x56, 0x7a,                   // Op6 OpRoll -> sig to top
    0x56, 0x7a,                   // Op6 OpRoll -> pk to top
    0xac, 0x69,                   // OpCheckSig OpVerify

    // Stack: pair_id(4), pnum(3), pden(2), amt(1), mrv(0)
    // 3. Drop all state items
    0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x5

    // 4. TRUE
    0x51,                         // Op1
];

/// Token covenant redeemScript: OpCovInputCount(myCovenantId) >= 1 -> TRUE (7 bytes).
pub const TOKEN_RS: &[u8] = &[0xb9, 0xcf, 0xd0, 0x51, 0xa2, 0x69, 0x51];

/// Build buy_order cancel sigscript:
/// [Op0] [pushData(sig+sighash_type 65B)] [pushData(pubkey 32B)] [pushData(RS)]
pub fn build_buy_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    // sig + sighash type byte (0x01 = SIGHASH_ALL)
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(102 + redeem_script.len() + 3);
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build sell_order cancel sigscript:
/// [pushData(sig+sighash_type 65B)] [pushData(pubkey 32B)] [Op0] [pushData(RS)]
///
/// Note: sell_order places sig/pubkey BEFORE the selector (different from buy_order).
pub fn build_sell_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(102 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00); // Op0 (selector = cancel)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build trade_receipt redeemScript (119 bytes).
///
/// Consume-only receipt — only the recipient (Blake2b(pk) == recipient_hash)
/// can spend via signature.
///
/// State (102B): [0x20][pair_id 32B][0x08][price_num 8B][0x08][price_den 8B]
///               [0x08][exec_amount 8B][0x08][min_receipt_value 8B][0x20][recipient_hash 32B]
/// Body (17B): RECEIPT_BODY
///
/// recipient_hash: Blake2b-256 of the recipient's public key (32 bytes).
/// Typically the matcher's own key, so the matcher can consume the receipt
/// to reclaim the deposited KAS (working capital loop).
pub fn build_receipt_redeem_script(
    pair_id: &[u8; 32],
    price_num: u64,
    price_den: u64,
    exec_amount: u64,
    min_receipt_value: u64,
    recipient_hash: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if price_den <= 0 {
        return Err(crate::KobError::Contract("price_den must be > 0".into()));
    }
    if exec_amount <= 0 {
        return Err(crate::KobError::Contract("exec_amount must be > 0".into()));
    }
    let mut rs = Vec::with_capacity(119);
    // State header (102 bytes)
    rs.push(0x20);
    rs.extend_from_slice(pair_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_num));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(price_den));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(exec_amount));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_receipt_value));
    rs.push(0x20);
    rs.extend_from_slice(recipient_hash);
    // Body (17 bytes)
    rs.extend_from_slice(RECEIPT_BODY);
    Ok(rs)
}

/// Build trade_receipt consume sigscript:
/// [pushData(sig+sighash_type 65B)] [pushData(pubkey 32B)] [pushData(RS)]
///
/// Only the recipient (typically the matcher) can consume the receipt to reclaim KAS.
/// sigOpCount = 1.
pub fn build_receipt_consume_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(66 + 33 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build P2PK signature sigscript: [pushData(sig+type 65B)]
pub fn build_p2pk_sigscript(signature: &[u8; 64]) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);
    let mut ss = Vec::with_capacity(66);
    ss.push(65); // length prefix
    ss.extend_from_slice(&sig_with_type);
    ss
}
