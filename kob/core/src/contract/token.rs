use crate::primitives::push_data;

/// token_mint body bytecode (14 bytes).
///
/// Selector-based dispatch via Op1 OpRoll:
/// - Op1 (mint): self-continuation (output[0] SPK == input SPK) + admin CheckSigVerify
/// - Op0 (burn): admin CheckSigVerify only, no continuation
///
/// State: [0x20][admin_pk 32B] = 33B
/// Total redeemScript: 33 (state) + 14 (body) = 47 bytes
///
/// Sigscript (mint): [41 <sig 64B> 01] [51] [pushData(RS 47B)]   = 116B
/// Sigscript (burn): [41 <sig 64B> 01] [00] [pushData(RS 47B)]   = 116B
pub const TOKEN_MINT_BODY: &[u8] = &[
    0x51, 0x7a,       // Op1 OpRoll (bring selector to top)
    0x63,             // OpIf (truthy = mint)
    0x00, 0xc3,       // Op0 OpTxOutputSpk (output[0] SPK)
    0xb9, 0xbf,       // OpTxInputIndex OpTxInputSpk (this input's SPK)
    0x87, 0x69,       // OpEqual OpVerify (self-continuation check)
    0xad,             // OpCheckSigVerify (admin sig)
    0x67,             // OpElse (burn)
    0xad,             // OpCheckSigVerify (admin sig)
    0x68,             // OpEndIf
    0x51,             // Op1 (TRUE)
];

/// token_unit body bytecode (2 bytes).
///
/// Simple owner signature check. Anyone holding the private key that matches
/// the embedded public key can spend (transfer) the token UTXO.
///
/// State: [0x20][owner_pk 32B] = 33B
/// Total redeemScript: 33 (state) + 2 (body) = 35 bytes
///
/// Sigscript (transfer): [41 <sig 64B> 01] [pushData(RS 35B)]   = 102B
pub const TOKEN_UNIT_BODY: &[u8] = &[
    0xad,             // OpCheckSigVerify (owner sig)
    0x51,             // Op1 (TRUE)
];

/// Build token_mint redeemScript (47 bytes).
///
/// State (33B): [0x20][admin_pk 32B]
/// Body (14B): TOKEN_MINT_BODY
pub fn build_token_mint_redeem_script(admin_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut rs = Vec::with_capacity(47);
    rs.push(0x20);
    rs.extend_from_slice(admin_pubkey);
    rs.extend_from_slice(TOKEN_MINT_BODY);
    rs
}

/// Build token_unit redeemScript (35 bytes).
///
/// State (33B): [0x20][owner_pk 32B]
/// Body (2B): TOKEN_UNIT_BODY
pub fn build_token_unit_redeem_script(owner_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut rs = Vec::with_capacity(35);
    rs.push(0x20);
    rs.extend_from_slice(owner_pubkey);
    rs.extend_from_slice(TOKEN_UNIT_BODY);
    rs
}

/// Build token_mint mint sigscript: [push sig(65B)] [Op1] [pushData(RS)]
///
/// Op1 selector triggers the mint path (self-continuation + admin sig).
/// sigOpCount = 1 for the input.
pub fn build_token_mint_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.push(65); // length prefix for sig
    ss.extend_from_slice(&sig_with_type);
    ss.push(0x51); // Op1 (selector = mint)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build token_mint burn sigscript: [push sig(65B)] [Op0] [pushData(RS)]
///
/// Op0 selector triggers the burn path (admin sig only, no continuation).
pub fn build_token_burn_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + 1 + redeem_script.len() + 3);
    ss.push(65); // length prefix for sig
    ss.extend_from_slice(&sig_with_type);
    ss.push(0x00); // Op0 (selector = burn)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build token_unit transfer sigscript: [push sig(65B)] [pushData(RS)]
///
/// Simple owner signature. No selector needed.
pub fn build_token_unit_sigscript(signature: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(66 + redeem_script.len() + 3);
    ss.push(65); // length prefix for sig
    ss.extend_from_slice(&sig_with_type);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
