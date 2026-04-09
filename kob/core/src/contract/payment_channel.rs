use crate::primitives::push_data;
use super::helpers::opn;

/// payment_channel body bytecode (36 bytes).
///
/// F13 fix: top-up now requires party_a or party_b signature.
///
/// Dispatch: Op2 OpRoll brings selector to top (2 state items).
/// - selector truthy (Op1) -> close (2-of-2 both sigs, sigOpCount=2)
/// - selector falsy  (Op0) -> authorized top-up (1 sig, sigOpCount=1)
///
/// State: [0x20][party_a_pk 32B][0x20][party_b_pk 32B] = 66B
pub const PAYMENT_CHANNEL_BODY: &[u8] = &[
    // --- DISPATCH (3B) ---
    0x52, 0x7a,       // Op2 OpRoll -> selector to top
    0x63,             // OpIf (truthy = close)
    // --- CLOSE PATH (10B) ---
    // Stack: [sig_b, sig_a, party_a_pk, party_b_pk]
    0x52, 0x7a,       // Op2 OpRoll -> sig_a to top
    0x52, 0x79,       // Op2 OpPick -> copy party_a_pk
    0xad,             // OpCheckSigVerify (sig_a, party_a_pk)
    0x52, 0x7a,       // Op2 OpRoll -> sig_b to top
    0x7c,             // OpSwap
    0xad,             // OpCheckSigVerify (sig_b, party_b_pk)
    0x75,             // OpDrop -> clean party_a_pk
    // --- TOP-UP PATH (20B) ---
    0x67,             // OpElse
    // Stack: [sig, party_idx, party_a_pk, party_b_pk]
    // top: party_b_pk(0), party_a_pk(1), party_idx(2), sig(3)
    //
    // Self-continuation (6B)
    0x00, 0xc3,       // Op0 OpTxOutputSpk
    0xb9, 0xbf,       // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,       // OpEqual OpVerify
    // Value guard: output > input strict (6B)
    0x00, 0xc2,       // Op0 OpTxOutputAmount
    0xb9, 0xbe,       // OpTxInputIndex OpTxInputAmount
    0xa0, 0x69,       // OpGreaterThan OpVerify (strict: funds must increase)
    // Auth: party_idx selects key (8B)
    0x52, 0x7a,       // Op2 OpRoll -> party_idx to top
    0x63,             // OpIf (party_idx=1 -> party_b)
    0x77,             // OpNip -> remove party_a_pk
    0x67,             // OpElse (party_idx=0 -> party_a)
    0x75,             // OpDrop -> drop party_b_pk
    0x68,             // OpEndIf (inner)
    0xad,             // OpCheckSigVerify -> verify sig against selected key
    // --- END (2B) ---
    0x68,             // OpEndIf (outer)
    0x51,             // Op1 (TRUE)
];

/// Build payment_channel redeemScript.
///
/// State (66B): [0x20][party_a_pk 32B][0x20][party_b_pk 32B]
/// Body (36B): PAYMENT_CHANNEL_BODY
/// Total: 102 bytes
pub fn build_payment_channel_redeem_script(
    party_a_pk: &[u8; 32],
    party_b_pk: &[u8; 32],
) -> Vec<u8> {
    let mut rs = Vec::with_capacity(102);
    // State header (66 bytes)
    rs.push(0x20);
    rs.extend_from_slice(party_a_pk);
    rs.push(0x20);
    rs.extend_from_slice(party_b_pk);
    // Body (36 bytes)
    rs.extend_from_slice(PAYMENT_CHANNEL_BODY);
    rs
}

/// Build payment_channel close sigscript:
/// [pushData(sig_b+type 65B)] [pushData(sig_a+type 65B)] [Op1] [pushData(RS)]
///
/// sigOpCount = 2 for this input.
pub fn build_payment_channel_close_sigscript(
    sig_a: &[u8; 64],
    sig_b: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_a_typed = Vec::with_capacity(65);
    sig_a_typed.extend_from_slice(sig_a);
    sig_a_typed.push(0x01);

    let mut sig_b_typed = Vec::with_capacity(65);
    sig_b_typed.extend_from_slice(sig_b);
    sig_b_typed.push(0x01);

    let mut ss = Vec::with_capacity(133 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_b_typed)); // sig_b pushed first (deeper on stack)
    ss.extend_from_slice(&push_data(&sig_a_typed)); // sig_a on top
    ss.push(0x51); // Op1 (selector = close)
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build payment_channel authorized top-up sigscript:
/// [pushData(sig+type 65B)] [OpN party_idx] [Op0] [pushData(RS)]
///
/// party_idx: 0 = party_a, 1 = party_b.
/// sigOpCount = 1 for this input.
pub fn build_payment_channel_topup_sigscript(
    signature: &[u8; 64],
    party_idx: u8,
    redeem_script: &[u8],
) -> crate::Result<Vec<u8>> {
    if party_idx > 1 {
        return Err(crate::KobError::Contract("party_idx must be 0 (party_a) or 1 (party_b)".into()));
    }
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);

    let mut ss = Vec::with_capacity(68 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.push(opn(party_idx)); // Op0 for party_a, Op1 for party_b
    ss.push(0x00); // Op0 (selector = top-up)
    ss.extend_from_slice(&push_data(redeem_script));
    Ok(ss)
}
