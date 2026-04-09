use crate::primitives::{push_data, u64_le};

/// order_router body bytecode (48 bytes).
///
/// Routes through multiple order pairs to execute indirect trades (A->B->C).
/// Two entrypoints: execute, cancel (owner sig).
///
/// State (150B):
///   [0x20][owner_hash 32B][0x20][input_cov_id 32B][0x20][output_cov_id 32B]
///   [0x20][intermediate_cov_id 32B][0x08][min_output 8B][0x08][max_hops 8B]
///
/// Stack after state pushes (6 items, top to bottom):
///   max_hops(0), min_output(1), inter_cid(2), output_cid(3), input_cid(4), owner_hash(5)
///
/// Dispatch: Op6 OpRoll brings selector to top.
///   selector=1 -> execute, selector=0 -> cancel
///
/// Execute: verify input token A consumed, output token C delivered, output >= min_output.
///
/// Body = 51B, RS = 150 + 51 = 201 bytes.
pub const ORDER_ROUTER_BODY: &[u8] = &[
    // === Dispatch (5B) ===
    0x56, 0x7a,                   // Op6 OpRoll -> selector
    0x00, 0xa0,                   // Op0 OpGreaterThan -> clean boolean
    0x63,                         // OpIf (execute)

    // === EXECUTE PATH (22B) ===
    // Verify input token A consumed
    0x54, 0x79,                   // Op4 OpPick -> input_cov_id
    0xd0,                         // OpCovInputCount(input_cid) -> count
    0x51, 0xa2, 0x69,             // Op1 OpGTE OpVerify
    // Verify output token C present
    0x53, 0x79,                   // Op3 OpPick -> output_cov_id
    0xd2,                         // OpCovOutCount(output_cid) -> count
    0x51, 0xa2, 0x69,             // Op1 OpGTE OpVerify
    // Verify output[0] amount >= min_output
    0x00, 0xc2,                   // Op0 OpTxOutputAmount
    0x51, 0x79,                   // Op1 OpPick -> min_output
    0xa2, 0x69,                   // OpGTE OpVerify
    // Cleanup
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6

    // === CANCEL PATH (18B) ===
    0x67,                         // OpElse
    0x56, 0x79, 0xaa,             // Op6 OpPick(pk) OpBlake2b
    0x56, 0x79, 0x87, 0x69,       // Op6 OpPick(owner_hash) OpEqual OpVerify
    0x57, 0x7a,                   // Op7 OpRoll -> sig
    0x57, 0x7a,                   // Op7 OpRoll -> pk
    0xac, 0x69,                   // OpCheckSig OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6

    // === CLOSING (2B) ===
    0x68,                         // OpEndIf
    0x51,                         // Op1 (TRUE)
];

/// Build order_router redeemScript (198 bytes).
///
/// State (150B):
///   [0x20][owner_hash 32B][0x20][input_cov_id 32B][0x20][output_cov_id 32B]
///   [0x20][intermediate_cov_id 32B][0x08][min_output 8B][0x08][max_hops 8B]
/// Body (51B): ORDER_ROUTER_BODY
/// # Panics
/// Panics if `min_output` is 0.
pub fn build_order_router_redeem_script(
    owner_hash: &[u8; 32],
    input_cov_id: &[u8; 32],
    output_cov_id: &[u8; 32],
    intermediate_cov_id: &[u8; 32],
    min_output: u64,
    max_hops: u64,
) -> crate::Result<Vec<u8>> {
    if min_output <= 0 {
        return Err(crate::KobError::Contract("min_output must be > 0".into()));
    }
    let state_size = 33 + 33 + 33 + 33 + 9 + 9; // 150B
    let mut rs = Vec::with_capacity(state_size + ORDER_ROUTER_BODY.len());
    rs.push(0x20);
    rs.extend_from_slice(owner_hash);
    rs.push(0x20);
    rs.extend_from_slice(input_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(output_cov_id);
    rs.push(0x20);
    rs.extend_from_slice(intermediate_cov_id);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_output));
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(max_hops));
    rs.extend_from_slice(ORDER_ROUTER_BODY);
    Ok(rs)
}

/// Build order_router execute sigscript: `[Op1][pushData(RS)]`
pub fn build_order_router_execute_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(0x51);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build order_router cancel sigscript:
/// `[pushData(sig 65B)][pushData(pk 32B)][Op0][pushData(RS)]`
pub fn build_order_router_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01);
    let mut ss = Vec::with_capacity(100 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type));
    ss.extend_from_slice(&push_data(pubkey));
    ss.push(0x00);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}
