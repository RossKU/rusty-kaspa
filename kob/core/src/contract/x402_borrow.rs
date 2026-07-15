//! x402 KIP-10 additive borrow covenant (template `kaspa-x402-kip10-additive-v1`).
//!
//! A borrow outpoint the merchant funds to this covenant's P2SH. Spendable by
//! ANYONE who produces a designated continuation output that returns at least
//! `min_continuation` sompi to the merchant's SPK — i.e. the reserved value
//! grows additively. No signature: the additive rule is the only condition.
//! This is the swap covenant's F2 (output amount >=) + F3 (output SPK hash ==)
//! introspection pattern, retargeted to a single merchant continuation output.

use crate::contract::helpers::push_index;
use crate::primitives::{push_data, u64_le};

/// Body bytecode. Redeem script = state (`[0x08]min_continuation[0x20]merchant_spk_hash`)
/// followed by this. Continuation output index is pushed by the sigscript.
///
/// Stack after the state pushes (top->bottom): merchant_hash, min_continuation,
/// continuation_index.
pub const X402_BORROW_BODY: &[u8] = &[
    // output[cont_idx].value >= min_continuation
    0x52, 0x79, // Op2 OpPick -> cont_idx
    0xc2, //       OpTxOutputAmount -> output[cont_idx].value
    0x52, 0x79, // Op2 OpPick -> min_continuation
    0xa2, 0x69, // OpGreaterThanOrEqual OpVerify
    // blake2b(output[cont_idx].spk) == merchant_hash
    0x52, 0x79, // Op2 OpPick -> cont_idx
    0xc3, //       OpTxOutputSpk -> output[cont_idx].spk
    0xaa, //       OpBlake2b
    0x51, 0x79, // Op1 OpPick -> merchant_hash
    0x87, 0x69, // OpEqual OpVerify
    // cleanup: drop merchant_hash, min_continuation, cont_idx
    0x6d, 0x75, // Op2Drop OpDrop
    0x51, //       Op1 (TRUE)
];

/// State size: `[0x08]+8` (min_continuation) + `[0x20]+32` (merchant_spk_hash).
pub const X402_BORROW_STATE_SIZE: usize = 9 + 33;
/// Full redeem script size.
pub const X402_BORROW_RS_SIZE: usize = X402_BORROW_STATE_SIZE + X402_BORROW_BODY.len();

/// Build the additive borrow redeem script.
///
/// `merchant_spk_hash` = blake2b-256 of the merchant continuation
/// scriptPublicKey (`version_u16LE || script`). `min_continuation` =
/// `borrow_amount + additive_threshold` — the minimum the continuation output
/// must return to the merchant.
pub fn build_x402_borrow_redeem_script(merchant_spk_hash: &[u8; 32], min_continuation: u64) -> Vec<u8> {
    let mut rs = Vec::with_capacity(X402_BORROW_RS_SIZE);
    rs.push(0x08);
    rs.extend_from_slice(&u64_le(min_continuation));
    rs.push(0x20);
    rs.extend_from_slice(merchant_spk_hash);
    rs.extend_from_slice(X402_BORROW_BODY);
    rs
}

/// Build the sigscript that spends the borrow outpoint via the additive path:
/// `[push continuation_output_index] [pushData(redeem_script)]`. sigOpCount = 0.
pub fn build_x402_borrow_spend_sigscript(continuation_output_idx: u16, redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(4 + redeem_script.len() + 3);
    push_index(&mut ss, continuation_output_idx);
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Decode `(min_continuation, merchant_spk_hash)` from a borrow redeem script.
pub fn parse_x402_borrow(rs: &[u8]) -> Option<(u64, [u8; 32])> {
    if rs.len() != X402_BORROW_RS_SIZE || rs[0] != 0x08 || rs[9] != 0x20 {
        return None;
    }
    if &rs[X402_BORROW_STATE_SIZE..] != X402_BORROW_BODY {
        return None;
    }
    let mut min_bytes = [0u8; 8];
    min_bytes.copy_from_slice(&rs[1..9]);
    let mut merchant_hash = [0u8; 32];
    merchant_hash.copy_from_slice(&rs[10..42]);
    Some((u64::from_le_bytes(min_bytes), merchant_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let merchant_hash = [0xABu8; 32];
        let rs = build_x402_borrow_redeem_script(&merchant_hash, 100_003_000);
        assert_eq!(rs.len(), X402_BORROW_RS_SIZE);
        let (minc, mh) = parse_x402_borrow(&rs).unwrap();
        assert_eq!(minc, 100_003_000);
        assert_eq!(mh, merchant_hash);
    }

    #[test]
    fn sigscript_shape() {
        let rs = build_x402_borrow_redeem_script(&[0u8; 32], 1);
        let ss = build_x402_borrow_spend_sigscript(1, &rs);
        // push_index(1) = Op1 (0x51); then pushData(rs).
        assert_eq!(ss[0], 0x51);
    }
}
