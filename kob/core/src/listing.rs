//! Listing covenant for KOB (Kaspa Order Book).
//!
//! Enables marketplace/auction/collateral functionality for ANY UTXO type by
//! working with PATH 11 (ownership transfer) on position covenants like perp.
//!
//! # How it works
//! 1. **List**: Owner signs PATH 11 Mode A on their position, setting
//!    `owner_spk_hash = Blake2b(listing_SPK)`. This delegates control to the
//!    listing covenant.
//! 2. **Fill/Buy**: Listing covenant verifies payment to seller and authorizes
//!    PATH 11 Mode B on the position to transfer ownership to buyer.
//! 3. **Cancel**: Seller reclaims by signing, listing authorizes PATH 11 Mode B
//!    to return ownership.
//!
//! # 6-Path Dispatch
//!
//! | Path | Selector | Function |
//! |------|----------|----------|
//! | 1 | Op1 | Fixed-price fill |
//! | 2 | Op2 | Cancel (seller sig) |
//! | 3 | Op3 | Dutch auction buy |
//! | 4 | Op4 | Dutch tick (D&R price decrement) |
//! | 5 | Op5 | English bid (D&R new highest bid) |
//! | 6 | Op6 | Settle english auction / collateral claim |
//!
//! # State layout (104 bytes)
//! ```text
//! [0x20][seller_spk_hash 32B]  — seller's SPK hash (payment verification)
//! [0x22][seller_spk 34B]       — seller's full SPK (output verification)
//! [0x08][asking_price 8B]      — price in sompi
//! [0x08][listing_type 8B]      — 0=fixed, 1=dutch, 2=english
//! [0x08][expiry_daa 8B]        — expiration DAA score
//! [0x08][param 8B]             — type-specific (dutch: tick_decrement, english: min_bid_increment)
//! ```
//!
//! After state pushes, stack (bottom to top):
//!   param(0), expiry(1), ltype(2), price(3), seller_spk(4), seller_spk_hash(5)

use crate::primitives::{push_data, u64_le};

/// KOB listing payload prefix (6 bytes, ASCII).
pub const KOB_LISTING_PAYLOAD_PREFIX: &[u8] = b"KOB:L:";

/// Build listing payload: `KOB:L:` + redeemScript bytes.
pub fn build_listing_payload(rs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KOB_LISTING_PAYLOAD_PREFIX.len() + rs.len());
    payload.extend_from_slice(KOB_LISTING_PAYLOAD_PREFIX);
    payload.extend_from_slice(rs);
    payload
}

/// Parse listing payload, returning the redeemScript portion if prefix matches.
pub fn parse_listing_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.starts_with(KOB_LISTING_PAYLOAD_PREFIX) {
        Some(&payload[KOB_LISTING_PAYLOAD_PREFIX.len()..])
    } else {
        None
    }
}

/// Listing covenant state size: 104 bytes.
///
/// Breakdown:
///   1 + 32 = 33 (seller_spk_hash)
///   1 + 34 = 35 (seller_spk)
///   1 + 8  = 9  (asking_price)
///   1 + 8  = 9  (listing_type)
///   1 + 8  = 9  (expiry_daa)
///   1 + 8  = 9  (param)
///   Total  = 104
pub const LISTING_STATE_SIZE: usize = 104;

/// Convert an integer (0..=16) to the corresponding OpN opcode.
fn opn(n: u8) -> u8 {
    match n {
        0 => 0x00,
        1..=16 => 0x50 + n,
        _ => panic!("OpN index out of range: {} (must be 0..=16)", n),
    }
}

/// Listing covenant body bytecode.
///
/// 6-path dispatch using Op6 OpRoll for the selector byte.
///
/// Stack after state: param(0), expiry(1), ltype(2), price(3), seller_spk(4), seller_spk_hash(5)
///
/// Sigscript layout: `[OpN selector] [pushdata(RS)]`
/// Cancel adds sig + pubkey before RS.
///
/// Dispatch: selector is rolled to top via `Op6 OpRoll`, then compared.
///
/// The bytecode uses nested OpIf/OpElse/OpEndIf for path selection:
///   selector == 1? PATH 1 (fixed fill)
///   selector == 2? PATH 2 (cancel)
///   selector == 3? PATH 3 (dutch buy, same as fixed fill — price already decremented)
///   selector == 4? PATH 4 (dutch tick D&R)
///   selector == 5? PATH 5 (english bid D&R)
///   else:          PATH 6 (settle/collateral)
pub const LISTING_BODY: &[u8] = &[
    // --- Roll selector to top (3B) ---
    // Stack before: param(0), expiry(1), ltype(2), price(3), seller_spk(4), seller_spk_hash(5), selector(6)
    // Op6 OpRoll brings selector(6) to top
    0x56, 0x7a,                   // Op6 OpRoll -> selector on top
    // Stack: selector(0), param(1), expiry(2), ltype(3), price(4), seller_spk(5), seller_spk_hash(6)

    // --- PATH 1 check: selector == Op1? (5B) ---
    0x76,                         // OpDup
    0x51, 0x9c,                   // Op1 OpNumEqual
    0x63,                         // OpIf
    0x75,                         // OpDrop (selector)
    // Stack: param(0), expiry(1), ltype(2), price(3), seller_spk(4), seller_spk_hash(5)

    // PATH 1: Fixed-price fill (21B)
    // Verify expiry not passed: OpTxLockTime < expiry_daa
    // (if expiry == 0, skip — means no expiry)
    0x51, 0x79,                   // Op1 OpPick -> expiry
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual
    0x64,                         // OpNotIf (has expiry)
    0xba, 0xa0, 0x69,             // OpTxLockTime OpGreaterThan OpVerify (expiry > lockTime)
    0x67,                         // OpElse
    0x75,                         // OpDrop (the 0)
    0x68,                         // OpEndIf
    // Verify output[1].value >= asking_price
    0x51, 0xc2,                   // Op1 OpTxOutputAmount -> output[1].value
    0x53, 0x79,                   // Op3 OpPick -> price
    0xa2, 0x69,                   // OpGTE OpVerify
    // Verify output[1].spk hash == seller_spk_hash
    0x51, 0xc3, 0xaa,             // Op1 OpTxOutputSpk OpBlake2b
    0x55, 0x79,                   // Op5 OpPick -> seller_spk_hash
    0x87, 0x69,                   // OpEqual OpVerify
    // Cleanup: drop 6 items
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6
    0x51,                         // Op1 (TRUE)

    // --- PATH 2 check: selector == Op2? (5B) ---
    0x67,                         // OpElse
    0x76,                         // OpDup
    0x52, 0x9c,                   // Op2 OpNumEqual
    0x63,                         // OpIf
    0x75,                         // OpDrop (selector)
    // Cancel sigscript: [push sig] [push pk] [Op2 sel] [pushdata(RS)]
    // After P2SH + state pushes: sig(8), pk(7), param(0)..seller_spk_hash(5)
    // Op6 OpRoll already consumed selector. pk at depth 6, sig at depth 7.

    // PATH 2: Cancel (14B)
    // Stack: param(0), expiry(1), ltype(2), price(3), seller_spk(4), seller_spk_hash(5), pk(6), sig(7)
    // Verify Blake2b(pubkey) == seller_spk_hash
    0x56, 0x79,                   // Op6 OpPick -> pk (at depth 6)
    0xaa,                         // OpBlake2b
    0x56, 0x79,                   // Op6 OpPick -> seller_spk_hash (now at depth 6 because pk_hash pushed)
    // Wait, after OpPick pk and OpBlake2b, stack has:
    // blake2b(pk)(0), param(1), expiry(2), ltype(3), price(4), seller_spk(5), seller_spk_hash(6), pk(7), sig(8)
    // seller_spk_hash is at depth 6. Op6 OpPick gets it.
    0x87, 0x69,                   // OpEqual OpVerify
    // Stack back to: param(0), expiry(1), ltype(2), price(3), seller_spk(4), seller_spk_hash(5), pk(6), sig(7)
    // CheckSig: need sig and pk on top in right order
    // OpRoll sig to top: sig is at depth 7
    0x57, 0x7a,                   // Op7 OpRoll -> sig to top
    // Stack: sig(0), param(1), expiry(2), ltype(3), price(4), seller_spk(5), seller_spk_hash(6), pk(7)
    // OpRoll pk to top: pk is at depth 7
    0x57, 0x7a,                   // Op7 OpRoll -> pk to top
    // Stack: pk(0), sig(1), ...
    0xad,                         // OpCheckSigVerify
    // Cleanup: 6 state items remain
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75, // OpDrop x6
    0x51,                         // Op1 (TRUE)

    // --- PATH 3 check: selector == Op3? (5B) ---
    0x67,                         // OpElse
    0x76,                         // OpDup
    0x53, 0x9c,                   // Op3 OpNumEqual
    0x63,                         // OpIf
    0x75,                         // OpDrop (selector)

    // PATH 3: Dutch buy (same as fixed fill) (21B)
    // Price is already in state (decremented by tick D&Rs), so identical to PATH 1.
    0x51, 0x79,                   // Op1 OpPick -> expiry
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual
    0x64,                         // OpNotIf
    0xba, 0xa0, 0x69,             // OpTxLockTime OpGreaterThan OpVerify
    0x67,                         // OpElse
    0x75,                         // OpDrop
    0x68,                         // OpEndIf
    0x51, 0xc2,                   // Op1 OpTxOutputAmount
    0x53, 0x79,                   // Op3 OpPick -> price
    0xa2, 0x69,                   // OpGTE OpVerify
    0x51, 0xc3, 0xaa,             // Op1 OpTxOutputSpk OpBlake2b
    0x55, 0x79,                   // Op5 OpPick -> seller_spk_hash
    0x87, 0x69,                   // OpEqual OpVerify
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
    0x51,

    // --- PATH 4 check: selector == Op4? (5B) ---
    0x67,                         // OpElse
    0x76,                         // OpDup
    0x54, 0x9c,                   // Op4 OpNumEqual
    0x63,                         // OpIf
    0x75,                         // OpDrop (selector)

    // PATH 4: Dutch tick D&R (22B)
    // Self-continuation: output[0].spk == input[0].spk
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify
    // Value conservation: output[0].value == input[0].value
    0x00, 0xc2,                   // Op0 OpTxOutputAmount
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount
    0x87, 0x69,                   // OpEqual OpVerify
    // Verify asking_price > param (don't go to zero or negative)
    // Stack: param(0), expiry(1), ltype(2), price(3), seller_spk(4), seller_spk_hash(5)
    0x53, 0x79,                   // Op3 OpPick -> price (now on top)
    0x51, 0x79,                   // Op1 OpPick -> param (depth 1 after price push)
    0xa0, 0x69,                   // OpGreaterThan OpVerify (price > param)
    // Cleanup
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
    0x51,

    // --- PATH 5 check: selector == Op5? (5B) ---
    0x67,                         // OpElse
    0x76,                         // OpDup
    0x55, 0x9c,                   // Op5 OpNumEqual
    0x63,                         // OpIf
    0x75,                         // OpDrop (selector)

    // PATH 5: English bid D&R (22B)
    // Self-continuation: output[0].spk == input[0].spk
    0x00, 0xc3,                   // Op0 OpTxOutputSpk
    0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
    0x87, 0x69,                   // OpEqual OpVerify
    // Verify new bid > input value + param (min increment)
    0xb9, 0xbe,                   // OpTxInputIndex OpTxInputAmount -> input_value
    0x51, 0x79,                   // Op1 OpPick -> param (stack: param, input_val, param(0), expiry(1)...)
    0x93,                         // OpAdd -> input_value + param
    0x00, 0xc2,                   // Op0 OpTxOutputAmount -> output[0].value
    0x7c,                         // OpSwap
    0xa0, 0x69,                   // OpGreaterThan OpVerify (output > input + param)
    // Verify expiry not passed
    0x51, 0x79,                   // Op1 OpPick -> expiry
    0x76, 0x00, 0x9c,             // OpDup Op0 OpNumEqual
    0x64,                         // OpNotIf
    0xba, 0xa0, 0x69,             // OpTxLockTime OpGreaterThan OpVerify
    0x67,                         // OpElse
    0x75,                         // OpDrop
    0x68,                         // OpEndIf
    // Cleanup
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
    0x51,

    // --- ELSE: PATH 6 (settle/collateral) ---
    0x67,                         // OpElse
    0x75,                         // OpDrop (selector)

    // PATH 6: Settle/Collateral (15B)
    // Verify expiry passed: OpTxLockTime >= expiry_daa
    0x51, 0x79,                   // Op1 OpPick -> expiry
    0xba,                         // OpTxLockTime
    0x7c,                         // OpSwap
    0xa2, 0x69,                   // OpGTE OpVerify (lockTime >= expiry)
    // Verify payment to seller from UTXO value (highest bid)
    0x51, 0xc3, 0xaa,             // Op1 OpTxOutputSpk OpBlake2b
    0x55, 0x79,                   // Op5 OpPick -> seller_spk_hash
    0x87, 0x69,                   // OpEqual OpVerify
    // Cleanup
    0x75, 0x75, 0x75, 0x75, 0x75, 0x75,
    0x51,

    // --- Close all if/else/endif ---
    0x68,                         // OpEndIf (path 5/6)
    0x68,                         // OpEndIf (path 4/5+6)
    0x68,                         // OpEndIf (path 3/4+5+6)
    0x68,                         // OpEndIf (path 2/3+4+5+6)
    0x68,                         // OpEndIf (path 1/2+3+4+5+6)
];

// Redeem script builder

/// Build listing redeemScript.
///
/// State (104B) + Body = full redeemScript.
///
/// # Arguments
/// * `seller_spk_hash` - Blake2b-256 hash of seller's SPK (32B)
/// * `seller_spk` - Seller's full SPK script bytes (34B: 0x20 + pubkey + 0xac for P2PK)
/// * `asking_price` - Price in sompi
/// * `listing_type` - 0=fixed, 1=dutch, 2=english
/// * `expiry_daa` - Expiration DAA score (0 = no expiry)
/// * `param` - Type-specific parameter (dutch: tick_decrement, english: min_bid_increment)
pub fn build_listing_redeem_script(
    seller_spk_hash: &[u8; 32],
    seller_spk: &[u8; 34],
    asking_price: u64,
    listing_type: u64,
    expiry_daa: u64,
    param: u64,
) -> Vec<u8> {
    let mut rs = Vec::with_capacity(LISTING_STATE_SIZE + LISTING_BODY.len());

    // State: 6 data pushes (104 bytes total)
    rs.push(0x20); // push 32 bytes
    rs.extend_from_slice(seller_spk_hash);        // 33B
    rs.push(0x22); // push 34 bytes
    rs.extend_from_slice(seller_spk);              // 35B
    rs.push(0x08); // push 8 bytes
    rs.extend_from_slice(&u64_le(asking_price));   // 9B
    rs.push(0x08); // push 8 bytes
    rs.extend_from_slice(&u64_le(listing_type));   // 9B
    rs.push(0x08); // push 8 bytes
    rs.extend_from_slice(&u64_le(expiry_daa));     // 9B
    rs.push(0x08); // push 8 bytes
    rs.extend_from_slice(&u64_le(param));          // 9B
    // Total state: 33 + 35 + 9 + 9 + 9 + 9 = 104

    // Body
    rs.extend_from_slice(LISTING_BODY);
    rs
}

// Sigscript builders

/// Build listing PATH 1 (fixed-price fill) sigscript.
///
/// Layout: `[Op1 selector] [pushdata(RS)]`
pub fn build_listing_fill_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(opn(1)); // Op1 selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build listing PATH 2 (cancel) sigscript.
///
/// Layout: `[push(sig+type 65B)] [push(pubkey 32B)] [Op2 selector] [pushdata(RS)]`
///
/// Sig and pubkey are placed BEFORE selector so that Op6 OpRoll always
/// finds the selector at depth 6 after state pushes.
pub fn build_listing_cancel_sigscript(
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut sig_with_type = Vec::with_capacity(65);
    sig_with_type.extend_from_slice(signature);
    sig_with_type.push(0x01); // SIGHASH_ALL

    let mut ss = Vec::with_capacity(66 + 33 + 1 + redeem_script.len() + 3);
    ss.extend_from_slice(&push_data(&sig_with_type)); // push sig (65B -> 66B with length prefix)
    ss.extend_from_slice(&push_data(pubkey));          // push pk (32B -> 33B with length prefix)
    ss.push(opn(2)); // Op2 selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build listing PATH 3 (dutch buy) sigscript.
///
/// Layout: `[Op3 selector] [pushdata(RS)]`
pub fn build_listing_dutch_buy_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(opn(3)); // Op3 selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build listing PATH 4 (dutch tick) sigscript.
///
/// Layout: `[Op4 selector] [pushdata(RS)]`
pub fn build_listing_dutch_tick_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(opn(4)); // Op4 selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build listing PATH 5 (english bid) sigscript.
///
/// Layout: `[Op5 selector] [pushdata(RS)]`
pub fn build_listing_english_bid_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(opn(5)); // Op5 selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build listing PATH 6 (settle/collateral) sigscript.
///
/// Layout: `[Op6 selector] [pushdata(RS)]`
pub fn build_listing_settle_sigscript(redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(1 + redeem_script.len() + 3);
    ss.push(opn(6)); // Op6 selector
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2sh::blake2b_256;

    // --- Helper data ---

    fn test_seller_pk() -> [u8; 32] {
        [0x02u8; 32]
    }

    fn test_seller_spk() -> [u8; 34] {
        let mut spk = [0u8; 34];
        spk[0] = 0x20; // push 32 bytes
        spk[1..33].copy_from_slice(&test_seller_pk());
        spk[33] = 0xac; // OpCheckSig
        spk
    }

    fn test_seller_spk_hash() -> [u8; 32] {
        // Hash of version(0u16 LE) + spk script
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&test_seller_spk());
        blake2b_256(&data)
    }

    fn build_test_rs() -> Vec<u8> {
        build_listing_redeem_script(
            &test_seller_spk_hash(),
            &test_seller_spk(),
            1_000_000,  // 0.01 KAS
            0,          // fixed
            100_000,    // expiry
            0,          // param (unused for fixed)
        )
    }

    // --- Body length ---

    #[test]
    fn body_length_stable() {
        // If this changes, sigscript dispatch thresholds may break.
        let len = LISTING_BODY.len();
        assert!(len > 0, "body must not be empty");
        // Verify the length is reasonable (expected ~170-200B for 6 paths)
        assert!(len < 300, "body unexpectedly large: {len}B");
    }

    // --- State size ---

    #[test]
    fn state_size_is_104() {
        assert_eq!(LISTING_STATE_SIZE, 104);
    }

    #[test]
    fn state_layout_matches() {
        // Verify: 33 + 35 + 9 + 9 + 9 + 9 = 104
        let expected = 33 + 35 + 9 + 9 + 9 + 9;
        assert_eq!(expected, LISTING_STATE_SIZE);
    }

    // --- Redeem script builder ---

    #[test]
    fn rs_builder_length() {
        let rs = build_test_rs();
        assert_eq!(rs.len(), LISTING_STATE_SIZE + LISTING_BODY.len());
    }

    #[test]
    fn rs_starts_with_state() {
        let rs = build_test_rs();
        // First byte should be 0x20 (push 32 bytes for seller_spk_hash)
        assert_eq!(rs[0], 0x20, "first byte must be push-32");
    }

    #[test]
    fn rs_ends_with_body() {
        let rs = build_test_rs();
        let body_start = LISTING_STATE_SIZE;
        assert_eq!(&rs[body_start..], LISTING_BODY, "RS must end with body bytecode");
    }

    #[test]
    fn rs_state_seller_spk_hash() {
        let rs = build_test_rs();
        let hash = test_seller_spk_hash();
        assert_eq!(&rs[1..33], &hash, "seller_spk_hash mismatch");
    }

    #[test]
    fn rs_state_seller_spk() {
        let rs = build_test_rs();
        let spk = test_seller_spk();
        // offset: 33 (spk_hash) + 1 (push opcode 0x22) = 34
        assert_eq!(rs[33], 0x22, "seller_spk push opcode must be 0x22 (34 bytes)");
        assert_eq!(&rs[34..68], &spk, "seller_spk mismatch");
    }

    #[test]
    fn rs_state_asking_price() {
        let rs = build_test_rs();
        // offset: 33 + 35 = 68, then +1 for push opcode = 69
        assert_eq!(rs[68], 0x08, "asking_price push opcode");
        let price_bytes = &rs[69..77];
        let price = u64::from_le_bytes(price_bytes.try_into().unwrap());
        assert_eq!(price, 1_000_000);
    }

    #[test]
    fn rs_state_listing_type() {
        let rs = build_test_rs();
        // offset: 68 + 9 = 77
        assert_eq!(rs[77], 0x08, "listing_type push opcode");
        let lt = u64::from_le_bytes(rs[78..86].try_into().unwrap());
        assert_eq!(lt, 0, "listing_type should be 0 (fixed)");
    }

    #[test]
    fn rs_state_expiry_daa() {
        let rs = build_test_rs();
        // offset: 77 + 9 = 86
        assert_eq!(rs[86], 0x08, "expiry_daa push opcode");
        let exp = u64::from_le_bytes(rs[87..95].try_into().unwrap());
        assert_eq!(exp, 100_000);
    }

    #[test]
    fn rs_state_param() {
        let rs = build_test_rs();
        // offset: 86 + 9 = 95
        assert_eq!(rs[95], 0x08, "param push opcode");
        let p = u64::from_le_bytes(rs[96..104].try_into().unwrap());
        assert_eq!(p, 0);
    }

    #[test]
    fn rs_deterministic() {
        let rs1 = build_test_rs();
        let rs2 = build_test_rs();
        assert_eq!(rs1, rs2, "RS must be deterministic");
    }

    #[test]
    fn rs_different_params_differ() {
        let rs_fixed = build_listing_redeem_script(
            &test_seller_spk_hash(), &test_seller_spk(),
            1_000_000, 0, 100_000, 0,
        );
        let rs_dutch = build_listing_redeem_script(
            &test_seller_spk_hash(), &test_seller_spk(),
            1_000_000, 1, 100_000, 50_000,
        );
        assert_ne!(rs_fixed, rs_dutch, "different listing types must produce different RS");
    }

    // --- Sigscript selectors ---

    #[test]
    fn fill_sigscript_selector() {
        let rs = build_test_rs();
        let ss = build_listing_fill_sigscript(&rs);
        assert_eq!(ss[0], 0x51, "fill selector must be Op1");
    }

    #[test]
    fn cancel_sigscript_selector() {
        let rs = build_test_rs();
        let sig = [0xAA; 64];
        let pk = [0xBB; 32];
        let ss = build_listing_cancel_sigscript(&sig, &pk, &rs);
        // sig push: 65B with length prefix = [0x41, sig..., 0x01] = 66B
        // pk push: 32B with length prefix = [0x20, pk...] = 33B
        // selector Op2 at offset 66 + 33 = 99
        assert_eq!(ss[99], 0x52, "cancel selector must be Op2");
    }

    #[test]
    fn cancel_sigscript_contains_sig_and_pk() {
        let rs = build_test_rs();
        let sig = [0xAA; 64];
        let pk = [0xBB; 32];
        let ss = build_listing_cancel_sigscript(&sig, &pk, &rs);
        // sig push starts at 0: [0x41 (len=65), sig_64B, 0x01 (sighash type)]
        assert_eq!(ss[0], 65, "sig push length byte");
        assert_eq!(&ss[1..65], &sig[..], "sig bytes");
        assert_eq!(ss[65], 0x01, "sighash type");
        // pk push starts at 66: [0x20 (len=32), pk_32B]
        assert_eq!(ss[66], 32, "pk push length byte");
        assert_eq!(&ss[67..99], &pk[..], "pk bytes");
    }

    #[test]
    fn dutch_buy_sigscript_selector() {
        let rs = build_test_rs();
        let ss = build_listing_dutch_buy_sigscript(&rs);
        assert_eq!(ss[0], 0x53, "dutch buy selector must be Op3");
    }

    #[test]
    fn dutch_tick_sigscript_selector() {
        let rs = build_test_rs();
        let ss = build_listing_dutch_tick_sigscript(&rs);
        assert_eq!(ss[0], 0x54, "dutch tick selector must be Op4");
    }

    #[test]
    fn english_bid_sigscript_selector() {
        let rs = build_test_rs();
        let ss = build_listing_english_bid_sigscript(&rs);
        assert_eq!(ss[0], 0x55, "english bid selector must be Op5");
    }

    #[test]
    fn settle_sigscript_selector() {
        let rs = build_test_rs();
        let ss = build_listing_settle_sigscript(&rs);
        assert_eq!(ss[0], 0x56, "settle selector must be Op6");
    }

    // --- Sigscript lengths ---

    #[test]
    fn fill_sigscript_length() {
        let rs = build_test_rs();
        let ss = build_listing_fill_sigscript(&rs);
        // Op1(1) + PUSHDATA2(3) + RS
        assert_eq!(ss.len(), 1 + 3 + rs.len(), "fill sigscript length");
    }

    #[test]
    fn cancel_sigscript_length() {
        let rs = build_test_rs();
        let sig = [0xAA; 64];
        let pk = [0xBB; 32];
        let ss = build_listing_cancel_sigscript(&sig, &pk, &rs);
        // push(sig65)(66) + push(pk32)(33) + Op2(1) + PUSHDATA2(3) + RS
        assert_eq!(ss.len(), 66 + 33 + 1 + 3 + rs.len(), "cancel sigscript length");
    }

    #[test]
    fn simple_sigscripts_same_size() {
        let rs = build_test_rs();
        let s1 = build_listing_fill_sigscript(&rs);
        let s3 = build_listing_dutch_buy_sigscript(&rs);
        let s4 = build_listing_dutch_tick_sigscript(&rs);
        let s5 = build_listing_english_bid_sigscript(&rs);
        let s6 = build_listing_settle_sigscript(&rs);
        // All simple sigscripts (no sig/pk) should be same length
        assert_eq!(s1.len(), s3.len());
        assert_eq!(s1.len(), s4.len());
        assert_eq!(s1.len(), s5.len());
        assert_eq!(s1.len(), s6.len());
    }

    // --- Payload ---

    #[test]
    fn payload_roundtrip() {
        let rs = build_test_rs();
        let payload = build_listing_payload(&rs);
        let parsed = parse_listing_payload(&payload).expect("must parse");
        assert_eq!(parsed, &rs[..], "roundtrip must preserve RS");
    }

    #[test]
    fn payload_prefix() {
        let payload = build_listing_payload(&[0x51]);
        assert!(payload.starts_with(b"KOB:L:"), "must start with listing prefix");
    }

    #[test]
    fn payload_parse_rejects_wrong_prefix() {
        let bad = b"KOB:A:somedata";
        assert!(parse_listing_payload(bad).is_none(), "must reject non-listing prefix");
    }

    #[test]
    fn payload_parse_empty() {
        assert!(parse_listing_payload(b"").is_none());
        assert!(parse_listing_payload(b"KOB:").is_none());
    }

    // --- Body structure ---

    #[test]
    fn body_starts_with_dispatch() {
        // First two bytes: Op6(0x56) OpRoll(0x7a) — roll selector from depth 6
        assert_eq!(LISTING_BODY[0], 0x56, "must start with Op6");
        assert_eq!(LISTING_BODY[1], 0x7a, "second byte must be OpRoll");
    }

    #[test]
    fn body_ends_with_endifs() {
        let len = LISTING_BODY.len();
        // Last 5 bytes should be OpEndIf (0x68) x5 for 5 nested if/else levels
        for i in 0..5 {
            assert_eq!(
                LISTING_BODY[len - 5 + i], 0x68,
                "byte at offset -{} must be OpEndIf", 5 - i
            );
        }
    }

    #[test]
    fn body_contains_checksig() {
        // PATH 2 (cancel) must contain OpCheckSigVerify (0xad)
        assert!(
            LISTING_BODY.contains(&0xad),
            "body must contain OpCheckSigVerify for cancel path"
        );
    }

    #[test]
    fn body_contains_blake2b() {
        // PATH 1/3/6 verify seller_spk_hash via Blake2b
        assert!(
            LISTING_BODY.contains(&0xaa),
            "body must contain OpBlake2b for SPK hash verification"
        );
    }

    #[test]
    fn body_contains_locktimeverify() {
        // PATH 6 uses expiry check via OpTxLockTime
        assert!(
            LISTING_BODY.contains(&0xba),
            "body must contain OpTxLockTime for expiry checks"
        );
    }

    #[test]
    fn body_contains_self_continuation() {
        // PATH 4 and 5 (D&R) need OpTxInputSpk (0xbf) for self-continuation
        assert!(
            LISTING_BODY.contains(&0xbf),
            "body must contain OpTxInputSpk for D&R self-continuation"
        );
    }

    #[test]
    fn body_if_else_balanced() {
        let mut depth: i32 = 0;
        for &b in LISTING_BODY {
            match b {
                0x63 | 0x64 => depth += 1, // OpIf | OpNotIf
                0x68 => depth -= 1,          // OpEndIf
                _ => {}
            }
            assert!(depth >= 0, "OpEndIf without matching OpIf");
        }
        assert_eq!(depth, 0, "unbalanced OpIf/OpEndIf: depth={depth}");
    }

    // --- Dutch listing ---

    #[test]
    fn dutch_rs_has_tick_param() {
        let rs = build_listing_redeem_script(
            &test_seller_spk_hash(), &test_seller_spk(),
            10_000_000, 1, 200_000, 500_000,
        );
        // param at offset 96..104
        let p = u64::from_le_bytes(rs[96..104].try_into().unwrap());
        assert_eq!(p, 500_000, "dutch tick decrement");
    }

    // --- English listing ---

    #[test]
    fn english_rs_has_min_increment() {
        let rs = build_listing_redeem_script(
            &test_seller_spk_hash(), &test_seller_spk(),
            5_000_000, 2, 300_000, 100_000,
        );
        let lt = u64::from_le_bytes(rs[78..86].try_into().unwrap());
        assert_eq!(lt, 2, "listing_type should be 2 (english)");
        let p = u64::from_le_bytes(rs[96..104].try_into().unwrap());
        assert_eq!(p, 100_000, "min bid increment");
    }

    // --- Opn helper ---

    #[test]
    fn opn_values() {
        assert_eq!(opn(0), 0x00);
        assert_eq!(opn(1), 0x51);
        assert_eq!(opn(6), 0x56);
        assert_eq!(opn(16), 0x60);
    }

    #[test]
    #[should_panic(expected = "OpN index out of range")]
    fn opn_panic_on_17() {
        opn(17);
    }

    // --- Edge cases ---

    #[test]
    fn zero_expiry_no_expiry() {
        // expiry_daa = 0 means no expiry (GTC listing)
        let rs = build_listing_redeem_script(
            &test_seller_spk_hash(), &test_seller_spk(),
            1_000_000, 0, 0, 0,
        );
        let exp = u64::from_le_bytes(rs[87..95].try_into().unwrap());
        assert_eq!(exp, 0, "zero expiry = no expiry");
    }

    #[test]
    fn max_price() {
        let rs = build_listing_redeem_script(
            &test_seller_spk_hash(), &test_seller_spk(),
            u64::MAX, 0, 0, 0,
        );
        let price = u64::from_le_bytes(rs[69..77].try_into().unwrap());
        assert_eq!(price, u64::MAX);
    }
}
