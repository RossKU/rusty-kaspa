//! Mint-authority contract — canonical MINT-attestation pre-image encoder
//! (`STABLECOIN_ROBUST_DESIGN.md` §9).
//!
//! This is the *Writer* side of the MINT attestation gate: the mint-authority
//! contract's hot MINT-role key signs `Blake3(pre-image)` (==
//! [`build_mint_attestation_message`]) over a message that binds this
//! specific spend AND (the §9-gap security fix this task closes) the exact
//! newly-minted coin's scriptPublicKey. On-chain, [`super::body`]
//! reconstructs the identical pre-image from transaction introspection and
//! `OpCheckSigFromStack`-verifies the signature (see `super::body`'s module
//! doc for the exact opcode sequence).
//!
//! Deliberately uses a DISTINCT `DOMAIN_TAG_MINT` (see [`super::DOMAIN_TAG_MINT`])
//! from the stablecoin covenant's own `super::super::DOMAIN_TAG` — this
//! prevents a MINT attestation from ever being replayed as a valid
//! stablecoin-covenant attestation (cross-CONTRACT replay), on top of the
//! stablecoin covenant's own `op_type`-based cross-BRANCH replay protection.
//!
//! # Message composition (124-byte pre-image, then Blake3 → 32-byte message)
//!
//! ```text
//! Blake3(
//!     DOMAIN_TAG_MINT        (8B  constant — super::DOMAIN_TAG_MINT)
//!  || covenant_id            (32B raw, on-chain: OpTxInputIndex OpInputCovenantId)
//!  || outpoint_txid          (32B raw, on-chain: OpTxInputIndex OpOutpointTxId)
//!  || outpoint_index         (4B  LE,  on-chain: OpTxInputIndex OpOutpointIndex OpNum2Bin(4))
//!  || mint_amount            (8B  LE,  sigscript-supplied, folded in as-is)
//!  || new_running_supply     (8B  LE,  on-chain: extracted from the
//!                                       authenticated successor redeemScript,
//!                                       NOT attacker-suppliable independent
//!                                       of that authentication)
//!  || recipient_spk_hash     (32B,     on-chain: Op1 OpTxOutputSpk OpBlake3 --
//!                                       Blake3 of the ACTUAL output[1]
//!                                       scriptPublicKey, recomputed fresh
//!                                       from the CURRENT transaction, never
//!                                       a separately-suppliable claim -- this
//!                                       is what binds the recipient and
//!                                       closes the §9 replay gap)
//! )
//! ```
//!
//! Every input-side introspection index is sourced from `OpTxInputIndex`
//! (never an immediate), so the pre-image is bound to *this* input's spend
//! and cannot be replayed for a different input/outpoint. `recipient_spk_hash`
//! being derived from the ACTUAL current output[1] (not a sigscript-supplied
//! value that would need its own separate equality check) means a captured,
//! honestly-signed MINT attestation cannot be replayed against a transaction
//! that redirects the newly-minted coin to a different recipient: swapping
//! the recipient changes the actual output[1] SPK, which changes the
//! recomputed message hash, which the original signature no longer matches.

use super::DOMAIN_TAG_MINT;

/// Width, in bytes, of the domain tag field.
pub const DOMAIN_TAG_LEN: usize = 8;
/// Width, in bytes, of the covenant id field.
pub const COVENANT_ID_LEN: usize = 32;
/// Width, in bytes, of the spent outpoint's transaction id field.
pub const OUTPOINT_TXID_LEN: usize = 32;
/// Width, in bytes, of the spent outpoint's index field (fixed via `OpNum2Bin`).
pub const OUTPOINT_INDEX_LEN: usize = 4;
/// Width, in bytes, of the `mint_amount` field.
pub const MINT_AMOUNT_LEN: usize = 8;
/// Width, in bytes, of the `new_running_supply` field.
pub const NEW_RUNNING_SUPPLY_LEN: usize = 8;
/// Width, in bytes, of the `recipient_spk_hash` field.
pub const RECIPIENT_SPK_HASH_LEN: usize = 32;

/// Byte offset of each field inside the pre-image (see module doc for order).
pub const OFFSET_DOMAIN_TAG: usize = 0;
pub const OFFSET_COVENANT_ID: usize = OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN; // 8
pub const OFFSET_OUTPOINT_TXID: usize = OFFSET_COVENANT_ID + COVENANT_ID_LEN; // 40
pub const OFFSET_OUTPOINT_INDEX: usize = OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN; // 72
pub const OFFSET_MINT_AMOUNT: usize = OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN; // 76
pub const OFFSET_NEW_RUNNING_SUPPLY: usize = OFFSET_MINT_AMOUNT + MINT_AMOUNT_LEN; // 84
pub const OFFSET_RECIPIENT_SPK_HASH: usize = OFFSET_NEW_RUNNING_SUPPLY + NEW_RUNNING_SUPPLY_LEN; // 92

/// Total pre-image length: `8+32+32+4+8+8+32 = 124` bytes (§9).
pub const MINT_ATTESTATION_PREIMAGE_LEN: usize = OFFSET_RECIPIENT_SPK_HASH + RECIPIENT_SPK_HASH_LEN;

/// Length of an x-only Schnorr public key (role key), in bytes.
pub const X_ONLY_PUBKEY_LEN: usize = 32;

/// `op_type` discriminant byte values for the mint-authority contract's own
/// (separate, 2-way) dispatch. Both `MINT` and `RAISE_CAP` are wired (see
/// `super::body::build_mint_branch`/`super::body::build_raise_cap_branch`).
pub mod op_type {
    pub const MINT: u8 = 0x00;
    pub const RAISE_CAP: u8 = 0x01;
}

/// Exclusive upper bound on `outpoint_index` for which the little-endian
/// 4-byte encoding here matches the engine's `OpNum2Bin(4)` acceptance.
pub const MAX_OUTPOINT_INDEX_EXCLUSIVE: u64 = 1 << 31;

/// Exclusive upper bound on `running_supply`/`current_cap`/`mint_amount`/
/// `new_cap` for which the fixed 8-byte LE encoding this contract uses stays
/// within the domain the engine's sign-magnitude script-number arithmetic
/// (`OpAdd`/`OpNumEqual`/`OpLessThanOrEqual`/`OpGreaterThan`/
/// `OpGreaterThanOrEqual`, all of which decode via `i64`) reads as
/// non-negative -- mirrors `stablecoin::attestation::MAX_AMOUNT_EXCLUSIVE`
/// (same bound, same rationale, distinct constant because it gates a
/// different set of fields in this separate contract).
pub const MAX_AMOUNT_EXCLUSIVE: u64 = 1 << 63;

/// Errors from constructing mint-authority attestation/state material outside
/// the numeric domain the on-chain bytecode's fixed-width, sign-magnitude
/// script-number fields can represent as non-negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MintAuthorityError {
    /// One of `running_supply`/`current_cap`/`mint_amount`/`new_cap` is
    /// outside `[0, 2^63)` -- at or above this bound the value's raw 8-byte
    /// LE encoding has its sign bit set, so the engine's script-number
    /// arithmetic would read it as non-positive instead of the intended u64
    /// magnitude.
    #[error("value {0} must be < 2^63 to match the on-chain sign-magnitude script-number domain")]
    AmountTooLarge(u64),
}

/// Check that `value` (a `running_supply`/`current_cap`/`mint_amount`/
/// `new_cap` field) falls in the numeric domain this contract's fixed 8-byte
/// LE fields must stay within. Mirrors
/// `stablecoin::attestation::check_numeric_domain`'s release-mode-check role
/// (that function is specific to the stablecoin covenant's own
/// `outpoint_index`/`amount` fields; this one covers the mint-authority
/// contract's distinct field set, all sharing the same `[0, 2^63)` bound).
pub fn check_numeric_domain(value: u64) -> Result<(), MintAuthorityError> {
    if value >= MAX_AMOUNT_EXCLUSIVE {
        return Err(MintAuthorityError::AmountTooLarge(value));
    }
    Ok(())
}

/// Build the 124-byte MINT attestation pre-image. `recipient_spk` is the
/// newly-minted coin's raw `ScriptPublicKey::to_bytes()` form (2-byte
/// big-endian version || script) — it is hashed with `Blake3` here to
/// produce `recipient_spk_hash`, mirroring the body's
/// `Op1 OpTxOutputSpk OpBlake3`.
pub fn build_mint_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    mint_amount: u64,
    new_running_supply: u64,
    recipient_spk: &[u8],
) -> [u8; MINT_ATTESTATION_PREIMAGE_LEN] {
    debug_assert!(u64::from(outpoint_index) < MAX_OUTPOINT_INDEX_EXCLUSIVE, "outpoint_index must be < 2^31 to match on-chain OpNum2Bin(4)");
    debug_assert!(mint_amount < MAX_AMOUNT_EXCLUSIVE, "mint_amount must be < 2^63 to match the on-chain sign-magnitude script-number domain");
    debug_assert!(new_running_supply < MAX_AMOUNT_EXCLUSIVE, "new_running_supply must be < 2^63 to match the on-chain sign-magnitude script-number domain");

    let recipient_spk_hash = *blake3::hash(recipient_spk).as_bytes();

    let mut out = [0u8; MINT_ATTESTATION_PREIMAGE_LEN];
    out[OFFSET_DOMAIN_TAG..OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN].copy_from_slice(&DOMAIN_TAG_MINT);
    out[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + COVENANT_ID_LEN].copy_from_slice(covenant_id);
    out[OFFSET_OUTPOINT_TXID..OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN].copy_from_slice(outpoint_txid);
    out[OFFSET_OUTPOINT_INDEX..OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN].copy_from_slice(&outpoint_index.to_le_bytes());
    out[OFFSET_MINT_AMOUNT..OFFSET_MINT_AMOUNT + MINT_AMOUNT_LEN].copy_from_slice(&mint_amount.to_le_bytes());
    out[OFFSET_NEW_RUNNING_SUPPLY..OFFSET_NEW_RUNNING_SUPPLY + NEW_RUNNING_SUPPLY_LEN].copy_from_slice(&new_running_supply.to_le_bytes());
    out[OFFSET_RECIPIENT_SPK_HASH..OFFSET_RECIPIENT_SPK_HASH + RECIPIENT_SPK_HASH_LEN].copy_from_slice(&recipient_spk_hash);
    out
}

/// Build the 32-byte MINT attestation message: `Blake3(pre-image)`. This is
/// exactly the digest the body's final `OpBlake3` produces and feeds to
/// `OpCheckSigFromStack`; the MINT role signs this with a raw (message-hash)
/// Schnorr signature (no SIGHASH type byte).
pub fn build_mint_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    mint_amount: u64,
    new_running_supply: u64,
    recipient_spk: &[u8],
) -> [u8; 32] {
    let preimage = build_mint_attestation_preimage(covenant_id, outpoint_txid, outpoint_index, mint_amount, new_running_supply, recipient_spk);
    *blake3::hash(&preimage).as_bytes()
}

/// Width, in bytes, of the `new_cap` field (RAISE_CAP's preimage tail).
pub const NEW_CAP_LEN: usize = 8;

/// Byte offsets inside the RAISE_CAP pre-image (§9: "`RAISE_CAP`'s attestation
/// preimage follows the same prefix with a `new_cap(8,LE)` tail in place of
/// the MINT-specific fields"). Shares the `DOMAIN_TAG_MINT || covenant_id ||
/// outpoint_txid || outpoint_index` prefix byte-for-byte with the MINT
/// pre-image above, then a `new_cap(8,LE)` tail instead of MINT's
/// `mint_amount || new_running_supply || recipient_spk_hash` tail. No
/// `op_type` byte: §9 states the RAISE_CAP pre-image is `DOMAIN_TAG_MINT ||
/// covenant_id || outpoint_txid || outpoint_index || new_cap(8,LE)`, 84B
/// total -- cross-op replay is "structurally impossible regardless" per that
/// same paragraph, since MINT and RAISE_CAP are authorized by entirely
/// different keys (`mint_pubkey` vs. the `cap_authority` quorum) and the two
/// pre-image shapes/lengths already differ (124B vs. 84B), so an extra
/// `op_type` disambiguator byte would be redundant -- this also matches the
/// already-implemented MINT pre-image's own precedent of NOT including an
/// `op_type` byte.
pub const RAISE_CAP_OFFSET_DOMAIN_TAG: usize = 0;
pub const RAISE_CAP_OFFSET_COVENANT_ID: usize = RAISE_CAP_OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN; // 8
pub const RAISE_CAP_OFFSET_OUTPOINT_TXID: usize = RAISE_CAP_OFFSET_COVENANT_ID + COVENANT_ID_LEN; // 40
pub const RAISE_CAP_OFFSET_OUTPOINT_INDEX: usize = RAISE_CAP_OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN; // 72
pub const RAISE_CAP_OFFSET_NEW_CAP: usize = RAISE_CAP_OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN; // 76

/// Total RAISE_CAP pre-image length: `8+32+32+4+8 = 84` bytes (§9).
pub const RAISE_CAP_ATTESTATION_PREIMAGE_LEN: usize = RAISE_CAP_OFFSET_NEW_CAP + NEW_CAP_LEN;

/// Build the 84-byte RAISE_CAP attestation pre-image (see the constants'
/// module doc above for the exact layout/rationale).
pub fn build_raise_cap_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    new_cap: u64,
) -> [u8; RAISE_CAP_ATTESTATION_PREIMAGE_LEN] {
    debug_assert!(u64::from(outpoint_index) < MAX_OUTPOINT_INDEX_EXCLUSIVE, "outpoint_index must be < 2^31 to match on-chain OpNum2Bin(4)");
    debug_assert!(new_cap < MAX_AMOUNT_EXCLUSIVE, "new_cap must be < 2^63 to match the on-chain sign-magnitude script-number domain");

    let mut out = [0u8; RAISE_CAP_ATTESTATION_PREIMAGE_LEN];
    out[RAISE_CAP_OFFSET_DOMAIN_TAG..RAISE_CAP_OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN].copy_from_slice(&DOMAIN_TAG_MINT);
    out[RAISE_CAP_OFFSET_COVENANT_ID..RAISE_CAP_OFFSET_COVENANT_ID + COVENANT_ID_LEN].copy_from_slice(covenant_id);
    out[RAISE_CAP_OFFSET_OUTPOINT_TXID..RAISE_CAP_OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN].copy_from_slice(outpoint_txid);
    out[RAISE_CAP_OFFSET_OUTPOINT_INDEX..RAISE_CAP_OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN].copy_from_slice(&outpoint_index.to_le_bytes());
    out[RAISE_CAP_OFFSET_NEW_CAP..RAISE_CAP_OFFSET_NEW_CAP + NEW_CAP_LEN].copy_from_slice(&new_cap.to_le_bytes());
    out
}

/// Build the 32-byte RAISE_CAP attestation message: `Blake3(pre-image)`. The
/// cold 2-of-3 `cap_authority` quorum signs this (each signer producing a raw
/// message-hash Schnorr signature, no SIGHASH type byte) over the pre-image
/// binding the specific new ceiling (`new_cap`) to this exact spend
/// (`covenant_id`/`outpoint_txid`/`outpoint_index`).
pub fn build_raise_cap_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    new_cap: u64,
) -> [u8; 32] {
    let preimage = build_raise_cap_attestation_preimage(covenant_id, outpoint_txid, outpoint_index, new_cap);
    *blake3::hash(&preimage).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const COV_ID: [u8; 32] = [0xC0; 32];
    const TXID: [u8; 32] = [0x10; 32];
    const SPK: [u8; 8] = [0, 0, 0xaa, 0x20, 1, 2, 3, 4];

    #[test]
    fn preimage_length_is_124() {
        let preimage = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1000, 2000, &SPK);
        assert_eq!(preimage.len(), MINT_ATTESTATION_PREIMAGE_LEN);
        assert_eq!(MINT_ATTESTATION_PREIMAGE_LEN, 124);
    }

    #[test]
    fn domain_tag_is_distinct_from_stablecoin_domain_tag() {
        assert_ne!(DOMAIN_TAG_MINT, crate::contract::stablecoin::DOMAIN_TAG);
    }

    #[test]
    fn preimage_is_field_sensitive() {
        let base = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1000, 2000, &SPK);

        let diff_amount = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1001, 2000, &SPK);
        assert_ne!(base, diff_amount);

        let diff_supply = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1000, 2001, &SPK);
        assert_ne!(base, diff_supply);

        let diff_spk = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1000, 2000, &[9, 9, 9]);
        assert_ne!(base, diff_spk);

        let diff_index = build_mint_attestation_preimage(&COV_ID, &TXID, 1, 1000, 2000, &SPK);
        assert_ne!(base, diff_index);
    }

    #[test]
    fn message_is_blake3_of_preimage() {
        let preimage = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1000, 2000, &SPK);
        let message = build_mint_attestation_message(&COV_ID, &TXID, 0, 1000, 2000, &SPK);
        assert_eq!(message, *blake3::hash(&preimage).as_bytes());
    }

    #[test]
    fn raise_cap_preimage_length_is_84() {
        let preimage = build_raise_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);
        assert_eq!(preimage.len(), RAISE_CAP_ATTESTATION_PREIMAGE_LEN);
        assert_eq!(RAISE_CAP_ATTESTATION_PREIMAGE_LEN, 84);
    }

    #[test]
    fn raise_cap_preimage_shares_prefix_with_mint_preimage() {
        // Both preimages start with DOMAIN_TAG_MINT || covenant_id ||
        // outpoint_txid || outpoint_index -- the same 76-byte prefix,
        // byte-for-byte, before diverging into their op-specific tails.
        let mint_preimage = build_mint_attestation_preimage(&COV_ID, &TXID, 3, 1000, 2000, &SPK);
        let raise_cap_preimage = build_raise_cap_attestation_preimage(&COV_ID, &TXID, 3, 1_000_000);
        assert_eq!(&mint_preimage[..76], &raise_cap_preimage[..76]);
    }

    #[test]
    fn raise_cap_preimage_is_field_sensitive() {
        let base = build_raise_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);

        let diff_cap = build_raise_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_001);
        assert_ne!(base, diff_cap);

        let diff_index = build_raise_cap_attestation_preimage(&COV_ID, &TXID, 1, 1_000_000);
        assert_ne!(base, diff_index);

        let other_txid: [u8; 32] = [0x11; 32];
        let diff_txid = build_raise_cap_attestation_preimage(&COV_ID, &other_txid, 0, 1_000_000);
        assert_ne!(base, diff_txid);
    }

    #[test]
    fn raise_cap_message_is_blake3_of_preimage() {
        let preimage = build_raise_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);
        let message = build_raise_cap_attestation_message(&COV_ID, &TXID, 0, 1_000_000);
        assert_eq!(message, *blake3::hash(&preimage).as_bytes());
    }

    #[test]
    fn check_numeric_domain_rejects_at_or_above_2pow63() {
        // SUB-FIX E off-chain builder regression: any of running_supply/
        // current_cap/mint_amount/new_cap at or above 2^63 must be rejected
        // (its raw 8-byte LE encoding would have the sign bit set, so the
        // on-chain sign-magnitude script-number arithmetic would read it as
        // non-positive instead of the intended u64 magnitude).
        assert!(check_numeric_domain(0).is_ok());
        assert!(check_numeric_domain(MAX_AMOUNT_EXCLUSIVE - 1).is_ok());
        assert_eq!(check_numeric_domain(MAX_AMOUNT_EXCLUSIVE), Err(MintAuthorityError::AmountTooLarge(MAX_AMOUNT_EXCLUSIVE)));
        assert_eq!(check_numeric_domain(u64::MAX), Err(MintAuthorityError::AmountTooLarge(u64::MAX)));
    }

    #[test]
    fn raise_cap_preimage_never_equals_a_mint_preimage() {
        // Even holding covenant_id/outpoint fields constant, the RAISE_CAP
        // preimage (84B) can never collide with a MINT preimage (124B) --
        // different lengths alone rule out cross-op replay, independent of
        // the fact the two ops are authorized by entirely different keys.
        let mint_preimage = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1000, 2000, &SPK);
        let raise_cap_preimage = build_raise_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);
        assert_ne!(mint_preimage.len(), raise_cap_preimage.len());
    }
}
