//! Canonical issuer-attestation pre-image encoder for the KCC-0020 native-value
//! stablecoin (WU-A).
//!
//! This is the *Writer* side of the attestation gate: the off-chain issuer
//! tool builds the pre-image with [`build_attestation_preimage`], signs
//! `Blake3(pre-image)` (== [`build_attestation_message`]) with the issuer's
//! x-only Schnorr key, and hands the raw 64-byte signature to the spender.
//! On-chain, [`super::body`] reconstructs the identical pre-image from
//! transaction introspection and `OpCheckSigFromStack`-verifies the signature.
//!
//! The two sides MUST agree byte-for-byte. This module is the single source
//! of truth for the field **order** and each field's **fixed width**; the
//! body's conformance test cross-checks its emitted opcode sequence against
//! the constants defined here.
//!
//! # Message composition (116-byte pre-image, then Blake3 → 32-byte message)
//!
//! ```text
//! Blake3(
//!     DOMAIN_TAG           (8B  constant, network-scoped — super::DOMAIN_TAG)
//!  || covenant_id          (32B raw, on-chain: OpTxInputIndex OpInputCovenantId)
//!  || outpoint_txid        (32B raw, on-chain: OpTxInputIndex OpOutpointTxId)
//!  || outpoint_index       (4B  LE,  on-chain: OpTxInputIndex OpOutpointIndex OpNum2Bin(4))
//!  || successor_spk_hash   (32B,     on-chain: OpTxInputIndex OpTxOutputSpk OpBlake3)
//!  || amount               (8B  LE,  on-chain: OpTxInputIndex OpTxInputAmount OpNum2Bin(8))
//! )
//! ```
//!
//! - Every input-side introspection index is sourced from `OpTxInputIndex`
//!   (never an immediate), so the pre-image is bound to *this* input's spend
//!   and cannot be replayed for a different input. `covenant_id` +
//!   `outpoint_txid` + `outpoint_index` together pin the exact UTXO being
//!   spent, which is the replay-protection requirement (memo GO-condition 1).
//! - `successor_spk_hash` is `Blake3` of the successor output's
//!   `ScriptPublicKey::to_bytes()` form (version as 2 big-endian bytes,
//!   followed by the script) — this is exactly what `OpTxOutputSpk` pushes
//!   before the body's `OpBlake3`. Callers pass the raw SPK bytes; this
//!   module hashes them.
//! - The `outpoint_index` (4B) and `amount` (8B) fixed-width encodings are
//!   plain little-endian, which is byte-identical to the engine's
//!   `OpNum2Bin(size)` output (`serialize_i64`) for the accepted numeric
//!   domain: `outpoint_index < 2^31` and `amount < 2^63` (the engine rejects
//!   larger values, so the covenant only ever runs inside this domain).

use super::DOMAIN_TAG;

/// Width, in bytes, of the domain tag field.
pub const DOMAIN_TAG_LEN: usize = 8;
/// Width, in bytes, of the covenant id field.
pub const COVENANT_ID_LEN: usize = 32;
/// Width, in bytes, of the spent outpoint's transaction id field.
pub const OUTPOINT_TXID_LEN: usize = 32;
/// Width, in bytes, of the spent outpoint's index field (fixed via `OpNum2Bin`).
pub const OUTPOINT_INDEX_LEN: usize = 4;
/// Width, in bytes, of the successor scriptPublicKey hash field.
pub const SUCCESSOR_SPK_HASH_LEN: usize = 32;
/// Width, in bytes, of the amount field (fixed via `OpNum2Bin`).
pub const AMOUNT_LEN: usize = 8;

/// Byte offset of each field inside the pre-image (see module doc for order).
pub const OFFSET_DOMAIN_TAG: usize = 0;
pub const OFFSET_COVENANT_ID: usize = OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN; // 8
pub const OFFSET_OUTPOINT_TXID: usize = OFFSET_COVENANT_ID + COVENANT_ID_LEN; // 40
pub const OFFSET_OUTPOINT_INDEX: usize = OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN; // 72
pub const OFFSET_SUCCESSOR_SPK_HASH: usize = OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN; // 76
pub const OFFSET_AMOUNT: usize = OFFSET_SUCCESSOR_SPK_HASH + SUCCESSOR_SPK_HASH_LEN; // 108

/// Total pre-image length: `8 + 32 + 32 + 4 + 32 + 8 = 116` bytes.
pub const ATTESTATION_PREIMAGE_LEN: usize =
    DOMAIN_TAG_LEN + COVENANT_ID_LEN + OUTPOINT_TXID_LEN + OUTPOINT_INDEX_LEN + SUCCESSOR_SPK_HASH_LEN + AMOUNT_LEN;

/// Length of an x-only Schnorr public key (issuer key), in bytes.
pub const X_ONLY_PUBKEY_LEN: usize = 32;

/// Exclusive upper bound on `outpoint_index` for which the little-endian
/// 4-byte encoding here matches the engine's `OpNum2Bin(4)` acceptance.
pub const MAX_OUTPOINT_INDEX_EXCLUSIVE: u64 = 1 << 31;
/// Exclusive upper bound on `amount` for which the little-endian 8-byte
/// encoding here matches the engine's `OpTxInputAmount` / `OpNum2Bin(8)`
/// acceptance (`u64 -> i64` conversion rejects `>= 2^63`).
pub const MAX_AMOUNT_EXCLUSIVE: u64 = 1 << 63;

/// Errors from building/validating stablecoin attestation material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StablecoinError {
    /// A key that must be a 32-byte x-only Schnorr pubkey had another length.
    /// A 33-byte compressed key is the classic mistake — it would brick the
    /// covenant (the engine's `OpCheckSigFromStack` parses the pubkey as
    /// x-only, i.e. strictly 32 bytes).
    #[error("issuer pubkey must be {X_ONLY_PUBKEY_LEN} bytes (x-only), got {0}")]
    InvalidIssuerPubkeyLen(usize),
    /// `outpoint_index` is outside the domain whose LE-4 encoding matches the
    /// on-chain `OpNum2Bin(4)` output.
    #[error("outpoint_index {0} must be < 2^31 to match on-chain OpNum2Bin(4)")]
    OutpointIndexTooLarge(u32),
    /// `amount` is outside the domain the engine accepts for `OpTxInputAmount`.
    #[error("amount {0} must be < 2^63 to match on-chain OpTxInputAmount")]
    AmountTooLarge(u64),
}

/// Validate that `bytes` is a 32-byte x-only Schnorr public key and return it
/// as a fixed array. Rejects 33-byte compressed keys (and any other length).
///
/// This is the guard the evaluation memo calls for: an issuer key embedded in
/// the covenant body must be strictly 32 bytes, or every transfer freezes
/// permanently. [`super::body::build_stablecoin_redeem_script`] takes a
/// `&[u8; 32]` so the type system already enforces this at that boundary;
/// this helper is for callers that start from raw / hex-decoded bytes whose
/// length is not known statically.
pub fn validate_x_only_pubkey(bytes: &[u8]) -> Result<[u8; X_ONLY_PUBKEY_LEN], StablecoinError> {
    <[u8; X_ONLY_PUBKEY_LEN]>::try_from(bytes).map_err(|_| StablecoinError::InvalidIssuerPubkeyLen(bytes.len()))
}

/// Check that `outpoint_index` / `amount` fall in the numeric domain for
/// which this module's fixed-width LE encoding matches the on-chain
/// `OpNum2Bin` output. Returns `Ok(())` in-domain; otherwise the specific
/// out-of-domain error. [`build_attestation_preimage`] and
/// [`build_attestation_message`] apply the same domain via `debug_assert!`;
/// use this helper for a hard, release-mode check.
pub fn check_numeric_domain(outpoint_index: u32, amount: u64) -> Result<(), StablecoinError> {
    if u64::from(outpoint_index) >= MAX_OUTPOINT_INDEX_EXCLUSIVE {
        return Err(StablecoinError::OutpointIndexTooLarge(outpoint_index));
    }
    if amount >= MAX_AMOUNT_EXCLUSIVE {
        return Err(StablecoinError::AmountTooLarge(amount));
    }
    Ok(())
}

/// The decoded fields of an attestation pre-image. `successor_spk_hash` is the
/// `Blake3` digest of the successor SPK (the pre-image commits the hash, not
/// the raw SPK, so decoding cannot recover the original SPK bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationFields {
    pub domain_tag: [u8; DOMAIN_TAG_LEN],
    pub covenant_id: [u8; COVENANT_ID_LEN],
    pub outpoint_txid: [u8; OUTPOINT_TXID_LEN],
    pub outpoint_index: u32,
    pub successor_spk_hash: [u8; SUCCESSOR_SPK_HASH_LEN],
    pub amount: u64,
}

/// Build the 116-byte issuer-attestation pre-image (the bytes that are
/// `Blake3`-hashed to form the signed message). `successor_spk` is the
/// successor output's raw `ScriptPublicKey::to_bytes()` form; it is hashed
/// with `Blake3` here to produce the 32-byte `successor_spk_hash` field,
/// mirroring the body's `OpTxOutputSpk OpBlake3`.
///
/// In debug builds this asserts the numeric domain (`outpoint_index < 2^31`,
/// `amount < 2^63`); [`check_numeric_domain`] gives a release-mode check.
pub fn build_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
) -> [u8; ATTESTATION_PREIMAGE_LEN] {
    debug_assert!(
        u64::from(outpoint_index) < MAX_OUTPOINT_INDEX_EXCLUSIVE,
        "outpoint_index must be < 2^31 to match on-chain OpNum2Bin(4)"
    );
    debug_assert!(amount < MAX_AMOUNT_EXCLUSIVE, "amount must be < 2^63 to match on-chain OpTxInputAmount");

    let successor_spk_hash = *blake3::hash(successor_spk).as_bytes();

    let mut out = [0u8; ATTESTATION_PREIMAGE_LEN];
    out[OFFSET_DOMAIN_TAG..OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN].copy_from_slice(&DOMAIN_TAG);
    out[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + COVENANT_ID_LEN].copy_from_slice(covenant_id);
    out[OFFSET_OUTPOINT_TXID..OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN].copy_from_slice(outpoint_txid);
    out[OFFSET_OUTPOINT_INDEX..OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN]
        .copy_from_slice(&outpoint_index.to_le_bytes());
    out[OFFSET_SUCCESSOR_SPK_HASH..OFFSET_SUCCESSOR_SPK_HASH + SUCCESSOR_SPK_HASH_LEN]
        .copy_from_slice(&successor_spk_hash);
    out[OFFSET_AMOUNT..OFFSET_AMOUNT + AMOUNT_LEN].copy_from_slice(&amount.to_le_bytes());
    out
}

/// Build the 32-byte issuer-attestation message: `Blake3(pre-image)`. This is
/// exactly the digest the body's final `OpBlake3` produces and feeds to
/// `OpCheckSigFromStack`; the issuer signs this with a raw (message-hash)
/// Schnorr signature.
pub fn build_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
) -> [u8; 32] {
    let preimage = build_attestation_preimage(covenant_id, outpoint_txid, outpoint_index, successor_spk, amount);
    *blake3::hash(&preimage).as_bytes()
}

/// Decode a 116-byte pre-image back into its fields (the *Reader* side used
/// for round-trip conformance testing of field order and fixed widths).
/// Returns `None` on any length mismatch.
pub fn decode_attestation_preimage(bytes: &[u8]) -> Option<AttestationFields> {
    if bytes.len() != ATTESTATION_PREIMAGE_LEN {
        return None;
    }
    let mut domain_tag = [0u8; DOMAIN_TAG_LEN];
    domain_tag.copy_from_slice(&bytes[OFFSET_DOMAIN_TAG..OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN]);
    let mut covenant_id = [0u8; COVENANT_ID_LEN];
    covenant_id.copy_from_slice(&bytes[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + COVENANT_ID_LEN]);
    let mut outpoint_txid = [0u8; OUTPOINT_TXID_LEN];
    outpoint_txid.copy_from_slice(&bytes[OFFSET_OUTPOINT_TXID..OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN]);
    let mut idx_bytes = [0u8; OUTPOINT_INDEX_LEN];
    idx_bytes.copy_from_slice(&bytes[OFFSET_OUTPOINT_INDEX..OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN]);
    let outpoint_index = u32::from_le_bytes(idx_bytes);
    let mut successor_spk_hash = [0u8; SUCCESSOR_SPK_HASH_LEN];
    successor_spk_hash.copy_from_slice(&bytes[OFFSET_SUCCESSOR_SPK_HASH..OFFSET_SUCCESSOR_SPK_HASH + SUCCESSOR_SPK_HASH_LEN]);
    let mut amt_bytes = [0u8; AMOUNT_LEN];
    amt_bytes.copy_from_slice(&bytes[OFFSET_AMOUNT..OFFSET_AMOUNT + AMOUNT_LEN]);
    let amount = u64::from_le_bytes(amt_bytes);
    Some(AttestationFields { domain_tag, covenant_id, outpoint_txid, outpoint_index, successor_spk_hash, amount })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spk() -> Vec<u8> {
        // A stand-in ScriptPublicKey::to_bytes() form: version 0 (2 BE bytes)
        // + a 35-byte P2SH script `aa 20 <32> 87`. The exact bytes don't
        // matter here (we only Blake3 them); the length (37) does not, either.
        let mut spk = vec![0x00, 0x00, 0xaa, 0x20];
        spk.extend_from_slice(&[0x5c; 32]);
        spk.push(0x87);
        spk
    }

    #[test]
    fn preimage_len_and_offsets_are_pinned() {
        assert_eq!(ATTESTATION_PREIMAGE_LEN, 116);
        assert_eq!(OFFSET_DOMAIN_TAG, 0);
        assert_eq!(OFFSET_COVENANT_ID, 8);
        assert_eq!(OFFSET_OUTPOINT_TXID, 40);
        assert_eq!(OFFSET_OUTPOINT_INDEX, 72);
        assert_eq!(OFFSET_SUCCESSOR_SPK_HASH, 76);
        assert_eq!(OFFSET_AMOUNT, 108);
        assert_eq!(OFFSET_AMOUNT + AMOUNT_LEN, ATTESTATION_PREIMAGE_LEN);
    }

    #[test]
    fn preimage_field_widths_and_domain_tag_placement() {
        let cov = [0x11u8; 32];
        let txid = [0x22u8; 32];
        let spk = sample_spk();
        let pre = build_attestation_preimage(&cov, &txid, 7, &spk, 1_000_000);
        assert_eq!(pre.len(), 116);
        // domain tag is the leading 8 bytes, verbatim.
        assert_eq!(&pre[0..8], &DOMAIN_TAG);
        // covenant_id / txid land raw at their offsets.
        assert_eq!(&pre[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + 32], &cov);
        assert_eq!(&pre[OFFSET_OUTPOINT_TXID..OFFSET_OUTPOINT_TXID + 32], &txid);
        // index is 4-byte LE, amount is 8-byte LE.
        assert_eq!(&pre[OFFSET_OUTPOINT_INDEX..OFFSET_OUTPOINT_INDEX + 4], &7u32.to_le_bytes());
        assert_eq!(&pre[OFFSET_AMOUNT..OFFSET_AMOUNT + 8], &1_000_000u64.to_le_bytes());
        // successor_spk_hash is Blake3 of the raw SPK.
        assert_eq!(&pre[OFFSET_SUCCESSOR_SPK_HASH..OFFSET_SUCCESSOR_SPK_HASH + 32], blake3::hash(&spk).as_bytes());
    }

    #[test]
    fn preimage_decode_round_trip() {
        let cov = [0xa1u8; 32];
        let txid = [0xb2u8; 32];
        let spk = sample_spk();
        let idx = 3u32;
        let amount = 42_000_000_000u64;
        let pre = build_attestation_preimage(&cov, &txid, idx, &spk, amount);
        let decoded = decode_attestation_preimage(&pre).expect("decode");
        assert_eq!(decoded.domain_tag, DOMAIN_TAG);
        assert_eq!(decoded.covenant_id, cov);
        assert_eq!(decoded.outpoint_txid, txid);
        assert_eq!(decoded.outpoint_index, idx);
        assert_eq!(decoded.amount, amount);
        assert_eq!(decoded.successor_spk_hash, *blake3::hash(&spk).as_bytes());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode_attestation_preimage(&[0u8; 115]).is_none());
        assert!(decode_attestation_preimage(&[0u8; 117]).is_none());
        assert!(decode_attestation_preimage(&[]).is_none());
    }

    #[test]
    fn message_is_blake3_of_preimage() {
        let cov = [0x33u8; 32];
        let txid = [0x44u8; 32];
        let spk = sample_spk();
        let pre = build_attestation_preimage(&cov, &txid, 1, &spk, 500);
        let msg = build_attestation_message(&cov, &txid, 1, &spk, 500);
        assert_eq!(msg, *blake3::hash(&pre).as_bytes());
    }

    #[test]
    fn message_is_deterministic_and_field_sensitive() {
        let cov = [0x01u8; 32];
        let txid = [0x02u8; 32];
        let spk = sample_spk();
        let base = build_attestation_message(&cov, &txid, 1, &spk, 100);
        assert_eq!(base, build_attestation_message(&cov, &txid, 1, &spk, 100));
        // flipping any field changes the message (replay-binding sanity).
        let mut cov2 = cov;
        cov2[0] ^= 0xff;
        assert_ne!(base, build_attestation_message(&cov2, &txid, 1, &spk, 100));
        let mut txid2 = txid;
        txid2[0] ^= 0xff;
        assert_ne!(base, build_attestation_message(&cov, &txid2, 1, &spk, 100));
        assert_ne!(base, build_attestation_message(&cov, &txid, 2, &spk, 100));
        assert_ne!(base, build_attestation_message(&cov, &txid, 1, &spk, 101));
        let mut spk2 = spk.clone();
        spk2[4] ^= 0xff;
        assert_ne!(base, build_attestation_message(&cov, &txid, 1, &spk2, 100));
    }

    #[test]
    fn validate_x_only_pubkey_accepts_32_rejects_others() {
        assert_eq!(validate_x_only_pubkey(&[0x07u8; 32]).unwrap(), [0x07u8; 32]);
        // 33-byte compressed key is the brick case — must be rejected.
        assert_eq!(validate_x_only_pubkey(&[0x02u8; 33]), Err(StablecoinError::InvalidIssuerPubkeyLen(33)));
        assert_eq!(validate_x_only_pubkey(&[0u8; 31]), Err(StablecoinError::InvalidIssuerPubkeyLen(31)));
        assert_eq!(validate_x_only_pubkey(&[]), Err(StablecoinError::InvalidIssuerPubkeyLen(0)));
    }

    #[test]
    fn numeric_domain_bounds() {
        assert!(check_numeric_domain(0, 0).is_ok());
        assert!(check_numeric_domain((MAX_OUTPOINT_INDEX_EXCLUSIVE - 1) as u32, MAX_AMOUNT_EXCLUSIVE - 1).is_ok());
        assert_eq!(
            check_numeric_domain(MAX_OUTPOINT_INDEX_EXCLUSIVE as u32, 0),
            Err(StablecoinError::OutpointIndexTooLarge(MAX_OUTPOINT_INDEX_EXCLUSIVE as u32))
        );
        assert_eq!(
            check_numeric_domain(0, MAX_AMOUNT_EXCLUSIVE),
            Err(StablecoinError::AmountTooLarge(MAX_AMOUNT_EXCLUSIVE))
        );
    }

    #[test]
    fn domain_tag_is_eight_bytes() {
        assert_eq!(DOMAIN_TAG.len(), DOMAIN_TAG_LEN);
    }
}
