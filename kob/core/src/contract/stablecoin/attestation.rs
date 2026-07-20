//! Canonical issuer-attestation pre-image encoder for the robust KCC-0020
//! stablecoin covenant (`STABLECOIN_ROBUST_DESIGN.md` §4/§5).
//!
//! This is the *Writer* side of the attestation gate: the off-chain role
//! signer (OPS for TRANSFER; FREEZE/SEIZE/MINT/ROTATE for their own branches
//! in Phase II) builds the pre-image with [`build_attestation_preimage`],
//! signs `Blake3(pre-image)` (== [`build_attestation_message`]) with the
//! role's x-only Schnorr key, and hands the raw 64-byte signature to the
//! spender. On-chain, [`super::body`] reconstructs the identical pre-image
//! from transaction introspection (plus, for `op_type` and `epoch`, values
//! already sitting on the data stack from the state header) and
//! `OpCheckSigFromStack`-verifies the signature.
//!
//! The two sides MUST agree byte-for-byte. This module is the single source
//! of truth for the field **order** and each field's **fixed width**; the
//! body's conformance tests cross-check its emitted opcode sequence against
//! the constants defined here.
//!
//! # Message composition (121-byte BASE pre-image, then Blake3 → 32-byte
//! message)
//!
//! ```text
//! Blake3(
//!     DOMAIN_TAG           (8B  constant, network-scoped — super::DOMAIN_TAG)
//!  || covenant_id          (32B raw, on-chain: OpTxInputIndex OpInputCovenantId)
//!  || op_type              (1B  constant per branch, e.g. 0x00 TRANSFER)
//!  || epoch                (4B  LE, on-chain: already on the data stack from
//!                                the state header -- this coin's CURRENT
//!                                epoch, not attacker-suppliable)
//!  || outpoint_txid        (32B raw, on-chain: OpTxInputIndex OpOutpointTxId)
//!  || outpoint_index       (4B  LE,  on-chain: OpTxInputIndex OpOutpointIndex OpNum2Bin(4))
//!  || successor_spk_hash   (32B,     on-chain: OpTxInputIndex OpTxOutputSpk OpBlake3)
//!  || amount               (8B  LE,  on-chain: OpTxInputIndex OpTxInputAmount OpNum2Bin(8))
//! )
//! ```
//!
//! This extends case-A's 116-byte pre-image (`DOMAIN_TAG || covenant_id ||
//! outpoint_txid || outpoint_index || successor_spk_hash || amount`) by
//! splicing in `op_type(1)` and `epoch(4)` right after `covenant_id` (§4: "121B
//! base (before op-specific fields)"). Per-branch op-specific tails (§5, e.g.
//! FREEZE's `new_frozen_flag(1)`) are NOT implemented in Phase I (TRANSFER's
//! tail is empty, so TRANSFER's total preimage length equals the 121B base) --
//! see `body.rs` module doc for the Phase I/Phase II split.
//!
//! - Every input-side introspection index is sourced from `OpTxInputIndex`
//!   (never an immediate), so the pre-image is bound to *this* input's spend
//!   and cannot be replayed for a different input. `covenant_id` +
//!   `outpoint_txid` + `outpoint_index` together pin the exact UTXO being
//!   spent (replay protection, unchanged from case-A).
//! - `op_type` inside the message prevents cross-branch replay (§6): an
//!   attestation minted for one op_type cannot be replayed as another.
//! - `epoch` inside the message, reconstructed on-chain from the coin's OWN
//!   current state (not from attacker-suppliable data), means a stale
//!   attestation signed under a pre-ROTATE epoch is rejected on any coin that
//!   has since been rotated (§6). Phase I never changes epoch (ROTATE is
//!   Phase II), but the field is wired now so Phase II doesn't require an
//!   attestation-format break.
//! - `successor_spk_hash` is `Blake3` of the successor output's
//!   `ScriptPublicKey::to_bytes()` form (version as 2 big-endian bytes,
//!   followed by the script) — this is exactly what `OpTxOutputSpk` pushes
//!   before the body's `OpBlake3`. Callers pass the raw SPK bytes; this
//!   module hashes them.
//! - The `outpoint_index` (4B) and `amount` (8B) fixed-width encodings are
//!   plain little-endian, byte-identical to the engine's `OpNum2Bin(size)`
//!   output for the accepted numeric domain: `outpoint_index < 2^31` and
//!   `amount < 2^63` (`check_numeric_domain`).

use super::DOMAIN_TAG;

/// Width, in bytes, of the domain tag field.
pub const DOMAIN_TAG_LEN: usize = 8;
/// Width, in bytes, of the covenant id field.
pub const COVENANT_ID_LEN: usize = 32;
/// Width, in bytes, of the `op_type` discriminant field (new, §4).
pub const OP_TYPE_LEN: usize = 1;
/// Width, in bytes, of the `epoch` field (new, §4; LE).
pub const EPOCH_LEN: usize = 4;
/// Width, in bytes, of the spent outpoint's transaction id field.
pub const OUTPOINT_TXID_LEN: usize = 32;
/// Width, in bytes, of the spent outpoint's index field (fixed via `OpNum2Bin`).
pub const OUTPOINT_INDEX_LEN: usize = 4;
/// Width, in bytes, of the successor scriptPublicKey hash field.
pub const SUCCESSOR_SPK_HASH_LEN: usize = 32;
/// Width, in bytes, of the amount field (fixed via `OpNum2Bin`).
pub const AMOUNT_LEN: usize = 8;

/// Byte offset of each field inside the BASE pre-image (see module doc for
/// order). Op-specific tail fields (§5), where implemented, are appended
/// starting at `ATTESTATION_PREIMAGE_LEN`.
pub const OFFSET_DOMAIN_TAG: usize = 0;
pub const OFFSET_COVENANT_ID: usize = OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN; // 8
pub const OFFSET_OP_TYPE: usize = OFFSET_COVENANT_ID + COVENANT_ID_LEN; // 40
pub const OFFSET_EPOCH: usize = OFFSET_OP_TYPE + OP_TYPE_LEN; // 41
pub const OFFSET_OUTPOINT_TXID: usize = OFFSET_EPOCH + EPOCH_LEN; // 45
pub const OFFSET_OUTPOINT_INDEX: usize = OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN; // 77
pub const OFFSET_SUCCESSOR_SPK_HASH: usize = OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN; // 81
pub const OFFSET_AMOUNT: usize = OFFSET_SUCCESSOR_SPK_HASH + SUCCESSOR_SPK_HASH_LEN; // 113

/// Total BASE pre-image length: `8+32+1+4+32+4+32+8 = 121` bytes (§4).
pub const ATTESTATION_PREIMAGE_LEN: usize = OFFSET_AMOUNT + AMOUNT_LEN;

/// Length of an x-only Schnorr public key (role key), in bytes.
pub const X_ONLY_PUBKEY_LEN: usize = 32;

/// `op_type` discriminant byte values (§4 branch table). `0x04` is
/// intentionally absent/reserved -- MINT lives in a separate, self-continuing
/// mint-authority contract (§9) and never attests against this covenant.
pub mod op_type {
    pub const TRANSFER: u8 = 0x00;
    pub const FREEZE: u8 = 0x01;
    pub const SEIZE: u8 = 0x02;
    pub const BURN: u8 = 0x03;
    // 0x04 reserved -- separate mint-authority contract, not this covenant.
    pub const ROTATE: u8 = 0x05;
    pub const MIGRATE: u8 = 0x06;
    /// N:M transfer (G1, split/merge) leader -- does ALL group bookkeeping
    /// for its covenant-id lineage. See `super::dispatch`'s module doc and
    /// the N:M design note above [`build_transfer_nm_attestation_preimage`].
    pub const TRANSFER_NM: u8 = 0x07;
    /// N:M transfer (G1) delegator -- self-authorizes only; does not
    /// re-verify the group attestation (the leader's script, unavoidably
    /// present in the same tx, carries it).
    pub const TRANSFER_NM_DELEGATOR: u8 = 0x08;
}

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
    #[error("role pubkey must be {X_ONLY_PUBKEY_LEN} bytes (x-only), got {0}")]
    InvalidRolePubkeyLen(usize),
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
pub fn validate_x_only_pubkey(bytes: &[u8]) -> Result<[u8; X_ONLY_PUBKEY_LEN], StablecoinError> {
    <[u8; X_ONLY_PUBKEY_LEN]>::try_from(bytes).map_err(|_| StablecoinError::InvalidRolePubkeyLen(bytes.len()))
}

/// Check that `outpoint_index` / `amount` fall in the numeric domain for
/// which this module's fixed-width LE encoding matches the on-chain
/// `OpNum2Bin` output. Returns `Ok(())` in-domain; otherwise the specific
/// out-of-domain error.
pub fn check_numeric_domain(outpoint_index: u32, amount: u64) -> Result<(), StablecoinError> {
    if u64::from(outpoint_index) >= MAX_OUTPOINT_INDEX_EXCLUSIVE {
        return Err(StablecoinError::OutpointIndexTooLarge(outpoint_index));
    }
    if amount >= MAX_AMOUNT_EXCLUSIVE {
        return Err(StablecoinError::AmountTooLarge(amount));
    }
    Ok(())
}

/// The decoded fields of a BASE attestation pre-image (no op-specific tail).
/// `successor_spk_hash` is the `Blake3` digest of the successor SPK (the
/// pre-image commits the hash, not the raw SPK, so decoding cannot recover
/// the original SPK bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationFields {
    pub domain_tag: [u8; DOMAIN_TAG_LEN],
    pub covenant_id: [u8; COVENANT_ID_LEN],
    pub op_type: u8,
    pub epoch: u32,
    pub outpoint_txid: [u8; OUTPOINT_TXID_LEN],
    pub outpoint_index: u32,
    pub successor_spk_hash: [u8; SUCCESSOR_SPK_HASH_LEN],
    pub amount: u64,
}

/// Build the 121-byte BASE issuer-attestation pre-image (the bytes that are
/// `Blake3`-hashed to form the signed message, for op_types with an empty
/// tail -- Phase I's TRANSFER (`0x00`) is the only wired one).
/// `successor_spk` is the successor output's raw `ScriptPublicKey::to_bytes()`
/// form; it is hashed with `Blake3` here to produce the 32-byte
/// `successor_spk_hash` field, mirroring the body's `OpTxOutputSpk OpBlake3`.
///
/// In debug builds this asserts the numeric domain (`outpoint_index < 2^31`,
/// `amount < 2^63`); [`check_numeric_domain`] gives a release-mode check.
#[allow(clippy::too_many_arguments)]
pub fn build_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    op_type: u8,
    epoch: u32,
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
    out[OFFSET_OP_TYPE] = op_type;
    out[OFFSET_EPOCH..OFFSET_EPOCH + EPOCH_LEN].copy_from_slice(&epoch.to_le_bytes());
    out[OFFSET_OUTPOINT_TXID..OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN].copy_from_slice(outpoint_txid);
    out[OFFSET_OUTPOINT_INDEX..OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN]
        .copy_from_slice(&outpoint_index.to_le_bytes());
    out[OFFSET_SUCCESSOR_SPK_HASH..OFFSET_SUCCESSOR_SPK_HASH + SUCCESSOR_SPK_HASH_LEN]
        .copy_from_slice(&successor_spk_hash);
    out[OFFSET_AMOUNT..OFFSET_AMOUNT + AMOUNT_LEN].copy_from_slice(&amount.to_le_bytes());
    out
}

/// Build the 32-byte attestation message: `Blake3(pre-image)`. This is
/// exactly the digest the body's final `OpBlake3` produces and feeds to
/// `OpCheckSigFromStack`; the role signer signs this with a raw
/// (message-hash) Schnorr signature.
#[allow(clippy::too_many_arguments)]
pub fn build_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    op_type: u8,
    epoch: u32,
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
) -> [u8; 32] {
    let preimage = build_attestation_preimage(covenant_id, op_type, epoch, outpoint_txid, outpoint_index, successor_spk, amount);
    *blake3::hash(&preimage).as_bytes()
}

/// Width, in bytes, of FREEZE's op-specific preimage tail field
/// (`new_frozen_flag`, §5).
pub const NEW_FROZEN_FLAG_LEN: usize = 1;

/// Byte offset of `new_frozen_flag` inside the FREEZE preimage (immediately
/// after the 121-byte BASE prefix, §5).
pub const OFFSET_NEW_FROZEN_FLAG: usize = ATTESTATION_PREIMAGE_LEN;

/// Total FREEZE pre-image length: 121B base + `new_frozen_flag(1)` = 122
/// bytes (§5).
pub const FREEZE_PREIMAGE_LEN: usize = ATTESTATION_PREIMAGE_LEN + NEW_FROZEN_FLAG_LEN;

/// Build the 122-byte FREEZE issuer-attestation pre-image: the 121-byte BASE
/// pre-image (`op_type` fixed to [`op_type::FREEZE`]) with `new_frozen_flag(1)`
/// appended (§4/§5). `successor_spk` is the successor output's raw
/// `ScriptPublicKey::to_bytes()` form, hashed here exactly as
/// [`build_attestation_preimage`] does for the BASE prefix.
#[allow(clippy::too_many_arguments)]
pub fn build_freeze_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
    new_frozen_flag: u8,
) -> [u8; FREEZE_PREIMAGE_LEN] {
    let base = build_attestation_preimage(covenant_id, op_type::FREEZE, epoch, outpoint_txid, outpoint_index, successor_spk, amount);
    let mut out = [0u8; FREEZE_PREIMAGE_LEN];
    out[..ATTESTATION_PREIMAGE_LEN].copy_from_slice(&base);
    out[OFFSET_NEW_FROZEN_FLAG] = new_frozen_flag;
    out
}

/// Build the 32-byte FREEZE attestation message: `Blake3(pre-image)` (§5).
/// This is exactly the digest the body's FREEZE branch reconstructs and feeds
/// to `OpCheckSigFromStack`; the FREEZE role signs this with a raw
/// (message-hash) Schnorr signature.
#[allow(clippy::too_many_arguments)]
pub fn build_freeze_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
    new_frozen_flag: u8,
) -> [u8; 32] {
    let preimage = build_freeze_attestation_preimage(covenant_id, epoch, outpoint_txid, outpoint_index, successor_spk, amount, new_frozen_flag);
    *blake3::hash(&preimage).as_bytes()
}

/// Width, in bytes, of SEIZE's op-specific preimage tail field
/// (`new_owner_pubkey`, §5).
pub const NEW_OWNER_PUBKEY_LEN: usize = 32;

/// Byte offset of `new_owner_pubkey` inside the SEIZE preimage (immediately
/// after the 121-byte BASE prefix, §5).
pub const OFFSET_NEW_OWNER_PUBKEY: usize = ATTESTATION_PREIMAGE_LEN;

/// Total SEIZE pre-image length: 121B base + `new_owner_pubkey(32)` = 153
/// bytes (§5).
pub const SEIZE_PREIMAGE_LEN: usize = ATTESTATION_PREIMAGE_LEN + NEW_OWNER_PUBKEY_LEN;

/// Build the 153-byte SEIZE issuer-attestation pre-image: the 121-byte BASE
/// pre-image (`op_type` fixed to [`op_type::SEIZE`]) with `new_owner_pubkey(32)`
/// appended (§4/§5). `successor_spk` is the successor output's raw
/// `ScriptPublicKey::to_bytes()` form, hashed here exactly as
/// [`build_attestation_preimage`] does for the BASE prefix.
#[allow(clippy::too_many_arguments)]
pub fn build_seize_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
    new_owner_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
) -> [u8; SEIZE_PREIMAGE_LEN] {
    let base = build_attestation_preimage(covenant_id, op_type::SEIZE, epoch, outpoint_txid, outpoint_index, successor_spk, amount);
    let mut out = [0u8; SEIZE_PREIMAGE_LEN];
    out[..ATTESTATION_PREIMAGE_LEN].copy_from_slice(&base);
    out[OFFSET_NEW_OWNER_PUBKEY..OFFSET_NEW_OWNER_PUBKEY + NEW_OWNER_PUBKEY_LEN].copy_from_slice(new_owner_pubkey);
    out
}

/// Build the 32-byte SEIZE attestation message: `Blake3(pre-image)` (§5).
/// This is exactly the digest the body's SEIZE branch reconstructs and feeds
/// to `OpCheckSigFromStack` (three times, once per candidate signature slot
/// in the 2-of-3 quorum -- see `body.rs`'s `build_seize_branch` doc); each
/// SEIZE-role signer signs this with a raw (message-hash) Schnorr signature.
#[allow(clippy::too_many_arguments)]
pub fn build_seize_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
    new_owner_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
) -> [u8; 32] {
    let preimage =
        build_seize_attestation_preimage(covenant_id, epoch, outpoint_txid, outpoint_index, successor_spk, amount, new_owner_pubkey);
    *blake3::hash(&preimage).as_bytes()
}

/// Width, in bytes, of MIGRATE's op-specific preimage tail field
/// (`new_template_hash`, §5).
pub const NEW_TEMPLATE_HASH_LEN: usize = 32;

/// Byte offset of `new_template_hash` inside the MIGRATE preimage
/// (immediately after the 121-byte BASE prefix, §5).
pub const OFFSET_NEW_TEMPLATE_HASH: usize = ATTESTATION_PREIMAGE_LEN;

/// Total MIGRATE pre-image length: 121B base + `new_template_hash(32)` = 153
/// bytes (§5) -- the same total length as SEIZE's preimage (both tails happen
/// to be 32 bytes), but a semantically distinct field.
pub const MIGRATE_PREIMAGE_LEN: usize = ATTESTATION_PREIMAGE_LEN + NEW_TEMPLATE_HASH_LEN;

/// Build the 153-byte MIGRATE issuer-attestation pre-image: the 121-byte BASE
/// pre-image (`op_type` fixed to [`op_type::MIGRATE`]) with
/// `new_template_hash(32)` appended (§4/§5). `successor_spk` is the successor
/// output's raw `ScriptPublicKey::to_bytes()` form, hashed here exactly as
/// [`build_attestation_preimage`] does for the BASE prefix (this is the SAME
/// successor output MIGRATE moves the coin to -- there is only one output
/// here, unlike a hypothetical split; §4's 1:1 successor-binding convention
/// is unchanged). `new_template_hash` is the caller-supplied `Blake3` digest
/// of that successor's SPK bytes -- callers MUST pass
/// `Blake3(successor_spk)` (the same hash [`build_attestation_preimage`]
/// computes internally for `successor_spk_hash`) so the OPS role's signature
/// commits to the SPECIFIC migration target the body re-derives on-chain via
/// `OpTxOutputSpk`/`OpBlake3` (see `body.rs`'s `build_migrate_branch`). This
/// module does not re-derive it internally (unlike `successor_spk_hash`)
/// because the caller must be free to pass a MISMATCHED hash when testing the
/// on-chain successor-template-mismatch rejection path.
#[allow(clippy::too_many_arguments)]
pub fn build_migrate_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
    new_template_hash: &[u8; NEW_TEMPLATE_HASH_LEN],
) -> [u8; MIGRATE_PREIMAGE_LEN] {
    let base = build_attestation_preimage(covenant_id, op_type::MIGRATE, epoch, outpoint_txid, outpoint_index, successor_spk, amount);
    let mut out = [0u8; MIGRATE_PREIMAGE_LEN];
    out[..ATTESTATION_PREIMAGE_LEN].copy_from_slice(&base);
    out[OFFSET_NEW_TEMPLATE_HASH..OFFSET_NEW_TEMPLATE_HASH + NEW_TEMPLATE_HASH_LEN].copy_from_slice(new_template_hash);
    out
}

/// Build the 32-byte MIGRATE attestation message: `Blake3(pre-image)` (§5).
/// This is exactly the digest the body's MIGRATE branch reconstructs and
/// feeds to `OpCheckSigFromStack`; the OPS role (or, post-Live, the ROTATE
/// role -- see `body.rs`'s decision note) signs this with a raw
/// (message-hash) Schnorr signature.
#[allow(clippy::too_many_arguments)]
pub fn build_migrate_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    successor_spk: &[u8],
    amount: u64,
    new_template_hash: &[u8; NEW_TEMPLATE_HASH_LEN],
) -> [u8; 32] {
    let preimage =
        build_migrate_attestation_preimage(covenant_id, epoch, outpoint_txid, outpoint_index, successor_spk, amount, new_template_hash);
    *blake3::hash(&preimage).as_bytes()
}

/// Width, in bytes, of TRANSFER_NM's `n_in`/`n_out` group-cardinality fields
/// (§ N:M design -- the ACTUAL `OpCovInputCount`/`OpCovOutputCount` values,
/// i.e. `n_in` counts the leader AND every sibling, `n_out` counts every
/// successor).
pub const N_IN_LEN: usize = 1;
pub const N_OUT_LEN: usize = 1;
/// Width, in bytes, of each TRANSFER_NM group digest field
/// (`inputs_digest`/`outputs_digest`).
pub const GROUP_DIGEST_LEN: usize = 32;

/// Byte offsets inside the TRANSFER_NM (`0x07`) pre-image. This is **not**
/// [`build_attestation_preimage`]'s BASE layout plus a tail: BASE's
/// single-successor replay fields (`outpoint_txid`/`outpoint_index`/
/// `successor_spk_hash`/`amount`) have no well-defined meaning for a group of
/// up to `MAX_N+1` inputs and `MAX_N` outputs, so TRANSFER_NM REPLACES them
/// (starting right after `epoch`) with `n_in`/`n_out`/`inputs_digest`/
/// `outputs_digest` instead. Only the leading 45 bytes (`DOMAIN_TAG ||
/// covenant_id || op_type || epoch`) share BASE's field order/widths.
///
/// The leader's own outpoint/amount are deliberately NOT folded into
/// `inputs_digest` (siblings only, see [`build_transfer_nm_attestation_preimage`]'s
/// doc): the leader's own coin identity is already authenticated on-chain by
/// `dr_input_spk_check` (against `self_rs`) and by the owner's SIGHASH_ALL
/// signature (which commits the whole transaction, including this input's own
/// outpoint), so nothing about the OPS attestation needs to re-pin it.
pub const OFFSET_N_IN: usize = OFFSET_EPOCH + EPOCH_LEN; // 45
pub const OFFSET_N_OUT: usize = OFFSET_N_IN + N_IN_LEN; // 46
pub const OFFSET_INPUTS_DIGEST: usize = OFFSET_N_OUT + N_OUT_LEN; // 47
pub const OFFSET_OUTPUTS_DIGEST: usize = OFFSET_INPUTS_DIGEST + GROUP_DIGEST_LEN; // 79

/// Total TRANSFER_NM pre-image length: `45 + 1 + 1 + 32 + 32 = 111` bytes.
pub const TRANSFER_NM_PREIMAGE_LEN: usize = OFFSET_OUTPUTS_DIGEST + GROUP_DIGEST_LEN;

/// Build the 111-byte TRANSFER_NM issuer-attestation pre-image (see the
/// `OFFSET_*` constants' doc for the field layout). `inputs_digest` is
/// `Blake3` of the concatenation, in ascending sibling-slot order
/// (`s = 1..MAX_N`, guarded by `s < OpCovInputCount`), of each sibling's
/// `outpoint_txid(32B) || outpoint_index(4B LE) || amount(8B LE)` --
/// mirroring exactly what the on-chain leader body folds via `OpCat` before
/// `OpBlake3` (see [`fold_transfer_nm_inputs_digest`] for the off-chain
/// equivalent). `outputs_digest` is `Blake3` of the concatenation, in
/// ascending successor-slot order (`j = 1..MAX_N`, guarded by
/// `j <= OpCovOutputCount`), of each successor's raw SPK bytes
/// (`ScriptPublicKey::to_bytes()` form -- version(2B BE) || script; every
/// successor here is a P2SH stablecoin covenant so each entry is always
/// exactly 37 bytes, which is what makes concatenation-then-hash
/// boundary-safe) -- see [`fold_transfer_nm_outputs_digest`].
pub fn build_transfer_nm_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    n_in: u8,
    n_out: u8,
    inputs_digest: &[u8; GROUP_DIGEST_LEN],
    outputs_digest: &[u8; GROUP_DIGEST_LEN],
) -> [u8; TRANSFER_NM_PREIMAGE_LEN] {
    let mut out = [0u8; TRANSFER_NM_PREIMAGE_LEN];
    out[OFFSET_DOMAIN_TAG..OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN].copy_from_slice(&DOMAIN_TAG);
    out[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + COVENANT_ID_LEN].copy_from_slice(covenant_id);
    out[OFFSET_OP_TYPE] = op_type::TRANSFER_NM;
    out[OFFSET_EPOCH..OFFSET_EPOCH + EPOCH_LEN].copy_from_slice(&epoch.to_le_bytes());
    out[OFFSET_N_IN] = n_in;
    out[OFFSET_N_OUT] = n_out;
    out[OFFSET_INPUTS_DIGEST..OFFSET_INPUTS_DIGEST + GROUP_DIGEST_LEN].copy_from_slice(inputs_digest);
    out[OFFSET_OUTPUTS_DIGEST..OFFSET_OUTPUTS_DIGEST + GROUP_DIGEST_LEN].copy_from_slice(outputs_digest);
    out
}

/// Build the 32-byte TRANSFER_NM attestation message: `Blake3(pre-image)`.
/// This is exactly the digest the leader body's TRANSFER_NM branch
/// reconstructs and feeds to `OpCheckSigFromStack`; the OPS role signs this
/// with a raw (message-hash) Schnorr signature over the WHOLE group in one
/// signature (delegators do not re-verify it -- see the branch's doc in
/// `body.rs`).
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_nm_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    epoch: u32,
    n_in: u8,
    n_out: u8,
    inputs_digest: &[u8; GROUP_DIGEST_LEN],
    outputs_digest: &[u8; GROUP_DIGEST_LEN],
) -> [u8; 32] {
    let preimage = build_transfer_nm_attestation_preimage(covenant_id, epoch, n_in, n_out, inputs_digest, outputs_digest);
    *blake3::hash(&preimage).as_bytes()
}

/// Off-chain equivalent of the on-chain leader body's sibling-input folding
/// (see [`build_transfer_nm_attestation_preimage`]'s doc): `Blake3` of the
/// concatenation, in order, of each sibling's `outpoint_txid(32B) ||
/// outpoint_index(4B LE) || amount(8B LE)`. Callers pass siblings in the SAME
/// ascending covenant-input-slot order (`s = 1..`) the on-chain body
/// enumerates via `OpCovInputIdx` -- i.e. NOT including the leader's own
/// input.
pub fn fold_transfer_nm_inputs_digest(siblings: &[([u8; 32], u32, u64)]) -> [u8; GROUP_DIGEST_LEN] {
    let mut acc = Vec::with_capacity(siblings.len() * 44);
    for (outpoint_txid, outpoint_index, amount) in siblings {
        acc.extend_from_slice(outpoint_txid);
        acc.extend_from_slice(&outpoint_index.to_le_bytes());
        acc.extend_from_slice(&amount.to_le_bytes());
    }
    *blake3::hash(&acc).as_bytes()
}

/// Off-chain equivalent of the on-chain leader body's successor-output
/// folding (see [`build_transfer_nm_attestation_preimage`]'s doc): `Blake3`
/// of the concatenation, in order, of each successor's raw SPK bytes
/// (`ScriptPublicKey::to_bytes()` form). Callers pass successors in the SAME
/// ascending covenant-output-slot order (`j = 1..`) the on-chain body
/// enumerates via `OpCovOutputIdx`.
pub fn fold_transfer_nm_outputs_digest(successor_spks: &[Vec<u8>]) -> [u8; GROUP_DIGEST_LEN] {
    let mut acc = Vec::new();
    for spk in successor_spks {
        acc.extend_from_slice(spk);
    }
    *blake3::hash(&acc).as_bytes()
}

/// Decode a 121-byte BASE pre-image back into its fields (the *Reader* side
/// used for round-trip conformance testing of field order and fixed widths).
/// Returns `None` on any length mismatch.
pub fn decode_attestation_preimage(bytes: &[u8]) -> Option<AttestationFields> {
    if bytes.len() != ATTESTATION_PREIMAGE_LEN {
        return None;
    }
    let mut domain_tag = [0u8; DOMAIN_TAG_LEN];
    domain_tag.copy_from_slice(&bytes[OFFSET_DOMAIN_TAG..OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN]);
    let mut covenant_id = [0u8; COVENANT_ID_LEN];
    covenant_id.copy_from_slice(&bytes[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + COVENANT_ID_LEN]);
    let op_type = bytes[OFFSET_OP_TYPE];
    let mut epoch_bytes = [0u8; EPOCH_LEN];
    epoch_bytes.copy_from_slice(&bytes[OFFSET_EPOCH..OFFSET_EPOCH + EPOCH_LEN]);
    let epoch = u32::from_le_bytes(epoch_bytes);
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
    Some(AttestationFields {
        domain_tag,
        covenant_id,
        op_type,
        epoch,
        outpoint_txid,
        outpoint_index,
        successor_spk_hash,
        amount,
    })
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
        assert_eq!(ATTESTATION_PREIMAGE_LEN, 121);
        assert_eq!(OFFSET_DOMAIN_TAG, 0);
        assert_eq!(OFFSET_COVENANT_ID, 8);
        assert_eq!(OFFSET_OP_TYPE, 40);
        assert_eq!(OFFSET_EPOCH, 41);
        assert_eq!(OFFSET_OUTPOINT_TXID, 45);
        assert_eq!(OFFSET_OUTPOINT_INDEX, 77);
        assert_eq!(OFFSET_SUCCESSOR_SPK_HASH, 81);
        assert_eq!(OFFSET_AMOUNT, 113);
        assert_eq!(OFFSET_AMOUNT + AMOUNT_LEN, ATTESTATION_PREIMAGE_LEN);
    }

    #[test]
    fn preimage_field_widths_and_domain_tag_placement() {
        let cov = [0x11u8; 32];
        let txid = [0x22u8; 32];
        let spk = sample_spk();
        let pre = build_attestation_preimage(&cov, op_type::TRANSFER, 7, &txid, 7, &spk, 1_000_000);
        assert_eq!(pre.len(), 121);
        assert_eq!(&pre[0..8], &DOMAIN_TAG);
        assert_eq!(&pre[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + 32], &cov);
        assert_eq!(pre[OFFSET_OP_TYPE], op_type::TRANSFER);
        assert_eq!(&pre[OFFSET_EPOCH..OFFSET_EPOCH + 4], &7u32.to_le_bytes());
        assert_eq!(&pre[OFFSET_OUTPOINT_TXID..OFFSET_OUTPOINT_TXID + 32], &txid);
        assert_eq!(&pre[OFFSET_OUTPOINT_INDEX..OFFSET_OUTPOINT_INDEX + 4], &7u32.to_le_bytes());
        assert_eq!(&pre[OFFSET_AMOUNT..OFFSET_AMOUNT + 8], &1_000_000u64.to_le_bytes());
        assert_eq!(&pre[OFFSET_SUCCESSOR_SPK_HASH..OFFSET_SUCCESSOR_SPK_HASH + 32], blake3::hash(&spk).as_bytes());
    }

    #[test]
    fn preimage_decode_round_trip() {
        let cov = [0xa1u8; 32];
        let txid = [0xb2u8; 32];
        let spk = sample_spk();
        let idx = 3u32;
        let amount = 42_000_000_000u64;
        let pre = build_attestation_preimage(&cov, op_type::TRANSFER, 99, &txid, idx, &spk, amount);
        let decoded = decode_attestation_preimage(&pre).expect("decode");
        assert_eq!(decoded.domain_tag, DOMAIN_TAG);
        assert_eq!(decoded.covenant_id, cov);
        assert_eq!(decoded.op_type, op_type::TRANSFER);
        assert_eq!(decoded.epoch, 99);
        assert_eq!(decoded.outpoint_txid, txid);
        assert_eq!(decoded.outpoint_index, idx);
        assert_eq!(decoded.amount, amount);
        assert_eq!(decoded.successor_spk_hash, *blake3::hash(&spk).as_bytes());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode_attestation_preimage(&[0u8; 120]).is_none());
        assert!(decode_attestation_preimage(&[0u8; 122]).is_none());
        assert!(decode_attestation_preimage(&[]).is_none());
    }

    #[test]
    fn message_is_blake3_of_preimage() {
        let cov = [0x33u8; 32];
        let txid = [0x44u8; 32];
        let spk = sample_spk();
        let pre = build_attestation_preimage(&cov, op_type::TRANSFER, 1, &txid, 1, &spk, 500);
        let msg = build_attestation_message(&cov, op_type::TRANSFER, 1, &txid, 1, &spk, 500);
        assert_eq!(msg, *blake3::hash(&pre).as_bytes());
    }

    #[test]
    fn message_is_deterministic_and_field_sensitive() {
        let cov = [0x01u8; 32];
        let txid = [0x02u8; 32];
        let spk = sample_spk();
        let base = build_attestation_message(&cov, op_type::TRANSFER, 5, &txid, 1, &spk, 100);
        assert_eq!(base, build_attestation_message(&cov, op_type::TRANSFER, 5, &txid, 1, &spk, 100));
        // flipping any field changes the message (replay-binding sanity).
        let mut cov2 = cov;
        cov2[0] ^= 0xff;
        assert_ne!(base, build_attestation_message(&cov2, op_type::TRANSFER, 5, &txid, 1, &spk, 100));
        assert_ne!(base, build_attestation_message(&cov, op_type::FREEZE, 5, &txid, 1, &spk, 100));
        assert_ne!(base, build_attestation_message(&cov, op_type::TRANSFER, 6, &txid, 1, &spk, 100));
        let mut txid2 = txid;
        txid2[0] ^= 0xff;
        assert_ne!(base, build_attestation_message(&cov, op_type::TRANSFER, 5, &txid2, 1, &spk, 100));
        assert_ne!(base, build_attestation_message(&cov, op_type::TRANSFER, 5, &txid, 2, &spk, 100));
        assert_ne!(base, build_attestation_message(&cov, op_type::TRANSFER, 5, &txid, 1, &spk, 101));
        let mut spk2 = spk.clone();
        spk2[4] ^= 0xff;
        assert_ne!(base, build_attestation_message(&cov, op_type::TRANSFER, 5, &txid, 1, &spk2, 100));
    }

    #[test]
    fn validate_x_only_pubkey_accepts_32_rejects_others() {
        assert_eq!(validate_x_only_pubkey(&[0x07u8; 32]).unwrap(), [0x07u8; 32]);
        // 33-byte compressed key is the brick case — must be rejected.
        assert_eq!(validate_x_only_pubkey(&[0x02u8; 33]), Err(StablecoinError::InvalidRolePubkeyLen(33)));
        assert_eq!(validate_x_only_pubkey(&[0u8; 31]), Err(StablecoinError::InvalidRolePubkeyLen(31)));
        assert_eq!(validate_x_only_pubkey(&[]), Err(StablecoinError::InvalidRolePubkeyLen(0)));
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

    #[test]
    fn freeze_preimage_len_and_tail_offset() {
        assert_eq!(FREEZE_PREIMAGE_LEN, 122);
        assert_eq!(OFFSET_NEW_FROZEN_FLAG, 121);
    }

    #[test]
    fn freeze_preimage_matches_base_prefix_plus_flag_tail() {
        let cov = [0x55u8; 32];
        let txid = [0x66u8; 32];
        let spk = sample_spk();
        let base = build_attestation_preimage(&cov, op_type::FREEZE, 3, &txid, 2, &spk, 777);
        let freeze = build_freeze_attestation_preimage(&cov, 3, &txid, 2, &spk, 777, 1);
        assert_eq!(freeze.len(), 122);
        assert_eq!(&freeze[..121], &base[..]);
        assert_eq!(freeze[121], 1);
        assert_eq!(freeze[OFFSET_OP_TYPE], op_type::FREEZE);
    }

    #[test]
    fn freeze_message_is_blake3_of_freeze_preimage() {
        let cov = [0x77u8; 32];
        let txid = [0x88u8; 32];
        let spk = sample_spk();
        let pre = build_freeze_attestation_preimage(&cov, 9, &txid, 1, &spk, 42, 0);
        let msg = build_freeze_attestation_message(&cov, 9, &txid, 1, &spk, 42, 0);
        assert_eq!(msg, *blake3::hash(&pre).as_bytes());
    }

    #[test]
    fn freeze_message_is_sensitive_to_new_frozen_flag() {
        let cov = [0x99u8; 32];
        let txid = [0xaau8; 32];
        let spk = sample_spk();
        let m0 = build_freeze_attestation_message(&cov, 1, &txid, 1, &spk, 10, 0);
        let m1 = build_freeze_attestation_message(&cov, 1, &txid, 1, &spk, 10, 1);
        assert_ne!(m0, m1);
    }

    #[test]
    fn seize_preimage_len_and_tail_offset() {
        assert_eq!(SEIZE_PREIMAGE_LEN, 153);
        assert_eq!(OFFSET_NEW_OWNER_PUBKEY, 121);
    }

    #[test]
    fn seize_preimage_matches_base_prefix_plus_new_owner_pubkey_tail() {
        let cov = [0x55u8; 32];
        let txid = [0x66u8; 32];
        let spk = sample_spk();
        let new_owner = [0x9au8; 32];
        let base = build_attestation_preimage(&cov, op_type::SEIZE, 3, &txid, 2, &spk, 777);
        let seize = build_seize_attestation_preimage(&cov, 3, &txid, 2, &spk, 777, &new_owner);
        assert_eq!(seize.len(), 153);
        assert_eq!(&seize[..121], &base[..]);
        assert_eq!(&seize[121..153], &new_owner);
        assert_eq!(seize[OFFSET_OP_TYPE], op_type::SEIZE);
    }

    #[test]
    fn seize_message_is_blake3_of_seize_preimage() {
        let cov = [0x77u8; 32];
        let txid = [0x88u8; 32];
        let spk = sample_spk();
        let new_owner = [0xbcu8; 32];
        let pre = build_seize_attestation_preimage(&cov, 9, &txid, 1, &spk, 42, &new_owner);
        let msg = build_seize_attestation_message(&cov, 9, &txid, 1, &spk, 42, &new_owner);
        assert_eq!(msg, *blake3::hash(&pre).as_bytes());
    }

    #[test]
    fn seize_message_is_sensitive_to_new_owner_pubkey() {
        let cov = [0x99u8; 32];
        let txid = [0xaau8; 32];
        let spk = sample_spk();
        let m0 = build_seize_attestation_message(&cov, 1, &txid, 1, &spk, 10, &[0x01u8; 32]);
        let m1 = build_seize_attestation_message(&cov, 1, &txid, 1, &spk, 10, &[0x02u8; 32]);
        assert_ne!(m0, m1);
    }

    #[test]
    fn migrate_preimage_len_and_tail_offset() {
        assert_eq!(MIGRATE_PREIMAGE_LEN, 153);
        assert_eq!(OFFSET_NEW_TEMPLATE_HASH, 121);
    }

    #[test]
    fn migrate_preimage_matches_base_prefix_plus_new_template_hash_tail() {
        let cov = [0x55u8; 32];
        let txid = [0x66u8; 32];
        let spk = sample_spk();
        let new_template_hash = [0x9au8; 32];
        let base = build_attestation_preimage(&cov, op_type::MIGRATE, 3, &txid, 2, &spk, 777);
        let migrate = build_migrate_attestation_preimage(&cov, 3, &txid, 2, &spk, 777, &new_template_hash);
        assert_eq!(migrate.len(), 153);
        assert_eq!(&migrate[..121], &base[..]);
        assert_eq!(&migrate[121..153], &new_template_hash);
        assert_eq!(migrate[OFFSET_OP_TYPE], op_type::MIGRATE);
    }

    #[test]
    fn migrate_message_is_blake3_of_migrate_preimage() {
        let cov = [0x77u8; 32];
        let txid = [0x88u8; 32];
        let spk = sample_spk();
        let new_template_hash = [0xbcu8; 32];
        let pre = build_migrate_attestation_preimage(&cov, 9, &txid, 1, &spk, 42, &new_template_hash);
        let msg = build_migrate_attestation_message(&cov, 9, &txid, 1, &spk, 42, &new_template_hash);
        assert_eq!(msg, *blake3::hash(&pre).as_bytes());
    }

    #[test]
    fn migrate_message_is_sensitive_to_new_template_hash() {
        let cov = [0x99u8; 32];
        let txid = [0xaau8; 32];
        let spk = sample_spk();
        let m0 = build_migrate_attestation_message(&cov, 1, &txid, 1, &spk, 10, &[0x01u8; 32]);
        let m1 = build_migrate_attestation_message(&cov, 1, &txid, 1, &spk, 10, &[0x02u8; 32]);
        assert_ne!(m0, m1);
    }

    #[test]
    fn op_type_0x04_is_not_defined() {
        // 0x04 is reserved for the separate mint-authority contract (§9) and
        // must never appear as a named constant in this covenant's op_type
        // set.
        let defined = [
            op_type::TRANSFER,
            op_type::FREEZE,
            op_type::SEIZE,
            op_type::BURN,
            op_type::ROTATE,
            op_type::MIGRATE,
            op_type::TRANSFER_NM,
            op_type::TRANSFER_NM_DELEGATOR,
        ];
        assert!(!defined.contains(&0x04));
        assert_eq!(op_type::TRANSFER_NM, 0x07);
        assert_eq!(op_type::TRANSFER_NM_DELEGATOR, 0x08);
    }

    #[test]
    fn transfer_nm_preimage_len_and_offsets() {
        assert_eq!(TRANSFER_NM_PREIMAGE_LEN, 111);
        assert_eq!(OFFSET_N_IN, 45);
        assert_eq!(OFFSET_N_OUT, 46);
        assert_eq!(OFFSET_INPUTS_DIGEST, 47);
        assert_eq!(OFFSET_OUTPUTS_DIGEST, 79);
        assert_eq!(OFFSET_OUTPUTS_DIGEST + GROUP_DIGEST_LEN, TRANSFER_NM_PREIMAGE_LEN);
    }

    #[test]
    fn transfer_nm_preimage_field_placement() {
        let cov = [0x11u8; 32];
        let inputs_digest = [0x22u8; 32];
        let outputs_digest = [0x33u8; 32];
        let pre = build_transfer_nm_attestation_preimage(&cov, 7, 3, 2, &inputs_digest, &outputs_digest);
        assert_eq!(pre.len(), 111);
        assert_eq!(&pre[0..8], &DOMAIN_TAG);
        assert_eq!(&pre[OFFSET_COVENANT_ID..OFFSET_COVENANT_ID + 32], &cov);
        assert_eq!(pre[OFFSET_OP_TYPE], op_type::TRANSFER_NM);
        assert_eq!(&pre[OFFSET_EPOCH..OFFSET_EPOCH + 4], &7u32.to_le_bytes());
        assert_eq!(pre[OFFSET_N_IN], 3);
        assert_eq!(pre[OFFSET_N_OUT], 2);
        assert_eq!(&pre[OFFSET_INPUTS_DIGEST..OFFSET_INPUTS_DIGEST + 32], &inputs_digest);
        assert_eq!(&pre[OFFSET_OUTPUTS_DIGEST..OFFSET_OUTPUTS_DIGEST + 32], &outputs_digest);
    }

    #[test]
    fn transfer_nm_message_is_blake3_of_preimage_and_field_sensitive() {
        let cov = [0x44u8; 32];
        let din = [0x55u8; 32];
        let dout = [0x66u8; 32];
        let pre = build_transfer_nm_attestation_preimage(&cov, 1, 2, 1, &din, &dout);
        let msg = build_transfer_nm_attestation_message(&cov, 1, 2, 1, &din, &dout);
        assert_eq!(msg, *blake3::hash(&pre).as_bytes());

        assert_ne!(msg, build_transfer_nm_attestation_message(&cov, 2, 2, 1, &din, &dout)); // epoch
        assert_ne!(msg, build_transfer_nm_attestation_message(&cov, 1, 3, 1, &din, &dout)); // n_in
        assert_ne!(msg, build_transfer_nm_attestation_message(&cov, 1, 2, 2, &din, &dout)); // n_out
        let mut din2 = din;
        din2[0] ^= 0xff;
        assert_ne!(msg, build_transfer_nm_attestation_message(&cov, 1, 2, 1, &din2, &dout));
        let mut dout2 = dout;
        dout2[0] ^= 0xff;
        assert_ne!(msg, build_transfer_nm_attestation_message(&cov, 1, 2, 1, &din, &dout2));
    }

    #[test]
    fn fold_transfer_nm_inputs_digest_matches_manual_concatenation() {
        let sib1 = ([0x01u8; 32], 5u32, 1_000u64);
        let sib2 = ([0x02u8; 32], 7u32, 2_000u64);
        let digest = fold_transfer_nm_inputs_digest(&[sib1, sib2]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&sib1.0);
        expected.extend_from_slice(&sib1.1.to_le_bytes());
        expected.extend_from_slice(&sib1.2.to_le_bytes());
        expected.extend_from_slice(&sib2.0);
        expected.extend_from_slice(&sib2.1.to_le_bytes());
        expected.extend_from_slice(&sib2.2.to_le_bytes());
        assert_eq!(digest, *blake3::hash(&expected).as_bytes());
        assert_eq!(fold_transfer_nm_inputs_digest(&[]), *blake3::hash(&[]).as_bytes());
    }

    #[test]
    fn fold_transfer_nm_outputs_digest_matches_manual_concatenation() {
        let spk1 = vec![0xAAu8; 37];
        let spk2 = vec![0xBBu8; 37];
        let digest = fold_transfer_nm_outputs_digest(&[spk1.clone(), spk2.clone()]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&spk1);
        expected.extend_from_slice(&spk2);
        assert_eq!(digest, *blake3::hash(&expected).as_bytes());
    }
}
