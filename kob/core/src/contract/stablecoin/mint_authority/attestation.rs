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
/// (separate, 3-way) dispatch. `MINT`, `ANNOUNCE_CAP` (renamed 2026-07-20
/// from `RAISE_CAP` -- SAME byte value, now writes `pending_cap` instead of
/// `current_cap`, see `state.rs`'s field-ownership table) and `ACTIVATE_CAP`
/// (new 2026-07-20: permissionless, CSV-timelocked promotion of
/// `pending_cap` into `current_cap`) are all wired -- see
/// `super::body::build_mint_branch`/`super::body::build_announce_cap_branch`/
/// `super::body::build_activate_cap_branch`.
pub mod op_type {
    pub const MINT: u8 = 0x00;
    pub const ANNOUNCE_CAP: u8 = 0x01;
    /// Permissionless: promotes an already-announced `pending_cap` into
    /// `current_cap` once `min_activation_delay_daa` (CSV) has elapsed since
    /// the input became spendable. Has NO attestation message of its own --
    /// there is no signature at all in this branch (sig_op_count = 0).
    pub const ACTIVATE_CAP: u8 = 0x02;
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

/// Sanity floor on `mint_amount` for a newly-emitted coin: **necessary, not
/// sufficient**.
///
/// Because a coin's face amount IS its native sompi value (the KCC-0020
/// amount=sompi model), a small mint drives the KIP-9 storage mass of the mint
/// transaction up. The emitted coin is a covenant-bound P2SH output, so its
/// UTXO occupies TWO 100-byte storage units (`utxo_plurality` = 2:
/// 63 const + 35 spk + 32 covenant_id = 130 bytes), and its contribution to
/// the whole-transaction harmonic term is `C * p^2 / amount` = `4e12 / amount`
/// -- four times the naive `C / amount` a plurality-1 output would cost.
///
/// The relay-gating limit is the mempool's storage-mass block-fit limit
/// (`block_mass_limits.storage`, 500_000 on all networks;
/// `mining/src/mempool/check_transaction_limits.rs`). The stricter
/// pre-Toccata per-dimension standardness cap of 100_000 no longer applies:
/// Toccata activated on testnet-10 (DAA 467_579_632, ~2026-05-18) and mainnet
/// (474_165_565, ~2026-06-30).
///
/// Crucially, storage mass is a property of the WHOLE transaction (outputs'
/// harmonic sum minus an input credit), not of `mint_amount` alone: with the
/// reference MINT shape (authority in/out 1 KAS, one wallet fee input, three
/// outputs) the true floor is ~8.1e6 sompi, but it rises above this constant
/// -- to ~1.1e7 -- once the authority's own balance drops to 0.2 KAS, because
/// output[0] then carries a larger harmonic term of its own. **No constant can
/// guarantee relay.** This value is therefore a cheap, shape-independent
/// rejection of obvious dust; the authoritative check is
/// `kob_core::mass::check_tx_storage_mass` on the fully-built transaction,
/// which every mint path must run before submission.
///
/// Enforced off-chain by [`check_mint_amount_floor`], which every
/// transaction-building mint path calls before signing.
/// It is deliberately NOT enforced on-chain: the floor's correct value depends
/// on transaction shape, so a hardcoded bytecode threshold would either be too
/// weak to guarantee anything or would permanently forbid legitimate mints in
/// shapes it never anticipated. A sub-floor mint is also not a third-party
/// attack -- it needs the MINT role's own key, and a mint that fails to relay
/// costs only the minter. It is not entirely harmless either, which is why the
/// off-chain check is a hard error rather than a warning: `running_supply` is
/// strictly monotonic (no burn path decrements it -- BURN acts on the coin's
/// own covenant, never on the authority UTXO), so a dust mint that DOES get
/// mined permanently consumes that much of `current_cap`.
pub const MIN_MINT_AMOUNT: u64 = 10_000_000;

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

    /// `mint_amount` is below [`MIN_MINT_AMOUNT`] -- the emitted coin would
    /// carry a KIP-9 storage-mass term large enough to push the mint
    /// transaction past the network's storage-mass limit, so the mint could
    /// not relay (and, if mined anyway, would permanently consume cap
    /// headroom for a coin of negligible value).
    #[error("mint_amount {0} is below the dust floor {1} (KIP-9 storage mass); see MIN_MINT_AMOUNT")]
    MintAmountBelowFloor(u64, u64),
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

/// Check that `mint_amount` clears the [`MIN_MINT_AMOUNT`] dust floor.
///
/// This is the lower-bound counterpart to [`check_numeric_domain`], and is the
/// enforcement point [`MIN_MINT_AMOUNT`] refers to. Every transaction-building
/// mint path MUST call it before signing; it is deliberately NOT wired into
/// [`build_mint_attestation_message`], which is also the verifier-side and
/// bytecode-conformance pre-image builder (those callers reconstruct messages
/// for amounts chosen to exercise encoding, not to be relayed, and must stay
/// infallible).
///
/// It is a NECESSARY condition only -- callers must ALSO run
/// `kob_core::mass::check_tx_storage_mass` on the assembled transaction, since
/// the real limit depends on the whole transaction's shape (see
/// [`MIN_MINT_AMOUNT`]'s doc).
pub fn check_mint_amount_floor(mint_amount: u64) -> Result<(), MintAuthorityError> {
    if mint_amount < MIN_MINT_AMOUNT {
        return Err(MintAuthorityError::MintAmountBelowFloor(mint_amount, MIN_MINT_AMOUNT));
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

/// Width, in bytes, of the `new_pending_cap` field (ANNOUNCE_CAP's preimage tail).
pub const NEW_CAP_LEN: usize = 8;

/// Byte offsets inside the ANNOUNCE_CAP pre-image (§9, renamed 2026-07-20
/// from RAISE_CAP: "the attestation preimage follows the same prefix with a
/// `new_pending_cap(8,LE)` tail in place of the MINT-specific fields").
/// Shares the `DOMAIN_TAG_MINT || covenant_id || outpoint_txid ||
/// outpoint_index` prefix byte-for-byte with the MINT pre-image above, then
/// a `new_pending_cap(8,LE)` tail instead of MINT's `mint_amount ||
/// new_running_supply || recipient_spk_hash` tail. No `op_type` byte: the
/// ANNOUNCE_CAP pre-image is `DOMAIN_TAG_MINT || covenant_id ||
/// outpoint_txid || outpoint_index || new_pending_cap(8,LE)`, 84B total --
/// cross-op replay is structurally impossible regardless, since MINT and
/// ANNOUNCE_CAP are authorized by entirely different keys (`mint_pubkey` vs.
/// the `cap_authority` quorum) and the two pre-image shapes/lengths already
/// differ (124B vs. 84B), so an extra `op_type` disambiguator byte would be
/// redundant -- this also matches the already-implemented MINT pre-image's
/// own precedent of NOT including an `op_type` byte. (ACTIVATE_CAP has no
/// preimage at all -- it is permissionless, no signature.)
pub const ANNOUNCE_CAP_OFFSET_DOMAIN_TAG: usize = 0;
pub const ANNOUNCE_CAP_OFFSET_COVENANT_ID: usize = ANNOUNCE_CAP_OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN; // 8
pub const ANNOUNCE_CAP_OFFSET_OUTPOINT_TXID: usize = ANNOUNCE_CAP_OFFSET_COVENANT_ID + COVENANT_ID_LEN; // 40
pub const ANNOUNCE_CAP_OFFSET_OUTPOINT_INDEX: usize = ANNOUNCE_CAP_OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN; // 72
pub const ANNOUNCE_CAP_OFFSET_NEW_PENDING_CAP: usize = ANNOUNCE_CAP_OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN; // 76

/// Total ANNOUNCE_CAP pre-image length: `8+32+32+4+8 = 84` bytes (§9).
pub const ANNOUNCE_CAP_ATTESTATION_PREIMAGE_LEN: usize = ANNOUNCE_CAP_OFFSET_NEW_PENDING_CAP + NEW_CAP_LEN;

/// Build the 84-byte ANNOUNCE_CAP attestation pre-image (see the constants'
/// module doc above for the exact layout/rationale).
pub fn build_announce_cap_attestation_preimage(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    new_pending_cap: u64,
) -> [u8; ANNOUNCE_CAP_ATTESTATION_PREIMAGE_LEN] {
    debug_assert!(u64::from(outpoint_index) < MAX_OUTPOINT_INDEX_EXCLUSIVE, "outpoint_index must be < 2^31 to match on-chain OpNum2Bin(4)");
    debug_assert!(new_pending_cap < MAX_AMOUNT_EXCLUSIVE, "new_pending_cap must be < 2^63 to match the on-chain sign-magnitude script-number domain");

    let mut out = [0u8; ANNOUNCE_CAP_ATTESTATION_PREIMAGE_LEN];
    out[ANNOUNCE_CAP_OFFSET_DOMAIN_TAG..ANNOUNCE_CAP_OFFSET_DOMAIN_TAG + DOMAIN_TAG_LEN].copy_from_slice(&DOMAIN_TAG_MINT);
    out[ANNOUNCE_CAP_OFFSET_COVENANT_ID..ANNOUNCE_CAP_OFFSET_COVENANT_ID + COVENANT_ID_LEN].copy_from_slice(covenant_id);
    out[ANNOUNCE_CAP_OFFSET_OUTPOINT_TXID..ANNOUNCE_CAP_OFFSET_OUTPOINT_TXID + OUTPOINT_TXID_LEN].copy_from_slice(outpoint_txid);
    out[ANNOUNCE_CAP_OFFSET_OUTPOINT_INDEX..ANNOUNCE_CAP_OFFSET_OUTPOINT_INDEX + OUTPOINT_INDEX_LEN].copy_from_slice(&outpoint_index.to_le_bytes());
    out[ANNOUNCE_CAP_OFFSET_NEW_PENDING_CAP..ANNOUNCE_CAP_OFFSET_NEW_PENDING_CAP + NEW_CAP_LEN].copy_from_slice(&new_pending_cap.to_le_bytes());
    out
}

/// Build the 32-byte ANNOUNCE_CAP attestation message: `Blake3(pre-image)`.
/// The cold 2-of-3 `cap_authority` quorum signs this (each signer producing
/// a raw message-hash Schnorr signature, no SIGHASH type byte) over the
/// pre-image binding the specific new ceiling (`new_pending_cap`) to this
/// exact spend (`covenant_id`/`outpoint_txid`/`outpoint_index`).
pub fn build_announce_cap_attestation_message(
    covenant_id: &[u8; COVENANT_ID_LEN],
    outpoint_txid: &[u8; OUTPOINT_TXID_LEN],
    outpoint_index: u32,
    new_pending_cap: u64,
) -> [u8; 32] {
    let preimage = build_announce_cap_attestation_preimage(covenant_id, outpoint_txid, outpoint_index, new_pending_cap);
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
    fn mint_amount_floor_rejects_dust_and_accepts_the_boundary() {
        // Audit 2026-07-20 §B3. The floor is a hard error, not a warning:
        // running_supply is strictly monotonic, so a dust mint that does get
        // mined permanently consumes cap headroom.
        assert_eq!(check_mint_amount_floor(0), Err(MintAuthorityError::MintAmountBelowFloor(0, MIN_MINT_AMOUNT)));
        assert_eq!(
            check_mint_amount_floor(MIN_MINT_AMOUNT - 1),
            Err(MintAuthorityError::MintAmountBelowFloor(MIN_MINT_AMOUNT - 1, MIN_MINT_AMOUNT))
        );
        assert!(check_mint_amount_floor(MIN_MINT_AMOUNT).is_ok());
        assert!(check_mint_amount_floor(MIN_MINT_AMOUNT + 1).is_ok());
    }

    #[test]
    fn mint_amount_floor_clears_storage_mass_in_the_reference_shape() {
        // Ties the constant to the arithmetic its doc claims, using kaspad's
        // own KIP-9 calculation rather than a restatement of the formula.
        // Reference MINT shape: authority coin in/out at 1 KAS, one 1-KAS
        // wallet fee input, outputs = [authority, minted coin, change].
        // Covenant-bound P2SH outputs have plurality 2; the wallet ones 1.
        let one_kas = 100_000_000u64;
        let est_fee = 250_000u64;
        let mass_for = |mint_amount: u64| -> u64 {
            crate::mass::compute_storage_mass_ex(
                &[(one_kas, 2), (one_kas, 1)],
                &[(one_kas, 2), (mint_amount, 2), (one_kas - mint_amount - est_fee, 1)],
            )
        };
        assert!(
            mass_for(MIN_MINT_AMOUNT) <= crate::mass::MAX_TX_MASS,
            "MIN_MINT_AMOUNT must clear the storage-mass limit in the reference shape (got {})",
            mass_for(MIN_MINT_AMOUNT)
        );
        // ... and the floor is not vacuous: an order of magnitude below it
        // genuinely blows the limit.
        assert!(mass_for(MIN_MINT_AMOUNT / 10) > crate::mass::MAX_TX_MASS);
    }

    #[test]
    fn announce_cap_preimage_length_is_84() {
        let preimage = build_announce_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);
        assert_eq!(preimage.len(), ANNOUNCE_CAP_ATTESTATION_PREIMAGE_LEN);
        assert_eq!(ANNOUNCE_CAP_ATTESTATION_PREIMAGE_LEN, 84);
    }

    #[test]
    fn announce_cap_preimage_shares_prefix_with_mint_preimage() {
        // Both preimages start with DOMAIN_TAG_MINT || covenant_id ||
        // outpoint_txid || outpoint_index -- the same 76-byte prefix,
        // byte-for-byte, before diverging into their op-specific tails.
        let mint_preimage = build_mint_attestation_preimage(&COV_ID, &TXID, 3, 1000, 2000, &SPK);
        let announce_cap_preimage = build_announce_cap_attestation_preimage(&COV_ID, &TXID, 3, 1_000_000);
        assert_eq!(&mint_preimage[..76], &announce_cap_preimage[..76]);
    }

    #[test]
    fn announce_cap_preimage_is_field_sensitive() {
        let base = build_announce_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);

        let diff_cap = build_announce_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_001);
        assert_ne!(base, diff_cap);

        let diff_index = build_announce_cap_attestation_preimage(&COV_ID, &TXID, 1, 1_000_000);
        assert_ne!(base, diff_index);

        let other_txid: [u8; 32] = [0x11; 32];
        let diff_txid = build_announce_cap_attestation_preimage(&COV_ID, &other_txid, 0, 1_000_000);
        assert_ne!(base, diff_txid);
    }

    #[test]
    fn announce_cap_message_is_blake3_of_preimage() {
        let preimage = build_announce_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);
        let message = build_announce_cap_attestation_message(&COV_ID, &TXID, 0, 1_000_000);
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
    fn announce_cap_preimage_never_equals_a_mint_preimage() {
        // Even holding covenant_id/outpoint fields constant, the RAISE_CAP
        // preimage (84B) can never collide with a MINT preimage (124B) --
        // different lengths alone rule out cross-op replay, independent of
        // the fact the two ops are authorized by entirely different keys.
        let mint_preimage = build_mint_attestation_preimage(&COV_ID, &TXID, 0, 1000, 2000, &SPK);
        let announce_cap_preimage = build_announce_cap_attestation_preimage(&COV_ID, &TXID, 0, 1_000_000);
        assert_ne!(mint_preimage.len(), announce_cap_preimage.len());
    }
}
