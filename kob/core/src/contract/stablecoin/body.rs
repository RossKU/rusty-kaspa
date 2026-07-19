//! KCC-0020 native-value stablecoin covenant **body** and complete redeem
//! script builder (WU-A).
//!
//! The redeem script is `state (35B) || body`:
//!
//! - **state (35B)** — the reused KCC20 Standard State Header
//!   ([`crate::contract::token::Kcc20StateHeader`]): `[0x20][owner_pubkey 32B]
//!   [0x01][identifier_type 1B]`. KCC20 `amount` is the UTXO's native value
//!   (Plan A), not a script field (see [`super`] module doc).
//! - **body** — the two-stage gate emitted by [`build_stablecoin_body`].
//!
//! # Sigscript the body consumes (contract for WU-F's builder)
//!
//! After P2SH extraction pops the redeem script, the remaining stack (pushed
//! by the sigscript) must be, top-to-bottom:
//!
//! ```text
//! owner_sig   (65B: 64-byte Schnorr sig || 0x01 SIGHASH_ALL)   <- top
//! issuer_sig  (64B: raw Schnorr sig over the attestation message)
//! ```
//!
//! i.e. the sigscript pushes `issuer_sig` first (deeper), then `owner_sig`,
//! then the redeem script last. This input's `sig_op_count` MUST be **2**
//! (one `OpCheckSigVerify` for the owner + one `OpCheckSigFromStack` for the
//! issuer).
//!
//! # Stack trace of the body
//!
//! Entry (top-to-bottom): `identifier_type, owner_pubkey, owner_sig, issuer_sig`.
//!
//! 1. `OpDrop` — drop `identifier_type`.
//! 2. `OpCheckSigVerify` — pop `owner_pubkey` (pubkey, top) + `owner_sig`
//!    (sig); verify SIGHASH_ALL over the tx. Stack: `issuer_sig`.
//! 3. Build the 116-byte attestation pre-image on top of `issuer_sig` by
//!    folding each field in with `OpCat`, in the exact order and widths of
//!    [`super::attestation::build_attestation_preimage`]:
//!    domain tag → covenant_id → outpoint_txid → outpoint_index(4) →
//!    successor_spk_hash → amount(8). Every input introspection index comes
//!    from `OpTxInputIndex` (replay-binding). The successor SPK is read from
//!    the output at *this input's index* (`OpTxInputIndex` reused as the
//!    output index — the 1:1 successor-binding convention, see below).
//! 4. `OpBlake3` — hash the pre-image → 32-byte `msg_hash`. Stack:
//!    `issuer_sig, msg_hash`.
//! 5. Push the issuer pubkey constant. Stack: `issuer_sig, msg_hash,
//!    issuer_pubkey` — exactly the layout `OpCheckSigFromStack` pops as
//!    `[signature, msg_hash, pubkey]`.
//! 6. `OpCheckSigFromStack` `OpVerify` — fail-close on a missing/invalid
//!    attestation.
//! 7. `Op1` — success.
//!
//! # Successor-binding convention (1:1, ISSUE-15 deferred)
//!
//! The body reads the successor output at the **same index as the gated
//! input** (`OpTxInputIndex` fed to `OpTxOutputSpk`). Together with binding
//! the input's *full* native `amount`, this fixes a 1:1 transfer shape: input
//! `i` funds the attested successor at output `i`, no token-side split/change.
//! WU-B/C/D/F MUST place the attested successor at that index. N:M shapes and
//! per-instance shape enforcement (`OpCovInputCount == 1`) are out of WU-A
//! scope.

use super::attestation::{AMOUNT_LEN, OUTPOINT_INDEX_LEN, X_ONLY_PUBKEY_LEN};
use super::DOMAIN_TAG;
use crate::contract::token::{identifier_type, Kcc20StateHeader};

/// Opcode bytes used by the stablecoin body (named for readability; values
/// are the canonical `crypto/txscript` assignments).
mod op {
    /// `OpDrop`.
    pub const DROP: u8 = 0x75;
    /// `OpCat` — pop b, pop a, push a||b.
    pub const CAT: u8 = 0x7e;
    /// `OpCheckSigVerify` — owner authorization (SIGHASH_ALL).
    pub const CHECKSIGVERIFY: u8 = 0xad;
    /// `OpTxInputIndex` — push this input's index.
    pub const TXINPUTINDEX: u8 = 0xb9;
    /// `OpOutpointTxId` — pop idx, push that input's outpoint txid (32B).
    pub const OUTPOINTTXID: u8 = 0xba;
    /// `OpOutpointIndex` — pop idx, push that input's outpoint index (number).
    pub const OUTPOINTINDEX: u8 = 0xbb;
    /// `OpTxInputAmount` — pop idx, push that input's UTXO amount (number).
    pub const TXINPUTAMOUNT: u8 = 0xbe;
    /// `OpTxOutputSpk` — pop idx, push that output's SPK bytes.
    pub const TXOUTPUTSPK: u8 = 0xc3;
    /// `OpNum2Bin` — pop size, pop num, push fixed-width LE bytes.
    pub const NUM2BIN: u8 = 0xcd;
    /// `OpInputCovenantId` — pop idx, push that input's covenant id (32B).
    pub const INPUTCOVENANTID: u8 = 0xcf;
    /// `OpCheckSigFromStack` — pop [sig, msg_hash, pubkey], push bool.
    pub const CHECKSIGFROMSTACK: u8 = 0xd7;
    /// `OpBlake3` — pop data, push 32-byte hash.
    pub const BLAKE3: u8 = 0xd9;
    /// `OpVerify`.
    pub const VERIFY: u8 = 0x69;
    /// `Op1` (TRUE) — also used as the `OpNum2Bin` size literal `1` is not
    /// needed; see `OP4`/`OP8`.
    pub const OP1: u8 = 0x51;
    /// `Op4` — pushes the number 4 (the `OpNum2Bin` width for `outpoint_index`).
    pub const OP4: u8 = 0x54;
    /// `Op8` — pushes the number 8 (the `OpNum2Bin` width for `amount`).
    pub const OP8: u8 = 0x58;
    /// `OpData8` push-opcode (push next 8 bytes) — for the domain tag.
    pub const DATA8: u8 = 0x08;
    /// `OpData32` push-opcode (push next 32 bytes) — for the issuer pubkey.
    pub const DATA32: u8 = 0x20;
}

// Compile-time guards tying the `OpNum2Bin` width literals to the encoder's
// field widths: if `attestation` ever changes a fixed width, these break the
// build rather than silently desyncing the on-chain composition.
const _: () = assert!(OUTPOINT_INDEX_LEN == 4);
const _: () = assert!(AMOUNT_LEN == 8);
const _: () = assert!(X_ONLY_PUBKEY_LEN == 32);

/// Length, in bytes, of the stablecoin covenant body.
pub const STABLECOIN_BODY_LEN: usize = 68;

/// Length, in bytes, of the complete stablecoin redeem script (state + body).
pub const STABLECOIN_REDEEM_SCRIPT_LEN: usize = Kcc20StateHeader::SCRIPT_ENCODED_LEN + STABLECOIN_BODY_LEN; // 103

/// Byte offset, within the full redeem script, of the issuer pubkey's 32-byte
/// payload (the byte immediately before it, at `offset - 1`, is the `OpData32`
/// push opcode `0x20`).
pub const ISSUER_PUBKEY_RS_OFFSET: usize = Kcc20StateHeader::SCRIPT_ENCODED_LEN + 33; // 68

/// Emit the stablecoin covenant body for a given issuer key. See the module
/// doc for the full stack trace; the emission order of the pre-image fields
/// is kept identical to [`super::attestation::build_attestation_preimage`].
pub fn build_stablecoin_body(issuer_pubkey: &[u8; X_ONLY_PUBKEY_LEN]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(STABLECOIN_BODY_LEN);

    // --- Stage 1: owner authorization (mirrors token::TOKEN_UNIT_BODY). ---
    b.push(DROP); // drop identifier_type
    b.push(CHECKSIGVERIFY); // owner_pubkey (state) x owner_sig (SIGHASH_ALL)

    // --- Stage 2: reconstruct the attestation pre-image on the stack. ---
    // Field 1: DOMAIN_TAG (8B constant) — seeds the accumulator.
    b.push(DATA8);
    b.extend_from_slice(&DOMAIN_TAG);
    // Field 2: covenant_id (32B) = OpTxInputIndex OpInputCovenantId.
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(CAT);
    // Field 3: outpoint_txid (32B) = OpTxInputIndex OpOutpointTxId.
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT);
    // Field 4: outpoint_index (4B LE) = OpTxInputIndex OpOutpointIndex OpNum2Bin(4).
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT);
    // Field 5: successor_spk_hash (32B) = OpTxInputIndex OpTxOutputSpk OpBlake3.
    // (OpTxInputIndex reused as the OUTPUT index — 1:1 successor binding.)
    b.push(TXINPUTINDEX);
    b.push(TXOUTPUTSPK);
    b.push(BLAKE3);
    b.push(CAT);
    // Field 6: amount (8B LE) = OpTxInputIndex OpTxInputAmount OpNum2Bin(8).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(OP8);
    b.push(NUM2BIN);
    b.push(CAT);

    // msg_hash = Blake3(pre-image).
    b.push(BLAKE3);

    // Push the issuer pubkey constant, then verify the attestation.
    b.push(DATA32);
    b.extend_from_slice(issuer_pubkey);
    b.push(CHECKSIGFROMSTACK);
    b.push(VERIFY);

    // Success.
    b.push(OP1);

    debug_assert_eq!(b.len(), STABLECOIN_BODY_LEN);
    b
}

/// Build the complete KCC-0020 native-value stablecoin redeem script
/// (`STABLECOIN_REDEEM_SCRIPT_LEN` = 103 bytes).
///
/// - `owner_pubkey` (32B x-only) → the state header's `owner_identifier`
///   (identifier type `PUBKEY`). As in `token_unit`, this alone determines
///   the P2SH address (native-value `amount`), so address-based discovery
///   keeps working.
/// - `issuer_pubkey` (32B x-only) → baked into the body as the
///   `OpCheckSigFromStack` attestation key. The `&[u8; 32]` parameter type
///   statically rejects a 33-byte compressed key (the brick case); callers
///   holding raw bytes should go through
///   [`super::attestation::validate_x_only_pubkey`] first.
pub fn build_stablecoin_redeem_script(
    owner_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    issuer_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
) -> Vec<u8> {
    let mut rs = Vec::with_capacity(STABLECOIN_REDEEM_SCRIPT_LEN);
    rs.extend_from_slice(&Kcc20StateHeader::new(*owner_pubkey, identifier_type::PUBKEY, 0).encode_script());
    rs.extend_from_slice(&build_stablecoin_body(issuer_pubkey));
    debug_assert_eq!(rs.len(), STABLECOIN_REDEEM_SCRIPT_LEN);
    rs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::stablecoin::attestation::DOMAIN_TAG_LEN;

    const OWNER: [u8; 32] = [0xAA; 32];
    const ISSUER: [u8; 32] = [0xBB; 32];

    #[test]
    fn lengths_are_pinned() {
        assert_eq!(STABLECOIN_BODY_LEN, 68);
        assert_eq!(STABLECOIN_REDEEM_SCRIPT_LEN, 103);
        assert_eq!(build_stablecoin_body(&ISSUER).len(), STABLECOIN_BODY_LEN);
        assert_eq!(build_stablecoin_redeem_script(&OWNER, &ISSUER).len(), STABLECOIN_REDEEM_SCRIPT_LEN);
    }

    #[test]
    fn state_header_layout_is_kcc20_standard() {
        let rs = build_stablecoin_redeem_script(&OWNER, &ISSUER);
        assert_eq!(rs[0], 0x20); // push 32
        assert_eq!(&rs[1..33], &OWNER); // owner_identifier
        assert_eq!(rs[33], 0x01); // push 1
        assert_eq!(rs[34], identifier_type::PUBKEY); // identifier_type
    }

    #[test]
    fn issuer_pubkey_is_baked_into_body() {
        let rs = build_stablecoin_redeem_script(&OWNER, &ISSUER);
        // OpData32 push opcode immediately precedes the 32-byte key.
        assert_eq!(rs[ISSUER_PUBKEY_RS_OFFSET - 1], 0x20);
        assert_eq!(&rs[ISSUER_PUBKEY_RS_OFFSET..ISSUER_PUBKEY_RS_OFFSET + 32], &ISSUER);
        // owner and issuer live in disjoint regions; swapping either changes
        // only its region.
        let rs2 = build_stablecoin_redeem_script(&OWNER, &[0xCC; 32]);
        assert_eq!(&rs[..ISSUER_PUBKEY_RS_OFFSET], &rs2[..ISSUER_PUBKEY_RS_OFFSET]);
        assert_ne!(&rs[ISSUER_PUBKEY_RS_OFFSET..], &rs2[ISSUER_PUBKEY_RS_OFFSET..]);
    }

    #[test]
    fn distinct_keys_yield_distinct_redeem_scripts() {
        let a = build_stablecoin_redeem_script(&OWNER, &ISSUER);
        let b = build_stablecoin_redeem_script(&[0x01; 32], &ISSUER);
        let c = build_stablecoin_redeem_script(&OWNER, &[0x02; 32]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    /// The exact expected body bytecode — the golden opcode-sequence lock.
    fn expected_body(issuer: &[u8; 32]) -> Vec<u8> {
        let mut e = Vec::new();
        // Stage 1.
        e.extend_from_slice(&[0x75, 0xad]); // OpDrop, OpCheckSigVerify
        // Stage 2 pre-image build.
        e.push(0x08); // OpData8
        e.extend_from_slice(&DOMAIN_TAG); // domain tag (8B)
        e.extend_from_slice(&[0xb9, 0xcf, 0x7e]); // idx, InputCovenantId, Cat
        e.extend_from_slice(&[0xb9, 0xba, 0x7e]); // idx, OutpointTxId, Cat
        e.extend_from_slice(&[0xb9, 0xbb, 0x54, 0xcd, 0x7e]); // idx, OutpointIndex, Op4, Num2Bin, Cat
        e.extend_from_slice(&[0xb9, 0xc3, 0xd9, 0x7e]); // idx, TxOutputSpk, Blake3, Cat
        e.extend_from_slice(&[0xb9, 0xbe, 0x58, 0xcd, 0x7e]); // idx, TxInputAmount, Op8, Num2Bin, Cat
        e.push(0xd9); // Blake3(pre-image) -> msg_hash
        e.push(0x20); // OpData32
        e.extend_from_slice(issuer); // issuer pubkey (32B)
        e.extend_from_slice(&[0xd7, 0x69]); // OpCheckSigFromStack, OpVerify
        e.push(0x51); // Op1
        e
    }

    #[test]
    fn body_matches_expected_opcode_sequence() {
        assert_eq!(build_stablecoin_body(&ISSUER), expected_body(&ISSUER));
    }

    /// Conformance core: the body's on-chain pre-image composition must fold
    /// fields in the SAME order and fixed widths as the off-chain encoder
    /// (`attestation::build_attestation_preimage`). This test pins that
    /// correspondence structurally, so WU-F's real-engine round-trip has a
    /// static guarantee to lean on.
    #[test]
    fn body_field_composition_matches_encoder_layout() {
        let body = build_stablecoin_body(&ISSUER);

        // Field 1: the domain tag pushed first must be the encoder's DOMAIN_TAG
        // (same length, same bytes), immediately after the two owner-auth ops.
        assert_eq!(body[0..2], [0x75, 0xad]);
        assert_eq!(body[2], 0x08); // OpData8 => 8-byte field
        assert_eq!(DOMAIN_TAG_LEN, 8);
        assert_eq!(&body[3..3 + DOMAIN_TAG_LEN], &DOMAIN_TAG);

        // The ordered field-producing opcodes after the domain tag, in encoder
        // order: covenant_id, txid, index(Num2Bin 4), spk_hash(Blake3), amount(Num2Bin 8).
        let after_tag = &body[3 + DOMAIN_TAG_LEN..];
        let expected_tail: &[u8] = &[
            0xb9, 0xcf, 0x7e, // covenant_id
            0xb9, 0xba, 0x7e, // outpoint_txid
            0xb9, 0xbb, 0x54, 0xcd, 0x7e, // outpoint_index @ width 4 (Op4)
            0xb9, 0xc3, 0xd9, 0x7e, // successor_spk_hash (OpBlake3)
            0xb9, 0xbe, 0x58, 0xcd, 0x7e, // amount @ width 8 (Op8)
            0xd9, // Blake3(pre-image)
        ];
        assert_eq!(&after_tag[..expected_tail.len()], expected_tail);

        // The Num2Bin width literals must equal the encoder's field widths.
        // Op4 (0x54) == OUTPOINT_INDEX_LEN, Op8 (0x58) == AMOUNT_LEN.
        assert_eq!(0x54 - 0x50, OUTPOINT_INDEX_LEN as u8);
        assert_eq!(0x58 - 0x50, AMOUNT_LEN as u8);
    }

    #[test]
    fn body_uses_input_index_for_every_introspection() {
        // Every introspection opcode in this body is immediately preceded by
        // OpTxInputIndex (0xb9), never an immediate index — the replay-binding
        // discipline. Introspection opcodes used here that take an index:
        // 0xcf, 0xba, 0xbb, 0xc3, 0xbe.
        let body = build_stablecoin_body(&ISSUER);
        let index_taking: [u8; 5] = [0xcf, 0xba, 0xbb, 0xc3, 0xbe];
        // Scan only the pre-image build region (skip the 32-byte issuer key
        // payload, which is opaque data, and the leading owner-auth ops).
        let key_start = ISSUER_PUBKEY_RS_OFFSET - Kcc20StateHeader::SCRIPT_ENCODED_LEN; // offset within body
        for i in 0..key_start {
            if index_taking.contains(&body[i]) {
                assert!(i > 0 && body[i - 1] == 0xb9, "introspection op at body[{i}] not preceded by OpTxInputIndex");
            }
        }
    }
}
