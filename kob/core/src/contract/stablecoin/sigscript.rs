//! KCC-0020 native-value stablecoin **sigscript** (unlocking script) builder
//! (WU-B).
//!
//! This is the spender side of the issuer-attestation gate defined in
//! [`super::body`]. It emits the push-only signature script that, once the
//! P2SH wrapper pops and executes the redeem script, leaves the stack in the
//! exact shape [`super::body::build_stablecoin_body`] consumes.
//!
//! # Layout the body requires (and this builder emits)
//!
//! After P2SH pops the redeem script, the body's entry stack must be, from the
//! spender's contributions, top-to-bottom:
//!
//! ```text
//! owner_sig   (65B: 64-byte Schnorr sig || 0x01 SIGHASH_ALL)   <- top
//! issuer_sig  (64B: raw Schnorr sig over the attestation message)
//! ```
//!
//! Because a sigscript is push-only and the last push is the redeem script
//! (which P2SH pops first), the *emission* order is the reverse of the stack
//! depth: `issuer_sig` (ends up deepest) is pushed first, then `owner_sig`,
//! then the redeem script last:
//!
//! ```text
//! push issuer_sig(64B)  ->  push owner_sig||0x01(65B)  ->  pushData(redeem_script)
//! ```
//!
//! # Signature formats (must match the engine exactly)
//!
//! - **owner_sig** is a Schnorr signature over the transaction's SIGHASH_ALL
//!   sighash; the builder appends the `0x01` SIGHASH_ALL type byte the body's
//!   `OpCheckSigVerify` (via `OpCheckSig`) strips and interprets. This is the
//!   same 64-byte-sig-plus-type-byte convention as
//!   [`crate::contract::token::build_token_unit_sigscript`].
//! - **issuer_sig** is a *raw* 64-byte Schnorr signature over the 32-byte
//!   attestation message ([`super::attestation::build_attestation_message`]).
//!   The body's `OpCheckSigFromStack` verifies it directly against the
//!   message hash it recomputes on-chain, so it carries **no** SIGHASH type
//!   byte (it is not tx-bound; the message's replay fields bind it instead).
//!
//! This input's `sig_op_count` MUST be **2** (one `OpCheckSigVerify` for the
//! owner + one `OpCheckSigFromStack` for the issuer).

use crate::primitives::push_data;

/// SIGHASH_ALL type byte appended to the owner signature (the body's
/// `OpCheckSig` pops this byte to select the sighash type).
const SIGHASH_ALL: u8 = 0x01;

/// Build the KCC-0020 native-value stablecoin transfer sigscript.
///
/// `owner_sig` — the owner's raw 64-byte Schnorr signature over the
/// transaction's SIGHASH_ALL sighash (the `0x01` type byte is appended here).
/// `issuer_sig` — the issuer's raw 64-byte Schnorr signature over
/// [`super::attestation::build_attestation_message`] (no type byte).
/// `redeem_script` — the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`] (103 bytes).
///
/// The returned bytes are push-only and pop in the order the body expects:
/// `issuer_sig` deepest, `owner_sig` above it, redeem script popped first by
/// the P2SH wrapper.
pub fn build_stablecoin_sigscript(owner_sig: &[u8; 64], issuer_sig: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    // Owner signature carries the SIGHASH_ALL type byte (65 bytes total).
    let mut owner_sig_with_type = Vec::with_capacity(65);
    owner_sig_with_type.extend_from_slice(owner_sig);
    owner_sig_with_type.push(SIGHASH_ALL);

    let mut ss = Vec::with_capacity(2 + 64 + 2 + 65 + 3 + redeem_script.len());
    // Emitted first -> ends up deepest on the stack: the issuer attestation sig.
    ss.extend_from_slice(&push_data(issuer_sig));
    // Then the owner authorization sig (65B: 64 Schnorr || 0x01 SIGHASH_ALL).
    ss.extend_from_slice(&push_data(&owner_sig_with_type));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::stablecoin::body::{build_stablecoin_redeem_script, STABLECOIN_REDEEM_SCRIPT_LEN};

    const OWNER_SIG: [u8; 64] = [0x11; 64];
    const ISSUER_SIG: [u8; 64] = [0x22; 64];

    fn rs() -> Vec<u8> {
        build_stablecoin_redeem_script(&[0xAA; 32], &[0xBB; 32])
    }

    #[test]
    fn emits_issuer_then_owner_then_redeem_script() {
        let rs = rs();
        let ss = build_stablecoin_sigscript(&OWNER_SIG, &ISSUER_SIG, &rs);

        // Field 1 (deepest): issuer_sig — OpData64 (0x40) + 64 raw bytes, no type byte.
        assert_eq!(ss[0], 64);
        assert_eq!(&ss[1..65], &ISSUER_SIG);

        // Field 2: owner_sig||0x01 — OpData65 (0x41) + 65 bytes.
        let owner_off = 1 + 64;
        assert_eq!(ss[owner_off], 65);
        assert_eq!(&ss[owner_off + 1..owner_off + 1 + 64], &OWNER_SIG);
        assert_eq!(ss[owner_off + 1 + 64], SIGHASH_ALL); // trailing SIGHASH_ALL byte

        // Field 3 (top / popped first by P2SH): the redeem script via PUSHDATA1
        // (103 bytes > 75), i.e. 0x4c, len, bytes.
        let rs_off = owner_off + 1 + 65;
        assert_eq!(ss[rs_off], 0x4c);
        assert_eq!(ss[rs_off + 1] as usize, STABLECOIN_REDEEM_SCRIPT_LEN);
        assert_eq!(&ss[rs_off + 2..rs_off + 2 + rs.len()], &rs[..]);

        // Nothing trailing: the sigscript is exactly the three pushes.
        assert_eq!(ss.len(), rs_off + 2 + rs.len());
    }

    #[test]
    fn total_length_is_pinned() {
        let rs = rs();
        let ss = build_stablecoin_sigscript(&OWNER_SIG, &ISSUER_SIG, &rs);
        // 1+64 (issuer) + 1+65 (owner) + 2+103 (rs) = 236.
        assert_eq!(ss.len(), (1 + 64) + (1 + 65) + (2 + STABLECOIN_REDEEM_SCRIPT_LEN));
        assert_eq!(ss.len(), 236);
    }

    #[test]
    fn owner_sig_gets_type_byte_issuer_sig_does_not() {
        let ss = build_stablecoin_sigscript(&OWNER_SIG, &ISSUER_SIG, &rs());
        // issuer push length is exactly 64 (raw, no type byte).
        assert_eq!(ss[0], 64);
        // owner push length is 65 (sig + one type byte).
        assert_eq!(ss[1 + 64], 65);
    }
}
