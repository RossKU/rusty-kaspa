//! KCC20 Standard State (kcc-0020 "## State"): the four fixed-order state
//! fields every KCC20 covenant state must begin with.
//!
//! ```text
//! owner_identifier:      bytes32
//! identifier_type:       byte
//! amount:                integer
//! extended_state_digest: bytes32
//! ```
//!
//! Distinct from `crate::contract::token::Kcc20StateHeader` -- KOB's
//! existing, UNCHANGED implementation, which encodes only
//! `owner_identifier`/`identifier_type` in-script and maps `amount` onto the
//! UTXO's native sompi value (see `token.rs`'s module doc for the address-
//! stability rationale). `Kcc20State` here encodes all four fields in-script,
//! per the literal reading of kcc-0020's "every KCC20 covenant state must
//! begin with the following fields, in this order" -- see the ISSUE list for
//! the resulting two-readings-of-one-spec tension this creates within the
//! same crate.

use super::{decode_push_explicit, decode_uint_from_int_state_payload, encode_uint_as_int_state_payload, push_explicit};

/// KCC20 `identifier_type` enum values (kcc-0020 "## State").
pub mod identifier_type {
    /// `owner_identifier` is a 32-byte Schnorr public key.
    pub const PUBKEY: u8 = 0x00;
    /// `owner_identifier` is a 32-byte hash of a locking script.
    pub const SCRIPT_HASH: u8 = 0x01;
    /// `owner_identifier` is a 32-byte covenant id.
    pub const COVENANT_ID: u8 = 0x02;
}

/// The KCC20 Standard State (kcc-0020 "## State"), decoded form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kcc20State {
    pub owner_identifier: [u8; 32],
    pub identifier_type: u8,
    /// Token quantity held by the state. NOTE: this Rust field is `u64`
    /// (range 0..=2^64-1), but the KCC1 `int` state-payload encoding it uses
    /// can only represent magnitudes up to `2^63-1` (see
    /// `super::KCC1_INT_MAX_MAGNITUDE` and the ISSUE list) -- `encode_script`
    /// errors for `amount > 2^63-1`.
    pub amount: u64,
    /// Commitment to token-specific extended state (kcc-0020 "## State
    /// Extendability"); opaque to this module.
    pub extended_state_digest: [u8; 32],
}

impl Kcc20State {
    pub fn new(
        owner_identifier: [u8; 32],
        identifier_type: u8,
        amount: u64,
        extended_state_digest: [u8; 32],
    ) -> Self {
        Self { owner_identifier, identifier_type, amount, extended_state_digest }
    }

    /// Fixed encoded length of a `Kcc20State`. All four fields have fixed
    /// payload widths (32, 1, 8, 32 bytes), each individually short enough
    /// (<=75 bytes) to always use `PushExplicit`'s `OP_DATA_n` row, so the
    /// total is a compile-time constant:
    /// `(1+32) + (1+1) + (1+8) + (1+32) = 77` bytes.
    pub const ENCODED_LEN: usize = (1 + 32) + (1 + 1) + (1 + 8) + (1 + 32);

    /// Encode the four state fields via `PushExplicit`, in kcc-0020's fixed
    /// field order (kcc-0001 §8.1: "State fields are recursively lowered in
    /// declaration order").
    pub fn encode_script(&self) -> crate::Result<Vec<u8>> {
        let amount_payload = encode_uint_as_int_state_payload(self.amount).map_err(|e| {
            crate::KobError::Contract(format!("Kcc20State.amount encode: {e}"))
        })?;

        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&push_explicit(&self.owner_identifier));
        out.extend_from_slice(&push_explicit(&[self.identifier_type]));
        out.extend_from_slice(&push_explicit(&amount_payload));
        out.extend_from_slice(&push_explicit(&self.extended_state_digest));
        debug_assert_eq!(out.len(), Self::ENCODED_LEN);
        Ok(out)
    }

    /// Decode the four state fields from `script`, which MUST be exactly the
    /// covenant's encoded-state byte range (kcc-0001 §8.2:
    /// `R[state.start : state.start + state.len]`).
    ///
    /// Per kcc-0001 §8.1, a decoder MUST consume exactly one `PushExplicit`
    /// push per field and MUST reject malformed pushes, invalid payloads,
    /// missing fields, or trailing bytes. Returns `None` on any such
    /// violation, including:
    /// - a push that is not a canonical `PushExplicit` encoding;
    /// - `identifier_type`'s payload not being exactly 1 byte;
    /// - `amount`'s payload having its KCC1-int sign bit set (a "negative
    ///   amount" -- see the ISSUE list on whether this is actually forbidden
    ///   by kcc-0020 or is KOB's own added constraint);
    /// - any bytes left over after the fourth field (kcc-0001 §8.1 trailing-
    ///   byte rejection).
    pub fn decode(script: &[u8]) -> Option<Self> {
        let mut offset = 0usize;

        let (owner_identifier_payload, n) = decode_push_explicit(&script[offset..])?;
        offset += n;
        let owner_identifier: [u8; 32] = owner_identifier_payload.try_into().ok()?;

        let (identifier_type_payload, n) = decode_push_explicit(&script[offset..])?;
        offset += n;
        if identifier_type_payload.len() != 1 {
            return None;
        }
        let identifier_type = identifier_type_payload[0];

        let (amount_payload, n) = decode_push_explicit(&script[offset..])?;
        offset += n;
        let amount_bytes: [u8; 8] = amount_payload.try_into().ok()?;
        let amount = decode_uint_from_int_state_payload(&amount_bytes)?;

        let (digest_payload, n) = decode_push_explicit(&script[offset..])?;
        offset += n;
        let extended_state_digest: [u8; 32] = digest_payload.try_into().ok()?;

        if offset != script.len() {
            return None; // reject trailing bytes
        }

        Some(Self { owner_identifier, identifier_type, amount, extended_state_digest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Kcc20State {
        Kcc20State::new([0x11u8; 32], identifier_type::PUBKEY, 1_000_000, [0x22u8; 32])
    }

    #[test]
    fn encode_decode_round_trip() {
        let state = sample();
        let encoded = state.encode_script().unwrap();
        assert_eq!(encoded.len(), Kcc20State::ENCODED_LEN);
        let decoded = Kcc20State::decode(&encoded).expect("decode");
        assert_eq!(decoded, state);
    }

    #[test]
    fn encode_decode_round_trip_all_identifier_types() {
        for identifier_type in [
            identifier_type::PUBKEY,
            identifier_type::SCRIPT_HASH,
            identifier_type::COVENANT_ID,
        ] {
            let state = Kcc20State::new([0xab; 32], identifier_type, 42, [0xcd; 32]);
            let encoded = state.encode_script().unwrap();
            assert_eq!(Kcc20State::decode(&encoded), Some(state));
        }
    }

    #[test]
    fn encode_decode_round_trip_zero_amount() {
        let state = Kcc20State::new([0x01; 32], identifier_type::PUBKEY, 0, [0x02; 32]);
        let encoded = state.encode_script().unwrap();
        assert_eq!(Kcc20State::decode(&encoded), Some(state));
    }

    #[test]
    fn encode_decode_round_trip_max_representable_amount() {
        let state = Kcc20State::new(
            [0x03; 32],
            identifier_type::PUBKEY,
            super::super::KCC1_INT_MAX_MAGNITUDE,
            [0x04; 32],
        );
        let encoded = state.encode_script().unwrap();
        assert_eq!(Kcc20State::decode(&encoded), Some(state));
    }

    #[test]
    fn field_order_is_owner_identifier_then_identifier_type_then_amount_then_digest() {
        let state = sample();
        let encoded = state.encode_script().unwrap();
        // owner_identifier: OP_DATA_32 || 32 bytes
        assert_eq!(encoded[0], 0x20);
        assert_eq!(&encoded[1..33], &[0x11u8; 32]);
        // identifier_type: OP_DATA_1 || 1 byte
        assert_eq!(encoded[33], 0x01);
        assert_eq!(encoded[34], identifier_type::PUBKEY);
        // amount: OP_DATA_8 || 8 bytes (LE signed-magnitude)
        assert_eq!(encoded[35], 0x08);
        assert_eq!(&encoded[36..44], &1_000_000u64.to_le_bytes());
        // extended_state_digest: OP_DATA_32 || 32 bytes
        assert_eq!(encoded[44], 0x20);
        assert_eq!(&encoded[45..77], &[0x22u8; 32]);
        assert_eq!(encoded.len(), 77);
    }

    #[test]
    fn identifier_type_field_always_uses_push_explicit_even_for_value_zero() {
        // identifier_type::PUBKEY == 0x00: PushExplicit must still emit
        // OP_DATA_1 || 0x00, NOT OP_0 -- the payload length is 1, not 0.
        let state = Kcc20State::new([0; 32], identifier_type::PUBKEY, 1, [0; 32]);
        let encoded = state.encode_script().unwrap();
        assert_eq!(encoded[33], 0x01);
        assert_eq!(encoded[34], 0x00);
    }

    #[test]
    fn amount_over_kcc1_int_max_magnitude_fails_to_encode() {
        let state = Kcc20State::new([0; 32], identifier_type::PUBKEY, u64::MAX, [0; 32]);
        assert!(state.encode_script().is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let state = sample();
        let mut encoded = state.encode_script().unwrap();
        encoded.push(0xff);
        assert_eq!(Kcc20State::decode(&encoded), None);
    }

    #[test]
    fn decode_rejects_missing_field() {
        let state = sample();
        let encoded = state.encode_script().unwrap();
        // Truncate right before the last field (extended_state_digest).
        assert_eq!(Kcc20State::decode(&encoded[..44]), None);
    }

    #[test]
    fn decode_rejects_malformed_identifier_type_length() {
        // Hand-craft: owner_identifier ok, but identifier_type pushed as 2 bytes.
        let mut script = push_explicit(&[0x11u8; 32]);
        script.extend_from_slice(&push_explicit(&[0x00, 0x00])); // wrong length
        script.extend_from_slice(&push_explicit(&encode_uint_as_int_state_payload(1).unwrap()));
        script.extend_from_slice(&push_explicit(&[0x22u8; 32]));
        assert_eq!(Kcc20State::decode(&script), None);
    }

    #[test]
    fn decode_rejects_non_canonical_push_for_owner_identifier() {
        // owner_identifier (32 bytes) pushed via OP_PUSHDATA1 instead of
        // OP_DATA_32 -- not canonical PushExplicit.
        let mut script = vec![0x4c, 32];
        script.extend_from_slice(&[0x11u8; 32]);
        script.extend_from_slice(&push_explicit(&[identifier_type::PUBKEY]));
        script.extend_from_slice(&push_explicit(&encode_uint_as_int_state_payload(1).unwrap()));
        script.extend_from_slice(&push_explicit(&[0x22u8; 32]));
        assert_eq!(Kcc20State::decode(&script), None);
    }

    #[test]
    fn decode_rejects_negative_amount() {
        // Hand-craft a state whose amount payload has the sign bit set.
        let mut script = push_explicit(&[0x11u8; 32]);
        script.extend_from_slice(&push_explicit(&[identifier_type::PUBKEY]));
        let negative_five = super::super::encode_int_state_payload(-5);
        script.extend_from_slice(&push_explicit(&negative_five));
        script.extend_from_slice(&push_explicit(&[0x22u8; 32]));
        assert_eq!(Kcc20State::decode(&script), None);
    }

    #[test]
    fn decode_empty_script_fails() {
        assert_eq!(Kcc20State::decode(&[]), None);
    }
}
