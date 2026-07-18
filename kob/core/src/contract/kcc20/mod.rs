//! KCC20 Fungible Token Covenant primitives (KCC-0020, first implementation
//! wave).
//!
//! This wave implements the covenant SURFACE only: the standard state header
//! (`state.rs`), entrypoint dispatch-tag computation and a 2-entrypoint
//! dispatch bytecode skeleton (`dispatch.rs`), the kcc-0001 P2SH sigScript
//! envelope specialized to KCC20's fixed two entrypoints (`p2sh.rs`), the
//! descriptor shape (`descriptor.rs`), and `identifier_type` ownership-check
//! bytecode (`identifier.rs`).
//!
//! Deliberately NOT implemented here (second wave, per task scope):
//!
//! ```text
//! pub mod transfer;           // wave 2 -- transfer/transfer_delegator body
//!                             // validation logic (amount preservation,
//!                             // authorization, successor-output checks).
//! pub mod borrowed_receive;   // wave 2 -- KCC20 Borrowed Receive Extension v1.
//! ```
//!
//! No CLI wiring and no engine-execution (real script-VM) tests are added in
//! this wave either. See the accompanying implementation report for the full
//! ISSUE list; several entries (in particular the `State[]` argument-encoding
//! contradiction between kcc-0020's `transfer` signature and kcc-0001
//! §5.5/§5.6's fixed-payload-width requirement for record arrays) block
//! `transfer.rs` far more than anything built in this module.
//!
//! Relationship to `crate::contract::token`: `token.rs` is KOB's existing,
//! UNCHANGED KCC20 implementation. It reads kcc-0020's "State" section as
//! three script-encoded fields (`owner_identifier`, `identifier_type`) plus
//! `amount` mapped onto the UTXO's native sompi value (see its module doc for
//! the full rationale: address-discovery stability). `Kcc20State` in this
//! module takes the OTHER reading -- `amount` as a fourth genuinely in-script
//! field, per kcc-0020's literal "every KCC20 covenant state must begin with
//! the following fields" phrasing (four fields, not three-plus-one). Both
//! readings now coexist in this crate; see the ISSUE list.

pub mod state;
pub mod dispatch;
pub mod p2sh;
pub mod descriptor;
pub mod identifier;

pub use state::*;
pub use dispatch::*;
pub use p2sh::*;
pub use descriptor::*;
pub use identifier::*;

// ============================================================================
// KCC1 (kcc-0001) §5.2 common push-encoding primitives
// ============================================================================
//
// KCC1 defines two related but distinct data-push encodings (§5.2):
//   - `PushMinimal`:  used for INVOCATION ARGUMENTS (§6.2 `PushArguments`,
//     §7 `PushMinimal(R)`).
//   - `PushExplicit`: used for ENCODED STATE FIELDS (§8.1).
// They agree on every row of the table except the two one-byte special
// cases (`OP_1`..`OP_16`, `OP_1NEGATE`): `PushMinimal` takes them for a
// matching one-byte payload; `PushExplicit` always uses the length-based
// `OP_DATA_1` form instead, even for the same payload byte.
//
// Scope note: the functions below implement the GENERIC byte-string table
// (§5.2) only. Two KCC1 scalar types are explicitly carved OUT of "apply
// PushMinimal to the canonical payload" for STANDALONE ARGUMENTS (§5.3/§5.4):
// `bool` (always `OP_0`/`OP_1`, not a payload-length computation) and `int`
// (PushMinimal is applied to the value's *minimal ScriptNum* encoding, not
// to a fixed byte-string payload). Neither is needed by this wave's actual
// call sites (`Kcc20State`'s fields are byte32/byte/int/byte32, always
// STATE-encoded via `PushExplicit`, where `int` unambiguously uses the fixed
// 8-byte form per §5.3; `transfer_delegator` takes no arguments; `transfer`'s
// own argument encoding is wave-2/ISSUE territory -- see `dispatch.rs`), so
// they are not implemented here.

const OP_0: u8 = 0x00;
const OP_1NEGATE: u8 = 0x4f;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;

/// `PushMinimal(b)` per kcc-0001 §5.2.
pub fn push_minimal(payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    if n == 0 {
        return vec![OP_0];
    }
    if n == 1 {
        let b = payload[0];
        if (0x01..=0x10).contains(&b) {
            return vec![0x50 + b]; // OP_1..OP_16
        }
        if b == 0x81 {
            return vec![OP_1NEGATE];
        }
    }
    push_length_based(payload)
}

/// `PushExplicit(b)` per kcc-0001 §5.2: `OP_0` for an empty payload, and the
/// length-based forms (table rows 3-6) for every non-empty payload -- no
/// one-byte numeric-opcode special-casing, even where `PushMinimal` would
/// apply one for the same bytes. Per kcc-0001: `PushMinimal(01) = OP_1` but
/// `PushExplicit(01) = OP_DATA_1 01`.
pub fn push_explicit(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return vec![OP_0];
    }
    push_length_based(payload)
}

/// Shared "length-based" tail of the §5.2 table (rows 3-6): used directly by
/// `push_explicit` for every non-empty payload, and by `push_minimal` once
/// the n=0 and one-byte-special cases have been ruled out.
fn push_length_based(payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = Vec::with_capacity(n + 5);
    match n {
        1..=75 => out.push(n as u8), // OP_DATA_n
        76..=255 => {
            out.push(OP_PUSHDATA1);
            out.push(n as u8);
        }
        256..=65535 => {
            out.push(OP_PUSHDATA2);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            // kcc-0001's last row caps at 2^32-1. `n` is a Rust `usize`
            // (64-bit on this build's target); a payload with n > u32::MAX
            // is not a valid PushMinimal/PushExplicit length under kcc-0001
            // at all, and this crate has no payload anywhere near that size,
            // so we do not special-case it -- see the ISSUE list entry on
            // the unspecified oversized-payload behavior.
            out.push(OP_PUSHDATA4);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Decode one `PushExplicit`-encoded field from the front of `script`.
/// Returns `(payload, bytes_consumed)`, or `None` if the bytes at the front
/// do not exactly match a canonical `PushExplicit` encoding.
///
/// kcc-0001 §8.1: "The consumed bytes MUST exactly equal `PushExplicit(payload)`."
/// A decoder must therefore reject any non-canonical push for the given
/// payload length -- e.g. a 32-byte payload pushed via `OP_PUSHDATA1` instead
/// of `OP_DATA_32`, or a length whose `OP_PUSHDATA1` byte falls outside
/// 76..=255 (which `OP_DATA_n` would have encoded more compactly), or a
/// one-byte payload pushed as `OP_1`/`OP_1NEGATE` (`PushMinimal`-only forms,
/// never valid for state).
pub fn decode_push_explicit(script: &[u8]) -> Option<(Vec<u8>, usize)> {
    let op = *script.first()?;
    match op {
        OP_0 => Some((Vec::new(), 1)),
        1..=75 => {
            let n = op as usize;
            if script.len() < 1 + n {
                return None;
            }
            Some((script[1..1 + n].to_vec(), 1 + n))
        }
        OP_PUSHDATA1 => {
            let n = *script.get(1)? as usize;
            if !(76..=255).contains(&n) {
                return None; // non-canonical: OP_DATA_n would encode this length
            }
            if script.len() < 2 + n {
                return None;
            }
            Some((script[2..2 + n].to_vec(), 2 + n))
        }
        OP_PUSHDATA2 => {
            if script.len() < 3 {
                return None;
            }
            let n = u16::from_le_bytes([script[1], script[2]]) as usize;
            if !(256..=65535).contains(&n) {
                return None;
            }
            if script.len() < 3 + n {
                return None;
            }
            Some((script[3..3 + n].to_vec(), 3 + n))
        }
        OP_PUSHDATA4 => {
            if script.len() < 5 {
                return None;
            }
            let n = u32::from_le_bytes([script[1], script[2], script[3], script[4]]) as usize;
            if n <= 65535 {
                return None;
            }
            if script.len() < 5 + n {
                return None;
            }
            Some((script[5..5 + n].to_vec(), 5 + n))
        }
        _ => None, // OP_1..OP_16 / OP_1NEGATE / anything else: not a valid PushExplicit form
    }
}

/// Decode one `PushMinimal`-encoded element from the front of `script`,
/// rejecting non-minimal encodings (e.g. a one-byte payload of `0x01` pushed
/// via `OP_DATA_1` instead of `OP_1`). Used by `p2sh.rs` to verify that the
/// final sigScript element (`R`, the redeem script) is both present and
/// minimally pushed, per kcc-0001 §7.
pub fn decode_push_minimal(script: &[u8]) -> Option<(Vec<u8>, usize)> {
    let op = *script.first()?;
    match op {
        OP_0 => Some((Vec::new(), 1)),
        0x51..=0x60 => Some((vec![op - 0x50], 1)), // OP_1..OP_16 -> payload 0x01..0x10
        OP_1NEGATE => Some((vec![0x81], 1)),
        1..=75 => {
            let n = op as usize;
            if script.len() < 1 + n {
                return None;
            }
            let payload = script[1..1 + n].to_vec();
            if n == 1 {
                let b = payload[0];
                if (0x01..=0x10).contains(&b) || b == 0x81 {
                    return None; // non-minimal: must use OP_1..OP_16/OP_1NEGATE
                }
            }
            Some((payload, 1 + n))
        }
        OP_PUSHDATA1 => {
            let n = *script.get(1)? as usize;
            if !(76..=255).contains(&n) {
                return None;
            }
            if script.len() < 2 + n {
                return None;
            }
            Some((script[2..2 + n].to_vec(), 2 + n))
        }
        OP_PUSHDATA2 => {
            if script.len() < 3 {
                return None;
            }
            let n = u16::from_le_bytes([script[1], script[2]]) as usize;
            if !(256..=65535).contains(&n) {
                return None;
            }
            if script.len() < 3 + n {
                return None;
            }
            Some((script[3..3 + n].to_vec(), 3 + n))
        }
        OP_PUSHDATA4 => {
            if script.len() < 5 {
                return None;
            }
            let n = u32::from_le_bytes([script[1], script[2], script[3], script[4]]) as usize;
            if n <= 65535 {
                return None;
            }
            if script.len() < 5 + n {
                return None;
            }
            Some((script[5..5 + n].to_vec(), 5 + n))
        }
        _ => None,
    }
}

// ============================================================================
// KCC1 §5.3 `int` STATE-payload encoding: eight-byte little-endian
// signed-magnitude.
// ============================================================================
//
// kcc-0001 §11.3's conformance vector fixes the convention: `int counter =
// -5` encodes as `0500000000000080` -- the magnitude (5) as an 8-byte LE
// unsigned integer, with the sign folded into the HIGH BIT of the LAST
// (most significant) byte. This is why the representable magnitude tops out
// at 2^63-1 rather than 2^64-1 (kcc-0001 §5.3's own stated `int` range is
// `-(2^63-1) <= value <= 2^63-1`) -- one bit is spent on the sign, not on
// magnitude. See the ISSUE list entry on `Kcc20State::amount: u64`, whose
// Rust type nominally allows values up to `2^64-1`.

/// Maximum magnitude representable by the KCC1 8-byte signed-magnitude `int`
/// state payload: `2^63 - 1` (`i64::MAX`).
pub const KCC1_INT_MAX_MAGNITUDE: u64 = i64::MAX as u64;

/// Encode a non-negative magnitude (e.g. a token `amount`) as the 8-byte
/// KCC1 `int` state payload (sign bit always clear).
///
/// Errors (via `crate::KobError::Contract`) if `magnitude >
/// KCC1_INT_MAX_MAGNITUDE` -- such a value has no valid KCC1 `int` state
/// encoding at all (see module note above).
pub fn encode_uint_as_int_state_payload(magnitude: u64) -> crate::Result<[u8; 8]> {
    if magnitude > KCC1_INT_MAX_MAGNITUDE {
        return Err(crate::KobError::Contract(format!(
            "value {magnitude} exceeds the KCC1 int state-payload max magnitude 2^63-1 ({KCC1_INT_MAX_MAGNITUDE})"
        )));
    }
    Ok(magnitude.to_le_bytes())
}

/// Encode a signed KCC1 `int` state payload (general form; exercised by the
/// round-trip / conformance-vector unit tests below -- `Kcc20State.amount`
/// itself only ever uses the non-negative form above).
pub fn encode_int_state_payload(value: i64) -> [u8; 8] {
    let magnitude = value.unsigned_abs();
    let mut bytes = magnitude.to_le_bytes();
    if value < 0 {
        bytes[7] |= 0x80;
    }
    bytes
}

/// Decode an 8-byte KCC1 `int` state payload to its mathematical value.
///
/// Accepts both zero encodings -- "positive zero" (`00` * 8) and "negative
/// zero" (`00` * 7 `80`) -- as the value `0`. kcc-0001 does not say whether
/// an encoder must avoid emitting "negative zero" or whether a decoder must
/// reject it; see the ISSUE list.
pub fn decode_int_state_payload(bytes: &[u8; 8]) -> i64 {
    let sign_negative = bytes[7] & 0x80 != 0;
    let mut magnitude_bytes = *bytes;
    magnitude_bytes[7] &= 0x7f;
    let magnitude = u64::from_le_bytes(magnitude_bytes);
    if sign_negative {
        -(magnitude as i64)
    } else {
        magnitude as i64
    }
}

/// Decode an 8-byte KCC1 `int` state payload known to represent a
/// non-negative quantity (e.g. `Kcc20State.amount`).
///
/// Returns `None` if the sign bit is set (a "negative token amount") -- see
/// the ISSUE list on whether kcc-0020 actually forbids this, or whether KOB
/// is imposing its own additional constraint here.
pub fn decode_uint_from_int_state_payload(bytes: &[u8; 8]) -> Option<u64> {
    if bytes[7] & 0x80 != 0 {
        return None;
    }
    Some(u64::from_le_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PushMinimal / PushExplicit: table-row coverage -------------------

    #[test]
    fn push_minimal_empty_is_op0() {
        assert_eq!(push_minimal(&[]), vec![0x00]);
    }

    #[test]
    fn push_explicit_empty_is_op0() {
        assert_eq!(push_explicit(&[]), vec![0x00]);
    }

    #[test]
    fn push_minimal_one_byte_special_opcodes() {
        // b = 01..10 (hex) -> OP_1..OP_16
        for (b, expected_op) in [(0x01u8, 0x51u8), (0x02, 0x52), (0x10, 0x60)] {
            assert_eq!(push_minimal(&[b]), vec![expected_op]);
        }
        // b = 81 -> OP_1NEGATE
        assert_eq!(push_minimal(&[0x81]), vec![0x4f]);
    }

    #[test]
    fn push_explicit_never_uses_one_byte_special_opcodes() {
        // Same payload bytes as above, but PushExplicit always uses OP_DATA_1.
        for b in [0x01u8, 0x02, 0x10, 0x81] {
            assert_eq!(push_explicit(&[b]), vec![0x01, b]);
        }
    }

    #[test]
    fn kcc1_spec_example_push_minimal_vs_explicit() {
        // kcc-0001 §5.2: "PushMinimal(01) = OP_1; PushExplicit(01) = OP_DATA_1 01"
        assert_eq!(push_minimal(&[0x01]), vec![0x51]);
        assert_eq!(push_explicit(&[0x01]), vec![0x01, 0x01]);
    }

    #[test]
    fn push_data_1_to_75_uses_op_data_n() {
        let payload = vec![0xab; 75];
        let m = push_minimal(&payload);
        assert_eq!(m[0], 75);
        assert_eq!(&m[1..], payload.as_slice());
        let e = push_explicit(&payload);
        assert_eq!(e, m);
    }

    #[test]
    fn push_data_76_to_255_uses_pushdata1() {
        let payload = vec![0xcd; 200];
        let enc = push_explicit(&payload);
        assert_eq!(enc[0], OP_PUSHDATA1);
        assert_eq!(enc[1], 200);
        assert_eq!(&enc[2..], payload.as_slice());
    }

    #[test]
    fn push_data_256_to_65535_uses_pushdata2() {
        let payload = vec![0xef; 300];
        let enc = push_explicit(&payload);
        assert_eq!(enc[0], OP_PUSHDATA2);
        assert_eq!(u16::from_le_bytes([enc[1], enc[2]]), 300);
        assert_eq!(&enc[3..], payload.as_slice());
    }

    #[test]
    fn push_data_65536_plus_uses_pushdata4() {
        let payload = vec![0x11u8; 70_000];
        let enc = push_explicit(&payload);
        assert_eq!(enc[0], OP_PUSHDATA4);
        assert_eq!(
            u32::from_le_bytes([enc[1], enc[2], enc[3], enc[4]]),
            70_000
        );
        assert_eq!(enc.len(), 5 + 70_000);
    }

    // ---- kcc-0001 conformance vectors --------------------------------------

    #[test]
    fn conformance_vector_11_2_p2sh_envelope_push_minimal_r() {
        // R = 51 (OP_1, one byte). PushMinimal(R) must be 0151, NOT OP_1 --
        // the payload byte 0x51 is outside the 01..10 special range.
        let r = [0x51u8];
        assert_eq!(push_minimal(&r), vec![0x01, 0x51]);
    }

    #[test]
    fn conformance_vector_11_3_state_encoding() {
        // kcc-0001 §11.3: pubkey key = 07^32, int counter = -5, bool enabled = true.
        let key = [0x07u8; 32];
        let counter_payload = encode_int_state_payload(-5);
        assert_eq!(counter_payload, [0x05, 0, 0, 0, 0, 0, 0, 0x80]);
        let enabled_payload = [0x01u8]; // bool true canonical payload

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&push_explicit(&key));
        encoded.extend_from_slice(&push_explicit(&counter_payload));
        encoded.extend_from_slice(&push_explicit(&enabled_payload));

        let expected = hex::decode(
            "2007070707070707070707070707070707070707070707070707070707070707070805\
             000000000000800101",
        )
        .unwrap();
        assert_eq!(encoded, expected);
    }

    // ---- decode_push_explicit / decode_push_minimal round trips -----------

    #[test]
    fn decode_push_explicit_round_trip_all_length_classes() {
        for len in [0usize, 1, 32, 75, 76, 255, 256, 65535, 70_000] {
            let payload = vec![0xaa; len];
            let encoded = push_explicit(&payload);
            let (decoded, consumed) = decode_push_explicit(&encoded).expect("decode");
            assert_eq!(decoded, payload, "len={len}");
            assert_eq!(consumed, encoded.len(), "len={len}");
        }
    }

    #[test]
    fn decode_push_explicit_rejects_trailing_bytes_not_consumed_by_caller() {
        // decode_push_explicit itself only reports what it consumed; callers
        // (state.rs) are responsible for rejecting leftovers. Verify the
        // consumed count is exactly right so that check is sound.
        let mut script = push_explicit(&[0xaa; 32]);
        script.push(0xff); // trailing junk
        let (_, consumed) = decode_push_explicit(&script).unwrap();
        assert_eq!(consumed, 33); // does NOT swallow the trailing 0xff
    }

    #[test]
    fn decode_push_explicit_rejects_non_canonical_pushdata1_for_short_length() {
        // A 10-byte payload canonically pushed via OP_DATA_10, not PUSHDATA1.
        let mut script = vec![OP_PUSHDATA1, 10];
        script.extend_from_slice(&[0xaa; 10]);
        assert_eq!(decode_push_explicit(&script), None);
    }

    #[test]
    fn decode_push_explicit_rejects_minimal_only_opcodes() {
        // OP_1 (0x51) is never a valid PushExplicit encoding.
        assert_eq!(decode_push_explicit(&[0x51]), None);
        // OP_1NEGATE (0x4f) is never a valid PushExplicit encoding.
        assert_eq!(decode_push_explicit(&[0x4f]), None);
    }

    #[test]
    fn decode_push_minimal_round_trip() {
        for payload in [
            vec![],
            vec![0x01],
            vec![0x10],
            vec![0x81],
            vec![0x51], // NOT a one-byte special case (0x51 outside 01..10 and != 0x81)
            vec![0xaa; 75],
            vec![0xaa; 200],
        ] {
            let encoded = push_minimal(&payload);
            let (decoded, consumed) = decode_push_minimal(&encoded).expect("decode");
            assert_eq!(decoded, payload);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn decode_push_minimal_rejects_non_minimal_one_byte_data_push() {
        // 0x01 pushed via OP_DATA_1 (explicit form) is NOT minimal.
        assert_eq!(decode_push_minimal(&[0x01, 0x01]), None);
    }

    // ---- int state-payload encode/decode -----------------------------------

    #[test]
    fn int_state_payload_round_trip_signed() {
        for v in [0i64, 1, -1, 5, -5, i64::MAX, -(i64::MAX)] {
            let enc = encode_int_state_payload(v);
            assert_eq!(decode_int_state_payload(&enc), v);
        }
    }

    #[test]
    fn int_state_payload_negative_five_matches_spec_vector() {
        assert_eq!(encode_int_state_payload(-5), [0x05, 0, 0, 0, 0, 0, 0, 0x80]);
    }

    #[test]
    fn uint_state_payload_round_trip() {
        for v in [0u64, 1, 5, KCC1_INT_MAX_MAGNITUDE] {
            let enc = encode_uint_as_int_state_payload(v).unwrap();
            assert_eq!(decode_uint_from_int_state_payload(&enc), Some(v));
        }
    }

    #[test]
    fn uint_state_payload_rejects_magnitude_over_i64_max() {
        assert!(encode_uint_as_int_state_payload(KCC1_INT_MAX_MAGNITUDE + 1).is_err());
        assert!(encode_uint_as_int_state_payload(u64::MAX).is_err());
    }

    #[test]
    fn uint_decode_rejects_sign_bit_set() {
        let mut negative_one = encode_int_state_payload(-1);
        assert_eq!(decode_uint_from_int_state_payload(&negative_one), None);
        // "negative zero" (sign bit set, magnitude 0) is also rejected by the
        // non-negative-only decoder, even though its mathematical value is 0.
        negative_one = [0, 0, 0, 0, 0, 0, 0, 0x80];
        assert_eq!(decode_uint_from_int_state_payload(&negative_one), None);
    }

    #[test]
    fn int_state_payload_positive_and_negative_zero_both_decode_to_zero() {
        let positive_zero = [0u8; 8];
        let negative_zero = [0, 0, 0, 0, 0, 0, 0, 0x80];
        assert_eq!(decode_int_state_payload(&positive_zero), 0);
        assert_eq!(decode_int_state_payload(&negative_zero), 0);
        assert_ne!(positive_zero, negative_zero); // two byte-strings, one value
    }
}
