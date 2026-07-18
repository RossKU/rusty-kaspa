//! KCC20 `identifier_type` ownership-verification bytecode (kcc-0020
//! "## State"):
//!
//! ```text
//! IDENTIFIER_PUBKEY      = 0x00
//! IDENTIFIER_SCRIPT_HASH = 0x01
//! IDENTIFIER_COVENANT_ID = 0x02
//! ```
//!
//! kcc-0020 defines what each `identifier_type` value means -- how
//! `owner_identifier` is *interpreted* -- but not, for `SCRIPT_HASH` /
//! `COVENANT_ID`, what a `transfer` implementation MUST actually check to
//! prove ownership against that interpreted value. This is a live,
//! explicitly unsettled question in the KCC20 review thread itself, e.g.
//! (PR review, paraphrased identifiers per task instructions): a reviewer
//! asking "why distinguish `identifier_type` at all -- why not collapse
//! ownership into a single generic witness/hint scheme (pubkey / script_hash
//! / cov_id / ecdsa / cov_id_plus_template), decided per-transfer instead of
//! fixed per-covenant?" -- i.e. whether `identifier_type` should even be a
//! static per-covenant enum is itself contested, not just the verification
//! rule for two of its three current values.
//!
//! Decision for this wave: implement `PUBKEY` (the one behaviorally
//! unambiguous case -- `owner_identifier` literally IS a 32-byte Schnorr
//! public key, verified via `OpCheckSigVerify`, matching the existing
//! `crate::contract::token::TOKEN_UNIT_BODY` precedent) and leave
//! `SCRIPT_HASH`/`COVENANT_ID` explicitly `unimplemented` (returning a typed
//! error identifying which value and why), rather than guessing a
//! verification rule. Guessing risks quietly encoding one PR participant's
//! proposal as if it were settled behavior; this task's stated purpose is to
//! surface exactly this kind of gap, not paper over it.

// `identifier_type` constants live in `state.rs` (kcc-0020 defines them under
// "## State", alongside the rest of `Kcc20State`); re-used here rather than
// re-declared, to avoid two co-existing copies of the same enum and the
// resulting ambiguous-glob-reexport from `mod.rs`'s `pub use {state,
// identifier}::*;`.
use super::state::identifier_type;

/// Result of attempting to emit an ownership-verification bytecode fragment
/// for a given `identifier_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierVerificationError {
    /// `identifier_type` is not one of the three kcc-0020-defined values.
    UnknownIdentifierType(u8),
    /// kcc-0020 defines the value's *meaning* but not (yet) a normative
    /// ownership-verification rule for it -- see the module doc and the
    /// implementation report's ISSUE list.
    VerificationRuleUndefined { identifier_type: u8, name: &'static str },
}

impl std::fmt::Display for IdentifierVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownIdentifierType(v) => {
                write!(f, "unknown KCC20 identifier_type {v:#04x}")
            }
            Self::VerificationRuleUndefined { identifier_type, name } => write!(
                f,
                "KCC20 identifier_type {name} ({identifier_type:#04x}) has no defined \
                 ownership-verification rule in kcc-0020 (open PR question)"
            ),
        }
    }
}

impl std::error::Error for IdentifierVerificationError {}

/// Emit the `identifier_type`-DEPENDENT ownership-verification bytecode
/// fragment, assuming `owner_identifier` is on top of the stack (and is the
/// only `Kcc20State` field still on the stack) at the point this fragment
/// begins executing -- the caller is responsible for dropping the other
/// three `Kcc20State` fields (`identifier_type`, `amount`,
/// `extended_state_digest`) before or after splicing this in, per its own
/// body layout (see `crate::contract::token::TOKEN_UNIT_BODY` for the
/// analogous existing precedent, which drops `identifier_type` immediately
/// before its own `OpCheckSigVerify`).
///
/// - `PUBKEY`: `owner_identifier` is checked directly as a Schnorr public
///   key via `OpCheckSigVerify` (`0xad`).
/// - `SCRIPT_HASH` / `COVENANT_ID`: `Err(VerificationRuleUndefined)` --
///   see module doc.
/// - any other byte value: `Err(UnknownIdentifierType)`.
pub fn emit_ownership_check(identifier_type: u8) -> Result<Vec<u8>, IdentifierVerificationError> {
    match identifier_type {
        identifier_type::PUBKEY => Ok(vec![0xad]), // OpCheckSigVerify
        identifier_type::SCRIPT_HASH => Err(IdentifierVerificationError::VerificationRuleUndefined {
            identifier_type,
            name: "SCRIPT_HASH",
        }),
        identifier_type::COVENANT_ID => Err(IdentifierVerificationError::VerificationRuleUndefined {
            identifier_type,
            name: "COVENANT_ID",
        }),
        other => Err(IdentifierVerificationError::UnknownIdentifierType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_emits_checksigverify() {
        assert_eq!(emit_ownership_check(identifier_type::PUBKEY), Ok(vec![0xad]));
    }

    #[test]
    fn script_hash_is_explicitly_unimplemented() {
        match emit_ownership_check(identifier_type::SCRIPT_HASH) {
            Err(IdentifierVerificationError::VerificationRuleUndefined { identifier_type, name }) => {
                assert_eq!(identifier_type, 0x01);
                assert_eq!(name, "SCRIPT_HASH");
            }
            other => panic!("expected VerificationRuleUndefined, got {other:?}"),
        }
    }

    #[test]
    fn covenant_id_is_explicitly_unimplemented() {
        match emit_ownership_check(identifier_type::COVENANT_ID) {
            Err(IdentifierVerificationError::VerificationRuleUndefined { identifier_type, name }) => {
                assert_eq!(identifier_type, 0x02);
                assert_eq!(name, "COVENANT_ID");
            }
            other => panic!("expected VerificationRuleUndefined, got {other:?}"),
        }
    }

    #[test]
    fn unknown_identifier_type_is_rejected() {
        for v in [0x03u8, 0xff] {
            assert_eq!(
                emit_ownership_check(v),
                Err(IdentifierVerificationError::UnknownIdentifierType(v))
            );
        }
    }

    #[test]
    fn identifier_type_constants_match_kcc_0020() {
        assert_eq!(identifier_type::PUBKEY, 0x00);
        assert_eq!(identifier_type::SCRIPT_HASH, 0x01);
        assert_eq!(identifier_type::COVENANT_ID, 0x02);
    }

    #[test]
    fn error_display_is_informative() {
        let e = emit_ownership_check(identifier_type::SCRIPT_HASH).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("SCRIPT_HASH"));
        assert!(msg.contains("kcc-0020"));
    }
}
