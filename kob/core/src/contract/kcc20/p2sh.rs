//! KCC1 §7 P2SH Covenant Envelope, specialized to KCC20's fixed two
//! entrypoints (`transfer`, `transfer_delegator`).
//!
//! kcc-0001 §7 sigScript layout:
//!
//! ```text
//! PushArguments(arguments)
//! [OP_DATA_4 dispatch_tag]
//! PushMinimal(R)
//! ```
//!
//! The dispatch-tag element "MUST be omitted for a program with exactly one
//! entrypoint" and "MUST be present" for two or more. Every KCC20 covenant
//! has exactly two entrypoints, so the tag is unconditionally required here
//! -- there is no single-entrypoint KCC20 form.
//!
//! The script public key itself (`OP_BLAKE2B OP_DATA_32 Blake2b(R) OP_EQUAL`)
//! is unchanged from KOB's existing P2SH machinery; see `crate::p2sh::build_p2sh`
//! (re-exported from `kob-settle`, already used by `token.rs`).

use super::dispatch::{transfer_delegator_dispatch_tag, transfer_dispatch_tag, Entrypoint};
use super::{decode_push_minimal, push_minimal};

const OP_DATA_4: u8 = 0x04;

/// Build a KCC20 sigScript: `pushed_arguments || OP_DATA_4 || dispatch_tag ||
/// PushMinimal(redeem_script)`.
///
/// `pushed_arguments` MUST already be the caller's fully `PushMinimal`-
/// encoded (kcc-0001 §6.2 `PushArguments`) entrypoint arguments. Encoding
/// `next_states` / `signatures` / `witnesses` for `transfer` is wave-2 scope
/// (see `dispatch.rs`'s `State[]` ISSUE note) -- this builder only assembles
/// the ENVELOPE around whatever argument bytes the caller supplies. For
/// `transfer_delegator` (no arguments), pass an empty slice.
pub fn build_sigscript(entrypoint: Entrypoint, pushed_arguments: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let tag = entrypoint.dispatch_tag();
    let minimal_r = push_minimal(redeem_script);
    let mut ss = Vec::with_capacity(pushed_arguments.len() + 1 + 4 + minimal_r.len());
    ss.extend_from_slice(pushed_arguments);
    ss.push(OP_DATA_4);
    ss.extend_from_slice(&tag);
    ss.extend_from_slice(&minimal_r);
    ss
}

/// Errors from `parse_sigscript`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigscriptError {
    /// Script shorter than `arguments_len + 5` (tag + at least an `OP_0` R push).
    TooShort,
    /// Byte at `arguments_len` is not `OP_DATA_4`.
    MissingDispatchTag,
    /// The bytes after the dispatch tag are not a valid, minimally-encoded
    /// `PushMinimal` element, or leave bytes unconsumed after it (kcc-0001
    /// §7: "`PushMinimal(R)` MUST be the final push in the signature
    /// script").
    RedeemScriptNotFinalMinimalPush,
    /// The dispatch tag byte value does not match either known KCC20 tag.
    UnknownDispatchTag([u8; 4]),
}

/// Parse a KCC20 sigScript produced by `build_sigscript`, given the caller-
/// known byte length of the leading `pushed_arguments` region.
///
/// kcc-0001 does not define a self-delimiting encoding for "where the
/// argument region ends" in general (see the implementation report's ISSUE
/// list) -- a real decoder needs the Program ABI's argument type list to
/// know `arguments_len` up front, exactly as this function requires it as a
/// parameter. This function only re-validates and splits the ENVELOPE
/// (dispatch tag placement + "R is the final, minimal push"); it does not
/// decode `pushed_arguments` itself.
pub fn parse_sigscript(
    script: &[u8],
    arguments_len: usize,
) -> Result<(Vec<u8>, Entrypoint, Vec<u8>), SigscriptError> {
    if script.len() < arguments_len + 1 + 4 + 1 {
        return Err(SigscriptError::TooShort);
    }
    let pushed_arguments = script[..arguments_len].to_vec();
    let rest = &script[arguments_len..];
    if rest[0] != OP_DATA_4 {
        return Err(SigscriptError::MissingDispatchTag);
    }
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&rest[1..5]);

    let (redeem_script, consumed) =
        decode_push_minimal(&rest[5..]).ok_or(SigscriptError::RedeemScriptNotFinalMinimalPush)?;
    if 5 + consumed != rest.len() {
        return Err(SigscriptError::RedeemScriptNotFinalMinimalPush);
    }

    let entrypoint = if tag == transfer_dispatch_tag() {
        Entrypoint::Transfer
    } else if tag == transfer_delegator_dispatch_tag() {
        Entrypoint::TransferDelegator
    } else {
        return Err(SigscriptError::UnknownDispatchTag(tag));
    };

    Ok((pushed_arguments, entrypoint, redeem_script))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_round_trip_transfer_delegator() {
        let redeem_script = vec![0x51u8, 0x52, 0x53]; // arbitrary stand-in bytecode
        let ss = build_sigscript(Entrypoint::TransferDelegator, &[], &redeem_script);
        let (args, entrypoint, rs) = parse_sigscript(&ss, 0).expect("parse");
        assert!(args.is_empty());
        assert_eq!(entrypoint, Entrypoint::TransferDelegator);
        assert_eq!(rs, redeem_script);
    }

    #[test]
    fn build_parse_round_trip_transfer_with_arguments() {
        let pushed_arguments = vec![0x02, 0xaa, 0xbb]; // stand-in pre-encoded PushArguments
        let redeem_script = vec![0x75u8; 40];
        let ss = build_sigscript(Entrypoint::Transfer, &pushed_arguments, &redeem_script);
        let (args, entrypoint, rs) = parse_sigscript(&ss, pushed_arguments.len()).expect("parse");
        assert_eq!(args, pushed_arguments);
        assert_eq!(entrypoint, Entrypoint::Transfer);
        assert_eq!(rs, redeem_script);
    }

    #[test]
    fn dispatch_tag_is_op_data_4_and_present() {
        // kcc-0001 §7: for 2+ entrypoints the tag MUST be present and use
        // OP_DATA_4.
        let ss = build_sigscript(Entrypoint::Transfer, &[], &[0x51]);
        assert_eq!(ss[0], 0x04);
        assert_eq!(&ss[1..5], &transfer_dispatch_tag());
    }

    #[test]
    fn conformance_vector_11_2_minimal_r_is_final_push() {
        // kcc-0001 §11.2: R = 51 (one byte, OP_1) -> PushMinimal(R) = 0151.
        let ss = build_sigscript(Entrypoint::TransferDelegator, &[], &[0x51]);
        assert_eq!(&ss[ss.len() - 2..], &[0x01, 0x51]);
    }

    #[test]
    fn parse_rejects_wrong_dispatch_tag_marker() {
        let mut ss = build_sigscript(Entrypoint::Transfer, &[], &[0x51]);
        ss[0] = 0x05; // corrupt OP_DATA_4 marker
        assert_eq!(parse_sigscript(&ss, 0), Err(SigscriptError::MissingDispatchTag));
    }

    #[test]
    fn parse_rejects_unknown_tag() {
        let mut ss = build_sigscript(Entrypoint::Transfer, &[], &[0x51]);
        ss[1] ^= 0xff; // corrupt tag bytes
        match parse_sigscript(&ss, 0) {
            Err(SigscriptError::UnknownDispatchTag(_)) => {}
            other => panic!("expected UnknownDispatchTag, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_non_final_redeem_script_push() {
        let mut ss = build_sigscript(Entrypoint::Transfer, &[], &[0x51]);
        ss.push(0xff); // trailing junk after PushMinimal(R)
        assert_eq!(
            parse_sigscript(&ss, 0),
            Err(SigscriptError::RedeemScriptNotFinalMinimalPush)
        );
    }

    #[test]
    fn parse_rejects_too_short_script() {
        assert_eq!(parse_sigscript(&[0x04, 0, 0, 0, 0], 0), Err(SigscriptError::TooShort));
    }
}
