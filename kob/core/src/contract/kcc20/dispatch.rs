//! KCC20 entrypoint dispatch (kcc-0001 §6): `FunctionSignature`,
//! `dispatch_tag` computation, and a 2-entrypoint dispatch bytecode skeleton
//! for `transfer` / `transfer_delegator` (kcc-0020 "## Transfer Interface").
//!
//! kcc-0001 §6.1:
//!
//! ```text
//! FunctionSignature = UTF8("{name}({comma-separated canonical type names})")
//! dispatch_tag      = Hash(FunctionSignature)[0:4]
//! ```
//!
//! with `Hash` = unkeyed BLAKE3 (kcc-0001 §3.1). Both are compile-time
//! constants for KCC20's fixed two entrypoints; no covenant input ever
//! chooses a name or argument list at runtime, so the tags below can be
//! (and are) computed once, off-chain, and embedded as literal 4-byte
//! constants in covenant bytecode -- on-chain, dispatch is a plain constant
//! comparison (see `build_dispatch_skeleton`).
//!
//! ## `FunctionSignature` for `transfer`: an unresolved naming question
//!
//! kcc-0020's transfer interface is declared as:
//!
//! ```text
//! transfer(State[] next_states, sig[] signatures, byte[] witnesses)
//! ```
//!
//! `sig[]` and `byte[]` are unambiguous canonical KCC1 type names (kcc-0001
//! §5.1/§5.5). `State[]` is NOT: per kcc-0001 §5.1, an array-of-records type
//! name is `TypeName(T)[]` where `T` is "its exact case-sensitive record
//! name" (§5.6), but kcc-0020 never formally declares a §5.6 record named
//! `State` (or anything else) -- it only prose-lists four fields under a
//! "## State" heading. We adopt the literal token from kcc-0020's own
//! pseudocode signature ("State") as the canonical record name for
//! `FunctionSignature` purposes. See the implementation report's ISSUE list
//! for:
//! - the naming ambiguity itself (kcc-0020 PR review discussion informally
//!   uses `KCC20State` instead, e.g. "the known `KCC20State`" -- a THIRD
//!   candidate name, distinct from both "State" and this crate's Rust type
//!   `Kcc20State`);
//! - the deeper, likely-fatal tension this creates with kcc-0001 §5.5/§5.6:
//!   an array of records is only valid when every recursively lowered leaf
//!   field has a POSITIVE FIXED payload width, but `State.amount` is an
//!   `int`, and kcc-0001 §5.3/§5.4 give `int` a FIXED 8-byte width only in
//!   its STATE-payload form -- as a standalone ARGUMENT (which is what
//!   `next_states` is, being `transfer`'s invocation data), `int` uses
//!   `PushMinimal` over a *minimal ScriptNum* representation, which is
//!   explicitly VARIABLE-width. kcc-0001 gives no encoding for "an `int`
//!   field inside a record that is itself inside an array argument", and its
//!   only worked `int[]`-shaped example (§5.7's `state.example_state_values`)
//!   is a STATE array, not an argument array. This module computes the
//!   dispatch tag anyway (the tag is just a hash of a type-name string; it
//!   does not require the named type to have a well-defined encoding), but a
//!   real `transfer.rs` (wave 2) cannot decode `next_states` until this is
//!   resolved upstream.

use crate::contract::helpers::push_index;

/// `Hash(FunctionSignature)[0:4]` (kcc-0001 §6.1), using unkeyed BLAKE3
/// (kcc-0001 §3.1) as `Hash`.
pub fn dispatch_tag(function_signature: &str) -> [u8; 4] {
    let digest = blake3::hash(function_signature.as_bytes());
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&digest.as_bytes()[0..4]);
    tag
}

/// `FunctionSignature` for `transfer` under this module's naming choice (see
/// module doc). Argument types: `State[]`, `sig[]`, `byte[]`.
pub const TRANSFER_FUNCTION_SIGNATURE: &str = "transfer(State[],sig[],byte[])";

/// `FunctionSignature` for `transfer_delegator`: no arguments (kcc-0001
/// §6.1: "the sequence of type names and commas is empty, so the signature
/// ends with `UTF8(\"()\")`").
pub const TRANSFER_DELEGATOR_FUNCTION_SIGNATURE: &str = "transfer_delegator()";

/// `transfer`'s dispatch tag under `TRANSFER_FUNCTION_SIGNATURE`.
pub fn transfer_dispatch_tag() -> [u8; 4] {
    dispatch_tag(TRANSFER_FUNCTION_SIGNATURE)
}

/// `transfer_delegator`'s dispatch tag.
pub fn transfer_delegator_dispatch_tag() -> [u8; 4] {
    dispatch_tag(TRANSFER_DELEGATOR_FUNCTION_SIGNATURE)
}

/// Which KCC20 entrypoint a sigScript selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entrypoint {
    Transfer,
    TransferDelegator,
}

impl Entrypoint {
    pub fn dispatch_tag(self) -> [u8; 4] {
        match self {
            Entrypoint::Transfer => transfer_dispatch_tag(),
            Entrypoint::TransferDelegator => transfer_delegator_dispatch_tag(),
        }
    }
}

// Local opcode bytes (named for readability; matches the values already
// used throughout `crate::contract::spot::order`'s `ops` table and
// `crate::contract::token`'s inline body bytes).
mod ops {
    pub const ROLL: u8 = 0x7a;
    pub const DUP: u8 = 0x76;
    pub const DROP: u8 = 0x75;
    pub const EQUAL: u8 = 0x87;
    pub const VERIFY: u8 = 0x69;
    pub const IF: u8 = 0x63;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const DATA4: u8 = 0x04; // OP_DATA_4
}

/// Build the KCC20 two-entrypoint dispatch SKELETON (kcc-0001 §7: for a
/// program with 2+ entrypoints the dispatch tag element is REQUIRED, and
/// dispatch itself is a plain constant comparison against the entrypoint's
/// known 4-byte tag).
///
/// `tag_depth` is the stack depth (0-based, top of stack = 0) of the
/// dispatch-tag element at the point this fragment begins executing --
/// i.e. after any state-field pushes the covenant's own bytecode performs
/// first (see `crate::contract::kcc20::state::Kcc20State`).
///
/// `on_transfer` / `on_transfer_delegator` are caller-supplied bytecode
/// fragments spliced into the two branches. **Wave-1 scope**: this function
/// only assembles the correct dispatch SHAPE (roll tag to top, compare
/// against both known constants, branch, drop the tag copy on each path);
/// it does not supply real transfer-validation bytecode for either branch --
/// see this module's parent (`mod.rs`) wave-2 placeholder note. Passing
/// empty slices produces a validly-shaped but functionally inert skeleton
/// (each branch leaves the stack in an unspecified, unfinished state -- not
/// something to run through a script engine as-is).
///
/// Bytecode shape produced:
///
/// ```text
/// <roll tag_depth>                  ; bring dispatch tag to top
/// OP_DUP
/// OP_DATA_4 <transfer_tag>
/// OP_EQUAL
/// OP_IF
///     OP_DROP                       ; discard the remaining tag copy
///     <on_transfer>
/// OP_ELSE
///     OP_DUP
///     OP_DATA_4 <transfer_delegator_tag>
///     OP_EQUAL
///     OP_VERIFY                     ; must be one of the two known tags
///     OP_DROP
///     <on_transfer_delegator>
/// OP_ENDIF
/// ```
pub fn build_dispatch_skeleton(
    tag_depth: u16,
    on_transfer: &[u8],
    on_transfer_delegator: &[u8],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(24 + on_transfer.len() + on_transfer_delegator.len());
    push_index(&mut b, tag_depth);
    b.push(ops::ROLL);

    b.push(ops::DUP);
    b.push(ops::DATA4);
    b.extend_from_slice(&transfer_dispatch_tag());
    b.push(ops::EQUAL);
    b.push(ops::IF);
    {
        b.push(ops::DROP);
        b.extend_from_slice(on_transfer);
    }
    b.push(ops::ELSE);
    {
        b.push(ops::DUP);
        b.push(ops::DATA4);
        b.extend_from_slice(&transfer_delegator_dispatch_tag());
        b.push(ops::EQUAL);
        b.push(ops::VERIFY);
        b.push(ops::DROP);
        b.extend_from_slice(on_transfer_delegator);
    }
    b.push(ops::ENDIF);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::opcodes::{disassemble, ScriptElement};

    #[test]
    fn conformance_vector_11_1_dispatch_tag() {
        // kcc-0001 §11.1: name="step", types=(int,byte[4],bool,byte)
        //   FunctionSignature = "step(int,byte[4],bool,byte)"
        //   dispatch_tag      = 2c49ed65
        let sig = "step(int,byte[4],bool,byte)";
        assert_eq!(dispatch_tag(sig), [0x2c, 0x49, 0xed, 0x65]);
    }

    #[test]
    fn conformance_vector_11_1_combined_argument_encoding() {
        // kcc-0001 §11.1: for (17, 01020304, true, 01):
        //   int 17            = 0111
        //   byte[4]           = 0401020304
        //   bool true         = 51
        //   byte 01           = 51
        //   dispatch-tag push = 042c49ed65
        //   combined          = 011104010203045151042c49ed65
        use crate::primitives::minimal_script_encode;
        use crate::contract::kcc20::push_minimal;

        let mut combined = Vec::new();
        combined.extend_from_slice(&push_minimal(&minimal_script_encode(17))); // int 17
        combined.extend_from_slice(&push_minimal(&[0x01, 0x02, 0x03, 0x04])); // byte[4]
        combined.push(0x51); // bool true (standalone bool: OP_0/OP_1, not via push_minimal)
        combined.extend_from_slice(&push_minimal(&[0x01])); // byte 01
        combined.push(0x04); // OP_DATA_4
        combined.extend_from_slice(&dispatch_tag("step(int,byte[4],bool,byte)"));

        let expected = hex::decode("011104010203045151042c49ed65").unwrap();
        assert_eq!(combined, expected);
    }

    #[test]
    fn transfer_and_transfer_delegator_tags_are_distinct() {
        // kcc-0001 §6.1: "All dispatch tags in a multi-entrypoint program
        // MUST be distinct."
        assert_ne!(transfer_dispatch_tag(), transfer_delegator_dispatch_tag());
    }

    #[test]
    fn transfer_delegator_signature_ends_with_empty_parens() {
        assert_eq!(TRANSFER_DELEGATOR_FUNCTION_SIGNATURE, "transfer_delegator()");
    }

    #[test]
    fn entrypoint_dispatch_tag_matches_free_functions() {
        assert_eq!(Entrypoint::Transfer.dispatch_tag(), transfer_dispatch_tag());
        assert_eq!(
            Entrypoint::TransferDelegator.dispatch_tag(),
            transfer_delegator_dispatch_tag()
        );
    }

    #[test]
    fn dispatch_tag_is_deterministic() {
        assert_eq!(transfer_dispatch_tag(), transfer_dispatch_tag());
    }

    #[test]
    fn skeleton_structural_shape() {
        let on_transfer = vec![0x51u8]; // placeholder: OP_1
        let on_transfer_delegator = vec![0x52u8]; // placeholder: OP_2
        let skeleton = build_dispatch_skeleton(3, &on_transfer, &on_transfer_delegator);

        let elements = disassemble(&skeleton);
        // roll(3) is a single-byte OpN push (3 <= 16) followed by OP_ROLL.
        assert!(matches!(elements[0], ScriptElement::Op(0x53))); // OP_3
        assert!(matches!(elements[1], ScriptElement::Op(0x7a))); // OP_ROLL
        assert!(matches!(elements[2], ScriptElement::Op(0x76))); // OP_DUP
        match &elements[3] {
            ScriptElement::Push(0x04, data) => assert_eq!(data, &transfer_dispatch_tag().to_vec()),
            other => panic!("expected transfer tag push, got {other:?}"),
        }
        assert!(matches!(elements[4], ScriptElement::Op(0x87))); // OP_EQUAL
        assert!(matches!(elements[5], ScriptElement::Op(0x63))); // OP_IF
        assert!(matches!(elements[6], ScriptElement::Op(0x75))); // OP_DROP
        assert!(matches!(elements[7], ScriptElement::Op(0x51))); // on_transfer placeholder
        assert!(matches!(elements[8], ScriptElement::Op(0x67))); // OP_ELSE
        assert!(matches!(elements[9], ScriptElement::Op(0x76))); // OP_DUP
        match &elements[10] {
            ScriptElement::Push(0x04, data) => {
                assert_eq!(data, &transfer_delegator_dispatch_tag().to_vec())
            }
            other => panic!("expected transfer_delegator tag push, got {other:?}"),
        }
        assert!(matches!(elements[11], ScriptElement::Op(0x87))); // OP_EQUAL
        assert!(matches!(elements[12], ScriptElement::Op(0x69))); // OP_VERIFY
        assert!(matches!(elements[13], ScriptElement::Op(0x75))); // OP_DROP
        assert!(matches!(elements[14], ScriptElement::Op(0x52))); // on_transfer_delegator placeholder
        assert!(matches!(elements[15], ScriptElement::Op(0x68))); // OP_ENDIF
        assert_eq!(elements.len(), 16);
    }

    #[test]
    fn skeleton_length_is_additive_in_branch_lengths() {
        let base = build_dispatch_skeleton(0, &[], &[]);
        let with_branches = build_dispatch_skeleton(0, &[0xaa, 0xbb], &[0xcc]);
        assert_eq!(with_branches.len(), base.len() + 3);
    }
}
