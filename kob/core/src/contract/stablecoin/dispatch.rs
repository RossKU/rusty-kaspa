//! Robust stablecoin covenant `op_type` dispatch (`STABLECOIN_ROBUST_DESIGN.md`
//! §4): generalizes `crate::contract::kcc20::dispatch::build_dispatch_skeleton`'s
//! roll/DUP/compare/IF/ELSE/ENDIF shape from a 2-way tag compare to a 6-way
//! `op_type` discriminant BYTE compare (`0x00..0x03, 0x05..0x06`; `0x04` is
//! reserved and intentionally absent -- MINT lives in a separate,
//! self-continuing mint-authority contract, §9, and never attests against
//! this covenant).
//!
//! Bytecode shape (nested, one `IF`/`ELSE`/`ENDIF` level per branch):
//!
//! ```text
//! <roll tag_depth>                  ; bring op_type selector to top
//! OP_DUP OP_DATA_1 0x00 OP_EQUAL
//! OP_IF
//!     OP_DROP
//!     <on_transfer>                 ; 0x00 TRANSFER
//! OP_ELSE
//!     OP_DUP OP_DATA_1 0x01 OP_EQUAL
//!     OP_IF
//!         OP_DROP
//!         <on_freeze>               ; 0x01 FREEZE
//!     OP_ELSE
//!         OP_DUP OP_DATA_1 0x02 OP_EQUAL
//!         OP_IF
//!             OP_DROP
//!             <on_seize>            ; 0x02 SEIZE
//!         OP_ELSE
//!             OP_DUP OP_DATA_1 0x03 OP_EQUAL
//!             OP_IF
//!                 OP_DROP
//!                 <on_burn>         ; 0x03 BURN
//!             OP_ELSE
//!                 OP_DUP OP_DATA_1 0x05 OP_EQUAL
//!                 OP_IF
//!                     OP_DROP
//!                     <on_rotate>   ; 0x05 ROTATE
//!                 OP_ELSE
//!                     OP_DUP OP_DATA_1 0x06 OP_EQUAL OP_VERIFY   ; hard-reject anything else (incl. 0x04)
//!                     OP_DROP
//!                     <on_migrate>  ; 0x06 MIGRATE
//!                 OP_ENDIF
//!             OP_ENDIF
//!         OP_ENDIF
//!     OP_ENDIF
//! OP_ENDIF
//! ```
//!
//! The final (MIGRATE) rung has no further `ELSE` fallback (any non-matching
//! byte, including the reserved `0x04`, must hard-abort via `OP_VERIFY`
//! rather than fall through), but it still needs the leading `OP_DUP`: every
//! rung's shape consumes a THROWAWAY COPY of the tag in its compare (`OP_DUP`
//! ... `OP_EQUAL`), leaving the ORIGINAL tag on the stack for the trailing
//! `OP_DROP` to remove once matched -- omitting the `OP_DUP` here would make
//! `OP_EQUAL` consume the tag directly (no copy to spare), so the trailing
//! `OP_DROP` would silently consume the next REAL data-stack item instead
//! (`body.rs`'s bug-fix note, `build_op_type_dispatch`, has the full story).
//!
//! `on_transfer` (0x00), `on_freeze` (0x01), `on_seize` (0x02), `on_burn`
//! (0x03), and `on_migrate` (0x06) wire real bytecode; `on_rotate` (0x05) is
//! the shared [`UNIMPLEMENTED_BRANCH_STUB`] placeholder (a bare `OP_0`, so
//! the script hard-fails if that branch is ever reached) -- `ROTATE` is
//! **deferred to post-Live** (Decision 2026-07-19, option B: it only becomes
//! meaningful once role keys are verified against `role_registry_root`
//! rather than baked; see `body.rs`'s top doc and
//! `STABLECOIN_ROBUST_DESIGN.md`'s "Deferred to post-Live robustness
//! upgrade").

use crate::contract::helpers::push_index;

/// Local opcode bytes (named for readability; matches the values already
/// used throughout this crate's other dispatch/body builders).
mod ops {
    pub const ROLL: u8 = 0x7a;
    pub const DUP: u8 = 0x76;
    pub const DROP: u8 = 0x75;
    pub const EQUAL: u8 = 0x87;
    pub const VERIFY: u8 = 0x69;
    pub const IF: u8 = 0x63;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const DATA1: u8 = 0x01;
}

/// `op_type` discriminant byte values (§4 branch table). Re-exported here
/// (mirroring [`super::attestation::op_type`]) so dispatch construction and
/// attestation-preimage construction read from a single conceptual source;
/// both modules define the SAME byte values -- see the `op_type_values_match`
/// test tying them together.
pub mod op_type {
    pub const TRANSFER: u8 = 0x00;
    pub const FREEZE: u8 = 0x01;
    pub const SEIZE: u8 = 0x02;
    pub const BURN: u8 = 0x03;
    // 0x04 reserved -- separate mint-authority contract, not this covenant.
    pub const ROTATE: u8 = 0x05;
    pub const MIGRATE: u8 = 0x06;
}

/// Placeholder bytecode for a not-yet-implemented `op_type` branch
/// (TODO(Phase II): FREEZE/SEIZE/BURN/ROTATE/MIGRATE). Pushes a literal
/// `OP_0` (empty-array / false); if this branch is ever reached the script
/// therefore ends on a falsy top-of-stack value and the spend is rejected --
/// fail-closed until the real branch lands.
pub const UNIMPLEMENTED_BRANCH_STUB: &[u8] = &[0x00];

/// Bytecode fragments spliced into the 6-way `op_type` dispatch, named by
/// branch. Phase I passes real bytecode only for `transfer`; the rest are
/// expected to be [`UNIMPLEMENTED_BRANCH_STUB`] until Phase II.
pub struct OpTypeBranches<'a> {
    pub transfer: &'a [u8],
    pub freeze: &'a [u8],
    pub seize: &'a [u8],
    pub burn: &'a [u8],
    pub rotate: &'a [u8],
    pub migrate: &'a [u8],
}

/// Build the 6-way `op_type` dispatch skeleton. `tag_depth` is the stack
/// depth (0-based, top of stack = 0) of the `op_type` selector byte (pushed
/// by the spender's sigscript, the LAST sigscript push before the redeem
/// script itself) at the point this fragment begins executing -- i.e. after
/// the state header's own field pushes (see `state.rs`'s module doc).
pub fn build_op_type_dispatch(tag_depth: u16, branches: OpTypeBranches) -> Vec<u8> {
    use ops::*;
    let mut b = Vec::with_capacity(
        64 + branches.transfer.len()
            + branches.freeze.len()
            + branches.seize.len()
            + branches.burn.len()
            + branches.rotate.len()
            + branches.migrate.len(),
    );
    push_index(&mut b, tag_depth);
    b.push(ROLL);

    // 0x00 TRANSFER
    b.push(DUP);
    b.push(DATA1);
    b.push(op_type::TRANSFER);
    b.push(EQUAL);
    b.push(IF);
    {
        b.push(DROP);
        b.extend_from_slice(branches.transfer);
    }
    b.push(ELSE);
    {
        // 0x01 FREEZE
        b.push(DUP);
        b.push(DATA1);
        b.push(op_type::FREEZE);
        b.push(EQUAL);
        b.push(IF);
        {
            b.push(DROP);
            b.extend_from_slice(branches.freeze);
        }
        b.push(ELSE);
        {
            // 0x02 SEIZE
            b.push(DUP);
            b.push(DATA1);
            b.push(op_type::SEIZE);
            b.push(EQUAL);
            b.push(IF);
            {
                b.push(DROP);
                b.extend_from_slice(branches.seize);
            }
            b.push(ELSE);
            {
                // 0x03 BURN
                b.push(DUP);
                b.push(DATA1);
                b.push(op_type::BURN);
                b.push(EQUAL);
                b.push(IF);
                {
                    b.push(DROP);
                    b.extend_from_slice(branches.burn);
                }
                b.push(ELSE);
                {
                    // 0x05 ROTATE (0x04 skipped -- reserved, never compared).
                    b.push(DUP);
                    b.push(DATA1);
                    b.push(op_type::ROTATE);
                    b.push(EQUAL);
                    b.push(IF);
                    {
                        b.push(DROP);
                        b.extend_from_slice(branches.rotate);
                    }
                    b.push(ELSE);
                    {
                        // 0x06 MIGRATE -- the final rung: must match exactly
                        // (OP_VERIFY), so any other byte (including the
                        // reserved 0x04) hard-aborts here rather than
                        // silently falling through to MIGRATE's bytecode.
                        //
                        // BUG FIX (found wiring MIGRATE's real bytecode in,
                        // 2026-07-19): this rung is the only one WITHOUT an
                        // `IF`/`ELSE` (it uses a hard `OP_VERIFY` instead,
                        // since there is no further fallback -- any
                        // non-matching byte, including the reserved 0x04,
                        // must hard-abort). Every OTHER rung's shape is `DUP;
                        // DATA1 <val>; EQUAL; IF { DROP; branch }` -- the
                        // `DUP` makes a throwaway copy for the comparison, so
                        // `EQUAL` consumes (copy, literal) and leaves the
                        // ORIGINAL tag on the stack for the matched branch's
                        // `DROP` to remove. This rung was missing that `DUP`:
                        // `EQUAL` consumed the tag ITSELF directly (no copy
                        // existed), so the trailing `DROP` was wrongly
                        // consuming the next REAL data-stack item (this
                        // covenant's `epoch`) instead of a tag copy --
                        // silently corrupting every stack depth the matched
                        // branch computes against. Undetected until now
                        // because `migrate` was always the depth-agnostic
                        // `UNIMPLEMENTED_BRANCH_STUB` (bare `OP_0`). Adding
                        // `DUP` here makes this rung's stack-shape mechanics
                        // parallel to every other rung's, exactly.
                        b.push(DUP);
                        b.push(DATA1);
                        b.push(op_type::MIGRATE);
                        b.push(EQUAL);
                        b.push(VERIFY);
                        b.push(DROP);
                        b.extend_from_slice(branches.migrate);
                    }
                    b.push(ENDIF);
                }
                b.push(ENDIF);
            }
            b.push(ENDIF);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::opcodes::{disassemble, ScriptElement};

    #[test]
    fn op_type_0x04_is_never_a_named_constant() {
        let defined = [op_type::TRANSFER, op_type::FREEZE, op_type::SEIZE, op_type::BURN, op_type::ROTATE, op_type::MIGRATE];
        assert!(!defined.contains(&0x04));
        assert_eq!(defined.len(), 6);
    }

    #[test]
    fn op_type_values_match_attestation_module() {
        use crate::contract::stablecoin::attestation::op_type as a;
        assert_eq!(op_type::TRANSFER, a::TRANSFER);
        assert_eq!(op_type::FREEZE, a::FREEZE);
        assert_eq!(op_type::SEIZE, a::SEIZE);
        assert_eq!(op_type::BURN, a::BURN);
        assert_eq!(op_type::ROTATE, a::ROTATE);
        assert_eq!(op_type::MIGRATE, a::MIGRATE);
    }

    fn branches<'a>(t: &'a [u8]) -> OpTypeBranches<'a> {
        OpTypeBranches {
            transfer: t,
            freeze: UNIMPLEMENTED_BRANCH_STUB,
            seize: UNIMPLEMENTED_BRANCH_STUB,
            burn: UNIMPLEMENTED_BRANCH_STUB,
            rotate: UNIMPLEMENTED_BRANCH_STUB,
            migrate: UNIMPLEMENTED_BRANCH_STUB,
        }
    }

    #[test]
    fn skeleton_structural_shape_head() {
        let on_transfer = vec![0x51u8]; // placeholder OP_1
        let skeleton = build_op_type_dispatch(3, branches(&on_transfer));
        let elements = disassemble(&skeleton);
        assert!(matches!(elements[0], ScriptElement::Op(0x53))); // OP_3
        assert!(matches!(elements[1], ScriptElement::Op(0x7a))); // OP_ROLL
        assert!(matches!(elements[2], ScriptElement::Op(0x76))); // OP_DUP
        match &elements[3] {
            ScriptElement::Push(0x01, data) => assert_eq!(data, &vec![0x00]),
            other => panic!("expected op_type 0x00 literal push, got {other:?}"),
        }
        assert!(matches!(elements[4], ScriptElement::Op(0x87))); // OP_EQUAL
        assert!(matches!(elements[5], ScriptElement::Op(0x63))); // OP_IF
        assert!(matches!(elements[6], ScriptElement::Op(0x75))); // OP_DROP
        assert!(matches!(elements[7], ScriptElement::Op(0x51))); // on_transfer placeholder
        assert!(matches!(elements[8], ScriptElement::Op(0x67))); // OP_ELSE
    }

    #[test]
    fn skeleton_is_balanced_if_else_endif() {
        let skeleton = build_op_type_dispatch(0, branches(&[0xAAu8]));
        let elements = disassemble(&skeleton);
        let ifs = elements.iter().filter(|e| matches!(e, ScriptElement::Op(0x63))).count();
        let elses = elements.iter().filter(|e| matches!(e, ScriptElement::Op(0x67))).count();
        let endifs = elements.iter().filter(|e| matches!(e, ScriptElement::Op(0x68))).count();
        // 5, not 6: the ladder has 6 op_type values (TRANSFER/FREEZE/SEIZE/
        // BURN/ROTATE/MIGRATE) but only 5 IF/ELSE/ENDIF triples -- the final
        // rung (MIGRATE) is the ELSE fallthrough of the ROTATE test, guarded
        // by a hard `OP_DATA_1 0x06 OP_EQUAL OP_VERIFY` instead of its own
        // IF/ELSE (see the module doc's bytecode-shape comment: "any other
        // byte (including the reserved 0x04) hard-aborts here").
        assert_eq!(ifs, 5);
        assert_eq!(elses, 5);
        assert_eq!(endifs, 5);
    }

    #[test]
    fn unimplemented_branch_stub_is_a_single_op0() {
        assert_eq!(UNIMPLEMENTED_BRANCH_STUB, &[0x00]);
    }

    #[test]
    fn all_six_rungs_dup_tag_before_compare_bugfix_regression() {
        // Regression test for the 2026-07-19 bug fix: the final (MIGRATE)
        // rung must ALSO `OP_DUP` the tag before comparing, exactly like the
        // other five rungs -- otherwise its `OP_EQUAL` consumes the tag
        // directly (no spare copy to consume instead), and the trailing
        // `OP_DROP` silently eats the next REAL data-stack item instead of a
        // tag copy (see `build_op_type_dispatch`'s bug-fix doc comment on the
        // MIGRATE rung). This was undetected while `migrate` was always the
        // depth-agnostic `UNIMPLEMENTED_BRANCH_STUB`.
        let skeleton = build_op_type_dispatch(0, branches(&[0xAAu8]));
        let dup_count = skeleton.iter().filter(|&&b| b == 0x76).count();
        assert_eq!(dup_count, 6, "expected 6 OP_DUP (one per op_type rung, including the final MIGRATE rung), found {dup_count}");
    }

    #[test]
    fn skeleton_length_is_additive_in_branch_length() {
        let base = build_op_type_dispatch(0, branches(&[]));
        let with_branch = build_op_type_dispatch(0, branches(&[0xaa, 0xbb, 0xcc]));
        assert_eq!(with_branch.len(), base.len() + 3);
    }
}
