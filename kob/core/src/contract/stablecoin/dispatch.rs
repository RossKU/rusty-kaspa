//! Robust stablecoin covenant `op_type` dispatch (`STABLECOIN_ROBUST_DESIGN.md`
//! §4): generalizes `crate::contract::kcc20::dispatch::build_dispatch_skeleton`'s
//! roll/DUP/compare/IF/ELSE/ENDIF shape from a 2-way tag compare to an 8-way
//! `op_type` discriminant BYTE compare (`0x00..0x03, 0x05..0x08`; `0x04` is
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
//!                     OP_DUP OP_DATA_1 0x06 OP_EQUAL
//!                     OP_IF
//!                         OP_DROP
//!                         <on_migrate>       ; 0x06 MIGRATE
//!                     OP_ELSE
//!                         OP_DUP OP_DATA_1 0x07 OP_EQUAL
//!                         OP_IF
//!                             OP_DROP
//!                             <on_transfer_nm>   ; 0x07 TRANSFER_NM (N:M leader)
//!                         OP_ELSE
//!                             OP_DUP OP_DATA_1 0x08 OP_EQUAL OP_VERIFY   ; hard-reject anything else (incl. 0x04)
//!                             OP_DROP
//!                             <on_transfer_nm_delegator>  ; 0x08 TRANSFER_NM_DELEGATOR
//!                         OP_ENDIF
//!                     OP_ENDIF
//!                 OP_ENDIF
//!             OP_ENDIF
//!         OP_ENDIF
//!     OP_ENDIF
//! OP_ENDIF
//! ```
//!
//! The final (TRANSFER_NM_DELEGATOR) rung has no further `ELSE` fallback (any
//! non-matching byte, including the reserved `0x04`, must hard-abort via
//! `OP_VERIFY` rather than fall through), but it still needs the leading
//! `OP_DUP`: every rung's shape consumes a THROWAWAY COPY of the tag in its
//! compare (`OP_DUP` ... `OP_EQUAL`), leaving the ORIGINAL tag on the stack
//! for the trailing `OP_DROP` to remove once matched -- omitting the
//! `OP_DUP` here would make `OP_EQUAL` consume the tag directly (no copy to
//! spare), so the trailing `OP_DROP` would silently consume the next REAL
//! data-stack item instead (`body.rs`'s bug-fix note, `build_op_type_dispatch`,
//! has the full story -- originally found on the MIGRATE rung when it was
//! still the final one; MIGRATE is now a normal mid-ladder `IF`/`ELSE` rung
//! following the N:M extension (item 1), and the SAME discipline applies to
//! the new final rung, TRANSFER_NM_DELEGATOR).
//!
//! `on_transfer` (0x00), `on_freeze` (0x01), `on_seize` (0x02), `on_burn`
//! (0x03), `on_migrate` (0x06), `on_transfer_nm` (0x07), and
//! `on_transfer_nm_delegator` (0x08) wire real bytecode; `on_rotate` (0x05)
//! is the shared [`UNIMPLEMENTED_BRANCH_STUB`] placeholder (a bare `OP_0`, so
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
    /// N:M transfer (G1) leader. See `super::attestation::op_type::TRANSFER_NM`.
    pub const TRANSFER_NM: u8 = 0x07;
    /// N:M transfer (G1) delegator. See `super::attestation::op_type::TRANSFER_NM_DELEGATOR`.
    pub const TRANSFER_NM_DELEGATOR: u8 = 0x08;
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
    /// N:M transfer (G1) leader, `0x07` -- see `super::body`'s
    /// `build_transfer_nm_branch`.
    pub transfer_nm: &'a [u8],
    /// N:M transfer (G1) delegator, `0x08` -- the new FINAL rung (hard
    /// `OP_VERIFY`, no `ELSE` fallback -- see `build_op_type_dispatch`'s doc).
    pub transfer_nm_delegator: &'a [u8],
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
            + branches.migrate.len()
            + branches.transfer_nm.len()
            + branches.transfer_nm_delegator.len(),
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
                        // 0x06 MIGRATE -- since the N:M extension (item 1),
                        // no longer the final rung: it now follows the SAME
                        // `IF`/`ELSE` shape as every other non-final rung
                        // (see the DUP-before-compare note preserved below,
                        // which is what the 2026-07-19 bug fix established
                        // and this restructuring keeps intact).
                        b.push(DUP);
                        b.push(DATA1);
                        b.push(op_type::MIGRATE);
                        b.push(EQUAL);
                        b.push(IF);
                        {
                            b.push(DROP);
                            b.extend_from_slice(branches.migrate);
                        }
                        b.push(ELSE);
                        {
                            // 0x07 TRANSFER_NM (N:M leader).
                            b.push(DUP);
                            b.push(DATA1);
                            b.push(op_type::TRANSFER_NM);
                            b.push(EQUAL);
                            b.push(IF);
                            {
                                b.push(DROP);
                                b.extend_from_slice(branches.transfer_nm);
                            }
                            b.push(ELSE);
                            {
                                // 0x08 TRANSFER_NM_DELEGATOR -- the new FINAL
                                // rung: must match exactly (OP_VERIFY), so any
                                // other byte (including the reserved 0x04)
                                // hard-aborts here rather than silently
                                // falling through. Still `DUP`s the tag first
                                // (2026-07-19 bug-fix discipline, see the
                                // MIGRATE rung's history above): `EQUAL`
                                // consumes the throwaway copy, leaving the
                                // ORIGINAL tag for the matched branch's
                                // trailing `DROP` to remove.
                                b.push(DUP);
                                b.push(DATA1);
                                b.push(op_type::TRANSFER_NM_DELEGATOR);
                                b.push(EQUAL);
                                b.push(VERIFY);
                                b.push(DROP);
                                b.extend_from_slice(branches.transfer_nm_delegator);
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
        assert_eq!(defined.len(), 8);
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
        assert_eq!(op_type::TRANSFER_NM, a::TRANSFER_NM);
        assert_eq!(op_type::TRANSFER_NM_DELEGATOR, a::TRANSFER_NM_DELEGATOR);
    }

    fn branches<'a>(t: &'a [u8]) -> OpTypeBranches<'a> {
        OpTypeBranches {
            transfer: t,
            freeze: UNIMPLEMENTED_BRANCH_STUB,
            seize: UNIMPLEMENTED_BRANCH_STUB,
            burn: UNIMPLEMENTED_BRANCH_STUB,
            rotate: UNIMPLEMENTED_BRANCH_STUB,
            migrate: UNIMPLEMENTED_BRANCH_STUB,
            transfer_nm: UNIMPLEMENTED_BRANCH_STUB,
            transfer_nm_delegator: UNIMPLEMENTED_BRANCH_STUB,
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
        // 7, not 8: the ladder has 8 op_type values (TRANSFER/FREEZE/SEIZE/
        // BURN/ROTATE/MIGRATE/TRANSFER_NM/TRANSFER_NM_DELEGATOR) but only 7
        // IF/ELSE/ENDIF triples -- the final rung (TRANSFER_NM_DELEGATOR) is
        // the ELSE fallthrough of the TRANSFER_NM test, guarded by a hard
        // `OP_DATA_1 0x08 OP_EQUAL OP_VERIFY` instead of its own IF/ELSE (see
        // the module doc's bytecode-shape comment: "any other byte (including
        // the reserved 0x04) hard-aborts here").
        assert_eq!(ifs, 7);
        assert_eq!(elses, 7);
        assert_eq!(endifs, 7);
    }

    #[test]
    fn unimplemented_branch_stub_is_a_single_op0() {
        assert_eq!(UNIMPLEMENTED_BRANCH_STUB, &[0x00]);
    }

    #[test]
    fn all_eight_rungs_dup_tag_before_compare_bugfix_regression() {
        // Regression test for the 2026-07-19 bug fix (originally on the
        // MIGRATE rung when it was still final): the FINAL rung must ALSO
        // `OP_DUP` the tag before comparing, exactly like every other rung --
        // otherwise its `OP_EQUAL` consumes the tag directly (no spare copy
        // to consume instead), and the trailing `OP_DROP` silently eats the
        // next REAL data-stack item instead of a tag copy (see
        // `build_op_type_dispatch`'s bug-fix doc comment). Now that the N:M
        // extension (item 1) moved MIGRATE off the final position and added
        // TRANSFER_NM/TRANSFER_NM_DELEGATOR, this guards the NEW final rung
        // (TRANSFER_NM_DELEGATOR) instead.
        let skeleton = build_op_type_dispatch(0, branches(&[0xAAu8]));
        let dup_count = skeleton.iter().filter(|&&b| b == 0x76).count();
        assert_eq!(dup_count, 8, "expected 8 OP_DUP (one per op_type rung, including the final TRANSFER_NM_DELEGATOR rung), found {dup_count}");
    }

    #[test]
    fn skeleton_length_is_additive_in_branch_length() {
        let base = build_op_type_dispatch(0, branches(&[]));
        let with_branch = build_op_type_dispatch(0, branches(&[0xaa, 0xbb, 0xcc]));
        assert_eq!(with_branch.len(), base.len() + 3);
    }

    #[test]
    fn transfer_nm_and_delegator_rungs_are_reachable() {
        // Pin the dispatch: a selector of 0x07 must reach `transfer_nm`'s
        // bytecode, and 0x08 must reach `transfer_nm_delegator`'s -- proves
        // the new 8th/9th... (7th/8th) rungs are wired into the ladder at
        // all, ahead of any real-engine test.
        let nm = vec![0x52u8]; // placeholder OP_2
        let nm_delegator = vec![0x53u8]; // placeholder OP_3
        let b = OpTypeBranches {
            transfer: UNIMPLEMENTED_BRANCH_STUB,
            freeze: UNIMPLEMENTED_BRANCH_STUB,
            seize: UNIMPLEMENTED_BRANCH_STUB,
            burn: UNIMPLEMENTED_BRANCH_STUB,
            rotate: UNIMPLEMENTED_BRANCH_STUB,
            migrate: UNIMPLEMENTED_BRANCH_STUB,
            transfer_nm: &nm,
            transfer_nm_delegator: &nm_delegator,
        };
        let skeleton = build_op_type_dispatch(0, b);
        // Both placeholder bytes must appear in the assembled skeleton.
        assert!(skeleton.windows(1).any(|w| w == [0x52u8]));
        assert!(skeleton.windows(1).any(|w| w == [0x53u8]));
    }
}
