//! Composable Direct & Responsive (D&R) bytecode builders.
//!
//! Redeem-script bodies repeat six D&R validation patterns that authenticate
//! the transaction's continuation covenant:
//!
//! 1. [`dr_input_spk_check`] — the spending input's SPK equals `P2SH(rs)`.
//! 2. [`dr_output_spk_check`] — a target output's SPK equals `P2SH(new_rs)`.
//! 3. [`dr_prefix_check`] — the `new_rs` prefix up to a boundary matches `old_rs`.
//! 4. [`dr_suffix_check`] — the `new_rs` tail from a boundary matches `old_rs`.
//! 5. [`dr_field_extract`] — extract a byte range from a redeem-script value.
//! 6. [`dr_value_continuity_check`] — the successor covenant output's native
//!    value equals the spending input's native value.
//!
//! These builders emit the exact same opcode sequences that the existing body
//! constants hand-tabulate; a byte-for-byte match is asserted in the tests
//! below against `DCA_ORDER_BODY`. Because the P2SH address of a deployed
//! contract is derived from the body bytes, any deviation would strand the
//! live UTXOs — callers MUST treat the output as opaque and must not
//! restructure the sequence without re-running the byte-exact tests.
//!
//! Depth semantics: every `*_depth` argument is an OpPick distance counted
//! from the top of the stack (0 = top, 1 = second from top, …). Values
//! 0..=16 are emitted as `OpN` (1 byte), 17..=127 as `[0x01, n]` (2 bytes),
//! 128..=32767 as `[0x02, lo, hi]` (3 bytes), via [`super::helpers::push_index`].

use super::helpers::push_index;

/// Reconstruct `P2SH(rs)` from a redeem-script value already on the stack
/// and assert it equals `OpTxInputSpk` (the current input's SPK).
///
/// Layout:
/// ```text
///   pick(rs) blake2b                       -> rs_hash
///   push [0x00, 0x00, 0xaa, 0x20]           # P2SH version prefix + push header
///   swap cat
///   push [0x87]                             # OpEqual trailing byte
///   cat                                     -> expected P2SH SPK
///   OpTxInputIndex OpTxInputSpk             -> actual input SPK
///   OpEqual OpVerify
/// ```
///
/// Output: 17 bytes when `rs_depth <= 16`.
pub fn dr_input_spk_check(rs_depth: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    push_index(&mut out, rs_depth);
    out.push(0x79); // OpPick -> rs copy
    out.push(0xaa); // OpBlake2b
    out.extend_from_slice(&[0x04, 0x00, 0x00, 0xaa, 0x20]);
    out.push(0x7c); // OpSwap
    out.push(0x7e); // OpCat
    out.extend_from_slice(&[0x01, 0x87]);
    out.push(0x7e); // OpCat -> expected input SPK
    out.extend_from_slice(&[0xb9, 0xbf]); // OpTxInputIndex OpTxInputSpk
    out.extend_from_slice(&[0x87, 0x69]); // OpEqual OpVerify
    out
}

/// Reconstruct `P2SH(new_rs)` from a redeem-script value on the stack and
/// assert it equals `output[output_idx].spk` where `output_idx` is itself on
/// the stack.
///
/// Layout:
/// ```text
///   pick(new_rs) blake2b
///   push version prefix; swap; cat
///   push [0x87]; cat                        -> expected output SPK
///   pick(output_idx) OpTxOutputSpk          -> actual output SPK
///   OpEqual OpVerify
/// ```
///
/// Output: 18 bytes when both depths are 0..=16.
pub fn dr_output_spk_check(new_rs_depth: u16, output_idx_depth: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    push_index(&mut out, new_rs_depth);
    out.push(0x79); // OpPick -> new_rs copy
    out.push(0xaa); // OpBlake2b
    out.extend_from_slice(&[0x04, 0x00, 0x00, 0xaa, 0x20]);
    out.push(0x7c); // OpSwap
    out.push(0x7e); // OpCat
    out.extend_from_slice(&[0x01, 0x87]);
    out.push(0x7e); // OpCat -> expected output SPK
    push_index(&mut out, output_idx_depth);
    out.push(0x79); // OpPick -> output_idx
    out.push(0xc3); // OpTxOutputSpk
    out.extend_from_slice(&[0x87, 0x69]); // OpEqual OpVerify
    out
}

/// Assert the first `end` bytes of `old_rs` and `new_rs` are byte-identical.
///
/// Layout:
/// ```text
///   pick(old_rs) Op0 push(end) OpSubstr     -> old_prefix
///   pick(new_rs) Op0 push(end) OpSubstr     -> new_prefix
///   OpEqual OpVerify
/// ```
///
/// Output: 16 bytes when depths are 0..=16 and `end` is in 128..=32767 (the
/// common case for state-header widths). Grows with wider numeric pushes.
pub fn dr_prefix_check(old_rs_depth: u16, new_rs_depth: u16, end: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    push_index(&mut out, old_rs_depth);
    out.push(0x79); // OpPick -> old_rs
    out.push(0x00); // Op0 (begin = 0)
    push_index(&mut out, end);
    out.push(0x7f); // OpSubstr -> old_prefix
    push_index(&mut out, new_rs_depth);
    out.push(0x79); // OpPick -> new_rs
    out.push(0x00); // Op0
    push_index(&mut out, end);
    out.push(0x7f); // OpSubstr -> new_prefix
    out.extend_from_slice(&[0x87, 0x69]); // OpEqual OpVerify
    out
}

/// Assert the suffix `old_rs[begin..]` equals `new_rs[begin..]` using
/// `OpSize` to resolve the dynamic length.
///
/// Layout:
/// ```text
///   pick(old_rs) OpSize push(begin) OpSwap OpSubstr  -> old_suffix
///   pick(new_rs) OpSize push(begin) OpSwap OpSubstr  -> new_suffix
///   OpEqual OpVerify
/// ```
///
/// Output: 18 bytes when depths are 0..=16 and `begin` is in 128..=32767.
pub fn dr_suffix_check(old_rs_depth: u16, new_rs_depth: u16, begin: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    push_index(&mut out, old_rs_depth);
    out.push(0x79); // OpPick -> old_rs
    out.push(0x82); // OpSize -> len (non-consuming)
    push_index(&mut out, begin);
    out.push(0x7c); // OpSwap -> (data, begin, end=len)
    out.push(0x7f); // OpSubstr -> old_suffix
    push_index(&mut out, new_rs_depth);
    out.push(0x79);
    out.push(0x82);
    push_index(&mut out, begin);
    out.push(0x7c);
    out.push(0x7f);
    out.extend_from_slice(&[0x87, 0x69]); // OpEqual OpVerify
    out
}

/// Extract `data[begin..end]` from a redeem-script value at `data_depth`.
/// The extracted slice is left on the top of the stack; callers are
/// responsible for any subsequent comparison or arithmetic.
///
/// Layout:
/// ```text
///   pick(data) push(begin) push(end) OpSubstr
/// ```
pub fn dr_field_extract(data_depth: u16, begin: u16, end: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    push_index(&mut out, data_depth);
    out.push(0x79); // OpPick -> data copy
    push_index(&mut out, begin);
    push_index(&mut out, end);
    out.push(0x7f); // OpSubstr
    out
}

/// Assert the spending input's native value (sompi) equals the successor
/// covenant output's native value — an exact-equality 1:1 covenant. The tx
/// fee MUST come from a separate funding input, never by shaving the
/// covenant coin's own value.
///
/// This closes a value-continuity hole that exists in any branch with no
/// owner `SIGHASH_ALL` signature: an ordinary owner-signed spend gets value
/// continuity "for free" because `SIGHASH_ALL` commits the whole
/// transaction, including every output's amount, so the owner's signature
/// alone already pins the successor's value. A branch authorized by some
/// OTHER role's `OpCheckSigFromStack` attestation (which signs only a
/// specific message, not the whole transaction) has nothing else pinning the
/// successor's value unless it explicitly checks it here — otherwise a
/// holder of only that lower-privileged role's key could alter the coin's
/// native value while exercising the branch (value theft/destruction by a
/// low-privilege role). See `STABLECOIN_ROBUST_DESIGN.md` §4/§11 for the
/// cross-branch invariant this helper is required by.
///
/// Uses the same "`OpTxInputIndex` reused as the output index" 1:1
/// successor-binding convention already relied on by every caller of
/// [`dr_output_spk_check`] in this codebase, so it needs no depth argument at
/// all — it is entirely self-contained: it reads nothing from, and has zero
/// net effect on, the caller's existing stack (it pushes exactly the two
/// values it then consumes), so callers may splice it in anywhere without
/// adjusting any other op's depth argument.
///
/// Layout:
/// ```text
///   OpTxInputIndex OpTxInputAmount    -> this input's native value
///   OpTxInputIndex OpTxOutputAmount   -> successor output's native value (same index)
///   OpEqual OpVerify
/// ```
///
/// Output: 6 bytes, unconditionally (no numeric pushes, so no depth-dependent
/// size variation).
pub fn dr_value_continuity_check() -> Vec<u8> {
    vec![
        0xb9, 0xbe, // OpTxInputIndex OpTxInputAmount -> this input's value
        0xb9, 0xc2, // OpTxInputIndex OpTxOutputAmount -> successor output's value
        0x87, 0x69, // OpEqual OpVerify
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference bytes below were copied verbatim from `DCA_ORDER_BODY`
    // (kob/core/src/contract/spot/dca.rs). The tests guard the invariant
    // that the D&R helpers emit the exact same byte sequences.

    #[test]
    fn dr_input_spk_check_matches_dca_step1() {
        // DCA D&R Step 1 (old_rs at stack depth 9), 17 bytes.
        let expected: &[u8] = &[
            0x59, 0x79,                   // Op9 OpPick -> old_rs copy
            0xaa,                         // OpBlake2b
            0x04, 0x00, 0x00, 0xaa, 0x20, // push [0x00, 0x00, 0xaa, 0x20]
            0x7c,                         // OpSwap
            0x7e,                         // OpCat
            0x01, 0x87,                   // push [0x87]
            0x7e,                         // OpCat
            0xb9, 0xbf,                   // OpTxInputIndex OpTxInputSpk
            0x87, 0x69,                   // OpEqual OpVerify
        ];
        assert_eq!(dr_input_spk_check(9), expected);
    }

    #[test]
    fn dr_prefix_check_matches_dca_step2() {
        // DCA D&R Step 2 (old_rs at d9, new_rs at d11, end=136), 16 bytes.
        let expected: &[u8] = &[
            0x59, 0x79,       // Op9 OpPick (old_rs)
            0x00,             // Op0 (begin = 0)
            0x02, 0x88, 0x00, // push 136
            0x7f,             // OpSubstr -> old_prefix
            0x5b, 0x79,       // Op11 OpPick (new_rs)
            0x00,
            0x02, 0x88, 0x00, // push 136
            0x7f,             // OpSubstr -> new_prefix
            0x87, 0x69,       // OpEqual OpVerify
        ];
        assert_eq!(dr_prefix_check(9, 11, 136), expected);
    }

    #[test]
    fn dr_suffix_check_matches_dca_step3() {
        // DCA D&R Step 3 (old_rs at d9, new_rs at d11, begin=153), 18 bytes.
        let expected: &[u8] = &[
            0x59, 0x79,       // Op9 OpPick
            0x82,             // OpSize
            0x02, 0x99, 0x00, // push 153
            0x7c,             // OpSwap
            0x7f,             // OpSubstr -> old_suffix
            0x5b, 0x79,       // Op11 OpPick
            0x82,
            0x02, 0x99, 0x00, // push 153
            0x7c,
            0x7f,             // OpSubstr -> new_suffix
            0x87, 0x69,       // OpEqual OpVerify
        ];
        assert_eq!(dr_suffix_check(9, 11, 153), expected);
    }

    #[test]
    fn dr_field_extract_matches_dca_step4() {
        // DCA D&R Step 4 range extract (new_rs at d10, [144..145)), 9 bytes.
        // Note: step 4 also emits an `Op8 OpEqual OpVerify` tail that is NOT
        // part of the extract helper — the tail is contract-specific.
        let expected: &[u8] = &[
            0x5a, 0x79,       // Op10 OpPick
            0x02, 0x90, 0x00, // push 144
            0x02, 0x91, 0x00, // push 145
            0x7f,             // OpSubstr
        ];
        assert_eq!(dr_field_extract(10, 144, 145), expected);
    }

    #[test]
    fn dr_field_extract_matches_dca_step5_new() {
        // DCA Step 5 first extract (new_rs at d10, [136..144)), 9 bytes.
        let expected: &[u8] = &[
            0x5a, 0x79,       // Op10 OpPick (new_rs)
            0x02, 0x88, 0x00, // push 136
            0x02, 0x90, 0x00, // push 144
            0x7f,             // OpSubstr
        ];
        assert_eq!(dr_field_extract(10, 136, 144), expected);
    }

    #[test]
    fn dr_field_extract_matches_dca_step6_new() {
        // DCA Step 6 first extract (new_rs at d10, [145..153)), 9 bytes.
        let expected: &[u8] = &[
            0x5a, 0x79,       // Op10 OpPick
            0x02, 0x91, 0x00, // push 145
            0x02, 0x99, 0x00, // push 153
            0x7f,             // OpSubstr
        ];
        assert_eq!(dr_field_extract(10, 145, 153), expected);
    }

    #[test]
    fn dr_output_spk_check_matches_dca_step7() {
        // DCA D&R Step 7 (new_rs at d10, ci at d9), 18 bytes.
        let expected: &[u8] = &[
            0x5a, 0x79,                   // Op10 OpPick (new_rs)
            0xaa,                         // OpBlake2b
            0x04, 0x00, 0x00, 0xaa, 0x20, // push version prefix
            0x7c,                         // OpSwap
            0x7e,                         // OpCat
            0x01, 0x87,                   // push [0x87]
            0x7e,                         // OpCat
            0x59, 0x79,                   // Op9 OpPick (ci)
            0xc3,                         // OpTxOutputSpk
            0x87, 0x69,                   // OpEqual OpVerify
        ];
        assert_eq!(dr_output_spk_check(10, 9), expected);
    }

    #[test]
    fn dr_prefix_check_small_end_uses_opn() {
        // end=16 uses Op16 (0x60) directly, yielding a 12-byte output.
        let bytes = dr_prefix_check(1, 2, 16);
        // 1 + 1 + 1 + 1 + 1   (pick old, OpPick, Op0, push 16, OpSubstr)
        // + 1 + 1 + 1 + 1 + 1  (pick new, OpPick, Op0, push 16, OpSubstr)
        // + 2                  (OpEqual OpVerify)
        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes[3], 0x60); // Op16
    }

    #[test]
    fn dr_field_extract_minimal_path() {
        // depth=1, begin=0, end=4 — every push is a 1-byte OpN.
        let bytes = dr_field_extract(1, 0, 4);
        let expected: &[u8] = &[
            0x51,       // Op1
            0x79,       // OpPick
            0x00,       // Op0 (begin=0)
            0x54,       // Op4 (end=4)
            0x7f,       // OpSubstr
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn dr_value_continuity_check_emits_expected_bytes() {
        let expected: &[u8] = &[
            0xb9, 0xbe, // OpTxInputIndex OpTxInputAmount
            0xb9, 0xc2, // OpTxInputIndex OpTxOutputAmount
            0x87, 0x69, // OpEqual OpVerify
        ];
        assert_eq!(dr_value_continuity_check(), expected);
    }

    #[test]
    fn dr_value_continuity_check_is_fixed_six_bytes() {
        // No numeric-depth arguments at all, so length can never vary.
        assert_eq!(dr_value_continuity_check().len(), 6);
    }
}
