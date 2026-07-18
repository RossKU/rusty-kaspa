//! KCC20 `transfer` / `transfer_delegator` body bytecode (kcc-0020 "## Transfer
//! Interface") and the complete redeem-script builder
//! (`build_kcc20_token_redeem_script`).
//!
//! ## Central interpretation decision (ISSUE #1, first flagged in `dispatch.rs`)
//!
//! kcc-0020 declares:
//!
//! ```text
//! transfer(State[] next_states, sig[] signatures, byte[] witnesses)
//! ```
//!
//! `State[]` cannot be encoded as a kcc-0001 §5.5/§5.6 array of records: the
//! `amount` leaf is an `int`, and an ARGUMENT `int` uses `PushMinimal` over a
//! *variable*-width minimal ScriptNum (§5.3), while §5.5/§5.6 require every
//! recursively-lowered leaf of an array-of-records to have a *positive fixed*
//! payload width. No amount of record-lowering fixes this; the type as
//! declared is not encodable.
//!
//! This module does **not** attempt to encode `next_states` as a kcc-0001
//! array at all. Instead — following the *existing, already-shipped* KOB
//! precedent for exactly this kind of "authenticate a successor covenant
//! program" problem (`crate::contract::dr`, used by `spot::dca`'s D&R steps)
//! — each successor is passed as a **whole successor redeem-script blob**
//! (`new_rs_k`, the complete candidate `R` for output slot `k`), not as a
//! `State` record. The leader:
//!
//! 1. authenticates its OWN current redeem script (`self_rs`, a second copy
//!    of `R` supplied as a plain argument) against the actual spent input's
//!    committed P2SH hash (`dr_input_spk_check`) — this is what lets the
//!    body use `self_rs`'s SUFFIX bytes as an *authenticated* copy of the
//!    template, with no self-referential ("my own bytecode as a data
//!    constant") construction anywhere;
//! 2. for each active successor slot `k` (`k < OpCovOutputCount(id)`),
//!    verifies `new_rs_k`'s suffix is byte-identical to `self_rs`'s suffix
//!    (`dr_suffix_check`, kcc-0001 §8.5's required template authentication —
//!    *not* implementing this would let a leader "reconstruct" a same-shaped
//!    amount/digest prefix while locking the successor under a
//!    completely different, attacker-chosen script body);
//! 3. verifies the actual output at the shared covenant-id output position
//!    hashes to `new_rs_k` (`dr_output_spk_check`);
//! 4. extracts `new_rs_k`'s `amount`/`extended_state_digest` fields at their
//!    FIXED byte offsets within the (kcc-0001 §8.1, fixed-width) leading
//!    77-byte `Kcc20State` region, for the conservation/digest checks below.
//!
//! This is a **deviation from kcc-0020's literal `State[]` argument type**,
//! not merely from kcc-0001's array encoding. It is the ISSUE this module
//! surfaces as its primary "an actual attempt to build this ran into a hole"
//! finding: `next_states` as declared cannot be implemented; "a list of whole
//! successor redeem scripts" is the substitute this wave ships, and is
//! reported as an ISSUE, not silently presented as if it were the spec's own
//! encoding.
//!
//! ## Second interpretation decision: delegator authorization
//!
//! `transfer_delegator()` is declared with **zero** arguments. But *some*
//! input-local data must authorize spending each delegator (non-leader)
//! covenant input — kaspa script has no notion of "the leader's script
//! already authorized every input in this group"; each input's OWN
//! spending script must itself return true. Two designs were considered:
//!
//! - (a) **leader-verifies-all**: the leader's `signatures[]` argument (as
//!   kcc-0020 literally describes it — "signatures corresponding to consumed
//!   states", plural) carries a signature for *every* consumed state,
//!   verified from the leader's own script via `OpCheckSigFromStack`
//!   (kcc-0001 does not mention this opcode at all, and defines no message-
//!   hash convention for "a signature authorizing some OTHER input's spend"
//!   — inventing one here would be exactly the kind of unreviewed protocol
//!   invention this task's ISSUE-extraction framing is supposed to avoid);
//! - (b) **delegator self-authorizes**: each delegator input independently
//!   proves its own owner's authorization from *its own* sigScript, using
//!   the totally standard (and already-shipped, see
//!   `crate::contract::token::TOKEN_UNIT_BODY`) "owner_identifier (already on
//!   the state stack) as the `OpCheckSigVerify` pubkey, `sig` supplied by
//!   this input's own sigScript" pattern — the *natural* per-input
//!   authorization Kaspa script already gives every other input in this
//!   transaction.
//!
//! This module implements **(b)**. It is a *necessary deviation* from
//! `transfer_delegator()`'s literal "zero arguments" declaration (a
//! delegator's sigScript here pushes one 65-byte `sig` — that is real,
//! consumed invocation data, not spec-conformant "no input data"). The
//! consequence: the leader's OWN `signatures[]`/`witnesses[]` arguments (as
//! declared by kcc-0020's `transfer` signature) are, in this implementation,
//! narrowed to exactly ONE meaningful entry (`self_sig`, the leader's own
//! authorization) rather than one entry per consumed state. Both deviations
//! (delegator's non-empty invocation, leader's narrowed array) are reported
//! as ISSUEs.
//!
//! `witnesses[]` (kcc-0020 base `transfer` argument) is not threaded through
//! this wave's bytecode at all: the only currently-specified semantics for a
//! `witnesses[i]` byte is the Borrowed Receive extension's `0xFF` sentinel
//! (`borrowed_receive.rs`, stubbed this wave — see that module). Adding a
//! pushed-but-never-read `witnesses[]` argument here would be ceremony, not
//! substance; the gap is reported, not silently papered over with dead bytes.
//!
//! ## `extended_state_digest` equality scope (another ISSUE)
//!
//! kcc-0020: "When multiple inputs are consolidated into one successor
//! state, they must have the same `extended_state_digest`." It gives no
//! consumed-input <-> successor-output correspondence for partial
//! consolidations/splits, so a literal implementation of "digest must match
//! *its own* predecessor(s)" is not well-defined from the interface alone.
//! This module adopts the simplest sound reading: **one shared digest value
//! across the WHOLE covenant-id group** (every consumed state AND every
//! produced state in this transfer must carry the identical
//! `extended_state_digest`). This is not an over-restriction in practice:
//! KIP-20's shared covenant-id context is already global per `covenant_id`
//! for the whole transaction (there is no sub-grouping mechanism), so two
//! independent consolidation groups with different extended state could not
//! coexist under the same `covenant_id` in one transaction regardless.
//!
//! ## MAX_N (unroll bound)
//!
//! Kaspa script has no loops; N-of-N validation is unrolled to a fixed bound
//! at build time (exactly the existing pattern in `spot::order`'s buy/sell
//! sweep bodies). `KCC20_TRANSFER_MAX_N` bounds BOTH the number of sibling
//! (delegator) covenant inputs the leader can validate and the number of
//! successor states it can construct/verify. See the module's parent report
//! for the mass/size measurement at this bound and notes on raising it.

use super::dispatch::build_dispatch_skeleton;
use super::state::Kcc20State;
use crate::contract::dr::{dr_field_extract, dr_input_spk_check, dr_output_spk_check, dr_suffix_check};
use crate::contract::helpers::push_index;
use crate::primitives::push_data;

/// Sibling (delegator) covenant inputs / successor covenant outputs this
/// wave's `transfer` unrolls up to. See module doc "MAX_N (unroll bound)".
pub const KCC20_TRANSFER_MAX_N: usize = 4;

mod ops {
    pub const OP0: u8 = 0x00;
    pub const OP1: u8 = 0x51;
    pub const DROP: u8 = 0x75;
    pub const TWO_DROP: u8 = 0x6d;
    pub const PICK: u8 = 0x79;
    pub const ROLL: u8 = 0x7a;
    pub const IF: u8 = 0x63;
    pub const ENDIF: u8 = 0x68;
    pub const VERIFY: u8 = 0x69;
    pub const EQUAL: u8 = 0x87;
    pub const NOT: u8 = 0x91;
    pub const ADD: u8 = 0x93;
    pub const SUB: u8 = 0x94;
    pub const LT: u8 = 0x9f;
    pub const LTE: u8 = 0xa1;
    pub const NUMEQUALVERIFY: u8 = 0x9d;
    pub const CHECKSIGVERIFY: u8 = 0xad;
    pub const TXINPUTINDEX: u8 = 0xb9;
    pub const TXINPUTSIGSUBSTR: u8 = 0xbc;
    pub const INPUTCOVENANTID: u8 = 0xcf;
    pub const COVINPUTCOUNT: u8 = 0xd0;
    pub const COVINPUTIDX: u8 = 0xd1;
    pub const COVOUTPUTCOUNT: u8 = 0xd2;
    pub const COVOUTPUTIDX: u8 = 0xd3;
}

fn e_num(b: &mut Vec<u8>, n: u16) {
    push_index(b, n);
}
fn e_pick(b: &mut Vec<u8>, depth: usize) {
    push_index(b, depth as u16);
    b.push(ops::PICK);
}
fn e_roll(b: &mut Vec<u8>, depth: usize) {
    push_index(b, depth as u16);
    b.push(ops::ROLL);
}
/// Push this input's own `covenant_id` (or `ZERO_HASH` if none): `OpTxInputIndex
/// OpInputCovenantId`. Net stack effect: `+1`. Cheap enough (2 opcodes) to
/// recompute fresh at every use site instead of caching a copy at a tracked
/// depth — this is what keeps the rest of this module's stack-depth
/// bookkeeping tractable (every other value that is reused across multiple
/// steps is read via `OpPick`, never destructively consumed until an
/// explicit final cleanup).
fn e_own_covenant_id(b: &mut Vec<u8>) {
    b.push(ops::TXINPUTINDEX);
    b.push(ops::INPUTCOVENANTID);
}

// ============================================================================
// Fixed byte offsets of `amount` / `extended_state_digest` WITHIN a
// `Kcc20State`-prefixed redeem script `R` (kcc-0001 §8.1 field order:
// owner_identifier, identifier_type, amount, extended_state_digest; each
// PushExplicit-encoded, all four fixed-width so these offsets are the same
// for every KCC20 instance of this covenant regardless of field VALUES).
// ============================================================================

const OWNER_PUSH_LEN: usize = 1 + 32; // PushExplicit(byte32): OP_DATA_32 + 32B
const IDENT_PUSH_LEN: usize = 1 + 1; // OP_DATA_1 + 1B
const AMOUNT_OPCODE_LEN: usize = 1; // OP_DATA_8
const AMOUNT_PAYLOAD_LEN: usize = 8;
const DIGEST_OPCODE_LEN: usize = 1; // OP_DATA_32
const DIGEST_PAYLOAD_LEN: usize = 32;

/// Offset of `amount`'s payload (8B) within `R`, i.e. within any
/// `new_rs_k`/`self_rs` blob (these always start at the encoded state, kcc-0001
/// `state.start = 0`, per this crate's `Kcc20Descriptor` convention).
const R_AMOUNT_PAYLOAD_START: usize = OWNER_PUSH_LEN + IDENT_PUSH_LEN + AMOUNT_OPCODE_LEN;
const R_AMOUNT_PAYLOAD_END: usize = R_AMOUNT_PAYLOAD_START + AMOUNT_PAYLOAD_LEN;
/// Offset of `extended_state_digest`'s payload (32B) within `R`.
const R_DIGEST_PAYLOAD_START: usize = R_AMOUNT_PAYLOAD_END + DIGEST_OPCODE_LEN;
const R_DIGEST_PAYLOAD_END: usize = R_DIGEST_PAYLOAD_START + DIGEST_PAYLOAD_LEN;

// Sanity: these must land exactly on Kcc20State::ENCODED_LEN.
const _: () = assert!(R_DIGEST_PAYLOAD_END == Kcc20State::ENCODED_LEN);

/// Fixed byte offsets, WITHIN a delegator (sibling) covenant input's own
/// sigScript, of its previous state's `amount` and `extended_state_digest`
/// payloads. These are read directly off the sibling's sigScript bytes via
/// `OpTxInputScriptSigSubstr` (kcc-0001 §7: the redeem script `R` is always
/// the FINAL push of an input's sigScript; a delegator's sigScript in this
/// implementation is exactly `push_data(sig[65B]) || OP_DATA_4 tag ||
/// PushMinimal(R)` — see `build_transfer_delegator_sigscript`). Offsets
/// depend on `redeem_script_len` (= `Kcc20State::ENCODED_LEN + suffix.len()`)
/// only through `PushMinimal(R)`'s OWN prefix length (1/2/3/5 bytes
/// depending on how big `R` is) — see `push_minimal_prefix_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiblingFieldOffsets {
    pub amount_start: usize,
    pub amount_end: usize,
    pub digest_start: usize,
    pub digest_end: usize,
}

/// `push_data`-encoded length of a 65-byte `sig` (kcc-0001 `sig` payload
/// width): `push_data` uses a single length byte for payloads `<=75`, so
/// `1 + 65 = 66`.
const DELEGATOR_SIG_PUSH_LEN: usize = 1 + 65;
/// `OP_DATA_4` (1B) + the 4-byte dispatch tag.
const DISPATCH_TAG_PUSH_LEN: usize = 1 + 4;

fn delegator_sigscript_prefix_len() -> usize {
    DELEGATOR_SIG_PUSH_LEN + DISPATCH_TAG_PUSH_LEN
}

/// Prefix length (in bytes) that kcc-0001 §5.2 `PushMinimal` adds in front of
/// an `n`-byte payload. Mirrors the `push_minimal` encoding table in
/// `kcc20/mod.rs` (the payload sizes this module deals with — full redeem
/// scripts, always well over 1 byte — never hit the one-byte
/// `OP_1`..`OP_16`/`OP_1NEGATE` special cases, so only the length-based rows
/// matter here).
fn push_minimal_prefix_len(n: usize) -> usize {
    match n {
        0 => 1,
        1..=75 => 1,
        76..=255 => 2,
        256..=65535 => 3,
        _ => 5,
    }
}

/// Compute `SiblingFieldOffsets` for a delegator whose redeem script (state +
/// suffix) is `redeem_script_len` bytes long.
pub fn sibling_field_offsets(redeem_script_len: usize) -> SiblingFieldOffsets {
    let r_start = delegator_sigscript_prefix_len() + push_minimal_prefix_len(redeem_script_len);
    SiblingFieldOffsets {
        amount_start: r_start + R_AMOUNT_PAYLOAD_START,
        amount_end: r_start + R_AMOUNT_PAYLOAD_END,
        digest_start: r_start + R_DIGEST_PAYLOAD_START,
        digest_end: r_start + R_DIGEST_PAYLOAD_END,
    }
}

// ============================================================================
// transfer_delegator() body
// ============================================================================

/// Build the `transfer_delegator()` body (kcc-0001 §9.1 delegator role +
/// this module's "delegator self-authorizes" decision, see module doc).
///
/// Entry stack (top to bottom, after the 4 `Kcc20State` fields and the
/// dispatch-tag ROLL/DROP have already run — see `dispatch::build_dispatch_skeleton`):
/// `extended_state_digest(0), amount(1), identifier_type(2), owner_identifier(3),
/// self_sig(4)`. `self_sig` is this delegator's OWN 65-byte
/// `sig || sighash_type` (see the module-doc ISSUE: `transfer_delegator()` is
/// declared with zero arguments; this is real, necessary, non-conformant
/// invocation data).
pub fn build_transfer_delegator_body() -> Vec<u8> {
    use ops::*;
    let mut b = Vec::with_capacity(48);

    // Reject being the leader (kcc-0001 §9.1 rule 1: "Each path MUST reject
    // the opposite position"). Net stack effect: 0.
    e_own_covenant_id(&mut b);
    b.push(OP0);
    b.push(COVINPUTIDX); // leader_idx
    b.push(TXINPUTINDEX); // own_idx
    b.push(EQUAL);
    b.push(NOT);
    b.push(VERIFY);

    // Self-authorization: owner_identifier (already on stack, depth3 once
    // digest/amount/identifier_type are dropped) as the CheckSigVerify
    // pubkey, self_sig (depth4 -> depth1 after the same two drops) as the
    // signature. Identical convention to `token::TOKEN_UNIT_BODY`.
    b.push(TWO_DROP); // drop extended_state_digest, amount
    b.push(DROP); // drop identifier_type
    b.push(CHECKSIGVERIFY); // owner_identifier (pubkey) + self_sig

    b.push(OP1);
    b
}

// ============================================================================
// transfer(next_states, signatures, witnesses) body (leader)
// ============================================================================

/// Build the `transfer` leader body for a given `SiblingFieldOffsets`
/// (computed by the caller for the ACTUAL total redeem-script length — see
/// `build_kcc20_token_redeem_script`'s fixed-point construction, needed
/// because these offsets are pushed as bytecode literals that are themselves
/// part of the length they depend on).
///
/// Sigscript push order (deepest/first-pushed to shallowest/last-pushed):
/// `self_rs, new_rs_1, new_rs_2, .., new_rs_{MAX_N}, self_sig`. Entry stack
/// (top to bottom) once the dispatch skeleton delivers control here:
/// `extended_state_digest(0), amount(1), identifier_type(2), owner_identifier(3),
/// self_sig(4), new_rs_{MAX_N}(5), .., new_rs_1(MAX_N+4), self_rs(MAX_N+5)`.
pub fn build_transfer_body(offsets: SiblingFieldOffsets) -> Vec<u8> {
    use ops::*;
    let n = KCC20_TRANSFER_MAX_N;
    let mut b = Vec::with_capacity(4096);

    let self_rs_depth = n + 5;

    // ---- Leader position check (kcc-0001 §9.1 rule 1). Net 0. ----
    e_own_covenant_id(&mut b);
    b.push(OP0);
    b.push(COVINPUTIDX); // leader_idx
    b.push(TXINPUTINDEX); // own_idx
    b.push(EQUAL);
    b.push(VERIFY);

    // ---- Cardinality caps: consumed inputs and produced outputs must fit
    // the unroll bound. Without this, extra consumed/produced covenant
    // members beyond MAX_N would silently escape the conservation loops
    // below. Net 0 each. ----
    e_own_covenant_id(&mut b);
    b.push(COVINPUTCOUNT); // N_in
    e_num(&mut b, (n + 1) as u16);
    b.push(LTE);
    b.push(VERIFY);

    e_own_covenant_id(&mut b);
    b.push(COVOUTPUTCOUNT); // N_out
    e_num(&mut b, n as u16);
    b.push(LTE);
    b.push(VERIFY);

    // ---- Authenticate self_rs: Blake2b(self_rs) must equal THIS input's
    // committed P2SH hash (kcc-0001 §8.5 template authentication —
    // `self_rs`'s suffix is only trustworthy as "the template" once this
    // passes). Net 0. ----
    b.extend_from_slice(&dr_input_spk_check(self_rs_depth as u16));

    // ---- Seed the running conservation accumulator from this (leader's)
    // own `amount` (depth1), consuming it via ROLL (not PICK) so no dead
    // copy is left behind. Net 0 (a pure relabeling: digest shifts from
    // depth0 to depth1's slot... in fact ROLL(1) swaps the top two, so
    // digest ends up back at depth1 and the (former) amount becomes the
    // new depth0 accumulator). identifier_type/owner/self_sig/new_rs_*/self_rs
    // (all at depth>=2) are untouched by a roll of depth1. ----
    e_roll(&mut b, 1);

    const DIGEST_DEPTH: usize = 1;
    const OWNER_DEPTH: usize = 3;

    // ---- Sibling (delegator) pass: fold each active sibling's amount into
    // the accumulator and verify its digest matches. Every iteration is
    // "net 0 aside from the accumulator's value" so NEW_RS/SELF_RS/DIGEST
    // depths stay valid constants across the whole unrolled loop regardless
    // of which iterations' guards fire. ----
    for s in 1..=n {
        e_num(&mut b, s as u16);
        e_own_covenant_id(&mut b);
        b.push(COVINPUTCOUNT);
        b.push(LT); // s < N_in  (sibling slot s exists iff s < total consumed count)
        b.push(IF);
        {
            // amount: accumulator += sibling.amount
            e_own_covenant_id(&mut b);
            e_num(&mut b, s as u16);
            b.push(COVINPUTIDX); // sibling_idx
            e_num(&mut b, offsets.amount_start as u16);
            e_num(&mut b, offsets.amount_end as u16);
            b.push(TXINPUTSIGSUBSTR); // sibling.amount payload (8B, raw non-minimal LE
                                       // signed-magnitude -- accepted directly by OpAdd
                                       // under covenants_enabled, see module report)
            b.push(ADD);

            // digest: sibling.extended_state_digest == state digest
            e_own_covenant_id(&mut b);
            e_num(&mut b, s as u16);
            b.push(COVINPUTIDX);
            e_num(&mut b, offsets.digest_start as u16);
            e_num(&mut b, offsets.digest_end as u16);
            b.push(TXINPUTSIGSUBSTR); // sibling.digest
            e_pick(&mut b, DIGEST_DEPTH + 1); // state digest copy
            b.push(EQUAL);
            b.push(VERIFY);
        }
        b.push(ENDIF);
    }

    // ---- Successor pass: fold each active new_rs_k's amount into the
    // accumulator (subtracting), verify its digest, verify it is
    // template-authentic (dr_suffix_check against self_rs) and that the
    // claimed covenant output slot really is locked to it
    // (dr_output_spk_check). ----
    for j in 1..=n {
        let new_rs_depth = n + 5 - j;

        e_num(&mut b, j as u16);
        e_own_covenant_id(&mut b);
        b.push(COVOUTPUTCOUNT);
        b.push(LTE); // j <= N_out
        b.push(IF);
        {
            // amount: accumulator -= new_rs_j.amount
            b.extend_from_slice(&dr_field_extract(
                new_rs_depth as u16,
                R_AMOUNT_PAYLOAD_START as u16,
                R_AMOUNT_PAYLOAD_END as u16,
            ));
            b.push(SUB);

            // digest: new_rs_j.extended_state_digest == state digest
            b.extend_from_slice(&dr_field_extract(
                new_rs_depth as u16,
                R_DIGEST_PAYLOAD_START as u16,
                R_DIGEST_PAYLOAD_END as u16,
            ));
            e_pick(&mut b, DIGEST_DEPTH + 1);
            b.push(EQUAL);
            b.push(VERIFY);

            // successor binding: out_idx = OpCovOutputIdx(cov_id, j-1);
            // OpTxOutputSpk(out_idx) == P2SH(new_rs_j); new_rs_j's suffix ==
            // self_rs's suffix (template authentication, kcc-0001 §8.5).
            //
            // NOTE on `dr_output_spk_check`/`dr_suffix_check`'s depth
            // parameters: each helper's SECOND (and later) depth argument
            // must already account for the stack growth caused by the
            // EARLIER part of that SAME helper call (its own `new_rs`/
            // `old_rs` PICK-then-hash-or-size dance leaves one net extra
            // item behind before it reaches the next depth argument) --
            // confirmed against `dr.rs`'s own DCA usage/tests (e.g.
            // `dr_suffix_check(9, 11, ..)` where the raw, pre-call depth of
            // `new_rs` is 10, not 11). Getting this wrong does not panic at
            // the depth-tracking level -- it silently PICKs the wrong stack
            // item (here: the 37-byte "expected P2SH SPK" intermediate
            // instead of `out_idx`), which then fails much later and much
            // more confusingly (`OpTxOutputSpk`/arithmetic erroring with
            // "NumberTooBig ... 37 bytes"). This was caught only by running
            // the engine tests, not by re-deriving the depths on paper --
            // see the implementation report.
            e_own_covenant_id(&mut b);
            e_num(&mut b, (j - 1) as u16);
            b.push(COVOUTPUTIDX); // out_idx
            b.extend_from_slice(&dr_output_spk_check((new_rs_depth + 1) as u16, 1));
            b.extend_from_slice(&dr_suffix_check(
                (self_rs_depth + 1) as u16,
                (new_rs_depth + 2) as u16,
                Kcc20State::ENCODED_LEN as u16,
            ));
            b.push(DROP); // drop out_idx
        }
        b.push(ENDIF);
    }

    // ---- Final conservation check: accumulator == 0. ----
    b.push(OP0);
    b.push(NUMEQUALVERIFY);

    // ---- Leader's own ownership authorization. Stack now (accumulator and
    // its comparison zero both consumed): digest(0)[dead], identifier_type(1)
    // [dead], owner_identifier(2), self_sig(3), new_rs_n..new_rs_1, self_rs. ----
    let _ = OWNER_DEPTH; // (documents the pre-cleanup depth; consumed via TWO_DROP below)
    b.push(TWO_DROP); // drop digest, identifier_type
    b.push(CHECKSIGVERIFY); // owner_identifier (pubkey) + self_sig

    // ---- Cleanup: new_rs_1..new_rs_n, self_rs (n+1 items). ----
    let mut remaining = n + 1;
    while remaining >= 2 {
        b.push(TWO_DROP);
        remaining -= 2;
    }
    if remaining == 1 {
        b.push(DROP);
    }

    b.push(OP1);
    b
}

// ============================================================================
// Complete redeem script (state || dispatch skeleton)
// ============================================================================

/// Build the complete KCC20 token redeem script for `state`: `Kcc20State`'s
/// 77-byte encoded state, followed by the fixed two-entrypoint dispatch
/// skeleton (`transfer` / `transfer_delegator`).
///
/// The suffix (dispatch skeleton) is IDENTICAL for every instance of this one
/// covenant "kind" regardless of `state`'s field values — it depends only on
/// `KCC20_TRANSFER_MAX_N`. It is computed via a small fixed-point iteration:
/// `sibling_field_offsets` (baked into the leader body as bytecode literals)
/// depends on the total redeem-script length, which depends on the suffix's
/// own length. `push_index`'s encoding is constant-width across the whole
/// range these offsets fall in in practice, so this converges immediately;
/// the loop (bounded, asserted) is defensive rather than essential.
pub fn build_kcc20_token_redeem_script(state: &Kcc20State) -> crate::Result<Vec<u8>> {
    let state_bytes = state.encode_script()?;
    let suffix = transfer_suffix();
    let mut rs = Vec::with_capacity(state_bytes.len() + suffix.len());
    rs.extend_from_slice(&state_bytes);
    rs.extend_from_slice(&suffix);
    Ok(rs)
}

/// The dispatch-skeleton suffix shared by every KCC20 token instance built by
/// this module (see `build_kcc20_token_redeem_script`).
pub fn transfer_suffix() -> Vec<u8> {
    let delegator_body = build_transfer_delegator_body();
    let mut guess_len = Kcc20State::ENCODED_LEN;
    for _ in 0..8 {
        let offsets = sibling_field_offsets(guess_len);
        let leader_body = build_transfer_body(offsets);
        let skeleton = build_dispatch_skeleton(4, &leader_body, &delegator_body);
        let new_len = Kcc20State::ENCODED_LEN + skeleton.len();
        if new_len == guess_len {
            return skeleton;
        }
        guess_len = new_len;
    }
    panic!("kcc20 transfer suffix construction did not converge (fixed-point iteration exceeded bound)");
}

// ============================================================================
// Sigscript builders
// ============================================================================

fn sig_with_sighash_all(sig: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(sig);
    out.push(0x01); // SIGHASH_ALL
    out
}

/// Build the leader's `transfer` sigScript.
///
/// `new_rs_slots` must have exactly `KCC20_TRANSFER_MAX_N` entries; pad
/// unused (beyond the real successor count) slots with an empty `Vec` --
/// they are never read on-chain (guarded by `j <= OpCovOutputCount`).
pub fn build_transfer_leader_sigscript(
    self_rs: &[u8],
    new_rs_slots: &[Vec<u8>; KCC20_TRANSFER_MAX_N],
    self_sig: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut args = Vec::new();
    args.extend_from_slice(&push_data(self_rs));
    for slot in new_rs_slots {
        args.extend_from_slice(&push_data(slot));
    }
    args.extend_from_slice(&push_data(&sig_with_sighash_all(self_sig)));
    super::p2sh::build_sigscript(super::dispatch::Entrypoint::Transfer, &args, redeem_script)
}

/// Build a delegator's `transfer_delegator` sigScript: `push_data(self_sig)
/// || OP_DATA_4 tag || PushMinimal(R)`. See module doc: this pushes real
/// (non-empty) invocation data despite `transfer_delegator()`'s zero-argument
/// declaration -- a documented, necessary deviation.
pub fn build_transfer_delegator_sigscript(self_sig: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let args = push_data(&sig_with_sighash_all(self_sig));
    super::p2sh::build_sigscript(super::dispatch::Entrypoint::TransferDelegator, &args, redeem_script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_offsets_within_r_match_state_layout() {
        assert_eq!(R_AMOUNT_PAYLOAD_START, 36);
        assert_eq!(R_AMOUNT_PAYLOAD_END, 44);
        assert_eq!(R_DIGEST_PAYLOAD_START, 45);
        assert_eq!(R_DIGEST_PAYLOAD_END, 77);
    }

    #[test]
    fn push_minimal_prefix_len_matches_encoding_table() {
        assert_eq!(push_minimal_prefix_len(75), 1);
        assert_eq!(push_minimal_prefix_len(76), 2);
        assert_eq!(push_minimal_prefix_len(255), 2);
        assert_eq!(push_minimal_prefix_len(256), 3);
    }

    #[test]
    fn transfer_suffix_is_deterministic_and_converges() {
        let s1 = transfer_suffix();
        let s2 = transfer_suffix();
        assert_eq!(s1, s2);
        assert!(!s1.is_empty());
    }

    #[test]
    fn redeem_script_round_trips_through_kcc20_state_decode() {
        let state = Kcc20State::new([0x11; 32], super::super::identifier_type::PUBKEY, 1_000_000, [0x22; 32]);
        let rs = build_kcc20_token_redeem_script(&state).unwrap();
        assert!(rs.len() > Kcc20State::ENCODED_LEN);
        let decoded = Kcc20State::decode(&rs[..Kcc20State::ENCODED_LEN]);
        assert_eq!(decoded, Some(state));
    }

    #[test]
    fn sibling_field_offsets_are_after_delegator_prefix() {
        let offsets = sibling_field_offsets(150);
        assert!(offsets.amount_start > delegator_sigscript_prefix_len());
        assert_eq!(offsets.amount_end - offsets.amount_start, 8);
        assert_eq!(offsets.digest_end - offsets.digest_start, 32);
    }
}
