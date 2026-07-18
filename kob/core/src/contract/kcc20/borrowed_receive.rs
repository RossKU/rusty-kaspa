//! KCC20 Borrowed Receive Extension v1 (kcc-0020 "### KCC20 Borrowed Receive
//! Extension v1") -- **explicit stub, not implemented this wave**.
//!
//! ## Why stubbed (time-boxing decision, per task scope)
//!
//! The extension's five conditions are individually simple (kcc-0020):
//!
//! - `next_states[i]` exists;
//! - `owner_identifier` unchanged;
//! - `identifier_type` unchanged;
//! - `extended_state_digest` unchanged;
//! - `next_states[i].amount > prev_states[i].amount`; and
//! - the successor output's KAS value `>=` the consumed input's KAS value.
//!
//! But wiring them in requires re-opening `transfer.rs`'s core loop
//! structure, not bolting logic on beside it:
//!
//! 1. **Positional pairing changes the loop shape.** Borrowed Receive pairs
//!    consumed-state position `i` with successor position `i` (same index in
//!    BOTH the consumed-input ordering and the produced-output ordering).
//!    `transfer.rs`'s two passes (sibling/input pass indexed by covenant
//!    *input* position, successor/output pass indexed by covenant *output*
//!    position) are independent unrolled loops precisely because base
//!    kcc-0020 transfer never needs to relate "input position i" to "output
//!    position i" -- conservation is a GLOBAL sum, and digest/template
//!    checks are per-item, not cross-indexed. Borrowed Receive breaks that
//!    independence: it needs one COMBINED loop (or a cross-reference between
//!    the two existing ones) keyed by a shared index, plus a THIRD per-slot
//!    input, `witnesses[i]`, threaded through to select, per position, which
//!    of "normal transfer accounting" or "borrowed-receive accounting"
//!    applies to that slot.
//! 2. **The `identifier_type`/`owner_identifier` values needed for the
//!    "unchanged" checks are not currently read for successors at all.**
//!    `transfer.rs`'s successor pass only extracts `amount` and
//!    `extended_state_digest` from `new_rs_k` (the only two fields its own
//!    checks need) -- Borrowed Receive would need TWO more
//!    `dr_field_extract` calls per successor slot, PLUS the same two fields
//!    from the paired CONSUMED state (already available on-stack for the
//!    leader's own state, but requiring two more `OpTxInputScriptSigSubstr`
//!    reads per sibling).
//! 3. **The "exempt only from owner authorization" carve-out interacts with
//!    the delegator-self-authorizes design** (see `transfer.rs`'s module
//!    doc, decision (b)): in this implementation, a delegator input proves
//!    its OWN authorization locally via its OWN `OpCheckSigVerify`, using a
//!    signature it supplies in its OWN sigScript -- there is no leader-side
//!    per-input `signatures[i]` array to skip verifying in the first place
//!    (unlike interpretation (a), which the module doc rejected as
//!    unspec'd). Making a delegator's OWN authorization conditionally
//!    OPTIONAL (skippable when it is the "borrowed" recipient side of the
//!    transaction, spent WITHOUT its owner's cooperation) requires the
//!    delegator body itself to learn "am I being borrowed-received in this
//!    transition" -- but the delegator has no arguments either
//!    (`transfer_delegator()` is declared zero-arg; this wave already
//!    deviates from that to carry ONE self-authorization signature -- see
//!    `transfer.rs`). A borrowed input, by definition, is NOT cooperating
//!    with its own spend, so it cannot supply even that: some OTHER
//!    mechanism (most plausibly: the leader recognizing, from
//!    `witnesses[i]`, that input `i` needs no local signature at all, and
//!    the delegator body branching on a witness byte instead of
//!    unconditionally requiring `OpCheckSigVerify`) is needed. This is a
//!    real redesign of the delegator body's dispatch, not an add-on.
//!
//! Given the task's explicit "stub + ISSUE" allowance for this specific
//! extension when time is short, and that getting the core `transfer`/
//! `transfer_delegator` bodies working (and adversarially tested) is the
//! higher-value, harder-blocked deliverable, this module ships as a
//! documented no-op: it defines the extension's identifier and its five
//! conditions as data (for descriptor/tooling purposes) but no bytecode
//! builder.
//!
//! ## What a real implementation would need to change
//!
//! - `transfer.rs`'s `build_transfer_body` would need `witnesses[i]` threaded
//!   in as a genuine per-consumed-slot sigScript argument (this wave omits
//!   `witnesses[]` entirely -- see that module's doc);
//! - the sibling (input) and successor (output) unrolled passes would need
//!   to become ONE combined pass keyed by a shared position index (or the
//!   existing two passes would need to cross-reference each other's
//!   extracted fields per slot);
//! - the delegator body would need a witness-driven branch so a borrowed
//!   input's local `OpCheckSigVerify` can be skipped for that specific
//!   position, without breaking `transfer_delegator()`'s existing
//!   self-authorization path for every OTHER (normally-consumed) delegator.

/// Extension ID, exactly as kcc-0020 declares it.
pub const KCC20_BORROWED_RECEIVE_V1: &str = "kcc20_borrowed_receive_v1";

/// The reserved witness sentinel selecting the borrowed-receive pairing rule
/// for a given consumed-state position (kcc-0020: `BORROWED_RECEIVE = 0xFF`).
pub const BORROWED_RECEIVE: u8 = 0xFF;

/// The extension's five per-pair conditions (kcc-0020), as data only -- see
/// module doc for why no bytecode builder is provided this wave.
pub const BORROWED_RECEIVE_CONDITIONS: &[&str] = &[
    "next_states[i] exists",
    "owner_identifier unchanged",
    "identifier_type unchanged",
    "extended_state_digest unchanged",
    "next_states[i].amount > prev_states[i].amount",
    "successor output KAS value >= consumed input KAS value",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_id_matches_kcc_0020() {
        assert_eq!(KCC20_BORROWED_RECEIVE_V1, "kcc20_borrowed_receive_v1");
    }

    #[test]
    fn borrowed_receive_sentinel_matches_kcc_0020() {
        assert_eq!(BORROWED_RECEIVE, 0xFF);
    }

    #[test]
    fn five_conditions_documented() {
        assert_eq!(BORROWED_RECEIVE_CONDITIONS.len(), 6); // kcc-0020 lists 5 bullets;
                                                            // the 5th ("amount >") and
                                                            // successor-KAS-value are
                                                            // two separate bullets in
                                                            // the source text, giving 6
                                                            // total enumerable conditions.
    }
}
