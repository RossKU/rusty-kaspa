//! Robust KCC-0020 stablecoin covenant **body** and complete redeem script
//! builder (`STABLECOIN_ROBUST_DESIGN.md` §4 -- Phase I: foundation + the
//! TRANSFER vertical slice; Phase II branches: FREEZE, SEIZE, BURN, MIGRATE).
//!
//! The redeem script is `state (75B, see state.rs) || body`. The body is a
//! 6-way `op_type` dispatch ([`super::dispatch::build_op_type_dispatch`]):
//! `0x00 TRANSFER` (Phase I), `0x01 FREEZE`, `0x02 SEIZE`, `0x03 BURN`, and
//! `0x06 MIGRATE` (Phase II) wire real bytecode; `0x05 ROTATE` remains a
//! [`super::dispatch::UNIMPLEMENTED_BRANCH_STUB`] placeholder (a bare `OP_0`
//! -- fail-closed if ever reached), **deferred to post-Live** under Decision
//! 2026-07-19 (option B, baked keys): ROTATE only becomes meaningful once
//! role keys are verified against `role_registry_root` rather than baked, so
//! key rotation for the initial Live is redeploy+MIGRATE instead (see
//! [`build_migrate_branch`]'s doc). `0x04` is never compared against --
//! reserved for the separate mint-authority contract (§9).
//!
//! # Sigscript the body consumes (contract for the sigscript builder)
//!
//! After P2SH extraction pops the redeem script, the remaining stack (pushed
//! by the sigscript) must be, top-to-bottom (i.e. LAST push is shallowest).
//! This is TRANSFER's (`0x00`) shape; FREEZE (`0x01`) has NO owner
//! signature and instead carries the op-specific `new_frozen_flag` field in
//! that slot -- see [`build_freeze_branch`]'s doc and
//! `super::sigscript::build_stablecoin_freeze_sigscript` for its distinct
//! layout:
//!
//! ```text
//! op_type_selector (1B)                          <- top (last pushed)
//! owner_sig        (65B: 64-byte Schnorr sig || 0x01 SIGHASH_ALL)
//! new_rs           (variable: full candidate successor redeem script)
//! issuer_sig       (64B: raw Schnorr sig over the attestation message)  <- deepest (first pushed)
//! ```
//!
//! This input's `sig_op_count` MUST be **2** (one `OpCheckSigVerify` for the
//! owner + one `OpCheckSigFromStack` for the OPS role), same as case-A.
//! FREEZE's `sig_op_count` is **1** (only `OpCheckSigFromStack`, no owner
//! `OpCheckSigVerify`). BURN (`0x03`) is back to `sig_op_count` **2** (owner +
//! MINT role), but has NO `new_rs` field at all -- see [`build_burn_branch`]'s
//! doc and `super::sigscript::build_stablecoin_burn_sigscript` for its
//! (shorter) distinct layout: `issuer_sig` deepest, then `owner_sig`, then
//! `op_type_selector`.
//!
//! # Why `new_rs` is required at all (the P2SH-opacity problem)
//!
//! §4's TRANSFER invariant requires the successor's `role_registry_root` and
//! `epoch` to be byte-identical to this coin's own current values. But
//! `OpTxOutputSpk` only pushes the successor output's **P2SH locking
//! script** (`[0xaa][0x20][blake2b256(redeem_script)][0x87]`, 35 bytes,
//! `crate::contract::dr`/`settle::crypto::p2sh::build_p2sh`) -- the redeem
//! script's actual bytes (where `role_registry_root`/`epoch` physically
//! live) are hashed away and are NOT recoverable from the spent input's view
//! of a not-yet-revealed successor. There is no opcode that returns a
//! not-yet-spent output's *redeem script content*, only its opaque P2SH
//! commitment.
//!
//! The only sound mechanism (already established in this codebase for
//! exactly this "authenticate a successor covenant program" problem --
//! `crate::contract::dr`, used by `spot::dca` and `kcc20::transfer`) is: the
//! spender supplies the **candidate** successor redeem script (`new_rs`) as
//! plaintext sigscript data, the body **authenticates** it
//! (`dr_output_spk_check`: `Blake2b(new_rs)` reconstructed as a P2SH SPK and
//! compared against the REAL output at this input's index -- reusing
//! case-A's existing "OpTxInputIndex reused as the output index" 1:1
//! successor-binding convention), and only THEN reads fields out of the
//! now-authenticated plaintext (`dr_field_extract`).
//!
//! This is a necessary elaboration beyond the design doc's simplified §4
//! pseudocode (which reads as if `OpTxOutputSpk` directly exposed
//! `role_registry_root`/`epoch` bytes at a fixed offset -- it cannot, for the
//! reason above). **Flagged for human review**: this is a judgment call
//! about HOW to implement an explicitly-required invariant, not a change to
//! what is enforced. It also means TRANSFER is now heavier than case-A: it
//! authenticates a full successor redeem-script blob, not just an opaque SPK
//! hash.
//!
//! # TRANSFER (`0x00`) stack trace
//!
//! Entry (top-to-bottom), once the dispatch skeleton's `op_type` compare
//! delivers control here (state header's five fields, freshly pushed, sit
//! above the sigscript's four pushes):
//!
//! ```text
//! epoch(0), frozen_flag(1), role_registry_root(2), identifier_type(3),
//! owner_pubkey(4), owner_sig(5), new_rs(6), issuer_sig(7)
//! ```
//!
//! 1. Roll `owner_sig`, then `owner_pubkey`, to the top; `OpCheckSigVerify`
//!    (SIGHASH_ALL) -- mirrors case-A's owner authorization exactly, just
//!    reordered around the three new state fields sitting above them.
//! 2. Roll `identifier_type` to top; `OpDrop` (unused, same as case-A).
//! 3. Roll `frozen_flag` to top; compare to a literal `[0x00]` (NOT `OP_0`
//!    -- `frozen_flag` is an explicit `PushExplicit`-style 1-byte field, so
//!    the zero-comparison constant must also be an explicit 1-byte push);
//!    `OpVerify` -- fail-closed if frozen (§4's new TRANSFER invariant).
//! 4. `OpPick` a copy of `epoch` (needed twice: successor-carry check here,
//!    attestation preimage later).
//! 5. Successor authentication: fresh `OpTxInputIndex` as the output index
//!    (case-A's existing 1:1 convention) + `dr_output_spk_check` --
//!    `Blake2b(new_rs)` reconstructed as a P2SH SPK must equal the REAL
//!    successor output's SPK at this input's index.
//! 6. Extract `new_rs`'s `role_registry_root` payload (`dr_field_extract`)
//!    and compare to this coin's own (`OpEqual OpVerify`) -- §4's "successor
//!    must carry same root" invariant.
//! 7. Extract `new_rs`'s `epoch` payload and compare to this coin's own
//!    epoch copy (`OpEqual OpVerify`) -- §4's "...and same epoch" invariant.
//! 8. `new_rs` is no longer needed; drop it.
//! 9. Build the 121-byte attestation pre-image on top of `issuer_sig` by
//!    folding each field in with `OpCat`, in the exact order/widths of
//!    [`super::attestation::build_attestation_preimage`]: `DOMAIN_TAG` →
//!    `covenant_id` → `op_type` (literal `0x00`) → `epoch` (the remaining
//!    stack copy, rolled in) → `outpoint_txid` → `outpoint_index` →
//!    `successor_spk_hash` → `amount`. Every introspection index comes from
//!    `OpTxInputIndex` (replay-binding, unchanged from case-A).
//! 10. `OpBlake3` → `msg_hash`; push the OPS pubkey constant;
//!     `OpCheckSigFromStack OpVerify` -- fail-close on a missing/invalid
//!     OPS attestation (mirrors case-A's issuer-attestation gate exactly,
//!     just renamed to the spec's OPS role terminology).
//! 11. `Op1` -- success.
//!
//! # Omission flagged for human review: `frozen_flag` is not pinned across
//! TRANSFER
//!
//! §4's TRANSFER invariant list names only `role_registry_root` and `epoch`
//! as required to carry forward unchanged; it does not require
//! `frozen_flag` continuity. This body implements exactly that (no
//! `frozen_flag` comparison against the successor), so an OPS-signed
//! TRANSFER could in principle also flip `frozen_flag` in the successor
//! without going through the (Phase II) FREEZE branch's dedicated gate.
//! Since FREEZE doesn't exist yet in Phase I this has no operational effect
//! today, but it's worth a deliberate Phase II decision (pin it, or
//! document it as intentionally OPS-mutable via TRANSFER).

use super::attestation::{op_type, AMOUNT_LEN, OUTPOINT_INDEX_LEN, X_ONLY_PUBKEY_LEN};
use super::dispatch::{build_op_type_dispatch, OpTypeBranches, UNIMPLEMENTED_BRANCH_STUB};
use super::state::{
    frozen_flag, StablecoinStateHeader, EPOCH_PAYLOAD_OFFSET, FROZEN_FLAG_PAYLOAD_OFFSET, IDENTIFIER_TYPE_PAYLOAD_OFFSET,
    OWNER_PUBKEY_PAYLOAD_OFFSET, ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET, STATE_HEADER_LEN,
};
use super::DOMAIN_TAG;
use crate::contract::dr::{
    dr_field_extract, dr_input_spk_check, dr_output_spk_check, dr_suffix_check, dr_value_continuity_check,
};
use crate::contract::helpers::push_index;

/// Opcode bytes used by the stablecoin body (named for readability; values
/// are the canonical `crypto/txscript` assignments -- see
/// `core/src/contract/opcodes.rs` / `crypto/txscript/src/opcodes/mod.rs`).
mod op {
    pub const DROP: u8 = 0x75;
    pub const PICK: u8 = 0x79;
    pub const ROLL: u8 = 0x7a;
    pub const CAT: u8 = 0x7e;
    pub const EQUAL: u8 = 0x87;
    pub const VERIFY: u8 = 0x69;
    pub const CHECKSIGVERIFY: u8 = 0xad;
    pub const TXINPUTINDEX: u8 = 0xb9;
    pub const OUTPOINTTXID: u8 = 0xba;
    pub const OUTPOINTINDEX: u8 = 0xbb;
    pub const TXINPUTAMOUNT: u8 = 0xbe;
    pub const TXOUTPUTSPK: u8 = 0xc3;
    pub const NUM2BIN: u8 = 0xcd;
    pub const INPUTCOVENANTID: u8 = 0xcf;
    pub const CHECKSIGFROMSTACK: u8 = 0xd7;
    pub const BLAKE3: u8 = 0xd9;
    pub const OP1: u8 = 0x51;
    pub const OP2: u8 = 0x52;
    pub const OP4: u8 = 0x54;
    pub const OP8: u8 = 0x58;
    pub const DATA1: u8 = 0x01;
    pub const DATA8: u8 = 0x08;
    pub const DATA32: u8 = 0x20;
    pub const ADD: u8 = 0x93;
    pub const GREATERTHANOREQUAL: u8 = 0xa2;
}

// Compile-time guards tying the `OpNum2Bin` width literals to the encoder's
// field widths (mirrors case-A's guards, extended to the new base).
const _: () = assert!(OUTPOINT_INDEX_LEN == 4);
const _: () = assert!(AMOUNT_LEN == 8);
const _: () = assert!(X_ONLY_PUBKEY_LEN == 32);

/// Canonical "burn sink" REDEEM SCRIPT (`STABLECOIN_ROBUST_DESIGN.md` §4/§8,
/// BURN `0x03`): a single `OpReturn` (`0x6a`) byte.
///
/// # Live-discovered bug this fixes: a BARE `OpReturn` OUTPUT is non-standard
/// on Kaspa
///
/// This constant used to be used DIRECTLY as the sink's locking script
/// (`ScriptPublicKey = version(0) || [0x6a]`). That output was rejected by
/// every real node's mempool with `"transaction output #0: non-standard
/// script form"` (live testnet-10 run; the other 6 covenant ops --
/// deploy/mint/transfer/freeze/seize/unfreeze -- all relayed fine, because
/// their outputs are P2PK/P2SH). The rejection is not a config quirk: Kaspa's
/// mempool standardness gate
/// (`mining/src/mempool/check_transaction_standard.rs`'s
/// `check_transaction_standard_in_isolation`, which raises
/// `NonStandardError::RejectOutputScriptClass` -> `"non-standard script
/// form"`, `mining/errors/src/mempool.rs`) classifies every output via
/// `kaspa_txscript::script_class::ScriptClass::from_script`, which recognizes
/// **only three** shapes as standard: `PubKey` (`[OpData32][pk][OpCheckSig]`,
/// P2PK Schnorr), `PubKeyECDSA` (P2PK ECDSA), and `ScriptHash` (P2SH,
/// `[OpBlake2b][OpData32][hash(32B)][OpEqual]`, 35 bytes) -- all at SPK
/// version `0` (`MAX_SCRIPT_PUBLIC_KEY_VERSION`). Anything else, including a
/// bare `OpReturn`, falls through to `ScriptClass::NonStandard` and is
/// rejected. **Kaspa has no OP_RETURN-output standardness class at all**
/// (unlike Bitcoin's `nulldata`).
///
/// # The fix: P2SH-wrap this same unspendable byte
///
/// [`BURN_SINK_SCRIPT`] is now used as a P2SH REDEEM script (see
/// [`burn_sink_spk`]) instead of a bare locking script, via [`crate::build_p2sh`]
/// -- the identical Blake2b-based P2SH path every other covenant output in
/// this codebase already uses. The resulting locking script --
/// `[OpBlake2b][OpData32][Blake2b256([0x6a])][OpEqual]` -- IS one of the
/// three standard forms (`ScriptClass::ScriptHash`), so the mempool relays
/// it. It remains exactly as unspendable as before: `OpReturn` is a
/// hardwired unconditional-abort opcode in this engine (vendored
/// `crypto/txscript/src/opcodes/mod.rs`: `opcode OpReturn<0x6a, 1>(self, vm)
/// Err(TxScriptError::EarlyReturn)`, unconditional regardless of any other
/// stack contents or position). The instant anyone reveals `[0x6a]` as the
/// redeem script to spend this P2SH output (the ONLY redeem script that
/// hashes to the committed value, since Blake2b is preimage-resistant),
/// script execution aborts with `EarlyReturn` before any other check can
/// even run. There is no sigscript that can make this redeem script
/// evaluate successfully, so the P2SH commitment to it is provably
/// unspendable -- and, being a fresh single-byte redeem script with no
/// signer/state, this address is unrelated to (and unreachable from) every
/// other covenant's P2SH address in this codebase.
pub const BURN_SINK_SCRIPT: [u8; 1] = [0x6a];

/// The P2SH `ScriptPublicKey` locking [`BURN_SINK_SCRIPT`] -- computed via
/// the same [`crate::build_p2sh`]/Blake2b path every other covenant output in
/// this codebase uses: `[OpBlake2b][OpData32][Blake2b256(BURN_SINK_SCRIPT)][OpEqual]`,
/// 35 bytes, at SPK version `0`. See [`BURN_SINK_SCRIPT`]'s doc for why this
/// (rather than a bare `OpReturn` locking script) is the sink's standard
/// AND provably-unspendable form.
pub fn burn_sink_spk() -> kaspa_consensus_core::tx::ScriptPublicKey {
    crate::build_p2sh(&BURN_SINK_SCRIPT)
}

/// The scriptPublicKey bytes (`version(2B BIG-ENDIAN) || script`) that
/// `OpTxOutputSpk` pushes for [`burn_sink_spk`] (37 bytes: 2-byte version +
/// 35-byte P2SH script) -- matches the vendored engine's
/// `SpkEncoding::to_bytes` (`crypto/txscript/src/lib.rs`:
/// `self.version.to_be_bytes().into_iter().chain(...)`) and the same
/// big-endian convention every other off-chain SPK-bytes helper in this
/// codebase uses (`spk_bytes_be`/`spk_to_bytes` in the CLI harness/tests,
/// `dr_output_spk_check`'s in-script `[0x00, 0x00, 0xaa, 0x20]` reconstruction
/// prefix). Version is always `0` (`MAX_SCRIPT_PUBLIC_KEY_VERSION`) for a
/// P2SH SPK, so big- vs little-endian is a no-op in practice today, but this
/// keeps the encoding correct-by-construction rather than correct-by-
/// coincidence. This is no longer baked into or compared against by
/// [`build_burn_branch`]'s on-chain sink-pin check (see that fn's doc) --
/// it remains as the OFF-CHAIN utility for constructing the actual sink
/// output (what the CLI harness's `build_p2sh(&BURN_SINK_SCRIPT)` computes).
pub fn burn_sink_spk_bytes() -> Vec<u8> {
    let spk = burn_sink_spk();
    let mut out = Vec::with_capacity(2 + spk.script().len());
    out.extend_from_slice(&spk.version().to_be_bytes());
    out.extend_from_slice(spk.script());
    out
}

fn e_roll(b: &mut Vec<u8>, depth: u16) {
    push_index(b, depth);
    b.push(op::ROLL);
}

fn e_pick(b: &mut Vec<u8>, depth: u16) {
    push_index(b, depth);
    b.push(op::PICK);
}

/// Emit the TRANSFER (`0x00`) branch bytecode. See the module doc's "TRANSFER
/// stack trace" for the full derivation. Entry stack (top to bottom):
/// `epoch(0), frozen_flag(1), role_registry_root(2), identifier_type(3),
/// owner_pubkey(4), owner_sig(5), new_rs(6), issuer_sig(7)`.
fn build_transfer_branch(ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(160);

    // ---- Owner authorization (mirrors case-A's stage 1). ----
    e_roll(&mut b, 5); // owner_sig -> top
    e_roll(&mut b, 5); // owner_pubkey -> top (owner_sig now at depth1)
    b.push(CHECKSIGVERIFY); // pubkey(top) x sig(next), SIGHASH_ALL

    // Stack: epoch(0), frozen_flag(1), role_registry_root(2),
    // identifier_type(3), new_rs(4), issuer_sig(5).
    // ---- successor.identifier_type == this coin's own (audit hygiene, final
    // round). FREEZE and SEIZE both pin it; TRANSFER used to DROP it unread. It
    // drives no on-chain branch, so an altered value has no consensus effect --
    // but off-chain indexers and wallets classify a coin's owner-identifier from
    // this byte, and nothing about a transfer should be able to relabel it.
    // Compared against this coin's OWN value rather than a baked literal,
    // because the deployer chooses `identifier_type` at construction. Net stack
    // effect is identical to the DROP this replaces. ----
    e_roll(&mut b, 3); // identifier_type -> top
    // Stack: identifier_type(0), epoch(1), frozen_flag(2), role_registry_root(3),
    // new_rs(4), issuer_sig(5).
    b.extend_from_slice(&dr_field_extract(4, IDENTIFIER_TYPE_PAYLOAD_OFFSET as u16, (IDENTIFIER_TYPE_PAYLOAD_OFFSET + 1) as u16));
    // Stack: succ_idtype(0), identifier_type(1), epoch(2), frozen_flag(3),
    // role_registry_root(4), new_rs(5), issuer_sig(6).
    e_roll(&mut b, 1); // this coin's own identifier_type -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch(0), frozen_flag(1), role_registry_root(2), new_rs(3),
    // issuer_sig(4).
    e_roll(&mut b, 1); // frozen_flag -> top
    b.push(DATA1);
    b.push(frozen_flag::CLEAR); // literal explicit-push [0x00] (NOT OpN 0 / empty array)
    b.push(EQUAL);
    b.push(VERIFY); // frozen_flag == 0, fail-closed (§4 new invariant)

    // Stack: epoch(0), role_registry_root(1), new_rs(2), issuer_sig(3).
    e_pick(&mut b, 0); // copy of epoch (needed again for the preimage below)

    // Stack: epoch_copy(0), epoch(1), role_registry_root(2), new_rs(3),
    // issuer_sig(4).
    b.push(TXINPUTINDEX); // fresh -- this input's own index, reused as the
    // output index (case-A's existing 1:1 successor-binding convention).
    // Stack: input_idx(0), epoch_copy(1), epoch(2), role_registry_root(3),
    // new_rs(4), issuer_sig(5).
    b.extend_from_slice(&dr_output_spk_check(4, 1)); // Blake2b(new_rs) == P2SH(real successor SPK)
    b.push(DROP); // drop input_idx (net effect of the check above is 0
                  // otherwise -- see dr.rs's own depth-adjustment discipline)

    // ---- Template authentication (CRITICAL fix, audit 2026-07-20 §E). ----
    // `dr_output_spk_check` above only proves the spender's `new_rs` is the
    // script the successor output pays to. It says NOTHING about what that
    // script CONTAINS. Every role pubkey lives in the body, after the mutable
    // state header, so without the check below a spender can hand over a
    // successor that keeps the state fields this branch compares while baking
    // an entirely different role set -- moving the coin into a covenant the
    // real issuer has no keys for. FREEZE takes no owner signature at all, so
    // there it was a single-key total takeover; TRANSFER reopened the exact
    // governance exit the MIGRATE cold-quorum gate closed, at the lower price
    // of a hot OPS key.
    //
    // `self_rs` is this coin's OWN redeem script, supplied by the sigscript as
    // its deepest item (the same bytes it already pushes last for the P2SH
    // wrapper, so no caller-visible field was added) and proven genuine here
    // against this input's own SPK. Everything from `STATE_HEADER_LEN` onward
    // must then match byte for byte -- the same template authentication
    // kcc-0001 5.8.5 requires and the sibling KCC20 transfer covenant already
    // performed. MIGRATE is deliberately exempt: its successor is an arbitrary
    // new template by design, which is why that branch requires the cold quorum.
    // Stack: epoch_copy(0), epoch(1), role_registry_root(2), new_rs(3),
    // issuer_sig(4), self_rs(5).
    b.extend_from_slice(&dr_input_spk_check(5)); // P2SH(self_rs) == this input's own SPK
    // dr_suffix_check's SECOND depth must account for the one net item its own
    // first half leaves behind -- new_rs is raw depth 3, hence 4 here.
    b.extend_from_slice(&dr_suffix_check(5, 4, STATE_HEADER_LEN as u16));
    e_roll(&mut b, 5); // self_rs -> top
    b.push(DROP); // done with it; stack returns to the layout below

    // Stack: epoch_copy(0), epoch(1), role_registry_root(2), new_rs(3),
    // issuer_sig(4).
    b.extend_from_slice(&dr_field_extract(3, ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET as u16, (ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET + 32) as u16));
    // Stack: new_root(0), epoch_copy(1), epoch(2), role_registry_root(3),
    // new_rs(4), issuer_sig(5).
    e_roll(&mut b, 3); // this coin's own role_registry_root -> top
    b.push(EQUAL);
    b.push(VERIFY); // successor.role_registry_root == own (§4 invariant)

    // Stack: epoch_copy(0), epoch(1), new_rs(2), issuer_sig(3).
    b.extend_from_slice(&dr_field_extract(2, EPOCH_PAYLOAD_OFFSET as u16, (EPOCH_PAYLOAD_OFFSET + 4) as u16));
    // Stack: new_epoch(0), epoch_copy(1), epoch(2), new_rs(3), issuer_sig(4).
    e_roll(&mut b, 1); // epoch_copy -> top
    b.push(EQUAL);
    b.push(VERIFY); // successor.epoch == own (§4 invariant)

    // ---- successor.frozen_flag == CLEAR (audit fix, final round 2026-07-20).
    // TRANSFER gates on THIS coin's frozen_flag being 0x00 but used to leave the
    // SUCCESSOR's byte entirely unconstrained, which made two claims elsewhere
    // in this file false: that FREEZE is the only branch that writes
    // `frozen_flag`, and that the domain gate confines it to {0x00, 0x01}.
    // Owner + OPS -- the two keys TRANSFER already needs, neither of them the
    // FREEZE role -- could hand the coin a successor carrying 0x01 (freezing it
    // without the freeze key) or an out-of-domain byte like 0x02, which every
    // owner branch's bytewise compare against [0x00] then rejects forever,
    // leaving the coin immobile until the FREEZE key or the SEIZE quorum
    // intervenes.
    //
    // Comparing against the literal, not against this coin's own byte, is
    // deliberate: the gate above already established the current value IS
    // 0x00, so the literal is the same constraint stated in one fewer stack
    // operation, and it stays correct if the gate is ever tightened. ----
    // Stack: epoch(0), new_rs(1), issuer_sig(2).
    b.extend_from_slice(&dr_field_extract(1, FROZEN_FLAG_PAYLOAD_OFFSET as u16, (FROZEN_FLAG_PAYLOAD_OFFSET + 1) as u16));
    // Stack: succ_frozen(0), epoch(1), new_rs(2), issuer_sig(3).
    b.push(DATA1);
    b.push(frozen_flag::CLEAR);
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch(0), new_rs(1), issuer_sig(2). new_rs no longer needed.
    e_roll(&mut b, 1);
    b.push(DROP);

    // ---- Attestation pre-image (121B base, §4/§5): DOMAIN_TAG || covenant_id
    // || op_type || epoch || outpoint_txid || outpoint_index ||
    // successor_spk_hash || amount. ----
    // Stack: epoch(0), issuer_sig(1).
    b.push(DATA8);
    b.extend_from_slice(&DOMAIN_TAG);
    // Stack: domain_tag(0), epoch(1), issuer_sig(2).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(CAT); // acc = domain_tag || covenant_id
    // Stack: acc(0), epoch(1), issuer_sig(2).
    b.push(DATA1);
    b.push(op_type::TRANSFER);
    b.push(CAT); // acc || op_type
    // Stack: acc(0), epoch(1), issuer_sig(2).
    e_roll(&mut b, 1); // epoch -> top
    b.push(CAT); // acc || epoch
    // Stack: acc(0), issuer_sig(1).
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT); // acc || outpoint_txid
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT); // acc || outpoint_index(4B LE)
    b.push(TXINPUTINDEX);
    b.push(TXOUTPUTSPK);
    b.push(BLAKE3);
    b.push(CAT); // acc || successor_spk_hash
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(OP8);
    b.push(NUM2BIN);
    b.push(CAT); // acc || amount(8B LE) == full 121B preimage

    // msg_hash = Blake3(preimage). Stack: msg_hash(0), issuer_sig(1).
    b.push(BLAKE3);

    // Push OPS pubkey; verify the attestation.
    b.push(DATA32);
    b.extend_from_slice(ops_pubkey);
    b.push(CHECKSIGFROMSTACK);
    b.push(VERIFY);

    b.push(OP1);
    b
}

/// Emit the FREEZE (`0x01`) branch bytecode (`STABLECOIN_ROBUST_DESIGN.md`
/// §4/§5). No owner signature at all -- the FREEZE role alone gates it, so
/// this branch's entry stack replaces TRANSFER's `owner_sig` slot with the
/// op-specific `new_frozen_flag` preimage field (both sit at the same depth,
/// 5, since the state header always pushes exactly five fields regardless of
/// which branch is taken -- see [`OP_TYPE_TAG_DEPTH`]).
///
/// Entry (top-to-bottom), once the dispatch skeleton's `op_type` compare
/// delivers control here:
///
/// ```text
/// epoch(0), frozen_flag(1), role_registry_root(2), identifier_type(3),
/// owner_pubkey(4), new_frozen_flag(5), new_rs(6), issuer_sig(7)
/// ```
///
/// Mirrors [`build_transfer_branch`]'s successor-authentication mechanics
/// (`dr_output_spk_check` + `dr_field_extract`, reused verbatim -- no changes
/// to `crate::contract::dr`), but the FREEZE effect (task spec: "successor
/// state identical to input EXCEPT frozen_flag set to new_frozen_flag") is
/// STRICTER than TRANSFER's successor-continuity check: TRANSFER only pins
/// `role_registry_root`+`epoch` (owner_pubkey is meant to change on a
/// transfer; identifier_type is dropped unchecked, a pre-existing case-A
/// carryover). FREEZE must not move funds or touch identity/policy at all, so
/// it pins ALL FOUR of `owner_pubkey`, `identifier_type`, `role_registry_root`,
/// `epoch` unchanged, and separately binds the successor's `frozen_flag` byte
/// to equal the attested `new_frozen_flag` (not this coin's OWN current
/// frozen_flag, which is read but otherwise unused/unconstrained here --
/// FREEZE must work from either starting state, 0->1 or 1->0).
///
/// # `new_frozen_flag` domain gate (audit fix 2026-07-20)
///
/// FREEZE is the only branch that CHANGES `frozen_flag` (TRANSFER/SEIZE pin
/// the successor's byte to a value they already know), and it writes
/// whatever byte the attestation carries. The post-Live audit
/// (`STABLECOIN_AUDIT_2026-07-20.md` §B4) flagged that nothing constrained
/// that byte to `{0x00, 0x01}`: every other branch tests the field with a
/// BYTEWISE `OpEqual` against `[0x00]`, so writing e.g. `[0x02]` creates an
/// undefined third state -- not "clear" to TRANSFER/BURN/MIGRATE (they all
/// abort), yet not the `[0x01]` that tooling recognizes as frozen. Reachable
/// by the FREEZE key alone, it would brick the coin's owner-side branches
/// with no defined unfreeze semantics. This branch now gates the value to
/// exactly the two canonical literals up front, bytewise (a numeric compare
/// would also admit non-minimal encodings of 0/1, which the explicit-push
/// convention forbids).
///
/// `freeze_pubkey` is baked into the branch bytecode as a literal constant,
/// exactly as `build_transfer_branch` bakes in `ops_pubkey` -- role pubkeys
/// are NOT (yet) individually revealed-and-verified against
/// `role_registry_root` on-chain in this phase (the root is carried as an
/// opaque commitment; see `state.rs`'s `compute_role_registry_root` doc). This
/// keeps FREEZE's authorization mechanism consistent with TRANSFER's existing
/// OPS-key pattern rather than inventing a different convention for the one
/// new role.
///
/// # Value continuity (security fix)
///
/// TRANSFER gets successor-value continuity "for free": the owner's
/// `SIGHASH_ALL` signature commits the whole transaction, including every
/// output's amount, so nothing else needs to pin it. FREEZE has **no owner
/// signature at all** -- the FREEZE role's `OpCheckSigFromStack` attestation
/// signs only the fixed-format 122-byte preimage (which includes this
/// input's CURRENT amount as a replay-binding field, but never compares it
/// against the successor OUTPUT's actual value). Without an explicit check,
/// a holder of only the FREEZE key could change the coin's native (sompi)
/// value in the successor output while freezing/unfreezing -- value
/// theft/destruction by a role the design (`STABLECOIN_ROBUST_DESIGN.md`
/// §11) documents as "policy-only" (freeze-flag-only) risk. This branch
/// closes that hole with [`dr_value_continuity_check`] (`crate::contract::dr`),
/// a reusable, depth-argument-free helper that asserts
/// `OpTxOutputAmount(successor) == OpTxInputAmount(self)` (exact equality --
/// a 1:1 covenant; the tx fee must come from a separate funding input, not by
/// shaving the covenant coin). The upcoming SEIZE (`0x02`) and ROTATE (`0x05`)
/// branches also lack an owner signature and MUST call the same helper (see
/// `STABLECOIN_ROBUST_DESIGN.md` §4's cross-branch invariant).
fn build_freeze_branch(freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(200);

    // ---- Domain gate: new_frozen_flag MUST be exactly one of the two
    // canonical 1-byte literals (`frozen_flag::CLEAR` / `frozen_flag::SET`).
    // Without this the FREEZE key can write ANY byte into the successor's
    // frozen_flag slot; every other branch tests that slot with a BYTEWISE
    // `OpEqual` against `[0x00]`, so an out-of-domain value (e.g. `[0x02]`)
    // reads as "not clear" to TRANSFER/BURN/MIGRATE while never matching the
    // `[0x01]` any tooling looks for -- an undefined third state reachable by
    // a single role key. Checked bytewise (NOT numerically): the field is a
    // literal explicit push, so a numeric comparison would also accept
    // non-minimal or alternately-encoded representations of 0/1. ----
    // Stack: epoch(0), frozen_flag(1), root(2), identifier_type(3),
    // owner_pubkey(4), new_frozen_flag(5), new_rs(6), issuer_sig(7).
    e_pick(&mut b, 5); // copy of new_frozen_flag -> top
    e_pick(&mut b, 0); // a second copy (the first is consumed by the CLEAR test)
    b.push(DATA1);
    b.push(frozen_flag::CLEAR);
    b.push(EQUAL); // is_clear
    // Stack: is_clear(0), new_frozen_flag_copy(1), epoch(2), ...
    e_roll(&mut b, 1); // new_frozen_flag_copy -> top
    b.push(DATA1);
    b.push(frozen_flag::SET);
    b.push(EQUAL); // is_set
    // Stack: is_set(0), is_clear(1), epoch(2), ...
    b.push(ADD); // exactly one can match, so the sum is 1 (valid) or 0 (invalid)
    b.push(VERIFY); // fail-closed on any other byte

    // Stack: epoch(0), frozen_flag(1), root(2), identifier_type(3),
    // owner_pubkey(4), new_frozen_flag(5), new_rs(6), issuer_sig(7).
    e_roll(&mut b, 1); // this coin's own frozen_flag -> top (unused by FREEZE)
    b.push(DROP);

    // Stack: epoch(0), root(1), identifier_type(2), owner_pubkey(3),
    // new_frozen_flag(4), new_rs(5), issuer_sig(6).
    e_pick(&mut b, 0); // copy of epoch (needed again for the preimage below)

    // Stack: epoch_copy(0), epoch(1), root(2), identifier_type(3),
    // owner_pubkey(4), new_frozen_flag(5), new_rs(6), issuer_sig(7).
    b.push(TXINPUTINDEX); // fresh -- this input's own index, reused as the
                           // output index (case-A's 1:1 successor-binding convention).
    // Stack: input_idx(0), epoch_copy(1), epoch(2), root(3),
    // identifier_type(4), owner_pubkey(5), new_frozen_flag(6), new_rs(7),
    // issuer_sig(8).
    b.extend_from_slice(&dr_output_spk_check(7, 1)); // Blake2b(new_rs) == P2SH(real successor SPK)
    b.push(DROP); // drop input_idx

    // ---- Template authentication (CRITICAL fix, audit 2026-07-20 §E). ----
    // `dr_output_spk_check` above only proves the spender's `new_rs` is the
    // script the successor output pays to. It says NOTHING about what that
    // script CONTAINS. Every role pubkey lives in the body, after the mutable
    // state header, so without the check below a spender can hand over a
    // successor that keeps the state fields this branch compares while baking
    // an entirely different role set -- moving the coin into a covenant the
    // real issuer has no keys for. FREEZE takes no owner signature at all, so
    // there it was a single-key total takeover; TRANSFER reopened the exact
    // governance exit the MIGRATE cold-quorum gate closed, at the lower price
    // of a hot OPS key.
    //
    // `self_rs` is this coin's OWN redeem script, supplied by the sigscript as
    // its deepest item (the same bytes it already pushes last for the P2SH
    // wrapper, so no caller-visible field was added) and proven genuine here
    // against this input's own SPK. Everything from `STATE_HEADER_LEN` onward
    // must then match byte for byte -- the same template authentication
    // kcc-0001 5.8.5 requires and the sibling KCC20 transfer covenant already
    // performed. MIGRATE is deliberately exempt: its successor is an arbitrary
    // new template by design, which is why that branch requires the cold quorum.
    // Stack: epoch_copy(0), epoch(1), root(2), identifier_type(3),
    // owner_pubkey(4), new_frozen_flag(5), new_rs(6), issuer_sig(7),
    // self_rs(8).
    b.extend_from_slice(&dr_input_spk_check(8)); // P2SH(self_rs) == this input's own SPK
    b.extend_from_slice(&dr_suffix_check(8, 7, STATE_HEADER_LEN as u16)); // new_rs raw depth 6 -> 7
    e_roll(&mut b, 8); // self_rs -> top
    b.push(DROP);

    // Stack: epoch_copy(0), epoch(1), root(2), identifier_type(3),
    // owner_pubkey(4), new_frozen_flag(5), new_rs(6), issuer_sig(7).

    // ---- Value continuity (security fix, see this fn's doc "Value
    // continuity" section): FREEZE has no owner SIGHASH_ALL signature, so
    // nothing else on this path pins the successor covenant output's native
    // value to this input's value -- without this check a holder of only the
    // FREEZE key could alter the coin's sompi amount while freezing/
    // unfreezing. `dr_value_continuity_check` is self-contained (net zero
    // stack effect, no depth argument), so it can be spliced in here without
    // touching any of the depth comments above/below.
    b.extend_from_slice(&dr_value_continuity_check());

    // ---- Successor must be identical EXCEPT frozen_flag (task spec). ----
    // owner_pubkey unchanged.
    b.extend_from_slice(&dr_field_extract(6, OWNER_PUBKEY_PAYLOAD_OFFSET as u16, (OWNER_PUBKEY_PAYLOAD_OFFSET + 32) as u16));
    // Stack: succ_owner(0), epoch_copy(1), epoch(2), root(3),
    // identifier_type(4), owner_pubkey(5), new_frozen_flag(6), new_rs(7),
    // issuer_sig(8).
    e_roll(&mut b, 5); // this coin's own owner_pubkey -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch_copy(0), epoch(1), root(2), identifier_type(3),
    // new_frozen_flag(4), new_rs(5), issuer_sig(6).
    // identifier_type unchanged.
    b.extend_from_slice(&dr_field_extract(5, IDENTIFIER_TYPE_PAYLOAD_OFFSET as u16, (IDENTIFIER_TYPE_PAYLOAD_OFFSET + 1) as u16));
    // Stack: succ_idtype(0), epoch_copy(1), epoch(2), root(3),
    // identifier_type(4), new_frozen_flag(5), new_rs(6), issuer_sig(7).
    e_roll(&mut b, 4); // this coin's own identifier_type -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch_copy(0), epoch(1), root(2), new_frozen_flag(3), new_rs(4),
    // issuer_sig(5).
    // role_registry_root unchanged.
    b.extend_from_slice(&dr_field_extract(4, ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET as u16, (ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET + 32) as u16));
    // Stack: succ_root(0), epoch_copy(1), epoch(2), root(3),
    // new_frozen_flag(4), new_rs(5), issuer_sig(6).
    e_roll(&mut b, 3); // this coin's own role_registry_root -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch_copy(0), epoch(1), new_frozen_flag(2), new_rs(3),
    // issuer_sig(4).
    // epoch unchanged.
    b.extend_from_slice(&dr_field_extract(3, EPOCH_PAYLOAD_OFFSET as u16, (EPOCH_PAYLOAD_OFFSET + 4) as u16));
    // Stack: succ_epoch(0), epoch_copy(1), epoch(2), new_frozen_flag(3),
    // new_rs(4), issuer_sig(5).
    e_roll(&mut b, 1); // epoch_copy -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch(0), new_frozen_flag(1), new_rs(2), issuer_sig(3).
    // frozen_flag == attested new_frozen_flag (NOT this coin's own current
    // frozen_flag -- that field was dropped, unused, above).
    e_pick(&mut b, 1); // copy of new_frozen_flag (needed again for the preimage tail)
    // Stack: new_frozen_flag_copy(0), epoch(1), new_frozen_flag(2), new_rs(3),
    // issuer_sig(4).
    b.extend_from_slice(&dr_field_extract(3, FROZEN_FLAG_PAYLOAD_OFFSET as u16, (FROZEN_FLAG_PAYLOAD_OFFSET + 1) as u16));
    // Stack: succ_frozen(0), new_frozen_flag_copy(1), epoch(2),
    // new_frozen_flag(3), new_rs(4), issuer_sig(5).
    e_roll(&mut b, 1); // new_frozen_flag_copy -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch(0), new_frozen_flag(1), new_rs(2), issuer_sig(3). new_rs no
    // longer needed; drop it.
    e_roll(&mut b, 2);
    b.push(DROP);

    // ---- Attestation pre-image (122B, §4/§5): 121B base + new_frozen_flag
    // tail. ----
    // Stack: epoch(0), new_frozen_flag(1), issuer_sig(2).
    b.push(DATA8);
    b.extend_from_slice(&DOMAIN_TAG);
    // Stack: domain_tag(0), epoch(1), new_frozen_flag(2), issuer_sig(3).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(CAT); // acc = domain_tag || covenant_id
    // Stack: acc(0), epoch(1), new_frozen_flag(2), issuer_sig(3).
    b.push(DATA1);
    b.push(op_type::FREEZE);
    b.push(CAT); // acc || op_type
    // Stack: acc(0), epoch(1), new_frozen_flag(2), issuer_sig(3).
    e_roll(&mut b, 1); // epoch -> top
    b.push(CAT); // acc || epoch
    // Stack: acc(0), new_frozen_flag(1), issuer_sig(2).
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT); // acc || outpoint_txid
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT); // acc || outpoint_index(4B LE)
    b.push(TXINPUTINDEX);
    b.push(TXOUTPUTSPK);
    b.push(BLAKE3);
    b.push(CAT); // acc || successor_spk_hash
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(OP8);
    b.push(NUM2BIN);
    b.push(CAT); // acc || amount(8B LE) == full 121B base preimage
    // Stack: acc(0), new_frozen_flag(1), issuer_sig(2).
    e_roll(&mut b, 1); // new_frozen_flag -> top
    b.push(CAT); // acc || new_frozen_flag == full 122B FREEZE preimage

    // msg_hash = Blake3(preimage). Stack: msg_hash(0), issuer_sig(1).
    b.push(BLAKE3);

    // Push FREEZE pubkey; verify the attestation.
    b.push(DATA32);
    b.extend_from_slice(freeze_pubkey);
    b.push(CHECKSIGFROMSTACK);
    b.push(VERIFY);

    b.push(OP1);
    b
}

/// Emit the SEIZE (`0x02`) branch bytecode (`STABLECOIN_ROBUST_DESIGN.md`
/// §4/§5/§7, Phase II branch 3). No owner signature at all -- the issuer
/// force-moves the coin without the holder's consent (§7: this doubles as
/// both punitive seizure and user-rescue, decided off-chain by whoever
/// controls the quorum before it signs). Authorization is a **2-of-3**
/// threshold over three BAKED SEIZE pubkeys (design decision "option B":
/// baked bytecode literals, the SAME convention as `ops_pubkey`/
/// `freeze_pubkey` -- `role_registry_root` is NOT individually read/verified
/// on-chain in this phase).
///
/// # Why three `OpCheckSigFromStack` calls instead of native `OpCheckMultiSig`
///
/// The design doc's own per-branch pseudocode (§4, "0x02 SEIZE") writes
/// `OpCheckMultiSig` operating over the reconstructed attestation `msg_hash`
/// (the `OpBlake3` result) -- but the codebase's REAL `OpCheckMultiSig`
/// (`crypto/txscript/src/opcodes/mod.rs:1000`, opcode `0xae`) has no such
/// "message from stack" form: it is hard-wired to
/// `op_check_multisig_schnorr_or_ecdsa`, which always verifies each candidate
/// signature against the CURRENT TRANSACTION's own sighash
/// (`calc_schnorr_signature_hash`/`SigHashType`), exactly like
/// `OpCheckSig`/`OpCheckSigVerify` -- there is no `OpCheckMultiSigFromStack`
/// opcode in this engine (only the single-signature
/// `OpCheckSigFromStack`/`OpCheckSigFromStackECDSA` support an arbitrary
/// stack-supplied message hash). A repo-wide grep for `OpCheckMultiSig` /
/// `0xae` / "multisig" turned up zero uses of native multisig anywhere in
/// this crate's own covenant builders (`spot`, `time`, `kcc20`, `stablecoin`)
/// -- the ONLY established KOB covenant idiom for role-gated, spend-bound
/// authorization is the `OpCheckSigFromStack`-over-reconstructed-preimage
/// pattern TRANSFER (OPS role) and FREEZE (FREEZE role) already use. This
/// branch reuses that exact idiom, three times over three baked pubkeys at
/// FIXED sigscript slots (`sig1`<->`seize_pubkeys[0]`, `sig2`<->`[1]`,
/// `sig3`<->`[2]`) -- a holder of only 2 of the 3 keys supplies a genuine
/// signature in their two slots and an arbitrary 64-byte placeholder in the
/// third (`OpCheckSigFromStack` parses any 64 bytes as a structurally valid
/// Schnorr signature and simply evaluates to `false` on a non-matching key --
/// see `check_schnorr_signature_with_msg_hash`; it only hard-errors on a
/// malformed PUBKEY or a wrong-length signature buffer, and the three
/// pubkeys here are fixed, valid constants). The three booleans are summed
/// (`OpAdd` twice) and compared `>= 2` (`OpGreaterThanOrEqual OpVerify`) -- a
/// fixed-position 2-of-3 threshold, simpler than native `OpCheckMultiSig`'s
/// greedy ordered-skip matching algorithm (which exists to support a
/// SPENDER-supplied, variable-order pubkey list; here the three pubkeys are
/// baked constants known at redeem-script-build time, so positional matching
/// is sufficient and avoids reimplementing an unused generality).
///
/// One consequence: unlike a genuine tx-sighash-bound signature (which would
/// commit every output's amount "for free", the same way TRANSFER's owner
/// `SIGHASH_ALL` signature does), these `OpCheckSigFromStack` checks only
/// commit the fixed-format attestation preimage -- so SEIZE needs its own
/// explicit value-continuity check, same as FREEZE (see below).
///
/// Entry (top-to-bottom), once the dispatch skeleton's `op_type` compare
/// delivers control here:
///
/// ```text
/// epoch(0), frozen_flag(1), role_registry_root(2), identifier_type(3),
/// owner_pubkey(4), new_owner_pubkey(5), new_rs(6), sig3(7), sig2(8), sig1(9)
/// ```
///
/// (sigscript push/emission order, first==deepest: `sig1`, `sig2`, `sig3`,
/// `new_rs`, `new_owner_pubkey`, `op_type_selector`, `redeem_script` -- see
/// `super::sigscript::build_stablecoin_seize_sigscript`.)
///
/// # Effect (task spec, §4/§7)
///
/// Successor is the SAME covenant with `owner_pubkey` REPLACED by the
/// attested `new_owner_pubkey`; `role_registry_root`/`epoch`/`identifier_type`
/// unchanged -- mirrors [`build_freeze_branch`]'s "pin everything except the
/// one field that's meant to change" discipline. This coin's own CURRENT
/// `owner_pubkey` is therefore irrelevant to this branch (read, then dropped,
/// unused) -- SEIZE force-moves regardless of who currently holds the coin.
///
/// # `frozen_flag` on seize -- flagged for human review
///
/// `STABLECOIN_ROBUST_DESIGN.md`'s SEIZE per-branch detail (§4) is SILENT on
/// `frozen_flag` continuity. This implementation PRESERVES the input's
/// current `frozen_flag` unchanged into the successor (the same "pin unless
/// told otherwise" discipline used for `identifier_type`/`role_registry_root`/
/// `epoch` above). **This is a judgment call, not a spec requirement, and is
/// flagged for human review**: a seizure used for rescue (§7 -- lost-key
/// recovery) arguably wants the recovered coin UNFROZEN regardless of its
/// pre-seizure state, since the whole point of a rescue is to hand a working
/// coin back to a legitimate owner. Preserving is the more conservative
/// (fail-closed, no implicit unfreeze-on-seize) choice, but unconditionally
/// clearing `frozen_flag` on every SEIZE is an equally defensible
/// alternative reading -- this should be a deliberate human decision, not an
/// implementation default silently picked here.
///
/// # Value continuity (security fix, §4 cross-branch invariant, §11-v)
///
/// No owner `SIGHASH_ALL` signature exists on this path (and, per the doc
/// section above, native tx-sighash `OpCheckMultiSig` isn't used here
/// either), so nothing else pins the successor's native value;
/// [`dr_value_continuity_check`] is spliced in exactly as it was for
/// [`build_freeze_branch`].
fn build_seize_branch(seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(400);

    // Stack: epoch(0), frozen_flag(1), root(2), identifier_type(3),
    // owner_pubkey(4), new_owner_pubkey(5), new_rs(6), sig3(7), sig2(8),
    // sig1(9).
    e_pick(&mut b, 0); // copy of epoch (needed again for the preimage below)

    // Stack: epoch_copy(0), epoch(1), frozen_flag(2), root(3),
    // identifier_type(4), owner_pubkey(5), new_owner_pubkey(6), new_rs(7),
    // sig3(8), sig2(9), sig1(10).
    b.push(TXINPUTINDEX); // fresh -- this input's own index, reused as the
                           // output index (1:1 successor-binding convention).
    // Stack: input_idx(0), epoch_copy(1), epoch(2), frozen_flag(3), root(4),
    // identifier_type(5), owner_pubkey(6), new_owner_pubkey(7), new_rs(8),
    // sig3(9), sig2(10), sig1(11).
    b.extend_from_slice(&dr_output_spk_check(8, 1)); // Blake2b(new_rs) == P2SH(real successor SPK)
    b.push(DROP); // drop input_idx

    // ---- Template authentication (CRITICAL fix, audit 2026-07-20 §E). ----
    // `dr_output_spk_check` above only proves the spender's `new_rs` is the
    // script the successor output pays to. It says NOTHING about what that
    // script CONTAINS. Every role pubkey lives in the body, after the mutable
    // state header, so without the check below a spender can hand over a
    // successor that keeps the state fields this branch compares while baking
    // an entirely different role set -- moving the coin into a covenant the
    // real issuer has no keys for. FREEZE takes no owner signature at all, so
    // there it was a single-key total takeover; TRANSFER reopened the exact
    // governance exit the MIGRATE cold-quorum gate closed, at the lower price
    // of a hot OPS key.
    //
    // `self_rs` is this coin's OWN redeem script, supplied by the sigscript as
    // its deepest item (the same bytes it already pushes last for the P2SH
    // wrapper, so no caller-visible field was added) and proven genuine here
    // against this input's own SPK. Everything from `STATE_HEADER_LEN` onward
    // must then match byte for byte -- the same template authentication
    // kcc-0001 5.8.5 requires and the sibling KCC20 transfer covenant already
    // performed. MIGRATE is deliberately exempt: its successor is an arbitrary
    // new template by design, which is why that branch requires the cold quorum.
    // Stack: epoch_copy(0), epoch(1), frozen_flag(2), root(3),
    // identifier_type(4), owner_pubkey(5), new_owner_pubkey(6), new_rs(7),
    // sig3(8), sig2(9), sig1(10), self_rs(11).
    b.extend_from_slice(&dr_input_spk_check(11)); // P2SH(self_rs) == this input's own SPK
    b.extend_from_slice(&dr_suffix_check(11, 8, STATE_HEADER_LEN as u16)); // new_rs raw depth 7 -> 8
    e_roll(&mut b, 11); // self_rs -> top
    b.push(DROP);

    // Stack: epoch_copy(0), epoch(1), frozen_flag(2), root(3),
    // identifier_type(4), owner_pubkey(5), new_owner_pubkey(6), new_rs(7),
    // sig3(8), sig2(9), sig1(10).

    // ---- Value continuity (security fix, cross-branch invariant, see this
    // fn's doc). ----
    b.extend_from_slice(&dr_value_continuity_check());

    // ---- Successor checks: owner_pubkey REPLACED by the attested
    // new_owner_pubkey; identifier_type/role_registry_root/epoch/frozen_flag
    // unchanged (task spec's Effect + the frozen_flag decision, see fn doc). ----

    // This coin's own CURRENT owner_pubkey is irrelevant to SEIZE (forced
    // move regardless of current holder) -- drop it, unused.
    e_roll(&mut b, 5); // owner_pubkey -> top
    b.push(DROP);

    // Stack: epoch_copy(0), epoch(1), frozen_flag(2), root(3),
    // identifier_type(4), new_owner_pubkey(5), new_rs(6), sig3(7), sig2(8),
    // sig1(9).

    // successor.owner_pubkey == new_owner_pubkey (the ATTESTED value --
    // picked, not rolled, since new_owner_pubkey is needed again for the
    // preimage tail below).
    b.extend_from_slice(&dr_field_extract(6, OWNER_PUBKEY_PAYLOAD_OFFSET as u16, (OWNER_PUBKEY_PAYLOAD_OFFSET + 32) as u16));
    // Stack: succ_owner(0), epoch_copy(1), epoch(2), frozen_flag(3), root(4),
    // identifier_type(5), new_owner_pubkey(6), new_rs(7), sig3(8), sig2(9),
    // sig1(10).
    e_pick(&mut b, 6); // copy of new_owner_pubkey -> top
    // Stack: new_owner_pubkey_copy(0), succ_owner(1), epoch_copy(2), epoch(3),
    // frozen_flag(4), root(5), identifier_type(6), new_owner_pubkey(7),
    // new_rs(8), sig3(9), sig2(10), sig1(11).
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch_copy(0), epoch(1), frozen_flag(2), root(3),
    // identifier_type(4), new_owner_pubkey(5), new_rs(6), sig3(7), sig2(8),
    // sig1(9).

    // identifier_type unchanged.
    b.extend_from_slice(&dr_field_extract(6, IDENTIFIER_TYPE_PAYLOAD_OFFSET as u16, (IDENTIFIER_TYPE_PAYLOAD_OFFSET + 1) as u16));
    // Stack: succ_idtype(0), epoch_copy(1), epoch(2), frozen_flag(3), root(4),
    // identifier_type(5), new_owner_pubkey(6), new_rs(7), sig3(8), sig2(9),
    // sig1(10).
    e_roll(&mut b, 5); // this coin's own identifier_type -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch_copy(0), epoch(1), frozen_flag(2), root(3),
    // new_owner_pubkey(4), new_rs(5), sig3(6), sig2(7), sig1(8).

    // role_registry_root unchanged.
    b.extend_from_slice(&dr_field_extract(5, ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET as u16, (ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET + 32) as u16));
    // Stack: succ_root(0), epoch_copy(1), epoch(2), frozen_flag(3), root(4),
    // new_owner_pubkey(5), new_rs(6), sig3(7), sig2(8), sig1(9).
    e_roll(&mut b, 4); // this coin's own role_registry_root -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch_copy(0), epoch(1), frozen_flag(2), new_owner_pubkey(3),
    // new_rs(4), sig3(5), sig2(6), sig1(7).

    // epoch unchanged.
    b.extend_from_slice(&dr_field_extract(4, EPOCH_PAYLOAD_OFFSET as u16, (EPOCH_PAYLOAD_OFFSET + 4) as u16));
    // Stack: succ_epoch(0), epoch_copy(1), epoch(2), frozen_flag(3),
    // new_owner_pubkey(4), new_rs(5), sig3(6), sig2(7), sig1(8).
    e_roll(&mut b, 1); // epoch_copy -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch(0), frozen_flag(1), new_owner_pubkey(2), new_rs(3),
    // sig3(4), sig2(5), sig1(6).

    // frozen_flag preserved (flagged for human review, see fn doc).
    b.extend_from_slice(&dr_field_extract(3, FROZEN_FLAG_PAYLOAD_OFFSET as u16, (FROZEN_FLAG_PAYLOAD_OFFSET + 1) as u16));
    // Stack: succ_frozen(0), epoch(1), frozen_flag(2), new_owner_pubkey(3),
    // new_rs(4), sig3(5), sig2(6), sig1(7).
    e_roll(&mut b, 2); // this coin's own frozen_flag -> top
    b.push(EQUAL);
    b.push(VERIFY);

    // Stack: epoch(0), new_owner_pubkey(1), new_rs(2), sig3(3), sig2(4),
    // sig1(5). new_rs no longer needed.
    e_roll(&mut b, 2);
    b.push(DROP);

    // Stack: epoch(0), new_owner_pubkey(1), sig3(2), sig2(3), sig1(4).

    // ---- Attestation pre-image (153B, §4/§5): 121B base +
    // new_owner_pubkey(32) tail. ----
    b.push(DATA8);
    b.extend_from_slice(&DOMAIN_TAG);
    // Stack: domain_tag(0), epoch(1), new_owner_pubkey(2), sig3(3), sig2(4),
    // sig1(5).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(CAT); // acc = domain_tag || covenant_id
    // Stack: acc(0), epoch(1), new_owner_pubkey(2), sig3(3), sig2(4), sig1(5).
    b.push(DATA1);
    b.push(op_type::SEIZE);
    b.push(CAT); // acc || op_type
    // Stack: acc(0), epoch(1), new_owner_pubkey(2), sig3(3), sig2(4), sig1(5).
    e_roll(&mut b, 1); // epoch -> top
    b.push(CAT); // acc || epoch
    // Stack: acc(0), new_owner_pubkey(1), sig3(2), sig2(3), sig1(4).
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT); // acc || outpoint_txid
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT); // acc || outpoint_index(4B LE)
    b.push(TXINPUTINDEX);
    b.push(TXOUTPUTSPK);
    b.push(BLAKE3);
    b.push(CAT); // acc || successor_spk_hash
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(OP8);
    b.push(NUM2BIN);
    b.push(CAT); // acc || amount(8B LE) == full 121B base preimage
    // Stack: acc(0), new_owner_pubkey(1), sig3(2), sig2(3), sig1(4).
    e_roll(&mut b, 1); // new_owner_pubkey -> top
    b.push(CAT); // acc || new_owner_pubkey == full 153B SEIZE preimage

    // msg_hash = Blake3(preimage). Stack: msg_hash(0), sig3(1), sig2(2),
    // sig1(3).
    b.push(BLAKE3);

    emit_2of3_threshold(&mut b, seize_pubkeys);

    b.push(OP1);
    b
}

/// Emit the 2-of-3 threshold check over three baked SEIZE-role pubkeys.
///
/// Entry stack is exactly `msg_hash(0), sig3(1), sig2(2), sig1(3)`; on success
/// all four are consumed and nothing is left behind (fail-closed via the
/// trailing `OpVerify`). Shared verbatim by [`build_seize_branch`] and
/// [`build_migrate_branch`] so the two quorum gates cannot drift apart.
///
/// This is three `OpCheckSigFromStack` calls against fixed positional slots
/// plus a summed threshold rather than a native `OpCheckMultiSig` (see
/// [`build_seize_branch`]'s doc for why): `sig3<->pubkeys[2]`,
/// `sig2<->pubkeys[1]`, `sig1<->pubkeys[0]`. Because every slot verifies the
/// SAME `msg_hash`, a duplicated baked pubkey would let one signature satisfy
/// two slots and collapse the threshold -- which is why
/// [`build_stablecoin_body`] asserts the baked role keys are pairwise
/// distinct, and [`build_stablecoin_redeem_script`] additionally asserts the
/// owner key differs from all of them (MIGRATE consumes an owner signature
/// AND this quorum).
fn emit_2of3_threshold(b: &mut Vec<u8>, pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3]) {
    use op::*;

    // -- check sig3 vs pubkeys[2] --
    // Stack: msg_hash(0), sig3(1), sig2(2), sig1(3).
    e_roll(b, 1); // sig3 -> top
    // Stack: sig3(0), msg_hash(1), sig2(2), sig1(3).
    e_pick(b, 1); // copy of msg_hash -> top
    // Stack: msg_hash_copy(0), sig3(1), msg_hash(2), sig2(3), sig1(4).
    b.push(DATA32);
    b.extend_from_slice(&pubkeys[2]);
    // Stack: pubkey3(0), msg_hash_copy(1), sig3(2), msg_hash(3), sig2(4),
    // sig1(5).
    b.push(CHECKSIGFROMSTACK);
    // Stack: bool3(0), msg_hash(1), sig2(2), sig1(3).

    // -- check sig2 vs pubkeys[1] --
    e_roll(b, 2); // sig2 -> top
    // Stack: sig2(0), bool3(1), msg_hash(2), sig1(3).
    e_pick(b, 2); // copy of msg_hash -> top
    // Stack: msg_hash_copy(0), sig2(1), bool3(2), msg_hash(3), sig1(4).
    b.push(DATA32);
    b.extend_from_slice(&pubkeys[1]);
    // Stack: pubkey2(0), msg_hash_copy(1), sig2(2), bool3(3), msg_hash(4),
    // sig1(5).
    b.push(CHECKSIGFROMSTACK);
    // Stack: bool2(0), bool3(1), msg_hash(2), sig1(3).

    // -- check sig1 vs pubkeys[0] (consumes the ORIGINAL msg_hash; no copy
    // needed since this is the last use) --
    e_roll(b, 3); // sig1 -> top
    // Stack: sig1(0), bool2(1), bool3(2), msg_hash(3).
    e_roll(b, 3); // msg_hash -> top (directly above sig1)
    // Stack: msg_hash(0), sig1(1), bool2(2), bool3(3).
    b.push(DATA32);
    b.extend_from_slice(&pubkeys[0]);
    // Stack: pubkey1(0), msg_hash(1), sig1(2), bool2(3), bool3(4).
    b.push(CHECKSIGFROMSTACK);
    // Stack: bool1(0), bool2(1), bool3(2).

    // sum(bool1, bool2, bool3) >= 2 -- fixed-position 2-of-3 threshold.
    b.push(ADD); // bool1 + bool2 -> Stack: sum12(0), bool3(1).
    b.push(ADD); // sum12 + bool3 -> Stack: total(0).
    b.push(OP2);
    b.push(GREATERTHANOREQUAL);
    b.push(VERIFY);
}

/// Emit the BURN (`0x03`) branch bytecode (`STABLECOIN_ROBUST_DESIGN.md`
/// §4/§5/§8, Phase II branch 4). Two-of-two authorization, the SAME SHAPE as
/// TRANSFER (owner `OpCheckSigVerify`, SIGHASH_ALL, PLUS an
/// `OpCheckSigFromStack` attestation) -- but the attesting role here is MINT
/// (the mint-authority's supply key, §2/§9: "authorizes BURN (issuer side) in
/// this covenant"), not OPS, and the attested pre-image is the 121-byte BASE
/// pre-image with NO op-specific tail (§5: "sink pinned structurally, not via
/// preimage").
///
/// # No `new_rs` sigscript field -- but the sink IS authenticated via
/// `dr_output_spk_check`, like every other branch's successor
///
/// Unlike TRANSFER/FREEZE/SEIZE, BURN's successor is NOT an arbitrary
/// candidate redeem script the SPENDER proposes via sigscript data -- it is
/// the FIXED canonical constant [`BURN_SINK_SCRIPT`], known at
/// redeem-script-build time. So there is no `new_rs` sigscript field (see
/// `super::sigscript::build_stablecoin_burn_sigscript`).
///
/// **Live-discovered bug this fixes (2026-07-19/20 testnet-10 run):** BURN
/// used to authenticate the sink by comparing the successor output's raw SPK
/// bytes (`OpTxOutputSpk`) directly against a HOST-COMPUTED literal
/// (`burn_sink_spk_bytes()`, baked in via a plain `OpEqual`) -- `OpTxInputIndex
/// OpTxOutputSpk <canonical sink SPK bytes literal> OpEqual OpVerify`. That
/// raw-literal compare had NEVER actually run on a real node before: the old
/// bare-`OpReturn` sink was rejected by mempool standardness *before* script
/// verification ever got a chance to exercise it (see [`BURN_SINK_SCRIPT`]'s
/// doc), so once the P2SH-wrap standardness fix let the transaction reach
/// script verification, this was the FIRST live exercise of the raw-literal
/// mechanism -- and it failed ("script ran, but verification failed"),
/// unlike TRANSFER/FREEZE/SEIZE's successor-authentication, which uses
/// [`dr_output_spk_check`] (an ON-CHAIN `OpBlake2b` reconstruction of
/// `P2SH(candidate)`, compared via `OpEqual` against the REAL successor's
/// `OpTxOutputSpk` result) and HAS been live-proven on testnet-10.
///
/// The fix: BURN now authenticates its (fixed, non-spender-suppliable) sink
/// through the exact same [`dr_output_spk_check`] mechanism, treating
/// [`BURN_SINK_SCRIPT`] as the "candidate redeem script" -- except, since it
/// is a compile-time constant rather than spender-supplied sigscript data,
/// it is pushed as a literal directly in the BODY bytecode (not read from
/// the sigscript) immediately before the check. This makes BURN inherit
/// TRANSFER's live-correct on-chain SPK reconstruction/serialization
/// handling instead of relying on a locally-computed absolute-byte literal
/// that was never exercised against a real node. [`burn_sink_spk_bytes`]/
/// [`burn_sink_spk`] remain as the OFF-CHAIN utility for constructing the
/// actual sink output (the CLI harness still builds output\[0\] as
/// `build_p2sh(&BURN_SINK_SCRIPT)`), but the ON-CHAIN check no longer bakes
/// in or compares against their output directly.
///
/// Because the destination is fixed and carries no coin state at all, neither
/// `role_registry_root` nor `identifier_type` is read for any
/// successor-continuity check (there is no successor covenant state to carry
/// them into) -- each is rolled up and dropped, unused, exactly as
/// `identifier_type` already is in [`build_transfer_branch`]. `frozen_flag`,
/// by contrast, IS gated (see the "frozen_flag -- gated" section below) --
/// it is the one field BURN reads for an owner-immobility check, not a
/// successor-continuity comparison.
///
/// # `frozen_flag` -- gated (resolved: freeze means total owner immobility)
///
/// `STABLECOIN_ROBUST_DESIGN.md`'s §4 BURN pseudocode and per-branch detail
/// are both silent on `frozen_flag`, but the resolved cross-branch invariant
/// is: a FROZEN coin is fully immobile to its owner. BURN is owner-initiated
/// (owner `OpCheckSigVerify` + MINT attestation), so it MUST respect the same
/// `frozen_flag == 0` gate [`build_transfer_branch`] enforces -- mirrored here
/// verbatim (same opcodes: roll `frozen_flag` to top, compare to the explicit
/// 1-byte literal `frozen_flag::CLEAR`, `OpVerify`). A FROZEN coin can
/// therefore no longer be burned by its owner; only the issuer's SEIZE branch
/// (which has no owner signature and intentionally no frozen gate -- it force-
/// moves the coin regardless of its frozen state, e.g. for sanctions
/// enforcement or lost-key rescue) can act on a frozen coin. Unfreezing
/// (via FREEZE, `frozen_flag` 1->0) is the only other way to make a frozen
/// coin burnable again.
///
/// # Value continuity -- intentionally NOT applied (task spec, §4)
///
/// FREEZE/SEIZE call [`dr_value_continuity_check`] because they have NO owner
/// signature at all, so nothing else pins the successor's native value. BURN
/// DOES have an owner `SIGHASH_ALL` signature (§4's cross-branch invariant
/// table lists BURN under the owner-signed column, alongside TRANSFER and
/// MIGRATE), so it gets value-PINNING "for free" the same mechanical way
/// TRANSFER does -- but unlike TRANSFER, the pinned value is INTENTIONALLY
/// not preserved into a covenant successor: it moves to the unspendable sink,
/// i.e. is destroyed. Calling `dr_value_continuity_check` here would be
/// actively WRONG (it asserts input amount == successor OUTPUT amount, which
/// would forbid ever actually burning anything into the sink) -- the owner's
/// own SIGHASH_ALL signature is what makes "burn exactly this much value"
/// an intentional, attributable choice, not a hole: nobody but the owner can
/// choose to fund the sink output from this coin's value.
///
/// Entry (top-to-bottom), once the dispatch skeleton's `op_type` compare
/// delivers control here:
///
/// ```text
/// epoch(0), frozen_flag(1), role_registry_root(2), identifier_type(3),
/// owner_pubkey(4), owner_sig(5), issuer_sig(6)
/// ```
///
/// (sigscript push/emission order, first==deepest: `issuer_sig`, `owner_sig`,
/// `op_type_selector`, `redeem_script` -- see
/// `super::sigscript::build_stablecoin_burn_sigscript`; no `new_rs`.)
fn build_burn_branch(mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(160);

    // ---- Owner authorization (identical mechanics to TRANSFER's stage 1). ----
    e_roll(&mut b, 5); // owner_sig -> top
    e_roll(&mut b, 5); // owner_pubkey -> top (owner_sig now at depth 1)
    b.push(CHECKSIGVERIFY); // pubkey(top) x sig(next), SIGHASH_ALL

    // Stack: epoch(0), frozen_flag(1), role_registry_root(2),
    // identifier_type(3), issuer_sig(4).
    e_roll(&mut b, 3); // identifier_type -> top
    b.push(DROP); // unused -- no successor covenant state to carry it into

    // Stack: epoch(0), frozen_flag(1), role_registry_root(2), issuer_sig(3).
    e_roll(&mut b, 1); // frozen_flag -> top
    b.push(DATA1);
    b.push(frozen_flag::CLEAR); // literal explicit-push [0x00] (NOT OpN 0 / empty array)
    b.push(EQUAL);
    b.push(VERIFY); // frozen_flag == 0, fail-closed -- a frozen coin is fully
                    // owner-immobile (see fn doc "frozen_flag" section);
                    // mirrors build_transfer_branch's gate exactly (same
                    // opcodes, same net stack effect as the DROP it replaces).

    // Stack: epoch(0), role_registry_root(1), issuer_sig(2).
    e_roll(&mut b, 1); // role_registry_root -> top
    b.push(DROP); // unused -- no successor state to compare it against

    // Stack: epoch(0), issuer_sig(1).
    // ---- Attestation pre-image (121B base, §4/§5, empty tail): identical
    // mechanics to TRANSFER's, just op_type::BURN and the MINT-role pubkey. ----
    b.push(DATA8);
    b.extend_from_slice(&DOMAIN_TAG);
    // Stack: domain_tag(0), epoch(1), issuer_sig(2).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(CAT); // acc = domain_tag || covenant_id
    // Stack: acc(0), epoch(1), issuer_sig(2).
    b.push(DATA1);
    b.push(op_type::BURN);
    b.push(CAT); // acc || op_type
    // Stack: acc(0), epoch(1), issuer_sig(2).
    e_roll(&mut b, 1); // epoch -> top
    b.push(CAT); // acc || epoch
    // Stack: acc(0), issuer_sig(1).
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT); // acc || outpoint_txid
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT); // acc || outpoint_index(4B LE)
    b.push(TXINPUTINDEX);
    b.push(TXOUTPUTSPK);
    b.push(BLAKE3);
    b.push(CAT); // acc || successor_spk_hash
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(OP8);
    b.push(NUM2BIN);
    b.push(CAT); // acc || amount(8B LE) == full 121B preimage

    // msg_hash = Blake3(preimage). Stack: msg_hash(0), issuer_sig(1).
    b.push(BLAKE3);

    // Push MINT pubkey; verify the attestation.
    b.push(DATA32);
    b.extend_from_slice(mint_pubkey);
    b.push(CHECKSIGFROMSTACK);
    b.push(VERIFY);

    // ---- Sink pin (§4/§8): successor SPK must equal the canonical
    // unspendable burn sink, exactly (not attacker-suppliable). Stack is
    // empty here (CHECKSIGFROMSTACK+VERIFY above consumed everything).
    //
    // Live-discovered bug fix (see this fn's doc): this used to be a
    // host-computed raw-literal `OpEqual` against `OpTxOutputSpk`'s output --
    // never actually exercised on a real node before the P2SH-wrap
    // standardness fix, and it failed the first time it was ("script ran,
    // but verification failed"). Now it uses the SAME live-proven mechanism
    // TRANSFER/FREEZE/SEIZE use for their `new_rs` ([`dr_output_spk_check`]:
    // an ON-CHAIN `OpBlake2b` reconstruction of `P2SH(candidate)`, `OpEqual`
    // against the REAL successor's `OpTxOutputSpk` result) -- BURN's
    // "candidate" is the fixed constant `BURN_SINK_SCRIPT`, pushed as a
    // literal directly here (not read from the sigscript, since it is not
    // spender-suppliable). ----
    b.push(DATA1);
    b.push(BURN_SINK_SCRIPT[0]); // literal [0x6a] -- stand-in "candidate redeem script"
    // Stack: sink_script(0).
    b.push(TXINPUTINDEX); // fresh -- reused as the output index (1:1 successor-binding convention)
    // Stack: input_idx(0), sink_script(1).
    b.extend_from_slice(&dr_output_spk_check(1, 1)); // Blake2b(sink_script) == P2SH(real successor SPK)
    b.push(DROP); // drop input_idx (dr_output_spk_check's own depth-adjustment discipline)
    b.push(DROP); // drop sink_script -- no longer needed (no fields to extract from it)

    b.push(OP1);
    b
}

/// Emit the MIGRATE (`0x06`) branch bytecode (`STABLECOIN_ROBUST_DESIGN.md`
/// §4/§5, Phase II final branch). Two-of-two authorization, the SAME SHAPE as
/// TRANSFER's/BURN's (owner `OpCheckSigVerify`, SIGHASH_ALL, PLUS an
/// `OpCheckSigFromStack` attestation) -- but see the authorizer note below.
///
/// # Authorizer: cold 2-of-3 SEIZE quorum (Decision 2026-07-20)
///
/// §4's branch table specifies MIGRATE authorization as "OWNER + (ROTATE or
/// OPS)". Under Decision 2026-07-19 (option B, baked keys), `ROTATE` (`0x05`)
/// is deferred to post-Live (it only becomes meaningful once role keys are
/// verified against `role_registry_root` rather than baked -- see this
/// module's top doc and `STABLECOIN_ROBUST_DESIGN.md`'s "Deferred to
/// post-Live robustness upgrade" section). The initial Live shipped OPS (the
/// SAME hot key TRANSFER uses) as the stand-in authorizer.
///
/// The post-Live audit (`STABLECOIN_AUDIT_2026-07-20.md` §B2) rejected that
/// as a **governance-exit hole**: MIGRATE moves the coin to an ARBITRARY new
/// template (see the next section), so owner + a compromised HOT ops key
/// could walk an unfrozen coin out of FREEZE/SEIZE/BURN reach entirely --
/// contradicting §11's "a stolen OPS key cannot redirect funds". **Decision
/// 2026-07-20: gate MIGRATE behind the same cold 2-of-3 quorum SEIZE uses**
/// (the SAME three baked `seize_pubkeys` -- no new key material, and the
/// quorum bytecode is literally the shared [`emit_2of3_threshold`] segment,
/// so the two gates cannot drift). Escaping governance now costs the owner
/// key AND two of the three cold keys -- i.e. exactly what it costs to seize
/// the coin outright, which is the intended equivalence.
///
/// `frozen_flag == 0` is retained on top of the quorum: it is the cheap gate
/// that stops a routine owner-initiated migration of a sanctioned coin
/// without needing the cold keys to be involved at all.
///
/// **Post-Live**, once ROTATE/root-verification land, MIGRATE authorization
/// MAY move to a dedicated ROTATE quorum -- that would be a body-bytecode
/// change at that time, not implied by anything here.
///
/// # No `new_rs` -- only the successor's SPK HASH is needed
///
/// Unlike TRANSFER/FREEZE/SEIZE, MIGRATE's successor is NOT the same covenant
/// template with specific fields (`role_registry_root`/`epoch`/`owner_pubkey`)
/// that this body reads and carries forward -- it is effect is "coin moves to
/// a NEW covenant template" (§4): a different redeem script ENTIRELY, whose
/// internal layout this covenant has no business understanding (it does not
/// even need to be another stablecoin covenant at all -- authorizing that is
/// the OPS-signer's off-chain responsibility, not this body's). So there is
/// no "authenticate the candidate redeem script, then extract fields from it"
/// dance (`dr_output_spk_check` + `dr_field_extract`, as TRANSFER/FREEZE/SEIZE
/// use) -- the body only needs the successor's SPK **hash**, which is exactly
/// what `OpTxOutputSpk`/`OpBlake3` produce directly, with no candidate
/// redeem-script plaintext required at all. `new_template_hash` is therefore
/// a plaintext 32-byte sigscript field (like FREEZE's `new_frozen_flag` /
/// SEIZE's `new_owner_pubkey`): the OPS role signs it (so the issuer approves
/// the SPECIFIC migration target, preventing migration to an
/// attacker-substituted template), and the body separately re-derives
/// `Blake3(OpTxOutputSpk)` for the REAL successor and compares the two with
/// an explicit `OpEqual OpVerify` -- so a captured, honestly-signed
/// attestation for one target cannot be replayed against a spend that
/// actually pays to a different one (`migrate_successor_template_mismatch_rejected`,
/// `core/tests/stablecoin_contracts.rs`).
///
/// # `role_registry_root`/`identifier_type` -- read then dropped, unused
///
/// Because the successor is an arbitrary new template with no promised field
/// layout, there is nothing on this coin's own state to meaningfully compare
/// against a successor (unlike FREEZE/SEIZE, which pin these fields
/// unchanged into a same-template successor). Both fields are rolled up and
/// dropped, unused -- §4's MIGRATE pseudocode shows no continuity check for
/// either.
///
/// # `frozen_flag` -- gated (resolved: freeze means total owner immobility)
///
/// Unlike `role_registry_root`/`identifier_type` above, `frozen_flag` is NOT
/// merely dropped: MIGRATE is owner-initiated (owner `OpCheckSigVerify` + OPS
/// attestation), so it MUST respect the same total-immobility invariant
/// [`build_transfer_branch`] enforces -- otherwise a frozen (sanctioned) coin
/// could escape governance entirely by migrating to an arbitrary,
/// non-stablecoin template. This branch mirrors TRANSFER's gate verbatim
/// (same opcodes: roll `frozen_flag` to top, compare to the explicit 1-byte
/// literal `frozen_flag::CLEAR`, `OpVerify`) -- a FROZEN coin can therefore no
/// longer be migrated by its owner, mirroring BURN's same resolved
/// `frozen_flag == 0` gate (`build_burn_branch`'s doc). Only the issuer's
/// SEIZE branch (no owner signature, intentionally no frozen gate) can act on
/// a frozen coin; unfreezing (via FREEZE) is the only other way to make a
/// frozen coin migratable again.
///
/// # Value continuity -- intentionally NOT applied (task spec, §4)
///
/// MIGRATE has an owner `SIGHASH_ALL` signature (§4's cross-branch invariant
/// table lists MIGRATE alongside TRANSFER and BURN under the owner-signed
/// column), so successor-value pinning comes "for free" the same way it does
/// for TRANSFER -- `dr_value_continuity_check` (used by FREEZE/SEIZE, which
/// have NO owner signature at all) is deliberately NOT called here; doing so
/// would be redundant at best (mirrors `build_burn_branch`'s identical
/// rationale, adapted: here the value is expected to actually carry forward
/// into the new template, not be destroyed, but the owner's own SIGHASH_ALL
/// signature is what makes that an intentional, attributable choice, not a
/// hole -- nobody but the owner can choose the new output's amount).
///
/// Entry (top-to-bottom), once the dispatch skeleton's `op_type` compare
/// delivers control here:
///
/// ```text
/// epoch(0), frozen_flag(1), role_registry_root(2), identifier_type(3),
/// owner_pubkey(4), owner_sig(5), new_template_hash(6), sig3(7), sig2(8),
/// sig1(9)
/// ```
///
/// (sigscript push/emission order, first==deepest: `sig1`, `sig2`, `sig3`,
/// `new_template_hash`, `owner_sig`, `op_type_selector`, `redeem_script` --
/// see `super::sigscript::build_stablecoin_migrate_sigscript`. The three
/// quorum sigs sit BELOW every field this branch rolls, so all roll/pick
/// depths are unchanged from the single-authorizer version.)
fn build_migrate_branch(seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(300);

    // ---- Owner authorization (identical mechanics to TRANSFER's/BURN's
    // stage 1). ----
    e_roll(&mut b, 5); // owner_sig -> top
    e_roll(&mut b, 5); // owner_pubkey -> top (owner_sig now at depth 1)
    b.push(CHECKSIGVERIFY); // pubkey(top) x sig(next), SIGHASH_ALL

    // Stack: epoch(0), frozen_flag(1), role_registry_root(2),
    // identifier_type(3), new_template_hash(4), issuer_sig(5).
    e_roll(&mut b, 3); // identifier_type -> top
    b.push(DROP); // unused -- see fn doc: MIGRATE's successor is a wholly
                  // different template with no promised field layout.

    // Stack: epoch(0), frozen_flag(1), role_registry_root(2),
    // new_template_hash(3), sig3(4), sig2(5), sig1(6).
    e_roll(&mut b, 1); // frozen_flag -> top
    b.push(DATA1);
    b.push(frozen_flag::CLEAR); // literal explicit-push [0x00] (NOT OpN 0 / empty array)
    b.push(EQUAL);
    b.push(VERIFY); // frozen_flag == 0, fail-closed -- a frozen coin is fully
                    // owner-immobile (see fn doc "frozen_flag" section);
                    // mirrors build_transfer_branch's gate exactly (same
                    // opcodes, same net stack effect as the DROP it replaces).

    // Stack: epoch(0), role_registry_root(1), new_template_hash(2), sig3(3), sig2(4), sig1(5).
    e_roll(&mut b, 1); // role_registry_root -> top
    b.push(DROP); // unused -- no shared successor state layout to carry it into

    // Stack: epoch(0), new_template_hash(1), sig3(2), sig2(3), sig1(4).

    // ---- Successor-template authentication (fn doc): the successor
    // output's SPK must Blake3-hash to the attested new_template_hash --
    // proves the OPS-signed migration target is EXACTLY the output actually
    // being paid to, not a substituted one. ----
    b.push(TXINPUTINDEX);
    b.push(TXOUTPUTSPK);
    b.push(BLAKE3); // real successor SPK hash
    // Stack: real_hash(0), epoch(1), new_template_hash(2), sig3(3), sig2(4), sig1(5).
    e_pick(&mut b, 2); // copy of new_template_hash -> top (needed again for the preimage tail below)
    // Stack: new_template_hash_copy(0), real_hash(1), epoch(2),
    // new_template_hash(3), sig3(4), sig2(5), sig1(6).
    b.push(EQUAL);
    b.push(VERIFY); // real successor SPK hash == attested new_template_hash

    // Stack: epoch(0), new_template_hash(1), sig3(2), sig2(3), sig1(4).

    // ---- Attestation pre-image (153B, §4/§5): 121B base + new_template_hash(32) tail. ----
    b.push(DATA8);
    b.extend_from_slice(&DOMAIN_TAG);
    // Stack: domain_tag(0), epoch(1), new_template_hash(2), sig3(3), sig2(4), sig1(5).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    b.push(CAT); // acc = domain_tag || covenant_id
    // Stack: acc(0), epoch(1), new_template_hash(2), sig3(3), sig2(4), sig1(5).
    b.push(DATA1);
    b.push(op_type::MIGRATE);
    b.push(CAT); // acc || op_type
    // Stack: acc(0), epoch(1), new_template_hash(2), sig3(3), sig2(4), sig1(5).
    e_roll(&mut b, 1); // epoch -> top
    b.push(CAT); // acc || epoch
    // Stack: acc(0), new_template_hash(1), sig3(2), sig2(3), sig1(4).
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT); // acc || outpoint_txid
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT); // acc || outpoint_index(4B LE)
    b.push(TXINPUTINDEX);
    b.push(TXOUTPUTSPK);
    b.push(BLAKE3);
    b.push(CAT); // acc || successor_spk_hash
    b.push(TXINPUTINDEX);
    b.push(TXINPUTAMOUNT);
    b.push(OP8);
    b.push(NUM2BIN);
    b.push(CAT); // acc || amount(8B LE) == full 121B base preimage
    // Stack: acc(0), new_template_hash(1), sig3(2), sig2(3), sig1(4).
    e_roll(&mut b, 1); // new_template_hash -> top
    b.push(CAT); // acc || new_template_hash == full 153B MIGRATE preimage

    // msg_hash = Blake3(preimage). Stack: msg_hash(0), sig3(1), sig2(2),
    // sig1(3) -- byte-identical to SEIZE's stack shape at this point, which
    // is why the quorum segment below is shared verbatim.
    b.push(BLAKE3);

    // ---- Cold 2-of-3 SEIZE-quorum attestation (see fn doc "Authorizer"). ----
    emit_2of3_threshold(&mut b, seize_pubkeys);

    b.push(OP1);
    b
}

/// Emit the stablecoin covenant body: state header's fields are already on
/// the stack (pushed when the redeem script's own leading bytes execute);
/// the body is the 6-way `op_type` dispatch. `tag_depth` is the stack depth
/// of the `op_type` selector once the state header has finished pushing its
/// five fields -- with the sigscript layout documented in the module doc
/// (`op_type_selector` as the LAST sigscript push before the redeem script),
/// that depth is always `5` (see [`OP_TYPE_TAG_DEPTH`]).
pub const OP_TYPE_TAG_DEPTH: u16 = 5;

pub fn build_stablecoin_body(
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
) -> Vec<u8> {
    // Role keys MUST be pairwise distinct: a duplicated SEIZE key collapses the
    // SEIZE (and MIGRATE) 2-of-3 threshold (one key satisfies two fixed
    // positional slots, sum>=2), and a shared ops/freeze/mint key erodes role
    // separation. The check lives HERE (not only in the
    // `build_stablecoin_redeem_script` wrapper) because this is the function
    // that actually emits the threshold bytecode and is itself `pub` -- a
    // caller must not be able to route around the assertion by composing the
    // state header manually.
    {
        let role_keys: [&[u8; X_ONLY_PUBKEY_LEN]; 6] =
            [ops_pubkey, freeze_pubkey, &seize_pubkeys[0], &seize_pubkeys[1], &seize_pubkeys[2], mint_pubkey];
        for i in 0..role_keys.len() {
            for j in (i + 1)..role_keys.len() {
                assert!(role_keys[i] != role_keys[j], "stablecoin role pubkeys must be pairwise distinct (slot {i} == slot {j})");
            }
        }
    }
    let transfer = build_transfer_branch(ops_pubkey);
    let freeze = build_freeze_branch(freeze_pubkey);
    let seize = build_seize_branch(seize_pubkeys);
    let burn = build_burn_branch(mint_pubkey);
    let migrate = build_migrate_branch(seize_pubkeys); // cold 2-of-3 quorum, Decision 2026-07-20 -- see build_migrate_branch's doc
    build_op_type_dispatch(
        OP_TYPE_TAG_DEPTH,
        OpTypeBranches {
            transfer: &transfer,
            freeze: &freeze,
            seize: &seize,
            burn: &burn,
            rotate: UNIMPLEMENTED_BRANCH_STUB, // DEFERRED (post-Live): ROTATE, see this module's top doc
            migrate: &migrate,
        },
    )
}

/// Build the complete robust stablecoin redeem script (state header +
/// dispatch body). `owner_pubkey`/`role_registry_root`/`frozen_flag`/`epoch`
/// go into the mutable state header (§3); `ops_pubkey` is baked into the body
/// as the TRANSFER branch's `OpCheckSigFromStack` key (§2 OPS role);
/// `freeze_pubkey` is baked into the body as the FREEZE branch's
/// `OpCheckSigFromStack` key (§2 FREEZE role); `seize_pubkeys` are baked into
/// the body as the SEIZE branch's three 2-of-3 `OpCheckSigFromStack` keys (§2
/// SEIZE role) -- the same "bake in as a literal constant" convention as
/// `ops_pubkey`/`freeze_pubkey` (see `build_freeze_branch`'s doc, and
/// `build_seize_branch`'s doc for why SEIZE's multisig is built from three
/// `OpCheckSigFromStack` calls rather than native `OpCheckMultiSig`: role
/// pubkeys are not yet individually verified against `role_registry_root`
/// on-chain in this phase); `mint_pubkey` is baked into the body as the BURN
/// branch's `OpCheckSigFromStack` key (§2 MINT role -- "the mint-authority's
/// supply key ... authorizes BURN (issuer side) in this covenant"). `ops_pubkey`
/// is ALSO baked into the body as the MIGRATE branch's `OpCheckSigFromStack`
/// key (§4: MIGRATE authorization is "OWNER + (ROTATE or OPS)"; OPS stands in
/// since ROTATE is deferred to post-Live -- see `build_migrate_branch`'s doc).
#[allow(clippy::too_many_arguments)]
pub fn build_stablecoin_redeem_script(
    owner_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    identifier_type: u8,
    role_registry_root: &[u8; 32],
    frozen_flag_value: u8,
    epoch: u32,
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
) -> Vec<u8> {
    // The owner key must ALSO be distinct from every baked role key. Role-vs-role
    // distinctness is asserted one layer down, in `build_stablecoin_body` (so no
    // caller can route around it); the owner key never reaches that function, so
    // it is checked here. This matters because MIGRATE requires an owner
    // `OpCheckSigVerify` AND a 2-of-3 SEIZE quorum over the same message: if the
    // owner key were also a SEIZE slot key, the owner's own keypair could cast
    // one of the three quorum votes, degrading "owner + 2 independent cold
    // signers" to "owner + 1". `owner == ops` would likewise let one party
    // satisfy both the owner signature and the OPS attestation in TRANSFER.
    {
        let role_keys: [&[u8; X_ONLY_PUBKEY_LEN]; 6] =
            [ops_pubkey, freeze_pubkey, &seize_pubkeys[0], &seize_pubkeys[1], &seize_pubkeys[2], mint_pubkey];
        for (i, role_key) in role_keys.iter().enumerate() {
            assert!(*role_key != owner_pubkey, "stablecoin owner pubkey must differ from every role pubkey (role slot {i})");
        }
    }
    let state = StablecoinStateHeader::new(*owner_pubkey, identifier_type, *role_registry_root, frozen_flag_value, epoch, 0);
    let mut rs = state.encode_script();
    debug_assert_eq!(rs.len(), STATE_HEADER_LEN);
    rs.extend_from_slice(&build_stablecoin_body(ops_pubkey, freeze_pubkey, seize_pubkeys, mint_pubkey));
    rs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::token::identifier_type as id_type;

    const OWNER: [u8; 32] = [0xAA; 32];
    const OPS: [u8; 32] = [0xBB; 32];
    const ROOT: [u8; 32] = [0xCC; 32];
    const FREEZE: [u8; 32] = [0xDD; 32];
    const SEIZE: [[u8; 32]; 3] = [[0x91; 32], [0x92; 32], [0x93; 32]];
    const MINT: [u8; 32] = [0xEF; 32];

    #[test]
    fn redeem_script_starts_with_state_header() {
        let rs = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        assert_eq!(rs[0], 0x20);
        assert_eq!(&rs[1..33], &OWNER);
        assert_eq!(rs[33], 0x01);
        assert_eq!(rs[34], id_type::PUBKEY);
        assert_eq!(rs[35], 0x20);
        assert_eq!(&rs[36..68], &ROOT);
        assert_eq!(rs[68], 0x01);
        assert_eq!(rs[69], frozen_flag::CLEAR);
        assert_eq!(rs[70], 0x04);
        assert_eq!(&rs[71..75], &0u32.to_le_bytes());
        assert!(rs.len() > STATE_HEADER_LEN);
    }

    #[test]
    fn ops_pubkey_is_baked_into_transfer_branch() {
        let rs = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        // The OPS pubkey must appear somewhere in the body (exact offset is
        // load-bearing on the dispatch/branch bytecode's fixed shape, so we
        // search rather than hardcode a brittle constant here).
        assert!(rs.windows(32).any(|w| w == OPS));
    }

    #[test]
    #[should_panic(expected = "pairwise distinct")]
    fn duplicated_seize_key_rejected() {
        // seize[0] == seize[1] would let one key satisfy two 2-of-3 slots.
        let dup_seize: [[u8; 32]; 3] = [[0x91; 32], [0x91; 32], [0x93; 32]];
        let _ = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &dup_seize, &MINT);
    }

    #[test]
    #[should_panic(expected = "pairwise distinct")]
    fn shared_ops_mint_key_rejected() {
        // mint == ops erodes role separation.
        let _ = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &OPS);
    }

    #[test]
    fn freeze_pubkey_is_baked_into_freeze_branch() {
        let rs = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        assert!(rs.windows(32).any(|w| w == FREEZE));
    }

    #[test]
    fn seize_pubkeys_are_baked_into_seize_branch() {
        let rs = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        // All three SEIZE pubkeys must appear somewhere in the body (exact
        // offsets are load-bearing on the dispatch/branch bytecode's fixed
        // shape, so we search rather than hardcode brittle constants here).
        for pk in &SEIZE {
            assert!(rs.windows(32).any(|w| w == pk), "SEIZE pubkey {pk:?} not found baked into redeem script");
        }
    }

    #[test]
    fn mint_pubkey_is_baked_into_burn_branch() {
        let rs = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        assert!(rs.windows(32).any(|w| w == MINT));
    }

    #[test]
    fn distinct_ops_keys_yield_distinct_redeem_scripts() {
        let a = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        let b =
            build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &[0xCD; 32], &FREEZE, &SEIZE, &MINT);
        assert_ne!(a, b);
        assert_eq!(&a[..STATE_HEADER_LEN], &b[..STATE_HEADER_LEN]); // state unaffected
    }

    #[test]
    fn distinct_freeze_keys_yield_distinct_redeem_scripts() {
        let a = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        let b =
            build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &[0xCD; 32], &SEIZE, &MINT);
        assert_ne!(a, b);
        assert_eq!(&a[..STATE_HEADER_LEN], &b[..STATE_HEADER_LEN]); // state unaffected
    }

    #[test]
    fn distinct_seize_keys_yield_distinct_redeem_scripts() {
        let a = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        let mut other_seize = SEIZE;
        other_seize[1] = [0xCD; 32];
        let b =
            build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &other_seize, &MINT);
        assert_ne!(a, b);
        assert_eq!(&a[..STATE_HEADER_LEN], &b[..STATE_HEADER_LEN]); // state unaffected
    }

    #[test]
    fn distinct_mint_keys_yield_distinct_redeem_scripts() {
        let a = build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &MINT);
        let b =
            build_stablecoin_redeem_script(&OWNER, id_type::PUBKEY, &ROOT, frozen_flag::CLEAR, 0, &OPS, &FREEZE, &SEIZE, &[0xCD; 32]);
        assert_ne!(a, b);
        assert_eq!(&a[..STATE_HEADER_LEN], &b[..STATE_HEADER_LEN]); // state unaffected
    }

    #[test]
    fn body_length_is_deterministic_regardless_of_state_field_values() {
        // Body bytecode never embeds state field VALUES (only ops_pubkey/
        // freeze_pubkey/seize_pubkeys/mint_pubkey are baked in), so its length
        // must be identical across different owner/root/epoch/frozen_flag
        // choices for the same keys.
        let a = build_stablecoin_body(&OPS, &FREEZE, &SEIZE, &MINT);
        let b = build_stablecoin_body(&OPS, &FREEZE, &SEIZE, &MINT);
        assert_eq!(a, b);
    }

    #[test]
    fn dispatch_stub_branches_are_all_present_and_unimplemented() {
        let body = build_stablecoin_body(&OPS, &FREEZE, &SEIZE, &MINT);
        // ROTATE is the only remaining not-yet-implemented branch (deferred
        // to post-Live, see this module's top doc); its OP_0 stub byte must
        // still appear -- a loose but real smoke check that we didn't forget
        // to splice a branch in. FREEZE/SEIZE/BURN/MIGRATE are now all real
        // bytecode, so the floor drops from 2 to 1 (this is a MINIMUM bound,
        // not an exact count -- other branches incidentally embed their own
        // 0x00 bytes too, e.g. TRANSFER's `frozen_flag::CLEAR` literal and
        // BURN's `dr_output_spk_check` sink-pin reconstruction, whose
        // `[0x00, 0x00, 0xaa, 0x20]` prefix literal also embeds two).
        let stub_count = body.iter().filter(|&&byte| byte == 0x00).count();
        assert!(stub_count >= 1, "expected at least 1 OP_0 stub byte (ROTATE), found {stub_count}");
    }

    #[test]
    fn freeze_branch_contains_value_continuity_check() {
        // Security-fix smoke check: the FREEZE branch must splice in
        // `dr_value_continuity_check`'s exact 6-byte sequence (OpTxInputIndex
        // OpTxInputAmount OpTxInputIndex OpTxOutputAmount OpEqual OpVerify) --
        // without it a FREEZE-only spend could alter the coin's native value.
        let freeze = build_freeze_branch(&FREEZE);
        let needle: &[u8] = &[0xb9, 0xbe, 0xb9, 0xc2, 0x87, 0x69];
        assert!(freeze.windows(needle.len()).any(|w| w == needle), "FREEZE branch missing dr_value_continuity_check bytes");
    }

    #[test]
    fn seize_branch_contains_value_continuity_check() {
        // Same security-fix invariant as FREEZE (§4 cross-branch invariant):
        // SEIZE has no owner SIGHASH_ALL signature either, so it must splice
        // in the same `dr_value_continuity_check` 6-byte sequence.
        let seize = build_seize_branch(&SEIZE);
        let needle: &[u8] = &[0xb9, 0xbe, 0xb9, 0xc2, 0x87, 0x69];
        assert!(seize.windows(needle.len()).any(|w| w == needle), "SEIZE branch missing dr_value_continuity_check bytes");
    }

    #[test]
    fn seize_branch_uses_checksigfromstack_three_times() {
        // Documents the design decision (see `build_seize_branch`'s doc): the
        // 2-of-3 quorum is emitted as three `OpCheckSigFromStack` (0xd7)
        // opcodes, NOT native `OpCheckMultiSig` (0xae) -- the latter is
        // hard-wired to the tx's own sighash in this engine and has no
        // stack-message form. (A raw byte-value scan for the ABSENCE of 0xae
        // would be unsound -- baked pubkey/data bytes could coincidentally
        // contain that value -- so this only positively asserts the expected
        // opcode is present exactly 3 times, which is what the branch
        // actually emits.)
        let seize = build_seize_branch(&SEIZE);
        let checksigfromstack_count = seize.iter().filter(|&&byte| byte == 0xd7).count();
        assert_eq!(checksigfromstack_count, 3, "expected exactly 3 OpCheckSigFromStack calls in the SEIZE branch");
    }

    #[test]
    fn burn_sink_spk_bytes_are_version_zero_plus_p2sh_of_burn_sink_script() {
        // Ties `burn_sink_spk_bytes()` (the off-chain utility for
        // constructing the actual sink output -- no longer baked into the
        // branch's on-chain check, see `build_burn_branch`'s doc) to
        // `burn_sink_spk()`/`BURN_SINK_SCRIPT` -- version 0 (2 BIG-ENDIAN
        // bytes, matching `OpTxOutputSpk`'s actual serialization) || the
        // 35-byte P2SH script wrapping BURN_SINK_SCRIPT, matching every other
        // SPK in this codebase (see `crate::build_p2sh`).
        let bytes = burn_sink_spk_bytes();
        let spk = burn_sink_spk();
        assert_eq!(bytes.len(), 37, "37 = 2-byte version + 35-byte P2SH script");
        assert_eq!(&bytes[..2], &[0x00, 0x00]);
        assert_eq!(&bytes[2..], spk.script());
        // And the P2SH script itself is the standard ScriptHash shape
        // (OpBlake2b OpData32 <hash> OpEqual) wrapping BURN_SINK_SCRIPT, not
        // BURN_SINK_SCRIPT used directly as a locking script.
        assert_eq!(spk.script().len(), 35);
        assert_eq!(spk.script()[0], 0xaa, "first byte must be OpBlake2b");
        assert_eq!(spk.script()[1], 0x20, "second byte must be push32");
        assert_eq!(spk.script()[34], 0x87, "last byte must be OpEqual");
        assert_eq!(&spk.script()[2..34], &crate::blake2b_256(&BURN_SINK_SCRIPT));
    }

    #[test]
    fn burn_sink_script_is_a_bare_op_return_used_as_a_p2sh_redeem_script() {
        // OpReturn (0x6a) as the FIRST (and only) opcode of the REDEEM
        // script (not the locking script -- see `BURN_SINK_SCRIPT`'s doc for
        // why a bare-OpReturn locking script is non-standard/non-relayable on
        // Kaspa). This engine's `OpReturn` unconditionally errors
        // (`TxScriptError::EarlyReturn`) the instant it executes, regardless
        // of stack contents or position, so revealing this redeem script to
        // spend the P2SH output can never succeed.
        assert_eq!(BURN_SINK_SCRIPT, [0x6a]);
    }

    #[test]
    fn mint_pubkey_baked_via_checksigfromstack_in_burn_branch() {
        let burn = build_burn_branch(&MINT);
        assert!(burn.windows(32).any(|w| w == MINT));
        // Exactly one OpCheckSigFromStack (0xd7) -- a single-signer MINT
        // attestation, unlike SEIZE's 3x quorum.
        let checksigfromstack_count = burn.iter().filter(|&&byte| byte == 0xd7).count();
        assert_eq!(checksigfromstack_count, 1, "expected exactly 1 OpCheckSigFromStack call in the BURN branch");
    }

    #[test]
    fn burn_branch_pins_canonical_sink_via_dr_output_spk_check() {
        // Live-discovered-bug regression guard (see `build_burn_branch`'s
        // doc): the sink-pin check must use the SAME live-proven on-chain
        // reconstruction mechanism TRANSFER/FREEZE/SEIZE use for their
        // `new_rs` (`dr_output_spk_check`: an ON-CHAIN `OpBlake2b`
        // reconstruction of `P2SH(candidate)` compared via `OpEqual` against
        // the REAL successor's `OpTxOutputSpk`), NOT a host-computed
        // raw-literal `OpEqual` against `OpTxOutputSpk`'s serialized bytes
        // (the mechanism that failed live the first time it was ever
        // exercised on a real node).
        let burn = build_burn_branch(&MINT);
        let needle = dr_output_spk_check(1, 1);
        assert!(
            burn.windows(needle.len()).any(|w| w == needle),
            "BURN branch missing dr_output_spk_check bytes for the sink-pin check"
        );
        // The BURN_SINK_SCRIPT literal (the "candidate redeem script" stand-in)
        // must still be baked in -- not attacker-suppliable.
        assert!(burn.contains(&BURN_SINK_SCRIPT[0]));
        // And the OLD host-computed absolute SPK-byte literal must no longer
        // appear anywhere in the branch bytecode -- the on-chain check no
        // longer trusts a baked absolute-byte literal at all.
        let sink_bytes = burn_sink_spk_bytes();
        assert!(
            !burn.windows(sink_bytes.len()).any(|w| w == sink_bytes),
            "BURN branch must not bake the raw canonical-sink SPK literal anymore"
        );
    }

    #[test]
    fn burn_branch_omits_value_continuity_check() {
        // §4/§8 (task spec): BURN has an owner SIGHASH_ALL signature, so it
        // gets value-pinning "for free" like TRANSFER -- and unlike
        // FREEZE/SEIZE, it must NOT call `dr_value_continuity_check` (that
        // helper asserts input amount == successor OUTPUT amount, which would
        // forbid ever burning value into the sink at all). This is a
        // regression guard on the deliberate omission documented in
        // `build_burn_branch`'s doc.
        let burn = build_burn_branch(&MINT);
        let needle: &[u8] = &[0xb9, 0xbe, 0xb9, 0xc2, 0x87, 0x69];
        assert!(
            !burn.windows(needle.len()).any(|w| w == needle),
            "BURN branch must NOT contain dr_value_continuity_check bytes"
        );
    }

    #[test]
    fn seize_quorum_keys_baked_via_checksigfromstack_in_migrate_branch() {
        // Decision 2026-07-20: MIGRATE's authorizer is the cold 2-of-3 SEIZE
        // quorum, NOT the hot OPS key (governance-exit hole, see
        // `build_migrate_branch`'s "Authorizer" doc section).
        let migrate = build_migrate_branch(&SEIZE);
        for (i, pk) in SEIZE.iter().enumerate() {
            assert!(migrate.windows(32).any(|w| w == pk), "SEIZE quorum key {i} must be baked into the MIGRATE branch");
        }
        assert!(!migrate.windows(32).any(|w| w == OPS), "the hot OPS key must NOT authorize MIGRATE any more");
        // Exactly three OpCheckSigFromStack (0xd7) calls -- the same 2-of-3
        // quorum shape SEIZE uses (shared `emit_2of3_threshold` segment).
        let checksigfromstack_count = migrate.iter().filter(|&&byte| byte == 0xd7).count();
        assert_eq!(checksigfromstack_count, 3, "expected exactly 3 OpCheckSigFromStack calls in the MIGRATE branch");
    }

    #[test]
    fn migrate_and_seize_share_the_same_quorum_segment() {
        // The two quorum gates must not drift: both are emitted by
        // `emit_2of3_threshold`, so MIGRATE's tail (from the first quorum
        // opcode through the threshold VERIFY) must appear verbatim in SEIZE.
        let mut expected = Vec::new();
        emit_2of3_threshold(&mut expected, &SEIZE);
        let migrate = build_migrate_branch(&SEIZE);
        let seize = build_seize_branch(&SEIZE);
        assert!(migrate.windows(expected.len()).any(|w| w == expected), "MIGRATE must use the shared 2-of-3 segment");
        assert!(seize.windows(expected.len()).any(|w| w == expected), "SEIZE must use the shared 2-of-3 segment");
    }

    #[test]
    fn migrate_branch_omits_value_continuity_check() {
        // §4 cross-branch invariant (task spec): MIGRATE has an owner
        // SIGHASH_ALL signature, so it gets value-pinning "for free" like
        // TRANSFER/BURN -- it must NOT call `dr_value_continuity_check`
        // (that helper is only needed by branches with no owner signature at
        // all, FREEZE/SEIZE). Regression guard on the deliberate omission
        // documented in `build_migrate_branch`'s doc.
        let migrate = build_migrate_branch(&SEIZE);
        let needle: &[u8] = &[0xb9, 0xbe, 0xb9, 0xc2, 0x87, 0x69];
        assert!(
            !migrate.windows(needle.len()).any(|w| w == needle),
            "MIGRATE branch must NOT contain dr_value_continuity_check bytes"
        );
    }

    #[test]
    fn migrate_branch_has_no_new_rs_authentication_opcodes() {
        // Regression guard on the fn doc's "No `new_rs`" design point:
        // MIGRATE must NOT use the dr_output_spk_check/dr_field_extract
        // "authenticate candidate redeem script, then slice fields from it"
        // mechanism TRANSFER/FREEZE/SEIZE rely on -- it only ever needs the
        // successor SPK's hash (OpTxOutputSpk + OpBlake3), never OpSubstr
        // (0x7f, dr_field_extract's/dr_output_spk_check's slicing opcode).
        let migrate = build_migrate_branch(&SEIZE);
        assert!(!migrate.contains(&0x7f), "MIGRATE branch must not contain OpSubstr (0x7f) -- no new_rs field/extraction expected");
    }
}
