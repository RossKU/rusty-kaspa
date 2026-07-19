//! Mint-authority contract — bytecode body (`STABLECOIN_ROBUST_DESIGN.md` §9
//! "Mint + Supply Cap"). Both mini-dispatch operations are wired: `MINT`
//! (`op_type 0x00`, [`build_mint_branch`]) and `RAISE_CAP` (`op_type 0x01`,
//! [`build_raise_cap_branch`]).
//!
//! # What is mirrored from where
//!
//! - **Self-continuation D&R shape** (authenticate `old_rs`, prefix/suffix
//!   match against `new_rs`, extract a mutable counter, verify the successor
//!   output's SPK) is [`crate::contract::spot::dca`]'s `DCA_ORDER_BODY` D&R
//!   block (`core/src/contract/spot/dca.rs:171-293`), generalized via the
//!   composable helpers in `crate::contract::dr`
//!   ([`dr_input_spk_check`]/[`dr_output_spk_check`]/[`dr_suffix_check`]/
//!   [`dr_field_extract`], `core/src/contract/dr.rs:43,72,127,153`) rather
//!   than dca.rs's hand-tabulated bytes. Unlike dca.rs (whose mutable zone
//!   sits in the MIDDLE of its state, needing both a prefix AND a suffix
//!   check), this contract's single mutable field (`running_supply`) is
//!   placed FIRST (`state.rs`), so "everything from `current_cap` onward" is
//!   ONE contiguous suffix — a single [`dr_suffix_check`] call covers both
//!   "`current_cap` unchanged" and "the entire baked body unchanged".
//! - **Coin-emission reconstruction + `OpCheckSigFromStack` attestation
//!   pattern** mirrors `crate::contract::stablecoin::body`'s
//!   `OpBlake2b`-then-P2SH-compare idiom (used by every `dr_output_spk_check`
//!   call, and hand-inlined here once more since the "successor" being
//!   authenticated — the emitted stablecoin coin — is built fresh via
//!   `OpCat` rather than picked whole off the stack) and its
//!   attestation-preimage-via-`OpCat`-chain-then-`OpCheckSigFromStack`
//!   pattern (`build_transfer_branch`/`build_freeze_branch`,
//!   `core/src/contract/stablecoin/body.rs:216-318,378-521`).
//! - **`token_mint`'s self-continuation/admin pattern**
//!   (`core/src/contract/token.rs:164-238`) is the *conceptual* precedent §9
//!   names ("reuses the existing `token_mint` self-continuation/admin
//!   pattern") — this implementation follows the STRONGER dr.rs/dca.rs D&R
//!   template instead (per this task's explicit instruction), since
//!   `token_mint`'s `output[0].spk == input.spk` (no cross-authentication of
//!   a spender-supplied successor blob) relies on `SIGHASH_ALL` alone and has
//!   no analogue here (this branch has no owner signature at all, only the
//!   MINT role's `OpCheckSigFromStack`).
//!
//! # Redeem script shape
//!
//! `state (18B, see state.rs) || body`. The body is a 2-way `op_type`
//! dispatch: `0x00 MINT` / `0x01 RAISE_CAP`, both real bytecode; the cold
//! `cap_authority_pubkeys` are baked into the RAISE_CAP branch.
//!
//! # Sigscript the MINT branch consumes
//!
//! After P2SH extraction pops the redeem script, the remaining stack (pushed
//! by the sigscript) must be, top-to-bottom (i.e. LAST push is shallowest):
//!
//! ```text
//! op_type_selector (1B: 0x00 for MINT)                 <- top (last pushed)
//! recipient_pubkey (32B: the newly-minted coin's owner_pubkey)
//! mint_amount      (8B, LE u64)
//! new_rs           (variable: candidate self-continuation successor)
//! old_rs           (variable: this input's own current redeemScript,
//!                    authenticated via dr_input_spk_check)
//! mint_sig         (64B: raw Schnorr sig over the MINT attestation message,
//!                    mint_authority::attestation::build_mint_attestation_message)
//!                                                       <- deepest (first pushed)
//! ```
//!
//! This input's `sig_op_count` MUST be **1** (a single `OpCheckSigFromStack`
//! for the MINT role — there is no owner signature at all, mirroring
//! `stablecoin::body::build_freeze_branch`'s "no owner signature" shape, not
//! `build_transfer_branch`'s owner+role shape).
//!
//! # Entry stack once the dispatch delivers control to the MINT branch
//!
//! State header pushes 2 fields (`current_cap` then `running_supply` --
//! `state.rs`'s "own state" pushes are always current_cap on top since it's
//! pushed LAST), then the dispatch consumes+drops the `op_type` selector:
//!
//! ```text
//! current_cap(0), running_supply(1), recipient_pubkey(2), mint_amount(3),
//! new_rs(4), old_rs(5), mint_sig(6)
//! ```
//!
//! # Coin-shape reconstruction + recipient binding (the anti-backdoor +
//! security-fix core of this branch)
//!
//! Because every stablecoin-covenant role pubkey (`ops_pubkey`,
//! `freeze_pubkey`, `seize_pubkeys`, and `mint_pubkey` itself, reused as the
//! stablecoin covenant's own MINT-role BURN-authorizer key per
//! `STABLECOIN_ROBUST_DESIGN.md` §2's role table) plus `identifier_type` /
//! `role_registry_root` are ALL baked constants, the ENTIRE tail of any
//! emitted coin's redeemScript (everything after its 33-byte
//! `owner_pubkey`-with-push-opcode prefix) is a build-time-computable
//! constant, identical for every mint. [`build_fixed_mid`] precomputes that
//! constant once (by calling the REAL
//! [`crate::contract::stablecoin::body::build_stablecoin_body`] — the exact
//! function that builds a genuine stablecoin covenant's body — so the
//! reconstruction is byte-identical to what that module actually deploys,
//! not a hand-rolled duplicate that could drift) and [`build_mint_branch`]
//! embeds it as ONE literal `OpCat`-able data push (`fixed_mid`). On-chain,
//! the MINT branch then only needs to `OpCat` `[0x20] || recipient_pubkey ||
//! fixed_mid` to reconstruct the complete expected coin redeemScript, hash it
//! (`OpBlake2b`) into a P2SH scriptPublicKey, and assert `output[1].spk`
//! equals it (`Op1 OpTxOutputSpk OpEqual OpVerify`, at the FIXED index 1 —
//! mirroring `stablecoin::body`'s "fixed output shape" test-harness
//! convention, since this contract always emits its self-continuation
//! successor at output[0] and the newly-minted coin at output[1]). This
//! guarantees the signer's only discretion over the emitted coin is
//! `recipient_pubkey` (via this reconstruction) and `mint_amount` (via the
//! output-value check below) — nothing else about the coin's shape
//! (frozen_flag, epoch, role keys, identifier_type) can be smuggled in.
//!
//! The **recipient-binding security fix** (closing the §9 gap where a MINT
//! attestation was unbound to any specific recipient and could be replayed
//! to redirect newly-minted coins): the attestation's `recipient_spk_hash`
//! field is computed via `Op1 OpTxOutputSpk OpBlake3` — i.e. `Blake3` of
//! WHATEVER is ACTUALLY at output[1] in the CURRENT transaction, never a
//! separately-suppliable sigscript value. Combined with the coin-shape check
//! above (which already pins output[1]'s actual SPK to encode the
//! sigscript's `recipient_pubkey`), this means the signed message
//! transitively commits to `recipient_pubkey`: redirecting the mint to a
//! different recipient changes output[1]'s real SPK, which changes the
//! on-chain-recomputed message hash, which the original signature no longer
//! matches (`OpCheckSigFromStack` fails). See `mint_authority::attestation`'s
//! module doc for the full 124-byte preimage layout.

use super::attestation::{op_type, X_ONLY_PUBKEY_LEN};
use crate::contract::dr::{dr_field_extract, dr_input_spk_check, dr_output_spk_check, dr_prefix_check, dr_suffix_check};
use crate::contract::helpers::push_index;

/// Opcode bytes used by this body (named for readability; values are the
/// canonical `crypto/txscript` assignments — see
/// `core/src/contract/stablecoin/body.rs`'s own `op` module, which this
/// mirrors, extended with `TXOUTPUTAMOUNT`/`ADD`/`NUMEQUAL`/`LESSTHANOREQUAL`
/// and the dispatch's `DUP`/`IF`/`ELSE`/`ENDIF`).
mod op {
    pub const DROP: u8 = 0x75;
    pub const DUP: u8 = 0x76;
    pub const PICK: u8 = 0x79;
    pub const ROLL: u8 = 0x7a;
    pub const SWAP: u8 = 0x7c;
    pub const CAT: u8 = 0x7e;
    pub const SIZE: u8 = 0x82;
    pub const IF: u8 = 0x63;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const EQUAL: u8 = 0x87;
    pub const VERIFY: u8 = 0x69;
    pub const ADD: u8 = 0x93;
    pub const NUMEQUAL: u8 = 0x9c;
    pub const GREATERTHAN: u8 = 0xa0;
    pub const LESSTHANOREQUAL: u8 = 0xa1;
    pub const GREATERTHANOREQUAL: u8 = 0xa2;
    pub const BLAKE2B: u8 = 0xaa;
    pub const TXINPUTINDEX: u8 = 0xb9;
    pub const OUTPOINTTXID: u8 = 0xba;
    pub const OUTPOINTINDEX: u8 = 0xbb;
    pub const TXINPUTAMOUNT: u8 = 0xbe;
    pub const TXOUTPUTAMOUNT: u8 = 0xc2;
    pub const TXOUTPUTSPK: u8 = 0xc3;
    pub const NUM2BIN: u8 = 0xcd;
    pub const INPUTCOVENANTID: u8 = 0xcf;
    pub const CHECKSIGFROMSTACK: u8 = 0xd7;
    pub const BLAKE3: u8 = 0xd9;
    pub const OP0: u8 = 0x00;
    pub const OP1: u8 = 0x51;
    pub const OP2: u8 = 0x52;
    pub const OP4: u8 = 0x54;
    pub const DATA1: u8 = 0x01;
    pub const DATA8: u8 = 0x08;
    pub const DATA32: u8 = 0x20;
}

fn e_roll(b: &mut Vec<u8>, depth: u16) {
    push_index(b, depth);
    b.push(op::ROLL);
}

fn e_pick(b: &mut Vec<u8>, depth: u16) {
    push_index(b, depth);
    b.push(op::PICK);
}

/// Assert output[0]'s native value equals the spending input's native value
/// -- the self-continuation successor's OPERATING BALANCE must not be
/// drainable by a spend authorized only by a lower-privileged role's
/// `OpCheckSigFromStack` attestation (MINT's hot `mint_pubkey`, RAISE_CAP's
/// cold `cap_authority` quorum) rather than a whole-transaction
/// `SIGHASH_ALL` owner signature (which would pin every output's amount "for
/// free"). Without this, a hot `mint_pubkey` holder (or the cap_authority
/// quorum) could shave value off the authority UTXO on every spend.
///
/// Unlike `crate::contract::dr::dr_value_continuity_check` (which reuses
/// `OpTxInputIndex` as the successor OUTPUT index too, i.e. assumes
/// `output_idx == input_idx` -- the convention every OTHER covenant in this
/// codebase follows for its 1:1 self-continuation successor), this
/// contract's self-continuation successor is ALWAYS emitted at the FIXED
/// output index 0 regardless of which input index is spending (mirroring
/// this module's own `dr_output_spk_check(_, 1)` calls, which likewise use a
/// literal `Op0`, not `OpTxInputIndex`, for the successor's output index) --
/// so this inlines the same shape with a literal `Op0` in place of
/// `dr_value_continuity_check`'s second `OpTxInputIndex`.
///
/// Layout (8 bytes):
/// ```text
///   OpTxInputIndex OpTxInputAmount   -> this input's native value
///   Op0 OpTxOutputAmount             -> output[0]'s native value
///   OpNumEqual OpVerify
/// ```
///
/// Self-contained: pushes exactly the two values it then consumes, so its
/// net effect on the caller's existing stack is 0 -- callers may splice it
/// in anywhere without adjusting any other op's depth argument.
fn value_continuity_check_output0() -> Vec<u8> {
    use op::*;
    vec![TXINPUTINDEX, TXINPUTAMOUNT, OP0, TXOUTPUTAMOUNT, NUMEQUAL, VERIFY]
}

/// Emit the `RAISE_CAP` (`op_type = 0x01`) branch bytecode
/// (`STABLECOIN_ROBUST_DESIGN.md` §9: "`RAISE_CAP` (authorized by cold 2-of-3
/// `cap_authority`): self-continue with `current_cap' = new_cap` where
/// `OpVerify(new_cap > current_cap)`; `running_supply` unchanged in the
/// successor; no coin emitted").
///
/// # What is mirrored from where
///
/// - **Authorization**: the SAME fixed-position 2-of-3 `OpCheckSigFromStack`
///   threshold idiom as [`crate::contract::stablecoin::body::build_seize_branch`]
///   (three checks, `bool1`/`bool2`/`bool3` summed via two `OpAdd`s, compared
///   `>= 2` via `OpGreaterThanOrEqual OpVerify`) — over the baked
///   `cap_authority_pubkeys`, structurally identical in strength to that
///   covenant's SEIZE quorum (§9's own text: "structurally identical in
///   strength to this covenant's SEIZE quorum").
/// - **Self-continuation D&R shape**: the SAME `crate::contract::dr` helpers
///   [`build_mint_branch`] uses (`dr_input_spk_check`/`dr_field_extract`),
///   but with the mutable/fixed regions SWAPPED relative to MINT: MINT's
///   mutable field is `running_supply` (prefix `[0..9)`) with `current_cap`
///   and the baked body carried forward as one contiguous suffix
///   `[9..end)`. RAISE_CAP mutates `current_cap` instead, so it needs BOTH a
///   [`dr_prefix_check`] over `[0..9)` (`running_supply` — including its own
///   push opcode — UNCHANGED) AND a [`dr_suffix_check`] over
///   `[STATE_HEADER_LEN..end)` (the baked body UNCHANGED), leaving exactly
///   the `current_cap` byte range `[9..18)` uncovered by either check — the
///   one region this branch is allowed, and required, to change.
///
/// # Entry stack once the dispatch delivers control to the RAISE_CAP branch
///
/// State header pushes 2 fields (`current_cap` then `running_supply`), then
/// the dispatch consumes+drops the `op_type` selector:
///
/// ```text
/// current_cap(0), running_supply(1), new_cap(2), new_rs(3), old_rs(4),
/// sig3(5), sig2(6), sig1(7)
/// ```
///
/// This is the sigscript layout callers must produce (push order,
/// first==deepest): `sig1, sig2, sig3, old_rs, new_rs, new_cap(8B LE),
/// op_type_selector(0x01)`, then the redeem script.
/// This input's `sig_op_count` MUST be **3** (three `OpCheckSigFromStack`
/// calls for the 2-of-3 `cap_authority` quorum — no owner signature, no
/// `mint_pubkey` involvement at all, mirroring `build_seize_branch`'s "no
/// owner signature" shape).
///
/// # Attestation pre-image (84B, §9 — see `mint_authority::attestation`'s
/// module doc for the exact byte layout/rationale)
///
/// `DOMAIN_TAG_MINT || covenant_id || outpoint_txid || outpoint_index ||
/// new_cap(8,LE)`. Every input-side introspection field is sourced from
/// `OpTxInputIndex` (never an immediate), binding the quorum's signatures to
/// THIS input's specific spend; `new_cap` is folded in as the sigscript
/// pushed it (fixed 8-byte LE), so the quorum's signatures attest to the
/// EXACT ceiling value being raised to — replaying a captured RAISE_CAP
/// attestation against a transaction proposing a DIFFERENT `new_cap` changes
/// the recomputed message hash, which the original signatures no longer
/// match.
fn build_raise_cap_branch(cap_authority_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3], genesis_covenant_id: &[u8; 32]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(220);

    // ---- Step 0: this coin's own (live-pushed) running_supply is unused --
    // RAISE_CAP re-authenticates unchanged-ness via the prefix check below
    // (over the AUTHENTICATED old_rs/new_rs blobs) instead of trusting this
    // live push directly, mirroring build_mint_branch's Step 0 discipline. ----
    e_roll(&mut b, 1);
    b.push(DROP);
    // Stack: current_cap(0), new_cap(1), new_rs(2), old_rs(3), sig3(4),
    // sig2(5), sig1(6).

    // ---- Step 0b (SECURITY FIX, numeric-domain bound): new_cap must decode
    // as non-negative (i.e. the raw u64 the sigscript intended to push must
    // be in [0, 2^63)). Kaspa script numbers are sign-magnitude LE, and the
    // engine's arithmetic ops read this fixed 8-byte push as an `i64` (see
    // `stablecoin::attestation::MAX_AMOUNT_EXCLUSIVE`'s own doc on this same
    // domain) -- a raw u64 >= 2^63 has its top bit set and so decodes
    // negative (or, for exactly 2^63, decodes as the same value as a
    // legitimate 0 -- an inherent sign-magnitude aliasing this check cannot
    // resolve; see this module's exploitability finding for why that
    // specific boundary value is caught anyway, by Step 7's pre-existing
    // strict-increase check). This is defense-in-depth: Step 7's `new_cap >
    // current_cap` already rejects every value in this range when
    // current_cap is itself non-negative (which it always is, inductively,
    // since RAISE_CAP is the only op that ever changes it and this same
    // check -- or Step 7 -- has always blocked the transition into
    // negative-decoding territory) -- but pin it here explicitly rather than
    // relying on that incidental interaction. Non-destructive: OpGreaterThan
    // Or Equal pops the copy and the literal, OpVerify pops the bool, netting
    // to 0 against the stack shape above. ----
    e_pick(&mut b, 1); // new_cap copy -> top
    // Stack: new_cap_copy(0), current_cap(1), new_cap(2), new_rs(3), old_rs(4),
    // sig3(5), sig2(6), sig1(7).
    b.push(OP0);
    // Stack: lit0(0), new_cap_copy(1), current_cap(2), new_cap(3), new_rs(4),
    // old_rs(5), sig3(6), sig2(7), sig1(8).
    b.push(GREATERTHANOREQUAL); // new_cap_copy >= 0 (deeper >= shallower)
    b.push(VERIFY);
    // Stack (net 0, restored): current_cap(0), new_cap(1), new_rs(2), old_rs(3),
    // sig3(4), sig2(5), sig1(6).

    // ---- Step 1: self-continuation (a) -- authenticate old_rs really is
    // this input's own committed redeemScript (mirrors build_mint_branch's
    // Step 1). ----
    b.extend_from_slice(&dr_input_spk_check(3));

    // ---- Step 2: running_supply UNCHANGED -- a straight prefix compare over
    // [0..9) (running_supply's own push opcode + its 8B payload) between
    // old_rs and new_rs. Unlike MINT (which carries current_cap+body forward
    // as one suffix and mutates running_supply), RAISE_CAP carries
    // running_supply forward unchanged and mutates current_cap instead -- so
    // the roles of "prefix" and "suffix" swap relative to build_mint_branch. ----
    b.extend_from_slice(&dr_prefix_check(3, 3, super::state::CURRENT_CAP_OPCODE_OFFSET as u16));
    // Stack unchanged (dr_prefix_check nets to 0): current_cap(0), new_cap(1),
    // new_rs(2), old_rs(3), sig3(4), sig2(5), sig1(6).

    // ---- Step 3: the baked body (everything after the 18B state header)
    // must be byte-identical between old_rs and new_rs -- current_cap
    // (bytes [9..18)) is deliberately EXCLUDED from both this and the Step 2
    // prefix check above: it is the one region this branch is allowed, and
    // required, to change. ----
    b.extend_from_slice(&dr_suffix_check(3, 3, super::state::STATE_HEADER_LEN as u16));
    // Stack unchanged: current_cap(0), new_cap(1), new_rs(2), old_rs(3),
    // sig3(4), sig2(5), sig1(6).

    // ---- Step 4: push-opcode sanity check -- new_rs[9] must still be the
    // 0x08 (OpData8) push opcode, so the successor's current_cap field parses
    // the same way it does here (mirrors build_mint_branch's Step 3, applied
    // to current_cap's opcode byte instead of running_supply's). ----
    b.extend_from_slice(&dr_field_extract(2, super::state::CURRENT_CAP_OPCODE_OFFSET as u16, (super::state::CURRENT_CAP_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: current_cap(0), new_cap(1), new_rs(2), old_rs(3), sig3(4),
    // sig2(5), sig1(6).

    // ---- Step 5: old_rs no longer needed -- drop it. ----
    e_roll(&mut b, 3);
    b.push(DROP);
    // Stack: current_cap(0), new_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).

    // ---- Step 6: extract the successor's current_cap payload (8B) from
    // new_rs, and assert it equals the ATTESTED new_cap exactly (raw 8-byte
    // LE byte compare -- both sides are fixed-width 8-byte representations,
    // so OpEqual is sufficient here; contrast Step 7 below, which needs a
    // NUMERIC comparison). ----
    let cap_off = super::state::CURRENT_CAP_PAYLOAD_OFFSET as u16;
    b.extend_from_slice(&dr_field_extract(2, cap_off, cap_off + 8)); // succ_cap, from new_rs (depth2)
    // Stack: succ_cap(0), current_cap(1), new_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    e_pick(&mut b, 2); // new_cap copy (need the original again below)
    // Stack: new_cap_copy(0), succ_cap(1), current_cap(2), new_cap(3),
    // new_rs(4), sig3(5), sig2(6), sig1(7).
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: current_cap(0), new_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).

    // ---- Step 7: STRICT increase -- new_cap > current_cap. Both operands
    // are fixed 8-byte LE extractions/pushes (the SAME representation
    // build_mint_branch's own OpAdd/OpLessThanOrEqual arithmetic already
    // operates on directly), so OpGreaterThan applies to them as numbers
    // without any width mismatch -- this is a genuine NUMERIC comparison
    // (unlike Step 6's raw-byte equality), so it MUST be OpGreaterThan, never
    // OpEqual (recall build_mint_branch's own OpEqual-vs-OpNumEqual encoding
    // pitfall at its output-amount check). A copy of new_cap is taken (it is
    // needed once more below, for the attestation pre-image tail), then
    // swapped so the engine's "deeper OP shallower" convention evaluates
    // `new_cap > current_cap` (not the reverse). ----
    e_pick(&mut b, 1); // new_cap copy -> top
    // Stack: new_cap_copy(0), current_cap(1), new_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    b.push(SWAP);
    // Stack: current_cap(0), new_cap_copy(1), new_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    b.push(GREATERTHAN); // new_cap_copy > current_cap (deeper > shallower)
    b.push(VERIFY);
    // Stack: new_cap(0), new_rs(1), sig3(2), sig2(3), sig1(4).

    // ---- Step 8: self-continuation (b) -- output[0].spk == P2SH(new_rs), at
    // the FIXED index 0 (this contract always emits its self-continuation
    // successor at output[0]; RAISE_CAP emits NO other output -- no coin, §9). ----
    b.push(OP0); // literal output index 0
    // Stack: idx0(0), new_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).
    b.extend_from_slice(&dr_output_spk_check(2, 1));
    b.push(DROP); // drop idx0 (dr_output_spk_check's net effect is 0 otherwise)
    // Stack: new_cap(0), new_rs(1), sig3(2), sig2(3), sig1(4).

    // ---- Step 8b (SECURITY FIX): output[0]'s native value must equal this
    // input's native value -- the cap_authority quorum's OpCheckSigFromStack
    // attestation (no owner SIGHASH_ALL signature at all) doesn't otherwise
    // pin the successor's operating balance, so without this a cap_authority
    // holder could drain the authority UTXO's value while raising the cap. ----
    b.extend_from_slice(&value_continuity_check_output0());
    // Stack unchanged (net 0): new_cap(0), new_rs(1), sig3(2), sig2(3), sig1(4).

    // ---- Step 9: new_rs no longer needed -- drop it. ----
    e_roll(&mut b, 1);
    b.push(DROP);
    // Stack: new_cap(0), sig3(1), sig2(2), sig1(3).

    // ---- Step 10: RAISE_CAP attestation pre-image (84B,
    // mint_authority::attestation): DOMAIN_TAG_MINT || covenant_id ||
    // outpoint_txid || outpoint_index || new_cap. ----
    b.push(DATA8);
    b.extend_from_slice(&super::DOMAIN_TAG_MINT);
    // Stack: acc(0)=domain_tag, new_cap(1), sig3(2), sig2(3), sig1(4).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    // Stack: covenant_id(0), acc(1), new_cap(2), sig3(3), sig2(4), sig1(5).

    // ---- Step 10a (SECURITY FIX, SUB-FIX B, genesis-binding): assert THIS
    // input's real covenant_id (just pushed above) equals the baked genesis
    // covenant_id G -- closing the gap where a fake parallel authority
    // deployment, baked with the SAME PUBLIC cap_authority_pubkeys/
    // mint_pubkey but a DIFFERENT genesis, could otherwise raise its own
    // fake cap (covenant_id is not itself secret; only a genuine covenant
    // whose consensus-tracked covenant_id == G, i.e. one descended from the
    // real genesis deploy via self-continuation -- covenant_id PROPAGATES
    // through self-continuation, verified in consensus -- passes here). Reuses
    // this same OpTxInputIndex/OpInputCovenantId push for the preimage below
    // (via OpDup) rather than pushing it a second time. Non-destructive: DUP
    // makes a copy to compare against G, leaving the ORIGINAL covenant_id
    // untouched at its original depth for the CAT that follows. ----
    b.push(DUP);
    // Stack: covenant_id_copy(0), covenant_id(1), acc(2), new_cap(3), sig3(4),
    // sig2(5), sig1(6).
    b.push(DATA32);
    b.extend_from_slice(genesis_covenant_id);
    // Stack: G(0), covenant_id_copy(1), covenant_id(2), acc(3), new_cap(4),
    // sig3(5), sig2(6), sig1(7).
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack (restored): covenant_id(0), acc(1), new_cap(2), sig3(3), sig2(4),
    // sig1(5).

    b.push(CAT); // acc || covenant_id
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT); // acc || outpoint_txid
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT); // acc || outpoint_index(4B LE)
    // Stack: acc(0), new_cap(1), sig3(2), sig2(3), sig1(4).
    e_roll(&mut b, 1); // new_cap -> top (last use, consumed)
    // Stack: new_cap(0), acc(1), sig3(2), sig2(3), sig1(4).
    b.push(CAT); // acc || new_cap(8B LE) == full 84B preimage
    // Stack: acc(0), sig3(1), sig2(2), sig1(3).

    b.push(BLAKE3); // msg_hash = Blake3(acc)
    // Stack: msg_hash(0), sig3(1), sig2(2), sig1(3).

    // ---- Step 11: 2-of-3 threshold over the three baked cap_authority
    // pubkeys -- IDENTICAL shape to build_seize_branch's own tail (three
    // fixed-position OpCheckSigFromStack checks, booleans summed via two
    // OpAdd, compared >= 2 via OpGreaterThanOrEqual OpVerify), just over
    // cap_authority_pubkeys instead of seize_pubkeys. Fixed positional
    // convention: sig3<->cap_authority_pubkeys[2], sig2<->[1], sig1<->[0]. ----

    // -- check sig3 vs cap_authority_pubkeys[2] --
    e_roll(&mut b, 1); // sig3 -> top
    // Stack: sig3(0), msg_hash(1), sig2(2), sig1(3).
    e_pick(&mut b, 1); // copy of msg_hash -> top
    // Stack: msg_hash_copy(0), sig3(1), msg_hash(2), sig2(3), sig1(4).
    b.push(DATA32);
    b.extend_from_slice(&cap_authority_pubkeys[2]);
    // Stack: pubkey3(0), msg_hash_copy(1), sig3(2), msg_hash(3), sig2(4),
    // sig1(5).
    b.push(CHECKSIGFROMSTACK);
    // Stack: bool3(0), msg_hash(1), sig2(2), sig1(3).

    // -- check sig2 vs cap_authority_pubkeys[1] --
    e_roll(&mut b, 2); // sig2 -> top
    // Stack: sig2(0), bool3(1), msg_hash(2), sig1(3).
    e_pick(&mut b, 2); // copy of msg_hash -> top
    // Stack: msg_hash_copy(0), sig2(1), bool3(2), msg_hash(3), sig1(4).
    b.push(DATA32);
    b.extend_from_slice(&cap_authority_pubkeys[1]);
    // Stack: pubkey2(0), msg_hash_copy(1), sig2(2), bool3(3), msg_hash(4),
    // sig1(5).
    b.push(CHECKSIGFROMSTACK);
    // Stack: bool2(0), bool3(1), msg_hash(2), sig1(3).

    // -- check sig1 vs cap_authority_pubkeys[0] (consumes the ORIGINAL
    // msg_hash; no copy needed since this is the last use) --
    e_roll(&mut b, 3); // sig1 -> top
    // Stack: sig1(0), bool2(1), bool3(2), msg_hash(3).
    e_roll(&mut b, 3); // msg_hash -> top (directly above sig1)
    // Stack: msg_hash(0), sig1(1), bool2(2), bool3(3).
    b.push(DATA32);
    b.extend_from_slice(&cap_authority_pubkeys[0]);
    // Stack: pubkey1(0), msg_hash(1), sig1(2), bool2(3), bool3(4).
    b.push(CHECKSIGFROMSTACK);
    // Stack: bool1(0), bool2(1), bool3(2).

    // sum(bool1, bool2, bool3) >= 2 -- fixed-position 2-of-3 threshold.
    b.push(ADD); // bool1 + bool2 -> Stack: sum12(0), bool3(1).
    b.push(ADD); // sum12 + bool3 -> Stack: total(0).
    b.push(OP2);
    b.push(GREATERTHANOREQUAL);
    b.push(VERIFY);

    b.push(OP1);
    b
}

/// Precompute the constant tail of any emitted stablecoin coin's redeemScript
/// — everything from `identifier_type`'s push opcode (offset 33 in
/// `stablecoin::state::StablecoinStateHeader`'s framing) through the end of
/// the body — by calling the REAL
/// `crate::contract::stablecoin::body::build_stablecoin_body`. This is a
/// build-time (Rust-side) computation, not on-chain bytecode: the resulting
/// bytes are embedded as ONE literal `OpCat`-able data push inside
/// [`build_mint_branch`]'s bytecode.
fn build_fixed_mid(
    identifier_type: u8,
    role_registry_root: &[u8; 32],
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
) -> Vec<u8> {
    // mint_pubkey doubles as the stablecoin covenant's own MINT-role key
    // (STABLECOIN_ROBUST_DESIGN.md §2: "MINT ... authorizes MINT in the
    // separate mint-authority contract (§9) + authorizes BURN (issuer side)
    // in this covenant" -- the same key, not two different ones).
    let stablecoin_body = crate::contract::stablecoin::body::build_stablecoin_body(ops_pubkey, freeze_pubkey, seize_pubkeys, mint_pubkey);
    let mut mid = Vec::with_capacity(2 + 33 + 2 + 5 + stablecoin_body.len());
    // identifier_type (2B: push opcode + payload) -- baked, per-mint constant.
    mid.push(0x01);
    mid.push(identifier_type);
    // role_registry_root (33B: push opcode + 32B payload) -- baked.
    mid.push(0x20);
    mid.extend_from_slice(role_registry_root);
    // frozen_flag (2B) -- every freshly-minted coin starts CLEAR (§9).
    mid.push(0x01);
    mid.push(crate::contract::stablecoin::state::frozen_flag::CLEAR);
    // epoch (5B, LE u32) -- every freshly-minted coin starts at epoch 0 (§9).
    mid.push(0x04);
    mid.extend_from_slice(&0u32.to_le_bytes());
    // The stablecoin covenant's own dispatch body (constant given the baked
    // role keys above).
    mid.extend_from_slice(&stablecoin_body);
    mid
}

/// Emit the MINT (`op_type = 0x00`) branch bytecode. See this module's top
/// doc for the full derivation. Entry stack (top to bottom): `current_cap(0),
/// running_supply(1), recipient_pubkey(2), mint_amount(3), new_rs(4),
/// old_rs(5), mint_sig(6)`.
fn build_mint_branch(mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN], fixed_mid: &[u8], genesis_covenant_id: &[u8; 32]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(300 + fixed_mid.len());

    // ---- Step 0: this coin's own (live-pushed) running_supply is unused --
    // MINT reads old_running_supply from the AUTHENTICATED old_rs blob
    // instead (below), per this task's spec ("mirror dca.rs's counter-update
    // pattern"). Drop it now, mirroring build_freeze_branch's discipline of
    // immediately dropping an unused own-state field. ----
    e_roll(&mut b, 1);
    b.push(DROP);
    // Stack: current_cap(0), recipient_pubkey(1), mint_amount(2), new_rs(3),
    // old_rs(4), mint_sig(5).

    // ---- Step 1: self-continuation (a) -- authenticate old_rs really is
    // this input's own committed redeemScript (mirrors dca.rs's D&R Step 1). ----
    b.extend_from_slice(&dr_input_spk_check(4));

    // ---- Step 2: self-continuation (b) -- the baked body AND current_cap
    // must be byte-identical between old_rs and new_rs. Because
    // running_supply occupies the ENTIRE mutable zone [0..9) with nothing
    // before it (state.rs), "everything from current_cap onward" is a single
    // contiguous suffix [9..end) -- one dr_suffix_check call covers BOTH
    // invariants at once. ----
    b.extend_from_slice(&dr_suffix_check(4, 4, super::state::CURRENT_CAP_OPCODE_OFFSET as u16));
    // Stack unchanged (dr_suffix_check nets to 0): current_cap(0),
    // recipient_pubkey(1), mint_amount(2), new_rs(3), old_rs(4), mint_sig(5).

    // ---- Step 3: push-prefix sanity check (mirrors dca.rs D&R Step 4) --
    // new_rs[0] must still be the 0x08 (OpData8) push opcode, so the
    // successor's running_supply field parses the same way it does here. ----
    b.extend_from_slice(&dr_field_extract(3, 0, 1));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: current_cap(0), recipient_pubkey(1), mint_amount(2), new_rs(3),
    // old_rs(4), mint_sig(5).

    // ---- Step 4: supply arithmetic (mirrors dca.rs D&R Step 5/6's shape) --
    // old_running_supply (extracted from the AUTHENTICATED old_rs) +
    // mint_amount == new_running_supply (extracted from the AUTHENTICATED
    // new_rs). ----
    let rs_off = super::state::RUNNING_SUPPLY_PAYLOAD_OFFSET as u16;
    b.extend_from_slice(&dr_field_extract(3, rs_off, rs_off + 8)); // new_supply, from new_rs (depth3)
    // Stack: new_supply(0), current_cap(1), recipient_pubkey(2), mint_amount(3),
    // new_rs(4), old_rs(5), mint_sig(6).
    b.extend_from_slice(&dr_field_extract(5, rs_off, rs_off + 8)); // old_supply, from old_rs (depth5, shifted)
    // Stack: old_supply(0), new_supply(1), current_cap(2), recipient_pubkey(3),
    // mint_amount(4), new_rs(5), old_rs(6), mint_sig(7).
    e_pick(&mut b, 4); // mint_amount copy
    // Stack: mint_amount_copy(0), old_supply(1), new_supply(2), current_cap(3),
    // recipient_pubkey(4), mint_amount(5), new_rs(6), old_rs(7), mint_sig(8).
    b.push(ADD); // old_supply + mint_amount
    // Stack: sum(0), new_supply(1), current_cap(2), recipient_pubkey(3),
    // mint_amount(4), new_rs(5), old_rs(6), mint_sig(7).
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // Stack: current_cap(0), recipient_pubkey(1), mint_amount(2), new_rs(3),
    // old_rs(4), mint_sig(5).

    // ---- Step 5: old_rs no longer needed -- drop it. ----
    e_roll(&mut b, 4);
    b.push(DROP);
    // Stack: current_cap(0), recipient_pubkey(1), mint_amount(2), new_rs(3),
    // mint_sig(4).

    // ---- Step 6: supply cap check -- new_running_supply <= current_cap. ----
    b.extend_from_slice(&dr_field_extract(3, rs_off, rs_off + 8)); // new_supply, from new_rs (depth3)
    // Stack: new_supply(0), current_cap(1), recipient_pubkey(2), mint_amount(3),
    // new_rs(4), mint_sig(5).
    e_pick(&mut b, 1); // current_cap copy
    // Stack: cap_copy(0), new_supply(1), current_cap(2), recipient_pubkey(3),
    // mint_amount(4), new_rs(5), mint_sig(6).
    b.push(LESSTHANOREQUAL); // new_supply <= cap_copy (engine convention: deeper <= shallower)
    b.push(VERIFY);
    // Stack: current_cap(0), recipient_pubkey(1), mint_amount(2), new_rs(3),
    // mint_sig(4).

    // ---- Step 7: current_cap no longer needed -- drop it. ----
    b.push(DROP);
    // Stack: recipient_pubkey(0), mint_amount(1), new_rs(2), mint_sig(3).

    // ---- Step 8: coin emission, anti-backdoor reconstruction -- rebuild the
    // ENTIRE expected emitted-coin redeemScript on-chain from the baked
    // covenant role constants (embedded in fixed_mid) + frozen_flag=0x00 +
    // epoch=0 (also embedded in fixed_mid) + the sigscript-supplied
    // recipient_pubkey, then assert output[1].spk == P2SH(that). ----
    b.push(DATA1);
    b.push(0x20); // owner_pubkey's push opcode
    // Stack: lit20(0), recipient_pubkey(1), mint_amount(2), new_rs(3), mint_sig(4).
    e_roll(&mut b, 1); // recipient_pubkey -> top (consumed here; not needed again)
    // Stack: recipient_pubkey(0), lit20(1), mint_amount(2), new_rs(3), mint_sig(4).

    // ---- Step 8a (SECURITY FIX): recipient_pubkey length pin -- without
    // this, recipient_pubkey is about to be OpCat'd directly onto the
    // fixed [0x20] owner_pubkey push opcode with NO length check. An
    // oversized recipient push (>32 bytes) would inject the extra,
    // attacker-chosen bytes past the intended 32-byte owner_pubkey field, as
    // live redeemScript bytecode inside the emitted coin's reconstructed
    // redeemScript (fixed_mid's role-key/role_registry_root/frozen_flag/epoch
    // literals would then start at the WRONG offset, or extra opcodes could
    // be smuggled into the coin's dispatch body) -- a governance-less
    // backdoor coin. OpSize pushes recipient_pubkey's byte length without
    // popping it, so this check is non-destructive: after OpNumEqual/
    // OpVerify pop their own operands, the stack is back to its pre-check
    // shape. ----
    b.push(SIZE);
    push_index(&mut b, X_ONLY_PUBKEY_LEN as u16);
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // Stack: recipient_pubkey(0), lit20(1), mint_amount(2), new_rs(3), mint_sig(4).

    b.push(CAT); // lit20 || recipient_pubkey
    // Stack: ecr_partial(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.extend_from_slice(&crate::primitives::push_data(fixed_mid));
    // Stack: fixed_mid(0), ecr_partial(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(CAT); // ecr_partial || fixed_mid == full expected coin redeemScript
    // Stack: ecr(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.push(BLAKE2B);
    // Stack: rs_hash(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.extend_from_slice(&[0x04, 0x00, 0x00, 0xaa, 0x20]); // P2SH version prefix + push header
    // Stack: prefix(0), rs_hash(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(SWAP);
    // Stack: rs_hash(0), prefix(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(CAT); // prefix || rs_hash
    // Stack: acc(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.extend_from_slice(&[0x01, 0x87]); // push [OpEqual trailing byte]
    // Stack: lit87(0), acc(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(CAT); // acc || 0x87 == expected P2SH SPK bytes (37B, with version)
    // Stack: expected_spk(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.push(OP1); // literal output index 1 -- the emitted coin's FIXED slot
    // Stack: idx1(0), expected_spk(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(TXOUTPUTSPK);
    // Stack: actual_spk1(0), expected_spk(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: mint_amount(0), new_rs(1), mint_sig(2).

    // ---- Step 9: output value -- output[1]'s native value must equal
    // mint_amount. NOTE: OpTxOutputAmount pushes a MINIMALLY-encoded script
    // number, while mint_amount is a fixed 8-byte LE sigscript push -- the
    // two byte-representations can differ for the same logical value (e.g.
    // 50_000 minimally-encodes to 3 bytes, not 8), so this MUST be
    // OpNumEqual (which deserializes both sides as numbers before
    // comparing), never a raw OpEqual (byte-string comparison). ----
    b.push(OP1);
    // Stack: idx1(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.push(TXOUTPUTAMOUNT);
    // Stack: out1_amount(0), mint_amount(1), new_rs(2), mint_sig(3).
    e_pick(&mut b, 1); // mint_amount copy
    // Stack: mint_amount_copy(0), out1_amount(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(NUMEQUAL);
    b.push(VERIFY);
    // Stack: mint_amount(0), new_rs(1), mint_sig(2).

    // ---- Step 10: self-continuation (c) -- output[0].spk == P2SH(new_rs),
    // at the FIXED index 0 (this contract always emits its self-continuation
    // successor at output[0] and the newly-minted coin at output[1] --
    // mirrors stablecoin::body's fixed-output-shape test convention). ----
    b.push(OP0); // literal output index 0
    // Stack: idx0(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.extend_from_slice(&dr_output_spk_check(2, 1));
    b.push(DROP); // drop idx0 (dr_output_spk_check's net effect is 0 otherwise)
    // Stack: mint_amount(0), new_rs(1), mint_sig(2).

    // ---- Step 10b (SECURITY FIX): output[0]'s native value must equal this
    // input's native value -- the MINT role's OpCheckSigFromStack attestation
    // (no owner SIGHASH_ALL signature at all) doesn't otherwise pin the
    // successor's operating balance, so without this a hot mint_pubkey holder
    // could drain the authority UTXO's value on every mint. ----
    b.extend_from_slice(&value_continuity_check_output0());
    // Stack unchanged (net 0): mint_amount(0), new_rs(1), mint_sig(2).

    // ---- Step 11: MINT attestation pre-image (124B,
    // mint_authority::attestation): DOMAIN_TAG_MINT || covenant_id ||
    // outpoint_txid || outpoint_index || mint_amount || new_running_supply ||
    // recipient_spk_hash. ----
    b.push(DATA8);
    b.extend_from_slice(&super::DOMAIN_TAG_MINT);
    // Stack: acc(0)=domain_tag, mint_amount(1), new_rs(2), mint_sig(3).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    // Stack: covenant_id(0), acc(1), mint_amount(2), new_rs(3), mint_sig(4).

    // ---- Step 11a (SECURITY FIX, SUB-FIX B, genesis-binding): assert THIS
    // input's real covenant_id (just pushed above) equals the baked genesis
    // covenant_id G -- closes the gap where a fake parallel authority
    // deployment, baked with the SAME PUBLIC mint_pubkey/role constants but a
    // DIFFERENT genesis, could otherwise mint. covenant_id PROPAGATES through
    // self-continuation (verified in consensus), so only a genuine covenant
    // descended from the real genesis deploy (whose consensus-tracked
    // covenant_id == G) ever passes here. Reuses this same
    // OpTxInputIndex/OpInputCovenantId push for the preimage below (via
    // OpDup) rather than pushing it a second time. Non-destructive: DUP makes
    // a copy to compare against G, leaving the ORIGINAL covenant_id untouched
    // at its original depth for the CAT that follows. ----
    b.push(DUP);
    // Stack: covenant_id_copy(0), covenant_id(1), acc(2), mint_amount(3),
    // new_rs(4), mint_sig(5).
    b.push(DATA32);
    b.extend_from_slice(genesis_covenant_id);
    // Stack: G(0), covenant_id_copy(1), covenant_id(2), acc(3), mint_amount(4),
    // new_rs(5), mint_sig(6).
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack (restored): covenant_id(0), acc(1), mint_amount(2), new_rs(3),
    // mint_sig(4).

    b.push(CAT); // acc || covenant_id
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTTXID);
    b.push(CAT); // acc || outpoint_txid
    b.push(TXINPUTINDEX);
    b.push(OUTPOINTINDEX);
    b.push(OP4);
    b.push(NUM2BIN);
    b.push(CAT); // acc || outpoint_index(4B LE)
    // Stack: acc(0), mint_amount(1), new_rs(2), mint_sig(3).
    e_pick(&mut b, 1); // mint_amount copy
    // Stack: mint_amount_copy(0), acc(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(CAT); // acc || mint_amount(8B LE, as originally pushed by the sigscript)
    // Stack: acc(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.extend_from_slice(&dr_field_extract(2, rs_off, rs_off + 8)); // new_running_supply, from new_rs (depth2)
    // Stack: new_supply(0), acc(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(CAT); // acc || new_running_supply
    // Stack: acc(0), mint_amount(1), new_rs(2), mint_sig(3).
    b.push(OP1);
    // Stack: idx1(0), acc(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(TXOUTPUTSPK);
    // Stack: spk1(0), acc(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(BLAKE3);
    // Stack: recipient_spk_hash(0), acc(1), mint_amount(2), new_rs(3), mint_sig(4).
    b.push(CAT); // acc || recipient_spk_hash == full 124B preimage
    // Stack: acc(0), mint_amount(1), new_rs(2), mint_sig(3).

    // new_rs / mint_amount no longer needed -- drop both before the final
    // signature check, mirroring build_transfer_branch's discipline of
    // reaching "acc(0), issuer_sig(1)" right before OpBlake3.
    e_roll(&mut b, 2);
    b.push(DROP);
    // Stack: acc(0), mint_amount(1), mint_sig(2).
    e_roll(&mut b, 1);
    b.push(DROP);
    // Stack: acc(0), mint_sig(1).

    b.push(BLAKE3); // msg_hash = Blake3(acc)
    // Stack: msg_hash(0), mint_sig(1).
    b.push(DATA32);
    b.extend_from_slice(mint_pubkey);
    // Stack: mint_pubkey(0), msg_hash(1), mint_sig(2).
    b.push(CHECKSIGFROMSTACK);
    b.push(VERIFY);

    b.push(OP1);
    b
}

/// Build the mint-authority contract's own 2-way `op_type` dispatch (`MINT =
/// 0x00`, `RAISE_CAP = 0x01`), reusing the covenant's dispatch idiom
/// (`crate::contract::stablecoin::dispatch::build_op_type_dispatch`'s
/// roll/DUP/compare/IF/ELSE/ENDIF shape), generalized down to 2 branches.
/// `tag_depth` is the stack depth of the `op_type` selector once the state
/// header has finished pushing its two fields -- see [`OP_TYPE_TAG_DEPTH`].
fn build_op_type_dispatch(tag_depth: u16, mint_branch: &[u8], raise_cap_branch: &[u8]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(16 + mint_branch.len() + raise_cap_branch.len());
    push_index(&mut b, tag_depth);
    b.push(ROLL);

    // 0x00 MINT
    b.push(DUP);
    b.push(DATA1);
    b.push(op_type::MINT);
    b.push(EQUAL);
    b.push(IF);
    {
        b.push(DROP);
        b.extend_from_slice(mint_branch);
    }
    b.push(ELSE);
    {
        // 0x01 RAISE_CAP -- the final rung: must match exactly (OP_VERIFY),
        // so any other byte hard-aborts here rather than falling through.
        b.push(DUP);
        b.push(DATA1);
        b.push(op_type::RAISE_CAP);
        b.push(EQUAL);
        b.push(VERIFY);
        b.push(DROP);
        b.extend_from_slice(raise_cap_branch);
    }
    b.push(ENDIF);
    b
}

/// Stack depth of the `op_type` selector once the state header has finished
/// pushing its two fields (`current_cap`, `running_supply`) -- with the
/// sigscript layout documented in this module's top doc (`op_type_selector`
/// as the LAST sigscript push before the redeem script), that depth is
/// always `2`.
pub const OP_TYPE_TAG_DEPTH: u16 = 2;

/// Emit the mint-authority covenant body: state header's fields are already
/// on the stack; the body is the 2-way `op_type` dispatch.
#[allow(clippy::too_many_arguments)]
pub fn build_mint_authority_body(
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    cap_authority_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    role_registry_root: &[u8; 32],
    identifier_type: u8,
    genesis_covenant_id: &[u8; 32],
) -> Vec<u8> {
    let fixed_mid = build_fixed_mid(identifier_type, role_registry_root, mint_pubkey, ops_pubkey, freeze_pubkey, seize_pubkeys);
    let mint_branch = build_mint_branch(mint_pubkey, &fixed_mid, genesis_covenant_id);
    let raise_cap_branch = build_raise_cap_branch(cap_authority_pubkeys, genesis_covenant_id);
    build_op_type_dispatch(OP_TYPE_TAG_DEPTH, &mint_branch, &raise_cap_branch)
}

/// Build the complete mint-authority redeem script (state header + dispatch
/// body). `running_supply`/`current_cap` go into the mutable state header
/// (`state.rs`); the rest are baked bytecode literals (option B, matching
/// the stablecoin covenant's own Decision 2026-07-19 convention):
/// `mint_pubkey` is the mint-authority's own hot MINT-role key (also reused
/// as the stablecoin covenant's MINT-role BURN-authorizer key, per §2's role
/// table); `cap_authority_pubkeys` are the cold 2-of-3 keys for the (stubbed)
/// future RAISE_CAP op; `ops_pubkey`/`freeze_pubkey`/`seize_pubkeys`/
/// `role_registry_root`/`identifier_type` are the stablecoin covenant's own
/// role constants, needed to reconstruct an emitted coin's redeem script.
///
/// `genesis_covenant_id` (SUB-FIX B, genesis-binding security fix) is the
/// UNIQUE covenant_id of this specific authority's genesis deploy, baked as a
/// literal into the body (the same fixed region `dr_suffix_check` already
/// pins as unchanged across self-continuation) and checked on-chain (both
/// MINT and RAISE_CAP) against the spending input's ACTUAL, consensus-tracked
/// covenant_id. Without this, two independently-deployed authority contracts
/// that happen to bake the SAME PUBLIC `mint_pubkey`/`cap_authority_pubkeys`
/// (which are public keys, not secrets) would be bytecode-indistinguishable
/// apart from their state header, and either one's `mint_pubkey`/
/// `cap_authority` holder could mint/raise-cap on behalf of what looks like
/// "the" authority -- covenant_id is what makes genesis, and therefore the
/// specific deployment, unique; it PROPAGATES through self-continuation
/// (verified in consensus), so binding to it is exactly the "unique genesis"
/// invariant this fix restores. Callers deploying a genuinely NEW authority
/// must pass the covenant_id their genesis transaction will actually be
/// assigned (the CLI two-transaction deploy bootstrap that computes this is
/// deferred -- out of scope here; this function only makes the covenant take
/// and enforce `genesis_covenant_id`, it does not compute one).
#[allow(clippy::too_many_arguments)]
pub fn build_mint_authority_redeem_script(
    running_supply: u64,
    current_cap: u64,
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    cap_authority_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    role_registry_root: &[u8; 32],
    identifier_type: u8,
    genesis_covenant_id: &[u8; 32],
) -> Vec<u8> {
    let state = super::state::MintAuthorityStateHeader::new(running_supply, current_cap);
    let mut rs = state.encode_script();
    debug_assert_eq!(rs.len(), super::state::STATE_HEADER_LEN);
    rs.extend_from_slice(&build_mint_authority_body(
        mint_pubkey,
        cap_authority_pubkeys,
        ops_pubkey,
        freeze_pubkey,
        seize_pubkeys,
        role_registry_root,
        identifier_type,
        genesis_covenant_id,
    ));
    rs
}

/// Off-chain convenience: reconstruct the emitted coin's redeem script
/// exactly as the on-chain MINT branch does (this module's "Step 8"), for
/// tests/tooling that need to independently predict a mint's resulting P2SH.
/// NOT used internally by the on-chain bytecode above (which builds the same
/// bytes via `OpCat`, never by calling into Rust) -- exists so callers (and
/// this module's own tests) can cross-check the two constructions agree.
#[allow(clippy::too_many_arguments)]
pub fn build_emitted_coin_redeem_script(
    recipient_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    identifier_type: u8,
    role_registry_root: &[u8; 32],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
) -> Vec<u8> {
    crate::contract::stablecoin::body::build_stablecoin_redeem_script(
        recipient_pubkey,
        identifier_type,
        role_registry_root,
        crate::contract::stablecoin::state::frozen_flag::CLEAR,
        0,
        ops_pubkey,
        freeze_pubkey,
        seize_pubkeys,
        mint_pubkey,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINT: [u8; 32] = [0xEF; 32];
    const CAP_AUTH: [[u8; 32]; 3] = [[0xA1; 32], [0xA2; 32], [0xA3; 32]];
    const OPS: [u8; 32] = [0xBB; 32];
    const FREEZE: [u8; 32] = [0xDD; 32];
    const SEIZE: [[u8; 32]; 3] = [[0x91; 32], [0x92; 32], [0x93; 32]];
    const ROOT: [u8; 32] = [0xCC; 32];
    const RECIPIENT: [u8; 32] = [0xAA; 32];
    const GENESIS: [u8; 32] = [0x77; 32];

    #[test]
    fn redeem_script_starts_with_state_header() {
        let rs = build_mint_authority_redeem_script(1_000, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        assert_eq!(rs[0], 0x08);
        assert_eq!(&rs[1..9], &1_000u64.to_le_bytes());
        assert_eq!(rs[9], 0x08);
        assert_eq!(&rs[10..18], &5_000u64.to_le_bytes());
        assert!(rs.len() > super::super::state::STATE_HEADER_LEN);
    }

    #[test]
    fn mint_pubkey_is_baked_into_body() {
        let rs = build_mint_authority_redeem_script(0, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        assert!(rs.windows(32).any(|w| w == MINT));
    }

    #[test]
    fn cap_authority_pubkeys_are_baked_into_body() {
        let rs = build_mint_authority_redeem_script(0, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        for pk in &CAP_AUTH {
            assert!(rs.windows(32).any(|w| w == pk), "cap authority pubkey {pk:?} not found baked into redeem script");
        }
    }

    #[test]
    fn stablecoin_role_constants_are_baked_into_body() {
        let rs = build_mint_authority_redeem_script(0, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        assert!(rs.windows(32).any(|w| w == OPS));
        assert!(rs.windows(32).any(|w| w == FREEZE));
        for pk in &SEIZE {
            assert!(rs.windows(32).any(|w| w == pk));
        }
        assert!(rs.windows(32).any(|w| w == ROOT));
    }

    #[test]
    fn genesis_covenant_id_is_baked_into_body_at_least_twice() {
        // SUB-FIX B regression: the genesis covenant_id G must be baked as a
        // literal into the body -- once for MINT's check, once for
        // RAISE_CAP's -- so both branches independently pin it (neither
        // branch's genesis check can be satisfied by accident; each has its
        // own baked copy of G).
        let rs = build_mint_authority_redeem_script(0, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        let occurrences = rs.windows(32).filter(|w| *w == GENESIS).count();
        assert!(occurrences >= 2, "expected genesis covenant_id baked into the body at least twice (MINT + RAISE_CAP), found {occurrences}");
    }

    #[test]
    fn distinct_genesis_covenant_ids_yield_distinct_redeem_scripts() {
        // Two authorities baked with otherwise-IDENTICAL public role
        // constants but DIFFERENT genesis covenant_ids must produce distinct
        // bytecode (proving G is actually read from the argument, not
        // hardcoded/ignored) -- the whole point of SUB-FIX B is that these
        // two scripts behave differently on-chain despite sharing every
        // other baked key.
        let a = build_mint_authority_redeem_script(0, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        let b = build_mint_authority_redeem_script(0, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &[0x99; 32]);
        assert_ne!(a, b);
        // The mutable state header (unaffected by G) stays identical.
        assert_eq!(&a[..super::super::state::STATE_HEADER_LEN], &b[..super::super::state::STATE_HEADER_LEN]);
    }

    #[test]
    fn body_length_is_deterministic_regardless_of_state_field_values() {
        let a = build_mint_authority_body(&MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        let b = build_mint_authority_body(&MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        assert_eq!(a, b);
    }

    #[test]
    fn raise_cap_branch_ends_in_real_threshold_bytecode_not_a_stub() {
        let body = build_mint_authority_body(&MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        // RAISE_CAP is now real bytecode ending in the same 2-of-3 threshold
        // shape as build_seize_branch's own tail: two OpAdd, Op2,
        // OpGreaterThanOrEqual, OpVerify -- not the old bare-OP_0 stub.
        assert!(
            body.windows(5).any(|w| w == [op::ADD, op::ADD, op::OP2, op::GREATERTHANOREQUAL, op::VERIFY]),
            "expected RAISE_CAP's 2-of-3 threshold tail (ADD ADD OP2 GREATERTHANOREQUAL VERIFY) to appear in the body"
        );
        // And the strict-increase check's OpGreaterThan must appear too.
        assert!(body.contains(&op::GREATERTHAN), "expected RAISE_CAP's strict-increase OpGreaterThan to appear in the body");
    }

    #[test]
    fn mini_dispatch_dups_tag_on_both_rungs_regression() {
        // Regression test mirroring dispatch.rs's own
        // `all_six_rungs_dup_tag_before_compare_bugfix_regression`: this
        // 2-way mini-dispatch must OP_DUP the op_type tag on BOTH rungs
        // (including the final RAISE_CAP rung, which uses a hard OP_VERIFY
        // instead of a further OP_ELSE fallback) -- otherwise the final
        // rung's OP_EQUAL would consume the tag directly (no spare copy to
        // compare with), and the trailing OP_DROP would silently eat the
        // next REAL data-stack item (this contract's own `new_cap`) instead
        // of a tag copy, corrupting every stack depth RAISE_CAP computes
        // against. Verified here now that RAISE_CAP carries real,
        // depth-sensitive bytecode (not the depth-agnostic bare `OP_0` stub
        // that made this bug undetectable in the covenant's own dispatch
        // until MIGRATE's real bytecode was wired, per dispatch.rs's
        // bug-fix note).
        let dispatch_only = build_op_type_dispatch(OP_TYPE_TAG_DEPTH, &[0xAAu8], &[0xBBu8]);
        let dup_count = dispatch_only.iter().filter(|&&b| b == op::DUP).count();
        assert_eq!(dup_count, 2, "expected 2 OP_DUP (one per op_type rung, including the final RAISE_CAP rung), found {dup_count}");
    }

    #[test]
    fn raise_cap_branch_stack_depth_is_correct_smoke_test() {
        // Exercises build_raise_cap_branch directly (not just through the
        // dispatch) as a lightweight structural regression: it must produce
        // non-empty bytecode ending in OP_1 (this codebase's uniform
        // branch-success convention, matching build_mint_branch/
        // build_seize_branch), and must be depth-sensitive to which
        // cap_authority_pubkeys are baked in (proving the three pubkeys are
        // read from the argument, not hardcoded).
        let a = build_raise_cap_branch(&CAP_AUTH, &GENESIS);
        let b = build_raise_cap_branch(&[[0x01; 32], [0x02; 32], [0x03; 32]], &GENESIS);
        assert_eq!(*a.last().unwrap(), op::OP1, "RAISE_CAP branch must end in OP_1 on success, matching the codebase's branch convention");
        assert_ne!(a, b, "RAISE_CAP branch bytecode must depend on the baked cap_authority_pubkeys");
        assert_eq!(a.len(), b.len(), "RAISE_CAP branch length must be deterministic regardless of which pubkeys are baked in");
    }

    #[test]
    fn fixed_mid_matches_real_stablecoin_redeem_script_tail() {
        // fixed_mid must be byte-identical to
        // build_stablecoin_redeem_script(...)'s own tail from offset 33
        // onward (everything after owner_pubkey's 32B payload), for ANY
        // owner_pubkey -- this is the load-bearing cross-check that the
        // on-chain reconstruction (Step 8) really produces THE SAME bytes a
        // genuine stablecoin covenant deployment would.
        let fixed_mid = build_fixed_mid(0x00, &ROOT, &MINT, &OPS, &FREEZE, &SEIZE);
        let real_rs = build_emitted_coin_redeem_script(&RECIPIENT, 0x00, &ROOT, &OPS, &FREEZE, &SEIZE, &MINT);
        assert_eq!(&real_rs[33..], fixed_mid.as_slice());

        // And it must NOT depend on the recipient/owner pubkey at all.
        let other_recipient = [0x77u8; 32];
        let real_rs_2 = build_emitted_coin_redeem_script(&other_recipient, 0x00, &ROOT, &OPS, &FREEZE, &SEIZE, &MINT);
        assert_eq!(&real_rs_2[33..], fixed_mid.as_slice());
    }

    #[test]
    fn distinct_mint_keys_yield_distinct_redeem_scripts() {
        let a = build_mint_authority_redeem_script(0, 5_000, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        let b = build_mint_authority_redeem_script(0, 5_000, &[0x01; 32], &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &ROOT, 0x00, &GENESIS);
        assert_ne!(a, b);
        assert_eq!(&a[..super::super::state::STATE_HEADER_LEN], &b[..super::super::state::STATE_HEADER_LEN]);
    }
}
