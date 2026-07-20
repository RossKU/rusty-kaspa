//! Mint-authority contract — bytecode body (`STABLECOIN_ROBUST_DESIGN.md` §9
//! "Mint + Supply Cap", extended 2026-07-20 by the mint-authority hardening
//! item: G4 ANNOUNCE_CAP ceiling+timelock via ACTIVATE_CAP, G5 MINT epoch
//! budget+dust floor). All three mini-dispatch operations are wired: `MINT`
//! (`op_type 0x00`, [`build_mint_branch`]), `ANNOUNCE_CAP` (`op_type 0x01`,
//! renamed from `RAISE_CAP`, [`build_announce_cap_branch`]), and
//! `ACTIVATE_CAP` (`op_type 0x02`, new, [`build_activate_cap_branch`]).
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
//!   check), MINT's mutable fields (`running_supply`/`minted_this_epoch`/
//!   `epoch_start_daa`, G5) are placed FIRST as one contiguous run
//!   (`state.rs`), so "everything from `current_cap` onward" is ONE
//!   contiguous suffix — a single [`dr_suffix_check`] call covers both
//!   "`current_cap`/`pending_cap` unchanged" and "the entire baked body
//!   unchanged". ANNOUNCE_CAP/ACTIVATE_CAP (G4) mirror this same
//!   field-ownership-driven layout for their own mutated regions — see
//!   `state.rs`'s module doc for the full table.
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
//! `state (54B, see state.rs) || body`. The body is a 3-way `op_type`
//! dispatch: `0x00 MINT` / `0x01 ANNOUNCE_CAP` / `0x02 ACTIVATE_CAP`, all
//! real bytecode; the cold `cap_authority_pubkeys` are baked into the
//! ANNOUNCE_CAP branch.
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
//! State header pushes 6 fields (`state.rs`'s "own state" pushes are always
//! `pending_since_daa` on top since it's pushed LAST), then the dispatch
//! consumes+drops the `op_type` selector:
//!
//! ```text
//! pending_since_daa(0), pending_cap(1), current_cap(2), epoch_start_daa(3),
//! minted_this_epoch(4), running_supply(5), recipient_pubkey(6),
//! mint_amount(7), new_rs(8), old_rs(9), mint_sig(10)
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
    pub const NOT: u8 = 0x91;
    pub const ADD: u8 = 0x93;
    pub const MUL: u8 = 0x95;
    pub const NUMEQUAL: u8 = 0x9c;
    pub const NUMEQUALVERIFY: u8 = 0x9d;
    pub const GREATERTHAN: u8 = 0xa0;
    pub const LESSTHANOREQUAL: u8 = 0xa1;
    pub const GREATERTHANOREQUAL: u8 = 0xa2;
    pub const BLAKE2B: u8 = 0xaa;
    pub const CHECKSEQUENCEVERIFY: u8 = 0xb1;
    pub const TXINPUTINDEX: u8 = 0xb9;
    pub const OUTPOINTTXID: u8 = 0xba;
    pub const OUTPOINTINDEX: u8 = 0xbb;
    pub const TXINPUTAMOUNT: u8 = 0xbe;
    pub const TXINPUTDAASCORE: u8 = 0xc0;
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

/// B.3 dust floor (2026-07-20 mint-authority hardening, Stage 1): assert
/// `mint_amount >= MIN_MINT_AMOUNT` (the existing off-chain-only constant,
/// `attestation::MIN_MINT_AMOUNT`, promoted on-chain as a baked literal --
/// no new constructor param). Non-destructive: pick(+1) + push(+1) -
/// GreaterThanOrEqual(-1) - Verify(-1) nets to 0, so this may be spliced in
/// anywhere `mint_amount_depth` is known without adjusting any other op's
/// depth argument.
fn dust_floor_check(mint_amount_depth: u16) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(14);
    e_pick(&mut b, mint_amount_depth); // mint_amount copy -> top
    b.push(DATA8);
    b.extend_from_slice(&super::attestation::MIN_MINT_AMOUNT.to_le_bytes());
    b.push(GREATERTHANOREQUAL); // mint_amount_copy >= MIN_MINT_AMOUNT (deeper >= shallower)
    b.push(VERIFY);
    b
}

/// B.1 MINT epoch budget (2026-07-20 mint-authority hardening, Stage 2):
/// self-contained block enforcing `state.rs`'s G5 epoch-budget invariant.
///
/// # Precondition (exact stack shape this block assumes, top-to-bottom)
///
/// ```text
/// current_cap(0), epoch_start_daa(1), minted_this_epoch(2),
/// recipient_pubkey(3), mint_amount(4), new_rs(5), old_rs(6), mint_sig(7)
/// ```
///
/// `epoch_start_daa`/`minted_this_epoch` are this coin's own LIVE state-header
/// pushes (trustworthy without a separate `dr_input_spk_check`-style
/// re-authentication: they are literal bytes of the currently-EXECUTING
/// redeem script, which is exactly what a P2SH commitment already pins --
/// the same shortcut `build_mint_branch`'s pre-existing Step 6 already takes
/// for `current_cap`).
///
/// # Postcondition
///
/// Restores the stack to EXACTLY the shape `build_mint_branch` had before
/// the G5 feature existed (`current_cap(0), recipient_pubkey(1),
/// mint_amount(2), new_rs(3), old_rs(4), mint_sig(5)`) -- i.e. it doesn't
/// just net to 0 extra items, it also consumes the 2 live fields it owns
/// (`epoch_start_daa`, `minted_this_epoch`), so every downstream step
/// (supply arithmetic, cap check, coin emission, attestation) needs ZERO
/// depth-argument changes.
///
/// # Logic (`state.rs`'s G5 invariant)
///
/// ```text
/// now       = this input's UTXO entry's block_daa_score (OpTxInputDaaScore)
/// boundary  = epoch_start_daa + epoch_length_daa
/// crossed   = boundary <= now                                    (0 or 1)
/// new_minted_this_epoch = minted_this_epoch * (1 - crossed) + mint_amount
/// assert new_minted_this_epoch <= epoch_mint_budget
/// new_epoch_start_daa    = crossed * now + (1 - crossed) * epoch_start_daa
/// assert successor's minted_this_epoch == new_minted_this_epoch  (NumEqualVerify --
///   these are ARITHMETIC RESULTS, not raw fixed-8-byte pushes, so unlike
///   the raw-byte OpEqual comparisons elsewhere in this file they may not be
///   exactly 8 bytes wide; OpNumEqualVerify deserializes both sides as
///   script numbers before comparing, exactly like MINT's pre-existing
///   supply-arithmetic OpNumEqual/OpVerify pair)
/// assert successor's epoch_start_daa == new_epoch_start_daa       (ditto)
/// ```
fn epoch_budget_block(epoch_length_daa: u64, epoch_mint_budget: u64) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(220);

    // ==== crossed = (epoch_start_daa + epoch_length_daa) <= now ====

    // -- now1 = OpTxInputIndex OpTxInputDaaScore --
    b.push(TXINPUTINDEX);
    b.push(TXINPUTDAASCORE);
    // Stack: now1(0), current_cap(1), epoch_start_daa(2), minted_this_epoch(3),
    // recipient_pubkey(4), mint_amount(5), new_rs(6), old_rs(7), mint_sig(8).

    // -- boundary = epoch_start_daa + epoch_length_daa --
    e_pick(&mut b, 2); // epoch_start_daa copy -> top
    // Stack: esd_copy(0), now1(1), current_cap(2), epoch_start_daa(3), ...
    b.push(DATA8);
    b.extend_from_slice(&epoch_length_daa.to_le_bytes());
    // Stack: eld(0), esd_copy(1), now1(2), current_cap(3), epoch_start_daa(4), ...
    b.push(ADD); // boundary = esd_copy + eld
    // Stack: boundary(0), now1(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).

    // -- crossed = boundary <= now1 (need boundary DEEPER, now1 SHALLOWER
    // for OpLessThanOrEqual's "deeper <= shallower" convention) --
    b.push(SWAP);
    // Stack: now1(0), boundary(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).
    b.push(LESSTHANOREQUAL); // boundary(deeper) <= now1(shallower) = crossed
    // Stack: crossed(0), current_cap(1), epoch_start_daa(2), minted_this_epoch(3),
    // recipient_pubkey(4), mint_amount(5), new_rs(6), old_rs(7), mint_sig(8).

    // ==== new_minted_this_epoch = minted_this_epoch * (1 - crossed) + mint_amount ====

    e_pick(&mut b, 0); // crossed copy -> top
    // Stack: crossed_copy(0), crossed(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).
    b.push(NOT); // not_crossed = !crossed_copy
    // Stack: not_crossed(0), crossed(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).
    e_pick(&mut b, 4); // minted_this_epoch copy -> top
    // Stack: mte_copy(0), not_crossed(1), crossed(2), current_cap(3),
    // epoch_start_daa(4), minted_this_epoch(5), recipient_pubkey(6),
    // mint_amount(7), new_rs(8), old_rs(9), mint_sig(10).
    b.push(MUL); // partial1 = not_crossed * mte_copy
    // Stack: partial1(0), crossed(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).
    e_pick(&mut b, 6); // mint_amount copy -> top
    // Stack: ma_copy(0), partial1(1), crossed(2), current_cap(3),
    // epoch_start_daa(4), minted_this_epoch(5), recipient_pubkey(6),
    // mint_amount(7), new_rs(8), old_rs(9), mint_sig(10).
    b.push(ADD); // new_minted = partial1 + ma_copy
    // Stack: new_minted(0), crossed(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).

    // ==== assert new_minted_this_epoch <= epoch_mint_budget ====

    e_pick(&mut b, 0); // new_minted copy -> top
    // Stack: new_minted_copy(0), new_minted(1), crossed(2), current_cap(3), ...
    b.push(DATA8);
    b.extend_from_slice(&epoch_mint_budget.to_le_bytes());
    // Stack: emb(0), new_minted_copy(1), new_minted(2), crossed(3), ...
    b.push(LESSTHANOREQUAL); // new_minted_copy(deeper) <= emb(shallower)
    b.push(VERIFY);
    // Stack: new_minted(0), crossed(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).

    // ==== new_epoch_start_daa = crossed * now + (1 - crossed) * epoch_start_daa ====

    b.push(TXINPUTINDEX);
    b.push(TXINPUTDAASCORE); // now2 (recomputed fresh -- now1 was already consumed above)
    // Stack: now2(0), new_minted(1), crossed(2), current_cap(3), epoch_start_daa(4),
    // minted_this_epoch(5), recipient_pubkey(6), mint_amount(7), new_rs(8),
    // old_rs(9), mint_sig(10).
    e_pick(&mut b, 2); // crossed copy -> top
    // Stack: crossed_copy(0), now2(1), new_minted(2), crossed(3), current_cap(4),
    // epoch_start_daa(5), minted_this_epoch(6), recipient_pubkey(7),
    // mint_amount(8), new_rs(9), old_rs(10), mint_sig(11).
    b.push(MUL); // term1 = now2 * crossed_copy
    // Stack: term1(0), new_minted(1), crossed(2), current_cap(3), epoch_start_daa(4),
    // minted_this_epoch(5), recipient_pubkey(6), mint_amount(7), new_rs(8),
    // old_rs(9), mint_sig(10).
    e_pick(&mut b, 2); // crossed copy (again) -> top
    // Stack: crossed_copy2(0), term1(1), new_minted(2), crossed(3), current_cap(4), ...
    b.push(NOT); // not_crossed2 = !crossed_copy2
    // Stack: not_crossed2(0), term1(1), new_minted(2), crossed(3), current_cap(4),
    // epoch_start_daa(5), minted_this_epoch(6), recipient_pubkey(7),
    // mint_amount(8), new_rs(9), old_rs(10), mint_sig(11).
    e_pick(&mut b, 5); // epoch_start_daa copy -> top
    // Stack: esd_copy2(0), not_crossed2(1), term1(2), new_minted(3), crossed(4),
    // current_cap(5), epoch_start_daa(6), minted_this_epoch(7), recipient_pubkey(8),
    // mint_amount(9), new_rs(10), old_rs(11), mint_sig(12).
    b.push(MUL); // term2 = not_crossed2 * esd_copy2
    // Stack: term2(0), term1(1), new_minted(2), crossed(3), current_cap(4),
    // epoch_start_daa(5), minted_this_epoch(6), recipient_pubkey(7),
    // mint_amount(8), new_rs(9), old_rs(10), mint_sig(11).
    b.push(ADD); // new_epoch_start = term1 + term2
    // Stack: new_epoch_start(0), new_minted(1), crossed(2), current_cap(3),
    // epoch_start_daa(4), minted_this_epoch(5), recipient_pubkey(6),
    // mint_amount(7), new_rs(8), old_rs(9), mint_sig(10).

    // ==== verify successor's minted_this_epoch/epoch_start_daa match ====

    // new_rs is currently at depth8.
    b.extend_from_slice(&dr_field_extract(8, super::state::MINTED_THIS_EPOCH_PAYLOAD_OFFSET as u16, (super::state::MINTED_THIS_EPOCH_PAYLOAD_OFFSET + 8) as u16));
    // Stack: succ_mte(0), new_epoch_start(1), new_minted(2), crossed(3), current_cap(4),
    // epoch_start_daa(5), minted_this_epoch(6), recipient_pubkey(7),
    // mint_amount(8), new_rs(9), old_rs(10), mint_sig(11).
    e_roll(&mut b, 2); // bring new_minted to top (adjacent to succ_mte)
    // Stack: new_minted(0), succ_mte(1), new_epoch_start(2), crossed(3), current_cap(4),
    // epoch_start_daa(5), minted_this_epoch(6), recipient_pubkey(7),
    // mint_amount(8), new_rs(9), old_rs(10), mint_sig(11).
    b.push(NUMEQUALVERIFY);
    // Stack: new_epoch_start(0), crossed(1), current_cap(2), epoch_start_daa(3),
    // minted_this_epoch(4), recipient_pubkey(5), mint_amount(6), new_rs(7),
    // old_rs(8), mint_sig(9).

    // new_rs is now at depth7.
    b.extend_from_slice(&dr_field_extract(7, super::state::EPOCH_START_DAA_PAYLOAD_OFFSET as u16, (super::state::EPOCH_START_DAA_PAYLOAD_OFFSET + 8) as u16));
    // Stack: succ_esd(0), new_epoch_start(1), crossed(2), current_cap(3), epoch_start_daa(4),
    // minted_this_epoch(5), recipient_pubkey(6), mint_amount(7), new_rs(8),
    // old_rs(9), mint_sig(10).
    b.push(NUMEQUALVERIFY); // succ_esd(top) vs new_epoch_start(depth1) -- already adjacent
    // Stack: crossed(0), current_cap(1), epoch_start_daa(2), minted_this_epoch(3),
    // recipient_pubkey(4), mint_amount(5), new_rs(6), old_rs(7), mint_sig(8).

    // ==== restore the pre-G5 stack shape: drop crossed, epoch_start_daa,
    // minted_this_epoch (nothing downstream needs them again) ====
    b.push(DROP); // crossed
    // Stack: current_cap(0), epoch_start_daa(1), minted_this_epoch(2),
    // recipient_pubkey(3), mint_amount(4), new_rs(5), old_rs(6), mint_sig(7).
    e_roll(&mut b, 1);
    b.push(DROP); // removes the item now at depth1 (epoch_start_daa)
    // Stack: current_cap(0), minted_this_epoch(1), recipient_pubkey(2),
    // mint_amount(3), new_rs(4), old_rs(5), mint_sig(6).
    e_roll(&mut b, 1);
    b.push(DROP); // removes the item now at depth1 (minted_this_epoch)
    // Stack: current_cap(0), recipient_pubkey(1), mint_amount(2), new_rs(3),
    // old_rs(4), mint_sig(5). <- EXACTLY the pre-G5 MINT branch shape.

    b
}

/// Emit the `ANNOUNCE_CAP` (`op_type = 0x01`, renamed 2026-07-20 from
/// `RAISE_CAP`) branch bytecode (`STABLECOIN_ROBUST_DESIGN.md` §9 + G4
/// hardening: authorized by cold 2-of-3 `cap_authority`, self-continue with
/// `pending_cap' = new_pending_cap` where `OpVerify(new_pending_cap >
/// current_cap)` AND `OpVerify(new_pending_cap <= current_cap *
/// cap_raise_multiplier_k)`, AND `pending_since_daa' = OpTxInputDaaScore`
/// (FIX 1, 2026-07-20 timelock-griefing hardening: stamps WHEN this
/// announcement happened, in state, so a later interleaved MINT cannot reset
/// `ACTIVATE_CAP`'s timelock clock) -- `running_supply`/`minted_this_epoch`/
/// `epoch_start_daa`/`current_cap` all unchanged in the successor; no coin
/// emitted). `current_cap` itself is NOT touched here -- only
/// `ACTIVATE_CAP` (below), gated by the state-anchored timelock, promotes
/// `pending_cap` into it.
///
/// # What is mirrored from where
///
/// - **Authorization**: the SAME fixed-position 2-of-3 `OpCheckSigFromStack`
///   threshold idiom as [`crate::contract::stablecoin::body::build_seize_branch`]
///   (three checks, `bool1`/`bool2`/`bool3` summed via two `OpAdd`s, compared
///   `>= 2` via `OpGreaterThanOrEqual OpVerify`) — over the baked
///   `cap_authority_pubkeys`, structurally identical in strength to that
///   covenant's SEIZE quorum.
/// - **Self-continuation D&R shape**: the SAME `crate::contract::dr` helpers
///   [`build_mint_branch`] uses (`dr_input_spk_check`/`dr_field_extract`),
///   but with the mutable/fixed regions SWAPPED relative to MINT: MINT's
///   mutable prefix is `[0..27)` (`running_supply`/`minted_this_epoch`/
///   `epoch_start_daa`) with `current_cap`+`pending_cap`+`pending_since_daa`+
///   the baked body carried forward as one contiguous suffix `[27..end)`.
///   ANNOUNCE_CAP mutates only the TRAILING PAIR `pending_cap`+
///   `pending_since_daa` instead, so it needs BOTH a [`dr_prefix_check`] over
///   `[0..36)` (everything up through `current_cap` — UNCHANGED) AND a
///   [`dr_suffix_check`] over `[STATE_HEADER_LEN..end)` (the baked body
///   UNCHANGED), leaving exactly the `pending_cap`+`pending_since_daa` byte
///   range `[36..54)` uncovered by either check — the one region this branch
///   is allowed, and required, to change (the same prefix+suffix-leaves-a-gap
///   shape the pre-2026-07-20 RAISE_CAP branch already used for
///   `current_cap`, just with the gap moved to the new layout's trailing
///   fields).
///
/// # Entry stack once the dispatch delivers control to the ANNOUNCE_CAP branch
///
/// State header pushes 6 fields (`state.rs`), then the dispatch
/// consumes+drops the `op_type` selector:
///
/// ```text
/// pending_since_daa(0), pending_cap(1), current_cap(2), epoch_start_daa(3),
/// minted_this_epoch(4), running_supply(5), new_pending_cap(6), new_rs(7),
/// old_rs(8), sig3(9), sig2(10), sig1(11)
/// ```
///
/// This is the sigscript layout callers must produce (push order,
/// first==deepest): `sig1, sig2, sig3, old_rs, new_rs,
/// new_pending_cap(8B LE), op_type_selector(0x01)`, then the redeem script.
/// This input's `sig_op_count` MUST be **3** (three `OpCheckSigFromStack`
/// calls for the 2-of-3 `cap_authority` quorum — no owner signature, no
/// `mint_pubkey` involvement at all, mirroring `build_seize_branch`'s "no
/// owner signature" shape).
///
/// # Attestation pre-image (84B, §9 — see `mint_authority::attestation`'s
/// module doc for the exact byte layout/rationale)
///
/// `DOMAIN_TAG_MINT || covenant_id || outpoint_txid || outpoint_index ||
/// new_pending_cap(8,LE)`. Every input-side introspection field is sourced
/// from `OpTxInputIndex` (never an immediate), binding the quorum's
/// signatures to THIS input's specific spend; `new_pending_cap` is folded in
/// as the sigscript pushed it (fixed 8-byte LE), so the quorum's signatures
/// attest to the EXACT ceiling value being announced — replaying a captured
/// ANNOUNCE_CAP attestation against a transaction proposing a DIFFERENT
/// `new_pending_cap` changes the recomputed message hash, which the
/// original signatures no longer match.
fn build_announce_cap_branch(cap_authority_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3], genesis_covenant_id: &[u8; 32], cap_raise_multiplier_k: u64) -> Vec<u8> {
    use op::*;
    assert!(cap_raise_multiplier_k >= 2, "cap_raise_multiplier_k must be >= 2 (a ceiling of < 2x would forbid ANY strict increase for cap doublings this small)");
    let mut b = Vec::with_capacity(280);

    // ---- Step 0: this coin's own (live-pushed) pending_since_daa/
    // pending_cap/epoch_start_daa/minted_this_epoch/running_supply are all
    // unused -- ANNOUNCE_CAP re-authenticates their unchanged-ness via the
    // prefix check below (over the AUTHENTICATED old_rs/new_rs blobs)
    // instead of trusting these live pushes directly, mirroring
    // build_mint_branch's Step 0 discipline. Only current_cap survives this
    // step (needed live for the ceiling/strict-increase checks below). ----
    b.push(DROP); // pending_since_daa (already at depth0, FIX 1)
    // Stack: pending_cap(0), current_cap(1), epoch_start_daa(2),
    // minted_this_epoch(3), running_supply(4), new_pending_cap(5), new_rs(6),
    // old_rs(7), sig3(8), sig2(9), sig1(10).
    b.push(DROP); // pending_cap (now at depth0)
    // Stack: current_cap(0), epoch_start_daa(1), minted_this_epoch(2),
    // running_supply(3), new_pending_cap(4), new_rs(5), old_rs(6), sig3(7),
    // sig2(8), sig1(9).
    e_roll(&mut b, 1);
    b.push(DROP); // epoch_start_daa (item now at depth1)
    // Stack: current_cap(0), minted_this_epoch(1), running_supply(2),
    // new_pending_cap(3), new_rs(4), old_rs(5), sig3(6), sig2(7), sig1(8).
    e_roll(&mut b, 1);
    b.push(DROP); // minted_this_epoch (item now at depth1)
    // Stack: current_cap(0), running_supply(1), new_pending_cap(2), new_rs(3),
    // old_rs(4), sig3(5), sig2(6), sig1(7).
    e_roll(&mut b, 1);
    b.push(DROP); // running_supply (item now at depth1)
    // Stack: current_cap(0), new_pending_cap(1), new_rs(2), old_rs(3), sig3(4),
    // sig2(5), sig1(6).

    // ---- Step 0b (SECURITY FIX, numeric-domain bound): new_pending_cap must
    // decode as non-negative (i.e. the raw u64 the sigscript intended to push
    // must be in [0, 2^63)). Kaspa script numbers are sign-magnitude LE, and
    // the engine's arithmetic ops read this fixed 8-byte push as an `i64`
    // (see `stablecoin::attestation::MAX_AMOUNT_EXCLUSIVE`'s own doc on this
    // same domain) -- a raw u64 >= 2^63 has its top bit set and so decodes
    // negative (or, for exactly 2^63, decodes as the same value as a
    // legitimate 0). This is defense-in-depth: Step 7's `new_pending_cap >
    // current_cap` already rejects every value in this range when
    // current_cap is itself non-negative -- but pin it here explicitly
    // rather than relying on that incidental interaction. Non-destructive:
    // OpGreaterThanOrEqual pops the copy and the literal, OpVerify pops the
    // bool, netting to 0 against the stack shape above. ----
    e_pick(&mut b, 1); // new_pending_cap copy -> top
    // Stack: npc_copy(0), current_cap(1), new_pending_cap(2), new_rs(3), old_rs(4),
    // sig3(5), sig2(6), sig1(7).
    b.push(OP0);
    // Stack: lit0(0), npc_copy(1), current_cap(2), new_pending_cap(3), new_rs(4),
    // old_rs(5), sig3(6), sig2(7), sig1(8).
    b.push(GREATERTHANOREQUAL); // npc_copy >= 0 (deeper >= shallower)
    b.push(VERIFY);
    // Stack (net 0, restored): current_cap(0), new_pending_cap(1), new_rs(2), old_rs(3),
    // sig3(4), sig2(5), sig1(6).

    // ---- Step 1: self-continuation (a) -- authenticate old_rs really is
    // this input's own committed redeemScript (mirrors build_mint_branch's
    // Step 1). ----
    b.extend_from_slice(&dr_input_spk_check(3));

    // ---- Step 2: running_supply/minted_this_epoch/epoch_start_daa/
    // current_cap UNCHANGED -- a straight prefix compare over [0..36)
    // between old_rs and new_rs. ----
    b.extend_from_slice(&dr_prefix_check(3, 3, super::state::PENDING_CAP_OPCODE_OFFSET as u16));
    // Stack unchanged (dr_prefix_check nets to 0): current_cap(0), new_pending_cap(1),
    // new_rs(2), old_rs(3), sig3(4), sig2(5), sig1(6).

    // ---- Step 3: the baked body (everything after the 54B state header)
    // must be byte-identical between old_rs and new_rs -- pending_cap AND
    // pending_since_daa (bytes [36..54)) are deliberately EXCLUDED from both
    // this and the Step 2 prefix check above: they are the region this
    // branch is allowed, and required, to change (FIX 1 extends the gap
    // from [36..45) to [36..54) automatically via STATE_HEADER_LEN). ----
    b.extend_from_slice(&dr_suffix_check(3, 3, super::state::STATE_HEADER_LEN as u16));
    // Stack unchanged: current_cap(0), new_pending_cap(1), new_rs(2), old_rs(3),
    // sig3(4), sig2(5), sig1(6).

    // ---- Step 4: push-opcode sanity check -- new_rs[36] must still be the
    // 0x08 (OpData8) push opcode, so the successor's pending_cap field parses
    // the same way it does here (mirrors build_mint_branch's Step 3, applied
    // to pending_cap's opcode byte). ----
    b.extend_from_slice(&dr_field_extract(2, super::state::PENDING_CAP_OPCODE_OFFSET as u16, (super::state::PENDING_CAP_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: current_cap(0), new_pending_cap(1), new_rs(2), old_rs(3), sig3(4),
    // sig2(5), sig1(6).

    // ---- Step 5: old_rs no longer needed -- drop it. ----
    e_roll(&mut b, 3);
    b.push(DROP);
    // Stack: current_cap(0), new_pending_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).

    // ---- Step 6: extract the successor's pending_cap payload (8B) from
    // new_rs, and assert it equals the ATTESTED new_pending_cap exactly (raw
    // 8-byte LE byte compare -- both sides are fixed-width 8-byte
    // representations, so OpEqual is sufficient here; contrast Step 7 below,
    // which needs a NUMERIC comparison). ----
    let pending_cap_off = super::state::PENDING_CAP_PAYLOAD_OFFSET as u16;
    b.extend_from_slice(&dr_field_extract(2, pending_cap_off, pending_cap_off + 8)); // succ_pending_cap, from new_rs (depth2)
    // Stack: succ_pending_cap(0), current_cap(1), new_pending_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    e_pick(&mut b, 2); // new_pending_cap copy (need the original again below)
    // Stack: npc_copy(0), succ_pending_cap(1), current_cap(2), new_pending_cap(3),
    // new_rs(4), sig3(5), sig2(6), sig1(7).
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: current_cap(0), new_pending_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).

    // ---- Step 6b (FIX 1, 2026-07-20 timelock-griefing hardening):
    // push-opcode sanity check -- new_rs[45] (pending_since_daa) must still
    // be the 0x08 (OpData8) push opcode (mirrors Step 4's check for
    // pending_cap's opcode). ----
    b.extend_from_slice(&dr_field_extract(2, super::state::PENDING_SINCE_DAA_OPCODE_OFFSET as u16, (super::state::PENDING_SINCE_DAA_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: current_cap(0), new_pending_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).

    // ---- Step 6c (FIX 1): stamp the successor's pending_since_daa with
    // THIS input's own real, unforgeable OpTxInputDaaScore -- i.e. WHEN this
    // announcement happened. This is the field MINT is forced to carry
    // forward byte-identical (see build_mint_branch's Step 0 doc), which is
    // what stops a later interleaved MINT from resetting ACTIVATE_CAP's
    // timelock clock: the clock is anchored to this value, not to whatever
    // UTXO's block_daa_score happens to be current when ACTIVATE_CAP runs. ----
    let pending_since_daa_off = super::state::PENDING_SINCE_DAA_PAYLOAD_OFFSET as u16;
    b.extend_from_slice(&dr_field_extract(2, pending_since_daa_off, pending_since_daa_off + 8)); // succ_pending_since_daa, from new_rs (depth2)
    // Stack: succ_psd(0), current_cap(1), new_pending_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTDAASCORE); // now (this announcing input's own UTXO block_daa_score)
    // Stack: now(0), succ_psd(1), current_cap(2), new_pending_cap(3), new_rs(4),
    // sig3(5), sig2(6), sig1(7).
    b.push(NUMEQUALVERIFY); // succ_psd(deeper) == now(shallower) -- arithmetic result, not a raw 8-byte compare
    // Stack: current_cap(0), new_pending_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).

    // ---- Step 7 (G4 hardening): STRICT increase (new_pending_cap >
    // current_cap) AND ceiling (new_pending_cap <= current_cap *
    // cap_raise_multiplier_k), combined so `current_cap` -- consumed by
    // Step 7's numeric checks -- feeds BOTH without needing a third live
    // copy beyond what's taken here. `ceiling_bound` is computed FIRST
    // (while current_cap is still fresh) via checked OpMul (hard-aborts on
    // i64 overflow, crypto/txscript's OpMul precedent), then the
    // strict-increase check consumes the (now doubly-copied) current_cap,
    // then the ceiling check consumes ceiling_bound. Ends in the SAME stack
    // shape the pre-G4 strict-increase-only Step 7 did. ----
    e_pick(&mut b, 0); // current_cap copy -> top
    // Stack: cc_copy(0), current_cap(1), new_pending_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    b.push(DATA8);
    b.extend_from_slice(&cap_raise_multiplier_k.to_le_bytes());
    // Stack: k(0), cc_copy(1), current_cap(2), new_pending_cap(3), new_rs(4),
    // sig3(5), sig2(6), sig1(7).
    b.push(MUL); // ceiling_bound = cc_copy * k (checked; hard-aborts on overflow)
    // Stack: ceiling_bound(0), current_cap(1), new_pending_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).

    e_pick(&mut b, 2); // new_pending_cap copy -> top
    // Stack: npc_copy(0), ceiling_bound(1), current_cap(2), new_pending_cap(3),
    // new_rs(4), sig3(5), sig2(6), sig1(7).
    e_roll(&mut b, 2); // bring current_cap to top (adjacent to npc_copy)
    // Stack: current_cap(0), npc_copy(1), ceiling_bound(2), new_pending_cap(3),
    // new_rs(4), sig3(5), sig2(6), sig1(7).
    b.push(GREATERTHAN); // npc_copy(deeper) > current_cap(shallower) -- strict increase
    b.push(VERIFY);
    // Stack: ceiling_bound(0), new_pending_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).

    e_pick(&mut b, 1); // new_pending_cap copy -> top
    // Stack: npc_copy2(0), ceiling_bound(1), new_pending_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    e_roll(&mut b, 1); // bring ceiling_bound to top (adjacent to npc_copy2)
    // Stack: ceiling_bound(0), npc_copy2(1), new_pending_cap(2), new_rs(3), sig3(4),
    // sig2(5), sig1(6).
    b.push(LESSTHANOREQUAL); // npc_copy2(deeper) <= ceiling_bound(shallower) -- G4 ceiling
    b.push(VERIFY);
    // Stack: new_pending_cap(0), new_rs(1), sig3(2), sig2(3), sig1(4).

    // ---- Step 8: self-continuation (b) -- output[0].spk == P2SH(new_rs), at
    // the FIXED index 0 (this contract always emits its self-continuation
    // successor at output[0]; ANNOUNCE_CAP emits NO other output -- no coin). ----
    b.push(OP0); // literal output index 0
    // Stack: idx0(0), new_pending_cap(1), new_rs(2), sig3(3), sig2(4), sig1(5).
    b.extend_from_slice(&dr_output_spk_check(2, 1));
    b.push(DROP); // drop idx0 (dr_output_spk_check's net effect is 0 otherwise)
    // Stack: new_pending_cap(0), new_rs(1), sig3(2), sig2(3), sig1(4).

    // ---- Step 8b (SECURITY FIX): output[0]'s native value must equal this
    // input's native value -- the cap_authority quorum's OpCheckSigFromStack
    // attestation (no owner SIGHASH_ALL signature at all) doesn't otherwise
    // pin the successor's operating balance, so without this a cap_authority
    // holder could drain the authority UTXO's value while announcing a cap. ----
    b.extend_from_slice(&value_continuity_check_output0());
    // Stack unchanged (net 0): new_pending_cap(0), new_rs(1), sig3(2), sig2(3), sig1(4).

    // ---- Step 9: new_rs no longer needed -- drop it. ----
    e_roll(&mut b, 1);
    b.push(DROP);
    // Stack: new_pending_cap(0), sig3(1), sig2(2), sig1(3).

    // ---- Step 10: ANNOUNCE_CAP attestation pre-image (84B,
    // mint_authority::attestation): DOMAIN_TAG_MINT || covenant_id ||
    // outpoint_txid || outpoint_index || new_pending_cap. ----
    b.push(DATA8);
    b.extend_from_slice(&super::DOMAIN_TAG_MINT);
    // Stack: acc(0)=domain_tag, new_pending_cap(1), sig3(2), sig2(3), sig1(4).
    b.push(TXINPUTINDEX);
    b.push(INPUTCOVENANTID);
    // Stack: covenant_id(0), acc(1), new_pending_cap(2), sig3(3), sig2(4), sig1(5).

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
    // Stack: covenant_id_copy(0), covenant_id(1), acc(2), new_pending_cap(3), sig3(4),
    // sig2(5), sig1(6).
    b.push(DATA32);
    b.extend_from_slice(genesis_covenant_id);
    // Stack: G(0), covenant_id_copy(1), covenant_id(2), acc(3), new_pending_cap(4),
    // sig3(5), sig2(6), sig1(7).
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack (restored): covenant_id(0), acc(1), new_pending_cap(2), sig3(3), sig2(4),
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
    // Stack: acc(0), new_pending_cap(1), sig3(2), sig2(3), sig1(4).
    e_roll(&mut b, 1); // new_pending_cap -> top (last use, consumed)
    // Stack: new_pending_cap(0), acc(1), sig3(2), sig2(3), sig1(4).
    b.push(CAT); // acc || new_pending_cap(8B LE) == full 84B preimage
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
///
/// DESIGN DECISION (2026-07-20 mint-authority hardening, recipient-allowlist
/// scope note): `role_registry_root` baked in here is the stablecoin
/// covenant's GOVERNANCE-ROLE commitment (a Blake3 root over the role keys
/// TRANSFER/FREEZE/SEIZE/etc. verify against) -- it is NOT, and must never be
/// wired as, a recipient allowlist. Gating WHO `recipient_pubkey` (the
/// sigscript-chosen owner of the newly-minted coin) may be is a category
/// error against this field's actual purpose, and doing so would require a
/// real Merkle-membership proof mechanism this covenant does not have. Any
/// recipient allowlisting for MINT is therefore DEFERRED to the operational
/// layer (off-chain policy on who the MINT role signs attestations for) --
/// this session lands only the G4 ceiling+timelock and G5 epoch
/// budget+dust-floor hardening, not an on-chain recipient gate.
fn build_fixed_mid(
    identifier_type: u8,
    role_registry_root: &[u8; 32],
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    recovery_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
) -> Vec<u8> {
    // mint_pubkey doubles as the stablecoin covenant's own MINT-role key
    // (STABLECOIN_ROBUST_DESIGN.md §2: "MINT ... authorizes MINT in the
    // separate mint-authority contract (§9) + authorizes BURN (issuer side)
    // in this covenant" -- the same key, not two different ones).
    let stablecoin_body =
        crate::contract::stablecoin::body::build_stablecoin_body(ops_pubkey, freeze_pubkey, seize_pubkeys, recovery_pubkeys, mint_pubkey);
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
/// doc for the full derivation. Entry stack (top to bottom):
/// `pending_since_daa(0), pending_cap(1), current_cap(2), epoch_start_daa(3),
/// minted_this_epoch(4), running_supply(5), recipient_pubkey(6),
/// mint_amount(7), new_rs(8), old_rs(9), mint_sig(10)`.
fn build_mint_branch(
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    fixed_mid: &[u8],
    genesis_covenant_id: &[u8; 32],
    epoch_length_daa: u64,
    epoch_mint_budget: u64,
) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(500 + fixed_mid.len());

    // ---- Step 0: this coin's own (live-pushed) pending_since_daa,
    // pending_cap and running_supply are unused -- MINT never touches
    // pending_cap/pending_since_daa at all (their unchanged-ness is covered
    // wholesale by Step 2's suffix check below, which -- because
    // pending_since_daa sits immediately after pending_cap, both inside the
    // suffix `dr_suffix_check` already anchors at CURRENT_CAP_OPCODE_OFFSET
    // -- extends automatically to carry the FIX 1 griefing-hardening field
    // forward too: this is exactly what stops a hot mint_pubkey holder from
    // resetting ACTIVATE_CAP's timelock clock by minting) and reads
    // old_running_supply from the AUTHENTICATED old_rs blob instead (Step 4),
    // per this task's spec ("mirror dca.rs's counter-update pattern").
    // epoch_start_daa/minted_this_epoch stay live (needed by the G5
    // epoch-budget block below, which owns their lifecycle and drops them
    // itself). Drop pending_since_daa (already on top), then pending_cap,
    // then running_supply, mirroring build_freeze_branch's discipline of
    // immediately dropping unused own-state fields. ----
    b.push(DROP); // pending_since_daa (already at depth0, FIX 1)
    // Stack: pending_cap(0), current_cap(1), epoch_start_daa(2),
    // minted_this_epoch(3), running_supply(4), recipient_pubkey(5),
    // mint_amount(6), new_rs(7), old_rs(8), mint_sig(9).
    b.push(DROP); // pending_cap (now at depth0)
    // Stack: current_cap(0), epoch_start_daa(1), minted_this_epoch(2),
    // running_supply(3), recipient_pubkey(4), mint_amount(5), new_rs(6),
    // old_rs(7), mint_sig(8).
    e_roll(&mut b, 3);
    b.push(DROP); // running_supply
    // Stack: current_cap(0), epoch_start_daa(1), minted_this_epoch(2),
    // recipient_pubkey(3), mint_amount(4), new_rs(5), old_rs(6), mint_sig(7).

    // ---- Step 1: self-continuation (a) -- authenticate old_rs really is
    // this input's own committed redeemScript (mirrors dca.rs's D&R Step 1). ----
    b.extend_from_slice(&dr_input_spk_check(6));

    // ---- Step 2: self-continuation (b) -- the baked body AND current_cap
    // (now also pending_cap) must be byte-identical between old_rs and
    // new_rs. Because running_supply/minted_this_epoch/epoch_start_daa
    // occupy the ENTIRE mutable zone [0..27) with nothing before it
    // (state.rs), "everything from current_cap onward" is a single
    // contiguous suffix [27..end) -- one dr_suffix_check call covers BOTH
    // invariants at once. ----
    b.extend_from_slice(&dr_suffix_check(6, 6, super::state::CURRENT_CAP_OPCODE_OFFSET as u16));
    // Stack unchanged (dr_suffix_check nets to 0): current_cap(0),
    // epoch_start_daa(1), minted_this_epoch(2), recipient_pubkey(3),
    // mint_amount(4), new_rs(5), old_rs(6), mint_sig(7).

    // ---- Step 3: push-prefix sanity checks (mirrors dca.rs D&R Step 4) --
    // new_rs's running_supply/minted_this_epoch/epoch_start_daa push opcodes
    // must all still be 0x08 (OpData8), so the successor's fields parse the
    // same way they do here. ----
    b.extend_from_slice(&dr_field_extract(5, super::state::RUNNING_SUPPLY_OPCODE_OFFSET as u16, (super::state::RUNNING_SUPPLY_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    b.extend_from_slice(&dr_field_extract(5, super::state::MINTED_THIS_EPOCH_OPCODE_OFFSET as u16, (super::state::MINTED_THIS_EPOCH_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    b.extend_from_slice(&dr_field_extract(5, super::state::EPOCH_START_DAA_OPCODE_OFFSET as u16, (super::state::EPOCH_START_DAA_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack unchanged: current_cap(0), epoch_start_daa(1), minted_this_epoch(2),
    // recipient_pubkey(3), mint_amount(4), new_rs(5), old_rs(6), mint_sig(7).

    // ---- Step 3b (B.3 dust floor, Stage 1): mint_amount >= MIN_MINT_AMOUNT. ----
    b.extend_from_slice(&dust_floor_check(4));

    // ---- Step 3c (B.1 epoch budget, Stage 2): self-contained block; see
    // `epoch_budget_block`'s own doc for the exact precondition/logic/
    // postcondition. Ends with the stack restored to EXACTLY the pre-G5
    // shape below, so every step from here on is UNCHANGED from before this
    // feature existed. ----
    b.extend_from_slice(&epoch_budget_block(epoch_length_daa, epoch_mint_budget));
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

/// Emit the `ACTIVATE_CAP` (`op_type = 0x02`, new 2026-07-20) branch
/// bytecode: PERMISSIONLESS (no signatures at all, `sig_op_count = 0`)
/// promotion of an already-announced `pending_cap` into `current_cap`, gated
/// by a STATE-ANCHORED timelock (FIX 1, 2026-07-20 timelock-griefing
/// hardening -- see `state.rs`'s module doc for the full rationale):
///
/// ```text
/// old_pending_since_daa + min_activation_delay_daa <= OpTxInputDaaScore
/// ```
///
/// where `old_pending_since_daa` is extracted from the AUTHENTICATED
/// `old_rs` (i.e. `ANNOUNCE_CAP`'s stamp of WHEN this announcement really
/// happened) and `OpTxInputDaaScore` is THIS (activating) input's own real,
/// unforgeable UTXO `block_daa_score`.
///
/// This REPLACES an earlier `push(min_activation_delay_daa)
/// OpCheckSequenceVerify` design (`OpCheckSequenceVerify` enforces
/// `input.sequence >= min_activation_delay_daa`, but consensus's own
/// `check_sequence_lock` separately re-derives the relative lock time
/// against the SELF-CONTINUING UTXO's own `block_daa_score` -- which every
/// routine MINT re-stamps, since MINT recreates the authority UTXO on every
/// spend. That reset the CSV clock on every mint, so a hot `mint_pubkey`
/// holder could mint dust once per window to block a cap-authority-approved
/// activation forever). Storing the announce height IN STATE instead means
/// MINT (forced to carry `pending_since_daa` forward byte-identical, see
/// `build_mint_branch`'s Step 0 doc) cannot push it, so interleaved mints no
/// longer widen the window.
///
/// # What is mirrored from where
///
/// - **Self-continuation D&R shape**: the SAME `crate::contract::dr` helpers
///   [`build_mint_branch`]/[`build_announce_cap_branch`] use. The mutated
///   region is the TRAILING TRIPLE `current_cap`+`pending_cap`+
///   `pending_since_daa` (`[27..54)`: `current_cap`/`pending_cap` both
///   promoted to the OLD `pending_cap` value, `pending_since_daa` reset to
///   `0`), so ACTIVATE_CAP needs a [`dr_prefix_check`] over `[0..27)`
///   (`running_supply`/`minted_this_epoch`/`epoch_start_daa` -- UNCHANGED)
///   AND a [`dr_suffix_check`] over `[STATE_HEADER_LEN..end)` (the baked
///   body UNCHANGED) -- exactly the prefix+suffix-leaves-a-gap shape
///   [`build_announce_cap_branch`] uses, just with the gap covering all
///   three trailing fields instead of two.
/// - **Value continuity**: the SAME [`value_continuity_check_output0`] every
///   other branch uses -- CRITICAL here specifically because this branch is
///   permissionless: without it, ANY third party (no key required at all)
///   could construct an activation transaction that also drains the
///   authority UTXO's operating balance.
///
/// No genesis-`covenant_id` check (unlike MINT/ANNOUNCE_CAP): this branch
/// signs no attestation at all, so there is no cross-authority replay
/// surface to close -- `old_rs` is authenticated as THIS input's own
/// committed redeemScript (`dr_input_spk_check`), and the successor is only
/// ever allowed to promote THAT SAME coin's own already-announced
/// `pending_cap`; nothing here could be satisfied by, or confused with, a
/// different authority's UTXO.
///
/// # Entry stack once the dispatch delivers control to the ACTIVATE_CAP branch
///
/// State header pushes 6 fields (`state.rs`), then the dispatch
/// consumes+drops the `op_type` selector:
///
/// ```text
/// pending_since_daa(0), pending_cap(1), current_cap(2), epoch_start_daa(3),
/// minted_this_epoch(4), running_supply(5), new_rs(6), old_rs(7)
/// ```
///
/// This is the sigscript layout callers must produce (push order,
/// first==deepest): `old_rs, new_rs, op_type_selector(0x02)`, then the
/// redeem script. `sig_op_count` MUST be **0** -- no signatures at all. The
/// timelock is now enforced purely from state + `OpTxInputDaaScore`, so
/// (unlike the earlier CSV design) callers need not set this input's
/// `sequence` field to anything in particular.
fn build_activate_cap_branch(min_activation_delay_daa: u64) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(170);

    // ---- Step 0: this coin's own (live-pushed) pending_since_daa/
    // current_cap/epoch_start_daa/minted_this_epoch/running_supply are all
    // unused -- ACTIVATE_CAP re-authenticates their unchanged-ness via the
    // prefix check below (over the AUTHENTICATED old_rs/new_rs blobs)
    // instead of trusting these live pushes directly, and reads
    // pending_since_daa fresh from the AUTHENTICATED old_rs below (Step 4b)
    // rather than from this live push. Only pending_cap survives this step
    // (needed live for Step 6/7's successor-equality checks). ----
    b.push(DROP); // pending_since_daa (already at depth0, FIX 1)
    // Stack: pending_cap(0), current_cap(1), epoch_start_daa(2),
    // minted_this_epoch(3), running_supply(4), new_rs(5), old_rs(6).
    e_roll(&mut b, 1);
    b.push(DROP); // current_cap (item now at depth1)
    // Stack: pending_cap(0), epoch_start_daa(1), minted_this_epoch(2),
    // running_supply(3), new_rs(4), old_rs(5).
    e_roll(&mut b, 1);
    b.push(DROP); // epoch_start_daa (item now at depth1)
    // Stack: pending_cap(0), minted_this_epoch(1), running_supply(2), new_rs(3),
    // old_rs(4).
    e_roll(&mut b, 1);
    b.push(DROP); // minted_this_epoch (item now at depth1)
    // Stack: pending_cap(0), running_supply(1), new_rs(2), old_rs(3).
    e_roll(&mut b, 1);
    b.push(DROP); // running_supply (item now at depth1)
    // Stack: pending_cap(0), new_rs(1), old_rs(2).

    // ---- Step 1: self-continuation (a) -- authenticate old_rs really is
    // this input's own committed redeemScript. ----
    b.extend_from_slice(&dr_input_spk_check(2));

    // ---- Step 2: running_supply/minted_this_epoch/epoch_start_daa
    // UNCHANGED -- a straight prefix compare over [0..27) between old_rs and
    // new_rs. ----
    b.extend_from_slice(&dr_prefix_check(2, 2, super::state::CURRENT_CAP_OPCODE_OFFSET as u16));
    // Stack unchanged (dr_prefix_check nets to 0): pending_cap(0), new_rs(1), old_rs(2).

    // ---- Step 3: the baked body (everything after the 54B state header)
    // must be byte-identical between old_rs and new_rs -- current_cap,
    // pending_cap AND pending_since_daa (bytes [27..54)) are deliberately
    // EXCLUDED from both this and the Step 2 prefix check above: they are
    // the region this branch is allowed, and required, to change. ----
    b.extend_from_slice(&dr_suffix_check(2, 2, super::state::STATE_HEADER_LEN as u16));
    // Stack unchanged: pending_cap(0), new_rs(1), old_rs(2).

    // ---- Step 4: push-opcode sanity checks -- new_rs[27] (current_cap),
    // new_rs[36] (pending_cap), and new_rs[45] (pending_since_daa, FIX 1)
    // must all still be 0x08 (OpData8), so the successor's fields parse the
    // same way they do here. ----
    b.extend_from_slice(&dr_field_extract(1, super::state::CURRENT_CAP_OPCODE_OFFSET as u16, (super::state::CURRENT_CAP_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    b.extend_from_slice(&dr_field_extract(1, super::state::PENDING_CAP_OPCODE_OFFSET as u16, (super::state::PENDING_CAP_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    b.extend_from_slice(&dr_field_extract(1, super::state::PENDING_SINCE_DAA_OPCODE_OFFSET as u16, (super::state::PENDING_SINCE_DAA_OPCODE_OFFSET + 1) as u16));
    b.push(DATA1);
    b.push(0x08);
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack unchanged: pending_cap(0), new_rs(1), old_rs(2).

    // ---- Step 4b (FIX 1, 2026-07-20 timelock-griefing hardening):
    // state-anchored timelock -- REPLACES the earlier
    // `push(min_activation_delay_daa) OpCheckSequenceVerify` design (see
    // this fn's doc). old_rs is still live at depth2 here (dropped next, in
    // Step 5), so extract pending_since_daa from it (the AUTHENTICATED
    // announce stamp) while it's available, add the baked
    // min_activation_delay_daa (checked OpAdd, hard-aborts on i64 overflow
    // per OpAdd's existing precedent), and assert the resulting deadline is
    // `<=` THIS input's own OpTxInputDaaScore. Self-contained: nets to 0
    // against the surrounding stack. ----
    b.extend_from_slice(&dr_field_extract(2, super::state::PENDING_SINCE_DAA_PAYLOAD_OFFSET as u16, (super::state::PENDING_SINCE_DAA_PAYLOAD_OFFSET + 8) as u16)); // old_pending_since_daa, from old_rs (depth2)
    // Stack: old_psd(0), pending_cap(1), new_rs(2), old_rs(3).
    b.push(DATA8);
    b.extend_from_slice(&min_activation_delay_daa.to_le_bytes());
    // Stack: mad(0), old_psd(1), pending_cap(2), new_rs(3), old_rs(4).
    b.push(ADD); // deadline = old_psd + mad
    // Stack: deadline(0), pending_cap(1), new_rs(2), old_rs(3).
    b.push(TXINPUTINDEX);
    b.push(TXINPUTDAASCORE); // now (this activating input's own UTXO block_daa_score)
    // Stack: now(0), deadline(1), pending_cap(2), new_rs(3), old_rs(4).
    b.push(LESSTHANOREQUAL); // deadline(deeper) <= now(shallower)
    b.push(VERIFY);
    // Stack: pending_cap(0), new_rs(1), old_rs(2).

    // ---- Step 5: old_rs no longer needed -- drop it. ----
    e_roll(&mut b, 2);
    b.push(DROP);
    // Stack: pending_cap(0), new_rs(1).

    // ---- Step 6: extract the successor's current_cap payload (8B) from
    // new_rs, and assert it equals THIS coin's own live pending_cap exactly
    // (raw 8-byte LE byte compare -- both sides are fixed-width 8-byte
    // representations). ----
    b.extend_from_slice(&dr_field_extract(1, super::state::CURRENT_CAP_PAYLOAD_OFFSET as u16, (super::state::CURRENT_CAP_PAYLOAD_OFFSET + 8) as u16));
    // Stack: succ_current_cap(0), pending_cap(1), new_rs(2).
    e_pick(&mut b, 1); // pending_cap copy (need the original again below)
    // Stack: pc_copy(0), succ_current_cap(1), pending_cap(2), new_rs(3).
    b.push(EQUAL);
    b.push(VERIFY);
    // Stack: pending_cap(0), new_rs(1).

    // ---- Step 7: extract the successor's pending_cap payload (8B) from
    // new_rs, and assert it ALSO equals THIS coin's own live pending_cap
    // (the sentinel invariant: after activation, current_cap == pending_cap
    // again, exactly like the genesis/no-pending-raise state). ----
    b.extend_from_slice(&dr_field_extract(1, super::state::PENDING_CAP_PAYLOAD_OFFSET as u16, (super::state::PENDING_CAP_PAYLOAD_OFFSET + 8) as u16));
    // Stack: succ_pending_cap(0), pending_cap(1), new_rs(2).
    b.push(EQUAL); // succ_pending_cap vs pending_cap -- already adjacent, no pick needed
    b.push(VERIFY);
    // Stack: new_rs(0).

    // ---- Step 7b (FIX 1): extract the successor's pending_since_daa
    // payload (8B) from new_rs, and assert it is RESET to the sentinel `0`
    // -- the other half of the sentinel invariant (Step 7 restores
    // current_cap == pending_cap; this restores "no announcement pending").
    // NUMEQUALVERIFY (not raw OpEqual): OP0 pushes an EMPTY byte string,
    // which would never raw-byte-equal an 8-byte zero payload, so this must
    // deserialize both sides as script numbers before comparing. ----
    b.extend_from_slice(&dr_field_extract(0, super::state::PENDING_SINCE_DAA_PAYLOAD_OFFSET as u16, (super::state::PENDING_SINCE_DAA_PAYLOAD_OFFSET + 8) as u16));
    // Stack: succ_psd(0), new_rs(1).
    b.push(OP0);
    // Stack: lit0(0), succ_psd(1), new_rs(2).
    b.push(NUMEQUALVERIFY); // succ_psd(deeper) == lit0(shallower)
    // Stack: new_rs(0).

    // ---- Step 8: self-continuation (b) -- output[0].spk == P2SH(new_rs), at
    // the FIXED index 0 (this contract always emits its self-continuation
    // successor at output[0]; ACTIVATE_CAP emits NO other output -- no coin). ----
    b.push(OP0); // literal output index 0
    // Stack: idx0(0), new_rs(1).
    b.extend_from_slice(&dr_output_spk_check(1, 1));
    b.push(DROP); // drop idx0 (dr_output_spk_check's net effect is 0 otherwise)
    // Stack: new_rs(0).

    // ---- Step 8b (SECURITY FIX, CRITICAL for a permissionless branch):
    // output[0]'s native value must equal this input's native value -- with
    // NO signature at all gating this branch, without this check ANY third
    // party could construct an activation transaction that also drains the
    // authority UTXO's operating balance. ----
    b.extend_from_slice(&value_continuity_check_output0());
    // Stack unchanged (net 0): new_rs(0).

    // ---- Step 9: new_rs no longer needed -- drop it. No attestation to
    // build (permissionless, no signature check at all). The state-anchored
    // timelock (Step 4b) already gated this branch above -- nothing left to
    // check. ----
    b.push(DROP);
    // Stack: EMPTY.

    b.push(OP1);
    b
}

/// Build the mint-authority contract's own 3-way `op_type` dispatch (`MINT =
/// 0x00`, `ANNOUNCE_CAP = 0x01`, `ACTIVATE_CAP = 0x02`), reusing the
/// covenant's dispatch idiom
/// (`crate::contract::stablecoin::dispatch::build_op_type_dispatch`'s
/// roll/DUP/compare/IF/ELSE/ENDIF shape), generalized down to 3 branches.
/// `tag_depth` is the stack depth of the `op_type` selector once the state
/// header has finished pushing its six fields -- see [`OP_TYPE_TAG_DEPTH`].
fn build_op_type_dispatch(tag_depth: u16, mint_branch: &[u8], announce_cap_branch: &[u8], activate_cap_branch: &[u8]) -> Vec<u8> {
    use op::*;
    let mut b = Vec::with_capacity(24 + mint_branch.len() + announce_cap_branch.len() + activate_cap_branch.len());
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
        // 0x01 ANNOUNCE_CAP
        b.push(DUP);
        b.push(DATA1);
        b.push(op_type::ANNOUNCE_CAP);
        b.push(EQUAL);
        b.push(IF);
        {
            b.push(DROP);
            b.extend_from_slice(announce_cap_branch);
        }
        b.push(ELSE);
        {
            // 0x02 ACTIVATE_CAP -- the final rung: must match exactly
            // (OP_VERIFY), so any other byte hard-aborts here rather than
            // falling through.
            b.push(DUP);
            b.push(DATA1);
            b.push(op_type::ACTIVATE_CAP);
            b.push(EQUAL);
            b.push(VERIFY);
            b.push(DROP);
            b.extend_from_slice(activate_cap_branch);
        }
        b.push(ENDIF);
    }
    b.push(ENDIF);
    b
}

/// Stack depth of the `op_type` selector once the state header has finished
/// pushing its six fields (`running_supply`, `minted_this_epoch`,
/// `epoch_start_daa`, `current_cap`, `pending_cap`, `pending_since_daa`) --
/// with the sigscript layout documented in this module's top doc
/// (`op_type_selector` as the LAST sigscript push before the redeem
/// script), that depth is always `6`.
pub const OP_TYPE_TAG_DEPTH: u16 = 6;

/// Emit the mint-authority covenant body: state header's fields are already
/// on the stack; the body is the 3-way `op_type` dispatch.
///
/// FIX 2 (2026-07-20 mint-authority hardening audit, MEDIUM): the 12-key
/// pairwise-distinctness assert used to live ONLY in the wrapper
/// [`build_mint_authority_redeem_script`], not here -- so a future caller
/// composing state manually (bypassing that wrapper, e.g. to build a
/// redeem script whose state header is supplied by some other means) could
/// collapse the cap-authority 2-of-3 quorum (or let `mint_pubkey` cast one
/// of its votes) without ever tripping the guard. Duplicated here, mirroring
/// how `stablecoin::body::build_stablecoin_body` carries its own copy of the
/// analogous check for the same stated reason (defense at the actual
/// bytecode-emitting layer, not just its most common caller).
#[allow(clippy::too_many_arguments)]
pub fn build_mint_authority_body(
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    cap_authority_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    recovery_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    role_registry_root: &[u8; 32],
    identifier_type: u8,
    genesis_covenant_id: &[u8; 32],
    cap_raise_multiplier_k: u64,
    epoch_length_daa: u64,
    epoch_mint_budget: u64,
    min_activation_delay_daa: u64,
) -> Vec<u8> {
    // FIX 2: role pubkeys MUST be pairwise distinct (mirrors
    // build_mint_authority_redeem_script's copy of this same assert -- see
    // that function's doc for the full rationale per slot).
    {
        let role_keys: [&[u8; X_ONLY_PUBKEY_LEN]; 12] = [
            mint_pubkey,
            &cap_authority_pubkeys[0], &cap_authority_pubkeys[1], &cap_authority_pubkeys[2],
            ops_pubkey, freeze_pubkey,
            &seize_pubkeys[0], &seize_pubkeys[1], &seize_pubkeys[2],
            &recovery_pubkeys[0], &recovery_pubkeys[1], &recovery_pubkeys[2],
        ];
        for i in 0..role_keys.len() {
            for j in (i + 1)..role_keys.len() {
                assert!(role_keys[i] != role_keys[j], "mint-authority role pubkeys must be pairwise distinct (slot {i} == slot {j})");
            }
        }
    }
    assert!(cap_raise_multiplier_k >= 2, "cap_raise_multiplier_k must be >= 2");
    // FIX 4 (LOW, 2026-07-20 audit): sanity bound on min_activation_delay_daa.
    // The now-removed CSV mechanism masked to 32 bits (SEQUENCE_LOCK_TIME_MASK);
    // FIX 1's state-anchored timelock instead compares against
    // OpTxInputDaaScore directly (checked i64 arithmetic, no 32-bit mask), so
    // the truncation concern this bound originally guarded against no longer
    // strictly applies -- kept anyway (mirroring the k>=2 code-level guard
    // above) to catch a silently-huge/mis-keyed delay at construction time
    // rather than deploying a covenant whose ACTIVATE_CAP could never clear.
    assert!(min_activation_delay_daa < (1u64 << 32), "min_activation_delay_daa must be < 2^32 (sanity bound; see FIX 4)");
    let fixed_mid =
        build_fixed_mid(identifier_type, role_registry_root, mint_pubkey, ops_pubkey, freeze_pubkey, seize_pubkeys, recovery_pubkeys);
    let mint_branch = build_mint_branch(mint_pubkey, &fixed_mid, genesis_covenant_id, epoch_length_daa, epoch_mint_budget);
    let announce_cap_branch = build_announce_cap_branch(cap_authority_pubkeys, genesis_covenant_id, cap_raise_multiplier_k);
    let activate_cap_branch = build_activate_cap_branch(min_activation_delay_daa);
    build_op_type_dispatch(OP_TYPE_TAG_DEPTH, &mint_branch, &announce_cap_branch, &activate_cap_branch)
}

/// Build the complete mint-authority redeem script (state header + dispatch
/// body). `running_supply`/`minted_this_epoch`/`epoch_start_daa`/
/// `current_cap`/`pending_cap`/`pending_since_daa` go into the mutable state
/// header (`state.rs`); the rest are baked bytecode literals (option B,
/// matching the stablecoin covenant's own Decision 2026-07-19 convention):
///
/// NOTE: this function is GENERIC -- used both to build a genuinely fresh
/// GENESIS deploy AND, throughout this module's tests/the CLI, to predict
/// arbitrary intermediate/successor state headers (e.g. an
/// already-announced `pending_cap != current_cap` state, needed to express
/// `ANNOUNCE_CAP`/`ACTIVATE_CAP` test fixtures and successors). Because of
/// that reuse it deliberately does NOT assert `pending_cap == current_cap`
/// -- prefer [`build_mint_authority_genesis_redeem_script`] for an actual
/// genesis deploy, which structurally cannot express that misconfiguration
/// (FIX 3, 2026-07-20 audit).
/// `mint_pubkey` is the mint-authority's own hot MINT-role key (also reused
/// as the stablecoin covenant's MINT-role BURN-authorizer key, per §2's role
/// table); `cap_authority_pubkeys` are the cold 2-of-3 keys for the
/// ANNOUNCE_CAP op; `ops_pubkey`/`freeze_pubkey`/`seize_pubkeys`/
/// `role_registry_root`/`identifier_type` are the stablecoin covenant's own
/// role constants, needed to reconstruct an emitted coin's redeem script.
///
/// `genesis_covenant_id` (SUB-FIX B, genesis-binding security fix) is the
/// UNIQUE covenant_id of this specific authority's genesis deploy, baked as a
/// literal into the body (the same fixed region `dr_suffix_check` already
/// pins as unchanged across self-continuation) and checked on-chain (both
/// MINT and ANNOUNCE_CAP) against the spending input's ACTUAL,
/// consensus-tracked covenant_id. Without this, two independently-deployed
/// authority contracts that happen to bake the SAME PUBLIC `mint_pubkey`/
/// `cap_authority_pubkeys` (which are public keys, not secrets) would be
/// bytecode-indistinguishable apart from their state header, and either
/// one's `mint_pubkey`/`cap_authority` holder could mint/announce-cap on
/// behalf of what looks like "the" authority -- covenant_id is what makes
/// genesis, and therefore the specific deployment, unique; it PROPAGATES
/// through self-continuation (verified in consensus), so binding to it is
/// exactly the "unique genesis" invariant this fix restores. Callers
/// deploying a genuinely NEW authority must pass the covenant_id their
/// genesis transaction will actually be assigned (the CLI two-transaction
/// deploy bootstrap that computes this is deferred -- out of scope here;
/// this function only makes the covenant take and enforce
/// `genesis_covenant_id`, it does not compute one).
///
/// `cap_raise_multiplier_k` (G4): ANNOUNCE_CAP's ceiling multiplier -- MUST
/// be `>= 2` (asserted below). `epoch_length_daa`/`epoch_mint_budget` (G5):
/// MINT's epoch window length (DAA) and per-window sompi budget.
/// `min_activation_delay_daa` (G4): ACTIVATE_CAP's state-anchored timelock
/// floor (FIX 1, 2026-07-20: no longer a CSV floor -- see
/// `build_activate_cap_branch`'s doc).
#[allow(clippy::too_many_arguments)]
pub fn build_mint_authority_redeem_script(
    running_supply: u64,
    minted_this_epoch: u64,
    epoch_start_daa: u64,
    current_cap: u64,
    pending_cap: u64,
    pending_since_daa: u64,
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    cap_authority_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    recovery_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    role_registry_root: &[u8; 32],
    identifier_type: u8,
    genesis_covenant_id: &[u8; 32],
    cap_raise_multiplier_k: u64,
    epoch_length_daa: u64,
    epoch_mint_budget: u64,
    min_activation_delay_daa: u64,
) -> Vec<u8> {
    // Role keys MUST be pairwise distinct: a duplicated cap_authority key collapses
    // the ANNOUNCE_CAP 2-of-3 threshold, and mint_pubkey sharing a cap_authority slot
    // lets the (hot) mint key cast one of the three cold cap-raise votes. Reject at
    // construction. (seize/ops/freeze/recovery are also baked here for emitted-coin
    // reconstruction and must match the covenant's own distinct set -- recovery_pubkeys
    // in particular must be independent of seize_pubkeys, Decision 2026-07-20-G0.)
    // (FIX 2: this same assert is duplicated in build_mint_authority_body
    // itself, which this function calls below -- kept here too as the
    // earliest-possible-failure copy, mirroring stablecoin::body's
    // build_stablecoin_body/build_stablecoin_redeem_script precedent.)
    {
        let role_keys: [&[u8; X_ONLY_PUBKEY_LEN]; 12] = [
            mint_pubkey,
            &cap_authority_pubkeys[0], &cap_authority_pubkeys[1], &cap_authority_pubkeys[2],
            ops_pubkey, freeze_pubkey,
            &seize_pubkeys[0], &seize_pubkeys[1], &seize_pubkeys[2],
            &recovery_pubkeys[0], &recovery_pubkeys[1], &recovery_pubkeys[2],
        ];
        for i in 0..role_keys.len() {
            for j in (i + 1)..role_keys.len() {
                assert!(role_keys[i] != role_keys[j], "mint-authority role pubkeys must be pairwise distinct (slot {i} == slot {j})");
            }
        }
    }
    assert!(cap_raise_multiplier_k >= 2, "cap_raise_multiplier_k must be >= 2");
    let state = super::state::MintAuthorityStateHeader::new(running_supply, minted_this_epoch, epoch_start_daa, current_cap, pending_cap, pending_since_daa);
    let mut rs = state.encode_script();
    debug_assert_eq!(rs.len(), super::state::STATE_HEADER_LEN);
    rs.extend_from_slice(&build_mint_authority_body(
        mint_pubkey,
        cap_authority_pubkeys,
        ops_pubkey,
        freeze_pubkey,
        seize_pubkeys,
        recovery_pubkeys,
        role_registry_root,
        identifier_type,
        genesis_covenant_id,
        cap_raise_multiplier_k,
        epoch_length_daa,
        epoch_mint_budget,
        min_activation_delay_daa,
    ));
    rs
}

/// Genesis-only wrapper around [`build_mint_authority_redeem_script`] (FIX 3,
/// 2026-07-20 audit, "genesis pending_cap==current_cap not enforced"). A
/// fresh deploy has no `MINT`/`ANNOUNCE_CAP`/`ACTIVATE_CAP` history yet, so
/// `minted_this_epoch`/`epoch_start_daa` start at `0` and
/// `pending_cap`/`pending_since_daa` start at the sentinel "no announcement
/// pending" values (`current_cap`/`0`) -- see
/// [`super::state::MintAuthorityStateHeader::new_genesis`]'s doc for the
/// full rationale (since `ACTIVATE_CAP` is PERMISSIONLESS, a deploy-time
/// misconfiguration setting `pending_cap > current_cap` would let ANYONE
/// promote an unvetted cap that never went through `ANNOUNCE_CAP`'s cold
/// quorum). Callers deploying a genuinely new authority should prefer this
/// over the generic constructor, which stays available (and does NOT carry
/// this guard) for predicting arbitrary non-genesis state headers.
#[allow(clippy::too_many_arguments)]
pub fn build_mint_authority_genesis_redeem_script(
    running_supply: u64,
    current_cap: u64,
    mint_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    cap_authority_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    ops_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    freeze_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    seize_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    recovery_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
    role_registry_root: &[u8; 32],
    identifier_type: u8,
    genesis_covenant_id: &[u8; 32],
    cap_raise_multiplier_k: u64,
    epoch_length_daa: u64,
    epoch_mint_budget: u64,
    min_activation_delay_daa: u64,
) -> Vec<u8> {
    // Structural guard (asserts are trivially true by construction here --
    // see new_genesis's doc for why they're kept as a refactor tripwire
    // rather than dropped).
    let genesis_state = super::state::MintAuthorityStateHeader::new_genesis(running_supply, current_cap);
    build_mint_authority_redeem_script(
        genesis_state.running_supply,
        genesis_state.minted_this_epoch,
        genesis_state.epoch_start_daa,
        genesis_state.current_cap,
        genesis_state.pending_cap,
        genesis_state.pending_since_daa,
        mint_pubkey,
        cap_authority_pubkeys,
        ops_pubkey,
        freeze_pubkey,
        seize_pubkeys,
        recovery_pubkeys,
        role_registry_root,
        identifier_type,
        genesis_covenant_id,
        cap_raise_multiplier_k,
        epoch_length_daa,
        epoch_mint_budget,
        min_activation_delay_daa,
    )
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
    recovery_pubkeys: &[[u8; X_ONLY_PUBKEY_LEN]; 3],
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
        recovery_pubkeys,
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
    const RECOVERY: [[u8; 32]; 3] = [[0xB1; 32], [0xB2; 32], [0xB3; 32]];
    const ROOT: [u8; 32] = [0xCC; 32];
    const RECIPIENT: [u8; 32] = [0xAA; 32];
    const GENESIS: [u8; 32] = [0x77; 32];

    // Deployment-parameter defaults shared by every test in this module
    // (not under test here -- see mint_authority_contracts.rs for the
    // real-engine adversarial coverage of these specific values).
    const K: u64 = 2;
    const EPOCH_LEN: u64 = 1_000;
    const EPOCH_BUDGET: u64 = u64::MAX / 4;
    const MIN_ACTIVATION_DELAY: u64 = 100;

    fn rs(running_supply: u64, current_cap: u64) -> Vec<u8> {
        build_mint_authority_redeem_script(
            running_supply,
            0,
            0,
            current_cap,
            current_cap,
            0, // pending_since_daa sentinel (no announcement pending)
            &MINT,
            &CAP_AUTH,
            &OPS,
            &FREEZE,
            &SEIZE,
            &RECOVERY,
            &ROOT,
            0x00,
            &GENESIS,
            K,
            EPOCH_LEN,
            EPOCH_BUDGET,
            MIN_ACTIVATION_DELAY,
        )
    }

    fn body_bytes() -> Vec<u8> {
        build_mint_authority_body(&MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &RECOVERY, &ROOT, 0x00, &GENESIS, K, EPOCH_LEN, EPOCH_BUDGET, MIN_ACTIVATION_DELAY)
    }

    #[test]
    fn redeem_script_starts_with_state_header() {
        let script = rs(1_000, 5_000);
        assert_eq!(script[0], 0x08);
        assert_eq!(&script[1..9], &1_000u64.to_le_bytes());
        assert_eq!(script[9], 0x08); // minted_this_epoch
        assert_eq!(script[18], 0x08); // epoch_start_daa
        assert_eq!(script[27], 0x08); // current_cap
        assert_eq!(&script[28..36], &5_000u64.to_le_bytes());
        assert_eq!(script[36], 0x08); // pending_cap
        assert_eq!(&script[37..45], &5_000u64.to_le_bytes());
        assert_eq!(script[45], 0x08); // pending_since_daa (FIX 1)
        assert_eq!(&script[46..54], &0u64.to_le_bytes());
        assert!(script.len() > super::super::state::STATE_HEADER_LEN);
    }

    #[test]
    fn mint_pubkey_is_baked_into_body() {
        let script = rs(0, 5_000);
        assert!(script.windows(32).any(|w| w == MINT));
    }

    #[test]
    fn cap_authority_pubkeys_are_baked_into_body() {
        let script = rs(0, 5_000);
        for pk in &CAP_AUTH {
            assert!(script.windows(32).any(|w| w == pk), "cap authority pubkey {pk:?} not found baked into redeem script");
        }
    }

    #[test]
    fn stablecoin_role_constants_are_baked_into_body() {
        let script = rs(0, 5_000);
        assert!(script.windows(32).any(|w| w == OPS));
        assert!(script.windows(32).any(|w| w == FREEZE));
        for pk in &SEIZE {
            assert!(script.windows(32).any(|w| w == pk));
        }
        assert!(script.windows(32).any(|w| w == ROOT));
    }

    #[test]
    fn genesis_covenant_id_is_baked_into_body_at_least_twice() {
        // SUB-FIX B regression: the genesis covenant_id G must be baked as a
        // literal into the body -- once for MINT's check, once for
        // ANNOUNCE_CAP's -- so both branches independently pin it (neither
        // branch's genesis check can be satisfied by accident; each has its
        // own baked copy of G). ACTIVATE_CAP has no genesis check (it signs
        // no attestation), so the count stays at exactly 2, not 3.
        let script = rs(0, 5_000);
        let occurrences = script.windows(32).filter(|w| *w == GENESIS).count();
        assert!(occurrences >= 2, "expected genesis covenant_id baked into the body at least twice (MINT + ANNOUNCE_CAP), found {occurrences}");
    }

    #[test]
    fn distinct_genesis_covenant_ids_yield_distinct_redeem_scripts() {
        // Two authorities baked with otherwise-IDENTICAL public role
        // constants but DIFFERENT genesis covenant_ids must produce distinct
        // bytecode (proving G is actually read from the argument, not
        // hardcoded/ignored) -- the whole point of SUB-FIX B is that these
        // two scripts behave differently on-chain despite sharing every
        // other baked key.
        let a = build_mint_authority_redeem_script(0, 0, 0, 5_000, 5_000, 0, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &RECOVERY, &ROOT, 0x00, &GENESIS, K, EPOCH_LEN, EPOCH_BUDGET, MIN_ACTIVATION_DELAY);
        let b = build_mint_authority_redeem_script(0, 0, 0, 5_000, 5_000, 0, &MINT, &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &RECOVERY, &ROOT, 0x00, &[0x99; 32], K, EPOCH_LEN, EPOCH_BUDGET, MIN_ACTIVATION_DELAY);
        assert_ne!(a, b);
        // The mutable state header (unaffected by G) stays identical.
        assert_eq!(&a[..super::super::state::STATE_HEADER_LEN], &b[..super::super::state::STATE_HEADER_LEN]);
    }

    #[test]
    fn body_length_is_deterministic_regardless_of_state_field_values() {
        let a = body_bytes();
        let b = body_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn announce_cap_branch_ends_in_real_threshold_bytecode_not_a_stub() {
        let body = body_bytes();
        // ANNOUNCE_CAP is real bytecode ending in the same 2-of-3 threshold
        // shape as build_seize_branch's own tail: two OpAdd, Op2,
        // OpGreaterThanOrEqual, OpVerify.
        assert!(
            body.windows(5).any(|w| w == [op::ADD, op::ADD, op::OP2, op::GREATERTHANOREQUAL, op::VERIFY]),
            "expected ANNOUNCE_CAP's 2-of-3 threshold tail (ADD ADD OP2 GREATERTHANOREQUAL VERIFY) to appear in the body"
        );
        // And the strict-increase check's OpGreaterThan must appear too.
        assert!(body.contains(&op::GREATERTHAN), "expected ANNOUNCE_CAP's strict-increase OpGreaterThan to appear in the body");
        // And the G4 ceiling check's OpMul must appear (checked multiplication).
        assert!(body.contains(&op::MUL), "expected ANNOUNCE_CAP's G4 ceiling OpMul to appear in the body");
        // And ACTIVATE_CAP's FIX 1 state-anchored timelock (OpTxInputDaaScore
        // compared via OpLessThanOrEqual+OpVerify, replacing the old CSV
        // OpCheckSequenceVerify) must appear -- this specific 4-byte window
        // (TxInputIndex TxInputDaaScore LessThanOrEqual Verify) is unique to
        // Step 4b's `deadline <= now` check (MINT's epoch-budget block and
        // ANNOUNCE_CAP's own pending_since_daa stamp both read
        // OpTxInputDaaScore too, but neither is immediately followed by
        // LessThanOrEqual+Verify).
        assert!(
            body.windows(4).any(|w| w == [op::TXINPUTINDEX, op::TXINPUTDAASCORE, op::LESSTHANOREQUAL, op::VERIFY]),
            "expected ACTIVATE_CAP's FIX 1 state-anchored timelock check to appear in the body"
        );
        // Note: a companion check that OpCheckSequenceVerify (0xb1) is
        // "gone" would be unreliable here via a raw byte-contains scan --
        // RECOVERY[0] == [0xB1; 32] is baked into this same body (as part of
        // the emitted-coin reconstruction constants) and would make a naive
        // `body.contains(&0xb1)` trivially true regardless of CSV's actual
        // presence. See `activate_cap_branch_no_longer_ends_in_csv_tail`
        // below (isolates `build_activate_cap_branch`'s own output, with no
        // such baked-pubkey collision) for that regression instead.
    }

    #[test]
    fn activate_cap_branch_no_longer_ends_in_csv_tail() {
        // FIX 1 regression: the old Step 10 ended every ACTIVATE_CAP branch
        // in `[..., DATA8, <8 bytes of min_activation_delay_daa>,
        // OpCheckSequenceVerify, OP1]`. The new state-anchored timelock
        // moves the check earlier (Step 4b) and the branch now ends in a
        // plain `[..., DROP, OP1]` (Step 9's stack-empty DROP immediately
        // before the branch's uniform OP1 success return) -- CSV is REPLACED,
        // not merely supplemented.
        let branch = build_activate_cap_branch(MIN_ACTIVATION_DELAY);
        assert!(!branch.contains(&op::CHECKSEQUENCEVERIFY), "OpCheckSequenceVerify must no longer appear in ACTIVATE_CAP's own branch bytecode at all");
        assert_eq!(&branch[branch.len() - 2..], &[op::DROP, op::OP1], "branch must end in a plain DROP OP1 (no trailing CSV push+opcode)");
    }

    #[test]
    fn mini_dispatch_dups_tag_on_all_three_rungs_regression() {
        // Regression test mirroring dispatch.rs's own
        // `all_six_rungs_dup_tag_before_compare_bugfix_regression`: this
        // 3-way mini-dispatch must OP_DUP the op_type tag on ALL THREE rungs
        // (including the final ACTIVATE_CAP rung, which uses a hard
        // OP_VERIFY instead of a further OP_ELSE fallback) -- otherwise the
        // final rung's OP_EQUAL would consume the tag directly (no spare
        // copy to compare with), and the trailing OP_DROP would silently eat
        // the next REAL data-stack item instead of a tag copy, corrupting
        // every stack depth ACTIVATE_CAP computes against.
        let dispatch_only = build_op_type_dispatch(OP_TYPE_TAG_DEPTH, &[0xAAu8], &[0xBBu8], &[0xCCu8]);
        let dup_count = dispatch_only.iter().filter(|&&b| b == op::DUP).count();
        assert_eq!(dup_count, 3, "expected 3 OP_DUP (one per op_type rung, including the final ACTIVATE_CAP rung), found {dup_count}");
    }

    #[test]
    fn announce_cap_branch_stack_depth_is_correct_smoke_test() {
        // Exercises build_announce_cap_branch directly (not just through the
        // dispatch) as a lightweight structural regression: it must produce
        // non-empty bytecode ending in OP_1 (this codebase's uniform
        // branch-success convention, matching build_mint_branch/
        // build_seize_branch), and must be depth-sensitive to which
        // cap_authority_pubkeys are baked in (proving the three pubkeys are
        // read from the argument, not hardcoded).
        let a = build_announce_cap_branch(&CAP_AUTH, &GENESIS, K);
        let b = build_announce_cap_branch(&[[0x01; 32], [0x02; 32], [0x03; 32]], &GENESIS, K);
        assert_eq!(*a.last().unwrap(), op::OP1, "ANNOUNCE_CAP branch must end in OP_1 on success, matching the codebase's branch convention");
        assert_ne!(a, b, "ANNOUNCE_CAP branch bytecode must depend on the baked cap_authority_pubkeys");
        assert_eq!(a.len(), b.len(), "ANNOUNCE_CAP branch length must be deterministic regardless of which pubkeys are baked in");
    }

    #[test]
    #[should_panic(expected = "cap_raise_multiplier_k must be >= 2")]
    fn announce_cap_branch_rejects_k_below_2() {
        build_announce_cap_branch(&CAP_AUTH, &GENESIS, 1);
    }

    #[test]
    fn activate_cap_branch_stack_depth_is_correct_smoke_test() {
        let a = build_activate_cap_branch(MIN_ACTIVATION_DELAY);
        let b = build_activate_cap_branch(MIN_ACTIVATION_DELAY + 1);
        assert_eq!(*a.last().unwrap(), op::OP1, "ACTIVATE_CAP branch must end in OP_1 on success");
        assert_ne!(a, b, "ACTIVATE_CAP branch bytecode must depend on the baked min_activation_delay_daa");
        assert_eq!(a.len(), b.len(), "ACTIVATE_CAP branch length must be deterministic regardless of the baked delay");
    }

    #[test]
    fn fixed_mid_matches_real_stablecoin_redeem_script_tail() {
        // fixed_mid must be byte-identical to
        // build_stablecoin_redeem_script(...)'s own tail from offset 33
        // onward (everything after owner_pubkey's 32B payload), for ANY
        // owner_pubkey -- this is the load-bearing cross-check that the
        // on-chain reconstruction (Step 8) really produces THE SAME bytes a
        // genuine stablecoin covenant deployment would.
        let fixed_mid = build_fixed_mid(0x00, &ROOT, &MINT, &OPS, &FREEZE, &SEIZE, &RECOVERY);
        let real_rs = build_emitted_coin_redeem_script(&RECIPIENT, 0x00, &ROOT, &OPS, &FREEZE, &SEIZE, &RECOVERY, &MINT);
        assert_eq!(&real_rs[33..], fixed_mid.as_slice());

        // And it must NOT depend on the recipient/owner pubkey at all.
        let other_recipient = [0x77u8; 32];
        let real_rs_2 = build_emitted_coin_redeem_script(&other_recipient, 0x00, &ROOT, &OPS, &FREEZE, &SEIZE, &RECOVERY, &MINT);
        assert_eq!(&real_rs_2[33..], fixed_mid.as_slice());
    }

    #[test]
    fn distinct_mint_keys_yield_distinct_redeem_scripts() {
        let a = rs(0, 5_000);
        let b = build_mint_authority_redeem_script(0, 0, 0, 5_000, 5_000, 0, &[0x01; 32], &CAP_AUTH, &OPS, &FREEZE, &SEIZE, &RECOVERY, &ROOT, 0x00, &GENESIS, K, EPOCH_LEN, EPOCH_BUDGET, MIN_ACTIVATION_DELAY);
        assert_ne!(a, b);
        assert_eq!(&a[..super::super::state::STATE_HEADER_LEN], &b[..super::super::state::STATE_HEADER_LEN]);
    }
}
