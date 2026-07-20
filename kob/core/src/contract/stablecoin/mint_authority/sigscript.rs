//! Mint-authority contract **sigscript** (unlocking script) builders
//! (`STABLECOIN_ROBUST_DESIGN.md` §9 "Mint + Supply Cap", extended
//! 2026-07-20 for G4 RAISE_CAP ceiling+timelock / G5 MINT epoch budget).
//!
//! This is the spender side of [`super::body`]'s three-way `op_type`
//! dispatch (`MINT`, `op_type = 0x00` / `ANNOUNCE_CAP`, `op_type = 0x01`,
//! renamed from `RAISE_CAP` / `ACTIVATE_CAP`, `op_type = 0x02`, new). Mirrors
//! the house style of `crate::contract::stablecoin::sigscript`: one
//! `build_mint_authority_*_sigscript` function per branch, each emitting
//! exactly the push-only bytes that branch's bytecode pops/rolls off the
//! stack, in the order it expects, with the redeem script pushed last (the
//! P2SH wrapper pops it first, before the body runs).
//!
//! # MINT (`op_type = 0x00`) push order
//!
//! Per [`super::body::build_mint_branch`]'s module doc, the entry stack once
//! the dispatch delivers control to the MINT branch is (top-to-bottom):
//! `pending_since_daa(0), pending_cap(1), current_cap(2), epoch_start_daa(3),
//! minted_this_epoch(4), running_supply(5), recipient_pubkey(6),
//! mint_amount(7), new_rs(8), old_rs(9), mint_sig(10)` — the first six are
//! pushed by the redeem script's own state header (`state.rs`), not the
//! sigscript. Because a sigscript is push-only and the *emission* order is
//! the reverse of stack depth (the first push ends up deepest), the sigscript
//! this builder emits is:
//!
//! ```text
//! push mint_sig(64B) -> push old_rs -> push new_rs -> push mint_amount(8B LE)
//!   -> push recipient_pubkey -> push op_type_selector(1B, 0x00)
//!   -> pushData(redeem_script)
//! ```
//!
//! - **mint_sig** — the MINT role's raw 64-byte Schnorr signature over
//!   [`super::attestation::build_mint_attestation_message`]
//!   (`OpCheckSigFromStack`, **no** SIGHASH type byte — there is no owner
//!   signature at all in this branch, mirroring
//!   `stablecoin::body::build_freeze_branch`'s "no owner signature" shape).
//! - **old_rs** — this input's own current redeemScript, authenticated
//!   on-chain via `dr_input_spk_check`.
//! - **new_rs** — the candidate self-continuation successor redeem script
//!   (plaintext; authenticated on-chain against the real successor output's
//!   P2SH commitment).
//! - **mint_amount** — the amount being minted, folded into the attestation
//!   pre-image and checked (via `OpNumEqual`) against output[1]'s native
//!   value.
//! - **recipient_pubkey** — the newly-minted coin's `owner_pubkey`. Takes a
//!   raw `&[u8]` slice (not `&[u8; 32]`) so callers can also express the
//!   SUB-FIX A oversized-recipient adversarial case (`body.rs`'s Step 8a
//!   length-pin check) — mirroring
//!   `core/tests/mint_authority_contracts.rs`'s own (pre-refactor)
//!   `build_mint_sigscript` helper.
//!
//! This input's `sig_op_count` MUST be **1** (a single `OpCheckSigFromStack`
//! for the MINT role).
//!
//! # ANNOUNCE_CAP (`op_type = 0x01`, renamed from RAISE_CAP) push order
//!
//! Per [`super::body::build_announce_cap_branch`]'s module doc, the entry
//! stack once the dispatch delivers control to the ANNOUNCE_CAP branch is
//! (top-to-bottom): `pending_since_daa(0), pending_cap(1), current_cap(2),
//! epoch_start_daa(3), minted_this_epoch(4), running_supply(5),
//! new_pending_cap(6), new_rs(7), old_rs(8), sig3(9), sig2(10), sig1(11)` —
//! the first six are the state header's own live pushes (`state.rs`), not
//! the sigscript. The sigscript this builder emits (first push == deepest)
//! is:
//!
//! ```text
//! push sig1(64B) -> push sig2(64B) -> push sig3(64B) -> push old_rs
//!   -> push new_rs -> push new_pending_cap(8B LE) -> push op_type_selector(1B, 0x01)
//!   -> pushData(redeem_script)
//! ```
//!
//! - **sig1**/**sig2**/**sig3** — FIXED POSITIONAL slots, the cold 2-of-3
//!   `cap_authority` quorum's raw 64-byte Schnorr signatures over
//!   [`super::attestation::build_announce_cap_attestation_message`]
//!   (`OpCheckSigFromStack`, **no** SIGHASH type byte), checked against
//!   `cap_authority_pubkeys[0]`/`[1]`/`[2]` respectively (mirroring
//!   `stablecoin::sigscript::build_stablecoin_seize_sigscript`'s SEIZE-quorum
//!   convention) — a holder of only 2 of the 3 keys supplies a genuine
//!   64-byte signature in their two slots and an arbitrary 64-byte
//!   placeholder (e.g. all-zero) in the third.
//! - **old_rs** — this input's own current redeemScript, authenticated
//!   on-chain via `dr_input_spk_check`.
//! - **new_rs** — the candidate self-continuation successor redeem script.
//! - **new_pending_cap** — the new ceiling being announced, folded into the
//!   attestation pre-image, checked against the G4 ceiling
//!   (`<= current_cap * K`), and checked against the successor's actual
//!   `pending_cap` field (NOT `current_cap`, which must stay unchanged until
//!   `ACTIVATE_CAP`'s state-anchored timelock clears, FIX 1 2026-07-20). The
//!   successor's `pending_since_daa` is NOT a separate sigscript push -- the
//!   branch stamps it on-chain from this input's own `OpTxInputDaaScore`
//!   (see `build_announce_cap_branch`'s Step 6c), so a caller's `new_rs`
//!   must set that field to whatever DAA score this specific spend will
//!   actually execute at.
//!
//! This input's `sig_op_count` MUST be **3** (three `OpCheckSigFromStack`
//! calls for the 2-of-3 `cap_authority` quorum — no owner signature, no
//! `mint_pubkey` involvement at all).
//!
//! # ACTIVATE_CAP (`op_type = 0x02`, new) push order
//!
//! Per [`super::body::build_activate_cap_branch`]'s module doc, the entry
//! stack once the dispatch delivers control to the ACTIVATE_CAP branch is
//! (top-to-bottom): `pending_since_daa(0), pending_cap(1), current_cap(2),
//! epoch_start_daa(3), minted_this_epoch(4), running_supply(5), new_rs(6),
//! old_rs(7)`. The sigscript this builder emits (first push == deepest) is:
//!
//! ```text
//! push old_rs -> push new_rs -> push op_type_selector(1B, 0x02)
//!   -> pushData(redeem_script)
//! ```
//!
//! No signatures at all: this branch is PERMISSIONLESS (gated only by the
//! FIX 1 state-anchored timelock -- `old_rs`'s own `pending_since_daa` +
//! `min_activation_delay_daa` `<=` this input's `OpTxInputDaaScore`,
//! REPLACING the earlier CSV `input.sequence >= min_activation_delay_daa`
//! design, see `build_activate_cap_branch`'s doc for why -- and the on-chain
//! checks that the successor's `current_cap`/`pending_cap` both equal this
//! coin's own already-announced `pending_cap`, and `pending_since_daa` is
//! reset to `0`). This input's `sig_op_count` MUST be **0**.

use crate::primitives::push_data;

/// Build the mint-authority MINT (`op_type = 0x00`) sigscript. See this
/// module's top doc for the derivation of the push order from
/// [`super::body::build_mint_branch`]'s entry-stack layout.
///
/// `mint_sig` — the MINT role's raw 64-byte Schnorr signature over
/// [`super::attestation::build_mint_attestation_message`] (no SIGHASH type
/// byte; verified via `OpCheckSigFromStack`, not `OpCheckSig`).
/// `old_rs` — this input's own current redeemScript (authenticated via
/// `dr_input_spk_check` on-chain).
/// `new_rs` — the candidate self-continuation successor redeem script.
/// `mint_amount` — the amount being minted (encoded here as a fixed 8-byte
/// LE sigscript push).
/// `recipient_pubkey` — the newly-minted coin's `owner_pubkey` (honestly 32
/// bytes; accepted as `&[u8]` so an oversized push can be expressed for the
/// SUB-FIX A adversarial test).
/// `redeem_script` — the full mint-authority redeem script from
/// [`super::body::build_mint_authority_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_mint_branch` (`body.rs`) expects: `mint_sig` deepest, then
/// `old_rs`, then `new_rs`, then `mint_amount`, then `recipient_pubkey`, then
/// the `op_type_selector` (`0x00 == MINT`), then the redeem script last.
pub fn build_mint_authority_mint_sigscript(
    mint_sig: &[u8; 64],
    old_rs: &[u8],
    new_rs: &[u8],
    mint_amount: u64,
    recipient_pubkey: &[u8],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(
        2 + 64 + 3 + old_rs.len() + 3 + new_rs.len() + 2 + 8 + 3 + recipient_pubkey.len() + 2 + 3 + redeem_script.len(),
    );
    // Emitted first -> ends up deepest on the stack: the MINT attestation sig.
    ss.extend_from_slice(&push_data(mint_sig));
    // Then this input's own current redeemScript (authenticated on-chain via
    // dr_input_spk_check).
    ss.extend_from_slice(&push_data(old_rs));
    // Then the candidate self-continuation successor redeem script.
    ss.extend_from_slice(&push_data(new_rs));
    // Then the amount being minted (8B LE u64).
    ss.extend_from_slice(&push_data(&mint_amount.to_le_bytes()));
    // Then the newly-minted coin's recipient owner_pubkey.
    ss.extend_from_slice(&push_data(recipient_pubkey));
    // Then the op_type selector (0x00 == MINT).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::MINT]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the mint-authority ANNOUNCE_CAP (`op_type = 0x01`, renamed from
/// RAISE_CAP) sigscript. See this module's top doc for the derivation of the
/// push order from [`super::body::build_announce_cap_branch`]'s entry-stack
/// layout.
///
/// `sig1`/`sig2`/`sig3` — FIXED POSITIONAL slots (checked against
/// `cap_authority_pubkeys[0]`/`[1]`/`[2]` respectively), each a raw 64-byte
/// Schnorr signature over
/// [`super::attestation::build_announce_cap_attestation_message`] (no
/// SIGHASH type byte; verified via `OpCheckSigFromStack`). A holder of only
/// 2 of the 3 keys supplies a genuine signature in two slots and an
/// arbitrary 64-byte placeholder in the third.
/// `old_rs` — this input's own current redeemScript (authenticated via
/// `dr_input_spk_check` on-chain).
/// `new_rs` — the candidate self-continuation successor redeem script.
/// `new_pending_cap` — the new ceiling being announced (encoded here as a
/// fixed 8-byte LE sigscript push); checked against the G4 ceiling
/// (`<= current_cap * K`) and against the successor's `pending_cap` field
/// (NOT `current_cap`).
/// `redeem_script` — the full mint-authority redeem script from
/// [`super::body::build_mint_authority_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_announce_cap_branch` (`body.rs`) expects: `sig1` deepest, then
/// `sig2`, then `sig3`, then `old_rs`, then `new_rs`, then
/// `new_pending_cap`, then the `op_type_selector` (`0x01 == ANNOUNCE_CAP`),
/// then the redeem script last.
pub fn build_mint_authority_announce_cap_sigscript(
    sig1: &[u8; 64],
    sig2: &[u8; 64],
    sig3: &[u8; 64],
    old_rs: &[u8],
    new_rs: &[u8],
    new_pending_cap: u64,
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(3 * (2 + 64) + 3 + old_rs.len() + 3 + new_rs.len() + 2 + 8 + 2 + 3 + redeem_script.len());
    // Emitted first -> ends up deepest on the stack: the three cap_authority
    // attestation sigs, in fixed positional order (sig1, sig2, sig3).
    ss.extend_from_slice(&push_data(sig1));
    ss.extend_from_slice(&push_data(sig2));
    ss.extend_from_slice(&push_data(sig3));
    // Then this input's own current redeemScript (authenticated on-chain via
    // dr_input_spk_check).
    ss.extend_from_slice(&push_data(old_rs));
    // Then the candidate self-continuation successor redeem script.
    ss.extend_from_slice(&push_data(new_rs));
    // Then the attested new_pending_cap (8B LE u64).
    ss.extend_from_slice(&push_data(&new_pending_cap.to_le_bytes()));
    // Then the op_type selector (0x01 == ANNOUNCE_CAP).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::ANNOUNCE_CAP]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the mint-authority ACTIVATE_CAP (`op_type = 0x02`, new) sigscript.
/// See this module's top doc for the derivation of the push order from
/// [`super::body::build_activate_cap_branch`]'s entry-stack layout.
///
/// PERMISSIONLESS: no signatures at all -- gated purely by FIX 1's (2026-07-20
/// timelock-griefing hardening) state-anchored timelock (`old_rs`'s own
/// `pending_since_daa` + `min_activation_delay_daa` `<=` this input's
/// `OpTxInputDaaScore`, enforced by the redeem script itself) and the
/// on-chain checks that the successor's `current_cap`/`pending_cap` both
/// equal this coin's own already-announced `pending_cap`, with
/// `pending_since_daa` reset to `0`.
///
/// `old_rs` — this input's own current redeemScript (authenticated via
/// `dr_input_spk_check` on-chain).
/// `new_rs` — the candidate self-continuation successor redeem script.
/// `redeem_script` — the full mint-authority redeem script from
/// [`super::body::build_mint_authority_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_activate_cap_branch` (`body.rs`) expects: `old_rs` deepest, then
/// `new_rs`, then the `op_type_selector` (`0x02 == ACTIVATE_CAP`), then the
/// redeem script last. `sig_op_count` MUST be `0`; unlike the earlier CSV
/// design, callers need not set this input's `sequence` field to anything
/// in particular (the timelock is enforced purely from state +
/// `OpTxInputDaaScore` now).
pub fn build_mint_authority_activate_cap_sigscript(old_rs: &[u8], new_rs: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(3 + old_rs.len() + 3 + new_rs.len() + 2 + 3 + redeem_script.len());
    // Emitted first -> ends up deepest on the stack: this input's own
    // current redeemScript (authenticated on-chain via dr_input_spk_check).
    ss.extend_from_slice(&push_data(old_rs));
    // Then the candidate self-continuation successor redeem script.
    ss.extend_from_slice(&push_data(new_rs));
    // Then the op_type selector (0x02 == ACTIVATE_CAP).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::ACTIVATE_CAP]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::stablecoin::mint_authority::body::build_mint_authority_redeem_script;
    use crate::contract::token::identifier_type;

    const MINT_SIG: [u8; 64] = [0x22; 64];
    const SIG1: [u8; 64] = [0x31; 64];
    const SIG2: [u8; 64] = [0x32; 64];
    const SIG3: [u8; 64] = [0x33; 64];

    const MINT_PK: [u8; 32] = [0xEF; 32];
    const CAP_AUTH: [[u8; 32]; 3] = [[0xA1; 32], [0xA2; 32], [0xA3; 32]];
    const OPS_PK: [u8; 32] = [0xBB; 32];
    const FREEZE_PK: [u8; 32] = [0xDD; 32];
    const SEIZE_PKS: [[u8; 32]; 3] = [[0x91; 32], [0x92; 32], [0x93; 32]];
    const RECOVERY_PKS: [[u8; 32]; 3] = [[0xB1; 32], [0xB2; 32], [0xB3; 32]];
    const ROOT: [u8; 32] = [0xCC; 32];
    const GENESIS: [u8; 32] = [0x77; 32];
    const RECIPIENT: [u8; 32] = [0xAA; 32];

    fn rs(running_supply: u64, current_cap: u64) -> Vec<u8> {
        build_mint_authority_redeem_script(
            running_supply,
            0,   // minted_this_epoch
            0,   // epoch_start_daa
            current_cap,
            current_cap, // pending_cap (sentinel: no announcement pending)
            0,           // pending_since_daa (sentinel: no announcement pending)
            &MINT_PK,
            &CAP_AUTH,
            &OPS_PK,
            &FREEZE_PK,
            &SEIZE_PKS,
            &RECOVERY_PKS,
            &ROOT,
            identifier_type::PUBKEY,
            &GENESIS,
            2,           // cap_raise_multiplier_k
            1_000,       // epoch_length_daa
            u64::MAX / 2, // epoch_mint_budget (generous, not under test here)
            100,         // min_activation_delay_daa
        )
    }

    #[test]
    fn mint_emits_sig_then_old_rs_then_new_rs_then_amount_then_recipient_then_optype_then_redeem_script() {
        let old_rs = rs(10_000, 1_000_000);
        let new_rs = rs(60_000, 1_000_000);
        let ss = build_mint_authority_mint_sigscript(&MINT_SIG, &old_rs, &new_rs, 50_000, &RECIPIENT, &old_rs);

        // Field 1 (deepest): mint_sig — OpData64 (0x40) + 64 raw bytes.
        assert_eq!(ss[0], 64);
        assert_eq!(&ss[1..65], &MINT_SIG);

        // Rather than hand-decode push_data's length-dependent opcode choice
        // (both old_rs/new_rs are well over 255 bytes, so they push via
        // PUSHDATA2), build the expected bytes with the SAME push_data
        // helper the builder uses and compare directly -- this still pins
        // the exact field ORDER and CONTENT.
        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&MINT_SIG));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&new_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&50_000u64.to_le_bytes()));
        expected.extend_from_slice(&crate::primitives::push_data(&RECIPIENT));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::mint_authority::attestation::op_type::MINT]));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn mint_accepts_oversized_recipient_slice() {
        // SUB-FIX A regression surface: recipient_pubkey is a raw &[u8], so
        // an oversized (33B) push can be expressed through the builder
        // itself, without hand-assembly, for the adversarial test in
        // `mint_authority_contracts.rs`.
        let old_rs = rs(10_000, 1_000_000);
        let mut oversized = RECIPIENT.to_vec();
        oversized.push(0xAA);
        assert_eq!(oversized.len(), 33);
        let ss = build_mint_authority_mint_sigscript(&MINT_SIG, &old_rs, &old_rs, 50_000, &oversized, &old_rs);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&MINT_SIG));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&50_000u64.to_le_bytes()));
        expected.extend_from_slice(&crate::primitives::push_data(&oversized));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::mint_authority::attestation::op_type::MINT]));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn announce_cap_emits_sig1_sig2_sig3_then_old_rs_then_new_rs_then_new_pending_cap_then_optype_then_redeem_script() {
        let old_rs = rs(10_000, 1_000_000);
        let new_rs = rs(10_000, 1_000_000);
        let ss = build_mint_authority_announce_cap_sigscript(&SIG1, &SIG2, &SIG3, &old_rs, &new_rs, 2_000_000, &old_rs);

        // Field 1 (deepest): sig1 — OpData64 (0x40) + 64 raw bytes.
        assert_eq!(ss[0], 64);
        assert_eq!(&ss[1..65], &SIG1);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&SIG1));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG2));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG3));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&new_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&2_000_000u64.to_le_bytes()));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::mint_authority::attestation::op_type::ANNOUNCE_CAP]));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn announce_cap_accepts_2pow63_new_pending_cap_without_panicking() {
        // Mirrors mint_authority_contracts.rs's
        // announce_cap_new_pending_cap_at_or_above_2pow63_rejected
        // regression: the builder itself performs no numeric-domain
        // validation (that lives in
        // MintAuthorityStateHeader::new_checked/check_numeric_domain) -- it
        // must faithfully push whatever raw u64 it is given, including the
        // 2^63 boundary value a real attacker could craft directly on the
        // wire.
        let old_rs = rs(10_000, 1_000_000);
        let new_pending_cap_raw: u64 = 1u64 << 63;
        let ss = build_mint_authority_announce_cap_sigscript(&SIG1, &SIG2, &SIG3, &old_rs, &old_rs, new_pending_cap_raw, &old_rs);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&SIG1));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG2));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG3));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&new_pending_cap_raw.to_le_bytes()));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::mint_authority::attestation::op_type::ANNOUNCE_CAP]));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn activate_cap_emits_old_rs_then_new_rs_then_optype_then_redeem_script() {
        let old_rs = rs(10_000, 1_000_000);
        let new_rs = rs(10_000, 2_000_000);
        let ss = build_mint_authority_activate_cap_sigscript(&old_rs, &new_rs, &old_rs);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&new_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::mint_authority::attestation::op_type::ACTIVATE_CAP]));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));

        assert_eq!(ss, expected);
    }
}
