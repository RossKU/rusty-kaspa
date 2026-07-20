//! Mint-authority contract **sigscript** (unlocking script) builders
//! (`STABLECOIN_ROBUST_DESIGN.md` §9 "Mint + Supply Cap").
//!
//! This is the spender side of [`super::body`]'s two-way `op_type` dispatch
//! (`MINT`, `op_type = 0x00` / `RAISE_CAP`, `op_type = 0x01`). Mirrors the
//! house style of `crate::contract::stablecoin::sigscript`: one
//! `build_mint_authority_*_sigscript` function per branch, each emitting
//! exactly the push-only bytes that branch's bytecode pops/rolls off the
//! stack, in the order it expects, with the redeem script pushed last (the
//! P2SH wrapper pops it first, before the body runs).
//!
//! # MINT (`op_type = 0x00`) push order
//!
//! Per [`super::body::build_mint_branch`]'s module doc, the entry stack once
//! the dispatch delivers control to the MINT branch is (top-to-bottom):
//! `current_cap(0), running_supply(1), recipient_pubkey(2), mint_amount(3),
//! new_rs(4), old_rs(5), mint_sig(6)` — `current_cap`/`running_supply` are
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
//! # RAISE_CAP (`op_type = 0x01`) push order
//!
//! Per [`super::body::build_raise_cap_branch`]'s module doc, the entry stack
//! once the dispatch delivers control to the RAISE_CAP branch is
//! (top-to-bottom): `current_cap(0), running_supply(1), new_cap(2),
//! new_rs(3), old_rs(4), sig3(5), sig2(6), sig1(7)`. The sigscript this
//! builder emits (first push == deepest) is:
//!
//! ```text
//! push sig1(64B) -> push sig2(64B) -> push sig3(64B) -> push old_rs
//!   -> push new_rs -> push new_cap(8B LE) -> push op_type_selector(1B, 0x01)
//!   -> pushData(redeem_script)
//! ```
//!
//! - **sig1**/**sig2**/**sig3** — FIXED POSITIONAL slots, the cold 2-of-3
//!   `cap_authority` quorum's raw 64-byte Schnorr signatures over
//!   [`super::attestation::build_raise_cap_attestation_message`]
//!   (`OpCheckSigFromStack`, **no** SIGHASH type byte), checked against
//!   `cap_authority_pubkeys[0]`/`[1]`/`[2]` respectively (mirroring
//!   `stablecoin::sigscript::build_stablecoin_seize_sigscript`'s SEIZE-quorum
//!   convention) — a holder of only 2 of the 3 keys supplies a genuine
//!   64-byte signature in their two slots and an arbitrary 64-byte
//!   placeholder (e.g. all-zero) in the third.
//! - **old_rs** — this input's own current redeemScript, authenticated
//!   on-chain via `dr_input_spk_check`.
//! - **new_rs** — the candidate self-continuation successor redeem script.
//! - **new_cap** — the new ceiling being raised to, folded into the
//!   attestation pre-image and checked against the successor's actual
//!   `current_cap` field.
//!
//! This input's `sig_op_count` MUST be **3** (three `OpCheckSigFromStack`
//! calls for the 2-of-3 `cap_authority` quorum — no owner signature, no
//! `mint_pubkey` involvement at all).

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

/// Build the mint-authority RAISE_CAP (`op_type = 0x01`) sigscript. See this
/// module's top doc for the derivation of the push order from
/// [`super::body::build_raise_cap_branch`]'s entry-stack layout.
///
/// `sig1`/`sig2`/`sig3` — FIXED POSITIONAL slots (checked against
/// `cap_authority_pubkeys[0]`/`[1]`/`[2]` respectively), each a raw 64-byte
/// Schnorr signature over
/// [`super::attestation::build_raise_cap_attestation_message`] (no SIGHASH
/// type byte; verified via `OpCheckSigFromStack`). A holder of only 2 of the
/// 3 keys supplies a genuine signature in two slots and an arbitrary 64-byte
/// placeholder in the third.
/// `old_rs` — this input's own current redeemScript (authenticated via
/// `dr_input_spk_check` on-chain).
/// `new_rs` — the candidate self-continuation successor redeem script.
/// `new_cap` — the new ceiling being raised to (encoded here as a fixed
/// 8-byte LE sigscript push).
/// `redeem_script` — the full mint-authority redeem script from
/// [`super::body::build_mint_authority_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_raise_cap_branch` (`body.rs`) expects: `sig1` deepest, then `sig2`,
/// then `sig3`, then `old_rs`, then `new_rs`, then `new_cap`, then the
/// `op_type_selector` (`0x01 == RAISE_CAP`), then the redeem script last.
pub fn build_mint_authority_raise_cap_sigscript(
    sig1: &[u8; 64],
    sig2: &[u8; 64],
    sig3: &[u8; 64],
    old_rs: &[u8],
    new_rs: &[u8],
    new_cap: u64,
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
    // Then the attested new_cap (8B LE u64).
    ss.extend_from_slice(&push_data(&new_cap.to_le_bytes()));
    // Then the op_type selector (0x01 == RAISE_CAP).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::RAISE_CAP]));
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
    const ROOT: [u8; 32] = [0xCC; 32];
    const GENESIS: [u8; 32] = [0x77; 32];
    const RECIPIENT: [u8; 32] = [0xAA; 32];

    fn rs(running_supply: u64, current_cap: u64) -> Vec<u8> {
        build_mint_authority_redeem_script(
            running_supply,
            current_cap,
            &MINT_PK,
            &CAP_AUTH,
            &OPS_PK,
            &FREEZE_PK,
            &SEIZE_PKS,
            &ROOT,
            identifier_type::PUBKEY,
            &GENESIS,
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
    fn raise_cap_emits_sig1_sig2_sig3_then_old_rs_then_new_rs_then_new_cap_then_optype_then_redeem_script() {
        let old_rs = rs(10_000, 1_000_000);
        let new_rs = rs(10_000, 2_000_000);
        let ss = build_mint_authority_raise_cap_sigscript(&SIG1, &SIG2, &SIG3, &old_rs, &new_rs, 2_000_000, &old_rs);

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
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::mint_authority::attestation::op_type::RAISE_CAP]));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn raise_cap_accepts_2pow63_new_cap_without_panicking() {
        // Mirrors mint_authority_contracts.rs's
        // raise_cap_new_cap_at_or_above_2pow63_rejected regression: the
        // builder itself performs no numeric-domain validation (that lives
        // in MintAuthorityStateHeader::new_checked/check_numeric_domain) --
        // it must faithfully push whatever raw u64 it is given, including
        // the 2^63 boundary value a real attacker could craft directly on
        // the wire.
        let old_rs = rs(10_000, 1_000_000);
        let new_cap_raw: u64 = 1u64 << 63;
        let ss = build_mint_authority_raise_cap_sigscript(&SIG1, &SIG2, &SIG3, &old_rs, &old_rs, new_cap_raw, &old_rs);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&SIG1));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG2));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG3));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&new_cap_raw.to_le_bytes()));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::mint_authority::attestation::op_type::RAISE_CAP]));
        expected.extend_from_slice(&crate::primitives::push_data(&old_rs));

        assert_eq!(ss, expected);
    }
}
