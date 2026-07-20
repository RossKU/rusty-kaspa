//! Robust KCC-0020 stablecoin covenant **sigscript** (unlocking script)
//! builder (`STABLECOIN_ROBUST_DESIGN.md` §4 -- Phase I: TRANSFER only).
//!
//! This is the spender side of the `body.rs` contract. It emits the
//! push-only signature script that, once the P2SH wrapper pops and executes
//! the redeem script, leaves the stack in the exact shape `body.rs`'s TRANSFER
//! branch consumes.
//!
//! # Layout the body requires (and this builder emits)
//!
//! After P2SH pops the redeem script, the body's entry stack must be, from
//! the spender's contributions, top-to-bottom:
//!
//! ```text
//! op_type_selector (1B: 0x00 for TRANSFER in Phase I)          <- top
//! owner_sig        (65B: 64-byte Schnorr sig || 0x01 SIGHASH_ALL)
//! new_rs           (variable: full candidate successor redeem script --
//!                    see body.rs module doc for why this is required)
//! issuer_sig       (64B: raw Schnorr sig over the attestation message)
//! ```
//!
//! Because a sigscript is push-only and the last push is the redeem script
//! (which P2SH pops first), the *emission* order is the reverse of the stack
//! depth: `issuer_sig` (ends up deepest) is pushed first, then `new_rs`, then
//! `owner_sig`, then `op_type_selector`, then the redeem script last:
//!
//! ```text
//! push issuer_sig(64B) -> push new_rs -> push owner_sig||0x01(65B)
//!   -> push op_type_selector(1B) -> pushData(redeem_script)
//! ```
//!
//! # Signature formats (must match the engine exactly)
//!
//! - **owner_sig** is a Schnorr signature over the transaction's SIGHASH_ALL
//!   sighash; the builder appends the `0x01` SIGHASH_ALL type byte.
//! - **issuer_sig** is a *raw* 64-byte Schnorr signature (OPS role, §2) over
//!   the 32-byte attestation message
//!   ([`super::attestation::build_attestation_message`]). It carries **no**
//!   SIGHASH type byte (not tx-bound on its own; the message's replay fields
//!   bind it instead).
//!
//! This input's `sig_op_count` MUST be **2** (one `OpCheckSigVerify` for the
//! owner + one `OpCheckSigFromStack` for the OPS role).

use crate::primitives::push_data;

/// SIGHASH_ALL type byte appended to the owner signature (the body's
/// `OpCheckSig` pops this byte to select the sighash type).
const SIGHASH_ALL: u8 = 0x01;

/// Build the robust stablecoin TRANSFER (`op_type = 0x00`) sigscript.
///
/// `owner_sig` — the owner's raw 64-byte Schnorr signature over the
/// transaction's SIGHASH_ALL sighash (the `0x01` type byte is appended here).
/// `issuer_sig` — the OPS role's raw 64-byte Schnorr signature over
/// [`super::attestation::build_attestation_message`] (no type byte).
/// `new_rs` — the full candidate successor redeem script (the plaintext
/// `body.rs`'s `dr_output_spk_check` authenticates against the real
/// successor output's P2SH commitment).
/// `redeem_script` — the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`].
///
/// The returned bytes are push-only and pop in the order the body expects.
pub fn build_stablecoin_transfer_sigscript(
    owner_sig: &[u8; 64],
    issuer_sig: &[u8; 64],
    new_rs: &[u8],
    redeem_script: &[u8],
) -> Vec<u8> {
    // Owner signature carries the SIGHASH_ALL type byte (65 bytes total).
    let mut owner_sig_with_type = Vec::with_capacity(65);
    owner_sig_with_type.extend_from_slice(owner_sig);
    owner_sig_with_type.push(SIGHASH_ALL);

    let mut ss = Vec::with_capacity(2 + 64 + 3 + new_rs.len() + 2 + 65 + 2 + 3 + redeem_script.len());
    // Deepest item: this coin's OWN redeem script, for the branch's template
    // authentication (audit 2026-07-20 section E -- the successor's body, where
    // every role pubkey is baked, was previously unchecked). These are the same
    // bytes pushed last for the P2SH wrapper, so no caller-visible field was
    // added; the branch proves the copy genuine against this input's own SPK
    // before comparing suffixes.
    ss.extend_from_slice(&push_data(redeem_script));
    // Emitted first -> ends up deepest on the stack: the OPS attestation sig.
    ss.extend_from_slice(&push_data(issuer_sig));
    // Then the candidate successor redeem script (plaintext, authenticated
    // on-chain against the real output's P2SH commitment).
    ss.extend_from_slice(&push_data(new_rs));
    // Then the owner authorization sig (65B: 64 Schnorr || 0x01 SIGHASH_ALL).
    ss.extend_from_slice(&push_data(&owner_sig_with_type));
    // Then the op_type selector (0x00 == TRANSFER, Phase I's only wired op).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::TRANSFER]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the robust stablecoin FREEZE (`op_type = 0x01`) sigscript.
///
/// No owner signature at all -- the FREEZE role alone gates this branch (§4).
/// `issuer_sig` -- the FREEZE role's raw 64-byte Schnorr signature over
/// [`super::attestation::build_freeze_attestation_message`] (no type byte).
/// `new_frozen_flag` -- the attested 0/1 value being set (§5's op-specific
/// preimage tail field); this is pushed as a 1-byte sigscript data item so
/// the body can both fold it into the on-chain preimage reconstruction AND
/// compare it against the successor's actual `frozen_flag` byte.
/// `new_rs` -- the full candidate successor redeem script (same
/// authenticate-then-slice mechanism as TRANSFER, see `body.rs`).
/// `redeem_script` -- the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_freeze_branch` (`body.rs`) expects: `issuer_sig` deepest, then
/// `new_rs`, then `new_frozen_flag`, then the `op_type_selector`
/// (`0x01 == FREEZE`), then the redeem script last.
pub fn build_stablecoin_freeze_sigscript(issuer_sig: &[u8; 64], new_frozen_flag: u8, new_rs: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(2 + 64 + 3 + new_rs.len() + 2 + 1 + 2 + 3 + redeem_script.len());
    // Deepest item: this coin's OWN redeem script, for the branch's template
    // authentication (audit 2026-07-20 section E -- the successor's body, where
    // every role pubkey is baked, was previously unchecked). These are the same
    // bytes pushed last for the P2SH wrapper, so no caller-visible field was
    // added; the branch proves the copy genuine against this input's own SPK
    // before comparing suffixes.
    ss.extend_from_slice(&push_data(redeem_script));
    // Emitted first -> ends up deepest on the stack: the FREEZE attestation sig.
    ss.extend_from_slice(&push_data(issuer_sig));
    // Then the candidate successor redeem script (plaintext, authenticated
    // on-chain against the real output's P2SH commitment).
    ss.extend_from_slice(&push_data(new_rs));
    // Then the attested new_frozen_flag (1B: 0x00 or 0x01).
    ss.extend_from_slice(&push_data(&[new_frozen_flag]));
    // Then the op_type selector (0x01 == FREEZE).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::FREEZE]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the robust stablecoin SEIZE (`op_type = 0x02`) sigscript.
///
/// No owner signature at all -- the issuer force-moves the coin without the
/// holder (§4/§7). Authorization is a 2-of-3 threshold over the three baked
/// SEIZE pubkeys (see `super::body::build_seize_branch`'s doc for why this is
/// three `OpCheckSigFromStack` calls rather than native `OpCheckMultiSig`).
///
/// `sig1`/`sig2`/`sig3` are FIXED POSITIONAL slots -- `sig1` is checked
/// against the FIRST baked SEIZE pubkey, `sig2` against the second, `sig3`
/// against the third (`seize_pubkeys[0]`/`[1]`/`[2]` in
/// [`super::body::build_stablecoin_redeem_script`]'s argument order). A
/// holder of only 2 of the 3 keys supplies a genuine 64-byte signature in
/// their two slots and an arbitrary 64-byte placeholder (e.g. all-zero) in
/// the third -- `OpCheckSigFromStack` parses any 64 bytes as a structurally
/// valid Schnorr signature and simply evaluates to `false` on a non-matching
/// key.
///
/// NOTE (Decision 2026-07-20-G0): MIGRATE's quorum is now a DIFFERENT
/// (independent `recovery_pubkeys`) key set from this SEIZE quorum --
/// they share only the `emit_2of3_threshold` bytecode SHAPE, not key
/// material, so `seize_pubkeys` signatures no longer authorize MIGRATE (see
/// [`build_stablecoin_migrate_sigscript`]'s doc).
/// `new_owner_pubkey` -- the attested target owner (§5's op-specific preimage
/// tail field); pushed as a 32-byte sigscript data item so the body can both
/// fold it into the on-chain preimage reconstruction AND compare it against
/// the successor's actual `owner_pubkey` field.
/// `new_rs` -- the full candidate successor redeem script (same
/// authenticate-then-slice mechanism as TRANSFER/FREEZE, see `body.rs`).
/// `redeem_script` -- the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_seize_branch` (`body.rs`) expects: `sig1` deepest, then `sig2`,
/// then `sig3`, then `new_rs`, then `new_owner_pubkey`, then the
/// `op_type_selector` (`0x02 == SEIZE`), then the redeem script last.
pub fn build_stablecoin_seize_sigscript(
    sig1: &[u8; 64],
    sig2: &[u8; 64],
    sig3: &[u8; 64],
    new_owner_pubkey: &[u8; 32],
    new_rs: &[u8],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut ss = Vec::with_capacity(
        3 * (2 + 64) + 3 + new_rs.len() + 2 + 32 + 2 + 3 + redeem_script.len(),
    );
    // Deepest item: this coin's OWN redeem script, for the branch's template
    // authentication (audit 2026-07-20 section E -- the successor's body, where
    // every role pubkey is baked, was previously unchecked). These are the same
    // bytes pushed last for the P2SH wrapper, so no caller-visible field was
    // added; the branch proves the copy genuine against this input's own SPK
    // before comparing suffixes.
    ss.extend_from_slice(&push_data(redeem_script));
    // Emitted first -> ends up deepest on the stack: the three SEIZE
    // attestation sigs, in fixed positional order (sig1, sig2, sig3).
    ss.extend_from_slice(&push_data(sig1));
    ss.extend_from_slice(&push_data(sig2));
    ss.extend_from_slice(&push_data(sig3));
    // Then the candidate successor redeem script (plaintext, authenticated
    // on-chain against the real output's P2SH commitment).
    ss.extend_from_slice(&push_data(new_rs));
    // Then the attested new_owner_pubkey (32B).
    ss.extend_from_slice(&push_data(new_owner_pubkey));
    // Then the op_type selector (0x02 == SEIZE).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::SEIZE]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the robust stablecoin BURN (`op_type = 0x03`) sigscript.
///
/// Two-of-two authorization, the SAME SHAPE as TRANSFER's owner
/// `OpCheckSigVerify` + role `OpCheckSigFromStack` -- but the attesting role
/// here is MINT (the mint-authority's supply key, §2/§9), not OPS, and there
/// is NO `new_rs` field at all: BURN's successor is a FIXED canonical
/// unspendable sink (`super::body::burn_sink_spk_bytes`, the P2SH wrapping of
/// `super::body::BURN_SINK_SCRIPT`), not a spender-supplied candidate
/// covenant -- so there is nothing for the SPENDER to reveal via sigscript
/// data. The body still authenticates the sink via `dr_output_spk_check`
/// (the same live-proven mechanism TRANSFER/FREEZE/SEIZE use for their
/// `new_rs`), just with the fixed `BURN_SINK_SCRIPT` constant pushed as a
/// literal directly in the body bytecode instead of read from the sigscript
/// -- see `build_burn_branch`'s doc (`body.rs`) for the full rationale
/// (including the live-discovered bug this fixes).
///
/// `owner_sig` -- the owner's raw 64-byte Schnorr signature over the
/// transaction's SIGHASH_ALL sighash (the `0x01` type byte is appended here).
/// `issuer_sig` -- the MINT role's raw 64-byte Schnorr signature over
/// [`super::attestation::build_attestation_message`] (`op_type =
/// op_type::BURN`, empty tail -- §5's BURN preimage is the 121-byte BASE
/// preimage verbatim, byte-identical in shape to TRANSFER's). No type byte
/// (not tx-bound on its own; the message's replay fields bind it instead).
/// `redeem_script` -- the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`].
///
/// The returned bytes are push-only and pop in the order `build_burn_branch`
/// (`body.rs`) expects: `issuer_sig` deepest, then `owner_sig`, then the
/// `op_type_selector` (`0x03 == BURN`), then the redeem script last.
pub fn build_stablecoin_burn_sigscript(owner_sig: &[u8; 64], issuer_sig: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    // Owner signature carries the SIGHASH_ALL type byte (65 bytes total).
    let mut owner_sig_with_type = Vec::with_capacity(65);
    owner_sig_with_type.extend_from_slice(owner_sig);
    owner_sig_with_type.push(SIGHASH_ALL);

    let mut ss = Vec::with_capacity(2 + 64 + 2 + 65 + 2 + 3 + redeem_script.len());
    // Emitted first -> ends up deepest on the stack: the MINT attestation sig.
    ss.extend_from_slice(&push_data(issuer_sig));
    // Then the owner authorization sig (65B: 64 Schnorr || 0x01 SIGHASH_ALL).
    ss.extend_from_slice(&push_data(&owner_sig_with_type));
    // Then the op_type selector (0x03 == BURN).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::BURN]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the robust stablecoin MIGRATE (`op_type = 0x06`) sigscript.
///
/// Owner `OpCheckSigVerify` PLUS a cold 2-of-3 quorum over the three baked
/// **recovery** keys (Decision 2026-07-20-G0: MIGRATE moves the coin to an
/// arbitrary template, so a hot-key authorizer made it a governance-exit
/// hole -- see `super::body::build_migrate_branch`'s "Authorizer" doc
/// section). An earlier revision (Decision 2026-07-20) gated MIGRATE behind
/// the SAME `seize_pubkeys` quorum SEIZE uses; that was a G0-CRITICAL bug
/// (a leaked SEIZE quorum also destroyed the recovery path) fixed by giving
/// MIGRATE its OWN independent `recovery_pubkeys` cold 2-of-3 set. The
/// quorum uses the SAME fixed positional convention and the SAME bytecode
/// SHAPE as SEIZE (`emit_2of3_threshold`), but different, independent KEY
/// MATERIAL. There is NO `new_rs` field at all (unlike TRANSFER/FREEZE/SEIZE):
/// MIGRATE's successor is an ARBITRARY new covenant template whose fields
/// this covenant never reads or carries forward (§4: "coin moves to new
/// redeem-script template"), so the body only needs the successor's SPK
/// HASH (`new_template_hash`), not its plaintext redeem-script bytes.
///
/// `owner_sig` -- the owner's raw 64-byte Schnorr signature over the
/// transaction's SIGHASH_ALL sighash (the `0x01` type byte is appended here).
/// `sig1`/`sig2`/`sig3` -- the independent recovery-quorum members' raw
/// 64-byte Schnorr signatures over
/// [`super::attestation::build_migrate_attestation_message`] (no type byte),
/// in fixed positional correspondence with the baked
/// `recovery_pubkeys[0]`/`[1]`/`[2]` (NOT `seize_pubkeys` -- see this fn's
/// doc above). Any TWO must be valid; the unused slot takes a 64-byte filler
/// (e.g. all-zero), exactly as SEIZE does.
/// `new_template_hash` -- the attested `Blake3` hash of the successor
/// output's SPK (§5's op-specific preimage tail field); pushed as a 32-byte
/// sigscript data item so the body can both fold it into the on-chain
/// preimage reconstruction AND compare it against the successor's ACTUAL
/// `OpTxOutputSpk`-derived hash.
/// `redeem_script` -- the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_migrate_branch` (`body.rs`) expects: `sig1` deepest, then `sig2`,
/// `sig3`, `new_template_hash`, `owner_sig`, then the `op_type_selector`
/// (`0x06 == MIGRATE`), then the redeem script last.
pub fn build_stablecoin_migrate_sigscript(
    owner_sig: &[u8; 64],
    sig1: &[u8; 64],
    sig2: &[u8; 64],
    sig3: &[u8; 64],
    new_template_hash: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<u8> {
    // Owner signature carries the SIGHASH_ALL type byte (65 bytes total).
    let mut owner_sig_with_type = Vec::with_capacity(65);
    owner_sig_with_type.extend_from_slice(owner_sig);
    owner_sig_with_type.push(SIGHASH_ALL);

    let mut ss = Vec::with_capacity(3 * (2 + 64) + 2 + 32 + 2 + 65 + 2 + 3 + redeem_script.len());
    // Emitted first -> ends up deepest on the stack: the three independent
    // recovery-quorum attestation sigs, in the SAME fixed positional SHAPE
    // SEIZE uses (sig1<->recovery_pubkeys[0], sig2<->[1], sig3<->[2]) but
    // over DIFFERENT, independent key material (Decision 2026-07-20-G0).
    ss.extend_from_slice(&push_data(sig1));
    ss.extend_from_slice(&push_data(sig2));
    ss.extend_from_slice(&push_data(sig3));
    // Then the attested new_template_hash (32B: Blake3 of the successor SPK).
    ss.extend_from_slice(&push_data(new_template_hash));
    // Then the owner authorization sig (65B: 64 Schnorr || 0x01 SIGHASH_ALL).
    ss.extend_from_slice(&push_data(&owner_sig_with_type));
    // Then the op_type selector (0x06 == MIGRATE).
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::MIGRATE]));
    // Redeem script last: the P2SH wrapper pops it first, before the body runs.
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the robust stablecoin TRANSFER_NM (`op_type = 0x07`, N:M leader)
/// sigscript. See `super::body::build_transfer_nm_branch`'s doc for the
/// group design/scope.
///
/// `self_rs` -- this coin's OWN redeem script (template-authentication copy,
/// same convention as every other branch's `self_rs`).
/// `issuer_sig` -- the OPS role's raw 64-byte Schnorr signature over
/// [`super::attestation::build_transfer_nm_attestation_message`] (no type
/// byte), covering the WHOLE group (leader + siblings + successors) in one
/// signature.
/// `new_rs_slots` -- `new_rs_slots[0]` is successor slot 1 (`new_rs_1`), ..,
/// `new_rs_slots[MAX_N-1]` is successor slot `MAX_N` (`new_rs_MAX_N`); pad
/// unused (beyond the real successor count) slots with an empty `Vec` --
/// they are never read on-chain (guarded by `j <= OpCovOutputCount`).
/// `owner_sig` -- the leader's own owner's raw 64-byte Schnorr signature over
/// the transaction's SIGHASH_ALL sighash (the `0x01` type byte is appended
/// here).
/// `redeem_script` -- the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`].
///
/// The returned bytes are push-only and pop in the order
/// `build_transfer_nm_branch` (`body.rs`) expects: `self_rs` deepest, then
/// `issuer_sig`, then `new_rs_MAX_N`, .., `new_rs_1`, then `owner_sig`, then
/// the `op_type_selector` (`0x07 == TRANSFER_NM`), then the redeem script
/// last.
pub fn build_stablecoin_transfer_nm_leader_sigscript(
    self_rs: &[u8],
    issuer_sig: &[u8; 64],
    new_rs_slots: &[Vec<u8>; super::body::TRANSFER_NM_MAX_N],
    owner_sig: &[u8; 64],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut owner_sig_with_type = Vec::with_capacity(65);
    owner_sig_with_type.extend_from_slice(owner_sig);
    owner_sig_with_type.push(SIGHASH_ALL);

    let mut ss = Vec::new();
    ss.extend_from_slice(&push_data(self_rs));
    ss.extend_from_slice(&push_data(issuer_sig));
    for slot in new_rs_slots.iter().rev() {
        // rev(): new_rs_MAX_N (slots[MAX_N-1]) pushed first (deepest), ..,
        // new_rs_1 (slots[0]) pushed last (shallowest, right before owner_sig).
        ss.extend_from_slice(&push_data(slot));
    }
    ss.extend_from_slice(&push_data(&owner_sig_with_type));
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::TRANSFER_NM]));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

/// Build the robust stablecoin TRANSFER_NM_DELEGATOR (`op_type = 0x08`)
/// sigscript: `self_sig, op_type_selector`. Self-authorizes only -- does not
/// re-verify the group attestation (see `build_transfer_nm_branch`'s doc).
///
/// `self_sig` -- this delegator's OWN raw 64-byte Schnorr signature over the
/// transaction's SIGHASH_ALL sighash (the `0x01` type byte is appended here).
/// `redeem_script` -- the full stablecoin redeem script from
/// [`super::body::build_stablecoin_redeem_script`].
pub fn build_stablecoin_transfer_nm_delegator_sigscript(self_sig: &[u8; 64], redeem_script: &[u8]) -> Vec<u8> {
    let mut self_sig_with_type = Vec::with_capacity(65);
    self_sig_with_type.extend_from_slice(self_sig);
    self_sig_with_type.push(SIGHASH_ALL);

    let mut ss = Vec::new();
    ss.extend_from_slice(&push_data(&self_sig_with_type));
    ss.extend_from_slice(&push_data(&[super::attestation::op_type::TRANSFER_NM_DELEGATOR]));
    ss.extend_from_slice(&push_data(redeem_script));
    ss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::stablecoin::body::build_stablecoin_redeem_script;
    use crate::contract::stablecoin::state::frozen_flag;
    use crate::contract::token::identifier_type;

    const OWNER_SIG: [u8; 64] = [0x11; 64];
    const ISSUER_SIG: [u8; 64] = [0x22; 64];
    const FREEZE_PK: [u8; 32] = [0xDD; 32];
    const SEIZE_PKS: [[u8; 32]; 3] = [[0x91; 32], [0x92; 32], [0x93; 32]];
    const RECOVERY_PKS: [[u8; 32]; 3] = [[0xA1; 32], [0xA2; 32], [0xA3; 32]];
    const MINT_PK: [u8; 32] = [0xFA; 32];

    fn rs() -> Vec<u8> {
        build_stablecoin_redeem_script(
            &[0xAA; 32],
            identifier_type::PUBKEY,
            &[0xEE; 32],
            frozen_flag::CLEAR,
            0,
            &[0xBB; 32],
            &FREEZE_PK,
            &SEIZE_PKS,
            &RECOVERY_PKS,
            &MINT_PK,
        )
    }

    fn sample_new_rs() -> Vec<u8> {
        build_stablecoin_redeem_script(
            &[0xCC; 32],
            identifier_type::PUBKEY,
            &[0xEE; 32],
            frozen_flag::CLEAR,
            0,
            &[0xBB; 32],
            &FREEZE_PK,
            &SEIZE_PKS,
            &RECOVERY_PKS,
            &MINT_PK,
        )
    }

    #[test]
    fn emits_issuer_then_new_rs_then_owner_then_optype_then_redeem_script() {
        let rs = rs();
        let new_rs = sample_new_rs();
        let ss = build_stablecoin_transfer_sigscript(&OWNER_SIG, &ISSUER_SIG, &new_rs, &rs);

        // Field 1 (deepest) is now self_rs (the template-authentication copy);
        // the attestation sig follows it.
        let self_rs_push = crate::primitives::push_data(&rs);
        assert_eq!(&ss[..self_rs_push.len()], &self_rs_push[..]);
        let after = &ss[self_rs_push.len()..];
        assert_eq!(after[0], 64);
        assert_eq!(&after[1..65], &ISSUER_SIG);

        // Fields 2-5: rather than hand-decode `push_data`'s length-dependent
        // opcode choice (OpDataN / PUSHDATA1 / PUSHDATA2 depending on payload
        // size -- the Phase I redeem script is now well over 255 bytes, so
        // both `new_rs` and `rs` push via PUSHDATA2, not the smaller scripts'
        // PUSHDATA1), build the expected bytes with the SAME `push_data`
        // helper the builder uses and compare directly. This still pins the
        // exact field ORDER and CONTENT (including the owner sig's appended
        // SIGHASH_ALL byte and the TRANSFER op_type selector), without a
        // brittle assumption about any field's absolute byte length.
        let mut owner_sig_with_type = OWNER_SIG.to_vec();
        owner_sig_with_type.push(SIGHASH_ALL);

        let mut expected = Vec::new();
        // self_rs (deepest): the template-authentication copy, same bytes as
        // the trailing P2SH push.
        expected.extend_from_slice(&crate::primitives::push_data(&rs));
        expected.extend_from_slice(&crate::primitives::push_data(&ISSUER_SIG));
        expected.extend_from_slice(&crate::primitives::push_data(&new_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&owner_sig_with_type));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::attestation::op_type::TRANSFER]));
        expected.extend_from_slice(&crate::primitives::push_data(&rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn freeze_emits_issuer_then_new_rs_then_flag_then_optype_then_redeem_script() {
        let rs = rs();
        // FREEZE's successor is identical except frozen_flag; reuse `rs()`'s
        // owner/root/epoch/keys, just flip frozen_flag in the successor.
        let new_rs = build_stablecoin_redeem_script(
            &[0xAA; 32],
            identifier_type::PUBKEY,
            &[0xEE; 32],
            frozen_flag::SET,
            0,
            &[0xBB; 32],
            &FREEZE_PK,
            &SEIZE_PKS,
            &RECOVERY_PKS,
            &MINT_PK,
        );
        let ss = build_stablecoin_freeze_sigscript(&ISSUER_SIG, frozen_flag::SET, &new_rs, &rs);

        // Field 1 (deepest) is now self_rs; the attestation sig follows it.
        let self_rs_push = crate::primitives::push_data(&rs);
        assert_eq!(&ss[..self_rs_push.len()], &self_rs_push[..]);
        let after = &ss[self_rs_push.len()..];
        assert_eq!(after[0], 64);
        assert_eq!(&after[1..65], &ISSUER_SIG);

        let mut expected = Vec::new();
        // self_rs (deepest): the template-authentication copy, same bytes as
        // the trailing P2SH push.
        expected.extend_from_slice(&crate::primitives::push_data(&rs));
        expected.extend_from_slice(&crate::primitives::push_data(&ISSUER_SIG));
        expected.extend_from_slice(&crate::primitives::push_data(&new_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&[frozen_flag::SET]));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::attestation::op_type::FREEZE]));
        expected.extend_from_slice(&crate::primitives::push_data(&rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn seize_emits_sig1_sig2_sig3_then_new_rs_then_new_owner_then_optype_then_redeem_script() {
        let rs = rs();
        // SEIZE's successor carries a NEW owner_pubkey; reuse `rs()`'s
        // root/epoch/keys, just replace owner in the successor.
        const SIG1: [u8; 64] = [0x31; 64];
        const SIG2: [u8; 64] = [0x32; 64];
        const SIG3: [u8; 64] = [0x33; 64];
        const NEW_OWNER: [u8; 32] = [0xFE; 32];
        let new_rs = build_stablecoin_redeem_script(
            &NEW_OWNER,
            identifier_type::PUBKEY,
            &[0xEE; 32],
            frozen_flag::CLEAR,
            0,
            &[0xBB; 32],
            &FREEZE_PK,
            &SEIZE_PKS,
            &RECOVERY_PKS,
            &MINT_PK,
        );
        let ss = build_stablecoin_seize_sigscript(&SIG1, &SIG2, &SIG3, &NEW_OWNER, &new_rs, &rs);

        // Field 1 (deepest) is now self_rs; sig1 follows it.
        let self_rs_push = crate::primitives::push_data(&rs);
        assert_eq!(&ss[..self_rs_push.len()], &self_rs_push[..]);
        let after = &ss[self_rs_push.len()..];
        assert_eq!(after[0], 64);
        assert_eq!(&after[1..65], &SIG1);

        let mut expected = Vec::new();
        // self_rs (deepest): the template-authentication copy, same bytes as
        // the trailing P2SH push.
        expected.extend_from_slice(&crate::primitives::push_data(&rs));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG1));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG2));
        expected.extend_from_slice(&crate::primitives::push_data(&SIG3));
        expected.extend_from_slice(&crate::primitives::push_data(&new_rs));
        expected.extend_from_slice(&crate::primitives::push_data(&NEW_OWNER));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::attestation::op_type::SEIZE]));
        expected.extend_from_slice(&crate::primitives::push_data(&rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn burn_emits_issuer_then_owner_then_optype_then_redeem_script() {
        // BURN has NO new_rs field (unlike TRANSFER/FREEZE/SEIZE): the
        // successor is the FIXED canonical sink, not a spender-supplied
        // candidate.
        let rs = rs();
        const OWNER_SIG2: [u8; 64] = [0x41; 64];
        const ISSUER_SIG2: [u8; 64] = [0x42; 64];
        let ss = build_stablecoin_burn_sigscript(&OWNER_SIG2, &ISSUER_SIG2, &rs);

        // Field 1 (deepest): issuer_sig — OpData64 (0x40) + 64 raw bytes.
        assert_eq!(ss[0], 64);
        assert_eq!(&ss[1..65], &ISSUER_SIG2);

        let mut owner_sig_with_type = OWNER_SIG2.to_vec();
        owner_sig_with_type.push(SIGHASH_ALL);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&ISSUER_SIG2));
        expected.extend_from_slice(&crate::primitives::push_data(&owner_sig_with_type));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::attestation::op_type::BURN]));
        expected.extend_from_slice(&crate::primitives::push_data(&rs));

        assert_eq!(ss, expected);
    }

    #[test]
    fn migrate_emits_quorum_sigs_then_new_template_hash_then_owner_then_optype_then_redeem_script() {
        // MIGRATE has NO new_rs field (like BURN, unlike TRANSFER/FREEZE/
        // SEIZE): the successor is an arbitrary new template identified only
        // by its attested SPK hash, not a spender-supplied plaintext blob.
        // Since Decision 2026-07-20-G0 the authorizer is MIGRATE's OWN
        // independent cold 2-of-3 recovery quorum (NOT seize_pubkeys), so
        // three sig slots are still emitted (SEIZE's positional SHAPE, over
        // different key material -- this builder itself is signature-agnostic,
        // so the change is invisible at this call site).
        let rs = rs();
        const OWNER_SIG3: [u8; 64] = [0x51; 64];
        const MIG_SIG1: [u8; 64] = [0x52; 64];
        const MIG_SIG2: [u8; 64] = [0x53; 64];
        const MIG_SIG3: [u8; 64] = [0x54; 64];
        const NEW_TEMPLATE_HASH: [u8; 32] = [0x77; 32];
        let ss = build_stablecoin_migrate_sigscript(&OWNER_SIG3, &MIG_SIG1, &MIG_SIG2, &MIG_SIG3, &NEW_TEMPLATE_HASH, &rs);

        // Field 1 (deepest): sig1 — OpData64 (0x40) + 64 raw bytes.
        assert_eq!(ss[0], 64);
        assert_eq!(&ss[1..65], &MIG_SIG1);

        let mut owner_sig_with_type = OWNER_SIG3.to_vec();
        owner_sig_with_type.push(SIGHASH_ALL);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::primitives::push_data(&MIG_SIG1));
        expected.extend_from_slice(&crate::primitives::push_data(&MIG_SIG2));
        expected.extend_from_slice(&crate::primitives::push_data(&MIG_SIG3));
        expected.extend_from_slice(&crate::primitives::push_data(&NEW_TEMPLATE_HASH));
        expected.extend_from_slice(&crate::primitives::push_data(&owner_sig_with_type));
        expected.extend_from_slice(&crate::primitives::push_data(&[crate::contract::stablecoin::attestation::op_type::MIGRATE]));
        expected.extend_from_slice(&crate::primitives::push_data(&rs));

        assert_eq!(ss, expected);
    }
}
