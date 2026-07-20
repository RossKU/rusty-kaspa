//! Mint-authority contract — mutable state header (`STABLECOIN_ROBUST_DESIGN.md`
//! §9: "the mint-authority contract carries the running-supply counter ...
//! read, incremented by `mint_amount`, and re-written into its own
//! self-continuation successor on every MINT spend"; extended 2026-07-20 by
//! the mint-authority hardening item for G4 RAISE_CAP ceiling+timelock and G5
//! MINT epoch budget+dust floor).
//!
//! Framed exactly like [`super::super::state::StablecoinStateHeader`]: each
//! field carries its own literal push-opcode immediately preceding its raw
//! payload (no extra length-prefix byte beyond the opcode itself).
//!
//! Field-ownership-driven layout (chosen so every branch's "don't touch"
//! check stays a single [`crate::contract::dr::dr_prefix_check`]/
//! [`crate::contract::dr::dr_suffix_check`] call, never a bespoke interior
//! field lock):
//!
//! ```text
//! offset  opcode  field                width  who mutates
//! 0       0x08    running_supply       8B     MINT
//! 9       0x08    minted_this_epoch    8B     MINT       (G5 epoch budget)
//! 18      0x08    epoch_start_daa      8B     MINT       (G5 epoch budget)
//! 27      0x08    current_cap          8B     ACTIVATE_CAP (G4)
//! 36      0x08    pending_cap          8B     ANNOUNCE_CAP + ACTIVATE_CAP (G4)
//! 45      0x08    pending_since_daa    8B     ANNOUNCE_CAP (sets) + ACTIVATE_CAP
//!                                              (resets to 0) (G4 timelock-griefing
//!                                              FIX, 2026-07-20)
//! ```
//!
//! Total header: `6 * (1 + 8) = 54` bytes. Body follows immediately at
//! offset 54.
//!
//! `pending_since_daa` (FIX 1, 2026-07-20 mint-authority hardening audit):
//! records the DAA score at which the CURRENTLY-PENDING `ANNOUNCE_CAP`
//! happened (`OpTxInputDaaScore` of the announcing input — an unforgeable
//! real past height), or `0` as the sentinel "no announcement pending"
//! value. This closes a griefing hole in the OLD design, which gated
//! `ACTIVATE_CAP` with `push(min_activation_delay_daa) OpCheckSequenceVerify`
//! — CSV enforces its floor against the SELF-CONTINUING UTXO's own
//! `block_daa_score`, which every routine MINT re-stamps (MINT recreates the
//! authority UTXO on every spend), resetting the CSV clock. A hot
//! `mint_pubkey` holder could therefore mint dust once per window to block a
//! cap-authority-approved activation forever. Storing the announce height IN
//! STATE instead means MINT (which must carry `pending_since_daa` forward
//! byte-identical, like `current_cap`/`pending_cap`) cannot push it, so
//! `ACTIVATE_CAP`'s timelock (`pending_since_daa + min_activation_delay_daa
//! <= OpTxInputDaaScore` of the ACTIVATING input) is measured from the
//! ORIGINAL announce, immune to interleaved mints.
//!
//! Every field is placed so each branch's mutated region is a CONTIGUOUS
//! run at one end of the header (or, for `ACTIVATE_CAP`, the trailing triple
//! `current_cap`+`pending_cap`+`pending_since_daa`):
//! - **MINT** mutates the leading run `[0..27)` (`running_supply`,
//!   `minted_this_epoch`, `epoch_start_daa`) and must carry `[27..end)`
//!   (`current_cap`, `pending_cap`, `pending_since_daa`, the whole baked
//!   body) forward byte-identical — one
//!   [`crate::contract::dr::dr_suffix_check`] from `CURRENT_CAP_OPCODE_OFFSET`
//!   (the suffix check's begin-offset is unchanged by the new field, and its
//!   end always tracks the redeem script's real length via `OpSize`, so
//!   widening `STATE_HEADER_LEN` automatically extends the carried-unchanged
//!   region to cover `pending_since_daa` too, with no code change needed in
//!   the MINT branch beyond dropping the new live-pushed field in Step 0).
//! - **ANNOUNCE_CAP** mutates the trailing PAIR `pending_cap`+
//!   `pending_since_daa` (`[36..54)`) and must carry `[0..36)` (everything
//!   else in the header) forward unchanged — one
//!   [`crate::contract::dr::dr_prefix_check`] up to
//!   `PENDING_CAP_OPCODE_OFFSET`, plus one
//!   [`crate::contract::dr::dr_suffix_check`] from `STATE_HEADER_LEN` for the
//!   baked body. (Two D&R calls, not one, because the mutated fields sit
//!   between two protected regions — exactly the same shape the OLD 2-field
//!   layout's RAISE_CAP branch already used for `current_cap`; here the
//!   "gap" the two checks leave uncovered is `[36..54)`, automatically
//!   widened from `[36..45)` by `STATE_HEADER_LEN`'s growth.)
//! - **ACTIVATE_CAP** mutates the trailing TRIPLE `current_cap`+
//!   `pending_cap`+`pending_since_daa` (`[27..54)`: `current_cap` and
//!   `pending_cap` both promoted to the OLD `pending_cap` value,
//!   `pending_since_daa` reset to `0`) and must carry `[0..27)` forward
//!   unchanged — one [`crate::contract::dr::dr_prefix_check`] up to
//!   `CURRENT_CAP_OPCODE_OFFSET`, plus one
//!   [`crate::contract::dr::dr_suffix_check`] from `STATE_HEADER_LEN` for the
//!   baked body.
//!
//! `running_supply` stays FIRST (offset 0), preserving the original
//! contiguous-prefix property MINT's D&R relies on.

/// Byte offset of `running_supply`'s push opcode (`0x08`).
pub const RUNNING_SUPPLY_OPCODE_OFFSET: usize = 0;
/// Byte offset of `running_supply`'s 8-byte (LE) payload.
pub const RUNNING_SUPPLY_PAYLOAD_OFFSET: usize = 1;
/// Byte offset of `minted_this_epoch`'s push opcode (`0x08`).
pub const MINTED_THIS_EPOCH_OPCODE_OFFSET: usize = 9;
/// Byte offset of `minted_this_epoch`'s 8-byte (LE) payload.
pub const MINTED_THIS_EPOCH_PAYLOAD_OFFSET: usize = 10;
/// Byte offset of `epoch_start_daa`'s push opcode (`0x08`).
pub const EPOCH_START_DAA_OPCODE_OFFSET: usize = 18;
/// Byte offset of `epoch_start_daa`'s 8-byte (LE) payload.
pub const EPOCH_START_DAA_PAYLOAD_OFFSET: usize = 19;
/// Byte offset of `current_cap`'s push opcode (`0x08`).
pub const CURRENT_CAP_OPCODE_OFFSET: usize = 27;
/// Byte offset of `current_cap`'s 8-byte (LE) payload.
pub const CURRENT_CAP_PAYLOAD_OFFSET: usize = 28;
/// Byte offset of `pending_cap`'s push opcode (`0x08`).
pub const PENDING_CAP_OPCODE_OFFSET: usize = 36;
/// Byte offset of `pending_cap`'s 8-byte (LE) payload.
pub const PENDING_CAP_PAYLOAD_OFFSET: usize = 37;
/// Byte offset of `pending_since_daa`'s push opcode (`0x08`) (FIX 1,
/// 2026-07-20 timelock-griefing hardening).
pub const PENDING_SINCE_DAA_OPCODE_OFFSET: usize = 45;
/// Byte offset of `pending_since_daa`'s 8-byte (LE) payload.
pub const PENDING_SINCE_DAA_PAYLOAD_OFFSET: usize = 46;

/// Total script-encoded length of the mint-authority state header.
pub const STATE_HEADER_LEN: usize = 54;

/// Decoded mint-authority state header (§9, extended 2026-07-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintAuthorityStateHeader {
    pub running_supply: u64,
    /// Sompi minted so far in the CURRENT epoch window (G5 budget). Reset to
    /// `mint_amount` whenever a MINT crosses the epoch boundary.
    pub minted_this_epoch: u64,
    /// DAA score at which the current epoch window began (G5 budget).
    pub epoch_start_daa: u64,
    /// The ACTIVE supply ceiling MINT's `new_running_supply <= current_cap`
    /// check enforces. Only `ACTIVATE_CAP` may change it (promoting
    /// `pending_cap` into it after the G4 timelock).
    pub current_cap: u64,
    /// The ceiling `ACTIVATE_CAP` will promote into `current_cap` once its
    /// timelock clears. Written by `ANNOUNCE_CAP` (subject to the G4
    /// ceiling check `new_pending_cap <= current_cap * K`); also
    /// re-asserted (unchanged) by `ACTIVATE_CAP`'s own successor.
    pub pending_cap: u64,
    /// The DAA score at which the currently-pending `ANNOUNCE_CAP` happened
    /// (FIX 1, 2026-07-20 timelock-griefing hardening), or `0` as the
    /// sentinel "no announcement pending" value. Written by `ANNOUNCE_CAP`
    /// (to the announcing input's own `OpTxInputDaaScore`), carried forward
    /// byte-identical by MINT (so a hot mint key cannot reset the clock by
    /// re-stamping the self-continuation UTXO's `block_daa_score`), and
    /// reset to `0` by `ACTIVATE_CAP` on promotion. See this module's top
    /// doc for the full griefing-fix rationale.
    pub pending_since_daa: u64,
}

impl MintAuthorityStateHeader {
    /// In debug builds this asserts the numeric domain (every field
    /// `< 2^63`, SUB-FIX E); [`Self::new_checked`] gives a release-mode
    /// check, mirroring `stablecoin::attestation::build_attestation_preimage`'s
    /// debug_assert-plus-`check_numeric_domain` precedent.
    pub fn new(
        running_supply: u64,
        minted_this_epoch: u64,
        epoch_start_daa: u64,
        current_cap: u64,
        pending_cap: u64,
        pending_since_daa: u64,
    ) -> Self {
        for (name, v) in [
            ("running_supply", running_supply),
            ("minted_this_epoch", minted_this_epoch),
            ("epoch_start_daa", epoch_start_daa),
            ("current_cap", current_cap),
            ("pending_cap", pending_cap),
            ("pending_since_daa", pending_since_daa),
        ] {
            debug_assert!(v < super::attestation::MAX_AMOUNT_EXCLUSIVE, "{name} must be < 2^63 to match the on-chain sign-magnitude script-number domain");
        }
        Self { running_supply, minted_this_epoch, epoch_start_daa, current_cap, pending_cap, pending_since_daa }
    }

    /// Fallible constructor (SUB-FIX E, numeric-domain bound): rejects any
    /// field >= 2^63 -- at or above that bound the field's raw 8-byte LE
    /// encoding has its sign bit set, so the body's sign-magnitude
    /// script-number arithmetic would read it as non-positive instead of the
    /// intended u64 magnitude. Mirrors `super::attestation::check_numeric_domain`'s
    /// release-mode-check role; off-chain callers constructing state
    /// (genesis deploy, or predicting a MINT/ANNOUNCE_CAP/ACTIVATE_CAP
    /// successor header) should prefer this over `new`, which stays
    /// infallible (only debug-asserting the bound) for internal/hot-path
    /// callers that have already validated their inputs.
    pub fn new_checked(
        running_supply: u64,
        minted_this_epoch: u64,
        epoch_start_daa: u64,
        current_cap: u64,
        pending_cap: u64,
        pending_since_daa: u64,
    ) -> Result<Self, super::attestation::MintAuthorityError> {
        super::attestation::check_numeric_domain(running_supply)?;
        super::attestation::check_numeric_domain(minted_this_epoch)?;
        super::attestation::check_numeric_domain(epoch_start_daa)?;
        super::attestation::check_numeric_domain(current_cap)?;
        super::attestation::check_numeric_domain(pending_cap)?;
        super::attestation::check_numeric_domain(pending_since_daa)?;
        Ok(Self::new(running_supply, minted_this_epoch, epoch_start_daa, current_cap, pending_cap, pending_since_daa))
    }

    /// Genesis-only constructor (FIX 3, 2026-07-20 audit: "genesis
    /// pending_cap==current_cap not enforced"). A fresh deploy has no
    /// `MINT`/`ANNOUNCE_CAP`/`ACTIVATE_CAP` history yet, so `minted_this_epoch`/
    /// `epoch_start_daa` start at `0` and `pending_cap`/`pending_since_daa`
    /// start at the sentinel "no announcement pending" values
    /// (`current_cap`/`0`) UNCONDITIONALLY -- because `ACTIVATE_CAP` is
    /// PERMISSIONLESS, a deploy-time misconfiguration setting
    /// `pending_cap > current_cap` at genesis would let ANYONE immediately
    /// promote an unvetted cap that never went through `ANNOUNCE_CAP`'s cold
    /// 2-of-3 quorum. Rather than merely asserting the relationship (which
    /// would have to reject some caller-supplied values), this constructor
    /// doesn't accept `pending_cap`/`pending_since_daa` as independent
    /// params at all, eliminating the misconfiguration class entirely for
    /// callers who deploy through it; the two `assert_eq!`s below are a
    /// belt-and-suspenders guard against a future refactor accidentally
    /// re-introducing independent params here (mirrors the code-level-guard
    /// style of the existing `cap_raise_multiplier_k >= 2` assert in
    /// `super::body::build_mint_authority_redeem_script`).
    pub fn new_genesis(running_supply: u64, current_cap: u64) -> Self {
        let pending_cap = current_cap;
        let pending_since_daa = 0u64;
        assert_eq!(pending_cap, current_cap, "mint-authority genesis: pending_cap must equal current_cap (no announcement pending at deploy)");
        assert_eq!(pending_since_daa, 0, "mint-authority genesis: pending_since_daa must be 0 (no announcement pending at deploy)");
        Self::new(running_supply, 0, 0, current_cap, pending_cap, pending_since_daa)
    }

    /// Encode the script-encoded state header (the "Writer" side).
    pub fn encode_script(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STATE_HEADER_LEN);
        out.push(0x08);
        out.extend_from_slice(&self.running_supply.to_le_bytes());
        out.push(0x08);
        out.extend_from_slice(&self.minted_this_epoch.to_le_bytes());
        out.push(0x08);
        out.extend_from_slice(&self.epoch_start_daa.to_le_bytes());
        out.push(0x08);
        out.extend_from_slice(&self.current_cap.to_le_bytes());
        out.push(0x08);
        out.extend_from_slice(&self.pending_cap.to_le_bytes());
        out.push(0x08);
        out.extend_from_slice(&self.pending_since_daa.to_le_bytes());
        debug_assert_eq!(out.len(), STATE_HEADER_LEN);
        out
    }

    /// Decode the leading header fields from a redeemScript (the "Reader"
    /// side). Bytes beyond `STATE_HEADER_LEN` (body opcodes) are ignored.
    /// Returns `None` if the input is too short or any push opcode doesn't
    /// match the expected layout.
    pub fn decode(script: &[u8]) -> Option<Self> {
        if script.len() < STATE_HEADER_LEN {
            return None;
        }
        for off in [
            RUNNING_SUPPLY_OPCODE_OFFSET,
            MINTED_THIS_EPOCH_OPCODE_OFFSET,
            EPOCH_START_DAA_OPCODE_OFFSET,
            CURRENT_CAP_OPCODE_OFFSET,
            PENDING_CAP_OPCODE_OFFSET,
            PENDING_SINCE_DAA_OPCODE_OFFSET,
        ] {
            if script[off] != 0x08 {
                return None;
            }
        }
        let read_u64 = |payload_off: usize| -> u64 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&script[payload_off..payload_off + 8]);
            u64::from_le_bytes(bytes)
        };
        Some(Self {
            running_supply: read_u64(RUNNING_SUPPLY_PAYLOAD_OFFSET),
            minted_this_epoch: read_u64(MINTED_THIS_EPOCH_PAYLOAD_OFFSET),
            epoch_start_daa: read_u64(EPOCH_START_DAA_PAYLOAD_OFFSET),
            current_cap: read_u64(CURRENT_CAP_PAYLOAD_OFFSET),
            pending_cap: read_u64(PENDING_CAP_PAYLOAD_OFFSET),
            pending_since_daa: read_u64(PENDING_SINCE_DAA_PAYLOAD_OFFSET),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MintAuthorityStateHeader {
        MintAuthorityStateHeader::new(1_000, 200, 5_000, 1_000_000, 1_000_000, 0)
    }

    #[test]
    fn lengths_are_pinned() {
        assert_eq!(STATE_HEADER_LEN, 54);
        assert_eq!(sample().encode_script().len(), STATE_HEADER_LEN);
    }

    #[test]
    fn field_offsets_and_opcodes() {
        let state = MintAuthorityStateHeader::new(1_000, 200, 5_000, 1_000_000, 1_000_000, 8_000);
        let enc = state.encode_script();
        assert_eq!(enc[RUNNING_SUPPLY_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[RUNNING_SUPPLY_PAYLOAD_OFFSET..RUNNING_SUPPLY_PAYLOAD_OFFSET + 8], &1_000u64.to_le_bytes());
        assert_eq!(enc[MINTED_THIS_EPOCH_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[MINTED_THIS_EPOCH_PAYLOAD_OFFSET..MINTED_THIS_EPOCH_PAYLOAD_OFFSET + 8], &200u64.to_le_bytes());
        assert_eq!(enc[EPOCH_START_DAA_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[EPOCH_START_DAA_PAYLOAD_OFFSET..EPOCH_START_DAA_PAYLOAD_OFFSET + 8], &5_000u64.to_le_bytes());
        assert_eq!(enc[CURRENT_CAP_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[CURRENT_CAP_PAYLOAD_OFFSET..CURRENT_CAP_PAYLOAD_OFFSET + 8], &1_000_000u64.to_le_bytes());
        assert_eq!(enc[PENDING_CAP_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[PENDING_CAP_PAYLOAD_OFFSET..PENDING_CAP_PAYLOAD_OFFSET + 8], &1_000_000u64.to_le_bytes());
        assert_eq!(enc[PENDING_SINCE_DAA_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[PENDING_SINCE_DAA_PAYLOAD_OFFSET..PENDING_SINCE_DAA_PAYLOAD_OFFSET + 8], &8_000u64.to_le_bytes());
        assert_eq!(enc.len(), 54);
    }

    #[test]
    fn encode_decode_round_trip() {
        let state = sample();
        let enc = state.encode_script();
        let decoded = MintAuthorityStateHeader::decode(&enc).expect("decode");
        assert_eq!(decoded, state);
    }

    #[test]
    fn decode_ignores_trailing_body_bytes() {
        let state = sample();
        let mut enc = state.encode_script();
        enc.extend_from_slice(&[0x75, 0xad, 0x51]); // pretend body bytes
        let decoded = MintAuthorityStateHeader::decode(&enc).expect("decode");
        assert_eq!(decoded, state);
    }

    #[test]
    fn decode_rejects_too_short() {
        let state = sample();
        let enc = state.encode_script();
        assert_eq!(MintAuthorityStateHeader::decode(&enc[..STATE_HEADER_LEN - 1]), None);
    }

    #[test]
    fn decode_rejects_wrong_push_opcode() {
        let state = sample();
        let mut enc = state.encode_script();
        enc[PENDING_CAP_OPCODE_OFFSET] = 0x07; // corrupt the opcode
        assert_eq!(MintAuthorityStateHeader::decode(&enc), None);
    }

    #[test]
    fn decode_rejects_wrong_push_opcode_for_pending_since_daa() {
        // Regression for the new trailing field (FIX 1): its opcode byte is
        // independently pinned, just like every other field's.
        let state = sample();
        let mut enc = state.encode_script();
        enc[PENDING_SINCE_DAA_OPCODE_OFFSET] = 0x07; // corrupt the opcode
        assert_eq!(MintAuthorityStateHeader::decode(&enc), None);
    }

    #[test]
    fn new_checked_rejects_any_field_at_or_above_2pow63() {
        // SUB-FIX E off-chain builder regression: constructing state with
        // any field >= 2^63 must be REJECTED (not silently accepted and
        // encoded, which is all the infallible `new` does outside of debug
        // builds).
        use super::super::attestation::{MintAuthorityError, MAX_AMOUNT_EXCLUSIVE};

        assert!(MintAuthorityStateHeader::new_checked(0, 0, 0, 1_000_000, 1_000_000, 0).is_ok());
        assert!(MintAuthorityStateHeader::new_checked(
            MAX_AMOUNT_EXCLUSIVE - 1,
            MAX_AMOUNT_EXCLUSIVE - 1,
            MAX_AMOUNT_EXCLUSIVE - 1,
            MAX_AMOUNT_EXCLUSIVE - 1,
            MAX_AMOUNT_EXCLUSIVE - 1,
            MAX_AMOUNT_EXCLUSIVE - 1
        )
        .is_ok());
        assert_eq!(
            MintAuthorityStateHeader::new_checked(MAX_AMOUNT_EXCLUSIVE, 0, 0, 1_000_000, 1_000_000, 0),
            Err(MintAuthorityError::AmountTooLarge(MAX_AMOUNT_EXCLUSIVE))
        );
        assert_eq!(
            MintAuthorityStateHeader::new_checked(0, 0, 0, 1_000_000, MAX_AMOUNT_EXCLUSIVE, 0),
            Err(MintAuthorityError::AmountTooLarge(MAX_AMOUNT_EXCLUSIVE))
        );
        assert_eq!(
            MintAuthorityStateHeader::new_checked(0, 0, 0, 1_000_000, 1_000_000, MAX_AMOUNT_EXCLUSIVE),
            Err(MintAuthorityError::AmountTooLarge(MAX_AMOUNT_EXCLUSIVE))
        );
    }

    #[test]
    fn zero_running_supply_uses_explicit_8byte_push_not_op0() {
        // running_supply == 0 (genesis) must still be an explicit
        // OP_DATA_8 || 0x00*8 (an 8-byte string), NOT OP_0 (empty string) --
        // otherwise MINT's on-chain OpAdd/OpNumEqual arithmetic (which reads
        // a fixed 8-byte slice via dr_field_extract) would misparse it.
        let state = MintAuthorityStateHeader::new(0, 0, 0, 1_000_000, 1_000_000, 0);
        let enc = state.encode_script();
        assert_eq!(enc[RUNNING_SUPPLY_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[RUNNING_SUPPLY_PAYLOAD_OFFSET..RUNNING_SUPPLY_PAYLOAD_OFFSET + 8], &[0u8; 8]);
    }

    #[test]
    fn new_genesis_sets_the_sentinel_fields() {
        // FIX 3 regression: the genesis constructor structurally cannot
        // express pending_cap != current_cap or a nonzero pending_since_daa.
        let state = MintAuthorityStateHeader::new_genesis(1_000, 1_000_000);
        assert_eq!(state.running_supply, 1_000);
        assert_eq!(state.minted_this_epoch, 0);
        assert_eq!(state.epoch_start_daa, 0);
        assert_eq!(state.current_cap, 1_000_000);
        assert_eq!(state.pending_cap, 1_000_000);
        assert_eq!(state.pending_since_daa, 0);
    }
}
