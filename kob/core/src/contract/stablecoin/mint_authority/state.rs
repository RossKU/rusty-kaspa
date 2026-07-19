//! Mint-authority contract — mutable state header (`STABLECOIN_ROBUST_DESIGN.md`
//! §9: "the mint-authority contract carries the running-supply counter ...
//! read, incremented by `mint_amount`, and re-written into its own
//! self-continuation successor on every MINT spend").
//!
//! Framed exactly like [`super::super::state::StablecoinStateHeader`]: each
//! field carries its own literal push-opcode immediately preceding its raw
//! payload (no extra length-prefix byte beyond the opcode itself).
//!
//! ```text
//! offset  push-opcode        field            width
//! 0       0x08 (OpData8)     running_supply    8B, LE u64  -- MUTABLE: the
//!                                                             only field a
//!                                                             MINT spend may
//!                                                             change (§9)
//! 9       0x08 (OpData8)     current_cap       8B, LE u64  -- MUTABLE in
//!                                                             principle (the
//!                                                             cap is
//!                                                             raisable, §9),
//!                                                             but MINT (this
//!                                                             task's only
//!                                                             wired op) must
//!                                                             carry it
//!                                                             forward
//!                                                             UNCHANGED;
//!                                                             only the
//!                                                             (stubbed)
//!                                                             RAISE_CAP op
//!                                                             may rewrite it
//! ```
//!
//! Total header: `1 + 8 + 1 + 8 = 18` bytes. Body follows immediately at
//! offset 18.
//!
//! `running_supply` is placed FIRST (offset 0) so the D&R "mutable zone" it
//! occupies is a single contiguous prefix `[0..9)` with nothing before it —
//! the body's suffix check (`crate::contract::dr::dr_suffix_check`) can then
//! authenticate "everything from `current_cap` onward" (i.e. `current_cap`
//! AND the entire baked body) as ONE unchanged suffix, `[9..end)`, mirroring
//! `spot::dca`'s D&R layout (prefix/mutable-middle/suffix), simplified to
//! prefix-less because there is exactly one mutable field here.

/// Byte offset of `running_supply`'s push opcode (`0x08`).
pub const RUNNING_SUPPLY_OPCODE_OFFSET: usize = 0;
/// Byte offset of `running_supply`'s 8-byte (LE) payload.
pub const RUNNING_SUPPLY_PAYLOAD_OFFSET: usize = 1;
/// Byte offset of `current_cap`'s push opcode (`0x08`).
pub const CURRENT_CAP_OPCODE_OFFSET: usize = 9;
/// Byte offset of `current_cap`'s 8-byte (LE) payload.
pub const CURRENT_CAP_PAYLOAD_OFFSET: usize = 10;

/// Total script-encoded length of the mint-authority state header.
pub const STATE_HEADER_LEN: usize = 18;

/// Decoded mint-authority state header (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintAuthorityStateHeader {
    pub running_supply: u64,
    pub current_cap: u64,
}

impl MintAuthorityStateHeader {
    /// In debug builds this asserts the numeric domain (`running_supply`/
    /// `current_cap < 2^63`, SUB-FIX E); [`Self::new_checked`] gives a
    /// release-mode check, mirroring
    /// `stablecoin::attestation::build_attestation_preimage`'s
    /// debug_assert-plus-`check_numeric_domain` precedent.
    pub fn new(running_supply: u64, current_cap: u64) -> Self {
        debug_assert!(running_supply < super::attestation::MAX_AMOUNT_EXCLUSIVE, "running_supply must be < 2^63 to match the on-chain sign-magnitude script-number domain");
        debug_assert!(current_cap < super::attestation::MAX_AMOUNT_EXCLUSIVE, "current_cap must be < 2^63 to match the on-chain sign-magnitude script-number domain");
        Self { running_supply, current_cap }
    }

    /// Fallible constructor (SUB-FIX E, numeric-domain bound): rejects
    /// `running_supply`/`current_cap` >= 2^63 -- at or above that bound the
    /// field's raw 8-byte LE encoding has its sign bit set, so the body's
    /// sign-magnitude script-number arithmetic (`OpAdd`/`OpNumEqual`/
    /// `OpLessThanOrEqual`/`OpGreaterThan`) would read it as non-positive
    /// instead of the intended u64 magnitude. Mirrors
    /// `super::attestation::check_numeric_domain`'s release-mode-check role;
    /// off-chain callers constructing state (genesis deploy, or predicting a
    /// MINT/RAISE_CAP successor header) should prefer this over `new`, which
    /// stays infallible (only debug-asserting the bound) for internal/
    /// hot-path callers that have already validated their inputs.
    pub fn new_checked(running_supply: u64, current_cap: u64) -> Result<Self, super::attestation::MintAuthorityError> {
        super::attestation::check_numeric_domain(running_supply)?;
        super::attestation::check_numeric_domain(current_cap)?;
        Ok(Self::new(running_supply, current_cap))
    }

    /// Encode the script-encoded state header (the "Writer" side).
    pub fn encode_script(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STATE_HEADER_LEN);
        out.push(0x08);
        out.extend_from_slice(&self.running_supply.to_le_bytes());
        out.push(0x08);
        out.extend_from_slice(&self.current_cap.to_le_bytes());
        debug_assert_eq!(out.len(), STATE_HEADER_LEN);
        out
    }

    /// Decode the leading header fields from a redeemScript (the "Reader"
    /// side). Bytes beyond `STATE_HEADER_LEN` (body opcodes) are ignored.
    /// Returns `None` if the input is too short or either push opcode
    /// doesn't match the expected layout.
    pub fn decode(script: &[u8]) -> Option<Self> {
        if script.len() < STATE_HEADER_LEN {
            return None;
        }
        if script[RUNNING_SUPPLY_OPCODE_OFFSET] != 0x08 || script[CURRENT_CAP_OPCODE_OFFSET] != 0x08 {
            return None;
        }
        let mut running_supply_bytes = [0u8; 8];
        running_supply_bytes.copy_from_slice(&script[RUNNING_SUPPLY_PAYLOAD_OFFSET..RUNNING_SUPPLY_PAYLOAD_OFFSET + 8]);
        let mut current_cap_bytes = [0u8; 8];
        current_cap_bytes.copy_from_slice(&script[CURRENT_CAP_PAYLOAD_OFFSET..CURRENT_CAP_PAYLOAD_OFFSET + 8]);
        Some(Self {
            running_supply: u64::from_le_bytes(running_supply_bytes),
            current_cap: u64::from_le_bytes(current_cap_bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MintAuthorityStateHeader {
        MintAuthorityStateHeader::new(1_000, 1_000_000)
    }

    #[test]
    fn lengths_are_pinned() {
        assert_eq!(STATE_HEADER_LEN, 18);
        assert_eq!(sample().encode_script().len(), STATE_HEADER_LEN);
    }

    #[test]
    fn field_offsets_and_opcodes() {
        let state = sample();
        let enc = state.encode_script();
        assert_eq!(enc[RUNNING_SUPPLY_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[RUNNING_SUPPLY_PAYLOAD_OFFSET..RUNNING_SUPPLY_PAYLOAD_OFFSET + 8], &1_000u64.to_le_bytes());
        assert_eq!(enc[CURRENT_CAP_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[CURRENT_CAP_PAYLOAD_OFFSET..CURRENT_CAP_PAYLOAD_OFFSET + 8], &1_000_000u64.to_le_bytes());
        assert_eq!(enc.len(), 18);
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
        assert_eq!(MintAuthorityStateHeader::decode(&enc[..17]), None);
    }

    #[test]
    fn decode_rejects_wrong_push_opcode() {
        let state = sample();
        let mut enc = state.encode_script();
        enc[CURRENT_CAP_OPCODE_OFFSET] = 0x07; // corrupt the opcode
        assert_eq!(MintAuthorityStateHeader::decode(&enc), None);
    }

    #[test]
    fn new_checked_rejects_running_supply_or_current_cap_at_or_above_2pow63() {
        // SUB-FIX E off-chain builder regression: constructing state with
        // either field >= 2^63 must be REJECTED (not silently accepted and
        // encoded, which is all the infallible `new` does outside of debug
        // builds).
        use super::super::attestation::{MintAuthorityError, MAX_AMOUNT_EXCLUSIVE};

        assert!(MintAuthorityStateHeader::new_checked(0, 1_000_000).is_ok());
        assert!(MintAuthorityStateHeader::new_checked(MAX_AMOUNT_EXCLUSIVE - 1, MAX_AMOUNT_EXCLUSIVE - 1).is_ok());
        assert_eq!(MintAuthorityStateHeader::new_checked(MAX_AMOUNT_EXCLUSIVE, 1_000_000), Err(MintAuthorityError::AmountTooLarge(MAX_AMOUNT_EXCLUSIVE)));
        assert_eq!(MintAuthorityStateHeader::new_checked(0, MAX_AMOUNT_EXCLUSIVE), Err(MintAuthorityError::AmountTooLarge(MAX_AMOUNT_EXCLUSIVE)));
    }

    #[test]
    fn zero_running_supply_uses_explicit_8byte_push_not_op0() {
        // running_supply == 0 (genesis) must still be an explicit
        // OP_DATA_8 || 0x00*8 (an 8-byte string), NOT OP_0 (empty string) --
        // otherwise MINT's on-chain OpAdd/OpNumEqual arithmetic (which reads
        // a fixed 8-byte slice via dr_field_extract) would misparse it.
        let state = MintAuthorityStateHeader::new(0, 1_000_000);
        let enc = state.encode_script();
        assert_eq!(enc[RUNNING_SUPPLY_OPCODE_OFFSET], 0x08);
        assert_eq!(&enc[RUNNING_SUPPLY_PAYLOAD_OFFSET..RUNNING_SUPPLY_PAYLOAD_OFFSET + 8], &[0u8; 8]);
    }
}
