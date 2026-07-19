//! KCC-0020 robust stablecoin covenant — mutable state header (§3 of
//! `STABLECOIN_ROBUST_DESIGN.md`).
//!
//! Extends case-A's 35-byte `Kcc20StateHeader` framing
//! ([`crate::contract::token::Kcc20StateHeader`]: `[0x20][owner_pubkey 32B]
//! [0x01][identifier_type 1B]`) with three new mutable-state fields, each
//! framed with its own literal push-opcode immediately preceding its raw
//! payload (the SAME convention case-A already uses — no extra length-prefix
//! byte beyond the opcode itself):
//!
//! ```text
//! offset  push-opcode        field                 width
//! 0       0x20 (OpData32)    owner_pubkey          32B   (case-A, unchanged)
//! 33      0x01 (OpData1)     identifier_type        1B   (case-A, unchanged)
//! 35      0x20 (OpData32)    role_registry_root     32B   (new)
//! 68      0x01 (OpData1)     frozen_flag             1B   (new)
//! 70      0x04 (OpData4)     epoch                   4B, LE  (new)
//! ```
//!
//! # Header length: 75B, not the design doc's stated 74B (judgment call)
//!
//! `STABLECOIN_ROBUST_DESIGN.md` §3's own offset table places `epoch`'s push
//! opcode at offset 70 with a 4-byte payload — that field alone spans bytes
//! `[70..75)` (1 opcode byte + 4 payload bytes), so the header is **75**
//! bytes, and the body must start at offset 75. The design doc's prose
//! ("Total header: 35 + 32 + 1 + 4 = 74B ... Body follows immediately at
//! offset 74") is internally inconsistent with its own offset table (and the
//! arithmetic `35+32+1+4` is `72`, not even `74`, under any reading). This
//! module follows the **offset table** (75B), because it is the one
//! cross-checked against the codebase's existing, load-bearing decode idiom
//! (`rs[OFFSET] == push_opcode`, exactly as `Kcc20StateHeader::decode` checks
//! `script[33] == 0x01` and `body.rs`'s `ISSUER_PUBKEY_RS_OFFSET` comment
//! documents `rs[OFFSET - 1] == push_opcode`). **Flagged for human review**:
//! this is a genuine spec arithmetic error, not a judgment call between two
//! equally-valid readings.
//!
//! Each field is pushed by its own literal opcode when the redeem script
//! begins executing, so at the point the covenant body's dispatch bytecode
//! starts, these five fields are already separate items on the data stack
//! (top to bottom): `epoch, frozen_flag, role_registry_root, identifier_type,
//! owner_pubkey` — no `OpCat`/hashing needed to read "own" state; only the
//! *successor*'s state (carried in a not-yet-existing redeem script) requires
//! the dr.rs-style authenticate-then-slice pattern (see `body.rs`).

/// Byte offset of `owner_pubkey`'s push opcode (`0x20`).
pub const OWNER_PUBKEY_OPCODE_OFFSET: usize = 0;
/// Byte offset of `owner_pubkey`'s 32-byte payload.
pub const OWNER_PUBKEY_PAYLOAD_OFFSET: usize = 1;
/// Byte offset of `identifier_type`'s push opcode (`0x01`).
pub const IDENTIFIER_TYPE_OPCODE_OFFSET: usize = 33;
/// Byte offset of `identifier_type`'s 1-byte payload.
pub const IDENTIFIER_TYPE_PAYLOAD_OFFSET: usize = 34;
/// Byte offset of `role_registry_root`'s push opcode (`0x20`).
pub const ROLE_REGISTRY_ROOT_OPCODE_OFFSET: usize = 35;
/// Byte offset of `role_registry_root`'s 32-byte payload.
pub const ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET: usize = 36;
/// Byte offset of `frozen_flag`'s push opcode (`0x01`).
pub const FROZEN_FLAG_OPCODE_OFFSET: usize = 68;
/// Byte offset of `frozen_flag`'s 1-byte payload.
pub const FROZEN_FLAG_PAYLOAD_OFFSET: usize = 69;
/// Byte offset of `epoch`'s push opcode (`0x04`).
pub const EPOCH_OPCODE_OFFSET: usize = 70;
/// Byte offset of `epoch`'s 4-byte (LE) payload.
pub const EPOCH_PAYLOAD_OFFSET: usize = 71;

/// Total script-encoded length of the extended stablecoin state header.
/// See the module doc for why this is 75, not the design doc's stated 74.
pub const STATE_HEADER_LEN: usize = 75;

/// `frozen_flag` values (§3: "0x00/0x01").
pub mod frozen_flag {
    pub const CLEAR: u8 = 0x00;
    pub const SET: u8 = 0x01;
}

/// Decoded extended stablecoin state header (§3). `amount` is NOT
/// script-encoded — it continues case-A's native-value mapping (the UTXO's
/// sompi value), so `decode` takes it from the caller (the UTXO entry), not
/// from the script bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StablecoinStateHeader {
    pub owner_pubkey: [u8; 32],
    pub identifier_type: u8,
    pub role_registry_root: [u8; 32],
    pub frozen_flag: u8,
    pub epoch: u32,
    pub amount: u64,
}

impl StablecoinStateHeader {
    pub fn new(
        owner_pubkey: [u8; 32],
        identifier_type: u8,
        role_registry_root: [u8; 32],
        frozen_flag: u8,
        epoch: u32,
        amount: u64,
    ) -> Self {
        Self { owner_pubkey, identifier_type, role_registry_root, frozen_flag, epoch, amount }
    }

    /// Encode the script-encoded portion of the header (the "Writer" side).
    /// `amount` is intentionally not written here (see module/struct doc).
    pub fn encode_script(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STATE_HEADER_LEN);
        out.push(0x20);
        out.extend_from_slice(&self.owner_pubkey);
        out.push(0x01);
        out.push(self.identifier_type);
        out.push(0x20);
        out.extend_from_slice(&self.role_registry_root);
        out.push(0x01);
        out.push(self.frozen_flag);
        out.push(0x04);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        debug_assert_eq!(out.len(), STATE_HEADER_LEN);
        out
    }

    /// Decode the leading header fields from a redeemScript (the "Reader"
    /// side), combined with the UTXO's native value for `amount`. Bytes
    /// beyond `STATE_HEADER_LEN` (body opcodes) are ignored. Returns `None`
    /// if the input is too short or any push opcode doesn't match the
    /// expected layout.
    pub fn decode(script: &[u8], utxo_value: u64) -> Option<Self> {
        if script.len() < STATE_HEADER_LEN {
            return None;
        }
        if script[OWNER_PUBKEY_OPCODE_OFFSET] != 0x20
            || script[IDENTIFIER_TYPE_OPCODE_OFFSET] != 0x01
            || script[ROLE_REGISTRY_ROOT_OPCODE_OFFSET] != 0x20
            || script[FROZEN_FLAG_OPCODE_OFFSET] != 0x01
            || script[EPOCH_OPCODE_OFFSET] != 0x04
        {
            return None;
        }
        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&script[OWNER_PUBKEY_PAYLOAD_OFFSET..OWNER_PUBKEY_PAYLOAD_OFFSET + 32]);
        let identifier_type = script[IDENTIFIER_TYPE_PAYLOAD_OFFSET];
        let mut role_registry_root = [0u8; 32];
        role_registry_root
            .copy_from_slice(&script[ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET..ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET + 32]);
        let frozen_flag = script[FROZEN_FLAG_PAYLOAD_OFFSET];
        let mut epoch_bytes = [0u8; 4];
        epoch_bytes.copy_from_slice(&script[EPOCH_PAYLOAD_OFFSET..EPOCH_PAYLOAD_OFFSET + 4]);
        let epoch = u32::from_le_bytes(epoch_bytes);
        Some(Self { owner_pubkey, identifier_type, role_registry_root, frozen_flag, epoch, amount: utxo_value })
    }
}

/// Off-chain helper: compute `role_registry_root` per §2's formula --
/// `Blake3(OPS_pk(32) || FREEZE_pk(32) || SEIZE_multisig_commit(32) ||
/// MINT_pk(32) || ROTATE_multisig_commit(32) || epoch(4))`. Purely an
/// off-chain convenience for whoever assembles the role registry; the
/// on-chain covenant (Phase I: `body.rs`'s TRANSFER branch) never verifies
/// this derivation -- it only enforces that a successor's committed root
/// bytes are carried forward unchanged, treating the root as opaque. Ready
/// for Phase II (ROTATE) to reuse when it needs to compute a NEW root.
pub fn compute_role_registry_root(
    ops_pk: &[u8; 32],
    freeze_pk: &[u8; 32],
    seize_multisig_commit: &[u8; 32],
    mint_pk: &[u8; 32],
    rotate_multisig_commit: &[u8; 32],
    epoch: u32,
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 * 5 + 4);
    preimage.extend_from_slice(ops_pk);
    preimage.extend_from_slice(freeze_pk);
    preimage.extend_from_slice(seize_multisig_commit);
    preimage.extend_from_slice(mint_pk);
    preimage.extend_from_slice(rotate_multisig_commit);
    preimage.extend_from_slice(&epoch.to_le_bytes());
    *blake3::hash(&preimage).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StablecoinStateHeader {
        StablecoinStateHeader::new([0x11u8; 32], 0x00, [0x22u8; 32], frozen_flag::CLEAR, 7, 1_000_000)
    }

    #[test]
    fn lengths_are_pinned() {
        assert_eq!(STATE_HEADER_LEN, 75);
        assert_eq!(sample().encode_script().len(), STATE_HEADER_LEN);
    }

    #[test]
    fn field_offsets_and_opcodes() {
        let state = sample();
        let enc = state.encode_script();
        assert_eq!(enc[OWNER_PUBKEY_OPCODE_OFFSET], 0x20);
        assert_eq!(&enc[OWNER_PUBKEY_PAYLOAD_OFFSET..OWNER_PUBKEY_PAYLOAD_OFFSET + 32], &[0x11u8; 32]);
        assert_eq!(enc[IDENTIFIER_TYPE_OPCODE_OFFSET], 0x01);
        assert_eq!(enc[IDENTIFIER_TYPE_PAYLOAD_OFFSET], 0x00);
        assert_eq!(enc[ROLE_REGISTRY_ROOT_OPCODE_OFFSET], 0x20);
        assert_eq!(
            &enc[ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET..ROLE_REGISTRY_ROOT_PAYLOAD_OFFSET + 32],
            &[0x22u8; 32]
        );
        assert_eq!(enc[FROZEN_FLAG_OPCODE_OFFSET], 0x01);
        assert_eq!(enc[FROZEN_FLAG_PAYLOAD_OFFSET], frozen_flag::CLEAR);
        assert_eq!(enc[EPOCH_OPCODE_OFFSET], 0x04);
        assert_eq!(&enc[EPOCH_PAYLOAD_OFFSET..EPOCH_PAYLOAD_OFFSET + 4], &7u32.to_le_bytes());
        assert_eq!(enc.len(), 75);
    }

    #[test]
    fn encode_decode_round_trip() {
        let state = sample();
        let enc = state.encode_script();
        let decoded = StablecoinStateHeader::decode(&enc, state.amount).expect("decode");
        assert_eq!(decoded, state);
    }

    #[test]
    fn decode_ignores_trailing_body_bytes() {
        let state = sample();
        let mut enc = state.encode_script();
        enc.extend_from_slice(&[0x75, 0xad, 0x51]); // pretend body bytes
        let decoded = StablecoinStateHeader::decode(&enc, state.amount).expect("decode");
        assert_eq!(decoded, state);
    }

    #[test]
    fn decode_rejects_too_short() {
        let state = sample();
        let enc = state.encode_script();
        assert_eq!(StablecoinStateHeader::decode(&enc[..74], state.amount), None);
    }

    #[test]
    fn decode_rejects_wrong_push_opcode() {
        let state = sample();
        let mut enc = state.encode_script();
        enc[ROLE_REGISTRY_ROOT_OPCODE_OFFSET] = 0x1f; // corrupt the opcode
        assert_eq!(StablecoinStateHeader::decode(&enc, state.amount), None);
    }

    #[test]
    fn frozen_flag_zero_uses_explicit_push_not_op0() {
        // frozen_flag::CLEAR == 0x00: the field must still be an explicit
        // OP_DATA_1 || 0x00 (a 1-byte string), NOT OP_0 (an empty string) --
        // otherwise the TRANSFER branch's OpEqual-against-[0x00] check
        // (body.rs) would never match a genuinely-clear flag.
        let state = sample();
        let enc = state.encode_script();
        assert_eq!(enc[FROZEN_FLAG_OPCODE_OFFSET], 0x01);
        assert_eq!(enc[FROZEN_FLAG_PAYLOAD_OFFSET], 0x00);
    }

    #[test]
    fn role_registry_root_formula_is_deterministic_and_field_sensitive() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let c = [0x03u8; 32];
        let d = [0x04u8; 32];
        let e = [0x05u8; 32];
        let root1 = compute_role_registry_root(&a, &b, &c, &d, &e, 0);
        let root2 = compute_role_registry_root(&a, &b, &c, &d, &e, 0);
        assert_eq!(root1, root2);
        let root3 = compute_role_registry_root(&a, &b, &c, &d, &e, 1);
        assert_ne!(root1, root3);
        let mut a2 = a;
        a2[0] ^= 0xff;
        assert_ne!(root1, compute_role_registry_root(&a2, &b, &c, &d, &e, 0));
    }
}
