//! ZK sigscript segment builder for OpZkPrecompile (0xa6).

use super::prover::BlacklistProof;
use super::{push_data, TAG_GROTH16};

/// Build a ZK sigscript segment for a freezable token spend.
///
/// Format (each item is push_data encoded):
///   1. Tag byte (0x20 for Groth16)
///   2. Proof bytes (~192 bytes for Groth16)
///   3. Public inputs (serialized field elements)
///   4. Verification key
///
/// # Arguments
/// * `proof` - The generated blacklist non-membership proof
///
/// # Returns
/// Raw bytes of the ZK sigscript segment, ready to append to a sigscript.
pub fn build_zk_sigscript_segment(proof: &BlacklistProof) -> Vec<u8> {
    let mut seg = Vec::new();

    // 1. Tag: 0x20 for Groth16/BN254
    push_data(&mut seg, &[TAG_GROTH16]);

    // 2. Proof bytes (~192 bytes)
    push_data(&mut seg, &proof.proof_bytes);

    // 3. Public inputs
    push_data(&mut seg, &proof.public_inputs_bytes);

    // 4. Verification key
    push_data(&mut seg, &proof.vk_bytes);

    seg
}

/// Estimate the byte size of a ZK sigscript segment.
///
/// Useful for transaction mass estimation before proof generation.
/// Groth16/BN254 proof is ~192 bytes, VK is ~400-800 bytes.
pub fn estimate_zk_segment_size(
    proof_size: usize,
    public_inputs_size: usize,
    vk_size: usize,
) -> usize {
    // Each push_data adds 1-5 bytes of overhead depending on data length
    let tag_overhead = 2; // 1 byte length + 1 byte tag
    let proof_overhead = if proof_size <= 75 { 1 } else if proof_size <= 255 { 2 } else { 3 };
    let pi_overhead = if public_inputs_size <= 75 { 1 } else if public_inputs_size <= 255 { 2 } else { 3 };
    let vk_overhead = if vk_size <= 75 { 1 } else if vk_size <= 255 { 2 } else { 3 };

    tag_overhead + proof_overhead + proof_size + pi_overhead + public_inputs_size + vk_overhead + vk_size
}

/// Estimate the sigop cost for a Groth16 ZK sigscript.
pub const GROTH16_SIGOPS: u32 = 140;

/// Estimate the block mass percentage for a Groth16 proof.
/// Based on the spec: Groth16 = 28% of block mass.
pub const GROTH16_BLOCK_MASS_PCT: u32 = 28;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_proof() -> BlacklistProof {
        BlacklistProof {
            proof_bytes: vec![0xaa; 192],
            public_inputs_bytes: vec![0xbb; 160], // 5 FE * 32 bytes
            vk_bytes: vec![0xcc; 400],
            address: vec![0xdd; 34],
            daa_score: 12345,
        }
    }

    #[test]
    fn segment_starts_with_tag() {
        let proof = make_test_proof();
        let seg = build_zk_sigscript_segment(&proof);

        // First push_data: 1-byte length prefix + tag byte
        assert_eq!(seg[0], 1, "tag push should have length 1");
        assert_eq!(seg[1], TAG_GROTH16, "tag should be 0x20");
    }

    #[test]
    fn segment_contains_proof_bytes() {
        let proof = make_test_proof();
        let seg = build_zk_sigscript_segment(&proof);

        // After tag (2 bytes), proof is push_data encoded
        // 192 bytes > 75, so uses OP_PUSHDATA1 (0x4c) + 1-byte length
        assert_eq!(seg[2], 0x4c, "proof should use OP_PUSHDATA1");
        assert_eq!(seg[3], 192, "proof length should be 192");
        assert_eq!(&seg[4..196], &[0xaa; 192], "proof bytes should match");
    }

    #[test]
    fn segment_contains_public_inputs() {
        let proof = make_test_proof();
        let seg = build_zk_sigscript_segment(&proof);

        // After tag (2) + proof (2 + 192 = 194) = offset 196
        // 160 bytes > 75, so uses OP_PUSHDATA1
        assert_eq!(seg[196], 0x4c, "PI should use OP_PUSHDATA1");
        assert_eq!(seg[197], 160, "PI length should be 160");
        assert_eq!(&seg[198..358], &[0xbb; 160], "PI bytes should match");
    }

    #[test]
    fn segment_contains_vk() {
        let proof = make_test_proof();
        let seg = build_zk_sigscript_segment(&proof);

        // After tag(2) + proof(194) + PI(162) = offset 358
        // 400 > 255, so uses OP_PUSHDATA2 (0x4d) + 2-byte LE length
        assert_eq!(seg[358], 0x4d, "VK should use OP_PUSHDATA2");
        let vk_len = u16::from_le_bytes([seg[359], seg[360]]);
        assert_eq!(vk_len, 400, "VK length should be 400");
        assert_eq!(&seg[361..761], &[0xcc; 400], "VK bytes should match");
    }

    #[test]
    fn segment_total_size() {
        let proof = make_test_proof();
        let seg = build_zk_sigscript_segment(&proof);

        // tag: 2 + proof: 2+192 + PI: 2+160 + VK: 3+400 = 761
        assert_eq!(seg.len(), 761);
    }

    #[test]
    fn estimate_matches_actual() {
        let proof = make_test_proof();
        let estimated = estimate_zk_segment_size(
            proof.proof_bytes.len(),
            proof.public_inputs_bytes.len(),
            proof.vk_bytes.len(),
        );
        let actual = build_zk_sigscript_segment(&proof).len();
        assert_eq!(estimated, actual, "estimate should match actual size");
    }

    #[test]
    fn small_proof_uses_direct_push() {
        let proof = BlacklistProof {
            proof_bytes: vec![0xaa; 50],
            public_inputs_bytes: vec![0xbb; 32],
            vk_bytes: vec![0xcc; 64],
            address: vec![],
            daa_score: 0,
        };
        let seg = build_zk_sigscript_segment(&proof);

        // Tag: len(1) + 0x20 = 2
        assert_eq!(seg[0], 1);
        // Proof: len(50) + 50 bytes = direct push
        assert_eq!(seg[2], 50);
        // PI: len(32) + 32 bytes = direct push
        assert_eq!(seg[53], 32);
        // VK: len(64) + 64 bytes = direct push
        assert_eq!(seg[86], 64);
    }

    #[test]
    fn sigops_constant() {
        assert_eq!(GROTH16_SIGOPS, 140);
    }
}
