//! Local Groth16/BN254 proof verification.

#[cfg(feature = "zk-prover")]
use ark_bn254::{Bn254, Fr};
#[cfg(feature = "zk-prover")]
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
#[cfg(feature = "zk-prover")]
use ark_serialize::CanonicalDeserialize;

use super::ZkError;

#[cfg(feature = "zk-prover")]
use super::prover::BlacklistProof;

/// Verify a blacklist non-membership proof using the embedded VK.
///
/// This deserializes the proof, public inputs, and VK from the `BlacklistProof`
/// struct and runs Groth16 verification.
#[cfg(feature = "zk-prover")]
pub fn verify_blacklist_proof(bp: &BlacklistProof) -> Result<bool, ZkError> {
    // Deserialize verification key
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&bp.vk_bytes[..])
        .map_err(|e| ZkError::ProofGenerationFailed(format!("VK deserialization: {}", e)))?;

    let pvk = prepare_verifying_key(&vk);

    verify_with_prepared_vk(&pvk, &bp.proof_bytes, &bp.public_inputs_bytes)
}

/// Verify a proof using a pre-prepared verifying key (faster for repeated verifications).
#[cfg(feature = "zk-prover")]
pub fn verify_with_prepared_vk(
    pvk: &PreparedVerifyingKey<Bn254>,
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool, ZkError> {
    // Deserialize proof
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| ZkError::ProofGenerationFailed(format!("proof deserialization: {}", e)))?;

    // Deserialize public inputs (5 field elements: 2 addr + 2 root + 1 daa)
    let mut reader = &public_inputs_bytes[..];
    let mut public_inputs = Vec::new();
    while !reader.is_empty() {
        let fe = Fr::deserialize_compressed(&mut reader)
            .map_err(|e| ZkError::ProofGenerationFailed(format!("PI deserialization: {}", e)))?;
        public_inputs.push(fe);
    }

    // Verify
    let result = Groth16::<Bn254>::verify_proof(pvk, &proof, &public_inputs)
        .map_err(|e| ZkError::ProofGenerationFailed(format!("verification: {}", e)))?;

    Ok(result)
}

/// Stub verification when zk-prover feature is disabled.
#[cfg(not(feature = "zk-prover"))]
pub fn verify_blacklist_proof_stub(
    _proof_bytes: &[u8],
    _public_inputs_bytes: &[u8],
    _vk_bytes: &[u8],
) -> Result<bool, ZkError> {
    Err(ZkError::NoProverConfigured)
}

#[cfg(test)]
#[cfg(feature = "zk-prover")]
mod tests {
    use super::*;
    use crate::zk::prover::Groth16Prover;

    #[test]
    fn prove_and_verify_roundtrip() {
        let prover = Groth16Prover::setup(5).unwrap();
        let proof = prover.generate_proof(b"clean_address", 500).unwrap();

        let result = verify_blacklist_proof(&proof).unwrap();
        assert!(result, "valid non-membership proof should verify");
    }

    #[test]
    fn verify_with_prepared_vk_works() {
        let prover = Groth16Prover::setup(5).unwrap();
        let proof = prover.generate_proof(b"clean_address", 500).unwrap();

        let result = verify_with_prepared_vk(
            prover.prepared_vk(),
            &proof.proof_bytes,
            &proof.public_inputs_bytes,
        )
        .unwrap();
        assert!(result, "verification with prepared VK should succeed");
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let prover = Groth16Prover::setup(5).unwrap();
        let mut proof = prover.generate_proof(b"clean_address", 500).unwrap();

        // Tamper with proof bytes
        if !proof.proof_bytes.is_empty() {
            proof.proof_bytes[0] ^= 0xff;
        }

        // Should either fail deserialization or verification
        let result = verify_blacklist_proof(&proof);
        match result {
            Ok(false) => {} // verification failed as expected
            Err(_) => {}    // deserialization failed, also acceptable
            Ok(true) => panic!("tampered proof should not verify"),
        }
    }
}
