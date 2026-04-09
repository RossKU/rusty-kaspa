//! Groth16/BN254 blacklist non-membership proof generation.

#[cfg(feature = "zk-prover")]
use ark_bn254::{Bn254, Fr};
#[cfg(feature = "zk-prover")]
use ark_crypto_primitives::snark::SNARK;
#[cfg(feature = "zk-prover")]
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
#[cfg(feature = "zk-prover")]
use ark_serialize::CanonicalSerialize;
#[cfg(feature = "zk-prover")]
use ark_std::rand::thread_rng;

use super::merkle::SparseMerkleTree;
use super::ZkError;

#[cfg(feature = "zk-prover")]
use super::circuit::BlacklistNonMembershipCircuit;

/// A generated ZK proof with all data needed for on-chain verification.
#[derive(Debug, Clone)]
pub struct BlacklistProof {
    /// Serialized Groth16 proof (~192 bytes: 2 G1 + 1 G2 point).
    pub proof_bytes: Vec<u8>,
    /// Serialized public inputs (address_hash + root + daa_score).
    pub public_inputs_bytes: Vec<u8>,
    /// Serialized verification key.
    pub vk_bytes: Vec<u8>,
    /// The address this proof is for.
    pub address: Vec<u8>,
    /// DAA score at proof generation time.
    pub daa_score: u64,
}

/// Groth16 blacklist non-membership prover.
///
/// Holds the proving key, verifying key, and blacklist merkle tree state.
/// Thread-safe: the proving key and VK are immutable after setup; only the
/// blacklist tree needs synchronization (handled by the caller via Mutex).
#[cfg(feature = "zk-prover")]
pub struct Groth16Prover {
    proving_key: ProvingKey<Bn254>,
    verifying_key: VerifyingKey<Bn254>,
    prepared_vk: PreparedVerifyingKey<Bn254>,
    vk_bytes: Vec<u8>,
    blacklist: SparseMerkleTree,
    tree_depth: usize,
}

#[cfg(feature = "zk-prover")]
impl Groth16Prover {
    /// Run trusted setup for the blacklist non-membership circuit.
    ///
    /// This generates the proving and verifying keys. In production, this
    /// would use a ceremony-generated CRS. For development/testing, we use
    /// a random setup.
    ///
    /// # Arguments
    /// * `tree_depth` - Depth of the sparse merkle tree (e.g., 20)
    pub fn setup(tree_depth: usize) -> Result<Self, ZkError> {
        let circuit = BlacklistNonMembershipCircuit::empty(tree_depth);
        let mut rng = thread_rng();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkError::ProofGenerationFailed(format!("setup failed: {}", e)))?;

        let prepared_vk = prepare_verifying_key(&vk);

        // Serialize VK for on-chain use
        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes)
            .map_err(|e| ZkError::ProofGenerationFailed(format!("VK serialization failed: {}", e)))?;

        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            prepared_vk,
            vk_bytes,
            blacklist: SparseMerkleTree::new(tree_depth),
            tree_depth,
        })
    }

    /// Add an address to the blacklist.
    pub fn add_to_blacklist(&mut self, address: &[u8]) {
        self.blacklist.insert(address);
    }

    /// Remove an address from the blacklist.
    pub fn remove_from_blacklist(&mut self, address: &[u8]) {
        self.blacklist.remove(address);
    }

    /// Update the blacklist with a full set of addresses (replaces existing).
    pub fn set_blacklist(&mut self, addresses: &[Vec<u8>]) {
        self.blacklist = SparseMerkleTree::new(self.tree_depth);
        for addr in addresses {
            self.blacklist.insert(addr);
        }
    }

    /// Check if an address is on the blacklist.
    pub fn is_blacklisted(&self, address: &[u8]) -> bool {
        self.blacklist.contains(address)
    }

    /// Generate a Groth16 proof that the given address is NOT on the blacklist.
    ///
    /// Returns an error if:
    /// - The address IS on the blacklist (cannot prove non-membership)
    /// - Proof generation fails
    pub fn generate_proof(
        &self,
        address: &[u8],
        daa_score: u64,
    ) -> Result<BlacklistProof, ZkError> {
        // Check: cannot prove non-membership for a blacklisted address
        if self.blacklist.contains(address) {
            return Err(ZkError::BlacklistCheckFailed(
                "address is on the blacklist; cannot generate non-membership proof".into(),
            ));
        }

        let address_hash = kob_core::blake2b_256(address);
        let merkle_proof = self.blacklist.prove(address);

        // Compute the algebraic root that matches the in-circuit hash computation.
        // The on-chain SMT uses Blake2b, but the R1CS circuit uses an algebraic hash
        // (H(L,R) = L*R + L + R + 1) for efficiency. The public input `blacklist_root`
        // must be computed with the same algebraic hash so the circuit is satisfiable.
        let algebraic_root_fe = super::circuit::compute_algebraic_root_fe(
            &merkle_proof.leaf,
            &merkle_proof.siblings,
            merkle_proof.index,
        );

        // Build the circuit with witness values
        let circuit = BlacklistNonMembershipCircuit::new(
            address_hash,
            algebraic_root_fe,
            daa_score,
            merkle_proof.siblings.clone(),
            merkle_proof.leaf,
            merkle_proof.index,
            self.tree_depth,
        );

        // Generate proof
        let mut rng = thread_rng();
        let proof = Groth16::<Bn254>::prove(&self.proving_key, circuit, &mut rng)
            .map_err(|e| ZkError::ProofGenerationFailed(format!("prove failed: {}", e)))?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ZkError::ProofGenerationFailed(format!("proof serialization: {}", e)))?;

        // Serialize public inputs
        let pi_circuit = BlacklistNonMembershipCircuit::new(
            address_hash,
            algebraic_root_fe,
            daa_score,
            merkle_proof.siblings,
            merkle_proof.leaf,
            merkle_proof.index,
            self.tree_depth,
        );
        let public_inputs: Vec<Fr> = pi_circuit
            .public_inputs()
            .ok_or_else(|| ZkError::ProofGenerationFailed("missing public inputs".into()))?;

        let mut pi_bytes = Vec::new();
        for pi in &public_inputs {
            CanonicalSerialize::serialize_compressed(pi, &mut pi_bytes)
                .map_err(|e| ZkError::ProofGenerationFailed(format!("PI serialization: {}", e)))?;
        }

        Ok(BlacklistProof {
            proof_bytes,
            public_inputs_bytes: pi_bytes,
            vk_bytes: self.vk_bytes.clone(),
            address: address.to_vec(),
            daa_score,
        })
    }

    /// Get the current blacklist merkle root.
    pub fn blacklist_root(&self) -> [u8; 32] {
        self.blacklist.root()
    }

    /// Number of blacklisted addresses.
    pub fn blacklist_size(&self) -> usize {
        self.blacklist.len()
    }

    /// Get serialized verification key bytes.
    pub fn vk_bytes(&self) -> &[u8] {
        &self.vk_bytes
    }

    /// Get a reference to the prepared verifying key (for local verification).
    pub fn prepared_vk(&self) -> &PreparedVerifyingKey<Bn254> {
        &self.prepared_vk
    }
}

// Stub prover for when zk-prover feature is disabled

/// Stub prover that reports ZK prover unavailable.
/// Used when the `zk-prover` feature is not enabled.
#[cfg(not(feature = "zk-prover"))]
pub struct Groth16Prover {
    blacklist: SparseMerkleTree,
    tree_depth: usize,
}

#[cfg(not(feature = "zk-prover"))]
impl Groth16Prover {
    pub fn setup(tree_depth: usize) -> Result<Self, ZkError> {
        Ok(Self {
            blacklist: SparseMerkleTree::new(tree_depth),
            tree_depth,
        })
    }

    pub fn add_to_blacklist(&mut self, address: &[u8]) {
        self.blacklist.insert(address);
    }

    pub fn remove_from_blacklist(&mut self, address: &[u8]) {
        self.blacklist.remove(address);
    }

    pub fn set_blacklist(&mut self, addresses: &[Vec<u8>]) {
        self.blacklist = SparseMerkleTree::new(self.tree_depth);
        for addr in addresses {
            self.blacklist.insert(addr);
        }
    }

    pub fn is_blacklisted(&self, address: &[u8]) -> bool {
        self.blacklist.contains(address)
    }

    pub fn generate_proof(
        &self,
        _address: &[u8],
        _daa_score: u64,
    ) -> Result<BlacklistProof, ZkError> {
        Err(ZkError::NoProverConfigured)
    }

    pub fn blacklist_root(&self) -> [u8; 32] {
        self.blacklist.root()
    }

    pub fn blacklist_size(&self) -> usize {
        self.blacklist.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_prover_blacklist_operations() {
        let mut prover = Groth16Prover::setup(10).unwrap();
        assert_eq!(prover.blacklist_size(), 0);

        prover.add_to_blacklist(b"bad_addr_1");
        assert_eq!(prover.blacklist_size(), 1);
        assert!(prover.is_blacklisted(b"bad_addr_1"));
        assert!(!prover.is_blacklisted(b"good_addr"));

        prover.remove_from_blacklist(b"bad_addr_1");
        assert_eq!(prover.blacklist_size(), 0);
    }

    #[test]
    fn stub_prover_set_blacklist() {
        let mut prover = Groth16Prover::setup(10).unwrap();
        prover.set_blacklist(&[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(prover.blacklist_size(), 3);
        assert!(prover.is_blacklisted(b"a"));
        assert!(prover.is_blacklisted(b"b"));
        assert!(prover.is_blacklisted(b"c"));
        assert!(!prover.is_blacklisted(b"d"));
    }

    #[cfg(not(feature = "zk-prover"))]
    #[test]
    fn stub_prover_generate_proof_returns_error() {
        let prover = Groth16Prover::setup(10).unwrap();
        let result = prover.generate_proof(b"addr", 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            ZkError::NoProverConfigured => {}
            other => panic!("expected NoProverConfigured, got: {:?}", other),
        }
    }

    #[cfg(feature = "zk-prover")]
    #[test]
    fn groth16_circuit_satisfaction_check() {
        use ark_bn254::Fr;
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
        use crate::zk::circuit::{compute_algebraic_root_fe, BlacklistNonMembershipCircuit};

        let depth = 5;
        let address = b"clean_address";
        let blacklist = SparseMerkleTree::new(depth);
        let address_hash = kob_core::blake2b_256(address);
        let merkle_proof = blacklist.prove(address);

        let siblings = merkle_proof.siblings.clone();
        let algebraic_root_fe = compute_algebraic_root_fe(
            &merkle_proof.leaf,
            &siblings,
            merkle_proof.index,
        );

        let circuit = BlacklistNonMembershipCircuit::new(
            address_hash,
            algebraic_root_fe,
            1000,
            siblings,
            merkle_proof.leaf,
            merkle_proof.index,
            depth,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit should be satisfied");
    }

    #[cfg(feature = "zk-prover")]
    #[test]
    fn groth16_setup_and_prove_non_member() {
        // Use small depth for fast testing
        let prover = Groth16Prover::setup(5).unwrap();
        let result = prover.generate_proof(b"clean_address", 1000);
        assert!(result.is_ok(), "should generate proof for non-blacklisted address: {:?}", result.err());
        let proof = result.unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert!(!proof.public_inputs_bytes.is_empty());
        assert!(!proof.vk_bytes.is_empty());
    }

    #[cfg(feature = "zk-prover")]
    #[test]
    fn groth16_prove_blacklisted_fails() {
        let mut prover = Groth16Prover::setup(5).unwrap();
        prover.add_to_blacklist(b"bad_address");
        let result = prover.generate_proof(b"bad_address", 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            ZkError::BlacklistCheckFailed(_) => {}
            other => panic!("expected BlacklistCheckFailed, got: {:?}", other),
        }
    }
}
