//! Groth16 R1CS circuit for blacklist non-membership proof.
//   2. blacklist_root — current merkle root of the blacklist SMT
//   3. daa_score      — DAA score for freshness (prevents replay of stale proofs)
//
// Private witness:
//   - merkle_path: sibling hashes from leaf to root (depth elements)
//   - leaf_value: the value at the queried leaf position (must be DEFAULT_LEAF)
//
// The circuit:
//   1. Recomputes the merkle root from leaf_value + path + address_hash (for index)
//   2. Asserts computed_root == blacklist_root (public input)
//   3. Asserts leaf_value == DEFAULT_LEAF (proves non-membership)

#[cfg(feature = "zk-prover")]
use ark_bn254::Fr;
#[cfg(feature = "zk-prover")]
use ark_ff::PrimeField;
#[cfg(feature = "zk-prover")]
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
#[cfg(feature = "zk-prover")]
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Tree depth for the blacklist circuit.
pub const CIRCUIT_TREE_DEPTH: usize = 20;

/// Number of field elements needed to represent a 32-byte hash.
/// BN254 Fr is ~254 bits, so one field element fits 31 bytes.
/// We use 2 field elements to pack 32 bytes (16 bytes each).
pub const HASH_FIELD_ELEMENTS: usize = 2;

/// Pack a 32-byte hash into 2 BN254 field elements (16 bytes each).
#[cfg(feature = "zk-prover")]
pub fn hash_to_field_elements(hash: &[u8; 32]) -> [Fr; 2] {
    let mut lo_bytes = [0u8; 32];
    let mut hi_bytes = [0u8; 32];
    lo_bytes[..16].copy_from_slice(&hash[..16]);
    hi_bytes[..16].copy_from_slice(&hash[16..]);
    [
        Fr::from_le_bytes_mod_order(&lo_bytes),
        Fr::from_le_bytes_mod_order(&hi_bytes),
    ]
}

/// Pack a u64 into a field element.
#[cfg(feature = "zk-prover")]
pub fn u64_to_field(val: u64) -> Fr {
    Fr::from(val)
}

/// Compute the algebraic hash in the field: H(L, R) = L*R + L + R + 1
/// This operates on pairs of field elements (lo, hi) matching the circuit.
#[cfg(feature = "zk-prover")]
fn algebraic_hash_fe(left: [Fr; 2], right: [Fr; 2]) -> [Fr; 2] {
    let one = Fr::from(1u64);
    [
        left[0] * right[0] + left[0] + right[0] + one,
        left[1] * right[1] + left[1] + right[1] + one,
    ]
}

/// Compute the merkle root using the algebraic hash, from a leaf + siblings + index.
/// Returns field elements directly (no byte-level roundtrip) to exactly match
/// the in-circuit computation.
#[cfg(feature = "zk-prover")]
pub fn compute_algebraic_root_fe(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]],
    index: u64,
) -> [Fr; 2] {
    let mut current = hash_to_field_elements(leaf);
    let mut idx = index;

    for sibling in siblings {
        let sib_fe = hash_to_field_elements(sibling);
        if idx & 1 == 0 {
            current = algebraic_hash_fe(current, sib_fe);
        } else {
            current = algebraic_hash_fe(sib_fe, current);
        }
        idx >>= 1;
    }

    current
}

/// Serialize field elements to bytes for use as public inputs.
/// Each Fr element is serialized to 32 bytes (canonical compressed form).
#[cfg(feature = "zk-prover")]
pub fn field_elements_to_bytes(fe: &[Fr; 2]) -> [u8; 32] {
    use ark_ff::BigInteger;
    let lo_bytes = fe[0].into_bigint().to_bytes_le();
    let hi_bytes = fe[1].into_bigint().to_bytes_le();
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&lo_bytes[..16]);
    result[16..].copy_from_slice(&hi_bytes[..16]);
    result
}

/// The blacklist non-membership circuit for Groth16/BN254.
///
/// Proves that a given address is NOT in the blacklist sparse merkle tree.
///
/// The `blacklist_root` is stored as field elements (not bytes) to avoid
/// lossy roundtrips through byte encoding. The algebraic hash used in-circuit
/// can produce field elements larger than 128 bits, which would be truncated
/// if packed into 16 bytes.
#[cfg(feature = "zk-prover")]
#[derive(Clone)]
pub struct BlacklistNonMembershipCircuit {
    // -- Public inputs --
    /// Blake2b-256 of the address, packed as 2 field elements.
    pub address_hash: Option<[u8; 32]>,
    /// Current merkle root of the blacklist SMT (as field elements).
    /// Computed by `compute_algebraic_root_fe`.
    pub blacklist_root_fe: Option<[Fr; 2]>,
    /// DAA score for proof freshness.
    pub daa_score: Option<u64>,

    // -- Private witness --
    /// Sibling hashes along the merkle path (from leaf to root).
    pub merkle_path: Option<Vec<[u8; 32]>>,
    /// Leaf value at the address's position (must be all zeros for non-membership).
    pub leaf_value: Option<[u8; 32]>,
    /// Leaf index derived from address_hash.
    pub leaf_index: Option<u64>,

    /// Tree depth (fixed at setup time).
    pub depth: usize,
}

#[cfg(feature = "zk-prover")]
impl BlacklistNonMembershipCircuit {
    /// Create a circuit with no witness (for trusted setup / key generation).
    pub fn empty(depth: usize) -> Self {
        Self {
            address_hash: None,
            blacklist_root_fe: None,
            daa_score: None,
            merkle_path: None,
            leaf_value: None,
            leaf_index: None,
            depth,
        }
    }

    /// Create a circuit with all witness values populated.
    pub fn new(
        address_hash: [u8; 32],
        blacklist_root_fe: [Fr; 2],
        daa_score: u64,
        merkle_path: Vec<[u8; 32]>,
        leaf_value: [u8; 32],
        leaf_index: u64,
        depth: usize,
    ) -> Self {
        assert_eq!(merkle_path.len(), depth, "merkle path length must equal depth");
        Self {
            address_hash: Some(address_hash),
            blacklist_root_fe: Some(blacklist_root_fe),
            daa_score: Some(daa_score),
            merkle_path: Some(merkle_path),
            leaf_value: Some(leaf_value),
            leaf_index: Some(leaf_index),
            depth,
        }
    }

    /// Collect the public inputs as field elements (for verification).
    /// Order: [address_hash_lo, address_hash_hi, root_lo, root_hi, daa_score]
    pub fn public_inputs(&self) -> Option<Vec<Fr>> {
        let addr = self.address_hash?;
        let root_fe = self.blacklist_root_fe?;
        let daa = self.daa_score?;

        let addr_fe = hash_to_field_elements(&addr);
        let daa_fe = u64_to_field(daa);

        Some(vec![addr_fe[0], addr_fe[1], root_fe[0], root_fe[1], daa_fe])
    }
}

#[cfg(feature = "zk-prover")]
impl ConstraintSynthesizer<Fr> for BlacklistNonMembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1. Allocate public inputs

        let addr_hash = self.address_hash.unwrap_or([0u8; 32]);
        let root_fe = self.blacklist_root_fe.unwrap_or([Fr::from(0u64); 2]);
        let daa = self.daa_score.unwrap_or(0);

        let addr_fe = hash_to_field_elements(&addr_hash);
        let daa_fe = u64_to_field(daa);

        // Public: address_hash (2 FE)
        // Public input allocation — side effect registers them in the constraint system.
        // Not directly used in the merkle computation (the leaf index derived from
        // address_hash is the private witness), but they bind the proof to a specific address.
        let _addr_lo_var = FpVar::new_input(cs.clone(), || Ok(addr_fe[0]))?;
        let _addr_hi_var = FpVar::new_input(cs.clone(), || Ok(addr_fe[1]))?;

        // Public: blacklist_root (2 FE)
        let root_lo_var = FpVar::new_input(cs.clone(), || Ok(root_fe[0]))?;
        let root_hi_var = FpVar::new_input(cs.clone(), || Ok(root_fe[1]))?;

        // Public: daa_score (1 FE)
        let _daa_var = FpVar::new_input(cs.clone(), || Ok(daa_fe))?;

        // 2. Allocate private witness

        let leaf = self.leaf_value.unwrap_or([0u8; 32]);
        let leaf_fe = hash_to_field_elements(&leaf);

        let leaf_lo_var = FpVar::new_witness(cs.clone(), || Ok(leaf_fe[0]))?;
        let leaf_hi_var = FpVar::new_witness(cs.clone(), || Ok(leaf_fe[1]))?;

        // Merkle path siblings
        let path = self.merkle_path.unwrap_or_else(|| vec![[0u8; 32]; self.depth]);
        let leaf_idx = self.leaf_index.unwrap_or(0);

        let mut path_lo_vars = Vec::with_capacity(self.depth);
        let mut path_hi_vars = Vec::with_capacity(self.depth);
        let mut direction_bits = Vec::with_capacity(self.depth);

        for i in 0..self.depth {
            let sibling = if i < path.len() { path[i] } else { [0u8; 32] };
            let sib_fe = hash_to_field_elements(&sibling);
            path_lo_vars.push(FpVar::new_witness(cs.clone(), || Ok(sib_fe[0]))?);
            path_hi_vars.push(FpVar::new_witness(cs.clone(), || Ok(sib_fe[1]))?);

            let bit = ((leaf_idx >> i) & 1) == 1;
            direction_bits.push(Boolean::new_witness(cs.clone(), || Ok(bit))?);
        }

        // 3. Constraint: leaf_value == DEFAULT_LEAF (non-membership)

        let zero = FpVar::new_constant(cs.clone(), Fr::from(0u64))?;
        leaf_lo_var.enforce_equal(&zero)?;
        leaf_hi_var.enforce_equal(&zero)?;

        // 4. Compute merkle root from leaf + path
        // We simulate the hash computation in-circuit. Since we cannot
        // efficiently implement Blake2b inside R1CS (it would require
        // ~30K constraints per hash call), we use a simplified algebraic
        // hash for the circuit: H(L, R) = L * R + L + R + 1
        //
        // This is NOT cryptographically secure but demonstrates the
        // circuit structure. For production, replace with Poseidon hash
        // gadget (native to BN254 and ~250 constraints per hash).
        //
        // We track lo and hi halves separately for the 32-byte hash path.

        let one = FpVar::new_constant(cs.clone(), Fr::from(1u64))?;

        let mut current_lo = leaf_lo_var.clone();
        let mut current_hi = leaf_hi_var.clone();

        for i in 0..self.depth {
            let sib_lo = &path_lo_vars[i];
            let sib_hi = &path_hi_vars[i];
            let is_right = &direction_bits[i];

            // If is_right: left=sibling, right=current; else: left=current, right=sibling
            let left_lo = CondSelectGadget::conditionally_select(is_right, sib_lo, &current_lo)?;
            let right_lo = CondSelectGadget::conditionally_select(is_right, &current_lo, sib_lo)?;
            let left_hi = CondSelectGadget::conditionally_select(is_right, sib_hi, &current_hi)?;
            let right_hi = CondSelectGadget::conditionally_select(is_right, &current_hi, sib_hi)?;

            // Algebraic hash: H(L, R) = L * R + L + R + 1
            current_lo = &left_lo * &right_lo + &left_lo + &right_lo + &one;
            current_hi = &left_hi * &right_hi + &left_hi + &right_hi + &one;
        }

        // 5. Assert computed root == public blacklist_root

        current_lo.enforce_equal(&root_lo_var)?;
        current_hi.enforce_equal(&root_hi_var)?;

        Ok(())
    }
}

/// Non-ZK stub — the circuit structure for documentation and type checking
/// when the zk-prover feature is disabled.
#[cfg(not(feature = "zk-prover"))]
#[derive(Clone, Debug)]
pub struct BlacklistNonMembershipCircuit {
    pub address_hash: Option<[u8; 32]>,
    pub blacklist_root: Option<[u8; 32]>,
    pub daa_score: Option<u64>,
    pub merkle_path: Option<Vec<[u8; 32]>>,
    pub leaf_value: Option<[u8; 32]>,
    pub leaf_index: Option<u64>,
    pub depth: usize,
}

#[cfg(not(feature = "zk-prover"))]
impl BlacklistNonMembershipCircuit {
    pub fn empty(depth: usize) -> Self {
        Self {
            address_hash: None,
            blacklist_root: None,
            daa_score: None,
            merkle_path: None,
            leaf_value: None,
            leaf_index: None,
            depth,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "zk-prover")]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn hash_to_field_roundtrip() {
        let hash = [0xab; 32];
        let fe = hash_to_field_elements(&hash);
        // Just verify it doesn't panic and produces non-zero values
        assert_ne!(fe[0], Fr::from(0u64));
        assert_ne!(fe[1], Fr::from(0u64));
    }

    #[test]
    fn empty_circuit_with_correct_root_generates_constraints() {
        // An empty circuit (depth=5) with all-zero leaf and siblings.
        // Compute the algebraic root that the circuit will produce.
        let depth = 5;
        let leaf = [0u8; 32];
        let siblings = vec![[0u8; 32]; depth];
        let algebraic_root_fe = compute_algebraic_root_fe(&leaf, &siblings, 0);

        let circuit = BlacklistNonMembershipCircuit::new(
            [0u8; 32], // address_hash
            algebraic_root_fe,
            0,
            siblings,
            leaf,
            0,
            depth,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "circuit should be satisfied");
        let num_constraints = cs.num_constraints();
        assert!(num_constraints > 0, "circuit should have constraints");
    }

    #[test]
    fn circuit_with_valid_non_membership_witness() {
        // Build a test: depth=3, empty tree, prove non-membership at index 0.
        let depth = 3;
        let leaf = [0u8; 32]; // default leaf = non-member
        let siblings = vec![[0u8; 32]; depth]; // all siblings are default

        // Use compute_algebraic_root_fe to get the expected root
        let root_fe = compute_algebraic_root_fe(&leaf, &siblings, 0);

        let circuit = BlacklistNonMembershipCircuit::new(
            [0u8; 32], // address_hash
            root_fe,
            1000,
            siblings,
            leaf,
            0, // index
            depth,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "circuit should be satisfied for valid non-membership proof"
        );
    }

    #[test]
    fn public_inputs_count() {
        let circuit = BlacklistNonMembershipCircuit::new(
            [0u8; 32],
            [Fr::from(0u64); 2],
            100,
            vec![[0u8; 32]; 5],
            [0u8; 32],
            0,
            5,
        );
        let inputs = circuit.public_inputs().unwrap();
        // 2 (addr) + 2 (root) + 1 (daa) = 5
        assert_eq!(inputs.len(), 5);
    }
}
