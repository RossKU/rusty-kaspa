//! Sparse Merkle tree for blacklist non-membership proofs.

use std::collections::HashMap;

/// Default tree depth (20 levels = 2^20 = ~1M leaf positions).
pub const DEFAULT_TREE_DEPTH: usize = 20;

/// Blake2b-256 hash used for merkle nodes. Matches Kaspa's native hash.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    kob_core::blake2b_256(data)
}

/// Hash two 32-byte children to produce a parent node hash.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    blake2b_256(&combined)
}

/// The default hash for an empty leaf (all zeros).
pub const DEFAULT_LEAF: [u8; 32] = [0u8; 32];

/// Precomputed default hashes at each level of the tree.
/// `defaults[0]` = DEFAULT_LEAF (leaf level)
/// `defaults[i]` = hash(defaults[i-1], defaults[i-1])
fn compute_defaults(depth: usize) -> Vec<[u8; 32]> {
    let mut defaults = vec![[0u8; 32]; depth + 1];
    defaults[0] = DEFAULT_LEAF;
    for i in 1..=depth {
        defaults[i] = hash_pair(&defaults[i - 1], &defaults[i - 1]);
    }
    defaults
}

/// A merkle proof for a leaf in the sparse merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf value at the queried position.
    pub leaf: [u8; 32],
    /// Sibling hashes from leaf to root. `siblings[0]` is at the leaf level.
    pub siblings: Vec<[u8; 32]>,
    /// The index (position) of the leaf in the tree.
    pub index: u64,
}

impl MerkleProof {
    /// Verify this proof against an expected root.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let mut current = self.leaf;
        let mut idx = self.index;
        for sibling in &self.siblings {
            if idx & 1 == 0 {
                current = hash_pair(&current, sibling);
            } else {
                current = hash_pair(sibling, &current);
            }
            idx >>= 1;
        }
        &current == expected_root
    }

    /// Returns true if this proof demonstrates non-membership (leaf is default).
    pub fn is_non_member(&self) -> bool {
        self.leaf == DEFAULT_LEAF
    }
}

/// Sparse Merkle Tree for blacklist management.
///
/// Only stores non-default leaves, keeping memory usage proportional to the
/// number of blacklisted addresses rather than 2^depth.
#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    /// Tree depth (number of levels from root to leaves).
    depth: usize,
    /// Non-default leaf values, indexed by their position in the tree.
    leaves: HashMap<u64, [u8; 32]>,
    /// Cached internal nodes. Key: (level, index), Value: hash.
    /// Level 0 = leaves, level `depth` = root.
    nodes: HashMap<(usize, u64), [u8; 32]>,
    /// Precomputed default hashes at each level.
    defaults: Vec<[u8; 32]>,
}

impl SparseMerkleTree {
    /// Create a new empty sparse merkle tree with the given depth.
    pub fn new(depth: usize) -> Self {
        let defaults = compute_defaults(depth);
        Self {
            depth,
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            defaults,
        }
    }

    /// Create a new tree with the default depth (20).
    pub fn new_default() -> Self {
        Self::new(DEFAULT_TREE_DEPTH)
    }

    /// Compute the leaf index for an address (position in the tree).
    /// Uses the first `depth` bits of Blake2b-256(address).
    pub fn address_to_index(&self, address: &[u8]) -> u64 {
        let h = blake2b_256(address);
        // Take the first 8 bytes and mask to tree depth
        let raw = u64::from_le_bytes(h[..8].try_into().unwrap());
        raw & ((1u64 << self.depth) - 1)
    }

    /// Insert an address into the blacklist.
    /// The leaf value is set to blake2b_256(address) (non-default = present).
    pub fn insert(&mut self, address: &[u8]) {
        let index = self.address_to_index(address);
        let leaf_value = blake2b_256(address);
        self.leaves.insert(index, leaf_value);
        self.update_path(index);
    }

    /// Remove an address from the blacklist.
    /// Resets the leaf to the default value.
    pub fn remove(&mut self, address: &[u8]) {
        let index = self.address_to_index(address);
        self.leaves.remove(&index);
        self.update_path(index);
    }

    /// Check if an address is in the blacklist.
    pub fn contains(&self, address: &[u8]) -> bool {
        let index = self.address_to_index(address);
        self.leaves.contains_key(&index)
    }

    /// Get the current root hash.
    pub fn root(&self) -> [u8; 32] {
        self.get_node(self.depth, 0)
    }

    /// Generate a merkle proof for the given address.
    pub fn prove(&self, address: &[u8]) -> MerkleProof {
        let index = self.address_to_index(address);
        let leaf = self.get_leaf(index);
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;

        for level in 0..self.depth {
            let sibling_idx = idx ^ 1; // flip last bit to get sibling
            siblings.push(self.get_node(level, sibling_idx));
            idx >>= 1;
        }

        MerkleProof {
            leaf,
            siblings,
            index,
        }
    }

    /// Number of blacklisted addresses.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the blacklist is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }

    // -- Internal helpers --

    fn get_leaf(&self, index: u64) -> [u8; 32] {
        self.leaves.get(&index).copied().unwrap_or(DEFAULT_LEAF)
    }

    fn get_node(&self, level: usize, index: u64) -> [u8; 32] {
        if level == 0 {
            return self.get_leaf(index);
        }
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.defaults[level])
    }

    fn update_path(&mut self, leaf_index: u64) {
        let mut idx = leaf_index;
        for level in 0..self.depth {
            let parent_idx = idx >> 1;
            let left_child = idx & !1; // even sibling
            let right_child = idx | 1; // odd sibling

            let left = self.get_node(level, left_child);
            let right = self.get_node(level, right_child);
            let parent_hash = hash_pair(&left, &right);

            if parent_hash == self.defaults[level + 1] {
                self.nodes.remove(&(level + 1, parent_idx));
            } else {
                self.nodes.insert((level + 1, parent_idx), parent_hash);
            }
            idx = parent_idx;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_deterministic() {
        let t1 = SparseMerkleTree::new(10);
        let t2 = SparseMerkleTree::new(10);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn empty_tree_root_equals_defaults() {
        let t = SparseMerkleTree::new(10);
        let defaults = compute_defaults(10);
        assert_eq!(t.root(), defaults[10]);
    }

    #[test]
    fn insert_changes_root() {
        let mut t = SparseMerkleTree::new(10);
        let root_before = t.root();
        t.insert(b"blacklisted_addr_1");
        assert_ne!(t.root(), root_before);
    }

    #[test]
    fn insert_and_remove_restores_root() {
        let mut t = SparseMerkleTree::new(10);
        let root_before = t.root();
        t.insert(b"blacklisted_addr_1");
        t.remove(b"blacklisted_addr_1");
        assert_eq!(t.root(), root_before);
    }

    #[test]
    fn contains_after_insert() {
        let mut t = SparseMerkleTree::new(10);
        assert!(!t.contains(b"addr1"));
        t.insert(b"addr1");
        assert!(t.contains(b"addr1"));
        assert!(!t.contains(b"addr2"));
    }

    #[test]
    fn non_membership_proof_for_absent_address() {
        let mut t = SparseMerkleTree::new(10);
        t.insert(b"blacklisted_1");
        t.insert(b"blacklisted_2");

        let proof = t.prove(b"clean_address");
        assert!(proof.is_non_member(), "clean address should have default leaf");
        assert!(proof.verify(&t.root()), "proof should verify against root");
    }

    #[test]
    fn membership_proof_for_present_address() {
        let mut t = SparseMerkleTree::new(10);
        t.insert(b"blacklisted_1");

        let proof = t.prove(b"blacklisted_1");
        assert!(!proof.is_non_member(), "blacklisted address should not have default leaf");
        assert!(proof.verify(&t.root()), "proof should verify against root");
    }

    #[test]
    fn proof_fails_against_wrong_root() {
        let mut t = SparseMerkleTree::new(10);
        t.insert(b"blacklisted_1");

        let proof = t.prove(b"clean_address");
        let wrong_root = [0xffu8; 32];
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn multiple_insertions() {
        let mut t = SparseMerkleTree::new(15);
        for i in 0..100u32 {
            t.insert(&i.to_le_bytes());
        }
        assert_eq!(t.len(), 100);

        // All inserted addresses should be members
        for i in 0..100u32 {
            let proof = t.prove(&i.to_le_bytes());
            assert!(!proof.is_non_member());
            assert!(proof.verify(&t.root()));
        }

        // Non-inserted address should be non-member
        let proof = t.prove(&200u32.to_le_bytes());
        assert!(proof.is_non_member());
        assert!(proof.verify(&t.root()));
    }

    #[test]
    fn default_depth_tree() {
        let t = SparseMerkleTree::new_default();
        assert_eq!(t.depth(), DEFAULT_TREE_DEPTH);
        assert!(t.is_empty());
    }

    #[test]
    fn proof_siblings_length_equals_depth() {
        let t = SparseMerkleTree::new(12);
        let proof = t.prove(b"any_address");
        assert_eq!(proof.siblings.len(), 12);
    }
}
