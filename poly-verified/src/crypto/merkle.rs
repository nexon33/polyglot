use crate::error::{ProofSystemError, Result};
use crate::crypto::hash::hash_combine;
use crate::types::{Hash, MerkleProof, ProofNode, ZERO_HASH};

/// A Merkle tree built from an ordered list of leaf hashes.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// layers[0] = leaves, layers[last] = [root].
    pub layers: Vec<Vec<Hash>>,
    pub root: Hash,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf hashes.
    ///
    /// Odd-element rule: when a layer has an odd number of elements, the last
    /// element is duplicated as hash_combine(element, element).
    pub fn build(leaves: &[Hash]) -> Self {
        if leaves.is_empty() {
            return Self {
                layers: vec![vec![]],
                root: ZERO_HASH,
            };
        }

        let mut layers: Vec<Vec<Hash>> = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));

            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(hash_combine(&current[i], &current[i + 1]));
                } else {
                    // Odd element: duplicate
                    next.push(hash_combine(&current[i], &current[i]));
                }
                i += 2;
            }

            layers.push(next.clone());
            current = next;
        }

        let root = current[0];
        Self { layers, root }
    }

    /// Generate a Merkle inclusion proof for the leaf at `leaf_index`.
    ///
    /// The `code_hash` binds this proof to the code that produced the computation.
    pub fn generate_proof(&self, leaf_index: u64, code_hash: &Hash) -> Result<MerkleProof> {
        let leaf_idx = leaf_index as usize;
        let leaves = &self.layers[0];

        if leaves.is_empty() || leaf_idx >= leaves.len() {
            return Err(ProofSystemError::IndexOutOfBounds {
                index: leaf_index,
                length: leaves.len() as u64,
            });
        }

        let mut siblings = Vec::new();
        let mut current_index = leaf_idx;

        // Traverse from leaf layer to just before root layer
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling_hash = if sibling_index < layer.len() {
                layer[sibling_index]
            } else {
                // Edge case: odd layer, duplicate self
                layer[current_index]
            };

            // is_left means: this sibling is on the LEFT of the current node
            // i.e., current_index is odd → sibling (at index-1) is on the left
            let is_left = current_index % 2 == 1;

            siblings.push(ProofNode {
                hash: sibling_hash,
                is_left,
            });

            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf: leaves[leaf_idx],
            leaf_index,
            siblings,
            root: self.root,
            code_hash: *code_hash,
        })
    }
}

/// Verify a Merkle inclusion proof.
pub fn verify_proof(proof: &MerkleProof) -> bool {
    let mut current = proof.leaf;

    for node in &proof.siblings {
        if node.is_left {
            current = hash_combine(&node.hash, &current);
        } else {
            current = hash_combine(&current, &node.hash);
        }
    }

    current == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::hash_data;

    fn make_4_leaves() -> Vec<Hash> {
        vec![
            hash_data(&[0x00]),
            hash_data(&[0x01]),
            hash_data(&[0x02]),
            hash_data(&[0x03]),
        ]
    }

    // Appendix A: 4-checkpoint Merkle tree
    #[test]
    fn test_build_4_leaves() {
        let leaves = make_4_leaves();
        let tree = MerkleTree::build(&leaves);

        assert_eq!(tree.layers.len(), 3); // leaves, interior, root
        assert_eq!(tree.layers[0].len(), 4);
        assert_eq!(tree.layers[1].len(), 2);
        assert_eq!(tree.layers[2].len(), 1);

        // Verify interior nodes
        let node_0 = hash_combine(&leaves[0], &leaves[1]);
        let node_1 = hash_combine(&leaves[2], &leaves[3]);
        assert_eq!(tree.layers[1][0], node_0);
        assert_eq!(tree.layers[1][1], node_1);

        // Verify root
        let root = hash_combine(&node_0, &node_1);
        assert_eq!(tree.root, root);
    }

    // Appendix A.5: Merkle proof for index 2
    #[test]
    fn test_proof_index_2() {
        let leaves = make_4_leaves();
        let tree = MerkleTree::build(&leaves);
        let proof = tree.generate_proof(2, &ZERO_HASH).unwrap();

        assert_eq!(proof.leaf, leaves[2]);
        assert_eq!(proof.leaf_index, 2);
        assert_eq!(proof.siblings.len(), 2);

        // Sibling 0: leaf_3, is_left=false (index 2 is even)
        assert_eq!(proof.siblings[0].hash, leaves[3]);
        assert!(!proof.siblings[0].is_left);

        // Sibling 1: node_0 = hash_combine(leaf_0, leaf_1), is_left=true (index 1 is odd)
        let node_0 = hash_combine(&leaves[0], &leaves[1]);
        assert_eq!(proof.siblings[1].hash, node_0);
        assert!(proof.siblings[1].is_left);

        // Verification
        assert!(verify_proof(&proof));
    }

    // Test all 4 indices
    #[test]
    fn test_proof_all_indices() {
        let leaves = make_4_leaves();
        let tree = MerkleTree::build(&leaves);

        for i in 0..4 {
            let proof = tree.generate_proof(i, &ZERO_HASH).unwrap();
            assert!(verify_proof(&proof), "proof failed for index {i}");
        }
    }

    // Edge case: single leaf
    #[test]
    fn test_single_leaf() {
        let leaf = hash_data(&[0x42]);
        let tree = MerkleTree::build(&[leaf]);

        assert_eq!(tree.layers.len(), 1);
        assert_eq!(tree.root, leaf);

        let proof = tree.generate_proof(0, &ZERO_HASH).unwrap();
        assert_eq!(proof.siblings.len(), 0);
        assert!(verify_proof(&proof));
    }

    // Edge case: 3 leaves (odd)
    #[test]
    fn test_3_leaves_odd() {
        let leaves = vec![
            hash_data(&[0x00]),
            hash_data(&[0x01]),
            hash_data(&[0x02]),
        ];
        let tree = MerkleTree::build(&leaves);

        // Layer 1: hash(l0,l1), hash(l2,l2) — odd element duplicated
        assert_eq!(tree.layers[1].len(), 2);
        let expected_dup = hash_combine(&leaves[2], &leaves[2]);
        assert_eq!(tree.layers[1][1], expected_dup);

        // All proofs verify
        for i in 0..3 {
            let proof = tree.generate_proof(i, &ZERO_HASH).unwrap();
            assert!(verify_proof(&proof), "proof failed for index {i}");
        }
    }

    // Edge case: empty
    #[test]
    fn test_empty() {
        let tree = MerkleTree::build(&[]);
        assert_eq!(tree.root, ZERO_HASH);
    }

    // Proof serialization round-trip
    #[test]
    fn test_proof_serialization_roundtrip() {
        let leaves = make_4_leaves();
        let tree = MerkleTree::build(&leaves);
        let proof = tree.generate_proof(2, &ZERO_HASH).unwrap();

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), proof.byte_size());

        let decoded = MerkleProof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.leaf, proof.leaf);
        assert_eq!(decoded.leaf_index, proof.leaf_index);
        assert_eq!(decoded.siblings.len(), proof.siblings.len());
        assert_eq!(decoded.root, proof.root);

        assert!(verify_proof(&decoded));
    }

    // Corrupted proof must fail
    #[test]
    fn test_corrupted_proof_fails() {
        let leaves = make_4_leaves();
        let tree = MerkleTree::build(&leaves);
        let mut proof = tree.generate_proof(2, &ZERO_HASH).unwrap();

        // Corrupt a sibling hash
        proof.siblings[0].hash[0] ^= 0xFF;
        assert!(!verify_proof(&proof));
    }

    // Out-of-bounds index
    #[test]
    fn test_out_of_bounds() {
        let leaves = make_4_leaves();
        let tree = MerkleTree::build(&leaves);
        assert!(tree.generate_proof(4, &ZERO_HASH).is_err());
    }
}
