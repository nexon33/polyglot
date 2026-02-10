use crate::crypto::hash::{hash_combine, hash_data};
use crate::types::{Hash, VerifiedProof};

/// A composite proof that encompasses multiple nested verified computations.
///
/// When `#[verified] fn outer()` calls `#[verified] fn inner()`,
/// the inner proof is absorbed into the composite proof. The result
/// is a single proof covering the entire computation graph.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompositeProof {
    /// The top-level proof (from the outermost verified function).
    pub outer_proof: VerifiedProof,
    /// Proofs from inner verified function calls, in call order.
    pub inner_proofs: Vec<VerifiedProof>,
    /// Hash binding all proofs together: H(outer || inner_0 || inner_1 || ...).
    pub composition_hash: Hash,
}

impl CompositeProof {
    /// Create a composite proof from an outer proof and a list of inner proofs.
    pub fn compose(outer_proof: VerifiedProof, inner_proofs: Vec<VerifiedProof>) -> Self {
        let composition_hash = Self::compute_composition_hash(&outer_proof, &inner_proofs);
        Self {
            outer_proof,
            inner_proofs,
            composition_hash,
        }
    }

    /// Compute the binding hash over all proofs.
    fn compute_composition_hash(
        outer: &VerifiedProof,
        inners: &[VerifiedProof],
    ) -> Hash {
        let outer_bytes = serde_json::to_vec(outer).unwrap_or_default();
        let mut combined = hash_data(&outer_bytes);

        for inner in inners {
            let inner_bytes = serde_json::to_vec(inner).unwrap_or_default();
            let inner_hash = hash_data(&inner_bytes);
            combined = hash_combine(&combined, &inner_hash);
        }

        combined
    }

    /// Verify the composition hash is consistent with the contained proofs.
    pub fn verify_composition(&self) -> bool {
        let expected = Self::compute_composition_hash(&self.outer_proof, &self.inner_proofs);
        expected == self.composition_hash
    }

    /// Total number of proofs in this composite.
    pub fn proof_count(&self) -> usize {
        1 + self.inner_proofs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZERO_HASH;

    #[test]
    fn test_compose_single() {
        let outer = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
        };
        let composite = CompositeProof::compose(outer, vec![]);
        assert_eq!(composite.proof_count(), 1);
        assert!(composite.verify_composition());
    }

    #[test]
    fn test_compose_nested() {
        let outer = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
        };
        let inner = VerifiedProof::Mock {
            input_hash: [0x01; 32],
            output_hash: [0x02; 32],
        };
        let composite = CompositeProof::compose(outer, vec![inner]);
        assert_eq!(composite.proof_count(), 2);
        assert!(composite.verify_composition());
    }

    #[test]
    fn test_tampered_composition_fails() {
        let outer = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
        };
        let mut composite = CompositeProof::compose(outer, vec![]);
        composite.composition_hash[0] ^= 0xFF;
        assert!(!composite.verify_composition());
    }
}
