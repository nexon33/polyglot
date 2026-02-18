use crate::crypto::hash::{hash_combine, hash_data};
use crate::types::{hash_eq, Hash, PrivacyMode, VerifiedProof};

/// A composite proof that encompasses multiple nested verified computations.
///
/// When `#[verified] fn outer()` calls `#[verified] fn inner()`,
/// the inner proof is absorbed into the composite proof. The result
/// is a single proof covering the entire computation graph.
///
/// The composite's effective privacy mode is the most restrictive among
/// all contained proofs: if any proof is `Private`, the composite is `Private`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompositeProof {
    /// The top-level proof (from the outermost verified function).
    pub outer_proof: VerifiedProof,
    /// Proofs from inner verified function calls, in call order.
    pub inner_proofs: Vec<VerifiedProof>,
    /// Hash binding all proofs together: H(outer || inner_0 || inner_1 || ...).
    pub composition_hash: Hash,
    /// The most restrictive privacy mode among all composed proofs.
    pub privacy_mode: PrivacyMode,
}

impl CompositeProof {
    /// Create a composite proof from an outer proof and a list of inner proofs.
    pub fn compose(outer_proof: VerifiedProof, inner_proofs: Vec<VerifiedProof>) -> Self {
        let composition_hash = Self::compute_composition_hash(&outer_proof, &inner_proofs);
        let privacy_mode = Self::most_restrictive_privacy(&outer_proof, &inner_proofs);
        Self {
            outer_proof,
            inner_proofs,
            composition_hash,
            privacy_mode,
        }
    }

    /// Compute the binding hash over all proofs.
    ///
    /// Panics if a proof cannot be serialized (this is a programming error,
    /// not an adversarial condition). Previous code used `unwrap_or_default()`
    /// which would silently produce identical hashes for different invalid
    /// proofs, allowing composition hash collisions.
    fn compute_composition_hash(outer: &VerifiedProof, inners: &[VerifiedProof]) -> Hash {
        let outer_bytes = serde_json::to_vec(outer)
            .expect("VerifiedProof serialization must not fail");
        let mut combined = hash_data(&outer_bytes);

        for inner in inners {
            let inner_bytes = serde_json::to_vec(inner)
                .expect("VerifiedProof serialization must not fail");
            let inner_hash = hash_data(&inner_bytes);
            combined = hash_combine(&combined, &inner_hash);
        }

        combined
    }

    /// Determine the most restrictive privacy mode among all proofs.
    /// Private > PrivateInputs > Transparent
    fn most_restrictive_privacy(
        outer: &VerifiedProof,
        inners: &[VerifiedProof],
    ) -> PrivacyMode {
        let mut most_restrictive = outer.privacy_mode();
        for inner in inners {
            let inner_privacy = inner.privacy_mode();
            most_restrictive = match (most_restrictive, inner_privacy) {
                (PrivacyMode::Private, _) | (_, PrivacyMode::Private) => PrivacyMode::Private,
                (PrivacyMode::PrivateInputs, _) | (_, PrivacyMode::PrivateInputs) => {
                    PrivacyMode::PrivateInputs
                }
                _ => PrivacyMode::Transparent,
            };
        }
        most_restrictive
    }

    /// Verify the composition hash is consistent with the contained proofs.
    /// Uses constant-time comparison to prevent timing side-channel leakage.
    pub fn verify_composition(&self) -> bool {
        let expected = Self::compute_composition_hash(&self.outer_proof, &self.inner_proofs);
        hash_eq(&expected, &self.composition_hash)
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
            privacy_mode: PrivacyMode::Transparent,
        };
        let composite = CompositeProof::compose(outer, vec![]);
        assert_eq!(composite.proof_count(), 1);
        assert_eq!(composite.privacy_mode, PrivacyMode::Transparent);
        assert!(composite.verify_composition());
    }

    #[test]
    fn test_compose_nested() {
        let outer = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        };
        let inner = VerifiedProof::Mock {
            input_hash: [0x01; 32],
            output_hash: [0x02; 32],
            privacy_mode: PrivacyMode::Transparent,
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
            privacy_mode: PrivacyMode::Transparent,
        };
        let mut composite = CompositeProof::compose(outer, vec![]);
        composite.composition_hash[0] ^= 0xFF;
        assert!(!composite.verify_composition());
    }

    #[test]
    fn test_compose_privacy_propagation_private() {
        let outer = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        };
        let inner = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Private,
        };
        let composite = CompositeProof::compose(outer, vec![inner]);
        // Most restrictive wins: Private
        assert_eq!(composite.privacy_mode, PrivacyMode::Private);
    }

    #[test]
    fn test_compose_privacy_propagation_private_inputs() {
        let outer = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::PrivateInputs,
        };
        let inner = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        };
        let composite = CompositeProof::compose(outer, vec![inner]);
        assert_eq!(composite.privacy_mode, PrivacyMode::PrivateInputs);
    }
}
