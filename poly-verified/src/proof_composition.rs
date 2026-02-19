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

/// Maximum number of inner proofs allowed in a composite.
/// A realistic verified computation graph should not exceed 1024 nested calls.
/// This prevents DoS via allocation of millions of serialized proof hashes.
pub const MAX_INNER_PROOFS: usize = 1024;

impl CompositeProof {
    /// Create a composite proof from an outer proof and a list of inner proofs.
    ///
    /// # Panics
    /// Panics if `inner_proofs.len()` exceeds [`MAX_INNER_PROOFS`] (1024).
    pub fn compose(outer_proof: VerifiedProof, inner_proofs: Vec<VerifiedProof>) -> Self {
        // [V8-03 FIX] Cap the number of inner proofs to prevent DoS via
        // unbounded serialization and hashing in compute_composition_hash.
        assert!(
            inner_proofs.len() <= MAX_INNER_PROOFS,
            "CompositeProof: inner_proofs count {} exceeds maximum {}",
            inner_proofs.len(),
            MAX_INNER_PROOFS,
        );
        let composition_hash = Self::compute_composition_hash(&outer_proof, &inner_proofs);
        let privacy_mode = Self::most_restrictive_privacy(&outer_proof, &inner_proofs);
        Self {
            outer_proof,
            inner_proofs,
            composition_hash,
            privacy_mode,
        }
    }

    /// Compute the binding hash over all proofs and the effective privacy mode.
    ///
    /// [V13-11 FIX] The privacy_mode is now bound into the composition hash.
    /// Previously, an attacker could deserialize a CompositeProof, tamper with
    /// the privacy_mode field (e.g., downgrade Private to Transparent), and
    /// verify_composition would still pass because privacy_mode was not part
    /// of the hash. Now the effective (most restrictive) privacy mode is
    /// included as the final hash_combine step.
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

        // [V13-11 FIX] Bind the effective privacy mode into the composition hash.
        let effective_privacy = Self::most_restrictive_privacy(outer, inners);
        let privacy_binding = hash_data(&[effective_privacy as u8]);
        combined = hash_combine(&combined, &privacy_binding);

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
    ///
    /// Also performs structural validation: the outer proof must be
    /// structurally valid (step_count > 0 for HashIvc), and all inner
    /// proofs must also be structurally valid.
    pub fn verify_composition(&self) -> bool {
        // [V8-03 FIX] Reject composites with too many inner proofs.
        // A deserialized CompositeProof bypasses the compose() constructor,
        // so we must also check the cap during verification.
        if self.inner_proofs.len() > MAX_INNER_PROOFS {
            return false;
        }

        // [V7-05 FIX] Structural validation of all contained proofs.
        // Without this, an attacker could wrap invalid proofs inside a
        // CompositeProof and the composition hash would still verify,
        // making the composite appear legitimate.
        if !Self::is_structurally_valid(&self.outer_proof) {
            return false;
        }
        for inner in &self.inner_proofs {
            if !Self::is_structurally_valid(inner) {
                return false;
            }
        }

        // [V13-11 FIX] Verify that the stored privacy_mode matches the
        // most restrictive mode computed from the contained proofs. Without
        // this, an attacker could tamper with the privacy_mode field after
        // serialization (e.g., downgrade Private to Transparent).
        let expected_privacy = Self::most_restrictive_privacy(&self.outer_proof, &self.inner_proofs);
        if self.privacy_mode as u8 != expected_privacy as u8 {
            return false;
        }

        let expected = Self::compute_composition_hash(&self.outer_proof, &self.inner_proofs);
        hash_eq(&expected, &self.composition_hash)
    }

    /// Check whether a proof is structurally valid (non-empty computation).
    fn is_structurally_valid(proof: &VerifiedProof) -> bool {
        match proof {
            VerifiedProof::HashIvc {
                step_count,
                checkpoints,
                ..
            } => *step_count > 0 && checkpoints.len() as u64 == *step_count,
            VerifiedProof::Mock { .. } => true,
        }
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
