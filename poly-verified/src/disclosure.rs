//! Selective disclosure of verified output tokens (Whitepaper §2.2).
//!
//! Build a Merkle tree over output tokens, reveal selected indices with
//! inclusion proofs, redact the rest with leaf-hash commitments. The tree
//! structure guarantees no gaps, insertions, or reordering.
//!
//! ```text
//! let result: Verified<Vec<u32>> = generate_verified(input, 50, 700, 42);
//!
//! // Pharmacist sees tokens 8..11 ("Recommended: LITHIUM ADJUSTMENT")
//! let pharmacist_view = create_disclosure(&result, &[8, 9, 10])?;
//!
//! // Insurer sees token 15 (risk score)
//! let insurer_view = create_disclosure(&result, &[15])?;
//!
//! // Both verify against the same execution proof
//! assert!(verify_disclosure(&pharmacist_view));
//! assert!(verify_disclosure(&insurer_view));
//! ```

use std::collections::HashSet;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

use crate::crypto::hash::hash_leaf;
use crate::crypto::merkle::{self, MerkleTree};
use crate::error::{ProofSystemError, Result};
use crate::ivc::hash_ivc::HashIvc;
use crate::ivc::IvcBackend;
use crate::types::{hash_eq, Hash, MerkleProof, VerifiedProof, ZERO_HASH};
use crate::verified_type::Verified;

/// Compute SHA-256 of raw token bytes for I/O binding.
fn tokens_hash(tokens: &[u32]) -> Hash {
    let mut hasher = Sha256::new();
    for &t in tokens {
        hasher.update(t.to_le_bytes());
    }
    hasher.finalize().into()
}

/// A single token position in a disclosure — either revealed or redacted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DisclosedToken {
    /// Token value is revealed to the verifier.
    Revealed { index: usize, token_id: u32 },
    /// Token exists but value is hidden — only the leaf commitment is shown.
    /// The verifier knows a token exists at this position but cannot learn its value.
    Redacted { index: usize, leaf_hash: Hash },
}

impl DisclosedToken {
    /// The position index of this token.
    pub fn index(&self) -> usize {
        match self {
            DisclosedToken::Revealed { index, .. } => *index,
            DisclosedToken::Redacted { index, .. } => *index,
        }
    }
}

/// Selective disclosure of verified output tokens.
///
/// Produced by [`create_disclosure`] or [`Verified::disclose`]. The client
/// controls which tokens to reveal and which to redact. Different audiences
/// can receive different `Disclosure` instances from the same computation proof.
///
/// Three disclosure levels (§2.2):
/// - **Full Reveal:** disclose all indices
/// - **Partial Redaction:** disclose a subset, redacted positions carry commitments
/// - **Fully Private:** disclose nothing (empty indices), only Merkle root available
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Disclosure {
    /// Every token position: revealed or redacted. Length == `total_tokens`.
    /// Guarantees no gaps, insertions, or reordering.
    pub tokens: Vec<DisclosedToken>,
    /// Merkle inclusion proofs for REVEALED tokens only.
    /// `proofs[i]` corresponds to the i-th `Revealed` entry in `tokens`.
    pub proofs: Vec<MerkleProof>,
    /// Merkle root over ALL output tokens (revealed + redacted).
    pub output_root: Hash,
    /// Total number of output tokens.
    pub total_tokens: usize,
    /// The execution proof from `#[verified]` — proves genuine computation.
    pub execution_proof: VerifiedProof,
    /// SHA-256 hash binding the output tokens to the execution proof.
    /// Must match the execution proof's `output_hash` to prevent proof detachment.
    pub output_binding: Hash,
}

/// Hash a token ID into a Merkle leaf.
pub fn token_leaf(token_id: u32) -> Hash {
    hash_leaf(&token_id.to_le_bytes())
}

/// Create a selective disclosure from a verified output.
///
/// # Arguments
/// - `verified` — the verified output from `#[verified]` execution
/// - `indices` — which token positions to reveal (the rest are redacted)
///
/// # Errors
/// Returns an error if any index is out of bounds.
pub fn create_disclosure(
    verified: &Verified<Vec<u32>>,
    indices: &[usize],
) -> Result<Disclosure> {
    let tokens = verified.value();
    let total_tokens = tokens.len();

    // Validate indices
    for &idx in indices {
        if idx >= total_tokens {
            return Err(ProofSystemError::IndexOutOfBounds {
                index: idx as u64,
                length: total_tokens as u64,
            });
        }
    }

    let reveal_set: HashSet<usize> = indices.iter().copied().collect();

    // Build Merkle leaves from ALL tokens
    let leaves: Vec<Hash> = tokens.iter().map(|&t| token_leaf(t)).collect();

    // Build Merkle tree
    let tree = MerkleTree::build(&leaves);

    // Get code hash from the execution proof
    let code_hash = verified.proof().code_hash();

    // Build disclosed token list + proofs for revealed tokens
    let mut disclosed_tokens = Vec::with_capacity(total_tokens);
    let mut proofs = Vec::with_capacity(indices.len());

    for i in 0..total_tokens {
        if reveal_set.contains(&i) {
            disclosed_tokens.push(DisclosedToken::Revealed {
                index: i,
                token_id: tokens[i],
            });
            let proof = tree.generate_proof(i as u64, &code_hash)?;
            proofs.push(proof);
        } else {
            disclosed_tokens.push(DisclosedToken::Redacted {
                index: i,
                leaf_hash: leaves[i],
            });
        }
    }

    // Compute binding: SHA-256 of all raw token bytes — matches proof's output_hash
    let output_binding = tokens_hash(tokens);

    Ok(Disclosure {
        tokens: disclosed_tokens,
        proofs,
        output_root: tree.root,
        total_tokens,
        execution_proof: verified.proof().clone(),
        output_binding,
    })
}

/// Create a disclosure for a contiguous range of token positions.
///
/// Convenience for the SDK pattern: `result.disclose_range(8..11)`
pub fn create_disclosure_range(
    verified: &Verified<Vec<u32>>,
    range: Range<usize>,
) -> Result<Disclosure> {
    let indices: Vec<usize> = range.collect();
    create_disclosure(verified, &indices)
}

/// Verify a selective disclosure.
///
/// Checks:
/// 1. Token positions are sequential 0..total_tokens (no gaps/reordering)
/// 2. Each revealed token's leaf matches its Merkle proof
/// 3. Each Merkle proof verifies against the output root
/// 4. Each redacted position has a non-zero leaf commitment
/// 5. The execution proof is structurally valid
pub fn verify_disclosure(disclosure: &Disclosure) -> bool {
    // Check total_tokens matches token list length
    if disclosure.tokens.len() != disclosure.total_tokens {
        return false;
    }

    // A disclosure with zero tokens is structurally invalid.
    // There must be at least one token to form a meaningful disclosure.
    if disclosure.total_tokens == 0 {
        return false;
    }

    // Check sequential indices (no gaps, no reordering)
    for (expected_idx, token) in disclosure.tokens.iter().enumerate() {
        if token.index() != expected_idx {
            return false;
        }
    }

    // Collect ALL leaf hashes (revealed = recomputed from token, redacted = as-provided)
    // and verify each revealed token against its Merkle proof.
    let mut all_leaves: Vec<Hash> = Vec::with_capacity(disclosure.total_tokens);
    let mut proof_idx = 0;
    for token in &disclosure.tokens {
        match token {
            DisclosedToken::Revealed { token_id, .. } => {
                if proof_idx >= disclosure.proofs.len() {
                    return false;
                }
                let proof = &disclosure.proofs[proof_idx];

                // Check leaf matches the token (constant-time)
                let expected_leaf = token_leaf(*token_id);
                if !hash_eq(&proof.leaf, &expected_leaf) {
                    return false;
                }

                // Check Merkle proof verifies
                if !merkle::verify_proof(proof) {
                    return false;
                }

                // Check proof root matches disclosure root (constant-time)
                if !hash_eq(&proof.root, &disclosure.output_root) {
                    return false;
                }

                all_leaves.push(expected_leaf);
                proof_idx += 1;
            }
            DisclosedToken::Redacted { leaf_hash, .. } => {
                // Redacted positions must have a real commitment (constant-time)
                if hash_eq(leaf_hash, &ZERO_HASH) {
                    return false;
                }
                all_leaves.push(*leaf_hash);
            }
        }
    }

    // All proofs should have been consumed
    if proof_idx != disclosure.proofs.len() {
        return false;
    }

    // [V5-03 FIX] Reconstruct the Merkle tree from ALL leaves and verify the
    // root matches the disclosure's output_root. This ensures redacted leaf
    // hashes are genuine (they must be the correct leaves to produce the
    // committed root). Without this check, an attacker could substitute
    // arbitrary non-zero hashes for redacted positions.
    if !all_leaves.is_empty() {
        let reconstructed = MerkleTree::build(&all_leaves);
        if !hash_eq(&reconstructed.root, &disclosure.output_root) {
            return false;
        }
    }

    // Verify output binding: disclosure must be tied to the execution proof
    match &disclosure.execution_proof {
        VerifiedProof::HashIvc {
            step_count,
            input_hash,
            output_hash,
            ..
        } => {
            if *step_count == 0 {
                return false;
            }
            // The output_binding must match the proof's committed output_hash (constant-time)
            if !hash_eq(&disclosure.output_binding, output_hash) {
                return false;
            }
            // Verify the cryptographic chain integrity (chain_tip, merkle_root,
            // checkpoints, blinding commitment). Without this, an attacker could
            // fabricate a proof with correct output_hash but invalid chain.
            let ivc = HashIvc;
            match ivc.verify(&disclosure.execution_proof, input_hash, output_hash) {
                Ok(true) => true,
                _ => false,
            }
        }
        VerifiedProof::Mock { output_hash, .. } => {
            // For Mock proofs, still check binding if output_hash is non-zero (constant-time)
            if !hash_eq(output_hash, &ZERO_HASH) && !hash_eq(&disclosure.output_binding, output_hash) {
                return false;
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::hash_data;
    use crate::ivc::hash_ivc::HashIvc;
    use crate::ivc::IvcBackend;
    use crate::types::{PrivacyMode, StepWitness, ZERO_HASH};

    fn mock_proof_for_tokens(tokens: &[u32]) -> VerifiedProof {
        VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: tokens_hash(tokens),
            privacy_mode: PrivacyMode::Transparent,
        }
    }

    /// Build a valid HashIvc proof whose output_hash matches the given tokens.
    fn valid_hash_ivc_proof_for_tokens(tokens: &[u32]) -> VerifiedProof {
        let ivc = HashIvc;
        let code_hash = [0x03; 32];
        let mut acc = ivc.init(&code_hash, PrivacyMode::Transparent);
        let witness = StepWitness {
            state_before: hash_data(b"before"),
            state_after: hash_data(b"after"),
            step_inputs: hash_data(b"inputs"),
        };
        ivc.fold_step(&mut acc, &witness).unwrap();
        // Patch I/O hashes to match the disclosure context
        acc.input_hash = ZERO_HASH;
        acc.output_hash = tokens_hash(tokens);
        ivc.finalize(acc).unwrap()
    }

    fn sample_tokens() -> Vec<u32> {
        vec![100, 200, 300, 400, 500, 600, 700, 800]
    }

    fn make_verified(tokens: Vec<u32>) -> Verified<Vec<u32>> {
        let proof = valid_hash_ivc_proof_for_tokens(&tokens);
        Verified::__macro_new(tokens, proof)
    }

    // ── Happy path tests ──────────────────────────────────────────────

    #[test]
    fn test_create_and_verify_disclosure() {
        let verified = make_verified(sample_tokens());
        let disclosure = create_disclosure(&verified, &[2, 5]).unwrap();

        assert_eq!(disclosure.total_tokens, 8);
        assert_eq!(disclosure.tokens.len(), 8);
        assert_eq!(disclosure.proofs.len(), 2);

        // Tokens 2 and 5 should be revealed
        match &disclosure.tokens[2] {
            DisclosedToken::Revealed { index, token_id } => {
                assert_eq!(*index, 2);
                assert_eq!(*token_id, 300);
            }
            _ => panic!("token 2 should be revealed"),
        }
        match &disclosure.tokens[5] {
            DisclosedToken::Revealed { index, token_id } => {
                assert_eq!(*index, 5);
                assert_eq!(*token_id, 600);
            }
            _ => panic!("token 5 should be revealed"),
        }

        // Other tokens should be redacted
        for i in [0, 1, 3, 4, 6, 7] {
            match &disclosure.tokens[i] {
                DisclosedToken::Redacted { index, leaf_hash } => {
                    assert_eq!(*index, i);
                    assert_ne!(*leaf_hash, ZERO_HASH);
                }
                _ => panic!("token {i} should be redacted"),
            }
        }

        assert!(verify_disclosure(&disclosure));
    }

    #[test]
    fn test_disclosure_range() {
        let verified = make_verified(sample_tokens());
        let disclosure = create_disclosure_range(&verified, 1..4).unwrap();

        assert_eq!(disclosure.proofs.len(), 3);

        // Tokens 1, 2, 3 revealed
        for i in 1..4 {
            assert!(matches!(&disclosure.tokens[i], DisclosedToken::Revealed { .. }));
        }
        // Others redacted
        for i in [0, 4, 5, 6, 7] {
            assert!(matches!(&disclosure.tokens[i], DisclosedToken::Redacted { .. }));
        }

        assert!(verify_disclosure(&disclosure));
    }

    #[test]
    fn test_different_audiences_same_proof() {
        let verified = make_verified(sample_tokens());

        // Pharmacist sees tokens 0..3
        let pharmacist = create_disclosure(&verified, &[0, 1, 2]).unwrap();
        // Insurer sees token 5 only
        let insurer = create_disclosure(&verified, &[5]).unwrap();

        // Both use the same execution proof
        assert!(verify_disclosure(&pharmacist));
        assert!(verify_disclosure(&insurer));

        // Same output root (same underlying tokens)
        assert_eq!(pharmacist.output_root, insurer.output_root);

        // Different number of proofs
        assert_eq!(pharmacist.proofs.len(), 3);
        assert_eq!(insurer.proofs.len(), 1);
    }

    #[test]
    fn test_full_reveal() {
        let verified = make_verified(sample_tokens());
        let indices: Vec<usize> = (0..8).collect();
        let disclosure = create_disclosure(&verified, &indices).unwrap();

        assert_eq!(disclosure.proofs.len(), 8);
        for token in &disclosure.tokens {
            assert!(matches!(token, DisclosedToken::Revealed { .. }));
        }

        assert!(verify_disclosure(&disclosure));
    }

    #[test]
    fn test_fully_private_empty_indices() {
        let verified = make_verified(sample_tokens());
        let disclosure = create_disclosure(&verified, &[]).unwrap();

        assert_eq!(disclosure.proofs.len(), 0);
        for token in &disclosure.tokens {
            assert!(matches!(token, DisclosedToken::Redacted { .. }));
        }

        assert!(verify_disclosure(&disclosure));
    }

    // ── Error tests ───────────────────────────────────────────────────

    #[test]
    fn test_out_of_bounds_index() {
        let verified = make_verified(sample_tokens());
        let result = create_disclosure(&verified, &[8]); // only 0..7 valid
        assert!(result.is_err());
    }

    #[test]
    fn test_out_of_bounds_range() {
        let verified = make_verified(sample_tokens());
        let result = create_disclosure_range(&verified, 6..10);
        assert!(result.is_err());
    }

    // ── Verification failure tests ────────────────────────────────────

    #[test]
    fn test_verify_wrong_token_fails() {
        let verified = make_verified(sample_tokens());
        let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

        // Tamper with the revealed token value
        disclosure.tokens[2] = DisclosedToken::Revealed {
            index: 2,
            token_id: 9999, // wrong!
        };

        assert!(!verify_disclosure(&disclosure));
    }

    #[test]
    fn test_verify_corrupted_merkle_proof_fails() {
        let verified = make_verified(sample_tokens());
        let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

        // Corrupt a sibling hash in the Merkle proof
        if !disclosure.proofs[0].siblings.is_empty() {
            disclosure.proofs[0].siblings[0].hash[0] ^= 0xFF;
        }

        assert!(!verify_disclosure(&disclosure));
    }

    #[test]
    fn test_verify_wrong_output_root_fails() {
        let verified = make_verified(sample_tokens());
        let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

        // Tamper with the output root
        disclosure.output_root = [0xFF; 32];

        assert!(!verify_disclosure(&disclosure));
    }

    #[test]
    fn test_verify_reordered_tokens_fails() {
        let verified = make_verified(sample_tokens());
        let mut disclosure = create_disclosure(&verified, &[]).unwrap();

        // Swap positions 0 and 1
        if disclosure.tokens.len() >= 2 {
            disclosure.tokens.swap(0, 1);
        }

        assert!(!verify_disclosure(&disclosure));
    }

    #[test]
    fn test_verify_missing_token_fails() {
        let verified = make_verified(sample_tokens());
        let mut disclosure = create_disclosure(&verified, &[]).unwrap();

        // Remove a token (create gap)
        disclosure.tokens.pop();

        assert!(!verify_disclosure(&disclosure));
    }

    #[test]
    fn test_verify_zero_leaf_hash_fails() {
        let verified = make_verified(sample_tokens());
        let mut disclosure = create_disclosure(&verified, &[]).unwrap();

        // Set a redacted leaf to zero hash
        disclosure.tokens[3] = DisclosedToken::Redacted {
            index: 3,
            leaf_hash: ZERO_HASH,
        };

        assert!(!verify_disclosure(&disclosure));
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn test_single_token() {
        let verified = make_verified(vec![42]);
        let disclosure = create_disclosure(&verified, &[0]).unwrap();

        assert_eq!(disclosure.total_tokens, 1);
        assert_eq!(disclosure.proofs.len(), 1);
        assert!(verify_disclosure(&disclosure));
    }

    #[test]
    fn test_single_token_redacted() {
        let verified = make_verified(vec![42]);
        let disclosure = create_disclosure(&verified, &[]).unwrap();

        assert_eq!(disclosure.total_tokens, 1);
        assert_eq!(disclosure.proofs.len(), 0);
        assert!(verify_disclosure(&disclosure));
    }

    #[test]
    fn test_duplicate_indices_handled() {
        let verified = make_verified(sample_tokens());
        // Duplicate index 2 — should still work (HashSet deduplicates)
        let disclosure = create_disclosure(&verified, &[2, 2, 5]).unwrap();

        assert_eq!(disclosure.proofs.len(), 2); // only 2 unique revealed
        assert!(verify_disclosure(&disclosure));
    }

    #[test]
    fn test_mock_proof_passes_verification() {
        let tokens = sample_tokens();
        let verified = Verified::__macro_new(tokens.clone(), mock_proof_for_tokens(&tokens));
        let disclosure = create_disclosure(&verified, &[0, 1]).unwrap();
        assert!(verify_disclosure(&disclosure));
    }
}
