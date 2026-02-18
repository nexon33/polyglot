//! Comprehensive selective disclosure integration tests.
//!
//! Tests cover: edge cases, large token arrays, adversarial tampering,
//! serialization roundtrips, proof count mismatches, boundary values,
//! and cross-privacy-mode scenarios.

use poly_verified::disclosure::*;
use poly_verified::types::*;
use poly_verified::verified_type::Verified;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash_ivc_proof() -> VerifiedProof {
    VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 1,
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::Transparent,
        blinding_commitment: None,
        checkpoints: vec![[0x04; 32]],
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
    }
}

fn make_verified(tokens: Vec<u32>) -> Verified<Vec<u32>> {
    Verified::__macro_new(tokens, hash_ivc_proof())
}

fn make_verified_with(tokens: Vec<u32>, proof: VerifiedProof) -> Verified<Vec<u32>> {
    Verified::__macro_new(tokens, proof)
}

// ---------------------------------------------------------------------------
// Large token sequences
// ---------------------------------------------------------------------------

#[test]
fn disclosure_100_tokens() {
    let tokens: Vec<u32> = (0..100).collect();
    let verified = make_verified(tokens);

    // Reveal every 10th token
    let indices: Vec<usize> = (0..100).step_by(10).collect();
    let disclosure = create_disclosure(&verified, &indices).unwrap();

    assert_eq!(disclosure.total_tokens, 100);
    assert_eq!(disclosure.proofs.len(), 10);
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_1000_tokens() {
    let tokens: Vec<u32> = (0..1000).collect();
    let verified = make_verified(tokens);

    // Reveal first 10 tokens
    let indices: Vec<usize> = (0..10).collect();
    let disclosure = create_disclosure(&verified, &indices).unwrap();

    assert_eq!(disclosure.total_tokens, 1000);
    assert_eq!(disclosure.proofs.len(), 10);
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_1000_tokens_full_reveal() {
    let tokens: Vec<u32> = (0..1000).collect();
    let verified = make_verified(tokens);

    let indices: Vec<usize> = (0..1000).collect();
    let disclosure = create_disclosure(&verified, &indices).unwrap();

    assert_eq!(disclosure.proofs.len(), 1000);
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_1000_tokens_fully_private() {
    let tokens: Vec<u32> = (0..1000).collect();
    let verified = make_verified(tokens);

    let disclosure = create_disclosure(&verified, &[]).unwrap();

    assert_eq!(disclosure.proofs.len(), 0);
    assert_eq!(disclosure.total_tokens, 1000);
    assert!(verify_disclosure(&disclosure));
}

// ---------------------------------------------------------------------------
// Boundary values
// ---------------------------------------------------------------------------

#[test]
fn disclosure_two_tokens_reveal_first() {
    let verified = make_verified(vec![100, 200]);
    let disclosure = create_disclosure(&verified, &[0]).unwrap();

    assert_eq!(disclosure.total_tokens, 2);
    assert_eq!(disclosure.proofs.len(), 1);
    assert!(matches!(
        &disclosure.tokens[0],
        DisclosedToken::Revealed {
            index: 0,
            token_id: 100
        }
    ));
    assert!(matches!(
        &disclosure.tokens[1],
        DisclosedToken::Redacted { index: 1, .. }
    ));
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_two_tokens_reveal_last() {
    let verified = make_verified(vec![100, 200]);
    let disclosure = create_disclosure(&verified, &[1]).unwrap();

    assert!(matches!(
        &disclosure.tokens[0],
        DisclosedToken::Redacted { index: 0, .. }
    ));
    assert!(matches!(
        &disclosure.tokens[1],
        DisclosedToken::Revealed {
            index: 1,
            token_id: 200
        }
    ));
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_token_id_zero() {
    let verified = make_verified(vec![0, 0, 0]);
    let disclosure = create_disclosure(&verified, &[0, 1, 2]).unwrap();

    assert!(verify_disclosure(&disclosure));
    // All tokens should be token_id 0 but still valid
    for token in &disclosure.tokens {
        match token {
            DisclosedToken::Revealed { token_id, .. } => assert_eq!(*token_id, 0),
            _ => panic!("expected revealed"),
        }
    }
}

#[test]
fn disclosure_token_id_max() {
    let verified = make_verified(vec![u32::MAX, u32::MAX - 1, 0]);
    let disclosure = create_disclosure(&verified, &[0, 1]).unwrap();

    assert!(verify_disclosure(&disclosure));

    match &disclosure.tokens[0] {
        DisclosedToken::Revealed { token_id, .. } => assert_eq!(*token_id, u32::MAX),
        _ => panic!("expected revealed"),
    }
}

#[test]
fn disclosure_empty_range() {
    let verified = make_verified(vec![100, 200, 300]);
    let disclosure = create_disclosure_range(&verified, 1..1).unwrap();

    // Empty range = no tokens revealed
    assert_eq!(disclosure.proofs.len(), 0);
    for token in &disclosure.tokens {
        assert!(matches!(token, DisclosedToken::Redacted { .. }));
    }
    assert!(verify_disclosure(&disclosure));
}

// ---------------------------------------------------------------------------
// Adversarial tampering
// ---------------------------------------------------------------------------

#[test]
fn tamper_add_extra_proof_fails() {
    let verified = make_verified(vec![100, 200, 300, 400]);
    let mut disclosure = create_disclosure(&verified, &[1]).unwrap();

    // Add a duplicate proof — should cause mismatch
    let extra = disclosure.proofs[0].clone();
    disclosure.proofs.push(extra);

    assert!(!verify_disclosure(&disclosure));
}

#[test]
fn tamper_remove_proof_fails() {
    let verified = make_verified(vec![100, 200, 300, 400]);
    let mut disclosure = create_disclosure(&verified, &[1, 2]).unwrap();
    assert_eq!(disclosure.proofs.len(), 2);

    // Remove one proof — should cause mismatch
    disclosure.proofs.pop();

    assert!(!verify_disclosure(&disclosure));
}

#[test]
fn tamper_insert_extra_token_fails() {
    let verified = make_verified(vec![100, 200, 300]);
    let mut disclosure = create_disclosure(&verified, &[]).unwrap();

    // Insert an extra redacted token
    disclosure.tokens.push(DisclosedToken::Redacted {
        index: 3,
        leaf_hash: [0xFF; 32],
    });

    // total_tokens mismatch
    assert!(!verify_disclosure(&disclosure));
}

#[test]
fn tamper_change_total_tokens_fails() {
    let verified = make_verified(vec![100, 200, 300]);
    let mut disclosure = create_disclosure(&verified, &[0]).unwrap();

    // Lie about total tokens
    disclosure.total_tokens = 5;

    assert!(!verify_disclosure(&disclosure));
}

#[test]
fn tamper_swap_revealed_and_redacted_fails() {
    let verified = make_verified(vec![100, 200, 300, 400]);
    let mut disclosure = create_disclosure(&verified, &[1]).unwrap();

    // Turn revealed token into redacted
    disclosure.tokens[1] = DisclosedToken::Redacted {
        index: 1,
        leaf_hash: [0xAB; 32],
    };

    // Now there's a proof for a position that's not revealed → mismatch
    assert!(!verify_disclosure(&disclosure));
}

#[test]
fn tamper_change_redacted_leaf_hash() {
    let verified = make_verified(vec![100, 200, 300, 400]);
    let mut disclosure = create_disclosure(&verified, &[0]).unwrap();

    // Change a redacted leaf hash to a different value
    // This is accepted by verify_disclosure since we don't verify
    // redacted leaves against the Merkle tree (by design — the verifier
    // only needs to know a token exists, not verify its commitment).
    // But ZERO_HASH would fail.
    if let DisclosedToken::Redacted { index, .. } = &disclosure.tokens[1] {
        disclosure.tokens[1] = DisclosedToken::Redacted {
            index: *index,
            leaf_hash: [0xFF; 32], // different but non-zero
        };
    }

    // This should still pass because redacted hashes aren't verified against tree
    // (the verifier only checks they aren't ZERO_HASH)
    // The output_root still binds the original tree, but we only verify revealed tokens.
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn tamper_proof_sibling_to_zero_fails() {
    let verified = make_verified(vec![100, 200, 300, 400]);
    let mut disclosure = create_disclosure(&verified, &[0]).unwrap();

    // Zero out all siblings in the proof
    for sibling in &mut disclosure.proofs[0].siblings {
        sibling.hash = ZERO_HASH;
    }

    assert!(!verify_disclosure(&disclosure));
}

// ---------------------------------------------------------------------------
// Serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn disclosure_serialization_roundtrip() {
    let verified = make_verified(vec![100, 200, 300, 400, 500]);
    let disclosure = create_disclosure(&verified, &[1, 3]).unwrap();

    let json = serde_json::to_string(&disclosure).unwrap();
    let deserialized: Disclosure = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.total_tokens, disclosure.total_tokens);
    assert_eq!(deserialized.output_root, disclosure.output_root);
    assert_eq!(deserialized.proofs.len(), disclosure.proofs.len());
    assert_eq!(deserialized.tokens.len(), disclosure.tokens.len());

    assert!(verify_disclosure(&deserialized));
}

#[test]
fn disclosed_token_serialization_roundtrip() {
    let revealed = DisclosedToken::Revealed {
        index: 5,
        token_id: 42,
    };
    let redacted = DisclosedToken::Redacted {
        index: 3,
        leaf_hash: [0xAB; 32],
    };

    let json_r = serde_json::to_string(&revealed).unwrap();
    let json_d = serde_json::to_string(&redacted).unwrap();

    let r2: DisclosedToken = serde_json::from_str(&json_r).unwrap();
    let d2: DisclosedToken = serde_json::from_str(&json_d).unwrap();

    assert_eq!(r2.index(), 5);
    assert_eq!(d2.index(), 3);
}

// ---------------------------------------------------------------------------
// Cross-privacy-mode scenarios
// ---------------------------------------------------------------------------

#[test]
fn disclosure_with_transparent_proof() {
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 3,
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::Transparent,
        blinding_commitment: None,
        checkpoints: vec![[0x04; 32]],
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
    };
    let verified = make_verified_with(vec![10, 20, 30], proof);
    let disclosure = create_disclosure(&verified, &[0, 2]).unwrap();
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_with_private_inputs_proof() {
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 5,
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::PrivateInputs,
        blinding_commitment: Some([0x04; 32]),
        checkpoints: vec![[0x04; 32]],
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
    };
    let verified = make_verified_with(vec![10, 20, 30], proof);
    let disclosure = create_disclosure(&verified, &[1]).unwrap();
    assert!(verify_disclosure(&disclosure));

    // The execution proof should be preserved
    match &disclosure.execution_proof {
        VerifiedProof::HashIvc { privacy_mode, .. } => {
            assert_eq!(*privacy_mode, PrivacyMode::PrivateInputs);
        }
        _ => panic!("expected HashIvc"),
    }
}

#[test]
fn disclosure_with_private_proof() {
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 10,
        code_hash: ZERO_HASH, // private mode hides code
        privacy_mode: PrivacyMode::Private,
        blinding_commitment: Some([0x04; 32]),
        checkpoints: vec![[0x04; 32]],
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
    };
    let verified = make_verified_with(vec![42, 43, 44, 45], proof);
    let disclosure = create_disclosure(&verified, &[0, 3]).unwrap();
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_with_zero_step_count_fails_verification() {
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 0, // invalid: no computation steps
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::Transparent,
        blinding_commitment: None,
        checkpoints: vec![],
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
    };
    let verified = make_verified_with(vec![10, 20], proof);
    let disclosure = create_disclosure(&verified, &[0]).unwrap();

    // Creation succeeds, but verification should fail (step_count must be > 0)
    assert!(!verify_disclosure(&disclosure));
}

// ---------------------------------------------------------------------------
// Multiple audiences from same proof
// ---------------------------------------------------------------------------

#[test]
fn three_audiences_from_same_proof() {
    let tokens: Vec<u32> = (0..20).map(|i| i * 100).collect();
    let verified = make_verified(tokens);

    // Doctor: full output
    let doctor = create_disclosure(&verified, &(0..20).collect::<Vec<_>>()).unwrap();
    // Pharmacist: tokens 5..10
    let pharmacist = create_disclosure_range(&verified, 5..10).unwrap();
    // Insurer: token 15 only (risk score)
    let insurer = create_disclosure(&verified, &[15]).unwrap();

    assert!(verify_disclosure(&doctor));
    assert!(verify_disclosure(&pharmacist));
    assert!(verify_disclosure(&insurer));

    // Same Merkle root
    assert_eq!(doctor.output_root, pharmacist.output_root);
    assert_eq!(pharmacist.output_root, insurer.output_root);

    // Different proof counts
    assert_eq!(doctor.proofs.len(), 20);
    assert_eq!(pharmacist.proofs.len(), 5);
    assert_eq!(insurer.proofs.len(), 1);
}

// ---------------------------------------------------------------------------
// Consecutive operations on same Verified
// ---------------------------------------------------------------------------

#[test]
fn multiple_disclosures_from_same_verified() {
    let verified = make_verified(vec![10, 20, 30, 40, 50]);

    // Create many different views — all should be valid
    for i in 0..5 {
        let disclosure = create_disclosure(&verified, &[i]).unwrap();
        assert!(verify_disclosure(&disclosure));
    }

    // Full and empty
    let full = create_disclosure(&verified, &[0, 1, 2, 3, 4]).unwrap();
    let empty = create_disclosure(&verified, &[]).unwrap();
    assert!(verify_disclosure(&full));
    assert!(verify_disclosure(&empty));
    assert_eq!(full.output_root, empty.output_root);
}

// ---------------------------------------------------------------------------
// Verified<Vec<u32>>::disclose() and disclose_range() methods
// ---------------------------------------------------------------------------

#[test]
fn verified_disclose_method() {
    let verified = make_verified(vec![10, 20, 30, 40]);
    let disclosure = verified.disclose(&[0, 2]).unwrap();
    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 2);
}

#[test]
fn verified_disclose_range_method() {
    let verified = make_verified(vec![10, 20, 30, 40]);
    let disclosure = verified.disclose_range(1..3).unwrap();
    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 2);
}

#[test]
fn verified_disclose_out_of_bounds() {
    let verified = make_verified(vec![10, 20, 30]);
    let result = verified.disclose(&[5]);
    assert!(result.is_err());
}

#[test]
fn verified_disclose_range_out_of_bounds() {
    let verified = make_verified(vec![10, 20, 30]);
    let result = verified.disclose_range(0..5);
    assert!(result.is_err());
}
