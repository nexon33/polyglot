//! End-to-end integration test for the verified execution pipeline.
//!
//! Tests that #[verified] functions compile, execute, and produce valid proofs.

use poly_verified::ivc::IvcBackend;
use poly_verified::types::{PrivacyMode, VerifiedProof};
use polyglot_macros::verified;

// ─── Basic: verified function with HashIvc (default) ────────────────────────

#[verified]
fn add_scores(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

#[test]
fn test_verified_add_scores() {
    let result = add_scores(42, 58);

    // Value is correct
    assert_eq!(*result.value(), 100);

    // Proof exists and is structurally valid
    assert!(result.is_verified());

    // Backend is HashIvc
    match result.proof() {
        VerifiedProof::HashIvc {
            step_count,
            code_hash,
            privacy_mode,
            blinding_commitment,
            ..
        } => {
            assert_eq!(*step_count, 1);
            assert_ne!(*code_hash, [0u8; 32]); // code hash is non-zero
            assert_eq!(*privacy_mode, PrivacyMode::Transparent);
            assert!(blinding_commitment.is_none()); // no blinding in transparent mode
        }
        _ => panic!("expected HashIvc proof"),
    }
}

// ─── Mock backend ───────────────────────────────────────────────────────────

#[verified(mock)]
fn add_mock(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

#[test]
fn test_verified_mock_backend() {
    let result = add_mock(10, 20);
    assert_eq!(*result.value(), 30);
    assert!(result.is_verified());

    match result.proof() {
        VerifiedProof::Mock { privacy_mode, .. } => {
            assert_eq!(*privacy_mode, PrivacyMode::Transparent);
        }
        _ => panic!("expected Mock proof"),
    }
}

// ─── Determinism: same inputs → same proof ──────────────────────────────────

#[test]
fn test_verified_determinism() {
    let r1 = add_scores(42, 58);
    let r2 = add_scores(42, 58);

    assert_eq!(*r1.value(), *r2.value());

    match (r1.proof(), r2.proof()) {
        (
            VerifiedProof::HashIvc {
                chain_tip: tip1,
                merkle_root: root1,
                ..
            },
            VerifiedProof::HashIvc {
                chain_tip: tip2,
                merkle_root: root2,
                ..
            },
        ) => {
            assert_eq!(tip1, tip2, "same inputs must produce same chain tip");
            assert_eq!(root1, root2, "same inputs must produce same merkle root");
        }
        _ => panic!("expected HashIvc proofs"),
    }
}

// ─── Different inputs → different proofs ────────────────────────────────────

#[test]
fn test_different_inputs_different_proofs() {
    let r1 = add_scores(42, 58);
    let r2 = add_scores(1, 2);

    assert_ne!(*r1.value(), *r2.value());

    match (r1.proof(), r2.proof()) {
        (
            VerifiedProof::HashIvc {
                chain_tip: tip1, ..
            },
            VerifiedProof::HashIvc {
                chain_tip: tip2, ..
            },
        ) => {
            assert_ne!(tip1, tip2, "different inputs must produce different proofs");
        }
        _ => panic!("expected HashIvc proofs"),
    }
}

// ─── Privacy: private mode ──────────────────────────────────────────────────

#[verified(private)]
fn secret_add(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

#[test]
fn test_verified_private_mode() {
    let result = secret_add(100, 200);
    assert_eq!(*result.value(), 300);
    assert!(result.is_private());

    match result.proof() {
        VerifiedProof::HashIvc {
            privacy_mode,
            blinding_commitment,
            ..
        } => {
            assert_eq!(*privacy_mode, PrivacyMode::Private);
            assert!(blinding_commitment.is_some(), "private mode must have blinding");
            assert_ne!(blinding_commitment.unwrap(), [0u8; 32]);
        }
        _ => panic!("expected HashIvc proof"),
    }

    // Private mode: code_hash() returns zero (hidden)
    assert_eq!(result.proof().code_hash(), [0u8; 32]);
}

// ─── Privacy: private_inputs mode ───────────────────────────────────────────

#[verified(private_inputs)]
fn hidden_inputs_add(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

#[test]
fn test_verified_private_inputs_mode() {
    let result = hidden_inputs_add(10, 20);
    assert_eq!(*result.value(), 30);
    assert!(result.is_private());

    match result.proof() {
        VerifiedProof::HashIvc {
            privacy_mode,
            blinding_commitment,
            code_hash,
            ..
        } => {
            assert_eq!(*privacy_mode, PrivacyMode::PrivateInputs);
            assert!(blinding_commitment.is_some());
            // Private inputs still reveals code hash
            assert_ne!(*code_hash, [0u8; 32]);
        }
        _ => panic!("expected HashIvc proof"),
    }

    // Code hash is visible in private_inputs mode
    assert_ne!(result.proof().code_hash(), [0u8; 32]);
}

// ─── Verify proof via backend ───────────────────────────────────────────────

#[test]
fn test_verify_proof_via_backend() {
    let result = add_scores(42, 58);
    let backend = poly_verified::ivc::hash_ivc::HashIvc;

    // Extract the proof's committed I/O hashes for verification
    let (input_hash, output_hash) = match result.proof() {
        VerifiedProof::HashIvc { input_hash, output_hash, .. } => (*input_hash, *output_hash),
        _ => panic!("expected HashIvc proof"),
    };

    let ok = backend
        .verify(result.proof(), &input_hash, &output_hash)
        .expect("verification should not error");
    assert!(ok, "proof should verify");
}

// ─── Proof serialization roundtrip ──────────────────────────────────────────

#[test]
fn test_proof_serialization_roundtrip() {
    use poly_verified::proof_serialize::VerifiedResponse;
    use poly_verified::types::ZERO_HASH;

    let result = add_scores(42, 58);
    let value_bytes = result.value().to_le_bytes().to_vec();

    let response = VerifiedResponse::new(result.proof(), ZERO_HASH, value_bytes.clone(), ZERO_HASH);

    let wire = response.to_bytes();
    let decoded = VerifiedResponse::from_bytes(&wire).expect("deserialization failed");

    assert_eq!(decoded.value_bytes, value_bytes);
    assert!(decoded.verify_value_integrity());
}

// ─── Map preserves proof ────────────────────────────────────────────────────

#[test]
fn test_map_preserves_proof() {
    let result = add_scores(42, 58);
    let original_proof_tip = match result.proof() {
        VerifiedProof::HashIvc { chain_tip, .. } => *chain_tip,
        _ => panic!("expected HashIvc"),
    };

    let doubled = result.map(|v| v * 2);
    assert_eq!(*doubled.value(), 200);

    match doubled.proof() {
        VerifiedProof::HashIvc { chain_tip, .. } => {
            assert_eq!(*chain_tip, original_proof_tip, "map must preserve proof");
        }
        _ => panic!("expected HashIvc"),
    }
}

// ─── Zero-argument function ─────────────────────────────────────────────────

#[verified]
fn constant_value() -> u64 {
    42
}

#[test]
fn test_verified_no_args() {
    let result = constant_value();
    assert_eq!(*result.value(), 42);
    assert!(result.is_verified());
}
