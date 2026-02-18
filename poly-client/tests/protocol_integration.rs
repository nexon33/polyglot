//! Comprehensive thin client protocol integration tests.
//!
//! Tests cover: all 4 modes, empty responses, sequential inferences,
//! disclosure from all modes, error handling, serialization roundtrips,
//! and the full whitepaper §2.5 protocol flow.

use poly_client::encryption::{EncryptionBackend, MockCiphertext, MockEncryption};
use poly_client::protocol::{InferRequest, InferResponse, Mode};
use poly_client::PolyClient;
use poly_verified::disclosure::verify_disclosure;
use poly_verified::types::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_proof() -> VerifiedProof {
    VerifiedProof::Mock {
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
        privacy_mode: PrivacyMode::Transparent,
    }
}

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

fn hash_ivc_proof_with_mode(mode: PrivacyMode) -> VerifiedProof {
    VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 1,
        code_hash: [0x03; 32],
        privacy_mode: mode,
        blinding_commitment: if mode == PrivacyMode::Transparent {
            None
        } else {
            Some([0x04; 32])
        },
        checkpoints: vec![[0x04; 32]],
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
    }
}

fn mock_server_response(output_tokens: &[u32], proof: VerifiedProof) -> InferResponse {
    let ct = MockCiphertext {
        tokens: output_tokens.to_vec(),
    };
    InferResponse {
        encrypted_output: serde_json::to_vec(&ct).unwrap(),
        proof,
        model_id: "test-model".into(),
    }
}

// ---------------------------------------------------------------------------
// Full protocol flow for each mode
// ---------------------------------------------------------------------------

#[test]
fn protocol_flow_transparent_mode() {
    let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Transparent, MockEncryption);
    assert_eq!(client.mode(), Mode::Transparent);
    assert!(!client.mode().requires_encryption());

    let req = client.prepare_request(&[1, 2, 3], 50, 700, 42);
    assert_eq!(req.mode, Mode::Transparent);
    assert_eq!(req.model_id, "Qwen/Qwen3-0.6B");

    let output = vec![1, 2, 3, 10, 20, 30];
    let resp = mock_server_response(&output, hash_ivc_proof_with_mode(PrivacyMode::Transparent));
    let verified = client.process_response(&resp);

    assert_eq!(verified.token_ids, output);
    assert!(verified.is_verified());
}

#[test]
fn protocol_flow_private_proven_mode() {
    let client = PolyClient::new("model", Mode::PrivateProven, MockEncryption);
    let req = client.prepare_request(&[100, 200], 100, 700, 0);
    assert_eq!(req.mode, Mode::PrivateProven);

    let resp = mock_server_response(
        &[100, 200, 300],
        hash_ivc_proof_with_mode(PrivacyMode::PrivateInputs),
    );
    let verified = client.process_response(&resp);
    assert_eq!(verified.token_ids, vec![100, 200, 300]);
    assert!(verified.is_verified());
}

#[test]
fn protocol_flow_private_mode() {
    let client = PolyClient::new("model", Mode::Private, MockEncryption);
    let req = client.prepare_request(&[50], 200, 1000, 99);
    assert_eq!(req.mode, Mode::Private);

    let resp = mock_server_response(
        &[50, 51, 52, 53],
        hash_ivc_proof_with_mode(PrivacyMode::Private),
    );
    let verified = client.process_response(&resp);
    assert_eq!(verified.token_ids, vec![50, 51, 52, 53]);
    assert!(verified.is_verified());
}

#[test]
fn protocol_flow_encrypted_mode() {
    let client = PolyClient::new("model", Mode::Encrypted, MockEncryption);
    assert!(client.mode().requires_encryption());

    let req = client.prepare_request(&[1, 2, 3, 4, 5], 50, 700, 42);
    assert_eq!(req.mode, Mode::Encrypted);

    // In encrypted mode, the server works on ciphertext
    let resp = mock_server_response(
        &[1, 2, 3, 4, 5, 10, 20, 30],
        hash_ivc_proof_with_mode(PrivacyMode::Private),
    );
    let verified = client.process_response(&resp);
    assert_eq!(verified.token_ids.len(), 8);
    assert!(verified.is_verified());
}

// ---------------------------------------------------------------------------
// Selective disclosure from all modes
// ---------------------------------------------------------------------------

#[test]
fn disclosure_from_transparent_response() {
    let client = PolyClient::new("model", Mode::Transparent, MockEncryption);
    let output = vec![100, 200, 300, 400, 500];
    let resp = mock_server_response(&output, hash_ivc_proof());
    let verified = client.process_response(&resp);

    let disclosure = verified.disclose(&[1, 3]).unwrap();
    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 2);
    assert_eq!(disclosure.total_tokens, 5);
}

#[test]
fn disclosure_from_private_response() {
    let client = PolyClient::new("model", Mode::Private, MockEncryption);
    let output: Vec<u32> = (0..10).collect();
    let resp = mock_server_response(&output, hash_ivc_proof_with_mode(PrivacyMode::Private));
    let verified = client.process_response(&resp);

    // Pharmacist sees tokens 2..5
    let pharmacist = verified.disclose_range(2..5).unwrap();
    assert!(verify_disclosure(&pharmacist));
    assert_eq!(pharmacist.proofs.len(), 3);

    // Insurer sees token 8
    let insurer = verified.disclose(&[8]).unwrap();
    assert!(verify_disclosure(&insurer));
    assert_eq!(insurer.proofs.len(), 1);

    // Same output root
    assert_eq!(pharmacist.output_root, insurer.output_root);
}

#[test]
fn disclosure_from_encrypted_response() {
    let client = PolyClient::new("model", Mode::Encrypted, MockEncryption);
    let output: Vec<u32> = (0..20).collect();
    let resp = mock_server_response(&output, hash_ivc_proof());
    let verified = client.process_response(&resp);

    let full = verified.disclose(&(0..20).collect::<Vec<_>>()).unwrap();
    let empty = verified.disclose(&[]).unwrap();
    let partial = verified.disclose(&[5, 10, 15]).unwrap();

    assert!(verify_disclosure(&full));
    assert!(verify_disclosure(&empty));
    assert!(verify_disclosure(&partial));

    assert_eq!(full.output_root, empty.output_root);
    assert_eq!(full.output_root, partial.output_root);
}

// ---------------------------------------------------------------------------
// Empty and edge-case responses
// ---------------------------------------------------------------------------

#[test]
fn process_empty_response() {
    let client = PolyClient::new("model", Mode::Transparent, MockEncryption);
    let resp = mock_server_response(&[], hash_ivc_proof());
    let verified = client.process_response(&resp);

    assert_eq!(verified.token_ids.len(), 0);
    assert!(verified.is_verified());
}

#[test]
fn disclosure_from_empty_response() {
    let client = PolyClient::new("model", Mode::Transparent, MockEncryption);
    let resp = mock_server_response(&[], hash_ivc_proof());
    let verified = client.process_response(&resp);

    // Empty disclosure from empty output
    let disclosure = verified.disclose(&[]).unwrap();
    assert_eq!(disclosure.total_tokens, 0);
    assert_eq!(disclosure.proofs.len(), 0);
    assert!(verify_disclosure(&disclosure));
}

#[test]
fn disclosure_from_empty_response_out_of_bounds() {
    let client = PolyClient::new("model", Mode::Transparent, MockEncryption);
    let resp = mock_server_response(&[], hash_ivc_proof());
    let verified = client.process_response(&resp);

    // Any index is out of bounds on an empty output
    assert!(verified.disclose(&[0]).is_err());
}

#[test]
fn single_token_response() {
    let client = PolyClient::new("model", Mode::Encrypted, MockEncryption);
    let resp = mock_server_response(&[42], hash_ivc_proof());
    let verified = client.process_response(&resp);

    assert_eq!(verified.token_ids, vec![42]);

    let revealed = verified.disclose(&[0]).unwrap();
    let redacted = verified.disclose(&[]).unwrap();

    assert!(verify_disclosure(&revealed));
    assert!(verify_disclosure(&redacted));
    assert_eq!(revealed.output_root, redacted.output_root);
}

// ---------------------------------------------------------------------------
// Sequential inferences (multiple request/response cycles)
// ---------------------------------------------------------------------------

#[test]
fn sequential_inferences_independent() {
    let client = PolyClient::new("model", Mode::Transparent, MockEncryption);

    // First inference
    let req1 = client.prepare_request(&[1, 2, 3], 50, 700, 42);
    let resp1 = mock_server_response(&[10, 20, 30], hash_ivc_proof());
    let v1 = client.process_response(&resp1);

    // Second inference (different prompt)
    let req2 = client.prepare_request(&[4, 5, 6], 50, 700, 43);
    let resp2 = mock_server_response(&[40, 50, 60], hash_ivc_proof());
    let v2 = client.process_response(&resp2);

    // Both valid independently
    assert!(v1.is_verified());
    assert!(v2.is_verified());

    // Different token outputs
    assert_ne!(v1.token_ids, v2.token_ids);

    // Disclosures from both work
    let d1 = v1.disclose(&[0]).unwrap();
    let d2 = v2.disclose(&[0]).unwrap();
    assert!(verify_disclosure(&d1));
    assert!(verify_disclosure(&d2));

    // Different outputs → different Merkle roots
    assert_ne!(d1.output_root, d2.output_root);

    // Requests are independent
    assert_ne!(req1.encrypted_input, req2.encrypted_input);
    assert_ne!(req1.seed, req2.seed);
}

// ---------------------------------------------------------------------------
// Request serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn infer_request_roundtrip_all_modes() {
    for mode in [
        Mode::Transparent,
        Mode::PrivateProven,
        Mode::Private,
        Mode::Encrypted,
    ] {
        let client = PolyClient::new("test-model", mode, MockEncryption);
        let req = client.prepare_request(&[1, 2, 3], 100, 700, 42);

        let json = serde_json::to_string(&req).unwrap();
        let req2: InferRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(req.model_id, req2.model_id);
        assert_eq!(req.mode, req2.mode);
        assert_eq!(req.max_tokens, req2.max_tokens);
        assert_eq!(req.temperature, req2.temperature);
        assert_eq!(req.seed, req2.seed);
        assert_eq!(req.encrypted_input, req2.encrypted_input);
    }
}

#[test]
fn infer_response_roundtrip() {
    let resp = mock_server_response(&[100, 200, 300], hash_ivc_proof());
    let json = serde_json::to_string(&resp).unwrap();
    let resp2: InferResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(resp.model_id, resp2.model_id);
    assert_eq!(resp.encrypted_output, resp2.encrypted_output);
}

// ---------------------------------------------------------------------------
// Encryption backend tests
// ---------------------------------------------------------------------------

#[test]
fn mock_encryption_large_input() {
    let backend = MockEncryption;
    let (pk, sk) = backend.keygen();

    let large_input: Vec<u32> = (0..10_000).collect();
    let ct = backend.encrypt(&large_input, &pk, &sk);
    let decrypted = backend.decrypt(&ct, &sk);

    assert_eq!(large_input, decrypted);
}

#[test]
fn mock_encryption_keys_are_deterministic() {
    let backend = MockEncryption;
    let (pk1, sk1) = backend.keygen();
    let (pk2, sk2) = backend.keygen();
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
}

#[test]
fn mock_encryption_ciphertext_is_json_stable() {
    let backend = MockEncryption;
    let (pk, sk) = backend.keygen();

    let ct1 = backend.encrypt(&[1, 2, 3], &pk, &sk);
    let ct2 = backend.encrypt(&[1, 2, 3], &pk, &sk);

    let json1 = serde_json::to_string(&ct1).unwrap();
    let json2 = serde_json::to_string(&ct2).unwrap();
    assert_eq!(json1, json2);
}

// ---------------------------------------------------------------------------
// Mode conversion tests
// ---------------------------------------------------------------------------

#[test]
fn mode_privacy_mapping_consistent() {
    assert_eq!(
        Mode::Transparent.to_privacy_mode(),
        PrivacyMode::Transparent
    );
    assert_eq!(
        Mode::PrivateProven.to_privacy_mode(),
        PrivacyMode::PrivateInputs
    );
    assert_eq!(Mode::Private.to_privacy_mode(), PrivacyMode::Private);
    assert_eq!(Mode::Encrypted.to_privacy_mode(), PrivacyMode::Private);
}

#[test]
fn only_encrypted_mode_requires_encryption() {
    assert!(!Mode::Transparent.requires_encryption());
    assert!(!Mode::PrivateProven.requires_encryption());
    assert!(!Mode::Private.requires_encryption());
    assert!(Mode::Encrypted.requires_encryption());
}

// ---------------------------------------------------------------------------
// Proof type handling
// ---------------------------------------------------------------------------

#[test]
fn process_response_with_mock_proof() {
    let client = PolyClient::new("model", Mode::Transparent, MockEncryption);
    let resp = mock_server_response(&[10, 20, 30], mock_proof());
    let verified = client.process_response(&resp);

    assert!(verified.is_verified());
    assert_eq!(verified.token_ids, vec![10, 20, 30]);
}

#[test]
fn process_response_with_hash_ivc_proof() {
    let client = PolyClient::new("model", Mode::Private, MockEncryption);
    let resp = mock_server_response(&[10, 20, 30], hash_ivc_proof());
    let verified = client.process_response(&resp);

    assert!(verified.is_verified());
    match verified.proof() {
        VerifiedProof::HashIvc { step_count, .. } => assert_eq!(*step_count, 1),
        _ => panic!("expected HashIvc"),
    }
}

// ---------------------------------------------------------------------------
// Large response handling
// ---------------------------------------------------------------------------

#[test]
fn large_response_with_selective_disclosure() {
    let client = PolyClient::new("model", Mode::Encrypted, MockEncryption);
    let large_output: Vec<u32> = (0..2000).collect();
    let resp = mock_server_response(&large_output, hash_ivc_proof());
    let verified = client.process_response(&resp);

    assert_eq!(verified.token_ids.len(), 2000);

    // Disclose just 5 tokens from a 2000-token output
    let disclosure = verified.disclose(&[0, 500, 1000, 1500, 1999]).unwrap();
    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 5);
    assert_eq!(disclosure.total_tokens, 2000);
}
