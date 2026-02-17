//! CKKS encryption backend integration tests.
//!
//! Tests the full protocol flow through PolyClient<CkksEncryption>:
//! encrypt → serialize → deserialize → decrypt → verify → disclose.

#![cfg(feature = "ckks")]

use poly_client::ckks::ciphertext::{decrypt, encrypt};
use poly_client::ckks::keys::keygen;
use poly_client::ckks::{CkksCiphertext, CkksEncryption, CkksPublicKey, CkksSecretKey};
use poly_client::encryption::EncryptionBackend;
use poly_client::protocol::{InferRequest, InferResponse, Mode};
use poly_client::PolyClient;
use poly_verified::disclosure::verify_disclosure;
use poly_verified::types::{PrivacyMode, VerifiedProof};
use rand::rngs::StdRng;
use rand::SeedableRng;

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
    }
}

/// Create a server response using the client's own public key for proper roundtrip.
fn server_response_with_key(
    output_tokens: &[u32],
    pk: &CkksPublicKey,
    proof: VerifiedProof,
) -> InferResponse {
    let mut rng = StdRng::seed_from_u64(77);
    let ct = encrypt(output_tokens, pk, &mut rng);
    InferResponse {
        encrypted_output: serde_json::to_vec(&ct).unwrap(),
        proof,
        model_id: "test-model".into(),
    }
}

// ---------------------------------------------------------------------------
// EncryptionBackend trait conformance
// ---------------------------------------------------------------------------

#[test]
fn ckks_backend_keygen() {
    let backend = CkksEncryption;
    let (pk, sk) = backend.keygen();
    assert_eq!(pk.a.coeffs.len(), 4096);
    assert_eq!(pk.b.coeffs.len(), 4096);
    assert_eq!(sk.s.coeffs.len(), 4096);
}

#[test]
fn ckks_backend_roundtrip() {
    let backend = CkksEncryption;
    let (pk, sk) = backend.keygen();
    let tokens = vec![100, 200, 300, 400, 500];
    let ct = backend.encrypt(&tokens, &pk);
    let decrypted = backend.decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

#[test]
fn ckks_backend_roundtrip_empty() {
    let backend = CkksEncryption;
    let (pk, sk) = backend.keygen();
    let tokens: Vec<u32> = vec![];
    let ct = backend.encrypt(&tokens, &pk);
    let decrypted = backend.decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

#[test]
fn ckks_backend_roundtrip_large_values() {
    let backend = CkksEncryption;
    let (pk, sk) = backend.keygen();
    let tokens = vec![u32::MAX, u32::MAX - 1, 0, 1, 42];
    let ct = backend.encrypt(&tokens, &pk);
    let decrypted = backend.decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

// ---------------------------------------------------------------------------
// Full protocol flow with CKKS
// ---------------------------------------------------------------------------

#[test]
fn protocol_flow_ckks_encrypted_mode() {
    let backend = CkksEncryption;
    let (pk, _sk) = backend.keygen();

    // Client prepares request
    let input_tokens = vec![1, 2, 3, 4, 5];
    let ct = backend.encrypt(&input_tokens, &pk);
    let encrypted_input = serde_json::to_vec(&ct).unwrap();

    let req = InferRequest {
        model_id: "test-model".into(),
        mode: Mode::Encrypted,
        encrypted_input,
        max_tokens: 50,
        temperature: 700,
        seed: 42,
    };

    // Verify request is serializable
    let json = serde_json::to_string(&req).unwrap();
    let req2: InferRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req.model_id, req2.model_id);
    assert_eq!(req.mode, req2.mode);
}

#[test]
fn full_protocol_ckks_with_polyclient() {
    // Use PolyClient<CkksEncryption> end-to-end
    let client = PolyClient::new("test-model", Mode::Encrypted, CkksEncryption);
    assert_eq!(client.mode(), Mode::Encrypted);

    let req = client.prepare_request(&[10, 20, 30], 50, 700, 42);
    assert_eq!(req.mode, Mode::Encrypted);

    // The encrypted_input should be a valid CkksCiphertext
    let ct: CkksCiphertext = serde_json::from_slice(&req.encrypted_input).unwrap();
    assert_eq!(ct.token_count, 3);
}

// ---------------------------------------------------------------------------
// Selective disclosure from CKKS-encrypted response
// ---------------------------------------------------------------------------

#[test]
fn disclosure_from_ckks_response() {
    // Simulate: server encrypts output with client's key, client decrypts + discloses
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let output = vec![100, 200, 300, 400, 500];
    let resp = server_response_with_key(&output, &pk, hash_ivc_proof());

    // Client decrypts
    let ct: CkksCiphertext = serde_json::from_slice(&resp.encrypted_output).unwrap();
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, output);

    // Build VerifiedResponse manually for disclosure
    let verified =
        poly_verified::verified_type::Verified::__macro_new(decrypted, resp.proof.clone());

    // Disclose tokens 1 and 3
    let disclosure = verified.disclose(&[1, 3]).unwrap();
    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 2);
    assert_eq!(disclosure.total_tokens, 5);
}

#[test]
fn disclosure_range_from_ckks_response() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let output: Vec<u32> = (0..20).collect();
    let resp = server_response_with_key(&output, &pk, hash_ivc_proof());

    let ct: CkksCiphertext = serde_json::from_slice(&resp.encrypted_output).unwrap();
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, output);

    let verified = poly_verified::verified_type::Verified::__macro_new(decrypted, resp.proof);

    // Pharmacist: tokens 5..10
    let pharmacist = verified.disclose_range(5..10).unwrap();
    assert!(verify_disclosure(&pharmacist));
    assert_eq!(pharmacist.proofs.len(), 5);

    // Insurer: token 15 only
    let insurer = verified.disclose(&[15]).unwrap();
    assert!(verify_disclosure(&insurer));

    // Same Merkle root
    assert_eq!(pharmacist.output_root, insurer.output_root);
}

// ---------------------------------------------------------------------------
// Serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn ciphertext_json_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![10, 20, 30, 40, 50];
    let ct = encrypt(&tokens, &pk, &mut rng);

    let json = serde_json::to_string(&ct).unwrap();
    let ct2: CkksCiphertext = serde_json::from_str(&json).unwrap();

    let decrypted = decrypt(&ct2, &sk);
    assert_eq!(decrypted, tokens);
}

#[test]
fn public_key_serialization_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, _sk) = keygen(&mut rng);

    let json = serde_json::to_string(&pk).unwrap();
    let pk2: CkksPublicKey = serde_json::from_str(&json).unwrap();

    assert_eq!(pk.a.coeffs, pk2.a.coeffs);
    assert_eq!(pk.b.coeffs, pk2.b.coeffs);
}

#[test]
fn secret_key_serialization_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    let (_pk, sk) = keygen(&mut rng);

    let json = serde_json::to_string(&sk).unwrap();
    let sk2: CkksSecretKey = serde_json::from_str(&json).unwrap();

    assert_eq!(sk.s.coeffs, sk2.s.coeffs);
}

// ---------------------------------------------------------------------------
// Security properties
// ---------------------------------------------------------------------------

#[test]
fn different_keys_different_ciphertexts() {
    let mut rng1 = StdRng::seed_from_u64(1);
    let mut rng2 = StdRng::seed_from_u64(2);
    let (pk1, _) = keygen(&mut rng1);
    let (pk2, _) = keygen(&mut rng2);

    let tokens = vec![42, 43, 44];
    let mut enc_rng = StdRng::seed_from_u64(100);
    let ct1 = encrypt(&tokens, &pk1, &mut enc_rng);
    let mut enc_rng = StdRng::seed_from_u64(100);
    let ct2 = encrypt(&tokens, &pk2, &mut enc_rng);

    // Different keys → different ciphertexts (even with same RNG seed for encryption)
    assert_ne!(ct1.chunks[0].0.coeffs, ct2.chunks[0].0.coeffs);
}

#[test]
fn same_plaintext_different_randomness_different_ciphertext() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![100, 200, 300];
    let mut rng1 = StdRng::seed_from_u64(1);
    let mut rng2 = StdRng::seed_from_u64(2);
    let ct1 = encrypt(&tokens, &pk, &mut rng1);
    let ct2 = encrypt(&tokens, &pk, &mut rng2);

    // Same plaintext, different randomness → different ciphertexts
    assert_ne!(ct1.chunks[0].0.coeffs, ct2.chunks[0].0.coeffs);

    // But both decrypt to the same value
    assert_eq!(decrypt(&ct1, &sk), tokens);
    assert_eq!(decrypt(&ct2, &sk), tokens);
}

#[test]
fn wrong_key_gives_wrong_decryption() {
    let mut rng1 = StdRng::seed_from_u64(1);
    let mut rng2 = StdRng::seed_from_u64(2);
    let (pk1, _sk1) = keygen(&mut rng1);
    let (_pk2, sk2) = keygen(&mut rng2);

    let tokens = vec![42, 43, 44];
    let ct = encrypt(&tokens, &pk1, &mut rng1);

    // Decrypt with wrong key
    let wrong_decrypted = decrypt(&ct, &sk2);
    assert_ne!(wrong_decrypted, tokens);
}

// ---------------------------------------------------------------------------
// Deterministic keygen with same seed
// ---------------------------------------------------------------------------

#[test]
fn deterministic_keygen_same_seed() {
    let mut rng1 = StdRng::seed_from_u64(42);
    let mut rng2 = StdRng::seed_from_u64(42);
    let (pk1, sk1) = keygen(&mut rng1);
    let (pk2, sk2) = keygen(&mut rng2);

    assert_eq!(pk1.a.coeffs, pk2.a.coeffs);
    assert_eq!(pk1.b.coeffs, pk2.b.coeffs);
    assert_eq!(sk1.s.coeffs, sk2.s.coeffs);
}

// ---------------------------------------------------------------------------
// Large token sequences (multi-chunk)
// ---------------------------------------------------------------------------

#[test]
fn large_sequence_1000_tokens() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let tokens: Vec<u32> = (0..1000).collect();
    let ct = encrypt(&tokens, &pk, &mut rng);

    // 1000 tokens, N=4096, so 1 chunk
    assert_eq!(ct.chunks.len(), 1);
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

#[test]
fn large_sequence_5000_tokens_multi_chunk() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let tokens: Vec<u32> = (0..5000).collect();
    let ct = encrypt(&tokens, &pk, &mut rng);

    // 5000 tokens, N=4096, so 2 chunks (4096 + 904)
    assert_eq!(ct.chunks.len(), 2);
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

// ---------------------------------------------------------------------------
// Boundary values
// ---------------------------------------------------------------------------

#[test]
fn single_token_max_value() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![u32::MAX];
    let ct = encrypt(&tokens, &pk, &mut rng);
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

#[test]
fn single_token_zero() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![0];
    let ct = encrypt(&tokens, &pk, &mut rng);
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

#[test]
fn all_same_tokens() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![42; 100];
    let ct = encrypt(&tokens, &pk, &mut rng);
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}

#[test]
fn alternating_zero_max() {
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, sk) = keygen(&mut rng);
    let tokens: Vec<u32> = (0..100).map(|i| if i % 2 == 0 { 0 } else { u32::MAX }).collect();
    let ct = encrypt(&tokens, &pk, &mut rng);
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(decrypted, tokens);
}
