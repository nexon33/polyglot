//! End-to-end integration tests for the verified inference pipeline.
//!
//! Tests the full flow: PolyClient → InferenceBackend → PolyClient → verify → disclose.
//! Mock backend tests run fast (no model needed). Real model tests are #[ignore].

use std::thread;

use poly_client::encryption::MockEncryption;
use poly_client::protocol::{InferRequest, InferResponse, Mode};
use poly_client::PolyClient;
use poly_inference::http::HttpServer;
use poly_inference::server::{InferenceBackend, MockInferenceBackend};
use poly_verified::disclosure::verify_disclosure;
use poly_verified::types::{PrivacyMode, VerifiedProof, ZERO_HASH};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run the full e2e flow: client prepares → server infers → client processes.
fn e2e_flow(mode: Mode, input_tokens: &[u32]) -> poly_client::VerifiedResponse {
    let backend = MockInferenceBackend::default();
    let client = PolyClient::new("test-model", mode, MockEncryption);

    let req = client.prepare_request(input_tokens, 50, 700, 42);
    let resp = backend.infer(&req).unwrap();
    client.process_response(&resp)
}

fn e2e_flow_with_backend(
    backend: &MockInferenceBackend,
    mode: Mode,
    input_tokens: &[u32],
    seed: u64,
) -> poly_client::VerifiedResponse {
    let client = PolyClient::new("test-model", mode, MockEncryption);
    let req = client.prepare_request(input_tokens, 50, 700, seed);
    let resp = backend.infer(&req).unwrap();
    client.process_response(&resp)
}

// ===========================================================================
// Protocol flow tests (MockBackend, fast)
// ===========================================================================

#[test]
fn e2e_transparent_full_flow() {
    let result = e2e_flow(Mode::Transparent, &[1, 2, 3]);

    assert!(result.is_verified());
    // 3 input + 5 new = 8 tokens
    assert_eq!(result.token_ids.len(), 8);
    // First 3 are the original input
    assert_eq!(&result.token_ids[..3], &[1, 2, 3]);
}

#[test]
fn e2e_private_proven_full_flow() {
    let result = e2e_flow(Mode::PrivateProven, &[10, 20, 30]);

    assert!(result.is_verified());
    assert_eq!(result.token_ids.len(), 8);
    assert_eq!(&result.token_ids[..3], &[10, 20, 30]);
}

#[test]
fn e2e_private_full_flow() {
    let result = e2e_flow(Mode::Private, &[100, 200]);

    assert!(result.is_verified());
    assert_eq!(result.token_ids.len(), 7); // 2 input + 5 new
}

#[test]
fn e2e_encrypted_full_flow() {
    let result = e2e_flow(Mode::Encrypted, &[42, 43, 44, 45]);

    assert!(result.is_verified());
    assert_eq!(result.token_ids.len(), 9); // 4 input + 5 new
}

#[test]
fn e2e_empty_input() {
    let result = e2e_flow(Mode::Transparent, &[]);

    assert!(result.is_verified());
    assert_eq!(result.token_ids.len(), 5); // 0 input + 5 new
}

#[test]
fn e2e_single_token() {
    let result = e2e_flow(Mode::Transparent, &[42]);

    assert!(result.is_verified());
    assert_eq!(result.token_ids.len(), 6); // 1 + 5
    assert_eq!(result.token_ids[0], 42);
}

#[test]
fn e2e_large_input_1000_tokens() {
    let input: Vec<u32> = (0..1000).collect();
    let backend = MockInferenceBackend::new(10);
    let result = e2e_flow_with_backend(&backend, Mode::Transparent, &input, 42);

    assert!(result.is_verified());
    assert_eq!(result.token_ids.len(), 1010); // 1000 + 10
}

#[test]
fn e2e_selective_disclosure_after_inference() {
    let result = e2e_flow(Mode::Transparent, &[1, 2, 3, 4, 5]);

    // Disclose tokens 1 and 3
    let disclosure = result.disclose(&[1, 3]).unwrap();
    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 2);
    assert_eq!(disclosure.total_tokens, 10); // 5 input + 5 new
}

#[test]
fn e2e_multiple_audiences_same_inference() {
    let result = e2e_flow(Mode::Private, &[10, 20, 30, 40, 50]);

    // Doctor: full output
    let doctor = result.disclose(&(0..10).collect::<Vec<_>>()).unwrap();
    // Pharmacist: tokens 3..6
    let pharmacist = result.disclose_range(3..6).unwrap();
    // Insurer: token 8 only
    let insurer = result.disclose(&[8]).unwrap();

    assert!(verify_disclosure(&doctor));
    assert!(verify_disclosure(&pharmacist));
    assert!(verify_disclosure(&insurer));

    // Same Merkle root
    assert_eq!(doctor.output_root, pharmacist.output_root);
    assert_eq!(pharmacist.output_root, insurer.output_root);

    // Different proof counts
    assert_eq!(doctor.proofs.len(), 10);
    assert_eq!(pharmacist.proofs.len(), 3);
    assert_eq!(insurer.proofs.len(), 1);
}

#[test]
fn e2e_sequential_inferences() {
    let backend = MockInferenceBackend::default();

    let r1 = e2e_flow_with_backend(&backend, Mode::Transparent, &[1, 2], 42);
    let r2 = e2e_flow_with_backend(&backend, Mode::Transparent, &[3, 4], 43);

    assert!(r1.is_verified());
    assert!(r2.is_verified());
    assert_ne!(r1.token_ids, r2.token_ids);
}

#[test]
fn e2e_different_seeds_different_outputs() {
    let backend = MockInferenceBackend::default();

    let r1 = e2e_flow_with_backend(&backend, Mode::Transparent, &[1, 2, 3], 42);
    let r2 = e2e_flow_with_backend(&backend, Mode::Transparent, &[1, 2, 3], 99);

    // Same input but different seeds → different generated tokens
    assert_eq!(&r1.token_ids[..3], &r2.token_ids[..3]); // inputs same
    assert_ne!(r1.token_ids[3..], r2.token_ids[3..]); // generated differ
}

#[test]
fn e2e_request_response_serialization_roundtrip() {
    let client = PolyClient::new("test-model", Mode::Encrypted, MockEncryption);
    let req = client.prepare_request(&[1, 2, 3], 50, 700, 42);

    // Serialize request → JSON → deserialize
    let json = serde_json::to_string(&req).unwrap();
    let req2: InferRequest = serde_json::from_str(&json).unwrap();

    // Server processes the deserialized request
    let backend = MockInferenceBackend::default();
    let resp = backend.infer(&req2).unwrap();

    // Serialize response → JSON → deserialize
    let json = serde_json::to_string(&resp).unwrap();
    let resp2: InferResponse = serde_json::from_str(&json).unwrap();

    // Client processes the deserialized response
    let result = client.process_response(&resp2);
    assert!(result.is_verified());
}

// ===========================================================================
// Proof verification tests
// ===========================================================================

#[test]
fn e2e_proof_is_real_hash_ivc() {
    let result = e2e_flow(Mode::Transparent, &[1, 2, 3]);

    match result.proof() {
        VerifiedProof::HashIvc { .. } => {} // Real HashIvc, not Mock
        _ => panic!("expected HashIvc proof from mock backend"),
    }
}

#[test]
fn e2e_proof_step_count_positive() {
    let result = e2e_flow(Mode::Transparent, &[1]);

    match result.proof() {
        VerifiedProof::HashIvc { step_count, .. } => {
            assert!(*step_count > 0, "step_count must be positive");
        }
        _ => panic!("expected HashIvc"),
    }
}

#[test]
fn e2e_transparent_proof_has_code_hash() {
    let result = e2e_flow(Mode::Transparent, &[1, 2, 3]);

    match result.proof() {
        VerifiedProof::HashIvc { code_hash, .. } => {
            assert_ne!(*code_hash, ZERO_HASH, "transparent mode should reveal code hash");
        }
        _ => panic!("expected HashIvc"),
    }
}

#[test]
fn e2e_private_proof_hides_code_hash() {
    let result = e2e_flow(Mode::Private, &[1, 2, 3]);

    // Private mode hides code hash (set to ZERO_HASH by convention)
    // Note: the mock backend sets a real code_hash but privacy_mode=Private
    // means the proof's code_hash() accessor returns ZERO_HASH
    assert_eq!(result.proof().code_hash(), ZERO_HASH);
}

#[test]
fn e2e_privacy_mode_matches_request() {
    for (mode, expected_privacy) in [
        (Mode::Transparent, PrivacyMode::Transparent),
        (Mode::PrivateProven, PrivacyMode::PrivateInputs),
        (Mode::Private, PrivacyMode::Private),
        (Mode::Encrypted, PrivacyMode::Private),
    ] {
        let result = e2e_flow(mode, &[1, 2, 3]);

        match result.proof() {
            VerifiedProof::HashIvc { privacy_mode, .. } => {
                assert_eq!(
                    *privacy_mode, expected_privacy,
                    "mode {:?} should produce {:?}",
                    mode, expected_privacy
                );
            }
            _ => panic!("expected HashIvc"),
        }
    }
}

// ===========================================================================
// Disclosure integration tests
// ===========================================================================

#[test]
fn e2e_disclose_single_token_from_inference() {
    let result = e2e_flow(Mode::Transparent, &[10, 20, 30]);
    let disclosure = result.disclose(&[0]).unwrap();

    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 1);
    assert_eq!(disclosure.total_tokens, 8);
}

#[test]
fn e2e_disclose_range_from_inference() {
    let result = e2e_flow(Mode::Transparent, &[10, 20, 30, 40, 50]);
    let disclosure = result.disclose_range(2..5).unwrap();

    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 3);
}

#[test]
fn e2e_full_and_empty_disclosure_same_root() {
    let result = e2e_flow(Mode::Transparent, &[10, 20, 30]);
    let total = result.token_ids.len();

    let full = result.disclose(&(0..total).collect::<Vec<_>>()).unwrap();
    let empty = result.disclose(&[]).unwrap();

    assert!(verify_disclosure(&full));
    assert!(verify_disclosure(&empty));
    assert_eq!(full.output_root, empty.output_root);
}

#[test]
fn e2e_disclosure_from_all_modes() {
    for mode in [
        Mode::Transparent,
        Mode::PrivateProven,
        Mode::Private,
        Mode::Encrypted,
    ] {
        let result = e2e_flow(mode, &[1, 2, 3, 4, 5]);

        let disclosure = result.disclose(&[0, 2, 4]).unwrap();
        assert!(
            verify_disclosure(&disclosure),
            "disclosure failed for mode {:?}",
            mode
        );
        assert_eq!(disclosure.proofs.len(), 3);
    }
}

// ===========================================================================
// HTTP transport tests
// ===========================================================================

#[test]
fn http_infer_transparent() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    // Server handles one request in a thread
    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    // Client sends request via HTTP
    let client = PolyClient::new("test-model", Mode::Transparent, MockEncryption);
    let req = client.prepare_request(&[1, 2, 3], 50, 700, 42);
    let req_json = serde_json::to_string(&req).unwrap();

    let url = format!("http://{}/infer", addr);
    let mut resp = ureq::post(&url)
        .content_type("application/json")
        .send(&req_json)
        .unwrap();

    let resp_body = resp.body_mut().read_to_string().unwrap();
    let infer_resp: InferResponse = serde_json::from_str(&resp_body).unwrap();

    // Process response
    let result = client.process_response(&infer_resp);
    assert!(result.is_verified());
    assert_eq!(result.token_ids.len(), 8);

    handle.join().unwrap();
}

#[test]
fn http_infer_private() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    let client = PolyClient::new("test-model", Mode::Private, MockEncryption);
    let req = client.prepare_request(&[10, 20], 50, 700, 42);
    let req_json = serde_json::to_string(&req).unwrap();

    let url = format!("http://{}/infer", addr);
    let mut resp = ureq::post(&url)
        .content_type("application/json")
        .send(&req_json)
        .unwrap();

    let resp_body = resp.body_mut().read_to_string().unwrap();
    let infer_resp: InferResponse = serde_json::from_str(&resp_body).unwrap();

    let result = client.process_response(&infer_resp);
    assert!(result.is_verified());

    // Selective disclosure works over HTTP
    let disclosure = result.disclose(&[0, 1]).unwrap();
    assert!(verify_disclosure(&disclosure));

    handle.join().unwrap();
}

#[test]
fn http_404_for_wrong_path() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    let url = format!("http://{}/wrong", addr);
    let resp = ureq::post(&url)
        .content_type("application/json")
        .send("{}")
        .unwrap_err();

    match resp {
        ureq::Error::StatusCode(code) => assert_eq!(code, 404),
        other => panic!("expected 404, got: {:?}", other),
    }

    handle.join().unwrap();
}

#[test]
fn http_405_for_get() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    let url = format!("http://{}/infer", addr);
    let resp = ureq::get(&url).call().unwrap_err();

    match resp {
        ureq::Error::StatusCode(code) => assert_eq!(code, 405),
        other => panic!("expected 405, got: {:?}", other),
    }

    handle.join().unwrap();
}

#[test]
fn http_sequential_requests() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    // Handle 3 requests
    let handle = thread::spawn(move || {
        for _ in 0..3 {
            server.handle_one(&backend).unwrap();
        }
    });

    let client = PolyClient::new("test-model", Mode::Transparent, MockEncryption);
    let url = format!("http://{}/infer", addr);

    for i in 0..3u32 {
        let req = client.prepare_request(&[i, i + 1], 50, 700, i as u64);
        let req_json = serde_json::to_string(&req).unwrap();

        let mut resp = ureq::post(&url)
            .content_type("application/json")
            .send(&req_json)
            .unwrap();

        let resp_body = resp.body_mut().read_to_string().unwrap();
        let infer_resp: InferResponse = serde_json::from_str(&resp_body).unwrap();
        let result = client.process_response(&infer_resp);
        assert!(result.is_verified());
    }

    handle.join().unwrap();
}

// ===========================================================================
// POST /generate endpoint tests
// ===========================================================================

#[test]
fn http_generate_bad_json() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    let url = format!("http://{}/generate", addr);
    let resp = ureq::post(&url)
        .content_type("application/json")
        .send("not json");

    // Should get 400 for invalid JSON
    match resp {
        Err(ureq::Error::StatusCode(400)) => {} // expected
        other => panic!("expected 400, got: {:?}", other),
    }

    handle.join().unwrap();
}

#[test]
fn http_generate_missing_prompt() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    let url = format!("http://{}/generate", addr);
    let resp = ureq::post(&url)
        .content_type("application/json")
        .send(r#"{"max_tokens": 10}"#);

    // Should get 400 — prompt is required
    match resp {
        Err(ureq::Error::StatusCode(400)) => {}
        other => panic!("expected 400, got: {:?}", other),
    }

    handle.join().unwrap();
}

// ===========================================================================
// POST /generate/encrypted endpoint tests
// ===========================================================================

#[test]
fn http_get_pubkey() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    let url = format!("http://{}/pubkey", addr);
    let mut resp = ureq::get(&url).call().unwrap();
    let body = resp.body_mut().read_to_string().unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(parsed["public_key"].is_string());
    let pk_hex = parsed["public_key"].as_str().unwrap();
    assert!(!pk_hex.is_empty());

    // Verify it's valid hex → valid CkksPublicKey
    let pk_bytes = hex::decode(pk_hex).unwrap();
    let _pk: poly_client::ckks::CkksPublicKey = serde_json::from_slice(&pk_bytes).unwrap();

    handle.join().unwrap();
}

#[test]
fn http_encrypted_roundtrip() {
    use poly_client::encryption::EncryptionBackend;
    use poly_client::ckks::CkksEncryption;

    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();

    // Get server's public key hex for encrypting our input
    let server_pk_hex = server.server_public_key_hex();

    // Client generates its own key pair (for response encryption)
    let ckks = CkksEncryption;
    let (client_pk, client_sk) = ckks.keygen();
    let client_pk_hex = hex::encode(serde_json::to_vec(&client_pk).unwrap());

    // Client encrypts some token IDs with server's public key
    let server_pk_bytes = hex::decode(&server_pk_hex).unwrap();
    let server_pk: poly_client::ckks::CkksPublicKey =
        serde_json::from_slice(&server_pk_bytes).unwrap();
    let input_tokens: Vec<u32> = vec![100, 200, 300];
    let input_ct = ckks.encrypt(&input_tokens, &server_pk);
    let input_ct_hex = hex::encode(serde_json::to_vec(&input_ct).unwrap());

    let backend = MockInferenceBackend::default();
    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    // POST /generate/encrypted
    let url = format!("http://{}/generate/encrypted", addr);
    let req_body = serde_json::json!({
        "encrypted_input": input_ct_hex,
        "client_public_key": client_pk_hex,
        "max_tokens": 10,
        "temperature": 700,
        "seed": 42,
    });

    let mut resp = ureq::post(&url)
        .content_type("application/json")
        .send(&serde_json::to_string(&req_body).unwrap())
        .unwrap();

    let resp_body = resp.body_mut().read_to_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&resp_body).unwrap();

    // Response should have encrypted_output, proof, compliance
    assert!(parsed["encrypted_output"].is_string());
    assert!(parsed["proof"].is_object());
    assert!(parsed["compliance"].is_object());
    assert!(parsed["generated_tokens"].is_number());
    assert!(parsed["total_tokens"].is_number());

    // Proof should be private (ZK)
    assert_eq!(parsed["proof"]["privacy_mode"].as_str().unwrap(), "Private");
    assert!(parsed["proof"]["verified"].as_bool().unwrap());

    // Decrypt the output
    let output_ct_hex = parsed["encrypted_output"].as_str().unwrap();
    let output_ct_bytes = hex::decode(output_ct_hex).unwrap();
    let output_ct: poly_client::ckks::CkksCiphertext =
        serde_json::from_slice(&output_ct_bytes).unwrap();
    let output_tokens = ckks.decrypt(&output_ct, &client_sk);

    // Output should contain input tokens + generated tokens
    let total = parsed["total_tokens"].as_u64().unwrap() as usize;
    assert_eq!(output_tokens.len(), total);
    // First tokens should be the input
    assert_eq!(&output_tokens[..3], &[100, 200, 300]);
    // Should have generated new tokens
    assert!(output_tokens.len() > 3);

    handle.join().unwrap();
}

#[test]
fn http_encrypted_bad_ciphertext() {
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    let backend = MockInferenceBackend::default();

    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    let url = format!("http://{}/generate/encrypted", addr);
    let req_body = serde_json::json!({
        "encrypted_input": "not_valid_hex!!!",
        "client_public_key": "deadbeef",
        "max_tokens": 10,
    });

    let resp = ureq::post(&url)
        .content_type("application/json")
        .send(&serde_json::to_string(&req_body).unwrap());

    match resp {
        Err(ureq::Error::StatusCode(400)) => {}
        other => panic!("expected 400, got: {:?}", other),
    }

    handle.join().unwrap();
}

// ===========================================================================
// Real model tests (heavy, require model download)
// ===========================================================================

#[test]
#[ignore]
fn real_model_transparent_e2e() {
    let _ = poly_inference::model::load_model(candle_core::Device::Cpu);

    let backend = poly_inference::server::RealInferenceBackend;
    let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Transparent, MockEncryption);
    let tokens = poly_inference::model::tokenize("Hello").unwrap();

    let req = client.prepare_request(&tokens, 10, 700, 42);
    let resp = backend.infer(&req).unwrap();
    let result = client.process_response(&resp);

    assert!(result.is_verified());
    assert!(result.token_ids.len() > tokens.len());
}

#[test]
#[ignore]
fn real_model_private_e2e() {
    // Model may already be loaded from previous test
    let _ = poly_inference::model::load_model(candle_core::Device::Cpu);

    let backend = poly_inference::server::RealInferenceBackend;
    let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Private, MockEncryption);
    let tokens = poly_inference::model::tokenize("The capital of France is").unwrap();

    let req = client.prepare_request(&tokens, 20, 700, 42);
    let resp = backend.infer(&req).unwrap();
    let result = client.process_response(&resp);

    assert!(result.is_verified());
    assert_eq!(result.proof().code_hash(), ZERO_HASH); // Private hides code hash

    match result.proof() {
        VerifiedProof::HashIvc {
            privacy_mode,
            blinding_commitment,
            ..
        } => {
            assert_eq!(*privacy_mode, PrivacyMode::Private);
            assert!(blinding_commitment.is_some());
        }
        _ => panic!("expected HashIvc"),
    }
}

#[test]
#[ignore]
fn real_model_disclosure_e2e() {
    let _ = poly_inference::model::load_model(candle_core::Device::Cpu);

    let backend = poly_inference::server::RealInferenceBackend;
    let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Transparent, MockEncryption);
    let tokens = poly_inference::model::tokenize("Hello world").unwrap();

    let req = client.prepare_request(&tokens, 10, 700, 42);
    let resp = backend.infer(&req).unwrap();
    let result = client.process_response(&resp);

    assert!(result.is_verified());

    // Selective disclosure from real inference output
    let disclosure = result.disclose(&[0, 1]).unwrap();
    assert!(verify_disclosure(&disclosure));
    assert_eq!(disclosure.proofs.len(), 2);
}
