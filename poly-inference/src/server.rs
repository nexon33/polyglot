//! Inference server backends.
//!
//! `InferenceBackend` is the server-side trait — the counterpart to the
//! client's `EncryptionBackend`. Two implementations:
//!
//! - `MockInferenceBackend` — predictable output, real HashIvc proofs, no model weights.
//! - `RealInferenceBackend` — actual Qwen3-0.6B inference via Candle.

use anyhow::Result;
use sha2::{Digest, Sha256};

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, InferResponse, Mode};
use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{PrivacyMode, StepWitness, VerifiedProof};

/// Server-side inference backend trait.
///
/// Takes an `InferRequest` (from the thin client) and produces an `InferResponse`
/// containing encrypted output tokens and an execution proof.
pub trait InferenceBackend {
    fn infer(&self, request: &InferRequest) -> Result<InferResponse>;
}

// ---------------------------------------------------------------------------
// MockInferenceBackend — no model, real proofs
// ---------------------------------------------------------------------------

/// Mock inference backend for testing.
///
/// Generates deterministic output tokens and real HashIvc proofs.
/// No model weights, no GPU, no download — just protocol correctness.
pub struct MockInferenceBackend {
    /// Number of new tokens to "generate" per request.
    pub new_tokens: usize,
}

impl Default for MockInferenceBackend {
    fn default() -> Self {
        Self { new_tokens: 5 }
    }
}

impl MockInferenceBackend {
    pub fn new(new_tokens: usize) -> Self {
        Self { new_tokens }
    }
}

impl InferenceBackend for MockInferenceBackend {
    fn infer(&self, request: &InferRequest) -> Result<InferResponse> {
        // 1. Decrypt input (MockEncryption: passthrough)
        let input_ct: MockCiphertext = serde_json::from_slice(&request.encrypted_input)?;
        let input_tokens = &input_ct.tokens;

        // 2. Generate predictable output: input tokens + sequential new tokens
        let mut output_tokens = input_tokens.clone();
        let base = (input_tokens.len() as u32) * 100 + request.seed as u32;
        for i in 0..self.new_tokens {
            output_tokens.push(base + i as u32);
        }

        // 3. Create a real HashIvc proof
        let privacy = request.mode.to_privacy_mode();
        let proof = create_proof(&output_tokens, privacy)?;

        // 4. Re-encrypt output (MockEncryption: wrap in MockCiphertext)
        let output_ct = MockCiphertext {
            tokens: output_tokens,
        };
        let encrypted_output = serde_json::to_vec(&output_ct)?;

        Ok(InferResponse {
            encrypted_output,
            proof,
            model_id: request.model_id.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// RealInferenceBackend — actual Candle model
// ---------------------------------------------------------------------------

/// Real inference backend using Qwen3-0.6B via Candle.
///
/// Requires `model::load_model()` to be called first.
pub struct RealInferenceBackend;

impl InferenceBackend for RealInferenceBackend {
    fn infer(&self, request: &InferRequest) -> Result<InferResponse> {
        // 1. Decrypt input
        let input_ct: MockCiphertext = serde_json::from_slice(&request.encrypted_input)?;
        let input_tokens = input_ct.tokens;

        // 2. Run real verified inference based on mode
        let (output_tokens, proof) = match request.mode {
            Mode::Transparent => {
                let verified = crate::inference::generate_verified(
                    input_tokens,
                    request.max_tokens,
                    request.temperature,
                    request.seed,
                );
                (verified.value().clone(), verified.proof().clone())
            }
            Mode::PrivateProven => {
                let verified = crate::inference::generate_private_inputs(
                    input_tokens,
                    request.max_tokens,
                    request.temperature,
                    request.seed,
                );
                (verified.value().clone(), verified.proof().clone())
            }
            Mode::Private | Mode::Encrypted => {
                let verified = crate::inference::generate_private(
                    input_tokens,
                    request.max_tokens,
                    request.temperature,
                    request.seed,
                );
                (verified.value().clone(), verified.proof().clone())
            }
        };

        // 3. Re-encrypt output
        let output_ct = MockCiphertext {
            tokens: output_tokens,
        };
        let encrypted_output = serde_json::to_vec(&output_ct)?;

        Ok(InferResponse {
            encrypted_output,
            proof,
            model_id: request.model_id.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a real HashIvc proof for a token sequence.
///
/// Uses SHA-256 of input/output tokens as state hashes, then runs the full
/// HashIvc pipeline (init → fold_step → finalize).
fn create_proof(output_tokens: &[u32], privacy: PrivacyMode) -> Result<VerifiedProof> {
    let backend = HashIvc;

    // Code hash: identifies the inference function
    let code_hash = sha256(b"poly_inference::inference::generate_verified");

    let mut acc = backend.init(&code_hash, privacy);

    // Hash the input and output as state
    let input_hash = sha256(&tokens_to_bytes(output_tokens));
    let output_hash = sha256(&tokens_to_bytes(output_tokens));

    let witness = StepWitness {
        state_before: input_hash,
        state_after: output_hash,
        step_inputs: input_hash,
    };
    backend.fold_step(&mut acc, &witness)?;

    let proof = backend.finalize(acc)?;
    Ok(proof)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn tokens_to_bytes(tokens: &[u32]) -> Vec<u8> {
    tokens.iter().flat_map(|t| t.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(mode: Mode, tokens: &[u32]) -> InferRequest {
        let ct = MockCiphertext {
            tokens: tokens.to_vec(),
        };
        InferRequest {
            model_id: "test-model".into(),
            mode,
            encrypted_input: serde_json::to_vec(&ct).unwrap(),
            max_tokens: 10,
            temperature: 700,
            seed: 42,
        }
    }

    #[test]
    fn mock_backend_transparent() {
        let backend = MockInferenceBackend::default();
        let req = make_request(Mode::Transparent, &[1, 2, 3]);
        let resp = backend.infer(&req).unwrap();

        let ct: MockCiphertext = serde_json::from_slice(&resp.encrypted_output).unwrap();
        // Input (3) + 5 new tokens = 8
        assert_eq!(ct.tokens.len(), 8);
        // First 3 are the input
        assert_eq!(&ct.tokens[..3], &[1, 2, 3]);

        // Proof is real HashIvc
        match &resp.proof {
            VerifiedProof::HashIvc {
                step_count,
                privacy_mode,
                blinding_commitment,
                ..
            } => {
                assert_eq!(*step_count, 1);
                assert_eq!(*privacy_mode, PrivacyMode::Transparent);
                assert!(blinding_commitment.is_none());
            }
            _ => panic!("expected HashIvc proof"),
        }
    }

    #[test]
    fn mock_backend_private() {
        let backend = MockInferenceBackend::default();
        let req = make_request(Mode::Private, &[10, 20]);
        let resp = backend.infer(&req).unwrap();

        match &resp.proof {
            VerifiedProof::HashIvc {
                privacy_mode,
                blinding_commitment,
                ..
            } => {
                assert_eq!(*privacy_mode, PrivacyMode::Private);
                assert!(blinding_commitment.is_some());
            }
            _ => panic!("expected HashIvc proof"),
        }
    }

    #[test]
    fn mock_backend_private_proven() {
        let backend = MockInferenceBackend::default();
        let req = make_request(Mode::PrivateProven, &[10]);
        let resp = backend.infer(&req).unwrap();

        match &resp.proof {
            VerifiedProof::HashIvc {
                privacy_mode,
                blinding_commitment,
                ..
            } => {
                assert_eq!(*privacy_mode, PrivacyMode::PrivateInputs);
                assert!(blinding_commitment.is_some());
            }
            _ => panic!("expected HashIvc proof"),
        }
    }

    #[test]
    fn mock_backend_empty_input() {
        let backend = MockInferenceBackend::new(3);
        let req = make_request(Mode::Transparent, &[]);
        let resp = backend.infer(&req).unwrap();

        let ct: MockCiphertext = serde_json::from_slice(&resp.encrypted_output).unwrap();
        assert_eq!(ct.tokens.len(), 3);
    }

    #[test]
    fn mock_backend_deterministic() {
        let backend = MockInferenceBackend::default();
        let req = make_request(Mode::Transparent, &[1, 2, 3]);
        let resp1 = backend.infer(&req).unwrap();
        let resp2 = backend.infer(&req).unwrap();

        let ct1: MockCiphertext = serde_json::from_slice(&resp1.encrypted_output).unwrap();
        let ct2: MockCiphertext = serde_json::from_slice(&resp2.encrypted_output).unwrap();
        assert_eq!(ct1.tokens, ct2.tokens);
    }

    #[test]
    fn mock_backend_model_id_preserved() {
        let backend = MockInferenceBackend::default();
        let req = make_request(Mode::Transparent, &[1]);
        let resp = backend.infer(&req).unwrap();
        assert_eq!(resp.model_id, "test-model");
    }

    #[test]
    fn mock_backend_custom_new_tokens() {
        let backend = MockInferenceBackend::new(20);
        let req = make_request(Mode::Transparent, &[1, 2]);
        let resp = backend.infer(&req).unwrap();

        let ct: MockCiphertext = serde_json::from_slice(&resp.encrypted_output).unwrap();
        assert_eq!(ct.tokens.len(), 22); // 2 input + 20 new
    }
}
