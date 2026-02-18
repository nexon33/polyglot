//! # Poly Client — Thin Client SDK for Private Verified Inference
//!
//! The encrypted inference client requires only a tokenizer vocabulary file
//! and a cryptographic key pair — no model weights, no GPU, no ML framework —
//! enabling private verified inference from any device including browsers
//! and mobile phones. (Whitepaper §2.5)
//!
//! ## Quick Start
//!
//! ```ignore
//! let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Encrypted, MockEncryption);
//! let response = client.infer("my secret query", &server)?;
//! println!("{}", response.text());
//!
//! // Selective disclosure for different audiences
//! let pharmacist_view = response.disclose(&[8, 9, 10])?;
//! let insurer_view = response.disclose_range(15..16)?;
//! ```

pub mod encryption;
pub mod protocol;

#[cfg(feature = "ckks")]
pub mod ckks;

use std::ops::Range;

use poly_verified::disclosure::Disclosure;
use poly_verified::error::Result;
use poly_verified::types::VerifiedProof;
use poly_verified::verified_type::Verified;

use crate::encryption::EncryptionBackend;
use crate::protocol::{InferRequest, InferResponse, Mode};

/// The thin client for Poly Network private verified inference.
///
/// Generic over the encryption backend:
/// - `MockEncryption` for development (passthrough)
/// - `CkksEncryption` for production FHE (future)
///
/// The client is extraordinarily thin: tokenizer vocab + key pair + encrypt/decrypt.
/// No model weights, no GPU, no ML framework.
pub struct PolyClient<E: EncryptionBackend> {
    model_id: String,
    mode: Mode,
    encryption: E,
    public_key: E::PublicKey,
    secret_key: E::SecretKey,
}

impl<E: EncryptionBackend> PolyClient<E> {
    /// Create a new thin client.
    ///
    /// Generates a fresh key pair from the encryption backend.
    pub fn new(model_id: &str, mode: Mode, encryption: E) -> Self {
        let (public_key, secret_key) = encryption.keygen();
        Self {
            model_id: model_id.to_string(),
            mode,
            encryption,
            public_key,
            secret_key,
        }
    }

    /// The model this client targets.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// The computation mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Prepare an inference request from a prompt's token IDs.
    ///
    /// In the full protocol flow:
    /// 1. Client tokenizes prompt → token_ids (caller handles this)
    /// 2. Client encrypts token_ids → ciphertext
    /// 3. Client builds InferRequest
    pub fn prepare_request(
        &self,
        token_ids: &[u32],
        max_tokens: u32,
        temperature: u32,
        seed: u64,
    ) -> InferRequest {
        let ct = self.encryption.encrypt(token_ids, &self.public_key);
        let encrypted_input = serde_json::to_vec(&ct).unwrap_or_default();

        InferRequest {
            model_id: self.model_id.clone(),
            mode: self.mode,
            encrypted_input,
            max_tokens,
            temperature,
            seed,
        }
    }

    /// Process the server's response: decrypt → build VerifiedResponse.
    ///
    /// In the full protocol flow:
    /// 4. Server runs inference on encrypted activations
    /// 5. Server returns encrypted output + proof
    /// 6. Client decrypts → token_ids
    /// 7. Client wraps as VerifiedResponse
    pub fn process_response(&self, response: &InferResponse) -> VerifiedResponse {
        let ct: E::Ciphertext =
            serde_json::from_slice(&response.encrypted_output).expect("invalid ciphertext");
        let token_ids = self.encryption.decrypt(&ct, &self.secret_key);

        // Wrap the decrypted tokens with the server's proof
        let verified = Verified::__macro_new(token_ids.clone(), response.proof.clone());

        VerifiedResponse {
            token_ids,
            verified,
        }
    }
}

/// Response from verified inference, as seen by the client.
///
/// Carries the decrypted output tokens and the execution proof.
/// Supports selective disclosure for different audiences.
pub struct VerifiedResponse {
    /// Raw output token IDs (decrypted by client).
    pub token_ids: Vec<u32>,
    /// The verified output (tokens + proof).
    verified: Verified<Vec<u32>>,
}

impl VerifiedResponse {
    /// Access the execution proof.
    pub fn proof(&self) -> &VerifiedProof {
        self.verified.proof()
    }

    /// Structural validity check on the proof.
    pub fn is_verified(&self) -> bool {
        self.verified.is_verified()
    }

    /// Create a selective disclosure revealing only the specified token positions.
    ///
    /// Different audiences receive different Disclosure instances from the same proof.
    pub fn disclose(&self, indices: &[usize]) -> Result<Disclosure> {
        self.verified.disclose(indices)
    }

    /// Create a selective disclosure for a contiguous range of token positions.
    pub fn disclose_range(&self, range: Range<usize>) -> Result<Disclosure> {
        self.verified.disclose_range(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{MockCiphertext, MockEncryption};
    use poly_verified::disclosure::verify_disclosure;
    use poly_verified::types::{PrivacyMode, VerifiedProof};

    fn mock_hash_ivc_proof() -> VerifiedProof {
        VerifiedProof::HashIvc {
            chain_tip: [0x01; 32],
            merkle_root: [0x02; 32],
            step_count: 1,
            code_hash: [0x03; 32],
            privacy_mode: PrivacyMode::Transparent,
            blinding_commitment: None,
            checkpoints: vec![[0x04; 32]],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
        }
    }

    fn mock_server_response(token_ids: &[u32]) -> InferResponse {
        let ct = MockCiphertext {
            tokens: token_ids.to_vec(),
        };
        InferResponse {
            encrypted_output: serde_json::to_vec(&ct).unwrap(),
            proof: mock_hash_ivc_proof(),
            model_id: "Qwen/Qwen3-0.6B".into(),
        }
    }

    #[test]
    fn test_client_creation() {
        let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Encrypted, MockEncryption);
        assert_eq!(client.model_id(), "Qwen/Qwen3-0.6B");
        assert_eq!(client.mode(), Mode::Encrypted);
    }

    #[test]
    fn test_prepare_request() {
        let client = PolyClient::new("test-model", Mode::PrivateProven, MockEncryption);
        let req = client.prepare_request(&[100, 200, 300], 50, 700, 42);

        assert_eq!(req.model_id, "test-model");
        assert_eq!(req.mode, Mode::PrivateProven);
        assert_eq!(req.max_tokens, 50);
        assert_eq!(req.temperature, 700);
        assert_eq!(req.seed, 42);

        // Encrypted input should deserialize back to the original tokens
        let ct: MockCiphertext = serde_json::from_slice(&req.encrypted_input).unwrap();
        assert_eq!(ct.tokens, vec![100, 200, 300]);
    }

    #[test]
    fn test_process_response() {
        let client = PolyClient::new("test-model", Mode::Transparent, MockEncryption);
        let output_tokens = vec![100, 200, 300, 400, 500];
        let response = mock_server_response(&output_tokens);

        let verified_response = client.process_response(&response);

        assert_eq!(verified_response.token_ids, output_tokens);
        assert!(verified_response.is_verified());
    }

    #[test]
    fn test_full_protocol_flow() {
        // 1. Client prepares request
        let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Encrypted, MockEncryption);
        let input_tokens = vec![1, 2, 3, 4, 5];
        let req = client.prepare_request(&input_tokens, 50, 700, 42);

        // 2. "Server" processes (mock: just echoes back with more tokens)
        let ct: MockCiphertext = serde_json::from_slice(&req.encrypted_input).unwrap();
        let mut output = ct.tokens.clone();
        output.extend_from_slice(&[10, 20, 30, 40, 50]); // "generated" tokens
        let response = mock_server_response(&output);

        // 3. Client processes response
        let verified_response = client.process_response(&response);
        assert_eq!(verified_response.token_ids.len(), 10);
        assert!(verified_response.is_verified());
    }

    #[test]
    fn test_selective_disclosure_from_response() {
        let client = PolyClient::new("test-model", Mode::PrivateProven, MockEncryption);
        let output_tokens = vec![100, 200, 300, 400, 500, 600, 700, 800];
        let response = mock_server_response(&output_tokens);
        let verified_response = client.process_response(&response);

        // Pharmacist sees tokens 1..4
        let pharmacist_view = verified_response.disclose(&[1, 2, 3]).unwrap();
        assert!(verify_disclosure(&pharmacist_view));
        assert_eq!(pharmacist_view.proofs.len(), 3);

        // Insurer sees token 6
        let insurer_view = verified_response.disclose(&[6]).unwrap();
        assert!(verify_disclosure(&insurer_view));
        assert_eq!(insurer_view.proofs.len(), 1);

        // Same output root
        assert_eq!(pharmacist_view.output_root, insurer_view.output_root);
    }

    #[test]
    fn test_disclosure_range_from_response() {
        let client = PolyClient::new("test-model", Mode::Private, MockEncryption);
        let output_tokens = vec![10, 20, 30, 40, 50];
        let response = mock_server_response(&output_tokens);
        let verified_response = client.process_response(&response);

        let disclosure = verified_response.disclose_range(1..3).unwrap();
        assert!(verify_disclosure(&disclosure));
        assert_eq!(disclosure.proofs.len(), 2);
    }

    #[test]
    fn test_mode_propagates_in_request() {
        for mode in [Mode::Transparent, Mode::PrivateProven, Mode::Private, Mode::Encrypted] {
            let client = PolyClient::new("model", mode, MockEncryption);
            let req = client.prepare_request(&[1], 10, 700, 42);
            assert_eq!(req.mode, mode);
        }
    }
}
