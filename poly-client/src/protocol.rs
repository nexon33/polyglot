//! Network protocol types for client-server inference communication.
//!
//! These types define the wire format between the thin client and the
//! inference server. The client serializes `InferRequest`, the server
//! responds with `InferResponse`.

use poly_verified::types::VerifiedProof;
use serde::{Deserialize, Serialize};

/// Computation mode selection (§2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// Server sees input. Proof reveals input hash, output hash, code hash. ~0% overhead.
    Transparent,
    /// Server sees input. Proof reveals nothing about input. ~0% overhead.
    PrivateProven,
    /// Server sees input. Proof reveals nothing about input or code. ~0% overhead.
    Private,
    /// Server never sees plaintext. 3–15x overhead depending on hardware.
    Encrypted,
}

impl Mode {
    /// Maps to the poly-verified privacy mode for proof generation.
    pub fn to_privacy_mode(&self) -> poly_verified::types::PrivacyMode {
        match self {
            Mode::Transparent => poly_verified::types::PrivacyMode::Transparent,
            Mode::PrivateProven => poly_verified::types::PrivacyMode::PrivateInputs,
            Mode::Private => poly_verified::types::PrivacyMode::Private,
            Mode::Encrypted => poly_verified::types::PrivacyMode::Private,
        }
    }

    /// Whether this mode requires FHE encryption.
    pub fn requires_encryption(&self) -> bool {
        matches!(self, Mode::Encrypted)
    }
}

/// Inference request from client to server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InferRequest {
    /// Model identifier (e.g., "Qwen/Qwen3-0.6B").
    pub model_id: String,
    /// Computation mode.
    pub mode: Mode,
    /// Encrypted input token IDs (serialized Ciphertext).
    pub encrypted_input: Vec<u8>,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Temperature × 1000 (u32 for deterministic hashing).
    pub temperature: u32,
    /// Random seed for reproducibility.
    pub seed: u64,
}

/// Inference response from server to client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InferResponse {
    /// Encrypted output token IDs (serialized Ciphertext).
    pub encrypted_output: Vec<u8>,
    /// Execution proof (IVC).
    pub proof: VerifiedProof,
    /// Model that was actually used.
    pub model_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use poly_verified::types::{PrivacyMode, ZERO_HASH};

    #[test]
    fn mode_to_privacy_mode() {
        assert_eq!(Mode::Transparent.to_privacy_mode(), PrivacyMode::Transparent);
        assert_eq!(Mode::PrivateProven.to_privacy_mode(), PrivacyMode::PrivateInputs);
        assert_eq!(Mode::Private.to_privacy_mode(), PrivacyMode::Private);
        assert_eq!(Mode::Encrypted.to_privacy_mode(), PrivacyMode::Private);
    }

    #[test]
    fn mode_requires_encryption() {
        assert!(!Mode::Transparent.requires_encryption());
        assert!(!Mode::PrivateProven.requires_encryption());
        assert!(!Mode::Private.requires_encryption());
        assert!(Mode::Encrypted.requires_encryption());
    }

    #[test]
    fn infer_request_serializable() {
        let req = InferRequest {
            model_id: "Qwen/Qwen3-0.6B".into(),
            mode: Mode::Encrypted,
            encrypted_input: vec![1, 2, 3],
            max_tokens: 50,
            temperature: 700,
            seed: 42,
        };
        let json = serde_json::to_string(&req).unwrap();
        let req2: InferRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.model_id, req2.model_id);
        assert_eq!(req.mode, req2.mode);
        assert_eq!(req.max_tokens, req2.max_tokens);
    }

    #[test]
    fn infer_response_serializable() {
        let resp = InferResponse {
            encrypted_output: vec![4, 5, 6],
            proof: VerifiedProof::Mock {
                input_hash: ZERO_HASH,
                output_hash: ZERO_HASH,
                privacy_mode: PrivacyMode::Transparent,
            },
            model_id: "Qwen/Qwen3-0.6B".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let resp2: InferResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp.model_id, resp2.model_id);
    }
}
