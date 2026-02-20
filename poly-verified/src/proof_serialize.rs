use crate::crypto::hash::hash_data;
use crate::error::{ProofSystemError, Result};
use crate::types::{hash_eq, BackendId, Hash, PrivacyMode, VerifiedProof, ZERO_HASH};

/// Wire format for transmitting verified values with their proofs.
///
/// Layout:
/// ```text
/// value_hash(32) | input_hash(32) | code_hash(32) | proof_scheme(1) |
/// privacy_mode(1) | proof_length(4) | proof_bytes(N) | verifier_key_hash(32) | value_bytes(M)
/// ```
///
/// Privacy behavior:
/// - `Private`: value_hash = ZERO, input_hash = ZERO, value_bytes = empty
/// - `PrivateInputs`: input_hash = ZERO, value_hash and value_bytes present
/// - `Transparent`: all fields present
#[derive(Clone, Debug)]
pub struct VerifiedResponse {
    pub value_hash: Hash,
    pub input_hash: Hash,
    pub code_hash: Hash,
    pub proof_scheme: BackendId,
    pub privacy_mode: PrivacyMode,
    pub proof_bytes: Vec<u8>,
    pub verifier_key_hash: Hash,
    pub value_bytes: Vec<u8>,
}

impl VerifiedResponse {
    /// Create a VerifiedResponse from a proof and serialized value.
    pub fn new(
        proof: &VerifiedProof,
        input_hash: Hash,
        value_bytes: Vec<u8>,
        verifier_key_hash: Hash,
    ) -> Self {
        let privacy = proof.privacy_mode();
        let proof_scheme = proof.backend_id();
        let code_hash = proof.code_hash();
        let proof_bytes = serde_json::to_vec(proof)
            .expect("VerifiedProof serialization must not fail");

        // Apply privacy: zero out hidden fields
        let (effective_value_hash, effective_input_hash, effective_value_bytes) = match privacy {
            PrivacyMode::Private => (ZERO_HASH, ZERO_HASH, Vec::new()),
            PrivacyMode::PrivateInputs => (hash_data(&value_bytes), ZERO_HASH, value_bytes),
            PrivacyMode::Transparent => (hash_data(&value_bytes), input_hash, value_bytes),
        };

        Self {
            value_hash: effective_value_hash,
            input_hash: effective_input_hash,
            code_hash,
            proof_scheme,
            privacy_mode: privacy,
            proof_bytes,
            verifier_key_hash,
            value_bytes: effective_value_bytes,
        }
    }

    /// Serialize to wire format.
    ///
    /// # Panics
    /// Panics if `proof_bytes` length exceeds `u32::MAX`, which would cause
    /// silent truncation in the wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(
            self.proof_bytes.len() <= u32::MAX as usize,
            "VerifiedResponse: proof_bytes length {} exceeds u32::MAX",
            self.proof_bytes.len()
        );
        let proof_len = self.proof_bytes.len() as u32;
        let total =
            32 + 32 + 32 + 1 + 1 + 4 + self.proof_bytes.len() + 32 + self.value_bytes.len();
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(&self.value_hash);
        buf.extend_from_slice(&self.input_hash);
        buf.extend_from_slice(&self.code_hash);
        buf.push(self.proof_scheme as u8);
        buf.push(self.privacy_mode as u8);
        buf.extend_from_slice(&proof_len.to_be_bytes());
        buf.extend_from_slice(&self.proof_bytes);
        buf.extend_from_slice(&self.verifier_key_hash);
        buf.extend_from_slice(&self.value_bytes);

        buf
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // 32+32+32+1+1+4+32 = 134 minimum
        let min_size = 134;
        if data.len() < min_size {
            return Err(ProofSystemError::InvalidEncoding(
                "verified response: too short".into(),
            ));
        }

        let mut value_hash = [0u8; 32];
        value_hash.copy_from_slice(&data[0..32]);
        let mut input_hash = [0u8; 32];
        input_hash.copy_from_slice(&data[32..64]);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&data[64..96]);

        let proof_scheme = BackendId::from_u8(data[96])?;
        let privacy_mode = PrivacyMode::from_u8(data[97])?;
        let proof_len = u32::from_be_bytes(data[98..102].try_into().unwrap()) as usize;

        // Sanity cap: proof_bytes cannot exceed 16 MiB. A valid serialized
        // VerifiedProof is at most a few KiB; allowing 16 MiB provides ample
        // headroom while preventing a crafted message from allocating 4 GiB.
        const MAX_PROOF_LEN: usize = 16 * 1024 * 1024;
        if proof_len > MAX_PROOF_LEN {
            return Err(ProofSystemError::InvalidEncoding(format!(
                "verified response: proof_len {} exceeds maximum {}",
                proof_len, MAX_PROOF_LEN
            )));
        }

        let proof_end = 102 + proof_len;
        if data.len() < proof_end + 32 {
            return Err(ProofSystemError::InvalidEncoding(
                "verified response: proof section truncated".into(),
            ));
        }

        let proof_bytes = data[102..proof_end].to_vec();

        let mut verifier_key_hash = [0u8; 32];
        verifier_key_hash.copy_from_slice(&data[proof_end..proof_end + 32]);

        let value_bytes = data[proof_end + 32..].to_vec();

        Ok(Self {
            value_hash,
            input_hash,
            code_hash,
            proof_scheme,
            privacy_mode,
            proof_bytes,
            verifier_key_hash,
            value_bytes,
        })
    }

    /// Verify that value_bytes matches value_hash.
    /// In Private mode, always returns true (value is hidden).
    /// Uses constant-time comparison to prevent timing side-channel leakage.
    pub fn verify_value_integrity(&self) -> bool {
        if self.privacy_mode == PrivacyMode::Private {
            return true;
        }
        let computed = hash_data(&self.value_bytes);
        hash_eq(&computed, &self.value_hash)
    }

    /// [V9-02 FIX] Validate that proof_bytes deserializes to a valid VerifiedProof.
    /// Without this, a receiver trusting verify_value_integrity() may accept a
    /// response with corrupt/malformed proof_bytes that can never be verified.
    pub fn validate_proof_bytes(&self) -> bool {
        serde_json::from_slice::<VerifiedProof>(&self.proof_bytes).is_ok()
    }

    /// [V11-04 FIX] Validate that proof_bytes content is consistent with the
    /// wire format header fields (proof_scheme and privacy_mode).
    ///
    /// Without this check, an attacker can tamper with the header's proof_scheme
    /// or privacy_mode bytes after serialization. For example, flipping
    /// privacy_mode from Transparent to Private causes `verify_value_integrity()`
    /// to skip the value hash check, bypassing integrity protection.
    pub fn validate_header_consistency(&self) -> bool {
        let proof: VerifiedProof = match serde_json::from_slice(&self.proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // Check proof_scheme matches actual proof variant
        if self.proof_scheme as u8 != proof.backend_id() as u8 {
            return false;
        }
        // Check privacy_mode matches actual proof content
        if self.privacy_mode as u8 != proof.privacy_mode() as u8 {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{VerifiedProof, ZERO_HASH};

    #[test]
    fn test_roundtrip_transparent() {
        let proof = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        };
        let value_bytes = b"hello world".to_vec();

        let response = VerifiedResponse::new(&proof, ZERO_HASH, value_bytes.clone(), ZERO_HASH);
        assert_eq!(response.privacy_mode, PrivacyMode::Transparent);

        let bytes = response.to_bytes();
        let decoded = VerifiedResponse::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.value_bytes, value_bytes);
        assert_eq!(decoded.input_hash, ZERO_HASH);
        assert_eq!(decoded.privacy_mode, PrivacyMode::Transparent);
        assert!(decoded.verify_value_integrity());
    }

    #[test]
    fn test_roundtrip_private() {
        let proof = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Private,
        };
        let value_bytes = b"secret data".to_vec();

        let response =
            VerifiedResponse::new(&proof, [0x42; 32], value_bytes, ZERO_HASH);

        // Private: value_bytes should be empty, hashes zeroed
        assert!(response.value_bytes.is_empty());
        assert_eq!(response.value_hash, ZERO_HASH);
        assert_eq!(response.input_hash, ZERO_HASH);

        let bytes = response.to_bytes();
        let decoded = VerifiedResponse::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.privacy_mode, PrivacyMode::Private);
        assert!(decoded.value_bytes.is_empty());
        assert!(decoded.verify_value_integrity());
    }

    #[test]
    fn test_roundtrip_private_inputs() {
        let proof = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::PrivateInputs,
        };
        let value_bytes = b"visible output".to_vec();

        let response =
            VerifiedResponse::new(&proof, [0x42; 32], value_bytes.clone(), ZERO_HASH);

        // PrivateInputs: input_hash zeroed, value present
        assert_eq!(response.input_hash, ZERO_HASH);
        assert_eq!(response.value_bytes, value_bytes);
        assert_ne!(response.value_hash, ZERO_HASH);

        let bytes = response.to_bytes();
        let decoded = VerifiedResponse::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.privacy_mode, PrivacyMode::PrivateInputs);
        assert_eq!(decoded.value_bytes, value_bytes);
        assert!(decoded.verify_value_integrity());
    }
}
