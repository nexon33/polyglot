use crate::crypto::hash::hash_data;
use crate::error::{ProofSystemError, Result};
use crate::types::{BackendId, Hash, VerifiedProof};

/// Wire format for transmitting verified values with their proofs.
///
/// Layout (per spec §10):
/// ```text
/// value_hash(32) | input_hash(32) | code_hash(32) | proof_scheme(1) |
/// proof_length(4) | proof_bytes(N) | verifier_key_hash(32) | value_bytes(M)
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedResponse {
    pub value_hash: Hash,
    pub input_hash: Hash,
    pub code_hash: Hash,
    pub proof_scheme: BackendId,
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
        let value_hash = hash_data(&value_bytes);
        let code_hash = proof.code_hash();
        let proof_scheme = proof.backend_id();
        let proof_bytes = serde_json::to_vec(proof).unwrap_or_default();

        Self {
            value_hash,
            input_hash,
            code_hash,
            proof_scheme,
            proof_bytes,
            verifier_key_hash,
            value_bytes,
        }
    }

    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let proof_len = self.proof_bytes.len() as u32;
        let total = 32 + 32 + 32 + 1 + 4 + self.proof_bytes.len() + 32 + self.value_bytes.len();
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(&self.value_hash);
        buf.extend_from_slice(&self.input_hash);
        buf.extend_from_slice(&self.code_hash);
        buf.push(self.proof_scheme as u8);
        buf.extend_from_slice(&proof_len.to_be_bytes());
        buf.extend_from_slice(&self.proof_bytes);
        buf.extend_from_slice(&self.verifier_key_hash);
        buf.extend_from_slice(&self.value_bytes);

        buf
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let min_size = 32 + 32 + 32 + 1 + 4 + 32; // 133 minimum
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
        let proof_len = u32::from_be_bytes(data[97..101].try_into().unwrap()) as usize;

        let proof_end = 101 + proof_len;
        if data.len() < proof_end + 32 {
            return Err(ProofSystemError::InvalidEncoding(
                "verified response: proof section truncated".into(),
            ));
        }

        let proof_bytes = data[101..proof_end].to_vec();

        let mut verifier_key_hash = [0u8; 32];
        verifier_key_hash.copy_from_slice(&data[proof_end..proof_end + 32]);

        let value_bytes = data[proof_end + 32..].to_vec();

        Ok(Self {
            value_hash,
            input_hash,
            code_hash,
            proof_scheme,
            proof_bytes,
            verifier_key_hash,
            value_bytes,
        })
    }

    /// Verify that value_bytes matches value_hash.
    pub fn verify_value_integrity(&self) -> bool {
        hash_data(&self.value_bytes) == self.value_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{VerifiedProof, ZERO_HASH};

    #[test]
    fn test_roundtrip() {
        let proof = VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
        };
        let value_bytes = b"hello world".to_vec();

        let response = VerifiedResponse::new(&proof, ZERO_HASH, value_bytes.clone(), ZERO_HASH);
        let bytes = response.to_bytes();
        let decoded = VerifiedResponse::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.value_bytes, value_bytes);
        assert_eq!(decoded.input_hash, ZERO_HASH);
        assert!(decoded.verify_value_integrity());
    }
}
