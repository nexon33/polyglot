use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::{ProofSystemError, Result};
use crate::types::{hash_eq, CodeAttestation, Hash};

/// O(1) code integrity check: constant-time comparison of two hashes.
pub fn check_code_integrity(received: &Hash, canonical: &Hash) -> bool {
    hash_eq(received, canonical)
}

/// Sign a CodeAttestation with Ed25519.
pub fn sign_attestation(
    node_id: &[u8; 32],
    code_hash: &Hash,
    circuit_id: u64,
    signing_key: &SigningKey,
) -> CodeAttestation {
    let mut msg = [0u8; 72];
    msg[0..32].copy_from_slice(node_id);
    msg[32..64].copy_from_slice(code_hash);
    msg[64..72].copy_from_slice(&circuit_id.to_le_bytes());

    let signature = signing_key.sign(&msg);

    CodeAttestation {
        node_id: *node_id,
        code_hash: *code_hash,
        circuit_id,
        signature: signature.to_bytes(),
    }
}

/// Verify a CodeAttestation's Ed25519 signature.
pub fn verify_attestation(
    attestation: &CodeAttestation,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let msg = attestation.sign_message();
    let sig = ed25519_dalek::Signature::from_bytes(&attestation.signature);
    verifying_key
        .verify(&msg, &sig)
        .map_err(|_| ProofSystemError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::hash_data;

    #[test]
    fn test_code_integrity_match() {
        let canonical = hash_data(b"canonical_wasm");
        assert!(check_code_integrity(&canonical, &canonical));
    }

    #[test]
    fn test_code_integrity_mismatch() {
        let canonical = hash_data(b"canonical_wasm");
        let modified = hash_data(b"modified_wasm");
        assert!(!check_code_integrity(&modified, &canonical));
    }

    #[test]
    fn test_attestation_sign_verify() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        let node_id = [0xAA; 32];
        let code_hash = hash_data(b"canonical_wasm");

        let attestation = sign_attestation(&node_id, &code_hash, 100, &signing_key);

        assert!(verify_attestation(&attestation, &verifying_key).is_ok());
    }

    #[test]
    fn test_attestation_wrong_key_fails() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let wrong_key = SigningKey::from_bytes(&[0x43; 32]);
        let wrong_verifying = wrong_key.verifying_key();
        let node_id = [0xAA; 32];
        let code_hash = hash_data(b"canonical_wasm");

        let attestation = sign_attestation(&node_id, &code_hash, 100, &signing_key);

        assert!(verify_attestation(&attestation, &wrong_verifying).is_err());
    }

    #[test]
    fn test_attestation_serialization_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let node_id = [0xAA; 32];
        let code_hash = hash_data(b"canonical_wasm");

        let attestation = sign_attestation(&node_id, &code_hash, 100, &signing_key);

        let bytes = attestation.to_bytes();
        assert_eq!(bytes.len(), 136);

        let decoded = CodeAttestation::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.node_id, attestation.node_id);
        assert_eq!(decoded.code_hash, attestation.code_hash);
        assert_eq!(decoded.circuit_id, attestation.circuit_id);
        assert_eq!(decoded.signature, attestation.signature);
    }
}
