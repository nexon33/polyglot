//! Encryption backends for the thin client SDK.
//!
//! Mirrors the `IvcBackend` trait pattern from poly-verified:
//! - `MockEncryption` — passthrough for development and testing
//! - `CkksEncryption` — real FHE (future, behind `ckks` feature flag)

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Trait for encryption backends.
///
/// The thin client (§2.5) encrypts token IDs before sending to the server
/// and decrypts the server's response. The encryption backend is generic —
/// swap `MockEncryption` for `CkksEncryption` without changing client code.
pub trait EncryptionBackend {
    /// The encrypted payload type.
    type Ciphertext: Clone + Serialize + DeserializeOwned;
    /// Public encryption key.
    type PublicKey: Clone;
    /// Secret decryption key.
    type SecretKey: Clone;

    /// Generate a fresh key pair.
    fn keygen(&self) -> (Self::PublicKey, Self::SecretKey);

    /// Encrypt token IDs for server-side inference.
    fn encrypt(&self, token_ids: &[u32], pk: &Self::PublicKey) -> Self::Ciphertext;

    /// Decrypt server's response back to token IDs.
    fn decrypt(&self, ciphertext: &Self::Ciphertext, sk: &Self::SecretKey) -> Vec<u32>;
}

// ---------------------------------------------------------------------------
// MockEncryption — passthrough for development
// ---------------------------------------------------------------------------

/// Mock encryption backend: encrypt = identity, decrypt = identity.
///
/// Demonstrates the full protocol flow without FHE overhead.
/// The protocol is identical to real FHE — only this type changes.
pub struct MockEncryption;

/// Mock ciphertext — just wraps the token IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockCiphertext {
    pub tokens: Vec<u32>,
}

impl EncryptionBackend for MockEncryption {
    type Ciphertext = MockCiphertext;
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32];

    fn keygen(&self) -> (Self::PublicKey, Self::SecretKey) {
        // Deterministic mock keys for reproducible tests
        ([0xAA; 32], [0xBB; 32])
    }

    fn encrypt(&self, token_ids: &[u32], _pk: &Self::PublicKey) -> MockCiphertext {
        MockCiphertext {
            tokens: token_ids.to_vec(),
        }
    }

    fn decrypt(&self, ciphertext: &MockCiphertext, _sk: &Self::SecretKey) -> Vec<u32> {
        ciphertext.tokens.clone()
    }
}

// ---------------------------------------------------------------------------
// CKKS backend (behind feature flag)
// ---------------------------------------------------------------------------

#[cfg(feature = "ckks")]
pub use crate::ckks::{CkksCiphertext, CkksEncryption, CkksPublicKey, CkksSecretKey};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_encryption_roundtrip() {
        let backend = MockEncryption;
        let (pk, sk) = backend.keygen();

        let original = vec![100, 200, 300, 400, 500];
        let ct = backend.encrypt(&original, &pk);
        let decrypted = backend.decrypt(&ct, &sk);

        assert_eq!(original, decrypted);
    }

    #[test]
    fn mock_encryption_empty() {
        let backend = MockEncryption;
        let (pk, sk) = backend.keygen();

        let original: Vec<u32> = vec![];
        let ct = backend.encrypt(&original, &pk);
        let decrypted = backend.decrypt(&ct, &sk);

        assert_eq!(original, decrypted);
    }

    #[test]
    fn mock_ciphertext_serializable() {
        let ct = MockCiphertext {
            tokens: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&ct).unwrap();
        let ct2: MockCiphertext = serde_json::from_str(&json).unwrap();
        assert_eq!(ct.tokens, ct2.tokens);
    }
}
