//! Ed25519 wallet keypairs and account-id derivation.
//!
//! A poly-chain account is identified by `AccountId = SHA-256(public key)`.
//! A transaction carries the signer's public key explicitly; the validator
//! checks both that the signature is valid and that `SHA-256(public key)`
//! equals the claimed account id. Hashing keeps addresses uniform and leaves
//! the public key undisclosed until an account first transacts.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{ChainError, Result};
use crate::primitives::AccountId;

/// An Ed25519 keypair owning a poly-chain account.
#[derive(Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a fresh random keypair using the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret)
            .map_err(|e| ChainError::Io(format!("CSPRNG failure: {e}")))?;
        Ok(Self::from_secret_bytes(&secret))
    }

    /// Reconstruct a keypair from its 32-byte secret scalar.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte Ed25519 secret. Treat as sensitive material.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The account id: `SHA-256(public key)`.
    pub fn account_id(&self) -> AccountId {
        account_id_from_public(&self.public_bytes())
    }

    /// Sign a message, returning the raw 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Derive an account id from a raw Ed25519 public key: `SHA-256(public key)`.
pub fn account_id_from_public(public_key: &[u8; 32]) -> AccountId {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest);
    id
}

/// Verify a raw 64-byte Ed25519 signature against a public key and message.
///
/// Uses `verify_strict` to reject small-order / malleable signatures, matching
/// [`crate::validation::verify_signature`].
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| ChainError::InvalidSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &sig)
        .map_err(|_| ChainError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_unique() {
        let a = Keypair::generate().unwrap();
        let b = Keypair::generate().unwrap();
        assert_ne!(a.account_id(), b.account_id());
        assert_ne!(a.secret_bytes(), b.secret_bytes());
    }

    #[test]
    fn secret_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let restored = Keypair::from_secret_bytes(&kp.secret_bytes());
        assert_eq!(kp.public_bytes(), restored.public_bytes());
        assert_eq!(kp.account_id(), restored.account_id());
    }

    #[test]
    fn account_id_is_sha256_of_public_key() {
        let kp = Keypair::generate().unwrap();
        assert_eq!(kp.account_id(), account_id_from_public(&kp.public_bytes()));
        // The account id is a hash, not the key itself.
        assert_ne!(kp.account_id(), kp.public_bytes());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let msg = b"poly-chain testnet transfer";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_bytes(), msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign(b"original");
        assert!(verify(&kp.public_bytes(), b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = Keypair::generate().unwrap();
        let other = Keypair::generate().unwrap();
        let sig = signer.sign(b"msg");
        assert!(verify(&other.public_bytes(), b"msg", &sig).is_err());
    }
}
