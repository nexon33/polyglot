//! Ed25519 node identity.
//!
//! Each node has a persistent Ed25519 keypair. The NodeId is SHA-256(public_key),
//! giving a compact 32-byte identifier that's hard to spoof.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// 32-byte node identifier = SHA-256(Ed25519 public key).
pub type NodeId = [u8; 32];

/// Ed25519 identity for a network node.
pub struct NodeIdentity {
    pub id: NodeId,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl NodeIdentity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let id = compute_node_id(&verifying_key);
        Self {
            id,
            signing_key,
            verifying_key,
        }
    }

    /// Sign arbitrary data with this node's private key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// Compute NodeId from a verifying key: SHA-256(public_key_bytes).
pub fn compute_node_id(vk: &VerifyingKey) -> NodeId {
    let mut hasher = Sha256::new();
    hasher.update(vk.as_bytes());
    hasher.finalize().into()
}

/// Verify an Ed25519 signature against a verifying key.
pub fn verify_signature(vk: &VerifyingKey, data: &[u8], sig_bytes: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_unique_ids() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn sign_and_verify() {
        let identity = NodeIdentity::generate();
        let msg = b"hello poly network";
        let sig = identity.sign(msg);
        assert!(verify_signature(identity.verifying_key(), msg, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let identity = NodeIdentity::generate();
        let sig = identity.sign(b"correct message");
        assert!(!verify_signature(
            identity.verifying_key(),
            b"wrong message",
            &sig
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        let sig = a.sign(b"message");
        assert!(!verify_signature(b.verifying_key(), b"message", &sig));
    }

    #[test]
    fn node_id_is_sha256_of_pubkey() {
        let identity = NodeIdentity::generate();
        let expected = compute_node_id(identity.verifying_key());
        assert_eq!(identity.id, expected);
    }

    #[test]
    fn public_key_bytes_match() {
        let identity = NodeIdentity::generate();
        assert_eq!(
            identity.public_key_bytes(),
            identity.verifying_key().to_bytes()
        );
    }
}
