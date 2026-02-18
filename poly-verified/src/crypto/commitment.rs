use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::crypto::chain::HashChain;
use crate::error::{ProofSystemError, Result};
use crate::crypto::merkle::MerkleTree;
use crate::types::{hash_eq, Commitment, Hash, SignedCommitment};

/// Build a Commitment from an ordered sequence of checkpoint hashes.
///
/// Constructs both a Merkle tree and a hash chain from the same sequence,
/// then packages them into a Commitment.
pub fn create_commitment(
    checkpoints: &[Hash],
    code_hash: &Hash,
) -> (Commitment, MerkleTree) {
    let tree = MerkleTree::build(checkpoints);

    let mut chain = HashChain::new();
    for cp in checkpoints {
        chain.append(cp);
    }

    let commitment = Commitment {
        root: tree.root,
        total_checkpoints: checkpoints.len() as u64,
        chain_tip: chain.tip,
        code_hash: *code_hash,
    };

    (commitment, tree)
}

/// Sign a Commitment with Ed25519, producing a SignedCommitment.
pub fn sign_commitment(
    commitment: &Commitment,
    signing_key: &SigningKey,
) -> SignedCommitment {
    let message = commitment.to_bytes();
    let signature = signing_key.sign(&message);
    let public_key = signing_key.verifying_key();

    SignedCommitment {
        commitment: commitment.clone(),
        signature: signature.to_bytes(),
        public_key: public_key.to_bytes(),
    }
}

/// Verify that a commitment's chain_tip matches the given checkpoints.
///
/// This ensures the checkpoint ordering in the commitment is consistent
/// with the provided sequence. Use during full verification when all
/// checkpoints are available.
pub fn verify_chain_tip(commitment: &Commitment, checkpoints: &[Hash]) -> bool {
    let mut chain = HashChain::new();
    for cp in checkpoints {
        chain.append(cp);
    }
    hash_eq(&chain.tip, &commitment.chain_tip)
}

/// Verify a SignedCommitment's Ed25519 signature.
pub fn verify_signed_commitment(sc: &SignedCommitment) -> Result<()> {
    let message = sc.commitment.to_bytes();
    let verifying_key = VerifyingKey::from_bytes(&sc.public_key)
        .map_err(|_| ProofSystemError::SignatureVerificationFailed)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sc.signature);
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| ProofSystemError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::hash_data;
    use crate::types::ZERO_HASH;

    // Appendix B.5: Commitment canonical encoding
    #[test]
    fn test_commitment_encoding() {
        let commitment = Commitment {
            root: [0xAB; 32],
            total_checkpoints: 100,
            chain_tip: [0xCD; 32],
            code_hash: [0xEF; 32],
        };

        let bytes = commitment.to_bytes();
        assert_eq!(bytes.len(), 104);

        // root: 32 bytes of 0xAB
        assert_eq!(&bytes[0..32], &[0xAB; 32]);
        // total_checkpoints: 100 as u64 LE = 0x6400000000000000
        assert_eq!(&bytes[32..40], &[0x64, 0, 0, 0, 0, 0, 0, 0]);
        // chain_tip: 32 bytes of 0xCD
        assert_eq!(&bytes[40..72], &[0xCD; 32]);
        // code_hash: 32 bytes of 0xEF
        assert_eq!(&bytes[72..104], &[0xEF; 32]);
    }

    #[test]
    fn test_commitment_roundtrip() {
        let original = Commitment {
            root: [0xAB; 32],
            total_checkpoints: 100,
            chain_tip: [0xCD; 32],
            code_hash: [0xEF; 32],
        };

        let decoded = Commitment::from_bytes(&original.to_bytes()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_create_commitment_4_checkpoints() {
        let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
        let code_hash = hash_data(b"test_code");

        let (commitment, tree) = create_commitment(&checkpoints, &code_hash);

        assert_eq!(commitment.total_checkpoints, 4);
        assert_eq!(commitment.root, tree.root);
        assert_eq!(commitment.code_hash, code_hash);
        assert_ne!(commitment.chain_tip, ZERO_HASH);
    }

    #[test]
    fn test_sign_and_verify() {
        let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
        let code_hash = hash_data(b"test_code");
        let (commitment, _) = create_commitment(&checkpoints, &code_hash);

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let signed = sign_commitment(&commitment, &signing_key);

        assert!(verify_signed_commitment(&signed).is_ok());
    }

    #[test]
    fn test_wrong_key_fails() {
        let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
        let code_hash = hash_data(b"test_code");
        let (commitment, _) = create_commitment(&checkpoints, &code_hash);

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let mut signed = sign_commitment(&commitment, &signing_key);

        // Swap in a different public key
        let wrong_key = SigningKey::from_bytes(&[0x43; 32]);
        signed.public_key = wrong_key.verifying_key().to_bytes();

        assert!(verify_signed_commitment(&signed).is_err());
    }

    #[test]
    fn test_signed_commitment_serialization() {
        let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
        let code_hash = hash_data(b"test_code");
        let (commitment, _) = create_commitment(&checkpoints, &code_hash);

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let signed = sign_commitment(&commitment, &signing_key);

        let bytes = signed.to_bytes();
        assert_eq!(bytes.len(), 200);

        let decoded = SignedCommitment::from_bytes(&bytes).unwrap();
        assert!(verify_signed_commitment(&decoded).is_ok());
    }

    #[test]
    fn test_verify_chain_tip_correct() {
        let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
        let code_hash = hash_data(b"test_code");
        let (commitment, _) = create_commitment(&checkpoints, &code_hash);

        assert!(verify_chain_tip(&commitment, &checkpoints));
    }

    #[test]
    fn test_verify_chain_tip_wrong_order() {
        let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
        let code_hash = hash_data(b"test_code");
        let (commitment, _) = create_commitment(&checkpoints, &code_hash);

        // Reverse the checkpoints — chain_tip should NOT match
        let mut reversed = checkpoints.clone();
        reversed.reverse();
        assert!(!verify_chain_tip(&commitment, &reversed));
    }

    #[test]
    fn test_verify_chain_tip_tampered() {
        let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
        let code_hash = hash_data(b"test_code");
        let (mut commitment, _) = create_commitment(&checkpoints, &code_hash);

        // Tamper with chain_tip
        commitment.chain_tip[0] ^= 0xFF;
        assert!(!verify_chain_tip(&commitment, &checkpoints));
    }
}
