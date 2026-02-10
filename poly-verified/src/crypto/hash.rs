use sha2::{Digest, Sha256};

use crate::types::Hash;

/// SHA-256 of arbitrary input bytes.
pub fn hash_data(input: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Domain-separated interior node hash: SHA-256(0x03 || left || right).
/// Used for Merkle tree interior nodes only.
pub fn hash_combine(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x03]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Domain-separated leaf hash: SHA-256(0x00 || data).
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Domain-separated transition hash: SHA-256(0x01 || prev || input || claimed).
/// Input is 97 bytes total.
pub fn hash_transition(prev: &Hash, input: &Hash, claimed: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(prev);
    hasher.update(input);
    hasher.update(claimed);
    hasher.finalize().into()
}

/// Domain-separated hash chain step: SHA-256(0x02 || tip || state_hash).
/// Input is 65 bytes total.
pub fn hash_chain_step(tip: &Hash, state_hash: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x02]);
    hasher.update(tip);
    hasher.update(state_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Appendix B.1: hash_data test vectors
    #[test]
    fn test_hash_data_empty() {
        let result = hash_data(&[]);
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hash_data_0x00() {
        let result = hash_data(&[0x00]);
        let expected =
            hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hash_data_0x01() {
        let result = hash_data(&[0x01]);
        let expected =
            hex::decode("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hash_data_multi_byte() {
        let result = hash_data(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        let expected =
            hex::decode("74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // Appendix B.2: hash_combine test vectors
    #[test]
    fn test_hash_combine_zeros() {
        let left = [0u8; 32];
        let right = [0u8; 32];
        let result = hash_combine(&left, &right);
        // SHA256(0x03 || [0x00; 64])
        let expected =
            hex::decode("dc48a742ae32cfd66352372d6120ed14d6629fc166246b05ff8b03e23804701f")
                .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hash_combine_different_values() {
        let left = [0x01u8; 32];
        let right = [0x02u8; 32];
        // SHA256([0x01;32] || [0x02;32]) — verify it's deterministic
        let result = hash_combine(&left, &right);
        assert_ne!(result, [0u8; 32]); // not zero
        // Verify commutative property does NOT hold
        let result2 = hash_combine(&right, &left);
        assert_ne!(result, result2);
    }

    // Domain separation: different contexts must produce different hashes
    #[test]
    fn test_domain_separation() {
        let data = [0xAB; 32];
        let h1 = hash_data(&data);
        let h2 = hash_leaf(&data);
        assert_ne!(h1, h2, "hash_data and hash_leaf must differ for same input");
    }

    #[test]
    fn test_domain_separation_combine_vs_data() {
        // hash_combine uses 0x03 prefix, so SHA256(0x03 || left || right)
        // must differ from SHA256(left || right) (which is hash_data on 64 bytes)
        let left = [0x00u8; 32];
        let right = [0x00u8; 32];
        let combined = hash_combine(&left, &right);
        let mut raw_input = [0u8; 64];
        raw_input[..32].copy_from_slice(&left);
        raw_input[32..].copy_from_slice(&right);
        let raw = hash_data(&raw_input);
        assert_ne!(
            combined, raw,
            "hash_combine must differ from hash_data on same 64-byte input"
        );
    }
}
