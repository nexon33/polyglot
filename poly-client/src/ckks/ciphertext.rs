//! CKKS ciphertext: encrypt and decrypt token ID sequences.
//!
//! A ciphertext is a pair (c0, c1) of polynomials in Z_q[X]/(X^N+1).
//! Encryption: c0 = b·u + e1 + m, c1 = a·u + e2
//! Decryption: m_noisy = c0 + c1·s ≈ m (noise << Δ/2)
//!
//! ## Authentication
//!
//! Ciphertexts include an `auth_tag` (SHA-256 over all ciphertext data + metadata),
//! a `key_id` (SHA-256 hash of the encrypting public key), and a random `nonce`
//! for replay protection. Use `verify_integrity()` to check before decrypting.

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::encoding::{decode, encode};
use super::keys::{CkksPublicKey, CkksSecretKey};
use super::params::{DELTA, N};
use super::poly::Poly;
use super::sampling::{sample_gaussian, sample_ternary};

fn default_scale() -> i64 {
    DELTA
}

/// A CKKS ciphertext encoding up to N token IDs.
/// For sequences longer than N, multiple chunks are stored.
///
/// Includes authentication metadata: `auth_tag` for integrity,
/// `key_id` for key binding, and `nonce` for replay protection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CkksCiphertext {
    /// Ciphertext polynomial pairs, one per chunk of N tokens.
    pub chunks: Vec<(Poly, Poly)>,
    /// Total number of encoded token IDs across all chunks.
    pub token_count: usize,
    /// Current scaling factor. Fresh ciphertexts have scale = DELTA.
    /// After ct*ct or ct*plain multiply, scale = DELTA^2.
    /// Decryption divides by this scale to recover the plaintext.
    #[serde(default = "default_scale")]
    pub scale: i64,
    /// SHA-256 authentication tag over ciphertext + metadata.
    /// Detects any tampering with ciphertext coefficients, token_count, or scale.
    #[serde(default)]
    pub auth_tag: Option<[u8; 32]>,
    /// SHA-256 hash of the public key used for encryption.
    /// Allows recipients to verify the ciphertext was encrypted for them.
    #[serde(default)]
    pub key_id: Option<[u8; 32]>,
    /// Random nonce for replay protection.
    /// Included in auth_tag computation to ensure ciphertext uniqueness.
    #[serde(default)]
    pub nonce: Option<[u8; 16]>,
}

/// Compute SHA-256 hash of a public key to create a key identifier.
pub fn compute_key_id(pk: &CkksPublicKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ckks_key_id_v1");
    for c in &pk.a.coeffs {
        hasher.update(c.to_le_bytes());
    }
    for c in &pk.b.coeffs {
        hasher.update(c.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Compute authentication tag over ciphertext data + metadata.
fn compute_auth_tag(
    chunks: &[(Poly, Poly)],
    token_count: usize,
    scale: i64,
    nonce: &[u8; 16],
    key_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ckks_auth_v1");
    hasher.update(key_id);
    hasher.update(nonce);
    hasher.update((token_count as u64).to_le_bytes());
    hasher.update(scale.to_le_bytes());
    for (c0, c1) in chunks {
        for c in &c0.coeffs {
            hasher.update(c.to_le_bytes());
        }
        for c in &c1.coeffs {
            hasher.update(c.to_le_bytes());
        }
    }
    hasher.finalize().into()
}

impl CkksCiphertext {
    /// Verify the integrity and authenticity of this ciphertext.
    ///
    /// Returns `true` if all authentication checks pass:
    /// - `auth_tag` matches recomputed tag over ciphertext + metadata
    /// - `key_id` matches the provided public key
    ///
    /// Returns `false` if any check fails (tampering detected) or if
    /// authentication fields are missing (unauthenticated ciphertext).
    pub fn verify_integrity(&self, pk: &CkksPublicKey) -> bool {
        let (Some(auth_tag), Some(key_id), Some(nonce)) =
            (self.auth_tag, self.key_id, self.nonce)
        else {
            return false; // unauthenticated ciphertext
        };

        // Check key binding
        let expected_key_id = compute_key_id(pk);
        if key_id != expected_key_id {
            return false;
        }

        // Check integrity
        let expected_tag = compute_auth_tag(&self.chunks, self.token_count, self.scale, &nonce, &key_id);
        auth_tag == expected_tag
    }
}

/// Encrypt a sequence of token IDs under the given public key.
///
/// Tokens are split into chunks of N, each encrypted independently.
/// Empty input produces a ciphertext with zero chunks.
///
/// The ciphertext includes authentication metadata: `auth_tag` for
/// integrity verification, `key_id` for key binding, and a random
/// `nonce` for replay protection.
pub fn encrypt<R: Rng>(tokens: &[u32], pk: &CkksPublicKey, rng: &mut R) -> CkksCiphertext {
    let key_id = compute_key_id(pk);
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);

    if tokens.is_empty() {
        let auth_tag = compute_auth_tag(&[], 0, DELTA, &nonce, &key_id);
        return CkksCiphertext {
            chunks: vec![],
            token_count: 0,
            scale: DELTA,
            auth_tag: Some(auth_tag),
            key_id: Some(key_id),
            nonce: Some(nonce),
        };
    }

    let mut chunks = Vec::new();
    for chunk in tokens.chunks(N) {
        let m = encode(chunk);

        // Ephemeral secret + errors
        let u = sample_ternary(rng);
        let e1 = sample_gaussian(rng);
        let e2 = sample_gaussian(rng);

        // c0 = b·u + e1 + m
        let bu = pk.b.mul(&u);
        let c0 = bu.add(&e1).add(&m);

        // c1 = a·u + e2
        let au = pk.a.mul(&u);
        let c1 = au.add(&e2);

        chunks.push((c0, c1));
    }

    let token_count = tokens.len();
    let auth_tag = compute_auth_tag(&chunks, token_count, DELTA, &nonce, &key_id);

    CkksCiphertext {
        chunks,
        token_count,
        scale: DELTA,
        auth_tag: Some(auth_tag),
        key_id: Some(key_id),
        nonce: Some(nonce),
    }
}

/// Decrypt a ciphertext using the secret key, recovering token IDs.
///
/// For each chunk: m_noisy = c0 + c1·s, then decode coefficients back to u32.
///
/// **Note:** Call `verify_integrity()` before decrypting to detect tampering.
/// This function does not verify the authentication tag — it only decrypts
/// the ciphertext data as-is.
pub fn decrypt(ct: &CkksCiphertext, sk: &CkksSecretKey) -> Vec<u32> {
    if ct.token_count == 0 {
        return vec![];
    }

    let mut all_tokens = Vec::with_capacity(ct.token_count);
    let mut remaining = ct.token_count;

    for (c0, c1) in &ct.chunks {
        let cs = c1.mul(&sk.s);
        let m_noisy = c0.add(&cs);

        let chunk_size = remaining.min(N);
        let decoded = decode(&m_noisy, chunk_size);
        all_tokens.extend_from_slice(&decoded);
        remaining -= chunk_size;
    }

    all_tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::keys::keygen;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn encrypt_decrypt_single_token() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let tokens = vec![42];
        let ct = encrypt(&tokens, &pk, &mut rng);
        assert!(ct.verify_integrity(&pk));
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn encrypt_decrypt_multiple_tokens() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let tokens = vec![100, 200, 300, 400, 500];
        let ct = encrypt(&tokens, &pk, &mut rng);
        assert!(ct.verify_integrity(&pk));
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn encrypt_decrypt_max_chunk() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        // Exactly N tokens = one full chunk
        let tokens: Vec<u32> = (0..N as u32).collect();
        let ct = encrypt(&tokens, &pk, &mut rng);
        assert_eq!(ct.chunks.len(), 1);
        assert!(ct.verify_integrity(&pk));
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn encrypt_decrypt_multi_chunk() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        // N+5 tokens = 2 chunks
        let tokens: Vec<u32> = (0..(N as u32 + 5)).collect();
        let ct = encrypt(&tokens, &pk, &mut rng);
        assert_eq!(ct.chunks.len(), 2);
        assert!(ct.verify_integrity(&pk));
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn encrypt_decrypt_empty() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let tokens: Vec<u32> = vec![];
        let ct = encrypt(&tokens, &pk, &mut rng);
        assert_eq!(ct.chunks.len(), 0);
        assert!(ct.verify_integrity(&pk));
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn encrypt_decrypt_large_values() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let tokens = vec![u32::MAX, u32::MAX - 1, 0, 1, 50000];
        let ct = encrypt(&tokens, &pk, &mut rng);
        assert!(ct.verify_integrity(&pk));
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn ciphertext_serialization_roundtrip() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let tokens = vec![10, 20, 30];
        let ct = encrypt(&tokens, &pk, &mut rng);

        let json = serde_json::to_string(&ct).unwrap();
        let ct2: CkksCiphertext = serde_json::from_str(&json).unwrap();

        assert!(ct2.verify_integrity(&pk));
        let decrypted = decrypt(&ct2, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn auth_tag_present_after_encrypt() {
        let mut rng = test_rng();
        let (pk, _sk) = keygen(&mut rng);
        let ct = encrypt(&[1, 2, 3], &pk, &mut rng);
        assert!(ct.auth_tag.is_some());
        assert!(ct.key_id.is_some());
        assert!(ct.nonce.is_some());
    }

    #[test]
    fn verify_integrity_detects_token_count_tampering() {
        let mut rng = test_rng();
        let (pk, _sk) = keygen(&mut rng);
        let mut ct = encrypt(&[100, 200, 300], &pk, &mut rng);
        assert!(ct.verify_integrity(&pk));

        ct.token_count = 2;
        assert!(!ct.verify_integrity(&pk));
    }

    #[test]
    fn verify_integrity_detects_coefficient_tampering() {
        let mut rng = test_rng();
        let (pk, _sk) = keygen(&mut rng);
        let mut ct = encrypt(&[100, 200, 300], &pk, &mut rng);
        assert!(ct.verify_integrity(&pk));

        ct.chunks[0].0.coeffs[0] ^= 1;
        assert!(!ct.verify_integrity(&pk));
    }

    #[test]
    fn verify_integrity_detects_wrong_key() {
        let mut rng1 = StdRng::seed_from_u64(1);
        let mut rng2 = StdRng::seed_from_u64(2);
        let (pk1, _sk1) = keygen(&mut rng1);
        let (pk2, _sk2) = keygen(&mut rng2);

        let ct = encrypt(&[42], &pk1, &mut rng1);
        assert!(ct.verify_integrity(&pk1));
        assert!(!ct.verify_integrity(&pk2));
    }
}
