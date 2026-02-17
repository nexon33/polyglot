//! CKKS ciphertext: encrypt and decrypt token ID sequences.
//!
//! A ciphertext is a pair (c0, c1) of polynomials in Z_q[X]/(X^N+1).
//! Encryption: c0 = b·u + e1 + m, c1 = a·u + e2
//! Decryption: m_noisy = c0 + c1·s ≈ m (noise << Δ/2)

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::encoding::{decode, encode};
use super::keys::{CkksPublicKey, CkksSecretKey};
use super::params::N;
use super::poly::Poly;
use super::sampling::{sample_gaussian, sample_ternary};

/// A CKKS ciphertext encoding up to N token IDs.
/// For sequences longer than N, multiple chunks are stored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CkksCiphertext {
    /// Ciphertext polynomial pairs, one per chunk of N tokens.
    pub chunks: Vec<(Poly, Poly)>,
    /// Total number of encoded token IDs across all chunks.
    pub token_count: usize,
}

/// Encrypt a sequence of token IDs under the given public key.
///
/// Tokens are split into chunks of N, each encrypted independently.
/// Empty input produces a ciphertext with zero chunks.
pub fn encrypt<R: Rng>(tokens: &[u32], pk: &CkksPublicKey, rng: &mut R) -> CkksCiphertext {
    if tokens.is_empty() {
        return CkksCiphertext {
            chunks: vec![],
            token_count: 0,
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

    CkksCiphertext {
        chunks,
        token_count: tokens.len(),
    }
}

/// Decrypt a ciphertext using the secret key, recovering token IDs.
///
/// For each chunk: m_noisy = c0 + c1·s, then decode coefficients back to u32.
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
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn encrypt_decrypt_multiple_tokens() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let tokens = vec![100, 200, 300, 400, 500];
        let ct = encrypt(&tokens, &pk, &mut rng);
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
        let decrypted = decrypt(&ct, &sk);
        assert_eq!(decrypted, tokens);
    }

    #[test]
    fn encrypt_decrypt_large_values() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let tokens = vec![u32::MAX, u32::MAX - 1, 0, 1, 50000];
        let ct = encrypt(&tokens, &pk, &mut rng);
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

        let decrypted = decrypt(&ct2, &sk);
        assert_eq!(decrypted, tokens);
    }
}
