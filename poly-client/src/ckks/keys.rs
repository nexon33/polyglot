//! CKKS key generation based on Ring-LWE.
//!
//! The public key is an RLWE instance (b, a) where b = -(a·s + e).
//! Security relies on the hardness of distinguishing (b, a) from uniform.

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::poly::Poly;
use super::sampling::{sample_gaussian, sample_ternary, sample_uniform};

/// CKKS public encryption key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CkksPublicKey {
    /// b = -(a·s + e) mod q
    pub b: Poly,
    /// Uniform random polynomial
    pub a: Poly,
}

/// CKKS secret decryption key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CkksSecretKey {
    /// Ternary secret polynomial
    pub s: Poly,
}

/// Generate a fresh CKKS key pair.
///
/// 1. s ← ternary distribution (secret key)
/// 2. a ← uniform over Z_q
/// 3. e ← discrete Gaussian (small error)
/// 4. b = -(a·s + e) mod q
///
/// The RLWE instance (b, a) is indistinguishable from uniform
/// under the Ring-LWE assumption.
pub fn keygen<R: Rng>(rng: &mut R) -> (CkksPublicKey, CkksSecretKey) {
    let s = sample_ternary(rng);
    let a = sample_uniform(rng);
    let e = sample_gaussian(rng);

    // b = -(a·s + e)
    let as_prod = a.mul(&s);
    let as_plus_e = as_prod.add(&e);
    let b = as_plus_e.neg();

    (CkksPublicKey { b, a }, CkksSecretKey { s })
}

/// Derive a MAC key from the secret key using HKDF-SHA256.
///
/// Uses proper HKDF extract-then-expand (not bare SHA-256) to provide
/// domain separation via the `context` parameter. Different contexts
/// (e.g., different server identities) produce different MAC keys from
/// the same secret key, preventing cross-context replay attacks.
pub fn derive_mac_key(sk: &CkksSecretKey) -> [u8; 32] {
    derive_mac_key_with_context(sk, b"default")
}

/// Derive a MAC key with a specific context string.
pub fn derive_mac_key_with_context(sk: &CkksSecretKey, context: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let ikm: Vec<u8> = sk.s.coeffs.iter()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let hk = Hkdf::<Sha256>::new(Some(context), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"ckks_mac_key_v1", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::params::N;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn keygen_produces_correct_dimensions() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        assert_eq!(pk.a.coeffs.len(), N);
        assert_eq!(pk.b.coeffs.len(), N);
        assert_eq!(sk.s.coeffs.len(), N);
    }

    #[test]
    fn secret_key_is_ternary() {
        let mut rng = test_rng();
        let (_, sk) = keygen(&mut rng);
        for &c in &sk.s.coeffs {
            assert!(c >= -1 && c <= 1);
        }
    }

    #[test]
    fn rlwe_instance_small_error() {
        // b + a·s should equal -e (small)
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let as_prod = pk.a.mul(&sk.s);
        let b_plus_as = pk.b.add(&as_prod);
        // b + a·s = -e, so all coefficients should be small (|e| < 50 for σ=3.2)
        for &c in &b_plus_as.coeffs {
            assert!(
                c.abs() < 100,
                "RLWE error too large: {} (expected small)",
                c
            );
        }
    }
}
