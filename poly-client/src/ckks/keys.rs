//! CKKS key generation based on Ring-LWE.
//!
//! The public key is an RLWE instance (b, a) where b = -(a·s + e).
//! Security relies on the hardness of distinguishing (b, a) from uniform.

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::params::{N, Q};
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

impl CkksPublicKey {
    /// [R44-01] Reject degenerate / low-norm public keys.
    ///
    /// CKKS encryption masks the plaintext with the ephemeral products `a·u`
    /// and `b·u` (`c0 = b·u + e1 + m`, `c1 = a·u + e2`). If `a` or `b` is the
    /// zero polynomial — or, more generally, a low-norm one — that masking
    /// term collapses and the "ciphertext" carries the plaintext essentially
    /// in the clear (with `b ≈ 0`, `c0 ≈ m + e1`, which `decode` recovers
    /// without any secret key).
    ///
    /// A genuine public key has `a` sampled uniformly over centered `Z_q` and
    /// `b = -(a·s + e)`, so both polynomials have ~`N/2` coefficients of
    /// magnitude above `Q/4`. This check requires at least `N/4` such
    /// coefficients in each: for a real key the count is Binomial(N, 1/2),
    /// mean `N/2` with std `≈ 32`, so the `N/4` floor sits ~32σ below the
    /// mean — a real key never fails, while any zero or low-norm key (the
    /// degenerate keys an attacker would substitute to strip encryption) is
    /// rejected.
    pub fn is_well_formed(&self) -> bool {
        const HIGH_NORM: u64 = (Q as u64) / 4;
        let min_high = N / 4;
        let high_norm_count = |p: &Poly| {
            p.coeffs
                .iter()
                .filter(|&&c| c.unsigned_abs() > HIGH_NORM)
                .count()
        };
        high_norm_count(&self.a) >= min_high && high_norm_count(&self.b) >= min_high
    }
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

/// Check whether `sk` is the secret key corresponding to `pk`.
///
/// For an RLWE keypair `pk.b = -(a·s + e)`, so `pk.b + pk.a·s = -e`, which has
/// only small (Gaussian-error-sized) coefficients. A non-matching secret key
/// instead yields large, uniform-looking coefficients.
///
/// [R31] `encrypt` uses this to decide whether it may emit a self-verifiable
/// `auth_tag`. The tag is an HMAC keyed by `derive_mac_key(sk)`, so only the
/// holder of `sk` can verify it — i.e. it is meaningful only for
/// *self-encryption* (encrypting under one's own public key). A party
/// encrypting *for another recipient* cannot produce a tag that recipient can
/// verify, so `encrypt` emits `auth_tag: None` in that case rather than a
/// bogus tag that would make the recipient's `decrypt` MAC check fail.
pub fn secret_matches_public(pk: &CkksPublicKey, sk: &CkksSecretKey) -> bool {
    // residual = b + a·s — equals -e (small) for the matching secret key.
    let residual = pk.b.add(&pk.a.mul(&sk.s));
    // The Gaussian error keeps |coeff| well under ~100; a mismatching key
    // produces coefficients orders of magnitude larger. 100_000 cleanly
    // separates the two cases.
    const ERROR_BOUND: u64 = 100_000;
    // [R44-01] An all-zero residual is NOT a match. A genuine keypair has
    // residual = -e for a discrete Gaussian `e`, which is all-zero only with
    // negligible probability (2^-N). A degenerate public key such as
    // `(a, b) = (0, 0)` instead produces an exactly-zero residual against
    // *any* secret key — without this guard such a key is misclassified as a
    // self-encryption, causing `encrypt` to emit an `auth_tag` keyed by the
    // wrong secret (a cross-party MAC the recipient cannot verify, breaking
    // the R31 invariant).
    residual.coeffs.iter().any(|&c| c != 0)
        && residual.coeffs.iter().all(|&c| c.unsigned_abs() < ERROR_BOUND)
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
