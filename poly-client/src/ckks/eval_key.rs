//! Evaluation keys for CKKS relinearization.
//!
//! After ciphertext-ciphertext multiplication, the result has 3 components
//! (a "triple"). Relinearization converts it back to 2 components using
//! the evaluation key. The eval key encrypts s^2 in a special form that
//! allows this without revealing the secret key.
//!
//! For each digit d in [0, NUM_DIGITS):
//!   b_d = -(a_d * s + e_d) + s^2 * T^d
//!   a_d = uniform random
//!
//! The evaluation key is public — safe to share with the server.

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::keys::CkksSecretKey;
use super::params::{DECOMP_BASE, NUM_DIGITS};
use super::poly::Poly;
use super::sampling::{sample_gaussian, sample_uniform};

/// CKKS evaluation key for relinearization.
///
/// Contains `NUM_DIGITS` RLWE encryptions of s^2 * T^d.
/// Used by `relinearize()` to convert a ciphertext triple back to a pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CkksEvalKey {
    /// (b_d, a_d) pairs, one per decomposition digit.
    pub keys: Vec<(Poly, Poly)>,
}

/// Generate an evaluation key from the secret key.
///
/// For each digit d: `b_d = -(a_d * s + e_d) + s^2 * T^d`
///
/// This is essentially an RLWE encryption of `s^2 * T^d` under key `s`.
pub fn gen_eval_key<R: Rng>(sk: &CkksSecretKey, rng: &mut R) -> CkksEvalKey {
    let s_squared = sk.s.mul(&sk.s);

    let mut keys = Vec::with_capacity(NUM_DIGITS);
    let mut power_of_t: i64 = 1; // T^d

    for _d in 0..NUM_DIGITS {
        let a_d = sample_uniform(rng);
        let e_d = sample_gaussian(rng);

        // b_d = -(a_d * s + e_d) + s^2 * T^d
        let a_s = a_d.mul(&sk.s);
        let a_s_plus_e = a_s.add(&e_d);
        let neg_a_s_e = a_s_plus_e.neg();
        let s2_scaled = s_squared.scalar_mul(power_of_t);
        let b_d = neg_a_s_e.add(&s2_scaled);

        keys.push((b_d, a_d));

        // T^(d+1) — may overflow for large d, but NUM_DIGITS=3 is safe
        power_of_t = power_of_t.saturating_mul(DECOMP_BASE);
    }

    CkksEvalKey { keys }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::keys::keygen;
    use crate::ckks::params::{DECOMP_BASE, NUM_DIGITS};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn eval_key_has_correct_digit_count() {
        let mut rng = test_rng();
        let (_, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);
        assert_eq!(evk.keys.len(), NUM_DIGITS);
    }

    #[test]
    fn eval_key_decryption_identity() {
        // For each digit d: b_d + a_d * s ≈ s^2 * T^d (up to small noise e_d)
        let mut rng = test_rng();
        let (_, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);
        let s_squared = sk.s.mul(&sk.s);

        let mut power_of_t: i64 = 1;
        for d in 0..NUM_DIGITS {
            let (ref b_d, ref a_d) = evk.keys[d];
            // b_d + a_d * s should ≈ s^2 * T^d
            let a_s = a_d.mul(&sk.s);
            let result = b_d.add(&a_s);
            let expected = s_squared.scalar_mul(power_of_t);

            // Difference should be small (just the noise e_d)
            let diff = result.sub(&expected);
            for &c in &diff.coeffs {
                assert!(
                    c.abs() < 100,
                    "eval key noise too large at digit {}: {}",
                    d,
                    c
                );
            }

            power_of_t = power_of_t.saturating_mul(DECOMP_BASE);
        }
    }

    #[test]
    fn eval_key_serialization_roundtrip() {
        let mut rng = test_rng();
        let (_, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);

        let json = serde_json::to_string(&evk).unwrap();
        let evk2: CkksEvalKey = serde_json::from_str(&json).unwrap();

        assert_eq!(evk.keys.len(), evk2.keys.len());
        for d in 0..NUM_DIGITS {
            assert_eq!(evk.keys[d].0.coeffs, evk2.keys[d].0.coeffs);
            assert_eq!(evk.keys[d].1.coeffs, evk2.keys[d].1.coeffs);
        }
    }
}
