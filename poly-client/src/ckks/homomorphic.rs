//! Homomorphic operations on CKKS ciphertexts.
//!
//! Phase 1: single-chunk ciphertexts only (panics on multi-chunk).
//! Operations:
//! - Addition/subtraction (noise grows additively — always safe)
//! - Plaintext-ciphertext operations (add, multiply, scalar)
//! - Ciphertext-ciphertext multiplication → triple → relinearize
//!
//! Scale tracking: fresh ciphertexts have scale = DELTA. After ct*ct or
//! ct*plain multiplication, scale becomes DELTA^2. Decryption must use
//! the ciphertext's actual scale. Rescaling (modulus switching) is not
//! implemented in Phase 1 — it requires a modulus chain (Phase 2).
//!
//! With Q = 2^54 and DELTA = 2^20, one level of multiplication is supported
//! (DELTA^2 = 2^40 << Q). Two levels would require DELTA^4 = 2^80 > Q.

use super::ciphertext::CkksCiphertext;
use super::eval_key::CkksEvalKey;
use super::params::DELTA;
use super::poly::Poly;

// ---------------------------------------------------------------------------
// Ciphertext triple (transient — result of ct-ct multiply before relin)
// ---------------------------------------------------------------------------

/// Result of ciphertext-ciphertext multiplication before relinearization.
///
/// Has 3 polynomial components instead of the usual 2.
/// Must be immediately relinearized — not serializable or storable.
pub struct CkksCiphertextTriple {
    pub d0: Poly,
    pub d1: Poly,
    pub d2: Poly,
    pub scale: i64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert single-chunk and return the (c0, c1) pair.
fn single_chunk(ct: &CkksCiphertext) -> &(Poly, Poly) {
    assert_eq!(
        ct.chunks.len(),
        1,
        "homomorphic ops require single-chunk ciphertexts (got {} chunks)",
        ct.chunks.len()
    );
    &ct.chunks[0]
}

/// Assert two ciphertexts have the same scale.
fn assert_same_scale(a: &CkksCiphertext, b: &CkksCiphertext) {
    assert_eq!(
        a.scale, b.scale,
        "scale mismatch: {} vs {}",
        a.scale, b.scale
    );
}

/// Wrap a single (c0, c1) pair into a CkksCiphertext with the given scale.
fn wrap(c0: Poly, c1: Poly, scale: i64) -> CkksCiphertext {
    CkksCiphertext {
        chunks: vec![(c0, c1)],
        token_count: 0, // token_count is meaningless for homomorphic results
        scale,
        auth_tag: None,
        key_id: None,
        nonce: None,
    }
}

// ---------------------------------------------------------------------------
// Addition / Subtraction (noise grows additively — always safe)
// ---------------------------------------------------------------------------

/// Homomorphic addition: encrypt(a) + encrypt(b) → encrypt(a + b).
///
/// Component-wise: (c0a + c0b, c1a + c1b). Both operands must have the same scale.
pub fn ct_add(a: &CkksCiphertext, b: &CkksCiphertext) -> CkksCiphertext {
    assert_same_scale(a, b);
    let (a0, a1) = single_chunk(a);
    let (b0, b1) = single_chunk(b);
    wrap(a0.add(b0), a1.add(b1), a.scale)
}

/// Homomorphic subtraction: encrypt(a) - encrypt(b) → encrypt(a - b).
pub fn ct_sub(a: &CkksCiphertext, b: &CkksCiphertext) -> CkksCiphertext {
    assert_same_scale(a, b);
    let (a0, a1) = single_chunk(a);
    let (b0, b1) = single_chunk(b);
    wrap(a0.sub(b0), a1.sub(b1), a.scale)
}

/// Negate a ciphertext: encrypt(a) → encrypt(-a).
pub fn ct_negate(ct: &CkksCiphertext) -> CkksCiphertext {
    let (c0, c1) = single_chunk(ct);
    wrap(c0.neg(), c1.neg(), ct.scale)
}

// ---------------------------------------------------------------------------
// Plaintext-Ciphertext operations
// ---------------------------------------------------------------------------

/// Add an encoded plaintext to a ciphertext.
///
/// The plaintext must be encoded at the same scale as the ciphertext.
/// For fresh ciphertexts (scale = DELTA), use `encode_f64`.
/// Only modifies c0: (c0 + plain, c1).
pub fn ct_add_plain(ct: &CkksCiphertext, plain: &Poly) -> CkksCiphertext {
    let (c0, c1) = single_chunk(ct);
    wrap(c0.add(plain), c1.clone(), ct.scale)
}

/// Multiply a ciphertext by an encoded plaintext polynomial.
///
/// Multiplies both components: (c0 * plain, c1 * plain).
/// The result scale becomes `ct.scale * DELTA` (since plain is encoded at scale DELTA).
/// For a fresh ciphertext (scale = DELTA), the result has scale = DELTA^2.
pub fn ct_mul_plain(ct: &CkksCiphertext, plain: &Poly) -> CkksCiphertext {
    let (c0, c1) = single_chunk(ct);
    wrap(c0.mul(plain), c1.mul(plain), ct.scale * DELTA)
}

/// Multiply a ciphertext by an integer scalar.
///
/// Unlike `ct_mul_plain`, this does NOT change the scale (no extra DELTA factor).
pub fn ct_scalar_mul(ct: &CkksCiphertext, scalar: i64) -> CkksCiphertext {
    let (c0, c1) = single_chunk(ct);
    wrap(c0.scalar_mul(scalar), c1.scalar_mul(scalar), ct.scale)
}

// ---------------------------------------------------------------------------
// Ciphertext-Ciphertext multiplication
// ---------------------------------------------------------------------------

/// Multiply two ciphertexts, producing a triple.
///
/// d0 = a0 * b0
/// d1 = a0 * b1 + a1 * b0
/// d2 = a1 * b1
///
/// The result scale = a.scale * b.scale (typically DELTA^2 for fresh inputs).
/// Must be followed by `relinearize()`.
pub fn ct_mul(a: &CkksCiphertext, b: &CkksCiphertext) -> CkksCiphertextTriple {
    assert_same_scale(a, b);
    let (a0, a1) = single_chunk(a);
    let (b0, b1) = single_chunk(b);

    let d0 = a0.mul(b0);
    let d1 = a0.mul(b1).add(&a1.mul(b0));
    let d2 = a1.mul(b1);

    CkksCiphertextTriple {
        d0,
        d1,
        d2,
        scale: a.scale * b.scale,
    }
}

// ---------------------------------------------------------------------------
// Relinearization
// ---------------------------------------------------------------------------

/// Relinearize a ciphertext triple back to a 2-component ciphertext.
///
/// Decomposes d2 into base-T digits, then uses the evaluation key:
///   c0' = d0 + sum(digit_d * evk.b_d)
///   c1' = d1 + sum(digit_d * evk.a_d)
pub fn relinearize(triple: CkksCiphertextTriple, evk: &CkksEvalKey) -> CkksCiphertext {
    let digits = triple.d2.decompose_base_t();

    let mut c0 = triple.d0;
    let mut c1 = triple.d1;

    for (d, digit) in digits.iter().enumerate() {
        let (ref b_d, ref a_d) = evk.keys[d];
        c0 = c0.add(&digit.mul(b_d));
        c1 = c1.add(&digit.mul(a_d));
    }

    wrap(c0, c1, triple.scale)
}

// ---------------------------------------------------------------------------
// Convenience: full multiply pipeline
// ---------------------------------------------------------------------------

/// Full ciphertext-ciphertext multiplication: multiply → relinearize.
///
/// The result has scale = a.scale * b.scale (typically DELTA^2).
/// Decode with `decode_f64_with_scale` using the ciphertext's scale.
pub fn ct_mul_relin(
    a: &CkksCiphertext,
    b: &CkksCiphertext,
    evk: &CkksEvalKey,
) -> CkksCiphertext {
    let triple = ct_mul(a, b);
    relinearize(triple, evk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::encoding_f64::{decode_f64_with_scale, encode_f64};
    use crate::ckks::eval_key::gen_eval_key;
    use crate::ckks::keys::keygen;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    /// Encrypt a pre-encoded polynomial directly (single chunk).
    fn encrypt_poly(
        m: &Poly,
        pk: &crate::ckks::keys::CkksPublicKey,
        rng: &mut StdRng,
    ) -> CkksCiphertext {
        use crate::ckks::sampling::{sample_gaussian, sample_ternary};
        let u = sample_ternary(rng);
        let e1 = sample_gaussian(rng);
        let e2 = sample_gaussian(rng);
        let c0 = pk.b.mul(&u).add(&e1).add(m);
        let c1 = pk.a.mul(&u).add(&e2);
        CkksCiphertext {
            chunks: vec![(c0, c1)],
            token_count: 0,
            scale: DELTA,
            auth_tag: None,
            key_id: None,
            nonce: None,
        }
    }

    /// Decrypt a single-chunk ciphertext and decode as f64 using its scale.
    fn decrypt_f64(ct: &CkksCiphertext, sk: &crate::ckks::keys::CkksSecretKey, count: usize) -> Vec<f64> {
        let (c0, c1) = single_chunk(ct);
        let m_noisy = c0.add(&c1.mul(&sk.s));
        decode_f64_with_scale(&m_noisy, count, ct.scale)
    }

    #[test]
    fn add_two_ciphertexts() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let m1 = encode_f64(&[1.0, 2.0, 3.0]);
        let m2 = encode_f64(&[4.0, 5.0, 6.0]);

        let ct1 = encrypt_poly(&m1, &pk, &mut rng);
        let ct2 = encrypt_poly(&m2, &pk, &mut rng);

        let ct_sum = ct_add(&ct1, &ct2);
        let result = decrypt_f64(&ct_sum, &sk, 3);

        assert!((result[0] - 5.0).abs() < 0.01, "expected 5.0, got {}", result[0]);
        assert!((result[1] - 7.0).abs() < 0.01, "expected 7.0, got {}", result[1]);
        assert!((result[2] - 9.0).abs() < 0.01, "expected 9.0, got {}", result[2]);
    }

    #[test]
    fn sub_is_inverse_of_add() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let m1 = encode_f64(&[10.0, -5.0]);
        let m2 = encode_f64(&[3.0, 7.0]);

        let ct1 = encrypt_poly(&m1, &pk, &mut rng);
        let ct2 = encrypt_poly(&m2, &pk, &mut rng);

        let ct_diff = ct_sub(&ct1, &ct2);
        let result = decrypt_f64(&ct_diff, &sk, 2);

        assert!((result[0] - 7.0).abs() < 0.01, "expected 7.0, got {}", result[0]);
        assert!((result[1] - (-12.0)).abs() < 0.01, "expected -12.0, got {}", result[1]);
    }

    #[test]
    fn negate_flips_sign() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let m = encode_f64(&[5.0, -3.0]);
        let ct = encrypt_poly(&m, &pk, &mut rng);

        let ct_neg = ct_negate(&ct);
        let result = decrypt_f64(&ct_neg, &sk, 2);

        assert!((result[0] - (-5.0)).abs() < 0.01, "expected -5.0, got {}", result[0]);
        assert!((result[1] - 3.0).abs() < 0.01, "expected 3.0, got {}", result[1]);
    }

    #[test]
    fn add_plain() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let m = encode_f64(&[2.0, 4.0]);
        let ct = encrypt_poly(&m, &pk, &mut rng);

        let plain = encode_f64(&[10.0, -1.0]);
        let ct_result = ct_add_plain(&ct, &plain);
        let result = decrypt_f64(&ct_result, &sk, 2);

        assert!((result[0] - 12.0).abs() < 0.01, "expected 12.0, got {}", result[0]);
        assert!((result[1] - 3.0).abs() < 0.01, "expected 3.0, got {}", result[1]);
    }

    #[test]
    fn mul_plain_scale_tracking() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        // encrypt(3.0) * encode(2.0) → should decrypt to ~6.0
        let m = encode_f64(&[3.0]);
        let ct = encrypt_poly(&m, &pk, &mut rng);

        let plain = encode_f64(&[2.0]);
        let ct_mul = ct_mul_plain(&ct, &plain);

        // Scale is now DELTA^2 — decrypt_f64 uses ct.scale automatically
        assert_eq!(ct_mul.scale, DELTA * DELTA);
        let result = decrypt_f64(&ct_mul, &sk, 1);

        assert!(
            (result[0] - 6.0).abs() < 0.01,
            "expected ~6.0, got {}",
            result[0]
        );
    }

    #[test]
    fn scalar_mul_no_rescale() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let m = encode_f64(&[5.0, -2.0]);
        let ct = encrypt_poly(&m, &pk, &mut rng);

        let ct_scaled = ct_scalar_mul(&ct, 3);
        assert_eq!(ct_scaled.scale, DELTA); // scale unchanged
        let result = decrypt_f64(&ct_scaled, &sk, 2);

        assert!((result[0] - 15.0).abs() < 0.01, "expected 15.0, got {}", result[0]);
        assert!((result[1] - (-6.0)).abs() < 0.01, "expected -6.0, got {}", result[1]);
    }

    #[test]
    fn ct_ct_multiply_relin() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);

        // encrypt(2.0) * encrypt(3.0) → should decrypt to ~6.0
        let m1 = encode_f64(&[2.0]);
        let m2 = encode_f64(&[3.0]);

        let ct1 = encrypt_poly(&m1, &pk, &mut rng);
        let ct2 = encrypt_poly(&m2, &pk, &mut rng);

        let ct_result = ct_mul_relin(&ct1, &ct2, &evk);
        assert_eq!(ct_result.scale, DELTA * DELTA);

        let result = decrypt_f64(&ct_result, &sk, 1);

        assert!(
            (result[0] - 6.0).abs() < 0.1,
            "expected ~6.0, got {}",
            result[0]
        );
    }

    #[test]
    fn linear_combination() {
        // Compute 3*x + 2*y homomorphically
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let x_val = 5.0;
        let y_val = 7.0;
        let expected = 3.0 * x_val + 2.0 * y_val; // 15 + 14 = 29

        let ct_x = encrypt_poly(&encode_f64(&[x_val]), &pk, &mut rng);
        let ct_y = encrypt_poly(&encode_f64(&[y_val]), &pk, &mut rng);

        let ct_3x = ct_scalar_mul(&ct_x, 3);
        let ct_2y = ct_scalar_mul(&ct_y, 2);
        let ct_result = ct_add(&ct_3x, &ct_2y);

        let result = decrypt_f64(&ct_result, &sk, 1);
        assert!(
            (result[0] - expected).abs() < 0.01,
            "expected {}, got {}",
            expected,
            result[0]
        );
    }

    #[test]
    #[should_panic(expected = "scale mismatch")]
    fn scale_mismatch_panics() {
        let mut rng = test_rng();
        let (pk, _sk) = keygen(&mut rng);

        let m = encode_f64(&[1.0]);
        let ct0 = encrypt_poly(&m, &pk, &mut rng);
        let mut ct1 = encrypt_poly(&m, &pk, &mut rng);
        ct1.scale = DELTA * DELTA; // artificially set different scale

        ct_add(&ct0, &ct1); // should panic
    }

    #[test]
    #[should_panic(expected = "single-chunk")]
    fn multi_chunk_panics() {
        let ct = CkksCiphertext {
            chunks: vec![
                (Poly::zero(), Poly::zero()),
                (Poly::zero(), Poly::zero()),
            ],
            token_count: 0,
            scale: DELTA,
            auth_tag: None,
            key_id: None,
            nonce: None,
        };
        ct_negate(&ct); // should panic
    }

    #[test]
    fn ct_ct_multiply_negative_values() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);

        // (-3.0) * (4.0) = -12.0
        let ct1 = encrypt_poly(&encode_f64(&[-3.0]), &pk, &mut rng);
        let ct2 = encrypt_poly(&encode_f64(&[4.0]), &pk, &mut rng);

        let ct_result = ct_mul_relin(&ct1, &ct2, &evk);
        let result = decrypt_f64(&ct_result, &sk, 1);

        assert!(
            (result[0] - (-12.0)).abs() < 0.2,
            "expected ~-12.0, got {}",
            result[0]
        );
    }

    #[test]
    fn add_then_negate_is_sub() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let ct_a = encrypt_poly(&encode_f64(&[8.0]), &pk, &mut rng);
        let ct_b = encrypt_poly(&encode_f64(&[3.0]), &pk, &mut rng);

        // a + (-b) should equal a - b
        let ct_neg_b = ct_negate(&ct_b);
        let ct_result = ct_add(&ct_a, &ct_neg_b);
        let result = decrypt_f64(&ct_result, &sk, 1);

        assert!(
            (result[0] - 5.0).abs() < 0.01,
            "expected 5.0, got {}",
            result[0]
        );
    }
}
