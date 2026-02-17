//! Integration tests for CKKS homomorphic operations.
//!
//! Tests the full pipeline: keygen → encrypt → homomorphic ops → decrypt → verify.

#![cfg(feature = "ckks")]

use poly_client::ckks::encoding_f64::{decode_f64_with_scale, encode_f64};
use poly_client::ckks::eval_key::gen_eval_key;
use poly_client::ckks::homomorphic::*;
use poly_client::ckks::keys::keygen;
use poly_client::ckks::params::DELTA;
use poly_client::ckks::poly::Poly;
use poly_client::ckks::sampling::{sample_gaussian, sample_ternary};
use poly_client::ckks::CkksCiphertext;

use rand::rngs::StdRng;
use rand::SeedableRng;

fn test_rng() -> StdRng {
    StdRng::seed_from_u64(12345)
}

/// Encrypt a pre-encoded polynomial.
fn encrypt_poly(
    m: &Poly,
    pk: &poly_client::ckks::CkksPublicKey,
    rng: &mut StdRng,
) -> CkksCiphertext {
    let u = sample_ternary(rng);
    let e1 = sample_gaussian(rng);
    let e2 = sample_gaussian(rng);
    let c0 = pk.b.mul(&u).add(&e1).add(m);
    let c1 = pk.a.mul(&u).add(&e2);
    CkksCiphertext {
        chunks: vec![(c0, c1)],
        token_count: 0,
        scale: DELTA,
    }
}

/// Decrypt and decode as f64 using the ciphertext's scale.
fn decrypt_f64(
    ct: &CkksCiphertext,
    sk: &poly_client::ckks::CkksSecretKey,
    count: usize,
) -> Vec<f64> {
    let (c0, c1) = &ct.chunks[0];
    let m_noisy = c0.add(&c1.mul(&sk.s));
    decode_f64_with_scale(&m_noisy, count, ct.scale)
}

// ---------------------------------------------------------------------------
// Full pipeline tests
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_add() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let vals_a = vec![1.5, 2.5, 3.5, 4.5, 5.5];
    let vals_b = vec![0.5, 1.0, 1.5, 2.0, 2.5];

    let ct_a = encrypt_poly(&encode_f64(&vals_a), &pk, &mut rng);
    let ct_b = encrypt_poly(&encode_f64(&vals_b), &pk, &mut rng);

    let ct_sum = ct_add(&ct_a, &ct_b);
    let result = decrypt_f64(&ct_sum, &sk, 5);

    let expected = vec![2.0, 3.5, 5.0, 6.5, 8.0];
    for (i, (r, e)) in result.iter().zip(expected.iter()).enumerate() {
        assert!(
            (r - e).abs() < 0.01,
            "slot {}: expected {}, got {}",
            i, e, r
        );
    }
}

#[test]
fn full_pipeline_sub() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let ct_a = encrypt_poly(&encode_f64(&[10.0, 20.0, 30.0]), &pk, &mut rng);
    let ct_b = encrypt_poly(&encode_f64(&[3.0, 7.0, 15.0]), &pk, &mut rng);

    let ct_diff = ct_sub(&ct_a, &ct_b);
    let result = decrypt_f64(&ct_diff, &sk, 3);

    let expected = vec![7.0, 13.0, 15.0];
    for (i, (r, e)) in result.iter().zip(expected.iter()).enumerate() {
        assert!(
            (r - e).abs() < 0.01,
            "slot {}: expected {}, got {}",
            i, e, r
        );
    }
}

#[test]
fn full_pipeline_ct_ct_multiply() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let evk = gen_eval_key(&sk, &mut rng);

    // encrypt(5.0) * encrypt(7.0) = 35.0
    let ct_a = encrypt_poly(&encode_f64(&[5.0]), &pk, &mut rng);
    let ct_b = encrypt_poly(&encode_f64(&[7.0]), &pk, &mut rng);

    let ct_prod = ct_mul_relin(&ct_a, &ct_b, &evk);
    assert_eq!(ct_prod.scale, DELTA * DELTA);

    let result = decrypt_f64(&ct_prod, &sk, 1);

    assert!(
        (result[0] - 35.0).abs() < 0.5,
        "expected ~35.0, got {}",
        result[0]
    );
}

#[test]
fn polynomial_evaluation_quadratic() {
    // Evaluate f(x) = 2x^2 + 3x + 1 at x = 4.0
    // Expected: 2*16 + 3*4 + 1 = 45
    //
    // Strategy: compute x^2 (scale DELTA^2), then do all additions at scale DELTA^2.
    // - 2*x^2 via scalar_mul (scale stays DELTA^2)
    // - 3*x via scalar_mul (scale DELTA), then mul_plain by encode(1.0) to get DELTA^2
    // - constant 1.0: encrypt, then mul_plain by encode(1.0) to get DELTA^2
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let evk = gen_eval_key(&sk, &mut rng);

    let x = 4.0;
    let ct_x = encrypt_poly(&encode_f64(&[x]), &pk, &mut rng);

    // x^2 via ct-ct multiply (scale becomes DELTA^2)
    let ct_x2 = ct_mul_relin(&ct_x, &ct_x, &evk);

    // 2*x^2 (scalar multiply — scale stays DELTA^2)
    let ct_2x2 = ct_scalar_mul(&ct_x2, 2);

    // 3*x (scalar multiply — scale stays DELTA)
    let ct_3x = ct_scalar_mul(&ct_x, 3);

    // Bring 3*x to scale DELTA^2 by multiplying with encode(1.0)
    let one_plain = encode_f64(&[1.0]);
    let ct_3x_scaled = ct_mul_plain(&ct_3x, &one_plain);

    // constant 1.0 at scale DELTA^2
    let ct_one = encrypt_poly(&encode_f64(&[1.0]), &pk, &mut rng);
    let ct_one_scaled = ct_mul_plain(&ct_one, &one_plain);

    // 2x^2 + 3x + 1 (all at scale DELTA^2)
    let ct_sum1 = ct_add(&ct_2x2, &ct_3x_scaled);
    let ct_result = ct_add(&ct_sum1, &ct_one_scaled);

    let result = decrypt_f64(&ct_result, &sk, 1);
    assert!(
        (result[0] - 45.0).abs() < 1.0,
        "expected ~45.0, got {}",
        result[0]
    );
}

#[test]
fn noise_growth_tracking() {
    // After multiple additions, noise should still be manageable
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let val = 1.0;
    let ct0 = encrypt_poly(&encode_f64(&[val]), &pk, &mut rng);

    // Sum 10 ciphertexts of 1.0 → should get ~10.0
    let mut ct_sum = ct0;
    for _ in 1..10 {
        let ct_next = encrypt_poly(&encode_f64(&[val]), &pk, &mut rng);
        ct_sum = ct_add(&ct_sum, &ct_next);
    }

    let result = decrypt_f64(&ct_sum, &sk, 1);
    assert!(
        (result[0] - 10.0).abs() < 0.1,
        "expected ~10.0 after 10 additions, got {}",
        result[0]
    );
}

#[test]
fn mixed_operations() {
    // Compute: 3*(a + b) - 2*c where a=2, b=3, c=1
    // Expected: 3*5 - 2*1 = 13
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let ct_a = encrypt_poly(&encode_f64(&[2.0]), &pk, &mut rng);
    let ct_b = encrypt_poly(&encode_f64(&[3.0]), &pk, &mut rng);
    let ct_c = encrypt_poly(&encode_f64(&[1.0]), &pk, &mut rng);

    let ct_sum = ct_add(&ct_a, &ct_b);        // a + b = 5
    let ct_3sum = ct_scalar_mul(&ct_sum, 3);   // 3*(a+b) = 15
    let ct_2c = ct_scalar_mul(&ct_c, 2);       // 2*c = 2
    let ct_result = ct_sub(&ct_3sum, &ct_2c);  // 15 - 2 = 13

    let result = decrypt_f64(&ct_result, &sk, 1);
    assert!(
        (result[0] - 13.0).abs() < 0.01,
        "expected 13.0, got {}",
        result[0]
    );
}
