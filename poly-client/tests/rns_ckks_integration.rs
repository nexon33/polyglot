//! Integration tests and benchmarks for the RNS-CKKS multi-level system.
//!
//! Tests deeper circuits (impossible with Phase 1), benchmarks NTT vs naive
//! polynomial multiply, and exercises the full encrypt→compute→rescale→decrypt pipeline.

use poly_client::ckks::ntt::{NttContext, NTT_PRIMES};
use poly_client::ckks::params::N;
use poly_client::ckks::rns::RnsPoly;
use poly_client::ckks::rns_ckks::*;
use poly_client::ckks::simd::NUM_SLOTS;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Instant;

fn test_rng() -> StdRng {
    StdRng::seed_from_u64(12345)
}

// ═══════════════════════════════════════════════════════════════════════
// Benchmark: NTT vs Naive polynomial multiplication
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn benchmark_ntt_vs_naive() {
    let q = NTT_PRIMES[0];
    let ctx = NttContext::new(q);

    // Create two random polynomials
    let mut rng = test_rng();
    let a: Vec<i64> = (0..N).map(|_| rand::Rng::gen_range(&mut rng, 0..q)).collect();
    let b: Vec<i64> = (0..N).map(|_| rand::Rng::gen_range(&mut rng, 0..q)).collect();

    // Naive: O(N²) negacyclic convolution
    let naive_start = Instant::now();
    let mut naive_result = vec![0i64; N];
    for i in 0..N {
        for j in 0..N {
            let idx = i + j;
            let prod = (a[i] as i128 * b[j] as i128) % q as i128;
            if idx < N {
                naive_result[idx] = ((naive_result[idx] as i128 + prod) % q as i128) as i64;
            } else {
                // Negacyclic: X^N = -1
                let wrap_idx = idx - N;
                naive_result[wrap_idx] =
                    ((naive_result[wrap_idx] as i128 - prod + q as i128 * 2) % q as i128) as i64;
            }
        }
    }
    let naive_time = naive_start.elapsed();

    // NTT: O(N log N)
    let ntt_start = Instant::now();
    let ntt_result = ctx.mul(&a, &b);
    let ntt_time = ntt_start.elapsed();

    // Verify results match
    for i in 0..N {
        assert_eq!(
            naive_result[i] % q,
            ntt_result[i] % q,
            "mismatch at coefficient {}",
            i
        );
    }

    let speedup = naive_time.as_micros() as f64 / ntt_time.as_micros().max(1) as f64;
    println!("\n=== NTT vs Naive Benchmark (N={}) ===", N);
    println!("  Naive O(N²):   {:>8.1} ms", naive_time.as_secs_f64() * 1000.0);
    println!("  NTT O(NlogN):  {:>8.1} ms", ntt_time.as_secs_f64() * 1000.0);
    println!("  Speedup:       {:>8.1}x", speedup);
    println!();

    // NTT should be significantly faster
    assert!(
        ntt_time < naive_time,
        "NTT ({:?}) should be faster than naive ({:?})",
        ntt_time,
        naive_time
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Deep circuit: polynomial evaluation f(x) = x^4 + 2x^2 + 1 = (x^2+1)^2
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn polynomial_evaluation_depth_2() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3); // 2 levels
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

    let x = 1.5f64;
    let expected = x.powi(4) + 2.0 * x.powi(2) + 1.0; // (x²+1)² = 7.5625

    let ct_x = rns_encrypt_f64(x, &pk_b, &pk_a, &ctx, &mut rng);

    // Level 0: compute x²
    let ct_x2 = rns_ct_mul_relin(&ct_x, &ct_x, &evk, &ctx);
    let ct_x2 = rns_rescale(&ct_x2);
    // ct_x2 is at level 1 with scale ~2^24

    // Compute x²+1 for squaring
    let ct_x2_p1 = rns_ct_add_plain(&ct_x2, 1.0, ct_x2.scale);

    // Level 1: compute (x²+1)²
    let ct_result = rns_ct_mul_relin(&ct_x2_p1, &ct_x2_p1, &evk, &ctx);
    let ct_result = rns_rescale(&ct_result);

    let decrypted = rns_decrypt_f64(&ct_result, &s, &ctx);
    let error = (decrypted - expected).abs();

    println!("\n=== Polynomial f(x)=(x²+1)² at x={} ===", x);
    println!("  Expected:  {:.4}", expected);
    println!("  Decrypted: {:.4}", decrypted);
    println!("  Error:     {:.6}", error);

    assert!(
        error < 5.0,
        "f({}) expected {}, got {} (error {})",
        x,
        expected,
        decrypted,
        error
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Full encrypt→compute→decrypt pipeline timing
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn full_pipeline_timing() {
    let mut rng = test_rng();

    println!("\n=== Full RNS-CKKS Pipeline Timing ===");

    // Setup
    let setup_start = Instant::now();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    let evk = rns_gen_eval_key(&s, &ctx, &mut rng);
    let setup_time = setup_start.elapsed();
    println!("  Setup (keygen + evalkey): {:>6.1} ms", setup_time.as_secs_f64() * 1000.0);

    // Encrypt
    let enc_start = Instant::now();
    let ct_a = rns_encrypt_f64(3.0, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_b = rns_encrypt_f64(4.0, &pk_b, &pk_a, &ctx, &mut rng);
    let enc_time = enc_start.elapsed();
    println!("  Encrypt (2 values):      {:>6.1} ms", enc_time.as_secs_f64() * 1000.0);

    // Homomorphic multiply + relin + rescale
    let mul_start = Instant::now();
    let ct_prod = rns_ct_mul_relin(&ct_a, &ct_b, &evk, &ctx);
    let ct_result = rns_rescale(&ct_prod);
    let mul_time = mul_start.elapsed();
    println!("  Multiply+Relin+Rescale:  {:>6.1} ms", mul_time.as_secs_f64() * 1000.0);

    // Decrypt
    let dec_start = Instant::now();
    let result = rns_decrypt_f64(&ct_result, &s, &ctx);
    let dec_time = dec_start.elapsed();
    println!("  Decrypt:                 {:>6.1} ms", dec_time.as_secs_f64() * 1000.0);

    let total = setup_time + enc_time + mul_time + dec_time;
    println!("  TOTAL:                   {:>6.1} ms", total.as_secs_f64() * 1000.0);
    println!("  Result: 3.0 * 4.0 = {:.4}", result);

    assert!(
        (result - 12.0).abs() < 1.0,
        "3*4 expected ~12, got {}",
        result
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Two sequential multiplies with timing
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn two_level_multiply_timing() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

    println!("\n=== Two Sequential Multiplies (x=2, compute x⁴=16) ===");

    let ct_x = rns_encrypt_f64(2.0, &pk_b, &pk_a, &ctx, &mut rng);

    // First multiply: x² = 4
    let t1 = Instant::now();
    let ct_x2 = rns_ct_mul_relin(&ct_x, &ct_x, &evk, &ctx);
    let ct_x2 = rns_rescale(&ct_x2);
    let t1_elapsed = t1.elapsed();

    let dec_x2 = rns_decrypt_f64(&ct_x2, &s, &ctx);
    println!("  Level 0→1 (x*x=x²):  {:>6.1} ms, result={:.4}", t1_elapsed.as_secs_f64() * 1000.0, dec_x2);

    // Second multiply: x⁴ = 16
    let t2 = Instant::now();
    let ct_x4 = rns_ct_mul_relin(&ct_x2, &ct_x2, &evk, &ctx);
    let ct_x4 = rns_rescale(&ct_x4);
    let t2_elapsed = t2.elapsed();

    let dec_x4 = rns_decrypt_f64(&ct_x4, &s, &ctx);
    println!("  Level 1→2 (x²*x²=x⁴): {:>5.1} ms, result={:.4}", t2_elapsed.as_secs_f64() * 1000.0, dec_x4);

    println!("  Primes remaining: {}", ct_x4.c0.num_primes);

    assert!((dec_x2 - 4.0).abs() < 1.0, "x² expected ~4, got {}", dec_x2);
    assert!((dec_x4 - 16.0).abs() < 5.0, "x⁴ expected ~16, got {}", dec_x4);
}

// ═══════════════════════════════════════════════════════════════════════
// Noise growth tracking across operations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn noise_growth_across_operations() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

    let value = 5.0f64;

    println!("\n=== Noise Growth Tracking (value={}) ===", value);

    // Fresh encryption
    let ct = rns_encrypt_f64(value, &pk_b, &pk_a, &ctx, &mut rng);
    let dec = rns_decrypt_f64(&ct, &s, &ctx);
    let err_fresh = (dec - value).abs();
    println!("  Fresh encrypt:         error = {:.2e}", err_fresh);

    // After addition
    let ct2 = rns_encrypt_f64(3.0, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_sum = rns_ct_add(&ct, &ct2);
    let dec_sum = rns_decrypt_f64(&ct_sum, &s, &ctx);
    let err_add = (dec_sum - 8.0).abs();
    println!("  After add (5+3=8):     error = {:.2e}", err_add);

    // After scalar multiply
    let ct_scaled = rns_ct_scalar_mul(&ct, 3);
    let dec_scaled = rns_decrypt_f64(&ct_scaled, &s, &ctx);
    let err_scalar = (dec_scaled - 15.0).abs();
    println!("  After scalar*3 (=15):  error = {:.2e}", err_scalar);

    // After ct-ct multiply + rescale
    let ct_prod = rns_ct_mul_relin(&ct, &ct2, &evk, &ctx);
    let ct_prod = rns_rescale(&ct_prod);
    let dec_prod = rns_decrypt_f64(&ct_prod, &s, &ctx);
    let err_mul = (dec_prod - 15.0).abs();
    println!("  After mul+rescale:     error = {:.2e}", err_mul);

    // Noise should grow: fresh < add ≤ scalar < multiply
    assert!(err_fresh < 0.01, "fresh error too large: {}", err_fresh);
    assert!(err_add < 0.01, "add error too large: {}", err_add);
    assert!(err_scalar < 0.01, "scalar error too large: {}", err_scalar);
    assert!(err_mul < 1.0, "multiply error too large: {}", err_mul);
}

// ═══════════════════════════════════════════════════════════════════════
// RNS multiply benchmark (multi-channel NTT)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn benchmark_rns_multiply() {
    let mut rng = test_rng();
    let ntt = poly_client::ckks::rns::create_ntt_contexts();

    // Create two random RNS polynomials with 3 primes
    let coeffs_a: Vec<i64> = (0..N).map(|_| rand::Rng::gen_range(&mut rng, -1000..1000)).collect();
    let coeffs_b: Vec<i64> = (0..N).map(|_| rand::Rng::gen_range(&mut rng, -1000..1000)).collect();
    let a = RnsPoly::from_coeffs(&coeffs_a, 3);
    let b = RnsPoly::from_coeffs(&coeffs_b, 3);

    // Benchmark: 10 multiplications
    let start = Instant::now();
    let iters = 10;
    let mut result = a.clone();
    for _ in 0..iters {
        result = result.mul(&b, &ntt);
    }
    let elapsed = start.elapsed();

    println!("\n=== RNS Multiply Benchmark (3 primes, N={}) ===", N);
    println!(
        "  {} multiplies: {:>6.1} ms ({:.2} ms/multiply)",
        iters,
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1000.0 / iters as f64
    );
}

// ═══════════════════════════════════════════════════════════════════════
// SIMD: throughput comparison (1 value vs 2048 values per ciphertext)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn simd_throughput_comparison() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

    println!("\n=== SIMD Throughput: 1 value/ct vs {} values/ct ===", NUM_SLOTS);

    // Scalar mode: encrypt 8 values as 8 separate ciphertexts, multiply pairwise
    let scalar_start = Instant::now();
    let n_pairs = 4;
    for i in 0..n_pairs {
        let ct_a = rns_encrypt_f64((i + 1) as f64, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_b = rns_encrypt_f64((i + 5) as f64, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_prod = rns_ct_mul_relin(&ct_a, &ct_b, &evk, &ctx);
        let _ = rns_rescale(&ct_prod);
    }
    let scalar_time = scalar_start.elapsed();
    let scalar_per_value = scalar_time.as_secs_f64() * 1000.0 / n_pairs as f64;

    // SIMD mode: encrypt all 2048 values in one ciphertext, one multiply
    let a_vals: Vec<f64> = (0..NUM_SLOTS).map(|i| (i % 10 + 1) as f64).collect();
    let b_vals: Vec<f64> = (0..NUM_SLOTS).map(|i| (i % 10 + 5) as f64).collect();

    let simd_start = Instant::now();
    let ct_a = rns_encrypt_simd(&a_vals, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_b = rns_encrypt_simd(&b_vals, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_prod = rns_ct_mul_relin(&ct_a, &ct_b, &evk, &ctx);
    let ct_result = rns_rescale(&ct_prod);
    let simd_time = simd_start.elapsed();
    let simd_per_value = simd_time.as_secs_f64() * 1000.0 / NUM_SLOTS as f64;

    // Verify SIMD result correctness (spot check first 8 slots)
    let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, 8);
    for i in 0..8 {
        let expected = a_vals[i] * b_vals[i];
        assert!(
            (decrypted[i] - expected).abs() < 1.0,
            "SIMD slot {} mul: expected {}, got {}",
            i, expected, decrypted[i]
        );
    }

    let throughput_ratio = scalar_per_value / simd_per_value;

    println!("  Scalar: {} muls in {:>6.1} ms ({:.3} ms/value)",
        n_pairs, scalar_time.as_secs_f64() * 1000.0, scalar_per_value);
    println!("  SIMD:   {} muls in {:>6.1} ms ({:.6} ms/value)",
        NUM_SLOTS, simd_time.as_secs_f64() * 1000.0, simd_per_value);
    println!("  Throughput improvement: {:.0}x", throughput_ratio);
    println!();

    // SIMD should have much better per-value throughput
    assert!(
        throughput_ratio > 10.0,
        "SIMD throughput improvement ({:.1}x) should be > 10x",
        throughput_ratio
    );
}

#[test]
fn simd_elementwise_add_large() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

    // Fill all 2048 slots with different values and add
    let a: Vec<f64> = (0..NUM_SLOTS).map(|i| (i as f64 * 0.01).sin()).collect();
    let b: Vec<f64> = (0..NUM_SLOTS).map(|i| (i as f64 * 0.01).cos()).collect();

    let ct_a = rns_encrypt_simd(&a, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_b = rns_encrypt_simd(&b, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_sum = rns_ct_add(&ct_a, &ct_b);

    let decrypted = rns_decrypt_simd(&ct_sum, &s, &ctx, NUM_SLOTS);

    let max_err = a.iter().zip(b.iter()).zip(decrypted.iter())
        .map(|((&ai, &bi), &di)| (ai + bi - di).abs())
        .fold(0.0f64, f64::max);

    println!("\n=== SIMD Element-wise Add (2048 slots) ===");
    println!("  Max error: {:.2e}", max_err);

    assert!(max_err < 0.01, "SIMD add max error {} too large", max_err);
}

#[test]
fn simd_elementwise_multiply_and_verify() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

    // 64 slots: simulates a 64-neuron layer multiplication
    let weights: Vec<f64> = (0..64).map(|i| (i as f64 - 32.0) * 0.1).collect();
    let activations: Vec<f64> = (0..64).map(|i| (i as f64 * 0.05).tanh()).collect();

    let ct_w = rns_encrypt_simd(&weights, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_a = rns_encrypt_simd(&activations, &pk_b, &pk_a, &ctx, &mut rng);

    let ct_prod = rns_ct_mul_relin(&ct_w, &ct_a, &evk, &ctx);
    let ct_prod = rns_rescale(&ct_prod);

    let decrypted = rns_decrypt_simd(&ct_prod, &s, &ctx, 64);

    let mut max_err = 0.0f64;
    for i in 0..64 {
        let expected = weights[i] * activations[i];
        let err = (decrypted[i] - expected).abs();
        max_err = max_err.max(err);
    }

    println!("\n=== SIMD 64-Neuron Layer Multiply ===");
    println!("  Max error across 64 slots: {:.2e}", max_err);

    assert!(
        max_err < 1.0,
        "64-neuron multiply max error {} too large",
        max_err
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Rotation + Matrix-Vector Multiply Integration Tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rotation_multiple_amounts() {
    // Test rotations by 1, 2, and 3 in a single key set
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    let rot_keys = rns_gen_rotation_keys(&s, &[1, 2, 3], &ctx, &mut rng);

    let values: Vec<f64> = (1..=8).map(|i| i as f64).collect();
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    for rot in 1..=3i32 {
        let ct_rot = rns_rotate(&ct, rot, &rot_keys, &ctx);
        let decrypted = rns_decrypt_simd(&ct_rot, &s, &ctx, 5);

        for i in 0..5 {
            let expected = values[(i + rot as usize) % values.len()];
            // Some wrap-around values go to slot 2048-k, not checked here
            if i + rot as usize >= values.len() {
                continue;
            }
            assert!(
                (decrypted[i] - expected).abs() < 0.5,
                "rot {} slot {}: expected {}, got {}",
                rot, i, expected, decrypted[i]
            );
        }
    }
    println!("\n=== Rotation by 1, 2, 3: all correct ===");
}

#[test]
fn matvec_8x8_neural_layer() {
    // 8×8 matrix-vector multiply: simulates a small neural network layer
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

    let d = 8;
    // Random-ish weight matrix (values in [-1, 1])
    let w: Vec<f64> = (0..d * d)
        .map(|i| (i as f64 * 0.37).sin() * 0.5)
        .collect();
    let x: Vec<f64> = (0..d).map(|i| (i as f64 + 1.0) * 0.25).collect();

    // Compute expected result
    let mut expected = vec![0.0f64; d];
    for i in 0..d {
        for j in 0..d {
            expected[i] += w[i * d + j] * x[j];
        }
    }

    let rotations: Vec<i32> = (1..d as i32).collect();
    let rot_keys = rns_gen_rotation_keys(&s, &rotations, &ctx, &mut rng);

    let t_start = Instant::now();
    let x_rep = replicate_vector(&x, d);
    let ct_x = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_result = rns_matvec(&ct_x, &w, d, &rot_keys, &ctx);
    let ct_result = rns_rescale(&ct_result);
    let elapsed = t_start.elapsed();

    let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, d);

    let max_err = expected.iter().zip(decrypted.iter())
        .map(|(e, d)| (e - d).abs())
        .fold(0.0f64, f64::max);

    println!("\n=== 8×8 Neural Layer via Encrypted Matvec ===");
    println!("  Expected: {:?}", expected.iter().map(|v| format!("{:.3}", v)).collect::<Vec<_>>());
    println!("  Got:      {:?}", decrypted.iter().map(|v| format!("{:.3}", v)).collect::<Vec<_>>());
    println!("  Max error: {:.2e}", max_err);
    println!("  Time:      {:.1} ms", elapsed.as_secs_f64() * 1000.0);

    assert!(
        max_err < 2.0,
        "8×8 matvec max error {} too large",
        max_err
    );
}

#[test]
fn plaintext_simd_multiply_integration() {
    // Multiply encrypted vector by plaintext weights (no ct-ct mul needed)
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

    let activations: Vec<f64> = (0..64).map(|i| (i as f64 * 0.05).tanh()).collect();
    let weights: Vec<f64> = (0..64).map(|i| (i as f64 - 32.0) * 0.1).collect();

    let ct = rns_encrypt_simd(&activations, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_prod = rns_ct_mul_plain_simd(&ct, &weights, &ctx);
    let ct_result = rns_rescale(&ct_prod);

    let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, 64);

    let max_err = activations.iter().zip(weights.iter()).zip(decrypted.iter())
        .map(|((&a, &w), &d)| (a * w - d).abs())
        .fold(0.0f64, f64::max);

    println!("\n=== Plaintext SIMD Multiply (64 slots) ===");
    println!("  Max error: {:.2e}", max_err);

    assert!(
        max_err < 1.0,
        "plaintext SIMD mul max error {} too large",
        max_err
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Verify Phase 1 tests still pass with Phase 2 code
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn phase1_compatibility() {
    // Verify that the basic encrypt/decrypt from Phase 1 still works
    // (different module, but ensure no regressions)
    use poly_client::ckks::CkksEncryption;
    use poly_client::encryption::EncryptionBackend;

    let backend = CkksEncryption;
    let (pk, sk) = backend.keygen();

    let tokens = vec![1u32, 42, 1000, 65535];
    let ct = backend.encrypt(&tokens, &pk);
    let decrypted = backend.decrypt(&ct, &sk);

    assert_eq!(tokens, decrypted, "Phase 1 basic encrypt/decrypt broken");
}
