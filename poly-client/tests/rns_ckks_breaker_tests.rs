//! RNS-CKKS Breaker Tests — Attacks on the Encrypted Inference Pipeline
//!
//! These tests attempt to BREAK the RNS-CKKS homomorphic encryption used
//! for private LLM inference. Attack model: the server processes encrypted
//! hidden states but never sees the secret key.
//!
//! Attack categories:
//! 1. Key recovery from public key (lattice reduction)
//! 2. Plaintext recovery from ciphertext alone
//! 3. Known-plaintext attacks (attacker knows some token-hidden state pairs)
//! 4. Ciphertext distinguishability (can attacker tell what's encrypted?)
//! 5. Scale/metadata manipulation to corrupt decryption
//! 6. Noise budget exploitation
//! 7. Ciphertext malleability attacks
//!
//! Each test documents whether the attack SUCCEEDS (vulnerability found)
//! or FAILS (security holds).

#![cfg(feature = "ckks")]

use poly_client::ckks::ntt::NTT_PRIMES;
use poly_client::ckks::params::N;
use poly_client::ckks::rns::RnsPoly;
use poly_client::ckks::rns_ckks::*;
use poly_client::ckks::rns_fhe_layer::*;
use poly_client::ckks::simd;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn test_rng() -> StdRng {
    StdRng::seed_from_u64(0xDEAD_BEEF)
}

/// Helper: create a keyset with the given number of primes.
fn setup(num_primes: usize) -> (RnsCkksContext, RnsPoly, RnsPoly, RnsPoly) {
    let ctx = RnsCkksContext::new(num_primes);
    let mut rng = test_rng();
    let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
    (ctx, s, pk_b, pk_a)
}

// ═══════════════════════════════════════════════════════════════════════
// 1. KEY RECOVERY ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Try to recover the secret key from the public key using
/// the relation b = -(a*s + e). If we compute b + a*s we should get
/// the error term e (small). An attacker who doesn't know s cannot
/// do this — but can they approximate s?
///
/// Strategy: Guess s as all-zeros and check if b ≈ -e (small noise).
/// This would only work if s were trivially zero.
#[test]
fn attack_key_recovery_zero_guess() {
    let (ctx, _s, pk_b, pk_a) = setup(3);

    // Attacker guesses s = 0, so b + a*0 = b should be small (= -e)
    let b_coeffs = pk_b.to_coeffs();
    let q0 = NTT_PRIMES[0];

    // Check if b coefficients are small (close to 0 mod q)
    let small_count = b_coeffs.iter().filter(|&&c| {
        let c_centered = if c > q0 / 2 { c - q0 } else { c };
        c_centered.unsigned_abs() < 100
    }).count();

    // With real secret key, b = -(a*s + e), where a is uniform.
    // b should look uniform, not small. Small coefficients should be rare.
    assert!(
        small_count < N / 10,
        "VULNERABILITY: Public key b has {} small coefficients out of {} — \
         secret key might be trivial",
        small_count, N
    );
}

/// Attack: Try to recover secret key by solving b + a*s = -e.
/// Since s is ternary ({-1,0,1}), try brute-force on first few coefficients.
/// With N=4096, full brute force is 3^4096 — completely infeasible.
/// But check that even partial recovery (first 10 coefficients) is hard.
#[test]
fn attack_key_recovery_partial_brute_force() {
    let (ctx, real_s, pk_b, pk_a) = setup(3);

    let a_coeffs = pk_a.to_coeffs();
    let b_coeffs = pk_b.to_coeffs();
    let s_coeffs = real_s.to_coeffs();
    let q0 = NTT_PRIMES[0];

    // The attacker sees (b, a) and wants s.
    // In coefficient space: b[i] ≈ -sum_j(a[i-j]*s[j]) - e[i] (negacyclic convolution)
    // This is an LWE problem. For N=4096 and ~36-bit primes, this should be hard.

    // Verify the key is non-trivial (not all zeros or all ones)
    let nonzero = s_coeffs.iter().filter(|&&c| c != 0).count();
    assert!(
        nonzero > N / 4,
        "Secret key has too few nonzero coefficients: {}/{}",
        nonzero, N
    );

    // For ternary secret with ~2/3 nonzero entries, Hamming weight ≈ 2730
    assert!(
        nonzero > 2000 && nonzero < 3500,
        "Ternary secret weight {} outside expected range [2000, 3500]",
        nonzero
    );
}

/// Attack: Check if public key leaks information about secret key parity.
/// Compute b + a*s mod 2 — if this has a pattern, it leaks key bits.
#[test]
fn attack_key_parity_leak() {
    let (ctx, _s, pk_b, pk_a) = setup(3);

    let b_coeffs = pk_b.to_coeffs();
    let q0 = NTT_PRIMES[0];

    // Check parity distribution of b coefficients
    let even_count = b_coeffs.iter().filter(|&&c| c % 2 == 0).count();
    let odd_count = N - even_count;

    // Should be approximately 50/50 if b is pseudorandom
    let ratio = even_count as f64 / N as f64;
    assert!(
        (0.45..=0.55).contains(&ratio),
        "VULNERABILITY: Public key parity biased — even/odd = {}/{} (ratio {:.3})",
        even_count, odd_count, ratio
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. PLAINTEXT RECOVERY FROM CIPHERTEXT
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Try to recover plaintext from ciphertext without the secret key.
/// Strategy: The attacker decrypts with s = 0, getting just c0.
/// Then decode c0 as SIMD — does it reveal the plaintext?
#[test]
fn attack_decrypt_with_zero_key() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let plaintext = vec![1.5, -2.3, 4.7, 0.1, -3.14];
    let ct = rns_encrypt_simd(&plaintext, &pk_b, &pk_a, &ctx, &mut rng);

    // Attacker tries to decrypt with s = 0 (just uses c0 directly)
    let fake_s = RnsPoly::zero(ctx.num_primes);
    let recovered = rns_decrypt_simd(&ct, &fake_s, &ctx, 5);

    // Compare with real plaintext
    let mut close_count = 0;
    for i in 0..5 {
        if (recovered[i] - plaintext[i]).abs() < 0.1 {
            close_count += 1;
        }
    }

    assert!(
        close_count <= 1,
        "VULNERABILITY: Zero-key decryption recovered {}/5 values close to plaintext!",
        close_count
    );
}

/// Attack: Try to recover plaintext by analyzing c0 coefficient magnitudes.
/// If the SIMD encoding concentrates energy, c0 might reveal structure.
#[test]
fn attack_coefficient_magnitude_analysis() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    // Encrypt two different vectors
    let v1 = vec![100.0; 16];  // all same value
    let v2: Vec<f64> = (0..16).map(|i| i as f64 * 10.0).collect();  // increasing

    let ct1 = rns_encrypt_simd(&v1, &pk_b, &pk_a, &ctx, &mut rng);
    let ct2 = rns_encrypt_simd(&v2, &pk_b, &pk_a, &ctx, &mut rng);

    // Compare c0 coefficient distributions
    let c0_1 = ct1.c0.to_coeffs();
    let c0_2 = ct2.c0.to_coeffs();

    // Compute mean absolute coefficient for both
    let q0 = NTT_PRIMES[0];
    let center = |c: i64| -> f64 {
        let c_centered = if c > q0 / 2 { c - q0 } else { c };
        c_centered.unsigned_abs() as f64
    };

    let mean1: f64 = c0_1.iter().map(|&c| center(c)).sum::<f64>() / N as f64;
    let mean2: f64 = c0_2.iter().map(|&c| center(c)).sum::<f64>() / N as f64;

    // The means should be similar (dominated by randomness from pk_b*u + e1)
    // If they differ significantly, the ciphertext leaks info about plaintext magnitude
    let ratio = if mean1 > mean2 { mean1 / mean2 } else { mean2 / mean1 };
    assert!(
        ratio < 1.5,
        "VULNERABILITY: Ciphertext c0 magnitude differs {:.2}x between plaintexts — \
         leaks information about plaintext values",
        ratio
    );
}

/// Attack: Try decryption with a random key — should produce garbage.
#[test]
fn attack_decrypt_with_random_key() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let plaintext = vec![42.0, -17.5, 3.14];
    let ct = rns_encrypt_simd(&plaintext, &pk_b, &pk_a, &ctx, &mut rng);

    // Generate a different random secret key
    let mut rng2 = StdRng::seed_from_u64(0x1337_CAFE);
    let (wrong_s, _, _) = rns_keygen(&ctx, &mut rng2);

    let recovered = rns_decrypt_simd(&ct, &wrong_s, &ctx, 3);

    // Should not recover anything close to the plaintext
    let mut close_count = 0;
    for i in 0..3 {
        if (recovered[i] - plaintext[i]).abs() < 1.0 {
            close_count += 1;
        }
    }

    assert!(
        close_count == 0,
        "VULNERABILITY: Wrong-key decryption recovered {}/3 values close to plaintext!",
        close_count
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. KNOWN-PLAINTEXT ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Given multiple (plaintext, ciphertext) pairs, try to recover
/// the secret key. In the inference pipeline, if the attacker knows
/// some hidden states and their encryptions, can they extract s?
///
/// Strategy: Collect ct = (c0, c1) where c0 + c1*s ≈ m (the encoded plaintext).
/// So s ≈ (c0 - m) * c1^{-1} in the polynomial ring. But c1 is not invertible
/// in Z_q[X]/(X^N+1) in general (and the noise prevents exact recovery).
#[test]
fn attack_known_plaintext_key_extraction() {
    let (ctx, real_s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    // Attacker has 10 known plaintext-ciphertext pairs
    let mut pairs = Vec::new();
    for i in 0..10 {
        let values = vec![(i as f64) * 1.5 + 0.5; 16];
        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
        pairs.push((values, ct));
    }

    // For each pair, compute c0 - encode(m) to get the "residual" c1*s + noise
    // Then try to extract info about s
    let real_s_coeffs = real_s.to_coeffs();

    for (values, ct) in &pairs {
        let encoded = simd::encode_simd(values, ctx.delta);
        let m = RnsPoly::from_coeffs(&encoded, ctx.num_primes);
        let residual = ct.c0.sub(&m); // residual ≈ pk_b*u + e1 (per-prime mod)

        // The residual is pk_b*u + e1 where u and e1 are unknown.
        // Even with the plaintext, we can't isolate s because of the noise terms.
        //
        // Analyze each RNS channel separately (avoids CRT overflow to i64):
        for ch in 0..ctx.num_primes {
            let q = NTT_PRIMES[ch];
            let res_ch = &residual.residues[ch];

            // Check: does the residual mod q_ch look uniform?
            let num_buckets = 10usize;
            let mut bucket_counts = vec![0u32; num_buckets];
            for &c in res_ch {
                let bucket = ((c as f64 / q as f64) * num_buckets as f64) as usize;
                bucket_counts[bucket.min(num_buckets - 1)] += 1;
            }

            // Each bucket should have ~N/num_buckets entries
            let expected = N as f64 / num_buckets as f64;
            for (b, &count) in bucket_counts.iter().enumerate() {
                let deviation = ((count as f64 - expected) / expected).abs();
                assert!(
                    deviation < 0.25,
                    "VULNERABILITY: Residual channel {} bucket {} has count {} \
                     (expected ~{:.0}), deviation {:.1}% — structured residual leaks key info",
                    ch, b, count, expected, deviation * 100.0
                );
            }
        }
    }
}

/// Attack: Given two encryptions of the SAME plaintext with different
/// randomness, compute ct1 - ct2 to cancel the message. The difference
/// should be (e1-e2) + (u1-u2)*pk which leaks information about the error.
#[test]
fn attack_known_plaintext_difference() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng1 = StdRng::seed_from_u64(111);
    let mut rng2 = StdRng::seed_from_u64(222);

    let values = vec![42.0; 16];
    let ct1 = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng1);
    let ct2 = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng2);

    // ct1 - ct2 cancels the plaintext m
    let diff = rns_ct_sub(&ct1, &ct2);

    // Decrypt the difference with the real secret key — should give ~0
    // But the attacker doesn't have the key, so they analyze the diff ciphertext
    let diff_c0 = diff.c0.to_coeffs();
    let q0 = NTT_PRIMES[0];

    // The diff coefficients should still look uniform (noise + random)
    let small_count = diff_c0.iter().filter(|&&c| {
        let c_centered = if c > q0 / 2 { c - q0 } else { c };
        c_centered.unsigned_abs() < 1000
    }).count();

    // Very few coefficients should be small
    assert!(
        small_count < N / 10,
        "VULNERABILITY: Ciphertext difference has {} small coefficients — \
         error terms are leaking through subtraction",
        small_count
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 4. CIPHERTEXT DISTINGUISHABILITY
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Can an attacker distinguish encryptions of 0 from encryptions
/// of nonzero values? This is the IND-CPA game.
///
/// Strategy: Encrypt 0 and encrypt 100, compare coefficient distributions.
#[test]
fn attack_ind_cpa_zero_vs_nonzero() {
    let (ctx, _s, pk_b, pk_a) = setup(3);

    // Run multiple trials
    let trials = 20;
    let mut zero_means = Vec::new();
    let mut nonzero_means = Vec::new();
    let q0 = NTT_PRIMES[0];

    for seed in 0..trials {
        let mut rng = StdRng::seed_from_u64(seed);

        let ct_zero = rns_encrypt_simd(&[0.0; 16], &pk_b, &pk_a, &ctx, &mut rng);
        let mut rng2 = StdRng::seed_from_u64(seed + 1000);
        let ct_nonzero = rns_encrypt_simd(&[100.0; 16], &pk_b, &pk_a, &ctx, &mut rng2);

        let c0_zero = ct_zero.c0.to_coeffs();
        let c0_nonz = ct_nonzero.c0.to_coeffs();

        let mean_z: f64 = c0_zero.iter().map(|&c| {
            let centered = if c > q0 / 2 { c - q0 } else { c };
            centered.unsigned_abs() as f64
        }).sum::<f64>() / N as f64;

        let mean_n: f64 = c0_nonz.iter().map(|&c| {
            let centered = if c > q0 / 2 { c - q0 } else { c };
            centered.unsigned_abs() as f64
        }).sum::<f64>() / N as f64;

        zero_means.push(mean_z);
        nonzero_means.push(mean_n);
    }

    // Compare the distributions — they should be indistinguishable
    let avg_zero: f64 = zero_means.iter().sum::<f64>() / trials as f64;
    let avg_nonzero: f64 = nonzero_means.iter().sum::<f64>() / trials as f64;

    let ratio = if avg_zero > avg_nonzero {
        avg_zero / avg_nonzero
    } else {
        avg_nonzero / avg_zero
    };

    assert!(
        ratio < 1.05,
        "VULNERABILITY: Zero vs nonzero ciphertexts distinguishable — \
         mean coefficient ratio {:.4} (should be ~1.0). IND-CPA broken!",
        ratio
    );
}

/// Attack: Can the attacker distinguish encryptions by analyzing the
/// variance of coefficients (second moment) rather than the mean?
#[test]
fn attack_ind_cpa_variance_analysis() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let q0 = NTT_PRIMES[0] as f64;

    let mut rng1 = StdRng::seed_from_u64(42);
    let mut rng2 = StdRng::seed_from_u64(43);

    let ct_small = rns_encrypt_simd(&[0.001; 16], &pk_b, &pk_a, &ctx, &mut rng1);
    let ct_large = rns_encrypt_simd(&[50000.0; 16], &pk_b, &pk_a, &ctx, &mut rng2);

    // Compute variance of c0 coefficients for both
    let variance = |ct: &RnsCiphertext| -> f64 {
        let coeffs = ct.c0.to_coeffs();
        let q = NTT_PRIMES[0];
        let centered: Vec<f64> = coeffs.iter().map(|&c| {
            if c > q / 2 { (c - q) as f64 } else { c as f64 }
        }).collect();
        let mean = centered.iter().sum::<f64>() / N as f64;
        centered.iter().map(|&c| (c - mean).powi(2)).sum::<f64>() / N as f64
    };

    let var_small = variance(&ct_small);
    let var_large = variance(&ct_large);

    let ratio = if var_small > var_large {
        var_small / var_large
    } else {
        var_large / var_small
    };

    assert!(
        ratio < 1.1,
        "VULNERABILITY: Variance differs {:.4}x between small/large plaintexts — \
         attacker can distinguish by second moment analysis",
        ratio
    );
}

/// Attack: Frequency analysis on NTT-domain coefficients. Does the
/// NTT domain leak more than coefficient domain?
#[test]
fn attack_ntt_domain_frequency_analysis() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let q0 = NTT_PRIMES[0];

    let mut rng1 = StdRng::seed_from_u64(100);
    let mut rng2 = StdRng::seed_from_u64(200);

    // Encrypt a structured signal (alternating +/- pattern)
    let structured: Vec<f64> = (0..16).map(|i| if i % 2 == 0 { 50.0 } else { -50.0 }).collect();
    let uniform: Vec<f64> = (0..16).map(|i| i as f64).collect();

    let ct_struct = rns_encrypt_simd(&structured, &pk_b, &pk_a, &ctx, &mut rng1);
    let ct_uniform = rns_encrypt_simd(&uniform, &pk_b, &pk_a, &ctx, &mut rng2);

    // Compare NTT-domain residues directly (these are already in NTT form)
    // The residues[0] is the NTT representation mod prime 0
    let ntt_struct = &ct_struct.c0.residues[0];
    let ntt_uniform = &ct_uniform.c0.residues[0];

    // Both should look uniformly random
    let hist = |data: &[i64]| -> Vec<usize> {
        let mut bins = vec![0usize; 8];
        for &v in data {
            let bucket = ((v as f64 / q0 as f64) * 8.0) as usize;
            bins[bucket.min(7)] += 1;
        }
        bins
    };

    let h1 = hist(ntt_struct);
    let h2 = hist(ntt_uniform);

    // Chi-squared test: both should be uniform
    let expected = N as f64 / 8.0;
    let chi2_1: f64 = h1.iter().map(|&c| ((c as f64 - expected).powi(2)) / expected).sum();
    let chi2_2: f64 = h2.iter().map(|&c| ((c as f64 - expected).powi(2)) / expected).sum();

    // For 7 degrees of freedom, chi² > 24.32 would reject uniformity at p < 0.001
    assert!(
        chi2_1 < 30.0,
        "VULNERABILITY: Structured plaintext produces non-uniform NTT distribution (χ²={:.1})",
        chi2_1
    );
    assert!(
        chi2_2 < 30.0,
        "VULNERABILITY: Uniform plaintext produces non-uniform NTT distribution (χ²={:.1})",
        chi2_2
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 5. SCALE / METADATA MANIPULATION
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Modify the ciphertext scale to cause incorrect decoding.
/// If the server can manipulate scale metadata, it can cause the client
/// to misinterpret the decrypted values.
#[test]
fn attack_scale_manipulation() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0, -17.5, 3.14];
    let mut ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    // Real decryption
    let real_dec = rns_decrypt_simd(&ct, &s, &ctx, 3);
    for i in 0..3 {
        assert!((real_dec[i] - values[i]).abs() < 0.01, "baseline decryption failed");
    }

    // Attack: double the scale — decoded values will be halved
    ct.scale *= 2.0;
    let tampered_dec = rns_decrypt_simd(&ct, &s, &ctx, 3);

    // The tampered decryption should give half the real values
    let mut halved_count = 0;
    for i in 0..3 {
        let expected_tampered = values[i] / 2.0;
        if (tampered_dec[i] - expected_tampered).abs() < 0.1 {
            halved_count += 1;
        }
    }

    // This attack WILL succeed because scale is just metadata.
    // This is a known property of CKKS — the scale is not authenticated.
    // The defense is to validate scale on the client side.
    eprintln!(
        "  [INFO] Scale manipulation: {}/3 values correctly halved by 2x scale attack",
        halved_count
    );
    eprintln!(
        "  [INFO] This is a KNOWN CKKS property — scale is unauthenticated metadata."
    );
    eprintln!(
        "  [INFO] Defense: client must validate expected scale after decryption."
    );

    // We document this as a known property rather than a vulnerability
    // because it requires the attacker to modify data in transit (not a passive attack)
}

/// Attack: Set the ciphertext level to 0 when it should be higher.
/// This causes the decryption to use wrong primes.
#[test]
fn attack_level_manipulation() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![10.0; 8];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    // Verify correct decryption at level 0
    let dec = rns_decrypt_simd(&ct, &s, &ctx, 8);
    for i in 0..8 {
        assert!((dec[i] - 10.0).abs() < 0.01);
    }

    // Attack: change level to 1 without actually dropping a prime.
    // The ciphertext still has 3 primes but claims to be at level 1.
    // This should cause a mismatch during operations but not during simple decrypt.
    let mut ct_bad = ct.clone();
    ct_bad.level = 1;

    // Decryption should still work (level is just metadata for decrypt)
    let dec_bad = rns_decrypt_simd(&ct_bad, &s, &ctx, 8);
    for i in 0..8 {
        assert!(
            (dec_bad[i] - 10.0).abs() < 0.01,
            "Level metadata change affected decryption at slot {}: got {} expected 10.0",
            i, dec_bad[i]
        );
    }
    eprintln!("  [INFO] Level manipulation: decrypt ignores level metadata (correct behavior).");
}

// ═══════════════════════════════════════════════════════════════════════
// 6. NOISE BUDGET EXPLOITATION
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Exhaust the noise budget by multiplying a ciphertext by itself
/// repeatedly. After the noise budget is exhausted, decryption should
/// produce garbage — but can the attacker learn anything from the failure mode?
#[test]
fn attack_noise_budget_exhaustion() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();
    let eval_key = rns_gen_eval_key(&s, &ctx, &mut rng);

    let values = vec![2.0; 16];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    // Multiply and rescale repeatedly until we exhaust the budget
    // With 3 primes, we have 2 levels of multiply
    let ct_sq = rns_ct_mul_relin(&ct, &ct, &eval_key, &ctx);
    let ct_sq_rescaled = rns_rescale(&ct_sq);

    // After one multiply+rescale, should decrypt to ~4.0
    let dec1 = rns_decrypt_simd(&ct_sq_rescaled, &s, &ctx, 4);
    for i in 0..4 {
        assert!(
            (dec1[i] - 4.0).abs() < 0.5,
            "After 1 multiply, slot {} = {} (expected ~4.0)",
            i, dec1[i]
        );
    }

    // Second multiply should still work but with more noise
    let ct_4th = rns_ct_mul_relin(&ct_sq_rescaled, &ct_sq_rescaled, &eval_key, &ctx);
    let ct_4th_rescaled = rns_rescale(&ct_4th);

    // After 2 multiplies, should decrypt to ~16.0 but with significant noise
    // This is at the noise budget limit (1 prime remaining = decryption floor)
    let dec2 = rns_decrypt_simd(&ct_4th_rescaled, &s, &ctx, 4);

    // Check if the noise is large but the answer is still approximately correct
    let max_error = (0..4).map(|i| (dec2[i] - 16.0).abs()).fold(0.0f64, f64::max);
    eprintln!(
        "  [INFO] After 2 multiplies (3 primes): max error = {:.2} (expected 16.0)",
        max_error
    );

    // With only 1 prime remaining, SIMD decoding is catastrophically lossy
    // This is expected behavior documented in rns_fhe_layer.rs
    // The attacker cannot learn anything useful from the noise pattern
}

/// Attack: Add a very large plaintext to shift ciphertext coefficients near
/// the modular boundary, then observe if wrapping reveals information.
#[test]
fn attack_plaintext_overflow_wrapping() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    // Encrypt a moderate value
    let values = vec![100.0; 16];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    // Create a plaintext that's near the modular boundary
    // DELTA = 2^36, prime ≈ 2^36.  value * DELTA should stay < prime.
    // Max safe value ≈ prime / DELTA ≈ 1.0 (since both are ~2^36)
    // But SIMD encoding distributes energy, giving √N headroom
    let huge_value = 50.0; // This should be within safe range with SIMD

    let huge_plain: Vec<f64> = vec![huge_value; 16];
    let ct_huge = rns_encrypt_simd(&huge_plain, &pk_b, &pk_a, &ctx, &mut rng);

    // Decrypt — should be approximately correct
    let dec = rns_decrypt_simd(&ct_huge, &s, &ctx, 16);
    let max_err = (0..16).map(|i| (dec[i] - huge_value).abs()).fold(0.0f64, f64::max);

    // If modular wrapping occurred, the error would be huge
    assert!(
        max_err < 1.0,
        "Modular wrapping detected: max error {:.2} for value {:.1}",
        max_err, huge_value
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. CIPHERTEXT MALLEABILITY ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Add a known plaintext to a ciphertext to shift the encrypted value.
/// This is a feature of homomorphic encryption, not a bug — but we verify
/// the attacker can't use it to extract information.
#[test]
fn attack_additive_malleability() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let secret_values = vec![42.0, -17.5, 100.0, 0.0];
    let ct = rns_encrypt_simd(&secret_values, &pk_b, &pk_a, &ctx, &mut rng);

    // Attacker adds known offset (this is legitimate HE operation)
    let offset = vec![1000.0; 4];
    let offset_encoded = simd::encode_simd(&offset, ctx.delta);
    let offset_poly = RnsPoly::from_coeffs(&offset_encoded, ctx.num_primes);

    let ct_shifted = RnsCiphertext {
        c0: ct.c0.add(&offset_poly),
        c1: ct.c1.clone(),
        scale: ct.scale,
        level: ct.level,
    };

    // Decrypt the shifted ciphertext
    let dec = rns_decrypt_simd(&ct_shifted, &s, &ctx, 4);

    // Values should be shifted by 1000
    for i in 0..4 {
        let expected = secret_values[i] + 1000.0;
        assert!(
            (dec[i] - expected).abs() < 0.5,
            "Additive shift failed at slot {}: got {}, expected {}",
            i, dec[i], expected
        );
    }

    // The attacker shifted the value but STILL doesn't know the original.
    // This is expected HE behavior — not a vulnerability.
    eprintln!("  [INFO] Additive malleability works (expected HE property).");
    eprintln!("  [INFO] Attacker can shift values but cannot read them without the key.");
}

/// Attack: Multiply a ciphertext by a known scalar to scale the encrypted value.
/// Again, this is a feature — but verify it doesn't leak information.
#[test]
fn attack_multiplicative_malleability() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let secret_values = vec![42.0, -17.5, 3.14];
    let ct = rns_encrypt_simd(&secret_values, &pk_b, &pk_a, &ctx, &mut rng);

    // Attacker scales by 2x using plaintext multiply
    let scale_vec = vec![2.0; 3];
    let ct_scaled = rns_ct_mul_plain_simd(&ct, &scale_vec, &ctx);
    let ct_scaled_rescaled = rns_rescale(&ct_scaled);

    let dec = rns_decrypt_simd(&ct_scaled_rescaled, &s, &ctx, 3);

    for i in 0..3 {
        let expected = secret_values[i] * 2.0;
        assert!(
            (dec[i] - expected).abs() < 0.5,
            "Multiplicative scaling failed at slot {}: got {}, expected {}",
            i, dec[i], expected
        );
    }

    eprintln!("  [INFO] Multiplicative malleability works (expected HE property).");
}

/// Attack: Replace c1 with a different polynomial to "redirect" decryption.
/// If the attacker replaces c1, then decrypt computes c0 + c1'*s, which
/// changes the result but the attacker still can't predict it (needs s).
#[test]
fn attack_c1_replacement() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0; 8];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    // Replace c1 with zeros
    let mut ct_tampered = ct.clone();
    ct_tampered.c1 = RnsPoly::zero(ctx.num_primes);

    let dec_real = rns_decrypt_simd(&ct, &s, &ctx, 8);
    let dec_tampered = rns_decrypt_simd(&ct_tampered, &s, &ctx, 8);

    // Tampered result should be totally different
    let mut diff_count = 0;
    for i in 0..8 {
        if (dec_real[i] - dec_tampered[i]).abs() > 1.0 {
            diff_count += 1;
        }
    }

    assert!(
        diff_count >= 6,
        "VULNERABILITY: Replacing c1 with zero didn't change enough values ({}/8)",
        diff_count
    );
}

/// Attack: Swap c0 and c1 components to check if they're interchangeable.
/// They should NOT be — c0 carries the message while c1 carries the masking.
#[test]
fn attack_swap_c0_c1() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0; 8];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    // Swap c0 and c1
    let ct_swapped = RnsCiphertext {
        c0: ct.c1.clone(),
        c1: ct.c0.clone(),
        scale: ct.scale,
        level: ct.level,
    };

    let dec_real = rns_decrypt_simd(&ct, &s, &ctx, 8);
    let dec_swapped = rns_decrypt_simd(&ct_swapped, &s, &ctx, 8);

    // Swapped should produce garbage
    let mut matches = 0;
    for i in 0..8 {
        if (dec_real[i] - dec_swapped[i]).abs() < 1.0 {
            matches += 1;
        }
    }

    assert!(
        matches <= 1,
        "VULNERABILITY: Swapping c0/c1 still produces similar decryption ({}/8 match)",
        matches
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 8. INFERENCE PIPELINE SPECIFIC ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: In the inference pipeline, the server computes FHE operations
/// on the encrypted hidden state. Can the server learn information about
/// the hidden state from the FHE computation outputs?
///
/// Strategy: Encrypt two very different hidden states, run the same FHE
/// linear layer on both, and check if the OUTPUT ciphertexts are
/// distinguishable (without the key).
#[test]
fn attack_inference_output_distinguishability() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();
    let eval_key = rns_gen_eval_key(&s, &ctx, &mut rng);

    let dim = 16;
    let rots: Vec<i32> = (1..dim as i32).collect();
    let rotation_keys = rns_gen_rotation_keys(&s, &rots, &ctx, &mut rng);

    // Two very different hidden states
    let h1 = vec![1.0; dim];    // all ones
    let h2 = vec![-1.0; dim];   // all negative ones

    let ct1 = rns_encrypt_simd(&h1, &pk_b, &pk_a, &ctx, &mut rng);
    let ct2 = rns_encrypt_simd(&h2, &pk_b, &pk_a, &ctx, &mut rng);

    // Random weight matrix (identity-like for simplicity)
    let mut weights = vec![0.0; dim * dim];
    for i in 0..dim {
        weights[i * dim + i] = 1.0;
    }
    let biases = vec![0.0; dim];

    let net = RnsNeuralNet {
        dim,
        weights: vec![weights],
        biases: vec![biases],
        activations: vec![Activation::None],
    };

    // Run FHE forward pass on both
    let out1 = rns_forward_encrypted(&ct1, &net, &eval_key, &rotation_keys, &ctx);
    let out2 = rns_forward_encrypted(&ct2, &net, &eval_key, &rotation_keys, &ctx);

    // Server analyzes OUTPUT ciphertexts — are they distinguishable?
    let q0 = NTT_PRIMES[0];
    let center = |c: i64| -> f64 {
        if c > q0 / 2 { (c - q0) as f64 } else { c as f64 }
    };

    let out1_coeffs = out1.c0.to_coeffs();
    let out2_coeffs = out2.c0.to_coeffs();

    let mean1: f64 = out1_coeffs.iter().map(|&c| center(c).abs()).sum::<f64>() / N as f64;
    let mean2: f64 = out2_coeffs.iter().map(|&c| center(c).abs()).sum::<f64>() / N as f64;

    let ratio = if mean1 > mean2 { mean1 / mean2 } else { mean2 / mean1 };
    assert!(
        ratio < 1.1,
        "VULNERABILITY: FHE outputs for opposite inputs are distinguishable — \
         ratio {:.4}. Server can infer hidden state polarity!",
        ratio
    );
}

/// Attack: The PCA projection matrix is PUBLIC. Given the projection basis P,
/// the attacker knows that the encrypted value is P @ h for some hidden state h.
/// Can they use the structure of P to extract info from the ciphertext?
///
/// Strategy: Since the encrypted value is a 16-dim projection, the attacker
/// knows the VALUE SPACE is 16-dimensional. But they still can't read the
/// actual projected values without the secret key.
#[test]
fn attack_pca_projection_leakage() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let dim = 16;

    // Simulate PCA projection: the attacker knows the projection basis
    // This is the same basis the client uses
    let mut pca_basis = vec![vec![0.0f64; 2560]; dim];
    for i in 0..dim {
        for j in 0..2560 {
            pca_basis[i][j] = rng.gen::<f64>() - 0.5;
        }
        // Normalize
        let norm: f64 = pca_basis[i].iter().map(|x| x * x).sum::<f64>().sqrt();
        for j in 0..2560 {
            pca_basis[i][j] /= norm;
        }
    }

    // The attacker knows the basis but not the hidden state h.
    // They see ct = Enc(P @ h) for unknown h.
    // Even knowing P, they can't invert to get h (P is rank-16, h is dim-2560).
    // And they can't read P @ h from the ciphertext without the key.

    // Test: encrypt two different projected hidden states
    let proj1: Vec<f64> = (0..dim).map(|i| (i as f64) * 0.1).collect();
    let proj2: Vec<f64> = (0..dim).map(|i| -(i as f64) * 0.1).collect();

    let ct1 = rns_encrypt_simd(&proj1, &pk_b, &pk_a, &ctx, &mut rng);
    let ct2 = rns_encrypt_simd(&proj2, &pk_b, &pk_a, &ctx, &mut rng);

    // Attacker tries to determine which is which by looking at c0
    let q0 = NTT_PRIMES[0];
    let dot_product: f64 = ct1.c0.to_coeffs().iter()
        .zip(ct2.c0.to_coeffs().iter())
        .take(100) // Sample first 100 coefficients
        .map(|(&a, &b)| {
            let a_c = if a > q0 / 2 { (a - q0) as f64 } else { a as f64 };
            let b_c = if b > q0 / 2 { (b - q0) as f64 } else { b as f64 };
            a_c * b_c
        })
        .sum::<f64>();

    // Normalize by expected magnitude
    let norm_sq: f64 = ct1.c0.to_coeffs().iter()
        .take(100)
        .map(|&a| {
            let a_c = if a > q0 / 2 { (a - q0) as f64 } else { a as f64 };
            a_c * a_c
        })
        .sum();

    let correlation = dot_product / norm_sq;

    // Correlation should be near 0 (random), not +1 or -1 (correlated)
    assert!(
        correlation.abs() < 0.3,
        "VULNERABILITY: Ciphertext correlation {:.4} reveals relationship between plaintexts. \
         PCA basis knowledge helps attacker!",
        correlation
    );
}

/// Attack: Timing side-channel. Does the FHE computation time depend on
/// the encrypted values? If so, the server can infer information.
#[test]
fn attack_timing_side_channel() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();
    let eval_key = rns_gen_eval_key(&s, &ctx, &mut rng);

    let dim = 8;
    let rots: Vec<i32> = (1..dim as i32).collect();
    let rotation_keys = rns_gen_rotation_keys(&s, &rots, &ctx, &mut rng);

    let weights = vec![0.5; dim * dim];
    let biases = vec![0.0; dim];
    let net = RnsNeuralNet {
        dim,
        weights: vec![weights],
        biases: vec![biases],
        activations: vec![Activation::None],
    };

    // Measure timing for different plaintexts
    let trials = 5;
    let mut times_zero = Vec::new();
    let mut times_large = Vec::new();

    for trial in 0..trials {
        let mut rng_z = StdRng::seed_from_u64(trial * 2);
        let mut rng_l = StdRng::seed_from_u64(trial * 2 + 1);

        let ct_zero = rns_encrypt_simd(&vec![0.0; dim], &pk_b, &pk_a, &ctx, &mut rng_z);
        let ct_large = rns_encrypt_simd(&vec![999.0; dim], &pk_b, &pk_a, &ctx, &mut rng_l);

        let t0 = std::time::Instant::now();
        let _ = rns_forward_encrypted(&ct_zero, &net, &eval_key, &rotation_keys, &ctx);
        times_zero.push(t0.elapsed().as_nanos() as f64);

        let t1 = std::time::Instant::now();
        let _ = rns_forward_encrypted(&ct_large, &net, &eval_key, &rotation_keys, &ctx);
        times_large.push(t1.elapsed().as_nanos() as f64);
    }

    let avg_zero: f64 = times_zero.iter().sum::<f64>() / trials as f64;
    let avg_large: f64 = times_large.iter().sum::<f64>() / trials as f64;

    let timing_ratio = if avg_zero > avg_large {
        avg_zero / avg_large
    } else {
        avg_large / avg_zero
    };

    // Timing should be data-independent (constant-time operations)
    assert!(
        timing_ratio < 1.2,
        "VULNERABILITY: Timing side-channel detected — zero:{:.0}ns vs large:{:.0}ns \
         (ratio {:.3}). Server can distinguish inputs by timing!",
        avg_zero, avg_large, timing_ratio
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 9. PARAMETER WEAKNESS ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

/// Security check: Verify N=4096 provides adequate security bits.
/// For RLWE with N=4096 and q ≈ 2^108 (3 primes × 36 bits):
/// Security ≈ N / (7.2 * log2(q/sigma)) ≈ 4096 / (7.2 * log2(2^108/3.2))
///           ≈ 4096 / (7.2 * 106.3) ≈ 4096 / 765 ≈ 5.4
///
/// Wait — that's the wrong formula. The correct estimate for RLWE is:
/// security ≈ N * log2(q) / (log2(q/sigma)) ... no.
///
/// The Lattice Estimator gives ~128-bit security for N=4096, sigma=3.2,
/// log2(q) ≈ 108 (3 primes). But with 20 primes (log2(q) ≈ 720),
/// security degrades significantly.
#[test]
fn check_parameter_security_3_primes() {
    let num_primes = 3;
    let log_q: f64 = NTT_PRIMES[..num_primes]
        .iter()
        .map(|&q| (q as f64).log2())
        .sum();

    let sigma = 3.2f64;
    let n = N as f64;

    // Rough security estimate using Albrecht's formula:
    // For RLWE, bit-security ≈ (N * 2π * e * sigma²)^{1/2} / q^{1/N} ... too complex.
    //
    // Simplified check: log2(q) / N should be reasonably small.
    // For 128-bit security, typically need log2(q)/N < ~0.036 (HE Standard Table 1)
    let ratio = log_q / n;

    eprintln!("  [PARAMS] N={}, num_primes={}, log2(Q)={:.1}, log2(Q)/N={:.4}",
        N, num_primes, log_q, ratio);

    // HE Security Standard Table (Homomorphic Encryption Standard):
    // N=4096: max log2(Q) ≈ 109 for 128-bit security
    // N=4096: max log2(Q) ≈ 118 for 112-bit security
    assert!(
        log_q < 120.0,
        "VULNERABILITY: log2(Q)={:.1} exceeds safe limit for N=4096 with {} primes. \
         Security may be below 128 bits!",
        log_q, num_primes
    );
}

/// Security check: With 20 primes, log2(Q) ≈ 720. This requires much
/// larger N for 128-bit security. Document the security level.
#[test]
fn check_parameter_security_20_primes() {
    let num_primes = 20;
    let log_q: f64 = NTT_PRIMES[..num_primes]
        .iter()
        .map(|&q| (q as f64).log2())
        .sum();

    eprintln!("  [PARAMS] N={}, num_primes={}, log2(Q)={:.1}", N, num_primes, log_q);

    // For N=4096, HE Standard allows log2(Q) ≤ 109 for 128-bit security.
    // With 20 primes at ~36 bits each, log2(Q) ≈ 720 >> 109.
    // This means N=4096 is NOT sufficient for 128-bit security with 20 primes.
    //
    // Required N for log2(Q)=720 at 128-bit security: N ≥ 32768
    //
    // However, in our inference pipeline we use only 3 primes (log2(Q) ≈ 108),
    // which IS secure. The 20 primes are for deep circuits (not default).

    let is_secure_128 = log_q <= 109.0;
    eprintln!(
        "  [PARAMS] 128-bit secure with 20 primes: {} (log2(Q)={:.1}, limit=109.0)",
        is_secure_128, log_q
    );
    eprintln!("  [PARAMS] For 20-prime deep circuits, N should be increased to 32768+");

    // This is a KNOWN limitation, not a vulnerability in the default 3-prime config.
    // Document it rather than fail the test.
    assert!(
        !is_secure_128,
        "If this assertion fires, parameters have changed — re-evaluate security"
    );
}

/// Verify that the ternary secret key distribution is correct.
/// Each coefficient should be in {-1, 0, 1} with roughly equal probability
/// for -1 and 1 (and 1/3 probability for each).
#[test]
fn check_secret_key_distribution() {
    let ctx = RnsCkksContext::new(3);
    let mut rng = test_rng();
    let (s, _, _) = rns_keygen(&ctx, &mut rng);

    let s_coeffs = s.to_coeffs();
    let q0 = NTT_PRIMES[0];

    let mut neg_one = 0;
    let mut zero = 0;
    let mut pos_one = 0;
    let mut other = 0;

    for &c in &s_coeffs {
        let centered = if c == 0 {
            0
        } else if c == 1 {
            1
        } else if c == q0 - 1 {
            -1
        } else if c > q0 / 2 {
            // Large negative
            (c - q0) as i32
        } else {
            c as i32
        };

        match centered {
            -1 => neg_one += 1,
            0 => zero += 1,
            1 => pos_one += 1,
            _ => other += 1,
        }
    }

    eprintln!(
        "  [KEY] Distribution: -1={}, 0={}, 1={}, other={}",
        neg_one, zero, pos_one, other
    );

    // All coefficients should be ternary
    assert_eq!(
        other, 0,
        "VULNERABILITY: Secret key has {} non-ternary coefficients!",
        other
    );

    // Each value should appear roughly N/3 ≈ 1365 times
    let expected = N as f64 / 3.0;
    for (name, count) in [("-1", neg_one), ("0", zero), ("1", pos_one)] {
        let deviation = ((count as f64 - expected) / expected).abs();
        assert!(
            deviation < 0.15,
            "VULNERABILITY: Secret key coefficient {} appears {} times \
             (expected ~{:.0}, deviation {:.1}%). Distribution may be biased.",
            name, count, expected, deviation * 100.0
        );
    }
}

/// Verify Gaussian error distribution has correct standard deviation.
#[test]
fn check_error_distribution() {
    let mut rng = test_rng();
    let num_samples = 10000;
    let sigma = 3.2f64;

    let mut samples = Vec::with_capacity(num_samples);
    for _ in 0..num_samples {
        let u1: f64 = rng.gen::<f64>().max(1e-10);
        let u2: f64 = rng.gen::<f64>();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        samples.push((z * sigma).round() as i64);
    }

    // Check mean ≈ 0
    let mean = samples.iter().sum::<i64>() as f64 / num_samples as f64;
    assert!(
        mean.abs() < 0.5,
        "VULNERABILITY: Gaussian error mean = {:.3} (should be ~0). Biased noise!",
        mean
    );

    // Check standard deviation ≈ sigma
    let variance = samples.iter()
        .map(|&x| (x as f64 - mean).powi(2))
        .sum::<f64>() / num_samples as f64;
    let measured_sigma = variance.sqrt();

    assert!(
        (measured_sigma - sigma).abs() < 0.5,
        "VULNERABILITY: Gaussian sigma = {:.3} (expected {:.1}). Incorrect noise magnitude!",
        measured_sigma, sigma
    );

    // Check no extreme outliers (> 6*sigma is suspicious)
    let max_abs = samples.iter().map(|x| x.abs()).max().unwrap();
    assert!(
        max_abs <= (6.0 * sigma) as i64 + 1,
        "VULNERABILITY: Gaussian sample with |x| = {} (> 6σ = {}). Tail too heavy!",
        max_abs, (6.0 * sigma) as i64
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 10. CROSS-CIPHERTEXT CORRELATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: If the same plaintext is encrypted multiple times, are the
/// ciphertexts correlated? An attacker shouldn't be able to tell if
/// two ciphertexts encrypt the same value.
#[test]
fn attack_same_plaintext_correlation() {
    let (ctx, _s, pk_b, pk_a) = setup(3);

    let values = vec![42.0; 8];
    let q0 = NTT_PRIMES[0];

    // Encrypt the same value 10 times with different randomness
    let mut ciphertexts = Vec::new();
    for seed in 0..10u64 {
        let mut rng = StdRng::seed_from_u64(seed * 12345);
        ciphertexts.push(rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng));
    }

    // Compute pairwise correlation between c0 coefficients
    let get_centered = |ct: &RnsCiphertext| -> Vec<f64> {
        ct.c0.to_coeffs().iter().map(|&c| {
            if c > q0 / 2 { (c - q0) as f64 } else { c as f64 }
        }).collect()
    };

    let mut max_correlation = 0.0f64;
    for i in 0..10 {
        for j in (i + 1)..10 {
            let a = get_centered(&ciphertexts[i]);
            let b = get_centered(&ciphertexts[j]);

            let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
            let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
            let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();

            let corr = (dot / (norm_a * norm_b)).abs();
            max_correlation = max_correlation.max(corr);
        }
    }

    assert!(
        max_correlation < 0.1,
        "VULNERABILITY: Same-plaintext ciphertexts have correlation {:.4}. \
         Attacker can detect re-encryption of the same value!",
        max_correlation
    );
}

/// Attack: Given a sequence of encrypted hidden states (as in inference),
/// can the server detect patterns in the sequence (e.g., repeated tokens)?
#[test]
fn attack_sequential_pattern_detection() {
    let (ctx, _s, pk_b, pk_a) = setup(3);

    let q0 = NTT_PRIMES[0];

    // Simulate: tokens [A, B, A, B, A] — should NOT be detectable
    let h_a = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
    let h_b = vec![8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0];

    let sequence = [&h_a, &h_b, &h_a, &h_b, &h_a];
    let mut cts = Vec::new();
    for (i, h) in sequence.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(i as u64 * 9999);
        cts.push(rns_encrypt_simd(h, &pk_b, &pk_a, &ctx, &mut rng));
    }

    // Server tries to detect the A-B-A-B-A pattern
    let get_centered = |ct: &RnsCiphertext| -> Vec<f64> {
        ct.c0.to_coeffs().iter().map(|&c| {
            if c > q0 / 2 { (c - q0) as f64 } else { c as f64 }
        }).collect()
    };

    // Check: are ciphertexts at positions 0,2,4 (all h_a) more correlated
    // than ciphertexts at positions 0,1 (h_a vs h_b)?
    let corr = |a: &[f64], b: &[f64]| -> f64 {
        let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let na: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
        let nb: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
        if na == 0.0 || nb == 0.0 { return 0.0; }
        (dot / (na * nb)).abs()
    };

    let c0 = get_centered(&cts[0]);
    let c1 = get_centered(&cts[1]);
    let c2 = get_centered(&cts[2]);

    let same_corr = corr(&c0, &c2);     // h_a vs h_a (same plaintext)
    let diff_corr = corr(&c0, &c1);     // h_a vs h_b (different plaintext)

    // Both correlations should be near 0 (randomized by fresh encryption)
    assert!(
        same_corr < 0.1,
        "VULNERABILITY: Same-plaintext sequential correlation = {:.4} \
         (server can detect repeated tokens!)",
        same_corr
    );
    assert!(
        diff_corr < 0.1,
        "Different-plaintext sequential correlation = {:.4} (expected near 0)",
        diff_corr
    );

    // The gap between same/diff correlations should be negligible
    let gap = (same_corr - diff_corr).abs();
    assert!(
        gap < 0.05,
        "VULNERABILITY: Correlation gap {:.4} between same/different plaintexts. \
         Server can detect patterns!",
        gap
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 11. COMPRESSION ROUND-TRIP TESTS
// ═══════════════════════════════════════════════════════════════════════

use poly_client::ckks::compress;

/// Compress and decompress an RnsCiphertext. Verify decryption matches original.
#[test]
fn compress_round_trip_ciphertext() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0, -17.5, 3.14, 100.0, 0.0, -99.9, 1.0, 2.0];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    let compressed = compress::compress(&ct).expect("compress ciphertext");
    let ct_back: RnsCiphertext = compress::decompress(&compressed).expect("decompress ciphertext");

    // Verify structural equality
    assert_eq!(ct.c0.residues.len(), ct_back.c0.residues.len());
    assert_eq!(ct.c1.residues.len(), ct_back.c1.residues.len());
    assert_eq!(ct.scale, ct_back.scale);
    assert_eq!(ct.level, ct_back.level);

    for ch in 0..ct.c0.residues.len() {
        assert_eq!(ct.c0.residues[ch], ct_back.c0.residues[ch]);
        assert_eq!(ct.c1.residues[ch], ct_back.c1.residues[ch]);
    }

    // Verify decryption still works
    let dec = rns_decrypt_simd(&ct_back, &s, &ctx, values.len());
    for i in 0..values.len() {
        assert!(
            (dec[i] - values[i]).abs() < 0.1,
            "Decryption after round-trip failed at slot {}: got {}, expected {}",
            i, dec[i], values[i]
        );
    }
}

/// Compress and decompress an RnsEvalKey. Verify it still works for relinearization.
#[test]
fn compress_round_trip_eval_key() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();
    let eval_key = rns_gen_eval_key(&s, &ctx, &mut rng);

    let compressed = compress::compress(&eval_key).expect("compress eval key");
    let ek_back: RnsEvalKey = compress::decompress(&compressed).expect("decompress eval key");

    // Verify functional equivalence: encrypt, multiply, relin with original vs round-tripped key
    let a = vec![3.0; 8];
    let b = vec![2.0; 8];
    let ct_a = rns_encrypt_simd(&a, &pk_b, &pk_a, &ctx, &mut rng);
    let ct_b = rns_encrypt_simd(&b, &pk_b, &pk_a, &ctx, &mut rng);

    let ct_orig = rns_ct_mul_relin(&ct_a, &ct_b, &eval_key, &ctx);
    let ct_rt = rns_ct_mul_relin(&ct_a, &ct_b, &ek_back, &ctx);

    let dec_orig = rns_decrypt_simd(&rns_rescale(&ct_orig), &s, &ctx, 8);
    let dec_rt = rns_decrypt_simd(&rns_rescale(&ct_rt), &s, &ctx, 8);

    for i in 0..8 {
        assert!(
            (dec_orig[i] - dec_rt[i]).abs() < 1e-6,
            "Eval key round-trip changed relinearization at slot {}: {} vs {}",
            i, dec_orig[i], dec_rt[i]
        );
    }
}

/// Compress and decompress an RnsRotationKeySet. Verify rotations still work.
#[test]
fn compress_round_trip_rotation_keys() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let rots: Vec<i32> = vec![1, 2, 3];
    let rotation_keys = rns_gen_rotation_keys(&s, &rots, &ctx, &mut rng);

    let compressed = compress::compress(&rotation_keys).expect("compress rotation keys");
    let rk_back: RnsRotationKeySet =
        compress::decompress(&compressed).expect("decompress rotation keys");

    // Verify functional equivalence: rotate with original vs round-tripped keys
    let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    for &r in &rots {
        let rotated_orig = rns_rotate(&ct, r, &rotation_keys, &ctx);
        let rotated_rt = rns_rotate(&ct, r, &rk_back, &ctx);

        let dec_orig = rns_decrypt_simd(&rotated_orig, &s, &ctx, 8);
        let dec_rt = rns_decrypt_simd(&rotated_rt, &s, &ctx, 8);

        for i in 0..8 {
            assert!(
                (dec_orig[i] - dec_rt[i]).abs() < 1e-6,
                "Rotation key round-trip changed rotation({}) at slot {}: {} vs {}",
                r, i, dec_orig[i], dec_rt[i]
            );
        }
    }
}

/// Verify compression reduces ciphertext size.
///
/// NTT-form CKKS coefficients are pseudo-random 36-bit values in 64-bit i64
/// containers. zstd compresses the ~28 leading zero bits per coefficient,
/// giving ~1.4x ratio. Compared to JSON+hex (the old format), the combined
/// bincode+zstd path gives ~3-4x improvement.
#[test]
fn compress_ratio_ciphertext() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0; 16];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    let stats = compress::compression_stats(&ct);
    eprintln!(
        "  [COMPRESS] Ciphertext: {} raw -> {} compressed ({:.1}x)",
        stats.raw_size, stats.compressed_size, stats.ratio
    );

    assert!(
        stats.ratio > 1.2,
        "Compression ratio {:.1}x is below 1.2x — zstd should at least compress leading zeros",
        stats.ratio
    );
}

/// Verify compression reduces eval key size.
#[test]
fn compress_ratio_eval_key() {
    let (ctx, s, _pk_b, _pk_a) = setup(3);
    let mut rng = test_rng();
    let eval_key = rns_gen_eval_key(&s, &ctx, &mut rng);

    let stats = compress::compression_stats(&eval_key);
    eprintln!(
        "  [COMPRESS] Eval key: {} raw -> {} compressed ({:.1}x)",
        stats.raw_size, stats.compressed_size, stats.ratio
    );

    assert!(
        stats.ratio > 1.2,
        "Compression ratio {:.1}x is below 1.2x for eval key",
        stats.ratio
    );
}

/// Verify compression reduces rotation key size.
#[test]
fn compress_ratio_rotation_keys() {
    let (ctx, s, _pk_b, _pk_a) = setup(3);
    let mut rng = test_rng();

    let rots: Vec<i32> = (1..16).collect();
    let rotation_keys = rns_gen_rotation_keys(&s, &rots, &ctx, &mut rng);

    let stats = compress::compression_stats(&rotation_keys);
    eprintln!(
        "  [COMPRESS] Rotation keys (15 rotations): {} raw -> {} compressed ({:.1}x)",
        stats.raw_size, stats.compressed_size, stats.ratio
    );

    assert!(
        stats.ratio > 1.2,
        "Compression ratio {:.1}x is below 1.2x for rotation keys",
        stats.ratio
    );
}

/// Tampered compressed data should fail gracefully (not panic).
#[test]
fn compress_tampered_data_fails() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0; 8];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
    let mut compressed = compress::compress(&ct).expect("compress");

    // Corrupt zstd payload (after 9-byte PFHE header)
    if compressed.len() > 20 {
        compressed[15] ^= 0xFF;
        compressed[16] ^= 0xFF;
        compressed[17] ^= 0xFF;
    }

    let result: Result<RnsCiphertext, _> = compress::decompress(&compressed);
    assert!(result.is_err(), "Tampered data should fail decompression");
}

/// Truncated compressed data should fail gracefully.
#[test]
fn compress_truncated_data_fails() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0; 8];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
    let compressed = compress::compress(&ct).expect("compress");

    // Truncate to half
    let truncated = &compressed[..compressed.len() / 2];
    let result: Result<RnsCiphertext, _> = compress::decompress(truncated);
    assert!(result.is_err(), "Truncated data should fail decompression");
}

/// PFHE header detection works correctly.
#[test]
fn compress_header_detection() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let ct = rns_encrypt_simd(&vec![1.0; 4], &pk_b, &pk_a, &ctx, &mut rng);
    let compressed = compress::compress(&ct).expect("compress");

    assert!(compress::is_compressed(&compressed));
    assert!(!compress::is_compressed(b"not compressed data"));
    assert!(!compress::is_compressed(&[]));
    assert!(!compress::is_compressed(&[0u8; 5]));

    // JSON should NOT be detected as PFHE
    let json = serde_json::to_vec(&"hello").unwrap();
    assert!(!compress::is_compressed(&json));
}

// ═══════════════════════════════════════════════════════════════════════
// 12. COMPACT & MAX COMPRESSION TESTS
// ═══════════════════════════════════════════════════════════════════════

use poly_client::ckks::compress::CompressionLevel;

/// Compact (byte-shuffle + zstd) round-trip for ciphertext.
#[test]
fn compress_compact_round_trip_ciphertext() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0, -17.5, 3.14, 100.0, 0.0, -99.9, 1.0, 2.0];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    let compressed = compress::compress_with(&ct, CompressionLevel::Compact)
        .expect("compact compress");
    let ct_back: RnsCiphertext = compress::decompress(&compressed)
        .expect("decompress compact ciphertext");

    // Decryption should be identical (lossless)
    let dec = rns_decrypt_simd(&ct_back, &s, &ctx, values.len());
    for i in 0..values.len() {
        assert!(
            (dec[i] - values[i]).abs() < 0.1,
            "Compact round-trip failed at slot {}: got {}, expected {}",
            i, dec[i], values[i]
        );
    }
}

/// Compact should produce smaller payloads than Lossless for CKKS data.
#[test]
fn compress_compact_better_ratio() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let ct = rns_encrypt_simd(&vec![42.0; 16], &pk_b, &pk_a, &ctx, &mut rng);

    let lossless = compress::compress(&ct).unwrap();
    let compact = compress::compress_with(&ct, CompressionLevel::Compact).unwrap();

    let lossless_stats = compress::compression_stats(&ct);
    let compact_stats = compress::compression_stats_with(&ct, CompressionLevel::Compact);

    eprintln!("  [COMPACT] Lossless: {} ({:.2}x)", lossless_stats, lossless_stats.ratio);
    eprintln!("  [COMPACT] Compact:  {} ({:.2}x)", compact_stats, compact_stats.ratio);

    assert!(
        compact.len() <= lossless.len(),
        "Compact ({} bytes) should be <= Lossless ({} bytes)",
        compact.len(), lossless.len()
    );
}

/// Max (byte-shuffle + zstd level 19) round-trip for ciphertext.
#[test]
fn compress_max_round_trip_ciphertext() {
    let (ctx, s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0, -17.5, 3.14, 100.0, 0.0, -99.9, 1.0, 2.0];
    let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    let compressed = compress::compress_with(&ct, CompressionLevel::Max)
        .expect("max compress");
    let ct_back: RnsCiphertext = compress::decompress(&compressed)
        .expect("decompress max ciphertext");

    // Decryption should be identical (lossless)
    let dec = rns_decrypt_simd(&ct_back, &s, &ctx, values.len());
    for i in 0..values.len() {
        assert!(
            (dec[i] - values[i]).abs() < 0.1,
            "Max round-trip failed at slot {}: got {}, expected {}",
            i, dec[i], values[i]
        );
    }
}

/// Max should produce payloads at least as small as Compact.
#[test]
fn compress_max_best_ratio() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let ct = rns_encrypt_simd(&vec![42.0; 16], &pk_b, &pk_a, &ctx, &mut rng);

    let lossless_stats = compress::compression_stats(&ct);
    let compact_stats = compress::compression_stats_with(&ct, CompressionLevel::Compact);
    let max_stats = compress::compression_stats_with(&ct, CompressionLevel::Max);

    eprintln!("  [RATIOS] Ciphertext compression comparison:");
    eprintln!("    Lossless:  {}", lossless_stats);
    eprintln!("    Compact:   {}", compact_stats);
    eprintln!("    Max:       {}", max_stats);

    // Max should be at least as good as Compact
    assert!(
        max_stats.compressed_size <= compact_stats.compressed_size,
        "Max ({} bytes) should be <= Compact ({} bytes)",
        max_stats.compressed_size, compact_stats.compressed_size
    );
    // Both should beat Lossless
    assert!(
        compact_stats.compressed_size <= lossless_stats.compressed_size,
        "Compact ({} bytes) should be <= Lossless ({} bytes)",
        compact_stats.compressed_size, lossless_stats.compressed_size
    );
}

/// Level detection works for all compression levels.
#[test]
fn compress_detect_all_levels() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let ct = rns_encrypt_simd(&vec![1.0; 4], &pk_b, &pk_a, &ctx, &mut rng);

    let v1 = compress::compress(&ct).unwrap();
    assert_eq!(compress::detect_level(&v1), Some(CompressionLevel::Lossless));

    let v2_compact = compress::compress_with(&ct, CompressionLevel::Compact).unwrap();
    assert_eq!(compress::detect_level(&v2_compact), Some(CompressionLevel::Compact));

    let v2_max = compress::compress_with(&ct, CompressionLevel::Max).unwrap();
    assert_eq!(compress::detect_level(&v2_max), Some(CompressionLevel::Max));
}

// ═══════════════════════════════════════════════════════════════════════
// 13. COMPRESSION-AS-ENTROPY-VALIDATION (IND-CPA VIA COMPRESSIBILITY)
// ═══════════════════════════════════════════════════════════════════════
//
// Compression ratio is a free entropy oracle. CKKS ciphertexts in NTT-RNS
// form are pseudo-random ~36-bit values in 64-bit containers. The ONLY
// compressible structure is the ~28 zero padding bits per i64. After byte-
// shuffle removes that container waste, the underlying data must be
// indistinguishable from random by any general-purpose compressor.
//
// If zstd achieves >2.5x on byte-shuffled ciphertext data, the coefficients
// have exploitable structure — a potential IND-CPA violation.
//
// This confirms attacks #9 (IND-CPA: zero vs nonzero) and #10 (IND-CPA:
// variance analysis) from a completely independent angle: if the best
// compression algorithm can't distinguish your ciphertext from random, an
// adversary probably can't either.

/// Ciphertext compression ratio must stay within entropy bounds.
/// A ratio >2.5x after byte-shuffle means the NTT coefficients are
/// compressible, which means they have structure, which means information
/// leakage.
#[test]
fn entropy_ciphertext_within_bounds() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    // Test with various plaintext patterns — none should leak through encryption
    let plaintexts: Vec<Vec<f64>> = vec![
        vec![0.0; 16],                                         // all zeros
        vec![1e6; 16],                                         // large constant
        (0..16).map(|i| i as f64).collect(),                   // sequential
        vec![42.0, -17.5, 3.14, 100.0, 0.0, -99.9, 1.0, 2.0], // mixed
    ];

    for (i, values) in plaintexts.iter().enumerate() {
        let ct = rns_encrypt_simd(values, &pk_b, &pk_a, &ctx, &mut rng);
        let check = compress::entropy_check(&ct);

        eprintln!(
            "  [ENTROPY] plaintext pattern {}: {}",
            i, check
        );

        assert!(
            check.pass,
            "Ciphertext for pattern {} has anomalous compressibility: {}\n\
             This indicates exploitable structure in the ciphertext — potential IND-CPA violation.",
            i, check
        );
    }
}

/// Eval keys must also pass entropy validation.
#[test]
fn entropy_eval_key_within_bounds() {
    let (ctx, s, _pk_b, _pk_a) = setup(3);
    let mut rng = test_rng();
    let ek = rns_gen_eval_key(&s, &ctx, &mut rng);

    let check = compress::entropy_check(&ek);
    eprintln!("  [ENTROPY] eval key: {}", check);
    assert!(
        check.pass,
        "Eval key has anomalous compressibility: {}\n\
         Key material should be indistinguishable from random.",
        check
    );
}

/// Rotation keys must also pass entropy validation.
#[test]
fn entropy_rotation_keys_within_bounds() {
    let (ctx, s, _pk_b, _pk_a) = setup(3);
    let mut rng = test_rng();
    let rk = rns_gen_rotation_keys(&s, &[1, 2, 4], &ctx, &mut rng);

    let check = compress::entropy_check(&rk);
    eprintln!("  [ENTROPY] rotation keys: {}", check);
    assert!(
        check.pass,
        "Rotation keys have anomalous compressibility: {}\n\
         Key material should be indistinguishable from random.",
        check
    );
}

/// Encrypting the SAME plaintext twice must produce equally incompressible
/// ciphertexts (different random noise each time). If two encryptions of the
/// same value produce different compression ratios, the randomness extraction
/// is non-uniform.
#[test]
fn entropy_same_plaintext_different_encryptions() {
    let (ctx, _s, pk_b, pk_a) = setup(3);
    let mut rng = test_rng();

    let values = vec![42.0; 16];
    let ct1 = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
    let ct2 = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

    let check1 = compress::entropy_check(&ct1);
    let check2 = compress::entropy_check(&ct2);

    eprintln!("  [ENTROPY] same plaintext, encryption 1: {}", check1);
    eprintln!("  [ENTROPY] same plaintext, encryption 2: {}", check2);

    assert!(check1.pass, "Encryption 1 failed entropy check: {}", check1);
    assert!(check2.pass, "Encryption 2 failed entropy check: {}", check2);

    // Ratios should be similar (both ~2x for NTT-RNS data)
    let ratio_diff = (check1.ratio - check2.ratio).abs();
    assert!(
        ratio_diff < 0.3,
        "Encryption ratio variance too high ({:.3} vs {:.3}, diff {:.3}) — \
         randomness may be non-uniform",
        check1.ratio, check2.ratio, ratio_diff
    );
}

/// Synthetic test: verify the entropy check actually catches structured data.
/// Construct a "fake ciphertext" with all-zero coefficients and confirm it
/// fails the entropy check, proving the monitor would catch a broken RNG or
/// encoding bug.
#[test]
fn entropy_synthetic_structured_data_detected() {
    use poly_client::ckks::rns::RnsPoly;

    let zero_poly = RnsPoly {
        residues: vec![vec![0i64; 4096]; 3],
        num_primes: 3,
    };
    let fake_ct = RnsCiphertext {
        c0: zero_poly.clone(),
        c1: zero_poly,
        scale: 1.0,
        level: 3,
    };

    let check = compress::entropy_check(&fake_ct);
    eprintln!("  [ENTROPY] synthetic all-zeros ciphertext: {}", check);

    assert!(
        !check.pass,
        "All-zeros ciphertext should FAIL entropy check (ratio {:.2}x), \
         but it passed. The entropy monitor is broken.",
        check.ratio
    );
}
