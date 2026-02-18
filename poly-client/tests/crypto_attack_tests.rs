//! Cryptographic layer attack tests.
//!
//! Tests security properties of the CKKS implementation by attempting
//! various attacks: ciphertext manipulation, noise injection, wrong-key
//! decryption, statistical bias in sampling, and parameter validation.

#![cfg(feature = "ckks")]

use poly_client::ckks::ciphertext::{decrypt, encrypt, CkksCiphertext};
use poly_client::ckks::encoding::{decode, encode};
use poly_client::ckks::keys::{keygen, CkksSecretKey};
use poly_client::ckks::ntt::{is_prime, mod_inv, mod_pow, NttContext, NTT_PRIMES};
use poly_client::ckks::params::{DECOMP_BASE, DELTA, N, NUM_DIGITS, Q, SIGMA};
use poly_client::ckks::poly::{mod_reduce, Poly};
use poly_client::ckks::sampling::{sample_gaussian, sample_ternary, sample_uniform};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn test_rng() -> StdRng {
    StdRng::seed_from_u64(42)
}

// ═══════════════════════════════════════════════════════════════════════
// 1. CIPHERTEXT MANIPULATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Flip bits in ciphertext c0 polynomial.
/// Expected: Decryption produces garbage (not the original plaintext).
#[test]
fn attack_ciphertext_bit_flip_c0() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![100, 200, 300, 400, 500];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Flip a significant coefficient in c0
    ct.chunks[0].0.coeffs[0] ^= 0x7FFF_FFFF;
    ct.chunks[0].0.coeffs[1] ^= 0x3FFF_FFFF;

    let decrypted = decrypt(&ct, &sk);
    assert_ne!(
        decrypted, tokens,
        "VULNERABILITY: ciphertext manipulation did not affect decryption"
    );
}

/// Attack: Flip bits in ciphertext c1 polynomial.
#[test]
fn attack_ciphertext_bit_flip_c1() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![42, 43, 44];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Corrupt c1
    ct.chunks[0].1.coeffs[0] = Q / 2;
    ct.chunks[0].1.coeffs[1] = -Q / 3;

    let decrypted = decrypt(&ct, &sk);
    assert_ne!(
        decrypted, tokens,
        "VULNERABILITY: c1 manipulation did not affect decryption"
    );
}

/// Attack: Replace ciphertext with all zeros (trivial encryption of zero).
/// Expected: Decryption gives all zeros, not original plaintext.
#[test]
fn attack_ciphertext_zeroed_out() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![100, 200, 300];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Zero out both polynomials
    ct.chunks[0].0 = Poly::zero();
    ct.chunks[0].1 = Poly::zero();

    let decrypted = decrypt(&ct, &sk);
    // Zero ciphertext should decrypt to all zeros
    assert_eq!(
        decrypted,
        vec![0, 0, 0],
        "Zero ciphertext should decrypt to zeros"
    );
    assert_ne!(decrypted, tokens);
}

/// Attack: Inject noise exceeding DELTA/2 to corrupt decryption.
/// CKKS decodes by rounding to nearest DELTA multiple, so noise > DELTA/2
/// pushes the decoded value to an adjacent integer.
#[test]
fn attack_ciphertext_noise_injection() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![42, 43, 44, 45, 46];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Add noise = DELTA (one full unit) to each encoded coefficient.
    // This shifts each decoded token by +1.
    // The decryption noise budget is only DELTA/2, so adding DELTA
    // guarantees corruption.
    for i in 0..tokens.len() {
        ct.chunks[0].0.coeffs[i] = mod_reduce(ct.chunks[0].0.coeffs[i] + DELTA);
    }

    let decrypted = decrypt(&ct, &sk);
    assert_ne!(
        decrypted, tokens,
        "VULNERABILITY: noise exceeding DELTA did not affect decryption"
    );
    // Each token should be shifted by approximately +1
    for i in 0..tokens.len() {
        assert!(
            decrypted[i] == tokens[i] + 1 || decrypted[i] == tokens[i] + 2,
            "Expected token {} shifted to ~{}, got {}",
            tokens[i],
            tokens[i] + 1,
            decrypted[i]
        );
    }
}

/// Attack: Swap c0 and c1 components.
/// Expected: Decryption produces garbage.
#[test]
fn attack_ciphertext_swap_components() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![10, 20, 30];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Swap c0 and c1
    let temp = ct.chunks[0].0.clone();
    ct.chunks[0].0 = ct.chunks[0].1.clone();
    ct.chunks[0].1 = temp;

    let decrypted = decrypt(&ct, &sk);
    assert_ne!(
        decrypted, tokens,
        "VULNERABILITY: swapping c0/c1 did not affect decryption"
    );
}

/// Attack: Negate the ciphertext (should negate the plaintext).
/// This tests homomorphic malleability — not a vulnerability per se,
/// but important to understand for protocol security.
#[test]
fn attack_ciphertext_negation_malleability() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![100, 200, 300];
    let ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Negate both components
    let negated = CkksCiphertext {
        chunks: vec![(ct.chunks[0].0.neg(), ct.chunks[0].1.neg())],
        token_count: ct.token_count,
        scale: ct.scale,
        auth_tag: None,
        key_id: None,
        nonce: None,
    };

    let decrypted = decrypt(&negated, &sk);
    // Negated ciphertext should NOT give the original tokens
    assert_ne!(
        decrypted, tokens,
        "Negated ciphertext should not decrypt to original"
    );
}

/// Attack: Additive ciphertext malleability — add known plaintext to c0.
/// If ct encrypts m, then (c0 + m', c1) encrypts m + m'.
/// This is inherent to CKKS/LWE and must be mitigated at protocol level.
#[test]
fn attack_additive_malleability() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let original = vec![100];
    let ct = encrypt(&original, &pk, &sk, &mut rng);

    // Add an encoded plaintext offset to c0 (known-plaintext attack)
    let offset = encode(&[50]);
    let tampered = CkksCiphertext {
        chunks: vec![(ct.chunks[0].0.add(&offset), ct.chunks[0].1.clone())],
        token_count: ct.token_count,
        scale: ct.scale,
        auth_tag: None,
        key_id: None,
        nonce: None,
    };

    let decrypted = decrypt(&tampered, &sk);
    // This IS a known property of additive HE: decrypted[0] ≈ 150
    // The test documents this as a protocol-level concern
    assert_eq!(
        decrypted[0], 150,
        "Additive malleability: expected 100+50=150, got {}",
        decrypted[0]
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. WRONG-KEY DECRYPTION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Decrypt with a completely different key pair.
#[test]
fn attack_wrong_key_decryption() {
    let mut rng1 = StdRng::seed_from_u64(1);
    let mut rng2 = StdRng::seed_from_u64(99);
    let (pk1, sk1) = keygen(&mut rng1);
    let (_pk2, sk2) = keygen(&mut rng2);

    let tokens = vec![42, 43, 44, 45, 46, 47, 48, 49, 50];
    let ct = encrypt(&tokens, &pk1, &sk1, &mut rng1);

    let wrong = decrypt(&ct, &sk2);
    // Not a single token should match (with overwhelmingly high probability)
    let matches: usize = wrong.iter().zip(tokens.iter()).filter(|(a, b)| a == b).count();
    assert!(
        matches <= 1,
        "VULNERABILITY: wrong key produced {} matching tokens out of {}",
        matches,
        tokens.len()
    );
}

/// Attack: Decrypt with a zero secret key (s = 0).
/// Expected: Only c0 contributes, missing the c1*s term.
#[test]
fn attack_zero_secret_key() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![100, 200, 300];
    let ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Create a fake secret key with all zeros
    let fake_sk = CkksSecretKey { s: Poly::zero() };

    let correct = decrypt(&ct, &sk);
    let wrong = decrypt(&ct, &fake_sk);

    assert_eq!(correct, tokens);
    assert_ne!(
        wrong, tokens,
        "VULNERABILITY: zero secret key decrypts correctly"
    );
}

/// Attack: Use the negative of the correct secret key.
#[test]
fn attack_negated_secret_key() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![42, 100, 999];
    let ct = encrypt(&tokens, &pk, &sk, &mut rng);

    let neg_sk = CkksSecretKey { s: sk.s.neg() };
    let decrypted = decrypt(&ct, &neg_sk);
    assert_ne!(
        decrypted, tokens,
        "VULNERABILITY: negated key decrypts correctly"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. NTT PRIME VALIDATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Verify ALL NTT primes are actually prime (not composite).
/// A composite "prime" would break NTT correctness.
#[test]
fn attack_ntt_prime_primality_exhaustive() {
    for (i, &q) in NTT_PRIMES.iter().enumerate() {
        assert!(
            is_prime(q),
            "CRITICAL: NTT_PRIMES[{}] = {} is NOT prime!",
            i,
            q
        );
    }
}

/// Verify NTT primes satisfy q ≡ 1 (mod 2N) — required for NTT roots to exist.
#[test]
fn attack_ntt_prime_congruence() {
    let two_n = 2 * N as i64;
    for (i, &q) in NTT_PRIMES.iter().enumerate() {
        assert_eq!(
            q % two_n,
            1,
            "CRITICAL: NTT_PRIMES[{}] = {} is not ≡ 1 (mod {})",
            i,
            q,
            two_n
        );
    }
}

/// Verify no two NTT primes are the same (would break CRT reconstruction).
#[test]
fn attack_ntt_prime_uniqueness() {
    for i in 0..NTT_PRIMES.len() {
        for j in (i + 1)..NTT_PRIMES.len() {
            assert_ne!(
                NTT_PRIMES[i], NTT_PRIMES[j],
                "CRITICAL: NTT_PRIMES[{}] == NTT_PRIMES[{}] = {}",
                i, j, NTT_PRIMES[i]
            );
        }
    }
}

/// Verify NTT primitive roots satisfy ψ^N ≡ -1 (mod q) and ψ^(2N) ≡ 1 (mod q).
/// A wrong root would produce incorrect NTT results.
#[test]
fn attack_ntt_root_validity() {
    for &q in &NTT_PRIMES {
        let ctx = NttContext::new(q);

        // ψ^N should be -1 mod q
        let psi_n = mod_pow(ctx.psi, N as u64, q);
        assert_eq!(
            psi_n,
            q - 1,
            "CRITICAL: ψ^N ≠ -1 (mod q) for q={}",
            q
        );

        // ψ^(2N) should be 1 mod q
        let psi_2n = mod_pow(ctx.psi, (2 * N) as u64, q);
        assert_eq!(
            psi_2n, 1,
            "CRITICAL: ψ^(2N) ≠ 1 (mod q) for q={}",
            q
        );

        // ψ should be a PRIMITIVE root (not of lower order)
        for k in 1..N as u64 {
            let v = mod_pow(ctx.psi, k, q);
            assert_ne!(v, 1, "CRITICAL: ψ has order {} < 2N for q={}", k, q);
        }
    }
}

/// Verify NTT inverse is correct: INTT(NTT(a)) == a.
/// Test with adversarial inputs (near-boundary values).
#[test]
fn attack_ntt_roundtrip_adversarial() {
    let q = NTT_PRIMES[0];
    let ctx = NttContext::new(q);

    // Test with boundary values: 0, 1, q-1, q/2
    let mut a = vec![0i64; N];
    a[0] = 0;
    a[1] = 1;
    a[2] = q - 1;
    a[3] = q / 2;
    a[N - 1] = q - 1;

    let forward = ctx.forward(&a);
    let back = ctx.inverse(&forward);

    for i in 0..N {
        let expected = a[i] % q;
        let actual = back[i] % q;
        assert_eq!(
            actual, expected,
            "NTT roundtrip failed at index {}: expected {}, got {}",
            i, expected, actual
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 4. SAMPLING DISTRIBUTION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Statistical test: ternary sampling should have P(0) ≈ 0.5, P(-1) ≈ P(1) ≈ 0.25.
/// Uses chi-squared test with large sample.
#[test]
fn attack_ternary_sampling_uniformity() {
    let mut rng = StdRng::seed_from_u64(12345);
    let mut count_neg = 0u64;
    let mut count_zero = 0u64;
    let mut count_pos = 0u64;

    // Sample 10 polynomials = 40960 coefficients
    for _ in 0..10 {
        let p = sample_ternary(&mut rng);
        for &c in &p.coeffs {
            match c {
                -1 => count_neg += 1,
                0 => count_zero += 1,
                1 => count_pos += 1,
                _ => panic!("CRITICAL: ternary sample {} is not in {{-1, 0, 1}}", c),
            }
        }
    }

    let total = (10 * N) as f64;
    let expected_zero = total * 0.5;
    let expected_nonzero = total * 0.25;

    // Chi-squared test: sum((observed - expected)^2 / expected)
    let chi_sq = (count_zero as f64 - expected_zero).powi(2) / expected_zero
        + (count_neg as f64 - expected_nonzero).powi(2) / expected_nonzero
        + (count_pos as f64 - expected_nonzero).powi(2) / expected_nonzero;

    // df=2, p=0.001 critical value is 13.82
    assert!(
        chi_sq < 20.0,
        "VULNERABILITY: ternary distribution is biased (chi^2 = {:.2}, counts: -1={}, 0={}, 1={})",
        chi_sq,
        count_neg,
        count_zero,
        count_pos
    );

    // Also check rough proportions
    let p_zero = count_zero as f64 / total;
    let p_neg = count_neg as f64 / total;
    let p_pos = count_pos as f64 / total;
    assert!(
        (p_zero - 0.5).abs() < 0.03,
        "P(0) = {:.4}, expected ~0.5",
        p_zero
    );
    assert!(
        (p_neg - 0.25).abs() < 0.03,
        "P(-1) = {:.4}, expected ~0.25",
        p_neg
    );
    assert!(
        (p_pos - 0.25).abs() < 0.03,
        "P(1) = {:.4}, expected ~0.25",
        p_pos
    );
}

/// Statistical test: Gaussian sampling should have mean ≈ 0 and std ≈ SIGMA.
#[test]
fn attack_gaussian_sampling_statistics() {
    let mut rng = StdRng::seed_from_u64(54321);
    let mut all_samples = Vec::new();

    for _ in 0..20 {
        let p = sample_gaussian(&mut rng);
        all_samples.extend(p.coeffs.iter().map(|&c| c as f64));
    }

    let n = all_samples.len() as f64;
    let mean = all_samples.iter().sum::<f64>() / n;
    let variance = all_samples.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
    let std_dev = variance.sqrt();

    // Mean should be near zero
    assert!(
        mean.abs() < 0.5,
        "VULNERABILITY: Gaussian mean = {:.4}, expected ~0",
        mean
    );

    // Std dev should be near SIGMA = 3.2
    assert!(
        (std_dev - SIGMA).abs() < 0.5,
        "VULNERABILITY: Gaussian std = {:.4}, expected ~{:.1}",
        std_dev,
        SIGMA
    );

    // No sample should be astronomically large (> 6σ is effectively impossible)
    let max_abs = all_samples.iter().map(|x| x.abs()).fold(0.0f64, f64::max);
    assert!(
        max_abs < 6.0 * SIGMA + 10.0,
        "VULNERABILITY: Gaussian sample {} exceeds 6σ",
        max_abs
    );
}

/// Verify uniform sampling covers the full range and doesn't cluster.
#[test]
fn attack_uniform_sampling_range() {
    let mut rng = StdRng::seed_from_u64(99999);
    let p = sample_uniform(&mut rng);

    let half = Q / 2;
    let mut has_positive_large = false;
    let mut has_negative_large = false;

    for &c in &p.coeffs {
        assert!(
            c >= -half && c <= half,
            "CRITICAL: uniform sample {} outside centered range [-{}, {}]",
            c,
            half,
            half
        );
        if c > half / 2 {
            has_positive_large = true;
        }
        if c < -half / 2 {
            has_negative_large = true;
        }
    }

    assert!(
        has_positive_large,
        "VULNERABILITY: uniform sampling never produces large positive values"
    );
    assert!(
        has_negative_large,
        "VULNERABILITY: uniform sampling never produces large negative values"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 5. MOD_REDUCE CORRECTNESS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Verify mod_reduce always produces centered results in (-Q/2, Q/2].
#[test]
fn attack_mod_reduce_centered_range() {
    let half = Q / 2;

    // Test boundary values
    let test_values = [
        0,
        1,
        -1,
        Q,
        -Q,
        Q + 1,
        -(Q + 1),
        Q - 1,
        -(Q - 1),
        half,
        half + 1,
        -half,
        -(half + 1),
        2 * Q,
        -2 * Q,
        i64::MAX / 2,
        i64::MIN / 2,
    ];

    for &v in &test_values {
        let r = mod_reduce(v);
        assert!(
            r >= -half && r <= half,
            "CRITICAL: mod_reduce({}) = {} outside [-{}, {}]",
            v,
            r,
            half,
            half
        );
        // Verify it's actually congruent to v mod Q
        let diff = (v as i128 - r as i128) % Q as i128;
        assert_eq!(
            diff, 0,
            "CRITICAL: mod_reduce({}) = {} is not congruent mod Q",
            v, r
        );
    }
}

/// Attack: Verify mod_reduce preserves additive structure.
#[test]
fn attack_mod_reduce_additive_homomorphism() {
    let test_pairs = [(100, 200), (Q / 2, Q / 2), (-Q / 3, Q / 3), (Q - 1, 1)];

    for (a, b) in test_pairs {
        let sum_then_reduce = mod_reduce(a + b);
        let reduce_then_sum = mod_reduce(mod_reduce(a) + mod_reduce(b));
        assert_eq!(
            sum_then_reduce, reduce_then_sum,
            "mod_reduce is not additive for ({}, {}): {} != {}",
            a, b, sum_then_reduce, reduce_then_sum
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 6. PARAMETER VALIDATION
// ═══════════════════════════════════════════════════════════════════════

/// Verify Q is prime (required for mod_inv and NTT).
#[test]
fn attack_q_is_prime() {
    assert!(is_prime(Q), "CRITICAL: Q = {} is not prime!", Q);
}

/// Verify Q = 2^54 - 33 exactly.
#[test]
fn attack_q_correct_value() {
    assert_eq!(Q, (1i64 << 54) - 33, "Q has wrong value");
}

/// Verify N is a power of 2 (required for NTT butterfly).
#[test]
fn attack_n_is_power_of_two() {
    assert!(N > 0 && N & (N - 1) == 0, "CRITICAL: N = {} is not a power of 2", N);
}

/// Verify DELTA * u32::MAX < Q (no overflow during encoding).
#[test]
fn attack_encoding_no_overflow() {
    let max_encoded = u32::MAX as i128 * DELTA as i128;
    assert!(
        max_encoded < Q as i128,
        "CRITICAL: DELTA * u32::MAX = {} >= Q = {} (encoding overflow)",
        max_encoded,
        Q
    );
}

/// Verify decomposition parameters are consistent.
#[test]
fn attack_decomposition_params() {
    assert_eq!(DECOMP_BASE, DELTA, "DECOMP_BASE should equal DELTA");
    // ceil(log_T(Q)) should equal NUM_DIGITS
    let mut val = Q;
    let mut digits = 0;
    while val > 0 {
        val /= DECOMP_BASE;
        digits += 1;
    }
    assert_eq!(
        digits, NUM_DIGITS,
        "NUM_DIGITS = {} but need {} digits for base-T representation of Q",
        NUM_DIGITS, digits
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. ENCODE/DECODE BOUNDARY ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Encoding with values that are exact multiples of DELTA.
/// These should roundtrip perfectly with no noise.
#[test]
fn attack_encode_decode_exact_multiples() {
    let tokens = vec![0, 1, 2, 1000, u32::MAX];
    let encoded = encode(&tokens);
    let decoded = decode(&encoded, tokens.len());
    assert_eq!(
        decoded, tokens,
        "Encode/decode roundtrip failed for exact values"
    );
}

/// Attack: Introduce noise just below DELTA/2 — should still decode correctly.
#[test]
fn attack_decode_with_noise_tolerance() {
    let tokens = vec![42, 100, 999];
    let mut encoded = encode(&tokens);

    // Add noise just under DELTA/2 to each coefficient
    let max_noise = DELTA / 2 - 1;
    encoded.coeffs[0] = mod_reduce(encoded.coeffs[0] + max_noise);
    encoded.coeffs[1] = mod_reduce(encoded.coeffs[1] - max_noise);
    encoded.coeffs[2] = mod_reduce(encoded.coeffs[2] + max_noise / 2);

    let decoded = decode(&encoded, tokens.len());
    assert_eq!(
        decoded, tokens,
        "Decode should tolerate noise < DELTA/2"
    );
}

/// Attack: Noise at exactly DELTA/2 — could go either way (rounding boundary).
#[test]
fn attack_decode_at_noise_boundary() {
    let token = 100u32;
    let mut encoded = encode(&[token]);

    // Add exactly DELTA/2 noise — this hits the rounding boundary
    let noise = DELTA / 2;
    encoded.coeffs[0] = mod_reduce(encoded.coeffs[0] + noise);

    let decoded = decode(&encoded, 1);
    // At the boundary, it rounds UP: 100 * DELTA + DELTA/2 → (100*DELTA + DELTA/2 + DELTA/2) / DELTA = 101
    assert!(
        decoded[0] == token || decoded[0] == token + 1,
        "At boundary: expected {} or {}, got {}",
        token,
        token + 1,
        decoded[0]
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 8. POLYNOMIAL RING ARITHMETIC ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Verify negacyclic multiplication is correct (X^N = -1).
/// An implementation bug here would silently corrupt all ciphertexts.
#[test]
fn attack_negacyclic_x_power_n() {
    // X^(N-1) * X^1 = X^N = -1 (constant)
    let mut a = vec![0i64; N];
    a[N - 1] = 1;
    let p1 = Poly::from_coeffs(a);

    let mut b = vec![0i64; N];
    b[1] = 1;
    let p2 = Poly::from_coeffs(b);

    let result = p1.mul(&p2);
    assert_eq!(result.coeffs[0], -1, "X^N should be -1");
    for i in 1..N {
        assert_eq!(result.coeffs[i], 0, "X^N has non-zero coeff at {}", i);
    }
}

/// Attack: Verify that X^(2N) = +1 (double wrap).
#[test]
fn attack_negacyclic_x_power_2n() {
    // X^(N-1) * X^(N-1) = X^(2N-2)
    // X^(2N-2) = X^N * X^(N-2) = (-1) * X^(N-2)
    let mut a = vec![0i64; N];
    a[N - 1] = 1;
    let p = Poly::from_coeffs(a);

    let result = p.mul(&p);
    // X^(2N-2) in Z[X]/(X^N+1):
    // 2*(N-1) = 2N - 2 ≥ N, so wrap: index = (2N-2) - N = N-2, sign = -1
    assert_eq!(result.coeffs[N - 2], -1, "X^(2N-2) should be -X^(N-2)");
    for i in 0..N {
        if i != N - 2 {
            assert_eq!(result.coeffs[i], 0, "unexpected coeff at {}", i);
        }
    }
}

/// Attack: Scalar multiplication by zero should give zero polynomial.
#[test]
fn attack_scalar_mul_zero() {
    let a = Poly::from_coeffs(vec![42, -17, 999, Q - 1]);
    let result = a.scalar_mul(0);
    assert_eq!(result, Poly::zero());
}

/// Attack: Decompose and reconstruct should be identity.
#[test]
fn attack_decompose_reconstruct_identity() {
    let a = Poly::from_coeffs(vec![Q / 3, -Q / 4, 42, 0, Q / 2 - 1]);
    let digits = a.decompose_base_t();
    assert_eq!(digits.len(), NUM_DIGITS);

    // Reconstruct: sum(digit[d] * T^d)
    for i in 0..5 {
        let original = {
            let v = a.coeffs[i];
            if v < 0 {
                v + Q
            } else {
                v
            }
        };
        let mut reconstructed: i64 = 0;
        let mut power: i64 = 1;
        for d in 0..NUM_DIGITS {
            let digit = {
                let v = digits[d].coeffs[i];
                if v < 0 {
                    v + Q
                } else {
                    v
                }
            };
            reconstructed += digit * power;
            power *= DECOMP_BASE;
        }
        assert_eq!(
            reconstructed % Q,
            original % Q,
            "Decompose/reconstruct failed at coeff {}",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 9. MODULAR ARITHMETIC ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: mod_inv(a, p) * a ≡ 1 (mod p) for all test values.
#[test]
fn attack_mod_inv_correctness() {
    let q = NTT_PRIMES[0];
    let test_values = [1, 2, 3, 42, 12345, q - 1, q / 2, q / 3 + 1];

    for &a in &test_values {
        let inv = mod_inv(a, q);
        let product = (a as i128 * inv as i128 % q as i128) as i64;
        assert_eq!(
            product, 1,
            "CRITICAL: mod_inv({}, {}) = {} but product = {}",
            a, q, inv, product
        );
    }
}

/// Attack: mod_pow with edge cases.
#[test]
fn attack_mod_pow_edge_cases() {
    let q = NTT_PRIMES[0];

    // a^0 = 1
    assert_eq!(mod_pow(42, 0, q), 1);
    // a^1 = a
    assert_eq!(mod_pow(42, 1, q), 42);
    // 0^n = 0 (for n > 0)
    assert_eq!(mod_pow(0, 100, q), 0);
    // 1^n = 1
    assert_eq!(mod_pow(1, u64::MAX, q), 1);
    // Fermat's little theorem: a^(p-1) ≡ 1 (mod p)
    assert_eq!(mod_pow(42, (q - 1) as u64, q), 1);
    // Negative base
    assert_eq!(
        mod_pow(-1, 2, q),
        1,
        "(-1)^2 should be 1"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 10. RLWE SECURITY PROPERTY VERIFICATION
// ═══════════════════════════════════════════════════════════════════════

/// Verify the RLWE instance error is small: b + a*s = -e, |e| < 100.
/// If error is large, the scheme is broken.
#[test]
fn attack_rlwe_error_bound() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    // b + a*s should equal -e (small)
    let as_prod = pk.a.mul(&sk.s);
    let neg_e = pk.b.add(&as_prod);

    let max_err = neg_e.coeffs.iter().map(|c| c.abs()).max().unwrap();
    assert!(
        max_err < 100,
        "RLWE error too large: max |e| = {} (expected < 100 for σ=3.2)",
        max_err
    );
}

/// Verify that the public key looks random (not trivially structured).
#[test]
fn attack_public_key_randomness() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    // The `a` polynomial should have high entropy — check it's not all zeros or constant
    let distinct_values: std::collections::HashSet<i64> = pk.a.coeffs.iter().copied().collect();
    assert!(
        distinct_values.len() > N / 2,
        "VULNERABILITY: public key 'a' polynomial has too few distinct values ({})",
        distinct_values.len()
    );

    // The `b` polynomial should also look random
    let b_distinct: std::collections::HashSet<i64> = pk.b.coeffs.iter().copied().collect();
    assert!(
        b_distinct.len() > N / 2,
        "VULNERABILITY: public key 'b' polynomial has too few distinct values ({})",
        b_distinct.len()
    );
}

/// Verify that different RNG seeds produce different keys (no determinism bug).
#[test]
fn attack_key_independence() {
    let mut rng1 = StdRng::seed_from_u64(1);
    let mut rng2 = StdRng::seed_from_u64(2);
    let mut rng3 = StdRng::seed_from_u64(3);

    let (pk1, sk1) = keygen(&mut rng1);
    let (pk2, sk2) = keygen(&mut rng2);
    let (pk3, sk3) = keygen(&mut rng3);
    let _ = (&pk3, &sk3);

    // All keys should be different
    assert_ne!(sk1.s.coeffs, sk2.s.coeffs, "Same secret key for different seeds");
    assert_ne!(sk2.s.coeffs, sk3.s.coeffs, "Same secret key for different seeds");
    assert_ne!(pk1.a.coeffs, pk2.a.coeffs, "Same public key for different seeds");
}

/// Verify ciphertext randomization: encrypting the same message twice
/// produces different ciphertexts (semantic security).
#[test]
fn attack_semantic_security() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![42, 42, 42];

    let mut rng1 = StdRng::seed_from_u64(100);
    let mut rng2 = StdRng::seed_from_u64(200);

    let ct1 = encrypt(&tokens, &pk, &sk, &mut rng1);
    let ct2 = encrypt(&tokens, &pk, &sk, &mut rng2);

    assert_ne!(
        ct1.chunks[0].0.coeffs, ct2.chunks[0].0.coeffs,
        "VULNERABILITY: same plaintext, same ciphertext (not semantically secure)"
    );
    assert_ne!(
        ct1.chunks[0].1.coeffs, ct2.chunks[0].1.coeffs,
        "VULNERABILITY: c1 components identical"
    );
}
