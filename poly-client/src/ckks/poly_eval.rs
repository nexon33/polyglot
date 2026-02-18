//! Polynomial evaluation over encrypted CKKS ciphertexts.
//!
//! Evaluates P(x) = a₀ + a₁x + a₂x² + ⋯ + aₐxᵈ on SIMD-packed encrypted
//! vectors. The polynomial is applied element-wise to all 2048 slots.
//!
//! ## Algorithms
//!
//! - **Horner** (`rns_poly_eval`): d levels for degree d. Clean, minimal code.
//!   Good for small degrees (d ≤ 7) when levels are plentiful.
//!
//! - **Paterson-Stockmeyer** (`rns_poly_eval_bsgs`): ~2√d levels for degree d.
//!   Baby-step/giant-step decomposition. Better for higher degrees (d ≥ 4).
//!
//! ## Level budget
//!
//! | Degree | Horner levels | PS levels |
//! |--------|--------------|-----------|
//! | 3      | 3            | 3         |
//! | 7      | 7            | 5         |
//! | 15     | 15           | 7         |
//!
//! With 20 primes (19 levels), Horner handles degree 7 easily.
//! PS is needed for degree 15+ (bootstrapping).

use super::rns::RnsPoly;
use super::rns_ckks::*;
use super::simd;

// ═══════════════════════════════════════════════════════════════════════
// Horner evaluation
// ═══════════════════════════════════════════════════════════════════════

/// Evaluate polynomial P(x) = coeffs[0] + coeffs[1]*x + ⋯ + coeffs[d]*x^d
/// on an encrypted SIMD-packed ciphertext using Horner's method.
///
/// The polynomial is applied element-wise: each SIMD slot independently
/// evaluates P. Consumes exactly `d` multiplication levels.
///
/// # Arguments
/// * `ct_x` — encrypted input (the polynomial variable x)
/// * `coeffs` — polynomial coefficients `[a₀, a₁, …, aₐ]` (length d+1)
/// * `evk` — evaluation key for relinearization (ct×ct steps)
/// * `ctx` — CKKS context
///
/// # Panics
/// If polynomial degree < 1 or insufficient levels remain.
pub fn rns_poly_eval(
    ct_x: &RnsCiphertext,
    coeffs: &[f64],
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    assert!(coeffs.len() >= 2, "polynomial must have degree >= 1");
    let d = coeffs.len() - 1;

    // Horner: P(x) = a₀ + x·(a₁ + x·(a₂ + ⋯ + x·aₐ))
    //
    // First step: r = aₐ * x + a_{d-1}  (plaintext-ct multiply, no relin)
    // Remaining: r = r * x + aᵢ         (ct-ct multiply + relin)

    let ad_broadcast = vec![coeffs[d]; simd::NUM_SLOTS];
    let r = rns_ct_mul_plain_simd(ct_x, &ad_broadcast, ctx);
    let mut r = rns_rescale(&r);
    r = rns_ct_add_scalar_broadcast(&r, coeffs[d - 1]);

    // Remaining Horner steps (d-1 ct-ct multiplications)
    for i in (0..d - 1).rev() {
        // r and x may be at different levels — leveled multiply handles this
        let r_times_x = rns_ct_mul_relin_leveled(&r, ct_x, evk, ctx);
        r = rns_rescale(&r_times_x);
        r = rns_ct_add_scalar_broadcast(&r, coeffs[i]);
    }

    r
}

// ═══════════════════════════════════════════════════════════════════════
// Paterson-Stockmeyer (baby-step / giant-step)
// ═══════════════════════════════════════════════════════════════════════

/// Evaluate polynomial using Paterson-Stockmeyer baby-step/giant-step.
///
/// For degree d, consumes approximately `B + G - 1` levels where
/// B = ceil(√(d+1)) and G = ceil((d+1)/B). This is ≈ 2√d levels,
/// significantly less than Horner's d levels for larger degrees.
///
/// Falls back to Horner for degree ≤ 2 (where PS has no advantage).
pub fn rns_poly_eval_bsgs(
    ct_x: &RnsCiphertext,
    coeffs: &[f64],
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    assert!(coeffs.len() >= 2, "polynomial must have degree >= 1");
    let d = coeffs.len() - 1;

    if d <= 2 {
        return rns_poly_eval(ct_x, coeffs, evk, ctx);
    }

    let b = ((d + 1) as f64).sqrt().ceil() as usize; // baby-step size
    let g = (d + b) / b; // number of groups = ceil((d+1)/b)

    // ── Baby step: compute x, x², …, x^b ──────────────────────────
    // powers[k] = x^(k+1), so powers[0] = x, powers[b-1] = x^b
    let mut powers: Vec<RnsCiphertext> = Vec::with_capacity(b);
    powers.push(ct_x.clone()); // x^1 at level 0

    for k in 1..b {
        // x^(k+1) = x^k * x  (leveled multiply auto-matches levels)
        let prod = rns_ct_mul_relin_leveled(&powers[k - 1], ct_x, evk, ctx);
        powers.push(rns_rescale(&prod));
    }
    // powers[k] is at level k (has been rescaled k times).
    // Baby step consumed b-1 levels.

    // Mod-switch all baby-step powers to the deepest level (b-1)
    let baby_min_primes = powers[b - 1].c0.num_primes;
    let aligned: Vec<RnsCiphertext> = powers
        .iter()
        .map(|p| rns_ct_mod_switch_to(p, baby_min_primes))
        .collect();

    // x^b for the giant step (already at deepest baby-step level)
    let x_b = aligned[b - 1].clone();

    // ── Group evaluation: G_j(x) = Σ c_{jb+i} · x^i ─────────────
    // For each group, compute the weighted sum of baby-step powers.
    // All aligned powers have the same num_primes, so plaintext-ct
    // multiply results all have scale ≈ delta² and can be summed.
    // One rescale per group brings scale back to ≈ delta.

    let mut groups: Vec<RnsCiphertext> = Vec::with_capacity(g);

    for j in 0..g {
        let base_idx = j * b;

        // Accumulate c_{jb+i} * x^i for i >= 1
        let mut accum: Option<RnsCiphertext> = None;

        for i in 1..b {
            let coeff_idx = base_idx + i;
            if coeff_idx > d {
                break;
            }
            let c = coeffs[coeff_idx];
            if c.abs() < 1e-30 {
                continue; // skip zero coefficients
            }

            // c * x^i: plaintext-ct multiply (broadcast scalar to all slots)
            let c_broadcast = vec![c; simd::NUM_SLOTS];
            let term = rns_ct_mul_plain_simd(&aligned[i - 1], &c_broadcast, ctx);

            accum = Some(match accum {
                None => term,
                Some(a) => rns_ct_add_leveled(&a, &term),
            });
        }

        match accum {
            Some(a) => {
                // Rescale the weighted sum (scale ≈ delta² → delta)
                let rescaled = rns_rescale(&a);
                // Add constant term at the rescaled scale
                let c_const = coeffs[base_idx.min(d)];
                groups.push(rns_ct_add_scalar_broadcast(&rescaled, c_const));
            }
            None => {
                // Only constant coefficient in this group (no x^i terms).
                // Create a trivial ciphertext at the expected level/primes.
                let c_const = if base_idx <= d { coeffs[base_idx] } else { 0.0 };
                let target_primes = baby_min_primes - 1; // one rescale less
                let target_scale = if !groups.is_empty() {
                    groups[0].scale
                } else {
                    // First group is constant-only (unusual). Use delta as scale.
                    ctx.delta
                };
                groups.push(trivial_ciphertext_broadcast(
                    c_const,
                    target_scale,
                    target_primes,
                ));
            }
        }
    }
    // Each group is at approximately the same level (baby_level + 1).

    // ── Giant step: Horner on groups with x^b ─────────────────────
    // P(x) = G₀ + x^b·(G₁ + x^b·(G₂ + ⋯))
    // = G₀ + x^b·(G₁ + x^b·(⋯ + x^b·G_{g-1}))

    let mut r = groups.pop().unwrap(); // G_{g-1}

    while let Some(g_j) = groups.pop() {
        // r = r * x^b + G_j  (leveled multiply + add)
        let prod = rns_ct_mul_relin_leveled(&r, &x_b, evk, ctx);
        let prod_rescaled = rns_rescale(&prod);
        r = rns_ct_add_leveled(&prod_rescaled, &g_j);
    }

    r
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

/// Create a noiseless "trivial" ciphertext with a scalar broadcast to all slots.
///
/// c0 = encode(scalar), c1 = 0. No encryption keys needed.
/// Useful as the initial accumulator in polynomial evaluation.
fn trivial_ciphertext_broadcast(
    scalar: f64,
    scale: f64,
    num_primes: usize,
) -> RnsCiphertext {
    let values = vec![scalar; simd::NUM_SLOTS];
    let coeffs = simd::encode_simd(&values, scale);
    let c0 = RnsPoly::from_coeffs(&coeffs, num_primes);
    let c1 = RnsPoly::zero(num_primes);
    RnsCiphertext {
        c0,
        c1,
        scale,
        level: 0,
        auth_tag: None,
    }
}

/// Evaluate a polynomial on plaintext values (reference implementation).
///
/// Used for computing expected results in tests.
pub fn poly_eval_plain(x: f64, coeffs: &[f64]) -> f64 {
    let mut result = 0.0;
    let mut x_pow = 1.0;
    for &c in coeffs {
        result += c * x_pow;
        x_pow *= x;
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn poly_eval_plain_correctness() {
        // P(x) = 1 + 2x + 3x² at x=2 → 1 + 4 + 12 = 17
        assert!((poly_eval_plain(2.0, &[1.0, 2.0, 3.0]) - 17.0).abs() < 1e-10);

        // P(x) = 5 at x=anything → 5
        assert!((poly_eval_plain(42.0, &[5.0]) - 5.0).abs() < 1e-10);
    }

    #[test]
    fn horner_degree_1() {
        // P(x) = 3 + 2x at x=1.5 → 3 + 3 = 6
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(5);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let input = vec![1.5; simd::NUM_SLOTS];
        let ct_x = rns_encrypt_simd(&input, &pk_b, &pk_a, &ctx, &mut rng);

        let coeffs = [3.0, 2.0]; // 3 + 2x
        let ct_result = rns_poly_eval(&ct_x, &coeffs, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, 4);

        let expected = poly_eval_plain(1.5, &coeffs);
        for i in 0..4 {
            assert!(
                (decrypted[i] - expected).abs() < 0.5,
                "slot {} degree-1: expected {}, got {}",
                i,
                expected,
                decrypted[i]
            );
        }
    }

    #[test]
    fn horner_degree_3() {
        // P(x) = 4 + 3x + 2x² + x³ at x=1.5
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(7); // 6 levels, need 3
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let input = vec![1.5; simd::NUM_SLOTS];
        let ct_x = rns_encrypt_simd(&input, &pk_b, &pk_a, &ctx, &mut rng);

        let coeffs = [4.0, 3.0, 2.0, 1.0]; // 4 + 3x + 2x² + x³
        let ct_result = rns_poly_eval(&ct_x, &coeffs, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, 4);

        let expected = poly_eval_plain(1.5, &coeffs);
        println!("degree-3: expected {:.4}, decrypted {:?}", expected, &decrypted[..4]);
        for i in 0..4 {
            assert!(
                (decrypted[i] - expected).abs() < 1.0,
                "slot {} degree-3: expected {:.4}, got {:.4}",
                i,
                expected,
                decrypted[i]
            );
        }
    }

    #[test]
    fn horner_degree_7() {
        // Degree-7 polynomial evaluated with 10 primes (9 levels, need 7)
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(10);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let x_val = 0.5;
        let input = vec![x_val; simd::NUM_SLOTS];
        let ct_x = rns_encrypt_simd(&input, &pk_b, &pk_a, &ctx, &mut rng);

        // Approximate SiLU-like polynomial (small coefficients)
        let coeffs = [0.0, 0.5, 0.0, 0.08333, 0.0, -0.00139, 0.0, 0.0000248];
        let ct_result = rns_poly_eval(&ct_x, &coeffs, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, 4);

        let expected = poly_eval_plain(x_val, &coeffs);
        println!(
            "degree-7: x={}, expected {:.6}, decrypted {:?}",
            x_val, expected, &decrypted[..4]
        );
        println!("  primes remaining: {}", ct_result.c0.num_primes);
        for i in 0..4 {
            assert!(
                (decrypted[i] - expected).abs() < 0.5,
                "slot {} degree-7: expected {:.6}, got {:.6}",
                i,
                expected,
                decrypted[i]
            );
        }
    }

    #[test]
    fn horner_simd_elementwise() {
        // Different values in different slots — verify element-wise evaluation
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(6);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let test_vals = [0.5, 1.0, -0.5, 2.0];
        let mut input = vec![0.0; simd::NUM_SLOTS];
        for (i, &v) in test_vals.iter().enumerate() {
            input[i] = v;
        }
        let ct_x = rns_encrypt_simd(&input, &pk_b, &pk_a, &ctx, &mut rng);

        // P(x) = 1 + x + x² (degree 2, need 2 levels)
        let coeffs = [1.0, 1.0, 1.0];
        let ct_result = rns_poly_eval(&ct_x, &coeffs, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, test_vals.len());

        for (i, &x) in test_vals.iter().enumerate() {
            let expected = poly_eval_plain(x, &coeffs);
            assert!(
                (decrypted[i] - expected).abs() < 1.0,
                "slot {}: x={}, expected {:.4}, got {:.4}",
                i,
                x,
                expected,
                decrypted[i]
            );
        }
    }

    #[test]
    fn bsgs_degree_3() {
        // Same polynomial as Horner degree-3 test, using PS algorithm
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(7);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let input = vec![1.5; simd::NUM_SLOTS];
        let ct_x = rns_encrypt_simd(&input, &pk_b, &pk_a, &ctx, &mut rng);

        let coeffs = [4.0, 3.0, 2.0, 1.0];
        let ct_result = rns_poly_eval_bsgs(&ct_x, &coeffs, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, 4);

        let expected = poly_eval_plain(1.5, &coeffs);
        println!(
            "bsgs degree-3: expected {:.4}, decrypted {:?}",
            expected, &decrypted[..4]
        );
        for i in 0..4 {
            assert!(
                (decrypted[i] - expected).abs() < 1.0,
                "slot {} bsgs degree-3: expected {:.4}, got {:.4}",
                i,
                expected,
                decrypted[i]
            );
        }
    }

    #[test]
    fn bsgs_degree_7() {
        // Degree-7 using Paterson-Stockmeyer (should use fewer levels than Horner)
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(10);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let x_val = 0.5;
        let input = vec![x_val; simd::NUM_SLOTS];
        let ct_x = rns_encrypt_simd(&input, &pk_b, &pk_a, &ctx, &mut rng);

        // Same polynomial as Horner degree-7 test
        let coeffs = [0.0, 0.5, 0.0, 0.08333, 0.0, -0.00139, 0.0, 0.0000248];
        let ct_result = rns_poly_eval_bsgs(&ct_x, &coeffs, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, 4);

        let expected = poly_eval_plain(x_val, &coeffs);
        println!(
            "bsgs degree-7: expected {:.6}, decrypted {:?}, primes left: {}",
            expected,
            &decrypted[..4],
            ct_result.c0.num_primes
        );
        for i in 0..4 {
            assert!(
                (decrypted[i] - expected).abs() < 0.5,
                "slot {} bsgs degree-7: expected {:.6}, got {:.6}",
                i,
                expected,
                decrypted[i]
            );
        }
    }

    #[test]
    fn mod_switch_preserves_value() {
        // Verify that mod-switching doesn't change the decrypted value
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(5);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let values = [3.14, -2.7, 1.0, 0.5];
        let mut input = vec![0.0; simd::NUM_SLOTS];
        for (i, &v) in values.iter().enumerate() {
            input[i] = v;
        }
        let ct = rns_encrypt_simd(&input, &pk_b, &pk_a, &ctx, &mut rng);
        assert_eq!(ct.c0.num_primes, 5);

        // Mod-switch to 3 primes
        let ct_switched = rns_ct_mod_switch_to(&ct, 3);
        assert_eq!(ct_switched.c0.num_primes, 3);
        assert_eq!(ct_switched.scale, ct.scale);
        assert_eq!(ct_switched.level, 2);

        let dec_original = rns_decrypt_simd(&ct, &s, &ctx, 4);
        let dec_switched = rns_decrypt_simd(&ct_switched, &s, &ctx, 4);

        for i in 0..4 {
            assert!(
                (dec_original[i] - dec_switched[i]).abs() < 0.01,
                "slot {} mod-switch changed value: {:.4} vs {:.4}",
                i,
                dec_original[i],
                dec_switched[i]
            );
        }
    }
}
