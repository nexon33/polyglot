//! Integration tests for RNS-CKKS neural network inference layer.
//!
//! End-to-end tests that exercise the full pipeline: keygen → encrypt →
//! forward pass → decrypt → compare with plaintext reference.

use poly_client::ckks::rns_ckks::*;
use poly_client::ckks::rns_fhe_layer::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Instant;

fn test_rng() -> StdRng {
    StdRng::seed_from_u64(99)
}

// ═══════════════════════════════════════════════════════════════════════
// 4-prime single-layer end-to-end
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn neural_net_e2e_4_primes() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(4);
    let d = 4;

    let net = RnsNeuralNet {
        dim: d,
        weights: vec![vec![
            0.5, 0.1, 0.0, 0.0,
            0.0, 0.5, 0.1, 0.0,
            0.0, 0.0, 0.5, 0.1,
            0.1, 0.0, 0.0, 0.5,
        ]],
        biases: vec![vec![0.1, 0.2, 0.3, 0.4]],
        activations: vec![Activation::Square], // linear + square
    };

    let input = vec![1.0, 2.0, 3.0, 4.0];
    let expected = rns_plaintext_forward(&input, &net);

    // Keygen
    let t0 = Instant::now();
    let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);
    let keygen_ms = t0.elapsed().as_millis();

    // Forward pass
    let t1 = Instant::now();
    let ct_result = rns_forward(&input, &net, &keys, &ctx, &mut rng);
    let forward_ms = t1.elapsed().as_millis();

    // Decrypt
    let t2 = Instant::now();
    let decrypted = rns_decrypt_simd(&ct_result, &keys.secret, &ctx, d);
    let decrypt_ms = t2.elapsed().as_millis();

    println!("=== 4-prime single-layer neural net ===");
    println!("  Keygen:  {} ms", keygen_ms);
    println!("  Forward: {} ms", forward_ms);
    println!("  Decrypt: {} ms", decrypt_ms);
    println!("  Total:   {} ms", keygen_ms + forward_ms + decrypt_ms);
    println!("  Primes remaining: {}", ct_result.c0.num_primes);
    println!("  Final scale: {:.0}", ct_result.scale);

    // Precision metrics
    let errors: Vec<f64> = expected.iter().zip(decrypted.iter())
        .map(|(e, d)| (e - d).abs())
        .collect();
    let max_err = errors.iter().cloned().fold(0.0f64, f64::max);
    let avg_err = errors.iter().sum::<f64>() / errors.len() as f64;

    println!("  Expected:  {:?}", expected);
    println!("  Decrypted: {:?}", decrypted);
    println!("  Max error: {:.6}", max_err);
    println!("  Avg error: {:.6}", avg_err);

    assert!(max_err < 3.0, "max error {} too large", max_err);
    assert_eq!(ct_result.c0.num_primes, 2, "should have 2 primes remaining");
}

// ═══════════════════════════════════════════════════════════════════════
// 5-prime two-layer end-to-end
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn neural_net_e2e_5_primes() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(5);
    let d = 4;

    let net = RnsNeuralNet {
        dim: d,
        weights: vec![
            // Layer 1 (with square activation)
            vec![
                0.3, 0.1, 0.0, 0.0,
                0.0, 0.3, 0.1, 0.0,
                0.0, 0.0, 0.3, 0.1,
                0.1, 0.0, 0.0, 0.3,
            ],
            // Layer 2 (no activation)
            vec![
                0.5, -0.1, 0.0, 0.0,
                0.0, 0.5, -0.1, 0.0,
                0.0, 0.0, 0.5, -0.1,
                -0.1, 0.0, 0.0, 0.5,
            ],
        ],
        biases: vec![
            vec![0.1, 0.1, 0.1, 0.1],
            vec![0.0, 0.0, 0.0, 0.0],
        ],
        activations: vec![Activation::Square, Activation::None], // linear+square, then linear only
    };

    let input = vec![1.0, 2.0, 3.0, 4.0];
    let expected = rns_plaintext_forward(&input, &net);

    // Keygen
    let t0 = Instant::now();
    let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);
    let keygen_ms = t0.elapsed().as_millis();

    // Forward pass
    let t1 = Instant::now();
    let ct_result = rns_forward(&input, &net, &keys, &ctx, &mut rng);
    let forward_ms = t1.elapsed().as_millis();

    // Decrypt
    let t2 = Instant::now();
    let decrypted = rns_decrypt_simd(&ct_result, &keys.secret, &ctx, d);
    let decrypt_ms = t2.elapsed().as_millis();

    println!("=== 5-prime two-layer neural net ===");
    println!("  Keygen:  {} ms", keygen_ms);
    println!("  Forward: {} ms", forward_ms);
    println!("  Decrypt: {} ms", decrypt_ms);
    println!("  Total:   {} ms", keygen_ms + forward_ms + decrypt_ms);
    println!("  Primes remaining: {}", ct_result.c0.num_primes);
    println!("  Final scale: {:.0}", ct_result.scale);

    // Precision metrics
    let errors: Vec<f64> = expected.iter().zip(decrypted.iter())
        .map(|(e, d)| (e - d).abs())
        .collect();
    let max_err = errors.iter().cloned().fold(0.0f64, f64::max);
    let avg_err = errors.iter().sum::<f64>() / errors.len() as f64;

    println!("  Expected:  {:?}", expected);
    println!("  Decrypted: {:?}", decrypted);
    println!("  Max error: {:.6}", max_err);
    println!("  Avg error: {:.6}", avg_err);

    assert!(max_err < 5.0, "max error {} too large", max_err);
    assert_eq!(ct_result.c0.num_primes, 2, "should have 2 primes remaining");
}

// ═══════════════════════════════════════════════════════════════════════
// Different input patterns
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn neural_net_negative_inputs() {
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(4);
    let d = 4;

    let net = RnsNeuralNet {
        dim: d,
        weights: vec![vec![
            1.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 1.0,
        ]],
        biases: vec![vec![0.0; d]],
        activations: vec![Activation::Square],
    };

    // Negative inputs: square activation should make them positive
    let input = vec![-1.0, -2.0, 3.0, -0.5];
    let expected = rns_plaintext_forward(&input, &net);

    let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);
    let ct_result = rns_forward(&input, &net, &keys, &ctx, &mut rng);
    let decrypted = rns_decrypt_simd(&ct_result, &keys.secret, &ctx, d);

    println!("Negative inputs:");
    println!("  Expected:  {:?}", expected);
    println!("  Decrypted: {:?}", decrypted);

    for i in 0..d {
        assert!(
            (decrypted[i] - expected[i]).abs() < 3.0,
            "slot {} negative input: expected {}, got {}",
            i, expected[i], decrypted[i]
        );
    }
}

#[test]
fn neural_net_linear_only_no_activation() {
    // Pure linear layer, no square activation. Tests that activation=false works.
    let mut rng = test_rng();
    let ctx = RnsCkksContext::new(3);
    let d = 4;

    let net = RnsNeuralNet {
        dim: d,
        weights: vec![vec![
            2.0, 0.0, 0.0, 0.0,
            0.0, 3.0, 0.0, 0.0,
            0.0, 0.0, 0.5, 0.0,
            0.0, 0.0, 0.0, 1.0,
        ]],
        biases: vec![vec![1.0, -1.0, 0.5, 0.0]],
        activations: vec![Activation::None],
    };

    let input = vec![1.0, 2.0, 3.0, 4.0];
    let expected = rns_plaintext_forward(&input, &net);

    let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);
    let ct_result = rns_forward(&input, &net, &keys, &ctx, &mut rng);
    let decrypted = rns_decrypt_simd(&ct_result, &keys.secret, &ctx, d);

    println!("Linear-only:");
    println!("  Expected:  {:?}", expected);
    println!("  Decrypted: {:?}", decrypted);

    // Linear only consumes 1 level, still have 2 primes
    assert_eq!(ct_result.c0.num_primes, 2);

    for i in 0..d {
        assert!(
            (decrypted[i] - expected[i]).abs() < 2.0,
            "slot {} linear-only: expected {}, got {}",
            i, expected[i], decrypted[i]
        );
    }
}
