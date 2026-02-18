//! Encrypted neural network inference using RNS-CKKS.
//!
//! Provides multi-layer neural network inference over encrypted data using
//! SIMD-packed ciphertexts and the diagonal matrix-vector multiply method.
//!
//! ## Minimum prime constraint
//!
//! Ciphertexts must have at least 2 primes remaining at decryption time.
//! Rescaling from 2→1 primes is catastrophically lossy for SIMD data
//! because the rounding error (proportional to N × q_last) wraps around
//! the single remaining modulus.
//!
//! ## Supported architectures
//!
//! - **4 primes (3 levels)**: 1 linear + 1 square, decrypt at 2 primes
//! - **5 primes (4 levels)**: Linear -> Square -> Linear, decrypt at 2 primes
//!
//! ## Scale budget
//!
//! Each linear layer (plaintext SIMD multiply via matvec) consumes 1 level.
//! Each square activation (ct-ct multiply) consumes 1 level.

use std::collections::HashSet;

use super::poly_eval;
use super::rns::RnsPoly;
use super::rns_ckks::*;
use super::simd;

// ═══════════════════════════════════════════════════════════════════════
// Activation functions
// ═══════════════════════════════════════════════════════════════════════

/// Activation function applied after a linear layer.
#[derive(Clone, Debug, PartialEq)]
pub enum Activation {
    /// No activation (linear output).
    None,
    /// Square activation: x² (1 level consumed).
    Square,
    /// SiLU approximation: degree-6 minimax polynomial on [-5, 5] (6 levels consumed).
    /// SiLU(x) = x / (1 + e^{-x}) ≈ a₀ + a₁x + a₂x² + a₄x⁴ + a₆x⁶
    SiLU,
}

/// Degree-6 minimax polynomial approximation of SiLU on [-5, 5].
///
/// Coefficients computed via Chebyshev-node least-squares fit.
/// Odd-degree terms (a3, a5, a7) are zero — SiLU's asymmetry is
/// captured entirely by even-degree terms plus the linear term.
///
/// Max error ≈ 0.027, avg error ≈ 0.013.
pub const SILU_COEFFS: [f64; 7] = [
    0.02673489959535637,  // a0
    0.5,                  // a1 (= SiLU'(0))
    0.20650281870027850,  // a2
    0.0,                  // a3
    -0.00748551431515227, // a4
    0.0,                  // a5
    0.00012607490156780,  // a6
];

// ═══════════════════════════════════════════════════════════════════════
// Network description
// ═══════════════════════════════════════════════════════════════════════

/// Neural network architecture for encrypted inference.
///
/// All layers must be square (dim_in == dim_out) for Phase 5.
/// Rectangular layers are a future extension.
pub struct RnsNeuralNet {
    /// Layer dimension (all layers share the same dimension).
    pub dim: usize,
    /// Weight matrices: `weights[i]` is dim x dim, row-major.
    pub weights: Vec<Vec<f64>>,
    /// Bias vectors: `biases[i]` has `dim` elements.
    pub biases: Vec<Vec<f64>>,
    /// Activation function after each layer.
    pub activations: Vec<Activation>,
}

/// All cryptographic keys needed for neural network inference.
pub struct RnsInferenceKeys {
    pub secret: RnsPoly,
    pub pk_b: RnsPoly,
    pub pk_a: RnsPoly,
    pub eval_key: RnsEvalKey,
    pub rotation_keys: RnsRotationKeySet,
}

// ═══════════════════════════════════════════════════════════════════════
// Key generation
// ═══════════════════════════════════════════════════════════════════════

/// Generate all cryptographic keys needed for the given network.
///
/// Produces secret/public key pair, evaluation key for relinearization
/// (square activation), and rotation keys for all rotations needed
/// by the matvec diagonal method.
pub fn rns_neural_net_keygen<R: rand::Rng>(
    net: &RnsNeuralNet,
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> RnsInferenceKeys {
    let (s, pk_b, pk_a) = rns_keygen(ctx, rng);
    let eval_key = rns_gen_eval_key(&s, ctx, rng);

    // Collect all rotation amounts needed: for dim d, need rotations 1..d-1
    let mut rotations = HashSet::new();
    for r in 1..net.dim as i32 {
        rotations.insert(r);
    }
    let rot_vec: Vec<i32> = rotations.into_iter().collect();
    let rotation_keys = rns_gen_rotation_keys(&s, &rot_vec, ctx, rng);

    RnsInferenceKeys {
        secret: s,
        pk_b,
        pk_a,
        eval_key,
        rotation_keys,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Primitives
// ═══════════════════════════════════════════════════════════════════════

/// Add a SIMD-packed plaintext bias vector to a ciphertext.
///
/// Encodes the bias at the ciphertext's current scale (not ctx.delta),
/// replicates it across all slots with period `dim`, and adds to c0.
pub fn rns_ct_add_plain_simd(
    ct: &RnsCiphertext,
    values: &[f64],
    dim: usize,
) -> RnsCiphertext {
    let mut replicated = vec![0.0; simd::NUM_SLOTS];
    for i in 0..simd::NUM_SLOTS {
        if i % dim < values.len() {
            replicated[i] = values[i % dim];
        }
    }

    let coeffs = simd::encode_simd(&replicated, ct.scale);
    let p = RnsPoly::from_coeffs(&coeffs, ct.c0.num_primes);

    RnsCiphertext {
        c0: ct.c0.add(&p),
        c1: ct.c1.clone(),
        scale: ct.scale,
        level: ct.level,
        auth_tag: None,
    }
}

/// Compute a single linear layer: y = W*x + b.
///
/// Input ciphertext must contain a replicated input vector (via `replicate_vector`).
/// The result is at the same scale as the input after rescaling, with bias added.
pub fn rns_linear_layer(
    ct_x: &RnsCiphertext,
    weights: &[f64],
    biases: &[f64],
    dim: usize,
    rot_keys: &RnsRotationKeySet,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    assert_eq!(weights.len(), dim * dim);
    assert_eq!(biases.len(), dim);

    // Matrix-vector multiply: scale becomes ct.scale * ctx.delta
    let ct_wx = rns_matvec(ct_x, weights, dim, rot_keys, ctx);

    // Rescale to bring scale back down
    let ct_wx_rescaled = rns_rescale(&ct_wx);

    // Add bias at the rescaled scale
    rns_ct_add_plain_simd(&ct_wx_rescaled, biases, dim)
}

/// Square activation: compute x^2 element-wise.
///
/// Consumes 1 multiplication level (ct*ct multiply + rescale).
pub fn rns_square_activation(
    ct: &RnsCiphertext,
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    let ct_squared = rns_ct_mul_relin(ct, ct, evk, ctx);
    rns_rescale(&ct_squared)
}

/// SiLU activation: degree-6 polynomial approximation of x/(1+e^{-x}).
///
/// Consumes 6 multiplication levels (Horner evaluation of degree-6 polynomial).
/// Requires at least 7 primes remaining in the ciphertext.
pub fn rns_silu_activation(
    ct: &RnsCiphertext,
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    poly_eval::rns_poly_eval(ct, &SILU_COEFFS, evk, ctx)
}

/// Apply the specified activation function to a ciphertext.
fn apply_activation(
    ct: &RnsCiphertext,
    activation: &Activation,
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    match activation {
        Activation::None => ct.clone(),
        Activation::Square => rns_square_activation(ct, evk, ctx),
        Activation::SiLU => rns_silu_activation(ct, evk, ctx),
    }
}

/// Apply the specified activation in plaintext (reference).
fn apply_activation_plain(x: f64, activation: &Activation) -> f64 {
    match activation {
        Activation::None => x,
        Activation::Square => x * x,
        Activation::SiLU => {
            // Use the same polynomial approximation for consistency
            poly_eval::poly_eval_plain(x, &SILU_COEFFS)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Forward pass
// ═══════════════════════════════════════════════════════════════════════

/// Full encrypted forward pass through the neural network.
///
/// Encrypts the input with SIMD replication, processes each layer
/// (linear + optional activation), and returns the encrypted result.
/// The caller decrypts with `rns_decrypt_simd`.
pub fn rns_forward<R: rand::Rng>(
    input: &[f64],
    net: &RnsNeuralNet,
    keys: &RnsInferenceKeys,
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> RnsCiphertext {
    assert_eq!(input.len(), net.dim, "input length must match network dimension");

    // Replicate input and encrypt
    let x_rep = replicate_vector(input, net.dim);
    let mut ct = rns_encrypt_simd(&x_rep, &keys.pk_b, &keys.pk_a, ctx, rng);

    // Process each layer
    for i in 0..net.weights.len() {
        ct = rns_linear_layer(
            &ct,
            &net.weights[i],
            &net.biases[i],
            net.dim,
            &keys.rotation_keys,
            ctx,
        );

        ct = apply_activation(&ct, &net.activations[i], &keys.eval_key, ctx);
    }

    ct
}

/// Server-side forward pass on an already-encrypted ciphertext.
///
/// Runs all layers (linear + activation) without encryption/decryption.
/// The server never sees the plaintext — it only operates on ciphertexts.
pub fn rns_forward_encrypted(
    ct: &RnsCiphertext,
    net: &RnsNeuralNet,
    eval_key: &RnsEvalKey,
    rotation_keys: &RnsRotationKeySet,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    let mut ct = ct.clone();
    for i in 0..net.weights.len() {
        ct = rns_linear_layer(
            &ct,
            &net.weights[i],
            &net.biases[i],
            net.dim,
            rotation_keys,
            ctx,
        );
        ct = apply_activation(&ct, &net.activations[i], eval_key, ctx);
    }
    ct
}

/// Plaintext reference computation for verification.
///
/// Computes the same forward pass without encryption. Used to verify
/// that the encrypted result matches.
pub fn rns_plaintext_forward(input: &[f64], net: &RnsNeuralNet) -> Vec<f64> {
    let d = net.dim;
    let mut x = input.to_vec();

    for i in 0..net.weights.len() {
        // y = W * x + b
        let mut y = vec![0.0f64; d];
        for row in 0..d {
            for col in 0..d {
                y[row] += net.weights[i][row * d + col] * x[col];
            }
            y[row] += net.biases[i][row];
        }

        // Activation
        for v in y.iter_mut() {
            *v = apply_activation_plain(*v, &net.activations[i]);
        }

        x = y;
    }

    x
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
    fn ct_add_plain_simd_correctness() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let values = vec![1.0, 2.0, 3.0, 4.0];
        let biases = vec![0.1, 0.2, 0.3, 0.4];
        let d = 4;

        let x_rep = replicate_vector(&values, d);
        let ct = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_biased = rns_ct_add_plain_simd(&ct, &biases, d);

        let decrypted = rns_decrypt_simd(&ct_biased, &s, &ctx, d);

        for i in 0..d {
            let expected = values[i] + biases[i];
            assert!(
                (decrypted[i] - expected).abs() < 0.01,
                "slot {} bias add: expected {}, got {}",
                i, expected, decrypted[i]
            );
        }
    }

    #[test]
    fn linear_layer_identity() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let d = 4;
        let mut identity = vec![0.0f64; d * d];
        for i in 0..d {
            identity[i * d + i] = 1.0;
        }
        let biases = vec![0.0; d];

        let x = vec![1.0, 2.0, 3.0, 4.0];
        let rotations: Vec<i32> = (1..d as i32).collect();
        let rot_keys = rns_gen_rotation_keys(&s, &rotations, &ctx, &mut rng);

        let x_rep = replicate_vector(&x, d);
        let ct = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_out = rns_linear_layer(&ct, &identity, &biases, d, &rot_keys, &ctx);

        let decrypted = rns_decrypt_simd(&ct_out, &s, &ctx, d);

        for i in 0..d {
            assert!(
                (decrypted[i] - x[i]).abs() < 1.0,
                "slot {} identity: expected {}, got {}",
                i, x[i], decrypted[i]
            );
        }
    }

    #[test]
    fn linear_layer_with_bias() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let d = 4;
        let w = vec![
            0.5, 0.1, 0.0, 0.0,
            0.0, 0.5, 0.1, 0.0,
            0.0, 0.0, 0.5, 0.1,
            0.1, 0.0, 0.0, 0.5,
        ];
        let biases = vec![1.0, 2.0, 3.0, 4.0];

        let x = vec![2.0, 4.0, 6.0, 8.0];

        // Expected: W*x + b
        let mut expected = vec![0.0f64; d];
        for i in 0..d {
            for j in 0..d {
                expected[i] += w[i * d + j] * x[j];
            }
            expected[i] += biases[i];
        }

        let rotations: Vec<i32> = (1..d as i32).collect();
        let rot_keys = rns_gen_rotation_keys(&s, &rotations, &ctx, &mut rng);

        let x_rep = replicate_vector(&x, d);
        let ct = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_out = rns_linear_layer(&ct, &w, &biases, d, &rot_keys, &ctx);

        let decrypted = rns_decrypt_simd(&ct_out, &s, &ctx, d);

        println!("Linear+bias expected: {:?}", expected);
        println!("Linear+bias got:      {:?}", decrypted);

        for i in 0..d {
            assert!(
                (decrypted[i] - expected[i]).abs() < 2.0,
                "slot {} linear+bias: expected {}, got {}",
                i, expected[i], decrypted[i]
            );
        }
    }

    #[test]
    fn square_activation_correctness() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let values = vec![1.0, 2.0, 3.0, -1.5];
        let expected: Vec<f64> = values.iter().map(|v| v * v).collect();

        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_sq = rns_square_activation(&ct, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_sq, &s, &ctx, values.len());

        for i in 0..values.len() {
            assert!(
                (decrypted[i] - expected[i]).abs() < 1.0,
                "slot {} square: expected {}, got {}",
                i, expected[i], decrypted[i]
            );
        }
    }

    #[test]
    fn square_replicated_at_fresh_level() {
        // Squaring with all 2048 slots filled (replicated pattern) at fresh level.
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let values = vec![1.0, 2.0, 3.0, -1.5];
        let d = 4;
        let x_rep = replicate_vector(&values, d);
        let ct = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);

        let ct_sq = rns_square_activation(&ct, &evk, &ctx);
        let decrypted = rns_decrypt_simd(&ct_sq, &s, &ctx, d);

        let expected: Vec<f64> = values.iter().map(|v| v * v).collect();
        for i in 0..d {
            assert!(
                (decrypted[i] - expected[i]).abs() < 1.0,
                "slot {} replicated square: expected {}, got {}",
                i, expected[i], decrypted[i]
            );
        }
    }

    #[test]
    fn square_after_rescale_4_primes() {
        // Square at level 1 (3 primes) after plaintext multiply + rescale.
        // Uses 4 primes so squaring rescales 3→2 (not 2→1).
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(4);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let values = vec![1.0, 2.0, 3.0, 4.0];
        let d = 4;
        let x_rep = replicate_vector(&values, d);
        let ct = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);

        // Plaintext multiply + rescale: 4→3 primes
        let ones = replicate_vector(&vec![1.0; d], d);
        let ct_mul = rns_ct_mul_plain_simd(&ct, &ones, &ctx);
        let ct_rescaled = rns_rescale(&ct_mul);
        assert_eq!(ct_rescaled.c0.num_primes, 3);

        let dec_after_rescale = rns_decrypt_simd(&ct_rescaled, &s, &ctx, d);
        println!("After pt mul + rescale (3 primes): {:?}", dec_after_rescale);
        println!("  scale={}", ct_rescaled.scale);

        // ct*ct
        let triple = rns_ct_mul(&ct_rescaled, &ct_rescaled, &ctx);
        println!("After ct*ct: scale={}", triple.scale);

        // Relin
        let ct_relin = rns_relinearize(triple, &evk, &ctx);
        let dec_after_relin = rns_decrypt_simd(&ct_relin, &s, &ctx, d);
        println!("After relin (3 primes): {:?}", dec_after_relin);
        println!("  scale={}, primes={}", ct_relin.scale, ct_relin.c0.num_primes);

        // Rescale
        let ct_sq = rns_rescale(&ct_relin);
        let decrypted = rns_decrypt_simd(&ct_sq, &s, &ctx, d);
        println!("After rescale (2 primes): {:?}", decrypted);
        println!("  scale={}, primes={}", ct_sq.scale, ct_sq.c0.num_primes);

        let expected: Vec<f64> = values.iter().map(|v| v * v).collect();
        println!("Expected: {:?}", expected);

        for i in 0..d {
            assert!(
                (decrypted[i] - expected[i]).abs() < 3.0,
                "slot {} square after rescale: expected {}, got {}",
                i, expected[i], decrypted[i]
            );
        }
    }

    #[test]
    fn drop_last_prime_simd_roundtrip() {
        // Encode SIMD values, multiply by q_last, drop_last_prime → exact recovery.
        use super::super::ntt::NTT_PRIMES;

        let values = vec![1.0, 2.0, 3.0, 4.0];
        let d = 4;
        let scale = 1073741824.0; // 2^30

        let x_rep = replicate_vector(&values, d);
        let coeffs = simd::encode_simd(&x_rep, scale);
        let poly_2 = super::super::rns::RnsPoly::from_coeffs(&coeffs, 2);
        let q_last = NTT_PRIMES[1];
        let poly_scaled = poly_2.scalar_mul(q_last);
        let poly_1 = poly_scaled.drop_last_prime();
        let out_coeffs = poly_1.to_coeffs();

        let decoded = simd::decode_simd(&out_coeffs, scale, d);
        for i in 0..d {
            assert!((decoded[i] - values[i]).abs() < 0.01,
                "slot {} exact: expected {}, got {}", i, values[i], decoded[i]);
        }
    }

    #[test]
    fn single_layer_4_primes() {
        // Linear -> Square -> Decrypt
        // 4 primes: linear consumes 1 level (4→3), square consumes 1 level (3→2)
        // Decrypt at 2 primes — avoids catastrophic 2→1 rescaling.
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(4);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let d = 4;
        let w = vec![
            0.5, 0.1, 0.0, 0.0,
            0.0, 0.5, 0.1, 0.0,
            0.0, 0.0, 0.5, 0.1,
            0.1, 0.0, 0.0, 0.5,
        ];
        let biases = vec![0.1, 0.2, 0.3, 0.4];

        let input = vec![1.0, 2.0, 3.0, 4.0];

        let net = RnsNeuralNet {
            dim: d,
            weights: vec![w.clone()],
            biases: vec![biases.clone()],
            activations: vec![Activation::Square],
        };
        let expected = rns_plaintext_forward(&input, &net);

        let rotations: Vec<i32> = (1..d as i32).collect();
        let rot_keys = rns_gen_rotation_keys(&s, &rotations, &ctx, &mut rng);

        let x_rep = replicate_vector(&input, d);
        let ct = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);

        let ct_linear = rns_linear_layer(&ct, &w, &biases, d, &rot_keys, &ctx);
        let ct_sq = rns_square_activation(&ct_linear, &evk, &ctx);

        assert_eq!(ct_sq.c0.num_primes, 2, "should decrypt at 2 primes");

        let dec_sq = rns_decrypt_simd(&ct_sq, &s, &ctx, d);
        println!("1-layer expected: {:?}", expected);
        println!("1-layer got:      {:?}", dec_sq);

        for i in 0..d {
            assert!(
                (dec_sq[i] - expected[i]).abs() < 3.0,
                "slot {} 1-layer: expected {}, got {}",
                i, expected[i], dec_sq[i]
            );
        }
    }

    #[test]
    fn two_layer_5_primes() {
        // Linear -> Square -> Linear (no final activation), 3 levels consumed
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(5);

        let d = 4;
        let net = RnsNeuralNet {
            dim: d,
            weights: vec![
                // Layer 1
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
            activations: vec![Activation::Square, Activation::None],
        };

        let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);

        let input = vec![1.0, 2.0, 3.0, 4.0];
        let expected = rns_plaintext_forward(&input, &net);

        let ct_result = rns_forward(&input, &net, &keys, &ctx, &mut rng);
        let decrypted = rns_decrypt_simd(&ct_result, &keys.secret, &ctx, d);

        println!("2-layer expected: {:?}", expected);
        println!("2-layer got:      {:?}", decrypted);

        for i in 0..d {
            assert!(
                (decrypted[i] - expected[i]).abs() < 5.0,
                "slot {} 2-layer: expected {}, got {}",
                i, expected[i], decrypted[i]
            );
        }
    }

    #[test]
    fn plaintext_forward_correctness() {
        let d = 4;
        let net = RnsNeuralNet {
            dim: d,
            weights: vec![vec![
                1.0, 0.0, 0.0, 0.0,
                0.0, 2.0, 0.0, 0.0,
                0.0, 0.0, 3.0, 0.0,
                0.0, 0.0, 0.0, 4.0,
            ]],
            biases: vec![vec![1.0, 1.0, 1.0, 1.0]],
            activations: vec![Activation::Square],
        };

        let input = vec![1.0, 2.0, 3.0, 4.0];
        let result = rns_plaintext_forward(&input, &net);

        // W*x + b = [1*1+1, 2*2+1, 3*3+1, 4*4+1] = [2, 5, 10, 17]
        // square:   [4, 25, 100, 289]
        assert!((result[0] - 4.0).abs() < 1e-10);
        assert!((result[1] - 25.0).abs() < 1e-10);
        assert!((result[2] - 100.0).abs() < 1e-10);
        assert!((result[3] - 289.0).abs() < 1e-10);
    }

    #[test]
    fn keygen_has_all_rotation_keys() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);

        let d = 4;
        let net = RnsNeuralNet {
            dim: d,
            weights: vec![vec![0.0; d * d]],
            biases: vec![vec![0.0; d]],
            activations: vec![Activation::None],
        };

        let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);

        // Should have rotation keys for 1, 2, 3
        for r in 1..d as i32 {
            assert!(
                keys.rotation_keys.keys.contains_key(&r),
                "missing rotation key for r={}",
                r
            );
        }
    }

    #[test]
    fn silu_activation_single_layer() {
        // Single linear layer + SiLU activation with 10 primes.
        // SiLU poly is degree 6 → 6 levels. Linear layer → 1 level. Total: 7.
        // With 10 primes, 2 remain for decryption.
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(10);
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
            activations: vec![Activation::SiLU],
        };

        let input = vec![1.0, -1.0, 2.0, 0.5];
        let expected = rns_plaintext_forward(&input, &net);

        let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);
        let ct_result = rns_forward(&input, &net, &keys, &ctx, &mut rng);
        let decrypted = rns_decrypt_simd(&ct_result, &keys.secret, &ctx, d);

        println!("SiLU activation:");
        println!("  Expected:  {:?}", expected);
        println!("  Decrypted: {:?}", decrypted);
        println!("  Primes remaining: {}", ct_result.c0.num_primes);

        for i in 0..d {
            assert!(
                (decrypted[i] - expected[i]).abs() < 0.5,
                "slot {} SiLU: expected {:.4}, got {:.4}",
                i, expected[i], decrypted[i]
            );
        }
    }
}
