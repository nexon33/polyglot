//! Encrypted neural network layer operations.
//!
//! Enables server-blind inference: the server computes on CKKS-encrypted
//! activations using public weights, never seeing the plaintext data.
//!
//! Supported operations (Phase 1):
//! - **Linear layer**: y = W·x + b (integer-quantized weights, float biases)
//! - **Quadratic activation**: y ≈ a·x² + b·x + c (SiLU polynomial approximation)
//!
//! Scale budget:
//! - Linear layer uses `ct_scalar_mul` → stays at scale DELTA
//! - Activation uses `ct_mul_relin` → goes to scale DELTA²
//! - Total: 1 multiplication level consumed (max for Phase 1)

use super::ciphertext::CkksCiphertext;
use super::encoding_f64::{encode_f64, encode_f64_at_scale};
use super::eval_key::CkksEvalKey;
use super::homomorphic::{ct_add, ct_add_plain, ct_mul_plain, ct_mul_relin, ct_scalar_mul};
use super::params::DELTA;

/// Compute an encrypted linear layer: y = W·x + b.
///
/// - `ct_inputs`: vector of encrypted activations (each at scale DELTA)
/// - `weights`: weight matrix [output_dim][input_dim], integer-quantized
/// - `biases`: bias vector [output_dim], floating-point
///
/// Returns encrypted output vector at scale DELTA (no multiplication level consumed).
///
/// # Panics
/// - If `weights` rows don't match `biases` length
/// - If `weights` columns don't match `ct_inputs` length
pub fn encrypted_linear(
    ct_inputs: &[CkksCiphertext],
    weights: &[Vec<i64>],
    biases: &[f64],
) -> Vec<CkksCiphertext> {
    let output_dim = weights.len();
    let input_dim = ct_inputs.len();
    assert_eq!(output_dim, biases.len(), "weights rows != biases length");

    let mut outputs = Vec::with_capacity(output_dim);

    for i in 0..output_dim {
        assert_eq!(
            weights[i].len(),
            input_dim,
            "weights[{}] has {} cols, expected {}",
            i,
            weights[i].len(),
            input_dim
        );

        // Weighted sum: w[i][0]*x[0] + w[i][1]*x[1] + ... + w[i][n-1]*x[n-1]
        let mut acc = ct_scalar_mul(&ct_inputs[0], weights[i][0]);
        for j in 1..input_dim {
            let term = ct_scalar_mul(&ct_inputs[j], weights[i][j]);
            acc = ct_add(&acc, &term);
        }

        // Add bias (encoded at same scale as the accumulator)
        let bias_plain = encode_f64(&[biases[i]]);
        acc = ct_add_plain(&acc, &bias_plain);

        outputs.push(acc);
    }

    outputs
}

/// Compute an encrypted quadratic activation: y ≈ a·x² + b·x + c.
///
/// This polynomial approximates SiLU(x) = x·σ(x) for small |x|.
/// Good approximation coefficients for |x| < 5:
///   a = 0.197, b = 0.5, c = 0.0 (or use fitted values)
///
/// - `ct_inputs`: encrypted values at scale DELTA
/// - `evk`: evaluation key for ciphertext-ciphertext multiplication
/// - `a_coeff`: quadratic coefficient (integer, applied to x² via scalar_mul)
/// - `b_coeff`: linear coefficient (float, applied to x via mul_plain)
/// - `c_coeff`: constant term (float, added at scale DELTA²)
///
/// Returns encrypted outputs at scale DELTA² (1 multiplication level consumed).
pub fn encrypted_quadratic_activation(
    ct_inputs: &[CkksCiphertext],
    evk: &CkksEvalKey,
    a_coeff: i64,
    b_coeff: f64,
    c_coeff: f64,
) -> Vec<CkksCiphertext> {
    let scale_squared = DELTA * DELTA;

    let mut outputs = Vec::with_capacity(ct_inputs.len());

    for ct_x in ct_inputs {
        // x² via ciphertext-ciphertext multiply (scale → DELTA²)
        let ct_x2 = ct_mul_relin(ct_x, ct_x, evk);

        // a·x² (integer scalar, scale stays DELTA²)
        let ct_ax2 = ct_scalar_mul(&ct_x2, a_coeff);

        // b·x: multiply by encoded b to bring x from DELTA to DELTA²
        let b_plain = encode_f64(&[b_coeff]);
        let ct_bx = ct_mul_plain(ct_x, &b_plain);

        // c at scale DELTA²
        let c_plain = encode_f64_at_scale(&[c_coeff], scale_squared);

        // a·x² + b·x + c (all at scale DELTA²)
        let ct_sum = ct_add(&ct_ax2, &ct_bx);
        let ct_result = ct_add_plain(&ct_sum, &c_plain);

        outputs.push(ct_result);
    }

    outputs
}

/// Full encrypted forward pass: linear layer → quadratic activation.
///
/// Demonstrates server-blind inference on a single hidden layer.
/// The server never sees the plaintext activations.
///
/// Returns encrypted outputs at scale DELTA² (ready for client decryption).
pub fn encrypted_forward(
    ct_inputs: &[CkksCiphertext],
    weights: &[Vec<i64>],
    biases: &[f64],
    evk: &CkksEvalKey,
    act_a: i64,
    act_b: f64,
    act_c: f64,
) -> Vec<CkksCiphertext> {
    // Linear layer: scale stays DELTA
    let hidden = encrypted_linear(ct_inputs, weights, biases);

    // Activation: scale goes to DELTA²
    encrypted_quadratic_activation(&hidden, evk, act_a, act_b, act_c)
}

/// Plaintext reference computation for verification.
///
/// Computes the same operation as `encrypted_forward` on plaintext values.
/// Used by the client to verify that homomorphic computation is correct.
pub fn plaintext_forward(
    inputs: &[f64],
    weights: &[Vec<i64>],
    biases: &[f64],
    act_a: i64,
    act_b: f64,
    act_c: f64,
) -> Vec<f64> {
    let output_dim = weights.len();
    let mut outputs = Vec::with_capacity(output_dim);

    for i in 0..output_dim {
        // Linear: w·x + b
        let mut h: f64 = biases[i];
        for j in 0..inputs.len() {
            h += weights[i][j] as f64 * inputs[j];
        }

        // Quadratic activation: a·h² + b·h + c
        let activated = act_a as f64 * h * h + act_b * h + act_c;
        outputs.push(activated);
    }

    outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::encoding_f64::{decode_f64_with_scale, encode_f64};
    use crate::ckks::eval_key::gen_eval_key;
    use crate::ckks::keys::keygen;
    use crate::ckks::poly::Poly;
    use crate::ckks::sampling::{sample_gaussian, sample_ternary};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    fn encrypt_poly(
        m: &Poly,
        pk: &crate::ckks::keys::CkksPublicKey,
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
            auth_tag: None,
            key_id: None,
            nonce: None,
        }
    }

    fn encrypt_f64_vec(
        values: &[f64],
        pk: &crate::ckks::keys::CkksPublicKey,
        rng: &mut StdRng,
    ) -> Vec<CkksCiphertext> {
        values
            .iter()
            .map(|&v| encrypt_poly(&encode_f64(&[v]), pk, rng))
            .collect()
    }

    fn decrypt_f64(
        ct: &CkksCiphertext,
        sk: &crate::ckks::keys::CkksSecretKey,
    ) -> f64 {
        let (c0, c1) = &ct.chunks[0];
        let m_noisy = c0.add(&c1.mul(&sk.s));
        decode_f64_with_scale(&m_noisy, 1, ct.scale)[0]
    }

    #[test]
    fn linear_layer_simple() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        // Input: [2.0, 3.0]
        // Weights: [[1, 2], [3, -1]]
        // Biases: [0.5, -0.5]
        // Expected: [1*2 + 2*3 + 0.5, 3*2 + (-1)*3 + (-0.5)] = [8.5, 2.5]
        let ct_inputs = encrypt_f64_vec(&[2.0, 3.0], &pk, &mut rng);
        let weights = vec![vec![1, 2], vec![3, -1]];
        let biases = vec![0.5, -0.5];

        let ct_outputs = encrypted_linear(&ct_inputs, &weights, &biases);
        assert_eq!(ct_outputs.len(), 2);

        let out0 = decrypt_f64(&ct_outputs[0], &sk);
        let out1 = decrypt_f64(&ct_outputs[1], &sk);

        assert!((out0 - 8.5).abs() < 0.01, "expected 8.5, got {}", out0);
        assert!((out1 - 2.5).abs() < 0.01, "expected 2.5, got {}", out1);
    }

    #[test]
    fn linear_layer_4_to_2() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let inputs = [1.5, -0.7, 2.3, 0.1];
        let ct_inputs = encrypt_f64_vec(&inputs, &pk, &mut rng);
        let weights = vec![vec![3, -2, 1, 4], vec![-1, 5, -3, 2]];
        let biases = vec![0.5, -0.3];

        let ct_outputs = encrypted_linear(&ct_inputs, &weights, &biases);

        let expected0 = 3.0 * 1.5 + (-2.0) * (-0.7) + 1.0 * 2.3 + 4.0 * 0.1 + 0.5;
        let expected1 = (-1.0) * 1.5 + 5.0 * (-0.7) + (-3.0) * 2.3 + 2.0 * 0.1 + (-0.3);

        let out0 = decrypt_f64(&ct_outputs[0], &sk);
        let out1 = decrypt_f64(&ct_outputs[1], &sk);

        assert!(
            (out0 - expected0).abs() < 0.01,
            "expected {}, got {}",
            expected0,
            out0
        );
        assert!(
            (out1 - expected1).abs() < 0.01,
            "expected {}, got {}",
            expected1,
            out1
        );
    }

    #[test]
    fn quadratic_activation_simple() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);

        // y = 1*x^2 + 0*x + 0 = x^2
        // x = 3.0 → y = 9.0
        let ct_inputs = encrypt_f64_vec(&[3.0], &pk, &mut rng);
        let ct_outputs = encrypted_quadratic_activation(&ct_inputs, &evk, 1, 0.0, 0.0);

        let out = decrypt_f64(&ct_outputs[0], &sk);
        assert!(
            (out - 9.0).abs() < 0.1,
            "expected ~9.0, got {}",
            out
        );
    }

    #[test]
    fn full_forward_pass() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);

        let inputs = [1.0, 2.0];
        let weights = vec![vec![2, -1], vec![1, 3]];
        let biases = vec![0.0, 0.0];
        let (act_a, act_b, act_c) = (1, 0.5, 0.0);

        // Plaintext reference
        let expected = plaintext_forward(&inputs, &weights, &biases, act_a, act_b, act_c);

        // Encrypted
        let ct_inputs = encrypt_f64_vec(&inputs, &pk, &mut rng);
        let ct_outputs = encrypted_forward(
            &ct_inputs, &weights, &biases, &evk, act_a, act_b, act_c,
        );

        for (i, ct) in ct_outputs.iter().enumerate() {
            let decrypted = decrypt_f64(ct, &sk);
            assert!(
                (decrypted - expected[i]).abs() < 0.5,
                "output {}: expected {}, got {}",
                i,
                expected[i],
                decrypted
            );
        }
    }

    #[test]
    fn plaintext_matches_encrypted() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);
        let evk = gen_eval_key(&sk, &mut rng);

        let inputs = [1.5, -0.7, 2.3, 0.1];
        let weights = vec![vec![3, -2, 1, 4], vec![-1, 5, -3, 2]];
        let biases = vec![0.5, -0.3];
        // SiLU approximation coefficients (rough)
        let (act_a, act_b, act_c) = (1, 0.5, 0.0);

        let expected = plaintext_forward(&inputs, &weights, &biases, act_a, act_b, act_c);

        let ct_inputs = encrypt_f64_vec(&inputs, &pk, &mut rng);
        let ct_outputs = encrypted_forward(
            &ct_inputs, &weights, &biases, &evk, act_a, act_b, act_c,
        );

        for (i, ct) in ct_outputs.iter().enumerate() {
            let decrypted = decrypt_f64(ct, &sk);
            assert!(
                (decrypted - expected[i]).abs() < 1.0,
                "output {}: expected {:.4}, got {:.4} (error {:.4})",
                i,
                expected[i],
                decrypted,
                (decrypted - expected[i]).abs()
            );
        }
    }
}
