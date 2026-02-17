//! Encrypted Inference Demo — Server computes on data it cannot see.
//!
//! Demonstrates CKKS homomorphic encryption for server-blind neural network inference.
//! The server performs a linear layer + activation on CKKS-encrypted activations
//! using public weights, without ever decrypting the data.
//!
//! Usage: cargo run --release -p poly-inference --bin poly-demo-fhe

use std::time::Instant;

use poly_client::ckks::ciphertext::CkksCiphertext;
use poly_client::ckks::encoding_f64::{decode_f64_with_scale, encode_f64};
use poly_client::ckks::eval_key::gen_eval_key;
use poly_client::ckks::fhe_layer::{
    encrypted_forward, encrypted_linear, encrypted_quadratic_activation, plaintext_forward,
};
use poly_client::ckks::keys::{keygen, CkksPublicKey, CkksSecretKey};
use poly_client::ckks::params::DELTA;
use poly_client::ckks::poly::Poly;
use poly_client::ckks::sampling::{sample_gaussian, sample_ternary};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn separator() {
    eprintln!("{}", "─".repeat(72));
}

fn main() {
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║      Poly Network — Encrypted Inference Demo (FHE / CKKS)          ║");
    eprintln!("║                                                                      ║");
    eprintln!("║   Server computes on encrypted data it CANNOT see                    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    let mut rng = StdRng::seed_from_u64(42);

    // ── Network architecture ──────────────────────────────────────────────
    let inputs = vec![1.5, -0.7, 2.3, 0.1];
    let weights = vec![
        vec![3, -2, 1, 4],
        vec![-1, 5, -3, 2],
    ];
    let biases = vec![0.5, -0.3];
    // SiLU polynomial approximation: a*x^2 + b*x + c
    let (act_a, act_b, act_c) = (1_i64, 0.5_f64, 0.0_f64);

    // ── [1] Client: generate CKKS keys ───────────────────────────────────
    eprint!("[1/7] Client generating CKKS keys...");
    let t = Instant::now();
    let (pk, sk) = keygen(&mut rng);
    let evk = gen_eval_key(&sk, &mut rng);
    eprintln!(" done ({:.1}ms)", t.elapsed().as_secs_f64() * 1000.0);
    eprintln!("       Public key:     {} polynomial coefficients", pk.a.coeffs.len());
    eprintln!("       Secret key:     ternary polynomial (kept by client)");
    eprintln!("       Eval key:       {} digit pairs (sent to server)", evk.keys.len());
    eprintln!();

    // ── [2] Client: encrypt activations ──────────────────────────────────
    eprint!("[2/7] Client encrypting {} activation values...", inputs.len());
    let t = Instant::now();
    let ct_inputs = encrypt_f64_vec(&inputs, &pk, &mut rng);
    eprintln!(" done ({:.1}ms)", t.elapsed().as_secs_f64() * 1000.0);
    eprintln!("       Input values:   {:?}", inputs);
    eprintln!("       Ciphertexts:    {} (one per value, {} coefficients each)",
        ct_inputs.len(), ct_inputs[0].chunks[0].0.coeffs.len());
    eprintln!("       Scale:          DELTA = 2^20 = {}", DELTA);
    eprintln!();

    // ── [3] What the server sees ─────────────────────────────────────────
    separator();
    eprintln!("  SERVER RECEIVES:");
    separator();
    eprintln!();
    eprintln!("  Encrypted activations:  {} ciphertexts (opaque polynomial pairs)", ct_inputs.len());
    eprintln!("  Public weights:         {:?}", weights);
    eprintln!("  Public biases:          {:?}", biases);
    eprintln!("  Activation coeffs:      a={}, b={}, c={}", act_a, act_b, act_c);
    eprintln!("  Eval key:               {} digit pairs", evk.keys.len());
    eprintln!();
    eprintln!("  Server CANNOT decrypt — it has NO access to the secret key.");
    eprintln!("  It computes on the encrypted data using homomorphic operations.");
    eprintln!();

    // ── [4] Server: encrypted linear layer ───────────────────────────────
    separator();
    eprintln!("  SERVER COMPUTING (all on encrypted data):");
    separator();
    eprintln!();

    eprint!("[3/7] Server: encrypted linear layer (4 → 2)...");
    let t = Instant::now();
    let ct_hidden = encrypted_linear(&ct_inputs, &weights, &biases);
    let linear_time = t.elapsed();
    eprintln!(" done ({:.1}ms)", linear_time.as_secs_f64() * 1000.0);
    eprintln!("       Operations: {} ct_scalar_mul + {} ct_add + {} ct_add_plain",
        inputs.len() * weights.len(),
        (inputs.len() - 1) * weights.len(),
        weights.len());
    eprintln!("       Output: {} encrypted hidden values (scale = DELTA)", ct_hidden.len());
    eprintln!();

    // ── [5] Server: encrypted activation ─────────────────────────────────
    eprint!("[4/7] Server: encrypted quadratic activation (SiLU approx)...");
    let t = Instant::now();
    let ct_outputs = encrypted_quadratic_activation(&ct_hidden, &evk, act_a, act_b, act_c);
    let activation_time = t.elapsed();
    eprintln!(" done ({:.1}ms)", activation_time.as_secs_f64() * 1000.0);
    eprintln!("       Operations per neuron: 1 ct_mul_relin + 2 ct_scalar_mul + 1 ct_mul_plain + 2 ct_add");
    eprintln!("       Output: {} encrypted values (scale = DELTA^2 = {})", ct_outputs.len(), DELTA as i64 * DELTA as i64);
    eprintln!("       Multiplication levels consumed: 1 of 1 (budget exhausted)");
    eprintln!();

    // ── [6] Client: decrypt and verify ───────────────────────────────────
    separator();
    eprintln!("  CLIENT DECRYPTS AND VERIFIES:");
    separator();
    eprintln!();

    eprint!("[5/7] Client decrypting results...");
    let t = Instant::now();
    let decrypted: Vec<f64> = ct_outputs
        .iter()
        .map(|ct| decrypt_f64_single(ct, &sk))
        .collect();
    eprintln!(" done ({:.1}ms)", t.elapsed().as_secs_f64() * 1000.0);

    // Plaintext reference
    let expected = plaintext_forward(&inputs, &weights, &biases, act_a, act_b, act_c);

    eprintln!();
    eprintln!("[6/7] Verification against plaintext computation:");
    eprintln!();
    eprintln!("       {:<12} {:>12} {:>12} {:>12}", "Output", "Encrypted", "Plaintext", "Error");
    eprintln!("       {:<12} {:>12} {:>12} {:>12}", "------", "---------", "---------", "-----");
    let mut max_error = 0.0f64;
    for (i, (dec, exp)) in decrypted.iter().zip(expected.iter()).enumerate() {
        let err = (dec - exp).abs();
        max_error = max_error.max(err);
        eprintln!("       {:<12} {:>12.6} {:>12.6} {:>12.6}", format!("neuron_{}", i), dec, exp, err);
    }
    eprintln!();
    eprintln!("       Max error: {:.6} (acceptable: < 1.0)", max_error);
    let verified = max_error < 1.0;
    eprintln!("       Verified:  {}", if verified { "PASS" } else { "FAIL" });
    eprintln!();

    // ── [7] Summary ──────────────────────────────────────────────────────
    separator();
    eprintln!("  PHASE 2: Full Forward Pass (linear + activation combined)");
    separator();
    eprintln!();

    eprint!("[7/7] Full encrypted forward pass...");
    let t = Instant::now();
    let ct_full = encrypted_forward(&ct_inputs, &weights, &biases, &evk, act_a, act_b, act_c);
    let total_time = t.elapsed();
    eprintln!(" done ({:.1}ms)", total_time.as_secs_f64() * 1000.0);

    let full_dec: Vec<f64> = ct_full
        .iter()
        .map(|ct| decrypt_f64_single(ct, &sk))
        .collect();

    for (i, (dec, exp)) in full_dec.iter().zip(expected.iter()).enumerate() {
        let err = (dec - exp).abs();
        eprintln!("       neuron_{}: {:.6} (expected {:.6}, error {:.6})", i, dec, exp, err);
    }
    eprintln!();

    // ── Summary ──────────────────────────────────────────────────────────
    separator();
    eprintln!("  SUMMARY");
    separator();
    eprintln!();
    eprintln!("  Network:           4 → 2 → SiLU(approx)");
    eprintln!("  Encryption:        CKKS (Ring-LWE, N=4096, Q=2^54)");
    eprintln!("  Linear layer:      {:.1}ms", linear_time.as_secs_f64() * 1000.0);
    eprintln!("  Activation:        {:.1}ms", activation_time.as_secs_f64() * 1000.0);
    eprintln!("  Total encrypted:   {:.1}ms", total_time.as_secs_f64() * 1000.0);
    eprintln!("  Max error:         {:.6}", max_error);
    eprintln!("  Server saw data:   NO (CKKS encrypted throughout)");
    eprintln!("  Verified correct:  {}", if verified { "YES" } else { "NO" });
    eprintln!();
    separator();
    eprintln!("  The server computed y = activation(W*x + b) on encrypted x.");
    eprintln!("  At no point did the server see the plaintext activations.");
    eprintln!("  The client decrypted and verified the result matches plaintext.");
    separator();
    eprintln!();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encrypt_f64_vec(
    values: &[f64],
    pk: &CkksPublicKey,
    rng: &mut StdRng,
) -> Vec<CkksCiphertext> {
    values
        .iter()
        .map(|&v| {
            let m = encode_f64(&[v]);
            encrypt_poly(&m, pk, rng)
        })
        .collect()
}

fn encrypt_poly(m: &Poly, pk: &CkksPublicKey, rng: &mut StdRng) -> CkksCiphertext {
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

fn decrypt_f64_single(ct: &CkksCiphertext, sk: &CkksSecretKey) -> f64 {
    let (c0, c1) = &ct.chunks[0];
    let m_noisy = c0.add(&c1.mul(&sk.s));
    decode_f64_with_scale(&m_noisy, 1, ct.scale)[0]
}
