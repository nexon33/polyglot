//! Private Inference Demo — RNS-CKKS with SiLU Activation
//!
//! End-to-end encrypted neural network inference using:
//! - RNS-CKKS with 10 NTT primes (9 multiplication levels)
//! - SIMD packing: 2048 slots per ciphertext
//! - Diagonal matrix-vector multiply for linear layers
//! - Degree-6 minimax polynomial SiLU activation
//!
//! The server computes on encrypted data it CANNOT see.
//!
//! Usage: cargo run --release -p poly-inference --bin poly-demo-rns-fhe

use std::time::Instant;

use poly_client::ckks::rns_ckks::*;
use poly_client::ckks::rns_fhe_layer::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn main() {
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║    Poly Network — Private Inference (RNS-CKKS + SiLU Activation)   ║");
    eprintln!("║                                                                    ║");
    eprintln!("║    Server computes on encrypted data it CANNOT see                 ║");
    eprintln!("║    10 NTT primes · 2048 SIMD slots · degree-6 SiLU polynomial     ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    let mut rng = StdRng::seed_from_u64(42);
    let total_start = Instant::now();

    // ── Network architecture ──────────────────────────────────────────
    let d = 4; // dimension
    let num_primes = 10; // 9 levels: 1 linear + 6 SiLU + 2 reserve

    let net = RnsNeuralNet {
        dim: d,
        weights: vec![vec![
            0.5, 0.3, -0.1, 0.0,
            0.0, 0.5, 0.3, -0.1,
            -0.1, 0.0, 0.5, 0.3,
            0.3, -0.1, 0.0, 0.5,
        ]],
        biases: vec![vec![0.1, -0.2, 0.3, 0.0]],
        activations: vec![Activation::SiLU],
    };

    let input = vec![1.0, -0.5, 2.0, 0.8];

    eprintln!("  Network: {}x{} linear + SiLU activation", d, d);
    eprintln!("  Input:   {:?}", input);
    eprintln!("  Primes:  {} ({} multiplication levels)", num_primes, num_primes - 1);
    eprintln!();

    // ── [1] Plaintext reference ───────────────────────────────────────
    eprintln!("─── Step 1: Plaintext reference ───────────────────────────────────────");
    let expected = rns_plaintext_forward(&input, &net);
    eprintln!("  Reference output: {:?}", expected);
    eprintln!();

    // ── [2] Key generation ────────────────────────────────────────────
    eprint!("─── Step 2: Key generation ");
    let t = Instant::now();
    let ctx = RnsCkksContext::new(num_primes);
    let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);
    let keygen_ms = t.elapsed().as_millis();
    eprintln!("({} ms) ───────────────────────────────────", keygen_ms);
    eprintln!("  Secret key:     ternary polynomial (N=4096, {} primes)", num_primes);
    eprintln!("  Public key:     RLWE pair");
    eprintln!("  Eval key:       digit-decomposed (base 2^18)");
    eprintln!("  Rotation keys:  {} keys (for {}x{} diagonal matvec)", d - 1, d, d);
    eprintln!();

    // ── [3] What the server sees ──────────────────────────────────────
    eprintln!("─── Step 3: What the server receives ──────────────────────────────────");
    eprintln!("  Encrypted input: 1 ciphertext (2 polynomials, {} primes each)", num_primes);
    eprintln!("  Public weights:  {}x{} matrix (plaintext)", d, d);
    eprintln!("  Activation:      SiLU degree-6 polynomial (plaintext coefficients)");
    eprintln!("  Eval key:        for relinearization and rotations");
    eprintln!("  Server CANNOT decrypt — only the client holds the secret key");
    eprintln!();

    // ── [4] Encrypted forward pass ────────────────────────────────────
    eprint!("─── Step 4: Encrypted forward pass ");
    let t = Instant::now();
    let ct_result = rns_forward(&input, &net, &keys, &ctx, &mut rng);
    let forward_ms = t.elapsed().as_millis();
    eprintln!("({} ms) ────────────────────────────", forward_ms);
    eprintln!("  Operations performed (on encrypted data):");
    eprintln!("    1. Replicate input across 2048 SIMD slots");
    eprintln!("    2. Diagonal matrix-vector multiply (W*x + b)");
    eprintln!("    3. SiLU activation via degree-6 Horner evaluation");
    eprintln!("  Primes remaining: {} (started with {})", ct_result.c0.num_primes, num_primes);
    eprintln!("  Final scale: {:.0}", ct_result.scale);
    eprintln!();

    // ── [5] Client decrypts ───────────────────────────────────────────
    eprint!("─── Step 5: Client decrypts result ");
    let t = Instant::now();
    let decrypted = rns_decrypt_simd(&ct_result, &keys.secret, &ctx, d);
    let decrypt_ms = t.elapsed().as_millis();
    eprintln!("({} ms) ────────────────────────────────", decrypt_ms);
    eprintln!();

    // ── [6] Verification ──────────────────────────────────────────────
    eprintln!("─── Step 6: Verification ──────────────────────────────────────────────");
    eprintln!();
    eprintln!("  {:>8}  {:>12}  {:>12}  {:>12}", "Slot", "Expected", "Decrypted", "Error");
    eprintln!("  {:>8}  {:>12}  {:>12}  {:>12}", "────", "────────", "─────────", "─────");

    let mut max_err = 0.0f64;
    let mut sum_err = 0.0f64;
    for i in 0..d {
        let err = (expected[i] - decrypted[i]).abs();
        max_err = max_err.max(err);
        sum_err += err;
        eprintln!(
            "  {:>8}  {:>12.6}  {:>12.6}  {:>12.2e}",
            i, expected[i], decrypted[i], err
        );
    }
    let avg_err = sum_err / d as f64;

    eprintln!();
    eprintln!("  Max error: {:.2e}", max_err);
    eprintln!("  Avg error: {:.2e}", avg_err);
    eprintln!();

    // ── Summary ───────────────────────────────────────────────────────
    let total_ms = total_start.elapsed().as_millis();
    eprintln!("═══════════════════════════════════════════════════════════════════════");
    eprintln!("  TIMING SUMMARY");
    eprintln!("  Key generation:   {:>6} ms", keygen_ms);
    eprintln!("  Forward pass:     {:>6} ms  (server-side, on encrypted data)", forward_ms);
    eprintln!("  Decryption:       {:>6} ms  (client-side)", decrypt_ms);
    eprintln!("  Total:            {:>6} ms", total_ms);
    eprintln!("═══════════════════════════════════════════════════════════════════════");
    eprintln!();

    if max_err < 0.5 {
        eprintln!("  RESULT: Private inference SUCCEEDED (max error < 0.5)");
    } else {
        eprintln!("  RESULT: Private inference FAILED (max error {:.4} >= 0.5)", max_err);
        std::process::exit(1);
    }
    eprintln!();
}
