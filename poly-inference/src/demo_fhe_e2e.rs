//! End-to-End Encrypted Inference over HTTP — Server NEVER sees the data.
//!
//! Full pipeline:
//!   1. Client tokenizes "The capital of France is" with Qwen3-0.6B
//!   2. Client generates CKKS keys and encrypts token-derived activations
//!   3. Client sends encrypted ciphertexts + eval key to server over HTTP
//!   4. Server computes encrypted forward pass (linear + activation) — BLIND
//!   5. Server returns encrypted results over HTTP
//!   6. Client decrypts, verifies against plaintext reference
//!
//! Usage: cargo run --release -p poly-inference --bin poly-demo-fhe-e2e

use std::thread;
use std::time::Instant;

use poly_client::ckks::ciphertext::CkksCiphertext;
use poly_client::ckks::encoding_f64::{decode_f64_with_scale, encode_f64};
use poly_client::ckks::eval_key::{gen_eval_key, CkksEvalKey};
use poly_client::ckks::fhe_layer::{encrypted_forward, plaintext_forward};
use poly_client::ckks::keys::{keygen, CkksPublicKey, CkksSecretKey};
use poly_client::ckks::params::DELTA;
use poly_client::ckks::poly::Poly;
use poly_client::ckks::sampling::{sample_gaussian, sample_ternary};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server, StatusCode};

fn separator() {
    eprintln!("{}", "─".repeat(72));
}

// ═══════════════════════════════════════════════════════════════════════
// Wire protocol: JSON payloads for encrypted inference over HTTP
// ═══════════════════════════════════════════════════════════════════════

/// Request: client → server (all encrypted, server cannot read activations)
#[derive(Serialize, Deserialize)]
struct FheInferRequest {
    /// Encrypted activation values (one ciphertext per value)
    encrypted_activations: Vec<CkksCiphertext>,
    /// Evaluation key for ciphertext-ciphertext multiply (public, safe to share)
    eval_key: CkksEvalKey,
    /// Public model weights (integer-quantized)
    weights: Vec<Vec<i64>>,
    /// Public model biases
    biases: Vec<f64>,
    /// Activation polynomial coefficients: a*x^2 + b*x + c
    act_a: i64,
    act_b: f64,
    act_c: f64,
}

/// Response: server → client (encrypted results, server never saw plaintext)
#[derive(Serialize, Deserialize)]
struct FheInferResponse {
    /// Encrypted output activations
    encrypted_outputs: Vec<CkksCiphertext>,
    /// Server-side compute time in milliseconds
    compute_ms: f64,
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

fn main() {
    let prompt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "The capital of France is".to_string());

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║   Poly Network — End-to-End Encrypted Inference over HTTP           ║");
    eprintln!("║                                                                      ║");
    eprintln!("║   Client ──CKKS──► HTTP ──► Server (BLIND) ──► HTTP ──► Client       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    let total_start = Instant::now();
    let mut rng = StdRng::seed_from_u64(42);

    // ── [1] Load model & tokenize ──────────────────────────────────────
    eprint!("[1/9] Loading Qwen3-0.6B model...");
    let t = Instant::now();
    poly_inference::model::load_model(candle_core::Device::Cpu)
        .expect("failed to load model");
    let model_time = t.elapsed();
    eprintln!(" done ({:.1}s)", model_time.as_secs_f64());

    let token_ids = poly_inference::model::tokenize(&prompt).expect("tokenization failed");
    eprintln!("[2/9] Tokenized: {:?}", prompt);
    eprintln!("       Token IDs: {:?} ({} tokens)", token_ids, token_ids.len());
    eprintln!();

    // ── Derive activations from token IDs ──────────────────────────────
    // Use token IDs as activation values (normalized to [-5, 5] range)
    // In a full system, these would be actual embedding vectors from the model
    let activations: Vec<f64> = token_ids
        .iter()
        .map(|&id| (id as f64 / 10000.0) - 5.0) // normalize to [-5, 5]
        .collect();
    let input_dim = activations.len();

    // Network architecture: input_dim → 2 hidden → SiLU(approx)
    // Weights simulate a projection layer
    let weights = vec![
        (0..input_dim).map(|i| if i % 2 == 0 { 2 } else { -1 }).collect::<Vec<i64>>(),
        (0..input_dim).map(|i| if i % 2 == 0 { -1 } else { 3 }).collect::<Vec<i64>>(),
    ];
    let biases = vec![0.5, -0.3];
    let (act_a, act_b, act_c) = (1_i64, 0.5_f64, 0.0_f64);

    eprintln!("       Activations (from tokens): {:?}", activations);
    eprintln!("       Network: {} → 2 → SiLU(approx)", input_dim);
    eprintln!();

    // ── [3] Client: generate CKKS keys ─────────────────────────────────
    eprint!("[3/9] Client generating CKKS keys...");
    let t = Instant::now();
    let (pk, sk) = keygen(&mut rng);
    let evk = gen_eval_key(&sk, &mut rng);
    let keygen_time = t.elapsed();
    eprintln!(" done ({:.1}ms)", keygen_time.as_secs_f64() * 1000.0);
    eprintln!("       Public key:  {} coefficients", pk.a.coeffs.len());
    eprintln!("       Eval key:    {} digit pairs", evk.keys.len());
    eprintln!("       Secret key:  kept by client (NEVER sent to server)");
    eprintln!();

    // ── [4] Client: encrypt activations ────────────────────────────────
    eprint!("[4/9] Client encrypting {} activations...", input_dim);
    let t = Instant::now();
    let ct_inputs = encrypt_f64_vec(&activations, &pk, &mut rng);
    let encrypt_time = t.elapsed();
    eprintln!(" done ({:.1}ms)", encrypt_time.as_secs_f64() * 1000.0);
    eprintln!();

    // ── [5] Serialize request ──────────────────────────────────────────
    eprint!("[5/9] Serializing encrypted request...");
    let t = Instant::now();
    let request = FheInferRequest {
        encrypted_activations: ct_inputs,
        eval_key: evk,
        weights: weights.clone(),
        biases: biases.clone(),
        act_a,
        act_b,
        act_c,
    };
    let req_json = serde_json::to_string(&request).unwrap();
    let serialize_time = t.elapsed();
    let req_size = req_json.len();
    eprintln!(" done ({:.1}ms)", serialize_time.as_secs_f64() * 1000.0);
    eprintln!("       Request size: {} bytes ({:.1} MB)", req_size, req_size as f64 / 1_048_576.0);
    eprintln!();

    // ── [6] Start HTTP server ──────────────────────────────────────────
    separator();
    eprintln!("  HTTP TRANSPORT: Client → Server → Client");
    separator();
    eprintln!();

    let server = Server::http("127.0.0.1:0")
        .map_err(|e| format!("bind failed: {}", e))
        .unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    eprintln!("  [server] Listening on http://{}/fhe-infer", addr);
    eprintln!("  [server] Server has NO secret key — cannot decrypt anything");
    eprintln!();

    // Server thread: receives encrypted data, computes blind, returns encrypted results
    let handle = thread::spawn(move || {
        let mut request = server.recv().unwrap();

        let json_header =
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();

        if request.method() != &Method::Post || request.url() != "/fhe-infer" {
            let resp = Response::new(
                StatusCode(404),
                vec![json_header],
                std::io::Cursor::new(b"{\"error\":\"not found\"}".to_vec()),
                None,
                None,
            );
            request.respond(resp).unwrap();
            return;
        }

        let mut body = Vec::new();
        request.as_reader().read_to_end(&mut body).unwrap();

        let req: FheInferRequest = serde_json::from_slice(&body).unwrap();

        // ── SERVER COMPUTATION (BLIND — cannot see activations) ──
        let compute_start = Instant::now();
        let encrypted_outputs = encrypted_forward(
            &req.encrypted_activations,
            &req.weights,
            &req.biases,
            &req.eval_key,
            req.act_a,
            req.act_b,
            req.act_c,
        );
        let compute_ms = compute_start.elapsed().as_secs_f64() * 1000.0;

        let resp = FheInferResponse {
            encrypted_outputs,
            compute_ms,
        };
        let resp_json = serde_json::to_vec(&resp).unwrap();

        let response = Response::new(
            StatusCode(200),
            vec![json_header],
            std::io::Cursor::new(resp_json),
            None,
            None,
        );
        request.respond(response).unwrap();
    });

    // ── [7] Client: send request over HTTP ─────────────────────────────
    eprint!("[6/9] Client POST http://{}/fhe-infer ...", addr);
    let t = Instant::now();
    let url = format!("http://{}/fhe-infer", addr);
    let mut http_resp = ureq::post(&url)
        .content_type("application/json")
        .send(&req_json)
        .expect("HTTP request failed");

    let resp_body = http_resp.body_mut().read_to_string().unwrap();
    let http_time = t.elapsed();
    let resp_size = resp_body.len();
    eprintln!(" done ({:.1}ms)", http_time.as_secs_f64() * 1000.0);
    eprintln!("       Response size: {} bytes ({:.1} MB)", resp_size, resp_size as f64 / 1_048_576.0);
    eprintln!();

    handle.join().unwrap();

    // ── [8] Client: deserialize and decrypt ────────────────────────────
    eprint!("[7/9] Deserializing response...");
    let t = Instant::now();
    let resp: FheInferResponse = serde_json::from_str(&resp_body).unwrap();
    let deserialize_time = t.elapsed();
    eprintln!(" done ({:.1}ms)", deserialize_time.as_secs_f64() * 1000.0);

    eprintln!("       Server compute time: {:.1}ms (blind, on encrypted data)", resp.compute_ms);
    eprintln!();

    eprint!("[8/9] Client decrypting {} outputs...", resp.encrypted_outputs.len());
    let t = Instant::now();
    let decrypted: Vec<f64> = resp
        .encrypted_outputs
        .iter()
        .map(|ct| decrypt_f64_single(ct, &sk))
        .collect();
    let decrypt_time = t.elapsed();
    eprintln!(" done ({:.1}ms)", decrypt_time.as_secs_f64() * 1000.0);
    eprintln!();

    // ── [9] Verify against plaintext ───────────────────────────────────
    separator();
    eprintln!("  VERIFICATION");
    separator();
    eprintln!();

    let expected = plaintext_forward(&activations, &weights, &biases, act_a, act_b, act_c);

    eprintln!("[9/9] Comparing encrypted vs plaintext computation:");
    eprintln!();
    eprintln!("       {:<12} {:>14} {:>14} {:>12}", "Output", "Encrypted", "Plaintext", "Error");
    eprintln!("       {:<12} {:>14} {:>14} {:>12}", "------", "---------", "---------", "-----");

    let mut max_error = 0.0f64;
    for (i, (dec, exp)) in decrypted.iter().zip(expected.iter()).enumerate() {
        let err = (dec - exp).abs();
        max_error = max_error.max(err);
        eprintln!(
            "       {:<12} {:>14.6} {:>14.6} {:>12.6}",
            format!("neuron_{}", i),
            dec,
            exp,
            err
        );
    }

    let verified = max_error < 1.0;
    eprintln!();
    eprintln!("       Max error:  {:.6}", max_error);
    eprintln!("       Verified:   {}", if verified { "PASS" } else { "FAIL" });
    eprintln!();

    // ── Timing summary ─────────────────────────────────────────────────
    let total_time = total_start.elapsed();

    separator();
    eprintln!("  TIMING BREAKDOWN");
    separator();
    eprintln!();
    eprintln!("  Model load:          {:>10.1}ms", model_time.as_secs_f64() * 1000.0);
    eprintln!("  CKKS keygen:         {:>10.1}ms", keygen_time.as_secs_f64() * 1000.0);
    eprintln!("  Encrypt activations: {:>10.1}ms", encrypt_time.as_secs_f64() * 1000.0);
    eprintln!("  Serialize request:   {:>10.1}ms", serialize_time.as_secs_f64() * 1000.0);
    eprintln!("  HTTP round-trip:     {:>10.1}ms  (includes server compute)", http_time.as_secs_f64() * 1000.0);
    eprintln!("    Server compute:    {:>10.1}ms  (BLIND — encrypted throughout)", resp.compute_ms);
    eprintln!("    Network overhead:  {:>10.1}ms", http_time.as_secs_f64() * 1000.0 - resp.compute_ms);
    eprintln!("  Deserialize resp:    {:>10.1}ms", deserialize_time.as_secs_f64() * 1000.0);
    eprintln!("  Decrypt outputs:     {:>10.1}ms", decrypt_time.as_secs_f64() * 1000.0);
    eprintln!("  ──────────────────────────────────");
    let pipeline_ms = keygen_time.as_secs_f64() * 1000.0
        + encrypt_time.as_secs_f64() * 1000.0
        + serialize_time.as_secs_f64() * 1000.0
        + http_time.as_secs_f64() * 1000.0
        + deserialize_time.as_secs_f64() * 1000.0
        + decrypt_time.as_secs_f64() * 1000.0;
    eprintln!("  Total pipeline:      {:>10.1}ms  (keygen → decrypt, excl. model load)", pipeline_ms);
    eprintln!("  Total wall clock:    {:>10.1}ms", total_time.as_secs_f64() * 1000.0);
    eprintln!();

    separator();
    eprintln!("  PAYLOAD SIZES");
    separator();
    eprintln!();
    eprintln!("  Request:   {:>10} bytes ({:.1} MB) — {} encrypted activations + eval key",
        req_size, req_size as f64 / 1_048_576.0, input_dim);
    eprintln!("  Response:  {:>10} bytes ({:.1} MB) — {} encrypted outputs",
        resp_size, resp_size as f64 / 1_048_576.0, resp.encrypted_outputs.len());
    eprintln!();

    separator();
    eprintln!("  SUMMARY");
    separator();
    eprintln!();
    eprintln!("  Prompt:            \"{}\"", prompt);
    eprintln!("  Tokens:            {:?} ({} tokens)", token_ids, token_ids.len());
    eprintln!("  Network:           {} → 2 → SiLU(approx)", input_dim);
    eprintln!("  Encryption:        CKKS (Ring-LWE, N=4096, Q=2^54)");
    eprintln!("  Transport:         HTTP (localhost)");
    eprintln!("  Server compute:    {:.1}ms (on encrypted data)", resp.compute_ms);
    eprintln!("  Max error:         {:.6}", max_error);
    eprintln!("  Server saw data:   NO (CKKS encrypted throughout)");
    eprintln!("  Verified correct:  {}", if verified { "YES" } else { "NO" });
    eprintln!();
    separator();
    eprintln!("  The server computed y = activation(W*x + b) on encrypted activations");
    eprintln!("  derived from tokenizing \"{}\".", prompt);
    eprintln!("  At NO point did the server see the plaintext values.");
    eprintln!("  The client decrypted and verified correctness over HTTP.");
    separator();
    eprintln!();
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

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
        auth_tag: None,
        key_id: None,
        nonce: None,
    }
}

fn decrypt_f64_single(ct: &CkksCiphertext, sk: &CkksSecretKey) -> f64 {
    let (c0, c1) = &ct.chunks[0];
    let m_noisy = c0.add(&c1.mul(&sk.s));
    decode_f64_with_scale(&m_noisy, 1, ct.scale)[0]
}
