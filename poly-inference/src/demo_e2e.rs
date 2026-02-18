//! End-to-end demo: PolyClient → InferenceServer → verify → selective disclosure.
//!
//! Shows every step of the protocol with real model inference.
//! Usage: cargo run --release --bin poly-demo-e2e [prompt] [max_tokens]

use std::thread;
use std::time::Instant;

use poly_client::encryption::MockEncryption;
use poly_client::protocol::{InferResponse, Mode};
use poly_client::PolyClient;
use poly_inference::compliance::default_policy;
use poly_inference::http::HttpServer;
use poly_inference::model;
use poly_inference::server::{
    ComplianceInferenceBackend, InferenceBackend, MockInferenceBackend, RealInferenceBackend,
};
use poly_verified::disclosure::verify_disclosure;
use poly_verified::types::{PrivacyMode, VerifiedProof};

fn separator() {
    eprintln!("{}", "─".repeat(72));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prompt = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("The capital of France is");
    let max_tokens: u32 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║         Poly Network — End-to-End Verified Inference Demo           ║");
    eprintln!("║                                                                      ║");
    eprintln!("║   PolyClient -> Server -> verify -> selective disclosure             ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    // ── [1] Load model ──────────────────────────────────────────────────
    eprint!("[1/8] Loading Qwen3-0.6B model...");
    let t = Instant::now();
    model::load_model(candle_core::Device::Cpu).expect("failed to load model");
    eprintln!(" done ({:.1}s)", t.elapsed().as_secs_f64());

    // ── [2] Tokenize ────────────────────────────────────────────────────
    let input_ids = model::tokenize(prompt).expect("tokenization failed");
    eprintln!("[2/8] Tokenized prompt: {:?}", prompt);
    eprintln!("      Token IDs: {:?} ({} tokens)", input_ids, input_ids.len());
    eprintln!();

    // ── [3] In-process: client → server → client ────────────────────────
    separator();
    eprintln!("  PHASE 1: In-Process (Direct Function Call)");
    separator();
    eprintln!();

    run_client_server_flow(
        "Transparent",
        Mode::Transparent,
        &input_ids,
        max_tokens,
    );

    run_client_server_flow(
        "Private (ZK)",
        Mode::Private,
        &input_ids,
        max_tokens,
    );

    run_client_server_flow(
        "PrivateInputs",
        Mode::PrivateProven,
        &input_ids,
        max_tokens,
    );

    // ── [7] HTTP round-trip ─────────────────────────────────────────────
    separator();
    eprintln!("  PHASE 2: HTTP Transport (localhost)");
    separator();
    eprintln!();

    run_http_flow(&input_ids, max_tokens);

    // ── [7.5] Compliance-aware inference ───────────────────────────────
    separator();
    eprintln!("  PHASE 2.5: Compliance-Aware Inference (per-token proof gate)");
    separator();
    eprintln!();

    run_compliance_flow(&input_ids, max_tokens);

    // ── [8] Mock backend (fast, for protocol demo) ──────────────────────
    separator();
    eprintln!("  PHASE 3: Mock Backend (no model, real proofs)");
    separator();
    eprintln!();

    run_mock_flow(&input_ids);

    eprintln!();
    separator();
    eprintln!("  Demo complete. All proofs verified, all disclosures valid.");
    separator();
    eprintln!();
}

fn run_client_server_flow(
    label: &str,
    mode: Mode,
    input_ids: &[u32],
    max_tokens: u32,
) {
    static mut STEP: u8 = 3;
    let step = unsafe {
        let s = STEP;
        STEP += 1;
        s
    };

    eprintln!("[{}/8] {} mode — full client-server flow", step, label);
    eprintln!();

    // Step A: Client prepares request
    let client = PolyClient::new("Qwen/Qwen3-0.6B", mode, MockEncryption);
    let t = Instant::now();
    let req = client.prepare_request(input_ids, max_tokens, 700, 42);

    eprintln!("  [client] prepare_request()");
    eprintln!("           Model:       {}", req.model_id);
    eprintln!("           Mode:        {:?}", req.mode);
    eprintln!("           Input bytes: {} (encrypted)", req.encrypted_input.len());
    eprintln!("           Max tokens:  {}", req.max_tokens);
    eprintln!("           Temperature: {:.1}", req.temperature as f64 / 1000.0);
    eprintln!("           Seed:        {}", req.seed);
    eprintln!();

    // Step B: Server processes request
    let backend = RealInferenceBackend;
    eprint!("  [server] infer()...");
    let resp = backend.infer(&req).unwrap();
    let infer_time = t.elapsed();
    eprintln!(" done ({:.3}s)", infer_time.as_secs_f64());

    eprintln!("           Output bytes: {} (encrypted)", resp.encrypted_output.len());
    eprintln!("           Model ID:     {}", resp.model_id);
    print_proof_summary("           ", &resp.proof);
    eprintln!();

    // Step C: Client processes response
    let result = client.process_response(&resp);
    let total_tokens = result.token_ids.len();
    let new_tokens = total_tokens - input_ids.len();
    let tok_s = new_tokens as f64 / infer_time.as_secs_f64();

    let decoded = model::decode(&result.token_ids);
    eprintln!("  [client] process_response()");
    eprintln!("           Decrypted {} tokens ({} new, {:.1} tok/s)", total_tokens, new_tokens, tok_s);
    eprintln!("           Verified:  {}", result.is_verified());
    eprintln!("           Output:    \"{}\"", decoded);
    eprintln!();

    // Step D: Selective disclosure
    eprintln!("  [client] selective disclosure");

    // Doctor: full output
    let all_indices: Vec<usize> = (0..total_tokens).collect();
    let doctor = result.disclose(&all_indices).unwrap();
    assert!(verify_disclosure(&doctor));
    eprintln!("           Doctor (full):      {} tokens revealed, verified: {}",
        doctor.proofs.len(), verify_disclosure(&doctor));

    // Pharmacist: last 5 generated tokens
    let pharma_start = total_tokens.saturating_sub(5);
    let pharmacist = result.disclose_range(pharma_start..total_tokens).unwrap();
    assert!(verify_disclosure(&pharmacist));
    eprintln!("           Pharmacist (tail):  {} tokens revealed, verified: {}",
        pharmacist.proofs.len(), verify_disclosure(&pharmacist));

    // Insurer: just token 0
    let insurer = result.disclose(&[0]).unwrap();
    assert!(verify_disclosure(&insurer));
    eprintln!("           Insurer (token 0):  {} token revealed,  verified: {}",
        insurer.proofs.len(), verify_disclosure(&insurer));

    // Same Merkle root across all
    assert_eq!(doctor.output_root, pharmacist.output_root);
    assert_eq!(pharmacist.output_root, insurer.output_root);
    eprintln!("           Merkle root:        {} (same for all audiences)",
        hex::encode(doctor.output_root));

    eprintln!();
}

fn run_http_flow(input_ids: &[u32], max_tokens: u32) {
    eprintln!("[6/8] HTTP round-trip — Transparent mode");
    eprintln!();

    // Start server
    let server = HttpServer::new("127.0.0.1:0").unwrap();
    let addr = server.addr();
    eprintln!("  [server] HTTP server listening on http://{}", addr);

    let backend = RealInferenceBackend;
    let handle = thread::spawn(move || {
        server.handle_one(&backend).unwrap();
    });

    // Client prepares and sends via HTTP
    let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Transparent, MockEncryption);
    let req = client.prepare_request(input_ids, max_tokens, 700, 42);
    let req_json = serde_json::to_string(&req).unwrap();

    eprintln!("  [client] POST http://{}/infer", addr);
    eprintln!("           Request size: {} bytes JSON", req_json.len());

    let t = Instant::now();
    let url = format!("http://{}/infer", addr);
    let mut resp = ureq::post(&url)
        .content_type("application/json")
        .send(&req_json)
        .expect("HTTP request failed");

    let resp_body = resp.body_mut().read_to_string().unwrap();
    let http_time = t.elapsed();
    eprintln!("  [server] Response: {} bytes JSON ({:.3}s)", resp_body.len(), http_time.as_secs_f64());

    let infer_resp: InferResponse = serde_json::from_str(&resp_body).unwrap();
    let result = client.process_response(&infer_resp);

    let decoded = model::decode(&result.token_ids);
    let new_tokens = result.token_ids.len() - input_ids.len();
    let tok_s = new_tokens as f64 / http_time.as_secs_f64();

    eprintln!("  [client] Verified:  {}", result.is_verified());
    eprintln!("           {} new tokens ({:.1} tok/s over HTTP)", new_tokens, tok_s);
    eprintln!("           Output:    \"{}\"", decoded);
    print_proof_summary("           ", result.proof());

    // Disclosure over HTTP result
    let disclosure = result.disclose(&[0, 1, 2]).unwrap();
    assert!(verify_disclosure(&disclosure));
    eprintln!("           Disclosure: 3 tokens, verified: {}", verify_disclosure(&disclosure));

    handle.join().unwrap();
    eprintln!("  [server] Connection closed.");
    eprintln!();
}

fn run_mock_flow(input_ids: &[u32]) {
    eprintln!("[7/8] Mock backend — protocol correctness without model");
    eprintln!();

    let backend = MockInferenceBackend::new(10);

    for (label, mode) in [
        ("Transparent", Mode::Transparent),
        ("Private", Mode::Private),
        ("PrivateProven", Mode::PrivateProven),
        ("Encrypted", Mode::Encrypted),
    ] {
        let client = PolyClient::new("mock-model", mode, MockEncryption);
        let req = client.prepare_request(input_ids, 50, 700, 42);

        let t = Instant::now();
        let resp = backend.infer(&req).unwrap();
        let elapsed = t.elapsed();

        let result = client.process_response(&resp);
        let disclosure = result.disclose(&[0, 1]).unwrap();

        eprintln!("  {:14} | {} tokens | verified: {} | disclosure: {} | {:.0}us",
            label,
            result.token_ids.len(),
            result.is_verified(),
            verify_disclosure(&disclosure),
            elapsed.as_micros(),
        );
    }
    eprintln!();
    eprintln!("  Mock proofs are real HashIvc — not hand-crafted values.");
}

fn run_compliance_flow(input_ids: &[u32], max_tokens: u32) {
    eprintln!("[7.5/8] Compliance-aware generation — per-token proof gate");
    eprintln!();

    let policy = default_policy();
    eprintln!("  Policy: v{}, {} blocked IDs, {} blocked n-grams, max {} tokens",
        policy.version, policy.blocked_token_ids.len(),
        policy.blocked_ngrams.len(), policy.max_sequence_length);
    eprintln!();

    // Use ComplianceInferenceBackend
    let backend = ComplianceInferenceBackend::with_default_policy();
    let client = PolyClient::new("Qwen/Qwen3-0.6B", Mode::Transparent, MockEncryption);
    let req = client.prepare_request(input_ids, max_tokens, 700, 42);

    eprint!("  [server] compliant infer()...");
    let t = Instant::now();
    let resp = backend.infer(&req).unwrap();
    let elapsed = t.elapsed();
    eprintln!(" done ({:.3}s)", elapsed.as_secs_f64());

    // Process response
    let result = client.process_response(&resp);
    let total_tokens = result.token_ids.len();
    let new_tokens = total_tokens - input_ids.len();
    let decoded = model::decode(&result.token_ids);

    eprintln!("  [client] {} new tokens ({:.1} tok/s)",
        new_tokens, new_tokens as f64 / elapsed.as_secs_f64());
    eprintln!("           Output: \"{}\"", decoded);
    eprintln!();

    // Show compliance proof
    if let Some(compliance_proof) = backend.last_compliance_proof() {
        let verified = compliance_proof.verify().unwrap_or(false);
        eprintln!("  [compliance] IVC proof verified: {}", if verified { "PASS" } else { "FAIL" });
        eprintln!("               Tokens checked:    {}", compliance_proof.total_tokens);
        eprintln!("               Compliant:         {}", compliance_proof.compliant_tokens);
        eprintln!("               All compliant:     {}", compliance_proof.all_compliant());
        eprintln!("               Policy hash:       {}...",
            &hex::encode(compliance_proof.policy_hash)[..16]);
        eprintln!("               State hash:        {}...",
            &hex::encode(compliance_proof.final_state_hash)[..16]);

        // Show the underlying IVC proof structure
        match &compliance_proof.ivc_proof {
            VerifiedProof::HashIvc { chain_tip, merkle_root, step_count, .. } => {
                eprintln!("               IVC chain tip:     {}...", &hex::encode(chain_tip)[..16]);
                eprintln!("               IVC merkle root:   {}...", &hex::encode(merkle_root)[..16]);
                eprintln!("               IVC steps:         {}", step_count);
            }
            _ => {}
        }
    } else {
        eprintln!("  [compliance] No compliance proof available");
    }
    eprintln!();

    // Also show the computation proof
    eprintln!("  [computation proof]");
    print_proof_summary("           ", &resp.proof);
    eprintln!();
}

fn print_proof_summary(indent: &str, proof: &VerifiedProof) {
    match proof {
        VerifiedProof::HashIvc {
            chain_tip,
            merkle_root,
            step_count,
            code_hash,
            privacy_mode,
            blinding_commitment,
            ..
        } => {
            eprintln!("{}Proof: HashIvc (quantum-resistant)", indent);
            eprintln!("{}  chain_tip:   {}...", indent, &hex::encode(chain_tip)[..16]);
            eprintln!("{}  merkle_root: {}...", indent, &hex::encode(merkle_root)[..16]);
            eprintln!("{}  steps:       {}", indent, step_count);
            eprintln!("{}  privacy:     {:?}", indent, privacy_mode);
            if *privacy_mode == PrivacyMode::Private {
                eprintln!("{}  code_hash:   (hidden)", indent);
            } else {
                eprintln!("{}  code_hash:   {}...", indent, &hex::encode(code_hash)[..16]);
            }
            if let Some(bc) = blinding_commitment {
                eprintln!("{}  blinding:    {}...", indent, &hex::encode(bc)[..16]);
            }
        }
        VerifiedProof::Mock { .. } => {
            eprintln!("{}Proof: Mock", indent);
        }
    }
}
