use poly_inference::{inference, model};

use std::time::Instant;

use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::prelude::Verified;
use poly_verified::types::VerifiedProof;
fn print_proof(_label: &str, proof: &VerifiedProof) {
    match proof {
        VerifiedProof::HashIvc {
            chain_tip,
            merkle_root,
            step_count,
            code_hash,
            privacy_mode,
            blinding_commitment,
        } => {
            eprintln!("      Backend:     HashIvc (quantum-resistant)");
            eprintln!("      Chain tip:   {}", hex::encode(chain_tip));
            eprintln!("      Merkle root: {}", hex::encode(merkle_root));
            eprintln!("      Steps:       {}", step_count);
            eprintln!("      Code hash:   {}", if *code_hash == [0u8; 32] {
                "(hidden)".to_string()
            } else {
                hex::encode(code_hash)
            });
            eprintln!("      Privacy:     {:?}", privacy_mode);
            if let Some(bc) = blinding_commitment {
                eprintln!("      Blinding:    {}", hex::encode(bc));
            }
        }
        VerifiedProof::Mock { .. } => {
            eprintln!("      (mock proof)");
        }
    }

    let backend = HashIvc;
    let zero = [0u8; 32];
    let ok = backend.verify(proof, &zero, &zero).unwrap();
    eprintln!("      Verified:    {}", if ok { "PASS" } else { "FAIL" });
}

fn time_verified(
    label: &str,
    step: &str,
    input_ids: &[u32],
    max_tokens: u32,
    temperature: u32,
    seed: u64,
    f: impl FnOnce(Vec<u32>, u32, u32, u64) -> Verified<Vec<u32>>,
) -> Verified<Vec<u32>> {
    eprint!("[{}] {} inference...", step, label);
    let t = Instant::now();
    let result = f(input_ids.to_vec(), max_tokens, temperature, seed);
    let elapsed = t.elapsed();
    let new_tokens = result.value().len() - input_ids.len();
    let tok_s = new_tokens as f64 / elapsed.as_secs_f64();
    eprintln!();
    eprintln!("      {} new tokens in {:.3}s ({:.1} tok/s)",
        new_tokens, elapsed.as_secs_f64(), tok_s);
    let decoded = model::decode(result.value());
    eprintln!("      \"{}\"", decoded);
    eprintln!();
    result
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prompt = args.get(1).map(|s| s.as_str()).unwrap_or("The capital of France is");
    let max_tokens: u32 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let temperature: u32 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(700);
    let seed: u64 = args
        .get(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);

    eprintln!();
    eprintln!("=== Poly Verified Inference \u{2014} Qwen3 0.6B ===");
    eprintln!("Model:       Qwen/Qwen3-0.6B");
    eprintln!("Prompt:      \"{}\"", prompt);
    eprintln!("Max tokens:  {}", max_tokens);
    eprintln!("Temperature: {:.1}", temperature as f64 / 1000.0);
    eprintln!("Seed:        {}", seed);
    eprintln!();

    // ── [1/7] Load model ──────────────────────────────────────────────
    eprint!("[1/7] Loading model...");
    let t0 = Instant::now();
    let device = candle_core::Device::Cpu;
    model::load_model(device).expect("failed to load model");
    let load_time = t0.elapsed();
    eprintln!(" done ({:.1}s)", load_time.as_secs_f64());

    // ── [2/7] Tokenize ────────────────────────────────────────────────
    let input_ids = model::tokenize(prompt).expect("tokenization failed");
    eprintln!("[2/7] Tokenized: {} tokens", input_ids.len());
    eprintln!();

    // ── [3/7] Unverified inference ────────────────────────────────────
    eprint!("[3/7] Unverified inference...");
    let t1 = Instant::now();
    let unverified_output = inference::generate(
        input_ids.clone(), max_tokens, temperature, seed,
    );
    let unverified_time = t1.elapsed();
    let new_tokens_uv = unverified_output.len() - input_ids.len();
    let tok_s_uv = new_tokens_uv as f64 / unverified_time.as_secs_f64();
    eprintln!();
    eprintln!("      {} new tokens in {:.3}s ({:.1} tok/s)",
        new_tokens_uv, unverified_time.as_secs_f64(), tok_s_uv);
    let decoded_uv = model::decode(&unverified_output);
    eprintln!("      \"{}\"", decoded_uv);
    eprintln!();

    // ── [4/7] Verified — Transparent ──────────────────────────────────
    let transparent = time_verified(
        "Transparent", "4/7", &input_ids, max_tokens, temperature, seed,
        inference::generate_verified,
    );

    // ── [5/7] Verified — Private (full ZK) ────────────────────────────
    let private = time_verified(
        "Private (ZK)", "5/7", &input_ids, max_tokens, temperature, seed,
        inference::generate_private,
    );

    // ── [6/7] Verified — PrivateInputs (selective disclosure) ─────────
    let private_inputs = time_verified(
        "PrivateInputs", "6/7", &input_ids, max_tokens, temperature, seed,
        inference::generate_private_inputs,
    );

    // ── [7/7] Proofs ──────────────────────────────────────────────────
    eprintln!("[7/7] Proofs:");
    eprintln!();

    eprintln!("  --- Transparent ---");
    print_proof("Transparent", transparent.proof());
    eprintln!();

    eprintln!("  --- Private (full ZK) ---");
    print_proof("Private", private.proof());
    eprintln!();

    eprintln!("  --- PrivateInputs (selective disclosure) ---");
    print_proof("PrivateInputs", private_inputs.proof());
    eprintln!();

    // ── Summary ───────────────────────────────────────────────────────
    let all_match = unverified_output == *transparent.value()
        && unverified_output == *private.value()
        && unverified_output == *private_inputs.value();

    eprintln!("Determinism: {} (all 4 runs produce identical tokens)",
        if all_match { "MATCH" } else { "MISMATCH" });
    eprintln!();

    // Show that private mode hides the code hash
    let transparent_code = transparent.proof().code_hash();
    let private_code = private.proof().code_hash();
    let pi_code = private_inputs.proof().code_hash();
    eprintln!("Privacy comparison:");
    eprintln!("  Transparent    code_hash: {}", hex::encode(transparent_code));
    eprintln!("  Private (ZK)   code_hash: {} (hidden!)", hex::encode(private_code));
    eprintln!("  PrivateInputs  code_hash: {}", hex::encode(pi_code));
    eprintln!();

    // Show that blinding commitments differ (different privacy domains)
    let get_blinding = |p: &VerifiedProof| -> Option<String> {
        match p {
            VerifiedProof::HashIvc { blinding_commitment, .. } =>
                blinding_commitment.map(|b| hex::encode(b)),
            _ => None,
        }
    };
    eprintln!("Blinding commitments:");
    eprintln!("  Transparent:   {}", get_blinding(transparent.proof()).unwrap_or("(none)".into()));
    eprintln!("  Private (ZK):  {}", get_blinding(private.proof()).unwrap_or("(none)".into()));
    eprintln!("  PrivateInputs: {}", get_blinding(private_inputs.proof()).unwrap_or("(none)".into()));
    eprintln!();

    // JSON to stdout
    let json = serde_json::json!({
        "model": "Qwen/Qwen3-0.6B",
        "prompt": prompt,
        "determinism": all_match,
        "runs": {
            "unverified": {
                "tokens": new_tokens_uv,
                "time_ms": unverified_time.as_millis(),
                "tok_s": tok_s_uv,
            },
            "transparent": proof_json(transparent.proof()),
            "private": proof_json(private.proof()),
            "private_inputs": proof_json(private_inputs.proof()),
        }
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

fn proof_json(proof: &VerifiedProof) -> serde_json::Value {
    let backend = HashIvc;
    let zero = [0u8; 32];
    let ok = backend.verify(proof, &zero, &zero).unwrap();

    match proof {
        VerifiedProof::HashIvc {
            chain_tip, merkle_root, step_count, code_hash,
            privacy_mode, blinding_commitment,
        } => {
            serde_json::json!({
                "backend": "HashIvc",
                "chain_tip": hex::encode(chain_tip),
                "merkle_root": hex::encode(merkle_root),
                "step_count": step_count,
                "code_hash": hex::encode(code_hash),
                "privacy_mode": format!("{:?}", privacy_mode),
                "blinding_commitment": blinding_commitment.map(|b| hex::encode(b)),
                "verified": ok,
            })
        }
        VerifiedProof::Mock { .. } => serde_json::json!({"mock": true}),
    }
}
