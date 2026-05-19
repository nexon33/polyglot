//! CLI client for encrypted inference against a Poly Inference Server.
//!
//! Sends a prompt encrypted with CKKS lattice-based encryption, receives
//! encrypted output, and decrypts locally. Plaintext tokens never appear
//! on the wire.
//!
//! Usage:
//!   poly-client-cli [OPTIONS] <PROMPT>
//!
//! Examples:
//!   poly-client-cli "The capital of France is"
//!   poly-client-cli --server http://localhost:3000 --max-tokens 20 "Hello world"
//!   poly-client-cli --mode transparent "What is AI?"
//!   poly-client-cli --mode encrypted "Patient medical record summary"

use std::io::Read;
use std::time::Instant;

use poly_client::ckks::{CkksCiphertext, CkksEncryption, CkksPublicKey};
use poly_client::encryption::EncryptionBackend;
use poly_inference::http;
use poly_inference::model;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut server = "http://127.0.0.1:3000".to_string();
    let mut max_tokens: u32 = 50;
    let mut temperature: u32 = 700;
    let mut seed: u64 = 42;
    let mut mode = "encrypted".to_string();
    let mut model_name = "0.6b".to_string();
    let mut prompt = String::new();
    // [R48] Optional pinned Ed25519 verifying key (hex) for response auth.
    let mut server_key: Option<String> = None;

    // Simple arg parsing
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--model" => {
                i += 1;
                model_name = args.get(i).cloned().unwrap_or(model_name);
            }
            "--server" | "-s" => {
                i += 1;
                server = args.get(i).cloned().unwrap_or(server);
            }
            "--server-key" => {
                i += 1;
                server_key = args.get(i).cloned();
            }
            "--max-tokens" | "-n" => {
                i += 1;
                max_tokens = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(max_tokens);
            }
            "--temperature" | "-t" => {
                i += 1;
                temperature = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(temperature);
            }
            "--seed" => {
                i += 1;
                seed = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(seed);
            }
            "--mode" | "-m" => {
                i += 1;
                mode = args.get(i).cloned().unwrap_or(mode);
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other => {
                if other.starts_with('-') {
                    eprintln!("Unknown option: {}", other);
                    print_usage();
                    std::process::exit(1);
                }
                prompt = other.to_string();
            }
        }
        i += 1;
    }

    if prompt.is_empty() {
        eprintln!("Error: no prompt provided\n");
        print_usage();
        std::process::exit(1);
    }

    match mode.as_str() {
        "encrypted" => {
            run_encrypted(&server, &prompt, max_tokens, temperature, seed, &model_name, server_key)
        }
        "transparent" | "private" | "private_inputs" => {
            run_plaintext(&server, &prompt, max_tokens, temperature, seed, &mode)
        }
        _ => {
            eprintln!("Error: invalid mode {:?}", mode);
            eprintln!("Valid modes: encrypted, transparent, private, private_inputs");
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage: poly-client-cli [OPTIONS] <PROMPT>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -s, --server <URL>       Server address (default: http://127.0.0.1:3000)");
    eprintln!("      --server-key <HEX>   Pinned Ed25519 verifying key (hex) for response");
    eprintln!("                           authentication. Use the key the server prints on");
    eprintln!("                           startup. Omitting it falls back to /pubkey (TOFU).");
    eprintln!("  -n, --max-tokens <N>     Max tokens to generate (default: 50)");
    eprintln!("  -t, --temperature <N>    Temperature x1000 (default: 700 = 0.7)");
    eprintln!("      --seed <N>           Random seed (default: 42)");
    eprintln!("  -m, --mode <MODE>        Privacy mode (default: encrypted)");
    eprintln!("  -h, --help               Show this help");
    eprintln!();
    eprintln!("Modes:");
    eprintln!("  encrypted       CKKS end-to-end encryption (tokens never in plaintext on wire)");
    eprintln!("  transparent     Plaintext prompt, verifier sees all hashes");
    eprintln!("  private         Plaintext prompt, ZK proof (verifier learns nothing)");
    eprintln!("  private_inputs  Plaintext prompt, inputs hidden in proof");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  poly-client-cli \"The capital of France is\"");
    eprintln!("  poly-client-cli -n 20 -m private \"What is deep learning?\"");
    eprintln!("  poly-client-cli -s http://gpu-server:3000 \"Explain quantum computing\"");
}

// ═══════════════════════════════════════════════════════════════════════════
// Encrypted mode: CKKS end-to-end
// ═══════════════════════════════════════════════════════════════════════════

fn run_encrypted(
    server: &str,
    prompt: &str,
    max_tokens: u32,
    temperature: u32,
    seed: u64,
    model_name: &str,
    server_key: Option<String>,
) {
    let total_start = Instant::now();

    eprintln!();
    eprintln!("=== Poly Encrypted Inference Client ===");
    eprintln!();
    eprintln!("  Server:      {}", server);
    eprintln!("  Mode:        encrypted (CKKS lattice-based)");
    eprintln!("  Prompt:      {:?}", prompt);
    eprintln!("  Max tokens:  {}", max_tokens);
    eprintln!("  Temperature: {:.1}", temperature as f64 / 1000.0);
    eprintln!("  Seed:        {}", seed);
    eprintln!();

    // [1] Load tokenizer
    eprint!("[1/7] Loading tokenizer...");
    let t = Instant::now();
    model::load_tokenizer_for(&model_name).expect("failed to load tokenizer");
    eprintln!(" done ({:.1}s)", t.elapsed().as_secs_f64());

    // [2] Tokenize prompt locally
    let token_ids = model::tokenize(prompt).expect("tokenization failed");
    eprintln!("[2/7] Tokenized: {} tokens", token_ids.len());

    // [3] Fetch server's public keys: CKKS encryption key + Ed25519 signing key.
    eprint!("[3/7] Fetching server public keys...");
    let t = Instant::now();
    use poly_client::ckks::compress;
    let mut resp = ureq::get(&format!("{}/pubkey", server))
        .call()
        .expect("GET /pubkey failed — is the server running?");
    let pubkey_body = resp
        .body_mut()
        .read_to_string()
        .expect("read /pubkey response");
    let pubkey_json: serde_json::Value =
        serde_json::from_str(&pubkey_body).expect("parse /pubkey JSON");
    let ckks_hex = pubkey_json["public_key"]
        .as_str()
        .expect("/pubkey response missing `public_key`");
    let server_pk: CkksPublicKey = serde_json::from_slice(
        &hex::decode(ckks_hex).expect("decode CKKS public key hex"),
    )
    .expect("parse CKKS public key");
    let served_signing_key = pubkey_json["signing_key"].as_str().map(|s| s.to_string());
    eprintln!(" done ({:.0}ms)", t.elapsed().as_millis());

    // [R48] Resolve the Ed25519 verifying key that authenticates the response.
    // A pinned --server-key is MITM-proof; falling back to the key /pubkey just
    // served is trust-on-first-use over the same channel — it catches a later
    // or passive attacker, but not a MITM present from the start (which would
    // substitute both the signing key and the signed response).
    let server_verifying_key: [u8; 32] = {
        let key_hex = match &server_key {
            Some(pinned) => pinned.clone(),
            None => {
                eprintln!("  WARNING: no --server-key pinned — trusting the signing key");
                eprintln!("           served by /pubkey (trust-on-first-use only).");
                served_signing_key
                    .clone()
                    .expect("/pubkey response did not include a `signing_key`")
            }
        };
        let bytes = hex::decode(key_hex.trim()).expect("decode server signing key hex");
        bytes
            .as_slice()
            .try_into()
            .expect("server signing key must be exactly 32 bytes")
    };

    // [4] Generate client key pair + encrypt prompt
    eprint!("[4/7] Encrypting prompt with CKKS...");
    let t = Instant::now();
    let ckks = CkksEncryption;
    let (client_pk, client_sk) = ckks.keygen();
    let client_pk_compressed = compress::compress(&client_pk).expect("compress client pk");
    let input_ct = ckks.encrypt(&token_ids, &server_pk, &client_sk);
    let input_ct_compressed = compress::compress(&input_ct).expect("compress input ct");
    eprintln!(" done ({:.0}ms, {} KB ciphertext)", t.elapsed().as_millis(), input_ct_compressed.len() / 1024);

    // [5] Send encrypted request (PFHE-compressed binary, no JSON)
    eprint!("[5/7] Sending encrypted request...");
    let t = Instant::now();
    let req = crate::http::EncryptedGenerateRequest {
        encrypted_input: input_ct_compressed,
        client_public_key: client_pk_compressed,
        max_tokens,
        temperature,
        seed,
    };
    let req_body = compress::compress(&req).expect("compress request");

    let mut resp = ureq::post(&format!("{}/generate/encrypted", server))
        .content_type("application/x-pfhe")
        .send(&req_body)
        .expect("POST /generate/encrypted failed");

    let mut resp_bytes = Vec::new();
    resp.body_mut().as_reader().read_to_end(&mut resp_bytes).unwrap();
    let inference_time = t.elapsed();
    eprintln!(" done ({:.3}s, {} KB response)", inference_time.as_secs_f64(), resp_bytes.len() / 1024);

    let resp_data: crate::http::EncryptedGenerateResponse =
        compress::decompress(&resp_bytes).expect("decompress response");

    // [R48] Authenticate the response with the server's Ed25519 signature
    // before trusting any of its contents (ciphertext, proof, compliance).
    match http::verify_encrypted_response_signature(&resp_data, &server_verifying_key) {
        Ok(()) => eprintln!("  Response signature: OK"),
        Err(reason) => {
            eprintln!();
            eprintln!("  ERROR: {reason}.");
            eprintln!("         The encrypted response is not authentic — discarding.");
            std::process::exit(1);
        }
    }

    // [6] Decrypt response
    eprint!("[6/7] Decrypting response...");
    let t = Instant::now();
    let output_ct: CkksCiphertext = compress::decompress(&resp_data.encrypted_output)
        .expect("decompress output ciphertext");
    let output_tokens = ckks.decrypt(&output_ct, &client_sk);

    // [R46] Bind the decrypted output to the server's execution proof before
    // trusting it. Without this the CLI would print the server's self-reported
    // `proof.verified` flag next to output it never checked the proof was
    // actually built for — a tampered or mismatched `encrypted_output` would
    // be displayed as a verified result.
    if let Err(reason) =
        http::verify_proof_io_binding(&token_ids, &output_tokens, &resp_data.proof)
    {
        eprintln!();
        eprintln!("  ERROR: {reason}.");
        eprintln!("         The encrypted response is not consistent with its");
        eprintln!("         execution proof — it may be corrupt or tampered with.");
        eprintln!("         Refusing to display an unverified result.");
        std::process::exit(1);
    }

    let text = model::decode(&output_tokens);
    let completion = model::decode(&output_tokens[token_ids.len()..]);
    eprintln!(" done ({:.0}ms)", t.elapsed().as_millis());

    let generated = resp_data.generated_tokens;
    let tok_s = generated as f64 / inference_time.as_secs_f64();

    // [7] Display results
    eprintln!("[7/7] Results:");
    eprintln!();
    eprintln!("  Output:      \"{}\"", text);
    eprintln!("  Completion:  \"{}\"", completion);
    eprintln!("  Tokens:      {} prompt + {} generated = {} total",
        token_ids.len(), generated, output_tokens.len());
    eprintln!("  Speed:       {:.1} tok/s", tok_s);
    eprintln!();

    // Proof info
    let proof = &resp_data.proof;
    eprintln!("  Proof:");
    eprintln!("    Privacy:   {} (ZK)", proof.privacy_mode);
    eprintln!("    Verified:  {}", proof.verified);
    if let Some(ref bc) = proof.blinding_commitment {
        if bc.len() > 20 {
            eprintln!("    Blinding:  {}...{}", &bc[..12], &bc[bc.len()-8..]);
        }
    }
    eprintln!("    Code hash: {}", proof.code_hash);
    eprintln!();

    // Compliance info
    let comp = &resp_data.compliance;
    eprintln!("  Compliance:");
    eprintln!("    Verified:  {}", comp.verified);
    eprintln!("    Compliant: {}/{}", comp.compliant_tokens, comp.total_tokens);
    eprintln!("    Policy:    v{}", comp.policy_version);
    eprintln!();

    // Encryption stats
    let ct_stats = compress::compression_stats(&input_ct);
    eprintln!("  Encryption:");
    eprintln!("    Scheme:    CKKS (Ring-LWE, N=4096, ~128-bit security)");
    eprintln!("    Input:     {}", ct_stats);
    eprintln!("    Output:    {} KB compressed", resp_data.encrypted_output.len() / 1024);
    eprintln!("    Wire:      Plaintext tokens NEVER appeared in request or response");
    eprintln!();

    let total = total_start.elapsed();
    eprintln!("  Total time:  {:.3}s", total.as_secs_f64());
    eprintln!();

    // Also print completion to stdout (for piping)
    println!("{}", completion);
}

// ═══════════════════════════════════════════════════════════════════════════
// Plaintext modes: transparent / private / private_inputs
// ═══════════════════════════════════════════════════════════════════════════

fn run_plaintext(server: &str, prompt: &str, max_tokens: u32, temperature: u32, seed: u64, mode: &str) {
    let total_start = Instant::now();

    eprintln!();
    eprintln!("=== Poly Inference Client ===");
    eprintln!();
    eprintln!("  Server:      {}", server);
    eprintln!("  Mode:        {}", mode);
    eprintln!("  Prompt:      {:?}", prompt);
    eprintln!("  Max tokens:  {}", max_tokens);
    eprintln!();

    eprint!("Generating...");
    let t = Instant::now();

    let req_body = serde_json::json!({
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "seed": seed,
        "mode": mode,
    });

    let mut resp = ureq::post(&format!("{}/generate", server))
        .content_type("application/json")
        .send(&serde_json::to_string(&req_body).unwrap())
        .expect("POST /generate failed — is the server running?");

    let resp_body = resp.body_mut().read_to_string().unwrap();
    let inference_time = t.elapsed();
    eprintln!(" done ({:.3}s)", inference_time.as_secs_f64());

    let resp_json: serde_json::Value = serde_json::from_str(&resp_body).unwrap();

    let text = resp_json["text"].as_str().unwrap_or("");
    let completion = resp_json["completion"].as_str().unwrap_or("");
    let generated = resp_json["generated_tokens"].as_u64().unwrap_or(0);
    let tok_s = generated as f64 / inference_time.as_secs_f64();

    eprintln!();
    eprintln!("  Output:      \"{}\"", text);
    eprintln!("  Completion:  \"{}\"", completion);
    eprintln!("  Tokens:      {} generated ({:.1} tok/s)", generated, tok_s);
    eprintln!();

    // Proof
    let proof = &resp_json["proof"];
    eprintln!("  Proof:");
    eprintln!("    Privacy:   {}", proof["privacy_mode"].as_str().unwrap_or("?"));
    eprintln!("    Verified:  {}", proof["verified"]);
    eprintln!();

    // Compliance
    let comp = &resp_json["compliance"];
    eprintln!("  Compliance:");
    eprintln!("    Verified:  {}", comp["verified"]);
    eprintln!("    Compliant: {}/{}", comp["compliant_tokens"], comp["total_tokens"]);
    eprintln!();

    let total = total_start.elapsed();
    eprintln!("  Total time:  {:.3}s", total.as_secs_f64());
    eprintln!();

    // Completion to stdout for piping
    println!("{}", completion);
}
