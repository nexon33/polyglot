//! LLM Inference Benchmark — Plaintext vs Encrypted (RNS-CKKS)
//!
//! Supports multiple architectures (Qwen3, LLaMA/Nanbeige) with automatic
//! pipeline selection:
//!   - Qwen3 full-precision: Direct hidden state access via BASE_MODEL
//!   - All others (quantized, LLaMA): Pseudoinverse recovery from logits
//!
//! Usage: cargo run --release -p poly-inference --bin poly-demo-rns-fhe-e2e \
//!        [--model <name>] [prompt] [max_tokens]

use std::time::Instant;

use poly_client::ckks::rns_ckks::*;
use poly_client::ckks::rns_fhe_layer::*;
use poly_inference::compliance::{default_policy, PolicyChecker, TokenVerdict};
use poly_inference::compliance_proof::ComplianceAccumulator;
use poly_inference::model::{BASE_MODEL, EOS_TOKENS, LOADED_ARCHITECTURE};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn separator() {
    eprintln!("{}", "═".repeat(72));
}

fn thin_sep() {
    eprintln!("{}", "─".repeat(72));
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

fn main() {
    // ── Argument parsing ────────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let mut model_name = String::from("0.6b");
    let mut prompt: Option<String> = None;
    let mut max_tokens: u32 = 50;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--model" && i + 1 < args.len() {
            model_name = args[i + 1].clone();
            i += 2;
        } else if prompt.is_none() {
            prompt = Some(args[i].clone());
            i += 1;
        } else {
            max_tokens = args[i].parse().unwrap_or(50);
            i += 1;
        }
    }
    let prompt = prompt.unwrap_or_else(|| "The capital of France is".to_string());

    eprintln!();
    separator();
    eprintln!("  Poly Network — LLM Inference Benchmark");
    eprintln!("  Plaintext LLM vs Encrypted (RNS-CKKS) Pipeline");
    separator();
    eprintln!();

    let total_start = Instant::now();

    // ══════════════════════════════════════════════════════════════════
    // PART A: Plaintext Inference
    // ══════════════════════════════════════════════════════════════════

    eprintln!("  PART A: Plaintext Inference");
    thin_sep();
    eprintln!();

    // [A1] Load model
    eprint!("  [A1] Loading {}...", model_name);
    let t = Instant::now();
    let device = candle_core::Device::cuda_if_available(0).unwrap_or(candle_core::Device::Cpu);
    eprintln!(" ({})", if device.is_cuda() { "CUDA" } else { "CPU" });
    poly_inference::model::load_model_by_name(&model_name, device)
        .expect("failed to load model");
    let model_load_ms = t.elapsed().as_secs_f64() * 1000.0;
    let display_name = poly_inference::model::current_model_name().to_string();
    eprintln!("       {} loaded ({:.1}s)", display_name, model_load_ms / 1000.0);

    let eos_tokens = EOS_TOKENS.get()
        .map(|v| v.as_slice())
        .unwrap_or(&[151643, 151645]);
    let arch = LOADED_ARCHITECTURE.get().copied();
    let use_direct_hidden = BASE_MODEL.get().is_some();

    eprintln!("       Architecture: {:?}, FHE mode: {}",
        arch.unwrap_or(poly_inference::model::Architecture::Qwen3),
        if use_direct_hidden { "direct hidden state" } else { "pseudoinverse from logits" });
    eprintln!();

    // [A2] Tokenize
    let token_ids = poly_inference::model::tokenize(&prompt).expect("tokenization failed");
    eprintln!("  [A2] Prompt:  \"{}\"", prompt);
    eprintln!("       Tokens:  {:?} ({} tokens)", token_ids, token_ids.len());
    eprintln!();

    // [A3] Plaintext inference (full generation)
    eprint!("  [A3] Running plaintext inference ({} max tokens)...", max_tokens);
    let t = Instant::now();
    let output_tokens = poly_inference::inference::generate(
        token_ids.clone(), max_tokens, 700, 42,
    );
    let inference_time = t.elapsed();
    let new_tokens = output_tokens.len() - token_ids.len();
    let tok_per_sec = new_tokens as f64 / inference_time.as_secs_f64();
    eprintln!();
    eprintln!("       Generated: {} new tokens in {:.3}s", new_tokens, inference_time.as_secs_f64());
    eprintln!("       Speed:     {:.1} tokens/sec", tok_per_sec);
    let decoded = poly_inference::model::decode(&output_tokens);
    eprintln!("       Output:    \"{}\"", decoded);
    eprintln!();

    // [A4] Breakdown: prefill vs decode (second run, fresh KV cache)
    eprint!("  [A4] Measuring prefill vs decode separately...");
    let prefill_ms;
    let decode_ms;
    let decode_tokens;
    {
        use candle_core::{DType, Tensor};
        use candle_transformers::generation::LogitsProcessor;
        use poly_inference::model::{DEVICE, MODEL};

        let model_guard = MODEL.get().expect("model not loaded");
        let mut model = model_guard.lock().unwrap();
        model.clear_kv_cache();
        let device = DEVICE.get().expect("device not set");

        // Helper: extract last-position 1D logits regardless of output shape
        // quantized_llama returns [batch, vocab], others return [batch, seq, vocab]
        let extract_logits = |raw: Tensor| -> Tensor {
            if raw.dims().len() == 3 {
                let seq_len = raw.dim(1).unwrap();
                raw.narrow(1, seq_len - 1, 1).unwrap()
                    .squeeze(1).unwrap().squeeze(0).unwrap()
                    .to_dtype(DType::F32).unwrap()
            } else {
                raw.squeeze(0).unwrap()
                    .to_dtype(DType::F32).unwrap()
            }
        };

        // Prefill
        let t = Instant::now();
        let input_tensor = Tensor::new(token_ids.as_slice(), device)
            .unwrap().unsqueeze(0).unwrap();
        let raw = model.forward(&input_tensor, 0).unwrap();
        prefill_ms = t.elapsed().as_secs_f64() * 1000.0;

        let logits = extract_logits(raw);
        let mut lp = LogitsProcessor::new(42, Some(0.7), None);
        let mut next_token = lp.sample(&logits).unwrap();

        // Decode
        let t = Instant::now();
        let mut count = 1u32;
        for i in 1..max_tokens {
            let pos = token_ids.len() + i as usize;
            let inp = Tensor::new(&[next_token], device)
                .unwrap().unsqueeze(0).unwrap();
            let raw = model.forward(&inp, pos).unwrap();
            let logits = extract_logits(raw);
            next_token = lp.sample(&logits).unwrap();
            count += 1;
            if eos_tokens.contains(&next_token) { break; }
        }
        decode_ms = t.elapsed().as_secs_f64() * 1000.0;
        decode_tokens = count;
    }
    eprintln!();
    eprintln!("       Prefill:   {:.1}ms ({} prompt tokens)", prefill_ms, token_ids.len());
    eprintln!("       Decode:    {:.1}ms ({} tokens, {:.1} tok/s)",
        decode_ms, decode_tokens, decode_tokens as f64 / (decode_ms / 1000.0));
    eprintln!("       Per-token: {:.1}ms/token (decode)", decode_ms / decode_tokens as f64);
    eprintln!();

    // ══════════════════════════════════════════════════════════════════
    // PART B: Encrypted Multi-Token Generation (RNS-CKKS)
    // ══════════════════════════════════════════════════════════════════

    separator();
    eprintln!("  PART B: Encrypted Multi-Token Generation (RNS-CKKS)");
    thin_sep();
    eprintln!();

    let mut rng = StdRng::seed_from_u64(42);
    let d: usize = std::env::var("PCA_DIM").ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);
    let num_primes = 3;
    let hidden_dim = poly_inference::model::get_hidden_dim()
        .expect("EMBED_TENSOR not loaded — cannot run FHE pipeline");

    if use_direct_hidden {
        eprintln!("  Mode: Direct hidden state (forward_base -> h -> project -> FHE)");
    } else {
        eprintln!("  Mode: CG recovery (forward -> logits -> CG solve -> h -> project -> FHE)");
    }
    eprintln!("  Per-token pipeline:");
    eprintln!("    forward -> {}h-aligned projection ({}->{}d)",
        if use_direct_hidden { "" } else { "CG recover -> " },
        hidden_dim, d);
    eprintln!("    -> RNS-CKKS encrypt -> blind FHE compute -> decrypt");
    eprintln!("    -> project back ({}d->{}d) -> lm_head -> next token", d, hidden_dim);
    eprintln!();

    // Identity network: preserves projected hidden state through FHE
    let mut id_weights = vec![0.0f64; d * d];
    for i in 0..d { id_weights[i * d + i] = 1.0; }
    let net = RnsNeuralNet {
        dim: d,
        weights: vec![id_weights],
        biases: vec![vec![0.0; d]],
        activations: vec![Activation::None],
    };

    // [B0] PCA eigenvectors + eigenvalues (one-time, reusable across all tokens)
    eprint!("  [B0] Computing PCA projection basis...");
    let t = Instant::now();
    let pca_dirs = poly_inference::model::compute_pca_projection(d + 4)
        .expect("PCA failed");
    let pca_ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!(" done ({:.1}s, top-{} eigenvectors of W^T W, hidden_dim={})",
        pca_ms / 1000.0, d + 4, hidden_dim);

    // [B1] RNS-CKKS keygen (one-time)
    eprint!("  [B1] RNS-CKKS keygen...");
    let t = Instant::now();
    let ctx = RnsCkksContext::new(num_primes);
    let keys = rns_neural_net_keygen(&net, &ctx, &mut rng);
    let keygen_ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!(" done ({:.0}ms, N=4096, {} primes)", keygen_ms, num_primes);
    eprintln!();

    // [B1.5] Compliance gate setup
    let policy = default_policy();
    let client_checker = PolicyChecker::new(policy.clone());
    let server_checker = PolicyChecker::new(policy.clone());
    let mut compliance_acc = ComplianceAccumulator::new(client_checker);
    eprintln!("  [B1.5] Compliance gate: policy v{}, {} blocked IDs, {} blocked n-grams",
        policy.version, policy.blocked_token_ids.len(), policy.blocked_ngrams.len());
    eprintln!();

    // [B2] Clear KV cache from Part A, then run initial forward pass
    if !use_direct_hidden {
        let model_guard = poly_inference::model::MODEL.get().expect("model not loaded");
        let mut model = model_guard.lock().unwrap();
        model.clear_kv_cache();
    }

    // h: full hidden state (from forward_base for Qwen3, or CG-recovered for others)
    let mut h: Vec<f64>;

    eprint!("  [B2] Forward on prompt ({} tokens)...", token_ids.len());
    let t = Instant::now();
    if use_direct_hidden {
        h = poly_inference::model::forward_base(&token_ids, 0)
            .expect("forward_base failed");
    } else {
        let logits = poly_inference::model::forward_model_logits(&token_ids, 0)
            .expect("forward_model_logits failed");
        eprint!(" CG solve...");
        h = poly_inference::model::recover_hidden_from_logits(&logits)
            .expect("CG recovery failed");
    }
    let prefill_fhe_ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!(" done ({:.0}ms)", prefill_fhe_ms);
    eprintln!();

    // [B3] Encrypted generation loop
    thin_sep();
    eprintln!("  GENERATING ({} tokens, encrypted)", max_tokens);
    thin_sep();
    eprint!("  {}", prompt);

    let mut enc_generated: Vec<u32> = Vec::new();
    let mut total_fwd_ms = prefill_fhe_ms;
    let mut total_fhe_ms = 0.0f64;
    let mut total_encrypt_ms = 0.0f64;
    let mut total_decrypt_ms = 0.0f64;
    let mut total_proj_ms = 0.0f64;
    let mut total_lmhead_ms = 0.0f64;
    let mut max_fhe_err = 0.0f64;

    let gen_start = Instant::now();

    for step in 0..max_tokens as usize {
        // (a) Build projection basis and project to d dimensions
        let t_proj = Instant::now();

        // h-aligned + PCA basis (Gram-Schmidt) — same approach for all architectures
        // since we always have a full hidden state h (direct or CG-recovered)
        let h_norm: f64 = h.iter().map(|x| x * x).sum::<f64>().sqrt();
        let e1: Vec<f64> = h.iter().map(|x| x / h_norm).collect();

        let mut proj: Vec<Vec<f64>> = Vec::with_capacity(d);
        proj.push(e1);

        for pca_dir in &pca_dirs {
            if proj.len() >= d { break; }
            let mut v = pca_dir.clone();
            for existing in &proj {
                let dot: f64 = v.iter().zip(existing.iter()).map(|(a, b)| a * b).sum();
                for (vi, ei) in v.iter_mut().zip(existing.iter()) {
                    *vi -= dot * ei;
                }
            }
            let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm > 1e-8 {
                proj.push(v.iter().map(|x| x / norm).collect());
            }
        }

        // Project hidden_dim -> d
        let input_d: Vec<f64> = proj.iter()
            .map(|row| row.iter().zip(h.iter()).map(|(w, e)| w * e).sum::<f64>())
            .collect();

        total_proj_ms += t_proj.elapsed().as_secs_f64() * 1000.0;

        // Plaintext reference (for error tracking)
        let expected = rns_plaintext_forward(&input_d, &net);

        // (b) Encrypt
        let t_enc = Instant::now();
        let x_rep = replicate_vector(&input_d, d);
        let ct = rns_encrypt_simd(&x_rep, &keys.pk_b, &keys.pk_a, &ctx, &mut rng);
        total_encrypt_ms += t_enc.elapsed().as_secs_f64() * 1000.0;

        // (c) Blind FHE compute (same computation a remote server would perform)
        let t_fhe = Instant::now();
        let ct_out = rns_forward_encrypted(
            &ct, &net, &keys.eval_key, &keys.rotation_keys, &ctx,
        );
        total_fhe_ms += t_fhe.elapsed().as_secs_f64() * 1000.0;

        // (d) Decrypt
        let t_dec = Instant::now();
        let decrypted = rns_decrypt_simd(&ct_out, &keys.secret, &ctx, d);
        total_decrypt_ms += t_dec.elapsed().as_secs_f64() * 1000.0;

        // Track FHE error
        for i in 0..d {
            max_fhe_err = max_fhe_err.max((expected[i] - decrypted[i]).abs());
        }

        // (e) Project back d -> hidden_dim and apply lm_head
        let t_lm = Instant::now();
        let h_back: Vec<f64> = (0..hidden_dim)
            .map(|j| (0..d).map(|i| proj[i][j] * decrypted[i]).sum::<f64>())
            .collect();
        let top = poly_inference::model::lm_head_top_k(&h_back, 1)
            .expect("lm_head failed");
        total_lmhead_ms += t_lm.elapsed().as_secs_f64() * 1000.0;

        let next_id = top[0].0;
        let next_text = &top[0].1;

        // ── COMPLIANCE GATE ─────────────────────────────────────────
        // CLIENT: check token + fold into IVC accumulator
        let verdict = compliance_acc.check_and_fold(next_id)
            .expect("compliance fold failed");
        if let TokenVerdict::Blocked(reason) = &verdict {
            eprintln!("\n  [COMPLIANCE] Blocked at token {step}: {reason:?}");
            break;
        }
        // SERVER: belt-and-suspenders independent check
        let server_verdict = server_checker.check_token(next_id, &enc_generated);
        if let TokenVerdict::Blocked(reason) = &server_verdict {
            eprintln!("\n  [SERVER COMPLIANCE] Blocked at token {step}: {reason:?}");
            break;
        }
        // ─────────────────────────────────────────────────────────────

        enc_generated.push(next_id);
        eprint!("{}", next_text);

        // EOS check (dynamic, model-specific)
        if eos_tokens.contains(&next_id) { break; }

        // (f) Forward pass for next hidden state
        if step < (max_tokens as usize) - 1 {
            let t_fwd = Instant::now();
            if use_direct_hidden {
                h = poly_inference::model::forward_base(
                    &[next_id], token_ids.len() + step,
                ).expect("forward_base failed");
            } else {
                let logits = poly_inference::model::forward_model_logits(
                    &[next_id], token_ids.len() + step,
                ).expect("forward_model_logits failed");
                h = poly_inference::model::recover_hidden_from_logits(&logits)
                    .expect("CG recovery failed");
            }
            total_fwd_ms += t_fwd.elapsed().as_secs_f64() * 1000.0;
        }
    }

    let gen_total_ms = gen_start.elapsed().as_secs_f64() * 1000.0;
    let n_enc = enc_generated.len();
    eprintln!();
    eprintln!();

    // Finalize compliance proof
    let compliance_proof = compliance_acc.finalize()
        .expect("compliance finalize failed");
    let compliance_verified = compliance_proof.verify().unwrap_or(false);
    eprintln!("  Compliance proof: {} tokens checked, {} compliant, policy v{}",
        compliance_proof.total_tokens, compliance_proof.compliant_tokens, policy.version);
    eprintln!("  IVC proof verified: {}", if compliance_verified { "PASS" } else { "FAIL" });
    eprintln!();

    // Full encrypted output
    let mut full_enc_ids = token_ids.clone();
    full_enc_ids.extend_from_slice(&enc_generated);
    let enc_output = poly_inference::model::decode(&full_enc_ids);

    // ══════════════════════════════════════════════════════════════════
    // OUTPUT COMPARISON
    // ══════════════════════════════════════════════════════════════════

    separator();
    eprintln!("  OUTPUT COMPARISON");
    separator();
    eprintln!();
    eprintln!("  Plaintext ({} tokens):", new_tokens);
    eprintln!("    \"{}\"", decoded);
    eprintln!();
    eprintln!("  Encrypted ({} tokens):", n_enc);
    eprintln!("    \"{}\"", enc_output);
    eprintln!();

    let a_new = &output_tokens[token_ids.len()..];
    let matching = a_new.iter().zip(enc_generated.iter())
        .take_while(|(a, b)| a == b)
        .count();
    eprintln!("  First {} tokens match (of {} plaintext, {} encrypted)",
        matching, a_new.len(), n_enc);
    eprintln!();

    // ══════════════════════════════════════════════════════════════════
    // FHE VERIFICATION
    // ══════════════════════════════════════════════════════════════════

    separator();
    eprintln!("  FHE VERIFICATION");
    separator();
    eprintln!();
    eprintln!("  Max error across {} tokens: {:.2e}", n_enc, max_fhe_err);
    let fhe_verified = max_fhe_err < 0.5;
    eprintln!("  Verified: {}", if fhe_verified { "PASS" } else { "FAIL" });
    eprintln!();

    // ══════════════════════════════════════════════════════════════════
    // TIMING SUMMARY
    // ══════════════════════════════════════════════════════════════════

    let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    separator();
    eprintln!("  TIMING SUMMARY");
    separator();
    eprintln!();

    eprintln!("  PART A — Plaintext {}:", display_name);
    eprintln!("    Model load:        {:>10.1}ms", model_load_ms);
    eprintln!("    Prefill:           {:>10.1}ms  ({} prompt tokens)", prefill_ms, token_ids.len());
    eprintln!("    Decode:            {:>10.1}ms  ({} tokens, {:.1} tok/s)",
        decode_ms, decode_tokens, decode_tokens as f64 / (decode_ms / 1000.0));
    eprintln!("    Per-token decode:  {:>10.1}ms", decode_ms / decode_tokens as f64);
    eprintln!();

    let per_token_ms = if n_enc > 0 { gen_total_ms / n_enc as f64 } else { 0.0 };

    eprintln!("  PART B — Encrypted RNS-CKKS ({} tokens, {}):", n_enc,
        if use_direct_hidden { "direct" } else { "CG recovery" });
    eprintln!("    PCA setup:         {:>10.1}ms  (one-time)", pca_ms);
    eprintln!("    Keygen:            {:>10.1}ms  (one-time)", keygen_ms);
    eprintln!("    Forward passes:    {:>10.1}ms  ({:.0}ms/tok)",
        total_fwd_ms, total_fwd_ms / n_enc.max(1) as f64);
    eprintln!("    Projection:        {:>10.1}ms  ({:.1}ms/tok)",
        total_proj_ms, total_proj_ms / n_enc.max(1) as f64);
    eprintln!("    Encrypt:           {:>10.1}ms  ({:.0}ms/tok)",
        total_encrypt_ms, total_encrypt_ms / n_enc.max(1) as f64);
    eprintln!("    FHE compute:       {:>10.1}ms  ({:.0}ms/tok, blind)",
        total_fhe_ms, total_fhe_ms / n_enc.max(1) as f64);
    eprintln!("    Decrypt:           {:>10.1}ms  ({:.0}ms/tok)",
        total_decrypt_ms, total_decrypt_ms / n_enc.max(1) as f64);
    eprintln!("    lm_head:           {:>10.1}ms  ({:.0}ms/tok)",
        total_lmhead_ms, total_lmhead_ms / n_enc.max(1) as f64);
    eprintln!("    ──────────────────────────────────");
    eprintln!("    Generation total:  {:>10.1}ms  ({:.1}s/tok)", gen_total_ms, per_token_ms / 1000.0);
    eprintln!();

    separator();
    eprintln!("  COMPARISON");
    separator();
    eprintln!();
    let plaintext_per_token = decode_ms / decode_tokens as f64;
    eprintln!("    Plaintext decode:    {:>8.1}ms/tok", plaintext_per_token);
    eprintln!("    Encrypted pipeline:  {:>8.1}ms/tok ({:.1}s)", per_token_ms, per_token_ms / 1000.0);
    eprintln!("    Overhead:            {:>8.0}x", per_token_ms / plaintext_per_token);
    eprintln!();

    separator();
    eprintln!("  RESULT");
    separator();
    eprintln!();
    eprintln!("    Model:       {}", display_name);
    eprintln!("    FHE mode:    {}", if use_direct_hidden { "direct hidden state" } else { "pseudoinverse" });
    eprintln!("    Hidden dim:  {}", hidden_dim);
    eprintln!("    Plaintext:   {} tokens at {:.1} tok/s", new_tokens, tok_per_sec);
    eprintln!("    Encrypted:   {} tokens at {:.3} tok/s ({:.1}s/tok)",
        n_enc, n_enc as f64 / (gen_total_ms / 1000.0), per_token_ms / 1000.0);
    eprintln!("    FHE verify:  {} (max error {:.2e} across {} tokens)",
        if fhe_verified { "PASS" } else { "FAIL" }, max_fhe_err, n_enc);
    eprintln!("    Compliance:  {} ({}/{} tokens, policy v{})",
        if compliance_verified && compliance_proof.all_compliant() { "PASS" } else { "BLOCKED" },
        compliance_proof.compliant_tokens, compliance_proof.total_tokens, policy.version);
    eprintln!("    Privacy:     Server NEVER sees plaintext data");
    eprintln!();
    separator();
    eprintln!();
    eprintln!("  Total wall clock: {:.1}s", total_ms / 1000.0);
    eprintln!();

    if !fhe_verified {
        std::process::exit(1);
    }
}
