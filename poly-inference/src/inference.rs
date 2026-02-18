use candle_core::{DType, Tensor};
use candle_transformers::generation::LogitsProcessor;
use polyglot_macros::verified;

use crate::compliance::{ContentPolicy, PolicyChecker, TokenVerdict};
use crate::compliance_proof::{ComplianceAccumulator, ComplianceProof};
use crate::model::{DEVICE, MODEL};

fn is_eos(token_id: u32) -> bool {
    crate::model::EOS_TOKENS
        .get()
        .expect("EOS_TOKENS not initialized — call load_model first")
        .contains(&token_id)
}

/// Extract last-position logits as a 1D [vocab_size] tensor.
///
/// Handles different output shapes from full-precision vs quantized models:
/// - [batch, seq_len, vocab_size] → narrow last position → squeeze → [vocab_size]
/// - [batch, vocab_size] → squeeze batch → [vocab_size]
/// - [vocab_size] → as-is
fn last_position_logits(logits: &Tensor) -> Tensor {
    match logits.rank() {
        3 => {
            // [batch, seq_len, vocab_size] — full-precision model
            let seq_len = logits.dim(1).unwrap();
            logits
                .narrow(1, seq_len - 1, 1).unwrap()
                .squeeze(1).unwrap()
                .squeeze(0).unwrap()
                .to_dtype(DType::F32).unwrap()
        }
        2 => {
            // [batch, vocab_size] or [seq_len, vocab_size]
            // Take the last row (last position / last batch element)
            let n = logits.dim(0).unwrap();
            logits
                .narrow(0, n - 1, 1).unwrap()
                .squeeze(0).unwrap()
                .to_dtype(DType::F32).unwrap()
        }
        1 => {
            // Already [vocab_size]
            logits.to_dtype(DType::F32).unwrap()
        }
        r => panic!("unexpected logits rank: {r}"),
    }
}

/// Core generation logic. Extracted as a macro to avoid duplicating
/// the body between generate() and generate_verified().
macro_rules! generate_body {
    ($input_ids:expr, $max_tokens:expr, $temperature:expr, $seed:expr) => {{
        let model_guard = MODEL.get().expect("model not loaded");
        let mut model = model_guard.lock().unwrap();
        model.clear_kv_cache();

        let device = DEVICE.get().expect("device not set");
        let temp_f64 = $temperature as f64 / 1000.0;
        let mut logits_processor = LogitsProcessor::new(
            $seed,
            Some(temp_f64),
            None, // no top_p
        );

        let mut generated: Vec<u32> = $input_ids.clone();
        let prompt_len = $input_ids.len();

        // Prefill: process entire prompt at once
        let input_tensor = Tensor::new($input_ids.as_slice(), device)
            .unwrap()
            .unsqueeze(0)
            .unwrap();
        let logits = model.forward(&input_tensor, 0).unwrap();
        let logits = last_position_logits(&logits);

        let mut next_token = logits_processor.sample(&logits).unwrap();
        if is_eos(next_token) {
            return generated;
        }
        generated.push(next_token);

        // Autoregressive decode
        for i in 1..$max_tokens {
            let pos = prompt_len + i as usize;
            let input = Tensor::new(&[next_token], device)
                .unwrap()
                .unsqueeze(0)
                .unwrap();
            let logits = model.forward(&input, pos).unwrap();
            let logits = last_position_logits(&logits);

            next_token = logits_processor.sample(&logits).unwrap();
            if is_eos(next_token) {
                break;
            }
            generated.push(next_token);
        }

        generated
    }};
}

/// Maximum allowed temperature value.
/// Temperature is divided by 1000.0 before use, so 2000 means T=2.0.
/// Zero is rejected (divide-by-zero risk in sampling).
pub const MAX_TEMPERATURE: u32 = 2000;

/// Validate temperature parameter. Returns an error message if invalid.
pub fn validate_temperature(temperature: u32) -> Result<(), &'static str> {
    if temperature == 0 {
        return Err("temperature must be > 0 (division by zero risk)");
    }
    if temperature > MAX_TEMPERATURE {
        return Err("temperature exceeds maximum allowed value of 2000");
    }
    Ok(())
}

/// Unverified generation — same logic, no proof overhead.
///
/// # Panics
/// Panics if temperature is 0 or exceeds `MAX_TEMPERATURE`.
pub fn generate(input_ids: Vec<u32>, max_tokens: u32, temperature: u32, seed: u64) -> Vec<u32> {
    assert!(validate_temperature(temperature).is_ok(), "invalid temperature: {}", temperature);
    generate_body!(input_ids, max_tokens, temperature, seed)
}

/// Verified generation — transparent mode (default).
/// Verifier sees input hash, output hash, code hash.
#[verified]
pub fn generate_verified(
    input_ids: Vec<u32>,
    max_tokens: u32,
    temperature: u32,
    seed: u64,
) -> Vec<u32> {
    generate_body!(input_ids, max_tokens, temperature, seed)
}

/// Verified generation — full private mode (ZK).
/// Verifier learns nothing except that the proof is valid.
/// Code hash is hidden, blinding commitment present.
#[verified(private)]
pub fn generate_private(
    input_ids: Vec<u32>,
    max_tokens: u32,
    temperature: u32,
    seed: u64,
) -> Vec<u32> {
    generate_body!(input_ids, max_tokens, temperature, seed)
}

/// Verified generation — private inputs mode (selective disclosure).
/// Verifier sees the output and code identity, but inputs are hidden.
#[verified(private_inputs)]
pub fn generate_private_inputs(
    input_ids: Vec<u32>,
    max_tokens: u32,
    temperature: u32,
    seed: u64,
) -> Vec<u32> {
    generate_body!(input_ids, max_tokens, temperature, seed)
}

// ═══════════════════════════════════════════════════════════════════════
// Compliance-aware generation
// ═══════════════════════════════════════════════════════════════════════

/// Generation with per-token compliance gate.
///
/// Every generated token is checked against the policy before being accepted.
/// Belt-and-suspenders: client proves compliance via IVC hash chain (the
/// `ComplianceAccumulator`), server independently re-checks (the
/// `PolicyChecker`). Both must pass for a token to be emitted.
///
/// Returns `(output_tokens, compliance_proof)`. If a token is blocked,
/// generation halts early and the proof covers all tokens up to (and
/// including) the blocked one.
pub fn generate_compliant(
    input_ids: Vec<u32>,
    max_tokens: u32,
    temperature: u32,
    seed: u64,
    policy: ContentPolicy,
) -> (Vec<u32>, ComplianceProof) {
    let server_checker = PolicyChecker::new(policy.clone());
    let mut compliance_acc = ComplianceAccumulator::new(PolicyChecker::new(policy));

    let model_guard = MODEL.get().expect("model not loaded");
    let mut model = model_guard.lock().unwrap();
    model.clear_kv_cache();

    let device = DEVICE.get().expect("device not set");
    let temp_f64 = temperature as f64 / 1000.0;
    let mut logits_processor = LogitsProcessor::new(seed, Some(temp_f64), None);

    let mut generated: Vec<u32> = input_ids.clone();
    let prompt_len = input_ids.len();

    // Prefill
    let input_tensor = Tensor::new(input_ids.as_slice(), device)
        .unwrap()
        .unsqueeze(0)
        .unwrap();
    let logits = model.forward(&input_tensor, 0).unwrap();
    let logits = last_position_logits(&logits);

    let mut next_token = logits_processor.sample(&logits).unwrap();
    if is_eos(next_token) {
        // Fold EOS so finalize has at least one step
        let _ = compliance_acc.check_and_fold(next_token);
        let proof = compliance_acc.finalize().expect("compliance finalize");
        return (generated, proof);
    }

    // Compliance gate — first token
    let verdict = compliance_acc
        .check_and_fold(next_token)
        .expect("compliance fold");
    if let TokenVerdict::Blocked(_) = &verdict {
        let proof = compliance_acc.finalize().expect("compliance finalize");
        return (generated, proof);
    }
    let sv = server_checker.check_token(next_token, &generated[prompt_len..]);
    if let TokenVerdict::Blocked(_) = &sv {
        let proof = compliance_acc.finalize().expect("compliance finalize");
        return (generated, proof);
    }
    generated.push(next_token);

    // Autoregressive decode with compliance
    for i in 1..max_tokens {
        let pos = prompt_len + i as usize;
        let input = Tensor::new(&[next_token], device)
            .unwrap()
            .unsqueeze(0)
            .unwrap();
        let logits = model.forward(&input, pos).unwrap();
        let logits = last_position_logits(&logits);

        next_token = logits_processor.sample(&logits).unwrap();
        if is_eos(next_token) {
            break;
        }

        // Compliance gate — per token
        let verdict = compliance_acc
            .check_and_fold(next_token)
            .expect("compliance fold");
        if let TokenVerdict::Blocked(_) = &verdict {
            break;
        }
        let sv = server_checker.check_token(next_token, &generated[prompt_len..]);
        if let TokenVerdict::Blocked(_) = &sv {
            break;
        }
        generated.push(next_token);
    }

    let proof = compliance_acc.finalize().expect("compliance finalize");
    (generated, proof)
}
