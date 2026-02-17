use candle_core::{DType, Tensor};
use candle_transformers::generation::LogitsProcessor;
use polyglot_macros::verified;

use crate::compliance::{ContentPolicy, PolicyChecker, TokenVerdict};
use crate::compliance_proof::{ComplianceAccumulator, ComplianceProof};
use crate::model::{DEVICE, MODEL};

/// Qwen3 EOS token IDs.
const EOS_TOKENS: &[u32] = &[
    151643, // <|endoftext|>
    151645, // <|im_end|>
];

fn is_eos(token_id: u32) -> bool {
    EOS_TOKENS.contains(&token_id)
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
        // logits shape: [1, seq_len, vocab_size] — take last position
        let seq_len = logits.dim(1).unwrap();
        let logits = logits
            .narrow(1, seq_len - 1, 1)
            .unwrap()
            .squeeze(1)
            .unwrap()
            .squeeze(0)
            .unwrap()
            .to_dtype(DType::F32)
            .unwrap();

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
            let logits = logits
                .squeeze(0)
                .unwrap()
                .squeeze(0)
                .unwrap()
                .to_dtype(DType::F32)
                .unwrap();

            next_token = logits_processor.sample(&logits).unwrap();
            if is_eos(next_token) {
                break;
            }
            generated.push(next_token);
        }

        generated
    }};
}

/// Unverified generation — same logic, no proof overhead.
pub fn generate(input_ids: Vec<u32>, max_tokens: u32, temperature: u32, seed: u64) -> Vec<u32> {
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
    let seq_len = logits.dim(1).unwrap();
    let logits = logits
        .narrow(1, seq_len - 1, 1)
        .unwrap()
        .squeeze(1)
        .unwrap()
        .squeeze(0)
        .unwrap()
        .to_dtype(DType::F32)
        .unwrap();

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
        let logits = logits
            .squeeze(0)
            .unwrap()
            .squeeze(0)
            .unwrap()
            .to_dtype(DType::F32)
            .unwrap();

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
