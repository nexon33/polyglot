use candle_core::{DType, Tensor};
use candle_transformers::generation::LogitsProcessor;
use polyglot_macros::verified;

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
