use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::qwen3::{Config, Model, ModelForCausalLM};
use hf_hub::api::sync::Api;
use tokenizers::Tokenizer;

pub static MODEL: OnceLock<Mutex<ModelForCausalLM>> = OnceLock::new();
pub static BASE_MODEL: OnceLock<Mutex<Model>> = OnceLock::new();
pub static TOKENIZER: OnceLock<Tokenizer> = OnceLock::new();
pub static DEVICE: OnceLock<Device> = OnceLock::new();
pub static WEIGHTS_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
/// Cached embed_tokens/lm_head weight tensor [vocab_size, hidden_dim] in F32.
pub static EMBED_TENSOR: OnceLock<Tensor> = OnceLock::new();

const MODEL_ID: &str = "Qwen/Qwen3-0.6B";

pub fn load_model(device: Device) -> Result<()> {
    let api = Api::new()?;
    let repo = api.model(MODEL_ID.to_string());

    eprintln!("      Downloading from {MODEL_ID}...");
    let config_path = repo.get("config.json")?;
    let tokenizer_path = repo.get("tokenizer.json")?;
    let weights_path = repo.get("model.safetensors")?;

    // Parse config
    let config_text = std::fs::read_to_string(&config_path)?;
    let config: Config = serde_json::from_str(&config_text)?;

    // Load tokenizer
    let tokenizer = Tokenizer::from_file(&tokenizer_path)
        .map_err(|e| anyhow!("tokenizer load: {e}"))?;

    // Load model weights
    let dtype = if device.is_cuda() { DType::BF16 } else { DType::F32 };
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[weights_path.clone()], dtype, &device)? };
    let model = ModelForCausalLM::new(&config, vb)?;

    // Cache paths and embedding tensor for direct access
    CONFIG_PATH.set(config_path).ok();
    WEIGHTS_PATH.set(weights_path.clone()).ok();
    let raw_tensors = candle_core::safetensors::load(&weights_path, &device)?;
    if let Some(embed) = raw_tensors.get("model.embed_tokens.weight") {
        let embed_f32 = embed.to_dtype(DType::F32)?;
        EMBED_TENSOR.set(embed_f32).ok();
    }

    // Load base model (without lm_head) for hidden state extraction with KV cache
    let vb2 = unsafe { VarBuilder::from_mmaped_safetensors(&[weights_path.clone()], dtype, &device)? };
    let base_model = Model::new(&config, vb2)?;

    DEVICE
        .set(device)
        .map_err(|_| anyhow!("device already set"))?;
    MODEL
        .set(Mutex::new(model))
        .map_err(|_| anyhow!("model already loaded"))?;
    BASE_MODEL
        .set(Mutex::new(base_model))
        .map_err(|_| anyhow!("base model already loaded"))?;
    TOKENIZER
        .set(tokenizer)
        .map_err(|_| anyhow!("tokenizer already loaded"))?;

    Ok(())
}

pub fn tokenize(text: &str) -> Result<Vec<u32>> {
    let tokenizer = TOKENIZER.get().ok_or_else(|| anyhow!("tokenizer not loaded"))?;
    let encoding = tokenizer
        .encode(text, true)
        .map_err(|e| anyhow!("encode: {e}"))?;
    Ok(encoding.get_ids().to_vec())
}

pub fn decode(tokens: &[u32]) -> String {
    let tokenizer = match TOKENIZER.get() {
        Some(t) => t,
        None => return "<tokenizer not loaded>".to_string(),
    };
    tokenizer
        .decode(tokens, true)
        .unwrap_or_else(|_| "<decode error>".to_string())
}

/// Get the 1024-dim embedding vector for a token ID from the real Qwen3 model.
pub fn get_token_embedding(token_id: u32) -> Result<Vec<f64>> {
    let embed = EMBED_TENSOR
        .get()
        .ok_or_else(|| anyhow!("embedding tensor not loaded"))?;
    let row = embed.narrow(0, token_id as usize, 1)?.squeeze(0)?;
    let row_f32: Vec<f32> = row.to_vec1()?;
    Ok(row_f32.iter().map(|&x| x as f64).collect())
}

/// Project a hidden state through the real Qwen3 lm_head to get token predictions.
///
/// Since Qwen3-0.6B uses tied embeddings, lm_head.weight == embed_tokens.weight.
/// Computes logits = embed_weight @ hidden, returns top-k (token_id, text, score).
pub fn lm_head_top_k(hidden: &[f64], k: usize) -> Result<Vec<(u32, String, f64)>> {
    let embed = EMBED_TENSOR
        .get()
        .ok_or_else(|| anyhow!("embedding tensor not loaded"))?;
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;

    // hidden: [hidden_dim] -> Tensor
    let hidden_f32: Vec<f32> = hidden.iter().map(|&x| x as f32).collect();
    let hidden_tensor = Tensor::new(&hidden_f32[..], device)?;

    // logits = embed_weight @ hidden  (matmul: [vocab, hidden] x [hidden] -> [vocab])
    let logits = embed.matmul(&hidden_tensor.unsqueeze(1)?)?.squeeze(1)?;
    let logits_f32: Vec<f32> = logits.to_vec1()?;

    // Find top-k by logit score
    let mut indexed: Vec<(usize, f32)> = logits_f32.iter().enumerate().map(|(i, &v)| (i, v)).collect();
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    indexed.truncate(k);

    let tokenizer = TOKENIZER
        .get()
        .ok_or_else(|| anyhow!("tokenizer not loaded"))?;

    let results: Vec<(u32, String, f64)> = indexed
        .iter()
        .map(|&(id, score)| {
            let text = tokenizer
                .decode(&[id as u32], true)
                .unwrap_or_else(|_| format!("<{}>", id));
            (id as u32, text, score as f64)
        })
        .collect();

    Ok(results)
}

/// Run the base Qwen3 model (28 transformer layers) and return the last-position
/// hidden state. Uses the cached BASE_MODEL with KV cache for incremental generation.
///
/// - First call: pass full prompt token_ids with offset=0
/// - Subsequent calls: pass single-token &[token_id] with offset=current_pos
pub fn forward_base(token_ids: &[u32], offset: usize) -> Result<Vec<f64>> {
    let base = BASE_MODEL.get().ok_or_else(|| anyhow!("base model not loaded"))?;
    let mut base = base.lock().unwrap();
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;

    let input = Tensor::new(token_ids, device)?.unsqueeze(0)?;
    let hidden = base.forward(&input, offset)?;

    let seq_len = hidden.dim(1)?;
    let last = hidden
        .narrow(1, seq_len - 1, 1)?
        .squeeze(1)?
        .squeeze(0)?
        .to_dtype(DType::F32)?;
    let values: Vec<f32> = last.to_vec1()?;
    Ok(values.iter().map(|&x| x as f64).collect())
}

/// Compute the top-d principal directions of the lm_head weight matrix.
///
/// Returns a d×hidden_dim matrix where each row is an eigenvector of
/// embed_weight^T @ embed_weight, sorted by eigenvalue (most important first).
/// These are the directions in hidden-state space that maximally differentiate
/// token logits — far more information-preserving than random projection.
pub fn compute_pca_projection(d: usize) -> Result<Vec<Vec<f64>>> {
    let embed = EMBED_TENSOR
        .get()
        .ok_or_else(|| anyhow!("embedding tensor not loaded"))?;
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;

    // G = embed_weight^T @ embed_weight  → [hidden, hidden] = [1024, 1024]
    let g = embed.t()?.matmul(embed)?;
    let hidden_dim = g.dim(0)?;

    // Power iteration with deflation to find top-d eigenvectors
    let mut g_deflated = g.to_dtype(DType::F64)?;
    let mut eigenvectors: Vec<Vec<f64>> = Vec::with_capacity(d);

    for _k in 0..d {
        // Random initial vector
        let mut v: Vec<f64> = (0..hidden_dim).map(|i| ((i * 7 + _k * 13) % 97) as f64 / 97.0 - 0.5).collect();
        let mut eigenvalue = 0.0f64;

        // Power iteration: 200 iterations for convergence
        for _ in 0..200 {
            // w = G @ v
            let v_tensor = Tensor::new(&v[..], device)?;
            let w_tensor = g_deflated.matmul(&v_tensor.unsqueeze(1)?)?.squeeze(1)?;
            let w: Vec<f64> = w_tensor.to_vec1()?;

            // Compute norm
            let norm: f64 = w.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm < 1e-12 { break; }

            eigenvalue = norm;
            v = w.iter().map(|x| x / norm).collect();
        }

        // Deflate: G = G - λ * v @ v^T
        let v_tensor = Tensor::new(&v[..], device)?;
        let vvt = v_tensor.unsqueeze(1)?.matmul(&v_tensor.unsqueeze(0)?)?;
        let scaled = (vvt * eigenvalue)?;
        g_deflated = g_deflated.broadcast_sub(&scaled)?;

        eigenvectors.push(v);
    }

    Ok(eigenvectors)
}

/// Get the 1024-dim contextualized hidden state for the last position by running
/// a full forward pass of the Qwen3 base model (28 transformer layers).
///
/// Unlike `get_token_embedding` which returns a static, context-free embedding,
/// this vector encodes the full prompt context and strongly predicts the next token.
pub fn get_last_hidden_state(token_ids: &[u32]) -> Result<Vec<f64>> {
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;
    let weights_path = WEIGHTS_PATH.get().ok_or_else(|| anyhow!("weights path not set"))?;
    let config_path = CONFIG_PATH.get().ok_or_else(|| anyhow!("config path not set"))?;

    let config: Config = serde_json::from_str(&std::fs::read_to_string(config_path)?)?;
    let dtype = if device.is_cuda() { DType::BF16 } else { DType::F32 };
    let vb = unsafe {
        VarBuilder::from_mmaped_safetensors(&[weights_path.clone()], dtype, device)?
    };
    // Construct a fresh Model (KV caches start empty — clear_kv_cache is private)
    // Note: Model::new() already prepends "model." to tensor names internally
    let mut base = Model::new(&config, vb)?;

    let input = Tensor::new(token_ids, device)?.unsqueeze(0)?;
    let hidden = base.forward(&input, 0)?; // [1, seq_len, 1024]

    let seq_len = hidden.dim(1)?;
    let last = hidden
        .narrow(1, seq_len - 1, 1)?
        .squeeze(1)?
        .squeeze(0)?
        .to_dtype(DType::F32)?;
    let values: Vec<f32> = last.to_vec1()?;
    Ok(values.iter().map(|&x| x as f64).collect())
}
