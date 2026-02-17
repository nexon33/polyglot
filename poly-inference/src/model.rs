use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use candle_core::quantized::gguf_file;
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::quantized_qwen3;
use candle_transformers::models::qwen3::{Config, Model, ModelForCausalLM};
use hf_hub::api::sync::Api;
use tokenizers::Tokenizer;

// ═══════════════════════════════════════════════════════════════════════════
// Model abstraction — supports both full-precision and GGUF quantized models
// ═══════════════════════════════════════════════════════════════════════════

/// Unified model type that dispatches to either full-precision or quantized inference.
pub enum ModelKind {
    FullPrecision(ModelForCausalLM),
    Quantized(quantized_qwen3::ModelWeights),
}

impl ModelKind {
    pub fn forward(&mut self, input: &Tensor, offset: usize) -> candle_core::Result<Tensor> {
        match self {
            ModelKind::FullPrecision(m) => m.forward(input, offset),
            ModelKind::Quantized(m) => m.forward(input, offset),
        }
    }

    pub fn clear_kv_cache(&mut self) {
        match self {
            ModelKind::FullPrecision(m) => m.clear_kv_cache(),
            ModelKind::Quantized(m) => m.clear_kv_cache(),
        }
    }

    pub fn is_quantized(&self) -> bool {
        matches!(self, ModelKind::Quantized(_))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Model catalog
// ═══════════════════════════════════════════════════════════════════════════

pub struct ModelSpec {
    pub name: &'static str,
    pub display_name: &'static str,
    pub base_repo: &'static str,
    pub weights_repo: &'static str,
    pub weights_file: &'static str,
    pub quantized: bool,
    pub size_hint: &'static str,
}

pub const MODELS: &[ModelSpec] = &[
    ModelSpec {
        name: "0.6b",
        display_name: "Qwen3-0.6B (full precision)",
        base_repo: "Qwen/Qwen3-0.6B",
        weights_repo: "Qwen/Qwen3-0.6B",
        weights_file: "model.safetensors",
        quantized: false,
        size_hint: "~1.2 GB",
    },
    ModelSpec {
        name: "8b-q4",
        display_name: "Qwen3-8B Q4_K_M (quantized)",
        base_repo: "Qwen/Qwen3-8B",
        weights_repo: "Qwen/Qwen3-8B-GGUF",
        weights_file: "Qwen3-8B-Q4_K_M.gguf",
        quantized: true,
        size_hint: "~5 GB",
    },
    ModelSpec {
        name: "32b-q4",
        display_name: "Qwen3-32B Q4_K_M (quantized)",
        base_repo: "Qwen/Qwen3-32B",
        weights_repo: "Qwen/Qwen3-32B-GGUF",
        weights_file: "Qwen3-32B-Q4_K_M.gguf",
        quantized: true,
        size_hint: "~20 GB VRAM",
    },
];

pub fn get_model_spec(name: &str) -> Option<&'static ModelSpec> {
    MODELS.iter().find(|m| m.name == name)
}

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

pub static MODEL: OnceLock<Mutex<ModelKind>> = OnceLock::new();
/// Base model (full-precision only) for hidden state extraction in FHE demos.
pub static BASE_MODEL: OnceLock<Mutex<Model>> = OnceLock::new();
pub static TOKENIZER: OnceLock<Tokenizer> = OnceLock::new();
pub static DEVICE: OnceLock<Device> = OnceLock::new();
pub static WEIGHTS_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
/// Cached embed_tokens/lm_head weight tensor [vocab_size, hidden_dim] in F32.
/// Only populated for full-precision models.
pub static EMBED_TENSOR: OnceLock<Tensor> = OnceLock::new();
/// Which model is currently loaded.
pub static MODEL_NAME: OnceLock<String> = OnceLock::new();

const DEFAULT_MODEL: &str = "0.6b";

/// Wrap a user message in Qwen3 chat template for instruct-tuned models.
///
/// This enables the model's built-in safety training (soft refusal for
/// harmful prompts). Used as a first line of defense before the cryptographic
/// compliance proof gate.
pub fn format_chat_prompt(user_message: &str) -> String {
    format!(
        "<|im_start|>system\nYou are a helpful assistant.<|im_end|>\n\
         <|im_start|>user\n{user_message}<|im_end|>\n\
         <|im_start|>assistant\n"
    )
}

/// Load only the tokenizer (no model weights, no GPU).
///
/// Used by the CLI client which only needs to tokenize/decode — not run inference.
/// Downloads the tokenizer from HuggingFace Hub if not cached.
/// All Qwen3 models share the same tokenizer, so we always pull from the 0.6B repo.
pub fn load_tokenizer_only() -> Result<()> {
    if TOKENIZER.get().is_some() {
        return Ok(()); // already loaded
    }
    let api = Api::new()?;
    let spec = get_model_spec(DEFAULT_MODEL).unwrap();
    let repo = api.model(spec.base_repo.to_string());
    let tokenizer_path = repo.get("tokenizer.json")?;
    let tokenizer = Tokenizer::from_file(&tokenizer_path)
        .map_err(|e| anyhow!("tokenizer load: {e}"))?;
    TOKENIZER
        .set(tokenizer)
        .map_err(|_| anyhow!("tokenizer already loaded"))?;
    Ok(())
}

/// Load the default model (Qwen3-0.6B full precision).
pub fn load_model(device: Device) -> Result<()> {
    load_model_by_name(DEFAULT_MODEL, device)
}

/// Load a model by name from the catalog.
///
/// Supported names: "0.6b", "8b-q4", "32b-q4"
pub fn load_model_by_name(name: &str, device: Device) -> Result<()> {
    let spec = get_model_spec(name)
        .ok_or_else(|| anyhow!("unknown model {:?} — available: {}", name,
            MODELS.iter().map(|m| m.name).collect::<Vec<_>>().join(", ")))?;

    eprintln!("      Model: {} ({})", spec.display_name, spec.size_hint);

    let api = Api::new()?;

    // Download tokenizer from base repo
    let base_repo = api.model(spec.base_repo.to_string());
    eprintln!("      Downloading tokenizer from {}...", spec.base_repo);
    let tokenizer_path = base_repo.get("tokenizer.json")?;
    let tokenizer = Tokenizer::from_file(&tokenizer_path)
        .map_err(|e| anyhow!("tokenizer load: {e}"))?;

    let model_kind = if spec.quantized {
        load_quantized(spec, &api, &device)?
    } else {
        load_full_precision(spec, &api, &device)?
    };

    DEVICE.set(device).map_err(|_| anyhow!("device already set"))?;
    MODEL.set(Mutex::new(model_kind)).map_err(|_| anyhow!("model already loaded"))?;
    TOKENIZER.set(tokenizer).map_err(|_| anyhow!("tokenizer already loaded"))?;
    MODEL_NAME.set(spec.display_name.to_string()).ok();

    Ok(())
}

/// Return the display name of the currently loaded model.
pub fn current_model_name() -> &'static str {
    MODEL_NAME.get().map(|s| s.as_str()).unwrap_or("(not loaded)")
}

/// Load full-precision safetensors model (e.g., Qwen3-0.6B).
fn load_full_precision(spec: &ModelSpec, api: &Api, device: &Device) -> Result<ModelKind> {
    let repo = api.model(spec.weights_repo.to_string());
    eprintln!("      Downloading weights from {}...", spec.weights_repo);
    let config_path = repo.get("config.json")?;
    let weights_path = repo.get(spec.weights_file)?;

    let config_text = std::fs::read_to_string(&config_path)?;
    let config: Config = serde_json::from_str(&config_text)?;

    let dtype = if device.is_cuda() { DType::BF16 } else { DType::F32 };
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[weights_path.clone()], dtype, device)? };
    let model = ModelForCausalLM::new(&config, vb)?;

    // Cache paths and embedding tensor for FHE demos
    CONFIG_PATH.set(config_path).ok();
    WEIGHTS_PATH.set(weights_path.clone()).ok();
    let raw_tensors = candle_core::safetensors::load(&weights_path, device)?;
    if let Some(embed) = raw_tensors.get("model.embed_tokens.weight") {
        let embed_f32 = embed.to_dtype(DType::F32)?;
        EMBED_TENSOR.set(embed_f32).ok();
    }

    // Load base model for hidden state extraction (FHE demos)
    let vb2 = unsafe { VarBuilder::from_mmaped_safetensors(&[weights_path.clone()], dtype, device)? };
    let base_model = Model::new(&config, vb2)?;
    BASE_MODEL.set(Mutex::new(base_model)).ok();

    Ok(ModelKind::FullPrecision(model))
}

/// Load GGUF quantized model (e.g., Qwen3-32B Q4_K_M).
fn load_quantized(spec: &ModelSpec, api: &Api, device: &Device) -> Result<ModelKind> {
    let repo = api.model(spec.weights_repo.to_string());
    eprintln!("      Downloading GGUF from {} / {}...", spec.weights_repo, spec.weights_file);
    let gguf_path = repo.get(spec.weights_file)?;

    eprintln!("      Loading quantized model...");
    let mut file = std::fs::File::open(&gguf_path)?;
    let content = gguf_file::Content::read(&mut file)
        .map_err(|e| anyhow!("GGUF read: {e}"))?;
    let model = quantized_qwen3::ModelWeights::from_gguf(content, &mut file, device)?;

    Ok(ModelKind::Quantized(model))
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
