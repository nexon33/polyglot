use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use candle_core::quantized::gguf_file;
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::{llama, quantized_llama, qwen3, quantized_qwen3};
use hf_hub::api::sync::Api;
use tokenizers::Tokenizer;

// ═══════════════════════════════════════════════════════════════════════════
// Model abstraction — supports both full-precision and GGUF quantized models
// ═══════════════════════════════════════════════════════════════════════════

/// Unified model type that dispatches to full-precision or quantized inference
/// across multiple architectures (Qwen3, LLaMA).
pub enum ModelKind {
    Qwen3Full(qwen3::ModelForCausalLM),
    Qwen3Quantized(quantized_qwen3::ModelWeights),
    LlamaFull {
        model: llama::Llama,
        cache: llama::Cache,
        config: llama::Config,
        dtype: DType,
        device: Device,
    },
    LlamaQuantized {
        model: quantized_llama::ModelWeights,
        gguf_bytes: Vec<u8>,
        device: Device,
    },
}

impl ModelKind {
    pub fn forward(&mut self, input: &Tensor, offset: usize) -> candle_core::Result<Tensor> {
        match self {
            ModelKind::Qwen3Full(m) => m.forward(input, offset),
            ModelKind::Qwen3Quantized(m) => m.forward(input, offset),
            ModelKind::LlamaFull { model, cache, .. } => model.forward(input, offset, cache),
            ModelKind::LlamaQuantized { model, .. } => model.forward(input, offset),
        }
    }

    pub fn clear_kv_cache(&mut self) {
        match self {
            ModelKind::Qwen3Full(m) => m.clear_kv_cache(),
            ModelKind::Qwen3Quantized(m) => m.clear_kv_cache(),
            ModelKind::LlamaFull { cache, config, dtype, device, .. } => {
                *cache = llama::Cache::new(true, *dtype, config, device)
                    .expect("failed to recreate LLaMA KV cache");
            }
            ModelKind::LlamaQuantized { model, gguf_bytes, device } => {
                // quantized_llama has no public clear_kv_cache — reload from cached GGUF bytes.
                let mut cursor = std::io::Cursor::new(&gguf_bytes[..]);
                if let Ok(content) = gguf_file::Content::read(&mut cursor) {
                    if let Ok(fresh) = quantized_llama::ModelWeights::from_gguf(content, &mut cursor, device) {
                        *model = fresh;
                    }
                }
            }
        }
    }

    pub fn is_quantized(&self) -> bool {
        matches!(self, ModelKind::Qwen3Quantized(_) | ModelKind::LlamaQuantized { .. })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Model catalog
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    Qwen3,
    Llama,
}

pub struct ModelSpec {
    pub name: &'static str,
    pub display_name: &'static str,
    pub architecture: Architecture,
    pub base_repo: &'static str,
    pub weights_repo: &'static str,
    pub weights_files: &'static [&'static str],
    pub quantized: bool,
    pub size_hint: &'static str,
    pub eos_tokens: &'static [u32],
}

pub const MODELS: &[ModelSpec] = &[
    ModelSpec {
        name: "0.6b",
        display_name: "Qwen3-0.6B (full precision)",
        architecture: Architecture::Qwen3,
        base_repo: "Qwen/Qwen3-0.6B",
        weights_repo: "Qwen/Qwen3-0.6B",
        weights_files: &["model.safetensors"],
        quantized: false,
        size_hint: "~1.2 GB",
        eos_tokens: &[151643, 151645],
    },
    ModelSpec {
        name: "8b-q4",
        display_name: "Qwen3-8B Q4_K_M (quantized)",
        architecture: Architecture::Qwen3,
        base_repo: "Qwen/Qwen3-8B",
        weights_repo: "Qwen/Qwen3-8B-GGUF",
        weights_files: &["Qwen3-8B-Q4_K_M.gguf"],
        quantized: true,
        size_hint: "~5 GB",
        eos_tokens: &[151643, 151645],
    },
    ModelSpec {
        name: "32b-q4",
        display_name: "Qwen3-32B Q4_K_M (quantized)",
        architecture: Architecture::Qwen3,
        base_repo: "Qwen/Qwen3-32B",
        weights_repo: "Qwen/Qwen3-32B-GGUF",
        weights_files: &["Qwen3-32B-Q4_K_M.gguf"],
        quantized: true,
        size_hint: "~20 GB VRAM",
        eos_tokens: &[151643, 151645],
    },
    ModelSpec {
        name: "nanbeige-3b",
        display_name: "Nanbeige4.1-3B (full precision)",
        architecture: Architecture::Llama,
        base_repo: "Nanbeige/Nanbeige4.1-3B",
        weights_repo: "Nanbeige/Nanbeige4.1-3B",
        weights_files: &[
            "model-00001-of-00002.safetensors",
            "model-00002-of-00002.safetensors",
        ],
        quantized: false,
        size_hint: "~6 GB",
        eos_tokens: &[166101, 166102, 2],
    },
    ModelSpec {
        name: "nanbeige-3b-q4",
        display_name: "Nanbeige4.1-3B Q4_K_M (quantized)",
        architecture: Architecture::Llama,
        base_repo: "Nanbeige/Nanbeige4.1-3B",
        weights_repo: "mradermacher/Nanbeige4.1-3B-GGUF",
        weights_files: &["Nanbeige4.1-3B.Q4_K_M.gguf"],
        quantized: true,
        size_hint: "~2.4 GB",
        eos_tokens: &[166101, 166102, 2],
    },
];

pub fn get_model_spec(name: &str) -> Option<&'static ModelSpec> {
    MODELS.iter().find(|m| m.name == name)
}

// ═══════════════════════════════════════════════════════════════════════════
// Global statics
// ═══════════════════════════════════════════════════════════════════════════

pub static MODEL: OnceLock<Mutex<ModelKind>> = OnceLock::new();
/// Base model (Qwen3 full-precision only) for hidden state extraction in FHE demos.
pub static BASE_MODEL: OnceLock<Mutex<qwen3::Model>> = OnceLock::new();
pub static TOKENIZER: OnceLock<Tokenizer> = OnceLock::new();
pub static DEVICE: OnceLock<Device> = OnceLock::new();
pub static WEIGHTS_PATH: OnceLock<PathBuf> = OnceLock::new();
pub static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
/// Cached lm_head weight tensor [vocab_size, hidden_dim] in F32.
/// For Qwen3 (tied embeddings): this equals embed_tokens.weight.
/// For LLaMA: this is lm_head.weight (or dequantized output.weight for GGUF).
pub static EMBED_TENSOR: OnceLock<Tensor> = OnceLock::new();
/// Which model is currently loaded.
pub static MODEL_NAME: OnceLock<String> = OnceLock::new();
/// EOS token IDs for the currently loaded model. Set during model loading.
pub static EOS_TOKENS: OnceLock<Vec<u32>> = OnceLock::new();
/// Which architecture is currently loaded.
pub static LOADED_ARCHITECTURE: OnceLock<Architecture> = OnceLock::new();
/// Cached Gram matrix G = W^T @ W [hidden_dim, hidden_dim] in F64.
/// Lazily computed on first use for conjugate gradient hidden state recovery.
pub static GRAM_MATRIX: OnceLock<Tensor> = OnceLock::new();

const DEFAULT_MODEL: &str = "0.6b";

/// Wrap a user message in ChatML template for instruct-tuned models.
///
/// Both Qwen3 and Nanbeige4.1-3B use the ChatML format with
/// `<|im_start|>`/`<|im_end|>` delimiters.
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
pub fn load_tokenizer_only() -> Result<()> {
    load_tokenizer_for(DEFAULT_MODEL)
}

/// Load the tokenizer for a specific model by name.
pub fn load_tokenizer_for(model_name: &str) -> Result<()> {
    if TOKENIZER.get().is_some() {
        return Ok(()); // already loaded
    }
    let api = Api::new()?;
    let spec = get_model_spec(model_name)
        .unwrap_or_else(|| get_model_spec(DEFAULT_MODEL).unwrap());
    let repo = api.model(spec.base_repo.to_string());
    let tokenizer_path = repo.get("tokenizer.json")?;
    let tokenizer = Tokenizer::from_file(&tokenizer_path)
        .map_err(|e| anyhow!("tokenizer load: {e}"))?;
    TOKENIZER
        .set(tokenizer)
        .map_err(|_| anyhow!("tokenizer already loaded"))?;
    EOS_TOKENS.set(spec.eos_tokens.to_vec()).ok();
    Ok(())
}

/// Load the default model (Qwen3-0.6B full precision).
pub fn load_model(device: Device) -> Result<()> {
    load_model_by_name(DEFAULT_MODEL, device)
}

/// Load a model by name from the catalog.
///
/// Supported names: "0.6b", "8b-q4", "32b-q4", "nanbeige-3b", "nanbeige-3b-q4"
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

    let model_kind = match (spec.architecture, spec.quantized) {
        (Architecture::Qwen3, false) => load_qwen3_full(spec, &api, &device)?,
        (Architecture::Qwen3, true) => load_qwen3_quantized(spec, &api, &device)?,
        (Architecture::Llama, false) => load_llama_full(spec, &api, &device)?,
        (Architecture::Llama, true) => load_llama_quantized(spec, &api, &device)?,
    };

    DEVICE.set(device).map_err(|_| anyhow!("device already set"))?;
    MODEL.set(Mutex::new(model_kind)).map_err(|_| anyhow!("model already loaded"))?;
    TOKENIZER.set(tokenizer).map_err(|_| anyhow!("tokenizer already loaded"))?;
    MODEL_NAME.set(spec.display_name.to_string()).ok();
    EOS_TOKENS.set(spec.eos_tokens.to_vec()).ok();
    LOADED_ARCHITECTURE.set(spec.architecture).ok();

    Ok(())
}

/// Return the display name of the currently loaded model.
pub fn current_model_name() -> &'static str {
    MODEL_NAME.get().map(|s| s.as_str()).unwrap_or("(not loaded)")
}

/// Load full-precision safetensors Qwen3 model.
fn load_qwen3_full(spec: &ModelSpec, api: &Api, device: &Device) -> Result<ModelKind> {
    let repo = api.model(spec.weights_repo.to_string());
    eprintln!("      Downloading weights from {}...", spec.weights_repo);
    let config_path = repo.get("config.json")?;
    let weights_paths: Vec<PathBuf> = spec.weights_files
        .iter()
        .map(|f| repo.get(f))
        .collect::<Result<Vec<_>, _>>()?;

    let config_text = std::fs::read_to_string(&config_path)?;
    let config: qwen3::Config = serde_json::from_str(&config_text)?;

    let dtype = if device.is_cuda() { DType::BF16 } else { DType::F32 };
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(&weights_paths, dtype, device)? };
    let model = qwen3::ModelForCausalLM::new(&config, vb)?;

    // Cache paths and embedding tensor for FHE demos
    CONFIG_PATH.set(config_path).ok();
    WEIGHTS_PATH.set(weights_paths[0].clone()).ok();
    for path in &weights_paths {
        let raw_tensors = candle_core::safetensors::load(path, device)?;
        if let Some(embed) = raw_tensors.get("model.embed_tokens.weight") {
            let embed_f32 = embed.to_dtype(DType::F32)?;
            EMBED_TENSOR.set(embed_f32).ok();
            break;
        }
    }

    // Load base model for hidden state extraction (FHE demos)
    let vb2 = unsafe { VarBuilder::from_mmaped_safetensors(&weights_paths, dtype, device)? };
    let base_model = qwen3::Model::new(&config, vb2)?;
    BASE_MODEL.set(Mutex::new(base_model)).ok();

    Ok(ModelKind::Qwen3Full(model))
}

/// Load GGUF quantized Qwen3 model.
fn load_qwen3_quantized(spec: &ModelSpec, api: &Api, device: &Device) -> Result<ModelKind> {
    let repo = api.model(spec.weights_repo.to_string());
    let gguf_file_name = spec.weights_files[0];
    eprintln!("      Downloading GGUF from {} / {}...", spec.weights_repo, gguf_file_name);
    let gguf_path = repo.get(gguf_file_name)?;

    eprintln!("      Loading quantized Qwen3 model...");
    let mut file = std::fs::File::open(&gguf_path)?;
    let content = gguf_file::Content::read(&mut file)
        .map_err(|e| anyhow!("GGUF read: {e}"))?;
    let model = quantized_qwen3::ModelWeights::from_gguf(content, &mut file, device)?;

    Ok(ModelKind::Qwen3Quantized(model))
}

/// Load full-precision safetensors LLaMA model (e.g., Nanbeige4.1-3B).
fn load_llama_full(spec: &ModelSpec, api: &Api, device: &Device) -> Result<ModelKind> {
    let repo = api.model(spec.weights_repo.to_string());
    eprintln!("      Downloading weights from {}...", spec.weights_repo);
    let config_path = repo.get("config.json")?;
    let weights_paths: Vec<PathBuf> = spec.weights_files
        .iter()
        .map(|f| {
            eprintln!("        {}", f);
            repo.get(f)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let config_text = std::fs::read_to_string(&config_path)?;
    let llama_config: llama::LlamaConfig = serde_json::from_str(&config_text)?;
    let config = llama_config.into_config(false);

    let dtype = if device.is_cuda() { DType::BF16 } else { DType::F32 };
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(&weights_paths, dtype, device)? };
    let model = llama::Llama::load(vb, &config)?;
    let cache = llama::Cache::new(true, dtype, &config, device)?;

    // Extract lm_head weight for FHE pipeline (PCA projection + lm_head_top_k)
    // Try lm_head.weight first (untied), fall back to model.embed_tokens.weight (tied)
    for path in &weights_paths {
        let raw_tensors = candle_core::safetensors::load(path, device)?;
        if let Some(lm_head) = raw_tensors.get("lm_head.weight") {
            let lm_head_f32 = lm_head.to_dtype(DType::F32)?;
            eprintln!("      Extracted lm_head.weight [{:?}] for FHE pipeline", lm_head_f32.dims());
            EMBED_TENSOR.set(lm_head_f32).ok();
            break;
        } else if let Some(embed) = raw_tensors.get("model.embed_tokens.weight") {
            let embed_f32 = embed.to_dtype(DType::F32)?;
            eprintln!("      Extracted embed_tokens.weight [{:?}] for FHE pipeline (tied)", embed_f32.dims());
            EMBED_TENSOR.set(embed_f32).ok();
            break;
        }
    }

    Ok(ModelKind::LlamaFull {
        model,
        cache,
        config,
        dtype,
        device: device.clone(),
    })
}

/// Load GGUF quantized LLaMA model (e.g., Nanbeige4.1-3B Q4_K_M).
fn load_llama_quantized(spec: &ModelSpec, api: &Api, device: &Device) -> Result<ModelKind> {
    let repo = api.model(spec.weights_repo.to_string());
    let gguf_file_name = spec.weights_files[0];
    eprintln!("      Downloading GGUF from {} / {}...", spec.weights_repo, gguf_file_name);
    let gguf_path = repo.get(gguf_file_name)?;

    eprintln!("      Loading quantized LLaMA model...");
    let mut file = std::fs::File::open(&gguf_path)?;
    let content = gguf_file::Content::read(&mut file)
        .map_err(|e| anyhow!("GGUF read: {e}"))?;

    // Dequantize lm_head weight for FHE pipeline before consuming `content`
    let lm_head_key = "output.weight";
    let embed_key = "token_embd.weight";
    let tensor_key = if content.tensor_infos.contains_key(lm_head_key) {
        lm_head_key
    } else if content.tensor_infos.contains_key(embed_key) {
        embed_key
    } else {
        ""
    };
    if !tensor_key.is_empty() {
        match content.tensor(&mut file, tensor_key, device) {
            Ok(qtensor) => match qtensor.dequantize(device) {
                Ok(t) => {
                    let t_f32 = t.to_dtype(DType::F32).unwrap_or(t);
                    eprintln!("      Dequantized {} [{:?}] for FHE pipeline", tensor_key, t_f32.dims());
                    EMBED_TENSOR.set(t_f32).ok();
                }
                Err(e) => eprintln!("      Warning: dequantize {} failed: {e}", tensor_key),
            },
            Err(e) => eprintln!("      Warning: GGUF tensor {} read failed: {e}", tensor_key),
        }
    }

    // Read GGUF bytes into memory for model construction and future KV cache resets
    let gguf_bytes = std::fs::read(&gguf_path)?;
    let mut cursor = std::io::Cursor::new(&gguf_bytes[..]);
    let content = gguf_file::Content::read(&mut cursor)
        .map_err(|e| anyhow!("GGUF re-read: {e}"))?;
    let model = quantized_llama::ModelWeights::from_gguf(content, &mut cursor, device)?;

    Ok(ModelKind::LlamaQuantized {
        model,
        gguf_bytes,
        device: device.clone(),
    })
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

/// Return the hidden dimension of the loaded model (from EMBED_TENSOR shape).
pub fn get_hidden_dim() -> Result<usize> {
    let embed = EMBED_TENSOR
        .get()
        .ok_or_else(|| anyhow!("embedding tensor not loaded"))?;
    Ok(embed.dim(1)?)
}

/// Compute the top-d principal directions of the lm_head weight matrix,
/// returning both eigenvectors AND eigenvalues.
///
/// Returns (eigenvectors: d×hidden_dim, eigenvalues: d) where eigenvalues[i] is the
/// eigenvalue of W^T W corresponding to eigenvectors[i].
/// Needed by the pseudoinverse method for LLaMA FHE pipeline.
pub fn compute_pca_projection_with_eigenvalues(d: usize) -> Result<(Vec<Vec<f64>>, Vec<f64>)> {
    let embed = EMBED_TENSOR
        .get()
        .ok_or_else(|| anyhow!("embedding tensor not loaded"))?;
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;

    let g = embed.t()?.matmul(embed)?;
    let hidden_dim = g.dim(0)?;

    let mut g_deflated = g.to_dtype(DType::F64)?;
    let mut eigenvectors: Vec<Vec<f64>> = Vec::with_capacity(d);
    let mut eigenvalues: Vec<f64> = Vec::with_capacity(d);

    for _k in 0..d {
        let mut v: Vec<f64> = (0..hidden_dim).map(|i| ((i * 7 + _k * 13) % 97) as f64 / 97.0 - 0.5).collect();
        let mut eigenvalue = 0.0f64;

        for _ in 0..200 {
            let v_tensor = Tensor::new(&v[..], device)?;
            let w_tensor = g_deflated.matmul(&v_tensor.unsqueeze(1)?)?.squeeze(1)?;
            let w: Vec<f64> = w_tensor.to_vec1()?;

            let norm: f64 = w.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm < 1e-12 { break; }

            eigenvalue = norm;
            v = w.iter().map(|x| x / norm).collect();
        }

        let v_tensor = Tensor::new(&v[..], device)?;
        let vvt = v_tensor.unsqueeze(1)?.matmul(&v_tensor.unsqueeze(0)?)?;
        let scaled = (vvt * eigenvalue)?;
        g_deflated = g_deflated.broadcast_sub(&scaled)?;

        eigenvectors.push(v);
        eigenvalues.push(eigenvalue);
    }

    Ok((eigenvectors, eigenvalues))
}

/// Run the main MODEL forward pass and return last-position logits as f64.
///
/// Works for any architecture (Qwen3, LLaMA, quantized or full).
/// Uses the KV cache for incremental decoding.
pub fn forward_model_logits(token_ids: &[u32], offset: usize) -> Result<Vec<f64>> {
    let model_guard = MODEL.get().ok_or_else(|| anyhow!("model not loaded"))?;
    let mut model = model_guard.lock().unwrap();
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;

    let input = Tensor::new(token_ids, device)?.unsqueeze(0)?;
    let raw = model.forward(&input, offset)?;

    // Handle both shapes: [batch, seq, vocab] and [batch, vocab] (quantized_llama)
    let last = if raw.dims().len() == 3 {
        let seq_len = raw.dim(1)?;
        raw.narrow(1, seq_len - 1, 1)?.squeeze(1)?.squeeze(0)?
    } else {
        raw.squeeze(0)?
    };
    let last = last.to_dtype(DType::F32)?;
    let values: Vec<f32> = last.to_vec1()?;
    Ok(values.iter().map(|&x| x as f64).collect())
}

/// Return the argmax token ID from a logits vector.
///
/// Used by batch mode to select the next token directly from model logits,
/// avoiding the round-trip through CG recovery + lm_head which introduces
/// numerical error.
pub fn argmax_token(logits: &[f64]) -> Result<(u32, String)> {
    let (max_idx, _) = logits.iter().enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .ok_or_else(|| anyhow!("empty logits"))?;
    let tokenizer = TOKENIZER.get().ok_or_else(|| anyhow!("tokenizer not loaded"))?;
    let text = tokenizer.decode(&[max_idx as u32], true)
        .unwrap_or_else(|_| format!("<{}>", max_idx));
    Ok((max_idx as u32, text))
}

/// Recover the PCA-projected hidden state from logits using the pseudoinverse method.
///
/// Given logits = W @ h, where W is [vocab × hidden] (lm_head weight):
///   h_pca[i] = (1/λ_i) * (W @ v_i)^T @ logits
///
/// This allows FHE pipeline on LLaMA models where we can only get logits,
/// not raw hidden states.
///
/// Arguments:
/// - `logits`: [vocab_size] logits from model forward pass
/// - `pca_dirs`: d eigenvectors of W^T W (each is [hidden_dim])
/// - `eigenvalues`: d eigenvalues corresponding to each eigenvector
pub fn logits_to_pca_hidden(
    logits: &[f64],
    pca_dirs: &[Vec<f64>],
    eigenvalues: &[f64],
) -> Result<Vec<f64>> {
    let embed = EMBED_TENSOR
        .get()
        .ok_or_else(|| anyhow!("embedding tensor not loaded"))?;
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;

    let d = pca_dirs.len();
    let mut projected = vec![0.0f64; d];

    // Compute W @ v_i for each PCA direction, then dot with logits
    for i in 0..d {
        if eigenvalues[i].abs() < 1e-12 { continue; }

        // W @ v_i: [vocab × hidden] @ [hidden] → [vocab]
        let v_tensor = Tensor::new(&pca_dirs[i][..], device)?.to_dtype(DType::F32)?;
        let wv = embed.matmul(&v_tensor.unsqueeze(1)?)?.squeeze(1)?;
        let wv_f64: Vec<f32> = wv.to_vec1()?;

        // dot(W @ v_i, logits) / λ_i
        let dot: f64 = wv_f64.iter().zip(logits.iter()).map(|(&a, &b)| a as f64 * b).sum();
        projected[i] = dot / eigenvalues[i];
    }

    Ok(projected)
}

/// Recover the full hidden state from logits using conjugate gradient.
///
/// Solves (W^T W) @ h = W^T @ logits where W is the lm_head weight [vocab, hidden].
/// This gives the exact hidden state h (assuming lm_head is full rank), enabling
/// the h-aligned+PCA projection approach on any model architecture.
///
/// The Gram matrix G = W^T @ W is cached after first computation.
pub fn recover_hidden_from_logits(logits: &[f64]) -> Result<Vec<f64>> {
    let embed = EMBED_TENSOR
        .get()
        .ok_or_else(|| anyhow!("EMBED_TENSOR not loaded"))?;
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;

    // Lazily compute and cache G = W^T @ W [hidden, hidden] in F64
    if GRAM_MATRIX.get().is_none() {
        let gt = embed.t()?.matmul(embed)?.to_dtype(DType::F64)?;
        GRAM_MATRIX.set(gt).ok();
    }
    let g = GRAM_MATRIX.get().ok_or_else(|| anyhow!("gram matrix init failed"))?;

    let hidden_dim = g.dim(0)?;

    // b = W^T @ logits [hidden]
    let logits_f32: Vec<f32> = logits.iter().map(|&x| x as f32).collect();
    let logits_tensor = Tensor::new(&logits_f32[..], device)?;
    let b_tensor = embed
        .t()?
        .matmul(&logits_tensor.unsqueeze(1)?)?
        .squeeze(1)?
        .to_dtype(DType::F64)?;
    let b: Vec<f64> = b_tensor.to_vec1()?;

    // Conjugate gradient: solve G @ h = b
    let mut x = vec![0.0f64; hidden_dim];
    let mut r = b.clone();
    let mut p = r.clone();
    let mut rsold: f64 = r.iter().map(|v| v * v).sum();

    let tol = 1e-8;
    let max_iter = 500;

    for _ in 0..max_iter {
        // ap = G @ p
        let p_tensor = Tensor::new(&p[..], device)?;
        let ap_tensor = g.matmul(&p_tensor.unsqueeze(1)?)?.squeeze(1)?;
        let ap: Vec<f64> = ap_tensor.to_vec1()?;

        let pap: f64 = p.iter().zip(ap.iter()).map(|(a, b)| a * b).sum();
        if pap.abs() < 1e-30 {
            break;
        }
        let alpha = rsold / pap;

        for j in 0..hidden_dim {
            x[j] += alpha * p[j];
            r[j] -= alpha * ap[j];
        }

        let rsnew: f64 = r.iter().map(|v| v * v).sum();
        if rsnew.sqrt() < tol {
            break;
        }

        let beta = rsnew / rsold;
        for j in 0..hidden_dim {
            p[j] = r[j] + beta * p[j];
        }
        rsold = rsnew;
    }

    Ok(x)
}

/// Get the contextualized hidden state for the last position by running
/// a full forward pass of the Qwen3 base model (28 transformer layers).
///
/// Unlike `get_token_embedding` which returns a static, context-free embedding,
/// this vector encodes the full prompt context and strongly predicts the next token.
pub fn get_last_hidden_state(token_ids: &[u32]) -> Result<Vec<f64>> {
    let device = DEVICE.get().ok_or_else(|| anyhow!("device not set"))?;
    let weights_path = WEIGHTS_PATH.get().ok_or_else(|| anyhow!("weights path not set"))?;
    let config_path = CONFIG_PATH.get().ok_or_else(|| anyhow!("config path not set"))?;

    let config: qwen3::Config = serde_json::from_str(&std::fs::read_to_string(config_path)?)?;
    let dtype = if device.is_cuda() { DType::BF16 } else { DType::F32 };
    let vb = unsafe {
        VarBuilder::from_mmaped_safetensors(&[weights_path.clone()], dtype, device)?
    };
    // Construct a fresh Qwen3 Model (KV caches start empty)
    let mut base = qwen3::Model::new(&config, vb)?;

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
