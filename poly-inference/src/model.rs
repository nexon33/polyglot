use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use candle_transformers::models::qwen3::{Config, ModelForCausalLM};
use hf_hub::api::sync::Api;
use tokenizers::Tokenizer;

pub static MODEL: OnceLock<Mutex<ModelForCausalLM>> = OnceLock::new();
pub static TOKENIZER: OnceLock<Tokenizer> = OnceLock::new();
pub static DEVICE: OnceLock<Device> = OnceLock::new();

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
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[weights_path], dtype, &device)? };
    let model = ModelForCausalLM::new(&config, vb)?;

    DEVICE
        .set(device)
        .map_err(|_| anyhow!("device already set"))?;
    MODEL
        .set(Mutex::new(model))
        .map_err(|_| anyhow!("model already loaded"))?;
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
