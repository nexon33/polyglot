//! # Poly Inference — Verified AI Inference Server
//!
//! Server-side infrastructure for the Poly Network verified inference protocol.
//! Connects the thin client SDK (`poly-client`) to actual model inference.
//!
//! ## Components
//!
//! - **`model`** — Model loading (Qwen3, LLaMA/Nanbeige), tokenization, detokenization
//! - **`inference`** — Verified generation with `#[verified]` macro (transparent, private, private_inputs)
//! - **`server`** — `InferenceBackend` trait + `MockInferenceBackend` + `RealInferenceBackend`
//! - **`http`** — HTTP transport via `tiny_http`

pub mod compliance;
pub mod compliance_proof;
pub mod inference;
pub mod model;
pub mod server;
pub mod http;
