//! # Poly Inference — Verified AI Inference Server
//!
//! Server-side infrastructure for the Poly Network verified inference protocol.
//! Connects the thin client SDK (`poly-client`) to actual model inference.
//!
//! ## Components
//!
//! - **`model`** — Qwen3-0.6B model loading, tokenization, detokenization
//! - **`inference`** — Verified generation with `#[verified]` macro (transparent, private, private_inputs)
//! - **`server`** — `InferenceBackend` trait + `MockInferenceBackend` + `RealInferenceBackend`
//! - **`http`** — HTTP transport via `tiny_http`

pub mod inference;
pub mod model;
pub mod server;
pub mod http;
