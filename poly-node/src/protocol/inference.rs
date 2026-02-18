//! Inference request/response protocol over QUIC.
//!
//! Wraps `poly_client::protocol::{InferRequest, InferResponse}` with
//! bincode serialization for QUIC transport. The same types used by
//! the HTTP server are reused here — just a different transport.
//!
//! All deserialization uses size-limited bincode to prevent
//! decompression bombs from crafted payloads.

use anyhow::Result;
use bincode::Options;
use poly_client::protocol::{InferRequest, InferResponse};
use poly_inference::server::InferenceBackend;

/// Maximum size for a serialized inference request (4 MB).
///
/// An InferRequest contains encrypted_input (PFHE ciphertext) which
/// can be large, but shouldn't exceed a few MB for reasonable inputs.
const MAX_INFER_REQUEST_SIZE: u64 = 4 * 1024 * 1024;

/// Maximum size for a serialized inference response (16 MB).
///
/// Responses contain encrypted output + proof, which can be larger
/// than requests due to proof data.
const MAX_INFER_RESPONSE_SIZE: u64 = 16 * 1024 * 1024;

fn bincode_options(limit: u64) -> impl Options {
    // R6: Removed allow_trailing_bytes() for strict deserialization.
    // Trailing bytes after a valid message are now rejected, preventing
    // injection of extra data after a valid payload.
    bincode::DefaultOptions::new()
        .with_limit(limit)
        .with_fixint_encoding()
}

pub fn encode_infer_request(req: &InferRequest) -> Result<Vec<u8>> {
    let bytes = bincode::serialize(req)?;
    // R6: Validate serialized size does not exceed the wire limit.
    // A corrupted or malicious caller could produce an oversized request.
    if bytes.len() as u64 > MAX_INFER_REQUEST_SIZE {
        anyhow::bail!(
            "serialized InferRequest too large: {} bytes (max {})",
            bytes.len(),
            MAX_INFER_REQUEST_SIZE
        );
    }
    Ok(bytes)
}

pub fn decode_infer_request(data: &[u8]) -> Result<InferRequest> {
    Ok(bincode_options(MAX_INFER_REQUEST_SIZE).deserialize(data)?)
}

pub fn encode_infer_response(resp: &InferResponse) -> Result<Vec<u8>> {
    let bytes = bincode::serialize(resp)?;
    // R6: Validate serialized size does not exceed the wire limit.
    // A corrupted backend could produce an oversized response.
    if bytes.len() as u64 > MAX_INFER_RESPONSE_SIZE {
        anyhow::bail!(
            "serialized InferResponse too large: {} bytes (max {})",
            bytes.len(),
            MAX_INFER_RESPONSE_SIZE
        );
    }
    Ok(bytes)
}

pub fn decode_infer_response(data: &[u8]) -> Result<InferResponse> {
    Ok(bincode_options(MAX_INFER_RESPONSE_SIZE).deserialize(data)?)
}

/// Handle an inference request: deserialize, run backend, serialize response.
///
/// Called from `spawn_blocking` — this is the sync bridge between the
/// async QUIC stream handler and the sync `InferenceBackend::infer()`.
pub fn handle_infer(data: &[u8], backend: &dyn InferenceBackend) -> Result<Vec<u8>> {
    let request = decode_infer_request(data)?;
    let response = backend.infer(&request)?;
    encode_infer_response(&response)
}
