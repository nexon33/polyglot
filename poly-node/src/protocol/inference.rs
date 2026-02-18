//! Inference request/response protocol over QUIC.
//!
//! Wraps `poly_client::protocol::{InferRequest, InferResponse}` with
//! bincode serialization for QUIC transport. The same types used by
//! the HTTP server are reused here — just a different transport.

use anyhow::Result;
use poly_client::protocol::{InferRequest, InferResponse};
use poly_inference::server::InferenceBackend;

pub fn encode_infer_request(req: &InferRequest) -> Result<Vec<u8>> {
    Ok(bincode::serialize(req)?)
}

pub fn decode_infer_request(data: &[u8]) -> Result<InferRequest> {
    Ok(bincode::deserialize(data)?)
}

pub fn encode_infer_response(resp: &InferResponse) -> Result<Vec<u8>> {
    Ok(bincode::serialize(resp)?)
}

pub fn decode_infer_response(data: &[u8]) -> Result<InferResponse> {
    Ok(bincode::deserialize(data)?)
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
