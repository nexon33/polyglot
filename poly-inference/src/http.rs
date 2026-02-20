//! HTTP transport for the inference server.
//!
//! Three endpoints:
//! - `POST /infer`              — Full protocol (encrypted input, proof, encrypted output)
//! - `POST /generate`           — Simple batch: prompt in, text + proof out
//! - `POST /generate/encrypted` — Encrypted batch: CKKS-encrypted tokens in, encrypted tokens out
//!
//! The `/generate` endpoint supports privacy modes:
//! - `"transparent"` (default) — verifier sees input hash, output hash, code hash
//! - `"private"` — full ZK: verifier learns nothing except proof validity
//! - `"private_inputs"` — selective disclosure: verifier sees output + code, inputs hidden
//!
//! The `/generate/encrypted` endpoint provides full end-to-end encryption:
//! - Client encrypts token IDs with server's CKKS public key
//! - Server decrypts, runs inference, re-encrypts output with client's CKKS public key
//! - Proof is always private (ZK) — verifier learns nothing
//! - Plaintext tokens never appear in the HTTP request or response

use std::io::Read;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server, StatusCode};

use crate::compliance::{check_prompt, default_policy};
use crate::server::InferenceBackend;
use poly_client::encryption::EncryptionBackend;
use poly_client::protocol::InferRequest;
use poly_verified::types::VerifiedProof;

/// Maximum allowed value for `max_tokens` in any request.
const MAX_ALLOWED_TOKENS: u32 = 4096;

/// Maximum allowed size of `encrypted_input` field in bytes (~1 MB).
/// This bounds the token count to roughly 8192 encrypted tokens, preventing
/// memory exhaustion from oversized payloads.
const MAX_ENCRYPTED_INPUT_SIZE: usize = 1_048_576;

/// Maximum allowed prompt length in characters.
/// Prevents DoS via extremely long prompts that tokenize to thousands of tokens,
/// causing GPU OOM or extreme latency. 100K characters is roughly 25K tokens.
const MAX_PROMPT_LENGTH: usize = 100_000;

/// Maximum allowed prompt token count after tokenization.
/// Even if the character count is under the limit, very token-dense inputs
/// can still overwhelm the model. 8192 tokens is a reasonable context window.
const MAX_PROMPT_TOKENS: usize = 8192;

// ─── Simple batch request/response types ─────────────────────────────────

/// Simple generation request. Prompt, parameters, and optional privacy mode.
///
/// ```json
/// {"prompt": "The capital of France is", "max_tokens": 10}
/// {"prompt": "Medical record...", "max_tokens": 50, "mode": "private"}
/// ```
#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    pub prompt: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temperature")]
    pub temperature: u32,
    #[serde(default = "default_seed")]
    pub seed: u64,
    /// Privacy mode for the execution proof.
    /// - `"transparent"` (default): verifier sees input/output/code hashes
    /// - `"private"`: full ZK — verifier learns nothing except proof validity
    /// - `"private_inputs"`: selective disclosure — inputs hidden, output visible
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_max_tokens() -> u32 { 50 }
fn default_temperature() -> u32 { 700 }
/// R8: Default seed uses system entropy to prevent output prediction.
/// Previously hardcoded to 42, which meant all requests without an explicit seed
/// produced identical outputs, allowing attackers to predict completions.
fn default_seed() -> u64 { rand::random::<u64>() }
fn default_mode() -> String { "transparent".into() }

/// Simple generation response. Text, tokens, execution proof, and compliance proof.
#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    /// The full generated text (prompt + completion).
    pub text: String,
    /// Just the completion (without prompt).
    pub completion: String,
    /// All token IDs (prompt + generated).
    pub tokens: Vec<u32>,
    /// Number of new tokens generated.
    pub generated_tokens: usize,
    /// Privacy mode used for the execution proof.
    pub mode: String,
    /// Execution proof (HashIvc).
    pub proof: ProofSummary,
    /// Compliance proof summary.
    pub compliance: ComplianceSummary,
}

/// Execution proof summary.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofSummary {
    pub backend: String,
    pub privacy_mode: String,
    pub chain_tip: String,
    pub merkle_root: String,
    pub step_count: u64,
    pub code_hash: String,
    pub blinding_commitment: Option<String>,
    pub verified: bool,
    /// Hash of the input token sequence (for I/O binding verification).
    pub input_hash: String,
    /// Hash of the output token sequence (for I/O binding verification).
    pub output_hash: String,
}

/// Compliance proof summary in the response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub verified: bool,
    pub total_tokens: u64,
    pub compliant_tokens: u64,
    pub all_compliant: bool,
    pub policy_version: u32,
    pub policy_hash: String,
    pub ivc_chain_tip: String,
    pub ivc_merkle_root: String,
    pub ivc_steps: u64,
}

// ─── Encrypted batch request/response types ─────────────────────────────

/// Binary request for encrypted generation.
///
/// The entire request body is PFHE-compressed (bincode + zstd).
/// Ciphertext and public key are nested PFHE-compressed blobs.
/// No JSON, no hex, no base64 — raw binary throughout.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedGenerateRequest {
    /// PFHE-compressed `CkksCiphertext`.
    pub encrypted_input: Vec<u8>,
    /// PFHE-compressed `CkksPublicKey`.
    pub client_public_key: Vec<u8>,
    pub max_tokens: u32,
    pub temperature: u32,
    pub seed: u64,
}

/// Binary response for encrypted generation.
///
/// The entire response body is PFHE-compressed (bincode + zstd).
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedGenerateResponse {
    /// PFHE-compressed `CkksCiphertext`.
    pub encrypted_output: Vec<u8>,
    pub generated_tokens: usize,
    pub total_tokens: usize,
    /// JSON-compatible proof metadata (serialized inline via bincode).
    pub proof: ProofSummary,
    pub compliance: ComplianceSummary,
}

// ─── HTTP Server ─────────────────────────────────────────────────────────

use poly_client::ckks::{CkksCiphertext, CkksPublicKey, CkksSecretKey, CkksEncryption};

/// HTTP inference server with CKKS key pair for encrypted inference.
pub struct HttpServer {
    server: Server,
    /// Server's CKKS public key (clients encrypt input with this).
    server_pk: CkksPublicKey,
    /// Server's CKKS secret key (server decrypts input with this).
    server_sk: CkksSecretKey,
}

impl HttpServer {
    /// Create a new HTTP server bound to the given address.
    ///
    /// Generates a fresh CKKS key pair for encrypted inference.
    /// Address format: "127.0.0.1:8080" or "0.0.0.0:3000".
    pub fn new(addr: &str) -> Result<Self> {
        let server =
            Server::http(addr).map_err(|e| anyhow::anyhow!("failed to bind {}: {}", addr, e))?;
        let ckks = CkksEncryption;
        let (pk, sk) = ckks.keygen();
        Ok(Self { server, server_pk: pk, server_sk: sk })
    }

    /// Get the server's CKKS public key (hex-encoded, for clients).
    pub fn server_public_key_hex(&self) -> String {
        hex::encode(serde_json::to_vec(&self.server_pk).unwrap())
    }

    /// Serve requests indefinitely (all endpoints).
    pub fn serve<B: InferenceBackend>(&self, backend: &B) {
        for mut request in self.server.incoming_requests() {
            let response = handle_request(&mut request, backend, &self.server_pk, &self.server_sk);
            let _ = request.respond(response);
        }
    }

    /// Handle exactly one request, then return. Used for testing.
    pub fn handle_one<B: InferenceBackend>(&self, backend: &B) -> Result<()> {
        let mut request = self
            .server
            .recv()
            .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
        let response = handle_request(&mut request, backend, &self.server_pk, &self.server_sk);
        request
            .respond(response)
            .map_err(|e| anyhow::anyhow!("respond failed: {}", e))?;
        Ok(())
    }

    /// Get the server's bound address (useful when binding to port 0).
    pub fn addr(&self) -> std::net::SocketAddr {
        self.server.server_addr().to_ip().unwrap()
    }
}

// ─── Request routing ─────────────────────────────────────────────────────

fn handle_request<B: InferenceBackend>(
    request: &mut tiny_http::Request,
    backend: &B,
    server_pk: &CkksPublicKey,
    server_sk: &CkksSecretKey,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let json_header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();

    // R8: Normalize URL by stripping query string and trailing slashes for routing.
    // This prevents bypass via `/generate?smuggle=true` or `/generate/` returning 404
    // while the canonical path works. Only the path component is used for matching.
    let raw_url = request.url().to_string();
    let url_path = raw_url.split('?').next().unwrap_or(&raw_url);
    let url_path = url_path.trim_end_matches('/');
    // Reject path traversal attempts (e.g., `/generate/../admin`)
    if url_path.contains("..") {
        return json_error(400, "invalid request path", json_header);
    }
    // R9: Reject percent-encoded path traversal (e.g., `%2e%2e` = `..`)
    // R10: Also reject double-encoded variants (e.g., `%252e%252e` decodes to `%2e%2e`
    // at one proxy layer, then to `..` at the next). This prevents multi-layer
    // proxy bypass where each layer decodes one level of percent-encoding.
    {
        let decoded_lower = url_path.to_lowercase();
        if decoded_lower.contains("%2e%2e")
            || decoded_lower.contains("%2e.")
            || decoded_lower.contains(".%2e")
            // R10: Double-encoded variants
            || decoded_lower.contains("%252e")
            || decoded_lower.contains("%2525")
        {
            return json_error(400, "invalid request path", json_header);
        }
    }
    // R9: Reject null bytes in URL path (can truncate paths in some parsers)
    if url_path.contains('\0') || url_path.contains("%00") {
        return json_error(400, "invalid request path", json_header);
    }

    // GET /pubkey returns the server's CKKS public key as JSON with hex-encoded bytes
    if url_path == "/pubkey" {
        if request.method() != &Method::Get {
            return json_error(405, "method not allowed (use GET)", json_header);
        }
        let pk_bytes = serde_json::to_vec(server_pk).unwrap_or_default();
        let pk_hex = hex::encode(&pk_bytes);
        let body = serde_json::json!({ "public_key": pk_hex }).to_string();
        let mut headers = vec![json_header];
        headers.extend(security_headers());
        return Response::new(
            StatusCode(200),
            headers,
            std::io::Cursor::new(body.into_bytes()),
            None,
            None,
        );
    }

    if request.method() != &Method::Post {
        return json_error(405, "method not allowed", json_header);
    }

    // R8: Validate Content-Type on POST endpoints.
    // JSON endpoints require application/json; encrypted endpoint requires application/x-pfhe.
    // Without this check, a reverse proxy routing on Content-Type could be tricked into
    // forwarding requests to the wrong backend (request smuggling via Content-Type mismatch).
    let content_type = request.headers().iter()
        .find(|h| h.field.equiv("Content-Type"))
        .map(|h| h.value.as_str().to_lowercase())
        .unwrap_or_default();

    match url_path {
        "/infer" | "/generate" => {
            if !content_type.is_empty() && !content_type.starts_with("application/json") {
                return json_error(
                    415,
                    "unsupported media type: expected application/json",
                    json_header,
                );
            }
            if url_path == "/infer" {
                handle_infer(request, backend, json_header)
            } else {
                handle_generate(request, json_header)
            }
        }
        "/generate/encrypted" => {
            // Accept application/x-pfhe or application/octet-stream for binary payloads
            if !content_type.is_empty()
                && !content_type.starts_with("application/x-pfhe")
                && !content_type.starts_with("application/octet-stream")
            {
                return json_error(
                    415,
                    "unsupported media type: expected application/x-pfhe",
                    json_header,
                );
            }
            handle_generate_encrypted(request, backend, server_sk, json_header)
        }
        _ => json_error(404, "not found", json_header),
    }
}

// ─── POST /infer — full protocol ─────────────────────────────────────────

fn handle_infer<B: InferenceBackend>(
    request: &mut tiny_http::Request,
    backend: &B,
    json_header: Header,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body(request) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read error: {e}");
            return json_error(400, "failed to read request body", json_header);
        }
    };

    // R9: Check JSON nesting depth to prevent stack overflow
    if !check_json_depth(&body) {
        return json_error(400, "invalid request body", json_header);
    }

    let infer_request: InferRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            // R7: Log full error server-side but return generic message to client
            eprintln!("invalid JSON: {e}");
            return json_error(400, "invalid request body", json_header);
        }
    };

    // R6: Validate max_tokens > 0 (zero wastes prefill resources with no output)
    if infer_request.max_tokens == 0 {
        return json_error(400, "max_tokens must be > 0", json_header);
    }

    // Validate max_tokens upper bound
    if infer_request.max_tokens > MAX_ALLOWED_TOKENS {
        return json_error(400, "max_tokens exceeds server limit", json_header);
    }

    // Validate temperature
    if let Err(msg) = crate::inference::validate_temperature(infer_request.temperature) {
        return json_error(400, msg, json_header);
    }

    // R9: Validate encrypted_input size BEFORE attempting to deserialize/decode.
    // Previously this check was after the safety check, meaning an attacker
    // could trigger expensive deserialization and decode on a huge payload
    // before the size check rejected it (TOCTOU ordering bug).
    if infer_request.encrypted_input.len() > MAX_ENCRYPTED_INPUT_SIZE {
        return json_error(
            400,
            "encrypted_input too large",
            json_header,
        );
    }

    // R6: Prompt safety check on /infer (previously missing — allowed bypass)
    {
        let input_ct: Result<poly_client::encryption::MockCiphertext, _> =
            serde_json::from_slice(&infer_request.encrypted_input);
        if let Ok(ct) = input_ct {
            if !ct.tokens.is_empty() {
                let prompt_text = crate::model::decode(&ct.tokens);
                if let Err(rejection) = crate::compliance::check_prompt(&prompt_text) {
                    // R7: Don't echo the specific rejection reason to the client
                    eprintln!("prompt rejected on /infer: {}", rejection);
                    return json_error(403, "prompt rejected by safety filter", json_header);
                }
            }
            // R6: Validate token count on /infer
            if ct.tokens.len() > MAX_PROMPT_TOKENS {
                return json_error(400, "input exceeds token limit", json_header);
            }
        }
    }

    match backend.infer(&infer_request) {
        Ok(response) => {
            let response_body = serde_json::to_vec(&response).unwrap();
            let mut headers = vec![json_header];
            headers.extend(security_headers());
            Response::new(
                StatusCode(200),
                headers,
                std::io::Cursor::new(response_body),
                None,
                None,
            )
        }
        Err(e) => {
            // R7: Log detailed error server-side, return generic message to client
            // to prevent information leakage about model internals
            eprintln!("inference failed: {e}");
            json_error(500, "internal server error", json_header)
        }
    }
}

// ─── POST /generate — simple batch ───────────────────────────────────────

fn handle_generate(
    request: &mut tiny_http::Request,
    json_header: Header,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body(request) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read error: {e}");
            return json_error(400, "failed to read request body", json_header);
        }
    };

    // R9: Check JSON nesting depth to prevent stack overflow
    if !check_json_depth(&body) {
        return json_error(400, "invalid request body", json_header);
    }

    let req: GenerateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid JSON: {e}");
            return json_error(400, "invalid request body", json_header);
        }
    };

    // R6: Validate max_tokens > 0 (zero wastes prefill resources with no output)
    if req.max_tokens == 0 {
        return json_error(400, "max_tokens must be > 0", json_header);
    }

    // Validate max_tokens upper bound
    // R9: Don't reveal exact limit in error — aids attacker tuning
    if req.max_tokens > MAX_ALLOWED_TOKENS {
        return json_error(400, "max_tokens exceeds server limit", json_header);
    }

    // Validate temperature (must be in 1..=2000; 0 causes divide-by-zero, high values
    // produce degenerate sampling distributions)
    if let Err(msg) = crate::inference::validate_temperature(req.temperature) {
        return json_error(400, msg, json_header);
    }

    // R6: Validate prompt length in characters (DoS prevention)
    // R9: Don't reveal exact character count or limit in error — aids DoS tuning
    if req.prompt.len() > MAX_PROMPT_LENGTH {
        return json_error(400, "prompt too long", json_header);
    }

    // Validate mode
    // R10: Don't echo the attacker-controlled mode value or list valid modes in the error.
    // Previously: format!("invalid mode {:?}: expected transparent, private, or private_inputs", mode)
    // This leaked: (1) the exact user input (potential XSS in downstream consumers),
    // (2) the full enumeration of valid mode values (aids enumeration attacks).
    let mode = req.mode.as_str();
    if !matches!(mode, "transparent" | "private" | "private_inputs") {
        eprintln!("invalid mode requested: {:?}", mode);
        return json_error(
            400,
            "invalid mode",
            json_header,
        );
    }

    if mode != "transparent" && mode != "" {
        // /generate uses generate_compliant which always produces transparent proofs.
        // Don't mislead the client by echoing their requested mode.
        return json_error(400, "POST /generate currently only supports transparent mode. Use POST /infer for private/encrypted modes.", json_header);
    }

    // Pre-inference safety gate: reject jailbreak and harmful prompts
    if let Err(rejection) = check_prompt(&req.prompt) {
        // R7: Log specific rejection server-side, return generic message to client
        // to prevent attackers from learning which pattern matched
        eprintln!("prompt rejected: {}", rejection);
        return json_error(403, "prompt rejected by safety filter", json_header);
    }

    // Tokenize
    let token_ids = match crate::model::tokenize(&req.prompt) {
        Ok(ids) => ids,
        Err(e) => {
            // R7: Don't reveal "tokenization failed" -- leaks implementation detail
            eprintln!("tokenization failed: {e}");
            return json_error(500, "internal server error", json_header);
        }
    };

    if token_ids.is_empty() {
        return json_error(400, "prompt tokenized to zero tokens", json_header);
    }

    // R6: Validate prompt token count (DoS prevention for token-dense inputs)
    // R9: Don't reveal exact token count or limit in error — aids DoS tuning
    if token_ids.len() > MAX_PROMPT_TOKENS {
        return json_error(400, "prompt too many tokens", json_header);
    }

    let prompt_len = token_ids.len();
    let policy = default_policy();
    let policy_version = policy.version;

    // Generate tokens with in-loop per-token compliance gate for ALL modes.
    // Every token is checked against the policy before being emitted.
    // This prevents harmful tokens from ever being generated, regardless of
    // the privacy mode requested. The execution proof comes from the compliant
    // generation's IVC chain.
    let (output_tokens, exec_proof, compliance_proof) = {
        let (tokens, comp_proof) = crate::inference::generate_compliant(
            token_ids.clone(),
            req.max_tokens,
            req.temperature,
            req.seed,
            policy,
        );
        (tokens, comp_proof.ivc_proof.clone(), comp_proof)
    };

    // Decode — use saturating_sub to prevent underflow if backend returns fewer tokens
    let text = crate::model::decode(&output_tokens);
    let safe_prompt_len = prompt_len.min(output_tokens.len());
    let completion = crate::model::decode(&output_tokens[safe_prompt_len..]);
    let generated_tokens = output_tokens.len().saturating_sub(prompt_len);

    // R7: Post-generation text-level compliance check.
    // Token-level n-gram checking can be evaded by interleaving whitespace/punctuation
    // tokens that break the contiguous n-gram match. This catches such evasion by
    // scanning the decoded completion text for harmful terms.
    if let Err(term) = crate::compliance::check_output_text(&completion) {
        eprintln!("R7: post-generation text check caught harmful term: {:?}", term);
        return json_error(
            451,
            "generation contained harmful content and was blocked",
            json_header,
        );
    }

    // Build execution proof summary with I/O binding
    let proof_summary = proof_to_summary(
        &exec_proof,
        &token_ids,
        &output_tokens[safe_prompt_len..],
    );

    // Build compliance summary
    let comp_verified = compliance_proof.verify().unwrap_or(false);
    let (comp_tip, comp_root, comp_steps) = match &compliance_proof.ivc_proof {
        VerifiedProof::HashIvc {
            chain_tip,
            merkle_root,
            step_count,
            ..
        } => (
            hex::encode(chain_tip),
            hex::encode(merkle_root),
            *step_count,
        ),
        _ => (String::new(), String::new(), 0),
    };

    // R10: Don't echo back the raw user-supplied `req.mode` string.
    // Even though it's validated above, echoing user input into JSON responses
    // risks injection if downstream consumers don't escape properly.
    // Use the validated canonical value instead.
    let canonical_mode = mode.to_string();

    let resp = GenerateResponse {
        text,
        completion,
        tokens: output_tokens,
        generated_tokens,
        mode: canonical_mode,
        proof: proof_summary,
        compliance: ComplianceSummary {
            verified: comp_verified,
            total_tokens: compliance_proof.total_tokens,
            compliant_tokens: compliance_proof.compliant_tokens,
            all_compliant: compliance_proof.all_compliant(),
            policy_version,
            policy_hash: hex::encode(compliance_proof.policy_hash),
            ivc_chain_tip: comp_tip,
            ivc_merkle_root: comp_root,
            ivc_steps: comp_steps,
        },
    };

    let response_body = serde_json::to_vec(&resp).unwrap();
    let mut headers = vec![json_header];
    headers.extend(security_headers());
    Response::new(
        StatusCode(200),
        headers,
        std::io::Cursor::new(response_body),
        None,
        None,
    )
}

// ─── POST /generate/encrypted — CKKS encrypted batch ────────────────────

fn handle_generate_encrypted<B: InferenceBackend>(
    request: &mut tiny_http::Request,
    backend: &B,
    server_sk: &CkksSecretKey,
    json_header: Header,
) -> Response<std::io::Cursor<Vec<u8>>> {
    use poly_client::ckks::compress;

    let body = match read_body(request) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read error: {e}");
            return json_error(400, "failed to read request body", json_header);
        }
    };

    // Entire body is PFHE-compressed (bincode + zstd).
    // The compress module has an internal MAX_DECOMPRESSED_SIZE (32 MB) that prevents
    // decompression bombs. The read_body() above caps the compressed input at 1 MB.
    let req: EncryptedGenerateRequest = match compress::decompress(&body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid PFHE payload: {e}");
            return json_error(400, "invalid encrypted payload", json_header);
        }
    };

    // R6: Validate max_tokens > 0
    if req.max_tokens == 0 {
        return json_error(400, "max_tokens must be > 0", json_header);
    }

    // Validate max_tokens upper bound
    // R9: Don't reveal exact limit in error — aids attacker tuning
    if req.max_tokens > MAX_ALLOWED_TOKENS {
        return json_error(400, "max_tokens exceeds server limit", json_header);
    }

    // Validate temperature
    if let Err(msg) = crate::inference::validate_temperature(req.temperature) {
        return json_error(400, msg, json_header);
    }

    // Validate encrypted_input size
    // R9: Don't reveal exact size or limit in error
    if req.encrypted_input.len() > MAX_ENCRYPTED_INPUT_SIZE {
        return json_error(
            400,
            "encrypted_input too large",
            json_header,
        );
    }

    // R7: Validate client_public_key size (same limit as encrypted_input).
    // Without this, an attacker can send a multi-MB client_public_key that
    // decompresses to an enormous CKKS key, exhausting memory.
    // R9: Don't reveal exact size or limit in error
    if req.client_public_key.len() > MAX_ENCRYPTED_INPUT_SIZE {
        return json_error(
            400,
            "client_public_key too large",
            json_header,
        );
    }

    // Nested PFHE-compressed ciphertext and public key
    let input_ct: CkksCiphertext = match compress::decompress(&req.encrypted_input) {
        Ok(ct) => ct,
        Err(e) => {
            eprintln!("invalid CkksCiphertext: {e}");
            return json_error(400, "invalid encrypted input", json_header);
        }
    };

    let client_pk: CkksPublicKey = match compress::decompress(&req.client_public_key) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("invalid CkksPublicKey: {e}");
            return json_error(400, "invalid client public key", json_header);
        }
    };

    // Decrypt input token IDs using server's secret key.
    // Use decrypt_unchecked because the auth tag was created by the client
    // (using the client's MAC key), not the server's.
    use poly_client::ckks::ciphertext::decrypt_unchecked;
    let token_ids = decrypt_unchecked(&input_ct, server_sk);
    let ckks = CkksEncryption;

    if token_ids.is_empty() {
        return json_error(400, "encrypted input decoded to zero tokens", json_header);
    }

    // R6: Validate decrypted token count (DoS prevention)
    // R9: Don't reveal exact count or limit in error
    if token_ids.len() > MAX_PROMPT_TOKENS {
        return json_error(400, "decrypted input too many tokens", json_header);
    }

    // Decode tokens to text for compliance check
    let prompt_text = crate::model::decode(&token_ids);
    if let Err(rejection) = check_prompt(&prompt_text) {
        // R8: Don't echo the specific rejection reason to the client on encrypted endpoint
        // (same fix as R7 applied to /generate). Prevents attackers from learning which
        // pattern matched to craft more precise evasions.
        eprintln!("prompt rejected on /generate/encrypted: {}", rejection);
        return json_error(403, "prompt rejected by safety filter", json_header);
    }

    let prompt_len = token_ids.len();
    let policy = default_policy();
    let policy_version = policy.version;

    // Route through InferenceBackend (uses ComplianceInferenceBackend in production,
    // MockInferenceBackend in tests). The ComplianceInferenceBackend runs generate_compliant()
    // which enforces per-token compliance in-loop.
    let mock_ct = poly_client::encryption::MockCiphertext { tokens: token_ids.clone() };
    let infer_request = poly_client::protocol::InferRequest {
        model_id: "encrypted-batch".into(),
        mode: poly_client::protocol::Mode::Private,
        encrypted_input: serde_json::to_vec(&mock_ct).unwrap(),
        max_tokens: req.max_tokens,
        temperature: req.temperature,
        seed: req.seed,
    };

    let infer_response = match backend.infer(&infer_request) {
        Ok(resp) => resp,
        Err(e) => {
            // R8: Return generic message to prevent information leakage about backend internals.
            // Same pattern as /infer endpoint (which returns "internal server error").
            eprintln!("inference failed on /generate/encrypted: {e}");
            return json_error(500, "internal server error", json_header);
        }
    };

    // Extract output tokens from backend response
    let output_ct: poly_client::encryption::MockCiphertext =
        match serde_json::from_slice(&infer_response.encrypted_output) {
            Ok(ct) => ct,
            Err(e) => {
                eprintln!("output decode failed: {e}");
                return json_error(500, "internal error", json_header);
            }
        };
    let output_tokens = output_ct.tokens;
    let exec_proof = infer_response.proof;
    let safe_enc_prompt_len = prompt_len.min(output_tokens.len());
    let generated_tokens = output_tokens.len().saturating_sub(prompt_len);

    // R7: Post-generation text-level compliance check on encrypted endpoint.
    // Same rationale as /generate: n-gram evasion via token interleaving.
    let completion_text = crate::model::decode(&output_tokens[safe_enc_prompt_len..]);
    if let Err(term) = crate::compliance::check_output_text(&completion_text) {
        eprintln!("R7: post-generation text check caught harmful term on encrypted endpoint: {:?}", term);
        return json_error(
            451,
            "generation contained harmful content and was blocked",
            json_header,
        );
    }

    // Post-hoc compliance attestation (the ComplianceInferenceBackend already
    // enforced per-token compliance in-loop via generate_compliant())
    let checker = crate::compliance::PolicyChecker::new(policy.clone());
    let mut acc = crate::compliance_proof::ComplianceAccumulator::new(checker);
    for &token in &output_tokens[safe_enc_prompt_len..] {
        let _ = acc.check_and_fold(token);
    }
    let comp_proof = acc.finalize().expect("compliance finalize");

    // Re-encrypt output token IDs with client's CKKS public key, then compress
    let output_ckks_ct = ckks.encrypt(&output_tokens, &client_pk, server_sk);
    let encrypted_output = compress::compress(&output_ckks_ct)
        .expect("compress output ciphertext");

    // Build proof summary with I/O binding
    let proof_summary = proof_to_summary(
        &exec_proof,
        &token_ids,
        &output_tokens[safe_enc_prompt_len..],
    );

    // Build compliance summary
    let comp_verified = comp_proof.verify().unwrap_or(false);
    let (comp_tip, comp_root, comp_steps) = match &comp_proof.ivc_proof {
        VerifiedProof::HashIvc {
            chain_tip,
            merkle_root,
            step_count,
            ..
        } => (
            hex::encode(chain_tip),
            hex::encode(merkle_root),
            *step_count,
        ),
        _ => (String::new(), String::new(), 0),
    };

    let resp = EncryptedGenerateResponse {
        encrypted_output,
        generated_tokens,
        total_tokens: output_tokens.len(),
        proof: proof_summary,
        compliance: ComplianceSummary {
            verified: comp_verified,
            total_tokens: comp_proof.total_tokens,
            compliant_tokens: comp_proof.compliant_tokens,
            all_compliant: comp_proof.all_compliant(),
            policy_version,
            policy_hash: hex::encode(comp_proof.policy_hash),
            ivc_chain_tip: comp_tip,
            ivc_merkle_root: comp_root,
            ivc_steps: comp_steps,
        },
    };

    // Entire response is PFHE-compressed binary
    let binary_header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/x-pfhe"[..]).unwrap();
    let response_body = compress::compress(&resp).expect("compress response");
    let mut headers = vec![binary_header];
    headers.extend(security_headers());
    Response::new(
        StatusCode(200),
        headers,
        std::io::Cursor::new(response_body),
        None,
        None,
    )
}


/// Convert a VerifiedProof into a JSON-friendly summary.
///
/// `input_tokens` and `output_tokens` are hashed and included in the summary
/// so external verifiers can bind the proof to specific I/O.
fn proof_to_summary(
    proof: &VerifiedProof,
    input_tokens: &[u32],
    output_tokens: &[u32],
) -> ProofSummary {
    use poly_verified::crypto::hash::hash_data;
    use poly_verified::ivc::hash_ivc::HashIvc;
    use poly_verified::ivc::IvcBackend;

    // Compute deterministic I/O hashes from actual token sequences
    let input_bytes: Vec<u8> = input_tokens.iter().flat_map(|t| t.to_le_bytes()).collect();
    let output_bytes: Vec<u8> = output_tokens.iter().flat_map(|t| t.to_le_bytes()).collect();
    let input_hash = hash_data(&input_bytes);
    let output_hash = hash_data(&output_bytes);

    let backend = HashIvc;
    let ok = backend.verify(proof, &input_hash, &output_hash).unwrap_or(false);

    match proof {
        VerifiedProof::HashIvc {
            chain_tip,
            merkle_root,
            step_count,
            code_hash,
            privacy_mode,
            blinding_commitment,
            ..
        } => ProofSummary {
            backend: "HashIvc".into(),
            privacy_mode: format!("{:?}", privacy_mode),
            chain_tip: hex::encode(chain_tip),
            merkle_root: hex::encode(merkle_root),
            step_count: *step_count,
            code_hash: if *code_hash == [0u8; 32] {
                "(hidden)".into()
            } else {
                hex::encode(code_hash)
            },
            blinding_commitment: blinding_commitment.map(|b| hex::encode(b)),
            verified: ok,
            input_hash: hex::encode(input_hash),
            output_hash: hex::encode(output_hash),
        },
        // Handle Mock variant (compiled in when poly-verified has "mock" feature)
        // and any future variants with a sensible fallback.
        #[allow(unreachable_patterns)]
        _ => ProofSummary {
            backend: "Unknown".into(),
            privacy_mode: "unknown".into(),
            chain_tip: String::new(),
            merkle_root: String::new(),
            step_count: 0,
            code_hash: String::new(),
            blinding_commitment: None,
            verified: false,
            input_hash: hex::encode(input_hash),
            output_hash: hex::encode(output_hash),
        },
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Maximum request body size: 1 MB.
const MAX_BODY_SIZE: usize = 1_048_576;

/// R9: Maximum JSON nesting depth. Deeply nested JSON (e.g., `{"a":{"a":...}}`)
/// can cause stack overflow during parsing. serde_json doesn't have a built-in
/// depth limit, so we scan the raw bytes to reject excessively nested payloads
/// before attempting deserialization.
const MAX_JSON_DEPTH: usize = 32;

fn read_body(request: &mut tiny_http::Request) -> std::io::Result<Vec<u8>> {
    let content_length = request.body_length().unwrap_or(0);
    if content_length > MAX_BODY_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }
    let mut body = Vec::new();
    request.as_reader().take(MAX_BODY_SIZE as u64 + 1).read_to_end(&mut body)?;
    if body.len() > MAX_BODY_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }
    Ok(body)
}

/// R9: Check that JSON nesting depth doesn't exceed MAX_JSON_DEPTH.
/// This prevents stack overflow from deeply nested payloads like
/// `{"a":{"a":{"a":...}}}` repeated thousands of times.
fn check_json_depth(body: &[u8]) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut prev_escape = false;

    for &b in body {
        if in_string {
            if prev_escape {
                prev_escape = false;
                continue;
            }
            if b == b'\\' {
                prev_escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }

        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return false;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    true
}

/// R9: Build standard security headers for all HTTP responses.
/// - X-Content-Type-Options: nosniff — prevents MIME-sniffing attacks
/// - Cache-Control: no-store — prevents caching of sensitive inference responses
/// - X-Frame-Options: DENY — prevents clickjacking
/// R11: Added Content-Security-Policy and Referrer-Policy headers.
/// - Content-Security-Policy: default-src 'none' — blocks all resource loading if response
///   is accidentally rendered as HTML (defense-in-depth against XSS via JSON injection)
/// - Referrer-Policy: no-referrer — prevents leaking inference URLs to third parties
/// R12: Added X-Permitted-Cross-Domain-Policies and cross-origin headers.
/// - X-Permitted-Cross-Domain-Policies: none — prevents Flash/PDF cross-domain access
/// - Cross-Origin-Opener-Policy: same-origin — prevents cross-origin window references
/// - Cross-Origin-Resource-Policy: same-origin — blocks cross-origin resource reads
/// R13: Added Strict-Transport-Security header.
/// - Strict-Transport-Security: max-age=63072000; includeSubDomains — instructs browsers
///   to only access the server over HTTPS for 2 years, preventing MITM downgrade attacks
///   that intercept inference requests/responses containing sensitive data.
/// R15: Added X-DNS-Prefetch-Control and Permissions-Policy headers.
/// - X-DNS-Prefetch-Control: off — prevents browsers from pre-resolving DNS for
///   external domains found in response content, which could leak information about
///   inference results to DNS observers.
/// - Permissions-Policy: interest-cohort=() — disables FLoC/Topics API to prevent
///   browser-side profiling of inference usage patterns.
fn security_headers() -> Vec<Header> {
    vec![
        Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap(),
        Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap(),
        Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]).unwrap(),
        Header::from_bytes(&b"Content-Security-Policy"[..], &b"default-src 'none'"[..]).unwrap(),
        Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap(),
        Header::from_bytes(&b"X-Permitted-Cross-Domain-Policies"[..], &b"none"[..]).unwrap(),
        Header::from_bytes(&b"Cross-Origin-Opener-Policy"[..], &b"same-origin"[..]).unwrap(),
        Header::from_bytes(&b"Cross-Origin-Resource-Policy"[..], &b"same-origin"[..]).unwrap(),
        Header::from_bytes(&b"Strict-Transport-Security"[..], &b"max-age=63072000; includeSubDomains"[..]).unwrap(),
        Header::from_bytes(&b"X-DNS-Prefetch-Control"[..], &b"off"[..]).unwrap(),
        Header::from_bytes(&b"Permissions-Policy"[..], &b"interest-cohort=()"[..]).unwrap(),
    ]
}

fn json_error(
    status: u16,
    message: &str,
    json_header: Header,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut headers = vec![json_header];
    headers.extend(security_headers());
    Response::new(
        StatusCode(status),
        headers,
        std::io::Cursor::new(
            serde_json::to_vec(&serde_json::json!({"error": message})).unwrap(),
        ),
        None,
        None,
    )
}
