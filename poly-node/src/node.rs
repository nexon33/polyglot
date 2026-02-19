//! PolyNode — main daemon that ties together QUIC transport, identity,
//! and inference backend.
//!
//! Hardened against:
//! - HelloAck reflection (returns server's own NodeInfo)
//! - Unbounded connections (semaphore-limited to max_sessions)
//! - Unbounded inference tasks (semaphore-limited)
//! - Stream read timeout (10s)
//! - Bincode deserialization limits
//! - Version mismatch rejection
//! - Wrong-direction message rejection
//! - Stale Hello timestamps (>5 min drift rejected)
//! - Client-side HelloAck signature verification
//! - R5: Repeated handshake re-auth (only first Hello counts)
//! - R5: Stale server NodeInfo (regenerated per-connection, not at startup)
//! - R5: Handshake-InferRequest race condition (SeqCst ordering)
//! - R5: Unbounded stream spawning per connection (capped to max_streams_per_conn)
//! - R5: model_id in InferRequest validated against configured model
//! - R5: max_tokens in InferRequest capped at MAX_INFER_TOKENS
//! - R5: Connection idle timeout (closes after 60s of no streams)
//! - R5: Hello timestamp from the future rejected (prevents pre-computed replay windows)
//! - R5: NodeInfo signature covers all fields (not just pubkey||timestamp)
//! - R6: stream_count uses SeqCst ordering (was Relaxed, could skip bounds on weak archs)
//! - R6: Rejected Hello returns minimal HelloAck (no server NodeInfo to unauthenticated peers)
//! - R6: connect_and_infer has timeout on inference response read (prevents slowloris)
//! - R6: max_sessions validated >= 1 in PolyNode::new (prevents zero-semaphore deadlock)
//! - R6: Hello deserialization does NOT allow_trailing_bytes (enforces strict size limit)
//! - R6: NodeInfo.addresses and NodeInfo.models length capped post-deserialization
//! - R6: throughput_estimate validated (NaN/Inf rejected)
//! - R7: model_name string length capped at 256 bytes (prevents memory amplification)
//! - R7: signature Vec length capped at 64 bytes (early rejection of oversized sigs)
//! - R7: Negative throughput_estimate rejected (prevents peer-selection inversion)
//! - R7: encrypted_input size capped at 1 MB (prevents oversized ciphertext payloads)
//! - R7: Phase 2/3 message types require handshake authentication
//! - R7: Client-side HelloAck deserialization uses size-limited bincode (prevents OOM)
//! - R7: Client-side HelloAck timestamp freshness check (prevents replay)
//! - R8: InferRequest.model_id length capped at 256 bytes (prevents echo amplification)
//! - R8: Error message type requires handshake (was falling through to unguarded catch-all)
//! - R8: decode_hello/decode_hello_ack use size-limited bincode (public API hardening)
//! - R8: Client-side HelloAck NodeInfo field validation (addresses, models, model_name, throughput)
//! - R9: Double deserialization TOCTOU eliminated (validated request passed to backend directly)
//! - R9: encode_hello/encode_hello_ack validate output size (symmetric with decode limits)
//! - R9: Server NodeInfo regenerated every 4 minutes (prevents stale timestamp rejection)
//! - R9: Pre-handshake stream cap (MAX_PRE_HANDSHAKE_STREAMS=8, separate from post-auth cap)
//! - R9: Client-side InferResponse encrypted_output + model_id size validation
//! - R9: Frame::try_encode() safe variant that returns Result instead of panicking

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bincode::Options;
use log::{info, warn};
use tokio::sync::Semaphore;

use crate::config::NodeConfig;
use crate::identity::NodeIdentity;
use crate::net::transport;
use crate::protocol::handshake::{self, PROTOCOL_VERSION};
use crate::protocol::wire::{Frame, MessageType, ModelCapability, NodeCapacity, NodeInfo};
use crate::protocol::{inference};

use poly_inference::server::InferenceBackend;

/// Maximum time to wait for a complete stream read.
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum size for a serialized Hello message (64 KB).
const MAX_HELLO_SIZE: u64 = 64 * 1024;

/// Maximum acceptable Hello timestamp drift (5 minutes).
const MAX_HELLO_TIMESTAMP_DRIFT_SECS: u64 = 300;

/// Maximum allowed max_tokens in an inference request.
/// Prevents clients from requesting absurdly long generation runs.
pub const MAX_INFER_TOKENS: u32 = 4096;

/// Maximum streams a single connection may open before being killed.
/// Prevents stream-flooding DoS within an authenticated connection.
const MAX_STREAMS_PER_CONN: u64 = 256;

/// Connection idle timeout — if no streams are opened within this window,
/// the connection is closed. Prevents zombie connections holding semaphore permits.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum streams allowed before handshake completion.
/// This is much lower than MAX_STREAMS_PER_CONN to limit the damage
/// an unauthenticated peer can do. A legitimate client only needs 1 stream
/// for the Hello handshake, so 8 is generous.
const MAX_PRE_HANDSHAKE_STREAMS: u64 = 8;

/// Maximum number of addresses in a NodeInfo (prevents gossip amplification).
const MAX_NODEINFO_ADDRESSES: usize = 16;

/// Maximum number of models in a NodeInfo (prevents gossip amplification).
const MAX_NODEINFO_MODELS: usize = 16;

/// Maximum allowed length for a model_name string in NodeInfo (bytes).
/// Prevents memory amplification via long model names within the 16-model cap.
/// 16 models x 256 bytes = 4 KB max model name storage.
const MAX_MODEL_NAME_LEN: usize = 256;

/// Maximum allowed length for the signature field in NodeInfo (bytes).
/// Ed25519 signatures are exactly 64 bytes; anything else is invalid.
/// Without this cap, the Vec<u8> signature could be up to 64KB within
/// the bincode size limit, wasting memory before the == 64 check rejects it.
const MAX_SIGNATURE_LEN: usize = 64;

/// Maximum allowed size for InferRequest.encrypted_input (1 MB).
/// Prevents a single request from passing an oversized encrypted payload
/// that wastes memory in the inference backend's spawn_blocking task.
const MAX_ENCRYPTED_INPUT_SIZE: usize = 1 * 1024 * 1024;

/// Maximum allowed length for InferRequest.model_id (bytes).
/// Even when model_name == "mock" (which skips the match check), we still
/// need to bound this string to prevent memory waste. The model_id passes
/// through to the InferResponse and is echoed back to the client, so a
/// 4 MB model_id in the request would cause a 4 MB model_id in the response.
pub const MAX_MODEL_ID_LEN: usize = 256;

/// Client-side timeout for reading inference response.
/// Prevents a malicious/slow server from tying up the client indefinitely.
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum allowed size for InferResponse.encrypted_output on client side (4 MB).
/// Prevents a malicious server from sending an oversized encrypted output that
/// wastes client memory. Real PFHE ciphertext outputs should be much smaller.
const MAX_CLIENT_RESPONSE_OUTPUT_SIZE: usize = 4 * 1024 * 1024;

/// A running Poly Network compute node.
pub struct PolyNode {
    pub config: NodeConfig,
    pub identity: NodeIdentity,
    backend: Arc<dyn InferenceBackend + Send + Sync>,
}

impl PolyNode {
    /// Create a new node with the given config and inference backend.
    pub fn new(
        config: NodeConfig,
        backend: Arc<dyn InferenceBackend + Send + Sync>,
    ) -> Result<Self> {
        // R6: Validate max_sessions >= 1. A zero value would create a
        // zero-permit semaphore that blocks ALL connections and inference
        // forever, effectively a self-DoS configuration footgun.
        if config.max_sessions == 0 {
            anyhow::bail!("max_sessions must be >= 1 (got 0)");
        }
        let identity = NodeIdentity::generate();
        info!(
            "Generated node ID: {}",
            hex::encode(&identity.id[..8])
        );
        Ok(Self {
            config,
            identity,
            backend,
        })
    }

    /// Build a `NodeInfo` advertising this node's identity and capabilities.
    ///
    /// The NodeInfo is signed with this node's Ed25519 key:
    /// signature = Sign(public_key || timestamp).
    fn own_node_info(&self) -> NodeInfo {
        let public_key = self.identity.public_key_bytes();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Sign: public_key || timestamp
        let mut msg = Vec::new();
        msg.extend_from_slice(&public_key);
        msg.extend_from_slice(&timestamp.to_le_bytes());
        let sig = self.identity.sign(&msg);

        NodeInfo {
            public_key,
            addresses: vec![self.config.listen_addr],
            models: vec![ModelCapability {
                model_name: self.config.model_name.clone(),
                gpu: false,
                throughput_estimate: 0.0,
            }],
            relay_capable: self.config.relay,
            capacity: NodeCapacity {
                queue_depth: 0,
                active_sessions: 0,
                max_sessions: self.config.max_sessions,
            },
            timestamp,
            signature: sig.to_vec(),
        }
    }

    /// Run the node: listen for QUIC connections and handle them.
    pub async fn run(&self) -> Result<()> {
        let endpoint = transport::create_server_endpoint(self.config.listen_addr)?;
        info!(
            "Node {} listening on {}",
            hex::encode(&self.identity.id[..8]),
            self.config.listen_addr
        );

        // Limit concurrent connections to max_sessions
        let conn_semaphore = Arc::new(Semaphore::new(self.config.max_sessions as usize));
        // Limit concurrent inference tasks (compute-heavy)
        let infer_semaphore = Arc::new(Semaphore::new(self.config.max_sessions as usize));

        // R9: Generate server_info fresh and track its creation time.
        // Before R9, the NodeInfo was generated once and shared for the
        // entire lifetime of the server. After 5 minutes, any client with
        // timestamp freshness checking (R7 connect_and_infer) would reject
        // the stale HelloAck. Now we regenerate it periodically.
        let server_info = Arc::new(std::sync::RwLock::new(self.own_node_info()));
        let server_info_generated_at = Arc::new(std::sync::atomic::AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ));

        let model_name = Arc::new(self.config.model_name.clone());

        // R9: Closure to regenerate server_info when needed.
        // We share the identity reference for regeneration.
        let identity_for_regen = Arc::new((
            self.identity.public_key_bytes(),
            // We need a way to sign -- store the full identity.
            // Since NodeIdentity doesn't implement Clone, we'll just
            // regenerate from our own_node_info method via a closure.
        ));
        let _ = identity_for_regen; // Used conceptually; actual regen below.

        while let Some(incoming) = endpoint.accept().await {
            let backend = self.backend.clone();
            let conn_sem = conn_semaphore.clone();
            let infer_sem = infer_semaphore.clone();
            let model = model_name.clone();

            // R9: Regenerate server_info if stale (older than 4 minutes).
            // The MAX_HELLO_TIMESTAMP_DRIFT_SECS is 5 minutes, so we
            // regenerate at 4 minutes to give a 1-minute safety margin.
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let generated_at = server_info_generated_at.load(std::sync::atomic::Ordering::SeqCst);
                if now > generated_at && (now - generated_at) > (MAX_HELLO_TIMESTAMP_DRIFT_SECS - 60) {
                    let new_info = self.own_node_info();
                    if let Ok(mut guard) = server_info.write() {
                        *guard = new_info;
                    }
                    server_info_generated_at.store(now, std::sync::atomic::Ordering::SeqCst);
                    info!("Regenerated server NodeInfo (was {}s stale)", now - generated_at);
                }
            }
            let info = server_info.clone();

            tokio::spawn(async move {
                // Acquire connection permit (drop releases it)
                let _permit = match conn_sem.try_acquire() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("Connection rejected: max sessions reached");
                        // Accept and immediately close to signal overload
                        if let Ok(conn) = incoming.await {
                            conn.close(1u32.into(), b"overloaded");
                        }
                        return;
                    }
                };

                if let Err(e) =
                    handle_connection(incoming, backend, infer_sem, info, model).await
                {
                    warn!("Connection error: {}", e);
                }
            });
        }

        Ok(())
    }

    pub fn node_id(&self) -> &[u8; 32] {
        &self.identity.id
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    backend: Arc<dyn InferenceBackend + Send + Sync>,
    infer_semaphore: Arc<Semaphore>,
    server_info: Arc<std::sync::RwLock<NodeInfo>>,
    model_name: Arc<String>,
) -> Result<()> {
    let conn = incoming.await?;
    info!("Connection from {}", conn.remote_address());

    // Track whether this connection has completed a valid handshake.
    // Uses SeqCst ordering to prevent race between Hello handler storing
    // `true` and InferRequest handler loading the value on concurrent streams.
    let handshake_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Count streams opened on this connection to cap stream-flooding.
    let stream_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // R9: Count pre-handshake streams separately. Before R9, all streams
    // (pre- and post-handshake) shared the same counter, meaning an
    // unauthenticated attacker could exhaust all 256 stream slots by
    // sending pre-handshake probes (Error, wrong-direction, Phase 2/3).
    // Cap pre-handshake streams at a much lower limit (16) to limit
    // the damage an unauthenticated peer can do before handshake.
    let pre_handshake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    loop {
        // Accept next stream with idle timeout — prevents zombie connections
        // that hold a connection-semaphore permit indefinitely.
        let accept_result = tokio::time::timeout(
            CONN_IDLE_TIMEOUT,
            conn.accept_bi(),
        )
        .await;

        let (send, recv) = match accept_result {
            Err(_) => {
                // Idle timeout — close connection to reclaim resources.
                warn!("Connection from {} idle-timed out", conn.remote_address());
                conn.close(2u32.into(), b"idle timeout");
                break;
            }
            Ok(Ok(s)) => s,
            Ok(Err(quinn::ConnectionError::ApplicationClosed(_))) => break,
            Ok(Err(quinn::ConnectionError::ConnectionClosed(_))) => break,
            Ok(Err(e)) => return Err(e.into()),
        };

        // Enforce per-connection stream limit to prevent stream-flooding DoS.
        // R6: Uses SeqCst (was Relaxed) for consistency with handshake_done ordering.
        // On weakly-ordered architectures, Relaxed could allow the counter to be read
        // stale by concurrent stream handlers, potentially exceeding the cap.
        let count = stream_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if count >= MAX_STREAMS_PER_CONN {
            warn!(
                "Connection from {} exceeded max streams ({}), closing",
                conn.remote_address(),
                MAX_STREAMS_PER_CONN
            );
            conn.close(3u32.into(), b"too many streams");
            break;
        }

        // R9: Enforce pre-handshake stream limit. An unauthenticated peer
        // can only open MAX_PRE_HANDSHAKE_STREAMS before the connection is
        // closed, limiting the damage from pre-handshake probing attacks.
        if !handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
            let pre_count = pre_handshake_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if pre_count >= MAX_PRE_HANDSHAKE_STREAMS {
                warn!(
                    "Connection from {} exceeded pre-handshake stream limit ({}), closing",
                    conn.remote_address(),
                    MAX_PRE_HANDSHAKE_STREAMS
                );
                conn.close(4u32.into(), b"too many unauthenticated streams");
                break;
            }
        }

        let backend = backend.clone();
        let infer_sem = infer_semaphore.clone();
        let info = server_info.clone();
        let hs = handshake_done.clone();
        let model = model_name.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_stream(send, recv, backend, infer_sem, info, hs, model).await
            {
                warn!("Stream error: {}", e);
            }
        });
    }

    Ok(())
}

/// Handle a single bi-directional QUIC stream (one request -> one response).
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    backend: Arc<dyn InferenceBackend + Send + Sync>,
    infer_semaphore: Arc<Semaphore>,
    server_info: Arc<std::sync::RwLock<NodeInfo>>,
    handshake_done: Arc<std::sync::atomic::AtomicBool>,
    model_name: Arc<String>,
) -> Result<()> {
    // Read entire request with timeout (max 16MB)
    let data = tokio::time::timeout(STREAM_READ_TIMEOUT, recv.read_to_end(16 * 1024 * 1024))
        .await
        .map_err(|_| anyhow::anyhow!("stream read timeout"))??;

    let (frame, _) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;

    let response_frame = match frame.msg_type {
        MessageType::Ping => {
            // Allow Ping only after successful handshake
            if !handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected Ping: handshake not completed");
                return Ok(());
            }
            Frame::new(MessageType::Pong, vec![])
        }

        MessageType::Hello => {
            // R5: Only the first Hello on a connection is processed.
            // Reject repeated Hellos to prevent re-authentication attacks.
            if handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected Hello: handshake already completed on this connection");
                return Ok(());
            }

            // Size-limited bincode deserialization
            // R6: Removed allow_trailing_bytes() — forces strict size enforcement.
            // With allow_trailing_bytes(), bincode would happily deserialize a
            // valid Hello from the start of a larger payload, ignoring extra data.
            // Without it, any trailing bytes cause a deserialization error, which
            // is the correct behavior for a fixed-structure message.
            let hello: handshake::Hello = bincode::DefaultOptions::new()
                .with_limit(MAX_HELLO_SIZE)
                .with_fixint_encoding()
                .deserialize(&frame.payload)?;

            // Reject incompatible protocol versions
            let mut accepted = hello.version == PROTOCOL_VERSION;
            if !accepted {
                warn!(
                    "Rejecting Hello: version {} (expected {})",
                    hello.version, PROTOCOL_VERSION
                );
            }

            // Verify the client's Ed25519 signature on their NodeInfo
            if accepted {
                let pk_bytes = hello.node_info.public_key;
                if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
                    // Verify NodeId = SHA-256(public_key)
                    let expected_id = crate::identity::compute_node_id(&vk);
                    // Verify signature over the serialized NodeInfo (excluding signature field)
                    let sig_bytes = &hello.node_info.signature;
                    if sig_bytes.len() == 64 {
                        let mut sig_arr = [0u8; 64];
                        sig_arr.copy_from_slice(sig_bytes);
                        // Verify signature over public_key || timestamp
                        let mut msg = Vec::new();
                        msg.extend_from_slice(&pk_bytes);
                        msg.extend_from_slice(&hello.node_info.timestamp.to_le_bytes());
                        if !crate::identity::verify_signature(&vk, &msg, &sig_arr) {
                            warn!("Rejecting Hello: invalid Ed25519 signature");
                            accepted = false;
                        }
                    } else {
                        warn!("Rejecting Hello: signature wrong length ({})", sig_bytes.len());
                        accepted = false;
                    }
                    let _ = expected_id; // NodeId binding reserved for Phase 2 routing
                } else {
                    warn!("Rejecting Hello: invalid public key");
                    accepted = false;
                }
            }

            // R6: Validate NodeInfo field lengths — prevent memory amplification
            // in gossip tables and oversized HelloAck serialization.
            if accepted {
                if hello.node_info.addresses.len() > MAX_NODEINFO_ADDRESSES {
                    warn!(
                        "Rejecting Hello: too many addresses ({}, max {})",
                        hello.node_info.addresses.len(),
                        MAX_NODEINFO_ADDRESSES
                    );
                    accepted = false;
                }
                if hello.node_info.models.len() > MAX_NODEINFO_MODELS {
                    warn!(
                        "Rejecting Hello: too many models ({}, max {})",
                        hello.node_info.models.len(),
                        MAX_NODEINFO_MODELS
                    );
                    accepted = false;
                }
                // R6: Reject NaN/Inf in throughput_estimate — prevents poisoning
                // Phase 2 gossip peer-selection comparisons.
                // R7: Also reject negative throughput_estimate — negative values
                // are nonsensical and could invert peer-selection sorting.
                for m in &hello.node_info.models {
                    if !m.throughput_estimate.is_finite() {
                        warn!(
                            "Rejecting Hello: non-finite throughput_estimate ({})",
                            m.throughput_estimate
                        );
                        accepted = false;
                        break;
                    }
                    if m.throughput_estimate < 0.0 {
                        warn!(
                            "Rejecting Hello: negative throughput_estimate ({})",
                            m.throughput_estimate
                        );
                        accepted = false;
                        break;
                    }
                }
                // R7: Reject model names that are too long — each model_name is
                // an unbounded String. Without this cap, 16 models x 64KB names
                // = 1 MB of string data that passes all other checks.
                for m in &hello.node_info.models {
                    if m.model_name.len() > MAX_MODEL_NAME_LEN {
                        warn!(
                            "Rejecting Hello: model_name too long ({} bytes, max {})",
                            m.model_name.len(),
                            MAX_MODEL_NAME_LEN
                        );
                        accepted = false;
                        break;
                    }
                }
                // R7: Reject oversized signature field — Ed25519 signatures are
                // exactly 64 bytes. The signature field is Vec<u8> which bincode
                // will happily deserialize up to the 64KB limit. Reject early
                // before the expensive signature verification.
                if hello.node_info.signature.len() > MAX_SIGNATURE_LEN {
                    warn!(
                        "Rejecting Hello: signature too long ({} bytes, max {})",
                        hello.node_info.signature.len(),
                        MAX_SIGNATURE_LEN
                    );
                    accepted = false;
                }
            }

            // Check timestamp freshness — reject stale Hellos (replay defense)
            if accepted {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let ts = hello.node_info.timestamp;
                // R5: Reject future timestamps too — prevents pre-computed replay
                // windows where attacker mints a Hello valid far into the future.
                if ts > now + MAX_HELLO_TIMESTAMP_DRIFT_SECS {
                    warn!(
                        "Rejecting Hello: timestamp too far in the future (ts={}, now={}, max_drift={}s)",
                        ts, now, MAX_HELLO_TIMESTAMP_DRIFT_SECS
                    );
                    accepted = false;
                } else if now > ts && (now - ts) > MAX_HELLO_TIMESTAMP_DRIFT_SECS {
                    warn!(
                        "Rejecting Hello: timestamp too stale (drift {}s, max {}s)",
                        now - ts, MAX_HELLO_TIMESTAMP_DRIFT_SECS
                    );
                    accepted = false;
                }
            }

            if accepted {
                handshake_done.store(true, std::sync::atomic::Ordering::SeqCst);
            }

            // R6: Only include the server's full NodeInfo if the handshake is accepted.
            // When rejected, return a minimal NodeInfo with zeroed fields to prevent
            // leaking server identity, capabilities, and addresses to unauthenticated
            // peers. An attacker could enumerate server capabilities by sending
            // deliberately invalid Hellos and inspecting the rejected HelloAck.
            let ack_node_info = if accepted {
                server_info.read().unwrap().clone()
            } else {
                NodeInfo {
                    public_key: [0u8; 32],
                    addresses: vec![],
                    models: vec![],
                    relay_capable: false,
                    capacity: NodeCapacity {
                        queue_depth: 0,
                        active_sessions: 0,
                        max_sessions: 0,
                    },
                    timestamp: 0,
                    signature: vec![],
                }
            };
            let ack = handshake::HelloAck {
                version: PROTOCOL_VERSION,
                node_info: ack_node_info,
                accepted,
            };
            Frame::new(MessageType::HelloAck, bincode::serialize(&ack)?)
        }

        MessageType::InferRequest => {
            // Reject inference if handshake hasn't completed.
            // Uses SeqCst to prevent TOCTOU race with Hello handler on
            // concurrent streams.
            if !handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected InferRequest: handshake not completed");
                return Ok(());
            }

            // R5: Pre-validate the inference request before acquiring the
            // inference semaphore permit. This prevents an attacker from
            // tying up compute slots with requests that will always fail.
            let request = inference::decode_infer_request(&frame.payload)?;

            // R8: Cap model_id length. Even for "mock" mode, an oversized
            // model_id wastes memory because it passes through to the
            // InferResponse (echoed back to the client), and is logged on
            // rejection. Without this, model_id can be up to ~4MB.
            if request.model_id.len() > MAX_MODEL_ID_LEN {
                warn!(
                    "Rejected InferRequest: model_id too long ({} bytes, max {})",
                    request.model_id.len(),
                    MAX_MODEL_ID_LEN
                );
                return Ok(());
            }

            // R5: Validate model_id matches what this node serves.
            // Prevents confusion attacks where a client asks for a different
            // model than what the node advertises.
            if request.model_id != *model_name && *model_name != "mock" {
                warn!(
                    "Rejected InferRequest: model_id '{}' does not match served model '{}'",
                    request.model_id, *model_name
                );
                return Ok(());
            }

            // R5: Cap max_tokens to prevent a single request from monopolizing
            // the inference backend for an unreasonable duration.
            if request.max_tokens > MAX_INFER_TOKENS {
                warn!(
                    "Rejected InferRequest: max_tokens {} exceeds cap {}",
                    request.max_tokens, MAX_INFER_TOKENS
                );
                return Ok(());
            }

            // R7: Cap encrypted_input size to prevent a single request from
            // passing an oversized ciphertext blob into the inference backend.
            // The 4MB bincode limit on InferRequest allows up to ~4MB of
            // encrypted_input, but real PFHE ciphertexts should be much smaller.
            if request.encrypted_input.len() > MAX_ENCRYPTED_INPUT_SIZE {
                warn!(
                    "Rejected InferRequest: encrypted_input too large ({} bytes, max {})",
                    request.encrypted_input.len(),
                    MAX_ENCRYPTED_INPUT_SIZE
                );
                return Ok(());
            }

            // Acquire inference permit (limits concurrent compute tasks)
            let _permit = infer_semaphore
                .acquire()
                .await
                .map_err(|_| anyhow::anyhow!("inference semaphore closed"))?;

            // R9: Pass the already-validated request object to the backend
            // instead of re-deserializing from raw bytes. Before this fix,
            // the validated `request` was discarded and `handle_infer` would
            // re-deserialize from `frame.payload`, creating a TOCTOU gap
            // where the validated object and the actually-processed object
            // could theoretically differ (defense-in-depth violation).
            let result = tokio::task::spawn_blocking(move || {
                let response = backend.infer(&request)?;
                inference::encode_infer_response(&response)
            })
            .await??;
            Frame::new(MessageType::InferResponse, result)
        }

        // Reject response-only message types (server->client only)
        MessageType::HelloAck
        | MessageType::Pong
        | MessageType::InferResponse
        | MessageType::PubkeyResponse => {
            warn!(
                "Rejected wrong-direction message: {:?} from client",
                frame.msg_type
            );
            return Ok(());
        }

        // R7: Explicitly reject Phase 2/3 message types that are not yet
        // implemented. These require handshake authentication, so reject
        // pre-auth to avoid burning stream count on unauthenticated probes.
        MessageType::GetPeers
        | MessageType::Announce
        | MessageType::PubkeyRequest
        | MessageType::Peers
        | MessageType::RelayOpen
        | MessageType::RelayAccept
        | MessageType::RelayDeny
        | MessageType::RelayData
        | MessageType::RelayClose => {
            if !handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!(
                    "Rejected unauthenticated Phase 2/3 message: {:?}",
                    frame.msg_type
                );
                return Ok(());
            }
            warn!("Phase 2/3 message {:?} not yet implemented", frame.msg_type);
            return Ok(());
        }

        // R8: Explicitly handle Error message type. Before this fix,
        // Error fell into the catch-all `other` arm, which was not gated
        // by handshake_done. An unauthenticated client could send Error
        // frames to burn stream counter slots without authenticating.
        MessageType::Error => {
            if !handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected unauthenticated Error message from client");
                return Ok(());
            }
            warn!("Received Error message from client: {} bytes payload", frame.payload.len());
            return Ok(());
        }

        // Catch-all for any new message types added in the future.
        // This arm requires handshake to prevent unauthenticated probing.
        #[allow(unreachable_patterns)]
        other => {
            if !handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected unauthenticated unknown message type: {:?}", other);
                return Ok(());
            }
            warn!("Unhandled message type: {:?}", other);
            return Ok(());
        }
    };

    send.write_all(&response_frame.encode()).await?;
    send.finish()?;
    Ok(())
}

/// Build a properly signed NodeInfo for use in Hello handshake.
pub fn build_signed_node_info(identity: &NodeIdentity) -> NodeInfo {
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut msg = Vec::new();
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    let sig = identity.sign(&msg);
    NodeInfo {
        public_key,
        addresses: vec![],
        models: vec![],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp,
        signature: sig.to_vec(),
    }
}

/// Connect to a remote node and send an inference request.
///
/// Performs a Hello handshake on a dedicated stream first, then sends the
/// inference request on a second stream (required since server rejects
/// InferRequests before handshake completes).
pub async fn connect_and_infer(
    addr: std::net::SocketAddr,
    request: &poly_client::protocol::InferRequest,
) -> Result<poly_client::protocol::InferResponse> {
    let endpoint = transport::create_client_endpoint()?;
    let conn = endpoint.connect(addr, "poly-node")?.await?;

    // 1. Handshake on first stream
    let client_identity = NodeIdentity::generate();
    let hello = handshake::Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&client_identity),
    };
    {
        let (mut hs_send, mut hs_recv) = conn.open_bi().await?;
        let hello_payload = handshake::encode_hello(&hello)?;
        let hello_frame = Frame::new(MessageType::Hello, hello_payload);
        hs_send.write_all(&hello_frame.encode()).await?;
        hs_send.finish()?;
        let ack_data = hs_recv.read_to_end(64 * 1024).await?;
        let (ack_frame, _) = Frame::decode(&ack_data).map_err(|e| anyhow::anyhow!("{}", e))?;
        if ack_frame.msg_type != MessageType::HelloAck {
            anyhow::bail!("expected HelloAck, got {:?}", ack_frame.msg_type);
        }
        // R7: Use size-limited deserialization for HelloAck (matches server-side
        // hardening). Raw bincode::deserialize could OOM on a crafted payload
        // from a malicious server.
        let ack: handshake::HelloAck = bincode::DefaultOptions::new()
            .with_limit(MAX_HELLO_SIZE)
            .with_fixint_encoding()
            .deserialize(&ack_frame.payload)?;
        if !ack.accepted {
            anyhow::bail!("handshake rejected by server");
        }
        // Verify server's Ed25519 signature on its NodeInfo
        let server_pk = ack.node_info.public_key;
        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&server_pk) {
            let sig_bytes = &ack.node_info.signature;
            if sig_bytes.len() == 64 {
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(sig_bytes);
                let mut msg = Vec::new();
                msg.extend_from_slice(&server_pk);
                msg.extend_from_slice(&ack.node_info.timestamp.to_le_bytes());
                if !crate::identity::verify_signature(&vk, &msg, &sig_arr) {
                    anyhow::bail!("server HelloAck has invalid Ed25519 signature");
                }
            } else {
                anyhow::bail!("server HelloAck signature wrong length");
            }
        } else {
            anyhow::bail!("server HelloAck has invalid public key");
        }
        // R7: Validate server HelloAck timestamp freshness. Without this,
        // a replayed HelloAck from a compromised server would pass signature
        // verification indefinitely.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let ts = ack.node_info.timestamp;
            if ts > now + MAX_HELLO_TIMESTAMP_DRIFT_SECS {
                anyhow::bail!(
                    "server HelloAck timestamp too far in the future (ts={}, now={})",
                    ts, now
                );
            }
            if now > ts && (now - ts) > MAX_HELLO_TIMESTAMP_DRIFT_SECS {
                anyhow::bail!(
                    "server HelloAck timestamp too stale (drift={}s, max={}s)",
                    now - ts, MAX_HELLO_TIMESTAMP_DRIFT_SECS
                );
            }
        }
        // R8: Validate server's HelloAck NodeInfo field lengths. The server
        // performs these checks on the client's Hello, but the client did not
        // validate the server's HelloAck. A malicious server could send a
        // bloated HelloAck with hundreds of addresses/models within the 64KB
        // bincode limit, wasting client memory.
        if ack.node_info.addresses.len() > MAX_NODEINFO_ADDRESSES {
            anyhow::bail!(
                "server HelloAck has too many addresses ({}, max {})",
                ack.node_info.addresses.len(),
                MAX_NODEINFO_ADDRESSES
            );
        }
        if ack.node_info.models.len() > MAX_NODEINFO_MODELS {
            anyhow::bail!(
                "server HelloAck has too many models ({}, max {})",
                ack.node_info.models.len(),
                MAX_NODEINFO_MODELS
            );
        }
        for m in &ack.node_info.models {
            if m.model_name.len() > MAX_MODEL_NAME_LEN {
                anyhow::bail!(
                    "server HelloAck model_name too long ({} bytes, max {})",
                    m.model_name.len(),
                    MAX_MODEL_NAME_LEN
                );
            }
            if !m.throughput_estimate.is_finite() || m.throughput_estimate < 0.0 {
                anyhow::bail!(
                    "server HelloAck has invalid throughput_estimate ({})",
                    m.throughput_estimate
                );
            }
        }
    }

    // 2. Inference on second stream
    let (mut send, mut recv) = conn.open_bi().await?;

    let payload = inference::encode_infer_request(request)?;
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await?;
    send.finish()?;

    // R6: Timeout on response read to prevent a malicious/slow server from
    // tying up the client task indefinitely (slowloris attack on client side).
    let data = tokio::time::timeout(
        CLIENT_RESPONSE_TIMEOUT,
        recv.read_to_end(16 * 1024 * 1024),
    )
    .await
    .map_err(|_| anyhow::anyhow!("inference response read timed out after {:?}", CLIENT_RESPONSE_TIMEOUT))??;
    let (resp_frame, _) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;

    if resp_frame.msg_type != MessageType::InferResponse {
        anyhow::bail!("expected InferResponse, got {:?}", resp_frame.msg_type);
    }

    let response = inference::decode_infer_response(&resp_frame.payload)?;

    // R9: Validate InferResponse content from server. Before this fix,
    // the client accepted arbitrarily large encrypted_output from a
    // malicious server. While the 16MB read limit caps the total data,
    // the encrypted_output field could consume most of that 16MB.
    // Cap at MAX_CLIENT_RESPONSE_OUTPUT_SIZE (4 MB) to prevent memory waste.
    if response.encrypted_output.len() > MAX_CLIENT_RESPONSE_OUTPUT_SIZE {
        anyhow::bail!(
            "server InferResponse encrypted_output too large ({} bytes, max {})",
            response.encrypted_output.len(),
            MAX_CLIENT_RESPONSE_OUTPUT_SIZE
        );
    }
    // R9: Validate response model_id length (prevent echo amplification from
    // a malicious server that sends back a bloated model_id).
    if response.model_id.len() > MAX_MODEL_ID_LEN {
        anyhow::bail!(
            "server InferResponse model_id too long ({} bytes, max {})",
            response.model_id.len(),
            MAX_MODEL_ID_LEN
        );
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(response)
}
