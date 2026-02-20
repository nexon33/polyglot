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
//! - R10: NodeInfo signature covers ALL fields (addresses, models, relay, capacity) not just pubkey||ts
//! - R10: RwLock poisoning handled gracefully (no server panic on poisoned lock)
//! - R10: Client-side model_id binding (response model_id must match request model_id)
//! - R10: Server HelloAck uses encode_hello_ack() (consistent encode/decode path)
//! - R10: handle_infer() deprecated (dead code that bypasses all validation)
//! - R10: build_signed_node_info_with() helper for tests with custom signed NodeInfo
//! - R11: NodeInfo signing includes domain separation tag (prevents cross-context replay)
//! - R11: NodeInfo signing includes addresses.len() count (prevents address list ambiguity)
//! - R11: Ping payload size validated (MAX_PING_PAYLOAD=128, prevents 16MB memory waste)
//! - R12: Trailing frame data rejected (bytes_consumed must equal data.len())
//! - R12: model_name length validated in PolyNode::new() (prevents config-driven amplification)
//! - R12: Frame::new_checked() validates payload at construction (fail-fast before encode)
//! - R12: Client-side trailing frame data rejected for HelloAck and InferResponse
//! - R12: Client-side HelloAck frame type validated before deserialization (not after)
//! - R13: bootstrap_addrs validated (max 64, no self-connection)
//! - R13: max_sessions capped at MAX_SESSIONS_LIMIT (1024)
//! - R13: InferRequest.temperature capped at MAX_TEMPERATURE (10_000)
//! - R13: InferRequest.encrypted_input must be non-empty (prevents backend deserialization failure)
//! - R13: Zero public key ([0u8; 32]) explicitly rejected in Hello validation
//! - R13: Duplicate addresses in NodeInfo rejected (prevents gossip amplification)
//! - R13: Client-side HelloAck version validation (must match PROTOCOL_VERSION)
//! - R15: InferRequest.model_id empty documented as audit finding (backward-compat with R8 audit)
//! - R15: InferRequest.model_id control characters documented as audit finding (Phase 2)
//! - R15: InferRequest.max_tokens == 0 documented as audit finding (wastes compute but backward-compatible)
//! - R15: NodeInfo.timestamp must be > 0 (epoch floor defense-in-depth)
//! - R15: NodeInfo addresses must not be multicast (QUIC requires unicast)
//! - R15: NodeInfo addresses must not be broadcast (255.255.255.255)
//! - R15: NodeInfo addresses must not be link-local (169.254.x.x, fe80::/10)
//! - R15: Duplicate model names in NodeInfo rejected (prevents gossip inflation)
//! - R15: Config listen_addr port must not be 0 (prevents unreachable nodes)
//! - R15: Client-side HelloAck throughput -0.0 rejection (matches R14 server-side)

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

/// R11: Maximum allowed payload for Ping messages (128 bytes).
/// Ping is a health-check with no meaningful payload. Before R11, the server
/// read up to 16 MB for every message type including Ping, and then discarded
/// the payload entirely. An authenticated attacker could send 16 MB Ping
/// frames to waste server memory (16 MB allocation per stream, up to 256
/// streams per connection). Now Ping payloads > 128 bytes are rejected.
pub const MAX_PING_PAYLOAD: usize = 128;

/// R13: Maximum allowed number of bootstrap addresses in NodeConfig.
/// Prevents resource exhaustion from excessive connection attempts at startup.
const MAX_BOOTSTRAP_ADDRS: usize = 64;

/// R13: Maximum allowed max_sessions in NodeConfig.
/// Without an upper bound, max_sessions=u32::MAX creates semaphores with
/// billions of permits, effectively disabling all rate limiting defenses.
const MAX_SESSIONS_LIMIT: u32 = 1024;

/// R13: Maximum allowed temperature in InferRequest (temperature x 1000).
/// 10_000 represents T=10.0, far above any practical temperature setting.
/// Values above this cause numerical instability in softmax and produce
/// degenerate output. Without this cap, u32::MAX (T=~4.3M) passes through.
pub const MAX_TEMPERATURE: u32 = 10_000;

/// R14: Maximum allowed queue_depth in a Hello NodeInfo capacity.
/// A peer claiming queue_depth > 1M is clearly lying or misconfigured.
/// This prevents gossip table pollution with unrealistic load data.
const MAX_QUEUE_DEPTH: u32 = 1_000_000;

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
        // R13: Validate max_sessions <= MAX_SESSIONS_LIMIT. Without an upper
        // bound, max_sessions=u32::MAX creates semaphores with billions of
        // permits, effectively disabling all connection and inference rate
        // limiting defenses.
        if config.max_sessions > MAX_SESSIONS_LIMIT {
            anyhow::bail!(
                "max_sessions too large: {} (max {})",
                config.max_sessions,
                MAX_SESSIONS_LIMIT
            );
        }
        // R12: Validate model_name length. The model_name is embedded in every
        // NodeInfo (own_node_info) and broadcast in HelloAck to every connecting
        // peer. Without this check, a multi-MB model_name in the config would be
        // amplified to every connection, wasting bandwidth and memory.
        if config.model_name.len() > MAX_MODEL_NAME_LEN {
            anyhow::bail!(
                "model_name too long: {} bytes (max {})",
                config.model_name.len(),
                MAX_MODEL_NAME_LEN
            );
        }
        // R13: Validate bootstrap_addrs length and content.
        // Too many bootstrap addresses waste resources on connection attempts.
        // Self-connection (listen_addr in bootstrap) creates a loop.
        if config.bootstrap_addrs.len() > MAX_BOOTSTRAP_ADDRS {
            anyhow::bail!(
                "too many bootstrap addresses: {} (max {})",
                config.bootstrap_addrs.len(),
                MAX_BOOTSTRAP_ADDRS
            );
        }
        if config.bootstrap_addrs.contains(&config.listen_addr) {
            anyhow::bail!(
                "bootstrap_addrs must not contain self (listen_addr={})",
                config.listen_addr
            );
        }
        // R14: Reject duplicate bootstrap addresses. An operator could
        // accidentally list the same peer twice (e.g., via automation),
        // causing double connection attempts at startup.
        {
            let mut unique_bootstrap = std::collections::HashSet::new();
            for a in &config.bootstrap_addrs {
                if !unique_bootstrap.insert(a) {
                    anyhow::bail!(
                        "duplicate bootstrap address: {}",
                        a
                    );
                }
            }
        }
        // R14: Reject model_name containing control characters (0x00-0x1F).
        // Control characters in model_name can:
        // - Inject newlines into log output (log forging)
        // - Inject ANSI escape sequences into terminal output
        // - Contain null bytes that truncate C strings in FFI contexts
        if config.model_name.bytes().any(|b| b < 0x20) {
            anyhow::bail!(
                "model_name contains control characters (bytes < 0x20)"
            );
        }
        // R15: Reject listen_addr with port 0. Port 0 means "OS picks a random
        // port", which makes the node unreachable by bootstrap peers (they don't
        // know which port was assigned). While useful for tests, production nodes
        // must specify an explicit port. Tests should use random ports obtained
        // from UdpSocket::bind("127.0.0.1:0") and read back the assigned port.
        if config.listen_addr.port() == 0 {
            anyhow::bail!(
                "listen_addr port must not be 0 (got {})",
                config.listen_addr
            );
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
    /// R10: The NodeInfo is signed with this node's Ed25519 key over ALL fields:
    /// signature = Sign(public_key || timestamp || SHA-256(addresses || models || relay || capacity)).
    ///
    /// Before R10, only `public_key || timestamp` was signed, leaving
    /// addresses, models, relay_capable, and capacity unprotected.
    fn own_node_info(&self) -> NodeInfo {
        let public_key = self.identity.public_key_bytes();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build the NodeInfo first (without signature)
        let mut info = NodeInfo {
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
            signature: vec![],
        };

        // R10: Sign ALL fields via canonical signing message
        let msg = crate::protocol::wire::compute_nodeinfo_signing_message(&info);
        let sig = self.identity.sign(&msg);
        info.signature = sig.to_vec();
        info
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
                    // R10: Handle poisoned write lock -- recover and replace data
                    match server_info.write() {
                        Ok(mut guard) => { *guard = new_info; }
                        Err(poisoned) => {
                            warn!("server_info RwLock poisoned during regeneration, recovering");
                            *poisoned.into_inner() = new_info;
                        }
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

    // R14: Track whether ANY Hello has been attempted on this connection
    // (regardless of success or failure). Before R14, only handshake_done
    // blocked re-auth (after success). A rejected Hello did not set any
    // flag, allowing the attacker to retry Hello up to MAX_PRE_HANDSHAKE_STREAMS
    // times, each costing deserialization + Ed25519 verification. Now,
    // once the first Hello is processed (accepted OR rejected), subsequent
    // Hellos are silently dropped without cryptographic work.
    let handshake_attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));

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
        let ha = handshake_attempted.clone();
        let model = model_name.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_stream(send, recv, backend, infer_sem, info, hs, ha, model).await
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
    handshake_attempted: Arc<std::sync::atomic::AtomicBool>,
    model_name: Arc<String>,
) -> Result<()> {
    // Read entire request with timeout (max 16MB)
    let data = tokio::time::timeout(STREAM_READ_TIMEOUT, recv.read_to_end(16 * 1024 * 1024))
        .await
        .map_err(|_| anyhow::anyhow!("stream read timeout"))??;

    // R12: Reject frames with trailing data. Before R12, the bytes_consumed
    // value from Frame::decode was silently discarded. An attacker could append
    // arbitrary data after a valid frame (up to 16 MB). While the extra data
    // is not processed, it wastes server memory (the full 16 MB is read into
    // `data` before the frame is decoded) and could be used for protocol
    // confusion attacks where the trailing data resembles a second frame.
    let (frame, consumed) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;
    if consumed != data.len() {
        warn!(
            "Rejected frame with {} trailing bytes (frame consumed {}, total {})",
            data.len() - consumed,
            consumed,
            data.len()
        );
        return Ok(());
    }

    let response_frame = match frame.msg_type {
        MessageType::Ping => {
            // Allow Ping only after successful handshake
            if !handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected Ping: handshake not completed");
                return Ok(());
            }
            // R11: Reject Ping with oversized payload. Ping is a health-check
            // that requires no payload. Before R11, the payload was silently
            // discarded regardless of size, allowing an authenticated attacker
            // to waste 16 MB of server memory per Ping stream.
            if frame.payload.len() > MAX_PING_PAYLOAD {
                warn!(
                    "Rejected Ping: payload too large ({} bytes, max {})",
                    frame.payload.len(),
                    MAX_PING_PAYLOAD
                );
                return Ok(());
            }
            // R14: Echo the Ping payload as a nonce in the Pong response.
            // Before R14, the Pong was always empty, so the client could not
            // correlate a Pong to a specific Ping (no request-response binding).
            // This enables unsolicited Pong injection where a MITM replaces
            // the real Pong with a forged one. Echoing the Ping payload allows
            // the client to verify the Pong corresponds to its Ping.
            Frame::new(MessageType::Pong, frame.payload.clone())
        }

        MessageType::Hello => {
            // R5: Only the first Hello on a connection is processed.
            // Reject repeated Hellos to prevent re-authentication attacks.
            if handshake_done.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected Hello: handshake already completed on this connection");
                return Ok(());
            }
            // R14: Block repeated Hello attempts after the first one (even
            // if the first Hello was rejected). Before R14, only handshake_done
            // blocked re-auth (after success). A rejected Hello did not set
            // any flag, allowing retry up to MAX_PRE_HANDSHAKE_STREAMS times,
            // each costing deserialization + Ed25519 verification.
            if handshake_attempted.swap(true, std::sync::atomic::Ordering::SeqCst) {
                warn!("Rejected Hello: handshake already attempted on this connection");
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
                // R13: Reject all-zeros public key (Ed25519 identity point).
                // The all-zeros key passes VerifyingKey::from_bytes() but is a
                // well-known weak key. Multiple peers claiming this key would
                // share the same NodeId, and signatures against it have special
                // properties that undermine security assumptions.
                if pk_bytes == [0u8; 32] {
                    warn!("Rejecting Hello: zero public key (identity point)");
                    accepted = false;
                } else if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
                    // Verify NodeId = SHA-256(public_key)
                    let expected_id = crate::identity::compute_node_id(&vk);
                    // Verify signature over the serialized NodeInfo (excluding signature field)
                    let sig_bytes = &hello.node_info.signature;
                    if sig_bytes.len() == 64 {
                        let mut sig_arr = [0u8; 64];
                        sig_arr.copy_from_slice(sig_bytes);
                        // R10: Verify signature over ALL NodeInfo fields
                        // (public_key || timestamp || SHA-256(addresses || models || relay || capacity))
                        let msg = crate::protocol::wire::compute_nodeinfo_signing_message(&hello.node_info);
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
                    // R14: Reject negative zero throughput_estimate. IEEE 754
                    // defines -0.0 as equal to 0.0 (so the < 0.0 check above
                    // does not catch it), but -0.0 has a different bit pattern
                    // and can cause inconsistent hashing/comparison in gossip
                    // tables. Detect via is_sign_negative() when value is 0.0.
                    if m.throughput_estimate == 0.0 && m.throughput_estimate.is_sign_negative() {
                        warn!(
                            "Rejecting Hello: negative-zero throughput_estimate"
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
                    // R14: Reject model names containing control characters
                    // (bytes < 0x20). Control characters can inject newlines
                    // into log output, ANSI escape sequences into terminals,
                    // or null bytes that truncate C strings in FFI contexts.
                    if m.model_name.bytes().any(|b| b < 0x20) {
                        warn!(
                            "Rejecting Hello: model_name contains control characters"
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
                // R13: Reject duplicate addresses — an attacker could include
                // the same address 16 times to amplify their gossip routing
                // weight without providing distinct endpoints.
                if accepted {
                    let mut unique_addrs = std::collections::HashSet::new();
                    for a in &hello.node_info.addresses {
                        if !unique_addrs.insert(a) {
                            warn!(
                                "Rejecting Hello: duplicate address {}",
                                a
                            );
                            accepted = false;
                            break;
                        }
                    }
                }
                // R14: Reject addresses with unspecified IP (0.0.0.0 or [::])
                // or port 0. These are non-routable and waste gossip table entries.
                // R15: Also reject multicast (224.0.0.0/4, ff00::/8), broadcast
                // (255.255.255.255), and link-local (169.254.0.0/16, fe80::/10)
                // addresses. QUIC requires unicast endpoints; multicast addresses
                // are unreachable and pollute gossip tables. Link-local addresses
                // require scope IDs and are meaningless in cross-network gossip.
                if accepted {
                    for a in &hello.node_info.addresses {
                        if a.ip().is_unspecified() || a.port() == 0 {
                            warn!(
                                "Rejecting Hello: non-routable address {} (unspecified IP or port 0)",
                                a
                            );
                            accepted = false;
                            break;
                        }
                        if a.ip().is_multicast() {
                            warn!(
                                "Rejecting Hello: multicast address {} (QUIC requires unicast)",
                                a
                            );
                            accepted = false;
                            break;
                        }
                        // R15: Reject broadcast and link-local addresses
                        match a.ip() {
                            std::net::IpAddr::V4(v4) => {
                                if v4.is_broadcast() {
                                    warn!(
                                        "Rejecting Hello: broadcast address {}",
                                        a
                                    );
                                    accepted = false;
                                    break;
                                }
                                if v4.is_link_local() {
                                    warn!(
                                        "Rejecting Hello: link-local address {} (unreachable cross-network)",
                                        a
                                    );
                                    accepted = false;
                                    break;
                                }
                            }
                            std::net::IpAddr::V6(v6) => {
                                // fe80::/10 (link-local)
                                let segments = v6.segments();
                                if (segments[0] & 0xffc0) == 0xfe80 {
                                    warn!(
                                        "Rejecting Hello: IPv6 link-local address {} (unreachable without scope)",
                                        a
                                    );
                                    accepted = false;
                                    break;
                                }
                            }
                        }
                    }
                }
                // R14: Validate NodeInfo capacity fields.
                // - max_sessions must be >= 1 (a node with 0 max_sessions cannot
                //   serve any requests, wasting gossip table entries)
                // - max_sessions must be <= MAX_SESSIONS_LIMIT (prevents inflated
                //   capacity claims that attract all traffic in gossip load balancing)
                // - active_sessions must be <= max_sessions (logically impossible
                //   to have more active sessions than the maximum)
                // - queue_depth must be <= MAX_QUEUE_DEPTH (prevents absurd claims)
                if accepted {
                    let cap = &hello.node_info.capacity;
                    if cap.max_sessions == 0 {
                        warn!(
                            "Rejecting Hello: max_sessions=0 in NodeInfo capacity"
                        );
                        accepted = false;
                    } else if cap.max_sessions > MAX_SESSIONS_LIMIT {
                        warn!(
                            "Rejecting Hello: max_sessions {} exceeds limit {} in NodeInfo capacity",
                            cap.max_sessions, MAX_SESSIONS_LIMIT
                        );
                        accepted = false;
                    } else if cap.active_sessions > cap.max_sessions {
                        warn!(
                            "Rejecting Hello: active_sessions ({}) > max_sessions ({}) in NodeInfo capacity",
                            cap.active_sessions, cap.max_sessions
                        );
                        accepted = false;
                    } else if cap.queue_depth > MAX_QUEUE_DEPTH {
                        warn!(
                            "Rejecting Hello: queue_depth {} exceeds limit {} in NodeInfo capacity",
                            cap.queue_depth, MAX_QUEUE_DEPTH
                        );
                        accepted = false;
                    }
                }
            }

            // R15: Reject duplicate model names. A peer advertising the same
            // model name twice inflates their apparent capability count in
            // Phase 2 gossip load balancing. Each model should be unique.
            if accepted {
                let mut unique_model_names = std::collections::HashSet::new();
                for m in &hello.node_info.models {
                    if !unique_model_names.insert(&m.model_name) {
                        warn!(
                            "Rejecting Hello: duplicate model name '{}'",
                            m.model_name
                        );
                        accepted = false;
                        break;
                    }
                }
            }

            // Check timestamp freshness — reject stale Hellos (replay defense)
            if accepted {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let ts = hello.node_info.timestamp;
                // R15: Reject timestamp == 0 (epoch floor). Timestamp 0 is a
                // sentinel value that should never appear in production. It
                // protects against edge cases where system clock is wrong or
                // timestamp arithmetic underflows.
                if ts == 0 {
                    warn!(
                        "Rejecting Hello: timestamp is zero (epoch floor)"
                    );
                    accepted = false;
                // R5: Reject future timestamps too — prevents pre-computed replay
                // windows where attacker mints a Hello valid far into the future.
                } else if ts > now + MAX_HELLO_TIMESTAMP_DRIFT_SECS {
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
            // R10: Use unwrap_or_else to handle RwLock poisoning gracefully.
            // Before R10, .unwrap() would panic if any previous writer panicked
            // while holding the write lock (e.g., during NodeInfo regeneration).
            // A poisoned lock should not crash the server -- fall back to
            // a minimal NodeInfo so the handshake can still complete.
            let ack_node_info = if accepted {
                match server_info.read() {
                    Ok(guard) => guard.clone(),
                    Err(poisoned) => {
                        // Lock is poisoned but data may still be valid.
                        // Read through the poison to recover the last good value.
                        warn!("server_info RwLock poisoned, recovering data");
                        poisoned.into_inner().clone()
                    }
                }
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
            // R10: Use encode_hello_ack() instead of raw bincode::serialize().
            // Before R10, the server used bincode::serialize() (legacy config)
            // while the client deserialized with DefaultOptions (new config).
            // While these happen to be compatible for fixint encoding, using
            // the same encode/decode path ensures consistency and applies the
            // output size validation added in R9.
            Frame::new(MessageType::HelloAck, handshake::encode_hello_ack(&ack)?)
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

            // R13: Reject empty encrypted_input. An empty Vec<u8> will fail
            // deserialization in the backend (serde_json::from_slice(&[])),
            // producing an error that propagates as a stream failure with no
            // response. This burns inference semaphore permit time and causes
            // the client to hang waiting for a response that never comes.
            // Reject early before acquiring the inference semaphore.
            if request.encrypted_input.is_empty() {
                warn!("Rejected InferRequest: encrypted_input is empty");
                return Ok(());
            }

            // R13: Cap temperature to prevent numerical instability in softmax.
            // temperature is defined as "temperature x 1000" (u32), so u32::MAX
            // represents T=~4.3 million. Anything above MAX_TEMPERATURE (10_000,
            // i.e., T=10.0) is nonsensical and could cause NaN/Inf in real backends.
            if request.temperature > MAX_TEMPERATURE {
                warn!(
                    "Rejected InferRequest: temperature {} exceeds cap {}",
                    request.temperature, MAX_TEMPERATURE
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
///
/// R10: Now signs ALL fields via compute_nodeinfo_signing_message(),
/// not just public_key || timestamp.
pub fn build_signed_node_info(identity: &NodeIdentity) -> NodeInfo {
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut info = NodeInfo {
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
        signature: vec![],
    };

    // R10: Sign ALL fields
    let msg = crate::protocol::wire::compute_nodeinfo_signing_message(&info);
    let sig = identity.sign(&msg);
    info.signature = sig.to_vec();
    info
}

/// Build a signed NodeInfo with custom addresses, models, and other fields.
///
/// R10: Useful for tests that need to create NodeInfo with specific content
/// while still having a valid signature covering all fields.
pub fn build_signed_node_info_with(
    identity: &NodeIdentity,
    addresses: Vec<std::net::SocketAddr>,
    models: Vec<ModelCapability>,
    relay_capable: bool,
    capacity: NodeCapacity,
) -> NodeInfo {
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut info = NodeInfo {
        public_key,
        addresses,
        models,
        relay_capable,
        capacity,
        timestamp,
        signature: vec![],
    };

    let msg = crate::protocol::wire::compute_nodeinfo_signing_message(&info);
    let sig = identity.sign(&msg);
    info.signature = sig.to_vec();
    info
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
        let (ack_frame, ack_consumed) = Frame::decode(&ack_data).map_err(|e| anyhow::anyhow!("{}", e))?;
        // R12: Reject HelloAck frames with trailing data. A malicious server
        // could append extra data after a valid HelloAck frame. While the extra
        // data is not processed, it could indicate a protocol confusion attack.
        if ack_consumed != ack_data.len() {
            anyhow::bail!(
                "HelloAck frame has {} trailing bytes (consumed {}, total {})",
                ack_data.len() - ack_consumed,
                ack_consumed,
                ack_data.len()
            );
        }
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
        // R13: Validate server HelloAck version matches client's PROTOCOL_VERSION.
        // Before R13, the client only checked ack.accepted but not the version.
        // A malicious server could return version=999 in the HelloAck. The client
        // would proceed with inference using potentially incompatible wire formats.
        if ack.version != PROTOCOL_VERSION {
            anyhow::bail!(
                "server HelloAck version mismatch: expected {}, got {}",
                PROTOCOL_VERSION,
                ack.version
            );
        }
        // Verify server's Ed25519 signature on its NodeInfo
        // R10: Now verifies signature over ALL NodeInfo fields
        let server_pk = ack.node_info.public_key;
        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&server_pk) {
            let sig_bytes = &ack.node_info.signature;
            if sig_bytes.len() == 64 {
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(sig_bytes);
                let msg = crate::protocol::wire::compute_nodeinfo_signing_message(&ack.node_info);
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
            // R15: Also reject -0.0 on client side (matches R14 server-side fix).
            // IEEE 754 -0.0 passes the < 0.0 check above, but has a different
            // bit pattern that can cause inconsistent hashing in gossip tables.
            if m.throughput_estimate == 0.0 && m.throughput_estimate.is_sign_negative() {
                anyhow::bail!(
                    "server HelloAck has negative-zero throughput_estimate"
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
    let (resp_frame, resp_consumed) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;
    // R12: Reject InferResponse frames with trailing data.
    if resp_consumed != data.len() {
        anyhow::bail!(
            "InferResponse frame has {} trailing bytes",
            data.len() - resp_consumed
        );
    }

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
    // R10: Verify response model_id matches the request model_id.
    // Before R10, a malicious server could return a response with a
    // different model_id (e.g., claiming a more expensive model was used
    // for billing purposes, or returning cached results from a different
    // model). The client now rejects mismatched model_ids.
    if response.model_id != request.model_id {
        anyhow::bail!(
            "server InferResponse model_id mismatch: expected '{}', got '{}'",
            request.model_id,
            response.model_id
        );
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(response)
}
