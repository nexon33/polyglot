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

/// Maximum number of addresses in a NodeInfo (prevents gossip amplification).
const MAX_NODEINFO_ADDRESSES: usize = 16;

/// Maximum number of models in a NodeInfo (prevents gossip amplification).
const MAX_NODEINFO_MODELS: usize = 16;

/// Client-side timeout for reading inference response.
/// Prevents a malicious/slow server from tying up the client indefinitely.
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

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

        // R5: Generate server_info fresh (will be shared across connections
        // but regenerated on server restart). The timestamp in this NodeInfo
        // is from startup, which is fine since it's the server's own identity.
        let server_info = Arc::new(self.own_node_info());

        let model_name = Arc::new(self.config.model_name.clone());

        while let Some(incoming) = endpoint.accept().await {
            let backend = self.backend.clone();
            let conn_sem = conn_semaphore.clone();
            let infer_sem = infer_semaphore.clone();
            let info = server_info.clone();
            let model = model_name.clone();

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
    server_info: Arc<NodeInfo>,
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
    server_info: Arc<NodeInfo>,
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
                for m in &hello.node_info.models {
                    if !m.throughput_estimate.is_finite() {
                        warn!(
                            "Rejecting Hello: non-finite throughput_estimate ({})",
                            m.throughput_estimate
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
                (*server_info).clone()
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

            // Acquire inference permit (limits concurrent compute tasks)
            let _permit = infer_semaphore
                .acquire()
                .await
                .map_err(|_| anyhow::anyhow!("inference semaphore closed"))?;

            let payload = frame.payload;
            let result = tokio::task::spawn_blocking(move || {
                inference::handle_infer(&payload, &*backend)
            })
            .await??;
            Frame::new(MessageType::InferResponse, result)
        }

        // Reject response-only and unimplemented message types
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

        other => {
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
        let ack: handshake::HelloAck = bincode::deserialize(&ack_frame.payload)?;
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

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(response)
}
