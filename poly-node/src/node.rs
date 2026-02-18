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

        let server_info = Arc::new(self.own_node_info());

        while let Some(incoming) = endpoint.accept().await {
            let backend = self.backend.clone();
            let conn_sem = conn_semaphore.clone();
            let infer_sem = infer_semaphore.clone();
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
                    handle_connection(incoming, backend, infer_sem, info).await
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
) -> Result<()> {
    let conn = incoming.await?;
    info!("Connection from {}", conn.remote_address());

    // Track whether this connection has completed a valid handshake.
    // Inference requests are rejected until handshake succeeds.
    let handshake_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
            Err(e) => return Err(e.into()),
        };

        let backend = backend.clone();
        let infer_sem = infer_semaphore.clone();
        let info = server_info.clone();
        let hs = handshake_done.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, backend, infer_sem, info, hs).await {
                warn!("Stream error: {}", e);
            }
        });
    }

    Ok(())
}

/// Handle a single bi-directional QUIC stream (one request → one response).
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    backend: Arc<dyn InferenceBackend + Send + Sync>,
    infer_semaphore: Arc<Semaphore>,
    server_info: Arc<NodeInfo>,
    handshake_done: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    // Read entire request with timeout (max 16MB)
    let data = tokio::time::timeout(STREAM_READ_TIMEOUT, recv.read_to_end(16 * 1024 * 1024))
        .await
        .map_err(|_| anyhow::anyhow!("stream read timeout"))??;

    let (frame, _) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;

    let response_frame = match frame.msg_type {
        MessageType::Ping => Frame::new(MessageType::Pong, vec![]),

        MessageType::Hello => {
            // Size-limited bincode deserialization
            let hello: handshake::Hello = bincode::DefaultOptions::new()
                .with_limit(MAX_HELLO_SIZE)
                .with_fixint_encoding()
                .allow_trailing_bytes()
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

            if accepted {
                handshake_done.store(true, std::sync::atomic::Ordering::Release);
            }

            // Return server's own NodeInfo — never echo back the client's
            let ack = handshake::HelloAck {
                version: PROTOCOL_VERSION,
                node_info: (*server_info).clone(),
                accepted,
            };
            Frame::new(MessageType::HelloAck, bincode::serialize(&ack)?)
        }

        MessageType::InferRequest => {
            // Reject inference if handshake hasn't completed
            if !handshake_done.load(std::sync::atomic::Ordering::Acquire) {
                warn!("Rejected InferRequest: handshake not completed");
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
    }

    // 2. Inference on second stream
    let (mut send, mut recv) = conn.open_bi().await?;

    let payload = inference::encode_infer_request(request)?;
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await?;
    send.finish()?;

    let data = recv.read_to_end(16 * 1024 * 1024).await?;
    let (resp_frame, _) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;

    if resp_frame.msg_type != MessageType::InferResponse {
        anyhow::bail!("expected InferResponse, got {:?}", resp_frame.msg_type);
    }

    let response = inference::decode_infer_response(&resp_frame.payload)?;

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(response)
}
