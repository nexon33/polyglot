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
    fn own_node_info(&self) -> NodeInfo {
        NodeInfo {
            public_key: self.identity.public_key_bytes(),
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
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            signature: vec![0; 64], // TODO: sign in Phase 2
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
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, backend, infer_sem, info).await {
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
            let accepted = hello.version == PROTOCOL_VERSION;
            if !accepted {
                warn!(
                    "Rejecting Hello: version {} (expected {})",
                    hello.version, PROTOCOL_VERSION
                );
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

/// Connect to a remote node and send an inference request.
pub async fn connect_and_infer(
    addr: std::net::SocketAddr,
    request: &poly_client::protocol::InferRequest,
) -> Result<poly_client::protocol::InferResponse> {
    let endpoint = transport::create_client_endpoint()?;
    let conn = endpoint.connect(addr, "poly-node")?.await?;

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
