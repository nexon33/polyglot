//! PolyNode — main daemon that ties together QUIC transport, identity,
//! and inference backend.

use std::sync::Arc;

use anyhow::Result;
use log::{info, warn};

use crate::config::NodeConfig;
use crate::identity::NodeIdentity;
use crate::net::transport;
use crate::protocol::wire::{Frame, MessageType};
use crate::protocol::{handshake, inference};

use poly_inference::server::InferenceBackend;

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

    /// Run the node: listen for QUIC connections and handle them.
    pub async fn run(&self) -> Result<()> {
        let endpoint = transport::create_server_endpoint(self.config.listen_addr)?;
        info!(
            "Node {} listening on {}",
            hex::encode(&self.identity.id[..8]),
            self.config.listen_addr
        );

        while let Some(incoming) = endpoint.accept().await {
            let backend = self.backend.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming, backend).await {
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
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, backend).await {
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
) -> Result<()> {
    // Read entire request (max 16MB)
    let data = recv.read_to_end(16 * 1024 * 1024).await?;
    let (frame, _) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;

    let response_frame = match frame.msg_type {
        MessageType::Ping => Frame::new(MessageType::Pong, vec![]),

        MessageType::Hello => {
            let hello: handshake::Hello = bincode::deserialize(&frame.payload)?;
            let ack = handshake::HelloAck {
                version: hello.version,
                node_info: hello.node_info,
                accepted: true,
            };
            Frame::new(MessageType::HelloAck, bincode::serialize(&ack)?)
        }

        MessageType::InferRequest => {
            let payload = frame.payload;
            let result = tokio::task::spawn_blocking(move || {
                inference::handle_infer(&payload, &*backend)
            })
            .await??;
            Frame::new(MessageType::InferResponse, result)
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
