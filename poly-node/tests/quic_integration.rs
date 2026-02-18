//! Phase 1 integration tests: QUIC transport + inference over two localhost nodes.
//!
//! These tests verify that:
//! 1. Two nodes can exchange Hello/HelloAck handshake over QUIC
//! 2. A client can send an inference request and receive a response
//! 3. Ping/Pong health checks work
//! 4. Frame encoding survives the full QUIC round-trip

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::NodeIdentity;
use poly_node::net::transport;
use poly_node::node::{connect_and_infer, PolyNode};
use poly_node::protocol::handshake::{self, PROTOCOL_VERSION, Hello};
use poly_node::protocol::wire::{
    Frame, MessageType,
};

/// Helper: pick a random available port on localhost.
fn localhost_addr() -> SocketAddr {
    // Bind to port 0 and let the OS pick a free port
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// Helper: create a NodeConfig with a free port.
fn test_config() -> NodeConfig {
    NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    }
}


/// Helper: perform a Hello handshake on a QUIC connection.
/// Must be called before sending InferRequest on the same connection.
async fn do_handshake(conn: &quinn::Connection) {
    let client_identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: poly_node::node::build_signed_node_info(&client_identity),
    };
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let hello_payload = handshake::encode_hello(&hello).unwrap();
    let hello_frame = Frame::new(MessageType::Hello, hello_payload);
    send.write_all(&hello_frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();
    assert_eq!(ack_frame.msg_type, MessageType::HelloAck);
    let ack: handshake::HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
    assert!(ack.accepted, "handshake must be accepted");
}

/// Helper: create a mock InferRequest.
fn test_infer_request(tokens: &[u32]) -> InferRequest {
    let ct = MockCiphertext {
        tokens: tokens.to_vec(),
    };
    InferRequest {
        model_id: "test-model".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Ping/Pong over QUIC
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ping_pong_over_quic() {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();

    // Start server in background
    let server_handle = tokio::spawn(async move {
        node.run().await.unwrap();
    });

    // Give server time to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client and send Ping
    let client_endpoint = transport::create_client_endpoint().unwrap();
    let conn = client_endpoint
        .connect(addr, "poly-node")
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let ping_frame = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(1024).await.unwrap();
    let (pong_frame, _) = Frame::decode(&data).unwrap();

    assert_eq!(pong_frame.msg_type, MessageType::Pong);
    assert!(pong_frame.payload.is_empty());

    conn.close(0u32.into(), b"done");
    client_endpoint.wait_idle().await;
    server_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Hello/HelloAck handshake over QUIC
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn hello_handshake_over_quic() {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();

    let server_handle = tokio::spawn(async move {
        node.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: poly_node::node::build_signed_node_info(&client_identity),
    };

    let client_endpoint = transport::create_client_endpoint().unwrap();
    let conn = client_endpoint
        .connect(addr, "poly-node")
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let hello_payload = handshake::encode_hello(&hello).unwrap();
    let hello_frame = Frame::new(MessageType::Hello, hello_payload);
    send.write_all(&hello_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();

    assert_eq!(ack_frame.msg_type, MessageType::HelloAck);

    let ack: handshake::HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
    assert_eq!(ack.version, PROTOCOL_VERSION);
    assert!(ack.accepted);

    conn.close(0u32.into(), b"done");
    client_endpoint.wait_idle().await;
    server_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Full inference over QUIC (MockInferenceBackend)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn inference_over_quic() {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::new(5));
    let node = PolyNode::new(config, backend).unwrap();

    let server_handle = tokio::spawn(async move {
        node.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = test_infer_request(&[1, 2, 3]);
    let response = connect_and_infer(addr, &request).await.unwrap();

    // MockInferenceBackend: input tokens + 5 new tokens
    let output_ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    assert_eq!(output_ct.tokens.len(), 8); // 3 input + 5 generated
    assert_eq!(&output_ct.tokens[..3], &[1, 2, 3]);

    // Model ID preserved
    assert_eq!(response.model_id, "test-model");

    // Proof is real HashIvc
    match &response.proof {
        poly_verified::types::VerifiedProof::HashIvc { step_count, .. } => {
            assert_eq!(*step_count, 1);
        }
        _ => panic!("expected HashIvc proof"),
    }

    server_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Multiple inference requests on same connection
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn multiple_inferences_same_connection() {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::new(3));
    let node = PolyNode::new(config, backend).unwrap();

    let server_handle = tokio::spawn(async move {
        node.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send 3 requests sequentially on the same QUIC connection
    let client_endpoint = transport::create_client_endpoint().unwrap();
    let conn = client_endpoint
        .connect(addr, "poly-node")
        .unwrap()
        .await
        .unwrap();

    // Handshake required before inference
    do_handshake(&conn).await;

    for i in 0..3u32 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let request = test_infer_request(&[i, i + 10]);
        let payload =
            poly_node::protocol::inference::encode_infer_request(&request).unwrap();
        let frame = Frame::new(MessageType::InferRequest, payload);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();

        let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
        let (resp_frame, _) = Frame::decode(&data).unwrap();
        assert_eq!(resp_frame.msg_type, MessageType::InferResponse);

        let response: poly_client::protocol::InferResponse =
            bincode::deserialize(&resp_frame.payload).unwrap();
        let ct: MockCiphertext =
            serde_json::from_slice(&response.encrypted_output).unwrap();
        assert_eq!(ct.tokens.len(), 5); // 2 input + 3 generated
        assert_eq!(ct.tokens[0], i);
        assert_eq!(ct.tokens[1], i + 10);
    }

    conn.close(0u32.into(), b"done");
    client_endpoint.wait_idle().await;
    server_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Deterministic inference — same request gives same response
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn deterministic_inference() {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::new(5));
    let node = PolyNode::new(config, backend).unwrap();

    let server_handle = tokio::spawn(async move {
        node.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = test_infer_request(&[10, 20, 30]);

    let resp1 = connect_and_infer(addr, &request).await.unwrap();
    let resp2 = connect_and_infer(addr, &request).await.unwrap();

    let ct1: MockCiphertext =
        serde_json::from_slice(&resp1.encrypted_output).unwrap();
    let ct2: MockCiphertext =
        serde_json::from_slice(&resp2.encrypted_output).unwrap();
    assert_eq!(ct1.tokens, ct2.tokens);

    server_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Empty input handled correctly
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_input_inference() {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::new(4));
    let node = PolyNode::new(config, backend).unwrap();

    let server_handle = tokio::spawn(async move {
        node.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = test_infer_request(&[]);
    let response = connect_and_infer(addr, &request).await.unwrap();

    let ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    assert_eq!(ct.tokens.len(), 4); // 0 input + 4 generated

    server_handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: Mixed message types on same connection
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mixed_messages_on_connection() {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::new(2));
    let node = PolyNode::new(config, backend).unwrap();

    let server_handle = tokio::spawn(async move {
        node.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_endpoint = transport::create_client_endpoint().unwrap();
    let conn = client_endpoint
        .connect(addr, "poly-node")
        .unwrap()
        .await
        .unwrap();

    // Handshake required before inference
    do_handshake(&conn).await;

    // Stream 1: Ping
    {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let frame = Frame::new(MessageType::Ping, vec![]);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();
        let data = recv.read_to_end(1024).await.unwrap();
        let (f, _) = Frame::decode(&data).unwrap();
        assert_eq!(f.msg_type, MessageType::Pong);
    }

    // Stream 2: Inference
    {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let request = test_infer_request(&[42]);
        let payload =
            poly_node::protocol::inference::encode_infer_request(&request).unwrap();
        let frame = Frame::new(MessageType::InferRequest, payload);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();
        let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
        let (f, _) = Frame::decode(&data).unwrap();
        assert_eq!(f.msg_type, MessageType::InferResponse);
    }

    // Stream 3: Another Ping
    {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let frame = Frame::new(MessageType::Ping, vec![]);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();
        let data = recv.read_to_end(1024).await.unwrap();
        let (f, _) = Frame::decode(&data).unwrap();
        assert_eq!(f.msg_type, MessageType::Pong);
    }

    conn.close(0u32.into(), b"done");
    client_endpoint.wait_idle().await;
    server_handle.abort();
}
