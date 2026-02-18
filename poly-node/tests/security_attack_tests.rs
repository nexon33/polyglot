//! Security attack tests for poly-node.
//!
//! These tests demonstrate actual vulnerabilities found during penetration
//! testing. Each test proves a specific attack vector works (or is properly
//! mitigated). Tests are grouped by severity.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::NodeIdentity;
use poly_node::net::transport;
use poly_node::node::PolyNode;
use poly_node::protocol::wire::{
    Frame, MessageType, ModelCapability, NodeCapacity, NodeInfo,
};

fn localhost_addr() -> SocketAddr {
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn test_config() -> NodeConfig {
    NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    }
}

fn test_infer_request(tokens: &[u32]) -> InferRequest {
    let ct = MockCiphertext {
        tokens: tokens.to_vec(),
    };
    InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    }
}

/// Start a node and return (addr, abort_handle)
async fn start_test_node() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();
    let handle = tokio::spawn(async move { node.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, handle)
}

// ═══════════════════════════════════════════════════════════════════════════
// CRITICAL: Authentication bypass — skip handshake, go straight to inference
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_auth_bypass_no_handshake_required() {
    // VULNERABILITY: A client can send an InferRequest without ever
    // performing a Hello handshake. The server processes it anyway.
    // The Ed25519 identity system is entirely decorative.

    let (addr, handle) = start_test_node().await;

    // Connect and immediately send inference request — no Hello first
    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let request = test_infer_request(&[1, 2, 3]);
    let payload =
        poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();

    // ATTACK SUCCEEDS: Server returns valid inference response
    // without any authentication
    assert_eq!(resp.msg_type, MessageType::InferResponse);
    let response: poly_client::protocol::InferResponse =
        bincode::deserialize(&resp.payload).unwrap();
    let ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    assert_eq!(ct.tokens.len(), 8); // 3 input + 5 default generated

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// CRITICAL: Signature never verified — fake identity accepted
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_signature_bypass_fake_identity() {
    // VULNERABILITY: The Hello handler never verifies the Ed25519 signature
    // in NodeInfo. An attacker can claim any public_key with a zeroed
    // signature and the server accepts it.

    let (addr, handle) = start_test_node().await;

    let fake_info = NodeInfo {
        public_key: [0xFF; 32], // Fake identity
        addresses: vec!["10.0.0.1:4001".parse().unwrap()],
        models: vec![ModelCapability {
            model_name: "fake-model".into(),
            gpu: true,
            throughput_estimate: 9999.0,
        }],
        relay_capable: true,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 100,
        },
        timestamp: 0,
        signature: vec![0; 64], // Invalid signature — should be rejected
    };

    let hello = poly_node::protocol::handshake::Hello {
        version: 1,
        node_info: fake_info,
    };

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let payload = bincode::serialize(&hello).unwrap();
    let frame = Frame::new(MessageType::Hello, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();

    // ATTACK SUCCEEDS: Server accepts fake identity without checking signature
    assert_eq!(ack_frame.msg_type, MessageType::HelloAck);
    let ack: poly_node::protocol::handshake::HelloAck =
        bincode::deserialize(&ack_frame.payload).unwrap();
    assert!(ack.accepted); // Accepted with a completely fake identity!

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// CRITICAL: HelloAck echoes attacker data — server never identifies itself
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_hello_ack_reflects_attacker_data() {
    // VULNERABILITY: The HelloAck copies the CLIENT's NodeInfo back instead
    // of returning the SERVER's identity. The server never authenticates
    // itself to the client. This also enables reflection amplification.

    let (addr, handle) = start_test_node().await;

    let attacker_info = NodeInfo {
        public_key: [0xAA; 32],
        addresses: vec![
            "1.2.3.4:1000".parse().unwrap(),
            "5.6.7.8:2000".parse().unwrap(),
        ],
        models: vec![],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 99,
            active_sessions: 88,
            max_sessions: 77,
        },
        timestamp: 12345,
        signature: vec![0xBB; 64],
    };

    let hello = poly_node::protocol::handshake::Hello {
        version: 1,
        node_info: attacker_info.clone(),
    };

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let payload = bincode::serialize(&hello).unwrap();
    let frame = Frame::new(MessageType::Hello, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();
    let ack: poly_node::protocol::handshake::HelloAck =
        bincode::deserialize(&ack_frame.payload).unwrap();

    // HARDENED: Server returns its OWN identity, not the attacker's
    assert_ne!(
        ack.node_info.public_key, [0xAA; 32],
        "server must return its own public key, not echo the attacker's"
    );
    assert_ne!(
        ack.node_info.capacity.queue_depth, 99,
        "server must return its own capacity, not echo the attacker's"
    );
    assert_ne!(
        ack.node_info.timestamp, 12345,
        "server must return its own timestamp, not echo the attacker's"
    );
    // Server now identifies itself correctly

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH: Frame parsing — adversarial byte sequences
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attack_frame_decode_all_zeros() {
    let data = [0u8; 1000];
    // Type 0x00 is not a valid MessageType
    assert!(matches!(
        Frame::decode(&data),
        Err(poly_node::protocol::wire::FrameError::UnknownType(0x00))
    ));
}

#[test]
fn attack_frame_decode_all_ff() {
    let data = [0xFF; 1000];
    assert!(matches!(
        Frame::decode(&data),
        Err(poly_node::protocol::wire::FrameError::UnknownType(0xFF))
    ));
}

#[test]
fn attack_frame_decode_max_length_field() {
    // Valid type (Ping) but length field claims 4 GB
    let data = [0x20, 0xFF, 0xFF, 0xFF, 0xFF];
    // HARDENED: Frame::decode rejects payloads > MAX_FRAME_PAYLOAD
    assert!(matches!(
        Frame::decode(&data),
        Err(poly_node::protocol::wire::FrameError::PayloadTooLarge(_))
    ));
}

#[test]
fn attack_frame_decode_length_exactly_at_boundary() {
    // Type: Ping, Length: 3, but only 2 bytes of payload
    let data = [0x20, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB];
    assert!(matches!(
        Frame::decode(&data),
        Err(poly_node::protocol::wire::FrameError::Incomplete)
    ));
}

#[test]
fn attack_frame_decode_every_invalid_type() {
    // Enumerate all 256 possible type bytes, verify only valid ones succeed
    let valid_types: Vec<u8> = vec![
        0x01, 0x02, 0x10, 0x11, 0x12, 0x20, 0x21, 0x30, 0x31, 0x32, 0x33,
        0x40, 0x41, 0x42, 0x43, 0x44,
    ];
    for byte in 0..=255u8 {
        let data = [byte, 0x00, 0x00, 0x00, 0x00]; // 0-length payload
        let result = Frame::decode(&data);
        if valid_types.contains(&byte) {
            assert!(result.is_ok(), "type 0x{:02x} should be valid", byte);
        } else {
            assert!(result.is_err(), "type 0x{:02x} should be invalid", byte);
        }
    }
}

#[test]
fn attack_frame_encode_length_truncation() {
    // Frame::encode casts payload.len() as u32 — what happens with huge payloads?
    // On 64-bit, a Vec larger than u32::MAX would silently truncate the length.
    // We can't allocate 4GB in a test, but verify the cast exists.
    let frame = Frame::new(MessageType::Ping, vec![0; 1000]);
    let encoded = frame.encode();
    // Length should be 1000 = 0x000003E8
    assert_eq!(encoded[1..5], [0x00, 0x00, 0x03, 0xE8]);
}

#[test]
fn attack_frame_consecutive_frames_parsed_correctly() {
    // Two frames concatenated — verify bytes_consumed is correct
    let f1 = Frame::new(MessageType::Ping, vec![0xAA, 0xBB]);
    let f2 = Frame::new(MessageType::Pong, vec![0xCC]);
    let mut data = f1.encode();
    data.extend_from_slice(&f2.encode());

    let (decoded1, consumed1) = Frame::decode(&data).unwrap();
    assert_eq!(decoded1.msg_type, MessageType::Ping);
    assert_eq!(decoded1.payload, vec![0xAA, 0xBB]);
    assert_eq!(consumed1, 7); // 5 header + 2 payload

    let (decoded2, consumed2) = Frame::decode(&data[consumed1..]).unwrap();
    assert_eq!(decoded2.msg_type, MessageType::Pong);
    assert_eq!(decoded2.payload, vec![0xCC]);
    assert_eq!(consumed2, 6); // 5 header + 1 payload
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH: Bincode deserialization bomb — crafted vec length
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_bincode_bomb_hello() {
    // VULNERABILITY: Bincode deserializes Vec<T> by reading a u64 length
    // prefix and attempting to allocate. A crafted payload can claim
    // a Vec of 2^63 elements, causing OOM.

    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    // Craft a payload that starts with a valid Hello but has a massive
    // Vec length for the addresses field. Bincode format for Hello:
    // - version: u32 (4 bytes)
    // - node_info.public_key: [u8; 32] (32 bytes)
    // - node_info.addresses: Vec<SocketAddr> length prefix (u64, 8 bytes)
    //   followed by that many SocketAddr entries
    let mut bomb = Vec::new();
    bomb.extend_from_slice(&1u32.to_le_bytes()); // version = 1
    bomb.extend_from_slice(&[0x42; 32]); // public_key
    // addresses Vec length: claim 2^60 elements (will try to allocate terabytes)
    bomb.extend_from_slice(&(1u64 << 60).to_le_bytes());
    // Don't actually send that many bytes — just the length prefix

    let frame = Frame::new(MessageType::Hello, bomb);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    // Server should handle this gracefully (bincode error), not crash
    // The stream will either get an error response or close without response
    let _result = tokio::time::timeout(
        Duration::from_secs(5),
        recv.read_to_end(64 * 1024),
    )
    .await;

    // If we get here without the server crashing, the test passes.
    // The server should still be responsive.
    // Try a Ping on a new stream to verify the server survived.
    let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
    let ping = Frame::new(MessageType::Ping, vec![]);
    send2.write_all(&ping.encode()).await.unwrap();
    send2.finish().unwrap();
    let pong_data = tokio::time::timeout(
        Duration::from_secs(5),
        recv2.read_to_end(1024),
    )
    .await
    .expect("server should still respond after bincode bomb")
    .unwrap();
    let (pong, _) = Frame::decode(&pong_data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH: Malformed bincode in valid frame — server must not crash
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_malformed_bincode_in_infer_request() {
    // Send a valid Frame with MessageType::InferRequest but garbage payload.
    // Server should handle the bincode error gracefully.

    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Stream 1: garbage InferRequest
    {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let frame = Frame::new(MessageType::InferRequest, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();
        // Server will fail to deserialize — stream should close
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            recv.read_to_end(64 * 1024),
        )
        .await;
    }

    // Stream 2: empty InferRequest payload
    {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let frame = Frame::new(MessageType::InferRequest, vec![]);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            recv.read_to_end(64 * 1024),
        )
        .await;
    }

    // Connection should still be alive — verify with a Ping
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping.encode()).await.unwrap();
    send.finish().unwrap();
    let data = tokio::time::timeout(
        Duration::from_secs(3),
        recv.read_to_end(1024),
    )
    .await
    .expect("server alive after malformed requests")
    .unwrap();
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH: Wrong-direction message types
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_wrong_direction_messages() {
    // Send server-to-client message types (Pong, HelloAck, InferResponse)
    // to the server. These should be rejected, not crash.

    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    let wrong_types = [
        MessageType::Pong,        // Server->Client only
        MessageType::HelloAck,    // Server->Client only
        MessageType::InferResponse, // Server->Client only
        MessageType::PubkeyResponse, // Server->Client only
        MessageType::Peers,       // Phase 2 — not implemented yet
        MessageType::RelayData,   // Phase 3 — not implemented yet
    ];

    for msg_type in wrong_types {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let frame = Frame::new(msg_type, vec![]);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();
        // Should get no response (server logs warning and drops stream)
        let result: Result<Result<Vec<u8>, _>, _> = tokio::time::timeout(
            Duration::from_secs(2),
            recv.read_to_end(1024),
        )
        .await;
        // Either timeout or empty response — both are acceptable
        match result {
            Ok(Ok(data)) => {
                // If we get data, it should be empty (stream closed without response)
                // or a proper error frame
                if !data.is_empty() {
                    let (f, _) = Frame::decode(&data).unwrap();
                    // Any response to a wrong-direction message is suspicious
                    panic!(
                        "Server responded to wrong-direction {:?} with {:?}",
                        msg_type, f.msg_type
                    );
                }
            }
            Ok(Err(_)) => {} // Stream reset — acceptable
            Err(_) => {}     // Timeout — acceptable
        }
    }

    // Connection should survive
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping.encode()).await.unwrap();
    send.finish().unwrap();
    let data = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024))
        .await
        .expect("server alive after wrong-direction messages")
        .unwrap();
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH: HelloAck amplification — large NodeInfo echoed back
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_hello_amplification() {
    // VULNERABILITY: Server echoes back the attacker's NodeInfo in the
    // HelloAck. An attacker can stuff megabytes of data in the
    // model names and addresses, forcing the server to serialize
    // and transmit it all back.

    let (addr, handle) = start_test_node().await;

    // Create a NodeInfo with 100 addresses and 50 models with long names
    let bloated_info = NodeInfo {
        public_key: [0; 32],
        addresses: (0..100)
            .map(|i| format!("10.0.{}.{}:4001", i / 256, i % 256).parse().unwrap())
            .collect(),
        models: (0..50)
            .map(|i| ModelCapability {
                model_name: format!("fake-model-{}-{}", i, "X".repeat(1000)),
                gpu: true,
                throughput_estimate: 0.0,
            })
            .collect(),
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 0,
        },
        timestamp: 0,
        signature: vec![0; 10000], // Oversized signature
    };

    let hello = poly_node::protocol::handshake::Hello {
        version: 1,
        node_info: bloated_info,
    };

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let hello_bytes = bincode::serialize(&hello).unwrap();
    let hello_size = hello_bytes.len();
    let frame = Frame::new(MessageType::Hello, hello_bytes);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(1024 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();

    // HARDENED: Server returns its own (small) NodeInfo, NOT the bloated attacker data
    // The response should be MUCH smaller than our bloated input
    assert!(
        ack_frame.payload.len() < hello_size / 2,
        "server should return its own small NodeInfo, not reflect bloated input: {} bytes response for {} bytes input",
        ack_frame.payload.len(),
        hello_size
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// MEDIUM: Replay attack — same request processed repeatedly
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_replay_inference_request() {
    // VULNERABILITY: No nonce, request ID, or replay protection.
    // A captured inference request can be replayed indefinitely,
    // wasting server compute.

    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[10, 20, 30]);
    let payload = poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let captured_frame = Frame::new(MessageType::InferRequest, payload).encode();

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Replay the exact same bytes 5 times
    for _ in 0..5 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&captured_frame).await.unwrap();
        send.finish().unwrap();

        let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
        let (resp, _) = Frame::decode(&data).unwrap();
        // Server processes every replay — no deduplication
        assert_eq!(resp.msg_type, MessageType::InferResponse);
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// MEDIUM: Version mismatch accepted — no protocol negotiation
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_version_mismatch_accepted() {
    // VULNERABILITY: Server accepts any protocol version in Hello
    // without checking it matches PROTOCOL_VERSION.

    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = NodeInfo {
        public_key: identity.public_key_bytes(),
        addresses: vec![],
        models: vec![],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 8,
        },
        timestamp: 0,
        signature: vec![0; 64],
    };

    // Send Hello with version = 999999
    let hello = poly_node::protocol::handshake::Hello {
        version: 999999,
        node_info: info,
    };

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let payload = bincode::serialize(&hello).unwrap();
    let frame = Frame::new(MessageType::Hello, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();
    let ack: poly_node::protocol::handshake::HelloAck =
        bincode::deserialize(&ack_frame.payload).unwrap();

    // HARDENED: Server rejects mismatched version
    assert!(!ack.accepted, "server must reject incompatible protocol version");
    assert_eq!(ack.version, 1, "server must return its own protocol version");

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// MEDIUM: max_sessions config is never enforced
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn attack_max_sessions_not_enforced() {
    // VULNERABILITY: NodeConfig.max_sessions is defined but never
    // consulted. Set it to 1 and verify we can still run multiple
    // concurrent inferences.

    let mut config = test_config();
    config.max_sessions = 1; // Only allow 1 session
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();

    let handle = tokio::spawn(async move { node.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Open 5 concurrent streams, all doing inference
    let mut tasks = Vec::new();
    for i in 0..5u32 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let request = test_infer_request(&[i]);
        let payload =
            poly_node::protocol::inference::encode_infer_request(&request).unwrap();
        let frame = Frame::new(MessageType::InferRequest, payload);
        let encoded = frame.encode();

        tasks.push(tokio::spawn(async move {
            send.write_all(&encoded).await.unwrap();
            send.finish().unwrap();
            let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
            let (resp, _) = Frame::decode(&data).unwrap();
            resp.msg_type
        }));
    }

    // All 5 succeed despite max_sessions = 1
    for task in tasks {
        let msg_type = task.await.unwrap();
        assert_eq!(msg_type, MessageType::InferResponse);
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}
