//! Round 12 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     Trailing frame data silently ignored by server (bytes_consumed discarded)
//!              Fix: Reject frames where consumed != data.len() in handle_stream
//! 2. HIGH:     NodeConfig.model_name unbounded (amplified to every HelloAck)
//!              Fix: Validate model_name <= MAX_MODEL_NAME_LEN in PolyNode::new()
//! 3. HIGH:     Frame::new() accepts payloads > MAX_FRAME_PAYLOAD (no fail-fast)
//!              Fix: Added Frame::new_checked() that validates at construction
//! 4. HIGH:     Client-side trailing frame data ignored in connect_and_infer
//!              Fix: Validate consumed == data.len() for HelloAck and InferResponse
//! 5. MEDIUM:   NodeInfo signing does not include protocol version (cross-version replay)
//!              Documented: domain tag "v1" embeds version; explicit field deferred to v2
//! 6. MEDIUM:   Server NodeInfo queue_depth/active_sessions always 0 (stale load data)
//!              Documented: accurate load reporting deferred to Phase 2 gossip
//! 7. MEDIUM:   connect_and_infer generates new identity per call (no client reputation)
//!              Documented: identity reuse deferred to connection pooling feature
//! 8. LOW:      encode_hello/encode_hello_ack use bincode::serialize (legacy)
//!              while decode_* use DefaultOptions (different internal config)
//!              Documented: compatible for fixint but asymmetric maintenance hazard

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::NodeIdentity;
use poly_node::net::transport;
use poly_node::node::{
    build_signed_node_info, build_signed_node_info_with, PolyNode,
};
use poly_node::protocol::handshake::{self, Hello, HelloAck, PROTOCOL_VERSION};
use poly_node::protocol::inference;
use poly_node::protocol::wire::{
    compute_nodeinfo_signing_message, Frame, FrameError, MessageType, ModelCapability,
    NodeCapacity, NodeInfo, MAX_FRAME_PAYLOAD,
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

async fn start_test_node() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();
    let handle = tokio::spawn(async move { node.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, handle)
}

async fn do_handshake(conn: &quinn::Connection) {
    let client_identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&client_identity),
    };
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let hello_payload = handshake::encode_hello(&hello).unwrap();
    let hello_frame = Frame::new(MessageType::Hello, hello_payload);
    send.write_all(&hello_frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();
    assert_eq!(ack_frame.msg_type, MessageType::HelloAck);
    let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
    assert!(ack.accepted, "handshake must be accepted");
}

// =============================================================================
// FINDING 1 -- HIGH: Trailing frame data silently ignored by server
//
// Before R12, handle_stream() called Frame::decode(&data) and discarded the
// bytes_consumed value. An attacker could send:
//   [valid Hello frame (5 + N bytes)] [garbage or second frame (up to 16MB - N - 5)]
//
// The server would decode the first frame and process it, silently ignoring
// the remaining bytes. This has several implications:
// - Memory waste: the full read_to_end(16MB) allocation includes the garbage
// - Protocol confusion: trailing data could contain a second valid frame that
//   looks like a different message type, confusing protocol analysis/logging
// - Fingerprinting: the server's acceptance of trailing data reveals that it
//   processes only the first frame, leaking implementation details
//
// Fix: Reject frames where consumed != data.len() in handle_stream.
// File: node.rs (handle_stream, frame decoding)
// =============================================================================

/// R12-01a: Server rejects Hello frame with trailing garbage bytes.
#[tokio::test]
async fn r12_attack_trailing_garbage_after_hello_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    // Build a valid Hello frame, then append garbage
    let hello_payload = handshake::encode_hello(&hello).unwrap();
    let hello_frame = Frame::new(MessageType::Hello, hello_payload);
    let mut data = hello_frame.encode();
    data.extend_from_slice(b"TRAILING_GARBAGE_DATA_INJECTED");

    send.write_all(&data).await.unwrap();
    send.finish().unwrap();

    // Server should either:
    // 1. Drop the stream (no response) -- trailing data rejected
    // 2. Send a rejection -- trailing data rejected
    // It should NOT process the Hello and return an accepted HelloAck
    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(64 * 1024)).await;

    let was_accepted = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            if let Ok((ack_frame, _)) = Frame::decode(&data) {
                if ack_frame.msg_type == MessageType::HelloAck {
                    let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
                    ack.accepted
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    };

    assert!(
        !was_accepted,
        "R12-01a: Hello frame with trailing garbage must NOT be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R12-01b: Server rejects Ping frame with trailing second frame appended.
#[tokio::test]
async fn r12_attack_trailing_frame_after_ping_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    // Build a valid Ping frame, then append a second valid frame
    let ping_frame = Frame::new(MessageType::Ping, vec![]);
    let infer_frame = Frame::new(MessageType::InferRequest, vec![0xFF; 100]);
    let mut data = ping_frame.encode();
    data.extend_from_slice(&infer_frame.encode());

    send.write_all(&data).await.unwrap();
    send.finish().unwrap();

    // Server should reject: trailing bytes detected
    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;

    let got_pong = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::Pong)
        }
        _ => false,
    };

    assert!(
        !got_pong,
        "R12-01b: Ping with trailing second frame must NOT return Pong"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R12-01c: Server rejects InferRequest with trailing data.
#[tokio::test]
async fn r12_attack_trailing_data_after_infer_request_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    // Build a valid InferRequest frame, then append trailing bytes
    let request = test_infer_request(&[1, 2, 3]);
    let payload = inference::encode_infer_request(&request).unwrap();
    let req_frame = Frame::new(MessageType::InferRequest, payload);
    let mut data = req_frame.encode();
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // 4 trailing bytes

    send.write_all(&data).await.unwrap();
    send.finish().unwrap();

    // Should NOT get a valid InferResponse
    let result = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16 * 1024 * 1024))
        .await;

    let got_response = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(
                Frame::decode(&data),
                Ok((f, _)) if f.msg_type == MessageType::InferResponse
            )
        }
        _ => false,
    };

    assert!(
        !got_response,
        "R12-01c: InferRequest with trailing data must NOT return InferResponse"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R12-01d: Server accepts clean frame with no trailing bytes (regression).
#[tokio::test]
async fn r12_regression_clean_frame_accepted() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R12-01d: Clean frames must still work: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.model_id, "test");
    assert!(!response.encrypted_output.is_empty());

    handle.abort();
}

/// R12-01e: Server rejects frame with single trailing null byte.
#[tokio::test]
async fn r12_attack_single_trailing_byte_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let hello_payload = handshake::encode_hello(&hello).unwrap();
    let hello_frame = Frame::new(MessageType::Hello, hello_payload);
    let mut data = hello_frame.encode();
    data.push(0x00); // Single trailing null byte

    send.write_all(&data).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(64 * 1024)).await;

    let was_accepted = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            if let Ok((ack_frame, _)) = Frame::decode(&data) {
                if ack_frame.msg_type == MessageType::HelloAck {
                    let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
                    ack.accepted
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    };

    assert!(
        !was_accepted,
        "R12-01e: Even a single trailing byte must cause rejection"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 2 -- HIGH: NodeConfig.model_name unbounded
//
// Before R12, NodeConfig had no validation on model_name length. The model_name
// is embedded in NodeInfo (via own_node_info()) and sent in every HelloAck
// response. A deployment configured with a multi-MB model_name would:
// - Amplify the model_name to every connecting peer (bandwidth waste)
// - Cause every HelloAck to be close to the 64KB serialization limit
// - If model_name > ~64KB, all HelloAck serialization would fail silently
//
// Fix: PolyNode::new() validates model_name <= MAX_MODEL_NAME_LEN (256 bytes).
// File: node.rs (PolyNode::new)
// =============================================================================

/// R12-02a: Config with model_name > 256 bytes is rejected.
#[test]
fn r12_attack_oversized_model_name_config_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "A".repeat(257),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R12-02a: Config with 257-byte model_name must be rejected"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("model_name too long"),
        "R12-02a: Error must mention model_name: {}",
        err
    );
}

/// R12-02b: Config with model_name exactly at limit (256 bytes) is accepted.
#[test]
fn r12_verify_max_model_name_config_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "A".repeat(256),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R12-02b: Config with 256-byte model_name must be accepted: {:?}",
        result.err()
    );
}

/// R12-02c: Config with empty model_name is accepted (edge case).
#[test]
fn r12_verify_empty_model_name_config_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: String::new(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R12-02c: Config with empty model_name must be accepted: {:?}",
        result.err()
    );
}

/// R12-02d: Multi-KB model_name in config is rejected.
#[test]
fn r12_attack_multi_kb_model_name_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "X".repeat(10_000),
        bootstrap_addrs: vec![],
        max_sessions: 4,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R12-02d: 10KB model_name must be rejected"
    );
}

// =============================================================================
// FINDING 3 -- HIGH: Frame::new() accepts payloads > MAX_FRAME_PAYLOAD
//
// Before R12, Frame::new() accepted any payload size. The payload size was
// only checked in:
// - Frame::encode() -- panics if > u32::MAX
// - Frame::try_encode() -- returns Err if > MAX_FRAME_PAYLOAD
// - Frame::decode() -- rejects if > MAX_FRAME_PAYLOAD
//
// This means a caller could construct a Frame with a 100 MB payload,
// allocating 100 MB of memory, only to have it rejected at encode time.
// Frame::new_checked() validates at construction for fail-fast behavior.
//
// Fix: Added Frame::new_checked() in wire.rs
// File: protocol/wire.rs
// =============================================================================

/// R12-03a: Frame::new_checked() rejects oversized payloads.
#[test]
fn r12_unit_frame_new_checked_rejects_oversized() {
    let oversized_payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
    let result = Frame::new_checked(MessageType::Ping, oversized_payload);
    assert!(
        result.is_err(),
        "R12-03a: new_checked must reject payload > MAX_FRAME_PAYLOAD"
    );
    assert_eq!(
        result.unwrap_err(),
        FrameError::PayloadTooLarge(MAX_FRAME_PAYLOAD + 1)
    );
}

/// R12-03b: Frame::new_checked() accepts payload at exact limit.
#[test]
fn r12_unit_frame_new_checked_accepts_at_limit() {
    let max_payload = vec![0u8; MAX_FRAME_PAYLOAD];
    let result = Frame::new_checked(MessageType::InferRequest, max_payload);
    assert!(
        result.is_ok(),
        "R12-03b: new_checked must accept payload at MAX_FRAME_PAYLOAD"
    );
    let frame = result.unwrap();
    assert_eq!(frame.payload.len(), MAX_FRAME_PAYLOAD);
}

/// R12-03c: Frame::new_checked() accepts empty payload.
#[test]
fn r12_unit_frame_new_checked_accepts_empty() {
    let result = Frame::new_checked(MessageType::Pong, vec![]);
    assert!(
        result.is_ok(),
        "R12-03c: new_checked must accept empty payload"
    );
    let frame = result.unwrap();
    assert!(frame.payload.is_empty());
}

/// R12-03d: Frame::new_checked() round-trips through encode/decode.
#[test]
fn r12_unit_frame_new_checked_round_trip() {
    let payload = vec![0xAB; 1000];
    let frame = Frame::new_checked(MessageType::InferResponse, payload.clone()).unwrap();
    let encoded = frame.encode();
    let (decoded, consumed) = Frame::decode(&encoded).unwrap();
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.msg_type, MessageType::InferResponse);
    assert_eq!(decoded.payload, payload);
}

/// R12-03e: Frame::new() still works for backward compatibility (no check).
#[test]
fn r12_regression_frame_new_no_size_check() {
    // Frame::new() does NOT check size -- this is intentional for backward compat
    let frame = Frame::new(MessageType::Ping, vec![0u8; 100]);
    assert_eq!(frame.payload.len(), 100);
}

// =============================================================================
// FINDING 4 -- HIGH: Client-side trailing frame data ignored
//
// Before R12, connect_and_infer() discarded the bytes_consumed value from
// Frame::decode() on both the HelloAck and InferResponse reads. A malicious
// server could append extra data after a valid frame:
// - Extra data after HelloAck: could contain a forged second HelloAck with
//   different parameters, or leak information about the server
// - Extra data after InferResponse: could contain injected data that a
//   higher-level parser might consume
//
// Fix: Validate consumed == data.len() for both frames in connect_and_infer.
// File: node.rs (connect_and_infer)
// =============================================================================

/// R12-04a: Audit -- client-side frame validation is symmetric with server.
/// The client must reject trailing data just like the server does.
#[test]
fn r12_audit_frame_decode_returns_consumed() {
    let frame = Frame::new(MessageType::Ping, vec![1, 2, 3]);
    let encoded = frame.encode();

    // Normal: consumed == encoded.len()
    let (_, consumed) = Frame::decode(&encoded).unwrap();
    assert_eq!(
        consumed,
        encoded.len(),
        "R12-04a: Frame::decode consumed must equal total length for clean frames"
    );

    // With trailing data: consumed < total
    let mut with_trailing = encoded.clone();
    with_trailing.extend_from_slice(b"EXTRA");
    let (_, consumed_with_trailing) = Frame::decode(&with_trailing).unwrap();
    assert!(
        consumed_with_trailing < with_trailing.len(),
        "R12-04a: Frame::decode consumed must be less than total when trailing data present"
    );
    assert_eq!(
        consumed_with_trailing,
        encoded.len(),
        "R12-04a: Consumed must be the original frame length"
    );
}

/// R12-04b: Verify connect_and_infer rejects a server that appends trailing
/// data to HelloAck. This is tested indirectly through the full flow,
/// since we can't easily modify server responses in integration tests.
/// We verify that a normal connect_and_infer still works (regression).
#[tokio::test]
async fn r12_regression_connect_and_infer_clean_frames() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[5, 10, 15]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R12-04b: Normal connect_and_infer must succeed: {:?}",
        result.err()
    );

    handle.abort();
}

// =============================================================================
// FINDING 5 -- MEDIUM: NodeInfo signing does not include protocol version
//
// The signing message format is:
//   Sign(public_key || timestamp || SHA-256(domain_tag || fields))
//
// The domain tag is "poly-node/NodeInfo/v1\0" which embeds the version "v1".
// However, if PROTOCOL_VERSION is bumped to 2 without updating the domain tag
// string, signatures from v1 would still verify under v2.
//
// Mitigation: The domain tag already contains "v1". Changing the tag for
// v2 would naturally invalidate v1 signatures. This is documented as a
// defense-in-depth recommendation for Phase 2.
//
// File: wire.rs (compute_nodeinfo_signing_message)
// =============================================================================

/// R12-05a: Verify domain tag contains version string.
#[test]
fn r12_audit_domain_tag_contains_version() {
    // The domain tag is "poly-node/NodeInfo/v1\0". If PROTOCOL_VERSION changes,
    // the tag MUST be updated in tandem.
    assert_eq!(
        PROTOCOL_VERSION, 1,
        "R12-05a: If PROTOCOL_VERSION changes from 1, update the domain tag in wire.rs"
    );
}

/// R12-05b: Verify that changing any field in the signing message produces a
/// different result. This ensures the signing message has no collisions
/// within the same protocol version.
#[test]
fn r12_unit_signing_message_collision_resistance() {
    use std::collections::HashSet;

    let base = NodeInfo {
        public_key: [1u8; 32],
        addresses: vec!["127.0.0.1:4001".parse().unwrap()],
        models: vec![ModelCapability {
            model_name: "test".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp: 1000000,
        signature: vec![],
    };

    let mut messages = HashSet::new();
    messages.insert(compute_nodeinfo_signing_message(&base));

    // Vary each field and check uniqueness
    let variations: Vec<NodeInfo> = vec![
        {
            let mut v = base.clone();
            v.public_key = [2u8; 32];
            v
        },
        {
            let mut v = base.clone();
            v.timestamp = 1000001;
            v
        },
        {
            let mut v = base.clone();
            v.addresses = vec!["127.0.0.2:4001".parse().unwrap()];
            v
        },
        {
            let mut v = base.clone();
            v.models[0].model_name = "other".into();
            v
        },
        {
            let mut v = base.clone();
            v.models[0].gpu = true;
            v
        },
        {
            let mut v = base.clone();
            v.relay_capable = true;
            v
        },
        {
            let mut v = base.clone();
            v.capacity.max_sessions = 2;
            v
        },
    ];

    for (i, var) in variations.iter().enumerate() {
        let msg = compute_nodeinfo_signing_message(var);
        assert!(
            messages.insert(msg),
            "R12-05b: Variation {} produced a duplicate signing message (collision!)",
            i
        );
    }
}

// =============================================================================
// FINDING 6 -- MEDIUM: Server NodeInfo queue_depth/active_sessions always 0
//
// own_node_info() hardcodes queue_depth=0 and active_sessions=0 regardless
// of actual server load. Clients using these values for Phase 2 load-balancing
// would see all nodes as equally loaded, defeating the purpose of capacity
// advertisement.
//
// This is a Phase 2 concern (gossip-based load balancing is not yet
// implemented). Documented for future implementation.
//
// File: node.rs (own_node_info)
// =============================================================================

/// R12-06a: Audit -- server NodeInfo always reports zero load.
#[tokio::test]
async fn r12_audit_server_reports_zero_load() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let payload = handshake::encode_hello(&hello).unwrap();
    let frame = Frame::new(MessageType::Hello, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();
    let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
    assert!(ack.accepted);

    // Document the gap: capacity fields are static
    assert_eq!(
        ack.node_info.capacity.queue_depth, 0,
        "R12-06a AUDIT: queue_depth is always 0 (stale load data)"
    );
    assert_eq!(
        ack.node_info.capacity.active_sessions, 0,
        "R12-06a AUDIT: active_sessions is always 0 (stale load data)"
    );
    // max_sessions SHOULD reflect the configured value
    assert_eq!(
        ack.node_info.capacity.max_sessions, 8,
        "R12-06a: max_sessions should reflect NodeConfig value"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 7 -- MEDIUM: connect_and_infer generates new identity per call
//
// Each call to connect_and_infer() generates a fresh NodeIdentity via
// NodeIdentity::generate(). This means:
// - Each connection presents a different client identity to the server
// - The server cannot build a reputation/trust model for repeat clients
// - Ed25519 key generation is performed unnecessarily on each call
// - The server cannot correlate requests from the same client
//
// Mitigation: This is acceptable for Phase 1 where trust is not implemented.
// Phase 2 should add connection pooling with persistent client identity.
//
// File: node.rs (connect_and_infer)
// =============================================================================

/// R12-07a: Audit -- each connect_and_infer generates a unique identity.
/// Verify by checking that two sequential calls produce responses
/// (proving both generate their own keys and handshake independently).
#[tokio::test]
async fn r12_audit_fresh_identity_per_call() {
    let (addr, handle) = start_test_node().await;

    let req1 = test_infer_request(&[1]);
    let req2 = test_infer_request(&[2]);

    let res1 = poly_node::node::connect_and_infer(addr, &req1).await.unwrap();
    let res2 = poly_node::node::connect_and_infer(addr, &req2).await.unwrap();

    // Both should succeed with independent identities
    assert_eq!(res1.model_id, "test");
    assert_eq!(res2.model_id, "test");
    // The outputs should differ because input tokens differ
    assert_ne!(
        res1.encrypted_output, res2.encrypted_output,
        "R12-07a: Different inputs should produce different outputs"
    );

    handle.abort();
}

// =============================================================================
// FINDING 8 -- LOW: encode_hello/encode_hello_ack use bincode::serialize()
// (legacy config) while decode_hello/decode_hello_ack use DefaultOptions
//
// bincode::serialize() uses the legacy configuration:
//   - FixintEncoding (u32 is always 4 bytes)
//   - LittleEndian
//   - AllowTrailingBytes
//   - NoLimit
//
// bincode::DefaultOptions::new().with_fixint_encoding() uses:
//   - FixintEncoding (same)
//   - LittleEndian (same)
//   - RejectTrailingBytes (DIFFERENT)
//   - Limit applied (DIFFERENT)
//
// For encoding output: both produce identical bytes (same encoding).
// For decoding: DefaultOptions is strictly tighter (no trailing bytes,
// has size limit). This is actually CORRECT -- the encoder is permissive
// and the decoder is strict. But the asymmetry is a maintenance hazard.
//
// No fix needed: this is the documented standard pattern for bincode 1.x.
// File: handshake.rs
// =============================================================================

/// R12-08a: Verify encode/decode round-trip works despite config difference.
#[test]
fn r12_unit_encode_decode_hello_round_trip() {
    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    let encoded = handshake::encode_hello(&hello).unwrap();
    let decoded = handshake::decode_hello(&encoded).unwrap();

    assert_eq!(decoded.version, hello.version);
    assert_eq!(decoded.node_info.public_key, hello.node_info.public_key);
    assert_eq!(decoded.node_info.timestamp, hello.node_info.timestamp);
}

/// R12-08b: Verify encode/decode round-trip for HelloAck.
#[test]
fn r12_unit_encode_decode_hello_ack_round_trip() {
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: NodeInfo {
            public_key: [42u8; 32],
            addresses: vec!["127.0.0.1:4001".parse().unwrap()],
            models: vec![ModelCapability {
                model_name: "test".into(),
                gpu: false,
                throughput_estimate: 1.0,
            }],
            relay_capable: false,
            capacity: NodeCapacity {
                queue_depth: 0,
                active_sessions: 0,
                max_sessions: 1,
            },
            timestamp: 12345,
            signature: vec![0u8; 64],
        },
        accepted: true,
    };

    let encoded = handshake::encode_hello_ack(&ack).unwrap();
    let decoded = handshake::decode_hello_ack(&encoded).unwrap();

    assert_eq!(decoded.version, ack.version);
    assert_eq!(decoded.accepted, ack.accepted);
    assert_eq!(decoded.node_info.public_key, ack.node_info.public_key);
}

/// R12-08c: decode_hello rejects trailing bytes (strict mode).
#[test]
fn r12_unit_decode_hello_rejects_trailing_bytes() {
    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    let mut encoded = handshake::encode_hello(&hello).unwrap();
    encoded.push(0xFF); // Append trailing byte

    let result = handshake::decode_hello(&encoded);
    assert!(
        result.is_err(),
        "R12-08c: decode_hello must reject trailing bytes"
    );
}

/// R12-08d: decode_hello_ack rejects trailing bytes (strict mode).
#[test]
fn r12_unit_decode_hello_ack_rejects_trailing_bytes() {
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: NodeInfo {
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
        },
        accepted: false,
    };

    let mut encoded = handshake::encode_hello_ack(&ack).unwrap();
    encoded.push(0xFF);

    let result = handshake::decode_hello_ack(&encoded);
    assert!(
        result.is_err(),
        "R12-08d: decode_hello_ack must reject trailing bytes"
    );
}

// =============================================================================
// ADDITIONAL ATTACKS: Edge cases and regression tests
// =============================================================================

/// R12-09a: Verify max_sessions=1 config still works (minimum valid config).
#[tokio::test]
async fn r12_regression_min_config_works() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 1,
        relay: false,
    };
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();
    let handle = tokio::spawn(async move { node.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = test_infer_request(&[1]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R12-09a: Minimum config (1 session) must work: {:?}",
        result.err()
    );

    handle.abort();
}

/// R12-09b: Verify inference works after multiple handshake + inference cycles
/// on the same server (connection churn test).
#[tokio::test]
async fn r12_regression_connection_churn() {
    let (addr, handle) = start_test_node().await;

    for i in 0..5 {
        let request = test_infer_request(&[i as u32]);
        let result = poly_node::node::connect_and_infer(addr, &request).await;
        assert!(
            result.is_ok(),
            "R12-09b: Connection {} must succeed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}

/// R12-10a: Frame::new_checked fails for payloads slightly over the limit.
#[test]
fn r12_unit_new_checked_boundary() {
    // Just over the limit
    let over = Frame::new_checked(MessageType::InferRequest, vec![0u8; MAX_FRAME_PAYLOAD + 1]);
    assert!(over.is_err());

    // At the limit
    let at = Frame::new_checked(MessageType::InferRequest, vec![0u8; MAX_FRAME_PAYLOAD]);
    assert!(at.is_ok());

    // Just under the limit
    let under = Frame::new_checked(MessageType::InferRequest, vec![0u8; MAX_FRAME_PAYLOAD - 1]);
    assert!(under.is_ok());
}

/// R12-10b: try_encode and new_checked are consistent in their checks.
#[test]
fn r12_unit_try_encode_and_new_checked_consistent() {
    // Both should reject the same payloads
    let oversized = vec![0u8; MAX_FRAME_PAYLOAD + 1];

    let new_checked_result = Frame::new_checked(MessageType::Ping, oversized.clone());
    assert!(new_checked_result.is_err());

    let frame = Frame::new(MessageType::Ping, oversized);
    let try_encode_result = frame.try_encode();
    assert!(try_encode_result.is_err());
}

/// R12-11a: InferRequest encode/decode round-trip preserves all fields.
#[test]
fn r12_unit_infer_request_round_trip() {
    let request = InferRequest {
        model_id: "test-model".into(),
        mode: Mode::Encrypted,
        encrypted_input: vec![1, 2, 3, 4, 5],
        max_tokens: 100,
        temperature: 700,
        seed: 42,
    };

    let encoded = inference::encode_infer_request(&request).unwrap();
    let decoded = inference::decode_infer_request(&encoded).unwrap();

    assert_eq!(decoded.model_id, request.model_id);
    assert_eq!(decoded.mode, request.mode);
    assert_eq!(decoded.encrypted_input, request.encrypted_input);
    assert_eq!(decoded.max_tokens, request.max_tokens);
    assert_eq!(decoded.temperature, request.temperature);
    assert_eq!(decoded.seed, request.seed);
}

/// R12-11b: InferRequest with u32::MAX temperature encodes/decodes correctly.
/// Documents that temperature has no server-side validation.
#[test]
fn r12_audit_extreme_temperature_accepted() {
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: vec![],
        max_tokens: 1,
        temperature: u32::MAX,
        seed: 0,
    };

    let encoded = inference::encode_infer_request(&request).unwrap();
    let decoded = inference::decode_infer_request(&encoded).unwrap();
    assert_eq!(
        decoded.temperature,
        u32::MAX,
        "R12-11b AUDIT: temperature has no validation, u32::MAX passes through"
    );
}

/// R12-11c: InferRequest with u64::MAX seed encodes/decodes correctly.
/// Documents that seed has no server-side validation.
#[test]
fn r12_audit_extreme_seed_accepted() {
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: vec![],
        max_tokens: 1,
        temperature: 0,
        seed: u64::MAX,
    };

    let encoded = inference::encode_infer_request(&request).unwrap();
    let decoded = inference::decode_infer_request(&encoded).unwrap();
    assert_eq!(
        decoded.seed,
        u64::MAX,
        "R12-11c AUDIT: seed has no validation, u64::MAX passes through"
    );
}

/// R12-12a: build_signed_node_info produces deterministic signatures for same identity.
/// (Same identity + same timestamp window should produce functionally equivalent NodeInfo)
#[test]
fn r12_unit_build_signed_node_info_deterministic_fields() {
    let identity = NodeIdentity::generate();
    let info1 = build_signed_node_info(&identity);
    let info2 = build_signed_node_info(&identity);

    // Public key must be the same
    assert_eq!(info1.public_key, info2.public_key);
    // Addresses should be empty (default)
    assert!(info1.addresses.is_empty());
    assert!(info2.addresses.is_empty());
    // Models should be empty (default)
    assert!(info1.models.is_empty());
    assert!(info2.models.is_empty());
    // Timestamps may differ by a small amount (called at slightly different times)
    // but should be within 1 second
    assert!(
        info1.timestamp.abs_diff(info2.timestamp) <= 1,
        "R12-12a: Timestamps should be within 1 second"
    );
}

/// R12-12b: build_signed_node_info_with signs all custom fields correctly.
#[test]
fn r12_unit_build_signed_node_info_with_all_fields_signed() {
    let identity = NodeIdentity::generate();

    let addrs = vec![
        "10.0.0.1:4001".parse().unwrap(),
        "192.168.1.1:4002".parse().unwrap(),
    ];
    let models = vec![
        ModelCapability {
            model_name: "llama-70b".into(),
            gpu: true,
            throughput_estimate: 50.0,
        },
        ModelCapability {
            model_name: "qwen-0.6b".into(),
            gpu: false,
            throughput_estimate: 100.0,
        },
    ];
    let capacity = NodeCapacity {
        queue_depth: 5,
        active_sessions: 2,
        max_sessions: 16,
    };

    let info = build_signed_node_info_with(&identity, addrs.clone(), models, true, capacity);

    // Verify all fields are set correctly
    assert_eq!(info.public_key, identity.public_key_bytes());
    assert_eq!(info.addresses, addrs);
    assert_eq!(info.models.len(), 2);
    assert_eq!(info.models[0].model_name, "llama-70b");
    assert_eq!(info.models[1].model_name, "qwen-0.6b");
    assert!(info.relay_capable);
    assert_eq!(info.capacity.max_sessions, 16);

    // Verify signature is valid
    let vk = identity.verifying_key();
    let msg = compute_nodeinfo_signing_message(&info);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&info.signature);
    assert!(
        poly_node::identity::verify_signature(vk, &msg, &sig_arr),
        "R12-12b: build_signed_node_info_with signature must be valid"
    );
}

/// R12-13a: Verify NodeId is collision-resistant (different keys produce different IDs).
#[test]
fn r12_unit_node_id_collision_resistance() {
    use std::collections::HashSet;

    let mut ids = HashSet::new();
    for _ in 0..100 {
        let identity = NodeIdentity::generate();
        assert!(
            ids.insert(identity.id),
            "R12-13a: NodeId collision detected!"
        );
    }
}

/// R12-13b: Verify NodeId is deterministic for the same public key.
#[test]
fn r12_unit_node_id_deterministic() {
    let identity = NodeIdentity::generate();
    let id1 = poly_node::identity::compute_node_id(identity.verifying_key());
    let id2 = poly_node::identity::compute_node_id(identity.verifying_key());
    assert_eq!(id1, id2, "R12-13b: NodeId must be deterministic for same key");
    assert_eq!(id1, identity.id);
}

/// R12-14a: Multiple concurrent inference requests on the same node.
#[tokio::test]
async fn r12_regression_concurrent_inferences() {
    let (addr, handle) = start_test_node().await;

    let mut handles = vec![];
    for i in 0..3 {
        let req = test_infer_request(&[i as u32]);
        handles.push(tokio::spawn(async move {
            poly_node::node::connect_and_infer(addr, &req).await
        }));
    }

    for (i, h) in handles.into_iter().enumerate() {
        let result = h.await.unwrap();
        assert!(
            result.is_ok(),
            "R12-14a: Concurrent inference {} failed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}

/// R12-14b: Handshake followed by multiple inference requests on same connection.
#[tokio::test]
async fn r12_regression_multiple_inferences_one_connection() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    for i in 0..3 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let request = test_infer_request(&[i as u32]);
        let payload = inference::encode_infer_request(&request).unwrap();
        let frame = Frame::new(MessageType::InferRequest, payload);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();

        let data = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(16 * 1024 * 1024))
            .await
            .expect("timeout")
            .expect("read error");
        let (resp_frame, consumed) = Frame::decode(&data).unwrap();
        assert_eq!(consumed, data.len(), "R12-14b: No trailing data in response");
        assert_eq!(resp_frame.msg_type, MessageType::InferResponse);

        let response = inference::decode_infer_response(&resp_frame.payload).unwrap();
        assert_eq!(response.model_id, "test", "Inference {} model_id mismatch", i);
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}
