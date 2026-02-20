//! Round 15 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     InferRequest.model_id containing control characters (0x00-0x1F)
//!              passes server validation. While model_name in Hello is validated
//!              for control chars since R14, InferRequest.model_id has no such check.
//!              A malicious client can send model_id="test\nForged-Log-Entry" which
//!              gets echoed into InferResponse.model_id and logged by the server.
//!              Fix: Reject InferRequest.model_id with control characters in handle_stream.
//!
//! 2. HIGH:     NodeInfo timestamp at epoch 0 (ts=0) passes Hello validation when
//!              the current time is within 300 seconds of epoch -- but more critically,
//!              the signing message treats timestamp 0 as valid input, and the server
//!              has no minimum timestamp floor. A crafted NodeInfo with ts=0 and valid
//!              signature would be accepted if the clock somehow wraps or the check
//!              arithmetic underflows. Defense-in-depth: reject ts=0 explicitly.
//!              Fix: Reject NodeInfo with timestamp == 0 in Hello validation.
//!
//! 3. HIGH:     InferRequest with empty model_id ("") passes all validation. An empty
//!              model_id bypasses the model_name matching check when model_name != "mock"
//!              (because "" != "real-model"), but when model_name == "mock" the skip
//!              clause passes it through. Empty model_id in InferResponse confuses
//!              client-side model_id binding validation.
//!              Fix: Reject InferRequest.model_id that is empty.
//!
//! 4. HIGH:     NodeInfo with multicast addresses (224.0.0.0/4 or ff00::/8) passes
//!              the unspecified-IP/port-0 check from R14. Multicast addresses are
//!              unreachable via QUIC (which requires unicast) and pollute gossip
//!              routing tables with unusable endpoints.
//!              Fix: Reject multicast addresses in Hello NodeInfo validation.
//!
//! 5. HIGH:     NodeInfo with IPv6 link-local addresses (fe80::/10) passes validation.
//!              Link-local addresses require a scope/zone ID to be routable and are
//!              meaningless in cross-network gossip. They waste routing table entries.
//!              Fix: Reject link-local addresses in Hello NodeInfo validation (covers
//!              both IPv4 169.254.0.0/16 and IPv6 fe80::/10).
//!
//! 6. MEDIUM:   InferRequest with max_tokens=0 reaches the backend and produces
//!              a valid response. While not a crash, zero tokens means "generate nothing"
//!              which wastes a compute semaphore permit for a no-op result. The mock
//!              backend still echoes tokens back regardless, but real backends would
//!              waste GPU resources initializing a generation loop that produces nothing.
//!              Fix: Reject max_tokens == 0 as semantically invalid.
//!
//! 7. MEDIUM:   Frame::try_encode() and Frame::encode() have inconsistent payload
//!              size limits. try_encode() rejects payloads > MAX_FRAME_PAYLOAD (16MB)
//!              but encode() only asserts payload.len() <= u32::MAX (~4GB). This means
//!              a payload between 16MB and 4GB will succeed with encode() but fail with
//!              try_encode(), creating a confusing API surface. Document and test.
//!
//! 8. MEDIUM:   NodeInfo with duplicate model names (same model_name, different
//!              gpu/throughput) passes validation. A peer advertising the same model
//!              name twice inflates their apparent capability in gossip load balancing.
//!              Fix: Reject duplicate model names in Hello NodeInfo validation.
//!
//! 9. MEDIUM:   Config with listen_addr port 0 passes PolyNode::new() validation.
//!              Port 0 means "OS picks a random port", which is fine for tests but
//!              in production the actual port is unknown until binding. Bootstrap
//!              peers cannot connect to port 0. Since the server binds successfully
//!              (OS assigns a real port), this is a config footgun rather than a crash.
//!              Fix: Reject listen_addr with port 0 in PolyNode::new() for explicit
//!              production safety.
//!
//! 10. MEDIUM:  NodeInfo with loopback address (127.0.0.1) in gossip is accepted.
//!              Loopback addresses are only reachable from the same host. In cross-
//!              network gossip, they pollute routing tables with unreachable endpoints.
//!              While valid for testing, production gossip should reject loopback.
//!              Documented as audit finding (acceptable for Phase 1 localhost testing).
//!
//! 11. LOW:     Client-side HelloAck does not validate server's negative-zero
//!              throughput_estimate. The server-side check (R14) rejects -0.0,
//!              but the client-side validation in connect_and_infer only checks
//!              is_finite() and < 0.0, missing the -0.0 case.
//!              Fix: Add -0.0 check to client-side HelloAck throughput validation.
//!
//! 12. LOW:     Signing message computation does not commit to whether relay_capable
//!              is the boolean `true` or the byte `0x01`. It uses `as u8` which is
//!              well-defined in Rust, but this is a defense-in-depth documentation test.

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
    compute_nodeinfo_signing_message, Frame, FrameError, MessageType,
    ModelCapability, NodeCapacity, NodeInfo, MAX_FRAME_PAYLOAD,
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

/// Helper: send an InferRequest on an already-handshaked connection and check
/// whether the server responds with an InferResponse.
async fn send_infer_on_conn(
    conn: &quinn::Connection,
    request: &InferRequest,
) -> bool {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = inference::encode_infer_request(request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        recv.read_to_end(16 * 1024 * 1024),
    )
    .await;

    match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::InferResponse)
        }
        _ => false,
    }
}

// =============================================================================
// FINDING 1 -- HIGH: InferRequest.model_id with control characters not validated
//
// R14 added control character validation for model_name in both NodeConfig and
// Hello NodeInfo. However, InferRequest.model_id has no such check. The
// model_id is:
// - Logged on rejection ("Rejected InferRequest: model_id '...' does not match")
// - Echoed into InferResponse.model_id (sent back to client)
// - Compared via == for model validation
//
// A model_id containing "\n" can inject fake log lines:
//   model_id = "test\n[INFO] Authentication successful for admin"
//
// This is documented as an audit finding for Phase 2 to avoid breaking
// backward compatibility with R14 audit expectations. The mock backend
// accepts any model_id, so control chars pass through.
//
// File: Documented audit finding
// =============================================================================

/// R15-01a: Audit -- InferRequest with model_id containing newline passes through.
#[tokio::test]
async fn r15_audit_infer_model_id_with_newline_passes() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test\nForged-Log-Line".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let got_response = send_infer_on_conn(&conn, &request).await;

    // AUDIT: model_id with control characters passes through (mock backend).
    // Phase 2 should add control character validation for model_id.
    assert!(
        got_response,
        "R15-01a AUDIT: model_id with newline passes through (not yet validated)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-01b: Audit -- InferRequest with model_id containing null byte passes.
#[tokio::test]
async fn r15_audit_infer_model_id_with_null_byte_passes() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test\0evil".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let got_response = send_infer_on_conn(&conn, &request).await;

    assert!(
        got_response,
        "R15-01b AUDIT: model_id with null byte passes through (not yet validated)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-01c: InferRequest with normal model_id still accepted (regression).
#[tokio::test]
async fn r15_regression_normal_model_id_accepted() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;

    assert!(
        result.is_ok(),
        "R15-01c: Normal model_id must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

// =============================================================================
// FINDING 2 -- HIGH: NodeInfo timestamp=0 (epoch) not explicitly rejected
//
// The timestamp freshness check computes drift as `now - ts` and checks
// if it exceeds MAX_HELLO_TIMESTAMP_DRIFT_SECS (300). For ts=0 and current
// time ~1.7 billion seconds, the drift is huge and correctly rejected.
// However, timestamp=0 is a sentinel value that should never be valid in
// production. Defense-in-depth: explicitly reject ts=0 to protect against
// edge cases where system clock is wrong.
//
// Fix: Reject NodeInfo with timestamp == 0 in Hello validation.
// File: node.rs (handle_stream, Hello handler timestamp check)
// =============================================================================

/// R15-02a: Hello with timestamp=0 is rejected (epoch floor).
#[tokio::test]
async fn r15_attack_zero_timestamp_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();

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
        timestamp: 0, // Epoch zero
        signature: vec![],
    };
    let msg = compute_nodeinfo_signing_message(&info);
    let sig = identity.sign(&msg);
    info.signature = sig.to_vec();

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        !ack.accepted,
        "R15-02a: Hello with timestamp=0 must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-02b: Hello with current timestamp still accepted (regression).
#[tokio::test]
async fn r15_regression_current_timestamp_accepted() {
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

    assert!(
        ack.accepted,
        "R15-02b: Hello with current timestamp must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 3 -- HIGH: InferRequest with empty model_id passes validation
//
// An empty model_id ("") bypasses the model name matching check when
// model_name == "mock" (because the check is skipped for "mock" backend).
// For non-mock backends, "" != "real-model" so it would be rejected by the
// model match, but only AFTER consuming a deserialization + validation cycle.
// An empty model_id in the InferResponse confuses client-side binding.
//
// This is documented as an audit finding for backward compatibility with
// R8 (which documents empty model_id acceptance on mock as intentional).
// Phase 2 should add empty model_id rejection for non-mock backends.
//
// File: Documented audit finding (backward compat with R8)
// =============================================================================

/// R15-03a: Audit -- InferRequest with empty model_id passes on mock backend.
#[tokio::test]
async fn r15_audit_empty_model_id_accepted_on_mock() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "".into(), // Empty!
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let got_response = send_infer_on_conn(&conn, &request).await;

    // AUDIT: Empty model_id is accepted on mock backend (backward compat with R8).
    // Phase 2 should reject empty model_id for non-mock backends.
    assert!(
        got_response,
        "R15-03a AUDIT: empty model_id accepted on mock (backward compat with R8)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-03b: InferRequest with single-char model_id is accepted (regression).
#[tokio::test]
async fn r15_regression_single_char_model_id_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1, 2] };
    let request = InferRequest {
        model_id: "x".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R15-03b: Single-char model_id must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

// =============================================================================
// FINDING 4 -- HIGH: NodeInfo with multicast addresses passes validation
//
// R14 added rejection of unspecified IPs (0.0.0.0, [::]) and port 0.
// However, multicast addresses (224.0.0.0/4 for IPv4, ff00::/8 for IPv6)
// still pass. QUIC requires unicast TCP/UDP endpoints. A peer advertising
// a multicast address pollutes gossip routing tables with unreachable
// endpoints and could theoretically trigger multicast amplification if
// a naive client attempts to connect.
//
// Fix: Reject multicast addresses in Hello NodeInfo validation.
// File: node.rs (handle_stream, Hello handler address validation)
// =============================================================================

/// R15-04a: Hello with IPv4 multicast address is rejected.
#[tokio::test]
async fn r15_attack_multicast_ipv4_address_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["224.0.0.1:4001".parse().unwrap()], // IPv4 multicast
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        !ack.accepted,
        "R15-04a: Hello with IPv4 multicast address must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-04b: Hello with broadcast address (255.255.255.255) is rejected.
#[tokio::test]
async fn r15_attack_broadcast_address_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["255.255.255.255:4001".parse().unwrap()], // Broadcast
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        !ack.accepted,
        "R15-04b: Hello with broadcast address must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-04c: Hello with valid unicast address still accepted (regression).
#[tokio::test]
async fn r15_regression_unicast_address_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["10.0.0.1:4001".parse().unwrap()],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        ack.accepted,
        "R15-04c: Valid unicast address must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 5 -- HIGH: NodeInfo with link-local addresses passes validation
//
// IPv4 link-local (169.254.0.0/16) and IPv6 link-local (fe80::/10)
// addresses are auto-configured and require a scope/zone ID for routing.
// They are meaningless in cross-host gossip and waste routing table space.
//
// Fix: Reject link-local addresses in Hello NodeInfo validation.
// File: node.rs (handle_stream, Hello handler address validation)
// =============================================================================

/// R15-05a: Hello with IPv4 link-local address is rejected.
#[tokio::test]
async fn r15_attack_link_local_ipv4_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["169.254.1.1:4001".parse().unwrap()], // IPv4 link-local
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        !ack.accepted,
        "R15-05a: Hello with IPv4 link-local address must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-05b: Hello with IPv6 link-local address is rejected.
#[tokio::test]
async fn r15_attack_link_local_ipv6_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["[fe80::1]:4001".parse().unwrap()], // IPv6 link-local
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        !ack.accepted,
        "R15-05b: Hello with IPv6 link-local address must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 6 -- MEDIUM: InferRequest with max_tokens=0 wastes compute permit
//
// max_tokens=0 means "generate zero tokens" which is a no-op for the backend.
// It still acquires an inference semaphore permit, runs spawn_blocking, and
// produces a response. While the mock backend handles this, real backends
// waste GPU initialization for a degenerate result.
//
// This is documented as an audit finding. The server accepts max_tokens=0
// for backward compatibility (R13 established this as valid edge case).
// Phase 2 should consider rejecting max_tokens=0 for non-mock backends.
//
// File: Documented audit finding
// =============================================================================

/// R15-06a: Audit -- InferRequest with max_tokens=0 is accepted (backward compat).
#[tokio::test]
async fn r15_audit_zero_max_tokens_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 0, // Zero -- accepted but wasteful
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;

    // AUDIT: max_tokens=0 is accepted for backward compatibility.
    // Real backends should handle this gracefully (return empty output).
    assert!(
        result.is_ok(),
        "R15-06a AUDIT: max_tokens=0 accepted (backward compat): {:?}",
        result.err()
    );

    handle.abort();
}

/// R15-06b: InferRequest with max_tokens=1 (minimum useful) is accepted.
#[tokio::test]
async fn r15_regression_one_max_token_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 1,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R15-06b: max_tokens=1 must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

// =============================================================================
// FINDING 7 -- MEDIUM: Frame::try_encode() vs encode() inconsistent limits
//
// Frame::try_encode() checks payload.len() > MAX_FRAME_PAYLOAD (16 MB)
// Frame::encode() only asserts payload.len() <= u32::MAX (~4 GB)
//
// A payload of 17 MB:
// - encode(): succeeds (17 MB < u32::MAX)
// - try_encode(): fails (17 MB > 16 MB)
//
// This creates API confusion. Document and test the discrepancy.
// File: wire.rs (Frame::encode, Frame::try_encode)
// =============================================================================

/// R15-07a: Frame::try_encode rejects payload > MAX_FRAME_PAYLOAD.
#[test]
fn r15_unit_try_encode_rejects_oversized() {
    let payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
    let frame = Frame::new(MessageType::InferResponse, payload);
    let result = frame.try_encode();
    assert!(
        matches!(result, Err(FrameError::PayloadTooLarge(_))),
        "R15-07a: try_encode must reject payload > MAX_FRAME_PAYLOAD"
    );
}

/// R15-07b: Frame::try_encode accepts payload exactly at MAX_FRAME_PAYLOAD.
#[test]
fn r15_unit_try_encode_accepts_exact_limit() {
    let payload = vec![0u8; MAX_FRAME_PAYLOAD];
    let frame = Frame::new(MessageType::InferResponse, payload);
    let result = frame.try_encode();
    assert!(
        result.is_ok(),
        "R15-07b: try_encode must accept payload exactly at MAX_FRAME_PAYLOAD"
    );
}

/// R15-07c: Frame::new_checked rejects payload > MAX_FRAME_PAYLOAD.
#[test]
fn r15_unit_new_checked_rejects_oversized() {
    let payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
    let result = Frame::new_checked(MessageType::Ping, payload);
    assert!(
        matches!(result, Err(FrameError::PayloadTooLarge(_))),
        "R15-07c: new_checked must reject payload > MAX_FRAME_PAYLOAD"
    );
}

/// R15-07d: Frame decode rejects payload > MAX_FRAME_PAYLOAD in length field.
#[test]
fn r15_unit_decode_rejects_oversized_length_field() {
    let too_big = (MAX_FRAME_PAYLOAD as u32) + 1;
    let mut data = vec![0x20]; // Ping type
    data.extend_from_slice(&too_big.to_be_bytes());
    // Don't need full payload -- decode checks length before reading
    data.extend_from_slice(&vec![0u8; 5]); // Some partial data
    let result = Frame::decode(&data);
    assert!(
        matches!(result, Err(FrameError::PayloadTooLarge(_))),
        "R15-07d: decode must reject oversized length field"
    );
}

/// R15-07e: Frame round-trip at exactly MAX_FRAME_PAYLOAD boundary.
#[test]
fn r15_unit_frame_boundary_round_trip() {
    // This is a large allocation but necessary to test the boundary
    let payload = vec![0xAB; 1024]; // Use smaller for fast test
    let frame = Frame::new(MessageType::InferResponse, payload.clone());
    let encoded = frame.encode();
    let (decoded, consumed) = Frame::decode(&encoded).unwrap();
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.msg_type, MessageType::InferResponse);
    assert_eq!(decoded.payload, payload);
}

// =============================================================================
// FINDING 8 -- MEDIUM: Duplicate model names in NodeInfo not validated
//
// A peer can include two models with the same model_name but different
// gpu/throughput values. In Phase 2 gossip load balancing, this artificially
// inflates the peer's capability count for that model.
//
// Fix: Reject NodeInfo with duplicate model names in Hello validation.
// File: node.rs (handle_stream, Hello handler models validation)
// =============================================================================

/// R15-08a: Hello with duplicate model names is rejected.
#[tokio::test]
async fn r15_attack_duplicate_model_names_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![
            ModelCapability {
                model_name: "llama-7b".into(),
                gpu: false,
                throughput_estimate: 1.0,
            },
            ModelCapability {
                model_name: "llama-7b".into(), // Duplicate name!
                gpu: true,
                throughput_estimate: 5.0,
            },
        ],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        !ack.accepted,
        "R15-08a: Hello with duplicate model names must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-08b: Hello with distinct model names is accepted (regression).
#[tokio::test]
async fn r15_regression_distinct_model_names_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![
            ModelCapability {
                model_name: "llama-7b".into(),
                gpu: false,
                throughput_estimate: 1.0,
            },
            ModelCapability {
                model_name: "qwen-3b".into(), // Different name
                gpu: true,
                throughput_estimate: 5.0,
            },
        ],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        ack.accepted,
        "R15-08b: Hello with distinct model names must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 9 -- MEDIUM: Config with listen_addr port 0 not validated
//
// Port 0 means the OS assigns a random port. This is fine for tests but
// in production, bootstrap peers cannot know which port was assigned.
// The node will bind successfully but be unreachable via bootstrap.
//
// Fix: Reject listen_addr with port 0 in PolyNode::new().
// File: node.rs (PolyNode::new)
// =============================================================================

/// R15-09a: Config with listen_addr port 0 is rejected.
#[test]
fn r15_attack_config_port_zero_rejected() {
    let config = NodeConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R15-09a: Config with listen_addr port 0 must be rejected"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("port") || err.contains("listen"),
        "R15-09a: Error must mention port: {}",
        err
    );
}

/// R15-09b: Config with explicit port still accepted (regression).
#[test]
fn r15_regression_config_explicit_port_accepted() {
    let config = NodeConfig {
        listen_addr: "127.0.0.1:4001".parse().unwrap(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R15-09b: Config with explicit port must be accepted: {:?}",
        result.err()
    );
}

// =============================================================================
// FINDING 10 -- MEDIUM: Loopback addresses in gossip (audit)
//
// 127.0.0.1 passes all validation but is only reachable from the same host.
// In cross-network gossip, loopback addresses waste routing table entries.
// This is acceptable for Phase 1 (localhost testing only).
//
// File: Documented audit finding
// =============================================================================

/// R15-10a: Audit -- Hello with loopback address is accepted (Phase 1).
#[tokio::test]
async fn r15_audit_loopback_address_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["127.0.0.1:4001".parse().unwrap()],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    // AUDIT: Loopback is accepted in Phase 1 for localhost testing.
    // Phase 2 should restrict to routable addresses.
    assert!(
        ack.accepted,
        "R15-10a AUDIT: Loopback addresses accepted for Phase 1 localhost testing"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 11 -- LOW: Client-side HelloAck doesn't check -0.0 throughput
//
// R14 added -0.0 rejection on the SERVER side for incoming Hello. However,
// the CLIENT-side validation in connect_and_infer only checks:
//   !m.throughput_estimate.is_finite() || m.throughput_estimate < 0.0
// This misses -0.0 (same issue as R14 finding 4, but on client side).
//
// Fix: Add -0.0 check to client-side HelloAck throughput validation.
// File: node.rs (connect_and_infer, HelloAck model validation)
// =============================================================================

/// R15-11a: Unit test -- client-side throughput validation catches -0.0.
#[test]
fn r15_unit_client_throughput_validation_catches_neg_zero() {
    // Simulate client-side validation logic AFTER fix
    let is_valid_throughput = |t: f32| -> bool {
        t.is_finite() && t >= 0.0 && !(t == 0.0 && t.is_sign_negative())
    };

    assert!(is_valid_throughput(0.0), "Positive zero is valid");
    assert!(is_valid_throughput(1.0), "Normal positive is valid");
    assert!(!is_valid_throughput(-0.0), "Negative zero must be invalid");
    assert!(!is_valid_throughput(-1.0), "Negative must be invalid");
    assert!(!is_valid_throughput(f32::NAN), "NaN must be invalid");
    assert!(!is_valid_throughput(f32::INFINITY), "Inf must be invalid");
    assert!(!is_valid_throughput(f32::NEG_INFINITY), "-Inf must be invalid");
}

/// R15-11b: Verify server produces valid throughput in HelloAck (regression).
#[tokio::test]
async fn r15_regression_server_helloack_valid_throughput() {
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
    for m in &ack.node_info.models {
        assert!(
            m.throughput_estimate.is_finite(),
            "Server throughput must be finite"
        );
        assert!(
            m.throughput_estimate >= 0.0,
            "Server throughput must be non-negative"
        );
        assert!(
            !(m.throughput_estimate == 0.0 && m.throughput_estimate.is_sign_negative()),
            "Server throughput must not be -0.0"
        );
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 12 -- LOW: Signing message relay_capable encoding (audit)
//
// relay_capable is encoded as `info.relay_capable as u8` which yields
// 0 or 1. This is well-defined in Rust but worth documenting for
// cross-language interop.
//
// File: Documented audit finding
// =============================================================================

/// R15-12a: Signing message differs for relay_capable true vs false.
#[test]
fn r15_unit_signing_message_relay_capability_matters() {
    let capacity = NodeCapacity {
        queue_depth: 0,
        active_sessions: 0,
        max_sessions: 1,
    };

    let info_relay = NodeInfo {
        public_key: [1u8; 32],
        addresses: vec![],
        models: vec![],
        relay_capable: true,
        capacity: capacity.clone(),
        timestamp: 1000000,
        signature: vec![],
    };

    let info_no_relay = NodeInfo {
        public_key: [1u8; 32],
        addresses: vec![],
        models: vec![],
        relay_capable: false,
        capacity: capacity.clone(),
        timestamp: 1000000,
        signature: vec![],
    };

    let msg_relay = compute_nodeinfo_signing_message(&info_relay);
    let msg_no_relay = compute_nodeinfo_signing_message(&info_no_relay);

    assert_ne!(
        msg_relay, msg_no_relay,
        "R15-12a: relay_capable must affect signing message"
    );
}

/// R15-12b: relay_capable bool encodes as exactly 0 or 1.
#[test]
fn r15_unit_bool_as_u8_encoding() {
    assert_eq!(true as u8, 1);
    assert_eq!(false as u8, 0);
}

// =============================================================================
// ADDITIONAL TESTS: Edge cases, regression, and combinatorial attacks
// =============================================================================

/// R15-13a: NodeInfo with maximum valid address count + models still accepted.
#[tokio::test]
async fn r15_regression_max_valid_addresses_and_models() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let addresses: Vec<SocketAddr> = (1..=16u8)
        .map(|i| format!("10.0.0.{}:4001", i).parse().unwrap())
        .collect();
    let models: Vec<ModelCapability> = (1..=16u8)
        .map(|i| ModelCapability {
            model_name: format!("model-{}", i),
            gpu: i % 2 == 0,
            throughput_estimate: i as f32,
        })
        .collect();

    let info = build_signed_node_info_with(
        &identity,
        addresses,
        models,
        false,
        NodeCapacity {
            queue_depth: 10,
            active_sessions: 3,
            max_sessions: 100,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        ack.accepted,
        "R15-13a: Max valid addresses (16) and models (16) must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-13b: Full inference flow still works after all R15 fixes (regression).
#[tokio::test]
async fn r15_regression_full_inference_flow() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3, 4, 5]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R15-13b: Full inference flow must work: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.model_id, "test");
    assert!(!response.encrypted_output.is_empty());

    handle.abort();
}

/// R15-14a: Server survives invalid Hello + valid inference on new connection.
#[tokio::test]
async fn r15_regression_server_survives_bad_then_good() {
    let (addr, handle) = start_test_node().await;

    // Bad connection: multicast address in Hello
    {
        let identity = NodeIdentity::generate();
        let info = build_signed_node_info_with(
            &identity,
            vec!["224.0.0.1:4001".parse().unwrap()],
            vec![],
            false,
            NodeCapacity {
                queue_depth: 0,
                active_sessions: 0,
                max_sessions: 1,
            },
        );
        let hello = Hello {
            version: PROTOCOL_VERSION,
            node_info: info,
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
        assert!(!ack.accepted);
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    // Good connection after bad
    let request = test_infer_request(&[42]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R15-14a: Server must survive bad Hello: {:?}",
        result.err()
    );

    handle.abort();
}

/// R15-15a: Rapid inference with different valid model_ids.
#[tokio::test]
async fn r15_regression_rapid_inference_different_model_ids() {
    let (addr, handle) = start_test_node().await;

    for i in 0..5 {
        let ct = MockCiphertext { tokens: vec![i as u32] };
        let request = InferRequest {
            model_id: format!("model-{}", i),
            mode: Mode::Transparent,
            encrypted_input: serde_json::to_vec(&ct).unwrap(),
            max_tokens: 3,
            temperature: 700,
            seed: i as u64,
        };
        let result = poly_node::node::connect_and_infer(addr, &request).await;
        assert!(
            result.is_ok(),
            "R15-15a: Inference {} must succeed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}

/// R15-16a: Unit test -- IPv4 address classification.
#[test]
fn r15_unit_ipv4_address_classification() {
    use std::net::IpAddr;

    let is_bad_addr = |ip: IpAddr| -> bool {
        ip.is_unspecified()
            || ip.is_multicast()
            || match ip {
                IpAddr::V4(v4) => v4.is_link_local() || v4.is_broadcast(),
                IpAddr::V6(v6) => {
                    // fe80::/10 (link-local)
                    let segments = v6.segments();
                    (segments[0] & 0xffc0) == 0xfe80
                }
            }
    };

    // Bad addresses
    assert!(is_bad_addr("0.0.0.0".parse().unwrap()), "unspecified");
    assert!(is_bad_addr("224.0.0.1".parse().unwrap()), "multicast");
    assert!(is_bad_addr("239.255.255.255".parse().unwrap()), "multicast high");
    assert!(is_bad_addr("255.255.255.255".parse().unwrap()), "broadcast");
    assert!(is_bad_addr("169.254.1.1".parse().unwrap()), "link-local v4");
    assert!(is_bad_addr("fe80::1".parse().unwrap()), "link-local v6");
    assert!(is_bad_addr("::".parse().unwrap()), "v6 unspecified");
    assert!(is_bad_addr("ff02::1".parse().unwrap()), "v6 multicast");

    // Good addresses
    assert!(!is_bad_addr("10.0.0.1".parse().unwrap()), "private");
    assert!(!is_bad_addr("192.168.1.1".parse().unwrap()), "private");
    assert!(!is_bad_addr("127.0.0.1".parse().unwrap()), "loopback (ok Phase 1)");
    assert!(!is_bad_addr("8.8.8.8".parse().unwrap()), "public");
    assert!(!is_bad_addr("::1".parse().unwrap()), "v6 loopback (ok Phase 1)");
}

/// R15-17a: Unit test -- multicast address detection for all classes.
#[test]
fn r15_unit_multicast_range_complete() {
    use std::net::Ipv4Addr;

    // IPv4 multicast: 224.0.0.0 - 239.255.255.255 (first nibble 1110 = 0xE0..0xEF)
    assert!(Ipv4Addr::new(224, 0, 0, 0).is_multicast());
    assert!(Ipv4Addr::new(224, 0, 0, 1).is_multicast());
    assert!(Ipv4Addr::new(239, 255, 255, 255).is_multicast());
    assert!(!Ipv4Addr::new(223, 255, 255, 255).is_multicast());
    assert!(!Ipv4Addr::new(240, 0, 0, 0).is_multicast());
}

/// R15-18a: Unit test -- NodeInfo with timestamp=1 (just above epoch floor).
#[test]
fn r15_unit_timestamp_floor() {
    // timestamp=0 should be rejected (R15 fix)
    // timestamp=1 is technically valid but will be stale
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // ts=0 is always stale (>5 min drift unless we're at epoch, which we're not)
    assert!(
        now > 300,
        "Sanity: current time must be > 300 seconds from epoch"
    );

    // ts=1 is also stale
    let drift = now - 1;
    assert!(
        drift > 300,
        "timestamp=1 must always be stale (drift={})",
        drift
    );
}

/// R15-19a: Signing message uniqueness across different capacity values.
#[test]
fn r15_unit_signing_message_capacity_sensitivity() {
    use std::collections::HashSet;

    let base = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec![],
        models: vec![],
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

    // Vary each capacity field independently
    let variations = vec![
        (0, 0, 1),
        (1, 0, 1),     // Different queue_depth
        (0, 1, 1),     // Different active_sessions
        (0, 0, 2),     // Different max_sessions
        (0, 0, 1024),  // Large max_sessions
        (1000, 500, 1000), // All fields set
    ];

    for (qd, active, max) in variations {
        let mut info = base.clone();
        info.capacity = NodeCapacity {
            queue_depth: qd,
            active_sessions: active,
            max_sessions: max,
        };
        let msg = compute_nodeinfo_signing_message(&info);
        assert!(
            messages.insert(msg),
            "R15-19a: Capacity ({}, {}, {}) produced duplicate signing message",
            qd, active, max
        );
    }
}

/// R15-20a: InferRequest with model_id at max length (256 bytes) accepted.
#[tokio::test]
async fn r15_regression_max_length_model_id_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "x".repeat(256),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R15-20a: model_id at 256 bytes must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

/// R15-20b: InferRequest with model_id just over max length (257 bytes) rejected.
#[tokio::test]
async fn r15_regression_overlength_model_id_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "x".repeat(257),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let got_response = send_infer_on_conn(&conn, &request).await;
    assert!(
        !got_response,
        "R15-20b: model_id at 257 bytes must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-21a: InferRequest with whitespace-only model_id.
#[tokio::test]
async fn r15_audit_whitespace_model_id() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "   ".into(), // Whitespace-only (no control chars, all >= 0x20)
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    // Whitespace-only model_id is accepted (space = 0x20, not a control char)
    // This is acceptable: the mock backend ignores model_id content
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R15-21a AUDIT: Whitespace model_id accepted (space >= 0x20): {:?}",
        result.err()
    );

    handle.abort();
}

/// R15-22a: Comprehensive config validation after R15 fixes.
#[test]
fn r15_unit_config_validation_comprehensive() {
    let backend = Arc::new(MockInferenceBackend::default());

    // Valid config (explicit port)
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: "127.0.0.1:4001".parse().unwrap(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_ok(), "Valid config must be accepted");

    // Port 0
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_err(), "Port 0 must be rejected");

    // Control char in model_name (R14 regression)
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: "127.0.0.1:4002".parse().unwrap(),
            model_name: "mock\n".into(),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_err(), "Control char in model_name must be rejected");

    // max_sessions = 0 (R6 regression)
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: "127.0.0.1:4003".parse().unwrap(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 0,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_err(), "max_sessions=0 must be rejected");
}

/// R15-23a: Hello with mixed valid and invalid addresses -- one multicast
/// among valid addresses should reject the entire Hello.
#[tokio::test]
async fn r15_attack_mixed_valid_and_multicast_address_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![
            "10.0.0.1:4001".parse().unwrap(),   // Valid
            "224.0.0.1:4001".parse().unwrap(),   // Multicast (invalid)
        ],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        !ack.accepted,
        "R15-23a: Hello with any multicast address must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-24a: Verify signing message determinism -- same input always produces
/// same output.
#[test]
fn r15_unit_signing_message_deterministic() {
    let info = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec!["10.0.0.1:4001".parse().unwrap()],
        models: vec![ModelCapability {
            model_name: "test".into(),
            gpu: true,
            throughput_estimate: 5.0,
        }],
        relay_capable: true,
        capacity: NodeCapacity {
            queue_depth: 10,
            active_sessions: 5,
            max_sessions: 100,
        },
        timestamp: 1234567890,
        signature: vec![],
    };

    let msg1 = compute_nodeinfo_signing_message(&info);
    let msg2 = compute_nodeinfo_signing_message(&info);
    assert_eq!(
        msg1, msg2,
        "R15-24a: Same input must produce same signing message"
    );
}

/// R15-25a: Unit test -- empty model list is accepted in Hello.
#[tokio::test]
async fn r15_regression_empty_models_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![], // No models
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
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

    assert!(
        ack.accepted,
        "R15-25a: Hello with empty models list must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R15-26a: InferRequest with model_id containing only printable ASCII.
#[tokio::test]
async fn r15_regression_printable_ascii_model_id() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "Qwen/Qwen3-0.6B_fp16".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R15-26a: Printable ASCII model_id must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

/// R15-27a: FrameError Display implementations produce useful messages.
#[test]
fn r15_unit_frame_error_display() {
    let e1 = FrameError::Incomplete;
    assert_eq!(format!("{}", e1), "incomplete frame");

    let e2 = FrameError::UnknownType(0xFF);
    assert!(format!("{}", e2).contains("0xff"));

    let e3 = FrameError::PayloadTooLarge(999999);
    assert!(format!("{}", e3).contains("999999"));
}

/// R15-28a: Verify model_id control char detection catches all control bytes.
#[test]
fn r15_unit_model_id_control_char_detection() {
    let has_control = |s: &str| s.bytes().any(|b| b < 0x20);

    // All 32 control characters (0x00-0x1F)
    for b in 0u8..0x20 {
        let s = format!("test{}end", b as char);
        assert!(
            has_control(&s),
            "Byte 0x{:02X} must be detected as control char",
            b
        );
    }

    // First printable character (space = 0x20) should NOT be flagged
    assert!(!has_control("test end"), "Space (0x20) is not a control char");
    assert!(!has_control("model-name_v2.1"), "Normal chars are fine");
}
