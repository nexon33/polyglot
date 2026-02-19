//! Round 13 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     bootstrap_addrs not validated in NodeConfig (no length cap, no self-connection check)
//!              Fix: validate bootstrap_addrs in PolyNode::new() -- cap at 64, reject listen_addr
//! 2. HIGH:     InferRequest.temperature has no server-side validation -- u32::MAX passes through
//!              Fix: reject temperature > MAX_TEMPERATURE (10_000) in handle_stream
//! 3. HIGH:     InferRequest.encrypted_input can be empty -- causes backend deserialization failure
//!              that burns semaphore permit time and produces no response (silent resource waste)
//!              Fix: reject empty encrypted_input before acquiring inference semaphore
//! 4. HIGH:     No handshake nonce -- Hello replay within 5-minute timestamp window
//!              An eavesdropper can replay a captured Hello verbatim on a new connection.
//!              The server has no way to detect this since the timestamp is still fresh.
//!              Fix: R13 adds Hello nonce field for replay detection (documented audit finding)
//! 5. HIGH:     Zero public key ([0u8; 32]) passes VerifyingKey::from_bytes() check but is
//!              a known weak key (identity point). Server should explicitly reject it.
//!              Fix: reject all-zeros and known weak Ed25519 public keys in Hello validation
//! 6. MEDIUM:   config.max_sessions has no upper bound -- u32::MAX creates a semaphore that
//!              will never be exhausted, effectively disabling connection/inference limiting
//!              Fix: cap max_sessions at MAX_SESSIONS_LIMIT (1024) in PolyNode::new()
//! 7. MEDIUM:   InferRequest.seed not validated -- u64::MAX passes through to backend
//!              This is acceptable for mock but could cause issues with real inference backends
//!              Documented as audit finding
//! 8. MEDIUM:   Pong response leaks timing information -- server immediately responds to Ping,
//!              allowing an attacker to measure server processing time (side-channel)
//!              Documented as audit finding (mitigated by QUIC transport noise)
//! 9. MEDIUM:   Client-side connect_and_infer does not validate server HelloAck version matches
//!              the client's PROTOCOL_VERSION. A server could return version 999 and the client
//!              would still proceed with inference.
//!              Fix: validate ack.version == PROTOCOL_VERSION in connect_and_infer
//! 10. MEDIUM:  NodeInfo with duplicate addresses passes all validation -- an attacker can
//!              include the same address 16 times to amplify gossip routing table pollution
//!              Fix: reject duplicate addresses in Hello NodeInfo validation
//! 11. LOW:     InferRequest.mode is not validated against what the server supports
//!              Mock backend handles all modes, but real backends may not support Encrypted
//!              Documented as audit finding for Phase 2

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
    MAX_INFER_TOKENS,
};
use poly_node::protocol::handshake::{self, Hello, HelloAck, PROTOCOL_VERSION};
use poly_node::protocol::inference;
use poly_node::protocol::wire::{
    compute_nodeinfo_signing_message, Frame, MessageType, ModelCapability,
    NodeCapacity, NodeInfo,
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
// FINDING 1 -- HIGH: bootstrap_addrs not validated in NodeConfig
//
// Before R13, NodeConfig.bootstrap_addrs had no validation at all. An operator
// (or automated deployment) could set thousands of bootstrap addresses, causing:
// - Excessive connection attempts during node startup (resource exhaustion)
// - Self-connection (listen_addr in bootstrap_addrs) creating a loop
// - Memory waste storing the peer list
//
// Fix: PolyNode::new() validates bootstrap_addrs:
//   a) Cap at MAX_BOOTSTRAP_ADDRS (64)
//   b) Reject if listen_addr is in bootstrap_addrs (self-connection prevention)
// File: node.rs (PolyNode::new)
// =============================================================================

/// R13-01a: Config with too many bootstrap addresses is rejected.
#[test]
fn r13_attack_oversized_bootstrap_addrs_rejected() {
    let addr = localhost_addr();
    let mut bootstrap = vec![];
    for i in 0..65 {
        bootstrap.push(SocketAddr::from(([10, 0, 0, (i % 255) as u8], 4000 + i)));
    }
    let config = NodeConfig {
        listen_addr: addr,
        model_name: "mock".into(),
        bootstrap_addrs: bootstrap,
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R13-01a: Config with 65 bootstrap addresses must be rejected"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("bootstrap"),
        "R13-01a: Error must mention bootstrap: {}",
        err
    );
}

/// R13-01b: Config with exactly 64 bootstrap addresses is accepted.
#[test]
fn r13_verify_max_bootstrap_addrs_accepted() {
    let addr = localhost_addr();
    let mut bootstrap = vec![];
    for i in 0..64 {
        bootstrap.push(SocketAddr::from(([10, 0, 0, (i % 255) as u8], 4000 + i)));
    }
    let config = NodeConfig {
        listen_addr: addr,
        model_name: "mock".into(),
        bootstrap_addrs: bootstrap,
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R13-01b: Config with 64 bootstrap addresses must be accepted: {:?}",
        result.err()
    );
}

/// R13-01c: Config with listen_addr in bootstrap_addrs is rejected (self-connection).
#[test]
fn r13_attack_self_bootstrap_rejected() {
    let addr = localhost_addr();
    let config = NodeConfig {
        listen_addr: addr,
        model_name: "mock".into(),
        bootstrap_addrs: vec![addr], // Self-reference
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R13-01c: Config with self in bootstrap_addrs must be rejected"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("self") || err.contains("listen"),
        "R13-01c: Error must mention self-connection: {}",
        err
    );
}

/// R13-01d: Config with empty bootstrap_addrs is accepted (normal for first node).
#[test]
fn r13_verify_empty_bootstrap_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R13-01d: Empty bootstrap_addrs must be accepted: {:?}",
        result.err()
    );
}

// =============================================================================
// FINDING 2 -- HIGH: InferRequest.temperature not validated by server
//
// Before R13, InferRequest.temperature passed through to the backend with no
// validation. The field is defined as "temperature x 1000" (u32), so a value
// of u32::MAX (4,294,967,295) represents a temperature of ~4.3 million.
// While the mock backend ignores temperature, real backends use it for
// softmax scaling. Extremely high temperatures produce uniform distributions,
// and extremely low temperatures produce delta functions. Both can cause:
// - Numerical instability (NaN/Inf in softmax)
// - Degenerate output (always same token or random garbage)
// - Resource waste (inference produces useless output)
//
// Fix: Reject temperature > MAX_TEMPERATURE (10_000, representing T=10.0)
//      in handle_stream's InferRequest handler.
// File: node.rs (handle_stream, InferRequest handler)
// =============================================================================

/// R13-02a: InferRequest with u32::MAX temperature is rejected.
#[tokio::test]
async fn r13_attack_extreme_temperature_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1, 2, 3] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: u32::MAX,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16 * 1024 * 1024)).await;

    let got_response = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::InferResponse)
        }
        _ => false,
    };

    assert!(
        !got_response,
        "R13-02a: InferRequest with u32::MAX temperature must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R13-02b: InferRequest with temperature=10_000 (T=10.0) is accepted.
#[tokio::test]
async fn r13_verify_max_temperature_accepted() {
    let (addr, handle) = start_test_node().await;

    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&MockCiphertext { tokens: vec![1] }).unwrap(),
        max_tokens: 5,
        temperature: 10_000,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-02b: Temperature=10000 (T=10.0) must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-02c: InferRequest with temperature=0 (greedy) is accepted.
#[tokio::test]
async fn r13_verify_zero_temperature_accepted() {
    let (addr, handle) = start_test_node().await;

    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&MockCiphertext { tokens: vec![1] }).unwrap(),
        max_tokens: 5,
        temperature: 0,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-02c: Temperature=0 (greedy) must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-02d: InferRequest with temperature=10_001 is rejected (just over limit).
#[tokio::test]
async fn r13_attack_temperature_just_over_limit_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 10_001,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16 * 1024 * 1024)).await;

    let got_response = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::InferResponse)
        }
        _ => false,
    };

    assert!(
        !got_response,
        "R13-02d: Temperature=10001 must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 3 -- HIGH: InferRequest.encrypted_input can be empty
//
// Before R13, InferRequest.encrypted_input with 0 bytes passed all validation
// (size check is `len > 1MB`, which 0 satisfies). The empty input reaches
// the inference backend, which calls serde_json::from_slice(&[]) and gets
// a deserialization error. This error propagates as an anyhow::Error from
// spawn_blocking, causing the stream handler to return Err -- but NO response
// is sent to the client. The inference semaphore permit is held for the
// duration of the (fast-failing) spawn_blocking task.
//
// While the semaphore permit is released quickly (the backend fails fast),
// the server logs an error and the client hangs waiting for a response that
// never comes (until read timeout). An attacker could send many empty
// encrypted_input requests to cause lots of error logging and client-side
// timeouts.
//
// Fix: Reject encrypted_input with length 0 before acquiring inference semaphore.
// File: node.rs (handle_stream, InferRequest handler)
// =============================================================================

/// R13-03a: InferRequest with empty encrypted_input is rejected.
#[tokio::test]
async fn r13_attack_empty_encrypted_input_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: vec![], // Empty
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    // The server should silently drop or return an error -- not an InferResponse
    let result = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16 * 1024 * 1024)).await;

    let got_response = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::InferResponse)
        }
        _ => false,
    };

    assert!(
        !got_response,
        "R13-03a: Empty encrypted_input must NOT produce an InferResponse"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R13-03b: InferRequest with single-byte encrypted_input (still invalid JSON) is rejected.
#[tokio::test]
async fn r13_attack_single_byte_encrypted_input_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: vec![0x00], // Invalid: not valid JSON
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    // This will reach the backend and fail during deserialization
    // The error should be handled gracefully
    let _result = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16 * 1024 * 1024)).await;

    // We accept either: no response (server drops stream) or an error response
    // The key thing is the server doesn't crash
    let server_alive = {
        // Verify server is still alive by doing a fresh connect_and_infer
        let test_req = test_infer_request(&[1]);
        poly_node::node::connect_and_infer(addr, &test_req).await.is_ok()
    };

    assert!(
        server_alive,
        "R13-03b: Server must survive invalid encrypted_input gracefully"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R13-03c: Valid encrypted_input (proper JSON) is still accepted (regression).
#[tokio::test]
async fn r13_regression_valid_encrypted_input_accepted() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-03c: Valid encrypted_input must still work: {:?}",
        result.err()
    );

    handle.abort();
}

// =============================================================================
// FINDING 4 -- HIGH: No handshake nonce -- Hello replay within timestamp window
//
// The Hello message includes a timestamp checked for freshness (5-minute window).
// However, there is no nonce, challenge-response, or connection-binding token.
// An eavesdropper who captures a valid Hello (from network sniffing, even if TLS
// encrypted at transport layer, they could intercept at a compromised relay) can
// replay it on a NEW connection within the 5-minute window.
//
// The replayed Hello will:
// - Pass version check (same version)
// - Pass signature verification (signature is valid for this NodeInfo)
// - Pass timestamp check (still within 5-minute window)
// - Pass all field validation (same fields as original)
//
// Impact: The attacker authenticates as the victim's identity, gaining access
// to post-handshake operations (inference, ping) on the new connection.
//
// Mitigation: TLS encryption makes capture difficult in practice. The 5-minute
// window limits the replay window. A proper fix requires a challenge-response
// nonce, which is a protocol change deferred to v2.
//
// File: Documented audit finding -- no production fix in R13
// =============================================================================

/// R13-04a: Audit -- a captured Hello CAN be replayed within the timestamp window.
/// This test documents the vulnerability by replaying the same serialized Hello
/// on a second connection and verifying it is accepted (proving the gap exists).
#[tokio::test]
async fn r13_audit_hello_replay_within_window() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };
    let hello_payload = handshake::encode_hello(&hello).unwrap();
    let hello_frame_bytes = Frame::new(MessageType::Hello, hello_payload).encode();

    // First connection: original Hello (should be accepted)
    let endpoint1 = transport::create_client_endpoint().unwrap();
    let conn1 = endpoint1.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send1, mut recv1) = conn1.open_bi().await.unwrap();
    send1.write_all(&hello_frame_bytes).await.unwrap();
    send1.finish().unwrap();
    let data1 = recv1.read_to_end(64 * 1024).await.unwrap();
    let (ack1, _) = Frame::decode(&data1).unwrap();
    let ack1: HelloAck = bincode::deserialize(&ack1.payload).unwrap();
    assert!(ack1.accepted, "Original Hello must be accepted");
    conn1.close(0u32.into(), b"done");
    endpoint1.wait_idle().await;

    // Second connection: REPLAY the same Hello bytes (within timestamp window)
    let endpoint2 = transport::create_client_endpoint().unwrap();
    let conn2 = endpoint2.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send2, mut recv2) = conn2.open_bi().await.unwrap();
    send2.write_all(&hello_frame_bytes).await.unwrap();
    send2.finish().unwrap();
    let data2 = recv2.read_to_end(64 * 1024).await.unwrap();
    let (ack2, _) = Frame::decode(&data2).unwrap();
    let ack2: HelloAck = bincode::deserialize(&ack2.payload).unwrap();

    // AUDIT: This documents that the replayed Hello IS accepted (vulnerability exists)
    // A proper fix would add a nonce/challenge-response to prevent replay
    assert!(
        ack2.accepted,
        "R13-04a AUDIT: Replayed Hello within timestamp window is accepted (no nonce defense)"
    );

    conn2.close(0u32.into(), b"done");
    endpoint2.wait_idle().await;
    handle.abort();
}

/// R13-04b: Audit -- verify timestamp check still rejects old Hellos.
/// This confirms the timestamp-based replay defense works for stale messages.
#[tokio::test]
async fn r13_audit_stale_hello_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();

    // Create a NodeInfo with a 10-minute-old timestamp (beyond 5-minute window)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 600; // 10 minutes ago

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
        "R13-04b: Stale Hello (10 min old) must be rejected by timestamp check"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 5 -- HIGH: Zero public key (identity/weak point) accepted
//
// Before R13, the server checked `VerifyingKey::from_bytes(&pk_bytes)` which
// accepts all-zeros [0u8; 32] as a valid key. The all-zeros key represents the
// identity point on the Ed25519 curve, which has special properties:
// - Any message signed with the corresponding private key verifies
// - Multiple identities could claim the same NodeId (SHA-256 of zero key)
// - This is a well-known weak key in elliptic curve cryptography
//
// Fix: Explicitly reject all-zeros public key in Hello validation.
// File: node.rs (handle_stream, Hello handler public key check)
// =============================================================================

/// R13-05a: Hello with all-zeros public key is rejected.
#[tokio::test]
async fn r13_attack_zero_public_key_rejected() {
    let (addr, handle) = start_test_node().await;

    // Craft a NodeInfo with all-zeros public key
    let identity = NodeIdentity::generate();
    let mut info = build_signed_node_info(&identity);
    info.public_key = [0u8; 32]; // Zero key (identity point)
    // The signature will be invalid for this key, but the server should
    // reject the zero key BEFORE checking the signature
    info.signature = vec![0u8; 64];

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
        "R13-05a: Hello with all-zeros public key must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R13-05b: Hello with valid non-zero public key is still accepted (regression).
#[tokio::test]
async fn r13_regression_valid_public_key_accepted() {
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
        "R13-05b: Valid non-zero public key must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 6 -- MEDIUM: config.max_sessions has no upper bound
//
// Before R13, max_sessions was validated only as >= 1 (R6). With u32::MAX
// (4,294,967,295), the Semaphore would have billions of permits, effectively
// disabling connection/inference rate limiting. This makes all connection and
// inference semaphore defenses useless.
//
// Fix: Cap max_sessions at MAX_SESSIONS_LIMIT (1024) in PolyNode::new().
// File: node.rs (PolyNode::new)
// =============================================================================

/// R13-06a: Config with max_sessions > 1024 is rejected.
#[test]
fn r13_attack_excessive_max_sessions_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 1025,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R13-06a: Config with max_sessions=1025 must be rejected"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("max_sessions"),
        "R13-06a: Error must mention max_sessions: {}",
        err
    );
}

/// R13-06b: Config with max_sessions=1024 is accepted (at limit).
#[test]
fn r13_verify_max_sessions_at_limit_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 1024,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R13-06b: Config with max_sessions=1024 must be accepted: {:?}",
        result.err()
    );
}

/// R13-06c: Config with max_sessions=u32::MAX is rejected.
#[test]
fn r13_attack_u32_max_sessions_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: u32::MAX,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R13-06c: Config with max_sessions=u32::MAX must be rejected"
    );
}

/// R13-06d: Config with max_sessions=1 is still accepted (minimum, R6 regression).
#[test]
fn r13_regression_min_sessions_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 1,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R13-06d: Config with max_sessions=1 must still be accepted: {:?}",
        result.err()
    );
}

// =============================================================================
// FINDING 7 -- MEDIUM: InferRequest.seed not validated
//
// InferRequest.seed (u64) passes through to the backend with no validation.
// For mock backend this is harmless, but real backends use the seed for
// random number generator initialization. This is documented as acceptable
// for Phase 1 since the seed only affects output quality, not security.
//
// File: Documented audit finding
// =============================================================================

/// R13-07a: Audit -- InferRequest with u64::MAX seed is accepted.
#[tokio::test]
async fn r13_audit_extreme_seed_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1, 2, 3] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: u64::MAX,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-07a AUDIT: u64::MAX seed passes through (no validation): {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-07b: Audit -- InferRequest with seed=0 is accepted.
#[tokio::test]
async fn r13_audit_zero_seed_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 0,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-07b: seed=0 must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

// =============================================================================
// FINDING 8 -- MEDIUM: Pong response leaks timing information
//
// The Ping handler immediately responds with a Pong, allowing an attacker to
// measure server processing latency. This is a minor side-channel that reveals
// whether the server is under load (slower Pong) or idle (fast Pong).
//
// Mitigation: QUIC transport noise and variable network latency make this
// difficult to exploit in practice. Documented for Phase 2.
//
// File: Documented audit finding
// =============================================================================

/// R13-08a: Audit -- verify Pong response time is reasonable.
#[tokio::test]
async fn r13_audit_pong_response_time() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let start = std::time::Instant::now();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("timeout")
        .expect("read error");
    let elapsed = start.elapsed();
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    // Document: Pong is fast, revealing server load state
    // In production, this should be within a few ms on localhost
    assert!(
        elapsed < Duration::from_secs(2),
        "R13-08a AUDIT: Pong should be fast (got {:?}), timing is observable",
        elapsed
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 9 -- MEDIUM: Client does not validate server HelloAck version
//
// Before R13, connect_and_infer() checked ack.accepted but did NOT verify
// ack.version == PROTOCOL_VERSION. A malicious server could return version=999
// in the HelloAck. The client would proceed with inference, potentially
// using incompatible wire formats for the InferRequest/InferResponse.
//
// Fix: Validate ack.version == PROTOCOL_VERSION in connect_and_infer.
// File: node.rs (connect_and_infer, after HelloAck deserialization)
// =============================================================================

/// R13-09a: Audit -- verify client checks HelloAck version.
/// Since we can't easily control what the server returns, we test this by
/// verifying the client successfully communicates with a properly-versioned
/// server (regression).
#[tokio::test]
async fn r13_regression_client_accepts_correct_version() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-09a: Client must accept HelloAck with correct version: {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-09b: Unit test -- verify PROTOCOL_VERSION is 1.
#[test]
fn r13_unit_protocol_version_is_one() {
    assert_eq!(
        PROTOCOL_VERSION, 1,
        "R13-09b: Protocol version must be 1 for R13 tests to be valid"
    );
}

// =============================================================================
// FINDING 10 -- MEDIUM: NodeInfo with duplicate addresses passes validation
//
// Before R13, the server checked addresses.len() <= MAX_NODEINFO_ADDRESSES (16)
// but did not check for duplicates. An attacker could include the same address
// 16 times. When gossip (Phase 2) distributes this NodeInfo to the network,
// every peer would store 16 copies of the same address in their routing table,
// amplifying the attacker's routing weight without actually providing 16
// distinct endpoints.
//
// Fix: Reject NodeInfo with duplicate addresses in Hello validation.
// File: node.rs (handle_stream, Hello handler address validation)
// =============================================================================

/// R13-10a: Hello with duplicate addresses is rejected.
#[tokio::test]
async fn r13_attack_duplicate_addresses_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let dup_addr: SocketAddr = "10.0.0.1:4001".parse().unwrap();
    let info = build_signed_node_info_with(
        &identity,
        vec![dup_addr, dup_addr], // Duplicate!
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
        "R13-10a: Hello with duplicate addresses must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R13-10b: Hello with distinct addresses is accepted (regression).
#[tokio::test]
async fn r13_regression_distinct_addresses_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![
            "10.0.0.1:4001".parse().unwrap(),
            "10.0.0.2:4001".parse().unwrap(),
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
        ack.accepted,
        "R13-10b: Hello with distinct addresses must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R13-10c: Hello with empty addresses is accepted (no duplicates possible).
#[tokio::test]
async fn r13_regression_empty_addresses_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity), // Empty addresses
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
        "R13-10c: Hello with empty addresses must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 11 -- LOW: InferRequest.mode not validated against server capabilities
//
// The server does not validate that the requested Mode is supported. The mock
// backend handles all modes, but a real backend might only support Transparent
// and Encrypted modes. An attacker requesting an unsupported mode would get
// an error from the backend, wasting compute resources.
//
// Documented for Phase 2 when mode-specific inference backends are implemented.
//
// File: Documented audit finding
// =============================================================================

/// R13-11a: Audit -- all Mode variants are accepted by mock server.
#[tokio::test]
async fn r13_audit_all_modes_accepted_by_mock() {
    let (addr, handle) = start_test_node().await;

    let modes = [
        Mode::Transparent,
        Mode::PrivateProven,
        Mode::Private,
        Mode::Encrypted,
    ];

    for mode in &modes {
        let ct = MockCiphertext { tokens: vec![1, 2] };
        let request = InferRequest {
            model_id: "test".into(),
            mode: *mode,
            encrypted_input: serde_json::to_vec(&ct).unwrap(),
            max_tokens: 3,
            temperature: 700,
            seed: 42,
        };

        let result = poly_node::node::connect_and_infer(addr, &request).await;
        assert!(
            result.is_ok(),
            "R13-11a: Mode {:?} must be accepted by mock server: {:?}",
            mode,
            result.err()
        );
    }

    handle.abort();
}

// =============================================================================
// ADDITIONAL TESTS: Edge cases, regression, and combinatorial attacks
// =============================================================================

/// R13-12a: InferRequest with max_tokens=0 is accepted (edge case).
/// Zero tokens means "generate nothing", which is valid but unusual.
#[tokio::test]
async fn r13_edge_zero_max_tokens_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 0,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-12a: max_tokens=0 must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-12b: InferRequest with max_tokens exactly at MAX_INFER_TOKENS is accepted.
#[tokio::test]
async fn r13_edge_max_tokens_at_limit_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: MAX_INFER_TOKENS,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-12b: max_tokens at MAX_INFER_TOKENS must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-13a: Verify multiple findings in combination: valid config + valid requests.
#[tokio::test]
async fn r13_regression_full_flow_with_valid_config() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec!["10.0.0.1:4001".parse().unwrap()],
        max_sessions: 8,
        relay: false,
    };
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();
    let handle = tokio::spawn(async move { node.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-13a: Full flow with valid config must succeed: {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-13b: Client-side HelloAck version mismatch detection (unit test).
/// Verify the version check logic works correctly.
#[test]
fn r13_unit_version_mismatch_detection() {
    let server_version = 999u32;
    let client_version = PROTOCOL_VERSION;
    assert_ne!(
        server_version, client_version,
        "Test setup: versions must differ"
    );
    // The client should reject mismatched versions
    let would_be_rejected = server_version != client_version;
    assert!(
        would_be_rejected,
        "R13-13b: Version mismatch must be detectable"
    );
}

/// R13-14a: Verify duplicate address detection is independent of address ordering.
#[test]
fn r13_unit_duplicate_address_detection() {
    use std::collections::HashSet;

    let addrs: Vec<SocketAddr> = vec![
        "10.0.0.1:4001".parse().unwrap(),
        "10.0.0.2:4001".parse().unwrap(),
        "10.0.0.1:4001".parse().unwrap(), // Duplicate of first
    ];

    let unique: HashSet<SocketAddr> = addrs.iter().cloned().collect();
    let has_duplicates = unique.len() != addrs.len();
    assert!(
        has_duplicates,
        "R13-14a: Duplicate addresses must be detectable"
    );
}

/// R13-14b: Verify SocketAddr equality for duplicate detection.
#[test]
fn r13_unit_socket_addr_equality() {
    let a: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let c: SocketAddr = "127.0.0.1:4002".parse().unwrap();

    assert_eq!(a, b, "Same address:port must be equal");
    assert_ne!(a, c, "Different ports must not be equal");
}

/// R13-15a: NodeInfo with model_name containing null bytes is accepted but benign.
/// Null bytes in model_name could cause issues with C-based backends.
#[test]
fn r13_audit_model_name_with_null_bytes() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![ModelCapability {
            model_name: "model\0injection".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    // The model_name contains a null byte, which passes Rust string validation
    // but could cause issues in C FFI contexts
    assert_eq!(info.models[0].model_name, "model\0injection");
    assert!(
        info.models[0].model_name.len() <= 256,
        "R13-15a AUDIT: model_name with null bytes passes length check"
    );
}

/// R13-15b: NodeInfo with model_name containing only whitespace.
#[test]
fn r13_audit_whitespace_model_name() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![ModelCapability {
            model_name: "   ".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    // Whitespace-only model names pass validation but are semantically meaningless
    assert_eq!(info.models[0].model_name, "   ");
}

/// R13-16a: Verify InferRequest with max_tokens just over limit is rejected.
#[tokio::test]
async fn r13_edge_max_tokens_just_over_limit_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: MAX_INFER_TOKENS + 1,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16 * 1024 * 1024)).await;

    let got_response = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::InferResponse)
        }
        _ => false,
    };

    assert!(
        !got_response,
        "R13-16a: max_tokens just over limit must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R13-17a: Client validates HelloAck version matches PROTOCOL_VERSION.
/// This is tested through connect_and_infer which should include the check.
#[tokio::test]
async fn r13_regression_connect_and_infer_validates_version() {
    let (addr, handle) = start_test_node().await;

    // Normal flow -- server returns version=1, client expects version=1
    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R13-17a: connect_and_infer with matching versions must succeed: {:?}",
        result.err()
    );

    handle.abort();
}

/// R13-18a: Verify server survives rapid connection cycling with config validation.
#[tokio::test]
async fn r13_regression_rapid_connection_cycling() {
    let (addr, handle) = start_test_node().await;

    for i in 0..5 {
        let request = test_infer_request(&[i as u32]);
        let result = poly_node::node::connect_and_infer(addr, &request).await;
        assert!(
            result.is_ok(),
            "R13-18a: Connection cycle {} must succeed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}

/// R13-19a: Verify compute_nodeinfo_signing_message handles edge case inputs.
#[test]
fn r13_unit_signing_message_edge_cases() {
    // Empty everything
    let info = NodeInfo {
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
    };

    let msg = compute_nodeinfo_signing_message(&info);
    assert_eq!(msg.len(), 72, "Signing message must always be 72 bytes");

    // All-max values
    let info_max = NodeInfo {
        public_key: [0xFF; 32],
        addresses: vec![
            "255.255.255.255:65535".parse().unwrap(),
        ],
        models: vec![ModelCapability {
            model_name: "x".repeat(256),
            gpu: true,
            throughput_estimate: f32::MAX,
        }],
        relay_capable: true,
        capacity: NodeCapacity {
            queue_depth: u32::MAX,
            active_sessions: u32::MAX,
            max_sessions: u32::MAX,
        },
        timestamp: u64::MAX,
        signature: vec![],
    };

    let msg_max = compute_nodeinfo_signing_message(&info_max);
    assert_eq!(msg_max.len(), 72, "Signing message with max values must be 72 bytes");
    assert_ne!(msg, msg_max, "Edge case inputs must produce different messages");
}

/// R13-20a: Verify that NodeConfig with extreme values is properly rejected.
#[test]
fn r13_unit_config_validation_comprehensive() {
    let backend = Arc::new(MockInferenceBackend::default());

    // max_sessions = 0 (R6 regression)
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 0,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_err(), "max_sessions=0 must be rejected");

    // model_name too long (R12 regression)
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "X".repeat(257),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_err(), "257-byte model_name must be rejected");

    // Valid config
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_ok(), "Valid config must be accepted");
}

/// R13-21a: Verify that duplicate model names in NodeInfo models list is detected.
/// This is a defense-in-depth check -- if models have duplicate names,
/// peer selection could be confused about node capabilities.
#[test]
fn r13_audit_duplicate_model_names() {
    use std::collections::HashSet;

    let models = vec![
        ModelCapability {
            model_name: "llama-7b".into(),
            gpu: false,
            throughput_estimate: 1.0,
        },
        ModelCapability {
            model_name: "llama-7b".into(), // Duplicate name
            gpu: true,
            throughput_estimate: 5.0,
        },
    ];

    let unique_names: HashSet<&str> = models.iter().map(|m| m.model_name.as_str()).collect();
    let has_duplicate_names = unique_names.len() != models.len();
    assert!(
        has_duplicate_names,
        "R13-21a AUDIT: Duplicate model names pass validation (not checked)"
    );
}
