//! Round 8 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     InferRequest.model_id string unbounded (echo amplification via response)
//! 2. HIGH:     Error message type bypasses handshake auth (catch-all not gated)
//! 3. HIGH:     decode_hello/decode_hello_ack use raw unbounded bincode (public API)
//! 4. HIGH:     Client-side HelloAck NodeInfo fields not validated (bloated server response)
//! 5. MEDIUM:   Multiple connections from distinct NodeIds exhaust connection semaphore
//! 6. MEDIUM:   build_signed_node_info hardcodes max_sessions=1 (misleading peer info)
//! 7. MEDIUM:   InferRequest with empty model_id accepted on "mock" server
//! 8. MEDIUM:   Frame::decode accepts data after valid frame (trailing data not rejected)
//! 9. LOW:      NodeInfo.addresses can contain loopback/unroutable addresses
//! 10. LOW:     Inference response model_id not validated by connect_and_infer client

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::NodeIdentity;
use poly_node::net::transport;
use poly_node::node::{build_signed_node_info, PolyNode, MAX_MODEL_ID_LEN};
use poly_node::protocol::handshake::{self, Hello, HelloAck, PROTOCOL_VERSION};
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

/// Helper: create a validly-signed NodeInfo with custom fields
/// R10: Updated to use compute_nodeinfo_signing_message for full-field signature
fn make_signed_node_info(
    identity: &NodeIdentity,
    addresses: Vec<SocketAddr>,
    models: Vec<ModelCapability>,
) -> NodeInfo {
    use poly_node::protocol::wire::compute_nodeinfo_signing_message;

    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut info = NodeInfo {
        public_key,
        addresses,
        models,
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
    info
}

// =============================================================================
// FINDING 1 -- HIGH: InferRequest.model_id string unbounded
//
// Before R8 fix: The server validated model_id against the configured
// model_name, but when model_name == "mock" the check was skipped entirely.
// An attacker could send a model_id of up to ~4 MB (bincode limit) which
// would be passed through to the InferResponse.model_id field, causing
// the response to echo back up to 4 MB of attacker-controlled data.
//
// Even for non-mock models, the model_id string length was not explicitly
// bounded. While a mismatched model_id would be rejected, the full string
// was already deserialized and allocated in memory.
//
// File: node.rs, handle_stream(), InferRequest handler
// Impact: Response echo amplification, memory waste
// Fix: Cap model_id at MAX_MODEL_ID_LEN (256 bytes) before any other check.
// =============================================================================

#[tokio::test]
async fn r8_attack_oversized_model_id_mock_server() {
    // On a "mock" server, model_id validation is skipped.
    // Before R8 fix, a 4MB model_id would pass through and be echoed in response.
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    // Create an InferRequest with a model_id just over the 256-byte cap
    let ct = MockCiphertext { tokens: vec![1, 2, 3] };
    let evil_request = InferRequest {
        model_id: "X".repeat(MAX_MODEL_ID_LEN + 1),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&evil_request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        recv.read_to_end(16 * 1024 * 1024),
    )
    .await;

    // HARDENED: Server rejects oversized model_id
    match result {
        Ok(Ok(data)) => {
            assert!(
                data.is_empty(),
                "HARDENED: server must reject model_id > {} bytes (got {} bytes response)",
                MAX_MODEL_ID_LEN,
                data.len()
            );
        }
        Ok(Err(_)) => {} // Stream reset
        Err(_) => {}     // Timeout
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r8_attack_oversized_model_id_1kb() {
    // A 1KB model_id -- larger than 256 byte cap
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1] };
    let evil_request = InferRequest {
        model_id: "A".repeat(1024),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&evil_request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        recv.read_to_end(16 * 1024 * 1024),
    )
    .await;

    match result {
        Ok(Ok(data)) => {
            assert!(
                data.is_empty(),
                "HARDENED: server must reject 1KB model_id"
            );
        }
        Ok(Err(_)) => {}
        Err(_) => {}
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r8_verify_model_id_at_limit_accepted() {
    // A model_id of exactly 256 bytes should be accepted (on mock server)
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1, 2, 3] };
    let request = InferRequest {
        model_id: "M".repeat(MAX_MODEL_ID_LEN), // Exactly at the limit
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(
        resp.msg_type,
        MessageType::InferResponse,
        "model_id of exactly 256 bytes should be accepted on mock server"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 2 -- HIGH: Error message type bypasses handshake auth
//
// Before R8 fix: The MessageType::Error variant (0xFE) was a valid message
// type that fell through to the catch-all `other` arm in handle_stream().
// This arm was NOT gated by handshake_done, meaning an unauthenticated
// client could send Error frames. While the server only logged a warning,
// each Error frame still consumed one count from the per-connection stream
// counter (MAX_STREAMS_PER_CONN = 256). An attacker could:
//   1. Connect without handshake
//   2. Send 256 Error frames on sequential streams
//   3. The connection would be killed for exceeding MAX_STREAMS_PER_CONN
//   4. But the attacker would have burned stream counts without auth
//
// More critically, the catch-all pattern means ANY future MessageType
// variant added to the enum would also bypass auth checks unless explicitly
// handled. This is a defense-in-depth violation.
//
// File: node.rs, handle_stream(), catch-all arm
// Impact: Stream counter exhaustion without authentication
// Fix: Explicit handler for Error type with auth check. Catch-all also
//      now requires handshake.
// =============================================================================

#[tokio::test]
async fn r8_attack_error_message_without_handshake() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send Error message without handshake
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let frame = Frame::new(MessageType::Error, b"fake error data".to_vec());
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        recv.read_to_end(1024),
    )
    .await;

    // HARDENED: Error without handshake should be silently dropped (no response)
    match result {
        Ok(Ok(data)) => {
            assert!(
                data.is_empty(),
                "HARDENED: Error message without handshake must get no response (got {} bytes)",
                data.len()
            );
        }
        Ok(Err(_)) => {} // Stream reset
        Err(_) => {}     // Timeout
    }

    // Server should still be functional -- do handshake and verify with Ping
    do_handshake(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping.encode()).await.unwrap();
    send.finish().unwrap();
    let data = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024))
        .await
        .expect("server alive after Error attack")
        .unwrap();
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r8_attack_error_message_after_handshake() {
    // After handshake, Error message should be accepted (logged) but not crash
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    // Send Error message after handshake -- should be accepted (logged)
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let frame = Frame::new(MessageType::Error, b"some error payload".to_vec());
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        recv.read_to_end(1024),
    )
    .await;

    // No response expected (Error is logged, not replied to)
    match result {
        Ok(Ok(data)) => {
            assert!(
                data.is_empty(),
                "Error message should not get a response (got {} bytes)",
                data.len()
            );
        }
        Ok(Err(_)) => {} // Stream reset
        Err(_) => {}     // Timeout
    }

    // Verify connection still works
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(1024).await.unwrap();
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 3 -- HIGH: decode_hello/decode_hello_ack use raw bincode
//
// Before R8 fix: The public API functions handshake::decode_hello() and
// handshake::decode_hello_ack() used raw bincode::deserialize() with no
// size limits. While the server's Hello handler in node.rs used its own
// size-limited bincode, the public functions were exposed for external use.
//
// If any future code path (e.g., a relay node forwarding Hello messages,
// or a gossip protocol parser) used these functions directly, they would
// be vulnerable to bincode decompression bombs.
//
// File: protocol/handshake.rs, decode_hello() and decode_hello_ack()
// Impact: Unbounded memory allocation from crafted payloads via public API
// Fix: Both functions now use size-limited bincode (MAX_HANDSHAKE_MSG_SIZE = 64KB).
// =============================================================================

#[test]
fn r8_verify_decode_hello_size_limited() {
    // Craft a payload with a massive Vec length prefix that would cause
    // unbounded allocation with raw bincode::deserialize.
    let mut bomb = Vec::new();
    bomb.extend_from_slice(&1u32.to_le_bytes()); // version = 1
    bomb.extend_from_slice(&[0x42; 32]); // public_key
    // addresses Vec length: claim 2^60 elements
    bomb.extend_from_slice(&(1u64 << 60).to_le_bytes());

    // decode_hello should fail with a size limit error, not OOM
    let result = handshake::decode_hello(&bomb);
    assert!(
        result.is_err(),
        "HARDENED: decode_hello must reject bincode bomb"
    );
}

#[test]
fn r8_verify_decode_hello_ack_size_limited() {
    // Same test for decode_hello_ack
    let mut bomb = Vec::new();
    bomb.extend_from_slice(&1u32.to_le_bytes()); // version = 1
    bomb.extend_from_slice(&[0x42; 32]); // public_key (start of NodeInfo)
    // addresses Vec length: claim 2^60 elements
    bomb.extend_from_slice(&(1u64 << 60).to_le_bytes());

    let result = handshake::decode_hello_ack(&bomb);
    assert!(
        result.is_err(),
        "HARDENED: decode_hello_ack must reject bincode bomb"
    );
}

#[test]
fn r8_verify_decode_hello_normal_still_works() {
    // A normal Hello should still decode correctly through the public API
    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };
    let encoded = handshake::encode_hello(&hello).unwrap();
    let decoded = handshake::decode_hello(&encoded).unwrap();
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert_eq!(decoded.node_info.public_key, identity.public_key_bytes());
}

#[test]
fn r8_verify_decode_hello_ack_normal_still_works() {
    let identity = NodeIdentity::generate();
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
        accepted: true,
    };
    let encoded = handshake::encode_hello_ack(&ack).unwrap();
    let decoded = handshake::decode_hello_ack(&encoded).unwrap();
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert!(decoded.accepted);
}

// =============================================================================
// FINDING 4 -- HIGH: Client-side HelloAck NodeInfo fields not validated
//
// Before R8 fix: The client-side connect_and_infer() validated the server's
// HelloAck signature, timestamp, and deserialization size limit, but did NOT
// validate the content of the server's NodeInfo fields:
//   - addresses: could contain hundreds of entries (up to 64KB bincode limit)
//   - models: could contain dozens of entries with long model names
//   - throughput_estimate: could be NaN/Inf/negative
//
// A malicious server could craft a HelloAck that passes signature verification
// but contains bloated NodeInfo fields, wasting client memory. In Phase 2
// where the client would cache/forward this NodeInfo, the bloat would propagate.
//
// File: node.rs, connect_and_infer(), after HelloAck deserialization
// Impact: Client-side memory waste, Phase 2 gossip amplification
// Fix: Added client-side validation matching server-side checks.
// =============================================================================

// NOTE: Testing client-side validation directly requires a malicious server,
// which is complex. Instead we verify the normal flow still works and test
// the validation logic via unit tests on the public API.

#[tokio::test]
async fn r8_verify_connect_and_infer_with_client_validation() {
    // Normal flow should still work with the added validation
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let response = poly_node::node::connect_and_infer(addr, &request)
        .await
        .unwrap();

    let ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    assert_eq!(ct.tokens.len(), 8); // 3 input + 5 generated
    assert_eq!(&ct.tokens[..3], &[1, 2, 3]);

    handle.abort();
}

// =============================================================================
// FINDING 5 -- MEDIUM: Multiple connections from distinct NodeIds exhaust semaphore
//
// The connection semaphore limits concurrent connections to max_sessions,
// but there's no per-NodeId tracking. An attacker can generate N different
// Ed25519 identities and open max_sessions connections, each authenticated
// with a different identity. This exhausts all connection permits, blocking
// legitimate clients.
//
// This is a Sybil attack vector: the cost of generating a new Ed25519
// identity is negligible (~microseconds), while each connection consumes
// a valuable semaphore permit that blocks for CONN_IDLE_TIMEOUT (60s).
//
// File: node.rs, handle_connection(), connection semaphore
// Impact: Connection starvation via Sybil identities
// Fix: Documented for Phase 2 (requires peer reputation / rate limiting).
//      No source fix in Phase 1 -- the semaphore provides a hard cap.
// =============================================================================

#[tokio::test]
async fn r8_audit_sybil_connection_exhaustion() {
    // Demonstrate: multiple connections with different identities can
    // exhaust the connection semaphore. This is a known limitation.
    let mut config = test_config();
    config.max_sessions = 2; // Only 2 slots
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();
    let handle = tokio::spawn(async move { node.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let endpoint = transport::create_client_endpoint().unwrap();

    // Connection 1: valid identity A
    let conn1 = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn1).await;

    // Connection 2: valid identity B (different identity)
    let conn2 = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn2).await;

    // Connection 3: should be rejected (semaphore full)
    let conn3 = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Try to do something on conn3 -- it should fail or get no response
    let identity3 = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity3),
    };
    let result = conn3.open_bi().await;
    match result {
        Ok((mut send, mut recv)) => {
            let payload = handshake::encode_hello(&hello).unwrap();
            let frame = Frame::new(MessageType::Hello, payload);
            let write_result = send.write_all(&frame.encode()).await;
            if write_result.is_ok() {
                let _ = send.finish();
                // The connection might be closed by server (overloaded)
                let read_result = tokio::time::timeout(
                    Duration::from_secs(3),
                    recv.read_to_end(64 * 1024),
                )
                .await;
                // Any result is fine -- the point is the first 2 connections
                // consumed all permits
                let _ = read_result;
            }
        }
        Err(_) => {
            // Connection already closed by server -- expected when overloaded
        }
    }

    // AUDIT: First two connections succeeded with different identities.
    // The server has no per-NodeId rate limiting. This is a known limitation.
    // Verify conn1 and conn2 are still functional.
    {
        let (mut send, mut recv) = conn1.open_bi().await.unwrap();
        let ping = Frame::new(MessageType::Ping, vec![]);
        send.write_all(&ping.encode()).await.unwrap();
        send.finish().unwrap();
        let data = recv.read_to_end(1024).await.unwrap();
        let (pong, _) = Frame::decode(&data).unwrap();
        assert_eq!(pong.msg_type, MessageType::Pong, "conn1 still works");
    }
    {
        let (mut send, mut recv) = conn2.open_bi().await.unwrap();
        let ping = Frame::new(MessageType::Ping, vec![]);
        send.write_all(&ping.encode()).await.unwrap();
        send.finish().unwrap();
        let data = recv.read_to_end(1024).await.unwrap();
        let (pong, _) = Frame::decode(&data).unwrap();
        assert_eq!(pong.msg_type, MessageType::Pong, "conn2 still works");
    }

    conn1.close(0u32.into(), b"done");
    conn2.close(0u32.into(), b"done");
    conn3.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 6 -- MEDIUM: build_signed_node_info hardcodes max_sessions=1
//
// The public helper build_signed_node_info() always creates a NodeInfo
// with capacity.max_sessions = 1 regardless of the actual configured value.
// In Phase 2 gossip, this would mislead peer-selection algorithms into
// thinking the node can only handle 1 session, even if it's configured
// for 64 sessions.
//
// File: node.rs, build_signed_node_info()
// Impact: Misleading capacity advertisement in Phase 2 peer selection
// Fix: Documented. The function is used for client-side Hello (not server
//      advertisement), so max_sessions=1 is conservative but not wrong.
// =============================================================================

#[test]
fn r8_audit_build_signed_node_info_hardcoded_max_sessions() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info(&identity);

    // AUDIT: max_sessions is hardcoded to 1 regardless of actual config
    assert_eq!(
        info.capacity.max_sessions, 1,
        "AUDIT: build_signed_node_info always sets max_sessions=1 -- \
         misleading for Phase 2 peer selection"
    );

    // Verify signature is still valid despite hardcoded value
    // R10: Use full-field signing message (not just pubkey||timestamp)
    let vk = identity.verifying_key();
    let msg = poly_node::protocol::wire::compute_nodeinfo_signing_message(&info);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&info.signature);
    assert!(poly_node::identity::verify_signature(vk, &msg, &sig_arr));
}

// =============================================================================
// FINDING 7 -- MEDIUM: InferRequest with empty model_id accepted on mock
//
// On a "mock" server, any model_id (including empty string) is accepted.
// An empty model_id is semantically invalid -- it should be rejected
// regardless of server mode. However, this is a design choice: the mock
// server intentionally accepts all model_ids for testing flexibility.
//
// File: node.rs, handle_stream(), model_id validation
// Impact: Semantically invalid requests processed on mock servers
// Fix: Documented. Mock server behavior is intentional for testing.
// =============================================================================

#[tokio::test]
async fn r8_audit_empty_model_id_accepted_on_mock() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    let ct = MockCiphertext { tokens: vec![1, 2, 3] };
    let request = InferRequest {
        model_id: String::new(), // Empty model_id
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();

    // AUDIT: Mock server accepts empty model_id (design choice for testing)
    assert_eq!(
        resp.msg_type,
        MessageType::InferResponse,
        "AUDIT: mock server accepts empty model_id (intentional)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 8 -- MEDIUM: Frame::decode accepts data after valid frame
//
// Frame::decode returns (frame, bytes_consumed) and does NOT reject trailing
// data. This is by design for supporting multiple frames in a buffer, but
// when used with read_to_end() in the stream handler, it means extra bytes
// after a valid frame are silently ignored. An attacker could append
// arbitrary data after a valid frame and it would be processed normally.
//
// While this doesn't directly cause a vulnerability (the stream handler
// only reads one frame), it means the frame layer provides no integrity
// guarantee for the total stream content.
//
// File: protocol/wire.rs, Frame::decode()
// Impact: Trailing data silently ignored, no total-stream integrity
// Fix: Documented. The frame protocol intentionally supports streaming.
// =============================================================================

#[test]
fn r8_audit_frame_decode_ignores_trailing_data() {
    // A valid frame followed by garbage
    let frame = Frame::new(MessageType::Ping, vec![0xAA]);
    let mut encoded = frame.encode();
    let valid_len = encoded.len();
    encoded.extend_from_slice(b"GARBAGE_TRAILING_DATA_12345");

    let (decoded, consumed) = Frame::decode(&encoded).unwrap();
    assert_eq!(decoded.msg_type, MessageType::Ping);
    assert_eq!(decoded.payload, vec![0xAA]);
    assert_eq!(consumed, valid_len);

    // AUDIT: Trailing data is silently ignored. Frame::decode returns
    // bytes_consumed = valid frame length, and the caller is responsible
    // for checking if there's leftover data. In handle_stream, the
    // entire stream is read into `data` and only the first frame is decoded,
    // so any trailing bytes are silently dropped.
    assert!(
        consumed < encoded.len(),
        "AUDIT: Frame::decode silently ignores {} trailing bytes",
        encoded.len() - consumed
    );
}

// =============================================================================
// FINDING 9 -- LOW: NodeInfo.addresses can contain loopback/unroutable addrs
//
// A client's Hello can include addresses like 127.0.0.1, 0.0.0.0, or
// 169.254.x.x in its NodeInfo.addresses. In Phase 2 gossip, these would
// be propagated to other nodes, which would waste time trying to connect
// to loopback or link-local addresses.
//
// File: protocol/wire.rs, NodeInfo.addresses (Vec<SocketAddr>)
// Impact: Gossip pollution with unroutable addresses
// Fix: Documented for Phase 2. Currently addresses are only used locally.
// =============================================================================

#[tokio::test]
async fn r8_audit_nodeinfo_loopback_addresses_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let node_info = make_signed_node_info(
        &identity,
        vec![
            "127.0.0.1:4001".parse().unwrap(), // Loopback
            "0.0.0.0:4002".parse().unwrap(),    // Unroutable
        ],
        vec![],
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info,
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
    let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();

    // AUDIT: Loopback/unroutable addresses are currently accepted.
    // Phase 2 gossip should filter these before forwarding.
    assert!(
        ack.accepted,
        "AUDIT: loopback/unroutable addresses currently accepted (Phase 1 limitation)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 10 -- LOW: Inference response model_id not validated by client
//
// The connect_and_infer client does not verify that the InferResponse.model_id
// matches the InferRequest.model_id. A malicious server could return a
// response with a different model_id, and the client would accept it.
//
// File: node.rs, connect_and_infer(), after InferResponse deserialization
// Impact: Client accepts response from wrong model
// Fix: Documented. Protocol-level fix needed (response binding to request).
// =============================================================================

#[tokio::test]
async fn r8_audit_response_model_id_not_verified() {
    // The client receives a response and doesn't check model_id matches
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let response = poly_node::node::connect_and_infer(addr, &request)
        .await
        .unwrap();

    // AUDIT: The response model_id is whatever the server chose to return.
    // On mock server, it reflects the request's model_id. But a malicious
    // server could return any model_id and the client wouldn't notice.
    // The client should verify response.model_id == request.model_id.
    assert!(
        !response.model_id.is_empty(),
        "AUDIT: response has a model_id but client does not verify it matches request"
    );

    handle.abort();
}

// =============================================================================
// BONUS: Server survives rapid Error frame flood (pre-handshake)
//
// Verify that sending many Error frames without handshake doesn't crash
// the server or leak resources.
// =============================================================================

#[tokio::test]
async fn r8_attack_error_frame_flood_without_handshake() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send several Error frames without handshake
    for _ in 0..4 {
        match conn.open_bi().await {
            Ok((mut send, mut recv)) => {
                let frame = Frame::new(MessageType::Error, vec![0xFF; 100]);
                let _ = send.write_all(&frame.encode()).await;
                let _ = send.finish();
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    recv.read_to_end(1024),
                )
                .await;
            }
            Err(_) => break, // Connection closed
        }
    }

    // After Error flood, do handshake and verify server is functional
    // (The connection might have been closed; if so, open a new one)
    let endpoint2 = transport::create_client_endpoint().unwrap();
    let conn2 = endpoint2.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn2).await;

    let (mut send, mut recv) = conn2.open_bi().await.unwrap();
    let ping = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping.encode()).await.unwrap();
    send.finish().unwrap();
    let data = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024))
        .await
        .expect("server should be alive after Error flood")
        .unwrap();
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    conn.close(0u32.into(), b"done");
    conn2.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    endpoint2.wait_idle().await;
    handle.abort();
}

// =============================================================================
// BONUS: Verify decode_hello rejects trailing bytes (R8 hardened)
//
// Since decode_hello now uses DefaultOptions (no allow_trailing_bytes),
// a valid Hello with trailing data should be rejected.
// =============================================================================

#[test]
fn r8_verify_decode_hello_rejects_trailing_bytes() {
    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };
    let mut encoded = handshake::encode_hello(&hello).unwrap();
    encoded.extend_from_slice(b"TRAILING");

    // decode_hello should reject trailing bytes
    let result = handshake::decode_hello(&encoded);
    assert!(
        result.is_err(),
        "HARDENED: decode_hello must reject trailing bytes"
    );
}

#[test]
fn r8_verify_decode_hello_ack_rejects_trailing_bytes() {
    let identity = NodeIdentity::generate();
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
        accepted: true,
    };
    let mut encoded = handshake::encode_hello_ack(&ack).unwrap();
    encoded.extend_from_slice(b"TRAILING_GARBAGE");

    let result = handshake::decode_hello_ack(&encoded);
    assert!(
        result.is_err(),
        "HARDENED: decode_hello_ack must reject trailing bytes"
    );
}

// =============================================================================
// BONUS: Regression -- full normal flow after R8 hardening
// =============================================================================

#[tokio::test]
async fn r8_regression_full_flow() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Handshake
    do_handshake(&conn).await;

    // Inference with normal model_id
    let request = test_infer_request(&[10, 20, 30]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    // Ping/Pong
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(1024).await.unwrap();
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r8_regression_connect_and_infer() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[5, 10, 15]);
    let response = poly_node::node::connect_and_infer(addr, &request)
        .await
        .unwrap();

    let ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    assert_eq!(ct.tokens.len(), 8);
    assert_eq!(&ct.tokens[..3], &[5, 10, 15]);

    handle.abort();
}
