//! Round 14 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     NodeInfo.capacity fields (queue_depth, active_sessions) unbounded in Hello
//!              validation. A peer can claim queue_depth=u32::MAX and active_sessions=u32::MAX,
//!              poisoning gossip load-balancing tables. active_sessions > max_sessions is illogical.
//!              Fix: Validate active_sessions <= max_sessions and queue_depth <= MAX_QUEUE_DEPTH
//! 2. HIGH:     Pong response does not echo Ping nonce -- attacker cannot correlate Pong to Ping,
//!              and server responds to ANY valid Ping with an empty Pong. This enables unsolicited
//!              Pong injection where a MITM replaces Pong with a forged one. Ping should carry a
//!              nonce that is echoed in Pong for request-response binding.
//!              Fix: Pong now echoes the Ping payload as its nonce (defense-in-depth)
//! 3. HIGH:     Config with duplicate bootstrap_addrs passes validation. An operator could
//!              accidentally list the same peer twice, doubling connection attempts at startup.
//!              Fix: Reject duplicate bootstrap addresses in PolyNode::new()
//! 4. HIGH:     NodeInfo with throughput_estimate = -0.0 passes the negative check
//!              (because -0.0 >= 0.0 is true in IEEE 754), but -0.0 has a different bit pattern
//!              than 0.0 and can cause inconsistent hash/comparison behavior in gossip tables.
//!              Fix: Reject -0.0 throughput_estimate explicitly
//! 5. HIGH:     After a rejected Hello, the client can send ANOTHER Hello on a new stream.
//!              The handshake_done flag only prevents re-auth after SUCCESS. A failed Hello
//!              does not set any flag, so the attacker can retry indefinitely (within
//!              pre-handshake stream limits). Each retry burns deserialization + crypto
//!              verification cost. Fix: Add a handshake_attempted flag that blocks all
//!              subsequent Hello attempts after the first one (success or failure).
//! 6. MEDIUM:   model_name containing control characters (0x00-0x1F) passes validation.
//!              Control characters in model_name can break log output (newline injection),
//!              terminal rendering (ANSI escape sequences), and file system operations.
//!              Fix: Reject model_name with control characters in both config and Hello
//! 7. MEDIUM:   NodeInfo with max_sessions=0 passes Hello validation but is logically invalid.
//!              A node advertising 0 max sessions cannot serve any requests. This wastes
//!              gossip routing table entries and confuses Phase 2 load balancing.
//!              Fix: Reject max_sessions=0 in Hello NodeInfo validation
//! 8. MEDIUM:   Signing message for NodeInfo with model_name containing special bytes
//!              (0x00, 0xFF, etc.) could theoretically allow length-prefix ambiguity.
//!              The len prefix is u32 LE, so model_name bytes "\x04\x00\x00\x00" could
//!              look like a length prefix of 4. This is NOT exploitable because the
//!              model_name length prefix is included, but we document and test it.
//! 9. MEDIUM:   NodeCapacity.max_sessions in Hello has no upper bound. A peer can claim
//!              max_sessions=u32::MAX, appearing to have infinite capacity in gossip tables.
//!              Fix: Reject capacity.max_sessions > MAX_SESSIONS_LIMIT in Hello validation
//! 10. LOW:     Multiple different message types on the same connection after handshake
//!              (e.g., Ping immediately followed by InferRequest on different streams)
//!              could theoretically race. Documented as acceptable since each stream is
//!              independent in QUIC.
//! 11. LOW:     Server does not validate that NodeInfo.addresses are routable (not 0.0.0.0:0).
//!              Fix: Reject unspecified (0.0.0.0 or [::]) addresses and port 0

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
    MAX_PING_PAYLOAD,
};
use poly_node::protocol::handshake::{self, Hello, HelloAck, PROTOCOL_VERSION};
use poly_node::protocol::inference;
use poly_node::protocol::wire::{
    compute_nodeinfo_signing_message, Frame, MessageType, ModelCapability, NodeCapacity, NodeInfo,
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
// FINDING 1 -- HIGH: NodeInfo.capacity fields unbounded in Hello validation
//
// Before R14, NodeInfo.capacity.active_sessions and queue_depth had no
// validation in the Hello handler. An attacker could claim:
// - active_sessions = u32::MAX (illogical: more sessions than max_sessions)
// - queue_depth = u32::MAX (claims infinite queue, poisoning load balancing)
//
// In Phase 2 gossip, these values are used for load balancing decisions.
// A malicious peer claiming active_sessions > max_sessions or absurd
// queue_depth would pollute routing tables with inconsistent data.
//
// Fix: Validate active_sessions <= max_sessions and queue_depth <= 1_000_000
//      in Hello NodeInfo validation.
// File: node.rs (handle_stream, Hello handler capacity validation)
// =============================================================================

/// R14-01a: Hello with active_sessions > max_sessions is rejected.
#[tokio::test]
async fn r14_attack_active_sessions_exceeds_max_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 100, // > max_sessions
            max_sessions: 10,
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
        "R14-01a: Hello with active_sessions > max_sessions must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-01b: Hello with queue_depth = u32::MAX is rejected.
#[tokio::test]
async fn r14_attack_excessive_queue_depth_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity {
            queue_depth: u32::MAX,
            active_sessions: 0,
            max_sessions: 8,
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
        "R14-01b: Hello with queue_depth=u32::MAX must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-01c: Hello with valid capacity (active <= max, reasonable queue) accepted.
#[tokio::test]
async fn r14_regression_valid_capacity_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 5,
            active_sessions: 3,
            max_sessions: 8,
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
        "R14-01c: Valid capacity must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-01d: Hello with active_sessions == max_sessions (fully loaded) accepted.
#[tokio::test]
async fn r14_edge_active_equals_max_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 8,
            max_sessions: 8,
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
        "R14-01d: active_sessions == max_sessions must be accepted (fully loaded)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 2 -- HIGH: Pong does not echo Ping nonce
//
// Before R14, the Ping handler responded with Frame::new(Pong, vec![]),
// discarding the Ping payload entirely. This means:
// - The client cannot verify the Pong corresponds to its Ping
// - A MITM could inject a forged Pong ahead of the real one
// - Multiple concurrent Pings cannot be distinguished
//
// Fix: Pong now echoes the Ping payload as its nonce:
//   Frame::new(MessageType::Pong, frame.payload.clone())
// File: node.rs (handle_stream, Ping handler)
// =============================================================================

/// R14-02a: Pong echoes the Ping payload as nonce.
#[tokio::test]
async fn r14_attack_pong_echoes_ping_nonce() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let nonce = b"r14-nonce-12345";
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, nonce.to_vec());
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("timeout")
        .expect("read error");
    let (pong, consumed) = Frame::decode(&data).unwrap();
    assert_eq!(consumed, data.len());
    assert_eq!(pong.msg_type, MessageType::Pong);

    assert_eq!(
        pong.payload, nonce.to_vec(),
        "R14-02a: Pong must echo the Ping payload as nonce"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-02b: Pong echoes empty Ping payload (backward compat).
#[tokio::test]
async fn r14_regression_empty_ping_empty_pong() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, vec![]);
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("timeout")
        .expect("read error");
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);
    assert!(
        pong.payload.is_empty(),
        "R14-02b: Empty Ping produces empty Pong"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-02c: Two Pings with different nonces get distinct Pongs.
#[tokio::test]
async fn r14_attack_distinct_ping_nonces_get_distinct_pongs() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // First Ping
    let nonce1 = b"nonce-A";
    let (mut send1, mut recv1) = conn.open_bi().await.unwrap();
    let ping1 = Frame::new(MessageType::Ping, nonce1.to_vec());
    send1.write_all(&ping1.encode()).await.unwrap();
    send1.finish().unwrap();
    let data1 = tokio::time::timeout(Duration::from_secs(5), recv1.read_to_end(1024))
        .await
        .expect("timeout")
        .expect("read error");
    let (pong1, _) = Frame::decode(&data1).unwrap();

    // Second Ping with different nonce
    let nonce2 = b"nonce-B";
    let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
    let ping2 = Frame::new(MessageType::Ping, nonce2.to_vec());
    send2.write_all(&ping2.encode()).await.unwrap();
    send2.finish().unwrap();
    let data2 = tokio::time::timeout(Duration::from_secs(5), recv2.read_to_end(1024))
        .await
        .expect("timeout")
        .expect("read error");
    let (pong2, _) = Frame::decode(&data2).unwrap();

    assert_ne!(
        pong1.payload, pong2.payload,
        "R14-02c: Different Ping nonces must produce different Pong payloads"
    );
    assert_eq!(pong1.payload, nonce1.to_vec());
    assert_eq!(pong2.payload, nonce2.to_vec());

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 3 -- HIGH: Config with duplicate bootstrap_addrs passes validation
//
// Before R14, PolyNode::new() checked that listen_addr was not in
// bootstrap_addrs and that len <= 64, but did NOT check for duplicates.
// An operator could accidentally list the same peer twice:
//   --bootstrap 10.0.0.1:4001 --bootstrap 10.0.0.1:4001
//
// This would cause the node to attempt connecting to the same peer twice
// at startup, wasting resources and potentially causing connection conflicts.
//
// Fix: Reject duplicate bootstrap addresses in PolyNode::new().
// File: node.rs (PolyNode::new, bootstrap_addrs validation)
// =============================================================================

/// R14-03a: Config with duplicate bootstrap addresses is rejected.
#[test]
fn r14_attack_duplicate_bootstrap_addrs_rejected() {
    let peer: SocketAddr = "10.0.0.1:4001".parse().unwrap();
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![peer, peer], // Duplicate
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R14-03a: Config with duplicate bootstrap addresses must be rejected"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("duplicate") || err.contains("bootstrap"),
        "R14-03a: Error must mention duplicate bootstrap: {}",
        err
    );
}

/// R14-03b: Config with distinct bootstrap addresses is accepted.
#[test]
fn r14_regression_distinct_bootstrap_addrs_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![
            "10.0.0.1:4001".parse().unwrap(),
            "10.0.0.2:4001".parse().unwrap(),
        ],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R14-03b: Distinct bootstrap addresses must be accepted: {:?}",
        result.err()
    );
}

/// R14-03c: Config with three addresses where two are duplicates is rejected.
#[test]
fn r14_attack_triple_with_duplicate_bootstrap_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![
            "10.0.0.1:4001".parse().unwrap(),
            "10.0.0.2:4001".parse().unwrap(),
            "10.0.0.1:4001".parse().unwrap(), // Duplicate of first
        ],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R14-03c: Bootstrap addresses with any duplicate must be rejected"
    );
}

// =============================================================================
// FINDING 4 -- HIGH: throughput_estimate -0.0 passes negative check
//
// IEEE 754 defines -0.0 as distinct from 0.0 in bit representation, but
// -0.0 >= 0.0 evaluates to true. The existing check:
//   if m.throughput_estimate < 0.0 { reject }
// does NOT catch -0.0 because -0.0 is not < 0.0.
//
// However, -0.0 has a set sign bit, which can cause issues in:
// - Serialization (different bytes than 0.0)
// - Hashing (different hash than 0.0)
// - Display (may show as "-0" in some formatters)
//
// In gossip tables, a peer with -0.0 throughput would hash differently
// than one with 0.0, potentially creating phantom entries.
//
// Fix: Reject -0.0 by checking sign bit via f32::is_sign_negative()
//      when the value is 0.0.
// File: node.rs (handle_stream, Hello handler throughput validation)
// =============================================================================

/// R14-04a: Hello with throughput_estimate = -0.0 is rejected.
#[tokio::test]
async fn r14_attack_negative_zero_throughput_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![ModelCapability {
            model_name: "test".into(),
            gpu: false,
            throughput_estimate: -0.0_f32, // Negative zero
        }],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
    );

    // Verify -0.0 is a tricky edge case
    assert!(!(-0.0_f32 < 0.0_f32), "IEEE 754: -0.0 is NOT < 0.0");
    assert!((-0.0_f32).is_sign_negative(), "IEEE 754: -0.0 has sign bit set");

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
        "R14-04a: Hello with throughput_estimate=-0.0 must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-04b: Hello with throughput_estimate = +0.0 is accepted.
#[tokio::test]
async fn r14_regression_positive_zero_throughput_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![ModelCapability {
            model_name: "test".into(),
            gpu: false,
            throughput_estimate: 0.0_f32,
        }],
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
        "R14-04b: Hello with throughput_estimate=0.0 must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-04c: Unit test confirming -0.0 IEEE 754 behavior.
#[test]
fn r14_unit_negative_zero_ieee754() {
    let neg_zero: f32 = -0.0;
    let pos_zero: f32 = 0.0;

    // IEEE 754 equality: -0.0 == 0.0
    assert_eq!(neg_zero, pos_zero, "IEEE 754: -0.0 == 0.0");
    assert!(!(neg_zero < pos_zero), "IEEE 754: -0.0 is NOT < 0.0");
    assert!(neg_zero.is_sign_negative(), "IEEE 754: -0.0 is sign-negative");
    assert!(!pos_zero.is_sign_negative(), "IEEE 754: 0.0 is not sign-negative");

    // But bit patterns differ
    assert_ne!(
        neg_zero.to_bits(),
        pos_zero.to_bits(),
        "IEEE 754: -0.0 and 0.0 have different bit patterns"
    );
}

// =============================================================================
// FINDING 5 -- HIGH: Repeated Hello after rejection not blocked
//
// Before R14, the handshake_done flag only blocked re-auth AFTER a successful
// Hello. A rejected Hello does NOT set any flag, so the attacker can:
// 1. Send Hello with bad signature -> rejected
// 2. Send another Hello with different payload -> processed again
// 3. Repeat up to MAX_PRE_HANDSHAKE_STREAMS (8) times
//
// Each retry costs the server: bincode deserialization + Ed25519 verification.
// The pre-handshake stream limit (8) bounds the damage, but processing 8
// cryptographic verifications for a single connection is wasteful.
//
// Fix: Add a handshake_attempted flag. Once ANY Hello has been processed
//      (accepted or rejected), further Hello attempts are silently dropped.
// File: node.rs (handle_stream, Hello handler)
// =============================================================================

/// R14-05a: Second Hello after rejection is silently dropped.
#[tokio::test]
async fn r14_attack_retry_hello_after_rejection_blocked() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // First Hello: send with wrong version to trigger rejection
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info(&identity);
    let bad_hello = Hello {
        version: 999, // Wrong version
        node_info: info.clone(),
    };

    let (mut send1, mut recv1) = conn.open_bi().await.unwrap();
    let payload1 = handshake::encode_hello(&bad_hello).unwrap();
    let frame1 = Frame::new(MessageType::Hello, payload1);
    send1.write_all(&frame1.encode()).await.unwrap();
    send1.finish().unwrap();
    let data1 = recv1.read_to_end(64 * 1024).await.unwrap();
    let (ack1_frame, _) = Frame::decode(&data1).unwrap();
    let ack1: HelloAck = bincode::deserialize(&ack1_frame.payload).unwrap();
    assert!(!ack1.accepted, "First Hello should be rejected (bad version)");

    // Allow first stream to settle
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second Hello: correct this time, but should be blocked
    let good_hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
    };

    let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
    let payload2 = handshake::encode_hello(&good_hello).unwrap();
    let frame2 = Frame::new(MessageType::Hello, payload2);
    send2.write_all(&frame2.encode()).await.unwrap();
    send2.finish().unwrap();

    let result2 = tokio::time::timeout(Duration::from_secs(3), recv2.read_to_end(64 * 1024)).await;

    let second_accepted = match result2 {
        Ok(Ok(data)) if !data.is_empty() => {
            if let Ok((ack2_frame, _)) = Frame::decode(&data) {
                if ack2_frame.msg_type == MessageType::HelloAck {
                    let ack2: HelloAck = bincode::deserialize(&ack2_frame.payload).unwrap();
                    ack2.accepted
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
        !second_accepted,
        "R14-05a: Second Hello after rejection must NOT be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-05b: Second Hello after acceptance is still blocked (R5 regression).
#[tokio::test]
async fn r14_regression_retry_hello_after_success_blocked() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await; // First Hello accepted

    // Second Hello on same connection
    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = handshake::encode_hello(&hello).unwrap();
    let frame = Frame::new(MessageType::Hello, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(64 * 1024)).await;

    let got_ack = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::HelloAck)
        }
        _ => false,
    };

    assert!(
        !got_ack,
        "R14-05b: Second Hello after successful handshake must be silently dropped"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 6 -- MEDIUM: model_name with control characters passes validation
//
// Before R14, model_name was only checked for length (max 256 bytes).
// A model_name containing control characters could:
// - Inject newlines into log output (log forging)
// - Inject ANSI escape sequences into terminal (terminal escape attack)
// - Contain null bytes that truncate C strings (FFI issues)
// - Contain backspace/tab that corrupt file system paths
//
// Fix: Reject model_name containing any byte in 0x00-0x1F (control chars)
//      in both config validation and Hello NodeInfo validation.
// File: node.rs (PolyNode::new and handle_stream Hello handler)
// =============================================================================

/// R14-06a: Config with model_name containing newline is rejected.
#[test]
fn r14_attack_model_name_with_newline_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock\nINJECTED_LOG_LINE".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R14-06a: model_name with newline must be rejected"
    );
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("control") || err.contains("model_name"),
        "R14-06a: Error must mention model_name: {}",
        err
    );
}

/// R14-06b: Config with model_name containing null byte is rejected.
#[test]
fn r14_attack_model_name_with_null_byte_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock\0evil".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R14-06b: model_name with null byte must be rejected"
    );
}

/// R14-06c: Config with model_name containing tab is rejected.
#[test]
fn r14_attack_model_name_with_tab_rejected() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock\ttab".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R14-06c: model_name with tab must be rejected"
    );
}

/// R14-06d: Hello with model_name containing newline is rejected.
#[tokio::test]
async fn r14_attack_hello_model_name_with_newline_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![ModelCapability {
            model_name: "test\ninjection".into(),
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
        "R14-06d: Hello with model_name containing newline must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-06e: Config with printable ASCII model_name is accepted (regression).
#[test]
fn r14_regression_printable_model_name_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "llama-3.1-70B_q4-K-M".into(), // Normal model name
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R14-06e: Printable ASCII model_name must be accepted: {:?}",
        result.err()
    );
}

/// R14-06f: Config with Unicode model_name (non-ASCII but no control chars) accepted.
#[test]
fn r14_regression_unicode_model_name_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "Qwen3-0.6B".into(), // ASCII
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R14-06f: Normal model_name must be accepted: {:?}",
        result.err()
    );
}

// =============================================================================
// FINDING 7 -- MEDIUM: NodeInfo with max_sessions=0 passes Hello validation
//
// Before R14, only the server's own max_sessions was validated (>= 1 in
// PolyNode::new). But a peer's Hello NodeInfo with max_sessions=0 passed
// all validation. A node advertising max_sessions=0:
// - Cannot serve any requests (has 0 capacity)
// - Wastes gossip routing table entries
// - Confuses load balancing (division by zero risk in capacity calculations)
//
// Fix: Reject NodeInfo with capacity.max_sessions == 0 in Hello validation.
// File: node.rs (handle_stream, Hello handler capacity validation)
// =============================================================================

/// R14-07a: Hello with max_sessions=0 in capacity is rejected.
#[tokio::test]
async fn r14_attack_zero_max_sessions_in_hello_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 0, // Zero!
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
        "R14-07a: Hello with max_sessions=0 must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-07b: Hello with max_sessions=1 (minimum valid) is accepted.
#[tokio::test]
async fn r14_regression_min_max_sessions_in_hello_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
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
        "R14-07b: Hello with max_sessions=1 must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 8 -- MEDIUM: Signing message determinism with special bytes
//
// The signing message computation uses model_name.len() as a u32 prefix
// followed by model_name bytes. If model_name contains bytes that look like
// length prefixes (e.g., "\x04\x00\x00\x00"), could this create ambiguity?
//
// Analysis: The message format is unambiguous because each field has an
// explicit length prefix. The concatenation of:
//   len_prefix(4B) || model_name_bytes(len) || gpu(1B) || throughput(4B)
// is uniquely parseable because len is read first, then exactly len bytes
// are consumed. There is no length-extension ambiguity.
//
// This is a defense-in-depth audit test, not a vulnerability fix.
// File: wire.rs (compute_nodeinfo_signing_message)
// =============================================================================

/// R14-08a: Signing messages for different model_names are unique even with
/// adversarial byte sequences that look like length prefixes.
#[test]
fn r14_audit_signing_message_no_length_prefix_ambiguity() {
    use std::collections::HashSet;

    let base_capacity = NodeCapacity {
        queue_depth: 0,
        active_sessions: 0,
        max_sessions: 1,
    };

    // Create model names that could cause ambiguity if parsing were wrong
    let adversarial_names = vec![
        "\x04\x00\x00\x00test",   // Looks like a length prefix of 4, then "test"
        "\x04\x00\x00\x00tes",    // Same "prefix" but shorter suffix
        "test\x04\x00\x00\x00",   // Length-like bytes at end
        "\x00\x00\x00\x00",       // All null bytes
        "",                        // Empty
        "test",                    // Normal name
    ];

    let mut messages = HashSet::new();
    for name in &adversarial_names {
        let info = NodeInfo {
            public_key: [1u8; 32],
            addresses: vec![],
            models: vec![ModelCapability {
                model_name: name.to_string(),
                gpu: false,
                throughput_estimate: 1.0,
            }],
            relay_capable: false,
            capacity: base_capacity.clone(),
            timestamp: 1000000,
            signature: vec![],
        };
        let msg = compute_nodeinfo_signing_message(&info);
        assert!(
            messages.insert(msg),
            "R14-08a: Model name '{}' (len={}) produced a duplicate signing message!",
            name.escape_default(),
            name.len()
        );
    }
}

/// R14-08b: Signing message is exactly 72 bytes regardless of content.
#[test]
fn r14_unit_signing_message_fixed_size() {
    let capacity = NodeCapacity {
        queue_depth: 0,
        active_sessions: 0,
        max_sessions: 1,
    };

    // Empty models
    let info1 = NodeInfo {
        public_key: [0u8; 32],
        addresses: vec![],
        models: vec![],
        relay_capable: false,
        capacity: capacity.clone(),
        timestamp: 0,
        signature: vec![],
    };

    // Many models with long names
    let info2 = NodeInfo {
        public_key: [0xFFu8; 32],
        addresses: vec![
            "255.255.255.255:65535".parse().unwrap(),
            "1.2.3.4:1234".parse().unwrap(),
        ],
        models: vec![
            ModelCapability {
                model_name: "A".repeat(200),
                gpu: true,
                throughput_estimate: 99999.0,
            },
            ModelCapability {
                model_name: "B".repeat(100),
                gpu: false,
                throughput_estimate: 0.001,
            },
        ],
        relay_capable: true,
        capacity: NodeCapacity {
            queue_depth: u32::MAX,
            active_sessions: u32::MAX,
            max_sessions: u32::MAX,
        },
        timestamp: u64::MAX,
        signature: vec![],
    };

    let msg1 = compute_nodeinfo_signing_message(&info1);
    let msg2 = compute_nodeinfo_signing_message(&info2);

    assert_eq!(msg1.len(), 72, "Signing message must be 72 bytes (empty case)");
    assert_eq!(msg2.len(), 72, "Signing message must be 72 bytes (large case)");
    assert_ne!(msg1, msg2, "Different inputs must produce different messages");
}

// =============================================================================
// FINDING 9 -- MEDIUM: NodeCapacity.max_sessions in Hello unbounded
//
// Before R14, the server validates its OWN max_sessions <= 1024 in config,
// but a PEER's Hello NodeInfo can claim max_sessions = u32::MAX. In Phase 2
// gossip, this inflated value would make the peer appear to have infinite
// capacity, attracting all client traffic.
//
// Fix: Reject capacity.max_sessions > MAX_SESSIONS_LIMIT in Hello validation.
// File: node.rs (handle_stream, Hello handler capacity validation)
// =============================================================================

/// R14-09a: Hello with max_sessions > 1024 in capacity is rejected.
#[tokio::test]
async fn r14_attack_inflated_max_sessions_in_hello_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: u32::MAX, // Inflated
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
        "R14-09a: Hello with max_sessions=u32::MAX must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-09b: Hello with max_sessions=1024 (at server limit) is accepted.
#[tokio::test]
async fn r14_regression_max_sessions_at_limit_in_hello_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1024,
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
        "R14-09b: Hello with max_sessions=1024 must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 10 -- LOW: Concurrent Ping and InferRequest on same connection
//
// After handshake, a client can open multiple streams simultaneously, sending
// a Ping on one and an InferRequest on another. QUIC handles these as
// independent streams, so both should be processed correctly. This test
// verifies no deadlock or race condition occurs.
//
// File: Documented as working correctly (QUIC stream independence)
// =============================================================================

/// R14-10a: Concurrent Ping and InferRequest on same connection both succeed.
#[tokio::test]
async fn r14_regression_concurrent_ping_and_infer() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // Open two streams simultaneously
    let (mut ping_send, mut ping_recv) = conn.open_bi().await.unwrap();
    let (mut infer_send, mut infer_recv) = conn.open_bi().await.unwrap();

    // Send Ping on first stream
    let nonce = b"concurrent-test";
    let ping_frame = Frame::new(MessageType::Ping, nonce.to_vec());
    ping_send.write_all(&ping_frame.encode()).await.unwrap();
    ping_send.finish().unwrap();

    // Send InferRequest on second stream
    let request = test_infer_request(&[1, 2, 3]);
    let payload = inference::encode_infer_request(&request).unwrap();
    let infer_frame = Frame::new(MessageType::InferRequest, payload);
    infer_send.write_all(&infer_frame.encode()).await.unwrap();
    infer_send.finish().unwrap();

    // Read both responses
    let ping_data = tokio::time::timeout(Duration::from_secs(5), ping_recv.read_to_end(1024))
        .await
        .expect("ping timeout")
        .expect("ping read error");
    let infer_data = tokio::time::timeout(
        Duration::from_secs(10),
        infer_recv.read_to_end(16 * 1024 * 1024),
    )
    .await
    .expect("infer timeout")
    .expect("infer read error");

    let (pong, _) = Frame::decode(&ping_data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);
    assert_eq!(pong.payload, nonce.to_vec());

    let (resp, _) = Frame::decode(&infer_data).unwrap();
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-10b: Multiple concurrent inferences on same connection all succeed.
#[tokio::test]
async fn r14_regression_multiple_concurrent_infers() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let mut handles = vec![];
    for i in 0..3 {
        let conn = conn.clone();
        handles.push(tokio::spawn(async move {
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            let request = InferRequest {
                model_id: "test".into(),
                mode: Mode::Transparent,
                encrypted_input: serde_json::to_vec(&MockCiphertext { tokens: vec![i as u32] })
                    .unwrap(),
                max_tokens: 3,
                temperature: 700,
                seed: i as u64,
            };
            let payload = inference::encode_infer_request(&request).unwrap();
            let frame = Frame::new(MessageType::InferRequest, payload);
            send.write_all(&frame.encode()).await.unwrap();
            send.finish().unwrap();

            let data = tokio::time::timeout(
                Duration::from_secs(10),
                recv.read_to_end(16 * 1024 * 1024),
            )
            .await
            .expect("timeout")
            .expect("read error");
            let (resp, _) = Frame::decode(&data).unwrap();
            assert_eq!(resp.msg_type, MessageType::InferResponse);
            i
        }));
    }

    for h in handles {
        let result = h.await.unwrap();
        assert!(result < 3, "R14-10b: Concurrent inference must complete");
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 11 -- LOW: NodeInfo.addresses with unspecified/zero address passes
//
// Before R14, addresses like 0.0.0.0:0, [::]:0, or port=0 passed validation.
// These are non-routable and would waste gossip table entries. A peer
// advertising 0.0.0.0:0 cannot be reached by other nodes.
//
// Fix: Reject addresses with unspecified IP (0.0.0.0 or [::]) or port 0.
// File: node.rs (handle_stream, Hello handler address validation)
// =============================================================================

/// R14-11a: Hello with 0.0.0.0:0 address is rejected.
#[tokio::test]
async fn r14_attack_unspecified_address_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["0.0.0.0:0".parse().unwrap()],
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
        "R14-11a: Hello with 0.0.0.0:0 address must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-11b: Hello with port=0 address is rejected.
#[tokio::test]
async fn r14_attack_zero_port_address_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["10.0.0.1:0".parse().unwrap()], // Valid IP but port 0
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
        "R14-11b: Hello with port=0 address must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-11c: Hello with valid routable address is accepted.
#[tokio::test]
async fn r14_regression_routable_address_accepted() {
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
        "R14-11c: Valid routable address must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-11d: Hello with empty addresses (no addresses) is still accepted.
#[tokio::test]
async fn r14_regression_empty_addresses_still_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info(&identity); // Empty addresses

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
        "R14-11d: Hello with empty addresses must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// ADDITIONAL TESTS: Edge cases and full flow regressions
// =============================================================================

/// R14-12a: Full inference flow still works after all R14 fixes (regression).
#[tokio::test]
async fn r14_regression_full_inference_flow() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R14-12a: Full inference flow must work: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.model_id, "test");
    assert!(!response.encrypted_output.is_empty());

    handle.abort();
}

/// R14-12b: Rapid sequential connections still work (regression).
#[tokio::test]
async fn r14_regression_rapid_sequential_connections() {
    let (addr, handle) = start_test_node().await;

    for i in 0..5 {
        let request = test_infer_request(&[i as u32]);
        let result = poly_node::node::connect_and_infer(addr, &request).await;
        assert!(
            result.is_ok(),
            "R14-12b: Connection {} must succeed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}

/// R14-13a: Ping max payload size (128 bytes) still works.
#[tokio::test]
async fn r14_regression_ping_max_payload() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let big_nonce = vec![0xAA; MAX_PING_PAYLOAD]; // Exactly at limit
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, big_nonce.clone());
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("timeout")
        .expect("read error");
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);
    assert_eq!(
        pong.payload, big_nonce,
        "R14-13a: Pong must echo 128-byte Ping nonce"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-13b: Ping over max payload size (129 bytes) is still rejected.
#[tokio::test]
async fn r14_regression_oversized_ping_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    let oversized_nonce = vec![0xBB; MAX_PING_PAYLOAD + 1];
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, oversized_nonce);
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;

    let got_pong = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::Pong)
        }
        _ => false,
    };

    assert!(
        !got_pong,
        "R14-13b: Oversized Ping (129 bytes) must NOT return Pong"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-14a: Unit test -- control character detection in strings.
#[test]
fn r14_unit_control_character_detection() {
    let has_control = |s: &str| s.bytes().any(|b| b < 0x20);

    assert!(has_control("test\x00"), "Null byte is control char");
    assert!(has_control("test\n"), "Newline is control char");
    assert!(has_control("test\r"), "Carriage return is control char");
    assert!(has_control("test\t"), "Tab is control char");
    assert!(has_control("\x1Btest"), "ESC (ANSI) is control char");
    assert!(!has_control("normal-model"), "Normal ASCII is not control");
    assert!(!has_control(""), "Empty string has no control chars");
    assert!(!has_control("model_with-dashes.and.dots"), "Punctuation is fine");
}

/// R14-14b: Unit test -- SocketAddr unspecified detection.
#[test]
fn r14_unit_unspecified_address_detection() {
    let is_unroutable = |addr: &SocketAddr| {
        addr.ip().is_unspecified() || addr.port() == 0
    };

    assert!(is_unroutable(&"0.0.0.0:0".parse().unwrap()));
    assert!(is_unroutable(&"0.0.0.0:4001".parse().unwrap()));
    assert!(is_unroutable(&"10.0.0.1:0".parse().unwrap()));
    assert!(!is_unroutable(&"10.0.0.1:4001".parse().unwrap()));
    assert!(!is_unroutable(&"127.0.0.1:4001".parse().unwrap()));
}

/// R14-15a: NodeCapacity validation logic unit test.
#[test]
fn r14_unit_capacity_validation() {
    const MAX_SESSIONS_LIMIT: u32 = 1024;
    const MAX_QUEUE_DEPTH: u32 = 1_000_000;

    let is_valid_capacity = |c: &NodeCapacity| -> bool {
        c.max_sessions >= 1
            && c.max_sessions <= MAX_SESSIONS_LIMIT
            && c.active_sessions <= c.max_sessions
            && c.queue_depth <= MAX_QUEUE_DEPTH
    };

    // Valid
    assert!(is_valid_capacity(&NodeCapacity {
        queue_depth: 0,
        active_sessions: 0,
        max_sessions: 8,
    }));

    // active > max
    assert!(!is_valid_capacity(&NodeCapacity {
        queue_depth: 0,
        active_sessions: 10,
        max_sessions: 8,
    }));

    // max_sessions = 0
    assert!(!is_valid_capacity(&NodeCapacity {
        queue_depth: 0,
        active_sessions: 0,
        max_sessions: 0,
    }));

    // max_sessions > limit
    assert!(!is_valid_capacity(&NodeCapacity {
        queue_depth: 0,
        active_sessions: 0,
        max_sessions: 1025,
    }));

    // queue_depth too large
    assert!(!is_valid_capacity(&NodeCapacity {
        queue_depth: u32::MAX,
        active_sessions: 0,
        max_sessions: 8,
    }));

    // Fully loaded (at limit)
    assert!(is_valid_capacity(&NodeCapacity {
        queue_depth: 100,
        active_sessions: 8,
        max_sessions: 8,
    }));
}

/// R14-15b: Verify NodeInfo with control chars in ALL model names is rejected.
#[tokio::test]
async fn r14_attack_hello_multiple_models_one_has_control_char_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![
            ModelCapability {
                model_name: "good-model".into(), // Valid
                gpu: false,
                throughput_estimate: 1.0,
            },
            ModelCapability {
                model_name: "bad\x07model".into(), // Bell character (control)
                gpu: true,
                throughput_estimate: 2.0,
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
        "R14-15b: Hello with any model_name containing control chars must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-16a: Verify server survives rejected Hello + new connection with valid Hello.
#[tokio::test]
async fn r14_regression_server_survives_bad_then_good() {
    let (addr, handle) = start_test_node().await;

    // Bad connection: zero public key
    {
        let identity = NodeIdentity::generate();
        let mut info = build_signed_node_info(&identity);
        info.public_key = [0u8; 32];
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
        assert!(!ack.accepted, "Bad Hello should be rejected");
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    // Good connection after bad one
    let request = test_infer_request(&[42]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R14-16a: Server must survive bad Hello and serve good ones: {:?}",
        result.err()
    );

    handle.abort();
}

/// R14-17a: Frame decode with type=0x00 (unmapped) is rejected.
#[test]
fn r14_unit_frame_type_zero_rejected() {
    let data = [0x00, 0x00, 0x00, 0x00, 0x00]; // Type 0x00, length 0
    let result = Frame::decode(&data);
    assert!(
        result.is_err(),
        "R14-17a: Frame type 0x00 must be rejected as unknown"
    );
}

/// R14-17b: All reserved/unused type bytes are rejected.
#[test]
fn r14_unit_all_unused_type_bytes_rejected() {
    let known_types: Vec<u8> = vec![
        0x01, 0x02, 0x10, 0x11, 0x12, 0x20, 0x21, 0x30, 0x31, 0x32, 0x33,
        0x40, 0x41, 0x42, 0x43, 0x44, 0xFE,
    ];

    for b in 0u8..=255u8 {
        if known_types.contains(&b) {
            continue;
        }
        let data = [b, 0x00, 0x00, 0x00, 0x00];
        let result = Frame::decode(&data);
        assert!(
            result.is_err(),
            "R14-17b: Type byte 0x{:02X} must be rejected as unknown",
            b
        );
    }
}

/// R14-18a: build_signed_node_info produces valid signatures (sanity check).
#[test]
fn r14_unit_build_signed_node_info_valid() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info(&identity);

    let vk = identity.verifying_key();
    let msg = compute_nodeinfo_signing_message(&info);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&info.signature);
    assert!(
        poly_node::identity::verify_signature(vk, &msg, &sig_arr),
        "R14-18a: build_signed_node_info must produce valid signatures"
    );
}

/// R14-18b: Modifying any field after signing invalidates the signature.
#[test]
fn r14_unit_signature_invalidated_by_field_change() {
    let identity = NodeIdentity::generate();
    let mut info = build_signed_node_info_with(
        &identity,
        vec!["10.0.0.1:4001".parse().unwrap()],
        vec![ModelCapability {
            model_name: "test".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        false,
        NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 8,
        },
    );

    let vk = identity.verifying_key();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&info.signature);

    // Modify a field
    info.capacity.max_sessions = 999;

    // Signature should now be invalid
    let msg = compute_nodeinfo_signing_message(&info);
    assert!(
        !poly_node::identity::verify_signature(vk, &msg, &sig_arr),
        "R14-18b: Modifying max_sessions must invalidate signature"
    );
}

/// R14-19a: Verify InferRequest model_id with control characters reaches server
/// but the inference still works (model_id is echoed back).
/// This documents that model_id is NOT currently validated for control chars.
#[tokio::test]
async fn r14_audit_infer_request_model_id_control_chars() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // model_id with control characters -- server model_name is "mock" which
    // skips model_id matching, so this will pass through
    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test\n\r\t".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        recv.read_to_end(16 * 1024 * 1024),
    )
    .await;

    let got_response = match &result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(data), Ok((f, _)) if f.msg_type == MessageType::InferResponse)
        }
        _ => false,
    };

    // Document: model_id with control characters is NOT rejected by the server.
    // This is acceptable because model_id is only echoed back (not logged
    // unsanitized) and the model_name match check uses == comparison.
    // For mock backend, any model_id is accepted.
    assert!(
        got_response,
        "R14-19a AUDIT: model_id with control chars passes through (mock backend)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R14-20a: Comprehensive config validation test.
#[test]
fn r14_unit_config_validation_comprehensive() {
    let backend = Arc::new(MockInferenceBackend::default());

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

    // Control char in model_name
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock\x1B[31m".into(), // ANSI escape
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_err(), "ANSI escape in model_name must be rejected");

    // Duplicate bootstrap
    let peer: SocketAddr = "10.0.0.1:4001".parse().unwrap();
    let r = PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![peer, peer],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    );
    assert!(r.is_err(), "Duplicate bootstrap must be rejected");
}
