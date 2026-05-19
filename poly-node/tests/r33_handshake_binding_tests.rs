//! Round 33 pentest attack tests for poly-node: handshake connection binding.
//!
//! Vulnerability discovered and fixed in this round:
//!
//! HIGH: Hello handshake replay / node impersonation. Before R33, a `Hello`
//!       frame was a self-contained, self-authenticating message — a `NodeInfo`
//!       plus an Ed25519 signature over that `NodeInfo`. Nothing in it was tied
//!       to the QUIC connection it travelled on. An eavesdropper who captured a
//!       victim's `Hello` could open its own QUIC connection to the server and
//!       replay the captured bytes verbatim: the signature still verified, so
//!       the server completed the handshake believing it was talking to the
//!       victim. Any per-identity authorization (rate limits, access control,
//!       accounting) could then be exercised under the victim's identity.
//!
//!       Fix: R33 adds a mandatory `HelloBinding` frame (MessageType `0x03`)
//!       that must immediately follow the `Hello` on the same handshake stream.
//!       Its payload is an Ed25519 signature, by the same node identity, over
//!       `compute_handshake_binding_message(connection_exporter, public_key)`.
//!       The `connection_exporter` is RFC 5705 exported TLS keying material —
//!       unique to each QUIC connection and independently derivable by both
//!       endpoints. The server recomputes the message from *its* view of the
//!       connection and verifies the signature. A `Hello` replayed onto a
//!       different connection carries a binding over the wrong exporter and is
//!       rejected.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::{verify_signature, NodeIdentity};
use poly_node::net::transport;
use poly_node::node::{
    build_signed_node_info, connect_and_infer, connection_exporter, PolyNode,
};
use poly_node::protocol::handshake::{self, Hello, HelloAck, PROTOCOL_VERSION};
use poly_node::protocol::wire::{
    compute_handshake_binding_message, Frame, MessageType,
};

// ─── Helpers ─────────────────────────────────────────────────────────────

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

async fn start_test_node() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = test_config();
    let addr = config.listen_addr;
    let backend = Arc::new(MockInferenceBackend::default());
    let node = PolyNode::new(config, backend).unwrap();
    let handle = tokio::spawn(async move { node.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, handle)
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

async fn client_conn(addr: SocketAddr) -> (quinn::Endpoint, quinn::Connection) {
    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    (endpoint, conn)
}

/// A valid, fully-signed `Hello` frame for `identity`.
fn hello_frame_for(identity: &NodeIdentity) -> Frame {
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(identity),
    };
    Frame::new(MessageType::Hello, handshake::encode_hello(&hello).unwrap())
}

/// The correct `HelloBinding` frame for `identity` on connection `conn`.
fn binding_frame_for(conn: &quinn::Connection, identity: &NodeIdentity) -> Frame {
    let exporter = connection_exporter(conn).unwrap();
    let msg = compute_handshake_binding_message(
        &exporter,
        &identity.public_key_bytes(),
    );
    Frame::new(MessageType::HelloBinding, identity.sign(&msg).to_vec())
}

/// Open a stream, write the given frames in order, and return the decoded
/// `HelloAck` the server replies with.
async fn run_handshake(conn: &quinn::Connection, frames: &[&Frame]) -> HelloAck {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    for f in frames {
        send.write_all(&f.encode()).await.unwrap();
    }
    send.finish().unwrap();
    let data = recv.read_to_end(64 * 1024).await.unwrap();
    let (ack_frame, _) = Frame::decode(&data).unwrap();
    assert_eq!(ack_frame.msg_type, MessageType::HelloAck);
    bincode::deserialize(&ack_frame.payload).unwrap()
}

// ─── Unit tests: binding message + message type ──────────────────────────

/// R33-U1: `HelloBinding` occupies wire type byte `0x03` and round-trips.
#[test]
fn r33_unit_hellobinding_message_type_byte() {
    assert_eq!(MessageType::HelloBinding as u8, 0x03);
    assert_eq!(
        MessageType::from_u8(0x03),
        Some(MessageType::HelloBinding),
        "type byte 0x03 must decode to HelloBinding"
    );
}

/// R33-U2: the binding message is `domain_tag(30) || public_key(32) || exporter(32)`.
#[test]
fn r33_unit_binding_message_layout() {
    let exporter = [0x11u8; 32];
    let pubkey = [0x22u8; 32];
    let msg = compute_handshake_binding_message(&exporter, &pubkey);

    assert_eq!(msg.len(), 94, "binding message must be 30 + 32 + 32 bytes");
    assert_eq!(&msg[0..30], b"poly-node/handshake-binding/v1");
    assert_eq!(&msg[30..62], &pubkey, "bytes 30..62 must be the public key");
    assert_eq!(&msg[62..94], &exporter, "bytes 62..94 must be the exporter");
}

/// R33-U3: a different connection exporter yields a different binding message.
/// This is what makes a replayed binding fail on a fresh connection.
#[test]
fn r33_unit_binding_message_distinct_per_exporter() {
    let pubkey = [0x22u8; 32];
    let m1 = compute_handshake_binding_message(&[1u8; 32], &pubkey);
    let m2 = compute_handshake_binding_message(&[2u8; 32], &pubkey);
    assert_ne!(
        m1, m2,
        "distinct exporters must produce distinct binding messages"
    );
}

/// R33-U4: a different public key yields a different binding message.
#[test]
fn r33_unit_binding_message_distinct_per_pubkey() {
    let exporter = [0x33u8; 32];
    let m1 = compute_handshake_binding_message(&exporter, &[1u8; 32]);
    let m2 = compute_handshake_binding_message(&exporter, &[2u8; 32]);
    assert_ne!(
        m1, m2,
        "distinct public keys must produce distinct binding messages"
    );
}

/// R33-U5: a signature over the binding message verifies under the signer's key.
#[test]
fn r33_unit_binding_signature_round_trips() {
    let identity = NodeIdentity::generate();
    let exporter = [0x44u8; 32];
    let msg = compute_handshake_binding_message(
        &exporter,
        &identity.public_key_bytes(),
    );
    let sig = identity.sign(&msg);
    assert!(
        verify_signature(identity.verifying_key(), &msg, &sig),
        "binding signature must verify under the signer's verifying key"
    );

    // And it must NOT verify under a different identity's key.
    let other = NodeIdentity::generate();
    assert!(
        !verify_signature(other.verifying_key(), &msg, &sig),
        "binding signature must not verify under a different key"
    );
}

/// R33-U6: the domain-separation tag prevents the binding message from
/// colliding with a bare `public_key || exporter` concatenation.
#[test]
fn r33_unit_binding_message_domain_separated() {
    let exporter = [0x55u8; 32];
    let pubkey = [0x66u8; 32];
    let msg = compute_handshake_binding_message(&exporter, &pubkey);

    assert!(msg.starts_with(b"poly-node/handshake-binding/v1"));

    let mut untagged = Vec::new();
    untagged.extend_from_slice(&pubkey);
    untagged.extend_from_slice(&exporter);
    assert_ne!(
        msg, untagged,
        "the binding message must not equal an untagged pubkey||exporter blob"
    );
}

// ─── Integration tests: verify the happy path ────────────────────────────

/// R33-01: a Hello followed by a correct HelloBinding completes the handshake.
#[tokio::test]
async fn r33_verify_valid_binding_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&identity);
    let binding = binding_frame_for(&conn, &identity);
    let ack = run_handshake(&conn, &[&hello, &binding]).await;

    assert!(
        ack.accepted,
        "R33-01: a Hello with a valid connection binding must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ─── Integration tests: replay / forgery rejection ───────────────────────

/// R33-02: a Hello with no HelloBinding frame is rejected.
#[tokio::test]
async fn r33_attack_missing_binding_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&identity);
    let ack = run_handshake(&conn, &[&hello]).await;

    assert!(
        !ack.accepted,
        "R33-02: a Hello with no HelloBinding frame must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-03: sending the HelloBinding *before* the Hello is rejected. The server
/// reads the first frame as a non-Hello with trailing data and drops the
/// stream (R12 trailing-data defense) without completing a handshake.
#[tokio::test]
async fn r33_attack_binding_before_hello_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&identity);
    let binding = binding_frame_for(&conn, &identity);

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    // Wrong order: binding first, then hello.
    send.write_all(&binding.encode()).await.unwrap();
    send.write_all(&hello.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(64 * 1024).await.unwrap();

    // The server either closes the stream with no reply, or replies with a
    // non-accepted HelloAck. Either way the handshake must not be accepted.
    if !data.is_empty() {
        let (ack_frame, _) = Frame::decode(&data).unwrap();
        let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
        assert!(
            !ack.accepted,
            "R33-03: binding-before-hello must not complete a handshake"
        );
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-04: the core replay defense. A Hello + HelloBinding captured from one
/// connection, replayed verbatim on a fresh connection, is rejected because
/// the binding was signed over the *first* connection's exporter.
#[tokio::test]
async fn r33_attack_replay_binding_other_connection_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = hello_frame_for(&identity);

    // Connection 1: legitimate handshake — binding signed over conn1's exporter.
    let (endpoint1, conn1) = client_conn(addr).await;
    let binding1 = binding_frame_for(&conn1, &identity);
    let ack1 = run_handshake(&conn1, &[&hello, &binding1]).await;
    assert!(ack1.accepted, "original handshake must be accepted");
    conn1.close(0u32.into(), b"done");
    endpoint1.wait_idle().await;

    // Connection 2: replay conn1's exact Hello AND conn1's exact binding.
    let (endpoint2, conn2) = client_conn(addr).await;
    let ack2 = run_handshake(&conn2, &[&hello, &binding1]).await;
    assert!(
        !ack2.accepted,
        "R33-04: a binding replayed from another connection must be rejected"
    );

    conn2.close(0u32.into(), b"done");
    endpoint2.wait_idle().await;
    handle.abort();
}

/// R33-05: a binding signed by a key other than the Hello's node identity is
/// rejected — even when it covers the correct exporter and the correct
/// (victim) public key.
#[tokio::test]
async fn r33_attack_binding_signed_by_wrong_key_rejected() {
    let (addr, handle) = start_test_node().await;

    let victim = NodeIdentity::generate();
    let attacker = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&victim);
    // Sign the correct binding message (real exporter, victim's pubkey) but
    // with the attacker's key.
    let exporter = connection_exporter(&conn).unwrap();
    let msg = compute_handshake_binding_message(
        &exporter,
        &victim.public_key_bytes(),
    );
    let forged = Frame::new(MessageType::HelloBinding, attacker.sign(&msg).to_vec());
    let ack = run_handshake(&conn, &[&hello, &forged]).await;

    assert!(
        !ack.accepted,
        "R33-05: a binding signed by a non-identity key must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-06: a HelloBinding frame carrying 64 bytes of garbage (not a real
/// signature) is rejected.
#[tokio::test]
async fn r33_attack_binding_garbage_signature_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&identity);
    let garbage = Frame::new(MessageType::HelloBinding, vec![0x42u8; 64]);
    let ack = run_handshake(&conn, &[&hello, &garbage]).await;

    assert!(
        !ack.accepted,
        "R33-06: a HelloBinding with a garbage signature must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-07: a second frame that is not a HelloBinding (here, a Ping) does not
/// satisfy the binding requirement.
#[tokio::test]
async fn r33_attack_binding_wrong_frame_type_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&identity);
    let not_a_binding = Frame::new(MessageType::Ping, vec![]);
    let ack = run_handshake(&conn, &[&hello, &not_a_binding]).await;

    assert!(
        !ack.accepted,
        "R33-07: a non-HelloBinding second frame must not satisfy the binding"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-08: a HelloBinding frame whose payload is not exactly 64 bytes (an
/// Ed25519 signature length) is rejected.
#[tokio::test]
async fn r33_attack_binding_wrong_payload_length_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&identity);
    let short = Frame::new(MessageType::HelloBinding, vec![0u8; 32]);
    let ack = run_handshake(&conn, &[&hello, &short]).await;

    assert!(
        !ack.accepted,
        "R33-08: a HelloBinding with a non-64-byte payload must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-09: a binding signed over an all-zero exporter (rather than the real
/// connection exporter) is rejected.
#[tokio::test]
async fn r33_attack_binding_over_zero_exporter_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;

    let hello = hello_frame_for(&identity);
    // Correct key + correct pubkey, but the wrong exporter.
    let msg = compute_handshake_binding_message(
        &[0u8; 32],
        &identity.public_key_bytes(),
    );
    let bad = Frame::new(MessageType::HelloBinding, identity.sign(&msg).to_vec());
    let ack = run_handshake(&conn, &[&hello, &bad]).await;

    assert!(
        !ack.accepted,
        "R33-09: a binding over the wrong exporter must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-10: each QUIC connection has a distinct keying-material exporter, and
/// the exporter is stable for the lifetime of a given connection.
#[tokio::test]
async fn r33_verify_distinct_connections_have_distinct_exporters() {
    let (addr, handle) = start_test_node().await;

    let (endpoint1, conn1) = client_conn(addr).await;
    let (endpoint2, conn2) = client_conn(addr).await;

    let e1 = connection_exporter(&conn1).unwrap();
    let e2 = connection_exporter(&conn2).unwrap();
    assert_ne!(
        e1, e2,
        "R33-10: distinct connections must have distinct exporters"
    );
    assert_ne!(e1, [0u8; 32], "exporter must not be all-zero");

    // Stable for a given connection.
    let e1_again = connection_exporter(&conn1).unwrap();
    assert_eq!(
        e1, e1_again,
        "R33-10: the exporter must be stable for a connection"
    );

    conn1.close(0u32.into(), b"done");
    conn2.close(0u32.into(), b"done");
    endpoint1.wait_idle().await;
    endpoint2.wait_idle().await;
    handle.abort();
}

// ─── Integration tests: regression ───────────────────────────────────────

/// R33-11: a rejected binding does not break the server — a fresh connection
/// with a valid binding still handshakes afterwards.
#[tokio::test]
async fn r33_regression_server_survives_rejected_binding() {
    let (addr, handle) = start_test_node().await;

    // Bad connection: Hello with a garbage binding.
    {
        let identity = NodeIdentity::generate();
        let (endpoint, conn) = client_conn(addr).await;
        let hello = hello_frame_for(&identity);
        let garbage = Frame::new(MessageType::HelloBinding, vec![0x99u8; 64]);
        let ack = run_handshake(&conn, &[&hello, &garbage]).await;
        assert!(!ack.accepted, "garbage binding must be rejected");
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    // Good connection afterwards.
    let identity = NodeIdentity::generate();
    let (endpoint, conn) = client_conn(addr).await;
    let hello = hello_frame_for(&identity);
    let binding = binding_frame_for(&conn, &identity);
    let ack = run_handshake(&conn, &[&hello, &binding]).await;
    assert!(
        ack.accepted,
        "R33-11: server must still accept a valid handshake after a rejected one"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R33-12: end-to-end — `connect_and_infer` (which sends its own binding)
/// completes a handshake and an inference.
#[tokio::test]
async fn r33_regression_inference_after_binding() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R33-12: connect_and_infer must complete with the binding handshake: {:?}",
        result.err()
    );

    handle.abort();
}

/// R33-13: two different clients each handshake successfully with their own
/// connection-specific bindings — the binding is per-(connection, identity).
#[tokio::test]
async fn r33_regression_two_clients_independent_bindings() {
    let (addr, handle) = start_test_node().await;

    let id_a = NodeIdentity::generate();
    let (endpoint_a, conn_a) = client_conn(addr).await;
    let ack_a = run_handshake(
        &conn_a,
        &[&hello_frame_for(&id_a), &binding_frame_for(&conn_a, &id_a)],
    )
    .await;
    assert!(ack_a.accepted, "client A handshake must be accepted");

    let id_b = NodeIdentity::generate();
    let (endpoint_b, conn_b) = client_conn(addr).await;
    let ack_b = run_handshake(
        &conn_b,
        &[&hello_frame_for(&id_b), &binding_frame_for(&conn_b, &id_b)],
    )
    .await;
    assert!(
        ack_b.accepted,
        "R33-13: a second client must handshake with its own binding"
    );

    conn_a.close(0u32.into(), b"done");
    conn_b.close(0u32.into(), b"done");
    endpoint_a.wait_idle().await;
    endpoint_b.wait_idle().await;
    handle.abort();
}
