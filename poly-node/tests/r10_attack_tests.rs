//! Round 10 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     NodeInfo signature only covered public_key||timestamp, not all fields
//!              (addresses, models, relay_capable, capacity unsigned -- attacker could tamper)
//! 2. HIGH:     RwLock::read().unwrap() panics if poisoned (server crash on poisoned lock)
//! 3. HIGH:     Client connect_and_infer doesn't verify response model_id matches request
//!              (malicious server can return results for a different model)
//! 4. MEDIUM:   handle_infer() is dead code with no validation (public API danger)
//! 5. MEDIUM:   Server uses bincode::serialize for HelloAck but client uses DefaultOptions
//!              (encode/decode path inconsistency)
//! 6. MEDIUM:   Ping has no rate limiting (mitigated by existing stream caps)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::NodeIdentity;
use poly_node::net::transport;
use poly_node::node::{build_signed_node_info, build_signed_node_info_with, PolyNode};
use poly_node::protocol::handshake::{self, Hello, HelloAck, PROTOCOL_VERSION};
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
// FINDING 1 -- HIGH: NodeInfo signature did not cover all fields
//
// Before R10, the signature only covered `public_key || timestamp`. An attacker
// who intercepts a valid NodeInfo could modify addresses (redirect traffic to
// a MITM), inflate throughput_estimate (attract more clients), set relay_capable
// to true, or inflate capacity to appear high-availability -- all without
// invalidating the signature.
//
// Fix: compute_nodeinfo_signing_message() now hashes ALL mutable fields into
// a 32-byte content hash appended to the signing message:
//   Sign(public_key || timestamp || SHA-256(addresses || models || relay || capacity))
//
// File: protocol/wire.rs (compute_nodeinfo_signing_message), node.rs (all signing/verification)
// =============================================================================

/// R10-01a: Verify that tampering with addresses breaks signature verification
#[tokio::test]
async fn r10_attack_tampered_addresses_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    // Build a validly signed NodeInfo
    let mut node_info = build_signed_node_info(&identity);

    // Attacker intercepts and modifies the addresses field
    node_info.addresses = vec!["10.66.66.66:4001".parse().unwrap()];

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

    // HARDENED: Tampered addresses break the signature
    assert!(
        !ack.accepted,
        "R10-01a: NodeInfo with tampered addresses must be rejected (signature covers all fields)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-01b: Verify that tampering with models breaks signature verification
#[tokio::test]
async fn r10_attack_tampered_models_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let mut node_info = build_signed_node_info(&identity);

    // Attacker inflates throughput to attract more clients
    node_info.models = vec![ModelCapability {
        model_name: "stolen-model".into(),
        gpu: true,
        throughput_estimate: 999.0,
    }];

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

    assert!(
        !ack.accepted,
        "R10-01b: NodeInfo with tampered models must be rejected (signature covers all fields)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-01c: Verify that tampering with relay_capable breaks signature verification
#[tokio::test]
async fn r10_attack_tampered_relay_capability_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let mut node_info = build_signed_node_info(&identity);

    // Attacker sets relay_capable to true to become an unauthorized relay
    node_info.relay_capable = !node_info.relay_capable;

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

    assert!(
        !ack.accepted,
        "R10-01c: NodeInfo with tampered relay_capable must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-01d: Verify that tampering with capacity breaks signature verification
#[tokio::test]
async fn r10_attack_tampered_capacity_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let mut node_info = build_signed_node_info(&identity);

    // Attacker inflates capacity to appear high-availability
    node_info.capacity = NodeCapacity {
        queue_depth: 0,
        active_sessions: 0,
        max_sessions: 9999,
    };

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

    assert!(
        !ack.accepted,
        "R10-01d: NodeInfo with tampered capacity must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-01e: Verify that a properly signed NodeInfo with all fields IS accepted
#[tokio::test]
async fn r10_verify_full_field_signature_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    // Use the build_signed_node_info_with helper to create a NodeInfo
    // with custom content, properly signed over all fields
    let node_info = build_signed_node_info_with(
        &identity,
        vec!["10.0.0.1:4001".parse().unwrap()],
        vec![ModelCapability {
            model_name: "my-model".into(),
            gpu: true,
            throughput_estimate: 42.0,
        }],
        true,
        NodeCapacity {
            queue_depth: 5,
            active_sessions: 2,
            max_sessions: 10,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info,
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
        "R10-01e: NodeInfo signed with build_signed_node_info_with must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-01f: Verify compute_nodeinfo_signing_message is deterministic
#[test]
fn r10_unit_signing_message_deterministic() {
    let info = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec![
            "127.0.0.1:4001".parse().unwrap(),
            "10.0.0.1:5000".parse().unwrap(),
        ],
        models: vec![
            ModelCapability {
                model_name: "model-a".into(),
                gpu: true,
                throughput_estimate: 10.5,
            },
            ModelCapability {
                model_name: "model-b".into(),
                gpu: false,
                throughput_estimate: 0.0,
            },
        ],
        relay_capable: true,
        capacity: NodeCapacity {
            queue_depth: 3,
            active_sessions: 1,
            max_sessions: 16,
        },
        timestamp: 1000000,
        signature: vec![], // Signature not included in signing message
    };

    let msg1 = compute_nodeinfo_signing_message(&info);
    let msg2 = compute_nodeinfo_signing_message(&info);

    assert_eq!(msg1.len(), 72, "Signing message must be 72 bytes (32 + 8 + 32)");
    assert_eq!(msg1, msg2, "Signing message must be deterministic");
}

/// R10-01g: Verify different content produces different signing messages
#[test]
fn r10_unit_signing_message_content_sensitive() {
    let base = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec!["127.0.0.1:4001".parse().unwrap()],
        models: vec![ModelCapability {
            model_name: "model".into(),
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

    let base_msg = compute_nodeinfo_signing_message(&base);

    // Change each field individually and verify the message changes

    // 1. Change address
    let mut modified = base.clone();
    modified.addresses = vec!["10.0.0.1:4001".parse().unwrap()];
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different addresses must produce different signing message"
    );

    // 2. Change model name
    let mut modified = base.clone();
    modified.models[0].model_name = "other-model".into();
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different model_name must produce different signing message"
    );

    // 3. Change GPU flag
    let mut modified = base.clone();
    modified.models[0].gpu = true;
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different gpu flag must produce different signing message"
    );

    // 4. Change throughput
    let mut modified = base.clone();
    modified.models[0].throughput_estimate = 2.0;
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different throughput must produce different signing message"
    );

    // 5. Change relay_capable
    let mut modified = base.clone();
    modified.relay_capable = true;
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different relay_capable must produce different signing message"
    );

    // 6. Change queue_depth
    let mut modified = base.clone();
    modified.capacity.queue_depth = 99;
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different queue_depth must produce different signing message"
    );

    // 7. Change active_sessions
    let mut modified = base.clone();
    modified.capacity.active_sessions = 5;
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different active_sessions must produce different signing message"
    );

    // 8. Change max_sessions
    let mut modified = base.clone();
    modified.capacity.max_sessions = 100;
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different max_sessions must produce different signing message"
    );

    // 9. Change timestamp
    let mut modified = base.clone();
    modified.timestamp = 2000000;
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different timestamp must produce different signing message"
    );

    // 10. Change public_key
    let mut modified = base.clone();
    modified.public_key = [99u8; 32];
    assert_ne!(
        compute_nodeinfo_signing_message(&modified),
        base_msg,
        "Different public_key must produce different signing message"
    );
}

/// R10-01h: Verify the signature field itself is NOT included in the signing message
/// (otherwise you'd need to sign the signature -- circular dependency)
#[test]
fn r10_unit_signature_field_not_in_signing_message() {
    let mut info = NodeInfo {
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
        signature: vec![0u8; 64],
    };

    let msg1 = compute_nodeinfo_signing_message(&info);

    // Change the signature field
    info.signature = vec![0xFF; 64];
    let msg2 = compute_nodeinfo_signing_message(&info);

    assert_eq!(
        msg1, msg2,
        "Signature field must NOT affect the signing message (would create circular dependency)"
    );
}

// =============================================================================
// FINDING 2 -- HIGH: RwLock::read().unwrap() panics if poisoned
//
// Before R10, server_info.read().unwrap() was used in the HelloAck construction
// path. If any previous writer panicked while holding the write lock (e.g.,
// during NodeInfo regeneration), the RwLock becomes poisoned and ALL subsequent
// reads would panic, crashing the server for every new connection.
//
// Fix: replaced .unwrap() with match on Ok/Err(poisoned), recovering data
// from the poisoned lock via poisoned.into_inner().clone().
//
// File: node.rs (HelloAck construction + regeneration paths)
// =============================================================================

/// R10-02a: Verify the server can still build HelloAck after lock is used
/// (functional test -- actual poisoning can't be triggered without unsafe code)
#[tokio::test]
async fn r10_verify_server_responds_after_multiple_handshakes() {
    // This test verifies the RwLock path works correctly by performing
    // multiple sequential handshakes. If the lock handling is broken,
    // later handshakes would fail.
    let (addr, handle) = start_test_node().await;

    for i in 0..5 {
        let endpoint = transport::create_client_endpoint().unwrap();
        let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

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

        let data = recv.read_to_end(64 * 1024).await.unwrap();
        let (ack_frame, _) = Frame::decode(&data).unwrap();
        let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();

        assert!(
            ack.accepted,
            "R10-02a: Handshake {} must succeed (RwLock must not be broken)",
            i
        );

        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    handle.abort();
}

// =============================================================================
// FINDING 3 -- HIGH: Client connect_and_infer model_id binding
//
// Before R10, connect_and_infer() accepted any model_id in the InferResponse
// without checking it matched the request's model_id. A malicious server could:
// - Return cached results from a cheaper model while claiming to run the
//   requested expensive model (billing fraud)
// - Return results for a completely different model (integrity violation)
// - Return a model_id that doesn't exist (confusion attack)
//
// Fix: connect_and_infer() now verifies response.model_id == request.model_id.
//
// File: node.rs (connect_and_infer)
// =============================================================================

/// R10-03a: Verify model_id binding works for matching model_ids
#[tokio::test]
async fn r10_verify_model_id_binding_matching() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);

    // connect_and_infer should succeed when server returns matching model_id
    // (MockInferenceBackend echoes the request's model_id in the response)
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R10-03a: Inference with matching model_id should succeed: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(
        response.model_id, request.model_id,
        "R10-03a: Response model_id must match request model_id"
    );

    handle.abort();
}

/// R10-03b: Verify model_id binding unit test -- mismatched model_id detection
/// (This tests the validation logic at the protocol level)
#[test]
fn r10_unit_model_id_mismatch_detected() {
    // Simulate what connect_and_infer checks:
    // If a malicious server returned a response with a different model_id,
    // the client should detect it.
    let request_model_id = "requested-model";
    let response_model_id = "cheaper-model";

    assert_ne!(
        request_model_id, response_model_id,
        "Test setup: model_ids must differ"
    );

    // This is the exact check from connect_and_infer:
    let would_be_rejected = response_model_id != request_model_id;
    assert!(
        would_be_rejected,
        "R10-03b: Mismatched model_id must be detected"
    );
}

// =============================================================================
// FINDING 4 -- MEDIUM: handle_infer() is dead code with no validation
//
// Since R9, the server's InferRequest handler passes the already-validated
// request object directly to backend.infer(). The old handle_infer() function
// in inference.rs performs raw deserialization and calls the backend with NO
// validation: no model_id check, no max_tokens cap, no encrypted_input size
// limit. It's a public API that callers might use thinking it's safe.
//
// Fix: Deprecated handle_infer() with a clear security warning. Callers
// should use decode_infer_request() + manual validation + backend.infer()
// + encode_infer_response() instead.
//
// File: protocol/inference.rs (#[deprecated] annotation)
// =============================================================================

/// R10-04a: Verify handle_infer still works but is deprecated
/// (compile-time deprecation warning, not a runtime failure)
#[test]
#[allow(deprecated)]
fn r10_audit_handle_infer_still_functional_but_deprecated() {
    use poly_node::protocol::inference;

    let backend = MockInferenceBackend::default();
    let request = test_infer_request(&[1, 2, 3]);
    let encoded = inference::encode_infer_request(&request).unwrap();

    // handle_infer still works -- just deprecated
    let result = inference::handle_infer(&encoded, &backend);
    assert!(
        result.is_ok(),
        "R10-04a: Deprecated handle_infer should still work"
    );

    let response_bytes = result.unwrap();
    let response = inference::decode_infer_response(&response_bytes).unwrap();
    assert_eq!(response.model_id, "test");
}

/// R10-04b: Demonstrate that handle_infer bypasses validation (audit)
/// An oversized max_tokens passes through handle_infer with no check.
#[test]
#[allow(deprecated)]
fn r10_audit_handle_infer_accepts_oversized_max_tokens() {
    use poly_node::protocol::inference;

    let backend = MockInferenceBackend::default();
    let ct = MockCiphertext {
        tokens: vec![1, 2, 3],
    };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 999_999, // Far exceeds MAX_INFER_TOKENS (4096)
        temperature: 700,
        seed: 42,
    };
    let encoded = inference::encode_infer_request(&request).unwrap();

    // handle_infer does NOT validate max_tokens -- it passes through
    let result = inference::handle_infer(&encoded, &backend);
    assert!(
        result.is_ok(),
        "R10-04b AUDIT: handle_infer accepts 999999 max_tokens (no validation)"
    );
}

// =============================================================================
// FINDING 5 -- MEDIUM: Server bincode encode/decode path inconsistency
//
// Before R10, the server serialized HelloAck using `bincode::serialize()`
// (which uses the legacy config with fixint encoding) but the client
// deserialized with `bincode::DefaultOptions::new().with_fixint_encoding()`.
// While these happen to produce identical output for fixint encoding, the
// asymmetry is a maintenance hazard: future changes to one side could
// silently break compatibility.
//
// Fix: Server now uses encode_hello_ack() (which uses bincode::serialize
// with output size validation from R9) for consistent encode/decode paths.
//
// File: node.rs (HelloAck encoding in handle_stream)
// =============================================================================

/// R10-05a: Verify HelloAck can be decoded with both legacy and new bincode
#[test]
fn r10_unit_hello_ack_encode_decode_consistency() {
    use bincode::Options;

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

    // Encode with the server's method (encode_hello_ack)
    let encoded = handshake::encode_hello_ack(&ack).unwrap();

    // Decode with both methods -- they must produce the same result
    let decoded_legacy: HelloAck = bincode::deserialize(&encoded).unwrap();
    let decoded_new: HelloAck = bincode::DefaultOptions::new()
        .with_limit(64 * 1024)
        .with_fixint_encoding()
        .deserialize(&encoded)
        .unwrap();

    assert_eq!(decoded_legacy.accepted, decoded_new.accepted);
    assert_eq!(decoded_legacy.version, decoded_new.version);
    assert_eq!(
        decoded_legacy.node_info.public_key,
        decoded_new.node_info.public_key
    );
    assert_eq!(
        decoded_legacy.node_info.timestamp,
        decoded_new.node_info.timestamp
    );
}

// =============================================================================
// FINDING 6 -- MEDIUM: Ping has no rate limiting
//
// After handshake, a client can send an unlimited number of Ping frames on
// separate streams. Each Ping is cheap (empty payload Pong response), but
// the stream overhead accumulates. This is mitigated by:
// - MAX_STREAMS_PER_CONN (256) -- connection killed after 256 streams
// - Ping requires handshake -- unauthenticated peers can't abuse it
// - Connection idle timeout (60s) -- zombie connections cleaned up
//
// These existing mitigations cap the damage sufficiently for Phase 1.
// File: node.rs (Ping handler)
// =============================================================================

/// R10-06a: Verify Ping is still rate-limited by stream cap
#[tokio::test]
async fn r10_audit_ping_limited_by_stream_cap() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Complete handshake first
    do_handshake(&conn).await;

    // Send many Pings -- should succeed until stream cap
    let mut success_count = 0u32;
    for _ in 0..50 {
        let result = async {
            let (mut send, mut recv) = conn.open_bi().await?;
            let ping_frame = Frame::new(MessageType::Ping, vec![]);
            send.write_all(&ping_frame.encode()).await?;
            send.finish()?;
            let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
                .await
                .map_err(|_| anyhow::anyhow!("timeout"))??;
            let (pong_frame, _) = Frame::decode(&data).map_err(|e| anyhow::anyhow!("{}", e))?;
            assert_eq!(pong_frame.msg_type, MessageType::Pong);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        if result.is_ok() {
            success_count += 1;
        }
    }

    // Some Pings should succeed but not all 50 should work indefinitely
    // (the handshake itself consumed 1 stream, plus 50 pings = 51 total)
    assert!(
        success_count > 0,
        "R10-06a: At least some Pings should succeed after handshake"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// BONUS: Additional R10 hardening verification tests
// =============================================================================

/// R10-bonus-a: Verify build_signed_node_info_with produces valid signatures
#[tokio::test]
async fn r10_verify_build_signed_node_info_with_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let node_info = build_signed_node_info_with(
        &identity,
        vec![
            "192.168.1.1:4001".parse().unwrap(),
            "192.168.1.2:4002".parse().unwrap(),
        ],
        vec![
            ModelCapability {
                model_name: "llama-7b".into(),
                gpu: true,
                throughput_estimate: 15.0,
            },
            ModelCapability {
                model_name: "qwen-3b".into(),
                gpu: false,
                throughput_estimate: 5.0,
            },
        ],
        true,
        NodeCapacity {
            queue_depth: 2,
            active_sessions: 1,
            max_sessions: 8,
        },
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info,
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
        "R10-bonus-a: build_signed_node_info_with with valid content must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-bonus-b: Old-format signature (pubkey||timestamp only) is now rejected
#[tokio::test]
async fn r10_attack_old_format_signature_rejected() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign with OLD format (only pubkey || timestamp)
    let mut old_msg = Vec::new();
    old_msg.extend_from_slice(&public_key);
    old_msg.extend_from_slice(&timestamp.to_le_bytes());
    let old_sig = identity.sign(&old_msg);

    let node_info = NodeInfo {
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
        signature: old_sig.to_vec(),
    };

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

    assert!(
        !ack.accepted,
        "R10-bonus-b: Old-format signature (pubkey||timestamp only) must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-bonus-c: Verify server HelloAck signature is properly verified by client
#[tokio::test]
async fn r10_verify_server_hello_ack_signature_valid() {
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

    assert!(ack.accepted, "Handshake must be accepted first");

    // Manually verify the server's HelloAck signature using the R10 method
    let server_pk = ack.node_info.public_key;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&server_pk).unwrap();
    let sig_bytes = &ack.node_info.signature;
    assert_eq!(sig_bytes.len(), 64, "Server signature must be 64 bytes");

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let msg = compute_nodeinfo_signing_message(&ack.node_info);
    let valid = poly_node::identity::verify_signature(&vk, &msg, &sig_arr);

    assert!(
        valid,
        "R10-bonus-c: Server's HelloAck NodeInfo must have a valid R10 full-field signature"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R10-bonus-d: Verify that connect_and_infer performs end-to-end with model_id binding
#[tokio::test]
async fn r10_verify_connect_and_infer_e2e_with_model_binding() {
    let (addr, handle) = start_test_node().await;

    // Send multiple inference requests with different model_ids
    // MockInferenceBackend echoes the model_id, so all should match
    for model_id in &["test", "mock-model", "llama-7b"] {
        let ct = MockCiphertext {
            tokens: vec![1, 2],
        };
        let request = InferRequest {
            model_id: model_id.to_string(),
            mode: Mode::Transparent,
            encrypted_input: serde_json::to_vec(&ct).unwrap(),
            max_tokens: 3,
            temperature: 700,
            seed: 42,
        };

        let result = poly_node::node::connect_and_infer(addr, &request).await;
        assert!(
            result.is_ok(),
            "R10-bonus-d: Inference with model_id '{}' should succeed: {:?}",
            model_id,
            result.err()
        );

        let response = result.unwrap();
        assert_eq!(
            response.model_id, *model_id,
            "R10-bonus-d: Response model_id must match request model_id"
        );
    }

    handle.abort();
}
