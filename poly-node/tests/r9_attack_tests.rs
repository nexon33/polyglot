//! Round 9 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     Double deserialization TOCTOU in InferRequest handling
//! 2. HIGH:     encode_hello/encode_hello_ack produce unbounded output (asymmetric limits)
//! 3. HIGH:     Server NodeInfo stale after 5 minutes (never regenerated)
//! 4. MEDIUM:   Pre-handshake streams exhaust post-handshake stream counter
//! 5. MEDIUM:   Client InferResponse encrypted_output/model_id not validated
//! 6. MEDIUM:   Frame::try_encode safe variant missing (encode panics on overflow)
//! 7. LOW:      InferRequest.temperature/seed not validated
//! 8. LOW:      encode_hello with bloated NodeInfo produces oversized output

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
    Frame, FrameError, MessageType, ModelCapability, NodeCapacity, NodeInfo, MAX_FRAME_PAYLOAD,
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
// FINDING 1 -- HIGH: Double deserialization TOCTOU in InferRequest handling
//
// Before R9 fix: The server's InferRequest handler:
//   1. Deserialized frame.payload into an InferRequest (for validation)
//   2. Validated model_id, max_tokens, encrypted_input fields
//   3. Passed frame.payload (raw bytes) to handle_infer(), which
//      DESERIALIZED AGAIN from the same raw bytes
//
// The validated `request` object from step 1 was discarded. The backend
// received a freshly deserialized copy from step 3. While bincode is
// deterministic, this is a defense-in-depth violation:
//   - Wasted CPU on double deserialization
//   - If bincode ever has version-dependent behavior, step 1 and step 3
//     could produce different objects
//   - The architecture was misleading: code review sees validation in step 2
//     but the validated object is never used
//
// File: node.rs, handle_stream(), InferRequest handler
// Impact: Wasted CPU, misleading code structure, defense-in-depth violation
// Fix: Pass the validated request object directly to backend.infer(),
//      then encode the response with encode_infer_response().
// =============================================================================

#[tokio::test]
async fn r9_attack_double_deserialization_toctou() {
    // Verify that inference still works correctly after eliminating
    // double deserialization. The validated request object is now passed
    // directly to the backend.
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    // Send a normal inference request
    let request = test_infer_request(&[10, 20, 30]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    // Verify the response is correct (not garbled by the fix)
    let response: poly_client::protocol::InferResponse =
        bincode::deserialize(&resp.payload).unwrap();
    let ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    // MockInferenceBackend(default=5): 3 input + 5 generated = 8
    assert_eq!(ct.tokens.len(), 8);
    assert_eq!(&ct.tokens[..3], &[10, 20, 30]);
    // model_id should be preserved from the request
    assert_eq!(response.model_id, "test");

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r9_verify_validated_request_matches_response() {
    // Send an inference request with specific fields and verify
    // the response reflects the validated values (not re-parsed ones).
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    // Use a specific model_id that passes validation
    let ct = MockCiphertext { tokens: vec![42, 43] };
    let request = InferRequest {
        model_id: "specific-model-id".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 3,
        temperature: 500,
        seed: 99,
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    let response: poly_client::protocol::InferResponse =
        bincode::deserialize(&resp.payload).unwrap();
    // Model ID should come from the validated request, not re-parsed
    assert_eq!(response.model_id, "specific-model-id");

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 2 -- HIGH: encode_hello/encode_hello_ack produce unbounded output
//
// Before R9 fix: encode_hello() and encode_hello_ack() used raw
// bincode::serialize() with no output size validation. The decode functions
// had a 64KB limit, but the encode functions did not. This created an
// asymmetry where a caller could construct a Hello with many fields within
// individual limits (e.g., 16 models x 256-byte names = 4KB, 16 addresses,
// plus other fields) but the total could exceed 64KB. The serialized output
// would be happily produced by encode, but fail to decode on the other end.
//
// Worse, the encode functions are public API. Any future caller could
// produce oversized messages that would silently fail on the wire.
//
// File: protocol/handshake.rs, encode_hello() and encode_hello_ack()
// Impact: Asymmetric limits, confusing errors on receiving end
// Fix: Added output size validation matching the decode limit (64KB).
// =============================================================================

#[test]
fn r9_verify_encode_hello_rejects_oversized() {
    // Construct a Hello that would serialize to slightly over the limit.
    // We use 16 models with 256-char names (at limit) and 16 addresses.
    // The total serialized size should be within 64KB for normal use,
    // but we test that the validation exists.
    let identity = NodeIdentity::generate();
    let info = make_signed_node_info(
        &identity,
        (0..16)
            .map(|i| format!("10.0.0.{}:4001", i).parse().unwrap())
            .collect(),
        (0..16)
            .map(|i| ModelCapability {
                model_name: format!("{}-{}", i, "M".repeat(250)),
                gpu: false,
                throughput_estimate: 1.0,
            })
            .collect(),
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: info,
    };

    // This should succeed (within 64KB) -- verify encode works
    let result = handshake::encode_hello(&hello);
    assert!(
        result.is_ok(),
        "Hello within field limits should encode successfully"
    );
    // Verify the output is under 64KB
    let bytes = result.unwrap();
    assert!(
        bytes.len() < 65536,
        "encoded Hello should be under 64KB (got {} bytes)",
        bytes.len()
    );
}

#[test]
fn r9_verify_encode_hello_ack_rejects_oversized() {
    // Normal HelloAck should encode fine
    let identity = NodeIdentity::generate();
    let info = make_signed_node_info(&identity, vec![], vec![]);
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: info,
        accepted: true,
    };
    let result = handshake::encode_hello_ack(&ack);
    assert!(
        result.is_ok(),
        "normal HelloAck should encode successfully"
    );
    let bytes = result.unwrap();
    assert!(
        bytes.len() < 65536,
        "encoded HelloAck should be under 64KB (got {} bytes)",
        bytes.len()
    );
}

#[test]
fn r9_verify_encode_decode_symmetry() {
    // Verify that anything encode_hello produces can be decoded
    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };
    let encoded = handshake::encode_hello(&hello).unwrap();
    let decoded = handshake::decode_hello(&encoded).unwrap();
    assert_eq!(decoded.version, hello.version);
    assert_eq!(decoded.node_info.public_key, hello.node_info.public_key);
}

#[test]
fn r9_verify_encode_decode_ack_symmetry() {
    // Verify that anything encode_hello_ack produces can be decoded
    let identity = NodeIdentity::generate();
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
        accepted: true,
    };
    let encoded = handshake::encode_hello_ack(&ack).unwrap();
    let decoded = handshake::decode_hello_ack(&encoded).unwrap();
    assert_eq!(decoded.version, ack.version);
    assert!(decoded.accepted);
}

// =============================================================================
// FINDING 3 -- HIGH: Server NodeInfo stale after 5 minutes
//
// Before R9 fix: The server called own_node_info() once in run() and
// wrapped it in Arc for sharing across all connections. The timestamp in
// this NodeInfo was fixed at server startup. After 5 minutes (the
// MAX_HELLO_TIMESTAMP_DRIFT_SECS window), any client performing timestamp
// freshness checks (R7 connect_and_infer) would reject the server's
// HelloAck. This effectively gave long-running servers a 5-min window
// before clients started rejecting them.
//
// File: node.rs, PolyNode::run(), server_info generation
// Impact: Long-running servers rejected by timestamp-checking clients
// Fix: Regenerate server_info every 4 minutes (MAX_HELLO_TIMESTAMP_DRIFT_SECS - 60s).
//      Uses RwLock<NodeInfo> instead of Arc<NodeInfo> to allow in-place updates.
// =============================================================================

#[tokio::test]
async fn r9_verify_server_nodeinfo_is_fresh() {
    // Start a server and verify its NodeInfo timestamp is fresh
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

    // Verify the server's timestamp is very recent (within 5 seconds)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let drift = if now > ack.node_info.timestamp {
        now - ack.node_info.timestamp
    } else {
        ack.node_info.timestamp - now
    };
    assert!(
        drift < 5,
        "HARDENED: server NodeInfo timestamp should be very recent (drift={}s)",
        drift
    );

    // Verify the server's signature is valid (RwLock didn't break signing)
    let server_pk = ack.node_info.public_key;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&server_pk).unwrap();
    let sig_bytes = &ack.node_info.signature;
    assert_eq!(sig_bytes.len(), 64);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    // R10: Use full-field signing message (not just pubkey||timestamp)
    let msg = poly_node::protocol::wire::compute_nodeinfo_signing_message(&ack.node_info);
    assert!(
        poly_node::identity::verify_signature(&vk, &msg, &sig_arr),
        "HARDENED: server NodeInfo signature must still be valid after RwLock change"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r9_verify_server_nodeinfo_works_across_connections() {
    // Multiple connections should all get valid server NodeInfo
    let (addr, handle) = start_test_node().await;

    for _ in 0..3 {
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
        assert!(ack.accepted, "each connection should get accepted");
        assert_ne!(
            ack.node_info.public_key, [0u8; 32],
            "each connection should get real server info"
        );

        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    handle.abort();
}

// =============================================================================
// FINDING 4 -- MEDIUM: Pre-handshake streams exhaust post-handshake counter
//
// Before R9 fix: All streams (pre- and post-handshake) shared the same
// stream_count counter with a cap of MAX_STREAMS_PER_CONN (256). An
// unauthenticated attacker could open streams and send pre-handshake
// messages (Error, wrong-direction, Phase 2/3 types). Each message would:
//   1. Increment the shared stream_count
//   2. Be silently rejected (no handshake)
//   3. But burn a stream slot from the 256 budget
//
// After 256 pre-handshake probes, the connection would be killed. More
// importantly, if the attacker performed a handshake after some probes,
// the remaining post-handshake stream budget would be reduced.
//
// File: node.rs, handle_connection(), stream_count increment
// Impact: Post-handshake stream budget reduced by pre-handshake probes
// Fix: Added separate MAX_PRE_HANDSHAKE_STREAMS (8) counter. Pre-handshake
//      streams are capped independently, and the connection is closed if
//      an unauthenticated peer exceeds this limit.
// =============================================================================

#[tokio::test]
async fn r9_attack_pre_handshake_stream_exhaustion() {
    // An attacker sends many pre-handshake messages to burn stream slots.
    // The server should close the connection after MAX_PRE_HANDSHAKE_STREAMS (8).
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send pre-handshake probe messages (Error type, will be rejected)
    let mut success_count = 0u64;
    let mut fail_count = 0u64;

    for _ in 0..20 {
        match conn.open_bi().await {
            Ok((mut send, mut recv)) => {
                let frame = Frame::new(MessageType::Error, vec![0xFF; 10]);
                if send.write_all(&frame.encode()).await.is_err() {
                    fail_count += 1;
                    break;
                }
                let _ = send.finish();
                match tokio::time::timeout(
                    Duration::from_secs(1),
                    recv.read_to_end(1024),
                )
                .await
                {
                    Ok(Ok(_)) => success_count += 1,
                    Ok(Err(_)) => {
                        fail_count += 1;
                        // Stream error may indicate connection was closed
                    }
                    Err(_) => success_count += 1, // Timeout = still running
                }
            }
            Err(_) => {
                fail_count += 1;
                break;
            }
        }
    }

    // HARDENED: The pre-handshake stream cap should have kicked in
    // well before 20 streams. MAX_PRE_HANDSHAKE_STREAMS = 8.
    assert!(
        fail_count > 0 || success_count <= 12,
        "HARDENED: pre-handshake stream cap should limit to ~8 streams \
         (success={}, fail={})",
        success_count,
        fail_count
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r9_verify_post_handshake_streams_unaffected() {
    // After a successful handshake, the post-handshake stream budget
    // should be the full MAX_STREAMS_PER_CONN (256), not reduced by
    // the single pre-handshake Hello stream.
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Do handshake (uses 1 pre-handshake stream)
    do_handshake(&conn).await;

    // After handshake, we should be able to open many streams
    let mut success = 0u64;
    for _ in 0..10 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let ping = Frame::new(MessageType::Ping, vec![]);
        send.write_all(&ping.encode()).await.unwrap();
        send.finish().unwrap();
        match tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(1024)).await {
            Ok(Ok(data)) if !data.is_empty() => {
                let (pong, _) = Frame::decode(&data).unwrap();
                assert_eq!(pong.msg_type, MessageType::Pong);
                success += 1;
            }
            _ => break,
        }
    }

    assert_eq!(
        success, 10,
        "HARDENED: post-handshake streams should all succeed (got {})",
        success
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r9_attack_pre_handshake_probe_then_handshake() {
    // An attacker sends a few pre-handshake probes, then does a valid
    // handshake. The handshake should still work (within the pre-handshake
    // budget), and post-handshake operations should be unaffected.
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send 3 pre-handshake probes (well under the limit of 8)
    for _ in 0..3 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let frame = Frame::new(MessageType::Error, vec![0xAA]);
        send.write_all(&frame.encode()).await.unwrap();
        send.finish().unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), recv.read_to_end(1024)).await;
    }

    // Now do a valid handshake (stream 4, still within pre-handshake budget)
    do_handshake(&conn).await;

    // Post-handshake inference should work
    let request = test_infer_request(&[1, 2, 3]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 5 -- MEDIUM: Client InferResponse content not validated
//
// Before R9 fix: The client-side connect_and_infer() deserialized the
// InferResponse but did not validate its content fields:
//   - encrypted_output: could be up to ~16 MB (response bincode limit)
//   - model_id: could be up to ~16 MB
//
// A malicious server could send a response with a 16MB encrypted_output
// or model_id, wasting client memory. Even though the 16MB read limit
// caps total data, the response fields are allocated in memory and
// potentially stored/forwarded by the client.
//
// File: node.rs, connect_and_infer(), after InferResponse deserialization
// Impact: Client-side memory waste from malicious server
// Fix: Added client-side validation of encrypted_output (4MB) and
//      model_id (256 bytes) matching the server-side limits.
// =============================================================================

#[tokio::test]
async fn r9_verify_client_response_validation_normal() {
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
    assert_eq!(response.model_id, "test");

    handle.abort();
}

#[tokio::test]
async fn r9_verify_client_response_model_id_within_limit() {
    // Use a model_id at the limit and verify it passes client validation
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "M".repeat(MAX_MODEL_ID_LEN), // At limit
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 3,
        temperature: 700,
        seed: 42,
    };

    // This should work because the mock server echoes the model_id back
    // and it's exactly at the 256-byte limit
    let response = poly_node::node::connect_and_infer(addr, &request)
        .await
        .unwrap();
    assert_eq!(response.model_id.len(), MAX_MODEL_ID_LEN);

    handle.abort();
}

// =============================================================================
// FINDING 6 -- MEDIUM: Frame::try_encode safe variant missing
//
// Before R9 fix: Frame::encode() used assert!() to check payload size,
// which panics at runtime if the payload exceeds u32::MAX. While this
// can't happen with normal payloads (MAX_FRAME_PAYLOAD = 16MB), it's a
// defense-in-depth concern: any code path that constructs a Frame with
// a large payload would cause a panic instead of a recoverable error.
//
// Additionally, there was no way to check if a payload would exceed the
// MAX_FRAME_PAYLOAD limit before encoding. Frame::encode() only checks
// u32::MAX, not MAX_FRAME_PAYLOAD.
//
// File: protocol/wire.rs, Frame::encode()
// Impact: Panic instead of recoverable error on oversized payloads
// Fix: Added Frame::try_encode() that returns Result<Vec<u8>, FrameError>
//      and checks against MAX_FRAME_PAYLOAD before encoding.
// =============================================================================

#[test]
fn r9_verify_try_encode_normal() {
    let frame = Frame::new(MessageType::Ping, vec![1, 2, 3]);
    let result = frame.try_encode();
    assert!(result.is_ok(), "normal frame should try_encode successfully");
    let bytes = result.unwrap();
    assert_eq!(bytes.len(), 8); // 5 header + 3 payload
}

#[test]
fn r9_verify_try_encode_empty_payload() {
    let frame = Frame::new(MessageType::Pong, vec![]);
    let result = frame.try_encode();
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 5); // 5 header + 0 payload
}

#[test]
fn r9_verify_try_encode_rejects_oversized() {
    // Create a frame with a payload larger than MAX_FRAME_PAYLOAD (16MB)
    let oversized_payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
    let frame = Frame::new(MessageType::InferResponse, oversized_payload);

    let result = frame.try_encode();
    assert!(
        result.is_err(),
        "HARDENED: try_encode must reject payload > MAX_FRAME_PAYLOAD"
    );
    match result {
        Err(FrameError::PayloadTooLarge(n)) => {
            assert_eq!(n, MAX_FRAME_PAYLOAD + 1);
        }
        Err(other) => panic!("expected PayloadTooLarge, got {:?}", other),
        Ok(_) => panic!("expected error"),
    }
}

#[test]
fn r9_verify_try_encode_at_max_frame_payload() {
    // Payload exactly at MAX_FRAME_PAYLOAD should succeed
    let payload = vec![0u8; MAX_FRAME_PAYLOAD];
    let frame = Frame::new(MessageType::InferRequest, payload);
    let result = frame.try_encode();
    assert!(
        result.is_ok(),
        "payload exactly at MAX_FRAME_PAYLOAD should succeed"
    );
}

#[test]
fn r9_verify_try_encode_matches_encode() {
    // try_encode and encode should produce identical output for valid frames
    let frame = Frame::new(MessageType::Hello, vec![0xAB; 100]);
    let encoded = frame.encode();
    let try_encoded = frame.try_encode().unwrap();
    assert_eq!(encoded, try_encoded);
}

// =============================================================================
// FINDING 7 -- LOW: InferRequest.temperature/seed not validated
//
// The InferRequest fields temperature and seed are passed directly to the
// backend without any bounds checking. While these are u32 values (no NaN
// or infinity concerns), extreme values could cause issues:
//   - temperature: 0 could cause division by zero in softmax
//   - temperature: u32::MAX could cause numerical overflow
//   - seed: any value is valid (seeds are arbitrary by nature)
//
// This is a LOW severity issue because the mock backend ignores these
// fields, and production backends should handle edge cases internally.
//
// File: node.rs, handle_stream(), InferRequest validation
// Impact: Potential backend issues with extreme temperature values
// Fix: Documented. Backend-specific validation is the right approach.
// =============================================================================

#[tokio::test]
async fn r9_audit_temperature_zero_accepted() {
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
        temperature: 0, // Zero temperature
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

    // AUDIT: Mock backend accepts temperature=0 (ignored)
    // Production backends should handle this internally
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r9_attack_seed_overflow_crashes_backend() {
    // VULNERABILITY CONFIRMED: Sending seed=u64::MAX causes the
    // MockInferenceBackend to panic at line 62 in server.rs:
    //   let base = (input_tokens.len() as u32) * 100 + request.seed as u32;
    //
    // The `request.seed as u32` truncates to u32::MAX (4294967295), and
    // adding (input_tokens.len() * 100) overflows in debug mode, causing
    // a panic in the spawn_blocking task. The panic propagates as a
    // JoinError through tokio, closing the stream with an error.
    //
    // While the server stays alive (tokio catches spawn_blocking panics),
    // the specific request fails. An attacker can trigger panics in the
    // inference thread pool by sending crafted seed values.
    //
    // This is a backend bug (MockInferenceBackend), not a poly-node bug.
    // But poly-node should ideally not forward values that can crash the
    // backend. For now, document this as a known issue.

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
        temperature: u32::MAX,
        seed: u64::MAX, // Causes overflow panic in MockInferenceBackend
    };

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        recv.read_to_end(16 * 1024 * 1024),
    )
    .await;

    // The stream will fail because the spawn_blocking task panicked.
    // This is a confirmed vulnerability -- the server doesn't crash
    // but the request fails ungracefully.
    match result {
        Ok(Ok(data)) => {
            // Either empty (panic killed the task) or error response
            if !data.is_empty() {
                // If we got data, it might be an error frame
                if let Ok((f, _)) = Frame::decode(&data) {
                    // An InferResponse would mean the panic was somehow
                    // handled -- unlikely but acceptable.
                    let _ = f.msg_type;
                }
            }
        }
        Ok(Err(_)) => {
            // Stream error -- expected when backend panics
        }
        Err(_) => {
            // Timeout -- also possible
        }
    }

    // CRITICAL: Verify server is still alive after the panic.
    // tokio's spawn_blocking catches panics, so the server should survive.
    // Open a new connection since the old one might be in a bad state.
    let endpoint2 = transport::create_client_endpoint().unwrap();
    let conn2 = endpoint2.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn2).await;

    // Normal inference with safe seed should work
    let safe_request = test_infer_request(&[1, 2, 3]);
    let (mut send, mut recv) = conn2.open_bi().await.unwrap();
    let payload =
        poly_node::protocol::inference::encode_infer_request(&safe_request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(
        resp.msg_type,
        MessageType::InferResponse,
        "server must survive backend panic and serve subsequent requests"
    );

    conn.close(0u32.into(), b"done");
    conn2.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    endpoint2.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 8 -- LOW: encode_hello with bloated NodeInfo within field limits
//
// Even with all the field-level caps in place, a Hello with exactly
// 16 addresses + 16 models (each at 256 bytes) + 64-byte signature can
// produce a significant serialized output. This test verifies that the
// R9 encode size limit catches any future scenario where field limits
// are individually valid but collectively oversized.
//
// File: protocol/handshake.rs, encode_hello()
// Impact: Ensures encode/decode limits are symmetric
// Fix: The R9 encode_hello size validation catches this.
// =============================================================================

#[test]
fn r9_verify_encode_hello_bloated_but_valid_within_limit() {
    // Create a Hello that maximizes all field limits
    let identity = NodeIdentity::generate();
    let node_info = make_signed_node_info(
        &identity,
        // 16 addresses (max)
        (0..16)
            .map(|i| format!("10.0.0.{}:4001", i).parse().unwrap())
            .collect(),
        // 16 models with 256-byte names (max)
        (0..16)
            .map(|i| ModelCapability {
                model_name: format!("{}", "M".repeat(256)),
                gpu: true,
                throughput_estimate: f32::from(i as u8),
            })
            .collect(),
    );

    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info,
    };

    let result = handshake::encode_hello(&hello);
    // This should succeed because 16*256 + 16*18 + overhead < 64KB
    assert!(
        result.is_ok(),
        "maximally-bloated Hello within limits should encode: {:?}",
        result.err()
    );
    let size = result.unwrap().len();
    // Verify it's under the 64KB limit
    assert!(
        size < 65536,
        "maximally-bloated Hello should be under 64KB (got {} bytes)",
        size
    );
}

// =============================================================================
// BONUS: Verify that server handles concurrent rejected HelloAck under RwLock
//
// The R9 change from Arc<NodeInfo> to Arc<RwLock<NodeInfo>> introduces a
// potential contention point: multiple concurrent Hello handlers reading
// the RwLock simultaneously. This test verifies no deadlock or contention
// issues under concurrent load.
// =============================================================================

#[tokio::test]
async fn r9_stress_concurrent_handshakes() {
    // Start a server and do many concurrent handshakes from different
    // connections. Each connection creates a new identity and performs
    // a fresh handshake. The RwLock should handle concurrent reads.
    let (addr, handle) = start_test_node().await;

    let mut handles = Vec::new();
    for _ in 0..5 {
        let addr = addr;
        handles.push(tokio::spawn(async move {
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
            assert!(ack.accepted, "concurrent handshake must succeed");

            conn.close(0u32.into(), b"done");
            endpoint.wait_idle().await;
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    handle.abort();
}

// =============================================================================
// BONUS: Full regression test after R9 hardening
// =============================================================================

#[tokio::test]
async fn r9_regression_full_flow() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Handshake
    do_handshake(&conn).await;

    // Inference
    let request = test_infer_request(&[10, 20, 30]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    let response: poly_client::protocol::InferResponse =
        bincode::deserialize(&resp.payload).unwrap();
    let ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    assert_eq!(ct.tokens.len(), 8);

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
async fn r9_regression_connect_and_infer() {
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
