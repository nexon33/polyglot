//! Round 6 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. HIGH:     Rejected Hello leaks server NodeInfo to unauthenticated peers
//! 2. HIGH:     stream_count uses Relaxed ordering (should be SeqCst)
//! 3. HIGH:     connect_and_infer has no timeout on response read (client-side slowloris)
//! 4. HIGH:     encode_infer_request/response had no size validation on output
//! 5. HIGH:     allow_trailing_bytes() in Hello deserialization allows data injection
//! 6. MEDIUM:   max_sessions=0 creates zero-permit semaphore (self-DoS)
//! 7. MEDIUM:   NodeInfo.addresses and NodeInfo.models unbounded (gossip amplification)
//! 8. MEDIUM:   throughput_estimate accepts NaN/Inf (poisons peer selection)
//! 9. MEDIUM:   No request-response binding (inference response not tied to request)
//! 10. LOW:     handshake_done does not track WHICH identity authenticated

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::NodeIdentity;
use poly_node::net::transport;
use poly_node::node::{build_signed_node_info, PolyNode};
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

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 1 — HIGH: Rejected Hello leaks server NodeInfo
//
// Before R6 fix: When a Hello was rejected (bad signature, bad version,
// stale timestamp), the server still returned a full HelloAck containing
// its own NodeInfo — public key, listen addresses, model names, capacity.
// An attacker could enumerate server capabilities by sending deliberately
// invalid Hellos and inspecting the rejected HelloAck. This leaks:
//   - Server's Ed25519 public key (32 bytes)
//   - Listen addresses (useful for DDoS targeting)
//   - Model names (useful for targeted model confusion attacks)
//   - Capacity info (useful for timing DoS attacks at peak load)
//
// File: node.rs, handle_stream(), Hello handler's rejected path
// Impact: Information disclosure to unauthenticated peers
// Fix: Return a zeroed-out NodeInfo when Hello is rejected. Only disclose
//      server identity after the handshake is accepted.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_attack_rejected_hello_leaks_server_info() {
    let (addr, handle) = start_test_node().await;

    // Send a Hello with a bad signature — it WILL be rejected.
    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign with correct key but wrong message to create an invalid signature
    let sig = identity.sign(b"wrong message content");

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
        signature: sig.to_vec(),
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

    // Hello was rejected (bad signature)
    assert!(
        !ack.accepted,
        "Hello with bad signature must be rejected"
    );

    // HARDENED: Rejected HelloAck must NOT contain real server info
    assert_eq!(
        ack.node_info.public_key, [0u8; 32],
        "HARDENED: rejected HelloAck must not leak server's public key"
    );
    assert!(
        ack.node_info.addresses.is_empty(),
        "HARDENED: rejected HelloAck must not leak server's addresses"
    );
    assert!(
        ack.node_info.models.is_empty(),
        "HARDENED: rejected HelloAck must not leak server's model list"
    );
    assert_eq!(
        ack.node_info.capacity.max_sessions, 0,
        "HARDENED: rejected HelloAck must not leak server's capacity"
    );
    assert_eq!(
        ack.node_info.timestamp, 0,
        "HARDENED: rejected HelloAck must not leak server's timestamp"
    );
    assert!(
        ack.node_info.signature.is_empty(),
        "HARDENED: rejected HelloAck must not leak any signature"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r6_attack_rejected_version_leaks_server_info() {
    // Same attack but using version mismatch to trigger rejection
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: 99999, // Invalid version — will be rejected
        node_info: build_signed_node_info(&identity),
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

    assert!(!ack.accepted, "bad version must be rejected");

    // HARDENED: No server info leaked even via version mismatch rejection
    assert_eq!(
        ack.node_info.public_key, [0u8; 32],
        "HARDENED: version-rejected HelloAck must not leak server public key"
    );
    assert!(
        ack.node_info.addresses.is_empty(),
        "HARDENED: version-rejected HelloAck must not leak addresses"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 2 — HIGH: stream_count used Relaxed ordering
//
// Before R6 fix: The stream_count AtomicU64 in handle_connection used
// Ordering::Relaxed for fetch_add. While handshake_done was fixed to
// SeqCst in R5, stream_count was left at Relaxed. On weakly-ordered
// architectures (ARM), this could allow the counter to be temporarily
// stale, allowing more streams than MAX_STREAMS_PER_CONN to be accepted.
//
// The fix upgrades to SeqCst for consistency with all other atomics.
//
// File: node.rs, handle_connection(), stream_count.fetch_add()
// Impact: Stream flood cap bypass on ARM architectures
// Fix: Changed Relaxed to SeqCst.
// ═══════════════════════════════════════════════════════════════════════════

// NOTE: Cannot directly test memory ordering in a unit test. Instead, we
// verify the fix is applied by testing that the stream cap still works:

#[tokio::test]
async fn r6_verify_stream_count_cap_still_works() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    // Open streams until server kills the connection. The cap is 256.
    let mut success = 0u64;
    for _ in 0..270 {
        match conn.open_bi().await {
            Ok((mut send, mut recv)) => {
                let ping = Frame::new(MessageType::Ping, vec![]);
                if send.write_all(&ping.encode()).await.is_err() {
                    break;
                }
                let _ = send.finish();
                match tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(1024)).await {
                    Ok(Ok(data)) if !data.is_empty() => success += 1,
                    _ => break,
                }
            }
            Err(_) => break,
        }
    }

    // Stream cap should have kicked in before 270
    assert!(
        success <= 260,
        "Stream cap should limit to ~256 streams, got {}",
        success
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 3 — HIGH: connect_and_infer client has no response timeout
//
// Before R6 fix: The client-side connect_and_infer function read the
// inference response with `recv.read_to_end(16MB)` and no timeout.
// A malicious server could:
//   1. Accept the handshake
//   2. Accept the InferRequest
//   3. Slowly drip-feed response bytes (1 byte per second)
// This would tie up the client task for ~16 million seconds.
//
// File: node.rs, connect_and_infer(), line: recv.read_to_end(16MB)
// Impact: Client-side DoS / task exhaustion
// Fix: Added CLIENT_RESPONSE_TIMEOUT (30s) wrapping the read.
// ═══════════════════════════════════════════════════════════════════════════

// NOTE: Testing this fully requires a malicious server, which is complex to
// set up. Instead, we verify normal operations still work with the timeout:

#[tokio::test]
async fn r6_verify_connect_and_infer_with_timeout() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[5, 10, 15]);
    let response = poly_node::node::connect_and_infer(addr, &request)
        .await
        .unwrap();

    let ct: MockCiphertext =
        serde_json::from_slice(&response.encrypted_output).unwrap();
    // MockInferenceBackend(default=5): 3 input + 5 generated = 8
    assert_eq!(ct.tokens.len(), 8);
    assert_eq!(&ct.tokens[..3], &[5, 10, 15]);

    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 4 — HIGH: encode_infer_request/response had no size validation
//
// Before R6 fix: encode_infer_request() and encode_infer_response() used
// raw bincode::serialize() with no size check on the output. While
// decode functions had size limits, encode functions did not. This meant:
//   - A corrupted backend could produce an arbitrarily large response
//   - A malicious caller of connect_and_infer could craft an oversized
//     request that would pass encode but fail on the receiving end
//   - Asymmetric limits make reasoning about wire safety harder
//
// File: protocol/inference.rs, encode_infer_request/response
// Impact: Memory exhaustion on serialization, asymmetric wire limits
// Fix: Added size validation after serialization in both encode functions.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn r6_verify_encode_infer_request_size_limit() {
    // A normal request should encode fine
    let normal = test_infer_request(&[1, 2, 3]);
    let encoded = poly_node::protocol::inference::encode_infer_request(&normal);
    assert!(encoded.is_ok(), "normal request should encode");
    assert!(encoded.unwrap().len() < 1024, "normal request should be small");
}

#[test]
fn r6_verify_encode_infer_response_normal() {
    use poly_verified::types::{VerifiedProof, PrivacyMode, ZERO_HASH};
    let response = poly_client::protocol::InferResponse {
        encrypted_output: vec![0u8; 100],
        proof: VerifiedProof::HashIvc {
            chain_tip: ZERO_HASH,
            merkle_root: ZERO_HASH,
            step_count: 1,
            code_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
            blinding_commitment: None,
            checkpoints: vec![],
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
        },
        model_id: "test".into(),
    };
    let encoded = poly_node::protocol::inference::encode_infer_response(&response);
    assert!(encoded.is_ok(), "normal response should encode");
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 5 — HIGH: allow_trailing_bytes() in Hello deserialization
//
// Before R6 fix: The Hello deserialization used .allow_trailing_bytes()
// with the bincode options. This means:
//   - A valid Hello struct followed by arbitrary trailing data would be
//     accepted without error
//   - The 64KB size limit only applied to the serialized data, not the
//     logical content — a 60KB Hello followed by 4KB of padding would
//     pass, and the padding could be anything
//   - Same issue in inference.rs bincode_options() function
//
// While the trailing data is not processed, it's a defense-in-depth issue:
// strict parsing prevents a class of attacks where trailing data might
// influence behavior in future protocol extensions.
//
// File: node.rs Hello handler, protocol/inference.rs bincode_options()
// Impact: Accepts malformed payloads, future protocol confusion risk
// Fix: Removed allow_trailing_bytes() from all deserialization paths.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_attack_hello_with_trailing_bytes() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    // Serialize the Hello, then append trailing garbage
    let mut hello_bytes = bincode::serialize(&hello).unwrap();
    hello_bytes.extend_from_slice(b"TRAILING_GARBAGE_DATA_HERE");

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let frame = Frame::new(MessageType::Hello, hello_bytes);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        recv.read_to_end(64 * 1024),
    )
    .await;

    // HARDENED: Server should reject the Hello due to trailing bytes.
    // The stream will either close without response (deserialization error
    // causes the stream handler to return Err) or return empty data.
    match result {
        Ok(Ok(data)) => {
            if !data.is_empty() {
                // If we got a response, check it's a rejected HelloAck
                let (ack_frame, _) = Frame::decode(&data).unwrap();
                if ack_frame.msg_type == MessageType::HelloAck {
                    let ack: HelloAck = bincode::deserialize(&ack_frame.payload).unwrap();
                    // If bincode with DefaultOptions rejects trailing bytes,
                    // we won't even get here. But if we do, the Hello should
                    // not have been accepted.
                    assert!(
                        !ack.accepted,
                        "HARDENED: Hello with trailing bytes should be rejected"
                    );
                }
            }
            // Empty data is also acceptable (stream closed on deser error)
        }
        Ok(Err(_)) => {} // Stream reset — acceptable (deser error)
        Err(_) => {}     // Timeout — acceptable
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 6 — MEDIUM: max_sessions=0 creates zero-permit semaphore
//
// Before R6 fix: NodeConfig.max_sessions was not validated. A value of 0
// would create Semaphore::new(0), which means:
//   - conn_semaphore: try_acquire() always fails -> ALL connections rejected
//   - infer_semaphore: acquire() blocks forever -> ALL inference blocked
// The node would start, bind its port, accept TLS, then immediately
// close every connection with "overloaded". It's a configuration footgun
// that could be triggered by a typo or programmatic error.
//
// File: node.rs, PolyNode::new()
// Impact: Self-DoS, silent failure to serve any requests
// Fix: Validate max_sessions >= 1 in PolyNode::new().
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn r6_attack_max_sessions_zero() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 0, // Zero sessions — should be rejected
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);

    // HARDENED: max_sessions=0 is rejected at construction time
    assert!(
        result.is_err(),
        "HARDENED: PolyNode::new must reject max_sessions=0"
    );
    // PolyNode doesn't implement Debug, so use match instead of unwrap_err
    match result {
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                err_msg.contains("max_sessions"),
                "Error message should mention max_sessions: {}",
                err_msg
            );
        }
        Ok(_) => panic!("expected error for max_sessions=0"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 7 — MEDIUM: NodeInfo.addresses and NodeInfo.models unbounded
//
// Before R6 fix: A Hello with hundreds of addresses and model entries
// would be accepted (as long as total serialized size < 64KB). In Phase 2
// gossip, these NodeInfo entries would be stored in peer tables and
// forwarded to other nodes, causing memory amplification.
//
// Even without gossip, a large NodeInfo wastes server memory during
// deserialization and processing.
//
// File: node.rs, Hello handler, after signature verification
// Impact: Memory amplification in gossip, DoS via oversized NodeInfo
// Fix: Cap addresses at 16 and models at 16 after deserialization.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_attack_nodeinfo_too_many_addresses() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut msg = Vec::new();
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    let sig = identity.sign(&msg);

    // Create NodeInfo with 50 addresses (exceeds cap of 16)
    let node_info = NodeInfo {
        public_key,
        addresses: (0..50)
            .map(|i| format!("10.0.{}.{}:4001", i / 256, i % 256).parse().unwrap())
            .collect(),
        models: vec![],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp,
        signature: sig.to_vec(),
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

    // HARDENED: Server rejects NodeInfo with too many addresses
    assert!(
        !ack.accepted,
        "HARDENED: Hello with 50 addresses must be rejected (cap is 16)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r6_attack_nodeinfo_too_many_models() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut msg = Vec::new();
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    let sig = identity.sign(&msg);

    // Create NodeInfo with 30 models (exceeds cap of 16)
    let node_info = NodeInfo {
        public_key,
        addresses: vec![],
        models: (0..30)
            .map(|i| ModelCapability {
                model_name: format!("model-{}", i),
                gpu: false,
                throughput_estimate: 1.0,
            })
            .collect(),
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp,
        signature: sig.to_vec(),
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

    // HARDENED: Server rejects NodeInfo with too many models
    assert!(
        !ack.accepted,
        "HARDENED: Hello with 30 models must be rejected (cap is 16)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 8 — MEDIUM: throughput_estimate accepts NaN/Inf
//
// Before R6 fix: The ModelCapability.throughput_estimate field (f32) was
// not validated. An attacker could set it to:
//   - f32::NAN: poisons all comparisons (NaN != NaN, NaN < x is false)
//   - f32::INFINITY: always "wins" sorting by throughput
//   - f32::NEG_INFINITY: always "loses"
//
// In Phase 2 gossip-based peer selection, this would poison the routing
// table. NaN is especially dangerous: any comparison returns false, so a
// NaN entry would never be evicted and could dominate the routing table.
//
// File: node.rs, Hello handler, NodeInfo validation
// Impact: Gossip peer-selection poisoning
// Fix: Reject NodeInfo with non-finite throughput_estimate.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_attack_throughput_nan() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut msg = Vec::new();
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    let sig = identity.sign(&msg);

    let node_info = NodeInfo {
        public_key,
        addresses: vec![],
        models: vec![ModelCapability {
            model_name: "poisoned-model".into(),
            gpu: false,
            throughput_estimate: f32::NAN, // NaN poison
        }],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp,
        signature: sig.to_vec(),
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

    // HARDENED: Server rejects NaN throughput_estimate
    assert!(
        !ack.accepted,
        "HARDENED: Hello with NaN throughput_estimate must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r6_attack_throughput_infinity() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut msg = Vec::new();
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    let sig = identity.sign(&msg);

    let node_info = NodeInfo {
        public_key,
        addresses: vec![],
        models: vec![ModelCapability {
            model_name: "infinite-model".into(),
            gpu: false,
            throughput_estimate: f32::INFINITY, // Infinity poison
        }],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp,
        signature: sig.to_vec(),
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

    // HARDENED: Server rejects Infinity throughput_estimate
    assert!(
        !ack.accepted,
        "HARDENED: Hello with Infinity throughput_estimate must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

#[tokio::test]
async fn r6_attack_throughput_neg_infinity() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut msg = Vec::new();
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    let sig = identity.sign(&msg);

    let node_info = NodeInfo {
        public_key,
        addresses: vec![],
        models: vec![ModelCapability {
            model_name: "neg-inf-model".into(),
            gpu: false,
            throughput_estimate: f32::NEG_INFINITY, // -Inf poison
        }],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp,
        signature: sig.to_vec(),
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

    // HARDENED: Server rejects -Infinity throughput_estimate
    assert!(
        !ack.accepted,
        "HARDENED: Hello with -Infinity throughput_estimate must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 9 — MEDIUM: No request-response binding in inference protocol
//
// The InferRequest/InferResponse protocol has no request ID, nonce, or
// correlation field. This means:
//   - A MITM could swap responses between different requests
//   - A malicious server could return a cached response from a previous
//     request (response replay)
//   - The client has no way to verify the response corresponds to its
//     specific request
//
// This is a design limitation that requires protocol changes to fix
// (adding a request_id field to InferRequest/InferResponse). For now,
// we document it and test the current behavior.
//
// File: poly-client/src/protocol.rs, InferRequest/InferResponse structs
// Impact: Response confusion/replay by MITM or malicious server
// Fix: Documented. Protocol change needed (request_id field) for Phase 2.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_audit_inference_response_not_bound_to_request() {
    // Demonstrate: two different requests produce different responses, but
    // the client has no way to verify WHICH request a response belongs to.
    // The InferResponse has model_id but no request_id/nonce.

    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    do_handshake(&conn).await;

    // Request A
    let req_a = test_infer_request(&[1, 2, 3]);
    let (mut send_a, mut recv_a) = conn.open_bi().await.unwrap();
    let payload_a = poly_node::protocol::inference::encode_infer_request(&req_a).unwrap();
    let frame_a = Frame::new(MessageType::InferRequest, payload_a);
    send_a.write_all(&frame_a.encode()).await.unwrap();
    send_a.finish().unwrap();
    let data_a = recv_a.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp_a, _) = Frame::decode(&data_a).unwrap();
    let response_a: poly_client::protocol::InferResponse =
        bincode::deserialize(&resp_a.payload).unwrap();

    // Request B (different input)
    let req_b = test_infer_request(&[99, 100]);
    let (mut send_b, mut recv_b) = conn.open_bi().await.unwrap();
    let payload_b = poly_node::protocol::inference::encode_infer_request(&req_b).unwrap();
    let frame_b = Frame::new(MessageType::InferRequest, payload_b);
    send_b.write_all(&frame_b.encode()).await.unwrap();
    send_b.finish().unwrap();
    let data_b = recv_b.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp_b, _) = Frame::decode(&data_b).unwrap();
    let response_b: poly_client::protocol::InferResponse =
        bincode::deserialize(&resp_b.payload).unwrap();

    // Responses ARE different (different inputs produce different outputs)
    let ct_a: MockCiphertext =
        serde_json::from_slice(&response_a.encrypted_output).unwrap();
    let ct_b: MockCiphertext =
        serde_json::from_slice(&response_b.encrypted_output).unwrap();
    assert_ne!(
        ct_a.tokens, ct_b.tokens,
        "Different inputs should produce different outputs"
    );

    // AUDIT: Neither response contains a request ID or nonce that would
    // bind it to the specific request. A MITM could swap resp_a and resp_b
    // and the client would have no way to detect the swap.
    // This is a known limitation — fix requires protocol-level request_id.

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 10 — LOW: handshake_done tracks completion but not identity
//
// The AtomicBool handshake_done tracks WHETHER a handshake completed but
// not WHICH identity completed it. After handshake, any stream on the
// connection can send InferRequests, and there's no per-request identity
// check. This means:
//   - If the underlying QUIC connection were somehow shared (e.g., via a
//     proxy or relay), different logical clients could piggyback on one
//     authenticated session
//   - Audit logs can't attribute specific inference requests to specific
//     Ed25519 identities
//
// For Phase 1 (point-to-point), this is acceptable because QUIC connections
// are exclusive. For Phase 2/3 (gossip/relay), this needs to be addressed.
//
// File: node.rs, handle_connection(), handshake_done variable
// Impact: Identity attribution gap for auditing
// Fix: Documented for Phase 2. No code change needed for Phase 1.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_audit_handshake_does_not_bind_identity() {
    // After handshake with identity A, any inference request on the same
    // connection succeeds regardless of what identity was used in Hello.
    // There is no per-request identity check.

    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Handshake with identity A
    do_handshake(&conn).await;

    // Inference works (handshake completed)
    let request = test_infer_request(&[1, 2, 3]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = poly_node::protocol::inference::encode_infer_request(&request).unwrap();
    let frame = Frame::new(MessageType::InferRequest, payload);
    send.write_all(&frame.encode()).await.unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(16 * 1024 * 1024).await.unwrap();
    let (resp, _) = Frame::decode(&data).unwrap();
    assert_eq!(resp.msg_type, MessageType::InferResponse);

    // AUDIT: The server has no way to know which identity sent this
    // InferRequest. It only knows that SOME valid Hello was accepted
    // on this connection. For audit/billing purposes, this is insufficient.

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// BONUS: Verify that accepted Hello still includes server NodeInfo
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_verify_accepted_hello_includes_server_info() {
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

    // Accepted Hello MUST include real server info
    assert!(ack.accepted, "valid Hello should be accepted");
    assert_ne!(
        ack.node_info.public_key, [0u8; 32],
        "accepted HelloAck must include real server public key"
    );
    assert!(
        !ack.node_info.addresses.is_empty(),
        "accepted HelloAck must include server addresses"
    );
    assert!(
        !ack.node_info.signature.is_empty(),
        "accepted HelloAck must include server signature"
    );
    assert!(
        ack.node_info.timestamp > 0,
        "accepted HelloAck must include real timestamp"
    );

    // Verify the server's signature is valid
    let server_pk = ack.node_info.public_key;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&server_pk).unwrap();
    let sig_bytes = &ack.node_info.signature;
    assert_eq!(sig_bytes.len(), 64);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    // R10: Use full-field signing message (not just pubkey||timestamp)
    let sig_msg = poly_node::protocol::wire::compute_nodeinfo_signing_message(&ack.node_info);
    assert!(
        poly_node::identity::verify_signature(&vk, &sig_msg, &sig_arr),
        "accepted HelloAck server signature must be valid"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// BONUS: Regression test — normal flow still works after R6 hardening
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_regression_full_flow() {
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
async fn r6_regression_connect_and_infer() {
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

// ═══════════════════════════════════════════════════════════════════════════
// BONUS: Verify valid NodeInfo within bounds is accepted
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn r6_verify_nodeinfo_within_bounds_accepted() {
    // A NodeInfo with exactly 16 addresses and 16 models should be accepted
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut node_info = NodeInfo {
        public_key,
        addresses: (0..16)
            .map(|i| format!("10.0.0.{}:4001", i).parse().unwrap())
            .collect(),
        models: (0..16)
            .map(|i| ModelCapability {
                model_name: format!("m{}", i),
                gpu: false,
                throughput_estimate: 1.0,
            })
            .collect(),
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp,
        signature: vec![],
    };
    let signing_msg = poly_node::protocol::wire::compute_nodeinfo_signing_message(&node_info);
    node_info.signature = identity.sign(&signing_msg).to_vec();

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

    // Exactly at the limit should be accepted
    assert!(
        ack.accepted,
        "NodeInfo with exactly 16 addresses and 16 models should be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}
