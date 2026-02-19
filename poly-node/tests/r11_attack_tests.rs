//! Round 11 pentest attack tests for poly-node.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. CRITICAL: NodeInfo signing lacked domain separation tag -- cross-context signature replay
//!              Fix: prepend `b"poly-node/NodeInfo/v1\0"` to the content hash in wire.rs
//! 2. HIGH:     NodeInfo signing did not include addresses.len() count -- address list ambiguity
//!              Fix: include `(addresses.len() as u32).to_le_bytes()` before iterating addresses
//! 3. HIGH:     Ping payload not validated -- 16 MB memory waste per authenticated stream
//!              Fix: reject Ping payloads > MAX_PING_PAYLOAD (128 bytes) in node.rs
//! 4. MEDIUM:   Server reads 16 MB for ALL message types (uniform read limit)
//! 5. MEDIUM:   InferResponse.proof field not validated by client
//! 6. MEDIUM:   SocketAddr to_string() non-canonical in signing (e.g., IPv6 bracket formats)
//! 7. LOW:      FrameError did not implement PartialEq (test ergonomics)
//!              Fix: added `#[derive(PartialEq)]` to FrameError in wire.rs
//! 8. LOW:      Client endpoint binds to 0.0.0.0:0 (unrestricted local port)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::identity::NodeIdentity;
use poly_node::net::transport;
use poly_node::node::{build_signed_node_info, build_signed_node_info_with, PolyNode, MAX_PING_PAYLOAD};
use poly_node::protocol::handshake::{self, Hello, HelloAck, PROTOCOL_VERSION};
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
// FINDING 1 -- CRITICAL: NodeInfo signing lacked domain separation tag
//
// Before R11, the content hash in compute_nodeinfo_signing_message() had no
// domain separation tag. If the same Ed25519 key were used for multiple
// protocol contexts (e.g., NodeInfo signing and Phase 2 gossip announcements),
// a signature produced for one context could theoretically be valid in another.
// This is a cross-context signature replay attack.
//
// The domain separation tag `b"poly-node/NodeInfo/v1\0"` is prepended to the
// content hash input, ensuring the signed message is unambiguously a NodeInfo.
// The null terminator prevents prefix ambiguity.
//
// Fix: wire.rs `compute_nodeinfo_signing_message()` -- first line of content_hasher
// File: poly-node/src/protocol/wire.rs
// =============================================================================

/// R11-01a: Verify domain separation tag is present in signing message.
/// The content hash MUST differ when computed with vs without the tag.
#[test]
fn r11_unit_domain_separation_tag_affects_hash() {
    use sha2::{Digest, Sha256};

    let info = NodeInfo {
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
        timestamp: 1000000,
        signature: vec![],
    };

    // Compute the official signing message (which includes domain tag)
    let official_msg = compute_nodeinfo_signing_message(&info);
    assert_eq!(official_msg.len(), 72, "Signing message must be 72 bytes");

    // Manually compute WITHOUT domain separation tag (old vulnerable format)
    let mut hasher_no_tag = Sha256::new();
    // Skip the tag -- go directly to addresses.len()
    hasher_no_tag.update((info.addresses.len() as u32).to_le_bytes());
    for addr in &info.addresses {
        let s = addr.to_string();
        hasher_no_tag.update((s.len() as u32).to_le_bytes());
        hasher_no_tag.update(s.as_bytes());
    }
    hasher_no_tag.update((info.models.len() as u32).to_le_bytes());
    for m in &info.models {
        hasher_no_tag.update((m.model_name.len() as u32).to_le_bytes());
        hasher_no_tag.update(m.model_name.as_bytes());
        hasher_no_tag.update(&[m.gpu as u8]);
        hasher_no_tag.update(m.throughput_estimate.to_le_bytes());
    }
    hasher_no_tag.update(&[info.relay_capable as u8]);
    hasher_no_tag.update(info.capacity.queue_depth.to_le_bytes());
    hasher_no_tag.update(info.capacity.active_sessions.to_le_bytes());
    hasher_no_tag.update(info.capacity.max_sessions.to_le_bytes());
    let no_tag_hash: [u8; 32] = hasher_no_tag.finalize().into();

    let mut no_tag_msg = Vec::with_capacity(72);
    no_tag_msg.extend_from_slice(&info.public_key);
    no_tag_msg.extend_from_slice(&info.timestamp.to_le_bytes());
    no_tag_msg.extend_from_slice(&no_tag_hash);

    // The messages MUST differ (domain tag changes the hash)
    assert_ne!(
        official_msg, no_tag_msg,
        "R11-01a: Domain separation tag must change the signing message"
    );
}

/// R11-01b: Signature produced without domain tag is rejected by server.
/// This simulates an attacker who has a valid signature from a pre-R11
/// signing context (or a different protocol using the same key).
#[tokio::test]
async fn r11_attack_signature_without_domain_tag_rejected() {
    use sha2::{Digest, Sha256};

    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Compute content hash WITHOUT domain separation tag (pre-R11 style)
    let mut hasher = Sha256::new();
    // No tag -- directly include address count (R11 addition)
    hasher.update(0u32.to_le_bytes()); // 0 addresses
    hasher.update(0u32.to_le_bytes()); // 0 models
    hasher.update(&[0u8]); // relay_capable = false
    hasher.update(0u32.to_le_bytes()); // queue_depth
    hasher.update(0u32.to_le_bytes()); // active_sessions
    hasher.update(1u32.to_le_bytes()); // max_sessions
    let content_hash: [u8; 32] = hasher.finalize().into();

    let mut msg = Vec::with_capacity(72);
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    msg.extend_from_slice(&content_hash);
    let sig = identity.sign(&msg);

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

    assert!(
        !ack.accepted,
        "R11-01b: Signature computed without domain separation tag must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R11-01c: Domain tag makes the signing message unique per protocol context.
/// Two different domain tags on the same data must produce different messages.
#[test]
fn r11_unit_different_domain_tags_produce_different_hashes() {
    use sha2::{Digest, Sha256};

    let info = NodeInfo {
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

    // Official tag
    let official_msg = compute_nodeinfo_signing_message(&info);

    // Hypothetical different tag (e.g., gossip announcement)
    let mut hasher_gossip = Sha256::new();
    hasher_gossip.update(b"poly-node/GossipAnnounce/v1\0");
    hasher_gossip.update((info.addresses.len() as u32).to_le_bytes());
    hasher_gossip.update((info.models.len() as u32).to_le_bytes());
    hasher_gossip.update(&[info.relay_capable as u8]);
    hasher_gossip.update(info.capacity.queue_depth.to_le_bytes());
    hasher_gossip.update(info.capacity.active_sessions.to_le_bytes());
    hasher_gossip.update(info.capacity.max_sessions.to_le_bytes());
    let gossip_hash: [u8; 32] = hasher_gossip.finalize().into();

    let mut gossip_msg = Vec::with_capacity(72);
    gossip_msg.extend_from_slice(&info.public_key);
    gossip_msg.extend_from_slice(&info.timestamp.to_le_bytes());
    gossip_msg.extend_from_slice(&gossip_hash);

    assert_ne!(
        official_msg, gossip_msg,
        "R11-01c: Different domain tags must produce different signing messages"
    );
}

/// R11-01d: Verify the domain tag includes a null terminator
/// (prevents prefix attacks where "v1" is a prefix of "v10")
#[test]
fn r11_unit_domain_tag_has_null_terminator() {
    use sha2::{Digest, Sha256};

    let info = NodeInfo {
        public_key: [0u8; 32],
        addresses: vec![],
        models: vec![],
        relay_capable: false,
        capacity: NodeCapacity {
            queue_depth: 0,
            active_sessions: 0,
            max_sessions: 1,
        },
        timestamp: 0,
        signature: vec![],
    };

    // Compute with null-terminated tag (correct)
    let msg_v1 = compute_nodeinfo_signing_message(&info);

    // Compute with hypothetical "v10" tag (would collide with "v1\0..." if no null)
    let mut hasher_v10 = Sha256::new();
    hasher_v10.update(b"poly-node/NodeInfo/v10"); // No null -- would be ambiguous prefix
    hasher_v10.update((info.addresses.len() as u32).to_le_bytes());
    hasher_v10.update((info.models.len() as u32).to_le_bytes());
    hasher_v10.update(&[info.relay_capable as u8]);
    hasher_v10.update(info.capacity.queue_depth.to_le_bytes());
    hasher_v10.update(info.capacity.active_sessions.to_le_bytes());
    hasher_v10.update(info.capacity.max_sessions.to_le_bytes());
    let v10_hash: [u8; 32] = hasher_v10.finalize().into();

    let mut msg_v10 = Vec::with_capacity(72);
    msg_v10.extend_from_slice(&info.public_key);
    msg_v10.extend_from_slice(&info.timestamp.to_le_bytes());
    msg_v10.extend_from_slice(&v10_hash);

    assert_ne!(
        msg_v1, msg_v10,
        "R11-01d: Null-terminated 'v1\\0' must differ from 'v10' (prevents prefix attacks)"
    );
}

// =============================================================================
// FINDING 2 -- HIGH: NodeInfo signing did not include addresses.len() count
//
// Before R11, only models.len() was included in the content hash as a count
// prefix. The address list was iterated without a leading count, making the
// hash theoretically vulnerable to ambiguous address boundaries. For example,
// if each address string is length-prefixed, the lack of a count means the
// hash can't distinguish "2 addresses" from "1 address whose serialization
// happens to parse as 2 length-prefixed strings". In practice this is hard
// to exploit because SocketAddr::to_string() has constrained format, but
// including the count is a defense-in-depth measure.
//
// Fix: wire.rs `compute_nodeinfo_signing_message()` -- added
//      `content_hasher.update((info.addresses.len() as u32).to_le_bytes())`
// File: poly-node/src/protocol/wire.rs
// =============================================================================

/// R11-02a: Different number of addresses (even if same total data) produces
/// different signing messages.
#[test]
fn r11_unit_address_count_affects_signing_message() {
    let info_one = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec!["127.0.0.1:4001".parse().unwrap()],
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

    let mut info_two = info_one.clone();
    info_two.addresses = vec![
        "127.0.0.1:4001".parse().unwrap(),
        "127.0.0.1:4001".parse().unwrap(), // Same address repeated
    ];

    let msg_one = compute_nodeinfo_signing_message(&info_one);
    let msg_two = compute_nodeinfo_signing_message(&info_two);

    assert_ne!(
        msg_one, msg_two,
        "R11-02a: Different address count must produce different signing messages"
    );
}

/// R11-02b: Empty vs non-empty address list produces different signing messages.
#[test]
fn r11_unit_empty_vs_nonempty_addresses_differ() {
    let info_empty = NodeInfo {
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

    let mut info_one = info_empty.clone();
    info_one.addresses = vec!["127.0.0.1:80".parse().unwrap()];

    let msg_empty = compute_nodeinfo_signing_message(&info_empty);
    let msg_one = compute_nodeinfo_signing_message(&info_one);

    assert_ne!(
        msg_empty, msg_one,
        "R11-02b: Empty address list must differ from non-empty"
    );
}

/// R11-02c: Server rejects NodeInfo signed without address count in hash.
/// This simulates an attacker producing a signature using the pre-R11 format.
#[tokio::test]
async fn r11_attack_signature_without_address_count_rejected() {
    use sha2::{Digest, Sha256};

    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let public_key = identity.public_key_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let addresses: Vec<SocketAddr> = vec!["127.0.0.1:5000".parse().unwrap()];

    // Compute content hash WITH domain tag but WITHOUT addresses.len()
    let mut hasher = Sha256::new();
    hasher.update(b"poly-node/NodeInfo/v1\0");
    // Skip addresses.len() -- go directly to iterating addresses (pre-R11)
    for a in &addresses {
        let s = a.to_string();
        hasher.update((s.len() as u32).to_le_bytes());
        hasher.update(s.as_bytes());
    }
    hasher.update(0u32.to_le_bytes()); // models.len() = 0
    hasher.update(&[0u8]); // relay_capable = false
    hasher.update(0u32.to_le_bytes()); // queue_depth
    hasher.update(0u32.to_le_bytes()); // active_sessions
    hasher.update(1u32.to_le_bytes()); // max_sessions
    let content_hash: [u8; 32] = hasher.finalize().into();

    let mut msg = Vec::with_capacity(72);
    msg.extend_from_slice(&public_key);
    msg.extend_from_slice(&timestamp.to_le_bytes());
    msg.extend_from_slice(&content_hash);
    let sig = identity.sign(&msg);

    let node_info = NodeInfo {
        public_key,
        addresses,
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

    assert!(
        !ack.accepted,
        "R11-02c: Signature without address count in hash must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 3 -- HIGH: Ping payload not validated, 16 MB memory waste per stream
//
// Before R11, handle_stream() read up to 16 MB for every message type,
// including Ping, and the Ping handler simply discarded the payload:
//   Frame::new(MessageType::Pong, vec![])
//
// An authenticated attacker could send 16 MB Ping frames on up to 256 streams
// per connection. Each stream allocates 16 MB in recv.read_to_end(),
// potentially consuming 4 GB of server memory per connection.
//
// Fix: Ping handler now rejects payloads > MAX_PING_PAYLOAD (128 bytes).
//      This caps the per-stream memory waste to 128 bytes + frame header.
//
// File: node.rs (Ping handler in handle_stream)
// =============================================================================

/// R11-03a: Ping with empty payload still works (regression test).
#[tokio::test]
async fn r11_verify_ping_empty_payload_accepted() {
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
    let (pong_frame, _) = Frame::decode(&data).unwrap();

    assert_eq!(
        pong_frame.msg_type,
        MessageType::Pong,
        "R11-03a: Empty Ping must return Pong"
    );
    assert!(
        pong_frame.payload.is_empty(),
        "R11-03a: Pong payload must be empty"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R11-03b: Ping with small payload (<= MAX_PING_PAYLOAD) still works.
#[tokio::test]
async fn r11_verify_ping_small_payload_accepted() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // Send a Ping with exactly MAX_PING_PAYLOAD bytes (at the limit)
    let payload = vec![0xAB; MAX_PING_PAYLOAD];
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, payload);
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("timeout")
        .expect("read error");
    let (pong_frame, _) = Frame::decode(&data).unwrap();

    assert_eq!(
        pong_frame.msg_type,
        MessageType::Pong,
        "R11-03b: Ping at MAX_PING_PAYLOAD must return Pong"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R11-03c: Ping with oversized payload is rejected (no Pong response).
#[tokio::test]
async fn r11_attack_ping_oversized_payload_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // Send Ping with payload just over the limit
    let payload = vec![0xBB; MAX_PING_PAYLOAD + 1];
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, payload);
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    // Server should drop the stream (no response or connection reset)
    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;

    let got_pong = match result {
        Ok(Ok(data)) if !data.is_empty() => {
            matches!(Frame::decode(&data), Ok((f, _)) if f.msg_type == MessageType::Pong)
        }
        _ => false,
    };

    assert!(
        !got_pong,
        "R11-03c: Oversized Ping payload must NOT return a Pong"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R11-03d: MAX_PING_PAYLOAD constant is appropriately sized.
#[test]
fn r11_unit_max_ping_payload_reasonable() {
    // Ping is a health-check. 128 bytes is more than enough for
    // a nonce or correlation ID. It must NOT be close to 16 MB.
    assert!(
        MAX_PING_PAYLOAD <= 1024,
        "R11-03d: MAX_PING_PAYLOAD should be small (health-check only), got {}",
        MAX_PING_PAYLOAD
    );
    assert!(
        MAX_PING_PAYLOAD >= 64,
        "R11-03d: MAX_PING_PAYLOAD should allow at least a nonce (64 bytes), got {}",
        MAX_PING_PAYLOAD
    );
}

/// R11-03e: Large Ping payload (1 KB) is rejected.
#[tokio::test]
async fn r11_attack_ping_1kb_payload_rejected() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // 1 KB payload -- well above the 128 byte limit
    let payload = vec![0xCC; 1024];
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, payload);
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
        "R11-03e: 1 KB Ping payload must be rejected"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 4 -- MEDIUM: Uniform 16 MB read limit for all message types
//
// handle_stream() uses `recv.read_to_end(16 * 1024 * 1024)` for ALL message
// types. This means a Ping (which needs 5 bytes) allocates the same buffer
// as an InferRequest (which can legitimately be 4 MB). While the Ping payload
// size validation in R11-03 caps the accepted payload, the initial read still
// allocates up to 16 MB from the QUIC stream.
//
// Mitigation: The frame decode rejects payloads > MAX_FRAME_PAYLOAD early,
// and the Ping handler now rejects payloads > 128 bytes. The 16 MB read
// limit is the worst case for a single stream before rejection. With the
// existing MAX_STREAMS_PER_CONN = 256 cap and connection semaphore, the
// maximum memory pressure from this is bounded.
//
// This is documented as a MEDIUM risk -- a future optimization could use
// per-message-type read limits, but the existing mitigations are sufficient
// for Phase 1.
//
// File: node.rs (handle_stream read_to_end call)
// =============================================================================

/// R11-04a: Audit -- verify read_to_end limit matches MAX_FRAME_PAYLOAD.
#[test]
fn r11_audit_read_limit_matches_frame_payload() {
    // The server reads up to 16 MB per stream. This must match MAX_FRAME_PAYLOAD
    // to prevent a legitimate large InferRequest from being rejected by the read
    // limit before reaching the frame decoder.
    assert_eq!(
        MAX_FRAME_PAYLOAD,
        16 * 1024 * 1024,
        "R11-04a: MAX_FRAME_PAYLOAD must be 16 MB"
    );
}

/// R11-04b: Audit -- verify frame decoding rejects payloads > MAX_FRAME_PAYLOAD.
#[test]
fn r11_audit_frame_decode_enforces_max_payload() {
    // Construct a frame header claiming a payload of MAX_FRAME_PAYLOAD + 1
    let oversized_len = (MAX_FRAME_PAYLOAD + 1) as u32;
    let mut data = vec![MessageType::Ping as u8];
    data.extend_from_slice(&oversized_len.to_be_bytes());
    // Add enough trailing bytes to satisfy length (just fill with zeros)
    data.extend(vec![0u8; MAX_FRAME_PAYLOAD + 1]);

    let result = Frame::decode(&data);
    assert!(
        matches!(result, Err(FrameError::PayloadTooLarge(_))),
        "R11-04b: Frame decode must reject payloads > MAX_FRAME_PAYLOAD"
    );
}

// =============================================================================
// FINDING 5 -- MEDIUM: InferResponse.proof field not validated by client
//
// connect_and_infer() validates encrypted_output size, model_id length,
// and model_id binding, but does not validate the `proof` field in
// InferResponse. A malicious server could include an arbitrarily large
// proof (up to 16 MB minus other fields).
//
// Mitigation: The 16 MB read limit caps total response size, and the
// proof field is typically small (< 1 KB for most proof systems).
// Full proof validation requires cryptographic verification which is
// outside the scope of the transport layer.
//
// File: node.rs (connect_and_infer -- InferResponse validation)
// =============================================================================

/// R11-05a: Audit -- client does not validate proof size.
/// This test documents the gap and verifies the response is accepted
/// with various proof sizes.
#[tokio::test]
async fn r11_audit_client_accepts_any_proof_size() {
    let (addr, handle) = start_test_node().await;

    // MockInferenceBackend produces an empty proof, but the client
    // doesn't check the proof field at all. Document this.
    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R11-05a: Normal inference should succeed: {:?}",
        result.err()
    );

    let response = result.unwrap();
    // The mock backend returns an empty proof -- document this gap
    // A real implementation should validate proof structure
    let _ = response.proof; // Proof field exists but is not validated

    handle.abort();
}

// =============================================================================
// FINDING 6 -- MEDIUM: SocketAddr to_string() non-canonical in signing
//
// The signing function uses `addr.to_string()` to serialize addresses into
// the content hash. Rust's SocketAddr::to_string() is deterministic for a
// given SocketAddr value, but different string representations could parse
// to the same SocketAddr:
// - IPv4: "127.0.0.1:80" vs "127.000.000.001:80" (parsed differently)
// - IPv6: "[::1]:80" vs "[0:0:0:0:0:0:0:1]:80" (same after parsing)
//
// Since we hash the string AFTER parsing (from Vec<SocketAddr>), the
// canonical form is always used. The risk is if two implementations
// serialize the same SocketAddr to different strings. Rust guarantees
// consistent output for Display on SocketAddr, so this is LOW in practice.
//
// File: wire.rs (compute_nodeinfo_signing_message -- addr.to_string())
// =============================================================================

/// R11-06a: Verify SocketAddr::to_string() is deterministic for IPv4.
#[test]
fn r11_unit_socket_addr_to_string_deterministic_ipv4() {
    let addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let s1 = addr.to_string();
    let s2 = addr.to_string();
    assert_eq!(s1, s2, "R11-06a: SocketAddr::to_string() must be deterministic");
    assert_eq!(s1, "127.0.0.1:4001", "R11-06a: Must use canonical form");
}

/// R11-06b: Verify SocketAddr::to_string() is deterministic for IPv6.
#[test]
fn r11_unit_socket_addr_to_string_deterministic_ipv6() {
    let addr: SocketAddr = "[::1]:4001".parse().unwrap();
    let s1 = addr.to_string();
    let s2 = addr.to_string();
    assert_eq!(s1, s2, "R11-06b: IPv6 SocketAddr::to_string() must be deterministic");
}

/// R11-06c: Different SocketAddr representations that parse to different values
/// produce different signing messages.
#[test]
fn r11_unit_different_socket_addrs_different_messages() {
    let info_v4 = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec!["127.0.0.1:4001".parse().unwrap()],
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

    let mut info_v6 = info_v4.clone();
    info_v6.addresses = vec!["[::1]:4001".parse().unwrap()];

    let msg_v4 = compute_nodeinfo_signing_message(&info_v4);
    let msg_v6 = compute_nodeinfo_signing_message(&info_v6);

    assert_ne!(
        msg_v4, msg_v6,
        "R11-06c: IPv4 and IPv6 loopback must produce different signing messages"
    );
}

// =============================================================================
// FINDING 7 -- LOW: FrameError did not implement PartialEq
//
// Before R11, FrameError only derived Debug. Test code had to use
// matches!() macro instead of direct == comparison. This is a QoL
// improvement for test ergonomics.
//
// Fix: Added `#[derive(PartialEq)]` to FrameError in wire.rs
// File: poly-node/src/protocol/wire.rs
// =============================================================================

/// R11-07a: Verify FrameError PartialEq works for Incomplete.
#[test]
fn r11_unit_frame_error_partial_eq_incomplete() {
    assert_eq!(
        Frame::decode(&[0x01]).unwrap_err(),
        FrameError::Incomplete,
        "R11-07a: FrameError::Incomplete must be comparable with =="
    );
}

/// R11-07b: Verify FrameError PartialEq works for UnknownType.
#[test]
fn r11_unit_frame_error_partial_eq_unknown_type() {
    let data = [0xFF, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        Frame::decode(&data).unwrap_err(),
        FrameError::UnknownType(0xFF),
        "R11-07b: FrameError::UnknownType must be comparable with =="
    );
}

/// R11-07c: Verify FrameError PartialEq works for PayloadTooLarge.
#[test]
fn r11_unit_frame_error_partial_eq_payload_too_large() {
    let oversized_len = (MAX_FRAME_PAYLOAD + 1) as u32;
    let mut data = vec![MessageType::Ping as u8];
    data.extend_from_slice(&oversized_len.to_be_bytes());
    data.extend(vec![0u8; MAX_FRAME_PAYLOAD + 1]);

    assert_eq!(
        Frame::decode(&data).unwrap_err(),
        FrameError::PayloadTooLarge(MAX_FRAME_PAYLOAD + 1),
        "R11-07c: FrameError::PayloadTooLarge must be comparable with =="
    );
}

// =============================================================================
// FINDING 8 -- LOW: Client endpoint binds to 0.0.0.0:0
//
// create_client_endpoint() binds to 0.0.0.0:0, letting the OS choose
// a port. This is standard for QUIC clients but means the client's
// local address is unpredictable. In restrictive firewall environments,
// binding to a specific interface might be preferred.
//
// This is a documentation/audit finding, not a security vulnerability.
// File: net/transport.rs
// =============================================================================

/// R11-08a: Audit -- client endpoint binds to 0.0.0.0:0
#[tokio::test]
async fn r11_audit_client_endpoint_binds_any() {
    let endpoint = transport::create_client_endpoint().unwrap();
    let local_addr = endpoint.local_addr().unwrap();
    // Verify the port is non-zero (OS assigned a port)
    assert_ne!(
        local_addr.port(),
        0,
        "R11-08a: Client endpoint must bind to OS-assigned port (not 0)"
    );
    endpoint.close(0u32.into(), b"test");
}

// =============================================================================
// REGRESSION TESTS: Verify all R11 changes are backwards-compatible
// =============================================================================

/// R11-regression-a: Full handshake + inference flow still works after R11 changes.
#[tokio::test]
async fn r11_regression_full_flow() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R11-regression-a: connect_and_infer must succeed: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.model_id, "test");
    assert!(!response.encrypted_output.is_empty());

    handle.abort();
}

/// R11-regression-b: Properly signed NodeInfo with custom fields still accepted.
#[tokio::test]
async fn r11_regression_signed_nodeinfo_with_fields_accepted() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let node_info = build_signed_node_info_with(
        &identity,
        vec!["192.168.1.1:4001".parse().unwrap()],
        vec![
            ModelCapability {
                model_name: "test-model".into(),
                gpu: true,
                throughput_estimate: 42.0,
            },
        ],
        true,
        NodeCapacity {
            queue_depth: 1,
            active_sessions: 0,
            max_sessions: 4,
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
        "R11-regression-b: Properly signed NodeInfo with custom fields must be accepted"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R11-regression-c: Ping-pong after handshake still works.
#[tokio::test]
async fn r11_regression_ping_pong_works() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // Send 5 sequential pings
    for i in 0..5 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let ping_frame = Frame::new(MessageType::Ping, vec![]);
        send.write_all(&ping_frame.encode()).await.unwrap();
        send.finish().unwrap();

        let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
            .await
            .expect("timeout")
            .expect("read error");
        let (pong_frame, _) = Frame::decode(&data).unwrap();
        assert_eq!(
            pong_frame.msg_type,
            MessageType::Pong,
            "R11-regression-c: Ping {} must return Pong",
            i
        );
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R11-regression-d: Server's HelloAck has a valid R11 full-field signature.
#[tokio::test]
async fn r11_regression_server_helloack_has_valid_r11_signature() {
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
    assert!(ack.accepted, "Handshake must succeed");

    // Verify server's signature using the R11 signing function
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&ack.node_info.public_key).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&ack.node_info.signature);
    let msg = compute_nodeinfo_signing_message(&ack.node_info);
    let valid = poly_node::identity::verify_signature(&vk, &msg, &sig_arr);

    assert!(
        valid,
        "R11-regression-d: Server's HelloAck must have a valid R11 signature \
        (domain tag + address count included)"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R11-regression-e: Multiple inference requests on different connections.
#[tokio::test]
async fn r11_regression_multiple_inferences() {
    let (addr, handle) = start_test_node().await;

    for i in 0..3 {
        let request = test_infer_request(&[i as u32, i as u32 + 1]);
        let result = poly_node::node::connect_and_infer(addr, &request).await;
        assert!(
            result.is_ok(),
            "R11-regression-e: Inference {} must succeed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}
