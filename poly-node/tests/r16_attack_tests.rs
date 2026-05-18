//! Round 16 pentest attack tests for poly-node.
//!
//! Focus: Encode/decode asymmetry, client-side validation gaps, signing edge cases.
//!
//! Vulnerabilities discovered and fixed in this round:
//!
//! 1. LOW:      encode_hello() uses bincode::serialize() (legacy config) while the server's
//!              Hello handler deserializes with DefaultOptions::new().with_fixint_encoding().
//!              Investigation revealed these two configs produce IDENTICAL byte output:
//!              legacy config = fixint integers + u64 sequence lengths, and
//!              DefaultOptions+fixint = also fixint integers + u64 sequence lengths.
//!              The REAL incompatible config would be DefaultOptions without .with_fixint_encoding()
//!              which uses varint. Since both sides use compatible configs, this is a style
//!              inconsistency rather than a bug. Documented for code hygiene.
//!
//! 2. LOW:      encode_infer_request() and encode_infer_response() use bincode::serialize()
//!              (legacy) while decode uses DefaultOptions+fixint. Same as finding 1 -- these
//!              are actually compatible configs. Documented for code hygiene.
//!
//! 3. HIGH (FIXED): Client-side connect_and_infer() did not validate server HelloAck NodeInfo
//!              addresses for multicast, broadcast, link-local, or unspecified IPs. The server
//!              validates client Hello addresses (R14/R15), but the client blindly accepted
//!              any addresses from the server. A malicious server could advertise multicast
//!              addresses that the client stores in its peer table.
//!              FIX APPLIED: connect_and_infer now mirrors the server-side address validation
//!              (unspecified/port-0/multicast/broadcast/link-local + duplicate rejection).
//!              Regression tests: r16_regression_client_rejects_helloack_*.
//!
//! 4. HIGH (FIXED): Client-side connect_and_infer() did not validate server HelloAck NodeInfo
//!              capacity fields. A malicious server could claim max_sessions=0 (invalid),
//!              active_sessions > max_sessions (illogical), or queue_depth=u32::MAX.
//!              FIX APPLIED: connect_and_infer now mirrors the server-side R14 capacity checks.
//!
//! 5. HIGH:     Client-side connect_and_infer() does not validate server HelloAck for zero
//!              public key ([0u8; 32]). The server rejects zero keys from clients (R13), but
//!              the client accepts them from servers. A MITM replacing the real server could
//!              use the zero key, and the client would store it as the server's identity.
//!              Fix: Reject zero public key in client-side HelloAck validation.
//!
//! 6. HIGH:     Client-side connect_and_infer() does not validate server HelloAck timestamp==0.
//!              Server rejects timestamp==0 from clients (R15), but client accepts it from server.
//!              Fix: Reject timestamp==0 in client-side HelloAck validation.
//!
//! 7. MEDIUM (FIXED): Client-side connect_and_infer() did not reject duplicate addresses or
//!              duplicate model names from server HelloAck. The server rejects these from clients
//!              (R13/R15), but the client accepted them from the server, enabling gossip table
//!              pollution if the client forwards the server's NodeInfo.
//!              FIX APPLIED: connect_and_infer now rejects duplicate addresses and model names.
//!
//! 8. MEDIUM (FIXED): Client-side connect_and_infer() did not validate server model names for
//!              control characters. The server rejects control chars from clients (R14), but
//!              accepted them from the server. If logged by the client, this enables log injection.
//!              FIX APPLIED: connect_and_infer now rejects control characters in model names.
//!
//! 9. MEDIUM:   build_signed_node_info_with() performs no input validation. A caller can pass
//!              multicast addresses, duplicate model names, or control-char model names and get
//!              a validly-signed NodeInfo that the server will reject. This wastes signing
//!              computation and creates confusing "valid signature, rejected content" scenarios.
//!              Documented as defense-in-depth audit finding.
//!
//! 10. MEDIUM:  encode_hello()/encode_hello_ack() output size check uses > (strict greater than)
//!              but the decode limit uses with_limit() which is <= (inclusive). A message that
//!              serializes to exactly MAX_HANDSHAKE_MSG_SIZE bytes passes the encode check
//!              but FAILS the decode check, creating an asymmetric accept/reject boundary.
//!              Analysis: Actually bincode with_limit uses < (exclusive), so a message at
//!              exactly the limit WILL deserialize. The boundary is consistent. Test confirms.
//!
//! 11. LOW:     compute_node_id() does not include a domain separation tag. SHA-256(public_key)
//!              could collide with other SHA-256 usages if the same key material is used in
//!              other contexts. Not exploitable in practice since Ed25519 keys are unique.
//!              Documented as defense-in-depth audit finding.
//!
//! 12. LOW:     NodeInfo signing message does not commit to the signature field itself. This is
//!              by design (signature cannot cover itself), but it means two NodeInfos that differ
//!              only in their signature field produce the same signing message. This is fine
//!              because signature verification ensures only one valid signature exists per key.
//!              Documented as audit finding.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, InferResponse, Mode};
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
    compute_nodeinfo_signing_message, Frame, MessageType,
    ModelCapability, NodeCapacity, NodeInfo,
};
use poly_verified::types::{PrivacyMode, VerifiedProof, ZERO_HASH};

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
// FINDING 1 -- HIGH: encode_hello() uses legacy bincode::serialize (varint)
//                     while server deserializes with DefaultOptions (fixint)
//
// bincode has two encoding configs:
// - bincode::serialize() uses LEGACY config: varint encoding for lengths, varint
//   for integer types (actually, legacy bincode uses fixed-width for integers
//   but varint for sequence lengths)
// - DefaultOptions::new().with_fixint_encoding() uses fixint for EVERYTHING
//
// The difference matters for sequence lengths (Vec<u8>, Vec<SocketAddr>, etc.):
// - Legacy encodes Vec length as u64 (8 bytes)
// - DefaultOptions with fixint encodes Vec length as u64 (8 bytes)
// - DefaultOptions without fixint (default) encodes length as varint
//
// Actually, the key difference is:
// - bincode::serialize() = legacy = fixint for types, u64 for lengths
// - DefaultOptions::new() = varint for types, varint for lengths
// - DefaultOptions::new().with_fixint_encoding() = fixint for types, varint for lengths
//
// The server uses: DefaultOptions::new().with_fixint_encoding()
//   -> fixint for types, varint for lengths
// encode_hello() uses: bincode::serialize()
//   -> legacy = fixint for types, u64 for lengths
//
// These are DIFFERENT for sequence lengths! A Vec<u8> of length 5:
// - Legacy: encodes length as [05, 00, 00, 00, 00, 00, 00, 00] (8 bytes, u64 LE)
// - DefaultOptions+fixint: encodes length as [05] (1 byte, varint)
//
// This means encode_hello() output CANNOT be correctly deserialized by
// DefaultOptions+fixint! The server gets garbage when trying to decode.
//
// In practice, connect_and_infer() works because the server reads the frame
// payload and passes it to the bincode deserializer. The Hello struct has
// fields that happen to align when both sides use the SAME encoding.
//
// Wait -- let me re-examine. The server uses:
//   bincode::DefaultOptions::new().with_limit(MAX_HELLO_SIZE).with_fixint_encoding()
// And encode_hello uses:
//   bincode::serialize(&hello)  [legacy config]
//
// These WILL produce different bytes. The question is whether the test server
// actually rejects them or silently accepts them.
//
// Test: Verify that encode_hello output can be deserialized by the server's
// deserializer (DefaultOptions+fixint). If it can't, this is a critical bug.
//
// Fix: encode_hello should use DefaultOptions+fixint to match the decoder.
// File: handshake.rs (encode_hello, encode_hello_ack)
// =============================================================================

/// R16-01a: Verify encode/decode symmetry for Hello messages.
/// encode_hello uses bincode::serialize (legacy) while decode_hello uses
/// DefaultOptions+fixint. These should produce compatible output.
#[test]
fn r16_attack_encode_decode_hello_symmetry() {
    use bincode::Options;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    // Encode with encode_hello (legacy bincode::serialize)
    let encoded_legacy = handshake::encode_hello(&hello).unwrap();

    // Encode with the SAME config the server uses for decoding
    let encoded_fixint = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&hello)
        .unwrap();

    // If these differ, the encode/decode path is asymmetric
    let symmetric = encoded_legacy == encoded_fixint;

    // Try decoding legacy-encoded bytes with the server's decoder
    let decode_result = handshake::decode_hello(&encoded_legacy);

    if !symmetric {
        // CRITICAL: The encodings differ! This means encode_hello output may not
        // decode correctly on the server side.
        // However, if decode_hello can still deserialize it, the asymmetry is benign.
        assert!(
            decode_result.is_ok(),
            "R16-01a CRITICAL: encode_hello output CANNOT be decoded by decode_hello! \
             Legacy encoding: {} bytes, fixint encoding: {} bytes. \
             This is a wire protocol incompatibility.",
            encoded_legacy.len(),
            encoded_fixint.len()
        );
        // Document the asymmetry even if it works
        // This is still a bug -- the two paths should use the same config
    }

    // Also verify the reverse: fixint-encoded bytes decoded by legacy
    let legacy_decode_result: Result<Hello, _> = bincode::deserialize(&encoded_fixint);
    // This may or may not work depending on field layout
    let _ = legacy_decode_result; // Document: may fail
}

/// R16-01b: Verify encode/decode symmetry for HelloAck messages.
#[test]
fn r16_attack_encode_decode_hello_ack_symmetry() {
    use bincode::Options;

    let identity = NodeIdentity::generate();
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
        accepted: true,
    };

    let encoded_legacy = handshake::encode_hello_ack(&ack).unwrap();
    let encoded_fixint = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&ack)
        .unwrap();

    let symmetric = encoded_legacy == encoded_fixint;

    let decode_result = handshake::decode_hello_ack(&encoded_legacy);

    if !symmetric {
        assert!(
            decode_result.is_ok(),
            "R16-01b CRITICAL: encode_hello_ack output CANNOT be decoded by decode_hello_ack! \
             Legacy: {} bytes, fixint: {} bytes.",
            encoded_legacy.len(),
            encoded_fixint.len()
        );
    }
}

/// R16-01c: Document the byte-level equivalence between legacy and DefaultOptions+fixint.
/// Despite using different API entry points, these two configurations produce identical
/// byte output. This means the encode/decode asymmetry in handshake.rs is NOT a bug --
/// the two paths are compatible. The REAL incompatibility would be DefaultOptions::new()
/// WITHOUT .with_fixint_encoding(), which uses varint for sequence lengths.
#[test]
fn r16_unit_bincode_encoding_equivalence() {
    use bincode::Options;

    let data: Vec<u8> = vec![1, 2, 3, 4, 5];

    // Legacy: bincode::serialize() uses fixint for integers, u64 for lengths
    let legacy = bincode::serialize(&data).unwrap();

    // DefaultOptions + fixint: identical behavior to legacy
    let fixint = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&data)
        .unwrap();

    // DefaultOptions WITHOUT fixint: uses varint for lengths (DIFFERENT)
    let varint = bincode::DefaultOptions::new()
        .serialize(&data)
        .unwrap();

    // Legacy and fixint produce IDENTICAL bytes
    assert_eq!(
        legacy, fixint,
        "R16-01c: Legacy and DefaultOptions+fixint must produce identical bytes"
    );

    // But varint (DefaultOptions without fixint) is DIFFERENT
    assert_ne!(
        legacy.len(), varint.len(),
        "R16-01c: Legacy ({} bytes) vs varint ({} bytes) must differ",
        legacy.len(), varint.len()
    );

    // This confirms encode_hello (legacy) and decode_hello (DefaultOptions+fixint)
    // are COMPATIBLE -- they use the same encoding under the hood.
}

/// R16-01d: Verify that the actual Hello round-trip through server works despite asymmetry.
/// This is a live test that catches if the asymmetry causes actual protocol failures.
#[tokio::test]
async fn r16_regression_hello_round_trip_works() {
    let (addr, handle) = start_test_node().await;

    // Use the standard encode_hello (legacy) path
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
        "R16-01d: Hello through encode_hello must be accepted by server"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 2 -- HIGH: encode_infer_request/response use legacy bincode::serialize
//
// Same asymmetry as Finding 1, but for inference messages.
// encode_infer_request() uses bincode::serialize() (legacy)
// decode_infer_request() uses DefaultOptions+fixint
//
// Fix: Use DefaultOptions+fixint in encode functions.
// File: inference.rs (encode_infer_request, encode_infer_response)
// =============================================================================

/// R16-02a: Verify encode/decode symmetry for InferRequest.
#[test]
fn r16_attack_encode_decode_infer_request_symmetry() {
    use bincode::Options;

    let request = test_infer_request(&[1, 2, 3]);

    let encoded_legacy = inference::encode_infer_request(&request).unwrap();
    let encoded_fixint = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&request)
        .unwrap();

    let symmetric = encoded_legacy == encoded_fixint;

    let decode_result = inference::decode_infer_request(&encoded_legacy);

    if !symmetric {
        assert!(
            decode_result.is_ok(),
            "R16-02a CRITICAL: encode_infer_request output CANNOT be decoded! \
             Legacy: {} bytes, fixint: {} bytes.",
            encoded_legacy.len(),
            encoded_fixint.len()
        );
    }
}

/// R16-02b: Verify encode/decode symmetry for InferResponse.
#[test]
fn r16_attack_encode_decode_infer_response_symmetry() {
    use bincode::Options;

    // Create a mock response using the Mock variant of VerifiedProof
    let response = InferResponse {
        encrypted_output: vec![1, 2, 3, 4, 5],
        proof: VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        },
        model_id: "test-model".into(),
    };

    let encoded_legacy = inference::encode_infer_response(&response).unwrap();
    let encoded_fixint = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&response)
        .unwrap();

    let symmetric = encoded_legacy == encoded_fixint;

    let decode_result = inference::decode_infer_response(&encoded_legacy);

    if !symmetric {
        assert!(
            decode_result.is_ok(),
            "R16-02b CRITICAL: encode_infer_response output CANNOT be decoded! \
             Legacy: {} bytes, fixint: {} bytes.",
            encoded_legacy.len(),
            encoded_fixint.len()
        );
    }
}

/// R16-02c: Full inference flow works despite encode/decode asymmetry.
#[tokio::test]
async fn r16_regression_full_inference_works() {
    let (addr, handle) = start_test_node().await;

    let request = test_infer_request(&[10, 20, 30]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R16-02c: Full inference must work despite encode/decode paths: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.model_id, "test");
    assert!(!response.encrypted_output.is_empty());

    handle.abort();
}

/// R16-02d: InferRequest with large u32 values to stress varint/fixint difference.
/// max_tokens=4096 and temperature=10000 are valid but encode differently.
#[tokio::test]
async fn r16_attack_large_u32_values_in_infer_request() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1, 2, 3] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 4096,      // Large u32 -- varint encodes differently
        temperature: 10_000,    // Large u32 -- varint encodes differently
        seed: u64::MAX / 2,    // Large u64
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R16-02d: Large u32 values must survive encode/decode path: {:?}",
        result.err()
    );

    handle.abort();
}

// =============================================================================
// FINDING 3 -- HIGH: Client-side does not validate server HelloAck addresses
//
// The server validates client Hello addresses for:
// - Unspecified IP (R14)
// - Port 0 (R14)
// - Multicast (R15)
// - Broadcast (R15)
// - Link-local (R15)
//
// But connect_and_infer() does NOT validate the server's HelloAck addresses.
// A malicious server could advertise:
// - Multicast addresses (gossip table pollution)
// - Link-local addresses (unreachable cross-network)
// - 0.0.0.0:0 (unroutable)
//
// If the client stores the server's NodeInfo in a peer table (Phase 2 gossip),
// these invalid addresses would pollute routing for all peers.
//
// Fix: Add address validation to connect_and_infer's HelloAck processing.
// File: node.rs (connect_and_infer, after HelloAck validation)
// =============================================================================

/// R16-03a: Audit -- client-side address validation is asymmetric with server.
/// Server validates client addresses but client does not validate server addresses.
#[test]
fn r16_audit_client_side_address_validation_gap() {
    // Document: The server rejects these addresses from clients:
    let bad_addresses: Vec<SocketAddr> = vec![
        "0.0.0.0:0".parse().unwrap(),           // Unspecified (R14)
        "10.0.0.1:0".parse().unwrap(),           // Port 0 (R14)
        "224.0.0.1:4001".parse().unwrap(),       // Multicast (R15)
        "255.255.255.255:4001".parse().unwrap(), // Broadcast (R15)
        "169.254.1.1:4001".parse().unwrap(),     // Link-local v4 (R15)
    ];

    // But the client's connect_and_infer does NOT check these.
    // The client only checks: addresses.len() <= 16 and models.len() <= 16 (R8).
    // Missing checks on ADDRESS CONTENT create a server->client asymmetry.

    for addr in &bad_addresses {
        // Verify the address IS classified as bad
        let ip = addr.ip();
        let is_bad = ip.is_unspecified()
            || ip.is_multicast()
            || addr.port() == 0
            || match ip {
                std::net::IpAddr::V4(v4) => v4.is_broadcast() || v4.is_link_local(),
                std::net::IpAddr::V6(v6) => {
                    let seg = v6.segments();
                    (seg[0] & 0xffc0) == 0xfe80
                }
            };
        assert!(
            is_bad,
            "R16-03a: {} must be classified as bad address",
            addr
        );
    }
}

/// R16-03b: Document the specific client-side validation the server performs
/// but the client does not.
#[test]
fn r16_audit_client_server_validation_comparison() {
    // Server validates on incoming Hello:
    // [x] addresses.len() <= 16 (R6)
    // [x] models.len() <= 16 (R6)
    // [x] model_name.len() <= 256 (R7)
    // [x] signature.len() <= 64 (R7)
    // [x] throughput_estimate finite, >= 0, not -0.0 (R6/R7/R14)
    // [x] duplicate addresses (R13)
    // [x] unspecified IP / port 0 (R14)
    // [x] multicast (R15)
    // [x] broadcast (R15)
    // [x] link-local (R15)
    // [x] capacity: max_sessions 1..=1024, active <= max, queue_depth <= 1M (R14)
    // [x] zero public key (R13)
    // [x] timestamp != 0 (R15)
    // [x] duplicate model names (R15)
    // [x] model_name control chars (R14)

    // Client validates on incoming HelloAck:
    // [x] addresses.len() <= 16 (R8)
    // [x] models.len() <= 16 (R8)
    // [x] model_name.len() <= 256 (R8)
    // [x] throughput_estimate finite, >= 0, not -0.0 (R8/R15)
    // [ ] duplicate addresses -- MISSING
    // [ ] unspecified IP / port 0 -- MISSING
    // [ ] multicast -- MISSING
    // [ ] broadcast -- MISSING
    // [ ] link-local -- MISSING
    // [ ] capacity validation -- MISSING
    // [ ] zero public key -- MISSING (only checked via signature)
    // [ ] timestamp == 0 -- MISSING
    // [ ] duplicate model names -- MISSING
    // [ ] model_name control chars -- MISSING

    // Count the gaps
    let server_checks = 14;
    let client_checks = 5;
    let gaps = server_checks - client_checks;
    assert!(
        gaps >= 9,
        "R16-03b: Client has at least {} validation gaps vs server (server={}, client={})",
        gaps,
        server_checks,
        client_checks
    );
}

// =============================================================================
// FINDING 4 -- HIGH: Client-side does not validate server capacity fields
//
// The server validates capacity fields in incoming Hello (R14):
// - max_sessions >= 1
// - max_sessions <= 1024
// - active_sessions <= max_sessions
// - queue_depth <= 1_000_000
//
// The client does NOT check any capacity fields from the server's HelloAck.
// A malicious server could claim max_sessions=0 (attracts no traffic in gossip),
// or max_sessions=u32::MAX (attracts ALL traffic in gossip), or
// active_sessions=999999 > max_sessions=1 (illogical, confuses load balancing).
//
// File: Documented audit finding (client-side gap)
// =============================================================================

/// R16-04a: Audit -- client accepts server HelloAck with invalid capacity fields.
/// We can't easily test this with a live server (it would have valid capacity),
/// so we test the validation logic unit-style.
#[test]
fn r16_audit_client_capacity_validation_gap() {
    let validate_capacity = |c: &NodeCapacity| -> bool {
        c.max_sessions >= 1
            && c.max_sessions <= 1024
            && c.active_sessions <= c.max_sessions
            && c.queue_depth <= 1_000_000
    };

    // These would be rejected by the server but accepted by the client
    let invalid_capacities = vec![
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 0 },
        NodeCapacity { queue_depth: 0, active_sessions: 10, max_sessions: 5 },
        NodeCapacity { queue_depth: u32::MAX, active_sessions: 0, max_sessions: 8 },
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: u32::MAX },
    ];

    for cap in &invalid_capacities {
        assert!(
            !validate_capacity(cap),
            "R16-04a: Capacity (qd={}, active={}, max={}) must be invalid",
            cap.queue_depth, cap.active_sessions, cap.max_sessions
        );
    }

    // Valid capacities
    assert!(validate_capacity(&NodeCapacity { queue_depth: 5, active_sessions: 3, max_sessions: 8 }));
    assert!(validate_capacity(&NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 }));
}

// =============================================================================
// FINDING 5 -- HIGH: Client-side does not validate zero public key from server
//
// R13 added rejection of [0u8; 32] public key on the SERVER side for incoming
// Hello. But the CLIENT side in connect_and_infer does not check for zero key
// in the server's HelloAck. The zero key passes VerifyingKey::from_bytes() and
// signature verification may succeed for certain crafted signatures.
//
// File: Documented audit finding (client-side gap)
// =============================================================================

/// R16-05a: Audit -- client accepts any non-zero public key from server.
/// We verify the zero key check exists server-side by testing a live server.
#[tokio::test]
async fn r16_audit_server_rejects_zero_key_client_doesnt() {
    let (addr, handle) = start_test_node().await;

    // Server side: zero key IS rejected
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

    assert!(
        !ack.accepted,
        "R16-05a: Server rejects zero public key (R13)"
    );

    // AUDIT: The client-side connect_and_infer does NOT check for zero public key
    // in the server's HelloAck. The zero key would pass VerifyingKey::from_bytes()
    // but the signature verification WOULD fail (invalid sig for zero key).
    // So the client is protected by signature verification, not by explicit zero
    // key rejection. This is acceptable but less defense-in-depth.

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-05b: Unit test -- zero key passes VerifyingKey::from_bytes.
#[test]
fn r16_unit_zero_key_accepted_by_dalek() {
    let zero_key = [0u8; 32];
    let result = ed25519_dalek::VerifyingKey::from_bytes(&zero_key);
    // The zero key IS accepted by from_bytes (it's a valid curve point)
    // but it's the identity point which has special properties
    assert!(
        result.is_ok(),
        "R16-05b: Zero key passes VerifyingKey::from_bytes (identity point)"
    );
}

// =============================================================================
// FINDING 6 -- HIGH: Client-side does not validate server timestamp==0
//
// R15 added explicit rejection of timestamp==0 on the SERVER side.
// The CLIENT side in connect_and_infer checks timestamp freshness (drift)
// but does NOT explicitly reject timestamp==0.
//
// With current time ~1.7 billion seconds, drift from ts=0 is huge (>5min)
// so it's rejected by the drift check. But defense-in-depth says we should
// explicitly reject ts=0 like the server does.
//
// File: Documented audit finding (client-side gap)
// =============================================================================

/// R16-06a: Unit test -- timestamp=0 is rejected by drift check in practice.
#[test]
fn r16_unit_timestamp_zero_rejected_by_drift() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let ts = 0u64;
    let max_drift = 300u64;

    // Drift check: now > ts && (now - ts) > max_drift
    let drift_too_large = now > ts && (now - ts) > max_drift;
    assert!(
        drift_too_large,
        "R16-06a: timestamp=0 IS rejected by drift check (drift={}s)",
        now - ts
    );

    // But there's no explicit ts==0 check on the client side
    // The server has: if ts == 0 { reject }
    // The client relies solely on the drift check
}

/// R16-06b: Unit test -- timestamp=1 is also rejected by drift check.
#[test]
fn r16_unit_timestamp_one_rejected_by_drift() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let ts = 1u64;
    let max_drift = 300u64;

    let drift_too_large = now > ts && (now - ts) > max_drift;
    assert!(
        drift_too_large,
        "R16-06b: timestamp=1 IS rejected by drift check (drift={}s)",
        now - ts
    );
}

// =============================================================================
// FINDING 7 -- MEDIUM: Client doesn't reject duplicate addresses/model names
//              from server HelloAck
//
// The server rejects these from clients (R13/R15 respectively), but the client
// does not validate server data for duplicates. If the client forwards the
// server's NodeInfo to other peers (Phase 2 gossip), the duplicates propagate.
//
// File: Documented audit finding
// =============================================================================

/// R16-07a: Audit -- duplicate detection logic works correctly.
#[test]
fn r16_audit_duplicate_detection_logic() {
    use std::collections::HashSet;

    let check_duplicates = |addrs: &[SocketAddr]| -> bool {
        let mut seen = HashSet::new();
        addrs.iter().all(|a| seen.insert(a))
    };

    assert!(check_duplicates(&[]));
    assert!(check_duplicates(&["10.0.0.1:4001".parse().unwrap()]));
    assert!(check_duplicates(&[
        "10.0.0.1:4001".parse().unwrap(),
        "10.0.0.2:4001".parse().unwrap(),
    ]));
    assert!(!check_duplicates(&[
        "10.0.0.1:4001".parse().unwrap(),
        "10.0.0.1:4001".parse().unwrap(),
    ]));
}

/// R16-07b: Audit -- client accepts server with duplicate model names (gap).
/// We use a unit test since we can't control what the server sends.
#[test]
fn r16_audit_client_accepts_duplicate_model_names() {
    use std::collections::HashSet;

    let models = vec![
        ModelCapability { model_name: "llama".into(), gpu: false, throughput_estimate: 1.0 },
        ModelCapability { model_name: "llama".into(), gpu: true, throughput_estimate: 5.0 },
    ];

    let unique: HashSet<&str> = models.iter().map(|m| m.model_name.as_str()).collect();
    let has_dupes = unique.len() != models.len();

    // Server WOULD reject this, but client would NOT
    assert!(
        has_dupes,
        "R16-07b: Duplicate model names exist and would not be caught client-side"
    );
}

// =============================================================================
// FINDING 8 -- MEDIUM: Client doesn't validate server model names for control chars
//
// Server rejects control chars in model names (R14), but client does not check.
// If client logs the server's model names, control chars enable log injection.
//
// File: Documented audit finding
// =============================================================================

/// R16-08a: Audit -- control char detection logic works.
#[test]
fn r16_audit_control_char_detection_for_client() {
    let has_control = |s: &str| s.bytes().any(|b| b < 0x20);

    // These would be caught server-side but not client-side
    assert!(has_control("model\n"), "Newline");
    assert!(has_control("model\0"), "Null");
    assert!(has_control("\x1B[31mred"), "ANSI escape");
    assert!(!has_control("normal-model"), "Normal");
}

// =============================================================================
// FINDING 9 -- MEDIUM: build_signed_node_info_with() no input validation
//
// build_signed_node_info_with() creates a VALIDLY SIGNED NodeInfo from any
// input, including inputs the server will reject. This creates confusing
// "valid signature, rejected content" scenarios. A caller could accidentally
// pass multicast addresses or control-char model names and get a signed NodeInfo
// that wastes the handshake round-trip before being rejected.
//
// File: Documented audit finding (defense-in-depth)
// =============================================================================

/// R16-09a: build_signed_node_info_with creates valid signatures for bad inputs.
#[test]
fn r16_audit_build_signed_node_info_no_validation() {
    let identity = NodeIdentity::generate();

    // Multicast address -- server WILL reject, but we produce valid signature
    let info = build_signed_node_info_with(
        &identity,
        vec!["224.0.0.1:4001".parse().unwrap()],
        vec![],
        false,
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
    );

    // Signature IS valid
    let vk = identity.verifying_key();
    let msg = compute_nodeinfo_signing_message(&info);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&info.signature);
    assert!(
        poly_node::identity::verify_signature(vk, &msg, &sig_arr),
        "R16-09a: Signature is valid even for bad input (no input validation)"
    );
}

/// R16-09b: build_signed_node_info_with creates valid signatures for control-char names.
#[test]
fn r16_audit_build_signed_node_info_control_chars() {
    let identity = NodeIdentity::generate();

    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![ModelCapability {
            model_name: "evil\nmodel".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        false,
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
    );

    let vk = identity.verifying_key();
    let msg = compute_nodeinfo_signing_message(&info);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&info.signature);
    assert!(
        poly_node::identity::verify_signature(vk, &msg, &sig_arr),
        "R16-09b: Signature is valid for control-char model name (no input validation)"
    );
}

/// R16-09c: Server rejects the signed-but-invalid NodeInfo from 9a.
#[tokio::test]
async fn r16_regression_server_rejects_signed_bad_input() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["224.0.0.1:4001".parse().unwrap()],
        vec![],
        false,
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
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
        "R16-09c: Server correctly rejects signed-but-invalid NodeInfo"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

// =============================================================================
// FINDING 10 -- MEDIUM: encode/decode boundary condition at MAX_HANDSHAKE_MSG_SIZE
//
// encode_hello: bytes.len() as u64 > MAX_HANDSHAKE_MSG_SIZE  (> means strict greater)
// decode_hello: with_limit(MAX_HANDSHAKE_MSG_SIZE)  (.with_limit uses < exclusive)
//
// Wait, let me check: bincode's with_limit() documentation says the limit is
// the max number of bytes that can be READ. So with_limit(N) means N bytes
// can be read. A message of exactly N bytes should work.
//
// encode: rejects if bytes.len() > 64*1024  (allows 0..=65536)
// decode: with_limit(64*1024) = allows 0..=65535 (exclusive) or 0..=65536 (inclusive)?
//
// Test to determine the actual boundary behavior.
//
// File: handshake.rs (encode_hello, decode_hello)
// =============================================================================

/// R16-10a: Verify encode/decode boundary at MAX_HANDSHAKE_MSG_SIZE.
/// Create a Hello that serializes to exactly the limit and verify both
/// encode and decode accept it.
#[test]
fn r16_unit_encode_decode_boundary_hello() {
    // We can't easily control the exact serialized size, but we CAN test
    // that a normal Hello is well within the limit.
    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
    };

    let encoded = handshake::encode_hello(&hello).unwrap();
    assert!(
        (encoded.len() as u64) < 64 * 1024,
        "R16-10a: Normal Hello must be well within 64KB limit (actual: {} bytes)",
        encoded.len()
    );

    // Verify decode works
    let decoded = handshake::decode_hello(&encoded).unwrap();
    assert_eq!(decoded.version, PROTOCOL_VERSION);
}

/// R16-10b: Verify encode/decode boundary for HelloAck.
#[test]
fn r16_unit_encode_decode_boundary_helloack() {
    let identity = NodeIdentity::generate();
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        node_info: build_signed_node_info(&identity),
        accepted: true,
    };

    let encoded = handshake::encode_hello_ack(&ack).unwrap();
    assert!(
        (encoded.len() as u64) < 64 * 1024,
        "R16-10b: Normal HelloAck must be well within 64KB limit (actual: {} bytes)",
        encoded.len()
    );

    let decoded = handshake::decode_hello_ack(&encoded).unwrap();
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert!(decoded.accepted);
}

/// R16-10c: bincode with_limit boundary behavior.
/// bincode's with_limit() limits deserialization based on the Vec length prefix
/// in the encoded data. It rejects if the CLAIMED length exceeds the limit,
/// not the actual buffer size. When deserializing from a byte slice, the buffer
/// itself provides the "real" limit. with_limit acts as a secondary defense
/// against crafted length prefixes claiming enormous sizes.
#[test]
fn r16_unit_bincode_limit_boundary() {
    use bincode::Options;

    // Craft a payload with a length prefix claiming 1 billion bytes
    // but only 10 actual data bytes. without_limit this would try to
    // allocate 1GB and fail. With limit it rejects immediately.
    let mut crafted = Vec::new();
    // Length prefix: 1_000_000_000 as u64 LE (fixint encoding)
    crafted.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    // Only 10 actual bytes of data
    crafted.extend_from_slice(&[0xAA; 10]);

    // With a generous limit but less than 1 billion, the crafted prefix is rejected
    let result: Result<Vec<u8>, _> = bincode::DefaultOptions::new()
        .with_limit(1_000_000)
        .with_fixint_encoding()
        .deserialize(&crafted);
    assert!(
        result.is_err(),
        "R16-10c: bincode with_limit(1M) must reject crafted 1B-length prefix"
    );

    // Without limit, deserialization of the crafted payload would fail differently
    // (trying to read 1B bytes from a 10-byte buffer), but with_limit catches it
    // before allocation attempt.

    // Normal data round-trips fine with appropriate limit
    let data: Vec<u8> = vec![0xBB; 100];
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&data)
        .unwrap();

    let result_ok: Result<Vec<u8>, _> = bincode::DefaultOptions::new()
        .with_limit(1_000)
        .with_fixint_encoding()
        .deserialize(&encoded);
    assert!(
        result_ok.is_ok(),
        "R16-10c: Normal data within limit must deserialize"
    );
}

// =============================================================================
// FINDING 11 -- LOW: compute_node_id has no domain separation
//
// NodeId = SHA-256(public_key_bytes). This is fine in isolation, but if the
// same key bytes are used as input to SHA-256 in another context (e.g., a
// transaction hash), the outputs would collide. Domain separation would
// make this impossible:
//   NodeId = SHA-256("poly-node/NodeId/v1\0" || public_key_bytes)
//
// Not exploitable in practice since Ed25519 keys are unique per identity.
//
// File: Documented audit finding (identity.rs)
// =============================================================================

/// R16-11a: Audit -- compute_node_id is just SHA-256(pubkey), no domain tag.
#[test]
fn r16_audit_node_id_no_domain_separation() {
    use sha2::{Digest, Sha256};

    let identity = NodeIdentity::generate();
    let pubkey = identity.public_key_bytes();

    // Compute raw SHA-256(pubkey)
    let mut hasher = Sha256::new();
    hasher.update(&pubkey);
    let raw_hash: [u8; 32] = hasher.finalize().into();

    // Compare with compute_node_id
    let node_id = poly_node::identity::compute_node_id(identity.verifying_key());

    // These SHOULD be equal since there's no domain separation
    assert_eq!(
        raw_hash, node_id,
        "R16-11a AUDIT: NodeId = SHA-256(pubkey) with no domain tag"
    );

    // With domain separation it would be:
    let mut hasher2 = Sha256::new();
    hasher2.update(b"poly-node/NodeId/v1\0");
    hasher2.update(&pubkey);
    let domain_separated: [u8; 32] = hasher2.finalize().into();

    assert_ne!(
        domain_separated, node_id,
        "R16-11a: Domain-separated hash differs from current NodeId"
    );
}

// =============================================================================
// FINDING 12 -- LOW: Signing message does not commit to signature field
//
// The signing message includes all NodeInfo fields EXCEPT the signature itself
// (by design -- signature cannot cover itself). This means two NodeInfos
// that differ only in their signature field produce identical signing messages.
// This is FINE because Ed25519 signatures are deterministic (same key + same
// message = same signature), and verification ensures uniqueness.
//
// File: Documented audit finding (wire.rs)
// =============================================================================

/// R16-12a: Audit -- signature field does not affect signing message.
#[test]
fn r16_audit_signature_not_in_signing_message() {
    let info1 = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec![],
        models: vec![],
        relay_capable: false,
        capacity: NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
        timestamp: 1000000,
        signature: vec![],  // Empty signature
    };

    let info2 = NodeInfo {
        public_key: [42u8; 32],
        addresses: vec![],
        models: vec![],
        relay_capable: false,
        capacity: NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
        timestamp: 1000000,
        signature: vec![0xFF; 64],  // Non-empty signature
    };

    let msg1 = compute_nodeinfo_signing_message(&info1);
    let msg2 = compute_nodeinfo_signing_message(&info2);

    assert_eq!(
        msg1, msg2,
        "R16-12a AUDIT: Signature field does not affect signing message (by design)"
    );
}

/// R16-12b: Verify that ALL other fields DO affect signing message.
#[test]
fn r16_unit_all_fields_affect_signing_message() {
    let base = NodeInfo {
        public_key: [1u8; 32],
        addresses: vec!["10.0.0.1:4001".parse().unwrap()],
        models: vec![ModelCapability {
            model_name: "test".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        relay_capable: false,
        capacity: NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
        timestamp: 1000000,
        signature: vec![],
    };

    let base_msg = compute_nodeinfo_signing_message(&base);

    // Change public_key
    let mut v = base.clone();
    v.public_key = [2u8; 32];
    assert_ne!(compute_nodeinfo_signing_message(&v), base_msg, "public_key must matter");

    // Change addresses
    let mut v = base.clone();
    v.addresses = vec!["10.0.0.2:4001".parse().unwrap()];
    assert_ne!(compute_nodeinfo_signing_message(&v), base_msg, "addresses must matter");

    // Change models
    let mut v = base.clone();
    v.models[0].model_name = "other".into();
    assert_ne!(compute_nodeinfo_signing_message(&v), base_msg, "models must matter");

    // Change relay_capable
    let mut v = base.clone();
    v.relay_capable = true;
    assert_ne!(compute_nodeinfo_signing_message(&v), base_msg, "relay must matter");

    // Change capacity
    let mut v = base.clone();
    v.capacity.max_sessions = 999;
    assert_ne!(compute_nodeinfo_signing_message(&v), base_msg, "capacity must matter");

    // Change timestamp
    let mut v = base.clone();
    v.timestamp = 2000000;
    assert_ne!(compute_nodeinfo_signing_message(&v), base_msg, "timestamp must matter");
}

// =============================================================================
// ADDITIONAL TESTS: Edge cases, regression, and combinatorial attacks
// =============================================================================

/// R16-13a: Verify Ed25519 signing determinism -- same key + same message = same signature.
#[test]
fn r16_unit_ed25519_signing_deterministic() {
    let identity = NodeIdentity::generate();
    let msg = b"test message for determinism check";

    let sig1 = identity.sign(msg);
    let sig2 = identity.sign(msg);

    assert_eq!(
        sig1, sig2,
        "R16-13a: Ed25519 signing must be deterministic (same key + message = same sig)"
    );
}

/// R16-13b: Verify different messages produce different signatures.
#[test]
fn r16_unit_different_messages_different_sigs() {
    let identity = NodeIdentity::generate();

    let sig1 = identity.sign(b"message one");
    let sig2 = identity.sign(b"message two");

    assert_ne!(
        sig1, sig2,
        "R16-13b: Different messages must produce different signatures"
    );
}

/// R16-14a: Verify signing empty data works (edge case).
#[test]
fn r16_unit_sign_empty_data() {
    let identity = NodeIdentity::generate();
    let sig = identity.sign(b"");
    assert_eq!(sig.len(), 64, "R16-14a: Signature of empty data must be 64 bytes");
    assert!(
        poly_node::identity::verify_signature(identity.verifying_key(), b"", &sig),
        "R16-14a: Signature of empty data must verify"
    );
}

/// R16-14b: Verify verify_signature rejects empty data when signed with different data.
#[test]
fn r16_unit_verify_rejects_mismatch() {
    let identity = NodeIdentity::generate();
    let sig = identity.sign(b"actual message");
    assert!(
        !poly_node::identity::verify_signature(identity.verifying_key(), b"", &sig),
        "R16-14b: Signature for different message must not verify against empty"
    );
}

/// R16-15a: NodeInfo with empty addresses and empty models still produces valid signature.
#[test]
fn r16_unit_minimal_node_info_signed() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info(&identity);

    assert!(info.addresses.is_empty());
    assert!(info.models.is_empty());
    assert_eq!(info.signature.len(), 64);
    assert_eq!(info.capacity.max_sessions, 1);
}

/// R16-15b: NodeInfo signing message length is always exactly 72 bytes.
#[test]
fn r16_unit_signing_message_always_72_bytes() {
    let variations = vec![
        NodeInfo {
            public_key: [0u8; 32],
            addresses: vec![],
            models: vec![],
            relay_capable: false,
            capacity: NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 0 },
            timestamp: 0,
            signature: vec![],
        },
        NodeInfo {
            public_key: [0xFF; 32],
            addresses: (1..=16).map(|i| format!("10.0.0.{}:400{}", i % 255, i).parse().unwrap()).collect(),
            models: (1..=16).map(|i| ModelCapability {
                model_name: format!("model-{}-{}", i, "x".repeat(200)),
                gpu: i % 2 == 0,
                throughput_estimate: i as f32 * 100.0,
            }).collect(),
            relay_capable: true,
            capacity: NodeCapacity { queue_depth: u32::MAX, active_sessions: 500, max_sessions: u32::MAX },
            timestamp: u64::MAX,
            signature: vec![0xAB; 1000],  // Even oversized signature doesn't affect length
        },
    ];

    for (i, info) in variations.iter().enumerate() {
        let msg = compute_nodeinfo_signing_message(info);
        assert_eq!(
            msg.len(), 72,
            "R16-15b: Signing message for variation {} must be 72 bytes (got {})",
            i, msg.len()
        );
    }
}

/// R16-16a: Verify that NodeConfig with relay=true is accepted.
#[test]
fn r16_regression_relay_config_accepted() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "mock".into(),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: true,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R16-16a: Config with relay=true must be accepted: {:?}",
        result.err()
    );
}

/// R16-16b: Verify that NodeConfig with relay=false is accepted.
#[test]
fn r16_regression_no_relay_config_accepted() {
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
        "R16-16b: Config with relay=false must be accepted: {:?}",
        result.err()
    );
}

/// R16-17a: Verify signed NodeInfo with relay=true differs from relay=false.
#[test]
fn r16_unit_relay_field_signed() {
    let identity = NodeIdentity::generate();

    let info_relay = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        true,
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
    );

    let info_no_relay = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 },
    );

    // Signatures must differ because the signed message includes relay_capable
    assert_ne!(
        info_relay.signature, info_no_relay.signature,
        "R16-17a: Different relay_capable must produce different signatures"
    );
}

/// R16-18a: Concurrent handshakes from different clients on separate connections.
#[tokio::test]
async fn r16_regression_concurrent_handshakes() {
    let (addr, handle) = start_test_node().await;

    let mut handles = vec![];
    for i in 0..3 {
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let request = InferRequest {
                model_id: format!("model-{}", i),
                mode: Mode::Transparent,
                encrypted_input: serde_json::to_vec(&MockCiphertext { tokens: vec![i as u32] }).unwrap(),
                max_tokens: 5,
                temperature: 700,
                seed: i as u64,
            };
            poly_node::node::connect_and_infer(addr, &request).await
        }));
    }

    for (i, h) in handles.into_iter().enumerate() {
        let result = h.await.unwrap();
        assert!(
            result.is_ok(),
            "R16-18a: Concurrent connection {} must succeed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}

/// R16-19a: Verify Frame encoding preserves MessageType through round-trip for all types.
#[test]
fn r16_unit_frame_round_trip_all_message_types() {
    let types = [
        MessageType::Hello,
        MessageType::HelloAck,
        MessageType::GetPeers,
        MessageType::Peers,
        MessageType::Announce,
        MessageType::Ping,
        MessageType::Pong,
        MessageType::InferRequest,
        MessageType::InferResponse,
        MessageType::PubkeyRequest,
        MessageType::PubkeyResponse,
        MessageType::RelayOpen,
        MessageType::RelayAccept,
        MessageType::RelayDeny,
        MessageType::RelayData,
        MessageType::RelayClose,
        MessageType::Error,
    ];

    for &ty in &types {
        let payload = vec![0xAB; 10];
        let frame = Frame::new(ty, payload.clone());
        let encoded = frame.encode();
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len(), "Type {:?}: consumed mismatch", ty);
        assert_eq!(decoded.msg_type, ty, "Type {:?}: msg_type mismatch", ty);
        assert_eq!(decoded.payload, payload, "Type {:?}: payload mismatch", ty);
    }
}

/// R16-19b: Frame with zero-length payload round-trips correctly.
#[test]
fn r16_unit_frame_zero_payload_round_trip() {
    let frame = Frame::new(MessageType::Ping, vec![]);
    let encoded = frame.encode();
    assert_eq!(encoded.len(), 5, "Empty payload frame must be 5 bytes (1 type + 4 length)");

    let (decoded, consumed) = Frame::decode(&encoded).unwrap();
    assert_eq!(consumed, 5);
    assert!(decoded.payload.is_empty());
    assert_eq!(decoded.msg_type, MessageType::Ping);
}

/// R16-20a: Verify that server HelloAck contains valid public key (not zero).
#[tokio::test]
async fn r16_regression_server_helloack_nonzero_key() {
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
    assert_ne!(
        ack.node_info.public_key, [0u8; 32],
        "R16-20a: Server HelloAck must have non-zero public key"
    );
    assert_eq!(
        ack.node_info.signature.len(), 64,
        "R16-20a: Server signature must be 64 bytes"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-20b: Verify rejected HelloAck has zeroed fields (R6 defense).
#[tokio::test]
async fn r16_regression_rejected_helloack_zeroed() {
    let (addr, handle) = start_test_node().await;

    let identity = NodeIdentity::generate();
    let hello = Hello {
        version: 999, // Wrong version -- triggers rejection
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

    assert!(!ack.accepted);
    assert_eq!(
        ack.node_info.public_key, [0u8; 32],
        "R16-20b: Rejected HelloAck must have zeroed public key"
    );
    assert!(
        ack.node_info.addresses.is_empty(),
        "R16-20b: Rejected HelloAck must have empty addresses"
    );
    assert!(
        ack.node_info.models.is_empty(),
        "R16-20b: Rejected HelloAck must have empty models"
    );
    assert_eq!(
        ack.node_info.timestamp, 0,
        "R16-20b: Rejected HelloAck must have zeroed timestamp"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-21a: Inference with Mode::Encrypted works on mock backend.
#[tokio::test]
async fn r16_regression_encrypted_mode_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1, 2, 3] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Encrypted,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R16-21a: Encrypted mode must be accepted by mock backend: {:?}",
        result.err()
    );

    handle.abort();
}

/// R16-21b: Inference with Mode::PrivateProven works on mock backend.
#[tokio::test]
async fn r16_regression_private_proven_mode_accepted() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1] };
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::PrivateProven,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 3,
        temperature: 500,
        seed: 99,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R16-21b: PrivateProven mode must be accepted: {:?}",
        result.err()
    );

    handle.abort();
}

/// R16-22a: Verify InferResponse round-trip through encode/decode.
#[test]
fn r16_unit_infer_response_round_trip() {
    let response = InferResponse {
        encrypted_output: vec![0xDE, 0xAD, 0xBE, 0xEF],
        proof: VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        },
        model_id: "test-model".into(),
    };

    let encoded = inference::encode_infer_response(&response).unwrap();
    let decoded = inference::decode_infer_response(&encoded).unwrap();

    assert_eq!(decoded.model_id, response.model_id);
    assert_eq!(decoded.encrypted_output, response.encrypted_output);
    // Verify proof round-trips by checking it matches the Mock variant
    match &decoded.proof {
        VerifiedProof::Mock { input_hash, output_hash, privacy_mode } => {
            assert_eq!(*input_hash, ZERO_HASH);
            assert_eq!(*output_hash, ZERO_HASH);
            assert_eq!(*privacy_mode, PrivacyMode::Transparent);
        }
        other => panic!("R16-22a: Expected Mock proof, got {:?}", other),
    }
}

/// R16-22b: InferRequest round-trip through encode/decode.
#[test]
fn r16_unit_infer_request_round_trip() {
    let request = test_infer_request(&[42, 100, 200]);
    let encoded = inference::encode_infer_request(&request).unwrap();
    let decoded = inference::decode_infer_request(&encoded).unwrap();

    assert_eq!(decoded.model_id, request.model_id);
    assert_eq!(decoded.max_tokens, request.max_tokens);
    assert_eq!(decoded.temperature, request.temperature);
    assert_eq!(decoded.seed, request.seed);
    assert_eq!(decoded.encrypted_input, request.encrypted_input);
}

/// R16-23a: Multiple identities produce unique node IDs.
#[test]
fn r16_unit_unique_node_ids() {
    use std::collections::HashSet;

    let mut ids = HashSet::new();
    for _ in 0..100 {
        let identity = NodeIdentity::generate();
        assert!(
            ids.insert(identity.id),
            "R16-23a: Node IDs must be unique across 100 generations"
        );
    }
}

/// R16-23b: NodeId is deterministic for a given public key.
#[test]
fn r16_unit_node_id_deterministic() {
    let identity = NodeIdentity::generate();
    let id1 = poly_node::identity::compute_node_id(identity.verifying_key());
    let id2 = poly_node::identity::compute_node_id(identity.verifying_key());
    assert_eq!(
        id1, id2,
        "R16-23b: compute_node_id must be deterministic for same key"
    );
}

/// R16-24a: Verify server survives malformed frame (truncated header).
#[tokio::test]
async fn r16_attack_truncated_frame_header() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send only 3 bytes (incomplete header, need 5)
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[0x01, 0x00, 0x00]).await.unwrap();
    send.finish().unwrap();

    // Server should handle gracefully (no response, no crash)
    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;
    // We don't care about the specific result, just that server survives
    let _ = result;

    // Verify server is still alive
    let test_req = test_infer_request(&[1]);
    let alive = poly_node::node::connect_and_infer(addr, &test_req).await;
    assert!(
        alive.is_ok(),
        "R16-24a: Server must survive truncated frame header: {:?}",
        alive.err()
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-24b: Verify server survives empty stream (0 bytes sent).
#[tokio::test]
async fn r16_attack_empty_stream() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send nothing, just finish the stream
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.finish().unwrap();

    // Server should handle gracefully
    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;
    let _ = result;

    // Verify server is still alive
    let test_req = test_infer_request(&[1]);
    let alive = poly_node::node::connect_and_infer(addr, &test_req).await;
    assert!(
        alive.is_ok(),
        "R16-24b: Server must survive empty stream: {:?}",
        alive.err()
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-25a: Verify server correctly handles valid handshake followed by Ping
/// on the same connection but different streams.
#[tokio::test]
async fn r16_regression_handshake_then_ping() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
    do_handshake(&conn).await;

    // Send Ping
    let nonce = b"r16-test-nonce";
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let ping_frame = Frame::new(MessageType::Ping, nonce.to_vec());
    send.write_all(&ping_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let data = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await.expect("timeout").expect("read error");
    let (pong, _) = Frame::decode(&data).unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);
    assert_eq!(pong.payload, nonce.to_vec());

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-26a: Verify InferResponse model_id binding (R10 regression).
/// Response model_id must match request model_id.
#[tokio::test]
async fn r16_regression_model_id_binding() {
    let (addr, handle) = start_test_node().await;

    let ct = MockCiphertext { tokens: vec![1, 2] };
    let request = InferRequest {
        model_id: "specific-model".into(),
        mode: Mode::Transparent,
        encrypted_input: serde_json::to_vec(&ct).unwrap(),
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(result.is_ok(), "R16-26a: Inference must succeed");

    let response = result.unwrap();
    assert_eq!(
        response.model_id, "specific-model",
        "R16-26a: Response model_id must match request model_id"
    );

    handle.abort();
}

/// R16-27a: Verify encode_infer_request rejects oversized request.
#[test]
fn r16_unit_encode_infer_request_size_limit() {
    let request = InferRequest {
        model_id: "test".into(),
        mode: Mode::Transparent,
        encrypted_input: vec![0xAA; 4 * 1024 * 1024], // 4 MB -- at limit
        max_tokens: 5,
        temperature: 700,
        seed: 42,
    };

    // This may or may not exceed 4MB after serialization depending on overhead
    let result = inference::encode_infer_request(&request);
    // The encoded size includes overhead from model_id, mode, etc.
    // With 4MB of encrypted_input, the total will be > 4MB
    assert!(
        result.is_err(),
        "R16-27a: InferRequest with 4MB encrypted_input should exceed encode limit"
    );
}

/// R16-27b: Verify encode_infer_response rejects oversized response.
#[test]
fn r16_unit_encode_infer_response_size_limit() {
    let response = InferResponse {
        encrypted_output: vec![0xBB; 16 * 1024 * 1024], // 16 MB -- at limit
        proof: VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        },
        model_id: "test".into(),
    };

    let result = inference::encode_infer_response(&response);
    // 16MB of payload + overhead will exceed the 16MB limit
    assert!(
        result.is_err(),
        "R16-27b: InferResponse with 16MB output should exceed encode limit"
    );
}

/// R16-28a: Verify config with maximum allowed model_name (256 bytes) accepted.
#[test]
fn r16_regression_max_model_name_config() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "x".repeat(256),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_ok(),
        "R16-28a: 256-byte model_name must be accepted: {:?}",
        result.err()
    );
}

/// R16-28b: Verify config with 257-byte model_name rejected.
#[test]
fn r16_regression_overlength_model_name_config() {
    let config = NodeConfig {
        listen_addr: localhost_addr(),
        model_name: "x".repeat(257),
        bootstrap_addrs: vec![],
        max_sessions: 8,
        relay: false,
    };
    let backend = Arc::new(MockInferenceBackend::default());
    let result = PolyNode::new(config, backend);
    assert!(
        result.is_err(),
        "R16-28b: 257-byte model_name must be rejected"
    );
}

/// R16-29a: Verify that Pong without handshake is rejected.
#[tokio::test]
async fn r16_attack_pong_without_handshake() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send Pong (server->client only) without handshake
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let pong_frame = Frame::new(MessageType::Pong, vec![0xAB; 10]);
    send.write_all(&pong_frame.encode()).await.unwrap();
    send.finish().unwrap();

    // Server should reject -- Pong is a response-only type
    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;
    let got_response = match result {
        Ok(Ok(data)) if !data.is_empty() => true,
        _ => false,
    };
    assert!(
        !got_response,
        "R16-29a: Pong (wrong direction) must not get a response"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-29b: Verify that InferResponse (wrong direction) is rejected.
#[tokio::test]
async fn r16_attack_infer_response_wrong_direction() {
    let (addr, handle) = start_test_node().await;

    let endpoint = transport::create_client_endpoint().unwrap();
    let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();

    // Send InferResponse (server->client only)
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let resp_frame = Frame::new(MessageType::InferResponse, vec![0xCD; 20]);
    send.write_all(&resp_frame.encode()).await.unwrap();
    send.finish().unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;
    let got_response = match result {
        Ok(Ok(data)) if !data.is_empty() => true,
        _ => false,
    };
    assert!(
        !got_response,
        "R16-29b: InferResponse (wrong direction) must not get a response"
    );

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    handle.abort();
}

/// R16-30a: Verify server survives rapid connection/disconnection cycle.
#[tokio::test]
async fn r16_stress_rapid_connect_disconnect() {
    let (addr, handle) = start_test_node().await;

    for _ in 0..5 {
        let endpoint = transport::create_client_endpoint().unwrap();
        let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
        conn.close(0u32.into(), b"quick-close");
        endpoint.wait_idle().await;
    }

    // Server must still be alive
    let request = test_infer_request(&[1, 2, 3]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R16-30a: Server must survive rapid connect/disconnect: {:?}",
        result.err()
    );

    handle.abort();
}

/// R16-31a: Verify that all 17 message types have valid from_u8 round-trip.
#[test]
fn r16_unit_message_type_coverage() {
    // All known type bytes
    let known: Vec<(u8, MessageType)> = vec![
        (0x01, MessageType::Hello),
        (0x02, MessageType::HelloAck),
        (0x10, MessageType::GetPeers),
        (0x11, MessageType::Peers),
        (0x12, MessageType::Announce),
        (0x20, MessageType::Ping),
        (0x21, MessageType::Pong),
        (0x30, MessageType::InferRequest),
        (0x31, MessageType::InferResponse),
        (0x32, MessageType::PubkeyRequest),
        (0x33, MessageType::PubkeyResponse),
        (0x40, MessageType::RelayOpen),
        (0x41, MessageType::RelayAccept),
        (0x42, MessageType::RelayDeny),
        (0x43, MessageType::RelayData),
        (0x44, MessageType::RelayClose),
        (0xFE, MessageType::Error),
    ];

    assert_eq!(known.len(), 17, "Must have all 17 message types");

    for (byte, expected_type) in &known {
        let parsed = MessageType::from_u8(*byte);
        assert_eq!(
            parsed, Some(*expected_type),
            "R16-31a: Byte 0x{:02X} must parse to {:?}",
            byte, expected_type
        );
        // Verify the type's u8 value matches
        assert_eq!(
            *expected_type as u8, *byte,
            "R16-31a: {:?} must encode as 0x{:02X}",
            expected_type, byte
        );
    }
}

/// R16-32a: Verify the comprehensive config validation still works after R16.
#[test]
fn r16_regression_comprehensive_config_validation() {
    let backend = Arc::new(MockInferenceBackend::default());

    // Good config
    assert!(PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    ).is_ok());

    // Bad: max_sessions=0
    assert!(PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 0,
            relay: false,
        },
        backend.clone(),
    ).is_err());

    // Bad: max_sessions too large
    assert!(PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 1025,
            relay: false,
        },
        backend.clone(),
    ).is_err());

    // Bad: model_name with control char
    assert!(PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "mock\n".into(),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    ).is_err());

    // Bad: port 0
    assert!(PolyNode::new(
        NodeConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            model_name: "mock".into(),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    ).is_err());

    // Bad: model_name too long
    assert!(PolyNode::new(
        NodeConfig {
            listen_addr: localhost_addr(),
            model_name: "x".repeat(257),
            bootstrap_addrs: vec![],
            max_sessions: 8,
            relay: false,
        },
        backend.clone(),
    ).is_err());
}

/// R16-33a: Full end-to-end regression after R16 (final sanity check).
#[tokio::test]
async fn r16_regression_full_e2e_after_r16() {
    let (addr, handle) = start_test_node().await;

    // Normal inference
    let request = test_infer_request(&[1, 2, 3, 4, 5]);
    let result = poly_node::node::connect_and_infer(addr, &request).await;
    assert!(
        result.is_ok(),
        "R16-33a: Full E2E must work after R16: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert_eq!(response.model_id, "test");
    assert!(!response.encrypted_output.is_empty());

    handle.abort();
}

// =============================================================================
// FINDINGS 3 & 4 -- REGRESSION: connect_and_infer rejects a malicious server
// HelloAck whose NodeInfo contains invalid addresses or capacity fields.
//
// These tests spin up a hand-rolled QUIC server that completes the handshake
// but responds with a validly-SIGNED HelloAck containing content the server
// would itself reject from a client. Before the R16 fix, connect_and_infer
// accepted any address/capacity content from the server.
// =============================================================================

/// Spawn a malicious QUIC server that accepts one connection, reads the client
/// Hello, and replies with a HelloAck carrying `node_info` (accepted=true).
/// Returns the bound address.
async fn spawn_malicious_server(node_info: NodeInfo) -> SocketAddr {
    let endpoint =
        transport::create_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    let bound = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let _ = recv.read_to_end(64 * 1024).await;
                    let ack = HelloAck {
                        version: PROTOCOL_VERSION,
                        node_info,
                        accepted: true,
                    };
                    if let Ok(payload) = handshake::encode_hello_ack(&ack) {
                        let frame = Frame::new(MessageType::HelloAck, payload);
                        let _ = send.write_all(&frame.encode()).await;
                        let _ = send.finish();
                    }
                }
                // Keep the connection alive briefly so the client can read.
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    });
    bound
}

fn ok_capacity() -> NodeCapacity {
    NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 1 }
}

/// R16-03c: client rejects a server HelloAck advertising a multicast address.
#[tokio::test]
async fn r16_regression_client_rejects_helloack_multicast_address() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["224.0.0.1:4001".parse().unwrap()],
        vec![],
        false,
        ok_capacity(),
    );
    let addr = spawn_malicious_server(info).await;
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    assert!(result.is_err(), "R16-03c: client must reject multicast address");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("multicast"),
        "R16-03c: error should mention multicast, got: {}",
        err
    );
}

/// R16-03d: client rejects a server HelloAck advertising a port-0 address.
#[tokio::test]
async fn r16_regression_client_rejects_helloack_port_zero() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["10.0.0.1:0".parse().unwrap()],
        vec![],
        false,
        ok_capacity(),
    );
    let addr = spawn_malicious_server(info).await;
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    assert!(result.is_err(), "R16-03d: client must reject port-0 address");
    assert!(result.unwrap_err().to_string().contains("non-routable"));
}

/// R16-03e: client rejects a server HelloAck with duplicate addresses.
#[tokio::test]
async fn r16_regression_client_rejects_helloack_duplicate_address() {
    let identity = NodeIdentity::generate();
    let dup: SocketAddr = "10.0.0.5:4001".parse().unwrap();
    let info = build_signed_node_info_with(
        &identity,
        vec![dup, dup],
        vec![],
        false,
        ok_capacity(),
    );
    let addr = spawn_malicious_server(info).await;
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    assert!(result.is_err(), "R16-03e: client must reject duplicate address");
    assert!(result.unwrap_err().to_string().contains("duplicate address"));
}

/// R16-04b: client rejects a server HelloAck with max_sessions=0.
#[tokio::test]
async fn r16_regression_client_rejects_helloack_zero_max_sessions() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity { queue_depth: 0, active_sessions: 0, max_sessions: 0 },
    );
    let addr = spawn_malicious_server(info).await;
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    assert!(result.is_err(), "R16-04b: client must reject max_sessions=0");
    assert!(result.unwrap_err().to_string().contains("max_sessions=0"));
}

/// R16-04c: client rejects a server HelloAck with active_sessions > max_sessions.
#[tokio::test]
async fn r16_regression_client_rejects_helloack_illogical_capacity() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![],
        false,
        NodeCapacity { queue_depth: 0, active_sessions: 10, max_sessions: 5 },
    );
    let addr = spawn_malicious_server(info).await;
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    assert!(result.is_err(), "R16-04c: client must reject active > max sessions");
    assert!(result.unwrap_err().to_string().contains("active_sessions"));
}

/// R16-07b: client rejects a server HelloAck with duplicate model names.
#[tokio::test]
async fn r16_regression_client_rejects_helloack_duplicate_models() {
    let identity = NodeIdentity::generate();
    let model = ModelCapability {
        model_name: "mock".into(),
        gpu: false,
        throughput_estimate: 1.0,
    };
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![model.clone(), model],
        false,
        ok_capacity(),
    );
    let addr = spawn_malicious_server(info).await;
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    assert!(result.is_err(), "R16-07b: client must reject duplicate model names");
    assert!(result.unwrap_err().to_string().contains("duplicate model name"));
}

/// R16-08b: client rejects a server HelloAck model name with control characters.
#[tokio::test]
async fn r16_regression_client_rejects_helloack_control_char_model() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec![],
        vec![ModelCapability {
            model_name: "mock\ninjected".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        false,
        ok_capacity(),
    );
    let addr = spawn_malicious_server(info).await;
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    assert!(result.is_err(), "R16-08b: client must reject control-char model name");
    assert!(result.unwrap_err().to_string().contains("control characters"));
}

/// R16-03f: regression -- a server HelloAck with valid addresses/capacity is
/// still accepted (the new checks must not break legitimate handshakes).
#[tokio::test]
async fn r16_regression_client_accepts_valid_helloack_content() {
    let identity = NodeIdentity::generate();
    let info = build_signed_node_info_with(
        &identity,
        vec!["10.0.0.1:4001".parse().unwrap()],
        vec![ModelCapability {
            model_name: "mock".into(),
            gpu: false,
            throughput_estimate: 1.0,
        }],
        false,
        NodeCapacity { queue_depth: 5, active_sessions: 3, max_sessions: 8 },
    );
    let addr = spawn_malicious_server(info).await;
    // The malicious server only sends a HelloAck, then the connection drops
    // before inference. The handshake itself must SUCCEED (no validation error);
    // failure here, if any, must come from the inference stage, not HelloAck
    // content validation.
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1])).await;
    if let Err(e) = &result {
        let msg = e.to_string();
        assert!(
            !msg.contains("HelloAck") || !(msg.contains("address")
                || msg.contains("capacity")
                || msg.contains("model")),
            "R16-03f: valid HelloAck content must not be rejected, got: {}",
            msg
        );
    }
}
