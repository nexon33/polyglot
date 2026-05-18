//! Round 17 pentest attack tests for poly-node.
//!
//! Finding fixed in this round:
//!
//! R17-01 HIGH:   `handle_stream` always read each stream with a 16 MB limit,
//!     including unauthenticated pre-handshake streams whose only valid message
//!     is a ~64 KB Hello. The 64 KB `MAX_HELLO_SIZE` limit was enforced only
//!     inside bincode, AFTER the full 16 MB `read_to_end`. An unauthenticated
//!     peer could open up to MAX_PRE_HANDSHAKE_STREAMS (8) streams per
//!     connection and send 16 MB on each, forcing the server to allocate
//!     8 x 16 MB of attacker-controlled memory before any size limit applied.
//!     FIX: pre-handshake reads are now capped at MAX_HELLO_SIZE + 1 KB; the
//!     16 MB cap applies only once the handshake has completed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poly_client::encryption::MockCiphertext;
use poly_client::protocol::{InferRequest, Mode};
use poly_inference::server::MockInferenceBackend;
use poly_node::config::NodeConfig;
use poly_node::net::transport;
use poly_node::node::PolyNode;
use poly_node::protocol::handshake::HelloAck;
use poly_node::protocol::wire::{Frame, MessageType};

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
    let ct = MockCiphertext { tokens: tokens.to_vec() };
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

// ===========================================================================
// R17-01: pre-handshake 16 MB read amplification
// ===========================================================================

/// R17-01a: an oversized (~256 KB) Hello-typed frame sent on a pre-handshake
/// stream must NOT complete a handshake — it exceeds the pre-handshake read cap
/// (MAX_HELLO_SIZE + 1 KB). The server must not accept it and must stay alive.
#[tokio::test]
async fn r17_oversized_prehandshake_frame_rejected_and_server_survives() {
    let (addr, handle) = start_test_node().await;

    {
        let endpoint = transport::create_client_endpoint().unwrap();
        let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // 256 KB payload — far above the ~65 KB pre-handshake cap, far below
        // the legacy 16 MB cap. Before R17 the server would buffer the whole
        // thing; after R17 the read_to_end cap rejects it outright.
        let huge = vec![0u8; 256 * 1024];
        let frame = Frame::new(MessageType::Hello, huge);
        let _ = send.write_all(&frame.encode()).await;
        let _ = send.finish();

        // The server must never reply with an *accepted* HelloAck.
        if let Ok(data) = recv.read_to_end(128 * 1024).await {
            if let Ok((f, _)) = Frame::decode(&data) {
                if f.msg_type == MessageType::HelloAck {
                    if let Ok(ack) = bincode::deserialize::<HelloAck>(&f.payload) {
                        assert!(
                            !ack.accepted,
                            "R17-01a: an oversized pre-handshake Hello must not be accepted"
                        );
                    }
                }
            }
        }
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    // The server must still serve a legitimate request afterwards.
    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1, 2, 3])).await;
    assert!(
        result.is_ok(),
        "R17-01a: server must survive the oversized pre-handshake attack: {:?}",
        result.err()
    );

    handle.abort();
}

/// R17-01b: regression — a normal handshake + inference still works (the
/// pre-handshake read cap must not break legitimate ~sub-64 KB Hello frames).
#[tokio::test]
async fn r17_regression_normal_handshake_and_inference() {
    let (addr, handle) = start_test_node().await;

    let result = poly_node::node::connect_and_infer(addr, &test_infer_request(&[1, 2, 3, 4, 5])).await;
    assert!(
        result.is_ok(),
        "R17-01b: normal handshake + inference must still work: {:?}",
        result.err()
    );
    let response = result.unwrap();
    assert_eq!(response.model_id, "test");
    assert!(!response.encrypted_output.is_empty());

    handle.abort();
}

/// R17-01c: regression — after a rejected oversized pre-handshake stream, the
/// same connection's handshake budget is consumed but a fresh connection from
/// the same peer can still handshake normally (server-wide liveness).
#[tokio::test]
async fn r17_regression_fresh_connection_after_attack() {
    let (addr, handle) = start_test_node().await;

    // Attack connection.
    {
        let endpoint = transport::create_client_endpoint().unwrap();
        let conn = endpoint.connect(addr, "poly-node").unwrap().await.unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        let huge = vec![0u8; 512 * 1024];
        let frame = Frame::new(MessageType::Hello, huge);
        let _ = send.write_all(&frame.encode()).await;
        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    }

    // Two fresh, independent connections must both succeed.
    for i in 0..2 {
        let result =
            poly_node::node::connect_and_infer(addr, &test_infer_request(&[i, i + 1])).await;
        assert!(
            result.is_ok(),
            "R17-01c: fresh connection {} after attack must succeed: {:?}",
            i,
            result.err()
        );
    }

    handle.abort();
}
