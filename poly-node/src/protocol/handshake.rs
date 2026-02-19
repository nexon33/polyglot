//! Hello/HelloAck handshake messages.
//!
//! The first exchange on a new QUIC connection. Both sides send their
//! NodeInfo so each knows the other's identity, capabilities, and addresses.

use bincode::Options;
use crate::protocol::wire::NodeInfo;
use serde::{Deserialize, Serialize};

/// Maximum size for deserialization of Hello/HelloAck (64 KB).
/// Matches the limit used in node.rs for server-side Hello deserialization.
const MAX_HANDSHAKE_MSG_SIZE: u64 = 64 * 1024;

/// Initial handshake message sent by the connecting peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version (currently 1).
    pub version: u32,
    /// Sender's node information.
    pub node_info: NodeInfo,
}

/// Handshake response from the listening peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    /// Protocol version.
    pub version: u32,
    /// Responder's node information.
    pub node_info: NodeInfo,
    /// Whether the connection is accepted.
    pub accepted: bool,
}

/// Protocol version for this implementation.
pub const PROTOCOL_VERSION: u32 = 1;

/// R9: Validate serialized size does not exceed the wire limit.
/// Before this fix, encode_hello used raw bincode::serialize() with no
/// output size validation. A bloated Hello (e.g., with long model names
/// within field-level limits) could serialize to >64KB and would be
/// silently rejected by the receiving side's size-limited deserialization,
/// producing a confusing error. Now the sender fails fast.
pub fn encode_hello(hello: &Hello) -> anyhow::Result<Vec<u8>> {
    let bytes = bincode::serialize(hello)?;
    if bytes.len() as u64 > MAX_HANDSHAKE_MSG_SIZE {
        anyhow::bail!(
            "serialized Hello too large: {} bytes (max {})",
            bytes.len(),
            MAX_HANDSHAKE_MSG_SIZE
        );
    }
    Ok(bytes)
}

/// R8: Use size-limited bincode for Hello deserialization.
/// Before this fix, decode_hello used raw bincode::deserialize which could
/// allocate unbounded memory on crafted payloads. While the server's Hello
/// handler in node.rs already uses size-limited bincode, this public API
/// function was unprotected and could be called by other code paths.
pub fn decode_hello(data: &[u8]) -> anyhow::Result<Hello> {
    Ok(bincode::DefaultOptions::new()
        .with_limit(MAX_HANDSHAKE_MSG_SIZE)
        .with_fixint_encoding()
        .deserialize(data)?)
}

/// R9: Validate serialized size does not exceed the wire limit.
/// Same issue as encode_hello -- asymmetric encode/decode limits.
pub fn encode_hello_ack(ack: &HelloAck) -> anyhow::Result<Vec<u8>> {
    let bytes = bincode::serialize(ack)?;
    if bytes.len() as u64 > MAX_HANDSHAKE_MSG_SIZE {
        anyhow::bail!(
            "serialized HelloAck too large: {} bytes (max {})",
            bytes.len(),
            MAX_HANDSHAKE_MSG_SIZE
        );
    }
    Ok(bytes)
}

/// R8: Use size-limited bincode for HelloAck deserialization.
/// Before this fix, decode_hello_ack used raw bincode::deserialize which
/// could allocate unbounded memory on crafted payloads from a malicious server.
pub fn decode_hello_ack(data: &[u8]) -> anyhow::Result<HelloAck> {
    Ok(bincode::DefaultOptions::new()
        .with_limit(MAX_HANDSHAKE_MSG_SIZE)
        .with_fixint_encoding()
        .deserialize(data)?)
}
