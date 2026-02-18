//! Hello/HelloAck handshake messages.
//!
//! The first exchange on a new QUIC connection. Both sides send their
//! NodeInfo so each knows the other's identity, capabilities, and addresses.

use crate::protocol::wire::NodeInfo;
use serde::{Deserialize, Serialize};

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

pub fn encode_hello(hello: &Hello) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serialize(hello)?)
}

pub fn decode_hello(data: &[u8]) -> anyhow::Result<Hello> {
    Ok(bincode::deserialize(data)?)
}

pub fn encode_hello_ack(ack: &HelloAck) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serialize(ack)?)
}

pub fn decode_hello_ack(data: &[u8]) -> anyhow::Result<HelloAck> {
    Ok(bincode::deserialize(data)?)
}
