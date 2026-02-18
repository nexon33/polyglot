//! Wire protocol: message types, framing, and node advertisement types.
//!
//! Frame format: `[1B type][4B length (big-endian)][payload]`
//!
//! All payloads are bincode-serialized structs.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// ─── Message types ───────────────────────────────────────────────────────

/// Protocol message type tags (1 byte on the wire).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    // Handshake
    Hello = 0x01,
    HelloAck = 0x02,
    // Discovery (Phase 2)
    GetPeers = 0x10,
    Peers = 0x11,
    Announce = 0x12,
    // Health
    Ping = 0x20,
    Pong = 0x21,
    // Inference
    InferRequest = 0x30,
    InferResponse = 0x31,
    PubkeyRequest = 0x32,
    PubkeyResponse = 0x33,
    // Relay (Phase 3)
    RelayOpen = 0x40,
    RelayAccept = 0x41,
    RelayDeny = 0x42,
    RelayData = 0x43,
    RelayClose = 0x44,
}

impl MessageType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::HelloAck),
            0x10 => Some(Self::GetPeers),
            0x11 => Some(Self::Peers),
            0x12 => Some(Self::Announce),
            0x20 => Some(Self::Ping),
            0x21 => Some(Self::Pong),
            0x30 => Some(Self::InferRequest),
            0x31 => Some(Self::InferResponse),
            0x32 => Some(Self::PubkeyRequest),
            0x33 => Some(Self::PubkeyResponse),
            0x40 => Some(Self::RelayOpen),
            0x41 => Some(Self::RelayAccept),
            0x42 => Some(Self::RelayDeny),
            0x43 => Some(Self::RelayData),
            0x44 => Some(Self::RelayClose),
            _ => None,
        }
    }
}

// ─── Frame encoding ──────────────────────────────────────────────────────

/// Maximum allowed frame payload size (16 MB).
///
/// Prevents memory exhaustion from malicious length fields.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Wire frame: 1B type + 4B big-endian length + payload.
pub struct Frame {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode frame to bytes: [type][length][payload].
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(5 + self.payload.len());
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a frame from bytes. Returns (frame, bytes_consumed).
    ///
    /// Rejects payloads larger than `MAX_FRAME_PAYLOAD` to prevent
    /// memory exhaustion from malicious length fields.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), FrameError> {
        if data.len() < 5 {
            return Err(FrameError::Incomplete);
        }
        let msg_type =
            MessageType::from_u8(data[0]).ok_or(FrameError::UnknownType(data[0]))?;
        let len =
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if len > MAX_FRAME_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(len));
        }
        if data.len() < 5 + len {
            return Err(FrameError::Incomplete);
        }
        let payload = data[5..5 + len].to_vec();
        Ok((Self { msg_type, payload }, 5 + len))
    }
}

/// Frame decoding errors.
#[derive(Debug)]
pub enum FrameError {
    /// Not enough bytes to decode a complete frame.
    Incomplete,
    /// Unknown message type byte.
    UnknownType(u8),
    /// Payload length exceeds `MAX_FRAME_PAYLOAD`.
    PayloadTooLarge(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete frame"),
            Self::UnknownType(b) => write!(f, "unknown message type: 0x{:02x}", b),
            Self::PayloadTooLarge(n) => write!(
                f,
                "payload too large: {} bytes (max {})",
                n, MAX_FRAME_PAYLOAD
            ),
        }
    }
}

impl std::error::Error for FrameError {}

// ─── Node advertisement types ────────────────────────────────────────────

/// Information about a network node, broadcast via gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Ed25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// Addresses this node listens on.
    pub addresses: Vec<SocketAddr>,
    /// Models this node can serve.
    pub models: Vec<ModelCapability>,
    /// Whether this node can relay traffic for NAT-traversed peers.
    pub relay_capable: bool,
    /// Current capacity.
    pub capacity: NodeCapacity,
    /// Unix timestamp (seconds) when this info was generated.
    pub timestamp: u64,
    /// Ed25519 signature over all fields above (self-authenticating, 64 bytes).
    pub signature: Vec<u8>,
}

/// A model this node can serve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCapability {
    pub model_name: String,
    pub gpu: bool,
    pub throughput_estimate: f32,
}

/// Current node capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub queue_depth: u32,
    pub active_sessions: u32,
    pub max_sessions: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let frame = Frame::new(MessageType::Ping, vec![1, 2, 3, 4]);
        let encoded = frame.encode();
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.msg_type, MessageType::Ping);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn frame_round_trip_empty_payload() {
        let frame = Frame::new(MessageType::Pong, vec![]);
        let encoded = frame.encode();
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(decoded.msg_type, MessageType::Pong);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn frame_round_trip_large_payload() {
        let payload = vec![0xAB; 100_000];
        let frame = Frame::new(MessageType::InferRequest, payload.clone());
        let encoded = frame.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::InferRequest);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn frame_decode_incomplete_header() {
        assert!(matches!(
            Frame::decode(&[0x01, 0x00]),
            Err(FrameError::Incomplete)
        ));
    }

    #[test]
    fn frame_decode_incomplete_payload() {
        // Header says 10 bytes, but only 3 present
        let data = [0x20, 0x00, 0x00, 0x00, 0x0A, 1, 2, 3];
        assert!(matches!(
            Frame::decode(&data),
            Err(FrameError::Incomplete)
        ));
    }

    #[test]
    fn frame_decode_unknown_type() {
        let data = [0xFF, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            Frame::decode(&data),
            Err(FrameError::UnknownType(0xFF))
        ));
    }

    #[test]
    fn message_type_round_trip_all() {
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
        ];
        for &ty in &types {
            let b = ty as u8;
            assert_eq!(MessageType::from_u8(b), Some(ty));
        }
    }

    #[test]
    fn node_info_bincode_round_trip() {
        let info = NodeInfo {
            public_key: [42; 32],
            addresses: vec!["127.0.0.1:4001".parse().unwrap()],
            models: vec![ModelCapability {
                model_name: "mock".into(),
                gpu: false,
                throughput_estimate: 10.0,
            }],
            relay_capable: false,
            capacity: NodeCapacity {
                queue_depth: 0,
                active_sessions: 0,
                max_sessions: 8,
            },
            timestamp: 1234567890,
            signature: vec![0; 64],
        };
        let bytes = bincode::serialize(&info).unwrap();
        let decoded: NodeInfo = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.public_key, info.public_key);
        assert_eq!(decoded.models[0].model_name, "mock");
    }
}
