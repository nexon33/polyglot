//! # Poly Node — Decentralized Compute Node
//!
//! QUIC-based peer-to-peer compute node for the Poly Network.
//! Nodes discover each other via gossip, serve encrypted inference
//! requests over QUIC, and relay opaque PFHE ciphertext for NAT-traversed peers.
//!
//! ## Architecture
//!
//! - **`identity`** — Ed25519 node identity (NodeId = SHA-256 of public key)
//! - **`config`** — Node configuration (listen addr, model, bootstrap peers)
//! - **`protocol`** — Wire protocol: frame encoding, handshake, inference messages
//! - **`net`** — QUIC transport via quinn (self-signed TLS, multiplexed streams)
//! - **`node`** — Main daemon: accept connections, dispatch inference, gossip

pub mod config;
pub mod identity;
pub mod net;
pub mod node;
pub mod protocol;
