use std::net::SocketAddr;

/// Configuration for a Poly Network compute node.
pub struct NodeConfig {
    /// Address to listen for QUIC connections.
    pub listen_addr: SocketAddr,
    /// Model to serve ("mock" for testing, model name for real inference).
    pub model_name: String,
    /// Bootstrap peer addresses for initial discovery.
    pub bootstrap_addrs: Vec<SocketAddr>,
    /// Maximum concurrent inference sessions.
    pub max_sessions: u32,
    /// Whether this node acts as a relay for NAT-traversed peers.
    pub relay: bool,
}
