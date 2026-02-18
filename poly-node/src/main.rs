use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use poly_inference::server::{InferenceBackend, MockInferenceBackend};

#[derive(Parser)]
#[command(name = "poly-node", about = "Poly Network decentralized compute node")]
struct Cli {
    /// Listen address for QUIC connections
    #[arg(long, default_value = "127.0.0.1:4001")]
    listen: SocketAddr,

    /// Model to serve ("mock" for testing)
    #[arg(long, default_value = "mock")]
    model: String,

    /// Bootstrap peer addresses
    #[arg(long)]
    bootstrap: Vec<SocketAddr>,

    /// Max concurrent inference sessions
    #[arg(long, default_value = "8")]
    max_sessions: u32,

    /// Enable relay mode (forward opaque PFHE bytes for NAT-traversed peers)
    #[arg(long)]
    relay: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let backend: Arc<dyn InferenceBackend + Send + Sync> = match cli.model.as_str() {
        "mock" => Arc::new(MockInferenceBackend::default()),
        _ => {
            eprintln!(
                "Warning: model '{}' not yet supported in p2p mode, using mock",
                cli.model
            );
            Arc::new(MockInferenceBackend::default())
        }
    };

    let config = poly_node::config::NodeConfig {
        listen_addr: cli.listen,
        model_name: cli.model,
        bootstrap_addrs: cli.bootstrap,
        max_sessions: cli.max_sessions,
        relay: cli.relay,
    };

    let node = poly_node::node::PolyNode::new(config, backend)?;
    node.run().await
}
