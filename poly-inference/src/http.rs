//! HTTP transport for the inference server.
//!
//! Wraps `tiny_http` to serve inference requests over HTTP.
//! Single endpoint: `POST /infer` with JSON body.

use anyhow::Result;
use tiny_http::{Header, Method, Response, Server, StatusCode};

use crate::server::InferenceBackend;
use poly_client::protocol::InferRequest;

/// HTTP inference server.
pub struct HttpServer {
    server: Server,
}

impl HttpServer {
    /// Create a new HTTP server bound to the given address.
    ///
    /// Address format: "127.0.0.1:8080" or "0.0.0.0:3000".
    pub fn new(addr: &str) -> Result<Self> {
        let server =
            Server::http(addr).map_err(|e| anyhow::anyhow!("failed to bind {}: {}", addr, e))?;
        Ok(Self { server })
    }

    /// Serve inference requests indefinitely.
    pub fn serve<B: InferenceBackend>(&self, backend: &B) {
        for mut request in self.server.incoming_requests() {
            let response = handle_request(&mut request, backend);
            let _ = request.respond(response);
        }
    }

    /// Handle exactly one request, then return. Used for testing.
    pub fn handle_one<B: InferenceBackend>(&self, backend: &B) -> Result<()> {
        let mut request = self
            .server
            .recv()
            .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
        let response = handle_request(&mut request, backend);
        request
            .respond(response)
            .map_err(|e| anyhow::anyhow!("respond failed: {}", e))?;
        Ok(())
    }

    /// Get the server's bound address (useful when binding to port 0).
    pub fn addr(&self) -> std::net::SocketAddr {
        self.server.server_addr().to_ip().unwrap()
    }
}

fn handle_request<B: InferenceBackend>(
    request: &mut tiny_http::Request,
    backend: &B,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let json_header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();

    // Only POST /infer is valid
    if request.method() != &Method::Post {
        return Response::new(
            StatusCode(405),
            vec![json_header],
            std::io::Cursor::new(
                serde_json::to_vec(&serde_json::json!({"error": "method not allowed"})).unwrap(),
            ),
            None,
            None,
        );
    }

    if request.url() != "/infer" {
        return Response::new(
            StatusCode(404),
            vec![json_header],
            std::io::Cursor::new(
                serde_json::to_vec(&serde_json::json!({"error": "not found"})).unwrap(),
            ),
            None,
            None,
        );
    }

    // Read and parse request body
    let mut body = Vec::new();
    if let Err(e) = request.as_reader().read_to_end(&mut body) {
        return Response::new(
            StatusCode(400),
            vec![json_header],
            std::io::Cursor::new(
                serde_json::to_vec(&serde_json::json!({"error": format!("read error: {}", e)}))
                    .unwrap(),
            ),
            None,
            None,
        );
    }

    let infer_request: InferRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return Response::new(
                StatusCode(400),
                vec![json_header],
                std::io::Cursor::new(
                    serde_json::to_vec(
                        &serde_json::json!({"error": format!("invalid JSON: {}", e)}),
                    )
                    .unwrap(),
                ),
                None,
                None,
            );
        }
    };

    // Run inference
    match backend.infer(&infer_request) {
        Ok(response) => {
            let response_body = serde_json::to_vec(&response).unwrap();
            Response::new(
                StatusCode(200),
                vec![json_header],
                std::io::Cursor::new(response_body),
                None,
                None,
            )
        }
        Err(e) => Response::new(
            StatusCode(500),
            vec![json_header],
            std::io::Cursor::new(
                serde_json::to_vec(
                    &serde_json::json!({"error": format!("inference failed: {}", e)}),
                )
                .unwrap(),
            ),
            None,
            None,
        ),
    }
}
