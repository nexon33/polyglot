use tokio::sync::{Mutex, oneshot, mpsc};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;
use anyhow::anyhow;
use crate::json_rpc::{read_message, write_message};
use serde_json::{json, Value};
use crate::virtual_fs::VirtualFile;

#[derive(Debug)]
pub struct Delegator {
    // Map lang_tag -> Child Process
    servers: Arc<Mutex<HashMap<String, ChildServer>>>,
    diagnostic_tx: Option<mpsc::Sender<Value>>,
}

#[derive(Debug)]
struct ChildServer {
    stdin: tokio::process::ChildStdin,
    pending: Arc<DashMap<u64, oneshot::Sender<Value>>>,
    next_id: Arc<AtomicU64>,
}

impl Delegator {
    /// Normalize language tags for consistent lookup
    /// "rs" | "rust" | "main" -> "rust", "py" | "python" -> "python"
    fn normalize_lang(lang: &str) -> &'static str {
        match lang {
            "rs" | "rust" | "main" | "interface" => "rust",
            "py" | "python" => "python",
            _ => "unknown",
        }
    }

    pub fn new(diagnostic_tx: Option<mpsc::Sender<Value>>) -> Self {
        Self {
            servers: Arc::new(Mutex::new(HashMap::new())),
            diagnostic_tx,
        }
    }

    pub async fn start_server(&self, lang: &str) -> anyhow::Result<()> {
        eprintln!("Delegator: Starting server for lang: {}", lang);
        let mut cmd = match lang {
            "rs" | "rust" => {
                let c = Command::new("rust-analyzer");
                c
            },
            "py" | "python" => {
                let mut c = Command::new("python");
                c.arg("-m").arg("pylsp");
                c
            },
            _ => return Err(anyhow!("Unsupported language for LSP delegation: {}", lang)),
        };

        cmd.stdin(Stdio::piped())
           .stdout(Stdio::piped())
           .stderr(Stdio::inherit()); 

        let mut child = cmd.spawn().map_err(|e| anyhow!("Failed to spawn {}: {}", lang, e))?;
        let stdin = child.stdin.take().ok_or(anyhow!("Failed to open stdin"))?;
        let mut stdout = child.stdout.take().ok_or(anyhow!("Failed to open stdout"))?;

        eprintln!("Delegator: Spawned server for {}", lang);

        let pending: Arc<DashMap<u64, oneshot::Sender<Value>>> = Arc::new(DashMap::new());
        let pending_clone = pending.clone();
        
        let diagnostic_tx = self.diagnostic_tx.clone();

        tokio::spawn(async move {
            loop {
                match read_message(&mut stdout).await {
                    Ok(Some(msg)) => {
                         // Check if it's a response
                         if let Some(id_val) = msg.get("id") {
                             if let Some(id) = id_val.as_u64() {
                                 if let Some((_, sender)) = pending_clone.remove(&id) {
                                     let _ = sender.send(msg);
                                 }
                             }
                         } else {
                             // No ID: Notification
                             if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
                                 if method == "textDocument/publishDiagnostics" {
                                      if let Some(tx) = &diagnostic_tx {
                                          let _ = tx.send(msg).await;
                                      }
                                 }
                             }
                         }
                    }
                    Ok(None) => {
                        eprintln!("LSP Reader EOF");
                        break;
                    }, 
                    Err(e) => {
                        eprintln!("LSP Reader Error: {}", e);
                        break;
                    }
                }
            }
        });
        
        let server = ChildServer {
            stdin,
            pending,
            next_id: Arc::new(AtomicU64::new(1)),
        };

        self.servers.lock().await.insert(Self::normalize_lang(lang).to_string(), server);
        Ok(())
    }

    pub async fn notify(&self, lang: &str, method: &str, params: Value) -> anyhow::Result<()> {
        let normalized = Self::normalize_lang(lang);
        let mut servers = self.servers.lock().await;
        if let Some(server) = servers.get_mut(normalized) {
            let msg = json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params
            });
            write_message(&mut server.stdin, &msg).await?;
        }
        Ok(())
    }

    pub async fn sync_open(&self, vfile: &VirtualFile) -> anyhow::Result<()> {
        // Construct a virtual URI
        // transform file:///path/to/test.poly -> file:///path/to/test_virtual.rs
        // This is a naive transformation
        let ext = vfile.lang_tag.clone();
        let uri_str = vfile.uri.to_string();
        let virtual_uri_str = if uri_str.ends_with(".poly") {
             uri_str.replace(".poly", &format!(".virtual.{}", ext))
        } else {
             format!("{}.virtual.{}", uri_str, ext)
        };
        
        let params = json!({
            "textDocument": {
                "uri": virtual_uri_str,
                "languageId": match ext.as_str() { "rs" => "rust", "py" => "python", _ => "plaintext" },
                "version": vfile.version,
                "text": vfile.content
            }
        });

        self.notify(&vfile.lang_tag, "textDocument/didOpen", params).await
    }

    pub async fn request(&self, lang: &str, method: &str, params: Value) -> anyhow::Result<Value> {
        let normalized = Self::normalize_lang(lang);
        let mut servers = self.servers.lock().await;
        if let Some(server) = servers.get_mut(normalized) {
            let id = server.next_id.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = oneshot::channel();
            
            server.pending.insert(id, tx);
            
            let msg = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params
            });
            
            write_message(&mut server.stdin, &msg).await?;
            drop(servers); // Release lock while waiting
            
            let response = rx.await?;
            // Return result or error
            if let Some(err) = response.get("error") {
                return Err(anyhow!("LSP Error: {:?}", err));
            }
            if let Some(res) = response.get("result") {
                return Ok(res.clone());
            }
            return Ok(Value::Null);
        }
        Err(anyhow!("Server not found for lang: {}", lang))
    }
}
