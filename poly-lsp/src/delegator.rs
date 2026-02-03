use tokio::sync::{Mutex, oneshot, mpsc};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;
use anyhow::anyhow;
use crate::json_rpc::{read_message, write_message};
use serde_json::{json, Value};
use crate::virtual_fs::VirtualFile;
use crate::type_graph::TypeGraph;
use tower_lsp::lsp_types::{Location, Position, Range, Url};

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
    initialized: Arc<AtomicBool>,
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
        
        let initialized = Arc::new(AtomicBool::new(false));
        
        let server = ChildServer {
            stdin,
            pending,
            next_id: Arc::new(AtomicU64::new(1)),
            initialized: initialized.clone(),
        };

        self.servers.lock().await.insert(Self::normalize_lang(lang).to_string(), server);
        
        // Send initialize request - required by LSP protocol before any other messages
        let init_params = json!({
            "processId": std::process::id(),
            "capabilities": {},
            "rootUri": null,
            "workspaceFolders": null
        });
        
        match self.request(lang, "initialize", init_params).await {
            Ok(_) => {
                eprintln!("Delegator: Initialized LSP for {}", lang);
                // Send initialized notification
                if let Err(e) = self.notify(lang, "initialized", json!({})).await {
                    eprintln!("Delegator: Failed to send initialized notification: {}", e);
                }
                // Mark server as fully initialized
                initialized.store(true, Ordering::SeqCst);
            },
            Err(e) => {
                eprintln!("Delegator: Failed to initialize LSP for {}: {}", lang, e);
            }
        }
        
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
        let normalized = Self::normalize_lang(&vfile.lang_tag);
        
        // Wait for server to be initialized (max 5 seconds)
        for _ in 0..50 {
            let servers = self.servers.lock().await;
            if let Some(server) = servers.get(normalized) {
                if server.initialized.load(Ordering::SeqCst) {
                    break;
                }
            }
            drop(servers);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        
        // Use the VirtualFile's virtual_uri which already normalizes the extension
        let virtual_uri_str = vfile.virtual_uri();
        
        // Write virtual file to disk - pylsp needs physical files
        // Convert URI to path: file:///c%3A/path/file.virtual.rs -> c:/path/file.virtual.rs
        if let Some(path_str) = virtual_uri_str.strip_prefix("file:///") {
            use std::io::Write;
            let decoded = urlencoding::decode(path_str).unwrap_or_else(|_| path_str.into());
            let path = std::path::PathBuf::from(decoded.as_ref());
            if let Ok(mut f) = std::fs::File::create(&path) {
                let _ = f.write_all(vfile.content.as_bytes());
            }
        }
        
        let params = json!({
            "textDocument": {
                "uri": virtual_uri_str,
                "languageId": vfile.language_id(),
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

    // ============ Middleware Interception Methods ============

    /// Request with fallback to TypeGraph when child LSP returns null/empty
    /// This is the core of Level 3 IDE integration - enabling cross-language features
    pub async fn request_with_fallback(
        &self,
        lang: &str,
        method: &str,
        params: Value,
        type_graph: Arc<Mutex<TypeGraph>>,
        word: &str,
        uri: &Url,
        position: Position,
    ) -> anyhow::Result<Value> {
        // First, try child LSP
        let response = self.request(lang, method, params).await;

        match method {
            "textDocument/definition" => {
                if self.is_null_or_empty(&response) {
                    return self.fallback_definition(type_graph, word, uri, position).await;
                }
            }
            "textDocument/references" => {
                // Always augment with cross-language references
                return self.augment_references(response, type_graph, word, uri, position).await;
            }
            "textDocument/hover" => {
                if self.is_null_or_empty(&response) {
                    return self.fallback_hover(type_graph, word).await;
                }
            }
            _ => {}
        }

        response
    }

    /// Check if a response is null, empty, or contains no useful data
    fn is_null_or_empty(&self, response: &anyhow::Result<Value>) -> bool {
        match response {
            Ok(Value::Null) => true,
            Ok(Value::Array(arr)) => arr.is_empty(),
            Ok(Value::Object(obj)) => obj.is_empty(),
            Err(_) => true,
            _ => false,
        }
    }

    /// Fallback for textDocument/definition using TypeGraph
    async fn fallback_definition(
        &self,
        type_graph: Arc<Mutex<TypeGraph>>,
        word: &str,
        uri: &Url,
        position: Position,
    ) -> anyhow::Result<Value> {
        let tg = type_graph.lock().await;

        // Look up symbol in SymbolTable
        if let Some(symbol) = tg.symbol_table.get_by_name(word) {
            // Prefer implementation over declaration
            if let Some(imp) = symbol.implementations.first() {
                return Ok(json!({
                    "uri": imp.uri.to_string(),
                    "range": {
                        "start": { "line": imp.range.start.line, "character": imp.range.start.character },
                        "end": { "line": imp.range.end.line, "character": imp.range.end.character }
                    }
                }));
            }

            // Fall back to declaration if no implementation found
            if let Some(decl) = &symbol.declaration {
                return Ok(json!({
                    "uri": decl.uri.to_string(),
                    "range": {
                        "start": { "line": decl.range.start.line, "character": decl.range.start.character },
                        "end": { "line": decl.range.end.line, "character": decl.range.end.character }
                    }
                }));
            }
        }

        Ok(Value::Null)
    }

    /// Augment references response with cross-language call sites
    async fn augment_references(
        &self,
        response: anyhow::Result<Value>,
        type_graph: Arc<Mutex<TypeGraph>>,
        word: &str,
        uri: &Url,
        position: Position,
    ) -> anyhow::Result<Value> {
        // Parse existing locations from child LSP response
        let mut locations: Vec<Value> = match &response {
            Ok(Value::Array(arr)) => arr.clone(),
            _ => Vec::new(),
        };

        // Get cross-language references from TypeGraph
        let tg = type_graph.lock().await;

        if let Some(symbol) = tg.symbol_table.get_by_name(word) {
            // Add call sites from all languages
            for call in &symbol.call_sites {
                let call_json = json!({
                    "uri": call.uri.to_string(),
                    "range": {
                        "start": { "line": call.range.start.line, "character": call.range.start.character },
                        "end": { "line": call.range.end.line, "character": call.range.end.character }
                    }
                });

                // Avoid duplicates
                if !locations.iter().any(|loc| {
                    loc.get("uri").and_then(|u| u.as_str()) == Some(call.uri.as_str())
                        && loc
                            .get("range")
                            .and_then(|r| r.get("start"))
                            .and_then(|s| s.get("line"))
                            .and_then(|l| l.as_u64())
                            == Some(call.range.start.line as u64)
                }) {
                    locations.push(call_json);
                }
            }

            // Add implementations as references too
            for imp in &symbol.implementations {
                let imp_json = json!({
                    "uri": imp.uri.to_string(),
                    "range": {
                        "start": { "line": imp.range.start.line, "character": imp.range.start.character },
                        "end": { "line": imp.range.end.line, "character": imp.range.end.character }
                    }
                });

                if !locations.iter().any(|loc| {
                    loc.get("uri").and_then(|u| u.as_str()) == Some(imp.uri.as_str())
                        && loc
                            .get("range")
                            .and_then(|r| r.get("start"))
                            .and_then(|s| s.get("line"))
                            .and_then(|l| l.as_u64())
                            == Some(imp.range.start.line as u64)
                }) {
                    locations.push(imp_json);
                }
            }

            // Add declaration if exists
            if let Some(decl) = &symbol.declaration {
                let decl_json = json!({
                    "uri": decl.uri.to_string(),
                    "range": {
                        "start": { "line": decl.range.start.line, "character": decl.range.start.character },
                        "end": { "line": decl.range.end.line, "character": decl.range.end.character }
                    }
                });

                if !locations.iter().any(|loc| {
                    loc.get("uri").and_then(|u| u.as_str()) == Some(decl.uri.as_str())
                        && loc
                            .get("range")
                            .and_then(|r| r.get("start"))
                            .and_then(|s| s.get("line"))
                            .and_then(|l| l.as_u64())
                            == Some(decl.range.start.line as u64)
                }) {
                    locations.push(decl_json);
                }
            }
        }

        Ok(Value::Array(locations))
    }

    /// Fallback hover using TypeGraph
    async fn fallback_hover(
        &self,
        type_graph: Arc<Mutex<TypeGraph>>,
        word: &str,
    ) -> anyhow::Result<Value> {
        let tg = type_graph.lock().await;

        // Try to get hover info from TypeGraph
        if let Some(hover_text) = tg.get_function_hover(word) {
            return Ok(json!({
                "contents": {
                    "kind": "markdown",
                    "value": hover_text
                }
            }));
        }

        // Try type hover
        if let Some(hover_text) = tg.get_type_hover(word) {
            return Ok(json!({
                "contents": {
                    "kind": "markdown",
                    "value": hover_text
                }
            }));
        }

        Ok(Value::Null)
    }
}
