use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

mod virtual_fs;
mod delegator;
mod json_rpc;
mod type_graph;

use virtual_fs::VirtualFileManager;
use delegator::Delegator;
use std::sync::Arc;

#[derive(Debug)]
struct Backend {
    client: Client,
    vfm: Arc<VirtualFileManager>,
    delegator: Arc<Delegator>,
    diag_rx: Arc<Mutex<mpsc::Receiver<Value>>>,
    type_graph: Arc<Mutex<type_graph::TypeGraph>>,
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        self.client
            .log_message(MessageType::INFO, "Polyglot LSP initializing...")
            .await;

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                completion_provider: Some(CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: Some(vec![".".to_string(), ":".to_string()]),
                    work_done_progress_options: Default::default(),
                    all_commit_characters: None,
                    ..Default::default()
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Polyglot LSP initialized!")
            .await;
            
        // Spawn diagnostic listener
        let client = self.client.clone();
        let vfm = self.vfm.clone();
        let diag_rx = self.diag_rx.clone();
        
        tokio::spawn(async move {
            let mut rx = diag_rx.lock().await;
            while let Some(msg) = rx.recv().await {
                 if let Some(params) = msg.get("params") {
                     // Check if it's publishDiagnostics
                     // msg is the whole JSON-RPC notification object.
                     // params is the parameters object.
                     
                     if let Ok(mut diag_params) = serde_json::from_value::<PublishDiagnosticsParams>(params.clone()) {
                          let v_uri_str = diag_params.uri.to_string();
                          
                          // TODO: reverse lookup
                          // Since we don't have a fast reverse map, we iterate all files.
                          // This is O(N_files * N_virtual_files).
                          
                          let mut target_real_uri = None;
                          let mut mapping_vfile: Option<crate::virtual_fs::VirtualFile> = None;

                          for entry in vfm.files.iter() {
                              let real_uri = entry.key();
                              let vfiles = entry.value();
                              
                              for vfile in vfiles {
                                  if vfile.virtual_uri() == v_uri_str {
                                      target_real_uri = Some(real_uri.clone());
                                      mapping_vfile = Some(vfile.clone());
                                      break;
                                  }
                              }
                              if target_real_uri.is_some() { break; }
                          }

                          if let Some(real_uri) = target_real_uri {
                              if let Some(vfile) = mapping_vfile {
                                  // Remap lines
                                  for diag in &mut diag_params.diagnostics {
                                      diag.range.start.line = vfile.map_to_real(diag.range.start.line as usize) as u32;
                                      diag.range.end.line = vfile.map_to_real(diag.range.end.line as usize) as u32;
                                  }

                                  client.publish_diagnostics(
                                      real_uri,
                                      diag_params.diagnostics,
                                      diag_params.version
                                  ).await;
                              }
                          }
                     }
                 }
            }
        });

        // Attempt to start child servers
        if let Err(e) = self.delegator.start_server("rs").await {
             self.client.log_message(MessageType::WARNING, format!("Failed to start Rust analyzer: {}", e)).await;
        }
        if let Err(e) = self.delegator.start_server("py").await {
             self.client.log_message(MessageType::WARNING, format!("Failed to start Python LSP: {}", e)).await;
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, format!("file opened: {}", params.text_document.uri))
            .await;
        
        let vfiles = self.vfm.update_file(
            params.text_document.uri.clone(), 
            &params.text_document.text, 
            params.text_document.version
        );

        for vfile in &vfiles {
            if let Err(e) = self.delegator.sync_open(vfile).await {
                self.client.log_message(MessageType::ERROR, format!("Sync error: {}", e)).await;
            }
        }

        // Run Type Graph Analysis
        {
            let mut tg = self.type_graph.lock().await;
            tg.clear();
            // We need full text. valid for single file workspace. 
            // In reality, type graph should be global.
            // But here we scan strictly the current file's content.
            tg.scan_file(&params.text_document.text, &vfiles);
            let diags = tg.check_consistency();
            
            if !diags.is_empty() {
                self.client.publish_diagnostics(
                    params.text_document.uri,
                    diags,
                    Some(params.text_document.version)
                ).await;
            }
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
         self.client
            .log_message(MessageType::INFO, format!("file changed: {}", params.text_document.uri))
            .await;
            
          // Simplification: Assume full text sync for now, or handle incremental
        if let Some(changes) = params.content_changes.first() {
             let vfiles = self.vfm.update_file(
                 params.text_document.uri.clone(),
                 &changes.text,
                 params.text_document.version
             );
             // TODO: Sync changes to children
             
             // Run Type Graph Analysis
             {
                 let mut tg = self.type_graph.lock().await;
                 tg.clear();
                 tg.scan_file(&changes.text, &vfiles);
                 let diags = tg.check_consistency();
                 
                 // Always publish, even if empty, to clear old errors
                 self.client.publish_diagnostics(
                     params.text_document.uri,
                     diags,
                     Some(params.text_document.version)
                 ).await;
             }
        }
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let line = params.text_document_position_params.position.line as usize;
        let character = params.text_document_position_params.position.character;

        let vfiles = self.vfm.get_files(&uri).unwrap_or_default();
        
        for vfile in vfiles {
            if let Some(v_line) = vfile.map_to_virtual(line) {
                // Found the block!
                // Construct virtual URI params
                let ext = vfile.lang_tag.clone();
                let uri_str = vfile.uri.to_string();
                let virtual_uri_str = if uri_str.ends_with(".poly") {
                    uri_str.replace(".poly", &format!(".virtual.{}", ext))
                } else {
                    format!("{}.virtual.{}", uri_str, ext)
                };

                let req_params = serde_json::json!({
                    "textDocument": {
                        "uri": virtual_uri_str
                    },
                    "position": {
                        "line": v_line,
                        "character": character
                    }
                });

                match self.delegator.request(&vfile.lang_tag, "textDocument/hover", req_params).await {
                    Ok(resp) => {
                        // Parse response into Option<Hover>
                        if let Ok(mut hover) = serde_json::from_value::<Hover>(resp) {
                            // Remap range if present
                            if let Some(range) = &mut hover.range {
                                range.start.line = vfile.map_to_real(range.start.line as usize) as u32;
                                range.end.line = vfile.map_to_real(range.end.line as usize) as u32;
                            }
                            return Ok(Some(hover));
                        }
                    },
                    Err(e) => {
                        self.client.log_message(MessageType::ERROR, format!("Hover failed: {}", e)).await;
                    }
                }
            }
        }

        Ok(None)
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| {
        let (tx, rx) = mpsc::channel(100);
        Backend { 
            client,
            vfm: Arc::new(VirtualFileManager::new()),
            delegator: Arc::new(Delegator::new(Some(tx))),
            diag_rx: Arc::new(Mutex::new(rx)),
            type_graph: Arc::new(Mutex::new(type_graph::TypeGraph::new())),
        }
    });
    Server::new(stdin, stdout, socket).serve(service).await;
}
