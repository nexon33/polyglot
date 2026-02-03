use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use std::time::Instant;
use std::path::PathBuf;

mod virtual_fs;
mod delegator;
mod json_rpc;
mod type_graph;
mod symbol_table;
mod semantic_tokens;
mod shadow_indexer;
mod sidecar_generator;

use virtual_fs::VirtualFileManager;
use delegator::Delegator;
use shadow_indexer::ShadowIndex;
use sidecar_generator::SidecarGenerator;
use std::sync::Arc;

struct Backend {
    client: Client,
    vfm: Arc<VirtualFileManager>,
    delegator: Arc<Delegator>,
    diag_rx: Arc<Mutex<mpsc::Receiver<Value>>>,
    type_graph: Arc<Mutex<type_graph::TypeGraph>>,
    /// Shadow indexer for fast signature extraction (<5ms)
    shadow_index: Arc<Mutex<ShadowIndex>>,
    /// Sidecar generator for TypeScript type definitions
    sidecar_generator: Arc<Mutex<SidecarGenerator>>,
    /// Debounce timer for full Tree-sitter scan
    debounce_timer: Arc<Mutex<Option<Instant>>>,
    /// Workspace root for sidecar generation
    workspace_root: Arc<Mutex<Option<PathBuf>>>,
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
                references_provider: Some(OneOf::Left(true)),
                semantic_tokens_provider: Some(
                    SemanticTokensServerCapabilities::SemanticTokensOptions(
                        SemanticTokensOptions {
                            legend: semantic_tokens::get_legend(),
                            full: Some(SemanticTokensFullOptions::Bool(true)),
                            range: Some(false),
                            ..Default::default()
                        }
                    )
                ),
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
            // Only clear call sites for THIS file, preserving other files' data
            tg.clear_for_file(&params.text_document.uri);
            tg.scan_file(&params.text_document.text, &vfiles);
            let diags = tg.check_consistency(&params.text_document.uri);

            if !diags.is_empty() {
                self.client.publish_diagnostics(
                    params.text_document.uri.clone(),
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

        // Simplification: Assume full text sync for now
        if let Some(changes) = params.content_changes.first() {
            let uri = params.text_document.uri.clone();
            let content = changes.text.clone();
            let version = params.text_document.version;

            let vfiles = self.vfm.update_file(uri.clone(), &content, version);

            // ========== PHASE 1: Quick Shadow Index Scan (<5ms) ==========
            // This runs immediately on every keystroke for responsive IDE features
            {
                let mut shadow = self.shadow_index.lock().await;
                for vfile in &vfiles {
                    shadow.quick_scan(
                        &vfile.content,
                        &vfile.lang_tag,
                        &uri,
                        vfile.start_line,
                    );
                }

                // Merge shadow signatures into TypeGraph's SymbolTable for immediate hover/completion
                let mut tg = self.type_graph.lock().await;
                shadow.merge_into_symbol_table(&mut tg.symbol_table, &uri);
            }

            // ========== PHASE 2: Debounced Full Tree-sitter Scan (500ms) ==========
            // This schedules a full AST parse after typing pauses
            let now = Instant::now();
            {
                let mut timer = self.debounce_timer.lock().await;
                *timer = Some(now);
            }

            // Clone Arc references for the spawned task
            let type_graph = self.type_graph.clone();
            let debounce_timer = self.debounce_timer.clone();
            let client = self.client.clone();
            let shadow_index = self.shadow_index.clone();
            let sidecar_gen = self.sidecar_generator.clone();
            let workspace_root = self.workspace_root.clone();
            let vfiles_clone = vfiles.clone();

            // Spawn debounced full scan
            tokio::spawn(async move {
                // Wait 500ms before doing full scan
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                // Check if we're still the most recent change
                let should_scan = {
                    let timer = debounce_timer.lock().await;
                    timer.map(|t| t == now).unwrap_or(false)
                };

                if should_scan {
                    // Perform full Tree-sitter scan
                    let mut tg = type_graph.lock().await;
                    tg.clear_for_file(&uri);
                    tg.scan_file(&content, &vfiles_clone);
                    let diags = tg.check_consistency(&uri);

                    // Publish diagnostics
                    client
                        .publish_diagnostics(uri.clone(), diags, Some(version))
                        .await;

                    // ========== PHASE 3: Regenerate Sidecar TypeScript Definitions ==========
                    let ws_root = workspace_root.lock().await;
                    if let Some(root) = ws_root.as_ref() {
                        let shadow = shadow_index.lock().await;
                        let mut sidecar = sidecar_gen.lock().await;
                        if let Some(dts_path) = sidecar.generate_dts(&tg, &shadow, &uri) {
                            client
                                .log_message(
                                    MessageType::INFO,
                                    format!("Generated: {}", dts_path.display()),
                                )
                                .await;
                        }
                    }
                }
            });
        }
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let line = params.text_document_position_params.position.line as usize;
        let character = params.text_document_position_params.position.character as usize;

        // Get the line content to check for Polyglot-specific keywords
        let vfiles = self.vfm.get_files(&uri).unwrap_or_default();
        
        // First, check for Polyglot-specific keywords that we handle directly
        if let Some(source) = self.vfm.get_source(&uri) {
            let lines: Vec<&str> = source.lines().collect();
            if line < lines.len() {
                let line_text = lines[line];
                
                // Check for visibility keywords
                if let Some(hover) = self.check_polyglot_hover(line_text, character) {
                    return Ok(Some(hover));
                }
                
                // Check for block directives
                if let Some(hover) = self.check_directive_hover(line_text, character) {
                    return Ok(Some(hover));
                }
                
                // Extract word at cursor for function/type hover
                let word = self.extract_word_at_cursor(line_text, character);
                
                if !word.is_empty() {
                    let tg = self.type_graph.lock().await;
                    
                    // Check for function hover
                    if let Some(hover_text) = tg.get_function_hover(&word) {
                        return Ok(Some(Hover {
                            contents: HoverContents::Markup(MarkupContent {
                                kind: MarkupKind::Markdown,
                                value: hover_text,
                            }),
                            range: None,
                        }));
                    }
                    
                    // Check for type hover
                    if let Some(hover_text) = tg.get_type_hover(&word) {
                        return Ok(Some(Hover {
                            contents: HoverContents::Markup(MarkupContent {
                                kind: MarkupKind::Markdown,
                                value: hover_text,
                            }),
                            range: None,
                        }));
                    }
                }
            }
        }
        
        // Delegate to language server for standard language hover
        for vfile in vfiles {
            if let Some(v_line) = vfile.map_to_virtual(line) {
                let virtual_uri_str = vfile.virtual_uri();

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
                        if let Ok(mut hover) = serde_json::from_value::<Hover>(resp) {
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

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = params.text_document_position_params.text_document.uri.clone();
        let line = params.text_document_position_params.position.line as usize;
        let character = params.text_document_position_params.position.character as usize;

        // First, try to find the word at cursor and look it up in SymbolTable
        let mut word = String::new();
        
        let vfiles = self.vfm.get_files(&uri).unwrap_or_default();
        
        // Try to extract word from virtual files
        for vfile in &vfiles {
            if let Some(v_line) = vfile.map_to_virtual(line) {
                let lines: Vec<&str> = vfile.content.lines().collect();
                if v_line < lines.len() {
                    let line_content = lines[v_line];
                    let char_idx = character.min(line_content.len());
                    let before = &line_content[..char_idx];
                    let after = &line_content[char_idx..];
                    
                    let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_').map(|i| i + 1).unwrap_or(0);
                    let end = after.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(after.len());
                    
                    word = format!("{}{}", &before[start..], &after[..end]);
                    break;
                }
            }
        }
        
        // Fallback: read from disk if not in virtual file (e.g., interface block)
        if word.is_empty() {
            if let Some(path_str) = uri.to_string().strip_prefix("file:///") {
                let decoded = urlencoding::decode(path_str).unwrap_or_else(|_| path_str.into());
                if let Ok(content) = std::fs::read_to_string(decoded.as_ref()) {
                    let lines: Vec<&str> = content.lines().collect();
                    if line < lines.len() {
                        let line_content = lines[line];
                        let char_idx = character.min(line_content.len());
                        let before = &line_content[..char_idx];
                        let after = &line_content[char_idx..];
                        
                        let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_').map(|i| i + 1).unwrap_or(0);
                        let end = after.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(after.len());
                        
                        word = format!("{}{}", &before[start..], &after[..end]);
                    }
                }
            }
        }

        // Look up in SymbolTable - prefer declaration, then implementation
        if !word.is_empty() {
            self.client.log_message(MessageType::INFO, format!("Definition lookup for word: '{}'", word)).await;
            
            let type_graph = self.type_graph.lock().await;
            let symbol_count = type_graph.symbol_table.all_symbols().count();
            self.client.log_message(MessageType::INFO, format!("SymbolTable has {} symbols", symbol_count)).await;
            
            if let Some(symbol) = type_graph.symbol_table.get_by_name(&word) {
                self.client.log_message(MessageType::INFO, format!("Found symbol: {} with {} impls, decl={}", 
                    symbol.name, symbol.implementations.len(), symbol.declaration.is_some())).await;
                
                // Prefer implementation (actual code) over declaration (interface)
                if let Some(imp) = symbol.implementations.first() {
                    self.client.log_message(MessageType::INFO, format!("Definition found for {} (implementation)", word)).await;
                    return Ok(Some(GotoDefinitionResponse::Scalar(Location {
                        uri: imp.uri.clone(),
                        range: imp.range,
                    })));
                }
                
                // Fall back to declaration if no implementation
                if let Some(decl) = &symbol.declaration {
                    self.client.log_message(MessageType::INFO, format!("Definition found for {} (declaration)", word)).await;
                    return Ok(Some(GotoDefinitionResponse::Scalar(Location {
                        uri: decl.uri.clone(),
                        range: decl.range,
                    })));
                }
            } else {
                self.client.log_message(MessageType::INFO, format!("Symbol '{}' NOT found in SymbolTable", word)).await;
            }
        } else {
            self.client.log_message(MessageType::INFO, "Definition lookup: word is empty").await;
        }

        // Fallback to delegated LSP for intra-block definitions (e.g., local variables)
        for vfile in &vfiles {
            if let Some(v_line) = vfile.map_to_virtual(line) {
                let virtual_uri_str = vfile.virtual_uri();
                let req_params = serde_json::json!({
                    "textDocument": {
                        "uri": virtual_uri_str
                    },
                    "position": {
                        "line": v_line,
                        "character": character
                    }
                });

                match self.delegator.request(&vfile.lang_tag, "textDocument/definition", req_params).await {
                    Ok(resp) => {
                        if let Ok(mut loc) = serde_json::from_value::<Location>(resp.clone()) {
                            if loc.uri == uri {
                                loc.range.start.line = vfile.map_to_real(loc.range.start.line as usize) as u32;
                                loc.range.end.line = vfile.map_to_real(loc.range.end.line as usize) as u32;
                            }
                            return Ok(Some(GotoDefinitionResponse::Scalar(loc)));
                        }
                        if resp.is_null() {
                            return Ok(None);
                        }
                    },
                    Err(e) => {
                        self.client.log_message(MessageType::ERROR, format!("Definition failed: {}", e)).await;
                    }
                }
            }
        }

        Ok(None)
    }
    
    /// Handle textDocument/references - Find all call sites of a function across all languages
    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let uri = params.text_document_position.text_document.uri.clone();
        let line = params.text_document_position.position.line as usize;
        let character = params.text_document_position.position.character as usize;
        
        // Get ALL vfiles for this document to access their content
        let vfiles = match self.vfm.files.get(&uri) {
            Some(vf) => vf.clone(),
            None => return Ok(None),
        };
        
        // Try to extract word from any virtual file that contains this line
        let mut word = String::new();
        
        // First try virtual files
        for vfile in &vfiles {
            if let Some(v_line) = vfile.map_to_virtual(line) {
                let lines: Vec<&str> = vfile.content.lines().collect();
                if v_line < lines.len() {
                    let line_content = lines[v_line];
                    let char_idx = character.min(line_content.len());
                    let before = &line_content[..char_idx];
                    let after = &line_content[char_idx..];
                    
                    let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_').map(|i| i + 1).unwrap_or(0);
                    let end = after.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(after.len());
                    
                    word = format!("{}{}", &before[start..], &after[..end]);
                    break;
                }
            }
        }
        
        // If still no word (e.g., in interface block), try reading from the virtual file URI on disk
        if word.is_empty() {
            // Read the poly file content from the file path
            if let Some(path_str) = uri.to_string().strip_prefix("file:///") {
                let decoded = urlencoding::decode(path_str).unwrap_or_else(|_| path_str.into());
                if let Ok(content) = std::fs::read_to_string(decoded.as_ref()) {
                    let lines: Vec<&str> = content.lines().collect();
                    if line < lines.len() {
                        let line_content = lines[line];
                        let char_idx = character.min(line_content.len());
                        let before = &line_content[..char_idx];
                        let after = &line_content[char_idx..];
                        
                        let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_').map(|i| i + 1).unwrap_or(0);
                        let end = after.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(after.len());
                        
                        word = format!("{}{}", &before[start..], &after[..end]);
                    }
                }
            }
        }
        
        if word.is_empty() {
            return Ok(None);
        }
        
        self.client.log_message(MessageType::INFO, format!("Find references for: {}", word)).await;
        
        // Query SymbolTable for ALL references (AST-based symbol linking)
        let type_graph = self.type_graph.lock().await;
        
        // Use SymbolTable for proper AST-based linking
        let mut locations: Vec<Location> = Vec::new();
        
        if let Some(symbol) = type_graph.symbol_table.get_by_name(&word) {
            // Add all call sites
            for loc in &symbol.call_sites {
                locations.push(Location {
                    uri: loc.uri.clone(),
                    range: loc.range,
                });
            }
            
            // Add all implementations  
            for loc in &symbol.implementations {
                locations.push(Location {
                    uri: loc.uri.clone(),
                    range: loc.range,
                });
            }
            
            // Also include the declaration if requested
            if params.context.include_declaration {
                if let Some(decl) = &symbol.declaration {
                    locations.push(Location {
                        uri: decl.uri.clone(),
                        range: decl.range,
                    });
                }
            }
        }
        
        self.client.log_message(MessageType::INFO, format!("Found {} references via SymbolTable", locations.len())).await;
        
        if locations.is_empty() {
            return Ok(None);
        }

        Ok(Some(locations))
    }

    /// Handle textDocument/semanticTokens/full - Provide semantic tokens for highlighting
    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri;

        // Get the source content
        let source = match self.vfm.get_source(&uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        self.client
            .log_message(MessageType::INFO, format!("Semantic tokens requested for: {}", uri))
            .await;

        // Tokenize the source
        let tokenizer = semantic_tokens::PolyTokenizer::new();
        let tokens = tokenizer.tokenize(&source);

        // Encode tokens into LSP format
        let data = semantic_tokens::encode_tokens_for_lsp(tokens);

        Ok(Some(SemanticTokensResult::Tokens(SemanticTokens {
            result_id: None,
            data,
        })))
    }
}

impl Backend {
    /// Check if cursor is on a Polyglot visibility keyword (export, public, internal)
    fn check_polyglot_hover(&self, line_text: &str, character: usize) -> Option<Hover> {
        let keywords = [
            ("export", "**export** *(Polyglot visibility)*\n\n---\n\nExported function callable from **other .poly files** that import this module.\n\n```\nexport fn foo() // Rust\nexport def bar() // Python\n```\n\nGenerates capability-protected FFI wrappers."),
            ("public", "**public** *(Polyglot visibility)*\n\n---\n\nPublic function callable from **anywhere**, including raw FFI calls.\n\n```\npublic fn foo() // or pub fn\npublic def bar()\n```\n\nNo capability check - use sparingly for true public APIs."),
            ("pub", "**pub** *(Polyglot visibility)*\n\n---\n\nAlias for `public`. Function callable from **anywhere**, including raw FFI.\n\nRust-friendly syntax for developers used to `pub fn`."),
            ("internal", "**internal** *(Polyglot visibility)*\n\n---\n\nInternal function only callable from **this file**.\n\n```\ninternal fn helper() // Explicit internal\nfn helper()          // Implicit internal (default)\n```\n\nNot exported to FFI. Capability-protected within the ecosystem."),
        ];
        
        for (keyword, description) in &keywords {
            if let Some(start) = line_text.find(keyword) {
                let end = start + keyword.len();
                // Check if cursor is within this keyword and it's followed by fn/def
                if character >= start && character <= end {
                    // Verify it's actually a visibility keyword (followed by fn/def)
                    let after = &line_text[end..].trim_start();
                    if after.starts_with("fn") || after.starts_with("def") {
                        return Some(Hover {
                            contents: HoverContents::Markup(MarkupContent {
                                kind: MarkupKind::Markdown,
                                value: description.to_string(),
                            }),
                            range: None,
                        });
                    }
                }
            }
        }
        
        None
    }
    
    /// Check if cursor is on a block directive (#[rust], #[python], etc.)
    fn check_directive_hover(&self, line_text: &str, character: usize) -> Option<Hover> {
        let directives = [
            ("#[types]", "**#[types]** *(Polyglot block)*\n\n---\n\nDefine cross-language type mappings.\n\n```\n#[types]\ntype Tensor = rust:gridmesh::Tensor<f32> | python:gridmesh.Tensor\n```\n\nTypes declared here are available in all subsequent blocks."),
            ("#[interface]", "**#[interface]** *(Polyglot block)*\n\n---\n\nDeclare function signatures without implementation.\n\n```\n#[interface]\nfn process(data: Tensor) -> Tensor\n```\n\nFunctions here must be implemented in a language block."),
            ("#[rust]", "**#[rust]** *(Polyglot block)*\n\n---\n\nRust implementation block. Code here compiles to WASM.\n\n```\n#[rust]\nexport fn create_tensor(rows: u32, cols: u32) -> Tensor {\n    Tensor::zeros(&[rows as usize, cols as usize])\n}\n```"),
            ("#[rs]", "**#[rs]** *(Polyglot block)*\n\n---\n\nAlias for `#[rust]`. Rust implementation block."),
            ("#[python]", "**#[python]** *(Polyglot block)*\n\n---\n\nPython implementation block. Runs via embedded RustPython.\n\n```\n#[python]\nexport def process_tensor(t: Tensor) -> Tensor:\n    print(f\"Processing {t.shape}\")\n    return t\n```"),
            ("#[py]", "**#[py]** *(Polyglot block)*\n\n---\n\nAlias for `#[python]`. Python implementation block."),
            ("#[main]", "**#[main]** *(Polyglot block)*\n\n---\n\nEntry point block (Rust syntax). Compiled as `_start` for WASM.\n\n```\n#[main]\nfn main() {\n    let t = create_tensor(128, 128);\n    print_tensor(t);\n}\n```"),
        ];
        
        for (directive, description) in &directives {
            if let Some(start) = line_text.find(directive) {
                let end = start + directive.len();
                if character >= start && character <= end {
                    return Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: description.to_string(),
                        }),
                        range: None,
                    });
                }
            }
        }
        
        None
    }
    
    /// Extract the word at the cursor position
    fn extract_word_at_cursor(&self, line_text: &str, character: usize) -> String {
        let chars: Vec<char> = line_text.chars().collect();
        
        if character >= chars.len() {
            return String::new();
        }
        
        // Find word boundaries
        let mut start = character;
        let mut end = character;
        
        // Expand left
        while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
            start -= 1;
        }
        
        // Expand right  
        while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        
        if start < end {
            chars[start..end].iter().collect()
        } else {
            String::new()
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Try to get workspace root from current directory
    let workspace_root = std::env::current_dir().ok();

    let (service, socket) = LspService::new(|client| {
        let (tx, rx) = mpsc::channel(100);

        // Initialize sidecar generator with workspace root
        let sidecar = if let Some(ref root) = workspace_root {
            SidecarGenerator::new(root.clone())
        } else {
            SidecarGenerator::new(std::env::temp_dir())
        };

        Backend {
            client,
            vfm: Arc::new(VirtualFileManager::new()),
            delegator: Arc::new(Delegator::new(Some(tx))),
            diag_rx: Arc::new(Mutex::new(rx)),
            type_graph: Arc::new(Mutex::new(type_graph::TypeGraph::new())),
            shadow_index: Arc::new(Mutex::new(ShadowIndex::new())),
            sidecar_generator: Arc::new(Mutex::new(sidecar)),
            debounce_timer: Arc::new(Mutex::new(None)),
            workspace_root: Arc::new(Mutex::new(workspace_root)),
        }
    });
    Server::new(stdin, stdout, socket).serve(service).await;
}
