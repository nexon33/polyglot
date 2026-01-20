use crate::virtual_fs::VirtualFile;
use crate::symbol_table::{SymbolTable, SymbolKind, SymbolLocation};
use std::collections::HashMap;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Position, Range, Url};
use tree_sitter::{Parser, Query, QueryCursor};

#[derive(Debug, Clone)]
pub struct TypeNode {
    pub name: String,
    pub params: Vec<String>, // Type strings for now
    pub return_type: Option<String>,
    pub range: Range,
}

/// Represents a location where a function is called
#[derive(Debug, Clone)]
pub struct CallSite {
    pub callee_name: String,   // Function being called
    pub caller_lang: String,   // Language of the caller ("rs", "py", "main")
    pub range: Range,          // Location of the call in the real poly file
    pub uri: Url,              // File containing the call
}

#[derive(Debug)]
pub struct TypeGraph {
    // Interface signatures: Function Name -> Signature
    interfaces: HashMap<String, TypeNode>,
    // Implementations: Function Name -> (Lang, Signature)
    implementations: HashMap<String, (String, TypeNode)>,
    // All function call sites (legacy, kept for compatibility)
    pub call_sites: Vec<CallSite>,
    // Unified symbol table for AST-based linking
    pub symbol_table: SymbolTable,
}

impl TypeGraph {
    pub fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
            implementations: HashMap::new(),
            call_sites: Vec::new(),
            symbol_table: SymbolTable::new(),
        }
    }

    pub fn clear(&mut self) {
        self.interfaces.clear();
        self.implementations.clear();
        self.call_sites.clear();
        self.symbol_table.clear();
    }
    
    /// Clear only data for a specific file URI (keeps other files' data)
    pub fn clear_for_file(&mut self, uri: &Url) {
        self.call_sites.retain(|cs| &cs.uri != uri);
        self.symbol_table.clear_for_file(uri);
    }

    pub fn add_interface(&mut self, name: &str, node: TypeNode) {
        self.interfaces.insert(name.to_string(), node);
    }

    pub fn scan_file(&mut self, _text: &str, vfiles: &[VirtualFile]) {
        // 1. Scan Interface Block (Regex for now, reliable enough for top-level)
        let interface_regex =
            regex::Regex::new(r"fn\s+(\w+)\s*\((.*?)\)\s*(?:->\s*(\w+))?").unwrap();

        eprintln!("TypeGraph: Scanning {} virtual files", vfiles.len());

        for vfile in vfiles {
            eprintln!("TypeGraph: Processing block lang_tag='{}' start_line={}", vfile.lang_tag, vfile.start_line);
            
            if vfile.lang_tag == "interface" {
                // Parse interface declarations - functions defined in the polyglot contract
                for (line_idx, line) in vfile.content.lines().enumerate() {
                    if let Some(cap) = interface_regex.captures(line) {
                        let name = cap[1].to_string();
                        let params_str = &cap[2];
                        let ret = cap.get(3).map(|m| m.as_str().to_string());

                        let params: Vec<String> = params_str
                            .split(',')
                            .filter(|s| !s.trim().is_empty())
                            .map(|s| s.split(':').nth(1).unwrap_or("").trim().to_string())
                            .collect();

                        // Calculate real line in poly file
                        let real_line = vfile.map_to_real(line_idx) as u32;
                        
                        let range = Range {
                            start: Position { line: real_line, character: 0 },
                            end: Position { line: real_line, character: line.len() as u32 },
                        };

                        // Add to legacy interface tracking
                        self.add_interface(
                            &name,
                            TypeNode {
                                name: name.clone(),
                                params,
                                return_type: ret,
                                range,
                            },
                        );
                        
                        // Register in SymbolTable as a declaration
                        let location = SymbolLocation {
                            uri: vfile.uri.clone(),
                            range,
                            lang: "interface".to_string(),
                        };
                        self.symbol_table.declare(&name, SymbolKind::Function, location);
                    }
                }
            } else if vfile.lang_tag == "rs" || vfile.lang_tag == "rust" || vfile.lang_tag == "main" {
                // Tree-sitter scan Rust (including main block)
                self.scan_rust(vfile);
            } else if vfile.lang_tag == "py" || vfile.lang_tag == "python" {
                // Tree-sitter scan Python
                self.scan_python(vfile);
            }
        }
        
        eprintln!("TypeGraph: Found {} call sites total", self.call_sites.len());
        for cs in &self.call_sites {
            eprintln!("  CallSite: {} called from {} at line {}", cs.callee_name, cs.caller_lang, cs.range.start.line);
        }
        
        // Debug print SymbolTable
        self.symbol_table.debug_print();
    }

    fn scan_rust(&mut self, vfile: &VirtualFile) {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_rust::language()).unwrap();
        let tree = parser.parse(&vfile.content, None).unwrap();

        // Query for function definitions
        let query = Query::new(
            tree_sitter_rust::language(),
            "(function_item name: (identifier) @name parameters: (parameters) @params) @func",
        )
        .unwrap();
        let mut cursor = QueryCursor::new();

        for m in cursor.matches(&query, tree.root_node(), vfile.content.as_bytes()) {
            // Captures are in parse tree order, not query order
            // For "(function_item name: (identifier) @name ...)" the function_item @func comes first
            // Let's find captures by index based on expected order: @name=0, @params=1, @func=2
            // But tree-sitter orders by node position, so @func first, then @name, then @params
            let func_node = m.captures[0].node;  // @func - the whole function_item
            let name_node = m.captures[1].node;  // @name - the identifier
            let params_node = m.captures[2].node; // @params - parameters

            let name = name_node
                .utf8_text(vfile.content.as_bytes())
                .unwrap()
                .to_string();

            // Count params (naive: count commas + 1?)
            // Better: iterate children of params_node
            let mut param_count = 0;
            let mut cursor2 = params_node.walk();
            for child in params_node.children(&mut cursor2) {
                if child.kind() == "parameter" {
                    param_count += 1;
                }
            }

            let params = vec!["?".to_string(); param_count];

            let range = Range {
                start: Position {
                    line: vfile.map_to_real(func_node.start_position().row) as u32,
                    character: func_node.start_position().column as u32,
                },
                end: Position {
                    line: vfile.map_to_real(func_node.end_position().row) as u32,
                    character: func_node.end_position().column as u32,
                },
            };

            self.add_implementation(
                &name,
                "rs",
                TypeNode {
                    name: name.clone(),
                    params,
                    return_type: None, // TODO
                    range,
                },
            );
            
            // Add to SymbolTable for AST-based linking
            let location = SymbolLocation {
                uri: vfile.uri.clone(),
                range,
                lang: vfile.lang_tag.clone(),
            };
            self.symbol_table.add_implementation(&name, location);
            eprintln!("  Added {} implementation: {} at line {}", vfile.lang_tag, name, range.start.line);
        }
        
        // Scan for function calls
        let call_query = Query::new(
            tree_sitter_rust::language(),
            "(call_expression function: (identifier) @callee)",
        )
        .unwrap();
        let mut call_cursor = QueryCursor::new();
        
        for m in call_cursor.matches(&call_query, tree.root_node(), vfile.content.as_bytes()) {
            let callee_node = m.captures[0].node;
            let callee_name = callee_node
                .utf8_text(vfile.content.as_bytes())
                .unwrap()
                .to_string();
            
            let range = Range {
                start: Position {
                    line: vfile.map_to_real(callee_node.start_position().row) as u32,
                    character: callee_node.start_position().column as u32,
                },
                end: Position {
                    line: vfile.map_to_real(callee_node.end_position().row) as u32,
                    character: callee_node.end_position().column as u32,
                },
            };
            
            self.call_sites.push(CallSite {
                callee_name: callee_name.clone(),
                caller_lang: vfile.lang_tag.clone(),
                range,
                uri: vfile.uri.clone(),
            });
            
            // Add to SymbolTable for AST-based linking
            let location = SymbolLocation {
                uri: vfile.uri.clone(),
                range,
                lang: vfile.lang_tag.clone(),
            };
            self.symbol_table.add_call_site(&callee_name, location);
        }
    }

    fn scan_python(&mut self, vfile: &VirtualFile) {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_python::language()).unwrap();
        let tree = parser.parse(&vfile.content, None).unwrap();

        // Query for function definitions
        let query = Query::new(
            tree_sitter_python::language(),
            "(function_definition name: (identifier) @name parameters: (parameters) @params) @func",
        )
        .unwrap();
        let mut cursor = QueryCursor::new();

        for m in cursor.matches(&query, tree.root_node(), vfile.content.as_bytes()) {
            // Captures are in parse tree order: @func first, then @name, then @params
            let func_node = m.captures[0].node;
            let name_node = m.captures[1].node;
            let params_node = m.captures[2].node;

            let name = name_node
                .utf8_text(vfile.content.as_bytes())
                .unwrap()
                .to_string();

            let mut param_count = 0;
            let mut cursor2 = params_node.walk();
            for child in params_node.children(&mut cursor2) {
                // Python parameters can be diverse (typed_parameter, identifier, etc.)
                // We count anything that's not punctuation?
                if child.kind().contains("parameter") || child.kind() == "identifier" {
                    param_count += 1;
                }
            }

            let params = vec!["?".to_string(); param_count];

            let range = Range {
                start: Position {
                    line: vfile.map_to_real(func_node.start_position().row) as u32,
                    character: func_node.start_position().column as u32,
                },
                end: Position {
                    line: vfile.map_to_real(func_node.end_position().row) as u32,
                    character: func_node.end_position().column as u32,
                },
            };

            self.add_implementation(
                &name,
                "py",
                TypeNode {
                    name: name.clone(),
                    params,
                    return_type: None, // TODO
                    range,
                },
            );
            
            // Add to SymbolTable for AST-based linking
            let location = SymbolLocation {
                uri: vfile.uri.clone(),
                range,
                lang: vfile.lang_tag.clone(),
            };
            self.symbol_table.add_implementation(&name, location);
        }
        
        // Scan for function calls - Python uses (call function: (identifier) @callee)
        let call_query = Query::new(
            tree_sitter_python::language(),
            "(call function: (identifier) @callee)",
        )
        .unwrap();
        let mut call_cursor = QueryCursor::new();
        
        for m in call_cursor.matches(&call_query, tree.root_node(), vfile.content.as_bytes()) {
            let callee_node = m.captures[0].node;
            let callee_name = callee_node
                .utf8_text(vfile.content.as_bytes())
                .unwrap()
                .to_string();
            
            let range = Range {
                start: Position {
                    line: vfile.map_to_real(callee_node.start_position().row) as u32,
                    character: callee_node.start_position().column as u32,
                },
                end: Position {
                    line: vfile.map_to_real(callee_node.end_position().row) as u32,
                    character: callee_node.end_position().column as u32,
                },
            };
            
            self.call_sites.push(CallSite {
                callee_name: callee_name.clone(),
                caller_lang: vfile.lang_tag.clone(),
                range,
                uri: vfile.uri.clone(),
            });
            
            // Add to SymbolTable for AST-based linking
            let location = SymbolLocation {
                uri: vfile.uri.clone(),
                range,
                lang: vfile.lang_tag.clone(),
            };
            self.symbol_table.add_call_site(&callee_name, location);
        }
    }
    
    /// Find all call sites for a given function name
    pub fn find_references(&self, name: &str) -> Vec<&CallSite> {
        self.call_sites
            .iter()
            .filter(|cs| cs.callee_name == name)
            .collect()
    }
    
    /// Get implementation location for a function
    pub fn get_implementation(&self, name: &str) -> Option<(&String, &TypeNode)> {
        self.implementations.get(name).map(|(lang, node)| (lang, node))
    }
    
    pub fn add_implementation(&mut self, name: &str, lang: &str, node: TypeNode) {
        self.implementations
            .insert(name.to_string(), (lang.to_string(), node));
    }

    pub fn check_consistency(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Check 1: Every interface has an implementation
        for (name, iface_node) in &self.interfaces {
            if !self.implementations.contains_key(name) {
                diagnostics.push(Diagnostic {
                    range: iface_node.range,
                    severity: Some(DiagnosticSeverity::ERROR),
                    code: Some(tower_lsp::lsp_types::NumberOrString::String(
                        "missing_impl".to_string(),
                    )),
                    code_description: None,
                    source: Some("poly-typegraph".to_string()),
                    message: format!(
                        "Function '{}' defined in interface but not implemented.",
                        name
                    ),
                    related_information: None,
                    tags: None,
                    data: None,
                });
            } else {
                // Check 2: Signature Mismatch (Naive string check for now)
                let (lang, impl_node) = self.implementations.get(name).unwrap();

                if iface_node.params.len() != impl_node.params.len() {
                    diagnostics.push(Diagnostic {
                        range: impl_node.range, // Blame implementation
                        severity: Some(DiagnosticSeverity::ERROR),
                        code: Some(tower_lsp::lsp_types::NumberOrString::String(
                            "sig_mismatch".to_string(),
                        )),
                        code_description: None,
                        source: Some("poly-typegraph".to_string()),
                        message: format!(
                            "Paramenter count mismatch. Interface expects {}, {} found {}.",
                            iface_node.params.len(),
                            lang,
                            impl_node.params.len()
                        ),
                        related_information: None,
                        tags: None,
                        data: None,
                    });
                }
            }
        }

        diagnostics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_fs::VirtualFile;
    use tower_lsp::lsp_types::Url;

    #[test]
    fn test_type_graph_consistency_manual() {
        let mut tg = TypeGraph::new();

        // Add Interface manually
        tg.add_interface(
            "add",
            TypeNode {
                name: "add".to_string(),
                params: vec!["Tensor".to_string(), "Tensor".to_string()],
                return_type: Some("Tensor".to_string()),
                range: Range::default(),
            },
        );
        tg.add_interface(
            "missing",
            TypeNode {
                name: "missing".to_string(),
                params: vec![],
                return_type: None,
                range: Range::default(),
            },
        );

        // Add Implementation manually
        tg.add_implementation(
            "add",
            "rs",
            TypeNode {
                name: "add".to_string(),
                params: vec!["?".to_string(), "?".to_string()], // 2 params
                return_type: None,
                range: Range::default(),
            },
        );

        let diags = tg.check_consistency();
        println!("{:?}", diags);

        // Expect 1 error: missing_impl "missing"
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("not implemented"));
    }

    #[test]
    fn test_param_mismatch_manual() {
        let mut tg = TypeGraph::new();

        tg.add_interface(
            "process",
            TypeNode {
                name: "process".to_string(),
                params: vec!["Tensor".to_string()], // 1 param
                return_type: None,
                range: Range::default(),
            },
        );

        tg.add_implementation(
            "process",
            "py",
            TypeNode {
                name: "process".to_string(),
                params: vec!["?".to_string(), "?".to_string()], // 2 params
                return_type: None,
                range: Range::default(),
            },
        );

        let diags = tg.check_consistency();
        println!("{:?}", diags);

        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("mismatch"));
    }
}
