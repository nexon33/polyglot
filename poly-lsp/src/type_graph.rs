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
    // Type declarations: Type Name -> (Rust impl, Python impl)
    type_declarations: HashMap<String, (Option<String>, Option<String>)>,
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
            type_declarations: HashMap::new(),
            call_sites: Vec::new(),
            symbol_table: SymbolTable::new(),
        }
    }

    pub fn clear(&mut self) {
        self.interfaces.clear();
        self.implementations.clear();
        self.type_declarations.clear();
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
            
            if vfile.lang_tag == "types" {
                // Parse type declarations: type Name = rust:path | python:path
                let type_regex = regex::Regex::new(
                    r"type\s+(\w+)\s*=\s*(?:rust:([^\s|]+))?\s*\|?\s*(?:python:([^\s]+))?"
                ).unwrap();
                
                for line in vfile.content.lines() {
                    if let Some(cap) = type_regex.captures(line) {
                        let name = cap[1].to_string();
                        let rust_impl = cap.get(2).map(|m| m.as_str().to_string());
                        let python_impl = cap.get(3).map(|m| m.as_str().to_string());
                        
                        eprintln!("TypeGraph: Parsed type '{}' rust={:?} python={:?}", name, rust_impl, python_impl);
                        self.add_type_declaration(&name, rust_impl, python_impl);
                    }
                }
            } else if vfile.lang_tag == "interface" {
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
        
        // Scan for closure definitions: let name = |params| body
        // This catches patterns like: let init_embed = |s: &mut u64| randf(s) * ...
        let closure_query = Query::new(
            tree_sitter_rust::language(),
            "(let_declaration pattern: (identifier) @name value: (closure_expression parameters: (closure_parameters) @params)) @decl",
        )
        .unwrap();
        let mut closure_cursor = QueryCursor::new();

        for m in closure_cursor.matches(&closure_query, tree.root_node(), vfile.content.as_bytes()) {
            let decl_node = m.captures[0].node;  // @decl - the whole let_declaration
            let name_node = m.captures[1].node;  // @name - the identifier
            let _params_node = m.captures[2].node; // @params - closure_parameters

            let name = name_node
                .utf8_text(vfile.content.as_bytes())
                .unwrap()
                .to_string();

            let range = Range {
                start: Position {
                    line: vfile.map_to_real(decl_node.start_position().row) as u32,
                    character: decl_node.start_position().column as u32,
                },
                end: Position {
                    line: vfile.map_to_real(decl_node.end_position().row) as u32,
                    character: decl_node.end_position().column as u32,
                },
            };

            // Register closure as a local function implementation
            self.add_implementation(
                &name,
                "rs",
                TypeNode {
                    name: name.clone(),
                    params: vec![], // Could parse closure params if needed
                    return_type: None,
                    range,
                },
            );

            // Add to SymbolTable for Go to Definition / Find References
            let location = SymbolLocation {
                uri: vfile.uri.clone(),
                range,
                lang: vfile.lang_tag.clone(),
            };
            self.symbol_table.add_implementation(&name, location);
            eprintln!("  Added closure: {} at line {}", name, range.start.line);
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

        eprintln!("[PY-DEBUG] Content length: {} bytes", vfile.content.len());
        eprintln!("[PY-DEBUG] First 300 chars: {:?}", &vfile.content.chars().take(300).collect::<String>());

        let tree = match parser.parse(&vfile.content, None) {
            Some(t) => t,
            None => {
                eprintln!("[PY-DEBUG] FAILED TO PARSE!");
                return;
            }
        };

        eprintln!("[PY-DEBUG] Tree root kind: {}", tree.root_node().kind());
        eprintln!("[PY-DEBUG] Tree root has {} children", tree.root_node().child_count());

        // Debug: print all top-level children
        let root = tree.root_node();
        let mut walk = root.walk();
        for child in root.children(&mut walk) {
            eprintln!("[PY-DEBUG] Child: kind={} text={:?}",
                child.kind(),
                child.utf8_text(vfile.content.as_bytes()).unwrap_or("???").chars().take(50).collect::<String>()
            );
        }

        // Query for function definitions - try simpler query first
        let simple_query = Query::new(
            tree_sitter_python::language(),
            "(function_definition) @func",
        );

        match &simple_query {
            Ok(q) => {
                let mut cursor = QueryCursor::new();
                let count = cursor.matches(q, tree.root_node(), vfile.content.as_bytes()).count();
                eprintln!("[PY-DEBUG] Simple query (function_definition) found {} matches", count);
            }
            Err(e) => eprintln!("[PY-DEBUG] Simple query FAILED: {:?}", e),
        }

        // Now try the full query
        let query = Query::new(
            tree_sitter_python::language(),
            "(function_definition name: (identifier) @name parameters: (parameters) @params) @func",
        );

        let query = match query {
            Ok(q) => {
                eprintln!("[PY-DEBUG] Full query OK, capture names: {:?}", q.capture_names());
                q
            }
            Err(e) => {
                eprintln!("[PY-DEBUG] Full query FAILED: {:?}", e);
                return;
            }
        };

        let mut cursor = QueryCursor::new();
        let matches: Vec<_> = cursor.matches(&query, tree.root_node(), vfile.content.as_bytes()).collect();
        eprintln!("[PY-DEBUG] Full query found {} matches", matches.len());

        for m in matches {
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
            eprintln!("  [PY] Added def: {} at line {}", name, range.start.line);
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
            eprintln!("  [PY] Call site: {}() at line {}", callee_name, range.start.line);
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
    
    /// Get function hover info: signature, implementation language, interface declaration
    pub fn get_function_hover(&self, name: &str) -> Option<String> {
        let mut hover_parts = Vec::new();
        
        // Interface declaration
        if let Some(iface) = self.interfaces.get(name) {
            let params = iface.params.join(", ");
            let ret = iface.return_type.as_deref().unwrap_or("()");
            hover_parts.push(format!(
                "**{}** *(Polyglot function)*\n\n---\n\n```\nfn {}({}) -> {}\n```\n\n*Declared in interface block*",
                name, name, params, ret
            ));
        }
        
        // Implementation info
        if let Some((lang, impl_node)) = self.implementations.get(name) {
            let lang_display = match lang.as_str() {
                "rs" | "rust" => "Rust 🦀",
                "py" | "python" => "Python 🐍",
                "main" => "Main (Rust)",
                _ => lang,
            };
            
            let params = impl_node.params.join(", ");
            let ret = impl_node.return_type.as_deref().unwrap_or("()");
            
            if hover_parts.is_empty() {
                // No interface, just implementation
                hover_parts.push(format!(
                    "**{}** *(Polyglot function)*\n\n---\n\n```\nfn {}({}) -> {}\n```\n\n**Implemented in:** {}",
                    name, name, params, ret, lang_display
                ));
            } else {
                hover_parts.push(format!("\n\n**Implemented in:** {}", lang_display));
            }
        }
        
        if hover_parts.is_empty() {
            None
        } else {
            Some(hover_parts.join(""))
        }
    }
    
    /// Get interface signature for a function
    pub fn get_interface(&self, name: &str) -> Option<&TypeNode> {
        self.interfaces.get(name)
    }
    
    /// Get all interfaces (for type hover)
    pub fn get_interfaces(&self) -> &HashMap<String, TypeNode> {
        &self.interfaces
    }
    
    /// Add a type declaration
    pub fn add_type_declaration(&mut self, name: &str, rust_impl: Option<String>, python_impl: Option<String>) {
        self.type_declarations.insert(name.to_string(), (rust_impl, python_impl));
    }
    
    /// Get type hover info
    pub fn get_type_hover(&self, name: &str) -> Option<String> {
        if let Some((rust_impl, python_impl)) = self.type_declarations.get(name) {
            let mut hover = format!("**{}** *(Polyglot type)*\n\n---\n\n", name);
            
            if let Some(rust) = rust_impl {
                hover.push_str(&format!("**Rust:** `{}`\n\n", rust));
            }
            if let Some(python) = python_impl {
                hover.push_str(&format!("**Python:** `{}`\n\n", python));
            }
            
            hover.push_str("*Cross-language type mapping defined in `#[types]` block*");
            
            return Some(hover);
        }
        None
    }
    
    /// Get all type declarations
    pub fn get_type_declarations(&self) -> &HashMap<String, (Option<String>, Option<String>)> {
        &self.type_declarations
    }

    /// Check consistency for a specific file URI only
    pub fn check_consistency(&self, file_uri: &Url) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        // Note: Interface checks are skipped for now as they're file-global
        // TODO: Track which file each interface belongs to

        // Check: Cross-language undefined function calls (filtered by file)
        // For each call site in THIS file, verify the function is either:
        // - Defined in an interface
        // - Has an implementation
        // - Is a built-in/stdlib function (whitelist)
        let builtins = self.get_builtin_whitelist();

        for call_site in &self.call_sites {
            // Only check call sites from THIS file
            if &call_site.uri != file_uri {
                continue;
            }

            let name = &call_site.callee_name;

            // Skip built-in functions
            if builtins.contains(name.as_str()) {
                continue;
            }

            // Check if function exists in interface or implementation
            let has_interface = self.interfaces.contains_key(name);
            let has_impl = self.implementations.contains_key(name);

            if !has_interface && !has_impl {
                // Check SymbolTable for any definition
                let has_symbol = self.symbol_table.get_by_name(name)
                    .map(|s| s.declaration.is_some() || !s.implementations.is_empty())
                    .unwrap_or(false);

                if !has_symbol {
                    diagnostics.push(Diagnostic {
                        range: call_site.range,
                        severity: Some(DiagnosticSeverity::WARNING),
                        code: Some(tower_lsp::lsp_types::NumberOrString::String(
                            "undefined_function".to_string(),
                        )),
                        code_description: None,
                        source: Some("poly-typegraph".to_string()),
                        message: format!(
                            "Function '{}' is not defined in this polyglot file. Called from {} block.",
                            name, call_site.caller_lang
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

    /// Returns a set of built-in function names to ignore in undefined checks
    fn get_builtin_whitelist(&self) -> std::collections::HashSet<&'static str> {
        let mut builtins = std::collections::HashSet::new();

        // Rust std
        builtins.insert("println");
        builtins.insert("print");
        builtins.insert("format");
        builtins.insert("vec");
        builtins.insert("String");
        builtins.insert("Vec");
        builtins.insert("Box");
        builtins.insert("Arc");
        builtins.insert("Rc");
        builtins.insert("Option");
        builtins.insert("Some");
        builtins.insert("None");
        builtins.insert("Result");
        builtins.insert("Ok");
        builtins.insert("Err");
        builtins.insert("panic");
        builtins.insert("assert");
        builtins.insert("assert_eq");
        builtins.insert("debug_assert");
        builtins.insert("unreachable");
        builtins.insert("unimplemented");
        builtins.insert("todo");
        builtins.insert("dbg");
        builtins.insert("eprintln");
        builtins.insert("eprint");
        builtins.insert("write");
        builtins.insert("writeln");

        // Python built-ins
        builtins.insert("len");
        builtins.insert("range");
        builtins.insert("enumerate");
        builtins.insert("zip");
        builtins.insert("map");
        builtins.insert("filter");
        builtins.insert("sum");
        builtins.insert("min");
        builtins.insert("max");
        builtins.insert("abs");
        builtins.insert("round");
        builtins.insert("sorted");
        builtins.insert("reversed");
        builtins.insert("list");
        builtins.insert("dict");
        builtins.insert("set");
        builtins.insert("tuple");
        builtins.insert("str");
        builtins.insert("int");
        builtins.insert("float");
        builtins.insert("bool");
        builtins.insert("type");
        builtins.insert("isinstance");
        builtins.insert("hasattr");
        builtins.insert("getattr");
        builtins.insert("setattr");
        builtins.insert("open");
        builtins.insert("input");
        builtins.insert("iter");
        builtins.insert("next");
        builtins.insert("any");
        builtins.insert("all");

        // Common JS/TS
        builtins.insert("console");
        builtins.insert("log");
        builtins.insert("setTimeout");
        builtins.insert("setInterval");
        builtins.insert("fetch");
        builtins.insert("Promise");
        builtins.insert("Array");
        builtins.insert("Object");
        builtins.insert("JSON");
        builtins.insert("Math");
        builtins.insert("Date");
        builtins.insert("parseInt");
        builtins.insert("parseFloat");
        builtins.insert("isNaN");
        builtins.insert("isFinite");
        builtins.insert("encodeURI");
        builtins.insert("decodeURI");
        builtins.insert("Map");
        builtins.insert("Set");
        builtins.insert("WeakMap");
        builtins.insert("WeakSet");
        builtins.insert("Symbol");
        builtins.insert("BigInt");
        builtins.insert("Uint8Array");
        builtins.insert("Float32Array");
        builtins.insert("Float64Array");
        builtins.insert("Int32Array");
        builtins.insert("ArrayBuffer");
        builtins.insert("DataView");
        builtins.insert("Error");
        builtins.insert("TypeError");
        builtins.insert("ReferenceError");
        builtins.insert("require");

        // Common method names that look like function calls
        builtins.insert("push");
        builtins.insert("pop");
        builtins.insert("shift");
        builtins.insert("unshift");
        builtins.insert("slice");
        builtins.insert("splice");
        builtins.insert("concat");
        builtins.insert("join");
        builtins.insert("split");
        builtins.insert("trim");
        builtins.insert("replace");
        builtins.insert("match");
        builtins.insert("search");
        builtins.insert("includes");
        builtins.insert("indexOf");
        builtins.insert("forEach");
        builtins.insert("find");
        builtins.insert("findIndex");
        builtins.insert("every");
        builtins.insert("some");
        builtins.insert("reduce");
        builtins.insert("keys");
        builtins.insert("values");
        builtins.insert("entries");
        builtins.insert("append");
        builtins.insert("extend");
        builtins.insert("insert");
        builtins.insert("remove");
        builtins.insert("clear");
        builtins.insert("copy");
        builtins.insert("update");
        builtins.insert("get");
        builtins.insert("items");
        builtins.insert("await");
        builtins.insert("async");
        builtins.insert("catch");
        builtins.insert("then");
        builtins.insert("finally");

        builtins
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

        // Note: Interface checks are now disabled (need file URI tracking)
        let test_uri = Url::parse("file:///test.poly").unwrap();
        let diags = tg.check_consistency(&test_uri);
        println!("{:?}", diags);

        // Interface checks are disabled - no diagnostics expected
        assert_eq!(diags.len(), 0);
    }

    #[test]
    fn test_undefined_function_call() {
        let mut tg = TypeGraph::new();
        let test_uri = Url::parse("file:///test.poly").unwrap();

        // Add a call site for an undefined function
        tg.call_sites.push(CallSite {
            callee_name: "undefined_func".to_string(),
            caller_lang: "rust".to_string(),
            range: Range::default(),
            uri: test_uri.clone(),
        });

        let diags = tg.check_consistency(&test_uri);
        println!("{:?}", diags);

        // Expect 1 warning for undefined function
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("not defined"));
    }

    #[test]
    fn test_defined_function_no_warning() {
        let mut tg = TypeGraph::new();
        let test_uri = Url::parse("file:///test.poly").unwrap();

        // Add implementation for a function
        tg.add_implementation(
            "my_func",
            "rust",
            TypeNode {
                name: "my_func".to_string(),
                params: vec![],
                return_type: None,
                range: Range::default(),
            },
        );

        // Add a call site for the defined function
        tg.call_sites.push(CallSite {
            callee_name: "my_func".to_string(),
            caller_lang: "rust".to_string(),
            range: Range::default(),
            uri: test_uri.clone(),
        });

        let diags = tg.check_consistency(&test_uri);
        println!("{:?}", diags);

        // No warnings - function is defined
        assert_eq!(diags.len(), 0);
    }
}
