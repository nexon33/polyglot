use crate::virtual_fs::VirtualFile;
use std::collections::HashMap;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Position, Range};
use tree_sitter::{Parser, Query, QueryCursor};

#[derive(Debug, Clone)]
pub struct TypeNode {
    pub name: String,
    pub params: Vec<String>, // Type strings for now
    pub return_type: Option<String>,
    pub range: Range,
}

#[derive(Debug)]
pub struct TypeGraph {
    // Interface signatures: Function Name -> Signature
    interfaces: HashMap<String, TypeNode>,
    // Implementations: Function Name -> (Lang, Signature)
    implementations: HashMap<String, (String, TypeNode)>,
}

impl TypeGraph {
    pub fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
            implementations: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.interfaces.clear();
        self.implementations.clear();
    }

    pub fn add_interface(&mut self, name: &str, node: TypeNode) {
        self.interfaces.insert(name.to_string(), node);
    }

    pub fn scan_file(&mut self, _text: &str, vfiles: &[VirtualFile]) {
        // 1. Scan Interface Block (Regex for now, reliable enough for top-level)
        let interface_regex =
            regex::Regex::new(r"fn\s+(\w+)\s*\((.*?)\)\s*(?:->\s*(\w+))?").unwrap();

        for vfile in vfiles {
            if vfile.lang_tag == "interface" {
                // Parse definitions
                for cap in interface_regex.captures_iter(&vfile.content) {
                    let name = cap[1].to_string();
                    let params_str = &cap[2];
                    let ret = cap.get(3).map(|m| m.as_str().to_string());

                    let params: Vec<String> = params_str
                        .split(',')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| {
                            // Extract type: "p: Tensor" -> "Tensor"
                            s.split(':').nth(1).unwrap_or("").trim().to_string()
                        })
                        .collect();

                    let range = Range {
                        start: Position {
                            line: 0,
                            character: 0,
                        }, // TODO: accurate position inside block
                        end: Position {
                            line: 0,
                            character: 0,
                        },
                    };

                    self.add_interface(
                        &name,
                        TypeNode {
                            name: name.clone(),
                            params,
                            return_type: ret,
                            range,
                        },
                    );
                }
            } else if vfile.lang_tag == "rs" || vfile.lang_tag == "rust" {
                // Tree-sitter scan Rust
                self.scan_rust(vfile);
            } else if vfile.lang_tag == "py" || vfile.lang_tag == "python" {
                // Tree-sitter scan Python
                self.scan_python(vfile);
            }
        }
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
            let name_node = m.captures[0].node;
            let params_node = m.captures[1].node; // parameters node
            let func_node = m.captures[2].node;

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
            let name_node = m.captures[0].node;
            let params_node = m.captures[1].node; // parameters node
            let func_node = m.captures[2].node;

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
        }
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
