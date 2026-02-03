//! Shadow Indexer - Lightweight signature extraction for real-time TypeGraph updates
//!
//! This module provides fast (<5ms) regex-based extraction of function signatures,
//! enabling responsive IDE features during rapid typing without waiting for full
//! Tree-sitter parsing.

use regex::Regex;
use std::collections::HashMap;
use std::time::Instant;
use tower_lsp::lsp_types::{Position, Range, Url};

/// Visibility level of a function
#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    Public,    // pub fn, export fn, public fn
    Internal,  // internal fn, fn (default)
    Private,   // private fn
}

/// A lightweight function signature extracted via regex
#[derive(Debug, Clone)]
pub struct ShadowSignature {
    pub name: String,
    pub params: Vec<String>,
    pub return_type: Option<String>,
    pub visibility: Visibility,
    pub range: Range,
    pub lang: String,
    pub is_async: bool,
}

/// Fast signature index populated by regex scanning
pub struct ShadowIndex {
    /// Map from function name to signature
    signatures: HashMap<String, ShadowSignature>,
    /// When this index was last updated
    pub last_update: Instant,
    /// Compiled regex patterns for efficiency
    rust_fn_pattern: Regex,
    python_fn_pattern: Regex,
    interface_fn_pattern: Regex,
    js_fn_pattern: Regex,
}

impl ShadowIndex {
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
            last_update: Instant::now(),
            // Rust: (export|public|pub|internal)? (async)? fn name(params) (-> return)?
            rust_fn_pattern: Regex::new(
                r"(?m)^\s*(?:(export|public|pub|internal)\s+)?(?:(async)\s+)?fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^\{\n]+))?"
            ).unwrap(),
            // Python: (@export)? (async)? def name(params) (-> return)?:
            python_fn_pattern: Regex::new(
                r"(?m)^\s*(?:@(export)\s+)?(?:(async)\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*(\w[\w\[\],\s]*))?\s*:"
            ).unwrap(),
            // Interface: fn name(params) (-> return)?;
            interface_fn_pattern: Regex::new(
                r"(?m)^\s*fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^\n;]+))?\s*;"
            ).unwrap(),
            // JavaScript: (export)? (async)? function name(params) or const name = (async)? (params) =>
            js_fn_pattern: Regex::new(
                r"(?m)^\s*(?:(export)\s+)?(?:(async)\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:(async)\s+)?\([^)]*\)\s*=>)"
            ).unwrap(),
        }
    }

    /// Perform a quick regex-based scan of source code
    /// This should complete in <5ms for typical files
    pub fn quick_scan(&mut self, content: &str, lang: &str, uri: &Url, start_line: usize) {
        self.last_update = Instant::now();

        match lang {
            "rs" | "rust" | "main" => self.scan_rust(content, uri, start_line),
            "py" | "python" => self.scan_python(content, uri, start_line),
            "interface" => self.scan_interface(content, uri, start_line),
            "js" | "javascript" | "ts" | "typescript" => self.scan_js(content, uri, start_line),
            _ => {}
        }
    }

    /// Clear signatures for a specific file before re-scanning
    pub fn clear_for_uri(&mut self, uri: &Url) {
        let uri_str = uri.to_string();
        self.signatures.retain(|_, sig| {
            // Keep signatures that don't belong to this URI
            // We can't easily check URI from Range, so we use a naming convention
            // This is a simplification - in production, store URI in ShadowSignature
            true // For now, keep all - we'll overwrite on rescan
        });
    }

    fn scan_rust(&mut self, content: &str, uri: &Url, start_line: usize) {
        for caps in self.rust_fn_pattern.captures_iter(content) {
            let visibility = match caps.get(1).map(|m| m.as_str()) {
                Some("pub") | Some("public") | Some("export") => Visibility::Public,
                Some("internal") => Visibility::Internal,
                _ => Visibility::Internal,
            };
            let is_async = caps.get(2).is_some();
            let name = caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
            let params_str = caps.get(4).map(|m| m.as_str()).unwrap_or("");
            let return_type = caps.get(5).map(|m| m.as_str().trim().to_string());

            let params = self.parse_params(params_str);
            let line = self.find_line_number(content, caps.get(0).unwrap().start());

            let sig = ShadowSignature {
                name: name.clone(),
                params,
                return_type,
                visibility,
                range: Range {
                    start: Position {
                        line: (start_line + line) as u32,
                        character: 0,
                    },
                    end: Position {
                        line: (start_line + line) as u32,
                        character: 100,
                    },
                },
                lang: "rust".to_string(),
                is_async,
            };

            self.signatures.insert(name, sig);
        }
    }

    fn scan_python(&mut self, content: &str, uri: &Url, start_line: usize) {
        for caps in self.python_fn_pattern.captures_iter(content) {
            let visibility = match caps.get(1) {
                Some(_) => Visibility::Public, // @export decorator
                None => Visibility::Internal,
            };
            let is_async = caps.get(2).is_some();
            let name = caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
            let params_str = caps.get(4).map(|m| m.as_str()).unwrap_or("");
            let return_type = caps.get(5).map(|m| m.as_str().trim().to_string());

            // Skip __init__, __str__, etc. for interface purposes
            if name.starts_with("__") && name.ends_with("__") && name != "__init__" {
                continue;
            }

            let params = self.parse_python_params(params_str);
            let line = self.find_line_number(content, caps.get(0).unwrap().start());

            let sig = ShadowSignature {
                name: name.clone(),
                params,
                return_type,
                visibility,
                range: Range {
                    start: Position {
                        line: (start_line + line) as u32,
                        character: 0,
                    },
                    end: Position {
                        line: (start_line + line) as u32,
                        character: 100,
                    },
                },
                lang: "python".to_string(),
                is_async,
            };

            self.signatures.insert(name, sig);
        }
    }

    fn scan_interface(&mut self, content: &str, uri: &Url, start_line: usize) {
        for caps in self.interface_fn_pattern.captures_iter(content) {
            let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            let params_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let return_type = caps.get(3).map(|m| m.as_str().trim().to_string());

            let params = self.parse_params(params_str);
            let line = self.find_line_number(content, caps.get(0).unwrap().start());

            let sig = ShadowSignature {
                name: name.clone(),
                params,
                return_type,
                visibility: Visibility::Public, // Interface functions are always public
                range: Range {
                    start: Position {
                        line: (start_line + line) as u32,
                        character: 0,
                    },
                    end: Position {
                        line: (start_line + line) as u32,
                        character: 100,
                    },
                },
                lang: "interface".to_string(),
                is_async: false,
            };

            self.signatures.insert(name, sig);
        }
    }

    fn scan_js(&mut self, content: &str, uri: &Url, start_line: usize) {
        for caps in self.js_fn_pattern.captures_iter(content) {
            let visibility = match caps.get(1) {
                Some(_) => Visibility::Public,
                None => Visibility::Internal,
            };
            // Check for async in both positions (before function or in arrow)
            let is_async = caps.get(2).is_some() || caps.get(5).is_some();
            // Name can be in position 3 (function name) or 4 (const/let name)
            let name = caps
                .get(3)
                .or_else(|| caps.get(4))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            if name.is_empty() {
                continue;
            }

            let line = self.find_line_number(content, caps.get(0).unwrap().start());

            let sig = ShadowSignature {
                name: name.clone(),
                params: vec![], // JS params parsing would require more complex regex
                return_type: None,
                visibility,
                range: Range {
                    start: Position {
                        line: (start_line + line) as u32,
                        character: 0,
                    },
                    end: Position {
                        line: (start_line + line) as u32,
                        character: 100,
                    },
                },
                lang: "javascript".to_string(),
                is_async,
            };

            self.signatures.insert(name, sig);
        }
    }

    /// Parse Rust-style parameters: "name: Type, name2: Type2"
    fn parse_params(&self, params_str: &str) -> Vec<String> {
        if params_str.trim().is_empty() {
            return vec![];
        }

        params_str
            .split(',')
            .filter_map(|p| {
                let p = p.trim();
                if p.is_empty() || p == "self" || p == "&self" || p == "&mut self" {
                    return None;
                }
                // Extract type after colon
                if let Some(colon_pos) = p.find(':') {
                    Some(p[colon_pos + 1..].trim().to_string())
                } else {
                    Some("?".to_string()) // Unknown type
                }
            })
            .collect()
    }

    /// Parse Python-style parameters: "self, name: Type, name2: Type2"
    fn parse_python_params(&self, params_str: &str) -> Vec<String> {
        if params_str.trim().is_empty() {
            return vec![];
        }

        params_str
            .split(',')
            .filter_map(|p| {
                let p = p.trim();
                if p.is_empty() || p == "self" || p == "cls" {
                    return None;
                }
                // Handle **kwargs and *args
                if p.starts_with("**") || p.starts_with("*") {
                    return Some(p.to_string());
                }
                // Extract type after colon if present
                if let Some(colon_pos) = p.find(':') {
                    Some(p[colon_pos + 1..].trim().to_string())
                } else {
                    Some("?".to_string()) // Unknown type
                }
            })
            .collect()
    }

    /// Find line number from byte offset
    fn find_line_number(&self, content: &str, offset: usize) -> usize {
        content[..offset].matches('\n').count()
    }

    /// Get a signature by name
    pub fn get_signature(&self, name: &str) -> Option<&ShadowSignature> {
        self.signatures.get(name)
    }

    /// Get all signatures
    pub fn all_signatures(&self) -> impl Iterator<Item = &ShadowSignature> {
        self.signatures.values()
    }

    /// Get signatures by language
    pub fn signatures_by_lang<'a>(&'a self, lang: &'a str) -> impl Iterator<Item = &'a ShadowSignature> + 'a {
        self.signatures.values().filter(move |s| s.lang == lang)
    }

    /// Check if a function exists
    pub fn has_function(&self, name: &str) -> bool {
        self.signatures.contains_key(name)
    }

    /// Get function count
    pub fn function_count(&self) -> usize {
        self.signatures.len()
    }

    /// Merge shadow signatures into TypeGraph's SymbolTable
    /// This provides a fast path for hover/completion during typing
    pub fn merge_into_symbol_table(&self, symbol_table: &mut crate::symbol_table::SymbolTable, uri: &Url) {
        use crate::symbol_table::{SymbolKind, SymbolLocation};

        for sig in self.signatures.values() {
            // Create or update symbol
            let location = SymbolLocation {
                uri: uri.clone(),
                range: sig.range,
                lang: sig.lang.clone(),
            };

            if sig.lang == "interface" {
                // Interface declarations go to the declaration slot
                symbol_table.declare(&sig.name, SymbolKind::Function, location);
            } else {
                // Implementations go to the implementations list
                symbol_table.add_implementation(&sig.name, location);
            }
        }
    }
}

impl Default for ShadowIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_function_extraction() {
        let mut index = ShadowIndex::new();
        let uri = Url::parse("file:///test.poly").unwrap();

        let code = r#"
            pub fn calculate(x: i32, y: i32) -> i32 {
                x + y
            }

            async fn process_data(data: Vec<u8>) -> Result<String> {
                Ok("done".to_string())
            }

            export fn exposed_api(input: &str) -> bool {
                true
            }
        "#;

        index.quick_scan(code, "rust", &uri, 0);

        assert!(index.has_function("calculate"));
        assert!(index.has_function("process_data"));
        assert!(index.has_function("exposed_api"));

        let calc = index.get_signature("calculate").unwrap();
        assert_eq!(calc.visibility, Visibility::Public);
        assert_eq!(calc.params.len(), 2);
        assert_eq!(calc.return_type, Some("i32".to_string()));
        assert!(!calc.is_async);

        let process = index.get_signature("process_data").unwrap();
        assert!(process.is_async);
    }

    #[test]
    fn test_python_function_extraction() {
        let mut index = ShadowIndex::new();
        let uri = Url::parse("file:///test.poly").unwrap();

        let code = r#"
            def simple_func(x, y):
                return x + y

            @export
            async def api_handler(request: Request) -> Response:
                return Response()

            def typed_func(data: list[int]) -> int:
                return sum(data)
        "#;

        index.quick_scan(code, "python", &uri, 0);

        assert!(index.has_function("simple_func"));
        assert!(index.has_function("api_handler"));
        assert!(index.has_function("typed_func"));

        let handler = index.get_signature("api_handler").unwrap();
        assert_eq!(handler.visibility, Visibility::Public);
        assert!(handler.is_async);
    }

    #[test]
    fn test_interface_extraction() {
        let mut index = ShadowIndex::new();
        let uri = Url::parse("file:///test.poly").unwrap();

        let code = r#"
            fn compute(x: i32) -> i32;
            fn process(data: Vec<u8>) -> Result<String>;
            fn simple();
        "#;

        index.quick_scan(code, "interface", &uri, 0);

        assert!(index.has_function("compute"));
        assert!(index.has_function("process"));
        assert!(index.has_function("simple"));

        let compute = index.get_signature("compute").unwrap();
        assert_eq!(compute.lang, "interface");
        assert_eq!(compute.visibility, Visibility::Public);
    }

    #[test]
    fn test_performance() {
        let mut index = ShadowIndex::new();
        let uri = Url::parse("file:///test.poly").unwrap();

        // Generate a large file with many functions
        let mut code = String::new();
        for i in 0..100 {
            code.push_str(&format!(
                "pub fn function_{i}(x: i32, y: String) -> Result<i32> {{ Ok(42) }}\n"
            ));
        }

        let start = Instant::now();
        index.quick_scan(&code, "rust", &uri, 0);
        let elapsed = start.elapsed();

        // Should complete in under 5ms
        assert!(elapsed.as_millis() < 5, "Scan took {}ms", elapsed.as_millis());
        assert_eq!(index.function_count(), 100);
    }
}
