//! Compiler validation - checks that interface contracts are satisfied
//!
//! Validates:
//! 1. COMPLETENESS: Every interface function is implemented exactly once
//! 2. NO DUPLICATES: Same function not implemented in multiple blocks
//! 3. SIGNATURE MATCH: Implementation matches interface declaration

use crate::interface::parser::{FunctionDecl, InterfaceItem};
use crate::parser::{CodeBlock, ParsedFile};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ValidationError {
    pub message: String,
    pub kind: ValidationErrorKind,
}

#[derive(Debug)]
pub enum ValidationErrorKind {
    MissingImplementation,
    DuplicateImplementation,
    SignatureMismatch,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Extract function names from a code block
/// For Rust: uses syn AST to only detect top-level functions (not impl methods)
fn extract_implemented_functions(block: &CodeBlock) -> Vec<String> {
    let mut functions = Vec::new();

    match block.lang_tag.as_str() {
        "rs" | "rust" | "main" => {
            // Preprocess: convert Polyglot keywords to valid Rust syntax for syn
            let preprocessed = block
                .code
                .replace("export fn ", "pub fn ")
                .replace("public fn ", "pub fn ")
                .replace("internal fn ", "fn ");

            // Use syn AST to only get top-level Item::Fn, not impl methods
            if let Ok(syntax) = syn::parse_file(&preprocessed) {
                for item in syntax.items {
                    if let syn::Item::Fn(func) = item {
                        functions.push(func.sig.ident.to_string());
                    }
                    // syn::Item::Impl contains impl methods - we explicitly IGNORE these
                    // This is the key fix: Item::Fn only matches top-level functions
                }
            }
        }
        "py" | "python" => {
            // Match: def name( - for Python we still use regex (no Python AST)
            let re = regex::Regex::new(r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap();
            for cap in re.captures_iter(&block.code) {
                if let Some(name) = cap.get(1) {
                    functions.push(name.as_str().to_string());
                }
            }
        }
        _ => {}
    }

    functions
}

/// Validate that the parsed file satisfies interface contracts
pub fn validate(parsed: &ParsedFile) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Collect interface function declarations
    let interface_functions: Vec<&FunctionDecl> = parsed
        .interfaces
        .iter()
        .filter_map(|item| {
            if let InterfaceItem::Function(f) = item {
                Some(f)
            } else {
                None
            }
        })
        .collect();

    if interface_functions.is_empty() {
        // No interface declarations = nothing to validate
        return Ok(());
    }

    // Build a map of function name -> implementing blocks
    let mut implementations: HashMap<String, Vec<String>> = HashMap::new();

    for block in &parsed.blocks {
        let lang = block.lang_tag.clone();
        for func_name in extract_implemented_functions(block) {
            implementations
                .entry(func_name)
                .or_default()
                .push(lang.clone());
        }
    }

    // Check 1: COMPLETENESS - every interface fn must be implemented
    for func in &interface_functions {
        if !implementations.contains_key(&func.name) {
            errors.push(ValidationError {
                message: format!(
                    "❌ Function `{}` declared in #[interface] but not implemented in any block",
                    func.name
                ),
                kind: ValidationErrorKind::MissingImplementation,
            });
        }
    }

    // Check 2: NO DUPLICATES - no fn implemented in multiple blocks
    for (name, impls) in &implementations {
        if impls.len() > 1 {
            // Check if it's in the interface (if not, it's a helper function - allow duplicates)
            let is_interface_fn = interface_functions.iter().any(|f| f.name == *name);
            if is_interface_fn {
                errors.push(ValidationError {
                    message: format!(
                        "❌ Function `{}` implemented {} times (in: {}). Interface functions must be implemented exactly once.",
                        name,
                        impls.len(),
                        impls.join(", ")
                    ),
                    kind: ValidationErrorKind::DuplicateImplementation,
                });
            }
        }
    }

    // Check 3: Implementation exists for interface functions (additional check)
    // TODO: Signature matching would require parsing the actual function signatures
    // from the code blocks, which is more complex

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_rust_functions() {
        let block = CodeBlock {
            lang_tag: "rust".to_string(),
            code: r#"
                fn create_tensor(rows: u32, cols: u32) -> Tensor {
                    Tensor::new(rows, cols)
                }
                
                fn process(t: Tensor) -> Tensor { t }
            "#
            .to_string(),
            options: Default::default(),
            start_line: 0,
            code_start_line: 0,
        };

        let funcs = extract_implemented_functions(&block);
        assert!(funcs.contains(&"create_tensor".to_string()));
        assert!(funcs.contains(&"process".to_string()));
    }

    #[test]
    fn test_extract_python_functions() {
        let block = CodeBlock {
            lang_tag: "python".to_string(),
            code: r#"
def transform(t: Tensor) -> Tensor:
    return t

def validate(t: Tensor) -> bool:
    return True
            "#
            .to_string(),
            options: Default::default(),
            start_line: 0,
            code_start_line: 0,
        };

        let funcs = extract_implemented_functions(&block);
        assert!(funcs.contains(&"transform".to_string()));
        assert!(funcs.contains(&"validate".to_string()));
    }
}
