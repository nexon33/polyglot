use crate::interface::parser::InterfaceItem;
use crate::types::{FunctionSig, Param, WitType};
use regex::Regex;

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum TypeRef {
    Primitive(WitType),
    Named(String),
}

/// Import statement: use <items> from "<path>"
#[derive(Debug, Clone)]
pub struct Import {
    pub items: Vec<String>, // Empty means import all (use * from)
    pub path: String,       // Relative path to .poly file
}

#[derive(Debug, Default)]
pub struct ParsedFile {
    pub blocks: Vec<CodeBlock>,
    pub signatures: Vec<FunctionSig>,
    pub interfaces: Vec<InterfaceItem>,
    pub imports: Vec<Import>, // Imported files
}

#[derive(Debug, Clone)]
pub struct CodeBlock {
    pub lang_tag: String,
    pub code: String,
    pub options: HashMap<String, String>,
    pub start_line: usize,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Parse error at line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

pub fn parse_poly(source: &str) -> Result<ParsedFile, ParseError> {
    let mut parsed = ParsedFile::default();

    // Parse import statements: use <item> from "<path>"
    // Syntax: use myfunction from "./other.poly"
    //         use * from "./types.poly"
    //         use { foo, bar } from "./utils.poly"
    let import_re =
        Regex::new(r#"(?m)^use\s+(?:(\*)|(\w+)|(?:\{([^}]+)\}))\s+from\s+"([^"]+)""#).unwrap();

    for cap in import_re.captures_iter(source) {
        let path = cap.get(4).unwrap().as_str().to_string();
        let items = if cap.get(1).is_some() {
            // use * from "..."
            vec![] // Empty means all
        } else if let Some(single) = cap.get(2) {
            // use item from "..."
            vec![single.as_str().to_string()]
        } else if let Some(multi) = cap.get(3) {
            // use { foo, bar } from "..."
            multi
                .as_str()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        } else {
            vec![]
        };

        parsed.imports.push(Import { items, path });
    }

    // Regex to find polyglot block headers: #[rust], #[python], #[interface], #[types], #[main], etc.
    // Only matches known polyglot tags, not Rust attributes like #[no_mangle]
    // Supported: rust/rs, python/py, interface, types, main, gpu, js, html, rscss, css
    let re = Regex::new(r"(?m)^#\[(interface|types|rust|rs|python|py|main|gpu|wgsl|js|jsx|html|rscss|css)(?::[a-zA-Z0-9_:]+)?\]\s*$")
        .unwrap();

    let matches: Vec<_> = re.find_iter(source).collect();

    for (i, m) in matches.iter().enumerate() {
        let start_idx = m.end();
        let end_idx = if i + 1 < matches.len() {
            matches[i + 1].start()
        } else {
            source.len()
        };

        if start_idx >= end_idx {
            continue;
        }

        let tag_header = m.as_str().trim(); // e.g. "#[rust]"
        let tag_content = &source[start_idx..end_idx];

        // Extract tag name from header: "#[rust]" -> "rust"
        let inner = tag_header.trim_start_matches("#[").trim_end_matches(']');

        let mut parts = inner.split(':');
        let lang_tag = parts.next().unwrap_or("").to_string();

        // Parse interface blocks specially
        if lang_tag == "interface" {
            if let Ok(interfaces) = crate::interface::parser::parse_interface(tag_content) {
                parsed.interfaces.extend(interfaces); // Extend instead of overwrite
            }
            // Fall through to also add interface as a code block for LSP VirtualFile tracking
        }

        // Parse #[types] blocks for type declarations (cleaner syntax than #[interface])
        if lang_tag == "types" {
            if let Ok(interfaces) = crate::interface::parser::parse_interface(tag_content) {
                parsed.interfaces.extend(interfaces);
            }
            // Fall through to also add as a code block for LSP
        }

        let mut options = HashMap::new();
        for opt in parts {
            options.insert(opt.to_string(), "true".to_string());
        }

        // Calculate start line
        let start_line = source[..m.start()].lines().count();

        parsed.blocks.push(CodeBlock {
            lang_tag,
            code: tag_content.trim().to_string(),
            options,
            start_line,
        });
    }

    // Auto-discover export/public functions from Rust/Python blocks
    scan_exported_functions(&mut parsed);

    Ok(parsed)
}

/// Scan code blocks for `export fn`, `public fn` (Rust) and `export def`, `public def` (Python)
fn scan_exported_functions(parsed: &mut ParsedFile) {
    use crate::interface::parser::{FunctionDecl, InterfaceItem, PrimitiveType, Type, Visibility};
    use regex::Regex;

    // Rust patterns:
    // - export fn name(params) -> Type  => Export visibility
    // - public fn name(params) -> Type  => Public visibility (FFI)
    // - pub fn name(params) -> Type      => Public (alias, Rust-friendly)
    let rust_export_re =
        Regex::new(r"export\s+fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^\{]+))?").unwrap();
    let rust_public_re =
        Regex::new(r"(?:public|pub)\s+fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^\{]+))?").unwrap();

    // Python patterns:
    // - export def name(params) -> Type:  => Export visibility
    // - public def name(params) -> Type:  => Public visibility (FFI)
    let python_export_re =
        Regex::new(r"export\s+def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*(\w+))?").unwrap();
    let python_public_re =
        Regex::new(r"(?:public|pub)\s+def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*(\w+))?").unwrap();

    for block in &parsed.blocks {
        let (patterns, is_rust): (Vec<(&Regex, Visibility)>, bool) = match block.lang_tag.as_str() {
            "rust" | "rs" => (
                vec![
                    (&rust_export_re, Visibility::Export),
                    (&rust_public_re, Visibility::Public),
                ],
                true,
            ),
            "python" | "py" => (
                vec![
                    (&python_export_re, Visibility::Export),
                    (&python_public_re, Visibility::Public),
                ],
                false,
            ),
            _ => continue,
        };

        for (re, visibility) in patterns {
            for cap in re.captures_iter(&block.code) {
                let name = cap
                    .get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let params_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let return_type_str = cap.get(3).map(|m| m.as_str().trim());

                // Parse parameters
                let params = parse_params_to_type(params_str, is_rust);

                // Parse return type
                let return_type = return_type_str.and_then(|s| {
                    let s = s.trim();
                    if s.is_empty() {
                        None
                    } else {
                        Some(parse_type_str(s, is_rust))
                    }
                });

                let func_decl = FunctionDecl {
                    name,
                    params,
                    return_type,
                    visibility,
                };

                // Check if this function is already in interfaces (avoid duplicates)
                let already_exists = parsed.interfaces.iter().any(|item| {
                    if let InterfaceItem::Function(f) = item {
                        f.name == func_decl.name
                    } else {
                        false
                    }
                });

                if !already_exists {
                    parsed.interfaces.push(InterfaceItem::Function(func_decl));
                }
            }
        }
    }
}

/// Parse a parameter string like "rows: u32, cols: u32" into Vec<(String, Type)>
fn parse_params_to_type(
    params_str: &str,
    is_rust: bool,
) -> Vec<(String, crate::interface::parser::Type)> {
    use crate::interface::parser::Type;

    let mut params = Vec::new();
    let trimmed = params_str.trim();

    if trimmed.is_empty() {
        return params;
    }

    // Skip self parameters
    let trimmed = if is_rust {
        trimmed
            .trim_start_matches("&mut self,")
            .trim_start_matches("&self,")
            .trim_start_matches("mut self,")
            .trim_start_matches("self,")
            .trim()
    } else {
        // Python: skip 'self' as first param
        if trimmed.starts_with("self,") {
            trimmed.trim_start_matches("self,").trim()
        } else if trimmed == "self" {
            return params;
        } else {
            trimmed
        }
    };

    if trimmed.is_empty() {
        return params;
    }

    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Parse "name: Type" or "name: Type = default"
        if let Some(colon_idx) = part.find(':') {
            let name = part[..colon_idx]
                .trim()
                .trim_start_matches("mut ")
                .to_string();
            let type_part = part[colon_idx + 1..].trim();

            // Remove default value if present (for Python)
            let type_str = if let Some(eq_idx) = type_part.find('=') {
                type_part[..eq_idx].trim()
            } else {
                type_part
            };

            let ty = parse_type_str(type_str, is_rust);
            params.push((name, ty));
        }
    }

    params
}

/// Parse a type string into Type enum
fn parse_type_str(s: &str, is_rust: bool) -> crate::interface::parser::Type {
    use crate::interface::parser::{PrimitiveType, Type};

    let s = s.trim();

    // Handle primitives
    if is_rust {
        match s {
            "bool" => return Type::Primitive(PrimitiveType::Bool),
            "u8" => return Type::Primitive(PrimitiveType::U8),
            "u16" => return Type::Primitive(PrimitiveType::U16),
            "u32" => return Type::Primitive(PrimitiveType::U32),
            "u64" => return Type::Primitive(PrimitiveType::U64),
            "i8" => return Type::Primitive(PrimitiveType::I8),
            "i16" => return Type::Primitive(PrimitiveType::I16),
            "i32" => return Type::Primitive(PrimitiveType::I32),
            "i64" => return Type::Primitive(PrimitiveType::I64),
            "f32" => return Type::Primitive(PrimitiveType::F32),
            "f64" => return Type::Primitive(PrimitiveType::F64),
            "String" | "&str" | "&String" => return Type::Primitive(PrimitiveType::String),
            _ => {}
        }
    } else {
        // Python types
        match s {
            "bool" => return Type::Primitive(PrimitiveType::Bool),
            "int" => return Type::Primitive(PrimitiveType::I64),
            "float" => return Type::Primitive(PrimitiveType::F64),
            "str" => return Type::Primitive(PrimitiveType::String),
            "bytes" => return Type::Primitive(PrimitiveType::Bytes),
            _ => {}
        }
    }

    // Handle generics like Vec<T> or list[T]
    if is_rust && s.starts_with("Vec<") && s.ends_with('>') {
        let inner = &s[4..s.len() - 1];
        return Type::Generic("Vec".to_string(), vec![parse_type_str(inner, is_rust)]);
    }

    if !is_rust && s.starts_with("list[") && s.ends_with(']') {
        let inner = &s[5..s.len() - 1];
        return Type::Generic("list".to_string(), vec![parse_type_str(inner, is_rust)]);
    }

    // Default: Named type
    Type::Named(s.to_string())
}

pub fn parse_python_params(s: &str) -> Result<Vec<Param>, ParseError> {
    let mut params = Vec::new();

    if s.trim().is_empty() {
        return Ok(params);
    }

    // Simple split - doesn't handle nested generics perfectly
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() || part == "self" {
            continue;
        }

        // name: type = default
        let (name, rest) = if let Some(idx) = part.find(':') {
            (part[..idx].trim(), Some(&part[idx + 1..]))
        } else {
            (part, None)
        };

        let (ty_str, default) = if let Some(rest) = rest {
            if let Some(idx) = rest.find('=') {
                (
                    Some(rest[..idx].trim()),
                    Some(rest[idx + 1..].trim().to_string()),
                )
            } else {
                (Some(rest.trim()), None)
            }
        } else {
            (None, None)
        };

        let ty = match ty_str {
            Some(s) => parse_python_type(s)?,
            None => WitType::Any,
        };

        params.push(Param {
            name: name.to_string(),
            ty,
            default,
        });
    }

    Ok(params)
}

pub fn parse_python_type(s: &str) -> Result<WitType, ParseError> {
    let s = s.trim();

    Ok(match s {
        "None" => WitType::Unit,
        "bool" => WitType::Bool,
        "int" => WitType::S64,
        "float" => WitType::F64,
        "str" => WitType::String,
        "bytes" => WitType::Bytes,
        "Any" => WitType::Any,

        s if s.starts_with("list[") && s.ends_with(']') => {
            let inner = &s[5..s.len() - 1];
            WitType::List(Box::new(parse_python_type(inner)?))
        }

        s if s.starts_with("dict[") && s.ends_with(']') => {
            let inner = &s[5..s.len() - 1];
            // Find the comma that separates key and value types
            // This is naive - doesn't handle nested generics
            if let Some(comma) = inner.find(',') {
                let key = parse_python_type(inner[..comma].trim())?;
                let val = parse_python_type(inner[comma + 1..].trim())?;
                WitType::Dict(Box::new(key), Box::new(val))
            } else {
                WitType::Dict(Box::new(WitType::String), Box::new(WitType::Any))
            }
        }

        s if s.starts_with("Optional[") && s.ends_with(']') => {
            let inner = &s[9..s.len() - 1];
            WitType::Option(Box::new(parse_python_type(inner)?))
        }

        s if s.starts_with("gridmesh.Tensor[") && s.ends_with(']') => {
            let inner = &s[16..s.len() - 1];
            WitType::Tensor(Box::new(parse_python_type(inner)?))
        }

        s if s.starts_with("Tensor[") && s.ends_with(']') => {
            let inner = &s[7..s.len() - 1];
            WitType::Tensor(Box::new(parse_python_type(inner)?))
        }

        s if s.starts_with("tuple[") && s.ends_with(']') => {
            let inner = &s[6..s.len() - 1];
            let parts: Result<Vec<_>, _> = inner
                .split(',')
                .map(|p| parse_python_type(p.trim()))
                .collect();
            WitType::Tuple(parts?)
        }

        _ => WitType::Custom(s.to_string()),
    })
}

pub fn parse_rust_params(s: &str) -> Result<Vec<Param>, ParseError> {
    let mut params = Vec::new();

    if s.trim().is_empty() {
        return Ok(params);
    }

    // Handle &self, &mut self
    let s = s
        .trim_start_matches("&mut self,")
        .trim_start_matches("&self,")
        .trim_start_matches("mut self,")
        .trim_start_matches("self,")
        .trim();

    if s.is_empty() {
        return Ok(params);
    }

    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // name: Type
        if let Some(idx) = part.find(':') {
            let name = part[..idx].trim().trim_start_matches("mut ");
            let ty_str = part[idx + 1..].trim();

            params.push(Param {
                name: name.to_string(),
                ty: parse_rust_type(ty_str)?,
                default: None,
            });
        }
    }

    Ok(params)
}

pub fn parse_rust_type(s: &str) -> Result<WitType, ParseError> {
    let s = s.trim();

    Ok(match s {
        "()" => WitType::Unit,
        "bool" => WitType::Bool,
        "i32" => WitType::S32,
        "i64" => WitType::S64,
        "u8" => WitType::U8,
        "u32" => WitType::U32,
        "u64" => WitType::U64,
        "f32" => WitType::F32,
        "f64" => WitType::F64,
        "String" | "&str" | "&String" => WitType::String,

        s if s.starts_with("Vec<") && s.ends_with('>') => {
            let inner = &s[4..s.len() - 1];
            WitType::List(Box::new(parse_rust_type(inner)?))
        }

        s if s.starts_with("&[") && s.ends_with(']') => {
            let inner = &s[2..s.len() - 1];
            WitType::List(Box::new(parse_rust_type(inner)?))
        }

        s if s.starts_with("Option<") && s.ends_with('>') => {
            let inner = &s[7..s.len() - 1];
            WitType::Option(Box::new(parse_rust_type(inner)?))
        }

        s if s.starts_with("Tensor<") && s.ends_with('>') => {
            let inner = &s[7..s.len() - 1];
            WitType::Tensor(Box::new(parse_rust_type(inner)?))
        }

        s if s.starts_with("gridmesh::Tensor<") && s.ends_with('>') => {
            let inner = &s[17..s.len() - 1]; // gridmesh::Tensor< is 17 chars
            WitType::Tensor(Box::new(parse_rust_type(inner)?))
        }

        s if s.starts_with("Result<") && s.ends_with('>') => {
            let inner = &s[7..s.len() - 1];
            if let Some(comma) = inner.find(',') {
                let ok = parse_rust_type(inner[..comma].trim())?;
                let err = parse_rust_type(inner[comma + 1..].trim())?;
                WitType::Result(Box::new(ok), Box::new(err))
            } else {
                WitType::Result(Box::new(parse_rust_type(inner)?), Box::new(WitType::String))
            }
        }

        s if s.starts_with('[') && s.contains(';') && s.ends_with(']') => {
            // [u8; 32]
            let inner = &s[1..s.len() - 1];
            let parts: Vec<&str> = inner.split(';').collect();
            if parts.len() == 2 {
                let elem = parse_rust_type(parts[0].trim())?;
                let size: usize = parts[1].trim().parse().unwrap_or(0);
                WitType::Array(Box::new(elem), size)
            } else {
                WitType::Custom(s.to_string())
            }
        }

        s if s.starts_with('(') && s.ends_with(')') => {
            let inner = &s[1..s.len() - 1];
            let parts: Result<Vec<_>, _> = inner
                .split(',')
                .map(|p| parse_rust_type(p.trim()))
                .collect();
            WitType::Tuple(parts?)
        }

        _ => WitType::Custom(s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let source = r#"
#[py]
def hello(name: str) -> str:
    return f"Hello, {name}!"

#[rs]
fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[py:fast]
def compute(x: float, y: float) -> float:
    return x * x + y * y
"#;

        let parsed = parse_poly(source).unwrap();
        assert_eq!(parsed.blocks.len(), 3);

        assert_eq!(parsed.blocks[0].lang_tag, "py");
        assert!(parsed.blocks[0].code.contains("def hello"));

        assert_eq!(parsed.blocks[1].lang_tag, "rs");
        assert!(parsed.blocks[1].code.contains("fn add"));

        assert_eq!(parsed.blocks[2].lang_tag, "py");
        assert!(parsed.blocks[2].code.contains("def compute"));
    }
}
