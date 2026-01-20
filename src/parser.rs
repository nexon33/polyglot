use crate::interface::parser::InterfaceItem;
use crate::types::{FunctionSig, Param, WitType};
use regex::Regex;

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum TypeRef {
    Primitive(WitType),
    Named(String),
}

#[derive(Debug, Default)]
pub struct ParsedFile {
    pub blocks: Vec<CodeBlock>,
    pub signatures: Vec<FunctionSig>,
    pub interfaces: Vec<InterfaceItem>,
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

    // Regex to find polyglot block headers: #[rust], #[python], #[interface], #[main], etc.
    // Only matches known polyglot tags, not Rust attributes like #[no_mangle]
    let re = Regex::new(r"(?m)^#\[(interface|rust|rs|python|py|main)(?::[a-zA-Z0-9_:]+)?\]\s*$").unwrap();

    let mut matches: Vec<_> = re.find_iter(source).collect();

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
                parsed.interfaces = interfaces;
            }
            continue; // Don't add interface as a code block
        }

        let mut options = HashMap::new();
        for opt in parts {
            options.insert(opt.to_string(), "true".to_string());
        }

        if lang_tag == "interface" {
            continue;
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

    Ok(parsed)
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
