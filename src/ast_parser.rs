//! AST-based parser for .poly files using nom parser combinators
//! Replaces regex-based parsing for better stability and error handling

use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while, take_while1},
    character::complete::{char, line_ending, multispace0, multispace1, space0},
    combinator::{map, opt, recognize},
    sequence::{delimited, pair, preceded},
    IResult,
};

use crate::interface::parser::InterfaceItem;
use std::collections::HashMap;

/// Import statement in a .poly file
#[derive(Debug, Clone)]
pub struct Import {
    pub items: Vec<String>,
    pub path: String,
}

/// A code block in a .poly file
#[derive(Debug, Clone)]
pub struct CodeBlock {
    pub lang_tag: String,
    pub code: String,
    pub options: HashMap<String, String>,
    pub start_line: usize,
    /// Line where the actual code starts (after header and any blank lines)
    pub code_start_line: usize,
}

/// Complete parsed .poly file
#[derive(Debug, Default)]
pub struct ParsedFile {
    pub blocks: Vec<CodeBlock>,
    pub interfaces: Vec<InterfaceItem>,
    pub imports: Vec<Import>,
    pub signatures: Vec<crate::types::FunctionSig>,
}

/// Parse error with location info
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

// ============ Nom Parsers ============

/// Parse whitespace and comments (lines starting with //)
#[allow(dead_code)]
fn ws_and_comments(input: &str) -> IResult<&str, ()> {
    let (input, _) = multispace0(input)?;
    Ok((input, ()))
}

/// Parse an identifier: [a-zA-Z_][a-zA-Z0-9_]*
fn identifier(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        take_while1(|c: char| c.is_alphabetic() || c == '_'),
        take_while(|c: char| c.is_alphanumeric() || c == '_'),
    ))(input)
}

/// Parse a quoted string: "..."
fn quoted_string(input: &str) -> IResult<&str, &str> {
    delimited(char('"'), take_until("\""), char('"'))(input)
}

/// Parse import statement: use X from "path" or use * from "path" or use { a, b } from "path"
fn parse_import(input: &str) -> IResult<&str, Import> {
    let (input, _) = tag("use")(input)?;
    let (input, _) = multispace1(input)?;

    // Parse items: *, identifier, or { list }
    let (input, items) = alt((
        // use * from
        map(char('*'), |_| vec![]),
        // use { foo, bar } from
        map(
            delimited(
                pair(char('{'), multispace0),
                take_until("}"),
                pair(multispace0, char('}')),
            ),
            |s: &str| s.split(',').map(|s| s.trim().to_string()).collect(),
        ),
        // use foo from
        map(identifier, |s| vec![s.to_string()]),
    ))(input)?;

    let (input, _) = multispace1(input)?;
    let (input, _) = tag("from")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, path) = quoted_string(input)?;
    let (input, _) = opt(line_ending)(input)?;

    Ok((
        input,
        Import {
            items,
            path: path.to_string(),
        },
    ))
}

/// Parse block header: #[rust], #[python], #[interface], #[main], #[rust:option]
fn parse_block_header(input: &str) -> IResult<&str, (String, HashMap<String, String>)> {
    let (input, _) = char('#')(input)?;
    let (input, _) = char('[')(input)?;

    // Parse known tags only - prevents matching Rust attributes like #[no_mangle]
    let (input, tag_name) = alt((
        tag("interface"),
        tag("rust"),
        tag("rs"),
        tag("python"),
        tag("py"),
        tag("main"),
    ))(input)?;

    // Parse optional :options
    let (input, options) = opt(preceded(char(':'), identifier))(input)?;

    let (input, _) = char(']')(input)?;
    let (input, _) = space0(input)?;
    let (input, _) = opt(line_ending)(input)?;

    let mut opts = HashMap::new();
    if let Some(opt_str) = options {
        opts.insert(opt_str.to_string(), "true".to_string());
    }

    Ok((input, (tag_name.to_string(), opts)))
}

/// Find the content of a block (everything until next #[...] block header or EOF)
fn block_content<'a>(input: &'a str, _source: &'a str) -> (&'a str, &'a str) {
    // Look for next block header
    let block_pattern = "\n#[";

    if let Some(pos) = input.find(block_pattern) {
        let content = &input[..pos];
        let remaining = &input[pos + 1..]; // Skip the newline
        (remaining, content)
    } else {
        // Rest of file
        ("", input)
    }
}

/// Parse an entire .poly file
pub fn parse_poly_ast(source: &str) -> Result<ParsedFile, ParseError> {
    let mut parsed = ParsedFile::default();
    let mut remaining = source;
    let mut line_num = 1;

    loop {
        // Skip whitespace
        let trimmed = remaining.trim_start();
        if trimmed.is_empty() {
            break;
        }

        // Update line count
        let skipped = remaining.len() - trimmed.len();
        line_num += remaining[..skipped].matches('\n').count();
        remaining = trimmed;

        // Try to parse import
        if remaining.starts_with("use ") {
            match parse_import(remaining) {
                Ok((rest, import)) => {
                    parsed.imports.push(import);
                    remaining = rest;
                    continue;
                }
                Err(_) => {
                    // Skip this line
                    if let Some(pos) = remaining.find('\n') {
                        remaining = &remaining[pos + 1..];
                    } else {
                        break;
                    }
                    line_num += 1;
                    continue;
                }
            }
        }

        // Try to parse block header
        if remaining.starts_with("#[") {
            match parse_block_header(remaining) {
                Ok((rest, (tag_name, options))) => {
                    // Find content until next block or EOF
                    let (next_remaining, raw_content) = block_content(rest, source);

                    // Calculate code_start_line: header + 1, plus any leading blank lines that get trimmed
                    let leading_newlines = raw_content.chars().take_while(|c| *c == '\n' || *c == '\r').filter(|c| *c == '\n').count();
                    let code_start_line = line_num + 1 + leading_newlines;

                    let content = raw_content.trim().to_string();

                    // Handle interface blocks specially
                    if tag_name == "interface" {
                        if let Ok(interfaces) = crate::interface::parser::parse_interface(&content)
                        {
                            parsed.interfaces.extend(interfaces);
                        }
                    } else {
                        parsed.blocks.push(CodeBlock {
                            lang_tag: tag_name,
                            code: content,
                            options,
                            start_line: line_num,
                            code_start_line,
                        });
                    }

                    remaining = next_remaining;
                    continue;
                }
                Err(_) => {
                    // Not a valid block header, skip line
                    if let Some(pos) = remaining.find('\n') {
                        remaining = &remaining[pos + 1..];
                    } else {
                        break;
                    }
                    line_num += 1;
                    continue;
                }
            }
        }

        // Skip unknown content
        if let Some(pos) = remaining.find('\n') {
            remaining = &remaining[pos + 1..];
            line_num += 1;
        } else {
            break;
        }
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_import_star() {
        let (_, import) = parse_import(r#"use * from "./geometry.poly""#).unwrap();
        assert!(import.items.is_empty());
        assert_eq!(import.path, "./geometry.poly");
    }

    #[test]
    fn test_parse_import_single() {
        let (_, import) = parse_import(r#"use foo from "./utils.poly""#).unwrap();
        assert_eq!(import.items, vec!["foo".to_string()]);
        assert_eq!(import.path, "./utils.poly");
    }

    #[test]
    fn test_parse_import_multi() {
        let (_, import) = parse_import(r#"use { foo, bar } from "./utils.poly""#).unwrap();
        assert_eq!(import.items, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_parse_block_header() {
        let (_, (tag, _)) = parse_block_header("#[rust]\n").unwrap();
        assert_eq!(tag, "rust");

        let (_, (tag, opts)) = parse_block_header("#[python:fast]\n").unwrap();
        assert_eq!(tag, "python");
        assert!(opts.contains_key("fast"));
    }

    #[test]
    fn test_parse_full_file() {
        let source = r#"
use * from "./geometry.poly"

#[interface]
fn greet(name: String) -> String

#[rust]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

#[main]
fn main() {
    println!("{}", greet("World".to_string()));
}
"#;

        let parsed = parse_poly_ast(source).unwrap();
        assert_eq!(parsed.imports.len(), 1);
        assert_eq!(parsed.blocks.len(), 2); // rust + main
        assert!(!parsed.interfaces.is_empty());
    }
}
