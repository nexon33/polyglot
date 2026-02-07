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
    /// Line where the actual code starts (after header and any blank lines)
    /// This is what LSP should use for line mapping, not start_line + 1
    pub code_start_line: usize,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
}

/// Find the matching closing brace for an opening brace at position `open_pos`.
/// Returns the content between braces and the position after the closing brace.
/// Handles nested braces, strings, comments, template literals, and character literals.
fn find_matching_brace(source: &str, open_pos: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    if open_pos >= bytes.len() || bytes[open_pos] != b'{' {
        return None;
    }

    let mut depth = 1;
    let mut pos = open_pos + 1;
    let mut in_double_string = false;  // Inside "..."
    let mut in_single_string = false;  // Inside '...'
    let mut in_template = false;       // Inside `...` (JS template literal)
    let mut template_depth = 0;        // For nested ${} in templates
    let mut escape_next = false;
    let mut in_triple_double = false;  // Inside """..."""
    let mut in_triple_single = false;  // Inside '''...'''
    let mut in_line_comment = false;   // Inside // comment
    let mut in_block_comment = false;  // Inside /* comment */
    let mut brace_stack: Vec<usize> = vec![open_pos]; // Track position of unmatched open braces
    let mut open_count: usize = 0;
    let mut close_count: usize = 0;

    while pos < bytes.len() && depth > 0 {
        let c = bytes[pos];

        // Handle line comments - skip until newline
        if in_line_comment {
            if c == b'\n' {
                in_line_comment = false;
            }
            pos += 1;
            continue;
        }

        // Handle block comments - skip until */
        if in_block_comment {
            if c == b'*' && pos + 1 < bytes.len() && bytes[pos + 1] == b'/' {
                in_block_comment = false;
                pos += 2;
                continue;
            }
            pos += 1;
            continue;
        }

        if escape_next {
            escape_next = false;
            pos += 1;
            continue;
        }

        // Check for comments and regex literals (only when not in any string)
        if !in_double_string && !in_single_string && !in_template && !in_triple_double && !in_triple_single {
            if c == b'/' && pos + 1 < bytes.len() {
                if bytes[pos + 1] == b'/' {
                    in_line_comment = true;
                    pos += 2;
                    continue;
                }
                if bytes[pos + 1] == b'*' {
                    in_block_comment = true;
                    pos += 2;
                    continue;
                }
                // Check for regex literal: / not followed by / or *
                // Only detect obvious cases: after = ( , : [ or at line start
                let prev_non_ws = {
                    let mut p = pos;
                    while p > open_pos + 1 {
                        p -= 1;
                        let pc = bytes[p];
                        if pc != b' ' && pc != b'\t' {
                            break;
                        }
                    }
                    if p > open_pos { bytes[p] } else { b'\n' }
                };
                // Very conservative: only after = ( , : [ or newline
                let is_regex_context = matches!(prev_non_ws, b'=' | b'(' | b',' | b':' | b'[' | b'\n' | b'\r');
                if is_regex_context {
                    // Skip regex literal: find closing / (handling escapes and char classes)
                    pos += 1; // skip opening /
                    let mut in_char_class = false;
                    while pos < bytes.len() {
                        let rc = bytes[pos];
                        if rc == b'\\' && pos + 1 < bytes.len() {
                            pos += 2; // skip escape
                            continue;
                        }
                        if rc == b'[' && !in_char_class {
                            in_char_class = true;
                        } else if rc == b']' && in_char_class {
                            in_char_class = false;
                        } else if rc == b'/' && !in_char_class {
                            pos += 1; // skip closing /
                            // Skip regex flags (g, i, m, s, u, y)
                            while pos < bytes.len() && matches!(bytes[pos], b'g' | b'i' | b'm' | b's' | b'u' | b'y') {
                                pos += 1;
                            }
                            break;
                        } else if rc == b'\n' {
                            // Regex can't span lines without escape - probably not a regex
                            break;
                        }
                        pos += 1;
                    }
                    continue;
                }
            }
        }

        // Check for triple quotes (Python docstrings/multiline strings)
        if !in_double_string && !in_single_string && !in_template {
            if pos + 2 < bytes.len() {
                if bytes[pos] == b'"' && bytes[pos + 1] == b'"' && bytes[pos + 2] == b'"' {
                    if in_triple_double {
                        in_triple_double = false;
                        pos += 3;
                        continue;
                    } else if !in_triple_single {
                        in_triple_double = true;
                        pos += 3;
                        continue;
                    }
                }
                if bytes[pos] == b'\'' && bytes[pos + 1] == b'\'' && bytes[pos + 2] == b'\'' {
                    if in_triple_single {
                        in_triple_single = false;
                        pos += 3;
                        continue;
                    } else if !in_triple_double {
                        in_triple_single = true;
                        pos += 3;
                        continue;
                    }
                }
            }
        }

        // Skip content inside triple-quoted strings
        if in_triple_double || in_triple_single {
            pos += 1;
            continue;
        }

        // Handle escape sequences inside strings and templates
        if c == b'\\' && (in_double_string || in_single_string || in_template) {
            escape_next = true;
            pos += 1;
            continue;
        }

        // Handle JS template literals (backticks)
        if c == b'`' && !in_double_string && !in_single_string {
            in_template = !in_template;
            if !in_template {
                template_depth = 0;
            }
            pos += 1;
            continue;
        }

        // Handle ${} inside template literals
        if in_template && c == b'$' && pos + 1 < bytes.len() && bytes[pos + 1] == b'{' {
            template_depth += 1;
            pos += 2;
            continue;
        }

        // Track braces inside template ${} expressions
        // Braces inside ${} are real code braces and should affect main depth
        if in_template && template_depth > 0 {
            if c == b'{' {
                template_depth += 1;  // Track for ${} nesting
                depth += 1;           // Also track main depth
                open_count += 1;
                brace_stack.push(pos);
            } else if c == b'}' {
                template_depth -= 1;
                if template_depth > 0 {
                    // This closes a nested brace inside ${}, not the ${} itself
                    depth -= 1;
                    close_count += 1;
                    brace_stack.pop();
                }
                // When template_depth hits 0, we just closed the ${}, no depth change
            }
            pos += 1;
            continue;
        }

        // Skip non-brace content inside templates (outside ${})
        if in_template {
            pos += 1;
            continue;
        }

        // Handle Rust raw strings: r"...", r#"..."#, br"...", etc.
        // These can contain quotes and should be skipped as a unit
        if (c == b'r' || c == b'b') && !in_double_string && !in_single_string && !in_template {
            let mut raw_start = pos;
            
            // Skip optional 'b' prefix
            if bytes[raw_start] == b'b' && raw_start + 1 < bytes.len() && bytes[raw_start + 1] == b'r' {
                raw_start += 1;
            }
            
            // Check for 'r' followed by optional '#'s and '"'
            if raw_start < bytes.len() && bytes[raw_start] == b'r' {
                let mut hash_count = 0;
                let mut scan = raw_start + 1;
                
                // Count leading '#'s
                while scan < bytes.len() && bytes[scan] == b'#' {
                    hash_count += 1;
                    scan += 1;
                }
                
                // Must be followed by '"'
                if scan < bytes.len() && bytes[scan] == b'"' {
                    scan += 1; // Skip opening quote
                    
                    // Scan for closing: "###...### (same number of #'s)
                    'raw_scan: while scan < bytes.len() {
                        if bytes[scan] == b'"' {
                            // Check for matching trailing #'s
                            let mut trailing = 0;
                            while scan + 1 + trailing < bytes.len() && 
                                  bytes[scan + 1 + trailing] == b'#' && 
                                  trailing < hash_count {
                                trailing += 1;
                            }
                            if trailing == hash_count {
                                // Found closing sequence
                                pos = scan + 1 + hash_count;
                                break 'raw_scan;
                            }
                        }
                        scan += 1;
                    }
                    if scan >= bytes.len() {
                        pos = scan; // Unclosed raw string, move to end
                    }
                    continue;
                }
            }
        }

        // Track double-quoted strings
        if c == b'"' && !in_single_string {
            in_double_string = !in_double_string;
            pos += 1;
            continue;
        }

        // Track single-quoted strings (JS/Python) and Rust char literals
        // IMPORTANT: Distinguish from Rust lifetimes like 'a, 'static, '_
        if c == b'\'' && !in_double_string && !in_template {
            if in_single_string {
                // Closing a single-quoted string
                in_single_string = false;
                pos += 1;
                continue;
            }
            
            // Check if this is a Rust lifetime (not a char literal or string)
            // Lifetimes: 'a, 'static, '_ followed by non-quote
            // Char literals: 'x', '\n', '\''
            if pos + 1 < bytes.len() {
                let next = bytes[pos + 1];
                
                // Check for Rust lifetime pattern: 'identifier or '_
                if next.is_ascii_lowercase() || next == b'_' {
                    // Look ahead to see if this is 'x' (char) or 'ident (lifetime)
                    let lookahead = pos + 2;
                    
                    // If immediately followed by ', it's a char literal like 'a'
                    if lookahead < bytes.len() && bytes[lookahead] == b'\'' {
                        // It's a char literal: 'x'
                        pos = lookahead + 1; // Skip past closing quote
                        continue;
                    }
                    
                    // NOT followed by ' means it's a lifetime (even single-letter like 'a in <'a>)
                    // Just skip the ' and let the identifier be scanned normally
                    // This handles: 'a, 'b, 'static, '_, 'lifetime, etc.
                    pos += 1;
                    continue;
                }
                
                // Check for escaped char literal: '\n', '\t', '\\'
                if next == b'\\' && pos + 3 < bytes.len() && bytes[pos + 3] == b'\'' {
                    // Escaped char literal like '\n' - skip the whole thing
                    pos += 4;
                    continue;
                }
                
                // Check for '\'' (escaped quote char)
                if next == b'\\' && pos + 4 < bytes.len() && bytes[pos + 2] == b'\'' && bytes[pos + 3] == b'\'' {
                    // This is '\'' - escaped quote character
                    pos += 4;
                    continue;
                }
            }
            
            // Default: treat as start of single-quoted string (JS/Python style)
            in_single_string = true;
            pos += 1;
            continue;
        }

        // Track braces only when outside strings
        if !in_double_string && !in_single_string {
            if c == b'{' {
                depth += 1;
                open_count += 1;
                brace_stack.push(pos);
            } else if c == b'}' {
                depth -= 1;
                close_count += 1;
                brace_stack.pop();
            }
        }

        pos += 1;
    }

    if depth == 0 {
        let content = &source[open_pos + 1..pos - 1];
        Some((content.to_string(), pos))
    } else {
        eprintln!("  → depth={}, opens={}, closes={} (diff={})",
            depth, open_count, close_count, open_count as i64 - close_count as i64);
        eprintln!("  → in_double={}, in_template={}, in_line_comment={}", 
            in_double_string, in_template, in_line_comment);
        // Show unmatched brace positions
        for brace_pos in brace_stack.iter().take(5) {
            let line = source[..=*brace_pos].matches('\n').count() + 1;
            let start = brace_pos.saturating_sub(20);
            // Find valid UTF-8 boundary
            let mut safe_start = start;
            while safe_start > 0 && !source.is_char_boundary(safe_start) {
                safe_start -= 1;
            }
            let end = (*brace_pos + 40).min(source.len());
            let mut safe_end = end;
            while safe_end < source.len() && !source.is_char_boundary(safe_end) {
                safe_end += 1;
            }
            let context = &source[safe_start..safe_end];
            eprintln!("  → Unmatched {{ at line {}: {:?}", line, context.replace('\n', "↵"));
        }
        None
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Parse error at line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

pub fn parse_poly(source: &str) -> Result<ParsedFile, ParseError> {
    // ═══════════════════════════════════════════════════════════════════════
    // Phase 24: Universal Syntax Normalization (per-block, post-parse)
    // ═══════════════════════════════════════════════════════════════════════
    // Normalization is now applied PER-BLOCK after parsing, only to Rust/Python
    // blocks. JS/HTML/CSS/GPU blocks are left untouched to preserve their
    // native syntax (template literals, this., arrow functions, etc).
    let source = source;

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
    // Supported: rust/rs, python/py, typescript/ts, javascript/js, interface, types, main, gpu, wgsl, jsx, html, rscss, css, test, doc
    // Static/config blocks (not compiled): md, toml, json, yaml, txt, cfg, ini, xml, env, dockerfile, makefile, sh, bat, ps1, sql
    // Note: Dependencies are declared in poly.toml, not inline blocks
    let re = Regex::new(r"(?m)^#\[(interface|types|rust|rs|python|py|typescript|ts|javascript|js|main|gpu|wgsl|jsx|html|rscss|css|test|doc|md|markdown|toml|json|yaml|yml|txt|cfg|ini|xml|env|dockerfile|makefile|sh|bat|ps1|sql)(?::[a-zA-Z0-9_:/\.\-]+)?(?::[a-zA-Z0-9_]+)?\]\s*$")
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

        // Calculate start line (header line)
        let start_line = source[..m.start()].lines().count();

        // Calculate code_start_line: header + 1, plus any leading blank lines that get trimmed
        let leading_newlines = tag_content.chars().take_while(|c| *c == '\n' || *c == '\r').filter(|c| *c == '\n').count();
        let code_start_line = start_line + 1 + leading_newlines;

        parsed.blocks.push(CodeBlock {
            lang_tag,
            code: tag_content.trim().to_string(),
            options,
            start_line,
            code_start_line,
        });
    }

    // === NEW SYNTAX: lang { } block-level and lang!{ } expression-level ===
    //
    // Block-level: `py { code }` or `rust { code }`
    // Expression-level: `py!{ expr }` or `rust!{ expr }` (reserved, not yet implemented)
    //
    // This mirrors Rust macro syntax where ! signals "something special happening"

    // Pattern for block-level: lang {
    let block_re = Regex::new(r"(?m)^(rust|rs|python|py|typescript|ts|javascript|js|wgsl|gpu)\s*\{").unwrap();

    // Pattern for expression-level: lang!{
    let expr_re = Regex::new(r"(?m)(rust|rs|python|py|typescript|ts|javascript|js|wgsl|gpu)!\s*\{").unwrap();

    // === UNIFIED SYNTAX: #[lang:path] { } - combines tag header with braces ===
    //
    // Examples:
    //   #[rust] { code }
    //   #[rust:src/main.rs] { code }
    //   #[python:utils.py] { code }
    //
    // The braces provide clear start/end markers, easier to parse and collapse
    // Static/config blocks (not compiled): md, toml, json, yaml, txt, cfg, ini, xml, env, dockerfile, makefile, sh, bat, ps1, sql
    let unified_re = Regex::new(
        r"(?m)^#\[(interface|types|rust|rs|python|py|typescript|ts|javascript|js|main|gpu|wgsl|jsx|html|rscss|css|test|doc|md|markdown|toml|json|yaml|yml|txt|cfg|ini|xml|env|dockerfile|makefile|sh|bat|ps1|sql)(?::([a-zA-Z0-9_:/\.\-]+))?\]\s*\{"
    ).unwrap();

    // Find unified syntax: #[lang] { ... } or #[lang:path] { ... }
    for cap in unified_re.captures_iter(source) {
        let m = cap.get(0).unwrap();
        let lang = cap.get(1).unwrap().as_str();
        let path = cap.get(2).map(|p| p.as_str().to_string());

        // Find matching closing brace
        if let Some((content, _end_pos)) = find_matching_brace(source, m.end() - 1) {
            eprintln!("📦 Block [{}] found: {} bytes", lang, content.len());
            let start_line = source[..m.start()].lines().count();

            // Normalize language tag
            let lang_tag = match lang {
                "rs" => "rust",
                "py" => "python",
                "ts" => "typescript",
                "js" => "javascript",
                _ => lang,
            }
            .to_string();

            // Phase 26: Parse interface/types blocks for trait definitions
            if lang_tag == "interface" || lang_tag == "types" {
                if let Ok(interfaces) = crate::interface::parser::parse_interface(&content) {
                    parsed.interfaces.extend(interfaces);
                }
            }

            let mut options = HashMap::new();
            if let Some(p) = path {
                options.insert("path".to_string(), p);
            }

            // Calculate code_start_line: header + 1, plus any leading blank lines that get trimmed
            let leading_newlines = content.chars().take_while(|c| *c == '\n' || *c == '\r').filter(|c| *c == '\n').count();
            let code_start_line = start_line + 1 + leading_newlines;

            parsed.blocks.push(CodeBlock {
                lang_tag,
                code: content.trim().to_string(),
                options,
                start_line,
                code_start_line,
            });
        } else {
            eprintln!("⚠️  Block [{}] FAILED brace matching at position {}", lang, m.end() - 1);
        }
    }

    // Find block-level syntax: lang { ... }
    for cap in block_re.captures_iter(source) {
        let m = cap.get(0).unwrap();
        let lang = cap.get(1).unwrap().as_str();

        // Find matching closing brace (handle nested braces)
        if let Some((content, _end_pos)) = find_matching_brace(source, m.end() - 1) {
            let start_line = source[..m.start()].lines().count();

            // Normalize language tag
            let lang_tag = match lang {
                "rs" => "rust",
                "py" => "python",
                "ts" => "typescript",
                "js" => "javascript",
                _ => lang,
            }
            .to_string();

            // Calculate code_start_line: header + 1, plus any leading blank lines that get trimmed
            let leading_newlines = content.chars().take_while(|c| *c == '\n' || *c == '\r').filter(|c| *c == '\n').count();
            let code_start_line = start_line + 1 + leading_newlines;

            parsed.blocks.push(CodeBlock {
                lang_tag,
                code: content.trim().to_string(),
                options: HashMap::new(),
                start_line,
                code_start_line,
            });
        }
    }

    // Find expression-level syntax: lang!{ ... } (reserved - not yet implemented)
    for cap in expr_re.captures_iter(source) {
        let m = cap.get(0).unwrap();
        let lang = cap.get(1).unwrap().as_str();
        let start_line = source[..m.start()].lines().count();

        // For now, just record these as warnings - syntax is reserved but not implemented
        eprintln!(
            "⚠️ Line {}: Expression syntax `{}!{{}}` is reserved but not yet implemented. Use block syntax `{} {{}}` for now.",
            start_line, lang, lang
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 24b: Per-block syntax normalization
    // ═══════════════════════════════════════════════════════════════════════
    // Only normalize Python blocks. Rust blocks are already valid Rust.
    // JS/HTML/CSS/GPU blocks keep their native syntax untouched.
    for block in &mut parsed.blocks {
        match block.lang_tag.as_str() {
            // Python blocks need full normalization (def→fn, indent→braces, etc.)
            "python" | "py" => {
                block.code = crate::syntax_aliases::normalize_all(&block.code);
            }
            // Rust/main blocks are already valid Rust - no normalization needed
            // JS, HTML, CSS, GPU, JSX, WGSL, test, doc, etc. → no normalization
            _ => {}
        }
    }

    // Auto-discover export/public functions from Rust/Python blocks
    scan_exported_functions(&mut parsed);

    Ok(parsed)
}

/// Scan code blocks for `export fn`, `public fn` (Rust) and `export def`, `public def` (Python)
fn scan_exported_functions(parsed: &mut ParsedFile) {
    use crate::interface::parser::{FunctionDecl, InterfaceItem, Visibility};
    use regex::Regex;

    // Rust patterns:
    // - export fn name(params) -> Type  => Export visibility
    // Only `export fn` creates interface functions (not `pub fn` which is internal visibility)
    // This prevents matching `pub fn new()` inside impl blocks
    let rust_export_re =
        Regex::new(r"export\s+fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^\{]+))?").unwrap();

    // Python: only `export def` creates interface functions
    let python_export_re =
        Regex::new(r"export\s+def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*(\w+))?").unwrap();

    for block in &parsed.blocks {
        let (patterns, is_rust): (Vec<(&Regex, Visibility)>, bool) = match block.lang_tag.as_str() {
            "rust" | "rs" => (
                vec![(&rust_export_re, Visibility::Export)],
                true,
            ),
            "python" | "py" => (
                vec![(&python_export_re, Visibility::Export)],
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
        // Phase 24: def is normalized to fn
        assert!(parsed.blocks[0].code.contains("fn hello") || parsed.blocks[0].code.contains("def hello"));

        assert_eq!(parsed.blocks[1].lang_tag, "rs");
        assert!(parsed.blocks[1].code.contains("fn add"));

        assert_eq!(parsed.blocks[2].lang_tag, "py");
        // Phase 24: def is normalized to fn
        assert!(parsed.blocks[2].code.contains("fn compute") || parsed.blocks[2].code.contains("def compute"));
    }
}
