//! Syntax Aliases - Universal syntax normalization
//!
//! Phase 24: Normalizes Python/Rust/C#/JS syntax variants to unified form.
//! "Chaos in. Order out."
//!
//! Accepts ALL syntax variants and normalizes them for the parser.

use regex::Regex;
use std::sync::LazyLock;

// ═══════════════════════════════════════════════════════════════════════════
// Source Location Tracking
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks character position mappings during normalization for error reporting.
/// Maps positions in normalized source back to original source.
#[derive(Debug, Clone, Default)]
pub struct SourceLocationMap {
    /// Maps (normalized_offset, original_offset, length)
    mappings: Vec<(usize, usize, usize)>,
    /// Original source length
    pub original_len: usize,
}

impl SourceLocationMap {
    pub fn new(original_len: usize) -> Self {
        Self {
            mappings: Vec::new(),
            original_len,
        }
    }

    /// Record a mapping: normalized position came from original position
    pub fn add_mapping(&mut self, normalized: usize, original: usize, len: usize) {
        self.mappings.push((normalized, original, len));
    }

    /// Lookup original position from normalized position
    pub fn lookup(&self, normalized: usize) -> usize {
        // Find the mapping that contains this offset
        for &(norm_start, orig_start, len) in self.mappings.iter().rev() {
            if normalized >= norm_start && normalized < norm_start + len {
                let offset = normalized - norm_start;
                return orig_start + offset;
            }
        }
        // Default: assume 1:1 mapping
        normalized.min(self.original_len.saturating_sub(1))
    }
}

/// Normalize all syntax variants in source code
///
/// Phase 24: Order of operations is CRITICAL:
/// 1. Decorators first (@ could conflict with f-strings)
/// 2. Keywords (None, True, False, elif)
/// 3. Operators (and, or, not, is)
/// 4. Strings (f-strings)
/// 5. Class syntax (prepare class declarations)
/// 6. Function syntax (def -> fn)
/// 7. Self/this (this -> self)
/// 8. Arrow functions (JS => to Rust ||)
/// 9. Indentation to braces (MUST BE LAST)
pub fn normalize_all(source: &str) -> String {
    let mut result = source.to_string();

    // Phase 1: Basic syntax normalization
    result = normalize_decorators(&result);    // @ -> #[]
    result = normalize_keywords(&result);      // None, True, False, elif
    result = normalize_operators(&result);     // and, or, not, is
    result = normalize_strings(&result);       // f-strings -> template literals

    // Phase 2: Structural normalization
    result = normalize_class_syntax(&result);      // Class declarations
    result = normalize_function_syntax(&result);   // def -> fn, **kwargs
    result = normalize_self_this(&result);         // this -> self
    result = normalize_arrow_functions(&result);   // () => to ||

    // Phase 3: Indentation to braces (MUST BE LAST - adds braces)
    result = infer_braces_from_indent(&result);

    result
}

/// Normalize all syntax variants with source location tracking
///
/// Returns (normalized_source, location_map) for error reporting
pub fn normalize_all_with_map(source: &str) -> (String, SourceLocationMap) {
    let loc_map = SourceLocationMap::new(source.len());
    let result = normalize_all(source);
    // Note: Full location tracking would require updating each function
    // For now, we use a simple 1:1 mapping approximation
    (result, loc_map)
}

/// Normalize keyword aliases to Rust-compatible forms
///
/// | Input | Output |
/// |-------|--------|
/// | null/nil | None | (Rust uses None for optional values)
/// | None | None | (preserved - already Rust-compatible)
/// | True | true |
/// | False | false |
/// | elif | else if |
pub fn normalize_keywords(source: &str) -> String {
    static REPLACEMENTS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| vec![
        // JS/C# null → Rust None
        (Regex::new(r"\bnull\b").unwrap(), "None"),
        // Ruby/Lua nil → Rust None
        (Regex::new(r"\bnil\b").unwrap(), "None"),
        // Python booleans → lowercase (Rust uses lowercase)
        (Regex::new(r"\bTrue\b").unwrap(), "true"),
        (Regex::new(r"\bFalse\b").unwrap(), "false"),
        // elif → else if
        (Regex::new(r"\belif\b").unwrap(), "else if"),
    ]);

    let mut result = source.to_string();

    for (re, replacement) in REPLACEMENTS.iter() {
        result = re.replace_all(&result, *replacement).to_string();
    }

    result
}

/// Normalize operator aliases
///
/// | Input | Output |
/// |-------|--------|
/// | and | && |
/// | or | \|\| |
/// | not | ! |
/// | is | == |
/// | is not | != |
pub fn normalize_operators(source: &str) -> String {
    static REPLACEMENTS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| vec![
        // Order matters: "is not" before "is", "not" careful placement
        // "is not" → != (must be before "is")
        (Regex::new(r"\bis\s+not\b").unwrap(), "!="),
        // "is" → == (identity check, simplified)
        (Regex::new(r"\bis\b").unwrap(), "=="),
        // "and" → && (surrounded by spaces for safety)
        (Regex::new(r"\band\b").unwrap(), "&&"),
        // "or" → ||
        (Regex::new(r"\bor\b").unwrap(), "||"),
        // "not" → ! (careful: not as prefix)
        // Only replace "not " at word boundary, followed by space or (
        (Regex::new(r"\bnot\s+").unwrap(), "!"),
    ]);

    let mut result = source.to_string();

    for (re, replacement) in REPLACEMENTS.iter() {
        result = re.replace_all(&result, *replacement).to_string();
    }

    result
}

/// Normalize string literals
///
/// Python f-strings and JS template literals → Rust format!() macro
///
/// f"hello {x}" → format!("hello {x}")
/// f'hello {x}' → format!("hello {x}")
/// `hello ${x}` → format!("hello {x}")
///
/// Note: Uses Rust 1.58+ captured identifiers syntax
pub fn normalize_strings(source: &str) -> String {
    static FSTRING_DOUBLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"f"([^"]*)""#).unwrap());
    static FSTRING_SINGLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"f'([^']*)'").unwrap());
    static TEMPLATE_LITERAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`([^`]*)`").unwrap());

    let mut result = source.to_string();

    // f-string with double quotes: f"...{expr}..." → format!("...{expr}...")
    result = FSTRING_DOUBLE
        .replace_all(&result, |caps: &regex::Captures| {
            let content = &caps[1];
            format!("format!(\"{}\")", content)
        })
        .to_string();

    // f-string with single quotes: f'...{expr}...' → format!("...{expr}...")
    result = FSTRING_SINGLE
        .replace_all(&result, |caps: &regex::Captures| {
            let content = &caps[1];
            format!("format!(\"{}\")", content)
        })
        .to_string();

    // JavaScript template literals: `...${expr}...` → format!("...{expr}...")
    result = TEMPLATE_LITERAL
        .replace_all(&result, |caps: &regex::Captures| {
            let content = &caps[1];
            // Convert ${expr} to {expr} for Rust format!
            let converted = content.replace("${", "{");
            format!("format!(\"{}\")", converted)
        })
        .to_string();

    result
}

/// Normalize decorators
///
/// @decorator → #[decorator]
/// @decorator(args) → #[decorator(args)]
pub fn normalize_decorators(source: &str) -> String {
    static DECORATOR_WITH_ARGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@(\w+)\(([^)]*)\)").unwrap());
    static DECORATOR_SIMPLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@(\w+)").unwrap());

    let mut result = source.to_string();

    // @decorator(args) → #[decorator(args)]
    // Must be done first to avoid double-processing
    result = DECORATOR_WITH_ARGS
        .replace_all(&result, "#[$1($2)]")
        .to_string();

    // @decorator (no args) → #[decorator]
    // Only match @ followed by word that's NOT already converted (not followed by opening paren)
    // Since we can't use look-ahead, we handle this differently:
    // Match @word at word boundary, then check if next char is NOT (
    result = DECORATOR_SIMPLE
        .replace_all(&result, |caps: &regex::Captures| {
            let name = &caps[1];
            // Check if already converted (starts with #[)
            if name.starts_with('#') {
                caps[0].to_string()
            } else {
                format!("#[{}]", name)
            }
        })
        .to_string();

    // Clean up double brackets from decorator with args: #[#[foo(bar)]] -> #[foo(bar)]
    result = result.replace("#[#[", "#[");

    result
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 24: Additional Normalizations
// ═══════════════════════════════════════════════════════════════════════════

/// Normalize class definition syntax
///
/// Python: `class Foo:` or `class Bar(Base):`
/// -> Unified: preserved (braces added by indent inference)
pub fn normalize_class_syntax(source: &str) -> String {
    // For now, class syntax is preserved as-is
    // The brace inference will handle adding braces after colons
    // Future: could convert Python classes to Rust struct + impl
    source.to_string()
}

/// Normalize function definition syntax
///
/// Python: `def foo(x):` or `async def bar():`
/// -> Rust: `fn foo(x):` or `async fn bar():`
///
/// Also handles: `**kwargs` -> `__kwargs_name`
pub fn normalize_function_syntax(source: &str) -> String {
    static ASYNC_DEF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\basync\s+def\b").unwrap());
    static DEF_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bdef\b").unwrap());
    static KWARGS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\*\*(\w+)").unwrap());

    let mut result = source.to_string();

    // Only normalize `def` if this looks like Python-style code
    // (to avoid breaking legitimate uses of "def" in other contexts)
    if is_python_style_code(&result) {
        // async def -> async fn (must be before def -> fn)
        result = ASYNC_DEF.replace_all(&result, "async fn").to_string();

        // def -> fn
        result = DEF_RE.replace_all(&result, "fn").to_string();
    }

    // Handle **kwargs -> __kwargs_name (for any context)
    result = KWARGS_RE
        .replace_all(&result, "__kwargs_$1: std::collections::HashMap<String, serde_json::Value>")
        .to_string();

    result
}

/// Check if source appears to use Python-style syntax
fn is_python_style_code(source: &str) -> bool {
    // Heuristics:
    // 1. Has `def ` keyword
    // 2. Has lines ending with `:` (block openers)
    // 3. Uses `self` parameter

    let has_def = source.contains("def ");

    // Check for lines ending with colon (multiline mode)
    let has_colon_blocks = source.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.ends_with(':') && !trimmed.contains(": {")
    });

    let has_self = source.contains("self");

    // If it has def, it's Python-style (regardless of other markers)
    has_def || (has_self && has_colon_blocks)
}

/// Unify self/this references
///
/// In JS/C# style code: `this.x` -> `self.x`
/// Python `self` stays as-is (Rust native)
pub fn normalize_self_this(source: &str) -> String {
    static THIS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bthis\.").unwrap());

    let mut result = source.to_string();

    // If we see `this.` without `self.`, it's likely JS/C# style
    let has_this = source.contains("this.");
    let has_self = source.contains("self.");

    if has_this && !has_self {
        // Pure JS/C# style - normalize to Rust's self
        result = THIS_RE.replace_all(&result, "self.").to_string();
    } else if has_this && has_self {
        // Mixed style (like chaos.poly) - normalize this to self
        result = THIS_RE.replace_all(&result, "self.").to_string();
    }

    result
}

/// Normalize arrow functions (JS) to Rust closures
///
/// JS: `(x) => x * 2` or `x => x * 2`
/// -> Rust: `|x| x * 2`
///
/// JS: `(x, y) => { return x + y; }`
/// -> Rust: `|x, y| { return x + y; }`
///
/// IMPORTANT: Does NOT convert Rust match arm syntax like `Ok(l) => l`
/// We detect this by checking if `(...)` is preceded by a word character.
pub fn normalize_arrow_functions(source: &str) -> String {
    static MULTI_ARROW_BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|[^a-zA-Z0-9_])\(([^)]*)\)\s*=>\s*\{").unwrap());
    static MULTI_ARROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|[^a-zA-Z0-9_])\(([^)]*)\)\s*=>\s*").unwrap());
    static SINGLE_ARROW_BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\s)(\w+)\s*=>\s*\{").unwrap());
    static SINGLE_ARROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\s)(\w+)\s*=>\s*(\S)").unwrap());

    let mut result = source.to_string();

    // Multi-param arrow with parens and block: (a, b) => {
    // Must be done first to handle block case
    // Capture preceding char to check it's NOT a word char (would indicate Rust enum like Ok(l))
    result = MULTI_ARROW_BLOCK
        .replace_all(&result, |caps: &regex::Captures| {
            let prefix = &caps[1];
            let params = &caps[2];
            format!("{}|{}| {{", prefix, params)
        })
        .to_string();

    // Multi-param arrow with parens: (a, b) => expr (no block)
    // Capture preceding char to exclude Rust enum patterns like Ok(l) => l
    result = MULTI_ARROW
        .replace_all(&result, |caps: &regex::Captures| {
            let prefix = &caps[1];
            let params = &caps[2];
            // If params look like type params (contain ::, <, >), skip
            if params.contains("::") || params.contains('<') || params.contains('>') {
                return caps[0].to_string();
            }
            // If already converted (starts with |), skip
            if params.starts_with('|') {
                return caps[0].to_string();
            }
            format!("{}|{}| ", prefix, params)
        })
        .to_string();

    // Single-param arrow with block: x => {
    // Only match when preceded by whitespace to avoid matching Rust enum patterns
    result = SINGLE_ARROW_BLOCK
        .replace_all(&result, |caps: &regex::Captures| {
            let space = &caps[1];
            let param = &caps[2];
            // Skip Rust enum variants and common match patterns
            let skip_patterns = ["Ok", "Err", "Some", "None", "true", "false", "_"];
            if skip_patterns.iter().any(|p| param == *p) {
                return caps[0].to_string();
            }
            format!("{}|{}| {{", space, param)
        })
        .to_string();

    // Single-param arrow without parens: x => expr
    // Only match when preceded by whitespace and param doesn't look like Rust pattern
    result = SINGLE_ARROW
        .replace_all(&result, |caps: &regex::Captures| {
            let space = &caps[1];
            let param = &caps[2];
            let next_char = &caps[3];
            // If next char is {, it was already handled
            if next_char == "{" {
                return caps[0].to_string();
            }
            // Skip Rust enum variants and common match patterns
            let skip_patterns = ["Ok", "Err", "Some", "None", "true", "false", "_"];
            if skip_patterns.iter().any(|p| param == *p) {
                return caps[0].to_string();
            }
            format!("{}|{}| {}", space, param, next_char)
        })
        .to_string();

    result
}

/// Convert Python-style indentation to explicit braces
///
/// Input:  `def foo():\n    return 42`
/// Output: `def foo(): {\n    return 42\n}`
///
/// This is the most complex normalization and MUST run last.
pub fn infer_braces_from_indent(source: &str) -> String {
    // First check if we need to do anything
    if !uses_indentation_syntax(source) {
        return source.to_string();
    }

    let mut result = String::with_capacity(source.len() * 2);
    let mut indent_stack: Vec<usize> = vec![0]; // Stack of indentation levels
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Skip empty lines - preserve them
        if trimmed.is_empty() {
            result.push_str(line);
            result.push('\n');
            i += 1;
            continue;
        }

        // Skip comments - preserve them
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            result.push_str(line);
            result.push('\n');
            i += 1;
            continue;
        }

        let current_indent = count_leading_whitespace(line);
        let prev_indent = *indent_stack.last().unwrap_or(&0);

        // Handle dedentation - close braces
        while current_indent < prev_indent && indent_stack.len() > 1 {
            indent_stack.pop();
            let close_indent = *indent_stack.last().unwrap_or(&0);
            result.push_str(&" ".repeat(close_indent));
            result.push_str("}\n");
        }

        // Handle `pass` keyword - convert to empty block
        if trimmed == "pass" {
            result.push_str(&" ".repeat(current_indent));
            result.push_str("// pass\n");
            i += 1;
            continue;
        }

        // Check if this line already has a brace after colon
        let has_brace_after_colon = trimmed.ends_with(": {") || trimmed.ends_with(":{");

        // Check if line ends with colon (block opener in Python)
        let is_block_opener = is_block_opener_line(trimmed) && !has_brace_after_colon;

        if is_block_opener {
            // Add the line with opening brace
            result.push_str(line);
            result.push_str(" {\n");

            // Look ahead to determine next indent level
            if let Some(next_line) = lines.get(i + 1) {
                let next_trimmed = next_line.trim();
                if !next_trimmed.is_empty() && !next_trimmed.starts_with("//") && !next_trimmed.starts_with('#') {
                    let next_indent = count_leading_whitespace(next_line);
                    if next_indent > current_indent {
                        indent_stack.push(next_indent);
                    }
                }
            }
        } else {
            // Regular line - just add it
            result.push_str(line);
            result.push('\n');
        }

        i += 1;
    }

    // Close any remaining open braces at end of file
    while indent_stack.len() > 1 {
        indent_stack.pop();
        let indent = *indent_stack.last().unwrap_or(&0);
        result.push_str(&" ".repeat(indent));
        result.push_str("}\n");
    }

    result
}

/// Check if source uses Python-style indentation syntax (needs brace inference)
fn uses_indentation_syntax(source: &str) -> bool {
    // If source uses NEW-style #[lang] { } blocks, skip brace inference entirely
    // This prevents mangling content inside explicit braced blocks
    static UNIFIED_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(
        r"(?m)^#\[(interface|types|rust|rs|python|py|typescript|ts|javascript|js|main|gpu|wgsl|jsx|html|rscss|css|test|doc)(?::[a-zA-Z0-9_:/\.\-]+)?\]\s*\{"
    ).unwrap());

    if UNIFIED_BLOCK_RE.is_match(source) {
        // Source uses new-style braced blocks - no brace inference needed
        return false;
    }

    // Check if there are block openers (`:`) at end of line without following braces
    let lines: Vec<&str> = source.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // Check if this is a block opener without explicit braces
        if is_block_opener_line(trimmed) {
            // Check if there's NO brace after the colon
            if !trimmed.ends_with(": {") && !trimmed.ends_with(":{") {
                // Check if next non-empty line is indented
                for next_line in lines.iter().skip(i + 1) {
                    let next_trimmed = next_line.trim();
                    if !next_trimmed.is_empty() && !next_trimmed.starts_with("//") && !next_trimmed.starts_with('#') {
                        let current_indent = count_leading_whitespace(line);
                        let next_indent = count_leading_whitespace(next_line);
                        if next_indent > current_indent {
                            return true; // Found indentation-based block
                        }
                        break;
                    }
                }
            }
        }
    }

    false
}

/// Check if a line is a block opener (ends with `:` and starts with block keyword)
fn is_block_opener_line(line: &str) -> bool {
    let trimmed = line.trim();

    // Must end with colon
    if !trimmed.ends_with(':') {
        return false;
    }

    // Skip dictionary/type annotation patterns
    // e.g., `foo: int` or `"key": value`
    if trimmed.contains(": ") && !trimmed.ends_with("):") && !trimmed.contains("->") {
        // This might be a type annotation, not a block
        // But we need to check if it starts with a block keyword
    }

    // Block opener keywords
    let block_keywords = [
        "fn ", "def ", "class ", "if ", "elif ", "else:", "else",
        "for ", "while ", "with ", "try:", "try", "except", "finally:",
        "finally", "async fn", "async def", "match ", "impl ", "struct ",
        "enum ", "trait ", "mod ",
    ];

    let trimmed_start = trimmed.trim_start();
    for kw in &block_keywords {
        if trimmed_start.starts_with(kw) || trimmed_start == kw.trim_end_matches(' ').trim_end_matches(':') {
            return true;
        }
    }

    // Also check for function definitions with return types: `fn foo() -> Type:`
    if trimmed.contains("->") && trimmed.ends_with(':') {
        return true;
    }

    // Check for class inheritance: `class Foo(Bar):`
    if trimmed.starts_with("class ") && trimmed.contains('(') && trimmed.ends_with("):") {
        return true;
    }

    false
}

/// Count leading whitespace, normalizing tabs to 4 spaces
fn count_leading_whitespace(line: &str) -> usize {
    let mut count = 0;
    for c in line.chars() {
        match c {
            ' ' => count += 1,
            '\t' => count += 4,
            _ => break,
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyword_normalization() {
        // None stays as None (Rust-compatible)
        assert_eq!(normalize_keywords("x = None"), "x = None");
        // null → None (JS/C# to Rust)
        assert_eq!(normalize_keywords("x = null"), "x = None");
        // nil → None (Ruby/Lua to Rust)
        assert_eq!(normalize_keywords("x = nil"), "x = None");
        // Booleans normalized to lowercase
        assert_eq!(normalize_keywords("if True:"), "if true:");
        assert_eq!(normalize_keywords("while False:"), "while false:");
        // elif → else if
        assert_eq!(normalize_keywords("elif x:"), "else if x:");
    }

    #[test]
    fn test_operator_normalization() {
        assert_eq!(normalize_operators("a and b"), "a && b");
        assert_eq!(normalize_operators("a or b"), "a || b");
        assert_eq!(normalize_operators("not x"), "!x");
        // Note: 'is' becomes '==' (identity check simplified)
        assert_eq!(normalize_operators("x is y"), "x == y");
        assert_eq!(normalize_operators("x is not y"), "x != y");
    }

    #[test]
    fn test_string_normalization() {
        assert_eq!(normalize_strings(r#"f"hello {name}""#), r#"format!("hello {name}")"#);
        assert_eq!(normalize_strings("f'count: {n}'"), r#"format!("count: {n}")"#);
    }

    #[test]
    fn test_template_literal_normalization() {
        // JavaScript template literals convert to format!
        assert_eq!(normalize_strings(r#"`hello ${name}`"#), r#"format!("hello {name}")"#);
        assert_eq!(normalize_strings(r#"`Count: ${n}`"#), r#"format!("Count: {n}")"#);
    }

    #[test]
    fn test_decorator_normalization() {
        assert_eq!(normalize_decorators("@component"), "#[component]");
        assert_eq!(
            normalize_decorators("@route(\"/api\")"),
            "#[route(\"/api\")]"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 24 Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_function_syntax_def_to_fn() {
        let input = "def hello(name: str):\n    return name";
        let output = normalize_function_syntax(input);
        assert!(output.contains("fn hello"), "def should become fn");
    }

    #[test]
    fn test_function_syntax_async_def() {
        let input = "async def fetch(url):\n    return data";
        let output = normalize_function_syntax(input);
        assert!(output.contains("async fn fetch"), "async def should become async fn");
    }

    #[test]
    fn test_function_syntax_kwargs() {
        let input = "def foo(**kwargs):";
        let output = normalize_function_syntax(input);
        assert!(output.contains("__kwargs_kwargs"), "**kwargs should be converted");
    }

    #[test]
    fn test_self_this_unification() {
        let input = "this.state = 42";
        let output = normalize_self_this(input);
        assert_eq!(output, "self.state = 42");
    }

    #[test]
    fn test_self_this_mixed() {
        let input = "this.x = 1\nself.y = 2";
        let output = normalize_self_this(input);
        assert!(output.contains("self.x = 1"), "this should become self");
        assert!(output.contains("self.y = 2"), "self should stay self");
    }

    #[test]
    fn test_arrow_function_multi_param() {
        let input = "(x, y) => x + y";
        let output = normalize_arrow_functions(input);
        assert!(output.contains("|x, y|"), "arrow should become closure");
    }

    #[test]
    fn test_arrow_function_with_block() {
        let input = "(x) => { return x * 2; }";
        let output = normalize_arrow_functions(input);
        assert!(output.contains("|x|"), "arrow should become closure");
        assert!(output.contains("{"), "block should be preserved");
    }

    #[test]
    fn test_indent_to_braces_simple() {
        let input = "def foo():\n    return 42";
        let output = infer_braces_from_indent(input);
        assert!(output.contains("{"), "should have opening brace");
        assert!(output.contains("}"), "should have closing brace");
    }

    #[test]
    fn test_indent_to_braces_nested() {
        let input = "def foo():\n    if x:\n        return 1\n    return 0";
        let output = infer_braces_from_indent(input);
        // Should have 2 opening and 2 closing braces
        assert_eq!(output.matches('{').count(), 2, "should have 2 opening braces");
        assert_eq!(output.matches('}').count(), 2, "should have 2 closing braces");
    }

    #[test]
    fn test_indent_skips_explicit_braces() {
        let input = "fn foo(): {\n    return 42\n}";
        let output = infer_braces_from_indent(input);
        // Should not add extra braces
        assert_eq!(output.matches('{').count(), 1, "should not add extra braces");
    }

    #[test]
    fn test_normalize_all_integration() {
        let input = r#"
def hello(name):
    if name is None:
        return "anonymous"
    elif name and not empty:
        return f"Hello, {name}"
"#;
        let output = normalize_all(input);

        // Keywords normalized
        assert!(output.contains("None"), "None should stay None (Rust-compatible)");
        assert!(output.contains("else if"), "elif should become else if");

        // Operators normalized
        assert!(output.contains("=="), "is should become ==");
        assert!(output.contains("&&"), "and should become &&");
        assert!(output.contains("!empty"), "not should become !");

        // Function syntax normalized
        assert!(output.contains("fn hello"), "def should become fn");

        // Strings normalized
        assert!(output.contains("format!(\"Hello, {name}\")"), "f-string should become format!");
    }

    #[test]
    fn test_source_location_map() {
        let map = SourceLocationMap::new(100);
        // Default lookup should return the input (or clamped)
        assert_eq!(map.lookup(50), 50);
        assert_eq!(map.lookup(150), 99); // Clamped to original_len - 1
    }

    #[test]
    fn test_is_block_opener() {
        assert!(is_block_opener_line("def foo():"));
        assert!(is_block_opener_line("class Bar:"));
        assert!(is_block_opener_line("if x > 0:"));
        assert!(is_block_opener_line("for i in range(10):"));
        assert!(is_block_opener_line("async fn fetch() -> Result:"));

        // Should NOT be block openers
        assert!(!is_block_opener_line("x: int"));  // Type annotation
        assert!(!is_block_opener_line("return 42"));  // No colon
    }
}
