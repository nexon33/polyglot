//! Semantic token provider for Polyglot LSP
//!
//! Provides intelligent syntax highlighting that understands mixed-language
//! chaos syntax (Python, Rust, JavaScript, C# in the same file).

use tower_lsp::lsp_types::*;
use regex::Regex;

/// Token types for semantic highlighting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolyTokenType {
    Keyword,
    Function,
    Variable,
    Parameter,
    Type,
    String,
    Number,
    Comment,
    Operator,
    Decorator,
    SelfKeyword,
    Macro,
    Property,
    Namespace,
}

impl PolyTokenType {
    pub fn as_u32(self) -> u32 {
        match self {
            PolyTokenType::Keyword => 0,
            PolyTokenType::Function => 1,
            PolyTokenType::Variable => 2,
            PolyTokenType::Parameter => 3,
            PolyTokenType::Type => 4,
            PolyTokenType::String => 5,
            PolyTokenType::Number => 6,
            PolyTokenType::Comment => 7,
            PolyTokenType::Operator => 8,
            PolyTokenType::Decorator => 9,
            PolyTokenType::SelfKeyword => 10,
            PolyTokenType::Macro => 11,
            PolyTokenType::Property => 12,
            PolyTokenType::Namespace => 13,
        }
    }
}

/// Token modifiers for semantic highlighting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolyTokenModifiers(u32);

impl PolyTokenModifiers {
    pub const DECLARATION: u32 = 1 << 0;
    pub const DEFINITION: u32 = 1 << 1;
    pub const READONLY: u32 = 1 << 2;
    pub const ASYNC: u32 = 1 << 3;
    pub const STATIC: u32 = 1 << 4;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn set_declaration(mut self) -> Self {
        self.0 |= Self::DECLARATION;
        self
    }

    pub fn set_definition(mut self) -> Self {
        self.0 |= Self::DEFINITION;
        self
    }

    pub fn set_async(mut self) -> Self {
        self.0 |= Self::ASYNC;
        self
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Get the semantic token legend (types and modifiers)
pub fn get_legend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: vec![
            SemanticTokenType::KEYWORD,       // 0
            SemanticTokenType::FUNCTION,      // 1
            SemanticTokenType::VARIABLE,      // 2
            SemanticTokenType::PARAMETER,     // 3
            SemanticTokenType::TYPE,          // 4
            SemanticTokenType::STRING,        // 5
            SemanticTokenType::NUMBER,        // 6
            SemanticTokenType::COMMENT,       // 7
            SemanticTokenType::OPERATOR,      // 8
            SemanticTokenType::DECORATOR,     // 9
            SemanticTokenType::new("selfKeyword"),   // 10
            SemanticTokenType::MACRO,         // 11
            SemanticTokenType::PROPERTY,      // 12
            SemanticTokenType::NAMESPACE,     // 13
        ],
        token_modifiers: vec![
            SemanticTokenModifier::DECLARATION,  // 0
            SemanticTokenModifier::DEFINITION,   // 1
            SemanticTokenModifier::READONLY,     // 2
            SemanticTokenModifier::ASYNC,        // 3
            SemanticTokenModifier::STATIC,       // 4
        ],
    }
}

/// A single semantic token before encoding
#[derive(Debug, Clone)]
pub struct SemanticToken {
    pub line: u32,
    pub start_char: u32,
    pub length: u32,
    pub token_type: PolyTokenType,
    pub modifiers: PolyTokenModifiers,
}

/// Tokenizer for polyglot source code
pub struct PolyTokenizer {
    // Keywords from multiple languages
    rust_keywords: Vec<&'static str>,
    python_keywords: Vec<&'static str>,
    js_keywords: Vec<&'static str>,
    common_keywords: Vec<&'static str>,

    // Type names
    builtin_types: Vec<&'static str>,
}

impl PolyTokenizer {
    pub fn new() -> Self {
        Self {
            rust_keywords: vec![
                "fn", "let", "mut", "const", "pub", "struct", "enum", "impl",
                "trait", "use", "mod", "crate", "super", "where", "match",
                "loop", "move", "ref", "static", "unsafe", "extern", "dyn",
                "type", "as", "break", "continue", "return", "yield",
            ],
            python_keywords: vec![
                "def", "class", "import", "from", "as", "global", "nonlocal",
                "lambda", "with", "assert", "raise", "try", "except", "finally",
                "pass", "del", "yield", "return", "break", "continue",
            ],
            js_keywords: vec![
                "function", "var", "const", "let", "class", "extends", "super",
                "new", "delete", "typeof", "instanceof", "void", "throw",
                "try", "catch", "finally", "debugger", "export", "import",
                "default", "yield", "return", "break", "continue",
            ],
            common_keywords: vec![
                "if", "else", "elif", "for", "while", "in", "async", "await",
                "true", "false", "True", "False", "null", "None", "nil",
                "and", "or", "not", "is",
            ],
            builtin_types: vec![
                // Rust types
                "u8", "u16", "u32", "u64", "u128", "usize",
                "i8", "i16", "i32", "i64", "i128", "isize",
                "f32", "f64", "bool", "char", "str", "String",
                "Vec", "Box", "Rc", "Arc", "Option", "Result",
                "HashMap", "HashSet", "BTreeMap", "BTreeSet",
                // Python types
                "int", "float", "complex", "list", "dict", "set", "tuple",
                "bytes", "bytearray", "frozenset", "range", "slice",
                // Generic
                "Array", "Object", "Map", "Set", "Promise",
            ],
        }
    }

    /// Tokenize source code and return semantic tokens
    pub fn tokenize(&self, source: &str) -> Vec<SemanticToken> {
        let mut tokens = Vec::new();

        for (line_idx, line) in source.lines().enumerate() {
            self.tokenize_line(line, line_idx as u32, &mut tokens);
        }

        tokens
    }

    fn tokenize_line(&self, line: &str, line_num: u32, tokens: &mut Vec<SemanticToken>) {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        // Skip empty lines
        if trimmed.is_empty() {
            return;
        }

        // Check for comments first
        if trimmed.starts_with("//") || trimmed.starts_with('#') && !trimmed.starts_with("#[") {
            tokens.push(SemanticToken {
                line: line_num,
                start_char: indent as u32,
                length: trimmed.len() as u32,
                token_type: PolyTokenType::Comment,
                modifiers: PolyTokenModifiers::new(),
            });
            return;
        }

        // Check for block directive: #[rust], #[python], #[js], etc.
        if let Some(caps) = Regex::new(r"^#\[(\w+)(?::\S*)?\]").ok().and_then(|re| re.captures(trimmed)) {
            let full_match = caps.get(0).unwrap();
            tokens.push(SemanticToken {
                line: line_num,
                start_char: indent as u32,
                length: full_match.len() as u32,
                token_type: PolyTokenType::Macro,
                modifiers: PolyTokenModifiers::new(),
            });
            return;
        }

        // Check for decorators: @decorator
        if let Some(caps) = Regex::new(r"^@([a-zA-Z_][a-zA-Z0-9_.]*)").ok().and_then(|re| re.captures(trimmed)) {
            let full_match = caps.get(0).unwrap();
            tokens.push(SemanticToken {
                line: line_num,
                start_char: indent as u32,
                length: full_match.len() as u32,
                token_type: PolyTokenType::Decorator,
                modifiers: PolyTokenModifiers::new(),
            });
            // Continue to tokenize rest of line if decorator has arguments
        }

        // Tokenize the line content
        self.tokenize_content(line, line_num, tokens);
    }

    fn tokenize_content(&self, line: &str, line_num: u32, tokens: &mut Vec<SemanticToken>) {
        // Match patterns in order of priority
        let patterns: Vec<(&str, PolyTokenType, PolyTokenModifiers)> = vec![
            // Strings (double-quoted)
            (r#""(?:[^"\\]|\\.)*""#, PolyTokenType::String, PolyTokenModifiers::new()),
            // Strings (single-quoted)
            (r"'(?:[^'\\]|\\.)*'", PolyTokenType::String, PolyTokenModifiers::new()),
            // F-strings
            (r#"f"[^"]*""#, PolyTokenType::String, PolyTokenModifiers::new()),
            // Numbers (hex, binary, octal, float, int)
            (r"0x[0-9a-fA-F_]+|0b[01_]+|0o[0-7_]+|\d+\.?\d*(?:e[+-]?\d+)?", PolyTokenType::Number, PolyTokenModifiers::new()),
            // Arrow operator
            (r"=>|->", PolyTokenType::Operator, PolyTokenModifiers::new()),
            // Operators
            (r"&&|\|\||[+\-*/%=<>!&|^~]+", PolyTokenType::Operator, PolyTokenModifiers::new()),
        ];

        let mut pos = 0;
        let chars: Vec<char> = line.chars().collect();

        while pos < chars.len() {
            // Skip whitespace
            if chars[pos].is_whitespace() {
                pos += 1;
                continue;
            }

            // Try to match identifier/keyword at current position
            if chars[pos].is_alphabetic() || chars[pos] == '_' {
                let start = pos;
                while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                    pos += 1;
                }
                let word: String = chars[start..pos].iter().collect();

                let token_type = self.classify_word(&word);
                let modifiers = self.get_word_modifiers(&word, line, start);

                tokens.push(SemanticToken {
                    line: line_num,
                    start_char: start as u32,
                    length: word.len() as u32,
                    token_type,
                    modifiers,
                });
                continue;
            }

            // Try pattern matches
            let rest: String = chars[pos..].iter().collect();
            let mut matched = false;

            for (pattern, token_type, modifiers) in &patterns {
                if let Ok(re) = Regex::new(&format!("^{}", pattern)) {
                    if let Some(m) = re.find(&rest) {
                        tokens.push(SemanticToken {
                            line: line_num,
                            start_char: pos as u32,
                            length: m.len() as u32,
                            token_type: *token_type,
                            modifiers: *modifiers,
                        });
                        pos += m.len();
                        matched = true;
                        break;
                    }
                }
            }

            if !matched {
                pos += 1;
            }
        }
    }

    fn classify_word(&self, word: &str) -> PolyTokenType {
        // Check for self/this
        if word == "self" || word == "this" {
            return PolyTokenType::SelfKeyword;
        }

        // Check for common keywords first
        if self.common_keywords.contains(&word) {
            return PolyTokenType::Keyword;
        }

        // Check for rust keywords
        if self.rust_keywords.contains(&word) {
            return PolyTokenType::Keyword;
        }

        // Check for python keywords
        if self.python_keywords.contains(&word) {
            return PolyTokenType::Keyword;
        }

        // Check for JS keywords
        if self.js_keywords.contains(&word) {
            return PolyTokenType::Keyword;
        }

        // Check for built-in types
        if self.builtin_types.contains(&word) {
            return PolyTokenType::Type;
        }

        // Check if it looks like a type (starts with uppercase)
        if word.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            return PolyTokenType::Type;
        }

        // Default to variable
        PolyTokenType::Variable
    }

    fn get_word_modifiers(&self, word: &str, line: &str, pos: usize) -> PolyTokenModifiers {
        let mut modifiers = PolyTokenModifiers::new();

        // Check context before the word
        let before: String = line.chars().take(pos).collect();
        let trimmed = before.trim_end();

        // Check for function declaration
        if trimmed.ends_with("fn") || trimmed.ends_with("def") || trimmed.ends_with("function") {
            modifiers = modifiers.set_definition();
        }

        // Check for async modifier
        if trimmed.ends_with("async fn") || trimmed.ends_with("async def") {
            modifiers = modifiers.set_async();
        }

        // Check for let/const declaration
        if trimmed.ends_with("let") || trimmed.ends_with("const") || trimmed.ends_with("var") {
            modifiers = modifiers.set_declaration();
        }

        modifiers
    }
}

/// Encode semantic tokens into LSP format (delta encoding)
/// Returns Vec<tower_lsp::lsp_types::SemanticToken> for use with SemanticTokens struct
pub fn encode_tokens_for_lsp(mut tokens: Vec<SemanticToken>) -> Vec<tower_lsp::lsp_types::SemanticToken> {
    use tower_lsp::lsp_types::SemanticToken as LspSemanticToken;

    // Sort tokens by position
    tokens.sort_by(|a, b| {
        a.line.cmp(&b.line).then(a.start_char.cmp(&b.start_char))
    });

    let mut result = Vec::new();
    let mut prev_line = 0u32;
    let mut prev_char = 0u32;

    for token in tokens {
        let delta_line = token.line - prev_line;
        let delta_start = if delta_line == 0 {
            token.start_char - prev_char
        } else {
            token.start_char
        };

        result.push(LspSemanticToken {
            delta_line,
            delta_start,
            length: token.length,
            token_type: token.token_type.as_u32(),
            token_modifiers_bitset: token.modifiers.as_u32(),
        });

        prev_line = token.line;
        prev_char = token.start_char;
    }

    result
}

/// Encode semantic tokens into the data array format (u32 array)
pub fn encode_tokens_data(mut tokens: Vec<SemanticToken>) -> Vec<u32> {
    // Sort tokens by position
    tokens.sort_by(|a, b| {
        a.line.cmp(&b.line).then(a.start_char.cmp(&b.start_char))
    });

    let mut data = Vec::new();
    let mut prev_line = 0u32;
    let mut prev_char = 0u32;

    for token in tokens {
        let delta_line = token.line - prev_line;
        let delta_char = if delta_line == 0 {
            token.start_char - prev_char
        } else {
            token.start_char
        };

        data.push(delta_line);
        data.push(delta_char);
        data.push(token.length);
        data.push(token.token_type.as_u32());
        data.push(token.modifiers.as_u32());

        prev_line = token.line;
        prev_char = token.start_char;
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legend() {
        let legend = get_legend();
        assert!(!legend.token_types.is_empty());
        assert!(!legend.token_modifiers.is_empty());
    }

    #[test]
    fn test_tokenize_keywords() {
        let tokenizer = PolyTokenizer::new();
        let tokens = tokenizer.tokenize("fn main() {}");

        assert!(!tokens.is_empty());
        // 'fn' should be a keyword
        let fn_token = tokens.iter().find(|t| t.start_char == 0 && t.length == 2);
        assert!(fn_token.is_some());
        assert_eq!(fn_token.unwrap().token_type, PolyTokenType::Keyword);
    }

    #[test]
    fn test_tokenize_self() {
        let tokenizer = PolyTokenizer::new();
        let tokens = tokenizer.tokenize("self.data = 5");

        let self_token = tokens.iter().find(|t| t.start_char == 0 && t.length == 4);
        assert!(self_token.is_some());
        assert_eq!(self_token.unwrap().token_type, PolyTokenType::SelfKeyword);
    }

    #[test]
    fn test_tokenize_decorator() {
        let tokenizer = PolyTokenizer::new();
        let tokens = tokenizer.tokenize("@component");

        assert!(!tokens.is_empty());
        let dec_token = tokens.iter().find(|t| t.token_type == PolyTokenType::Decorator);
        assert!(dec_token.is_some());
    }

    #[test]
    fn test_encode_tokens() {
        let tokens = vec![
            SemanticToken {
                line: 0,
                start_char: 0,
                length: 2,
                token_type: PolyTokenType::Keyword,
                modifiers: PolyTokenModifiers::new(),
            },
            SemanticToken {
                line: 0,
                start_char: 3,
                length: 4,
                token_type: PolyTokenType::Function,
                modifiers: PolyTokenModifiers::new().set_definition(),
            },
        ];

        let data = encode_tokens_data(tokens);
        // First token: delta_line=0, delta_char=0, length=2, type=0, modifiers=0
        // Second token: delta_line=0, delta_char=3, length=4, type=1, modifiers=2
        assert_eq!(data.len(), 10);
        assert_eq!(data[0], 0); // delta_line
        assert_eq!(data[1], 0); // delta_char
        assert_eq!(data[2], 2); // length
    }
}
