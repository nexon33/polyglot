//! Polyglot compiler diagnostics using miette
//!
//! This module provides beautiful, Rust-style error messages with:
//! - Source code snippets with underlines
//! - Multiple labels per error
//! - Help text and suggestions
//! - Color support

// Miette's derive macros use these fields via #[source_code], #[label], etc.
// The compiler doesn't see this usage, so we suppress the warnings.
#![allow(dead_code, unused_assignments)]

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

// ============ Source Holder ============

/// Source code holder for miette diagnostics
#[derive(Debug, Clone)]
pub struct PolySource {
    pub name: String,
    pub content: String,
}

impl PolySource {
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            content: content.into(),
        }
    }

    pub fn named_source(&self) -> NamedSource<String> {
        NamedSource::new(&self.name, self.content.clone())
    }
}

// ============ Error Types ============

/// E001: No main entry point found
#[derive(Error, Debug, Diagnostic)]
#[error("No main entry point found")]
#[diagnostic(
    code(polyglot::E001),
    help("Add a main function:\n\n  #[main] {{\n      fn main() {{\n          println!(\"Hello!\");\n      }}\n  }}\n\n  -- or --\n\n  #[python] {{\n      def main():\n          print(\"Hello!\")\n  }}")
)]
pub struct NoMainError {
    #[source_code]
    pub src: NamedSource<String>,

    #[label("file has {block_count} block(s) but no main() function")]
    pub span: SourceSpan,

    pub block_count: usize,
}

/// E002: Multiple main entry points found
#[derive(Error, Debug, Diagnostic)]
#[error("Multiple main entry points found")]
#[diagnostic(
    code(polyglot::E002),
    help("Remove one of the main functions. A polyglot file can only have one entry point.")
)]
pub struct MultipleMainError {
    #[source_code]
    pub src: NamedSource<String>,

    #[label("first main defined here")]
    pub first: SourceSpan,

    #[label("second main defined here")]
    pub second: SourceSpan,
}

/// E003: Invalid block directive
#[derive(Error, Debug, Diagnostic)]
#[error("Invalid block directive: {directive}")]
#[diagnostic(code(polyglot::E003))]
pub struct InvalidBlockError {
    pub directive: String,

    #[source_code]
    pub src: NamedSource<String>,

    #[label("unknown block type")]
    pub span: SourceSpan,

    #[help]
    pub suggestion: String,
}

/// E004: Unterminated block
#[derive(Error, Debug, Diagnostic)]
#[error("Unterminated block")]
#[diagnostic(
    code(polyglot::E004),
    help("Add a closing brace '}}' to end the block")
)]
pub struct UnterminatedBlockError {
    #[source_code]
    pub src: NamedSource<String>,

    #[label("block starts here but never closes")]
    pub span: SourceSpan,
}

/// E005: Mismatched braces
#[derive(Error, Debug, Diagnostic)]
#[error("Mismatched braces")]
#[diagnostic(code(polyglot::E005))]
pub struct MismatchedBracesError {
    #[source_code]
    pub src: NamedSource<String>,

    #[label("opening brace here")]
    pub open: SourceSpan,

    #[label("expected closing brace")]
    pub close: SourceSpan,

    #[help]
    pub suggestion: String,
}

/// E006: Parse error
#[derive(Error, Debug, Diagnostic)]
#[error("Parse error: {message}")]
#[diagnostic(code(polyglot::E006))]
pub struct ParseDiagnostic {
    pub message: String,

    #[source_code]
    pub src: NamedSource<String>,

    #[label("{message}")]
    pub span: SourceSpan,
}

/// E007: Syntax error in block
#[derive(Error, Debug, Diagnostic)]
#[error("Syntax error in {language} block")]
#[diagnostic(code(polyglot::E007))]
pub struct SyntaxError {
    pub language: String,

    #[source_code]
    pub src: NamedSource<String>,

    #[label("{detail}")]
    pub span: SourceSpan,

    pub detail: String,

    #[help]
    pub suggestion: Option<String>,
}

/// E010: Type error at boundary
#[derive(Error, Debug, Diagnostic)]
#[error("Type mismatch at block boundary")]
#[diagnostic(code(polyglot::E010))]
pub struct TypeBoundaryError {
    #[source_code]
    pub src: NamedSource<String>,

    #[label("expected {expected}")]
    pub expected_span: SourceSpan,

    #[label("found {found}")]
    pub found_span: SourceSpan,

    pub expected: String,
    pub found: String,

    #[help]
    pub suggestion: Option<String>,
}

/// E020: Unknown language tag
#[derive(Error, Debug, Diagnostic)]
#[error("Unknown language tag: {tag}")]
#[diagnostic(
    code(polyglot::E020),
    help("Valid tags: rust, python, js, main, test, wasm")
)]
pub struct UnknownLanguageError {
    pub tag: String,

    #[source_code]
    pub src: NamedSource<String>,

    #[label("unknown tag '{tag}'")]
    pub span: SourceSpan,
}

/// E021: Language feature not supported
#[derive(Error, Debug, Diagnostic)]
#[error("Language feature not supported: {feature}")]
#[diagnostic(code(polyglot::E021))]
pub struct UnsupportedFeatureError {
    pub feature: String,

    #[source_code]
    pub src: NamedSource<String>,

    #[label("this feature is not yet supported")]
    pub span: SourceSpan,

    #[help]
    pub workaround: Option<String>,
}

/// E030: Build error
#[derive(Error, Debug, Diagnostic)]
#[error("Build failed: {message}")]
#[diagnostic(code(polyglot::E030))]
pub struct BuildError {
    pub message: String,

    #[source_code]
    pub src: Option<NamedSource<String>>,

    #[label("error occurred here")]
    pub span: Option<SourceSpan>,

    #[help]
    pub suggestion: Option<String>,
}

/// E031: Rust compilation error (detailed rustc output)
#[derive(Debug, Diagnostic)]
#[diagnostic(
    code(polyglot::E031),
    help("Fix the Rust errors above. If referencing types from other language blocks, use the #[interface] pattern for cross-language communication.")
)]
pub struct RustCompileError {
    #[source_code]
    pub src: NamedSource<String>,

    #[label("compilation started from this block")]
    pub span: SourceSpan,

    /// The detailed rustc error output
    pub details: String,
}

impl RustCompileError {
    /// Format the error with rustc output prominently displayed
    pub fn with_details(src: NamedSource<String>, span: SourceSpan, details: String) -> Self {
        Self { src, span, details }
    }
}

impl std::fmt::Display for RustCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rust compilation failed:\n\n{}", self.details)
    }
}

impl std::error::Error for RustCompileError {}

/// W001: Mixed indentation warning
#[derive(Error, Debug, Diagnostic)]
#[error("Mixed indentation detected")]
#[diagnostic(
    code(polyglot::W001),
    severity(Warning),
    help("Use consistent indentation - either tabs or spaces, not both")
)]
pub struct MixedIndentationWarning {
    #[source_code]
    pub src: NamedSource<String>,

    #[label("tabs and spaces mixed here")]
    pub span: SourceSpan,
}

// ============ Helper Functions ============

/// Convert byte offset to SourceSpan
pub fn offset_to_span(start: usize, len: usize) -> SourceSpan {
    SourceSpan::from((start, len))
}

/// Find byte offset and length of a line (1-indexed)
pub fn line_span(source: &str, line_num: usize) -> SourceSpan {
    let mut current_line = 1;
    let mut line_start = 0;

    for (i, c) in source.char_indices() {
        if current_line == line_num {
            // Find end of this line
            let line_end = source[i..].find('\n').map(|pos| i + pos).unwrap_or(source.len());
            return SourceSpan::from((line_start, line_end - line_start));
        }
        if c == '\n' {
            current_line += 1;
            line_start = i + 1;
        }
    }

    // If we didn't find the line, return the last line
    SourceSpan::from((line_start, source.len() - line_start))
}

/// Find byte offset from line/column (both 1-indexed)
pub fn line_col_to_offset(source: &str, line: usize, col: usize) -> usize {
    let mut current_line = 1;
    let mut current_col = 1;

    for (i, c) in source.char_indices() {
        if current_line == line && current_col == col {
            return i;
        }
        if c == '\n' {
            if current_line == line {
                // Column is past end of line
                return i;
            }
            current_line += 1;
            current_col = 1;
        } else {
            current_col += 1;
        }
    }

    source.len()
}

/// Find line and column from byte offset (returns 1-indexed)
pub fn offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;

    for (i, c) in source.char_indices() {
        if i >= offset {
            break;
        }
        if c == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    (line, col)
}

/// Find the span of a pattern in source, starting from a given offset
pub fn find_pattern_span(source: &str, pattern: &str, start_offset: usize) -> Option<SourceSpan> {
    source[start_offset..]
        .find(pattern)
        .map(|pos| SourceSpan::from((start_offset + pos, pattern.len())))
}

/// Create a span from start offset to end of line
pub fn span_to_eol(source: &str, start: usize) -> SourceSpan {
    let end = source[start..].find('\n').map(|pos| start + pos).unwrap_or(source.len());
    SourceSpan::from((start, end - start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_col_to_offset() {
        let source = "line 1\nline 2\nline 3";
        assert_eq!(line_col_to_offset(source, 1, 1), 0);
        assert_eq!(line_col_to_offset(source, 2, 1), 7);
        assert_eq!(line_col_to_offset(source, 3, 1), 14);
    }

    #[test]
    fn test_offset_to_line_col() {
        let source = "line 1\nline 2\nline 3";
        assert_eq!(offset_to_line_col(source, 0), (1, 1));
        assert_eq!(offset_to_line_col(source, 7), (2, 1));
        assert_eq!(offset_to_line_col(source, 14), (3, 1));
    }

    #[test]
    fn test_line_span() {
        let source = "line 1\nline 2\nline 3";
        let span = line_span(source, 2);
        assert_eq!(span.offset(), 7);
        assert_eq!(span.len(), 6); // "line 2"
    }
}
