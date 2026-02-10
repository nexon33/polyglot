//! Verified execution compiler integration
//!
//! Provides compile-time support for `#[verified]` functions:
//! - Determinism checking (reject non-deterministic operations)
//! - Error code definitions (V001-V015)
//! - Code generation for verified execution wrappers

pub mod determinism_check;
pub mod error_codes;
pub mod verified_codegen;

use crate::parser::CodeBlock;

/// Check if a code block contains any verified execution markers
pub fn has_verified_markers(block: &CodeBlock) -> bool {
    let code = &block.code;
    code.contains("#[verified]") || code.contains("#[pure]") || code.contains("fold!(")
}

/// Check if any blocks in a parsed file use verified execution
pub fn needs_verified_support(blocks: &[CodeBlock]) -> bool {
    blocks.iter().any(|b| {
        matches!(b.lang_tag.as_str(), "rust" | "rs" | "main" | "verified")
            && has_verified_markers(b)
    })
}
