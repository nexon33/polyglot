//! Polyglot Runtime - Cross-language marshaling and interpreters
//!
//! Provides runtime support for the polyglot macros:
//! - JavaScript engine via Boa (pure Rust, no Node.js)
//! - TypeScript via SWC transpiler + Boa
//! - Python via RustPython (actual Python 3 interpreter)
//! - Scripting via Rhai (Rust-like, pure Rust)
//! - Bridge system for type-safe cross-language FFI
//!
//! All interpreters are fully embedded - no external runtimes needed!

pub mod bridge;
pub mod marshal;

#[cfg(feature = "scripting")]
pub mod python;

#[cfg(feature = "python")]
pub mod rustpython;

#[cfg(feature = "javascript")]
pub mod javascript;

#[cfg(feature = "typescript")]
pub mod typescript;

pub mod prelude {
    #[cfg(feature = "scripting")]
    pub use crate::python::{PythonRuntime, ScriptRuntime};

    #[cfg(feature = "python")]
    pub use crate::rustpython::PyRuntime;

    #[cfg(feature = "javascript")]
    pub use crate::javascript::JsRuntime;

    #[cfg(feature = "typescript")]
    pub use crate::typescript::TsRuntime;
}

/// Error type for polyglot operations
#[derive(Debug)]
pub enum PolyglotError {
    Python(String),
    JavaScript(String),
    TypeScript(String),
    TypeConversion(String),
    NotInitialized(String),
}

impl std::fmt::Display for PolyglotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolyglotError::Python(s) => write!(f, "Script error: {}", s),
            PolyglotError::JavaScript(s) => write!(f, "JavaScript error: {}", s),
            PolyglotError::TypeScript(s) => write!(f, "TypeScript error: {}", s),
            PolyglotError::TypeConversion(s) => write!(f, "Type conversion error: {}", s),
            PolyglotError::NotInitialized(s) => write!(f, "Runtime not initialized: {}", s),
        }
    }
}

impl std::error::Error for PolyglotError {}

pub type Result<T> = std::result::Result<T, PolyglotError>;
