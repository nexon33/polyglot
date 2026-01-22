//! Polyglot Runtime - Cross-language marshaling and interpreters
//!
//! Provides runtime support for the polyglot macros:
//! - Python interpreter via PyO3
//! - JavaScript engine via QuickJS (optional)
//! - Type marshaling between Rust and foreign languages

pub mod marshal;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "javascript")]
pub mod javascript;

pub mod prelude {
    #[cfg(feature = "python")]
    pub use crate::python::PythonRuntime;

    #[cfg(feature = "javascript")]
    pub use crate::javascript::JsRuntime;
}

/// Error type for polyglot operations
#[derive(Debug)]
pub enum PolyglotError {
    Python(String),
    JavaScript(String),
    TypeConversion(String),
    NotInitialized(String),
}

impl std::fmt::Display for PolyglotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolyglotError::Python(s) => write!(f, "Python error: {}", s),
            PolyglotError::JavaScript(s) => write!(f, "JavaScript error: {}", s),
            PolyglotError::TypeConversion(s) => write!(f, "Type conversion error: {}", s),
            PolyglotError::NotInitialized(s) => write!(f, "Runtime not initialized: {}", s),
        }
    }
}

impl std::error::Error for PolyglotError {}

pub type Result<T> = std::result::Result<T, PolyglotError>;
