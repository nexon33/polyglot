pub mod python;
pub mod rust;

use crate::parser::ParseError;
use crate::types::{CompileOptions, FunctionSig, WitType};
use anyhow::Result;

pub trait Language: Send + Sync {
    /// The tag used in source files, e.g., "py", "rs"
    fn tag(&self) -> &'static str;

    /// File extension for temporary files
    fn extension(&self) -> &'static str;

    /// Compile source to WASM bytes
    fn compile(&self, source: &str, opts: &CompileOptions) -> Result<Vec<u8>>;

    /// Extract function signatures for WIT generation
    fn parse_signatures(&self, source: &str) -> Result<Vec<FunctionSig>, ParseError>;

    /// Map language-specific types to WIT types
    fn map_type(&self, type_str: &str) -> WitType;

    /// Optional: variants like #[py:fast]
    fn variants(&self) -> Vec<&'static str> {
        vec![]
    }
}

// Registry
pub fn default_languages() -> Vec<Box<dyn Language>> {
    vec![Box::new(python::Python::new()), Box::new(rust::Rust::new())]
}

pub fn find_language(tag: &str) -> Option<Box<dyn Language>> {
    let (base_tag, _variant) = tag.split_once(':').unwrap_or((tag, ""));

    match base_tag {
        "py" => Some(Box::new(python::Python::new())),
        "rs" => Some(Box::new(rust::Rust::new())),
        _ => None,
    }
}
