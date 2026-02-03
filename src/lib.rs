pub mod ast_parser;
pub mod capability;
pub mod compiler;
pub mod component_builder;
pub mod component_linker;
pub mod diagnostic;
pub mod implements_verify;
pub mod interface;
pub mod languages;
pub mod parser;
pub mod source_map;
pub mod syntax_aliases;
pub mod transpile;
pub mod types;
pub mod validation;
pub mod wit_gen;

pub use parser::{CodeBlock, ParsedFile, parse_poly};
pub use validation::validate;
pub use implements_verify::verify_implementations;
pub use component_builder::{ComponentBuilder, check_component_tools};
pub use component_linker::{ComponentLinker, LinkResult};
// New AST parser (can be used as alternative)
pub use ast_parser::parse_poly_ast;
