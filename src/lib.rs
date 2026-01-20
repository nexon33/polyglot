pub mod ast_parser;
pub mod capability;
pub mod compiler;
pub mod interface;
pub mod languages;
pub mod parser;
pub mod types;
pub mod validation;
pub mod wit_gen;

pub use parser::{parse_poly, CodeBlock, ParsedFile};
pub use validation::validate;
// New AST parser (can be used as alternative)
pub use ast_parser::parse_poly_ast;
