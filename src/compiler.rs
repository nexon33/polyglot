// Compile Python and Rust blocks to WASM

use crate::languages::find_language;
use crate::parser::ParsedFile;
use crate::types::CompileOptions;
use anyhow::{anyhow, Result};
use std::fs;
use std::process::Command;

// We need a local error type or just use anyhow
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Compilation failed: {0}")]
    Build(String),
    #[error("Unknown language: {0}")]
    UnknownLanguage(String),
    #[error("Anyhow error: {0}")]
    Other(#[from] anyhow::Error),
}

pub fn compile(parsed: &ParsedFile, opts: &CompileOptions) -> Result<Vec<u8>, CompileError> {
    fs::create_dir_all(&opts.temp_dir)?;

    let mut wasm_modules = Vec::new();

    // Generate interface code
    let py_interface = crate::interface::codegen::generate_python(&parsed.interfaces);
    let rs_interface = crate::interface::codegen::generate_rust(&parsed.interfaces);

    for (i, block) in parsed.blocks.iter().enumerate() {
        let lang = find_language(&block.lang_tag)
            .ok_or_else(|| CompileError::UnknownLanguage(block.lang_tag.clone()))?;

        // Prepend generated interface code
        let mut code_with_interface = String::new();
        if block.lang_tag == "py" || block.lang_tag == "python" {
            code_with_interface.push_str(&py_interface);
        } else if block.lang_tag == "rs" || block.lang_tag == "rust" {
            code_with_interface.push_str(&rs_interface);
        }
        code_with_interface.push_str(&block.code);

        let wasm = lang.compile(&code_with_interface, opts)?;
        wasm_modules.push(wasm);
    }

    // Generate WIT separate file or return it?
    // For now we just print it to show it works or write to a file in temp
    let wit_content = crate::interface::codegen::generate_wit(&parsed.interfaces);
    fs::write(opts.temp_dir.join("interface.wit"), wit_content).map_err(|e| CompileError::Io(e))?;

    // Link all modules together
    link_modules(&wasm_modules, opts)
}

fn link_modules(modules: &[Vec<u8>], opts: &CompileOptions) -> Result<Vec<u8>, CompileError> {
    // For now, if there is only one module, just return it.
    // Real component linking requires more complex logic with wasm-tools
    if modules.len() == 1 {
        return Ok(modules[0].clone());
    }

    // Temporary: return the first one to allow build to pass for single-language tests
    // In a real polyglot scenario, we'd use wasm-compose or similar.
    println!("Warning: Linking multiple modules is mock-implemented. Returning first module.");
    Ok(modules[0].clone())
}
