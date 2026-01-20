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

    // First, collect all Rust code to know what functions are implemented
    let mut raw_rust_code = String::new();
    let mut python_blocks = Vec::new();

    for block in &parsed.blocks {
        match block.lang_tag.as_str() {
            "rs" | "rust" | "main" => {
                raw_rust_code.push_str(&block.code);
                raw_rust_code.push('\n');
            }
            "py" | "python" => {
                python_blocks.push(block.code.clone());
            }
            "interface" => {
                // Already processed via parsed.interfaces
            }
            _ => {
                return Err(CompileError::UnknownLanguage(block.lang_tag.clone()));
            }
        }
    }

    // Generate interface code with knowledge of what's implemented
    let rs_interface = crate::interface::codegen::generate_rust_with_source(&parsed.interfaces, &raw_rust_code);
    
    // Merge all Python code for embedding
    let merged_python_code = python_blocks.join("\n");
    
    // Generate Python bridge functions (Rust functions that call Python via RustPython)
    let python_bridge = crate::interface::codegen::generate_python_bridge(
        &parsed.interfaces, 
        &merged_python_code, 
        &raw_rust_code
    );

    // Prepend interface and Python bridge to Rust code
    let mut merged_rust_code = String::new();
    merged_rust_code.push_str(&rs_interface);
    merged_rust_code.push_str(&python_bridge);
    merged_rust_code.push_str(&raw_rust_code);

    // Compile merged Rust code as single unit (with embedded Python)
    if !merged_rust_code.trim().is_empty() {
        let rust_lang = find_language("rust").unwrap();
        let mut rust_opts = opts.clone();
        rust_opts.temp_dir = opts.temp_dir.join("rust_merged");
        fs::create_dir_all(&rust_opts.temp_dir)?;
        
        let wasm = rust_lang.compile(&merged_rust_code, &rust_opts)?;
        wasm_modules.push(wasm);
    }

    // Note: Python is now embedded in Rust via RustPython bridge
    // No separate Python compilation needed for cross-language calls

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
    println!("Note: Multi-module linking requires wasm-compose. Returning first module.");
    Ok(modules[0].clone())
}
