use crate::languages::Language;
use crate::parser::{parse_rust_params, parse_rust_type, ParseError};
use crate::types::{CompileOptions, FunctionSig, Param, WitType};
use anyhow::Result;
use regex::Regex;
use std::fs;
use std::process::Command;

pub struct Rust;

impl Rust {
    pub fn new() -> Self {
        Self
    }
}

impl Language for Rust {
    fn tag(&self) -> &'static str {
        "rs"
    }

    fn extension(&self) -> &'static str {
        "rs"
    }

    fn compile(&self, source: &str, opts: &CompileOptions) -> Result<Vec<u8>> {
        // Standard Rust compilation
        // We wrap the code in a library crate structure if needed, or just compile as is
        // For partial blocks, we might need a wrapper, but for now assuming valid items.

        // We wrap in a block to ensure no_std/no_main if user didn't provider it?
        // Actually, the user provides "fn ...". We need to wrap it.

        // This wrapping logic should be robust.
        let wrapped = format!(
            r#"
#![no_std]
#![no_main]

// Panic handler for wasm32-unknown-unknown or wasi (wasi guides often use std though)
// For now, let's assume WASI target which has std support usually, but we want cdylib.
// Explicitly no_std might require a panic_handler. 
// Let's rely on user provided code or minimal wrapper.

#[no_mangle]
pub extern "C" fn __pyrs_keepalive() {{}}

{}
"#,
            source
        );

        let rs_file = opts.temp_dir.join(format!("module.{}", self.extension()));
        fs::write(&rs_file, wrapped)?;

        let output_wasm = rs_file.with_extension("wasm");
        let mut cmd = Command::new("rustc");
        cmd.arg(&rs_file)
            .arg("--target=wasm32-wasi")
            .arg("--crate-type=cdylib")
            .arg("-o")
            .arg(&output_wasm);

        if opts.release {
            cmd.arg("-O");
        }

        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("Rust compilation failed"));
        }

        Ok(fs::read(&output_wasm)?)
    }

    fn parse_signatures(&self, source: &str) -> Result<Vec<FunctionSig>, ParseError> {
        let mut sigs = Vec::new();
        let func_regex = Regex::new(
            r"(?m)^(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^{]+))?",
        )
        .unwrap();

        for caps in func_regex.captures_iter(source) {
            let start = caps.get(0).unwrap().start();
            // Check for async keyword in the lines before the match
            let is_async = source[..start]
                .lines()
                .last()
                .map(|l| l.contains("async"))
                .unwrap_or(false);

            let name = caps.get(1).unwrap().as_str().to_string();
            let params_str = caps.get(2).unwrap().as_str();
            let returns_str = caps.get(3).map(|m| m.as_str().trim());

            let params = parse_rust_params(params_str)?;
            let returns = match returns_str {
                Some(s) if !s.is_empty() => Some(parse_rust_type(s)?),
                _ => None,
            };

            sigs.push(FunctionSig {
                name,
                params,
                returns,
                is_async,
            });
        }
        Ok(sigs)
    }

    fn map_type(&self, type_str: &str) -> WitType {
        match parse_rust_type(type_str) {
            Ok(t) => t,
            Err(_) => WitType::Custom(type_str.to_string()),
        }
    }
}
