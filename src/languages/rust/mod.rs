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
        // Create a temporary Cargo project to handle dependencies correctly
        let package_name = "poly_cell";
        let cargo_toml_content = r#"
[workspace]

[package]
name = "poly_cell"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]
path = "lib.rs"

[dependencies]
anyhow = "1.0" 
wit-bindgen = "0.41"
gridmesh = { path = "C:/Users/adria/Downloads/pyrs polygot/pyrs/gridmesh" }
"#;

        fs::write(opts.temp_dir.join("Cargo.toml"), cargo_toml_content)?;

        // Wrap the user code.
        // We do NOT use no_std so that println! and vec! work (WASI supports them).
        let wrapped = format!(
            r#"
#[no_mangle]
pub extern "C" fn __pyrs_keepalive() {{}}

{}
"#,
            source
        );

        let lib_rs = opts.temp_dir.join("lib.rs");
        let should_write = if lib_rs.exists() {
            fs::read_to_string(&lib_rs)
                .map(|c| c != wrapped)
                .unwrap_or(true)
        } else {
            true
        };

        if should_write {
            fs::write(&lib_rs, wrapped)?;
        }

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&opts.temp_dir)
            .arg("build")
            .arg("--target=wasm32-wasip1")
            .arg("--release"); // Always release for WASM size/speed in demo

        // Suppress output unless error
        // cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("Rust compilation failed"));
        }

        // Path to the output WASM
        let wasm_path = opts
            .temp_dir
            .join("target")
            .join("wasm32-wasip1")
            .join("release")
            .join("poly_cell.wasm");

        Ok(fs::read(&wasm_path)?)
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
