use crate::languages::Language;
use crate::parser::{ParseError, parse_rust_params, parse_rust_type};
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
        let _package_name = "poly_cell";

        // Check if Python bridge is being used (contains RustPython imports)
        let needs_rustpython = source.contains("rustpython_vm");

        let mut cargo_toml = String::from(
            r#"
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
"#,
        );

        if needs_rustpython {
            cargo_toml.push_str("rustpython-vm = { git = \"https://github.com/RustPython/RustPython\", default-features = false, features = [\"compiler\", \"codegen\"] }\n");
        }

        fs::write(opts.temp_dir.join("Cargo.toml"), cargo_toml)?;

        // Determine entry point based on main_lang
        let main_lang = opts.main_lang.as_deref().unwrap_or("rust");

        let start_wrapper = match main_lang {
            "python" | "py" => {
                // Python main: _start calls the Python main via RustPython bridge
                r#"
// WASI entry point - calls Python main via RustPython
#[no_mangle]
pub extern "C" fn _start() {
    __python_main();
}
"#
            }
            _ => {
                // Rust main (default): _start calls Rust main directly
                r#"
// WASI entry point - calls user's Rust main
#[no_mangle]
pub extern "C" fn _start() {
    main();
}
"#
            }
        };

        // Wrap the user code.
        // We do NOT use no_std so that println! and vec! work (WASI supports them).
        let wrapped = format!(
            r#"
#[no_mangle]
pub extern "C" fn __pyrs_keepalive() {{}}
{}
{}
"#,
            start_wrapper, source
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
            .env("RUSTFLAGS", "-C target-feature=+simd128")
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
        let syntax = syn::parse_file(source).map_err(|e| ParseError {
            message: e.to_string(),
            line: 0, // Span line info requires extra features, defaulting to 0
        })?;

        let mut sigs = Vec::new();

        for item in syntax.items {
            if let syn::Item::Fn(func) = item {
                // Ignore non-pub functions if desired, but for now we follow regex behavior which allowed non-pub (regex was loose)
                // Actually regex had `(?:pub\s+)?`, so it didn't require pub.
                // We keep capturing all top-level functions.

                let name = func.sig.ident.to_string();
                println!("DEBUG: Found function: {}", name);
                let is_async = func.sig.asyncness.is_some();

                // Parse params
                let mut params_str = String::new();
                for input in func.sig.inputs {
                    if !params_str.is_empty() {
                        params_str.push_str(", ");
                    }
                    // Reconstruct param string "name: type" for generic parser
                    // Or ideally we parse AST to Param directly.
                    // Let's rely on quote to get the type string.
                    if let syn::FnArg::Typed(pat_type) = input {
                        let pat = quote::quote!(#pat_type).to_string();
                        params_str.push_str(&pat);
                    }
                }
                let params = parse_rust_params(&params_str)?;

                // Parse return type
                let returns = match func.sig.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, ty) => {
                        let type_str = quote::quote!(#ty).to_string();
                        // Remove whitespace from quote output (e . g . "Vec < f32 >") if needed
                        // parse_rust_type handles spacing well usually, but let's be careful.
                        // Actually, simple spacing is fine.
                        Some(parse_rust_type(&type_str)?)
                    }
                };

                sigs.push(FunctionSig {
                    name,
                    params,
                    returns,
                    is_async,
                });
            }
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
