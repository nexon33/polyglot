use crate::languages::Language;
use crate::parser::{ParseError, parse_rust_params, parse_rust_type};
use crate::types::{CompileOptions, FunctionSig, WitType};
use anyhow::Result;
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
polyglot-macros = { path = "C:/Users/adria/Downloads/pyrs polygot/pyrs/polyglot-macros" }
polyglot-runtime = { path = "C:/Users/adria/Downloads/pyrs polygot/pyrs/polyglot-runtime", default-features = false, features = ["javascript", "scripting"] }
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
        // Auto-inject memory management functions for JS<->WASM interop
        let memory_management = r#"
// Auto-generated memory management for JS<->WASM array passing
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub extern "C" fn __malloc(size: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, 4).unwrap();
    unsafe { alloc(layout) }
}

#[no_mangle]
pub extern "C" fn __free(ptr: *mut u8, size: usize) {
    if ptr.is_null() { return; }
    let layout = Layout::from_size_align(size, 4).unwrap();
    unsafe { dealloc(ptr, layout); }
}
"#;

        let wrapped = format!(
            r#"
#[no_mangle]
pub extern "C" fn __pyrs_keepalive() {{}}
{}
{}
{}
"#,
            memory_management, start_wrapper, source
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
        cmd.current_dir(&opts.temp_dir);

        if opts.test_mode {
            // Run tests natively (not WASM) - tests run on host
            cmd.arg("test")
                .arg("--lib") // Only test the library code
                .arg("--")
                .arg("--nocapture"); // Show println! output

            // For tests, we want to see output
            cmd.stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit());

            let status = cmd.status()?;
            if !status.success() {
                return Err(anyhow::anyhow!("Rust tests failed"));
            }
        } else {
            // Normal WASM build - capture output for better error messages
            cmd.env("RUSTFLAGS", "-C target-feature=+simd128")
                .arg("build")
                .arg("--target=wasm32-wasip1")
                .arg("--release");

            let output = cmd.output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let _stdout = String::from_utf8_lossy(&output.stdout);

                // Parse the error output more carefully
                // Focus on lines from lib.rs (our generated code) not from dependencies
                let mut error_sections: Vec<String> = Vec::new();
                let mut current_section: Vec<&str> = Vec::new();
                let mut in_error = false;
                let mut error_count = 0;

                for line in stderr.lines() {
                    // Start of a new error
                    if line.starts_with("error[") || line.starts_with("error:") {
                        // Save previous section if any
                        if !current_section.is_empty() && error_count < 5 {
                            error_sections.push(current_section.join("\n"));
                            error_count += 1;
                        }
                        current_section.clear();
                        current_section.push(line);
                        in_error = true;
                    } else if in_error {
                        // Continue collecting error context
                        // Skip lines that are just from dependency crates
                        let is_dep_line = line.contains("polyglot-macros") ||
                                          line.contains("polyglot-runtime") ||
                                          line.contains("gridmesh");

                        if !is_dep_line || line.contains("lib.rs") {
                            current_section.push(line);
                        }

                        // End of this error's context (blank line or new error)
                        if line.trim().is_empty() || line.starts_with("warning:") {
                            in_error = false;
                        }
                    }
                }

                // Don't forget the last section
                if !current_section.is_empty() && error_count < 5 {
                    error_sections.push(current_section.join("\n"));
                }

                // If we didn't find structured errors, look for key patterns
                let error_summary = if error_sections.is_empty() {
                    // Fall back to filtering key error patterns
                    stderr
                        .lines()
                        .filter(|line| {
                            (line.contains("error[") || line.contains("error:") ||
                             line.contains("cannot find") || line.contains("not found in scope") ||
                             line.contains("expected") || line.contains("mismatched types") ||
                             (line.contains("lib.rs") && line.contains("-->")))
                            && !line.contains("polyglot-macros")
                            && !line.contains("polyglot-runtime")
                        })
                        .take(15)
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    error_sections.join("\n\n")
                };

                // Provide helpful hints based on the errors
                let hint = if stderr.contains("cannot find function") || stderr.contains("not found in this scope") {
                    if stderr.contains("PyProcessor") || stderr.contains("TsProcessor") || stderr.contains("JsProcessor") {
                        "\n\n💡 Hint: Types like PyProcessor, TsProcessor from other language blocks aren't directly accessible in Rust.\n   The #[interface] trait pattern requires implementation stubs or actual WASM component linking."
                    } else {
                        "\n\n💡 Hint: This may be a cross-language reference. Use #[interface] for cross-language contracts."
                    }
                } else if stderr.contains("dyn Processor") || stderr.contains("size for values of type") {
                    "\n\n💡 Hint: Cross-language trait objects (`dyn Trait`) aren't supported yet.\n   Use concrete types with the WASM Component Model for cross-language polymorphism."
                } else if stderr.contains("trait `Processor` is not implemented") {
                    "\n\n💡 Hint: Traits from #[interface] need implementations. In chaos.poly, the cross-language \n   implementations would be linked via WASM components, which isn't fully implemented yet."
                } else {
                    ""
                };

                // If error_summary is empty, show a portion of stderr
                let final_error = if error_summary.trim().is_empty() {
                    // Get last 30 lines of stderr as fallback
                    let lines: Vec<&str> = stderr.lines().collect();
                    let start = if lines.len() > 30 { lines.len() - 30 } else { 0 };
                    lines[start..].join("\n")
                } else {
                    error_summary
                };

                return Err(anyhow::anyhow!(
                    "Rust compilation failed:\n\n{}{}",
                    final_error.trim(),
                    hint
                ));
            }
        }

        // In test mode, we don't produce WASM - just return empty
        if opts.test_mode {
            println!("✅ Tests completed successfully!");
            return Ok(Vec::new());
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
