use crate::languages::Language;
use crate::parser::{ParseError, parse_rust_params, parse_rust_type};
use crate::types::{CompileOptions, CompileTarget, FunctionSig, WitType};
use anyhow::Result;
use std::fs;
use std::process::Command;
use std::path::PathBuf;

pub struct Rust;

impl Rust {
    pub fn new() -> Self {
        Self
    }
    
    /// Compile to native binary (for Android, Linux, Windows targets)
    fn compile_native(&self, source: &str, opts: &CompileOptions) -> Result<Vec<u8>> {
        let target_triple = opts.target.target_triple();
        eprintln!("🔧 Native compilation target: {}", target_triple);
        
        // Determine if we can use serialport crate (desktop only, not Android)
        let is_android = opts.target == CompileTarget::Aarch64Android;
        let needs_serial = source.contains("serialport::") || source.contains("SerialPort::open");
        
        let serial_dep = if needs_serial && !is_android {
            "serialport = \"4.6\"\n"
        } else {
            ""
        };
        
        // For Android, build as shared library with JNI
        let cargo_toml = if is_android {
            format!(
                r#"
[workspace]

[package]
name = "poly_native"
version = "0.1.0"
edition = "2021"

[lib]
name = "poly_native"
crate-type = ["cdylib"]
path = "lib.rs"

[dependencies]
anyhow = "1.0"
jni = "0.21"

[profile.release]
opt-level = "s"
lto = false
strip = "none"
"#
            )
        } else {
            format!(
                r#"
[workspace]

[package]
name = "poly_native"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "poly_native"
path = "main.rs"

[dependencies]
anyhow = "1.0"
{serial_dep}
[profile.release]
opt-level = "z"
lto = true
strip = true
"#
            )
        };

        fs::write(opts.temp_dir.join("Cargo.toml"), &cargo_toml)?;
        
        // For Android target, we may need to configure the linker
        if is_android {
            self.setup_android_config(&opts.temp_dir)?;
            
            // Generate JNI wrapper library
            let jni_source = self.generate_jni_lib(source);
            fs::write(opts.temp_dir.join("lib.rs"), &jni_source)?;
            
            // Debug: save a copy for inspection
            let debug_path = std::path::Path::new("C:/Users/adria/.openclaw/workspace/tmp/debug_lib.rs");
            let _ = fs::write(debug_path, &jni_source);
        } else {
            // Write the source directly (no WASM wrappers needed)
            let main_rs = opts.temp_dir.join("main.rs");
            fs::write(&main_rs, source)?;
        }

        // Build
        let mut cmd = Command::new("cargo");
        cmd.current_dir(&opts.temp_dir);
        cmd.arg("build")
            .arg("--release")
            .arg(format!("--target={}", target_triple));

        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "Native compilation failed for target {}:\n{}",
                target_triple,
                stderr.lines().take(30).collect::<Vec<_>>().join("\n")
            ));
        }

        // Find output binary/library
        let binary_path = if is_android {
            // Android: shared library
            opts.temp_dir
                .join("target")
                .join(target_triple)
                .join("release")
                .join("libpoly_native.so")
        } else {
            let ext = opts.target.output_extension();
            let binary_name = if ext.is_empty() {
                "poly_native".to_string()
            } else {
                format!("poly_native.{}", ext)
            };
            opts.temp_dir
                .join("target")
                .join(target_triple)
                .join("release")
                .join(&binary_name)
        };

        if !binary_path.exists() {
            return Err(anyhow::anyhow!(
                "Expected binary not found at: {}",
                binary_path.display()
            ));
        }

        let binary_bytes = fs::read(&binary_path)?;
        let kind = if is_android { "library (.so)" } else { "binary" };
        eprintln!("✅ Native {}: {} bytes", kind, binary_bytes.len());
        
        Ok(binary_bytes)
    }
    
    /// Setup .cargo/config.toml for Android NDK
    fn setup_android_config(&self, temp_dir: &PathBuf) -> Result<()> {
        // Try to find Android NDK
        let ndk_path = self.find_android_ndk();
        
        let cargo_dir = temp_dir.join(".cargo");
        fs::create_dir_all(&cargo_dir)?;
        
        let config = if let Some(ndk) = ndk_path {
            // Find the linker in NDK
            let toolchain_dir = ndk.join("toolchains/llvm/prebuilt");
            let host_dir = if cfg!(windows) {
                "windows-x86_64"
            } else if cfg!(target_os = "macos") {
                "darwin-x86_64"
            } else {
                "linux-x86_64"
            };
            
            // On Windows, the linker wrapper has .cmd extension
            let linker_name = if cfg!(windows) {
                "aarch64-linux-android21-clang.cmd"
            } else {
                "aarch64-linux-android21-clang"
            };
            
            let linker = toolchain_dir
                .join(host_dir)
                .join("bin")
                .join(linker_name);
            
            format!(
                r#"[target.aarch64-linux-android]
linker = "{}"
"#,
                linker.display().to_string().replace("\\", "/")
            )
        } else {
            // No NDK found - user needs to configure manually
            eprintln!("⚠️  Android NDK not found. You may need to configure the linker manually.");
            eprintln!("   Set ANDROID_NDK_HOME or install NDK via Android Studio.");
            r#"# Android NDK not found - configure linker manually:
# [target.aarch64-linux-android]
# linker = "/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
"#.to_string()
        };
        
        fs::write(cargo_dir.join("config.toml"), config)?;
        Ok(())
    }
    
    /// Try to find Android NDK installation
    fn find_android_ndk(&self) -> Option<PathBuf> {
        // Check ANDROID_NDK_HOME first
        if let Ok(ndk) = std::env::var("ANDROID_NDK_HOME") {
            let path = PathBuf::from(&ndk);
            if path.exists() {
                return Some(path);
            }
        }
        
        // Check common NDK locations (these are directories containing version folders)
        let home = dirs::home_dir()?;
        let ndk_dirs = [
            home.join("Android/Sdk/ndk"), // Linux/Mac
            PathBuf::from("C:/Android/ndk"),
            PathBuf::from("C:/Users").join(whoami::username()).join("AppData/Local/Android/Sdk/ndk"),
        ];
        
        for ndk_dir in &ndk_dirs {
            // Check if the ndk directory exists and contains version folders
            if ndk_dir.exists() && ndk_dir.is_dir() {
                if let Ok(entries) = fs::read_dir(ndk_dir) {
                    let mut versions: Vec<_> = entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().is_dir())
                        // Filter to only version-like directories (start with digit)
                        .filter(|e| e.file_name().to_string_lossy().chars().next().map_or(false, |c| c.is_ascii_digit()))
                        .collect();
                    // Sort in descending order to get newest version first
                    versions.sort_by(|a, b| b.path().cmp(&a.path()));
                    if let Some(latest) = versions.first() {
                        eprintln!("📱 Found Android NDK: {}", latest.path().display());
                        return Some(latest.path());
                    }
                }
            }
        }
        
        None
    }
    
    /// Generate JNI wrapper library for Android
    fn generate_jni_lib(&self, source: &str) -> String {
        // Extract public functions from source (export fn becomes pub fn during preprocessing)
        // Match top-level pub fn (at start of line or after newline)
        let export_re = regex::Regex::new(r"(?m)^pub\s+fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^\{]+))?").unwrap();
        
        let mut jni_functions = String::new();
        for cap in export_re.captures_iter(source) {
            let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let params_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let ret_type = cap.get(3).map(|m| m.as_str().trim());
            
            // Parse parameters: "port: String, count: i32" -> [("port", "String"), ...]
            let params: Vec<(&str, &str)> = if params_str.trim().is_empty() {
                vec![]
            } else {
                params_str.split(',')
                    .filter_map(|p| {
                        let parts: Vec<&str> = p.trim().split(':').collect();
                        if parts.len() == 2 {
                            Some((parts[0].trim(), parts[1].trim()))
                        } else {
                            None
                        }
                    })
                    .collect()
            };
            
            // Generate JNI parameter declarations
            let jni_params: String = params.iter()
                .map(|(pname, ptype)| {
                    let jni_type = match *ptype {
                        "String" => "jni::sys::jstring",
                        "bool" => "jni::sys::jboolean",
                        "i32" => "jni::sys::jint",
                        "i64" => "jni::sys::jlong",
                        "f32" => "jni::sys::jfloat",
                        "f64" => "jni::sys::jdouble",
                        _ => "jni::sys::jstring",
                    };
                    format!("{}: {}", pname, jni_type)
                })
                .collect::<Vec<_>>()
                .join(", ");
            
            // Check if we need JNIEnv for String conversion
            let has_string_params = params.iter().any(|(_, ptype)| *ptype == "String");
            let needs_env = has_string_params || ret_type == Some("String");
            
            // Generate env wrapping if needed (mut for get_string calls)
            let env_wrap = if needs_env {
                "    let mut env = unsafe { JNIEnv::from_raw(env).unwrap() };\n"
            } else {
                ""
            };
            
            // Generate parameter conversion code (after env is wrapped)
            let param_conversions: String = params.iter()
                .filter(|(_, ptype)| *ptype == "String")
                .map(|(pname, _)| format!(
                    "    let {pname}: String = env.get_string(&jni::objects::JString::from_raw({pname})).map(|s| s.into()).unwrap_or_default();",
                    pname = pname
                ))
                .collect::<Vec<_>>()
                .join("\n");
            
            // Generate function call arguments
            let call_args: String = params.iter()
                .map(|(pname, _)| *pname)
                .collect::<Vec<_>>()
                .join(", ");
            
            // Generate JNI return type
            let (jni_ret, needs_return) = match ret_type {
                Some("String") => ("jstring", true),
                Some("bool") => ("jboolean", true),
                Some("i32") => ("jint", true),
                Some("i64") => ("jlong", true),
                Some("f32") => ("jfloat", true),
                Some("f64") => ("jdouble", true),
                _ => ("()", false),  // void -> unit type
            };
            
            // Generate the call and return
            let jni_call = match ret_type {
                Some("String") => format!(
                    r#"{env_wrap}{conversions}
    let result = {name}({args});
    match env.new_string(&result) {{
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }}"#, env_wrap = env_wrap, conversions = param_conversions, name = name, args = call_args),
                Some("bool") => format!(
                    r#"{env_wrap}{conversions}
    if {name}({args}) {{ 1 }} else {{ 0 }}"#, env_wrap = env_wrap, conversions = param_conversions, name = name, args = call_args),
                _ => format!(r#"{env_wrap}{conversions}
    {name}({args});"#, env_wrap = env_wrap, conversions = param_conversions, name = name, args = call_args),
            };
            
            // JNI name mangling: underscores become _1
            let jni_name = name.replace("_", "_1");
            
            // Build JNI parameter list (env, class, then user params)
            let full_params = if jni_params.is_empty() {
                "env: *mut jni::sys::JNIEnv, _class: jni::sys::jclass".to_string()
            } else {
                format!("env: *mut jni::sys::JNIEnv, _class: jni::sys::jclass, {}", jni_params)
            };
            
            // Return type clause
            let ret_clause = if needs_return {
                format!(" -> {}", jni_ret)
            } else {
                String::new()
            };
            
            jni_functions.push_str(&format!(r#"
#[no_mangle]
pub unsafe extern "C" fn Java_com_poly_app_MainActivity_{jni_name}(
    {params}
){ret_clause} {{
{jni_call}
}}
"#, jni_name = jni_name, params = full_params, ret_clause = ret_clause, jni_call = jni_call));
        }
        
        // Build the full library source
        let mut lib_source = String::from(r#"
use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::*;

"#);
        
        // Add the original source (with export fn -> pub fn)
        let processed = source
            .replace("export fn ", "pub fn ")
            .replace("fn main()", "fn _main()");  // Rename main
        lib_source.push_str(&processed);
        
        // Add JNI wrappers
        lib_source.push_str("\n// JNI Wrappers\n");
        lib_source.push_str(&jni_functions);
        
        lib_source
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
        // Check if this is a native target
        if opts.target.is_native() {
            return self.compile_native(source, opts);
        }
        
        // === WASM compilation (original logic) ===
        
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
