// Compile Python and Rust blocks to WASM

use crate::languages::find_language;
use crate::parser::ParsedFile;
use crate::types::CompileOptions;
use anyhow::{Result, anyhow};
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

    // First, collect all code by type and detect main functions
    let mut raw_rust_code = String::new();
    let mut python_blocks = Vec::new();
    let mut gpu_blocks = Vec::new(); // WGSL shaders
    let mut js_blocks = Vec::new(); // JS/JSX components
    let mut html_blocks = Vec::new(); // HTML entry points
    let mut css_blocks = Vec::new(); // rscss/css blocks
    let mut main_locations: Vec<(&str, &str)> = Vec::new(); // (language, block_preview)

    for block in &parsed.blocks {
        match block.lang_tag.as_str() {
            "rs" | "rust" | "main" => {
                // Detect Rust main: fn main()
                if block.code.contains("fn main(") {
                    main_locations.push(("rust", &block.code[..block.code.len().min(50)]));
                }
                raw_rust_code.push_str(&block.code);
                raw_rust_code.push('\n');
            }
            "py" | "python" => {
                // Detect Python main: def main():
                if block.code.contains("def main(") {
                    main_locations.push(("python", &block.code[..block.code.len().min(50)]));
                }
                python_blocks.push(block.code.clone());
            }
            "gpu" | "wgsl" => {
                gpu_blocks.push(block.code.clone());
            }
            "js" | "jsx" => {
                js_blocks.push(block.code.clone());
            }
            "ts" | "tsx" | "typescript" => {
                // TypeScript blocks - will be transpiled alongside JS
                // For browser, Babel handles TS transpilation
                js_blocks.push(block.code.clone());
            }
            "html" => {
                html_blocks.push(block.code.clone());
            }
            "rscss" | "css" => {
                css_blocks.push(block.code.clone());
            }
            "interface" => {
                // Already processed via parsed.interfaces
            }
            "types" => {
                // Already processed via parsed.interfaces (type declarations)
            }
            _ => {
                return Err(CompileError::UnknownLanguage(block.lang_tag.clone()));
            }
        }
    }

    // Validate main entry point
    let main_lang = match main_locations.len() {
        0 => {
            return Err(CompileError::Build(
                "No main function found. Add `fn main()` in a Rust block or `def main():` in a Python block.".to_string()
            ));
        }
        1 => main_locations[0].0,
        _ => {
            let locations: Vec<String> = main_locations
                .iter()
                .map(|(lang, preview)| format!("  - {} block: {}...", lang, preview.trim()))
                .collect();
            return Err(CompileError::Build(format!(
                "Multiple main functions found. Only one entry point is allowed:\n{}",
                locations.join("\n")
            )));
        }
    };

    eprintln!("📍 Entry point: {} main()", main_lang);

    // Generate interface code with knowledge of what's implemented
    let rs_interface =
        crate::interface::codegen::generate_rust_with_source(&parsed.interfaces, &raw_rust_code);

    // Merge all Python code for embedding
    let merged_python_code = python_blocks.join("\n");

    // Generate Python bridge functions (Rust functions that call Python via RustPython)
    let python_bridge = crate::interface::codegen::generate_python_bridge(
        &parsed.interfaces,
        &merged_python_code,
        &raw_rust_code,
    );

    // Prepend interface and Python bridge to Rust code
    let mut merged_rust_code = String::new();
    merged_rust_code.push_str(&rs_interface);
    merged_rust_code.push_str(&python_bridge);
    merged_rust_code.push_str(&raw_rust_code);

    // Preprocess: convert Polyglot visibility keywords to valid Rust syntax
    // - "export fn" -> "pub fn" (cross-file callable)
    // - "public fn" -> "pub fn" (FFI/external callable)
    // - "internal fn" -> "fn" (file-private, default)
    let merged_rust_code = merged_rust_code
        .replace("export fn ", "pub fn ")
        .replace("public fn ", "pub fn ")
        .replace("internal fn ", "fn ");

    // Compile merged Rust code as single unit (with embedded Python)
    if !merged_rust_code.trim().is_empty() {
        let rust_lang = find_language("rust").unwrap();
        let mut rust_opts = opts.clone();
        rust_opts.temp_dir = opts.temp_dir.join("rust_merged");
        rust_opts.main_lang = Some(main_lang.to_string()); // Pass main language info
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

    // =========================================================
    // WEB BUNDLE GENERATION (GPU, JS, CSS, HTML)
    // =========================================================

    // Extract Rust public constants for CSS interpolation
    let rust_consts = extract_rust_constants(&raw_rust_code);

    // Process rscss: interpolate @{CONST} with Rust values
    let processed_css = if !css_blocks.is_empty() {
        let raw_css = css_blocks.join("\n");
        interpolate_css_constants(&raw_css, &rust_consts)
    } else {
        String::new()
    };

    // Write GPU shaders (WGSL)
    if !gpu_blocks.is_empty() {
        let shaders = gpu_blocks.join("\n/* --- */\n");
        fs::write(opts.temp_dir.join("shaders.wgsl"), &shaders)?;
        eprintln!("📊 Generated: shaders.wgsl ({} bytes)", shaders.len());
    }

    // Write processed CSS
    if !processed_css.is_empty() {
        fs::write(opts.temp_dir.join("styles.css"), &processed_css)?;
        eprintln!("🎨 Generated: styles.css ({} bytes)", processed_css.len());
    }

    // Write JS/JSX
    if !js_blocks.is_empty() {
        let js_code = js_blocks.join("\n");
        fs::write(opts.temp_dir.join("app.js"), &js_code)?;
        eprintln!("📜 Generated: app.js ({} bytes)", js_code.len());
    }

    // Generate HTML entry point
    if !html_blocks.is_empty() {
        let html = html_blocks.join("\n");
        fs::write(opts.temp_dir.join("index.html"), &html)?;
        eprintln!("🌐 Generated: index.html");
    } else if !js_blocks.is_empty() || !css_blocks.is_empty() {
        // Auto-generate HTML if we have JS/CSS but no explicit HTML
        let auto_html = generate_index_html(!processed_css.is_empty(), !js_blocks.is_empty());
        fs::write(opts.temp_dir.join("index.html"), &auto_html)?;
        eprintln!("🌐 Generated: index.html (auto)");
    }

    // Link all modules together
    link_modules(&wasm_modules, opts)
}

/// Extract pub const NAME: &str = "VALUE"; from Rust code
fn extract_rust_constants(rust_code: &str) -> std::collections::HashMap<String, String> {
    use regex::Regex;
    let mut consts = std::collections::HashMap::new();

    // Match: pub const NAME: &str = "VALUE";
    let re = Regex::new(r#"pub\s+const\s+(\w+)\s*:\s*&str\s*=\s*"([^"]+)"\s*;"#).unwrap();
    for cap in re.captures_iter(rust_code) {
        if let (Some(name), Some(value)) = (cap.get(1), cap.get(2)) {
            consts.insert(name.as_str().to_string(), value.as_str().to_string());
        }
    }

    // Match enum variants for @{Enum::Variant} syntax
    let enum_re = Regex::new(r"pub\s+enum\s+(\w+)\s*\{([^}]+)\}").unwrap();
    for cap in enum_re.captures_iter(rust_code) {
        if let (Some(enum_name), Some(body)) = (cap.get(1), cap.get(2)) {
            for variant in body.as_str().split(',') {
                let variant = variant.trim().split('(').next().unwrap_or("").trim();
                if !variant.is_empty() && !variant.starts_with("//") {
                    // Store as EnumName::Variant -> variant (kebab-case for CSS)
                    let key = format!("{}::{}", enum_name.as_str(), variant);
                    let value = variant
                        .chars()
                        .flat_map(|c| {
                            if c.is_uppercase() {
                                vec!['-', c.to_lowercase().next().unwrap()]
                            } else {
                                vec![c]
                            }
                        })
                        .collect::<String>()
                        .trim_start_matches('-')
                        .to_string();
                    consts.insert(key, value);
                }
            }
        }
    }

    consts
}

/// Replace @{CONST_NAME} with actual values in CSS
fn interpolate_css_constants(
    css: &str,
    consts: &std::collections::HashMap<String, String>,
) -> String {
    use regex::Regex;
    let re = Regex::new(r"@\{([^}]+)\}").unwrap();

    re.replace_all(css, |caps: &regex::Captures| {
        let key = &caps[1];
        consts.get(key).cloned().unwrap_or_else(|| {
            eprintln!("⚠️  Warning: CSS constant @{{{}}} not found in Rust", key);
            format!("/* UNDEFINED: {} */", key)
        })
    })
    .to_string()
}

/// Generate minimal HTML entry point
fn generate_index_html(has_css: bool, has_js: bool) -> String {
    let mut html = String::from("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("    <meta charset=\"UTF-8\">\n");
    html.push_str(
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
    );
    html.push_str("    <title>Polyglot App</title>\n");
    if has_css {
        html.push_str("    <link rel=\"stylesheet\" href=\"styles.css\">\n");
    }
    html.push_str("</head>\n<body>\n");
    html.push_str("    <div id=\"root\"></div>\n");
    html.push_str("    <script type=\"module\">\n");
    html.push_str("        import init from './pkg/poly_cell.js';\n");
    html.push_str("        await init();\n");
    if has_js {
        html.push_str("        import('./app.js');\n");
    }
    html.push_str("    </script>\n");
    html.push_str("</body>\n</html>\n");
    html
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

/// Generate a single self-contained HTML file with all assets inlined
/// - WASM binary is base64 encoded
/// - CSS is <style> inlined  
/// - JS is <script> inlined
/// - WGSL shaders are embedded for WebGPU
pub fn generate_inline_bundle(
    wasm_bytes: &[u8],
    css: &str,
    js: &str,
    wgsl: &str,
    html_template: Option<&str>,
    title: &str,
) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let wasm_base64 = STANDARD.encode(wasm_bytes);

    let mut html = String::with_capacity(wasm_base64.len() + css.len() + js.len() + 8192);

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("    <meta charset=\"UTF-8\">\n");
    html.push_str(
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
    );
    html.push_str(&format!("    <title>{}</title>\n", title));

    // Inject React & Babel for JSX compilation in the browser
    html.push_str(
        "    <script src=\"https://unpkg.com/react@18/umd/react.production.min.js\"></script>\n",
    );
    html.push_str("    <script src=\"https://unpkg.com/react-dom@18/umd/react-dom.production.min.js\"></script>\n");
    html.push_str(
        "    <script src=\"https://unpkg.com/@babel/standalone/babel.min.js\"></script>\n",
    );
    // Parquet parser for datasets
    html.push_str(
        "    <script src=\"https://unpkg.com/hyparquet@1.7.2/dist/hyparquet.min.js\"></script>\n",
    );

    // Inline CSS
    if !css.is_empty() {
        html.push_str("    <style>\n");
        html.push_str(css);
        html.push_str("\n    </style>\n");
    }

    html.push_str("</head>\n<body>\n");
    html.push_str("    <div id=\"root\"></div>\n\n");

    // WGSL shaders as data (for WebGPU)
    if !wgsl.is_empty() {
        html.push_str("    <script id=\"wgsl-shaders\" type=\"x-shader/wgsl\">\n");
        html.push_str(wgsl);
        html.push_str("\n    </script>\n\n");
    }

    // WASM loader (Standard JS Module)
    // NOTE: This must be separate from the JSX code because browsers handle them differently.
    html.push_str("    <script type=\"text/javascript\">\n");
    html.push_str("    // Polyglot Single-File Bundle\n");
    html.push_str("    // WASM is base64-encoded and loaded inline\n\n");

    html.push_str("    const wasmBase64 = '");
    html.push_str(&wasm_base64);
    html.push_str("';\n\n");

    html.push_str(
        r#"
    // Decode base64 WASM
    function base64ToBytes(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    
    // Initialize WASM module
    async function initWasm() {
        try {
            const wasmBytes = base64ToBytes(wasmBase64);
            const { instance } = await WebAssembly.instantiate(wasmBytes, {
                env: {
                    // WASI stubs for browser
                    fd_write: () => 0,
                },
                wasi_snapshot_preview1: {
                    // Implement basic stdout for println!
                    fd_write: (fd, iovs_ptr, iovs_len, nwritten_ptr) => {
                        const mem = new DataView(instance.exports.memory.buffer);
                        let written = 0;
                        for (let i = 0; i < iovs_len; i++) {
                            const ptr = iovs_ptr + i * 8;
                            const buf = mem.getUint32(ptr, true);
                            const bufLen = mem.getUint32(ptr + 4, true);
                            
                            // Decode string and log if stdout (1) or stderr (2)
                            if (fd === 1 || fd === 2) {
                                const chunk = new Uint8Array(instance.exports.memory.buffer, buf, bufLen);
                                const str = new TextDecoder().decode(chunk);
                                console.log(str.replace(/\n$/, '')); // Remove trailing newline for console.log
                            }
                            
                            written += bufLen;
                        }
                        mem.setUint32(nwritten_ptr, written, true);
                        return 0; // Success
                    },
                    fd_close: () => 0,
                    fd_seek: () => 0,
                    proc_exit: () => {},
                    environ_sizes_get: () => 0,
                    environ_get: () => 0,
                }
            });
            
            
            // Expose logic to window.polyglot
            // NOTE: instance.exports is often read-only/frozen, so we must clone it to add aliases
            window.polyglot = Object.create(null);
            
            // Copy raw exports
            for (const key in instance.exports) {
                window.polyglot[key] = instance.exports[key];
            }
            
            console.log('Polyglot WASM loaded:', Object.keys(window.polyglot));
            
            // Auto-map __export_foo to foo to handle mangled names from codegen
            for (const key in window.polyglot) {
                if (key.startsWith('__export_')) {
                    const newKey = key.replace('__export_', '');
                    window.polyglot[newKey] = window.polyglot[key];
                    console.log(`Mapped ${key} -> window.polyglot.${newKey}`);
                }
            }
            
            // Call main if available
            if (window.polyglot._start) {
                window.polyglot._start();
            }
            
            // Signal readiness for other scripts
            window.polyglotReady = true;
            if (window.onPolyglotReady) window.onPolyglotReady();
            
            // ========================================
            // Array Passing Helpers for WASM
            // ========================================
            // Requires Rust to export __malloc and __free
            
            window.polyglot.passArrayU32 = function(arr) {
                const len = arr.length;
                const ptr = window.polyglot.__malloc(len * 4);
                const view = new Uint32Array(window.polyglot.memory.buffer, ptr, len);
                view.set(arr);
                return [ptr, len];
            };
            
            window.polyglot.passArrayF32 = function(arr) {
                const len = arr.length;
                const ptr = window.polyglot.__malloc(len * 4);
                const view = new Float32Array(window.polyglot.memory.buffer, ptr, len);
                view.set(arr);
                return [ptr, len];
            };
            
            window.polyglot.freeArray = function(ptr, len) {
                if (window.polyglot.__free) {
                    window.polyglot.__free(ptr, len * 4);
                }
            };
            
            return instance;
        } catch (e) {
            console.error("WASM init failed:", e);
        }
    }
    
    // Get WGSL shaders
    function getShaders() {
        const el = document.getElementById('wgsl-shaders');
        return el ? el.textContent : '';
    }
    
    window.polyglotShaders = getShaders;
    
    // Start loading immediately
    window.wasmPromise = initWasm();
    
"#,
    );
    html.push_str("    </script>\n\n");

    // Inline app JS (Babel/JSX)
    if !js.is_empty() {
        html.push_str("    <script type=\"text/babel\">\n");
        html.push_str("    // Application code (JSX)\n");
        html.push_str("    // Wait for WASM before rendering if needed\n");
        html.push_str("    (async () => {\n");
        html.push_str("        if (!window.polyglotReady) await window.wasmPromise;\n\n");
        html.push_str(js);
        html.push_str("\n    })();\n");
        html.push_str("    </script>\n");
    }

    html.push_str("</body>\n</html>\n");

    html
}

/// Public function to create inline bundle from temp directory outputs
pub fn bundle_to_single_file(
    temp_dir: &std::path::Path,
    wasm_bytes: &[u8],
    title: &str,
) -> Result<String, std::io::Error> {
    let css = fs::read_to_string(temp_dir.join("styles.css")).unwrap_or_default();
    let js = fs::read_to_string(temp_dir.join("app.js")).unwrap_or_default();
    let wgsl = fs::read_to_string(temp_dir.join("shaders.wgsl")).unwrap_or_default();

    Ok(generate_inline_bundle(
        wasm_bytes, &css, &js, &wgsl, None, title,
    ))
}
