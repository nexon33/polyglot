// Compile Python and Rust blocks to WASM or native binaries

use crate::languages::find_language;
use crate::parser::ParsedFile;
use crate::types::CompileOptions;
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::sync::LazyLock;

/// Deduplicate `use` statements in merged Rust code
/// 
/// When multiple blocks are merged, they may contain duplicate imports.
/// This function:
/// 1. Expands braced imports: `use foo::{A, B};` → `use foo::A; use foo::B;`
/// 2. Deduplicates individual imports
/// 3. Places all imports at the top of the file
fn deduplicate_use_statements(code: &str) -> String {
    let mut individual_imports: HashSet<String> = HashSet::new();
    let mut other_lines: Vec<&str> = Vec::new();
    
    for line in code.lines() {
        let trimmed = line.trim();
        
        // Match use statements
        if trimmed.starts_with("use ") && trimmed.ends_with(';') {
            // Check for braced imports: use foo::{A, B, C};
            if let Some(brace_start) = trimmed.find("::{") {
                if let Some(brace_end) = trimmed.rfind("};") {
                    let prefix = &trimmed[4..brace_start]; // "foo::bar" from "use foo::bar::{X, Y};"
                    let items = &trimmed[brace_start + 3..brace_end]; // "X, Y"
                    
                    // Split items and create individual imports
                    for item in items.split(',') {
                        let item = item.trim();
                        if !item.is_empty() {
                            // Handle nested braces like `use foo::{bar::{X, Y}};` - just keep as-is
                            if item.contains('{') {
                                individual_imports.insert(trimmed.to_string());
                            } else {
                                individual_imports.insert(format!("use {}::{};", prefix, item));
                            }
                        }
                    }
                    continue;
                }
            }
            
            // Check for braced imports without :: prefix: use {A, B};
            if trimmed.starts_with("use {") && trimmed.ends_with("};") {
                // Rare case, just keep as-is
                individual_imports.insert(trimmed.to_string());
                continue;
            }
            
            // Simple import: use foo::bar;
            individual_imports.insert(trimmed.to_string());
        } else if trimmed.starts_with("use ") {
            // Multi-line use statement - keep in other_lines
            other_lines.push(line);
        } else {
            other_lines.push(line);
        }
    }
    
    // Build result: deduplicated uses first, then rest of code
    let mut result = String::new();
    
    // Sort use statements for consistent output
    let mut sorted_uses: Vec<_> = individual_imports.into_iter().collect();
    sorted_uses.sort();
    
    for use_stmt in sorted_uses {
        result.push_str(&use_stmt);
        result.push('\n');
    }
    
    if !result.is_empty() {
        result.push('\n');
    }
    
    // Add rest of code
    let other_code = other_lines.join("\n");
    result.push_str(&other_code);
    
    result
}

/// Sort merged Rust code so that `fn main()` appears last.
/// This avoids forward-reference issues when merging multiple blocks.
fn sort_main_last(code: &str) -> String {
    // Split into logical chunks: we look for top-level fn definitions
    // and move any chunk containing `fn main(` to the end
    let mut before_main = Vec::new();
    let mut main_chunk = Vec::new();
    let mut current_chunk = Vec::new();
    let mut in_main = false;
    let mut brace_depth: i32 = 0;

    for line in code.lines() {
        let trimmed = line.trim();

        // Detect start of fn main
        if !in_main && (trimmed.starts_with("fn main(") || trimmed.starts_with("pub fn main(")
            || trimmed.starts_with("async fn main(") || trimmed.starts_with("pub async fn main("))
        {
            // Push accumulated non-main lines
            if !current_chunk.is_empty() {
                before_main.push(current_chunk.join("\n"));
                current_chunk = Vec::new();
            }
            in_main = true;
            brace_depth = 0;
        }

        if in_main {
            for ch in line.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }
            main_chunk.push(line);
            if brace_depth <= 0 && main_chunk.len() > 1 {
                // End of main function body
                in_main = false;
            }
        } else {
            current_chunk.push(line);
        }
    }

    // Push remaining lines
    if !current_chunk.is_empty() {
        before_main.push(current_chunk.join("\n"));
    }

    let mut result = before_main.join("\n");
    if !main_chunk.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&main_chunk.join("\n"));
    }
    result
}

/// Sort merged JS/TS code so `function main()` and the `main()` call appear last.
/// This avoids forward-reference issues when merging multiple blocks.
fn sort_js_main_last(code: &str) -> String {
    let mut before_main = Vec::new();
    let mut main_chunk = Vec::new();
    let mut main_call_line: Option<String> = None;
    let mut in_main = false;
    let mut brace_depth: i32 = 0;

    for line in code.lines() {
        let trimmed = line.trim();

        // Detect standalone main() call (not inside a function definition)
        if !in_main && (trimmed == "main();" || trimmed == "main()") {
            main_call_line = Some(line.to_string());
            continue;
        }

        // Detect start of function main
        if !in_main && (trimmed.starts_with("function main(")
            || trimmed.starts_with("export function main(")
            || trimmed.starts_with("async function main(")
            || trimmed.starts_with("export async function main("))
        {
            in_main = true;
            brace_depth = 0;
        }

        if in_main {
            for ch in line.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }
            main_chunk.push(line);
            if brace_depth <= 0 && main_chunk.len() > 1 {
                in_main = false;
            }
        } else {
            before_main.push(line);
        }
    }

    let mut result = before_main.join("\n");
    if !main_chunk.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&main_chunk.join("\n"));
    }
    if let Some(call) = main_call_line {
        result.push('\n');
        result.push_str(&call);
    }
    result.push('\n');
    result
}

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

/// Result of compilation, may include binary and/or web assets
#[derive(Debug, Default)]
pub struct CompileOutput {
    /// The compiled binary (WASM, native, or merged source for script targets)
    pub binary: Vec<u8>,
    /// Whether this includes web assets (JS/HTML/CSS)
    pub has_web_assets: bool,
    /// Paths to generated web assets (relative to temp_dir)
    pub web_assets: Vec<String>,
    /// Override output extension (e.g. "ts" for TypeScript, "js" for JavaScript)
    /// If None, uses the target's default extension
    pub output_extension: Option<String>,
}

pub fn compile(parsed: &ParsedFile, opts: &CompileOptions) -> Result<CompileOutput, CompileError> {
    fs::create_dir_all(&opts.temp_dir)?;

    let mut wasm_modules = Vec::new();

    // First, collect all code by type and detect main functions
    let mut rust_files: Vec<(Option<String>, String)> = Vec::new(); // (path, code) for Rust blocks
    let mut python_blocks = Vec::new();
    let mut gpu_blocks = Vec::new(); // WGSL shaders
    let mut js_blocks = Vec::new(); // JS/JSX components
    let mut html_blocks = Vec::new(); // HTML entry points
    let mut css_blocks = Vec::new(); // rscss/css blocks
    let mut test_blocks = Vec::new(); // #[test] blocks
    let mut static_files: Vec<(String, String, String)> = Vec::new(); // (lang, path, content) for non-compiled blocks
    let mut main_locations: Vec<(&str, &str)> = Vec::new(); // (language, block_preview)

    for block in &parsed.blocks {
        match block.lang_tag.as_str() {
            "rs" | "rust" | "main" | "verified" => {
                // Detect Rust main: fn main()
                if block.code.contains("fn main(") {
                    main_locations.push(("rust", &block.code[..block.code.len().min(50)]));
                }
                // Get output path from options if present (e.g., #[rust:src/main.rs])
                let output_path = block.options.keys().next().cloned();
                rust_files.push((output_path, block.code.clone()));
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
            "js" | "jsx" | "javascript" => {
                // Detect JS main: function main()
                if block.code.contains("function main(") {
                    main_locations.push(("javascript", &block.code[..block.code.len().min(50)]));
                }
                js_blocks.push(block.code.clone());
            }
            "ts" | "tsx" | "typescript" => {
                // Detect TS main: function main()
                if block.code.contains("function main(") {
                    main_locations.push(("typescript", &block.code[..block.code.len().min(50)]));
                }
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
            "test" => {
                if opts.test_mode {
                    test_blocks.push(block.code.clone());
                }
            }
            "interface" => {
                // Already processed via parsed.interfaces
            }
            "types" => {
                // Already processed via parsed.interfaces (type declarations)
            }
            // Static/config blocks - not compiled, but may be written to output
            "md" | "markdown" | "toml" | "json" | "yaml" | "yml" | "txt" | "cfg" | "ini" | "xml"
            | "env" | "dockerfile" | "makefile" | "sh" | "bat" | "ps1" | "sql" | "doc" => {
                // Extract output path from options if present (e.g., #[md:README.md])
                let output_path = block.options.keys().next().cloned().unwrap_or_default();
                static_files.push((block.lang_tag.clone(), output_path, block.code.clone()));
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
                "No main function found. Add `fn main()` in a Rust block, `def main():` in a Python block, or `function main()` in a JS/TS block.".to_string()
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

    // ── JavaScript/TypeScript compilation path ────────────────────────────
    // When the main entry point is in a JS/TS block, merge all JS/TS blocks
    // into a single file and return it as the output (no Rust/WASM compilation).
    if main_lang == "javascript" || main_lang == "typescript" {
        let is_ts = main_lang == "typescript";
        let ext = if is_ts { "ts" } else { "js" };

        // Deduplicate ES import statements and merge blocks
        let mut seen_imports: HashSet<String> = HashSet::new();
        let mut import_lines: Vec<String> = Vec::new();
        let mut body_lines: Vec<String> = Vec::new();

        for block_code in &js_blocks {
            for line in block_code.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("import ") {
                    if seen_imports.insert(trimmed.to_string()) {
                        import_lines.push(line.to_string());
                    }
                } else {
                    body_lines.push(line.to_string());
                }
            }
            body_lines.push(String::new()); // blank line between blocks
        }

        let mut merged = String::new();
        merged.push_str(&format!("// Auto-generated by polyglot compiler ({})\n\n", main_lang));
        for imp in &import_lines {
            merged.push_str(imp);
            merged.push('\n');
        }
        if !import_lines.is_empty() {
            merged.push('\n');
        }
        merged.push_str(&body_lines.join("\n"));

        // Sort so function main() is at the end, followed by the main() call
        let merged = sort_js_main_last(&merged);

        let out_file = opts.temp_dir.join(format!("main.{}", ext));
        fs::write(&out_file, &merged)?;
        eprintln!("📜 Generated: main.{} ({} lines)", ext, merged.lines().count());

        // Write static files (package.json etc.) if provided
        for (_lang, path, content) in &static_files {
            if !path.is_empty() {
                let file_path = opts.temp_dir.join(path);
                if let Some(parent) = file_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&file_path, content)?;
                eprintln!("📄 Generated: {} ({} bytes)", path, content.len());
            }
        }

        // Auto-generate package.json from poly.toml if not already provided
        let has_pkg_json = static_files.iter().any(|(_, p, _)| p == "package.json")
            || opts.temp_dir.join("package.json").exists();
        if !has_pkg_json {
            if let Some(source_path) = &opts.source_path {
                let manifest = crate::manifest::Manifest::load_for_file(source_path);
                if let Some(manifest) = manifest {
                    let pkg_json = manifest.generate_package_json();
                    if !pkg_json.is_empty() {
                        fs::write(opts.temp_dir.join("package.json"), &pkg_json)?;
                        eprintln!("📄 Generated: package.json (from poly.toml)");
                    }
                }
            }
        }

        // Copy web assets (HTML files)
        for html in &html_blocks {
            fs::write(opts.temp_dir.join("index.html"), html)?;
            eprintln!("🌐 Generated: index.html");
        }

        // For host target, also copy any source-adjacent web files
        if let Some(source_path) = &opts.source_path {
            let src_dir = source_path.parent().unwrap_or(std::path::Path::new("."));
            let web_dir = src_dir.join("web");
            if web_dir.exists() {
                let target_web = opts.temp_dir.clone();
                if let Ok(entries) = fs::read_dir(&web_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            let fname = path.file_name().unwrap();
                            let dst = target_web.join(fname);
                            fs::copy(&path, &dst)?;
                            eprintln!("📄 Copied: {}", fname.to_string_lossy());
                        }
                    }
                }
            }
        }

        return Ok(CompileOutput {
            binary: merged.into_bytes(),
            has_web_assets: !html_blocks.is_empty(),
            web_assets: if !html_blocks.is_empty() { vec!["index.html".to_string()] } else { vec![] },
            output_extension: Some(ext.to_string()),
        });
    }

    // Determine if this is a multi-file Rust project
    // Multi-file if we have blocks with different paths (e.g., src/main.rs, src/stack.rs)
    let unique_paths: std::collections::HashSet<_> = rust_files.iter()
        .filter_map(|(path, _)| path.as_ref())
        .collect();
    let is_multi_file = unique_paths.len() > 1;

    // Merge all Rust code for interface generation (even in multi-file mode)
    let raw_rust_code: String = rust_files.iter().map(|(_, code)| code.as_str()).collect::<Vec<_>>().join("\n");

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

    // Phase 26: Parse @implements decorators from foreign language blocks
    let mut all_foreign_impls = Vec::new();

    // Collect foreign implementations from Python blocks
    for py_code in &python_blocks {
        let impls = crate::interface::foreign_impls::parse_implements_decorators(py_code, "python");
        all_foreign_impls.extend(impls);
    }

    // Collect foreign implementations from TypeScript/JavaScript blocks
    for block in &parsed.blocks {
        match block.lang_tag.as_str() {
            "ts" | "tsx" | "typescript" => {
                let impls = crate::interface::foreign_impls::parse_implements_decorators(&block.code, "typescript");
                all_foreign_impls.extend(impls);
            }
            "js" | "jsx" | "javascript" => {
                let impls = crate::interface::foreign_impls::parse_implements_decorators(&block.code, "javascript");
                all_foreign_impls.extend(impls);
            }
            _ => {}
        }
    }

    // Extract traits from interfaces for stub generation
    let traits: Vec<_> = parsed.interfaces.iter()
        .filter_map(|item| {
            if let crate::interface::parser::InterfaceItem::Trait(t) = item {
                Some(t.clone())
            } else {
                None
            }
        })
        .collect();

    // Generate Rust stubs for foreign implementations
    let foreign_stubs = crate::interface::foreign_impls::generate_foreign_stubs(&all_foreign_impls, &traits);

    // Handle multi-file vs single-file Rust compilation
    if is_multi_file {
        // Multi-file project: write each file to its designated path
        eprintln!("📁 Multi-file Rust project detected ({} files)", unique_paths.len());

        let _rust_lang = find_language("rust").unwrap();
        let mut rust_opts = opts.clone();
        rust_opts.temp_dir = opts.temp_dir.join("rust_project");
        rust_opts.main_lang = Some(main_lang.to_string());
        fs::create_dir_all(&rust_opts.temp_dir)?;

        // Write each Rust file to its path
        for (path_opt, code) in &rust_files {
            let file_path = if let Some(path) = path_opt {
                rust_opts.temp_dir.join(path)
            } else {
                rust_opts.temp_dir.join("lib.rs")
            };

            // Create parent directories
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Preprocess: convert Polyglot visibility keywords
            let processed_code = code
                .replace("export fn ", "pub fn ")
                .replace("public fn ", "pub fn ")
                .replace("internal fn ", "fn ");

            fs::write(&file_path, &processed_code)?;
            eprintln!("  📄 {}", file_path.strip_prefix(&rust_opts.temp_dir).unwrap_or(&file_path).display());
        }

        // Write static files (toml, json, etc.) to project directory
        for (_lang, path, content) in &static_files {
            if !path.is_empty() {
                let file_path = rust_opts.temp_dir.join(path);
                if let Some(parent) = file_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // For Cargo.toml, ensure it has [workspace] to be independent from parent
                let final_content = if path == "Cargo.toml" {
                    if !content.contains("[workspace]") {
                        format!("[workspace]\n\n{}", content)
                    } else {
                        content.clone()
                    }
                } else {
                    content.clone()
                };

                fs::write(&file_path, final_content)?;
                eprintln!("  📄 {}", path);
            }
        }

        // Generate Cargo.toml if not provided as a static file
        let has_cargo_toml = static_files.iter().any(|(_, p, _)| p == "Cargo.toml")
            || rust_opts.temp_dir.join("Cargo.toml").exists();
        if !has_cargo_toml {
            let manifest = opts.source_path.as_ref()
                .and_then(|p| crate::manifest::Manifest::load_for_file(p));
            let manifest_deps = manifest.as_ref()
                .map(|m| m.rust_dependencies_toml())
                .unwrap_or_default();
            // Auto-detect if no manifest
            let auto_deps = if manifest_deps.is_empty() {
                crate::languages::rust::Rust::detect_dependencies_from_code(&raw_rust_code)
            } else {
                String::new()
            };
            let all_deps = format!("{}{}", manifest_deps,
                if !manifest_deps.is_empty() && !auto_deps.is_empty() { "\n" } else { "" });
            let all_deps = format!("{}{}", all_deps, auto_deps);

            let pkg_name = opts.source_path.as_ref()
                .and_then(|p| p.file_stem())
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "poly_project".to_string())
                .replace(|c: char| !c.is_alphanumeric() && c != '_' && c != '-', "_");

            let cargo_toml = format!(
                r#"[workspace]

[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "{name}"
path = "src/main.rs"

[dependencies]
{deps}
"#,
                name = pkg_name,
                deps = all_deps
            );
            fs::write(rust_opts.temp_dir.join("Cargo.toml"), &cargo_toml)?;
            eprintln!("  📄 Cargo.toml (auto-generated)");
        }

        // Compile the multi-file project using cargo directly
        // (Don't use rust_lang.compile() as it overwrites with its own lib.rs)
        let target_triple = opts.target.target_triple();
        eprintln!("🔨 Running cargo build (target: {})...", target_triple);

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&rust_opts.temp_dir);

        // Only set WASM-specific RUSTFLAGS for WASM targets
        if !opts.target.is_native() {
            cmd.env("RUSTFLAGS", "-C target-feature=+simd128");
        }

        cmd.arg("build")
            .arg(format!("--target={}", target_triple));

        if opts.release {
            cmd.arg("--release");
        }

        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{}", stderr);
            return Err(CompileError::Build(format!(
                "Cargo build failed:\n{}",
                stderr.lines().take(30).collect::<Vec<_>>().join("\n")
            )));
        }

        // Find the output binary
        let profile_dir = if opts.release { "release" } else { "debug" };
        let output_dir = rust_opts.temp_dir
            .join("target")
            .join(target_triple)
            .join(profile_dir);

        // Look for output file based on target type
        let output_ext = opts.target.output_extension();
        let output_file = if output_ext == "wasm" {
            // WASM: look for any .wasm file
            fs::read_dir(&output_dir)?
                .filter_map(|e| e.ok())
                .find(|e| e.path().extension().map_or(false, |ext| ext == "wasm"))
                .map(|e| e.path())
                .ok_or_else(|| CompileError::Build("No WASM output found".to_string()))?
        } else if output_ext == "exe" {
            // Windows: look for .exe files
            fs::read_dir(&output_dir)?
                .filter_map(|e| e.ok())
                .find(|e| e.path().extension().map_or(false, |ext| ext == "exe"))
                .map(|e| e.path())
                .ok_or_else(|| CompileError::Build("No native binary output found".to_string()))?
        } else {
            // Linux/Android: look for extensionless executable files
            fs::read_dir(&output_dir)?
                .filter_map(|e| e.ok())
                .find(|e| {
                    let path = e.path();
                    path.extension().is_none() && path.is_file()
                })
                .map(|e| e.path())
                .ok_or_else(|| CompileError::Build("No native binary output found".to_string()))?
        };

        let binary_bytes = fs::read(&output_file)?;
        wasm_modules.push(binary_bytes);

        // Clear static_files that were already written to avoid duplication
        static_files.retain(|(_, path, _)| path.is_empty());
    } else {
        // Single-file project: merge all code into one file (original behavior)
        let mut merged_rust_code = String::new();

        // For native targets, we skip polyglot-specific imports and just use raw code
        if opts.target.is_native() {
            merged_rust_code.push_str("// Auto-generated by polyglot compiler (native target)\n\n");

            // Include interface trait definitions (from #[interface] blocks)
            merged_rust_code.push_str(&rs_interface);

            // Include foreign implementation stubs (JS/TS @implements → JsRuntime calls)
            merged_rust_code.push_str(&foreign_stubs);

            // Sort blocks so fn main() is last (avoids forward-reference issues)
            let sorted_code = sort_main_last(&raw_rust_code);
            // Deduplicate use statements when merging multiple blocks
            let deduped_code = deduplicate_use_statements(&sorted_code);
            merged_rust_code.push_str(&deduped_code);

            // Check for verified execution markers and process
            if crate::verified::needs_verified_support(&parsed.blocks) {
                let verified_result =
                    crate::verified::verified_codegen::process_verified_block(&merged_rust_code);
                merged_rust_code = verified_result.code;

                // Report determinism violations as compiler warnings
                for err in &verified_result.errors {
                    eprintln!("  [verified] {}", err);
                }
            }
        } else {
            // WASM targets: Auto-import polyglot macros for .poly files
            merged_rust_code.push_str("// Auto-generated by polyglot compiler\n");
            merged_rust_code
                .push_str("use polyglot_macros::{js, py, ts, cuda, sql, gpu, poly_bridge};\n\n");

            // Inject host_imports module for host target
            if opts.target == crate::types::CompileTarget::Host {
                merged_rust_code.push_str("// Host imports for Node.js native access\n");
                merged_rust_code.push_str(include_str!("host_imports_injectable.rs"));
                merged_rust_code.push_str("\n\n");
            }

            merged_rust_code.push_str(&rs_interface);
            merged_rust_code.push_str(&python_bridge);
            merged_rust_code.push_str(&foreign_stubs);
            merged_rust_code.push_str(&raw_rust_code);
        }

        // Preprocess: convert Polyglot visibility keywords to valid Rust syntax
        let mut merged_rust_code = merged_rust_code
            .replace("export fn ", "pub fn ")
            .replace("public fn ", "pub fn ")
            .replace("internal fn ", "fn ");

        if opts.test_mode && !test_blocks.is_empty() {
            merged_rust_code.push_str("\n#[cfg(test)]\nmod poly_tests {\n    use super::*;\n");
            for block in test_blocks {
                // Add #[test] attribute to each fn definition
                let with_test_attr = block.replace("fn ", "#[test]\n    fn ");
                merged_rust_code.push_str("    ");
                merged_rust_code.push_str(&with_test_attr);
                merged_rust_code.push('\n');
            }
            merged_rust_code.push_str("}\n");
        }

        // Compile merged Rust code as single unit (with embedded Python)
        if !merged_rust_code.trim().is_empty() {
            let rust_lang = find_language("rust").unwrap();
            let mut rust_opts = opts.clone();
            rust_opts.temp_dir = opts.temp_dir.join("rust_merged");
            rust_opts.main_lang = Some(main_lang.to_string());
            fs::create_dir_all(&rust_opts.temp_dir)?;

            let wasm = rust_lang.compile(&merged_rust_code, &rust_opts)?;
            wasm_modules.push(wasm);
        }
    }

    // In test mode, we're done after running tests - skip artifact generation
    if opts.test_mode {
        return Ok(CompileOutput::default());
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

    // Write static/config files (md, toml, json, yaml, etc.)
    for (lang, path, content) in &static_files {
        let filename = if !path.is_empty() {
            path.clone()
        } else {
            // Default filename based on language
            match lang.as_str() {
                "md" | "markdown" => "README.md".to_string(),
                "toml" => "config.toml".to_string(),
                "json" => "config.json".to_string(),
                "yaml" | "yml" => "config.yaml".to_string(),
                "txt" => "output.txt".to_string(),
                "env" => ".env".to_string(),
                "dockerfile" => "Dockerfile".to_string(),
                "makefile" => "Makefile".to_string(),
                "sh" => "script.sh".to_string(),
                "bat" => "script.bat".to_string(),
                "ps1" => "script.ps1".to_string(),
                "sql" => "query.sql".to_string(),
                _ => format!("output.{}", lang),
            }
        };
        let output_path = opts.temp_dir.join(&filename);

        // Create parent directories if the path contains them
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&output_path, content)?;
        eprintln!("📄 Generated: {} ({} bytes)", filename, content.len());
    }

    // Track which web assets were generated
    let mut web_assets = Vec::new();
    if opts.temp_dir.join("index.html").exists() {
        web_assets.push("index.html".to_string());
    }
    if opts.temp_dir.join("app.js").exists() {
        web_assets.push("app.js".to_string());
    }
    if opts.temp_dir.join("styles.css").exists() {
        web_assets.push("styles.css".to_string());
    }
    if opts.temp_dir.join("shaders.wgsl").exists() {
        web_assets.push("shaders.wgsl".to_string());
    }
    
    let has_web_assets = !web_assets.is_empty();

    // Link all modules together
    let binary = link_modules(&wasm_modules, opts)?;
    
    Ok(CompileOutput {
        binary,
        has_web_assets,
        web_assets,
        output_extension: None,
    })
}

/// Extract pub const NAME: &str = "VALUE"; from Rust code
fn extract_rust_constants(rust_code: &str) -> std::collections::HashMap<String, String> {
    use regex::Regex;
    static CONST_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"pub\s+const\s+(\w+)\s*:\s*&str\s*=\s*"([^"]+)"\s*;"#).unwrap()
    });
    static ENUM_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"pub\s+enum\s+(\w+)\s*\{([^}]+)\}").unwrap()
    });

    let mut consts = std::collections::HashMap::new();

    // Match: pub const NAME: &str = "VALUE";
    for cap in CONST_RE.captures_iter(rust_code) {
        if let (Some(name), Some(value)) = (cap.get(1), cap.get(2)) {
            consts.insert(name.as_str().to_string(), value.as_str().to_string());
        }
    }

    // Match enum variants for @{Enum::Variant} syntax
    for cap in ENUM_RE.captures_iter(rust_code) {
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
    static CSS_CONST_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"@\{([^}]+)\}").unwrap()
    });

    CSS_CONST_RE.replace_all(css, |caps: &regex::Captures| {
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

fn link_modules(modules: &[Vec<u8>], _opts: &CompileOptions) -> Result<Vec<u8>, CompileError> {
    if modules.is_empty() {
        return Ok(Vec::new());
    }

    // Single module: just return it directly
    if modules.len() == 1 {
        return Ok(modules[0].clone());
    }

    // Multi-module linking is not yet implemented.
    // Use `polyglot component` + `polyglot compose` for WASM component linking.
    eprintln!("⚠️  Multi-module linking not yet built-in. Using first module only.");
    eprintln!("   Tip: Use `polyglot component` + `polyglot compose` for multi-language linking.");
    Ok(modules[0].clone())
}

/// Generate a single self-contained HTML file with all assets inlined
/// - WASM binary is base64 encoded
/// - CSS is <style> inlined  
/// - JS is <script> inlined
/// - WGSL shaders are embedded for WebGPU
/// - Source map for .poly line number mapping
pub fn generate_inline_bundle(
    wasm_bytes: &[u8],
    css: &str,
    js: &str,
    wgsl: &str,
    _html_template: Option<&str>,
    title: &str,
    source_map_js: &str,
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

    // Source map for .poly line number mapping (inject before other scripts)
    if !source_map_js.is_empty() {
        html.push_str("    <script type=\"text/javascript\">\n");
        html.push_str("    // Polyglot Source Map - maps errors to .poly file lines\n");
        html.push_str(source_map_js);
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
    let source_map_js = fs::read_to_string(temp_dir.join("source_map.js")).unwrap_or_default();

    Ok(generate_inline_bundle(
        wasm_bytes,
        &css,
        &js,
        &wgsl,
        None,
        title,
        &source_map_js,
    ))
}

/// Create inline bundle with source map from parsed file
pub fn bundle_with_source_map(
    temp_dir: &std::path::Path,
    wasm_bytes: &[u8],
    title: &str,
    parsed: &crate::parser::ParsedFile,
    source_file: &str,
) -> Result<String, std::io::Error> {
    use crate::source_map::SourceTracker;

    let css = fs::read_to_string(temp_dir.join("styles.css")).unwrap_or_default();
    let js = fs::read_to_string(temp_dir.join("app.js")).unwrap_or_default();
    let wgsl = fs::read_to_string(temp_dir.join("shaders.wgsl")).unwrap_or_default();

    // Build source map from parsed blocks
    let mut tracker = SourceTracker::new(source_file);

    for block in &parsed.blocks {
        tracker.track_block(block.start_line, &block.code, &block.lang_tag);
    }

    let source_map = tracker.finalize();
    let source_map_js = source_map.to_js_lookup_function();

    // Write source map for debugging
    fs::write(temp_dir.join("source_map.js"), &source_map_js)?;
    fs::write(
        temp_dir.join("source_map.json"),
        source_map.to_inline_json(),
    )?;

    Ok(generate_inline_bundle(
        wasm_bytes,
        &css,
        &js,
        &wgsl,
        None,
        title,
        &source_map_js,
    ))
}
