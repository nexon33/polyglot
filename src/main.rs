use clap::{Parser, Subcommand};
use polyglot::{
    compiler::{compile, CompileError},
    component_builder::{ComponentBuilder, check_component_tools},
    diagnostic::{self, PolySource, NoMainError, MultipleMainError, ParseDiagnostic, RustCompileError},
    implements_verify::verify_implementations,
    parser::{ParsedFile, parse_poly},
    types::CompileOptions,
    validate,
    wit_gen::generate_wit,
};
use miette::{IntoDiagnostic, Result as MietteResult};

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

#[derive(Parser, Debug)]
#[command(author, version, about = "Polyglot compiler - Multi-language WASM development", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check a poly file for errors and print WIT export
    Check {
        /// Input file
        file: PathBuf,
    },
    /// Compile a poly file to WASM
    Build {
        /// Input file
        file: PathBuf,

        /// Release mode
        #[arg(long, short)]
        release: bool,

        /// Emit additional artifacts (wit, ir)
        #[arg(long, value_parser = ["wit", "ir"])]
        emit: Option<String>,

        /// Target: browser (default), host, android, linux, windows, apk
        #[arg(long, short, value_parser = ["browser", "host", "android", "linux", "windows", "apk"], default_value = "browser")]
        target: String,
    },
    /// Generate WIT interface from a poly file
    Wit {
        /// Input file
        file: PathBuf,

        /// Output file (default: <name>.wit)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Build and run a poly file with wasmtime
    Run {
        /// Input file
        file: PathBuf,

        /// Build in release mode (default)
        #[arg(long, default_value_t = true)]
        release: bool,

        /// Arguments to pass to the WASM program (use -- before args)
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Initialize a new polyglot project
    Init {
        /// Project name (default: current directory name)
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Build and bundle into a single self-contained HTML file
    Bundle {
        /// Input poly file
        file: PathBuf,

        /// Output HTML file (default: <name>.html)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Title for the HTML page
        #[arg(short, long, default_value = "Polyglot App")]
        title: String,
    },
    /// Install npm dependencies and bundle with esbuild
    Npm {
        /// Subcommand: install, bundle, or init
        #[arg(default_value = "install")]
        action: String,

        /// Package names to install (for 'install' action)
        #[arg(trailing_var_arg = true)]
        packages: Vec<String>,
    },
    /// Watch mode with hot reload
    Watch {
        /// Input poly file
        file: PathBuf,

        /// Dev server port
        #[arg(short, long, default_value_t = 3000)]
        port: u16,

        /// Open browser automatically
        #[arg(long)]
        open: bool,
    },
    /// Run inline tests
    Test {
        /// Input poly file
        file: PathBuf,
    },
    /// Verify @implements declarations match interface traits
    Verify {
        /// Input poly file
        file: PathBuf,
    },
    /// Create a new project from a template
    New {
        /// Template name: react-app, ml-demo, or game
        template: String,

        /// Project directory (default: template name)
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Check which component tools are installed
    Tools,
    /// Build language blocks as WASM components (requires jco, componentize-py)
    Component {
        /// Input poly file
        file: PathBuf,

        /// Output directory (default: target/components)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Also compose components into single composed.wasm (requires wasm-compose)
        #[arg(long)]
        compose: bool,
    },
    /// Compose multiple WASM components into one (requires wasm-compose)
    Compose {
        /// Input WASM component files
        #[arg(required = true)]
        components: Vec<PathBuf>,

        /// Output file (default: composed.wasm)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> MietteResult<()> {
    // Install miette's fancy error handler for beautiful diagnostics
    miette::set_hook(Box::new(|_| {
        Box::new(
            miette::MietteHandlerOpts::new()
                .terminal_links(true)
                .unicode(true)
                .context_lines(2)
                .tab_width(4)
                .build(),
        )
    }))?;

    let args = Args::parse();

    match args.command {
        Commands::Check { file } => {
            println!("🔍 Checking {}", file.display());
            let source = fs::read_to_string(&file).into_diagnostic()?;
            match parse_poly(&source) {
                Ok(parsed) => {
                    println!("✅ Successfully parsed {} blocks", parsed.blocks.len());
                    match generate_wit(&parsed) {
                        Ok(wit) => {
                            println!("\n📝 Generated WIT Interface:");
                            println!("-----------------------");
                            println!("{}", wit);
                        }
                        Err(e) => eprintln!("❌ Error generating WIT: {}", e),
                    }
                }
                Err(e) => eprintln!("❌ {}", e),
            }
        }
        Commands::Build { file, release, emit, target } => {
            // Handle --emit=wit flag
            if emit.as_deref() == Some("wit") {
                generate_wit_file(&file)?;
            }
            build_poly(&file, release, false, &target)?;
        }
        Commands::Wit { file, output } => {
            generate_wit_file_to(&file, output)?;
        }
        Commands::Run {
            file,
            release,
            args,
        } => {
            let wasm_path = build_poly(&file, release, false, "browser")?;
            run_wasm(&wasm_path, &args)?;
        }
        Commands::Init { name } => {
            init_project(name)?;
        }
        Commands::New { template, name } => {
            new_from_template(&template, name)?;
        }
        Commands::Test { file } => {
            eprintln!("🧪 Running inline tests for {}", file.display());
            build_poly(&file, false, true, "browser")?; // release=false, test_mode=true
        }
        Commands::Verify { file } => {
            verify_poly(&file)?;
        }
        Commands::Tools => {
            check_tools();
        }
        Commands::Component { file, output, verbose, compose } => {
            build_components(&file, output, verbose, compose)?;
        }
        Commands::Compose { components, output, verbose } => {
            compose_components(&components, output, verbose)?;
        }
        Commands::Bundle {
            file,
            output,
            title,
        } => {
            // Build first (always browser target for bundle)
            let wasm_path = build_poly(&file, true, false, "browser")?;

            // Read WASM bytes
            let wasm_bytes = fs::read(&wasm_path).into_diagnostic()?;

            // Use the same temp dir as CompileOptions::default() (relative to cwd)
            let temp_dir = PathBuf::from("target/polyglot_tmp");

            // Generate bundle
            let bundle = polyglot::compiler::bundle_to_single_file(&temp_dir, &wasm_bytes, &title).into_diagnostic()?;

            // Determine output path
            let out_path = output.unwrap_or_else(|| {
                let stem = file.file_stem().unwrap_or_default().to_string_lossy();
                PathBuf::from(format!("{}.html", stem))
            });

            fs::write(&out_path, &bundle).into_diagnostic()?;

            let size_kb = bundle.len() / 1024;
            println!(
                "📦 Single-file bundle: {} ({} KB)",
                out_path.display(),
                size_kb
            );
            println!("   ✓ WASM: base64 inline");
            println!("   ✓ CSS:  <style> inline");
            println!("   ✓ JS:   <script> inline");
            println!("   ✓ GPU:  WGSL shaders embedded");
            println!(
                "\n🌐 Open in browser: file://{}",
                fs::canonicalize(&out_path).into_diagnostic()?.display()
            );
        }
        Commands::Npm { action, packages } => {
            match action.as_str() {
                "init" => {
                    println!("📦 Initializing npm project...");
                    let status = Command::new("npm")
                        .args(["init", "-y"])
                        .status()
                        .expect("Failed to run npm init");

                    if status.success() {
                        println!("✅ Created package.json");

                        // Also install esbuild
                        println!("📦 Installing esbuild...");
                        let esbuild_status = Command::new("npm")
                            .args(["install", "--save-dev", "esbuild"])
                            .status()
                            .expect("Failed to install esbuild");

                        if esbuild_status.success() {
                            println!("✅ esbuild installed");
                        }
                    }
                }
                "install" | "i" => {
                    if packages.is_empty() {
                        println!("📦 Installing all dependencies...");
                        let status = Command::new("npm")
                            .args(["install"])
                            .status()
                            .expect("Failed to run npm install");

                        if status.success() {
                            println!("✅ Dependencies installed");
                        }
                    } else {
                        println!("📦 Installing: {}", packages.join(", "));
                        let mut args = vec!["install", "--save"];
                        for pkg in &packages {
                            args.push(pkg);
                        }

                        let status = Command::new("npm")
                            .args(&args)
                            .status()
                            .expect("Failed to run npm install");

                        if status.success() {
                            println!("✅ Installed: {}", packages.join(", "));
                        }
                    }
                }
                "bundle" => {
                    println!("📦 Bundling JS dependencies with esbuild...");

                    // Create entry point that re-exports all dependencies
                    let entry = "// Auto-generated entry point\nexport * from './node_modules';\n";
                    fs::write("_poly_entry.js", entry).into_diagnostic()?;

                    let status = Command::new("npx")
                        .args([
                            "esbuild",
                            "_poly_entry.js",
                            "--bundle",
                            "--outfile=_poly_bundled.js",
                            "--format=esm",
                            "--minify",
                        ])
                        .status()
                        .expect("Failed to run esbuild");

                    // Cleanup temp entry
                    let _ = fs::remove_file("_poly_entry.js");

                    if status.success() {
                        println!("✅ Bundled to _poly_bundled.js");
                        println!("   Include this in your #[js] block or import it");
                    }
                }
                _ => {
                    eprintln!("❌ Unknown action: {}. Use: init, install, bundle", action);
                }
            }
        }
        Commands::Watch { file, port, open } => {
            watch_poly(&file, port, open)?;
        }
    }

    Ok(())
}

/// Check which component tools are installed
fn check_tools() {
    println!("🔧 Component Model Tools Status:\n");

    let tools = check_component_tools();
    for (name, available, status) in &tools {
        let icon = if *available { "✅" } else { "❌" };
        println!("  {} {}: {}", icon, name, status.split(": ").last().unwrap_or(status));
    }

    let available_count = tools.iter().filter(|(_, a, _)| *a).count();
    println!("\n📊 {}/{} tools available", available_count, tools.len());

    if available_count < tools.len() {
        println!("\n💡 Install missing tools to enable full component model support.");
    }
}

/// Build language blocks as WASM components
fn build_components(file: &PathBuf, output: Option<PathBuf>, verbose: bool, compose: bool) -> MietteResult<()> {
    println!("🔨 Building WASM components from {}", file.display());

    let source = fs::read_to_string(file).into_diagnostic()?;
    let filename = file.display().to_string();

    let parsed = parse_poly(&source).map_err(|e| {
        miette::miette!("Parse error: {}", e)
    })?;

    // Determine output directory
    let work_dir = output.unwrap_or_else(|| {
        file.parent()
            .unwrap_or(Path::new("."))
            .join("target/components")
    });

    let mut builder = ComponentBuilder::new(work_dir.clone());
    builder.verbose = verbose;

    // Count componentizable blocks in the file
    let componentizable_count = parsed.blocks.iter()
        .filter(|b| matches!(b.lang_tag.as_str(), "typescript" | "ts" | "javascript" | "js" | "python" | "py"))
        .count();

    match builder.build_all(&parsed, &filename) {
        Ok(results) => {
            if results.is_empty() {
                if componentizable_count > 0 {
                    println!("⚠️  Found {} componentizable blocks but couldn't build any.", componentizable_count);
                    println!("   Run `polyglot tools` to check which tools are installed.");
                } else {
                    println!("⚠️  No componentizable blocks found (need #[typescript], #[javascript], or #[python])");
                }
            } else {
                println!("\n✅ Built {} component(s):\n", results.len());
                for result in &results {
                    println!("  📦 {}: {} ({} KB)",
                        result.language,
                        result.wasm_path.display(),
                        result.size_bytes / 1024
                    );
                }

                // Optionally compose components
                if compose && results.len() >= 2 {
                    println!("\n🔗 Composing {} components...", results.len());
                    let wit_path = work_dir.join("interfaces.wit");
                    let mut linker = polyglot::ComponentLinker::new(work_dir);
                    linker.verbose = verbose;

                    match linker.link(&results, &wit_path) {
                        Ok(link_result) => {
                            println!("\n✅ Composed component: {} ({} KB)",
                                link_result.output_path.display(),
                                link_result.size_bytes / 1024
                            );
                        }
                        Err(e) => {
                            println!("⚠️  Composition failed: {}", e);
                            println!("   Run `polyglot tools` to check if wasm-compose is installed.");
                        }
                    }
                } else if compose && results.len() < 2 {
                    println!("\n⚠️  Need at least 2 components to compose (got {})", results.len());
                }
            }
            Ok(())
        }
        Err(e) => {
            Err(miette::miette!("Component build failed: {}", e))
        }
    }
}

/// Compose multiple WASM components into one
fn compose_components(components: &[PathBuf], output: Option<PathBuf>, verbose: bool) -> MietteResult<()> {
    use polyglot::component_builder::ComponentBuildResult;

    if components.len() < 2 {
        return Err(miette::miette!("Need at least 2 components to compose (got {})", components.len()));
    }

    println!("🔗 Composing {} components...", components.len());

    // Convert PathBuf to ComponentBuildResult
    let results: Vec<ComponentBuildResult> = components.iter().enumerate().map(|(i, path)| {
        let size = fs::metadata(path).map(|m| m.len() as usize).unwrap_or(0);
        ComponentBuildResult {
            language: format!("component_{}", i),
            wasm_path: path.clone(),
            size_bytes: size,
        }
    }).collect();

    // Determine output directory
    let work_dir = output.clone().unwrap_or_else(|| PathBuf::from("target/components"));
    fs::create_dir_all(&work_dir).into_diagnostic()?;

    let mut linker = polyglot::ComponentLinker::new(work_dir.clone());
    linker.verbose = verbose;
    if let Some(out) = output {
        linker.output_path = out;
    }

    // Create a dummy WIT path (composition doesn't always need it)
    let wit_path = work_dir.join("interfaces.wit");

    match linker.link(&results, &wit_path) {
        Ok(link_result) => {
            println!("\n✅ Composed component: {} ({} KB)",
                link_result.output_path.display(),
                link_result.size_bytes / 1024
            );
            println!("   Linked {} components", link_result.components_linked);
            Ok(())
        }
        Err(e) => {
            Err(miette::miette!("Composition failed: {}", e))
        }
    }
}

/// Verify @implements declarations against interface traits
fn verify_poly(file: &PathBuf) -> MietteResult<()> {
    println!("🔍 Verifying @implements in {}", file.display());
    let source = fs::read_to_string(file).into_diagnostic()?;

    let parsed = parse_poly(&source).map_err(|e| {
        miette::miette!("Parse error: {}", e)
    })?;

    let errors = verify_implementations(&parsed);

    if errors.is_empty() {
        println!("✅ All @implements declarations are valid");
        Ok(())
    } else {
        println!("\n❌ Found {} verification error(s):\n", errors.len());
        for err in &errors {
            eprintln!("   {} (line {}): class `{}` @implements({}):",
                err.lang_tag, err.line, err.class_name, err.trait_name);
            eprintln!("      {}\n", err.message);
        }
        Err(miette::miette!(
            "{} @implements verification error(s) found",
            errors.len()
        ))
    }
}

/// Generate WIT file from a poly file (writes to <name>.wit)
fn generate_wit_file(file: &PathBuf) -> MietteResult<()> {
    let wit_path = file.with_extension("wit");
    generate_wit_file_to(file, Some(wit_path))
}

/// Generate WIT file from a poly file to specified output
fn generate_wit_file_to(file: &PathBuf, output: Option<PathBuf>) -> MietteResult<()> {
    use polyglot::wit_gen::generate_wit_for_file;

    let source = fs::read_to_string(file).into_diagnostic()?;
    let filename = file.display().to_string();

    let parsed = parse_poly(&source).map_err(|e| {
        miette::miette!("Parse error: {}", e)
    })?;

    let wit = generate_wit_for_file(&parsed, &filename).map_err(|e| {
        miette::miette!("WIT generation error: {}", e)
    })?;

    let output_path = output.unwrap_or_else(|| file.with_extension("wit"));
    fs::write(&output_path, &wit).into_diagnostic()?;

    println!("📄 Generated WIT: {}", output_path.display());
    println!("{}", wit);

    Ok(())
}

fn build_poly(file: &PathBuf, release: bool, test_mode: bool, target_str: &str) -> MietteResult<PathBuf> {
    println!("🔨 Compiling {}", file.display());
    let source = fs::read_to_string(file).into_diagnostic()?;
    let filename = file.display().to_string();

    // Create source holder for error reporting
    let poly_src = PolySource::new(&filename, &source);

    let mut parsed = match parse_poly(&source) {
        Ok(p) => p,
        Err(e) => {
            // Convert parse error to miette diagnostic
            let err_msg = e.to_string();
            return Err(ParseDiagnostic {
                message: err_msg.clone(),
                src: poly_src.named_source(),
                span: diagnostic::line_span(&source, 1), // Default to first line if no position
            }.into());
        }
    };

    // Resolve imports - load and merge imported files
    let base_dir = file.parent().unwrap_or(std::path::Path::new("."));
    resolve_imports(&mut parsed, base_dir)?;

    // Phase 26b: Verify @implements declarations match interface traits
    let impl_errors = verify_implementations(&parsed);
    if !impl_errors.is_empty() {
        println!("\n❌ @implements Verification Errors:");
        for err in &impl_errors {
            eprintln!("   {} (line {}): class `{}` @implements({}):",
                err.lang_tag, err.line, err.class_name, err.trait_name);
            eprintln!("      {}", err.message);
        }
        return Err(miette::miette!(
            "{} @implements verification error(s) found",
            impl_errors.len()
        ));
    }

    // Validate interface contracts
    if let Err(errors) = validate(&parsed) {
        println!("\n🔍 Validation Errors:");
        for err in &errors {
            eprintln!("   {}", err);
        }
        return Err(miette::miette!(
            "{} validation error(s) found",
            errors.len()
        ));
    }

    // Handle APK target specially
    if target_str == "apk" {
        return build_apk(file, &parsed);
    }
    
    // Parse target string to CompileTarget enum
    let target = match target_str {
        "host" => polyglot::types::CompileTarget::Host,
        "android" => polyglot::types::CompileTarget::Aarch64Android,
        "linux" => polyglot::types::CompileTarget::X86_64Linux,
        "windows" => polyglot::types::CompileTarget::X86_64Windows,
        _ => polyglot::types::CompileTarget::default(), // "browser" or default
    };

    // Print target info
    match target_str {
        "host" => println!("🎯 Target: host (Node.js with native access)"),
        "android" => println!("🎯 Target: android (aarch64-linux-android native binary)"),
        "linux" => println!("🎯 Target: linux (x86_64-unknown-linux-gnu native binary)"),
        "windows" => println!("🎯 Target: windows (x86_64-pc-windows-msvc native binary)"),
        _ => {}
    }

    let opts = CompileOptions {
        release,
        test_mode,
        target,
        ..Default::default()
    };

    match compile(&parsed, &opts) {
        Ok(output) => {
            if test_mode {
                // Tests already ran and printed output, just return dummy path
                return Ok(file.with_extension("test"));
            }
            println!("✅ Successfully compiled {} bytes", output.binary.len());
            
            // Determine output extension based on target
            let out_ext = target.output_extension();
            let out_path = if out_ext.is_empty() {
                // Native binaries on Linux/Android have no extension
                file.with_extension("")
            } else {
                file.with_extension(out_ext)
            };
            
            fs::write(&out_path, &output.binary).into_diagnostic()?;
            println!("📦 Wrote to {}", out_path.display());
            
            // For native targets with web assets, copy them to a web/ subdirectory
            if target.is_native() && output.has_web_assets {
                let web_dir = out_path.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join("web");
                fs::create_dir_all(&web_dir).into_diagnostic()?;
                
                for asset in &output.web_assets {
                    let src = opts.temp_dir.join(asset);
                    let dst = web_dir.join(asset);
                    if src.exists() {
                        fs::copy(&src, &dst).into_diagnostic()?;
                    }
                }
                println!("🌐 Web assets copied to {}/", web_dir.display());
            }
            
            Ok(out_path)
        }
        Err(e) => {
            // Convert compile errors to miette diagnostics with source context
            match &e {
                CompileError::Build(msg) if msg.contains("No main function found") => {
                    return Err(NoMainError {
                        src: poly_src.named_source(),
                        span: (0, source.len().min(50)).into(),
                        block_count: parsed.blocks.len(),
                    }.into());
                }
                CompileError::Build(msg) if msg.contains("Multiple main functions found") => {
                    // Find main function locations
                    let mut first_span = (0usize, 10usize);
                    let mut second_span = (0usize, 10usize);

                    for (i, block) in parsed.blocks.iter().enumerate() {
                        if block.code.contains("fn main(") || block.code.contains("def main(") {
                            let offset = diagnostic::line_col_to_offset(&source, block.start_line, 1);
                            if first_span.0 == 0 && i == 0 || first_span == (0, 10) {
                                first_span = (offset, 15);
                            } else {
                                second_span = (offset, 15);
                                break;
                            }
                        }
                    }

                    return Err(MultipleMainError {
                        src: poly_src.named_source(),
                        first: first_span.into(),
                        second: second_span.into(),
                    }.into());
                }
                CompileError::UnknownLanguage(tag) => {
                    // Find the unknown language tag in source
                    let pattern = format!("#[{}]", tag);
                    let span = diagnostic::find_pattern_span(&source, &pattern, 0)
                        .unwrap_or_else(|| (0, 10).into());

                    return Err(diagnostic::UnknownLanguageError {
                        tag: tag.clone(),
                        src: poly_src.named_source(),
                        span,
                    }.into());
                }
                CompileError::Other(ref anyhow_err) => {
                    let err_str = anyhow_err.to_string();

                    // Check if this is a Rust compilation error with details
                    if err_str.contains("Rust compilation failed") {
                        // Find the first Rust or main block for context
                        let rust_block_line = parsed.blocks.iter()
                            .find(|b| matches!(b.lang_tag.as_str(), "rust" | "rs" | "main"))
                            .map(|b| b.start_line)
                            .unwrap_or(1);

                        let span_offset = diagnostic::line_col_to_offset(&source, rust_block_line, 1);

                        // Print the detailed error directly (miette will also show context)
                        eprintln!("\n{}", err_str);

                        return Err(RustCompileError {
                            src: poly_src.named_source(),
                            span: diagnostic::span_to_eol(&source, span_offset),
                            details: err_str,
                        }.into());
                    }

                    // Generic build error
                    return Err(diagnostic::BuildError {
                        message: err_str,
                        src: Some(poly_src.named_source()),
                        span: Some((0, 1).into()),
                        suggestion: None,
                    }.into());
                }
                _ => {
                    // Generic build error - show with source context if possible
                    return Err(diagnostic::BuildError {
                        message: e.to_string(),
                        src: Some(poly_src.named_source()),
                        span: Some((0, 1).into()),
                        suggestion: None,
                    }.into());
                }
            }
        }
    }
}

/// Build an APK from a .poly file
fn build_apk(file: &PathBuf, parsed: &polyglot::parser::ParsedFile) -> MietteResult<PathBuf> {
    use polyglot::apk_builder::{ApkBuilder, ApkConfig};
    
    println!("🎯 Target: apk (Android application package)");
    
    // First, compile for Android target
    let opts = CompileOptions {
        release: true,
        test_mode: false,
        target: polyglot::types::CompileTarget::Aarch64Android,
        ..Default::default()
    };
    
    println!("📦 Step 1: Compiling native binary for aarch64...");
    let output = compile(parsed, &opts).into_diagnostic()?;
    
    if output.binary.is_empty() {
        return Err(miette::miette!("No binary output from compilation"));
    }
    println!("   ✓ Native binary: {} bytes", output.binary.len());
    
    // Collect web assets
    let mut web_assets = Vec::new();
    let temp_dir = PathBuf::from("target/polyglot_tmp");
    
    for asset_name in &output.web_assets {
        let asset_path = temp_dir.join(asset_name);
        if asset_path.exists() {
            let content = fs::read(&asset_path).into_diagnostic()?;
            web_assets.push((asset_name.clone(), content));
            println!("   ✓ Web asset: {}", asset_name);
        }
    }
    
    // Build APK
    println!("📦 Step 2: Building APK...");
    
    let apk_work_dir = temp_dir.join("apk_build");
    let builder = ApkBuilder::new(apk_work_dir)
        .map_err(|e| miette::miette!("APK builder error: {}", e))?;
    
    // Get app name from file stem
    let app_name = file.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or("Poly App".to_string());
    
    let config = ApkConfig {
        app_name: app_name.clone(),
        package_name: format!("com.poly.{}", app_name.to_lowercase().replace(" ", "_")),
        ..Default::default()
    };
    
    let apk_bytes = builder.build(&output.binary, &web_assets, &config)
        .map_err(|e| miette::miette!("APK build failed: {}", e))?;
    
    // Write APK
    let out_path = file.with_extension("apk");
    fs::write(&out_path, &apk_bytes).into_diagnostic()?;
    
    println!("✅ APK built: {} ({} KB)", out_path.display(), apk_bytes.len() / 1024);
    
    Ok(out_path)
}

fn run_wasm(wasm_path: &PathBuf, args: &[String]) -> MietteResult<()> {
    println!("🚀 Running {}...\n", wasm_path.display());

    let mut cmd = Command::new("wasmtime");
    cmd.arg(wasm_path);
    cmd.args(args);

    let status = cmd.status().into_diagnostic()?;

    if !status.success() {
        if let Some(code) = status.code() {
            eprintln!("\n❌ Process exited with code {}", code);
        }
    }

    Ok(())
}

fn init_project(name: Option<String>) -> MietteResult<()> {
    let project_name = name.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my_poly_project".to_string())
    });

    println!("🎉 Initializing polyglot project: {}", project_name);

    // Create main.poly
    let main_poly = format!(
        r#"
#[interface]
// Define your cross-language interface here
fn greet(name: String) -> String

#[rust]
fn greet(name: String) -> String {{
    format!("Hello from Rust, {{}}!", name)
}}

#[main]
fn main() {{
    let message = greet("World".to_string());
    println!("{{}}", message);
}}
"#
    );

    fs::write("main.poly", main_poly).into_diagnostic()?;
    println!("📝 Created main.poly");

    // Create poly.toml (project manifest)
    let poly_toml = format!(
        r#"[package]
name = "{}"
version = "0.1.0"

[dependencies]
# Add your dependencies here
# gridmesh = {{ path = "../gridmesh" }}
"#,
        project_name
    );

    fs::write("poly.toml", poly_toml).into_diagnostic()?;
    println!("📝 Created poly.toml");

    println!("\n✅ Project initialized! Run:");
    println!("   polyglot build main.poly");
    println!("   polyglot run main.poly");

    Ok(())
}

/// Create a new project from a template
fn new_from_template(template: &str, name: Option<String>) -> MietteResult<()> {
    let project_name = name.unwrap_or_else(|| template.to_string());
    let project_dir = PathBuf::from(&project_name);

    if project_dir.exists() {
        return Err(miette::miette!(
            "Directory '{}' already exists",
            project_name
        ));
    }

    fs::create_dir_all(&project_dir).into_diagnostic()?;

    println!("🎉 Creating {} project: {}", template, project_name);

    let main_poly = match template {
        "react-app" => get_react_template(&project_name),
        "ml-demo" => get_ml_template(&project_name),
        "game" => get_game_template(&project_name),
        _ => {
            return Err(miette::miette!(
                "Unknown template '{}'. Available: react-app, ml-demo, game",
                template
            ));
        }
    };

    fs::write(project_dir.join("main.poly"), main_poly).into_diagnostic()?;
    println!("📝 Created main.poly");

    // Create poly.toml
    let poly_toml = format!(
        r#"[package]
name = "{}"
version = "0.1.0"
template = "{}"
"#,
        project_name, template
    );
    fs::write(project_dir.join("poly.toml"), poly_toml).into_diagnostic()?;
    println!("📝 Created poly.toml");

    println!("\n✅ Project created! Run:");
    println!("   cd {}", project_name);
    println!("   polyglot bundle main.poly");
    println!("   polyglot watch main.poly --open");

    Ok(())
}

fn get_react_template(name: &str) -> String {
    format!(
        r#"// {} - React App Template
// Created with: poly new react-app

#[rust]
static mut COUNTER: i32 = 0;

export fn increment() -> i32 {{
    unsafe {{
        COUNTER += 1;
        COUNTER
    }}
}}

export fn decrement() -> i32 {{
    unsafe {{
        COUNTER -= 1;
        COUNTER
    }}
}}

export fn get_count() -> i32 {{
    unsafe {{ COUNTER }}
}}

#[js]
function App() {{
    const [count, setCount] = React.useState(0);
    
    const handleIncrement = async () => {{
        const newCount = await window.wasm.increment();
        setCount(newCount);
    }};
    
    const handleDecrement = async () => {{
        const newCount = await window.wasm.decrement();
        setCount(newCount);
    }};
    
    return (
        <div className="app">
            <h1>🚀 {}</h1>
            <div className="counter">
                <button onClick={{handleDecrement}}>-</button>
                <span className="count">{{count}}</span>
                <button onClick={{handleIncrement}}>+</button>
            </div>
            <p className="hint">
                State managed in Rust, UI in React
            </p>
        </div>
    );
}}

#[rscss]
* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

body {{
    font-family: 'Inter', -apple-system, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}}

.app {{
    background: rgba(255, 255, 255, 0.95);
    padding: 3rem;
    border-radius: 1.5rem;
    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
    text-align: center;
}}

h1 {{
    font-size: 2.5rem;
    margin-bottom: 2rem;
    background: linear-gradient(135deg, #667eea, #764ba2);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}}

.counter {{
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1.5rem;
}}

.counter button {{
    width: 60px;
    height: 60px;
    font-size: 2rem;
    border: none;
    border-radius: 50%;
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
}}

.counter button:hover {{
    transform: scale(1.1);
    box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
}}

.count {{
    font-size: 4rem;
    font-weight: 700;
    min-width: 120px;
    color: #333;
}}

.hint {{
    margin-top: 2rem;
    color: #666;
    font-size: 0.9rem;
}}

#[main]
fn main() {{
    // Entry point - React handles the UI
}}
"#,
        name, name
    )
}

fn get_ml_template(name: &str) -> String {
    format!(
        r#"// {} - ML Demo Template
// Created with: poly new ml-demo

#[rust]
use std::f32::consts::PI;

const VOCAB_SIZE: usize = 128;
const HIDDEN_SIZE: usize = 64;

static mut EMBEDDINGS: [[f32; HIDDEN_SIZE]; VOCAB_SIZE] = [[0.0; HIDDEN_SIZE]; VOCAB_SIZE];
static mut WEIGHTS: [[f32; VOCAB_SIZE]; HIDDEN_SIZE] = [[0.0; VOCAB_SIZE]; HIDDEN_SIZE];

fn init_weights() {{
    unsafe {{
        for i in 0..VOCAB_SIZE {{
            for j in 0..HIDDEN_SIZE {{
                let x = (i * HIDDEN_SIZE + j) as f32;
                EMBEDDINGS[i][j] = (x * 0.1).sin() * 0.1;
            }}
        }}
        for i in 0..HIDDEN_SIZE {{
            for j in 0..VOCAB_SIZE {{
                let x = (i * VOCAB_SIZE + j) as f32;
                WEIGHTS[i][j] = (x * 0.1).cos() * 0.1;
            }}
        }}
    }}
}}

export fn predict_next(current_char: i32) -> i32 {{
    unsafe {{
        // Get embedding
        let idx = (current_char as usize) % VOCAB_SIZE;
        let hidden = EMBEDDINGS[idx];
        
        // Project to vocabulary
        let mut best_idx = 0;
        let mut best_score = f32::NEG_INFINITY;
        
        for v in 0..VOCAB_SIZE {{
            let mut score = 0.0;
            for h in 0..HIDDEN_SIZE {{
                score += hidden[h] * WEIGHTS[h][v];
            }}
            if score > best_score {{
                best_score = score;
                best_idx = v;
            }}
        }}
        
        best_idx as i32
    }}
}}

export fn train_step(input: i32, target: i32, lr: f32) -> f32 {{
    unsafe {{
        init_weights();
        // Simplified training - just return mock loss
        let loss = 2.0 - (lr * 0.1);
        loss.max(0.1)
    }}
}}

#[js]
function App() {{
    const [loss, setLoss] = React.useState(2.0);
    const [step, setStep] = React.useState(0);
    const [generated, setGenerated] = React.useState("");
    const [isTraining, setIsTraining] = React.useState(false);
    
    const train = async () => {{
        setIsTraining(true);
        for (let i = 0; i < 100; i++) {{
            const newLoss = await window.wasm.train_step(65, 66, 0.01);
            setLoss(newLoss);
            setStep(s => s + 1);
            await new Promise(r => setTimeout(r, 50));
        }}
        setIsTraining(false);
    }};
    
    const generate = async () => {{
        let text = "A";
        let current = 65;
        for (let i = 0; i < 50; i++) {{
            const next = await window.wasm.predict_next(current);
            text += String.fromCharCode(next % 128);
            current = next;
        }}
        setGenerated(text);
    }};
    
    return (
        <div className="app">
            <h1>🧠 {}</h1>
            <div className="stats">
                <div className="stat">
                    <span className="label">Loss</span>
                    <span className="value">{{loss.toFixed(4)}}</span>
                </div>
                <div className="stat">
                    <span className="label">Step</span>
                    <span className="value">{{step}}</span>
                </div>
            </div>
            <div className="buttons">
                <button onClick={{train}} disabled={{isTraining}}>
                    {{isTraining ? "Training..." : "Train"}}
                </button>
                <button onClick={{generate}}>Generate</button>
            </div>
            {{generated && (
                <div className="output">
                    <h3>Generated:</h3>
                    <pre>{{generated}}</pre>
                </div>
            )}}
        </div>
    );
}}

#[rscss]
body {{
    font-family: 'Inter', sans-serif;
    background: linear-gradient(135deg, #1a1a2e, #16213e);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
}}

.app {{
    background: rgba(255, 255, 255, 0.05);
    padding: 3rem;
    border-radius: 1.5rem;
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    min-width: 400px;
}}

h1 {{
    text-align: center;
    margin-bottom: 2rem;
}}

.stats {{
    display: flex;
    justify-content: center;
    gap: 2rem;
    margin-bottom: 2rem;
}}

.stat {{
    text-align: center;
}}

.label {{
    display: block;
    font-size: 0.8rem;
    color: rgba(255, 255, 255, 0.6);
}}

.value {{
    font-size: 2rem;
    font-weight: 700;
    color: #00ff88;
}}

.buttons {{
    display: flex;
    gap: 1rem;
    justify-content: center;
}}

button {{
    padding: 1rem 2rem;
    font-size: 1rem;
    border: none;
    border-radius: 0.5rem;
    background: linear-gradient(135deg, #00ff88, #00cc6a);
    color: #1a1a2e;
    cursor: pointer;
    font-weight: 600;
    transition: transform 0.2s;
}}

button:hover:not(:disabled) {{
    transform: scale(1.05);
}}

button:disabled {{
    opacity: 0.5;
}}

.output {{
    margin-top: 2rem;
    padding: 1rem;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 0.5rem;
}}

.output h3 {{
    margin-bottom: 0.5rem;
    color: rgba(255, 255, 255, 0.8);
}}

.output pre {{
    font-family: 'Fira Code', monospace;
    word-wrap: break-word;
    white-space: pre-wrap;
}}

#[main]
fn main() {{
    // Entry point
}}
"#,
        name, name
    )
}

fn get_game_template(name: &str) -> String {
    format!(
        r#"// {} - Game Template
// Created with: poly new game

#[rust]
static mut PLAYER_X: f32 = 400.0;
static mut PLAYER_Y: f32 = 300.0;
static mut PLAYER_VX: f32 = 0.0;
static mut PLAYER_VY: f32 = 0.0;
static mut SCORE: i32 = 0;

const SPEED: f32 = 5.0;
const FRICTION: f32 = 0.9;

export fn tick() -> i32 {{
    unsafe {{
        // Apply physics
        PLAYER_X += PLAYER_VX;
        PLAYER_Y += PLAYER_VY;
        PLAYER_VX *= FRICTION;
        PLAYER_VY *= FRICTION;
        
        // Bounds
        if PLAYER_X < 20.0 {{ PLAYER_X = 20.0; }}
        if PLAYER_X > 780.0 {{ PLAYER_X = 780.0; }}
        if PLAYER_Y < 20.0 {{ PLAYER_Y = 20.0; }}
        if PLAYER_Y > 580.0 {{ PLAYER_Y = 580.0; }}
        
        SCORE
    }}
}}

export fn move_left() {{
    unsafe {{ PLAYER_VX -= SPEED; }}
}}

export fn move_right() {{
    unsafe {{ PLAYER_VX += SPEED; }}
}}

export fn move_up() {{
    unsafe {{ PLAYER_VY -= SPEED; }}
}}

export fn move_down() {{
    unsafe {{ PLAYER_VY += SPEED; }}
}}

export fn get_x() -> f32 {{
    unsafe {{ PLAYER_X }}
}}

export fn get_y() -> f32 {{
    unsafe {{ PLAYER_Y }}
}}

export fn add_score(points: i32) -> i32 {{
    unsafe {{
        SCORE += points;
        SCORE
    }}
}}

#[js]
function App() {{
    const canvasRef = React.useRef(null);
    const [score, setScore] = React.useState(0);
    
    React.useEffect(() => {{
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        
        const keys = {{}};
        
        window.addEventListener('keydown', (e) => {{
            keys[e.key] = true;
        }});
        
        window.addEventListener('keyup', (e) => {{
            keys[e.key] = false;
        }});
        
        const gameLoop = async () => {{
            // Handle input
            if (keys['ArrowLeft'] || keys['a']) await window.wasm.move_left();
            if (keys['ArrowRight'] || keys['d']) await window.wasm.move_right();
            if (keys['ArrowUp'] || keys['w']) await window.wasm.move_up();
            if (keys['ArrowDown'] || keys['s']) await window.wasm.move_down();
            
            // Update game state
            await window.wasm.tick();
            
            // Get player position
            const x = await window.wasm.get_x();
            const y = await window.wasm.get_y();
            
            // Render
            ctx.fillStyle = '#1a1a2e';
            ctx.fillRect(0, 0, 800, 600);
            
            // Grid
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
            for (let i = 0; i < 800; i += 40) {{
                ctx.beginPath();
                ctx.moveTo(i, 0);
                ctx.lineTo(i, 600);
                ctx.stroke();
            }}
            for (let i = 0; i < 600; i += 40) {{
                ctx.beginPath();
                ctx.moveTo(0, i);
                ctx.lineTo(800, i);
                ctx.stroke();
            }}
            
            // Player (glowing orb)
            const gradient = ctx.createRadialGradient(x, y, 0, x, y, 25);
            gradient.addColorStop(0, '#00ff88');
            gradient.addColorStop(0.5, '#00cc6a');
            gradient.addColorStop(1, 'transparent');
            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.arc(x, y, 25, 0, Math.PI * 2);
            ctx.fill();
            
            // Core
            ctx.fillStyle = '#fff';
            ctx.beginPath();
            ctx.arc(x, y, 8, 0, Math.PI * 2);
            ctx.fill();
            
            requestAnimationFrame(gameLoop);
        }};
        
        gameLoop();
    }}, []);
    
    return (
        <div className="game-container">
            <h1>🎮 {}</h1>
            <canvas ref={{canvasRef}} width={{800}} height={{600}} />
            <p className="controls">Use WASD or Arrow Keys to move</p>
        </div>
    );
}}

#[rscss]
body {{
    margin: 0;
    padding: 0;
    font-family: 'Inter', sans-serif;
    background: #0a0a0f;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}}

.game-container {{
    text-align: center;
}}

h1 {{
    color: #00ff88;
    margin-bottom: 1rem;
    font-size: 2rem;
    text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
}}

canvas {{
    border: 2px solid #00ff88;
    border-radius: 8px;
    box-shadow: 0 0 40px rgba(0, 255, 136, 0.2);
}}

.controls {{
    color: rgba(255, 255, 255, 0.6);
    margin-top: 1rem;
    font-size: 0.9rem;
}}

#[main]
fn main() {{
    // Game entry point
}}
"#,
        name, name
    )
}

/// Resolve imports by loading and merging imported .poly files
fn resolve_imports(parsed: &mut ParsedFile, base_dir: &Path) -> MietteResult<()> {
    use std::collections::HashSet;

    fn resolve_inner(
        parsed: &mut ParsedFile,
        base_dir: &Path,
        visited: &mut HashSet<PathBuf>,
    ) -> MietteResult<()> {
        // Take imports to avoid borrowing issues
        let imports = std::mem::take(&mut parsed.imports);

        if imports.is_empty() {
            return Ok(());
        }

        println!("📦 Resolving {} import(s)...", imports.len());

        for import in imports {
            let import_path = base_dir
                .join(&import.path)
                .canonicalize()
                .unwrap_or_else(|_| base_dir.join(&import.path));

            // Skip already visited files (cycle detection)
            if visited.contains(&import_path) {
                continue;
            }

            if !import_path.exists() {
                return Err(miette::miette!("Import not found: {}", import.path));
            }

            println!("   ← {}", import.path);
            visited.insert(import_path.clone());

            let import_source = fs::read_to_string(&import_path).into_diagnostic()?;
            let mut import_parsed = parse_poly(&import_source)
                .map_err(|e| miette::miette!("Error parsing {}: {}", import.path, e))?;

            // Recursively resolve nested imports FIRST
            let child_base = import_path.parent().unwrap_or(base_dir);
            resolve_inner(&mut import_parsed, child_base, visited)?;

            // Then merge interfaces from imported file
            for item in import_parsed.interfaces {
                parsed.interfaces.push(item);
            }

            // Merge code blocks from imported file
            for block in import_parsed.blocks {
                parsed.blocks.push(block);
            }
        }

        Ok(())
    }

    let mut visited = HashSet::new();
    resolve_inner(parsed, base_dir, &mut visited)
}

/// Watch mode with hot reload
fn watch_poly(file: &PathBuf, port: u16, open: bool) -> MietteResult<()> {
    use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc::channel;
    use std::thread;

    // Atomic counter for version tracking (increments on each rebuild)
    let version = Arc::new(AtomicU64::new(0));
    let version_server = Arc::clone(&version);

    // Build initially
    println!("🔥 Starting watch mode...");
    let html_path = file.with_extension("html");

    // Do initial build
    if let Err(e) = rebuild_for_watch(file, &html_path, &version) {
        eprintln!("⚠️  Initial build failed: {}", e);
    }

    // Get directory to watch
    let watch_dir = file.parent().unwrap_or(Path::new(".")).to_path_buf();
    let file_clone = file.clone();
    let html_path_clone = html_path.clone();
    let version_watcher = Arc::clone(&version);

    // Start file watcher in a thread
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default()).into_diagnostic()?;
    watcher.watch(&watch_dir, RecursiveMode::Recursive).into_diagnostic()?;

    // Spawn watcher thread
    thread::spawn(move || {
        let mut last_rebuild = SystemTime::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(event)) => {
                    // Debounce - wait 200ms between rebuilds
                    let now = SystemTime::now();
                    if now.duration_since(last_rebuild).unwrap_or_default()
                        < Duration::from_millis(200)
                    {
                        continue;
                    }

                    // Only rebuild for .poly file changes
                    let is_poly = event
                        .paths
                        .iter()
                        .any(|p| p.extension().map(|e| e == "poly").unwrap_or(false));

                    if is_poly {
                        println!("\n🔄 Change detected, rebuilding...");
                        if let Err(e) =
                            rebuild_for_watch(&file_clone, &html_path_clone, &version_watcher)
                        {
                            eprintln!("⚠️  Rebuild failed: {}", e);
                        } else {
                            println!(
                                "✅ Rebuild complete (v{})",
                                version_watcher.load(Ordering::SeqCst)
                            );
                        }
                        last_rebuild = now;
                    }
                }
                _ => {}
            }
        }
    });

    // Start HTTP server
    let addr = format!("127.0.0.1:{}", port);
    let server = tiny_http::Server::http(&addr)
        .map_err(|e| miette::miette!("Failed to start server: {}", e))?;

    println!("\n🌐 Dev server running at http://localhost:{}", port);
    println!("   Serving: {}", html_path.display());
    println!("   Watching: {}/*.poly", watch_dir.display());
    println!("\n   Press Ctrl+C to stop.\n");

    // Open browser if requested
    if open {
        let url = format!("http://localhost:{}", port);
        #[cfg(target_os = "windows")]
        Command::new("cmd").args(["/c", "start", &url]).spawn().ok();
        #[cfg(target_os = "macos")]
        Command::new("open").arg(&url).spawn().ok();
        #[cfg(target_os = "linux")]
        Command::new("xdg-open").arg(&url).spawn().ok();
    }

    // Serve requests
    for request in server.incoming_requests() {
        let url = request.url().to_string();

        match url.as_str() {
            "/version" => {
                // Return current version for polling
                let v = version_server.load(Ordering::SeqCst);
                let response = tiny_http::Response::from_string(v.to_string());
                let _ = request.respond(response);
            }
            "/" | "/index.html" => {
                // Serve the HTML with live reload script injected
                match fs::read_to_string(&html_path) {
                    Ok(mut content) => {
                        // Inject live reload polling script
                        let live_reload_script = format!(
                            r#"
<script>
(function() {{
  let lastVersion = {};
  setInterval(async function() {{
    try {{
      const res = await fetch('/version');
      const version = parseInt(await res.text());
      if (version > lastVersion) {{
        console.log('🔥 New version detected, reloading...');
        location.reload();
      }}
    }} catch(e) {{}}
  }}, 500);
}})();
</script>
</body>"#,
                            version_server.load(Ordering::SeqCst)
                        );

                        content = content.replace("</body>", &live_reload_script);

                        let response = tiny_http::Response::from_string(content).with_header(
                            "Content-Type: text/html; charset=utf-8"
                                .parse::<tiny_http::Header>()
                                .unwrap(),
                        );
                        let _ = request.respond(response);
                    }
                    Err(_) => {
                        let response = tiny_http::Response::from_string("Build pending...")
                            .with_status_code(503);
                        let _ = request.respond(response);
                    }
                }
            }
            _ => {
                // 404 for other paths
                let response = tiny_http::Response::from_string("Not Found").with_status_code(404);
                let _ = request.respond(response);
            }
        }
    }

    Ok(())
}

/// Rebuild for watch mode (bundle to HTML)
fn rebuild_for_watch(
    file: &PathBuf,
    html_path: &PathBuf,
    version: &Arc<AtomicU64>,
) -> MietteResult<()> {
    // Build WASM first
    let source = fs::read_to_string(file).into_diagnostic()?;
    let mut parsed = parse_poly(&source).map_err(|e| miette::miette!("{}", e))?;

    let base_dir = file.parent().unwrap_or(Path::new("."));
    resolve_imports(&mut parsed, base_dir)?;

    if let Err(errors) = validate(&parsed) {
        return Err(miette::miette!("Validation failed: {:?}", errors));
    }

    let opts = CompileOptions {
        release: false, // Dev mode - faster builds
        ..Default::default()
    };

    let output = compile(&parsed, &opts).into_diagnostic()?;

    // Bundle to HTML - use same temp_dir as CompileOptions::default()
    let temp_dir = PathBuf::from("target/polyglot_tmp");
    let bundle = polyglot::compiler::bundle_to_single_file(&temp_dir, &output.binary, "Polyglot Dev").into_diagnostic()?;

    fs::write(html_path, &bundle).into_diagnostic()?;

    // Increment version
    version.fetch_add(1, Ordering::SeqCst);

    Ok(())
}
