use clap::{Parser, Subcommand};
use polyglot::{
    compiler::compile,
    parser::{ParsedFile, parse_poly},
    types::CompileOptions,
    validate,
    wit_gen::generate_wit,
};

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    },
    /// Build and run a poly file with wasmtime
    Run {
        /// Input file
        file: PathBuf,

        /// Build in release mode (default)
        #[arg(long, default_value_t = true)]
        release: bool,

        /// Arguments to pass to the WASM program (use -- before args)
        #[arg(trailing_var_arg = true, last = true)]
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
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Check { file } => {
            println!("🔍 Checking {}", file.display());
            let source = fs::read_to_string(&file)?;
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
        Commands::Build { file, release } => {
            build_poly(&file, release)?;
        }
        Commands::Run {
            file,
            release,
            args,
        } => {
            let wasm_path = build_poly(&file, release)?;
            run_wasm(&wasm_path, &args)?;
        }
        Commands::Init { name } => {
            init_project(name)?;
        }
        Commands::Bundle {
            file,
            output,
            title,
        } => {
            // Build first
            let wasm_path = build_poly(&file, true)?;

            // Read WASM bytes
            let wasm_bytes = fs::read(&wasm_path)?;

            // Get temp dir from the file's parent
            let temp_dir = file
                .parent()
                .unwrap_or(Path::new("."))
                .join("target/polyglot_tmp");

            // Generate bundle
            let bundle = polyglot::compiler::bundle_to_single_file(&temp_dir, &wasm_bytes, &title)?;

            // Determine output path
            let out_path = output.unwrap_or_else(|| {
                let stem = file.file_stem().unwrap_or_default().to_string_lossy();
                PathBuf::from(format!("{}.html", stem))
            });

            fs::write(&out_path, &bundle)?;

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
                fs::canonicalize(&out_path)?.display()
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
                    fs::write("_poly_entry.js", entry)?;

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
    }

    Ok(())
}

fn build_poly(file: &PathBuf, release: bool) -> anyhow::Result<PathBuf> {
    println!("🔨 Compiling {}", file.display());
    let source = fs::read_to_string(file)?;
    let mut parsed = parse_poly(&source).map_err(|e| anyhow::anyhow!("{}", e))?;

    // Resolve imports - load and merge imported files
    let base_dir = file.parent().unwrap_or(std::path::Path::new("."));
    resolve_imports(&mut parsed, base_dir)?;

    // Validate interface contracts
    if let Err(errors) = validate(&parsed) {
        println!("\n🔍 Validation Errors:");
        for err in &errors {
            eprintln!("   {}", err);
        }
        return Err(anyhow::anyhow!(
            "{} validation error(s) found",
            errors.len()
        ));
    }

    let opts = CompileOptions {
        release,
        ..Default::default()
    };

    match compile(&parsed, &opts) {
        Ok(wasm) => {
            println!("✅ Successfully compiled {} bytes", wasm.len());
            let out_path = file.with_extension("wasm");
            fs::write(&out_path, wasm)?;
            println!("📦 Wrote to {}", out_path.display());
            Ok(out_path)
        }
        Err(e) => {
            eprintln!("❌ Compilation error: {}", e);
            Err(anyhow::anyhow!("Compilation failed"))
        }
    }
}

fn run_wasm(wasm_path: &PathBuf, args: &[String]) -> anyhow::Result<()> {
    println!("🚀 Running {}...\n", wasm_path.display());

    let mut cmd = Command::new("wasmtime");
    cmd.arg(wasm_path);
    cmd.args(args);

    let status = cmd.status()?;

    if !status.success() {
        if let Some(code) = status.code() {
            eprintln!("\n❌ Process exited with code {}", code);
        }
    }

    Ok(())
}

fn init_project(name: Option<String>) -> anyhow::Result<()> {
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

    fs::write("main.poly", main_poly)?;
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

    fs::write("poly.toml", poly_toml)?;
    println!("📝 Created poly.toml");

    println!("\n✅ Project initialized! Run:");
    println!("   polyglot build main.poly");
    println!("   polyglot run main.poly");

    Ok(())
}

/// Resolve imports by loading and merging imported .poly files
fn resolve_imports(parsed: &mut ParsedFile, base_dir: &Path) -> anyhow::Result<()> {
    use std::collections::HashSet;

    fn resolve_inner(
        parsed: &mut ParsedFile,
        base_dir: &Path,
        visited: &mut HashSet<PathBuf>,
    ) -> anyhow::Result<()> {
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
                return Err(anyhow::anyhow!("Import not found: {}", import.path));
            }

            println!("   ← {}", import.path);
            visited.insert(import_path.clone());

            let import_source = fs::read_to_string(&import_path)?;
            let mut import_parsed = parse_poly(&import_source)
                .map_err(|e| anyhow::anyhow!("Error parsing {}: {}", import.path, e))?;

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
