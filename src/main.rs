use clap::{Parser, Subcommand};
use polyglot::{
    compiler::compile, parser::parse_poly, types::CompileOptions, wit_gen::generate_wit,
};

use std::fs;
use std::path::PathBuf;
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
    }

    Ok(())
}

fn build_poly(file: &PathBuf, release: bool) -> anyhow::Result<PathBuf> {
    println!("🔨 Compiling {}", file.display());
    let source = fs::read_to_string(file)?;
    let parsed = parse_poly(&source).map_err(|e| anyhow::anyhow!("{}", e))?;

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
