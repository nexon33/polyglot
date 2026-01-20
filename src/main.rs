use clap::{Parser, Subcommand};
use polyglot::{
    compiler::compile, parser::parse_poly, types::CompileOptions, wit_gen::generate_wit,
};

use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
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
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Check { file } => {
            println!("Checking {}", file.display());
            let source = fs::read_to_string(&file)?;
            match parse_poly(&source) {
                Ok(parsed) => {
                    println!("Successfully parsed {} blocks", parsed.blocks.len());
                    match generate_wit(&parsed) {
                        Ok(wit) => {
                            println!("\nGenerated WIT Interface:");
                            println!("-----------------------");
                            println!("{}", wit);
                        }
                        Err(e) => eprintln!("Error generating WIT: {}", e),
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }
        Commands::Build { file, release } => {
            println!("Compiling {}", file.display());
            let source = fs::read_to_string(&file)?;
            let parsed = parse_poly(&source).map_err(|e| anyhow::anyhow!("{}", e))?;

            let opts = CompileOptions {
                release,
                ..Default::default()
            };

            match compile(&parsed, &opts) {
                Ok(wasm) => {
                    println!("Successfully compiled {} bytes", wasm.len());
                    let out_path = file.with_extension("wasm");
                    fs::write(&out_path, wasm)?;
                    println!("Wrote to {}", out_path.display());
                }
                Err(e) => eprintln!("Compilation error: {}", e),
            }
        }
    }

    Ok(())
}
