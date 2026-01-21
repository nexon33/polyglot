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
    /// Create a new project from a template
    New {
        /// Template name: react-app, ml-demo, or game
        template: String,

        /// Project directory (default: template name)
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
            build_poly(&file, release, false)?;
        }
        Commands::Run {
            file,
            release,
            args,
        } => {
            let wasm_path = build_poly(&file, release, false)?;
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
            build_poly(&file, false, true)?; // release=false, test_mode=true
        }
        Commands::Bundle {
            file,
            output,
            title,
        } => {
            // Build first
            let wasm_path = build_poly(&file, true, false)?;

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
        Commands::Watch { file, port, open } => {
            watch_poly(&file, port, open)?;
        }
    }

    Ok(())
}

fn build_poly(file: &PathBuf, release: bool, test_mode: bool) -> anyhow::Result<PathBuf> {
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
        test_mode,
        ..Default::default()
    };

    match compile(&parsed, &opts) {
        Ok(wasm) => {
            if test_mode {
                // Tests already ran and printed output, just return dummy path
                return Ok(file.with_extension("test"));
            }
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

/// Create a new project from a template
fn new_from_template(template: &str, name: Option<String>) -> anyhow::Result<()> {
    let project_name = name.unwrap_or_else(|| template.to_string());
    let project_dir = PathBuf::from(&project_name);

    if project_dir.exists() {
        return Err(anyhow::anyhow!(
            "Directory '{}' already exists",
            project_name
        ));
    }

    fs::create_dir_all(&project_dir)?;

    println!("🎉 Creating {} project: {}", template, project_name);

    let main_poly = match template {
        "react-app" => get_react_template(&project_name),
        "ml-demo" => get_ml_template(&project_name),
        "game" => get_game_template(&project_name),
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown template '{}'. Available: react-app, ml-demo, game",
                template
            ));
        }
    };

    fs::write(project_dir.join("main.poly"), main_poly)?;
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
    fs::write(project_dir.join("poly.toml"), poly_toml)?;
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

/// Watch mode with hot reload
fn watch_poly(file: &PathBuf, port: u16, open: bool) -> anyhow::Result<()> {
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
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&watch_dir, RecursiveMode::Recursive)?;

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
        .map_err(|e| anyhow::anyhow!("Failed to start server: {}", e))?;

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
) -> anyhow::Result<()> {
    // Build WASM first
    let source = fs::read_to_string(file)?;
    let mut parsed = parse_poly(&source).map_err(|e| anyhow::anyhow!("{}", e))?;

    let base_dir = file.parent().unwrap_or(Path::new("."));
    resolve_imports(&mut parsed, base_dir)?;

    if let Err(errors) = validate(&parsed) {
        return Err(anyhow::anyhow!("Validation failed: {:?}", errors));
    }

    let opts = CompileOptions {
        release: false, // Dev mode - faster builds
        ..Default::default()
    };

    let wasm = compile(&parsed, &opts)?;

    // Bundle to HTML
    let temp_dir = file
        .parent()
        .unwrap_or(Path::new("."))
        .join("target/polyglot_tmp");
    let bundle = polyglot::compiler::bundle_to_single_file(&temp_dir, &wasm, "Polyglot Dev")?;

    fs::write(html_path, &bundle)?;

    // Increment version
    version.fetch_add(1, Ordering::SeqCst);

    Ok(())
}
