# Poly

> **One language. Every platform.**

Poly is a polyglot compiler that lets you write multi-language programs and compile them to **native executables**, **WASM**, **browser apps**, or **Android APKs** from a single `.poly` file.

## Two Ways to Mix Languages

### 1. Language Blocks — Organize by Language

```poly
// Separate sections for each language
#[rust] {
    fn main() {
        println!("Hello from Poly!");
    }
}

#[js] {
    const greet = (name) => `Hello, ${name}!`;
}

#[python] {
    def add(a, b):
        return a + b
}
```

### 2. Inline Macros — Embed in Rust

```poly
#[rust] {
    fn main() {
        // Call JavaScript inline
        let doubled: Vec<i32> = js!{ [1,2,3].map(x => x * 2) };
        
        // Call Python inline  
        let sum: i32 = py!{ sum([1, 2, 3, 4, 5]) };
        
        println!("Doubled: {:?}, Sum: {}", doubled, sum);
    }
}
```

Both approaches work together — use blocks to organize code, macros to call across languages inline.

Build for any target:
```bash
polyglot build hello.poly --target windows  # → hello.exe
polyglot build hello.poly --target linux    # → hello (ELF)
polyglot build hello.poly --target browser  # → hello.wasm + HTML
polyglot build hello.poly --target apk      # → hello.apk
```

## Features

| Feature | Status |
|---------|--------|
| Rust blocks | ✅ Full support |
| JavaScript blocks | ✅ Full support |
| Python blocks | ✅ Full support |
| HTML/CSS blocks | ✅ Full support |
| Verified execution (`#[verified]`) | ✅ Working |
| Native executables (Windows/Linux) | ✅ Working |
| WASM compilation | ✅ Working |
| Browser bundling | ✅ Working |
| Android APK | ✅ Working |
| Hot reload (`watch`) | ✅ Working |
| Inline tests | ✅ Working |
| WASM Components | 🚧 Experimental |

## Installation

```bash
# Clone and build
git clone https://github.com/user/poly.git
cd poly
cargo build --release

# Add to PATH
export PATH="$PATH:$(pwd)/target/release"
```

## Quick Start

### Hello World

```poly
// hello.poly
#[rust] {
    fn main() {
        println!("Hello, Poly!");
    }
}
```

```bash
polyglot run hello.poly
```

### Browser App

```poly
// app.poly
#[html] {
    <div id="app">
        <h1>My Poly App</h1>
        <button onclick="greet()">Click me</button>
    </div>
}

#[css] {
    #app {
        font-family: system-ui;
        padding: 2rem;
    }
    button {
        padding: 0.5rem 1rem;
        cursor: pointer;
    }
}

#[js] {
    function greet() {
        alert("Hello from Poly!");
    }
}

#[main] {
    // Entry point for WASM
}
```

```bash
polyglot bundle app.poly -o app.html
# Open app.html in browser
```

### Native App with GUI

```poly
// gui.poly
#[rust] {
    use eframe::egui;
    
    fn main() -> eframe::Result<()> {
        eframe::run_simple_native("Poly App", Default::default(), |ctx, _| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Hello from Poly!");
            });
        })
    }
}
```

```bash
polyglot build gui.poly --target windows
./gui.exe
```

### Verified Execution

Mark functions with `#[verified]` to get mathematical proofs of correct execution:

```poly
#[rust] {
    use poly_verified::prelude::*;
    use polyglot_macros::verified;

    #[verified]
    fn add_scores(a: u64, b: u64) -> u64 {
        a.saturating_add(b)
    }

    fn main() {
        let result = add_scores(42, 58);
        println!("Value: {}", result.value());      // 100
        println!("Verified: {}", result.is_verified()); // true
    }
}
```

The compiler enforces determinism at compile time -- no floats, IO, unsafe, or randomness allowed inside `#[verified]` functions. Results are wrapped in `Verified<T>` which carries a cryptographic proof.

See [Verified Execution](docs/VERIFIED_EXECUTION.md) for full documentation.

## Language Blocks

### Rust `#[rust]` or `#[rs]`
The primary language. Compiles to native code or WASM.

```poly
#[rust] {
    use std::collections::HashMap;
    
    pub fn main() {
        let mut map = HashMap::new();
        map.insert("key", "value");
        println!("{:?}", map);
    }
}
```

### JavaScript `#[js]` or `#[javascript]`
For frontend logic and browser APIs.

```poly
#[js] {
    const fetchData = async (url) => {
        const res = await fetch(url);
        return res.json();
    };
    
    document.getElementById("btn").onclick = () => {
        console.log("Clicked!");
    };
}
```

### Python `#[python]` or `#[py]`
For scripting, data processing, ML.

```poly
#[python] {
    def process_data(items):
        return [x * 2 for x in items if x > 0]
    
    result = process_data([1, -2, 3, 4])
    print(f"Result: {result}")
}
```

### HTML `#[html]`
For document structure. Inlined into the bundle.

```poly
#[html] {
    <div class="container">
        <h1>Welcome</h1>
        <p>This is a Poly app.</p>
    </div>
}
```

### CSS `#[css]`
For styling. Inlined into the bundle.

```poly
#[css] {
    .container {
        max-width: 800px;
        margin: 0 auto;
    }
}
```

## Imports

Import from other `.poly` files:

```poly
use * from "./utils.poly"
use { helper, Config } from "./lib.poly"
```

## Commands

```bash
# Build
polyglot build file.poly --target <browser|windows|linux|apk>
polyglot build file.poly --release  # Optimized build

# Run
polyglot run file.poly              # Build and run with wasmtime
polyglot run file.poly -- arg1 arg2 # Pass arguments

# Development
polyglot watch file.poly            # Hot reload on changes
polyglot check file.poly            # Parse and validate
polyglot test file.poly             # Run inline tests

# Bundle
polyglot bundle file.poly -o out.html  # Self-contained HTML

# Project
polyglot init                       # Initialize project
polyglot new --template basic       # Create from template

# Advanced
polyglot wit file.poly              # Generate WIT interface
polyglot component file.poly        # Build WASM component
polyglot compose a.wasm b.wasm      # Compose components
```

## Build Targets

| Target | Output | Use Case |
|--------|--------|----------|
| `browser` | `.wasm` + `.html` | Web apps |
| `windows` | `.exe` | Windows desktop |
| `linux` | ELF binary | Linux desktop/server |
| `apk` | `.apk` | Android apps |
| `host` | Native binary | Current platform |

## Dependencies (poly.toml)

Create a `poly.toml` next to your `.poly` file to declare dependencies:

```toml
[package]
name = "myapp"
version = "0.1.0"

[rust]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
reqwest = "0.11"

[npm]
react = "^18.0.0"
lodash = "^4.17.0"

[pip]
numpy = ">=1.20"
requests = ">=2.25"

[verified]
backend = "hash-ivc"    # or "mock" for testing
fold_interval = 32       # auto-fold every N operations
```

Dependencies flow into the appropriate package manager:
- `[rust]` → Cargo.toml
- `[npm]` → package.json
- `[pip]` → requirements.txt
- `[verified]` → Verified execution configuration

If no `poly.toml` exists, common dependencies are auto-detected from `use` statements.

## Examples

See the `examples/` directory:

- `hello.poly` - Basic hello world
- `web_app.poly` - Full-stack web app
- `calculator.poly` - Interactive calculator
- `native_test.poly` - Native binary test

## Documentation

- [Language Specification](docs/LANGUAGE_SPEC.md) - Full syntax reference
- [Architecture](docs/ARCHITECTURE.md) - Compiler internals
- [Verified Execution](docs/VERIFIED_EXECUTION.md) - Provable computation guide
- [Android Builds](docs/APK_GENERATION.md) - APK generation guide

## Philosophy

- **One file, many languages** - Write Rust, JS, Python together
- **One command, any target** - Same source → exe, wasm, apk
- **Zero config** - Sensible defaults, no boilerplate
- **Native performance** - Compiles to real machine code

## License

MIT
