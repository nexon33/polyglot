# Poly

> **Private computation. Verified execution. Decentralized inference.**

Poly is a polyglot compiler and private AI infrastructure. Write multi-language programs, compile to any target, and run AI inference where **the server computes on encrypted data it cannot see**.

The stack: CKKS lattice-based homomorphic encryption, zero-knowledge execution proofs, QUIC-based peer-to-peer compute network, and a polyglot compiler that targets native executables, WASM, browser apps, and Android APKs from a single `.poly` file.

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

## Why This Exists

People need to talk to AI about things they can't talk to anyone else about. Medical questions they're afraid to ask a doctor. Mental health crises they can't afford to have on record. Legal questions where the question itself is incriminating.

Right now, every one of those conversations lives on a corporate server in plaintext. One subpoena, one breach, one policy change, and the most vulnerable conversations a person has ever had are exposed.

Poly makes it so the server **literally cannot see** what you asked or what it answered. Not "we promise not to look" -- the math makes it impossible. The computation happens on encrypted data, the result comes back encrypted, and only the person who asked can decrypt it.

### Why this matters: the case of antipsychotics vs Open Dialogue

The mental health system has a problem it cannot talk about honestly, and people who try to research alternatives face real consequences for having that search history.

**What antipsychotics do to people:**

- People with schizophrenia die **14.5-25 years earlier** than the general population
- 32-68% of patients on second-generation antipsychotics develop metabolic syndrome (obesity, type 2 diabetes, dyslipidemia)
- Sudden cardiac death rate **doubles**: ~1 in 340 person-years on antipsychotics vs ~1 in 700 for nonusers
- Long-term use causes progressive **brain volume loss** -- primate studies show ~10% reduction at human-equivalent doses, mostly from loss of glial cells
- 1 in 5 patients on SGAs long-term develop **tardive dyskinesia** (permanent involuntary movements)
- The drugs impair cellular glucose uptake in the liver, dysregulate fatty acid metabolism, and increase mitochondrial oxidative stress

**What Open Dialogue achieves (Western Lapland, Finland, 30 years of data):**

| Metric | Open Dialogue | Standard Treatment |
|---|---|---|
| Full recovery (no symptoms) | **81-85%** | ~15-20% |
| Return to work/school within 2 years | **84%** | ~20-30% |
| Still on antipsychotics at 2 years | **17-33%** | ~100% |
| Needed neuroleptics at all | **3%** | **100%** (comparison group) |
| Schizophrenia incidence (regional) | **7/100,000** (down from 35) | Unchanged elsewhere |

Open Dialogue was developed by Jaakko Seikkula's team at Keropudas Hospital. It works by responding to psychotic crises within 24 hours, meeting in the person's home instead of a hospital, including family and social network in transparent dialogue, and treating medication as a last resort instead of first-line. The 19-year follow-up confirmed these outcomes are stable.

The standard system creates chronic patients. Open Dialogue creates recovered people. 85% go back to their lives.

**The privacy problem:** Someone researching this -- questioning whether their medication is helping or harming them, looking into alternatives their doctor never mentioned -- is generating exactly the kind of search history that can be used against them in custody hearings, insurance decisions, and involuntary commitment proceedings.

That is why private AI inference is not a feature. It is infrastructure.

**Sources:**
[PMC meta-analysis on antipsychotic mortality](https://pmc.ncbi.nlm.nih.gov/articles/PMC9851750/) |
[FIN20 20-year follow-up](https://onlinelibrary.wiley.com/doi/10.1002/wps.20699) |
[AAFP adverse effects review](https://www.aafp.org/pubs/afp/issues/2010/0301/p617.html) |
[Brain volume loss (Psychiatric Times)](https://www.psychiatrictimes.com/view/antipsychotics-and-shrinking-brain) |
[Brain volume loss (PMC)](https://pmc.ncbi.nlm.nih.gov/articles/PMC3476840/) |
[Metabolic syndrome (Frontiers)](https://www.frontiersin.org/journals/psychiatry/articles/10.3389/fpsyt.2023.1257460/full) |
[Open Dialogue 19-year outcomes](https://www.sciencedirect.com/science/article/abs/pii/S0165178117323338) |
[Western Lapland long-term stability](https://www.tandfonline.com/doi/abs/10.1080/17522439.2011.595819) |
[Psychology Today overview](https://www.psychologytoday.com/us/blog/beyond-mental-health/202310/a-finnish-remedy-to-mental-health-crisis-shows-promise)

## Private Inference Demo

```
cargo run --release -p poly-inference --bin poly-demo-rns-fhe
```

```
  Network: 4x4 linear + SiLU activation
  Input:   [1.0, -0.5, 2.0, 0.8]
  Primes:  10 (9 multiplication levels)

  Slot    Expected     Decrypted         Error
     0    0.164612      0.164660       4.75e-5
     1    0.062747      0.062742       4.58e-6
     2    1.143877      1.143867       1.01e-5
     3    0.515547      0.515546       2.47e-7

  RESULT: Private inference SUCCEEDED (max error < 0.5)
```

The server performed a neural network forward pass (matrix multiply + SiLU activation) on **encrypted** data using CKKS homomorphic encryption with 10 NTT primes and 2048 SIMD slots. It never saw the input, never saw the output, and the result is mathematically correct to 5 decimal places.

## Features

| Feature | Status |
|---------|--------|
| CKKS homomorphic encryption (RNS, 20 primes) | ✅ Working |
| Private neural network inference | ✅ Working |
| Zero-knowledge execution proofs | ✅ Working |
| PFHE compression (lossless, ~2x) | ✅ Working |
| Entropy validation (IND-CPA monitor) | ✅ Working |
| Decentralized QUIC compute network | ✅ Phase 1 |
| End-to-end encrypted inference (Qwen3, Nanbeige 3B) | ✅ Working |
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
| 570+ tests | ✅ Passing |

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

**Privacy modes** — optional zero-knowledge privacy via blinding factors:
- `#[verified]` — transparent (default)
- `#[verified(private)]` — full ZK: verifier learns nothing except validity
- `#[verified(private_inputs)]` — selective: verifier sees output but not inputs

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

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
