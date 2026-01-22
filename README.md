# Poly

> **One language. Every runtime.**

Poly is a polyglot macro system that enables type-safe cross-language programming in Rust with **zero external dependencies**.

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## Quick Start

```rust
use polyglot_macros::{js, py, ts};

fn main() {
    // JavaScript (Boa engine - pure Rust)
    let sum: i32 = js!{ [1,2,3].reduce((a,b) => a+b, 0) };
    
    // TypeScript (SWC + Boa - pure Rust)
    let typed: i32 = ts!{ const x: number = 5; x * 2 };
    
    // Scripting (Rhai - pure Rust)
    let result: i32 = py!{ let x = 10; x * 2 };
    
    println!("{sum}, {typed}, {result}");  // 6, 10, 20
}
```

**All interpreters are embedded. No Python, Node.js, or external runtimes required.**

## Features

| Macro | Engine | Status |
|-------|--------|--------|
| `js!{}` | Boa | ✅ Working |
| `ts!{}` | SWC + Boa | ✅ Working |
| `py!{}` | Rhai | ✅ Working |
| `cuda!{}` | - | 🚧 Reserved |
| `sql!{}` | - | 🚧 Reserved |
| `#[poly_bridge]` | - | ✅ Designed |

## Installation

```toml
[dependencies]
polyglot-macros = { path = "./polyglot-macros" }
polyglot-runtime = { path = "./polyglot-runtime" }
```

## Type-Safe FFI Bridge

```rust
use polyglot_macros::poly_bridge;

#[poly_bridge(javascript)]
trait Calculator {
    fn add(&self, a: i32, b: i32) -> i32;
}

// Generates JsCalculator with type-safe methods
```

## The `.poly` Format

Poly also supports `.poly` files - multi-language source files:

```poly
// main.poly

import numpy as np  // Python imports

rust {
    // Macros are auto-imported in .poly files!
    let data = vec![1, 2, 3, 4, 5];
    let doubled = py!{ (np.array(data) * 2).tolist() };
}

python {
    def process(data):
        return [x * 2 for x in data]
}

javascript {
    const render = (data) => console.log(data);
}
```

Compile with:
```bash
polyglot compile main.poly --target wasm
polyglot watch main.poly  # Hot reload
```

## Documentation

- [Language Spec](docs/LANGUAGE_SPEC.md) - Full specification
- [API Reference](docs/API_REFERENCE.md) - Complete API docs
- [Architecture](docs/ARCHITECTURE.md) - System design

## Running Examples

```bash
cargo run --example poly_runtime_demo
```

## Building

```bash
cargo build -p polyglot-macros -p polyglot-runtime
```

## Philosophy

- **Simple things simple**: `let x: i32 = js!{ 1 + 2 };`
- **Complex things possible**: `#[poly_bridge(javascript)]`
- **Zero dependencies**: All interpreters are pure Rust
- **Type safety**: Compile-time checking across language boundaries

## License

MIT
