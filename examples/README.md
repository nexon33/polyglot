# Examples

This directory contains demos showcasing Poly's versatility.

## Rust Examples (Macro Usage)

Run with `cargo run --example <name>`:

| Example | Description |
|---------|-------------|
| `demo_javascript` | JavaScript via Boa - arrow functions, Math, template literals |
| `demo_scripting` | Rhai scripting - loops, arrays, control flow |
| `poly_runtime_demo` | Combined demo of all embedded runtimes |

```bash
cargo run --example demo_javascript
cargo run --example demo_scripting
cargo run --example poly_runtime_demo
```

## .poly Format Examples

Compile with `polyglot compile <file> --target wasm`:

| File | Description |
|------|-------------|
| `calculator.poly` | Stats calculator with Rust + JS + Python |
| `data_pipeline.poly` | Data processing pipeline across languages |
| `web_app.poly` | Full-stack web app architecture demo |

```bash
polyglot compile calculator.poly --target wasm
polyglot watch data_pipeline.poly  # Hot reload
```

## Key Features Demonstrated

### Expression Macros
```rust
let sum: i32 = js!{ [1,2,3].reduce((a,b) => a+b) };
let fact: i32 = py!{ let n=5; let r=1; for i in 1..=n { r*=i; } r };
```

### Multi-Language Files
```poly
rust {
    let data = vec![1, 2, 3];
    let doubled = js!{ data.map(x => x * 2) };
}

python {
    def process(data):
        return [x * 2 for x in data]
}
```

### Zero Dependencies
All examples run without Python, Node.js, or any external runtime installed.
