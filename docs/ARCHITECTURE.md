# Poly Compiler Architecture

> How the Polyglot compiler transforms `.poly` files into executables.

## Overview

Poly supports two complementary paradigms:
- **Language Blocks** — `#[rust] { }`, `#[js] { }` for organizing code by language
- **Inline Macros** — `js!{}`, `py!{}` for cross-language calls within Rust

```
┌─────────────────────────────────────────────────────────────────┐
│                         SOURCE FILE                              │
│   #[rust] { fn main() { let x = js!{ 1+2 }; } }                 │
│   #[js] { const render = (d) => console.log(d); }               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                         PARSER                                   │
│   Extracts language blocks, imports, signatures                  │
│   → ParsedFile { blocks, signatures, interfaces, imports }      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SYNTAX NORMALIZATION                          │
│   Converts language-specific syntax to Rust equivalents         │
│   → Python f-strings → format!()                                │
│   → JS template literals → format!()                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      CODE MERGER                                 │
│   Combines all Rust blocks into single main.rs                  │
│   → Inserts runtime imports, host bindings                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
               ┌────────────┴────────────┐
               ▼                         ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│     WASM BACKEND         │  │    NATIVE BACKEND        │
│   cargo build --target   │  │  cargo build --target    │
│   wasm32-unknown-unknown │  │  x86_64-pc-windows-msvc  │
└──────────────────────────┘  └──────────────────────────┘
               │                         │
               ▼                         ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│  BUNDLER (browser)       │  │  OUTPUT                  │
│  → Embed WASM in HTML    │  │  → .exe / ELF / .apk     │
│  → Inline JS/CSS         │  │                          │
└──────────────────────────┘  └──────────────────────────┘
```

## Source Files

```
polyglot/src/
├── main.rs               # CLI entry point (clap-based)
├── lib.rs                # Library exports
├── parser.rs             # .poly file parser
├── syntax_aliases.rs     # Cross-language syntax normalization
├── compiler.rs           # Rust compilation orchestration
├── types.rs              # Core type definitions
├── validation.rs         # Semantic validation
├── diagnostic.rs         # Error reporting (miette-based)
├── source_map.rs         # Source location tracking
├── wit_gen.rs            # WIT interface generation
├── host_imports.rs       # Host function bindings
├── host_imports_injectable.rs  # Injectable host imports
├── capability.rs         # Capability checking
├── apk_builder.rs        # Android APK generation
├── component_builder.rs  # WASM Component Model builder
├── component_linker.rs   # WASM component linking
├── implements_verify.rs  # @implements verification
└── ast_parser.rs         # AST-level parsing utilities
```

## Key Modules

### parser.rs

Parses `.poly` files into structured data.

```rust
pub struct ParsedFile {
    pub blocks: Vec<CodeBlock>,      // Language-tagged code
    pub signatures: Vec<FunctionSig>, // Export signatures
    pub interfaces: Vec<InterfaceItem>, // Interface definitions
    pub imports: Vec<Import>,         // File imports
}

pub struct CodeBlock {
    pub lang_tag: String,    // "rust", "js", "python", etc.
    pub code: String,        // Block content
    pub options: HashMap<String, String>,
    pub start_line: usize,
    pub code_start_line: usize,
}
```

**Key algorithm: `find_matching_brace()`**

Handles nested braces while respecting:
- String literals (`"..."`, `'...'`, `` `...` ``)
- Raw strings (`r"..."`, `r#"..."#`)
- Triple-quoted strings (`"""..."""`)
- Comments (`//`, `/* */`)
- Template literal interpolation (`${...}`)
- Regex literals (`/pattern/flags`)
- Rust lifetimes (`'a`, `'static`) — NOT char literals

### syntax_aliases.rs

Normalizes non-Rust syntax to Rust equivalents.

| Source | Target |
|--------|--------|
| `print(x)` | `println!("{}", x)` |
| `f"hello {name}"` | `format!("hello {}", name)` |
| `` `template ${x}` `` | `format!("template {}", x)` |
| `console.log(x)` | `println!("{:?}", x)` |
| `this.field` | `self.field` |

**Selective application:** Only runs on non-Rust blocks to preserve Rust semantics.

### compiler.rs

Orchestrates the Rust compilation pipeline.

```rust
pub fn compile(source: &str, options: &CompileOptions) -> Result<PathBuf, CompileError>
```

**Steps:**
1. Parse `.poly` file
2. Resolve imports recursively
3. Merge blocks into single Rust source
4. Write to temp directory
5. Generate `Cargo.toml` with dependencies
6. Invoke `cargo build` with target
7. Copy output artifact

### types.rs

Core type definitions for the compiler.

```rust
pub struct CompileOptions {
    pub target: Target,
    pub release: bool,
    pub emit_wit: bool,
    pub emit_ir: bool,
}

pub enum Target {
    Browser,   // WASM + HTML
    Host,      // Native for current platform
    Windows,   // x86_64-pc-windows-msvc
    Linux,     // x86_64-unknown-linux-gnu
    Android,   // aarch64-linux-android
    Apk,       // Full APK package
}

pub struct FunctionSig {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Option<WitType>,
}
```

### wit_gen.rs

Generates WebAssembly Interface Types (WIT) from export signatures.

```rust
pub fn generate_wit(parsed: &ParsedFile) -> String
```

Example output:
```wit
package poly:component;

interface exports {
    greet: func(name: string) -> string;
    add: func(a: s32, b: s32) -> s32;
}

world poly-world {
    export exports;
}
```

### diagnostic.rs

Error reporting with source locations using miette.

```rust
#[derive(Error, Diagnostic)]
pub struct ParseDiagnostic {
    #[source_code]
    src: PolySource,
    #[label("error occurred here")]
    location: SourceSpan,
    message: String,
}
```

Produces errors like:
```
error[E0001]: Unmatched brace
  --> file.poly:15:10
   |
15 |     fn broken( {
   |              ^ unclosed brace
```

### apk_builder.rs

Android APK generation pipeline.

```rust
pub struct ApkBuilder {
    ndk_path: PathBuf,
    sdk_path: PathBuf,
}
```

**Steps:**
1. Compile to `aarch64-linux-android` target
2. Create APK structure
3. Add native library to `lib/arm64-v8a/`
4. Generate `AndroidManifest.xml`
5. Sign with debug key
6. Align with `zipalign`

### component_builder.rs

WASM Component Model support.

```rust
pub fn check_component_tools() -> Vec<ToolStatus>
pub fn build_component(file: &Path) -> Result<PathBuf>
```

Requires external tools:
- `jco` — JavaScript Component tools
- `componentize-py` — Python component builder
- `wasm-compose` — Component composer

## Compilation Targets

### Browser (WASM)

```
.poly → Rust → wasm32-unknown-unknown → .wasm
                    ↓
         Bundle with HTML/JS/CSS → index.html
```

The bundler:
1. Base64-encodes WASM
2. Inlines `#[html]` blocks into `<body>`
3. Inlines `#[css]` blocks into `<style>`
4. Inlines `#[js]` blocks into `<script>`
5. Adds WASM loader glue code

### Native (Windows/Linux)

```
.poly → Rust → target-triple → .exe / ELF
```

Uses `cross` or native `cargo build` with appropriate target triple.

### Android APK

```
.poly → Rust → aarch64-linux-android → libpoly.so
                    ↓
         APK packaging → app-debug.apk
```

## Import Resolution

```poly
use * from "./utils.poly"
use { helper } from "../shared/lib.poly"
```

**Resolution algorithm:**
1. Path is relative to importing file
2. Recursively parse imported file
3. Merge blocks from imported file
4. Handle circular imports (detect and error)

## Error Handling

All errors flow through miette for rich diagnostics:

```rust
enum PolyError {
    Parse(ParseDiagnostic),
    Compile(RustCompileError),
    NoMain(NoMainError),
    MultipleMain(MultipleMainError),
    Validation(ValidationError),
}
```

## Extension Points

### Adding a New Language Block

1. Update `parser.rs` to recognize new tag
2. Add syntax normalization in `syntax_aliases.rs` (if needed)
3. Update bundler to handle the block type
4. Add documentation

### Adding a New Build Target

1. Add variant to `Target` enum in `types.rs`
2. Implement compilation in `compiler.rs`
3. Add target triple and dependencies
4. Update CLI in `main.rs`

## Dependencies

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }  # CLI
miette = { version = "7", features = ["fancy"] }  # Errors
regex = "1"                                       # Parsing
notify = "6"                                      # File watching
axum = "0.7"                                      # Dev server
```

**Build-time dependencies:**
- `cargo` — Rust compilation
- `wasmtime` — WASM execution (for `run`)
- Android NDK — APK builds
