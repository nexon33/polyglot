# Poly CLI Reference

> Complete reference for the `polyglot` command-line interface.

## Synopsis

```
polyglot <COMMAND> [OPTIONS]
```

## Commands

| Command | Description |
|---------|-------------|
| `build` | Compile a poly file to executable |
| `run` | Build and run with wasmtime |
| `bundle` | Create self-contained HTML file |
| `watch` | Development server with hot reload |
| `check` | Parse and validate without compiling |
| `test` | Run inline tests |
| `init` | Initialize project in current directory |
| `new` | Create project from template |
| `wit` | Generate WIT interface |
| `component` | Build WASM component |
| `compose` | Compose multiple WASM components |
| `npm` | Manage npm dependencies |
| `tools` | Check installed component tools |
| `verify` | Verify @implements declarations |

---

## build

Compile a `.poly` file to the specified target.

```
polyglot build [OPTIONS] <FILE>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<FILE>` | Input `.poly` file |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--target <TARGET>` | `-t` | Build target (see below) |
| `--release` | `-r` | Optimized release build |
| `--emit <ARTIFACT>` | | Emit additional artifacts (`wit`, `ir`) |

### Targets

| Target | Output | Description |
|--------|--------|-------------|
| `browser` | `.wasm` + `.html` | Web application (default) |
| `windows` | `.exe` | Windows executable |
| `linux` | ELF binary | Linux executable |
| `host` | Native binary | Current platform |
| `android` | `.so` | Android native library |
| `apk` | `.apk` | Android package |

### Examples

```bash
# Browser WASM (default)
polyglot build app.poly

# Windows executable
polyglot build app.poly --target windows

# Release build for Linux
polyglot build app.poly --target linux --release

# Emit WIT alongside build
polyglot build app.poly --emit wit
```

---

## run

Build and immediately run with wasmtime.

```
polyglot run [OPTIONS] <FILE> [-- <ARGS>...]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<FILE>` | Input `.poly` file |
| `<ARGS>` | Arguments passed to the WASM program |

### Options

| Option | Description |
|--------|-------------|
| `--release` | Build in release mode (default: true) |

### Examples

```bash
# Run a program
polyglot run hello.poly

# Pass arguments
polyglot run app.poly -- --config /path/to/config
```

---

## bundle

Create a single self-contained HTML file with embedded WASM.

```
polyglot bundle [OPTIONS] <FILE>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<FILE>` | Input `.poly` file |

### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output <FILE>` | `-o` | `<name>.html` | Output HTML file |
| `--title <TITLE>` | `-t` | "Polyglot App" | HTML page title |

### Examples

```bash
# Default output name
polyglot bundle app.poly
# Creates: app.html

# Custom output
polyglot bundle app.poly -o index.html -t "My App"
```

---

## watch

Development server with hot reload.

```
polyglot watch [OPTIONS] <FILE>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<FILE>` | Input `.poly` file |

### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--port <PORT>` | `-p` | 3000 | Dev server port |
| `--open` | | false | Open browser automatically |

### Examples

```bash
# Start dev server
polyglot watch app.poly

# Custom port, auto-open browser
polyglot watch app.poly --port 8080 --open
```

---

## check

Parse and validate a file without compiling.

```
polyglot check <FILE>
```

Reports syntax errors and prints the WIT export signature.

---

## test

Run inline `#[test]` functions.

```
polyglot test <FILE>
```

### Example

```poly
#[rust] {
    pub fn add(a: i32, b: i32) -> i32 { a + b }
    
    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }
}
```

```bash
polyglot test math.poly
```

---

## init

Initialize a new project in the current directory.

```
polyglot init [OPTIONS]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--name <NAME>` | `-n` | Project name (default: directory name) |

Creates `poly.toml` and a basic project structure.

---

## new

Create a new project from a template.

```
polyglot new [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--template <NAME>` | Template to use |

### Templates

- `basic` — Minimal hello world
- (more templates planned)

---

## wit

Generate WebAssembly Interface Types definition.

```
polyglot wit [OPTIONS] <FILE>
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--output <FILE>` | `-o` | Output file (default: `<name>.wit`) |

---

## component

Build a WASM component (requires `jco`, `componentize-py`).

```
polyglot component <FILE>
```

Builds the file as a WASM component for the Component Model.

---

## compose

Compose multiple WASM components into one.

```
polyglot compose <FILES...>
```

Requires `wasm-compose` tool.

---

## npm

Manage npm dependencies for JavaScript blocks.

```
polyglot npm <ACTION> [PACKAGES...]
```

### Actions

| Action | Description |
|--------|-------------|
| `init` | Initialize package.json |
| `install` | Install packages |
| `bundle` | Bundle with esbuild |

### Examples

```bash
# Initialize npm
polyglot npm init

# Install packages
polyglot npm install react react-dom

# Bundle dependencies
polyglot npm bundle
```

---

## tools

Check which component tools are installed.

```
polyglot tools
```

Reports status of:
- `wasmtime`
- `jco`
- `componentize-py`
- `wasm-compose`

---

## verify

Verify `@implements` declarations match interface traits.

```
polyglot verify <FILE>
```

---

## Global Options

| Option | Description |
|--------|-------------|
| `--help`, `-h` | Print help information |
| `--version`, `-V` | Print version |

---

## Project Manifest (poly.toml)

Place a `poly.toml` file alongside your `.poly` files to declare dependencies and project metadata.

### Format

```toml
[package]
name = "myapp"
version = "0.1.0"
description = "My polyglot application"

[rust]
# Cargo.toml format - flows to [dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"

[npm]
# package.json format - flows to dependencies
react = "^18.0.0"
lodash = "^4.17.0"

[pip]
# requirements.txt format
numpy = ">=1.20"
requests = { version = ">=2.25", extras = ["security"] }

[build]
# Build configuration
target = "browser"  # Default target
release = false     # Default to debug builds
```

### Dependency Formats

**Rust:**
```toml
[rust]
simple = "1.0"                           # version only
complex = { version = "1.0", features = ["derive"] }
```

**NPM:**
```toml
[npm]
react = "^18.0.0"
lodash = "~4.17.0"
```

**Python:**
```toml
[pip]
numpy = ">=1.20"
requests = { version = ">=2.25", extras = ["security"] }
```

### Fallback

If no `poly.toml` exists, dependencies are auto-detected from `use` statements in your code.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANDROID_HOME` | Android SDK path (for APK builds) |
| `JAVA_HOME` | Java installation (for APK signing) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Compilation error |
| 2 | Runtime error |
| 101 | Panic |

---

## Examples

### Full Development Workflow

```bash
# Create project
mkdir myapp && cd myapp
polyglot init

# Edit main.poly
# ...

# Development with hot reload
polyglot watch main.poly --open

# Build for production
polyglot build main.poly --target browser --release
polyglot bundle main.poly -o dist/index.html
```

### Cross-Platform Build

```bash
# Build for all platforms
polyglot build app.poly --target windows --release
polyglot build app.poly --target linux --release
polyglot build app.poly --target browser --release
```

### Android Development

```bash
# Check tools
polyglot tools

# Build APK
polyglot build app.poly --target apk
```
