# Examples

This directory contains demos showcasing Poly's multi-language, multi-target capabilities.

## Running Examples

```bash
# Build and run with wasmtime
polyglot run hello.poly

# Build for browser
polyglot build calculator.poly --target browser

# Build native executable
polyglot build hello.poly --target windows

# Development with hot reload
polyglot watch web_app.poly --open
```

## Example Files

| File | Description | Best Target |
|------|-------------|-------------|
| `hello.poly` | Simple hello world | Any |
| `hello_simple.poly` | Minimal example | Any |
| `calculator.poly` | Multi-language calculator | Browser |
| `calculator_simple.poly` | Basic calculator | Browser |
| `web_app.poly` | Full-stack architecture demo | Browser |
| `native_test.poly` | Native binary test | Windows/Linux |
| `host_test.poly` | Host imports test | Host |
| `pure_math.poly` | Pure computation | Any |
| `simple_apk.poly` | Android app | APK |
| `chaos.poly` | Chaos engineering demo | Browser |
| `data_pipeline.poly` | Data processing | Any |

## Hello World

```poly
// hello.poly
#[rust] {
    fn main() {
        println!("Hello from Poly!");
    }
}
```

```bash
polyglot run hello.poly
```

## Multi-Language Example

```poly
// multi.poly
#[rust] {
    fn main() {
        println!("Main logic in Rust");
    }
}

#[js] {
    const greet = (name) => `Hello, ${name}!`;
    document.onclick = () => console.log(greet("World"));
}

#[python] {
    def calculate(x, y):
        return x + y
}

#[html] {
    <div id="app">
        <h1>Multi-Language App</h1>
        <p>Click anywhere to greet!</p>
    </div>
}

#[css] {
    #app {
        font-family: system-ui;
        padding: 2rem;
        text-align: center;
    }
}
```

## Browser App with Bundle

```bash
polyglot bundle web_app.poly -o app.html --title "My App"
# Open app.html in browser
```

## Native Executable

```bash
# Windows
polyglot build native_test.poly --target windows --release
./target/native_test.exe

# Linux
polyglot build native_test.poly --target linux --release
./target/native_test
```

## Android APK

```bash
# Requires Android SDK and NDK
polyglot build simple_apk.poly --target apk
# Install: adb install target/simple_apk.apk
```

## Development Workflow

```bash
# Start dev server with hot reload
polyglot watch calculator.poly --port 8080 --open

# File changes auto-rebuild and refresh browser
```

## Key Features Demonstrated

### Language Blocks — Organize by Language
```poly
#[rust] { /* type-safe logic */ }
#[js] { /* browser interactivity */ }
#[python] { /* scripting */ }
#[html] { /* structure */ }
#[css] { /* styling */ }
```

### Inline Macros — Cross-Language Calls
```poly
#[rust] {
    fn main() {
        // Call JS inline from Rust
        let sum: i32 = js!{ [1,2,3].reduce((a,b) => a+b, 0) };
        
        // Call Python inline from Rust
        let fact: i32 = py!{ let n=5; let r=1; for i in 1..=n { r*=i; } r };
        
        println!("JS sum: {}, Py factorial: {}", sum, fact);
    }
}
```

### Cross-Target Compilation
Same source compiles to:
- Windows `.exe`
- Linux ELF
- Browser WASM + HTML
- Android APK

### Zero External Dependencies
No Python, Node.js, or other runtimes needed to build or run.
