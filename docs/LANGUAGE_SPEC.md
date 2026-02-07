# Poly Language Specification

> Version 1.0 — February 2026

## Overview

Poly is a polyglot source format that combines multiple languages in a single `.poly` file. The compiler parses language-tagged blocks and compiles them to the appropriate target.

## File Structure

A `.poly` file consists of:
1. **Comments** — Single-line `//` comments
2. **Imports** — `use` statements for other `.poly` files
3. **Language blocks** — `#[lang] { code }` sections

```poly
// Comments at top level
use * from "./utils.poly"

#[rust] {
    // Rust code here
}

#[js] {
    // JavaScript code here
}
```

## Two Paradigms

Poly supports two complementary ways to mix languages:

| Paradigm | Syntax | Use Case |
|----------|--------|----------|
| **Blocks** | `#[rust] { ... }` | Organize code by language |
| **Macros** | `js!{ ... }` | Inline cross-language calls |

## Language Blocks

### Syntax

```
#[language_tag] {
    code
}
```

Or with options:

```
#[language_tag, option="value"] {
    code
}
```

### Supported Languages

| Tag | Aliases | Description |
|-----|---------|-------------|
| `rust` | `rs` | Rust code (primary) |
| `javascript` | `js` | JavaScript code |
| `python` | `py` | Python code |
| `html` | — | HTML markup |
| `css` | — | CSS styles |
| `main` | — | Entry point marker |

### Rust Blocks

Rust is the primary language. Most compilation happens through Rust.

```poly
#[rust] {
    use std::collections::HashMap;
    
    pub fn main() {
        println!("Hello!");
    }
}

// Short form
#[rs] {
    fn helper() -> i32 { 42 }
}
```

**Features supported:**
- Full Rust syntax including generics, lifetimes, macros
- `use` statements for crates
- `async`/`await` (with tokio for native builds)
- All standard library types

### JavaScript Blocks

For frontend logic and browser APIs.

```poly
#[js] {
    const greet = (name) => `Hello, ${name}!`;
    
    document.querySelector('#btn').onclick = () => {
        console.log(greet('World'));
    };
}

// Short form
#[javascript] {
    // Same as #[js]
}
```

**Features supported:**
- ES6+ syntax (arrow functions, template literals, destructuring)
- DOM manipulation
- `async`/`await`, Promises
- Module imports (when using `npm` command)

### Python Blocks

For scripting and data processing.

```poly
#[python] {
    def process(items):
        return [x * 2 for x in items]
    
    result = process([1, 2, 3])
    print(f"Result: {result}")
}

// Short form
#[py] {
    # Same as #[python]
}
```

**Note:** Python blocks are transpiled or interpreted depending on target.

### HTML Blocks

For document structure.

```poly
#[html] {
    <div id="app">
        <h1>Title</h1>
        <p>Content here.</p>
    </div>
}
```

HTML is extracted and inlined into the bundle's `<body>`.

### CSS Blocks

For styling.

```poly
#[css] {
    #app {
        max-width: 800px;
        margin: 0 auto;
    }
    
    h1 {
        color: #333;
    }
}
```

CSS is extracted and inlined into a `<style>` tag.

### Main Block

Marks the entry point for WASM targets.

```poly
#[main] {
    // Called when WASM module loads
}
```

For native targets, use `fn main()` in a Rust block.

## Inline Macros

Within Rust blocks, you can embed other languages inline using macros.

### `js!{ expr }`

Evaluate JavaScript and return the result to Rust.

```poly
#[rust] {
    fn main() {
        // Simple expression
        let sum: i32 = js!{ 1 + 2 + 3 };
        
        // Array operations
        let doubled: Vec<i32> = js!{ [1,2,3].map(x => x * 2) };
        
        // Template literals
        let msg: String = js!{ `Hello, ${"World"}!` };
        
        // Complex logic
        let result: f64 = js!{
            const data = [1, 2, 3, 4, 5];
            data.reduce((a, b) => a + b) / data.length
        };
        
        println!("{}, {:?}, {}, {}", sum, doubled, msg, result);
    }
}
```

### `py!{ expr }`

Evaluate Python/Rhai scripting inline.

```poly
#[rust] {
    fn main() {
        // Arithmetic
        let factorial: i32 = py!{
            let n = 5;
            let result = 1;
            for i in 1..=n { result *= i; }
            result
        };
        
        // List comprehension style
        let squares: Vec<i32> = py!{ [1, 4, 9, 16, 25] };
        
        println!("5! = {}, squares = {:?}", factorial, squares);
    }
}
```

### `ts!{ expr }`

Evaluate TypeScript (transpiled via SWC, then executed).

```poly
#[rust] {
    fn main() {
        let typed: i32 = ts!{
            const x: number = 10;
            const y: number = 20;
            x + y
        };
        println!("TypeScript result: {}", typed);
    }
}
```

### Type Marshaling

Macros automatically convert between Rust and foreign types:

| Rust Type | Foreign Value |
|-----------|---------------|
| `i32`, `i64` | Integer |
| `f64` | Float |
| `bool` | Boolean |
| `String` | String |
| `Vec<T>` | Array |
| `Option<T>` | Value or null |

### When to Use Each

| Use Case | Approach |
|----------|----------|
| Organizing a multi-language app | Language blocks |
| Quick inline calculation | Macros |
| DOM manipulation (browser) | `#[js]` block |
| Data processing in Rust | `py!{}` macro for helpers |
| Type definitions | `#[rust]` block |

---

## Imports

Import definitions from other `.poly` files:

```poly
// Import everything
use * from "./utils.poly"

// Import specific items
use { helper, Config } from "./lib.poly"

// Relative paths
use * from "../shared/types.poly"
```

**Resolution:**
- Paths are relative to the importing file
- `.poly` extension is required
- Imported blocks are merged into the compilation

## Comments

```poly
// This is a single-line comment

#[rust] {
    // Comments inside blocks follow that language's rules
    /* Block comments work in Rust/JS */
}

#[python] {
    # Python uses hash comments
    """
    And docstrings
    """
}
```

## Block Options

Blocks can have options:

```poly
#[rust, feature="async"] {
    async fn fetch() { }
}
```

Currently recognized options:
- Reserved for future use

## Strings and Escaping

Each language block follows its own string rules:

```poly
#[rust] {
    let s = "double quotes";
    let r = r#"raw string"#;
    let c = 'c';  // char
}

#[js] {
    const s = "double quotes";
    const t = `template ${literal}`;
    const r = /regex/gi;
}

#[python] {
    s = "double quotes"
    s2 = 'single quotes'
    ml = """multiline
    string"""
    f = f"formatted {value}"
}
```

The parser correctly handles:
- Nested braces inside strings
- Escape sequences (`\"`, `\'`, `\\`)
- Template literals with `${}` interpolation
- Raw strings (`r"..."`, `r#"..."#`)
- Triple-quoted strings
- Rust lifetimes (`'a`, `'static`)

## Entry Points

### Native Builds

Use `fn main()` in a Rust block:

```poly
#[rust] {
    fn main() {
        println!("Native app!");
    }
}
```

Or `export fn main()`:

```poly
#[rust] {
    export fn main() {
        // Exported main
    }
}
```

### WASM/Browser Builds

Use `#[main]` block:

```poly
#[main] {
    console.log("WASM loaded!");
}
```

Or call into Rust from JS.

## Type Exports

Export types for use across blocks (planned):

```poly
#[rust] {
    #[derive(Debug)]
    pub struct User {
        pub name: String,
        pub age: u32,
    }
}

#[js] {
    // User type available here
}
```

## Inline Tests

```poly
#[rust] {
    pub fn add(a: i32, b: i32) -> i32 {
        a + b
    }
    
    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }
}
```

Run with:
```bash
polyglot test file.poly
```

## WIT Interface Generation

The compiler can generate WebAssembly Interface Types (WIT):

```poly
#[rust] {
    export fn greet(name: String) -> String {
        format!("Hello, {}!", name)
    }
}
```

Generates:
```wit
package poly:component;

interface exports {
    greet: func(name: string) -> string;
}
```

## Error Handling

Parse errors report the source location:

```
error[E0001]: Unmatched brace
  --> file.poly:15:10
   |
15 |     fn broken( {
   |              ^ unclosed brace
```

## Reserved Keywords

These are reserved for future use:
- `cuda!{}` — GPU compute
- `sql!{}` — Database queries
- `wgsl!{}` — WebGPU shaders

## Grammar (Simplified)

```ebnf
file        = { comment | import | block } ;
comment     = "//" { any } newline ;
import      = "use" import_items "from" string ;
import_items = "*" | "{" ident { "," ident } "}" ;
block       = "#[" tag { "," option } "]" "{" code "}" ;
tag         = "rust" | "rs" | "js" | "javascript" | "python" | "py" | "html" | "css" | "main" ;
option      = ident "=" string ;
code        = { any except unmatched-brace } ;
```

## Compatibility

- Rust: 1.70+
- JavaScript: ES6+
- Python: 3.8+ (syntax)
- Targets: Windows, Linux, macOS, WASM, Android
