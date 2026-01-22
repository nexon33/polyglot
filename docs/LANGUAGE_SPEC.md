# Poly Language Specification

> **One language. Every runtime.**

Poly is a polyglot macro system that enables type-safe cross-language programming in Rust.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Expression Macros](#expression-macros)
3. [Type Bridge](#type-bridge)
4. [Marshaling](#marshaling)
5. [Ownership Model](#ownership-model)
6. [Error Handling](#error-handling)

---

## Quick Start

```rust
use polyglot_macros::{js, py, ts, poly_bridge};

fn main() {
    // JavaScript - Boa engine (pure Rust)
    let sum: i32 = js!{ [1,2,3].reduce((a,b) => a+b, 0) };
    
    // TypeScript - SWC + Boa (pure Rust)
    let typed: i32 = ts!{ const x: number = 5; x * 2 };
    
    // Scripting - Rhai engine (pure Rust)
    let script: i32 = py!{ let x = 10; x * 2 };
    
    println!("{sum}, {typed}, {script}");  // 6, 10, 20
}
```

**Zero external dependencies** - all interpreters are embedded in pure Rust.

---

## Expression Macros

### `js!{ expr }`

Evaluates JavaScript using the Boa engine.

```rust
// Arithmetic
let n: i32 = js!{ 1 + 2 + 3 };

// ES6 arrow functions
let doubled: Vec<i32> = js!{ [1,2,3].map(x => x * 2) };

// Template literals
let msg: String = js!{ `Hello ${name}!` };

// Math operations
let pi: f64 = js!{ Math.PI };
```

### `ts!{ expr }`

Evaluates TypeScript using SWC (transpile) + Boa (execute).

```rust
// Type annotations
let result: i32 = ts!{ const x: number = 5; x * 2 };

// Interfaces (compile-time only)
let obj: String = ts!{
    interface Point { x: number; y: number }
    const p: Point = { x: 10, y: 20 };
    `${p.x},${p.y}`
};
```

### `py!{ expr }`

Evaluates Rhai scripting language (Python-like syntax).

```rust
// Variables and loops
let sum: i32 = py!{
    let total = 0;
    for i in 1..=10 { total += i; }
    total
};

// Arrays
let arr: Vec<i32> = py!{ [1, 2, 3, 4, 5] };

// String operations
let hello: String = py!{ "Hello" + " " + "World" };
```

---

## Type Bridge

The `#[poly_bridge]` attribute generates type-safe FFI wrappers.

### Basic Usage

```rust
#[poly_bridge(javascript)]
trait Calculator {
    fn add(&self, a: i32, b: i32) -> i32;
    fn multiply(&self, a: i32, b: i32) -> i32;
}

// Generates: JsCalculator struct
let calc: JsCalculator = js!{ ({ 
    add: (a, b) => a + b,
    multiply: (a, b) => a * b 
}) };

// Type-safe method calls!
let sum = calc.add(2, 3);       // Compile-time type checking
let prod = calc.multiply(4, 5); // Returns i32
```

### Runtime Selection

```rust
#[poly_bridge(python)]      // → PyDataFrame
#[poly_bridge(javascript)]  // → JsDataFrame  
#[poly_bridge(typescript)]  // → TsDataFrame
```

### Generated Code

For `#[poly_bridge(javascript)] trait Foo { ... }`:

1. **Wrapper struct**: `JsFoo` with `ForeignHandle`
2. **Trait impl**: Methods marshal args, call runtime, unmarshal result
3. **From impl**: `JsFoo::from_foreign(value)`

---

## Marshaling

### ToForeign Trait

Converts Rust types to foreign values:

| Rust Type | Foreign Value |
|-----------|---------------|
| `i32`, `i64` | `Int(i64)` |
| `f64` | `Float(f64)` |
| `bool` | `Bool(bool)` |
| `String`, `&str` | `String(String)` |
| `Vec<T>` | `Array(Vec<ForeignValue>)` |
| `Option<T>` | `T` or `Null` |

### FromForeign Trait

Converts foreign values to Rust types. Returns `Result<T, PolyglotError>`.

### Custom Types

```rust
use polyglot_runtime::bridge::{ToForeign, FromForeign, ForeignValue};

struct Point { x: i32, y: i32 }

impl ToForeign for Point {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::Object(HashMap::from([
            ("x".into(), self.x.to_foreign()),
            ("y".into(), self.y.to_foreign()),
        ]))
    }
}
```

---

## Ownership Model

### ForeignHandle

References to foreign objects are tracked with `ForeignHandle`:

```rust
pub struct ForeignHandle {
    id: u64,                      // Unique identifier
    value: ForeignValue,          // Cached value
    runtime: Option<RuntimeRef>,  // For cleanup
}
```

### Automatic Cleanup

When a `ForeignHandle` is dropped, it notifies the foreign runtime:

```rust
impl Drop for ForeignHandle {
    fn drop(&mut self) {
        if let Some(runtime) = &self.runtime {
            runtime.release(self.id);  // Release foreign reference
        }
    }
}
```

### Clone Semantics

Cloning a handle creates a new Rust reference to the same foreign object. The foreign runtime's reference count is not automatically incremented - this is by design for runtimes like JavaScript that use GC.

---

## Error Handling

### PolyglotError

```rust
pub enum PolyglotError {
    Python(String),         // Scripting engine error
    JavaScript(String),     // JS engine error
    TypeScript(String),     // TS compilation error
    TypeConversion(String), // Marshaling error
    NotInitialized(String), // Runtime not ready
}
```

### Error Propagation

```rust
// Panics on error (immediate feedback)
let x: i32 = js!{ invalid syntax here };  // panic!

// Explicit Result handling (future)
let result: Result<i32, PolyglotError> = js_try!{ 1 + 2 };
```

---

## Future: Expression Strings for Closures

For predicates and transformations, MVP uses expression strings:

```rust
// Instead of closures (complex to marshal)
df.filter(|r| r.price > 100)

// Use expression strings (safe, simple)
df.filter("price > 100")
df.select("name, price * 1.1 as adjusted_price")
```

This avoids the complexity of marshaling Rust closures across language boundaries while maintaining type safety for inputs and outputs.
