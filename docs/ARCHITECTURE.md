# Poly Architecture

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER CODE                                │
│   let result = js!{ [1,2,3].map(x => x*2) };                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    POLYGLOT-MACROS                               │
│   Proc macros that generate runtime calls at compile time       │
│                                                                  │
│   js!{} → JsRuntime::get().eval_i32("...")                      │
│   py!{} → ScriptRuntime::get().eval_i32("...")                  │
│   #[poly_bridge] → Wrapper struct + trait impl                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    POLYGLOT-RUNTIME                              │
│   Embedded interpreters (all pure Rust, zero external deps)     │
│                                                                  │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐     │
│   │   Rhai      │  │   Boa       │  │   SWC + Boa         │     │
│   │  Scripting  │  │ JavaScript  │  │   TypeScript        │     │
│   └─────────────┘  └─────────────┘  └─────────────────────┘     │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    BRIDGE                                │   │
│   │   ForeignHandle, ForeignValue, ToForeign, FromForeign   │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Crate Structure

```
polyglot/
├── polyglot-macros/          # Proc macro crate
│   └── src/
│       ├── lib.rs            # Macro exports
│       ├── js_macro.rs       # js!{} implementation
│       ├── py_macro.rs       # py!{} implementation  
│       ├── ts_macro.rs       # ts!{} implementation
│       ├── bridge_macro.rs   # #[poly_bridge] implementation
│       ├── capture.rs        # Variable capture analysis
│       └── gpu_macro.rs      # cuda!/gpu! stubs
│
├── polyglot-runtime/         # Runtime crate
│   └── src/
│       ├── lib.rs            # Runtime exports
│       ├── javascript.rs     # Boa JS engine wrapper
│       ├── typescript.rs     # SWC + Boa TS wrapper
│       ├── python.rs         # Rhai scripting wrapper
│       ├── bridge.rs         # FFI bridge infrastructure
│       └── marshal.rs        # Type conversion traits
│
└── docs/                     # Documentation
    ├── LANGUAGE_SPEC.md      # Language specification
    ├── API_REFERENCE.md      # API documentation
    └── ARCHITECTURE.md       # This file
```

## Data Flow

### Expression Macro Flow

```
1. User writes:     let x: i32 = js!{ 1 + 2 };

2. Macro expands to:
   {
       use polyglot_runtime::prelude::JsRuntime;
       let __js = JsRuntime::get();
       __js.eval_i32("1 + 2").expect("JS error")
   }

3. At runtime:
   - Boa parses "1 + 2"
   - Boa evaluates → JsValue
   - JsValue converted to i32
   - Result returned to user
```

### Type Bridge Flow

```
1. User writes:
   #[poly_bridge(javascript)]
   trait Calc { fn add(&self, a: i32, b: i32) -> i32; }

2. Macro expands to:
   trait Calc { fn add(&self, a: i32, b: i32) -> i32; }
   
   struct JsCalc { handle: ForeignHandle }
   
   impl Calc for JsCalc {
       fn add(&self, a: i32, b: i32) -> i32 {
           let args = vec![a.to_foreign(), b.to_foreign()];
           let result = self.handle.call_method("add", &args);
           i32::from_foreign(result).unwrap()
       }
   }

3. At runtime:
   - Args marshaled to ForeignValue
   - Method called on foreign object
   - Result unmarshaled to i32
```

## Ownership Semantics

### ForeignHandle Lifecycle

```
┌────────────────────────────────────────────────────────────────┐
│  Rust                           │  Foreign Runtime             │
├────────────────────────────────────────────────────────────────┤
│                                 │                              │
│  let obj = js!{ ({...}) };      │  Object created, GC refs it  │
│      ↓                          │                              │
│  ForeignHandle::new()           │  ID assigned                 │
│      ↓                          │                              │
│  obj.method()                   │  Method called               │
│      ↓                          │                              │
│  drop(obj)                      │  runtime.release(id)         │
│                                 │      ↓                       │
│                                 │  Reference released          │
│                                 │  GC can collect if no refs   │
└────────────────────────────────────────────────────────────────┘
```

### Clone Behavior

Cloning a `ForeignHandle` creates a new Rust reference to the same foreign object. The `id` is preserved, so both handles refer to the same object.

## Extension Points

### Adding New Runtime

1. Create `src/newlang.rs` in `polyglot-runtime`
2. Implement `eval_i32()`, `eval_f64()`, `eval_string()`, `exec()`
3. Add feature flag in `Cargo.toml`
4. Create `src/newlang_macro.rs` in `polyglot-macros`
5. Export macro in `lib.rs`

### Adding New Marshaling Type

```rust
impl ToForeign for MyType {
    fn to_foreign(&self) -> ForeignValue {
        // Convert to ForeignValue variant
    }
}

impl FromForeign for MyType {
    fn from_foreign(value: ForeignValue) -> Result<Self> {
        // Convert from ForeignValue
    }
}
```
