# Poly API Reference

## polyglot-macros

Proc macros for inline foreign language expressions.

### Expression Macros

#### `js!{ expr }`
Evaluates JavaScript expression using Boa engine.
- **Returns**: Inferred from context (i32, f64, String, Vec<T>)
- **Panics**: On parse or runtime error

#### `ts!{ expr }`  
Evaluates TypeScript expression using SWC + Boa.
- **Returns**: Inferred from context
- **Panics**: On transpile or runtime error

#### `py!{ expr }`
Evaluates Rhai script (Python-like syntax).
- **Returns**: Inferred from context
- **Panics**: On parse or runtime error

#### `cuda!{ expr }` (reserved)
GPU compute - not yet implemented.

#### `sql!{ expr }` (reserved)
SQL queries - not yet implemented.

### Attribute Macro

#### `#[poly_bridge(runtime)]`

Generates type-safe wrapper for a foreign trait.

**Arguments:**
- `python` / `py` - Rhai scripting
- `javascript` / `js` - Boa JS engine
- `typescript` / `ts` - SWC + Boa

**Generates:**
- `{Prefix}{TraitName}` wrapper struct
- Trait implementation with marshaling
- `from_foreign()` constructor

**Example:**
```rust
#[poly_bridge(javascript)]
trait DataProcessor {
    fn process(&self, data: Vec<i32>) -> Vec<i32>;
}
// Generates: JsDataProcessor
```

---

## polyglot-runtime

Runtime support for embedded interpreters.

### Runtimes

#### `ScriptRuntime` (feature: `scripting`)
Rhai-based scripting engine.

```rust
let rt = ScriptRuntime::get();
let n: i32 = rt.eval_i32("1 + 2")?;
let s: String = rt.eval_string("\"hello\"")?;
let v: Vec<i32> = rt.eval_vec_i32("[1, 2, 3]")?;
rt.exec("let x = 10;")?;
```

#### `JsRuntime` (feature: `javascript`)
Boa JavaScript engine.

```rust
let rt = JsRuntime::get();
let n: i32 = rt.eval_i32("[1,2,3].reduce((a,b)=>a+b)")?;
let f: f64 = rt.eval_f64("Math.PI")?;
```

#### `TsRuntime` (feature: `typescript`)
SWC transpiler + Boa engine.

```rust
let rt = TsRuntime::get();
let n: i32 = rt.eval_i32("const x: number = 5; x * 2")?;
```

### Bridge Types

#### `ForeignValue`
```rust
pub enum ForeignValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<ForeignValue>),
    Object(HashMap<String, ForeignValue>),
    Handle(u64),
}
```

#### `ForeignHandle`
```rust
impl ForeignHandle {
    fn new(value: ForeignValue) -> Self;
    fn with_runtime(value: ForeignValue, runtime: RuntimeRef) -> Self;
    fn id(&self) -> u64;
    fn value(&self) -> &ForeignValue;
    fn call_method(&self, method: &str, args: &[ForeignValue]) -> ForeignValue;
}
```

#### `RuntimeRef`
```rust
impl RuntimeRef {
    fn new(release_fn: fn(u64)) -> Self;
    fn noop() -> Self;
    fn release(&self, id: u64);
}
```

### Marshaling Traits

#### `ToForeign`
```rust
pub trait ToForeign {
    fn to_foreign(&self) -> ForeignValue;
}
```

#### `FromForeign`
```rust
pub trait FromForeign: Sized {
    fn from_foreign(value: ForeignValue) -> Result<Self>;
}
```

---

## Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `scripting` | Rhai engine | rhai |
| `javascript` | Boa JS engine | boa_engine |
| `typescript` | SWC + Boa | boa_engine, swc_* |
| `gpu` | GPU compute (future) | - |

**Default:** `javascript`, `scripting`

---

## Cargo.toml

```toml
[dependencies]
polyglot-macros = { path = "./polyglot-macros" }
polyglot-runtime = { path = "./polyglot-runtime", features = ["javascript", "scripting"] }
```
