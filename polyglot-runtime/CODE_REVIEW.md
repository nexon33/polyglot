# polyglot-runtime — Documentation & Code Review

## Overview

`polyglot-runtime` is the runtime half of the "pyrs polyglot" toolchain. It provides the
embedded language interpreters and the type-marshalling glue that lets Rust code execute
snippets of JavaScript, TypeScript, Python, and a Rhai-based scripting language inline.

It is the companion of [`polyglot-macros`](../polyglot-macros). The proc-macros (`js!`,
`ts!`, `py!`, `bridge!`, etc.) do not execute anything themselves — they expand into Rust
code that calls into this crate. For example
[polyglot-macros/src/js_macro.rs](polyglot-macros/src/js_macro.rs) emits
`JsRuntime::get()` / `JsRuntime::eval(...)`, and
[polyglot-macros/src/bridge_macro.rs](polyglot-macros/src/bridge_macro.rs) emits
`polyglot_runtime::bridge::{ForeignValue, ForeignHandle, ToForeign, FromForeign}` calls.
Everything is "fully embedded" — no Node.js or CPython process is spawned; all four
backends are pure-Rust libraries.

The crate's public surface is:

- Language runtimes: `JsRuntime`, `TsRuntime`, `PyRuntime`, `ScriptRuntime`
  (alias `PythonRuntime`).
- The bridge/FFI layer: `ForeignValue`, `ForeignHandle`, `RuntimeRef`, `ToForeign`,
  `FromForeign`.
- The error type `PolyglotError` and crate `Result<T>`.

## Architecture

### Language backends

| Backend | Module | Underlying engine | How it works |
|---------|--------|-------------------|--------------|
| JavaScript | [src/javascript.rs](polyglot-runtime/src/javascript.rs) | Boa (`boa_engine`) | Each call builds a fresh `Context::default()` and evaluates the source via `Source::from_bytes`. |
| TypeScript | [src/typescript.rs](polyglot-runtime/src/typescript.rs) | SWC + Boa | SWC parses the TS, `strip()` removes the type annotations, the codegen emits JS, then Boa evaluates it. |
| Python | [src/python.rs](polyglot-runtime/src/python.rs) | RustPython (`rustpython_vm`) | A persistent `Interpreter::without_stdlib` is held; each call enters the VM, compiles in `Eval`/`Exec` mode, and runs the code object in a fresh builtin scope. |
| Scripting / "Python" | [src/rustpython.rs](polyglot-runtime/src/rustpython.rs) | Rhai (`rhai::Engine`) | Holds a persistent `Engine`; `eval::<T>` / `run` execute the script. Exposed as both `ScriptRuntime` and the alias `PythonRuntime`. |

Note the confusing naming: the *file* `python.rs` contains the **Rhai** runtime
(`ScriptRuntime` / `PythonRuntime`), while the *file* `rustpython.rs` contains the
**real Python** runtime (`PyRuntime`). See the Code Review section.

### Value marshalling

Two parallel marshalling systems exist:

1. **`bridge::ForeignValue`** — a dynamically typed enum (`Null`, `Bool`, `Int(i64)`,
   `Float(f64)`, `String`, `Array`, `Object`, `Handle(u64)`). The `ToForeign` /
   `FromForeign` traits convert between Rust primitives/containers and `ForeignValue`.
   `FromForeign` is used by `bridge!`-generated code; `ToForeign` serialises Rust
   arguments. `ForeignValue::to_js_literal` renders a value as a JS source fragment.
2. **`marshal::Marshal` / `marshal::Unmarshal`** — generic `Marshal<T>` / `Unmarshal<T>`
   traits in [src/marshal.rs](polyglot-runtime/src/marshal.rs). These are declared but
   **have no implementations anywhere in the crate**.

The language runtimes themselves do *not* use either trait system — they expose
typed `eval_i32` / `eval_f64` / `eval_string` / `eval_vec_i32` entry points and delegate
narrowing to the engine (`to_i32`, `to_number`, `try_into_value`, etc.).

### Bridge layer

```
  Rust caller
      │  ToForeign::to_foreign(&arg)
      ▼
  ForeignValue ──── to_js_literal() ───► JS source fragment
      │                                      │
      │                              ForeignHandle::call_method
      │                              builds "({method})(args...)"
      │                                      │ eval
      │                                      ▼
      │                              JsRuntime / ScriptRuntime
      ▼
  FromForeign::from_foreign(result) ──► Rust value / PolyglotError
```

`ForeignHandle` wraps a `ForeignValue` plus a process-global atomic id and an optional
`RuntimeRef` (a `fn(u64)` release callback) invoked on `Drop`. `call_method` validates
the method path with `is_safe_js_method_path`, escapes argument literals with
`escape_js_string`, assembles an eval expression, and runs it.

### Feature gating

Defined in [Cargo.toml](polyglot-runtime/Cargo.toml):

| Feature | Pulls in | Enables module |
|---------|----------|----------------|
| `javascript` (default) | `boa_engine` | `javascript` |
| `scripting` (default) | `rhai` | `python` (the Rhai runtime) |
| `typescript` | `boa_engine`, `swc_*` | `typescript` |
| `python` | `rustpython-vm` | `rustpython` (the real Python runtime) |
| `gpu` | — | (unused) |

[src/lib.rs](polyglot-runtime/src/lib.rs) `#[cfg]`-gates each module and re-exports the
runtimes through `prelude`.

## Module Reference

### [src/lib.rs](polyglot-runtime/src/lib.rs)

Crate root. Declares modules, the `prelude` re-export module
([lib.rs:27](polyglot-runtime/src/lib.rs#L27)), the `PolyglotError` enum
([lib.rs:43](polyglot-runtime/src/lib.rs#L43)) with its `Display`/`Error` impls, and the
crate `Result<T>` alias ([lib.rs:65](polyglot-runtime/src/lib.rs#L65)).

### [src/bridge.rs](polyglot-runtime/src/bridge.rs)

Cross-language FFI infrastructure.

- `ForeignValue` ([bridge.rs:12](polyglot-runtime/src/bridge.rs#L12)) — dynamically typed
  value enum, plus accessors `as_i32`/`as_i64`/`as_f64`/`as_string`/`as_bool`/`as_usize`
  and `to_js_literal`.
- `escape_js_string` ([bridge.rs:143](polyglot-runtime/src/bridge.rs#L143)) — JS
  string-literal escaper (`pub(crate)`).
- `is_safe_js_method_path` ([bridge.rs:170](polyglot-runtime/src/bridge.rs#L170)) —
  validates a method name is a dotted identifier path.
- `RuntimeRef` ([bridge.rs:184](polyglot-runtime/src/bridge.rs#L184)) — release-callback
  holder.
- `ForeignHandle` ([bridge.rs:211](polyglot-runtime/src/bridge.rs#L211)) — id + value +
  optional runtime; `call_method` ([bridge.rs:252](polyglot-runtime/src/bridge.rs#L252));
  `Drop` releases the handle ([bridge.rs:300](polyglot-runtime/src/bridge.rs#L300)).
- `ToForeign` / `FromForeign` traits ([bridge.rs:310](polyglot-runtime/src/bridge.rs#L310))
  with impls for `i32`, `i64`, `f64`, `bool`, `String`, `&str`, `usize`, `Vec<T>`,
  `Option<T>`, `()`.

### [src/marshal.rs](polyglot-runtime/src/marshal.rs)

Declares the generic `Marshal<T>` and `Unmarshal<T>` traits
([marshal.rs:6](polyglot-runtime/src/marshal.rs#L6),
[marshal.rs:11](polyglot-runtime/src/marshal.rs#L11)). No implementations exist; the
module is effectively dead code.

### [src/javascript.rs](polyglot-runtime/src/javascript.rs)

`JsRuntime` — a zero-sized struct. `get()` returns `Self`. Methods `eval_i32`,
`eval_f64`, `eval_string`, `eval_vec_i32`, `exec`, each creating a fresh
`Context::default()`. `eval_vec_i32` ([javascript.rs:60](polyglot-runtime/src/javascript.rs#L60))
range-checks each array element into `i32`.

### [src/typescript.rs](polyglot-runtime/src/typescript.rs)

`TsRuntime` — zero-sized struct. Private `transpile_ts_to_js`
([typescript.rs:25](polyglot-runtime/src/typescript.rs#L25)) drives the SWC parse →
strip → codegen pipeline. `eval_i32`, `eval_f64`, `eval_string`, `exec` transpile then
delegate to a fresh Boa `Context`. No `eval_vec_i32`.

### [src/python.rs](polyglot-runtime/src/python.rs)

Despite the filename, this is the **Rhai** scripting runtime. `ScriptRuntime`
([python.rs:11](polyglot-runtime/src/python.rs#L11)) holds an owned `rhai::Engine`.
`new`/`get`, `eval_i32`/`eval_f64`/`eval_string`/`eval_vec_i32`, `exec`.
`PythonRuntime` is a `type` alias ([python.rs:77](polyglot-runtime/src/python.rs#L77)).

### [src/rustpython.rs](polyglot-runtime/src/rustpython.rs)

The **real Python** runtime (`#[cfg(feature = "python")]`). `PyRuntime`
([rustpython.rs:19](polyglot-runtime/src/rustpython.rs#L19)) holds an
`Interpreter::without_stdlib`. Methods `eval_i32`/`eval_f64`/`eval_string`/`eval_vec_i32`,
`exec`, plus the `exec_and_eval_*` variants that run setup code then evaluate an
expression in the shared scope. Integer narrowing is range-checked
([rustpython.rs:52](polyglot-runtime/src/rustpython.rs#L52)).

## Code Review

### Critical

**C1 — `js!` macro calls runtime API that does not exist (crate does not compile when `js!` is used).**
[polyglot-macros/src/js_macro.rs:18-26](polyglot-macros/src/js_macro.rs#L18) expands to:

```rust
use polyglot_runtime::javascript::JsRuntime;
use polyglot_runtime::marshal::FromJs;
let __js = JsRuntime::get();
let __result = __js.eval(#code);
match __result { Ok(val) => FromJs::from_js(val), ... }
```

Neither `JsRuntime::eval` nor `marshal::FromJs` / `FromJs::from_js` exist in this crate.
`JsRuntime` only exposes `eval_i32`/`eval_f64`/`eval_string`/`eval_vec_i32`/`exec`
([javascript.rs:12-119](polyglot-runtime/src/javascript.rs#L12)), and
[marshal.rs](polyglot-runtime/src/marshal.rs) defines only `Marshal`/`Unmarshal`.
Why it matters: any downstream use of the `js!` macro is a hard compile error — the
runtime and macro crates are out of sync. Fix: either add a generic `eval` returning a
marshallable value plus a `FromJs` trait to `marshal.rs`, or change `js_macro.rs` to call
the typed methods. The two crates must be kept in lockstep (consider a shared integration
test that actually expands and compiles each macro).

### High

**H1 — A fresh JS/TS `Context` per call destroys all state; `exec` then `eval` cannot share anything.**
Every `JsRuntime`/`TsRuntime` method builds `Context::default()`
([javascript.rs:20](polyglot-runtime/src/javascript.rs#L20),
[javascript.rs:112](polyglot-runtime/src/javascript.rs#L112),
[typescript.rs:73](polyglot-runtime/src/typescript.rs#L73)). `JsRuntime`/`TsRuntime` are
zero-sized and `get()` returns a unit value, so there is no place to keep a context.
Consequently, calling `exec("var x = 1")` then `eval_i32("x")` evaluates `x` in a brand
new context and fails (or in Boa returns `undefined`). The Python `exec_and_eval_*`
methods exist precisely to work around this for RustPython — JS/TS have no equivalent.
Why it matters: stateful polyglot blocks (define a function, then call it) silently do
not work for JS/TS. Fix: hold a persistent `Context` (e.g. behind `RefCell`) inside
`JsRuntime`, or provide `exec_and_eval_*` analogues.

**H2 — `ForeignHandle::call_method` ignores the receiver object; "method call" is really a bare global call.**
[bridge.rs:252-287](polyglot-runtime/src/bridge.rs#L252) builds the expression
`({method})({args})` and evals it in a *fresh* runtime. `self.value` / `self.id` are
never referenced, so the call neither targets the foreign object the handle represents
nor sees any state it was created with. The doc comment claims it evaluates
`obj.method(arg1, ...)` but the code does not. A handle to `{count: 0}` calling
`increment` just evaluates `(increment)()` against an empty global scope. Why it matters:
the entire `ForeignHandle` method-call abstraction is non-functional and misleading.
Fix: either render the receiver into the expression (`(<obj-literal>).method(args)`) or
keep object state inside a persistent runtime and address it by `id`.

**H3 — `call_method` swallows every error and returns `ForeignValue::Null`.**
[bridge.rs:257-286](polyglot-runtime/src/bridge.rs#L257): an unsafe method path, an
`eval_string` error, or no JS/scripting feature enabled all yield the same
`ForeignValue::Null`. The caller cannot distinguish "the method returned null", "the
method threw", "the method name was rejected", and "no runtime is compiled in". Why it
matters: errors crossing the FFI boundary are erased, making misuse and genuine runtime
exceptions invisible. Fix: change the signature to `crate::Result<ForeignValue>` (or
`Result<ForeignValue, _>`).

**H4 — `call_method` always coerces the result to a string, losing type fidelity.**
[bridge.rs:272](polyglot-runtime/src/bridge.rs#L272) and
[bridge.rs:281](polyglot-runtime/src/bridge.rs#L281) wrap the result of
`eval_string` in `ForeignValue::String`. A method returning a number, bool, array, or
object comes back as its stringified form. Then `FromForeign for i32`/`bool`/`Vec<T>`
([bridge.rs:378-449](polyglot-runtime/src/bridge.rs#L378)) all reject strings, so a
`bridge!`-declared method with a non-string return type fails type conversion even when
it behaved correctly. Why it matters: the bridge is unusable for any non-string return
value. Fix: parse the JS result as JSON and map it into the matching `ForeignValue`
variant.

### Medium

**M1 — Filename/type naming is actively misleading.**
[src/python.rs](polyglot-runtime/src/python.rs) contains the **Rhai** runtime, exported
as `ScriptRuntime` *and* aliased `PythonRuntime`
([python.rs:77](polyglot-runtime/src/python.rs#L77)); the **real Python** runtime
`PyRuntime` lives in [src/rustpython.rs](polyglot-runtime/src/rustpython.rs). To compound
it, the Rhai runtime reports failures as `PolyglotError::Python(...)`
([python.rs:33](polyglot-runtime/src/python.rs#L33),
[python.rs:72](polyglot-runtime/src/python.rs#L72)) — a Rhai syntax error is surfaced as
a "Python error". The `scripting` feature gates the file named `python.rs`, while the
`python` feature gates `rustpython.rs`. A maintainer reading `py!` macro output
(`use polyglot_runtime::prelude::PythonRuntime;` in
[polyglot-macros/src/py_macro.rs:184](polyglot-macros/src/py_macro.rs#L184)) would
reasonably expect real Python and instead get Rhai. Why it matters: high risk of wrong
fixes and wrong assumptions. Fix: rename `python.rs` → `scripting.rs`, drop or clearly
deprecate the `PythonRuntime` alias, and add a dedicated `PolyglotError::Script` variant.

**M2 — No sandboxing / resource limits on executed code.**
All four backends execute arbitrary embedded source with no timeout, no instruction
budget, no memory cap, and no I/O restriction. RustPython is created
`without_stdlib` ([rustpython.rs:27](polyglot-runtime/src/rustpython.rs#L27)) which
reduces surface area, but a snippet like `while True: pass` or `[0]*10**12` will hang or
OOM the host process; Boa and Rhai have the same exposure (`for(;;);`, deep recursion).
`rhai::Engine::new()` ([python.rs:19](polyglot-runtime/src/python.rs#L19)) is the full
engine with no `set_max_operations`/`set_max_call_levels`/`set_max_string_size`. The
`bridge!`/macro design treats the embedded snippet as a compile-time literal, so the
threat is mostly DoS from buggy code rather than injected code — but `call_method` evals
a *runtime-derived* `method` string, so untrusted input can reach the engine. Why it
matters: a single bad snippet takes down the whole process; no defence in depth. Fix:
apply Rhai's operation/level/size limits, run untrusted evals on a worker thread with a
timeout, and document the trust model.

**M3 — `as_f64` silently loses precision for large `i64` values.**
[bridge.rs:58-64](polyglot-runtime/src/bridge.rs#L58): `ForeignValue::Int(i)` is mapped
with `*i as f64`. Integers beyond 2^53 lose precision. Every other numeric accessor in
this file was hardened (the `[R38-01]` comments) to *reject* lossy conversions; `as_f64`
was not. Why it matters: a marshalled `i64` id/counter can come back as a different
number. Fix: either accept the documented IEEE-754 behaviour explicitly, or reject when
`i` is not exactly representable.

**M4 — `ScriptRuntime::eval_i32` truncates `i64` → `i32` with `as`.**
[python.rs:29-34](polyglot-runtime/src/python.rs#L29): `.map(|v| v as i32)` silently
discards the high bits, and `eval_vec_i32` does the same at
[python.rs:62](polyglot-runtime/src/python.rs#L62) (`values.push(i as i32)`). The
JavaScript and RustPython backends were both hardened to range-check this exact
narrowing (`[R39-01]` in
[javascript.rs:75](polyglot-runtime/src/javascript.rs#L75) and
[python.rs/rustpython.rs](polyglot-runtime/src/rustpython.rs#L52)); the Rhai backend was
missed. Why it matters: inconsistent, silently-wrong results from one backend only. Fix:
use `i32::try_from` and return `PolyglotError::TypeConversion` on overflow, matching the
other backends.

**M5 — `marshal` module is dead code.**
`Marshal<T>` / `Unmarshal<T>` ([marshal.rs:6-13](polyglot-runtime/src/marshal.rs#L6))
have zero implementations and zero callers in either crate, yet `js_macro.rs` references
a *different*, also-nonexistent `marshal::FromJs` (see C1). Why it matters: confusing
surface; suggests an abandoned design. Fix: either implement and use these traits, or
delete the module and reconcile with what the macros actually need.

### Low

**L1 — Thread-safety / re-entrancy is undocumented.**
`PyRuntime` holds an `Interpreter` and `ScriptRuntime` holds a `rhai::Engine`; neither
is documented as `Send`/`Sync`-safe or single-threaded. `ForeignHandle`'s id `COUNTER`
is process-global and atomic ([bridge.rs:220](polyglot-runtime/src/bridge.rs#L220)) but
`call_method` spins up a *new* runtime on whatever thread calls it. Fix: document the
threading contract for each runtime.

**L2 — Two independent `static COUNTER`s for handle ids.**
`ForeignHandle::new` ([bridge.rs:220](polyglot-runtime/src/bridge.rs#L220)) and
`with_runtime` ([bridge.rs:230](polyglot-runtime/src/bridge.rs#L230)) each declare their
own function-local `static COUNTER`, so the two constructors can hand out the **same
id**. If ids are ever used as map keys for handle bookkeeping this collides. Fix: hoist a
single module-level `AtomicU64`.

**L3 — Errors are formatted with `{:?}` instead of `{}`.**
e.g. [javascript.rs:24](polyglot-runtime/src/javascript.rs#L24),
[typescript.rs:44](polyglot-runtime/src/typescript.rs#L44),
[rustpython.rs:45](polyglot-runtime/src/rustpython.rs#L45). Boa/SWC/RustPython errors
have proper `Display` impls; `{:?}` yields verbose, less readable messages and can leak
internal struct layout into user-facing strings. Fix: prefer `{}` where the error type
implements `Display`.

**L4 — `RuntimeRef::release_fn` is `fn(u64)` (a plain function pointer).**
[bridge.rs:185](polyglot-runtime/src/bridge.rs#L185) cannot capture any state, so a
release callback cannot reference a specific runtime instance / handle table. In
practice every constructed handle uses `noop()` or `None`, meaning handle cleanup is
effectively never wired up. Fix: use `Arc<dyn Fn(u64) + Send + Sync>` if real cleanup is
intended, or remove the mechanism until it is.

**L5 — `transpile_ts_to_js` hard-codes `tsx: false`, `decorators: false`, ES2020.**
[typescript.rs:31-36](polyglot-runtime/src/typescript.rs#L31). TS using JSX or decorators
fails to parse with no way to opt in. Minor, but worth a config knob or a doc note.

**L6 — `ForeignValue::Handle` round-trips through `to_js_literal` as a bare identifier.**
[bridge.rs:129](polyglot-runtime/src/bridge.rs#L129) renders `Handle(id)` as
`__handle_<id>`, an identifier that is almost never bound in the fresh eval context, so
any expression containing a handle argument throws `ReferenceError`. Fix: define the
`__handle_*` bindings before eval, or reject handle arguments explicitly.

## Strengths

- **Genuinely self-contained.** All four backends (Boa, SWC, RustPython, Rhai) are
  pure-Rust; there is no external process or toolchain dependency, which makes the
  toolchain portable and reproducible.
- **Numeric marshalling has been hardened deliberately.** The `[R38-01]`/`[R39-01]`
  comments in [bridge.rs](polyglot-runtime/src/bridge.rs),
  [javascript.rs](polyglot-runtime/src/javascript.rs) and
  [rustpython.rs](polyglot-runtime/src/rustpython.rs) show range-checked conversions with
  clear rationale — `as_i32`/`as_i64`/`as_usize` correctly reject out-of-range and
  non-finite inputs instead of truncating.
- **JS-injection escaping is thorough.** `escape_js_string`
  ([bridge.rs:143](polyglot-runtime/src/bridge.rs#L143)) handles line terminators,
  U+2028/U+2029 and control characters, and both object keys *and* values are escaped;
  `is_safe_js_method_path` ([bridge.rs:170](polyglot-runtime/src/bridge.rs#L170)) locks
  the method path down to identifier segments. The pentest-driven fixes (`[R23-01]`,
  `[R28-01]`) are well-reasoned.
- **`FromForeign for String` rejects non-string inputs** rather than fabricating a
  `Debug` string ([bridge.rs:410-430](polyglot-runtime/src/bridge.rs#L410)) — a real
  type-confusion fix.
- **Consistent typed-error model.** `PolyglotError` is small, implements
  `Display`/`Error`, and the `Result` alias keeps signatures clean.
- **RustPython created `without_stdlib`** reduces the embedded-Python attack surface.

## Recommendations

Prioritised, actionable:

1. **Fix C1 — reconcile `js_macro.rs` with the real `JsRuntime` API.** This is a hard
   compile break for any `js!` user. Add a generic `eval` + `FromJs` trait, or change the
   macro to call `eval_i32`/`eval_string`/etc. Add a macro-expansion integration test so
   the two crates cannot drift again.
2. **Fix H1 — make JS/TS runtimes stateful.** Hold a persistent `Context` so
   define-then-call works; add `exec_and_eval_*` parity with `PyRuntime`.
3. **Fix H2/H3/H4 — make `ForeignHandle::call_method` real.** Target the receiver object,
   return `Result`, and decode the JS result into the correct `ForeignValue` variant
   (JSON parse) instead of always stringifying.
4. **Fix M1 — rename for honesty.** `python.rs` → `scripting.rs`, retire the
   `PythonRuntime` alias, add `PolyglotError::Script`. Reduces the chance of wrong fixes.
5. **Fix M4/M3 — finish the numeric-hardening pass.** Apply `i32::try_from` in
   `ScriptRuntime::eval_i32`/`eval_vec_i32`; decide and document `as_f64`'s `i64`
   precision behaviour.
6. **Address M2 — add resource limits & document the trust model.** Set Rhai
   operation/level/string limits, run untrusted evals (the `call_method` path) under a
   timeout, and document that snippets are otherwise expected to be trusted compile-time
   literals.
7. **Clean up the dead/duplicated bits (M5, L2, L4, L6).** Either implement or delete the
   `marshal` traits; merge the two handle `COUNTER`s into one module-level atomic; fix or
   remove `RuntimeRef`/handle cleanup; handle `ForeignValue::Handle` in `to_js_literal`.
8. **Polish (L1, L3, L5).** Document each runtime's threading contract; switch error
   formatting to `Display`; expose TS parser config (tsx/decorators/ES version).
9. **Add tests.** The crate has pentest regression tests (`r23`/`r27`/`r28`/`r38`/`r39`)
   but no functional tests for `JsRuntime`/`TsRuntime` statefulness or `call_method`
   semantics — exactly the areas where the bugs above live.
