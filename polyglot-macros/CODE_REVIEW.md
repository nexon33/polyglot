# polyglot-macros — Documentation & Code Review

## Overview

`polyglot-macros` is the procedural-macro crate of the **pyrs polyglot** workspace. It
provides the compile-time front end for two distinct capabilities:

1. **Inline foreign-language embedding** — function-like macros (`py!`, `js!`, `ts!`,
   `cuda!`, `gpu!`, `sql!`, plus reserved `js_try!`/`py_try!`/`ts_try!`) that let Rust
   source contain expressions written in another language. The macro captures the
   inner tokens, stringifies them, and emits Rust code that hands the string to an
   embedded interpreter from `polyglot-runtime` (RustPython, Boa, SWC).

2. **Verified execution** — the `#[verified]` attribute macro wraps a function body in
   an IVC (Incrementally Verifiable Computation) accumulator lifecycle from the
   `poly-verified` crate, producing a `Verified<T>` return value carrying a proof of
   correct execution. Supporting macros: `#[pure]` (purity gate), `fold!` (explicit
   fold point), and `#[poly_bridge]` (type-safe cross-language FFI wrappers).

### How `#[verified]` expands

Given `fn f(args) -> T { body }`, the macro emits `fn f(args) -> Verified<T>` whose
body, in order:

1. Computes `__code_hash = SHA256(module_path!() ++ "::" ++ fn_name)`.
2. Computes `__input_hash` by SHA256-hashing the `Debug` representation of every
   named parameter (or `ZERO_HASH` when there are no parameters).
3. Initializes an IVC accumulator: `IvcBackend::init(&backend, &code_hash, privacy)`
   where `backend` is `HashIvc` (default) or `MockIvc` (`#[verified(mock)]`).
4. Executes the original body inside an immediately-invoked closure
   `(|| #fn_body)()` and binds the result to `__result`.
5. Computes `__output_hash = SHA256(format!("{:?}", __result))`.
6. Folds a `StepWitness { state_before, state_after, step_inputs }` into the
   accumulator, sets `acc.input_hash`/`acc.output_hash`, and calls
   `IvcBackend::finalize` to obtain `__proof`.
7. Returns `Verified::__macro_new(__result, __proof)`.

`PrivacyMode` is selected from the attribute string (`private`, `private_inputs`, or
`Transparent` by default).

## Architecture

The crate has two macro categories with different mechanics:

| Category | Macros | Kind | Input parsing | Codegen strategy |
|----------|--------|------|---------------|------------------|
| Foreign-language embedding | `py!`, `js!`, `ts!`, `cuda!`, `gpu!`, `sql!` | function-like (`#[proc_macro]`) | `TokenStream::to_string()` — **no AST parse** | Stringify tokens, strip outer braces, emit `Runtime::get().eval(...)` block |
| Verified execution | `#[verified]`, `#[pure]`, `#[poly_bridge]` | attribute (`#[proc_macro_attribute]`) | `syn::parse2::<ItemFn/ItemTrait>` | Re-emit the item wrapped in lifecycle/marshaling code |
| Fold point | `fold!` | function-like | `syn::parse2::<Expr>` | Wrap expression in a hashing block |
| Reserved | `js_try!`, `py_try!`, `ts_try!` | function-like | none | Emit `compile_error!` |

```
                       lib.rs  (proc-macro entry points, thin shims)
                          |
        +-----------------+------------------+-------------------+
        |                 |                  |                   |
  foreign-language    verified exec      bridge / FFI        stubs/reserved
  py/js/ts_macro.rs   verified_macro.rs  bridge_macro.rs     gpu_macro.rs
  capture.rs (unused) pure_macro.rs                          sql_macro.rs
                      fold_macro.rs                          js_try/py_try/ts_try
        |                 |                  |
        v                 v                  v
  polyglot-runtime    poly-verified     polyglot-runtime::bridge
  (interpreters)      (IVC accumulator)
```

**Token capture.** Foreign-language macros do *not* parse their input as Rust. They
call `input.to_string()` on the `proc_macro2::TokenStream`, trim whitespace, and strip
a single layer of `{ }` if present. The resulting string is embedded as a `&str`
literal into the generated `eval` call. `capture.rs` is intended to detect Rust
variables referenced inside the foreign code so they can be marshaled across the
boundary, but it is currently a stub (`analyze_captures` returns `vec![]`).

**Codegen strategy.** All generation uses `quote!`. The verified/bridge macros build
fragments conditionally and splice them with `#(...)*` interpolation. Generated code
references fully-qualified paths into sibling crates (`poly_verified::...`,
`polyglot_runtime::...`, `sha2::...`).

## Module Reference

### [polyglot-macros/src/lib.rs](polyglot-macros/src/lib.rs)
Crate root. Declares all `#[proc_macro]` / `#[proc_macro_attribute]` entry points
(lines 42–157) and the three reserved `*_try!` macros (lines 168–186). Each entry
point is a one-line shim that converts `proc_macro::TokenStream` to/from
`proc_macro2::TokenStream` and delegates to a module `expand` function.

### [polyglot-macros/src/verified_macro.rs](polyglot-macros/src/verified_macro.rs)
Provides `#[verified]`. `expand` (line 5) parses the item as `ItemFn`, derives
backend/privacy flags from the raw argument string (lines 11–14), builds the
input-hashing statements (lines 45–69), the backend init block (lines 79–91), and the
`fold_and_finalize` block (lines 93–106), then emits the rewritten function (lines
108–148). Return type is rewritten to `Verified<#inner_return_type>` and the result
wrapped with `Verified::__macro_new`.

### [polyglot-macros/src/pure_macro.rs](polyglot-macros/src/pure_macro.rs)
Provides `#[pure]`. `expand` (line 5) parses an `ItemFn`, stringifies the body, and
scans for impurity substrings (lines 14–23) — `std::fs`, `std::net`, `std::io`,
`println!`, `eprintln!`, `std::thread`, `tokio::spawn`, `unsafe`. On match it emits a
`compile_error!`; otherwise it re-emits the function with `#[inline]` added.

### [polyglot-macros/src/fold_macro.rs](polyglot-macros/src/fold_macro.rs)
Provides `fold!`. `expand` (line 5) parses an `Expr`, then emits a block that binds
the value, computes a SHA256 hash of its `Debug` form, and returns the original value
(lines 13–30). The hash is computed but discarded — see Code Review.

### [polyglot-macros/src/bridge_macro.rs](polyglot-macros/src/bridge_macro.rs)
Provides `#[poly_bridge]`. Defines a `Runtime` enum (lines 26–58) with
`from_str`/`prefix`/`runtime_type`. `parse_runtime` (line 61) extracts the runtime
from the raw arg string. `expand` (line 74) parses an `ItemTrait`, generates a wrapper
struct `{Prefix}{Trait}` with a `ForeignHandle`, and a trait `impl`. Per-method
codegen is in `generate_single_method` (line 141): it collects argument names,
marshals them via `ToForeign::to_foreign`, calls `handle.call_method`, and unmarshals
the result (special-casing `Self`).

### [polyglot-macros/src/py_macro.rs](polyglot-macros/src/py_macro.rs)
Provides `py!`. `extract_likely_variables` (line 21) is a char-by-char heuristic that
collects identifier-like tokens, skipping string contents, Python keywords
(`is_python_keyword`, line 67) and builtins (`is_python_builtin`, line 108). `expand`
(line 160) stringifies the input, strips braces, runs capture detection, and emits a
`PythonRuntime::get().eval_i32(...)` block. `expand_typed` (line 216, `dead_code`) is
an unfinished typed variant.

### [polyglot-macros/src/js_macro.rs](polyglot-macros/src/js_macro.rs)
Provides `js!`. `expand` (line 6) stringifies/trims/de-braces the input and emits a
block that calls `JsRuntime::get().eval(#code)`, then `FromJs::from_js` on success or
`panic!` on error.

### [polyglot-macros/src/ts_macro.rs](polyglot-macros/src/ts_macro.rs)
Provides `ts!`. `expand` (line 9) mirrors `js_macro` but emits
`TsRuntime::get().eval_i32(#code)`.

### [polyglot-macros/src/gpu_macro.rs](polyglot-macros/src/gpu_macro.rs)
Provides `cuda!`/`gpu!`. Both `expand_cuda` (line 6) and `expand_gpu` (line 14) are
stubs that emit `compile_error!`.

### [polyglot-macros/src/sql_macro.rs](polyglot-macros/src/sql_macro.rs)
Provides `sql!`. `expand` (line 6) is a stub emitting `compile_error!`.

### [polyglot-macros/src/capture.rs](polyglot-macros/src/capture.rs)
Defines `CapturedVar` and `analyze_captures` (line 15) for cross-boundary variable
capture. Entire module is `#[allow(dead_code)]`; `analyze_captures` is unimplemented.

## Code Review

### Critical

**C1 — `sha2` is used in generated code but is not a declared dependency.**
[verified_macro.rs:61](polyglot-macros/src/verified_macro.rs#L61),
[verified_macro.rs:113](polyglot-macros/src/verified_macro.rs#L113),
[verified_macro.rs:134](polyglot-macros/src/verified_macro.rs#L134),
[fold_macro.rs:18](polyglot-macros/src/fold_macro.rs#L18).
The expansions emit `sha2::Sha256::new()` / `use sha2::Digest;`, but
[Cargo.toml](polyglot-macros/Cargo.toml) lists only `proc-macro2`, `quote`, `syn`.
The generated code compiles **only** if the *downstream* crate that invokes
`#[verified]` happens to have `sha2` in scope (i.e. as one of its own dependencies
with that exact crate name). This is a hidden, undocumented requirement: a fresh
consumer crate gets `error[E0433]: failed to resolve: use of undeclared crate or
module 'sha2'`. Proc-macro crates cannot re-export runtime deps via their own
`Cargo.toml`, so the fix is to route hashing through a re-export from a guaranteed
dependency — e.g. emit `poly_verified::sha2::Sha256` (have `poly-verified` pub-use
`sha2`), or move the hashing into a `poly_verified` helper function (`hash_code`,
`hash_value`) and emit a call to that. The same applies to `poly_verified` itself:
the macro assumes the consumer has it as a dependency under that exact name.

**C2 — `Debug`-based hashing silently breaks proof soundness for many return/param types.**
[verified_macro.rs:54](polyglot-macros/src/verified_macro.rs#L54),
[verified_macro.rs:135](polyglot-macros/src/verified_macro.rs#L135),
[fold_macro.rs:20](polyglot-macros/src/fold_macro.rs#L20).
Input and output hashes are derived from `format!("{:?}", value)`. This is unsound as
a verification primitive: (a) `f32`/`f64` `Debug` output is lossy and platform/precision
dependent, so two runs producing bit-different floats can hash identically or
identically-valued runs can diverge; (b) `HashMap`/`HashSet` `Debug` ordering is
non-deterministic, so the same logical value yields different hashes across runs;
(c) any type without a `Debug` impl produces a confusing `E0277` error pointing at
generated code rather than the user's type. For a crate whose stated purpose is
*mathematical proof of correct execution*, hashing the `Debug` string undermines the
guarantee. Use a canonical, stable serialization (`bincode`/`borsh` with a `Serialize`
bound, or a dedicated `VerifiableHash` trait) and add an explicit, well-spanned trait
bound so missing impls produce a clear error.

### High

**H1 — `.expect()` panics inside generated `#[verified]` bodies.**
[verified_macro.rs:100](polyglot-macros/src/verified_macro.rs#L100),
[verified_macro.rs:105](polyglot-macros/src/verified_macro.rs#L105),
[bridge_macro.rs:184](polyglot-macros/src/bridge_macro.rs#L184).
`fold_step` and `finalize` results are `.expect(...)`-ed, and `#[poly_bridge]`
unmarshaling does `.expect("Failed to unmarshal return value")`. These panics fire at
*runtime* in the consumer's code with messages that point at macro-generated source
the user never wrote. A verified function that fails to fold should surface a typed
error, not abort the process. Either change the macro to require `-> Verified<Result<T, E>>`
style signatures, or document loudly that `#[verified]` functions panic on IVC
failure. (Note: these are runtime `.expect()`s on values, not the `parse` `.unwrap()`s
the task asked about — the `parse` paths here are correctly handled with
`to_compile_error()`, see Strengths.)

**H2 — Attribute arguments parsed by raw substring matching.**
[verified_macro.rs:11-14](polyglot-macros/src/verified_macro.rs#L11-L14),
[bridge_macro.rs:61-71](polyglot-macros/src/bridge_macro.rs#L61-L71).
`#[verified]` decides `use_mock`/`is_private` with `args_str.contains("mock")` /
`.contains("private")`. Consequences: `#[verified(not_mock)]`,
`#[verified(mockingbird)]`, or a stray comment containing `mock` all silently enable
the mock backend; an unknown argument like `#[verified(foo)]` is silently ignored
instead of erroring. `is_private` is patched with `&& !contains("private_inputs")`,
which is a fragile workaround for the substring overlap. `parse_runtime` similarly
does `trim_matches('(' / ')')`, which mishandles `#[poly_bridge(python, extra)]`.
Parse the attribute properly with `syn` (`Meta`, `Punctuated<Path, Comma>`, or
`syn::parse::Parser`) and emit a `compile_error!` on unknown tokens.

**H3 — Foreign-language macros lose source fidelity by round-tripping through `to_string()`.**
[js_macro.rs:7](polyglot-macros/src/js_macro.rs#L7),
[ts_macro.rs:10](polyglot-macros/src/ts_macro.rs#L10),
[py_macro.rs:162](polyglot-macros/src/py_macro.rs#L162).
`TokenStream::to_string()` re-renders tokens with the formatter's own spacing rules,
not the user's source. For Python this is fatal: `py!{ for x in data: print(x) }`
loses meaningful indentation/newlines, and `proc_macro2` will also choke on tokens
that are not valid *Rust* tokens (e.g. Python `:` block syntax inside braces is fine,
but f-strings, `**kwargs`, decorators, or `'` string literals tokenize unexpectedly).
The de-brace step (`code[1..len-1]`) also assumes exactly one brace pair and would
corrupt code like `js!{ {a:1} }` (strips the inner object braces' outer pair leaving
`{a:1}` — accidentally OK here, but `js!{ {a:1}; {b:2} }` becomes `a:1}; {b:2`).
Consider accepting a string literal (`py!(r#"..."#)`) or at minimum documenting the
tokenization constraints.

**H4 — `#[verified]` drops `where` clauses and mishandles non-`self` signatures.**
[verified_macro.rs:108-110](polyglot-macros/src/verified_macro.rs#L108-L110).
The regenerated signature uses `#fn_generics` and `#fn_inputs` but the generated body
wraps `#fn_body` in a closure `(|| #fn_body)()`. A `where` clause on `fn_generics`
*is* carried by `syn::Generics` only if `split_for_impl` is used; here `#fn_generics`
interpolates the `<...>` params but the `where` clause lives in
`generics.where_clause` and is **not emitted**, so any verified generic function with
a `where` clause loses it. Also, if the function takes `&self`/`self` (a method),
the macro still emits a free `fn` (it never special-cases receivers), so applying
`#[verified]` to a method body produces invalid code. Use
`generics.split_for_impl()` and reject (or properly handle) receiver arguments with a
clear `compile_error!`.

### Medium

**M1 — `fold!` computes a hash and immediately discards it.**
[fold_macro.rs:16-28](polyglot-macros/src/fold_macro.rs#L16-L28).
The expansion builds `__fold_hash` then returns only `__fold_value`; `__fold_hash` is
unused, so every `fold!` invocation emits an `unused variable` warning in user code
and accomplishes nothing beyond evaluating the expression. The comment admits the
plumbing (thread-local / context) is absent. Either implement the fold-into-accumulator
mechanism or make `fold!` a no-op pass-through until it works, to avoid dead codegen.

**M2 — `#[pure]` purity check is trivially bypassed and produces false positives.**
[pure_macro.rs:11-29](polyglot-macros/src/pure_macro.rs#L11-L29).
The check stringifies the body and substring-matches patterns like `"std :: fs ::"`.
False negatives: `use std::fs as f; f::read(...)`, aliased imports, `let p = println;`
in macros, or any IO reached through a helper all pass. False positives: a variable or
field literally named `unsafe`-adjacent, a string literal `"println!"`, or a comment
mentioning `std::io` would all wrongly reject. Note the brittle reliance on `syn`'s
exact spacing (`"std :: fs ::"`) — a different `syn` version's `to_token_stream`
spacing would silently disable the check. Purity is a semantic property; a substring
scan cannot enforce it. Either downgrade the docs to "best-effort lint" or walk the
AST with a `syn::visit::Visit` pass.

**M3 — `capture.rs` is dead code; `py!` capture detection has no effect.**
[capture.rs:15](polyglot-macros/src/capture.rs#L15),
[py_macro.rs:191-210](polyglot-macros/src/py_macro.rs#L191-L210).
`analyze_captures` returns `vec![]` and the whole module is `#[allow(dead_code)]`.
In `py_macro::expand`, the `captured_vars` branch detects variables but the `else`
branch emits the *same* eval call as the `if` branch — captured variables are never
marshaled. The doc comment in `py_macro.rs` (lines 5–13) promises "Variables ... are
automatically marshaled", which is false. Also note line 202's `// Detected potential
captures: #vars_str` is inside `quote!` — `#vars_str` is not interpolated (the binding
is `_vars_str`), so it emits a literal `#vars_str` comment. Remove the misleading docs
or implement capture.

**M4 — `py!`/`ts!` hard-code the return type to `i32`.**
[py_macro.rs:187](polyglot-macros/src/py_macro.rs#L187),
[ts_macro.rs:27](polyglot-macros/src/ts_macro.rs#L27).
`expand` always emits `eval_i32`. The crate docs and `lib.rs` examples
([lib.rs:53-54](polyglot-macros/src/lib.rs#L53-L54)) advertise `Vec<i32>` and other
return types, and `js!` correctly uses generic `FromJs::from_js`. `py!`/`ts!` will
fail to compile (or silently truncate) for any non-`i32` target. `expand_typed`
exists but is `#[allow(dead_code)]` and unreachable. Align `py!`/`ts!` with the `js!`
approach (generic `FromX` trait) or wire up `expand_typed`.

**M5 — Inconsistent error handling between foreign macros (`panic!` vs `expect`).**
[js_macro.rs:26](polyglot-macros/src/js_macro.rs#L26) uses `panic!("JavaScript error: {}", e)`
while [py_macro.rs:188](polyglot-macros/src/py_macro.rs#L188) and
[ts_macro.rs:28](polyglot-macros/src/ts_macro.rs#L28) use `.expect("... failed")`.
Behaviour is similar but the messages and patterns differ; a user catching/formatting
errors sees inconsistent output. Standardize.

### Low

**L1 — `#[verified]` does not forward doc comments / preserves attrs only partially.**
[verified_macro.rs:18](polyglot-macros/src/verified_macro.rs#L18),
[verified_macro.rs:109](polyglot-macros/src/verified_macro.rs#L109).
`fn_attrs` re-emits all attributes including doc comments — fine — but a doc comment
written for `-> T` may now be misleading since the real return type is `Verified<T>`.
Minor; consider appending a generated note.

**L2 — `bridge_macro` ignores method generics and default trait method bodies.**
[bridge_macro.rs:141-197](polyglot-macros/src/bridge_macro.rs#L141-L197).
`generate_single_method` uses `method.sig.ident/inputs/output` but ignores
`method.sig.generics` and any provided default body. A generic trait method or one
with a default impl produces a wrong/incomplete `impl`. `runtime_type()` /
`_runtime_type` is computed and discarded ([bridge_macro.rs:89](polyglot-macros/src/bridge_macro.rs#L89)),
so the chosen runtime never actually influences the generated marshaling code beyond
the struct name prefix.

**L3 — `Self`-return detection is a string `.contains("Self")`.**
[bridge_macro.rs:177](polyglot-macros/src/bridge_macro.rs#L177).
`quote!(#ty).to_string().contains("Self")` also matches `MySelfType`, `SelfRefWrapper`,
or `Vec<Self>` (the latter would take the `Self::from_foreign` branch and fail to
compile). Match on the `syn::Type` AST (`Type::Path` whose last segment is exactly
`Self`).

**L4 — `_i` index in `extract_likely_variables` loop is unused.**
[py_macro.rs:30](polyglot-macros/src/py_macro.rs#L30). `for (_i, c) in code.chars().enumerate()`
— the `enumerate()` is pointless; iterate `code.chars()` directly. Cosmetic.

**L5 — No span propagation; all generated code uses call-site/`def_site` default spans.**
Throughout. Errors in generated code (type mismatches, missing trait impls) point at
synthetic spans rather than the user's macro invocation. Where the macro re-emits user
tokens (`#fn_body`, `#inputs`) spans survive, but synthesized fragments do not. Using
`quote_spanned!` keyed to the relevant user token would substantially improve
diagnostics — especially for C2/H1 failures.

### Status of previously-fixed bugs

The memory note mentions earlier fixes for "missing `&self` receiver in UFCS calls,
unhandled `Result<>`, `pub(crate)` visibility". Current state:

- **`__macro_new` visibility** — [verified_macro.rs:146](polyglot-macros/src/verified_macro.rs#L146)
  calls `Verified::__macro_new`, which the memory describes as a `doc(hidden)` public
  constructor. That is the correct pattern (a `pub(crate)` constructor could not be
  named from generated downstream code), so this fix appears to hold.
- **`Result<>` handling** — the macro still hashes/wraps `__result` opaquely; it does
  not special-case `Result` return types. If the previous "unhandled `Result<>`" bug
  was about `Verified<Result<T,E>>`, the current code treats it as just another `T`
  (which works but means a verified function returning `Err` still produces a "valid"
  proof of having returned that `Err`). Worth confirming intended semantics.
- **UFCS receiver** — `IvcBackend::init/fold_step/finalize` are all called in UFCS
  form with an explicit `&__backend` / `&mut __acc` first argument
  ([verified_macro.rs:83](polyglot-macros/src/verified_macro.rs#L83),
  [verified_macro.rs:99](polyglot-macros/src/verified_macro.rs#L99)), so the receiver
  is present. This fix appears to hold.

## Strengths

- **Correct `parse` error handling.** Every `syn::parse2` call in the AST-based macros
  (`verified_macro`, `pure_macro`, `fold_macro`, `bridge_macro`) matches the `Err`
  arm and returns `e.to_compile_error()` instead of `.unwrap()`-ing — so malformed
  user input yields a proper compiler diagnostic, not an ICE-style panic.
- **Thin, consistent entry-point layer.** [lib.rs](polyglot-macros/src/lib.rs) keeps
  every `#[proc_macro]` shim to one line and delegates to a focused module, making the
  crate easy to navigate.
- **Reserved macros fail loudly.** `cuda!`, `gpu!`, `sql!`, and the `*_try!` variants
  emit clear `compile_error!` messages rather than silently producing nothing.
- **Conditional codegen is clean.** `verified_macro` builds the privacy/backend/hash
  fragments separately and splices them, which keeps the final `quote!` readable.
- **`#[poly_bridge]` keeps the original trait** ([bridge_macro.rs:97](polyglot-macros/src/bridge_macro.rs#L97))
  so users can still implement it for other types — a good extensibility decision.
- **Good module-level documentation** explaining intent for most files.

## Recommendations

Prioritized, actionable:

1. **(C1) Fix the `sha2` dependency leak.** Route all hashing through a helper
   re-exported by `poly-verified` (e.g. `poly_verified::hash::sha256(&[u8])`) so
   generated code only references `poly_verified`. Add an integration test that
   compiles a `#[verified]` function from a crate that does *not* depend on `sha2`.
2. **(C2) Replace `Debug`-based hashing with canonical serialization.** Introduce a
   `VerifiableHash`/`CanonicalBytes` trait in `poly-verified`, add the bound to the
   generated signature, and hash stable bytes. This is the soundness fix that
   justifies the crate's name.
3. **(H2) Parse attribute arguments with `syn`.** Use `Meta` / `Punctuated` parsing
   for `#[verified(...)]` and `#[poly_bridge(...)]`; emit `compile_error!` on unknown
   arguments instead of silent substring behaviour.
4. **(H1/M5) Improve runtime error reporting.** Decide on a policy: either generate
   `Verified<Result<T,E>>` returns, or document the panic behaviour prominently. Use
   `quote_spanned!` so generated-code failures point at the macro call site.
5. **(H4) Use `generics.split_for_impl()`** in `verified_macro` so `where` clauses
   survive, and explicitly reject (or support) methods with `self` receivers.
6. **(M3/M4) Align documentation with reality.** Either implement `py!` variable
   capture and generic return typing (`expand_typed`), or remove the false promises
   from the doc comments and delete the dead `capture.rs` / `expand_typed` code.
7. **(M2) Downgrade or harden `#[pure]`.** Re-document it as a best-effort lint, or
   replace the substring scan with a `syn::visit::Visit` AST walk.
8. **(M1) Resolve `fold!`.** Implement accumulator plumbing or make it an explicit
   no-op pass-through so it stops emitting an unused-variable warning.
9. **(L3/L2) Replace string `.contains` type checks in `bridge_macro` with AST
   matching**, and handle method generics / default bodies.
10. **(H3) Constrain or document foreign-macro tokenization.** Prefer a raw-string
    literal form for `py!`/`js!`/`ts!` to avoid `to_string()` fidelity loss.
11. **General: add `quote_spanned!` and a `trybuild` test suite** covering both
    success expansions and the `compile_error!` paths, so regressions in diagnostics
    are caught.
```
