# polyglot (core compiler) — Documentation & Code Review

## Overview

`polyglot` is the root crate of the *pyrs polyglot* workspace — the core compiler and CLI for the
`.poly` polyglot programming language. A `.poly` file is a single source file containing multiple
fenced *language blocks* (`#[rust]`, `#[python]`, `#[js]`, `#[interface]`, `#[gpu]`, `#[html]`,
`#[rscss]`, etc.). The compiler parses these blocks, merges/transpiles them, and produces:

- **WASM modules** (`wasm32-wasip1`) for browser/host targets,
- **native binaries** for Linux / Windows / Android (`aarch64-linux-android` shared library),
- **Android APKs** (built directly with `aapt2`/`d8`/`zipalign`/`apksigner`, no Gradle),
- **WASM Components** (via `jco` / `componentize-py` / `wasm-compose`),
- **single-file HTML bundles** with the WASM base64-inlined.

It sits at the top of the workspace and depends on sibling crates `polyglot-macros`,
`polyglot-runtime`, `gridmesh`, and (for the `#[verified]` feature) `poly-verified`. Source lives
directly in [src/](src/) (~16k lines). The library API is re-exported from [src/lib.rs](src/lib.rs)
and the CLI entry point is [src/main.rs](src/main.rs).

What it produces is determined by the `--target` flag and the language of the `main` block: a JS/TS
`main` short-circuits to a merged `.ts`/`.js` file, otherwise all Rust/Python is merged into one
Rust crate and compiled via `cargo`.

## Architecture

The compilation pipeline is a largely text-driven, regex-and-`cargo`-orchestration design. Polyglot
does **not** have its own backend codegen; it merges source text and shells out to `rustc`/`cargo`,
`jco`, `npm`, Android SDK tools, etc.

```
 .poly source file
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. PARSE   parser::parse_poly  [src/parser.rs:412]            │
│   • IMPORT_RE  → use X from "..."                             │
│   • RE / UNIFIED_RE / BLOCK_RE  → #[lang] blocks + lang{}     │
│   • find_matching_brace for braced blocks  [src/parser.rs:50] │
│   • interface/types blocks → interface::parser::parse_interface│
│   • per-block normalization (Python only) syntax_aliases      │
│   • scan_exported_functions → auto-discover `export fn/def`   │
│                         ▼                                     │
│              ParsedFile { blocks, interfaces, imports }       │
└─────────────────────────────────────────────────────────────┘
      │
      ▼  (CLI only) resolve_imports — recursively merge imported .poly files [src/main.rs:1611]
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. VERIFY / VALIDATE                                          │
│   • verify_implementations  @implements ↔ trait [implements_verify.rs]│
│   • validate  interface fn completeness / no dupes [validation.rs]    │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. COMPILE   compiler::compile  [src/compiler.rs:237]         │
│   • bucket blocks by lang_tag, detect single main()          │
│   • JS/TS main → merge blocks, sort_js_main_last → return .ts │
│   • else: generate interface stubs (interface::codegen),      │
│           python bridge stubs, foreign_impls stubs            │
│   • multi-file Rust → write files + cargo build               │
│   • single-file Rust → merge, sort_main_last, dedup `use`,    │
│           process #[verified], → languages::rust::compile     │
│   • write web assets (app.js, styles.css, shaders.wgsl, html) │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. BACKEND BUILD (shell out)                                  │
│   • Rust::compile  → write Cargo.toml + lib.rs/main.rs,        │
│                      `cargo build --target ...`  [rust/mod.rs]│
│   • native: compile_native; android: generate_jni_lib (cdylib)│
│   • component: ComponentBuilder → jco/componentize-py         │
│   • apk: ApkBuilder → aapt2/d8/zipalign/apksigner             │
│   • bundle: generate_inline_bundle (base64 WASM in HTML)      │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
  WASM / native binary / APK / HTML  → written by main.rs::build_poly
```

A second, unfinished parser exists — `ast_parser::parse_poly_ast` ([src/ast_parser.rs:163](src/ast_parser.rs#L163))
built on `nom` — but it is not used by `compile()`; the regex-based `parse_poly` is the live path.

## Module Reference

### [src/lib.rs](src/lib.rs)
Crate root. Declares the module tree and re-exports the public API (`parse_poly`, `validate`,
`verify_implementations`, `ComponentBuilder`, `ComponentLinker`, `parse_poly_ast`).

### [src/main.rs](src/main.rs)
The CLI built with `clap`. Subcommands: `check`, `build`, `wit`, `run`, `init`, `bundle`, `npm`,
`watch`, `test`, `verify`, `new`, `tools`, `component`, `compose`. Key internals:
- `build_poly` ([src/main.rs:601](src/main.rs#L601)) — orchestrates parse → resolve_imports →
  verify → validate → `compile`, then writes output and maps `CompileError`s to `miette` diagnostics.
- `build_apk` ([src/main.rs:872](src/main.rs#L872)) — Android target path.
- `resolve_imports` ([src/main.rs:1611](src/main.rs#L1611)) — recursive `.poly` import merging with
  cycle detection via a `visited` set.
- `watch_poly` ([src/main.rs:1696](src/main.rs#L1696)) — file watcher + `tiny_http` dev server with
  a `/version` poll-based live reload.
- `new_from_template` / `get_react_template` / `get_ml_template` / `get_game_template` — large inline
  string templates (~550 lines of the file).

### [src/parser.rs](src/parser.rs)
The live regex-based `.poly` parser. `parse_poly` ([src/parser.rs:412](src/parser.rs#L412)) handles
three block syntaxes: header `#[lang]`, unified `#[lang]{...}`, and bare `lang {...}`.
`find_matching_brace` ([src/parser.rs:50](src/parser.rs#L50)) is a hand-written brace matcher that
tracks strings, comments, JS template literals, Rust raw strings, lifetimes, and regex literals.
`scan_exported_functions` auto-discovers `export fn`/`export def` into `parsed.interfaces`.
Also contains `parse_rust_type` / `parse_python_type` and param parsers.

### [src/ast_parser.rs](src/ast_parser.rs)
An alternative `nom`-based parser (`parse_poly_ast`). **Not wired into the compile pipeline** — it
only recognizes 6 tags (`interface/rust/rs/python/py/main`), has no brace matching, and no
normalization. Effectively dead/incomplete code kept as a "can be used as alternative".

### [src/types.rs](src/types.rs)
Core types: `WitType` enum, `FunctionSig`, `Param`, `CompileOptions`, `CompileTarget` (with
`is_native`, `target_triple`, `output_extension`).

### [src/compiler.rs](src/compiler.rs)
The heart of codegen orchestration. `compile` ([src/compiler.rs:237](src/compiler.rs#L237)) buckets
blocks, validates a single `main`, and dispatches to JS/TS-merge or Rust-merge paths. Helpers:
`deduplicate_use_statements`, `sort_main_last`, `sort_js_main_last` (brace-counting line scanners),
`extract_rust_constants` + `interpolate_css_constants` (CSS `@{CONST}` interpolation),
`link_modules` ([src/compiler.rs:980](src/compiler.rs#L980)) — *multi-module linking is a stub*,
`generate_inline_bundle` — builds the self-contained HTML with base64 WASM and a hand-written WASI
shim.

### [src/languages/](src/languages/mod.rs)
`Language` trait + registry. `find_language` maps tags to `Rust`/`Python` impls.
- [src/languages/rust/mod.rs](src/languages/rust/mod.rs): `Rust::compile` writes a temp Cargo project
  and shells `cargo build`. `compile_native` handles Linux/Windows/Android; `generate_jni_lib`
  ([src/languages/rust/mod.rs:417](src/languages/rust/mod.rs#L417)) regex-generates JNI wrappers.
  `find_workspace_root` walks up looking for a `Cargo.toml` containing `gridmesh`.
  `detect_dependencies` ([src/languages/rust/mod.rs:67](src/languages/rust/mod.rs#L67)) infers Cargo
  deps from `use` substrings.
- [src/languages/python/mod.rs](src/languages/python/mod.rs): Python language impl.

### [src/transpile/](src/transpile/mod.rs)
Re-exports `python::PythonTranspiler` — a Python→Rust transpiler ([src/transpile/python.rs](src/transpile/python.rs)).

### [src/syntax_aliases.rs](src/syntax_aliases.rs)
"Universal syntax normalization" — converts Python/JS syntax variants to Rust-ish form via regex:
`normalize_keywords`, `normalize_operators`, `normalize_strings` (f-strings/template literals →
`format!`), `normalize_decorators`, `normalize_arrow_functions`, and `infer_braces_from_indent`
(indentation → braces). Applied **only to Python blocks** in `parse_poly`.

### [src/validation.rs](src/validation.rs)
`validate` checks interface-function completeness and forbids duplicate implementations. Uses `syn`
to extract top-level Rust fns (correctly ignoring `impl` methods); uses regex for Python. Signature
matching is a `TODO` ([src/validation.rs:139](src/validation.rs#L139)).

### [src/implements_verify.rs](src/implements_verify.rs)
`verify_implementations` checks `@implements(Trait)` classes (Python/TS/JS) against `#[interface]`
trait defs — verifies method presence, parameter *count*, and return-type presence (not types).

### [src/interface/](src/interface/mod.rs)
- `parser.rs`: `nom`-based parser for `#[interface]`/`#[types]` blocks → `InterfaceItem` (Trait,
  Struct, Enum, Function, TypeAlias, TypeDecl).
- `codegen.rs`: generates Rust/Python/WIT from interface items; `generate_rust_with_source` emits
  `#[no_mangle] __export_*` wrappers and the `generate_python_bridge` **stub** functions.
- `foreign_impls.rs`, `type_registry.rs`: `@implements` decorator parsing and a type registry.

### [src/wit_gen.rs](src/wit_gen.rs)
Generates WIT interfaces from `ParsedFile` — both trait-based (`generate_wit_for_file`) and the
legacy signature-based (`generate_wit`).

### [src/verified/](src/verified/mod.rs)
`#[verified]` execution support. `verified_codegen.rs` prepends imports and runs
`determinism_check.rs`, a line-based scanner rejecting non-deterministic patterns (floats, unsafe,
IO, RNG, time). `error_codes.rs` defines V001–V015.

### [src/capability.rs](src/capability.rs)
A capability-token access-control subsystem (`Capability`, `CapabilityGenerator`,
`CapabilityVerifier`, code generators). **Not referenced by the compile pipeline** — appears to be
unwired/aspirational. Notably uses a custom `simple_hash` rather than a real HMAC.

### [src/component_builder.rs](src/component_builder.rs) / [src/component_linker.rs](src/component_linker.rs)
Build language blocks into WASM Components via `jco`/`componentize-py`, and compose them via
`wasm-compose`. `check_component_tools` reports tool availability.

### [src/apk_builder.rs](src/apk_builder.rs)
Gradle-free APK builder: generates `AndroidManifest.xml`, a fixed `MainActivity.java` (a LoRa/USB
chat app), compiles with `javac`, dexes with `d8`, packages/aligns/signs.

### [src/manifest.rs](src/manifest.rs)
`poly.toml` parser (`[package]`, `[rust]`, `[npm]`, `[pip]`, `[build]`, `[verified]`); converts to
`Cargo.toml` / `package.json` / `requirements.txt` fragments.

### [src/diagnostic.rs](src/diagnostic.rs) / [src/source_map.rs](src/source_map.rs)
`miette`-based diagnostic structs (E001–E031, W001) and offset/line helpers; source map generation
mapping generated lines back to `.poly` lines.

### [src/host_imports.rs](src/host_imports.rs) / `host_imports_injectable.rs`
Host-target import surface; `host_imports_injectable.rs` is `include_str!`-injected into generated
Rust for the `Host` target.

## Code Review

### Critical

**C1. APK builder is Windows-only and hardcoded to a specific demo app — [src/apk_builder.rs:205](src/apk_builder.rs#L205), [src/apk_builder.rs:268](src/apk_builder.rs#L268), [src/apk_builder.rs:684](src/apk_builder.rs#L684)**
The builder hardcodes `aapt2.exe`, `zipalign.exe`, `d8.bat`, and invokes `cmd /c`. On macOS/Linux
these names/wrappers do not exist, so `polyglot build --target apk` always fails off Windows.
Worse, `generate_java_code` ([src/apk_builder.rs:268](src/apk_builder.rs#L268)) emits a fixed
`MainActivity.java` titled "LoRaChat" with USB-serial logic that has nothing to do with the user's
`.poly` program — every APK ships the same LoRa chat UI. The native methods declared
(`native_refresh_ports`, etc.) also will not match arbitrary `export fn` JNI symbols generated by
`generate_jni_lib`. *Fix:* resolve tool names per-OS (`.exe`/`.bat` only on Windows), and generate
`MainActivity.java` from the user's exports / WebView entry, not a hardcoded app.

**C2. `find_matching_brace` regex-literal heuristic corrupts arbitrary code — [src/parser.rs:113](src/parser.rs#L113)-[src/parser.rs:156](src/parser.rs#L156)**
While scanning a braced block, any `/` preceded by `= ( , : [` or a newline is treated as the start
of a JS regex literal and the scanner *skips to the next `/`*. In Rust/Python blocks this silently
swallows division and path text. E.g. `let x = a / b; let y = c / d;` — the `/` after `=` starts
"regex mode" and everything up to the next `/` (including a real `}`) is consumed, producing wrong
block boundaries or a brace-match failure. Because block content is later compiled verbatim, this is
a correctness bug that depends on innocuous source. *Fix:* only apply regex-literal detection to
JS/TS blocks, or drop the heuristic and rely on string/comment tracking only.

**C3. Multi-module linking is a silent no-op — [src/compiler.rs:980](src/compiler.rs#L980)-[src/compiler.rs:995](src/compiler.rs#L995)**
`link_modules` returns `modules[0]` and prints a warning when more than one module exists. In
practice `compile` only ever pushes one module, so this is currently inert, but the function name
and signature advertise linking that does not happen. Any future code path that produces 2+ modules
will silently drop all but the first. *Fix:* either remove the dead branch or return an explicit
error instead of producing a wrong binary.

### High

**H1. Pervasive `.unwrap()` / `.expect()` on external-process and IO results — [src/main.rs:316](src/main.rs#L316), [src/main.rs:323](src/main.rs#L323), [src/main.rs:339](src/main.rs#L339), [src/main.rs:1828](src/main.rs#L1828), [src/main.rs:1851](src/main.rs#L1851)**
The `npm` subcommand uses `.expect("Failed to run npm init")` etc. — if `npm` is not on `PATH` the
CLI panics with a backtrace instead of a clean error. `watch_poly` calls
`"...".parse::<tiny_http::Header>().unwrap()` on every request; while these literals are valid, the
pattern is fragile. *Fix:* propagate `Result` via `into_diagnostic()` consistently as the rest of
`main.rs` already does.

**H2. `generate_index_html` references a nonexistent path — [src/compiler.rs:970](src/compiler.rs#L970)**
The auto-generated HTML imports `./pkg/poly_cell.js`, but the WASM crate is named `poly_cell` and
the compiler never produces a `pkg/` directory or a JS shim (no `wasm-bindgen`/`wasm-pack` step
exists in the pipeline). Auto-HTML output therefore cannot load the module. The single-file
`generate_inline_bundle` path works because it inlines a hand-written loader, but the `index.html`
written by `compile` for the non-bundle WASM path is broken. *Fix:* emit the same inline loader, or
remove the auto-HTML branch.

**H3. `resolve_imports` merges duplicate `main`/blocks with no namespacing — [src/main.rs:1654](src/main.rs#L1654)-[src/main.rs:1663](src/main.rs#L1663)**
Imported `.poly` files have all their `blocks` and `interfaces` appended wholesale. If two files
both define a helper `fn add`, or an imported file has its own `#[main]`, compilation fails later
with confusing "Multiple main functions"/duplicate-symbol errors rather than a clear import-level
diagnostic. The `import.items` selector (`use { foo } from`) is parsed but **never used** to filter
what is merged — every import is effectively `use *`. *Fix:* honor `items` for selective import, and
detect/scope conflicts at merge time.

**H4. Path-traversal surface in the `watch` dev server is only partly mitigated — [src/main.rs:1839](src/main.rs#L1839)-[src/main.rs:1857](src/main.rs#L1857)**
The static-file branch canonicalizes and checks `starts_with(base)`, which is correct — but the URL
is not URL-decoded, and the check is bypassed only because `file_path.exists()` is tested *before*
canonicalization on the raw joined path. On Windows, `watch_dir.join("C:/Windows/...")` would
produce an absolute path; the canonical-prefix check catches it, so it is contained, but the design
is fragile. The server also binds `127.0.0.1` only (good) but injects a `</body>` replace
([src/main.rs:1823](src/main.rs#L1823)) that silently fails if the HTML has no `</body>`. *Fix:*
URL-decode, reject `..` segments explicitly, and handle the missing-`</body>` case.

**H5. `simple_hash` in the capability system is not cryptographically sound — [src/capability.rs:250](src/capability.rs#L250)**
`CapabilityGenerator::derive_capability` is documented as "HMAC-SHA256-like" but uses a custom
add/xor/rotate mixing function (`simple_hash`). Capability tokens derived from it are forgeable by
anyone who can analyze the mixing function; the module's own doc-comment claims tokens are
"unforgeable (cryptographically derived)". This is a security-claim/implementation mismatch.
Mitigating factor: the whole module is currently unwired (see L1). *Fix:* if the feature is kept,
use a real HMAC (`hmac` + `sha2` are already workspace deps); otherwise delete the module.

**H6. `detect_dependencies` matches substrings, causing false dependency injection — [src/languages/rust/mod.rs:110](src/languages/rust/mod.rs#L114)**
Dependencies are inferred by `source.contains("use serde::")` *or* `source.contains("serde::")`. The
bare `crate_name::` test matches inside strings, comments, or unrelated identifiers (e.g. a local
module also named `http` or `url`). A false positive adds a dependency that may fail to resolve or
shadow a local module, breaking the build. *Fix:* parse `use` statements with `syn` (already a
dependency) instead of substring scans.

### Medium

**M1. `sort_main_last` / `sort_js_main_last` brace counting ignores strings and comments — [src/compiler.rs:117](src/compiler.rs#L117)-[src/compiler.rs:127](src/compiler.rs#L127), [src/compiler.rs:178](src/compiler.rs#L187)**
These functions count `{`/`}` character-by-character with no string/char/comment awareness. A `main`
body containing `"}"` in a string literal, or `'{'` as a char, ends the function early and the
remainder of `main` is left in `before_main`, producing scrambled output. The dedicated
`find_matching_brace` already solves this correctly and should be reused.

**M2. Visibility keyword rewriting is a blind string replace — [src/compiler.rs:737](src/compiler.rs#L737)-[src/compiler.rs:740](src/compiler.rs#L740), [src/languages/rust/mod.rs:555](src/languages/rust/mod.rs#L555)**
`merged_rust_code.replace("export fn ", "pub fn ")` (and `"fn main()"` → `"fn _main()"` in
`generate_jni_lib`) will rewrite those substrings inside string literals, comments, or doc text.
A Rust block containing the literal `"export fn "` in a string gets silently corrupted. *Fix:* do
the substitution token-aware (it is already only meaningful at statement start).

**M3. `normalize_operators` mangles identifiers and strings — [src/syntax_aliases.rs:136](src/syntax_aliases.rs#L136)-[src/159](src/syntax_aliases.rs#L159)**
`is` → `==`, `and` → `&&`, `or` → `||`, `not ` → `!` are applied with word-boundary regex over the
*entire Python block text*, including string literals and f-string contents. Python code like
`msg = "this is fine"` becomes `msg = "this == fine"`. Also `is` → `==` is semantically wrong
(Python `is` is identity, not equality). Because normalization runs before block compilation, this
corrupts user strings. *Fix:* tokenize, or at minimum skip string spans.

**M4. `extract_rust_constants` only matches single-line `enum` bodies — [src/compiler.rs:894](src/compiler.rs#L894)**
`ENUM_RE = r"pub\s+enum\s+(\w+)\s*\{([^}]+)\}"` cannot match a multi-line enum (the `[^}]+` still
spans lines, but a variant with a `{}` struct body breaks it) and silently yields no constants, so
`@{Enum::Variant}` CSS interpolation falls back to `/* UNDEFINED */`. Minor, but a silent failure.

**M5. `find_workspace_root` couples the compiler to a `gridmesh` sibling directory — [src/languages/rust/mod.rs:20](src/languages/rust/mod.rs#L20)**
Workspace detection requires a `Cargo.toml` containing `[workspace]` *and* a `gridmesh/`
subdirectory. If the crate is installed/relocated without the workspace layout, all WASM builds fail
because the generated `Cargo.toml` path-depends on `gridmesh`, `polyglot-macros`,
`polyglot-runtime`. This makes the produced binary effectively non-portable. *Fix:* allow these to
be published crates or make the dependency optional.

**M6. `ast_parser.rs` and `capability.rs` are dead/unwired code — [src/ast_parser.rs](src/ast_parser.rs), [src/capability.rs](src/capability.rs)**
~320 + ~800 lines of code (plus `host_imports.rs` partially) are public but never invoked by the
compile pipeline. They drift from the live `parser.rs` (different `CodeBlock`/`ParsedFile` types,
fewer tags). This is a maintainability hazard — a reader cannot tell which parser is authoritative.
*Fix:* delete or clearly gate behind a feature flag with a doc note.

**M7. `parse_poly` interface blocks are double-counted — [src/parser.rs:488](src/parser.rs#L488)-[src/parser.rs:501](src/parser.rs#L501)**
`#[interface]`/`#[types]` blocks are parsed into `parsed.interfaces` *and* then "fall through" to be
pushed as a `CodeBlock` as well (comment says "for LSP VirtualFile tracking"). `compile` then has
explicit `"interface" => {}` / `"types" => {}` arms to ignore them. This works but is brittle: any
new code that iterates `blocks` must remember to skip these. The unified-syntax path
([src/parser.rs:589](src/parser.rs#L589)) also pushes them as blocks. Document or separate the LSP
concern.

**M8. `generate_python_bridge` emits stub functions that fake results — [src/interface/codegen.rs:283](src/interface/codegen.rs#L283)-[src/interface/codegen.rs:326](src/interface/codegen.rs#L326)**
Cross-language Python calls compile to Rust functions that just `println!("[Python Bridge]...")` and
return a default value. A `.poly` file that relies on a Python implementation of an interface
function will *compile successfully* but produce semantically wrong output at runtime with no
warning. This is a correctness landmine disguised as a working feature. *Fix:* emit a
`compile_error!`/`todo!()` or a clear warning so the gap is visible.

### Low

**L1. Inconsistent panic vs. `Result` on slicing — [src/compiler.rs:258](src/compiler.rs#L258)**
`&block.code[..block.code.len().min(50)]` is byte-sliced; if byte 50 lands inside a multi-byte UTF-8
char this panics. `find_matching_brace` already carefully uses `is_char_boundary` elsewhere — apply
the same care here (`char_indices`).

**L2. `count_leading_whitespace` treats tab as 4 spaces unconditionally — [src/syntax_aliases.rs:609](src/syntax_aliases.rs#L609)**
Mixed tabs/spaces in a Python block can produce wrong brace nesting in `infer_braces_from_indent`.
The diagnostic `W001 MixedIndentationWarning` exists but is never emitted.

**L3. `RustCompileError` error-extraction is heuristic and lossy — [src/languages/rust/mod.rs:726](src/languages/rust/mod.rs#L726)-[src/languages/rust/mod.rs:809](src/languages/rust/mod.rs#L809)**
The rustc-stderr parser caps at 5 errors and filters by substrings (`lib.rs`, dependency names). On
generated code where the relevant line is in `lib.rs` this is OK, but column/line numbers refer to
the *generated* merged file, not the `.poly` source, so users see misleading locations. The
`source_map` module exists but is not used to remap these.

**L4. `Language` trait is over-broad / partly unused — [src/languages/mod.rs:8](src/languages/mod.rs#L8)**
`parse_signatures` and `map_type` are part of the trait but `wit_gen` only calls `parse_signatures`
for `py`/`rs`; the Python impl's signature parsing is regex-based. The trait would benefit from
splitting compilation from introspection.

**L5. `find_language("main")` maps to Rust silently — [src/languages/mod.rs:39](src/languages/mod.rs#L39)**
`#[main]` is treated as a Rust block, which is the intent, but a `#[main]` containing Python/JS would
be miscompiled. The actual `main` language is detected separately in `compile` via `main_locations`,
so the mapping here is misleading.

**L6. CLI `Run --release` flag is documented as default-true but `build` is default-false — [src/main.rs:75](src/main.rs#L75) vs [src/main.rs:45](src/main.rs#L45)**
Minor UX inconsistency; `run` always builds release, `build` defaults to debug.

**L7. `compose_components` fabricates `ComponentBuildResult` with `size = 0` on metadata failure — [src/main.rs:507](src/main.rs#L507)**
If `fs::metadata` fails the size is silently `0`; later size reporting is wrong. Prefer surfacing the
error.

## Strengths

- **Clear pipeline separation.** Parse → validate → compile → backend-build is well factored across
  modules; `CompileOptions`/`CompileTarget` cleanly parameterize targets.
- **`find_matching_brace` is genuinely careful** about strings, triple-quoted Python strings, JS
  template literals with nested `${}`, Rust raw strings (`r#"..."#`), char literals vs. lifetimes,
  and line/block comments — and it emits useful debug context on failure.
- **Excellent diagnostics surface.** [src/diagnostic.rs](src/diagnostic.rs) defines structured,
  coded (`E001`–`E031`) `miette` errors with help text; `build_poly` maps internal errors to them
  with source spans.
- **Validation correctly uses `syn`** for Rust function extraction, properly ignoring `impl`
  methods — a subtle correctness point handled well ([src/validation.rs:46](src/validation.rs#L46)).
- **Determinism checker** for `#[verified]` is a thoughtful feature with clear, hint-bearing error
  codes.
- **Good test coverage at the unit level** — `parser`, `syntax_aliases`, `wit_gen`,
  `implements_verify`, `manifest`, `capability`, `verified_codegen` all carry `#[cfg(test)]` suites.
- **`poly.toml` manifest support** is comprehensive (rust/npm/pip, dev-dep classification,
  parent-directory walk).
- **Constant-time comparison** (`secure_eq`, `constant_time_eq`) is used in the capability code —
  the right instinct, even if `simple_hash` undermines it.

## Recommendations

Prioritized, actionable:

1. **Fix the regex-literal heuristic in `find_matching_brace` (C2).** Gate it to JS/TS blocks only.
   This is the highest-impact correctness bug because it can corrupt ordinary Rust/Python.
2. **Make the APK builder cross-platform and program-driven (C1).** Resolve tool names per-OS and
   generate `MainActivity.java` from the user's exports instead of the hardcoded LoRa app.
3. **Make stubbed features fail loudly.** `generate_python_bridge` (M8) and `link_modules` (C3)
   should emit `compile_error!`/explicit errors rather than producing silently-wrong binaries.
4. **Replace text-replace transforms with token-aware logic.** Visibility rewriting (M2), operator
   normalization (M3), and `sort_*_main_last` brace counting (M1) all corrupt strings/comments;
   reuse `syn` (already a dependency) and `find_matching_brace`.
5. **Delete or feature-gate dead modules** `ast_parser.rs` and `capability.rs` (M6) — they confuse
   the authoritative-parser question and contain a misleading security claim (H5).
6. **Replace substring dependency detection with `syn` `use`-statement parsing (H6).**
7. **Harden the watch server (H4):** URL-decode, reject `..`, handle missing `</body>`.
8. **Honor selective imports** (`use { foo } from`) and detect conflicts at merge time (H3).
9. **Fix or remove `generate_index_html`'s broken `./pkg/poly_cell.js` reference (H2).**
10. **Replace `.expect()` on subprocess spawns with propagated diagnostics (H1).**
11. **Wire `source_map` into rustc error remapping (L3)** so users see `.poly` line numbers.
12. **Reduce coupling to the `gridmesh` sibling directory (M5)** so the installed compiler is
    relocatable.
