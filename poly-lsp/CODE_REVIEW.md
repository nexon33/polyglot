# poly-lsp — Documentation & Code Review

## Overview

`poly-lsp` is the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
server for the polyglot `.poly` language — a source format that interleaves multiple
real programming languages (Rust, Python, JavaScript) inside a single file using block
directives such as `#[rust]`, `#[python]`, `#[interface]`, and `#[types]`.

A `.poly` file is *not* itself a language any off-the-shelf compiler understands; it is a
container. `poly-lsp`'s job is to make an editor treat that container as a coherent,
single document while still delegating per-block intelligence to the real language
servers for each embedded language.

**How editors connect.** The server speaks LSP over stdio. `main` ([poly-lsp/src/main.rs:727](poly-lsp/src/main.rs#L727))
wires `tokio::io::stdin`/`stdout` into `tower_lsp::Server`. An editor extension
(`poly-vscode`) spawns the `poly-lsp` binary as a child process and exchanges
`Content-Length`-framed JSON-RPC messages over the child's stdio pipes. `poly-vscode`
is the thin client: it registers the `.poly` language, launches this binary, and
forwards LSP requests; all language intelligence lives here in `poly-lsp`.

**What it provides.** Capabilities advertised in `initialize`
([poly-lsp/src/main.rs:46](poly-lsp/src/main.rs#L46)): full-document text sync,
completion (trigger chars `.` and `:`), hover, go-to-definition, find-references,
and full-document semantic tokens.

## Architecture

### Request lifecycle

`tower-lsp` owns the JSON-RPC transport for the *editor-facing* side: it parses
inbound requests, dispatches them to the `LanguageServer` trait methods on `Backend`
([poly-lsp/src/main.rs:45](poly-lsp/src/main.rs#L45)), and serializes responses.
The hand-rolled `json_rpc` module ([poly-lsp/src/json_rpc.rs](poly-lsp/src/json_rpc.rs))
is used only for the *child-server-facing* side — talking to `rust-analyzer` and
`pylsp`.

A typical request (`hover`, `definition`, `references`) flows:

1. Editor sends an LSP request referring to a real `.poly` URI and a real line/column.
2. `Backend` resolves the request against in-memory polyglot state first
   (the `TypeGraph`/`SymbolTable` for cross-language symbols, plus directive/keyword
   hovers).
3. If the polyglot layer has no answer, `Backend` finds the `VirtualFile` containing
   that real line, maps the real line down to a *virtual* line, and delegates the
   request to the child language server via the `Delegator`.
4. The child server's response (ranges, locations) is mapped *back up* from virtual
   lines to real `.poly` lines and returned to the editor.

### Shadow index, virtual FS, and sidecar

```
                          .poly file (real document)
                                   │
                  ┌────────────────┼─────────────────┐
                  ▼                                   ▼
        ┌───────────────────┐              ┌────────────────────────┐
        │ VirtualFileManager │              │   ShadowIndex (regex)  │
        │  parse_poly()      │              │   <5ms signature scan  │
        │  splits into blocks│              │   runs every keystroke │
        └─────────┬──────────┘              └───────────┬────────────┘
                  │ Vec<VirtualFile>                    │ merge_into_symbol_table
                  │ (one per #[lang] block,             │
                  │  start_line/code_start_line offsets)▼
                  │                          ┌────────────────────────┐
       ┌──────────┴───────────┐              │  TypeGraph / SymbolTable│
       ▼                      ▼              │  cross-language symbols │
┌──────────────┐   ┌────────────────────┐   └───────────┬────────────┘
│  Delegator   │   │ debounced 500ms     │               │
│ rust-analyzer│   │ Tree-sitter scan    │───────────────┘
│ pylsp        │   │ (full AST, diags)   │
│ child procs  │   └─────────┬───────────┘
└──────┬───────┘             ▼
       │            ┌────────────────────┐
       │            │ SidecarGenerator   │
       │            │ writes .d.ts so    │
       │            │ tsserver sees      │
       │            │ Rust/Py types      │
       │            └────────────────────┘
       ▼
  child writes .virtual.rs / .virtual.py to disk;
  publishDiagnostics flow back through diag channel,
  lines remapped virtual->real, re-published to editor.
```

- **Virtual FS** (`virtual_fs.rs`): a `.poly` file is split by `parse_poly` into one
  `VirtualFile` per language block. Each `VirtualFile` records `start_line` (header
  line) and `code_start_line` (first real code line), enabling the
  `map_to_real`/`map_to_virtual` line translation that glues editor coordinates to
  child-server coordinates.

- **Shadow index** (`shadow_indexer.rs`): a deliberately cheap, regex-only pass that
  extracts function signatures in under 5 ms so hover/completion stay responsive while
  the user is typing. Its results are merged into the `SymbolTable` immediately; a
  slower, accurate Tree-sitter scan runs 500 ms after typing stops.

- **Sidecar** (`sidecar_generator.rs`): because JavaScript/TypeScript tooling cannot
  see Rust or Python types, the generator emits a `polyglot_types.d.ts` file (plus an
  optional `tsconfig.polyglot.json`) into a `.poly-lsp/` directory so `tsserver` can
  type-check JS blocks against cross-language signatures.

## Module Reference

### [poly-lsp/src/main.rs](poly-lsp/src/main.rs)
Entry point and the `Backend` LSP implementation.
- `Backend` ([poly-lsp/src/main.rs:28](poly-lsp/src/main.rs#L28)) — holds all shared
  state behind `Arc`/`Mutex`: `VirtualFileManager`, `Delegator`, `TypeGraph`,
  `ShadowIndex`, `SidecarGenerator`, a debounce timestamp, and the diagnostic receiver.
- `impl LanguageServer for Backend` ([poly-lsp/src/main.rs:45](poly-lsp/src/main.rs#L45)) —
  `initialize`, `initialized`, `shutdown`, `did_open`, `did_change`, `hover`,
  `goto_definition`, `references`, `semantic_tokens_full`.
- Helper methods on `Backend`: `check_polyglot_hover`, `check_directive_hover`,
  `extract_word_at_cursor` ([poly-lsp/src/main.rs:636](poly-lsp/src/main.rs#L636)).
- `main` ([poly-lsp/src/main.rs:727](poly-lsp/src/main.rs#L727)) — constructs the
  `LspService` and serves over stdio.

### [poly-lsp/src/json_rpc.rs](poly-lsp/src/json_rpc.rs)
Minimal LSP wire codec used for child-server communication.
- `read_message` ([poly-lsp/src/json_rpc.rs:5](poly-lsp/src/json_rpc.rs#L5)) — reads
  `Content-Length` headers one byte at a time, then the body.
- `write_message` ([poly-lsp/src/json_rpc.rs:40](poly-lsp/src/json_rpc.rs#L40)) —
  serializes a `Value` with a `Content-Length` header.

### [poly-lsp/src/delegator.rs](poly-lsp/src/delegator.rs)
Spawns and proxies child language servers (`rust-analyzer`, `pylsp`).
- `Delegator` ([poly-lsp/src/delegator.rs:16](poly-lsp/src/delegator.rs#L16)) — owns a
  `HashMap<lang, ChildServer>` and the diagnostic forwarding channel.
- `ChildServer` ([poly-lsp/src/delegator.rs:23](poly-lsp/src/delegator.rs#L23)) — child
  stdin, a `DashMap` of pending request IDs to `oneshot` senders, an ID counter, and an
  `initialized` flag.
- `start_server` ([poly-lsp/src/delegator.rs:48](poly-lsp/src/delegator.rs#L48)) —
  spawns the process, starts a reader task, performs the LSP `initialize` handshake.
- `request` / `notify` ([poly-lsp/src/delegator.rs:204](poly-lsp/src/delegator.rs#L204),
  [poly-lsp/src/delegator.rs:149](poly-lsp/src/delegator.rs#L149)) — send a
  request/notification and await the matched response.
- `sync_open` ([poly-lsp/src/delegator.rs:163](poly-lsp/src/delegator.rs#L163)) — writes
  the virtual file to disk and sends `didOpen`.
- `request_with_fallback`, `fallback_definition`, `augment_references`, `fallback_hover`
  ([poly-lsp/src/delegator.rs:240](poly-lsp/src/delegator.rs#L240)) — "middleware" that
  falls back to / augments with `TypeGraph` data. *Note: these are defined but not
  called by `Backend`.*

### [poly-lsp/src/virtual_fs.rs](poly-lsp/src/virtual_fs.rs)
Splits `.poly` files into per-language virtual files and maps line coordinates.
- `VirtualFile` ([poly-lsp/src/virtual_fs.rs:23](poly-lsp/src/virtual_fs.rs#L23)) —
  one language block; `map_to_real`/`map_to_virtual`/`virtual_uri`/`language_id`.
- `VirtualFileManager` ([poly-lsp/src/virtual_fs.rs:35](poly-lsp/src/virtual_fs.rs#L35)) —
  `DashMap<Url, Vec<VirtualFile>>` plus a source cache; `update_file`, `get_files`,
  `get_source`.
- `detect_syntax_regions` ([poly-lsp/src/virtual_fs.rs:156](poly-lsp/src/virtual_fs.rs#L156)) —
  heuristic regex scoring to label line ranges as Rust/Python/JS/Mixed.

### [poly-lsp/src/type_graph.rs](poly-lsp/src/type_graph.rs)
Cross-language symbol and consistency analysis via Tree-sitter.
- `TypeGraph` ([poly-lsp/src/type_graph.rs:24](poly-lsp/src/type_graph.rs#L24)) —
  interfaces, implementations, type declarations, call sites, and a `SymbolTable`.
- `scan_file` ([poly-lsp/src/type_graph.rs:67](poly-lsp/src/type_graph.rs#L67)) —
  dispatches per block kind; `scan_rust`/`scan_python` run Tree-sitter queries.
- `check_consistency` ([poly-lsp/src/type_graph.rs:584](poly-lsp/src/type_graph.rs#L584)) —
  emits `undefined_function` diagnostics filtered against a builtin whitelist.
- `get_function_hover` / `get_type_hover` — render hover markdown.

### [poly-lsp/src/symbol_table.rs](poly-lsp/src/symbol_table.rs)
Unified symbol store for cross-language linking.
- `SymbolInfo` ([poly-lsp/src/symbol_table.rs:22](poly-lsp/src/symbol_table.rs#L22)) —
  declaration, implementations, call sites for one symbol.
- `SymbolTable` ([poly-lsp/src/symbol_table.rs:58](poly-lsp/src/symbol_table.rs#L58)) —
  `declare`, `add_implementation`, `add_call_site`, `get_by_name`, `clear_for_file`.

### [poly-lsp/src/semantic_tokens.rs](poly-lsp/src/semantic_tokens.rs)
Mixed-language syntax highlighting.
- `PolyTokenizer` ([poly-lsp/src/semantic_tokens.rs:124](poly-lsp/src/semantic_tokens.rs#L124)) —
  hand-rolled, line-based tokenizer with multi-language keyword sets.
- `get_legend`, `encode_tokens_for_lsp`, `encode_tokens_data` — LSP delta encoding.

### [poly-lsp/src/shadow_indexer.rs](poly-lsp/src/shadow_indexer.rs)
Fast regex-only signature extraction.
- `ShadowIndex` ([poly-lsp/src/shadow_indexer.rs:33](poly-lsp/src/shadow_indexer.rs#L33)) —
  precompiled per-language regexes; `quick_scan`, `merge_into_symbol_table`,
  `signatures_by_lang`.

### [poly-lsp/src/sidecar_generator.rs](poly-lsp/src/sidecar_generator.rs)
TypeScript `.d.ts` generation.
- `SidecarGenerator` ([poly-lsp/src/sidecar_generator.rs:13](poly-lsp/src/sidecar_generator.rs#L13)) —
  `generate_dts`, `generate_tsconfig`, `type_to_typescript`, `extract_inner_type`.

## Code Review

### Critical

**C1. `read_message` does not bound `Content-Length`; a hostile or buggy child can OOM/abort the process.**
[poly-lsp/src/json_rpc.rs:30-34](poly-lsp/src/json_rpc.rs#L30)
`let mut body = vec![0; len];` allocates exactly `len` bytes with no upper limit. A
child server that emits a malformed header (`Content-Length: 99999999999`) causes an
immediate multi-GB allocation, likely aborting the process. *Why it matters:* the child
process is external (`rust-analyzer`, `pylsp`) and its output is untrusted from a
robustness standpoint; one bad frame kills the whole language server.
*Fix:* validate `len` against a sane cap (e.g. 32 MB) and return an error frame instead
of allocating blindly.

**C2. Tree-sitter scanning unwraps in many places; any parse failure or query mismatch panics the scan path.**
[poly-lsp/src/type_graph.rs:155-156](poly-lsp/src/type_graph.rs#L155),
[poly-lsp/src/type_graph.rs:163](poly-lsp/src/type_graph.rs#L163),
[poly-lsp/src/type_graph.rs:171-178](poly-lsp/src/type_graph.rs#L171)
`parser.parse(...).unwrap()`, `Query::new(...).unwrap()`, and especially
`m.captures[0..2]` index directly into the capture array. The comments at
[poly-lsp/src/type_graph.rs:169-174](poly-lsp/src/type_graph.rs#L169) openly admit
uncertainty about capture ordering ("captures are in parse tree order, not query
order"). If a query matches with fewer captures than expected (e.g. a function with no
parameters node, or a tree-sitter grammar version change), `m.captures[2]` panics with
an out-of-bounds index. `name_node.utf8_text(...).unwrap()` also panics on invalid
UTF-8 boundaries. *Why it matters:* `scan_file` runs inside the debounced task and in
`did_open`; a panic there is silently swallowed by `tokio::spawn` for `did_change`, but
in `did_open` it runs on the request task and aborts that handler — and in either case
the analysis state is left half-populated. *Fix:* replace `unwrap` with graceful
`match`/`?`, and index captures by capture *name* (`query.capture_index_for_name`)
rather than positional index.

**C3. `goto_definition` / `references` slice strings by byte offset using a character (UTF-16/char) column.**
[poly-lsp/src/main.rs:391-396](poly-lsp/src/main.rs#L391),
[poly-lsp/src/main.rs:519-524](poly-lsp/src/main.rs#L519),
[poly-lsp/src/main.rs:413-418](poly-lsp/src/main.rs#L413)
`let char_idx = character.min(line_content.len()); let before = &line_content[..char_idx];`
treats the LSP `character` field (a UTF-16 code-unit offset per the LSP spec) as a Rust
byte offset. On any line containing non-ASCII text, `&line_content[..char_idx]` will
either slice in the middle of a UTF-8 sequence and **panic**, or silently extract the
wrong word. `extract_word_at_cursor` ([poly-lsp/src/main.rs:698](poly-lsp/src/main.rs#L698))
correctly uses a `Vec<char>` but still conflates `char` index with the UTF-16 column.
*Why it matters:* a single emoji or accented identifier in a `.poly` file crashes
go-to-definition. *Fix:* convert the LSP UTF-16 column to a byte offset over the actual
line content before slicing, and guard against non-char-boundary indices.

### High

**H1. Blocking, synchronous filesystem I/O on async request paths.**
`std::fs::read_to_string` in `goto_definition` ([poly-lsp/src/main.rs:408](poly-lsp/src/main.rs#L408))
and `references` ([poly-lsp/src/main.rs:537](poly-lsp/src/main.rs#L537)) runs on the
tokio worker thread inside an `async fn`. `Delegator::sync_open` similarly does
`std::fs::File::create` + `write_all` ([poly-lsp/src/delegator.rs:187](poly-lsp/src/delegator.rs#L187)),
and `SidecarGenerator::generate_dts` does `std::fs::write`
([poly-lsp/src/sidecar_generator.rs:104](poly-lsp/src/sidecar_generator.rs#L104)) while
holding the `sidecar_generator` mutex inside the debounced task. *Why it matters:*
blocking syscalls stall the tokio executor and can delay unrelated requests; on a slow
disk this is user-visible latency. *Fix:* use `tokio::fs` or wrap in
`tokio::task::spawn_blocking`.

**H2. The diagnostic reverse-lookup is O(files × virtual-files) on every child diagnostic.**
[poly-lsp/src/main.rs:103-122](poly-lsp/src/main.rs#L103)
The code itself flags this with a `TODO: reverse lookup` comment. Every
`publishDiagnostics` notification from a child triggers a full linear scan of every
real file's every virtual file to find the matching virtual URI. *Why it matters:*
`rust-analyzer` emits diagnostics frequently; in a large workspace this is wasted CPU
on a hot path. *Fix:* maintain a `DashMap<virtual_uri_string, real_uri>` reverse index
populated in `VirtualFileManager::update_file`.

**H3. `request`/`notify` hold the `servers` mutex across an `await` on child stdin write.**
[poly-lsp/src/delegator.rs:206-221](poly-lsp/src/delegator.rs#L206),
[poly-lsp/src/delegator.rs:151-158](poly-lsp/src/delegator.rs#L151)
`request` locks `servers`, then `write_message(&mut server.stdin, ...).await` while the
lock is held (it is dropped only afterward at line 221). If the child's stdin pipe is
full / the child is slow to drain, *all* delegation for *all* languages is serialized
behind that one lock — a request to `pylsp` blocks because a `rust-analyzer` write is
in flight. *Why it matters:* one stuck child can wedge cross-language features
entirely. *Fix:* store each `ChildServer.stdin` behind its own `Mutex` (or an mpsc
writer task) so the per-server map lock is released before the write `await`.

**H4. Child requests have no timeout; a hung child blocks the handler forever.**
[poly-lsp/src/delegator.rs:223](poly-lsp/src/delegator.rs#L223)
`let response = rx.await?;` waits indefinitely on the `oneshot`. If the child never
replies (crash after the reader task already exited, or a dropped sender), the
`hover`/`definition` handler hangs forever. The `oneshot` sender is only removed from
`pending` on a *matched* response ([poly-lsp/src/delegator.rs:85](poly-lsp/src/delegator.rs#L85));
if the reader task breaks on EOF ([poly-lsp/src/delegator.rs:100](poly-lsp/src/delegator.rs#L100))
all outstanding senders are leaked and their receivers will error — but only if the
`DashMap` is dropped, which it is not. *Fix:* wrap the await in `tokio::time::timeout`,
and on reader-task exit drain `pending` so receivers fail fast.

**H5. JSON-RPC header parsing only handles numeric `id` and ignores responses without `id`.**
[poly-lsp/src/delegator.rs:83-88](poly-lsp/src/delegator.rs#L83)
`id_val.as_u64()` silently drops responses whose `id` is a string or a negative number
(both legal in JSON-RPC 2.0). A child that echoes string IDs would have its responses
discarded, and the corresponding `request` call (H4) would hang forever. *Why it
matters:* correctness depends on every child using `u64` IDs. *Fix:* normalize IDs to a
canonical key type (string) on both send and receive.

### Medium

**M1. `did_change` assumes full-document sync but never enforces it; incremental changes corrupt state.**
[poly-lsp/src/main.rs:197-203](poly-lsp/src/main.rs#L197)
The server advertises `TextDocumentSyncKind::FULL`, and `did_change` takes
`params.content_changes.first()` and treats `.text` as the whole document. That is only
valid for full sync. If a client ever sends incremental ranges (e.g. capability
negotiation differs), `.text` is a *fragment* and `update_file` replaces the whole
document with the fragment, silently destroying the buffer. *Fix:* assert/handle the
sync kind explicitly, or implement incremental application.

**M2. Virtual files written to disk are never cleaned up and pollute the user's workspace.**
[poly-lsp/src/delegator.rs:183-190](poly-lsp/src/delegator.rs#L183)
`sync_open` writes `*.virtual.rs` / `*.virtual.py` next to the real `.poly` file so
`pylsp` can see physical files. These files are created but never deleted, are not in a
temp directory, and become stale the moment the user edits the buffer (only `didOpen`
writes them — `did_change` never rewrites them). *Why it matters:* leftover, stale,
possibly version-control-tracked junk files; and delegated diagnostics/positions can be
computed against an out-of-date on-disk copy. *Fix:* write to a temp directory, rewrite
on every change, and clean up on `didClose`/`shutdown`.

**M3. Symbol/shadow indexes are global by name, not scoped — name collisions across files merge silently.**
[poly-lsp/src/symbol_table.rs:131-143](poly-lsp/src/symbol_table.rs#L131),
[poly-lsp/src/shadow_indexer.rs:128](poly-lsp/src/shadow_indexer.rs#L128)
`SymbolTable` keys on bare function name (`name_to_id`), so two files each defining
`process` collapse into one `SymbolInfo` with mixed implementations. `ShadowIndex`
`signatures` is `HashMap<String, ShadowSignature>`, so a `process` in file A is
overwritten by `process` in file B — and `clear_for_uri`
([poly-lsp/src/shadow_indexer.rs:84](poly-lsp/src/shadow_indexer.rs#L84)) is an
acknowledged no-op (`true // For now, keep all`). *Why it matters:* go-to-definition and
hover will jump to the wrong file in any multi-file workspace. *Fix:* key shadow
signatures by `(uri, name)` and store the URI in `ShadowSignature`; consider
`(uri, name)` scoping in `SymbolTable` too.

**M4. `shutdown` does not terminate child processes.**
[poly-lsp/src/main.rs:153-155](poly-lsp/src/main.rs#L155)
`shutdown` is `Ok(())` and does nothing. The spawned `rust-analyzer` and `pylsp`
children are never sent an LSP `shutdown`/`exit` and the `Child` handles are owned by
`ChildServer` structs that are dropped only when the process ends. *Why it matters:*
orphaned child processes can survive editor restarts and leak memory/CPU. *Fix:* send
LSP `shutdown` + `exit`, then `kill`/`wait` the children in the `shutdown` handler.

**M5. `did_change` debounce uses `Instant` equality as a generation token — fragile and panic-prone in theory.**
[poly-lsp/src/main.rs:225-248](poly-lsp/src/main.rs#L225)
The debounce stores `Some(Instant::now())` and the spawned task checks `t == now`. This
works, but `Instant` equality as a "did anything newer arrive" check is an implicit
contract; two changes in the same instant (possible on coarse clocks) would both think
they are current. *Why it matters:* duplicate full scans / racey diagnostics. *Fix:*
use a monotonic `AtomicU64` generation counter instead of `Instant` identity.

**M6. `references` returns the call sites but never delegates to child servers, while `goto_definition` does.**
[poly-lsp/src/main.rs:561-600](poly-lsp/src/main.rs#L561)
`references` only consults the `SymbolTable`; it never falls back to the child LSP for
intra-block local references (the way `goto_definition` does at
[poly-lsp/src/main.rs:461](poly-lsp/src/main.rs#L461)). The `Delegator::augment_references`
machinery ([poly-lsp/src/delegator.rs:324](poly-lsp/src/delegator.rs#L324)) exists
precisely for this but is dead code. *Why it matters:* find-references on a
block-local variable returns nothing. *Fix:* wire `references` through
`request_with_fallback`/`augment_references`.

**M7. `String::replace(".poly", ...)` in `virtual_uri` replaces every occurrence, not just the suffix.**
[poly-lsp/src/virtual_fs.rs:128-130](poly-lsp/src/virtual_fs.rs#L128)
A path like `file:///my.poly.project/a.poly` becomes
`file:///my.virtual.rs.project/a.virtual.rs`. The `ends_with(".poly")` guard ensures
the suffix is `.poly`, but `replace` still rewrites the earlier occurrence. *Fix:* use
`uri_str.strip_suffix(".poly")` and append.

### Low

**L1. Per-line regex recompilation in the tokenizer.**
[poly-lsp/src/semantic_tokens.rs:209](poly-lsp/src/semantic_tokens.rs#L209),
[poly-lsp/src/semantic_tokens.rs:222](poly-lsp/src/semantic_tokens.rs#L222),
[poly-lsp/src/semantic_tokens.rs:291](poly-lsp/src/semantic_tokens.rs#L291)
`Regex::new(...)` is called inside `tokenize_line`/`tokenize_content`, i.e. once per
line and once per pattern per token. Regex compilation is expensive; this should be
hoisted into `PolyTokenizer::new` (compiled once, like `ShadowIndex` already does).

**L2. Extensive `eprintln!` debug logging left in production paths.**
[poly-lsp/src/type_graph.rs:72](poly-lsp/src/type_graph.rs#L72),
[poly-lsp/src/type_graph.rs:323-345](poly-lsp/src/type_graph.rs#L323),
[poly-lsp/src/delegator.rs:49](poly-lsp/src/delegator.rs#L49), and the per-request
`client.log_message(MessageType::INFO, ...)` calls throughout `goto_definition`. The
`[PY-DEBUG]` block prints every child node on every scan. The crate already depends on
`log`/`env_logger` ([poly-lsp/Cargo.toml:14](poly-lsp/Cargo.toml#L14)); use `log::debug!`
behind a level filter instead. The verbose INFO `log_message` calls also spam the
editor's output channel.

**L3. `#![allow(dead_code, unused_imports, unused_variables)]` blanket-suppresses warnings.**
[poly-lsp/src/main.rs:2](poly-lsp/src/main.rs#L2)
This hides genuine issues — e.g. the unused `Delegator::request_with_fallback` family
(M6), unused `uri`/`position` parameters in `fallback_*`, and the no-op `clear_for_uri`.
*Fix:* remove the blanket allow and address warnings (or scope `allow` narrowly).

**L4. `detect_syntax_regions` recompiles its regex sets on every `update_file`.**
[poly-lsp/src/virtual_fs.rs:197-205](poly-lsp/src/virtual_fs.rs#L197)
The pattern lists are compiled per call. Use `once_cell`/`lazy_static` to compile once.

**L5. `interface_regex` and `type_regex` in `scan_file` are compiled on every scan and `.unwrap()`ed.**
[poly-lsp/src/type_graph.rs:69-70](poly-lsp/src/type_graph.rs#L69),
[poly-lsp/src/type_graph.rs:79-81](poly-lsp/src/type_graph.rs#L79)
Compile-once via a static; the `unwrap` on a literal pattern is acceptable but moving it
to a `OnceLock` removes the repeated cost.

**L6. `find_line_number` is O(n) per match, making shadow scan O(n·matches).**
[poly-lsp/src/shadow_indexer.rs:301-303](poly-lsp/src/shadow_indexer.rs#L301)
`content[..offset].matches('\n').count()` rescans the prefix for every signature. For
the advertised <5ms budget on large files this can regress; precompute a line-start
offset table once per scan.

**L7. `params_to_typescript` discards real parameter names, emitting `arg0`, `arg1`.**
[poly-lsp/src/sidecar_generator.rs:162-176](poly-lsp/src/sidecar_generator.rs#L162)
Generated `.d.ts` signatures lose parameter names, degrading TS hover/completion
quality. The shadow signatures only keep types ([poly-lsp/src/shadow_indexer.rs:251](poly-lsp/src/shadow_indexer.rs#L251)
extracts the part *after* the colon), so the name is lost upstream. *Fix:* keep both
name and type in `ShadowSignature::params`.

## Strengths

- **Clean conceptual layering.** The virtual-FS / shadow-index / type-graph / sidecar
  separation is genuinely well-conceived: each module has a single, well-named
  responsibility, and the two-phase (fast regex / slow Tree-sitter) indexing strategy
  is a sound, professional design for IDE responsiveness.
- **Coordinate remapping is consistently applied.** `map_to_real`/`map_to_virtual` are
  used uniformly when delegating to and receiving from child servers, including for
  hover ranges and diagnostic line numbers — the hard part of an embedded-language LSP.
- **Per-file incremental clearing.** `clear_for_file` on both `TypeGraph` and
  `SymbolTable` correctly preserves other files' analysis instead of nuking global
  state on every keystroke.
- **Reasonable test coverage** in `shadow_indexer`, `semantic_tokens`, `type_graph`,
  and `sidecar_generator`, including a performance assertion for the shadow scan.
- **The `Delegator` request/response correlation** via `DashMap<id, oneshot::Sender>`
  plus a dedicated reader task is the right pattern for multiplexing a child LSP.
- **Idempotent sidecar writes** — `last_generated` content hashing avoids redundant
  disk writes.

## Recommendations

Prioritized, actionable:

1. **Harden the wire codec (C1, H5).** Cap `Content-Length` in `read_message`; normalize
   JSON-RPC IDs to strings. This is small, isolated, and removes a process-kill vector.
2. **Eliminate panics in the Tree-sitter scan (C2).** Index captures by name, replace
   every `unwrap` with `match`/`?`, return early on parse failure. Scanning untrusted
   in-progress source must never abort a handler.
3. **Fix UTF-16/byte column handling (C3).** Add one shared `utf16_col_to_byte_offset`
   helper and route all three word-extraction sites through it. Non-ASCII content
   currently panics core features.
4. **Add timeouts and per-server stdin locks to the `Delegator` (H3, H4).** Wrap child
   awaits in `tokio::time::timeout`; give each `ChildServer` its own stdin mutex so one
   slow child cannot wedge the others.
5. **Move all blocking FS I/O off the executor (H1, M2).** Switch to `tokio::fs` /
   `spawn_blocking`; write virtual files into a temp dir, rewrite on `did_change`, and
   clean up on `didClose`/`shutdown`.
6. **Add the virtual-URI reverse index (H2)** in `VirtualFileManager` to make
   diagnostic remapping O(1).
7. **Scope symbol/shadow indexes by URI (M3)** and implement a real `clear_for_uri`;
   otherwise multi-file workspaces produce wrong navigation results.
8. **Implement `shutdown` properly (M4)** — terminate child processes.
9. **Either wire up or delete the `request_with_fallback` middleware (M6, L3).** Right
   now it is dead code that suggests `references` should delegate but does not.
10. **Compile all regexes once (L1, L4, L5, L6)** via `OnceLock`/`lazy_static`, and
    replace `eprintln!`/verbose `log_message` with leveled `log` macros (L2).
11. **Remove the blanket `#![allow(...)]` (L3)** and address the surfaced warnings.
12. **Preserve parameter names through the shadow signature → sidecar pipeline (L7)** for
    higher-quality generated `.d.ts`.
```

