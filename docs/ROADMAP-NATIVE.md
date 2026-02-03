# Polyglot Native Target Roadmap

> **Goal:** Extend Polyglot to compile server-side applications with full system access, enabling OpenClaw conversion.

## Executive Summary

| Phase | Duration | Outcome |
|-------|----------|---------|
| Phase 1: WASI Foundation | 2-3 months | WASM with filesystem, env, args |
| Phase 2: WASI Networking | 2-3 months | TCP/UDP sockets, HTTP |
| Phase 3: Native Backend | 4-6 months | Direct native compilation via Cranelift |
| Phase 4: Node.js Compat | 4-6 months | fs, path, crypto, child_process APIs |
| Phase 5: Async Runtime | 2-3 months | Event loop, async/await, timers |
| Phase 6: Package System | 2-3 months | Dependency resolution, npm interop |
| **Total** | **16-24 months** | Full server-side capability |

---

## Phase 1: WASI Foundation (Months 1-3)

**Objective:** Run Polyglot WASM in Wasmtime/Wasmer with system access.

### 1.1 WASI Preview 1 Integration
```
Current:  .poly → WASM (browser only)
Target:   .poly → WASM-WASI → runs in Wasmtime with FS access
```

**Tasks:**
- [ ] Add `wasi-common` crate dependency
- [ ] Implement WASI imports in generated WASM
- [ ] Add `--target wasi` flag to compiler
- [ ] File system access: `fd_read`, `fd_write`, `path_open`
- [ ] Environment: `environ_get`, `args_get`
- [ ] Clock: `clock_time_get`

**Deliverable:** `polyglot build app.poly --target wasi` produces WASM runnable with:
```bash
wasmtime run app.wasm --dir=.
```

### 1.2 WASI Preview 2 (Component Model)
- [ ] Upgrade to `wit-bindgen` for interface types
- [ ] Support `wasi:filesystem`, `wasi:cli`, `wasi:random`
- [ ] Component composition for multi-module apps

**Key Files to Create:**
```
src/targets/
  mod.rs
  wasm_browser.rs    # Existing
  wasm_wasi.rs       # NEW
  native.rs          # Phase 3
```

---

## Phase 2: WASI Networking (Months 4-6)

**Objective:** TCP/UDP sockets, HTTP client/server capability.

### 2.1 WASI Sockets
- [ ] Implement `wasi:sockets` interface
- [ ] TCP listener: `tcp_create_socket`, `tcp_bind`, `tcp_listen`, `tcp_accept`
- [ ] TCP streams: `tcp_connect`, stream read/write
- [ ] UDP: `udp_create_socket`, `udp_bind`, send/receive

### 2.2 HTTP via WASI-HTTP
- [ ] Implement `wasi:http` incoming/outgoing handlers
- [ ] Request/response types
- [ ] Headers, body streaming

### 2.3 Polyglot Standard Library
Create `#[stdlib]` blocks with high-level APIs:

```poly
#[stdlib:net]
pub fn listen(addr: &str) -> TcpListener;
pub fn connect(addr: &str) -> TcpStream;

#[stdlib:http]
pub fn serve(addr: &str, handler: fn(Request) -> Response);
pub fn fetch(url: &str) -> Response;
```

**Deliverable:** Working HTTP server in Polyglot:
```poly
#[rust]
use stdlib::http::{serve, Request, Response};

fn main() {
    serve("0.0.0.0:8080", |req| {
        Response::ok("Hello from Polyglot!")
    });
}
```

---

## Phase 3: Native Compilation Backend (Months 7-12)

**Objective:** Compile directly to native executables, bypassing WASM.

### 3.1 Backend Selection
**Recommended: Cranelift**
- Same backend as Wasmtime
- Faster compilation than LLVM
- Good enough codegen for servers
- Rust-native (no C++ deps)

Alternative: LLVM (better optimization, slower compile, harder integration)

### 3.2 Native IR Generation
```
Current:  Rust AST → rustc → WASM
Target:   Rust AST → Cranelift IR → native binary
```

**Tasks:**
- [ ] Add `cranelift-codegen`, `cranelift-frontend` crates
- [ ] Implement `NativeBackend` trait
- [ ] Function compilation: Rust functions → Cranelift IR
- [ ] Memory management: stack, heap allocation
- [ ] Calling convention: System V AMD64 / Windows x64
- [ ] Object file emission: ELF (Linux), Mach-O (macOS), PE (Windows)
- [ ] Linking: integrate with system linker or use `lld`

### 3.3 Runtime Library
Native binaries need a runtime for:
- [ ] Memory allocator (use `mimalloc` or system malloc)
- [ ] Panic handling
- [ ] Stack unwinding (optional, can use abort)
- [ ] Entry point (`_start` / `main`)

### 3.4 Native Standard Library
Direct system call wrappers:
- [ ] Linux: syscall interface
- [ ] macOS: libSystem bindings  
- [ ] Windows: Win32 API bindings

**Deliverable:** `polyglot build app.poly --target native` produces executable.

---

## Phase 4: Node.js API Compatibility (Months 13-18)

**Objective:** Implement Node.js-compatible APIs for OpenClaw migration.

### 4.1 Core Modules

| Module | Priority | Complexity | Notes |
|--------|----------|------------|-------|
| `fs` | 🔴 Critical | Medium | OpenClaw config, sessions |
| `path` | 🔴 Critical | Low | Path manipulation |
| `crypto` | 🔴 Critical | High | Use `ring` crate |
| `child_process` | 🔴 Critical | Medium | Shell commands |
| `net` | 🔴 Critical | Medium | TCP sockets |
| `http`/`https` | 🔴 Critical | Medium | HTTP server/client |
| `url` | 🟡 High | Low | URL parsing |
| `buffer` | 🟡 High | Low | Binary data |
| `events` | 🟡 High | Low | EventEmitter |
| `stream` | 🟡 High | Medium | Readable/Writable |
| `os` | 🟢 Medium | Low | System info |
| `util` | 🟢 Medium | Low | Utilities |

### 4.2 Implementation Strategy

**Option A: Pure Polyglot/Rust implementation**
```poly
#[interface]
trait Fs {
    fn read_file(path: &str) -> Result<Vec<u8>, IoError>;
    fn write_file(path: &str, data: &[u8]) -> Result<(), IoError>;
    fn exists(path: &str) -> bool;
    // ...
}

#[rust]
impl Fs for NativeFs {
    fn read_file(path: &str) -> Result<Vec<u8>, IoError> {
        std::fs::read(path).map_err(|e| IoError::from(e))
    }
}
```

**Option B: FFI to actual Node.js (hybrid)**
- Embed V8 or QuickJS for JS interop
- Call into Node.js native modules
- Higher compatibility, more complexity

**Recommendation:** Start with Option A for core modules, use Option B only for complex native modules (Sharp, node-pty).

### 4.3 Async Model
Node.js uses an event loop. Options:
- [ ] Implement Tokio-style async runtime in Polyglot
- [ ] Support `async/await` syntax in Rust blocks
- [ ] Provide `#[async]` block type

```poly
#[async]
async fn handle_request(req: Request) -> Response {
    let data = fs::read_file("config.json").await?;
    let config: Config = json::parse(&data)?;
    Response::json(config)
}
```

---

## Phase 5: Async Runtime (Months 19-21)

**Objective:** Full async/await support with event loop.

### 5.1 Runtime Core
- [ ] Task scheduler (work-stealing or simple queue)
- [ ] I/O reactor (epoll/kqueue/IOCP)
- [ ] Timer wheel for `setTimeout`/`setInterval`
- [ ] Integrate with Tokio or build minimal runtime

### 5.2 Async Standard Library
- [ ] `async fn` support in Polyglot syntax
- [ ] `Promise`-like futures
- [ ] `spawn()` for background tasks
- [ ] Channels for task communication

### 5.3 Event Loop Semantics
Match Node.js event loop phases:
1. Timers
2. I/O callbacks
3. Idle/prepare
4. Poll
5. Check (setImmediate)
6. Close callbacks

---

## Phase 6: Package System (Months 22-24)

**Objective:** Dependency management and npm interop.

### 6.1 Polyglot Package Format
```toml
# poly.toml
[package]
name = "my-app"
version = "1.0.0"

[dependencies]
polyglot-http = "0.1"
polyglot-json = "0.1"

[npm-dependencies]  # Optional npm interop
sharp = "^0.34"
```

### 6.2 Package Registry
- [ ] Design registry API (crates.io-like or custom)
- [ ] Package publishing CLI
- [ ] Version resolution
- [ ] Lock file support

### 6.3 npm Interop (Stretch Goal)
- [ ] Parse `package.json`
- [ ] Call into Node.js native modules via FFI
- [ ] TypeScript type import for interface generation

---

## OpenClaw Migration (Post-Roadmap)

Once all phases complete, OpenClaw migration can begin:

### Migration Strategy
1. **Module-by-module conversion** (recommended)
   - Start with leaf modules (utils, types)
   - Work toward core (gateway, auto-reply)
   
2. **Hybrid operation**
   - Run converted modules alongside TypeScript
   - Gradually shift traffic

### Estimated Migration Timeline
| Module Group | Files | Est. Duration |
|--------------|-------|---------------|
| Utils, Types, Config | ~200 | 1 month |
| Providers (AI APIs) | ~150 | 1 month |
| Channels | ~400 | 2 months |
| Gateway | ~300 | 2 months |
| Auto-reply, Agents | ~300 | 2 months |
| CLI, TUI | ~200 | 1 month |
| Remaining | ~1000 | 3 months |
| **Total** | 2519 | **12 months** |

---

## Immediate Next Steps (This Week)

1. **Create target abstraction layer**
   ```
   src/targets/mod.rs - Target trait
   src/targets/wasm_browser.rs - Current impl
   src/targets/wasm_wasi.rs - New WASI target
   ```

2. **Add WASI dependencies to Cargo.toml**
   ```toml
   wasi = "0.11"
   wasmtime = { version = "19", optional = true }
   ```

3. **Implement minimal WASI filesystem**
   - `fd_read`, `fd_write` for stdin/stdout
   - `path_open` for file access
   - Test with Wasmtime

4. **Create tracking issue/project**
   - GitHub project board
   - Milestone per phase

---

## Resources

- [WASI Specification](https://github.com/WebAssembly/WASI)
- [Cranelift Documentation](https://cranelift.dev/)
- [Wasmtime Embedding](https://docs.wasmtime.dev/)
- [Node.js API Docs](https://nodejs.org/api/)

---

*Document created: 2026-02-03*
*Target completion: 2028-Q1*
