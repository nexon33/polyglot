# Android Target Support for Poly

## Overview

Add `aarch64-linux-android` as a compilation target, enabling .poly files to generate:
1. **Native Android binary** (from Rust blocks) — runs in Termux or as native Android app
2. **Web frontend** (from JS/HTML/CSS blocks) — runs in WebView or browser

One .poly file → both native backend AND web UI.

## Use Case: LoRa USB Bridge

```poly
#[rs]
fn usb_bridge(port: &str) -> SerialPort {
    // Native USB/serial — compiles to Android aarch64
    // Uses rusb/nusb crates, or /dev/ttyUSB0 directly
}

#[js]
export const App = () => {
    // Chat UI — runs in WebView or browser
    const ws = new WebSocket("ws://localhost:8765");
    // ...
}
```

**Output:**
- `target/android/bridge` — static aarch64 binary for Termux
- `target/android/web/` — bundled web app for WebView

## Implementation Plan

### Phase 1: Target Types

**File: `src/types.rs`**
```rust
#[derive(Clone, Copy, Default, PartialEq)]
pub enum CompileTarget {
    #[default]
    Wasm32Wasi,
    Wasm32Unknown,
    Host,           // WASM with Node.js host imports
    // NEW:
    Aarch64Android, // Native Android/Termux binary
    X86_64Linux,    // Native Linux binary (for testing)
    X86_64Windows,  // Native Windows binary
}
```

### Phase 2: CLI Updates

**File: `src/main.rs`**

Add `--target android` option:
```rust
#[arg(long, short, value_parser = ["browser", "host", "android", "linux", "windows"], default_value = "browser")]
target: String,
```

### Phase 3: Native Compilation

**File: `src/languages/rust/mod.rs`**

When target is native:
1. Skip WASM-specific wrappers (`_start`, memory management exports)
2. Use appropriate rustc target triple
3. Build with `cargo build --target=aarch64-linux-android --release`
4. Requires Android NDK toolchain installed

```rust
impl Language for Rust {
    fn compile(&self, source: &str, opts: &CompileOptions) -> Result<Vec<u8>> {
        match opts.target {
            CompileTarget::Aarch64Android => self.compile_native(source, opts, "aarch64-linux-android"),
            CompileTarget::X86_64Linux => self.compile_native(source, opts, "x86_64-unknown-linux-gnu"),
            _ => self.compile_wasm(source, opts),
        }
    }
    
    fn compile_native(&self, source: &str, opts: &CompileOptions, target_triple: &str) -> Result<Vec<u8>> {
        // Create Cargo.toml for [[bin]] instead of [lib] cdylib
        // Don't inject WASM-specific wrappers
        // Build with cargo build --target=<triple> --release
        // Return the binary bytes (or just write to output path)
    }
}
```

### Phase 4: Split Output

**File: `src/compiler.rs`**

When target is native, generate two outputs:
1. Native binary from Rust blocks
2. Web bundle from JS/HTML/CSS blocks (existing logic)

```rust
pub struct CompileOutput {
    pub native_binary: Option<Vec<u8>>,
    pub native_path: Option<PathBuf>,
    pub wasm_module: Option<Vec<u8>>,
    pub web_bundle: Option<WebBundle>,
}

pub struct WebBundle {
    pub html: String,
    pub js: String,
    pub css: String,
}
```

### Phase 5: Android NDK Integration

**Requirements:**
- Android NDK installed
- `aarch64-linux-android` target added to rustup
- Linker configured in `.cargo/config.toml`

**Auto-detection:**
```rust
fn find_android_ndk() -> Option<PathBuf> {
    // Check ANDROID_NDK_HOME
    // Check common paths: ~/Android/Sdk/ndk/*, C:\Android\ndk\*
    // Return path to toolchain
}

fn setup_android_linker(ndk_path: &Path, temp_dir: &Path) -> Result<()> {
    // Write .cargo/config.toml with linker path
    let config = format!(r#"
[target.aarch64-linux-android]
linker = "{}/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang"
"#, ndk_path.display());
    fs::write(temp_dir.join(".cargo/config.toml"), config)?;
    Ok(())
}
```

## Dependencies for Android Target

Native USB access options:
1. **rusb** — libusb wrapper, requires libusb compiled for Android
2. **nusb** — pure Rust USB, may work better on Android
3. **Direct serial** — open `/dev/ttyUSB0` as file when kernel driver loaded

For the LoRa bridge specifically:
- When CH341 kernel driver is loaded, device appears as `/dev/ttyUSB0`
- Can use standard `serialport` crate or raw `std::fs::File`

## Example .poly File

```poly
#[interface]
trait Bridge {
    fn send(data: &[u8]) -> Result<(), String>;
    fn recv() -> Result<Vec<u8>, String>;
}

#[rs]
use std::io::{Read, Write};
use std::fs::OpenOptions;

static mut PORT: Option<std::fs::File> = None;

fn init_serial(path: &str) -> Result<(), String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    unsafe { PORT = Some(file); }
    Ok(())
}

fn send(data: &[u8]) -> Result<(), String> {
    unsafe {
        PORT.as_mut()
            .ok_or("Port not initialized")?
            .write_all(data)
            .map_err(|e| e.to_string())
    }
}

fn recv() -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; 1024];
    unsafe {
        let n = PORT.as_mut()
            .ok_or("Port not initialized")?
            .read(&mut buf)
            .map_err(|e| e.to_string())?;
        buf.truncate(n);
    }
    Ok(buf)
}

fn main() {
    init_serial("/dev/ttyUSB0").expect("Failed to open serial port");
    println!("LoRa bridge ready");
    
    // Start WebSocket server for web UI
    // ...
}

#[js]
import { useState, useEffect } from 'react';

export const App = () => {
    const [messages, setMessages] = useState([]);
    const [ws, setWs] = useState(null);
    
    useEffect(() => {
        const socket = new WebSocket('ws://localhost:8765');
        socket.onmessage = (e) => {
            setMessages(prev => [...prev, JSON.parse(e.data)]);
        };
        setWs(socket);
        return () => socket.close();
    }, []);
    
    const send = (text) => {
        ws?.send(JSON.stringify({ type: 'message', text }));
    };
    
    return (
        <div className="chat">
            {messages.map((m, i) => <div key={i}>{m.text}</div>)}
            <input onKeyDown={e => e.key === 'Enter' && send(e.target.value)} />
        </div>
    );
};

#[html]
<!DOCTYPE html>
<html>
<head><title>LoRa Chat</title></head>
<body><div id="root"></div></body>
</html>
```

## Build Commands

```bash
# Build for Android/Termux
poly build bridge.poly --target android

# Output:
#   target/android/bridge           <- native aarch64 binary
#   target/android/web/index.html   <- web UI bundle

# Copy to Android device
adb push target/android/bridge /data/local/tmp/
adb push target/android/web/ /sdcard/lora-chat/

# Run in Termux
./bridge

# Open web UI in browser
# Navigate to file:///sdcard/lora-chat/index.html
# Or serve via bridge's built-in HTTP server
```

## Status

- [ ] Phase 1: Target types
- [ ] Phase 2: CLI updates
- [ ] Phase 3: Native compilation
- [ ] Phase 4: Split output
- [ ] Phase 5: Android NDK integration
- [ ] Phase 6: Testing on actual Android device
