// Host Imports — WASM-to-Node.js bridge functions
//
// These extern functions are imported from the Node.js host at runtime.
// They provide filesystem, networking, and process capabilities to WASM.
//
// This module is only compiled for WASM targets. For native compilation,
// it provides stub types and empty implementations.

#[cfg(target_family = "wasm")]
#[allow(dead_code, unused_imports)]
mod host_imports {

// ============================================================================
// Memory Management
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Allocate memory in the host for returning data
    fn host_alloc(size: usize) -> *mut u8;
    
    /// Free memory allocated by host
    fn host_free(ptr: *mut u8, size: usize);
    
    /// Get the length of data at a host pointer
    fn host_get_len(ptr: *const u8) -> usize;
}

// ============================================================================
// Filesystem
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Read entire file contents
    /// Returns pointer to data in WASM memory, sets len via out param
    fn host_fs_read(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
    
    /// Write data to file (creates or overwrites)
    /// Returns 0 on success, negative on error
    fn host_fs_write(
        path_ptr: *const u8, 
        path_len: usize, 
        data_ptr: *const u8, 
        data_len: usize
    ) -> i32;
    
    /// Append data to file
    fn host_fs_append(
        path_ptr: *const u8, 
        path_len: usize, 
        data_ptr: *const u8, 
        data_len: usize
    ) -> i32;
    
    /// Check if path exists
    fn host_fs_exists(path_ptr: *const u8, path_len: usize) -> i32;
    
    /// Check if path is a directory
    fn host_fs_is_dir(path_ptr: *const u8, path_len: usize) -> i32;
    
    /// Create directory (recursive)
    fn host_fs_mkdir(path_ptr: *const u8, path_len: usize) -> i32;
    
    /// Remove file
    fn host_fs_remove(path_ptr: *const u8, path_len: usize) -> i32;
    
    /// Remove directory (recursive)
    fn host_fs_rmdir(path_ptr: *const u8, path_len: usize) -> i32;
    
    /// List directory contents
    /// Returns JSON array of filenames
    fn host_fs_readdir(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
}

// ============================================================================
// Environment
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Get environment variable
    fn host_env_get(name_ptr: *const u8, name_len: usize, out_len: *mut usize) -> *mut u8;
    
    /// Set environment variable
    fn host_env_set(name_ptr: *const u8, name_len: usize, val_ptr: *const u8, val_len: usize) -> i32;
    
    /// Get current working directory
    fn host_env_cwd(out_len: *mut usize) -> *mut u8;
    
    /// Change current working directory
    fn host_env_chdir(path_ptr: *const u8, path_len: usize) -> i32;
    
    /// Get command line arguments as JSON array
    fn host_env_args(out_len: *mut usize) -> *mut u8;
}

// ============================================================================
// Console
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Print to stdout
    fn host_console_log(msg_ptr: *const u8, msg_len: usize);
    
    /// Print to stderr
    fn host_console_error(msg_ptr: *const u8, msg_len: usize);
    
    /// Read line from stdin
    fn host_console_read_line(out_len: *mut usize) -> *mut u8;
}

// ============================================================================
// Process
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Spawn a child process and wait for completion
    /// Returns exit code, stdout in out_stdout, stderr in out_stderr
    fn host_process_exec(
        cmd_ptr: *const u8,
        cmd_len: usize,
        out_stdout_len: *mut usize,
        out_stderr_len: *mut usize,
        out_stdout: *mut *mut u8,
        out_stderr: *mut *mut u8,
    ) -> i32;
    
    /// Exit the process with given code
    fn host_process_exit(code: i32) -> !;
}

// ============================================================================
// Filesystem Extended (stat, rename, watch, copy)
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Get file/directory stats as JSON
    /// Returns: {"size":N,"mtime":N,"atime":N,"ctime":N,"isFile":bool,"isDir":bool,"isSymlink":bool,"mode":N}
    fn host_fs_stat(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
    
    /// Rename/move file or directory
    fn host_fs_rename(
        old_ptr: *const u8, old_len: usize,
        new_ptr: *const u8, new_len: usize
    ) -> i32;
    
    /// Copy file
    fn host_fs_copy(
        src_ptr: *const u8, src_len: usize,
        dst_ptr: *const u8, dst_len: usize
    ) -> i32;
    
    /// Create symlink
    fn host_fs_symlink(
        target_ptr: *const u8, target_len: usize,
        link_ptr: *const u8, link_len: usize
    ) -> i32;
    
    /// Read symlink target
    fn host_fs_readlink(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
    
    /// Watch a path for changes (returns watch handle)
    fn host_fs_watch(path_ptr: *const u8, path_len: usize) -> i32;
    
    /// Poll watch for events (returns JSON array of events, empty if none)
    fn host_fs_watch_poll(handle: i32, out_len: *mut usize) -> *mut u8;
    
    /// Close a watch handle
    fn host_fs_watch_close(handle: i32) -> i32;
}

// ============================================================================
// Networking — TCP
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Connect to TCP server, returns socket handle (>0) or error (<0)
    fn host_tcp_connect(host_ptr: *const u8, host_len: usize, port: u16) -> i32;
    
    /// Start TCP server listening, returns server handle (>0) or error (<0)
    fn host_tcp_listen(host_ptr: *const u8, host_len: usize, port: u16) -> i32;
    
    /// Accept connection on server (blocking), returns socket handle
    fn host_tcp_accept(server_handle: i32) -> i32;
    
    /// Accept connection non-blocking: returns handle (>0), 0 if would block, <0 on error
    fn host_tcp_accept_nonblocking(server_handle: i32) -> i32;
    
    /// Read from socket (blocking), returns bytes read (0 = closed, <0 = error)
    fn host_tcp_read(handle: i32, buf_ptr: *mut u8, buf_len: usize) -> i32;
    
    /// Try read non-blocking: returns bytes read, 0 if would block, -1 if closed, -2 on error
    fn host_tcp_try_read(handle: i32, buf_ptr: *mut u8, buf_len: usize) -> i32;
    
    /// Check if socket has data ready to read: 1 = yes, 0 = no, <0 = error/closed
    fn host_tcp_readable(handle: i32) -> i32;
    
    /// Write to socket, returns bytes written (<0 = error)
    fn host_tcp_write(handle: i32, data_ptr: *const u8, data_len: usize) -> i32;
    
    /// Close socket or server
    fn host_tcp_close(handle: i32) -> i32;
    
    /// Get local address of socket as "host:port"
    fn host_tcp_local_addr(handle: i32, out_len: *mut usize) -> *mut u8;
    
    /// Get remote address of socket as "host:port"
    fn host_tcp_remote_addr(handle: i32, out_len: *mut usize) -> *mut u8;
    
    /// Set socket option (e.g., "nodelay", "keepalive")
    fn host_tcp_set_opt(handle: i32, opt_ptr: *const u8, opt_len: usize, value: i32) -> i32;
}

// ============================================================================
// Networking — HTTP
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Perform HTTP request (blocking)
    /// method: GET, POST, PUT, DELETE, etc.
    /// headers_json: JSON object {"Header-Name": "value", ...} or null (ptr=0)
    /// body: request body bytes or null (ptr=0)
    /// Returns response handle
    fn host_http_request(
        method_ptr: *const u8, method_len: usize,
        url_ptr: *const u8, url_len: usize,
        headers_ptr: *const u8, headers_len: usize,
        body_ptr: *const u8, body_len: usize
    ) -> i32;
    
    /// Get HTTP response status code
    fn host_http_status(handle: i32) -> i32;
    
    /// Get HTTP response headers as JSON object
    fn host_http_headers(handle: i32, out_len: *mut usize) -> *mut u8;
    
    /// Get HTTP response body
    fn host_http_body(handle: i32, out_len: *mut usize) -> *mut u8;
    
    /// Free HTTP response
    fn host_http_free(handle: i32) -> i32;
}

// ============================================================================
// Async — Event Loop & Futures
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Schedule a timer, returns timer handle
    fn host_timer_set(ms: u32) -> i32;
    
    /// Cancel a timer
    fn host_timer_cancel(handle: i32) -> i32;
    
    /// Poll for next ready event (non-blocking)
    /// Returns JSON: {"type":"timer"|"tcp_read"|"tcp_connect"|"watch", "handle":N, "data":...}
    /// Returns null pointer if no events ready
    fn host_poll(out_len: *mut usize) -> *mut u8;
    
    /// Block until any event is ready or timeout (ms, 0=forever)
    /// Returns number of ready events
    fn host_wait(timeout_ms: u32) -> i32;
    
    /// Register interest in socket readability
    fn host_poll_read(handle: i32) -> i32;
    
    /// Register interest in socket writability
    fn host_poll_write(handle: i32) -> i32;
    
    /// Unregister poll interest
    fn host_poll_remove(handle: i32) -> i32;
    
    /// Get current timestamp in milliseconds
    fn host_time_now() -> u64;
    
    /// Sleep for milliseconds (blocking)
    fn host_sleep(ms: u32);
}

// ============================================================================
// Streams
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    /// Open file as stream, mode: "r", "w", "a", "r+", "w+", "a+"
    /// Returns stream handle
    fn host_stream_open(path_ptr: *const u8, path_len: usize, mode_ptr: *const u8, mode_len: usize) -> i32;
    
    /// Read chunk from stream (up to buf_len bytes)
    /// Returns bytes read, 0 = EOF, <0 = error
    fn host_stream_read(handle: i32, buf_ptr: *mut u8, buf_len: usize) -> i32;
    
    /// Write chunk to stream
    /// Returns bytes written, <0 = error
    fn host_stream_write(handle: i32, data_ptr: *const u8, data_len: usize) -> i32;
    
    /// Seek in stream (whence: 0=SET, 1=CUR, 2=END)
    /// Returns new position, <0 = error
    fn host_stream_seek(handle: i32, offset: i64, whence: i32) -> i64;
    
    /// Get current position
    fn host_stream_tell(handle: i32) -> i64;
    
    /// Flush stream
    fn host_stream_flush(handle: i32) -> i32;
    
    /// Close stream
    fn host_stream_close(handle: i32) -> i32;
    
    /// Pipe: create connected read/write stream pair
    /// Returns read handle, write handle via out param
    fn host_pipe_create(out_write: *mut i32) -> i32;
}

// ============================================================================
// High-Level Rust API
// ============================================================================

/// Result type for host operations
pub type HostResult<T> = Result<T, HostError>;

#[derive(Debug, Clone)]
pub struct HostError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostError {}: {}", self.code, self.message)
    }
}

impl std::error::Error for HostError {}

pub mod fs {
    use super::*;

    /// Read entire file as bytes
    pub fn read(path: &str) -> HostResult<Vec<u8>> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_fs_read(path.as_ptr(), path.len(), &mut len);
            if ptr.is_null() {
                return Err(HostError { code: -1, message: format!("Failed to read: {}", path) });
            }
            let data = std::slice::from_raw_parts(ptr, len).to_vec();
            host_free(ptr, len);
            Ok(data)
        }
    }

    /// Read file as UTF-8 string
    pub fn read_to_string(path: &str) -> HostResult<String> {
        let bytes = read(path)?;
        String::from_utf8(bytes).map_err(|e| HostError { 
            code: -2, 
            message: format!("UTF-8 error: {}", e) 
        })
    }

    /// Write bytes to file
    pub fn write(path: &str, data: &[u8]) -> HostResult<()> {
        unsafe {
            let result = host_fs_write(path.as_ptr(), path.len(), data.as_ptr(), data.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to write: {}", path) });
            }
            Ok(())
        }
    }

    /// Write string to file
    pub fn write_str(path: &str, content: &str) -> HostResult<()> {
        write(path, content.as_bytes())
    }

    /// Append bytes to file
    pub fn append(path: &str, data: &[u8]) -> HostResult<()> {
        unsafe {
            let result = host_fs_append(path.as_ptr(), path.len(), data.as_ptr(), data.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to append: {}", path) });
            }
            Ok(())
        }
    }

    /// Check if path exists
    pub fn exists(path: &str) -> bool {
        unsafe { host_fs_exists(path.as_ptr(), path.len()) == 1 }
    }

    /// Check if path is a directory
    pub fn is_dir(path: &str) -> bool {
        unsafe { host_fs_is_dir(path.as_ptr(), path.len()) == 1 }
    }

    /// Create directory (and parents)
    pub fn mkdir(path: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_mkdir(path.as_ptr(), path.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to mkdir: {}", path) });
            }
            Ok(())
        }
    }

    /// Remove file
    pub fn remove(path: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_remove(path.as_ptr(), path.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to remove: {}", path) });
            }
            Ok(())
        }
    }

    /// List directory contents
    pub fn read_dir(path: &str) -> HostResult<Vec<String>> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_fs_readdir(path.as_ptr(), path.len(), &mut len);
            if ptr.is_null() {
                return Err(HostError { code: -1, message: format!("Failed to readdir: {}", path) });
            }
            let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?;
            host_free(ptr, len);
            // Parse JSON array - simple implementation
            let entries: Vec<String> = json
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().trim_matches('"').to_string())
                .collect();
            Ok(entries)
        }
    }
    
    // ========================================================================
    // Extended Filesystem Functions
    // ========================================================================
    
    /// File/directory metadata
    #[derive(Debug, Clone)]
    pub struct FileStat {
        pub size: u64,
        pub mtime: u64,
        pub atime: u64,
        pub ctime: u64,
        pub is_file: bool,
        pub is_dir: bool,
        pub is_symlink: bool,
        pub mode: u32,
    }
    
    /// File watch event
    #[derive(Debug, Clone)]
    pub struct WatchEvent {
        pub kind: String,
        pub path: String,
    }
    
    /// File watcher handle
    pub struct Watcher {
        handle: i32,
    }
    
    /// Get file/directory stats
    pub fn stat(path: &str) -> HostResult<FileStat> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_fs_stat(path.as_ptr(), path.len(), &mut len);
            if ptr.is_null() {
                return Err(HostError { code: -1, message: format!("Failed to stat: {}", path) });
            }
            let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?;
            host_free(ptr, len);
            
            // Simple JSON parsing
            fn get_num(json: &str, key: &str) -> u64 {
                let pattern = format!("\"{}\":", key);
                if let Some(start) = json.find(&pattern) {
                    let rest = &json[start + pattern.len()..];
                    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                    rest[..end].trim().parse().unwrap_or(0)
                } else { 0 }
            }
            fn get_bool(json: &str, key: &str) -> bool {
                let pattern = format!("\"{}\":true", key);
                json.contains(&pattern)
            }
            
            Ok(FileStat {
                size: get_num(json, "size"),
                mtime: get_num(json, "mtime"),
                atime: get_num(json, "atime"),
                ctime: get_num(json, "ctime"),
                is_file: get_bool(json, "isFile"),
                is_dir: get_bool(json, "isDir"),
                is_symlink: get_bool(json, "isSymlink"),
                mode: get_num(json, "mode") as u32,
            })
        }
    }
    
    /// Rename/move file or directory
    pub fn rename(old: &str, new: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_rename(old.as_ptr(), old.len(), new.as_ptr(), new.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to rename {} -> {}", old, new) });
            }
            Ok(())
        }
    }
    
    /// Copy file
    pub fn copy(src: &str, dst: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_copy(src.as_ptr(), src.len(), dst.as_ptr(), dst.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to copy {} -> {}", src, dst) });
            }
            Ok(())
        }
    }
    
    /// Create symlink
    pub fn symlink(target: &str, link: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_symlink(target.as_ptr(), target.len(), link.as_ptr(), link.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to symlink {} -> {}", link, target) });
            }
            Ok(())
        }
    }
    
    /// Read symlink target
    pub fn readlink(path: &str) -> HostResult<String> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_fs_readlink(path.as_ptr(), path.len(), &mut len);
            if ptr.is_null() {
                return Err(HostError { code: -1, message: format!("Failed to readlink: {}", path) });
            }
            let target = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?
                .to_string();
            host_free(ptr, len);
            Ok(target)
        }
    }
    
    /// Watch a path for changes
    pub fn watch(path: &str) -> HostResult<Watcher> {
        unsafe {
            let handle = host_fs_watch(path.as_ptr(), path.len());
            if handle < 0 {
                return Err(HostError { code: handle, message: format!("Failed to watch: {}", path) });
            }
            Ok(Watcher { handle })
        }
    }
    
    impl Watcher {
        /// Poll for events (non-blocking)
        pub fn poll(&self) -> Vec<WatchEvent> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_fs_watch_poll(self.handle, &mut len);
                if ptr.is_null() || len == 0 {
                    return Vec::new();
                }
                let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap_or("[]");
                host_free(ptr, len);
                
                // Parse watch events
                let mut events = Vec::new();
                for part in json.split("},") {
                    fn extract(json: &str, key: &str) -> Option<String> {
                        let pattern = format!("\"{}\":\"", key);
                        if let Some(start) = json.find(&pattern) {
                            let rest = &json[start + pattern.len()..];
                            if let Some(end) = rest.find('"') {
                                return Some(rest[..end].to_string());
                            }
                        }
                        None
                    }
                    let kind = extract(part, "kind").unwrap_or_default();
                    let path = extract(part, "path").unwrap_or_default();
                    if !kind.is_empty() {
                        events.push(WatchEvent { kind, path });
                    }
                }
                events
            }
        }
        
        /// Close the watcher
        pub fn close(self) {
            unsafe { host_fs_watch_close(self.handle); }
        }
    }
}

pub mod env {
    use super::*;

    /// Get environment variable
    pub fn get(name: &str) -> Option<String> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_env_get(name.as_ptr(), name.len(), &mut len);
            if ptr.is_null() || len == 0 {
                return None;
            }
            let val = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .ok()?
                .to_string();
            host_free(ptr, len);
            Some(val)
        }
    }

    /// Set environment variable
    pub fn set(name: &str, value: &str) -> HostResult<()> {
        unsafe {
            let result = host_env_set(name.as_ptr(), name.len(), value.as_ptr(), value.len());
            if result < 0 {
                return Err(HostError { code: result, message: "Failed to set env".to_string() });
            }
            Ok(())
        }
    }

    /// Get current working directory
    pub fn cwd() -> HostResult<String> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_env_cwd(&mut len);
            if ptr.is_null() {
                return Err(HostError { code: -1, message: "Failed to get cwd".to_string() });
            }
            let path = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?
                .to_string();
            host_free(ptr, len);
            Ok(path)
        }
    }
}

pub mod console {
    use super::*;

    /// Print to stdout with newline
    pub fn log(msg: &str) {
        unsafe { host_console_log(msg.as_ptr(), msg.len()); }
    }

    /// Print to stderr with newline  
    pub fn error(msg: &str) {
        unsafe { host_console_error(msg.as_ptr(), msg.len()); }
    }
}

pub mod process {
    use super::*;

    /// Execute a command and return (exit_code, stdout, stderr)
    pub fn exec(cmd: &str) -> HostResult<(i32, String, String)> {
        unsafe {
            let mut stdout_len: usize = 0;
            let mut stderr_len: usize = 0;
            let mut stdout_ptr: *mut u8 = std::ptr::null_mut();
            let mut stderr_ptr: *mut u8 = std::ptr::null_mut();
            
            let code = host_process_exec(
                cmd.as_ptr(),
                cmd.len(),
                &mut stdout_len,
                &mut stderr_len,
                &mut stdout_ptr,
                &mut stderr_ptr,
            );
            
            let stdout = if !stdout_ptr.is_null() && stdout_len > 0 {
                let s = std::str::from_utf8(std::slice::from_raw_parts(stdout_ptr, stdout_len))
                    .unwrap_or("")
                    .to_string();
                host_free(stdout_ptr, stdout_len);
                s
            } else {
                String::new()
            };
            
            let stderr = if !stderr_ptr.is_null() && stderr_len > 0 {
                let s = std::str::from_utf8(std::slice::from_raw_parts(stderr_ptr, stderr_len))
                    .unwrap_or("")
                    .to_string();
                host_free(stderr_ptr, stderr_len);
                s
            } else {
                String::new()
            };
            
            Ok((code, stdout, stderr))
        }
    }

    /// Exit the process
    pub fn exit(code: i32) -> ! {
        unsafe { host_process_exit(code) }
    }
}

// Extended fs types and functions are in the fs module above

// ============================================================================
// TCP Networking API
// ============================================================================

pub mod tcp {
    use super::*;
    
    /// TCP socket
    pub struct TcpStream {
        handle: i32,
    }
    
    /// TCP server
    pub struct TcpListener {
        handle: i32,
    }
    
    impl TcpStream {
        /// Connect to a TCP server
        pub fn connect(host: &str, port: u16) -> HostResult<TcpStream> {
            unsafe {
                let handle = host_tcp_connect(host.as_ptr(), host.len(), port);
                if handle < 0 {
                    return Err(HostError { code: handle, message: format!("Failed to connect to {}:{}", host, port) });
                }
                Ok(TcpStream { handle })
            }
        }
        
        /// Read data from socket (blocks until data available)
        pub fn read(&self, buf: &mut [u8]) -> HostResult<usize> {
            unsafe {
                let n = host_tcp_read(self.handle, buf.as_mut_ptr(), buf.len());
                if n < 0 {
                    return Err(HostError { code: n, message: "Read error".to_string() });
                }
                Ok(n as usize)
            }
        }
        
        /// Read all available data
        pub fn read_to_vec(&self, max: usize) -> HostResult<Vec<u8>> {
            let mut buf = vec![0u8; max.min(65536)];
            let n = self.read(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        }
        
        /// Try to read without blocking
        /// Returns Ok(Some(n)) with bytes read, Ok(None) if would block
        /// Returns Ok(Some(0)) if connection closed
        pub fn try_read(&self, buf: &mut [u8]) -> HostResult<Option<usize>> {
            unsafe {
                let n = host_tcp_try_read(self.handle, buf.as_mut_ptr(), buf.len());
                if n > 0 {
                    Ok(Some(n as usize))
                } else if n == 0 {
                    Ok(None) // Would block
                } else if n == -1 {
                    Ok(Some(0)) // EOF/closed
                } else {
                    Err(HostError { code: n, message: "Read error".to_string() })
                }
            }
        }
        
        /// Check if data is ready to read
        pub fn readable(&self) -> bool {
            unsafe { host_tcp_readable(self.handle) > 0 }
        }
        
        /// Write data to socket
        pub fn write(&self, data: &[u8]) -> HostResult<usize> {
            unsafe {
                let n = host_tcp_write(self.handle, data.as_ptr(), data.len());
                if n < 0 {
                    return Err(HostError { code: n, message: "Write error".to_string() });
                }
                Ok(n as usize)
            }
        }
        
        /// Write all data
        pub fn write_all(&self, data: &[u8]) -> HostResult<()> {
            let mut offset = 0;
            while offset < data.len() {
                let n = self.write(&data[offset..])?;
                if n == 0 {
                    return Err(HostError { code: -1, message: "Write returned 0".to_string() });
                }
                offset += n;
            }
            Ok(())
        }
        
        /// Get local address
        pub fn local_addr(&self) -> Option<String> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_tcp_local_addr(self.handle, &mut len);
                if ptr.is_null() { return None; }
                let addr = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()?.to_string();
                host_free(ptr, len);
                Some(addr)
            }
        }
        
        /// Get remote address
        pub fn peer_addr(&self) -> Option<String> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_tcp_remote_addr(self.handle, &mut len);
                if ptr.is_null() { return None; }
                let addr = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()?.to_string();
                host_free(ptr, len);
                Some(addr)
            }
        }
        
        /// Set TCP_NODELAY
        pub fn set_nodelay(&self, nodelay: bool) -> HostResult<()> {
            unsafe {
                let opt = "nodelay";
                let result = host_tcp_set_opt(self.handle, opt.as_ptr(), opt.len(), if nodelay { 1 } else { 0 });
                if result < 0 {
                    return Err(HostError { code: result, message: "Failed to set nodelay".to_string() });
                }
                Ok(())
            }
        }
        
        /// Close the socket
        pub fn close(self) {
            unsafe { host_tcp_close(self.handle); }
        }
        
        /// Get raw handle for polling
        pub fn handle(&self) -> i32 { self.handle }
    }
    
    impl Drop for TcpStream {
        fn drop(&mut self) {
            unsafe { host_tcp_close(self.handle); }
        }
    }
    
    impl TcpListener {
        /// Bind and listen on address
        pub fn bind(host: &str, port: u16) -> HostResult<TcpListener> {
            unsafe {
                let handle = host_tcp_listen(host.as_ptr(), host.len(), port);
                if handle < 0 {
                    return Err(HostError { code: handle, message: format!("Failed to bind {}:{}", host, port) });
                }
                Ok(TcpListener { handle })
            }
        }
        
        /// Accept a connection (blocks until one arrives)
        pub fn accept(&self) -> HostResult<TcpStream> {
            unsafe {
                let handle = host_tcp_accept(self.handle);
                if handle < 0 {
                    return Err(HostError { code: handle, message: "Accept failed".to_string() });
                }
                Ok(TcpStream { handle })
            }
        }
        
        /// Try to accept a connection without blocking
        /// Returns Ok(Some(stream)) if connection available, Ok(None) if would block
        pub fn accept_nonblocking(&self) -> HostResult<Option<TcpStream>> {
            unsafe {
                let handle = host_tcp_accept_nonblocking(self.handle);
                if handle > 0 {
                    Ok(Some(TcpStream { handle }))
                } else if handle == 0 {
                    Ok(None) // Would block
                } else {
                    Err(HostError { code: handle, message: "Accept failed".to_string() })
                }
            }
        }
        
        /// Get local address
        pub fn local_addr(&self) -> Option<String> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_tcp_local_addr(self.handle, &mut len);
                if ptr.is_null() { return None; }
                let addr = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()?.to_string();
                host_free(ptr, len);
                Some(addr)
            }
        }
        
        /// Get raw handle for polling
        pub fn handle(&self) -> i32 { self.handle }
    }
    
    impl Drop for TcpListener {
        fn drop(&mut self) {
            unsafe { host_tcp_close(self.handle); }
        }
    }
}

// ============================================================================
// HTTP API
// ============================================================================

pub mod http {
    use super::*;
    
    /// HTTP response
    pub struct Response {
        handle: i32,
    }
    
    /// HTTP request builder
    pub struct Request {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    }
    
    impl Request {
        pub fn new(method: &str, url: &str) -> Self {
            Request {
                method: method.to_string(),
                url: url.to_string(),
                headers: Vec::new(),
                body: None,
            }
        }
        
        pub fn get(url: &str) -> Self { Self::new("GET", url) }
        pub fn post(url: &str) -> Self { Self::new("POST", url) }
        pub fn put(url: &str) -> Self { Self::new("PUT", url) }
        pub fn delete(url: &str) -> Self { Self::new("DELETE", url) }
        
        pub fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
        
        pub fn body(mut self, data: impl Into<Vec<u8>>) -> Self {
            self.body = Some(data.into());
            self
        }
        
        pub fn json(self, body: &str) -> Self {
            self.header("Content-Type", "application/json").body(body.as_bytes().to_vec())
        }
        
        /// Send the request
        pub fn send(self) -> HostResult<Response> {
            // Build headers JSON
            let headers_json = if self.headers.is_empty() {
                String::new()
            } else {
                let mut json = String::from("{");
                for (i, (k, v)) in self.headers.iter().enumerate() {
                    if i > 0 { json.push(','); }
                    json.push('"');
                    json.push_str(k);
                    json.push_str("\":\"");
                    json.push_str(v);
                    json.push('"');
                }
                json.push('}');
                json
            };
            
            let body = self.body.as_deref().unwrap_or(&[]);
            
            unsafe {
                let handle = host_http_request(
                    self.method.as_ptr(), self.method.len(),
                    self.url.as_ptr(), self.url.len(),
                    if headers_json.is_empty() { std::ptr::null() } else { headers_json.as_ptr() },
                    headers_json.len(),
                    if body.is_empty() { std::ptr::null() } else { body.as_ptr() },
                    body.len(),
                );
                if handle < 0 {
                    return Err(HostError { code: handle, message: format!("HTTP request failed: {}", self.url) });
                }
                Ok(Response { handle })
            }
        }
    }
    
    impl Response {
        /// Get status code
        pub fn status(&self) -> u16 {
            unsafe { host_http_status(self.handle) as u16 }
        }
        
        /// Get response headers
        pub fn headers(&self) -> Vec<(String, String)> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_http_headers(self.handle, &mut len);
                if ptr.is_null() { return Vec::new(); }
                let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap_or("{}");
                host_free(ptr, len);
                parse_headers_json(json)
            }
        }
        
        /// Get response body as bytes
        pub fn bytes(&self) -> HostResult<Vec<u8>> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_http_body(self.handle, &mut len);
                if ptr.is_null() {
                    return Ok(Vec::new());
                }
                let data = std::slice::from_raw_parts(ptr, len).to_vec();
                host_free(ptr, len);
                Ok(data)
            }
        }
        
        /// Get response body as string
        pub fn text(&self) -> HostResult<String> {
            let bytes = self.bytes()?;
            String::from_utf8(bytes).map_err(|e| HostError { code: -2, message: e.to_string() })
        }
    }
    
    impl Drop for Response {
        fn drop(&mut self) {
            unsafe { host_http_free(self.handle); }
        }
    }
    
    /// Convenience function for GET
    pub fn get(url: &str) -> HostResult<Response> {
        Request::get(url).send()
    }
    
    /// Convenience function for POST
    pub fn post(url: &str, body: &[u8]) -> HostResult<Response> {
        Request::post(url).body(body.to_vec()).send()
    }
}

// ============================================================================
// Async / Event Loop API
// ============================================================================

pub mod async_io {
    use super::*;
    
    /// Event from poll
    #[derive(Debug, Clone)]
    pub struct Event {
        pub kind: String,
        pub handle: i32,
        pub data: Option<String>,
    }
    
    /// Set a timer, returns timer handle
    pub fn timer(ms: u32) -> i32 {
        unsafe { host_timer_set(ms) }
    }
    
    /// Cancel a timer
    pub fn cancel_timer(handle: i32) {
        unsafe { host_timer_cancel(handle); }
    }
    
    /// Get current time in milliseconds
    pub fn now() -> u64 {
        unsafe { host_time_now() }
    }
    
    /// Sleep for milliseconds
    pub fn sleep(ms: u32) {
        unsafe { host_sleep(ms); }
    }
    
    /// Poll for ready events (non-blocking)
    pub fn poll() -> Option<Event> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_poll(&mut len);
            if ptr.is_null() || len == 0 {
                return None;
            }
            let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()?;
            host_free(ptr, len);
            parse_event_json(json)
        }
    }
    
    /// Wait for events (blocking)
    /// Returns number of ready events
    pub fn wait(timeout_ms: u32) -> i32 {
        unsafe { host_wait(timeout_ms) }
    }
    
    /// Register interest in socket becoming readable
    pub fn poll_read(handle: i32) {
        unsafe { host_poll_read(handle); }
    }
    
    /// Register interest in socket becoming writable
    pub fn poll_write(handle: i32) {
        unsafe { host_poll_write(handle); }
    }
    
    /// Unregister poll interest
    pub fn poll_remove(handle: i32) {
        unsafe { host_poll_remove(handle); }
    }
    
    /// Simple event loop runner
    pub fn run_until<F: FnMut(Event) -> bool>(mut callback: F) {
        loop {
            if wait(1000) > 0 {
                while let Some(event) = poll() {
                    if !callback(event) {
                        return;
                    }
                }
            }
        }
    }
}

// ============================================================================
// Streams API
// ============================================================================

pub mod stream {
    use super::*;
    
    /// File stream modes
    pub const READ: &str = "r";
    pub const WRITE: &str = "w";
    pub const APPEND: &str = "a";
    pub const READ_WRITE: &str = "r+";
    pub const WRITE_READ: &str = "w+";
    pub const APPEND_READ: &str = "a+";
    
    /// Seek origins
    pub const SEEK_SET: i32 = 0;
    pub const SEEK_CUR: i32 = 1;
    pub const SEEK_END: i32 = 2;
    
    /// File stream
    pub struct FileStream {
        handle: i32,
    }
    
    impl FileStream {
        /// Open a file stream
        pub fn open(path: &str, mode: &str) -> HostResult<FileStream> {
            unsafe {
                let handle = host_stream_open(path.as_ptr(), path.len(), mode.as_ptr(), mode.len());
                if handle < 0 {
                    return Err(HostError { code: handle, message: format!("Failed to open stream: {}", path) });
                }
                Ok(FileStream { handle })
            }
        }
        
        /// Read up to buf.len() bytes
        pub fn read(&self, buf: &mut [u8]) -> HostResult<usize> {
            unsafe {
                let n = host_stream_read(self.handle, buf.as_mut_ptr(), buf.len());
                if n < 0 {
                    return Err(HostError { code: n, message: "Stream read error".to_string() });
                }
                Ok(n as usize)
            }
        }
        
        /// Read entire stream to vec
        pub fn read_to_end(&self) -> HostResult<Vec<u8>> {
            let mut result = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = self.read(&mut buf)?;
                if n == 0 { break; }
                result.extend_from_slice(&buf[..n]);
            }
            Ok(result)
        }
        
        /// Write bytes
        pub fn write(&self, data: &[u8]) -> HostResult<usize> {
            unsafe {
                let n = host_stream_write(self.handle, data.as_ptr(), data.len());
                if n < 0 {
                    return Err(HostError { code: n, message: "Stream write error".to_string() });
                }
                Ok(n as usize)
            }
        }
        
        /// Write all bytes
        pub fn write_all(&self, data: &[u8]) -> HostResult<()> {
            let mut offset = 0;
            while offset < data.len() {
                let n = self.write(&data[offset..])?;
                if n == 0 {
                    return Err(HostError { code: -1, message: "Stream write returned 0".to_string() });
                }
                offset += n;
            }
            Ok(())
        }
        
        /// Seek
        pub fn seek(&self, offset: i64, whence: i32) -> HostResult<u64> {
            unsafe {
                let pos = host_stream_seek(self.handle, offset, whence);
                if pos < 0 {
                    return Err(HostError { code: pos as i32, message: "Seek error".to_string() });
                }
                Ok(pos as u64)
            }
        }
        
        /// Get current position
        pub fn tell(&self) -> u64 {
            unsafe { host_stream_tell(self.handle) as u64 }
        }
        
        /// Flush
        pub fn flush(&self) -> HostResult<()> {
            unsafe {
                let result = host_stream_flush(self.handle);
                if result < 0 {
                    return Err(HostError { code: result, message: "Flush error".to_string() });
                }
                Ok(())
            }
        }
    }
    
    impl Drop for FileStream {
        fn drop(&mut self) {
            unsafe { host_stream_close(self.handle); }
        }
    }
    
    /// Create a pipe (returns read end, write end)
    pub fn pipe() -> HostResult<(FileStream, FileStream)> {
        unsafe {
            let mut write_handle: i32 = 0;
            let read_handle = host_pipe_create(&mut write_handle);
            if read_handle < 0 {
                return Err(HostError { code: read_handle, message: "Failed to create pipe".to_string() });
            }
            Ok((FileStream { handle: read_handle }, FileStream { handle: write_handle }))
        }
    }
}

// ============================================================================
// JSON Parsing Helpers (used by http and async_io modules)
// ============================================================================

fn parse_headers_json(json: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    let json = json.trim_matches(|c| c == '{' || c == '}');
    for pair in json.split(',') {
        let parts: Vec<&str> = pair.splitn(2, ':').collect();
        if parts.len() == 2 {
            let key = parts[0].trim().trim_matches('"');
            let val = parts[1].trim().trim_matches('"');
            headers.push((key.to_string(), val.to_string()));
        }
    }
    headers
}

fn parse_event_json(json: &str) -> Option<async_io::Event> {
    fn extract(json: &str, key: &str) -> Option<String> {
        let pattern = format!("\"{}\":\"", key);
        if let Some(start) = json.find(&pattern) {
            let rest = &json[start + pattern.len()..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }
        // Try numeric value
        let pattern = format!("\"{}\":", key);
        if let Some(start) = json.find(&pattern) {
            let rest = &json[start + pattern.len()..];
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
            if end > 0 {
                return Some(rest[..end].trim().to_string());
            }
        }
        None
    }
    
    let kind = extract(json, "type")?;
    let handle = extract(json, "handle")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let data = extract(json, "data");
    Some(async_io::Event { kind, handle, data })
}

} // end mod host_imports (wasm)

// Native stub - provides types but no implementation
// Used when this module is included in native compilation
#[cfg(not(target_family = "wasm"))]
#[allow(dead_code)]
mod host_imports {
    pub type HostResult<T> = Result<T, HostError>;
    
    #[derive(Debug, Clone)]
    pub struct HostError {
        pub code: i32,
        pub message: String,
    }
    
    impl std::fmt::Display for HostError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "HostError {}: {}", self.code, self.message)
        }
    }
    impl std::error::Error for HostError {}
    
    pub mod fs {
        use super::*;
        #[derive(Debug, Clone)]
        pub struct FileStat {
            pub size: u64, pub mtime: u64, pub atime: u64, pub ctime: u64,
            pub is_file: bool, pub is_dir: bool, pub is_symlink: bool, pub mode: u32,
        }
        pub struct Watcher;
        #[derive(Debug, Clone)]
        pub struct WatchEvent { pub kind: String, pub path: String }
        
        pub fn read(_: &str) -> HostResult<Vec<u8>> { unimplemented!("host_imports only available in WASM") }
        pub fn read_to_string(_: &str) -> HostResult<String> { unimplemented!() }
        pub fn write(_: &str, _: &[u8]) -> HostResult<()> { unimplemented!() }
        pub fn write_str(_: &str, _: &str) -> HostResult<()> { unimplemented!() }
        pub fn exists(_: &str) -> bool { false }
        pub fn is_dir(_: &str) -> bool { false }
        pub fn mkdir(_: &str) -> HostResult<()> { unimplemented!() }
        pub fn remove(_: &str) -> HostResult<()> { unimplemented!() }
        pub fn read_dir(_: &str) -> HostResult<Vec<String>> { unimplemented!() }
        pub fn stat(_: &str) -> HostResult<FileStat> { unimplemented!() }
        pub fn rename(_: &str, _: &str) -> HostResult<()> { unimplemented!() }
        pub fn copy(_: &str, _: &str) -> HostResult<()> { unimplemented!() }
        pub fn symlink(_: &str, _: &str) -> HostResult<()> { unimplemented!() }
        pub fn readlink(_: &str) -> HostResult<String> { unimplemented!() }
        pub fn watch(_: &str) -> HostResult<Watcher> { unimplemented!() }
        pub fn append(_: &str, _: &[u8]) -> HostResult<()> { unimplemented!() }
    }
    
    pub mod env {
        use super::*;
        pub fn get(_: &str) -> Option<String> { None }
        pub fn set(_: &str, _: &str) -> HostResult<()> { unimplemented!() }
        pub fn cwd() -> HostResult<String> { unimplemented!() }
    }
    
    pub mod console {
        pub fn log(_: &str) {}
        pub fn error(_: &str) {}
    }
    
    pub mod process {
        use super::*;
        pub fn exec(_: &str) -> HostResult<(i32, String, String)> { unimplemented!() }
        pub fn exit(_: i32) -> ! { std::process::exit(1) }
    }
    
    pub mod tcp {
        use super::*;
        pub struct TcpStream;
        pub struct TcpListener;
        impl TcpStream {
            pub fn connect(_: &str, _: u16) -> HostResult<Self> { unimplemented!() }
        }
        impl TcpListener {
            pub fn bind(_: &str, _: u16) -> HostResult<Self> { unimplemented!() }
        }
    }
    
    pub mod http {
        use super::*;
        pub struct Response;
        pub struct Request;
        impl Request {
            pub fn get(_: &str) -> Self { Request }
            pub fn post(_: &str) -> Self { Request }
            pub fn header(self, _: &str, _: &str) -> Self { self }
            pub fn body(self, _: Vec<u8>) -> Self { self }
            pub fn json(self, _: &str) -> Self { self }
            pub fn send(self) -> HostResult<Response> { unimplemented!() }
        }
        impl Response {
            pub fn status(&self) -> u16 { 0 }
            pub fn text(&self) -> HostResult<String> { unimplemented!() }
        }
        pub fn get(_: &str) -> HostResult<Response> { unimplemented!() }
    }
    
    pub mod async_io {
        #[derive(Debug, Clone)]
        pub struct Event { pub kind: String, pub handle: i32, pub data: Option<String> }
        pub fn timer(_: u32) -> i32 { 0 }
        pub fn now() -> u64 { 0 }
        pub fn sleep(_: u32) {}
        pub fn poll() -> Option<Event> { None }
        pub fn wait(_: u32) -> i32 { 0 }
    }
    
    pub mod stream {
        use super::*;
        pub const READ: &str = "r";
        pub const WRITE: &str = "w";
        pub const SEEK_SET: i32 = 0;
        pub struct FileStream;
        impl FileStream {
            pub fn open(_: &str, _: &str) -> HostResult<Self> { unimplemented!() }
            pub fn read(&self, _: &mut [u8]) -> HostResult<usize> { unimplemented!() }
            pub fn read_to_end(&self) -> HostResult<Vec<u8>> { unimplemented!() }
            pub fn write_all(&self, _: &[u8]) -> HostResult<()> { unimplemented!() }
            pub fn seek(&self, _: i64, _: i32) -> HostResult<u64> { unimplemented!() }
            pub fn flush(&self) -> HostResult<()> { unimplemented!() }
        }
    }
} // end mod host_imports (native stub)

// Re-export for convenient access
#[allow(unused_imports)]
pub use host_imports::*;
