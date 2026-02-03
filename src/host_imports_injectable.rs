// Host Imports — WASM-to-Node.js bridge functions
// Injected by Polyglot compiler when --target host is used

// ============================================================================
// Memory Management
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_alloc(size: usize) -> *mut u8;
    fn host_free(ptr: *mut u8, size: usize);
    fn host_get_len(ptr: *const u8) -> usize;
}

// ============================================================================
// Filesystem (Basic)
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_fs_read(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
    fn host_fs_write(path_ptr: *const u8, path_len: usize, data_ptr: *const u8, data_len: usize) -> i32;
    fn host_fs_append(path_ptr: *const u8, path_len: usize, data_ptr: *const u8, data_len: usize) -> i32;
    fn host_fs_exists(path_ptr: *const u8, path_len: usize) -> i32;
    fn host_fs_is_dir(path_ptr: *const u8, path_len: usize) -> i32;
    fn host_fs_mkdir(path_ptr: *const u8, path_len: usize) -> i32;
    fn host_fs_remove(path_ptr: *const u8, path_len: usize) -> i32;
    fn host_fs_rmdir(path_ptr: *const u8, path_len: usize) -> i32;
    fn host_fs_readdir(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
}

// ============================================================================
// Filesystem (Extended)
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_fs_stat(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
    fn host_fs_rename(old_ptr: *const u8, old_len: usize, new_ptr: *const u8, new_len: usize) -> i32;
    fn host_fs_copy(src_ptr: *const u8, src_len: usize, dst_ptr: *const u8, dst_len: usize) -> i32;
    fn host_fs_symlink(target_ptr: *const u8, target_len: usize, link_ptr: *const u8, link_len: usize) -> i32;
    fn host_fs_readlink(path_ptr: *const u8, path_len: usize, out_len: *mut usize) -> *mut u8;
    fn host_fs_watch(path_ptr: *const u8, path_len: usize) -> i32;
    fn host_fs_watch_poll(handle: i32, out_len: *mut usize) -> *mut u8;
    fn host_fs_watch_close(handle: i32) -> i32;
}

// ============================================================================
// Environment
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_env_get(name_ptr: *const u8, name_len: usize, out_len: *mut usize) -> *mut u8;
    fn host_env_set(name_ptr: *const u8, name_len: usize, val_ptr: *const u8, val_len: usize) -> i32;
    fn host_env_cwd(out_len: *mut usize) -> *mut u8;
    fn host_env_chdir(path_ptr: *const u8, path_len: usize) -> i32;
    fn host_env_args(out_len: *mut usize) -> *mut u8;
}

// ============================================================================
// Console
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_console_log(msg_ptr: *const u8, msg_len: usize);
    fn host_console_error(msg_ptr: *const u8, msg_len: usize);
    fn host_console_read_line(out_len: *mut usize) -> *mut u8;
}

// ============================================================================
// Process
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_process_exec(
        cmd_ptr: *const u8, cmd_len: usize,
        out_stdout_len: *mut usize, out_stderr_len: *mut usize,
        out_stdout: *mut *mut u8, out_stderr: *mut *mut u8,
    ) -> i32;
    fn host_process_exit(code: i32) -> !;
}

// ============================================================================
// TCP Networking
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_tcp_connect(host_ptr: *const u8, host_len: usize, port: u16) -> i32;
    fn host_tcp_listen(host_ptr: *const u8, host_len: usize, port: u16) -> i32;
    fn host_tcp_accept(server_handle: i32) -> i32;
    fn host_tcp_read(handle: i32, buf_ptr: *mut u8, buf_len: usize) -> i32;
    fn host_tcp_write(handle: i32, data_ptr: *const u8, data_len: usize) -> i32;
    fn host_tcp_close(handle: i32) -> i32;
    fn host_tcp_local_addr(handle: i32, out_len: *mut usize) -> *mut u8;
    fn host_tcp_remote_addr(handle: i32, out_len: *mut usize) -> *mut u8;
    fn host_tcp_set_opt(handle: i32, opt_ptr: *const u8, opt_len: usize, value: i32) -> i32;
}

// ============================================================================
// HTTP
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_http_request(
        method_ptr: *const u8, method_len: usize,
        url_ptr: *const u8, url_len: usize,
        headers_ptr: *const u8, headers_len: usize,
        body_ptr: *const u8, body_len: usize
    ) -> i32;
    fn host_http_status(handle: i32) -> i32;
    fn host_http_headers(handle: i32, out_len: *mut usize) -> *mut u8;
    fn host_http_body(handle: i32, out_len: *mut usize) -> *mut u8;
    fn host_http_free(handle: i32) -> i32;
}

// ============================================================================
// Async / Event Loop
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_timer_set(ms: u32) -> i32;
    fn host_timer_cancel(handle: i32) -> i32;
    fn host_poll(out_len: *mut usize) -> *mut u8;
    fn host_wait(timeout_ms: u32) -> i32;
    fn host_poll_read(handle: i32) -> i32;
    fn host_poll_write(handle: i32) -> i32;
    fn host_poll_remove(handle: i32) -> i32;
    fn host_time_now() -> u64;
    fn host_sleep(ms: u32);
}

// ============================================================================
// Streams
// ============================================================================

#[link(wasm_import_module = "host")]
extern "C" {
    fn host_stream_open(path_ptr: *const u8, path_len: usize, mode_ptr: *const u8, mode_len: usize) -> i32;
    fn host_stream_read(handle: i32, buf_ptr: *mut u8, buf_len: usize) -> i32;
    fn host_stream_write(handle: i32, data_ptr: *const u8, data_len: usize) -> i32;
    fn host_stream_seek(handle: i32, offset: i64, whence: i32) -> i64;
    fn host_stream_tell(handle: i32) -> i64;
    fn host_stream_flush(handle: i32) -> i32;
    fn host_stream_close(handle: i32) -> i32;
    fn host_pipe_create(out_write: *mut i32) -> i32;
}

// ============================================================================
// High-Level Rust API
// ============================================================================

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

pub type HostResult<T> = Result<T, HostError>;

// ============================================================================
// fs module
// ============================================================================

#[allow(dead_code)]
pub mod fs {
    use super::*;

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

    #[derive(Debug, Clone)]
    pub struct WatchEvent {
        pub kind: String,
        pub path: String,
    }

    pub struct Watcher { handle: i32 }

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

    pub fn read_to_string(path: &str) -> HostResult<String> {
        let bytes = read(path)?;
        String::from_utf8(bytes).map_err(|e| HostError { code: -2, message: format!("UTF-8 error: {}", e) })
    }

    pub fn write(path: &str, data: &[u8]) -> HostResult<()> {
        unsafe {
            let result = host_fs_write(path.as_ptr(), path.len(), data.as_ptr(), data.len());
            if result < 0 { return Err(HostError { code: result, message: format!("Failed to write: {}", path) }); }
            Ok(())
        }
    }

    pub fn write_str(path: &str, content: &str) -> HostResult<()> { write(path, content.as_bytes()) }

    pub fn append(path: &str, data: &[u8]) -> HostResult<()> {
        unsafe {
            let result = host_fs_append(path.as_ptr(), path.len(), data.as_ptr(), data.len());
            if result < 0 { return Err(HostError { code: result, message: format!("Failed to append: {}", path) }); }
            Ok(())
        }
    }

    pub fn exists(path: &str) -> bool { unsafe { host_fs_exists(path.as_ptr(), path.len()) == 1 } }
    pub fn is_dir(path: &str) -> bool { unsafe { host_fs_is_dir(path.as_ptr(), path.len()) == 1 } }

    pub fn mkdir(path: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_mkdir(path.as_ptr(), path.len());
            if result < 0 { return Err(HostError { code: result, message: format!("Failed to mkdir: {}", path) }); }
            Ok(())
        }
    }

    pub fn remove(path: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_remove(path.as_ptr(), path.len());
            if result < 0 { return Err(HostError { code: result, message: format!("Failed to remove: {}", path) }); }
            Ok(())
        }
    }

    pub fn read_dir(path: &str) -> HostResult<Vec<String>> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_fs_readdir(path.as_ptr(), path.len(), &mut len);
            if ptr.is_null() { return Err(HostError { code: -1, message: format!("Failed to readdir: {}", path) }); }
            let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?;
            host_free(ptr, len);
            let entries: Vec<String> = json.trim_matches(|c| c == '[' || c == ']')
                .split(',').filter(|s| !s.is_empty()).map(|s| s.trim().trim_matches('"').to_string()).collect();
            Ok(entries)
        }
    }

    pub fn stat(path: &str) -> HostResult<FileStat> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_fs_stat(path.as_ptr(), path.len(), &mut len);
            if ptr.is_null() { return Err(HostError { code: -1, message: format!("Failed to stat: {}", path) }); }
            let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?;
            host_free(ptr, len);
            fn get_num(json: &str, key: &str) -> u64 {
                let pat = format!("\"{}\":", key);
                json.find(&pat).map(|i| {
                    let rest = &json[i + pat.len()..];
                    rest[..rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len())].trim().parse().unwrap_or(0)
                }).unwrap_or(0)
            }
            fn get_bool(json: &str, key: &str) -> bool { json.contains(&format!("\"{}\":true", key)) }
            Ok(FileStat {
                size: get_num(json, "size"), mtime: get_num(json, "mtime"), atime: get_num(json, "atime"),
                ctime: get_num(json, "ctime"), is_file: get_bool(json, "isFile"), is_dir: get_bool(json, "isDir"),
                is_symlink: get_bool(json, "isSymlink"), mode: get_num(json, "mode") as u32,
            })
        }
    }

    pub fn rename(old: &str, new: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_rename(old.as_ptr(), old.len(), new.as_ptr(), new.len());
            if result < 0 { return Err(HostError { code: result, message: format!("Failed to rename {} -> {}", old, new) }); }
            Ok(())
        }
    }

    pub fn copy(src: &str, dst: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_copy(src.as_ptr(), src.len(), dst.as_ptr(), dst.len());
            if result < 0 { return Err(HostError { code: result, message: format!("Failed to copy {} -> {}", src, dst) }); }
            Ok(())
        }
    }

    pub fn watch(path: &str) -> HostResult<Watcher> {
        unsafe {
            let handle = host_fs_watch(path.as_ptr(), path.len());
            if handle < 0 { return Err(HostError { code: handle, message: format!("Failed to watch: {}", path) }); }
            Ok(Watcher { handle })
        }
    }

    impl Watcher {
        pub fn poll(&self) -> Vec<WatchEvent> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_fs_watch_poll(self.handle, &mut len);
                if ptr.is_null() || len == 0 { return Vec::new(); }
                let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap_or("[]");
                host_free(ptr, len);
                let mut events = Vec::new();
                for part in json.split("},") {
                    fn extract(json: &str, key: &str) -> Option<String> {
                        let pat = format!("\"{}\":\"", key);
                        json.find(&pat).and_then(|i| {
                            let rest = &json[i + pat.len()..];
                            rest.find('"').map(|end| rest[..end].to_string())
                        })
                    }
                    let kind = extract(part, "kind").unwrap_or_default();
                    let path = extract(part, "path").unwrap_or_default();
                    if !kind.is_empty() { events.push(WatchEvent { kind, path }); }
                }
                events
            }
        }
        pub fn close(self) { unsafe { host_fs_watch_close(self.handle); } }
    }
}

// ============================================================================
// env module
// ============================================================================

#[allow(dead_code)]
pub mod env {
    use super::*;

    pub fn get(name: &str) -> Option<String> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_env_get(name.as_ptr(), name.len(), &mut len);
            if ptr.is_null() || len == 0 { return None; }
            let val = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()?.to_string();
            host_free(ptr, len);
            Some(val)
        }
    }

    pub fn set(name: &str, value: &str) -> HostResult<()> {
        unsafe {
            let result = host_env_set(name.as_ptr(), name.len(), value.as_ptr(), value.len());
            if result < 0 { return Err(HostError { code: result, message: "Failed to set env".to_string() }); }
            Ok(())
        }
    }

    pub fn cwd() -> HostResult<String> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_env_cwd(&mut len);
            if ptr.is_null() { return Err(HostError { code: -1, message: "Failed to get cwd".to_string() }); }
            let path = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?.to_string();
            host_free(ptr, len);
            Ok(path)
        }
    }

    pub fn chdir(path: &str) -> HostResult<()> {
        unsafe {
            let result = host_env_chdir(path.as_ptr(), path.len());
            if result < 0 { return Err(HostError { code: result, message: format!("Failed to chdir: {}", path) }); }
            Ok(())
        }
    }
}

// ============================================================================
// console module
// ============================================================================

#[allow(dead_code)]
pub mod console {
    use super::*;
    pub fn log(msg: &str) { unsafe { host_console_log(msg.as_ptr(), msg.len()); } }
    pub fn error(msg: &str) { unsafe { host_console_error(msg.as_ptr(), msg.len()); } }
}

// ============================================================================
// process module
// ============================================================================

#[allow(dead_code)]
pub mod process {
    use super::*;

    pub fn exec(cmd: &str) -> HostResult<(i32, String, String)> {
        unsafe {
            let mut stdout_len: usize = 0;
            let mut stderr_len: usize = 0;
            let mut stdout_ptr: *mut u8 = std::ptr::null_mut();
            let mut stderr_ptr: *mut u8 = std::ptr::null_mut();
            let code = host_process_exec(cmd.as_ptr(), cmd.len(), &mut stdout_len, &mut stderr_len, &mut stdout_ptr, &mut stderr_ptr);
            let stdout = if !stdout_ptr.is_null() && stdout_len > 0 {
                let s = std::str::from_utf8(std::slice::from_raw_parts(stdout_ptr, stdout_len)).unwrap_or("").to_string();
                host_free(stdout_ptr, stdout_len); s
            } else { String::new() };
            let stderr = if !stderr_ptr.is_null() && stderr_len > 0 {
                let s = std::str::from_utf8(std::slice::from_raw_parts(stderr_ptr, stderr_len)).unwrap_or("").to_string();
                host_free(stderr_ptr, stderr_len); s
            } else { String::new() };
            Ok((code, stdout, stderr))
        }
    }

    pub fn exit(code: i32) -> ! { unsafe { host_process_exit(code) } }
}

// ============================================================================
// tcp module
// ============================================================================

#[allow(dead_code)]
pub mod tcp {
    use super::*;

    pub struct TcpStream { handle: i32 }
    pub struct TcpListener { handle: i32 }

    impl TcpStream {
        pub fn connect(host: &str, port: u16) -> HostResult<TcpStream> {
            unsafe {
                let handle = host_tcp_connect(host.as_ptr(), host.len(), port);
                if handle < 0 { return Err(HostError { code: handle, message: format!("Failed to connect to {}:{}", host, port) }); }
                Ok(TcpStream { handle })
            }
        }

        pub fn read(&self, buf: &mut [u8]) -> HostResult<usize> {
            unsafe {
                let n = host_tcp_read(self.handle, buf.as_mut_ptr(), buf.len());
                if n < 0 { return Err(HostError { code: n, message: "Read error".to_string() }); }
                Ok(n as usize)
            }
        }

        pub fn read_to_vec(&self, max: usize) -> HostResult<Vec<u8>> {
            let mut buf = vec![0u8; max.min(65536)];
            let n = self.read(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        }

        pub fn write(&self, data: &[u8]) -> HostResult<usize> {
            unsafe {
                let n = host_tcp_write(self.handle, data.as_ptr(), data.len());
                if n < 0 { return Err(HostError { code: n, message: "Write error".to_string() }); }
                Ok(n as usize)
            }
        }

        pub fn write_all(&self, data: &[u8]) -> HostResult<()> {
            let mut offset = 0;
            while offset < data.len() {
                let n = self.write(&data[offset..])?;
                if n == 0 { return Err(HostError { code: -1, message: "Write returned 0".to_string() }); }
                offset += n;
            }
            Ok(())
        }

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

        pub fn set_nodelay(&self, nodelay: bool) -> HostResult<()> {
            unsafe {
                let opt = "nodelay";
                let result = host_tcp_set_opt(self.handle, opt.as_ptr(), opt.len(), if nodelay { 1 } else { 0 });
                if result < 0 { return Err(HostError { code: result, message: "Failed to set nodelay".to_string() }); }
                Ok(())
            }
        }

        pub fn handle(&self) -> i32 { self.handle }
    }

    impl Drop for TcpStream {
        fn drop(&mut self) { unsafe { host_tcp_close(self.handle); } }
    }

    impl TcpListener {
        pub fn bind(host: &str, port: u16) -> HostResult<TcpListener> {
            unsafe {
                let handle = host_tcp_listen(host.as_ptr(), host.len(), port);
                if handle < 0 { return Err(HostError { code: handle, message: format!("Failed to bind {}:{}", host, port) }); }
                Ok(TcpListener { handle })
            }
        }

        pub fn accept(&self) -> HostResult<TcpStream> {
            unsafe {
                let handle = host_tcp_accept(self.handle);
                if handle < 0 { return Err(HostError { code: handle, message: "Accept failed".to_string() }); }
                Ok(TcpStream { handle })
            }
        }

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

        pub fn handle(&self) -> i32 { self.handle }
    }

    impl Drop for TcpListener {
        fn drop(&mut self) { unsafe { host_tcp_close(self.handle); } }
    }
}

// ============================================================================
// http module
// ============================================================================

#[allow(dead_code)]
pub mod http {
    use super::*;

    pub struct Response { handle: i32 }

    pub struct Request {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    }

    impl Request {
        pub fn new(method: &str, url: &str) -> Self {
            Request { method: method.to_string(), url: url.to_string(), headers: Vec::new(), body: None }
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

        pub fn send(self) -> HostResult<Response> {
            let headers_json = if self.headers.is_empty() { String::new() } else {
                let mut json = String::from("{");
                for (i, (k, v)) in self.headers.iter().enumerate() {
                    if i > 0 { json.push(','); }
                    json.push('"'); json.push_str(k); json.push_str("\":\""); json.push_str(v); json.push('"');
                }
                json.push('}');
                json
            };
            let body = self.body.as_deref().unwrap_or(&[]);
            unsafe {
                let handle = host_http_request(
                    self.method.as_ptr(), self.method.len(),
                    self.url.as_ptr(), self.url.len(),
                    if headers_json.is_empty() { std::ptr::null() } else { headers_json.as_ptr() }, headers_json.len(),
                    if body.is_empty() { std::ptr::null() } else { body.as_ptr() }, body.len(),
                );
                if handle < 0 { return Err(HostError { code: handle, message: format!("HTTP request failed: {}", self.url) }); }
                Ok(Response { handle })
            }
        }
    }

    impl Response {
        pub fn status(&self) -> u16 { unsafe { host_http_status(self.handle) as u16 } }

        pub fn headers(&self) -> Vec<(String, String)> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_http_headers(self.handle, &mut len);
                if ptr.is_null() { return Vec::new(); }
                let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap_or("{}");
                host_free(ptr, len);
                let mut headers = Vec::new();
                let json = json.trim_matches(|c| c == '{' || c == '}');
                for pair in json.split(',') {
                    let parts: Vec<&str> = pair.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        headers.push((parts[0].trim().trim_matches('"').to_string(), parts[1].trim().trim_matches('"').to_string()));
                    }
                }
                headers
            }
        }

        pub fn bytes(&self) -> HostResult<Vec<u8>> {
            unsafe {
                let mut len: usize = 0;
                let ptr = host_http_body(self.handle, &mut len);
                if ptr.is_null() { return Ok(Vec::new()); }
                let data = std::slice::from_raw_parts(ptr, len).to_vec();
                host_free(ptr, len);
                Ok(data)
            }
        }

        pub fn text(&self) -> HostResult<String> {
            let bytes = self.bytes()?;
            String::from_utf8(bytes).map_err(|e| HostError { code: -2, message: e.to_string() })
        }
    }

    impl Drop for Response {
        fn drop(&mut self) { unsafe { host_http_free(self.handle); } }
    }

    pub fn get(url: &str) -> HostResult<Response> { Request::get(url).send() }
    pub fn post(url: &str, body: &[u8]) -> HostResult<Response> { Request::post(url).body(body.to_vec()).send() }
}

// ============================================================================
// async_io module
// ============================================================================

#[allow(dead_code)]
pub mod async_io {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Event {
        pub kind: String,
        pub handle: i32,
        pub data: Option<String>,
    }

    pub fn timer(ms: u32) -> i32 { unsafe { host_timer_set(ms) } }
    pub fn cancel_timer(handle: i32) { unsafe { host_timer_cancel(handle); } }
    pub fn now() -> u64 { unsafe { host_time_now() } }
    pub fn sleep(ms: u32) { unsafe { host_sleep(ms); } }

    pub fn poll() -> Option<Event> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_poll(&mut len);
            if ptr.is_null() || len == 0 { return None; }
            let json = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()?;
            host_free(ptr, len);
            fn extract(json: &str, key: &str) -> Option<String> {
                let pat = format!("\"{}\":\"", key);
                json.find(&pat).and_then(|i| {
                    let rest = &json[i + pat.len()..];
                    rest.find('"').map(|end| rest[..end].to_string())
                }).or_else(|| {
                    let pat = format!("\"{}\":", key);
                    json.find(&pat).and_then(|i| {
                        let rest = &json[i + pat.len()..];
                        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
                        if end > 0 { Some(rest[..end].trim().to_string()) } else { None }
                    })
                })
            }
            let kind = extract(json, "type")?;
            let handle = extract(json, "handle").and_then(|s| s.parse().ok()).unwrap_or(0);
            let data = extract(json, "data");
            Some(Event { kind, handle, data })
        }
    }

    pub fn wait(timeout_ms: u32) -> i32 { unsafe { host_wait(timeout_ms) } }
    pub fn poll_read(handle: i32) { unsafe { host_poll_read(handle); } }
    pub fn poll_write(handle: i32) { unsafe { host_poll_write(handle); } }
    pub fn poll_remove(handle: i32) { unsafe { host_poll_remove(handle); } }

    pub fn run_until<F: FnMut(Event) -> bool>(mut callback: F) {
        loop {
            if wait(1000) > 0 {
                while let Some(event) = poll() {
                    if !callback(event) { return; }
                }
            }
        }
    }
}

// ============================================================================
// stream module
// ============================================================================

#[allow(dead_code)]
pub mod stream {
    use super::*;

    pub const READ: &str = "r";
    pub const WRITE: &str = "w";
    pub const APPEND: &str = "a";
    pub const READ_WRITE: &str = "r+";
    pub const SEEK_SET: i32 = 0;
    pub const SEEK_CUR: i32 = 1;
    pub const SEEK_END: i32 = 2;

    pub struct FileStream { handle: i32 }

    impl FileStream {
        pub fn open(path: &str, mode: &str) -> HostResult<FileStream> {
            unsafe {
                let handle = host_stream_open(path.as_ptr(), path.len(), mode.as_ptr(), mode.len());
                if handle < 0 { return Err(HostError { code: handle, message: format!("Failed to open stream: {}", path) }); }
                Ok(FileStream { handle })
            }
        }

        pub fn read(&self, buf: &mut [u8]) -> HostResult<usize> {
            unsafe {
                let n = host_stream_read(self.handle, buf.as_mut_ptr(), buf.len());
                if n < 0 { return Err(HostError { code: n, message: "Stream read error".to_string() }); }
                Ok(n as usize)
            }
        }

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

        pub fn write(&self, data: &[u8]) -> HostResult<usize> {
            unsafe {
                let n = host_stream_write(self.handle, data.as_ptr(), data.len());
                if n < 0 { return Err(HostError { code: n, message: "Stream write error".to_string() }); }
                Ok(n as usize)
            }
        }

        pub fn write_all(&self, data: &[u8]) -> HostResult<()> {
            let mut offset = 0;
            while offset < data.len() {
                let n = self.write(&data[offset..])?;
                if n == 0 { return Err(HostError { code: -1, message: "Stream write returned 0".to_string() }); }
                offset += n;
            }
            Ok(())
        }

        pub fn seek(&self, offset: i64, whence: i32) -> HostResult<u64> {
            unsafe {
                let pos = host_stream_seek(self.handle, offset, whence);
                if pos < 0 { return Err(HostError { code: pos as i32, message: "Seek error".to_string() }); }
                Ok(pos as u64)
            }
        }

        pub fn tell(&self) -> u64 { unsafe { host_stream_tell(self.handle) as u64 } }

        pub fn flush(&self) -> HostResult<()> {
            unsafe {
                let result = host_stream_flush(self.handle);
                if result < 0 { return Err(HostError { code: result, message: "Flush error".to_string() }); }
                Ok(())
            }
        }
    }

    impl Drop for FileStream {
        fn drop(&mut self) { unsafe { host_stream_close(self.handle); } }
    }

    pub fn pipe() -> HostResult<(FileStream, FileStream)> {
        unsafe {
            let mut write_handle: i32 = 0;
            let read_handle = host_pipe_create(&mut write_handle);
            if read_handle < 0 { return Err(HostError { code: read_handle, message: "Failed to create pipe".to_string() }); }
            Ok((FileStream { handle: read_handle }, FileStream { handle: write_handle }))
        }
    }
}
