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
// Filesystem
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
        cmd_ptr: *const u8,
        cmd_len: usize,
        out_stdout_len: *mut usize,
        out_stderr_len: *mut usize,
        out_stdout: *mut *mut u8,
        out_stderr: *mut *mut u8,
    ) -> i32;
    fn host_process_exit(code: i32) -> !;
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

#[allow(dead_code)]
pub mod fs {
    use super::*;

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
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to write: {}", path) });
            }
            Ok(())
        }
    }

    pub fn write_str(path: &str, content: &str) -> HostResult<()> {
        write(path, content.as_bytes())
    }

    pub fn append(path: &str, data: &[u8]) -> HostResult<()> {
        unsafe {
            let result = host_fs_append(path.as_ptr(), path.len(), data.as_ptr(), data.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to append: {}", path) });
            }
            Ok(())
        }
    }

    pub fn exists(path: &str) -> bool {
        unsafe { host_fs_exists(path.as_ptr(), path.len()) == 1 }
    }

    pub fn is_dir(path: &str) -> bool {
        unsafe { host_fs_is_dir(path.as_ptr(), path.len()) == 1 }
    }

    pub fn mkdir(path: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_mkdir(path.as_ptr(), path.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to mkdir: {}", path) });
            }
            Ok(())
        }
    }

    pub fn remove(path: &str) -> HostResult<()> {
        unsafe {
            let result = host_fs_remove(path.as_ptr(), path.len());
            if result < 0 {
                return Err(HostError { code: result, message: format!("Failed to remove: {}", path) });
            }
            Ok(())
        }
    }

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
            let entries: Vec<String> = json
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().trim_matches('"').to_string())
                .collect();
            Ok(entries)
        }
    }
}

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
            if result < 0 {
                return Err(HostError { code: result, message: "Failed to set env".to_string() });
            }
            Ok(())
        }
    }

    pub fn cwd() -> HostResult<String> {
        unsafe {
            let mut len: usize = 0;
            let ptr = host_env_cwd(&mut len);
            if ptr.is_null() {
                return Err(HostError { code: -1, message: "Failed to get cwd".to_string() });
            }
            let path = std::str::from_utf8(std::slice::from_raw_parts(ptr, len))
                .map_err(|e| HostError { code: -2, message: e.to_string() })?.to_string();
            host_free(ptr, len);
            Ok(path)
        }
    }
}

#[allow(dead_code)]
pub mod console {
    use super::*;

    pub fn log(msg: &str) {
        unsafe { host_console_log(msg.as_ptr(), msg.len()); }
    }

    pub fn error(msg: &str) {
        unsafe { host_console_error(msg.as_ptr(), msg.len()); }
    }
}

#[allow(dead_code)]
pub mod process {
    use super::*;

    pub fn exec(cmd: &str) -> HostResult<(i32, String, String)> {
        unsafe {
            let mut stdout_len: usize = 0;
            let mut stderr_len: usize = 0;
            let mut stdout_ptr: *mut u8 = std::ptr::null_mut();
            let mut stderr_ptr: *mut u8 = std::ptr::null_mut();
            
            let code = host_process_exec(
                cmd.as_ptr(), cmd.len(),
                &mut stdout_len, &mut stderr_len,
                &mut stdout_ptr, &mut stderr_ptr,
            );
            
            let stdout = if !stdout_ptr.is_null() && stdout_len > 0 {
                let s = std::str::from_utf8(std::slice::from_raw_parts(stdout_ptr, stdout_len)).unwrap_or("").to_string();
                host_free(stdout_ptr, stdout_len);
                s
            } else { String::new() };
            
            let stderr = if !stderr_ptr.is_null() && stderr_len > 0 {
                let s = std::str::from_utf8(std::slice::from_raw_parts(stderr_ptr, stderr_len)).unwrap_or("").to_string();
                host_free(stderr_ptr, stderr_len);
                s
            } else { String::new() };
            
            Ok((code, stdout, stderr))
        }
    }

    pub fn exit(code: i32) -> ! {
        unsafe { host_process_exit(code) }
    }
}
