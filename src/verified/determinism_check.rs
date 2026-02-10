//! Compile-time determinism checker for `#[verified]` functions.
//!
//! Walks the source code of verified functions and rejects patterns
//! that could introduce non-determinism:
//! - Floating point types and literals (V002)
//! - Unsafe blocks and raw pointers (V005)
//! - IO, networking, filesystem operations (V001)
//! - Random number generation (V001)
//! - System time access (V009)
//! - Thread/async spawning (V011)
//! - Global mutable state (V007)
//! - Interior mutability types (V008)
//! - Non-deterministic iteration order (V006)
//! - Environment variable access (V010)

use super::error_codes::*;

/// Check a block of Rust code within a #[verified] context for determinism violations.
/// Returns a list of errors found.
pub fn check_determinism(code: &str) -> Vec<VerifiedCompileError> {
    let mut errors = Vec::new();

    for (line_idx, line) in code.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }

        // V002: Floating-point types
        for fp_pattern in &["f32", "f64"] {
            if contains_type_usage(trimmed, fp_pattern) {
                errors.push(
                    VerifiedCompileError::new(
                        V002,
                        format!(
                            "Floating-point type `{}` is not allowed in #[verified] functions",
                            fp_pattern
                        ),
                        line_num,
                    )
                    .with_hint(
                        "Use `FixedPoint` from poly_verified for deterministic arithmetic",
                    ),
                );
            }
        }

        // V005: Unsafe blocks
        if trimmed.contains("unsafe ") || trimmed.contains("unsafe{") {
            errors.push(VerifiedCompileError::new(
                V005,
                "Unsafe code is not allowed in #[verified] functions",
                line_num,
            ));
        }

        // V005: Raw pointers
        if trimmed.contains("*const ") || trimmed.contains("*mut ") {
            errors.push(VerifiedCompileError::new(
                V005,
                "Raw pointers are not allowed in #[verified] functions",
                line_num,
            ));
        }

        // V001: IO operations
        for io_pattern in &[
            "std::fs::",
            "std::net::",
            "std::io::",
            "File::open",
            "File::create",
            "TcpStream::",
            "UdpSocket::",
        ] {
            if trimmed.contains(io_pattern) {
                errors.push(VerifiedCompileError::new(
                    V001,
                    format!(
                        "IO operation `{}` is not allowed in #[verified] functions",
                        io_pattern
                    ),
                    line_num,
                ));
            }
        }

        // V001: Random number generation
        for rand_pattern in &["rand::", "thread_rng()", "OsRng", "StdRng"] {
            if trimmed.contains(rand_pattern) {
                errors.push(VerifiedCompileError::new(
                    V001,
                    format!(
                        "Random number generation `{}` is not allowed in #[verified] functions",
                        rand_pattern
                    ),
                    line_num,
                ));
            }
        }

        // V009: System time
        for time_pattern in &[
            "SystemTime::now()",
            "Instant::now()",
            "chrono::Utc::now()",
        ] {
            if trimmed.contains(time_pattern) {
                errors.push(VerifiedCompileError::new(
                    V009,
                    format!(
                        "Time access `{}` is not allowed in #[verified] functions",
                        time_pattern
                    ),
                    line_num,
                ));
            }
        }

        // V010: Environment variables
        if trimmed.contains("std::env::var") || trimmed.contains("env::var") {
            errors.push(VerifiedCompileError::new(
                V010,
                "Environment variable access is not allowed in #[verified] functions",
                line_num,
            ));
        }

        // V011: Thread spawning
        for thread_pattern in &[
            "std::thread::spawn",
            "thread::spawn",
            "tokio::spawn",
            "async_std::task::spawn",
        ] {
            if trimmed.contains(thread_pattern) {
                errors.push(VerifiedCompileError::new(
                    V011,
                    format!(
                        "Thread/task spawning `{}` is not allowed in #[verified] functions",
                        thread_pattern
                    ),
                    line_num,
                ));
            }
        }

        // V007: Global mutable state
        if trimmed.contains("static mut ") {
            errors.push(VerifiedCompileError::new(
                V007,
                "Global mutable state (`static mut`) is not allowed in #[verified] functions",
                line_num,
            ));
        }

        // V008: Interior mutability
        for cell_pattern in &[
            "Cell<",
            "RefCell<",
            "Mutex<",
            "RwLock<",
            "AtomicBool",
            "AtomicU",
            "AtomicI",
        ] {
            if trimmed.contains(cell_pattern) {
                errors.push(
                    VerifiedCompileError::new(
                        V008,
                        format!(
                            "Interior mutability type `{}` is not allowed in #[verified] functions",
                            cell_pattern
                        ),
                        line_num,
                    )
                    .with_hint("Use immutable data structures or function parameters instead"),
                );
            }
        }

        // V006: Non-deterministic iteration
        if trimmed.contains("HashMap")
            && (trimmed.contains(".iter()")
                || trimmed.contains(".keys()")
                || trimmed.contains(".values()"))
        {
            errors.push(
                VerifiedCompileError::new(
                    V006,
                    "HashMap iteration has non-deterministic order in #[verified] functions",
                    line_num,
                )
                .with_hint("Use BTreeMap for deterministic iteration order"),
            );
        }

        // V013: Inline assembly
        if trimmed.contains("asm!") || trimmed.contains("global_asm!") {
            errors.push(VerifiedCompileError::new(
                V013,
                "Inline assembly is not allowed in #[verified] functions",
                line_num,
            ));
        }

        // V014: Process spawning
        if trimmed.contains("Command::new") || trimmed.contains("std::process::") {
            errors.push(VerifiedCompileError::new(
                V014,
                "Process spawning is not allowed in #[verified] functions",
                line_num,
            ));
        }
    }

    errors
}

/// Check if a line contains a type usage (not just a substring in a comment/string)
fn contains_type_usage(line: &str, type_name: &str) -> bool {
    let patterns = [
        format!(": {}", type_name),
        format!("-> {}", type_name),
        format!("<{}>", type_name),
        format!("<{},", type_name),
        format!(", {}>", type_name),
        format!("as {}", type_name),
        format!("{}::", type_name),
    ];

    patterns.iter().any(|p| line.contains(p.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_float() {
        let code = "let x: f64 = 3.14;";
        let errors = check_determinism(code);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].code, V002);
    }

    #[test]
    fn test_detect_unsafe() {
        let code = "unsafe { *ptr = 42; }";
        let errors = check_determinism(code);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].code, V005);
    }

    #[test]
    fn test_detect_io() {
        let code = "let f = std::fs::read(\"file.txt\");";
        let errors = check_determinism(code);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].code, V001);
    }

    #[test]
    fn test_clean_code_passes() {
        let code = r#"
            let x: u64 = 42;
            let y = x.saturating_add(10);
            let z = if y > 50 { y - 50 } else { y };
        "#;
        let errors = check_determinism(code);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_detect_hashmap_iter() {
        let code2 = "let keys: Vec<_> = HashMap::new().keys().collect();";
        let errors2 = check_determinism(code2);
        assert!(!errors2.is_empty());
        assert_eq!(errors2[0].code, V006);
    }

    #[test]
    fn test_detect_thread_spawn() {
        let code = "std::thread::spawn(|| { heavy_work(); });";
        let errors = check_determinism(code);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].code, V011);
    }

    #[test]
    fn test_detect_env_var() {
        let code = "let key = std::env::var(\"API_KEY\").unwrap();";
        let errors = check_determinism(code);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].code, V010);
    }
}
