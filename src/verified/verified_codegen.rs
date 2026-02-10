//! Code generation for verified execution.
//!
//! Handles the compiler's side of `#[verified]` support:
//! - Auto-adds `use poly_verified::prelude::*;` to blocks with verified markers
//! - Auto-adds `use sha2::Digest;` (needed by macro-generated code)
//! - Reports determinism check errors as compile warnings/errors

use super::determinism_check;
use super::error_codes::VerifiedCompileError;

/// Result of processing a verified code block
pub struct VerifiedCodegenResult {
    /// The processed code with auto-imports prepended
    pub code: String,
    /// Any determinism violations found (warnings/errors)
    pub errors: Vec<VerifiedCompileError>,
}

/// Process a Rust code block that contains verified execution markers.
///
/// This function:
/// 1. Prepends necessary imports for the #[verified] macro expansion
/// 2. Runs determinism checks on #[verified] function bodies
/// 3. Returns processed code and any errors
pub fn process_verified_block(code: &str) -> VerifiedCodegenResult {
    let mut imports = Vec::new();
    let mut errors = Vec::new();

    // Auto-add imports needed by the verified macro expansion
    if !code.contains("use poly_verified::") && !code.contains("poly_verified::prelude") {
        imports.push("use poly_verified::prelude::*;");
    }
    if !code.contains("use sha2::") {
        imports.push("use sha2::Digest;");
    }

    // Run determinism check on verified function bodies
    let verified_bodies = extract_verified_bodies(code);
    for (body, offset) in verified_bodies {
        let body_errors = determinism_check::check_determinism(&body);
        for mut err in body_errors {
            err.line += offset;
            errors.push(err);
        }
    }

    // Build final code
    let mut result = String::new();
    for imp in &imports {
        result.push_str(imp);
        result.push('\n');
    }
    if !imports.is_empty() {
        result.push('\n');
    }
    result.push_str(code);

    VerifiedCodegenResult {
        code: result,
        errors,
    }
}

/// Extract function bodies that are preceded by #[verified] attribute.
/// Returns (body_code, line_offset) pairs.
fn extract_verified_bodies(code: &str) -> Vec<(String, usize)> {
    let mut bodies = Vec::new();
    let lines: Vec<&str> = code.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Look for #[verified] or #[verified(...)]
        if trimmed.starts_with("#[verified") && trimmed.contains(']') {
            // Next non-empty, non-attribute line should be the function signature
            let mut fn_start = i + 1;
            while fn_start < lines.len() {
                let next_trimmed = lines[fn_start].trim();
                if next_trimmed.is_empty() || next_trimmed.starts_with("#[") {
                    fn_start += 1;
                    continue;
                }
                break;
            }

            // Find function body (between { and matching })
            if fn_start < lines.len() {
                let fn_line = lines[fn_start].trim();
                if fn_line.contains("fn ") {
                    // Find opening brace
                    let mut brace_line = fn_start;
                    while brace_line < lines.len() && !lines[brace_line].contains('{') {
                        brace_line += 1;
                    }

                    if brace_line < lines.len() {
                        // Collect body until matching close brace
                        let mut depth = 0;
                        let mut body_lines = Vec::new();
                        let body_start = brace_line;

                        for j in brace_line..lines.len() {
                            for ch in lines[j].chars() {
                                match ch {
                                    '{' => depth += 1,
                                    '}' => depth -= 1,
                                    _ => {}
                                }
                            }
                            body_lines.push(lines[j]);
                            if depth == 0 {
                                break;
                            }
                        }

                        bodies.push((body_lines.join("\n"), body_start));
                    }
                }
            }
        }
        i += 1;
    }

    bodies
}

/// Generate the additional Cargo.toml dependencies needed for verified execution
pub fn verified_dependencies_toml() -> &'static str {
    r#"poly-verified = { path = "../poly-verified" }
sha2 = "0.10""#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_imports() {
        let code = r#"
#[verified]
fn add(a: u64, b: u64) -> u64 {
    a + b
}
"#;
        let result = process_verified_block(code);
        assert!(result.code.contains("use poly_verified::prelude::*;"));
        assert!(result.code.contains("use sha2::Digest;"));
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_detect_violation_in_verified() {
        let code = r#"
#[verified]
fn bad_fn(x: f64) -> f64 {
    x * 2.0
}
"#;
        let result = process_verified_block(code);
        assert!(!result.errors.is_empty());
        assert_eq!(result.errors[0].code, "V002");
    }

    #[test]
    fn test_skip_imports_when_present() {
        let code = "use poly_verified::prelude::*;\nuse sha2::Digest;\nfn foo() {}";
        let result = process_verified_block(code);
        // Should not duplicate imports
        let import_count = result
            .code
            .matches("use poly_verified::prelude")
            .count();
        assert_eq!(import_count, 1);
    }
}
