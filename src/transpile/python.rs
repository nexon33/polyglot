//! Python to Rust transpiler
//!
//! Converts Python expressions and statements to equivalent Rust code.

use regex::Regex;

/// Python transpiler that converts Python code to Rust
pub struct PythonTranspiler;

impl PythonTranspiler {
    pub fn new() -> Self {
        Self
    }

    /// Transpile a Python method body to Rust
    /// Takes the method source and parameter names
    pub fn transpile_method(&self, source: &str, params: &[&str]) -> Option<String> {
        // Extract the return expression from the method
        let return_expr = self.extract_return_expr(source)?;

        // Transpile the expression
        self.transpile_expr(&return_expr, params)
    }

    /// Extract the return expression from a Python method
    fn extract_return_expr(&self, source: &str) -> Option<String> {
        // Look for return statement
        let return_re = Regex::new(r"return\s+(.+)").ok()?;
        if let Some(caps) = return_re.captures(source) {
            return Some(caps.get(1)?.as_str().trim().to_string());
        }

        // Look for single expression (implicit return)
        // This handles cases like def foo(): expr
        let lines: Vec<&str> = source.lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .collect();

        if lines.len() == 1 {
            let line = lines[0].trim();
            if !line.starts_with("def ") && !line.starts_with("fn ") {
                return Some(line.to_string());
            }
        }

        None
    }

    /// Transpile a Python expression to Rust
    pub fn transpile_expr(&self, expr: &str, params: &[&str]) -> Option<String> {
        let expr = expr.trim();

        // Try each pattern in order
        if let Some(rust) = self.transpile_sum_comprehension(expr, params) {
            return Some(rust);
        }

        if let Some(rust) = self.transpile_list_comprehension(expr, params) {
            return Some(rust);
        }

        if let Some(rust) = self.transpile_len(expr, params) {
            return Some(rust);
        }

        if let Some(rust) = self.transpile_str_literal(expr) {
            return Some(rust);
        }

        if let Some(rust) = self.transpile_simple_arithmetic(expr, params) {
            return Some(rust);
        }

        // Check if it's a simple variable reference
        if params.contains(&expr) {
            return Some(expr.to_string());
        }

        None
    }

    /// Transpile sum(expr for x in iter if cond) to Rust
    fn transpile_sum_comprehension(&self, expr: &str, _params: &[&str]) -> Option<String> {
        // Match: sum(expr for var in iter)
        // Match: sum(expr for var in iter if cond)
        let sum_re = Regex::new(
            r"sum\s*\(\s*(.+?)\s+for\s+(\w+)\s+in\s+(\w+)(?:\s+if\s+(.+?))?\s*\)"
        ).ok()?;

        let caps = sum_re.captures(expr)?;
        let map_expr = caps.get(1)?.as_str().trim();
        let var = caps.get(2)?.as_str();
        let iter = caps.get(3)?.as_str();
        let cond = caps.get(4).map(|m| m.as_str().trim());

        // Build the Rust expression
        let mut rust = format!("{}.iter()", iter);

        if let Some(condition) = cond {
            let rust_cond = self.transpile_condition(condition, var)?;
            rust.push_str(&format!(".filter(|&&{}| {})", var, rust_cond));
        }

        let rust_map = self.transpile_map_expr(map_expr, var)?;
        rust.push_str(&format!(".map(|&{}| {})", var, rust_map));
        rust.push_str(".sum()");

        Some(rust)
    }

    /// Transpile [expr for x in iter if cond] to Rust
    fn transpile_list_comprehension(&self, expr: &str, _params: &[&str]) -> Option<String> {
        // Match: [expr for var in iter]
        // Match: [expr for var in iter if cond]
        let list_re = Regex::new(
            r"\[\s*(.+?)\s+for\s+(\w+)\s+in\s+(\w+)(?:\s+if\s+(.+?))?\s*\]"
        ).ok()?;

        let caps = list_re.captures(expr)?;
        let map_expr = caps.get(1)?.as_str().trim();
        let var = caps.get(2)?.as_str();
        let iter = caps.get(3)?.as_str();
        let cond = caps.get(4).map(|m| m.as_str().trim());

        // Build the Rust expression
        let mut rust = format!("{}.into_iter()", iter);

        if let Some(condition) = cond {
            let rust_cond = self.transpile_condition(condition, var)?;
            rust.push_str(&format!(".filter(|&{}| {})", var, rust_cond));
        }

        // If map_expr is just the variable, we can skip the map
        if map_expr == var {
            rust.push_str(".collect()");
        } else {
            let rust_map = self.transpile_map_expr(map_expr, var)?;
            rust.push_str(&format!(".map(|{}| {})", var, rust_map));
            rust.push_str(".collect()");
        }

        Some(rust)
    }

    /// Transpile len(x) to x.len()
    fn transpile_len(&self, expr: &str, _params: &[&str]) -> Option<String> {
        let len_re = Regex::new(r"^len\s*\(\s*(\w+)\s*\)$").ok()?;
        let caps = len_re.captures(expr)?;
        let arg = caps.get(1)?.as_str();
        Some(format!("{}.len()", arg))
    }

    /// Transpile string literal
    fn transpile_str_literal(&self, expr: &str) -> Option<String> {
        // Match Python string literals
        if (expr.starts_with('"') && expr.ends_with('"')) ||
           (expr.starts_with('\'') && expr.ends_with('\'')) {
            // Extract content and convert to Rust string
            let content = &expr[1..expr.len()-1];
            return Some(format!("\"{}\".to_string()", content));
        }

        // Match f-strings: f"..." or f'...'
        if expr.starts_with("f\"") || expr.starts_with("f'") {
            let content = &expr[2..expr.len()-1];
            // Convert Python f-string to Rust format!
            // {var} stays the same
            return Some(format!("format!(\"{}\")", content));
        }

        None
    }

    /// Transpile simple arithmetic expressions
    fn transpile_simple_arithmetic(&self, expr: &str, params: &[&str]) -> Option<String> {
        // Only handle simple binary operations
        let ops = ["+", "-", "*", "/", "%", "//"];

        for op in ops {
            if let Some(pos) = expr.find(op) {
                let left = expr[..pos].trim();
                let right = expr[pos + op.len()..].trim();

                // Recursively transpile
                let rust_left = if params.contains(&left) {
                    left.to_string()
                } else {
                    self.transpile_expr(left, params)?
                };

                let rust_right = if params.contains(&right) {
                    right.to_string()
                } else {
                    self.transpile_expr(right, params)?
                };

                // Convert Python // to Rust /
                let rust_op = if op == "//" { "/" } else { op };

                return Some(format!("{} {} {}", rust_left, rust_op, rust_right));
            }
        }

        // Check if it's a numeric literal
        if expr.parse::<i64>().is_ok() || expr.parse::<f64>().is_ok() {
            return Some(expr.to_string());
        }

        None
    }

    /// Transpile a Python condition to Rust
    fn transpile_condition(&self, cond: &str, var: &str) -> Option<String> {
        let cond = cond.trim();

        // x > 0, x >= 5, x < 10, etc.
        let cmp_re = Regex::new(r"^(\w+)\s*(==|!=|>=|<=|>|<)\s*(.+)$").ok()?;
        if let Some(caps) = cmp_re.captures(cond) {
            let left = caps.get(1)?.as_str();
            let op = caps.get(2)?.as_str();
            let right = caps.get(3)?.as_str().trim();

            // If left is the loop variable, it's already in scope
            if left == var {
                return Some(format!("{} {} {}", left, op, right));
            }
        }

        // Handle 'and' and 'or'
        if cond.contains(" and ") {
            let parts: Vec<&str> = cond.split(" and ").collect();
            let rust_parts: Option<Vec<String>> = parts.iter()
                .map(|p| self.transpile_condition(p.trim(), var))
                .collect();
            return rust_parts.map(|p| p.join(" && "));
        }

        if cond.contains(" or ") {
            let parts: Vec<&str> = cond.split(" or ").collect();
            let rust_parts: Option<Vec<String>> = parts.iter()
                .map(|p| self.transpile_condition(p.trim(), var))
                .collect();
            return rust_parts.map(|p| p.join(" || "));
        }

        // Handle 'not'
        if cond.starts_with("not ") {
            let inner = &cond[4..];
            return self.transpile_condition(inner, var).map(|c| format!("!({})", c));
        }

        Some(cond.to_string())
    }

    /// Transpile a map expression
    fn transpile_map_expr(&self, expr: &str, var: &str) -> Option<String> {
        let expr = expr.trim();

        // Simple variable reference
        if expr == var {
            return Some(var.to_string());
        }

        // x * 2, x + 1, etc.
        let arith_re = Regex::new(r"^(\w+)\s*([+\-*/])\s*(\d+)$").ok()?;
        if let Some(caps) = arith_re.captures(expr) {
            let left = caps.get(1)?.as_str();
            let op = caps.get(2)?.as_str();
            let right = caps.get(3)?.as_str();

            if left == var {
                return Some(format!("{} {} {}", left, op, right));
            }
        }

        // 2 * x
        let arith_rev_re = Regex::new(r"^(\d+)\s*([+\-*/])\s*(\w+)$").ok()?;
        if let Some(caps) = arith_rev_re.captures(expr) {
            let left = caps.get(1)?.as_str();
            let op = caps.get(2)?.as_str();
            let right = caps.get(3)?.as_str();

            if right == var {
                return Some(format!("{} {} {}", left, op, right));
            }
        }

        // Fallback: return as-is
        Some(expr.to_string())
    }
}

impl Default for PythonTranspiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sum_comprehension() {
        let transpiler = PythonTranspiler::new();

        let result = transpiler.transpile_expr(
            "sum(x * 2 for x in data if x > 0)",
            &["data"]
        );
        assert!(result.is_some());
        let rust = result.unwrap();
        assert!(rust.contains(".iter()"));
        assert!(rust.contains(".filter("));
        assert!(rust.contains(".map("));
        assert!(rust.contains(".sum()"));
    }

    #[test]
    fn test_list_comprehension() {
        let transpiler = PythonTranspiler::new();

        let result = transpiler.transpile_expr(
            "[x for x in data if x >= threshold]",
            &["data", "threshold"]
        );
        assert!(result.is_some());
        let rust = result.unwrap();
        assert!(rust.contains(".into_iter()"));
        assert!(rust.contains(".filter("));
        assert!(rust.contains(".collect()"));
    }

    #[test]
    fn test_list_comprehension_with_transform() {
        let transpiler = PythonTranspiler::new();

        let result = transpiler.transpile_expr(
            "[x * 2 for x in data]",
            &["data"]
        );
        assert!(result.is_some());
        let rust = result.unwrap();
        assert!(rust.contains(".map("));
    }

    #[test]
    fn test_len() {
        let transpiler = PythonTranspiler::new();

        let result = transpiler.transpile_expr("len(data)", &["data"]);
        assert_eq!(result, Some("data.len()".to_string()));
    }

    #[test]
    fn test_string_literal() {
        let transpiler = PythonTranspiler::new();

        let result = transpiler.transpile_expr("\"hello\"", &[]);
        assert_eq!(result, Some("\"hello\".to_string()".to_string()));
    }

    #[test]
    fn test_transpile_method() {
        let transpiler = PythonTranspiler::new();

        let source = r#"
def process(self, data):
    return sum(x * 2 for x in data if x > 0)
"#;

        let result = transpiler.transpile_method(source, &["data"]);
        assert!(result.is_some());
        let rust = result.unwrap();
        assert!(rust.contains(".sum()"));
    }
}
