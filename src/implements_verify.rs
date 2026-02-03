// Phase 26b: @implements verification
//
// Verifies that classes marked with @implements(Trait) actually
// implement all methods required by the trait from #[interface] blocks.

use crate::interface::parser::{InterfaceItem, TraitDef, Type, PrimitiveType};
use crate::parser::{ParsedFile, CodeBlock};
use regex::Regex;

/// Information about a class that claims to implement a trait
#[derive(Debug, Clone)]
pub struct Implementation {
    pub class_name: String,
    pub trait_name: String,
    pub methods: Vec<MethodSignature>,
    pub lang_tag: String,
    pub line: usize,
}

/// A method signature extracted from a class
#[derive(Debug, Clone)]
pub struct MethodSignature {
    pub name: String,
    pub params: Vec<(String, String)>,  // (name, type_str)
    pub return_type: Option<String>,
}

/// Verification error
#[derive(Debug)]
pub struct VerifyError {
    pub class_name: String,
    pub trait_name: String,
    pub message: String,
    pub lang_tag: String,
    pub line: usize,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (line {}): class `{}` claims to implement `{}` but {}",
            self.lang_tag, self.line, self.class_name, self.trait_name, self.message
        )
    }
}

impl std::error::Error for VerifyError {}

/// Extract all @implements declarations from parsed blocks
pub fn extract_implementations(parsed: &ParsedFile) -> Vec<Implementation> {
    let mut implementations = Vec::new();

    for block in &parsed.blocks {
        match block.lang_tag.as_str() {
            "python" | "py" => {
                implementations.extend(extract_python_implementations(block));
            }
            "typescript" | "ts" => {
                implementations.extend(extract_typescript_implementations(block));
            }
            "javascript" | "js" => {
                implementations.extend(extract_javascript_implementations(block));
            }
            // Rust uses native `impl Trait for Type` syntax - handled separately
            _ => {}
        }
    }

    implementations
}

/// Extract @implements(Trait) from Python code
fn extract_python_implementations(block: &CodeBlock) -> Vec<Implementation> {
    let mut implementations = Vec::new();

    // Pattern: @implements(TraitName) or #[implements(TraitName)] followed by class ClassName
    // The syntax normalizer converts @decorator to #[decorator], so we need to handle both
    // After normalization, Python classes may have `: {` instead of just `:`
    let decorator_re = Regex::new(
        r"(?:#\[implements\((\w+)\)\]|@implements\((\w+)\))\s*(?:\r?\n)?\s*class\s+(\w+)(?:\([^)]*\))?(?::\s*\{|:)"
    ).unwrap();

    for cap in decorator_re.captures_iter(&block.code) {
        // Trait name could be in group 1 (#[implements]) or group 2 (@implements)
        let trait_name = cap.get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let class_name = cap.get(3).unwrap().as_str().to_string();

        // Find the class body and extract methods
        let class_start = cap.get(0).unwrap().end();
        let methods = extract_python_methods(&block.code[class_start..], &class_name);

        let line_offset = block.code[..cap.get(0).unwrap().start()]
            .lines()
            .count();

        implementations.push(Implementation {
            class_name,
            trait_name,
            methods,
            lang_tag: block.lang_tag.clone(),
            line: block.start_line + line_offset,
        });
    }

    implementations
}

/// Extract methods from a Python class body
fn extract_python_methods(code: &str, _class_name: &str) -> Vec<MethodSignature> {
    let mut methods = Vec::new();

    // Pattern: def/fn method_name(self, param: type, ...) -> return_type:
    // The syntax normalizer converts `def` to `fn`, so we need to handle both
    // After normalization: fn method(self, params): { body }
    let method_re = Regex::new(
        r"(?:def|fn)\s+(\w+)\s*\(\s*self\s*(?:,\s*([^)]*))?\)\s*(?:->\s*([^:{]+))?(?::\s*\{|:)"
    ).unwrap();

    // Find the end of this class (next class or end of indented block)
    let class_end = find_class_end(code);
    let class_body = &code[..class_end];

    for cap in method_re.captures_iter(class_body) {
        let name = cap.get(1).unwrap().as_str().to_string();

        // Skip dunder methods except __init__
        if name.starts_with("__") && name != "__init__" {
            continue;
        }

        let params_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let return_type = cap.get(3).map(|m| m.as_str().trim().to_string());

        let params = parse_python_params(params_str);

        methods.push(MethodSignature {
            name,
            params,
            return_type,
        });
    }

    methods
}

/// Find where a Python class ends (based on indentation)
fn find_class_end(code: &str) -> usize {
    let mut lines = code.lines().peekable();
    let mut pos = 0;
    let mut found_content = false;

    while let Some(line) = lines.next() {
        let trimmed = line.trim();

        // Skip empty lines and comments at the start
        if !found_content && (trimmed.is_empty() || trimmed.starts_with('#')) {
            pos += line.len() + 1;
            continue;
        }

        found_content = true;

        // Check if this line is at class level (indented)
        let indent = line.len() - line.trim_start().len();

        // If we hit a non-indented line that's not empty, class is done
        if indent == 0 && !trimmed.is_empty() && !trimmed.starts_with('#') {
            // Check if it's a new class or @implements decorator
            if trimmed.starts_with("class ") || trimmed.starts_with("@") {
                return pos;
            }
        }

        pos += line.len() + 1;
    }

    code.len()
}

/// Parse Python parameter string into (name, type) pairs
fn parse_python_params(params_str: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();

    if params_str.trim().is_empty() {
        return params;
    }

    for part in params_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some(colon_idx) = part.find(':') {
            let name = part[..colon_idx].trim().to_string();
            let ty = part[colon_idx + 1..].trim();
            // Remove default value if present
            let ty = if let Some(eq_idx) = ty.find('=') {
                ty[..eq_idx].trim()
            } else {
                ty
            };
            params.push((name, ty.to_string()));
        } else {
            // Untyped parameter
            params.push((part.to_string(), "Any".to_string()));
        }
    }

    params
}

/// Extract @implements(Trait) from TypeScript code
fn extract_typescript_implementations(block: &CodeBlock) -> Vec<Implementation> {
    let mut implementations = Vec::new();

    // Pattern: @implements(TraitName) or #[implements(TraitName)] followed by class ClassName {
    // The syntax normalizer converts @decorator to #[decorator]
    let decorator_re = Regex::new(
        r"(?:#\[implements\((\w+)\)\]|@implements\((\w+)\))\s*(?:\r?\n)?\s*class\s+(\w+)(?:\s+extends\s+\w+)?\s*\{"
    ).unwrap();

    for cap in decorator_re.captures_iter(&block.code) {
        // Trait name could be in group 1 (#[implements]) or group 2 (@implements)
        let trait_name = cap.get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let class_name = cap.get(3).unwrap().as_str().to_string();

        // Find the class body and extract methods
        let class_start = cap.get(0).unwrap().end() - 1; // Include the opening brace
        let methods = extract_ts_methods(&block.code[class_start..]);

        let line_offset = block.code[..cap.get(0).unwrap().start()]
            .lines()
            .count();

        implementations.push(Implementation {
            class_name,
            trait_name,
            methods,
            lang_tag: block.lang_tag.clone(),
            line: block.start_line + line_offset,
        });
    }

    implementations
}

/// Extract @implements(Trait) from JavaScript code
fn extract_javascript_implementations(block: &CodeBlock) -> Vec<Implementation> {
    let mut implementations = Vec::new();

    // Pattern: @implements(TraitName) or #[implements(TraitName)] followed by class ClassName {
    // The syntax normalizer converts @decorator to #[decorator]
    let decorator_re = Regex::new(
        r"(?:#\[implements\((\w+)\)\]|@implements\((\w+)\))\s*(?:\r?\n)?\s*class\s+(\w+)(?:\s+extends\s+\w+)?\s*\{"
    ).unwrap();

    for cap in decorator_re.captures_iter(&block.code) {
        // Trait name could be in group 1 (#[implements]) or group 2 (@implements)
        let trait_name = cap.get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let class_name = cap.get(3).unwrap().as_str().to_string();

        // Find the class body and extract methods (JS has no types)
        let class_start = cap.get(0).unwrap().end() - 1;
        let methods = extract_js_methods(&block.code[class_start..]);

        let line_offset = block.code[..cap.get(0).unwrap().start()]
            .lines()
            .count();

        implementations.push(Implementation {
            class_name,
            trait_name,
            methods,
            lang_tag: block.lang_tag.clone(),
            line: block.start_line + line_offset,
        });
    }

    implementations
}

/// Extract methods from TypeScript class body
fn extract_ts_methods(code: &str) -> Vec<MethodSignature> {
    let mut methods = Vec::new();

    // Find matching closing brace for class
    let class_body = extract_brace_content(code).unwrap_or_default();

    // Pattern: methodName(param: type, ...): returnType {
    let method_re = Regex::new(
        r"(\w+)\s*\(\s*([^)]*)\s*\)\s*(?::\s*([^{]+))?\s*\{"
    ).unwrap();

    for cap in method_re.captures_iter(&class_body) {
        let name = cap.get(1).unwrap().as_str().to_string();

        // Skip constructor
        if name == "constructor" {
            continue;
        }

        let params_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let return_type = cap.get(3).map(|m| m.as_str().trim().to_string());

        let params = parse_ts_params(params_str);

        methods.push(MethodSignature {
            name,
            params,
            return_type,
        });
    }

    methods
}

/// Extract methods from JavaScript class body (no types)
fn extract_js_methods(code: &str) -> Vec<MethodSignature> {
    let mut methods = Vec::new();

    let class_body = extract_brace_content(code).unwrap_or_default();

    // Pattern: methodName(params) {
    let method_re = Regex::new(
        r"(\w+)\s*\(\s*([^)]*)\s*\)\s*\{"
    ).unwrap();

    for cap in method_re.captures_iter(&class_body) {
        let name = cap.get(1).unwrap().as_str().to_string();

        // Skip constructor
        if name == "constructor" {
            continue;
        }

        let params_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");

        // JS has no types, so we just track parameter names
        let params: Vec<(String, String)> = params_str
            .split(',')
            .filter_map(|p| {
                let p = p.trim();
                if p.is_empty() { None }
                else { Some((p.to_string(), "any".to_string())) }
            })
            .collect();

        methods.push(MethodSignature {
            name,
            params,
            return_type: None, // JS has no return type annotations
        });
    }

    methods
}

/// Parse TypeScript parameter string
fn parse_ts_params(params_str: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();

    if params_str.trim().is_empty() {
        return params;
    }

    for part in params_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some(colon_idx) = part.find(':') {
            let name = part[..colon_idx].trim().to_string();
            let ty = part[colon_idx + 1..].trim().to_string();
            params.push((name, ty));
        } else {
            params.push((part.to_string(), "any".to_string()));
        }
    }

    params
}

/// Extract content within braces
fn extract_brace_content(code: &str) -> Option<String> {
    let bytes = code.as_bytes();
    let mut depth = 0;
    let mut start = None;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, &c) in bytes.iter().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        if c == b'\\' {
            escape_next = true;
            continue;
        }

        if c == b'"' || c == b'\'' || c == b'`' {
            in_string = !in_string;
            continue;
        }

        if in_string {
            continue;
        }

        if c == b'{' {
            if depth == 0 {
                start = Some(i + 1);
            }
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = start {
                    return Some(code[s..i].to_string());
                }
            }
        }
    }

    None
}

/// Get trait definition by name from interfaces
fn get_trait_def<'a>(interfaces: &'a [InterfaceItem], name: &str) -> Option<&'a TraitDef> {
    interfaces.iter().find_map(|item| {
        if let InterfaceItem::Trait(t) = item {
            if t.name == name {
                return Some(t);
            }
        }
        None
    })
}

/// Verify all implementations against their declared traits
pub fn verify_implementations(parsed: &ParsedFile) -> Vec<VerifyError> {
    let mut errors = Vec::new();
    let implementations = extract_implementations(parsed);

    for impl_ in implementations {
        // Find the trait definition
        let Some(trait_def) = get_trait_def(&parsed.interfaces, &impl_.trait_name) else {
            errors.push(VerifyError {
                class_name: impl_.class_name.clone(),
                trait_name: impl_.trait_name.clone(),
                message: format!("trait `{}` is not defined in #[interface] block", impl_.trait_name),
                lang_tag: impl_.lang_tag,
                line: impl_.line,
            });
            continue;
        };

        // Check each required method
        for required_method in &trait_def.methods {
            let found = impl_.methods.iter().find(|m| m.name == required_method.name);

            match found {
                None => {
                    errors.push(VerifyError {
                        class_name: impl_.class_name.clone(),
                        trait_name: impl_.trait_name.clone(),
                        message: format!("missing required method `{}`", required_method.name),
                        lang_tag: impl_.lang_tag.clone(),
                        line: impl_.line,
                    });
                }
                Some(impl_method) => {
                    // Verify parameter count matches
                    if impl_method.params.len() != required_method.params.len() {
                        errors.push(VerifyError {
                            class_name: impl_.class_name.clone(),
                            trait_name: impl_.trait_name.clone(),
                            message: format!(
                                "method `{}` has {} parameters but trait requires {}",
                                required_method.name,
                                impl_method.params.len(),
                                required_method.params.len()
                            ),
                            lang_tag: impl_.lang_tag.clone(),
                            line: impl_.line,
                        });
                    }

                    // Verify return type presence matches (if both are typed languages)
                    if impl_.lang_tag != "javascript" && impl_.lang_tag != "js" {
                        let impl_has_return = impl_method.return_type.is_some();
                        let trait_has_return = required_method.return_type.is_some();

                        if trait_has_return && !impl_has_return {
                            errors.push(VerifyError {
                                class_name: impl_.class_name.clone(),
                                trait_name: impl_.trait_name.clone(),
                                message: format!(
                                    "method `{}` should return `{}` but has no return type",
                                    required_method.name,
                                    type_to_string(&required_method.return_type.as_ref().unwrap())
                                ),
                                lang_tag: impl_.lang_tag.clone(),
                                line: impl_.line,
                            });
                        }
                    }
                }
            }
        }
    }

    errors
}

/// Convert Type to human-readable string
fn type_to_string(ty: &Type) -> String {
    match ty {
        Type::Primitive(prim) => match prim {
            PrimitiveType::Bool => "bool".to_string(),
            PrimitiveType::U8 => "u8".to_string(),
            PrimitiveType::U16 => "u16".to_string(),
            PrimitiveType::U32 => "u32".to_string(),
            PrimitiveType::U64 => "u64".to_string(),
            PrimitiveType::I8 => "i8".to_string(),
            PrimitiveType::I16 => "i16".to_string(),
            PrimitiveType::I32 => "i32".to_string(),
            PrimitiveType::I64 => "i64".to_string(),
            PrimitiveType::F32 => "f32".to_string(),
            PrimitiveType::F64 => "f64".to_string(),
            PrimitiveType::String => "string".to_string(),
            PrimitiveType::Bytes => "bytes".to_string(),
        },
        Type::Named(name) => name.clone(),
        Type::Generic(name, params) => {
            let inner: Vec<String> = params.iter().map(type_to_string).collect();
            format!("{}<{}>", name, inner.join(", "))
        }
        Type::Tuple(types) => {
            let inner: Vec<String> = types.iter().map(type_to_string).collect();
            format!("({})", inner.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_poly;

    #[test]
    fn test_verify_valid_implementation() {
        let source = r#"
#[interface] {
    trait Processor {
        fn process(data: list<i32>) -> i32;
        fn name() -> string;
    }
}

#[python] {
    @implements(Processor)
    class PyProcessor:
        def process(self, data: list[int]) -> int:
            return sum(data)

        def name(self) -> str:
            return "PyProcessor"
}
"#;

        let parsed = parse_poly(source).unwrap();
        let errors = verify_implementations(&parsed);

        assert!(errors.is_empty(), "Expected no errors but got: {:?}", errors);
    }

    #[test]
    fn test_verify_missing_method() {
        let source = r#"
#[interface] {
    trait Processor {
        fn process(data: list<i32>) -> i32;
        fn name() -> string;
    }
}

#[python] {
    @implements(Processor)
    class PyProcessor:
        def process(self, data: list[int]) -> int:
            return sum(data)
        # Missing name() method!
}
"#;

        let parsed = parse_poly(source).unwrap();
        let errors = verify_implementations(&parsed);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("missing required method `name`"));
    }

    #[test]
    fn test_verify_undefined_trait() {
        let source = r#"
#[python] {
    @implements(NonExistentTrait)
    class MyClass:
        def foo(self):
            pass
}
"#;

        let parsed = parse_poly(source).unwrap();
        let errors = verify_implementations(&parsed);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("not defined"));
    }

    #[test]
    fn test_verify_typescript_implementation() {
        let source = r#"
#[interface] {
    trait Filter {
        fn filter(data: list<i32>, threshold: i32) -> list<i32>;
    }
}

#[typescript] {
    @implements(Filter)
    class TsFilter {
        filter(data: number[], threshold: number): number[] {
            return data.filter(x => x >= threshold);
        }
    }
}
"#;

        let parsed = parse_poly(source).unwrap();
        let errors = verify_implementations(&parsed);

        assert!(errors.is_empty(), "Expected no errors but got: {:?}", errors);
    }

    #[test]
    fn test_verify_javascript_no_types() {
        let source = r#"
#[interface] {
    trait Processor {
        fn process(data: list<i32>) -> i32;
    }
}

#[javascript] {
    @implements(Processor)
    class JsProcessor {
        process(data) {
            return data.reduce((a, b) => a + b, 0);
        }
    }
}
"#;

        let parsed = parse_poly(source).unwrap();
        let errors = verify_implementations(&parsed);

        // JS has no type annotations, so we can't verify types - just method presence
        assert!(errors.is_empty(), "Expected no errors but got: {:?}", errors);
    }
}
