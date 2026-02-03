// Generate WIT interface from parsed file
//
// Phase 26: Now supports trait definitions from #[interface] blocks
// Traits compile to WIT interfaces that can be implemented by any language

use crate::interface::parser::{InterfaceItem, TraitDef, Type, PrimitiveType};
use crate::languages::find_language;
use crate::parser::ParsedFile;
use crate::types::WitType;

#[derive(Debug)]
pub struct WitGenError(pub String);

impl std::fmt::Display for WitGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WIT generation error: {}", self.0)
    }
}

impl std::error::Error for WitGenError {}

/// Generate WIT from a parsed file, extracting package name from filename
pub fn generate_wit_for_file(parsed: &ParsedFile, filename: &str) -> Result<String, WitGenError> {
    // Extract package name from filename (e.g., "chaos.poly" -> "chaos")
    let package_name = std::path::Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("module")
        .to_lowercase()
        .replace('-', "_");

    generate_wit_with_package(parsed, &package_name)
}

/// Generate WIT with a specific package name
pub fn generate_wit_with_package(parsed: &ParsedFile, package_name: &str) -> Result<String, WitGenError> {
    let mut wit = String::new();

    wit.push_str(&format!("package polyglot:{}@0.1.0;\n\n", package_name));

    // Phase 26: Generate interfaces from trait definitions
    let traits = extract_traits(parsed);
    for trait_def in &traits {
        wit.push_str(&generate_interface_from_trait(trait_def));
        wit.push('\n');
    }

    // Generate world that exports all trait interfaces
    if !traits.is_empty() {
        wit.push_str(&format!("world {} {{\n", package_name));
        for trait_def in &traits {
            wit.push_str(&format!("    export {};\n", to_kebab(&trait_def.name)));
        }
        wit.push_str("}\n");
    }

    Ok(wit)
}

/// Extract trait definitions from parsed interfaces
fn extract_traits(parsed: &ParsedFile) -> Vec<TraitDef> {
    parsed.interfaces.iter()
        .filter_map(|item| match item {
            InterfaceItem::Trait(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

/// Generate a WIT interface from a trait definition
fn generate_interface_from_trait(trait_def: &TraitDef) -> String {
    let mut wit = String::new();

    // Doc comment
    if let Some(doc) = &trait_def.doc {
        wit.push_str(&format!("/// {}\n", doc));
    }

    wit.push_str(&format!("interface {} {{\n", to_kebab(&trait_def.name)));

    for method in &trait_def.methods {
        wit.push_str(&format!("    {}: func(", to_kebab(&method.name)));

        let params: Vec<String> = method.params.iter()
            .map(|(name, ty)| format!("{}: {}", to_kebab(name), interface_type_to_wit(ty)))
            .collect();
        wit.push_str(&params.join(", "));

        wit.push(')');
        if let Some(ret) = &method.return_type {
            wit.push_str(&format!(" -> {}", interface_type_to_wit(ret)));
        }
        wit.push_str(";\n");
    }

    wit.push_str("}\n");
    wit
}

/// Convert interface Type to WIT type string
fn interface_type_to_wit(ty: &Type) -> String {
    match ty {
        Type::Primitive(prim) => match prim {
            PrimitiveType::Bool => "bool".to_string(),
            PrimitiveType::U8 => "u8".to_string(),
            PrimitiveType::U16 => "u16".to_string(),
            PrimitiveType::U32 => "u32".to_string(),
            PrimitiveType::U64 => "u64".to_string(),
            PrimitiveType::I8 => "s8".to_string(),
            PrimitiveType::I16 => "s16".to_string(),
            PrimitiveType::I32 => "s32".to_string(),
            PrimitiveType::I64 => "s64".to_string(),
            PrimitiveType::F32 => "float32".to_string(),
            PrimitiveType::F64 => "float64".to_string(),
            PrimitiveType::String => "string".to_string(),
            PrimitiveType::Bytes => "list<u8>".to_string(),
        },
        Type::Named(name) => to_kebab(name),
        Type::Generic(name, params) => {
            let inner: Vec<String> = params.iter().map(interface_type_to_wit).collect();
            format!("{}<{}>", to_kebab(name), inner.join(", "))
        },
        Type::Tuple(types) => {
            let inner: Vec<String> = types.iter().map(interface_type_to_wit).collect();
            format!("tuple<{}>", inner.join(", "))
        },
    }
}

pub fn generate_wit(parsed: &ParsedFile) -> Result<String, WitGenError> {
    let mut wit = String::new();

    wit.push_str("package pyrs:generated@0.1.0;\n\n");

    // Common types
    wit.push_str("interface types {\n");
    wit.push_str("    type hash32 = list<u8>;\n");
    wit.push_str("    type bytes = list<u8>;\n");
    wit.push_str("    \n");
    wit.push_str("    variant py-value {\n");
    wit.push_str("        none,\n");
    wit.push_str("        bool(bool),\n");
    wit.push_str("        int(s64),\n");
    wit.push_str("        float(float64),\n");
    wit.push_str("        str(string),\n");
    wit.push_str("        bytes(list<u8>),\n");
    wit.push_str("        list(list<py-value>),\n");
    wit.push_str("    }\n");
    wit.push_str("}\n\n");

    // Collect exports by language tag
    // We'll use a simple map: "py" -> Vec<FunctionSig>, "rs" -> Vec<FunctionSig>
    // Or just iterate and collect.

    let mut py_funcs = Vec::new();
    let mut rs_funcs = Vec::new();

    for block in &parsed.blocks {
        if let Some(lang) = find_language(&block.lang_tag) {
            let sigs = lang
                .parse_signatures(&block.code)
                .map_err(|e| WitGenError(format!("Error parsing signatures in block: {:?}", e)))?;

            match lang.tag() {
                "py" => py_funcs.extend(sigs),
                "rs" => rs_funcs.extend(sigs),
                _ => {} // Unknown languages ignored for now
            }
        }
    }

    if !py_funcs.is_empty() {
        wit.push_str("interface python-exports {\n");
        wit.push_str("    use types.{py-value, hash32, bytes};\n\n");

        for func in &py_funcs {
            wit.push_str(&format!("    {}: func(", to_kebab(&func.name)));

            let params: Vec<String> = func
                .params
                .iter()
                .map(|p| format!("{}: {}", to_kebab(&p.name), type_to_wit(&p.ty)))
                .collect();
            wit.push_str(&params.join(", "));

            wit.push_str(")");
            if let Some(ret) = &func.returns {
                wit.push_str(&format!(" -> {}", type_to_wit(ret)));
            }
            wit.push_str(";\n");
        }

        wit.push_str("}\n\n");
    }

    if !rs_funcs.is_empty() {
        wit.push_str("interface rust-exports {\n");
        wit.push_str("    use types.{py-value, hash32, bytes};\n\n");

        for func in &rs_funcs {
            wit.push_str(&format!("    {}: func(", to_kebab(&func.name)));

            let params: Vec<String> = func
                .params
                .iter()
                .map(|p| format!("{}: {}", to_kebab(&p.name), type_to_wit(&p.ty)))
                .collect();
            wit.push_str(&params.join(", "));

            wit.push_str(")");
            if let Some(ret) = &func.returns {
                wit.push_str(&format!(" -> {}", type_to_wit(ret)));
            }
            wit.push_str(";\n");
        }

        wit.push_str("}\n\n");
    }

    // World
    wit.push_str("world pyrs-module {\n");
    wit.push_str("    import types;\n");
    if !py_funcs.is_empty() {
        wit.push_str("    export python-exports;\n");
    }
    if !rs_funcs.is_empty() {
        wit.push_str("    export rust-exports;\n");
    }
    wit.push_str("}\n");

    Ok(wit)
}

fn to_kebab(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('-');
            }
            result.push(c.to_lowercase().next().unwrap());
        } else if c == '_' {
            result.push('-');
        } else {
            result.push(c);
        }
    }
    result
}

fn type_to_wit(ty: &WitType) -> String {
    match ty {
        WitType::Unit => "unit".to_string(),
        WitType::Bool => "bool".to_string(),
        WitType::S32 => "s32".to_string(),
        WitType::S64 => "s64".to_string(),
        WitType::U8 => "u8".to_string(),
        WitType::U32 => "u32".to_string(),
        WitType::U64 => "u64".to_string(),
        WitType::F32 => "float32".to_string(),
        WitType::F64 => "float64".to_string(),
        WitType::String => "string".to_string(),
        WitType::Bytes => "list<u8>".to_string(),
        WitType::List(inner) => format!("list<{}>", type_to_wit(inner)),
        WitType::Dict(k, v) => format!("list<tuple<{}, {}>>", type_to_wit(k), type_to_wit(v)),
        WitType::Option(inner) => format!("option<{}>", type_to_wit(inner)),
        WitType::Result(ok, err) => format!("result<{}, {}>", type_to_wit(ok), type_to_wit(err)),
        WitType::Tuple(parts) => {
            let inner: Vec<_> = parts.iter().map(type_to_wit).collect();
            format!("tuple<{}>", inner.join(", "))
        }
        WitType::Record(name) => name.clone(),
        WitType::Tensor(inner) => format!("list<{}>", type_to_wit(inner)),
        _ => "any".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_poly;

    #[test]
    fn test_wit_generation() {
        // Test WIT generation from Rust blocks
        // TODO: Add Python function signature parsing for WIT generation
        let source = r#"
#[rust] {
    fn hash(input: &[u8]) -> [u8; 32] {
        todo!()
    }

    fn process(data: Vec<i32>) -> i32 {
        data.iter().sum()
    }
}
"#;

        let parsed = parse_poly(source).unwrap();
        let wit = generate_wit(&parsed).unwrap();

        println!("{}", wit);

        assert!(wit.contains("interface rust-exports"));
        assert!(wit.contains("hash: func"));
        assert!(wit.contains("process: func"));
    }

    #[test]
    fn test_trait_to_wit_generation() {
        let source = r#"
#[interface] {
    /// Data processing contract
    trait Processor {
        fn process(data: list<i32>) -> i32;
        fn name() -> string;
    }

    /// Filtering contract
    trait Filter {
        fn filter(data: list<i32>, threshold: i32) -> list<i32>;
        fn description() -> string;
    }
}
"#;

        let parsed = parse_poly(source).unwrap();
        let wit = generate_wit_for_file(&parsed, "chaos.poly").unwrap();

        println!("Generated WIT:\n{}", wit);

        // Check package
        assert!(wit.contains("package polyglot:chaos@0.1.0"));

        // Check interfaces
        assert!(wit.contains("interface processor"));
        assert!(wit.contains("interface filter"));

        // Check methods
        assert!(wit.contains("process: func(data: list<s32>) -> s32"));
        assert!(wit.contains("name: func() -> string"));
        assert!(wit.contains("filter: func(data: list<s32>, threshold: s32) -> list<s32>"));
        assert!(wit.contains("description: func() -> string"));

        // Check world
        assert!(wit.contains("world chaos"));
        assert!(wit.contains("export processor"));
        assert!(wit.contains("export filter"));
    }

    #[test]
    fn test_python_wit_generation() {
        let source = r#"
#[python] {
    def process(data: list[int]) -> int:
        return sum(data)

    def filter_items(items: list[str], prefix: str) -> list[str]:
        return [x for x in items if x.startswith(prefix)]

    async def fetch_data(url: str) -> dict[str, int]:
        pass
}
"#;

        let parsed = parse_poly(source).unwrap();
        let wit = generate_wit(&parsed).unwrap();

        println!("Python WIT:\n{}", wit);

        // Check Python exports are generated
        assert!(wit.contains("interface python-exports"), "Should have python-exports interface");
        assert!(wit.contains("process: func"), "Should have process function");
        assert!(wit.contains("filter-items: func"), "Should have filter-items function");
        assert!(wit.contains("fetch-data: func"), "Should have fetch-data function");
    }

    #[test]
    fn test_mixed_language_wit_generation() {
        let source = r#"
#[python] {
    def py_process(data: list[int]) -> int:
        return sum(data)
}

#[rust] {
    fn rs_process(data: Vec<i32>) -> i32 {
        data.iter().sum()
    }
}
"#;

        let parsed = parse_poly(source).unwrap();
        let wit = generate_wit(&parsed).unwrap();

        println!("Mixed WIT:\n{}", wit);

        // Check both language exports are generated
        assert!(wit.contains("interface python-exports"), "Should have python-exports");
        assert!(wit.contains("interface rust-exports"), "Should have rust-exports");
        assert!(wit.contains("py-process: func"), "Should have py_process");
        assert!(wit.contains("rs-process: func"), "Should have rs_process");
    }
}
