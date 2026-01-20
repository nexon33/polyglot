use super::parser::*;

pub fn generate_python(items: &[InterfaceItem]) -> String {
    let mut out = String::new();
    out.push_str("from dataclasses import dataclass\n");
    out.push_str("from typing import List, Optional, Tuple\n\n");

    for item in items {
        match item {
            InterfaceItem::Struct(s) => {
                out.push_str(&generate_python_struct(s));
            }
            InterfaceItem::Enum(e) => {
                out.push_str(&generate_python_enum(e));
            }
            InterfaceItem::TypeAlias(name, ty) => {
                out.push_str(&format!("{} = {}\n\n", name, type_to_python(ty)));
            }
            InterfaceItem::Function(_) => {
                // Python doesn't need extern imports, functions are in scope
            }
            InterfaceItem::TypeDecl(td) => {
                // Generate Python type import from the type definition
                if let Some(py_impl) = &td.python_impl {
                    out.push_str(&format!("# Type import: {} = {}\n", td.name, py_impl));
                }
            }
        }
    }

    out
}

fn generate_python_struct(s: &StructDef) -> String {
    let mut out = String::new();
    out.push_str("@dataclass\n");
    out.push_str(&format!("class {}:\n", s.name));

    if s.fields.is_empty() {
        out.push_str("    pass\n");
    } else {
        for field in &s.fields {
            out.push_str(&format!(
                "    {}: {}\n",
                field.name,
                type_to_python(&field.ty)
            ));
        }
    }
    out.push_str("\n");
    out
}

fn generate_python_enum(e: &EnumDef) -> String {
    // For now, enums can be represented as TypeAliases of Unions or separate classes
    // Python doesn't have Rust-like enums natively.
    // We'll treat them as a minimal implementation or skip for now
    format!(
        "# Enum {} not fully supported in Python generator yet\n",
        e.name
    )
}

fn type_to_python(ty: &Type) -> String {
    match ty {
        Type::Primitive(p) => match p {
            PrimitiveType::Bool => "bool".to_string(),
            PrimitiveType::U8
            | PrimitiveType::U16
            | PrimitiveType::U32
            | PrimitiveType::U64
            | PrimitiveType::I8
            | PrimitiveType::I16
            | PrimitiveType::I32
            | PrimitiveType::I64 => "int".to_string(),
            PrimitiveType::F32 | PrimitiveType::F64 => "float".to_string(),
            PrimitiveType::String => "str".to_string(),
            PrimitiveType::Bytes => "bytes".to_string(),
        },
        Type::Named(name) => name.clone(),
        Type::Generic(name, params) => {
            let params_str: Vec<_> = params.iter().map(type_to_python).collect();
            match name.as_str() {
                "list" => format!("List[{}]", params_str.join(", ")),
                "option" => format!("Optional[{}]", params_str.join(", ")),
                _ => format!("{}[{}]", name, params_str.join(", ")),
            }
        }
        Type::Tuple(types) => {
            let types_str: Vec<_> = types.iter().map(type_to_python).collect();
            format!("Tuple[{}]", types_str.join(", "))
        }
    }
}

/// Generate Rust code from interface items
/// source_code: The actual Rust source to check which functions are implemented
pub fn generate_rust_with_source(items: &[InterfaceItem], source_code: &str) -> String {
    let mut out = String::new();

    out.push_str("// Auto-generated from interface block\n\n");

    // FIRST: Generate type declarations (needed before they're used in functions)
    for item in items {
        if let InterfaceItem::TypeDecl(td) = item {
            if let Some(rust_impl) = &td.rust_impl {
                out.push_str(&format!("pub type {} = {};\n", td.name, rust_impl));
            }
        }
        if let InterfaceItem::TypeAlias(name, ty) = item {
            out.push_str(&format!("pub type {} = {};\n\n", name, type_to_rust(ty)));
        }
    }
    out.push_str("\n");

    // Collect functions for export wrapper generation
    let functions: Vec<_> = items
        .iter()
        .filter_map(|item| {
            if let InterfaceItem::Function(f) = item {
                Some(f)
            } else {
                None
            }
        })
        .collect();

    // Generate export wrappers only for functions that are actually implemented
    if !functions.is_empty() {
        out.push_str("// Auto-generated export wrappers\n");
        for f in &functions {
            // Check if this function is defined in the source code
            let fn_pattern = format!("fn {}(", f.name);
            if !source_code.contains(&fn_pattern) {
                // Function not implemented in Rust, skip wrapper
                continue;
            }

            let params: Vec<String> = f
                .params
                .iter()
                .map(|(name, ty)| format!("{}: {}", name, type_to_rust(ty)))
                .collect();
            let param_names: Vec<&str> = f.params.iter().map(|(name, _)| name.as_str()).collect();
            let ret = match &f.return_type {
                Some(ty) => format!(" -> {}", type_to_rust(ty)),
                None => String::new(),
            };

            // Generate #[no_mangle] wrapper that calls the user's implementation
            out.push_str(&format!(
                "#[no_mangle]\npub extern \"C\" fn __export_{}({}){} {{\n    {}({})\n}}\n\n",
                f.name,
                params.join(", "),
                ret,
                f.name,
                param_names.join(", ")
            ));
        }
    }

    for item in items {
        match item {
            InterfaceItem::Struct(s) => {
                out.push_str(&generate_rust_struct(s));
            }
            InterfaceItem::Enum(_e) => {
                out.push_str("// Enum support pending\n");
            }
            InterfaceItem::TypeAlias(_, _) => {
                // Already handled at start
            }
            InterfaceItem::Function(_) => {
                // Already handled in export wrapper generation
            }
            InterfaceItem::TypeDecl(_) => {
                // Already handled at start
            }
        }
    }
    out
}

/// Legacy function for compatibility
pub fn generate_rust(items: &[InterfaceItem]) -> String {
    generate_rust_with_source(items, "")
}

/// Generate Rust bridge code to call Python functions via RustPython
/// python_source: The Python code to embed
/// rust_source: Rust source to check which functions need Python bridges
pub fn generate_python_bridge(
    items: &[InterfaceItem],
    python_source: &str,
    rust_source: &str,
) -> String {
    let mut out = String::new();

    // Check if Python has a main function
    let has_python_main = python_source.contains("def main(");

    // Check if we have any Python functions to bridge
    let functions: Vec<_> = items
        .iter()
        .filter_map(|item| {
            if let InterfaceItem::Function(f) = item {
                Some(f)
            } else {
                None
            }
        })
        .collect();

    let python_functions: Vec<_> = functions
        .iter()
        .filter(|f| {
            // Check if function is NOT in Rust source (so it must be in Python)
            let fn_pattern = format!("fn {}(", f.name);
            !rust_source.contains(&fn_pattern)
        })
        .collect();

    if python_functions.is_empty() && !has_python_main && python_source.trim().is_empty() {
        return out;
    }

    // For now, generate simple stub bridges that simulate Python calls
    // Full RustPython integration would be added here
    out.push_str("\n// Python-Rust Bridge (Stub for cross-language demo)\n");
    out.push_str("// In full implementation, these would call RustPython interpreter\n\n");

    // Generate __python_main if Python has a main function
    if has_python_main {
        out.push_str("// Python main entry point bridge\n");
        out.push_str("fn __python_main() {\n");
        out.push_str("    println!(\"[Python Bridge] Calling Python main()\");\n");
        out.push_str("    // In full implementation, this would:\n");
        out.push_str("    // 1. Initialize RustPython interpreter\n");
        out.push_str("    // 2. Load the embedded Python code\n");
        out.push_str("    // 3. Call main()\n");
        out.push_str("}\n\n");
    }

    // Generate bridge functions for each Python function
    for f in &python_functions {
        out.push_str(&format!("// Bridge to Python function: {}\n", f.name));

        let params: Vec<String> = f
            .params
            .iter()
            .map(|(name, ty)| format!("{}: {}", name, type_to_rust(ty)))
            .collect();
        let ret = match &f.return_type {
            Some(ty) => format!(" -> {}", type_to_rust(ty)),
            None => String::new(),
        };

        out.push_str(&format!("fn {}({}){} {{\n", f.name, params.join(", "), ret));
        out.push_str(&format!(
            "    println!(\"[Python Bridge] Calling: {}\");\n",
            f.name
        ));

        // Generate appropriate return value based on return type
        if let Some(ty) = &f.return_type {
            let default_val = default_value_for_type(ty);
            out.push_str(&format!("    {}\n", default_val));
        }
        out.push_str("}\n\n");
    }

    out
}

/// Generate a default value expression for a given type (used for Python bridge stubs)
fn default_value_for_type(ty: &Type) -> String {
    match ty {
        Type::Primitive(p) => match p {
            PrimitiveType::Bool => "false".to_string(),
            PrimitiveType::U8 | PrimitiveType::U16 | PrimitiveType::U32 | PrimitiveType::U64 => {
                "0".to_string()
            }
            PrimitiveType::I8 | PrimitiveType::I16 | PrimitiveType::I32 | PrimitiveType::I64 => {
                "0".to_string()
            }
            PrimitiveType::F32 | PrimitiveType::F64 => "0.0".to_string(),
            PrimitiveType::String => "String::new()".to_string(),
            PrimitiveType::Bytes => "Vec::new()".to_string(),
        },
        Type::Named(name) => match name.as_str() {
            "str" | "String" => "String::new()".to_string(),
            "int" | "i64" => "0i64".to_string(),
            "float" | "f64" => "0.0f64".to_string(),
            "bool" => "false".to_string(),
            "None" | "NoneType" => "()".to_string(),
            "tuple" | "dict" | "list" | "set" | "Any" | "object" => {
                "Default::default()".to_string()
            }
            _ => format!("{}::default()", name),
        },
        Type::Generic(name, _params) => match name.as_str() {
            "list" | "List" | "Vec" => "Vec::new()".to_string(),
            "dict" | "Dict" | "HashMap" => "std::collections::HashMap::new()".to_string(),
            "set" | "Set" | "HashSet" => "std::collections::HashSet::new()".to_string(),
            "option" | "Optional" | "Option" => "None".to_string(),
            _ => "Default::default()".to_string(),
        },
        Type::Tuple(types) => {
            if types.is_empty() {
                "()".to_string()
            } else {
                let defaults: Vec<String> = types.iter().map(default_value_for_type).collect();
                format!("({})", defaults.join(", "))
            }
        }
    }
}

fn generate_rust_struct(s: &StructDef) -> String {
    let mut out = String::new();
    out.push_str("#[repr(C)]\n");
    out.push_str("#[derive(Debug, Clone)]\n");
    out.push_str(&format!("pub struct {} {{\n", s.name));

    for field in &s.fields {
        out.push_str(&format!(
            "    pub {}: {},\n",
            field.name,
            type_to_rust(&field.ty)
        ));
    }

    out.push_str("}\n\n");
    out
}

fn type_to_rust(ty: &Type) -> String {
    match ty {
        Type::Primitive(p) => match p {
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
            PrimitiveType::String => "String".to_string(),
            PrimitiveType::Bytes => "Vec<u8>".to_string(),
        },
        Type::Named(name) => {
            // Map Python types to Rust equivalents
            match name.as_str() {
                // Python basic types
                "str" => "String".to_string(),
                "int" => "i64".to_string(),
                "float" => "f64".to_string(),
                "bool" => "bool".to_string(),
                "bytes" => "Vec<u8>".to_string(),
                "None" | "NoneType" => "()".to_string(),

                // Python collection types (unparameterized)
                "tuple" => "(Vec<serde_json::Value>,)".to_string(), // Generic tuple as Vec
                "dict" => "std::collections::HashMap<String, serde_json::Value>".to_string(),
                "list" => "Vec<serde_json::Value>".to_string(),
                "set" => "std::collections::HashSet<serde_json::Value>".to_string(),

                // Python typing module aliases
                "Any" => "serde_json::Value".to_string(),
                "object" => "serde_json::Value".to_string(),

                // Keep other named types as-is (user-defined types)
                _ => name.clone(),
            }
        }
        Type::Generic(name, params) => {
            let params_str: Vec<_> = params.iter().map(type_to_rust).collect();
            match name.as_str() {
                // Python list[T] -> Rust Vec<T>
                "list" | "List" => format!("Vec<{}>", params_str.join(", ")),
                // Python dict[K, V] -> Rust HashMap<K, V>
                "dict" | "Dict" => {
                    if params_str.len() >= 2 {
                        format!(
                            "std::collections::HashMap<{}, {}>",
                            params_str[0], params_str[1]
                        )
                    } else {
                        "std::collections::HashMap<String, serde_json::Value>".to_string()
                    }
                }
                // Python tuple[T, ...] -> Rust (T, ...)
                "tuple" | "Tuple" => format!("({})", params_str.join(", ")),
                // Python set[T] -> Rust HashSet<T>
                "set" | "Set" => format!("std::collections::HashSet<{}>", params_str.join(", ")),
                // Python Optional[T] -> Rust Option<T>
                "option" | "Optional" => format!("Option<{}>", params_str.join(", ")),
                // Python Result, Rust Result
                "result" | "Result" => format!("Result<{}>", params_str.join(", ")),
                // Pass through other generics
                _ => format!("{}<{}>", name, params_str.join(", ")),
            }
        }
        Type::Tuple(types) => {
            let types_str: Vec<_> = types.iter().map(type_to_rust).collect();
            format!("({})", types_str.join(", "))
        }
    }
}

pub fn generate_wit(items: &[InterfaceItem]) -> String {
    let mut out = String::new();

    // WIT package header
    out.push_str("package polyglot:interface@0.1.0;\n\n");

    // Interface definition with all functions
    out.push_str("interface exports {\n");

    for item in items {
        match item {
            InterfaceItem::Struct(s) => {
                out.push_str(&format!("    record {} {{\n", to_kebab(&s.name)));
                for field in &s.fields {
                    out.push_str(&format!(
                        "        {}: {},\n",
                        to_kebab(&field.name),
                        type_to_wit(&field.ty)
                    ));
                }
                out.push_str("    }\n\n");
            }
            InterfaceItem::Function(f) => {
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|(name, ty)| format!("{}: {}", to_kebab(name), type_to_wit(ty)))
                    .collect();
                let ret = match &f.return_type {
                    Some(ty) => format!(" -> {}", type_to_wit(ty)),
                    None => String::new(),
                };
                out.push_str(&format!(
                    "    {}: func({}){};\n",
                    to_kebab(&f.name),
                    params.join(", "),
                    ret
                ));
            }
            _ => {}
        }
    }

    out.push_str("}\n\n");

    // World definition
    out.push_str("world polyglot {\n");
    out.push_str("    export exports;\n");
    out.push_str("}\n");

    out
}

fn type_to_wit(ty: &Type) -> String {
    match ty {
        Type::Primitive(p) => match p {
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
            let params_str: Vec<_> = params.iter().map(type_to_wit).collect();
            format!("{}<{}>", to_kebab(name), params_str.join(", "))
        }
        Type::Tuple(types) => {
            let types_str: Vec<_> = types.iter().map(type_to_wit).collect();
            format!("tuple<{}>", types_str.join(", "))
        }
    }
}

fn to_kebab(s: &str) -> String {
    // Convert CamelCase to kebab-case
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('-');
        }
        result.push(c.to_lowercase().next().unwrap());
    }
    result
}
