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

pub fn generate_rust(items: &[InterfaceItem]) -> String {
    let mut out = String::new();
    out.push_str("// Auto-generated from interface block\n\n");

    for item in items {
        match item {
            InterfaceItem::Struct(s) => {
                out.push_str(&generate_rust_struct(s));
            }
            InterfaceItem::Enum(_e) => {
                // out.push_str(&generate_rust_enum(e));
                out.push_str("// Enum support pending\n");
            }
            InterfaceItem::TypeAlias(name, ty) => {
                out.push_str(&format!("pub type {} = {};\n\n", name, type_to_rust(ty)));
            }
        }
    }

    out
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
            PrimitiveType::String => "String".to_string(), // Simplified for now, was WasmString
            PrimitiveType::Bytes => "Vec<u8>".to_string(), // Simplified was WasmBytes
        },
        Type::Named(name) => name.clone(),
        Type::Generic(name, params) => {
            let params_str: Vec<_> = params.iter().map(type_to_rust).collect();
            match name.as_str() {
                "list" => format!("Vec<{}>", params_str.join(", ")), // Rust list is Vec
                "option" => format!("Option<{}>", params_str.join(", ")),
                "result" => format!("Result<{}>", params_str.join(", ")),
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
    out.push_str("// Auto-generated WIT\n\n");

    for item in items {
        match item {
            InterfaceItem::Struct(s) => {
                out.push_str(&format!("record {} {{\n", to_kebab(&s.name)));
                for field in &s.fields {
                    out.push_str(&format!(
                        "    {}: {},\n",
                        to_kebab(&field.name),
                        type_to_wit(&field.ty)
                    ));
                }
                out.push_str("}\n\n");
            }
            // ... enums, type aliases
            _ => {}
        }
    }

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
