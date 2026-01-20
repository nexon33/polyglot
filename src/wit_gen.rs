// Generate WIT interface from parsed file

use crate::languages::find_language;
use crate::parser::ParsedFile;
use crate::types::{FunctionSig, WitType};

#[derive(Debug)]
pub struct WitGenError(pub String);

impl std::fmt::Display for WitGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WIT generation error: {}", self.0)
    }
}

impl std::error::Error for WitGenError {}

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
                _ => {} // Unknown languages ignored for now or we could add generic exports
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
        let source = r#"
#[py]
def process(data: list[str]) -> dict[str, int]:
    pass

#[rs]
fn hash(input: &[u8]) -> [u8; 32] {
    todo!()
}
"#;

        let parsed = parse_poly(source).unwrap();
        let wit = generate_wit(&parsed).unwrap();

        println!("{}", wit);

        assert!(wit.contains("interface python-exports"));
        assert!(wit.contains("interface rust-exports"));
        assert!(wit.contains("process: func"));
        assert!(wit.contains("hash: func"));
    }
}
