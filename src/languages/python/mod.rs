use crate::languages::Language;
use crate::parser::{parse_python_params, parse_python_type, ParseError};
use crate::types::{CompileOptions, FunctionSig, Param, WitType};
use anyhow::{anyhow, Result};
use regex::Regex;
use std::fs;
use std::process::Command;

pub struct Python;

impl Python {
    pub fn new() -> Self {
        Self
    }

    fn to_lang_type(&self, wit_type: &WitType, options: &CompileOptions) -> String {
        match wit_type {
            WitType::Bool => "bool".to_string(),
            WitType::S8 => "int".to_string(),
            WitType::U8 => "int".to_string(),
            WitType::S16 => "int".to_string(),
            WitType::U16 => "int".to_string(),
            WitType::S32 => "int".to_string(),
            WitType::U32 => "int".to_string(),
            WitType::S64 => "int".to_string(),
            WitType::U64 => "int".to_string(),
            WitType::F32 => "float".to_string(),
            WitType::F64 => "float".to_string(),
            WitType::String => "str".to_string(),
            WitType::Bytes => "bytes".to_string(),
            WitType::List(inner) => format!("List[{}]", self.to_lang_type(inner, options)),
            WitType::Tuple(inner) => format!(
                "Tuple[{}]",
                inner
                    .iter()
                    .map(|t| self.to_lang_type(t, options))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            WitType::Result(_ok, _err) => "Any".to_string(), // Simplified for now
            WitType::Option(inner) => format!("Optional[{}]", self.to_lang_type(inner, options)),
            WitType::Record(name) => name.clone(),
            WitType::Enum(name) => name.clone(),
            WitType::Variant(name) => name.clone(),
            WitType::Flags(name) => name.clone(),
            WitType::Resource(name) => name.clone(),
            // GridMesh Tensor Support
            WitType::Tensor(_inner) => "gridmesh.Tensor".to_string(),
            WitType::Custom(name) => name.clone(),
            _ => "Any".to_string(),
        }
    }
}

impl Language for Python {
    fn tag(&self) -> &'static str {
        "py"
    }

    fn extension(&self) -> &'static str {
        "py"
    }

    fn compile(&self, source: &str, opts: &CompileOptions) -> Result<Vec<u8>> {
        // Implement compilation logic for Python
        // This creates a Rust wrapper and compiles it using Cargo to pull in rustpython_vm

        let package_name = "poly_py_cell";
        let cargo_toml_content = r#"
[workspace]

[package]
name = "poly_py_cell"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]
path = "lib.rs"

[dependencies]
# We need rustpython-vm to run the code. 
# For demo speed, we might want to use a local path if available, or just the crate.
# Using git dependency for latest WASI support or standard crate.
# We need rustpython-vm to run the code. 
# For demo speed, we might want to use a local path if available, or just the crate.
# Using git dependency for latest WASI support or standard crate.
rustpython-vm = { git = "https://github.com/RustPython/RustPython", default-features = false, features = ["compiler", "codegen"] }

"#;

        fs::write(opts.temp_dir.join("Cargo.toml"), cargo_toml_content)?;

        let mut wrapper = String::new();
        wrapper.push_str("// Auto-generated RustPython wrapper\n");
        // We assume rustpython_vm dependency is available
        wrapper.push_str("use rustpython_vm::{Interpreter, Settings};\n\n");
        wrapper.push_str("static PYTHON_SOURCE: &str = r###\"");
        wrapper.push_str(source);
        wrapper.push_str("\"###;\n\n");

        wrapper.push_str("#[no_mangle]\n");
        wrapper.push_str("pub extern \"C\" fn __pyrs_init() {\n");
        wrapper.push_str("    let settings = Settings::default();\n");
        wrapper.push_str("    let interpreter = Interpreter::with_init(settings, |_vm| {});\n");
        wrapper.push_str("    interpreter.enter(|vm| {\n");
        wrapper.push_str("        let scope = vm.new_scope_with_builtins();\n");
        wrapper.push_str("        let code_obj = vm.compile(PYTHON_SOURCE, rustpython_vm::compiler::Mode::Exec, \"<embedded>\".to_string()).map_err(|err| vm.new_syntax_error(&err, None)).unwrap();\n");
        wrapper.push_str("        let _ = vm.run_code_obj(code_obj, scope);\n");
        wrapper.push_str("    });\n");
        wrapper.push_str("}\n");

        let rs_file = opts.temp_dir.join("lib.rs");
        let should_write = if rs_file.exists() {
            fs::read_to_string(&rs_file)
                .map(|c| c != wrapper)
                .unwrap_or(true)
        } else {
            true
        };

        if should_write {
            fs::write(&rs_file, wrapper)?;
        }

        // Invoke cargo
        let mut cmd = Command::new("cargo");
        cmd.current_dir(&opts.temp_dir)
            .arg("build")
            .arg("--target=wasm32-wasip1")
            .arg("--release");

        // cmd.stdout(Stdio::null()).stderr(Stdio::inherit());

        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow!("Rust wrapper compilation failed"));
        }

        let wasm_path = opts
            .temp_dir
            .join("target")
            .join("wasm32-wasip1")
            .join("release")
            .join("poly_py_cell.wasm");

        Ok(fs::read(&wasm_path)?)
    }

    fn parse_signatures(&self, source: &str) -> Result<Vec<FunctionSig>, ParseError> {
        let mut sigs = Vec::new();

        let func_regex =
            Regex::new(r"(?m)^(async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?\s*:")
                .unwrap();

        for caps in func_regex.captures_iter(source) {
            let is_async = caps.get(1).is_some();
            let name = caps.get(2).unwrap().as_str().to_string();
            let params_str = caps.get(3).unwrap().as_str();
            let returns_str = caps.get(4).map(|m| m.as_str().trim());

            let params = parse_python_params(params_str)?;
            let returns = returns_str.map(|s| parse_python_type(s)).transpose()?;

            sigs.push(FunctionSig {
                name,
                params,
                returns,
                is_async,
            });
        }

        Ok(sigs)
    }

    fn map_type(&self, type_str: &str) -> WitType {
        match parse_python_type(type_str) {
            Ok(t) => t,
            Err(_) => WitType::Custom(type_str.to_string()),
        }
    }
}
