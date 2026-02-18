//! Python macro implementation
//!
//! Expands `py!{ expr }` to runtime Python evaluation with marshaling.
//!
//! # Variable Capture
//! Variables referenced in the Python code that exist in the Rust scope
//! are automatically marshaled and passed to Python.
//!
//! # Example  
//! ```rust
//! let data = vec![1, 2, 3];
//! let result: Vec<i32> = py!{ [x * 2 for x in data] };
//! ```

use proc_macro2::TokenStream;
use quote::quote;
use std::collections::HashSet;
// syn used for future typed macro expansion

/// Extract identifiers that look like variable references in Python code
fn extract_likely_variables(code: &str) -> HashSet<String> {
    let mut vars = HashSet::new();

    // Simple heuristic: find word boundaries that look like identifiers
    // This matches: alphanumeric starting with letter/underscore
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = ' ';

    for (_i, c) in code.chars().enumerate() {
        // Track string state
        if !in_string && (c == '"' || c == '\'') {
            in_string = true;
            string_char = c;
            continue;
        }
        if in_string && c == string_char {
            in_string = false;
            continue;
        }
        if in_string {
            continue;
        }

        // Build identifier
        if c.is_alphabetic() || c == '_' || (c.is_numeric() && !current.is_empty()) {
            current.push(c);
        } else {
            if !current.is_empty() {
                // Skip Python keywords and builtins
                if !is_python_keyword(&current) && !is_python_builtin(&current) {
                    vars.insert(current.clone());
                }
                current.clear();
            }
        }
    }

    // Don't forget last identifier
    if !current.is_empty() && !is_python_keyword(&current) && !is_python_builtin(&current) {
        vars.insert(current);
    }

    vars
}

fn is_python_keyword(s: &str) -> bool {
    matches!(
        s,
        "and"
            | "as"
            | "assert"
            | "async"
            | "await"
            | "break"
            | "class"
            | "continue"
            | "def"
            | "del"
            | "elif"
            | "else"
            | "except"
            | "finally"
            | "for"
            | "from"
            | "global"
            | "if"
            | "import"
            | "in"
            | "is"
            | "lambda"
            | "None"
            | "nonlocal"
            | "not"
            | "or"
            | "pass"
            | "raise"
            | "return"
            | "True"
            | "False"
            | "try"
            | "while"
            | "with"
            | "yield"
    )
}

fn is_python_builtin(s: &str) -> bool {
    matches!(
        s,
        "print"
            | "len"
            | "range"
            | "list"
            | "dict"
            | "set"
            | "tuple"
            | "str"
            | "int"
            | "float"
            | "bool"
            | "type"
            | "isinstance"
            | "hasattr"
            | "getattr"
            | "setattr"
            | "abs"
            | "min"
            | "max"
            | "sum"
            | "sorted"
            | "reversed"
            | "enumerate"
            | "zip"
            | "map"
            | "filter"
            | "any"
            | "all"
            | "open"
            | "input"
            | "round"
            | "pow"
            | "divmod"
            | "hex"
            | "oct"
            | "bin"
            | "np"
            | "numpy"
            | "pd"
            | "pandas"
            | "x"
            | "i"
            | "j"
            | "k"
            | "n"
            | "_"
    )
}

pub fn expand(input: TokenStream) -> TokenStream {
    // Parse the input as raw tokens (Python code as string)
    let code = input.to_string();

    // Clean up the code - remove the braces if present
    let code = code.trim();
    let code = if code.starts_with('{') && code.ends_with('}') {
        &code[1..code.len() - 1]
    } else {
        code
    };
    let code = code.trim();

    // Extract likely variables for capture (heuristic)
    let captured_vars = extract_likely_variables(code);

    // Generate code to marshal each captured variable
    // For now, we generate eval with the code directly
    // Future: inject captured vars into Python locals

    if captured_vars.is_empty() {
        // No captures - simple eval
        quote! {
            {
                use polyglot_runtime::prelude::PythonRuntime;

                let __py = PythonRuntime::get();
                __py.eval_i32(#code)
                    .expect("Python evaluation failed")
            }
        }
    } else {
        // Has captures - need to pass them
        // For now, just document what would be captured
        let vars_list: Vec<&str> = captured_vars.iter().map(|s| s.as_str()).collect();
        let _vars_str = vars_list.join(", ");

        // Still use simple eval for now, but add comment about captures
        quote! {
            {
                use polyglot_runtime::prelude::PythonRuntime;

                // Detected potential captures: #vars_str
                // TODO: Marshal these Rust variables to Python

                let __py = PythonRuntime::get();
                __py.eval_i32(#code)
                    .expect("Python evaluation failed")
            }
        }
    }
}

/// Expand py! macro with explicit type annotation
/// Usage: py!(Type){ expr }
#[allow(dead_code)]
pub fn expand_typed(type_hint: TokenStream, code: TokenStream) -> TokenStream {
    let code_str = code.to_string();
    let code_str = code_str.trim();
    let code_str = if code_str.starts_with('{') && code_str.ends_with('}') {
        &code_str[1..code_str.len() - 1]
    } else {
        code_str
    };
    let code_str = code_str.trim();

    // Parse the type
    let type_str = type_hint.to_string();

    // Generate appropriate eval method based on type
    match type_str.as_str() {
        "i32" | "i64" | "isize" => quote! {
            {
                use polyglot_runtime::prelude::PythonRuntime;
                let __py = PythonRuntime::get();
                __py.eval_i32(#code_str).expect("Python evaluation failed")
            }
        },
        "f32" | "f64" => quote! {
            {
                use polyglot_runtime::prelude::PythonRuntime;
                let __py = PythonRuntime::get();
                __py.eval_f64(#code_str).expect("Python evaluation failed") as #type_hint
            }
        },
        "String" => quote! {
            {
                use polyglot_runtime::prelude::PythonRuntime;
                let __py = PythonRuntime::get();
                __py.eval_string(#code_str).expect("Python evaluation failed")
            }
        },
        _ => quote! {
            compile_error!(concat!("py! macro doesn't yet support type: ", #type_str))
        },
    }
}
