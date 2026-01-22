//! Python macro implementation
//!
//! Expands `py!{ expr }` to runtime Python evaluation with marshaling.

use proc_macro2::TokenStream;
use quote::quote;

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

    // TODO: Analyze captured variables from surrounding Rust scope
    // For now, just embed the code as a string literal

    quote! {
        {
            use polyglot_runtime::python::PythonRuntime;
            use polyglot_runtime::marshal::FromPython;

            let __py = PythonRuntime::get();
            let __result = __py.eval(#code);

            match __result {
                Ok(val) => FromPython::from_python(val),
                Err(e) => panic!("Python error: {}", e),
            }
        }
    }
}
