//! TypeScript macro implementation
//!
//! Expands `ts!{ expr }` to runtime TypeScript evaluation.
//! Uses SWC to transpile to JS, then Boa to execute.

use proc_macro2::TokenStream;
use quote::quote;

pub fn expand(input: TokenStream) -> TokenStream {
    let code = input.to_string();

    // Clean up the code - remove the braces if present
    let code = code.trim();
    let code = if code.starts_with('{') && code.ends_with('}') {
        &code[1..code.len() - 1]
    } else {
        code
    };
    let code = code.trim();

    quote! {
        {
            use polyglot_runtime::prelude::TsRuntime;

            let __ts = TsRuntime::get();
            __ts.eval_i32(#code)
                .expect("TypeScript evaluation failed")
        }
    }
}
