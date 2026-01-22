//! JavaScript macro implementation

use proc_macro2::TokenStream;
use quote::quote;

pub fn expand(input: TokenStream) -> TokenStream {
    let code = input.to_string();
    let code = code.trim();
    let code = if code.starts_with('{') && code.ends_with('}') {
        &code[1..code.len() - 1]
    } else {
        code
    };
    let code = code.trim();

    quote! {
        {
            use polyglot_runtime::javascript::JsRuntime;
            use polyglot_runtime::marshal::FromJs;

            let __js = JsRuntime::get();
            let __result = __js.eval(#code);

            match __result {
                Ok(val) => FromJs::from_js(val),
                Err(e) => panic!("JavaScript error: {}", e),
            }
        }
    }
}
