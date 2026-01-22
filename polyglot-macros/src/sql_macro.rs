//! SQL macro implementation (stub - reserved syntax)

use proc_macro2::TokenStream;
use quote::quote;

pub fn expand(input: TokenStream) -> TokenStream {
    let code = input.to_string();

    quote! {
        compile_error!("sql!{} macro is reserved but not yet implemented. SQL support coming soon!")
    }
}
