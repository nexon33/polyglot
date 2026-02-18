//! GPU/CUDA macro implementation (stub - reserved syntax)

use proc_macro2::TokenStream;
use quote::quote;

pub fn expand_cuda(input: TokenStream) -> TokenStream {
    let _code = input.to_string();

    quote! {
        compile_error!("cuda!{} macro is reserved but not yet implemented. GPU support coming soon!")
    }
}

pub fn expand_gpu(input: TokenStream) -> TokenStream {
    let _code = input.to_string();

    quote! {
        compile_error!("gpu!{} macro is reserved but not yet implemented. GPU support coming soon!")
    }
}
