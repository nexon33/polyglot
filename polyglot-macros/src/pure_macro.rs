use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse2, ItemFn};

pub fn expand(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = match parse2::<ItemFn>(input) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error(),
    };

    let code = input_fn.block.to_token_stream().to_string();

    // Basic compile-time checks for impurity markers
    let impure_patterns: &[(&str, &str)] = &[
        ("std :: fs ::", "File system access is not allowed in #[pure] functions"),
        ("std :: net ::", "Network access is not allowed in #[pure] functions"),
        ("std :: io ::", "IO operations are not allowed in #[pure] functions"),
        ("println !", "Console output is not allowed in #[pure] functions"),
        ("eprintln !", "Console output is not allowed in #[pure] functions"),
        ("std :: thread ::", "Thread spawning is not allowed in #[pure] functions"),
        ("tokio :: spawn", "Async task spawning is not allowed in #[pure] functions"),
        ("unsafe", "Unsafe code is not allowed in #[pure] functions"),
    ];

    for (pattern, message) in impure_patterns {
        if code.contains(pattern) {
            return syn::Error::new_spanned(&input_fn.sig.ident, message).to_compile_error();
        }
    }

    // Emit the function with #[inline] marker
    let fn_attrs = &input_fn.attrs;
    let fn_vis = &input_fn.vis;
    let fn_sig = &input_fn.sig;
    let fn_body = &input_fn.block;

    quote! {
        #(#fn_attrs)*
        #[inline]
        #fn_vis #fn_sig #fn_body
    }
}
