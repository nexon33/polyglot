use proc_macro2::TokenStream;
use quote::quote;
use syn::parse2;

pub fn expand(input: TokenStream) -> TokenStream {
    // The input expression is what to fold
    // fold!(state_expr) -> hash the expression and create a fold witness
    let expr = match parse2::<syn::Expr>(input) {
        Ok(e) => e,
        Err(e) => return e.to_compile_error(),
    };

    quote! {
        {
            let __fold_value = #expr;
            // Hash the fold point value
            let __fold_hash: poly_verified::types::Hash = {
                use sha2::Digest;
                let mut __h = sha2::Sha256::new();
                __h.update(format!("{:?}", __fold_value).as_bytes());
                let __r = __h.finalize();
                let mut __hash = [0u8; 32];
                __hash.copy_from_slice(&__r);
                __hash
            };
            // The fold hash can be used by the enclosing #[verified] accumulator
            // via thread-local or passed context
            __fold_value
        }
    }
}
