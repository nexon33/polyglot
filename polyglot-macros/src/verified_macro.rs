use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, FnArg, ItemFn, Pat, ReturnType};

pub fn expand(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = match parse2::<ItemFn>(input) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error(),
    };

    let args_str = args.to_string();
    let use_mock = args_str.contains("mock");

    let fn_name = &input_fn.sig.ident;
    let fn_vis = &input_fn.vis;
    let fn_attrs: Vec<_> = input_fn.attrs.iter().collect();
    let fn_generics = &input_fn.sig.generics;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_body = &input_fn.block;

    // Extract the inner return type (what the user wrote)
    let inner_return_type = match &input_fn.sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => quote! { #ty },
    };

    // Build parameter names for hashing inputs
    let param_names: Vec<_> = input_fn
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                if let Pat::Ident(ident) = pat_type.pat.as_ref() {
                    return Some(ident.ident.clone());
                }
            }
            None
        })
        .collect();

    // Build input hashing: hash all parameter bytes together
    let input_hash_stmts = if param_names.is_empty() {
        quote! {
            let __input_hash: poly_verified::types::Hash = poly_verified::types::ZERO_HASH;
        }
    } else {
        let hash_parts: Vec<_> = param_names
            .iter()
            .map(|name| {
                quote! {
                    __input_hasher.update(format!("{:?}", #name).as_bytes());
                }
            })
            .collect();
        quote! {
            let __input_hash: poly_verified::types::Hash = {
                use sha2::Digest;
                let mut __input_hasher = sha2::Sha256::new();
                #(#hash_parts)*
                let __result = __input_hasher.finalize();
                let mut __hash = [0u8; 32];
                __hash.copy_from_slice(&__result);
                __hash
            };
        }
    };

    let backend_init = if use_mock {
        quote! {
            let mut __acc = <poly_verified::ivc::mock_ivc::MockIvc as poly_verified::ivc::IvcBackend>::init(&__code_hash);
        }
    } else {
        quote! {
            let mut __acc = <poly_verified::ivc::hash_ivc::HashIvc as poly_verified::ivc::IvcBackend>::init(&__code_hash);
        }
    };

    let fold_and_finalize = if use_mock {
        quote! {
            let __witness = poly_verified::types::StepWitness {
                state_before: __input_hash,
                state_after: __output_hash,
                step_inputs: __input_hash,
            };
            <poly_verified::ivc::mock_ivc::MockIvc as poly_verified::ivc::IvcBackend>::fold_step(&mut __acc, &__witness);
            let __proof = <poly_verified::ivc::mock_ivc::MockIvc as poly_verified::ivc::IvcBackend>::finalize(__acc);
        }
    } else {
        quote! {
            let __witness = poly_verified::types::StepWitness {
                state_before: __input_hash,
                state_after: __output_hash,
                step_inputs: __input_hash,
            };
            <poly_verified::ivc::hash_ivc::HashIvc as poly_verified::ivc::IvcBackend>::fold_step(&mut __acc, &__witness);
            let __proof = <poly_verified::ivc::hash_ivc::HashIvc as poly_verified::ivc::IvcBackend>::finalize(__acc);
        }
    };

    quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name #fn_generics(#fn_inputs) -> poly_verified::verified_type::Verified<#inner_return_type> {
            // Compute code hash from function name (compile-time identifier)
            let __code_hash: poly_verified::types::Hash = {
                use sha2::Digest;
                let mut __h = sha2::Sha256::new();
                __h.update(concat!(module_path!(), "::", stringify!(#fn_name)).as_bytes());
                let __r = __h.finalize();
                let mut __hash = [0u8; 32];
                __hash.copy_from_slice(&__r);
                __hash
            };

            // Hash inputs
            #input_hash_stmts

            // Initialize IVC accumulator
            #backend_init

            // Execute the original function body
            let __result: #inner_return_type = (|| #fn_body)();

            // Hash the output
            let __output_hash: poly_verified::types::Hash = {
                use sha2::Digest;
                let mut __h = sha2::Sha256::new();
                __h.update(format!("{:?}", __result).as_bytes());
                let __r = __h.finalize();
                let mut __hash = [0u8; 32];
                __hash.copy_from_slice(&__r);
                __hash
            };

            // Fold witness and finalize proof
            #fold_and_finalize

            // Wrap in Verified<T>
            poly_verified::verified_type::Verified::new_proven(__result, __proof)
        }
    }
}
