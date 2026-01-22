//! #[poly_bridge] - Compile-time type-safe cross-language FFI
//!
//! Generates wrapper structs and trait implementations that marshal
//! data between Rust and foreign language runtimes.
//!
//! # Example
//! ```rust
//! #[poly_bridge(python)]
//! trait DataFrame {
//!     fn len(&self) -> usize;
//!     fn filter(&self, pred: impl Fn(&Row) -> bool) -> Self;
//! }
//!
//! // Generates PyDataFrame with type-safe methods
//! let df: PyDataFrame = py!{ pd.read_csv("data.csv") };
//! let count = df.len();  // Compile-time type checking!
//! ```

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse2, Attribute, FnArg, Ident, ItemTrait, Meta, ReturnType, TraitItem, TraitItemFn, Type,
};

/// Supported foreign language runtimes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Runtime {
    Python,
    JavaScript,
    TypeScript,
}

impl Runtime {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "python" | "py" => Some(Runtime::Python),
            "javascript" | "js" => Some(Runtime::JavaScript),
            "typescript" | "ts" => Some(Runtime::TypeScript),
            _ => None,
        }
    }

    fn prefix(&self) -> &'static str {
        match self {
            Runtime::Python => "Py",
            Runtime::JavaScript => "Js",
            Runtime::TypeScript => "Ts",
        }
    }

    fn runtime_type(&self) -> TokenStream {
        match self {
            Runtime::Python => quote! { polyglot_runtime::prelude::ScriptRuntime },
            Runtime::JavaScript => quote! { polyglot_runtime::prelude::JsRuntime },
            Runtime::TypeScript => quote! { polyglot_runtime::prelude::TsRuntime },
        }
    }
}

/// Parse the runtime from attribute args: #[poly_bridge(python)]
fn parse_runtime(args: TokenStream) -> Result<Runtime, String> {
    let args_str = args.to_string();
    let runtime_name = args_str.trim().trim_matches(|c| c == '(' || c == ')');

    Runtime::from_str(runtime_name).ok_or_else(|| {
        format!(
            "Unknown runtime: {}. Use python, javascript, or typescript.",
            runtime_name
        )
    })
}

/// Main expansion function for #[poly_bridge]
pub fn expand(args: TokenStream, input: TokenStream) -> TokenStream {
    // Parse runtime
    let runtime = match parse_runtime(args) {
        Ok(r) => r,
        Err(e) => return quote! { compile_error!(#e); },
    };

    // Parse trait definition
    let trait_def: ItemTrait = match parse2(input.clone()) {
        Ok(t) => t,
        Err(e) => return e.to_compile_error(),
    };

    let trait_name = &trait_def.ident;
    let wrapper_name = format_ident!("{}{}", runtime.prefix(), trait_name);
    let runtime_type = runtime.runtime_type();

    // Generate method implementations
    let method_impls = generate_method_impls(&trait_def, runtime);

    // Generate the wrapper struct and trait impl
    let expanded = quote! {
        // Keep the original trait
        #trait_def

        /// Generated wrapper for foreign runtime
        pub struct #wrapper_name {
            handle: polyglot_runtime::bridge::ForeignHandle,
        }

        impl #wrapper_name {
            /// Create from a foreign value
            pub fn from_foreign(value: polyglot_runtime::bridge::ForeignValue) -> Self {
                Self {
                    handle: polyglot_runtime::bridge::ForeignHandle::new(value),
                }
            }

            /// Get the underlying handle ID
            pub fn handle_id(&self) -> u64 {
                self.handle.id()
            }
        }

        impl #trait_name for #wrapper_name {
            #method_impls
        }
    };

    expanded
}

/// Generate impl blocks for each trait method
fn generate_method_impls(trait_def: &ItemTrait, runtime: Runtime) -> TokenStream {
    let mut methods = Vec::new();

    for item in &trait_def.items {
        if let TraitItem::Fn(method) = item {
            let method_impl = generate_single_method(method, runtime);
            methods.push(method_impl);
        }
    }

    quote! { #(#methods)* }
}

/// Generate implementation for a single method
fn generate_single_method(method: &TraitItemFn, runtime: Runtime) -> TokenStream {
    let method_name = &method.sig.ident;
    let method_name_str = method_name.to_string();
    let inputs = &method.sig.inputs;
    let output = &method.sig.output;

    // Collect argument names (skip self)
    let arg_names: Vec<_> = inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    return Some(&pat_ident.ident);
                }
            }
            None
        })
        .collect();

    // Generate marshaling for arguments
    let marshal_args = if arg_names.is_empty() {
        quote! { let __args: Vec<polyglot_runtime::bridge::ForeignValue> = vec![]; }
    } else {
        quote! {
            let __args = vec![
                #(polyglot_runtime::bridge::ToForeign::to_foreign(&#arg_names)),*
            ];
        }
    };

    // Generate return type handling
    let return_handling = match output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => {
            // Check if return type is Self
            let ty_str = quote!(#ty).to_string();
            if ty_str.contains("Self") {
                quote! {
                    Self::from_foreign(__result)
                }
            } else {
                quote! {
                    polyglot_runtime::bridge::FromForeign::from_foreign(__result)
                        .expect("Failed to unmarshal return value")
                }
            }
        }
    };

    quote! {
        fn #method_name(#inputs) #output {
            #marshal_args
            let __result = self.handle.call_method(#method_name_str, &__args);
            #return_handling
        }
    }
}
