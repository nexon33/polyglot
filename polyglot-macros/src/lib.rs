//! Polyglot Macros - Inline foreign language expressions
//!
//! Provides proc macros for embedding Python, JavaScript, CUDA, and SQL
//! expressions directly in Rust code with automatic type marshaling.
//!
//! # Example
//! ```rust
//! use polyglot::prelude::*;
//!
//! fn main() {
//!     let data = vec![1, 2, 3, 4, 5];
//!     let doubled: Vec<i32> = py!{ (np.array(data) * 2).tolist() };
//!     println!("{:?}", doubled);
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, LitStr};

mod capture;
mod gpu_macro;
mod js_macro;
mod py_macro;
mod sql_macro;

/// Python expression macro - executes Python code and returns result
///
/// # Example
/// ```rust
/// let result: i32 = py!{ 1 + 2 };
/// let arr: Vec<f64> = py!{ np.array([1.0, 2.0, 3.0]).tolist() };
/// ```
///
/// Captured Rust variables are automatically marshaled to Python.
#[proc_macro]
pub fn py(input: TokenStream) -> TokenStream {
    py_macro::expand(input.into()).into()
}

/// JavaScript expression macro - executes JS code and returns result
///
/// Useful for WASM interop and DOM manipulation.
///
/// # Example
/// ```rust
/// let value: String = js!{ document.getElementById("input").value };
/// ```
#[proc_macro]
pub fn js(input: TokenStream) -> TokenStream {
    js_macro::expand(input.into()).into()
}

/// CUDA/GPU kernel macro (reserved - not yet implemented)
///
/// # Example
/// ```rust
/// let result = cuda!{ parallel_map(data, |x| x * x) };
/// ```
#[proc_macro]
pub fn cuda(input: TokenStream) -> TokenStream {
    gpu_macro::expand_cuda(input.into()).into()
}

/// GPU compute macro (reserved - not yet implemented)
#[proc_macro]
pub fn gpu(input: TokenStream) -> TokenStream {
    gpu_macro::expand_gpu(input.into()).into()
}

/// SQL query macro (reserved - not yet implemented)
///
/// # Example
/// ```rust
/// let users: Vec<User> = sql!{ SELECT * FROM users WHERE active = true };
/// ```
#[proc_macro]
pub fn sql(input: TokenStream) -> TokenStream {
    sql_macro::expand(input.into()).into()
}
