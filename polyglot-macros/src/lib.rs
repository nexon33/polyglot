//! Polyglot Macros - Inline foreign language expressions
//!
//! Provides proc macros for embedding Python, JavaScript, TypeScript, CUDA, and SQL
//! expressions directly in Rust code with automatic type marshaling.
//!
//! Also provides `#[poly_bridge]` for compile-time type-safe cross-language FFI.
//!
//! All interpreters are fully embedded - no external runtimes needed!
//!
//! # Example
//! ```rust
//! use polyglot::prelude::*;
//!
//! fn main() {
//!     let js_result: i32 = js!{ 1 + 2 + 3 };
//!     let ts_result: i32 = ts!{ (1 as number) + (2 as number) };
//!     println!("{js_result}, {ts_result}");
//! }
//! ```

use proc_macro::TokenStream;

mod bridge_macro;
mod capture;
mod gpu_macro;
mod js_macro;
mod py_macro;
mod sql_macro;
mod ts_macro;

/// Python expression macro - executes Python code and returns result
///
/// Uses RustPython (pure Rust interpreter, no system Python needed).
///
/// # Example
/// ```rust
/// let result: i32 = py!{ 1 + 2 };
/// ```
#[proc_macro]
pub fn py(input: TokenStream) -> TokenStream {
    py_macro::expand(input.into()).into()
}

/// JavaScript expression macro - executes JS code and returns result
///
/// Uses Boa engine (pure Rust, no Node.js needed).
///
/// # Example
/// ```rust
/// let value: i32 = js!{ 1 + 2 + 3 };
/// let arr: Vec<i32> = js!{ [1, 2, 3].map(x => x * 2) };
/// ```
#[proc_macro]
pub fn js(input: TokenStream) -> TokenStream {
    js_macro::expand(input.into()).into()
}

/// TypeScript expression macro - compiles and executes TS code
///
/// Uses SWC (pure Rust) to transpile, then Boa to execute.
///
/// # Example
/// ```rust
/// let result: i32 = ts!{ const x: number = 5; x * 2 };
/// ```
#[proc_macro]
pub fn ts(input: TokenStream) -> TokenStream {
    ts_macro::expand(input.into()).into()
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

/// Type-safe cross-language FFI bridge
///
/// Generates wrapper types and trait implementations for calling
/// foreign language methods with compile-time type checking.
///
/// # Example
/// ```rust
/// #[poly_bridge(javascript)]
/// trait Calculator {
///     fn add(&self, a: i32, b: i32) -> i32;
///     fn multiply(&self, a: i32, b: i32) -> i32;
/// }
///
/// // Generates JsCalculator with type-safe methods
/// let calc: JsCalculator = js!{ ({ add: (a,b) => a+b, multiply: (a,b) => a*b }) };
/// let sum = calc.add(2, 3);  // Type-checked at compile time!
/// ```
#[proc_macro_attribute]
pub fn poly_bridge(args: TokenStream, input: TokenStream) -> TokenStream {
    bridge_macro::expand(args.into(), input.into()).into()
}
