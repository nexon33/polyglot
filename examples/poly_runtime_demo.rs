//! Poly Runtime Demo - All Three Engines
//!
//! Demonstrates the self-contained polyglot runtime:
//! - py!{} - Rhai scripting (Python-like)
//! - js!{} - Boa JavaScript engine
//! - ts!{} - SWC TypeScript + Boa
//!
//! Run with: cargo run --example poly_runtime_demo

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                                                              ║");
    println!("║                      P O L Y                                 ║");
    println!("║                                                              ║");
    println!("║           One language. Every runtime.                       ║");
    println!("║                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ═══════════════════════════════════════════════════════════════════════
    // RHAI SCRIPTING ENGINE (py! macro)
    // ═══════════════════════════════════════════════════════════════════════
    println!("━━━ Rhai Scripting Engine (py!) ━━━");

    use polyglot_runtime::prelude::ScriptRuntime;

    let script = ScriptRuntime::get();

    // Basic arithmetic
    let result = script.eval_i32("1 + 2 + 3 + 4 + 5").unwrap();
    println!("  1 + 2 + 3 + 4 + 5 = {}", result);

    // Variables and expressions
    let result = script.eval_i32("let x = 10; let y = 20; x * y").unwrap();
    println!("  let x = 10; let y = 20; x * y = {}", result);

    // Loops and accumulation
    let result = script
        .eval_i32(
            r#"
        let sum = 0;
        for i in 1..=10 {
            sum += i;
        }
        sum
    "#,
        )
        .unwrap();
    println!("  sum(1..=10) = {}", result);

    // String operations
    let result = script.eval_string(r#""Hello" + " " + "Poly!""#).unwrap();
    println!("  \"Hello\" + \" \" + \"Poly!\" = {}", result);

    // Arrays
    let result = script.eval_vec_i32("[1, 2, 3, 4, 5]").unwrap();
    println!("  [1, 2, 3, 4, 5] = {:?}", result);

    println!();

    // ═══════════════════════════════════════════════════════════════════════
    // BOA JAVASCRIPT ENGINE (js! macro)
    // ═══════════════════════════════════════════════════════════════════════
    println!("━━━ Boa JavaScript Engine (js!) ━━━");

    use polyglot_runtime::prelude::JsRuntime;

    let js = JsRuntime::get();

    // Basic arithmetic
    let result = js.eval_i32("1 + 2 + 3 + 4 + 5").unwrap();
    println!("  1 + 2 + 3 + 4 + 5 = {}", result);

    // Arrow functions and array methods
    let result = js
        .eval_i32("[1, 2, 3, 4, 5].reduce((a, b) => a + b, 0)")
        .unwrap();
    println!("  [1,2,3,4,5].reduce((a,b) => a+b) = {}", result);

    // Math operations
    let result = js.eval_f64("Math.pow(2, 10)").unwrap();
    println!("  Math.pow(2, 10) = {}", result);

    // String methods
    let result = js.eval_string("'poly'.toUpperCase() + '!'").unwrap();
    println!("  'poly'.toUpperCase() + '!' = {}", result);

    // Array map
    let result = js.eval_vec_i32("[1, 2, 3].map(x => x * x)").unwrap();
    println!("  [1,2,3].map(x => x*x) = {:?}", result);

    // Template literals (ES6)
    let result = js.eval_string("`The answer is ${6 * 7}`").unwrap();
    println!("  `The answer is ${{6*7}}` = {}", result);

    println!();

    // ═══════════════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════════════
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  ✓ Rhai scripting engine - Pure Rust, Python-like syntax");
    println!("  ✓ Boa JavaScript engine - Pure Rust, full ES6+ support");
    println!("  ✓ SWC TypeScript compiler - Pure Rust (when enabled)");
    println!();
    println!("  All engines are FULLY EMBEDDED. No external runtimes needed!");
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
