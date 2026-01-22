// demo_javascript.rs - JavaScript macro examples
//
// Demonstrates js!{} macro with Boa engine (pure Rust, no Node.js)
//
// Run: cargo run --example demo_javascript

fn main() {
    println!("════════════════════════════════════════════════════════════");
    println!("  Poly: JavaScript Demo (Boa Engine)");
    println!("════════════════════════════════════════════════════════════\n");

    use polyglot_runtime::prelude::JsRuntime;
    let js = JsRuntime::get();

    // ─────────────────────────────────────────────────────────────────
    // Basic Arithmetic
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Basic Arithmetic:");
    let sum = js.eval_i32("1 + 2 + 3 + 4 + 5").unwrap();
    println!("  1 + 2 + 3 + 4 + 5 = {}", sum);

    let product = js.eval_i32("2 * 3 * 4").unwrap();
    println!("  2 * 3 * 4 = {}", product);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // ES6 Arrow Functions
    // ─────────────────────────────────────────────────────────────────
    println!("▸ ES6 Arrow Functions:");
    let doubled = js.eval_vec_i32("[1,2,3,4,5].map(x => x * 2)").unwrap();
    println!("  [1,2,3,4,5].map(x => x * 2) = {:?}", doubled);

    let filtered = js
        .eval_vec_i32("[1,2,3,4,5,6,7,8,9,10].filter(x => x % 2 === 0)")
        .unwrap();
    println!("  [1..10].filter(x => x % 2 === 0) = {:?}", filtered);

    let reduced = js
        .eval_i32("[1,2,3,4,5].reduce((acc, x) => acc + x, 0)")
        .unwrap();
    println!("  [1,2,3,4,5].reduce((acc, x) => acc + x, 0) = {}", reduced);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // Math Object
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Math Object:");
    let pi = js.eval_f64("Math.PI").unwrap();
    println!("  Math.PI = {}", pi);

    let sqrt = js.eval_f64("Math.sqrt(144)").unwrap();
    println!("  Math.sqrt(144) = {}", sqrt);

    let pow = js.eval_f64("Math.pow(2, 10)").unwrap();
    println!("  Math.pow(2, 10) = {}", pow);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // Template Literals (ES6)
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Template Literals:");
    let greeting = js.eval_string("`Hello, ${'Poly'}!`").unwrap();
    println!("  `Hello, ${{'Poly'}}!` = {}", greeting);

    let math_result = js.eval_string("`The answer is ${6 * 7}`").unwrap();
    println!("  `The answer is ${{6 * 7}}` = {}", math_result);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // String Methods
    // ─────────────────────────────────────────────────────────────────
    println!("▸ String Methods:");
    let upper = js.eval_string("'polyglot'.toUpperCase()").unwrap();
    println!("  'polyglot'.toUpperCase() = {}", upper);

    let split = js.eval_string("'a,b,c'.split(',').join(' - ')").unwrap();
    println!("  'a,b,c'.split(',').join(' - ') = {}", split);
    println!();

    println!("════════════════════════════════════════════════════════════");
    println!("  ✓ All JavaScript demos completed successfully!");
    println!("════════════════════════════════════════════════════════════");
}
