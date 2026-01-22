//! Example demonstrating the polyglot macro system
//!
//! Run with: cargo run -p polyglot-example

use polyglot_macros::py;

fn main() {
    println!("=== Polyglot Macro Example ===\n");

    // Simple Python expression
    println!("Evaluating: py!{{ 1 + 2 + 3 }}");
    let result: i32 = py! { 1 + 2 + 3 };
    println!("Result: {}\n", result);

    // Python with math
    println!("Evaluating: py!{{ 10 ** 2 }}");
    let squared: i32 = py! { 10 ** 2 };
    println!("Result: {}\n", squared);

    // Python list comprehension
    println!("Evaluating: py!{{ sum([1, 2, 3, 4, 5]) }}");
    let sum: i32 = py! { sum([1, 2, 3, 4, 5]) };
    println!("Result: {}\n", sum);

    println!("All tests passed!");
}
