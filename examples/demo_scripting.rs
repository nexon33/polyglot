// demo_scripting.rs - Rhai scripting examples (py! macro)
//
// Demonstrates py!{} macro with Rhai engine (Python-like syntax)
//
// Run: cargo run --example demo_scripting

fn main() {
    println!("════════════════════════════════════════════════════════════");
    println!("  Poly: Scripting Demo (Rhai Engine)");
    println!("════════════════════════════════════════════════════════════\n");

    use polyglot_runtime::prelude::ScriptRuntime;
    let script = ScriptRuntime::get();

    // ─────────────────────────────────────────────────────────────────
    // Variables and Expressions
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Variables and Expressions:");
    let result = script.eval_i32("let x = 10; let y = 20; x + y").unwrap();
    println!("  let x = 10; let y = 20; x + y = {}", result);

    let result = script.eval_i32("let a = 5; a * a").unwrap();
    println!("  let a = 5; a * a = {}", result);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // Control Flow
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Control Flow:");
    let result = script
        .eval_i32(
            r#"
        let result = 0;
        if 5 > 3 {
            result = 100;
        } else {
            result = 0;
        }
        result
    "#,
        )
        .unwrap();
    println!("  if 5 > 3 {{ 100 }} else {{ 0 }} = {}", result);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // Loops
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Loops:");
    let sum = script
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
    println!("  sum(1..=10) = {}", sum);

    let factorial = script
        .eval_i32(
            r#"
        let n = 5;
        let result = 1;
        while n > 0 {
            result *= n;
            n -= 1;
        }
        result
    "#,
        )
        .unwrap();
    println!("  5! = {}", factorial);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // Arrays
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Arrays:");
    let arr = script.eval_vec_i32("[1, 2, 3, 4, 5]").unwrap();
    println!("  [1, 2, 3, 4, 5] = {:?}", arr);

    let arr = script.eval_vec_i32("[10, 20, 30]").unwrap();
    println!("  [10, 20, 30] = {:?}", arr);
    println!();

    // ─────────────────────────────────────────────────────────────────
    // Strings
    // ─────────────────────────────────────────────────────────────────
    println!("▸ Strings:");
    let hello = script.eval_string(r#""Hello" + " " + "World""#).unwrap();
    println!("  \"Hello\" + \" \" + \"World\" = {}", hello);

    let repeated = script.eval_string(r#""poly" + "glot""#).unwrap();
    println!("  \"poly\" + \"glot\" = {}", repeated);
    println!();

    println!("════════════════════════════════════════════════════════════");
    println!("  ✓ All scripting demos completed successfully!");
    println!("════════════════════════════════════════════════════════════");
}
