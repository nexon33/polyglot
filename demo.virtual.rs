fn main() {
    println!("Polyglot Runtime Init");
    
    // Create tensor in Rust
    let t = create_tensor(128, 128);
    
    // Process in Python (cross-language call!)
    let t2 = process_tensor(t);
    
    // Print result in Rust
    print_tensor(t2);
}