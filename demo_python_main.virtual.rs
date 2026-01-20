// Helper functions in Rust

export fn create_tensor(rows: u32, cols: u32) -> Tensor {
    println!("Rust: Creating {}x{} tensor", rows, cols);
    let shape = vec![rows as usize, cols as usize];
    Tensor::zeros(&shape)
}

export fn print_tensor(t: Tensor) {
    println!("Rust: Tensor is {:?}", t);
}