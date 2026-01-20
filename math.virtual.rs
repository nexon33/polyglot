// Rust handles the low-level Matrix type and allocation
#[derive(Debug, Clone)]
pub struct Matrix {
    pub data: Vec<f64>,
    pub rows: u32,
    pub cols: u32,
}

fn create_matrix(rows: u32, cols: u32) -> Matrix {
    println!("Rust: Creating {}x{} matrix", rows, cols);
    Matrix {
        data: vec![0.0; (rows * cols) as usize],
        rows,
        cols,
    }
}

fn multiply(a: Matrix, b: Matrix) -> Matrix {
    println!("Rust: Matrix multiply {}x{} * {}x{}", a.rows, a.cols, b.rows, b.cols);
    // Simple identity return for demo
    a
}