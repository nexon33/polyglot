fn main() {
    let a = create_point(0.0, 0.0);
    let b = create_point(3.0, 4.0);
    let d = distance(a, b);
    println!("Distance: {} (should be 5.0)", d);
}