use std::fs;
use polyglot::syntax_aliases::normalize_all;

fn main() {
    let source = fs::read_to_string("examples/chaos.poly").unwrap();
    let normalized = normalize_all(&source);
    let bytes = normalized.as_bytes();
    
    // Start from Python block opening brace
    let start = 1909;
    let end = 3000;
    
    println!("Tracing from Python block start:");
    
    let mut in_string = false;
    let mut in_char = false;
    let mut depth = 1;
    let mut escape_next = false;
    let mut in_triple_double = false;
    let in_triple_single = false;
    
    let mut i = start;
    while i < end {
        let c = bytes[i];
        
        if escape_next {
            escape_next = false;
            i += 1;
            continue;
        }
        
        // Check for triple quotes when not in regular string
        if !in_char && !in_string && !in_triple_double && !in_triple_single {
            if i + 2 < bytes.len() && bytes[i] == b'"' && bytes[i+1] == b'"' && bytes[i+2] == b'"' {
                in_triple_double = true;
                println!("  {:>4}: \"\"\" START triple", i);
                i += 3;
                continue;
            }
        }
        
        // Check for closing triple quote when inside triple
        if in_triple_double && i + 2 < bytes.len() && bytes[i] == b'"' && bytes[i+1] == b'"' && bytes[i+2] == b'"' {
            in_triple_double = false;
            println!("  {:>4}: \"\"\" END triple", i);
            i += 3;
            continue;
        }
        
        // Skip content inside triple
        if in_triple_double || in_triple_single {
            i += 1;
            continue;
        }
        
        // Only escape when in string/char
        if c == b'\\' && (in_string || in_char) {
            escape_next = true;
            i += 1;
            continue;
        }
        
        if c == b'"' && !in_char {
            in_string = !in_string;
            println!("  {:>4}: \" in_string -> {}", i, in_string);
        } else if c == b'\'' && !in_string {
            in_char = !in_char;
            println!("  {:>4}: ' in_char -> {}", i, in_char);
        } else if !in_string && !in_char {
            if c == b'{' {
                depth += 1;
                println!("  {:>4}: {{ depth={}", i, depth);
            } else if c == b'}' {
                depth -= 1;
                println!("  {:>4}: }} depth={}", i, depth);
                if depth == 0 {
                    println!("  FOUND closing brace!");
                    break;
                }
            }
        }
        
        i += 1;
    }
    
    println!("\nFinal: in_string={}, in_char={}, in_triple={}, depth={}", 
        in_string, in_char, in_triple_double, depth);
}
