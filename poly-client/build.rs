fn main() {
    if std::env::var("CARGO_FEATURE_CUDA").is_ok() {
        compile_cuda_kernels();
    }
}

fn compile_cuda_kernels() {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let kernel_dir = Path::new("kernels");

    // Default to sm_86 (RTX 3090 / Ampere). Override via POLY_CUDA_ARCH env var.
    let arch = std::env::var("POLY_CUDA_ARCH").unwrap_or_else(|_| "sm_86".to_string());

    for kernel in &["ntt", "modular_ops"] {
        let input = kernel_dir.join(format!("{}.cu", kernel));
        let output = PathBuf::from(&out_dir).join(format!("{}.ptx", kernel));

        if !input.exists() {
            panic!("CUDA kernel not found: {}", input.display());
        }

        let status = Command::new("nvcc")
            .args([
                "--ptx",
                &format!("-arch={}", arch),
                "--use_fast_math",
                "-O3",
                "-o",
                output.to_str().unwrap(),
                input.to_str().unwrap(),
            ])
            .status()
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to run nvcc: {e}. \
                     Install CUDA toolkit and ensure nvcc is in PATH.\n\
                     On Windows, also add VS 2019+ cl.exe to PATH:\n  \
                     set PATH=C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\\
                     VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64;%PATH%"
                );
            });

        if !status.success() {
            panic!(
                "nvcc failed to compile {}. Exit code: {:?}",
                input.display(),
                status.code()
            );
        }

        println!("cargo:rerun-if-changed={}", input.display());
    }
}
