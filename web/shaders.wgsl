// WebGPU shaders (placeholder for future GPU acceleration)
struct Uniforms { M: u32, K: u32, N: u32 }
@group(0) @binding(0) var<uniform> uniforms: Uniforms;
@group(0) @binding(1) var<storage, read> a: array<f32>;
@group(0) @binding(2) var<storage, read> b: array<f32>;
@group(0) @binding(3) var<storage, read_write> c: array<f32>;

@compute @workgroup_size(16, 16)
fn matmul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.y;
    let col = gid.x;
    if (row >= uniforms.M || col >= uniforms.N) { return; }
    var sum: f32 = 0.0;
    for (var k: u32 = 0u; k < uniforms.K; k = k + 1u) {
        sum = sum + a[row * uniforms.K + k] * b[k * uniforms.N + col];
    }
    c[row * uniforms.N + col] = sum;
}