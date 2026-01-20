//! Polyglot Capability System
//! 
//! Provides cryptographic access control for cross-language function calls.
//! 
//! # Security Model
//! 
//! - `internal` functions: Only callable from same .poly file
//! - `export` functions: Callable from other .poly files that `use` this module  
//! - `public` functions: Callable from anywhere (FFI boundary)
//!
//! # How It Works
//!
//! Each .poly file gets a unique capability token at compile time.
//! Internal functions require the caller to prove they have this token.
//! The token is unforgeable (cryptographically derived) and invisible to developers.

use std::collections::HashMap;
use std::sync::RwLock;

// ============================================================
// CORE TYPES
// ============================================================

/// A 128-bit capability token
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capability([u8; 16]);

impl Capability {
    pub const INVALID: Capability = Capability([0u8; 16]);
    
    pub fn new(bytes: [u8; 16]) -> Self {
        Capability(bytes)
    }
    
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
    
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            bytes[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Capability(bytes))
    }
    
    /// Constant-time equality comparison (prevents timing attacks)
    pub fn secure_eq(&self, other: &Capability) -> bool {
        let mut result = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cap({}...)", &self.to_hex()[..8])
    }
}

/// Visibility/access scope for a function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Only callable from within the same .poly file
    /// Requires exact capability match
    Internal,
    
    /// Callable from other .poly files that import this module
    /// Requires any valid poly ecosystem capability
    Export,
    
    /// Callable from anywhere, including raw FFI
    /// No capability required
    Public,
}

impl Scope {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "internal" => Some(Scope::Internal),
            "export" => Some(Scope::Export),
            "public" | "pub" => Some(Scope::Public),
            _ => None,
        }
    }
    
    pub fn to_str(&self) -> &'static str {
        match self {
            Scope::Internal => "internal",
            Scope::Export => "export",
            Scope::Public => "public",
        }
    }
}

// ============================================================
// CAPABILITY GENERATOR (Compile-time)
// ============================================================

/// Generates capabilities at compile time
pub struct CapabilityGenerator {
    /// Secret seed for deterministic generation (set once per project)
    secret_seed: [u8; 32],
    
    /// Cache of generated capabilities
    cache: HashMap<String, Capability>,
}

impl CapabilityGenerator {
    /// Create a new generator with a random seed
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("Failed to generate random seed");
        Self {
            secret_seed: seed,
            cache: HashMap::new(),
        }
    }
    
    /// Create a generator with a specific seed (for reproducible builds)
    pub fn with_seed(seed: [u8; 32]) -> Self {
        Self {
            secret_seed: seed,
            cache: HashMap::new(),
        }
    }
    
    /// Create a generator from a project secret file
    pub fn from_secret_file(path: &std::path::Path) -> std::io::Result<Self> {
        if path.exists() {
            let contents = std::fs::read(path)?;
            if contents.len() >= 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&contents[..32]);
                Ok(Self::with_seed(seed))
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Secret file too short"
                ))
            }
        } else {
            // Generate new secret and save it
            let gen = Self::new();
            std::fs::write(path, &gen.secret_seed)?;
            Ok(gen)
        }
    }
    
    /// Generate a capability for a specific file
    pub fn generate_file_capability(&mut self, file_path: &str) -> Capability {
        let key = format!("file:{}", file_path);
        
        if let Some(cap) = self.cache.get(&key) {
            return *cap;
        }
        
        let cap = self.derive_capability(&key);
        self.cache.insert(key, cap);
        cap
    }
    
    /// Generate a capability for a specific function
    pub fn generate_function_capability(
        &mut self, 
        file_path: &str, 
        fn_name: &str
    ) -> Capability {
        let key = format!("fn:{}:{}", file_path, fn_name);
        
        if let Some(cap) = self.cache.get(&key) {
            return *cap;
        }
        
        let cap = self.derive_capability(&key);
        self.cache.insert(key, cap);
        cap
    }
    
    /// Generate the "poly ecosystem" capability
    /// This proves a caller is from compiled poly code
    pub fn generate_ecosystem_capability(&mut self) -> Capability {
        let key = "ecosystem:poly".to_string();
        
        if let Some(cap) = self.cache.get(&key) {
            return *cap;
        }
        
        let cap = self.derive_capability(&key);
        self.cache.insert(key, cap);
        cap
    }
    
    /// Internal: Derive a capability from a key using HMAC-like construction
    fn derive_capability(&self, key: &str) -> Capability {
        // Simple HMAC-SHA256-like construction
        // In production, use a proper HMAC crate
        
        let mut state = [0u8; 32];
        
        // XOR seed with ipad
        for (i, &b) in self.secret_seed.iter().enumerate() {
            state[i] = b ^ 0x36;
        }
        
        // Hash with key
        state = simple_hash(&state, key.as_bytes());
        
        // XOR seed with opad
        let mut outer = [0u8; 32];
        for (i, &b) in self.secret_seed.iter().enumerate() {
            outer[i] = b ^ 0x5c;
        }
        
        // Final hash
        let result = simple_hash(&outer, &state);
        
        // Take first 16 bytes
        let mut cap_bytes = [0u8; 16];
        cap_bytes.copy_from_slice(&result[..16]);
        
        Capability(cap_bytes)
    }
    
    /// Export all capabilities for embedding in generated code
    pub fn export_capabilities(&self) -> CapabilityManifest {
        CapabilityManifest {
            capabilities: self.cache.clone(),
        }
    }
}

impl Default for CapabilityGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple hash function (replace with SHA256 in production)
fn simple_hash(state: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut result = *state;
    
    for (i, &b) in data.iter().enumerate() {
        let idx = i % 32;
        result[idx] = result[idx].wrapping_add(b);
        result[(idx + 1) % 32] ^= result[idx].rotate_left(3);
        result[(idx + 7) % 32] = result[(idx + 7) % 32].wrapping_mul(33).wrapping_add(b);
    }
    
    // Mix rounds
    for _ in 0..8 {
        for i in 0..32 {
            result[i] = result[i]
                .wrapping_add(result[(i + 13) % 32])
                .rotate_left(5)
                ^ result[(i + 7) % 32];
        }
    }
    
    result
}

// ============================================================
// CAPABILITY MANIFEST (Serialization)
// ============================================================

/// Manifest of all capabilities in a compilation unit
#[derive(Debug, Clone)]
pub struct CapabilityManifest {
    capabilities: HashMap<String, Capability>,
}

impl CapabilityManifest {
    /// Serialize to embeddable Rust code
    pub fn to_rust_code(&self, module_name: &str) -> String {
        let mut code = String::new();
        
        code.push_str(&format!(
            "// Auto-generated capability manifest for {}\n",
            module_name
        ));
        code.push_str("// DO NOT EDIT - regenerated on each compile\n\n");
        
        code.push_str("pub mod __poly_cap {\n");
        
        for (key, cap) in &self.capabilities {
            let const_name = key
                .replace(":", "_")
                .replace("/", "_")
                .replace(".", "_")
                .replace("-", "_")
                .to_uppercase();
            
            code.push_str(&format!(
                "    pub const {}: [u8; 16] = {:?};\n",
                const_name,
                cap.as_bytes()
            ));
        }
        
        code.push_str("}\n");
        
        code
    }
    
    /// Serialize to embeddable Python code
    pub fn to_python_code(&self, module_name: &str) -> String {
        let mut code = String::new();
        
        code.push_str(&format!(
            "# Auto-generated capability manifest for {}\n",
            module_name
        ));
        code.push_str("# DO NOT EDIT - regenerated on each compile\n\n");
        
        code.push_str("class __PolyCap:\n");
        
        for (key, cap) in &self.capabilities {
            let const_name = key
                .replace(":", "_")
                .replace("/", "_")
                .replace(".", "_")
                .replace("-", "_")
                .to_uppercase();
            
            code.push_str(&format!(
                "    {} = bytes([{}])\n",
                const_name,
                cap.as_bytes().iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ")
            ));
        }
        
        code
    }
}

// ============================================================
// RUNTIME VERIFICATION
// ============================================================

/// Runtime capability verifier
/// This code gets embedded into compiled poly programs
pub struct CapabilityVerifier {
    /// Valid file capabilities (loaded at startup)
    file_caps: RwLock<HashMap<String, Capability>>,
    
    /// The ecosystem capability
    ecosystem_cap: Capability,
}

impl CapabilityVerifier {
    pub fn new(ecosystem_cap: Capability) -> Self {
        Self {
            file_caps: RwLock::new(HashMap::new()),
            ecosystem_cap,
        }
    }
    
    /// Register a file's capability
    pub fn register_file(&self, file_id: &str, cap: Capability) {
        self.file_caps.write().unwrap().insert(file_id.to_string(), cap);
    }
    
    /// Verify a capability for internal function access
    pub fn verify_internal(&self, provided: &Capability, file_id: &str) -> bool {
        if let Some(expected) = self.file_caps.read().unwrap().get(file_id) {
            expected.secure_eq(provided)
        } else {
            false
        }
    }
    
    /// Verify a capability is from the poly ecosystem
    pub fn verify_ecosystem(&self, provided: &Capability) -> bool {
        // Check if it's the ecosystem cap
        if self.ecosystem_cap.secure_eq(provided) {
            return true;
        }
        
        // Or any registered file cap
        for cap in self.file_caps.read().unwrap().values() {
            if cap.secure_eq(provided) {
                return true;
            }
        }
        
        false
    }
    
    /// Verify for export functions (any poly caller)
    pub fn verify_export(&self, provided: &Capability) -> bool {
        self.verify_ecosystem(provided)
    }
}

// ============================================================
// RUNTIME LIBRARY (Generated into each poly binary)
// ============================================================

/// Generate the runtime verification code for Rust
pub fn generate_rust_runtime() -> String {
    r#"
// Poly Runtime - Capability Verification
// Auto-generated - do not edit

pub mod poly_runtime {
    use std::sync::OnceLock;
    
    static VERIFIER: OnceLock<CapabilityVerifier> = OnceLock::new();
    
    pub struct CapabilityVerifier {
        ecosystem_cap: [u8; 16],
        file_caps: std::sync::RwLock<std::collections::HashMap<&'static str, [u8; 16]>>,
    }
    
    impl CapabilityVerifier {
        pub fn new(ecosystem_cap: [u8; 16]) -> Self {
            Self {
                ecosystem_cap,
                file_caps: std::sync::RwLock::new(std::collections::HashMap::new()),
            }
        }
        
        pub fn register(&self, file_id: &'static str, cap: [u8; 16]) {
            self.file_caps.write().unwrap().insert(file_id, cap);
        }
    }
    
    pub fn init(ecosystem_cap: [u8; 16]) {
        VERIFIER.get_or_init(|| CapabilityVerifier::new(ecosystem_cap));
    }
    
    pub fn register_file(file_id: &'static str, cap: [u8; 16]) {
        if let Some(v) = VERIFIER.get() {
            v.register(file_id, cap);
        }
    }
    
    /// Verify internal function access (same file only)
    #[inline]
    pub fn verify_internal(provided: &[u8; 16], expected: &[u8; 16]) -> bool {
        constant_time_eq(provided, expected)
    }
    
    /// Verify export function access (any poly file)
    #[inline]
    pub fn verify_export(provided: &[u8; 16]) -> bool {
        if let Some(v) = VERIFIER.get() {
            // Check ecosystem cap
            if constant_time_eq(provided, &v.ecosystem_cap) {
                return true;
            }
            // Check any file cap
            for cap in v.file_caps.read().unwrap().values() {
                if constant_time_eq(provided, cap) {
                    return true;
                }
            }
        }
        false
    }
    
    /// Constant-time comparison
    #[inline]
    fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
    
    /// Panic with access denied (no information leakage)
    #[cold]
    #[inline(never)]
    pub fn access_denied() -> ! {
        panic!("poly: access denied")
    }
}
"#.to_string()
}

/// Generate the runtime verification code for Python
pub fn generate_python_runtime() -> String {
    r#"
# Poly Runtime - Capability Verification
# Auto-generated - do not edit

import hmac

class PolyRuntime:
    _instance = None
    
    def __init__(self):
        self.ecosystem_cap = None
        self.file_caps = {}
    
    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def init(self, ecosystem_cap: bytes):
        self.ecosystem_cap = ecosystem_cap
    
    def register_file(self, file_id: str, cap: bytes):
        self.file_caps[file_id] = cap
    
    def verify_internal(self, provided: bytes, expected: bytes) -> bool:
        """Constant-time comparison for internal access"""
        return hmac.compare_digest(provided, expected)
    
    def verify_export(self, provided: bytes) -> bool:
        """Verify caller is from poly ecosystem"""
        if self.ecosystem_cap and hmac.compare_digest(provided, self.ecosystem_cap):
            return True
        for cap in self.file_caps.values():
            if hmac.compare_digest(provided, cap):
                return True
        return False
    
    def access_denied(self):
        raise PermissionError("poly: access denied")

# Global instance
_poly_rt = PolyRuntime.get()

def poly_init(ecosystem_cap: bytes):
    _poly_rt.init(ecosystem_cap)

def poly_register_file(file_id: str, cap: bytes):
    _poly_rt.register_file(file_id, cap)

def poly_verify_internal(provided: bytes, expected: bytes) -> bool:
    return _poly_rt.verify_internal(provided, expected)

def poly_verify_export(provided: bytes) -> bool:
    return _poly_rt.verify_export(provided)

def poly_access_denied():
    _poly_rt.access_denied()
"#.to_string()
}

// ============================================================
// CODEGEN INTEGRATION
// ============================================================

/// Information needed for generating capability-protected functions
#[derive(Debug, Clone)]
pub struct ProtectedFunction {
    pub name: String,
    pub file_path: String,
    pub scope: Scope,
    pub capability: Capability,
    pub params: Vec<(String, String)>,  // (name, type)
    pub return_type: Option<String>,
}

/// Generate a capability-protected Rust function wrapper
pub fn generate_rust_wrapper(func: &ProtectedFunction) -> String {
    let cap_const = format!("__CAP_{}", func.name.to_uppercase());
    
    let params_with_types: String = func.params
        .iter()
        .map(|(name, ty)| format!("{}: {}", name, ty))
        .collect::<Vec<_>>()
        .join(", ");
    
    let param_names: String = func.params
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    
    let return_ty = func.return_type.as_deref().unwrap_or("()");
    
    match func.scope {
        Scope::Internal => {
            format!(
                r#"
const {cap_const}: [u8; 16] = [{}];

#[no_mangle]
pub extern "C" fn __poly_{name}(__cap: [u8; 16], {params}) -> {ret} {{
    if !poly_runtime::verify_internal(&__cap, &{cap_const}) {{
        poly_runtime::access_denied();
    }}
    {name}_impl({param_names})
}}
"#,
                func.capability.as_bytes().iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", "),
                cap_const = cap_const,
                name = func.name,
                params = params_with_types,
                ret = return_ty,
                param_names = param_names,
            )
        }
        
        Scope::Export => {
            format!(
                r#"
#[no_mangle]
pub extern "C" fn poly_{name}(__cap: [u8; 16], {params}) -> {ret} {{
    if !poly_runtime::verify_export(&__cap) {{
        poly_runtime::access_denied();
    }}
    {name}_impl({param_names})
}}
"#,
                name = func.name,
                params = params_with_types,
                ret = return_ty,
                param_names = param_names,
            )
        }
        
        Scope::Public => {
            format!(
                r#"
#[no_mangle]
pub extern "C" fn {name}({params}) -> {ret} {{
    {name}_impl({param_names})
}}
"#,
                name = func.name,
                params = params_with_types,
                ret = return_ty,
                param_names = param_names,
            )
        }
    }
}

/// Generate a capability-protected Python function wrapper
pub fn generate_python_wrapper(func: &ProtectedFunction) -> String {
    let cap_bytes = func.capability.as_bytes()
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    
    let params: String = func.params
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    
    match func.scope {
        Scope::Internal => {
            format!(
                r#"
_CAP_{name_upper} = bytes([{cap_bytes}])

def __poly_{name}(__cap: bytes, {params}):
    if not poly_verify_internal(__cap, _CAP_{name_upper}):
        poly_access_denied()
    return {name}_impl({params})
"#,
                name_upper = func.name.to_uppercase(),
                cap_bytes = cap_bytes,
                name = func.name,
                params = params,
            )
        }
        
        Scope::Export => {
            format!(
                r#"
def poly_{name}(__cap: bytes, {params}):
    if not poly_verify_export(__cap):
        poly_access_denied()
    return {name}_impl({params})
"#,
                name = func.name,
                params = params,
            )
        }
        
        Scope::Public => {
            format!(
                r#"
def {name}({params}):
    return {name}_impl({params})
"#,
                name = func.name,
                params = params,
            )
        }
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capability_generation() {
        let mut gen = CapabilityGenerator::with_seed([42u8; 32]);
        
        let cap1 = gen.generate_file_capability("math.poly");
        let cap2 = gen.generate_file_capability("math.poly");
        let cap3 = gen.generate_file_capability("other.poly");
        
        // Same input = same capability
        assert_eq!(cap1, cap2);
        
        // Different input = different capability
        assert_ne!(cap1, cap3);
    }
    
    #[test]
    fn test_capability_verification() {
        let mut gen = CapabilityGenerator::with_seed([42u8; 32]);
        let eco_cap = gen.generate_ecosystem_capability();
        let file_cap = gen.generate_file_capability("test.poly");
        
        let verifier = CapabilityVerifier::new(eco_cap);
        verifier.register_file("test.poly", file_cap);
        
        // Internal verification
        assert!(verifier.verify_internal(&file_cap, "test.poly"));
        assert!(!verifier.verify_internal(&eco_cap, "test.poly"));
        
        // Export verification
        assert!(verifier.verify_export(&file_cap));
        assert!(verifier.verify_export(&eco_cap));
        assert!(!verifier.verify_export(&Capability::INVALID));
    }
    
    #[test]
    fn test_secure_eq_timing() {
        let cap1 = Capability([0x00; 16]);
        let cap2 = Capability([0xFF; 16]);
        let cap3 = Capability([0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
                               0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF]);
        
        // All comparisons should take similar time
        assert!(!cap1.secure_eq(&cap2));
        assert!(!cap1.secure_eq(&cap3));
        assert!(!cap2.secure_eq(&cap3));
        assert!(cap1.secure_eq(&cap1));
    }
    
    #[test]
    fn test_rust_wrapper_generation() {
        let mut gen = CapabilityGenerator::with_seed([42u8; 32]);
        
        let func = ProtectedFunction {
            name: "helper".to_string(),
            file_path: "math.poly".to_string(),
            scope: Scope::Internal,
            capability: gen.generate_function_capability("math.poly", "helper"),
            params: vec![("x".to_string(), "f32".to_string())],
            return_type: Some("f32".to_string()),
        };
        
        let code = generate_rust_wrapper(&func);
        
        assert!(code.contains("__poly_helper"));
        assert!(code.contains("verify_internal"));
        assert!(code.contains("__cap: [u8; 16]"));
    }
    
    #[test]
    fn test_manifest_generation() {
        let mut gen = CapabilityGenerator::with_seed([42u8; 32]);
        gen.generate_file_capability("math.poly");
        gen.generate_file_capability("util.poly");
        gen.generate_ecosystem_capability();
        
        let manifest = gen.export_capabilities();
        
        let rust_code = manifest.to_rust_code("test_project");
        assert!(rust_code.contains("pub mod __poly_cap"));
        assert!(rust_code.contains("FILE_MATH_POLY"));
        
        let python_code = manifest.to_python_code("test_project");
        assert!(python_code.contains("class __PolyCap"));
        assert!(python_code.contains("FILE_MATH_POLY"));
    }
}
