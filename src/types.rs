use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum WitType {
    Bool,
    S32,
    S64,
    U8,
    U32,
    U64,
    F32,
    F64,
    String,
    Bytes,
    List(Box<WitType>),
    Dict(Box<WitType>, Box<WitType>),
    Option(Box<WitType>),
    Result(Box<WitType>, Box<WitType>),
    Tuple(Vec<WitType>),
    Array(Box<WitType>, usize),
    Record(String), // Changed to String for named reference
    Enum(String),
    Variant(String),
    Flags(String),
    Resource(String),
    Tensor(Box<WitType>),
    Custom(String),
    Unit,
    Any,
    // Add missing
    S8,
    S16,
    U16,
}

#[derive(Debug, Clone)]
pub struct FunctionSig {
    pub name: String,
    pub params: Vec<Param>,
    pub returns: Option<WitType>,
    pub is_async: bool,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: WitType,
    pub default: Option<String>,
}

#[derive(Clone)]
pub struct CompileOptions {
    pub release: bool,
    pub target: CompileTarget,
    pub temp_dir: PathBuf,
    /// Which language contains the main entry point: "rust" or "python"
    pub main_lang: Option<String>,
    pub test_mode: bool,
    /// Path to the source .poly file (for locating poly.toml)
    pub source_path: Option<PathBuf>,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            release: false,
            target: CompileTarget::default(),
            temp_dir: PathBuf::from("target/polyglot_tmp"),
            main_lang: None,
            test_mode: false,
            source_path: None,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub enum CompileTarget {
    #[default]
    Wasm32Wasi,
    Wasm32Unknown,
    /// Host target: WASM with custom imports for Node.js host
    Host,
    /// Native Android/Termux binary (aarch64-linux-android)
    Aarch64Android,
    /// Native Linux binary (x86_64-unknown-linux-gnu)
    X86_64Linux,
    /// Native Windows binary (x86_64-pc-windows-msvc)
    X86_64Windows,
}

impl CompileTarget {
    /// Returns true if this is a native (non-WASM) target
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Aarch64Android | Self::X86_64Linux | Self::X86_64Windows)
    }
    
    /// Returns the Rust target triple for this target
    pub fn target_triple(&self) -> &'static str {
        match self {
            Self::Wasm32Wasi => "wasm32-wasip1",
            Self::Wasm32Unknown => "wasm32-unknown-unknown",
            Self::Host => "wasm32-wasip1",
            Self::Aarch64Android => "aarch64-linux-android",
            Self::X86_64Linux => "x86_64-unknown-linux-gnu",
            Self::X86_64Windows => "x86_64-pc-windows-msvc",
        }
    }
    
    /// Returns the output file extension for this target
    pub fn output_extension(&self) -> &'static str {
        match self {
            Self::Wasm32Wasi | Self::Wasm32Unknown | Self::Host => "wasm",
            Self::X86_64Windows => "exe",
            _ => "", // Linux/Android binaries have no extension
        }
    }
}

// Keep WasmTarget as alias for backward compatibility
pub type WasmTarget = CompileTarget;
