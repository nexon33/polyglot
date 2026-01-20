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
    pub target: WasmTarget,
    pub temp_dir: PathBuf,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            release: false,
            target: WasmTarget::default(),
            temp_dir: PathBuf::from("target/polyglot_tmp"),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub enum WasmTarget {
    #[default]
    Wasm32Wasi,
    Wasm32Unknown,
}
