//! Bridge infrastructure for cross-language FFI
//!
//! Provides types and traits for type-safe foreign function calls:
//! - `ForeignHandle` - Handle to a foreign object
//! - `ForeignValue` - Dynamically typed foreign value  
//! - `ToForeign` / `FromForeign` - Marshaling traits

use std::collections::HashMap;

/// A dynamically typed value from a foreign runtime
#[derive(Debug, Clone)]
pub enum ForeignValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<ForeignValue>),
    Object(HashMap<String, ForeignValue>),
    Handle(u64), // Reference to a foreign object
}

impl ForeignValue {
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            ForeignValue::Int(i) => Some(*i as i32),
            ForeignValue::Float(f) => Some(*f as i32),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ForeignValue::Int(i) => Some(*i),
            ForeignValue::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            ForeignValue::Float(f) => Some(*f),
            ForeignValue::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            ForeignValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ForeignValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_usize(&self) -> Option<usize> {
        self.as_i64().map(|i| i as usize)
    }

    /// Convert to JavaScript literal for expression building
    pub fn to_js_literal(&self) -> String {
        match self {
            ForeignValue::Null => "null".to_string(),
            ForeignValue::Bool(b) => b.to_string(),
            ForeignValue::Int(i) => i.to_string(),
            ForeignValue::Float(f) => f.to_string(),
            ForeignValue::String(s) => {
                format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
            }
            ForeignValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| v.to_js_literal()).collect();
                format!("[{}]", items.join(", "))
            }
            ForeignValue::Object(map) => {
                let pairs: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("\"{}\": {}", k, v.to_js_literal()))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
            ForeignValue::Handle(id) => format!("__handle_{}", id),
        }
    }
}

/// Reference to a runtime for releasing handles
#[derive(Clone)]
pub struct RuntimeRef {
    release_fn: fn(u64),
}

impl RuntimeRef {
    pub fn new(release_fn: fn(u64)) -> Self {
        Self { release_fn }
    }

    pub fn release(&self, id: u64) {
        (self.release_fn)(id);
    }

    /// No-op runtime for handles that don't need cleanup
    pub fn noop() -> Self {
        Self { release_fn: |_| {} }
    }
}

impl std::fmt::Debug for RuntimeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuntimeRef")
    }
}

/// Handle to a foreign object in a runtime
#[derive(Debug)]
pub struct ForeignHandle {
    id: u64,
    value: ForeignValue,
    runtime: Option<RuntimeRef>,
}

impl ForeignHandle {
    /// Create a new handle from a foreign value (no cleanup)
    pub fn new(value: ForeignValue) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            value,
            runtime: None,
        }
    }

    /// Create with explicit runtime reference for cleanup
    pub fn with_runtime(value: ForeignValue, runtime: RuntimeRef) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            value,
            runtime: Some(runtime),
        }
    }

    /// Get the handle ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the underlying value
    pub fn value(&self) -> &ForeignValue {
        &self.value
    }

    /// Call a method on the foreign object using expression string
    ///
    /// For objects, evaluates: `obj.method(arg1, arg2, ...)`
    /// Arguments are serialized to JSON for safe cross-boundary passing.
    pub fn call_method(&self, method: &str, args: &[ForeignValue]) -> ForeignValue {
        // Build the method call expression
        let args_str: Vec<String> = args.iter().map(|a| a.to_js_literal()).collect();
        let args_joined = args_str.join(", ");

        // For object values, we need the object reference
        // For now, use a simplified approach with direct eval
        let expr = format!("({})({})", method, args_joined);

        #[cfg(feature = "javascript")]
        {
            use crate::prelude::JsRuntime;
            let rt = JsRuntime::get();
            if let Ok(result) = rt.eval_string(&expr) {
                return ForeignValue::String(result);
            }
        }

        #[cfg(feature = "scripting")]
        {
            use crate::prelude::ScriptRuntime;
            let rt = ScriptRuntime::get();
            if let Ok(result) = rt.eval_string(&expr) {
                return ForeignValue::String(result);
            }
        }

        ForeignValue::Null
    }
}

impl Clone for ForeignHandle {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            value: self.value.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

impl Drop for ForeignHandle {
    fn drop(&mut self) {
        // Release reference in foreign runtime
        if let Some(ref runtime) = self.runtime {
            runtime.release(self.id);
        }
    }
}

/// Convert Rust type to foreign value
pub trait ToForeign {
    fn to_foreign(&self) -> ForeignValue;
}

/// Convert foreign value to Rust type
pub trait FromForeign: Sized {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Primitive Implementations
// ═══════════════════════════════════════════════════════════════════════════

impl ToForeign for i32 {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::Int(*self as i64)
    }
}

impl ToForeign for i64 {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::Int(*self)
    }
}

impl ToForeign for f64 {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::Float(*self)
    }
}

impl ToForeign for bool {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::Bool(*self)
    }
}

impl ToForeign for String {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::String(self.clone())
    }
}

impl ToForeign for &str {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::String(self.to_string())
    }
}

impl<T: ToForeign> ToForeign for Vec<T> {
    fn to_foreign(&self) -> ForeignValue {
        ForeignValue::Array(self.iter().map(|x| x.to_foreign()).collect())
    }
}

impl<T: ToForeign> ToForeign for Option<T> {
    fn to_foreign(&self) -> ForeignValue {
        match self {
            Some(v) => v.to_foreign(),
            None => ForeignValue::Null,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FromForeign Implementations
// ═══════════════════════════════════════════════════════════════════════════

impl FromForeign for i32 {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        value
            .as_i32()
            .ok_or_else(|| crate::PolyglotError::TypeConversion("Expected i32".to_string()))
    }
}

impl FromForeign for i64 {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        value
            .as_i64()
            .ok_or_else(|| crate::PolyglotError::TypeConversion("Expected i64".to_string()))
    }
}

impl FromForeign for f64 {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        value
            .as_f64()
            .ok_or_else(|| crate::PolyglotError::TypeConversion("Expected f64".to_string()))
    }
}

impl FromForeign for bool {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        value
            .as_bool()
            .ok_or_else(|| crate::PolyglotError::TypeConversion("Expected bool".to_string()))
    }
}

impl FromForeign for String {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        match value {
            ForeignValue::String(s) => Ok(s),
            other => Ok(format!("{:?}", other)), // Fallback to debug format
        }
    }
}

impl FromForeign for usize {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        value
            .as_usize()
            .ok_or_else(|| crate::PolyglotError::TypeConversion("Expected usize".to_string()))
    }
}

impl<T: FromForeign> FromForeign for Vec<T> {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        match value {
            ForeignValue::Array(arr) => arr.into_iter().map(T::from_foreign).collect(),
            _ => Err(crate::PolyglotError::TypeConversion(
                "Expected array".to_string(),
            )),
        }
    }
}

impl<T: FromForeign> FromForeign for Option<T> {
    fn from_foreign(value: ForeignValue) -> crate::Result<Self> {
        match value {
            ForeignValue::Null => Ok(None),
            other => Ok(Some(T::from_foreign(other)?)),
        }
    }
}

impl FromForeign for () {
    fn from_foreign(_value: ForeignValue) -> crate::Result<Self> {
        Ok(())
    }
}
