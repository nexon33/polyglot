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
            // [R38-01] Range-check rather than truncate. `*i as i32` silently
            // discarded the high bits of an out-of-range Int, so a foreign Int
            // outside i32 range produced a wrong i32 that still passed
            // `FromForeign for i32`.
            ForeignValue::Int(i) => i32::try_from(*i).ok(),
            ForeignValue::Float(f) => {
                if f.is_finite() && *f >= i32::MIN as f64 && *f <= i32::MAX as f64 {
                    Some(*f as i32)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ForeignValue::Int(i) => Some(*i),
            // [R38-01] Range-check the float→i64 conversion. A non-finite or
            // out-of-range float must not silently saturate to i64::MIN/MAX.
            ForeignValue::Float(f) => {
                if f.is_finite() && *f >= i64::MIN as f64 && *f <= i64::MAX as f64 {
                    Some(*f as i64)
                } else {
                    None
                }
            }
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
        // [R38-01 FIX] Reject negative and out-of-range values. This previously
        // delegated to `as_i64` and cast `i as usize`, so a negative foreign
        // Int — e.g. the ubiquitous `-1` error sentinel — wrapped to a
        // gigantic `usize` (usize::MAX). A `usize` marshaled from a foreign
        // call is typically used as a length, capacity, or index, so a wrapped
        // value means an OOM-sized allocation or an out-of-bounds access
        // instead of a clean `FromForeign` type error.
        match self {
            ForeignValue::Int(i) => usize::try_from(*i).ok(),
            ForeignValue::Float(f) => {
                if f.is_finite() && *f >= 0.0 && *f <= usize::MAX as f64 {
                    Some(*f as usize)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Convert to JavaScript literal for expression building
    pub fn to_js_literal(&self) -> String {
        match self {
            ForeignValue::Null => "null".to_string(),
            ForeignValue::Bool(b) => b.to_string(),
            ForeignValue::Int(i) => i.to_string(),
            ForeignValue::Float(f) => f.to_string(),
            ForeignValue::String(s) => {
                format!("\"{}\"", escape_js_string(s))
            }
            ForeignValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| v.to_js_literal()).collect();
                format!("[{}]", items.join(", "))
            }
            ForeignValue::Object(map) => {
                let pairs: Vec<String> = map
                    .iter()
                    // [R23-01 FIX] Object keys MUST be escaped. Previously the
                    // key was interpolated raw (`format!("\"{}\":", k)`), so a
                    // `ForeignValue::Object` whose key contained `"` — e.g.
                    // `x": (maliciousJs()), "y` — produced syntactically valid
                    // JS that executed attacker code when `call_method` evals
                    // the assembled expression. Both key and value now go
                    // through `escape_js_string`.
                    .map(|(k, v)| format!("\"{}\": {}", escape_js_string(k), v.to_js_literal()))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
            ForeignValue::Handle(id) => format!("__handle_{}", id),
        }
    }
}

/// Escape a string for safe embedding inside a JavaScript double-quoted
/// string literal.
///
/// [R23-01] The previous inline escaper only handled `\` and `"`. It missed
/// JS line terminators (`\n`, `\r`, U+2028, U+2029) — a raw line terminator
/// inside a `"..."` literal terminates the literal, which both breaks the
/// `call_method` eval expression and, on the object-key path, lets an attacker
/// inject code. Control characters are escaped too. Backslash is escaped first
/// so the escape sequences this function emits are not themselves re-escaped.
pub(crate) fn escape_js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Whether `method` is a safe JavaScript member-access path: a non-empty
/// sequence of dot-separated identifiers (`foo`, `obj.method`, `a.b.c`).
///
/// [R28-01] `ForeignHandle::call_method` interpolates `method` into the eval
/// expression `({method})(...)`. R23 escaped the argument values but the
/// method name was still raw — a runtime-derived method string such as
/// `globalThis.x=1)//` would break out and inject arbitrary JS. This rejects
/// anything that is not a plain identifier path (parentheses, quotes,
/// operators, whitespace, etc.).
pub fn is_safe_js_method_path(method: &str) -> bool {
    !method.is_empty()
        && method.split('.').all(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
                _ => return false,
            }
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        })
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
        // [R28-01 FIX] Validate the method name before interpolating it into
        // the `({method})(...)` eval expression. R23 escaped the argument
        // values; the method name was still raw, so a runtime-derived method
        // string could break out of the expression and inject arbitrary JS.
        if !is_safe_js_method_path(method) {
            return ForeignValue::Null;
        }
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
            // [R27-01 FIX] Previously this fabricated a String from the Debug
            // representation of any non-string value (`format!("{:?}", other)`).
            // A foreign function declared to return a string that actually
            // returned an Int/Array/Object/Handle then yielded a value that
            // passed type-checking but was NOT what the foreign call produced
            // (e.g. the literal text `Object({"role": String("admin")})`) —
            // a type confusion at the marshaling boundary that could feed a
            // fabricated string into a downstream security decision. Every
            // other FromForeign impl errors on a type mismatch; String now
            // does too.
            other => Err(crate::PolyglotError::TypeConversion(format!(
                "Expected string, got {:?}",
                other
            ))),
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
