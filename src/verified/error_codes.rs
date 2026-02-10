//! Verified execution compiler error codes (V001-V015)
//!
//! These errors are emitted during determinism checking when
//! `#[verified]` functions contain non-deterministic operations.

/// Error code for verified execution violations
#[derive(Debug, Clone)]
pub struct VerifiedCompileError {
    pub code: &'static str,
    pub message: String,
    pub line: usize,
    pub hint: Option<String>,
}

impl std::fmt::Display for VerifiedCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\n  hint: {}", hint)?;
        }
        Ok(())
    }
}

pub const V001: &str = "V001"; // Non-deterministic operation (IO, network, time, random)
pub const V002: &str = "V002"; // Floating-point type used (f32/f64)
pub const V003: &str = "V003"; // Unbounded loop without #[verified_bound]
pub const V004: &str = "V004"; // Call to non-verified/non-pure function
pub const V005: &str = "V005"; // Unsafe code block or raw pointer
pub const V006: &str = "V006"; // Non-deterministic iteration (HashMap::iter)
pub const V007: &str = "V007"; // Global mutable state (static mut)
pub const V008: &str = "V008"; // Interior mutability (Cell, RefCell, Mutex)
pub const V009: &str = "V009"; // System time or instant access
pub const V010: &str = "V010"; // Environment variable access
pub const V011: &str = "V011"; // Thread or async task spawning
pub const V012: &str = "V012"; // Dynamic dispatch (dyn Trait) in verified context
pub const V013: &str = "V013"; // Inline assembly
pub const V014: &str = "V014"; // Process spawning (Command::new)
pub const V015: &str = "V015"; // Unverified external crate usage

impl VerifiedCompileError {
    pub fn new(code: &'static str, message: impl Into<String>, line: usize) -> Self {
        Self {
            code,
            message: message.into(),
            line,
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}
