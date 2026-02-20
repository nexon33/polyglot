//! Scripting runtime wrapper using Rhai
//!
//! Rhai is a lightweight, embedded scripting language for Rust.
//! Syntax is similar to Rust/JS/Python hybrid.
//! Fully self-contained, no external dependencies!

use crate::{PolyglotError, Result};
use rhai::{Array, Engine};

/// Scripting runtime wrapper (uses embedded Rhai engine)
pub struct ScriptRuntime {
    engine: Engine,
}

impl ScriptRuntime {
    /// Create a new scripting runtime
    pub fn new() -> Self {
        Self {
            engine: Engine::new(),
        }
    }

    /// Get a scripting runtime
    pub fn get() -> Self {
        Self::new()
    }

    /// Evaluate an expression and return the result as i32
    pub fn eval_i32(&self, code: &str) -> Result<i32> {
        self.engine
            .eval::<i64>(code)
            .map(|v| v as i32)
            .map_err(|e| PolyglotError::Python(format!("Eval error: {}", e)))
    }

    /// Evaluate an expression and return the result as f64
    pub fn eval_f64(&self, code: &str) -> Result<f64> {
        self.engine
            .eval::<f64>(code)
            .map_err(|e| PolyglotError::Python(format!("Eval error: {}", e)))
    }

    /// Evaluate an expression and return the result as String
    pub fn eval_string(&self, code: &str) -> Result<String> {
        self.engine
            .eval::<String>(code)
            .map_err(|e| PolyglotError::Python(format!("Eval error: {}", e)))
    }

    /// Evaluate an expression and return as Vec<i32>
    pub fn eval_vec_i32(&self, code: &str) -> Result<Vec<i32>> {
        let result: Array = self
            .engine
            .eval(code)
            .map_err(|e| PolyglotError::Python(format!("Eval error: {}", e)))?;

        let mut values = Vec::with_capacity(result.len());
        for item in result {
            let i = item
                .as_int()
                .map_err(|_| PolyglotError::TypeConversion("Array item not an int".to_string()))?;
            values.push(i as i32);
        }

        Ok(values)
    }

    /// Execute script (no return value)
    pub fn exec(&self, code: &str) -> Result<()> {
        self.engine
            .run(code)
            .map_err(|e| PolyglotError::Python(format!("Run error: {}", e)))
    }
}

// Keep PythonRuntime as alias for backwards compatibility
pub type PythonRuntime = ScriptRuntime;
