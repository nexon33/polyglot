//! Python runtime wrapper and interpreter management

use crate::{PolyglotError, Result};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Mutex;

/// Global Python runtime instance
static PYTHON_INIT: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(true));

/// Python runtime wrapper
pub struct PythonRuntime;

impl PythonRuntime {
    /// Get the Python runtime
    pub fn get() -> Self {
        let _ = PYTHON_INIT.lock(); // Ensure initialized
        Self
    }

    /// Evaluate a Python expression and return the result as i32
    pub fn eval_i32(&self, code: &str) -> Result<i32> {
        Python::with_gil(|py| {
            let locals = PyDict::new_bound(py);

            // Pre-import numpy if available
            if let Ok(np) = py.import_bound("numpy") {
                locals.set_item("np", np).ok();
            }

            let result = py
                .eval_bound(code, None, Some(&locals))
                .map_err(|e| PolyglotError::Python(e.to_string()))?;

            result
                .extract::<i32>()
                .map_err(|e| PolyglotError::TypeConversion(e.to_string()))
        })
    }

    /// Evaluate a Python expression and return the result as f64
    pub fn eval_f64(&self, code: &str) -> Result<f64> {
        Python::with_gil(|py| {
            let locals = PyDict::new_bound(py);

            if let Ok(np) = py.import_bound("numpy") {
                locals.set_item("np", np).ok();
            }

            let result = py
                .eval_bound(code, None, Some(&locals))
                .map_err(|e| PolyglotError::Python(e.to_string()))?;

            result
                .extract::<f64>()
                .map_err(|e| PolyglotError::TypeConversion(e.to_string()))
        })
    }

    /// Evaluate a Python expression and return the result as String
    pub fn eval_string(&self, code: &str) -> Result<String> {
        Python::with_gil(|py| {
            let locals = PyDict::new_bound(py);

            let result = py
                .eval_bound(code, None, Some(&locals))
                .map_err(|e| PolyglotError::Python(e.to_string()))?;

            result
                .extract::<String>()
                .map_err(|e| PolyglotError::TypeConversion(e.to_string()))
        })
    }

    /// Evaluate a Python expression and return as Vec<i32>
    pub fn eval_vec_i32(&self, code: &str) -> Result<Vec<i32>> {
        Python::with_gil(|py| {
            let locals = PyDict::new_bound(py);

            if let Ok(np) = py.import_bound("numpy") {
                locals.set_item("np", np).ok();
            }

            let result = py
                .eval_bound(code, None, Some(&locals))
                .map_err(|e| PolyglotError::Python(e.to_string()))?;

            result
                .extract::<Vec<i32>>()
                .map_err(|e| PolyglotError::TypeConversion(e.to_string()))
        })
    }

    /// Execute Python statements (no return value)
    pub fn exec(&self, code: &str) -> Result<()> {
        Python::with_gil(|py| {
            py.run_bound(code, None, None)
                .map_err(|e| PolyglotError::Python(e.to_string()))
        })
    }
}
