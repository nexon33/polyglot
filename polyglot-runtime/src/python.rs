//! Python runtime wrapper using RustPython
//!
//! RustPython is a Python 3 interpreter written entirely in Rust.
//! No system Python installation required - fully self-contained!

use crate::{PolyglotError, Result};
use once_cell::sync::Lazy;
use rustpython_vm::{
    builtins::PyStrRef, compiler, function::FuncArgs, Interpreter, PyResult, Settings,
};
use std::sync::Mutex;

/// Global RustPython interpreter instance
static INTERPRETER: Lazy<Mutex<Interpreter>> = Lazy::new(|| {
    let interp = Interpreter::with_init(Settings::default(), |vm| {
        vm.add_native_modules(rustpython_stdlib::get_module_inits());
    });
    Mutex::new(interp)
});

/// Python runtime wrapper (uses embedded RustPython)
pub struct PythonRuntime;

impl PythonRuntime {
    /// Get the Python runtime
    pub fn get() -> Self {
        Self
    }

    /// Evaluate a Python expression and return the result as i32
    pub fn eval_i32(&self, code: &str) -> Result<i32> {
        let interp = INTERPRETER
            .lock()
            .map_err(|e| PolyglotError::Python(e.to_string()))?;

        interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            // Compile and execute
            let code_obj = vm
                .compile(code, compiler::Mode::Eval, "<py!>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {}", e)))?;

            let result = vm
                .run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Runtime error: {:?}", e)))?;

            // Convert to i32
            vm.to_index(&result)
                .map_err(|e| {
                    PolyglotError::TypeConversion(format!("Cannot convert to i32: {:?}", e))
                })
                .map(|idx| idx.as_bigint().to_i32().unwrap_or(0))
        })
    }

    /// Evaluate a Python expression and return the result as f64
    pub fn eval_f64(&self, code: &str) -> Result<f64> {
        let interp = INTERPRETER
            .lock()
            .map_err(|e| PolyglotError::Python(e.to_string()))?;

        interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm
                .compile(code, compiler::Mode::Eval, "<py!>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {}", e)))?;

            let result = vm
                .run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Runtime error: {:?}", e)))?;

            // Convert to f64
            vm.to_index(&result)
                .map_err(|e| {
                    PolyglotError::TypeConversion(format!("Cannot convert to f64: {:?}", e))
                })
                .map(|idx| idx.as_bigint().to_f64().unwrap_or(0.0))
        })
    }

    /// Evaluate a Python expression and return the result as String
    pub fn eval_string(&self, code: &str) -> Result<String> {
        let interp = INTERPRETER
            .lock()
            .map_err(|e| PolyglotError::Python(e.to_string()))?;

        interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm
                .compile(code, compiler::Mode::Eval, "<py!>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {}", e)))?;

            let result = vm
                .run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Runtime error: {:?}", e)))?;

            // Convert to string via __str__
            let py_str = result.str(vm).map_err(|e| {
                PolyglotError::TypeConversion(format!("Cannot convert to string: {:?}", e))
            })?;

            Ok(py_str.as_str().to_owned())
        })
    }

    /// Evaluate a Python expression and return as Vec<i32>
    pub fn eval_vec_i32(&self, code: &str) -> Result<Vec<i32>> {
        let interp = INTERPRETER
            .lock()
            .map_err(|e| PolyglotError::Python(e.to_string()))?;

        interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm
                .compile(code, compiler::Mode::Eval, "<py!>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {}", e)))?;

            let result = vm
                .run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Runtime error: {:?}", e)))?;

            // Try to iterate and collect
            let iter = result
                .get_iter(vm)
                .map_err(|e| PolyglotError::TypeConversion(format!("Not iterable: {:?}", e)))?;

            let mut values = Vec::new();
            while let Some(item) = iter.next(vm) {
                let item =
                    item.map_err(|e| PolyglotError::Python(format!("Iterator error: {:?}", e)))?;
                let idx = vm
                    .to_index(&item)
                    .map_err(|e| PolyglotError::TypeConversion(format!("Item not int: {:?}", e)))?;
                values.push(idx.as_bigint().to_i32().unwrap_or(0));
            }

            Ok(values)
        })
    }

    /// Execute Python statements (no return value)
    pub fn exec(&self, code: &str) -> Result<()> {
        let interp = INTERPRETER
            .lock()
            .map_err(|e| PolyglotError::Python(e.to_string()))?;

        interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm
                .compile(code, compiler::Mode::Exec, "<py!>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {}", e)))?;

            vm.run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Runtime error: {:?}", e)))?;

            Ok(())
        })
    }
}
