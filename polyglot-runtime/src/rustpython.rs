//! Python runtime wrapper using RustPython
//!
//! RustPython is a full Python 3 interpreter implemented in Rust.
//! This allows executing actual Python code within Rust!

use crate::{PolyglotError, Result};

#[cfg(feature = "python")]
use rustpython_vm::{
    Interpreter,
    PyResult,
    VirtualMachine,
    builtins::PyStr,
    compiler::Mode,
};

/// Python runtime wrapper (uses embedded RustPython interpreter)
#[cfg(feature = "python")]
pub struct PyRuntime {
    interp: Interpreter,
}

#[cfg(feature = "python")]
impl PyRuntime {
    /// Create a new Python runtime
    pub fn new() -> Self {
        let interp = Interpreter::without_stdlib(Default::default());
        Self { interp }
    }

    /// Get a Python runtime (creates new instance)
    pub fn get() -> Self {
        Self::new()
    }

    /// Evaluate a Python expression and return the result as i32
    pub fn eval_i32(&self, code: &str) -> Result<i32> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm.compile(code, Mode::Eval, "<eval>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            let result = vm.run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Python error: {:?}", e)))?;

            // Try to get as integer
            let int_result = result.clone().try_into_value::<i64>(vm)
                .map(|v| v as i32)
                .or_else(|_| {
                    result.try_into_value::<i32>(vm)
                })
                .map_err(|_| PolyglotError::TypeConversion(
                    "Cannot convert Python result to i32".to_string()
                ))?;

            Ok(int_result)
        })
    }

    /// Evaluate a Python expression and return the result as f64
    pub fn eval_f64(&self, code: &str) -> Result<f64> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm.compile(code, Mode::Eval, "<eval>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            let result = vm.run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Python error: {:?}", e)))?;

            result.try_into_value::<f64>(vm)
                .map_err(|_| PolyglotError::TypeConversion(
                    "Cannot convert Python result to f64".to_string()
                ))
        })
    }

    /// Evaluate a Python expression and return the result as String
    pub fn eval_string(&self, code: &str) -> Result<String> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm.compile(code, Mode::Eval, "<eval>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            let result = vm.run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Python error: {:?}", e)))?;

            // Convert to string using Python's str()
            let str_result = result.str(vm)
                .map_err(|e| PolyglotError::TypeConversion(
                    format!("Cannot convert to string: {:?}", e)
                ))?;

            Ok(str_result.as_str().to_string())
        })
    }

    /// Evaluate a Python expression and return as Vec<i32>
    pub fn eval_vec_i32(&self, code: &str) -> Result<Vec<i32>> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm.compile(code, Mode::Eval, "<eval>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            let result = vm.run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Python error: {:?}", e)))?;

            // Convert to list of i32
            let list: Vec<i64> = result.try_into_value(vm)
                .map_err(|_| PolyglotError::TypeConversion(
                    "Cannot convert to list of integers".to_string()
                ))?;

            Ok(list.into_iter().map(|v| v as i32).collect())
        })
    }

    /// Execute Python code (no return value)
    pub fn exec(&self, code: &str) -> Result<()> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let code_obj = vm.compile(code, Mode::Exec, "<exec>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            vm.run_code_obj(code_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Python error: {:?}", e)))?;

            Ok(())
        })
    }

    /// Execute Python code and then evaluate an expression in the same scope
    pub fn exec_and_eval_i32(&self, setup_code: &str, eval_expr: &str) -> Result<i32> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            // First execute the setup code (class definition, etc.)
            let setup_obj = vm.compile(setup_code, Mode::Exec, "<setup>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            vm.run_code_obj(setup_obj, scope.clone())
                .map_err(|e| PolyglotError::Python(format!("Setup error: {:?}", e)))?;

            // Then evaluate the expression
            let eval_obj = vm.compile(eval_expr, Mode::Eval, "<eval>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            let result = vm.run_code_obj(eval_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Eval error: {:?}", e)))?;

            let int_result = result.clone().try_into_value::<i64>(vm)
                .map(|v| v as i32)
                .or_else(|_| result.try_into_value::<i32>(vm))
                .map_err(|_| PolyglotError::TypeConversion(
                    "Cannot convert Python result to i32".to_string()
                ))?;

            Ok(int_result)
        })
    }

    /// Execute Python code and then evaluate an expression, returning String
    pub fn exec_and_eval_string(&self, setup_code: &str, eval_expr: &str) -> Result<String> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            // First execute the setup code
            let setup_obj = vm.compile(setup_code, Mode::Exec, "<setup>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            vm.run_code_obj(setup_obj, scope.clone())
                .map_err(|e| PolyglotError::Python(format!("Setup error: {:?}", e)))?;

            // Then evaluate the expression
            let eval_obj = vm.compile(eval_expr, Mode::Eval, "<eval>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            let result = vm.run_code_obj(eval_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Eval error: {:?}", e)))?;

            let str_result = result.str(vm)
                .map_err(|e| PolyglotError::TypeConversion(
                    format!("Cannot convert to string: {:?}", e)
                ))?;

            Ok(str_result.as_str().to_string())
        })
    }

    /// Execute Python code and then evaluate an expression, returning Vec<i32>
    pub fn exec_and_eval_vec_i32(&self, setup_code: &str, eval_expr: &str) -> Result<Vec<i32>> {
        self.interp.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            // First execute the setup code
            let setup_obj = vm.compile(setup_code, Mode::Exec, "<setup>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            vm.run_code_obj(setup_obj, scope.clone())
                .map_err(|e| PolyglotError::Python(format!("Setup error: {:?}", e)))?;

            // Then evaluate the expression
            let eval_obj = vm.compile(eval_expr, Mode::Eval, "<eval>".to_owned())
                .map_err(|e| PolyglotError::Python(format!("Compile error: {:?}", e)))?;

            let result = vm.run_code_obj(eval_obj, scope)
                .map_err(|e| PolyglotError::Python(format!("Eval error: {:?}", e)))?;

            // Convert to list of i32
            let list: Vec<i64> = result.try_into_value(vm)
                .map_err(|_| PolyglotError::TypeConversion(
                    "Cannot convert to list of integers".to_string()
                ))?;

            Ok(list.into_iter().map(|v| v as i32).collect())
        })
    }
}

#[cfg(feature = "python")]
impl Default for PyRuntime {
    fn default() -> Self {
        Self::new()
    }
}
