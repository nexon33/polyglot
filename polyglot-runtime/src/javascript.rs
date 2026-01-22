//! JavaScript runtime wrapper using Boa Engine
//!
//! Boa is a JavaScript engine written entirely in Rust.
//! No Node.js or browser required - fully self-contained!

use crate::{PolyglotError, Result};
use boa_engine::{Context, JsValue, Source};

/// JavaScript runtime wrapper (uses embedded Boa engine)
pub struct JsRuntime;

impl JsRuntime {
    /// Get the JavaScript runtime
    pub fn get() -> Self {
        Self
    }

    /// Evaluate a JavaScript expression and return the result as i32
    pub fn eval_i32(&self, code: &str) -> Result<i32> {
        let mut ctx = Context::default();

        let result = ctx
            .eval(Source::from_bytes(code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        result
            .to_i32(&mut ctx)
            .map_err(|e| PolyglotError::TypeConversion(format!("Cannot convert to i32: {:?}", e)))
    }

    /// Evaluate a JavaScript expression and return the result as f64
    pub fn eval_f64(&self, code: &str) -> Result<f64> {
        let mut ctx = Context::default();

        let result = ctx
            .eval(Source::from_bytes(code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        result
            .to_number(&mut ctx)
            .map_err(|e| PolyglotError::TypeConversion(format!("Cannot convert to f64: {:?}", e)))
    }

    /// Evaluate a JavaScript expression and return the result as String
    pub fn eval_string(&self, code: &str) -> Result<String> {
        let mut ctx = Context::default();

        let result = ctx
            .eval(Source::from_bytes(code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        let js_str = result.to_string(&mut ctx).map_err(|e| {
            PolyglotError::TypeConversion(format!("Cannot convert to String: {:?}", e))
        })?;

        Ok(js_str.to_std_string_escaped())
    }

    /// Evaluate a JavaScript expression and return as Vec<i32>
    pub fn eval_vec_i32(&self, code: &str) -> Result<Vec<i32>> {
        let mut ctx = Context::default();

        let result = ctx
            .eval(Source::from_bytes(code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        // Use JSON.stringify to get array contents
        let json = result.to_json(&mut ctx).map_err(|e| {
            PolyglotError::TypeConversion(format!("Cannot convert to JSON: {:?}", e))
        })?;

        if let Some(arr) = json.as_array() {
            let mut values = Vec::with_capacity(arr.len());
            for item in arr {
                if let Some(n) = item.as_i64() {
                    values.push(n as i32);
                } else if let Some(n) = item.as_f64() {
                    values.push(n as i32);
                } else {
                    return Err(PolyglotError::TypeConversion(
                        "Array item not a number".to_string(),
                    ));
                }
            }
            Ok(values)
        } else {
            Err(PolyglotError::TypeConversion(
                "Result is not an array".to_string(),
            ))
        }
    }

    /// Execute JavaScript code (no return value)
    pub fn exec(&self, code: &str) -> Result<()> {
        let mut ctx = Context::default();

        ctx.eval(Source::from_bytes(code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        Ok(())
    }
}
