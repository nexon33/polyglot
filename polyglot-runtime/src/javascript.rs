//! JavaScript runtime wrapper (stub)

use crate::{PolyglotError, Result};

pub struct JsRuntime;

impl JsRuntime {
    pub fn get() -> Self {
        JsRuntime
    }

    pub fn eval<T>(&self, _code: &str) -> Result<T> {
        Err(PolyglotError::NotInitialized(
            "JavaScript runtime not yet implemented".to_string(),
        ))
    }
}
