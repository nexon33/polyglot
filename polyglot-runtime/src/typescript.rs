//! TypeScript runtime wrapper using SWC + Boa Engine
//!
//! Uses SWC (Rust-based TypeScript compiler) to transpile TS to JS,
//! then runs with Boa engine. Fully self-contained, no Node.js needed!

use crate::{PolyglotError, Result};
use boa_engine::{Context, Source};
use swc_core::common::{sync::Lrc, FileName, Globals, SourceMap, GLOBALS};
use swc_core::ecma::ast::*;
use swc_core::ecma::transforms::typescript::strip;
use swc_core::ecma::visit::{as_folder, FoldWith};
use swc_ecma_codegen::{text_writer::JsWriter, Emitter};
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax, TsConfig};

/// TypeScript runtime wrapper
pub struct TsRuntime;

impl TsRuntime {
    /// Get the TypeScript runtime
    pub fn get() -> Self {
        Self
    }

    /// Transpile TypeScript to JavaScript using SWC
    fn transpile_ts_to_js(ts_code: &str) -> Result<String> {
        let cm: Lrc<SourceMap> = Default::default();
        let fm = cm.new_source_file(FileName::Anon, ts_code.to_string());

        let lexer = Lexer::new(
            Syntax::Typescript(TsConfig {
                tsx: false,
                decorators: false,
                ..Default::default()
            }),
            EsVersion::Es2020,
            StringInput::from(&*fm),
            None,
        );

        let mut parser = Parser::new_from(lexer);

        let module = parser
            .parse_module()
            .map_err(|e| PolyglotError::TypeConversion(format!("TS parse error: {:?}", e)))?;

        // Strip TypeScript types
        let module = GLOBALS.set(&Globals::new(), || {
            module.fold_with(&mut as_folder(strip()))
        });

        // Generate JavaScript code
        let mut buf = vec![];
        {
            let mut emitter = Emitter {
                cfg: swc_ecma_codegen::Config::default(),
                cm: cm.clone(),
                comments: None,
                wr: JsWriter::new(cm.clone(), "\n", &mut buf, None),
            };

            emitter
                .emit_module(&module)
                .map_err(|e| PolyglotError::TypeConversion(format!("JS emit error: {:?}", e)))?;
        }

        String::from_utf8(buf)
            .map_err(|e| PolyglotError::TypeConversion(format!("UTF8 error: {:?}", e)))
    }

    /// Evaluate a TypeScript expression and return the result as i32
    pub fn eval_i32(&self, code: &str) -> Result<i32> {
        let js_code = Self::transpile_ts_to_js(code)?;
        let mut ctx = Context::default();

        let result = ctx
            .eval(Source::from_bytes(&js_code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        result
            .to_i32(&mut ctx)
            .map_err(|e| PolyglotError::TypeConversion(format!("Cannot convert to i32: {:?}", e)))
    }

    /// Evaluate a TypeScript expression and return the result as f64
    pub fn eval_f64(&self, code: &str) -> Result<f64> {
        let js_code = Self::transpile_ts_to_js(code)?;
        let mut ctx = Context::default();

        let result = ctx
            .eval(Source::from_bytes(&js_code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        result
            .to_number(&mut ctx)
            .map_err(|e| PolyglotError::TypeConversion(format!("Cannot convert to f64: {:?}", e)))
    }

    /// Evaluate a TypeScript expression and return the result as String
    pub fn eval_string(&self, code: &str) -> Result<String> {
        let js_code = Self::transpile_ts_to_js(code)?;
        let mut ctx = Context::default();

        let result = ctx
            .eval(Source::from_bytes(&js_code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        let js_str = result.to_string(&mut ctx).map_err(|e| {
            PolyglotError::TypeConversion(format!("Cannot convert to String: {:?}", e))
        })?;

        Ok(js_str.to_std_string_escaped())
    }

    /// Execute TypeScript code (no return value)
    pub fn exec(&self, code: &str) -> Result<()> {
        let js_code = Self::transpile_ts_to_js(code)?;
        let mut ctx = Context::default();

        ctx.eval(Source::from_bytes(&js_code))
            .map_err(|e| PolyglotError::JavaScript(format!("JS error: {:?}", e)))?;

        Ok(())
    }
}
