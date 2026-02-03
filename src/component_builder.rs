// Phase 26c: Component Builder for WASM Component Model
//
// Compiles language blocks to WASM components using external tools:
// - TypeScript/JavaScript: jco componentize
// - Python: componentize-py
// - Rust: cargo component build (or wasm32-wasip1 target)
//
// Each component implements interfaces defined in #[interface] blocks.

use crate::parser::{ParsedFile, CodeBlock};
use crate::wit_gen::generate_wit_for_file;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of building a component
#[derive(Debug)]
pub struct ComponentBuildResult {
    pub language: String,
    pub wasm_path: PathBuf,
    pub size_bytes: usize,
}

/// Errors during component building
#[derive(Debug)]
pub enum ComponentBuildError {
    WitGeneration(String),
    IoError(std::io::Error),
    ToolNotFound(String),
    ToolFailed { tool: String, stderr: String },
    UnsupportedLanguage(String),
}

impl std::fmt::Display for ComponentBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WitGeneration(msg) => write!(f, "WIT generation failed: {}", msg),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::ToolNotFound(tool) => write!(f, "Tool not found: {}. Install it first.", tool),
            Self::ToolFailed { tool, stderr } => write!(f, "{} failed:\n{}", tool, stderr),
            Self::UnsupportedLanguage(lang) => write!(f, "Unsupported language for componentization: {}", lang),
        }
    }
}

impl std::error::Error for ComponentBuildError {}

impl From<std::io::Error> for ComponentBuildError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

/// Component builder configuration
pub struct ComponentBuilder {
    /// Working directory for temp files
    pub work_dir: PathBuf,
    /// Whether to keep intermediate files
    pub keep_temp: bool,
    /// Verbose output
    pub verbose: bool,
}

impl Default for ComponentBuilder {
    fn default() -> Self {
        Self {
            work_dir: std::env::temp_dir().join("polyglot_components"),
            keep_temp: false,
            verbose: false,
        }
    }
}

impl ComponentBuilder {
    pub fn new(work_dir: PathBuf) -> Self {
        Self {
            work_dir,
            keep_temp: false,
            verbose: false,
        }
    }

    /// Build all language blocks as separate WASM components
    pub fn build_all(
        &self,
        parsed: &ParsedFile,
        filename: &str,
    ) -> Result<Vec<ComponentBuildResult>, ComponentBuildError> {
        // Create work directory
        fs::create_dir_all(&self.work_dir)?;

        // Generate WIT for interfaces
        let wit_content = generate_wit_for_file(parsed, filename)
            .map_err(|e| ComponentBuildError::WitGeneration(e.to_string()))?;

        let wit_path = self.work_dir.join("interfaces.wit");
        fs::write(&wit_path, &wit_content)?;

        if self.verbose {
            println!("📝 Generated WIT: {}", wit_path.display());
        }

        let mut results = Vec::new();

        // Build each language block
        for block in &parsed.blocks {
            if self.verbose {
                println!("  📋 Block: lang_tag='{}' (line {})", block.lang_tag, block.start_line);
            }
            match block.lang_tag.as_str() {
                "typescript" | "ts" => {
                    match self.build_typescript_component(block, &wit_path) {
                        Ok(result) => results.push(result),
                        Err(ComponentBuildError::ToolNotFound(msg)) => {
                            if self.verbose {
                                println!("⚠️  Skipping TypeScript: {}", msg);
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                "javascript" | "js" => {
                    match self.build_javascript_component(block, &wit_path) {
                        Ok(result) => results.push(result),
                        Err(ComponentBuildError::ToolNotFound(msg)) => {
                            if self.verbose {
                                println!("⚠️  Skipping JavaScript: {}", msg);
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                "python" | "py" => {
                    match self.build_python_component(block, &wit_path) {
                        Ok(result) => results.push(result),
                        Err(ComponentBuildError::ToolNotFound(msg)) => {
                            if self.verbose {
                                println!("⚠️  Skipping Python: {}", msg);
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                "rust" | "rs" => {
                    // Rust components are handled by the main compiler
                    // Skip for now - could add cargo-component support later
                    if self.verbose {
                        println!("⏭️  Skipping Rust block (handled by main compiler)");
                    }
                }
                "interface" | "types" | "main" => {
                    // Skip interface/types/main blocks
                }
                other => {
                    if self.verbose {
                        println!("⚠️  Skipping unknown language: {}", other);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Build a TypeScript block using jco componentize
    fn build_typescript_component(
        &self,
        block: &CodeBlock,
        wit_path: &Path,
    ) -> Result<ComponentBuildResult, ComponentBuildError> {
        // Check if jco is installed
        if !self.check_tool("jco") {
            return Err(ComponentBuildError::ToolNotFound(
                "jco (install with: npm install -g @bytecodealliance/jco)".to_string()
            ));
        }

        // Write TypeScript source
        let ts_path = self.work_dir.join("component.ts");
        fs::write(&ts_path, &block.code)?;

        // Output path
        let wasm_path = self.work_dir.join("typescript_component.wasm");

        if self.verbose {
            println!("🔨 Building TypeScript component with jco...");
        }

        // Run jco componentize
        let output = Command::new("jco")
            .args([
                "componentize",
                ts_path.to_str().unwrap(),
                "--wit", wit_path.to_str().unwrap(),
                "-o", wasm_path.to_str().unwrap(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(ComponentBuildError::ToolFailed {
                tool: "jco".to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        let size = fs::metadata(&wasm_path)?.len() as usize;

        if self.verbose {
            println!("✅ TypeScript component: {} ({} bytes)", wasm_path.display(), size);
        }

        Ok(ComponentBuildResult {
            language: "typescript".to_string(),
            wasm_path,
            size_bytes: size,
        })
    }

    /// Build a JavaScript block using jco componentize
    fn build_javascript_component(
        &self,
        block: &CodeBlock,
        wit_path: &Path,
    ) -> Result<ComponentBuildResult, ComponentBuildError> {
        // Check if jco is installed
        if !self.check_tool("jco") {
            return Err(ComponentBuildError::ToolNotFound(
                "jco (install with: npm install -g @bytecodealliance/jco)".to_string()
            ));
        }

        // Write JavaScript source
        let js_path = self.work_dir.join("component.js");
        fs::write(&js_path, &block.code)?;

        // Output path
        let wasm_path = self.work_dir.join("javascript_component.wasm");

        if self.verbose {
            println!("🔨 Building JavaScript component with jco...");
        }

        // Run jco componentize
        let output = Command::new("jco")
            .args([
                "componentize",
                js_path.to_str().unwrap(),
                "--wit", wit_path.to_str().unwrap(),
                "-o", wasm_path.to_str().unwrap(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(ComponentBuildError::ToolFailed {
                tool: "jco".to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        let size = fs::metadata(&wasm_path)?.len() as usize;

        if self.verbose {
            println!("✅ JavaScript component: {} ({} bytes)", wasm_path.display(), size);
        }

        Ok(ComponentBuildResult {
            language: "javascript".to_string(),
            wasm_path,
            size_bytes: size,
        })
    }

    /// Build a Python block using componentize-py
    fn build_python_component(
        &self,
        block: &CodeBlock,
        wit_path: &Path,
    ) -> Result<ComponentBuildResult, ComponentBuildError> {
        // Check if componentize-py is installed
        if !self.check_tool("componentize-py") {
            return Err(ComponentBuildError::ToolNotFound(
                "componentize-py (install with: pip install componentize-py)".to_string()
            ));
        }

        // Write Python source
        let py_path = self.work_dir.join("component.py");
        fs::write(&py_path, &block.code)?;

        // Output path
        let wasm_path = self.work_dir.join("python_component.wasm");

        if self.verbose {
            println!("🔨 Building Python component with componentize-py...");
        }

        // Run componentize-py
        // componentize-py -d <wit-dir> -w <world-name> <python-file> -o <output.wasm>
        let wit_dir = wit_path.parent().unwrap_or(Path::new("."));

        let output = Command::new("componentize-py")
            .args([
                "-d", wit_dir.to_str().unwrap(),
                "-w", "component",  // World name from WIT
                py_path.to_str().unwrap(),
                "-o", wasm_path.to_str().unwrap(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(ComponentBuildError::ToolFailed {
                tool: "componentize-py".to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        let size = fs::metadata(&wasm_path)?.len() as usize;

        if self.verbose {
            println!("✅ Python component: {} ({} bytes)", wasm_path.display(), size);
        }

        Ok(ComponentBuildResult {
            language: "python".to_string(),
            wasm_path,
            size_bytes: size,
        })
    }

    /// Build all components and optionally compose them into a single component
    pub fn build_and_compose(
        &self,
        parsed: &ParsedFile,
        filename: &str,
    ) -> Result<Option<crate::component_linker::LinkResult>, ComponentBuildError> {
        use crate::component_linker::ComponentLinker;

        // Build individual components
        let results = self.build_all(parsed, filename)?;

        if results.len() < 2 {
            if self.verbose {
                println!("⚠️  Need at least 2 components to compose (got {})", results.len());
            }
            return Ok(None);
        }

        // Create linker and compose
        let wit_path = self.work_dir.join("interfaces.wit");
        let mut linker = ComponentLinker::new(self.work_dir.clone());
        linker.verbose = self.verbose;

        match linker.link(&results, &wit_path) {
            Ok(link_result) => Ok(Some(link_result)),
            Err(crate::component_linker::LinkError::ToolNotFound(msg)) => {
                if self.verbose {
                    println!("⚠️  Skipping composition: {}", msg);
                }
                Ok(None)
            }
            Err(e) => Err(ComponentBuildError::ToolFailed {
                tool: "wasm-compose".to_string(),
                stderr: e.to_string(),
            }),
        }
    }

    /// Check if a tool is available on PATH
    fn check_tool(&self, tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Check what component tools are available
pub fn check_component_tools() -> Vec<(String, bool, String)> {
    let tools = [
        ("jco", "npm install -g @bytecodealliance/jco", "TypeScript/JavaScript → WASM Component"),
        ("componentize-py", "pip install componentize-py", "Python → WASM Component"),
        ("wasm-tools", "cargo install wasm-tools", "WASM manipulation utilities"),
        ("wasm-compose", "cargo install wasm-compose", "Component composition"),
    ];

    tools.iter().map(|(name, install, desc)| {
        let available = Command::new(name)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let status = if available {
            format!("✅ {}", desc)
        } else {
            format!("❌ Not found. Install: {}", install)
        };

        (name.to_string(), available, status)
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_component_tools() {
        let tools = check_component_tools();
        assert!(!tools.is_empty());

        for (name, _available, status) in &tools {
            println!("{}: {}", name, status);
        }
    }
}
