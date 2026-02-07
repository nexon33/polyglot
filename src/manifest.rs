//! Unified package manifest (poly.toml) parser
//!
//! Supports dependencies for all languages:
//! - [rust] → Cargo.toml dependencies
//! - [npm] → package.json dependencies
//! - [pip] → requirements.txt / pyproject.toml

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// The full poly.toml manifest
#[derive(Debug, Deserialize, Default)]
pub struct Manifest {
    /// Package metadata
    #[serde(default)]
    pub package: Package,
    
    /// Rust/Cargo dependencies
    #[serde(default)]
    pub rust: HashMap<String, toml::Value>,
    
    /// NPM/JS/TS dependencies
    #[serde(default)]
    pub npm: HashMap<String, toml::Value>,
    
    /// Python/pip dependencies
    #[serde(default)]
    pub pip: HashMap<String, toml::Value>,
    
    /// Build configuration
    #[serde(default)]
    pub build: BuildConfig,
}

/// Package metadata
#[derive(Debug, Deserialize, Default)]
pub struct Package {
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub authors: Option<Vec<String>>,
    pub license: Option<String>,
}

/// Build configuration
#[derive(Debug, Deserialize, Default)]
pub struct BuildConfig {
    /// Default build target
    pub target: Option<String>,
    /// Enable release mode by default
    pub release: Option<bool>,
}

impl Manifest {
    /// Load manifest from poly.toml in the given directory
    pub fn load(dir: &Path) -> Option<Self> {
        let manifest_path = dir.join("poly.toml");
        if !manifest_path.exists() {
            return None;
        }
        
        let content = fs::read_to_string(&manifest_path).ok()?;
        let manifest: Manifest = toml::from_str(&content).ok()?;
        Some(manifest)
    }
    
    /// Load manifest from the same directory as a .poly file
    pub fn load_for_file(poly_file: &Path) -> Option<Self> {
        let dir = poly_file.parent()?;
        Self::load(dir)
    }
    
    /// Convert rust dependencies to Cargo.toml [dependencies] format
    pub fn rust_dependencies_toml(&self) -> String {
        if self.rust.is_empty() {
            return String::new();
        }
        
        let mut lines = Vec::new();
        for (name, value) in &self.rust {
            let dep_line = match value {
                toml::Value::String(version) => {
                    format!("{} = \"{}\"", name, version)
                }
                toml::Value::Table(table) => {
                    // Convert table to inline TOML
                    let parts: Vec<String> = table.iter().map(|(k, v)| {
                        match v {
                            toml::Value::String(s) => format!("{} = \"{}\"", k, s),
                            toml::Value::Array(arr) => {
                                let items: Vec<String> = arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| format!("\"{}\"", s)))
                                    .collect();
                                format!("{} = [{}]", k, items.join(", "))
                            }
                            toml::Value::Boolean(b) => format!("{} = {}", k, b),
                            _ => format!("{} = {:?}", k, v),
                        }
                    }).collect();
                    format!("{} = {{ {} }}", name, parts.join(", "))
                }
                _ => format!("{} = {:?}", name, value),
            };
            lines.push(dep_line);
        }
        
        lines.join("\n")
    }
    
    /// Convert npm dependencies to package.json dependencies object
    pub fn npm_dependencies_json(&self) -> String {
        if self.npm.is_empty() {
            return "{}".to_string();
        }
        
        let deps: HashMap<&str, &str> = self.npm.iter()
            .filter_map(|(name, value)| {
                value.as_str().map(|v| (name.as_str(), v))
            })
            .collect();
        
        serde_json::to_string_pretty(&deps).unwrap_or_else(|_| "{}".to_string())
    }
    
    /// Convert pip dependencies to requirements.txt format
    pub fn pip_requirements(&self) -> String {
        if self.pip.is_empty() {
            return String::new();
        }
        
        let mut lines = Vec::new();
        for (name, value) in &self.pip {
            let req = match value {
                toml::Value::String(version) => {
                    if version.starts_with(">=") || version.starts_with("==") || 
                       version.starts_with("<=") || version.starts_with("~=") ||
                       version.starts_with(">") || version.starts_with("<") {
                        format!("{}{}", name, version)
                    } else {
                        format!("{}=={}", name, version)
                    }
                }
                toml::Value::Table(table) => {
                    // Support version and extras
                    let version = table.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*");
                    let extras = table.get("extras")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            let items: Vec<&str> = arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect();
                            format!("[{}]", items.join(","))
                        })
                        .unwrap_or_default();
                    
                    if version.starts_with(">=") || version.starts_with("==") {
                        format!("{}{}{}", name, extras, version)
                    } else {
                        format!("{}{}=={}", name, extras, version)
                    }
                }
                _ => name.clone(),
            };
            lines.push(req);
        }
        
        lines.join("\n")
    }
    
    /// Check if manifest has any rust dependencies
    pub fn has_rust_deps(&self) -> bool {
        !self.rust.is_empty()
    }
    
    /// Check if manifest has any npm dependencies
    pub fn has_npm_deps(&self) -> bool {
        !self.npm.is_empty()
    }
    
    /// Check if manifest has any pip dependencies
    pub fn has_pip_deps(&self) -> bool {
        !self.pip.is_empty()
    }
}

// Need serde_json for npm output
use serde::Serialize;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_manifest() {
        let toml_str = r#"
[package]
name = "myapp"
version = "0.1.0"

[rust]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"

[npm]
react = "^18.0.0"
lodash = "^4.17.0"

[pip]
numpy = ">=1.20"
requests = { version = ">=2.25", extras = ["security"] }
"#;
        
        let manifest: Manifest = toml::from_str(toml_str).unwrap();
        
        assert_eq!(manifest.package.name, Some("myapp".to_string()));
        assert_eq!(manifest.rust.len(), 3);
        assert_eq!(manifest.npm.len(), 2);
        assert_eq!(manifest.pip.len(), 2);
        
        let rust_deps = manifest.rust_dependencies_toml();
        assert!(rust_deps.contains("serde"));
        assert!(rust_deps.contains("tokio"));
        
        let pip_reqs = manifest.pip_requirements();
        assert!(pip_reqs.contains("numpy"));
        assert!(pip_reqs.contains("requests"));
    }
}
