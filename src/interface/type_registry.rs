// Type Registry for cross-language type mappings
//
// Maps interface types to their concrete implementations in each language.
// This is the single source of truth for how types cross language boundaries.

use std::collections::HashMap;

/// Represents a type mapping across languages
#[derive(Debug, Clone)]
pub struct TypeMapping {
    /// Name in the interface (e.g., "Tensor")
    pub interface_name: String,
    /// Rust implementation path (e.g., "gridmesh::tensor::Tensor<f32>")
    pub rust_impl: Option<String>,
    /// Python implementation path (e.g., "gridmesh.Tensor")
    pub python_impl: Option<String>,
    /// Whether this type supports zero-copy sharing
    pub zero_copy: bool,
}

impl TypeMapping {
    pub fn new(name: &str) -> Self {
        Self {
            interface_name: name.to_string(),
            rust_impl: None,
            python_impl: None,
            zero_copy: false,
        }
    }
    
    pub fn with_rust(mut self, impl_path: &str) -> Self {
        self.rust_impl = Some(impl_path.to_string());
        self
    }
    
    pub fn with_python(mut self, impl_path: &str) -> Self {
        self.python_impl = Some(impl_path.to_string());
        self
    }
    
    pub fn with_zero_copy(mut self) -> Self {
        self.zero_copy = true;
        self
    }
}

/// Registry of all type mappings
#[derive(Debug, Default)]
pub struct TypeRegistry {
    types: HashMap<String, TypeMapping>,
}

impl TypeRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Register a type mapping
    pub fn register(&mut self, mapping: TypeMapping) {
        self.types.insert(mapping.interface_name.clone(), mapping);
    }
    
    /// Get a type mapping by interface name
    pub fn get(&self, name: &str) -> Option<&TypeMapping> {
        self.types.get(name)
    }
    
    /// Get the Rust implementation for an interface type
    pub fn rust_type(&self, interface_name: &str) -> Option<&str> {
        self.types.get(interface_name)
            .and_then(|m| m.rust_impl.as_deref())
    }
    
    /// Get the Python implementation for an interface type
    pub fn python_type(&self, interface_name: &str) -> Option<&str> {
        self.types.get(interface_name)
            .and_then(|m| m.python_impl.as_deref())
    }
    
    /// Check if type supports zero-copy
    pub fn is_zero_copy(&self, interface_name: &str) -> bool {
        self.types.get(interface_name)
            .map(|m| m.zero_copy)
            .unwrap_or(false)
    }
    
    /// Get all registered type names
    pub fn all_types(&self) -> impl Iterator<Item = &str> {
        self.types.keys().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_type_registry() {
        let mut registry = TypeRegistry::new();
        
        registry.register(
            TypeMapping::new("Tensor")
                .with_rust("gridmesh::tensor::Tensor<f32>")
                .with_python("gridmesh.Tensor")
                .with_zero_copy()
        );
        
        assert_eq!(registry.rust_type("Tensor"), Some("gridmesh::tensor::Tensor<f32>"));
        assert_eq!(registry.python_type("Tensor"), Some("gridmesh.Tensor"));
        assert!(registry.is_zero_copy("Tensor"));
    }
}
