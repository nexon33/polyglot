use std::collections::HashMap;
use tower_lsp::lsp_types::{Range, Url};

/// Unique identifier for polyglot symbols
pub type SymbolId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Type,
}

/// Location of a symbol reference
#[derive(Debug, Clone)]
pub struct SymbolLocation {
    pub uri: Url,
    pub range: Range,
    pub lang: String,  // "interface", "rust", "python", "main"
}

/// All information about a polyglot symbol
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub id: SymbolId,
    pub name: String,
    pub kind: SymbolKind,
    pub declaration: Option<SymbolLocation>,          // Interface declaration
    pub implementations: Vec<SymbolLocation>,          // impl in rust/python
    pub call_sites: Vec<SymbolLocation>,               // Call locations
}

impl SymbolInfo {
    pub fn new(id: SymbolId, name: String, kind: SymbolKind) -> Self {
        Self {
            id,
            name,
            kind,
            declaration: None,
            implementations: Vec::new(),
            call_sites: Vec::new(),
        }
    }
    
    /// Get all reference locations (calls + implementations + declaration)
    pub fn all_references(&self, include_declaration: bool) -> Vec<&SymbolLocation> {
        let mut refs: Vec<&SymbolLocation> = self.call_sites.iter().collect();
        refs.extend(self.implementations.iter());
        if include_declaration {
            if let Some(decl) = &self.declaration {
                refs.push(decl);
            }
        }
        refs
    }
}

/// Unified symbol table for cross-language symbol linking
#[derive(Debug, Default)]
pub struct SymbolTable {
    symbols: HashMap<SymbolId, SymbolInfo>,
    name_to_id: HashMap<String, SymbolId>,
    next_id: SymbolId,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.name_to_id.clear();
        self.next_id = 0;
    }
    
    /// Clear only symbols for a specific file URI
    pub fn clear_for_file(&mut self, uri: &Url) {
        // Remove call sites and implementations for this file
        for symbol in self.symbols.values_mut() {
            symbol.call_sites.retain(|loc| &loc.uri != uri);
            symbol.implementations.retain(|loc| &loc.uri != uri);
            if let Some(decl) = &symbol.declaration {
                if &decl.uri == uri {
                    symbol.declaration = None;
                }
            }
        }
    }
    
    /// Declare a symbol (from interface block)
    pub fn declare(&mut self, name: &str, kind: SymbolKind, location: SymbolLocation) -> SymbolId {
        if let Some(&id) = self.name_to_id.get(name) {
            // Symbol already exists, update declaration
            if let Some(symbol) = self.symbols.get_mut(&id) {
                symbol.declaration = Some(location);
            }
            id
        } else {
            // Create new symbol
            let id = self.next_id;
            self.next_id += 1;
            
            let mut info = SymbolInfo::new(id, name.to_string(), kind);
            info.declaration = Some(location);
            
            self.symbols.insert(id, info);
            self.name_to_id.insert(name.to_string(), id);
            id
        }
    }
    
    /// Add an implementation (from rust/python block)
    pub fn add_implementation(&mut self, name: &str, location: SymbolLocation) -> SymbolId {
        let id = self.get_or_create(name, SymbolKind::Function);
        if let Some(symbol) = self.symbols.get_mut(&id) {
            symbol.implementations.push(location);
        }
        id
    }
    
    /// Add a call site
    pub fn add_call_site(&mut self, name: &str, location: SymbolLocation) -> SymbolId {
        let id = self.get_or_create(name, SymbolKind::Function);
        if let Some(symbol) = self.symbols.get_mut(&id) {
            symbol.call_sites.push(location);
        }
        id
    }
    
    /// Get or create a symbol by name
    fn get_or_create(&mut self, name: &str, kind: SymbolKind) -> SymbolId {
        if let Some(&id) = self.name_to_id.get(name) {
            id
        } else {
            let id = self.next_id;
            self.next_id += 1;
            
            let info = SymbolInfo::new(id, name.to_string(), kind);
            self.symbols.insert(id, info);
            self.name_to_id.insert(name.to_string(), id);
            id
        }
    }
    
    /// Look up a symbol by name
    pub fn get_by_name(&self, name: &str) -> Option<&SymbolInfo> {
        self.name_to_id.get(name).and_then(|id| self.symbols.get(id))
    }
    
    /// Get all symbols
    pub fn all_symbols(&self) -> impl Iterator<Item = &SymbolInfo> {
        self.symbols.values()
    }
    
    /// Debug: print all symbols
    pub fn debug_print(&self) {
        eprintln!("SymbolTable: {} symbols", self.symbols.len());
        for symbol in self.symbols.values() {
            eprintln!("  Symbol {}: {} ({:?})", symbol.id, symbol.name, symbol.kind);
            if let Some(decl) = &symbol.declaration {
                eprintln!("    Declaration: {} line {}", decl.lang, decl.range.start.line);
            }
            for imp in &symbol.implementations {
                eprintln!("    Implementation: {} line {}", imp.lang, imp.range.start.line);
            }
            for call in &symbol.call_sites {
                eprintln!("    CallSite: {} line {}", call.lang, call.range.start.line);
            }
        }
    }
}
