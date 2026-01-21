// Source map generation for Polyglot compiler
// Maps generated code lines back to original .poly file lines

use std::collections::HashMap;

/// A single mapping entry
#[derive(Debug, Clone)]
pub struct SourceMapping {
    /// Line in the generated file (1-indexed)
    pub generated_line: usize,
    /// Line in the original .poly file (1-indexed)
    pub original_line: usize,
    /// Column in generated file (0-indexed)
    pub generated_column: usize,
    /// Column in original file (0-indexed)  
    pub original_column: usize,
    /// Source file name
    pub source: String,
    /// Language block (rust, js, etc)
    pub block_type: String,
}

/// Source map for a compiled Polyglot file
#[derive(Debug, Default)]
pub struct SourceMap {
    /// Version (always 3)
    pub version: u8,
    /// Original source file
    pub file: String,
    /// List of source files
    pub sources: Vec<String>,
    /// Source contents (optional inline)
    pub sources_content: Vec<Option<String>>,
    /// Mappings in VLQ format
    pub mappings: Vec<SourceMapping>,
    /// Names referenced in mappings
    pub names: Vec<String>,
}

impl SourceMap {
    pub fn new(file: &str) -> Self {
        Self {
            version: 3,
            file: file.to_string(),
            sources: vec![file.to_string()],
            sources_content: vec![],
            mappings: vec![],
            names: vec![],
        }
    }

    /// Add a mapping from generated line to original line
    pub fn add_mapping(&mut self, generated_line: usize, original_line: usize, block_type: &str) {
        self.mappings.push(SourceMapping {
            generated_line,
            original_line,
            generated_column: 0,
            original_column: 0,
            source: self.file.clone(),
            block_type: block_type.to_string(),
        });
    }

    /// Add a range of mappings (for entire blocks)
    pub fn add_block_mapping(
        &mut self,
        generated_start: usize,
        original_start: usize,
        line_count: usize,
        block_type: &str,
    ) {
        for i in 0..line_count {
            self.add_mapping(generated_start + i, original_start + i, block_type);
        }
    }

    /// Lookup original line from generated line
    pub fn lookup(&self, generated_line: usize) -> Option<&SourceMapping> {
        self.mappings
            .iter()
            .find(|m| m.generated_line == generated_line)
    }

    /// Generate a simple inline JSON source map (for debugging)
    /// This is a simplified format, not standard VLQ for readability
    pub fn to_inline_json(&self) -> String {
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"version\": {},\n", self.version));
        json.push_str(&format!("  \"file\": \"{}\",\n", self.file));
        json.push_str(&format!(
            "  \"sources\": [\"{}\"],\n",
            self.sources.join("\", \"")
        ));

        // Simple line-to-line mappings (not VLQ encoded)
        json.push_str("  \"lineMap\": {\n");
        let map_entries: Vec<String> = self
            .mappings
            .iter()
            .map(|m| {
                format!(
                    "    \"{}\": {{ \"line\": {}, \"block\": \"{}\" }}",
                    m.generated_line, m.original_line, m.block_type
                )
            })
            .collect();
        json.push_str(&map_entries.join(",\n"));
        json.push_str("\n  }\n");

        json.push_str("}");
        json
    }

    /// Generate JavaScript source map lookup function
    pub fn to_js_lookup_function(&self) -> String {
        let mut js = String::from("window.__polySourceMap = {\n");

        // Build line map
        let entries: Vec<String> = self
            .mappings
            .iter()
            .map(|m| {
                format!(
                    "  {}: {{ o: {}, b: '{}' }}",
                    m.generated_line, m.original_line, m.block_type
                )
            })
            .collect();
        js.push_str(&entries.join(",\n"));
        js.push_str("\n};\n\n");

        // Lookup function
        js.push_str(
            r#"
window.__polyLookup = function(genLine) {
  const entry = window.__polySourceMap[genLine];
  if (entry) {
    return { line: entry.o, block: entry.b, file: '"#,
        );
        js.push_str(&self.file);
        js.push_str(
            r#"' };
  }
  return null;
};

// Enhanced error reporting
window.onerror = function(msg, url, line, col, error) {
  const mapping = window.__polyLookup(line);
  if (mapping) {
    console.error(
      `%c⚠️ Error in ${mapping.file}:${mapping.line} [${mapping.block}]%c\n${msg}`,
      'color: #ff6b6b; font-weight: bold;',
      'color: inherit;'
    );
    return true; // Prevent default error handling
  }
  return false;
};
"#,
        );

        js
    }
}

/// Track source locations during code generation
#[derive(Debug, Default)]
pub struct SourceTracker {
    /// Current line in generated output
    pub current_line: usize,
    /// Source map being built
    pub source_map: SourceMap,
    /// Block offsets: maps block index to (start_line_in_poly, line_count)
    pub block_offsets: HashMap<usize, (usize, usize)>,
}

impl SourceTracker {
    pub fn new(source_file: &str) -> Self {
        Self {
            current_line: 1,
            source_map: SourceMap::new(source_file),
            block_offsets: HashMap::new(),
        }
    }

    /// Track a block of code being added to output
    pub fn track_block(&mut self, original_start_line: usize, code: &str, block_type: &str) {
        let line_count = code.lines().count();

        self.source_map.add_block_mapping(
            self.current_line,
            original_start_line,
            line_count,
            block_type,
        );

        self.current_line += line_count;
    }

    /// Advance current line by N
    pub fn advance(&mut self, lines: usize) {
        self.current_line += lines;
    }

    /// Get the source map
    pub fn finalize(self) -> SourceMap {
        self.source_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_map_basic() {
        let mut sm = SourceMap::new("demo.poly");
        sm.add_mapping(1, 10, "rust");
        sm.add_mapping(2, 11, "rust");
        sm.add_mapping(3, 12, "rust");

        let lookup = sm.lookup(2);
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap().original_line, 11);
    }

    #[test]
    fn test_source_tracker() {
        let mut tracker = SourceTracker::new("test.poly");

        // Simulate adding a 5-line Rust block starting at line 10
        tracker.track_block(10, "line1\nline2\nline3\nline4\nline5", "rust");

        let sm = tracker.finalize();
        assert_eq!(sm.mappings.len(), 5);
        assert_eq!(sm.lookup(3).unwrap().original_line, 12);
    }
}
