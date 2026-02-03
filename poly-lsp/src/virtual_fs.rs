use dashmap::DashMap;
use polyglot::parser::parse_poly;
use tower_lsp::lsp_types::Url;
use regex::Regex;

/// Detected syntax style within a block
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxStyle {
    Rust,
    Python,
    JavaScript,
    Mixed,  // Contains syntax from multiple languages
}

/// A region within a virtual file with detected syntax style
#[derive(Debug, Clone)]
pub struct SyntaxRegion {
    pub start_line: usize,  // Line within virtual file (0-indexed)
    pub end_line: usize,    // Inclusive end line
    pub style: SyntaxStyle,
}

#[derive(Debug, Clone)]
pub struct VirtualFile {
    pub uri: Url,
    pub lang_tag: String,
    pub content: String,
    pub version: i32,
    pub start_line: usize, // Real line index where block starts (header)
    pub code_start_line: usize, // Real line where actual code starts (after header + blank lines)
    pub line_count: usize, // Number of lines in the virtual file
    pub syntax_regions: Vec<SyntaxRegion>, // Detected mixed syntax regions
}

#[derive(Debug, Default)]
pub struct VirtualFileManager {
    // Map of Real URI -> List of Virtual Files
    pub files: DashMap<Url, Vec<VirtualFile>>,
    // Map of Real URI -> Source content (for hover support)
    sources: DashMap<Url, String>,
}

impl VirtualFileManager {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Get the source content for a file
    pub fn get_source(&self, uri: &Url) -> Option<String> {
        self.sources.get(uri).map(|v| v.clone())
    }

    pub fn update_file(&self, uri: Url, content: &str, version: i32) -> Vec<VirtualFile> {
        let mut virtual_files = Vec::new();
        
        // Store the source for hover support
        self.sources.insert(uri.clone(), content.to_string());

        // Use the shared parser from the main crate
        if let Ok(parsed) = parse_poly(content) {
            for (_idx, block) in parsed.blocks.iter().enumerate() {
                // Determine URI scheme for virtual file?
                // e.g. poly://path/to/file.poly#python:0

                let line_count = block.code.lines().count();
                // Use code_start_line from parser which accounts for leading blank lines after trim

                let syntax_regions = detect_syntax_regions(&block.code);
                virtual_files.push(VirtualFile {
                    uri: uri.clone(),
                    lang_tag: block.lang_tag.clone(),
                    content: block.code.clone(),
                    version,
                    start_line: block.start_line,
                    code_start_line: block.code_start_line,
                    line_count,
                    syntax_regions,
                });
            }
        }

        self.files.insert(uri, virtual_files.clone());
        virtual_files
    }

    pub fn get_files(&self, uri: &Url) -> Option<Vec<VirtualFile>> {
        self.files.get(uri).map(|v| v.clone())
    }
}

impl VirtualFile {
    /// Returns the normalized file extension for this virtual file
    /// Maps: "rs"|"rust"|"main"|"interface" -> "rs", "py"|"python" -> "py"
    pub fn normalized_ext(&self) -> &'static str {
        match self.lang_tag.as_str() {
            "rs" | "rust" | "main" | "interface" => "rs",
            "py" | "python" => "py",
            _ => "txt",
        }
    }
    
    /// Returns the LSP languageId for this virtual file
    pub fn language_id(&self) -> &'static str {
        match self.lang_tag.as_str() {
            "rs" | "rust" | "main" | "interface" => "rust",
            "py" | "python" => "python",
            _ => "plaintext",
        }
    }

    pub fn map_to_virtual(&self, real_line: usize) -> Option<usize> {
        // Use code_start_line which accounts for header AND any blank lines
        if real_line >= self.code_start_line && real_line < self.code_start_line + self.line_count {
            Some(real_line - self.code_start_line)
        } else {
            None
        }
    }

    pub fn map_to_real(&self, virtual_line: usize) -> usize {
        // Use code_start_line which accounts for header AND any blank lines
        self.code_start_line + virtual_line
    }

    pub fn virtual_uri(&self) -> String {
        let ext = self.normalized_ext();
        let uri_str = self.uri.to_string();
        if uri_str.ends_with(".poly") {
            uri_str.replace(".poly", &format!(".virtual.{}", ext))
        } else {
            format!("{}.virtual.{}", uri_str, ext)
        }
    }

    /// Get the detected syntax style for a specific line within this virtual file
    pub fn get_syntax_style(&self, virtual_line: usize) -> SyntaxStyle {
        for region in &self.syntax_regions {
            if virtual_line >= region.start_line && virtual_line <= region.end_line {
                return region.style;
            }
        }
        // Default based on lang_tag
        match self.lang_tag.as_str() {
            "rs" | "rust" | "main" => SyntaxStyle::Rust,
            "py" | "python" => SyntaxStyle::Python,
            "js" | "javascript" => SyntaxStyle::JavaScript,
            _ => SyntaxStyle::Mixed,
        }
    }
}

/// Detect syntax style regions within a code block
///
/// This analyzes the code to identify areas using Python-style, Rust-style,
/// JavaScript-style, or mixed syntax.
fn detect_syntax_regions(code: &str) -> Vec<SyntaxRegion> {
    let mut regions = Vec::new();
    let lines: Vec<&str> = code.lines().collect();

    if lines.is_empty() {
        return regions;
    }

    // Patterns for detecting syntax styles
    let python_patterns = [
        r"^\s*def\s+\w+\s*\(",           // def function()
        r":\s*$",                         // line ending with colon
        r"\bself\.",                      // self.something
        r"^\s*class\s+\w+.*:",           // class Foo:
        r"\b(and|or|not)\b",             // Python boolean operators
        r"\bNone\b",                      // None
        r"\bTrue\b|\bFalse\b",           // Python booleans
        r"\*\*\w+",                       // **kwargs
    ];

    let rust_patterns = [
        r"^\s*fn\s+\w+",                 // fn function
        r"^\s*let\s+(mut\s+)?\w+",       // let/let mut
        r"^\s*impl\s+",                  // impl block
        r"^\s*struct\s+\w+",             // struct
        r"^\s*enum\s+\w+",               // enum
        r"->\s*\w+",                      // return type
        r"::\w+",                         // path separator
        r"&\w+|&mut\s+\w+",              // references
    ];

    let js_patterns = [
        r"=>\s*\{?",                      // arrow function
        r"^\s*const\s+\w+",              // const declaration
        r"^\s*var\s+\w+",                // var declaration
        r"\bthis\.",                      // this.something
        r"^\s*function\s+\w+",           // function keyword
        r"===|!==",                       // strict equality
    ];

    // Compile patterns
    let py_re: Vec<Regex> = python_patterns.iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();
    let rs_re: Vec<Regex> = rust_patterns.iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();
    let js_re: Vec<Regex> = js_patterns.iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    let mut current_style = SyntaxStyle::Mixed;
    let mut region_start = 0;

    for (i, line) in lines.iter().enumerate() {
        let py_score = py_re.iter().filter(|re| re.is_match(line)).count();
        let rs_score = rs_re.iter().filter(|re| re.is_match(line)).count();
        let js_score = js_re.iter().filter(|re| re.is_match(line)).count();

        let line_style = if py_score > 0 && rs_score > 0 {
            SyntaxStyle::Mixed
        } else if py_score > rs_score && py_score > js_score {
            SyntaxStyle::Python
        } else if rs_score > py_score && rs_score > js_score {
            SyntaxStyle::Rust
        } else if js_score > 0 {
            SyntaxStyle::JavaScript
        } else {
            current_style // Keep current style for neutral lines
        };

        // If style changes, close current region and start new one
        if line_style != current_style && i > 0 {
            if region_start < i {
                regions.push(SyntaxRegion {
                    start_line: region_start,
                    end_line: i - 1,
                    style: current_style,
                });
            }
            region_start = i;
            current_style = line_style;
        } else if i == 0 {
            current_style = line_style;
        }
    }

    // Close final region
    if region_start < lines.len() {
        regions.push(SyntaxRegion {
            start_line: region_start,
            end_line: lines.len() - 1,
            style: current_style,
        });
    }

    regions
}

