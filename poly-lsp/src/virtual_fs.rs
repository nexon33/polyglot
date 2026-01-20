use dashmap::DashMap;
use polyglot::parser::parse_poly;
use tower_lsp::lsp_types::Url;

#[derive(Debug, Clone)]
pub struct VirtualFile {
    pub uri: Url,
    pub lang_tag: String,
    pub content: String,
    pub version: i32,
    pub start_line: usize, // Real line index where block starts (header)
    pub line_count: usize, // Number of lines in the virtual file
}

#[derive(Debug, Default)]
pub struct VirtualFileManager {
    // Map of Real URI -> List of Virtual Files
    pub files: DashMap<Url, Vec<VirtualFile>>,
}

impl VirtualFileManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_file(&self, uri: Url, content: &str, version: i32) -> Vec<VirtualFile> {
        let mut virtual_files = Vec::new();

        // Use the shared parser from the main crate
        if let Ok(parsed) = parse_poly(content) {
            for (_idx, block) in parsed.blocks.iter().enumerate() {
                // Determine URI scheme for virtual file?
                // e.g. poly://path/to/file.poly#python:0

                let line_count = block.code.lines().count();
                // Assumption: code starts 1 line after the header
                // We trimmed the code in parser, which is risky for LSP, but we flow with it for now.
                // Ideally parser shouldn't trim for LSP, or we should track offsets better.

                virtual_files.push(VirtualFile {
                    uri: uri.clone(),
                    lang_tag: block.lang_tag.clone(),
                    content: block.code.clone(),
                    version,
                    start_line: block.start_line,
                    line_count,
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
        // block starts at start_line (the header). code starts at start_line + 1.
        let code_start = self.start_line + 1;
        if real_line >= code_start && real_line < code_start + self.line_count {
            Some(real_line - code_start)
        } else {
            None
        }
    }

    pub fn map_to_real(&self, virtual_line: usize) -> usize {
        self.start_line + 1 + virtual_line
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
}

