"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activateBlockDecorations = exports.LanguageBlockDecorator = void 0;
const vscode = require("vscode");
/**
 * Language block decorator - adds visual cues to help distinguish blocks:
 * 1. Subtle background tint per language
 * 2. Gutter markers (colored bars)
 */
class LanguageBlockDecorator {
    constructor() {
        this.decorationTypes = new Map();
        this.gutterTypes = new Map();
        // Language colors - subtle for background, visible for gutter
        this.languageColors = {
            'rust': { bg: 'rgba(255, 107, 53, 0.08)', gutter: '#FF6B35', icon: '🦀' },
            'rs': { bg: 'rgba(255, 107, 53, 0.08)', gutter: '#FF6B35', icon: '🦀' },
            'python': { bg: 'rgba(55, 118, 171, 0.08)', gutter: '#3776AB', icon: '🐍' },
            'py': { bg: 'rgba(55, 118, 171, 0.08)', gutter: '#3776AB', icon: '🐍' },
            'typescript': { bg: 'rgba(49, 120, 198, 0.08)', gutter: '#3178C6', icon: 'TS' },
            'ts': { bg: 'rgba(49, 120, 198, 0.08)', gutter: '#3178C6', icon: 'TS' },
            'javascript': { bg: 'rgba(247, 223, 30, 0.08)', gutter: '#F7DF1E', icon: 'JS' },
            'js': { bg: 'rgba(247, 223, 30, 0.08)', gutter: '#F7DF1E', icon: 'JS' },
            'interface': { bg: 'rgba(155, 89, 182, 0.08)', gutter: '#9B59B6', icon: '◆' },
            'main': { bg: 'rgba(46, 204, 113, 0.08)', gutter: '#2ECC71', icon: '▶' },
            'gpu': { bg: 'rgba(46, 204, 113, 0.08)', gutter: '#1ABC9C', icon: '⚡' },
            'wgsl': { bg: 'rgba(46, 204, 113, 0.08)', gutter: '#1ABC9C', icon: '⚡' },
            'html': { bg: 'rgba(227, 76, 38, 0.08)', gutter: '#E34C26', icon: '🌐' },
            'rscss': { bg: 'rgba(86, 61, 124, 0.08)', gutter: '#563D7C', icon: '🎨' },
            'css': { bg: 'rgba(86, 61, 124, 0.08)', gutter: '#563D7C', icon: '🎨' },
        };
        this.createDecorationTypes();
    }
    createDecorationTypes() {
        for (const [lang, colors] of Object.entries(this.languageColors)) {
            // Background tint decoration
            this.decorationTypes.set(lang, vscode.window.createTextEditorDecorationType({
                backgroundColor: colors.bg,
                isWholeLine: true,
            }));
            // Gutter decoration (colored bar)
            this.gutterTypes.set(lang, vscode.window.createTextEditorDecorationType({
                gutterIconPath: this.createGutterSvg(colors.gutter),
                gutterIconSize: 'contain',
            }));
        }
    }
    createGutterSvg(color) {
        // Create a simple colored bar SVG for the gutter
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
            <rect x="0" y="0" width="4" height="16" fill="${color}" rx="1"/>
        </svg>`;
        return vscode.Uri.parse(`data:image/svg+xml,${encodeURIComponent(svg)}`);
    }
    /**
     * Update decorations for the given editor
     */
    updateDecorations(editor) {
        if (editor.document.languageId !== 'polyglot') {
            return;
        }
        const text = editor.document.getText();
        const blocks = this.findLanguageBlocks(text);
        // Clear all existing decorations
        for (const decorationType of this.decorationTypes.values()) {
            editor.setDecorations(decorationType, []);
        }
        for (const gutterType of this.gutterTypes.values()) {
            editor.setDecorations(gutterType, []);
        }
        // Group ranges by language
        const bgRangesByLang = new Map();
        const gutterRangesByLang = new Map();
        for (const block of blocks) {
            const lang = this.normalizeLanguage(block.language);
            if (!this.decorationTypes.has(lang))
                continue;
            // Background ranges (all lines in block)
            if (!bgRangesByLang.has(lang)) {
                bgRangesByLang.set(lang, []);
            }
            bgRangesByLang.get(lang).push({ range: block.range });
            // Gutter ranges (all lines in block)
            if (!gutterRangesByLang.has(lang)) {
                gutterRangesByLang.set(lang, []);
            }
            // Add gutter decoration to each line
            for (let line = block.range.start.line; line <= block.range.end.line; line++) {
                const lineRange = new vscode.Range(line, 0, line, 0);
                gutterRangesByLang.get(lang).push({ range: lineRange });
            }
        }
        // Apply decorations
        for (const [lang, ranges] of bgRangesByLang) {
            const decorationType = this.decorationTypes.get(lang);
            if (decorationType) {
                editor.setDecorations(decorationType, ranges);
            }
        }
        for (const [lang, ranges] of gutterRangesByLang) {
            const gutterType = this.gutterTypes.get(lang);
            if (gutterType) {
                editor.setDecorations(gutterType, ranges);
            }
        }
    }
    normalizeLanguage(lang) {
        // Normalize language aliases
        const aliases = {
            'rs': 'rust',
            'py': 'python',
            'ts': 'typescript',
            'tsx': 'typescript',
            'js': 'javascript',
            'jsx': 'javascript',
        };
        return aliases[lang] || lang;
    }
    findLanguageBlocks(text) {
        const blocks = [];
        // Match #[lang] { ... } style blocks
        const blockRegex = /^[ \t]*(#\[(interface|types|rust|rs|python|py|typescript|ts|javascript|js|jsx|tsx|main|gpu|wgsl|html|rscss|css|test|doc)(?::[^\]]+)?\])[ \t]*\{?[ \t]*$/gm;
        let match;
        while ((match = blockRegex.exec(text)) !== null) {
            const language = match[2];
            const startLine = text.substring(0, match.index).split('\n').length - 1;
            // Find the end of the block
            let endLine = startLine;
            const lines = text.split('\n');
            if (match[0].includes('{')) {
                // Brace-delimited block - find matching }
                let braceDepth = 1;
                for (let i = startLine + 1; i < lines.length && braceDepth > 0; i++) {
                    const line = lines[i];
                    // Simple brace counting (doesn't handle strings/comments, but good enough for decoration)
                    for (const char of line) {
                        if (char === '{')
                            braceDepth++;
                        else if (char === '}')
                            braceDepth--;
                    }
                    endLine = i;
                    if (braceDepth === 0)
                        break;
                }
            }
            else {
                // Indentation-based block - find next block directive or end
                for (let i = startLine + 1; i < lines.length; i++) {
                    const line = lines[i];
                    if (/^[ \t]*#\[(interface|types|rust|rs|python|py|typescript|ts|javascript|js|jsx|tsx|main|gpu|wgsl|html|rscss|css|test|doc)/.test(line)) {
                        break;
                    }
                    endLine = i;
                }
            }
            const document = vscode.window.activeTextEditor?.document;
            if (document) {
                blocks.push({
                    language,
                    range: new vscode.Range(startLine, 0, endLine, lines[endLine]?.length || 0)
                });
            }
        }
        return blocks;
    }
    dispose() {
        for (const decorationType of this.decorationTypes.values()) {
            decorationType.dispose();
        }
        for (const gutterType of this.gutterTypes.values()) {
            gutterType.dispose();
        }
    }
}
exports.LanguageBlockDecorator = LanguageBlockDecorator;
/**
 * Activates language block decorations
 */
function activateBlockDecorations(context) {
    const decorator = new LanguageBlockDecorator();
    // Update decorations when editor changes
    let activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
        decorator.updateDecorations(activeEditor);
    }
    context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(editor => {
        activeEditor = editor;
        if (editor) {
            decorator.updateDecorations(editor);
        }
    }), vscode.workspace.onDidChangeTextDocument(event => {
        if (activeEditor && event.document === activeEditor.document) {
            // Debounce updates
            setTimeout(() => {
                if (activeEditor) {
                    decorator.updateDecorations(activeEditor);
                }
            }, 100);
        }
    }), { dispose: () => decorator.dispose() });
    return decorator;
}
exports.activateBlockDecorations = activateBlockDecorations;
//# sourceMappingURL=languageBlockDecorator.js.map