"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolyTreeProvider = void 0;
const vscode = require("vscode");
/**
 * Provides a virtual file tree in the Explorer sidebar for .poly files.
 * Each block with a path (e.g., #[rust:src/main.rs]) appears as a file.
 */
class PolyTreeProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this._files = [];
    }
    refresh(polyUri) {
        if (polyUri) {
            this._polyUri = polyUri;
            this.parsePolyFile(polyUri);
        }
        this._onDidChangeTreeData.fire(undefined);
    }
    async parsePolyFile(uri) {
        try {
            const doc = await vscode.workspace.openTextDocument(uri);
            const text = doc.getText();
            this._files = this.extractVirtualFiles(text, uri);
        }
        catch (e) {
            this._files = [];
        }
    }
    extractVirtualFiles(text, polyUri) {
        const files = [];
        // Match #[lang:path] or #[lang] blocks
        const blockRegex = /^#\[([a-zA-Z]+)(?::([^\]]+))?\]/gm;
        let match;
        let index = 0;
        while ((match = blockRegex.exec(text)) !== null) {
            const lang = match[1];
            const path = match[2] || this.defaultPath(lang, index);
            files.push({
                name: path.split('/').pop() || path,
                path: path,
                language: lang,
                blockIndex: index,
                polyUri
            });
            index++;
        }
        return files;
    }
    defaultPath(lang, index) {
        const extensions = {
            rust: '.rs',
            rs: '.rs',
            js: '.js',
            jsx: '.jsx',
            ts: '.ts',
            tsx: '.tsx',
            css: '.css',
            html: '.html',
            python: '.py',
            py: '.py',
            wgsl: '.wgsl',
            gpu: '.wgsl',
            doc: '.md',
            test: '.test.rs'
        };
        const ext = extensions[lang] || '.txt';
        return `block_${index}${ext}`;
    }
    getTreeItem(element) {
        const item = new vscode.TreeItem(element.name, vscode.TreeItemCollapsibleState.None);
        item.tooltip = element.path;
        item.description = element.language;
        // Set icon based on language
        item.iconPath = new vscode.ThemeIcon(this.getIcon(element.language));
        // Command to open virtual file
        item.command = {
            command: 'polyglot.openVirtualFile',
            title: 'Open Virtual File',
            arguments: [element]
        };
        return item;
    }
    getIcon(lang) {
        const icons = {
            rust: 'symbol-misc',
            rs: 'symbol-misc',
            js: 'symbol-method',
            jsx: 'symbol-method',
            ts: 'symbol-method',
            tsx: 'symbol-method',
            css: 'symbol-color',
            html: 'code',
            python: 'symbol-method',
            py: 'symbol-method',
            wgsl: 'symbol-operator',
            gpu: 'symbol-operator',
            doc: 'book',
            test: 'beaker'
        };
        return icons[lang] || 'file';
    }
    getChildren(element) {
        if (element) {
            return []; // No nested children
        }
        return this._files;
    }
    getParent(element) {
        return null;
    }
}
exports.PolyTreeProvider = PolyTreeProvider;
//# sourceMappingURL=polyTreeProvider.js.map