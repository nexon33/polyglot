"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolyglotFileSystemProvider = void 0;
const vscode = require("vscode");
class PolyglotFileSystemProvider {
    constructor() {
        // Event emitter for file changes
        this._onDidChangeFile = new vscode.EventEmitter();
        this.onDidChangeFile = this._onDidChangeFile.event;
    }
    watch(uri, options) {
        // We watch the real file instead, but needed for interface compliance
        return new vscode.Disposable(() => { });
    }
    stat(uri) {
        // For now, return a generic file stat
        // In a real implementation, we'd want to check existence
        return {
            type: vscode.FileType.File,
            ctime: Date.now(),
            mtime: Date.now(),
            size: 0
        };
    }
    readDirectory(uri) {
        // We don't support directory reading for now
        return [];
    }
    createDirectory(uri) {
        throw vscode.FileSystemError.NoPermissions();
    }
    async readFile(uri) {
        const { realUri, blockId } = this.parseVirtualUri(uri);
        const doc = await vscode.workspace.openTextDocument(realUri);
        const text = doc.getText();
        const block = this.findBlock(text, blockId);
        if (!block) {
            throw vscode.FileSystemError.FileNotFound();
        }
        return Buffer.from(block.content);
    }
    async writeFile(uri, content, options) {
        const { realUri, blockId } = this.parseVirtualUri(uri);
        const newContent = content.toString();
        const doc = await vscode.workspace.openTextDocument(realUri);
        const text = doc.getText();
        const block = this.findBlock(text, blockId);
        if (!block) {
            throw vscode.FileSystemError.FileNotFound();
        }
        // Apply edit to the real document
        const edit = new vscode.WorkspaceEdit();
        const startPos = doc.positionAt(block.startIndex);
        const endPos = doc.positionAt(block.endIndex);
        const range = new vscode.Range(startPos, endPos);
        edit.replace(realUri, range, newContent);
        await vscode.workspace.applyEdit(edit);
        // Save the real document to persist changes
        await doc.save();
        // Notify change
        this._onDidChangeFile.fire([{ type: vscode.FileChangeType.Changed, uri }]);
    }
    delete(uri) {
        throw vscode.FileSystemError.NoPermissions();
    }
    rename(oldUri, newUri, options) {
        throw vscode.FileSystemError.NoPermissions();
    }
    // --- Helper Methods ---
    parseVirtualUri(uri) {
        // Scheme: polyglot:/path/to/virtual/file.rs?blockId=rust_1&realPath=/path/to/real.poly
        const query = new URLSearchParams(uri.query);
        const blockId = query.get('blockId');
        const realPath = query.get('realPath');
        if (!blockId || !realPath) {
            throw vscode.FileSystemError.FileNotFound();
        }
        return {
            realUri: vscode.Uri.file(realPath),
            blockId
        };
    }
    findBlock(text, blockId) {
        // Simple regex-based block finder
        // Matches #[tag] ... content ... (next tag or end)
        // This regex is simplified and might need robustness improvements
        // matching #[tag]
        const blockRegex = /(?:^|\n)#\[([a-zA-Z0-9_:]+)\]/g;
        let match;
        let blocks = [];
        let lastIndex = 0;
        // Use a simple counter for IDs for now, assuming sequential access
        // Ideally we'd have stable IDs based on content or explicit IDs
        let counter = 0;
        while ((match = blockRegex.exec(text)) !== null) {
            if (counter > 0) {
                // Determine the end of the previous block
                const prevBlockStart = blocks[blocks.length - 1].startIndex;
                // The content usually starts after the tag line
                const contentStart = text.indexOf('\n', prevBlockStart) + 1;
                const contentEnd = match.index;
                blocks[blocks.length - 1].endIndex = contentEnd;
                blocks[blocks.length - 1].content = text.substring(contentStart, contentEnd).trim();
            }
            blocks.push({
                tag: match[1],
                startIndex: match.index,
                endIndex: text.length,
                content: "",
                id: `${match[1]}_${counter}` // rudimentary ID
            });
            counter++;
        }
        // Handle the last block
        if (blocks.length > 0) {
            const lastBlock = blocks[blocks.length - 1];
            const contentStart = text.indexOf('\n', lastBlock.startIndex) + 1;
            lastBlock.content = text.substring(contentStart).trim();
            lastBlock.endIndex = text.length;
        }
        // Find the requested block
        // Note: This ID generation strategy is fragile because edits shift indices.
        // A robust solution needs persistent stable IDs or AST-based range tracking.
        // For MVP, we'll try to find by index if passed, or just simple tag matching if unique.
        // But for now let's just use the index embedded in the ID if possible or tag search.
        // Let's assume blockId format is "tag_index" for now
        const parts = blockId.split('_');
        const tag = parts[0];
        const indexStr = parts[1];
        if (indexStr !== undefined) {
            const idx = parseInt(indexStr);
            if (idx >= 0 && idx < blocks.length) {
                return blocks[idx];
            }
        }
        return null;
    }
}
exports.PolyglotFileSystemProvider = PolyglotFileSystemProvider;
//# sourceMappingURL=polyglotFileSystemProvider.js.map