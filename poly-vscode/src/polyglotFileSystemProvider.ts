
import * as vscode from 'vscode';
import * as path from 'path';

export class PolyglotFileSystemProvider implements vscode.FileSystemProvider {
    // Event emitter for file changes
    private _onDidChangeFile = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
    readonly onDidChangeFile: vscode.Event<vscode.FileChangeEvent[]> = this._onDidChangeFile.event;

    constructor() { }

    watch(uri: vscode.Uri, options: { recursive: boolean; excludes: string[]; }): vscode.Disposable {
        // We watch the real file instead, but needed for interface compliance
        return new vscode.Disposable(() => { });
    }

    stat(uri: vscode.Uri): vscode.FileStat {
        // For now, return a generic file stat
        // In a real implementation, we'd want to check existence
        return {
            type: vscode.FileType.File,
            ctime: Date.now(),
            mtime: Date.now(),
            size: 0
        };
    }

    readDirectory(uri: vscode.Uri): [string, vscode.FileType][] {
        // We don't support directory reading for now
        return [];
    }

    createDirectory(uri: vscode.Uri): void {
        throw vscode.FileSystemError.NoPermissions();
    }

    async readFile(uri: vscode.Uri): Promise<Uint8Array> {
        const { realUri, blockId } = this.parseVirtualUri(uri);
        const doc = await vscode.workspace.openTextDocument(realUri);
        const text = doc.getText();

        const block = this.findBlock(text, blockId);
        if (!block) {
            throw vscode.FileSystemError.FileNotFound();
        }

        return Buffer.from(block.content);
    }

    async writeFile(uri: vscode.Uri, content: Uint8Array, options: { create: boolean, overwrite: boolean }): Promise<void> {
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

    delete(uri: vscode.Uri): void {
        throw vscode.FileSystemError.NoPermissions();
    }

    rename(oldUri: vscode.Uri, newUri: vscode.Uri, options: { overwrite: boolean }): void {
        throw vscode.FileSystemError.NoPermissions();
    }

    // --- Helper Methods ---

    private parseVirtualUri(uri: vscode.Uri): { realUri: vscode.Uri, blockId: string } {
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

    private findBlock(text: string, blockId: string): { content: string, startIndex: number, endIndex: number } | null {
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
                endIndex: text.length, // Placeholder
                content: "", // Placeholder
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
