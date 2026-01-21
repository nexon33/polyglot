import * as vscode from 'vscode';

interface VirtualFile {
    name: string;
    path: string;
    language: string;
    blockIndex: number;
    polyUri: vscode.Uri;
}

/**
 * Provides a virtual file tree in the Explorer sidebar for .poly files.
 * Each block with a path (e.g., #[rust:src/main.rs]) appears as a file.
 */
export class PolyTreeProvider implements vscode.TreeDataProvider<VirtualFile> {
    private _onDidChangeTreeData = new vscode.EventEmitter<VirtualFile | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private _files: VirtualFile[] = [];
    private _polyUri: vscode.Uri | undefined;

    constructor() { }

    refresh(polyUri?: vscode.Uri): void {
        if (polyUri) {
            this._polyUri = polyUri;
            this.parsePolyFile(polyUri);
        }
        this._onDidChangeTreeData.fire(undefined);
    }

    private async parsePolyFile(uri: vscode.Uri): Promise<void> {
        try {
            const doc = await vscode.workspace.openTextDocument(uri);
            const text = doc.getText();
            this._files = this.extractVirtualFiles(text, uri);
        } catch (e) {
            this._files = [];
        }
    }

    private extractVirtualFiles(text: string, polyUri: vscode.Uri): VirtualFile[] {
        const files: VirtualFile[] = [];

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

    private defaultPath(lang: string, index: number): string {
        const extensions: Record<string, string> = {
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

    getTreeItem(element: VirtualFile): vscode.TreeItem {
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

    private getIcon(lang: string): string {
        const icons: Record<string, string> = {
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

    getChildren(element?: VirtualFile): VirtualFile[] {
        if (element) {
            return []; // No nested children
        }
        return this._files;
    }

    getParent(element: VirtualFile): vscode.ProviderResult<VirtualFile> {
        return null;
    }
}
