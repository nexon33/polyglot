import * as vscode from 'vscode';

export type ViewMode = 'combined' | 'split';

/**
 * Manages the dual view state for .poly files.
 * Combined: Single editor showing the raw .poly file
 * Split: Virtual file tree with per-block editors
 */
export class DualViewManager {
    private _mode: ViewMode = 'combined';
    private _onDidChangeMode = new vscode.EventEmitter<ViewMode>();
    readonly onDidChangeMode = this._onDidChangeMode.event;

    private _activePolyFile: vscode.Uri | undefined;
    private _virtualEditors: Map<string, vscode.TextEditor> = new Map();

    constructor(private context: vscode.ExtensionContext) {}

    get mode(): ViewMode {
        return this._mode;
    }

    get activePolyFile(): vscode.Uri | undefined {
        return this._activePolyFile;
    }

    async toggle(): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        
        if (!editor) {
            vscode.window.showWarningMessage('No active editor');
            return;
        }

        // Check if current file is a .poly file or virtual poly file
        const uri = editor.document.uri;
        const isPolyFile = uri.fsPath.endsWith('.poly');
        const isVirtualPoly = uri.scheme === 'polyglot';

        if (!isPolyFile && !isVirtualPoly) {
            vscode.window.showWarningMessage('Toggle only works on .poly files');
            return;
        }

        if (this._mode === 'combined') {
            await this.enterSplitMode(isVirtualPoly ? this._activePolyFile! : uri);
        } else {
            await this.enterCombinedMode();
        }
    }

    private async enterSplitMode(polyUri: vscode.Uri): Promise<void> {
        this._activePolyFile = polyUri;
        this._mode = 'split';
        this._onDidChangeMode.fire(this._mode);

        // Show the virtual file tree
        await vscode.commands.executeCommand('polyglot.showVirtualTree');

        vscode.window.showInformationMessage('📂 Split View: Virtual files visible in explorer');
    }

    private async enterCombinedMode(): Promise<void> {
        // Close virtual editors and open the real .poly file
        if (this._activePolyFile) {
            const doc = await vscode.workspace.openTextDocument(this._activePolyFile);
            await vscode.window.showTextDocument(doc);
        }

        this._mode = 'combined';
        this._virtualEditors.clear();
        this._onDidChangeMode.fire(this._mode);

        vscode.window.showInformationMessage('📄 Combined View: Single .poly file');
    }

    dispose(): void {
        this._onDidChangeMode.dispose();
    }
}
