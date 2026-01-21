"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DualViewManager = void 0;
const vscode = require("vscode");
/**
 * Manages the dual view state for .poly files.
 * Combined: Single editor showing the raw .poly file
 * Split: Virtual file tree with per-block editors
 */
class DualViewManager {
    constructor(context) {
        this.context = context;
        this._mode = 'combined';
        this._onDidChangeMode = new vscode.EventEmitter();
        this.onDidChangeMode = this._onDidChangeMode.event;
        this._virtualEditors = new Map();
    }
    get mode() {
        return this._mode;
    }
    get activePolyFile() {
        return this._activePolyFile;
    }
    async toggle() {
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
            await this.enterSplitMode(isVirtualPoly ? this._activePolyFile : uri);
        }
        else {
            await this.enterCombinedMode();
        }
    }
    async enterSplitMode(polyUri) {
        this._activePolyFile = polyUri;
        this._mode = 'split';
        this._onDidChangeMode.fire(this._mode);
        // Show the virtual file tree
        await vscode.commands.executeCommand('polyglot.showVirtualTree');
        vscode.window.showInformationMessage('📂 Split View: Virtual files visible in explorer');
    }
    async enterCombinedMode() {
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
    dispose() {
        this._onDidChangeMode.dispose();
    }
}
exports.DualViewManager = DualViewManager;
//# sourceMappingURL=dualViewManager.js.map