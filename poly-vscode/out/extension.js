"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const path = require("path");
const vscode_1 = require("vscode");
const node_1 = require("vscode-languageclient/node");
const dualViewManager_1 = require("./dualViewManager");
const polyTreeProvider_1 = require("./polyTreeProvider");
const docBlockProvider_1 = require("./docBlockProvider");
const polyglotFileSystemProvider_1 = require("./polyglotFileSystemProvider");
const autoWorkspaceManager_1 = require("./autoWorkspaceManager");
let client;
let polyglotBin;
let terminal;
let dualViewManager;
let polyTreeProvider;
let docBlockProvider;
let autoWorkspaceManager;
function getTerminal() {
    if (!terminal || terminal.exitStatus !== undefined) {
        terminal = vscode_1.window.createTerminal('Polyglot');
    }
    terminal.show();
    return terminal;
}
function runPolyglotCommand(command, file) {
    if (!polyglotBin) {
        vscode_1.window.showErrorMessage('Polyglot compiler not found. Install the extension with bundled binaries.');
        return;
    }
    const term = getTerminal();
    const filePath = file || vscode_1.window.activeTextEditor?.document.fileName;
    // Use & for PowerShell call operator when path contains spaces
    const cmd = process.platform === 'win32' ? `& "${polyglotBin}"` : `"${polyglotBin}"`;
    if (command === 'init') {
        term.sendText(`${cmd} init`);
    }
    else if (filePath) {
        term.sendText(`${cmd} ${command} "${filePath}"`);
    }
    else {
        vscode_1.window.showErrorMessage('No .poly file is open');
    }
}
function activate(context) {
    const config = vscode_1.workspace.getConfiguration('polyglot');
    const fs = require('fs');
    // Check for bundled binary first, then fall back to config/PATH
    const bundledPath = path.join(context.extensionPath, 'bin', process.platform === 'win32' ? 'poly-lsp.exe' : 'poly-lsp');
    const configPath = config.get('serverPath');
    // Priority: bundled > config > PATH
    let serverPath;
    if (fs.existsSync(bundledPath)) {
        serverPath = bundledPath;
        vscode_1.window.showInformationMessage(`Polyglot: Using bundled LSP`);
    }
    else if (configPath && fs.existsSync(configPath)) {
        serverPath = configPath;
    }
    else {
        serverPath = 'poly-lsp'; // Fall back to PATH
    }
    // Also set POLYGLOT_BIN env for the LSP and commands
    const binDir = path.join(context.extensionPath, 'bin');
    const polyglotBinPath = path.join(binDir, process.platform === 'win32' ? 'polyglot.exe' : 'polyglot');
    if (fs.existsSync(polyglotBinPath)) {
        polyglotBin = polyglotBinPath;
        process.env.POLYGLOT_BIN = polyglotBinPath;
        // Add bin directory to PATH so 'polyglot' works in VS Code terminals
        const pathSep = process.platform === 'win32' ? ';' : ':';
        if (!process.env.PATH?.includes(binDir)) {
            process.env.PATH = binDir + pathSep + process.env.PATH;
        }
    }
    // Initialize Dual View components
    dualViewManager = new dualViewManager_1.DualViewManager(context);
    polyTreeProvider = new polyTreeProvider_1.PolyTreeProvider();
    docBlockProvider = new docBlockProvider_1.DocBlockProvider();
    autoWorkspaceManager = new autoWorkspaceManager_1.AutoWorkspaceManager();
    // Register virtual file system
    const polyFs = new polyglotFileSystemProvider_1.PolyglotFileSystemProvider();
    context.subscriptions.push(vscode_1.workspace.registerFileSystemProvider('polyglot', polyFs, { isCaseSensitive: true }));
    // Register tree view
    const treeView = vscode_1.window.createTreeView('polyglotVirtualFiles', {
        treeDataProvider: polyTreeProvider,
        showCollapseAll: true
    });
    context.subscriptions.push(treeView);
    // Auto-create workspace for .poly files without Cargo.toml
    context.subscriptions.push(vscode_1.workspace.onDidOpenTextDocument(async (doc) => {
        if (doc.uri.fsPath.endsWith('.poly') && autoWorkspaceManager.needsWorkspace(doc.uri)) {
            const text = doc.getText();
            // Extract Rust code from blocks
            const rustBlocks = [];
            const blockRegex = /#\[(rust|rs)(?::[^\]]+)?\]\s*\n([\s\S]*?)(?=\n#\[|$)/g;
            let match;
            while ((match = blockRegex.exec(text)) !== null) {
                rustBlocks.push(match[2]);
            }
            if (rustBlocks.length > 0) {
                const rustCode = rustBlocks.join('\n\n');
                const workspacePath = autoWorkspaceManager.createWorkspace(doc.uri, rustCode);
                vscode_1.window.showInformationMessage(`📦 Created temp Rust workspace: ${workspacePath}`);
            }
        }
    }));
    // Register document providers
    context.subscriptions.push(require('vscode').languages.registerHoverProvider({ language: 'polyglot' }, docBlockProvider), require('vscode').languages.registerDocumentLinkProvider({ language: 'polyglot' }, docBlockProvider));
    // Register commands
    context.subscriptions.push(vscode_1.commands.registerCommand('polyglot.build', () => runPolyglotCommand('build')), vscode_1.commands.registerCommand('polyglot.run', () => runPolyglotCommand('run')), vscode_1.commands.registerCommand('polyglot.check', () => runPolyglotCommand('check')), vscode_1.commands.registerCommand('polyglot.init', () => runPolyglotCommand('init')), vscode_1.commands.registerCommand('polyglot.test', () => runPolyglotCommand('test')), vscode_1.commands.registerCommand('polyglot.toggleView', () => dualViewManager.toggle()), vscode_1.commands.registerCommand('polyglot.showVirtualTree', () => {
        const editor = vscode_1.window.activeTextEditor;
        if (editor?.document.uri.fsPath.endsWith('.poly')) {
            polyTreeProvider.refresh(editor.document.uri);
        }
    }), vscode_1.commands.registerCommand('polyglot.openVirtualFile', async (file) => {
        if (!file)
            return;
        const virtualUri = require('vscode').Uri.parse(`polyglot:/${file.path}?blockId=${file.language}_${file.blockIndex}&realPath=${encodeURIComponent(file.polyUri.fsPath)}`);
        await vscode_1.commands.executeCommand('vscode.open', virtualUri);
    }), vscode_1.commands.registerCommand('polyglot.goToSymbol', async (args) => {
        // Search for symbol definition in the file
        const uri = require('vscode').Uri.parse(args.uri);
        const doc = await vscode_1.workspace.openTextDocument(uri);
        const text = doc.getText();
        // Simple regex search for fn symbol or similar
        const symbolRegex = new RegExp(`\\b(fn|function|def|const|let|var)\\s+${args.symbol}\\b`);
        const match = symbolRegex.exec(text);
        if (match) {
            const pos = doc.positionAt(match.index);
            await vscode_1.window.showTextDocument(doc, { selection: new (require('vscode').Range)(pos, pos) });
        }
        else {
            vscode_1.window.showWarningMessage(`Symbol "${args.symbol}" not found`);
        }
    }));
    // Listen for active editor changes to refresh tree
    context.subscriptions.push(vscode_1.window.onDidChangeActiveTextEditor(editor => {
        if (editor?.document.uri.fsPath.endsWith('.poly') && dualViewManager.mode === 'split') {
            polyTreeProvider.refresh(editor.document.uri);
        }
    }));
    const serverOptions = {
        run: { command: serverPath, transport: node_1.TransportKind.stdio },
        debug: {
            command: serverPath,
            transport: node_1.TransportKind.stdio,
        }
    };
    const clientOptions = {
        documentSelector: [{ scheme: 'file', language: 'polyglot' }],
        synchronize: {
            fileEvents: vscode_1.workspace.createFileSystemWatcher('**/*.poly')
        }
    };
    client = new node_1.LanguageClient('polyglot', 'Polyglot Language Server', serverOptions, clientOptions);
    // Start the client. This will also launch the server
    client.start();
}
exports.activate = activate;
function deactivate() {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map