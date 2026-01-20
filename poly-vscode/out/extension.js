"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const path = require("path");
const vscode_1 = require("vscode");
const node_1 = require("vscode-languageclient/node");
let client;
let polyglotBin;
let terminal;
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
    // Register commands
    context.subscriptions.push(vscode_1.commands.registerCommand('polyglot.build', () => runPolyglotCommand('build')), vscode_1.commands.registerCommand('polyglot.run', () => runPolyglotCommand('run')), vscode_1.commands.registerCommand('polyglot.check', () => runPolyglotCommand('check')), vscode_1.commands.registerCommand('polyglot.init', () => runPolyglotCommand('init')));
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