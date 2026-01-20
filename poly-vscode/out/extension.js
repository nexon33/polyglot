"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const path = require("path");
const vscode_1 = require("vscode");
const node_1 = require("vscode-languageclient/node");
let client;
function activate(context) {
    const config = vscode_1.workspace.getConfiguration('polyglot');
    // Check for bundled binary first, then fall back to config/PATH
    const bundledPath = path.join(context.extensionPath, 'bin', process.platform === 'win32' ? 'poly-lsp.exe' : 'poly-lsp');
    const configPath = config.get('serverPath');
    // Priority: bundled > config > PATH
    let serverPath;
    const fs = require('fs');
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
    // Also set POLYGLOT_BIN env for the LSP to find the compiler
    const polyglotBin = path.join(context.extensionPath, 'bin', process.platform === 'win32' ? 'polyglot.exe' : 'polyglot');
    if (fs.existsSync(polyglotBin)) {
        process.env.POLYGLOT_BIN = polyglotBin;
    }
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