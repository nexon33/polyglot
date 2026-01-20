"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode_1 = require("vscode");
const node_1 = require("vscode-languageclient/node");
let client;
function activate(context) {
    const config = vscode_1.workspace.getConfiguration('polyglot');
    const serverPath = config.get('serverPath') || 'poly-lsp';
    // NOTE: In development, we can point to the cargo project
    // serverPath might be "poly-lsp" which assumes it is in PATH.
    // Launch the server
    // If we are in debug mode, we can try to use cargo run? 
    // For now, assume compiled binary.
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
            fileEvents: vscode_1.workspace.createFileSystemWatcher('**/.poly')
        }
    };
    client = new node_1.LanguageClient('polyglot', 'Polyglot Language Server', serverOptions, clientOptions);
    // Start the client. This will also launch the server
    client.start();
    vscode_1.window.showInformationMessage(`Polyglot Client Started. Connecting to: ${serverPath}`);
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