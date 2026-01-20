
import * as path from 'path';
import { workspace, ExtensionContext, window } from 'vscode';

import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: ExtensionContext) {
    const config = workspace.getConfiguration('polyglot');

    // Check for bundled binary first, then fall back to config/PATH
    const bundledPath = path.join(context.extensionPath, 'bin', process.platform === 'win32' ? 'poly-lsp.exe' : 'poly-lsp');
    const configPath = config.get<string>('serverPath');

    // Priority: bundled > config > PATH
    let serverPath: string;
    const fs = require('fs');

    if (fs.existsSync(bundledPath)) {
        serverPath = bundledPath;
        window.showInformationMessage(`Polyglot: Using bundled LSP`);
    } else if (configPath && fs.existsSync(configPath)) {
        serverPath = configPath;
    } else {
        serverPath = 'poly-lsp'; // Fall back to PATH
    }

    // Also set POLYGLOT_BIN env for the LSP to find the compiler
    const polyglotBin = path.join(context.extensionPath, 'bin', process.platform === 'win32' ? 'polyglot.exe' : 'polyglot');
    if (fs.existsSync(polyglotBin)) {
        process.env.POLYGLOT_BIN = polyglotBin;
    }

    const serverOptions: ServerOptions = {
        run: { command: serverPath, transport: TransportKind.stdio },
        debug: {
            command: serverPath,
            transport: TransportKind.stdio,
        }
    };

    const clientOptions: LanguageClientOptions = {
        documentSelector: [{ scheme: 'file', language: 'polyglot' }],
        synchronize: {
            fileEvents: workspace.createFileSystemWatcher('**/*.poly')
        }
    };

    client = new LanguageClient(
        'polyglot',
        'Polyglot Language Server',
        serverOptions,
        clientOptions
    );

    // Start the client. This will also launch the server
    client.start();
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
