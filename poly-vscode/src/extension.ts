
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
    const serverPath = config.get<string>('serverPath') || 'poly-lsp';

    // NOTE: In development, we can point to the cargo project
    // serverPath might be "poly-lsp" which assumes it is in PATH.

    // Launch the server
    // If we are in debug mode, we can try to use cargo run? 
    // For now, assume compiled binary.

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
            fileEvents: workspace.createFileSystemWatcher('**/.poly')
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

    window.showInformationMessage(`Polyglot Client Started. Connecting to: ${serverPath}`);
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
