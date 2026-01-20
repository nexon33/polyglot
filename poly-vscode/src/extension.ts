
import * as path from 'path';
import { workspace, ExtensionContext, window, commands, Terminal } from 'vscode';

import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;
let polyglotBin: string | undefined;
let terminal: Terminal | undefined;

function getTerminal(): Terminal {
    if (!terminal || terminal.exitStatus !== undefined) {
        terminal = window.createTerminal('Polyglot');
    }
    terminal.show();
    return terminal;
}

function runPolyglotCommand(command: string, file?: string) {
    if (!polyglotBin) {
        window.showErrorMessage('Polyglot compiler not found. Install the extension with bundled binaries.');
        return;
    }

    const term = getTerminal();
    const filePath = file || window.activeTextEditor?.document.fileName;

    // Use & for PowerShell call operator when path contains spaces
    const cmd = process.platform === 'win32' ? `& "${polyglotBin}"` : `"${polyglotBin}"`;

    if (command === 'init') {
        term.sendText(`${cmd} init`);
    } else if (filePath) {
        term.sendText(`${cmd} ${command} "${filePath}"`);
    } else {
        window.showErrorMessage('No .poly file is open');
    }
}

export function activate(context: ExtensionContext) {
    const config = workspace.getConfiguration('polyglot');
    const fs = require('fs');

    // Check for bundled binary first, then fall back to config/PATH
    const bundledPath = path.join(context.extensionPath, 'bin', process.platform === 'win32' ? 'poly-lsp.exe' : 'poly-lsp');
    const configPath = config.get<string>('serverPath');

    // Priority: bundled > config > PATH
    let serverPath: string;

    if (fs.existsSync(bundledPath)) {
        serverPath = bundledPath;
        window.showInformationMessage(`Polyglot: Using bundled LSP`);
    } else if (configPath && fs.existsSync(configPath)) {
        serverPath = configPath;
    } else {
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
    context.subscriptions.push(
        commands.registerCommand('polyglot.build', () => runPolyglotCommand('build')),
        commands.registerCommand('polyglot.run', () => runPolyglotCommand('run')),
        commands.registerCommand('polyglot.check', () => runPolyglotCommand('check')),
        commands.registerCommand('polyglot.init', () => runPolyglotCommand('init'))
    );

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
