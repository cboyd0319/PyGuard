/**
 * PyGuard VS Code Extension
 *
 * Main extension entry point that initializes the LSP client and provides
 * commands for security scanning and auto-fixing.
 */

import * as path from 'path';
import * as vscode from 'vscode';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;
let outputChannel: vscode.OutputChannel;

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('PyGuard extension is now active');

    // Create output channel
    outputChannel = vscode.window.createOutputChannel('PyGuard');
    outputChannel.appendLine('PyGuard extension activated');

    // Start LSP client
    startLanguageClient(context);

    // Register commands
    registerCommands(context);

    // Show welcome message (first time only)
    const isFirstTime = context.globalState.get('pyguard.firstActivation', true);
    if (isFirstTime) {
        showWelcomeMessage();
        context.globalState.update('pyguard.firstActivation', false);
    }
}

/**
 * Start the Language Server Protocol client
 */
function startLanguageClient(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('pyguard');

    // Get Python path
    const pythonPath = config.get<string>('pythonPath', 'python');

    // Get LSP server path
    let serverPath = config.get<string>('lspServerPath', '');
    if (!serverPath) {
        // Default: use server from extension bundle or workspace
        serverPath = path.join(context.extensionPath, '..', 'pyguard_lsp', 'server.py');
    }

    outputChannel.appendLine(`Python path: ${pythonPath}`);
    outputChannel.appendLine(`LSP server path: ${serverPath}`);

    // Server options - start the LSP server as a subprocess
    const serverOptions: ServerOptions = {
        command: pythonPath,
        args: ['-m', 'pyguard_lsp.server'],
        transport: TransportKind.stdio,
        options: {
            env: process.env
        }
    };

    // Client options - configure how the client interacts with the server
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'python' },
            { scheme: 'untitled', language: 'python' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.py')
        },
        outputChannel: outputChannel,
        traceOutputChannel: outputChannel,
        revealOutputChannelOn: 4 // Never automatically reveal
    };

    // Create and start the client
    client = new LanguageClient(
        'pyguard',
        'PyGuard Language Server',
        serverOptions,
        clientOptions
    );

    // Start the client (also starts the server)
    client.start().then(() => {
        outputChannel.appendLine('PyGuard LSP client started successfully');
    }).catch((error) => {
        outputChannel.appendLine(`Error starting LSP client: ${error}`);
        vscode.window.showErrorMessage(
            'Failed to start PyGuard. Is PyGuard installed? Run: pip install pyguard'
        );
    });
}

/**
 * Register extension commands
 */
function registerCommands(context: vscode.ExtensionContext) {
    // Command: Scan current file
    context.subscriptions.push(
        vscode.commands.registerCommand('pyguard.scan', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active Python file to scan');
                return;
            }

            if (editor.document.languageId !== 'python') {
                vscode.window.showWarningMessage('Current file is not a Python file');
                return;
            }

            outputChannel.appendLine(`Scanning file: ${editor.document.fileName}`);
            vscode.window.showInformationMessage('PyGuard: Scanning file...');

            // Save first
            await editor.document.save();

            // The LSP server will automatically scan on save
            // Just show a message
            vscode.window.showInformationMessage('PyGuard: Scan complete. Check Problems panel for results.');
        })
    );

    // Command: Scan workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('pyguard.scanWorkspace', async () => {
            outputChannel.appendLine('Scanning workspace...');
            vscode.window.showInformationMessage('PyGuard: Scanning workspace...');

            // Find all Python files in workspace
            const files = await vscode.workspace.findFiles('**/*.py', '**/node_modules/**');

            outputChannel.appendLine(`Found ${files.length} Python files`);

            // TODO: Implement workspace-wide scanning
            // For now, just show message
            vscode.window.showInformationMessage(
                `PyGuard: Found ${files.length} Python files. Workspace scanning coming soon!`
            );
        })
    );

    // Command: Fix all auto-fixable issues
    context.subscriptions.push(
        vscode.commands.registerCommand('pyguard.fixAll', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active file');
                return;
            }

            outputChannel.appendLine(`Applying auto-fixes to: ${editor.document.fileName}`);

            // TODO: Implement auto-fix via LSP code actions
            vscode.window.showInformationMessage('PyGuard: Auto-fix feature coming soon!');
        })
    );

    // Command: Show output channel
    context.subscriptions.push(
        vscode.commands.registerCommand('pyguard.showOutput', () => {
            outputChannel.show();
        })
    );
}

/**
 * Show welcome message on first activation
 */
function showWelcomeMessage() {
    const message = 'Welcome to PyGuard! Real-time Python security scanning is now active.';
    const learnMore = 'Learn More';
    const dontShowAgain = "Don't Show Again";

    vscode.window.showInformationMessage(message, learnMore, dontShowAgain).then(selection => {
        if (selection === learnMore) {
            vscode.env.openExternal(vscode.Uri.parse('https://github.com/cboyd0319/PyGuard'));
        }
    });
}

/**
 * Extension deactivation
 */
export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }

    outputChannel.appendLine('Deactivating PyGuard extension');
    return client.stop();
}
