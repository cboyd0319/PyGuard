#!/usr/bin/env python3
"""
PyGuard LSP Server

Language Server Protocol implementation for PyGuard security scanner.
Provides real-time security diagnostics and quick fixes in VS Code.

Usage:
    python -m pyguard_lsp.server

Requirements:
    pip install pygls pyguard
"""

import logging
import sys
from pathlib import Path
from typing import List, Optional
import asyncio

from pygls.server import LanguageServer
from pygls.lsp.types import (
    Diagnostic,
    DiagnosticSeverity,
    DidChangeTextDocumentParams,
    DidOpenTextDocumentParams,
    DidSaveTextDocumentParams,
    Position,
    Range,
    InitializeParams,
    CodeAction,
    CodeActionParams,
    CodeActionKind,
    WorkspaceEdit,
    TextEdit,
    Command,
)
from pygls.workspace import Document

# Add parent directory to path to import pyguard
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from pyguard.api.json_rpc import PyGuardJSONRPC
    from pyguard.core.scanner import Scanner
    PYGUARD_AVAILABLE = True
except ImportError:
    PYGUARD_AVAILABLE = False
    logging.warning("PyGuard not available. Install with: pip install pyguard")


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/pyguard-lsp.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PyGuardLanguageServer(LanguageServer):
    """PyGuard Language Server implementation"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scanner = None
        self.scan_cache = {}  # Cache scan results by file URI
        self.debounce_tasks = {}  # Track debounce tasks

    def initialize_scanner(self):
        """Initialize PyGuard scanner"""
        if not PYGUARD_AVAILABLE:
            logger.error("PyGuard not available")
            return False

        try:
            self.scanner = Scanner()
            logger.info("PyGuard scanner initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize PyGuard scanner: {e}")
            return False


# Create server instance
server = PyGuardLanguageServer('pyguard', 'v0.7.0')


@server.feature('initialize')
def initialize(ls: PyGuardLanguageServer, params: InitializeParams):
    """Handle initialization request"""
    logger.info("Initializing PyGuard LSP Server")
    ls.initialize_scanner()
    return {
        'capabilities': {
            'textDocumentSync': {
                'openClose': True,
                'change': 1,  # Full document sync
                'save': {'includeText': True}
            },
            'codeActionProvider': True,
            'diagnosticProvider': {
                'interFileDependencies': False,
                'workspaceDiagnostics': False
            }
        },
        'serverInfo': {
            'name': 'PyGuard LSP Server',
            'version': '0.7.0'
        }
    }


async def scan_document_debounced(ls: PyGuardLanguageServer, uri: str, delay: float = 0.5):
    """Scan document with debouncing to avoid excessive scans"""
    # Cancel existing debounce task for this URI
    if uri in ls.debounce_tasks:
        ls.debounce_tasks[uri].cancel()

    # Create new debounce task
    async def delayed_scan():
        await asyncio.sleep(delay)
        await scan_document(ls, uri)

    task = asyncio.create_task(delayed_scan())
    ls.debounce_tasks[uri] = task

    try:
        await task
    except asyncio.CancelledError:
        pass  # Task was cancelled, which is expected
    finally:
        if uri in ls.debounce_tasks:
            del ls.debounce_tasks[uri]


async def scan_document(ls: PyGuardLanguageServer, uri: str):
    """Scan a document and publish diagnostics"""
    if not ls.scanner:
        logger.warning("Scanner not initialized")
        return

    try:
        # Get document
        document = ls.workspace.get_document(uri)
        if not document:
            logger.warning(f"Document not found: {uri}")
            return

        # Get file path
        file_path = Path(document.path)

        # Only scan Python files
        if file_path.suffix != '.py':
            logger.debug(f"Skipping non-Python file: {file_path}")
            return

        logger.info(f"Scanning document: {uri}")

        # Scan with PyGuard
        # Note: This is a simplified version. In production, use the JSON-RPC API
        # or Scanner class properly
        source_code = document.source

        # For now, create placeholder diagnostics
        # TODO: Integrate actual PyGuard scanning
        diagnostics = await create_diagnostics_from_scan(source_code, file_path)

        # Cache results
        ls.scan_cache[uri] = diagnostics

        # Publish diagnostics
        ls.publish_diagnostics(uri, diagnostics)

        logger.info(f"Published {len(diagnostics)} diagnostics for {uri}")

    except Exception as e:
        logger.error(f"Error scanning document {uri}: {e}", exc_info=True)
        # Publish empty diagnostics on error
        ls.publish_diagnostics(uri, [])


async def create_diagnostics_from_scan(source: str, file_path: Path) -> List[Diagnostic]:
    """
    Create LSP diagnostics from PyGuard scan results

    TODO: Integrate with actual PyGuard scanner
    For now, returns placeholder diagnostics for testing
    """
    diagnostics = []

    # Placeholder: Check for common security issues in source
    lines = source.split('\n')

    for line_num, line in enumerate(lines):
        # Example: Flag uses of eval()
        if 'eval(' in line:
            col = line.find('eval(')
            diagnostics.append(Diagnostic(
                range=Range(
                    start=Position(line=line_num, character=col),
                    end=Position(line=line_num, character=col + 4)
                ),
                severity=DiagnosticSeverity.Error,
                message="Use of eval() is dangerous and can lead to arbitrary code execution",
                source='PyGuard',
                code='PY001-eval-usage'
            ))

        # Example: Flag use of pickle
        if 'pickle.load' in line:
            col = line.find('pickle.load')
            diagnostics.append(Diagnostic(
                range=Range(
                    start=Position(line=line_num, character=col),
                    end=Position(line=line_num, character=col + 11)
                ),
                severity=DiagnosticSeverity.Warning,
                message="Pickle deserialization can execute arbitrary code",
                source='PyGuard',
                code='PY002-unsafe-deserialization'
            ))

    return diagnostics


@server.feature('textDocument/didOpen')
async def did_open(ls: PyGuardLanguageServer, params: DidOpenTextDocumentParams):
    """Handle document open event"""
    uri = params.text_document.uri
    logger.info(f"Document opened: {uri}")
    await scan_document(ls, uri)


@server.feature('textDocument/didChange')
async def did_change(ls: PyGuardLanguageServer, params: DidChangeTextDocumentParams):
    """Handle document change event (with debouncing)"""
    uri = params.text_document.uri
    logger.debug(f"Document changed: {uri}")
    # Debounce to avoid excessive scans while typing
    await scan_document_debounced(ls, uri, delay=0.5)


@server.feature('textDocument/didSave')
async def did_save(ls: PyGuardLanguageServer, params: DidSaveTextDocumentParams):
    """Handle document save event"""
    uri = params.text_document.uri
    logger.info(f"Document saved: {uri}")
    # Scan immediately on save (no debounce)
    await scan_document(ls, uri)


@server.feature('textDocument/codeAction')
async def code_action(ls: PyGuardLanguageServer, params: CodeActionParams) -> List[CodeAction]:
    """Provide code actions (quick fixes) for diagnostics"""
    uri = params.text_document.uri
    logger.info(f"Code action requested for {uri}")

    actions = []

    # Get diagnostics at the requested range
    for diagnostic in params.context.diagnostics:
        if diagnostic.source != 'PyGuard':
            continue

        # Example: Provide fix for eval() usage
        if diagnostic.code == 'PY001-eval-usage':
            # Create a code action to replace eval with ast.literal_eval
            document = ls.workspace.get_document(uri)
            if document:
                action = CodeAction(
                    title="Replace eval() with ast.literal_eval()",
                    kind=CodeActionKind.QuickFix,
                    diagnostics=[diagnostic],
                    edit=WorkspaceEdit(
                        changes={
                            uri: [
                                TextEdit(
                                    range=diagnostic.range,
                                    new_text="ast.literal_eval"
                                )
                            ]
                        }
                    )
                )
                actions.append(action)

        # Add action to show documentation
        doc_action = CodeAction(
            title=f"View PyGuard documentation for {diagnostic.code}",
            kind=CodeActionKind.QuickFix,
            command=Command(
                title="View Documentation",
                command="pyguard.showDocumentation",
                arguments=[diagnostic.code]
            )
        )
        actions.append(doc_action)

    logger.info(f"Returning {len(actions)} code actions")
    return actions


@server.command('pyguard.showDocumentation')
async def show_documentation(ls: PyGuardLanguageServer, args: List[str]):
    """Show documentation for a rule"""
    if not args:
        return

    rule_code = args[0]
    # TODO: Generate URL from rule code
    doc_url = f"https://github.com/cboyd0319/PyGuard/blob/main/docs/rules/{rule_code}.md"

    ls.show_message(f"Documentation: {doc_url}")


def main():
    """Start the LSP server"""
    logger.info("Starting PyGuard LSP Server")

    if not PYGUARD_AVAILABLE:
        logger.error("PyGuard is not installed. Please install with: pip install pyguard")
        sys.exit(1)

    # Start server (reads from stdin, writes to stdout)
    server.start_io()


if __name__ == '__main__':
    main()
