# PyGuard LSP Server

Language Server Protocol implementation for PyGuard security scanner.

## Overview

This LSP server wraps PyGuard's security scanning capabilities to provide real-time diagnostics and quick fixes in VS Code and other LSP-compatible editors.

## Features

- ✅ Real-time security scanning as you type
- ✅ Diagnostic highlighting (squiggly lines)
- ✅ Quick fixes for common security issues
- ✅ Debounced scanning (500ms delay to avoid excessive scans)
- ✅ Scan on save (immediate, no debounce)

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install pygls directly
pip install pygls

# PyGuard should be installed from parent directory
cd ..
pip install -e .
```

## Usage

### Standalone Testing

```bash
# Start the LSP server
python -m pyguard_lsp.server

# The server will read from stdin and write to stdout
# Use an LSP client to connect
```

### With VS Code Extension

The VS Code extension (in `../vscode-pyguard/`) automatically starts this LSP server.

## Development

### Running Locally

```bash
# Install in development mode
pip install -e .

# Run with logging
python -m pyguard_lsp.server

# Check logs
tail -f /tmp/pyguard-lsp.log
```

### Testing with Generic LSP Client

You can test the LSP server with any generic LSP client:

```python
import json
import subprocess

# Start server
proc = subprocess.Popen(
    ['python', '-m', 'pyguard_lsp.server'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Send initialize request
initialize_request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "processId": None,
        "rootUri": "file:///path/to/project",
        "capabilities": {}
    }
}

# Format as LSP message
content = json.dumps(initialize_request)
message = f"Content-Length: {len(content)}\r\n\r\n{content}"

proc.stdin.write(message.encode())
proc.stdin.flush()

# Read response
# ... (LSP protocol handling)
```

## Architecture

```
┌─────────────────────────────────────┐
│         LSP Client (VS Code)        │
└──────────────┬──────────────────────┘
               │ stdin/stdout (JSON-RPC)
               │
┌──────────────┴──────────────────────┐
│       PyGuard LSP Server            │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  Protocol Handler (pygls)    │  │
│  └──────────┬───────────────────┘  │
│             │                       │
│  ┌──────────┴───────────────────┐  │
│  │  Diagnostic Converter        │  │
│  └──────────┬───────────────────┘  │
│             │                       │
│  ┌──────────┴───────────────────┐  │
│  │  PyGuard Scanner             │  │
│  │  (via JSON-RPC API)          │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

## LSP Methods Implemented

### Text Document Synchronization

- `textDocument/didOpen` - Scan when document opens
- `textDocument/didChange` - Scan on changes (debounced)
- `textDocument/didSave` - Scan on save (immediate)

### Code Actions

- `textDocument/codeAction` - Provide quick fixes

### Commands

- `pyguard.showDocumentation` - Show rule documentation

## Configuration

### Client Configuration (VS Code)

```json
{
  "pyguard.enable": true,
  "pyguard.severity": "MEDIUM",
  "pyguard.scanOnType": true,
  "pyguard.scanOnSave": true,
  "pyguard.debounceDelay": 500
}
```

### Server Configuration

The server can be configured via initialization options:

```python
{
  "severity": "MEDIUM",  # Minimum severity to report
  "autoFix": false,      # Enable auto-fix on save
  "excludePatterns": ["tests/", "**/*_test.py"]
}
```

## Logging

Logs are written to:
- `/tmp/pyguard-lsp.log` - Main log file
- `stderr` - Error output

Set log level:

```python
import logging
logging.getLogger('pyguard_lsp').setLevel(logging.DEBUG)
```

## Current Limitations

- **Placeholder Diagnostics:** Currently uses simple pattern matching (eval, pickle) as proof-of-concept
- **TODO:** Integrate full PyGuard scanner via JSON-RPC API
- **TODO:** Implement comprehensive code actions for all auto-fixes
- **TODO:** Add workspace-wide scanning
- **TODO:** Implement configuration via LSP settings

## Next Steps

1. **Integrate Full Scanner:**
   - Use PyGuardJSONRPC API for comprehensive scanning
   - Map all PyGuard findings to LSP diagnostics

2. **Implement All Code Actions:**
   - Map PyGuard's 199+ auto-fixes to LSP CodeActions
   - Support multiple fix options when available

3. **Add Configuration:**
   - Support .pyguard.yml configuration files
   - Workspace-specific settings
   - Per-project severity thresholds

4. **Performance Optimization:**
   - Incremental scanning (only changed regions)
   - Background scanning threads
   - Result caching

5. **Testing:**
   - Unit tests for protocol handlers
   - Integration tests with mock LSP client
   - End-to-end tests with VS Code

## References

- **LSP Specification:** https://microsoft.github.io/language-server-protocol/
- **pygls Documentation:** https://pygls.readthedocs.io/
- **PyGuard JSON-RPC API:** `../pyguard/api/json_rpc.py`
- **VS Code Extension:** `../vscode-pyguard/`

## License

MIT License - see LICENSE file in parent directory

## Maintainers

- Chad Boyd (@cboyd0319)

## Contributing

See CONTRIBUTING.md in the parent directory.
