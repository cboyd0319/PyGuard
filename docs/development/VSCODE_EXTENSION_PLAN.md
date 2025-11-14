# VS Code Extension Development Plan

**Status:** ❌ NOT STARTED - CRITICAL BLOCKER FOR v0.7.0
**Priority:** **HIGHEST** - Only major gap for v0.7.0 completion
**Estimated Effort:** 4-6 weeks full-time
**Backend Status:** ✅ 100% Ready (JSON-RPC API implemented)

---

## Executive Summary

The VS Code extension is the **single most important missing piece** for PyGuard v0.7.0 "Easy Distribution" completion. Everything else is either complete or nearly complete.

### Why Critical

- **Developer Onboarding:** VS Code is #1 Python IDE (~60% market share)
- **Real-time Feedback:** Catch issues while coding, not during CI/CD
- **Quick Fixes:** One-click auto-fix directly in editor
- **Market Adoption:** 1K+ install target for v0.7.0

### Current State

- ✅ **Backend:** JSON-RPC API fully implemented (`pyguard/api/json_rpc.py`, 676 lines)
- ✅ **Analysis Engine:** Ready for real-time integration
- ✅ **Auto-Fix System:** 199+ fixes ready to expose via CodeActions
- ❌ **Frontend:** No extension code exists

---

## Architecture Overview

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                      VS Code Extension                       │
│                                                              │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Extension │  │  LSP Client  │  │  UI Components      │ │
│  │  Main      │──│  Integration │──│  - Diagnostics      │ │
│  │            │  │              │  │  - Quick Fixes      │ │
│  │            │  │              │  │  - Code Actions     │ │
│  │            │  │              │  │  - Status Bar       │ │
│  └────────────┘  └──────────────┘  └─────────────────────┘ │
└───────────────────────────┬─────────────────────────────────┘
                            │ stdin/stdout (LSP protocol)
                            │
┌───────────────────────────┴─────────────────────────────────┐
│                       LSP Server (Python)                    │
│                                                              │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Protocol  │  │  Diagnostic  │  │  JSON-RPC Backend   │ │
│  │  Handler   │──│  Converter   │──│  (Already Exists!)  │ │
│  │            │  │              │  │                     │ │
│  └────────────┘  └──────────────┘  └─────────────────────┘ │
│                                     ┌─────────────────────┐ │
│                                     │  PyGuard Engine     │ │
│                                     │  - Scan             │ │
│                                     │  - Auto-fix         │ │
│                                     │  - Rules            │ │
│                                     └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Communication Flow

1. **User types code** → VS Code calls LSP
2. **LSP Server receives** → `textDocument/didChange`
3. **PyGuard scans** → Via JSON-RPC API
4. **Results convert** → LSP Diagnostic format
5. **VS Code displays** → Squiggly lines, problems panel
6. **User clicks** → Quick Fix → LSP CodeAction
7. **PyGuard fixes** → Return edit
8. **VS Code applies** → Code updated

---

## Development Phases

### Phase 1: LSP Server (Week 1-2)

**Goal:** Wrap PyGuard's JSON-RPC API with LSP protocol

**Tasks:**
1. **Project Setup**
   ```bash
   mkdir pyguard-lsp
   cd pyguard-lsp
   python -m venv venv
   source venv/bin/activate
   pip install pygls  # Python LSP library
   ```

2. **Create LSP Server** (`pyguard_lsp/server.py`)
   ```python
   from pygls.server import LanguageServer
   from pygls.lsp.types import *
   from pyguard.api.json_rpc import PyGuardJSONRPC

   server = LanguageServer('pyguard', 'v0.7.0')

   @server.feature(TEXT_DOCUMENT_DID_OPEN)
   async def did_open(ls: LanguageServer, params: DidOpenTextDocumentParams):
       # Scan file when opened
       pass

   @server.feature(TEXT_DOCUMENT_DID_CHANGE)
   async def did_change(ls: LanguageServer, params: DidChangeTextDocumentParams):
       # Scan file on changes (debounced)
       pass

   @server.feature(CODE_ACTION)
   async def code_action(ls: LanguageServer, params: CodeActionParams):
       # Provide quick fixes
       pass

   if __name__ == '__main__':
       server.start_io()
   ```

3. **Diagnostic Converter** (`pyguard_lsp/diagnostics.py`)
   ```python
   from pygls.lsp.types import Diagnostic, DiagnosticSeverity

   def pyguard_to_lsp_diagnostic(finding: dict) -> Diagnostic:
       severity_map = {
           'CRITICAL': DiagnosticSeverity.Error,
           'HIGH': DiagnosticSeverity.Error,
           'MEDIUM': DiagnosticSeverity.Warning,
           'LOW': DiagnosticSeverity.Information
       }

       return Diagnostic(
           range=Range(...),
           severity=severity_map[finding['severity']],
           message=finding['message'],
           source='PyGuard',
           code=finding['rule_id']
       )
   ```

4. **Testing**
   ```bash
   # Test LSP server with generic LSP client
   python -m pyguard_lsp.server
   ```

**Deliverables:**
- ✅ LSP server binary/script
- ✅ Basic diagnostics working
- ✅ Test with generic LSP client

**Estimated Time:** 1-2 weeks

---

### Phase 2: VS Code Extension (Week 2-3)

**Goal:** Create VS Code extension that uses the LSP server

**Tasks:**
1. **Extension Scaffold**
   ```bash
   npm install -g yo generator-code
   yo code

   # Choose:
   # - New Language Server Extension
   # - TypeScript
   # - Name: pyguard
   # - ID: pyguard
   ```

2. **Extension Structure**
   ```
   vscode-pyguard/
   ├── package.json           # Extension manifest
   ├── src/
   │   ├── extension.ts      # Main entry point
   │   ├── client.ts         # LSP client
   │   └── commands.ts       # Command handlers
   ├── language-server/       # LSP server (Python)
   │   └── server.py
   ├── syntaxes/              # Syntax highlighting (optional)
   ├── icons/                 # Extension icons
   └── README.md
   ```

3. **Extension Manifest** (`package.json`)
   ```json
   {
     "name": "pyguard",
     "displayName": "PyGuard Security Scanner",
     "description": "Real-time Python security & code quality scanning",
     "version": "0.7.0",
     "publisher": "cboyd0319",
     "repository": "https://github.com/cboyd0319/PyGuard",
     "engines": {
       "vscode": "^1.80.0"
     },
     "categories": [
       "Linters",
       "Programming Languages"
     ],
     "keywords": [
       "python",
       "security",
       "linter",
       "code-quality",
       "static-analysis"
     ],
     "activationEvents": [
       "onLanguage:python"
     ],
     "main": "./out/extension.js",
     "contributes": {
       "commands": [
         {
           "command": "pyguard.scan",
           "title": "PyGuard: Scan File"
         },
         {
           "command": "pyguard.scanWorkspace",
           "title": "PyGuard: Scan Workspace"
         },
         {
           "command": "pyguard.fixAll",
           "title": "PyGuard: Fix All Auto-Fixable Issues"
         }
       ],
       "configuration": {
         "title": "PyGuard",
         "properties": {
           "pyguard.enable": {
             "type": "boolean",
             "default": true,
             "description": "Enable/disable PyGuard"
           },
           "pyguard.severity": {
             "type": "string",
             "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
             "default": "MEDIUM",
             "description": "Minimum severity to show"
           }
         }
       }
     }
   }
   ```

4. **LSP Client** (`src/client.ts`)
   ```typescript
   import * as path from 'path';
   import { workspace, ExtensionContext } from 'vscode';
   import {
     LanguageClient,
     LanguageClientOptions,
     ServerOptions,
   } from 'vscode-languageclient/node';

   let client: LanguageClient;

   export function activate(context: ExtensionContext) {
     const serverModule = context.asAbsolutePath(
       path.join('language-server', 'server.py')
     );

     const serverOptions: ServerOptions = {
       command: 'python',
       args: [serverModule]
     };

     const clientOptions: LanguageClientOptions = {
       documentSelector: [{ scheme: 'file', language: 'python' }],
       synchronize: {
         fileEvents: workspace.createFileSystemWatcher('**/.py')
       }
     };

     client = new LanguageClient(
       'pyguard',
       'PyGuard Language Server',
       serverOptions,
       clientOptions
     );

     client.start();
   }

   export function deactivate(): Thenable<void> | undefined {
     if (!client) {
       return undefined;
     }
     return client.stop();
   }
   ```

**Deliverables:**
- ✅ Extension installable locally
- ✅ LSP client connected to server
- ✅ Basic commands working

**Estimated Time:** 1 week

---

### Phase 3: Quick Fixes (Week 3-4)

**Goal:** Implement CodeActions for auto-fixes

**Tasks:**
1. **CodeAction Provider**
   ```python
   @server.feature(CODE_ACTION)
   async def code_action(ls: LanguageServer, params: CodeActionParams):
       # Get diagnostics at cursor
       diagnostics = params.context.diagnostics

       actions = []
       for diagnostic in diagnostics:
           # Get available fixes from PyGuard
           fixes = get_available_fixes(diagnostic.code)

           for fix in fixes:
               action = CodeAction(
                   title=f"PyGuard: {fix.description}",
                   kind=CodeActionKind.QuickFix,
                   diagnostics=[diagnostic],
                   edit=fix.to_workspace_edit()
               )
               actions.append(action)

       return actions
   ```

2. **Test Auto-Fixes**
   - Trigger diagnostic
   - Click lightbulb
   - Select "PyGuard: Fix..."
   - Verify code updated

**Deliverables:**
- ✅ Quick fixes appear on diagnostics
- ✅ Fixes apply correctly
- ✅ Multiple fix options when available

**Estimated Time:** 1 week

---

### Phase 4: Polish & Testing (Week 4-6)

**Goal:** Production-ready extension

**Tasks:**
1. **Configuration**
   - Settings UI integration
   - Workspace-specific config
   - `.pyguard.yml` file support

2. **UI Enhancements**
   - Status bar item (scan status)
   - Output channel (detailed logs)
   - Progress notifications

3. **Performance**
   - Debounce document changes (500ms)
   - Incremental scanning
   - Background scanning

4. **Testing**
   - Unit tests (Jest)
   - Integration tests
   - Manual testing on real projects

5. **Documentation**
   - Extension README
   - Configuration guide
   - Troubleshooting guide

6. **Marketplace Assets**
   - Extension icon (PNG, 128x128)
   - Screenshots
   - Demo GIF/video
   - Categories and keywords

**Deliverables:**
- ✅ Polished, production-ready extension
- ✅ Comprehensive documentation
- ✅ Test coverage >80%

**Estimated Time:** 2 weeks

---

### Phase 5: Publishing (Week 6)

**Goal:** Extension live on VS Code Marketplace

**Tasks:**
1. **Create Publisher**
   ```bash
   npx vsce create-publisher cboyd0319
   ```

2. **Package Extension**
   ```bash
   npx vsce package
   # Creates: pyguard-0.7.0.vsix
   ```

3. **Test VSIX Locally**
   ```bash
   code --install-extension pyguard-0.7.0.vsix
   ```

4. **Publish**
   ```bash
   npx vsce publish
   ```

5. **Verify**
   - Check marketplace: https://marketplace.visualstudio.com/items?itemName=cboyd0319.pyguard
   - Test installation: `code --install-extension cboyd0319.pyguard`

**Deliverables:**
- ✅ Extension on VS Code Marketplace
- ✅ Installation command works
- ✅ README and docs linked

**Estimated Time:** 2-3 days

---

## Technical Requirements

### Dependencies

**Python:**
- `pygls` - Language Server Protocol implementation
- `pyguard` - Core engine (already exists)

**Node.js:**
- `vscode` - VS Code extension API
- `vscode-languageclient` - LSP client
- `@types/vscode` - TypeScript types

### Development Environment

```bash
# Python
python --version  # 3.11+
pip install pygls

# Node.js
node --version  # v18+
npm install -g yo generator-code vsce

# VS Code
code --version  # 1.80+
```

---

## Feature Specifications

### MVP Features (v0.7.0)

**Must Have:**
- ✅ Real-time security scanning
- ✅ Diagnostics (squiggly lines)
- ✅ Quick fixes (lightbulb)
- ✅ Command: Scan File
- ✅ Command: Fix All
- ✅ Configuration: Enable/Disable
- ✅ Configuration: Severity threshold

### Nice to Have (v0.8.0+)

- ⚠️ Jupyter notebook support
- ⚠️ Inline documentation
- ⚠️ Rule explanations on hover
- ⚠️ Code actions for suppressions
- ⚠️ Integration with VS Code Tasks
- ⚠️ Testing integration

---

## User Experience

### Installation

```bash
# VS Code Marketplace
code --install-extension cboyd0319.pyguard

# Or via UI:
# 1. Open Extensions (Ctrl+Shift+X)
# 2. Search "PyGuard"
# 3. Click Install
```

### First Use

1. **Open Python file**
2. **Extension activates** (shows in status bar)
3. **Automatic scan** (within 1-2 seconds)
4. **Issues highlighted** (squiggly lines)
5. **Click lightbulb** → Quick Fix

**Goal:** Zero configuration, instant value

### Configuration

```jsonc
// settings.json
{
  "pyguard.enable": true,
  "pyguard.severity": "MEDIUM",
  "pyguard.scanOnSave": true,
  "pyguard.scanOnType": true,
  "pyguard.autoFixOnSave": false
}
```

---

## Success Metrics

### v0.7.0 Launch Goals

| Metric | Target |
|--------|--------|
| **Marketplace Installs** | 1,000+ |
| **Active Users (MAU)** | 500+ |
| **Rating** | 4.0+ stars |
| **Reviews** | 10+ reviews |
| **GitHub Stars** | +500 |

### Quality Metrics

- **Extension Load Time:** <2 seconds
- **Scan Latency:** <1 second for 100 LOC
- **Memory Usage:** <100 MB
- **CPU Usage:** <5% idle, <25% scanning

---

## Risks and Mitigation

### Risk 1: LSP Complexity

**Risk:** LSP protocol complex, hard to debug

**Mitigation:**
- Use `pygls` library (handles protocol)
- Test with generic LSP clients first
- Start with minimal LSP features

### Risk 2: Performance

**Risk:** Real-time scanning too slow

**Mitigation:**
- Debounce document changes (500ms)
- Incremental scanning (changed lines only)
- Background thread for scanning
- Cache scan results

### Risk 3: PyGuard as Dependency

**Risk:** Extension must bundle PyGuard

**Mitigation:**
- Bundle PyGuard with extension
- Or prompt user to install via pip
- Document both approaches

### Risk 4: Cross-Platform Issues

**Risk:** Different Python paths on Windows/Mac/Linux

**Mitigation:**
- Detect Python automatically
- Allow manual Python path configuration
- Test on all platforms

---

## Timeline and Milestones

### 6-Week Plan

| Week | Milestone | Deliverables |
|------|-----------|--------------|
| **1** | LSP Server MVP | Basic LSP server, diagnostics working |
| **2** | Extension Scaffold | Extension structure, LSP client |
| **3** | Quick Fixes | CodeActions, auto-fix integration |
| **4** | Configuration & UI | Settings, status bar, commands |
| **5** | Testing & Polish | Tests, docs, refinement |
| **6** | Publishing | Marketplace publish, launch |

### Critical Path

- **Week 1-2:** LSP Server (BLOCKING)
- **Week 2-3:** Extension Integration (BLOCKING)
- **Week 3-4:** Quick Fixes (HIGH)
- **Week 4-6:** Polish (MEDIUM)

---

## Resources

### Documentation

- **LSP Spec:** https://microsoft.github.io/language-server-protocol/
- **pygls:** https://pygls.readthedocs.io/
- **VS Code Extension API:** https://code.visualstudio.com/api
- **VS Code LSP Guide:** https://code.visualstudio.com/api/language-extensions/language-server-extension-guide

### Examples

- **Python LSP Example:** https://github.com/microsoft/vscode-extension-samples/tree/main/lsp-sample
- **pylint Extension:** https://github.com/microsoft/vscode-pylint
- **Ruff Extension:** https://github.com/astral-sh/ruff-vscode

### Tools

- **Yeoman Generator:** `yo code`
- **VSCE:** `vsce package`, `vsce publish`
- **LSP Inspector:** VS Code extension for debugging LSP

---

## Next Steps

1. **Allocate Developer** - Assign dedicated developer for 6 weeks
2. **Set Up Dev Environment** - Install tools, clone repos
3. **Week 1 Kickoff** - Start LSP server implementation
4. **Weekly Check-ins** - Review progress, unblock issues
5. **Week 6 Launch** - Publish to marketplace, announce!

---

**Status:** Plan complete, ready for implementation
**Blocker Status:** CRITICAL - v0.7.0 cannot release without this
**Recommendation:** START IMMEDIATELY
**Owner:** TBD (needs developer assignment)
**Last Updated:** 2025-11-14
