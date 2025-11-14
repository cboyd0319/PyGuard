# PyGuard for VS Code

Real-time Python security & code quality scanning directly in your editor.

![PyGuard Logo](https://raw.githubusercontent.com/cboyd0319/PyGuard/main/docs/images/logo.png)

## Features

### 🛡️ Real-Time Security Scanning

- **1,230+ Security Checks** - Most comprehensive Python security coverage
- **25 Framework Integrations** - Django, Flask, FastAPI, TensorFlow, PyTorch, and more
- **Scan as You Type** - Catch issues before they reach your codebase
- **Zero Configuration** - Works out of the box

### ⚡ Auto-Fix Everything

- **199+ Auto-Fixes** - One-click fixes for common security issues
- **Smart Fixes** - Context-aware fixes that preserve your code's intent
- **Safe Mode** - Preview changes before applying

### 📊 Comprehensive Coverage

- SQL Injection, XSS, Command Injection
- Insecure Deserialization (pickle, yaml)
- Hardcoded Credentials & Secrets
- Cryptography Issues
- Path Traversal
- And 1,200+ more checks

## Installation

### Prerequisites

1. **VS Code 1.80+**
2. **Python 3.11+**
3. **PyGuard installed:**
   ```bash
   pip install pyguard
   ```

### Install Extension

#### From VS Code Marketplace (Recommended)

1. Open VS Code
2. Press `Ctrl+Shift+X` (or `Cmd+Shift+X` on Mac)
3. Search for "PyGuard"
4. Click Install

#### From VSIX File

```bash
code --install-extension pyguard-0.7.0.vsix
```

#### From Source

```bash
git clone https://github.com/cboyd0319/PyGuard
cd PyGuard/vscode-pyguard
npm install
npm run compile
code --install-extension .
```

## Quick Start

1. **Open a Python file** - Extension activates automatically
2. **See issues highlighted** - Squiggly lines appear under security issues
3. **Click lightbulb** 💡 - Apply quick fixes
4. **Check Problems panel** - View all issues

## Usage

### Commands

Access via Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

- **PyGuard: Scan File** - Scan current file
- **PyGuard: Scan Workspace** - Scan all Python files
- **PyGuard: Fix All** - Apply all auto-fixes
- **PyGuard: Show Output** - View detailed logs

### Keyboard Shortcuts

- `Ctrl+Shift+P` (Mac: `Cmd+Shift+P`) - Scan current file

### Status Bar

- Shows PyGuard status
- Click to view output

## Configuration

### Settings

Open Settings (`Ctrl+,` / `Cmd+,`) and search for "PyGuard":

```jsonc
{
  // Enable/disable PyGuard
  "pyguard.enable": true,

  // Minimum severity to display (LOW, MEDIUM, HIGH, CRITICAL)
  "pyguard.severity": "MEDIUM",

  // Scan as you type (debounced)
  "pyguard.scanOnType": true,

  // Scan on file save
  "pyguard.scanOnSave": true,

  // Auto-fix on save (use with caution)
  "pyguard.autoFixOnSave": false,

  // Python executable path
  "pyguard.pythonPath": "python",

  // Custom LSP server path (optional)
  "pyguard.lspServerPath": "",

  // Files to exclude
  "pyguard.excludePatterns": [
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.venv/**"
  ],

  // Configuration file
  "pyguard.configFile": ".pyguard.yml",

  // Trace LSP communication (for debugging)
  "pyguard.trace.server": "off"
}
```

### Workspace Configuration

Create `.vscode/settings.json` in your project:

```json
{
  "pyguard.enable": true,
  "pyguard.severity": "HIGH",
  "pyguard.configFile": "config/pyguard.yml"
}
```

### PyGuard Configuration

Create `.pyguard.yml` in project root:

```yaml
severity: MEDIUM
exclude:
  - tests/
  - **/*_test.py
frameworks:
  - django
  - flask
auto_fix: safe  # safe, unsafe, or off
```

## Examples

### SQL Injection Detection

```python
# ❌ PyGuard detects this vulnerability
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # 🚨 SQL Injection
    return db.execute(query)
```

**Quick Fix:**
```python
# ✅ PyGuard fixes it
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
```

### Hardcoded Credentials

```python
# ❌ Security issue detected
API_KEY = "hardcoded_secret_123"  # 🚨 Hardcoded credentials
```

**Quick Fix:**
```python
# ✅ Use environment variables
import os
API_KEY = os.environ.get("API_KEY")
```

### Insecure Deserialization

```python
# ❌ Dangerous pattern detected
import pickle
data = pickle.load(open('data.pkl', 'rb'))  # 🚨 Unsafe deserialization
```

**Quick Fix:**
```python
# ✅ Use safe alternatives
import json
data = json.load(open('data.json', 'r'))
```

## Framework Support

PyGuard provides specialized security checks for 25+ frameworks:

### Web Frameworks
- Django - 25+ checks
- Flask - 20+ checks
- FastAPI - 37+ checks
- Tornado - 15+ checks
- Sanic - 15+ checks

### Data Science
- NumPy - 10+ checks
- Pandas - 15+ checks
- Scikit-learn - 20+ checks

### Machine Learning
- TensorFlow - 50+ checks
- PyTorch - 45+ checks
- Keras - 30+ checks

### And Many More!
- SQLAlchemy, Celery, Requests, BeautifulSoup, Selenium, and more...

## Troubleshooting

### Extension Not Working

1. **Check Python installation:**
   ```bash
   python --version  # Should be 3.11+
   ```

2. **Verify PyGuard is installed:**
   ```bash
   pip show pyguard
   pyguard --version
   ```

3. **Check Output panel:**
   - View → Output
   - Select "PyGuard" from dropdown
   - Look for error messages

4. **Restart VS Code:**
   - Close and reopen VS Code
   - Extension should reinitialize

### No Diagnostics Showing

1. **Check file is Python:**
   - File extension: `.py`
   - Language mode: Python (bottom right)

2. **Check severity threshold:**
   - Settings → PyGuard → Severity
   - Try setting to "LOW" to see all issues

3. **Save the file:**
   - PyGuard scans on save
   - Press `Ctrl+S` / `Cmd+S`

### LSP Server Not Starting

1. **Check Python path:**
   - Settings → PyGuard → Python Path
   - Use full path if needed: `/usr/bin/python3`

2. **Reinstall PyGuard:**
   ```bash
   pip uninstall pyguard
   pip install pyguard
   ```

3. **Check logs:**
   - View → Output → PyGuard
   - Look for "LSP server started" message

### Performance Issues

1. **Disable scan on type:**
   ```json
   {
     "pyguard.scanOnType": false,
     "pyguard.scanOnSave": true
   }
   ```

2. **Exclude large directories:**
   ```json
   {
     "pyguard.excludePatterns": [
       "**/node_modules/**",
       "**/venv/**",
       "**/build/**"
     ]
   }
   ```

3. **Increase severity threshold:**
   ```json
   {
     "pyguard.severity": "HIGH"
   }
   ```

## Requirements

- **VS Code:** 1.80 or higher
- **Python:** 3.11 or higher
- **PyGuard:** Latest version (`pip install pyguard`)
- **OS:** Windows, macOS, Linux

## Known Limitations

- **Workspace scanning:** Currently scans files individually (workspace-wide coming soon)
- **Jupyter notebooks:** Support coming in v0.8.0
- **Auto-fix:** Some complex fixes require manual intervention

## Roadmap

### v0.7.0 (Current)
- ✅ Real-time diagnostics
- ✅ Quick fixes (lightbulb)
- ✅ Command palette integration
- ⚠️ Basic configuration support

### v0.8.0 (Next)
- Jupyter notebook support
- Workspace-wide scanning
- Rule explanations on hover
- Code actions for suppressions
- Testing integration

### v1.0.0 (Future)
- Inline documentation
- Custom rule creation
- Team sharing of configurations
- Performance profiling

## Contributing

We welcome contributions! See [CONTRIBUTING.md](https://github.com/cboyd0319/PyGuard/blob/main/CONTRIBUTING.md).

### Development Setup

```bash
# Clone repository
git clone https://github.com/cboyd0319/PyGuard
cd PyGuard/vscode-pyguard

# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Open in VS Code
code .

# Press F5 to launch Extension Development Host
```

## Support

- **Issues:** [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Discussions:** [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- **Documentation:** [PyGuard Docs](https://github.com/cboyd0319/PyGuard/tree/main/docs)

## License

MIT License - see [LICENSE](https://github.com/cboyd0319/PyGuard/blob/main/LICENSE)

## Credits

Created by [Chad Boyd](https://github.com/cboyd0319)

## Privacy

PyGuard runs **100% locally**. No data is sent to external servers. All scanning happens on your machine.

## More Information

- **GitHub:** https://github.com/cboyd0319/PyGuard
- **PyPI:** https://pypi.org/project/pyguard/
- **Documentation:** https://github.com/cboyd0319/PyGuard/tree/main/docs

---

**Enjoy secure Python coding with PyGuard!** 🛡️
