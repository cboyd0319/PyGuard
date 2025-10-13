# Getting Started with PyGuard

**TL;DR:** PyGuard finds security vulnerabilities and code quality issues in Python projects. Install with `pip install pyguard`, run `pyguard scan .` to check your code. Auto-fixes available with `--fix` flag.

**Quick start:**
```bash
pip install pyguard
cd your-project/
pyguard scan .
```

---

## What is PyGuard?

PyGuard is a Python security and code quality analyzer that detects 55+ vulnerability types and automatically fixes many of them. It runs locally (no data leaves your machine) and integrates with CI/CD pipelines.

### What It Detects
- **Security:** SQL injection, hardcoded secrets, insecure deserialization, path traversal, command injection, XXE, SSRF, and 40+ more CWE patterns
- **Code quality:** Naming violations, missing docstrings, complexity issues, type hint problems
- **Compliance:** OWASP Top 10, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA

### Key Features
| Feature | Description |
|---------|-------------|
| **Auto-fix** | Automatically fixes 70%+ of detected issues with backup/rollback |
| **ML-powered** | Machine learning risk scoring and anomaly detection |
| **Zero telemetry** | All analysis happens locally, no data sent anywhere |
| **Multi-framework** | 10+ compliance frameworks (OWASP, PCI-DSS, HIPAA, etc.) |
| **Reports** | HTML, JSON, and console output with severity filtering |

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.8+ | Recommend 3.13 for development |
| pip | Latest | Comes with Python |
| OS | Windows/macOS/Linux | Universal support |
| Disk space | ~50MB | For package + dependencies |

**Check your Python version:**
```bash
python --version
# Should show: Python 3.8.0 or higher
```

**If Python not installed:**
- Windows: https://python.org/downloads (check "Add Python to PATH")
- macOS: `brew install python3`
- Linux: `sudo apt install python3 python3-pip` (Ubuntu/Debian)

---

## Installation

### Option 1: pip (Recommended)

```bash
pip install pyguard
```

**Verify installation:**
```bash
pyguard --version
# Output: PyGuard v0.8.0 (or newer)
```

### Option 2: From Source (Development)

```bash
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e ".[dev]"  # Editable install with dev dependencies
```

### Option 3: Docker

```bash
docker pull cboyd0319/pyguard:latest
docker run --rm -v $(pwd):/app pyguard scan /app
```

---

## Your First Scan

### Create a Test File

Create `test.py` with intentionally vulnerable code:

```python
# test.py - DO NOT use this pattern in real code!
import pickle
import os

def load_data(filename):
    # VULNERABILITY: Insecure deserialization
    with open(filename, 'rb') as f:
        data = pickle.load(f)  # PyGuard will flag this
    return data

def run_command(user_input):
    # VULNERABILITY: Command injection
    os.system(f"echo {user_input}")  # PyGuard will flag this

# VULNERABILITY: Hardcoded secret
API_KEY = "sk-1234567890abcdef"  # PyGuard will flag this
```

### Run Your First Scan

```bash
pyguard scan test.py
```

**Expected output:**
```
PyGuard v0.8.0 - Python Security & Quality Analysis

Scanning: test.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

Found 3 issues:

┌─────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL: Insecure Deserialization (CWE-502)        │
├─────────────────────────────────────────────────────────┤
│ File: test.py:8                                         │
│ Code: data = pickle.load(f)                             │
│ Risk: Arbitrary code execution via malicious pickle    │
│ Fix:  Use json.load() or validate pickle source        │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL: Command Injection (CWE-78)                 │
├─────────────────────────────────────────────────────────┤
│ File: test.py:13                                        │
│ Code: os.system(f"echo {user_input}")                   │
│ Risk: Arbitrary command execution                       │
│ Fix:  Use subprocess.run() with shell=False             │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 🟡 HIGH: Hardcoded Secret (CWE-798)                     │
├─────────────────────────────────────────────────────────┤
│ File: test.py:16                                        │
│ Code: API_KEY = "sk-1234567890abcdef"                   │
│ Risk: Exposed credentials in source code               │
│ Fix:  Move to environment variable or secrets manager  │
└─────────────────────────────────────────────────────────┘

Summary:
  3 issues found (2 critical, 1 high, 0 medium, 0 low)
  Scan completed in 0.34s
```

### Auto-Fix Issues

```bash
pyguard scan test.py --fix
```

PyGuard will:
1. Create backup (`test.py.bak`)
2. Fix issues automatically where possible
3. Show what was fixed
4. Leave comments for manual fixes

**Fixed code example:**
```python
# test.py - Fixed by PyGuard
import json  # Changed from pickle
import subprocess  # Changed from os.system
import os

def load_data(filename):
    # Fixed: Using JSON instead of pickle
    with open(filename, 'r') as f:
        data = json.load(f)
    return data

def run_command(user_input):
    # Fixed: Using subprocess with shell=False
    subprocess.run(["echo", user_input], shell=False, check=True)

# Fixed: Load from environment
API_KEY = os.environ.get("API_KEY")  # PyGuard: Moved secret to env var
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")
```

---

## Common Use Cases

### Scan Entire Project

```bash
# Scan current directory and subdirectories
pyguard scan .

# Scan specific directory
pyguard scan /path/to/project

# Exclude directories
pyguard scan . --exclude tests,venv,.tox
```

### Generate Reports

```bash
# HTML report (opens in browser)
pyguard scan . --format html --output report.html

# JSON report (for CI/CD integration)
pyguard scan . --format json --output results.json

# Console output (default)
pyguard scan .
```

### Filter by Severity

```bash
# Show only critical issues
pyguard scan . --severity critical

# Show critical and high
pyguard scan . --severity high

# Show all (default)
pyguard scan .
```

### Check Compliance

```bash
# OWASP Top 10
pyguard scan . --compliance owasp

# PCI-DSS
pyguard scan . --compliance pci-dss

# Multiple frameworks
pyguard scan . --compliance owasp,hipaa,gdpr
```

### CI/CD Integration

**GitHub Actions:**
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  pyguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install pyguard
      - run: pyguard scan . --format json --output results.json
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: results.json
```

**Exit codes:**
- `0` — No issues found
- `1` — Issues found (blocks CI if set)
- `2` — Scan error

---

## Understanding Results

### Severity Levels

| Level | Icon | Meaning | Example |
|-------|------|---------|---------|
| **Critical** | 🔴 | Exploitable vulnerability | SQL injection, RCE |
| **High** | 🟡 | Serious security risk | Hardcoded secrets, XXE |
| **Medium** | 🟠 | Potential vulnerability | Weak crypto, TOCTOU |
| **Low** | 🔵 | Code quality issue | Naming, docstrings |

### CWE References

PyGuard maps issues to Common Weakness Enumeration (CWE) IDs:
- **CWE-89:** SQL Injection
- **CWE-78:** Command Injection
- **CWE-798:** Hardcoded Credentials
- **CWE-502:** Deserialization of Untrusted Data
- See full list: https://cwe.mitre.org/

### ML Risk Scoring

PyGuard uses machine learning to score vulnerability risk:
- **Context analysis:** Function usage patterns
- **Data flow:** Taint tracking from user input
- **Historical patterns:** Known vulnerability signatures
- **Anomaly detection:** Unusual code patterns

---

## Configuration

### Config File: `pyguard.toml`

Create in project root:

```toml
[scan]
exclude = ["tests/", "venv/", ".tox/", "build/"]
severity = "medium"  # Minimum severity to report
max_line_length = 100

[auto-fix]
enabled = true
create_backups = true
backup_dir = ".pyguard_backups/"

[compliance]
frameworks = ["owasp", "pci-dss"]

[output]
format = "console"  # Options: console, json, html
verbose = false
```

### Environment Variables

```bash
# Disable color output
export PYGUARD_NO_COLOR=1

# Custom config file
export PYGUARD_CONFIG=/path/to/pyguard.toml

# Cache directory
export PYGUARD_CACHE_DIR=/tmp/pyguard_cache
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'pyguard'"

**Cause:** PyGuard not installed or wrong Python environment

**Fix:**
```bash
# Check if installed
pip list | grep pyguard

# Install if missing
pip install pyguard

# Verify Python environment
which python
which pip
```

### Scan Running Slow

**Cause:** Large project or many files

**Solutions:**
```bash
# Exclude unnecessary directories
pyguard scan . --exclude tests,venv,node_modules

# Use cache (speeds up subsequent scans)
pyguard scan . --cache

# Scan specific files only
pyguard scan src/
```

### False Positives

**Cause:** PyGuard flagging legitimate code

**Solutions:**
```bash
# Inline ignore comment
password = get_from_secure_vault()  # pyguard: ignore[hardcoded-secret]

# Config file ignore
[ignore]
rules = ["CWE-798"]  # Ignore hardcoded secrets (use cautiously!)

# File-level ignore
# pyguard: skip-file
```

### Auto-Fix Not Working

**Cause:** Complex fixes require manual intervention

**Check:**
```bash
# Verify backup was created
ls -la *.bak

# Review PyGuard comments in code
grep -r "PyGuard:" .

# Check what can't be auto-fixed
pyguard scan . --fix --verbose
```

---

## Next Steps

### Learn More
- **[User Guide](user-guide.md)** — Comprehensive feature documentation
- **[Configuration](configuration.md)** — All config options explained
- **[Security Rules](security-rules.md)** — Complete vulnerability catalog
- **[Best Practices](best-practices.md)** — Production deployment patterns
- **[API Reference](api-reference.md)** — Programmatic usage

### Advanced Features
- **[ML Detection](ML-DETECTION.md)** — Machine learning capabilities
- **[AST Analysis](ast-analysis.md)** — Abstract Syntax Tree analysis
- **[Compliance](COMPLIANCE.md)** — Multi-framework compliance
- **[Supply Chain Security](SUPPLY-CHAIN-SECURITY.md)** — Dependency scanning

### Get Help
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** — Common issues and solutions
- **[GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)** — Report bugs or request features
- **[Contributing](../CONTRIBUTING.md)** — Help improve PyGuard

---

## Quick Reference

| Task | Command |
|------|---------|
| Install | `pip install pyguard` |
| First scan | `pyguard scan .` |
| Auto-fix | `pyguard scan . --fix` |
| HTML report | `pyguard scan . --format html --output report.html` |
| Critical only | `pyguard scan . --severity critical` |
| OWASP check | `pyguard scan . --compliance owasp` |
| Exclude dirs | `pyguard scan . --exclude tests,venv` |
| Config file | Create `pyguard.toml` in project root |
| Help | `pyguard --help` |
| Version | `pyguard --version` |

---

**Ready to secure your Python code?** Run your first scan now!
