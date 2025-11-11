# PyGuard Quick Start Guide

**Get started with PyGuard in 2 minutes!** 🚀

PyGuard finds and fixes security vulnerabilities, code quality issues, and formatting problems in your Python code automatically.

---

## Installation

### Option 1: Install from GitHub (Current)
```bash
pip install git+https://github.com/cboyd0319/PyGuard.git
```

### Option 2: Clone and Install (Development)
```bash
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .
```

---

## Your First Scan (30 seconds)

### Step 1: Create a test file
```bash
cat > test.py << 'EOF'
import os

password = "hardcoded123"
eval("print('test')")

def get_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return query
EOF
```

### Step 2: Run PyGuard
```bash
pyguard test.py --scan-only
```

**That's it!** PyGuard will show you all security issues found.

### Step 3: Auto-fix issues
```bash
pyguard test.py
```

PyGuard will automatically fix safe issues and create backups of your files.

---

## Common Use Cases

### 1. Scan a Single File
```bash
pyguard myfile.py --scan-only
```

### 2. Scan and Fix a Directory
```bash
pyguard src/
```

### 3. Security-Only Scan
```bash
pyguard . --security-only --scan-only
```

### 4. Generate SARIF Report for GitHub
```bash
pyguard . --sarif
```

### 5. Watch Mode (Auto-scan on file changes)
```bash
pyguard src/ --watch
```

### 6. Fast Scan with RipGrep (Large codebases)
```bash
pyguard . --fast
```

---

## Understanding Output

PyGuard shows issues in three severity levels:

- 🔴 **HIGH (Security)** - Fix immediately! (SQL injection, hardcoded secrets, etc.)
- 🟡 **MEDIUM (Quality)** - Improve code quality (naming, complexity, etc.)
- 🟢 **LOW (Style)** - Formatting and style issues

---

## Command Reference

### Basic Options
```bash
pyguard <path>              # Scan and fix
pyguard <path> --scan-only  # Scan only, no fixes
pyguard <path> --no-backup  # Don't create backups
```

### Targeted Scans
```bash
pyguard <path> --security-only         # Security issues only
pyguard <path> --best-practices-only   # Code quality only
pyguard <path> --formatting-only       # Formatting only
```

### Reports
```bash
pyguard <path> --sarif                 # SARIF report for GitHub
pyguard <path> --compliance-html out.html  # HTML compliance report
pyguard <path> --compliance-json out.json  # JSON compliance report
```

### Advanced
```bash
pyguard <path> --unsafe-fixes          # Apply unsafe fixes (review carefully!)
pyguard <path> --parallel              # Parallel processing
pyguard <path> --fast                  # Fast mode with ripgrep
pyguard <path> --watch                 # Watch mode
```

---

## Configuration (Optional)

Create `.pyguard.toml` in your project root:

```toml
[general]
log_level = "INFO"
backup_dir = ".pyguard_backups"

[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM", "LOW"]

[security.checks]
hardcoded_passwords = true
sql_injection = true
command_injection = true
eval_exec_usage = true

[best_practices]
check_docstrings = true
check_naming_conventions = true
max_complexity = 10

[formatting]
line_length = 100
use_black = true
use_isort = true
```

---

## GitHub Actions Integration

Add to `.github/workflows/pyguard.yml`:

```yaml
name: PyGuard Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install PyGuard
        run: pip install git+https://github.com/cboyd0319/PyGuard.git

      - name: Run PyGuard
        run: pyguard . --sarif --scan-only

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: pyguard-results.sarif
```

---

## Pre-commit Hook (Auto-scan on commit)

### Install hook:
```bash
pyguard-hooks install
```

### Or manually create `.git/hooks/pre-commit`:
```bash
#!/bin/bash
pyguard . --scan-only --security-only
if [ $? -ne 0 ]; then
    echo "❌ Security issues found! Fix them before committing."
    exit 1
fi
```

---

## Programmatic API

Use PyGuard in your Python code:

```python
from pyguard import PyGuardAPI

# Initialize
api = PyGuardAPI()

# Scan a file
result = api.analyze_file("myfile.py")

# Check for security issues
if result.has_security_issues:
    for issue in result.security_issues:
        print(f"{issue.severity}: {issue.message}")

# Apply fixes
fixed_count = api.fix_file("myfile.py", unsafe=False)
print(f"Fixed {fixed_count} issues")
```

---

## Examples

The `examples/` directory contains:

- `basic_usage.py` - Simple API usage
- `api_usage.py` - Advanced API usage
- `advanced_usage.py` - Complex scenarios
- `sample_code.py` - Sample code with issues to test against
- `plugins/` - Custom plugin examples

Try them:
```bash
cd examples/
python basic_usage.py
python api_usage.py
```

---

## Troubleshooting

### "Command not found: pyguard"
```bash
# Make sure PyGuard is installed
pip install -e .

# Or use python -m
python -m pyguard.cli <path>
```

### "No issues found" but I see problems
```bash
# Try scanning with all checks enabled
pyguard <path> --scan-only

# Check specific frameworks
pyguard <path> --scan-only  # Auto-detects frameworks
```

### Large codebase is slow
```bash
# Use fast mode with ripgrep
pyguard . --fast

# Or use parallel processing
pyguard . --parallel
```

### False positives
```bash
# Suppress specific issues with comments
# pyguard: disable=S101  (disable rule S101)

# Or create .pyguardignore
echo "tests/*" >> .pyguardignore
echo "*.pyi" >> .pyguardignore
```

---

## What PyGuard Checks

### Security (1,230+ checks)
- SQL/NoSQL/Command/Template injection
- Hardcoded secrets and credentials
- Insecure cryptography
- Unsafe deserialization
- XSS vulnerabilities
- Path traversal
- Insecure random number generation
- Weak authentication/authorization
- **510 AI/ML-specific security checks**

### Frameworks (25 frameworks)
- **Web:** Django, Flask, FastAPI, Pyramid, Sanic, Quart, Bottle, Tornado
- **Data:** Pandas, NumPy, SciPy, TensorFlow, scikit-learn
- **Big Data:** PySpark, Airflow
- **UI:** Streamlit, Gradio, Dash
- **Database:** SQLAlchemy, Peewee, Tortoise, Pony
- **Other:** Celery, asyncio

### Code Quality
- PEP 8 compliance
- Naming conventions
- Code complexity
- Best practices
- Type hints
- Docstrings
- Dead code detection

---

## Next Steps

1. ✅ **You're ready!** Start scanning your code
2. 📖 Read the full [README.md](README.md) for advanced features
3. 🔌 Check out [Plugin Architecture](docs/guides/PLUGIN_ARCHITECTURE.md) to create custom rules
4. 🛡️ Review [Security Documentation](docs/security/) for supply chain security
5. 🚀 Set up [GitHub Actions](docs/guides/github-action-guide.md) for automated scanning

---

## Get Help

- 📖 **Documentation:** [docs/](docs/)
- 🐛 **Issues:** https://github.com/cboyd0319/PyGuard/issues
- 💬 **Discussions:** https://github.com/cboyd0319/PyGuard/discussions
- 📧 **Security:** See [SECURITY.md](SECURITY.md)

---

## Quick Reference Card

```bash
# Most common commands
pyguard <file>                    # Scan and fix
pyguard <dir> --scan-only         # Scan only
pyguard . --security-only         # Security scan
pyguard . --sarif                 # GitHub integration
pyguard . --watch                 # Watch mode
pyguard --help                    # Show all options

# Tips
# 1. Always use --scan-only first to preview issues
# 2. Backups are created automatically (in .pyguard_backups/)
# 3. Use --unsafe-fixes carefully and review changes
# 4. Set up pre-commit hooks for team enforcement
```

---

**That's it! You're ready to make your Python code more secure! 🛡️**

For questions or issues, check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or open a GitHub issue.
