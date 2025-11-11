# PyGuard Troubleshooting Guide

This guide helps you solve common issues when using PyGuard.

---

## Table of Contents

- [Installation Issues](#installation-issues)
- [Command Not Found](#command-not-found)
- [Import Errors](#import-errors)
- [Permission Errors](#permission-errors)
- [Performance Issues](#performance-issues)
- [False Positives](#false-positives)
- [Output/Reporting Issues](#outputreporting-issues)
- [Integration Issues](#integration-issues)
- [Advanced Debugging](#advanced-debugging)

---

## Installation Issues

### Issue: `pip install` fails with dependency conflicts

**Solution 1:** Use a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install git+https://github.com/cboyd0319/PyGuard.git
```

**Solution 2:** Force reinstall dependencies
```bash
pip install --force-reinstall git+https://github.com/cboyd0319/PyGuard.git
```

**Solution 3:** Install with exact versions
```bash
pip install -e . --use-deprecated=legacy-resolver
```

### Issue: `packaging` conflict on Debian/Ubuntu

**Error:** `ERROR: Cannot uninstall packaging 24.0, RECORD file not found`

**Solution:**
```bash
pip install -e . --ignore-installed packaging
```

### Issue: Missing development dependencies

**Error:** `pytest` or other test tools not found

**Solution:**
```bash
pip install -e ".[dev]"  # Install with development dependencies
```

---

## Command Not Found

### Issue: `pyguard: command not found`

**Solution 1:** Verify installation
```bash
pip list | grep pyguard
# Should show: pyguard 0.6.0 (or current version)
```

**Solution 2:** Use Python module syntax
```bash
python -m pyguard.cli --help
```

**Solution 3:** Check PATH
```bash
# Find where pip installs scripts
python -m site --user-base

# Add to PATH (Linux/Mac)
export PATH="$PATH:$(python -m site --user-base)/bin"

# Add to PATH (Windows)
set PATH=%PATH%;%APPDATA%\Python\Scripts
```

**Solution 4:** Reinstall in editable mode
```bash
cd /path/to/PyGuard
pip install -e .
```

---

## Import Errors

### Issue: `ModuleNotFoundError: No module named 'pyguard'`

**Solution 1:** Verify installation
```bash
python -c "import pyguard; print(pyguard.__version__)"
# Should print: 0.6.0
```

**Solution 2:** Check Python version
```bash
python --version
# Should be Python 3.11 or higher
```

**Solution 3:** Install from correct directory
```bash
# If you cloned the repo
cd PyGuard
pip install -e .
```

### Issue: `ImportError: cannot import name 'X' from 'pyguard'`

**Solution:** Reinstall clean
```bash
pip uninstall pyguard
pip install git+https://github.com/cboyd0319/PyGuard.git
```

---

## Permission Errors

### Issue: `PermissionError: [Errno 13] Permission denied`

**Solution 1:** Don't use sudo (preferred)
```bash
pip install --user git+https://github.com/cboyd0319/PyGuard.git
```

**Solution 2:** Use virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate
pip install git+https://github.com/cboyd0319/PyGuard.git
```

**Solution 3:** Fix ownership (if necessary)
```bash
sudo chown -R $USER:$USER ~/.local/lib/python*/site-packages/pyguard*
```

### Issue: `PermissionError` when scanning files

**Solution 1:** Check file permissions
```bash
ls -la <file>
chmod 644 <file>  # Make readable
```

**Solution 2:** Run with appropriate user
```bash
# Don't run as root unless necessary
# PyGuard respects file permissions
```

---

## Performance Issues

### Issue: Scanning is too slow on large codebases

**Solution 1:** Use fast mode with RipGrep
```bash
# Install ripgrep first
# Mac: brew install ripgrep
# Linux: apt install ripgrep
# Windows: choco install ripgrep

pyguard . --fast
```

**Solution 2:** Enable parallel processing
```bash
pyguard . --parallel
```

**Solution 3:** Exclude unnecessary directories
```bash
pyguard . --exclude venv node_modules .git build dist
```

**Solution 4:** Scan incrementally with git diff
```bash
# Only scan changed files
pyguard . --diff HEAD~1

# Only scan staged files
pyguard . --diff staged
```

**Solution 5:** Use .pyguardignore
```bash
cat > .pyguardignore << 'EOF'
venv/
.venv/
node_modules/
__pycache__/
*.pyc
.git/
build/
dist/
*.egg-info/
.tox/
.coverage
htmlcov/
EOF
```

### Issue: High memory usage

**Solution 1:** Process files sequentially (disable parallel)
```bash
pyguard . --no-parallel  # If this option exists
# Or just run normally without --parallel
```

**Solution 2:** Scan in batches
```bash
# Scan by directory
pyguard src/
pyguard tests/
pyguard scripts/
```

---

## False Positives

### Issue: PyGuard reports issues that aren't actually problems

**Solution 1:** Suppress specific rules inline
```python
# Suppress single rule
password = "test_password"  # pyguard: disable=S105

# Suppress multiple rules
eval(user_input)  # pyguard: disable=S307,S102

# Suppress for entire file (top of file)
# pyguard: disable-file
```

**Solution 2:** Configure rules in `.pyguard.toml`
```toml
[security.checks]
hardcoded_passwords = false  # Disable specific check

[best_practices]
check_docstrings = false  # Disable docstring requirement
```

**Solution 3:** Use .pyguardignore for files
```bash
# Ignore test files
echo "tests/*" >> .pyguardignore

# Ignore generated code
echo "generated/*" >> .pyguardignore

# Ignore type stubs
echo "*.pyi" >> .pyguardignore
```

**Solution 4:** Report false positive
If it's a genuine false positive, please report it:
https://github.com/cboyd0319/PyGuard/issues

### Issue: Missing real security issues

**Solution:** Ensure all checks are enabled
```bash
# Run with maximum detection
pyguard . --scan-only --security-only

# Check configuration
cat .pyguard.toml  # Ensure checks aren't disabled
```

---

## Output/Reporting Issues

### Issue: No HTML report generated

**Solution 1:** Check command
```bash
# HTML is generated by default unless disabled
pyguard . --scan-only

# Explicitly enable HTML
pyguard .  # (--no-html NOT specified)
```

**Solution 2:** Check output directory
```bash
ls -la pyguard-results.html
ls -la reports/  # Check reports directory
```

**Solution 3:** Check permissions
```bash
# Ensure you can write to current directory
touch test.txt && rm test.txt
```

### Issue: SARIF upload fails on GitHub

**Solution 1:** Verify SARIF format
```bash
pyguard . --sarif

# Check file was created
ls -la pyguard-results.sarif

# Validate SARIF format
cat pyguard-results.sarif | jq .
```

**Solution 2:** Check GitHub Actions workflow
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: pyguard-results.sarif  # Correct file name
  if: always()  # Upload even if scan finds issues
```

**Solution 3:** Verify GitHub Advanced Security is enabled
- Go to repo Settings → Security & analysis
- Enable "Code scanning"

### Issue: Colors/formatting broken in terminal

**Solution 1:** Check terminal support
```bash
# Test color support
python -c "from rich.console import Console; Console().print('[red]Test[/red]')"
```

**Solution 2:** Disable colors if needed
```bash
export NO_COLOR=1
pyguard .
```

**Solution 3:** Update Rich library
```bash
pip install --upgrade rich
```

---

## Integration Issues

### Issue: Pre-commit hook fails

**Solution 1:** Verify hook installation
```bash
cat .git/hooks/pre-commit
# Should contain pyguard command
```

**Solution 2:** Make hook executable
```bash
chmod +x .git/hooks/pre-commit
```

**Solution 3:** Test hook manually
```bash
.git/hooks/pre-commit
echo $?  # Should be 0 for success
```

**Solution 4:** Reinstall hook
```bash
pyguard-hooks install --force
```

### Issue: GitHub Action fails

**Solution 1:** Check Python version in workflow
```yaml
- uses: actions/setup-python@v4
  with:
    python-version: '3.11'  # Must be 3.11+
```

**Solution 2:** Check PyGuard installation
```yaml
- name: Install PyGuard
  run: |
    pip install git+https://github.com/cboyd0319/PyGuard.git
    pyguard --version  # Verify installation
```

**Solution 3:** Check for path issues
```yaml
- name: Run PyGuard
  run: |
    python -m pyguard.cli . --sarif --scan-only
```

### Issue: CI/CD pipeline timeout

**Solution:** Use fast mode and exclusions
```yaml
- name: Run PyGuard
  run: |
    pyguard . --fast --scan-only \
      --exclude venv node_modules .git
  timeout-minutes: 10
```

---

## Advanced Debugging

### Enable Debug Logging

Create `.pyguard.toml`:
```toml
[general]
log_level = "DEBUG"
log_file = "pyguard-debug.log"
```

Then run:
```bash
pyguard . --scan-only
cat pyguard-debug.log
```

### Verbose Output

```bash
pyguard . --scan-only -v
# or
python -m pyguard.cli . --scan-only -v
```

### Check Rule Registration

```python
from pyguard import DEBUGGING_RULES, XSS_RULES
print(f"Debugging rules: {len(DEBUGGING_RULES)}")
print(f"XSS rules: {len(XSS_RULES)}")
```

### Test Individual Modules

```python
from pyguard.lib.security import SecurityChecker
from pathlib import Path

checker = SecurityChecker()
violations = checker.check_file(Path("test.py"))
for v in violations:
    print(f"{v.rule_id}: {v.message}")
```

### Check Dependencies

```bash
pip list | grep -E "pylint|flake8|black|isort|mypy|bandit|ruff"
```

### Verify File Detection

```bash
# Check what files PyGuard will scan
find . -name "*.py" | grep -v ".venv" | grep -v "node_modules"
```

---

## Common Error Messages

### `SyntaxError: invalid syntax`

**Cause:** File has Python syntax errors

**Solution:** Fix syntax errors first
```bash
python -m py_compile yourfile.py
```

### `RecursionError: maximum recursion depth exceeded`

**Cause:** Circular imports or very deep nesting

**Solution:** Simplify code structure or increase recursion limit
```python
import sys
sys.setrecursionlimit(2000)  # Temporary workaround
```

### `UnicodeDecodeError`

**Cause:** File encoding issue

**Solution:** Ensure files are UTF-8 encoded
```bash
file -I yourfile.py  # Check encoding
iconv -f ISO-8859-1 -t UTF-8 yourfile.py > yourfile_utf8.py
```

### `FileNotFoundError: [Errno 2] No such file or directory`

**Cause:** Path doesn't exist

**Solution:** Check path and current directory
```bash
ls -la yourfile.py
pwd  # Check current directory
```

---

## Getting More Help

### 1. Check Existing Issues
https://github.com/cboyd0319/PyGuard/issues

### 2. Search Discussions
https://github.com/cboyd0319/PyGuard/discussions

### 3. Create Bug Report
Include:
- PyGuard version: `pyguard --version`
- Python version: `python --version`
- OS: `uname -a` (Linux/Mac) or `ver` (Windows)
- Command run: exact command that failed
- Error message: full error output
- Minimal reproduction: smallest code example that triggers issue

### 4. Security Issues
**DO NOT** report security vulnerabilities publicly!
See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## Still Stuck?

Try running through the [QUICKSTART.md](QUICKSTART.md) guide from scratch with a fresh virtual environment. This solves 90% of issues.

If the problem persists:
1. Create a minimal reproduction
2. Open an issue on GitHub with details
3. We'll help you debug!

---

**Happy Scanning! 🛡️**
