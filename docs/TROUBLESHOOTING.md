# PyGuard Troubleshooting Guide

This guide helps you resolve common issues when using PyGuard. **No technical knowledge required** - just follow the steps!

---

## 📋 Table of Contents

- [Installation Issues](#installation-issues)
- [Running PyGuard](#running-pyguard)
- [Performance Issues](#performance-issues)
- [False Positives](#false-positives)
- [Getting Help](#getting-help)

---

## Installation Issues

### Problem: `pip install pyguard` fails

**Solution 1: Update pip**
```bash
python -m pip install --upgrade pip
pip install pyguard
```

**Solution 2: Use Python 3.8+**
```bash
# Check your Python version
python --version

# If less than 3.8, install Python 3.8+ from python.org
# Then try again
pip install pyguard
```

**Solution 3: Install from source**
```bash
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .
```

### Problem: `pyguard: command not found`

**Solution 1: Add to PATH (Linux/Mac)**
```bash
export PATH="$HOME/.local/bin:$PATH"
```

**Solution 2: Run as module**
```bash
python -m pyguard myfile.py
```

**Solution 3: Reinstall with --user**
```bash
pip install --user pyguard
```

### Problem: Permission denied errors

**Solution: Install without sudo**
```bash
pip install --user pyguard
```

**Never use `sudo pip install`** - this can break your system Python!

---

## Running PyGuard

### Problem: "No Python files found"

**Cause**: PyGuard only analyzes `.py` files.

**Solution**:
```bash
# Make sure you're in the right directory
cd /path/to/your/project

# Or specify the directory
pyguard /path/to/your/code
```

### Problem: Too many issues found

**Solution 1: Start with security only**
```bash
pyguard src/ --security-only
```

**Solution 2: Fix one file at a time**
```bash
pyguard myfile.py
```

**Solution 3: Review without fixing**
```bash
pyguard src/ --scan-only
```

### Problem: Changes I don't want

**Solution: Backups are automatic!**
```bash
# PyGuard creates backups before making changes
# They're saved as: filename.py.backup

# To restore a file:
cp myfile.py.backup myfile.py
```

### Problem: "Syntax error in code"

**Cause**: PyGuard can't analyze code with syntax errors.

**Solution**: Fix syntax errors first
```bash
# Use Python to find syntax errors
python -m py_compile myfile.py

# Fix the syntax error, then run PyGuard
pyguard myfile.py
```

---

## Performance Issues

### Problem: PyGuard is slow

**Solution 1: Use caching (automatic)**
```bash
# Second run is 10-100x faster due to caching
pyguard src/  # First run: 10s
pyguard src/  # Second run: 0.1s
```

**Solution 2: Use parallel processing**
```bash
# PyGuard automatically uses all CPU cores
# No configuration needed!
```

**Solution 3: Exclude unnecessary files**
```bash
# Create .pyguardignore file
echo "tests/" > .pyguardignore
echo "*.pyc" >> .pyguardignore
echo "__pycache__/" >> .pyguardignore
```

### Problem: Running out of memory

**Solution: Process files in batches**
```bash
# Process one directory at a time
pyguard src/module1/
pyguard src/module2/
# etc.
```

---

## False Positives

### Problem: PyGuard flags code that's actually safe

**Solution 1: Add inline comments**
```python
# pyguard: disable=hardcoded-password
TEST_PASSWORD = "test123"  # Only used in tests
```

**Solution 2: Configure in pyproject.toml**
```toml
[tool.pyguard]
ignore = [
    "hardcoded-password:tests/*",
    "eval-usage:config_parser.py"
]
```

**Solution 3: Report false positives**
File an issue at: https://github.com/cboyd0319/PyGuard/issues

Include:
- Code snippet
- PyGuard version
- Why it's a false positive

---

## Common Error Messages

### Error: "ModuleNotFoundError: No module named 'pyguard'"

**Solution**: Install PyGuard
```bash
pip install pyguard
```

### Error: "Permission denied: '.pyguard_cache'"

**Solution**: Delete cache and retry
```bash
rm -rf .pyguard_cache
pyguard myfile.py
```

### Error: "Cannot parse file: unexpected indent"

**Cause**: File has mixed tabs and spaces

**Solution**: Fix indentation
```python
# In your editor, convert tabs to spaces
# Most editors have a "Convert Indentation" option
```

### Error: "Failed to create backup"

**Solution**: Check write permissions
```bash
# Make sure you have write permissions
ls -la myfile.py

# Or run from a different directory where you have permissions
cd ~/my-writeable-directory
pyguard /path/to/code/
```

---

## CI/CD Integration Issues

### Problem: PyGuard fails in CI but works locally

**Solution 1: Check Python version**
```yaml
# GitHub Actions example
- uses: actions/setup-python@v4
  with:
    python-version: '3.8'  # Must be 3.8+
```

**Solution 2: Install dependencies**
```yaml
- name: Install dependencies
  run: |
    pip install --upgrade pip
    pip install pyguard
```

**Solution 3: Set exit code**
```bash
# Fail build on high severity issues only
pyguard src/ --fail-on high
```

### Problem: Cache not working in CI

**Solution: Configure cache**
```yaml
# GitHub Actions example
- uses: actions/cache@v3
  with:
    path: .pyguard_cache
    key: pyguard-${{ hashFiles('**/*.py') }}
```

---

## Getting Help

### Option 1: Check Documentation

- [User Guide](user-guide.md) - Complete usage guide
- [Features](FEATURES.md) - All features explained
- [Beginner Tutorial](BEGINNER-TUTORIAL.md) - Step-by-step guide

### Option 2: Search Issues

Visit: https://github.com/cboyd0319/PyGuard/issues

Search for your problem - it might already be solved!

### Option 3: Ask for Help

**File an Issue**: https://github.com/cboyd0319/PyGuard/issues/new

Include:
1. **What you tried**: Command you ran
2. **What happened**: Error message or unexpected behavior
3. **What you expected**: What should have happened
4. **Environment**:
   - Python version: `python --version`
   - PyGuard version: `pyguard --version`
   - Operating system: Windows/Mac/Linux

**Example Good Issue**:
```
Title: PyGuard fails with "Permission denied" on Windows 10

What I tried:
pyguard myproject/

What happened:
Error: Permission denied: '.pyguard_cache'

What I expected:
PyGuard to analyze my code

Environment:
- Python: 3.9.5
- PyGuard: 0.7.0
- OS: Windows 10 Home
```

### Option 4: Join the Community

- ⭐ Star the repo: https://github.com/cboyd0319/PyGuard
- 💬 Discussions: https://github.com/cboyd0319/PyGuard/discussions
- 📧 Email: security@pyguard.dev

---

## Still Stuck?

### Quick Checklist

- [ ] Python 3.8 or higher installed
- [ ] PyGuard installed: `pip install pyguard`
- [ ] Running in correct directory
- [ ] Have write permissions
- [ ] No syntax errors in code
- [ ] Checked existing issues

### Emergency Workaround

If nothing works, you can still benefit from PyGuard:

```bash
# Generate report without modifying files
pyguard src/ --scan-only --report json --output issues.json

# Review issues.json manually
# Fix issues by hand using the suggestions
```

---

## Prevention Tips

### Best Practices

1. **Always review changes before committing**
   ```bash
   pyguard src/ --scan-only  # Review first
   pyguard src/              # Then apply fixes
   git diff                  # Review changes
   ```

2. **Use version control**
   ```bash
   git commit -m "Before PyGuard fixes"
   pyguard src/
   git diff  # Review changes
   git commit -m "Applied PyGuard fixes"
   ```

3. **Start small**
   ```bash
   # Don't run on entire project at once
   pyguard src/module1.py  # Test on one file
   # If good, expand
   pyguard src/
   ```

4. **Keep PyGuard updated**
   ```bash
   pip install --upgrade pyguard
   ```

---

## Reporting Bugs

Found a bug? Help us improve PyGuard!

### What to Report

- 🐛 Crashes or errors
- ⚠️ False positives
- 🔒 Missed security issues
- 🚀 Performance problems
- 📚 Documentation errors

### What NOT to Report

- ❌ How to use Python (ask on Stack Overflow)
- ❌ How to fix specific code (ask in discussions)
- ❌ Feature requests (use discussions first)

### Bug Report Template

```
**Description**
Brief description of the bug

**To Reproduce**
1. Step 1
2. Step 2
3. See error

**Expected Behavior**
What should have happened

**Screenshots/Code**
Include relevant code or screenshots

**Environment**
- Python version:
- PyGuard version:
- OS:
```

---

**Remember: PyGuard is here to help! If you're stuck, we're here to help you get unstuck. Don't hesitate to ask!** 🚀
