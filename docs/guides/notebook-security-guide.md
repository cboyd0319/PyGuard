# Jupyter Notebook Security Analysis Guide

PyGuard provides comprehensive security analysis for Jupyter notebooks (`.ipynb` files), making it one of the few security tools with first-class notebook support.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Security Checks](#security-checks)
4. [Python API](#python-api)
5. [Common Issues & Fixes](#common-issues--fixes)
6. [Best Practices](#best-practices)
7. [Integration](#integration)

## Overview

Jupyter notebooks are widely used in data science, machine learning, and research, but they present unique security challenges:

- **Code execution context**: Cells can execute in any order
- **Embedded credentials**: API keys and passwords often hardcoded for convenience
- **Magic commands**: Shell access through Jupyter-specific syntax
- **Output disclosure**: Cell outputs may leak sensitive information
- **Shared notebooks**: Security issues persist when notebooks are shared

PyGuard's notebook security analyzer detects **8+ categories of security issues** specific to Jupyter notebooks.

## Quick Start

### Analyze a notebook

```python
from pyguard.lib.notebook_security import scan_notebook

# Scan a notebook file
issues = scan_notebook('my_analysis.ipynb')

# Print all issues
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
    print(f"  Cell {issue.cell_index}, Line {issue.line_number}")
    print(f"  Code: {issue.code_snippet}")
    print(f"  Fix: {issue.fix_suggestion}\n")
```

### Analyze with full control

```python
from pathlib import Path
from pyguard.lib.notebook_security import NotebookSecurityAnalyzer

analyzer = NotebookSecurityAnalyzer()
issues = analyzer.analyze_notebook(Path('my_notebook.ipynb'))

# Filter by severity
critical_issues = [i for i in issues if i.severity == "CRITICAL"]
high_issues = [i for i in issues if i.severity == "HIGH"]

print(f"Found {len(critical_issues)} CRITICAL and {len(high_issues)} HIGH severity issues")
```

### Apply automated fixes

```python
from pyguard.lib.notebook_security import NotebookFixer

fixer = NotebookFixer()
success, fixes_applied = fixer.fix_notebook(
    Path('my_notebook.ipynb'),
    issues
)

if success:
    print(f"Applied {len(fixes_applied)} fixes:")
    for fix in fixes_applied:
        print(f"  - {fix}")
```

## Security Checks

PyGuard detects the following security issues in notebooks:

### 1. Hardcoded Secrets (HIGH)

**Detects:**
- Passwords and credentials
- API keys and tokens
- AWS access keys
- Secret keys and authentication tokens

**Example:**
```python
# Cell with hardcoded secret
api_key = 'sk-1234567890abcdef'
password = 'SuperSecret123'
```

**Fix:** Use environment variables or secure credential storage:
```python
import os
api_key = os.getenv('API_KEY')
password = os.getenv('PASSWORD')
```

### 2. Dangerous Magic Commands (HIGH)

**Detects:**
- Shell command execution (`!`, `%system`)
- Script execution (`%%bash`, `%%sh`, `%%script`)
- External extension loading (`%load_ext`)
- File operations (`%run`)

**Example:**
```python
# Dangerous magic command
!rm -rf /tmp/data
%system cat /etc/passwd
```

**Fix:** Use Python subprocess with proper validation:
```python
import subprocess
subprocess.run(['rm', '-rf', '/tmp/data'], check=True)
```

### 3. Code Injection (CRITICAL)

**Detects:**
- `eval()` calls
- `exec()` calls
- `compile()` calls

**Example:**
```python
# Dangerous code injection
user_input = input('Enter expression: ')
result = eval(user_input)  # Can execute arbitrary code!
```

**Fix:** Use `ast.literal_eval()` for safe evaluation:
```python
import ast
result = ast.literal_eval(user_input)  # Only evaluates literals
```

### 4. Command Injection (CRITICAL)

**Detects:**
- `subprocess` with `shell=True`
- `os.system()` calls
- Unsanitized command strings

**Example:**
```python
# Command injection vulnerability
filename = input('Enter filename: ')
subprocess.run(f'cat {filename}', shell=True)  # Injection possible!
```

**Fix:** Use command lists with `shell=False`:
```python
subprocess.run(['cat', filename], shell=False, check=True)
```

### 5. Unsafe Deserialization (HIGH)

**Detects:**
- `pickle.load()` calls
- `pickle.loads()` calls
- Untrusted pickle files

**Example:**
```python
import pickle

# Unsafe deserialization
with open('data.pkl', 'rb') as f:
    data = pickle.load(f)  # Can execute arbitrary code!
```

**Fix:** Use JSON or other safe formats:
```python
import json

with open('data.json', 'r') as f:
    data = json.load(f)  # Safe
```

### 6. Information Disclosure (MEDIUM)

**Detects:**
- System paths in error outputs
- Sensitive information in tracebacks
- Environment details in outputs

**Example:**
```python
# Cell output contains path disclosure
Traceback (most recent call last):
  File "/home/user/secret/project/script.py", line 42
    ...
```

**Fix:** Clear cell outputs before sharing:
```python
# Use Jupyter menu: Cell → All Output → Clear
# Or programmatically clear outputs
```

### 7. Execution Order Issues (MEDIUM)

**Detects:**
- Variables used before definition
- Cell dependency violations
- Out-of-order execution risks

**Example:**
```python
# Cell 1: Uses variable before definition
print(result)

# Cell 2: Defines variable (should be first)
result = 42
```

**Fix:** Restructure code to eliminate order dependencies:
```python
# Cell 1: Define first
result = 42

# Cell 2: Then use
print(result)
```

### 8. Unsafe File Operations (HIGH)

**Detects:**
- Path traversal risks
- Unvalidated file paths
- Insecure temp file creation

**Example:**
```python
# Path traversal vulnerability
user_file = input('Enter file: ')
with open(user_file, 'r') as f:  # No validation!
    data = f.read()
```

**Fix:** Validate and sanitize file paths:
```python
from pathlib import Path

user_file = input('Enter file: ')
safe_path = Path('/safe/directory') / Path(user_file).name
with open(safe_path, 'r') as f:
    data = f.read()
```

## Python API

### NotebookSecurityAnalyzer

Main class for analyzing notebook security.

```python
from pyguard.lib.notebook_security import NotebookSecurityAnalyzer

analyzer = NotebookSecurityAnalyzer()
```

#### Methods

**`analyze_notebook(notebook_path: Path) -> List[NotebookIssue]`**

Analyze a notebook file for security issues.

**Parameters:**
- `notebook_path`: Path to `.ipynb` file

**Returns:**
- List of `NotebookIssue` objects

**Raises:**
- `FileNotFoundError`: If notebook doesn't exist
- `ValueError`: If file is not a valid notebook

**Example:**
```python
from pathlib import Path

issues = analyzer.analyze_notebook(Path('analysis.ipynb'))
```

### NotebookIssue

Represents a security issue found in a notebook.

**Attributes:**
- `severity`: `str` - "CRITICAL", "HIGH", "MEDIUM", or "LOW"
- `category`: `str` - Issue category (e.g., "Hardcoded Secret")
- `message`: `str` - Issue description
- `cell_index`: `int` - Cell where issue was found (0-indexed)
- `line_number`: `int` - Line within cell (1-indexed)
- `code_snippet`: `str` - Relevant code
- `fix_suggestion`: `Optional[str]` - How to fix the issue
- `cwe_id`: `Optional[str]` - CWE identifier (e.g., "CWE-798")
- `owasp_id`: `Optional[str]` - OWASP identifier (e.g., "ASVS-2.6.3")

### NotebookFixer

Provides automated fixes for notebook issues.

```python
from pyguard.lib.notebook_security import NotebookFixer

fixer = NotebookFixer()
```

#### Methods

**`fix_notebook(notebook_path: Path, issues: List[NotebookIssue]) -> Tuple[bool, List[str]]`**

Apply automated fixes to a notebook.

**Parameters:**
- `notebook_path`: Path to notebook file
- `issues`: List of issues to fix

**Returns:**
- Tuple of `(success: bool, fixes_applied: List[str])`

**Example:**
```python
from pathlib import Path

success, fixes = fixer.fix_notebook(
    Path('notebook.ipynb'),
    issues
)
```

### Convenience Functions

**`scan_notebook(notebook_path: str) -> List[NotebookIssue]`**

Quick function to scan a notebook.

```python
from pyguard.lib.notebook_security import scan_notebook

issues = scan_notebook('my_notebook.ipynb')
```

## Common Issues & Fixes

### Issue: Too many false positives for secrets

**Solution:** Exclude test/placeholder values by checking the secret pattern:

```python
# These are NOT flagged as secrets:
api_key = "test"
password = "YOUR_KEY_HERE"
token = "***"
```

### Issue: Syntax errors in cells break analysis

**Solution:** PyGuard gracefully handles syntax errors and continues analysis:

```python
# Incomplete code in cell
def incomplete_function(
    # Analysis continues without crashing
```

### Issue: Markdown cells trigger false positives

**Solution:** PyGuard only analyzes code cells, not markdown:

```markdown
# This markdown content is ignored
password = "example"
```

## Best Practices

### 1. Scan before sharing

Always scan notebooks before sharing or committing:

```bash
# In your pre-commit hook
pyguard examples/my_notebook.ipynb --scan-only
```

### 2. Clear outputs

Clear cell outputs before committing notebooks:

```python
# Jupyter menu: Cell → All Output → Clear
# Or use nbconvert
jupyter nbconvert --clear-output --inplace notebook.ipynb
```

### 3. Use environment variables

Never hardcode secrets in notebooks:

```python
# Bad
api_key = "sk-1234567890abcdef"

# Good
import os
api_key = os.getenv('API_KEY')
```

### 4. Avoid magic commands

Prefer Python code over magic commands:

```python
# Bad
!rm -rf /tmp/data

# Good
import subprocess
subprocess.run(['rm', '-rf', '/tmp/data'], check=True)
```

### 5. Document cell order

Add markdown cells explaining execution order:

```markdown
## Setup (Run this cell first)
```

### 6. Use .env files

Store credentials in `.env` files (never commit these!):

```python
from dotenv import load_dotenv
import os

load_dotenv()  # Load .env file
api_key = os.getenv('API_KEY')
```

## Integration

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: pyguard-notebooks
        name: PyGuard Notebook Security
        entry: python -c "from pyguard.lib.notebook_security import scan_notebook; import sys; issues = scan_notebook(sys.argv[1]); sys.exit(1 if issues else 0)"
        language: python
        files: \.ipynb$
```

### CI/CD Pipeline

Add to GitHub Actions:

```yaml
- name: Scan Notebooks
  run: |
    # PyGuard is not yet on PyPI - install from source
    python -c "
    from pathlib import Path
    from pyguard.lib.notebook_security import scan_notebook
    import sys
    
    notebooks = Path('.').rglob('*.ipynb')
    all_issues = []
    
    for nb in notebooks:
        issues = scan_notebook(str(nb))
        all_issues.extend(issues)
        
    if all_issues:
        print(f'Found {len(all_issues)} security issues in notebooks')
        sys.exit(1)
    "
```

### Jupyter Extension (Future)

Coming soon: PyGuard Jupyter extension for real-time analysis.

## Performance

Notebook analysis is fast:

- **Small notebooks** (< 10 cells): < 100ms
- **Medium notebooks** (10-50 cells): < 500ms
- **Large notebooks** (50+ cells): < 2s

Memory usage is minimal, only loading one notebook at a time.

## Comparison with Other Tools

| Feature | PyGuard | Bandit | Ruff | nbqa |
|---------|---------|--------|------|------|
| Notebook-native analysis | ✅ Yes | ❌ No | ❌ No | ⚠️ Limited |
| Cell order analysis | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Magic command detection | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Output scanning | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Secrets in notebooks | ✅ Yes | ⚠️ Limited | ⚠️ Limited | ⚠️ Limited |
| Automated fixes | ✅ Yes | ❌ No | ⚠️ Limited | ❌ No |

## Limitations

1. **Dynamic analysis**: PyGuard performs static analysis only. It cannot detect runtime-specific issues.

2. **Custom magics**: Detection is based on common magic commands. Custom magics may not be detected.

3. **Kernel-specific issues**: Language kernel security is not analyzed.

4. **Extension security**: Third-party Jupyter extensions are not audited.

## Future Enhancements

Planned features for upcoming releases:

- [ ] JupyterLab extension for real-time analysis
- [ ] Custom magic command pattern support
- [ ] Kernel security analysis
- [ ] Notebook diff security analysis
- [ ] Integration with Jupyter trust system
- [ ] Automated secret redaction
- [ ] Cell dependency graph visualization
- [ ] SARIF output for notebooks

## Contributing

Have ideas for improving notebook security? Open an issue or submit a PR:

- GitHub: https://github.com/cboyd0319/PyGuard
- Issues: https://github.com/cboyd0319/PyGuard/issues

## References

- [Jupyter Security Documentation](https://jupyter-notebook.readthedocs.io/en/stable/security.html)
- [OWASP Jupyter Notebook Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Jupyter_Notebook)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)

---

**Note:** Notebook security analysis is a new feature in PyGuard v0.3.0. Feedback and contributions are welcome!
