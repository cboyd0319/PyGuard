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
- **PII exposure**: Personal data often embedded in code and outputs
- **ML pipeline risks**: Model poisoning and unsafe deserialization
- **XSS vulnerabilities**: HTML outputs can introduce cross-site scripting risks

PyGuard's notebook security analyzer detects **15+ categories of security issues** specific to Jupyter notebooks, making it one of the most comprehensive tools available for notebook security.

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

### 1. Hardcoded Secrets (HIGH/CRITICAL)

**Detects:**
- Passwords and credentials
- API keys and tokens (AWS, GitHub, Slack, etc.)
- AWS access keys and secret keys
- Secret keys and authentication tokens
- SSH/RSA private keys
- GitHub personal access tokens

**Example:**
```python
# Cell with hardcoded secret
api_key = 'sk-1234567890abcdef'
password = 'SuperSecret123'
github_token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'
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
- File operations (`%run`, `%%writefile`)
- Environment variable manipulation (`%env`)
- Cross-notebook variable storage (`%store`)

**Example:**
```python
# Dangerous magic command
!rm -rf /tmp/data
%system cat /etc/passwd
%%writefile /etc/hosts  # Path traversal risk
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

### 9. PII (Personally Identifiable Information) Exposure (HIGH)

**Detects:**
- Social Security Numbers (SSN)
- Email addresses
- Credit card numbers
- Phone numbers
- IP addresses
- Postal codes (US ZIP, UK postcodes)

**Example:**
```python
# PII in code
user_email = 'john.doe@company.com'
ssn = '987-65-4321'
phone = '555-123-4567'
```

**Fix:** Remove or redact PII before sharing:
```python
# Use placeholder values
user_email = os.getenv('USER_EMAIL')
ssn = '***-**-****'
```

### 10. ML Pipeline Security Issues (CRITICAL/HIGH)

**Detects:**
- Unsafe pickle deserialization (model poisoning risk)
- PyTorch model loading without verification
- TensorFlow model loading from untrusted sources
- Joblib model loading
- NumPy pickle loading with `allow_pickle=True`
- Data loading without type validation

**Example:**
```python
# Unsafe model loading - arbitrary code execution risk
import torch
model = torch.load('untrusted_model.pth')

# Data loading without validation - data poisoning risk
import pandas as pd
df = pd.read_csv('untrusted_data.csv')  # No dtype validation
```

**Fix:** Verify sources and validate data:
```python
# Verify model checksum before loading
import hashlib
with open('model.pth', 'rb') as f:
    checksum = hashlib.sha256(f.read()).hexdigest()
assert checksum == KNOWN_GOOD_CHECKSUM

# Validate data types
df = pd.read_csv('data.csv', dtype={
    'column1': 'int64',
    'column2': 'float64'
})
```

### 11. XSS Vulnerabilities (HIGH)

**Detects:**
- Raw HTML display (`IPython.display.HTML()`)
- HTML cell magic (`%%html`)
- DataFrame to HTML conversion without escaping

**Example:**
```python
# XSS vulnerability
from IPython.display import HTML
user_input = input('Enter HTML: ')
display(HTML(user_input))  # User input not sanitized!
```

**Fix:** Sanitize user input or use safe display methods:
```python
from IPython.display import Text
display(Text(user_input))  # Safe - no HTML rendering
```

### 12. PII in Cell Outputs (HIGH)

**Detects:**
- PII exposed in stdout/stderr
- PII in execution results
- PII in error tracebacks

**Example:**
```python
# Cell output contains PII
print(f"User email: {user_email}")
# Output: User email: alice@secretcorp.com
```

**Fix:** Clear outputs before sharing:
```python
# Jupyter menu: Cell → All Output → Clear
# Or use nbconvert
jupyter nbconvert --clear-output --inplace notebook.ipynb
```

### 13. Untrusted Notebook Metadata (MEDIUM)

**Detects:**
- Notebooks explicitly marked as untrusted
- Missing trust signatures

**Fix:** Review and verify notebook content before trusting.

### 14. Non-Standard Kernels (LOW)

**Detects:**
- Custom or third-party kernels
- Kernels from unverified sources

**Fix:** Verify kernel source and security before use.

### 15. Data Validation Issues (MEDIUM)

**Detects:**
- Data loading without schema validation
- Missing dtype specifications
- Lack of input sanitization

**Fix:** Implement comprehensive data validation:
```python
import pandas as pd
from pandera import DataFrameSchema, Column, Check

schema = DataFrameSchema({
    'age': Column(int, Check.in_range(0, 120)),
    'name': Column(str, Check.str_length(1, 100))
})

df = pd.read_csv('data.csv')
schema.validate(df)  # Raises error if validation fails
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
- `category`: `str` - Issue category (e.g., "Hardcoded Secret", "PII Exposure", "ML Pipeline Security")
- `message`: `str` - Issue description
- `cell_index`: `int` - Cell where issue was found (0-indexed, -1 for metadata issues)
- `line_number`: `int` - Line within cell (1-indexed)
- `code_snippet`: `str` - Relevant code
- `fix_suggestion`: `Optional[str]` - How to fix the issue
- `cwe_id`: `Optional[str]` - CWE identifier (e.g., "CWE-798")
- `owasp_id`: `Optional[str]` - OWASP identifier (e.g., "ASVS-2.6.3")
- `confidence`: `float` - Detection confidence (0.0-1.0, default 1.0)
- `auto_fixable`: `bool` - Whether the issue can be automatically fixed (default False)

### NotebookFixer

Provides automated fixes for notebook issues.

```python
from pyguard.lib.notebook_security import NotebookFixer

fixer = NotebookFixer()
```

#### Methods

**`fix_notebook(notebook_path: Path, issues: List[NotebookIssue]) -> Tuple[bool, List[str]]`**

Apply automated fixes to a notebook. Creates a backup before modifying the notebook.

**Parameters:**
- `notebook_path`: Path to notebook file
- `issues`: List of issues to fix (only auto-fixable issues will be processed)

**Returns:**
- Tuple of `(success: bool, fixes_applied: List[str])`

**Supported Auto-Fixes:**
- **Hardcoded Secrets**: Comments out lines containing secrets
- **PII Exposure**: Adds warning comments before PII
- **PII in Output**: Clears cell outputs containing PII

**Example:**
```python
from pathlib import Path

# Analyze notebook
analyzer = NotebookSecurityAnalyzer()
issues = analyzer.analyze_notebook(Path('notebook.ipynb'))

# Apply auto-fixes
fixer = NotebookFixer()
success, fixes = fixer.fix_notebook(
    Path('notebook.ipynb'),
    issues
)

if success:
    print(f"Applied {len(fixes)} fixes:")
    for fix in fixes:
        print(f"  - {fix}")
    print("\nBackup created at: notebook.ipynb.backup")
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

| Feature | PyGuard | nbdefense | Bandit | Ruff |
|---------|---------|-----------|--------|------|
| Notebook-native analysis | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| Cell order analysis | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Magic command detection | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Output scanning | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| Secrets in notebooks | ✅ Yes | ✅ Yes | ⚠️ Limited | ⚠️ Limited |
| PII detection | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| ML pipeline security | ✅ Yes | ❌ No | ⚠️ Limited | ❌ No |
| XSS vulnerability detection | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Dependency vulnerabilities | ⚠️ Planned | ✅ Yes | ❌ No | ❌ No |
| License compliance | ⚠️ Planned | ✅ Yes | ❌ No | ❌ No |
| Automated fixes | ✅ Yes | ❌ No | ⚠️ Limited | ⚠️ Limited |
| Metadata security | ✅ Yes | ❌ No | ❌ No | ❌ No |
| GitHub token detection | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| AWS credential detection | ✅ Yes | ✅ Yes | ⚠️ Limited | ❌ No |
| Data poisoning detection | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Model security checks | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Confidence scoring | ✅ Yes | ❌ No | ❌ No | ❌ No |

### PyGuard's Unique Strengths

1. **ML/AI Pipeline Security**: Unlike nbdefense, PyGuard specifically detects ML-specific risks like unsafe model loading (PyTorch, TensorFlow), data poisoning vectors, and missing data validation.

2. **XSS Vulnerability Detection**: PyGuard detects XSS risks in HTML outputs, a critical security gap in data science notebooks.

3. **Automated Fixes**: PyGuard can automatically fix many issues including commenting out secrets, clearing outputs with PII, and adding security warnings.

4. **Cell Execution Order Analysis**: Detects when variables are used before definition, a unique notebook-specific issue.

5. **Confidence Scoring**: Each detection includes a confidence score, reducing false positives.

6. **100% Local Operation**: No telemetry or cloud dependencies - all analysis happens locally.

### nbdefense's Unique Strengths

1. **Dependency Scanning**: Built-in CVE scanning for Python packages (coming soon to PyGuard).

2. **License Compliance**: Automated license checking for open-source dependencies (coming soon to PyGuard).

3. **JupyterLab Extension**: In-line security recommendations within JupyterLab interface.

### Why PyGuard for Notebooks?

- **Comprehensive Coverage**: More detection categories (15+) than any other tool
- **ML-First Security**: Built for modern ML/AI workflows
- **Auto-Fix Capabilities**: Save time with automated remediation
- **Privacy Focused**: 100% local, no data leaves your machine
- **Integration Friendly**: Works with pre-commit hooks, CI/CD, and GitHub Actions

## Limitations

1. **Dynamic analysis**: PyGuard performs static analysis only. It cannot detect runtime-specific issues.

2. **Custom magics**: Detection is based on common magic commands. Custom magics may not be detected.

3. **Kernel-specific issues**: Language kernel security is not analyzed.

4. **Extension security**: Third-party Jupyter extensions are not audited.

## Future Enhancements

Planned features for upcoming releases:

- [ ] **Dependency vulnerability scanning** - CVE detection in imported packages (à la nbdefense)
- [ ] **License compliance checking** - Detect non-permissive licenses in dependencies
- [ ] **JupyterLab extension** - Real-time analysis within JupyterLab interface
- [ ] Custom magic command pattern support
- [ ] Kernel security analysis and sandboxing recommendations
- [ ] Notebook diff security analysis
- [ ] Integration with Jupyter trust system
- [ ] Automated secret redaction with placeholder generation
- [ ] Cell dependency graph visualization
- [ ] SARIF output for notebooks
- [ ] **Advanced ML security**: Model integrity verification, adversarial attack detection
- [ ] **Collaborative notebook security**: Multi-user notebook analysis
- [ ] **Cloud-native features**: S3 bucket security, cloud credential detection

## Contributing

Have ideas for improving notebook security? Open an issue or submit a PR:

- GitHub: https://github.com/cboyd0319/PyGuard
- Issues: https://github.com/cboyd0319/PyGuard/issues

## References

### Security Standards
- [Jupyter Security Documentation](https://jupyter-notebook.readthedocs.io/en/stable/security.html)
- [OWASP Jupyter Notebook Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Jupyter_Notebook)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)

### Recent CVEs (2024-2025)
- **CVE-2024-39700** (Critical): JupyterLab RCE via extension templates - [Details](https://nvd.nist.gov/vuln/detail/CVE-2024-39700)
- **CVE-2024-28233** (High): JupyterHub XSS vulnerability - [Details](https://nvd.nist.gov/vuln/detail/CVE-2024-28233)
- **CVE-2024-22420** (Medium): JupyterLab Markdown preview vulnerability - [Details](https://nvd.nist.gov/vuln/detail/CVE-2024-22420)
- **CVE-2025-30167** (High): Jupyter Core Windows configuration vulnerability - [Details](https://nvd.nist.gov/vuln/detail/CVE-2025-30167)

### Industry Resources
- [Protect AI nbdefense](https://protectai.com/nbdefense) - Complementary tool for dependency scanning
- [NVIDIA: Evaluating Jupyter Security](https://developer.nvidia.com/blog/evaluating-the-security-of-jupyter-environments/)
- [6 Ways Jupyter Notebooks Can Be Used for Cyber Attacks](https://cybsoftware.com/6-ways-jupyter-notebooks-can-be-used-for-cyber-attacks-in-ml-pipelines-and-ai-systems-and-how-organizations-can-prevent-those-attacks-from-happening/)
- [OpenCVE: Jupyter Vulnerabilities](https://app.opencve.io/cve/?vendor=jupyter)

---

**Note:** PyGuard's Jupyter notebook security analysis is continuously evolving to stay ahead of emerging threats. With 15+ detection categories and industry-leading auto-fix capabilities, PyGuard provides comprehensive protection for notebook-based workflows. For dependency scanning and license compliance, we recommend using PyGuard in combination with tools like nbdefense until those features are integrated.

**Latest Updates (2025):**
- ✅ PII detection (SSN, email, credit cards, phone numbers)
- ✅ ML pipeline security (model poisoning, unsafe deserialization)
- ✅ XSS vulnerability detection
- ✅ Advanced secret detection (GitHub, Slack, SSH keys)
- ✅ Metadata security analysis
- ✅ Enhanced auto-fix with backup creation
- ✅ Confidence scoring for all detections

Feedback and contributions are always welcome!
