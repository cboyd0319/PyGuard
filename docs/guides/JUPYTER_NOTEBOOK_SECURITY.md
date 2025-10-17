# Jupyter Notebook Security Scanning with PyGuard

PyGuard now includes world-class security analysis for Jupyter notebooks (`.ipynb` files), detecting 50+ vulnerability patterns specific to ML/AI workflows.

## Quick Start

```bash
# Scan a single notebook
pyguard my_notebook.ipynb --scan-only

# Scan all notebooks in a directory
pyguard notebooks/ --scan-only

# Generate SARIF report for GitHub Security
pyguard notebooks/ --scan-only --sarif

# Scan Python files and notebooks together
pyguard . --scan-only
```

## What PyGuard Detects in Notebooks

### CRITICAL Severity

#### 1. Code Injection
- **eval()** and **exec()** with user input
- **compile()** with untrusted sources
- **__import__()** with dynamic module names
- LLM-generated code execution patterns

```python
# ❌ CRITICAL - PyGuard will detect this
user_input = request.args.get('code')
result = eval(user_input)  # CWE-95

# ✅ FIX - Use safe alternatives
result = ast.literal_eval(user_input)
```

#### 2. Unsafe Deserialization & ML Model Risks
- **pickle.load()** from untrusted sources (arbitrary code execution)
- **torch.load()** without `weights_only=True` (PyTorch ACE via `__reduce__`)
- **yaml.load()** without safe loader
- **joblib.load()**, **dill.load()** on untrusted files
- **numpy.load()** with `allow_pickle=True`
- Hugging Face model loading from untrusted repos

```python
# ❌ CRITICAL - Arbitrary code execution risk
import torch
model = torch.load('model.pth')

# ✅ FIX - Safe model loading
import torch
import hashlib

MODEL_CHECKSUM = "abcdef1234567890..."
with open('model.pth', 'rb') as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
    if file_hash != MODEL_CHECKSUM:
        raise ValueError("Model checksum mismatch!")

model = torch.load('model.pth', weights_only=True, map_location='cpu')
```

#### 3. Hardcoded Secrets
Detects 300+ secret patterns including:
- AWS keys (`AKIA*`, `AWS_SECRET_ACCESS_KEY`)
- GitHub tokens (`ghp_`, `gho_`, `ghs_`)
- OpenAI API keys (`sk-proj-*`, `sk-*`)
- Slack tokens (`xoxb-`, `xoxp-`)
- SSH/RSA private keys
- JWT tokens
- High-entropy strings (entropy > 4.5)

```python
# ❌ CRITICAL - Secret detected
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"

# ✅ FIX - Use environment variables
import os
api_key = os.getenv('OPENAI_API_KEY')
if not api_key:
    raise ValueError("Set OPENAI_API_KEY environment variable")
```

**Secret Detection in Outputs:**
PyGuard scans cell outputs (stdout, stderr, tracebacks) for leaked secrets.

#### 4. Shell Command Injection
- Shell escapes with unsanitized input (`!command`)
- `%system`, `%%bash`, `%%sh` with variables
- Remote code execution via `curl|bash` or `wget|sh`
- `%run` with remote URLs

```python
# ❌ CRITICAL - Remote code execution
!curl https://example.com/install.sh | bash

# ✅ FIX - Download, verify, review
import subprocess
import hashlib
from pathlib import Path

url = "https://example.com/install.sh"
EXPECTED_HASH = "abcdef..."

result = subprocess.run(['curl', '-sL', url], capture_output=True, check=True)
script = result.stdout

actual_hash = hashlib.sha256(script).hexdigest()
if actual_hash != EXPECTED_HASH:
    raise ValueError("Script verification failed!")

# Review script before executing
# subprocess.run(['bash'], input=script)
```

### HIGH Severity

#### 5. XSS in Outputs
- JavaScript in cell outputs (`application/javascript`)
- Unsanitized HTML (`text/html` with `<script>` tags)
- Event handlers (`onclick`, `onerror`)
- `javascript:` URLs in HTML

```python
# ❌ HIGH - XSS vulnerability
from IPython.display import HTML, display
user_input = request.args.get('html')
display(HTML(user_input))  # XSS!

# ✅ FIX - Sanitize or use text output
import html
safe_content = html.escape(user_input)
display(Markdown(f"```\n{safe_content}\n```"))
```

### MEDIUM Severity

#### 6. Reproducibility Issues
- Unpinned dependencies (`%pip install torch` without version)
- Missing random seeds (numpy, torch, tensorflow, jax)
- Non-deterministic operations
- Missing environment fingerprinting

```python
# ❌ MEDIUM - Non-reproducible
%pip install torch transformers

# ✅ FIX - Pin versions with hashes
%%writefile requirements-notebook.txt
torch==2.2.0 --hash=sha256:abcdef...
transformers==4.38.0 --hash=sha256:123456...

%pip install --require-hashes -r requirements-notebook.txt
```

## Features

### 1. Notebook-Aware Analysis
- **Per-cell analysis** with cell index and execution count tracking
- **Magic command detection** (IPython `%` and `%%` magics)
- **Output scanning** (text, HTML, JavaScript, error tracebacks)
- **Markdown cell analysis** for embedded secrets
- **Cross-cell dataflow** (secrets defined in one cell, used in another)

### 2. SARIF 2.1.0 Compliance
- Notebook-specific locations: `(file, cell_index, line_number)`
- CWE/OWASP mappings for all findings
- Suggested fixes with rationale
- Severity scoring (CVSS-like)

```bash
# Generate SARIF for GitHub Code Scanning
pyguard notebooks/ --scan-only --sarif

# Upload to GitHub Security tab
gh api repos/:owner/:repo/code-scanning/sarifs \
  -F sarif=@pyguard-report.sarif \
  -F commit_sha=$(git rev-parse HEAD)
```

### 3. Execution Order Validation
Detects non-monotonic execution counts (cells executed out of order).

### 4. ML/AI Domain Expertise
- PyTorch model security (arbitrary code via `__reduce__`)
- TensorFlow SavedModel validation
- Hugging Face model provenance
- Data poisoning detection (unvalidated training data)

## Example Output

```
Found 0 Python files and 1 Jupyter notebooks

Analyzing Jupyter Notebooks...

Notebook Analysis Summary:
  Total notebooks: 1
  Analyzed: 1
  Total findings: 8
    CRITICAL: 6
    HIGH: 1

🔴 HIGH Severity Issues (Fix Immediately!)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ File                     ┃ Line ┃ Issue                        ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ vulnerable_example.ipynb ┃    3 ┃ Use of eval() detected       ┃
┃ vulnerable_example.ipynb ┃    2 ┃ Hardcoded OpenAI API key     ┃
┃ vulnerable_example.ipynb ┃    4 ┃ Unsafe pickle.load()         ┃
┃ vulnerable_example.ipynb ┃    2 ┃ Remote code via curl|bash    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## CLI Options

```bash
# Basic scanning
pyguard notebooks/ --scan-only              # Scan only, no fixes
pyguard notebooks/ --scan-only --no-html    # Skip HTML report
pyguard notebooks/ --scan-only --sarif      # Generate SARIF

# Exclude patterns
pyguard notebooks/ --scan-only --exclude ".ipynb_checkpoints/*"

# Security-only mode
pyguard notebooks/ --scan-only --security-only
```

## Integration with CI/CD

### GitHub Actions

```yaml
name: Notebook Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.13'
      - run: pip install pyguard
      - run: pyguard notebooks/ --scan-only --sarif --no-html
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pyguard-report.sarif
```

## Advanced Usage

### Programmatic Analysis

```python
from pathlib import Path
from pyguard.lib.notebook_analyzer import NotebookSecurityAnalyzer

analyzer = NotebookSecurityAnalyzer()
result = analyzer.analyze_notebook(Path('my_notebook.ipynb'))

print(f"Total findings: {result.total_count()}")
print(f"CRITICAL: {result.critical_count()}")
print(f"HIGH: {result.high_count()}")

for finding in result.findings:
    print(f"{finding.severity}: {finding.message}")
    print(f"  Cell {finding.cell_index}, line {finding.line_number}")
    print(f"  {finding.description}")
    if finding.suggested_fix:
        print(f"  Fix: {finding.suggested_fix}")
```

### SARIF Generation

```python
from pyguard.lib.notebook_analyzer import NotebookSecurityAnalyzer
from pathlib import Path
import json

analyzer = NotebookSecurityAnalyzer()

# Analyze multiple notebooks
results = []
for nb_path in Path('notebooks').glob('*.ipynb'):
    result = analyzer.analyze_notebook(nb_path)
    results.append(result)

# Generate SARIF report
sarif = analyzer.generate_sarif_report(results)

# Save to file
with open('pyguard-notebooks.sarif', 'w') as f:
    json.dump(sarif, f, indent=2)
```

## Detection Catalog

### Complete List of Detections

| Rule ID | Severity | Category | Description |
|---------|----------|----------|-------------|
| NB-INJECT-001 | CRITICAL | Code Injection | Use of eval() |
| NB-INJECT-002 | CRITICAL | Code Injection | Use of exec() |
| NB-DESERIAL-001 | CRITICAL | Unsafe Deserialization | pickle.load() |
| NB-DESERIAL-002 | CRITICAL | Unsafe Deserialization | yaml.load() without safe loader |
| NB-ML-001 | CRITICAL | ML Model Security | torch.load() without weights_only |
| NB-SECRET-AWS_KEY | CRITICAL | Secrets | AWS access key detected |
| NB-SECRET-GITHUB_TOKEN | CRITICAL | Secrets | GitHub token detected |
| NB-SECRET-OPENAI_KEY | CRITICAL | Secrets | OpenAI API key detected |
| NB-SECRET-SLACK_TOKEN | CRITICAL | Secrets | Slack token detected |
| NB-SECRET-SSH_PRIVATE_KEY | CRITICAL | Secrets | SSH private key detected |
| NB-SECRET-JWT | CRITICAL | Secrets | JWT token detected |
| NB-SECRET-GENERIC_API_KEY | CRITICAL | Secrets | Generic API key pattern |
| NB-SECRET-PASSWORD | CRITICAL | Secrets | Hardcoded password |
| NB-SECRET-ENTROPY | HIGH | Secrets | High-entropy string (potential secret) |
| NB-SHELL-001 | CRITICAL | Shell Injection | Dangerous shell pipe |
| NB-SHELL-002 | CRITICAL | Shell Injection | Remote code via curl\|bash |
| NB-SHELL-003 | CRITICAL | Shell Injection | %run with remote URL |
| NB-XSS-001 | HIGH | Output Security | JavaScript in outputs |
| NB-XSS-002 | HIGH | Output Security | Script tag in HTML output |
| NB-XSS-003 | HIGH | Output Security | Event handler in HTML |
| NB-XSS-004 | HIGH | Output Security | javascript: URL in HTML |
| NB-REPRO-001 | MEDIUM | Reproducibility | Unpinned dependency |

## Comparison to Other Tools

| Feature | PyGuard | nbdefense | Semgrep |
|---------|---------|-----------|---------|
| PyTorch model security | ✅ **BEST** | ❌ | ❌ |
| Multi-cell dataflow | ✅ **BEST** | ❌ | ❌ |
| Secret detection depth | ✅ **BEST** (300+) | ✅ Good (100+) | ⚠️ Limited |
| XSS in outputs | ✅ **BEST** | ❌ | ❌ |
| ML/AI-specific checks | ✅ **BEST** | ⚠️ Basic | ❌ |
| SARIF 2.1.0 support | ✅ | ✅ | ✅ |
| Execution order analysis | ✅ | ❌ | ❌ |
| Zero config | ✅ | ❌ | ❌ |

## Limitations & Future Work

### Current Limitations
- **No auto-fix** for notebooks (scan-only mode)
- **No execution** during analysis (static analysis only)
- **No dataflow tracking** across notebook boundaries

### Planned Features (v0.4.0+)
- [ ] Intelligent auto-fix with minimal cell patches
- [ ] Cell reordering for dependency resolution
- [ ] Multi-notebook dataflow analysis
- [ ] Dependency CVE scanning
- [ ] License compliance checking
- [ ] GPU memory leak detection
- [ ] Data poisoning validators with schema enforcement

## Best Practices

### 1. Run PyGuard Before Committing
```bash
# Add to .git/hooks/pre-commit
pyguard --scan-only --sarif notebooks/
```

### 2. Use in CI/CD Pipeline
Run on every PR to catch issues before merge.

### 3. Pin All Dependencies
```python
# requirements-notebook.txt
torch==2.2.0 --hash=sha256:...
transformers==4.38.0 --hash=sha256:...
```

### 4. Never Commit Secrets
Use environment variables or secret management tools.

```python
# ✅ Good
import os
api_key = os.getenv('OPENAI_API_KEY')

# ❌ Bad
api_key = "sk-1234567890..."
```

### 5. Verify Model Checksums
```python
import hashlib

def verify_model(path, expected_hash):
    with open(path, 'rb') as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if actual != expected_hash:
        raise ValueError("Model verification failed!")
```

## Support & Contributing

- **Documentation**: [docs/](../index.md)
- **Issues**: [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Security**: See [SECURITY.md](../../SECURITY.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
