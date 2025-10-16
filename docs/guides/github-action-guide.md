# PyGuard GitHub Action Guide

Complete guide for using PyGuard as a GitHub Action in your Python projects.

## Quick Start

### Basic Security Scanning

Add this workflow to `.github/workflows/pyguard.yml`:

```yaml
name: PyGuard Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

permissions:
  contents: read
  security-events: write  # Required for SARIF upload

jobs:
  security-scan:
    name: PyGuard Security Analysis
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run PyGuard Security Scan
      uses: cboyd0319/PyGuard@main
      with:
        paths: '.'
        scan-only: 'true'
        upload-sarif: 'true'
```

**That's it!** PyGuard will:
- ✅ Scan your Python code for security vulnerabilities
- ✅ Generate a SARIF report
- ✅ Upload results to GitHub Security tab
- ✅ Add inline annotations to pull requests

## Action Inputs

### Core Configuration

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `paths` | Paths to scan (space-separated) | `.` | No |
| `python-version` | Python version to use | `3.13` | No |
| `scan-only` | Only scan without fixing issues | `true` | No |
| `security-only` | Only run security checks (skip quality) | `false` | No |

### Filtering Options

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `severity` | Minimum severity level | `LOW` | No |
| `exclude` | Patterns to exclude (space-separated) | `tests/* venv/*...` | No |

**Severity levels:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### Output Configuration

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `sarif-file` | Output SARIF file path | `pyguard-report.sarif` | No |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` | No |
| `fail-on-issues` | Fail workflow if issues are found | `false` | No |

### Advanced Options

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `unsafe-fixes` | Enable unsafe auto-fixes | `false` | No |

## Action Outputs

| Output | Description |
|--------|-------------|
| `issues-found` | Number of security issues detected |
| `sarif-file` | Path to generated SARIF report |

## Usage Examples

### 1. Security-Only Scanning (Recommended for CI)

Scan for security vulnerabilities without fixing code:

```yaml
- name: Security Scan
  uses: cboyd0319/PyGuard@main
  with:
    paths: 'src/ app/'
    scan-only: 'true'
    security-only: 'true'
    upload-sarif: 'true'
```

### 2. Fail on High/Critical Issues

Fail the workflow if high or critical security issues are found:

```yaml
- name: Security Gate
  uses: cboyd0319/PyGuard@main
  with:
    paths: '.'
    scan-only: 'true'
    severity: 'HIGH'
    fail-on-issues: 'true'
    upload-sarif: 'true'
```

### 3. Exclude Test Files and Dependencies

Scan only production code:

```yaml
- name: Scan Production Code
  uses: cboyd0319/PyGuard@main
  with:
    paths: 'src/'
    exclude: 'tests/* *_test.py venv/* .venv/* build/* dist/*'
    scan-only: 'true'
```

### 4. Multiple Paths

Scan specific directories:

```yaml
- name: Scan Multiple Paths
  uses: cboyd0319/PyGuard@main
  with:
    paths: 'src/ lib/ scripts/'
    scan-only: 'true'
```

### 5. Use Output in Workflow

Access scan results in subsequent steps:

```yaml
- name: Run PyGuard
  id: pyguard-scan
  uses: cboyd0319/PyGuard@main
  with:
    paths: '.'
    scan-only: 'true'
    upload-sarif: 'true'

- name: Check Results
  run: |
    echo "Issues found: ${{ steps.pyguard-scan.outputs.issues-found }}"
    echo "SARIF file: ${{ steps.pyguard-scan.outputs.sarif-file }}"
```

### 6. Scheduled Security Audits

Run daily security scans:

```yaml
name: Daily Security Audit

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight UTC
  workflow_dispatch:  # Allow manual trigger

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: PyGuard Security Audit
      uses: cboyd0319/PyGuard@main
      with:
        paths: '.'
        scan-only: 'true'
        security-only: 'true'
        upload-sarif: 'true'
```

### 7. Pull Request Scanning

Add inline security annotations to pull requests:

```yaml
name: PR Security Check

on:
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write
  pull-requests: write  # For PR comments

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: PyGuard PR Scan
      uses: cboyd0319/PyGuard@main
      with:
        paths: '.'
        scan-only: 'true'
        severity: 'MEDIUM'
        upload-sarif: 'true'
        fail-on-issues: 'false'  # Don't block PR
```

### 8. Matrix Testing with Multiple Python Versions

Test security across Python versions:

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12', '3.13']
    
    steps:
    - uses: actions/checkout@v4
    
    - name: PyGuard Scan (Python ${{ matrix.python-version }})
      uses: cboyd0319/PyGuard@main
      with:
        python-version: ${{ matrix.python-version }}
        paths: '.'
        scan-only: 'true'
        upload-sarif: 'true'
```

### 9. Security + Code Quality

Full analysis including code quality:

```yaml
- name: Full PyGuard Analysis
  uses: cboyd0319/PyGuard@main
  with:
    paths: 'src/'
    scan-only: 'true'
    security-only: 'false'  # Include quality checks
    upload-sarif: 'true'
```

### 10. Custom SARIF Output Location

Specify custom SARIF file location:

```yaml
- name: Custom SARIF Location
  uses: cboyd0319/PyGuard@main
  with:
    paths: '.'
    scan-only: 'true'
    sarif-file: 'reports/security-scan.sarif'
    upload-sarif: 'true'

- name: Upload SARIF Artifact
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: reports/security-scan.sarif
```

## Viewing Results

### GitHub Security Tab

Results appear in your repository's Security tab:

1. Navigate to `https://github.com/OWNER/REPO/security/code-scanning`
2. View detected vulnerabilities with severity, CWE, and OWASP mappings
3. Click on issues to see details, location, and fix suggestions

### Pull Request Annotations

On pull requests, PyGuard adds inline annotations:
- Security issues appear directly on the affected lines
- Click annotations to see full details and remediation steps
- Severity indicated by icon (error, warning, note)

### Workflow Logs

Detailed output in the Actions tab:
- Complete list of issues found
- File-by-file analysis results
- Timing and performance metrics

## Integration with Existing Workflows

### With CodeQL

Combine PyGuard with CodeQL for comprehensive security:

```yaml
jobs:
  codeql:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: github/codeql-action/init@v3
      with:
        languages: python
    - uses: github/codeql-action/analyze@v3

  pyguard:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: cboyd0319/PyGuard@main
      with:
        paths: '.'
        scan-only: 'true'
        upload-sarif: 'true'
```

### With Dependabot

Scan dependencies for known vulnerabilities:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"

# .github/workflows/pyguard.yml
on:
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: cboyd0319/PyGuard@main
      with:
        paths: '.'
        scan-only: 'true'
```

### With Pre-commit

Combine CI scanning with local pre-commit hooks:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/cboyd0319/PyGuard
    rev: main
    hooks:
      - id: pyguard
        args: ['--scan-only', '--security-only']

# .github/workflows/pyguard.yml
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: cboyd0319/PyGuard@main
```

## Compliance Frameworks

PyGuard supports multiple compliance frameworks:

```yaml
- name: PCI-DSS Compliance Scan
  uses: cboyd0319/PyGuard@main
  with:
    paths: 'payment_processing/'
    scan-only: 'true'
    security-only: 'true'
    severity: 'MEDIUM'
    fail-on-issues: 'true'
```

**Supported frameworks:**
- OWASP Top 10 & ASVS v5.0
- PCI-DSS
- HIPAA
- SOC 2
- ISO 27001
- NIST
- GDPR
- CCPA
- FedRAMP
- SOX

## Security Best Practices

### 1. Use SARIF Upload for Long-term Tracking

Always enable SARIF upload to track security trends:

```yaml
upload-sarif: 'true'
```

### 2. Set Appropriate Permissions

Minimal permissions required:

```yaml
permissions:
  contents: read        # Read repository code
  security-events: write  # Upload SARIF reports
```

### 3. Pin Action Versions

Use specific versions or SHA in production:

```yaml
uses: cboyd0319/PyGuard@v1.0.0  # Recommended
# or
uses: cboyd0319/PyGuard@abc123def456  # SHA pin
```

### 4. Scan Pull Requests Before Merge

Catch issues early:

```yaml
on:
  pull_request:
    branches: [ main, develop ]
```

### 5. Use fail-on-issues for Critical Environments

Block deployments with security issues:

```yaml
fail-on-issues: 'true'
severity: 'HIGH'
```

### 6. Exclude Test and Build Artifacts

Focus on production code:

```yaml
exclude: 'tests/* *_test.py build/* dist/* .tox/* htmlcov/*'
```

## Troubleshooting

### SARIF Upload Fails

**Issue:** "Resource not accessible by integration"

**Solution:** Add required permission:
```yaml
permissions:
  security-events: write
```

### No Issues Detected

**Issue:** PyGuard reports 0 issues but you expect some

**Solutions:**
1. Check `severity` setting - may be filtering issues
2. Verify `exclude` patterns aren't too broad
3. Check `security-only` isn't set when you want quality checks

### Action Times Out

**Issue:** Workflow times out on large codebases

**Solutions:**
1. Increase timeout:
   ```yaml
   timeout-minutes: 15
   ```
2. Exclude unnecessary directories
3. Scan in parallel jobs

### Python Version Compatibility

**Issue:** Syntax errors on modern Python code

**Solution:** Match your project's Python version:
```yaml
python-version: '3.13'  # Use your version
```

## Performance Optimization

### Caching Dependencies

Speed up workflow with caching:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: '3.13'
    cache: 'pip'

- uses: cboyd0319/PyGuard@main
```

### Parallel Jobs

Scan different paths in parallel:

```yaml
jobs:
  scan-backend:
    steps:
    - uses: cboyd0319/PyGuard@main
      with:
        paths: 'backend/'
  
  scan-api:
    steps:
    - uses: cboyd0319/PyGuard@main
      with:
        paths: 'api/'
```

## Support and Resources

- **Documentation:** [docs/README.md](README.md)
- **Security Policy:** [SECURITY.md](../SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Issues:** https://github.com/cboyd0319/PyGuard/issues
- **Discussions:** https://github.com/cboyd0319/PyGuard/discussions

## Example Projects

See PyGuard in action:
- [PyGuard Repository](https://github.com/cboyd0319/PyGuard) - Uses PyGuard to scan itself
- Check `.github/workflows/pyguard-security-scan.yml` for our production workflow

## What's Next?

- ✅ Set up basic security scanning
- ✅ Configure SARIF upload
- ✅ Add to pull request workflows
- ✅ Set up scheduled scans
- ✅ Explore compliance frameworks
- ✅ Integrate with other security tools

**Happy Secure Coding! 🛡️**
