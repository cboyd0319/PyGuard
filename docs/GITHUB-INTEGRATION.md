# GitHub Integration Guide

## Overview

PyGuard seamlessly integrates with GitHub repositories to provide automated security scanning and code quality analysis. This guide covers how to set up PyGuard in your GitHub workflows with full support for GitHub Code Scanning via SARIF reports.

## Features

- 🔒 **GitHub Code Scanning**: Upload security findings directly to the GitHub Security tab
- 📊 **SARIF Format**: Full SARIF 2.1.0 compliance for standard reporting
- 🤖 **Automated Workflows**: Run on push, pull requests, or scheduled intervals
- 🏷️ **CWE/OWASP Mapping**: Industry-standard vulnerability classifications
- 🔧 **Fix Suggestions**: Actionable remediation guidance for each issue
- 📈 **Trend Analysis**: Track security improvements over time

## Quick Start

### 1. Add PyGuard Workflow to Your Repository

Create `.github/workflows/pyguard-security-scan.yml`:

```yaml
name: PyGuard Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

permissions:
  contents: read
  security-events: write  # Required for SARIF upload

jobs:
  pyguard-scan:
    name: PyGuard Security Analysis
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
      
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.13'
        
    - name: Install PyGuard
      run: |
        python -m pip install --upgrade pip
        pip install pyguard
        
    - name: Run PyGuard Security Scan
      run: |
        pyguard . \
          --scan-only \
          --sarif \
          --no-html \
          --exclude "tests/*" "venv/*" "build/*" "dist/*"
      continue-on-error: true
      
    - name: Upload SARIF to GitHub Security
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: pyguard-report.sarif
      if: always()
```

### 2. Configure Permissions

Ensure your workflow has the necessary permissions:

```yaml
permissions:
  contents: read          # Read repository contents
  security-events: write  # Upload SARIF to Security tab
  actions: read          # Read workflow status
```

### 3. Commit and Push

```bash
git add .github/workflows/pyguard-security-scan.yml
git commit -m "Add PyGuard security scanning workflow"
git push
```

## SARIF Output Format

PyGuard generates SARIF 2.1.0 compliant reports that include:

### Basic Structure

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "PyGuard",
        "version": "0.3.0",
        "informationUri": "https://github.com/cboyd0319/PyGuard",
        "rules": [...]
      }
    },
    "results": [...]
  }]
}
```

### Issue Details

Each security issue includes:

- **Rule ID**: Unique identifier (e.g., `PY/CWE-89`)
- **Severity Level**: `error`, `warning`, or `note`
- **Location**: File path, line number, and column
- **Message**: Clear description of the issue
- **Fix Suggestion**: Actionable remediation guidance
- **CWE/OWASP IDs**: Industry-standard classifications
- **Code Snippet**: Context around the vulnerable code

### Example Issue

```json
{
  "ruleId": "PY/CWE-89",
  "level": "error",
  "message": {
    "text": "Potential SQL injection vulnerability"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {
        "uri": "app.py"
      },
      "region": {
        "startLine": 42,
        "startColumn": 5
      }
    }
  }],
  "fixes": [{
    "description": {
      "text": "Use parameterized queries instead of string formatting"
    }
  }],
  "properties": {
    "cwe": "CWE-89",
    "owasp": "A03:2021"
  }
}
```

## CLI Options

### Generate SARIF Report

```bash
# Basic SARIF output
pyguard . --scan-only --sarif

# SARIF only (no HTML)
pyguard . --scan-only --sarif --no-html

# Security issues only
pyguard . --scan-only --sarif --security-only

# Exclude specific paths
pyguard . --scan-only --sarif --exclude "tests/*" "docs/*"
```

### Output Files

- `pyguard-report.sarif` - SARIF format for GitHub Code Scanning
- `pyguard-report.html` - Human-readable HTML report (unless --no-html)
- `pyguard-report.json` - JSON format for programmatic processing

## Viewing Results in GitHub

### Security Tab

After the workflow runs:

1. Navigate to your repository on GitHub
2. Click the **Security** tab
3. Select **Code scanning alerts**
4. View PyGuard findings alongside other security tools

### Pull Request Comments

Security issues are automatically commented on pull requests when they're introduced.

### Filtering Results

Use GitHub's filtering options to:
- Filter by severity (High, Medium, Low)
- Filter by rule (CWE ID)
- Filter by branch or pull request
- View trends over time

## Advanced Configuration

### Custom Exclusions

```yaml
- name: Run PyGuard Security Scan
  run: |
    pyguard . \
      --scan-only \
      --sarif \
      --exclude \
        "tests/*" \
        "venv/*" \
        "migrations/*" \
        "node_modules/*" \
        ".git/*"
```

### Different Scan Modes

```yaml
# Security-only scan (fastest)
- name: Security Scan
  run: pyguard . --scan-only --sarif --security-only

# Full analysis with auto-fix
- name: Full Analysis
  run: pyguard . --sarif

# Best practices only
- name: Code Quality
  run: pyguard . --scan-only --sarif --best-practices-only
```

### Matrix Strategy

Run PyGuard across multiple Python versions:

```yaml
strategy:
  matrix:
    python-version: ['3.9', '3.10', '3.11', '3.12', '3.13']

steps:
- uses: actions/setup-python@v5
  with:
    python-version: ${{ matrix.python-version }}
```

### Scheduled Scans

Run security scans on a schedule:

```yaml
on:
  schedule:
    # Daily at 2 AM UTC
    - cron: '0 2 * * *'
    
    # Weekly on Monday at 9 AM UTC
    - cron: '0 9 * * 1'
```

## Integration with Other Tools

### Combine with CodeQL

```yaml
jobs:
  pyguard:
    name: PyGuard Scan
    runs-on: ubuntu-latest
    steps:
      # PyGuard steps...

  codeql:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    steps:
      # CodeQL steps...
```

### Use with Bandit

PyGuard complements other security tools:

```yaml
- name: Run Bandit
  run: bandit -r . -f json -o bandit.json
  
- name: Run PyGuard
  run: pyguard . --scan-only --sarif
```

## Troubleshooting

### SARIF Upload Fails

**Issue**: `Error: Unable to upload SARIF file`

**Solutions**:
1. Verify `security-events: write` permission is set
2. Check SARIF file exists: `ls -la pyguard-report.sarif`
3. Validate SARIF format: Use GitHub's SARIF validator
4. Ensure file is not empty: `cat pyguard-report.sarif`

### No Issues Shown in Security Tab

**Issue**: Workflow succeeds but no alerts appear

**Solutions**:
1. Wait 5-10 minutes for processing
2. Check workflow logs for upload confirmation
3. Verify branch has code scanning enabled
4. Ensure repository has Advanced Security enabled (for private repos)

### Permission Denied

**Issue**: `Error: Resource not accessible by integration`

**Solution**: Add required permissions to workflow:

```yaml
permissions:
  security-events: write
  contents: read
```

### PyGuard Not Found

**Issue**: `pyguard: command not found`

**Solution**: Install from source in the workflow:

```yaml
- name: Install PyGuard
  run: |
    git clone https://github.com/cboyd0319/PyGuard.git
    cd PyGuard
    pip install -e .
```

## Best Practices

### 1. Run on Pull Requests

Always scan code before merging:

```yaml
on:
  pull_request:
    branches: [ main, develop ]
```

### 2. Use continue-on-error

Prevent workflow failures from blocking builds:

```yaml
- name: Run PyGuard
  run: pyguard . --scan-only --sarif
  continue-on-error: true
```

### 3. Cache Dependencies

Speed up workflow runs:

```yaml
- name: Cache pip packages
  uses: actions/cache@v4
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('**/pyproject.toml') }}
```

### 4. Store Artifacts

Keep SARIF reports for auditing:

```yaml
- name: Upload SARIF artifact
  uses: actions/upload-artifact@v4
  with:
    name: pyguard-sarif
    path: pyguard-report.sarif
    retention-days: 30
```

### 5. Set Status Checks

Require PyGuard to pass before merging:

1. Go to **Settings** → **Branches**
2. Edit branch protection rule
3. Require status check: "PyGuard Security Analysis"

## Examples

### Minimal Configuration

```yaml
name: Security Scan
on: [push, pull_request]
permissions:
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install pyguard
      - run: pyguard . --scan-only --sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pyguard-report.sarif
```

### Full-Featured Configuration

See `.github/workflows/pyguard-security-scan.yml` in this repository for a complete example with:
- Multiple triggers (push, PR, schedule, manual)
- Comprehensive exclusions
- Artifact upload
- Error handling
- Proper permissions

## Support

- **Documentation**: [GitHub Repository](https://github.com/cboyd0319/PyGuard)
- **Issues**: [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)

## References

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)
- [CWE Database](https://cwe.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
