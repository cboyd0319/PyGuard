# PyGuard Security Scanner - GitHub Marketplace

## Overview

PyGuard is a comprehensive Python security and code quality scanner designed for GitHub Actions. It combines the power of multiple security tools (Bandit, Semgrep, Ruff) with ML-powered detection to find 55+ vulnerability types and automatically generate actionable reports.

## Why PyGuard?

### 🎯 Single Action, Complete Coverage

Replace multiple security tools with one action that provides:
- **55+ Security Checks** - SQL injection, XSS, command injection, secrets detection, and more
- **OWASP & CWE Aligned** - Mapped to OWASP ASVS v5.0 and CWE Top 25
- **179+ Auto-Fixes** - Automatically fix security issues (optional)
- **SARIF Native** - Perfect integration with GitHub Code Scanning
- **Zero Configuration** - Works out of the box, customize when needed

### 🔒 Security Features

| Feature | Description |
|---------|-------------|
| Injection Detection | SQL, NoSQL, Command, LDAP, Template injection |
| Secrets Scanning | API keys, AWS credentials, database passwords, JWT tokens |
| Crypto Analysis | Weak algorithms, insecure random, timing attacks |
| Framework Security | Django, Flask, FastAPI specific checks |
| Supply Chain | Dependency scanning, SBOM generation, license detection |
| Network Security | SSRF, insecure HTTP, path traversal |

### 📊 Compliance Mapping

PyGuard automatically maps findings to:
- OWASP ASVS v5.0
- CWE (Common Weakness Enumeration)
- PCI DSS
- HIPAA
- SOC 2
- ISO 27001
- NIST 800-53
- GDPR

## Quick Start

### Basic Security Scan

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cboyd0319/PyGuard@main
        with:
          paths: '.'
          upload-sarif: 'true'
```

### Security Gate on Pull Requests

Block PRs with high/critical security issues:

```yaml
name: Security Gate

on:
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cboyd0319/PyGuard@main
        with:
          paths: '.'
          severity: 'HIGH'
          fail-on-issues: 'true'
          upload-sarif: 'true'
```

### Scheduled Security Audit

Run comprehensive security audits on a schedule:

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cboyd0319/PyGuard@main
        with:
          paths: '.'
          security-only: 'true'
          severity: 'LOW'
          upload-sarif: 'true'
```

## Inputs

### Essential Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `paths` | Files/directories to scan (space-separated) | `.` | No |
| `scan-only` | Only scan, don't fix code | `true` | No |
| `upload-sarif` | Upload results to Security tab | `true` | No |

### Filtering Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `security-only` | Only run security checks | `false` | No |
| `severity` | Minimum severity (LOW/MEDIUM/HIGH/CRITICAL) | `LOW` | No |
| `exclude` | File patterns to exclude | `tests/* venv/*` | No |

### Advanced Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `python-version` | Python version for scanning | `3.13` | No |
| `fail-on-issues` | Fail workflow if issues found | `false` | No |
| `unsafe-fixes` | Enable unsafe auto-fixes | `false` | No |
| `sarif-file` | Output SARIF file path | `pyguard-report.sarif` | No |

## Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `issues-found` | Number of issues detected | `12` |
| `sarif-file` | Path to SARIF report | `pyguard-report.sarif` |

### Using Outputs

```yaml
- name: Run PyGuard
  id: scan
  uses: cboyd0319/PyGuard@main
  with:
    paths: 'src/'

- name: Check results
  run: |
    echo "Found ${{ steps.scan.outputs.issues-found }} issues"
    
- name: Comment on PR
  if: steps.scan.outputs.issues-found != '0'
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: '🔍 PyGuard found ${{ steps.scan.outputs.issues-found }} security issues'
      })
```

## Common Workflows

### 1. Multi-Path Scanning

Scan different parts of your codebase:

```yaml
- uses: cboyd0319/PyGuard@main
  with:
    paths: 'src/ app/ lib/'
    exclude: 'tests/* docs/*'
```

### 2. Different Severity Levels per Branch

```yaml
- uses: cboyd0319/PyGuard@main
  with:
    paths: '.'
    severity: ${{ github.ref == 'refs/heads/main' && 'HIGH' || 'CRITICAL' }}
    fail-on-issues: 'true'
```

### 3. Scan Only Changed Files

```yaml
- name: Get changed files
  id: changed-files
  uses: tj-actions/changed-files@v41
  with:
    files: |
      **.py
      
- name: Scan changed Python files
  if: steps.changed-files.outputs.any_changed == 'true'
  uses: cboyd0319/PyGuard@main
  with:
    paths: ${{ steps.changed-files.outputs.all_changed_files }}
```

### 4. Matrix Testing Across Python Versions

```yaml
strategy:
  matrix:
    python-version: ['3.11', '3.12', '3.13']

steps:
  - uses: actions/checkout@v4
  - uses: cboyd0319/PyGuard@main
    with:
      python-version: ${{ matrix.python-version }}
      paths: '.'
```

## Integration with GitHub Security

### Viewing Results

After the action runs with `upload-sarif: 'true'`:

1. Go to your repository
2. Click **Security** tab
3. Click **Code scanning**
4. View PyGuard findings with:
   - Severity levels
   - CWE mappings
   - Fix suggestions
   - File locations

### Code Scanning Alerts

PyGuard automatically:
- Creates alerts for each finding
- Annotates pull requests with inline comments
- Tracks issue trends over time
- Shows which issues are new vs. existing
- Provides remediation guidance

### Alert Filtering

Filter alerts by:
- **Severity** - Critical, High, Medium, Low
- **CWE** - Common Weakness Enumeration ID
- **Rule** - Specific PyGuard rule
- **State** - Open, Fixed, Dismissed

## Performance

| Codebase Size | Scan Time | SARIF Upload |
|---------------|-----------|--------------|
| Small (<1K LOC) | ~5 seconds | ~1 second |
| Medium (1K-10K LOC) | ~15 seconds | ~2 seconds |
| Large (10K-50K LOC) | ~45 seconds | ~3 seconds |
| Very Large (50K+ LOC) | ~2 minutes | ~5 seconds |

### Optimization Tips

1. **Use security-only mode** for faster scans:
   ```yaml
   security-only: 'true'
   ```

2. **Exclude unnecessary paths**:
   ```yaml
   exclude: 'tests/* docs/* examples/* scripts/*'
   ```

3. **Scan only changed files** (see example above)

4. **Use appropriate severity levels**:
   ```yaml
   severity: 'HIGH'  # Skip low/medium findings
   ```

## Permissions

### Minimal Permissions (Scan Only)

```yaml
permissions:
  contents: read
```

### Full Permissions (With SARIF Upload)

```yaml
permissions:
  contents: read
  security-events: write
```

### With PR Comments

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
```

## Troubleshooting

### SARIF File Not Generated

**Problem**: Action completes but no SARIF file is created.

**Solution**:
```yaml
- uses: cboyd0319/PyGuard@main
  with:
    paths: '.'
    scan-only: 'true'  # Ensure this is true for CI/CD
```

### SARIF Upload Failed

**Problem**: "security-events: write permission required"

**Solution**: Add permissions to workflow:
```yaml
permissions:
  security-events: write
```

### No Issues Found

**Problem**: Scan completes but shows 0 issues on codebase with known problems.

**Solution**: Check your Python files are being scanned:
```yaml
- uses: cboyd0319/PyGuard@main
  with:
    paths: '.'  # Make sure this covers your Python files
    exclude: ''  # Temporarily remove exclusions
```

### Action Fails on Windows/macOS

**Problem**: Action doesn't run on non-Linux runners.

**Solution**: PyGuard action supports all platforms:
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
runs-on: ${{ matrix.os }}
```

## Comparison with Other Tools

| Feature | PyGuard | Bandit | Semgrep | CodeQL |
|---------|---------|--------|---------|--------|
| Security Checks | 55+ | 40+ | 50+ | 100+ |
| Auto-Fix | ✅ 179+ | ❌ | ❌ | ❌ |
| SARIF Output | ✅ Native | ✅ Plugin | ✅ Native | ✅ Native |
| Setup Time | ~30 sec | ~2 min | ~5 min | ~10 min |
| Configuration | Optional | Required | Required | Required |
| Python Versions | 3.11+ | 3.8+ | Any | 3.8+ |
| Framework Detection | ✅ Auto | ❌ | ✅ Manual | ✅ Auto |
| Supply Chain | ✅ | ❌ | ❌ | ✅ |
| License | MIT | Apache 2.0 | LGPL | Proprietary |

## Support & Resources

- **Documentation**: [Full Docs](https://github.com/cboyd0319/PyGuard/tree/main/docs)
- **GitHub Action Guide**: [Action Guide](https://github.com/cboyd0319/PyGuard/blob/main/docs/guides/github-action-guide.md)
- **Examples**: [Workflow Examples](https://github.com/cboyd0319/PyGuard/tree/main/examples/github-workflows)
- **Issues**: [Report Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Security**: [Security Policy](https://github.com/cboyd0319/PyGuard/blob/main/SECURITY.md)

## License

MIT License - See [LICENSE](https://github.com/cboyd0319/PyGuard/blob/main/LICENSE)

## Version

Current version: **0.3.0**

For version history, see [CHANGELOG](https://github.com/cboyd0319/PyGuard/blob/main/docs/CHANGELOG.md)
