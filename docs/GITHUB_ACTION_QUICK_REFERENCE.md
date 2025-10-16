# PyGuard GitHub Action - Quick Reference

**One-page reference for using PyGuard as a GitHub Action**

## 🚀 Quick Start (30 seconds)

```yaml
# .github/workflows/pyguard.yml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cboyd0319/PyGuard@v0
        with:
          paths: '.'
          upload-sarif: 'true'
```

## 📥 Inputs Reference

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `paths` | string | `.` | Files/dirs to scan (space-separated) |
| `python-version` | string | `3.13` | Python version (3.11, 3.12, 3.13) |
| `scan-only` | bool | `true` | Only scan, don't fix code |
| `security-only` | bool | `false` | Only security checks (faster) |
| `severity` | string | `LOW` | Min severity: LOW/MEDIUM/HIGH/CRITICAL |
| `exclude` | string | `tests/* venv/*` | Patterns to exclude |
| `sarif-file` | string | `pyguard-report.sarif` | SARIF output path |
| `upload-sarif` | bool | `true` | Upload to Security tab |
| `fail-on-issues` | bool | `false` | Fail if issues found |
| `unsafe-fixes` | bool | `false` | Enable unsafe auto-fixes |

## 📤 Outputs Reference

| Output | Type | Description |
|--------|------|-------------|
| `issues-found` | number | Count of issues detected |
| `sarif-file` | string | Path to SARIF report |

## 🎯 Common Patterns

### Security Gate (Block PRs)

```yaml
on:
  pull_request:
    branches: [main]

- uses: cboyd0319/PyGuard@v0
  with:
    severity: 'HIGH'
    fail-on-issues: 'true'
```

### Multi-Path Scan

```yaml
- uses: cboyd0319/PyGuard@v0
  with:
    paths: 'src/ app/ lib/'
    exclude: 'tests/* docs/*'
```

### Scheduled Audit

```yaml
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

- uses: cboyd0319/PyGuard@v0
  with:
    severity: 'LOW'
    security-only: 'true'
```

### Use Outputs

```yaml
- id: scan
  uses: cboyd0319/PyGuard@v0

- run: echo "Found ${{ steps.scan.outputs.issues-found }} issues"
```

### Matrix Testing

```yaml
strategy:
  matrix:
    python: ['3.11', '3.12', '3.13']

- uses: cboyd0319/PyGuard@v0
  with:
    python-version: ${{ matrix.python }}
```

## 🔒 Permissions

### Scan Only
```yaml
permissions:
  contents: read
```

### With SARIF Upload
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

## ⚡ Performance Tips

1. **Faster scans**: Use `security-only: 'true'`
2. **Fewer findings**: Increase severity to `HIGH` or `CRITICAL`
3. **Exclude paths**: Add `tests/* docs/* examples/*`
4. **Scan changed files only**: Combine with changed-files action

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| SARIF not uploaded | Add `security-events: write` permission |
| No issues found | Check `paths` covers Python files |
| Action fails | Ensure `scan-only: 'true'` for CI |
| Slow scans | Use `security-only: 'true'` + exclusions |

## 📖 Full Documentation

- **Complete Guide**: [docs/guides/github-action-guide.md](https://github.com/cboyd0319/PyGuard/blob/main/docs/guides/github-action-guide.md)
- **Example Workflows**: [examples/github-workflows/](https://github.com/cboyd0319/PyGuard/tree/main/examples/github-workflows)
- **Marketplace**: [GitHub Marketplace](https://github.com/marketplace/actions/pyguard-security-scanner)

## 🆘 Support

- **Issues**: https://github.com/cboyd0319/PyGuard/issues
- **Discussions**: https://github.com/cboyd0319/PyGuard/discussions
- **Security**: https://github.com/cboyd0319/PyGuard/security/advisories

---

**Version**: 0.3.0 | **License**: MIT | **Python**: 3.11+
