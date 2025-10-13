# PyGuard User Guide

## TL;DR

```bash
pip install pyguard
pyguard src/
```

Scans Python code for security issues, quality problems, and style violations. Fixes automatically. See [README](../README.md) for feature list.

## Install

```bash
# From PyPI
pip install pyguard

# From source
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .

# Verify
pyguard --version
```

**Prerequisites**: Python 3.8+, pip

## Basic usage

**Single file**:
```bash
pyguard myfile.py
```

Creates backup → `.pyguard_backups/`, applies fixes, shows diff, logs to `logs/pyguard.jsonl`.

**Directory** (recursive):
```bash
pyguard src/
```

**Scan only** (no changes):
```bash
pyguard src/ --scan-only
```

Use for CI/CD: `pyguard src/ --scan-only || exit 1`

## Options

| Option | Description | Example |
|--------|-------------|---------|
| `--help` | Show help | `pyguard --help` |
| `--version` | Show version | `pyguard --version` |
| `--scan-only` | Scan without fixing | `pyguard src/ --scan-only` |
| `--no-backup` | Skip backup | `pyguard src/ --no-backup` |
| `--security-only` | Security fixes only | `pyguard src/ --security-only` |
| `--best-practices-only` | Quality fixes only | `pyguard src/ --best-practices-only` |
| `--formatting-only` | Formatting only | `pyguard src/ --formatting-only` |
| `--no-black` | Skip Black | `pyguard src/ --no-black` |
| `--no-isort` | Skip isort | `pyguard src/ --no-isort` |
| `--exclude` | Exclude patterns | `pyguard src/ --exclude "tests/*"` |

## Common scenarios

**Security audit**:
```bash
pyguard src/ --security-only
```

**Format only** (skip other checks):
```bash
pyguard src/ --formatting-only --no-backup
```

**Exclude test files**:
```bash
pyguard src/ --exclude "*/test_*.py" "tests/*"
```

## Configuration

Create `pyguard.toml` in project root or `~/.config/pyguard/config.toml`.

Precedence: CLI args → project config → user config → defaults

```toml
[general]
log_level = "INFO"
backup_dir = ".pyguard_backups"
max_backups = 10

[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM", "LOW"]

[best_practices]
enabled = true
max_complexity = 10
max_line_length = 50

[formatting]
line_length = 100
use_black = true
use_isort = true

[security.exclude]
patterns = ["*/tests/*", "*/test_*.py"]
```

## Python API

```python
from pathlib import Path
from pyguard import SecurityFixer, BestPracticesFixer, FormattingFixer

# Security scan
fixer = SecurityFixer()
success, fixes = fixer.fix_file(Path("myfile.py"))
print(f"Applied {len(fixes)} fixes")

# Best practices
bp = BestPracticesFixer()
success, fixes = bp.fix_file(Path("myfile.py"))

# Formatting
formatter = FormattingFixer()
result = formatter.format_file(
    Path("myfile.py"),
    use_black=True,
    use_isort=True
)
```

## CI/CD Integration

**GitHub Actions**:
```yaml
name: PyGuard

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
      - run: pyguard src/ --scan-only
```

**GitLab CI**:
```yaml
pyguard:
  image: python:3.13
  script:
    - pip install pyguard
    - pyguard src/ --scan-only
  only: [merge_requests, main]
```

**Pre-commit** (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: https://github.com/cboyd0319/PyGuard
    rev: v0.3.0
    hooks:
      - id: pyguard
        args: ['--scan-only']
```

## Troubleshooting

See [README Troubleshooting section](../README.md#troubleshooting) for common issues and fixes.

**Performance issues**: Use `--exclude` to skip vendor code, tests, migrations.

**False positives**: Report at [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues) with code sample.

## Output

PyGuard produces:
- **Console**: Summary table with counts, severity breakdown
- **HTML report**: `pyguard-report.html` (open in browser)
- **JSON logs**: `logs/pyguard.jsonl` (machine-readable)
- **Backups**: `.pyguard_backups/file.py.TIMESTAMP`

## See also

- [README](../README.md) — Feature overview, installation, quickstart
- [ARCHITECTURE](ARCHITECTURE.md) — How PyGuard works internally
- [CONTRIBUTING](../CONTRIBUTING.md) — How to contribute
- [SECURITY](../SECURITY.md) — Security policy and disclosure
