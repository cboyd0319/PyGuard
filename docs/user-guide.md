# PyGuard User Guide

Complete guide to using PyGuard for Python code quality, security, and formatting.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command-Line Usage](#command-line-usage)
- [Configuration](#configuration)
- [Python API](#python-api)
- [CI/CD Integration](#cicd-integration)
- [Editor Integration](#editor-integration)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Requirements

- Python 3.8 or higher
- pip or Poetry package manager

### Install from PyPI

```bash
pip install pyguard
```

### Install from Source

```bash
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .
```

### Verify Installation

```bash
pyguard --version
pyguard --help
```

---

## Quick Start

### Analyze a Single File

```bash
pyguard myfile.py
```

This will:
1. Create a backup in `.pyguard_backups/`
2. Analyze for security issues, best practices, and formatting
3. Apply fixes automatically
4. Show a unified diff of changes
5. Log results to `logs/pyguard.jsonl`

### Analyze a Directory

```bash
pyguard src/
```

Recursively analyzes all Python files in `src/` and subdirectories.

### Scan Only (No Fixes)

```bash
pyguard src/ --scan-only
```

Reports issues without modifying files. Useful for CI/CD pipelines.

---

## Command-Line Usage

### Basic Syntax

```bash
pyguard [paths] [options]
```

### Options

#### **General Options**

| Option | Description | Example |
|--------|-------------|---------|
| `--help` | Show help message | `pyguard --help` |
| `--version` | Show version | `pyguard --version` |
| `--scan-only` | Only scan, don't fix | `pyguard src/ --scan-only` |
| `--no-backup` | Skip backup creation | `pyguard src/ --no-backup` |

#### **Fix Type Options**

| Option | Description | Example |
|--------|-------------|---------|
| `--security-only` | Only security fixes | `pyguard src/ --security-only` |
| `--best-practices-only` | Only best practices | `pyguard src/ --best-practices-only` |
| `--formatting-only` | Only formatting | `pyguard src/ --formatting-only` |

#### **Formatter Options**

| Option | Description | Example |
|--------|-------------|---------|
| `--no-black` | Skip Black formatter | `pyguard src/ --no-black` |
| `--no-isort` | Skip isort | `pyguard src/ --no-isort` |

#### **Exclusion Options**

| Option | Description | Example |
|--------|-------------|---------|
| `--exclude` | Exclude patterns | `pyguard src/ --exclude "tests/*" "venv/*"` |

### Examples

#### Fix Security Issues Only

```bash
pyguard src/ --security-only
```

#### Format Code Only

```bash
pyguard src/ --formatting-only --no-backup
```

#### Scan Without Fixing (CI/CD)

```bash
pyguard src/ --scan-only || exit 1
```

#### Exclude Test Files

```bash
pyguard src/ --exclude "*/test_*.py" "tests/*"
```

---

## Configuration

### Configuration File

Create `pyguard.toml` in your project root:

```toml
[general]
log_level = "INFO"
backup_dir = ".pyguard_backups"
max_backups = 10

[formatting]
line_length = 100
use_black = true
use_isort = true
use_autopep8 = false

[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM", "LOW"]

[security.exclude]
patterns = ["*/tests/*", "*/test_*.py", "*_test.py"]

[best_practices]
enabled = true
naming_conventions = true
docstring_checks = true

[best_practices.exclude]
patterns = ["*/migrations/*", "*/vendor/*"]
```

### Configuration Precedence

1. Command-line options (highest priority)
2. Project `pyguard.toml`
3. User `~/.config/pyguard/config.toml`
4. System `/etc/pyguard/config.toml`
5. Default values (lowest priority)

### Environment Variables

Override settings with environment variables:

```bash
export PYGUARD_LOG_LEVEL=DEBUG
export PYGUARD_BACKUP_DIR=.backups
pyguard src/
```

---

## Python API

### SecurityFixer

```python
from pathlib import Path
from pyguard import SecurityFixer

# Create fixer instance
security_fixer = SecurityFixer()

# Fix a single file
file_path = Path("myfile.py")
success, fixes = security_fixer.fix_file(file_path)

print(f"Success: {success}")
print(f"Fixes applied: {len(fixes)}")
for fix in fixes:
    print(f"  - {fix}")

# Fix multiple files
files = [Path("file1.py"), Path("file2.py")]
for file_path in files:
    success, fixes = security_fixer.fix_file(file_path)
```

### BestPracticesFixer

```python
from pathlib import Path
from pyguard import BestPracticesFixer

# Create fixer instance
bp_fixer = BestPracticesFixer()

# Fix file
success, fixes = bp_fixer.fix_file(Path("myfile.py"))

# Get statistics
stats = bp_fixer.get_statistics()
print(f"Files analyzed: {stats['files_analyzed']}")
print(f"Issues found: {stats['issues_found']}")
print(f"Fixes applied: {stats['fixes_applied']}")
```

### FormattingFixer

```python
from pathlib import Path
from pyguard import FormattingFixer

# Create formatter instance
formatter = FormattingFixer()

# Format file
result = formatter.format_file(
    Path("myfile.py"),
    use_black=True,
    use_isort=True
)

if result["success"]:
    print("Formatting complete")
    print(f"Black: {result['black_success']}")
    print(f"isort: {result['isort_success']}")
```

### Logging

```python
from pyguard import PyGuardLogger

# Create logger
logger = PyGuardLogger(
    log_file="logs/custom.jsonl",
    level="DEBUG"
)

# Log messages
logger.info("Starting analysis", file="myfile.py")
logger.warning("Found issue", details={"type": "security"})
logger.error("Fix failed", exception=e)
```

### Backup Management

```python
from pyguard import BackupManager
from pathlib import Path

# Create backup manager
backup_mgr = BackupManager(backup_dir=".backups")

# Create backup before modifying
original_file = Path("myfile.py")
backup_path = backup_mgr.create_backup(original_file)
print(f"Backup created: {backup_path}")

# Restore from backup
backup_mgr.restore_backup(backup_path, original_file)

# Clean old backups (keep last 10)
backup_mgr.cleanup_old_backups(max_backups=10)
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: PyGuard Analysis

on: [push, pull_request]

jobs:
  pyguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install PyGuard
        run: pip install pyguard
      
      - name: Run PyGuard scan
        run: pyguard src/ --scan-only
```

### GitLab CI

```yaml
pyguard:
  image: python:3.11
  script:
    - pip install pyguard
    - pyguard src/ --scan-only
  only:
    - merge_requests
    - main
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cboyd0319/PyGuard
    rev: v0.1.0
    hooks:
      - id: pyguard
        args: ['--scan-only']
```

---

## Editor Integration

### VS Code

Install the PyGuard extension (coming soon) or use Tasks:

`.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "PyGuard: Fix Current File",
      "type": "shell",
      "command": "pyguard",
      "args": ["${file}"],
      "problemMatcher": []
    },
    {
      "label": "PyGuard: Scan Project",
      "type": "shell",
      "command": "pyguard",
      "args": ["${workspaceFolder}/src", "--scan-only"],
      "problemMatcher": []
    }
  ]
}
```

### PyCharm/IntelliJ

Add External Tool:
1. Settings → Tools → External Tools
2. Add new tool:
   - Name: PyGuard
   - Program: `pyguard`
   - Arguments: `$FilePath$`
   - Working directory: `$ProjectFileDir$`

### Vim/Neovim

Add to `.vimrc`:

```vim
" Run PyGuard on current file
nnoremap <leader>pg :!pyguard %<CR>

" Scan without fixing
nnoremap <leader>ps :!pyguard % --scan-only<CR>
```

---

## Troubleshooting

### Common Issues

#### "Command not found: pyguard"

**Solution**: Ensure PyGuard is installed and in PATH:

```bash
pip install pyguard
which pyguard  # Should show path
```

#### "Permission denied" on backup directory

**Solution**: Change backup directory or fix permissions:

```bash
# Option 1: Change directory
pyguard src/ --backup-dir=/tmp/pyguard_backups

# Option 2: Fix permissions
chmod 755 .pyguard_backups
```

#### "SyntaxError: invalid syntax" when analyzing Python 2 code

**Solution**: PyGuard only supports Python 3.8+. Upgrade your code or use legacy tools.

#### Black formatting conflicts with project style

**Solution**: Disable Black or configure it:

```bash
# Disable Black
pyguard src/ --no-black

# Or configure in pyguard.toml
[formatting]
use_black = false
```

### Debug Mode

Enable debug logging:

```bash
export PYGUARD_LOG_LEVEL=DEBUG
pyguard src/
```

View logs:

```bash
cat logs/pyguard.jsonl | jq .
```

### Getting Help

- **Documentation**: https://github.com/cboyd0319/PyGuard/docs
- **Issues**: https://github.com/cboyd0319/PyGuard/issues
- **Discussions**: https://github.com/cboyd0319/PyGuard/discussions

---

## Next Steps

- [API Reference](api-reference.md) - Complete Python API documentation
- [Configuration Guide](configuration.md) - Advanced configuration options
- [Security Rules](security-rules.md) - Security vulnerability patterns
- [Best Practices](best-practices.md) - Code quality checks reference
