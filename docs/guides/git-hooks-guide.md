# PyGuard Git Hooks Integration Guide

> **Automatic code quality checks before every commit**

PyGuard provides seamless integration with Git hooks to automatically run security and quality checks before commits and pushes, helping you catch issues before they reach your repository.

## Quick Start

### Install Pre-commit Hook

```bash
# Install in current repository
pyguard-hooks install

# Install in specific repository
pyguard-hooks install --path /path/to/repo

# Install pre-push hook instead
pyguard-hooks install --type pre-push

# Force overwrite existing hook
pyguard-hooks install --force
```

### Verify Installation

```bash
# Check if hook is properly installed
pyguard-hooks validate

# List all installed hooks
pyguard-hooks list

# Test the hook
pyguard-hooks test
```

### Uninstall Hook

```bash
# Remove pre-commit hook
pyguard-hooks uninstall

# Remove pre-push hook
pyguard-hooks uninstall --type pre-push
```

## Hook Types

### Pre-commit Hook

The pre-commit hook runs **before each commit** and:
- ✅ Scans only staged Python files
- ✅ Runs security and quality checks
- ✅ Fails commit if issues are found
- ✅ Provides clear error messages
- ✅ Can be bypassed with `--no-verify`

**Generated Hook Content:**
```bash
#!/usr/bin/env bash
# PyGuard pre-commit hook

# Get list of staged Python files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR | grep '\.py$' || true)

if [ -z "$STAGED_FILES" ]; then
    echo "No Python files staged for commit"
    exit 0
fi

echo "Running PyGuard security and quality checks..."

# Run PyGuard on staged files
pyguard --scan-only $STAGED_FILES

if [ $? -ne 0 ]; then
    echo "PyGuard found issues. Fix them before committing."
    echo "To skip this check, use: git commit --no-verify"
    exit 1
fi

echo "PyGuard checks passed ✓"
```

### Pre-push Hook

The pre-push hook runs **before each push** and:
- ✅ Scans entire codebase
- ✅ More comprehensive than pre-commit
- ✅ Catches issues across all files
- ✅ Can be bypassed with `--no-verify`

**Generated Hook Content:**
```bash
#!/usr/bin/env bash
# PyGuard pre-push hook

echo "Running PyGuard comprehensive analysis before push..."

# Run PyGuard on entire codebase
pyguard --scan-only .

if [ $? -ne 0 ]; then
    echo "PyGuard found issues. Fix them before pushing."
    echo "To skip this check, use: git push --no-verify"
    exit 1
fi

echo "PyGuard checks passed ✓"
```

## Usage Examples

### Example 1: First-time Setup

```bash
# Clone repository
git clone https://github.com/your/project.git
cd project

# Install PyGuard
# PyGuard is not yet on PyPI - install from source

# Install pre-commit hook
pyguard-hooks install

# Verify installation
pyguard-hooks validate
# Output: ✅ pre-commit hook is valid and ready to use
```

### Example 2: Making a Commit

```bash
# Edit files
vim myproject/module.py

# Stage changes
git add myproject/module.py

# Commit (hook runs automatically)
git commit -m "Add new feature"
# Output:
# Running PyGuard security and quality checks...
# Scanning: myproject/module.py
# PyGuard checks passed ✓
```

### Example 3: Handling Issues

```bash
# Stage file with security issue
git add vulnerable.py

# Attempt commit
git commit -m "Update code"
# Output:
# Running PyGuard security and quality checks...
# ❌ HIGH: SQL injection vulnerability found (line 42)
# PyGuard found issues. Fix them before committing.
# To skip this check, use: git commit --no-verify

# Fix the issues
vim vulnerable.py

# Try again
git add vulnerable.py
git commit -m "Fix SQL injection"
# Output: PyGuard checks passed ✓
```

### Example 4: Emergency Bypass

```bash
# Skip hook in emergency (NOT RECOMMENDED)
git commit -m "Emergency hotfix" --no-verify

# Same for push
git push --no-verify
```

## Integration with pre-commit Framework

PyGuard also supports the [pre-commit](https://pre-commit.com/) framework. Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cboyd0319/PyGuard
    rev: v0.3.0
    hooks:
      # Full PyGuard analysis
      - id: pyguard
        name: PyGuard Security & Quality Analysis
        args: ['--scan-only']
      
      # Security checks only
      - id: pyguard-security
        name: PyGuard Security Only
        args: ['--security-only', '--scan-only']
      
      # Formatting only
      - id: pyguard-format
        name: PyGuard Formatting
        args: ['--formatting-only']
```

Then install:
```bash
pre-commit install
```

## CI/CD Integration

Git hooks work great locally but should be complemented with CI/CD checks:

### GitHub Actions

```yaml
name: PyGuard Quality Check

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install PyGuard
        run: # PyGuard is not yet on PyPI - install from source
      
      - name: Run PyGuard
        run: pyguard --scan-only .
      
      - name: Upload SARIF report
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pyguard-report.sarif
```

### GitLab CI

```yaml
pyguard:
  stage: test
  image: python:3.11
  script:
    - # PyGuard is not yet on PyPI - install from source
    - pyguard --scan-only .
  only:
    - merge_requests
    - main
```

## Management Commands

### List Hooks

```bash
pyguard-hooks list

# Output:
# Found 2 installed hooks:
#   ✓ pre-commit (executable)
#     Path: .git/hooks/pre-commit
#   ✓ pre-push (executable)
#     Path: .git/hooks/pre-push
```

### Validate Hook

```bash
pyguard-hooks validate

# Checks:
# ✓ Hook file exists
# ✓ Hook is executable
# ✓ Hook is a PyGuard hook
# ✓ pyguard command is in PATH
```

### Test Hook

```bash
pyguard-hooks test

# Output:
# Testing pre-commit hook...
# Running PyGuard security and quality checks...
# No Python files staged for commit
# Hook test passed ✓
```

## Troubleshooting

### Hook Not Running

**Problem:** Hook doesn't run when committing

**Solutions:**
1. Check hook is installed: `pyguard-hooks list`
2. Verify hook is executable: `ls -la .git/hooks/pre-commit`
3. Make executable if needed: `chmod +x .git/hooks/pre-commit`
4. Validate installation: `pyguard-hooks validate`

### PyGuard Command Not Found

**Problem:** Hook fails with "pyguard: command not found"

**Solutions:**
1. Ensure PyGuard is installed: `# PyGuard is not yet on PyPI - install from source`
2. Check PATH includes Python scripts: `which pyguard`
3. Use absolute path in hook (edit `.git/hooks/pre-commit`)
4. Activate virtual environment before committing

### Hook Slow on Large Repositories

**Problem:** Hook takes too long to run

**Solutions:**
1. Use pre-commit hook (only staged files) instead of pre-push
2. Configure PyGuard to exclude patterns:
   ```bash
   # Edit .git/hooks/pre-commit
   pyguard --scan-only --exclude 'tests/*' 'venv/*' $STAGED_FILES
   ```
3. Use security-only mode for faster checks:
   ```bash
   pyguard --security-only --scan-only $STAGED_FILES
   ```

### Conflicts with Existing Hooks

**Problem:** Already have custom pre-commit hook

**Solutions:**
1. Backup existing hook: `cp .git/hooks/pre-commit .git/hooks/pre-commit.backup`
2. Merge PyGuard into existing hook manually
3. Use pre-commit framework to manage multiple hooks
4. Install PyGuard as pre-push hook instead

## Best Practices

### 1. Start with Pre-commit Hook

The pre-commit hook is faster and less intrusive:
```bash
pyguard-hooks install --type pre-commit
```

### 2. Gradually Increase Strictness

Begin with security-only checks, then expand:
```bash
# Edit .git/hooks/pre-commit
# Start with:   pyguard --security-only --scan-only $STAGED_FILES
# Progress to:  pyguard --scan-only $STAGED_FILES
```

### 3. Educate Team Members

Document the bypass mechanism for emergencies:
```bash
# Emergency bypass (use sparingly)
git commit --no-verify -m "Hotfix: critical production issue"
```

### 4. Combine with CI/CD

Never rely solely on local hooks:
- ✅ Local hooks catch issues early
- ✅ CI/CD ensures nothing bypassed
- ✅ Both together provide comprehensive coverage

### 5. Keep PyGuard Updated

```bash
# Update PyGuard regularly
pip install --upgrade pyguard

# Reinstall hooks to get latest improvements
pyguard-hooks install --force
```

## Advanced Configuration

### Custom Hook Behavior

Edit the generated hook to customize behavior:

```bash
# Edit .git/hooks/pre-commit
vim .git/hooks/pre-commit

# Add custom flags
pyguard --scan-only --severity HIGH $STAGED_FILES

# Add custom exclusions
pyguard --scan-only --exclude 'migrations/*' $STAGED_FILES

# Use unsafe fixes (not recommended for hooks)
# pyguard --unsafe-fixes $STAGED_FILES
```

### Multi-Repository Setup

Install across multiple repositories:

```bash
# Install in multiple projects
for repo in ~/projects/*; do
  if [ -d "$repo/.git" ]; then
    pyguard-hooks install --path "$repo"
  fi
done
```

### Git Worktrees

PyGuard hooks work with git worktrees:

```bash
# Create worktree
git worktree add ../feature-branch feature-branch

# Install hook
cd ../feature-branch
pyguard-hooks install
```

## Performance Tips

1. **Use --scan-only**: Always use scan-only mode in hooks
2. **Limit file scope**: Pre-commit only checks staged files
3. **Exclude test files**: Add `--exclude 'tests/*'` if tests are slow
4. **Cache analysis**: PyGuard caches results for unchanged files
5. **Parallel processing**: PyGuard automatically parallelizes when possible

## Security Considerations

1. **Verify hook contents**: Always check hook before running
2. **Don't disable hooks globally**: Use `--no-verify` selectively
3. **Review auto-fixes carefully**: Never use `--unsafe-fixes` in hooks
4. **Combine with code review**: Hooks complement, not replace, review
5. **Keep hooks updated**: Update PyGuard regularly for latest security checks

## Support

For issues or questions:
- 📚 Documentation: https://github.com/cboyd0319/PyGuard/docs
- 🐛 Issues: https://github.com/cboyd0319/PyGuard/issues
- 💬 Discussions: https://github.com/cboyd0319/PyGuard/discussions

## See Also

- [PyGuard Main Documentation](../../README.md)
- [Security Rules Reference](security-rules.md)
- [Capabilities Reference](capabilities-reference.md)
- [CI/CD Integration Examples](../../examples/)
