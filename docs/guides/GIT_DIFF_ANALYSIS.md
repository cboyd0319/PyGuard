# Git Diff Analysis Guide

**PyGuard v0.8.0 Feature**

Analyze only changed files in git diffs, PRs, and branches for faster, focused security scanning.

## Overview

Git Diff Analysis allows you to scan only the files that have changed between commits, branches, or in staging. This dramatically reduces scan time for large codebases and is critical for efficient CI/CD pipelines.

### Key Benefits

- **10-100x faster scans** for large repositories
- **PR-focused security** - catch issues before merge
- **Efficient CI/CD** - scan only what changed
- **Branch comparison** - compare security posture
- **Staged changes** - pre-commit validation

## Quick Start

```bash
# Scan changes in current branch vs main
pyguard --diff main..feature-branch src/

# Scan last commit
pyguard --diff HEAD~1 src/

# Scan staged changes before commit
pyguard --diff staged src/

# Scan changes between specific commits
pyguard --diff abc123..def456 src/
```

## Usage Examples

### PR-Based Workflows

```bash
# GitHub Actions workflow
- name: Security Scan PR Changes
  run: |
    pyguard --diff origin/main..HEAD . \
      --sarif \
      --compliance-html pr-compliance.html
```

### Pre-Commit Hooks

```bash
# Scan only staged files
pyguard --diff staged . --scan-only

# Auto-fix staged files before commit
pyguard --diff staged . --fix
```

### Branch Comparison

```bash
# Compare feature branch to main
pyguard --diff main..feature/auth-update src/

# Compare two releases
pyguard --diff v1.0.0..v1.1.0 .
```

### CI/CD Integration

```bash
# GitLab CI
script:
  - pyguard --diff $CI_MERGE_REQUEST_TARGET_BRANCH_NAME..$CI_COMMIT_SHA .

# Jenkins
sh 'pyguard --diff origin/main..${GIT_COMMIT} .'

# Azure DevOps
- script: pyguard --diff $(System.PullRequest.TargetBranch)..HEAD .
```

## Diff Specifications

### Branch Comparison

```bash
# Two-dot syntax: changes in feature not in main
pyguard --diff main..feature .

# Three-dot syntax: changes since common ancestor
pyguard --diff main...feature .
```

### Commit Ranges

```bash
# Last N commits
pyguard --diff HEAD~5 .

# Between specific commits
pyguard --diff abc123..def456 .

# Single commit
pyguard --diff abc123^..abc123 .
```

### Special Cases

```bash
# Staged changes (ready for commit)
pyguard --diff staged .

# Working directory changes (unstaged)
# Note: Use standard path scanning for unstaged files
pyguard src/
```

## Output and Statistics

PyGuard shows diff statistics before scanning:

```
Git Diff Analysis
  Diff specification: main..feature-branch
  Changed files: 15
  Python files: 12
  Lines added: +543
  Lines deleted: -127

Analyzing 12 Python files...
```

## Advanced Usage

### Combine with Other Flags

```bash
# Fast scan with diff analysis
pyguard --diff main..feature . --fast

# Security-only scan of changes
pyguard --diff HEAD~1 . --security-only

# Generate compliance report for changes
pyguard --diff main..feature . \
  --compliance-html pr-compliance.html \
  --compliance-json pr-compliance.json

# SARIF output for GitHub integration
pyguard --diff origin/main..HEAD . --sarif
```

### Multiple Paths

```bash
# Scan changes in specific directories
pyguard --diff main..feature src/ tests/
```

### Exclude Patterns

```bash
# Exclude generated files from diff scan
pyguard --diff HEAD~1 . --exclude '*_pb2.py' 'migrations/*'
```

## GitHub Actions Integration

Complete workflow for PR scanning:

```yaml
name: Security Scan PR
on:
  pull_request:
    branches: [main, develop]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Need full history for diff
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install PyGuard
        run: pip install pyguard
      
      - name: Scan PR Changes
        run: |
          pyguard --diff origin/${{ github.base_ref }}..HEAD . \
            --sarif \
            --compliance-html pr-compliance.html
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pyguard-sarif.json
      
      - name: Upload Compliance Report
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: pr-compliance.html
```

## Best Practices

### 1. Always Fetch Full History

For accurate diff analysis, ensure you have the complete git history:

```bash
git fetch --depth=0  # Remove shallow clone restrictions
```

### 2. Use Appropriate Base Branch

Compare against the correct base branch:

```bash
# Feature branches → main
pyguard --diff main..feature-branch .

# Hotfix branches → production
pyguard --diff production..hotfix-urgent .
```

### 3. Combine with Fast Mode

For very large repositories, combine diff analysis with fast mode:

```bash
pyguard --diff main..feature . --fast
```

### 4. Pre-Commit Validation

Use in pre-commit hooks to catch issues early:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pyguard-security
        name: PyGuard Security (Changed Files Only)
        entry: pyguard --diff staged --security-only
        language: system
        pass_filenames: false
```

## Troubleshooting

### "Not a git repository" Error

**Problem:** PyGuard can't find the git repository.

**Solution:**
```bash
# Ensure you're in a git repository
git status

# Or specify the repository path
cd /path/to/repo && pyguard --diff main..feature .
```

### "No changed Python files found"

**Problem:** No Python files were modified in the diff.

**Solution:** This is expected if no Python files changed. Verify with:
```bash
git diff --name-only main..feature | grep '\.py$'
```

### Invalid Diff Specification

**Problem:** Git doesn't recognize the diff spec.

**Solution:** Verify the branches/commits exist:
```bash
# Check branch exists
git branch -a

# Verify commits
git log --oneline -n 5
```

## Performance Metrics

Expected performance improvements with diff analysis:

| Repository Size | Files Changed | Scan Time (full) | Scan Time (diff) | Improvement |
|----------------|---------------|------------------|------------------|-------------|
| Small (< 100 files) | 5 files | 10s | 2s | 5x faster |
| Medium (1000 files) | 20 files | 60s | 5s | 12x faster |
| Large (10K+ files) | 50 files | 600s | 10s | 60x faster |

## API Usage

Use diff analysis programmatically:

```python
from pathlib import Path
from pyguard.lib.git_diff_analyzer import GitDiffAnalyzer

# Initialize analyzer
analyzer = GitDiffAnalyzer(repo_path=Path("/path/to/repo"))

# Get changed files
changed_files = analyzer.get_changed_files(
    diff_spec="main..feature",
    python_only=True,
)

# Get statistics
stats = analyzer.get_diff_stats("main..feature")
print(f"Changed: {stats.python_files} Python files")
print(f"Added: +{stats.added_lines} lines")
print(f"Deleted: -{stats.deleted_lines} lines")

# Compare branches
comparison = analyzer.compare_security_posture(
    base_branch="main",
    compare_branch="feature",
)
```

## Related Features

- **Fast Mode** (`--fast`) - Combine with diff for even faster scans
- **SARIF Output** (`--sarif`) - Perfect for GitHub integration
- **Compliance Reports** - Generate compliance docs for PR reviews
- **Watch Mode** (`--watch`) - Continuous scanning during development

## References

- [Git diff documentation](https://git-scm.com/docs/git-diff)
- [GitHub Actions with PyGuard](github-action-guide.md)
- [CI/CD Integration Guide](ADVANCED_FEATURES.md#cicd-generation)
- [Compliance Reporting](COMPLIANCE_REPORTING.md)

## Support

For issues or questions:
- [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
