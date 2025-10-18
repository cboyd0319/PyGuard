# PyGuard Git Hooks Examples

This directory contains example Git hooks for integrating PyGuard into your development workflow.

## Available Hooks

### 1. Secret Scanning Hook (`pre-commit-secret-scan`)

Prevents commits containing hardcoded secrets, API keys, passwords, or tokens.

**Installation:**
```bash
cp examples/hooks/pre-commit-secret-scan .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**What it does:**
- Scans staged Python files for secrets before each commit
- Blocks commits if secrets are detected
- Shows which secrets were found

### 2. Fast Security Scan Hook (`pre-commit-fast-scan`)

Runs a fast security scan on staged files using RipGrep pre-filtering.

**Installation:**
```bash
cp examples/hooks/pre-commit-fast-scan .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**What it does:**
- Uses RipGrep to quickly identify suspicious code patterns
- Runs full PyGuard analysis only on potentially problematic files
- Much faster than a full scan for large codebases

## Requirements

- **RipGrep**: Required for both hooks
  - macOS: `brew install ripgrep`
  - Ubuntu/Debian: `apt install ripgrep`
  - Windows: `winget install BurntSushi.ripgrep.MSVC`

- **PyGuard**: Must be installed and accessible in PATH
  ```bash
  pip install -e .
  ```

## Customization

You can modify these hooks to:
- Add more strict checks
- Exclude certain file patterns
- Generate reports
- Send notifications

## Testing Hooks

Test your hook without committing:
```bash
.git/hooks/pre-commit
```

## Bypassing Hooks (Emergency Use Only)

If you need to bypass the hook temporarily:
```bash
git commit --no-verify -m "Emergency fix"
```

**Warning**: Only use `--no-verify` in emergencies. Always fix security issues before merging.
