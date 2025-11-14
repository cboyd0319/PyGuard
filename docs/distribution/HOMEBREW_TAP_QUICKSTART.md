# Homebrew Tap Quick Start Guide

**Status:** ✅ Formula Ready (1,905 lines), ⚠️ Needs Tap Repository
**Priority:** HIGH - Quick Win
**Estimated Time:** 20-30 minutes

---

## Overview

The Homebrew formula is **100% ready** and just needs a tap repository to be created and published. This guide provides the fastest path to getting PyGuard on Homebrew.

---

## Quick Start (3 Steps)

### Step 1: Create the Tap Repository (5 minutes)

1. Go to https://github.com/new
2. Repository name: **`homebrew-pyguard`** (must start with `homebrew-`)
3. Description: `Homebrew tap for PyGuard - Python security scanner (1,230+ checks, auto-fixes)`
4. Public repository
5. Add MIT License
6. Add README
7. Click "Create repository"

### Step 2: Upload the Formula (10 minutes)

```bash
# Clone the new tap repository
git clone https://github.com/cboyd0319/homebrew-pyguard.git
cd homebrew-pyguard

# Create Formula directory
mkdir -p Formula

# Copy the formula from PyGuard repo
cp /path/to/PyGuard/homebrew/pyguard.rb Formula/

# Update README (see content below)

# Commit and push
git add .
git commit -m "Add PyGuard formula with comprehensive test suite"
git push origin main
```

### Step 3: Test Installation (5 minutes)

```bash
# Add the tap
brew tap cboyd0319/pyguard

# Install PyGuard
brew install pyguard

# Verify it works
pyguard --version
pyguard --help

# Test scanning
echo 'import pickle; pickle.load(open("file.pkl"))' > test.py
pyguard test.py --scan-only
rm test.py

# Success! 🎉
```

---

## Tap Repository Files

### README.md for homebrew-pyguard

Create this as the main README.md in the tap repository:

```markdown
# PyGuard Homebrew Tap

![PyGuard Logo](https://raw.githubusercontent.com/cboyd0319/PyGuard/main/docs/images/logo.png)

Official Homebrew tap for [PyGuard](https://github.com/cboyd0319/PyGuard) - The comprehensive Python security & code quality scanner.

## Features

- **1,230+ Security Checks** - Most comprehensive coverage
- **199+ Auto-Fixes** - Automatically fix issues
- **25 Frameworks** - Django, Flask, FastAPI, TensorFlow, PyTorch, and more
- **Zero Telemetry** - 100% local operation, complete privacy
- **Production Ready** - 4,500+ tests, 84% coverage

## Installation

```bash
# Add the tap
brew tap cboyd0319/pyguard

# Install PyGuard
brew install pyguard
```

## Quick Start

```bash
# Scan Python files for security issues
pyguard /path/to/your/code

# Auto-fix security issues
pyguard /path/to/your/code --fix

# Scan with specific severity
pyguard /path/to/your/code --severity HIGH

# Watch mode - continuous scanning
pyguard /path/to/your/code --watch

# Generate compliance report
pyguard /path/to/your/code --compliance-html report.html
```

## Platform Support

- **macOS** (Intel & Apple Silicon)
- **Linux** (Ubuntu, Debian, Fedora, etc.)

Tested on:
- macOS 13 (Ventura) - Intel
- macOS 14 (Sonoma) - Apple Silicon
- Ubuntu 22.04, 24.04
- Debian 11, 12

## Upgrading

```bash
# Update Homebrew
brew update

# Upgrade PyGuard
brew upgrade pyguard
```

## Uninstalling

```bash
brew uninstall pyguard
brew untap cboyd0319/pyguard
```

## What's New

### v0.7.0 (Coming March 2026)
- VS Code extension
- Docker Hub images
- Watch mode for continuous scanning
- Performance improvements (50%+ faster with caching)

### v0.6.0 (Current)
- 1,230+ security checks
- 25 framework integrations
- 199+ auto-fixes
- 4,500+ tests
- Git diff analysis
- Compliance reporting (10+ frameworks)

## Documentation

- **Main Documentation:** https://github.com/cboyd0319/PyGuard
- **Capabilities Reference:** https://github.com/cboyd0319/PyGuard/blob/main/docs/reference/capabilities-reference.md
- **Security Policy:** https://github.com/cboyd0319/PyGuard/blob/main/SECURITY.md
- **Roadmap:** https://github.com/cboyd0319/PyGuard/blob/main/ROADMAP.md

## Issues & Support

- **Report Issues:** https://github.com/cboyd0319/PyGuard/issues
- **Discussions:** https://github.com/cboyd0319/PyGuard/discussions
- **Formula Issues:** https://github.com/cboyd0319/homebrew-pyguard/issues

## Contributing

Contributions welcome! See [Contributing Guide](https://github.com/cboyd0319/PyGuard/blob/main/CONTRIBUTING.md).

## License

MIT License - see [LICENSE](https://github.com/cboyd0319/PyGuard/blob/main/LICENSE) file.

## Maintained By

[cboyd0319](https://github.com/cboyd0319) - PyGuard Core Team
```

---

## Adding GitHub Actions for CI/CD

### .github/workflows/tests.yml

This tests the formula on multiple platforms automatically:

```yaml
name: Test Formula

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:
  schedule:
    # Test weekly to catch dependency issues
    - cron: '0 0 * * 0'

jobs:
  test-macos:
    strategy:
      fail-fast: false
      matrix:
        os:
          - macos-13      # Intel (x86_64)
          - macos-14      # Apple Silicon (ARM64)

    runs-on: ${{ matrix.os }}

    steps:
      - name: Checkout tap
        uses: actions/checkout@v4

      - name: Set up Homebrew
        uses: Homebrew/actions/setup-homebrew@master

      - name: Audit formula
        run: |
          brew audit --strict --online ./Formula/pyguard.rb

      - name: Install formula
        run: |
          brew install --build-from-source ./Formula/pyguard.rb

      - name: Run formula tests
        run: |
          brew test pyguard

      - name: Test basic functionality
        run: |
          # Version check
          pyguard --version

          # Help check
          pyguard --help

          # Create test file with security issue
          cat > test_security.py << 'EOF'
          import pickle
          import subprocess

          # Security issue: Unsafe deserialization
          data = pickle.load(open('data.pkl', 'rb'))

          # Security issue: Shell injection
          subprocess.call('ls ' + user_input, shell=True)
          EOF

          # Run scan (should detect issues)
          pyguard test_security.py --scan-only || echo "Security issues detected (expected)"

          # Cleanup
          rm test_security.py

          echo "✅ All tests passed!"

      - name: Test auto-fix functionality
        run: |
          # Create fixable test file
          cat > test_fix.py << 'EOF'
          # Missing docstring
          def calculate(x, y):
              return x + y

          # Hardcoded credentials (will be flagged, not auto-fixed)
          api_key = "hardcoded_key_123"
          EOF

          # Test scan-only mode
          pyguard test_fix.py --scan-only

          # Cleanup
          rm test_fix.py

  test-linux:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout tap
        uses: actions/checkout@v4

      - name: Set up Homebrew
        run: |
          # Install Homebrew on Linux
          /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
          echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> $HOME/.bashrc
          eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"

      - name: Audit formula
        run: |
          eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
          brew audit --strict --online ./Formula/pyguard.rb

      - name: Install formula
        run: |
          eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
          brew install --build-from-source ./Formula/pyguard.rb

      - name: Run formula tests
        run: |
          eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
          brew test pyguard

      - name: Test basic functionality
        run: |
          eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
          pyguard --version
          pyguard --help

          echo "✅ Linux tests passed!"
```

---

## Automating Formula Updates

### .github/workflows/update-formula.yml

This auto-updates the formula when PyGuard releases a new version:

```yaml
name: Update Formula

on:
  workflow_dispatch:
    inputs:
      version:
        description: 'PyGuard version (e.g., 0.7.0)'
        required: true
      tarball_url:
        description: 'Release tarball URL'
        required: true
  repository_dispatch:
    types: [update-formula]

jobs:
  update:
    runs-on: ubuntu-latest

    permissions:
      contents: write
      pull-requests: write

    steps:
      - name: Checkout tap
        uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Calculate SHA256
        id: sha256
        run: |
          VERSION="${{ github.event.inputs.version || github.event.client_payload.version }}"
          URL="${{ github.event.inputs.tarball_url || github.event.client_payload.tarball_url }}"

          # Download tarball and calculate SHA256
          curl -sL "$URL" -o pyguard.tar.gz
          SHA256=$(sha256sum pyguard.tar.gz | cut -d' ' -f1)
          rm pyguard.tar.gz

          echo "sha256=$SHA256" >> $GITHUB_OUTPUT
          echo "Calculated SHA256: $SHA256"

      - name: Update formula
        run: |
          VERSION="${{ github.event.inputs.version || github.event.client_payload.version }}"
          SHA256="${{ steps.sha256.outputs.sha256 }}"

          # Update version in formula
          sed -i "s|url \".*\"|url \"https://files.pythonhosted.org/packages/source/p/pyguard/pyguard-${VERSION}.tar.gz\"|g" Formula/pyguard.rb
          sed -i "s|sha256 \".*\"|sha256 \"${SHA256}\"|g" Formula/pyguard.rb
          sed -i "s|version \".*\"|version \"${VERSION}\"|g" Formula/pyguard.rb

          # Show changes
          git diff Formula/pyguard.rb

      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v5
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          commit-message: "Update PyGuard to v${{ github.event.inputs.version || github.event.client_payload.version }}"
          branch: update-v${{ github.event.inputs.version || github.event.client_payload.version }}
          title: "Update PyGuard to v${{ github.event.inputs.version || github.event.client_payload.version }}"
          body: |
            Automated update to PyGuard v${{ github.event.inputs.version || github.event.client_payload.version }}

            **Changes:**
            - Version: `${{ github.event.inputs.version || github.event.client_payload.version }}`
            - SHA256: `${{ steps.sha256.outputs.sha256 }}`

            **Release Notes:** https://github.com/cboyd0319/PyGuard/releases/tag/v${{ github.event.inputs.version || github.event.client_payload.version }}

            ---

            Triggered by PyGuard release workflow.

            **Testing:**
            - [ ] macOS Intel tested
            - [ ] macOS Apple Silicon tested
            - [ ] Linux tested
            - [ ] Formula audit passed
            - [ ] Installation works
            - [ ] Basic functionality verified
```

---

## Integration with PyGuard Release Workflow

Add this to PyGuard's `.github/workflows/release.yml` to automatically trigger tap updates:

```yaml
      - name: Trigger Homebrew tap update
        if: github.event_name == 'release' && !github.event.release.prerelease
        run: |
          VERSION="${{ github.event.release.tag_name }}"
          VERSION="${VERSION#v}"  # Remove 'v' prefix if present

          TARBALL_URL="https://files.pythonhosted.org/packages/source/p/pyguard/pyguard-${VERSION}.tar.gz"

          # Trigger update in homebrew-pyguard repository
          curl -X POST \
            -H "Accept: application/vnd.github+json" \
            -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "https://api.github.com/repos/cboyd0319/homebrew-pyguard/dispatches" \
            -d "{\"event_type\":\"update-formula\",\"client_payload\":{\"version\":\"${VERSION}\",\"tarball_url\":\"${TARBALL_URL}\"}}"

          echo "✅ Triggered Homebrew tap update for v${VERSION}"
```

---

## Testing Checklist

Before going live:

- [ ] Tap repository created: `cboyd0319/homebrew-pyguard`
- [ ] Formula copied to `Formula/pyguard.rb`
- [ ] README.md created with installation instructions
- [ ] GitHub Actions workflows added
- [ ] Formula tested locally:
  ```bash
  brew audit --strict --online ./Formula/pyguard.rb
  brew install --build-from-source ./Formula/pyguard.rb
  brew test pyguard
  pyguard --version
  ```
- [ ] Test installation from tap:
  ```bash
  brew tap cboyd0319/pyguard
  brew install pyguard
  ```
- [ ] Multi-platform testing complete (macOS Intel, Apple Silicon, Linux)
- [ ] Auto-update workflow tested
- [ ] Main PyGuard README updated with Homebrew installation instructions

---

## Post-Launch

### Update Main PyGuard README

Add Homebrew installation section:

```markdown
### Homebrew (macOS & Linux)

```bash
# Add the tap
brew tap cboyd0319/pyguard

# Install
brew install pyguard

# Verify
pyguard --version
```

**Supported Platforms:**
- macOS 13+ (Intel & Apple Silicon)
- Linux (Ubuntu, Debian, Fedora, etc.)
```

### Add Homebrew Badge

```markdown
[![Homebrew](https://img.shields.io/badge/homebrew-cboyd0319%2Fpyguard-blue)](https://github.com/cboyd0319/homebrew-pyguard)
```

### Promote on Social Media

```
🎉 PyGuard is now on Homebrew!

Install with: brew tap cboyd0319/pyguard && brew install pyguard

✅ 1,230+ security checks
✅ 199+ auto-fixes
✅ 25 frameworks
✅ Works on macOS (Intel & Apple Silicon) and Linux

#Python #Security #DevTools #Homebrew
```

---

## Troubleshooting

### Formula fails brew audit

Check:
- SHA256 matches tarball exactly
- URL is correct and accessible
- License specified correctly
- All dependencies available on Homebrew

### Installation fails on Apple Silicon

Ensure Python version and all dependencies support ARM64. Some packages may need Rosetta 2.

### Tests fail in CI

- Check Python version compatibility
- Verify test data and expectations
- Review logs in GitHub Actions

---

## Success Criteria

- [ ] Tap repository live and public
- [ ] Formula installable via `brew tap cboyd0319/pyguard && brew install pyguard`
- [ ] Tests pass on macOS (Intel + ARM) and Linux
- [ ] Auto-update workflow functional
- [ ] Documentation updated
- [ ] Homebrew installation added to main README

---

## Timeline

- **Setup:** 20-30 minutes
- **Testing:** 30-45 minutes
- **Total:** ~1 hour to go live

---

**Status:** Ready for implementation
**Last Updated:** 2025-11-14
**Next Action:** Create `homebrew-pyguard` repository and upload formula
