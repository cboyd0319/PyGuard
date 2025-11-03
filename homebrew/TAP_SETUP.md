# Homebrew Tap Setup Guide

This guide explains how to set up and maintain the `homebrew-pyguard` tap repository for distributing PyGuard via Homebrew.

## What is a Homebrew Tap?

A tap is a third-party repository that contains Homebrew formulae. Users can "tap" your repository to access your formulae:

```bash
brew tap cboyd0319/pyguard
brew install pyguard
```

## Repository Structure

Create a new repository: `homebrew-pyguard` with this structure:

```
homebrew-pyguard/
├── Formula/
│   └── pyguard.rb          # The formula file
├── .github/
│   └── workflows/
│       ├── tests.yml       # Test formula on multiple platforms
│       └── update.yml      # Auto-update formula on new releases
├── README.md               # Installation and usage instructions
└── LICENSE                 # MIT License
```

## Setting Up the Tap Repository

### 1. Create the Repository

```bash
# On GitHub, create a new repository named: homebrew-pyguard
# Description: "Homebrew tap for PyGuard - Python security scanner"
# Public repository, MIT License

# Clone it locally
git clone https://github.com/cboyd0319/homebrew-pyguard.git
cd homebrew-pyguard
```

### 2. Add the Formula

```bash
# Create Formula directory
mkdir -p Formula

# Copy the formula from PyGuard repository
cp /path/to/PyGuard/homebrew/pyguard.rb Formula/

# Commit and push
git add Formula/pyguard.rb
git commit -m "Add PyGuard formula"
git push origin main
```

### 3. Create README.md

```markdown
# PyGuard Homebrew Tap

Homebrew tap for [PyGuard](https://github.com/cboyd0319/PyGuard) - Comprehensive Python security & code quality scanner.

## Installation

```bash
# Add the tap
brew tap cboyd0319/pyguard

# Install PyGuard
brew install pyguard
```

## Usage

```bash
# Scan Python files for security issues
pyguard /path/to/code

# Auto-fix security issues
pyguard /path/to/code --fix

# Scan with specific severity
pyguard /path/to/code --severity HIGH

# Generate compliance report
pyguard /path/to/code --compliance-report
```

## Upgrading

```bash
brew upgrade pyguard
```

## Uninstalling

```bash
brew uninstall pyguard
brew untap cboyd0319/pyguard
```

## Issues

Report issues at: https://github.com/cboyd0319/PyGuard/issues

## License

MIT License - see [LICENSE](LICENSE) file.
```

### 4. Add GitHub Actions for Testing

Create `.github/workflows/tests.yml`:

```yaml
name: Test Formula

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  test-macos:
    strategy:
      matrix:
        os:
          - macos-13      # Intel
          - macos-14      # Apple Silicon
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Homebrew
        uses: Homebrew/actions/setup-homebrew@master
      
      - name: Test formula
        run: |
          # Install from local formula
          brew install --build-from-source ./Formula/pyguard.rb
          
          # Run built-in tests
          brew test pyguard
          
          # Test basic functionality
          pyguard --version
          
          # Create test file
          echo 'import pickle; data = pickle.load(open("file.pkl", "rb"))' > test.py
          
          # Run scan
          pyguard test.py --scan-only
      
      - name: Audit formula
        run: |
          brew audit --strict --online ./Formula/pyguard.rb

  test-linux:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Homebrew
        uses: Homebrew/actions/setup-homebrew@master
      
      - name: Test formula
        run: |
          # Install from local formula
          brew install --build-from-source ./Formula/pyguard.rb
          
          # Run tests
          brew test pyguard
          
          # Test functionality
          pyguard --version
      
      - name: Audit formula
        run: |
          brew audit --strict --online ./Formula/pyguard.rb
```

### 5. Add Auto-Update Workflow

Create `.github/workflows/update.yml`:

```yaml
name: Update Formula

on:
  # Trigger manually or via repository_dispatch from PyGuard repo
  workflow_dispatch:
    inputs:
      version:
        description: 'PyGuard version to update to'
        required: true
      sha256:
        description: 'SHA256 checksum of the release tarball'
        required: true
  repository_dispatch:
    types: [update-formula]

jobs:
  update:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.PAT_TOKEN }}
      
      - name: Update formula
        run: |
          VERSION="${{ github.event.inputs.version || github.event.client_payload.version }}"
          SHA256="${{ github.event.inputs.sha256 || github.event.client_payload.sha256 }}"
          
          # Update version and SHA256 in formula
          sed -i "s|pyguard-.*\.tar\.gz|pyguard-${VERSION}.tar.gz|g" Formula/pyguard.rb
          sed -i "s|sha256 \".*\"|sha256 \"${SHA256}\"|g" Formula/pyguard.rb
          
          # Commit and push
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add Formula/pyguard.rb
          git commit -m "Update PyGuard to v${VERSION}"
          git push
      
      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v5
        with:
          token: ${{ secrets.PAT_TOKEN }}
          branch: update-v${{ github.event.inputs.version }}
          title: "Update PyGuard to v${{ github.event.inputs.version }}"
          body: |
            Automated update to PyGuard v${{ github.event.inputs.version }}
            
            - Version: ${{ github.event.inputs.version }}
            - SHA256: ${{ github.event.inputs.sha256 }}
            
            Triggered by PyGuard release workflow.
```

## Automating Formula Updates from PyGuard

In the main PyGuard repository, add this to `.github/workflows/release.yml`:

```yaml
- name: Update Homebrew formula
  if: github.event_name == 'release'
  run: |
    # Calculate SHA256 of release tarball
    SHA256=$(curl -sL https://files.pythonhosted.org/packages/source/p/pyguard/pyguard-${{ github.event.release.tag_name }}.tar.gz | sha256sum | cut -d' ' -f1)
    
    # Trigger update in homebrew-pyguard repository
    curl -X POST \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${{ secrets.HOMEBREW_TAP_TOKEN }}" \
      https://api.github.com/repos/cboyd0319/homebrew-pyguard/dispatches \
      -d "{\"event_type\":\"update-formula\",\"client_payload\":{\"version\":\"${{ github.event.release.tag_name }}\",\"sha256\":\"${SHA256}\"}}"
```

## Testing the Formula Locally

Before publishing, test the formula:

```bash
# Test syntax
brew audit --strict --online ./Formula/pyguard.rb

# Install from local formula
brew install --build-from-source ./Formula/pyguard.rb

# Run tests
brew test pyguard

# Verify installation
pyguard --version
pyguard --help

# Uninstall
brew uninstall pyguard
```

## Publishing the Tap

Once everything is tested:

1. Push the `homebrew-pyguard` repository to GitHub
2. Users can now install with:
   ```bash
   brew tap cboyd0319/pyguard
   brew install pyguard
   ```

## Maintenance

### Updating for New Releases

When PyGuard releases a new version:

1. The PyGuard release workflow triggers the tap update workflow
2. The formula is automatically updated with new version and SHA256
3. Tests run on macOS (Intel + ARM) and Linux
4. If tests pass, the update is merged

### Manual Updates

If needed, update manually:

```bash
cd homebrew-pyguard

# Update formula
python3 ../PyGuard/homebrew/generate_formula.py 0.7.0

# Test
brew install --build-from-source ./Formula/pyguard.rb
brew test pyguard

# Commit and push
git add Formula/pyguard.rb
git commit -m "Update to v0.7.0"
git push
```

## User Experience

Once published, users can install PyGuard with:

```bash
# One-time tap setup
brew tap cboyd0319/pyguard

# Install
brew install pyguard

# Use immediately
pyguard /path/to/code --fix
```

## Troubleshooting

### Formula fails to install

1. Check Python version compatibility
2. Verify all dependencies are available
3. Review Homebrew logs: `brew config`

### Tests fail on Apple Silicon

Ensure dependencies support ARM64 architecture. Some Python packages may need to be built from source.

### Formula rejected during audit

Common issues:
- Missing or incorrect license
- Invalid SHA256 checksum
- Deprecated Homebrew methods
- Missing test block

Run: `brew audit --strict --online ./Formula/pyguard.rb`

## Resources

- [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Homebrew Python Virtualenv Guide](https://docs.brew.sh/Python-for-Formula-Authors)
- [Homebrew Tap Documentation](https://docs.brew.sh/Taps)
- [Homebrew API Documentation](https://rubydoc.brew.sh/)

## Support

For questions or issues:
- PyGuard Issues: https://github.com/cboyd0319/PyGuard/issues
- Homebrew Discussions: https://github.com/Homebrew/discussions
- PyGuard Discussions: https://github.com/cboyd0319/PyGuard/discussions
