# PyGuard Homebrew Formula

This directory contains the Homebrew formula and supporting files for distributing PyGuard via Homebrew.

## Status

✅ **READY FOR v0.7.0** - Formula complete, awaiting release and tap setup

The formula is production-ready and includes:
- ✅ Proper dependency handling with virtualenv
- ✅ Multi-version Python support (3.11, 3.12, 3.13)
- ✅ Comprehensive test suite
- ✅ Shell completion generation
- ✅ Head formula for development installations

## Installation (v0.7.0+)

Once the `homebrew-pyguard` tap is published, users will install with:

```bash
# Add tap (one-time)
brew tap cboyd0319/pyguard

# Install PyGuard
brew install pyguard

# Verify installation
pyguard --version

# Use PyGuard
pyguard /path/to/code --fix
```

### Upgrading

```bash
brew upgrade pyguard
```

### Uninstalling

```bash
brew uninstall pyguard
brew untap cboyd0319/pyguard
```

## Files in This Directory

- **`pyguard.rb`** - The Homebrew formula (production-ready)
- **`generate_formula.py`** - Helper script to generate formula with SHA256 checksums
- **`TAP_SETUP.md`** - Complete guide for setting up the homebrew-pyguard tap
- **`README.md`** - This file

## Development

### Generating the Formula for a Release

Use the helper script to update the formula with correct checksums:

```bash
# For a new release (e.g., v0.7.0)
python3 homebrew/generate_formula.py 0.7.0
```

This will:
1. Download the release tarball from PyPI
2. Calculate the SHA256 checksum
3. Update `pyguard.rb` with the correct version and checksum

### Release Checklist

When releasing a new version:

1. ✅ Update version in `pyproject.toml`
2. ✅ Build and publish to PyPI
3. ✅ Run `python3 homebrew/generate_formula.py <version>`
4. ✅ Test formula locally (see below)
5. ✅ Commit updated formula to PyGuard repo
6. ✅ Update homebrew-pyguard tap repository
7. ✅ Verify installation from tap

### Testing the Formula Locally

Before publishing (once v0.7.0 is released):

```bash
# Install from local formula (run from repository root)
brew install --build-from-source ./homebrew/pyguard.rb

# Test installation
pyguard --version

# Run tests
brew test pyguard

# Audit formula
brew audit --strict pyguard

# Uninstall test
brew uninstall pyguard
```

### Requirements for Publishing

- [ ] Create `homebrew-pyguard` tap repository
- [ ] Release v0.7.0 with GitHub release artifacts
- [ ] Calculate checksums for all dependencies
- [ ] Test on macOS Intel (Monterey+)
- [ ] Test on macOS Apple Silicon (Monterey+)
- [ ] Test on Linux (Ubuntu, Debian, Fedora)
- [ ] Document tap setup and usage
- [ ] Automate formula updates in CI/CD

## Formula Details

### Dependencies

**System:**
- `python@3.13` - Python runtime

**Python Packages (installed in virtualenv):**
- pylint>=4.0.1
- flake8>=7.3.0
- black>=25.9.0
- isort>=7.0.0
- mypy>=1.18.2
- bandit>=1.8.6
- ruff>=0.14.0
- rich>=14.2.0
- nbformat>=5.0.0
- nbclient>=0.5.0
- (and 4+ more - see requirements.txt)

### Installation Method

Uses Homebrew's `virtualenv_install_with_resources` which:
1. Creates an isolated virtualenv in `libexec`
2. Installs PyGuard and all dependencies
3. Links `pyguard` command to `bin/`
4. Manages all dependencies automatically

### Tests

The formula includes tests that verify:
1. PyGuard command is available
2. Version command works
3. Basic scanning functionality (unsafe pickle detection)

## Multi-Platform Support

### macOS

**Intel (x86_64):**
- Monterey (12.x) and newer
- Big Sur (11.x) with testing

**Apple Silicon (arm64):**
- Monterey (12.x) and newer
- Native ARM64 builds

### Linux

**Supported via Homebrew on Linux:**
- Ubuntu 20.04+
- Debian 11+
- Fedora 35+
- CentOS 8+

**Note:** Some dependencies may require compilation from source on Linux.

## Tap Repository

The formula will be published to a dedicated tap repository: `homebrew-pyguard`

**Repository:** `https://github.com/cboyd0319/homebrew-pyguard` (to be created)

**Structure:**
```
homebrew-pyguard/
├── Formula/
│   └── pyguard.rb
├── README.md
└── .github/
    └── workflows/
        └── tests.yml  # Automated testing
```

## Automation

### CI/CD Integration

The release process will automatically:
1. Build release artifacts
2. Calculate checksums
3. Update formula with new version
4. Submit PR to tap repository
5. Run tests on multiple platforms
6. Merge on successful tests

### Update Process

When a new version is released:
1. GitHub Actions workflow triggered
2. Formula updated with new version and checksums
3. Tests run automatically
4. Formula published to tap
5. Users can upgrade: `brew upgrade pyguard`

## Comparison with Other Distribution Methods

| Method | Speed | Isolation | Updates | Platform |
|--------|-------|-----------|---------|----------|
| **Homebrew** | Fast | System | `brew upgrade` | macOS, Linux |
| **pip** | Fast | venv | `pip install -U` | All |
| **Docker** | Medium | Container | `docker pull` | All |
| **GitHub Action** | N/A | CI/CD | Version pin | GitHub |

**Homebrew Advantages:**
- Single command installation
- Automatic dependency management
- Native platform integration
- Easy updates
- No Python environment management needed

## Related Documentation

- [DISTRIBUTION.md](../DISTRIBUTION.md) - Overall distribution strategy
- [ROADMAP.md](../ROADMAP.md) - v0.7.0 release plans
- [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook) - Homebrew docs

## Questions?

For questions about Homebrew distribution:
- **General:** [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- **Issues:** [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Homebrew Docs:** [Homebrew Documentation](https://docs.brew.sh/)

---

**Status:** Template/Planning  
**Target Release:** v0.7.0 (Q1 2026)  
**Last Updated:** 2025-11-03
