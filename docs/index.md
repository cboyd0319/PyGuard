# PyGuard Documentation Hub

Welcome to the comprehensive documentation for PyGuard - The World's Best Python Security & Compliance Tool.

> **📦 Installation:** PyGuard is currently available via GitHub only. Install with:
> ```bash
> pip install git+https://github.com/cboyd0319/PyGuard.git
> ```
> PyPI/Homebrew releases coming soon!

## 📚 Documentation Structure

### Getting Started
- [Main README](../README.md) - Quick start and overview
- [Installation & Setup](../README.md#installation) - Detailed installation guide
- [Quickstart Guide](../QUICKSTART.md) - Get started in 2 minutes ✨
- [Examples](examples/README.md) - Code examples

### 🚀 New Subcommand Interface (v0.7.0+)
PyGuard now features an intuitive command-line interface:
- `pyguard scan` - Scan code for issues without making changes
- `pyguard fix` - Automatically fix issues (with `--interactive` mode!)
- `pyguard init` - Create `.pyguard.toml` with interactive wizard
- `pyguard doctor` - Verify installation and dependencies
- `pyguard explain` - Learn about security issues and fixes
- `pyguard validate-config` - Check configuration file validity
- `pyguard watch` - Auto-fix files on save

**Quick Examples:**
```bash
pyguard scan .                  # Scan current directory
pyguard fix . --interactive     # Fix issues with confirmation
pyguard init --interactive      # Create config with wizard
pyguard doctor                  # Check installation
pyguard explain sql-injection   # Learn about SQL injection
```

### Strategic Documentation
- [🗺️ Roadmap](../ROADMAP.md) - Complete roadmap with v0.7.0-v1.0.0 plans
- [📦 Distribution Strategy](reference/DISTRIBUTION_STRATEGY.md) - Multi-channel distribution & security
- [🎯 Capabilities Reference](reference/capabilities-reference.md) - Complete feature catalog
- [🏗️ Architecture](reference/ARCHITECTURE.md) - System design and technical overview

### User Guides
- [📚 Quickstart Guide](../QUICKSTART.md) - Get started in 2 minutes ✨ NEW
- [🔧 Troubleshooting Guide](../TROUBLESHOOTING.md) - Common issues and solutions ✨ NEW
- [Advanced Features Guide](guides/ADVANCED_FEATURES.md) - Jupyter notebook security & AI explanations
- [GitHub Action Guide](guides/github-action-guide.md) - CI/CD integration with GitHub Actions
- [GitHub Marketplace Guide](guides/GITHUB_MARKETPLACE_GUIDE.md) - Publishing and using the GitHub Action
- [Advanced Integrations Guide](guides/advanced-integrations.md) - CI/CD, Performance, Dependencies, Custom Rules
- [Auto-Fix Guide](guides/auto-fix-guide.md) - Automated code fixes
- [Git Hooks Guide](guides/git-hooks-guide.md) - Pre-commit integration
- [Notebook Security Guide](guides/notebook-security-guide.md) - Jupyter notebook scanning
- [RipGrep Integration](guides/RIPGREP_INTEGRATION.md) - High-performance scanning (10-100x faster)
- [Plugin Architecture Guide](guides/PLUGIN_ARCHITECTURE.md) - Extend PyGuard with custom plugins
- [Security Rules Reference](reference/security-rules.md) - All security checks

### Security & Supply Chain
- [Supply Chain Security Guide](guides/SUPPLY_CHAIN_SECURITY.md) - SLSA, Sigstore, SBOM ✨ NEW
- [SLSA Provenance Verification](security/SLSA_PROVENANCE_VERIFICATION.md) - Build integrity verification ✨ NEW
- [SBOM Guide](security/SBOM_GUIDE.md) - Software Bill of Materials usage ✨ NEW
- [Signature Verification Guide](security/SIGNATURE_VERIFICATION.md) - How to verify releases ✨ NEW
- [GPG Verification](security/GPG_VERIFICATION.md) - Traditional GPG signature verification
- [Security Quickstart](security/SECURITY_QUICKSTART.md) - Quick security verification guide
- [Reproducible Builds Guide](guides/REPRODUCIBLE_BUILDS.md) - Bit-for-bit build verification ✨ NEW
- [Air-Gapped Installation Guide](guides/AIR_GAPPED_INSTALLATION.md) - Offline installation methods ✨ NEW
- [Security Policy](../SECURITY.md) - Vulnerability disclosure

### Architecture & Implementation
- [Architecture](reference/ARCHITECTURE.md) - System design and technical overview
- [Implementation Summary](reference/architecture/IMPLEMENTATION_SUMMARY.md) - Technical overview
- [Auto-Fix Analysis](reference/architecture/AUTOFIX_ANALYSIS.md) - Fix safety classifications
- [Competing Products Analysis](reference/COMPETING_PRODUCTS_COVERAGE.md) - Feature comparison

### Historical Reports & Analysis
- [Reports Index](reports/README.md) - All historical reports
- [2025-11-11 Deep Analysis](reports/2025-11-11-deep-analysis.md) - Comprehensive codebase analysis
- [2025-11-11 Enhancements](reports/2025-11-11-enhancements-summary.md) - Usability improvements
- [2024 Implementation Reports](reports/) - v0.7.0-v1.0.0 implementation summaries

### Archived Documentation
- [Archived Development Docs](development/archived/README.md) - Old version documentation
- [Development Archive](development/archived/) - Historical development files

### Project Information
- [Changelog](CHANGELOG.md) - Version history
- [Contributors](CONTRIBUTORS.md) - Hall of fame
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute
- [Code of Conduct](../CODE_OF_CONDUCT.md) - Community guidelines
- [Security Policy](../SECURITY.md) - Security reporting

## 🎯 Quick Navigation

### For Users
- **First time?** Start with [Main README](../README.md)
- **Want examples?** Check [examples/](examples/)
- **Need help?** See [Capabilities Reference](reference/capabilities-reference.md)

### For Developers
- **Contributing?** Read [Contributing Guide](../CONTRIBUTING.md)
- **Understanding code?** See [Architecture](reference/ARCHITECTURE.md) and [Implementation Summary](reference/architecture/IMPLEMENTATION_SUMMARY.md)
- **Historical context?** Check [Reports](reports/) and [Archived Docs](development/archived/)

### For Security Teams
- **Compliance?** Review [Capabilities Reference](reference/capabilities-reference.md)
- **Supply chain security?** See [Supply Chain Security Guide](guides/SUPPLY_CHAIN_SECURITY.md)
- **SLSA provenance?** Check [SLSA Provenance Verification](security/SLSA_PROVENANCE_VERIFICATION.md)
- **SBOM analysis?** Read [SBOM Guide](security/SBOM_GUIDE.md)
- **Verifying releases?** Read [Signature Verification Guide](security/SIGNATURE_VERIFICATION.md)
- **Reproducible builds?** See [Reproducible Builds Guide](guides/REPRODUCIBLE_BUILDS.md)
- **Air-gapped environment?** Read [Air-Gapped Installation Guide](guides/AIR_GAPPED_INSTALLATION.md)
- **Integration?** See [Git Hooks Guide](guides/git-hooks-guide.md)
- **Custom rules?** Check [Plugin Architecture Guide](guides/PLUGIN_ARCHITECTURE.md)
- **Built-in rules?** Review [Security Rules Reference](reference/security-rules.md)

## 📖 Documentation Templates

Template files for maintaining consistent documentation:
- [README Template](doc_templates/README_TEMPLATE.md)
- [Contributing Template](doc_templates/CONTRIBUTING.md)
- [Security Template](doc_templates/SECURITY.md)
- [Code of Conduct Template](doc_templates/CODE_OF_CONDUCT.md)
- [Documentation Tone Guide](doc_templates/github-repo-docs-tone-guide.md)

## 🔗 External Resources

- [GitHub Repository](https://github.com/cboyd0319/PyGuard)
- [Issue Tracker](https://github.com/cboyd0319/PyGuard/issues)
- [Discussions](https://github.com/cboyd0319/PyGuard/discussions)

---

**Need help?** Open an [issue](https://github.com/cboyd0319/PyGuard/issues) or start a [discussion](https://github.com/cboyd0319/PyGuard/discussions).
