# Changelog

All notable changes to PyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v0.4.0
- VS Code extension
- Language Server Protocol (LSP) support
- Pre-commit hooks integration
- Watch mode for continuous monitoring
- Git diff analysis

### Planned for v0.5.0
- Configuration inheritance (project → user → system)
- Advanced performance profiling
- Custom rules API enhancements

---

## [0.3.0] - 2025-10-16

### Added
- **GitHub Action** - Complete marketplace-ready GitHub Action for CI/CD integration
  - Native SARIF output for GitHub Code Scanning
  - Auto-upload to Security tab
  - Support for security-only, fail-on-issues, and unsafe-fixes modes
  - Cross-platform support (Ubuntu, macOS, Windows)
  - Python 3.11-3.13 compatibility
- **Advanced Features**
  - CI/CD integration generator for GitHub Actions, GitLab CI, CircleCI, Azure Pipelines
  - Performance profiler for detecting bottlenecks
  - Dependency analyzer with circular import detection
  - Custom rules engine (TOML and Python API)
- **Expanded Security Coverage**
  - GraphQL injection detection and fixes
  - JWT security checks (weak algorithms)
  - API rate limiter detection
  - Container security (privileged mode)
  - SSTI (Server-Side Template Injection) checks
- **Documentation**
  - Complete GitHub Action documentation
  - Marketplace listing (MARKETPLACE.md)
  - GitHub Action Quick Reference
  - Publishing guide for maintainers
  - Action setup summary
- **Quality Improvements**
  - 1002 tests with 82% coverage
  - Complete CI/CD pipeline with multiple workflows
  - Comprehensive example workflows
  - Validation script for action publishing

### Changed
- Updated to Python 3.13 as default version
- Improved SARIF validation and error handling
- Enhanced Windows Unicode encoding support
- Optimized workflow path filtering

### Fixed
- SARIF validation issues in CI/CD
- Pre-existing lint violations handling
- Windows Unicode encoding errors
- Missing config files in workflows

---

## [0.1.0] - 2025-01-XX (Initial Release)

### Added
- 🔒 **Security Analysis**: Detect and fix 9 categories of vulnerabilities
  - Hardcoded passwords/secrets
  - SQL injection
  - Command injection
  - Insecure random (random → secrets)
  - Unsafe YAML loading (yaml.load → yaml.safe_load)
  - Pickle usage warnings
  - Dangerous eval()/exec() calls
  - Weak cryptographic hashing (MD5/SHA1 → SHA256)
  - Path traversal vulnerabilities

- ✨ **Best Practices Enforcement**: 10+ code quality improvements
  - Mutable default arguments
  - Bare except clauses
  - None comparison (== → is)
  - Boolean comparison simplification
  - Type vs isinstance() checks
  - List comprehension suggestions
  - String concatenation in loops
  - Context manager suggestions
  - Missing docstring placeholders
  - Global variable warnings

- 🎨 **Code Formatting**: Integration with industry-standard tools
  - Black - Uncompromising code formatter
  - isort - Import sorting
  - autopep8 - PEP 8 compliance (optional)
  - Trailing whitespace removal
  - Blank line normalization

- 📊 **Code Quality Metrics**:
  - Complexity analysis
  - Naming convention checks (PEP 8)
  - Docstring coverage reporting

- 🛡️ **Safety Features**:
  - Automatic backups before modifications (.pyguard_backups/)
  - Unified diff generation showing all changes
  - Scan-only mode for CI/CD integration
  - Exclude patterns for tests/vendored code
  - JSONL structured logging

- 🔧 **Command-Line Interface**:
  - Simple usage: `pyguard [paths]`
  - Options: --scan-only, --no-backup, --security-only, --formatting-only
  - Exclude patterns support
  - Verbose logging

- 📦 **Python API**:
  - `SecurityFixer` class for security fixes
  - `BestPracticesFixer` class for quality improvements
  - `FormattingFixer` class for code formatting
  - `PyGuardLogger` for structured logging
  - `BackupManager` for safe file operations
  - `DiffGenerator` for change visualization

- 📝 **Configuration**:
  - TOML-based configuration (pyguard.toml)
  - Security rules configuration (config/security_rules.toml)
  - QA settings configuration (config/qa_settings.toml)

- 📚 **Documentation**:
  - Comprehensive README with quick start guide
  - API reference documentation
  - Configuration guide
  - Security rules reference
  - Best practices reference
  - Contributing guidelines

### Technical Details
- Python 3.8+ support
- Type hints throughout codebase
- Regex-based pattern matching (AST-based coming in v0.2.0)
- Cross-platform support (Windows, macOS, Linux)
- Zero external runtime dependencies (formatters optional)

---

## Release Process

### Version Numbering
- **Major (X.0.0)**: Breaking changes, major feature additions
- **Minor (0.X.0)**: New features, backwards compatible
- **Patch (0.0.X)**: Bug fixes, minor improvements

### Release Checklist
- [ ] Update version in `pyguard/__init__.py`
- [ ] Update version in `pyproject.toml`
- [ ] Update version in `Dockerfile`
- [ ] Update version badge in `README.md`
- [ ] Update CHANGELOG.md with release date
- [ ] Run full test suite (`pytest`)
- [ ] Build package (`python -m build`)
- [ ] Create git tag (`git tag v0.3.0`)
- [ ] Push to GitHub (`git push && git push --tags`)
- [ ] Publish to PyPI (`python -m twine upload dist/*`)
- [ ] Create GitHub release with notes

**Note**: Use `scripts/release.sh` to automate these steps.

---

## Links
- [Homepage](https://github.com/cboyd0319/PyGuard)
- [Documentation](https://github.com/cboyd0319/PyGuard/docs)
- [Issue Tracker](https://github.com/cboyd0319/PyGuard/issues)
- [PyPI Package](https://pypi.org/project/pyguard/) (coming soon)

---

[Unreleased]: https://github.com/cboyd0319/PyGuard/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/cboyd0319/PyGuard/releases/tag/v0.3.0
