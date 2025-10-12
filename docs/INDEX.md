# PyGuard Documentation Index

Welcome to the PyGuard documentation! This index will help you find the information you need.

## 📚 Getting Started

### For Users
- [**User Guide**](user-guide.md) - Complete guide for using PyGuard
- [**Quick Start**](../README.md#quick-start) - Get up and running in minutes
- [**Configuration Guide**](configuration.md) - Customize PyGuard for your project
- [**Examples**](../examples/) - Real-world usage examples

### For Contributors
- [**Contributing Guide**](../CONTRIBUTING.md) - How to contribute to PyGuard
- [**Architecture**](ARCHITECTURE.md) - Understanding PyGuard's design
- [**Development Setup**](../scripts/setup_dev.sh) - Set up your dev environment

## 📖 Core Documentation

### Features & Capabilities

1. **[Security Rules Reference](security-rules.md)**
   - All security vulnerability checks
   - Severity levels and auto-fix capabilities
   - Examples and recommendations

2. **[Best Practices Reference](best-practices.md)**
   - Code quality improvements
   - Python conventions and standards
   - Performance considerations

3. **[API Reference](api-reference.md)**
   - Complete Python API documentation
   - Class and method references
   - Usage examples

### Configuration

- [**Configuration Guide**](configuration.md)
  - All configuration options
  - TOML file format
  - Configuration hierarchy
  - [Example Configuration](../examples/pyguard.toml.example)

### Integration

- **CI/CD Integration**
  - [GitHub Actions](.github/workflows/)
  - GitLab CI (coming soon)
  - Jenkins (coming soon)

- **Pre-commit Hooks**
  - [Installation guide](user-guide.md#pre-commit-integration)
  - [Configuration](.pre-commit-hooks.yaml)

## 🔧 Technical Documentation

### Architecture & Design

- [**Architecture Overview**](ARCHITECTURE.md)
  - System design
  - Component interactions
  - Data flow
  - Extension points

### Development

- [**Contributing**](../CONTRIBUTING.md)
  - Development workflow
  - Code standards
  - Testing guidelines
  - Pull request process

- [**Testing**](../tests/)
  - Unit tests
  - Integration tests
  - Test fixtures
  - Running tests

- [**Benchmarks**](../benchmarks/)
  - Performance testing
  - Benchmarking methodology
  - Results and trends

## 🔒 Security & Policy

- [**Security Policy**](../SECURITY.md)
  - Vulnerability reporting
  - Security best practices
  - Supported versions

- [**Code of Conduct**](../CODE_OF_CONDUCT.md)
  - Community guidelines
  - Enforcement

## 📦 Release Information

- [**Changelog**](../CHANGELOG.md) - Version history and changes
- [**Roadmap**](../README.md#roadmap) - Future plans and features
- [**License**](../LICENSE) - MIT License

## 🆘 Support & Community

### Getting Help

1. **[Issues](https://github.com/cboyd0319/PyGuard/issues)** - Bug reports and feature requests
2. **[Discussions](https://github.com/cboyd0319/PyGuard/discussions)** - Questions and community
3. **Documentation** - You're here! 📖

### Useful Links

- [GitHub Repository](https://github.com/cboyd0319/PyGuard)
- [PyPI Package](https://pypi.org/project/pyguard/) (coming soon)
- [Release Notes](../CHANGELOG.md)

## 📊 Quick Reference

### Command Line

```bash
# Basic usage
pyguard myfile.py
pyguard src/

# Options
pyguard src/ --scan-only        # No auto-fixes
pyguard src/ --security-only    # Security only
pyguard src/ --formatting-only  # Formatting only
pyguard src/ --severity HIGH    # Filter by severity
```

### Python API

```python
from pyguard import SecurityFixer, BestPracticesFixer

# Analyze code
security = SecurityFixer()
issues = security.scan_file_for_issues(file_path)
fixes = security.fix_file(file_path)
```

### Configuration

```toml
# pyguard.toml
[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM"]

[formatting]
line_length = 100
```

## 🎓 Tutorials

### Beginner
- [Your First PyGuard Run](user-guide.md#first-run)
- [Understanding Output](user-guide.md#understanding-output)
- [Basic Configuration](configuration.md#basic-setup)

### Intermediate
- [Customizing Rules](configuration.md#custom-rules)
- [CI/CD Integration](user-guide.md#cicd-integration)
- [Using as a Library](../examples/api_usage.py)

### Advanced
- [Writing Custom Rules](ARCHITECTURE.md#extension-points)
- [Performance Optimization](user-guide.md#performance)
- [Contributing](../CONTRIBUTING.md)

## 🔄 Migration Guides

- **From Bandit**: Coming soon
- **From Pylint**: Coming soon
- **From Flake8**: Coming soon

## 📈 Performance

- [**Benchmarks**](../benchmarks/README.md)
- [**Performance Tips**](user-guide.md#performance)
- [**Optimization Guide**](ARCHITECTURE.md#performance-considerations)

---

## 📝 Documentation Status

| Document | Status | Last Updated |
|----------|--------|--------------|
| User Guide | ✅ Complete | 2025-10-12 |
| API Reference | ✅ Complete | 2025-10-12 |
| Configuration | ✅ Complete | 2025-10-12 |
| Security Rules | ✅ Complete | 2025-10-12 |
| Best Practices | ✅ Complete | 2025-10-12 |
| Architecture | ✅ Complete | 2025-10-12 |
| Contributing | ✅ Complete | 2025-10-12 |

## 🤝 Contributing to Documentation

Found an issue or want to improve the documentation? See our [Contributing Guide](../CONTRIBUTING.md#documentation).

---

**Need help?** Open an [issue](https://github.com/cboyd0319/PyGuard/issues) or start a [discussion](https://github.com/cboyd0319/PyGuard/discussions).
