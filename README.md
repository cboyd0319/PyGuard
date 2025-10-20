<div align="center">

<img src="docs/images/logo.png" alt="PyGuard Logo" width="200">

# PyGuard

### **Python security & code quality analysis with auto-fixes**

Replace 7+ tools with one • 179+ auto-fixes • 100% local, zero telemetry

![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Ready-brightgreen.svg)](https://github.com/marketplace/actions/pyguard-security-scanner)

[![Code Scanning](https://github.com/cboyd0319/PyGuard/actions/workflows/codeql.yml/badge.svg)](https://github.com/cboyd0319/PyGuard/actions/workflows/codeql.yml)
[![Test Action](https://github.com/cboyd0319/PyGuard/actions/workflows/test-action.yml/badge.svg)](https://github.com/cboyd0319/PyGuard/actions/workflows/test-action.yml)
[![Lint](https://github.com/cboyd0319/PyGuard/actions/workflows/lint.yml/badge.svg)](https://github.com/cboyd0319/PyGuard/actions/workflows/lint.yml)
[![Scorecard](https://github.com/cboyd0319/PyGuard/actions/workflows/scorecard.yml/badge.svg)](https://github.com/cboyd0319/PyGuard/actions/workflows/scorecard.yml)
[![codecov](https://codecov.io/github/cboyd0319/PyGuard/graph/badge.svg?token=6BZPB1L79Z)](https://codecov.io/github/cboyd0319/PyGuard)

[Quickstart](#-quickstart) •
[Features](#-features) •
[Documentation](docs/index.md) •
[GitHub Action](docs/guides/github-action-guide.md)

</div>

---

## What is PyGuard?

**The problem:** Juggling 7+ security and quality tools (Bandit, Ruff, Pylint, Black, isort, mypy, Semgrep) creates overlapping reports, config conflicts, and no unified auto-fix workflow.

**The solution:** PyGuard consolidates everything into a single AST-based analyzer that finds vulnerabilities, enforces code quality, generates compliance reports, and **fixes issues automatically** — all while running 100% locally with zero telemetry.

### Who is this for?

- **Python developers** who want comprehensive security and quality checks without tool sprawl
- **Security teams** enforcing OWASP ASVS and CWE compliance
- **DevSecOps engineers** automating security scanning in CI/CD pipelines
- **Open source maintainers** needing SARIF reports for GitHub Security tab

### What's New

- **10-100x faster scanning** with RipGrep integration
- **Secret scanning** finds hardcoded credentials in seconds (114x faster)
- **Import analysis** detects circular dependencies and god modules
- **Test coverage checks** identify untested code automatically
- **Compliance tracking** extracts OWASP/CWE references from code comments
- **GitHub Action** ready for immediate CI/CD integration

### 🛡️ Security-First Design

PyGuard practices what it preaches - **one of the most secure Python projects on GitHub**:

- **🔒 Supply Chain Security**: 2,648 dependencies with SHA256 hash verification
- **✅ SLSA Level 3**: Build provenance with signed attestations
- **🔍 Automated Scanning**: Bandit, Semgrep, CodeQL, OSSF Scorecard in CI
- **📋 SBOM Generation**: SPDX 2.3 and CycloneDX formats for all releases
- **🎯 Zero Critical Vulnerabilities**: Continuous security monitoring and patching
- **📚 Security Audit**: [Full audit report](security/SECURITY_AUDIT_2025.md) - Grade A+ (95/100)

See [SECURITY.md](SECURITY.md) and [docs/DEPENDENCY_MANAGEMENT.md](docs/DEPENDENCY_MANAGEMENT.md) for details.

---

## Quickstart

### Option 1: GitHub Action (Recommended for CI/CD)

Add PyGuard to your repository in 30 seconds:

```yaml
# .github/workflows/pyguard.yml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cboyd0319/PyGuard@main
        with:
          paths: '.'
          scan-only: 'true'
          upload-sarif: 'true'
```

**What it does:**
- Automatically scans your code on every push/PR
- Uploads findings to GitHub Security tab
- Comments on PRs with vulnerability details
- Blocks merges on critical issues

[Full GitHub Action Guide →](docs/guides/github-action-guide.md)

### Option 2: Local Installation

Install from source (PyPI coming soon):

```bash
# Install from source (PyPI coming soon)
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .

# Verify installation
pyguard --version
```

### Option 3: Quick Commands

```bash
# Scan and auto-fix entire project
pyguard src/

# Security fixes only (skip formatting)
pyguard src/ --security-only

# Scan without applying changes (CI mode)
pyguard src/ --scan-only

# Fast mode (10-100x faster with RipGrep)
pyguard src/ --fast

# Secret scanning (find hardcoded credentials)
pyguard src/ --scan-secrets --sarif

# Import analysis (circular dependencies)
pyguard src/ --analyze-imports

# Test coverage check
pyguard src/ --check-test-coverage

# Generate SARIF for GitHub Security
pyguard src/ --scan-only --sarif
```

**Output:** Backups in `.pyguard_backups/`, fixes applied in-place, HTML report at `pyguard-report.html`

New to PyGuard? Follow the [5-minute tutorial](docs/index.md)

---

## Features

<table>
<tr>
<td width="50%">

**Security Scanning**
- 55+ vulnerability checks (OWASP ASVS v5.0 aligned)
- Code injection (eval, exec, compile)
- SQL/NoSQL/LDAP injection detection
- Hardcoded secrets scanning (AWS, GitHub, JWT)
- Weak cryptography detection (MD5, SHA1)
- SSRF, XXE, and path traversal checks
- Framework-specific rules (Django, Flask, FastAPI)
- **179+ auto-fixes** (most comprehensive available)

**RipGrep Integration** (NEW)
- 10-100x faster scanning on large codebases
- Secret scanning in 3.4s (vs 390s AST-only)
- Import analysis 16x faster
- Test coverage checks 15x faster
- Automatic fallback if RipGrep unavailable
- Zero configuration required

**Code Quality**
- 150+ quality rules (PEP 8, Pylint, Bugbear)
- Cyclomatic complexity analysis
- Code smell detection
- Missing docstring checks
- Mutable default detection
- Magic number identification
- Type checking improvements

</td>
<td width="50%">

**Compliance & Reporting**
- **10+ frameworks**: OWASP ASVS, CWE, PCI DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP
- SARIF 2.1.0 output for GitHub Security
- HTML reports with severity categorization
- CSV export for audit trails
- Compliance tracking from code comments
- CWE/OWASP vulnerability mapping
- Risk scoring and prioritization

**GitHub Integration**
- GitHub Action for CI/CD
- Automatic SARIF upload
- PR annotations with fix suggestions
- Security trend tracking
- Policy enforcement (block on critical)
- Zero-config setup

**Supply Chain Security**
- Dependency vulnerability scanning
- SBOM generation (CycloneDX/SPDX)
- License compliance detection
- Risk scoring per dependency
- Known CVE detection

**Developer Experience**
- AST-based (10-100x faster than regex)
- Watch mode for continuous monitoring
- Git hooks for pre-commit checks
- VS Code integration (planned)
- Parallel processing
- Incremental analysis

</td>
</tr>
</table>

---

## ⚡ RipGrep Integration (NEW)

PyGuard now includes optional RipGrep integration for **10-100x performance improvements** on large codebases:

### Features

- **Fast Mode (`--fast`)**: Pre-filter files using RipGrep before AST analysis
  - Dramatically reduces scan time for large projects
  - Only runs deep analysis on suspicious files
  - Example: 10,000 files scanned in 52s instead of 480s

- **Secret Scanning (`--scan-secrets`)**: Detect hardcoded credentials in seconds
  - AWS keys, GitHub tokens, API keys, passwords, JWT tokens
  - Database connection strings, private keys
  - SARIF export for GitHub Security tab
  - 114x faster than AST-only scanning

- **Import Analysis (`--analyze-imports`)**: Find circular imports and god modules
  - Detect circular dependency chains
  - Identify over-imported modules (code smells)
  - 16x faster with RipGrep

- **Test Coverage (`--check-test-coverage`)**: Find modules without tests
  - Identify untested code
  - Calculate coverage percentage
  - 15x faster analysis

- **Compliance Tracking (`--compliance-report`)**: Extract OWASP/CWE references
  - Generate audit trail from code comments
  - Map findings to compliance frameworks

### Installation

RipGrep is optional but recommended for best performance:

```bash
# macOS
brew install ripgrep

# Ubuntu/Debian
apt install ripgrep

# Windows
winget install BurntSushi.ripgrep.MSVC

# Verify installation
rg --version
```

PyGuard automatically detects RipGrep and falls back gracefully if unavailable.

### Performance Benchmarks

| Task | AST-Only | With RipGrep | Speedup |
|------|----------|--------------|---------|
| Full security scan (10k files) | 480s | 52s | **9.2x** |
| Secret scanning | 390s | 3.4s | **114.7x** |
| Import analysis | 67s | 4.1s | **16.3x** |
| Test coverage check | 12s | 0.8s | **15x** |

See [RipGrep Integration Guide](docs/guides/RIPGREP_INTEGRATION.md) for full documentation.

## What this is

Static analysis tool for Python. Finds security vulnerabilities, enforces code quality standards, generates compliance reports, and fixes issues automatically.

**What it does**:
- Finds 55+ security vulnerabilities (SQL injection, XSS, hardcoded secrets, command injection, SSRF)
- Enforces 150+ code quality rules (PEP 8, Pylint, Bugbear, code smells, best practices)
- Framework-specific checks (Django, Flask, FastAPI, Pandas, Pytest)
- Maps to 10+ compliance frameworks (OWASP ASVS, CWE, PCI DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR)
- ML pattern recognition, anomaly detection, risk scoring
- **179+ auto-fixes** (safe and unsafe modes) — only tool with complete auto-fix coverage
- Supply chain security (dependency scanning, SBOM generation, license detection)
- AST-based (10-100x faster than regex), parallel processing

**Built for**: Python developers, security teams, DevSecOps engineers, compliance officers, CI/CD pipelines.

**Problem solved**: Juggling 7+ tools with overlapping reports, config conflicts, and no unified auto-fix. PyGuard replaces them all.

**Privacy**: Runs locally. No telemetry. No SaaS. No external API calls (except optional MCP integrations).

---

## Installation

### Prerequisites

<table>
  <thead>
    <tr>
      <th>Tool</th>
      <th>Version</th>
      <th>Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Python</strong></td>
      <td>≥ 3.11</td>
      <td>Runtime (3.13 recommended for development)</td>
    </tr>
    <tr>
      <td><strong>pip</strong></td>
      <td>latest</td>
      <td>Package manager</td>
    </tr>
    <tr>
      <td><strong>RipGrep</strong> (optional)</td>
      <td>≥ 13.0</td>
      <td>10-100x faster scanning (auto-detected)</td>
    </tr>
  </tbody>
</table>

**Optional dependencies:** Black, isort (auto-installed with PyGuard)

### Quick Install

```bash
# From source (PyPI coming soon)
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .

# Verify installation
pyguard --version

# Optional: Install RipGrep for 10-100x faster scanning
# macOS
brew install ripgrep

# Ubuntu/Debian
apt install ripgrep

# Windows
winget install BurntSushi.ripgrep.MSVC
```

## Usage

### Basic — Default happy-path

```bash
# Fix entire project
pyguard src/

# Single file
pyguard myfile.py
```

Creates backups in `.pyguard_backups/`, applies fixes, generates `pyguard-report.html`.

### Advanced — Common non-defaults

```bash
# Security only, no formatting
pyguard src/ --security-only

# Scan for CI/CD (no file changes)
pyguard src/ --scan-only

# Generate SARIF report for GitHub Code Scanning
pyguard src/ --scan-only --sarif --no-html

# Skip backup creation
pyguard src/ --no-backup

# Exclude patterns
pyguard src/ --exclude "tests/*" --exclude "migrations/*"

# Watch mode (re-analyze on file changes)
pyguard src/ --watch

# Use config file
pyguard src/ -c pyguard.toml

# Fast mode with RipGrep pre-filtering
pyguard src/ --fast

# Secret scanning
pyguard src/ --scan-secrets

# Import analysis
pyguard src/ --analyze-imports

# Test coverage check
pyguard src/ --check-test-coverage
```

### Git Hooks

Integrate PyGuard into your Git workflow:

```bash
# Install pre-commit hook for secret scanning
cp examples/hooks/pre-commit-secret-scan .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Or use fast security scan
cp examples/hooks/pre-commit-fast-scan .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

See [examples/hooks/README.md](examples/hooks/README.md) for more options.

Sample config (`pyguard.toml`):

```toml
[general]
log_level = "INFO"
backup_dir = ".pyguard_backups"
max_backups = 10

[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM", "LOW"]

[formatting]
line_length = 100
use_black = true
use_isort = true
```

## Configuration

| Key | Type | Default | Example | Notes |
|-----|------|---------|---------|-------|
| `general.log_level` | string | "INFO" | "DEBUG" | Logging verbosity |
| `general.backup_dir` | string | ".pyguard_backups" | "backups/" | Backup location |
| `general.max_backups` | int | 10 | 5 | Max backup files to keep |
| `security.enabled` | bool | true | false | Toggle security checks |
| `security.severity_levels` | list | ["HIGH","MEDIUM","LOW"] | ["HIGH"] | Filter by severity |
| `formatting.line_length` | int | 100 | 88 | Max line length |
| `formatting.use_black` | bool | true | false | Enable Black formatter |
| `formatting.use_isort` | bool | true | false | Enable isort |

Create `pyguard.toml` in project root or use `~/.config/pyguard/config.toml`.

### GitHub Integration

**Option 1: Use PyGuard as a GitHub Action (Recommended)**

```yaml
# .github/workflows/pyguard-security.yml
name: PyGuard Security Scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cboyd0319/PyGuard@main
        with:
          paths: '.'
          scan-only: 'true'
          upload-sarif: 'true'
```

**Option 2: Install and Run PyGuard**

```yaml
# .github/workflows/pyguard-manual.yml
name: PyGuard Security Scan

on: [push, pull_request]

permissions:
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.13'
      - run: # PyGuard is not yet on PyPI - install from source
      - run: pyguard . --scan-only --sarif --no-html
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pyguard-report.sarif
```

**What you get:**
- ✅ Upload to GitHub Security tab
- ✅ SARIF 2.1.0 compliant reports
- ✅ CWE/OWASP vulnerability mappings
- ✅ Fix suggestions for each issue
- ✅ Security trend tracking
- ✅ Pull request annotations

**📖 See [GitHub Action Guide](docs/guides/github-action-guide.md) for complete setup instructions and examples**

See [docs/index.md](docs/index.md) for the documentation hub.

**📖 [COMPLETE CAPABILITIES REFERENCE](docs/reference/capabilities-reference.md) — Detailed catalog of features**

**🎯 [GITHUB ACTION GUIDE](docs/guides/github-action-guide.md) — Using PyGuard in GitHub Actions with examples and best practices**

## Advanced Features (NEW!)

PyGuard now includes powerful development workflow integrations:

- **🔄 CI/CD Integration** — Auto-generate configs for GitHub Actions, GitLab CI, CircleCI, Azure Pipelines
- **⚡ Performance Profiler** — Detect performance bottlenecks and optimization opportunities  
- **🔗 Dependency Analyzer** — Visualize dependencies, detect circular imports and god modules
- **📋 Custom Rules Engine** — Define your own security/quality rules via TOML or Python API

[Learn more →](docs/guides/ADVANCED_FEATURES.md)

**Core vulnerabilities** — OWASP ASVS v5.0, CWE Top 25 aligned
- Code injection (eval, exec, compile) — CWE-95
- Unsafe deserialization (yaml.load, pickle) — CWE-502
- Command injection (shell=True, os.system) — CWE-78
- SQL injection (string concatenation) — CWE-89
- Hardcoded secrets (passwords, API keys) — CWE-798
- Weak crypto (MD5, SHA1) — CWE-327
- Insecure random (random instead of secrets) — CWE-330
- Timing attacks (non-constant-time comparisons) — CWE-208

**Injection attacks**
- XXE (XML External Entity) — CWE-611
- LDAP injection — CWE-90
- NoSQL injection (MongoDB) — CWE-943
- CSV injection (formula injection) — CWE-1236
- Template injection (Jinja2/Mako SSTI) — CWE-1336
- GraphQL injection — CWE-943

**Network & file security**
- SSRF (Server-Side Request Forgery) — CWE-918
- Insecure HTTP — CWE-319
- Path traversal — CWE-22
- Insecure temp files — CWE-377
- Format string bugs — CWE-134

**Access control & sessions**
- IDOR (Insecure Direct Object Reference) — CWE-639
- Mass assignment — CWE-915
- Insecure cookies (missing HttpOnly/Secure) — CWE-1004
- JWT security (weak algorithms) — CWE-327
- Clickjacking (missing X-Frame-Options) — CWE-1021

**Information disclosure**
- Secret scanning (AWS, GCP, Azure, Slack, GitHub tokens)
- Database credentials (MongoDB, Redis, PostgreSQL URIs)
- Memory disclosure (traceback, locals(), vars())
- Debug code (pdb, ipdb, breakpoint())

**Supply chain**
- Dependency scanning (finds known vulnerabilities)
- SBOM generation (CycloneDX format)
- License detection
- Risk scoring

**20+ auto-fixes** — most comprehensive security auto-fixes available
- GraphQL injection → parameterized queries
- JWT 'none' algorithm → RS256
- SSTI render_template_string → safe templates
- Missing API rate limiters → @limiter decorators
- MD5/SHA1 → SHA256
- DES → AES encryption
- SQL injection → parameterized queries
- XSS → output encoding
- Container privileged mode → secure defaults

**Code quality** — SWEBOK aligned
- Cyclomatic complexity (threshold: 10)
- Long methods (>50 lines)
- Too many parameters (>6)
- Missing docstrings
- Mutable defaults
- Type checks (type() vs isinstance())
- Magic numbers
- Bare except clauses

**Formatting**
- Black (uncompromising formatter)
- isort (import sorting)
- autopep8 (PEP 8 compliance)
- Trailing whitespace removal
- Line ending normalization

## Why PyGuard

### Comprehensiveness

- **55+ security checks** vs Bandit (~10), Semgrep (~15), Ruff (~15)
- **150+ code quality rules** covering PEP 8, Pylint, Bugbear, Refurb, PIE, pyupgrade patterns
- **150+ auto-fixes** (safe + unsafe modes) — most comprehensive security auto-fixes available
- **Framework-specific rules** for Django, Flask, FastAPI, Pandas, Pytest
- **10+ compliance frameworks** — OWASP ASVS, CWE, PCI DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX

### Technology

- **AST-based analysis** — 10-100x faster than regex, eliminates false positives from comments/strings
- **ML-powered detection** — pattern recognition, anomaly detection, risk scoring
- **Context-aware** — understands Python semantics, not text patterns
- **Supply chain security** — dependency scanning, SBOM generation (CycloneDX/SPDX), license detection

### Production Quality

- **1002 tests, 82% coverage** — tested, production-ready
- **51 specialized modules** — 26,886 lines of analysis code
- **100% local** — no SaaS, no telemetry, no external dependencies for core functionality
- **Privacy-first** — all analysis happens on your machine, no data leaves your environment

### Unified Platform

**Replaces 7+ tools:**
1. Bandit (security scanning)
2. Semgrep (pattern matching)
3. Ruff (fast linting)
4. Pylint (code quality)
5. Black (code formatting)
6. isort (import sorting)
7. mypy (type checking - partial)

Single config file. Single command. Unified reports.

## Security

**Secrets:** Use environment variables. Never commit credentials. PyGuard requires no secrets (reads local files only). Optional: `PYGUARD_LOG_LEVEL` for logging control.

**Least privilege:** Read access to scan files, write access to fix files. No network access required (runs offline). No elevated privileges needed.

**Supply chain:** Releases signed with GPG (v1.0+). SBOM published at `/releases/tag/v*` (CycloneDX format). Dependencies: 14 packages from PyPI (see pyproject.toml).

**Disclosure:** GitHub Security Advisories or https://github.com/cboyd0319 (see SECURITY.md)

---

## Troubleshooting

### Common Issues

<details>
<summary><strong>Error: SyntaxError: invalid syntax</strong></summary>

**Cause:** File contains invalid Python syntax

**Fix:** Verify syntax before scanning:

```bash
python -m py_compile <file>
```

</details>

<details>
<summary><strong>Error: FileNotFoundError: .pyguard_backups</strong></summary>

**Cause:** Backup directory missing or no write permissions

**Fix:** PyGuard creates this automatically. Check parent directory permissions:

```bash
ls -la . | grep pyguard_backups
chmod 755 .
```

</details>

<details>
<summary><strong>Error: PermissionError: [Errno 13]</strong></summary>

**Cause:** No write access to file or backup directory

**Fix:** Check permissions:

```bash
# Fix file permissions
chmod 644 path/to/file.py

# Fix directory permissions
chmod 755 path/to/directory
```

</details>

<details>
<summary><strong>Slow performance on large codebases</strong></summary>

**Cause:** Scanning unnecessary files (tests, migrations, vendor code)

**Fix:** Use `--exclude` patterns or `--fast` mode:

```bash
# Exclude specific directories
pyguard src/ --exclude "*/tests/*" --exclude "*/migrations/*"

# Use RipGrep fast mode (10-100x faster)
pyguard src/ --fast
```

See [Performance Guide](docs/guides/RIPGREP_INTEGRATION.md) for optimization tips.

</details>

<details>
<summary><strong>Error: TypeError: 'NoneType' object is not iterable</strong></summary>

**Cause:** Code uses unsupported Python feature (rare edge case)

**Fix:** Report issue with minimal code sample:

[File a bug report →](https://github.com/cboyd0319/PyGuard/issues/new?template=bug_report.md)

</details>

**More help:** [Troubleshooting Guide](docs/guides/TROUBLESHOOTING.md) • [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)

## Performance

**Expected throughput**
- Single file: 10-50ms (depends on file size and complexity)
- 1000 files (sequential): ~30s
- 1000 files (parallel, 8 cores): ~5s (6x speedup)
- Per-line average: ~1ms

**Latency characteristics**
- AST parsing: 5-10x faster than regex for simple patterns
- AST parsing: 50-100x faster than regex for complex patterns
- Cache hit: instant (skips unchanged files by content hash)
- First run: full scan
- Subsequent runs: only changed files

**Limits**
- File size: tested up to 10,000 lines per file
- Project size: tested up to 100,000 total lines
- Memory: ~50MB baseline + ~1KB per file

## Roadmap

Current: v0.3.0 (991 tests, 82% coverage)

Planned:
- [ ] v0.4.0 — Watch mode, pre-commit hooks, VS Code extension
- [ ] v0.5.0 — LSP support, git diff analysis
- [ ] v1.0.0 — Production stable, >90% coverage, signed releases

See [docs/development/UPDATEv2.md](docs/development/UPDATEv2.md) for development status.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to run tests, lint, format code
- Branch naming and commit conventions
- PR process and review requirements
- Release management

Quick start:
```bash
git clone https://github.com/YOUR_USERNAME/PyGuard.git
cd PyGuard
pip install -e ".[dev]"
make test
make lint
```

## Maintenance

Dependabot auto-updates dependencies weekly. Auto-merges patch/minor updates after CI passes.

---

## Documentation

### Getting Started
- **[Documentation Index](docs/index.md)** - Complete documentation map
- **[GitHub Action Guide](docs/guides/github-action-guide.md)** - CI/CD integration
- **[Capabilities Reference](docs/reference/capabilities-reference.md)** - Detailed feature catalog

### Advanced Features
- **[RipGrep Integration](docs/guides/RIPGREP_INTEGRATION.md)** - 10-100x faster scanning
- **[Advanced Features](docs/guides/ADVANCED_FEATURES.md)** - CI/CD, profiling, custom rules
- **[Configuration Guide](docs/guides/CONFIGURATION.md)** - pyguard.toml reference

### Full Documentation Index
See [docs/index.md](docs/index.md) for complete documentation map.

---

## License

**MIT License** - See [LICENSE](LICENSE) for full text.

```
✅ Commercial use allowed
✅ Modification allowed
✅ Distribution allowed
✅ Private use allowed
📋 License and copyright notice required
```

**TL;DR:** Use it however you want. Just include the license.

Learn more: https://choosealicense.com/licenses/mit/

---

## Support & Community

**Need help?**
- 🐛 [File a bug report](https://github.com/cboyd0319/PyGuard/issues/new?template=bug_report.md)
- 💡 [Request a feature](https://github.com/cboyd0319/PyGuard/discussions/new?category=feature-requests)
- 💬 [Ask a question](https://github.com/cboyd0319/PyGuard/discussions/new?category=q-a)
- 🔒 [Report a security issue](SECURITY.md) (private)

**Resources:**
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development setup and contribution guidelines
- [Changelog](docs/development/UPDATEv2.md) - Release history and roadmap
- [GitHub Marketplace](https://github.com/marketplace/actions/pyguard-security-scanner) - PyGuard Action

---

<div align="center">

## ⭐ Spread the Word

If PyGuard helps secure your Python projects, **give us a star** ⭐

[![Star History](https://img.shields.io/github/stars/cboyd0319/PyGuard?style=social)](https://github.com/cboyd0319/PyGuard/stargazers)

**Active Development** • **Production-Ready** • **Community-Driven**

Made with ❤️ for Python developers who value security

[⬆ Back to top](#pyguard)

</div>
