# PyGuard — Python Security & Code Quality Analysis

![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Tests](https://img.shields.io/badge/tests-1002%20passing-success.svg)
![Coverage](https://img.shields.io/badge/coverage-82%25-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**TL;DR**: Replace 7+ tools (Bandit, Ruff, Pylint, Black, isort, mypy, Semgrep) with one. Finds 55+ security issues, enforces 150+ quality rules, fixes 179+ problems automatically. Runs locally, no telemetry.

```bash
pip install pyguard
pyguard src/
```

## Quickstart

```bash
# Install
pip install pyguard

# Scan and fix entire project
pyguard src/

# Security fixes only
pyguard src/ --security-only

# Scan without applying fixes
pyguard src/ --scan-only

# Generate SARIF for GitHub Security tab
pyguard src/ --scan-only --sarif
```

Expected output: backups in `.pyguard_backups/`, fixed files in place, HTML report at `pyguard-report.html`, optional SARIF at `pyguard-report.sarif`.

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

## Prerequisites

| Item | Version | Why |
|------|---------|-----|
| Python | 3.11+ | Runtime (3.13.9 recommended for dev) |
| pip | latest | Package manager |

Optional: Black, isort (auto-installed with PyGuard).

## Install

```bash
# From PyPI (when published)
pip install pyguard

# From source
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .

# Verify
pyguard --version
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
```

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
      - run: pip install pyguard
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

**📖 See [GitHub Action Guide](docs/github-action-guide.md) for complete setup instructions and examples**

See [docs/index.md](docs/index.md) for complete documentation hub.

**📖 [COMPLETE CAPABILITIES REFERENCE](docs/capabilities-reference.md) — Detailed catalog of ALL 55+ security checks, 150+ code quality rules, auto-fixes, and features**

**🎯 [GITHUB ACTION GUIDE](docs/github-action-guide.md) — Complete guide for using PyGuard in GitHub Actions workflows with examples and best practices**

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
- **Context-aware** — understands Python semantics, not just text patterns
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

## Troubleshooting

**`SyntaxError: invalid syntax`**
- Cause: File contains invalid Python.
- Fix: Run `python -m py_compile <file>` to verify syntax first.

**`FileNotFoundError: .pyguard_backups`**
- Cause: Backup directory missing.
- Fix: PyGuard creates this automatically. Check write permissions on parent directory.

**`PermissionError: [Errno 13]`**
- Cause: No write access to file or backup directory.
- Fix: Run with appropriate user or fix directory permissions.

**`TypeError: 'NoneType' object is not iterable`**
- Cause: Code uses unsupported Python feature (rare).
- Fix: Report issue with code sample at github.com/cboyd0319/PyGuard/issues.

**Slow performance on large codebases**
- Run with `--exclude` to skip vendor code, tests, or migrations.
- Example: `pyguard src/ --exclude "*/tests/*" --exclude "*/migrations/*"`

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

See [docs/UPDATEv2.md](docs/UPDATEv2.md) for detailed development status.

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

## License

MIT License. You can: use commercially, modify, distribute, sublicense. You cannot: hold author liable. Must: include license and copyright notice.

Full text: [LICENSE](LICENSE) | Unsure? See [choosealicense.com](https://choosealicense.com/licenses/mit/)

---

Made by [Chad Boyd](https://github.com/cboyd0319) — contributions welcome