# PyGuard — Python security scanner and auto-fixer

![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Tests](https://img.shields.io/badge/tests-991%20passing-success.svg)
![Coverage](https://img.shields.io/badge/coverage-82%25-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**TL;DR**: Install PyGuard, run it on your codebase, get security fixes and quality improvements applied automatically. Works locally, no telemetry.

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

PyGuard scans Python code for security vulnerabilities, code quality issues, and style problems. It fixes 20+ vulnerability types automatically (SQL injection, hardcoded secrets, weak crypto, unsafe deserialization). Runs locally. Zero telemetry.

Built for: developers who want fast, automated security and quality checks without third-party SaaS or complex setup.

Pain: maintaining 5 tools (Bandit + Pylint + Black + isort + Ruff) takes time and creates overlapping reports. PyGuard replaces all five.

Target users: Python developers, security teams, CI/CD pipelines.

## Prerequisites

| Item | Version | Why |
|------|---------|-----|
| Python | 3.11+ | Runtime (3.13.8 recommended for dev) |
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

PyGuard integrates seamlessly with GitHub Code Scanning via SARIF reports:

```yaml
# .github/workflows/pyguard-security-scan.yml
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

**Features:**
- 🔒 Automatic upload to GitHub Security tab
- 📊 SARIF 2.1.0 compliant reports
- 🏷️ CWE/OWASP vulnerability mappings
- 🔧 Fix suggestions for each issue
- 📈 Track security trends over time

See [docs/README.md](docs/README.md) for complete documentation.

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
- Dependency scanning (automatic vulnerability detection)
- SBOM generation (CycloneDX format)
- License detection
- Risk scoring

**20+ auto-fixes** — only tool with comprehensive security auto-fixes
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

- **55+ security checks** vs Bandit (~10), Semgrep (~15)
- **150+ auto-fixes** vs competitors (none with security auto-fix)
- **991 tests, 82% coverage** - thoroughly tested
- **10+ compliance frameworks** - OWASP, PCI DSS, HIPAA, SOC 2, ISO 27001
- **100% local** - no SaaS, no telemetry, no third-party services
- **Replaces 5 tools** - Bandit + Pylint + Black + isort + Ruff in one

## Security

**Secrets handling**
- Never commit credentials. Use environment variables or config files.
- Required: none (PyGuard reads local files only)
- Optional: `PYGUARD_LOG_LEVEL` for logging control

**Least privilege**
- PyGuard needs read access to scan files, write access to fix files.
- No network access required (runs entirely offline).
- No elevated privileges needed.

**Supply chain**
- Releases signed with GPG (planned for v1.0).
- SBOM published at `/releases/tag/v*` (CycloneDX format).
- Dependencies: 13 packages, all from PyPI (see pyproject.toml).

**Disclosure**
- Email: security@pyguard.dev (PGP key in SECURITY.md)
- Or: GitHub Security Advisories (private reporting)

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