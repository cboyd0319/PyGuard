<div align="center">

<img src="docs/images/logo.png" alt="PyGuard Logo" width="200">

# PyGuard

### Security & code quality that feels effortless

Replace 7+ static analysis tools with one fast CLI • 739 security checks • 199+ auto-fixes • 25 frameworks • 100% local, no telemetry

![Version](https://img.shields.io/badge/version-0.7.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Ready-brightgreen.svg)](https://github.com/marketplace/actions/pyguard-security-scanner)
[![codecov](https://codecov.io/github/cboyd0319/PyGuard/graph/badge.svg?token=6BZPB1L79Z)](https://codecov.io/github/cboyd0319/PyGuard)

[Quickstart](#quick-start) • [Why PyGuard](#why-developers-choose-pyguard) • [Capabilities](#capabilities-map) • [CLI](#cli--automation) • [GitHub Action](#zero-effort-ci) • [Docs](#documentation--support)

</div>

---

## PyGuard at a Glance

- **Everything in one command** – security testing, quality enforcement, formatting, dependency insights, SARIF/HTML reporting
- **739 security checks across 25 frameworks** – FastAPI, Django, Flask, Pandas, NumPy, TensorFlow, asyncio, Celery, Airflow, PySpark, SQLAlchemy, Tornado, and 14 more
- **199+ auto-fixes** – AST-powered refactors, formatting, modernization, and best-practice updates with automatic backups
- **AI/ML, supply chain, and notebook aware** – dedicated analyzers for model security, SBOM workflows, Jupyter notebooks, cloud misconfigurations
- **Designed for developer joy** – Rich-powered UI, contextual suggestions, interactive mode, watch mode, 100% local execution with zero telemetry

---

## Quick Start

```bash
pip install git+https://github.com/cboyd0319/PyGuard.git
pyguard doctor          # verifies environment
pyguard scan .          # read-only analysis
pyguard fix .           # apply safe fixes with backups
```

### 1. Install & verify (1 minute)
- Requires Python 3.11+
- `pyguard doctor` confirms dependencies, RipGrep support, optional notebook extras

### 2. Scan confidently (2 minutes)
```bash
pyguard scan src/ --sarif --json results.json
```
- Security, quality, formatting, notebooks analyzed together
- SARIF + HTML reports ready for GitHub Advanced Security

### 3. Fix issues automatically
```bash
pyguard fix src/ --interactive      # confirm each fix
pyguard fix . --security-only       # limit to security issues
pyguard fix . --formatting-only     # run formatter only
```
- Auto-fixes use backups (`.pyguard_backups/`)
- Unsafe fixes opt-in with `--unsafe`

### 4. Configure once, reuse everywhere
```bash
pyguard init --interactive
pyguard validate-config
```
- Generates `.pyguard.toml` tailored to strict, balanced, lenient, security-only, or formatting-only profiles
- Configuration discovery walks up from current directory to project root

---

## Why Developers Choose PyGuard

| Challenge | PyGuard experience |
| --- | --- |
| Tool sprawl | Replaces Bandit, Semgrep, Ruff, Pylint, Black, isort, Safety, partial mypy in one CLI |
| False positives & context switching | Rich UI groups issues by severity/framework, `pyguard explain` gives human-friendly guidance |
| Security depth | Advanced taint tracking, AI/ML lifecycle checks, mobile/IoT, blockchain, supply chain and SBOM validation |
| Compliance pressure | OWASP/CWE mapping, HTML/SARIF/compliance JSON, auto-tracked waivers |
| Continuous delivery | GitHub Action, pre-commit hooks, watch mode, JSON-RPC & webhook APIs |
| Developer time | Auto-fixes for 199+ issues, backups, diff preview, interactive mode, custom rule engine |

> PyGuard is intentionally “the tool teams *want* to run.” Every flow is optimized for minimal flags, instant remediation, and zero external services.

---

## Capabilities Map

### Security & Privacy (739 Checks)
- **Core security** (20+ checks): Hardcoded secrets, SQL/command/template injection, unsafe deserialization, weak crypto, insecure random, path traversal, SSRF, XXE
- **Advanced security** (40+ checks): Taint analysis, race conditions, integer overflow, ReDoS, timing attacks, advanced injection patterns
- **AI/ML security** (30+ checks): Model serialization (pickle/joblib), TensorFlow/PyTorch/Scikit-learn patterns, adversarial inputs, notebook scanning
- **Domain-specific**: API security (REST/GraphQL/WebSocket - 20 checks), Cloud (AWS/Azure/GCP - 15 checks), Auth (15 checks), PII detection (25 checks), Blockchain/Web3, mobile/IoT
- **Supply chain**: Dependency scanning, SBOM generation, typosquatting detection, malicious package identification

### Framework Awareness (25 Frameworks, 266+ Rules)
**Web Frameworks**: FastAPI (37 checks), Django (13 checks), Flask (7 checks), Tornado (20 checks), Pyramid (15 checks), Sanic (14 checks), Quart (15 checks), Bottle (10 checks)
**Async & Workers**: asyncio (15 checks), Celery (20 checks), PySpark (10 checks), Airflow (9 checks)
**Data & Science**: Pandas (7 checks), NumPy (15 checks), TensorFlow (20 checks), Scikit-learn (8 checks), SciPy (10 checks)
**Databases**: SQLAlchemy (14 checks), Peewee (12 checks), Pony (12 checks), Tortoise (15 checks)
**UI & Notebooks**: Streamlit (7 checks), Dash (5 checks), Gradio (6 checks), Jupyter notebooks (8+ checks)
**Testing**: Pytest (8 checks)

### Quality, Modernization & Formatting (216+ Rules)
- **PEP 8 Style** (88 rules): Comprehensive pycodestyle implementation - indentation, whitespace, blank lines, imports, line length, statements
- **Code Quality**: Pylint rules (60+), Bugbear patterns (40+), best practices (20+), complexity analysis, dead code detection
- **Modernization** (35+ patterns): Python 3.8+ idioms, pathlib migration, type annotations, f-strings, modern collections, context managers
- **Formatting**: Black-compatible formatting, isort import sorting, whitespace normalization
- **Performance**: List comprehensions, generator expressions, regex compilation, loop optimization
- All fixes classified as SAFE (automatic) or UNSAFE (requires --unsafe flag)

### Reporting & Collaboration
- **SARIF 2.1.0**: GitHub Code Scanning integration with CWE/OWASP mappings, fix suggestions, code snippets
- **HTML Reports**: ModernHTMLReporter with charts, severity breakdown, expandable details, compliance footnotes
- **JSON**: Machine-readable output for CI/CD pipelines, programmatic access
- **Console**: Rich-powered terminal UI with color coding, progress bars, severity grouping
- **Compliance**: 10+ framework mappings (OWASP ASVS, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, GDPR, CCPA, FedRAMP, SOX)
- **Remediation**: `pyguard explain <topic>` provides human-readable guidance for common vulnerabilities
- **Audit Logging**: Structured logging with correlation IDs for compliance and debugging

---

## CLI & Automation

| Command | Purpose |
| --- | --- |
| `pyguard scan [paths]` | Read-only analysis, optional SARIF/HTML/JSON output, RipGrep-powered fast mode |
| `pyguard fix [paths]` | Apply safe fixes, optional --interactive/--unsafe/--security-only/--formatting-only modes |
| `pyguard init [--interactive]` | Generate `.pyguard.toml` with guided questionnaire (strict/balanced/lenient/security/formatting profiles) |
| `pyguard validate-config` | Verify and display active configuration |
| `pyguard watch [paths]` | Watch files for changes and auto-fix in real time (perfect for development workflows) |
| `pyguard doctor` | Environment diagnostics - verifies Python version, Rich, RipGrep, notebook extras |
| `pyguard explain <topic>` | Human-readable remediation guides for security issues |
| `pyguard-hooks install` | Install/manage pre-commit or pre-push hooks (separate CLI: `pyguard-hooks`) |

### Programmatic API

```python
from pyguard import PyGuardAPI

api = PyGuardAPI()
result = api.analyze_file("service.py")
if result.has_critical_issues():
    for issue in result.critical_issues:
        print(issue.category, issue.message)
api.fix_file("service.py", unsafe=False)
```

JSON-RPC, webhook listener, and ModernHTMLReporter live in `pyguard/lib/` for IDE and CI integrations.

---

## Zero-Effort CI

### GitHub Action
```yaml
name: PyGuard
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
- Uploads SARIF to GitHub Security tab
- Blocks merges on critical issues
- Compatible with Dependabot PR gating and reusable workflows

### Pre-commit hook
```bash
pyguard-hooks install --type pre-commit
```
Adds `pyguard . --scan-only --security-only` to hooks with automatic validation/testing commands.

### Watch mode & local automation
- `pyguard watch src/` auto-fixes on save (ideal alongside `uvicorn --reload`)
- `pyguard scan . --fast --parallel` leverages RipGrep filters and multiprocessing for monorepos

---

## Architecture & Extensibility

### Core Design
- **AST-first analysis** – Python Abstract Syntax Tree parsing for 100% accurate, zero false positive detection from code vs comments/strings
- **Three-layer architecture**: CLI → Core Engine (rule_engine.py, ast_analyzer.py) → Detection Modules (114 files in lib/)
- **Modern command system**: 7 dedicated commands (scan, fix, init, validate-config, watch, doctor, explain) with clean separation of concerns

### Performance & Scalability
- **RipGrep integration**: Optional 10-100x faster scanning for large codebases with `--fast` flag
- **Parallel processing**: Multi-core analysis with configurable worker pools
- **Incremental scanning**: Smart caching based on file modification time and content hash
- **Watch mode**: Real-time file monitoring and auto-fixing with watchdog integration

### Extensibility
- **Custom rules**: TOML-based rule definitions with regex and AST pattern matching
- **Plugin architecture**: Modular detection system - each security/quality module is independently testable
- **Programmatic API**: `PyGuardAPI` class for IDE and CI/CD integrations (see api.py)
- **Multiple output formats**: SARIF 2.1.0, JSON, HTML, Console with extensible reporter system

### Supply Chain Security
- **Minimal dependencies**: Only 2 core deps (rich + watchdog), 2 optional (nbformat + nbclient for notebooks)
- **SBOM generation**: CycloneDX and SPDX bill-of-materials support
- **Dependency scanning**: Vulnerability detection, typosquatting identification, license compliance
- **Reproducible builds**: Planned for v1.0 with SLSA Level 3 provenance

Read more in `docs/reference/ARCHITECTURE.md`, `docs/reference/architecture/IMPLEMENTATION_SUMMARY.md`, and `docs/reference/capabilities-reference.md`.

---

## Documentation & Support

Category | Key resources
--- | ---
Getting started | [Quickstart](QUICKSTART.md), [docs/index.md](docs/index.md)
CLI & automation | [GitHub Action Guide](docs/guides/github-action-guide.md), [Git Hooks](docs/guides/git-hooks-guide.md), [Advanced Integrations](docs/guides/advanced-integrations.md)
Advanced use | [Auto-fix Guide](docs/guides/auto-fix-guide.md), [Notebook Security](docs/guides/notebook-security-guide.md), [Plugin Architecture](docs/guides/PLUGIN_ARCHITECTURE.md)
Security & compliance | [SECURITY.md](SECURITY.md), [Supply Chain Security](docs/guides/SUPPLY_CHAIN_SECURITY.md), [Security Quickstart](docs/security/SECURITY_QUICKSTART.md), [Threat Model](security/THREAT_MODEL.md)
Reference | [Capabilities Reference](docs/reference/capabilities-reference.md), [Security Rules](docs/reference/security-rules.md), [Code Scanning Alerts](docs/reference/CODE-SCANNING-ALERTS.md)
Project health | [ROADMAP.md](ROADMAP.md), [CHANGELOG](docs/CHANGELOG.md), [TEST_PLAN](docs/TEST_PLAN.md), [COMPREHENSIVE_TEST_PLAN](docs/COMPREHENSIVE_TEST_PLAN.md)
Full inventory | [Documentation Manifest](docs/MANIFEST.md)

Need help? Open an [issue](https://github.com/cboyd0319/PyGuard/issues) or start a [discussion](https://github.com/cboyd0319/PyGuard/discussions).

---

## License

PyGuard is released under the [MIT License](LICENSE).

Security disclosures follow our [Security Policy](SECURITY.md).
