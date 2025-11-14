<div align="center">

<img src="docs/images/logo.png" alt="PyGuard Logo" width="200">

# PyGuard

### Security & code quality that feels effortless

Replace 7+ static analysis tools with one fast CLI • 700+ security checks • 199+ auto-fixes • AI/ML & supply chain aware • 100% local, no telemetry

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
- **700+ security checks & 25 frameworks** – FastAPI, Django, Flask, Pandas, NumPy, TensorFlow, asyncio, Airflow, PySpark, SQLAlchemy + more
- **199+ auto-fixes** – AST-powered refactors, formatting, modernization, and best-practice updates with automatic backups
- **AI/ML, supply chain, and notebook aware** – dedicated analyzers for LLM prompts, model serialization, SBOM/SLSA workflows, Jupyter notebooks
- **Designed for developer joy** – Rich-powered UI, contextual suggestions, optional interactive mode, 100% local execution

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
- Generates `.pyguard.toml` tailored to strict, balanced, lenient, security, or formatting-first profiles

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

### Security & Privacy
- Core security engine detects hardcoded secrets, SQL/command/template injection, unsafe serialization, weak crypto, insecure random, path traversal, SSRF, XXE
- Advanced modules: taint analysis, race conditions, integer overflow, ReDoS, dependency confusion, supply-chain attestation, SBOM validation
- AI/ML coverage: model serialization (TensorFlow/PyTorch/Sklearn), LLM prompt handling, adversarial training signals, MLOps & notebook scanning
- Domain-specific packs: cloud (AWS/Azure/GCP/K8s/Terraform), API security (REST, GraphQL, WebSockets), mobile/IoT, blockchain/Web3, business logic

### Framework Awareness
- 25+ targeted analyzers with rule IDs, OWASP/CWE mapping, and auto-fix metadata for FastAPI, Django, Flask, Pyramid, Sanic, Quart, Bottle, Tornado, asyncio, Celery, SQLAlchemy, Peewee, Tortoise, Pony, Pandas, NumPy, SciPy, TensorFlow, PySpark, Airflow, Streamlit, Dash, Gradio, Jupyter notebooks

### Quality, Modernization & Formatting
- Best-practice modules: naming, docstrings, unused code, complexity budgets, debugging statements, exception handling, performance hints
- Modernization & style: PEP8, Refurb-inspired refactors, automatic formatting (Black/isort), import hygiene, whitespace, string operations
- Optional unsafe fixes for deep refactors (guarded by prompts)

### Reporting & Collaboration
- SARIF 2.1.0, JSON, HTML (ModernHTMLReporter) with severity breakdown and compliance footnotes
- ComplianceTracker extracts OWASP/CWE references from comments and issue suppressions
- `pyguard explain` knowledge base for remediation coaching
- Audit-ready JSON logs with correlation IDs via `PyGuardLogger`

---

## CLI & Automation

| Command | Purpose |
| --- | --- |
| `pyguard scan [paths]` | Read-only analysis, optional SARIF/HTML/JSON, RipGrep-powered fast mode |
| `pyguard fix [paths]` | Apply safe fixes, optional interactive/unsafe/security-only/formatting-only modes |
| `pyguard init` | Generate `.pyguard.toml` (interactive profiles) |
| `pyguard validate-config` | Verify and print configuration |
| `pyguard watch` | Watch files for changes and auto-fix in real time |
| `pyguard doctor` | Environment diagnostics (Python, Rich, RipGrep, notebook extras) |
| `pyguard explain <topic>` | Human-readable remediation guides for common issues |
| `pyguard git-hooks` | Install/manage `pre-commit`/`pre-push` hooks |

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

- **AST-first analyzers** – shared `ASTAnalyzer`, taint engine, and rule registry across security, quality, and modernization modules
- **Rule engine & plugin system** – define custom rules in TOML, integrate third-party detectors, or extend frameworks via `pyguard.lib.plugin_system`
- **Incremental & cached scanning** – `AnalysisCache`, RipGrep pre-filter, and watch mode reduce rerun time
- **Rich UI + HTML reports** – `EnhancedConsole` for terminals, `ModernHTMLReporter` for archival dashboards
- **Secure supply chain** – SBOM, SLSA provenance, signed releases, reproducible build guides, Sigstore/TUF verification

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
