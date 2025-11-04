# Copilot Instructions — PyGuard

Purpose: Provide clear, enforceable guidance so changes remain aligned with PyGuard's mission, security posture, testing rigor, and documentation standards.

## Mission & Non‑Negotiables

- World-class Python security & code quality analysis with ML-powered detection and auto-fix capabilities.
- Private-by-default: 100% privacy, zero telemetry. Offline-first operation is required.
- Comprehensive coverage: 720+ security checks (240% of target), 20 framework integrations (100% complete).
- Policy-as-code: TOML configuration, 10+ compliance frameworks (OWASP, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX).
- Auto-fix with safety: 199+ fixes with 100% coverage, backup/rollback, idempotent operations.
- GitHub integration: SARIF 2.1.0 output, Security tab integration, native GitHub Action support.

CRITICAL Repo Rules (must follow)
- Zero telemetry. Never ship code that phones home or collects analytics.
- Avoid doc sprawl. Do not create a new doc for every small task. Prefer updating canonical docs under `docs/`. Create new documents only when a clear gap exists, and then link them from `docs/index.md`.
- Use inclusive terminology: "allowlist/denylist" not "whitelist/blacklist", "main" not "master".

Primary audience: Python developers, security engineers, DevSecOps teams, open source maintainers.
Target OS: Linux → macOS → Windows.

## Architecture Snapshot

- Python 3.11+ codebase: 105 Python files, 102 library modules, 91,000+ lines of code
- Core architecture: CLI → AST Analysis → Detection → Auto-Fix → Report Generation
- Detection engines:
  - `pyguard/lib/security.py` — Core security vulnerability detection (720+ checks)
  - `pyguard/lib/ast_analyzer.py` — AST-based static analysis with SecurityVisitor and CodeQualityVisitor
  - `pyguard/lib/advanced_security.py` — Taint tracking, race conditions, ReDoS, integer overflow
  - `pyguard/lib/ml_detection.py` — ML-powered pattern recognition and risk scoring
  - `pyguard/lib/enhanced_detections.py` — Advanced detection patterns for complex vulnerabilities
- Framework support: Django, Flask, FastAPI, Pandas, Pytest, Tornado, Celery, NumPy, TensorFlow, Pyramid, SQLAlchemy, asyncio, Sanic, Quart, Bottle, Scikit-learn, SciPy, Peewee, Pony, Tortoise (20 total)
- Auto-fix system: 199+ fixes in `pyguard/lib/security.py`, `pyguard/lib/ultra_advanced_fixes.py`, `pyguard/lib/best_practices.py`
- Reporting: JSON, HTML, SARIF 2.1.0, console output with severity filtering
- Integration: GitHub Action, pre-commit hooks, CI/CD pipelines

## Documentation Policy (must follow)

- All canonical docs live under `docs/` only.
- Allowed root stubs (minimal link‑only): `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `ROADMAP.md`.
- This file (`.github/copilot-instructions.md`) is an operational exception.
- Standards: see `docs/development/workflows/copilot-instructions.md` for comprehensive development guide.
  - markdownlint enforced (line length ≤ 120 chars, MD013); Vale for terminology and spelling.
  - Active voice; consistent terminology; relative links.
  - Runnable examples with expected output where useful.

## Testing & Coverage Requirements

- Repo‑wide coverage ≥ 70% (currently 84%); critical modules ~90% (security, AST analysis, auto-fix).
- Coverage enforced in CI (fail‑under gates in pytest configuration).
- pytest + pytest‑cov for all tests; coverage reports in HTML and XML.
- Test structure:
  - Unit tests: `tests/unit/` (112 test files)
  - Integration tests: `tests/integration/` for CLI and multi-file operations
  - Fixtures: `tests/fixtures/` for deterministic test data
- Test naming: `test_*.py` files, `Test*` classes, `test_*` methods.
- Golden files for SARIF/JSON output validation; property-based tests for normalization.

## CI Rules & Required Checks

- Coverage job with fail‑under thresholds (repo ≥70%; critical modules ≥90%).
- Docs checks: markdownlint, Vale, link check (lychee); verify docs are under `docs/` except allowlisted stubs and this file.
- Security: CodeQL, Bandit scanning, supply chain policies, dependency scanning.
- Linting: Ruff (primary), Pylint, Flake8, mypy type checking.
- Quality gates: All PRs must pass before merge; no lowering existing coverage.

## Single Source of Truth

- Capabilities Reference: `docs/reference/capabilities-reference.md` — Complete feature catalog with current statistics.
- Root README: Overview, quickstart, and links into `docs/` (don't duplicate detailed content).
- All user/developer docs: under `docs/` (reference, guides, development notes).
- Development guide: `docs/development/workflows/copilot-instructions.md` — Comprehensive development workflows and standards.

## When Adding or Changing Features

1) Update reference and guides:
   - `docs/reference/capabilities-reference.md` — Feature catalog, statistics, competitive position
   - `docs/guides/RIPGREP_INTEGRATION.md` — Performance features (RipGrep integration)
   - `docs/guides/github-action-guide.md` — CI/CD integration examples
   - `docs/guides/ADVANCED_FEATURES.md` — Advanced features and configurations
   - `docs/guides/CONFIGURATION.md` — pyguard.toml reference
2) Update root `README.md` where applicable:
   - Feature bullets in "Features" section
   - Statistics in "Production Quality" section
   - Usage examples if CLI flags change
3) Update CLI help text and examples in `pyguard/cli.py`.
4) If detection patterns change: Update security rules in code and documentation.
5) Run validation:
   ```bash
   make test && make lint
   pyguard pyguard/ --scan-only  # Use PyGuard to scan itself
   ```

## Current Statistics (Keep Updated)

Track these in `docs/reference/capabilities-reference.md` and README.md:
- **Library Modules:** 102 (verify with `find pyguard/lib -name "*.py" | wc -l`)
- **Lines of Code:** 91,000+ (verify with `find pyguard/lib -name "*.py" | xargs wc -l`)
- **Test Files:** 112 (verify with `find tests -name "test_*.py" | wc -l`)
- **Test Coverage:** 84% (from pytest-cov output)
- **Security Checks:** 720+ vulnerability types
- **Auto-Fixes:** 199+ with 100% coverage (safe mode default, unsafe mode opt-in)
- **Frameworks:** 20 (Django, Flask, FastAPI, Pandas, Pytest, Tornado, Celery, NumPy, TensorFlow, Pyramid, SQLAlchemy, asyncio, Sanic, Quart, Bottle, Scikit-learn, SciPy, Peewee, Pony, Tortoise)
- **Compliance Frameworks:** 10+ (OWASP, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX)

## Performance & Integrations

**RipGrep Features** (keep documented in RIPGREP_INTEGRATION.md):
- Fast mode (`--fast`) — 10x faster pre-filtering
- Secret scanning (`--scan-secrets`) — 114x faster
- Import analysis (`--analyze-imports`) — 16x faster
- Test coverage (`--check-test-coverage`) — 15x faster
- Compliance tracking (`--compliance-report`)

**GitHub Integration** (keep examples current in github-action-guide.md):
- SARIF 2.1.0 output format
- Security tab integration with annotations
- PR annotations and inline comments
- Action configuration examples
- Pre-commit hook support

## Documentation Style Guidelines

- **Format:** Bulleted, scannable, answer-first; lines ≤ 120 chars (MD013)
- **Examples:** Runnable code blocks with expected output
- **Links:** Use relative paths; maintain consistency
- **Voice:** Active voice, no hedging (enforced by Vale)
- **Commands:** Include flags and parameters; show real usage

## Security & Privacy Requirements

- SLSA Level 3 provenance; signed releases; checksums.
- Zero telemetry; no outbound data collection, ever.
- No PII in logs; structured JSON logging only.
- Secrets handling: Environment variables only, never hardcoded.
- Backup before fix: Always create backups before destructive operations.
- Auto-fix safety: Default "scan-only" mode; explicit `--fix` flag required for changes.

## Development Workflow Standards

- Python 3.11+ required; Python 3.13 recommended for development.
- Virtual environment: Always activate before development; use `make dev` for setup.
- Type hints: Required for all new code; mypy checking enforced.
- Logging: Use `PyGuardLogger` with structured JSON; no secrets or PII.
- Error handling: Graceful degradation; don't fail entire run on single file error.
- Configuration: TOML format; precedence: CLI args > Project config > User config > System config > Defaults.

## Code Quality Standards

- **Style:** PEP 8/PEP 257 with Black formatter (line length: 100)
- **Linting:** Ruff (primary), Pylint, Flake8, mypy type checking
- **Testing:** pytest with 70%+ coverage target (currently 84%)
- **Imports:** Use `from pyguard.lib.module import Class` or `from pyguard import Class` (via __init__.py)
- **Docstrings:** Required for all public functions; Google-style format
- **Comments:** Minimal; code should be self-documenting; security notes marked with `# SECURITY:`

## Sanity Checks Before Merge

- [ ] Capabilities Reference updated with new features
- [ ] Statistics match actual codebase (modules, lines, tests, coverage)
- [ ] README.md reflects current capabilities
- [ ] No duplicate capability docs (use pointers to capabilities-reference.md)
- [ ] `docs/index.md` links to Capabilities Reference
- [ ] CLI help text matches documentation
- [ ] All cross-references valid (no broken links)
- [ ] Tests pass with coverage ≥70%
- [ ] Linters pass (ruff, pylint, mypy, flake8)
- [ ] No telemetry or outbound data collection
- [ ] No secrets committed
- [ ] Documentation only under `docs/` (except allowed stubs and this file)

## For Comprehensive Development Guide

See `docs/development/workflows/copilot-instructions.md` for:
- Complete repository structure
- Development workflows and standards
- MCP integration details (Context7, OpenAI web search, fetch, playwright)
- Coding standards and patterns
- Testing requirements and patterns
- Security detection patterns
- Data contracts and schemas
- Import patterns and module organization
- Performance guidelines
- Common pitfalls and gotchas

Questions? See `docs/index.md` for documentation hub or open an issue.
