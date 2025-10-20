# Copilot Instructions — PyGuard

**Purpose:** Keep PyGuard's documentation and capabilities current, consistent, and discoverable.

## Project Overview

PyGuard is a comprehensive Python security & code quality platform with:
- **67 library modules**, 35,000+ lines of code, 78 test files, 84% coverage
- **55+ security checks** (OWASP ASVS, CWE Top 25, PCI-DSS, HIPAA, SOC 2, etc.)
- **179+ auto-fixes** with 100% coverage (safe + unsafe modes)
- **RipGrep integration** for 10-100x performance improvements
- **Jupyter notebook security** analysis (unique capability)
- **GitHub Action** for native CI/CD integration
- **100% local operation** with zero telemetry

## Single Source of Truth

- **Capabilities Reference:** `docs/reference/capabilities-reference.md` — Complete feature catalog
- **README:** Must link to Capabilities Reference and reflect current statistics
- **All user docs:** Live in `docs/` (guides, reference, development notes)

## Key Documentation

Essential guides to keep updated:
- `docs/guides/RIPGREP_INTEGRATION.md` — Performance features (10-100x faster)
- `docs/guides/github-action-guide.md` — CI/CD integration
- `docs/guides/ADVANCED_FEATURES.md` — CI/CD generation, profiling, custom rules
- `docs/guides/CONFIGURATION.md` — pyguard.toml reference
- `docs/development/NOTEBOOK_SECURITY_CAPABILITIES.md` — Jupyter security (points to capabilities-reference.md)

## When Adding or Changing Features

1. Update `docs/reference/capabilities-reference.md` with:
   - Module count, lines of code, test count, coverage percentage
   - New security checks or auto-fixes
   - New framework support or compliance mappings
2. Update README.md:
   - Feature bullets in "Features" section
   - Statistics in "Production Quality" section
   - Usage examples if CLI flags change
3. Update relevant guides:
   - `docs/guides/RIPGREP_INTEGRATION.md` for performance features
   - `docs/guides/github-action-guide.md` for CI/CD examples
   - `docs/guides/ADVANCED_FEATURES.md` for new integrations
4. Update CLI help text and examples in `pyguard/cli.py`
5. Run validation:
   ```bash
   make test && make lint
   pyguard pyguard/ --scan-only  # Use PyGuard to scan itself
   ```

## Documentation Style Guidelines

- **Format:** Bulleted, scannable, answer-first; lines ≤ 120 chars (MD013)
- **Examples:** Runnable code blocks with expected output
- **Links:** Use relative paths; maintain consistency
- **Voice:** Active voice, no hedging (enforced by Vale)
- **Commands:** Include flags and parameters; show real usage

## Current Statistics (Keep Updated)

Track these in `docs/reference/capabilities-reference.md` and README.md:
- **Library Modules:** 67 (verify with `find pyguard/lib -name "*.py" | wc -l`)
- **Lines of Code:** 35,000+ (verify with `find pyguard/lib -name "*.py" | xargs wc -l`)
- **Test Files:** 78 (verify with `find tests -name "test_*.py" | wc -l`)
- **Test Coverage:** 84% (from pytest-cov output)
- **Security Checks:** 55+ vulnerability types
- **Auto-Fixes:** 179+ (107 safe, 72 unsafe)
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
- Security tab integration
- PR annotations
- Action configuration examples

## Sanity Checks Before Merge

- [ ] Capabilities Reference updated with new features
- [ ] Statistics match actual codebase (modules, lines, tests, coverage)
- [ ] README.md reflects current capabilities
- [ ] No duplicate capability docs (use pointers to capabilities-reference.md)
- [ ] `docs/index.md` links to Capabilities Reference
- [ ] CLI help text matches documentation
- [ ] All cross-references valid (no broken links)

## For Comprehensive Development Guide

See `docs/development/workflows/copilot-instructions.md` for:
- Complete repository structure
- Development workflows and standards
- MCP integration details
- Coding standards and patterns
- Testing requirements
- Security detection patterns
- Data contracts and schemas
