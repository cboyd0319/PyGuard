# PyGuard Quickstart

Set up PyGuard, run your first scans, and keep fixes flowing in under ten minutes. This guide covers installation, basic usage, and integration options to get you productive fast.

**Version**: 0.7.0 | **Python**: 3.11+ | **Platforms**: macOS, Linux, Windows

---

## 1. Requirements

| Requirement | Notes |
| --- | --- |
| Python | 3.11 or newer |
| OS | macOS, Linux, Windows |
| Optional | `ripgrep` for `--fast`, `nbformat`/`nbclient` for notebook scanning |

Install directly from GitHub until PyPI/Homebrew releases land:

```bash
pip install git+https://github.com/cboyd0319/PyGuard.git
```

---

## 2. Verify your environment (1 minute)

```bash
pyguard doctor
```
- Confirms Python version, Rich UI dependencies, RipGrep, notebook extras
- Reminds you to install `.pyguard.toml` when missing

---

## 3. First scan (2 minutes)

```bash
pyguard scan src/ --sarif --json pyguard-results.json
```

What to expect:
- **739 security checks** across 25 frameworks + 216+ quality rules analyzed in one pass
- Rich console summary with color-coded severity levels
- HTML report (enabled by default) with charts and expandable details
- SARIF 2.1.0 output for GitHub Code Scanning integration
- JSON output for programmatic access and CI/CD pipelines
- Exit code `1` when HIGH/CRITICAL issues found (perfect for CI gates)

**Performance tips**:
- Add `--fast` for RipGrep pre-filtering (10-100x faster on large codebases)
- Add `--parallel` to use multiple CPU cores for concurrent analysis

---

## 4. First fixes (2 minutes)

```bash
pyguard fix src/                    # safe fixes with backups
pyguard fix api/ --interactive      # preview each fix before applying
pyguard fix . --security-only       # only apply security fixes
pyguard fix . --formatting-only     # only apply formatting fixes
pyguard fix . --unsafe              # include unsafe fixes (with prompts)
```

**Fix highlights**:
- **199+ auto-fixes**: Most comprehensive auto-fix coverage of any Python security tool
- **Automatic backups**: All files backed up to `.pyguard_backups/` before modification
- **Interactive mode**: Preview diffs in terminal and confirm each fix individually
- **Safety classification**:
  - SAFE (107+ fixes): Applied automatically - won't change behavior
  - UNSAFE (72+ fixes): Require `--unsafe` flag - may need testing
- **Scoped fixing**: Use `--security-only` or `--formatting-only` to limit scope

---

## 5. Configure once, reuse everywhere

```bash
pyguard init --interactive   # guided questionnaire
pyguard validate-config      # verify + print summary
```

**Configuration options**:
- **Profiles**: strict, balanced, lenient, security-only, formatting-only
- **Settings**: log level, exclude patterns, enabled check families, severity thresholds
- **Formatting preferences**: line length, indentation, import sorting
- **Quality thresholds**: max complexity, function length, parameter count
- **File location**: `.pyguard.toml` at repo root (auto-discovered by walking up from cwd)

**Configuration discovery**:
- Searches from current directory up to project root
- Supports per-directory overrides
- Environment variables can override config file settings
- CLI arguments override everything

Store `.pyguard.toml` at the repo root to keep CLI, CI, pre-commit hooks, and watch mode aligned.

---

## 6. Automation patterns

### Watch mode for tight feedback loops
```bash
pyguard watch app/                  # watch all files, apply safe fixes on change
pyguard watch src/ --security-only  # only security fixes
pyguard watch . --interactive       # confirm each fix
```
**Perfect for development**: Automatically fixes changed files on save. Great alongside your dev server (uvicorn --reload, flask run, etc.).

### Pre-commit hook in one command
```bash
pyguard-hooks install --type pre-commit  # install hook
pyguard-hooks install --type pre-push    # or pre-push
pyguard-hooks test                        # verify hook works
pyguard-hooks uninstall --type pre-commit # remove hook
```
The hook runs `pyguard . --scan-only --security-only` before commits. Blocks commits with HIGH/CRITICAL issues.

### GitHub Action (CI)
```yaml
name: PyGuard Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write  # Required for SARIF upload

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
          fail-on: 'high'  # Block on HIGH/CRITICAL issues
```

**GitHub Action features**:
- Publishes SARIF to GitHub Security tab (Code Scanning)
- Blocks merges when CRITICAL/HIGH issues remain (configurable)
- Use `paths` input to scan specific directories in monorepos
- Supports custom config with `config-path` input
- Available at [GitHub Marketplace](https://github.com/marketplace/actions/pyguard-security-scanner)

---

## 7. Situational playbook

| Scenario | Recommended command |
|----------|---------------------|
| Preview findings without touching code | `pyguard scan .` |
| Only trust auto-formatting | `pyguard fix src/ --formatting-only` |
| Security sweeps in notebooks | `pyguard scan notebooks/ --security-only` |
| Report-focused run for CI | `pyguard scan services/ --sarif --json results.json --no-html` |
| Large repo with vendor folders | `pyguard scan . --exclude 'vendor/*' '.venv/*'` |
| Fast scan of monorepo | `pyguard scan . --fast --parallel` |
| Explain a finding to teammates | `pyguard explain sql-injection` |
| Watch mode during development | `pyguard watch src/` |
| Pre-commit security gate | `pyguard-hooks install --type pre-commit` |
| Check environment setup | `pyguard doctor` |
| Verify configuration | `pyguard validate-config` |

---

## 8. Extend & integrate

### Programmatic API
```python
from pyguard.api import PyGuardAPI

api = PyGuardAPI()
result = api.analyze_file("mycode.py")

if result.has_critical_issues():
    for issue in result.critical_issues:
        print(f"{issue.category}: {issue.message} at line {issue.line_number}")

# Apply fixes programmatically
api.fix_file("mycode.py", unsafe=False)
```

### Custom Rules
Create `.pyguard.toml` with custom rules:
```toml
[[custom_rules]]
id = "CUSTOM001"
pattern = "deprecated_function\\("
severity = "MEDIUM"
message = "Use new_function() instead"
category = "BEST_PRACTICES"
```

### Advanced Integrations
- **JSON-RPC API** (`pyguard.lib.jsonrpc_api`): Real-time analysis for IDE plugins
- **Webhook API** (`pyguard.lib.webhook_api`): CI/CD pipeline integration with API key auth
- **Audit Logger** (`pyguard.lib.audit_logger`): Tamper-evident logging for compliance (SOC 2, ISO 27001)
- **Git Diff Analysis** (`pyguard --diff`): Scan only changed files in PRs (10-100x faster)
- **Compliance Reporting** (`pyguard --compliance-html`): Generate audit-ready reports

See `docs/guides/` for detailed integration guides.

---

Next steps:
1. Review the [main README](README.md) for capability overviews.
2. Browse the [documentation hub](docs/index.md) for task-oriented guides.
3. Tailor `.pyguard.toml`, run `pyguard watch`, and wire PyGuard into CI.
