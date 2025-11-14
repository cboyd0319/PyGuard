# PyGuard Quickstart

Set up PyGuard, run your first scans, and keep fixes flowing in under ten minutes. Every step keeps developer experience front and center so your team can focus on shipping.

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
- Security, quality, formatting, and notebooks analyzed together
- Rich console summary + HTML (enabled by default) + SARIF for GitHub Advanced Security
- Exit code `1` when HIGH/CRITICAL issues remain (ideal for CI gates)

Need speed? Add `--fast` (RipGrep pre-filter) and `--parallel` for monorepos.

---

## 4. First fixes (2 minutes)

```bash
pyguard fix src/            # safe fixes with backups
pyguard fix api/ --interactive
pyguard fix . --security-only
```

Highlights:
- Automatic backups live in `.pyguard_backups/`
- Interactive mode previews file-level diffs inside the terminal
- `--unsafe` unlocks deep refactors with safety prompts

---

## 5. Configure once, reuse everywhere

```bash
pyguard init --interactive   # guided questionnaire
pyguard validate-config      # verify + print summary
```

Profiles: strict, balanced, lenient, security-only, formatting-only. Configuration covers log level, exclude globs, enabled check families, formatting preferences, and max complexity budgets.

Store the resulting `.pyguard.toml` at the repo root to keep CLI, CI, and hooks aligned.

---

## 6. Automation patterns

### Watch mode for tight feedback loops
```bash
pyguard watch app/ --security-only
```
Automatically fixes changed files on save (great next to your web server or notebook runner).

### Pre-commit hook in one command
```bash
pyguard-hooks install --type pre-commit
```
Runs `pyguard . --scan-only --security-only` before every commit. Use `pyguard-hooks test` to verify.

### GitHub Action (CI)
```yaml
name: PyGuard
on: [push, pull_request]

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
- Publishes SARIF to the Security tab
- Blocks merges when CRITICAL issues remain
- Use `paths` to limit monorepo scans

---

## 7. Situational playbook

Scenario | Recommended command
--- | ---
Preview findings without touching code | `pyguard scan .`
Only trust auto-formatting | `pyguard fix src/ --formatting-only`
Security sweeps in notebooks | `pyguard scan notebooks/ --security-only`
Report-focused run | `pyguard scan services/ --sarif --json results.json --no-html`
Large repo with vendor folders | `pyguard scan . --exclude 'vendor/*' '.venv/*'`
Explain a finding to teammates | `pyguard explain sql-injection`

---

## 8. Extend & integrate

- **API** – `PyGuardAPI` lets IDEs or services call `analyze_file`, inspect severities, and run fixes programmatically (`examples/api_usage.py`).
- **Custom rules** – Load TOML definitions via `create_rule_engine_from_config` (see `examples/custom_rules_example.toml`).
- **Advanced workflows** – JSON-RPC server, webhook integration, SBOM + SLSA verification, and reproducible builds live under `docs/guides/`.

---

Next steps:
1. Review the [main README](README.md) for capability overviews.
2. Browse the [documentation hub](docs/index.md) for task-oriented guides.
3. Tailor `.pyguard.toml`, run `pyguard watch`, and wire PyGuard into CI.
