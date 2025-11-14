# PyGuard Troubleshooting

The goal of this guide is to get you back to shipping quickly. Every fix below assumes you want the easiest, sanest way to keep scans running.

---

## 1. Setup & Installation

**`pip install` fails or dependencies conflict**
1. Use a clean virtual environment:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install git+https://github.com/cboyd0319/PyGuard.git
   ```
2. If the system `packaging` package blocks uninstall (`RECORD file not found`), run:
   ```bash
   pip install -e . --ignore-installed packaging
   ```
3. Still stuck? Run `pip install -e . --force-reinstall` inside the repo to rebuild everything.

**`pyguard: command not found`**
- Confirm installation: `python -m pip show pyguard`
- Prefer module invocation when PATH is locked down: `python -m pyguard.cli --help`
- Ensure the scripts directory is on PATH:
  ```bash
  export PATH="$PATH:$(python -m site --user-base)/bin"   # macOS/Linux
  set PATH=%PATH%;%APPDATA%\Python\Scripts               # Windows
  ```

**Import errors after cloning the repo**
- Run `pip install -e .` from the project root.
- Validate Python 3.11+: `python --version`
- Verify version: `python -c "import pyguard; print(pyguard.__version__)"`

**Permission errors when installing**
- Avoid `sudo pip`. Instead use `pip install --user` or a virtual environment.
- Check ownership of `~/.local/lib/python*/site-packages/` and fix with `chown` if a previous root install left files behind.

Run `pyguard doctor` whenever something feels off; it checks Python version, dependency health, optional notebook extras, RipGrep, and `.pyguard.toml` presence.

---

## 2. CLI Usage & Scanning

**“No Python files or notebooks found”**
- Confirm you are pointing at the right directory: `pyguard scan backend/`
- Review excludes from `.pyguard.toml`: `pyguard validate-config`
- Override quickly: `pyguard scan . --exclude venv/* .venv/* build/* dist/*`

**Exit code 1 even when issues are fixed**
- PyGuard returns non-zero when HIGH/CRITICAL issues remain. Re-run `pyguard scan . --security-only` to verify.
- In CI, add `--best-practices-only` or `--formatting-only` to limit the gate.

**“Command not found: nbformat” errors**
- Notebook analysis requires optional dependencies:
  ```bash
  pip install nbformat nbclient
  ```
- Or disable notebook analysis by excluding `*.ipynb` in `.pyguardignore`.

**False positives or intentional exceptions**
- Suppress at the line with `# pyguard: disable=RULE_ID`
- Centralize ignores in `.pyguardignore`
- Capture waivers in `pyguard lib compliance tracker?` (docs/guides/COMPLIANCE_REPORTING.md)

**Auto-fix skipped a file**
- Check `.pyguard_backups/` for diff context.
- Ensure `--no-backup` is not set when you expect backups.
- Interactive fix mode (`pyguard fix . --interactive`) clarifies why a change might be unsafe.

---

## 3. Performance & Large Repos

Symptom | Solution
--- | ---
Scans feel slow | Install `ripgrep` and run `pyguard scan . --fast`
Max out CPUs | Use `pyguard scan . --parallel` (PyGuard automatically balances workloads)
Too many files | Maintain excludes in `.pyguard.toml` or `.pyguardignore`, e.g. `exclude_patterns = ["venv/*", "node_modules/*", "generated/*"]`
Need incremental scans | Use `pyguard . --diff HEAD~1` or `pyguard . --diff staged` to focus on changed files
Vendor code overwhelms signal | Combine `--exclude` with `pyguard scan src/ libs/` to target relevant folders

Remember to commit `.pyguard.toml` so every environment shares the same excludes.

---

## 4. CI, Reports & Integrations

**GitHub Action fails because `pyguard` missing**
- Use the official action (`cboyd0319/PyGuard@main`) instead of reinstalling manually.
- Verify `actions/setup-python@v4` installs Python 3.11+.

**SARIF upload fails**
- Always enable permissions:
  ```yaml
  permissions:
    contents: read
    security-events: write
  ```
- Confirm the SARIF file path matches (`pyguard scan . --sarif` writes `pyguard-results.sarif`).

**Pre-commit hook blocks every commit**
- Run `pyguard fix .` locally to address findings.
- Temporarily bypass with `SKIP=pyguard git commit ...` only when necessary and after filing an issue.

**HTML/JSON report missing**
- `--no-html` and `--json` are opt-in flags. Ensure you call: `pyguard scan . --json report.json`
- Check write permissions in the output directory.

---

## 5. Advanced Debugging & Support

Tooling | Usage
--- | ---
Verbose logs | Set `log_level = "DEBUG"` in `.pyguard.toml` and re-run. Structured logs live in `logs/pyguard.jsonl`.
Diffs vs. backups | Inspect `.pyguard_backups/<file>.<timestamp>.bak` and use standard `diff` tools.
Internal modules | Browse `pyguard/lib/` for focused capabilities (e.g., `advanced_security.py`, `ai_ml_security.py`).
Explain findings | `pyguard explain <topic>` renders Rich-formatted remediation notes.

Still blocked?
1. Run `pyguard doctor --verbose` and capture the output.
2. Collect the failing command with `PYGUARD_LOG_LEVEL=DEBUG`.
3. Open an [issue](https://github.com/cboyd0319/PyGuard/issues) with logs, OS, Python version, and sample code if possible.

If the issue involves a vulnerability disclosure, follow [SECURITY.md](SECURITY.md) instead of filing a public ticket.
