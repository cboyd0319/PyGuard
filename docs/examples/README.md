# PyGuard Examples

Hands-on scenarios for every adoption stage. Clone, run, and adapt these scripts to accelerate your own onboarding.

## Core walkthroughs

File | What it shows
--- | ---
`basic_usage.py` | Minimal scan/fix loop
`api_usage.py` | Programmatic `PyGuardAPI` for IDE or automation
`advanced_usage.py` | Chained analyzers, SARIF exports, custom configuration
`phase3_demo.py` | Full demonstration of security + quality packs leading up to v0.7+

## Advanced integrations

File | Highlights
--- | ---
`advanced_integrations_demo.py` | CI/CD workflow generation, performance profiler, dependency analyzer, custom rule engine
`advanced_features_demo.py` | Notebook security, AI explanations, compliance reporting
`github-workflows/README.md` | Ready-to-use workflow snippets for GitHub Actions
`hooks/README.md` | How to wire PyGuard into Git hooks manually (mirrors `pyguard-hooks` CLI)

## Configuration & customization

Resource | Purpose
--- | ---
`pyguard.toml.example` | Starting point for `.pyguard.toml`
`custom_rules_example.toml` | Sample custom security/quality rules for the rule engine
`notebook_security_demo.*` | Secure and insecure notebooks for validation and training
`plugins/` | Extending PyGuard with third-party detectors

## Running examples

```bash
# From repository root
python examples/basic_usage.py
python examples/advanced_integrations_demo.py
python examples/notebook_security_demo.py
```

Need dependencies for notebooks? Install extras first:
```bash
pip install nbformat nbclient
```

## Next steps

- Pair these scripts with the [Quickstart](../../QUICKSTART.md)
- Drop the GitHub workflow examples directly into `.github/workflows/`
- Use `custom_rules_example.toml` as a template for your organization’s policy pack
