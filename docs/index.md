# PyGuard Documentation Hub

PyGuard’s documentation is organized around how teams actually adopt the tool: start fast, automate scans, then go deep on reference material when needed. Everything here keeps the “developer-first and easy-to-run” philosophy intact.

---

## Start Here

Resource | Why it matters
--- | ---
[README](../README.md) | Product overview, capabilities map, CLI summary
[Quickstart](../QUICKSTART.md) | Install, run first scan, automate in <10 minutes
[Troubleshooting](../TROUBLESHOOTING.md) | Fast answers for installation, scanning, CI, and reporting issues
[Examples](examples/README.md) | Copy-paste demos for API usage, integrations, notebook scans, and plugins

---

## Run PyGuard Day-to-Day

Topic | Key guides
--- | ---
Command reference & UX | [Quickstart](../QUICKSTART.md), [RipGrep Integration](guides/RIPGREP_INTEGRATION.md), [Watch Mode](../pyguard/commands/watch.py)
Auto-fix workflows | [Auto-Fix Guide](guides/auto-fix-guide.md), [Notebook Security](guides/notebook-security-guide.md)
Configuration | [Plugin Architecture](guides/PLUGIN_ARCHITECTURE.md), [Advanced Integrations](guides/advanced-integrations.md), [Custom Rules Demo](../examples/custom_rules_example.toml)
Reporting | [Compliance Reporting](guides/COMPLIANCE_REPORTING.md), [GITHUB_ACTION_QUICK_REFERENCE](../docs/GITHUB_ACTION_QUICK_REFERENCE.md)
Git hooks & local automation | [Git Hooks Guide](guides/git-hooks-guide.md), [`pyguard-hooks` CLI](../pyguard/git_hooks_cli.py)

---

## Automate & Integrate

Workflow | Guides & references
--- | ---
CI/CD (GitHub, GitLab, Jenkins, Azure Pipelines) | [GitHub Action Guide](guides/github-action-guide.md), [Advanced Integrations](guides/advanced-integrations.md)
Marketplace distribution | [GitHub Marketplace Guide](guides/GITHUB_MARKETPLACE_GUIDE.md), [Distribution Strategy](reference/DISTRIBUTION_STRATEGY.md)
Air-gapped / offline | [Air-Gapped Installation](guides/AIR_GAPPED_INSTALLATION.md), [Reproducible Builds](guides/REPRODUCIBLE_BUILDS.md)
SBOM & compliance exports | [Supply Chain Security](guides/SUPPLY_CHAIN_SECURITY.md), [SBOM Guide](security/SBOM_GUIDE.md)
Performance tuning | [Performance & Benchmarks](development/benchmarks.md), [Incremental Analysis](../pyguard/lib/incremental_analysis.py)

---

## Reference Library

Area | Resources
--- | ---
Capabilities & rules | [Capabilities Reference](reference/capabilities-reference.md), [Security Rules](reference/security-rules.md), [Suppression Syntax](reference/SUPPRESSIONS.md)
Architecture & implementation | [Architecture Overview](reference/ARCHITECTURE.md), [Implementation Summary](reference/architecture/IMPLEMENTATION_SUMMARY.md), [Autofix Analysis](reference/architecture/AUTOFIX_ANALYSIS.md)
APIs & extensibility | [API files](../pyguard/api.py), [JSON-RPC API](../pyguard/lib/jsonrpc_api.py), [Webhook API](../pyguard/lib/webhook_api.py)
Testing strategy | [TEST_PLAN](TEST_PLAN.md), [COMPREHENSIVE_TEST_PLAN](COMPREHENSIVE_TEST_PLAN.md), [Development testing guide](development/TESTING_GUIDE.md)
Historical reports | [Reports index](reports/README.md) with deep dives, enhancements, and roadmap execution logs

---

## Security & Supply Chain

Topic | Resources
--- | ---
Security policy & disclosures | [SECURITY.md](../SECURITY.md), [Security Quickstart](security/SECURITY_QUICKSTART.md)
Threat modeling | [Threat Model](security/THREAT_MODEL.md), [Risk Ledger](security/RISK_LEDGER.md)
Release integrity | [SLSA Provenance Verification](security/SLSA_PROVENANCE_VERIFICATION.md), [Signature Verification](security/SIGNATURE_VERIFICATION.md), [GPG Verification](security/GPG_VERIFICATION.md)
SBOM & dependency posture | [SBOM Guide](security/SBOM_GUIDE.md), [Dependency Management](DEPENDENCY_MANAGEMENT.md)
Workflow security | [WORKFLOW_SECURITY_CHECKLIST](security/WORKFLOW_SECURITY_CHECKLIST.md), [Workflow Security Guide](security/SECURITY_MAINTENANCE.md)

---

## Project Health & Community

- [ROADMAP](../ROADMAP.md) — strategy toward v1.0 and beyond
- [CHANGELOG](CHANGELOG.md) — release notes
- [CONTRIBUTING](../CONTRIBUTING.md) & [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md) — how to collaborate respectfully
- [COMPREHENSIVE_TEST_PLAN](COMPREHENSIVE_TEST_PLAN.md) & [coverage dashboards](development/COVERAGE_STATUS.md) — quality benchmarks
- [Documentation Manifest](MANIFEST.md) — auto-generated index of every Markdown file with titles & summaries
- [Docs tone guide](doc_templates/github-repo-docs-tone-guide.md) — follow this when extending documentation

Need help? Open an [issue](https://github.com/cboyd0319/PyGuard/issues) or start a [discussion](https://github.com/cboyd0319/PyGuard/discussions).
