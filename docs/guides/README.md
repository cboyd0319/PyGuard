# PyGuard Guides Index

This folder hosts tactical guides for common workflows. Use this index to jump directly to the playbook that matches your need.

| Guide | Purpose |
| --- | --- |
| [Auto-Fix Guide](auto-fix-guide.md) | Understand how the auto-fix pipeline categorizes safe vs. unsafe changes, interactive flows, and backup handling. |
| [Advanced Integrations](advanced-integrations.md) | Wire PyGuard into CI/CD systems (GitHub, GitLab, Jenkins), external services, and dependency/performance pipelines. |
| [Air-Gapped Installation](AIR_GAPPED_INSTALLATION.md) | Install PyGuard in fully offline or regulated environments, including dependency whitelists. |
| [Compliance Reporting](COMPLIANCE_REPORTING.md) | Generate HTML, JSON, SARIF, and audit logs that map to OWASP, CWE, and internal controls. |
| [GitHub Action Guide](github-action-guide.md) | Step-by-step instructions for running PyGuard as a first-class GitHub Action. |
| [GitHub Marketplace Guide](GITHUB_MARKETPLACE_GUIDE.md) | Publish and maintain the PyGuard action on GitHub Marketplace, including screenshots and pricing. |
| [Git Hooks Guide](git-hooks-guide.md) | Install and validate `pyguard-hooks` for pre-commit and pre-push enforcement. |
| [Git Diff Analysis](GIT_DIFF_ANALYSIS.md) | Target delta scans and incremental analysis in monorepos or large PRs. |
| [Notebook Security Guide](notebook-security-guide.md) | Operationalize notebook scanning with CLI/API patterns, detections, and automation tips. |
| [Plugin Architecture](PLUGIN_ARCHITECTURE.md) | Extend PyGuard with custom rule packs, detectors, and external signals. |
| [RipGrep Integration](RIPGREP_INTEGRATION.md) | Enable the RipGrep pre-filter for 10-100x faster scans on large repos. |
| [Reproducible Builds](REPRODUCIBLE_BUILDS.md) | Produce verifiable, bit-for-bit builds that support Sigstore/SLSA attestations. |
| [Supply Chain Security](SUPPLY_CHAIN_SECURITY.md) | Apply SBOM, dependency signing, and policy enforcement end-to-end. |
