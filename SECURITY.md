# Security Policy

## Supported Versions

We support the latest minor release and security patches.

| Version | Supported | Notes |
|---------|-----------|-------|
| 0.7.0   | ✅ Yes    | Current stable release |
| 0.6.x   | ⚠️ Limited | Security patches only |
| < 0.6   | ❌ No     | Please upgrade to 0.7.0 |

## Reporting a Vulnerability

**🔒 IMPORTANT: Do not use public GitHub issues for security vulnerabilities.**

### Preferred Method: GitHub Security Advisories
Report privately via [GitHub Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories/new)

### Alternative Methods
- Email: security@pyguard.dev *(if configured)*
- Direct contact: https://github.com/cboyd0319

### Response Timeline
- **Initial Response:** Within 3 business days
- **Status Update:** Within 7 days
- **Resolution Target:** 30 days for high/critical issues

### Disclosure Policy
We follow coordinated disclosure:
1. Researcher reports vulnerability privately
2. We confirm and develop fix
3. We release patch
4. Public disclosure after users have time to update (typically 7-14 days)

### What to Include in Your Report

A good security report includes:

1. **Vulnerability Type** - What kind of issue (injection, overflow, etc.)
2. **Affected Component** - File paths, functions, or features affected
3. **Version Information** - PyGuard version and Python version
4. **Steps to Reproduce** - Clear, step-by-step instructions
5. **Proof of Concept** - Safe, minimal code demonstrating the issue
6. **Impact Assessment** - Severity, exploitability, and potential damage
7. **Suggested Fix** - Optional, but helpful if you have ideas
8. **Credit Information** - How you'd like to be credited (optional)

### Example Report Template

```markdown
## Vulnerability Report

**Type:** [e.g., Command Injection]
**Severity:** [Low/Medium/High/Critical]
**Component:** [e.g., pyguard/lib/scanner.py, line 123]
**Version:** [e.g., PyGuard 0.3.0, Python 3.12]

### Description
[Brief description of the vulnerability]

### Steps to Reproduce
1. [First step]
2. [Second step]
3. [Result]

### Proof of Concept
```python
# Minimal code demonstrating the issue
```

### Impact
[Who is affected? What can an attacker do?]

### Suggested Fix
[Optional: Your recommendation]
```

## Handling of secrets

- Never commit secrets. Use environment variables or secret managers.
- Required runtime secrets documented in README (Security section).
- PyGuard scans for hardcoded secrets — review warnings.

## Supply Chain Security

PyGuard implements comprehensive supply chain security measures:

### Release Security
- ✅ **Build Provenance:** Attestations generated via GitHub Actions OIDC
- ✅ **SBOM Generation:** SPDX 2.3 format attached to all releases
- 🔄 **Sigstore Signing:** Planned for future releases
- ✅ **Reproducible Builds:** Deterministic wheel generation
- ✅ **Checksum Verification:** SHA256 checksums for all artifacts

### Dependency Management
- **Total Dependencies:** 14 core packages (see `pyproject.toml`)
- **Version Pinning:** All dependencies pinned with **SHA256 hashes** for tamper protection
- **Hash Verification:** `requirements.txt` and `requirements-dev.txt` include cryptographic hashes
- **Automated Scanning:** 
  - pip-audit (PyPI Advisory Database)
  - OSV-Scanner (Google's Open Source Vulnerabilities)
  - Safety DB (security vulnerabilities)
- **Update Strategy:** Dependabot weekly updates with security priority
- **License Compliance:** MIT, Apache-2.0, BSD-2/3-Clause allowed

📚 **See [docs/DEPENDENCY_MANAGEMENT.md](docs/DEPENDENCY_MANAGEMENT.md) for detailed dependency security practices**

### Verification
You can verify PyGuard releases:
```bash
# Download release and verify checksum
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.3.0/pyguard-0.3.0.tar.gz
sha256sum -c checksums.sha256

# Verify SBOM
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.3.0/pyguard-0.3.0.spdx.json
# Review SBOM for dependencies
```

## Security features in PyGuard

PyGuard helps you find:
- Hardcoded secrets (API keys, passwords, tokens)
- SQL/Command/NoSQL injection patterns
- Unsafe deserialization (pickle, yaml.load)
- Weak cryptography (MD5, SHA1, DES)
- Path traversal vulnerabilities
- Insecure random number generation

## Best Practices When Using PyGuard

### For Users
1. **Review Auto-Fixes** - Always review changes before committing
2. **Keep Updated** - `pip install --upgrade pyguard` regularly
3. **Backup First** - PyGuard creates `.pyguard_backups/` automatically
4. **Sandbox Scans** - Run in CI/CD, not on production systems
5. **Review Logs** - Check `logs/pyguard.jsonl` for issues
6. **Start with Scan-Only** - Use `--scan-only` first, then apply fixes
7. **Use in CI/CD** - Integrate with GitHub Actions for continuous scanning

### For Contributors
1. **Read Security Docs** - See `security/SECURE_CODING_GUIDE.md`
2. **Run Security Tests** - `pytest tests/test_security*.py`
3. **Use Pre-Commit Hooks** - Automated security checks
4. **Follow Threat Model** - See `security/THREAT_MODEL.md`
5. **Report Issues Privately** - Use GitHub Security Advisories

## Security Infrastructure

### Automated Security Scanning
PyGuard itself is continuously scanned with:
- **CodeQL** - Weekly security analysis (Python extended queries)
- **Bandit** - SAST for Python security issues
- **Semgrep** - Advanced pattern matching (security-audit, OWASP, CI rules)
- **OSSF Scorecard** - Supply chain security rating
- **Dependency Review** - Blocks vulnerable dependencies in PRs
- **Gitleaks** - Secrets detection in commits

### GitHub Actions Security
- ✅ **SHA-pinned actions** - All actions pinned to full commit SHAs
- ✅ **Minimal permissions** - Least-privilege access per workflow
- ✅ **OIDC authentication** - No long-lived credentials
- ✅ **Workflow isolation** - Proper concurrency and branch protection
- ✅ **SARIF uploads** - Security findings in GitHub Security tab

### Documentation
- 📋 **Risk Ledger** - `security/RISK_LEDGER.md`
- 🎯 **Threat Model** - `security/THREAT_MODEL.md`
- 📚 **Secure Coding Guide** - `security/SECURE_CODING_GUIDE.md`
- 🔍 **Custom Security Rules** - `security/POLICIES/semgrep/`
- 🚀 **Security Quickstart** - `docs/security/SECURITY_QUICKSTART.md`
- 📄 **Security Summary** - `docs/security/SECURITY_SUMMARY.md`

## Security Hall of Fame

We appreciate security researchers who help make PyGuard safer:

*No vulnerabilities reported yet - be the first!*

When you report a vulnerability, you can be listed here (with your permission).

## Security Certifications & Ratings

- 🏆 **OSSF Scorecard:** Target 9+/10
- ✅ **OpenSSF Best Practices Badge:** In Progress
- 🔒 **CVE-Free:** No known vulnerabilities in current release

## Contact

- **Security Team:** https://github.com/cboyd0319
- **Public Discussion:** GitHub Discussions (for non-security issues)
- **Updates:** Watch this repo for security advisories

---

**Last Updated:** 2025-10-19  
**Next Review:** 2026-01-19
