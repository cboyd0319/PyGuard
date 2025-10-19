# PyGuard Security Quick Start Guide

**🔒 Welcome to one of the MOST secure GitHub projects!**

This guide gets you started with PyGuard's comprehensive security infrastructure.

---

## 🚀 For New Users

### 1. Verify Release Security

All PyGuard releases include security artifacts:

```bash
# Download from GitHub Releases
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.3.0/pyguard-0.3.0.tar.gz
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.3.0/checksums.sha256

# Verify checksum
sha256sum -c checksums.sha256

# Review SBOM
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.3.0/pyguard-0.3.0.spdx.json
cat pyguard-0.3.0.spdx.json | jq '.packages[] | select(.name)'
```

### 2. Install Securely

```bash
# Option 1: From PyPI (recommended)
pip install pyguard

# Option 2: From source (verify first)
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .

# Verify installation
pyguard --version
```

### 3. Review Security Policy

Read our security policy: [SECURITY.md](./SECURITY.md)

- Supported versions
- Vulnerability reporting
- Supply chain security
- Security features

---

## 🛠️ For Contributors

### 1. Set Up Security Tools

```bash
# Clone repository
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard

# Install development dependencies (includes security tools)
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Verify setup
pre-commit run --all-files
```

### 2. Run Security Scans Locally

```bash
# Bandit SAST
bandit -r pyguard/ -f screen

# PyGuard dogfooding (use PyGuard on itself)
pyguard pyguard/ --security-only --scan-only

# Validate workflow security
./scripts/validate-workflow-security.sh
```

### 3. Read Security Docs

**Essential reading:**
1. [SECURE_CODING_GUIDE.md](./security/SECURE_CODING_GUIDE.md) - Python security best practices
2. [THREAT_MODEL.md](./security/THREAT_MODEL.md) - Understand attack scenarios
3. [WORKFLOW_SECURITY_CHECKLIST.md](./security/WORKFLOW_SECURITY_CHECKLIST.md) - GitHub Actions security

### 4. Before Committing

Pre-commit hooks automatically run:
- ✅ PyGuard security check
- ✅ Bandit SAST
- ✅ Gitleaks secret detection
- ✅ Code formatting (Black, isort)
- ✅ Type checking (mypy)
- ✅ YAML/Markdown linting

If hooks fail, fix issues before pushing.

---

## 🔍 For Security Reviewers

### 1. Review Security Posture

```bash
# Clone and navigate to security docs
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard/security

# Read in this order:
# 1. README.md - Security documentation index
# 2. IMPLEMENTATION_SUMMARY.md - What's been implemented
# 3. RISK_LEDGER.md - Current risks and mitigations
# 4. THREAT_MODEL.md - Threat analysis
```

### 2. Validate Workflow Security

```bash
# Run automated validation
./scripts/validate-workflow-security.sh

# Expected output:
# ✅ All external actions are SHA-pinned
# ✅ No workflow injection risks
# ✅ No excessive permissions
# ✅ pull_request_target usage is safe
# ✅ No secrets in run blocks
# ✅ No credential persistence
# ✅ All required security workflows present
# Result: 0 Errors, 0 Warnings
```

### 3. Review Security Scans

GitHub Security tab includes:
- **CodeQL** - Weekly Python security analysis
- **Bandit** - SAST scan results
- **Semgrep** - Advanced pattern matching
- **OSSF Scorecard** - Supply chain security rating
- **Dependency Review** - Vulnerable dependency checks

### 4. Check Custom Security Rules

```bash
# Review custom Semgrep rules
cat security/POLICIES/semgrep/python-security-custom.yml

# Test rules locally
semgrep --config security/POLICIES/semgrep/python-security-custom.yml pyguard/
```

---

## 🚨 Reporting Security Issues

### DO NOT use public GitHub issues!

**Preferred Method:**
[GitHub Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories/new) (private)

**What to Include:**
- Vulnerability type (injection, overflow, etc.)
- Affected version and component
- Steps to reproduce
- Proof of concept (safe example)
- Impact assessment

**Response Time:**
- Initial response: 3 business days
- Status updates: Weekly
- Resolution target: 30 days (high/critical)

**Template:** See [SECURITY.md](./SECURITY.md) for detailed template

---

## 📊 Security Metrics

### Current Status
- ✅ **100%** GitHub Actions SHA-pinned
- ✅ **17** custom security rules (Semgrep)
- ✅ **6** automated security scanners
- ✅ **87%+** test coverage
- ✅ **0** high/critical Bandit findings
- ✅ **5,500+** lines of security documentation

### OSSF Scorecard
- **Target:** 9.8+/10
- **Updated:** Weekly
- **View:** GitHub Security tab

---

## 🔧 Common Tasks

### Add Security Check to CI

```yaml
# .github/workflows/your-workflow.yml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@<SHA> # v5.0.0
        with:
          persist-credentials: false
      
      - name: Run PyGuard
        run: |
          pip install pyguard
          pyguard . --security-only --scan-only --sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@<SHA> # v4.30.8
        if: always()
        with:
          sarif_file: pyguard-report.sarif
```

### Generate SBOM

```bash
# Install tools
pip install cyclonedx-bom

# Generate SBOM
cyclonedx-py --format json --output sbom.json

# Review dependencies
cat sbom.json | jq '.components[] | {name, version, licenses}'
```

### Update Dependencies Securely

```bash
# Check for vulnerabilities
pip-audit

# Update specific package
pip install --upgrade <package>

# Regenerate requirements with hashes
pip-compile --generate-hashes requirements.in
```

---

## 📚 Documentation

### Quick Reference
- [SECURITY.md](./SECURITY.md) - Security policy and reporting
- [security/README.md](./security/README.md) - Security docs index
- [security/SECURE_CODING_GUIDE.md](./security/SECURE_CODING_GUIDE.md) - Coding best practices

### In-Depth
- [security/RISK_LEDGER.md](./security/RISK_LEDGER.md) - Risk assessment
- [security/THREAT_MODEL.md](./security/THREAT_MODEL.md) - Threat analysis
- [security/WORKFLOW_SECURITY_CHECKLIST.md](./security/WORKFLOW_SECURITY_CHECKLIST.md) - GitHub Actions
- [security/IMPLEMENTATION_SUMMARY.md](./security/IMPLEMENTATION_SUMMARY.md) - What's implemented

### External Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)

---

## 💡 Tips

### For Maximum Security

1. **Always update** - `pip install --upgrade pyguard` regularly
2. **Review auto-fixes** - Never blindly apply changes to production
3. **Use scan-only mode first** - `--scan-only` before applying fixes
4. **Run in CI/CD** - Automate security scanning
5. **Keep dependencies updated** - Enable Dependabot
6. **Monitor Security tab** - Check GitHub Security for findings
7. **Use pre-commit hooks** - Catch issues before committing

### For Best Results

- Start with security-only mode: `--security-only`
- Use SARIF output for CI: `--sarif`
- Review logs: `logs/pyguard.jsonl`
- Check backups: `.pyguard_backups/` before applying fixes
- Run multiple scanners (Bandit + PyGuard + Semgrep)

---

## 🤝 Getting Help

### Security Questions
- [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions) (for non-security issues)
- [Security Policy](./SECURITY.md) (for vulnerability reporting)

### Documentation Issues
- Open PR to improve docs
- Follow [CONTRIBUTING.md](./CONTRIBUTING.md)

### Security Issues
- **Private:** [GitHub Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories/new)
- **Urgent:** Email security@pyguard.dev (if configured)

---

## ✅ Checklist for New Contributors

- [ ] Read [SECURITY.md](./SECURITY.md)
- [ ] Read [SECURE_CODING_GUIDE.md](./security/SECURE_CODING_GUIDE.md)
- [ ] Install pre-commit hooks: `pre-commit install`
- [ ] Run security scans locally: `bandit -r pyguard/`
- [ ] Validate workflows: `./scripts/validate-workflow-security.sh`
- [ ] Review [THREAT_MODEL.md](./security/THREAT_MODEL.md)
- [ ] Understand risk tracking: [RISK_LEDGER.md](./security/RISK_LEDGER.md)

---

**🎯 PyGuard: One of the MOST secure GitHub projects**

Security is not a feature, it's a foundation. We've built PyGuard on that principle.

---

**Last Updated:** 2025-10-19  
**Version:** 1.0  
**Maintained By:** PyGuard Security Team
