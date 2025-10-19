# GitHub Actions Security Checklist

This checklist ensures all GitHub Actions workflows follow security best practices based on PYSEC_OMEGA standards.

## ✅ Pre-Deployment Checklist

### Action Pinning
- [ ] All actions pinned to full 40-character SHA
- [ ] Version comments included (e.g., `# v5.0.0`)
- [ ] Dependabot configured for action updates
- [ ] Local actions (`./.github/actions/`) documented

### Permissions
- [ ] Default permissions set to `contents: read` or more restrictive
- [ ] Each job has explicit, minimal permissions
- [ ] No `permissions: write-all` or inherited write permissions
- [ ] `id-token: write` only for OIDC flows
- [ ] `security-events: write` only for SARIF uploads

### Input Validation
- [ ] No unescaped `${{ github.event.* }}` in `run:` blocks
- [ ] Untrusted input passed via environment variables
- [ ] User input validated and sanitized
- [ ] No `pull_request_target` with code checkout

### Secrets Management
- [ ] No secrets in logs (even if masked)
- [ ] OIDC preferred over long-lived credentials
- [ ] Secrets scoped to necessary jobs only
- [ ] Environment protection rules for production
- [ ] Secrets rotation schedule documented

### Concurrency
- [ ] Concurrency groups defined: `${{ github.workflow }}-${{ github.ref }}`
- [ ] `cancel-in-progress` set appropriately
- [ ] No race conditions in parallel jobs
- [ ] Proper dependency chains (`needs:`)

### Artifacts & Caching
- [ ] Artifacts signed or checksummed
- [ ] Cache keyed by lockfile hash
- [ ] No secrets cached
- [ ] Retention days set (90 max)
- [ ] Artifact integrity verified before use

---

## 📋 Workflow-Specific Checks

### Security Scanning Workflows

#### Requirements
- [x] Run on: push, pull_request, schedule, workflow_dispatch
- [x] Multiple scanners (Bandit, Semgrep, pip-audit, OSV)
- [x] SARIF upload to Security tab
- [x] Continue on error for advisory scans
- [x] Timeout limits (15-20 min)

#### Example: `.github/workflows/security-scan.yml`
```yaml
name: Security Scanning
on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: '0 2 * * 1'  # Weekly
  workflow_dispatch:

permissions:
  contents: read

jobs:
  bandit-sast:
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@<SHA> # v5.0.0
        with:
          persist-credentials: false
```

### Release Workflows

#### Requirements
- [ ] Triggered only on tags (`v*.*.*`)
- [ ] OIDC for PyPI publishing (no stored credentials)
- [ ] Build provenance attestation
- [ ] SBOM generation (SPDX + CycloneDX)
- [ ] Artifact signing (Sigstore)
- [ ] Checksum generation
- [ ] Concurrency: `cancel-in-progress: false`

#### Checklist
- [x] `id-token: write` for attestations
- [x] `contents: write` for release creation
- [x] Build artifacts before publishing
- [x] Generate checksums
- [x] Create SBOM
- [x] Attest provenance
- [ ] Sign with Sigstore (planned)

### Test Workflows

#### Requirements
- [ ] Matrix across Python versions (3.11, 3.12, 3.13)
- [ ] Matrix across OS (ubuntu, macos, windows)
- [ ] `fail-fast: false` for complete results
- [ ] Coverage upload to CodeCov
- [ ] Proper timeout (20 min)

#### Coverage Upload (CodeCov)
```yaml
- name: Upload coverage
  uses: codecov/codecov-action@<SHA> # v5.5.1
  if: always() && hashFiles('coverage.xml') != ''
  with:
    files: ./coverage.xml
    token: ${{ secrets.CODECOV_TOKEN }}
    fail_ci_if_error: false
    verbose: true
```

### Dependency Review

#### Requirements
- [ ] Run on: pull_request only
- [ ] `fail-on-severity: moderate` or higher
- [ ] License compliance checks
- [ ] Comment summary in PR
- [ ] `pull-requests: write` permission

---

## 🔍 Common Vulnerabilities

### 1. Workflow Injection

❌ **VULNERABLE:**
```yaml
- name: Bad
  run: echo "Title: ${{ github.event.issue.title }}"
```

✅ **SAFE:**
```yaml
- name: Good
  env:
    ISSUE_TITLE: ${{ github.event.issue.title }}
  run: echo "Title: $ISSUE_TITLE"
```

### 2. Excessive Permissions

❌ **VULNERABLE:**
```yaml
permissions: write-all
```

✅ **SAFE:**
```yaml
permissions:
  contents: read
  security-events: write
```

### 3. Action Version Pinning

❌ **VULNERABLE:**
```yaml
- uses: actions/checkout@v5
```

✅ **SAFE:**
```yaml
- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
```

### 4. pull_request_target Misuse

❌ **VULNERABLE:**
```yaml
on: pull_request_target
steps:
  - uses: actions/checkout@v5
    with:
      ref: ${{ github.event.pull_request.head.ref }}
```

✅ **SAFE:**
```yaml
on: pull_request  # Use regular pull_request
steps:
  - uses: actions/checkout@<SHA> # v5.0.0
```

### 5. Secret Exposure

❌ **VULNERABLE:**
```yaml
- run: echo "API_KEY=${{ secrets.API_KEY }}"
```

✅ **SAFE:**
```yaml
- run: echo "Deploying to production"
  env:
    API_KEY: ${{ secrets.API_KEY }}
```

---

## 🛠️ Tools for Validation

### actionlint
```bash
# Install
brew install actionlint  # macOS
# or download from https://github.com/rhysd/actionlint

# Run
actionlint .github/workflows/*.yml
```

### GitHub Action Security Checker
```bash
pip install action-validator
action-validator .github/workflows/
```

### Manual Review
```bash
# Check all actions are SHA-pinned
grep -r "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"

# Check for workflow injection vulnerabilities
grep -r "github.event" .github/workflows/ | grep "run:"
```

---

## 📊 Security Metrics

### Current Status (PyGuard)
- ✅ **93%** of actions SHA-pinned (target: 100%)
- ✅ **100%** of workflows have minimal permissions
- ✅ **0** workflow injection vulnerabilities
- ✅ **4** security scanning workflows
- ✅ **Weekly** automated security scans

### Targets
- 🎯 100% action pinning
- 🎯 OSSF Scorecard 9+/10
- 🎯 Zero high/critical workflow vulnerabilities
- 🎯 All secrets via OIDC (no long-lived tokens)

---

## 🔄 Maintenance Schedule

### Weekly
- [ ] Review Dependabot PRs for action updates
- [ ] Check OSSF Scorecard results
- [ ] Review security scan findings

### Monthly
- [ ] Audit all workflow permissions
- [ ] Review action pinning status
- [ ] Update this checklist

### Quarterly
- [ ] Full workflow security audit
- [ ] Review and update security policies
- [ ] Test incident response procedures

---

## 📚 References

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OSSF Scorecard](https://github.com/ossf/scorecard)
- [Secure GitHub Actions](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [Action Pinning Best Practices](https://github.com/github/roadmap/issues/386)

---

**Last Updated:** 2025-10-19  
**Next Review:** 2026-01-19  
**Owner:** PyGuard Security Team
