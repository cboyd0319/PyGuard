# OpenSSF Scorecard Guide

**Status:** ✅ Workflow Active, ⚠️ Baseline Score Not Documented
**Target:** >8.0 for v0.8.0
**Priority:** MEDIUM - Security posture metric

---

## Overview

The OpenSSF Scorecard is an automated security assessment tool that evaluates open-source projects against best practices. PyGuard runs weekly scorecard scans to track and improve security posture.

### What is OpenSSF Scorecard?

The Scorecard project evaluates repositories on multiple security criteria:
- **Maintained** - Regular updates and active maintainers
- **Code Review** - All changes require code review
- **CI Tests** - Automated testing on all changes
- **SAST** - Static analysis security testing
- **Dependencies** - Automated dependency updates
- **Signed Releases** - Cryptographically signed releases
- **Branch Protection** - Protected main branches
- **Vulnerability Disclosure** - Security policy in place
- And more...

**Score Range:** 0-10 (10 = best)

---

## Current Implementation

### Automated Workflow

PyGuard runs OpenSSF Scorecard automatically:
- **Schedule:** Weekly on Monday at 00:00 UTC
- **Triggers:** Push to main, branch protection changes, manual dispatch
- **Workflow:** `.github/workflows/scorecard.yml`
- **Results:** Uploaded to GitHub Security tab

### Manual Run

```bash
# Trigger manual scorecard run
gh workflow run scorecard.yml

# View results
gh api repos/cboyd0319/PyGuard/code-scanning/alerts?tool_name=ossf-scorecard
```

### View Results

1. **GitHub Security Tab:**
   - Go to https://github.com/cboyd0319/PyGuard/security
   - Click "Code scanning alerts"
   - Filter by tool: "ossf-scorecard"

2. **GitHub API:**
   ```bash
   gh api repos/cboyd0319/PyGuard/code-scanning/alerts?tool_name=ossf-scorecard | jq
   ```

3. **Latest Artifact:**
   ```bash
   gh run list --workflow=scorecard.yml --limit 1
   gh run download <run-id> --name ossf-scorecard-results
   ```

---

## Running Scorecard Locally

### Installation

```bash
# Using Homebrew (macOS/Linux)
brew install scorecard

# Using Go
go install github.com/ossf/scorecard/v5/cmd/scorecard@latest

# Using Docker
docker pull gcr.io/openssf/scorecard:stable
```

### Run Scorecard

```bash
# Basic run (requires GitHub token)
export GITHUB_AUTH_TOKEN=<your-token>
scorecard --repo=github.com/cboyd0319/PyGuard

# With JSON output
scorecard --repo=github.com/cboyd0319/PyGuard --format=json > scorecard.json

# Specific checks only
scorecard --repo=github.com/cboyd0319/PyGuard --checks=Branch-Protection,Code-Review

# Show detailed results
scorecard --repo=github.com/cboyd0319/PyGuard --show-details
```

### Docker Run

```bash
docker run -e GITHUB_AUTH_TOKEN=<token> \
  gcr.io/openssf/scorecard:stable \
  --repo=github.com/cboyd0319/PyGuard \
  --format=json
```

---

## Scorecard Checks Explained

### 1. Binary-Artifacts (10/10 expected)

**What it checks:** Detects binary files that may be compromised or contain malicious code.

**How to pass:**
- Don't commit binary files (executables, .so, .dll)
- Use package managers for dependencies
- Store large binaries in separate asset releases

**PyGuard status:** ✅ LIKELY PASS (no binaries in repo)

### 2. Branch-Protection (8-10/10 target)

**What it checks:** Main branch has protection rules enabled.

**How to pass:**
- Require pull request reviews before merging
- Require status checks to pass
- Enforce for administrators
- Require signed commits (optional)

**PyGuard status:** ⚠️ NEEDS VERIFICATION

**Action needed:**
1. Go to https://github.com/cboyd0319/PyGuard/settings/branches
2. Add branch protection rule for `main`:
   - ✅ Require pull request before merging
   - ✅ Require approvals: 1+
   - ✅ Dismiss stale PR approvals when new commits are pushed
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - ✅ Require conversation resolution before merging
   - ⚠️ Include administrators (optional for solo maintainer)

### 3. CI-Tests (10/10 expected)

**What it checks:** Repository runs tests in CI on most commits.

**How to pass:**
- Have GitHub Actions workflows with tests
- Run tests on pull requests
- Run tests on main branch pushes

**PyGuard status:** ✅ LIKELY PASS
- `.github/workflows/test.yml`
- `.github/workflows/comprehensive-tests.yml`
- `.github/workflows/coverage.yml`

### 4. CII-Best-Practices (0-10/10)

**What it checks:** OpenSSF Best Practices badge earned.

**How to pass:**
1. Go to https://bestpractices.coreinfrastructure.org/
2. Register project
3. Answer questionnaire (100+ questions)
4. Earn passing badge (60%+)
5. Add badge to README

**PyGuard status:** ⚠️ NOT STARTED

**Action needed:**
- Register at https://bestpractices.coreinfrastructure.org/projects/new
- Complete questionnaire
- Add badge to README.md

### 5. Code-Review (10/10 expected)

**What it checks:** Most commits have been reviewed via pull requests.

**How to pass:**
- Use pull requests for all changes
- Require reviews before merging
- Don't push directly to main

**PyGuard status:** ✅ LIKELY PASS (if using PRs)

### 6. Contributors (10/10 expected)

**What it checks:** Project has multiple contributors.

**How to pass:**
- Have 2+ contributors with recent commits
- Accept community pull requests
- Encourage external contributions

**PyGuard status:** ⚠️ LIKELY LOW (single maintainer initially)

**Note:** This score improves naturally as project grows

### 7. Dangerous-Workflow (10/10 expected)

**What it checks:** GitHub Actions workflows don't have dangerous patterns.

**How to pass:**
- Don't use `pull_request_target` with untrusted code
- Don't expose secrets in untrusted contexts
- Pin actions to specific SHA (not tags)

**PyGuard status:** ✅ LIKELY PASS
- Actions pinned to SHA in most workflows
- No dangerous patterns detected

### 8. Dependency-Update-Tool (10/10 expected)

**What it checks:** Automated dependency update tool in use.

**How to pass:**
- Use Dependabot (enabled in settings)
- Use Renovate Bot
- Or similar automated tool

**PyGuard status:** ✅ LIKELY PASS
- `.github/dependabot.yml` exists
- Dependabot configured for GitHub Actions and pip

### 9. Fuzzing (0-10/10)

**What it checks:** Project uses fuzzing to find bugs.

**How to pass:**
- Integrate with OSS-Fuzz
- Run local fuzzing (AFL, libFuzzer)
- Document fuzzing in SECURITY.md

**PyGuard status:** ⚠️ LIKELY LOW (not implemented)

**Future enhancement:** Add fuzzing for rule engine, parser, etc.

### 10. License (10/10 expected)

**What it checks:** Project has a valid open-source license.

**How to pass:**
- Include LICENSE file in root
- Use OSI-approved license
- Match GitHub license detection

**PyGuard status:** ✅ LIKELY PASS (MIT License)

### 11. Maintained (10/10 expected)

**What it checks:** Project has recent commits (90 days).

**How to pass:**
- Regular commits and updates
- Active issue responses
- Recent releases

**PyGuard status:** ✅ LIKELY PASS (actively developed)

### 12. Pinned-Dependencies (8-10/10 target)

**What it checks:** Dependencies pinned to specific versions or hashes.

**How to pass:**
- Pin GitHub Actions to SHA (e.g., `uses: actions/checkout@abc123...`)
- Pin Python deps with hashes (pip-tools, poetry)
- Pin Docker base images to digests

**PyGuard status:** ✅ LIKELY GOOD
- Most actions pinned to SHA
- Python deps in pyproject.toml

**Improvement:** Add SHA digests to Docker images

### 13. Packaging (10/10 expected)

**What it checks:** Project published to package manager.

**How to pass:**
- Publish to PyPI (Python)
- Or npm, RubyGems, etc.

**PyGuard status:** ✅ LIKELY PASS
- Published to PyPI: https://pypi.org/project/pyguard/

### 14. SAST (10/10 expected)

**What it checks:** Static analysis security testing used.

**How to pass:**
- CodeQL (GitHub native)
- Bandit, Semgrep, or similar
- Run on PRs and main

**PyGuard status:** ✅ LIKELY PASS
- `.github/workflows/codeql.yml` exists
- `.github/workflows/security-scan.yml` exists
- Multiple SAST tools configured

### 15. Security-Policy (10/10 expected)

**What it checks:** SECURITY.md file exists with vulnerability reporting process.

**How to pass:**
- Create SECURITY.md in root
- Document how to report vulnerabilities
- Include response timeline

**PyGuard status:** ✅ PASS
- `SECURITY.md` exists with comprehensive policy

### 16. Signed-Releases (8-10/10 target)

**What it checks:** Releases are cryptographically signed.

**How to pass:**
- Sign release tags with GPG
- Sign release artifacts with Sigstore
- Document verification process

**PyGuard status:** ✅ LIKELY GOOD
- Sigstore signing implemented in release workflow
- GPG signing supported
- See: `docs/security/SIGSTORE_VERIFICATION_GUIDE.md`

### 17. Token-Permissions (10/10 expected)

**What it checks:** GitHub Actions use minimal token permissions.

**How to pass:**
- Declare `permissions:` in workflows
- Use least-privilege principle
- Don't use default `GITHUB_TOKEN` permissions

**PyGuard status:** ✅ LIKELY PASS
- Most workflows declare explicit permissions
- Scorecard workflow uses minimal permissions

### 18. Vulnerabilities (10/10 expected)

**What it checks:** No known vulnerabilities in dependencies.

**How to pass:**
- Keep dependencies updated
- Use Dependabot or similar
- Address security alerts promptly

**PyGuard status:** ✅ LIKELY PASS
- Active dependency updates
- Security scanning in CI

---

## Target Score Breakdown

### Expected Current Score: ~7.5-8.5/10

**Strong areas (9-10/10):**
- Binary-Artifacts (10)
- CI-Tests (10)
- Dependency-Update-Tool (10)
- License (10)
- Maintained (10)
- Packaging (10)
- SAST (10)
- Security-Policy (10)
- Vulnerabilities (10)

**Good areas (7-9/10):**
- Code-Review (8-10)
- Dangerous-Workflow (9-10)
- Pinned-Dependencies (8-9)
- Signed-Releases (8-9)
- Token-Permissions (9-10)

**Needs improvement (0-7/10):**
- Branch-Protection (5-8) - **Needs configuration**
- CII-Best-Practices (0) - **Needs registration**
- Contributors (3-5) - **Will improve with growth**
- Fuzzing (0) - **Future enhancement**

---

## Improvement Roadmap

### Quick Wins (This Week) - +1.0 to +1.5 points

1. **Configure Branch Protection** (+0.5 to +1.0)
   - Go to repository settings
   - Add branch protection rule
   - Enable PR reviews, status checks

2. **Verify Signed Releases** (+0.2 to +0.5)
   - Ensure Sigstore signing active
   - Test verification process
   - Document in SECURITY.md

### Short-Term (This Month) - +0.5 to +1.0 points

3. **Register for CII Best Practices Badge** (+0.3 to +0.5)
   - Complete questionnaire
   - Earn passing badge (60%+)
   - Add badge to README.md

4. **Improve Dependency Pinning** (+0.2)
   - Add SHA digests to Docker images
   - Use pip-tools with hashes
   - Document dependency management

### Long-Term (Future) - +0.5 points

5. **Add Fuzzing** (+0.3)
   - Integrate OSS-Fuzz
   - Add fuzzing tests
   - Document in SECURITY.md

6. **Grow Contributor Base** (+0.2)
   - Encourage community contributions
   - Good first issues
   - Contributor recognition

---

## Tracking and Monitoring

### Add Scorecard Badge to README

Once baseline is established:

```markdown
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cboyd0319/PyGuard/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cboyd0319/PyGuard)
```

### Monitor Trends

```bash
# Run scorecard monthly
scorecard --repo=github.com/cboyd0319/PyGuard --format=json > scorecard_$(date +%Y%m).json

# Compare with previous month
diff scorecard_202411.json scorecard_202412.json
```

### Set Up Alerts

Create GitHub issue automation for scorecard regressions:

```yaml
# .github/workflows/scorecard-alert.yml
name: Scorecard Alert

on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Check scorecard
        run: |
          SCORE=$(scorecard --repo=github.com/cboyd0319/PyGuard --format=json | jq '.score')
          if (( $(echo "$SCORE < 8.0" | bc -l) )); then
            gh issue create --title "Scorecard below target: $SCORE" \
              --body "OpenSSF Scorecard dropped below 8.0 target"
          fi
```

---

## Success Criteria

### v0.8.0 Goals

- [ ] Scorecard baseline established and documented
- [ ] Scorecard score >8.0
- [ ] All quick wins implemented (branch protection, badge)
- [ ] Scorecard badge added to README
- [ ] Monthly scorecard monitoring in place

### v1.0.0 Goals

- [ ] Scorecard score >8.5
- [ ] CII Best Practices badge earned
- [ ] Fuzzing integrated
- [ ] 5+ regular contributors
- [ ] All checks scoring 7+

---

## References

- **Scorecard Project:** https://github.com/ossf/scorecard
- **Scorecard Checks:** https://github.com/ossf/scorecard/blob/main/docs/checks.md
- **OpenSSF Best Practices:** https://bestpractices.coreinfrastructure.org/
- **PyGuard Scorecard Workflow:** `.github/workflows/scorecard.yml`
- **PyGuard Security Policy:** `SECURITY.md`

---

**Status:** Ready for baseline measurement
**Next Action:** Run scorecard locally and document baseline
**Owner:** PyGuard Core Team
**Last Updated:** 2025-11-14
