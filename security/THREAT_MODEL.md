# PyGuard Threat Model

**Version:** 1.0  
**Last Updated:** 2025-10-19  
**Scope:** PyGuard v0.3.0 - Python Security & Compliance Tool

## Overview

PyGuard is a static analysis security tool that scans Python codebases for vulnerabilities and security issues. This threat model identifies potential threats to PyGuard itself and to systems using PyGuard.

---

## System Context

### What is PyGuard?

PyGuard is a Python security scanner that:
- Analyzes Python source code for vulnerabilities
- Detects secrets, SQL injection, command injection, etc.
- Generates SARIF reports for CI/CD integration
- Provides auto-fix capabilities for common issues
- Supports Jupyter notebooks
- Integrates with GitHub Actions

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ External/Untrusted Zone                                     │
│  - User-provided source code to scan                        │
│  - User configuration files                                 │
│  - Third-party dependencies                                 │
│  - GitHub PR code (via Actions)                             │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ PyGuard Trusted Zone                                        │
│  - PyGuard core scanner                                     │
│  - Analysis engines (AST, pattern matching)                 │
│  - Report generation                                        │
│  - Auto-fix engine                                          │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ Output Zone                                                 │
│  - SARIF reports                                            │
│  - Log files                                                │
│  - Modified source files (auto-fix)                         │
│  - GitHub Security tab (via Actions)                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Assets

### Critical Assets
1. **PyGuard Source Code** - The tool itself must be secure
2. **User's Source Code** - Code being scanned (confidential)
3. **Scan Results** - Security findings (sensitive)
4. **GitHub Tokens** - Used for GitHub Actions integration
5. **Release Artifacts** - Distributed via PyPI

### Data Flow
1. User provides Python code → PyGuard scans → Generates reports
2. GitHub Actions runs PyGuard → Uploads SARIF → GitHub Security tab
3. PyGuard auto-fix modifies code → User reviews changes

---

## Threat Actors

### External Attackers
- **Motivation:** Supply chain attacks, data theft, system compromise
- **Capabilities:** Can submit malicious code, craft exploits, social engineering
- **Access:** Public GitHub repo, PyPI distribution, submitted code

### Insider Threats
- **Motivation:** Sabotage, IP theft
- **Capabilities:** Code contribution access, CI/CD knowledge
- **Access:** Limited by code review requirements

### Accidental Threats
- **Motivation:** None (unintentional)
- **Capabilities:** Introduce bugs, misconfigurations
- **Access:** Contributors, users

---

## Threats & Mitigations

### T1: Malicious Code Injection via Scanned Files

**Threat:** Attacker provides malicious Python code that exploits vulnerabilities in PyGuard's parser/analyzer

**Attack Vectors:**
- Crafted AST structures that cause code execution
- Pickle/YAML payloads in scanned files
- Path traversal in import statements
- Infinite loops or resource exhaustion

**Impact:** High - Could compromise scanning system

**Mitigations:**
- ✅ Use `ast.parse()` (safe) instead of `eval()`/`exec()`
- ✅ Sandbox analysis (no code execution, static analysis only)
- ✅ Resource limits (timeout on scans)
- 🔄 Validate all file paths (prevent path traversal)
- 🔄 Limit recursion depth in AST analysis

**Status:** Partially Mitigated

---

### T2: Supply Chain Attack via Dependencies

**Threat:** Compromised or malicious dependencies (typosquatting, dependency confusion)

**Attack Vectors:**
- Malicious packages on PyPI
- Compromised legitimate packages
- Transitive dependency vulnerabilities

**Impact:** Critical - Could affect all PyGuard users

**Mitigations:**
- ✅ Dependency review in PRs
- ✅ Dependabot for updates
- ✅ OSSF Scorecard monitoring
- 🔄 Hash pinning in requirements.txt
- 🔄 Automated pip-audit/OSV scanning
- 🔄 SBOM generation and verification

**Status:** Actively Being Hardened

---

### T3: GitHub Actions Workflow Injection

**Threat:** Attacker injects malicious code via PR title/body/issue that gets executed in workflows

**Attack Vectors:**
- Unescaped `${{ github.event.issue.title }}` in `run:` blocks
- PR code execution in `pull_request_target` workflows
- Compromised third-party actions

**Impact:** High - Could compromise CI/CD, steal secrets

**Mitigations:**
- ✅ Minimal workflow permissions (contents: read)
- ✅ SHA-pinned actions with version comments
- ✅ No `pull_request_target` workflows with code checkout
- ✅ Environment variables for untrusted input
- 🔄 Audit all workflows for injection vectors

**Status:** Good, Under Review

---

### T4: Secrets Leakage in Scan Results

**Threat:** PyGuard scan reports inadvertently expose secrets from scanned code

**Attack Vectors:**
- Secrets in SARIF reports uploaded to GitHub
- Secrets in log files
- Secrets in error messages

**Impact:** High - Data breach, credential compromise

**Mitigations:**
- ✅ PyGuard detects secrets (but must not log them)
- 🔄 Sanitize all output (redact detected secrets)
- 🔄 Review SARIF generation for secret exposure
- 🔄 Implement secret redaction in logs

**Status:** Requires Review

---

### T5: Auto-Fix Code Modification Vulnerabilities

**Threat:** PyGuard's auto-fix feature introduces new vulnerabilities or breaks code

**Attack Vectors:**
- Logic errors in fix patterns
- Incomplete fixes that worsen security
- File corruption or data loss

**Impact:** Medium - Could harm user's codebase

**Mitigations:**
- ✅ Backup created before auto-fix (`.pyguard_backups/`)
- ✅ Scan-only mode available (no modifications)
- ✅ User review required before deployment
- 🔄 Comprehensive tests for all fix patterns
- 🔄 Property-based testing (Hypothesis) for fixes

**Status:** Acceptable with Current Safeguards

---

### T6: Insufficient Input Validation

**Threat:** PyGuard doesn't validate configuration files, leading to exploits

**Attack Vectors:**
- Malicious `pyproject.toml` settings
- Command injection via config values
- Path traversal in config paths

**Impact:** Medium - Could affect scanning behavior

**Mitigations:**
- ✅ Use safe YAML/TOML parsers
- 🔄 Validate all config values against schema
- 🔄 Sanitize file paths from config
- 🔄 Reject dangerous config options

**Status:** Requires Hardening

---

### T7: Denial of Service (Resource Exhaustion)

**Threat:** Attacker provides code that causes PyGuard to consume excessive resources

**Attack Vectors:**
- Extremely large files
- Deeply nested AST structures
- Infinite loops in regex patterns
- Memory exhaustion

**Impact:** Low - Availability issue, no data compromise

**Mitigations:**
- ✅ Timeout limits in CI workflows (20 min)
- 🔄 File size limits
- 🔄 Recursion depth limits
- 🔄 Memory usage monitoring

**Status:** Basic Mitigations in Place

---

### T8: Compromised Release Artifacts

**Threat:** Attackers distribute malicious PyGuard packages via PyPI or GitHub

**Attack Vectors:**
- Compromised PyPI account
- Compromised GitHub releases
- Man-in-the-middle during download

**Impact:** Critical - Supply chain attack on users

**Mitigations:**
- ✅ 2FA on PyPI account
- ✅ GitHub Actions for releases (OIDC)
- ✅ SBOM generation
- ✅ Build provenance attestation
- 🔄 Sigstore signing
- 🔄 Reproducible builds

**Status:** Good, Adding Signing

---

### T9: Information Disclosure via Error Messages

**Threat:** Verbose error messages reveal sensitive information

**Attack Vectors:**
- Stack traces with internal paths
- Debug logs with credentials
- SARIF reports with too much context

**Impact:** Low - Information leakage

**Mitigations:**
- ✅ Production logging sanitized
- 🔄 Review error message verbosity
- 🔄 Implement log levels (debug vs. production)

**Status:** Acceptable

---

### T10: Jupyter Notebook Execution Risks

**Threat:** Scanning Jupyter notebooks with embedded malicious code

**Attack Vectors:**
- Magic commands execution
- Kernel exploits
- Output injection

**Impact:** Medium - Could execute code during scan

**Mitigations:**
- ✅ Static analysis only (no kernel execution)
- ✅ nbformat for safe parsing
- 🔄 Sanitize notebook outputs before processing
- 🔄 Document that PyGuard never executes notebooks

**Status:** Safe (Static Analysis Only)

---

## Security Controls Summary

### Implemented Controls ✅

1. **Input Validation**
   - AST-based parsing (no code execution)
   - Safe YAML/TOML parsing
   - Static analysis only

2. **Access Controls**
   - GitHub Actions minimal permissions
   - No elevated privileges required
   - 2FA on release accounts

3. **Monitoring & Logging**
   - CodeQL weekly scans
   - OSSF Scorecard
   - Dependency review

4. **Secure Development**
   - Code review required
   - Test coverage >87%
   - Multiple linters/type checkers

### In Progress 🔄

1. **Supply Chain Security**
   - Hash pinning requirements
   - Automated vulnerability scanning
   - SBOM generation
   - Artifact signing

2. **Runtime Security**
   - Resource limits
   - Input sanitization
   - Config validation

3. **Secrets Management**
   - Automated secrets scanning
   - Log sanitization
   - Output redaction

---

## Residual Risks

After implementing all planned mitigations:

1. **Zero-Day Vulnerabilities in Dependencies** - Mitigated by rapid patching
2. **Advanced Persistent Threats** - Beyond scope, assume secure development environment
3. **Social Engineering** - Rely on code review and 2FA
4. **Physical Security** - GitHub/PyPI infrastructure security

---

## Security Testing Plan

### Static Analysis
- [x] Bandit SAST
- [ ] Semgrep with security rules
- [x] CodeQL extended queries
- [ ] Custom security checks

### Dynamic Testing
- [ ] Fuzz testing with Hypothesis
- [ ] Property-based testing for parsers
- [ ] Resource exhaustion tests

### Penetration Testing
- [ ] Supply chain attack simulation
- [ ] Workflow injection testing
- [ ] Malicious input fuzzing

---

## Incident Response

### Security Issue Discovered

1. **Assessment** - Determine severity and scope
2. **Containment** - Remove vulnerable code/releases
3. **Remediation** - Patch and test fix
4. **Communication** - Disclose via GitHub Security Advisories
5. **Post-Mortem** - Update threat model and controls

### Contact

- GitHub Security Advisories: https://github.com/cboyd0319/PyGuard/security/advisories
- Email: security@pyguard.dev (if configured)

---

## Assumptions

1. PyGuard runs in trusted environment (not on untrusted/public servers)
2. Users review auto-fix changes before production deployment
3. CI/CD environment follows security best practices
4. Dependencies from PyPI are monitored by ecosystem security teams
5. GitHub Actions infrastructure is secure

---

## References

- STRIDE Threat Modeling: https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
- NIST SP 800-154: Guide to Data-Centric System Threat Modeling

---

**Review Schedule:** Quarterly or after major releases  
**Next Review:** 2026-01-19
