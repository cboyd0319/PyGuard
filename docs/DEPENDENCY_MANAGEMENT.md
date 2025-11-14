# Dependency Management & Supply Chain Security

## Overview

PyGuard implements comprehensive supply chain security measures following PYSEC_OMEGA best practices and industry standards (SLSA, Sigstore, SBOM).

## Hash Verification (SHA256)

All dependencies are pinned with cryptographic hashes to prevent supply chain attacks, including:
- Dependency confusion attacks
- Typosquatting
- Package hijacking
- Malicious dependency injection

### Files Structure

```
requirements.in          # Source file for production dependencies
requirements.txt         # Generated with SHA256 hashes for all dependencies
requirements-dev.in      # Source file for development dependencies  
requirements-dev.txt     # Generated with SHA256 hashes for all dev dependencies
```

### Updating Dependencies

#### 1. Update Source Files

Edit the `.in` files to add/update dependencies:

```bash
# Edit requirements.in for production dependencies
vim requirements.in

# Edit requirements-dev.in for development dependencies
vim requirements-dev.in
```

#### 2. Generate Hashed Requirements

Use `pip-tools` to generate requirements with hashes:

```bash
# Install pip-tools if not already installed
pip install pip-tools

# Generate requirements.txt with hashes
pip-compile --generate-hashes --allow-unsafe --resolver=backtracking requirements.in

# Generate requirements-dev.txt with hashes
pip-compile --generate-hashes --allow-unsafe --resolver=backtracking requirements-dev.in
```

#### 3. Install with Hash Verification

Install dependencies with automatic hash verification:

```bash
# Production dependencies only
pip install -r requirements.txt --require-hashes

# Development dependencies (includes production)
pip install -r requirements-dev.txt --require-hashes
```

### Why Hash Verification?

**Security Benefits:**
- ✅ **Immutability**: Exact versions with cryptographic verification
- ✅ **Tamper Detection**: Any modification to packages is immediately detected
- ✅ **Supply Chain Protection**: Prevents malicious package substitution
- ✅ **Reproducibility**: Identical installs across all environments
- ✅ **Audit Trail**: Exact dependencies used in production are documented

**Compliance:**
- SLSA Level 2+ requirement
- NIST Supply Chain Security guidelines
- OSSF Scorecard best practices
- SOC 2 Type II control evidence

## Dependency Scanning

PyGuard automatically scans dependencies for vulnerabilities using:

### 1. pip-audit (PyPI Advisory Database)

```bash
pip install pip-audit
pip-audit --format json --output audit-results.json
```

### 2. OSV-Scanner (Google's Open Source Vulnerabilities)

```bash
# Install OSV-Scanner (via binary, not pip)
# macOS: brew install osv-scanner
# Linux: Download from GitHub releases

osv-scanner --format json --output osv-results.json .
```

### 3. Safety DB

```bash
pip install safety
safety check --json --output safety-results.json
```

### 4. Dependabot (Automated)

GitHub Dependabot automatically:
- Scans for vulnerabilities weekly
- Creates PRs for security updates
- Groups related updates to reduce noise
- Prioritizes critical security patches

See `.github/dependabot.yml` for configuration.

## Dependency Updates Strategy

### Security Updates (Immediate)
- Applied within 24 hours of disclosure
- Automated via Dependabot
- Manual verification for breaking changes

### Minor/Patch Updates (Weekly)
- Reviewed and merged Monday mornings
- Grouped by dependency type
- Tested in CI/CD before merge

### Major Updates (Quarterly)
- Planned during maintenance windows
- Comprehensive testing required
- Migration guide prepared if needed

## Supply Chain Security Layers

### Layer 1: Source Control
- ✅ SHA-pinned GitHub Actions (all workflows)
- ✅ Dependabot for automated updates
- ✅ Required code reviews
- ✅ Signed commits recommended

### Layer 2: Build Process
- ✅ Reproducible builds (SOURCE_DATE_EPOCH)
- ✅ Hermetic build environment
- ✅ SLSA Level 3 provenance generation
- ✅ Build attestations via GitHub OIDC

### Layer 3: Artifact Security
- ✅ SBOM generation (SPDX 2.3, CycloneDX)
- ✅ SHA256 checksums for all artifacts
- ✅ Digital signatures (planned: Sigstore)
- ✅ Artifact attestations

### Layer 4: Runtime Protection
- ✅ Hash-verified dependency installation
- ✅ No arbitrary code execution during install
- ✅ Minimal runtime dependencies
- ✅ Regular security scanning

## Private Package Index (Optional)

If using a private PyPI mirror:

### Configuration

```toml
# pyproject.toml
[[tool.uv.index]]
name = "corporate"
url = "https://pypi.corp.internal/simple/"

# Priority: private index first, public second
[[tool.uv.index]]
name = "pypi"
url = "https://pypi.org/simple/"
```

### Security Considerations

1. **Never mix authenticated and public indexes without URL scoping**
2. **Use private index for all internal packages**
3. **Prevent dependency confusion attacks**
4. **Monitor for namespace hijacking**

See [SECURE_CODING_GUIDE.md](../security/SECURE_CODING_GUIDE.md) for comprehensive private registry security practices.

## Transitive Dependencies

### Audit Full Dependency Tree

```bash
# Install pipdeptree
pip install pipdeptree

# View all dependencies (including transitive)
pipdeptree --graph-output png > dependency-tree.png

# Find security issues in transitive deps
pipdeptree --warn silence | grep -i security
```

### Reachability Analysis

Not all vulnerabilities in transitive dependencies are exploitable:

1. Check if vulnerable code is actually used
2. Review call paths to vulnerable functions
3. Assess impact based on actual usage
4. Document exceptions with justification

## License Compliance

### Allowed Licenses
- MIT
- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- ISC
- Python Software Foundation License

### Generate License Report

```bash
pip install pip-licenses
pip-licenses --format=markdown --output-file=licenses.md
```

### Flag Problematic Licenses

```bash
# Flag GPL/LGPL (copyleft)
pip-licenses | grep -E "GPL|LGPL"

# Flag unknown licenses
pip-licenses --summary | grep Unknown
```

## Best Practices

### ✅ DO
- Use hash-verified requirements for all environments
- Update `.in` files, then regenerate `.txt` files
- Review dependency updates before merging
- Run security scans on all PRs
- Document exceptions with justification
- Test across Python 3.11, 3.12, 3.13

### ❌ DON'T
- Manually edit `requirements.txt` or `requirements-dev.txt`
- Skip hash verification (`--no-deps`, `--no-verify`)
- Install packages without reviewing source
- Use `pip freeze` for production requirements
- Allow untrusted package indexes
- Disable security scanners

## CI/CD Integration

All workflows automatically:
1. Use hash-verified requirements
2. Run dependency vulnerability scans
3. Generate SBOM for releases
4. Upload security findings to SARIF
5. Block PRs with high-severity vulnerabilities

See `.github/workflows/security-scan.yml` for implementation.

## Troubleshooting

### Hash Mismatch Error

```
ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE
```

**Cause**: Package was modified or re-uploaded to PyPI

**Solution**:
```bash
# Regenerate with latest hashes
pip-compile --generate-hashes --upgrade requirements.in
```

### Dependency Conflict

```
ERROR: Cannot install X and Y because these package versions have conflicting dependencies
```

**Solution**:
1. Check dependency constraints
2. Update one package at a time
3. Use `pip-compile` with `--upgrade-package` for specific updates
4. Document conflicts in requirements.in comments

### Slow Installation

Hash verification adds verification time but increases security.

**Mitigation**:
- Use pip cache: `pip install --cache-dir=/tmp/pip-cache`
- Pre-download wheels: `pip download -r requirements.txt`
- Use CI cache: `actions/cache` with lockfile hash key

## Additional Resources

- [SECURE_CODING_GUIDE.md](../security/SECURE_CODING_GUIDE.md) - Comprehensive Python security guidelines
- [SECURITY.md](../SECURITY.md) - Security policy and reporting
- [RISK_LEDGER.md](../security/RISK_LEDGER.md) - Current security risks
- [pip-tools documentation](https://pip-tools.readthedocs.io/)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore](https://www.sigstore.dev/)

---

**Last Updated:** 2025-10-20  
**Maintained By:** Security Team  
**Review Schedule:** Quarterly
