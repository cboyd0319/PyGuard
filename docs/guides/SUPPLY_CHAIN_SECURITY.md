# PyGuard Supply Chain Security Guide

## Overview

PyGuard implements **industry-leading supply chain security** practices to ensure the integrity and authenticity of releases. This guide documents our security measures and helps you verify PyGuard releases.

## Security Architecture

### Multi-Layer Defense

PyGuard's supply chain security uses multiple complementary layers:

```
┌─────────────────────────────────────────────┐
│  Layer 1: Build Provenance (SLSA Level 3)  │
│  ├─ GitHub OIDC Authentication              │
│  ├─ Build Attestations                      │
│  └─ Verifiable Build Process                │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Layer 2: Sigstore Signatures               │
│  ├─ Keyless Signing                         │
│  ├─ Rekor Transparency Log                  │
│  └─ Certificate Verification                │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Layer 3: SBOM Generation                   │
│  ├─ SPDX Format                             │
│  ├─ CycloneDX Format                        │
│  └─ Dependency Tracking                     │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  Layer 4: Checksums & Hashes                │
│  ├─ SHA256 Checksums                        │
│  ├─ Signed Checksums File                   │
│  └─ Verification Scripts                    │
└─────────────────────────────────────────────┘
```

## SLSA Level 3 Compliance

### What is SLSA?

[SLSA (Supply Chain Levels for Software Artifacts)](https://slsa.dev/) is a framework for ensuring the integrity of software artifacts throughout the supply chain.

### PyGuard's SLSA Implementation

**Level 3 Requirements Met:**
- ✅ **Build provenance**: Attestations for all artifacts
- ✅ **Isolated builds**: GitHub Actions hosted runners
- ✅ **Ephemeral environments**: Fresh containers per build
- ✅ **Non-falsifiable**: GitHub OIDC prevents impersonation
- ✅ **Parameterless builds**: Reproducible from source

### Verifying Build Provenance

```bash
# Install GitHub CLI
brew install gh  # or see https://cli.github.com/

# Verify an artifact's provenance
gh attestation verify pyguard-0.8.0.tar.gz \
  --repo cboyd0319/PyGuard

# Output shows:
# ✓ Verification succeeded!
# ✓ Built by .github/workflows/release.yml
# ✓ SLSA provenance verified
```

## Sigstore Integration

### Keyless Signing

PyGuard uses Sigstore's keyless signing, which means:

1. **No private keys to manage**: Uses GitHub's OIDC tokens
2. **Automatic rotation**: Tokens expire after minutes
3. **Identity verification**: Tied to specific workflow and tag
4. **Public transparency**: All signatures in Rekor log

### What Gets Signed

Every release artifact is signed:

| Artifact | Purpose | Signed |
|----------|---------|--------|
| `pyguard-X.Y.Z.tar.gz` | Source distribution | ✅ |
| `pyguard-X.Y.Z-py3-none-any.whl` | Wheel package | ✅ |
| `pyguard-X.Y.Z.spdx.json` | SBOM (SPDX) | ✅ |
| `pyguard-X.Y.Z.cyclonedx.json` | SBOM (CycloneDX) | ✅ |
| `checksums.sha256` | All checksums | ✅ |

### Signature Files

Each signed artifact gets two files:

- **`.sig`** - The cryptographic signature
- **`.crt`** - The signing certificate (contains identity)

**Example:**
```
pyguard-0.8.0.tar.gz
pyguard-0.8.0.tar.gz.sig    ← Signature
pyguard-0.8.0.tar.gz.crt    ← Certificate
```

### Verification Process

See [docs/security/SIGNATURE_VERIFICATION.md](../security/SIGNATURE_VERIFICATION.md) for detailed verification instructions.

**Quick verification:**
```bash
pip install sigstore

sigstore verify github pyguard-0.8.0.tar.gz \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com
```

## SBOM (Software Bill of Materials)

### Why SBOM Matters

An SBOM provides:
- Complete inventory of dependencies
- Version information for vulnerability tracking
- License compliance checking
- Transparency about what's included

### Two Formats

PyGuard generates SBOMs in both industry-standard formats:

#### SPDX 2.3

**Use case:** Enterprise compliance, legal review

```bash
# Download SBOM
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.spdx.json

# Verify signature
sigstore verify github pyguard-0.8.0.spdx.json \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# Analyze with SPDX tools
pip install spdx-tools
pyspdxtools -i pyguard-0.8.0.spdx.json
```

#### CycloneDX

**Use case:** Security scanning, dependency tracking

```bash
# Download SBOM
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.cyclonedx.json

# Verify signature
sigstore verify github pyguard-0.8.0.cyclonedx.json \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# Scan for vulnerabilities
pip install cyclonedx-cli
cyclonedx validate --input-file pyguard-0.8.0.cyclonedx.json
```

### SBOM Contents

Our SBOMs include:

- **Package information**: Name, version, license
- **Dependencies**: Direct and transitive
- **Checksums**: SHA256 for all components
- **Relationships**: Dependency graph
- **Metadata**: Build time, creator, tool versions

## Checksum Verification

### SHA256 Checksums

Every release includes a `checksums.sha256` file with hashes for all artifacts.

**Download and verify:**
```bash
# Download checksums file
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/checksums.sha256

# Verify signature on checksums file
sigstore verify github checksums.sha256 \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# Download artifacts
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.tar.gz
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0-py3-none-any.whl

# Verify checksums
sha256sum -c checksums.sha256
# ✓ pyguard-0.8.0.tar.gz: OK
# ✓ pyguard-0.8.0-py3-none-any.whl: OK
```

## Release Workflow Security

### Workflow Hardening

Our release workflow implements security best practices:

#### 1. Action Pinning

All GitHub Actions are pinned to specific SHA commits:

```yaml
# ❌ BAD - Vulnerable to tag hijacking
- uses: actions/checkout@v4

# ✅ GOOD - Pinned to specific SHA
- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
```

#### 2. Minimal Permissions

Workflows use least-privilege permissions:

```yaml
permissions:
  contents: write       # Only what's needed
  packages: write       # for releases
  id-token: write       # for OIDC
  attestations: write   # for provenance
```

#### 3. Environment Isolation

- Fresh container per build
- No persistent state between builds
- Ephemeral credentials (GitHub OIDC)

#### 4. Audit Trail

Everything is logged:
- GitHub Actions logs (public)
- Rekor transparency log (public)
- SLSA provenance (verifiable)

### Workflow Source

View our release workflow: [.github/workflows/release.yml](../../.github/workflows/release.yml)

## Dependency Security

### Dependency Scanning

PyGuard's dependencies are continuously scanned:

- **Dependabot**: Automated security updates
- **pip-audit**: Python vulnerability scanning
- **OSV-Scanner**: Cross-ecosystem vulnerability detection
- **Safety**: Known security issues database

### Minimal Dependencies

PyGuard maintains a minimal dependency footprint:

**Runtime dependencies (~14 packages):**
- AST manipulation: `astroid`, `ast-decompiler`
- Code formatting: `black`, `isort`
- UI/reporting: `rich`, `jinja2`
- Utilities: `pyyaml`, `toml`, `click`

**Development dependencies** are not included in releases.

### Dependency Verification

```bash
# Download SBOM
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.spdx.json

# Extract dependencies
jq '.packages[] | select(.name != "pyguard") | .name' pyguard-0.8.0.spdx.json

# Scan for vulnerabilities
pip install pip-audit
pip-audit --desc on --requirement <(jq -r '.packages[] | select(.name != "pyguard") | .name + "==" + .versionInfo' pyguard-0.8.0.spdx.json)
```

## Incident Response

### Vulnerability Disclosure

**If you find a security issue:**

1. **DO NOT** open a public GitHub issue
2. **DO** report via [GitHub Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories/new)
3. Include: Description, impact, reproduction steps
4. We respond within 3 business days

See [SECURITY.md](../../SECURITY.md) for full policy.

### Compromised Release Detection

**Red flags that might indicate compromise:**

- ❌ Signature verification fails
- ❌ Checksum mismatch
- ❌ No Rekor transparency log entry
- ❌ SLSA provenance missing or invalid
- ❌ Unexpected workflow identity

**If you suspect a compromise:**

1. **Stop using the artifact immediately**
2. Report via [Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories/new)
3. Include: Version, verification output, how you obtained it
4. Wait for official response

### Past Incidents

**No security incidents to date** (as of v0.8.0)

We maintain a security advisory feed:
https://github.com/cboyd0319/PyGuard/security/advisories

## Best Practices for Users

### Installation Security

#### ✅ Recommended: Verify Before Installing

```bash
# 1. Download release
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.tar.gz

# 2. Verify signature
pip install sigstore
sigstore verify github pyguard-0.8.0.tar.gz \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# 3. Install after verification
pip install pyguard-0.8.0.tar.gz
```

#### ⚠️ PyPI Installation

PyPI doesn't yet support Sigstore verification (coming with PEP 740).

**For now:**
```bash
# PyPI installation (no signature verification)
pip install pyguard

# Verify after installation
pip show pyguard  # Check version matches GitHub release
pyguard --version  # Confirm working correctly
```

#### ❌ Avoid: Unverified Sources

Don't install from:
- Random GitHub forks
- Third-party package indexes
- Unverified mirror sites
- Unofficial Docker images

**Always use:**
- Official PyPI: `pip install pyguard`
- Official GitHub releases: https://github.com/cboyd0319/PyGuard/releases
- Official Docker: `docker pull cboyd0319/pyguard` (v0.7.0+)
- Official Homebrew: `brew install cboyd0319/pyguard/pyguard` (v0.7.0+)

### CI/CD Security

Add verification to CI/CD pipelines:

#### GitHub Actions

```yaml
- name: Install PyGuard with verification
  run: |
    pip install sigstore
    VERSION="0.8.0"
    
    # Download
    wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz
    
    # Verify
    sigstore verify github pyguard-${VERSION}.tar.gz \
      --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION} \
      --cert-oidc-issuer https://token.actions.githubusercontent.com
    
    # Install
    pip install pyguard-${VERSION}.tar.gz
```

#### GitLab CI

```yaml
install-pyguard:
  script:
    - pip install sigstore
    - VERSION="0.8.0"
    - wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz
    - |
      sigstore verify github pyguard-${VERSION}.tar.gz \
        --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION} \
        --cert-oidc-issuer https://token.actions.githubusercontent.com
    - pip install pyguard-${VERSION}.tar.gz
```

### Docker Security

When using Docker images:

```bash
# Pull official image
docker pull cboyd0319/pyguard:0.8.0

# Verify image digest (once available)
docker image inspect cboyd0319/pyguard:0.8.0

# Run with security options
docker run --rm --read-only -v $(pwd):/code:ro \
  cboyd0319/pyguard:0.8.0 /code
```

## OpenSSF Scorecard

We track our supply chain security with [OpenSSF Scorecard](https://securityscorecards.dev/):

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cboyd0319/PyGuard/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cboyd0319/PyGuard)

**Target Score: >8.0** (v0.8.0 goal)

### Scorecard Checks We Pass

- ✅ **Binary-Artifacts**: No committed binaries
- ✅ **Branch-Protection**: Main branch protected
- ✅ **CI-Tests**: Comprehensive test suite
- ✅ **CII-Best-Practices**: Following best practices
- ✅ **Code-Review**: All PRs reviewed
- ✅ **Dangerous-Workflow**: Safe workflow patterns
- ✅ **Dependency-Update-Tool**: Dependabot enabled
- ✅ **Fuzzing**: Fuzz testing implemented
- ✅ **License**: OSI-approved license
- ✅ **Maintained**: Active development
- ✅ **Pinned-Dependencies**: All actions pinned
- ✅ **SAST**: Multiple SAST tools
- ✅ **Security-Policy**: Published security policy
- ✅ **Signed-Releases**: Sigstore signing
- ✅ **Token-Permissions**: Minimal permissions
- ✅ **Vulnerabilities**: No known vulnerabilities

## Compliance Mappings

PyGuard's supply chain security supports compliance with:

### Industry Standards

| Standard | Requirement | PyGuard Implementation |
|----------|-------------|------------------------|
| **NIST SSDF** | Build provenance | SLSA Level 3 attestations |
| **NIST SSDF** | Dependency tracking | SBOM (SPDX + CycloneDX) |
| **NIST SSDF** | Signature verification | Sigstore signing |
| **ISO 27001** | Supply chain security | Multi-layer verification |
| **SOC 2** | Change management | Git-based, reviewed workflows |
| **PCI-DSS** | Secure software development | SAST, SBOM, signatures |

### Future Enhancements (v1.0+)

- [ ] PEP 740 attestations for PyPI
- [ ] GPG signing (complementary to Sigstore)
- [ ] Reproducible builds (bit-for-bit)
- [ ] SLSA Level 4 (two-person review)
- [ ] VEX (Vulnerability Exploitability eXchange)

## Resources

### Official Documentation

- [SLSA Framework](https://slsa.dev/)
- [Sigstore Project](https://www.sigstore.dev/)
- [SPDX Specification](https://spdx.dev/)
- [CycloneDX Standard](https://cyclonedx.org/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)

### PyGuard Security

- [Security Policy](../../SECURITY.md)
- [Signature Verification Guide](../security/SIGNATURE_VERIFICATION.md)
- [Release Workflow](../../.github/workflows/release.yml)
- [Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories)

### Industry Standards

- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)
- [CISA SBOM](https://www.cisa.gov/sbom)
- [OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/)

## FAQ

### Why both SLSA and Sigstore?

They serve complementary purposes:

- **SLSA**: Proves *how* it was built (provenance)
- **Sigstore**: Proves *who* built it (identity)

Together they provide complete supply chain security.

### Can I verify old releases?

- **v0.8.0+**: Full Sigstore + SLSA verification ✅
- **v0.7.0**: SLSA provenance only
- **v0.6.0 and earlier**: SHA256 checksums only

### What if Sigstore is down?

Signatures and certificates are included in releases. You can verify offline using cosign:

```bash
cosign verify-blob artifact \
  --certificate artifact.crt \
  --signature artifact.sig \
  --certificate-identity <identity> \
  --certificate-oidc-issuer <issuer>
```

### Do I need to verify every time?

**Recommended:**
- ✅ Verify on first install
- ✅ Verify in CI/CD pipelines
- ✅ Verify for production deployments
- ✅ Verify after security advisories

**Optional:**
- Updates from PyPI (relies on PyPI security)
- Development/testing environments

---

**Last Updated**: 2025-11-03 (v0.8.0 development)  
**Maintained by**: PyGuard Security Team  
**Questions?**: See [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
