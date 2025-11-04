# SLSA Provenance Verification Guide

## Overview

PyGuard implements **SLSA Level 3 build provenance** for all releases, providing cryptographic
assurance about how PyGuard was built. This guide explains how to verify PyGuard's build provenance
and what security guarantees it provides.

## What is SLSA?

[SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) is a security framework
developed by Google and the OpenSSF to prevent supply chain attacks. It provides graduated levels
of supply chain security from Level 0 (no guarantees) to Level 4 (highest assurance).

**PyGuard achieves SLSA Level 3**, which provides:
- **Non-falsifiable provenance**: Build metadata cannot be tampered with
- **Isolated builds**: Builds run in ephemeral, isolated environments
- **Verifiable identity**: Build provenance is cryptographically tied to the GitHub workflow
- **Tamper-evident audit trail**: All build events recorded in public transparency logs

## PyGuard's SLSA Implementation

### Build Provenance Generation

Every PyGuard release automatically generates build provenance attestations using GitHub's
`actions/attest-build-provenance` action. These attestations contain:

- **Builder Identity**: The specific GitHub Actions workflow that performed the build
- **Build Parameters**: All inputs and environment variables used
- **Source Repository**: The exact commit SHA and ref (tag/branch) that was built
- **Timestamp**: When the build occurred
- **Artifacts**: Cryptographic hashes of all generated artifacts

### What Gets Attested

Build provenance is generated for all PyGuard artifacts:

| Artifact | Description | Attested |
|----------|-------------|----------|
| `pyguard-X.Y.Z.tar.gz` | Source distribution (sdist) | ✅ |
| `pyguard-X.Y.Z-py3-none-any.whl` | Python wheel package | ✅ |
| SBOM files | Software Bill of Materials | ✅ |
| Checksums | SHA256 checksums file | ✅ |

## Verifying Build Provenance

### Prerequisites

Install the GitHub CLI with attestation support:

```bash
# macOS
brew install gh

# Ubuntu/Debian
type -p curl >/dev/null || sudo apt install curl -y
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh -y

# Windows
winget install --id GitHub.cli
```

**Version requirement**: GitHub CLI v2.40.0 or later (includes `gh attestation verify` command)

```bash
# Check version
gh --version
# Output: gh version 2.40.0 (2024-01-23)
```

### Basic Verification

Verify any PyGuard artifact downloaded from a release:

```bash
# Download artifact
VERSION="0.8.0"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz"

# Verify provenance
gh attestation verify "pyguard-${VERSION}.tar.gz" \
  --repo cboyd0319/PyGuard

# Expected output:
# Loaded digest sha256:abc123... for file://pyguard-0.8.0.tar.gz
# Loaded 1 attestation from GitHub API
# ✓ Verification succeeded!
#
# sha256:abc123... was attested by:
# REPO            PREDICATE_TYPE          WORKFLOW
# cboyd0319/PyGuard  https://slsa.dev/provenance/v1  .github/workflows/release.yml@refs/tags/v0.8.0
```

**What this verifies:**
- ✅ Artifact was built by the official PyGuard repository
- ✅ Artifact was built by the specified release workflow
- ✅ Artifact corresponds to the specific git tag
- ✅ Artifact hasn't been tampered with since build
- ✅ Build happened in an isolated GitHub Actions runner

### Detailed Verification

For more detailed provenance information:

```bash
# Download and examine attestation bundle
gh attestation download "pyguard-${VERSION}.tar.gz" \
  --repo cboyd0319/PyGuard \
  --output attestation-bundle.json

# Pretty-print the provenance
cat attestation-bundle.json | jq '.attestations[0].verificationResult.statement'
```

**Provenance fields explained:**

```json
{
  "subject": [{
    "name": "pyguard-0.8.0.tar.gz",
    "digest": {
      "sha256": "abc123..."
    }
  }],
  "predicate": {
    "buildType": "https://slsa.dev/provenance/v1",
    "builder": {
      "id": "https://github.com/actions/runner/github-hosted"
    },
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/cboyd0319/PyGuard@refs/tags/v0.8.0",
        "digest": {
          "sha1": "def456..."
        }
      }
    },
    "metadata": {
      "buildStartedOn": "2024-11-03T10:15:30Z",
      "buildFinishedOn": "2024-11-03T10:18:45Z"
    }
  }
}
```

### Automated CI/CD Verification

Integrate provenance verification into your CI/CD pipeline:

```yaml
# .github/workflows/verify-pyguard.yml
name: Verify PyGuard Provenance

on:
  pull_request:
  schedule:
    - cron: '0 0 * * 1'  # Weekly

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Download PyGuard
        run: |
          VERSION="0.8.0"
          wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz"
      
      - name: Verify provenance
        run: |
          gh attestation verify pyguard-${VERSION}.tar.gz \
            --repo cboyd0319/PyGuard
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Install only if verified
        if: success()
        run: pip install pyguard-${VERSION}.tar.gz
```

## Advanced Verification Scenarios

### Verify Specific Workflow

Verify that an artifact was built by a specific workflow at a specific ref:

```bash
gh attestation verify pyguard-0.8.0.tar.gz \
  --repo cboyd0319/PyGuard \
  --owner cboyd0319
```

### Verify Multiple Artifacts

Verify all artifacts from a release:

```bash
# Download all release artifacts
VERSION="0.8.0"
gh release download "v${VERSION}" --repo cboyd0319/PyGuard --pattern "*.tar.gz" --pattern "*.whl"

# Verify each
for file in pyguard-${VERSION}*; do
  echo "Verifying $file..."
  gh attestation verify "$file" --repo cboyd0319/PyGuard
done
```

### Offline Verification

For air-gapped environments, download attestation bundles separately:

```bash
# Online machine: Download artifact and attestation
gh attestation download pyguard-0.8.0.tar.gz \
  --repo cboyd0319/PyGuard \
  --output attestation-bundle.json

# Transfer both files to offline machine
# Offline machine: Verify using local bundle
gh attestation verify pyguard-0.8.0.tar.gz \
  --bundle attestation-bundle.json
```

## SLSA Level 3 Requirements Met

PyGuard satisfies all SLSA Level 3 requirements:

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Build provenance** | ✅ | GitHub Actions attestations |
| **Non-falsifiable** | ✅ | GitHub OIDC prevents impersonation |
| **Isolated builds** | ✅ | Ephemeral GitHub Actions runners |
| **Parameterless** | ✅ | Reproducible from source only |
| **Hermetic** | ✅ | Pinned dependencies with SHA256 hashes |
| **Provenance available** | ✅ | Downloadable via GitHub API |
| **Provenance authentic** | ✅ | Signed with GitHub's signing key |

## Comparison with Other Signing Methods

PyGuard uses multiple complementary signing mechanisms:

| Method | Purpose | Trust Model | Verification |
|--------|---------|-------------|--------------|
| **SLSA Provenance** | Build integrity | GitHub OIDC | `gh attestation verify` |
| **Sigstore/Cosign** | Release signing | Keyless (OIDC) | `sigstore verify` |
| **GPG Signatures** | Traditional signing | PGP web of trust | `gpg --verify` |

**Recommended approach**: Verify all three for maximum assurance. Each provides different guarantees:
- SLSA provenance proves *how* the artifact was built
- Sigstore proves *who* signed the release
- GPG provides long-term verifiability even if OIDC tokens expire

## Troubleshooting

### Error: "No attestations found"

**Cause**: Artifact was not built with provenance generation, or attestation not yet propagated.

**Solution**: Wait a few minutes for attestations to propagate to GitHub API. For older releases (pre-v0.8.0), provenance may not be available.

### Error: "Verification failed: subject digest mismatch"

**Cause**: Artifact has been modified or corrupted after build.

**Solution**: Re-download the artifact from the official GitHub release page. If issue persists, report to security@pyguard.dev.

### Error: "gh: command not found"

**Cause**: GitHub CLI not installed or not in PATH.

**Solution**: Install GitHub CLI following instructions in Prerequisites section.

## Security Implications

### What SLSA Provenance DOES Protect Against

- ✅ **Compromised build scripts**: Provenance shows exact workflow used
- ✅ **Artifact tampering**: Cryptographic hashes detect any modifications
- ✅ **Build parameter injection**: All parameters are recorded and verifiable
- ✅ **Malicious maintainer**: Provenance ties artifacts to specific code commits
- ✅ **Supply chain attacks**: End-to-end verifiability from source to artifact

### What SLSA Provenance DOES NOT Protect Against

- ❌ **Compromised source code**: Provenance verifies *build integrity*, not code correctness
- ❌ **Vulnerabilities**: Provenance doesn't detect bugs or security flaws
- ❌ **Compromised dependencies**: Verify dependencies separately (see SBOM)

### Defense in Depth

For complete security, combine SLSA provenance verification with:

1. **Code review**: Audit PyGuard source code on GitHub
2. **SBOM analysis**: Check dependencies for known vulnerabilities
3. **Signature verification**: Verify Sigstore and GPG signatures
4. **Security scanning**: Run security tools (Bandit, CodeQL) on downloaded code
5. **Sandboxed testing**: Test in isolated environment before production use

## References

- [SLSA Framework](https://slsa.dev/)
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
- [OpenSSF Best Practices](https://best.openssf.org/)
- [PyGuard Supply Chain Security Guide](SUPPLY_CHAIN_SECURITY.md)
- [Sigstore Documentation](https://docs.sigstore.dev/)

## Getting Help

- **Questions**: [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- **Security Issues**: [Security Policy](../../SECURITY.md)
- **Documentation**: [PyGuard Docs](../index.md)

---

**Last Updated**: 2025-11-04  
**Applies To**: PyGuard v0.8.0+  
**SLSA Level**: 3 (Meets all requirements)
