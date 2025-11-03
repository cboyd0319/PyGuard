# PyGuard Signature Verification Guide

## Overview

Starting with v0.8.0, all PyGuard releases are signed using [Sigstore](https://www.sigstore.dev/), providing cryptographic proof of authenticity and integrity. This guide explains how to verify PyGuard releases.

## What is Sigstore?

Sigstore provides:
- **Keyless signing**: No need to manage GPG keys
- **Transparency**: All signatures recorded in public Rekor log
- **GitHub integration**: Uses GitHub OIDC for identity verification
- **Standard tooling**: Works with standard verification tools

## Quick Start

### Install Verification Tools

```bash
# Install sigstore CLI
pip install sigstore

# Or use cosign (alternative)
brew install sigstore/tap/cosign
```

### Verify a Release Artifact

```bash
# Download release files (example for v0.8.0)
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.tar.gz
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.tar.gz.sig
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.tar.gz.crt

# Verify with sigstore CLI
sigstore verify github pyguard-0.8.0.tar.gz \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# Verify with cosign (alternative)
cosign verify-blob pyguard-0.8.0.tar.gz \
  --certificate pyguard-0.8.0.tar.gz.crt \
  --signature pyguard-0.8.0.tar.gz.sig \
  --certificate-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## What Gets Signed?

All release artifacts are signed:

| Artifact Type | Example | Signature Files |
|---------------|---------|-----------------|
| Source tarball | `pyguard-0.8.0.tar.gz` | `.sig`, `.crt` |
| Wheel package | `pyguard-0.8.0-py3-none-any.whl` | `.sig`, `.crt` |
| SBOM (SPDX) | `pyguard-0.8.0.spdx.json` | `.sig`, `.crt` |
| SBOM (CycloneDX) | `pyguard-0.8.0.cyclonedx.json` | `.sig`, `.crt` |
| Checksums | `checksums.sha256` | `.sig`, `.crt` |

## Verification Methods

### Method 1: Sigstore CLI (Recommended)

**Advantages:**
- Simple, one-command verification
- Automatic Rekor log verification
- Built-in GitHub OIDC verification

**Usage:**
```bash
sigstore verify github <artifact> \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v<version> \
  --cert-oidc-issuer https://token.actions.githubusercontent.com
```

**Success output:**
```
OK: Verified signature
```

### Method 2: Cosign

**Advantages:**
- Works offline with downloaded signatures
- More control over verification parameters

**Usage:**
```bash
cosign verify-blob <artifact> \
  --certificate <artifact>.crt \
  --signature <artifact>.sig \
  --certificate-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Method 3: Python sigstore Library

**For programmatic verification:**

```python
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity
from sigstore.oidc import Issuer

# Load artifact and signature
with open("pyguard-0.8.0.tar.gz", "rb") as f:
    artifact = f.read()

with open("pyguard-0.8.0.tar.gz.crt", "rb") as f:
    cert = f.read()

with open("pyguard-0.8.0.tar.gz.sig", "rb") as f:
    sig = f.read()

# Verify
verifier = Verifier.production()
policy = Identity(
    identity="https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0",
    issuer=Issuer.GITHUB
)

result = verifier.verify(
    input_=artifact,
    certificate=cert,
    signature=sig,
    policy=policy
)

print(f"Verified: {result}")
```

## Understanding the Certificate

The signing certificate contains:

1. **Issuer**: `https://token.actions.githubusercontent.com`
   - Confirms signature was created by GitHub Actions

2. **Subject**: `https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v<version>`
   - Confirms the exact workflow and tag that created the signature

3. **SAN (Subject Alternative Name)**: Workflow identity
   - Additional verification of workflow source

4. **Rekor Entry**: Transparency log entry
   - Public, tamper-proof record of signing event

## Verification Best Practices

### Always Verify Before Installing

```bash
# Download and verify
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.tar.gz
sigstore verify github pyguard-0.8.0.tar.gz \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# If verification succeeds, install
pip install pyguard-0.8.0.tar.gz
```

### Verify Checksums

```bash
# Download checksums and verify signature
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/checksums.sha256
sigstore verify github checksums.sha256 \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# Then verify artifacts against checksums
sha256sum -c checksums.sha256
```

### CI/CD Integration

Add verification to your CI/CD pipeline:

```yaml
# GitHub Actions example
- name: Download and verify PyGuard
  run: |
    pip install sigstore
    
    # Download release
    wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.tar.gz
    
    # Verify signature
    sigstore verify github pyguard-0.8.0.tar.gz \
      --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
      --cert-oidc-issuer https://token.actions.githubusercontent.com
    
    # Install after verification
    pip install pyguard-0.8.0.tar.gz
```

## Troubleshooting

### "Certificate identity does not match"

**Problem**: The workflow identity doesn't match expectations.

**Solution**: Ensure you're using the exact version tag in the identity:
```bash
# Correct (with version tag)
--cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0

# Incorrect (missing tag)
--cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml
```

### "Signature verification failed"

**Possible causes:**
1. **Corrupted download**: Re-download the artifact
2. **Wrong signature file**: Ensure `.sig` matches the artifact
3. **Tampered artifact**: Do not use this artifact

**Solution**: Always download from official GitHub releases.

### "Rekor log verification failed"

**Problem**: Can't reach Rekor transparency log.

**Solution**: 
1. Check internet connectivity
2. Verify firewall isn't blocking sigstore.dev
3. For offline verification, use `cosign verify-blob` with downloaded signatures

## Security Considerations

### What Sigstore Protects Against

✅ **Protects against:**
- Compromised PyPI uploads
- Man-in-the-middle attacks
- Tampered artifacts
- Unofficial releases

✅ **Provides:**
- Cryptographic proof of authenticity
- Audit trail in transparency log
- Identity verification via OIDC

### What Sigstore Doesn't Protect Against

❌ **Does NOT protect against:**
- Vulnerabilities in PyGuard code itself
- Compromised GitHub Actions runner (though unlikely)
- Supply chain attacks in dependencies

### Defense in Depth

Sigstore is one layer of security. Also:

1. **Verify checksums**: Cross-check SHA256 hashes
2. **Review SBOMs**: Check dependency versions
3. **Monitor advisories**: Watch for security updates
4. **Use PyPI signatures**: When available (future)
5. **Run security scans**: Use PyGuard to scan PyGuard!

## Frequently Asked Questions

### Why Sigstore instead of GPG?

**Sigstore advantages:**
- No key management required
- Transparency log prevents backdating
- GitHub OIDC integration
- Industry standard for modern supply chain security

**GPG still supported for users who prefer it (v0.8.0+)**

### How long are signatures valid?

Signatures are valid indefinitely because:
1. **Certificate includes timestamp**: Proves signing time
2. **Rekor log entry**: Permanent, tamper-proof record
3. **Short-lived certificate**: GitHub OIDC tokens expire in minutes, but signature remains valid

### Can I verify old releases?

**v0.8.0+**: Full Sigstore signing  
**v0.7.0 and earlier**: SLSA provenance only (use `gh attestation verify`)

### What if GitHub Actions is compromised?

Multiple safeguards:
1. **OIDC tokens**: Short-lived, specific to workflow
2. **Rekor log**: Public record shows anomalies
3. **Workflow pinning**: SHA-pinned actions
4. **Code review**: All workflow changes reviewed

### How does this compare to PyPI signatures?

**Current (v0.8.0):**
- GitHub releases: Full Sigstore signing ✅
- PyPI uploads: No signatures (PyPI limitation) ❌

**Future:** PyPI is adding PEP 740 (attestations) - we'll support when available.

## Additional Resources

### Official Documentation
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Rekor Documentation](https://docs.sigstore.dev/rekor/overview/)

### Standards and Specifications
- [SLSA Framework](https://slsa.dev/)
- [Supply Chain Levels for Software Artifacts](https://slsa.dev/spec/v1.0/)
- [Sigstore Specifications](https://github.com/sigstore/protobuf-specs)

### PyGuard Security
- [Security Policy](../../SECURITY.md)
- [Supply Chain Security](../guides/SUPPLY_CHAIN_SECURITY.md) (coming soon)
- [Release Workflow](.github/workflows/release.yml)

## Reporting Issues

Found a problem with signature verification?

1. **Verification failures**: Report via [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
2. **Security concerns**: Use [Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories)

---

**Last Updated**: 2025-11-03 (v0.8.0 development)  
**Maintained by**: PyGuard Security Team  
**Questions?**: See [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
