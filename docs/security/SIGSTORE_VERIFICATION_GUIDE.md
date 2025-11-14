# Sigstore Signature Verification Guide

**Status:** ✅ FULLY IMPLEMENTED AND ACTIVE
**Last Updated:** 2025-11-14

---

## Overview

PyGuard releases are automatically signed using **Sigstore** (keyless signing) starting with v0.6.0+. All release artifacts include:

- **Sigstore signatures** (`.sig` files) - Cryptographic signatures
- **Sigstore certificates** (`.crt` files) - OIDC identity certificates
- **Rekor transparency log entries** - Immutable audit trail
- **Build provenance attestations** - SLSA Level 3 provenance

---

## What is Sigstore?

Sigstore is a new standard for signing, verifying, and protecting software:

- **Keyless signing** - No long-lived private keys to manage or leak
- **Short-lived certificates** - Valid for 10 minutes, issued via OIDC
- **Transparency log (Rekor)** - Public, append-only ledger of all signatures
- **Verifiable identity** - Ties signatures to GitHub Actions workflow identity

### Why Keyless is Better

Traditional signing (like GPG) requires:
- Managing private keys securely
- Key rotation policies
- Key backup and recovery
- Risk of key compromise

Sigstore eliminates these concerns:
- Certificates issued on-demand via GitHub OIDC
- Certificates expire in 10 minutes
- Identity verified by GitHub
- All signatures logged publicly in Rekor

---

## Signed Artifacts

Every PyGuard release includes signatures for:

1. **Distribution Packages**
   - `pyguard-X.Y.Z.tar.gz` (source distribution)
   - `pyguard-X.Y.Z-py3-none-any.whl` (wheel)

2. **SBOM Files**
   - `pyguard-X.Y.Z.spdx.json` (SPDX format)
   - `pyguard-X.Y.Z.cyclonedx.json` (CycloneDX format)

3. **Checksums**
   - `checksums.sha256` (SHA256 hashes of all artifacts)

Each artifact has three associated files:
- `.sig` - Sigstore signature
- `.crt` - Sigstore certificate (OIDC identity)
- `.asc` - GPG signature (traditional, if available)

---

## Verification Methods

### Method 1: Using `sigstore-python` (Recommended)

#### Install Sigstore

```bash
pip install sigstore
```

#### Verify a Release Artifact

```bash
# Download the artifact and its signature
VERSION="0.7.0"  # Replace with actual version
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz.sig"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz.crt"

# Verify the signature
sigstore verify github \
  pyguard-${VERSION}.tar.gz \
  --cert-identity "https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

**Expected Output:**
```
OK: pyguard-0.7.0.tar.gz
```

#### What This Verifies

✅ The artifact was built by the official PyGuard release workflow
✅ The artifact was built from the specific git tag (e.g., `v0.7.0`)
✅ The signature is recorded in the Rekor transparency log
✅ The artifact has not been tampered with

### Method 2: Using Cosign

#### Install Cosign

```bash
# macOS
brew install cosign

# Linux
wget "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

#### Verify with Cosign

```bash
VERSION="0.7.0"

# Verify using certificate and signature bundle
cosign verify-blob \
  pyguard-${VERSION}.tar.gz \
  --certificate pyguard-${VERSION}.tar.gz.crt \
  --signature pyguard-${VERSION}.tar.gz.sig \
  --certificate-identity "https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

**Expected Output:**
```
Verified OK
```

### Method 3: Manual Certificate Inspection

You can manually inspect the certificate to see the verified identity:

```bash
# Display certificate details
openssl x509 -in pyguard-${VERSION}.tar.gz.crt -text -noout
```

Look for:
- **Subject Alternative Name (SAN):** Contains the workflow identity URL
- **OIDC Issuer:** `https://token.actions.githubusercontent.com`
- **Validity Period:** Very short (10 minutes)

---

## Verifying SBOM Files

SBOM files are also signed for supply chain security:

```bash
VERSION="0.7.0"

# Verify SPDX SBOM
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.spdx.json"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.spdx.json.sig"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.spdx.json.crt"

sigstore verify github \
  pyguard-${VERSION}.spdx.json \
  --cert-identity "https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify CycloneDX SBOM
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.cyclonedx.json"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.cyclonedx.json.sig"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.cyclonedx.json.crt"

sigstore verify github \
  pyguard-${VERSION}.cyclonedx.json \
  --cert-identity "https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

---

## Verifying Checksums

The checksums file is also signed:

```bash
VERSION="0.7.0"

# Download checksums and signature
cd dist
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/checksums.sha256"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/checksums.sha256.sig"
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/checksums.sha256.crt"

# Verify checksums file
sigstore verify github \
  checksums.sha256 \
  --cert-identity "https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"

# Now verify artifact checksums
sha256sum -c checksums.sha256
```

---

## Rekor Transparency Log

Every signature is recorded in the Rekor transparency log. You can search for PyGuard signatures:

### Using rekor-cli

```bash
# Install rekor-cli
go install github.com/sigstore/rekor/cmd/rekor-cli@latest

# Search for PyGuard signatures
rekor-cli search --artifact pyguard-0.7.0.tar.gz

# Get details of a specific log entry
rekor-cli get --log-index <index>
```

### Using Web Interface

Visit https://search.sigstore.dev/ and search for:
- Artifact: `pyguard-X.Y.Z.tar.gz`
- Certificate identity: `cboyd0319/PyGuard`

---

## Build Provenance Attestation

In addition to Sigstore signatures, PyGuard releases include **build provenance attestations** (SLSA Level 3):

```bash
VERSION="0.7.0"

# Download artifact
gh release download "v${VERSION}" \
  --repo cboyd0319/PyGuard \
  --pattern "pyguard-${VERSION}.tar.gz"

# Verify provenance
gh attestation verify \
  "pyguard-${VERSION}.tar.gz" \
  --repo cboyd0319/PyGuard
```

**What This Verifies:**

✅ The artifact was built by GitHub Actions
✅ The build was triggered by the specified git tag
✅ The build environment and inputs are recorded
✅ The provenance is cryptographically bound to the artifact

See [SLSA_PROVENANCE_VERIFICATION.md](SLSA_PROVENANCE_VERIFICATION.md) for more details.

---

## Automation in CI/CD

### GitHub Actions

```yaml
- name: Download and verify PyGuard
  run: |
    VERSION="0.7.0"

    # Download artifact
    wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz"
    wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz.sig"
    wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz.crt"

    # Install sigstore
    pip install sigstore

    # Verify signature
    sigstore verify github \
      pyguard-${VERSION}.tar.gz \
      --cert-identity "https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
      --cert-oidc-issuer "https://token.actions.githubusercontent.com"

    # Install if verification succeeds
    pip install pyguard-${VERSION}.tar.gz
```

### Shell Script

```bash
#!/bin/bash
set -euo pipefail

VERSION="${1:-0.7.0}"

echo "Downloading PyGuard v${VERSION}..."
wget -q "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz"
wget -q "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz.sig"
wget -q "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz.crt"

echo "Verifying signature..."
sigstore verify github \
  pyguard-${VERSION}.tar.gz \
  --cert-identity "https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"

if [ $? -eq 0 ]; then
  echo "✅ Signature verified! Installing PyGuard..."
  pip install pyguard-${VERSION}.tar.gz
else
  echo "❌ Signature verification failed!"
  exit 1
fi
```

---

## Troubleshooting

### Error: "certificate identity mismatch"

**Cause:** The certificate identity doesn't match the expected workflow URL.

**Solution:** Ensure you're using the correct cert-identity URL:
```
https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/vX.Y.Z
```

### Error: "certificate has expired"

**Cause:** Certificates are valid for only 10 minutes from issuance.

**Solution:** This is expected! Verification uses the Rekor timestamp, not the current time. If verification fails, the signature was invalid at signing time.

### Error: "entry not found in transparency log"

**Cause:** Signature not recorded in Rekor or connectivity issues.

**Solution:**
1. Check internet connectivity
2. Verify the artifact filename is correct
3. Wait a few minutes for Rekor propagation
4. Check Rekor status: https://status.sigstore.dev/

### Signature Exists but Won't Verify

**Cause:** Artifact may have been modified or corrupted.

**Solution:**
1. Re-download the artifact
2. Verify SHA256 checksum against `checksums.sha256`
3. Check that artifact and signature are from the same release

---

## Technical Details

### Signing Process

The release workflow (`.github/workflows/release.yml`) performs these steps:

1. **Build artifacts** - Create source and wheel distributions
2. **Generate SBOM** - Create software bill of materials
3. **Sign with Sigstore** - Use GitHub OIDC to get short-lived certificate
4. **Upload to Rekor** - Record signature in transparency log
5. **Attach to release** - Upload signatures and certificates to GitHub release

### Sigstore Configuration

```yaml
- name: Sign artifacts with Sigstore
  uses: sigstore/gh-action-sigstore-python@v3.0.0
  with:
    inputs: >-
      dist/*.tar.gz
      dist/*.whl
      pyguard-${{ steps.get_version.outputs.VERSION }}.spdx.json
      pyguard-${{ steps.get_version.outputs.VERSION }}.cyclonedx.json
      dist/checksums.sha256
    upload-signing-artifacts: true
    release-signing-artifacts: true
```

This action:
- Uses GitHub's OIDC token to authenticate
- Gets a short-lived certificate from Fulcio (Sigstore CA)
- Signs each artifact
- Records signature in Rekor transparency log
- Uploads `.sig` and `.crt` files to the release

---

## Comparison with GPG Signing

PyGuard provides both Sigstore and GPG signatures:

| Feature | Sigstore | GPG |
|---------|----------|-----|
| **Key Management** | Keyless (OIDC) | Long-lived private keys |
| **Identity** | GitHub workflow URL | Email address |
| **Expiration** | 10 minutes | Years (user-defined) |
| **Transparency** | Public log (Rekor) | Keyservers (opt-in) |
| **Revocation** | Automatic (time-based) | Manual (CRL, keyservers) |
| **Adoption** | Growing (npm, Homebrew, Python) | Established (Debian, RPM) |

**Recommendation:** Use **Sigstore** for modern workflows. Use **GPG** for compatibility with legacy systems.

---

## Security Guarantees

When you verify a Sigstore signature, you get:

✅ **Authenticity** - Artifact was created by the official GitHub Actions workflow
✅ **Integrity** - Artifact has not been modified since signing
✅ **Non-repudiation** - Signature is recorded in immutable transparency log
✅ **Identity binding** - Signature tied to specific git tag and workflow
✅ **Timeliness** - Signature timestamp recorded in Rekor

What Sigstore does NOT protect against:
❌ Vulnerabilities in PyGuard code itself
❌ Compromised dependencies (use SBOM scanning for this)
❌ Malicious commits merged into the repository

---

## References

- **Sigstore:** https://www.sigstore.dev/
- **Sigstore Python:** https://github.com/sigstore/sigstore-python
- **Rekor:** https://docs.sigstore.dev/logging/overview/
- **SLSA:** https://slsa.dev/
- **PyGuard SLSA Guide:** [SLSA_PROVENANCE_VERIFICATION.md](SLSA_PROVENANCE_VERIFICATION.md)
- **PyGuard SBOM Guide:** [SBOM_GUIDE.md](SBOM_GUIDE.md)

---

## Support

For questions about Sigstore verification:
- **PyGuard Issues:** https://github.com/cboyd0319/PyGuard/issues
- **Sigstore Slack:** https://sigstore.slack.com/
- **Sigstore Docs:** https://docs.sigstore.dev/

---

**Status:** ✅ Fully implemented and active in all releases
**Implementation:** `.github/workflows/release.yml` (lines 98-108)
**First Release:** v0.6.0+
**Verified By:** Automated CI/CD testing on every release
