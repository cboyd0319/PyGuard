# GPG Signature Verification Guide

PyGuard releases are signed with both GPG (GNU Privacy Guard) and Sigstore to provide maximum security and verification options.

## Why Dual Signing?

**GPG Signing:**
- Traditional, widely-understood cryptographic signing
- Long-term key management with web of trust
- Works offline once key is imported
- Compatible with all package managers

**Sigstore:**
- Modern keyless signing using OIDC
- Shorter-lived certificates
- Transparency log (Rekor) integration
- Automated verification in CI/CD

**Together:** They provide defense-in-depth and accommodate different security preferences.

## Quick Start

### Verify with GPG

```bash
# Download release and signature
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-0.7.0.tar.gz
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-0.7.0.tar.gz.asc

# Import PyGuard's public key
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-pgp-public-key.asc
gpg --import pyguard-pgp-public-key.asc

# Verify signature
gpg --verify pyguard-0.7.0.tar.gz.asc pyguard-0.7.0.tar.gz
```

### Verify with Sigstore

```bash
# Install sigstore CLI
pip install sigstore

# Verify release artifact
sigstore verify github pyguard-0.7.0.tar.gz \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.7.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com
```

## Detailed GPG Verification

### Prerequisites

Install GPG if not already installed:

**macOS:**
```bash
brew install gnupg
```

**Ubuntu/Debian:**
```bash
sudo apt-get install gnupg
```

**Windows:**
Download from https://www.gnupg.org/download/

### Step 1: Download Release Files

Download the release tarball and its GPG signature:

```bash
VERSION="0.7.0"
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.tar.gz.asc
```

### Step 2: Import Public Key

Download and import the PyGuard GPG public key:

```bash
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-pgp-public-key.asc
gpg --import pyguard-pgp-public-key.asc
```

### Step 3: Verify Signature

Verify the signature matches the file:

```bash
gpg --verify pyguard-${VERSION}.tar.gz.asc pyguard-${VERSION}.tar.gz
```

**Expected output:**
```
gpg: Signature made [DATE]
gpg:                using RSA key [KEY_ID]
gpg: Good signature from "PyGuard Release Bot <releases@pyguard.dev>" [unknown]
```

### Step 4: Trust the Key (Optional)

To suppress "unknown" trust warnings:

```bash
# Get key fingerprint
gpg --fingerprint releases@pyguard.dev

# Verify fingerprint matches published fingerprint (see below)
# Then trust the key locally
gpg --edit-key releases@pyguard.dev
gpg> trust
# Select trust level (usually 5 = "I trust ultimately")
gpg> quit
```

## Published Key Fingerprint

**Verify the key fingerprint matches:**

```
Key fingerprint: [Will be added after key generation]
```

This fingerprint is also published at:
- GitHub repository: https://github.com/cboyd0319/PyGuard/blob/main/docs/security/GPG_VERIFICATION.md
- PyPI project page: https://pypi.org/project/pyguard/
- Project website: https://pyguard.dev (when available)

## Verifying Wheels

PyGuard wheels (.whl files) are also signed:

```bash
VERSION="0.7.0"
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}-py3-none-any.whl
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}-py3-none-any.whl.asc

gpg --verify pyguard-${VERSION}-py3-none-any.whl.asc pyguard-${VERSION}-py3-none-any.whl
```

## Verifying SBOM Files

SBOM (Software Bill of Materials) files are signed for supply chain verification:

```bash
VERSION="0.7.0"
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.spdx.json
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.spdx.json.asc

gpg --verify pyguard-${VERSION}.spdx.json.asc pyguard-${VERSION}.spdx.json
```

## Verifying Checksums

The checksums file is also signed:

```bash
VERSION="0.7.0"
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/checksums.sha256
wget https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/checksums.sha256.asc

gpg --verify checksums.sha256.asc checksums.sha256
```

## Automation in CI/CD

### GitHub Actions

```yaml
- name: Verify PyGuard release
  run: |
    # Download release and signatures
    wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-0.7.0.tar.gz
    wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-0.7.0.tar.gz.asc
    wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-pgp-public-key.asc
    
    # Import and verify
    gpg --import pyguard-pgp-public-key.asc
    gpg --verify pyguard-0.7.0.tar.gz.asc pyguard-0.7.0.tar.gz
```

### GitLab CI

```yaml
verify_pyguard:
  script:
    - apt-get update && apt-get install -y gnupg wget
    - wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-0.7.0.tar.gz
    - wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-0.7.0.tar.gz.asc
    - wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-pgp-public-key.asc
    - gpg --import pyguard-pgp-public-key.asc
    - gpg --verify pyguard-0.7.0.tar.gz.asc pyguard-0.7.0.tar.gz
```

## Troubleshooting

### "Can't check signature: No public key"

**Solution:** Import the public key:
```bash
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.7.0/pyguard-pgp-public-key.asc
gpg --import pyguard-pgp-public-key.asc
```

### "WARNING: This key is not certified with a trusted signature"

This is normal if you haven't explicitly trusted the key. The signature is still valid.

**To suppress:** Trust the key after verifying the fingerprint (see Step 4 above).

### Signature verification fails

**Possible causes:**
1. File was modified or corrupted during download
2. Wrong version of signature file
3. Using wrong public key

**Solution:**
- Re-download both files
- Verify you're using matching versions
- Confirm key fingerprint matches published fingerprint

## Security Considerations

### Key Management

- **Private Key:** Stored securely in GitHub Secrets, never exposed
- **Public Key:** Available in every release for verification
- **Key Rotation:** Keys will be rotated annually and announced in advance

### Best Practices

1. **Always verify signatures** before using downloaded releases
2. **Check key fingerprint** against multiple sources
3. **Use HTTPS** for all downloads to prevent MITM attacks
4. **Verify checksums** in addition to GPG signatures
5. **Keep GPG updated** to latest version

### Reporting Security Issues

If you discover a security issue with PyGuard releases or signatures:

- **Email:** security@pyguard.dev
- **GitHub Security Advisory:** https://github.com/cboyd0319/PyGuard/security/advisories/new
- **Do NOT** disclose publicly until patched

## Additional Resources

- **GPG Documentation:** https://www.gnupg.org/documentation/
- **Sigstore Documentation:** https://docs.sigstore.dev/
- **SLSA Framework:** https://slsa.dev/
- **Supply Chain Security:** https://www.cisa.gov/sbom

## FAQ

**Q: Why both GPG and Sigstore?**  
A: Defense in depth. GPG is traditional and widely trusted. Sigstore is modern with transparency logs. Both together provide maximum assurance.

**Q: Which should I use?**  
A: Use whichever you're more comfortable with. GPG if you prefer traditional PKI, Sigstore if you want keyless verification.

**Q: Are PyPI packages signed?**  
A: PyPI doesn't support GPG signature uploads, but the source distributions on GitHub are signed. Always download from GitHub releases for maximum verification.

**Q: How do I know the public key is authentic?**  
A: Check the key fingerprint against multiple sources (GitHub, PyPI, website) and through secure channels. Consider the web of trust if the key is signed by keys you already trust.

**Q: What if signatures don't match?**  
A: **Do not use the package.** Report the issue immediately to security@pyguard.dev.

---

**Last Updated:** 2025-11-03  
**Version:** v0.7.0+  
**Maintained by:** PyGuard Security Team
