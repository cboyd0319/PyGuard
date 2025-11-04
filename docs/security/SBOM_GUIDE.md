# PyGuard SBOM (Software Bill of Materials) Guide

## Overview

PyGuard generates comprehensive **Software Bill of Materials (SBOM)** for every release in both
industry-standard formats: **SPDX 2.3** and **CycloneDX**. This guide explains how to access,
verify, and use PyGuard's SBOMs for security and compliance purposes.

## What is an SBOM?

A Software Bill of Materials is a complete inventory of all components, dependencies, and metadata
that make up a software package. Think of it as an "ingredients list" for software.

**Why SBOMs matter:**
- 🔍 **Vulnerability tracking**: Quickly identify if you're affected by disclosed CVEs
- 📋 **License compliance**: Audit all licenses in your software supply chain
- 🔒 **Supply chain security**: Verify all components come from trusted sources
- 📊 **Risk assessment**: Understand your security exposure across dependencies
- ✅ **Regulatory compliance**: Required by Executive Order 14028, NIST, and others

## PyGuard SBOM Formats

PyGuard provides SBOMs in two complementary formats:

### SPDX 2.3 (Software Package Data Exchange)

**Best for:** Enterprise compliance, legal review, M&A due diligence

**Filename:** `pyguard-X.Y.Z.spdx.json`

**Key features:**
- ISO/IEC 5962:2021 international standard
- Comprehensive license information
- Package relationships and dependencies
- Cryptographic checksums
- Creator and tooling metadata

**Use cases:**
- Legal department license audits
- M&A software inventory
- Export control compliance
- Government procurement requirements

### CycloneDX 1.4

**Best for:** Security operations, vulnerability management, DevSecOps

**Filename:** `pyguard-X.Y.Z.cyclonedx.json`

**Key features:**
- Security-focused metadata
- Vulnerability correlation
- Component pedigree tracking
- Cryptographic hashes
- External reference links

**Use cases:**
- Automated vulnerability scanning
- CI/CD security gates
- Container security analysis
- Dependency risk scoring

## Accessing PyGuard SBOMs

### Download from GitHub Releases

Every PyGuard release includes signed SBOM files:

```bash
# Set version
VERSION="0.8.0"

# Download SPDX SBOM
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.spdx.json"

# Download CycloneDX SBOM
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.cyclonedx.json"
```

### Download via GitHub CLI

```bash
# Download all SBOM files from latest release
gh release download --repo cboyd0319/PyGuard --pattern "*.spdx.json" --pattern "*.cyclonedx.json"

# Download specific version
gh release download v0.8.0 --repo cboyd0319/PyGuard --pattern "*.spdx.json"
```

### Verify SBOM Signatures

All SBOM files are cryptographically signed with both Sigstore and GPG:

```bash
# Verify with Sigstore (recommended)
pip install sigstore

sigstore verify github pyguard-0.8.0.spdx.json \
  --cert-identity https://github.com/cboyd0319/PyGuard/.github/workflows/release.yml@refs/tags/v0.8.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com

# Verify with GPG (traditional)
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-0.8.0.spdx.json.asc
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.8.0/pyguard-pgp-public-key.asc

gpg --import pyguard-pgp-public-key.asc
gpg --verify pyguard-0.8.0.spdx.json.asc pyguard-0.8.0.spdx.json
```

## Using PyGuard SBOMs

### 1. Vulnerability Scanning

**Check for known vulnerabilities in PyGuard's dependencies:**

```bash
# Using OSV-Scanner (Google/OpenSSF)
osv-scanner --sbom pyguard-0.8.0.cyclonedx.json

# Using Grype (Anchore)
grype sbom:pyguard-0.8.0.cyclonedx.json

# Using Trivy (Aqua Security)
trivy sbom pyguard-0.8.0.cyclonedx.json

# Using Dependency-Track (OWASP)
# Upload SBOM to Dependency-Track web UI or API
curl -X POST "https://dependency-track.example.com/api/v1/bom" \
  -H "X-API-Key: $DT_API_KEY" \
  -H "Content-Type: application/json" \
  -d @pyguard-0.8.0.cyclonedx.json
```

**Expected output (example):**

```
✓ Scanned 247 packages in pyguard-0.8.0.cyclonedx.json
✓ No known vulnerabilities found
✓ All dependencies are up-to-date

Summary:
  Critical: 0
  High: 0
  Medium: 0
  Low: 0
```

### 2. License Compliance Audit

**Analyze license distribution:**

```bash
# Using SPDX tools
pip install spdx-tools

# Validate SBOM
spdx-tools-validate pyguard-0.8.0.spdx.json

# Extract license summary
jq '.packages[] | {name: .name, license: .licenseConcluded}' pyguard-0.8.0.spdx.json

# Count licenses
jq -r '.packages[].licenseConcluded' pyguard-0.8.0.spdx.json | sort | uniq -c | sort -rn
```

**Example license summary:**

```
    187 MIT
     32 Apache-2.0
     15 BSD-3-Clause
      8 BSD-2-Clause
      3 ISC
      2 PSF-2.0
```

### 3. Dependency Analysis

**Identify all direct and transitive dependencies:**

```bash
# Direct dependencies (top-level)
jq '.packages[] | select(.externalRefs[]?.referenceType == "purl") | .name' pyguard-0.8.0.spdx.json | head -20

# Analyze dependency tree depth
jq '.relationships[] | select(.relationshipType == "DEPENDS_ON")' pyguard-0.8.0.spdx.json | wc -l

# Find packages with security advisories
jq '.packages[] | select(.externalRefs[]?.referenceLocator | contains("security"))' pyguard-0.8.0.spdx.json
```

### 4. Continuous Monitoring

**Set up automated SBOM scanning in CI/CD:**

```yaml
# .github/workflows/sbom-scan.yml
name: SBOM Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Download latest PyGuard SBOM
        run: |
          gh release download --repo cboyd0319/PyGuard \
            --pattern "pyguard-*.cyclonedx.json" \
            --output pyguard-sbom.json
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Scan for vulnerabilities
        uses: anchore/scan-action@v3
        with:
          sbom: pyguard-sbom.json
          fail-build: true
          severity-cutoff: high
      
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### 5. Risk Assessment

**Calculate risk score based on dependencies:**

```bash
# Using custom scoring (Python)
cat << 'EOF' > sbom_risk_score.py
import json
import sys

with open(sys.argv[1]) as f:
    sbom = json.load(f)

risk_score = 0
packages = sbom.get('packages', [])

for pkg in packages:
    # Age risk (older = higher risk)
    if 'created' in pkg:
        # Simplified - would parse actual dates
        risk_score += 1
    
    # Complexity risk (more dependencies = higher risk)
    risk_score += len(sbom.get('relationships', []))
    
    # License risk (copyleft = higher risk for proprietary software)
    license_concluded = pkg.get('licenseConcluded', '')
    if 'GPL' in license_concluded:
        risk_score += 10

print(f"Total Risk Score: {risk_score}")
print(f"Packages Analyzed: {len(packages)}")
EOF

python sbom_risk_score.py pyguard-0.8.0.spdx.json
```

## SBOM Contents

### SPDX Structure

**Top-level fields:**

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "pyguard-0.8.0",
  "documentNamespace": "https://github.com/cboyd0319/PyGuard/pyguard-0.8.0",
  "creationInfo": {
    "created": "2024-11-03T10:18:30Z",
    "creators": ["Tool: syft-0.100.0"],
    "licenseListVersion": "3.21"
  },
  "packages": [...],
  "relationships": [...]
}
```

**Package entry example:**

```json
{
  "SPDXID": "SPDXRef-Package-python-requests-2.31.0",
  "name": "requests",
  "versionInfo": "2.31.0",
  "supplier": "Organization: Python Software Foundation",
  "downloadLocation": "https://pypi.org/project/requests/2.31.0",
  "filesAnalyzed": false,
  "licenseConcluded": "Apache-2.0",
  "licenseDeclared": "Apache-2.0",
  "copyrightText": "NOASSERTION",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceType": "purl",
      "referenceLocator": "pkg:pypi/requests@2.31.0"
    }
  ],
  "checksums": [
    {
      "algorithm": "SHA256",
      "checksumValue": "942c5a758f98d0aa7f06b..."
    }
  ]
}
```

### CycloneDX Structure

**Top-level fields:**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2024-11-03T10:18:30Z",
    "tools": [...],
    "component": {
      "type": "library",
      "name": "pyguard",
      "version": "0.8.0"
    }
  },
  "components": [...],
  "dependencies": [...]
}
```

**Component entry example:**

```json
{
  "type": "library",
  "name": "requests",
  "version": "2.31.0",
  "purl": "pkg:pypi/requests@2.31.0",
  "licenses": [
    {
      "license": {
        "id": "Apache-2.0"
      }
    }
  ],
  "hashes": [
    {
      "alg": "SHA-256",
      "content": "942c5a758f98d0aa7f06b..."
    }
  ],
  "externalReferences": [
    {
      "type": "distribution",
      "url": "https://pypi.org/project/requests/2.31.0"
    }
  ]
}
```

## SBOM Generation Process

PyGuard's SBOMs are automatically generated during the release workflow:

### Build-Time Generation

1. **Package Build**: `python -m build` creates wheel and sdist
2. **SPDX Generation**: Syft (Anchore) scans artifacts and generates SPDX 2.3
3. **CycloneDX Generation**: cyclonedx-py generates CycloneDX from environment
4. **Signing**: Both SBOMs signed with Sigstore and GPG
5. **Publication**: SBOMs attached to GitHub Release

### Verification Chain

```
Source Code (Git)
      ↓
Build Artifacts (wheel/sdist)
      ↓
SBOM Generation (Syft/cyclonedx-py)
      ↓
Cryptographic Signing (Sigstore/GPG)
      ↓
Build Provenance (SLSA Level 3)
      ↓
Release Publication (GitHub)
```

Each step is verifiable and tamper-evident.

## Integration Examples

### Python Dependency Checker

```python
#!/usr/bin/env python3
"""Check PyGuard SBOM for vulnerable dependencies."""

import json
import sys
from pathlib import Path

import requests

def check_vulnerabilities(sbom_path):
    """Check SBOM against OSV database."""
    with open(sbom_path) as f:
        sbom = json.load(f)
    
    # Extract PURLs from CycloneDX
    if sbom.get('bomFormat') == 'CycloneDX':
        purls = [c['purl'] for c in sbom.get('components', []) if 'purl' in c]
    else:
        # SPDX format
        purls = []
        for pkg in sbom.get('packages', []):
            for ref in pkg.get('externalRefs', []):
                if ref.get('referenceType') == 'purl':
                    purls.append(ref['referenceLocator'])
    
    # Query OSV API
    vulnerabilities = []
    for purl in purls:
        response = requests.post(
            'https://api.osv.dev/v1/query',
            json={'package': {'purl': purl}}
        )
        if response.ok and response.json().get('vulns'):
            vulnerabilities.extend(response.json()['vulns'])
    
    return vulnerabilities

if __name__ == '__main__':
    sbom_file = sys.argv[1] if len(sys.argv) > 1 else 'pyguard-0.8.0.cyclonedx.json'
    vulns = check_vulnerabilities(sbom_file)
    
    if vulns:
        print(f"⚠️  Found {len(vulns)} vulnerabilities:")
        for vuln in vulns:
            print(f"  - {vuln['id']}: {vuln.get('summary', 'No summary')}")
        sys.exit(1)
    else:
        print("✅ No vulnerabilities found")
        sys.exit(0)
```

### Docker Container Scanning

```bash
#!/bin/bash
# Scan Docker images using SBOM

set -euo pipefail

IMAGE="cboyd0319/pyguard:latest"
VERSION="0.8.0"

# Pull image
docker pull "$IMAGE"

# Download PyGuard SBOM
wget "https://github.com/cboyd0319/PyGuard/releases/download/v${VERSION}/pyguard-${VERSION}.cyclonedx.json"

# Scan image
grype "$IMAGE" -o json > image-scan.json

# Compare with SBOM
# (Custom logic to correlate image packages with SBOM)

echo "Image scan complete. Results in image-scan.json"
```

## Compliance Requirements

### Executive Order 14028 (US Federal)

✅ **Requirement**: Provide SBOM for all software sold to federal government  
✅ **PyGuard compliance**: SPDX 2.3 SBOM provided for every release

### NTIA Minimum Elements

PyGuard SBOMs include all NTIA minimum required elements:

| Element | Included | Location |
|---------|----------|----------|
| Supplier Name | ✅ | `packages[].supplier` (SPDX) |
| Component Name | ✅ | `packages[].name` |
| Version | ✅ | `packages[].versionInfo` |
| Dependencies | ✅ | `relationships[]` |
| Author | ✅ | `creationInfo.creators` |
| Timestamp | ✅ | `creationInfo.created` |
| Unique ID | ✅ | `SPDXID` |

### ISO/IEC 5962:2021

✅ **Standard**: SPDX is ISO/IEC 5962:2021 international standard  
✅ **PyGuard compliance**: Uses SPDX 2.3 (latest ratified version)

## Troubleshooting

### SBOM file not found

**Issue**: Cannot download SBOM from release

**Solution**: SBOMs are only available for releases v0.7.0+. For older versions, generate manually:

```bash
pip install cyclonedx-bom
pip show pyguard | cyclonedx-py --format json --output pyguard-sbom.json
```

### Signature verification fails

**Issue**: SBOM signature verification returns error

**Solution**: Re-download SBOM and signature files. Ensure you're using latest GitHub CLI (`gh version >= 2.40.0`).

### SBOM shows unexpected packages

**Issue**: SBOM includes packages not in requirements.txt

**Solution**: SBOM includes all transitive dependencies (dependencies of dependencies). This is expected and provides complete visibility.

## References

- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
- [CISA SBOM Resources](https://www.cisa.gov/sbom)
- [PyGuard Supply Chain Security](SUPPLY_CHAIN_SECURITY.md)

## Getting Help

- **Questions**: [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- **Issues**: [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Security**: [Security Policy](../../SECURITY.md)

---

**Last Updated**: 2025-11-04  
**Applies To**: PyGuard v0.7.0+  
**SBOM Formats**: SPDX 2.3, CycloneDX 1.4
