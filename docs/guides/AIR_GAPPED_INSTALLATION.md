# Air-Gapped Installation Guide for PyGuard

Complete guide for installing and using PyGuard in air-gapped, offline, or restricted network environments.

## Overview

An air-gapped environment is a network security measure that physically isolates a computer or network from unsecured networks, including the internet. This guide covers:

- Offline installation methods
- Dependency bundling
- Update procedures
- Security considerations
- Compliance requirements

## Prerequisites

### Internet-Connected Machine (Build Station)

Requirements for preparing PyGuard installation package:

- Python 3.11+ installed
- pip with download capabilities
- 500 MB free disk space
- Access to PyPI or mirror
- USB drive or secure file transfer mechanism

### Air-Gapped Machine (Target Station)

Requirements for installation:

- Python 3.11+ installed (or bundled)
- 200 MB free disk space
- Same OS and architecture as build station
- Appropriate permissions for software installation

## Installation Methods

### Method 1: Wheel with Bundled Dependencies (Recommended)

This method creates a single wheel file with all dependencies included.

#### Step 1: Download on Internet-Connected Machine

```bash
# Create download directory
mkdir -p pyguard-offline
cd pyguard-offline

# Download PyGuard and all dependencies
pip download pyguard

# Verify downloads
ls -lh
```

Expected output:
```
pyguard-0.6.0-py3-none-any.whl
pylint-4.0.1-py3-none-any.whl
flake8-7.3.0-py2.py3-none-any.whl
black-25.9.0-cp312-cp312-linux_x86_64.whl
# ... more dependencies
```

#### Step 2: Create Checksums

```bash
# Generate checksums for verification
sha256sum *.whl > checksums.txt
sha512sum *.whl >> checksums.txt

# Optional: Sign checksums
gpg --detach-sign --armor checksums.txt
```

#### Step 3: Transfer to Air-Gapped System

```bash
# Create transfer archive
tar czf pyguard-offline-bundle.tar.gz *.whl checksums.txt

# Copy to USB drive or secure transfer location
cp pyguard-offline-bundle.tar.gz /media/usb/
```

#### Step 4: Install on Air-Gapped System

```bash
# Extract bundle
tar xzf pyguard-offline-bundle.tar.gz
cd pyguard-offline/

# Verify checksums (optional but recommended)
sha256sum -c checksums.txt

# Install from local wheels
pip install --no-index --find-links=. pyguard

# Verify installation
pyguard --version
```

### Method 2: Source Distribution

Install from source tarball when pip wheels are not suitable.

#### Step 1: Download Source and Dependencies

```bash
# Download PyGuard source
wget https://github.com/cboyd0319/PyGuard/archive/refs/tags/v0.6.0.tar.gz

# Download all runtime dependencies
pip download -r requirements.txt -d deps/

# Create bundle
tar czf pyguard-source-bundle.tar.gz v0.6.0.tar.gz deps/
```

#### Step 2: Install on Air-Gapped System

```bash
# Extract bundle
tar xzf pyguard-source-bundle.tar.gz

# Install dependencies first
pip install --no-index --find-links=deps/ -r requirements.txt

# Install PyGuard from source
tar xzf v0.6.0.tar.gz
cd PyGuard-0.6.0
pip install --no-index .

# Verify
pyguard --version
```

### Method 3: Virtual Environment Bundle

Create a complete, portable virtual environment.

#### Step 1: Create Environment on Build Station

```bash
# Create virtual environment
python3 -m venv pyguard-env
source pyguard-env/bin/activate

# Install PyGuard and dependencies
pip install pyguard

# Deactivate
deactivate

# Create relocatable bundle
tar czf pyguard-venv-bundle.tar.gz pyguard-env/
```

#### Step 2: Deploy on Air-Gapped System

```bash
# Extract bundle
tar xzf pyguard-venv-bundle.tar.gz

# Activate environment
source pyguard-env/bin/activate

# Verify installation
pyguard --version

# Optional: Add to PATH
echo 'export PATH="$HOME/pyguard-env/bin:$PATH"' >> ~/.bashrc
```

### Method 4: Docker Image

Use containerized deployment for consistency across environments.

#### Step 1: Build and Export on Build Station

```bash
# Pull or build PyGuard image
docker pull ghcr.io/cboyd0319/pyguard:latest
# OR
docker build -t pyguard:airgap .

# Export to tar file
docker save pyguard:airgap | gzip > pyguard-docker-image.tar.gz

# Calculate checksum
sha256sum pyguard-docker-image.tar.gz > image-checksum.txt
```

#### Step 2: Load on Air-Gapped System

```bash
# Copy tar file to air-gapped system

# Verify checksum
sha256sum -c image-checksum.txt

# Load image
docker load < pyguard-docker-image.tar.gz

# Verify
docker images | grep pyguard

# Run PyGuard
docker run --rm -v $(pwd):/app pyguard:airgap scan /app
```

## Complete Offline Bundle Creation

For maximum convenience, create a complete installation bundle with everything needed.

### Build Complete Bundle Script

```bash
#!/bin/bash
# create-offline-bundle.sh

set -e

VERSION="0.6.0"
BUNDLE_DIR="pyguard-offline-bundle-${VERSION}"

echo "Creating PyGuard offline bundle v${VERSION}..."

# Create bundle directory structure
mkdir -p "${BUNDLE_DIR}"/{wheels,docs,scripts}

# Download PyGuard and dependencies
echo "Downloading PyGuard and dependencies..."
pip download pyguard==${VERSION} -d "${BUNDLE_DIR}/wheels"

# Download Python installer (optional)
echo "Downloading Python installer..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    wget -O "${BUNDLE_DIR}/Python-3.11.6-Linux.tar.xz" \
        https://www.python.org/ftp/python/3.11.6/Python-3.11.6.tar.xz
elif [[ "$OSTYPE" == "darwin"* ]]; then
    wget -O "${BUNDLE_DIR}/Python-3.11.6-macOS.pkg" \
        https://www.python.org/ftp/python/3.11.6/python-3.11.6-macos11.pkg
fi

# Download documentation
echo "Downloading documentation..."
git clone --depth 1 --branch v${VERSION} \
    https://github.com/cboyd0319/PyGuard.git \
    temp-docs
cp -r temp-docs/docs "${BUNDLE_DIR}/"
rm -rf temp-docs

# Generate checksums
echo "Generating checksums..."
cd "${BUNDLE_DIR}/wheels"
sha256sum *.whl > ../checksums.txt
cd ../..

# Create installation script
cat > "${BUNDLE_DIR}/scripts/install.sh" << 'EOF'
#!/bin/bash
# PyGuard Air-Gapped Installation Script

set -e

echo "PyGuard Air-Gapped Installation"
echo "================================"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "Found Python: $PYTHON_VERSION"

# Verify checksums
echo "Verifying package integrity..."
cd wheels
sha256sum -c ../checksums.txt || {
    echo "Error: Checksum verification failed"
    exit 1
}
cd ..

# Install PyGuard
echo "Installing PyGuard..."
pip install --no-index --find-links=wheels pyguard

# Verify installation
if pyguard --version; then
    echo ""
    echo "✅ PyGuard installed successfully!"
    echo ""
    echo "Usage: pyguard --help"
else
    echo "❌ Installation verification failed"
    exit 1
fi
EOF

chmod +x "${BUNDLE_DIR}/scripts/install.sh"

# Create README
cat > "${BUNDLE_DIR}/README.md" << EOF
# PyGuard Offline Installation Bundle v${VERSION}

This bundle contains everything needed to install PyGuard in an air-gapped environment.

## Contents

- \`wheels/\` - PyGuard and all dependencies as wheel files
- \`docs/\` - Complete documentation
- \`scripts/install.sh\` - Automated installation script
- \`checksums.txt\` - SHA256 checksums for verification

## Installation

1. Transfer this bundle to your air-gapped system
2. Extract: \`tar xzf pyguard-offline-bundle-${VERSION}.tar.gz\`
3. Run: \`cd pyguard-offline-bundle-${VERSION} && ./scripts/install.sh\`

## Manual Installation

\`\`\`bash
cd pyguard-offline-bundle-${VERSION}
pip install --no-index --find-links=wheels pyguard
\`\`\`

## Verification

\`\`\`bash
pyguard --version
pyguard --help
\`\`\`

## Support

- Documentation: See \`docs/\` directory
- Issues: https://github.com/cboyd0319/PyGuard/issues

EOF

# Create archive
echo "Creating bundle archive..."
tar czf "${BUNDLE_DIR}.tar.gz" "${BUNDLE_DIR}"

# Generate final checksum
sha256sum "${BUNDLE_DIR}.tar.gz" > "${BUNDLE_DIR}.tar.gz.sha256"

echo ""
echo "✅ Bundle created successfully!"
echo "File: ${BUNDLE_DIR}.tar.gz"
echo "Size: $(du -h ${BUNDLE_DIR}.tar.gz | cut -f1)"
echo "SHA256: $(cat ${BUNDLE_DIR}.tar.gz.sha256)"
```

### Use the Bundle Creation Script

```bash
# Make executable
chmod +x create-offline-bundle.sh

# Run
./create-offline-bundle.sh

# Transfer the bundle
cp pyguard-offline-bundle-*.tar.gz /media/usb/
```

## Private PyPI Mirror Setup

For organizations requiring regular updates in air-gapped environments, set up a private PyPI mirror.

### Using devpi

```bash
# On internet-connected mirror server
pip install devpi-server devpi-web

# Initialize
devpi-init

# Start server
devpi-server --start

# Create index
devpi use http://localhost:3141
devpi user -c mirror password=secret
devpi login mirror --password=secret
devpi index -c pypi mirror=https://pypi.org/simple/ type=mirror

# Sync PyGuard and dependencies
devpi use mirror/pypi
devpi mirror --mirror-url=https://pypi.org/simple/ pyguard

# On air-gapped systems, configure pip
cat > ~/.pip/pip.conf << EOF
[global]
index-url = http://your-mirror-server:3141/mirror/pypi/+simple/
trusted-host = your-mirror-server
EOF
```

## Configuration for Air-Gapped Use

### Disable Telemetry and External Calls

```toml
# pyguard.toml
[global]
# Disable all external network calls
offline_mode = true

# Disable update checks
check_for_updates = false

[reporting]
# Use only local reporting
remote_logging = false
```

### Configure Local Resources

```toml
[rules]
# Use local rule definitions only
custom_rules_path = "./rules"

[plugins]
# Local plugin directories only
plugin_dirs = ["./plugins", "/opt/pyguard/plugins"]
```

## Updating PyGuard in Air-Gapped Environment

### Manual Update Process

```bash
# On internet-connected machine
# Download new version
pip download pyguard==0.6.1 -d pyguard-update/

# Create update bundle
tar czf pyguard-update-0.6.1.tar.gz pyguard-update/

# Transfer to air-gapped system
# On air-gapped system
tar xzf pyguard-update-0.6.1.tar.gz
pip install --no-index --find-links=pyguard-update/ --upgrade pyguard

# Verify update
pyguard --version  # Should show 0.6.1
```

### Automated Update Script

```bash
#!/bin/bash
# update-pyguard-offline.sh

UPDATE_BUNDLE="$1"

if [[ ! -f "$UPDATE_BUNDLE" ]]; then
    echo "Usage: $0 <update-bundle.tar.gz>"
    exit 1
fi

# Extract
TEMP_DIR=$(mktemp -d)
tar xzf "$UPDATE_BUNDLE" -C "$TEMP_DIR"

# Backup current version
CURRENT_VERSION=$(pyguard --version | cut -d' ' -f2)
echo "Backing up current version: $CURRENT_VERSION"

# Update
echo "Installing update..."
pip install --no-index --find-links="${TEMP_DIR}" --upgrade pyguard

# Verify
NEW_VERSION=$(pyguard --version | cut -d' ' -f2)
echo "Updated to version: $NEW_VERSION"

# Cleanup
rm -rf "$TEMP_DIR"
```

## Security Considerations

### Package Verification

Always verify packages before installation:

```bash
# Verify checksums
sha256sum -c checksums.txt

# Verify GPG signatures (if available)
gpg --verify pyguard-0.6.0.tar.gz.asc pyguard-0.6.0.tar.gz

# Verify SLSA provenance
gh attestation verify pyguard-0.6.0-py3-none-any.whl \
    --owner cboyd0319
```

### Secure Transfer

Ensure secure transfer of installation bundles:

```bash
# Encrypt bundle for transfer
gpg --encrypt --recipient security@company.com \
    pyguard-offline-bundle.tar.gz

# On receiving system
gpg --decrypt pyguard-offline-bundle.tar.gz.gpg > pyguard-offline-bundle.tar.gz
```

### Integrity Monitoring

Monitor PyGuard integrity in production:

```bash
# Create baseline
find $(pip show pyguard | grep Location | cut -d' ' -f2)/pyguard -type f \
    -exec sha256sum {} \; > pyguard-baseline.txt

# Verify integrity periodically
sha256sum -c pyguard-baseline.txt
```

## Compliance and Auditing

### Audit Trail

Maintain audit trail for air-gapped installations:

```bash
# Log installation
cat >> /var/log/software-installs.log << EOF
$(date -Iseconds) - PyGuard v0.6.0 installed
User: $(whoami)
Source: pyguard-offline-bundle-0.6.0.tar.gz
Checksum: $(sha256sum pyguard-offline-bundle-0.6.0.tar.gz)
EOF
```

### Generate SBOM

Create Software Bill of Materials:

```bash
# Generate SBOM for installed PyGuard
pip install cyclonedx-bom
cyclonedx-py --requirements requirements.txt --output pyguard-sbom.json

# Review dependencies
cat pyguard-sbom.json | jq '.components[] | {name, version}'
```

## Troubleshooting

### Issue: Missing Dependencies

```bash
# Symptom: Import errors or missing modules

# Solution: Identify and download missing dependencies
pip download <missing-package> -d additional-wheels/
pip install --no-index --find-links=additional-wheels/ <missing-package>
```

### Issue: Architecture Mismatch

```bash
# Symptom: Binary wheel incompatibility

# Solution: Download platform-specific wheels
pip download --platform manylinux2014_x86_64 --only-binary=:all: pyguard

# Or build from source
pip download --no-binary=:all: pyguard
```

### Issue: Python Version Mismatch

```bash
# Symptom: Wheels won't install

# Solution: Ensure matching Python versions
# On build station
python3 --version  # Note version

# Download for specific Python version
pip download --python-version 3.11 pyguard
```

## Best Practices

### 1. Version Control

Track all versions deployed:

```bash
# versions.txt
2024-11-04: PyGuard v0.6.0 deployed to production
2024-10-15: PyGuard v0.5.8 deployed to staging
```

### 2. Testing Before Deployment

Always test bundles before deployment:

```bash
# Create test environment
python3 -m venv test-env
source test-env/bin/activate

# Test installation
pip install --no-index --find-links=wheels/ pyguard

# Run tests
pyguard --version
pyguard scan tests/fixtures/

# Cleanup
deactivate
rm -rf test-env
```

### 3. Documentation

Include documentation in every bundle:

```
bundle/
├── wheels/
├── docs/
├── examples/
├── README.md
└── CHANGELOG.md
```

### 4. Backup Strategy

Maintain backups of installation bundles:

```bash
# Copy to backup location
cp pyguard-offline-bundle-*.tar.gz /backup/pyguard/$(date +%Y%m%d)/
```

## Example: Complete Deployment Workflow

```bash
#!/bin/bash
# complete-airgap-deployment.sh

set -e

# Configuration
VERSION="0.6.0"
BUNDLE_NAME="pyguard-offline-${VERSION}"
TARGET_SYSTEM="airgap-server"

echo "=== PyGuard Air-Gap Deployment Workflow ==="
echo

# Step 1: Download on internet-connected system
echo "[1/6] Downloading PyGuard v${VERSION}..."
mkdir -p ${BUNDLE_NAME}
pip download pyguard==${VERSION} -d ${BUNDLE_NAME}/

# Step 2: Generate checksums
echo "[2/6] Generating checksums..."
cd ${BUNDLE_NAME}
sha256sum *.whl > checksums.txt
cd ..

# Step 3: Create bundle
echo "[3/6] Creating bundle archive..."
tar czf ${BUNDLE_NAME}.tar.gz ${BUNDLE_NAME}/

# Step 4: Transfer (simulated)
echo "[4/6] Transferring to air-gapped system..."
echo "Please transfer ${BUNDLE_NAME}.tar.gz to ${TARGET_SYSTEM}"
echo "Press Enter when transfer is complete..."
read

# Step 5: Install (on target system)
echo "[5/6] Installing on ${TARGET_SYSTEM}..."
ssh ${TARGET_SYSTEM} << EOF
    tar xzf ${BUNDLE_NAME}.tar.gz
    cd ${BUNDLE_NAME}
    sha256sum -c checksums.txt
    pip install --no-index --find-links=. pyguard
    pyguard --version
EOF

# Step 6: Verify
echo "[6/6] Verifying installation..."
ssh ${TARGET_SYSTEM} "pyguard --help"

echo
echo "✅ Deployment complete!"
```

## Resources

- **pip Documentation**: <https://pip.pypa.io/en/stable/>
- **Offline Installation**: <https://pip.pypa.io/en/stable/user_guide/#installing-from-local-packages>
- **devpi Server**: <https://devpi.net/>
- **Private PyPI**: <https://packaging.python.org/guides/hosting-your-own-index/>

## Related Documentation

- [Security Policy](../../SECURITY.md)
- [SLSA Provenance Verification](../security/SLSA_PROVENANCE_VERIFICATION.md)
- [SBOM Guide](../security/SBOM_GUIDE.md)
- [Reproducible Builds](REPRODUCIBLE_BUILDS.md)

---

**Last Updated**: 2024-11-04  
**Status**: Production Ready
