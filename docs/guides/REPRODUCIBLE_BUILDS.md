# Reproducible Builds for PyGuard

Complete guide to achieving reproducible (deterministic) builds for PyGuard, ensuring bit-for-bit identical outputs across different environments.

## Overview

Reproducible builds allow independent verification that the source code matches the distributed binaries. This is critical for:

- **Supply chain security**: Verify that distributed packages haven't been tampered with
- **Trust**: Allow anyone to verify the build process
- **Compliance**: Meet requirements for critical infrastructure
- **Auditing**: Enable third-party security audits

## Build Reproducibility Status

PyGuard aims for **Level 3 reproducibility**:

- ✅ **Level 1**: Same source → Same binary (on same machine)
- ✅ **Level 2**: Same source → Same binary (across machines with same OS)
- 🎯 **Level 3**: Same source → Same binary (across different OS/architectures)

### Current Status

| Component | Reproducibility | Notes |
|-----------|----------------|-------|
| Python Wheel | ✅ Reproducible | Deterministic metadata, sorted file lists |
| Source Tarball | ✅ Reproducible | Consistent timestamps, sorted archives |
| Docker Images | 🎯 In Progress | Multi-arch builds, layer ordering |
| Documentation | ✅ Reproducible | Fixed timestamps, sorted indexes |

## Requirements for Reproducible Builds

### Build Environment

```bash
# Python version (exact)
Python 3.11.6

# Build tools (pinned versions)
build==1.0.3
setuptools==68.2.2
wheel==0.42.0

# Operating system
Ubuntu 22.04 LTS or equivalent
```

### Required Tools

```bash
pip install --upgrade pip==24.0
pip install build==1.0.3
pip install wheel==0.42.0
```

## Step-by-Step Reproducible Build

### 1. Clone Repository

```bash
# Clone at specific commit/tag
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
git checkout v0.6.0  # Use specific tag or commit SHA
```

### 2. Verify Source Integrity

```bash
# Verify git signatures (if signed)
git verify-commit HEAD

# Check commit hash
git rev-parse HEAD
# Should match: <expected-commit-hash>
```

### 3. Set Build Environment

```bash
# Set reproducible timestamp (SOURCE_DATE_EPOCH)
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)

# Set build directory
export BUILD_DIR="$(pwd)/build"

# Set Python hash seed for determinism
export PYTHONHASHSEED=0

# Ensure consistent locale
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
```

### 4. Install Dependencies

```bash
# Create clean virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install exact pinned dependencies
pip install --no-cache-dir -r requirements.txt
pip install --no-cache-dir -r requirements-dev.txt
```

### 5. Build Package

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Build with deterministic settings
python -m build --no-isolation --wheel --sdist

# Verify outputs
ls -lh dist/
```

### 6. Verify Reproducibility

```bash
# Calculate checksums
sha256sum dist/pyguard-0.6.0-py3-none-any.whl
sha256sum dist/pyguard-0.6.0.tar.gz

# Compare with published checksums
curl -L https://github.com/cboyd0319/PyGuard/releases/download/v0.6.0/checksums.txt
```

## Configuration for Reproducibility

### pyproject.toml Settings

```toml
[build-system]
requires = ["setuptools>=68.2.2", "wheel>=0.42.0"]
build-backend = "setuptools.build_meta"

[project]
# ... project metadata ...

[tool.setuptools]
# Ensure deterministic file ordering
zip-safe = false

[tool.setuptools.packages.find]
where = ["."]
include = ["pyguard*"]
```

### setup.py (if used)

```python
from setuptools import setup, find_packages
import os
import time

# Use SOURCE_DATE_EPOCH for reproducible builds
if "SOURCE_DATE_EPOCH" in os.environ:
    # Set build timestamp from environment
    build_time = int(os.environ["SOURCE_DATE_EPOCH"])
else:
    # Fallback to current time
    build_time = int(time.time())

setup(
    # ... setup configuration ...
    options={
        'bdist_wheel': {
            # Ensure reproducible wheel metadata
            'universal': False,
        }
    }
)
```

### GitHub Actions Workflow

```yaml
name: Reproducible Build

on:
  push:
    tags:
      - 'v*'

jobs:
  reproducible-build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for SOURCE_DATE_EPOCH

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11.6'  # Exact version

      - name: Set reproducible environment
        run: |
          echo "SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)" >> $GITHUB_ENV
          echo "PYTHONHASHSEED=0" >> $GITHUB_ENV
          echo "LC_ALL=C.UTF-8" >> $GITHUB_ENV

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip==24.0
          pip install build==1.0.3 wheel==0.42.0

      - name: Build package
        run: |
          python -m build --no-isolation

      - name: Generate checksums
        run: |
          cd dist
          sha256sum * > ../checksums.txt
          cat ../checksums.txt

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

      - name: Upload checksums
        uses: actions/upload-artifact@v4
        with:
          name: checksums
          path: checksums.txt
```

## Verifying Reproducible Builds

### Independent Verification

Anyone can verify PyGuard builds are reproducible:

```bash
# 1. Clone repository at release tag
git clone --depth 1 --branch v0.6.0 https://github.com/cboyd0319/PyGuard.git
cd PyGuard

# 2. Set up environment
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
export PYTHONHASHSEED=0
export LC_ALL=C.UTF-8

# 3. Create clean environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install exact build tools
pip install --no-cache-dir build==1.0.3 wheel==0.42.0

# 5. Build
python -m build --no-isolation --wheel

# 6. Compare checksums
sha256sum dist/pyguard-0.6.0-py3-none-any.whl

# 7. Download official release
wget https://github.com/cboyd0319/PyGuard/releases/download/v0.6.0/pyguard-0.6.0-py3-none-any.whl

# 8. Compare files
sha256sum pyguard-0.6.0-py3-none-any.whl
```

If checksums match, the build is reproducible! ✅

### Automated Verification

```python
#!/usr/bin/env python3
"""Verify PyGuard reproducible build."""

import hashlib
import subprocess
import sys
from pathlib import Path


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def verify_build(built_file: Path, official_file: Path) -> bool:
    """Verify built file matches official release."""
    if not built_file.exists():
        print(f"❌ Built file not found: {built_file}")
        return False

    if not official_file.exists():
        print(f"❌ Official file not found: {official_file}")
        return False

    built_hash = calculate_sha256(built_file)
    official_hash = calculate_sha256(official_file)

    print(f"Built:    {built_hash}")
    print(f"Official: {official_hash}")

    if built_hash == official_hash:
        print("✅ Build is reproducible!")
        return True
    else:
        print("❌ Build hashes do not match")
        return False


if __name__ == "__main__":
    built = Path("dist/pyguard-0.6.0-py3-none-any.whl")
    official = Path("pyguard-0.6.0-py3-none-any.whl")

    if verify_build(built, official):
        sys.exit(0)
    else:
        sys.exit(1)
```

## Common Reproducibility Issues

### Issue 1: Timestamp Variations

**Problem**: Build timestamps differ between builds.

**Solution**: Use `SOURCE_DATE_EPOCH` environment variable.

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
```

### Issue 2: File Ordering

**Problem**: Files in archive have non-deterministic order.

**Solution**: Sort files before adding to archive.

```python
import zipfile
from pathlib import Path

def create_deterministic_zip(output_file: Path, files: list[Path]):
    """Create zip with sorted files."""
    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(files):  # Sort for determinism
            zf.write(file_path)
```

### Issue 3: Python Bytecode

**Problem**: `.pyc` files have timestamps embedded.

**Solution**: Use `--no-compile` or ensure consistent Python version.

```bash
python -m py_compile --invalidation-mode checked-hash module.py
```

### Issue 4: Random Seeds

**Problem**: Build process uses random numbers.

**Solution**: Set `PYTHONHASHSEED=0` for deterministic hashing.

```bash
export PYTHONHASHSEED=0
```

### Issue 5: Build Tool Versions

**Problem**: Different versions of build tools produce different output.

**Solution**: Pin exact versions in requirements.

```txt
build==1.0.3
setuptools==68.2.2
wheel==0.42.0
```

## Docker Reproducible Builds

### Dockerfile for Reproducible Builds

```dockerfile
FROM python:3.11.6-slim AS builder

# Set reproducible environment
ENV PYTHONHASHSEED=0
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Install build dependencies (pinned)
RUN pip install --no-cache-dir \
    build==1.0.3 \
    setuptools==68.2.2 \
    wheel==0.42.0

# Copy source
WORKDIR /build
COPY . .

# Set SOURCE_DATE_EPOCH from git
RUN export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) && \
    python -m build --no-isolation --wheel

# Verify checksums
RUN sha256sum dist/*.whl > dist/checksums.txt

# Final image
FROM python:3.11.6-slim
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

ENTRYPOINT ["pyguard"]
```

### Building Reproducible Docker Image

```bash
# Build with buildkit for reproducibility
export DOCKER_BUILDKIT=1

# Build image
docker build \
    --build-arg SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
    --tag pyguard:reproducible \
    .

# Export and verify
docker save pyguard:reproducible | gzip > pyguard-image.tar.gz
sha256sum pyguard-image.tar.gz
```

## Verifying Package Integrity

### Manual Verification

```bash
# Download wheel
wget https://pypi.org/packages/.../pyguard-0.6.0-py3-none-any.whl

# Extract wheel
unzip pyguard-0.6.0-py3-none-any.whl -d extracted/

# Inspect contents
tree extracted/
cat extracted/pyguard-0.6.0.dist-info/METADATA
cat extracted/pyguard-0.6.0.dist-info/RECORD
```

### Programmatic Verification

```python
#!/usr/bin/env python3
"""Verify wheel integrity."""

import zipfile
import hashlib
from pathlib import Path


def verify_wheel(wheel_path: Path) -> bool:
    """Verify wheel integrity using RECORD file."""
    with zipfile.ZipFile(wheel_path, 'r') as zf:
        # Read RECORD file
        record_file = [f for f in zf.namelist() if f.endswith('RECORD')][0]
        record_content = zf.read(record_file).decode('utf-8')

        # Verify each file
        for line in record_content.strip().split('\n'):
            if not line:
                continue

            file_path, expected_hash, size = line.split(',')

            # Skip RECORD itself
            if file_path.endswith('RECORD'):
                continue

            # Read file and calculate hash
            file_content = zf.read(file_path)
            actual_hash = hashlib.sha256(file_content).hexdigest()

            # Compare
            if expected_hash.startswith('sha256='):
                expected_hash = expected_hash[7:]  # Remove 'sha256=' prefix

            if actual_hash != expected_hash:
                print(f"❌ Hash mismatch for {file_path}")
                return False

    print("✅ Wheel integrity verified")
    return True


if __name__ == "__main__":
    wheel = Path("dist/pyguard-0.6.0-py3-none-any.whl")
    verify_wheel(wheel)
```

## Best Practices

### 1. Version Pinning

Always pin exact versions of build dependencies:

```bash
# requirements-build.txt
build==1.0.3
setuptools==68.2.2
wheel==0.42.0
```

### 2. Clean Build Environment

Start with a clean environment for each build:

```bash
# Remove previous builds
rm -rf build/ dist/ *.egg-info/ .eggs/

# Clear pip cache
pip cache purge

# Use fresh virtual environment
rm -rf .venv/
python -m venv .venv
source .venv/bin/activate
```

### 3. Document Build Process

Maintain detailed build instructions:

```markdown
# Build Instructions

## Prerequisites
- Python 3.11.6
- Git 2.40+
- build 1.0.3

## Steps
1. Clone repository at tag
2. Set SOURCE_DATE_EPOCH
3. Install dependencies
4. Build package
5. Verify checksums
```

### 4. Automate Verification

Add verification to CI/CD:

```yaml
- name: Verify reproducibility
  run: |
    # First build
    python -m build --no-isolation
    sha256sum dist/*.whl > checksums1.txt

    # Clean
    rm -rf dist/ build/

    # Second build
    python -m build --no-isolation
    sha256sum dist/*.whl > checksums2.txt

    # Compare
    diff checksums1.txt checksums2.txt
```

### 5. Publish Checksums

Include checksums with every release:

```bash
# Generate checksums
sha256sum dist/* > checksums.txt
sha512sum dist/* >> checksums.txt

# Sign checksums
gpg --detach-sign --armor checksums.txt

# Upload with release
gh release upload v0.6.0 checksums.txt checksums.txt.asc
```

## Integration with Supply Chain Security

Reproducible builds complement other security measures:

1. **SLSA Provenance**: Proves where/how built → see [SLSA_PROVENANCE_VERIFICATION.md](../security/SLSA_PROVENANCE_VERIFICATION.md)
2. **Sigstore Signing**: Cryptographic signatures → built-in to releases
3. **SBOM**: Bill of materials → see [SBOM_GUIDE.md](../security/SBOM_GUIDE.md)
4. **Reproducible Builds**: Bit-for-bit verification → this guide

Together, these provide comprehensive supply chain security.

## Troubleshooting

### Builds Not Matching

```bash
# Enable verbose output
python -m build --no-isolation --wheel --verbose

# Check environment
env | grep -E '(SOURCE_DATE_EPOCH|PYTHONHASHSEED|LC_ALL)'

# Compare files
diff <(zipinfo -l dist/wheel1.whl) <(zipinfo -l dist/wheel2.whl)
```

### Platform-Specific Issues

```bash
# Ensure consistent platform tags
pip wheel --no-deps --wheel-dir dist .

# Check wheel contents
python -m wheel unpack dist/pyguard-*.whl
```

## Resources

- **Reproducible Builds**: <https://reproducible-builds.org/>
- **Python Wheel Format**: <https://packaging.python.org/specifications/binary-distribution-format/>
- **SOURCE_DATE_EPOCH**: <https://reproducible-builds.org/docs/source-date-epoch/>
- **SLSA Framework**: <https://slsa.dev/>

## Related Documentation

- [SLSA Provenance Verification](../security/SLSA_PROVENANCE_VERIFICATION.md)
- [SBOM Guide](../security/SBOM_GUIDE.md)
- [Security Policy](../../SECURITY.md)
- [Distribution Strategy](../../DISTRIBUTION.md)

---

**Last Updated**: 2025-11-04  
**Status**: In Progress - Achieving Level 3 reproducibility
