# PyGuard Distribution Strategy

**Making PyGuard THE solution for Python security - everywhere developers work**

This document outlines PyGuard's comprehensive multi-channel distribution strategy. By meeting developers wherever they work - from CLI to IDE to CI/CD - PyGuard becomes the natural, effortless choice for Python security and code quality.

## 📦 Distribution Channels

### 1. GitHub Marketplace ✅ ACTIVE

**Status:** Published and active at [GitHub Marketplace](https://github.com/marketplace/actions/pyguard-security-scanner)

**Current Capabilities:**
- Native GitHub Action integration
- SARIF 2.1.0 output for Code Scanning
- Security tab integration
- PR annotations and blocking
- Configurable security gates
- Zero-configuration setup

**Usage:**
```yaml
- uses: cboyd0319/PyGuard@main
  with:
    paths: '.'
    upload-sarif: 'true'
```

**Documentation:** [docs/guides/github-action-guide.md](docs/guides/github-action-guide.md)

---

### 2. PyPI (Python Package Index) ✅ READY

**Status:** Installable via pip

**Installation:**
```bash
pip install pyguard
```

**Current Capabilities:**
- Full CLI tool with all features
- Library usage for programmatic access
- Pre-commit hooks integration
- Git hooks for local development
- Configuration file support (pyguard.toml)

**Documentation:** [README.md](README.md#installation)

---

### 3. Homebrew 🚧 PLANNED (v0.7.0)

**Status:** Not yet available - high priority for v0.7.0

**Planned Implementation:**

#### Homebrew Formula Structure
```ruby
# Formula: pyguard.rb
class Pyguard < Formula
  desc "Comprehensive Python security & code quality scanner with auto-fixes"
  homepage "https://github.com/cboyd0319/PyGuard"
  url "https://github.com/cboyd0319/PyGuard/archive/v0.7.0.tar.gz"
  sha256 "TBD"
  license "MIT"

  depends_on "python@3.13"
  
  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/pyguard", "--version"
  end
end
```

#### Installation Commands (Future)
```bash
# Add tap
brew tap cboyd0319/pyguard

# Install
brew install pyguard

# Upgrade
brew upgrade pyguard
```

#### Benefits
- **Single command installation** - No Python environment management required
- **Automatic dependency resolution** - Homebrew handles all dependencies
- **Easy updates** - `brew upgrade pyguard` keeps tool current
- **Cross-platform** - Works on macOS and Linux
- **Native performance** - Integrates with system Python

#### Implementation Tasks
- [ ] Create `homebrew/` directory in repository
- [ ] Write Homebrew formula (`pyguard.rb`)
- [ ] Set up GitHub tap repository: `homebrew-pyguard`
- [ ] Create installation script (`install.sh`) for direct downloads
- [ ] Document tap setup and formula maintenance
- [ ] Automate formula updates in release workflow
- [ ] Test formula on macOS (Intel & Apple Silicon) and Linux

**Target Release:** v0.7.0 (Q1 2026)

**Why Homebrew:** Developers love simple, native installations. `brew install pyguard` provides instant access without Python environment concerns.

---

### 4. IDE Plugins 🚧 PLANNED (v0.7.0 - v0.8.0)

**Status:** Not yet available - phased rollout planned

#### VS Code Extension (v0.7.0)

**Planned Features:**
- Real-time security linting as you type
- Inline security warnings with CWE/OWASP references
- Quick fix suggestions (CodeActions)
- Command palette integration
- Settings UI for configuration
- Status bar indicators
- Output panel for detailed reports
- File watcher for automatic rescans
- Jupyter notebook cell-level security scanning

**Technical Approach:**
- Language Server Protocol (LSP) implementation
- VS Code Extension API
- Tree-sitter for fast parsing
- WebAssembly for performance-critical operations

**Installation (Future):**
```bash
# VS Code Marketplace
code --install-extension cboyd0319.pyguard

# Or search "PyGuard" in VS Code Extensions
```

**Implementation Tasks:**
- [ ] Implement Language Server Protocol (LSP) for PyGuard
- [ ] Create VS Code extension scaffold
- [ ] Integrate LSP client with VS Code
- [ ] Build settings UI and configuration management
- [ ] Implement CodeActions for auto-fixes
- [ ] Add Jupyter notebook support
- [ ] Package and publish to VS Code Marketplace
- [ ] Create extension documentation and demos

**Target Release:** v0.7.0 (Q1 2026)

---

#### PyCharm/IntelliJ Plugin (v0.8.0)

**Planned Features:**
- Inspection tool window integration
- Problem highlighting in editor
- Quick fixes via intentions
- Tool window for results
- Settings dialog
- Run configuration support
- Integration with IntelliJ Platform's security framework

**Technical Approach:**
- IntelliJ Platform Plugin SDK
- Kotlin/Java implementation
- External tool integration
- Code inspection framework

**Installation (Future):**
```
File → Settings → Plugins → Marketplace → Search "PyGuard"
```

**Implementation Tasks:**
- [ ] Create IntelliJ Platform plugin project
- [ ] Implement external tool wrapper
- [ ] Build inspection providers
- [ ] Add intention actions for fixes
- [ ] Create settings panel
- [ ] Package and publish to JetBrains Marketplace
- [ ] Create plugin documentation

**Target Release:** v0.8.0 (Q2 2026)

---

#### Other IDEs (Future Consideration)

**Sublime Text:** LSP-based plugin (low effort, v0.8.0+)
**Vim/Neovim:** LSP client integration (community-driven)
**Emacs:** LSP mode integration (community-driven)

---

### 5. Docker/Container Distribution ✅ ACTIVE

**Status:** Available via Dockerfile in repository

**Current Usage:**
```bash
# Build image
docker build -t pyguard .

# Run scan
docker run -v $(pwd):/code pyguard /code

# Docker Compose
docker-compose up pyguard
```

**Docker Hub Distribution (Planned):**
```bash
# Future simplified usage
docker pull cboyd0319/pyguard:latest
docker run -v $(pwd):/code cboyd0319/pyguard:latest
```

**Implementation Tasks:**
- [ ] Publish official images to Docker Hub
- [ ] Set up automated builds on releases
- [ ] Create multi-arch images (amd64, arm64)
- [ ] Document Docker usage patterns
- [ ] Add docker-compose examples

**Target:** v0.7.0

---

### 6. Pre-commit Hooks ✅ ACTIVE

**Status:** Fully functional with `.pre-commit-hooks.yaml`

**Installation:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/cboyd0319/PyGuard
    rev: v0.6.0
    hooks:
      - id: pyguard
        args: ['--scan-only', '--severity=HIGH']
```

**Features:**
- Automatic security scanning on commit
- Configurable severity thresholds
- Fast scanning with file filtering
- Integration with pre-commit framework

**Documentation:** [docs/guides/git-hooks-guide.md](docs/guides/git-hooks-guide.md)

---

## 🔒 Secure Distribution

PyGuard implements industry-leading supply chain security practices to ensure every release is verifiable, tamper-proof, and trustworthy.

### Supply Chain Security Roadmap

#### 1. SLSA Provenance (v0.7.0)

**Goal:** Achieve SLSA Level 3 compliance

**Implementation:**
- [ ] Integrate `slsa-github-generator` in release workflow
- [ ] Generate provenance attestations for all releases
- [ ] Publish provenance alongside release artifacts
- [ ] Document provenance verification for users
- [ ] Add provenance verification to installation docs

**SLSA Benefits:**
- Tamper-evident build process
- Reproducible builds
- Verifiable supply chain integrity
- Meets compliance requirements (FedRAMP, SOC 2)

**Documentation:**
```bash
# Verify SLSA provenance (future)
slsa-verifier verify-artifact pyguard-0.7.0.tar.gz \
  --provenance-path pyguard-0.7.0.intoto.jsonl \
  --source-uri github.com/cboyd0319/PyGuard
```

---

#### 2. Sigstore/Cosign Signing (v0.7.0)

**Goal:** Sign all releases with keyless signing

**Implementation:**
- [ ] Integrate Cosign in release workflow
- [ ] Sign release tarballs and wheels
- [ ] Sign container images
- [ ] Generate transparency log entries
- [ ] Document signature verification

**Benefits:**
- Keyless signing (no key management)
- Transparency log for public verification
- Integration with Rekor/Fulcio
- Industry-standard supply chain security

**Documentation:**
```bash
# Verify signatures (future)
cosign verify-blob pyguard-0.7.0.tar.gz \
  --certificate pyguard-0.7.0.tar.gz.pem \
  --signature pyguard-0.7.0.tar.gz.sig \
  --certificate-identity-regexp "^https://github.com/cboyd0319/PyGuard"
```

---

#### 3. Software Bill of Materials (SBOM) ✅ ACTIVE

**Status:** PyGuard generates SBOMs for others, now needs its own

**Implementation:**
- [ ] Generate SBOM for PyGuard releases (CycloneDX & SPDX)
- [ ] Publish SBOM with each release
- [ ] Include dependency vulnerability information
- [ ] Document SBOM verification and usage
- [ ] Automate SBOM generation in CI/CD

**Formats:**
- **CycloneDX 1.5** (primary)
- **SPDX 2.3** (secondary)

**Publication:**
```
/releases/tag/v0.7.0/
  ├── pyguard-0.7.0.tar.gz
  ├── pyguard-0.7.0.sbom.json (CycloneDX)
  └── pyguard-0.7.0.spdx.json (SPDX)
```

**Target:** v0.7.0

---

#### 4. Signed Releases (v0.7.0)

**Implementation:**
- [ ] GPG signing of release tags
- [ ] GPG signing of release artifacts
- [ ] Publish GPG public key
- [ ] Document signature verification
- [ ] Automate signing in release workflow

**Process:**
```bash
# Future release verification
gpg --import pyguard-release.asc
gpg --verify pyguard-0.7.0.tar.gz.sig pyguard-0.7.0.tar.gz
```

---

#### 5. Reproducible Builds (v0.8.0)

**Goal:** Bit-for-bit reproducible releases

**Implementation:**
- [ ] Lock all dependencies with hashes
- [ ] Use deterministic build tools
- [ ] Document build environment
- [ ] Provide build reproduction instructions
- [ ] Set up independent build verification

**Benefits:**
- Maximum supply chain security
- Independent verification possible
- Compliance with highest security standards

---

### Security Features Summary

| Feature | Status | Target | Industry Standard |
|---------|--------|--------|-------------------|
| SLSA Provenance | 🚧 Planned | v0.7.0 | SLSA Level 3 |
| Sigstore/Cosign | 🚧 Planned | v0.7.0 | Keyless signing |
| SBOM Generation | ✅ Partial | v0.7.0 | CycloneDX/SPDX |
| GPG Signing | 🚧 Planned | v0.7.0 | Release signatures |
| Zero Telemetry | ✅ Active | - | 100% privacy |
| Offline-First | ✅ Active | - | No internet required |
| Reproducible Builds | 🚧 Planned | v0.8.0 | Bit-for-bit verification |

---

## 📊 Distribution Metrics & Goals

### Target User Adoption (12 months)

| Channel | Current | 6-Month Goal | 12-Month Goal |
|---------|---------|--------------|---------------|
| PyPI Downloads | 1K/month | 10K/month | 50K/month |
| GitHub Action Usage | 500 repos | 2K repos | 10K repos |
| Homebrew Installs | 0 | 500/month | 5K/month |
| VS Code Extension | 0 | 1K installs | 10K installs |
| Docker Pulls | <100 | 1K/month | 10K/month |

### Quality Metrics

- **Installation Success Rate:** >99%
- **First-Run Success:** >95%
- **Documentation Completeness:** 100%
- **Security Score (OpenSSF):** >8.0/10

---

## 🎯 Why PyGuard's Distribution Strategy Wins

### Multi-Channel Availability = Developer Choice

**The Problem:** Developers use different tools for different workflows. Security tools that only work in one environment create friction and get abandoned.

**PyGuard's Solution:** Be everywhere developers work.

| Distribution Channel | Developer Benefit | Status |
|---------------------|-------------------|--------|
| **PyPI** | Quick pip install, familiar Python workflow | ✅ Active |
| **Homebrew** | System-level install, no Python env needed | 🚧 v0.7.0 |
| **GitHub Action** | Native CI/CD, zero config | ✅ Active |
| **Docker Hub** | Containerized, reproducible scans | 🚧 v0.7.0 |
| **VS Code** | Real-time linting as you type | 🚧 v0.7.0 |
| **PyCharm** | Native IDE integration | 🚧 v0.8.0 |
| **Pre-commit** | Git hooks, automatic checks | ✅ Active |

**Result:** Developers choose PyGuard because it fits their workflow, not because they had to change their workflow.

---

### vs. Traditional Python Security Tools

| Feature | PyGuard | Bandit | Semgrep |
|---------|---------|--------|---------|
| **Homebrew** | Planned | ❌ | ❌ |
| **VS Code Extension** | Planned | ❌ | ✅ |
| **GitHub Action** | ✅ Native | ⚠️ 3rd party | ✅ |
| **Pre-commit** | ✅ | ✅ | ✅ |
| **Docker** | ✅ | ❌ | ✅ |
| **Signed Releases** | Planned | ❌ | ⚠️ Partial |

**Advantage:** PyGuard will be the ONLY Python security tool with comprehensive, secure distribution across all channels.

---

## 🚀 Implementation Roadmap

### v0.7.0 (Q1 2026) - "Easy Distribution"

**Focus:** Make installation trivially easy everywhere

- [ ] **Homebrew Formula**
  - Create formula and tap
  - Test on macOS (Intel/ARM) and Linux
  - Document installation
  
- [ ] **VS Code Extension**
  - Implement LSP server
  - Build extension
  - Publish to VS Code Marketplace
  
- [ ] **Docker Hub**
  - Publish official images
  - Multi-arch support (amd64, arm64)
  - Automated builds

- [ ] **Enhanced GitHub Marketplace**
  - Improved action configuration
  - Better documentation
  - More usage examples

### v0.8.0 (Q2 2026) - "Secure Distribution"

**Focus:** Industry-leading supply chain security

- [ ] **SLSA Level 3 Provenance**
  - Automated provenance generation
  - Public verification documentation
  
- [ ] **Sigstore/Cosign Signing**
  - Keyless signing for all releases
  - Transparency log integration
  
- [ ] **Complete SBOM**
  - CycloneDX and SPDX formats
  - Vulnerability information included
  
- [ ] **PyCharm Plugin**
  - IntelliJ Platform integration
  - Publish to JetBrains Marketplace

### v1.0.0 (Q3 2026) - "Production Excellence"

**Focus:** Enterprise-ready distribution

- [ ] **Reproducible Builds**
  - Bit-for-bit reproducibility
  - Independent verification
  
- [ ] **Enterprise Repository Support**
  - Artifactory integration
  - Nexus repository support
  - Air-gapped installation support
  
- [ ] **Additional IDE Support**
  - Sublime Text (LSP)
  - Vim/Neovim (LSP)
  
- [ ] **Package Distribution**
  - Windows Chocolatey
  - Linux distribution repos (apt, yum)

---

## 📚 Documentation Requirements

Each distribution channel requires comprehensive documentation:

### User Documentation
- [ ] Installation guides for each channel
- [ ] Quick start tutorials
- [ ] Configuration examples
- [ ] Troubleshooting guides
- [ ] Migration guides (from other tools)

### Developer Documentation
- [ ] Building from source
- [ ] Contributing guidelines
- [ ] Release process
- [ ] Formula/plugin maintenance
- [ ] Security verification procedures

### Compliance Documentation
- [ ] Supply chain security verification
- [ ] SLSA provenance validation
- [ ] Signature verification
- [ ] Audit trail procedures

---

## 🎯 Success Criteria

PyGuard distribution will be considered successful when:

1. **Ease of Installation**
   - Single command installation on all major platforms
   - <5 minutes from discovery to first scan
   - >95% installation success rate

2. **Security Verification**
   - All releases signed and verifiable
   - SLSA Level 3 provenance available
   - Supply chain security documented

3. **Market Reach**
   - Available in 6+ distribution channels
   - 50K+ monthly PyPI downloads
   - 10K+ GitHub Action users
   - 5K+ Homebrew installs
   - 10K+ IDE extension users

4. **Developer Experience**
   - IDE integration for real-time feedback
   - Pre-commit hooks for early detection
   - CI/CD integration for automated gates
   - Zero-configuration setup

5. **Enterprise Readiness**
   - Air-gapped installation support
   - Private registry compatibility
   - Compliance documentation complete
   - Professional support available

---

## 🔗 Related Documentation

- [README.md](README.md) - Main project documentation
- [docs/guides/github-action-guide.md](docs/guides/github-action-guide.md) - GitHub Action usage
- [docs/guides/git-hooks-guide.md](docs/guides/git-hooks-guide.md) - Pre-commit hooks
- [SECURITY.md](SECURITY.md) - Security policy and disclosure
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contributing guidelines

---

**Last Updated:** 2025-11-03

**Next Review:** v0.7.0 release planning (2026-Q1)
