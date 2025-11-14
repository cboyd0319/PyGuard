# Priority Actions Based on Gap Analysis

**Date:** 2025-11-14
**Based On:** Comprehensive Roadmap Gap Analysis
**Status:** Action Required

---

## 🚨 Critical Priority (Start Immediately)

### 1. VS Code Extension Development

**Why Critical:** ONLY blocker for v0.7.0 "Easy Distribution" completion

**Current Status:**
- ✅ Backend ready: JSON-RPC API (676 lines) fully functional
- ❌ Extension code: 0% complete

**What's Needed:**

#### Phase 1: LSP Server (Week 1-2)
- [ ] Create LSP server wrapper around existing JSON-RPC API
- [ ] Implement textDocument/publishDiagnostics
- [ ] Add basic error/warning reporting
- [ ] Test with generic LSP client

**Files to Create:**
```
pyguard/lsp/
├── server.py           # LSP server main
├── protocol.py         # LSP protocol handlers
├── diagnostics.py      # Convert PyGuard results to LSP diagnostics
└── __init__.py
```

#### Phase 2: VS Code Extension (Week 2-3)
- [ ] Initialize extension project: `yo code`
- [ ] Create package.json with extension metadata
- [ ] Implement LSP client integration
- [ ] Add real-time diagnostics on save
- [ ] Add command palette integration

**Files to Create:**
```
vscode-extension/
├── package.json        # Extension manifest
├── src/
│   ├── extension.ts   # Main extension entry point
│   ├── client.ts      # LSP client
│   └── commands.ts    # Command handlers
├── tsconfig.json
└── README.md
```

#### Phase 3: Quick Fixes (Week 3-4)
- [ ] Implement CodeAction provider
- [ ] Map PyGuard auto-fixes to CodeActions
- [ ] Add "Quick Fix" UI integration
- [ ] Test auto-fix application

#### Phase 4: Polish & Publish (Week 4-6)
- [ ] Add configuration UI
- [ ] Write comprehensive README
- [ ] Add screenshots and demos
- [ ] Test on multiple platforms
- [ ] Publish to VS Code Marketplace
- [ ] Set up telemetry (opt-in, privacy-focused)

**Success Criteria:**
- [ ] Extension installable via `code --install-extension cboyd0319.pyguard`
- [ ] Real-time security linting works
- [ ] Quick fixes apply correctly
- [ ] Published to marketplace

**Resources Needed:**
- VS Code Extension API docs: https://code.visualstudio.com/api
- LSP specification: https://microsoft.github.io/language-server-protocol/
- Example: https://github.com/microsoft/vscode-extension-samples/tree/main/lsp-sample

**Estimated Effort:** 4-6 weeks full-time

---

## 🔥 High Priority (Next 2 Weeks)

### 2. Docker Hub Publishing

**Why Important:** Quick win, workflow already complete

**Current Status:**
- ✅ Workflow ready: `.github/workflows/docker-publish.yml`
- ❌ Not published: Missing secrets configuration

**Action Items:**
- [ ] Configure GitHub secrets:
  - `DOCKER_USERNAME`: Docker Hub username
  - `DOCKER_TOKEN`: Docker Hub access token
- [ ] Test workflow on a test release
- [ ] Verify images published to:
  - Docker Hub: `docker.io/cboyd0319/pyguard`
  - GitHub Container Registry: `ghcr.io/cboyd0319/pyguard`
- [ ] Test pull: `docker pull cboyd0319/pyguard:latest`
- [ ] Update README with Docker installation instructions

**Success Criteria:**
- [ ] Images published to Docker Hub and GHCR
- [ ] Multi-arch support verified (amd64, arm64)
- [ ] SBOM included with images
- [ ] Pull works from both registries

**Estimated Effort:** 2-4 hours

### 3. Homebrew Tap Publishing

**Why Important:** Quick win, formula already complete

**Current Status:**
- ✅ Formula ready: `homebrew/pyguard.rb` (1,905 lines)
- ❌ Tap not created

**Action Items:**
- [ ] Create GitHub repository: `cboyd0319/homebrew-pyguard`
- [ ] Copy formula to tap repository
- [ ] Update formula URL to point to latest release
- [ ] Test installation: `brew install cboyd0319/pyguard/pyguard`
- [ ] Automate tap updates in release workflow
- [ ] Update README with Homebrew installation instructions

**Success Criteria:**
- [ ] Tap repository created and configured
- [ ] Formula installable via Homebrew
- [ ] macOS (Intel & Apple Silicon) tested
- [ ] Linux tested
- [ ] Auto-updates on new releases

**Estimated Effort:** 4-6 hours

---

## 📊 Medium Priority (Next 1-2 Months)

### 4. Test Coverage to 90%

**Why Important:** Quality metric for v0.7.0

**Current Status:**
- Current: 84% (4,543 tests)
- Target: 90%
- Gap: ~50-60 additional tests needed

**Action Items:**
- [ ] Identify uncovered code areas:
  ```bash
  coverage report --show-missing
  coverage html  # Generate detailed HTML report
  ```
- [ ] Focus areas:
  - Framework visitor methods (especially visitor-based frameworks)
  - Edge cases in auto-fix system
  - Error handling paths
  - Advanced features edge cases
- [ ] Add property-based tests for auto-fix safety
- [ ] Add integration tests for each framework
- [ ] Re-run coverage to verify 90% achieved

**Success Criteria:**
- [ ] Coverage >= 90% overall
- [ ] All critical paths covered
- [ ] Property-based tests for auto-fixes

**Estimated Effort:** 1-2 weeks

### 5. Sigstore/Cosign Signing Activation

**Why Important:** Supply chain security for v0.8.0

**Current Status:**
- Infrastructure: 70% complete
- Needs: Workflow activation and verification

**Action Items:**
- [ ] Review `.github/workflows/release.yml`
- [ ] Enable cosign signing steps (may be commented out)
- [ ] Install cosign in workflow:
  ```yaml
  - uses: sigstore/cosign-installer@v3
  ```
- [ ] Sign artifacts:
  ```bash
  cosign sign-blob --bundle pyguard-<version>.tar.gz.bundle pyguard-<version>.tar.gz
  ```
- [ ] Verify Rekor transparency log integration
- [ ] Update `docs/security/SIGNATURE_VERIFICATION.md` with cosign examples
- [ ] Test verification workflow:
  ```bash
  cosign verify-blob --bundle pyguard-<version>.tar.gz.bundle pyguard-<version>.tar.gz
  ```

**Success Criteria:**
- [ ] All release artifacts signed with cosign
- [ ] Signatures verifiable via cosign CLI
- [ ] Rekor transparency log entries created
- [ ] Documentation updated with examples

**Estimated Effort:** 1 week

### 6. False Positive Rate Benchmarking

**Why Important:** Quality metric, user satisfaction

**Current Status:**
- Target: <1.5%
- Measured: Not yet

**Action Items:**
- [ ] Select 10-15 popular Python projects for benchmarking:
  - Django
  - Flask
  - FastAPI
  - Requests
  - NumPy
  - Pandas
  - Scikit-learn
  - TensorFlow examples
  - Pytest
  - Black
- [ ] Run PyGuard on each project
- [ ] Manually review findings to identify false positives
- [ ] Calculate FP rate: (False Positives / Total Findings) * 100
- [ ] Document common FP patterns
- [ ] Create GitHub issues for FP fixes
- [ ] Tune detection patterns to reduce FPs
- [ ] Re-benchmark after fixes

**Success Criteria:**
- [ ] Baseline FP rate established
- [ ] FP rate < 2% (stretch: <1.5%)
- [ ] Common FP patterns documented
- [ ] Tracking system for FP reports

**Estimated Effort:** 2-3 weeks

---

## 📈 Long-Term Priority (3-6 Months)

### 7. PyCharm Plugin Development

**Why Important:** Second-largest IDE user base, Python-focused

**Dependencies:** VS Code extension proven first

**Action Items:**
- [ ] Review VS Code extension learnings
- [ ] Set up IntelliJ Platform SDK
- [ ] Create Gradle build for plugin
- [ ] Implement External Tool integration
- [ ] Create Code Inspection providers
- [ ] Add Intention Actions for quick fixes
- [ ] Build Settings dialog
- [ ] Test on IntelliJ IDEA and PyCharm
- [ ] Publish to JetBrains Marketplace

**Success Criteria:**
- [ ] Plugin installable from JetBrains Marketplace
- [ ] Real-time inspections work
- [ ] Quick fixes apply correctly
- [ ] Settings configurable

**Estimated Effort:** 3-4 weeks (after VS Code proven)

### 8. OpenSSF Scorecard >8.0

**Why Important:** Security posture metric for v0.8.0

**Current Status:**
- Target: >8.0
- Measured: Not yet (likely 6-7 range)

**Action Items:**
- [ ] Run OpenSSF Scorecard:
  ```bash
  scorecard --repo=github.com/cboyd0319/PyGuard --format=json
  ```
- [ ] Review low-scoring areas
- [ ] Common areas to improve:
  - Branch protection rules
  - SAST tools (CodeQL already configured)
  - Dependency update tools (Dependabot already configured)
  - Signed releases (working on this)
  - Vulnerability disclosure policy
  - Security champions
- [ ] Implement improvements
- [ ] Re-run scorecard
- [ ] Add scorecard badge to README
- [ ] Set up automated scorecard runs in CI

**Success Criteria:**
- [ ] Scorecard score >8.0
- [ ] Badge displayed in README
- [ ] Automated tracking in CI

**Estimated Effort:** 2-3 weeks

### 9. Framework Check Count Audit

**Why Important:** Accurate documentation, methodology clarity

**Current Status:**
- 25 frameworks verified
- Check counts based on visitor methods not fully audited

**Action Items:**
- [ ] For each framework file in `pyguard/lib/framework_*.py`:
  - [ ] Audit all `visit_*` methods
  - [ ] Document specific security checks
  - [ ] Count actual detection patterns
  - [ ] Update documentation
- [ ] Create per-framework check list
- [ ] Update `docs/reference/capabilities-reference.md`
- [ ] Add methodology note about visitor pattern vs explicit checks
- [ ] Verify claimed check counts (739+)

**Success Criteria:**
- [ ] Accurate per-framework check counts
- [ ] Documentation reflects actual implementation
- [ ] Methodology clearly explained

**Estimated Effort:** 1-2 weeks

---

## 📝 Quality Metrics Establishment

### 10. Performance Benchmarking

**Why Important:** v1.0.0 quality metric

**Target:** <5s for 1K SLOC

**Action Items:**
- [ ] Create benchmark suite:
  - Small project: 500 SLOC
  - Medium project: 1,000 SLOC
  - Large project: 5,000 SLOC
  - Extra large: 10,000+ SLOC
- [ ] Run benchmarks with performance tracking
- [ ] Document baseline performance
- [ ] Compare against competitors (if possible)
- [ ] Identify optimization opportunities
- [ ] Re-benchmark after optimizations

**Success Criteria:**
- [ ] Baseline performance documented
- [ ] <5s for 1K SLOC achieved
- [ ] Performance tracking automated

**Estimated Effort:** 1 week

### 11. Bug Tracking System

**Why Important:** v1.0.0 quality metric (zero critical bugs for 90 days)

**Action Items:**
- [ ] Establish bug severity levels:
  - Critical: Security vulnerability, data loss, crash
  - High: Major functionality broken
  - Medium: Functionality impaired
  - Low: Minor issues, cosmetic
- [ ] Set up GitHub Projects for bug tracking
- [ ] Create bug report template
- [ ] Define critical bug SLA (e.g., 48-hour response)
- [ ] Track time-to-resolution
- [ ] Monitor critical bug count over time

**Success Criteria:**
- [ ] Bug tracking system operational
- [ ] Critical bugs categorized and tracked
- [ ] 90-day window monitored

**Estimated Effort:** 4-8 hours setup + ongoing

---

## 📦 Package Manager Publishing (Low Priority)

### 12. Chocolatey, Scoop, Snap Publishing

**Why Important:** Additional distribution channels

**Current Status:**
- Configuration files ready
- Not yet published

**Action Items:**

#### Chocolatey (Windows)
- [ ] Review `packaging/chocolatey/pyguard.nuspec`
- [ ] Create Chocolatey account
- [ ] Test package locally
- [ ] Submit to Chocolatey Gallery
- [ ] Automate updates in release workflow

#### Scoop (Windows)
- [ ] Review `packaging/scoop/pyguard.json`
- [ ] Fork scoop bucket
- [ ] Submit PR to main bucket
- [ ] Automate updates

#### Snap (Linux)
- [ ] Review `packaging/snap/snapcraft.yaml`
- [ ] Create Snapcraft account
- [ ] Build and test snap
- [ ] Publish to Snap Store
- [ ] Automate updates

**Success Criteria:**
- [ ] All three package managers live
- [ ] Auto-updates on new releases
- [ ] Documentation updated

**Estimated Effort:** 1-2 weeks total

---

## 📋 Summary of Time Estimates

| Priority | Task | Estimated Effort | Impact |
|----------|------|------------------|--------|
| **Critical** | VS Code Extension | 4-6 weeks | **HIGHEST** - Unblocks v0.7.0 |
| **High** | Docker Hub Publish | 2-4 hours | Quick win |
| **High** | Homebrew Tap Publish | 4-6 hours | Quick win |
| **Medium** | Test Coverage 90% | 1-2 weeks | Quality |
| **Medium** | Sigstore Activation | 1 week | Security |
| **Medium** | FP Benchmarking | 2-3 weeks | Quality |
| **Long-term** | PyCharm Plugin | 3-4 weeks | Market expansion |
| **Long-term** | OpenSSF Scorecard | 2-3 weeks | Security posture |
| **Long-term** | Framework Audit | 1-2 weeks | Documentation |
| **Quality** | Performance Benchmarking | 1 week | Metrics |
| **Quality** | Bug Tracking | 4-8 hours | Tracking |
| **Low** | Package Managers | 1-2 weeks | Distribution |

**Total Critical Path to v0.7.0:** ~6-8 weeks (dominated by VS Code extension)

---

## 🎯 Recommended Execution Plan

### Sprint 1-2 (Weeks 1-2): Quick Wins + Start Extension
- **Week 1:** Docker Hub publish, Homebrew tap publish, start VS Code LSP server
- **Week 2:** Complete VS Code LSP server, start extension

### Sprint 3-4 (Weeks 3-4): Extension Development
- **Week 3:** VS Code extension core features
- **Week 4:** VS Code extension polish, quick fixes

### Sprint 5-6 (Weeks 5-6): Extension Completion + Quality
- **Week 5:** VS Code extension testing, marketplace prep
- **Week 6:** Publish extension, start test coverage work

### Sprint 7-8 (Weeks 7-8): Quality & Security
- **Week 7:** Test coverage to 90%, Sigstore activation
- **Week 8:** FP benchmarking start

### Beyond (Months 3-6): PyCharm, Metrics, Polish
- PyCharm plugin development
- OpenSSF Scorecard improvements
- Performance benchmarking
- Framework check audit
- Additional package managers

---

## 📞 Next Steps

1. **Review this plan** with core team
2. **Prioritize** VS Code extension development (assign developer)
3. **Quick wins** - Docker Hub and Homebrew publishing this week
4. **Set up tracking** - Create GitHub project board for these tasks
5. **Schedule reviews** - Weekly progress checks

**Report Generated:** 2025-11-14
**Based On:** [2025-11-14-roadmap-gap-analysis.md](2025-11-14-roadmap-gap-analysis.md)
**Status:** Ready for implementation
