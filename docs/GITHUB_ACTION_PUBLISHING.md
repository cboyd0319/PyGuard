# PyGuard GitHub Action Publishing Checklist

This document provides step-by-step instructions for publishing PyGuard to the GitHub Marketplace as a GitHub Action.

## ✅ Pre-Release Checklist

### 1. Repository Structure

- [x] `action.yml` in repository root
- [x] Action metadata complete (name, description, author, branding)
- [x] All inputs documented with descriptions
- [x] All outputs documented with descriptions
- [x] Example workflows in `examples/github-workflows/`
- [x] Comprehensive documentation in `docs/guides/github-action-guide.md`

### 2. Action Implementation

- [x] Composite action using `runs: composite`
- [x] Python setup step with configurable version
- [x] PyGuard installation step
- [x] Scan execution step with all input parameters
- [x] SARIF upload integration (optional)
- [x] Proper error handling and exit codes
- [x] GitHub Actions outputs properly set
- [x] Step summaries for workflow logs

### 3. Testing

- [x] Test workflow in `.github/workflows/test-action.yml`
- [ ] All test scenarios pass:
  - [ ] Basic scan
  - [ ] Security-only mode
  - [ ] Multiple paths
  - [ ] Exclusion patterns
  - [ ] SARIF upload
  - [ ] Fail on issues
  - [ ] Output validation
  - [ ] Python version matrix
  - [ ] Vulnerability detection
- [ ] Test on all platforms (Linux, macOS, Windows)
- [ ] Test with various Python versions (3.11, 3.12, 3.13)

### 4. Documentation

- [x] README.md has GitHub Action section
- [x] MARKETPLACE.md with comprehensive marketplace docs
- [x] GitHub Action Guide in docs/
- [x] Example workflows for common use cases:
  - [x] Basic security scan
  - [x] Security gate (fail on issues)
  - [x] Scheduled audit
  - [x] Multi-path scan
- [ ] Screenshots/GIFs of action results (optional but recommended)
- [ ] Video tutorial (optional)

### 5. Permissions & Security

- [x] Minimal permissions documented
- [x] SARIF upload permissions documented
- [x] No secrets required in action inputs
- [x] Secure handling of repository content
- [ ] Security policy in place (SECURITY.md)
- [ ] Dependabot configured for action dependencies

### 6. Branding

- [x] Icon selected ('shield')
- [x] Color selected ('blue')
- [x] Badges in README for action status
- [ ] Logo/icon image for marketplace (optional)

### 7. Versioning

- [x] Release workflow configured
- [x] Major version tag update strategy (v0, v1, etc.)
- [x] Semantic versioning followed (MAJOR.MINOR.PATCH)
- [ ] CHANGELOG.md updated with version details

## 📦 Release Process

### Step 1: Verify Tests Pass

```bash
# Check all workflows are passing
gh run list --workflow=test.yml --limit 1
gh run list --workflow=test-action.yml --limit 1
gh run list --workflow=lint.yml --limit 1
```

### Step 2: Update Version

1. Update version in `pyproject.toml`:
   ```toml
   version = "0.3.0"
   ```

2. Update version in `action.yml` if referenced:
   ```yaml
   # Update any version references in description or comments
   ```

3. Update CHANGELOG.md:
   ```markdown
   ## [0.3.0] - 2025-01-XX
   
   ### Added
   - GitHub Action support
   - SARIF upload capability
   - Comprehensive example workflows
   
   ### Changed
   - Improved security detection
   
   ### Fixed
   - Bug fixes
   ```

4. Update README.md badges:
   ```markdown
   ![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)
   ```

### Step 3: Create Release Tag

```bash
# Commit all changes
git add .
git commit -m "Release v0.3.0"
git push origin main

# Create and push tag
git tag -a v0.3.0 -m "Release version 0.3.0"
git push origin v0.3.0
```

The release workflow will automatically:
- Build Python package
- Publish to PyPI
- Create GitHub release
- Update major version tag (v0)
- Generate SBOM and attestations

### Step 4: Verify Release

1. Check GitHub Release: https://github.com/cboyd0319/PyGuard/releases
2. Check PyPI: https://pypi.org/project/pyguard/
3. Verify major version tag updated: `git ls-remote --tags origin`

### Step 5: Publish to Marketplace

1. Go to your repository on GitHub
2. Click **Releases** (right sidebar)
3. Find your latest release (v0.3.0)
4. Click **"Publish this Action to the GitHub Marketplace"** button
5. Review the action details:
   - **Primary Category**: Code Quality
   - **Secondary Category**: Continuous Integration
   - **Tags**: security, python, code-quality, SARIF, scanning
6. Accept the GitHub Marketplace terms
7. Click **"Publish Release"**

### Step 6: Verify Marketplace Listing

1. Go to: https://github.com/marketplace/actions/pyguard-security-scanner
2. Verify:
   - [ ] Action appears in search results
   - [ ] Description is clear and compelling
   - [ ] README renders correctly
   - [ ] Example usage is visible
   - [ ] Inputs/outputs are documented
   - [ ] Branding (icon/color) displays correctly

## 🔄 Update Process (For Future Releases)

### For Patch Releases (0.3.0 → 0.3.1)

```bash
# Update version
vim pyproject.toml  # Change version
vim docs/CHANGELOG.md  # Add changelog entry

# Commit and tag
git commit -am "Release v0.3.1"
git tag -a v0.3.1 -m "Release version 0.3.1"
git push origin main v0.3.1
```

Major version tag (v0) automatically updates to point to v0.3.1.

### For Minor Releases (0.3.0 → 0.4.0)

Same as patch, but include more significant changes in CHANGELOG.

### For Major Releases (0.3.0 → 1.0.0)

```bash
# Update version
vim pyproject.toml  # Change to 1.0.0
vim docs/CHANGELOG.md  # Add detailed changelog

# Commit and tag
git commit -am "Release v1.0.0"
git tag -a v1.0.0 -m "Release version 1.0.0 - First stable release"
git push origin main v1.0.0
```

This creates a new major version tag (v1) pointing to v1.0.0.

## 📝 Marketplace Best Practices

### 1. Clear Value Proposition

Your action should clearly state:
- ✅ What it does: "Comprehensive Python security and code quality scanning"
- ✅ Why use it: "Replace 7+ tools with one action"
- ✅ Key benefits: "55+ security checks, SARIF native, 179+ auto-fixes"

### 2. Easy to Get Started

- ✅ Provide a minimal working example upfront
- ✅ Show results users can expect
- ✅ Keep required inputs minimal

### 3. Comprehensive Documentation

- ✅ Document ALL inputs with clear descriptions
- ✅ Provide example workflows for common scenarios
- ✅ Include troubleshooting section
- ✅ Link to detailed guides

### 4. Trust Signals

- ✅ Badges for test status, coverage, security scans
- ✅ Open source license (MIT)
- ✅ Active maintenance (recent commits)
- ✅ Security policy
- ✅ Code of conduct
- ✅ Contributing guidelines

### 5. SEO & Discoverability

Include these keywords in your action.yml description:
- security
- code-quality
- python
- SARIF
- vulnerability-scanning
- OWASP
- CWE
- static-analysis
- code-scanning
- DevSecOps

### 6. Version Management

Users can reference your action in three ways:
```yaml
uses: cboyd0319/PyGuard@v0.3.0  # Specific version (pinned)
uses: cboyd0319/PyGuard@v0      # Latest v0.x.x (auto-updates)
uses: cboyd0319/PyGuard@main    # Latest main branch (bleeding edge)
```

Recommend `@v0` or `@v1` for most users in documentation.

## 🎯 Post-Release Tasks

- [ ] Announce release on GitHub Discussions
- [ ] Update examples to use new version
- [ ] Tweet/LinkedIn post about release (optional)
- [ ] Blog post about features (optional)
- [ ] Update any external documentation links
- [ ] Monitor GitHub Issues for bug reports
- [ ] Respond to user feedback/questions

## 🔍 Monitoring & Maintenance

### Track Usage

GitHub provides analytics for Marketplace actions:
1. Go to **Insights** → **Traffic**
2. View action usage statistics
3. Monitor installation counts
4. Track which versions are most popular

### User Feedback

- Monitor GitHub Issues for bug reports
- Watch GitHub Discussions for questions
- Check action workflow runs in user repos (public)
- Respond to marketplace reviews (if any)

### Regular Updates

- Keep dependencies updated (Dependabot)
- Update Python versions as new releases come out
- Add new security checks as vulnerabilities are discovered
- Improve documentation based on user questions
- Fix bugs promptly

## 📋 Quick Reference

### Useful Commands

```bash
# Test action locally (using act)
act -W .github/workflows/test-action.yml

# List releases
gh release list

# View action in marketplace
gh browse --repo cboyd0319/PyGuard marketplace

# Check action usage
gh api /repos/cboyd0319/PyGuard/actions/workflows

# Update major version tag manually
git tag -fa v0 -m "Update v0 to v0.3.0"
git push origin v0 --force
```

### Important Links

- **Repository**: https://github.com/cboyd0319/PyGuard
- **Marketplace**: https://github.com/marketplace/actions/pyguard-security-scanner
- **PyPI**: https://pypi.org/project/pyguard/
- **Documentation**: https://github.com/cboyd0319/PyGuard/tree/main/docs
- **Issues**: https://github.com/cboyd0319/PyGuard/issues
- **Releases**: https://github.com/cboyd0319/PyGuard/releases

## ✅ Final Checklist Before Publishing

- [ ] All tests pass
- [ ] Documentation is complete and accurate
- [ ] Examples work correctly
- [ ] Version numbers updated everywhere
- [ ] CHANGELOG.md updated
- [ ] Release tag created
- [ ] GitHub release created
- [ ] Published to PyPI
- [ ] Major version tag updated
- [ ] Ready to publish to Marketplace!

---

**Next Step**: If all items are checked, proceed with "Step 5: Publish to Marketplace" above.

**Questions?** Open an issue or check the [GitHub Action Guide](https://github.com/cboyd0319/PyGuard/blob/main/docs/guides/github-action-guide.md).
