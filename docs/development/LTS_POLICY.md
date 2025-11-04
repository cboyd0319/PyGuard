# PyGuard Long-Term Support (LTS) Policy

**Version:** 1.0  
**Effective Date:** 2024-11-04  
**Last Updated:** 2024-11-04

## Overview

This document defines the Long-Term Support (LTS) policy for PyGuard, establishing guidelines for release stability, maintenance windows, and support commitments for production deployments.

## Release Strategy

### Version Numbering

PyGuard follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR.MINOR.PATCH** (e.g., 1.0.0)
  - **MAJOR**: Incompatible API changes
  - **MINOR**: New functionality in a backward-compatible manner
  - **PATCH**: Backward-compatible bug fixes

### Release Types

#### Standard Releases

- **Frequency:** Monthly to quarterly
- **Support Duration:** Until next minor version release
- **Updates:** Bug fixes, security patches, new features
- **Best For:** Development, testing, early adoption

#### Long-Term Support (LTS) Releases

- **Designation:** Specific minor versions marked as LTS
- **Frequency:** Annually (starting with v1.0.0)
- **Support Duration:** 24 months from release date
- **Updates:** Critical bug fixes and security patches only
- **Best For:** Production deployments, enterprise environments, air-gapped systems

## LTS Release Schedule

### v1.0.0 LTS (First LTS Release)

- **Release Date:** Q3 2026 (September 2026)
- **Support Ends:** Q3 2028 (September 2028)
- **Status:** Planned

### Future LTS Releases

- **v2.0.0 LTS:** Q3 2027
- **v3.0.0 LTS:** Q3 2028
- **Pattern:** Every 12 months after v1.0.0

## Support Levels

### Active Support (First 18 Months)

For LTS releases during active support:

- ✅ **Security Updates:** Critical and high-severity vulnerabilities
- ✅ **Bug Fixes:** Critical bugs affecting core functionality
- ✅ **Compatibility Updates:** Python version compatibility, framework updates
- ✅ **Documentation Updates:** Corrections and clarifications
- ❌ **New Features:** Not backported to LTS releases
- ❌ **Framework Additions:** No new framework support

### Maintenance Support (Final 6 Months)

For LTS releases during maintenance support:

- ✅ **Security Updates:** Critical vulnerabilities only (CVE-2024-XXXXX level)
- ✅ **Critical Bug Fixes:** Production-breaking issues only
- ❌ **Enhancement Requests:** No enhancements or improvements
- ❌ **Framework Updates:** No framework version updates

### End of Life (EOL)

After support ends:

- ❌ No further updates of any kind
- ❌ No security patches
- ✅ Code remains available (MIT License)
- ✅ Community support via GitHub Discussions

## Python Version Support

### LTS Python Version Policy

LTS releases support:

- **Minimum Python Version:** As defined at LTS release time
- **Maximum Python Version:** Latest stable at LTS release + 2 minor versions
- **Support Duration:** For the entire LTS support window

**Example (v1.0.0 LTS):**
- If released with Python 3.11 support
- Guarantees compatibility with Python 3.11-3.13
- May add support for Python 3.14+ via patches

### Python EOL Alignment

PyGuard LTS releases align with [Python's release schedule](https://devguide.python.org/versions/):

- Support maintained for Python versions in active or security-fix status
- Warning issued 6 months before Python version reaches EOL
- Migration path provided to newer Python versions

## Framework Support

### LTS Framework Stability

For frameworks included in an LTS release:

- **Version Pinning:** Compatible framework versions documented
- **Security Updates:** Framework-specific security rules updated
- **Breaking Changes:** Major framework version upgrades not backported
- **New Frameworks:** Not added to LTS releases

### Framework EOL Handling

If a supported framework reaches EOL during LTS support:

1. **Security rules maintained** for known vulnerabilities
2. **Documentation updated** with EOL notice
3. **Alternative frameworks suggested** in documentation
4. **Removal considered** only for next major version

## Security Updates

### Vulnerability Response

**Timeline:**
- **Critical (CVSS 9.0-10.0):** Patch within 48 hours
- **High (CVSS 7.0-8.9):** Patch within 7 days
- **Medium (CVSS 4.0-6.9):** Patch within 30 days
- **Low (CVSS 0.1-3.9):** Considered for next release

**Disclosure:**
- Security advisories published via [GitHub Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories)
- CVE IDs requested for all high and critical vulnerabilities
- Patch releases tagged and released immediately

### Backporting Policy

Security fixes are backported to:
- ✅ Current LTS release (active support)
- ✅ Previous LTS release (if still in support window)
- ❌ Non-LTS releases
- ❌ EOL releases

## Upgrade Paths

### Recommended Upgrade Strategy

**For Production Deployments:**

1. **Start with LTS:** Deploy LTS releases for stability
2. **Test Upgrades:** Test new LTS releases in staging for 30 days
3. **Plan Migrations:** Plan LTS-to-LTS upgrades 3-6 months before EOL
4. **Stay Current:** Upgrade to latest LTS within support window

**For Development:**

1. **Use Latest:** Use latest standard release for new features
2. **Track LTS:** Monitor LTS release announcements
3. **Prepare Early:** Test LTS releases before production deployment

### Migration Assistance

For LTS-to-LTS upgrades:
- ✅ Migration guides provided
- ✅ Breaking changes documented
- ✅ Configuration migration tools
- ✅ Deprecation warnings in advance

## Commercial Support

### Enterprise LTS Support

For organizations requiring extended support beyond standard LTS:

**Extended LTS (36 Months):**
- Additional 12 months beyond standard 24-month LTS
- Security patches and critical bug fixes
- Priority support channel
- Custom SLA options

**Custom Support Plans:**
- Extended support beyond 36 months
- Custom patch schedules
- Dedicated support engineer
- On-site training and consultation

**Contact:** [Support inquiry form](https://github.com/cboyd0319/PyGuard/discussions)

## Release Channels

### Stable Channel

- LTS releases only
- Recommended for production
- **Installation:** `pip install pyguard-lts`

### Standard Channel

- All releases (LTS and standard)
- Latest features and improvements
- **Installation:** `pip install pyguard`

### Edge Channel

- Pre-release and beta versions
- For testing and early feedback
- **Installation:** `pip install pyguard --pre`

## Version Support Matrix

| Version | Release Date | Support Ends | Status | Python Versions |
|---------|--------------|--------------|--------|-----------------|
| v0.6.0  | Oct 2025     | Jun 2026     | Current | 3.11-3.13       |
| v0.7.0  | Mar 2026     | Sep 2026     | Planned | 3.11-3.13       |
| v0.8.0  | Jun 2026     | Dec 2026     | Planned | 3.11-3.13       |
| **v1.0.0 LTS** | **Sep 2026** | **Sep 2028** | **Planned** | **3.11-3.14** |
| v1.1.0  | Dec 2026     | Jun 2027     | Planned | 3.11-3.14       |
| **v2.0.0 LTS** | **Sep 2027** | **Sep 2029** | **Planned** | **3.12-3.15** |

## Communication Channels

### LTS Announcements

- **GitHub Releases:** https://github.com/cboyd0319/PyGuard/releases
- **Security Advisories:** https://github.com/cboyd0319/PyGuard/security/advisories
- **Discussions:** https://github.com/cboyd0319/PyGuard/discussions
- **Roadmap:** https://github.com/cboyd0319/PyGuard/blob/main/ROADMAP.md

### Support Resources

- **Documentation:** https://github.com/cboyd0319/PyGuard/tree/main/docs
- **Issue Tracker:** https://github.com/cboyd0319/PyGuard/issues
- **Community Forum:** https://github.com/cboyd0319/PyGuard/discussions
- **Security Reports:** security@pyguard.dev (if available)

## Frequently Asked Questions

### Q: Should I use LTS or standard releases?

**A:** 
- **Production/Enterprise:** Use LTS releases for stability and extended support
- **Development/Testing:** Use standard releases for latest features
- **CI/CD Pipelines:** Consider LTS for consistent results over time

### Q: Can I mix LTS and standard releases?

**A:** Yes, but maintain separate environments:
- Development: Standard releases
- Staging: LTS releases (match production)
- Production: LTS releases

### Q: What happens at EOL?

**A:** After EOL:
- No further updates or security patches
- Software continues to work but becomes increasingly risky
- Upgrade to current LTS release strongly recommended
- Community support still available

### Q: Will configuration files remain compatible?

**A:** Within an LTS version:
- ✅ Configuration format remains stable
- ✅ New options may be added (backward compatible)
- ✅ Deprecated options removed only in next major version

Between LTS versions:
- ⚠️ Breaking changes possible (documented in migration guide)
- ✅ Migration tools provided when feasible

### Q: How are security vulnerabilities prioritized?

**A:** Based on:
1. **CVSS Score:** Higher scores get priority
2. **Exploitability:** Actively exploited vulnerabilities prioritized
3. **Impact:** Production-breaking issues prioritized
4. **Affected Versions:** LTS releases receive priority backports

## Changes to This Policy

This LTS policy may be updated to reflect:
- Community feedback and requirements
- Industry best practices evolution
- Operational experience and lessons learned
- Market demands and competitive landscape

**Version History:**
- v1.0 (2024-11-04): Initial LTS policy document

## License

This policy is part of PyGuard and is available under the MIT License.

## Acknowledgments

This LTS policy is inspired by:
- [Ubuntu LTS Release Cycle](https://ubuntu.com/about/release-cycle)
- [Node.js Release Schedule](https://github.com/nodejs/release)
- [Python Release Schedule](https://devguide.python.org/versions/)
- [Django Supported Versions](https://www.djangoproject.com/download/#supported-versions)
