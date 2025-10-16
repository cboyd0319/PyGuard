# Security Policy

## Supported versions

We support the latest minor release and security patches.

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ Yes    |
| < 0.3   | ❌ No     |

## Reporting a vulnerability

**Do not use public GitHub issues.**

Report via:
- [GitHub Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories/new) (preferred, private)
- Email: security@pyguard.dev *(if configured, otherwise use GitHub)*
- Direct contact: https://github.com/cboyd0319

We aim to respond within **3 business days**.

### What to include

- Issue type (injection, overflow, etc.)
- Source file paths (tag/branch/commit)
- Steps to reproduce
- Proof-of-concept code
- Impact assessment

## Handling of secrets

- Never commit secrets. Use environment variables or secret managers.
- Required runtime secrets documented in README (Security section).
- PyGuard scans for hardcoded secrets — review warnings.

## Supply chain

- Releases are signed with Sigstore/cosign
- SBOM (SPDX 2.3) attached to every release at `/releases/tag/v*`
- Build provenance attached when available
- Dependencies: 14 packages from PyPI (see pyproject.toml)

## Security features in PyGuard

PyGuard helps you find:
- Hardcoded secrets (API keys, passwords, tokens)
- SQL/Command/NoSQL injection patterns
- Unsafe deserialization (pickle, yaml.load)
- Weak cryptography (MD5, SHA1, DES)
- Path traversal vulnerabilities
- Insecure random number generation

## Best practices when using PyGuard

1. **Review auto-fixes** before production deployment
2. **Keep PyGuard updated** — `pip install --upgrade pyguard`
3. **Backup code** before running fixes (PyGuard does this automatically in `.pyguard_backups/`)
4. **Sandbox untrusted code** — PyGuard analyzes but doesn't execute code
5. **Review logs** regularly — `logs/pyguard.jsonl`

 
