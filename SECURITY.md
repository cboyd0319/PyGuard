# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Reporting Vulnerabilities

**Do not report security issues through public GitHub issues.**

Report via:
- Email: security@pyguard.dev
- GitHub Security Advisories (private)

Include:
- Issue type (e.g., buffer overflow, injection)
- Source file paths and locations (tag/branch/commit)
- Steps to reproduce
- Proof-of-concept or exploit code (if available)
- Impact assessment

**Response**: Acknowledgment within 48 hours. Investigation, timeline, patch, credit (if desired).

## User Security Practices

When using PyGuard:
1. Review auto-fixes before applying to production.
2. Keep PyGuard updated.
3. Backup code before running fixes.
4. Run in sandbox when analyzing untrusted code.
5. Review logs regularly (`logs/pyguard.jsonl`).

## Security Considerations

- PyGuard analyzes but does not execute code. Still, review untrusted code carefully.
- PyGuard reads and writes files. Set appropriate permissions on sensitive files.
- Keep dependencies updated: `pip list --outdated`

## PyGuard Security Features

- Hardcoded secrets detection
- SQL injection pattern detection
- Command injection prevention
- Unsafe deserialization warnings
- Weak cryptography detection
- Path traversal detection

## Disclosure Process

On receiving a report:
1. Confirm and determine affected versions.
2. Audit for similar issues.
3. Prepare fixes for supported versions.
4. Release patches quickly.

## Policy Feedback

Suggestions welcome via PR or issue.

---

**Last Updated**: 2025-10-13
