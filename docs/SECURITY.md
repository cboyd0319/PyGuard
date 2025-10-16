# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Reporting Vulnerabilities

**Do not use public GitHub issues for security reports.**

Report via:
- GitHub Security Advisories (private)
- Direct contact: https://github.com/cboyd0319

Include:
- Issue type (buffer overflow, injection, etc.)
- Source file paths (tag/branch/commit)
- Steps to reproduce
- Proof-of-concept code (if available)
- Impact assessment

**Response:** Acknowledgment within 48 hours. Then investigation, timeline, patch, credit (if desired).

## Best Practices

When using PyGuard:
1. Review auto-fixes before production
2. Keep PyGuard updated
3. Backup code before running fixes
4. Sandbox untrusted code
5. Review logs regularly (`logs/pyguard.jsonl`)

## Security Considerations

- PyGuard analyzes code (does not execute it). Still review untrusted code carefully.
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
