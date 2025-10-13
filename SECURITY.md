# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| 0.4.x   | :white_check_mark: |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

We take the security of PyGuard seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Reporting Process

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@pyguard.dev** (or open a private security advisory on GitHub)

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

### What to Expect

After you submit a vulnerability report, we will:

1. **Acknowledge** your email within 48 hours
2. **Investigate** the issue and determine its impact and severity
3. **Provide** an estimated timeline for a fix
4. **Release** a security advisory and patch when ready
5. **Credit** you in the security advisory (unless you prefer to remain anonymous)

### Security Best Practices for Users

When using PyGuard:

1. **Always review auto-fixes** before applying them to production code
2. **Keep PyGuard updated** to the latest version
3. **Use secure configurations** - review the security rules in `config/security_rules.toml`
4. **Backup your code** before running auto-fixes
5. **Run in a sandbox** when analyzing untrusted code
6. **Review logs** regularly for security findings in `logs/pyguard.jsonl`

### Known Security Considerations

1. **Code Execution**: PyGuard analyzes Python code but does not execute it. However, always review code from untrusted sources.
2. **File System Access**: PyGuard reads and writes files. Ensure proper permissions are set on sensitive files.
3. **Dependencies**: Keep all dependencies updated. Run `pip list --outdated` regularly.

### Security Features

PyGuard includes several security-focused features:

- 🔒 Detection of hardcoded secrets and credentials
- 🔒 SQL injection pattern detection
- 🔒 Command injection prevention
- 🔒 Unsafe deserialization warnings (pickle)
- 🔒 Weak cryptography detection
- 🔒 Path traversal vulnerability detection

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine affected versions
2. Audit code to find any similar problems
3. Prepare fixes for all supported versions
4. Release new security fix versions as quickly as possible

## Comments on This Policy

If you have suggestions on how this process could be improved, please submit a pull request or open an issue.

---

**Last Updated**: 2025-10-13
