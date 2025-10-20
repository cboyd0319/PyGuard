# PyGuard Secure Coding Guide

**Version:** 1.0  
**Last Updated:** 2025-10-19  
**For:** PyGuard Contributors and Python Developers

## Introduction

This guide provides secure coding practices for contributing to PyGuard and general Python security best practices. PyGuard scans for many of these issues, but developers should be aware of common pitfalls.

---

## Table of Contents

1. [Input Validation](#input-validation)
2. [Command Injection Prevention](#command-injection-prevention)
3. [SQL Injection Prevention](#sql-injection-prevention)
4. [Deserialization Security](#deserialization-security)
5. [Path Traversal Prevention](#path-traversal-prevention)
6. [Secrets Management](#secrets-management)
7. [Cryptography Best Practices](#cryptography-best-practices)
8. [Dependencies & Supply Chain](#dependencies--supply-chain)
9. [Error Handling](#error-handling)
10. [Logging Security](#logging-security)

---

## Input Validation

### ❌ Bad: No Validation

```python
def process_user_input(data):
    eval(data)  # NEVER USE eval() on user input!
    exec(data)  # NEVER USE exec() on user input!
```

### ✅ Good: Validate and Sanitize

```python
import ast

def process_user_input(data: str) -> dict:
    """Safely parse user input."""
    try:
        # Use ast.literal_eval for safe evaluation of literals
        return ast.literal_eval(data)
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Invalid input format: {e}")

def validate_integer(value: str, min_val: int = 0, max_val: int = 100) -> int:
    """Validate integer input with bounds."""
    try:
        num = int(value)
        if not min_val <= num <= max_val:
            raise ValueError(f"Value must be between {min_val} and {max_val}")
        return num
    except ValueError as e:
        raise ValueError(f"Invalid integer: {e}")
```

---

## Command Injection Prevention

### ❌ Bad: Shell Injection

```python
import os
import subprocess

def bad_example(filename):
    # VULNERABLE: Shell injection
    os.system(f"cat {filename}")
    
    # VULNERABLE: Shell=True with user input
    subprocess.run(f"ls {filename}", shell=True)
```

### ✅ Good: Use Argument Lists

```python
import subprocess
import shlex

def good_example(filename: str):
    """Safe command execution."""
    # Use argument list (no shell)
    subprocess.run(["cat", filename], check=True)
    
    # If shell is required, use shlex.quote()
    safe_filename = shlex.quote(filename)
    subprocess.run(f"cat {safe_filename}", shell=True, check=True)

def better_example(filename: str):
    """Even better: avoid shell entirely."""
    with open(filename, 'r') as f:
        return f.read()
```

---

## SQL Injection Prevention

### ❌ Bad: String Concatenation

```python
import sqlite3

def bad_query(username):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
```

### ✅ Good: Parameterized Queries

```python
import sqlite3

def good_query(username: str):
    """Safe SQL query with parameters."""
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    
    # Safe: Parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()

# For ORMs (SQLAlchemy example)
from sqlalchemy import text

def orm_query(session, username: str):
    """Safe ORM query."""
    query = text("SELECT * FROM users WHERE username = :username")
    return session.execute(query, {"username": username})
```

---

## Deserialization Security

### ❌ Bad: Unsafe Deserialization

```python
import pickle
import yaml

def bad_deserialize(data):
    # VULNERABLE: Arbitrary code execution
    pickle.loads(data)
    
    # VULNERABLE: yaml.load allows code execution
    yaml.load(data)
```

### ✅ Good: Safe Deserialization

```python
import json
import yaml
from pathlib import Path

def safe_deserialize(data: str) -> dict:
    """Safe deserialization."""
    # Prefer JSON (safe by design)
    return json.loads(data)

def safe_yaml(data: str) -> dict:
    """Safe YAML loading."""
    # Use safe_load instead of load
    return yaml.safe_load(data)

def avoid_pickle():
    """Prefer JSON over pickle."""
    # Use JSON for serialization when possible
    data = {"key": "value"}
    serialized = json.dumps(data)
    deserialized = json.loads(serialized)
    return deserialized
```

---

## Path Traversal Prevention

### ❌ Bad: Unchecked Path Operations

```python
import os

def bad_file_access(filename):
    # VULNERABLE: Path traversal (../../etc/passwd)
    with open(f"/app/data/{filename}", 'r') as f:
        return f.read()
```

### ✅ Good: Validate Paths

```python
from pathlib import Path
import os

def safe_file_access(filename: str, base_dir: str = "/app/data") -> str:
    """Safe file access with path validation."""
    # Resolve absolute paths and check containment
    base_path = Path(base_dir).resolve()
    file_path = (base_path / filename).resolve()
    
    # Ensure file is within base directory
    if not str(file_path).startswith(str(base_path)):
        raise ValueError("Path traversal detected")
    
    # Check if file exists and is a file (not a directory/symlink)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {filename}")
    
    with open(file_path, 'r') as f:
        return f.read()

def safe_path_join(base: str, *parts: str) -> Path:
    """Safely join paths and validate."""
    base_path = Path(base).resolve()
    full_path = base_path.joinpath(*parts).resolve()
    
    if not str(full_path).startswith(str(base_path)):
        raise ValueError("Invalid path: outside base directory")
    
    return full_path
```

---

## Secrets Management

### ❌ Bad: Hardcoded Secrets

```python
# NEVER DO THIS
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "password123"

def connect_to_api():
    return requests.get("https://api.example.com", 
                       headers={"Authorization": f"Bearer {API_KEY}"})
```

### ✅ Good: Environment Variables & Secret Managers

```python
import os
from pathlib import Path
from typing import Optional

def get_secret(key: str, default: Optional[str] = None) -> str:
    """Safely retrieve secrets from environment."""
    value = os.environ.get(key, default)
    if value is None:
        raise ValueError(f"Missing required secret: {key}")
    return value

def connect_to_api():
    """Use environment variables for secrets."""
    api_key = get_secret("API_KEY")
    return requests.get(
        "https://api.example.com",
        headers={"Authorization": f"Bearer {api_key}"}
    )

# For development, use .env files (never commit them!)
from dotenv import load_dotenv

def load_dev_secrets():
    """Load secrets from .env for development only."""
    env_file = Path(".env")
    if env_file.exists():
        load_dotenv(env_file)
    else:
        raise FileNotFoundError(".env file not found")
```

---

## Cryptography Best Practices

### ❌ Bad: Weak Cryptography

```python
import hashlib

def bad_crypto(password):
    # WEAK: MD5 is broken
    hashlib.md5(password.encode()).hexdigest()
    
    # WEAK: SHA1 is broken
    hashlib.sha1(password.encode()).hexdigest()
    
    # INSECURE: Custom crypto
    return password[::-1]  # reversing is not encryption!
```

### ✅ Good: Strong Cryptography

```python
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def hash_password(password: str) -> tuple[str, str]:
    """Securely hash password with salt."""
    # Generate random salt
    salt = secrets.token_bytes(32)
    
    # Use PBKDF2 with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    
    return base64.b64encode(key).decode(), base64.b64encode(salt).decode()

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password against stored hash."""
    salt_bytes = base64.b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
    )
    
    try:
        kdf.verify(password.encode(), base64.b64decode(stored_hash))
        return True
    except Exception:
        return False

def encrypt_data(data: str, key: bytes) -> str:
    """Encrypt data with Fernet (symmetric encryption)."""
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token."""
    return secrets.token_urlsafe(length)
```

---

## Dependencies & Supply Chain

### ✅ Best Practices

```python
# pyproject.toml - Pin versions
[project]
dependencies = [
    "requests>=2.31.0,<3.0.0",  # Pin major version
    "cryptography>=41.0.0",      # Security library - keep updated
]

# Use lock files
# pip freeze > requirements.txt
# pip install -r requirements.txt

# Generate hashes for integrity
# pip-compile --generate-hashes requirements.in
```

### Security Checklist

- [ ] Pin all direct dependencies
- [ ] Review transitive dependencies (`pip list --outdated`)
- [ ] Run `pip-audit` regularly
- [ ] Use `safety check` in CI
- [ ] Enable Dependabot
- [ ] Review dependency licenses
- [ ] Check OSSF Scorecard ratings
- [ ] Verify package signatures when available

---

## Error Handling

### ❌ Bad: Information Disclosure

```python
def bad_error_handling():
    try:
        secret_data = load_secrets()
        process(secret_data)
    except Exception as e:
        # INSECURE: Exposes secrets in error message
        print(f"Error processing {secret_data}: {e}")
        raise
```

### ✅ Good: Safe Error Messages

```python
import logging

logger = logging.getLogger(__name__)

def good_error_handling():
    """Safe error handling without information leakage."""
    try:
        secret_data = load_secrets()
        process(secret_data)
    except ValueError as e:
        # Log detailed error (ensure logs are protected)
        logger.error("Validation error during processing", exc_info=True)
        # Return safe error to user
        raise ValueError("Invalid input format") from e
    except Exception as e:
        # Log unexpected errors
        logger.exception("Unexpected error during processing")
        # Return generic error to user
        raise RuntimeError("An error occurred during processing") from e

def sanitize_error_message(error: Exception, safe_message: str) -> str:
    """Provide safe error messages in production."""
    if os.environ.get("DEBUG") == "true":
        return str(error)
    return safe_message
```

---

## Logging Security

### ❌ Bad: Logging Secrets

```python
import logging

def bad_logging(api_key, user_data):
    # INSECURE: Logs secrets
    logging.info(f"Using API key: {api_key}")
    logging.debug(f"User data: {user_data}")
```

### ✅ Good: Sanitized Logging

```python
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

def sanitize_log_data(data: Any) -> Any:
    """Remove sensitive data from logs."""
    if isinstance(data, str):
        # Redact common secret patterns
        data = re.sub(r'(api[_-]?key|token|password)["\']?\s*[:=]\s*["\']?(\S+)["\']?',
                     r'\1=<REDACTED>', data, flags=re.IGNORECASE)
    elif isinstance(data, dict):
        return {k: sanitize_log_data(v) for k, v in data.items()}
    return data

def safe_logging(api_key: str, user_data: dict):
    """Safe logging with redaction."""
    # Never log secrets
    logger.info("API authentication in progress")
    
    # Sanitize user data before logging
    safe_data = sanitize_log_data(user_data)
    logger.debug(f"Processing user data: {safe_data}")
    
    # Log only non-sensitive identifiers
    logger.info(f"Request completed for user_id: {user_data.get('id')}")
```

---

## Testing Security

### Security Test Examples

```python
import pytest
from hypothesis import given, strategies as st

def test_path_traversal_prevention():
    """Test that path traversal is blocked."""
    with pytest.raises(ValueError, match="Path traversal"):
        safe_file_access("../../etc/passwd")

def test_sql_injection_prevention():
    """Test SQL injection is prevented."""
    # Parameterized queries should escape this
    malicious_input = "'; DROP TABLE users; --"
    result = good_query(malicious_input)
    assert result == []  # No results, no damage

@given(st.text())
def test_input_validation_fuzzing(user_input):
    """Fuzz test input validation."""
    # Should never raise unhandled exceptions
    try:
        validate_and_process(user_input)
    except ValueError:
        pass  # Expected for invalid input
    except Exception as e:
        pytest.fail(f"Unexpected exception: {e}")

def test_secrets_not_in_logs(caplog):
    """Ensure secrets are not logged."""
    secret = "sk-1234567890"
    process_with_secret(secret)
    
    for record in caplog.records:
        assert secret not in record.message
```

---

## Pre-Commit Security Checks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: '1.8.0'
    hooks:
      - id: bandit
        args: ['-r', 'pyguard/', '-f', 'screen']

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-yaml
      - id: check-json
```

---

## Security Review Checklist

Before committing code, ensure:

- [ ] No hardcoded secrets (API keys, passwords, tokens)
- [ ] All user input is validated and sanitized
- [ ] No `eval()`, `exec()`, or `pickle.loads()` on untrusted data
- [ ] SQL queries use parameterization
- [ ] Command execution uses argument lists (no shell=True)
- [ ] File paths are validated (no path traversal)
- [ ] Cryptography uses modern algorithms (no MD5/SHA1)
- [ ] Error messages don't leak sensitive information
- [ ] Logs don't contain secrets
- [ ] Dependencies are up-to-date and audited
- [ ] Tests cover security-critical paths

---

## Resources

### Official Documentation
- Python Security: https://python.readthedocs.io/en/latest/library/security_warnings.html
- OWASP Python Security: https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html

### Security Tools
- Bandit: https://bandit.readthedocs.io/
- Semgrep: https://semgrep.dev/
- pip-audit: https://github.com/pypa/pip-audit
- Safety: https://pyup.io/safety/

### Learning Resources
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/
- Python Cryptography: https://cryptography.io/

---

## Getting Help

If you discover a security vulnerability:
1. **DO NOT** open a public issue
2. Report via [GitHub Security Advisories](https://github.com/cboyd0319/PyGuard/security/advisories/new)
3. Include: description, impact, reproduction steps, suggested fix

For security questions:
- Email: security@pyguard.dev (if configured)
- GitHub Discussions: Security category

---

**Remember:** Security is everyone's responsibility. When in doubt, ask for a security review!
