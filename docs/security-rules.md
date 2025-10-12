# Security Rules Reference

Complete reference for security vulnerability detection and fixes in PyGuard.

## Overview

PyGuard detects and fixes 9 categories of security vulnerabilities in Python code:

| Category | Severity | Auto-Fix | Count |
|----------|----------|----------|-------|
| Hardcoded Passwords | HIGH | ⚠️ Warning | - |
| SQL Injection | HIGH | ⚠️ Warning | - |
| Command Injection | HIGH | ⚠️ Warning | - |
| Insecure Random | MEDIUM | ✅ Replace | - |
| Unsafe YAML | HIGH | ✅ Replace | - |
| Pickle Usage | MEDIUM | ⚠️ Warning | - |
| eval()/exec() | HIGH | ⚠️ Warning | - |
| Weak Crypto | MEDIUM | ✅ Replace | - |
| Path Traversal | HIGH | ⚠️ Warning | - |

---

## 1. Hardcoded Passwords

**Severity**: HIGH

### Description

Detects hardcoded passwords, API keys, tokens, and secrets in source code.

### Detected Patterns

```python
# ❌ Bad - Hardcoded credentials
password = "secret123"
api_key = "sk-1234567890abcdef"
token = "ghp_abc123def456"
SECRET_KEY = "django-secret-key"
DATABASE_PASSWORD = "mypass"
```

### Fix Applied

```python
# ✅ Fixed - Warning added
password = "secret123"  # SECURITY: Use environment variables or config files
api_key = "sk-1234567890abcdef"  # SECURITY: Use environment variables or config files
```

### Recommendation

Use environment variables or secure configuration:

```python
import os
from pathlib import Path

# ✅ Good - Environment variables
password = os.environ.get("DB_PASSWORD")
api_key = os.getenv("API_KEY")

# ✅ Good - Config file (not in git)
config = json.loads(Path(".secrets.json").read_text())
token = config["github_token"]
```

---

## 2. SQL Injection

**Severity**: HIGH

### Description

Detects SQL injection vulnerabilities from string formatting and concatenation.

### Detected Patterns

```python
# ❌ Bad - SQL injection risk
query = f"SELECT * FROM users WHERE id = {user_id}"
query = "SELECT * FROM users WHERE name = '%s'" % username
query = "DELETE FROM users WHERE id = " + user_id
cursor.execute(f"SELECT * FROM {table} WHERE id = {id}")
```

### Fix Applied

```python
# ✅ Fixed - Warning added
query = f"SELECT * FROM users WHERE id = {user_id}"  # ANTI-PATTERN: Use parameterized queries
```

### Recommendation

Use parameterized queries:

```python
# ✅ Good - Parameterized query (safe)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))

# ✅ Good - ORM (SQLAlchemy, Django ORM)
User.objects.filter(id=user_id)
session.query(User).filter_by(id=user_id).first()
```

---

## 3. Command Injection

**Severity**: HIGH

### Description

Detects command injection vulnerabilities from shell=True and string formatting.

### Detected Patterns

```python
# ❌ Bad - Command injection risk
os.system(f"ls {user_input}")
subprocess.call("rm " + filename, shell=True)
subprocess.Popen(f"cat {file}", shell=True)
os.popen(f"grep {pattern} file.txt")
```

### Fix Applied

```python
# ✅ Fixed - Warning added
os.system(f"ls {user_input}")  # ANTI-PATTERN: Use subprocess with list arguments
```

### Recommendation

Use subprocess with list arguments:

```python
# ✅ Good - Safe subprocess usage
subprocess.run(["ls", user_input], check=True)
subprocess.call(["rm", filename])
subprocess.Popen(["cat", file])

# ✅ Good - No shell=True, validated input
if filename.isalnum():  # Validate first
    subprocess.run(["rm", filename], check=True)
```

---

## 4. Insecure Random

**Severity**: MEDIUM

### Description

Detects use of `random` module for security-sensitive operations.

### Detected Patterns

```python
# ❌ Bad - Not cryptographically secure
import random
token = random.randint(1000, 9999)
session_id = str(random.random())
password = ''.join(random.choice(string.ascii_letters) for _ in range(10))
```

### Fix Applied

```python
# ✅ Fixed - Replaced with secrets module
import secrets
token = secrets.randbelow(9000) + 1000
session_id = secrets.token_hex(16)
password = ''.join(secrets.choice(string.ascii_letters) for _ in range(10))
```

### Recommendation

```python
# ✅ Good - Use secrets module for security
import secrets

# Generate tokens
token = secrets.token_urlsafe(32)
api_key = secrets.token_hex(16)

# Generate password
import string
alphabet = string.ascii_letters + string.digits
password = ''.join(secrets.choice(alphabet) for _ in range(20))

# Generate random numbers
random_int = secrets.randbelow(1000)
```

---

## 5. Unsafe YAML Loading

**Severity**: HIGH

### Description

Detects unsafe YAML loading that allows arbitrary code execution.

### Detected Patterns

```python
# ❌ Bad - Allows code execution
import yaml
data = yaml.load(file)
config = yaml.load(input_string)
```

### Fix Applied

```python
# ✅ Fixed - Use safe_load
import yaml
data = yaml.safe_load(file)
config = yaml.safe_load(input_string)
```

### Recommendation

```python
# ✅ Good - Always use safe_load
import yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)

# ✅ Good - For multiple documents
with open("multi.yaml") as f:
    for doc in yaml.safe_load_all(f):
        process(doc)
```

---

## 6. Pickle Usage

**Severity**: MEDIUM

### Description

Warns about pickle usage with untrusted data (code execution risk).

### Detected Patterns

```python
# ⚠️ Warning - Pickle is unsafe with untrusted data
import pickle
data = pickle.load(file)
obj = pickle.loads(bytes_data)
```

### Fix Applied

```python
# ✅ Fixed - Warning added
data = pickle.load(file)  # WARNING: pickle is unsafe with untrusted data
```

### Recommendation

```python
# ✅ Better - Use JSON for simple data
import json
data = json.load(file)

# ✅ Better - Use safer serialization
import msgpack
data = msgpack.unpackb(bytes_data)

# ⚠️ If you must use pickle, validate source
import pickle
import hmac

def safe_unpickle(data: bytes, secret: bytes) -> object:
    """Unpickle with HMAC verification."""
    # Verify HMAC first
    ...
    return pickle.loads(data)
```

---

## 7. eval()/exec() Usage

**Severity**: HIGH

### Description

Detects dangerous `eval()` and `exec()` calls that execute arbitrary code.

### Detected Patterns

```python
# ❌ Bad - Arbitrary code execution
result = eval(user_input)
exec(code_string)
exec(open("script.py").read())
```

### Fix Applied

```python
# ✅ Fixed - Warning added
result = eval(user_input)  # DANGER: eval() executes arbitrary code
exec(code_string)  # DANGER: exec() executes arbitrary code
```

### Recommendation

```python
# ✅ Good - Use ast.literal_eval for literals
import ast
data = ast.literal_eval("[1, 2, 3]")  # Safe for literals only

# ✅ Good - Parse and validate
import json
data = json.loads(user_input)  # Safe for JSON

# ✅ Good - Use safer alternatives
result = int(user_input)  # If expecting number
config = yaml.safe_load(user_input)  # If expecting config
```

---

## 8. Weak Cryptographic Hashing

**Severity**: MEDIUM

### Description

Detects use of weak hash algorithms (MD5, SHA1).

### Detected Patterns

```python
# ❌ Bad - Weak hashing algorithms
import hashlib
hash1 = hashlib.md5(data).hexdigest()
hash2 = hashlib.sha1(data).hexdigest()
```

### Fix Applied

```python
# ✅ Fixed - Replaced with SHA256
import hashlib
hash1 = hashlib.sha256(data).hexdigest()
hash2 = hashlib.sha256(data).hexdigest()
```

### Recommendation

```python
# ✅ Good - Use strong hashing
import hashlib

# For general hashing
hash_value = hashlib.sha256(data).hexdigest()
hash_value = hashlib.sha512(data).hexdigest()

# For password hashing, use bcrypt or argon2
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Or use argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
```

---

## 9. Path Traversal

**Severity**: HIGH

### Description

Detects path traversal vulnerabilities from user-controlled file paths.

### Detected Patterns

```python
# ❌ Bad - Path traversal risk
filename = request.GET['file']
with open(f"/uploads/{filename}") as f:
    content = f.read()

path = user_input
os.remove(path)
```

### Fix Applied

```python
# ✅ Fixed - Warning added
with open(f"/uploads/{filename}") as f:  # ANTI-PATTERN: Validate and sanitize paths
    content = f.read()
```

### Recommendation

```python
# ✅ Good - Validate and sanitize paths
from pathlib import Path
import os

def safe_file_access(filename: str, base_dir: str) -> Path:
    """Safely access file within base directory."""
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()
    
    # Ensure target is within base directory
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    
    return target

# Usage
try:
    file_path = safe_file_access(user_filename, "/uploads")
    content = file_path.read_text()
except ValueError:
    return "Invalid filename"
```

---

## Configuration

Enable/disable specific checks in `pyguard.toml`:

```toml
[security.rules]
check_hardcoded_passwords = true
check_sql_injection = true
check_command_injection = true
check_insecure_random = true
check_yaml_load = true
check_pickle = true
check_eval_exec = true
check_weak_crypto = true
check_path_traversal = true
```

---

## Severity Levels

Filter by severity:

```bash
# Only HIGH severity
pyguard src/ --severity HIGH

# HIGH and MEDIUM
pyguard src/ --severity HIGH MEDIUM
```

Or in configuration:

```toml
[security]
severity_levels = ["HIGH", "MEDIUM"]
```
