# Security Rules Reference

Complete reference for security vulnerability detection and fixes in PyGuard.

## Overview

PyGuard v0.3.0 detects and fixes **20+ categories** of security vulnerabilities in Python code, aligned with OWASP ASVS v5.0 and CWE Top 25:

### Core Vulnerabilities
| Category | Severity | OWASP | CWE | Auto-Fix |
|----------|----------|-------|-----|----------|
| Code Injection | HIGH | ASVS-5.2.1 | CWE-95 | ⚠️ Warning |
| Hardcoded Passwords | HIGH | ASVS-2.6.3 | CWE-798 | ⚠️ Warning |
| SQL Injection | HIGH | ASVS-5.3.4 | CWE-89 | ⚠️ Warning |
| Command Injection | HIGH | ASVS-5.3.3 | CWE-78 | ⚠️ Warning |
| Unsafe Deserialization | HIGH | ASVS-5.5.3 | CWE-502 | ✅ Replace |

### Injection Attacks (NEW in v0.3.0)
| Category | Severity | OWASP | CWE | Auto-Fix |
|----------|----------|-------|-----|----------|
| XXE Injection | HIGH | ASVS-5.5.2 | CWE-611 | ⚠️ Warning |
| LDAP Injection | HIGH | ASVS-5.3.7 | CWE-90 | ⚠️ Warning |
| NoSQL Injection | HIGH | ASVS-5.3.4 | CWE-943 | ⚠️ Warning |
| CSV Injection | MEDIUM | ASVS-5.2.2 | CWE-1236 | ⚠️ Warning |
| Format String | MEDIUM | ASVS-5.2.8 | CWE-134 | ⚠️ Warning |

### Cryptography & Random
| Category | Severity | OWASP | CWE | Auto-Fix |
|----------|----------|-------|-----|----------|
| Weak Crypto | MEDIUM | ASVS-6.2.1 | CWE-327 | ✅ Replace |
| Weak Random | MEDIUM | ASVS-6.3.1 | CWE-330 | ✅ Replace |
| Timing Attacks | MEDIUM | ASVS-2.7.3 | CWE-208 | ⚠️ Warning |

### Network & File Security
| Category | Severity | OWASP | CWE | Auto-Fix |
|----------|----------|-------|-----|----------|
| SSRF | HIGH | ASVS-13.1.1 | CWE-918 | ⚠️ Warning |
| Path Traversal | HIGH | ASVS-12.3.1 | CWE-22 | ⚠️ Warning |
| Insecure Temp Files | HIGH | ASVS-12.3.2 | CWE-377 | ⚠️ Warning |
| Insecure HTTP | MEDIUM | ASVS-9.1.1 | CWE-319 | ⚠️ Warning |

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

---

## 10. XML External Entity (XXE) Injection

**Severity**: HIGH  
**OWASP**: ASVS-5.5.2  
**CWE**: CWE-611

### Description

Detects XML parsing vulnerabilities that allow XML External Entity attacks.

### Detected Patterns

```python
# ❌ Bad - XXE vulnerability
import xml.etree.ElementTree as ET
tree = ET.parse('user_file.xml')

import xml.dom.minidom as minidom
doc = minidom.parse('data.xml')

from lxml import etree
root = etree.parse('input.xml')
```

### Fix Applied

```python
# ✅ Fixed - Warning added
import xml.etree.ElementTree as ET
tree = ET.parse('user_file.xml')  # WARNING: XXE vulnerability
```

### Recommendation

Use defusedxml library or disable external entity processing:

```python
# ✅ Good - Use defusedxml
from defusedxml import ElementTree as ET
tree = ET.parse('user_file.xml')

# ✅ Good - Disable external entities
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import XMLParser

class SafeXMLParser(XMLParser):
    def __init__(self):
        super().__init__()
        self.entity_decl = False

parser = SafeXMLParser()
tree = ET.parse('file.xml', parser=parser)
```

---

## 11. Server-Side Request Forgery (SSRF)

**Severity**: HIGH  
**OWASP**: ASVS-13.1.1  
**CWE**: CWE-918

### Description

Detects potential SSRF vulnerabilities where user-controlled URLs are used in HTTP requests.

### Detected Patterns

```python
# ❌ Bad - SSRF vulnerability
import requests
url = user_input
response = requests.get(url)

import urllib.request
response = urllib.request.urlopen(user_url)
```

### Recommendation

Validate and whitelist URLs:

```python
# ✅ Good - URL validation
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.example.com', 'trusted-service.com']

def safe_request(user_url):
    parsed = urlparse(user_url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Untrusted host")
    if parsed.scheme != 'https':
        raise ValueError("Only HTTPS allowed")
    return requests.get(user_url)
```

---

## 12. Timing Attack Vulnerabilities

**Severity**: MEDIUM  
**OWASP**: ASVS-2.7.3  
**CWE**: CWE-208

### Description

Detects direct string comparison of secrets that are vulnerable to timing attacks.

### Detected Patterns

```python
# ❌ Bad - Timing attack vulnerability
if password == stored_password:
    return True

if token == expected_token:
    authenticate()

if api_key == valid_key:
    grant_access()
```

### Recommendation

Use constant-time comparison:

```python
# ✅ Good - Constant-time comparison
import hmac

if hmac.compare_digest(password, stored_password):
    return True

# ✅ Good - Using secrets module
import secrets

if secrets.compare_digest(token, expected_token):
    authenticate()
```

---

## 13. LDAP Injection

**Severity**: HIGH  
**OWASP**: ASVS-5.3.7  
**CWE**: CWE-90

### Description

Detects LDAP queries that may be vulnerable to injection attacks.

### Detected Patterns

```python
# ❌ Bad - LDAP injection
import ldap
filter_str = f"(uid={username})"
results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```

### Recommendation

Escape LDAP special characters:

```python
# ✅ Good - Proper escaping
import ldap
from ldap.filter import escape_filter_chars

safe_username = escape_filter_chars(username)
filter_str = f"(uid={safe_username})"
results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```

---

## 14. NoSQL Injection

**Severity**: HIGH  
**OWASP**: ASVS-5.3.4  
**CWE**: CWE-943

### Description

Detects NoSQL (MongoDB) queries vulnerable to injection attacks.

### Detected Patterns

```python
# ❌ Bad - NoSQL injection
from pymongo import MongoClient
query = f"{{'username': '{user_input}'}}"
result = collection.find(query)
```

### Recommendation

Use parameterized queries:

```python
# ✅ Good - Parameterized query
from pymongo import MongoClient
query = {'username': user_input}
result = collection.find(query)

# ✅ Good - With validation
def validate_username(username):
    if not username.isalnum():
        raise ValueError("Invalid username")
    return username

safe_username = validate_username(user_input)
query = {'username': safe_username}
result = collection.find(query)
```

---

## 15. CSV Injection (Formula Injection)

**Severity**: MEDIUM  
**OWASP**: ASVS-5.2.2  
**CWE**: CWE-1236

### Description

Detects potential CSV injection vulnerabilities where cells starting with special characters can execute formulas.

### Detected Patterns

```python
# ❌ Bad - CSV injection
import csv
data = [user_input]
writer.writerow(data)  # If user_input starts with =, +, -, @
```

### Recommendation

Sanitize CSV data:

```python
# ✅ Good - Sanitize CSV cells
import csv

def sanitize_csv_value(value):
    if value and value[0] in ['=', '+', '-', '@']:
        return "'" + value
    return value

data = [sanitize_csv_value(user_input)]
writer.writerow(data)
```

---

## 16. Insecure Temporary Files

**Severity**: HIGH  
**OWASP**: ASVS-12.3.2  
**CWE**: CWE-377

### Description

Detects usage of deprecated and insecure `tempfile.mktemp()`.

### Detected Patterns

```python
# ❌ Bad - Race condition vulnerability
import tempfile
temp_path = tempfile.mktemp()
```

### Recommendation

Use secure alternatives:

```python
# ✅ Good - Secure temp file
import tempfile

# Option 1: TemporaryFile (auto-deleted)
with tempfile.TemporaryFile() as f:
    f.write(b'data')

# Option 2: NamedTemporaryFile
with tempfile.NamedTemporaryFile(delete=False) as f:
    temp_path = f.name
    f.write(b'data')

# Option 3: mkstemp (returns file descriptor)
fd, temp_path = tempfile.mkstemp()
with os.fdopen(fd, 'w') as f:
    f.write('data')
```

---

## 17. Format String Vulnerabilities

**Severity**: MEDIUM  
**OWASP**: ASVS-5.2.8  
**CWE**: CWE-134

### Description

Detects dynamic format strings that can lead to information disclosure.

### Detected Patterns

```python
# ❌ Bad - Format string vulnerability
fmt = user_input
message = fmt.format(data)
```

### Recommendation

Use safe formatting:

```python
# ✅ Good - F-strings with explicit values
name = user_input
message = f"Hello, {name}"

# ✅ Good - Template strings
from string import Template
template = Template("Hello, $name")
message = template.substitute(name=user_input)

# ✅ Good - Fixed format string
message = "Hello, {}".format(sanitized_input)
```

---

## Summary of v0.3.0 Enhancements

PyGuard v0.3.0 now detects **20+ security vulnerability categories**:

**Injection Attacks (9 types):**
- Code Injection (eval/exec)
- SQL Injection
- Command Injection
- XXE Injection
- LDAP Injection
- NoSQL Injection
- CSV Injection
- Format String
- Path Traversal

**Cryptography & Authentication (3 types):**
- Weak Cryptography
- Weak Random
- Timing Attacks

**Deserialization & Data (2 types):**
- Unsafe Deserialization (YAML, Pickle)
- Hardcoded Credentials

**Network & File Security (4 types):**
- SSRF
- Insecure HTTP
- Insecure Temp Files
- Path Traversal

**Coverage:** All mapped to OWASP ASVS v5.0 and CWE Top 25 standards.
