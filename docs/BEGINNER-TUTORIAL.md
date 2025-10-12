# PyGuard Beginner Tutorial

**For Users with ZERO Technical Knowledge**

Welcome! This tutorial will teach you how to use PyGuard to make your Python code more secure and higher quality, even if you've never used a security tool before.

---

## 📖 Table of Contents

1. [What is PyGuard?](#what-is-pyguard)
2. [Why Should I Use It?](#why-should-i-use-it)
3. [Installation](#installation)
4. [Your First Scan](#your-first-scan)
5. [Understanding the Results](#understanding-the-results)
6. [Fixing Issues](#fixing-issues)
7. [Advanced Usage](#advanced-usage)
8. [Common Problems & Solutions](#common-problems--solutions)
9. [Getting Help](#getting-help)

---

## What is PyGuard?

PyGuard is a **security and quality checker** for Python code. Think of it like a spell-checker, but instead of finding typos in your writing, it finds:
- **Security vulnerabilities** (places hackers could attack)
- **Code quality issues** (ways to make your code better)
- **Best practice violations** (not following Python conventions)

### Real-World Example
Imagine you're writing code for an online store. PyGuard can find:
- ❌ Passwords written directly in code (hackers could find them!)
- ❌ Weak encryption that hackers can break
- ❌ Injection vulnerabilities that let attackers run malicious code
- ❌ Missing security checks that expose customer data

---

## Why Should I Use It?

### Without PyGuard
```python
# This looks fine... but it's VERY dangerous!
password = "myPassword123"  # ❌ Hardcoded password
user_query = "SELECT * FROM users WHERE id = " + user_id  # ❌ SQL injection
data = eval(user_input)  # ❌ Code injection
```

### With PyGuard
PyGuard will immediately tell you:
```
⚠️  [HIGH] Hardcoded Credentials on line 2
⚠️  [HIGH] SQL Injection on line 3
⚠️  [HIGH] Code Injection on line 4
```

**Result**: You fix the issues before hackers find them!

---

## Installation

### Step 1: Check Python Version
First, make sure you have Python 3.8 or newer:

```bash
python --version
```

If you see `Python 3.8.x` or higher, you're good! If not, download Python from [python.org](https://python.org).

### Step 2: Install PyGuard
Open your terminal (Command Prompt on Windows, Terminal on Mac/Linux) and type:

```bash
pip install pyguard
```

**What if it doesn't work?**
- Try `pip3 install pyguard` instead
- Try `python -m pip install pyguard`
- Make sure you have administrator/sudo rights

### Step 3: Verify Installation
Check that PyGuard is installed:

```bash
pyguard --version
```

You should see something like `PyGuard v0.6.0`.

---

## Your First Scan

Let's start with a simple example!

### Step 1: Create a Test File
Create a new file called `test.py` with this code:

```python
# test.py
password = "admin123"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return query

def process_data(user_input):
    result = eval(user_input)
    return result
```

### Step 2: Run PyGuard
In your terminal, run:

```bash
pyguard test.py
```

### Step 3: See the Results
PyGuard will show you something like:

```
======================================================================
                    PyGuard Analysis Summary                          
======================================================================

▶ Files Processed
----------------------------------------------------------------------
  Total files.............................................. 1
  Files analyzed........................................... 1
  Files with issues........................................ 1

▶ Issues Detected
----------------------------------------------------------------------
  [HIGH] Hardcoded Credentials: Line 2
  [HIGH] SQL Injection: Line 5
  [HIGH] Code Injection: Line 9

⚠️  3 security issues found
```

**Congratulations!** You just ran your first security scan!

---

## Understanding the Results

Let's break down what PyGuard tells you:

### Issue Severity

| Severity | Meaning | Should You Fix It? |
|----------|---------|-------------------|
| **HIGH** | 🚨 Critical security vulnerability | **YES, IMMEDIATELY** |
| **MEDIUM** | ⚠️ Important issue, should be fixed | **Yes, soon** |
| **LOW** | ℹ️ Minor issue or best practice | When you have time |

### Common Issue Types

#### 1. Hardcoded Credentials
**What it means:** Passwords or API keys written directly in code.

```python
# ❌ BAD - Anyone can see this!
password = "mySecret123"
api_key = "sk_live_abc123xyz"

# ✅ GOOD - Use environment variables
import os
password = os.environ.get('DATABASE_PASSWORD')
api_key = os.environ.get('API_KEY')
```

**Why it's dangerous:** If you share your code (GitHub, etc.), everyone can see your passwords!

#### 2. SQL Injection
**What it means:** Attackers can run their own database commands.

```python
# ❌ BAD - Attacker can inject malicious SQL
query = "SELECT * FROM users WHERE id = " + user_id

# ✅ GOOD - Use parameterized queries
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

**Why it's dangerous:** Attackers could:
- Delete your entire database
- Steal all user data
- Create admin accounts

#### 3. Code Injection
**What it means:** Attackers can run their own Python code.

```python
# ❌ BAD - Extremely dangerous!
result = eval(user_input)

# ✅ GOOD - Use safe alternatives
import json
result = json.loads(user_input)  # For JSON data
# Or validate input first
```

**Why it's dangerous:** Attackers could:
- Take over your entire system
- Install malware
- Steal sensitive data

#### 4. Weak Cryptography
**What it means:** Using outdated encryption methods.

```python
# ❌ BAD - MD5 is broken!
import hashlib
hash = hashlib.md5(password.encode())

# ✅ GOOD - Use modern algorithms
hash = hashlib.sha256(password.encode())
```

**Why it's dangerous:** Attackers can easily crack weak encryption.

---

## Fixing Issues

PyGuard not only finds issues but tells you how to fix them!

### Example 1: Fix Hardcoded Password

**Before:**
```python
database_password = "myDBpass123"
```

**After:**
```python
import os
database_password = os.getenv('DATABASE_PASSWORD')
```

**How to set environment variable:**
```bash
# On Linux/Mac
export DATABASE_PASSWORD="myDBpass123"

# On Windows (Command Prompt)
set DATABASE_PASSWORD=myDBpass123

# On Windows (PowerShell)
$env:DATABASE_PASSWORD="myDBpass123"
```

### Example 2: Fix SQL Injection

**Before:**
```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
```

**After:**
```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
```

### Example 3: Fix Code Injection

**Before:**
```python
def calculate(expression):
    result = eval(expression)  # DANGEROUS!
    return result
```

**After:**
```python
def calculate(expression):
    # Validate input first
    allowed_chars = set('0123456789+-*/(). ')
    if not all(c in allowed_chars for c in expression):
        raise ValueError("Invalid input")
    
    # Use safer alternative
    import ast
    result = ast.literal_eval(expression)
    return result
```

---

## Advanced Usage

### Scan Entire Project
Instead of one file, scan your entire project:

```bash
pyguard src/
```

### Scan Only (Don't Auto-Fix)
Just see the issues without making changes:

```bash
pyguard src/ --scan-only
```

### Security Issues Only
Focus on security, skip quality checks:

```bash
pyguard src/ --security-only
```

### Generate a Report
Create an HTML report you can share:

```bash
pyguard src/ --report html --output security-report.html
```

Then open `security-report.html` in your web browser to see a beautiful, detailed report!

### Ignore Specific Issues
Sometimes you have a good reason to ignore an issue:

```python
# pyguard: ignore[hardcoded-credentials]
TEST_PASSWORD = "test123"  # Only used in tests
```

---

## Common Problems & Solutions

### Problem 1: "Command not found: pyguard"
**Solution:** PyGuard isn't in your PATH. Try:
```bash
python -m pyguard test.py
```

### Problem 2: "No module named pyguard"
**Solution:** PyGuard isn't installed. Try:
```bash
pip install --user pyguard
```

### Problem 3: "Permission denied"
**Solution:** You need administrator rights. Try:
```bash
sudo pip install pyguard  # On Mac/Linux
# Or run Command Prompt as Administrator on Windows
```

### Problem 4: Too Many Issues!
**Solution:** Start small! Fix HIGH severity issues first:
```bash
pyguard test.py --security-only
```

Then gradually address MEDIUM and LOW issues.

### Problem 5: False Positives
Sometimes PyGuard flags code that's actually safe. You can:

1. **Ignore the specific line:**
   ```python
   # pyguard: ignore[sql-injection]
   query = safe_query_builder(user_id)
   ```

2. **Report it:** File an issue on GitHub so we can improve detection!

---

## Real-World Tutorial: Securing a Flask App

Let's walk through securing a real Flask web application!

### Step 1: Initial Code
```python
# app.py - INSECURE VERSION
from flask import Flask, request
import sqlite3

app = Flask(__name__)
DATABASE_PASSWORD = "admin123"  # ❌

@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # ❌ SQL Injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
    user = cursor.fetchone()
    return f"User: {user}"

@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # ❌ Code Injection vulnerability
    result = eval(expression)
    return f"Result: {result}"

if __name__ == '__main__':
    app.run(debug=True)  # ❌ Debug mode in production
```

### Step 2: Run PyGuard
```bash
pyguard app.py
```

### Step 3: Review Issues
```
⚠️  [HIGH] Hardcoded Credentials: Line 6
⚠️  [HIGH] SQL Injection: Line 13
⚠️  [HIGH] Code Injection: Line 21
⚠️  [MEDIUM] Debug Mode Enabled: Line 26
```

### Step 4: Fix All Issues
```python
# app.py - SECURE VERSION
from flask import Flask, request
import sqlite3
import os
import ast

app = Flask(__name__)

# ✅ Use environment variable
DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')

@app.route('/user/<int:user_id>')  # ✅ Type validation
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # ✅ Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    user = cursor.fetchone()
    return f"User: {user}"

@app.route('/calculate')
def calculate():
    expression = request.args.get('expr', '')
    
    # ✅ Validate input
    if not expression or len(expression) > 100:
        return "Invalid input", 400
    
    # ✅ Use safe evaluation
    try:
        result = ast.literal_eval(expression)
        return f"Result: {result}"
    except (ValueError, SyntaxError):
        return "Invalid expression", 400

if __name__ == '__main__':
    # ✅ Debug disabled in production
    app.run(debug=False)
```

### Step 5: Verify Fixes
```bash
pyguard app.py
```

```
✅ No security issues found!
```

**Congratulations!** You've secured your first web application!

---

## Getting Help

### Documentation
- **User Guide**: [docs/user-guide.md](user-guide.md)
- **API Reference**: [docs/api-reference.md](api-reference.md)
- **FAQ**: [docs/FAQ.md](FAQ.md)

### Community
- **GitHub Issues**: [Report bugs or ask questions](https://github.com/cboyd0319/PyGuard/issues)
- **GitHub Discussions**: [Community forum](https://github.com/cboyd0319/PyGuard/discussions)
- **Examples**: [examples/](../examples/) - Working code samples

### Quick Tips
1. **Start small**: Scan one file first
2. **Fix HIGH issues first**: Focus on critical security problems
3. **Read the suggestions**: PyGuard tells you how to fix each issue
4. **Don't ignore everything**: Each ignored issue is a potential vulnerability
5. **Run regularly**: Make PyGuard part of your workflow

---

## Next Steps

Now that you know the basics:

1. ✅ Scan your own projects
2. ✅ Fix security issues one by one
3. ✅ Set up automatic scanning (see [CI/CD Integration](CI-CD-INTEGRATION.md))
4. ✅ Learn about advanced features (see [Advanced Usage](ADVANCED-USAGE.md))
5. ✅ Share with your team!

---

## Cheat Sheet

Quick reference for common commands:

```bash
# Basic scan
pyguard myfile.py

# Scan directory
pyguard src/

# Scan only (no fixes)
pyguard src/ --scan-only

# Security only
pyguard src/ --security-only

# Generate HTML report
pyguard src/ --report html --output report.html

# Generate JSON report
pyguard src/ --report json --output report.json

# Show version
pyguard --version

# Show help
pyguard --help
```

---

## Summary

You've learned:
- ✅ What PyGuard is and why it's important
- ✅ How to install and run PyGuard
- ✅ How to understand security issues
- ✅ How to fix common vulnerabilities
- ✅ How to use advanced features
- ✅ Where to get help

**Remember:** Security is a journey, not a destination. Keep scanning, keep learning, and keep your code secure!

---

**Questions?** Check out our [FAQ](FAQ.md) or ask in [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)!

**PyGuard: Making Python Security Accessible to Everyone** 🛡️
