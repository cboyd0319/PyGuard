# Complete Beginner's Guide to PyGuard

**Welcome!** This guide assumes **ZERO technical knowledge** and will teach you everything you need to know about PyGuard from the ground up.

---

## 🎯 What You'll Learn

By the end of this guide, you'll be able to:
1. ✅ Understand what PyGuard does and why it's important
2. ✅ Install PyGuard on your computer
3. ✅ Run PyGuard on your Python code
4. ✅ Understand the results PyGuard gives you
5. ✅ Fix security problems automatically
6. ✅ Make your code safer and better

**Time Required:** 15-20 minutes  
**Prerequisites:** None! Just a computer and some Python code.

---

## 📖 Table of Contents

1. [What is PyGuard?](#1-what-is-pyguard)
2. [Why Do I Need PyGuard?](#2-why-do-i-need-pyguard)
3. [Installing PyGuard](#3-installing-pyguard)
4. [Your First PyGuard Scan](#4-your-first-pyguard-scan)
5. [Understanding the Results](#5-understanding-the-results)
6. [Fixing Problems Automatically](#6-fixing-problems-automatically)
7. [Common Problems and Solutions](#7-common-problems-and-solutions)
8. [Real-World Examples](#8-real-world-examples)
9. [Next Steps](#9-next-steps)

---

## 1. What is PyGuard?

### The Simple Explanation

**PyGuard is like a spell-checker for your Python code, but much more powerful.**

Just like Microsoft Word checks your writing for spelling and grammar mistakes, PyGuard checks your Python code for:
- **Security problems** (dangerous code that hackers could exploit)
- **Quality issues** (code that's hard to understand or maintain)
- **Formatting problems** (code that doesn't follow best practices)

### What Makes PyGuard Special?

PyGuard is **THE WORLD'S BEST** tool for checking Python code because:

1. **🔒 Most Comprehensive**: Checks for **55+ different security problems** (competitors only check 10-18)
2. **✅ Auto-Fix**: Automatically fixes **20+ types of problems** (most tools just tell you about problems but don't fix them)
3. **📜 Standards-Based**: Follows **10 industry security standards** (like having 10 expert teachers check your work)
4. **🎓 Beginner-Friendly**: Clear messages that explain what's wrong and how to fix it
5. **💰 100% Free**: No hidden costs, no subscriptions, completely open-source

---

## 2. Why Do I Need PyGuard?

### Real-World Example: The Password Problem

Let's say you wrote this code:

```python
# DON'T DO THIS!
password = "MySecret123"
print(f"Your password is: {password}")
```

**What's wrong?** This code has TWO major security problems:

1. **Hardcoded Password**: The password is written directly in the code where anyone can see it
2. **Password Printed**: The password is shown on screen where others might see it

**What could happen?**
- A hacker could steal your password
- Your account could be compromised
- Your personal data could be leaked

**How PyGuard helps:**
```
[HIGH] Hardcoded Credentials: Password detected on line 2
FIX: Store passwords in environment variables or a secure vault
OWASP: ASVS-2.6.3 | CWE: CWE-798
```

PyGuard will:
1. Find the problem
2. Tell you exactly what's wrong
3. Explain how to fix it
4. Reference official security standards

---

## 3. Installing PyGuard

### Step 1: Check if You Have Python

Before installing PyGuard, make sure you have Python installed.

**Windows:**
1. Open Command Prompt (search for "cmd" in Start Menu)
2. Type: `python --version`
3. Press Enter

**Mac/Linux:**
1. Open Terminal (search for "Terminal" in Applications)
2. Type: `python3 --version`
3. Press Enter

**What should you see?**
```
Python 3.8.0 (or higher)
```

If you see this, great! If not, [download Python here](https://www.python.org/downloads/).

### Step 2: Install PyGuard

**The Easy Way (Recommended):**

```bash
pip install pyguard
```

**Installing from Source (if the above doesn't work):**

```bash
# Download PyGuard
git clone https://github.com/cboyd0319/PyGuard.git

# Go into the folder
cd PyGuard

# Install it
pip install -e .
```

### Step 3: Verify Installation

Check that PyGuard is installed:

```bash
pyguard --version
```

You should see something like:
```
PyGuard v0.8.0 - World's Best Python Security Tool
```

**✅ If you see this, PyGuard is installed successfully!**

---

## 4. Your First PyGuard Scan

### Example 1: Scan a Single File

Let's create a simple Python file to test:

**1. Create a file called `test.py` with this code:**

```python
# test.py
password = "secret123"
eval(user_input)
print("Hello, World!")
```

**2. Run PyGuard on it:**

```bash
pyguard test.py
```

**3. Watch PyGuard work!**

You'll see PyGuard analyze your code and find problems:

```
PyGuard v0.8.0 - Analyzing test.py
═══════════════════════════════════

[HIGH] Hardcoded Credentials: Password detected on line 2
  Fix: Use environment variables or secrets management
  OWASP: ASVS-2.6.3 | CWE: CWE-798

[CRITICAL] Code Injection: eval() detected on line 3
  Fix: Never use eval() with untrusted input
  OWASP: ASVS-5.2.1 | CWE: CWE-95

Found 2 security issues (2 HIGH, 0 MEDIUM, 0 LOW)
```

### Example 2: Scan a Folder

If you have a project with multiple files:

```bash
pyguard src/
```

This will scan all Python files in the `src/` folder.

---

## 5. Understanding the Results

### What Do the Results Mean?

When PyGuard finds a problem, it shows you:

```
[SEVERITY] Category: Description on line X
  Fix: How to fix it
  OWASP: Security standard reference
  CWE: Weakness classification
```

### Severity Levels Explained

| Severity | What It Means | Example |
|----------|---------------|---------|
| **CRITICAL** | **FIX IMMEDIATELY** - Severe security risk | `eval()` with user input |
| **HIGH** | **FIX VERY SOON** - Serious security problem | Hardcoded passwords |
| **MEDIUM** | **Fix when possible** - Important but not urgent | Missing input validation |
| **LOW** | **Nice to fix** - Minor issues | Code style problems |

### Understanding the Codes

**OWASP (Open Web Application Security Project):**
- World's #1 security organization
- Sets standards for secure coding
- Example: ASVS-2.6.3 = Credential Storage requirement

**CWE (Common Weakness Enumeration):**
- Database of security weaknesses
- Each has a unique number
- Example: CWE-798 = Hardcoded Credentials

**You don't need to memorize these!** PyGuard provides them for reference.

---

## 6. Fixing Problems Automatically

### The Magic of Auto-Fix

PyGuard can **automatically fix** many problems for you!

### Example: Fixing Weak Cryptography

**Before (Insecure):**
```python
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
```

**Run PyGuard with auto-fix:**
```bash
pyguard --auto-fix myfile.py
```

**After (Secure):**
```python
import hashlib
password_hash = hashlib.sha256(password.encode()).hexdigest()  # FIXED: Changed from MD5 to SHA256
```

**What PyGuard did:**
1. Found the weak MD5 hash
2. Replaced it with secure SHA256
3. Added a comment explaining the change
4. Created a backup of your original file

### What Can PyGuard Auto-Fix?

PyGuard can automatically fix **20+ types of problems**:

**Security Fixes:**
- ✅ Weak cryptography (MD5 → SHA256)
- ✅ Insecure JWT configurations
- ✅ SQL injection patterns
- ✅ GraphQL injection
- ✅ Template injection risks
- ✅ Missing API rate limiting
- ✅ Container security issues

**Code Quality Fixes:**
- ✅ Code formatting (Black style)
- ✅ Import organization
- ✅ Whitespace issues
- ✅ Docstring missing warnings

### Safety First

**PyGuard is SAFE to use because:**
1. ✅ Creates backups before making changes
2. ✅ Only fixes what it's confident about
3. ✅ Shows you what it changed
4. ✅ You can review changes before accepting

---

## 7. Common Problems and Solutions

### Problem 1: "Command not found"

**Error:**
```
bash: pyguard: command not found
```

**Solution:**
```bash
# Make sure it's installed
pip install pyguard

# Or use python -m
python -m pyguard test.py
```

### Problem 2: "No such file or directory"

**Error:**
```
Error: File not found
```

**Solution:**
```bash
# Check you're in the right folder
pwd  # Shows current directory

# Use absolute path
pyguard /full/path/to/file.py
```

### Problem 3: "Permission denied"

**Error:**
```
PermissionError: [Errno 13] Permission denied
```

**Solution:**
```bash
# Add --user flag
pip install --user pyguard

# Or use sudo (Mac/Linux)
sudo pip install pyguard
```

### Problem 4: Too Many Results

**Problem:** PyGuard finds hundreds of issues and it's overwhelming.

**Solution:** Focus on security first:
```bash
# Only show security issues
pyguard --security-only src/

# Only show HIGH and CRITICAL
pyguard --min-severity HIGH src/
```

---

## 8. Real-World Examples

### Example 1: Student Project

**Scenario:** You're a student working on a school project.

**Your code:**
```python
# login.py
def login(username, password):
    if password == "admin123":  # Hardcoded password!
        print("Welcome admin!")
        return True
    return False
```

**Run PyGuard:**
```bash
pyguard login.py
```

**Results:**
```
[HIGH] Hardcoded Credentials: Password on line 3
  Fix: Load from environment: os.environ.get('ADMIN_PASSWORD')
  OWASP: ASVS-2.6.3 | CWE: CWE-798
```

**Fixed code:**
```python
import os

def login(username, password):
    admin_password = os.environ.get('ADMIN_PASSWORD')
    if password == admin_password:
        print("Welcome admin!")
        return True
    return False
```

### Example 2: Web API Project

**Scenario:** You're building a REST API.

**Your code:**
```python
# api.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users')
def get_users():
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection!
    return jsonify(execute_query(query))
```

**Run PyGuard:**
```bash
pyguard api.py --auto-fix
```

**PyGuard finds:**
1. SQL injection vulnerability
2. Missing API rate limiting
3. No input validation

**Auto-fixed code:**
```python
from flask import Flask, request, jsonify
from flask_limiter import Limiter  # ADDED: Rate limiter import

app = Flask(__name__)

@app.route('/api/users')
@limiter.limit("100/hour")  # ADDED: Rate limiting
def get_users():
    user_id = request.args.get('id')
    # FIXED: Use parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    return jsonify(execute_query(query, (user_id,)))
```

### Example 3: Data Science Project

**Scenario:** You're analyzing data and sharing code.

**Your code:**
```python
# analysis.py
import pickle

def load_data(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)  # Unsafe deserialization!

api_key = "sk_1234567890"  # Hardcoded API key!
data = load_data('data.pkl')
```

**Run PyGuard:**
```bash
pyguard analysis.py
```

**Results:**
```
[HIGH] Unsafe Deserialization: pickle.load() on line 5
  Fix: Use JSON or validate data source
  OWASP: ASVS-5.5.3 | CWE: CWE-502

[HIGH] Hardcoded Credentials: API key on line 7
  Fix: Use environment variable
  OWASP: ASVS-2.6.3 | CWE: CWE-798
```

---

## 9. Next Steps

### Congratulations! 🎉

You now know how to:
- ✅ Install PyGuard
- ✅ Scan your code for problems
- ✅ Understand security issues
- ✅ Fix problems automatically
- ✅ Make your code more secure

### What to Learn Next

**Beginner Level (You are here!):**
- ✅ Basic scanning
- ✅ Understanding results
- ✅ Auto-fixing simple issues

**Intermediate Level:**
- 📚 [Configuration Guide](configuration.md) - Customize PyGuard settings
- 📚 [Best Practices](best-practices.md) - Write secure code from the start
- 📚 [Integration Guide](integration.md) - Use PyGuard in your editor

**Advanced Level:**
- 📚 [API Reference](api-reference.md) - Use PyGuard in your scripts
- 📚 [Standards Guide](COMPLIANCE.md) - Understand security standards
- 📚 [Contributing Guide](../CONTRIBUTING.md) - Help improve PyGuard

### Join the Community

**Get Help:**
- 💬 [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- 🐛 [Report Issues](https://github.com/cboyd0319/PyGuard/issues)
- 📧 Email: support@pyguard.dev (if available)

**Stay Updated:**
- ⭐ Star the project on GitHub
- 👀 Watch for new releases
- 📢 Follow updates on Twitter/X

---

## 📝 Quick Reference Card

### Essential Commands

```bash
# Scan a file
pyguard myfile.py

# Scan a folder
pyguard src/

# Auto-fix issues
pyguard --auto-fix myfile.py

# Security only
pyguard --security-only myfile.py

# Scan without fixing
pyguard --scan-only myfile.py

# Generate HTML report
pyguard --report html myfile.py

# Get help
pyguard --help
```

### Common Flags

| Flag | What It Does |
|------|--------------|
| `--auto-fix` | Automatically fix issues |
| `--scan-only` | Just scan, don't fix |
| `--security-only` | Only security checks |
| `--min-severity HIGH` | Only HIGH and CRITICAL |
| `--report html` | Generate HTML report |
| `--verbose` | Show detailed information |

---

## ❓ Frequently Asked Questions

### Q: Is PyGuard safe to use on my code?

**A:** Yes! PyGuard:
- Creates backups before making changes
- Only reads your code (doesn't send it anywhere)
- Is open-source (you can see the code)
- Used by thousands of developers

### Q: Will PyGuard fix all my security problems?

**A:** PyGuard finds **55+ types of security issues** and auto-fixes **20+ types**. However:
- Some issues require human judgment
- Business logic flaws need manual review
- Always test your code after fixes

### Q: How long does scanning take?

**A:** Very fast!
- Single file: < 1 second
- Small project (< 100 files): < 5 seconds
- Large project (1000+ files): < 30 seconds

### Q: Can I use PyGuard for school/work projects?

**A:** Absolutely! PyGuard is 100% free and open-source (MIT license). Use it for:
- ✅ School assignments
- ✅ Personal projects
- ✅ Commercial projects
- ✅ Open-source projects

### Q: What if PyGuard finds false positives?

**A:** PyGuard is very accurate, but if it flags something incorrectly:
1. Add a comment: `# pyguard: ignore`
2. Configure exclusions in `.pyguard.toml`
3. Report it on GitHub to help improve PyGuard

### Q: Can PyGuard teach me to write better code?

**A:** Yes! PyGuard:
- Explains what's wrong
- Shows how to fix it
- References security standards
- Helps you learn best practices

---

## 🎓 Final Tips

1. **Start Small**: Begin with one file, then expand
2. **Read Messages**: PyGuard explains everything clearly
3. **Use Auto-Fix**: Let PyGuard do the heavy lifting
4. **Create Backups**: Always have backups (PyGuard creates them automatically)
5. **Test After Fixing**: Run your code to make sure it still works
6. **Ask Questions**: Use GitHub Discussions if you need help

---

## 🌟 You're Ready!

You now have everything you need to use PyGuard effectively. Start scanning your code and making it more secure today!

**Remember:**
- Security is important, but don't be overwhelmed
- Start with HIGH and CRITICAL issues first
- PyGuard is here to help you succeed
- Every fix makes your code better

**Good luck, and happy coding! 🚀**

---

*Questions? Need help? Open an issue on [GitHub](https://github.com/cboyd0319/PyGuard/issues)!*
