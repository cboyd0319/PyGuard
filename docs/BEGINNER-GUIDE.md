# PyGuard Beginner's Guide

**Welcome to PyGuard!** This guide is designed for users with **zero technical knowledge**. We'll walk you through everything step-by-step.

---

## 📚 Table of Contents

1. [What is PyGuard?](#what-is-pyguard)
2. [Why Should I Use It?](#why-should-i-use-it)
3. [Installing PyGuard](#installing-pyguard)
4. [Your First Scan](#your-first-scan)
5. [Understanding the Results](#understanding-the-results)
6. [Fixing Issues Automatically](#fixing-issues-automatically)
7. [Common Questions](#common-questions)
8. [Getting Help](#getting-help)

---

## What is PyGuard?

PyGuard is like a **spell-checker for your Python code**, but instead of checking spelling, it:

- 🔒 **Finds security problems** that hackers could exploit
- ✨ **Improves code quality** to make your code easier to read and maintain
- 🎨 **Formats your code** to look professional and consistent
- 🤖 **Fixes issues automatically** (with your permission)

Think of it as having an expert programmer review your code 24/7!

---

## Why Should I Use It?

### Security 🔒
Without PyGuard, your code might have vulnerabilities (weak spots) that hackers can exploit. PyGuard finds and fixes these automatically.

**Example Problem PyGuard Finds:**
```python
# BAD: Hackers can inject malicious code here!
password = "mypassword123"  # Never hardcode passwords!
```

**PyGuard's Fix:**
```python
# GOOD: Password loaded from secure config
password = os.environ.get('PASSWORD')  # Safe!
```

### Code Quality ✨
PyGuard ensures your code follows best practices, making it:
- Easier to understand
- Easier to maintain
- Less likely to have bugs

### Time Savings ⏰
Instead of manually reviewing every line of code, PyGuard does it instantly!

---

## Installing PyGuard

### Step 1: Check if Python is Installed

**On Windows:**
1. Press `Windows Key + R`
2. Type `cmd` and press Enter
3. Type `python --version` and press Enter
4. You should see something like `Python 3.8.0` or higher

**On Mac:**
1. Press `Command + Space`
2. Type `terminal` and press Enter
3. Type `python3 --version` and press Enter
4. You should see something like `Python 3.8.0` or higher

**On Linux:**
1. Open Terminal
2. Type `python3 --version` and press Enter
3. You should see something like `Python 3.8.0` or higher

### Step 2: Install PyGuard

**Easy Installation (Recommended):**

1. Open your command line (see Step 1 above)
2. Copy and paste this command:

   ```bash
   pip install pyguard
   ```

3. Press Enter and wait for it to finish

**From Source (Advanced):**

If you want the latest development version:

```bash
git clone https://github.com/cboyd0319/PyGuard.git
cd PyGuard
pip install -e .
```

### Step 3: Verify Installation

Type this command:

```bash
pyguard --help
```

If you see a help message, you're all set! ✅

---

## Your First Scan

Let's scan your first Python file!

### Step 1: Create a Test File

Create a file named `test.py` with this code:

```python
# test.py - A simple Python file
password = "secret123"

def add_numbers(x, y):
    return x + y

result = add_numbers(5, 3)
print(result)
```

### Step 2: Run PyGuard

**Option A: Scan Only (No Changes)**

This just shows you problems without fixing them:

```bash
pyguard test.py --scan-only
```

**Option B: Scan and Fix Automatically**

This will find and fix issues:

```bash
pyguard test.py
```

### Step 3: Review the Output

You'll see something like:

```
======================================================================
                    PyGuard Analysis Summary                          
======================================================================

▶ Files Processed
----------------------------------------------------------------------
  Total files.............................................. 1
  Files with issues........................................ 1

▶ Issues Detected
----------------------------------------------------------------------
  Total issues............................................. 1
  Security issues.......................................... 1 [HIGH]

⚠️  Issues found:
  [HIGH] Hardcoded Credentials: password = "secret123"
    Line 2: Never store passwords directly in code
    Fix: Use environment variables or config files

✅ Want PyGuard to fix this? Run without --scan-only
```

---

## Understanding the Results

### Issue Severity Levels

PyGuard categorizes issues by severity:

| Severity | Icon | What It Means | Example |
|----------|------|---------------|---------|
| **CRITICAL** | 🔴 | Fix immediately! Can be exploited right now | `eval(user_input)` |
| **HIGH** | 🟠 | Fix very soon. Serious security risk | Hardcoded passwords |
| **MEDIUM** | 🟡 | Fix when possible. Could cause problems | Weak encryption |
| **LOW** | 🟢 | Fix eventually. Minor issues | Missing docstrings |

### Common Issues Explained

#### 1. Hardcoded Credentials 🔒

**What It Means:**
You put a password or API key directly in your code.

**Why It's Bad:**
Anyone who sees your code (like on GitHub) can steal your password.

**How PyGuard Fixes It:**
Adds a comment telling you to use environment variables instead.

**Example:**
```python
# Before:
api_key = "12345-SECRET-KEY"

# After (PyGuard adds comment):
api_key = "12345-SECRET-KEY"  # SECURITY: Move to environment variable
```

#### 2. SQL Injection 🔒

**What It Means:**
Your database queries could be manipulated by attackers.

**Why It's Bad:**
Hackers could steal, modify, or delete your entire database!

**How PyGuard Fixes It:**
Shows you how to use parameterized queries.

**Example:**
```python
# Before (DANGEROUS):
query = f"SELECT * FROM users WHERE name = '{user_name}'"

# After (SAFE):
query = "SELECT * FROM users WHERE name = ?"
cursor.execute(query, (user_name,))
```

#### 3. Code Injection 🔒

**What It Means:**
Using `eval()` or `exec()` with user input.

**Why It's Bad:**
Attackers can run ANY code on your system!

**How PyGuard Fixes It:**
Replaces with safe alternatives like `ast.literal_eval()`.

---

## Fixing Issues Automatically

### Step 1: Create a Backup

**Good News:** PyGuard automatically creates backups before making changes!

Backups are stored in `.pyguard_backups/` folder.

### Step 2: Run Auto-Fix

```bash
pyguard test.py
```

### Step 3: Review Changes

PyGuard shows you what changed:

```diff
--- test.py (before)
+++ test.py (after)
@@ -1,4 +1,4 @@
-password = "secret123"
+password = "secret123"  # SECURITY: Use environment variables
```

### Step 4: Restore If Needed

If you don't like the changes:

```bash
# List backups
ls .pyguard_backups/

# Restore from backup
cp .pyguard_backups/test.py.backup.20250112_143022 test.py
```

---

## Common Questions

### Q: Will PyGuard break my code?

**A:** No! PyGuard:
- Creates backups before any changes
- Only makes safe, tested fixes
- You can always restore from backup

### Q: How long does a scan take?

**A:** Very fast!
- 1 file: ~10-50 milliseconds
- 100 files: ~2-5 seconds
- 1000 files: ~30-60 seconds

### Q: What if I don't understand an issue?

**A:** Every issue includes:
- Plain English explanation
- Why it's a problem
- How to fix it
- Example code

You can also check our [detailed documentation](./user-guide.md).

### Q: Can I ignore certain issues?

**A:** Yes! Create a `.pyguardignore` file:

```
# Ignore test files
tests/*

# Ignore specific patterns
**/test_*.py
```

### Q: Is PyGuard free?

**A:** Yes! PyGuard is 100% free and open source under the MIT license.

### Q: Does PyGuard send my code anywhere?

**A:** No! PyGuard runs entirely on your computer. Your code never leaves your machine.

### Q: What programming languages does PyGuard support?

**A:** Currently only Python 3.8+. Support for other languages is planned.

---

## Getting Help

### 🆘 Need Help?

1. **Documentation**: Check our [User Guide](./user-guide.md)
2. **Examples**: See [examples/](../examples/) folder
3. **Issues**: Report bugs on [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
4. **Discussions**: Ask questions on [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)

### 📧 Contact

- **Email**: your.email@example.com
- **GitHub**: [@cboyd0319](https://github.com/cboyd0319)

---

## Quick Reference Card

### Essential Commands

```bash
# Scan a file (no changes)
pyguard file.py --scan-only

# Scan and fix a file
pyguard file.py

# Scan entire directory
pyguard src/

# Security checks only
pyguard file.py --security-only

# Show help
pyguard --help
```

### File Organization

```
your-project/
├── src/                    # Your code
├── .pyguard_backups/       # Automatic backups
├── .pyguardignore          # Files to ignore
├── pyguard.toml            # Configuration (optional)
└── pyguard-report.html     # Scan report
```

---

## Next Steps

Now that you understand the basics:

1. ✅ Scan your first project
2. 📖 Read the [User Guide](./user-guide.md) for advanced features
3. 🔧 Set up [Configuration](./configuration.md) for your needs
4. 🤝 Join our community on GitHub!

**Happy coding! 🚀**

---

<p align="center">
  <strong>PyGuard</strong> - The World's Best Python Code Quality Tool
  <br>
  Made with ❤️ by the PyGuard Team
</p>
