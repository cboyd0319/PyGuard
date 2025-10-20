# PyGuard Git Hooks Demo

This example demonstrates how to set up and use PyGuard git hooks in your project.

## Installation

### Step 1: Install PyGuard

```bash
# PyGuard is not yet on PyPI - install from source
```

### Step 2: Install Pre-commit Hook

```bash
# Navigate to your repository
cd /path/to/your/project

# Install the pre-commit hook
pyguard-hooks install

# Verify installation
pyguard-hooks validate
```

## Usage Example

### Normal Workflow

```bash
# Make changes to your code
vim myproject/module.py

# Stage your changes
git add myproject/module.py

# Commit (PyGuard runs automatically)
git commit -m "Add new feature"

# Output:
# Running PyGuard security and quality checks...
# Scanning: myproject/module.py
# ✓ PyGuard checks passed
```

### When Issues Are Found

```bash
# Let's say you have a file with security issues
cat > vulnerable.py << 'EOF'
import os

def execute_command(user_input):
    # Security issue: command injection vulnerability
    os.system("ls " + user_input)
    
def get_user(user_id):
    # Security issue: SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
EOF

# Stage the file
git add vulnerable.py

# Try to commit
git commit -m "Add user functions"

# Output:
# Running PyGuard security and quality checks...
# 
# ❌ HIGH: Command injection vulnerability (line 5)
# Issue: Concatenating user input with system command
# Fix: Use subprocess.run() with a list of arguments
# 
# ❌ HIGH: SQL injection vulnerability (line 9)  
# Issue: String concatenation in SQL query
# Fix: Use parameterized queries
# 
# PyGuard found issues. Fix them before committing.
# To skip this check, use: git commit --no-verify
```

### Fixing the Issues

```bash
# Fix the security issues
cat > vulnerable.py << 'EOF'
import subprocess

def execute_command(user_input):
    # Fixed: Using subprocess with argument list
    subprocess.run(["ls", user_input], check=True)
    
def get_user(user_id):
    # Fixed: Using parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
EOF

# Stage and commit again
git add vulnerable.py
git commit -m "Fix security vulnerabilities"

# Output:
# Running PyGuard security and quality checks...
# ✓ PyGuard checks passed
```

## Advanced Features

### Install Pre-push Hook

```bash
# Install pre-push hook for comprehensive checks
pyguard-hooks install --type pre-push

# This runs a full codebase scan before pushing
git push origin main
```

### List Installed Hooks

```bash
pyguard-hooks list

# Output:
# Found 2 installed hooks:
#   ✓ pre-commit (executable)
#     Path: .git/hooks/pre-commit
#   ✓ pre-push (executable)
#     Path: .git/hooks/pre-push
```

### Test Hooks

```bash
# Test pre-commit hook
pyguard-hooks test --type pre-commit

# Test pre-push hook
pyguard-hooks test --type pre-push
```

### Emergency Bypass

```bash
# In emergencies, you can bypass the hook
git commit --no-verify -m "Emergency hotfix"

# But use this sparingly!
```

### Uninstall Hooks

```bash
# Remove pre-commit hook
pyguard-hooks uninstall

# Remove pre-push hook
pyguard-hooks uninstall --type pre-push
```

## Integration with pre-commit Framework

If you use the [pre-commit](https://pre-commit.com/) framework, add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cboyd0319/PyGuard
    rev: v0.3.0
    hooks:
      - id: pyguard
        name: PyGuard Security & Quality Analysis
      - id: pyguard-security
        name: PyGuard Security Only
```

Then install:

```bash
pre-commit install
```

## CI/CD Complement

Git hooks are great for catching issues locally, but always complement with CI/CD:

### GitHub Actions Example

```yaml
name: PyGuard Check

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install PyGuard
        run: # PyGuard is not yet on PyPI - install from source
      
      - name: Run PyGuard
        run: pyguard --scan-only .
```

## Best Practices

1. **Start Simple**: Begin with pre-commit hooks only
2. **Educate Team**: Make sure everyone knows about the hooks
3. **Document Bypass**: Let team know when `--no-verify` is acceptable
4. **Keep Updated**: Regularly update PyGuard for latest checks
5. **Combine Approaches**: Use hooks locally + CI/CD remotely

## Troubleshooting

### Hook Not Running

```bash
# Check installation
pyguard-hooks validate

# Check if executable
ls -la .git/hooks/pre-commit

# Make executable if needed
chmod +x .git/hooks/pre-commit
```

### PyGuard Not Found

```bash
# Make sure PyGuard is installed
# PyGuard is not yet on PyPI - install from source

# Check if in PATH
which pyguard
```

### Hook Too Slow

```bash
# Use security-only mode for faster checks
# Edit .git/hooks/pre-commit and change:
pyguard --security-only --scan-only $STAGED_FILES
```

## Real-World Example

Here's a complete example of setting up PyGuard hooks in a new project:

```bash
# Create new project
mkdir myproject
cd myproject

# Initialize git
git init

# Create Python virtual environment
python -m venv venv
source venv/bin/activate

# Install PyGuard
# PyGuard is not yet on PyPI - install from source

# Install pre-commit hook
pyguard-hooks install

# Create a sample Python file
cat > app.py << 'EOF'
def main():
    print("Hello, World!")

if __name__ == "__main__":
    main()
EOF

# Add and commit
git add app.py
git commit -m "Initial commit"

# Output:
# Running PyGuard security and quality checks...
# ✓ PyGuard checks passed

# Success! Your project now has automated quality checks
```

## Conclusion

PyGuard git hooks provide:
- ✅ Automatic security and quality checks
- ✅ Immediate feedback during development
- ✅ Prevention of problematic code reaching repository
- ✅ Easy installation and management
- ✅ Team-wide consistency

For more information, see:
- [Git Hooks Guide](../guides/git-hooks-guide.md)
- [Documentation Hub](../index.md)
- [Security Rules Reference](../reference/security-rules.md)
