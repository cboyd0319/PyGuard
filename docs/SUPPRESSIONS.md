# PyGuard Suppression Guide

PyGuard supports inline suppression comments to handle false positives and intentional security patterns (like security tool code that contains vulnerability detection patterns).

## Suppression Syntax

### Generic Suppression (All Rules)
```python
eval("user_input")  # pyguard: disable
some_code()         # noqa
```

### Specific Rule Suppression
```python
eval("safe_literal")  # pyguard: disable=CWE-95
password == "test"    # noqa: CWE-208
```

### Multiple Rule Suppression
```python
exec(code)  # pyguard: disable=CWE-95,CWE-78
```

## When to Use Suppressions

### ✅ Appropriate Use Cases

1. **Security Tool Code**: Code that detects vulnerabilities but isn't itself vulnerable
   ```python
   # Detection pattern in security scanner - not actual vulnerable code
   if "eval(" in code:  # pyguard: disable=CWE-95
       report_vulnerability("Code Injection")
   ```

2. **False Positives**: When PyGuard incorrectly flags safe code
   ```python
   __author__ = "Jane Doe"  # pyguard: disable=CWE-798
   ```

3. **Test Code**: Intentionally vulnerable code for testing
   ```python
   def test_sql_injection_detection():
       vulnerable = f"SELECT * FROM users WHERE id = {user_id}"  # pyguard: disable=CWE-89
       assert scanner.detect(vulnerable)
   ```

4. **Acceptable Trade-offs**: When you've assessed the risk and decided it's acceptable
   ```python
   # Internal admin tool, input validated elsewhere
   result = subprocess.call(command)  # pyguard: disable=CWE-78
   ```

### ❌ Inappropriate Use Cases

1. **Avoiding Real Security Issues**: Don't suppress actual vulnerabilities
   ```python
   # BAD: This is a real security issue
   password = "hardcoded123"  # pyguard: disable
   ```

2. **Ignoring Code Quality**: Don't suppress quality issues without refactoring
   ```python
   # BAD: Fix the complexity instead
   def complex_function():  # pyguard: disable=COMPLEXITY
       # 500 lines of spaghetti code...
   ```

3. **Lazy Development**: Don't suppress issues to avoid proper fixes
   ```python
   # BAD: Use parameterized queries instead
   query = f"SELECT * FROM {table}"  # pyguard: disable
   ```

## Available Rule IDs

### Security Rules (CWE-*)
- `CWE-89`: SQL Injection
- `CWE-78`: Command Injection  
- `CWE-22`: Path Traversal
- `CWE-79`: Cross-Site Scripting (XSS)
- `CWE-95`: Code Injection (eval, exec)
- `CWE-208`: Timing Attack
- `CWE-327`: Weak Cryptography
- `CWE-330`: Insecure Random
- `CWE-502`: Unsafe Deserialization
- `CWE-798`: Hardcoded Credentials

### Code Quality Rules
- `COMPLEXITY`: High cyclomatic complexity
- `LONG-METHOD`: Method exceeds line limit
- `MAGIC-NUMBER`: Unnamed numeric literal
- `DOCUMENTATION`: Missing docstring
- `ERROR-HANDLING`: Broad exception catching

## Best Practices

1. **Document Why**: Add a comment explaining the suppression
   ```python
   # This is pattern matching code in a security scanner, not actual vulnerable code
   if "eval(" in source_code:  # pyguard: disable=CWE-95
       issues.append(SecurityIssue("Code Injection"))
   ```

2. **Be Specific**: Suppress only the specific rule, not all rules
   ```python
   # Good: Specific suppression
   password_check = pwd == user_input  # pyguard: disable=CWE-208
   
   # Bad: Generic suppression
   password_check = pwd == user_input  # noqa
   ```

3. **Regular Review**: Periodically review suppressions to ensure they're still valid
   ```python
   # TODO: Review this suppression after refactoring - 2025-10-15
   complex_code()  # pyguard: disable=COMPLEXITY
   ```

4. **Prefer Fixes**: Only suppress when fixing isn't feasible or appropriate
   ```python
   # Better: Fix the issue
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   
   # Instead of suppressing
   # cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # pyguard: disable
   ```

## Configuration

To exclude entire files or directories from scanning, use `pyguard.toml`:

```toml
[security]
exclude_patterns = [
    "*/tests/*",
    "*/test_*.py",
    "*_test.py",
    "*/fixtures/*"
]
```

## Compatibility

PyGuard's `# noqa` comments are compatible with other Python tools:
- flake8
- pylint  
- ruff
- mypy

Use `# noqa` for cross-tool compatibility, or `# pyguard: disable` for PyGuard-specific suppressions.

## Examples

### Security Scanner Code
```python
class SecurityScanner:
    def detect_sql_injection(self, code: str):
        """Detect SQL injection patterns."""
        # These are detection patterns, not vulnerable code
        if "execute(" in code and "%" in code:  # pyguard: disable=CWE-89
            return SecurityIssue("SQL Injection")
        if ".format(" in code and "SELECT" in code:  # pyguard: disable=CWE-89
            return SecurityIssue("SQL Injection")
```

### Test Code
```python
class TestSecurityScanner:
    def test_detects_sql_injection(self):
        """Test SQL injection detection."""
        # Intentionally vulnerable code for testing
        vulnerable_code = '''
        query = f"SELECT * FROM users WHERE id = {user_id}"  # pyguard: disable=CWE-89
        cursor.execute(query)
        '''
        
        scanner = SecurityScanner()
        issues = scanner.analyze(vulnerable_code)
        assert len(issues) > 0
```

### Machine Learning Constants
```python
# ML hyperparameters are not magic numbers
LEARNING_RATE = 0.001  # pyguard: disable=MAGIC-NUMBER
BATCH_SIZE = 32  # pyguard: disable=MAGIC-NUMBER
EPOCHS = 100  # pyguard: disable=MAGIC-NUMBER
```

## Reporting False Positives

If you find a false positive that shouldn't require suppression, please:
1. Document the pattern
2. Open an issue on GitHub
3. Provide a minimal reproduction example
4. Suggest how detection should be improved

This helps improve PyGuard for everyone!
