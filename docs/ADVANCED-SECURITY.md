# PyGuard Advanced Security Analysis

Comprehensive guide to PyGuard's advanced security detection capabilities that go beyond traditional static analysis.

## Overview

PyGuard's advanced security module provides cutting-edge vulnerability detection including:

- **Taint Tracking**: Data flow analysis from untrusted sources to dangerous sinks
- **ReDoS Detection**: Regular Expression Denial of Service vulnerabilities
- **Race Condition Detection**: Time-of-check to time-of-use (TOCTOU) issues
- **Integer Security**: Overflow and underflow vulnerability detection

## Standards Compliance

All advanced security features are aligned with industry standards:

- **OWASP ASVS v5.0**: Application Security Verification Standard
- **CWE Top 25**: Most Dangerous Software Weaknesses
- **NIST SSDF**: Secure Software Development Framework
- **SANS Top 25**: Most Dangerous Software Errors
- **MITRE ATT&CK**: Adversarial Tactics and Techniques

---

## Taint Tracking Analysis

### What is Taint Tracking?

Taint tracking follows untrusted data from its source (user input, network, files) through your code to detect when it reaches dangerous functions without proper validation or sanitization.

### Taint Sources

PyGuard tracks the following sources of untrusted data:

| Source | Type | Risk Level |
|--------|------|-----------|
| `input()` | User Input | HIGH |
| `sys.argv` | Command Line | HIGH |
| `os.environ` | Environment | MEDIUM |
| `request.args` | HTTP Request | HIGH |
| `request.form` | HTTP Form | HIGH |
| `request.json` | HTTP JSON | HIGH |
| `socket.recv()` | Network | HIGH |
| `open()` | File Input | MEDIUM |

### Dangerous Sinks

PyGuard flags when tainted data reaches:

- `eval()` - Code Injection (CWE-95)
- `exec()` - Code Injection (CWE-95)
- `compile()` - Code Injection (CWE-95)
- `os.system()` - Command Injection (CWE-78)
- `subprocess.call()` - Command Injection (CWE-78)
- `subprocess.run()` - Command Injection (CWE-78)

### Example

```python
# ❌ VULNERABLE: Taint flow violation
user_input = input("Enter command: ")
os.system(user_input)  # CRITICAL: Untrusted data flows into os.system()

# ✅ SAFE: Validated and sanitized
user_input = input("Enter filename: ")
if re.match(r'^[a-zA-Z0-9_-]+\.txt$', user_input):
    os.system(f"cat {user_input}")
```

### Mapping

- **OWASP ASVS**: 5.1.1 - Input Validation Architecture
- **CWE**: 20 - Improper Input Validation
- **Severity**: CRITICAL

---

## ReDoS Detection

### What is ReDoS?

Regular Expression Denial of Service (ReDoS) occurs when regex patterns with nested quantifiers cause catastrophic backtracking, leading to excessive CPU usage.

### Vulnerable Patterns Detected

PyGuard detects these dangerous regex patterns:

| Pattern | Description | Example |
|---------|-------------|---------|
| `(a+)+` | Nested quantifiers | `(a+)+b` |
| `(a*)+` | Nested star + plus | `(a*)+b` |
| `(a+)*` | Nested plus + star | `(a+)*b` |
| `(a*)*` | Double nested star | `(a*)*b` |
| `(a\|b)+` | Alternation + quantifier | `(a\|b)+c` |

### Example

```python
import re

# ❌ VULNERABLE: ReDoS attack possible
pattern = re.compile(r"(a+)+b")
result = pattern.match("a" * 50000)  # Will cause excessive CPU usage

# ✅ SAFE: No nested quantifiers
pattern = re.compile(r"a+b")
result = pattern.match("a" * 50000)  # Completes quickly
```

### Mitigation

1. **Avoid nested quantifiers** in regex patterns
2. **Use possessive quantifiers** (Python 3.11+): `(?>a+)+`
3. **Use re2 library** for guaranteed linear time regex
4. **Set timeouts** on regex operations
5. **Validate input length** before regex matching

### Mapping

- **OWASP ASVS**: 5.1.5 - Regular Expression Validation
- **CWE**: 1333 - Inefficient Regular Expression Complexity
- **Severity**: HIGH

---

## Race Condition Detection (TOCTOU)

### What are TOCTOU Vulnerabilities?

Time-of-Check to Time-of-Use (TOCTOU) race conditions occur when file attributes are checked before use, creating a window where an attacker can change the file state.

### Detected Patterns

PyGuard detects these TOCTOU patterns:

```python
# ❌ VULNERABLE: TOCTOU race condition
if os.path.exists(file_path):  # Check
    with open(file_path, 'r') as f:  # Use (window for attack)
        content = f.read()

# ❌ VULNERABLE: Permission check before use
if os.access(file_path, os.R_OK):  # Check
    with open(file_path, 'r') as f:  # Use
        content = f.read()

# ✅ SAFE: Exception-based approach (EAFP)
try:
    with open(file_path, 'r') as f:
        content = f.read()
except FileNotFoundError:
    handle_missing_file()
except PermissionError:
    handle_permission_error()
```

### Mitigation

1. **Use exception handling** instead of checking (EAFP - Easier to Ask for Forgiveness than Permission)
2. **Use atomic operations** where possible
3. **Use file locking** for critical operations
4. **Validate after opening** the file
5. **Use secure temporary directories** with proper permissions

### Mapping

- **OWASP ASVS**: 1.4.2 - Security Architecture
- **CWE**: 367 - Time-of-check Time-of-use Race Condition
- **CWE**: 362 - Concurrent Execution using Shared Resource
- **Severity**: MEDIUM

---

## Integer Security Analysis

### What are Integer Security Issues?

Integer overflow and underflow can lead to:
- Buffer overflows
- Memory corruption
- Logic errors
- Security bypass

### Detected Patterns

PyGuard detects potentially unsafe integer operations:

```python
# ❌ RISKY: Unchecked multiplication in memory allocation
size = user_size * item_count  # Could overflow
buffer = bytearray(size)  # Could allocate huge buffer

# ✅ SAFE: Validated ranges
MAX_SIZE = 1024 * 1024  # 1MB limit
if 0 < user_size < 1024 and 0 < item_count < 1024:
    size = user_size * item_count
    if size <= MAX_SIZE:
        buffer = bytearray(size)
```

### Mitigation

1. **Validate input ranges** before arithmetic operations
2. **Use safe integer libraries** that check for overflow
3. **Set maximum limits** on calculated values
4. **Use Python's arbitrary precision** where appropriate
5. **Check results** after arithmetic operations

### Mapping

- **OWASP ASVS**: 5.1.4 - Input and Output Validation
- **CWE**: 190 - Integer Overflow or Wraparound
- **CWE**: 191 - Integer Underflow
- **CWE**: 682 - Incorrect Calculation
- **Severity**: MEDIUM to HIGH

---

## Using Advanced Security Analysis

### Python API

```python
from pathlib import Path
from pyguard.lib.advanced_security import AdvancedSecurityAnalyzer

# Create analyzer
analyzer = AdvancedSecurityAnalyzer()

# Analyze a file
issues = analyzer.analyze_file(Path("myfile.py"))

# Print results
for issue in issues:
    print(f"[{issue.severity}] {issue.category}")
    print(f"  Line {issue.line_number}: {issue.message}")
    print(f"  CWE: {issue.cwe_id}, OWASP: {issue.owasp_id}")
    print(f"  Fix: {issue.fix_suggestion}")
    print()
```

### Analyze Source Code

```python
from pyguard.lib.advanced_security import AdvancedSecurityAnalyzer

code = """
import os
user_input = input("Enter command: ")
os.system(user_input)
"""

analyzer = AdvancedSecurityAnalyzer()
issues = analyzer.analyze_code(code)

print(f"Found {len(issues)} advanced security issues")
```

### Individual Analyzers

```python
from pyguard.lib.advanced_security import (
    TaintAnalyzer,
    ReDoSDetector,
    RaceConditionDetector,
    IntegerSecurityAnalyzer
)

# Use individual analyzers
taint = TaintAnalyzer(source_lines)
redos = ReDoSDetector()
race = RaceConditionDetector(source_lines)
integer = IntegerSecurityAnalyzer(source_lines)
```

---

## Best Practices

### 1. Defense in Depth

Don't rely on a single security check. Layer multiple defenses:

```python
# ✅ Multiple layers of defense
user_input = request.args.get('filename')

# Layer 1: Whitelist validation
if not re.match(r'^[a-zA-Z0-9_-]+\.(txt|log)$', user_input):
    raise ValueError("Invalid filename")

# Layer 2: Path canonicalization
safe_path = os.path.realpath(os.path.join(SAFE_DIR, user_input))

# Layer 3: Verify still in safe directory
if not safe_path.startswith(SAFE_DIR):
    raise SecurityError("Path traversal detected")

# Layer 4: Exception handling
try:
    with open(safe_path, 'r') as f:
        return f.read()
except Exception as e:
    log_security_event(e)
    raise
```

### 2. Input Validation

Always validate at trust boundaries:

```python
# ✅ Comprehensive input validation
def validate_user_input(data):
    # Type validation
    if not isinstance(data, str):
        raise TypeError("Expected string")
    
    # Length validation
    if len(data) > MAX_LENGTH:
        raise ValueError("Input too long")
    
    # Format validation
    if not ALLOWED_PATTERN.match(data):
        raise ValueError("Invalid format")
    
    # Sanitization
    return sanitize(data)
```

### 3. Secure Defaults

Use secure options by default:

```python
# ❌ Insecure defaults
subprocess.run(command, shell=True)  # Dangerous

# ✅ Secure defaults
subprocess.run(command.split(), shell=False)  # Safe
```

---

## Performance Considerations

### Taint Tracking

- **Cost**: Low to Medium
- **Scalability**: Handles files up to 10,000 lines efficiently
- **Optimization**: Uses AST walking (linear time)

### ReDoS Detection

- **Cost**: Very Low
- **Scalability**: Analyzes regex patterns instantly
- **Optimization**: Pattern matching on regex string

### Race Condition Detection

- **Cost**: Low
- **Scalability**: Efficient AST traversal
- **Optimization**: Only tracks relevant operations

### Integer Analysis

- **Cost**: Low
- **Scalability**: Integrated with AST traversal
- **Optimization**: Analyzes only arithmetic operations

---

## Comparison with Other Tools

| Feature | PyGuard | Bandit | Semgrep | SonarQube |
|---------|---------|--------|---------|-----------|
| **Taint Tracking** | ✅ Full | ❌ | ⚠️ Limited | ✅ Full |
| **ReDoS Detection** | ✅ Yes | ❌ | ❌ | ⚠️ Partial |
| **Race Conditions** | ✅ TOCTOU | ❌ | ❌ | ⚠️ Limited |
| **Integer Security** | ✅ Yes | ❌ | ❌ | ✅ Yes |
| **CWE Mapping** | ✅ Complete | ⚠️ Partial | ⚠️ Partial | ✅ Complete |
| **OWASP Mapping** | ✅ ASVS 5.0 | ❌ | ❌ | ⚠️ Partial |

**PyGuard Advantage**: Only open-source tool with comprehensive taint tracking, ReDoS detection, and TOCTOU analysis combined with full CWE/OWASP mapping.

---

## References

### Standards

1. **OWASP ASVS v5.0**  
   https://owasp.org/ASVS  
   Application Security Verification Standard - comprehensive security requirements

2. **CWE Top 25**  
   https://cwe.mitre.org/top25/  
   Most Dangerous Software Weaknesses - updated annually

3. **NIST SSDF**  
   https://csrc.nist.gov/publications/detail/sp/800-218/final  
   Secure Software Development Framework - secure SDLC practices

4. **SANS Top 25**  
   https://www.sans.org/top25-software-errors/  
   Most Dangerous Software Errors - critical security issues

5. **MITRE ATT&CK**  
   https://attack.mitre.org/  
   Adversarial Tactics, Techniques & Common Knowledge

### Research Papers

- "Taint Analysis: A Review" - IEEE Security & Privacy
- "Regular Expression Denial of Service - ReDoS" - OWASP Foundation
- "Race Conditions: The Silent Killer" - SANS Institute

### Tools & Libraries

- **Pyre**: Facebook's Python type checker with taint tracking
- **Pysa**: Python Static Analyzer for security
- **re2**: Google's safe regex library
- **semgrep**: Lightweight static analysis

---

## FAQ

### Q: How accurate is taint tracking?

**A**: PyGuard's taint tracking uses AST-based flow analysis with very high accuracy (low false positives). However, it's intra-procedural, meaning it tracks flows within functions but not across complex call chains.

### Q: Can ReDoS detection catch all vulnerable patterns?

**A**: PyGuard detects the most common ReDoS patterns (nested quantifiers). Some complex patterns might not be caught. Consider using `re2` library for guaranteed safety.

### Q: Does race condition detection find all TOCTOU issues?

**A**: PyGuard detects the most common file-based TOCTOU patterns. Complex multi-threaded race conditions require runtime analysis tools.

### Q: How does this compare to commercial tools?

**A**: PyGuard's advanced security analysis is on par with commercial SAST tools like SonarQube while being completely free and open-source.

---

## Contributing

Want to improve PyGuard's advanced security features? See [CONTRIBUTING.md](../CONTRIBUTING.md).

Ideas for enhancements:
- Cross-function taint tracking
- More ReDoS patterns
- Memory race conditions
- Cryptographic vulnerability detection
- ML-based anomaly detection

---

**PyGuard**: THE WORLD'S BEST Python Security Tool 🏆
