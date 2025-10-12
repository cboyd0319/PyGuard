# PyGuard API Reference

Complete Python API documentation for PyGuard.

## Table of Contents

- [Core Module](#core-module)
- [Security Module](#security-module)
- [Best Practices Module](#best-practices-module)
- [Formatting Module](#formatting-module)
- [Exceptions](#exceptions)

---

## Core Module

### PyGuardLogger

Structured JSON Lines (JSONL) logger for PyGuard operations.

#### Class Definition

```python
class PyGuardLogger:
    """Structured logger using JSONL format."""
    
    def __init__(
        self,
        log_file: str | Path = "logs/pyguard.jsonl",
        level: str = "INFO"
    ) -> None:
        """Initialize logger.
        
        Args:
            log_file: Path to log file (default: logs/pyguard.jsonl)
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
```

#### Methods

##### `info(message: str, **kwargs) -> None`

Log informational message.

```python
logger.info("Starting analysis", file="myfile.py", lines=100)
```

##### `warning(message: str, **kwargs) -> None`

Log warning message.

```python
logger.warning("Deprecated function used", function="old_func")
```

##### `error(message: str, exception: Exception = None, **kwargs) -> None`

Log error message with optional exception.

```python
try:
    result = risky_operation()
except Exception as e:
    logger.error("Operation failed", exception=e, file="test.py")
```

#### Example

```python
from pyguard import PyGuardLogger

logger = PyGuardLogger(log_file="custom.jsonl", level="DEBUG")
logger.info("Analysis started", files=10)
logger.warning("Issue found", type="security", severity="HIGH")
logger.error("Fix failed", file="bad.py")
```

---

### BackupManager

Manages file backups before modifications.

#### Class Definition

```python
class BackupManager:
    """Manages automatic backups of files before modification."""
    
    def __init__(
        self,
        backup_dir: str | Path = ".pyguard_backups",
        max_backups: int = 10
    ) -> None:
        """Initialize backup manager.
        
        Args:
            backup_dir: Directory for backups (default: .pyguard_backups)
            max_backups: Maximum number of backups to keep per file
        """
```

#### Methods

##### `create_backup(file_path: Path) -> Path`

Create timestamped backup of file.

```python
backup_path = backup_mgr.create_backup(Path("myfile.py"))
# Returns: .pyguard_backups/myfile_20250120_143022.py.bak
```

##### `restore_backup(backup_path: Path, target_path: Path) -> bool`

Restore file from backup.

```python
success = backup_mgr.restore_backup(backup_path, original_path)
```

##### `cleanup_old_backups(max_backups: int = 10) -> int`

Remove old backups, keeping only the most recent.

```python
removed_count = backup_mgr.cleanup_old_backups(max_backups=5)
print(f"Removed {removed_count} old backups")
```

##### `list_backups(file_path: Path) -> list[Path]`

List all backups for a specific file.

```python
backups = backup_mgr.list_backups(Path("myfile.py"))
for backup in backups:
    print(backup)
```

---

### DiffGenerator

Generates unified diffs showing changes.

#### Class Definition

```python
class DiffGenerator:
    """Generates unified diffs for code changes."""
    
    def __init__(
        self,
        context_lines: int = 3,
        use_color: bool = True
    ) -> None:
        """Initialize diff generator.
        
        Args:
            context_lines: Lines of context around changes
            use_color: Use ANSI colors in output
        """
```

#### Methods

##### `generate_diff(original: str, modified: str, filename: str = "") -> str`

Generate unified diff.

```python
diff = diff_gen.generate_diff(
    original="x == None",
    modified="x is None",
    filename="test.py"
)
print(diff)
# Output:
# --- test.py
# +++ test.py
# @@ -1 +1 @@
# -x == None
# +x is None
```

##### `generate_side_by_side(original: str, modified: str) -> str`

Generate side-by-side diff.

```python
diff = diff_gen.generate_side_by_side(original, modified)
```

---

### FileOperations

File system operations utilities.

#### Static Methods

##### `read_file(file_path: Path) -> str`

Read file content safely.

```python
content = FileOperations.read_file(Path("myfile.py"))
```

##### `write_file(file_path: Path, content: str) -> bool`

Write content to file.

```python
success = FileOperations.write_file(Path("output.py"), code)
```

##### `find_python_files(directory: Path, exclude_patterns: list[str] = None) -> list[Path]`

Find all Python files in directory.

```python
files = FileOperations.find_python_files(
    Path("src/"),
    exclude_patterns=["*/tests/*", "*_test.py"]
)
```

---

## Security Module

### SecurityFixer

Detects and fixes security vulnerabilities.

#### Class Definition

```python
class SecurityFixer:
    """Detects and fixes security vulnerabilities in Python code."""
    
    def __init__(
        self,
        severity_filter: list[str] = None,
        logger: PyGuardLogger = None
    ) -> None:
        """Initialize security fixer.
        
        Args:
            severity_filter: List of severities to fix (HIGH, MEDIUM, LOW)
            logger: Custom logger instance
        """
```

#### Methods

##### `fix_file(file_path: Path) -> tuple[bool, list[str]]`

Fix security issues in file.

```python
security_fixer = SecurityFixer()
success, fixes = security_fixer.fix_file(Path("myfile.py"))

print(f"Success: {success}")
print(f"Fixes applied: {len(fixes)}")
for fix in fixes:
    print(f"  - {fix}")
```

**Returns**:
- `success` (bool): True if file was processed successfully
- `fixes` (list[str]): List of fix descriptions

##### `scan_file(file_path: Path) -> list[dict]`

Scan file for issues without fixing.

```python
issues = security_fixer.scan_file(Path("myfile.py"))
for issue in issues:
    print(f"{issue['severity']}: {issue['description']}")
    print(f"  Line {issue['line']}: {issue['code']}")
```

**Returns**: List of issue dictionaries with keys:
- `severity`: HIGH, MEDIUM, or LOW
- `type`: Issue category
- `description`: Human-readable description
- `line`: Line number
- `code`: Code snippet
- `fix`: Suggested fix (if available)

#### Detected Vulnerabilities

| Vulnerability | Severity | Auto-Fix |
|---------------|----------|----------|
| Hardcoded passwords | HIGH | ⚠️ Warning comment |
| SQL injection | HIGH | ⚠️ Warning comment |
| Command injection | HIGH | ⚠️ Warning comment |
| Insecure random | MEDIUM | ✅ Replace with `secrets` |
| Unsafe YAML loading | HIGH | ✅ `yaml.load` → `yaml.safe_load` |
| Pickle usage | MEDIUM | ⚠️ Warning comment |
| `eval()`/`exec()` usage | HIGH | ⚠️ Warning comment |
| Weak crypto (MD5/SHA1) | MEDIUM | ✅ Replace with SHA256 |
| Path traversal | HIGH | ⚠️ Warning comment |

#### Example

```python
from pathlib import Path
from pyguard import SecurityFixer

# Initialize
security_fixer = SecurityFixer(
    severity_filter=["HIGH", "MEDIUM"]
)

# Fix file
file_path = Path("app/auth.py")
success, fixes = security_fixer.fix_file(file_path)

if success:
    print(f"✅ Applied {len(fixes)} security fixes")
else:
    print("❌ Failed to fix file")
```

---

## Best Practices Module

### BestPracticesFixer

Enforces Python best practices and code quality.

#### Class Definition

```python
class BestPracticesFixer:
    """Enforces Python best practices and code quality improvements."""
    
    def __init__(
        self,
        logger: PyGuardLogger = None
    ) -> None:
        """Initialize best practices fixer."""
```

#### Methods

##### `fix_file(file_path: Path) -> tuple[bool, list[str]]`

Apply best practice fixes to file.

```python
bp_fixer = BestPracticesFixer()
success, fixes = bp_fixer.fix_file(Path("myfile.py"))
```

##### `get_statistics() -> dict`

Get fixer statistics.

```python
stats = bp_fixer.get_statistics()
print(f"Files analyzed: {stats['files_analyzed']}")
print(f"Issues found: {stats['issues_found']}")
print(f"Fixes applied: {stats['fixes_applied']}")
```

#### Fixed Patterns

| Pattern | Fix |
|---------|-----|
| `def func(items=[])` | Add warning about mutable defaults |
| `except:` | Replace with `except Exception:` |
| `if x == None:` | Replace with `if x is None:` |
| `if x == True:` | Replace with `if x:` |
| `type(x) == int` | Suggest `isinstance(x, int)` |
| `for i in range(len(lst)): x = lst[i]` | Suggest enumerate/direct iteration |
| `s = ""; for x in items: s += x` | Warn about string concatenation |
| No docstring | Add `# TODO: Add docstring` |
| `global var` | Add warning comment |

---

### NamingConventionFixer

Checks PEP 8 naming conventions.

#### Class Definition

```python
class NamingConventionFixer:
    """Checks and suggests fixes for PEP 8 naming conventions."""
    
    def __init__(self, logger: PyGuardLogger = None) -> None:
        """Initialize naming convention fixer."""
```

#### Methods

##### `check_file(file_path: Path) -> list[dict]`

Check file for naming issues.

```python
naming_fixer = NamingConventionFixer()
issues = naming_fixer.check_file(Path("myfile.py"))

for issue in issues:
    print(f"Line {issue['line']}: {issue['message']}")
    print(f"  Current: {issue['name']}")
    print(f"  Suggested: {issue['suggestion']}")
```

#### Naming Rules

| Type | Convention | Example |
|------|------------|---------|
| Class | PascalCase | `MyClass` |
| Function | snake_case | `my_function()` |
| Method | snake_case | `my_method()` |
| Constant | UPPER_SNAKE | `MAX_SIZE` |
| Variable | snake_case | `my_variable` |
| Private | _snake_case | `_internal_func()` |

---

## Formatting Module

### FormattingFixer

Integrates with Black, isort, and autopep8.

#### Class Definition

```python
class FormattingFixer:
    """Code formatting using Black, isort, and autopep8."""
    
    def __init__(
        self,
        line_length: int = 100,
        logger: PyGuardLogger = None
    ) -> None:
        """Initialize formatting fixer.
        
        Args:
            line_length: Maximum line length
            logger: Custom logger
        """
```

#### Methods

##### `format_file(file_path: Path, use_black: bool = True, use_isort: bool = True) -> dict`

Format file with specified formatters.

```python
formatter = FormattingFixer(line_length=88)
result = formatter.format_file(
    Path("myfile.py"),
    use_black=True,
    use_isort=True
)

if result["success"]:
    print("✅ Formatting complete")
    if result["black_success"]:
        print("  - Black formatting applied")
    if result["isort_success"]:
        print("  - Imports sorted with isort")
```

**Returns**: Dictionary with keys:
- `success` (bool): Overall success
- `black_success` (bool): Black formatting success
- `isort_success` (bool): isort success
- `autopep8_success` (bool): autopep8 success (if enabled)

##### `format_with_black(code: str) -> str`

Format code string with Black.

```python
formatted = formatter.format_with_black("def f(x,y):return x+y")
print(formatted)
# Output:
# def f(x, y):
#     return x + y
```

##### `sort_imports_with_isort(code: str) -> str`

Sort imports with isort.

```python
code = "import os\nimport sys\nimport ast"
sorted_code = formatter.sort_imports_with_isort(code)
```

---

### WhitespaceFixer

Fixes whitespace and line ending issues.

#### Methods

##### `fix_trailing_whitespace(code: str) -> str`

Remove trailing whitespace.

```python
ws_fixer = WhitespaceFixer()
cleaned = ws_fixer.fix_trailing_whitespace("code   \n")
```

##### `fix_blank_lines(code: str) -> str`

Normalize blank lines (2 between classes, 1 between methods).

```python
normalized = ws_fixer.fix_blank_lines(code)
```

##### `normalize_line_endings(code: str) -> str`

Convert to LF line endings.

```python
normalized = ws_fixer.normalize_line_endings(windows_code)
```

---

## Exceptions

### PyGuardError

Base exception for all PyGuard errors.

```python
class PyGuardError(Exception):
    """Base exception for PyGuard errors."""
```

### FileNotFoundError

Raised when file doesn't exist.

```python
try:
    fixer.fix_file(Path("nonexistent.py"))
except FileNotFoundError as e:
    print(f"File not found: {e}")
```

### SyntaxError

Raised when file has invalid Python syntax.

```python
try:
    fixer.fix_file(Path("invalid.py"))
except SyntaxError as e:
    print(f"Syntax error: {e}")
```

---

## Complete Example

```python
from pathlib import Path
from pyguard import (
    PyGuardLogger,
    BackupManager,
    SecurityFixer,
    BestPracticesFixer,
    FormattingFixer,
    DiffGenerator
)

# Setup
logger = PyGuardLogger(level="INFO")
backup_mgr = BackupManager()
diff_gen = DiffGenerator(use_color=True)

# Create fixers
security_fixer = SecurityFixer(logger=logger)
bp_fixer = BestPracticesFixer(logger=logger)
formatter = FormattingFixer(line_length=100, logger=logger)

# Process file
file_path = Path("myapp/module.py")

# 1. Create backup
backup_path = backup_mgr.create_backup(file_path)
logger.info(f"Backup created: {backup_path}")

# 2. Read original
original_code = file_path.read_text()

# 3. Apply fixes
success1, sec_fixes = security_fixer.fix_file(file_path)
success2, bp_fixes = bp_fixer.fix_file(file_path)
result = formatter.format_file(file_path)

# 4. Show diff
modified_code = file_path.read_text()
diff = diff_gen.generate_diff(original_code, modified_code, str(file_path))
print(diff)

# 5. Summary
total_fixes = len(sec_fixes) + len(bp_fixes)
logger.info(f"Total fixes: {total_fixes}")
logger.info(f"Security: {len(sec_fixes)}")
logger.info(f"Best practices: {len(bp_fixes)}")
logger.info(f"Formatting: {result['success']}")
```

---

## Type Hints

PyGuard uses comprehensive type hints. Import types:

```python
from pathlib import Path
from typing import Optional, List, Dict, Tuple

def my_function(
    file_path: Path,
    options: Optional[Dict[str, str]] = None
) -> Tuple[bool, List[str]]:
    """Type-annotated function."""
    pass
```

---

## Next Steps

- [User Guide](user-guide.md) - Complete usage documentation
- [Configuration](configuration.md) - Advanced configuration
- [Security Rules](security-rules.md) - Security patterns reference
