# PyGuard New Rules Quick Reference

Quick reference guide for the 46+ new detection rules added in Phase 1.

## Modern Python (UP) - 10 rules

| Rule ID | Description | Auto-Fix | Example |
|---------|-------------|----------|---------|
| UP001 | Old-style super() | ✅ Yes | `super(MyClass, self)` → `super()` |
| UP004 | Six library usage | 🔍 Detect | `import six` (not needed in Python 3) |
| UP005 | Unnecessary __future__ | ✅ Yes | `from __future__ import print_function` |
| UP006 | typing.List vs list | 🔍 Detect | `List[str]` → use `list[str]` |
| UP007 | Optional/Union | 🔍 Detect | `Optional[str]` → use `str \| None` |
| UP031 | % formatting | 🔍 Detect | `"Hello %s" % name` → use f-string |
| UP032 | .format() | 🔍 Detect | `"Hello {}".format(name)` → use f-string |

## Code Simplification (SIM) - 15 rules

| Rule ID | Description | Auto-Fix | Example |
|---------|-------------|----------|---------|
| SIM101 | Multiple isinstance | 🔍 Detect | `isinstance(x, int) or isinstance(x, float)` → `isinstance(x, (int, float))` |
| SIM102 | Nested if | 🔍 Detect | `if a: if b: pass` → `if a and b: pass` |
| SIM103 | Return bool | 🔍 Detect | `if x: return True else: return False` → `return x` |
| SIM105 | Try-except-pass | 🔍 Detect | Use `contextlib.suppress()` instead |
| SIM107 | Return in else | 🔍 Detect | Don't return in try-else block |
| SIM108 | Ternary operator | 🔍 Detect | Simple if-else → ternary |
| SIM109 | Redundant bool() | 🔍 Detect | `bool(x > 5)` (comparison is already bool) |
| SIM112 | Env var naming | 🔍 Detect | `os.getenv("my_var")` → use `"MY_VAR"` |
| SIM113 | Use enumerate | 🔍 Detect | Manual counter → `enumerate()` |
| SIM114 | Duplicate if body | 🔍 Detect | Multiple ifs with same code → combine |
| SIM201 | Compare to True | 🔍 Detect | `x == True` → `x is True` |
| SIM202 | Compare to False | 🔍 Detect | `x == False` → `x is False` |

## Performance (PERF) - 6 rules

| Rule ID | Description | Auto-Fix | Example |
|---------|-------------|----------|---------|
| PERF101 | Try in loop | 🔍 Detect | Move try-except outside loop |
| PERF102 | List concat in loop | 🔍 Detect | `result += [item]` → `result.append(item)` |
| PERF402 | Unnecessary wrapper | 🔍 Detect | `list([x for x in y])` → `[x for x in y]` |
| PERF403 | Dict comprehension | 🔍 Detect | `dict([(k, v) for ...])` → `{k: v for ...}` |
| PERF404 | .keys() in test | ✅ Yes | `key in dict.keys()` → `key in dict` |
| PERF405 | list[:] vs .copy() | 🔍 Detect | `list[:]` → `list.copy()` for clarity |

## Unused Code (F/ARG) - 5 rules

| Rule ID | Description | Auto-Fix | Example |
|---------|-------------|----------|---------|
| F401 | Unused import | ✅ Yes | `import os` (never used) → removed |
| F841 | Unused variable | 🔍 Detect | `unused = 42` (never used) |
| ARG001 | Unused argument | 🔍 Detect | `def f(x, unused): return x` → prefix with `_` |

**Note:** Ignores `self`, `cls`, and names starting with `_`

## Naming Conventions (N/E) - 10 rules

| Rule ID | Description | Auto-Fix | Example |
|---------|-------------|----------|---------|
| N801 | Class name | 🔍 Detect | `class my_class:` → `class MyClass:` |
| N802 | Function name | 🔍 Detect | `def MyFunc():` → `def my_func():` |
| N803 | Argument name | 🔍 Detect | `def f(CamelArg):` → `def f(camel_arg):` |
| N806 | Variable name | 🔍 Detect | `MyVar = 1` → `my_var = 1` |
| N807 | Custom __dunder__ | 🔍 Detect | `def __custom__():` (not magic method) |
| N811 | Import alias | 🔍 Detect | Import aliases should follow conventions |
| E741 | Ambiguous name | 🔍 Detect | `l = 1`, `O = 0`, `I = 1` (confusing) |

**Exceptions:**
- Constants in UPPER_CASE are allowed
- Private names with `_` prefix are allowed
- Test methods like `test_*`, `setUp`, `tearDown` are allowed
- Magic methods like `__init__`, `__str__` are allowed

## Legend

- ✅ **Auto-Fix:** Issue is automatically fixed
- 🔍 **Detect:** Issue is detected and reported with fix suggestion

## Usage Examples

### Scan for Issues

```python
from pyguard.lib.modern_python import ModernPythonFixer
from pyguard.lib.unused_code import UnusedCodeFixer
from pathlib import Path

# Modern Python issues
modern_fixer = ModernPythonFixer()
issues = modern_fixer.scan_file_for_issues(Path("myfile.py"))

for issue in issues:
    print(f"{issue.rule_id}: {issue.message}")
    print(f"  Line {issue.line_number}: {issue.code_snippet}")
    print(f"  Fix: {issue.fix_suggestion}")

# Unused code
unused_fixer = UnusedCodeFixer()
issues = unused_fixer.scan_file_for_issues(Path("myfile.py"))
```

### Apply Auto-Fixes

```python
from pyguard.lib.unused_code import UnusedCodeFixer
from pyguard.lib.performance_checks import PerformanceFixer
from pathlib import Path

# Remove unused imports
unused_fixer = UnusedCodeFixer()
success, fixes = unused_fixer.fix_file(Path("myfile.py"))
print(f"Applied {len(fixes)} fixes:")
for fix in fixes:
    print(f"  - {fix}")

# Fix performance issues
perf_fixer = PerformanceFixer()
success, fixes = perf_fixer.fix_file(Path("myfile.py"))
```

### Scan Multiple Files

```python
from pathlib import Path
from pyguard.lib.modern_python import ModernPythonFixer

fixer = ModernPythonFixer()

for py_file in Path("src").rglob("*.py"):
    issues = fixer.scan_file_for_issues(py_file)
    if issues:
        print(f"\n{py_file}:")
        for issue in issues:
            print(f"  {issue.rule_id} (line {issue.line_number}): {issue.message}")
```

## Integration with Existing PyGuard

These new rules complement PyGuard's existing capabilities:

**Security (55+ rules) + New Quality (46+ rules) = 100+ total rules**

```python
# Comprehensive analysis
from pyguard.lib.security import SecurityFixer
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.modern_python import ModernPythonFixer
from pyguard.lib.unused_code import UnusedCodeFixer

file_path = Path("myfile.py")

# Security analysis
security_fixer = SecurityFixer()
security_issues = security_fixer.scan_file_for_issues(file_path)

# Code quality
quality_fixer = BestPracticesFixer()
quality_issues = quality_fixer.scan_file_for_issues(file_path)

# Modern Python
modern_fixer = ModernPythonFixer()
modern_issues = modern_fixer.scan_file_for_issues(file_path)

# Unused code
unused_fixer = UnusedCodeFixer()
unused_issues = unused_fixer.scan_file_for_issues(file_path)

all_issues = security_issues + quality_issues + modern_issues + unused_issues
print(f"Total issues found: {len(all_issues)}")
```

## Coming in Phase 2

**150+ additional rules planned:**
- Bugbear (B) - 50 rules for common mistakes
- Exception Handling (TRY) - 20 rules for proper error handling
- Import Management (I, TID, TCH) - 50 rules for import organization
- Remaining Modern Python (UP) - 40 rules for complete modernization
- 20+ additional auto-fix capabilities

## See Also

- [LINTER-GAP-ANALYSIS.md](./LINTER-GAP-ANALYSIS.md) - Complete gap analysis
- [PHASE1-IMPLEMENTATION.md](./PHASE1-IMPLEMENTATION.md) - Detailed implementation guide
- [PyGuard README](../README.md) - Project overview
- [CONTRIBUTING.md](../CONTRIBUTING.md) - How to contribute new rules
