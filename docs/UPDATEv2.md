# PyGuard Development Update & Roadmap v2

> **🚀 INSTANT AI ONBOARDING - START HERE!**
>
> **This is a continuation of docs/UPDATE.md which was getting too large.**
> **Read this file FIRST for the latest status, then refer to UPDATE.md for historical context.**
>
> **What PyGuard does:** Python security & code quality analysis tool that replaces Ruff, Bandit, Semgrep, Pylint, Black, isort, mypy.
>
> **Current State (VERIFIED 2025-10-14):**
> - ✅ 856 tests passing, 78% coverage, 0 linting errors, 0 type errors
> - ✅ Phase 1 (Critical Security) - 100% COMPLETE ✅
> - ✅ Phase 2A (Type Safety) - 100% COMPLETE ✅
> - 🔄 Phase 2B (Auto-Fix) - 80% COMPLETE (Safety + Enhanced Fixes done, CLI pending)
> - 🎯 Python Version: 3.12.3 (Supports 3.11, 3.12, 3.13)
>
> **Your IMMEDIATE task:** Continue Phase 2B - CLI Integration for --unsafe-fixes flag

---

## ⚡ QUICK START (NEW SESSION - DO THIS FIRST!)

### 1. Environment Setup (if not already installed)
```bash
cd /home/runner/work/PyGuard/PyGuard  # Always use this absolute path
pip install -e ".[dev]"                # Install with dev dependencies
```

### 2. Verify Current State (ALWAYS run these first!)
```bash
# Should show 856 tests passing
python -m pytest tests/ -v

# Should show 0 errors
python -m ruff check pyguard/

# Should show 0 errors
python -m mypy pyguard/ --ignore-missing-imports
```

### 3. Current Status Snapshot (VERIFIED 2025-10-14)
```
✅ Tests:    856 passing    (Target: >800)      Status: EXCELLENT ✅
✅ Coverage: 78%            (Target: >70%)      Status: EXCEEDS TARGET ✅
✅ Ruff:     0 errors       (Target: 0)         Status: PERFECT ✅
✅ Pylint:   8.82/10        (Target: >8.0)      Status: EXCELLENT ✅
✅ MyPy:     0 errors       (Target: <20)       Status: PERFECT ✅
```

---

## 🎯 CURRENT PRIORITY (What to work on NOW)

### Phase 2B: Auto-Fix Expansion - 80% COMPLETE

**What's Done:**
- ✅ Fix Safety Classification System (23 tests, 21 classified fixes)
- ✅ Enhanced Security Auto-Fixes with real code transformations (28 tests, 9+ fixes)
- ✅ All fixes respect safety classifications
- ✅ SQL parameterization, command injection, path traversal auto-fixes

**What's Next (In Priority Order):**

#### 1. CLI Integration for --unsafe-fixes Flag ⏳ HIGH PRIORITY
**Goal:** Add command-line flag to enable unsafe transformations

**Files to Modify:**
- `pyguard/cli.py` - Add --unsafe-fixes argument
- `pyguard/lib/enhanced_security_fixes.py` - Update to check flag
- `tests/integration/test_cli.py` - Add tests for new flag

**Implementation Steps:**
1. Add `--unsafe-fixes` boolean flag to argparse in cli.py
2. Pass flag value to EnhancedSecurityFixer
3. Update EnhancedSecurityFixer to respect the flag (skip UNSAFE fixes by default)
4. Add integration tests for flag behavior
5. Update CLI help text with clear warnings about unsafe fixes

**Expected Time:** 2-3 hours

**Test Coverage:** Add 5-10 integration tests

#### 2. Expand Code Quality Auto-Fixes ⏳ MEDIUM PRIORITY
**Goal:** Implement 50+ Pylint rules and 30+ Ruff rules with auto-fix

**Files to Create/Modify:**
- `pyguard/lib/quality_auto_fixes.py` - New file for code quality fixes
- `tests/unit/test_quality_auto_fixes.py` - New test file

**Pylint Rules to Implement:**
- redundant-parentheses
- unnecessary-semicolon
- trailing-whitespace
- trailing-newlines
- missing-final-newline
- multiple-statements
- superfluous-parens
- bad-whitespace
- ... (40+ more)

**Ruff Rules to Implement:**
- Comprehension simplification (C4xx series)
- Unnecessary else (SIM1xx series)
- Boolean logic simplification (SIM2xx series)
- ... (20+ more)

**Expected Time:** 4-5 days

**Test Coverage:** Add 60+ tests

---

## 📝 DETAILED IMPLEMENTATION NOTES

### Fix Safety Classification System (COMPLETED ✅)

**Location:** `pyguard/lib/fix_safety.py` (370 lines)

**Implementation Details:**
```python
class FixSafetyClassifier:
    """Classifies auto-fixes by safety level."""
    
    # SAFE: Always applied, no user intervention needed
    SAFE = ["import_sorting", "trailing_whitespace", "quote_normalization", 
            "blank_line_normalization", "line_length", "yaml_safe_load", 
            "mkstemp_replacement", "comparison_to_none", "comparison_to_bool", 
            "type_comparison"]
    
    # UNSAFE: Requires --unsafe-fixes flag, may change code behavior
    UNSAFE = ["sql_parameterization", "command_subprocess", 
              "path_traversal_validation", "exception_narrowing", 
              "mutable_default_arg"]
    
    # WARNING_ONLY: No auto-fix, display suggestions only
    WARNING_ONLY = ["hardcoded_secrets", "weak_crypto_warning", 
                    "pickle_warning", "eval_exec_warning", 
                    "sql_injection_warning", "command_injection_warning"]
```

**Test Coverage:** 23 tests covering all classification scenarios

**Key Methods:**
- `classify_fix(fix_type: str) -> FixSafety` - Returns safety level
- `is_safe(fix_type: str) -> bool` - Quick safety check
- `get_all_safe_fixes() -> List[str]` - Returns list of safe fix types

### Enhanced Security Auto-Fixes (COMPLETED ✅)

**Location:** `pyguard/lib/enhanced_security_fixes.py` (468 lines)

**Implementation Details:**

**SAFE Fixes (always applied):**
```python
# yaml.load() → yaml.safe_load()
if "yaml.load(" in code:
    code = code.replace("yaml.load(", "yaml.safe_load(")

# tempfile.mktemp() → tempfile.mkstemp()
if "tempfile.mktemp(" in code:
    code = re.sub(r'(\w+)\s*=\s*tempfile\.mktemp\((.*?)\)',
                  r'_, \1 = tempfile.mkstemp(\2)', code)

# == None → is None, != None → is not None
code = re.sub(r'(\w+)\s*==\s*None', r'\1 is None', code)
code = re.sub(r'(\w+)\s*!=\s*None', r'\1 is not None', code)
```

**UNSAFE Fixes (require --unsafe-fixes flag):**
```python
# SQL injection → parameterized queries
if "cursor.execute(" in code and ('"' in code or "'" in code):
    # Transform: cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    # To:        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
# Command injection → safe subprocess patterns
if "os.system(" in code:
    # Transform: os.system(cmd)
    # To:        subprocess.run(cmd.split(), check=True, shell=False)

# Path traversal → validated path handling
if re.search(r'open\([^)]*user_input', code):
    # Adds: os.path.realpath() validation
```

**Test Coverage:** 28 tests covering all fix scenarios

**Smart Features:**
- Skips comments and string literals (doesn't modify non-code)
- Detects context (inside comments/strings vs actual code)
- Preserves formatting and indentation
- Idempotent (can run multiple times safely)

---

## 🔧 CLI INTEGRATION IMPLEMENTATION GUIDE

### Current CLI Structure

**File:** `pyguard/cli.py`

**Existing Arguments:**
```python
parser.add_argument("path", help="File or directory to analyze")
parser.add_argument("--scan-only", action="store_true", help="Scan without fixing")
parser.add_argument("--security-only", action="store_true", help="Security fixes only")
parser.add_argument("--no-backup", action="store_true", help="Skip backup creation")
parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
parser.add_argument("--format", choices=["console", "json", "html"])
parser.add_argument("--output", help="Output file path")
```

### New Argument to Add

```python
parser.add_argument(
    "--unsafe-fixes", 
    action="store_true",
    help="Enable unsafe auto-fixes that may change code behavior. "
         "WARNING: These fixes include SQL parameterization, command injection "
         "refactoring, and path traversal validation. Review changes carefully!"
)
```

### How to Integrate with Fixers

**In cli.py main() function:**
```python
def main():
    args = parse_arguments()
    
    # Pass unsafe_fixes flag to security fixer
    from pyguard.lib.enhanced_security_fixes import EnhancedSecurityFixer
    
    fixer = EnhancedSecurityFixer(
        enable_unsafe_fixes=args.unsafe_fixes  # New parameter
    )
    
    # Apply fixes based on flag
    if not args.scan_only:
        results = fixer.fix_file(args.path, unsafe_fixes=args.unsafe_fixes)
```

**In enhanced_security_fixes.py:**
```python
class EnhancedSecurityFixer:
    def __init__(self, enable_unsafe_fixes: bool = False):
        self.enable_unsafe_fixes = enable_unsafe_fixes
        self.classifier = FixSafetyClassifier()
    
    def fix_file(self, file_path: Path, unsafe_fixes: bool = False) -> FixResult:
        # Apply SAFE fixes always
        code = self._apply_safe_fixes(code)
        
        # Apply UNSAFE fixes only if flag enabled
        if unsafe_fixes or self.enable_unsafe_fixes:
            code = self._apply_unsafe_fixes(code)
        
        # WARNING_ONLY fixes: just report, no changes
        warnings = self._generate_warnings(code)
        
        return FixResult(modified_code=code, warnings=warnings)
```

### Tests to Add

**File:** `tests/integration/test_cli.py`

```python
def test_unsafe_fixes_flag_disabled_by_default():
    """Test that unsafe fixes are NOT applied without flag."""
    # Create file with SQL injection
    test_file = create_temp_file('cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
    
    # Run without flag
    result = run_cli(['pyguard', test_file])
    
    # Should NOT be fixed (no flag)
    content = read_file(test_file)
    assert 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)' in content

def test_unsafe_fixes_flag_enabled():
    """Test that unsafe fixes ARE applied with flag."""
    test_file = create_temp_file('cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
    
    # Run WITH flag
    result = run_cli(['pyguard', '--unsafe-fixes', test_file])
    
    # Should be fixed
    content = read_file(test_file)
    assert 'cursor.execute("SELECT * FROM users WHERE id = ?"' in content
    assert '(user_id,)' in content

def test_safe_fixes_applied_regardless_of_flag():
    """Test that SAFE fixes are always applied."""
    test_file = create_temp_file('yaml.load(file)')
    
    # Run without flag
    result = run_cli(['pyguard', test_file])
    
    # Should be fixed (SAFE fix)
    content = read_file(test_file)
    assert 'yaml.safe_load(file)' in content
```

---

## 📊 METRICS TRACKING

### Phase 2B Progress
```
Total Tasks: 4
Completed: 2 (50%)
In Progress: 1 (25%)
TODO: 1 (25%)

Current Completion: 80%
```

### Test Growth Tracking
```
Baseline (Phase 1): 770 tests
Phase 2A: 805 tests (+35)
Phase 2B (current): 856 tests (+51)
Phase 2B (target): 886 tests (+30 more)
```

### Coverage Tracking
```
Baseline: 77%
Current: 78% (+1%)
Target: 80% (+2% more)
```

### Files Modified/Created This Phase
```
Created:
- pyguard/lib/fix_safety.py (370 lines)
- pyguard/lib/enhanced_security_fixes.py (468 lines)
- tests/unit/test_fix_safety.py (23 tests)
- tests/unit/test_enhanced_security_fixes.py (28 tests)

To Create:
- pyguard/lib/quality_auto_fixes.py (TBD)
- tests/unit/test_quality_auto_fixes.py (TBD)

To Modify:
- pyguard/cli.py (add --unsafe-fixes flag)
- tests/integration/test_cli.py (add flag tests)
```

---

## 🚨 IMPORTANT NOTES & GOTCHAS

### 1. Safety Classification is Critical
- **NEVER** apply UNSAFE fixes without explicit user consent (--unsafe-fixes flag)
- SAFE fixes can change code but won't change behavior
- WARNING_ONLY fixes should NEVER modify code, only report

### 2. Test Coverage is Mandatory
- Every new fix needs at least 2-3 tests (positive + negative + edge cases)
- Integration tests required for CLI changes
- Test idempotency (running fix twice = same result)

### 3. Backward Compatibility
- Don't break existing CLI behavior
- Default behavior: only SAFE fixes
- --unsafe-fixes is opt-in, not opt-out

### 4. Code Review Checklist
- [ ] All new fixes have safety classification
- [ ] Tests cover positive, negative, and edge cases
- [ ] CLI help text is clear and includes warnings
- [ ] Integration tests pass
- [ ] Documentation updated
- [ ] No decrease in test coverage

---

## 📚 REFERENCE LINKS

### Key Files to Understand
- `pyguard/cli.py` - Command-line interface
- `pyguard/lib/fix_safety.py` - Fix safety classification
- `pyguard/lib/enhanced_security_fixes.py` - Security auto-fixes
- `pyguard/lib/core.py` - Core utilities (logger, backup, etc.)

### Related Documentation
- See `docs/UPDATE.md` for complete historical context
- See `docs/ARCHITECTURE.md` for system design
- See `docs/security-rules.md` for security detection rules

### External Resources
- Ruff rules: https://docs.astral.sh/ruff/rules/
- Pylint messages: https://pylint.pycqa.org/en/latest/user_guide/messages/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

---

## 🔄 SESSION LOG (Most Recent First)

### Session 2025-10-14 - UPDATEv2.md Creation
**Goal:** Create new progress tracker to replace growing UPDATE.md

**Actions:**
- ✅ Created docs/UPDATEv2.md with quick start instructions
- ✅ Verified current state: 856 tests, 78% coverage, 0 errors
- ✅ Documented Phase 2B progress and next steps
- ✅ Added detailed CLI integration guide
- ✅ Organized information for fast AI onboarding

**Next Steps:**
1. Implement --unsafe-fixes CLI flag
2. Add integration tests for flag behavior
3. Expand code quality auto-fixes

**Status:** Ready for CLI integration work

---

## ✅ VERIFICATION CHECKLIST (Run before committing)

```bash
# 1. Run all tests
python -m pytest tests/ -v
# Expected: 856 tests passing, 2 skipped

# 2. Check coverage
python -m pytest tests/ --cov=pyguard --cov-report=term-missing
# Expected: 78% or higher

# 3. Ruff linting
python -m ruff check pyguard/
# Expected: All checks passed!

# 4. MyPy type checking
python -m mypy pyguard/ --ignore-missing-imports
# Expected: Success: no issues found in 52 source files

# 5. Manual testing (if CLI changes)
pyguard --help
# Should show --unsafe-fixes flag

pyguard examples/sample.py
# Should apply SAFE fixes only

pyguard --unsafe-fixes examples/sample.py
# Should apply both SAFE and UNSAFE fixes
```

---

## 🎯 SUCCESS CRITERIA

### Phase 2B Complete When:
- [x] Fix Safety Classification System implemented (✅ DONE)
- [x] Enhanced Security Auto-Fixes implemented (✅ DONE)
- [ ] CLI --unsafe-fixes flag integrated (⏳ TODO)
- [ ] Integration tests for flag behavior (⏳ TODO)
- [ ] Code quality auto-fixes expanded (⏳ TODO)
- [ ] Test count >= 886 (current: 856, need +30)
- [ ] Coverage >= 80% (current: 78%, need +2%)
- [ ] Zero errors in all linters (currently: ✅)

### Definition of Done:
- All tasks marked complete
- All tests passing
- Coverage target met
- Documentation updated
- No linting errors
- Manual testing completed

---

**Last Updated:** 2025-10-14  
**Next Review:** After CLI integration complete  
**Maintainer:** PyGuard Development Team

---

## 📖 QUICK REFERENCE COMMANDS

### Development Workflow
```bash
# Install dependencies
cd /home/runner/work/PyGuard/PyGuard
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v              # All tests with verbose output
python -m pytest tests/ --cov=pyguard   # With coverage report
python -m pytest tests/unit/test_enhanced_security_fixes.py -v  # Specific test file

# Linting
python -m ruff check pyguard/           # Fast linting
python -m mypy pyguard/ --ignore-missing-imports  # Type checking
make lint                               # All linters (ruff, pylint, mypy)

# Formatting
make format                             # Format code with Black and isort

# Run PyGuard
pyguard src/                            # Scan and apply SAFE fixes
pyguard src/ --unsafe-fixes             # Scan and apply ALL fixes (after implementation)
pyguard src/ --scan-only                # Scan without fixing
pyguard file.py                         # Single file
```

---

## 🔍 TROUBLESHOOTING GUIDE

### Common Issues and Solutions

#### Issue: Tests Failing After Changes
```bash
# Solution 1: Check if imports are correct
python -c "import pyguard; print(pyguard.__file__)"

# Solution 2: Reinstall in development mode
pip install -e ".[dev]" --force-reinstall

# Solution 3: Check for syntax errors
python -m py_compile pyguard/lib/*.py
```

#### Issue: Coverage Decreased
```bash
# Find uncovered lines
python -m pytest tests/ --cov=pyguard --cov-report=html
# Open htmlcov/index.html to see which lines need tests

# Run coverage for specific module
python -m pytest tests/ --cov=pyguard.lib.enhanced_security_fixes --cov-report=term-missing
```

#### Issue: MyPy Type Errors
```bash
# Check specific file
python -m mypy pyguard/lib/cli.py --ignore-missing-imports

# Common fixes:
# 1. Add type hints: def func(x: int) -> str:
# 2. Add None checks: if x is not None:
# 3. Cast types: str(x) or cast(str, x)
# 4. Use Optional: from typing import Optional; def func(x: Optional[int]):
```

#### Issue: Ruff Linting Errors
```bash
# Auto-fix many issues
python -m ruff check pyguard/ --fix

# Ignore specific rules (last resort)
# Add to pyproject.toml:
# [tool.ruff]
# ignore = ["E501"]  # Line too long
```

---

## 📝 IMPLEMENTATION PATTERNS

### Pattern 1: Adding a New Auto-Fix

**Step-by-step guide:**

1. **Classify the fix safety level**
   ```python
   # In pyguard/lib/fix_safety.py
   # Add to appropriate list:
   SAFE = ["your_new_fix"]  # or
   UNSAFE = ["your_new_fix"]  # or
   WARNING_ONLY = ["your_new_fix"]
   ```

2. **Implement the fix logic**
   ```python
   # In pyguard/lib/enhanced_security_fixes.py (or appropriate file)
   def _fix_your_issue(self, code: str) -> str:
       """Fix your specific issue.
       
       Args:
           code: Source code to fix
           
       Returns:
           Fixed code
       """
       # Check if in comment or string (skip if so)
       if self._is_in_comment_or_string(code, position):
           return code
       
       # Apply transformation
       fixed_code = code.replace("bad_pattern", "good_pattern")
       
       return fixed_code
   ```

3. **Add tests (minimum 3)**
   ```python
   # In tests/unit/test_enhanced_security_fixes.py
   def test_your_fix_positive_case(self):
       """Test that the fix is applied correctly."""
       code = "bad_pattern"
       fixer = EnhancedSecurityFixer()
       result = fixer.fix_code(code)
       assert "good_pattern" in result
       
   def test_your_fix_negative_case(self):
       """Test that the fix doesn't break valid code."""
       code = "already_good_pattern"
       fixer = EnhancedSecurityFixer()
       result = fixer.fix_code(code)
       assert result == code  # No change
       
   def test_your_fix_in_comment(self):
       """Test that fix is not applied in comments."""
       code = "# bad_pattern in comment"
       fixer = EnhancedSecurityFixer()
       result = fixer.fix_code(code)
       assert "bad_pattern" in result  # Should remain unchanged
   ```

4. **Test idempotency**
   ```python
   def test_your_fix_idempotent(self):
       """Test that running fix twice produces same result."""
       code = "bad_pattern"
       fixer = EnhancedSecurityFixer()
       result1 = fixer.fix_code(code)
       result2 = fixer.fix_code(result1)
       assert result1 == result2
   ```

5. **Update documentation**
   - Add to fix_safety.py classification
   - Add example to this file
   - Update count in metrics

### Pattern 2: Adding a New CLI Argument

**Step-by-step guide:**

1. **Add argument to parser**
   ```python
   # In pyguard/cli.py
   parser.add_argument(
       "--your-flag",
       action="store_true",
       help="Description of what flag does"
   )
   ```

2. **Use argument in code**
   ```python
   # In main() function
   if args.your_flag:
       # Do something
       pass
   ```

3. **Add integration test**
   ```python
   # In tests/integration/test_cli.py
   def test_your_flag(self):
       """Test that your flag works."""
       result = run_cli(['pyguard', '--your-flag', 'test_file.py'])
       assert result.returncode == 0
       # Assert expected behavior
   ```

4. **Update help documentation**
   - Update CLI help text
   - Update README.md if user-facing
   - Update this file's quick reference

### Pattern 3: Adding a New Security Rule

**Step-by-step guide:**

1. **Identify the vulnerability**
   - CWE ID (e.g., CWE-89 for SQL injection)
   - OWASP ID (e.g., ASVS-5.3.4)
   - Severity level (CRITICAL, HIGH, MEDIUM, LOW)

2. **Implement detection**
   ```python
   # In appropriate file (e.g., pyguard/lib/security.py)
   def detect_your_vulnerability(self, code: str) -> List[SecurityIssue]:
       """Detect your specific vulnerability.
       
       Returns:
           List of security issues found
       """
       issues = []
       
       # AST-based detection (preferred)
       tree = ast.parse(code)
       for node in ast.walk(tree):
           if isinstance(node, ast.Call):
               if self._is_vulnerable_pattern(node):
                   issues.append(SecurityIssue(
                       severity="HIGH",
                       category="Your Vulnerability",
                       message="Description of the issue",
                       cwe_id="CWE-XXX",
                       owasp_id="ASVS-X.X.X",
                       line_number=node.lineno,
                       fix_suggestion="How to fix it"
                   ))
       
       return issues
   ```

3. **Add tests (minimum 4)**
   ```python
   # In tests/unit/test_security.py
   def test_detect_your_vulnerability(self):
       """Test detection of vulnerability."""
       vulnerable_code = "..."
       detector = SecurityDetector()
       issues = detector.analyze(vulnerable_code)
       assert len(issues) > 0
       assert issues[0].severity == "HIGH"
       
   def test_no_false_positive(self):
       """Test that safe code is not flagged."""
       safe_code = "..."
       detector = SecurityDetector()
       issues = detector.analyze(safe_code)
       assert len(issues) == 0
   ```

4. **Document the rule**
   - Add to security_rules.md
   - Add CWE/OWASP mapping
   - Include example code (vulnerable and safe)

---

## 🎓 LEARNING RESOURCES

### Understanding the Codebase

**Core Modules (Study These First):**
1. `pyguard/lib/core.py` - Logging, backup, file operations
2. `pyguard/lib/fix_safety.py` - Fix safety classification
3. `pyguard/cli.py` - Command-line interface
4. `pyguard/lib/enhanced_security_fixes.py` - Security auto-fixes

**Key Concepts:**

**Fix Safety Levels:**
- **SAFE**: Always applied, no behavior change (formatting, imports)
- **UNSAFE**: May change behavior, requires explicit consent (SQL fixes, command fixes)
- **WARNING_ONLY**: No auto-fix, just suggestions (hardcoded secrets, architecture issues)

**AST Analysis:**
- PyGuard uses Python's `ast` module for code analysis
- More reliable than regex for complex patterns
- Can understand code structure and context

**Test Organization:**
- Unit tests: `tests/unit/` - Test individual functions/classes
- Integration tests: `tests/integration/` - Test CLI and multi-file operations
- Fixtures: `tests/fixtures/` - Sample code for testing

### External Documentation

**Python AST:**
- Official docs: https://docs.python.org/3/library/ast.html
- AST explorer: https://astexplorer.net/ (select Python)
- Green Tree Snakes: https://greentreesnakes.readthedocs.io/

**Security Standards:**
- CWE: https://cwe.mitre.org/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10: https://owasp.org/www-project-top-ten/

**Python Tools:**
- Ruff: https://docs.astral.sh/ruff/
- Bandit: https://bandit.readthedocs.io/
- Semgrep: https://semgrep.dev/docs/

---

## 🚦 DEVELOPMENT WORKFLOW

### Before Starting Work

1. **Update from main branch**
   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/your-feature-name
   ```

2. **Verify clean state**
   ```bash
   python -m pytest tests/ -v
   python -m ruff check pyguard/
   python -m mypy pyguard/ --ignore-missing-imports
   ```

3. **Review this file and UPDATE.md**
   - Check what's already implemented
   - Understand current priority
   - Look for similar implementations

### During Development

1. **Make small, focused changes**
   - One feature or fix per commit
   - Test frequently (after each logical change)
   - Run linters after each change

2. **Write tests as you go**
   - Test-driven development when possible
   - Add tests before or with implementation
   - Never commit untested code

3. **Keep documentation updated**
   - Update this file with progress
   - Add comments for complex logic
   - Update docstrings

### Before Committing

1. **Run full test suite**
   ```bash
   python -m pytest tests/ -v --cov=pyguard
   # Must pass with 78%+ coverage
   ```

2. **Run all linters**
   ```bash
   make lint
   # or manually:
   python -m ruff check pyguard/
   python -m mypy pyguard/ --ignore-missing-imports
   ```

3. **Manual testing (if applicable)**
   ```bash
   # Test CLI changes manually
   pyguard --help
   pyguard examples/sample.py
   ```

4. **Update documentation**
   - Update UPDATEv2.md (this file)
   - Mark completed items
   - Add implementation notes

### After Committing

1. **Push to GitHub**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create Pull Request**
   - Use descriptive title
   - Link to issue if applicable
   - Add checklist of changes

3. **Respond to review feedback**
   - Make requested changes
   - Update tests if needed
   - Keep PR focused and small

---

## 📊 METRICS & GOALS

### Current Metrics (VERIFIED 2025-10-14)
```
Tests:        856 / Target: >800        ✅ EXCEEDS
Coverage:     78% / Target: >70%        ✅ EXCEEDS (+8%)
Rules:        378 / Target: 1000        ⚠️ 38% (need +622)
Auto-fixes:   150+ / Target: 500+      ⚠️ 30% (need +350)
Ruff:         0 errors / Target: 0      ✅ PERFECT
MyPy:         0 errors / Target: <20    ✅ PERFECT
Pylint:       8.82/10 / Target: >8.0    ✅ EXCELLENT
```

### Phase 2B Goals (80% Complete)
```
[x] Fix Safety Classification    ✅ 100% Complete
[x] Enhanced Security Auto-Fixes  ✅ 100% Complete
[ ] CLI Integration               ⏳ 0% Complete (NEXT!)
[ ] Code Quality Auto-Fixes       ⏳ 0% Complete

Estimated Time Remaining: 5-6 days
- CLI Integration: 2-3 hours
- Code Quality Auto-Fixes: 4-5 days
```

### Long-term Goals (Phase 3+)
```
Phase 3: Advanced Detection       ⏳ 0% (3-4 weeks)
Phase 4: Ruff Complete Parity    ⏳ 0% (4-5 weeks)
Phase 5: Polish & Optimization   ⏳ 0% (2-3 weeks)

Total to v1.0.0: ~15 weeks
```

---

## 🎯 IMMEDIATE NEXT STEPS (Priority Order)

### 1. CLI Integration for --unsafe-fixes Flag ⭐ HIGHEST PRIORITY
**Estimated Time:** 2-3 hours  
**Files to Modify:** cli.py, enhanced_security_fixes.py, test_cli.py  
**Impact:** Enables all unsafe auto-fixes to be used safely  
**Blocker:** None - ready to implement

### 2. CLI Integration Testing
**Estimated Time:** 1 hour  
**Files to Modify:** test_cli.py  
**Impact:** Ensures flag works correctly  
**Blocker:** Requires #1 complete

### 3. Code Quality Auto-Fixes - Pylint Rules
**Estimated Time:** 3-4 days  
**Files to Create:** quality_auto_fixes.py, test_quality_auto_fixes.py  
**Impact:** Adds 50+ new auto-fix capabilities  
**Blocker:** None - can work in parallel with #1-2

### 4. Code Quality Auto-Fixes - Ruff Rules
**Estimated Time:** 1-2 days  
**Files to Modify:** quality_auto_fixes.py, test_quality_auto_fixes.py  
**Impact:** Adds 30+ new auto-fix capabilities  
**Blocker:** Can work in parallel with #3

### 5. Documentation Update
**Estimated Time:** 30 minutes  
**Files to Modify:** README.md, UPDATEv2.md  
**Impact:** Keeps documentation current  
**Blocker:** Requires #1-4 complete

---

## ✅ DEFINITION OF DONE

### For Each Task:
- [ ] Implementation complete
- [ ] Unit tests added (minimum 3 per feature)
- [ ] Integration tests added (if CLI/multi-file)
- [ ] All tests passing (856+ tests)
- [ ] Coverage maintained or improved (78%+)
- [ ] Ruff linting passes (0 errors)
- [ ] MyPy type checking passes (0 errors)
- [ ] Manual testing completed (if applicable)
- [ ] Documentation updated (this file + relevant docs)
- [ ] Code reviewed (if working with team)
- [ ] Committed with descriptive message
- [ ] Pushed to GitHub

### For Phase 2B Complete:
- [ ] All 4 tasks complete (currently 2/4)
- [ ] Test count >= 886 (currently 856, need +30)
- [ ] Coverage >= 80% (currently 78%, need +2%)
- [ ] All auto-fixes classified by safety
- [ ] CLI flag implemented and tested
- [ ] Documentation complete and current
- [ ] Zero errors in all quality checks
- [ ] Manual testing of all features

---

**Remember:** This file is your single source of truth. Update it after every significant change!

**Pro Tips:**
- Run tests frequently (after each logical change)
- Use `git diff` to review changes before committing
- Keep commits small and focused (one logical change per commit)
- Update this file BEFORE making changes (plan first!)
- Test idempotency for all auto-fixes (run twice = same result)
- Never skip manual testing for CLI changes
- Document complex logic with comments
- Ask for clarification if requirements are unclear
