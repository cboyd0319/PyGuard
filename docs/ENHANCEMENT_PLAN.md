# PyGuard Enhancement Plan

## Overview

This document outlines the comprehensive enhancement plan to make PyGuard a complete replacement for all major Python linters, formatters, and code quality tools (Ruff, Sonar, Pytype, Pylint, Flake8, Black, autopep8, PyChecker, Pylama, Codacy).

## Phase 1: Foundation (COMPLETED ✓)

### Rule Engine Framework ✓
**Module:** `pyguard/lib/rule_engine.py`

Implemented a comprehensive rule engine that provides:
- **Rule class**: Base class for all detection rules
- **RuleViolation**: Standardized violation reporting
- **RuleRegistry**: Central registry for all rules
- **RuleExecutor**: Executes rules and manages violations
- **Categories**: Security, Error, Warning, Style, Convention, Refactor, Performance, Type, Import, Documentation, Design, Duplication, Complexity
- **Severity Levels**: Critical, High, Medium, Low, Info
- **Fix Applicability**: Automatic, Suggested, Manual, None

**Features:**
- Enable/disable rules individually or by category
- Filter by severity and tags
- Support for OWASP/CWE mappings
- Comprehensive message templating
- Fix application framework

**Test Coverage:** 82% (13 test classes, 44 tests total)

### Type Checking System ✓
**Module:** `pyguard/lib/type_checker.py`

Implemented type analysis and type hint detection:
- **TypeInferenceEngine**: Simple type inference from defaults and assignments
- **TypeHintVisitor**: AST visitor for type hint analysis
- **TypeChecker**: Main type checking class

**Rules Implemented:**
1. `PG-T001`: Missing return type annotation
2. `PG-T002`: Missing parameter type annotation
3. `PG-T003`: Any type usage detection
4. `PG-T004`: Type comparison (type() vs isinstance())

**Test Coverage:** 77% (4 test classes, 15 tests)

### Import Management ✓
**Module:** `pyguard/lib/import_manager.py`

Implemented import analysis and organization:
- **ImportAnalyzer**: Extract and analyze imports
- **ImportManager**: Main import management class
- Import categorization (future, stdlib, third-party, local)
- Import sorting (PEP 8 compliant)
- Unused import detection

**Rules Implemented:**
1. `PG-I001`: Unused import
2. `PG-I002`: Import shadowing
3. `PG-I003`: Unsorted imports
4. `PG-I004`: Star import

**Test Coverage:** 91% (5 test classes, 15 tests)

### Integration ✓
- All new modules exported in `pyguard/__init__.py`
- 44 new tests added
- Overall test coverage increased from 72% to 74%
- All 367 tests passing

---

## Phase 2: String Operations (NEXT)

### Module: `pyguard/lib/string_operations.py`

**Detection Capabilities:**
1. **F-string Modernization**
   - Detect `.format()` that can be f-strings
   - Detect `%` formatting that can be f-strings
   - Detect unnecessary f-strings (no placeholders)

2. **Quote Consistency**
   - Single vs double quote consistency
   - Docstring quote style
   - Mixed quote usage

3. **String Concatenation**
   - String concat in loops (should use join)
   - Multiple + operations
   - String formatting best practices

4. **Format String Validation**
   - Missing format arguments
   - Extra format arguments
   - Type mismatches in format

**Auto-fix Capabilities:**
- Convert `.format()` to f-strings
- Convert `%` formatting to f-strings
- Normalize quote style
- Replace string concat with join
- Remove unnecessary f-string prefix

**Rules:**
- `PG-S001`: Use f-string instead of .format()
- `PG-S002`: Use f-string instead of % formatting
- `PG-S003`: Unnecessary f-string
- `PG-S004`: Inconsistent quote style
- `PG-S005`: String concatenation in loop
- `PG-S006`: Format string argument mismatch

---

## Phase 3: Code Simplification Enhancement

### Module: `pyguard/lib/code_simplification.py` (Enhancement)

**Additional Patterns to Detect:**
1. **Boolean Simplification**
   - `if x == True:` → `if x:`
   - `if x == False:` → `if not x:`
   - `if x is True:` → `if x is True:` (keep, subtle difference)
   - `return True if condition else False` → `return condition`

2. **Comparison Simplification**
   - `len(x) == 0` → `not x`
   - `len(x) > 0` → `bool(x)`
   - `x == None` → `x is None`

3. **Control Flow**
   - Unnecessary `else` after `return`
   - Nested `if` that can be combined with `and`
   - `if not ... else ...` can be simplified

4. **Comprehensions**
   - `list()` around comprehension
   - Unnecessary comprehension when map/filter better
   - Dict comprehension opportunities

5. **Iterator Operations**
   - `for i in range(len(x)):` → `for i, item in enumerate(x):`
   - `x[i]` when iterating by index

**Rules:**
- `PG-C001`: Simplifiable boolean expression
- `PG-C002`: Use `not x` instead of `len(x) == 0`
- `PG-C003`: Unnecessary else after return
- `PG-C004`: Use enumerate() instead of range(len())
- `PG-C005`: Unnecessary list() around comprehension
- `PG-C006`: Nested if can be combined

---

## Phase 4: PEP 8 Comprehensive

### Module: `pyguard/lib/pep8_comprehensive.py`

**Complete pycodestyle (E/W) Coverage:**

**E1xx - Indentation:**
- E101: Indentation contains mixed spaces and tabs
- E111: Indentation is not a multiple of four
- E112: Expected an indented block
- E113: Unexpected indentation
- E114: Indentation is not a multiple of four (comment)
- E115: Expected an indented block (comment)
- E116: Unexpected indentation (comment)
- E117: Over-indented
- E121-E131: Continuation line indentation

**E2xx - Whitespace:**
- E201-E206: Whitespace issues
- E211: Whitespace before '('
- E221-E231: Whitespace around operators
- E241-E275: Whitespace issues

**E3xx - Blank Lines:**
- E301-E306: Expected/unexpected blank lines

**E4xx - Imports:**
- E401-E402: Import issues

**E5xx - Line Length:**
- E501: Line too long

**E7xx - Statements:**
- E701-E743: Multiple statements, naming

**E9xx - Runtime:**
- E901-E902: Syntax errors

**W1xx - Indentation Warning:**
- W191: Indentation contains tabs

**W2xx - Whitespace Warning:**
- W291-W293: Trailing whitespace

**W3xx - Blank Line Warning:**
- W391: Blank line at end of file

**W5xx - Line Break Warning:**
- W503-W504: Line break before/after binary operator

**W6xx - Deprecation Warning:**
- W601-W606: Deprecated features

**Auto-fix:** Most E/W codes can be auto-fixed

---

## Phase 5: Modern Python Idioms

### Module: `pyguard/lib/modern_python.py` (Enhancement)

**Additional Patterns:**
1. **Pathlib vs os.path**
   - `os.path.exists()` → `Path.exists()`
   - `os.path.join()` → `Path() / "subdir"`
   - `open()` → `Path.read_text()` / `Path.write_text()`

2. **Dict Operations**
   - `if key in dict: x = dict[key] else: x = default` → `dict.get(key, default)`
   - Manual dict building → comprehension

3. **Modern Syntax**
   - `subprocess.call()` → `subprocess.run()`
   - Old string methods → modern equivalents
   - Context managers for file operations

4. **Type Hints**
   - `List` → `list` (Python 3.9+)
   - `Dict` → `dict` (Python 3.9+)
   - `Optional[X]` → `X | None` (Python 3.10+)

**Rules:**
- `PG-M001`: Use pathlib instead of os.path
- `PG-M002`: Use dict.get() instead of manual check
- `PG-M003`: Use subprocess.run() instead of call()
- `PG-M004`: Use modern type hint syntax (3.9+)
- `PG-M005`: Use context manager for file operations
- `PG-M006`: Use | for Union types (3.10+)

---

## Phase 6: Design Metrics

### Module: `pyguard/lib/design_metrics.py`

**Metrics to Calculate:**
1. **Cognitive Complexity**
   - Different from cyclomatic complexity
   - Measures understandability
   - Weights nested structures higher

2. **Class Design Metrics**
   - Too many public methods
   - Too many instance attributes
   - Too many ancestors
   - Too many dependencies

3. **Module Metrics**
   - Module cohesion
   - Coupling between modules
   - Maintainability index

4. **Function Metrics**
   - Parameter count
   - Local variable count
   - Return statement count
   - Nesting depth

**Rules:**
- `PG-D001`: Cognitive complexity too high
- `PG-D002`: Too many public methods
- `PG-D003`: Too many instance attributes
- `PG-D004`: Too deep inheritance
- `PG-D005`: Too many function parameters
- `PG-D006`: Too many local variables
- `PG-D007`: Too many return statements
- `PG-D008`: Nesting too deep

---

## Phase 7: Code Duplication

### Module: `pyguard/lib/duplication_detector.py`

**Detection Methods:**
1. **Exact Duplication**
   - Identical code blocks
   - Hash-based comparison

2. **Similar Code**
   - AST-based similarity
   - Structural similarity
   - Token-based similarity

3. **Copy-Paste Detection**
   - Similar variable names
   - Similar structure with minor differences

**Metrics:**
- Duplication percentage
- Duplicated line count
- Similar block detection

**Rules:**
- `PG-DUP001`: Exact code duplication detected
- `PG-DUP002`: Similar code blocks (consider refactoring)
- `PG-DUP003`: Duplicated string literals
- `PG-DUP004`: Copy-paste pattern detected

---

## Phase 8: Enhanced Documentation

### Module: `pyguard/lib/docstring_analyzer.py`

**Documentation Checks:**
1. **Completeness**
   - Missing docstrings
   - Missing parameter documentation
   - Missing return documentation
   - Missing raises documentation
   - Missing type information in docstring

2. **Style**
   - Docstring format (Google, NumPy, Sphinx)
   - Consistent style across project
   - First line imperative mood

3. **Accuracy**
   - Parameters in docstring match function signature
   - Return type matches docstring
   - Exceptions in docstring are actually raised

4. **Quality**
   - Vague descriptions
   - Too short docstrings
   - Example code in docstrings

**Rules:**
- `PG-DOC001`: Missing docstring
- `PG-DOC002`: Missing parameter documentation
- `PG-DOC003`: Missing return documentation
- `PG-DOC004`: Missing exception documentation
- `PG-DOC005`: Parameter mismatch in docstring
- `PG-DOC006`: Inconsistent docstring style
- `PG-DOC007`: Vague or incomplete description

**Auto-fix:**
- Generate docstring templates
- Add missing parameter documentation
- Fix parameter name mismatches

---

## Phase 9: Advanced Security

### Module: `pyguard/lib/security_advanced.py`

**Additional Security Patterns:**
1. **Framework-Specific**
   - Django security issues
   - Flask security issues
   - FastAPI security patterns

2. **API Security**
   - Missing authentication checks
   - Missing authorization checks
   - API rate limiting
   - CORS misconfiguration

3. **Additional Injection Types**
   - XPath injection
   - NoSQL injection
   - Template injection
   - Expression language injection

4. **Cryptography**
   - Weak key sizes
   - Hardcoded IVs
   - ECB mode usage
   - Insecure random in crypto

**Rules:**
- `PG-SEC001`: Django debug mode in production
- `PG-SEC002`: Flask secret_key hardcoded
- `PG-SEC003`: Missing CSRF protection
- `PG-SEC004`: XPath injection risk
- `PG-SEC005`: NoSQL injection risk
- `PG-SEC006`: Weak cryptographic key
- `PG-SEC007`: ECB mode encryption
- `PG-SEC008`: Missing rate limiting

---

## Phase 10: Integration & Polish

### Tasks:
1. **CLI Enhancement**
   - Add rule selection flags
   - Add category filtering
   - Add severity filtering
   - Progress bars for large codebases

2. **Configuration**
   - pyproject.toml integration
   - .pyguardrc support
   - Rule enable/disable
   - Severity customization

3. **Performance**
   - Parallel processing for all modules
   - Incremental analysis
   - Caching improvements

4. **Reporting**
   - Enhanced HTML reports
   - Rule coverage reports
   - Fix suggestions
   - Before/after comparisons

5. **Documentation**
   - Rule reference documentation
   - Migration guides from other tools
   - Configuration examples
   - Best practices guide

---

## Implementation Timeline

### Week 1-2: Phase 1 ✓ (COMPLETED)
- ✓ Rule engine framework
- ✓ Type checking system
- ✓ Import management
- ✓ Testing and integration

### Week 3: Phase 2
- String operations module
- F-string conversion
- Quote normalization
- Testing

### Week 4: Phase 3
- Code simplification enhancements
- Boolean simplification
- Iterator pattern improvements
- Testing

### Week 5: Phase 4
- PEP 8 comprehensive coverage
- All E/W code implementation
- Auto-fix for most rules
- Testing

### Week 6: Phase 5
- Modern Python idioms
- Pathlib conversions
- Modern syntax suggestions
- Testing

### Week 7: Phases 6-7
- Design metrics
- Code duplication detection
- Testing

### Week 8: Phases 8-9
- Enhanced documentation checks
- Advanced security patterns
- Testing

### Week 9-10: Phase 10
- CLI improvements
- Configuration system
- Performance optimization
- Comprehensive testing

---

## Success Metrics

### Coverage Goals:
- **Detection:** 800+ rules (matching Ruff)
- **Auto-fix:** 200+ auto-fixable rules
- **Test Coverage:** Maintain 70%+ coverage
- **Performance:** <100ms per file average
- **Quality:** Zero breaking changes

### Competitive Position:
After implementation, PyGuard will:
- ✓ Replace Ruff (detection + auto-fix)
- ✓ Replace Pylint (comprehensive checks)
- ✓ Replace Flake8 + plugins (all E/W/F/B codes)
- ✓ Replace Black (formatting)
- ✓ Replace isort (import sorting)
- ✓ Replace autopep8 (PEP 8 fixes)
- ✓ Replace mypy/pytype (basic type checking)
- ✓ Replace Bandit (security)
- ✓ Match Sonar (code quality + security)
- ✓ Match Codacy (comprehensive analysis)

### Unique Differentiators:
- ML-powered detection (existing)
- MCP integration (existing)
- Compliance frameworks (existing)
- All-in-one tool (new)
- Comprehensive auto-fix (new)
- Zero telemetry (always)

---

## Next Steps

1. **Immediate (Week 3):**
   - Implement Phase 2: String Operations
   - Create comprehensive test suite
   - Update documentation

2. **Short-term (Weeks 4-6):**
   - Implement Phases 3-5
   - CLI enhancements
   - Configuration system

3. **Medium-term (Weeks 7-10):**
   - Implement Phases 6-10
   - Performance optimization
   - Documentation completion
   - Release preparation

---

## Notes

- All new code follows existing PyGuard patterns
- Maintain backward compatibility
- Each phase is independently testable
- Progressive enhancement approach
- No breaking changes to existing API
