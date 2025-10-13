# PyGuard Linter Capability Gap Analysis

**Goal:** Make PyGuard capable of replacing ALL major Python linters for both detection AND auto-fix.

**Target Tools:** Ruff, Pylint, Flake8, Black, autopep8, pytype, Sonar, Codacy, PyChecker, Pylama

**Status:** Phase 1 Complete (46+ rules implemented) | ~700 rules remaining

## Executive Summary

PyGuard currently excels at security vulnerability detection (55+ checks) but lacks comprehensive code quality, style, and modern Python idiom detection compared to the ecosystem tools. To become a complete replacement for all Python linters, PyGuard needs approximately 700+ additional detection rules and 300+ auto-fix capabilities.

### Current Strengths

**Security (55+ rules) ✅ BEST IN CLASS**
- Code injection, SQL injection, command injection
- Unsafe deserialization, weak cryptography
- Path traversal, SSRF, XXE, LDAP injection
- Hardcoded secrets, timing attacks
- Supply chain security, SBOM generation
- Multi-framework compliance (OWASP, PCI-DSS, HIPAA, etc.)

**Code Quality (15+ rules) ✅ BASIC**
- Cyclomatic complexity, long methods
- Too many parameters, missing docstrings
- Mutable defaults, bare except, type checks

**Formatting ✅ DELEGATED**
- Black, isort, autopep8 integration

## Gap Analysis by Category

### 1. Ruff Gaps (~800 rules total, ~750 needed)

#### ✅ Phase 1 Implemented (50 rules)

**Modern Python (UP) - 10 rules**
- ✅ UP001: Old-style super()
- ✅ UP004: Six usage detection
- ✅ UP005: Unnecessary __future__ imports
- ✅ UP006: typing.List vs list (PEP 585)
- ✅ UP007: Optional/Union vs X | None (PEP 604)
- ✅ UP031: % formatting vs f-strings
- ✅ UP032: .format() vs f-strings

**Code Simplification (SIM) - 15 rules**
- ✅ SIM101: Multiple isinstance can be combined
- ✅ SIM102: Nested if statements
- ✅ SIM103: Return bool pattern
- ✅ SIM105: contextlib.suppress for try-except-pass
- ✅ SIM107: Return in try-else
- ✅ SIM108: Ternary operator for if-else
- ✅ SIM109: Redundant bool() calls
- ✅ SIM112: Environment variable naming
- ✅ SIM113: enumerate() vs manual counter
- ✅ SIM114: Duplicate if bodies
- ✅ SIM201-204: Compare to True/False with 'is'

**Performance (PERF) - 6 rules**
- ✅ PERF101: Try-except in loop
- ✅ PERF102: List concatenation in loop
- ✅ PERF402: Unnecessary type wrappers
- ✅ PERF403: dict() with list comprehension
- ✅ PERF404: .keys() in membership test
- ✅ PERF405: list[:] vs .copy()

**Unused Code (F, ARG) - 5 rules**
- ✅ F401: Unused imports (with auto-fix)
- ✅ F841: Unused variables
- ✅ ARG001: Unused function arguments

**Naming Conventions (N) - 10 rules**
- ✅ N801: Class names should use CamelCase
- ✅ N802: Function names should use snake_case
- ✅ N803: Argument names should use snake_case
- ✅ N806: Variable names should use snake_case
- ✅ N807: No custom __dunder__ names
- ✅ N811: Import alias naming
- ✅ E741: Ambiguous variable names (l, O, I)

#### ❌ Phase 2 Needed (150 rules)

**Modern Python (UP) - Remaining 40 rules**
- [ ] UP002: Unnecessary encode/decode
- [ ] UP003: Type() vs types module
- [ ] UP008: Use super() without arguments
- [ ] UP009: UTF-8 encoding declarations
- [ ] UP010-030: Various modernization patterns
- [ ] UP033-036: functools.lru_cache, abc.ABC, etc.

**Code Simplification (SIM) - Remaining 85 rules**
- [ ] SIM104: Use 'yield from'
- [ ] SIM106: Handle error cases first (guard clauses)
- [ ] SIM110: Use all() instead of loop
- [ ] SIM111: Use any() instead of loop
- [ ] SIM115-120: Various dict/set patterns
- [ ] SIM201-299: Comparison simplifications
- [ ] SIM300-400: Context manager simplifications

**Bugbear (B) - 50 rules**
- [ ] B001: Bare except without exception
- [ ] B002: Unary prefix increment
- [ ] B003: __eq__ without __hash__
- [ ] B004: hasattr() with default
- [ ] B005: .strip() with same character
- [ ] B006: Mutable default args in function def
- [ ] B007-050: Various common bugs

**Import Management (I, TID, TCH) - 50 rules**
- [ ] I001-025: isort rules (import ordering)
- [ ] TID001-020: Import tidy rules
- [ ] TCH001-010: Type checking imports

**Exception Handling (TRY) - 20 rules**
- [ ] TRY001-004: Exception raising patterns
- [ ] TRY200-203: Exception handling patterns
- [ ] TRY300-302: Exception type patterns
- [ ] TRY400-401: Logging in exceptions

**Return Issues (RET) - 15 rules**
- [ ] RET501: Unnecessary return None
- [ ] RET502: Implicit return None
- [ ] RET503: Missing explicit return
- [ ] RET504: Unnecessary variable before return
- [ ] RET505-508: Various return patterns

**Comprehensions (C4) - 15 rules**
- [ ] C400: Unnecessary generator
- [ ] C401-416: List/set/dict comprehension opportunities

**String Formatting (ISC, FLY) - 15 rules**
- [ ] ISC001-003: Implicit string concatenation
- [ ] FLY001-003: f-string improvements

**Debugging/Print (T10, T20) - 5 rules**
- [ ] T201-203: print() statements
- [ ] T10: Debugger statements (already have)

**Boolean Traps (FBT) - 5 rules**
- [ ] FBT001-003: Boolean positional arguments

**Annotations (ANN) - 15 rules**
- [ ] ANN001: Missing type annotation for function argument
- [ ] ANN002-003: *args, **kwargs annotations
- [ ] ANN101-102: Missing self/cls annotations
- [ ] ANN201-206: Missing return annotations
- [ ] ANN401: Any usage

**Async (ASYNC) - 15 rules**
- [ ] ASYNC100: Blocking calls in async
- [ ] ASYNC101: open() in async
- [ ] ASYNC102: Async function with no await
- [ ] ASYNC103-115: Various async patterns

**Refactor (FURB, PIE) - 30 rules**
- [ ] FURB001-050: Various refactoring opportunities
- [ ] PIE001-030: Code smell patterns

**Framework-Specific - 100 rules**
- [ ] DJ001-050: Django-specific checks
- [ ] PT001-050: pytest-specific checks
- [ ] FAST001-030: FastAPI-specific checks
- [ ] AIR001-020: Airflow-specific checks

**Pandas/NumPy (PD, NPY) - 30 rules**
- [ ] PD001-030: pandas anti-patterns
- [ ] NPY001-020: NumPy deprecations

### 2. Pylint Gaps (~200 rules)

**Code Smells - 50 rules**
- [ ] C0111-C0115: Missing docstrings (various types)
- [ ] C0200-C0209: Consider-using-* patterns
- [ ] C0301: Line too long (have basic)
- [ ] C0302: Too many lines in module
- [ ] C0321: Multiple statements on one line
- [ ] C0325-C0330: Bad whitespace patterns
- [ ] C0411-C0415: Import order/position

**Design Issues - 40 rules**
- [ ] R0901: Too many ancestors
- [ ] R0902: Too many instance attributes
- [ ] R0903: Too few public methods
- [ ] R0904: Too many public methods
- [ ] R0911: Too many return statements
- [ ] R0912: Too many branches
- [ ] R0913: Too many arguments (have this)
- [ ] R0914: Too many local variables
- [ ] R0915: Too many statements
- [ ] R0916: Too many boolean expressions

**Error Detection - 60 rules**
- [ ] E0001-E0015: Syntax errors and AST issues
- [ ] E0100-E0120: Class/method issues
- [ ] E0200-E0240: Attribute/member issues
- [ ] E0241-E0270: Import/module issues
- [ ] E1101-E1111: Variable/attribute errors
- [ ] E1120-E1125: Function call errors
- [ ] E1130-E1142: Sequence/iterator errors

**Warnings - 50 rules**
- [ ] W0101-W0125: Unreachable code warnings
- [ ] W0201-W0238: Attribute/method warnings
- [ ] W0301-W0331: Format/style warnings
- [ ] W0401-W0406: Import warnings
- [ ] W0601-W0640: Variable/global warnings

### 3. Pytype Gaps (~30 rules)

**Type Inference Without Annotations**
- [ ] Infer types from usage patterns
- [ ] Detect type mismatches
- [ ] Detect attribute errors
- [ ] Detect wrong argument types
- [ ] Detect missing return values
- [ ] Detect incompatible assignments

### 4. Black/Autopep8 Gaps (~50 native rules needed)

**Currently Delegated, Should Be Native**
- [ ] E101: Indentation contains mixed spaces/tabs
- [ ] E111-E117: Indentation issues
- [ ] E201-E203: Whitespace before/after punctuation
- [ ] E211: Whitespace before '('
- [ ] E221-E226: Missing/extra whitespace around operators
- [ ] E231: Missing whitespace after ':'
- [ ] E241-E251: Whitespace issues
- [ ] E261-E266: Comment formatting
- [ ] E271-E276: Keyword whitespace
- [ ] E301-E306: Blank line issues
- [ ] E401-E402: Import formatting
- [ ] E501: Line too long (have basic)
- [ ] E502: Backslash in statement
- [ ] E701-E706: Statement formatting
- [ ] W291-W293: Trailing whitespace
- [ ] W391: Blank line at end of file
- [ ] W503-W504: Line break around operators

### 5. Sonar/Codacy Gaps (~100 rules)

**Cognitive Complexity**
- [ ] Calculate cognitive complexity (different from cyclomatic)
- [ ] Detect deeply nested code
- [ ] Track decision points and nesting levels

**Code Duplication**
- [ ] Detect duplicate code blocks (3+ lines)
- [ ] Detect similar code patterns (token-based)
- [ ] Calculate duplication percentage

**Dead Code Detection**
- [ ] Detect unreachable code after return
- [ ] Detect unused functions
- [ ] Detect unused classes
- [ ] Detect unnecessary else after return

**Complexity Metrics**
- [ ] Lines of code (LOC) per file/class/function
- [ ] Comment density
- [ ] Function length distribution
- [ ] Maintainability index

**Security Patterns (Already Strong)**
- ✅ Most security patterns already covered
- [ ] Add SANS Top 25 mappings
- [ ] Add MITRE ATT&CK mappings

## Implementation Roadmap

### Phase 1: Critical Ruff Rules ✅ COMPLETE
**Status:** 50/200 rules (25% complete)
**Timeline:** Completed
**Focus:** Most impactful rules for everyday development

- ✅ Modern Python (UP) - 10 rules
- ✅ Code Simplification (SIM) - 15 rules
- ✅ Performance (PERF) - 6 rules
- ✅ Unused Code (F, ARG) - 5 rules
- ✅ Naming Conventions (N) - 10 rules

### Phase 2: Code Quality Rules ⏳ NEXT
**Status:** 0/150 rules
**Estimated Timeline:** 2-3 weeks
**Focus:** Completing critical Ruff rules + Pylint essentials

1. **Remaining Modern Python (UP)** - 40 rules
   - Type annotation modernization
   - Unnecessary imports and conversions
   - Deprecated syntax patterns

2. **Remaining Code Simplification (SIM)** - 85 rules
   - Iterator patterns (all, any, yield from)
   - Context manager improvements
   - Dictionary/set patterns

3. **Bugbear (B)** - 50 rules
   - Common mistakes and gotchas
   - Dangerous default arguments
   - Hash/equality issues

4. **Import Management (I, TID, TCH)** - 50 rules
   - Complete isort functionality
   - Type checking imports
   - Import organization

5. **Exception Handling (TRY)** - 20 rules
   - Proper exception patterns
   - Logging in exceptions
   - Error message quality

6. **Return Issues (RET)** - 15 rules
   - Unnecessary returns
   - Implicit returns
   - Return value consistency

7. **Comprehensions (C4)** - 15 rules
   - List/dict/set comprehension opportunities
   - Generator expressions
   - Performance optimizations

8. **Annotations (ANN)** - 15 rules
   - Type hint completeness
   - Any usage detection
   - Annotation quality

### Phase 3: Advanced Patterns 📅 PLANNED
**Status:** 0/150 rules
**Estimated Timeline:** 3-4 weeks
**Focus:** Framework-specific and advanced patterns

1. **Framework-Specific Rules** - 100 rules
   - Django best practices
   - pytest patterns
   - FastAPI patterns
   - Airflow DAG patterns

2. **Async Patterns (ASYNC)** - 15 rules
   - Blocking operations in async
   - Async/await best practices
   - Event loop management

3. **Pandas/NumPy (PD, NPY)** - 30 rules
   - Vectorization opportunities
   - Deprecated API usage
   - Performance anti-patterns

4. **String/Boolean (ISC, FLY, FBT)** - 35 rules
   - String concatenation patterns
   - f-string improvements
   - Boolean parameter traps

5. **Refactoring (FURB, PIE)** - 30 rules
   - Pathlib opportunities
   - Code smell detection
   - Modernization opportunities

### Phase 4: Polish & Advanced Analysis 📅 PLANNED
**Status:** 0/200 rules
**Estimated Timeline:** 4-6 weeks
**Focus:** Type inference, complexity, and code duplication

1. **Type Inference (Pytype)** - 30 rules
   - Type inference without annotations
   - Flow analysis
   - Attribute error detection

2. **Formatting (Native)** - 50 rules
   - Complete PEP 8 formatting
   - Whitespace normalization
   - Comment formatting

3. **Cognitive Complexity** - 20 rules
   - Nesting penalties
   - Decision point tracking
   - Readability scoring

4. **Code Duplication** - 30 rules
   - Clone detection (Type-1, Type-2, Type-3)
   - Similarity analysis
   - Refactoring opportunities

5. **Dead Code** - 20 rules
   - Unreachable code detection
   - Unused definition detection
   - Call graph analysis

6. **Pylint Remaining** - 50 rules
   - Design issues
   - Error detection
   - Warning patterns

## Auto-Fix Capabilities

### Currently Implemented (10 fixes)
- ✅ Remove unused imports
- ✅ Fix old-style super()
- ✅ Remove unnecessary __future__ imports
- ✅ Fix .keys() in membership tests
- ✅ Fix hardcoded passwords (add comments)
- ✅ Fix SQL injection patterns
- ✅ Fix command injection
- ✅ Fix weak crypto
- ✅ Fix YAML/pickle usage
- ✅ Format with Black/isort/autopep8

### Phase 2 Targets (50 fixes)
- [ ] Convert % formatting to f-strings
- [ ] Convert .format() to f-strings
- [ ] Remove unnecessary type wrappers
- [ ] Simplify if-return patterns
- [ ] Merge nested if statements
- [ ] Convert to ternary operators
- [ ] Add enumerate() for manual counters
- [ ] Replace try-except-pass with suppress()
- [ ] Fix comparison to True/False
- [ ] Convert to dict/list/set comprehensions
- [ ] Remove unnecessary else after return
- [ ] Fix import ordering
- [ ] Add type annotations (basic)
- [ ] Rename variables to snake_case
- [ ] Rename classes to CamelCase

### Phase 3 Targets (50 fixes)
- [ ] Convert to pathlib
- [ ] Simplify boolean expressions
- [ ] Remove duplicate code (suggest refactoring)
- [ ] Fix async/await patterns
- [ ] Modernize pandas operations
- [ ] Fix framework-specific patterns
- [ ] Convert to generator expressions
- [ ] Add context managers
- [ ] Fix string concatenation
- [ ] Remove dead code

### Phase 4 Targets (40 fixes)
- [ ] Infer and add type annotations
- [ ] Format whitespace (native)
- [ ] Fix indentation issues
- [ ] Normalize blank lines
- [ ] Fix comment formatting
- [ ] Extract duplicate code
- [ ] Refactor complex functions
- [ ] Simplify nested loops

## Success Metrics

### Coverage Targets
- **Detection Rules:** 700/~1000 ecosystem rules (70%)
- **Auto-Fix Rules:** 150/~300 possible fixes (50%)
- **Test Coverage:** >90% for new modules
- **Performance:** <100ms per 1000 LOC

### Quality Targets
- **False Positives:** <5% (industry standard: 10-20%)
- **False Negatives:** <10% (compared to running all tools)
- **Fix Correctness:** >95% (fixes should not break code)
- **User Satisfaction:** >80% (based on issue reports)

### Adoption Targets
- **Replace Ruff:** 80% of rules + better auto-fix
- **Replace Pylint:** 70% of rules + faster execution
- **Replace Black:** 100% formatting compatibility
- **Replace pytype:** 50% type inference (basic cases)
- **Unique Value:** Best-in-class security + all-in-one

## Competitive Advantages

PyGuard's unique position after full implementation:

1. **Security-First:** Best security detection in the ecosystem
2. **All-in-One:** One tool replaces 5+ tools
3. **Auto-Fix:** Most comprehensive auto-fix (150+ fixes)
4. **Performance:** Parallel processing, caching
5. **Standards:** 10+ compliance frameworks
6. **ML-Powered:** Risk scoring, anomaly detection
7. **Supply Chain:** SBOM, dependency scanning
8. **Privacy:** 100% local, zero telemetry
9. **Integration:** GitHub Security, SARIF, JSON
10. **Extensible:** Plugin architecture (future)

## References

- [Ruff Rules](https://docs.astral.sh/ruff/rules/) - Complete rule list
- [Pylint Messages](https://pylint.pycqa.org/en/latest/user_guide/messages/messages_overview.html) - All Pylint checks
- [Flake8 Rules](https://www.flake8rules.com/) - Flake8 error codes
- [PEP 8](https://peps.python.org/pep-0008/) - Style guide
- [Black](https://black.readthedocs.io/) - Formatter
- [Pytype](https://google.github.io/pytype/) - Type checker
- [OWASP ASVS](https://owasp.org/ASVS) - Security standard
- [CWE Top 25](https://cwe.mitre.org/top25/) - Common weaknesses

## Contributing

To add new rules:

1. Identify the rule category (UP, SIM, PERF, etc.)
2. Add detection logic to appropriate visitor class
3. Add auto-fix logic if applicable
4. Write comprehensive tests
5. Update this document
6. Submit PR with clear examples

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
