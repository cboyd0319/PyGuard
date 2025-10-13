# PyGuard Next Implementation Priorities

**Date:** 2025-10-13
**Status:** Planning Phase
**Current Progress:** 151/800+ rules (19%)

## Executive Summary

Based on comprehensive analysis of PyGuard's current capabilities and gaps compared to Ruff, Pylint, Flake8, Black, autopep8, mypy/pytype, Sonar, and Codacy, this document outlines the highest-priority implementations to maximize PyGuard's value as an all-in-one Python linter replacement.

## Priority Ranking Strategy

**Criteria for prioritization:**
1. **Usage Frequency:** Most commonly triggered rules
2. **Auto-fix Value:** Rules that can be automatically fixed
3. **Impact:** High-value rules that catch serious issues
4. **Differentiation:** Rules that set PyGuard apart
5. **Quick Wins:** Rules that are easy to implement

## Top Priority Phases (Next 4-6 Weeks)

### Phase 9: Core Ruff Rules Completion (Week 8-9) 🔴 HIGH PRIORITY
**Target:** 100+ rules
**Est. Time:** 2 weeks
**Value:** HIGH - These are the most commonly used rules

#### 9.1: Import Improvements (I, TID, TCH) - 30 rules
- **Why:** Import issues are very common, auto-fixable
- **Rules:**
  - I001-I025: Complete isort implementation (native, not shelling out)
  - TID001-TID010: Tidy imports (relative/absolute consistency)
  - TCH001-TCH005: Type-checking imports
- **Auto-fix:** 25/30 rules fixable
- **Implementation:**
  - Enhance `import_manager.py`
  - Add import rewriting capabilities
  - Implement TYPE_CHECKING block detection

#### 9.2: Exception Handling Enhancements (TRY) - 10 more rules
- **Why:** Exception handling is critical for reliability
- **Rules (already have 8, need 10 more):**
  - TRY001: Avoid raising generic Exception types
  - TRY004: Type check without passing Exception
  - TRY100-TRY115: Additional exception patterns
  - TRY300-TRY302: Exception type improvements
- **Auto-fix:** 5/10 rules fixable
- **Implementation:**
  - Enhance `exception_handling.py`
  - Add exception type analysis
  - Implement exception chain validation

#### 9.3: Async/Await Patterns (ASYNC) - 15 rules
- **Why:** Async code is increasingly common
- **Rules:**
  - ASYNC100: Blocking calls in async functions
  - ASYNC101: open() in async function
  - ASYNC102: Async function with no await
  - ASYNC103-ASYNC115: Various async patterns
- **Auto-fix:** 8/15 rules fixable
- **Implementation:**
  - New module: `async_patterns.py`
  - Detect blocking operations in async context
  - Validate await usage

#### 9.4: String Formatting (ISC, FLY) - 12 rules
- **Why:** String handling is very common
- **Rules:**
  - ISC001-ISC003: Implicit string concatenation
  - FLY001-FLY003: f-string improvements
  - Additional string literal patterns
- **Auto-fix:** 10/12 rules fixable
- **Implementation:**
  - Enhance `string_operations.py`
  - Add implicit concatenation detection
  - Improve f-string analysis

#### 9.5: Debugging (T10, T20) - 5 rules
- **Why:** Quick win, commonly needed
- **Rules:**
  - T201-T203: print() statement detection
  - T100: Debugger statements (already have)
  - T20: pdb/ipdb/breakpoint detection
- **Auto-fix:** 2/5 rules fixable (can comment out)
- **Implementation:**
  - New module: `debugging_patterns.py`
  - Simple pattern matching
  - Auto-fix: comment out or remove

#### 9.6: Boolean Traps (FBT) - 5 rules
- **Why:** Improves code readability significantly
- **Rules:**
  - FBT001: Boolean positional argument
  - FBT002: Boolean default value
  - FBT003: Boolean return value
- **Auto-fix:** 1/5 rules (can add named parameters)
- **Implementation:**
  - New module: `boolean_traps.py`
  - Detect boolean parameters
  - Suggest keyword-only arguments

#### 9.7: Refactoring Opportunities (FURB, PIE) - 25 rules
- **Why:** Code quality improvements
- **Rules:**
  - FURB001-015: Pathlib opportunities
  - FURB016-030: Dict/list patterns
  - PIE001-015: Code smell detection
- **Auto-fix:** 15/25 rules fixable
- **Implementation:**
  - New module: `refactoring_opportunities.py`
  - Pathlib conversion detection
  - Modern Python pattern suggestions

### Phase 10: Type System Enhancement (Week 10) 🟡 MEDIUM PRIORITY
**Target:** 30+ rules
**Est. Time:** 1 week
**Value:** MEDIUM - Important for type-safe code

#### 10.1: Enhanced Type Checking - 15 rules
- **Rules:**
  - Type inference improvements
  - Generic type validation
  - Protocol/structural typing
  - TypedDict validation
  - Final reassignment detection
- **Auto-fix:** 5/15 rules (can add type hints)
- **Implementation:**
  - Enhance `type_checker.py`
  - Add basic type inference engine
  - Cross-function type flow analysis

#### 10.2: Annotation Quality (ANN) - 15 rules
- **Rules:**
  - ANN001-ANN003: Missing parameter annotations
  - ANN101-ANN102: self/cls annotations
  - ANN201-ANN206: Return type annotations
  - ANN401: Any usage detection (already have)
- **Auto-fix:** 10/15 rules (can add type hints based on inference)
- **Implementation:**
  - Enhance `type_checker.py`
  - Add annotation suggestion engine
  - Infer types from usage

### Phase 11: Code Quality & Metrics (Week 11) 🟡 MEDIUM PRIORITY
**Target:** 40+ rules
**Est. Time:** 1 week
**Value:** MEDIUM - Quality insights

#### 11.1: Code Duplication Detection - 10 rules
- **Rules:**
  - Exact duplication (Type-1 clones)
  - Renamed duplication (Type-2 clones)
  - Similar code (Type-3 clones)
  - Duplication percentage reporting
- **Auto-fix:** 2/10 rules (can suggest extraction)
- **Implementation:**
  - New module: `duplication_detector.py`
  - Token-based comparison
  - AST-based similarity
  - Rabin-Karp rolling hash for performance

#### 11.2: Design Metrics - 15 rules
- **Rules:**
  - Cognitive complexity (vs cyclomatic)
  - Too many methods/attributes
  - Too many ancestors
  - Too few public methods
  - Class cohesion metrics
- **Auto-fix:** 0/15 rules (informational)
- **Implementation:**
  - New module: `design_metrics.py`
  - Cognitive complexity calculator
  - Class structure analysis
  - Module organization metrics

#### 11.3: Dead Code Detection - 15 rules
- **Rules:**
  - Unreachable code after return/raise
  - Unused functions/classes
  - Unused methods
  - Unnecessary else after return
  - Dead code in conditionals (always True/False)
- **Auto-fix:** 10/15 rules (can remove)
- **Implementation:**
  - New module: `dead_code_detector.py`
  - Control flow graph analysis
  - Unused definition tracking
  - Constant folding for conditionals

### Phase 12: Framework-Specific Rules (Week 12-13) 🟢 LOW PRIORITY
**Target:** 80+ rules
**Est. Time:** 2 weeks
**Value:** MEDIUM - Specialized but valuable

#### 12.1: Django Patterns - 30 rules
- **Rules:**
  - DJ001-DJ030: Django best practices
  - Security patterns (SQL injection in ORM)
  - Model design issues
  - Template security
- **Auto-fix:** 10/30 rules
- **Implementation:**
  - New module: `framework_django.py`
  - Django-specific AST patterns
  - ORM security analysis

#### 12.2: Flask Patterns - 20 rules
- **Rules:**
  - FAST001-FAST020: Flask best practices
  - Route security
  - Blueprint organization
  - Template security
- **Auto-fix:** 8/20 rules
- **Implementation:**
  - New module: `framework_flask.py`
  - Route decorator analysis
  - Security header checking

#### 12.3: pytest Patterns - 20 rules
- **Rules:**
  - PT001-PT020: pytest best practices
  - Test naming
  - Fixture usage
  - Assertion quality
- **Auto-fix:** 12/20 rules
- **Implementation:**
  - New module: `framework_pytest.py`
  - Test structure analysis
  - Fixture dependency analysis

#### 12.4: FastAPI Patterns - 10 rules
- **Rules:**
  - FAST001-FAST010: FastAPI best practices
  - Dependency injection
  - Response models
  - Path operation design
- **Auto-fix:** 5/10 rules
- **Implementation:**
  - New module: `framework_fastapi.py`
  - Async route analysis
  - Pydantic integration

### Phase 13: Documentation Quality (Week 14) 🟢 LOW PRIORITY
**Target:** 40+ rules
**Est. Time:** 1 week
**Value:** MEDIUM - Code maintainability

#### 13.1: Docstring Quality - 25 rules
- **Rules:**
  - Completeness (all public APIs documented)
  - Parameter documentation
  - Return value documentation
  - Raises documentation
  - Style consistency (Google/NumPy/reST)
  - Example code validation
- **Auto-fix:** 15/25 rules (can generate templates)
- **Implementation:**
  - New module: `docstring_quality.py`
  - Docstring parser for multiple styles
  - Template generator
  - Parameter matching

#### 13.2: Comment Quality - 15 rules
- **Rules:**
  - TODO/FIXME tracking
  - Commented-out code detection
  - Comment spelling
  - Comment density metrics
  - Outdated comments
- **Auto-fix:** 5/15 rules
- **Implementation:**
  - New module: `comment_quality.py`
  - Comment extraction and analysis
  - Code pattern detection

### Phase 14: Remaining Pylint Rules (Week 15-16) 🟡 MEDIUM PRIORITY
**Target:** 150+ rules
**Est. Time:** 2 weeks
**Value:** MEDIUM - Comprehensive coverage

#### 14.1: Design Issues (R) - 40 rules
- **Rules:**
  - R0901-R0916: Class/method design
  - Too many arguments/locals/branches
  - Complexity metrics
- **Auto-fix:** 5/40 rules
- **Implementation:**
  - Enhance `design_metrics.py`
  - Add Pylint-specific thresholds

#### 14.2: Error Detection (E) - 60 rules
- **Rules:**
  - E0001-E0015: Syntax/AST errors
  - E0100-E0240: Class/method issues
  - E1101-E1142: Variable/function errors
- **Auto-fix:** 20/60 rules
- **Implementation:**
  - New module: `error_detection.py`
  - Enhanced AST validation
  - Type error detection

#### 14.3: Warnings (W) - 50 rules
- **Rules:**
  - W0101-W0640: Various warnings
  - Unreachable code
  - Redefined names
  - Global variable usage
- **Auto-fix:** 25/50 rules
- **Implementation:**
  - New module: `warning_patterns.py`
  - Scope analysis
  - Name shadowing detection

## Implementation Guidelines

### Module Organization
```
pyguard/lib/
├── async_patterns.py          # Phase 9.3
├── boolean_traps.py           # Phase 9.6
├── debugging_patterns.py      # Phase 9.5
├── refactoring_opportunities.py  # Phase 9.7
├── duplication_detector.py    # Phase 11.1
├── design_metrics.py          # Phase 11.2 (enhance)
├── dead_code_detector.py      # Phase 11.3
├── docstring_quality.py       # Phase 13.1
├── comment_quality.py         # Phase 13.2
├── error_detection.py         # Phase 14.2
├── warning_patterns.py        # Phase 14.3
├── framework_django.py        # Phase 12.1
├── framework_flask.py         # Phase 12.2
├── framework_pytest.py        # Phase 12.3
├── framework_fastapi.py       # Phase 12.4
└── (enhance existing modules)
```

### Testing Standards
- Each new rule must have:
  - 3+ test cases (positive, negative, edge case)
  - Vulnerable/bad code example
  - Fixed/good code example
  - Edge cases documented
- Maintain 70%+ coverage
- Integration tests for multi-file scenarios

### Performance Requirements
- Target: < 100ms per 1000 LOC
- Use caching for expensive operations
- Parallel processing for directory scans
- Lazy loading for framework-specific rules

### Documentation Requirements
- Each module needs:
  - Module docstring with purpose
  - Rule list with IDs, severity, fixability
  - Examples in docstrings
  - Update IMPLEMENTATION_STATUS.md

## Success Metrics

### Phase 9 (Week 8-9)
- [ ] 100+ new rules
- [ ] 50+ auto-fixes
- [ ] Total: 251/800 rules (31%)
- [ ] Test coverage: 70%+ maintained
- [ ] Performance: < 100ms per 1000 LOC

### Phase 10 (Week 10)
- [ ] 30+ new rules
- [ ] 15+ auto-fixes
- [ ] Total: 281/800 rules (35%)
- [ ] Type inference working for simple cases

### Phase 11 (Week 11)
- [ ] 40+ new rules
- [ ] 12+ auto-fixes
- [ ] Total: 321/800 rules (40%)
- [ ] Duplication detection working

### Phase 12 (Week 12-13)
- [ ] 80+ new rules
- [ ] 35+ auto-fixes
- [ ] Total: 401/800 rules (50%)
- [ ] Framework-specific detection working

### Phase 13 (Week 14)
- [ ] 40+ new rules
- [ ] 20+ auto-fixes
- [ ] Total: 441/800 rules (55%)
- [ ] Docstring auto-generation working

### Phase 14 (Week 15-16)
- [ ] 150+ new rules
- [ ] 50+ auto-fixes
- [ ] Total: 591/800 rules (74%)
- [ ] Comprehensive Pylint coverage

## Risk Mitigation

### Technical Risks
1. **Performance degradation** with 600+ rules
   - Mitigation: Lazy loading, rule filtering, caching
   
2. **Test coverage drop** below 70%
   - Mitigation: Test-first development, coverage gates

3. **False positives** increase
   - Mitigation: Comprehensive testing, user feedback

### Resource Risks
1. **Time estimation** may be optimistic
   - Mitigation: Focus on high-value rules first
   
2. **Maintenance burden** with complex rules
   - Mitigation: Clear documentation, modular design

## Next Steps

1. **Immediate (This Week):**
   - Begin Phase 9.1: Import improvements
   - Set up module structure
   - Create test fixtures

2. **Short-term (Next 2 Weeks):**
   - Complete Phase 9
   - Start Phase 10

3. **Medium-term (Next Month):**
   - Complete Phases 10-11
   - Reassess priorities based on feedback

4. **Long-term (Next 2 Months):**
   - Complete Phases 12-14
   - Reach 70%+ rule coverage (560/800 rules)

## Conclusion

This plan provides a clear path to making PyGuard a comprehensive replacement for all major Python linters. By focusing on high-value, commonly-used rules first, we can deliver maximum value quickly while building toward complete coverage.

**Estimated Timeline:**
- **Weeks 8-9:** Phase 9 (Core Ruff rules) - 31% coverage
- **Week 10:** Phase 10 (Type system) - 35% coverage
- **Week 11:** Phase 11 (Quality metrics) - 40% coverage
- **Weeks 12-13:** Phase 12 (Frameworks) - 50% coverage
- **Week 14:** Phase 13 (Documentation) - 55% coverage
- **Weeks 15-16:** Phase 14 (Pylint rules) - 74% coverage

**Final Target:** 591/800 rules (74%) by end of Week 16, with remaining 209 rules for future phases.
