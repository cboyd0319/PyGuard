# Comprehensive PyGuard Test Plan
## PyTest Architect Agent - Test Suite Enhancement

### Executive Summary
This test plan follows **PyTest Architect Agent** best practices to achieve high-signal, maintainable test coverage for the PyGuard security and code quality tool. Target: **90%+ line coverage**, **85%+ branch coverage**.

### Current Coverage Status (Baseline)
- **Total Tests**: 1,754 passing, 3 skipped
- **Overall Coverage**: 85.58% (lines), meeting 84% threshold
- **Test Framework**: pytest with coverage, hypothesis, freezegun, pytest-mock
- **Execution Time**: ~30 seconds (acceptable for CI)

### Coverage Analysis by Priority

#### Priority 1: Critical Modules < 75% Coverage (High Risk)
These modules require immediate attention as they are below the 75% threshold:

1. **`pyguard/lib/unused_code.py`** - **70% coverage**
   - **Missing**: Lines 63, 77, 92, 94, 96, 98, 116->109, 139-185, 190->189, 196-198, 221, 241, 268, 305, 314-315, 329, 348->345, 351->345, 353->345, 365->372
   - **Gaps**: Assignment tracking, complex function argument patterns, nested scopes
   - **Tests Needed**:
     - Edge cases for assignment tracking (line 63, 77)
     - Positional-only and keyword-only argument handling (92, 94, 96, 98)
     - Complex nested function scenarios (139-185)
     - AsyncFunctionDef handling (196-198)
     - Lambda function tracking (221, 241)
     - Class variable usage (268, 305)
     - Error handling paths (314-315, 329)

2. **`pyguard/lib/type_checker.py`** - **72% coverage**
   - **Missing**: Lines 28, 32-52, 56, 61-75, 83-85, 90-134, 139-150, 154, 158-161, 237-262, 267-299, 311-313, 317-332, 345-368
   - **Gaps**: Type annotation parsing, complex type hints, error handling
   - **Tests Needed**:
     - Generic types (List[str], Dict[str, int])
     - Union types and Optional
     - Custom type annotations
     - Type checking edge cases
     - Error conditions for invalid types

3. **`pyguard/lib/refurb_patterns.py`** - **74% coverage**
   - **Missing**: Lines 40->59, 42->59, 43->59, 45->59, 89->104, 106->105, etc.
   - **Gaps**: Modern Python pattern detection and auto-fixes
   - **Tests Needed**:
     - All refactoring pattern detections
     - Edge cases for pattern matching
     - Safe fix application verification

4. **`pyguard/lib/ruff_security.py`** - **74% coverage**
   - **Missing**: Lines 51, 55-66, 148, 164, 180, 196, 212, 228, etc.
   - **Gaps**: Ruff security rule integration
   - **Tests Needed**:
     - All security rule detections
     - Rule configuration handling
     - Integration with Ruff output

#### Priority 2: Modules 75-80% Coverage (Medium Risk)
5. **`pyguard/lib/modern_python.py`** - **75% coverage**
6. **`pyguard/lib/performance_checks.py`** - **75% coverage**
7. **`pyguard/lib/pylint_rules.py`** - **75% coverage**
8. **`pyguard/lib/ast_analyzer.py`** - **77% coverage**
9. **`pyguard/lib/code_simplification.py`** - **77% coverage**
10. **`pyguard/lib/core.py`** - **78% coverage**
11. **`pyguard/lib/ultra_advanced_security.py`** - **78% coverage**
12. **`pyguard/lib/rule_engine.py`** - **78% coverage**
13. **`pyguard/lib/naming_conventions.py`** - **79% coverage**
14. **`pyguard/lib/reporting.py`** - **79% coverage**
15. **`pyguard/lib/ml_detection.py`** - **79% coverage**

#### Priority 3: Modules 80-85% Coverage (Low Risk)
16. **`pyguard/lib/bugbear.py`** - **80% coverage**
17. **`pyguard/lib/cache.py`** - **81% coverage**
18. **`pyguard/lib/exception_handling.py`** - **80% coverage**
19. **`pyguard/lib/git_hooks.py`** - **80% coverage**
20. **`pyguard/lib/supply_chain.py`** - **80% coverage**
21. **`pyguard/lib/string_operations.py`** - **80% coverage**
22. **`pyguard/lib/xss_detection.py`** - **84% coverage**

### Test Strategy by Category

#### 1. Unused Code Detection (`unused_code.py`)
**Current Coverage: 70% → Target: 90%**

**Test Matrix:**
| Feature | Happy Path | Edge Cases | Error Cases | Status |
|---------|-----------|------------|-------------|--------|
| Import tracking | ✅ | ⚠️ Partial | ❌ Missing | Needs work |
| From imports | ✅ | ⚠️ Partial | ❌ Missing | Needs work |
| Function arguments | ✅ | ⚠️ Partial | ❌ Missing | Needs work |
| Assignment tracking | ❌ Missing | ❌ Missing | ❌ Missing | **TODO** |
| Nested functions | ❌ Missing | ❌ Missing | ❌ Missing | **TODO** |
| Async functions | ❌ Missing | ❌ Missing | ❌ Missing | **TODO** |
| Lambda functions | ❌ Missing | ❌ Missing | ❌ Missing | **TODO** |
| Class variables | ❌ Missing | ❌ Missing | ❌ Missing | **TODO** |

**New Tests to Add:**
```python
# Test assignment tracking
def test_detect_unused_assignment()
def test_detect_unused_assignment_in_loop()
def test_detect_unused_tuple_unpacking()

# Test nested functions
def test_detect_unused_in_nested_function()
def test_detect_closure_variable_usage()
def test_detect_nonlocal_variable_usage()

# Test async patterns
def test_detect_unused_in_async_function()
def test_detect_unused_async_context_manager()

# Test lambda
def test_detect_unused_lambda_parameter()

# Test class variables
def test_detect_unused_class_variable()
def test_detect_unused_instance_variable()
def test_ignore_dunder_methods()

# Test edge cases
def test_handle_syntax_error_gracefully()
def test_empty_file_no_issues()
def test_star_import_handling()
def test_future_import_handling()

# Test positional-only and keyword-only args
def test_detect_unused_posonly_arg()
def test_detect_unused_kwonly_arg()
def test_detect_unused_vararg()
def test_detect_unused_kwarg()
```

#### 2. Type Checker (`type_checker.py`)
**Current Coverage: 72% → Target: 90%**

**New Tests to Add:**
```python
# Type annotation parsing
def test_parse_simple_type_hint()
def test_parse_generic_type_hint()
def test_parse_union_type_hint()
def test_parse_optional_type_hint()
def test_parse_callable_type_hint()
def test_parse_literal_type_hint()

# Type checking
def test_check_type_mismatch()
def test_check_return_type()
def test_check_argument_type()
def test_check_variable_annotation()

# Edge cases
def test_handle_invalid_type_annotation()
def test_handle_forward_reference()
def test_handle_string_annotation()
def test_handle_typing_extensions()

# Complex types
def test_nested_generic_types()
def test_type_var_usage()
def test_protocol_usage()
def test_type_alias_usage()
```

#### 3. Core Module (`core.py`)
**Current Coverage: 78% → Target: 90%**

**New Tests to Add:**
```python
# File operations edge cases
def test_read_file_encoding_errors()
def test_read_file_permission_denied()
def test_write_file_disk_full()
def test_atomic_write_failure()

# Logger edge cases
def test_logger_with_null_handler()
def test_logger_exception_during_log()
def test_logger_rich_not_available()

# Configuration edge cases
def test_config_load_invalid_json()
def test_config_load_invalid_toml()
def test_config_merge_conflicts()
def test_config_validation_failure()
```

### Test Quality Requirements

#### Coverage Gates (CI Enforcement)
```toml
[tool.coverage.report]
fail_under = 90  # Increased from 84
skip_covered = true
show_missing = true
```

#### Test Characteristics (All Tests Must Have)
- ✅ **AAA Pattern**: Arrange → Act → Assert clearly separated
- ✅ **Deterministic**: No time/random/network dependencies (seeded)
- ✅ **Isolated**: No shared state between tests
- ✅ **Fast**: < 100ms typical, < 500ms max per test
- ✅ **Focused**: One behavior per test
- ✅ **Named**: `test_<unit>_<scenario>_<expected>()`
- ✅ **Parametrized**: Use `@pytest.mark.parametrize` for input matrices

#### Required Test Patterns
1. **Happy Path**: Normal, expected usage
2. **Edge Cases**: Empty, None, zero, negative, large, Unicode
3. **Error Cases**: Invalid input, missing files, permissions
4. **Boundary**: Min/max values, limits
5. **Branch Coverage**: All if/elif/else paths

### Implementation Plan

#### Phase 1: Critical Modules (Week 1)
- [ ] **Day 1-2**: Enhance `unused_code.py` tests (70% → 90%)
  - Add 15 new test cases for missing coverage
  - Focus on nested functions, async, assignments
- [ ] **Day 3-4**: Enhance `type_checker.py` tests (72% → 90%)
  - Add 12 new test cases for type annotations
  - Test complex generic types and edge cases
- [ ] **Day 5**: Enhance `refurb_patterns.py` tests (74% → 85%)
  - Add pattern detection tests
  - Verify all auto-fixes

#### Phase 2: Medium Priority (Week 2)
- [ ] Enhance `modern_python.py` tests
- [ ] Enhance `performance_checks.py` tests
- [ ] Enhance `ast_analyzer.py` tests
- [ ] Enhance `code_simplification.py` tests
- [ ] Enhance `core.py` tests

#### Phase 3: Polish & Verification (Week 3)
- [ ] Add property-based tests with Hypothesis for algorithmic logic
- [ ] Add mutation testing with mutmut (target 85% kill rate)
- [ ] Review and optimize slow tests
- [ ] Update CI configuration
- [ ] Generate final coverage report

### Property-Based Testing Candidates

**Modules suitable for Hypothesis:**
1. **`ast_analyzer.py`**: AST traversal invariants
2. **`string_operations.py`**: String manipulation properties
3. **`formatting.py`**: Format preservation properties
4. **`comprehensions.py`**: List/dict comprehension equivalence

**Example Properties:**
```python
from hypothesis import given, strategies as st

@given(st.text())
def test_detect_issues_never_crashes(code):
    """Property: analyzer should never crash on any input."""
    # Arrange
    analyzer = UnusedCodeVisitor(code.splitlines())
    
    # Act & Assert: Should not raise
    try:
        tree = ast.parse(code)
        analyzer.visit(tree)
        analyzer.finalize()
    except SyntaxError:
        pass  # Expected for invalid Python

@given(st.lists(st.text(min_size=1)))
def test_import_detection_idempotent(imports):
    """Property: detecting imports multiple times gives same result."""
    code = "\n".join(f"import {imp}" for imp in imports)
    # Test that running detection twice gives same issues
```

### Mutation Testing Strategy

**Tools**: `mutmut` or `cosmic-ray`

**Target Modules for Mutation Testing:**
1. `security.py` - Critical security logic
2. `unused_code.py` - Complex detection logic
3. `rule_engine.py` - Core rule evaluation
4. `fix_safety.py` - Safe fix application

**Target Mutation Score**: ≥85%

### CI/CD Integration

**GitHub Actions Workflow Updates:**
```yaml
name: Comprehensive Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      
      - name: Install dependencies
        run: pip install -e .[dev]
      
      - name: Run tests with coverage
        run: |
          pytest tests/ \
            --cov=pyguard \
            --cov-report=term-missing:skip-covered \
            --cov-report=html \
            --cov-report=xml \
            --cov-branch \
            --cov-fail-under=90
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
      
      - name: Run mutation tests (on main branch)
        if: github.ref == 'refs/heads/main'
        run: |
          pip install mutmut
          mutmut run --paths-to-mutate=pyguard/lib/security.py
```

### Success Criteria

✅ **Phase Complete When:**
1. All modules ≥ 90% line coverage
2. All modules ≥ 85% branch coverage
3. No flaky tests (100 consecutive CI runs pass)
4. Average test execution time < 60 seconds
5. Mutation score ≥ 85% for critical modules
6. All tests follow AAA pattern
7. All tests are deterministic (seeded RNG, frozen time)
8. Documentation updated with testing guide

### Maintenance Plan

**Ongoing Requirements:**
- New code must include tests achieving 90%+ coverage
- PRs cannot reduce overall coverage
- Monthly mutation testing runs
- Quarterly test suite performance review
- Annual test architecture review

### Appendix: Test Fixtures Inventory

**Existing Fixtures (from conftest.py):**
- ✅ `_seed_rng`: Auto-applied RNG seeding
- ✅ `temp_dir`: Temporary directory
- ✅ `temp_file`: Temporary file factory
- ✅ `sample_vulnerable_code`: Security test samples
- ✅ `sample_bad_practices_code`: Best practice test samples
- ✅ `sample_modern_code`: Modernization test samples
- ✅ `sample_async_code`: Async pattern test samples
- ✅ `freeze_2025_01_01`: Time freezing fixture
- ✅ `env`: Environment variable setter
- ✅ `ast_tree_factory`: AST parsing factory
- ✅ `mock_file_system`: File system mock
- ✅ `capture_all_output`: Output capture helper
- ✅ `parametrized_code_samples`: Code sample library
- ✅ `assertion_helpers`: Common assertion patterns

**Fixtures to Add:**
- `mock_subprocess`: Subprocess execution mock
- `mock_network`: Network request mock
- `performance_timer`: Test performance measurement
- `memory_profiler`: Memory usage tracker
- `code_mutation_factory`: Generate mutated code for testing

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-16  
**Owner**: PyTest Architect Agent  
**Status**: In Progress
