# Comprehensive Test Plan for PyGuard/lib Modules

## Executive Summary

This document outlines a comprehensive testing strategy for all 60 Python modules under `pyguard/lib/`. The goal is to achieve:
- **≥90% line coverage** for all modules
- **≥85% branch coverage** for all modules
- **Comprehensive edge case and error path testing**
- **Deterministic, isolated, and maintainable tests**

## Current State (Baseline)

- **Total Tests**: 1,341 passing, 2 skipped
- **Overall Coverage**: 83% lines, ~78% branches
- **Test Infrastructure**: pytest, pytest-cov, pytest-mock in place
- **Existing Patterns**: Good use of fixtures, parametrization, and AAA pattern

## Module Coverage Analysis

### Priority 1: Critical Modules (<60% coverage)
1. **security.py** (57%) - Core security vulnerability fixing
2. **framework_django.py** (60%) - Django-specific patterns
3. **pylint_rules.py** (61%) - Pylint integration

### Priority 2: Low Coverage (60-70%)
4. **framework_pandas.py** (67%)
5. **refurb_patterns.py** (69%)
6. **watch.py** (69%)
7. **unused_code.py** (70%)

### Priority 3: Moderate Coverage (70-80%)
8. **framework_pytest.py** (72%)
9. **type_checker.py** (72%)
10. **best_practices.py** (73%)
11. **logging_patterns.py** (73%)
12. **ruff_security.py** (74%)
13. **modern_python.py** (75%)
14. **performance_checks.py** (75%)
15. **core.py** (76%)
16. **ast_analyzer.py** (77%)
17. **code_simplification.py** (77%)
18. **rule_engine.py** (78%)
19. **ultra_advanced_security.py** (78%)
20. **ml_detection.py** (79%)
21. **naming_conventions.py** (79%)
22. **reporting.py** (79%)

### Priority 4: Good Coverage (80-90%)
23-42. Various modules at 80-89% coverage

### Already Excellent (≥90%)
43-60. Modules with 90%+ coverage (maintain/enhance)

## Testing Strategy

### Phase 1: Infrastructure Enhancement (Complete)
- [x] Pytest configuration with branch coverage enabled
- [x] Shared fixtures in conftest.py
- [x] Test discovery patterns configured

### Phase 2: Fixtures & Test Utilities
Create comprehensive fixtures for:
- **Deterministic RNG**: Seeded random, numpy.random
- **Time freezing**: freezegun for time-dependent tests
- **Filesystem isolation**: tmp_path for all file operations
- **Mock external dependencies**: HTTP, DB, subprocess, etc.
- **Sample code fixtures**: Vulnerable code, best practices violations, etc.

### Phase 3: Systematic Module Enhancement

For each module, following this checklist:

#### A. API Surface Analysis
1. Enumerate all public functions/classes
2. Identify input/output contracts
3. List all error conditions and exceptions
4. Map branch decision points

#### B. Happy Path Testing
- Primary use cases
- Default parameter values
- Common input patterns

#### C. Edge Cases & Boundaries
- Empty inputs ([], "", None, 0)
- Large inputs (10^6 elements, long strings)
- Special values (NaN, inf, -0, Unicode)
- Type boundaries (int/float, str/bytes)

#### D. Error Paths
- Invalid inputs (wrong types, out of range)
- Exception raising and messages
- Error recovery behavior
- Graceful degradation

#### E. Branch Coverage
- All if/elif/else paths
- Early returns
- Guard clauses
- Loop iterations (0, 1, many)

#### F. Side Effects
- File system operations
- Environment variables
- Logging calls
- External API calls
- State mutations

#### G. Concurrency (where applicable)
- Async/await patterns
- Race conditions
- Deadlock prevention
- Timeout handling

## Test Patterns & Examples

### Pattern 1: Parametrized Table Tests
```python
@pytest.mark.parametrize(
    "input_code, expected_fix, expected_warning",
    [
        ("password = 'secret'", True, "hardcoded password"),
        ("api_key = ''", False, None),  # Empty string OK
        ("PASSWORD = 'test123'", True, "hardcoded password"),  # Case insensitive
    ],
    ids=["hardcoded_pwd", "empty_string_safe", "case_insensitive"]
)
def test_fix_hardcoded_passwords_parametrized(input_code, expected_fix, expected_warning):
    """Test hardcoded password detection with various inputs."""
    fixer = SecurityFixer()
    result = fixer._fix_hardcoded_passwords(input_code)
    if expected_fix:
        assert expected_warning.lower() in result.lower()
    else:
        assert result == input_code
```

### Pattern 2: Error Handling
```python
def test_security_fixer_handles_invalid_file(tmp_path):
    """Test that SecurityFixer gracefully handles non-existent files."""
    fixer = SecurityFixer()
    non_existent = tmp_path / "does_not_exist.py"
    
    success, fixes = fixer.fix_file(non_existent)
    
    assert not success
    assert fixes == []
```

### Pattern 3: Mocking External Dependencies
```python
def test_security_fixer_logs_success(mocker, tmp_path, sample_vulnerable_code):
    """Test that fixes are properly logged."""
    mock_logger = mocker.patch.object(SecurityFixer, 'logger')
    fixer = SecurityFixer()
    test_file = tmp_path / "test.py"
    test_file.write_text(sample_vulnerable_code)
    
    success, fixes = fixer.fix_file(test_file)
    
    assert success
    mock_logger.success.assert_called_once()
    call_args = mock_logger.success.call_args
    assert "security fixes" in call_args[0][0].lower()
```

### Pattern 4: Property-Based Testing (for complex algorithms)
```python
from hypothesis import given, strategies as st

@given(st.text())
def test_security_fixer_never_corrupts_syntax(code_text):
    """Property: SecurityFixer should never produce invalid Python syntax."""
    fixer = SecurityFixer()
    result = fixer._fix_hardcoded_passwords(code_text)
    
    # Result should either be valid Python or unchanged
    try:
        compile(result, '<string>', 'exec')
        assert True  # Valid syntax
    except SyntaxError:
        assert result == code_text  # Unchanged if already invalid
```

### Pattern 5: Filesystem Isolation
```python
def test_fix_file_writes_changes(tmp_path, sample_vulnerable_code):
    """Test that fix_file persists changes to disk."""
    test_file = tmp_path / "vulnerable.py"
    test_file.write_text(sample_vulnerable_code)
    original_content = test_file.read_text()
    
    fixer = SecurityFixer()
    success, fixes = fixer.fix_file(test_file)
    
    assert success
    assert len(fixes) > 0
    modified_content = test_file.read_text()
    assert modified_content != original_content
```

## Module-Specific Test Requirements

### security.py (Priority 1)
**Missing Coverage:**
- Empty file handling
- Files with only comments
- Multiple security issues in one file
- Nested function detection
- Edge cases in regex patterns (Unicode, escaped quotes)
- Error paths (file permission errors, disk full)
- All fix methods with edge inputs
- Legacy scan method with various patterns

**Required Tests:**
- 15 parametrized test cases for each fix method
- 5 error handling tests
- 10 edge case tests
- 3 integration tests (multiple fixes in one file)

### framework_django.py (Priority 1)
**Missing Coverage:**
- All Django-specific patterns
- Settings.py analysis
- View security patterns
- ORM query patterns
- Template security

**Required Tests:**
- 20 Django pattern tests
- 10 edge cases
- 5 error paths

### pylint_rules.py (Priority 1)
**Missing Coverage:**
- Rule application logic
- Multiple rule combinations
- Rule conflict resolution
- Configuration parsing

**Required Tests:**
- 25 rule-specific tests
- 10 combination tests
- 5 error paths

## Coverage Goals by Module

| Module | Current | Target | Missing Tests (Est.) |
|--------|---------|--------|---------------------|
| security.py | 57% | 90% | 35 tests |
| framework_django.py | 60% | 90% | 30 tests |
| pylint_rules.py | 61% | 90% | 30 tests |
| framework_pandas.py | 67% | 90% | 25 tests |
| refurb_patterns.py | 69% | 90% | 50 tests (large module) |
| watch.py | 69% | 90% | 20 tests |
| unused_code.py | 70% | 90% | 25 tests |
| ... (other modules) | ... | 90% | ~800 total tests |

## Quality Assurance

### Determinism Checklist
- [ ] All random operations use seeded RNG
- [ ] All time-dependent code uses freezegun
- [ ] No network calls (use mocks/responses)
- [ ] No sleep() calls (use time mocking)
- [ ] All filesystem ops use tmp_path

### Test Quality Metrics
- [ ] Every test has clear AAA structure
- [ ] Test names follow `test_<unit>_<scenario>_<expected>` pattern
- [ ] Complex tests have docstrings
- [ ] No copy-paste tests (use parametrization)
- [ ] No global state mutations
- [ ] Tests run in <100ms each (unit tests)

### Coverage Validation
```bash
# Run full test suite with branch coverage
pytest tests/unit/ --cov=pyguard/lib --cov-report=term-missing --cov-branch

# Per-module coverage check
pytest tests/unit/test_security.py --cov=pyguard/lib/security --cov-report=term

# Fail if coverage below threshold
pytest --cov=pyguard/lib --cov-fail-under=90 --cov-branch
```

### Mutation Testing (Optional)
```bash
# Install mutmut
pip install mutmut

# Run mutation tests on critical modules
mutmut run --paths-to-mutate=pyguard/lib/security.py

# Aim for >85% mutation kill rate
```

## Implementation Schedule

### Week 1: Priority 1 Modules (3 modules)
- security.py: 35 tests
- framework_django.py: 30 tests
- pylint_rules.py: 30 tests
**Total: ~95 tests**

### Week 2: Priority 2 Modules (4 modules)
- framework_pandas.py: 25 tests
- refurb_patterns.py: 50 tests
- watch.py: 20 tests
- unused_code.py: 25 tests
**Total: ~120 tests**

### Week 3: Priority 3 Modules (15 modules)
- Various 70-80% coverage modules
**Total: ~400 tests**

### Week 4: Priority 4 + Polish
- Remaining modules
- Mutation testing
- Documentation
- CI integration
**Total: ~200 tests**

## Success Criteria

1. ✅ All modules achieve ≥90% line coverage
2. ✅ All modules achieve ≥85% branch coverage
3. ✅ Zero flaky tests (pytest-randomly passes 100 times)
4. ✅ All tests pass in <60 seconds total
5. ✅ Mutation kill rate ≥85% for critical modules
6. ✅ No violations of test quality checklist
7. ✅ CI integration complete and passing

## Risk Mitigation

### Risk: Tests too slow
**Mitigation**: Use mocks for I/O, avoid real filesystem where possible

### Risk: Flaky tests
**Mitigation**: Seed all RNG, freeze time, use pytest-randomly

### Risk: Over-mocking (brittle tests)
**Mitigation**: Mock at boundaries, test behaviors not implementations

### Risk: Low mutation kill rate
**Mitigation**: Add assertion diversity, test invariants not just happy paths

## Continuous Improvement

1. Run pytest-randomly with different seeds weekly
2. Review coverage reports monthly for regressions
3. Add property-based tests for algorithmic code
4. Collect metrics on test execution time
5. Refactor slow or brittle tests proactively

## References

- pytest documentation: https://docs.pytest.org/
- pytest-cov: https://pytest-cov.readthedocs.io/
- hypothesis: https://hypothesis.readthedocs.io/
- freezegun: https://github.com/spulec/freezegun
- mutmut: https://mutmut.readthedocs.io/
