# PyGuard Comprehensive Test Plan

## Executive Summary

This document outlines the strategy to achieve **≥90% line and branch coverage** across all PyGuard modules, following pytest best practices and the PyTest Architect Agent playbook.

### Current State (Baseline)
- **Total Tests**: 1,443 passing, 2 skipped
- **Current Coverage**: 84% (below target of 90%)
- **Test Framework**: pytest with coverage, hypothesis, freezegun, pytest-mock
- **Configuration**: Already aligned with best practices (branch coverage, strict markers, deterministic seeds)

### Target State
- **Line Coverage**: ≥90%
- **Branch Coverage**: ≥85%
- **Test Quality**: Deterministic, isolated, fast (<100ms per test typical)
- **Maintainability**: Clear AAA pattern, parametrized tests, explicit fixtures

---

## Priority Modules for Test Enhancement

### Tier 1: Critical Low Coverage (<70%)

#### 1. `pyguard/lib/ui.py` (25.3% coverage) - **HIGHEST PRIORITY**
**Module Purpose**: Enhanced console UI and HTML report generation
**Test Strategy**:
- ✅ Test EnhancedConsole color rendering, progress bars, tables
- ✅ Test ModernHTMLReporter report generation with various issue sets
- ✅ Test accessibility features (ARIA labels, semantic HTML)
- ✅ Test edge cases: empty results, malformed data, Unicode content
- ✅ Mock Rich library components for isolation
- ✅ Snapshot tests for HTML output structure

**Missing Coverage Areas**:
- HTML template generation edge cases
- Error handling for malformed input
- Console rendering with different terminal capabilities
- Export functionality

**New Tests Needed**: ~30-40 tests

#### 2. `pyguard/cli.py` (61.3% coverage)
**Module Purpose**: Main CLI entry point and command handling
**Test Strategy**:
- ✅ Test all CLI commands with valid/invalid arguments
- ✅ Test file path resolution and glob patterns
- ✅ Test output formatting options (json, sarif, html, console)
- ✅ Test error handling for missing files, permissions
- ✅ Test configuration loading from various sources
- ✅ Use CliRunner or subprocess for integration-style tests
- ✅ Mock file I/O and external tool calls

**Missing Coverage Areas**:
- CLI argument parsing edge cases
- Configuration precedence (CLI > file > defaults)
- Error messages and exit codes
- Watch mode integration
- Parallel processing flag handling

**New Tests Needed**: ~25-35 tests

#### 3. `pyguard/lib/refurb_patterns.py` (62.5% coverage)
**Module Purpose**: Modern Python refactoring patterns
**Test Strategy**:
- ✅ Parametrized tests for each refurb pattern
- ✅ Test pattern detection across Python 3.11-3.13 features
- ✅ Test fix application and code transformation
- ✅ Test combinations of multiple patterns in same file
- ✅ Negative tests: code that should NOT trigger patterns

**Missing Coverage Areas**:
- Complex nested pattern detection
- Pattern interaction and fix ordering
- Edge cases in AST traversal
- Python version-specific features

**New Tests Needed**: ~40-50 tests

### Tier 2: Moderate Low Coverage (70-85%)

#### 4. `pyguard/lib/pylint_rules.py` (69.7% coverage)
**Module Purpose**: Pylint integration and custom rules
**Test Strategy**:
- ✅ Test each Pylint rule detection
- ✅ Test rule configuration and severity levels
- ✅ Test suppression mechanisms
- ✅ Test interaction with Pylint API

**New Tests Needed**: ~20-25 tests

#### 5. `pyguard/lib/watch.py` (71.2% coverage)
**Module Purpose**: File watching and auto-fix on save
**Test Strategy**:
- ✅ Mock watchdog filesystem events
- ✅ Test debouncing logic
- ✅ Test file change detection and filtering
- ✅ Test graceful shutdown
- ✅ Use tmp_path for isolated filesystem tests

**New Tests Needed**: ~15-20 tests

#### 6. `pyguard/lib/unused_code.py` (75.7% coverage)
**Module Purpose**: Dead code detection
**Test Strategy**:
- ✅ Test unused import detection
- ✅ Test unused variable detection
- ✅ Test unused function detection
- ✅ Test false positive prevention (magic methods, __all__)

**New Tests Needed**: ~15-20 tests

#### 7. `pyguard/lib/type_checker.py` (76.4% coverage)
**Module Purpose**: Type checking and inference
**Test Strategy**:
- ✅ Test type inference for various expressions
- ✅ Test type compatibility checking
- ✅ Test generic types and type variables
- ✅ Property-based tests with hypothesis for type operations

**New Tests Needed**: ~20-25 tests

#### 8. Framework Integration Modules (69-78% coverage)
- `framework_django.py` (69.4%)
- `framework_pandas.py` (72.6%)
- `framework_pytest.py` (77.5%)

**Test Strategy**:
- ✅ Mock framework imports (don't require actual Django/pandas installation)
- ✅ Test framework-specific pattern detection
- ✅ Test false positives prevention
- ✅ Test framework version compatibility

**New Tests Needed**: ~15-20 tests each

#### 9. `pyguard/lib/security.py` (77.5% coverage)
**Module Purpose**: Security vulnerability detection
**Test Strategy**:
- ✅ Comprehensive tests for each CWE pattern
- ✅ Test security fix application
- ✅ Test severity assessment
- ✅ Negative tests: secure code patterns

**New Tests Needed**: ~20-25 tests

#### 10. `pyguard/lib/best_practices.py` (77.8% coverage)
**Module Purpose**: Python best practices enforcement
**Test Strategy**:
- ✅ Test each best practice rule
- ✅ Test fix suggestions
- ✅ Test edge cases and false positives

**New Tests Needed**: ~20-25 tests

#### 11. `pyguard/lib/core.py` (79.7% coverage)
**Module Purpose**: Core utilities (BackupManager, DiffGenerator, Logger)
**Test Strategy**:
- ✅ Test backup creation and restoration
- ✅ Test diff generation accuracy
- ✅ Test logger output levels and formatting
- ✅ Test error handling in file operations

**New Tests Needed**: ~15-20 tests

#### 12. `pyguard/lib/rule_engine.py` (82.0% coverage)
**Module Purpose**: Pluggable rule system
**Test Strategy**:
- ✅ Test rule registration and lookup
- ✅ Test rule execution pipeline
- ✅ Test rule priority and ordering
- ✅ Test rule applicability checks

**New Tests Needed**: ~15-18 tests

#### 13. `pyguard/lib/ast_analyzer.py` (83.5% coverage)
**Module Purpose**: AST-based code analysis
**Test Strategy**:
- ✅ Test AST visitor patterns
- ✅ Test complex code constructs
- ✅ Test error recovery on malformed AST
- ✅ Property tests for AST transformations

**New Tests Needed**: ~20-25 tests

### Tier 3: Near Target Coverage (85-90%)

#### 14. Modules at 84-90% (14 modules)
**Test Strategy**:
- ✅ Review coverage reports for missing branches
- ✅ Add targeted tests for uncovered paths
- ✅ Focus on error handling and edge cases
- ✅ Add boundary tests (empty, None, large inputs)

**New Tests Needed**: ~5-10 tests each (~70-140 total)

---

## Test Development Patterns

### 1. Parametrization Strategy
```python
@pytest.mark.parametrize(
    "input_code, expected_issues",
    [
        # Happy path
        ("x = 1", []),
        # Security issue
        ("eval(user_input)", ["S001-EVAL-USAGE"]),
        # Edge case: empty
        ("", []),
        # Boundary: complex expression
        ("x = (lambda: eval('1+1'))()", ["S001-EVAL-USAGE"]),
    ],
    ids=["valid", "eval-usage", "empty", "nested-eval"]
)
def test_detect_security_issues(input_code, expected_issues):
    issues = detect(input_code)
    assert [i.code for i in issues] == expected_issues
```

### 2. Fixture Composition
```python
@pytest.fixture
def analyzer(mock_logger):
    """Create analyzer with mocked logger."""
    return SecurityAnalyzer(logger=mock_logger)

@pytest.fixture
def vulnerable_code(tmp_path):
    """Create temp file with vulnerable code."""
    file = tmp_path / "test.py"
    file.write_text('eval(input())')
    return file
```

### 3. Error Handling Tests
```python
def test_parse_invalid_file_raises_clear_error(tmp_path):
    bad_file = tmp_path / "bad.py"
    bad_file.write_text("def foo(\n")  # Syntax error
    
    with pytest.raises(SyntaxError, match="unexpected EOF"):
        parse_file(bad_file)
```

### 4. Property-Based Tests (hypothesis)
```python
from hypothesis import given, strategies as st

@given(st.text())
def test_sanitize_preserves_length_or_reduces(user_input):
    sanitized = sanitize(user_input)
    assert len(sanitized) <= len(user_input)
    assert isinstance(sanitized, str)
```

### 5. Mocking External Dependencies
```python
def test_cli_calls_security_scanner(mocker, tmp_path):
    mock_scan = mocker.patch("pyguard.cli.SecurityScanner.scan")
    
    result = cli_main(["scan", str(tmp_path)])
    
    mock_scan.assert_called_once()
    assert result.exit_code == 0
```

---

## Coverage Measurement Strategy

### Tools
- `pytest-cov` with branch coverage enabled
- `coverage.py` for detailed reports
- Optional: `mutmut` for mutation testing on critical modules

### Targets
- **Global**: 90% line, 85% branch
- **Critical modules** (security, core): 95%+ line, 90%+ branch
- **New code**: 100% line + branch requirement

### Monitoring
```bash
# Run with coverage
pytest --cov=pyguard --cov-report=term-missing --cov-branch

# Generate HTML report
pytest --cov=pyguard --cov-report=html

# Check coverage against threshold
pytest --cov=pyguard --cov-fail-under=90
```

---

## Test Execution Plan

### Phase 1: Foundation (Week 1)
- ✅ Enhance ui.py tests → 90%+ coverage
- ✅ Enhance cli.py tests → 90%+ coverage
- ✅ Verify test infrastructure and fixtures

### Phase 2: Core Modules (Week 2)
- ✅ Enhance refurb_patterns.py tests
- ✅ Enhance pylint_rules.py tests
- ✅ Enhance security.py tests
- ✅ Enhance best_practices.py tests

### Phase 3: Specialized Modules (Week 3)
- ✅ Enhance framework integration tests
- ✅ Enhance type_checker.py tests
- ✅ Enhance unused_code.py tests
- ✅ Enhance watch.py tests

### Phase 4: Refinement (Week 4)
- ✅ Target all 85-90% modules
- ✅ Add property-based tests
- ✅ Review and optimize slow tests
- ✅ Final coverage validation

---

## Quality Assurance Checklist

### Per Module
- [ ] All public functions have ≥3 tests (happy, error, edge)
- [ ] All branches in if/elif/else covered
- [ ] All exception handlers tested
- [ ] Mocks used for external dependencies
- [ ] No flaky tests (deterministic seeds, frozen time)
- [ ] Test names follow convention: `test_<unit>_<scenario>_<expected>`
- [ ] Docstrings on complex tests
- [ ] Parametrization used for input matrices

### Global
- [ ] No inter-test dependencies
- [ ] Tests run in <60 seconds total
- [ ] Coverage ≥90% line, ≥85% branch
- [ ] No skipped tests without clear JIRA/issue
- [ ] All warnings addressed
- [ ] CI passes on Python 3.11, 3.12, 3.13

---

## Risk Mitigation

### Risk: Breaking Existing Functionality
**Mitigation**: Run full test suite after each module enhancement

### Risk: Slow Test Suite
**Mitigation**: Profile tests with `pytest-benchmark`, parallelize with `pytest-xdist`

### Risk: Flaky Tests
**Mitigation**: Use deterministic fixtures, freeze time, seed RNGs, avoid real I/O

### Risk: Low-Value Tests (Testing Implementation Details)
**Mitigation**: Focus on public API contracts, not internal implementation

---

## Success Metrics

1. **Coverage**: ≥90% line, ≥85% branch across all modules
2. **Test Count**: ~1,700-2,000 total tests (up from 1,443)
3. **Test Quality**: No flakes, <60s total runtime
4. **Maintainability**: Clear test names, good use of fixtures/parametrization
5. **CI**: Green builds on all supported Python versions

---

## Implementation Notes

### Existing Strengths
✅ Excellent conftest.py with reusable fixtures
✅ Deterministic RNG seeding in place
✅ Coverage reporting configured correctly
✅ pytest.ini properly configured
✅ Good use of pytest-mock, freezegun available

### Areas to Enhance
- Add more edge case tests (empty, None, Unicode, large inputs)
- Increase use of hypothesis for property-based testing
- Mock more external dependencies (filesystem, network)
- Add more integration-style CLI tests
- Enhance error handling coverage

### Tools Already Configured
- pytest 8.4.2
- pytest-cov 7.0.0
- pytest-mock 3.15.1
- pytest-randomly 3.15.0
- pytest-benchmark 4.0.0
- freezegun 1.5.0
- hypothesis 6.100.0

---

## Estimated Effort

| Module | Current % | Target % | Tests to Add | Effort (hours) |
|--------|-----------|----------|--------------|----------------|
| ui.py | 25 | 90 | 35 | 8 |
| cli.py | 61 | 90 | 30 | 6 |
| refurb_patterns.py | 62 | 90 | 45 | 8 |
| pylint_rules.py | 70 | 90 | 25 | 5 |
| watch.py | 71 | 90 | 18 | 4 |
| Framework modules (3) | 70-78 | 90 | 45 | 9 |
| type_checker.py | 76 | 90 | 22 | 5 |
| security.py | 78 | 90 | 20 | 4 |
| best_practices.py | 78 | 90 | 20 | 4 |
| Others (25+) | 80-90 | 90 | 100 | 15 |
| **TOTAL** | **84** | **90** | **~360** | **68 hours** |

---

## Next Steps

1. Start with Tier 1 modules (ui.py, cli.py, refurb_patterns.py)
2. Create tests following AAA pattern and parametrization
3. Run coverage after each module
4. Iterate until ≥90% coverage achieved
5. Document any uncovered code with clear exclusion reasons
