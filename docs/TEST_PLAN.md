# PyGuard Test Plan & Coverage Strategy

## Overview
This document outlines the comprehensive testing strategy for PyGuard, following PyTest Architect Agent best practices.

**Current Status:**
- Total Coverage: **87.33%**
- Line Coverage: 87.33%
- Branch Coverage: 84.45%
- Total Tests: 1,826 passing, 2 skipped
- Test Framework: pytest with strict configuration

## Testing Principles

### 1. Framework & Style
- **pytest** for all tests (not unittest style)
- **AAA Pattern**: Arrange – Act – Assert in every test
- **Naming Convention**: `test_<unit>_<scenario>_<expected>()`
- **Determinism**: Seeded RNG (1337), frozen time where needed
- **Isolation**: Each test stands alone, no inter-test dependencies

### 2. Coverage Goals
- **Target**: ≥90% line coverage, ≥85% branch coverage
- **Current**: 87.33% overall (moving towards target)
- **Focus**: Meaningful paths, edge cases, error handling

### 3. Test Organization
```
tests/
  ├── unit/               # Unit tests for all modules
  │   ├── test_*.py       # Test files matching module names
  │   └── __init__.py
  ├── integration/        # Integration tests
  ├── conftest.py         # Shared fixtures and configuration
  └── fixtures/           # Test data and fixtures
```

## Module Coverage Status

### High Priority (Already Enhanced)
✅ **debugging_patterns**: 99% (was 76%)
- Edge cases: syntax errors, read/write errors
- All detection patterns tested
- Auto-fix idempotency verified

✅ **naming_conventions**: 95% (was 79%)
- Async function naming
- Import alias conventions
- Ambiguous name detection
- Error handling paths

✅ **reporting**: 98% (was 79%)
- All reporter types (Console, JSON, HTML)
- Status determination logic
- Error handling for file operations
- Edge cases for metrics

✅ **pathlib_patterns**: 91% (was 80%)
- All os.path to pathlib conversions
- Import detection (including aliases)
- glob.glob patterns
- Error handling

### Medium Priority Modules (80-90%)

#### Near Target (85-90%)
- **advanced_security**: 86%
- **async_patterns**: 88%
- **datetime_patterns**: 87%
- **framework_flask**: 89%
- **git_hooks**: 89%
- **missing_auto_fixes**: 87%
- **modern_python**: 86%
- **pep8_comprehensive**: 87%
- **performance_checks**: 87%
- **type_checker**: 88%
- **ultra_advanced_fixes**: 87%

#### Needs Enhancement (80-85%)
- **bugbear**: 80%
- **code_simplification**: 83%
- **comprehensions**: 80%
- **enhanced_security_fixes**: 84%
- **fix_safety**: 83%
- **framework_django**: 84%
- **framework_pandas**: 84%
- **refurb_patterns**: 82%
- **string_operations**: 80%
- **supply_chain**: 80%
- **xss_detection**: 84%

### Low Priority (< 80%)
- **ast_analyzer**: 77%
- **pylint_rules**: 75%
- **ruff_security**: 74%
- **rule_engine**: 78%
- **ultra_advanced_security**: 78%

## Test Coverage Strategy

### What We Test (Priority Order)
1. ✅ **Public API** - All public functions and classes
2. ✅ **Happy Paths** - Expected normal operation
3. ✅ **Error Handling** - Exceptions, error messages, types
4. ✅ **Edge Cases** - Empty/None/zero/large/unicode inputs
5. ✅ **Boundary Conditions** - Min/max values, limits
6. ✅ **Branch Logic** - All if/elif/else, early returns
7. ✅ **State & Side Effects** - Filesystem, env vars, logs

### Testing Patterns Used

#### 1. Parametrization
```python
@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0),
        (1, 1),
        (-1, 1),
        (10**6, 10**12),
    ],
    ids=["zero", "one", "neg_one", "large"]
)
def test_square_value_returns_square(value, expected):
    result = square(value)
    assert result == expected
```

#### 2. Error Testing
```python
def test_parse_config_raises_on_missing_field(tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text('{"host": "x"}')
    with pytest.raises(KeyError, match="port"):
        parse_config(cfg)
```

#### 3. Fixtures for Setup
```python
@pytest.fixture
def sample_code():
    return """
    def example():
        pass
    """
```

#### 4. Mocking External Dependencies
```python
def test_fetch_uses_auth(mocker):
    mock_get = mocker.patch("module.requests.get")
    fetch_user("token", user_id=1)
    mock_get.assert_called_once()
```

## Quality Gates

### CI Requirements
- All tests must pass
- Coverage threshold: 87% (incrementing towards 90%)
- No deprecation warnings (strict)
- Randomized test order (--randomly-seed=1337)
- Branch coverage enabled

### Test Quality Checks
- ✅ Tests are deterministic (seeded RNG)
- ✅ No network calls (mocked)
- ✅ No real filesystem access (tmp_path)
- ✅ Fast execution (< 25s for full suite)
- ✅ Clear, descriptive test names
- ✅ Proper isolation between tests

## Fixture Guidelines

### Shared Fixtures (conftest.py)
- `_seed_rng`: Auto-use fixture for deterministic randomness
- `temp_dir`: Temporary directory for file operations
- `sample_vulnerable_code`: Common vulnerable code patterns
- `mock_logger`: Logger mock for testing
- `python_file_factory`: Create Python files for testing

### Best Practices
1. Keep fixtures small and composable
2. Use function scope by default
3. Document fixture purpose
4. Avoid fixture dependencies unless necessary

## Configuration

### pytest.ini / pyproject.toml
```toml
[tool.pytest.ini_options]
addopts = [
    "-ra",
    "-q",
    "--strict-config",
    "--strict-markers",
    "--maxfail=1",
    "--disable-warnings",
    "--randomly-seed=1337",
    "--cov=pyguard",
    "--cov-report=term-missing:skip-covered",
    "--cov-report=html",
    "--cov-report=xml",
    "--cov-branch",
]
testpaths = ["tests"]
xfail_strict = true
filterwarnings = [
    "error::DeprecationWarning",
    "error::PendingDeprecationWarning",
]

[tool.coverage.report]
fail_under = 87
skip_covered = true
show_missing = true
```

## Running Tests

### Full Suite
```bash
pytest tests/unit
```

### Specific Module
```bash
pytest tests/unit/test_security.py -v
```

### Coverage Report
```bash
pytest tests/unit --cov=pyguard --cov-report=html
```

### Fast Fail
```bash
pytest tests/unit --maxfail=1 -x
```

## Test Metrics

### Recent Improvements
- **debugging_patterns**: +23% coverage (76% → 99%)
- **naming_conventions**: +16% coverage (79% → 95%)
- **reporting**: +19% coverage (79% → 98%)
- **pathlib_patterns**: +11% coverage (80% → 91%)

### Overall Progress
- Initial: 86.84%
- Current: 87.33%
- Target: 90.00%
- Gap: 2.67%

## Next Steps

### Immediate Focus
1. Push remaining 80-85% modules to 90%
2. Address low-hanging fruit in 85-90% modules
3. Improve branch coverage in complex modules
4. Add property-based tests where applicable

### Long-term Goals
1. Maintain >90% coverage across all modules
2. Add mutation testing (mutmut)
3. Add performance benchmarks for hotspots
4. Implement snapshot testing for stable outputs

## Anti-Patterns to Avoid

❌ **Don't:**
- Write flaky tests with implicit time/randomness
- Mock implementation details
- Test multiple behaviors in one test
- Copy-paste tests (use parametrization)
- Use global mutable state
- Sleep in tests
- Make real network calls
- Access real filesystem (use tmp_path)

✅ **Do:**
- Write deterministic, isolated tests
- Mock behavior at boundaries
- Test one behavior per test
- Use parametrization for similar cases
- Reset state between tests
- Control time with freezegun
- Mock network calls
- Use temporary directories

## Contributing Tests

### Checklist for New Tests
- [ ] Follows AAA pattern
- [ ] Has descriptive name
- [ ] Tests one behavior
- [ ] Uses proper fixtures
- [ ] Handles edge cases
- [ ] Tests error paths
- [ ] Is deterministic
- [ ] Runs quickly (< 100ms typical)
- [ ] Properly isolated

### Review Guidelines
- All new code must have tests
- Tests should increase coverage
- Tests should be maintainable
- Follow existing patterns
- Document complex scenarios

---

**Last Updated**: 2025-10-17
**Coverage Target**: 90% (lines), 85% (branches)
**Current Coverage**: 87.33% (lines), 84.45% (branches)
