# PyGuard Testing Guide

This guide covers best practices for running and writing tests for PyGuard, following the PyTest Architect Agent principles.

## Quick Start

### Running All Tests

```bash
# Run all tests with coverage
pytest

# Run tests without coverage (faster for development)
pytest --no-cov

# Run tests in parallel (requires pytest-xdist)
pytest -n auto

# Run tests without slow tests
pytest -m "not slow"
```

### Running Specific Test Categories

```bash
# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# Specific test file
pytest tests/unit/test_cache.py

# Specific test function
pytest tests/unit/test_cache.py::TestAnalysisCache::test_cache_hit

# Tests by marker
pytest -m security
pytest -m "unit and not slow"
```

## Test Performance

### Current Performance Metrics

- **Total tests**: 2,369 tests
- **Full suite runtime**: ~22-25 seconds (sequential)
- **Expected parallel runtime**: ~8-12 seconds (with -n auto)
- **Unit tests**: ~15 seconds
- **Integration tests**: ~7-10 seconds

### Performance Best Practices

1. **Use fixtures efficiently**: Prefer function scope unless session/module scope is needed
2. **Avoid sleep()**: Use `freezegun` for time control or polling with timeouts
3. **Mark slow tests**: Use `@pytest.mark.slow` for tests > 500ms
4. **Use parallel execution**: Run with `-n auto` for faster CI builds
5. **Skip coverage in development**: Use `--no-cov` when iterating

### Slow Test Markers

Tests marked as `@pytest.mark.slow` take > 500ms:

```bash
# Skip slow tests during development
pytest -m "not slow"

# Run only slow tests (e.g., before committing)
pytest -m slow
```

Current slow tests:
- Integration batch processing tests (~2s)
- Large file processing tests (~0.7s)
- Property-based tests with hypothesis (~2s)

## Test Categories & Markers

PyGuard uses pytest markers to categorize tests:

- `@pytest.mark.unit` - Fast, isolated unit tests
- `@pytest.mark.integration` - Integration tests with file I/O
- `@pytest.mark.slow` - Tests taking > 500ms
- `@pytest.mark.security` - Security-specific tests
- `@pytest.mark.best_practices` - Code quality tests
- `@pytest.mark.formatting` - Code formatting tests

## Writing Tests

### Test Structure (AAA Pattern)

All tests follow the **Arrange-Act-Assert** pattern:

```python
def test_cache_stores_and_retrieves_data(temp_dir):
    """Test cache can store and retrieve analysis results."""
    # Arrange
    cache = AnalysisCache(cache_dir=temp_dir)
    test_file = temp_dir / "test.py"
    test_file.write_text("print('hello')")
    results = {"issues": [], "fixes": []}
    
    # Act
    cache.set(test_file, results)
    retrieved = cache.get(test_file)
    
    # Assert
    assert retrieved == results
```

### Using Fixtures

PyGuard provides comprehensive fixtures in `tests/conftest.py`:

```python
def test_with_temp_file(temp_dir, temp_file):
    """Example using fixtures."""
    # temp_dir: Temporary directory (Path object)
    # temp_file: Factory to create temp files
    
    test_file = temp_file("test.py", "print('hello')")
    assert test_file.exists()
```

Common fixtures:
- `temp_dir` - Temporary directory
- `temp_file` - Factory to create temp files
- `sample_vulnerable_code` - Sample code with vulnerabilities
- `mock_logger` - Mock logger for testing
- `freeze_2025_01_01` - Freeze time for deterministic tests
- `env` - Set environment variables safely

### Time Control with Freezegun

**Never use `time.sleep()` in tests**. Use `freezegun` instead:

```python
from freezegun import freeze_time

def test_cache_expiration():
    """Test cache entry expiration."""
    cache = AnalysisCache(max_age_hours=1/3600)
    
    # Set cache at time T
    with freeze_time("2025-01-01 00:00:00"):
        cache.set(test_file, data)
        assert cache.is_cached(test_file)
    
    # Advance time past expiration
    with freeze_time("2025-01-01 00:00:02"):
        cache._clean_expired()
        assert not cache.is_cached(test_file)
```

### Parametrized Tests

Use `@pytest.mark.parametrize` for testing multiple inputs:

```python
@pytest.mark.parametrize(
    "input_code,expected_issue",
    [
        ("password = 'secret'", "hardcoded_password"),
        ("query = 'SELECT * FROM ' + user", "sql_injection"),
        ("eval(user_input)", "eval_usage"),
    ],
    ids=["password", "sql", "eval"]
)
def test_security_detector_finds_issues(input_code, expected_issue):
    """Test security detector identifies vulnerabilities."""
    detector = SecurityDetector()
    issues = detector.detect(input_code)
    assert any(i.rule_id == expected_issue for i in issues)
```

### Property-Based Tests

Use `hypothesis` for algorithmic testing:

```python
from hypothesis import given
from hypothesis import strategies as st

@pytest.mark.slow
@given(st.text(min_size=0, max_size=1000))
def test_fixer_never_returns_none(code):
    """Property: Fixers always return a string."""
    fixer = SecurityFixer()
    result = fixer.fix_code(code)
    assert result is not None
    assert isinstance(result, str)
```

### Async Tests

Use `pytest.mark.asyncio` for async code:

```python
import pytest

@pytest.mark.asyncio
async def test_async_analyzer_processes_file(temp_file):
    """Test async analyzer processes files correctly."""
    test_file = temp_file("test.py", "import yaml")
    analyzer = AsyncAnalyzer()
    
    result = await analyzer.analyze(test_file)
    
    assert result is not None
    assert len(result.issues) > 0
```

## Coverage

### Running with Coverage

```bash
# Full coverage report
pytest

# Coverage for specific module
pytest --cov=pyguard.lib.cache --cov-report=term-missing

# HTML coverage report (opens in browser)
pytest --cov-report=html
open htmlcov/index.html
```

### Coverage Requirements

- **Minimum coverage**: 87% (enforced in CI)
- **Target for new code**: 90%+ lines, 85%+ branches
- **Pure functions**: Aim for 100% coverage

### Excluded from Coverage

These patterns are excluded (see `pyproject.toml`):
- `pragma: no cover` comments
- `__repr__` and `__str__` methods
- Abstract methods
- `if __name__ == "__main__"` blocks
- Type checking blocks (`if TYPE_CHECKING:`)

## Continuous Integration

### GitHub Actions Workflow

Tests run automatically on:
- Push to main branch
- Pull requests
- Scheduled nightly builds

```yaml
# .github/workflows/tests.yml
- name: Run tests
  run: |
    pip install -e .[dev]
    pytest --cov --cov-report=xml
    
- name: Upload coverage
  uses: codecov/codecov-action@v3
```

### Pre-commit Hooks

Run tests before committing:

```bash
# Install pre-commit
pip install pre-commit
pre-commit install

# Run manually
pre-commit run --all-files
```

## Debugging Tests

### Verbose Output

```bash
# Show detailed output
pytest -vv

# Show local variables on failure
pytest -l

# Show stdout/stderr
pytest -s

# Drop into debugger on failure
pytest --pdb
```

### Running Specific Tests

```bash
# Run failed tests from last run
pytest --lf

# Run failed tests first, then others
pytest --ff

# Stop after first failure
pytest -x

# Stop after N failures
pytest --maxfail=3
```

### Using pytest-benchmark

For performance testing:

```python
def test_analyzer_performance(benchmark):
    """Benchmark analyzer performance."""
    analyzer = CodeAnalyzer()
    code = "print('hello')" * 1000
    
    result = benchmark(analyzer.analyze, code)
    
    assert result is not None
```

## Best Practices

### DO ✅

- Use descriptive test names: `test_<unit>_<scenario>_<expected>`
- Follow AAA pattern (Arrange-Act-Assert)
- Use fixtures for common setup
- Use `freezegun` for time control
- Mark slow tests with `@pytest.mark.slow`
- Use parametrization for input matrices
- Write docstrings for complex tests
- Test both happy path and error cases
- Test edge cases (None, empty, zero, large values)

### DON'T ❌

- Use `time.sleep()` - use `freezegun` or polling with timeout
- Test implementation details - test behavior
- Share state between tests
- Use real network/filesystem without mocking
- Write tests dependent on execution order
- Use hardcoded paths - use `tmp_path` or fixtures
- Skip tests without a good reason and comment
- Write tests > 1000 lines - split into smaller files

## Troubleshooting

### Tests Are Slow

1. Run without coverage: `pytest --no-cov`
2. Use parallel execution: `pytest -n auto`
3. Skip slow tests: `pytest -m "not slow"`
4. Profile tests: `pytest --durations=20`

### Tests Are Flaky

1. Check for `time.sleep()` - replace with `freezegun`
2. Check for race conditions - use proper synchronization
3. Check for filesystem races - use `tmp_path` properly
4. Run with random seed: `pytest --randomly-seed=1337`

### Coverage Is Low

1. Check coverage report: `pytest --cov-report=term-missing`
2. Identify uncovered lines: `pytest --cov-report=html`
3. Focus on new code first
4. Use `# pragma: no cover` for untestable code (sparingly)

### Tests Fail in CI But Pass Locally

1. Check Python version compatibility
2. Check for environment-specific assumptions
3. Verify all dependencies are in `pyproject.toml`
4. Check for hardcoded paths
5. Run with same flags as CI: `pytest --strict-markers --strict-config`

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [hypothesis documentation](https://hypothesis.readthedocs.io/)
- [freezegun documentation](https://github.com/spulec/freezegun)
- [PyGuard Testing Workflows](./TESTING-WORKFLOWS.md)
- [PyGuard Test Coverage Report](./TEST_COVERAGE_REPORT.md)

## Getting Help

- Check test failures in CI: GitHub Actions logs
- Review test output: `pytest -v`
- Ask in issues: https://github.com/cboyd0319/PyGuard/issues
- Review similar tests in the test suite
