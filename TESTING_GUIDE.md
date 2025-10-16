# PyGuard Testing Guide

## Quick Start

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=pyguard --cov-report=html

# Run specific test file
pytest tests/unit/test_security.py

# Run specific test
pytest tests/unit/test_security.py::TestSecurityChecker::test_sql_injection

# Run tests by marker
pytest -m security
pytest -m "not slow"

# Run with verbose output
pytest -v

# Run in parallel (if pytest-xdist installed)
pytest -n auto
```

### Test Organization

```
tests/
├── unit/                   # Unit tests (isolated components)
│   ├── test_security.py
│   ├── test_framework_django.py
│   └── ...
├── integration/            # Integration tests (workflows)
│   ├── test_cli.py
│   ├── test_file_operations.py
│   └── ...
├── fixtures/              # Test data and sample files
│   ├── sample_vulnerable.py
│   └── ...
└── conftest.py           # Shared fixtures and configuration
```

## Writing Tests

### Test Structure (AAA Pattern)

```python
def test_feature_scenario_expected_result():
    """Test that <feature> <scenario> produces <expected result>."""
    # Arrange - Set up test data and conditions
    input_data = "test data"
    expected_output = "expected result"
    
    # Act - Execute the code under test
    result = function_under_test(input_data)
    
    # Assert - Verify the result
    assert result == expected_output
```

### Naming Conventions

- Test files: `test_<module>.py`
- Test classes: `Test<Feature>` or `Test<Class>`
- Test methods: `test_<unit>_<scenario>_<expected>()`

Examples:
```python
def test_sql_injection_detector_detects_string_concat()
def test_pandas_checker_skips_non_pandas_files()
def test_django_model_without_str_triggers_violation()
```

### Using Fixtures

```python
@pytest.fixture
def sample_code():
    """Fixture providing sample Python code."""
    return """
def example():
    return "Hello"
"""

@pytest.fixture
def temp_python_file(tmp_path):
    """Fixture creating a temporary Python file."""
    file_path = tmp_path / "test.py"
    file_path.write_text("# Python code")
    return file_path

def test_parser_with_fixtures(sample_code, temp_python_file):
    """Test using fixtures."""
    # Use fixtures in test
    assert "def" in sample_code
    assert temp_python_file.exists()
```

### Parametrized Tests

```python
@pytest.mark.parametrize("input_value,expected", [
    (0, 0),
    (1, 1),
    (-1, 1),
    (10, 100),
], ids=["zero", "one", "negative", "ten"])
def test_square_various_inputs(input_value, expected):
    """Test square function with various inputs."""
    assert square(input_value) == expected
```

### Testing Error Conditions

```python
def test_parser_raises_on_invalid_syntax(tmp_path):
    """Test that parser raises SyntaxError for invalid Python."""
    bad_code = "def incomplete("
    file_path = tmp_path / "bad.py"
    file_path.write_text(bad_code)
    
    with pytest.raises(SyntaxError, match="invalid syntax"):
        parse_file(file_path)
```

### Mocking External Dependencies

```python
def test_api_call_with_mock(mocker):
    """Test API call using mock."""
    # Mock the external API call
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "value"}
    
    mocker.patch('requests.get', return_value=mock_response)
    
    # Test code that uses the API
    result = fetch_data("https://api.example.com")
    assert result["data"] == "value"
```

### Property-Based Testing

```python
from hypothesis import given, strategies as st

@given(st.text())
def test_sanitize_never_raises(input_text):
    """Property: sanitize should never raise for any text input."""
    result = sanitize_string(input_text)
    assert isinstance(result, str)

@given(st.lists(st.integers()))
def test_sort_is_idempotent(numbers):
    """Property: sorting twice gives same result as sorting once."""
    sorted_once = sorted(numbers)
    sorted_twice = sorted(sorted_once)
    assert sorted_once == sorted_twice
```

## Test Patterns by Module Type

### Security Rule Detectors

```python
class TestSecurityDetection:
    """Template for security detection tests."""
    
    def test_detect_vulnerability(self, tmp_path):
        """Test detection of specific vulnerability."""
        vulnerable_code = """
import os
command = "ls " + user_input  # Vulnerable
os.system(command)
"""
        file_path = tmp_path / "vuln.py"
        file_path.write_text(vulnerable_code)
        
        checker = SecurityChecker()
        violations = checker.check_file(file_path)
        
        assert len(violations) > 0
        assert any(v.rule_id == "SEC001" for v in violations)
    
    def test_no_false_positive_on_safe_code(self, tmp_path):
        """Test no false positive on safe code."""
        safe_code = """
import subprocess
subprocess.run(["ls", "-la"], check=True)  # Safe
"""
        file_path = tmp_path / "safe.py"
        file_path.write_text(safe_code)
        
        checker = SecurityChecker()
        violations = checker.check_file(file_path)
        
        assert not any(v.rule_id == "SEC001" for v in violations)
```

### Framework-Specific Rules

```python
class TestFrameworkRules:
    """Template for framework-specific tests."""
    
    def test_framework_import_detection(self):
        """Test framework import detection."""
        code = "from django.db import models"
        detector = FrameworkDetector()
        assert detector.is_django_code(code) is True
    
    def test_rule_violation(self, tmp_path):
        """Test framework-specific rule violation."""
        # Setup
        code = """
from django.db import models

class Product(models.Model):
    name = models.CharField(max_length=100)
    # Missing __str__ method - should trigger DJ006
"""
        file_path = tmp_path / "models.py"
        file_path.write_text(code)
        
        # Execute
        checker = DjangoRulesChecker()
        violations = checker.check_file(file_path)
        
        # Verify
        assert any(v.rule_id == "DJ006" for v in violations)
```

### File Operations

```python
class TestFileOperations:
    """Template for file operation tests."""
    
    def test_read_file_success(self, tmp_path):
        """Test successful file read."""
        content = "# Test content"
        file_path = tmp_path / "test.py"
        file_path.write_text(content)
        
        result = read_file(file_path)
        assert result == content
    
    def test_read_file_not_found(self, tmp_path):
        """Test reading non-existent file."""
        file_path = tmp_path / "missing.py"
        
        result = read_file(file_path)
        assert result is None  # Or raises FileNotFoundError
    
    def test_write_file_permission_error(self, tmp_path, monkeypatch):
        """Test write with permission error."""
        file_path = tmp_path / "readonly.py"
        file_path.write_text("content")
        file_path.chmod(0o444)  # Read-only
        
        result = write_file(file_path, "new content")
        assert result is False  # Operation should fail gracefully
```

## Common Testing Scenarios

### Testing Unicode Handling

```python
def test_unicode_in_code(self, tmp_path):
    """Test handling of Unicode characters."""
    unicode_code = """
def greet():
    return "こんにちは世界"  # Japanese: Hello World
"""
    file_path = tmp_path / "unicode.py"
    file_path.write_text(unicode_code, encoding="utf-8")
    
    result = analyze_file(file_path)
    assert result is not None  # Should not raise encoding errors
```

### Testing Empty/Edge Cases

```python
def test_empty_file(self, tmp_path):
    """Test handling of empty file."""
    file_path = tmp_path / "empty.py"
    file_path.write_text("")
    
    result = analyze_file(file_path)
    assert result == []  # Empty file returns empty results

def test_single_line_file(self, tmp_path):
    """Test handling of single-line file."""
    file_path = tmp_path / "single.py"
    file_path.write_text("x = 1")
    
    result = analyze_file(file_path)
    assert isinstance(result, list)
```

### Testing Error Recovery

```python
def test_syntax_error_handling(self, tmp_path):
    """Test graceful handling of syntax errors."""
    bad_code = "def incomplete("
    file_path = tmp_path / "bad.py"
    file_path.write_text(bad_code)
    
    # Should not raise, should return empty or error result
    result = analyze_file(file_path)
    assert result is not None
```

## Test Markers

Use markers to categorize tests:

```python
@pytest.mark.unit
def test_basic_functionality():
    """Unit test."""
    pass

@pytest.mark.integration
def test_workflow():
    """Integration test."""
    pass

@pytest.mark.slow
def test_large_file_processing():
    """Slow test (> 1 second)."""
    pass

@pytest.mark.security
def test_vulnerability_detection():
    """Security-related test."""
    pass
```

Run specific markers:
```bash
pytest -m unit           # Run only unit tests
pytest -m "not slow"     # Skip slow tests
pytest -m security       # Run only security tests
```

## Coverage Best Practices

### Measuring Coverage

```bash
# Generate coverage report
pytest --cov=pyguard --cov-report=html

# View in browser
open htmlcov/index.html

# Terminal report with missing lines
pytest --cov=pyguard --cov-report=term-missing
```

### Interpreting Coverage

- **Line Coverage**: % of code lines executed
- **Branch Coverage**: % of code branches (if/else) taken
- **Target**: ≥90% for critical modules, ≥84% overall

### What to Test

✅ **DO Test:**
- Public API functions and methods
- Error conditions and edge cases
- Boundary values (0, -1, None, empty)
- Integration points
- Security-critical paths

❌ **DON'T Test:**
- Private implementation details
- Third-party library behavior
- Simple getters/setters (unless they contain logic)
- Auto-generated code

## Performance Testing

### Benchmarking

```python
def test_performance_benchmark(benchmark):
    """Benchmark function performance."""
    result = benchmark(expensive_function, large_input)
    assert result is not None
    assert benchmark.stats['mean'] < 0.1  # Under 100ms mean
```

### Profiling Slow Tests

```bash
# Find slow tests
pytest --durations=10

# Profile specific test
pytest --profile tests/unit/test_slow.py
```

## Debugging Tests

### Running with Debug Output

```bash
# Show print statements
pytest -s

# Show local variables on failure
pytest -l

# Start debugger on failure
pytest --pdb

# Full traceback
pytest --tb=long
```

### Interactive Debugging

```python
def test_with_debugging():
    """Test with breakpoint."""
    result = complex_function()
    
    # Set breakpoint for debugging
    import pdb; pdb.set_trace()
    
    assert result == expected
```

## CI/CD Integration

### Pre-commit Checks

```bash
# Run tests before commit
pytest tests/

# Fast checks only
pytest tests/ -m "not slow"

# With coverage check
pytest --cov=pyguard --cov-fail-under=84
```

### GitHub Actions Example

```yaml
name: Tests
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
      - run: pip install -e .[dev]
      - run: pytest --cov=pyguard --cov-report=xml
      - uses: codecov/codecov-action@v3
```

## Troubleshooting

### Common Issues

**Issue**: Test fails only in CI, not locally
- **Solution**: Check for time/timezone dependencies, use `freezegun`
- **Solution**: Ensure random seeds are set with `pytest-randomly`

**Issue**: Tests are slow
- **Solution**: Use `pytest-xdist` for parallel execution
- **Solution**: Mark slow tests with `@pytest.mark.slow`
- **Solution**: Mock expensive operations

**Issue**: Flaky tests (intermittent failures)
- **Solution**: Remove time dependencies, use deterministic inputs
- **Solution**: Properly isolate tests (no shared state)
- **Solution**: Fix race conditions in async code

**Issue**: Low coverage despite many tests
- **Solution**: Check branch coverage, not just line coverage
- **Solution**: Add tests for error paths
- **Solution**: Test edge cases and boundaries

## Contributing Tests

### Before Submitting PR

1. ✅ All tests pass locally
2. ✅ New code has ≥90% coverage
3. ✅ Tests follow naming conventions
4. ✅ Tests are documented
5. ✅ No new flaky tests
6. ✅ Fast execution (< 100ms per test typical)

### Test Review Checklist

- [ ] Tests are clear and well-named
- [ ] AAA pattern followed
- [ ] Both success and failure paths tested
- [ ] Edge cases covered
- [ ] No hard-coded paths or dependencies
- [ ] Proper use of fixtures
- [ ] Deterministic (no random/time dependencies)

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [hypothesis documentation](https://hypothesis.readthedocs.io/)
- [Real Python: Effective pytest](https://realpython.com/pytest-python-testing/)

---

**Maintained by**: PyGuard Development Team  
**Last Updated**: 2025-10-16
