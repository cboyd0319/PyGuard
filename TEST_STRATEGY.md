# PyGuard Test Strategy & Implementation Guide

## Overview

This document provides a comprehensive testing strategy for PyGuard, following industry best practices and the pytest ecosystem's strengths. The goal is to achieve **high-signal** test suites with **meaningful coverage** while maintaining **deterministic, isolated, and repeatable** tests.

## Current Status

- **Total Tests**: 1,539 passing (64 new CLI tests added)
- **Overall Coverage**: 88% lines (with branch coverage)
- **Test Infrastructure**: pytest, pytest-cov, pytest-mock, pytest-randomly, freezegun, hypothesis
- **Configuration**: Strict markers, branch coverage, 90% coverage target

## Core Testing Principles

### 1. Framework: pytest
- Use **plain pytest style** over unittest style
- Leverage pytest's powerful fixtures and parametrization
- Use pytest plugins for enhanced functionality

### 2. AAA Pattern
Every test follows **Arrange – Act – Assert**:
```python
def test_security_fixer_detects_hardcoded_password():
    # Arrange
    fixer = SecurityFixer()
    code = 'password = "secret123"'
    
    # Act
    result = fixer.fix_hardcoded_passwords(code)
    
    # Assert
    assert "WARNING" in result
    assert "hardcoded password" in result.lower()
```

### 3. Naming Convention
`test_<unit>_<scenario>_<expected>()` with readable, intent-revealing names:
- ✅ `test_fix_sql_injection_parameterizes_query()`
- ✅ `test_security_fixer_handles_empty_file_gracefully()`
- ❌ `test_fix()` (too vague)
- ❌ `test_security_1()` (meaningless)

### 4. Determinism
- ✅ Seed all randomness: `random.seed(1337)`, `np.random.seed(1337)`
- ✅ Freeze time: Use `freezegun` fixture for time-dependent code
- ✅ No network calls: Use mocks/responses
- ✅ No sleep(): Use time mocking instead
- ✅ Filesystem isolation: Use `tmp_path` fixture

### 5. Isolation
- Each test is independent
- No inter-test dependencies
- No global state mutations
- Clean setup and teardown

### 6. Coverage as Guardrail
- Focus on **meaningful paths**, not 100% coverage
- Test edge cases, error handling, and branch logic
- Use coverage to identify untested code paths

## Test Structure

### Directory Layout
```
tests/
├── conftest.py              # Shared fixtures and configuration
├── fixtures/                # Sample code for testing
│   ├── sample_vulnerable.py
│   ├── sample_bad_practices.py
│   └── sample_correct.py
├── unit/                    # Unit tests (fast, isolated)
│   ├── test_security.py
│   ├── test_cli.py
│   └── test_*.py
└── integration/             # Integration tests
    ├── test_cli.py
    └── test_workflow_validation.py
```

### Fixtures (conftest.py)

#### Determinism Fixtures
```python
@pytest.fixture(autouse=True, scope="session")
def _seed_random():
    """Seed RNG for deterministic tests."""
    random.seed(1337)
    np.random.seed(1337)

@pytest.fixture
def freeze_2025_01_01():
    """Freeze time for deterministic time testing."""
    from freezegun import freeze_time
    with freeze_time("2025-01-01 00:00:00"):
        yield
```

#### Filesystem Fixtures
```python
@pytest.fixture
def temp_dir():
    """Create temporary directory."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)

@pytest.fixture
def temp_file(temp_dir):
    """Factory to create temporary files."""
    def _create_file(name: str, content: str = "") -> Path:
        file_path = temp_dir / name
        file_path.write_text(content)
        return file_path
    return _create_file
```

#### Sample Code Fixtures
```python
@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable Python code."""
    return '''
import random
password = "admin123"
query = "SELECT * FROM users WHERE id = " + user_id
token = random.random()
'''

@pytest.fixture
def sample_edge_cases():
    """Edge case inputs for testing."""
    return {
        "empty_string": "",
        "none_value": None,
        "zero": 0,
        "unicode": "Hello 世界 🌍",
        "large_number": 10**6,
    }
```

## Testing Strategies

### 1. Parametrized Table Tests

Use `@pytest.mark.parametrize` for input matrices:

```python
@pytest.mark.parametrize(
    "code, expected_warning",
    [
        ('password = "secret"', "hardcoded password"),
        ('api_key = "xyz123"', "hardcoded api_key"),
        ('token = "abc"', "hardcoded token"),
        ('config = getenv("KEY")', None),  # Safe
    ],
    ids=["password", "api_key", "token", "safe_env"]
)
def test_fix_hardcoded_secrets_detection(code, expected_warning):
    """Test hardcoded secret detection with various patterns."""
    fixer = SecurityFixer()
    result = fixer.fix_hardcoded_passwords(code)
    
    if expected_warning:
        assert expected_warning in result.lower()
    else:
        assert result == code  # No change for safe code
```

### 2. Error Handling Tests

Test all error paths explicitly:

```python
def test_security_fixer_handles_nonexistent_file(tmp_path):
    """Test that SecurityFixer gracefully handles missing files."""
    fixer = SecurityFixer()
    non_existent = tmp_path / "does_not_exist.py"
    
    success, fixes = fixer.fix_file(non_existent)
    
    assert not success
    assert fixes == []

def test_fix_raises_on_invalid_code():
    """Test that fixer raises appropriate error for invalid syntax."""
    fixer = SecurityFixer()
    
    with pytest.raises(SyntaxError):
        fixer.fix_hardcoded_passwords("def foo(\n  invalid")
```

### 3. Mocking External Dependencies

Mock at the **import site**, not the definition site:

```python
def test_cli_uses_sarif_reporter(mocker, tmp_path):
    """Test that CLI generates SARIF report when requested."""
    mock_sarif = mocker.patch("pyguard.cli.SARIFReporter")
    
    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1")
    
    cli = PyGuardCLI()
    cli.print_results({"issues": []}, generate_sarif=True)
    
    mock_sarif.assert_called_once()
```

### 4. Property-Based Testing

Use `hypothesis` for algorithmic or parsing logic:

```python
from hypothesis import given, strategies as st

@given(st.text())
def test_security_fixer_never_corrupts_syntax(code_text):
    """Property: SecurityFixer never produces invalid syntax."""
    fixer = SecurityFixer()
    result = fixer.fix_hardcoded_passwords(code_text)
    
    # Result should be valid Python or unchanged
    try:
        compile(result, '<string>', 'exec')
    except SyntaxError:
        assert result == code_text  # Unchanged if invalid
```

### 5. Edge Cases & Boundaries

Test edge cases systematically:

```python
@pytest.mark.parametrize("input_value", [
    "",              # Empty
    None,            # None
    0,               # Zero
    -1,              # Negative
    10**6,           # Large
    "Hello 世界",    # Unicode
    " \t\n ",        # Whitespace
])
def test_function_handles_edge_cases(input_value):
    """Test function with edge case inputs."""
    result = process_input(input_value)
    assert result is not None  # Should not crash
```

## Quality Gates

### Coverage Requirements
- **Line Coverage**: ≥ 90%
- **Branch Coverage**: ≥ 85%
- **New/Changed Code**: ~100% coverage

### Running Tests
```bash
# Run all tests with coverage
pytest

# Run specific module tests
pytest tests/unit/test_security.py

# Run with branch coverage report
pytest --cov=pyguard --cov-report=term-missing --cov-branch

# Run with coverage failure threshold
pytest --cov-fail-under=90

# Run with randomized order (flake detection)
pytest --randomly-seed=last
```

### Mutation Testing (Optional)
```bash
# Install mutmut
pip install mutmut

# Run mutation tests on critical module
mutmut run --paths-to-mutate=pyguard/lib/security.py

# View results
mutmut results

# Target: ≥85% mutation kill rate
```

## Anti-Patterns to Avoid

### ❌ Don't Do This
```python
# Bad: Flaky test with sleep
def test_async_operation():
    start_task()
    time.sleep(2)  # ❌ Flaky!
    assert task_is_complete()

# Bad: Testing implementation details
def test_internal_method():
    obj = MyClass()
    assert obj._internal_counter == 0  # ❌ Private implementation!

# Bad: Multiple assertions for different behaviors
def test_everything():
    assert func(1) == 2
    assert func(2) == 4
    assert func(0) == 0
    # ❌ Use parametrize instead!
```

### ✅ Do This Instead
```python
# Good: Mock time
def test_async_operation(mocker):
    mocker.patch("time.time", return_value=1000)
    start_task()
    assert task_is_complete()

# Good: Test public API
def test_public_api():
    obj = MyClass()
    result = obj.process()  # ✅ Public interface
    assert result.is_valid()

# Good: Parametrized tests
@pytest.mark.parametrize("input,expected", [
    (1, 2), (2, 4), (0, 0)
])
def test_function(input, expected):
    assert func(input) == expected
```

## Module-Specific Testing Guidance

### Security Modules (security.py, advanced_security.py)
- **Priority**: Critical - requires comprehensive testing
- **Focus**: All vulnerability detection patterns
- **Edge Cases**: Unicode, escaped strings, nested functions
- **Property Tests**: "Fixer never creates vulnerabilities"

### CLI Module (cli.py)
- **Priority**: High - user-facing functionality
- **Focus**: All command-line flags and combinations
- **Edge Cases**: Empty files, non-existent paths, invalid syntax
- **Integration**: Test with real file operations

### Framework Modules (framework_django.py, framework_flask.py)
- **Priority**: Medium-High - framework-specific patterns
- **Focus**: Framework-specific vulnerability patterns
- **Mocking**: Mock framework imports if not available

### Core Modules (core.py, rule_engine.py)
- **Priority**: High - foundation for other modules
- **Focus**: Core logic, state management, error handling
- **Edge Cases**: Empty inputs, invalid states, concurrent access

## CI/CD Integration

### GitHub Actions Configuration
```yaml
name: tests
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
        run: |
          pip install -e .[dev]
      
      - name: Run tests with coverage
        run: |
          pytest --cov=pyguard --cov-report=xml --cov-fail-under=90
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
          fail_ci_if_error: true
```

## Best Practices Checklist

### Before Writing Tests
- [ ] Identify all public API functions/methods
- [ ] Map all error conditions and exceptions
- [ ] List edge cases and boundary values
- [ ] Identify external dependencies to mock

### When Writing Tests
- [ ] Follow AAA pattern (Arrange-Act-Assert)
- [ ] Use descriptive test names
- [ ] One behavior per test
- [ ] Use parametrization for input matrices
- [ ] Mock external dependencies
- [ ] Use fixtures for common setup

### After Writing Tests
- [ ] Run tests with randomized order (`pytest-randomly`)
- [ ] Check coverage report for gaps
- [ ] Verify tests are fast (< 100ms per test)
- [ ] Ensure tests are deterministic (run 10 times)
- [ ] Review for test quality anti-patterns

## Example: Complete Test Module

```python
"""
Comprehensive tests for security.py module.

Tests cover:
- All vulnerability detection patterns
- Error handling and edge cases
- File operations
- Integration with other components
"""

import pytest
from pathlib import Path
from pyguard.lib.security import SecurityFixer


class TestSecurityFixerInitialization:
    """Tests for SecurityFixer initialization."""
    
    def test_initialization_creates_valid_instance(self):
        """Test that SecurityFixer initializes correctly."""
        fixer = SecurityFixer()
        
        assert fixer is not None
        assert hasattr(fixer, 'fix_file')


class TestFixHardcodedPasswords:
    """Tests for hardcoded password detection and fixing."""
    
    @pytest.mark.parametrize(
        "code, should_warn",
        [
            ('password = "secret"', True),
            ('PASSWORD = "admin123"', True),
            ('api_key = "xyz"', True),
            ('token = ""', False),  # Empty is OK
            ('password = None', False),  # None is OK
            ('password = os.getenv("PWD")', False),  # Env var is OK
        ],
        ids=["lowercase", "uppercase", "api_key", "empty", "none", "env_var"]
    )
    def test_fix_hardcoded_passwords_detection(self, code, should_warn):
        """Test hardcoded password detection with various patterns."""
        fixer = SecurityFixer()
        result = fixer.fix_hardcoded_passwords(code)
        
        if should_warn:
            assert "WARNING" in result or "warning" in result.lower()
        else:
            assert result == code or "WARNING" not in result


class TestFixFile:
    """Tests for fix_file method."""
    
    def test_fix_file_creates_fixes_for_vulnerable_code(self, tmp_path):
        """Test that fix_file applies fixes to vulnerable code."""
        fixer = SecurityFixer()
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text('password = "secret123"')
        
        success, fixes = fixer.fix_file(test_file)
        
        assert success
        assert len(fixes) > 0
    
    def test_fix_file_handles_nonexistent_file(self, tmp_path):
        """Test that fix_file handles nonexistent files gracefully."""
        fixer = SecurityFixer()
        non_existent = tmp_path / "does_not_exist.py"
        
        success, fixes = fixer.fix_file(non_existent)
        
        assert not success
        assert fixes == []


class TestEdgeCases:
    """Edge case tests."""
    
    def test_empty_file(self, tmp_path):
        """Test handling of empty file."""
        fixer = SecurityFixer()
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")
        
        success, fixes = fixer.fix_file(empty_file)
        
        assert success
        assert fixes == []
    
    def test_unicode_content(self, tmp_path):
        """Test handling of Unicode content."""
        fixer = SecurityFixer()
        unicode_file = tmp_path / "unicode.py"
        unicode_file.write_text('# Comment: 世界\npassword = "secret"')
        
        success, fixes = fixer.fix_file(unicode_file)
        
        assert success
```

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-cov](https://pytest-cov.readthedocs.io/)
- [hypothesis](https://hypothesis.readthedocs.io/)
- [freezegun](https://github.com/spulec/freezegun)
- [mutmut](https://mutmut.readthedocs.io/)

## Continuous Improvement

1. **Weekly**: Run `pytest-randomly` with different seeds
2. **Monthly**: Review coverage reports for regressions
3. **Quarterly**: Run mutation testing on critical modules
4. **Ongoing**: Refactor slow or brittle tests proactively

---

**Last Updated**: 2025-10-16  
**Version**: 1.0  
**Maintainer**: PyGuard Team
