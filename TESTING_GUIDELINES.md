# PyGuard Testing Strategy & Guidelines

## Overview

This document outlines the testing strategy, guidelines, and best practices for the PyGuard project. It follows the PyTest Architect Agent principles for building comprehensive, maintainable, and deterministic test suites.

## Core Principles

### 1. Framework: pytest
All tests use pytest framework with the following characteristics:
- Plain pytest style (not unittest style)
- Fixtures for setup/teardown
- Parametrization for table-driven tests
- Marks for test categorization

### 2. AAA Pattern
Every test follows Arrange-Act-Assert:

```python
def test_example():
    # Arrange: Set up test data and conditions
    code = "x = 1"
    checker = MyChecker()
    
    # Act: Execute the code under test
    result = checker.check(code)
    
    # Assert: Verify expected outcomes
    assert len(result) == 0
```

### 3. Naming Convention
Tests are named: `test_<unit>_<scenario>_<expected>()`

Examples:
- `test_detect_sql_injection_with_user_input_reports_issue()`
- `test_fix_file_with_invalid_syntax_returns_false()`
- `test_checker_with_empty_file_returns_no_violations()`

### 4. Determinism
All tests must be deterministic:
- ✅ Seeded random number generators
- ✅ Frozen time when needed
- ✅ Controlled environment variables
- ✅ No network calls
- ✅ No external service dependencies

### 5. Isolation
Each test must be isolated:
- ✅ No shared mutable state
- ✅ No inter-test dependencies
- ✅ Independent execution order
- ✅ Proper cleanup after each test

## Test Categories

### Unit Tests (`tests/unit/`)
Test individual functions, classes, and modules in isolation.

**Characteristics:**
- Fast (<100ms typical)
- No I/O operations
- Mocked external dependencies
- High coverage target (>90%)

**Example:**
```python
def test_security_visitor_detects_eval_usage():
    code = "result = eval(user_input)"
    tree = ast.parse(code)
    visitor = SecurityVisitor()
    visitor.visit(tree)
    
    assert len(visitor.issues) > 0
    assert any("eval" in issue.message for issue in visitor.issues)
```

### Integration Tests (`tests/integration/`)
Test interactions between components and modules.

**Characteristics:**
- Moderate speed (<1s typical)
- May use temporary files
- Tests end-to-end workflows
- Coverage target (>80%)

**Example:**
```python
def test_cli_processes_file_and_generates_report(tmp_path):
    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1")
    
    result = cli.main(["--file", str(test_file)])
    
    assert result.exit_code == 0
    assert result.violations_found >= 0
```

## What to Test

### Priority Order

1. **✅ Public API** - All public functions and methods
   - Happy path scenarios
   - Common use cases
   - Expected inputs

2. **✅ Error Handling** - Exception paths
   - Invalid inputs
   - Edge cases
   - Error messages
   - Exception types

3. **✅ Boundary Cases** - Edge inputs
   - Empty collections
   - None values
   - Zero/negative numbers
   - Very large inputs
   - Unicode and special characters

4. **✅ Branching Logic** - All code paths
   - if/elif/else branches
   - Early returns
   - Guards and assertions

5. **✅ State & Side Effects**
   - File system operations
   - Environment variables
   - Logging output
   - External calls (mocked)

## Test Structure Requirements

### Docstrings
Complex tests should have docstrings:

```python
def test_complex_scenario():
    """
    Test that the checker correctly handles nested try-except
    blocks with multiple exception types and validates that
    the proper recommendations are provided.
    """
    # Test implementation
```

### Parametrization
Use `@pytest.mark.parametrize` for table-driven tests:

```python
@pytest.mark.parametrize(
    "code,expected_rule",
    [
        ("x = eval(input())", "SEC101"),
        ("import pickle", "SEC201"),
        ("yaml.load(data)", "SEC301"),
    ],
    ids=["eval", "pickle", "yaml"]
)
def test_security_patterns(code, expected_rule):
    violations = check_security(code)
    assert any(v.rule_id == expected_rule for v in violations)
```

### Fixtures
Put shared setup in conftest.py:

```python
@pytest.fixture
def temp_python_file(tmp_path):
    """Create a temporary Python file for testing."""
    def _create(content: str) -> Path:
        file_path = tmp_path / "test.py"
        file_path.write_text(content)
        return file_path
    return _create
```

## Mocking Guidelines

### Use pytest-mock (mocker)
```python
def test_with_mock(mocker):
    mock_open = mocker.patch("builtins.open")
    mock_open.return_value.__enter__.return_value.read.return_value = "data"
    
    result = read_file("test.py")
    
    assert result == "data"
```

### Patch at Import Site
```python
# Patch where it's used, not where it's defined
mocker.patch("mymodule.checker.open", ...)  # ✅
mocker.patch("builtins.open", ...)  # ❌ (unless specifically needed)
```

### Time & Randomness
```python
# Use fixtures from conftest.py
def test_with_frozen_time(freeze_2025_01_01):
    result = get_current_date()
    assert result == "2025-01-01"

# Seed randomness
def test_with_random(_seed_rng):  # autouse fixture
    value = random.randint(1, 100)
    # Deterministic behavior
```

## Coverage Requirements

### Line Coverage
- **New Code:** ≥90%
- **Overall:** ≥84% (current: 86.84%)
- **Pure Functions:** ~100%

### Branch Coverage
- **New Code:** ≥80%
- **Overall:** ≥85% (target)
- **Critical Logic:** ~100%

### Configuration
```toml
[tool.coverage.report]
fail_under = 84
skip_covered = true
show_missing = true
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
]
```

## Testing Anti-Patterns (Avoid)

### ❌ Flaky Tests
- Hidden time dependencies
- Race conditions
- Non-seeded randomness
- Network calls
- Sleep statements

### ❌ Over-Mocking
- Mocking implementation details
- Too many mocks in one test
- Mocking what you're testing

### ❌ Multiple Assertions Per Concept
```python
# ❌ Bad
def test_everything():
    assert checker.check_security(code1)
    assert checker.check_style(code2)
    assert checker.check_performance(code3)

# ✅ Good
def test_security_check():
    assert checker.check_security(code1)

def test_style_check():
    assert checker.check_style(code2)

def test_performance_check():
    assert checker.check_performance(code3)
```

### ❌ Copy-Paste Tests
```python
# ❌ Bad
def test_with_value_1():
    assert square(1) == 1

def test_with_value_2():
    assert square(2) == 4

# ✅ Good
@pytest.mark.parametrize("value,expected", [
    (1, 1),
    (2, 4),
])
def test_square(value, expected):
    assert square(value) == expected
```

## Data Strategies

### Table-Driven Tests
```python
@pytest.fixture
def security_patterns():
    return {
        "sql_injection": 'query = "SELECT * FROM users WHERE id = " + user_id',
        "command_injection": 'os.system("ls " + user_input)',
        "eval_usage": "result = eval(user_input)",
    }

def test_security_detection(security_patterns):
    for pattern_name, code in security_patterns.items():
        violations = check_security(code)
        assert len(violations) > 0, f"Failed to detect {pattern_name}"
```

### Factories
```python
@pytest.fixture
def code_factory():
    """Factory to create code samples with specific patterns."""
    def _create(pattern: str, **kwargs) -> str:
        templates = {
            "loop": "for i in range({n}):\n    process(i)",
            "try_except": "try:\n    {code}\nexcept {exc}:\n    pass",
        }
        return templates[pattern].format(**kwargs)
    return _create
```

## Performance Guidelines

### Execution Time
- **Unit Tests:** <100ms typical, <500ms max
- **Integration Tests:** <1s typical, <5s max
- **Full Suite:** <30s target

### Optimization Tips
- Use `tmp_path` instead of creating real files when possible
- Mock expensive operations
- Use module-scoped fixtures for heavy setup
- Parallelize with `pytest-xdist` if needed

## Continuous Integration

### GitHub Actions Example
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
        run: pip install -e .[dev]
      
      - name: Run tests
        run: pytest
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Workflow

### Adding New Tests

1. **Identify what to test**
   - New feature/function?
   - Bug fix?
   - Edge case?

2. **Write test first** (TDD)
   ```python
   def test_new_feature():
       # This will fail until feature is implemented
       result = new_feature(input)
       assert result == expected
   ```

3. **Implement feature**

4. **Verify test passes**

5. **Check coverage**
   ```bash
   pytest --cov=pyguard tests/unit/test_new_feature.py
   ```

6. **Add edge cases**
   - What if input is None?
   - What if input is empty?
   - What if input is invalid?

### Running Tests

```bash
# All tests
pytest

# Specific file
pytest tests/unit/test_security.py

# Specific test
pytest tests/unit/test_security.py::test_detect_sql_injection

# With coverage
pytest --cov=pyguard

# Fast fail
pytest -x

# Verbose
pytest -v

# Show print statements
pytest -s
```

## Additional Resources

### pytest Plugins Used
- `pytest-cov` - Coverage reporting
- `pytest-mock` - Mocking support
- `pytest-randomly` - Random test order
- `pytest-benchmark` - Performance testing
- `freezegun` - Time freezing

### Documentation
- pytest docs: https://docs.pytest.org/
- pytest-cov: https://pytest-cov.readthedocs.io/
- Coverage.py: https://coverage.readthedocs.io/

## Conclusion

Following these guidelines ensures that PyGuard maintains a high-quality, maintainable, and comprehensive test suite. The principles outlined here support confident refactoring, rapid development, and reliable software delivery.

**Key Takeaways:**
- ✅ Write deterministic, isolated tests
- ✅ Follow AAA pattern consistently  
- ✅ Use parametrization for similar cases
- ✅ Mock external dependencies
- ✅ Aim for 90%+ coverage on new code
- ✅ Keep tests fast and focused
- ✅ Document complex test scenarios
