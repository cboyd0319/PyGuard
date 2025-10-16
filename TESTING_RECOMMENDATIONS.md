# PyGuard Testing Recommendations

## Current State Summary

### What Has Been Accomplished ✅

1. **Comprehensive Test Infrastructure**
   - Enhanced `conftest.py` with 10+ reusable fixtures
   - Deterministic testing with seeded random (session-scoped)
   - Factory patterns for file and code creation
   - Sample code patterns for common vulnerabilities
   - Mock logger with full method coverage

2. **Complete Test Suite for security.py**
   - Coverage improved from 57% → 98% (line) and 95% (branch)
   - 63 comprehensive parametrized tests added
   - All 10 security fix methods thoroughly tested
   - Edge cases, error paths, and integration tests
   - Serves as template for other modules

3. **Documentation**
   - [TEST_PLAN.md](./TEST_PLAN.md): Comprehensive 350+ line testing strategy
   - [COVERAGE_STATUS.md](./COVERAGE_STATUS.md): Detailed module-by-module analysis
   - This document: Practical recommendations

4. **Overall Metrics**
   - Total tests: 1,341 → 1,399 (+58 tests)
   - Overall coverage: 83% lines, 79% branches
   - 11 modules at ≥95% coverage
   - 17 modules at ≥90% coverage

### What Remains 📋

**Critical Priority (5 modules <70% coverage)**
- framework_django.py (60%) - 35 tests needed
- pylint_rules.py (61%) - 35 tests needed
- refurb_patterns.py (69%) - 50 tests needed (large module)
- watch.py (69%) - 20 tests needed
- unused_code.py (70%) - 25 tests needed

**High Priority (10 modules 70-79%)**
- Various core modules needing 20-30 tests each

**Medium Priority (12 modules 80-89%)**
- Modules needing 10-20 tests each

**Quick Wins (6 modules 90-94%)**
- Modules needing only 5-10 tests each

**Total Remaining Effort: ~650 tests needed**

## Recommended Next Steps

### Option 1: Incremental Improvement (Recommended)

Continue systematic enhancement of modules in priority order:

**Week 1: Critical Modules (150 tests)**
1. framework_django.py (35 tests)
2. pylint_rules.py (35 tests)
3. refurb_patterns.py (50 tests)
4. watch.py (20 tests)
5. unused_code.py (10 tests to 90%+)

**Week 2: Quick Wins (35 tests)**
6. Bring 6 modules from 90-94% to 95%+

**Week 3-4: High Priority (130 tests)**
7. Improve 10 modules from 70-79% to 90%+

**Week 5-8: Medium Priority (335 tests)**
8. Improve remaining modules to 90%+

### Option 2: Focused Critical Path

Focus exclusively on security and quality-critical modules:

1. **Security Modules** (Already strong)
   - security.py ✅ 98%
   - advanced_security.py ⚠️ 86%
   - enhanced_security_fixes.py ✅ 95%
   - ultra_advanced_security.py ⚠️ 78%
   - xss_detection.py ⚠️ 84%

2. **Core Analysis Modules**
   - ast_analyzer.py ⚠️ 77%
   - core.py ⚠️ 76%
   - rule_engine.py ⚠️ 78%

3. **Framework Integrations**
   - framework_django.py 🚨 60%
   - framework_pandas.py 🚨 67%
   - framework_flask.py 🚨 0%
   - framework_pytest.py ⚠️ 72%

### Option 3: Automated Enhancement

Use AI/automation tools to generate test scaffolds:

```bash
# Use pytest-testgen (if available)
pytest-testgen pyguard/lib/framework_django.py

# Or use LLM-based tools with prompt:
# "Generate comprehensive pytest tests for [module] following security.py patterns"
```

## Test Template Pattern

Based on security.py success, use this pattern for all modules:

```python
"""Comprehensive unit tests for [module_name] module."""

import pytest
from pyguard.lib.[module_name] import [MainClass]


class Test[MainClass]Init:
    """Test initialization."""
    
    def test_initialization(self):
        """Test component initializes properly."""
        obj = [MainClass]()
        assert obj is not None
        # Test initial state


class Test[Method]HappyPath:
    """Test [method] happy paths."""
    
    def setup_method(self):
        """Set up fixtures."""
        self.obj = [MainClass]()
    
    @pytest.mark.parametrize(
        "input_val, expected",
        [
            (normal_case, expected_output),
            (edge_case_1, expected_output_1),
            (edge_case_2, expected_output_2),
        ],
        ids=["normal", "edge1", "edge2"]
    )
    def test_method_parametrized(self, input_val, expected):
        """Test method with various inputs."""
        result = self.obj.method(input_val)
        assert result == expected


class Test[Method]ErrorPaths:
    """Test [method] error handling."""
    
    def setup_method(self):
        """Set up fixtures."""
        self.obj = [MainClass]()
    
    def test_method_handles_none(self):
        """Test method handles None input."""
        result = self.obj.method(None)
        # Assert appropriate behavior
    
    def test_method_raises_on_invalid_input(self):
        """Test method raises appropriate exception."""
        with pytest.raises(ValueError, match="expected pattern"):
            self.obj.method(invalid_input)


class Test[Method]EdgeCases:
    """Test [method] edge cases."""
    
    def setup_method(self):
        """Set up fixtures."""
        self.obj = [MainClass]()
    
    def test_method_empty_input(self):
        """Test method with empty input."""
        result = self.obj.method("")
        assert result == expected_for_empty
    
    def test_method_unicode_input(self):
        """Test method handles Unicode."""
        result = self.obj.method("тест")
        assert isinstance(result, str)
    
    def test_method_large_input(self):
        """Test method handles large input."""
        large_input = "x" * 10000
        result = self.obj.method(large_input)
        assert result is not None


class TestIntegration:
    """Test integration scenarios."""
    
    def test_complete_workflow(self, temp_file):
        """Test complete workflow end-to-end."""
        # Arrange: Create test scenario
        # Act: Execute workflow
        # Assert: Verify results
```

## Common Testing Patterns

### Pattern 1: File Operations
```python
def test_processes_file(self, tmp_path):
    """Test file processing."""
    test_file = tmp_path / "test.py"
    test_file.write_text("code content")
    
    processor = FileProcessor()
    result = processor.process(test_file)
    
    assert result.success
    assert test_file.exists()  # Or not, depending on operation
```

### Pattern 2: AST Parsing
```python
@pytest.mark.parametrize(
    "code, expected_issues",
    [
        ("def foo(): pass", 0),
        ("eval(input())", 1),
        ("def foo():\n    eval(x)", 1),
    ],
    ids=["safe", "eval_top", "eval_function"]
)
def test_detect_issues(code, expected_issues):
    """Test issue detection in various code structures."""
    analyzer = Analyzer()
    issues = analyzer.analyze(code)
    assert len(issues) == expected_issues
```

### Pattern 3: Mocking External Calls
```python
def test_external_call_logged(mocker, tmp_path):
    """Test that external calls are logged."""
    mock_logger = mocker.patch('pyguard.lib.module.logger')
    test_file = tmp_path / "test.py"
    test_file.write_text("content")
    
    processor = Processor()
    processor.process(test_file)
    
    mock_logger.info.assert_called()
```

### Pattern 4: Framework Testing
```python
def test_django_pattern_detection():
    """Test Django-specific pattern detection."""
    code = """
from django.db import models

class User(models.Model):
    password = models.CharField(max_length=100)  # Security issue
"""
    checker = DjangoChecker()
    issues = checker.check_code(code)
    assert len(issues) > 0
    assert any("password" in str(issue).lower() for issue in issues)
```

## Tooling Recommendations

### Essential Tools (Already Installed)
- ✅ pytest
- ✅ pytest-cov
- ✅ pytest-mock

### Highly Recommended (Add These)
```bash
pip install pytest-randomly      # Order-independent tests
pip install pytest-timeout       # Prevent hanging tests
pip install pytest-benchmark     # Performance testing
pip install hypothesis           # Property-based testing
pip install freezegun           # Time mocking
```

### Optional but Valuable
```bash
pip install pytest-xdist        # Parallel test execution
pip install mutmut              # Mutation testing
pip install pytest-html         # HTML test reports
pip install pytest-json-report  # JSON test reports
```

### CI/CD Integration

Update `.github/workflows/test.yml`:

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
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      
      - name: Install dependencies
        run: |
          pip install -e .[dev]
          pip install pytest-randomly pytest-timeout
      
      - name: Run tests with coverage
        run: |
          pytest tests/unit/ \
            --cov=pyguard/lib \
            --cov-report=term-missing \
            --cov-report=xml \
            --cov-branch \
            --cov-fail-under=85 \
            --randomly-seed=1337 \
            --timeout=10
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

## Module-Specific Guidance

### For Framework Modules (Django, Flask, Pandas, Pytest)

**Challenge**: Require framework-specific mocking

**Strategy**:
1. Mock framework imports at module level
2. Use factory fixtures for framework objects
3. Test pattern detection without full framework
4. Consider integration tests with real frameworks (optional)

**Example**:
```python
@pytest.fixture
def mock_django(monkeypatch):
    """Mock Django imports."""
    mock_models = type('models', (), {
        'Model': type('Model', (), {}),
        'CharField': lambda **kw: None,
    })
    monkeypatch.setattr('django.db.models', mock_models)
    return mock_models

def test_django_model_detection(mock_django):
    """Test Django model pattern detection."""
    from pyguard.lib.framework_django import DjangoChecker
    # ... test code
```

### For Large Modules (refurb_patterns.py, ruff_security.py)

**Challenge**: 1000+ lines with many patterns

**Strategy**:
1. Break tests into pattern groups
2. One test class per pattern type
3. Heavy use of parametrization
4. Focus on pattern matching, not implementation

**Example**:
```python
class TestSliceSimplification:
    """Test slice pattern simplification."""
    
    @pytest.mark.parametrize(
        "input_code, expected_fix",
        [
            ("x[0:len(x)]", "x[0:]"),
            ("x[0:len(x):1]", "x[:]"),
            # ... many more cases
        ],
        ids=lambda x: x[:20]  # Use input as id
    )
    def test_simplify_slice(self, input_code, expected_fix):
        """Test slice simplification patterns."""
        checker = RefurbChecker()
        result = checker.fix(input_code)
        assert expected_fix in result
```

### For AST-Heavy Modules (ast_analyzer.py, etc.)

**Challenge**: Complex AST parsing logic

**Strategy**:
1. Test with complete, compilable code snippets
2. Use `textwrap.dedent` for readable multi-line strings
3. Test at AST node level and full-parse level
4. Include syntax error handling

**Example**:
```python
from textwrap import dedent

def test_detect_nested_function():
    """Test detection in nested function."""
    code = dedent("""
        def outer():
            def inner():
                eval(x)  # Should detect this
            return inner
    """)
    
    analyzer = ASTAnalyzer()
    issues = analyzer.analyze(code)
    assert len(issues) == 1
    assert "eval" in issues[0].message
```

## Coverage Blind Spots

Common areas that tests miss:

1. **Import-time code**: Code that runs when module is imported
2. **CLI entry points**: `if __name__ == "__main__"` blocks
3. **Exception handlers**: Broad except clauses
4. **Cleanup code**: `finally` blocks and context manager `__exit__`
5. **Defensive code**: Type checks that "should never happen"

**Solution**: Explicitly test these with:
- Import tests
- CLI runner tests
- Exception injection
- Context manager tests
- Property-based testing for defensive code

## Quality Assurance Checklist

Before submitting tests for a module:

- [ ] All new tests pass consistently (run 10 times)
- [ ] No warnings or deprecations
- [ ] Coverage report shows ≥90% lines, ≥85% branches
- [ ] All tests follow AAA pattern
- [ ] Parametrized tests have descriptive ids
- [ ] No sleep() or time.sleep() calls
- [ ] All file operations use tmp_path
- [ ] No real network calls
- [ ] Edge cases tested (empty, None, large, Unicode)
- [ ] Error paths tested (exceptions, invalid inputs)
- [ ] Tests run in <10 seconds for module
- [ ] No test interdependencies (can run in any order)

## Performance Considerations

### Current Performance
- Total test time: ~11 seconds for 1,399 tests
- Average: ~8ms per test ✅ (target: <100ms)

### Keep Tests Fast
```python
# ❌ Slow
def test_slow():
    time.sleep(1)
    result = process()

# ✅ Fast
def test_fast(mocker):
    mocker.patch('time.sleep')
    result = process()
```

### Use Fixtures Wisely
```python
# ❌ Slow - recreates for every test
@pytest.fixture
def big_data():
    return generate_large_dataset()

# ✅ Fast - shared across tests
@pytest.fixture(scope="module")
def big_data():
    return generate_large_dataset()
```

## Mutation Testing Strategy

For critical security modules, add mutation testing:

### Setup
```bash
pip install mutmut

# Configure in setup.cfg or pyproject.toml
[tool.mutmut]
paths_to_mutate = pyguard/lib/security.py,pyguard/lib/advanced_security.py
runner = pytest
tests_dir = tests/unit/
```

### Run
```bash
# Run mutation tests
mutmut run

# Show results
mutmut results
mutmut show

# Generate HTML report
mutmut html
```

### Interpret
- **Killed**: Test caught the mutation ✅
- **Survived**: Mutation not detected ⚠️ (add test)
- **Timeout**: Test too slow ⚠️
- **Suspicious**: Unusual behavior ⚠️

**Target**: ≥85% kill rate for security modules

## Continuous Improvement

### Weekly
- Run full test suite with different random seeds
- Review new modules for test coverage
- Fix any flaky tests immediately

### Monthly
- Review coverage reports for regressions
- Run mutation tests on critical modules
- Update test patterns based on learnings
- Refactor slow or brittle tests

### Quarterly
- Audit test quality (follow checklist)
- Update testing documentation
- Train team on testing best practices
- Evaluate new testing tools/techniques

## Getting Help

### Resources
- **TEST_PLAN.md**: Comprehensive strategy (350+ lines)
- **COVERAGE_STATUS.md**: Module-by-module analysis
- **tests/unit/test_security.py**: Template with 63 examples
- **tests/conftest.py**: Reusable fixtures

### Common Issues

**"Coverage not improving despite tests"**
- Ensure tests actually exercise the code paths
- Check for unreachable code (dead code)
- Use `--cov-report=html` to visualize missing lines

**"Tests are flaky"**
- Check for time dependencies (use freezegun)
- Check for order dependencies (use pytest-randomly)
- Check for file system race conditions (use unique tmp_path)

**"Tests are slow"**
- Profile with `pytest --durations=10`
- Mock I/O operations
- Use module/session-scoped fixtures for expensive setup

**"Can't test framework-specific code"**
- Mock the framework imports
- Test pattern detection logic separately
- Consider optional integration tests

## Conclusion

### What's Been Done ✅
- Solid foundation with security.py at 98% coverage
- Comprehensive test infrastructure and fixtures
- Clear documentation and patterns established
- 58 new high-quality tests added

### What's Needed 📋
- ~650 additional tests for remaining modules
- Focus on 5 critical modules <70% coverage
- Estimated 4-8 weeks for comprehensive coverage

### Recommendation 💡
Continue incremental improvement using the patterns established in security.py. Focus on one critical module per week, using this document and TEST_PLAN.md as guides. The infrastructure is solid, the pattern is proven, and the path forward is clear.

**Start with**: framework_django.py (60%) → pylint_rules.py (61%) → refurb_patterns.py (69%)

---

**Questions?** See TEST_PLAN.md for detailed strategies or examine test_security.py for comprehensive examples.
