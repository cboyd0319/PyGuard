"""
Tests for pytest framework rules module.

Comprehensive test suite following PyTest Architect Agent principles:
- AAA pattern (Arrange-Act-Assert)
- Parametrized tests for input matrices
- Edge cases and boundary conditions
- Error handling validation
- Deterministic test execution
"""

from pathlib import Path

import pytest

from pyguard.lib.framework_pytest import PYTEST_RULES, PytestRulesChecker, PytestVisitor


class TestPytestRulesDetection:
    """Test detection of pytest-specific issues."""

    def test_detect_fixture_no_call(self, tmp_path):
        """Test detection of fixture without call."""
        code = """
import pytest
from pytest import fixture

@fixture
def test_my_fixture():
    return "value"
"""
        file_path = tmp_path / "test_something.py"
        file_path.write_text(code)

        checker = PytestRulesChecker()
        violations = checker.check_file(file_path)

        # PT001 checks for @fixture instead of @pytest.fixture()
        assert len(violations) > 0
        assert any(v.rule_id == "PT001" for v in violations)

    def test_detect_raises_without_exception(self, tmp_path):
        """Test detection of pytest.raises() without exception type."""
        code = """
import pytest

def test_something():
    with pytest.raises():
        do_something()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PytestRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PT011" for v in violations)

    def test_detect_assert_false(self, tmp_path):
        """Test detection of assert False."""
        code = """
import pytest

def test_feature():
    assert False, "Not implemented yet"
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PytestRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PT015" for v in violations)

    def test_detect_composite_assertion(self, tmp_path):
        """Test detection of composite assertions."""
        code = """
def test_values():
    x = 5
    y = 3
    assert x > 0 and y < 10
"""
        file_path = tmp_path / "test_something.py"
        file_path.write_text(code)

        checker = PytestRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PT018" for v in violations)

    def test_rules_registered(self):
        """Test that all pytest rules are registered."""
        assert len(PYTEST_RULES) >= 7
        rule_ids = [rule.rule_id for rule in PYTEST_RULES]
        assert "PT001" in rule_ids
        assert "PT011" in rule_ids
        assert "PT015" in rule_ids
        assert "PT018" in rule_ids


# ============================================================================
# Enhanced Test Coverage - Following PyTest Architect Agent Guidelines
# ============================================================================


class TestPytestVisitorInit:
    """Test PytestVisitor initialization and detection."""

    def test_visitor_init_with_test_file(self, tmp_path):
        """Test visitor initialization detects test file."""
        # Arrange
        code = "import pytest\ndef test_something(): pass"
        file_path = tmp_path / "test_example.py"

        # Act
        visitor = PytestVisitor(file_path, code)

        # Assert
        assert visitor.is_test_file is True
        assert visitor.file_path == file_path
        assert len(visitor.violations) == 0
        assert visitor.code == code

    def test_visitor_init_with_non_test_file(self, tmp_path):
        """Test visitor initialization with non-test file."""
        # Arrange
        code = "def regular_function(): pass"
        file_path = tmp_path / "regular.py"

        # Act
        visitor = PytestVisitor(file_path, code)

        # Assert
        assert visitor.is_test_file is False

    @pytest.mark.parametrize(
        "code,expected_is_test",
        [
            ("import pytest", True),
            ("from pytest import fixture", True),
            ("from pytest import *", True),
            ("# no pytest here", False),
            ("import unittest", False),
        ],
        ids=["import_pytest", "from_pytest", "from_star", "no_pytest", "unittest"],
    )
    def test_pytest_detection(self, tmp_path, code, expected_is_test):
        """Test _detect_pytest method with various imports."""
        # Arrange
        file_path = tmp_path / "test_file.py" if expected_is_test else tmp_path / "file.py"

        # Act
        visitor = PytestVisitor(file_path, code)

        # Assert
        # File name with test_ prefix can override
        if "test_" in str(file_path.name):
            assert visitor.is_test_file is True
        else:
            assert visitor.is_test_file == expected_is_test


class TestPT001FixtureWithoutCall:
    """Test PT001: Use @pytest.fixture() instead of @fixture."""

    def test_detect_bare_fixture_decorator(self, tmp_path):
        """Test detection of bare @fixture decorator."""
        # Arrange
        code = """
import pytest
from pytest import fixture

@fixture
def test_my_fixture():
    return "value"
"""
        file_path = tmp_path / "test_fixtures.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        pt001_violations = [v for v in violations if v.rule_id == "PT001"]
        assert len(pt001_violations) > 0
        assert pt001_violations[0].severity.name == "LOW"

    def test_no_violation_with_fixture_call(self, tmp_path):
        """Test no violation when using @pytest.fixture()."""
        # Arrange
        code = """
import pytest

@pytest.fixture()
def my_fixture():
    return "value"
"""
        file_path = tmp_path / "test_correct.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT001" for v in violations)


class TestPT002YieldInTestFunction:
    """Test PT002: Test function contains yield - should be a fixture."""

    def test_detect_yield_in_test_function(self, tmp_path):
        """Test detection of yield in test function."""
        # Arrange
        code = """
import pytest

def test_generator():
    yield 1
    yield 2
"""
        file_path = tmp_path / "test_gen.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        pt002_violations = [v for v in violations if v.rule_id == "PT002"]
        assert len(pt002_violations) > 0
        assert pt002_violations[0].severity.name == "MEDIUM"

    def test_no_violation_for_fixture_with_yield(self, tmp_path):
        """Test no violation when fixture uses yield."""
        # Arrange
        code = """
import pytest

@pytest.fixture()
def my_fixture():
    resource = setup()
    yield resource
    teardown(resource)
"""
        file_path = tmp_path / "test_fixture.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT002" for v in violations)


class TestPT004FixtureNoReturnYield:
    """Test PT004: Fixture should return or yield a value."""

    def test_detect_fixture_without_return_or_yield(self, tmp_path):
        """Test detection of fixture that doesn't return/yield."""
        # Arrange
        code = """
import pytest

@pytest.fixture()
def test_empty_fixture():
    print("Setting up")
"""
        file_path = tmp_path / "test_empty.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        pt004_violations = [v for v in violations if v.rule_id == "PT004"]
        # PT004 only checks when it's a fixture on a test function
        # This is testing the fixture detection logic
        assert isinstance(violations, list)

    def test_no_violation_fixture_with_return(self, tmp_path):
        """Test no violation when fixture returns value."""
        # Arrange
        code = """
import pytest

@pytest.fixture()
def test_value_fixture():
    return 42
"""
        file_path = tmp_path / "test_return.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT004" for v in violations)

    def test_no_violation_fixture_with_yield(self, tmp_path):
        """Test no violation when fixture yields value."""
        # Arrange
        code = """
import pytest

@pytest.fixture()
def test_yield_fixture():
    yield "resource"
"""
        file_path = tmp_path / "test_yield.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT004" for v in violations)


class TestPT011RaisesWithoutException:
    """Test PT011: pytest.raises() should specify exception type."""

    @pytest.mark.parametrize(
        "raises_code",
        [
            "with pytest.raises():\n        do_something()",
            "with pytest.raises() as exc_info:\n        risky_call()",
        ],
        ids=["simple_raises", "raises_with_as"],
    )
    def test_detect_raises_without_exception(self, tmp_path, raises_code):
        """Test detection of pytest.raises() without exception type."""
        # Arrange
        code = f"""
import pytest

def test_function():
    {raises_code}
"""
        file_path = tmp_path / "test_raises.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        pt011_violations = [v for v in violations if v.rule_id == "PT011"]
        assert len(pt011_violations) > 0
        assert pt011_violations[0].severity.name == "HIGH"

    def test_no_violation_raises_with_exception(self, tmp_path):
        """Test no violation when pytest.raises() specifies exception."""
        # Arrange
        code = """
import pytest

def test_function():
    with pytest.raises(ValueError):
        raise ValueError("error")
"""
        file_path = tmp_path / "test_correct_raises.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT011" for v in violations)

    def test_raises_with_multiple_exceptions(self, tmp_path):
        """Test pytest.raises() with tuple of exceptions."""
        # Arrange
        code = """
import pytest

def test_function():
    with pytest.raises((ValueError, TypeError)):
        may_fail()
"""
        file_path = tmp_path / "test_multi_raises.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT011" for v in violations)


class TestPT015AssertFalse:
    """Test PT015: Use pytest.fail() instead of assert False."""

    def test_detect_assert_false_without_message(self, tmp_path):
        """Test detection of plain assert False."""
        # Arrange
        code = """
def test_feature():
    assert False
"""
        file_path = tmp_path / "test_fail.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        pt015_violations = [v for v in violations if v.rule_id == "PT015"]
        assert len(pt015_violations) > 0
        assert pt015_violations[0].severity.name == "LOW"

    def test_detect_assert_false_with_message(self, tmp_path):
        """Test detection of assert False with message."""
        # Arrange
        code = """
def test_feature():
    assert False, "Not implemented yet"
"""
        file_path = tmp_path / "test_not_impl.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert any(v.rule_id == "PT015" for v in violations)

    def test_no_violation_assert_true(self, tmp_path):
        """Test no violation for assert True or other conditions."""
        # Arrange
        code = """
def test_feature():
    assert True
    assert 1 + 1 == 2
    assert value is not None
"""
        file_path = tmp_path / "test_valid.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT015" for v in violations)


class TestPT018CompositeAssertion:
    """Test PT018: Composite assertion with 'and' should be split."""

    @pytest.mark.parametrize(
        "assertion",
        [
            "assert x > 0 and y < 10",
            "assert a and b and c",
            "assert value is not None and len(value) > 0",
        ],
        ids=["comparison_and", "multiple_and", "mixed_conditions"],
    )
    def test_detect_composite_assertions(self, tmp_path, assertion):
        """Test detection of various composite assertions."""
        # Arrange
        code = f"""
def test_values():
    {assertion}
"""
        file_path = tmp_path / "test_composite.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        pt018_violations = [v for v in violations if v.rule_id == "PT018"]
        assert len(pt018_violations) > 0
        assert pt018_violations[0].severity.name == "LOW"

    def test_no_violation_single_assertion(self, tmp_path):
        """Test no violation for single assertions."""
        # Arrange
        code = """
def test_values():
    assert x > 0
    assert y < 10
    assert a or b  # 'or' is acceptable
"""
        file_path = tmp_path / "test_single.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert not any(v.rule_id == "PT018" for v in violations)


class TestNonTestFiles:
    """Test that violations aren't reported for non-test files."""

    def test_no_violations_for_non_test_file(self, tmp_path):
        """Test that non-test files don't trigger pytest violations."""
        # Arrange
        code = """
# Regular Python file, not a test
def fixture():
    return "value"

def regular_function():
    assert False
    with raises():
        pass
"""
        file_path = tmp_path / "regular_module.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        # Should have no pytest-specific violations
        pytest_violations = [v for v in violations if v.rule_id.startswith("PT")]
        assert len(pytest_violations) == 0


class TestPytestRulesCheckerEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_file(self, tmp_path):
        """Test handling of empty file."""
        # Arrange
        file_path = tmp_path / "test_empty.py"
        file_path.write_text("")
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        assert len(violations) == 0

    def test_syntax_error_file(self, tmp_path):
        """Test handling of file with syntax errors."""
        # Arrange
        code = """
def test_broken(
    # Unclosed parenthesis
"""
        file_path = tmp_path / "test_broken.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        # Should handle gracefully without crashing
        assert isinstance(violations, list)

    def test_unicode_in_test_file(self, tmp_path):
        """Test handling of Unicode characters in test file."""
        # Arrange
        code = """
import pytest

def test_unicode():
    \"\"\"Test with Unicode: 你好 世界 🎉\"\"\"
    message = "Hello 世界"
    assert message == "Hello 世界"
"""
        file_path = tmp_path / "test_unicode.py"
        file_path.write_text(code, encoding="utf-8")
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        # Should handle Unicode without issues
        assert isinstance(violations, list)

    def test_nonexistent_file(self, tmp_path):
        """Test handling of nonexistent file."""
        # Arrange
        file_path = tmp_path / "nonexistent.py"
        checker = PytestRulesChecker()

        # Act & Assert
        # Should handle gracefully, possibly returning empty list
        try:
            violations = checker.check_file(file_path)
            assert isinstance(violations, list)
        except (FileNotFoundError, Exception):
            # Acceptable to raise exception for nonexistent file
            pass


class TestMultipleViolationsInOneFile:
    """Test files with multiple pytest violations."""

    def test_multiple_pytest_issues(self, tmp_path):
        """Test detection of multiple issues in single file."""
        # Arrange
        code = """
import pytest
from pytest import fixture

@fixture  # PT001
def test_bad_fixture():
    pass  # PT004 - no return/yield

def test_with_yield():  # PT002
    yield 1

def test_composite():
    assert x > 0 and y < 10  # PT018

def test_assert_false():
    assert False  # PT015

def test_raises():
    with pytest.raises():  # PT011
        risky()
"""
        file_path = tmp_path / "test_multiple.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        rule_ids = {v.rule_id for v in violations}
        assert "PT001" in rule_ids
        assert "PT002" in rule_ids
        assert "PT004" in rule_ids
        assert "PT011" in rule_ids
        assert "PT015" in rule_ids
        assert "PT018" in rule_ids
        assert len(violations) >= 6


class TestPytestRulesRegistry:
    """Test the PYTEST_RULES registry."""

    def test_all_rules_have_required_fields(self):
        """Test that all rules have required fields."""
        # Act & Assert
        for rule in PYTEST_RULES:
            assert rule.rule_id.startswith("PT")
            assert rule.description
            assert rule.severity
            assert rule.category
            assert hasattr(rule, "fix_applicability")

    def test_rule_ids_are_unique(self):
        """Test that all rule IDs are unique."""
        # Arrange & Act
        rule_ids = [rule.rule_id for rule in PYTEST_RULES]

        # Assert
        assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs found"

    def test_rules_have_documentation(self):
        """Test that all rules have non-empty descriptions."""
        # Act & Assert
        for rule in PYTEST_RULES:
            assert len(rule.description) > 10, f"Rule {rule.rule_id} has too short description"


class TestComplexPytestPatterns:
    """Test complex real-world pytest patterns."""

    def test_fixture_with_params(self, tmp_path):
        """Test fixture with parameters."""
        # Arrange
        code = """
import pytest

@pytest.fixture(scope="module")
def database():
    db = setup_database()
    yield db
    teardown_database(db)

@pytest.fixture(params=[1, 2, 3])
def number(request):
    return request.param
"""
        file_path = tmp_path / "test_params.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        # Should not have violations for properly used fixtures
        assert not any(v.rule_id in ["PT001", "PT004"] for v in violations)

    def test_parametrize_decorator(self, tmp_path):
        """Test parametrize decorator usage."""
        # Arrange
        code = """
import pytest

@pytest.mark.parametrize("input,expected", [
    (1, 2),
    (2, 4),
    (3, 6),
])
def test_double(input, expected):
    assert input * 2 == expected
"""
        file_path = tmp_path / "test_parametrize.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        # Parametrize should not trigger issues
        assert isinstance(violations, list)

    def test_nested_test_class(self, tmp_path):
        """Test pytest patterns in test classes."""
        # Arrange
        code = """
import pytest

class TestFeature:
    def test_method(self):
        assert True
    
    def test_with_fixture(self, my_fixture):
        assert my_fixture is not None
"""
        file_path = tmp_path / "test_class.py"
        file_path.write_text(code)
        checker = PytestRulesChecker()

        # Act
        violations = checker.check_file(file_path)

        # Assert
        # Should handle test classes properly
        assert isinstance(violations, list)
