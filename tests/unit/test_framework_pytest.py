"""Tests for pytest framework rules module."""

from pathlib import Path

import pytest

from pyguard.lib.framework_pytest import PYTEST_RULES, PytestRulesChecker


class TestPytestRulesDetection:
    """Test detection of pytest-specific issues."""

    def test_detect_fixture_no_call(self, tmp_path):
        """Test detection of fixture without call."""
        code = '''
import pytest
from pytest import fixture

@fixture
def test_my_fixture():
    return "value"
'''
        file_path = tmp_path / "test_something.py"
        file_path.write_text(code)

        checker = PytestRulesChecker()
        violations = checker.check_file(file_path)

        # PT001 checks for @fixture instead of @pytest.fixture()
        assert len(violations) > 0
        assert any(v.rule_id == "PT001" for v in violations)

    def test_detect_raises_without_exception(self, tmp_path):
        """Test detection of pytest.raises() without exception type."""
        code = '''
import pytest

def test_something():
    with pytest.raises():
        do_something()
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PytestRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PT011" for v in violations)

    def test_detect_assert_false(self, tmp_path):
        """Test detection of assert False."""
        code = '''
import pytest

def test_feature():
    assert False, "Not implemented yet"
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PytestRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PT015" for v in violations)

    def test_detect_composite_assertion(self, tmp_path):
        """Test detection of composite assertions."""
        code = '''
def test_values():
    x = 5
    y = 3
    assert x > 0 and y < 10
'''
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
