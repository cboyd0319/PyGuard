"""Tests for Pylint rules module."""

from pathlib import Path

import pytest

from pyguard.lib.pylint_rules import PYLINT_RULES, PylintRulesChecker


class TestPylintRulesDetection:
    """Test detection of Pylint rule violations."""

    def test_detect_too_many_return_statements(self, tmp_path):
        """Test detection of too many returns."""
        code = '''
def complex_function(x):
    if x == 1: return 1
    if x == 2: return 2
    if x == 3: return 3
    if x == 4: return 4
    if x == 5: return 5
    if x == 6: return 6
    if x == 7: return 7
    return 0
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PylintRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PLR0911" for v in violations)

    def test_detect_too_many_arguments(self, tmp_path):
        """Test detection of too many arguments."""
        code = '''
def many_args(a, b, c, d, e, f, g):
    pass
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PylintRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PLR0913" for v in violations)

    def test_detect_too_many_instance_attributes(self, tmp_path):
        """Test detection of too many instance attributes."""
        code = '''
class DataClass:
    def __init__(self):
        self.a = 1
        self.b = 2
        self.c = 3
        self.d = 4
        self.e = 5
        self.f = 6
        self.g = 7
        self.h = 8
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PylintRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PLR0902" for v in violations)

    def test_detect_compare_to_empty_string(self, tmp_path):
        """Test detection of comparison to empty string."""
        code = '''
if text == "":
    pass
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PylintRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PLC1901" for v in violations)

    def test_detect_global_statement(self, tmp_path):
        """Test detection of global statement."""
        code = '''
count = 0

def increment():
    global count
    count += 1
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PylintRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PLW0603" for v in violations)

    def test_detect_assert_on_tuple(self, tmp_path):
        """Test detection of assert on tuple."""
        code = '''
assert (1, 2), "This is a tuple assertion"
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PylintRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PLW0129" for v in violations)

    def test_rules_registered(self):
        """Test that all Pylint rules are registered."""
        assert len(PYLINT_RULES) >= 20
        rule_ids = [rule.rule_id for rule in PYLINT_RULES]
        assert "PLR0911" in rule_ids
        assert "PLR0913" in rule_ids
        assert "PLW0603" in rule_ids
        assert "PLE0711" in rule_ids
