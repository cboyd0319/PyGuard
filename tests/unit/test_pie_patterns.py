"""Tests for PIE patterns module."""

from pathlib import Path

import pytest

from pyguard.lib.pie_patterns import PIE_RULES, PIEPatternChecker


class TestPIEPatternDetection:
    """Test detection of code smells and unnecessary patterns."""

    def test_detect_unnecessary_pass(self, tmp_path):
        """Test detection of unnecessary pass."""
        code = '''
def empty_func():
    pass
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE790" for v in violations)

    def test_detect_is_false_comparison(self, tmp_path):
        """Test detection of == False."""
        code = '''
if value == False:
    pass
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE792" for v in violations)

    def test_detect_is_true_comparison(self, tmp_path):
        """Test detection of == True."""
        code = '''
if value == True:
    pass
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE793" for v in violations)

    def test_detect_class_with_only_init(self, tmp_path):
        """Test detection of class with only __init__."""
        code = '''
class DataHolder:
    def __init__(self, value):
        self.value = value
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE794" for v in violations)

    def test_detect_unnecessary_list_comp(self, tmp_path):
        """Test detection of unnecessary list comprehension."""
        code = '''
result = list([x for x in range(10)])
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE797" for v in violations)

    def test_detect_unnecessary_else_after_return(self, tmp_path):
        """Test detection of unnecessary else after return."""
        code = '''
def func(x):
    if x > 0:
        return True
    else:
        return False
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE808" for v in violations)

    def test_no_violations_for_clean_code(self, tmp_path):
        """Test that clean code produces no violations."""
        code = '''
def func(value):
    if value is True:
        return "yes"
    return "no"

class ProperClass:
    def __init__(self, val):
        self.val = val
    
    def method(self):
        return self.val * 2
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        # Should have no PIE792, PIE793, PIE808 violations
        assert not any(v.rule_id in ("PIE792", "PIE793", "PIE808") for v in violations)


class TestAutoFix:
    """Test automatic fixes for code smells."""

    def test_fix_is_false_comparison(self, tmp_path):
        """Test fixing == False to is False."""
        code = '''
if value == False:
    print("no")
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 1

        fixed_code = file_path.read_text()
        assert "is False" in fixed_code
        assert "== False" not in fixed_code

    def test_fix_is_true_comparison(self, tmp_path):
        """Test fixing == True to is True."""
        code = '''
if value == True:
    print("yes")
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 1

        fixed_code = file_path.read_text()
        assert "is True" in fixed_code
        assert "== True" not in fixed_code

    def test_fix_multiple_issues(self, tmp_path):
        """Test fixing multiple issues at once."""
        code = '''
def check(a, b):
    if a == True and b == False:
        return True
    return False
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 2

        fixed_code = file_path.read_text()
        assert "is True" in fixed_code
        assert "is False" in fixed_code
        assert "== True" not in fixed_code
        assert "== False" not in fixed_code


class TestRuleRegistration:
    """Test that PIE rules are properly defined."""

    def test_rules_defined(self):
        """Test that PIE rules are defined."""
        assert len(PIE_RULES) >= 14
        rule_ids = {rule.rule_id for rule in PIE_RULES}
        expected_ids = {
            "PIE790", "PIE791", "PIE792", "PIE793", "PIE794",
            "PIE795", "PIE796", "PIE797", "PIE799", "PIE800",
            "PIE801", "PIE804", "PIE807", "PIE808"
        }
        assert expected_ids.issubset(rule_ids)

    def test_rule_metadata(self):
        """Test that rules have proper metadata."""
        for rule in PIE_RULES:
            assert rule.rule_id.startswith("PIE")
            assert rule.name
            assert rule.description
            assert rule.message_template
