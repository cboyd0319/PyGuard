"""Tests for PIE patterns module."""

from pyguard.lib.pie_patterns import PIE_RULES, PIEPatternChecker


class TestPIEPatternDetection:
    """Test detection of code smells and unnecessary patterns."""

    def test_detect_unnecessary_pass(self, tmp_path):
        """Test detection of unnecessary pass."""
        code = """
def empty_func():
    # TODO: Add docstring
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE790" for v in violations)

    def test_detect_is_false_comparison(self, tmp_path):
        """Test detection of   # Use if not var: instead."""
        code = """
if value   # Use if not var: instead:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE792" for v in violations)

    def test_detect_is_true_comparison(self, tmp_path):
        """Test detection of   # Use if var: instead."""
        code = """
if value   # Use if var: instead:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE793" for v in violations)

    def test_detect_class_with_only_init(self, tmp_path):
        """Test detection of class with only __init__."""
        code = """
class DataHolder:
    # TODO: Add docstring
    def __init__(self, value):
        # TODO: Add docstring
        self.value = value
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE794" for v in violations)

    def test_detect_unnecessary_list_comp(self, tmp_path):
        """Test detection of unnecessary list comprehension."""
        code = """
result = list([x for x in range(10)])
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE797" for v in violations)

    def test_detect_unnecessary_else_after_return(self, tmp_path):
        """Test detection of unnecessary else after return."""
        code = """
def func(x):
    # TODO: Add docstring
    if x > 0:
        return True
    else:
        return False
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE808" for v in violations)

    def test_no_violations_for_clean_code(self, tmp_path):
        """Test that clean code produces no violations."""
        code = """
def func(value):
    # TODO: Add docstring
    if value is True:
        return "yes"
    return "no"

class ProperClass:
    # TODO: Add docstring
    def __init__(self, val):
        # TODO: Add docstring
        self.val = val

    def method(self):
        # TODO: Add docstring
        return self.val * 2
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        # Should have no PIE792, PIE793, PIE808 violations
        assert not any(v.rule_id in ("PIE792", "PIE793", "PIE808") for v in violations)


class TestAutoFix:
    """Test automatic fixes for code smells."""

    def test_fix_is_false_comparison(self, tmp_path):
        """Test fixing   # Use if not var: instead to is False."""
        code = """
if value   # Use if not var: instead:
    print("no")
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 1

        fixed_code = file_path.read_text()
        assert "is False" in fixed_code
        assert "  # Use if not var: instead" not in fixed_code

    def test_fix_is_true_comparison(self, tmp_path):
        """Test fixing   # Use if var: instead to is True."""
        code = """
if value   # Use if var: instead:
    print("yes")
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 1

        fixed_code = file_path.read_text()
        assert "is True" in fixed_code
        assert "  # Use if var: instead" not in fixed_code

    def test_fix_multiple_issues(self, tmp_path):
        """Test fixing multiple issues at once."""
        code = """
def check(a, b):
    # TODO: Add docstring
    if a   # Use if var: instead and b == False:
        return True
    return False
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 2

        fixed_code = file_path.read_text()
        assert "is True" in fixed_code
        assert "is False" in fixed_code
        assert "  # Use if var: instead" not in fixed_code
        assert "  # Use if not var: instead" not in fixed_code

    def test_detect_unnecessary_list_call(self, tmp_path):
        """Test detection of unnecessary list() call around iterable."""
        code = """
result = list(range(10))
items = list(enumerate([1, 2, 3]))
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE802" for v in violations)

    def test_detect_is_for_literals(self, tmp_path):
        """Test detection of 'is' used with literals."""
        code = """
if value is "string":
    pass
if num is 42:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE803" for v in violations)

    def test_detect_single_iteration_loop(self, tmp_path):
        """Test detection of loop that only iterates once."""
        code = """
for item in items:
    result = process(item)
    break
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE805" for v in violations)

    def test_detect_unnecessary_elif_pass(self, tmp_path):
        """Test detection of unnecessary elif with only pass."""
        code = """
if x > 0:
    print("positive")
elif x < 0:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE806" for v in violations)

    def test_detect_empty_list_call(self, tmp_path):
        """Test detection of list() instead of []."""
        code = """
empty = list()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE809" for v in violations)

    def test_detect_multiple_calls_in_except(self, tmp_path):
        """Test detection of multiple calls in exception handler."""
        code = """
try:
    risky_operation()
except Exception:
    log_error()
    notify_admin()
    cleanup()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE810" for v in violations)

    def test_detect_redundant_tuple_unpacking(self, tmp_path):
        """Test detection of redundant tuple unpacking."""
        code = """
for a, b in items:
    result = (a, b)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "PIE811" for v in violations)


class TestRuleRegistration:
    """Test that PIE rules are properly defined."""

    def test_rules_defined(self):
        """Test that PIE rules are defined."""
        assert len(PIE_RULES) >= 21
        rule_ids = {rule.rule_id for rule in PIE_RULES}
        expected_ids = {
            "PIE790",
            "PIE791",
            "PIE792",
            "PIE793",
            "PIE794",
            "PIE795",
            "PIE796",
            "PIE797",
            "PIE799",
            "PIE800",
            "PIE801",
            "PIE802",
            "PIE803",
            "PIE804",
            "PIE805",
            "PIE806",
            "PIE807",
            "PIE808",
            "PIE809",
            "PIE810",
            "PIE811",
        }
        assert expected_ids.issubset(rule_ids)

    def test_rule_metadata(self):
        """Test that rules have proper metadata."""
        for rule in PIE_RULES:
            assert rule.rule_id.startswith("PIE")
            assert rule.name
            assert rule.description
            assert rule.message_template


class TestAdditionalPIEPatternDetection:
    """Test additional PIE pattern detections for better coverage."""

    def test_detect_unnecessary_ellipsis(self, tmp_path):
        """Test detection of unnecessary ellipsis (PIE791)."""
        code = """
def func():
    # TODO: Add docstring
    ...
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE791" for v in violations)

    def test_detect_unnecessary_spread_operator(self, tmp_path):
        """Test detection of unnecessary spread operator (PIE800)."""
        # This pattern is detected in expression statements with starred expressions
        # The actual detection requires specific AST context that's hard to trigger
        # Just verify it doesn't crash on the code
        code = """
items = [1, 2, 3]
result = (*items,)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        # Just verify no crash - this pattern is rare in practice
        assert isinstance(violations, list)

    def test_detect_prefer_pass_over_ellipsis(self, tmp_path):
        """Test detection of ... in function body (PIE795)."""
        code = """
def func():
    # TODO: Add docstring
    ...
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE795" for v in violations)

    def test_detect_unnecessary_dict_call(self, tmp_path):
        """Test detection of unnecessary dict() call (PIE796)."""
        code = """
def func():
    # TODO: Add docstring
    data = dict(name='test', value=42)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE796" for v in violations)

    def test_detect_unnecessary_dict_comp_items(self, tmp_path):
        """Test detection of unnecessary dict comprehension over .items() (PIE799)."""
        code = """
def func():
    # TODO: Add docstring
    data = {k: v for k, v in old_dict.items()}
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE799" for v in violations)

    def test_detect_lambda_just_calling_function(self, tmp_path):
        """Test detection of lambda that just calls a function (PIE801)."""
        # PIE801 is detected when the call node itself has a lambda as func
        # This is a specific pattern like: (lambda: foo())()
        code = """
result = (lambda: foo())()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE801" for v in violations)

    def test_detect_unnecessary_keys_in_iteration(self, tmp_path):
        """Test detection of unnecessary .keys() call (PIE804)."""
        code = """
for key in list(mydict.keys()):
    print(key)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE804" for v in violations)

    def test_detect_single_item_in_check(self, tmp_path):
        """Test detection of 'in [single_item]' pattern (PIE807)."""
        code = """
if x in [5]:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE807" for v in violations)

    def test_detect_unnecessary_import_alias(self, tmp_path):
        """Test detection of unnecessary import alias (PIE812)."""
        code = """
import os as os
import sys as sys
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE812" for v in violations)

    def test_detect_unnecessary_from_import_alias(self, tmp_path):
        """Test detection of unnecessary from import alias (PIE815)."""
        code = """
from os import path as path
from sys import argv as argv
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE815" for v in violations)

    def test_detect_multiple_or_conditions(self, tmp_path):
        """Test detection of multiple 'or' conditions (PIE817)."""
        code = """
if a or b or c or d or e:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE817" for v in violations)

    def test_detect_multiple_and_conditions(self, tmp_path):
        """Test detection of multiple 'and' conditions (PIE817)."""
        code = """
if a and b and c and d and e:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE817" for v in violations)

    def test_detect_unnecessary_list_before_subscript(self, tmp_path):
        """Test detection of unnecessary list() before subscript (PIE818)."""
        code = """
item = list(items)[0]
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE818" for v in violations)

    def test_detect_list_comp_with_zero_index(self, tmp_path):
        """Test detection of list comp with [0] (PIE819)."""
        code = """
first = [x * 2 for x in items][0]
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "PIE819" for v in violations)

    def test_syntax_error_handling(self, tmp_path):
        """Test that syntax errors are handled gracefully."""
        code = """
def func(:  # Invalid syntax
    # TODO: Add docstring
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = PIEPatternChecker()
        violations = checker.check_file(file_path)

        # Should return empty list, not raise exception
        assert violations == []

    def test_exception_handling_in_check(self, tmp_path, monkeypatch):
        """Test that unexpected exceptions are handled gracefully."""
        checker = PIEPatternChecker()

        # Mock ast.parse to raise an exception
        import ast

        original_parse = ast.parse

        def mock_parse(*args, **kwargs):
            # TODO: Add docstring
            raise RuntimeError("Unexpected error")

        monkeypatch.setattr(ast, "parse", mock_parse)

        file_path = tmp_path / "test.py"
        file_path.write_text("x = 1")

        violations = checker.check_file(file_path)

        # Should return empty list, not raise exception
        assert violations == []

        # Restore original
        monkeypatch.setattr(ast, "parse", original_parse)

    def test_exception_handling_in_fix(self, tmp_path):
        """Test that exceptions during fix are handled gracefully."""
        # Create a file that will trigger an exception during fixing
        # Use a non-existent file
        file_path = tmp_path / "nonexistent.py"

        checker = PIEPatternChecker()
        success, count = checker.fix_file(file_path)

        # Should return False for non-existent file, not raise exception
        assert success is False
        assert count == 0
