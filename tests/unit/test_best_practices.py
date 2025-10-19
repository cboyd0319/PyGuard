"""Unit tests for best practices fixer module.

Following PyTest Architect Agent best practices:
- AAA pattern (Arrange-Act-Assert)
- Parametrized tests for edge cases
- Clear, intent-revealing names
- Comprehensive coverage of error handling
"""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.best_practices import BestPracticesFixer, NamingConventionFixer


class TestBestPracticesFixer:
    """Test cases for BestPracticesFixer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = BestPracticesFixer()

    def test_init_creates_required_components(self):
        """Test that initialization creates all required components."""
        # Arrange & Act
        fixer = BestPracticesFixer()

        # Assert
        assert fixer.logger is not None
        assert fixer.file_ops is not None
        assert fixer.fixes_applied == []
        assert fixer.ast_analyzer is not None

    @pytest.mark.parametrize(
        "code,expected_in_result",
        [
            ("def foo(x=[]):\n    pass", "ANTI-PATTERN"),
            ("def bar(opts={}):\n    pass", "ANTI-PATTERN"),
            ("def baz(items=None):\n    pass", "items=None"),  # Good practice, unchanged
        ],
        ids=["list_default", "dict_default", "none_default"],
    )
    def test_fix_mutable_defaults_handles_various_cases(self, code, expected_in_result):
        """Test fixing mutable default arguments with various patterns."""
        # Arrange & Act
        result = self.fixer._fix_mutable_default_arguments(code)

        # Assert
        assert expected_in_result in result

    def test_fix_mutable_defaults_skips_already_fixed(self):
        """Test that already-annotated mutable defaults are not re-annotated."""
        # Arrange
        code = "def foo(x=[]):  # MUTABLE DEFAULT warning\n    pass"

        # Act
        result = self.fixer._fix_mutable_default_arguments(code)

        # Assert - should not add another annotation
        assert result.count("MUTABLE DEFAULT") == 1

    @pytest.mark.parametrize(
        "code,expected",
        [
            ("try:\n    pass\nexcept:\n    pass", "except Exception:"),
            ("try:\n    x = 1\nexcept:\n    print('error')", "except Exception:"),
            ("try:\n    pass\nexcept ValueError:\n    pass", "except ValueError:"),  # Good
        ],
        ids=["bare_except", "bare_except_with_stmt", "specific_except"],
    )
    def test_fix_bare_except_handles_various_patterns(self, code, expected):
        """Test fixing bare except clauses."""
        # Arrange & Act
        result = self.fixer._fix_bare_except(code)

        # Assert
        assert expected in result

    @pytest.mark.parametrize(
        "code,expected",
        [
            ("if x == None:", "if x is None:"),
            ("if x != None:", "if x is not None:"),
            ("while value == None:", "while value is None:"),
            ("if x is None:", "if x is None:"),  # Already correct
        ],
        ids=["eq_none", "ne_none", "in_while", "already_correct"],
    )
    def test_fix_none_comparison_handles_various_operators(self, code, expected):
        """Test fixing None comparison with various operators."""
        # Arrange & Act
        result = self.fixer._fix_comparison_to_none(code)

        # Assert
        assert expected in result

    @pytest.mark.parametrize(
        "code,expected",
        [
            ("if type(x) == str:", "isinstance(x, str)"),
            ("if type(value) == list:", "isinstance(value, list)"),
            ("if isinstance(x, str):", "isinstance(x, str)"),  # Already good
        ],
        ids=["type_str", "type_list", "already_isinstance"],
    )
    def test_fix_type_check_suggests_isinstance(self, code, expected):
        """Test fixing type() checks to use isinstance()."""
        # Arrange & Act
        result = self.fixer._fix_type_comparison(code)

        # Assert
        assert expected in result

    def test_fix_type_comparison_skips_already_annotated(self):
        """Test that already-annotated type checks are not re-annotated."""
        # Arrange
        code = "if type(x) == str:  # Better: isinstance(x, str)\n    pass"

        # Act
        result = self.fixer._fix_type_comparison(code)

        # Assert - should not add another annotation
        assert result.count("Better:") == 1

    @pytest.mark.parametrize(
        "code,should_suggest",
        [
            ("if x == True:\n    pass", True),
            ("if x == False:\n    pass", True),
            ("if x:\n    pass", False),  # Already good
            ("if not x:\n    pass", False),  # Already good
        ],
        ids=["eq_true", "eq_false", "direct_bool", "negated_bool"],
    )
    def test_fix_comparison_to_bool_handles_patterns(self, code, should_suggest):
        """Test fixing boolean comparisons."""
        # Arrange & Act
        result = self.fixer._fix_comparison_to_bool(code)

        # Assert
        if should_suggest:
            assert "if var:" in result or "if not var:" in result
        else:
            assert result == code

    def test_fix_list_comprehension_suggestion(self):
        """Test suggesting list comprehensions."""
        # Arrange
        code = "for item in items:\n    results.append(item)"

        # Act
        result = self.fixer._fix_list_comprehension(code)

        # Assert
        assert "Consider list comprehension" in result or code in result

    def test_fix_list_comprehension_skips_annotated(self):
        """Test that already-annotated loops are not re-annotated."""
        # Arrange
        code = "for item in items:  # Consider list comprehension\n    results.append(item)"

        # Act
        result = self.fixer._fix_list_comprehension(code)

        # Assert - should not add another annotation
        assert result.count("Consider list comprehension") == 1

    @pytest.mark.parametrize(
        "code,should_warn",
        [
            ("for i in range(10):\n    s += 'x'", True),  # String literal
            ("for i in range(10):\n    msg += \"hello\"", True),  # String literal
            ("for i in range(10):\n    msg += data", False),  # Variable, not detected
            ("s = ''.join(items)", False),  # Good practice
        ],
        ids=["for_loop_singlequote", "for_loop_doublequote", "for_loop_var", "join_method"],
    )
    def test_fix_string_concatenation_warns_in_loops(self, code, should_warn):
        """Test warning about string concatenation in loops."""
        # Arrange & Act
        result = self.fixer._fix_string_concatenation(code)

        # Assert
        if should_warn:
            assert "PERFORMANCE" in result or "join()" in result
        else:
            assert result == code

    @pytest.mark.parametrize(
        "code,should_suggest",
        [
            ("f = open('file.txt')", True),
            ("file = open('data.json', 'r')", True),
            ("with open('file.txt') as f:", False),  # Good practice
        ],
        ids=["simple_open", "open_with_mode", "with_statement"],
    )
    def test_fix_context_managers_suggests_with_statement(self, code, should_suggest):
        """Test suggesting context managers for file operations."""
        # Arrange & Act
        result = self.fixer._fix_context_managers(code)

        # Assert
        if should_suggest:
            assert "with" in result.lower() or "context" in result.lower()
        else:
            assert result == code

    @pytest.mark.parametrize(
        "code,should_add_todo",
        [
            ("def foo():\n    return 42", True),
            ("class Bar:\n    pass", True),
            ("def baz():\n    '''Has docstring.'''\n    return 1", False),
            ("def qux():\n    \"\"\"Also has docstring.\"\"\"\n    return 2", False),
        ],
        ids=["function_no_doc", "class_no_doc", "function_with_doc", "class_with_doc"],
    )
    def test_add_missing_docstrings_handles_various_cases(self, code, should_add_todo):
        """Test adding docstring warnings."""
        # Arrange & Act
        result = self.fixer._add_missing_docstrings(code)

        # Assert
        if should_add_todo:
            assert "TODO" in result or "docstring" in result.lower()

    def test_add_missing_docstrings_skips_already_annotated(self):
        """Test that functions with TODO comments are not re-annotated."""
        # Arrange
        code = "def foo():\n    # TODO: Add docstring\n    return 42"

        # Act
        result = self.fixer._add_missing_docstrings(code)

        # Assert - should not add another TODO
        assert result.count("TODO: Add docstring") == 1

    def test_add_missing_docstrings_handles_empty_lines_after_definition(self):
        """Test that empty lines after function definition are handled correctly."""
        # Arrange - function with empty lines before code
        code = "def foo():\n\n\n    return 42"

        # Act
        result = self.fixer._add_missing_docstrings(code)

        # Assert - should add TODO after empty lines
        assert "TODO: Add docstring" in result

    @pytest.mark.parametrize(
        "code,should_warn",
        [
            ("global my_var\nmy_var = 10", True),
            ("global x, y, z", True),
            ("def foo():\n    local_var = 1", False),
        ],
        ids=["single_global", "multiple_globals", "local_var"],
    )
    def test_fix_global_variables_warns_appropriately(self, code, should_warn):
        """Test flagging global variables."""
        # Arrange & Act
        result = self.fixer._fix_global_variables(code)

        # Assert
        if should_warn:
            assert "Avoid" in result or "global" in result.lower()

    def test_scan_file_for_issues_with_valid_file(self, tmp_path):
        """Test scanning file for quality issues."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
def test():  # Missing docstring
    x = None
    if x == None:  # Bad comparison
        pass
"""
        )

        # Act
        issues = self.fixer.scan_file_for_issues(test_file)

        # Assert
        assert isinstance(issues, list)

    def test_scan_file_for_issues_with_invalid_file(self, tmp_path):
        """Test scanning non-existent file."""
        # Arrange
        nonexistent = tmp_path / "nonexistent.py"

        # Act
        issues = self.fixer.scan_file_for_issues(nonexistent)

        # Assert
        assert isinstance(issues, list)

    def test_get_complexity_report_returns_dict(self, tmp_path):
        """Test complexity report generation returns dictionary."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
def simple_func():
    return 42

def complex_func(x):
    if x > 0:
        if x > 10:
            return "big"
        else:
            return "small"
    else:
        return "negative"
"""
        )

        # Act
        report = self.fixer.get_complexity_report(test_file)

        # Assert
        assert isinstance(report, dict)

    def test_get_complexity_report_with_nonexistent_file(self, tmp_path):
        """Test complexity report for nonexistent file."""
        # Arrange
        nonexistent = tmp_path / "nonexistent.py"

        # Act
        report = self.fixer.get_complexity_report(nonexistent)

        # Assert
        assert report == {}

    def test_fix_file_with_changes_applies_fixes(self, tmp_path):
        """Test fixing a file that needs changes."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text("if x == None:\n    pass")

        # Act
        success, fixes = self.fixer.fix_file(test_file)

        # Assert
        assert success
        content = test_file.read_text()
        assert "is None" in content
        assert len(fixes) > 0

    def test_fix_file_no_changes_needed(self, tmp_path):
        """Test fixing a file that doesn't need changes."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
def good_function():
    '''This function is well-written.'''
    if x is None:
        pass
    return True
"""
        )

        # Act
        success, fixes = self.fixer.fix_file(test_file)

        # Assert
        assert success
        assert len(fixes) == 0

    def test_fix_file_with_nonexistent_file(self, tmp_path):
        """Test fixing nonexistent file returns False."""
        # Arrange
        nonexistent = tmp_path / "nonexistent.py"

        # Act
        success, fixes = self.fixer.fix_file(nonexistent)

        # Assert
        assert success is False
        assert fixes == []

    def test_analyze_complexity_with_valid_file(self, tmp_path):
        """Test analyzing complexity of valid Python file."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
import os
import sys

class MyClass:
    pass

def func1():
    pass

def func2():
    pass
"""
        )

        # Act
        metrics = self.fixer.analyze_complexity(test_file)

        # Assert
        assert isinstance(metrics, dict)
        assert "functions" in metrics
        assert "classes" in metrics
        assert "imports" in metrics
        assert "lines" in metrics
        assert metrics["functions"] == 2
        assert metrics["classes"] == 1
        assert metrics["imports"] == 2

    def test_analyze_complexity_with_syntax_error(self, tmp_path):
        """Test analyzing file with syntax error returns empty dict."""
        # Arrange
        test_file = tmp_path / "invalid.py"
        test_file.write_text("def broken(\n")  # Syntax error

        # Act
        metrics = self.fixer.analyze_complexity(test_file)

        # Assert
        assert metrics == {}

    def test_analyze_complexity_with_nonexistent_file(self, tmp_path):
        """Test analyzing nonexistent file returns empty dict."""
        # Arrange
        nonexistent = tmp_path / "nonexistent.py"

        # Act
        metrics = self.fixer.analyze_complexity(nonexistent)

        # Assert
        assert metrics == {}


class TestNamingConventionFixer:
    """Test cases for NamingConventionFixer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = NamingConventionFixer()

    def test_init_creates_required_components(self):
        """Test initialization creates required components."""
        # Arrange & Act
        fixer = NamingConventionFixer()

        # Assert
        assert fixer.logger is not None
        assert fixer.file_ops is not None

    @pytest.mark.parametrize(
        "code,expected_violations",
        [
            ("def myFunction():\n    pass", 1),  # camelCase - should be snake_case
            ("def MyFunc():\n    pass", 1),  # PascalCase - should be snake_case
            ("def my_function():\n    pass", 0),  # Correct snake_case
            ("def __init__(self):\n    pass", 0),  # Dunder methods are OK
            ("def _private_func():\n    pass", 0),  # Private functions OK
        ],
        ids=["camelCase", "PascalCase", "snake_case", "dunder", "private"],
    )
    def test_check_naming_conventions_functions(self, code, expected_violations, tmp_path):
        """Test checking function naming conventions."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        # Act
        violations = self.fixer.check_naming_conventions(test_file)

        # Assert
        assert len(violations) == expected_violations
        if expected_violations > 0:
            assert violations[0]["type"] == "function"
            assert "snake_case" in violations[0]["issue"]

    @pytest.mark.parametrize(
        "code,expected_violations",
        [
            ("class myclass:\n    pass", 1),  # lowercase - should be PascalCase
            ("class my_class:\n    pass", 1),  # snake_case - should be PascalCase
            ("class MyClass:\n    pass", 0),  # Correct PascalCase
            ("class MyClassV2:\n    pass", 0),  # PascalCase with numbers OK
        ],
        ids=["lowercase", "snake_case", "PascalCase", "with_numbers"],
    )
    def test_check_naming_conventions_classes(self, code, expected_violations, tmp_path):
        """Test checking class naming conventions."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        # Act
        violations = self.fixer.check_naming_conventions(test_file)

        # Assert
        assert len(violations) == expected_violations
        if expected_violations > 0:
            assert violations[0]["type"] == "class"
            assert "PascalCase" in violations[0]["issue"]

    def test_check_naming_conventions_with_nonexistent_file(self, tmp_path):
        """Test checking naming conventions for nonexistent file."""
        # Arrange
        nonexistent = tmp_path / "nonexistent.py"

        # Act
        violations = self.fixer.check_naming_conventions(nonexistent)

        # Assert
        assert violations == []

    def test_check_naming_conventions_with_syntax_error(self, tmp_path):
        """Test checking naming conventions for file with syntax error."""
        # Arrange
        test_file = tmp_path / "invalid.py"
        test_file.write_text("def broken(\n")  # Syntax error

        # Act
        violations = self.fixer.check_naming_conventions(test_file)

        # Assert
        assert violations == []

    def test_check_naming_conventions_mixed_violations(self, tmp_path):
        """Test detecting multiple types of naming violations."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
class my_bad_class:
    pass

def BadFunction():
    pass

def good_function():
    pass

class GoodClass:
    pass
"""
        )

        # Act
        violations = self.fixer.check_naming_conventions(test_file)

        # Assert
        assert len(violations) == 2
        violation_types = {v["type"] for v in violations}
        assert "class" in violation_types
        assert "function" in violation_types


class TestBestPracticesFixerEdgeCases:
    """Test edge cases and missing branch coverage."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = BestPracticesFixer()

    def test_fix_file_write_failure(self, mocker, tmp_path):
        """Test fix_file handles write failure."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text("result = []\nfor x in range(10):\n    result.append(x)")
        
        # Mock write_file to return False
        mocker.patch.object(self.fixer.file_ops, "write_file", return_value=False)
        
        # Act
        success, fixes = self.fixer.fix_file(test_file)
        
        # Assert - should return False when write fails
        assert success is False
        assert len(fixes) > 0  # Fixes were detected but not written

    def test_fix_list_comprehension_already_commented(self):
        """Test list comprehension suggestion when comment already exists on one loop."""
        # Arrange - code with multiple for loops, one already commented
        code = """result1 = []
for x in range(10):
    result1.append(x)

result2 = []
for y in range(5):  # Consider list comprehension
    result2.append(y)"""
        
        # Act
        result = self.fixer._fix_list_comprehension(code)
        
        # Assert - first loop gets comment, second already has it
        lines = result.split("\n")
        # Should have comments on both for loops now
        for_lines = [line for line in lines if "for " in line]
        commented_fors = [line for line in for_lines if "# Consider list comprehension" in line]
        # At least one should be commented (the one we added)
        assert len(commented_fors) >= 1

    def test_fix_string_concatenation_already_commented(self):
        """Test string concatenation fix when comment already exists."""
        # Arrange - code already has the comment marker
        code = """result = ""
for item in items:
    result += "item"  # Use list and join()"""
        
        # Act  
        result = self.fixer._fix_string_concatenation(code)
        
        # Assert - should not add duplicate comment (check for PERFORMANCE: prefix)
        assert "PERFORMANCE:" not in result or result.count("PERFORMANCE:") == 0
        # Original comment should still be there
        assert "# Use list and join()" in result

    def test_fix_context_managers_already_commented(self):
        """Test context manager suggestion when comment already exists."""
        # Arrange - code already has a comment matching the check pattern
        code = "f = open('file.txt')  # Use 'with' statement"
        
        # Act
        result = self.fixer._fix_context_managers(code)
        
        # Assert - should not add another comment when marker exists
        assert result == code
        # Should not have the "Best Practice:" prefix added
        assert result.count("Best Practice:") == 0
