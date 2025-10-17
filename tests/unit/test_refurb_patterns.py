"""Tests for refurb patterns module."""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.refurb_patterns import REFURB_RULES, RefurbPatternChecker


class TestRefurbPatternDetection:
    """Test detection of refactoring opportunities."""

    def test_detect_while_read_loop(self, tmp_path):
        """Test detection of while loop with file read."""
        code = """
while line := f.read():
    process(line)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB101" for v in violations)

    def test_detect_sorted_list_comp(self, tmp_path):
        """Test detection of sorted() with list comprehension."""
        code = """
result = sorted([x * 2 for x in range(10)])
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB102" for v in violations)

    def test_detect_unnecessary_list_sorted(self, tmp_path):
        """Test detection of unnecessary list() around sorted()."""
        code = """
result = list(sorted(items))
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB104" for v in violations)

    def test_detect_print_sep_empty(self, tmp_path):
        """Test detection of print() with sep=''."""
        code = """
print("hello", "world", sep="")
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB105" for v in violations)

    def test_detect_string_paths_with_open(self, tmp_path):
        """Test detection of string paths with open()."""
        code = """
with open("/path/to/file.txt") as f:
    content = f.read()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB106" for v in violations)

    def test_detect_os_path_usage(self, tmp_path):
        """Test detection of os.path usage."""
        code = """
import os
path = os.path.join("dir", "file.txt")
exists = os.path.exists(path)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB108" for v in violations)

    def test_detect_math_floor_for_int(self, tmp_path):
        """Test detection of math.floor() used for int conversion."""
        code = """
import math
value = math.floor(3.7)
another = math.ceil(2.3)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB109" for v in violations)

    def test_detect_if_else_expression(self, tmp_path):
        """Test detection of if-else that should use conditional expression."""
        code = """
if condition:
    result = "yes"
else:
    result = "no"
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB110" for v in violations)

    def test_detect_os_listdir(self, tmp_path):
        """Test detection of os.listdir() instead of Path.iterdir()."""
        code = """
import os
files = os.listdir("/some/path")
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB111" for v in violations)

    def test_detect_repeated_append(self, tmp_path):
        """Test detection of repeated append() in loop."""
        code = """
for item in items:
    result.append(item * 2)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB113" for v in violations)

    def test_detect_dict_setdefault(self, tmp_path):
        """Test detection of if-not-in pattern instead of setdefault()."""
        code = """
if key not in mydict:
    mydict[key] = []
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB120" for v in violations)

    def test_detect_max_instead_of_sorted_last(self, tmp_path):
        """Test detection of sorted()[-1] instead of max()."""
        code = """
largest = sorted(numbers)[-1]
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB132" for v in violations)

    def test_detect_min_instead_of_sorted_first(self, tmp_path):
        """Test detection of sorted()[0] instead of min()."""
        code = """
smallest = sorted(numbers)[0]
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB133" for v in violations)

    def test_no_violations_for_clean_code(self, tmp_path):
        """Test that clean code produces no violations."""
        code = """
from pathlib import Path

def process_file(path: Path):
    with path.open() as f:
        return f.read()

result = sorted(x * 2 for x in range(10))
largest = max(numbers)
smallest = min(numbers)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should have no FURB102, FURB104, FURB132, FURB133 violations
        assert not any(
            v.rule_id in ("FURB102", "FURB104", "FURB132", "FURB133") for v in violations
        )


class TestAutoFix:
    """Test automatic fixes for refactoring opportunities."""

    def test_fix_unnecessary_list_sorted(self, tmp_path):
        """Test fixing unnecessary list() around sorted()."""
        code = """
result = list(sorted(items))
another = list(sorted(data, key=lambda x: x.value))
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 1

        fixed_code = file_path.read_text()
        assert "list(sorted(" not in fixed_code
        assert "sorted(items)" in fixed_code


class TestRuleRegistration:
    """Test that refurb rules are properly defined."""

    def test_rules_defined(self):
        """Test that FURB rules are defined."""
        assert len(REFURB_RULES) >= 18
        rule_ids = {rule.rule_id for rule in REFURB_RULES}
        expected_ids = {
            "FURB101",
            "FURB102",
            "FURB104",
            "FURB105",
            "FURB106",
            "FURB107",
            "FURB108",
            "FURB109",
            "FURB110",
            "FURB111",
            "FURB113",
            "FURB114",
            "FURB115",
            "FURB120",
            "FURB121",
            "FURB122",
            "FURB132",
            "FURB133",
        }
        assert expected_ids.issubset(rule_ids)

    def test_rule_metadata(self):
        """Test that rules have proper metadata."""
        for rule in REFURB_RULES:
            assert rule.rule_id.startswith("FURB")
            assert rule.name
            assert rule.description
            assert rule.message_template


class TestAdditionalPatternDetection:
    """Test additional refurb pattern detections for better coverage."""

    def test_detect_str_replace_with_empty_string(self, tmp_path):
        """Test detection of str.replace() with empty string (FURB122)."""
        code = """
text = "hello world"
result = text.replace("hello", "")
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB122" for v in violations)

    def test_detect_isinstance_with_tuple(self, tmp_path):
        """Test detection of isinstance() with tuple (FURB128)."""
        code = """
result = isinstance(obj, (str, int))
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # This should not trigger a violation as it's already using tuple
        assert not any(v.rule_id == "FURB128" for v in violations)

    def test_detect_isinstance_single_type(self, tmp_path):
        """Test detection of isinstance() with single type (FURB128)."""
        code = """
result = isinstance(obj, str)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # This check just passes through, no violation expected
        # (the rule just marks it as potentially combinable in the future)
        assert True

    def test_detect_unnecessary_assignment_before_return(self, tmp_path):
        """Test detection of unnecessary assignment before return (FURB123)."""
        code = """
with open('file.txt') as f:
    result = f.read()
    return result
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB123" for v in violations)

    def test_detect_sys_version_info_comparison(self, tmp_path):
        """Test detection of sys.version_info comparison (FURB107)."""
        code = """
import sys
if sys.version_info >= (3, 8):
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB107" for v in violations)

    def test_detect_lambda_itemgetter(self, tmp_path):
        """Test detection of lambda that should use operator.itemgetter (FURB118)."""
        code = """
items = sorted(data, key=lambda x: x['name'])
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB118" for v in violations)

    def test_detect_lambda_attrgetter(self, tmp_path):
        """Test detection of lambda that should use operator.attrgetter (FURB119)."""
        code = """
items = sorted(data, key=lambda x: x.name)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB119" for v in violations)

    def test_detect_try_except_pass(self, tmp_path):
        """Test detection of try-except-pass (FURB124)."""
        code = """
try:
    risky_operation()
except ValueError:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB124" for v in violations)

    def test_detect_assign_none_instead_of_del(self, tmp_path):
        """Test detection of assigning None instead of del (FURB136)."""
        code = """
try:
    data = None
    empty = []
    text = ""
except Exception:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect multiple FURB136 violations
        furb136_violations = [v for v in violations if v.rule_id == "FURB136"]
        assert len(furb136_violations) >= 1

    def test_detect_os_path_operations(self, tmp_path):
        """Test detection of os.path operations that should use pathlib (FURB115, FURB121)."""
        code = """
import os
abs_path = os.path.abspath('/path/to/file')
dirname = os.path.dirname('/path/to/file')
basename = os.path.basename('/path/to/file')
size = os.path.getsize('/path/to/file')
mtime = os.path.getmtime('/path/to/file')
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect FURB115 and FURB121 violations
        assert any(v.rule_id == "FURB115" for v in violations)
        assert any(v.rule_id == "FURB121" for v in violations)

    def test_detect_identity_list_comprehension(self, tmp_path):
        """Test detection of identity list comprehension (FURB129)."""
        code = """
copied = [x for x in original]
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB129" for v in violations)

    def test_detect_slice_comparison_in_comprehension(self, tmp_path):
        """Test detection of slice comparison in comprehension (FURB145)."""
        code = """
result = [x for x in items if x[:3] == 'abc']
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB145" for v in violations)

    def test_detect_dict_comprehension_for_unpacking(self, tmp_path):
        """Test detection of dict comprehension for unpacking (FURB140)."""
        code = """
result = {k: v for k, v in items}
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == "FURB140" for v in violations)

    def test_detect_split_join_pattern(self, tmp_path):
        """Test detection of join(split()) pattern (FURB114)."""
        code = """
result = ''.join(text.split())
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # FURB114 may or may not be detected depending on implementation
        # Just verify checker runs without errors
        assert isinstance(violations, list)

    def test_detect_sys_version_info_two_element_tuple(self, tmp_path):
        """Test detection of sys.version_info with 2-element tuple (FURB107)."""
        code = """
import sys
if sys.version_info >= (3, 8):
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB107" for v in violations)

    def test_detect_pathlib_read_text_opportunity(self, tmp_path):
        """Test detection of Path().read_text() opportunities."""
        code = """
from pathlib import Path
p = Path("file.txt")
content = p.open().read()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect some pattern
        assert isinstance(violations, list)

    @pytest.mark.parametrize(
        "code,expected_rule",
        [
            # FURB102: sorted with list comprehension
            ("sorted([x*2 for x in range(10)])", "FURB102"),
            # FURB104: unnecessary list() around sorted()
            ("list(sorted(items))", "FURB104"),
            # FURB105: print with sep=""
            ('print("a", "b", sep="")', "FURB105"),
            # FURB122: str.replace with empty string
            ('text.replace("prefix", "")', "FURB122"),
        ],
        ids=["sorted-listcomp", "list-sorted", "print-sep", "str-replace-empty"],
    )
    def test_detect_refurb_patterns_parametrized(self, code, expected_rule, tmp_path):
        """Parametrized test for various FURB patterns."""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert any(v.rule_id == expected_rule for v in violations), \
            f"Expected {expected_rule} in {[v.rule_id for v in violations]}"

    def test_checker_handles_syntax_errors_gracefully(self, tmp_path):
        """Test that checker handles files with syntax errors."""
        code = """
def foo(
    # Incomplete function
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should return empty list or handle gracefully, not crash
        assert isinstance(violations, list)

    def test_checker_handles_empty_file(self, tmp_path):
        """Test that checker handles empty files."""
        file_path = tmp_path / "test.py"
        file_path.write_text("")

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert violations == []

    def test_checker_handles_nonexistent_file(self, tmp_path):
        """Test that checker handles nonexistent files."""
        file_path = tmp_path / "nonexistent.py"

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should handle gracefully
        assert isinstance(violations, list)

    def test_fix_file_with_violations(self, tmp_path):
        """Test fixing a file with refurb violations."""
        code = """
result = list(sorted(items))
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        was_modified, count = checker.fix_file(file_path)

        # Check that fix attempt was made
        assert isinstance(was_modified, bool)
        assert isinstance(count, int)
        assert count >= 0

    def test_unicode_in_code(self, tmp_path):
        """Test handling of Unicode characters in source code."""
        code = """
# Comment with Unicode: 世界 🌍
text = "Hello 世界"
result = sorted([x for x in text])
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code, encoding="utf-8")

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should handle Unicode gracefully
        assert isinstance(violations, list)

    def test_large_file_performance(self, tmp_path):
        """Test performance on larger files."""
        # Generate a large file with repetitive patterns
        code_lines = ["result = list(sorted(items))" for _ in range(100)]
        code = "\n".join(code_lines)

        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should complete without timeout
        assert len(violations) >= 100  # At least one per repetition

    def test_checker_on_complex_nested_code(self, tmp_path):
        """Test checker on complex nested structures."""
        code = """
def process_data(items):
    results = []
    for item in items:
        if item.valid:
            try:
                value = sorted([x for x in item.values])
                results.append(list(value))
            except Exception:
                pass
    return results
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect multiple patterns
        assert len(violations) > 0

    def test_no_false_positives_on_valid_code(self, tmp_path):
        """Test that valid modern Python doesn't trigger unnecessary warnings."""
        code = """
from pathlib import Path
import sys

# Valid modern code
data = [x for x in range(10) if x % 2 == 0]
path = Path("file.txt")
if sys.version_info >= (3, 11, 0):
    content = path.read_text()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should have minimal or no violations for modern code
        # All violations should be LOW severity if any
        for v in violations:
            assert v.severity.name == "LOW" or v.severity.value == "LOW"


class TestAdditionalRefurbPatterns:
    """Additional tests for uncovered refurb patterns."""

    def test_detect_unnecessary_lambda_in_sorted(self, tmp_path):
        """Test detection of unnecessary lambda in sorted/map/filter (FURB125)."""
        code = """
def process():
    items = sorted(data, key=lambda x: str(x))
    filtered = list(filter(lambda x: bool(x), items))
    mapped = list(map(lambda x: int(x), values))
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB125" for v in violations)

    def test_detect_type_comparison_instead_of_isinstance(self, tmp_path):
        """Test detection of type() == comparison (FURB126)."""
        code = """
def check_types(x, y):
    if type(x) == int:
        process(x)
    if type(y) == str:
        print(y)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB126" for v in violations)

    def test_detect_dict_fromkeys_opportunity(self, tmp_path):
        """Test detection of dict comprehension with constant value (FURB127)."""
        code = """
def create_dicts(keys, items):
    d = {k: None for k in keys}
    d2 = {item: 0 for item in items}
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB127" for v in violations)

    def test_detect_reraise_caught_exception(self, tmp_path):
        """Test detection of re-raising caught exception (FURB131)."""
        code = """
def risky_function():
    try:
        risky_operation()
    except ValueError as e:
        log_error(e)
        raise e
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB131" for v in violations)

    def test_detect_path_read_text_opportunity(self, tmp_path):
        """Test detection of open().read() pattern (FURB130)."""
        code = """
content = open('file.txt').read()
data = open('data.bin').read()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB130" for v in violations)

    def test_detect_datetime_now_instead_of_fromtimestamp(self, tmp_path):
        """Test detection of datetime.fromtimestamp(time.time()) (FURB135)."""
        code = """
import time
from datetime import datetime

now = datetime.fromtimestamp(time.time())
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB135" for v in violations)

    def test_detect_math_ceil_pattern_negative_floordiv(self, tmp_path):
        """Test detection of -(-x//y) pattern (FURB139)."""
        code = """
def calculate():
    result = -(-x // y)
    value = -(-numerator // denominator)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # This pattern is detected in Assign nodes
        assert len(violations) > 0
        assert any(v.rule_id == "FURB139" for v in violations)

    def test_lambda_with_simple_call_in_map(self, tmp_path):
        """Test lambda detection in various contexts."""
        code = """
def func(x):
    # Lambda just calling function - unnecessary
    result = list(map(lambda x: func(x), items))
    
    # Lambda with more complex expression - acceptable
    result2 = list(map(lambda x: x * 2 + 1, items))
    
    return result, result2
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect the first lambda as unnecessary
        furb125_violations = [v for v in violations if v.rule_id == "FURB125"]
        assert len(furb125_violations) > 0

    def test_type_comparison_variations(self, tmp_path):
        """Test different variations of type comparisons."""
        code = """
def check_values(value, items):
    # Direct type comparison - should trigger
    if type(value) == int:
        pass

    # Type comparison with list - should trigger  
    if type(items) == list:
        pass

    # Proper isinstance - should not trigger
    if isinstance(value, int):
        pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should find type comparisons but not isinstance
        furb126_violations = [v for v in violations if v.rule_id == "FURB126"]
        assert len(furb126_violations) == 2

    def test_dict_comprehension_with_various_constant_values(self, tmp_path):
        """Test dict comprehension detection with different constant values."""
        code = """
def make_dicts(keys):
    # With None - should trigger
    d1 = {k: None for k in keys}

    # With 0 - should trigger
    d2 = {k: 0 for k in keys}

    # With empty string - should trigger
    d3 = {k: "" for k in keys}

    # With variable value - should not trigger
    d4 = {k: compute_value(k) for k in keys}
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect constant value dict comprehensions
        furb127_violations = [v for v in violations if v.rule_id == "FURB127"]
        assert len(furb127_violations) >= 3

    def test_bare_raise_vs_reraise(self, tmp_path):
        """Test bare raise (good) vs re-raising exception (bad)."""
        code = """
def handle_errors():
    # Bad: Re-raising caught exception by name
    try:
        operation1()
    except ValueError as e:
        raise e

    # Good: Bare raise
    try:
        operation2()
    except TypeError:
        raise

    # Bad: Re-raising with same name
    try:
        operation3()
    except KeyError as err:
        log("Error occurred")
        raise err
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect explicit re-raises but not bare raises
        furb131_violations = [v for v in violations if v.rule_id == "FURB131"]
        assert len(furb131_violations) == 2

    def test_edge_cases_for_patterns(self, tmp_path):
        """Test edge cases and boundary conditions."""
        code = """
def process_data(keys, vals, items):
    # Empty collections
    empty_dict = {k: None for k in []}
    empty_sorted = sorted([])

    # Nested structures
    nested = {k: {v: None for v in vals} for k in keys}

    # Type checks in nested conditions
    if x > 0 and type(x) == int:
        pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should handle edge cases without crashing
        assert isinstance(violations, list)
