"""Tests for refurb patterns module."""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.refurb_patterns import REFURB_RULES, RefurbPatternChecker


class TestRefurbPatternDetection:
    """Test detection of refactoring opportunities."""

    def test_detect_while_read_loop(self, tmp_path):
        """Test detection of while loop with file read."""
        code = '''
while line := f.read():
    process(line)
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB101" for v in violations)

    def test_detect_sorted_list_comp(self, tmp_path):
        """Test detection of sorted() with list comprehension."""
        code = '''
result = sorted([x * 2 for x in range(10)])
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB102" for v in violations)

    def test_detect_unnecessary_list_sorted(self, tmp_path):
        """Test detection of unnecessary list() around sorted()."""
        code = '''
result = list(sorted(items))
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB104" for v in violations)

    def test_detect_print_sep_empty(self, tmp_path):
        """Test detection of print() with sep=''."""
        code = '''
print("hello", "world", sep="")
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB105" for v in violations)

    def test_detect_string_paths_with_open(self, tmp_path):
        """Test detection of string paths with open()."""
        code = '''
with open("/path/to/file.txt") as f:
    content = f.read()
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB106" for v in violations)

    def test_detect_os_path_usage(self, tmp_path):
        """Test detection of os.path usage."""
        code = '''
import os
path = os.path.join("dir", "file.txt")
exists = os.path.exists(path)
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "FURB108" for v in violations)

    def test_no_violations_for_clean_code(self, tmp_path):
        """Test that clean code produces no violations."""
        code = '''
from pathlib import Path

def process_file(path: Path):
    with path.open() as f:
        return f.read()

result = sorted(x * 2 for x in range(10))
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = RefurbPatternChecker()
        violations = checker.check_file(file_path)

        # Should have no FURB102 or FURB104 violations
        assert not any(v.rule_id in ("FURB102", "FURB104") for v in violations)


class TestAutoFix:
    """Test automatic fixes for refactoring opportunities."""

    def test_fix_unnecessary_list_sorted(self, tmp_path):
        """Test fixing unnecessary list() around sorted()."""
        code = '''
result = list(sorted(items))
another = list(sorted(data, key=lambda x: x.value))
'''
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
        assert len(REFURB_RULES) >= 7
        rule_ids = {rule.rule_id for rule in REFURB_RULES}
        expected_ids = {"FURB101", "FURB102", "FURB104", "FURB105", "FURB106", "FURB107", "FURB108"}
        assert expected_ids.issubset(rule_ids)

    def test_rule_metadata(self):
        """Test that rules have proper metadata."""
        for rule in REFURB_RULES:
            assert rule.rule_id.startswith("FURB")
            assert rule.name
            assert rule.description
            assert rule.message_template
