"""Tests for debugging pattern detection."""

import ast
from pathlib import Path
import tempfile
import pytest

from pyguard.lib.debugging_patterns import (
    DebuggingPatternChecker,
    DebuggingPatternVisitor,
    DEBUGGING_RULES,
)
from pyguard.lib.rule_engine import RuleCategory, RuleSeverity


class TestPrintStatementDetection:
    """Test T201: print() statement detection."""

    def test_detect_simple_print(self, tmp_path):
        """Test detection of simple print statement."""
        code = """
x = 10
print(x)
y = 20
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) == 1
        assert violations[0].rule_id == "T201"
        assert violations[0].severity == RuleSeverity.LOW
        assert "print()" in violations[0].message

    def test_detect_multiple_prints(self, tmp_path):
        """Test detection of multiple print statements."""
        code = """
print("Starting")
x = compute()
print(f"Result: {x}")
print("Done")
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) == 3
        assert all(v.rule_id == "T201" for v in violations)

    def test_no_false_positive_on_custom_print(self, tmp_path):
        """Test that custom print functions don't trigger false positives."""
        code = """
class Printer:
    def print(self, msg):
        self.messages.append(msg)

printer = Printer()
printer.print("test")  # This should not trigger
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        # Should not detect class method as builtin print
        assert len([v for v in violations if v.rule_id == "T201"]) == 0


class TestBreakpointDetection:
    """Test T100: breakpoint() call detection."""

    def test_detect_breakpoint(self, tmp_path):
        """Test detection of breakpoint() call."""
        code = """
def process(data):
    breakpoint()
    return data * 2
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) == 1
        assert violations[0].rule_id == "T100"
        assert violations[0].severity == RuleSeverity.MEDIUM
        assert "breakpoint()" in violations[0].message

    def test_breakpoint_with_condition(self, tmp_path):
        """Test detection of conditional breakpoint."""
        code = """
if debug_mode:
    breakpoint()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) == 1
        assert violations[0].rule_id == "T100"


class TestPdbDetection:
    """Test T101: pdb.set_trace() detection."""

    def test_detect_pdb_set_trace(self, tmp_path):
        """Test detection of pdb.set_trace()."""
        code = """
import pdb

def buggy_function():
    pdb.set_trace()
    result = complex_calculation()
    return result
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        # Should detect both the import and the set_trace call
        t101_violations = [v for v in violations if v.rule_id == "T101"]
        t102_violations = [v for v in violations if v.rule_id == "T102"]

        assert len(t101_violations) == 1
        assert "set_trace()" in t101_violations[0].message
        assert len(t102_violations) == 1

    def test_detect_ipdb_set_trace(self, tmp_path):
        """Test detection of ipdb.set_trace()."""
        code = """
import ipdb

ipdb.set_trace()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        t101_violations = [v for v in violations if v.rule_id == "T101"]
        assert len(t101_violations) == 1
        assert "ipdb" in t101_violations[0].message

    def test_detect_pudb_set_trace(self, tmp_path):
        """Test detection of pudb.set_trace()."""
        code = """
import pudb

def debug_here():
    pudb.set_trace()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        t101_violations = [v for v in violations if v.rule_id == "T101"]
        assert len(t101_violations) == 1
        assert "pudb" in t101_violations[0].message


class TestDebugImportDetection:
    """Test T102: Debug import detection."""

    def test_detect_pdb_import(self, tmp_path):
        """Test detection of pdb import."""
        code = """
import pdb
import sys
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        t102_violations = [v for v in violations if v.rule_id == "T102"]
        assert len(t102_violations) == 1
        assert "pdb" in t102_violations[0].message

    def test_detect_from_pdb_import(self, tmp_path):
        """Test detection of from pdb import."""
        code = """
from pdb import set_trace
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        t102_violations = [v for v in violations if v.rule_id == "T102"]
        assert len(t102_violations) == 1

    def test_detect_all_debug_imports(self, tmp_path):
        """Test detection of all debug library imports."""
        code = """
import pdb
import ipdb
import pudb
import pdbpp
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        t102_violations = [v for v in violations if v.rule_id == "T102"]
        assert len(t102_violations) == 4


class TestAutoFix:
    """Test auto-fix capabilities."""

    def test_fix_breakpoint(self, tmp_path):
        """Test fixing breakpoint() calls."""
        code = """
def process(data):
    breakpoint()
    return data * 2
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count == 1

        fixed_code = file_path.read_text()
        assert "# breakpoint()" in fixed_code
        assert "REMOVED by PyGuard" in fixed_code

    def test_fix_pdb_set_trace(self, tmp_path):
        """Test fixing pdb.set_trace() calls."""
        code = """
import pdb

def buggy():
    pdb.set_trace()
    return 42
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count == 2  # import + set_trace

        fixed_code = file_path.read_text()
        assert "# import pdb" in fixed_code
        assert "# pdb.set_trace()" in fixed_code

    def test_fix_print_adds_comment(self, tmp_path):
        """Test that fixing print() adds a TODO comment."""
        code = """
x = 10
print(x)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count == 1

        fixed_code = file_path.read_text()
        assert "print(x)  # TODO: Replace with logging" in fixed_code

    def test_fix_multiple_issues(self, tmp_path):
        """Test fixing multiple debugging patterns at once."""
        code = """
import pdb
import sys

def process(data):
    print("Processing")
    breakpoint()
    pdb.set_trace()
    return data
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        success, count = checker.fix_file(file_path)

        assert success
        assert count >= 4  # import, print, breakpoint, set_trace

        fixed_code = file_path.read_text()
        assert "# import pdb" in fixed_code
        assert "# TODO: Replace with logging" in fixed_code
        assert "# breakpoint()" in fixed_code
        assert "# pdb.set_trace()" in fixed_code


class TestRuleRegistration:
    """Test that debugging rules are properly registered."""

    def test_rules_defined(self):
        """Test that debugging rules are defined."""
        assert len(DEBUGGING_RULES) == 4

        rule_ids = [rule.rule_id for rule in DEBUGGING_RULES]
        assert "T201" in rule_ids  # print statement
        assert "T100" in rule_ids  # breakpoint
        assert "T101" in rule_ids  # pdb.set_trace
        assert "T102" in rule_ids  # debug imports

    def test_rule_properties(self):
        """Test rule properties are correct."""
        for rule in DEBUGGING_RULES:
            assert rule.category in [RuleCategory.STYLE, RuleCategory.ERROR]
            assert rule.severity in [RuleSeverity.LOW, RuleSeverity.MEDIUM]
            assert rule.description
            assert rule.message_template


class TestEdgeCases:
    """Test edge cases."""

    def test_syntax_error_handling(self, tmp_path):
        """Test graceful handling of syntax errors."""
        code = """
def broken(
    # Missing closing parenthesis
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        # Should return empty list, not crash
        assert violations == []

    def test_empty_file(self, tmp_path):
        """Test handling of empty file."""
        file_path = tmp_path / "test.py"
        file_path.write_text("")

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        assert violations == []

    def test_no_debugging_patterns(self, tmp_path):
        """Test file with no debugging patterns."""
        code = """
def calculate(x, y):
    return x + y

result = calculate(10, 20)
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()
        violations = checker.check_file(file_path)

        assert len(violations) == 0

    def test_fix_idempotency(self, tmp_path):
        """Test that fixing is idempotent."""
        code = """
breakpoint()
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DebuggingPatternChecker()

        # First fix
        success1, count1 = checker.fix_file(file_path)
        assert success1
        assert count1 == 1

        # Second fix should find nothing to fix
        success2, count2 = checker.fix_file(file_path)
        assert success2
        assert count2 == 0
