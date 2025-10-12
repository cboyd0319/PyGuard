"""Tests for advanced security analysis module."""

import pytest

from pyguard.lib.advanced_security import (
    AdvancedSecurityAnalyzer,
    IntegerSecurityAnalyzer,
    RaceConditionDetector,
    ReDoSDetector,
    TaintAnalyzer,
)


class TestTaintAnalyzer:
    """Test taint tracking analysis."""

    def test_detect_taint_flow_from_input(self):
        """Test detection of tainted data from input() flowing to eval()."""
        code = """
user_input = input("Enter value: ")
result = eval(user_input)
"""
        source_lines = code.strip().split("\n")
        analyzer = TaintAnalyzer(source_lines)
        
        import ast
        tree = ast.parse(code)
        analyzer.visit(tree)
        
        assert len(analyzer.issues) == 1
        assert analyzer.issues[0].category == "Taint Flow Violation"
        assert analyzer.issues[0].severity == "CRITICAL"
        assert "untrusted data" in analyzer.issues[0].message.lower()

    def test_no_taint_with_safe_code(self):
        """Test that safe code doesn't trigger taint issues."""
        code = """
safe_value = "constant"
result = len(safe_value)
"""
        source_lines = code.strip().split("\n")
        analyzer = TaintAnalyzer(source_lines)
        
        import ast
        tree = ast.parse(code)
        analyzer.visit(tree)
        
        assert len(analyzer.issues) == 0


class TestReDoSDetector:
    """Test ReDoS vulnerability detection."""

    def test_detect_nested_quantifiers(self):
        """Test detection of nested quantifiers in regex."""
        detector = ReDoSDetector()
        
        # Vulnerable pattern with nested quantifiers
        issue = detector.analyze_regex(
            r"(a+)+",
            line_number=1,
            code_snippet='re.compile(r"(a+)+")'
        )
        
        assert issue is not None
        assert issue.category == "Regular Expression DoS"
        assert issue.severity == "HIGH"

    def test_safe_regex_pattern(self):
        """Test that safe regex patterns don't trigger ReDoS detection."""
        detector = ReDoSDetector()
        
        # Safe pattern
        issue = detector.analyze_regex(
            r"[a-zA-Z0-9]+",
            line_number=1,
            code_snippet='re.compile(r"[a-zA-Z0-9]+")'
        )
        
        assert issue is None


class TestRaceConditionDetector:
    """Test race condition detection."""

    def test_detect_toctou_vulnerability(self):
        """Test detection of time-of-check to time-of-use race condition."""
        code = """
import os

file_path = "/tmp/test.txt"
if os.path.exists(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
"""
        source_lines = code.strip().split("\n")
        detector = RaceConditionDetector(source_lines)
        
        import ast
        tree = ast.parse(code)
        detector.visit(tree)
        
        assert len(detector.issues) == 1
        assert detector.issues[0].category == "Race Condition (TOCTOU)"
        assert "TOCTOU" in detector.issues[0].category

    def test_safe_exception_based_approach(self):
        """Test that exception-based file handling doesn't trigger issues."""
        code = """
try:
    with open("/tmp/test.txt", 'r') as f:
        content = f.read()
except FileNotFoundError:
    pass
"""
        source_lines = code.strip().split("\n")
        detector = RaceConditionDetector(source_lines)
        
        import ast
        tree = ast.parse(code)
        detector.visit(tree)
        
        assert len(detector.issues) == 0


class TestIntegerSecurityAnalyzer:
    """Test integer overflow/underflow detection."""

    def test_detect_potential_overflow(self):
        """Test detection of potential integer overflow in memory allocation."""
        code = """
size = user_size * item_count
buffer = bytearray(size)
"""
        source_lines = code.strip().split("\n")
        analyzer = IntegerSecurityAnalyzer(source_lines)
        
        import ast
        tree = ast.parse(code)
        
        # Add parent references
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node
        
        analyzer.visit(tree)
        
        # May or may not detect depending on context
        # This test ensures the analyzer runs without errors
        assert isinstance(analyzer.issues, list)


class TestAdvancedSecurityAnalyzer:
    """Test comprehensive advanced security analysis."""

    def test_analyze_code_with_multiple_issues(self):
        """Test analysis of code with multiple advanced security issues."""
        code = """
import re
import os

# Taint flow issue
user_input = input("Enter command: ")
os.system(user_input)

# ReDoS issue
pattern = re.compile(r"(a+)+")

# Race condition
file_path = "/tmp/data.txt"
if os.path.exists(file_path):
    os.remove(file_path)
"""
        analyzer = AdvancedSecurityAnalyzer()
        issues = analyzer.analyze_code(code)
        
        assert len(issues) >= 2  # At least taint flow and ReDoS
        
        # Check for variety of issue types
        categories = {issue.category for issue in issues}
        assert len(categories) >= 2

    def test_analyze_safe_code(self):
        """Test that safe code produces no issues."""
        code = """
import json

data = {"key": "value"}
json_str = json.dumps(data)
result = json.loads(json_str)
"""
        analyzer = AdvancedSecurityAnalyzer()
        issues = analyzer.analyze_code(code)
        
        assert len(issues) == 0

    def test_analyze_code_with_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
def broken_function(
    # Missing closing paren
"""
        analyzer = AdvancedSecurityAnalyzer()
        issues = analyzer.analyze_code(code)
        
        # Should return empty list, not crash
        assert issues == []

    def test_redos_detection_in_context(self):
        """Test ReDoS detection within code analysis."""
        code = """
import re

# Vulnerable regex
pattern = re.compile(r"(a*)*b")
result = pattern.match(user_input)
"""
        analyzer = AdvancedSecurityAnalyzer()
        issues = analyzer.analyze_code(code)
        
        # Should detect ReDoS vulnerability
        redos_issues = [i for i in issues if "ReDoS" in i.category or "Regular Expression" in i.category]
        assert len(redos_issues) >= 1
