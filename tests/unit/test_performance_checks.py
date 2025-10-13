"""Tests for performance checks."""

import ast
from pathlib import Path
from tempfile import NamedTemporaryFile

from pyguard.lib.performance_checks import PerformanceFixer, PerformanceVisitor


class TestPerformanceVisitor:
    """Test performance issue detection."""

    def test_detect_try_in_loop(self):
        """Test detection of try-except inside loop."""
        code = """
for item in items:
    try:
        process(item)
    except Exception:
        pass
"""
        tree = ast.parse(code)
        visitor = PerformanceVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("try-except" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "PERF101" for issue in visitor.issues)

    def test_detect_list_concat_in_loop(self):
        """Test detection of list concatenation in loop."""
        code = """
result = []
for item in items:
    result += [item]
"""
        tree = ast.parse(code)
        visitor = PerformanceVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("concatenation" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "PERF102" for issue in visitor.issues)

    def test_detect_dict_keys_in_membership(self):
        """Test detection of .keys() in membership test."""
        code = """
if key in my_dict.keys():
    pass
"""
        tree = ast.parse(code)
        visitor = PerformanceVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("keys()" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "PERF404" for issue in visitor.issues)

    def test_detect_unnecessary_list_wrapper(self):
        """Test detection of unnecessary list() wrapper."""
        code = """
result = list([x for x in range(10)])
"""
        tree = ast.parse(code)
        visitor = PerformanceVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("unnecessary" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "PERF402" for issue in visitor.issues)

    def test_detect_list_copy_slice(self):
        """Test detection of list[:] for copying."""
        code = """
copy = my_list[:]
"""
        tree = ast.parse(code)
        visitor = PerformanceVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("copy()" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "PERF405" for issue in visitor.issues)

    def test_no_issues_with_efficient_code(self):
        """Test that efficient code has no issues."""
        code = """
result = []
for item in items:
    result.append(item)

if key in my_dict:
    pass

copy = my_list.copy()
"""
        tree = ast.parse(code)
        visitor = PerformanceVisitor(code.splitlines())
        visitor.visit(tree)

        # Should have no or minimal issues
        assert len(visitor.issues) == 0


class TestPerformanceFixer:
    """Test performance fixes."""

    def test_scan_file_for_issues(self):
        """Test scanning file for performance issues."""
        code = """
for item in items:
    try:
        process(item)
    except:
        pass

if key in dict.keys():
    pass
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = PerformanceFixer()
        issues = fixer.scan_file_for_issues(path)

        assert len(issues) > 0

        # Clean up
        path.unlink()

    def test_fix_dict_keys(self):
        """Test fixing .keys() in membership test."""
        code = """
if key in my_dict.keys():
    pass
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = PerformanceFixer()
        success, fixes = fixer.fix_file(path)

        assert success
        assert len(fixes) > 0
        assert any("PERF404" in fix for fix in fixes)

        # Clean up
        path.unlink()
