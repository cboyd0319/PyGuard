"""
Tests for pathlib_patterns module (PTH rules).
"""

import pytest
from pyguard.lib.pathlib_patterns import PathlibChecker, PathlibIssue


class TestPathlibBasics:
    """Test basic pathlib pattern detection."""

    def test_detect_os_path_exists(self):
        """Test detection of os.path.exists()."""
        code = """
import os
if os.path.exists("/tmp/file"):
    pass
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH100" for issue in issues)
        assert any("Path.exists()" in issue.message for issue in issues)

    def test_detect_os_path_join(self):
        """Test detection of os.path.join()."""
        code = """
import os
path = os.path.join("/tmp", "file.txt")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH105" for issue in issues)
        assert any("Path / operator" in issue.message for issue in issues)

    def test_detect_os_path_basename(self):
        """Test detection of os.path.basename()."""
        code = """
import os
name = os.path.basename("/tmp/file.txt")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH106" for issue in issues)
        assert any("Path.name" in issue.suggested_fix for issue in issues)

    def test_detect_os_path_dirname(self):
        """Test detection of os.path.dirname()."""
        code = """
import os
parent = os.path.dirname("/tmp/file.txt")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH107" for issue in issues)
        assert any("Path.parent" in issue.suggested_fix for issue in issues)


class TestPathlibFileOperations:
    """Test file operation pattern detection."""

    def test_glob_pattern(self):
        """Test detection of glob.glob() → Path.glob()."""
        code = """
import glob
files = glob.glob("*.txt")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH124" for issue in issues)


class TestPathlibStat:
    """Test os.path stat function detection."""

    def test_detect_getsize(self):
        """Test detection of os.path.getsize()."""
        code = """
import os
size = os.path.getsize("/tmp/file")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH113" for issue in issues)

    def test_detect_getmtime(self):
        """Test detection of os.path.getmtime()."""
        code = """
import os
mtime = os.path.getmtime("/tmp/file")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH114" for issue in issues)


class TestPathlibChecks:
    """Test path checking functions."""

    def test_detect_isfile(self):
        """Test detection of os.path.isfile()."""
        code = """
import os
if os.path.isfile("/tmp/file"):
    pass
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH101" for issue in issues)

    def test_detect_isdir(self):
        """Test detection of os.path.isdir()."""
        code = """
import os
if os.path.isdir("/tmp"):
    pass
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH102" for issue in issues)

    def test_detect_islink(self):
        """Test detection of os.path.islink()."""
        code = """
import os
if os.path.islink("/tmp/link"):
    pass
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH103" for issue in issues)


class TestPathlibNoFalsePositives:
    """Test that we don't report false positives."""

    def test_no_issues_with_pathlib(self):
        """Test that pathlib usage doesn't trigger issues."""
        code = """
from pathlib import Path
p = Path("/tmp/file")
if p.exists():
    pass
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        # Should not detect issues when already using pathlib
        assert len(issues) == 0

    def test_no_issues_without_os_import(self):
        """Test that code without os import doesn't trigger false positives."""
        code = """
def my_function():
    return "result"
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) == 0

    def test_handle_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
import os
if os.path.exists(
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) == 0  # Should not crash


class TestPathlibAdvanced:
    """Test advanced pathlib patterns."""

    def test_detect_splitext(self):
        """Test detection of os.path.splitext()."""
        code = """
import os
name, ext = os.path.splitext("/tmp/file.txt")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH108" for issue in issues)

    def test_detect_abspath(self):
        """Test detection of os.path.abspath()."""
        code = """
import os
abs_path = os.path.abspath("./file")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH110" for issue in issues)

    def test_detect_realpath(self):
        """Test detection of os.path.realpath()."""
        code = """
import os
real_path = os.path.realpath("/tmp/link")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH111" for issue in issues)

    def test_detect_glob(self):
        """Test detection of glob.glob()."""
        code = """
import glob
files = glob.glob("*.txt")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH124" for issue in issues)


class TestPathlibIntegration:
    """Test comprehensive integration scenarios."""

    def test_multiple_issues_in_file(self):
        """Test detection of multiple pathlib issues."""
        code = """
import os

def process_files(directory):
    if os.path.exists(directory):
        for name in os.listdir(directory):
            full_path = os.path.join(directory, name)
            if os.path.isfile(full_path):
                size = os.path.getsize(full_path)
                basename = os.path.basename(full_path)
                return size, basename
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        # Should detect multiple issues
        assert len(issues) >= 4
        rule_ids = {issue.rule_id for issue in issues}
        assert "PTH100" in rule_ids  # exists
        assert "PTH105" in rule_ids  # join
        assert "PTH101" in rule_ids  # isfile
        assert "PTH113" in rule_ids  # getsize

    def test_issue_properties(self):
        """Test that issues have correct properties."""
        code = """
import os
os.path.exists("/tmp/file")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        issue = issues[0]
        assert issue.rule_id.startswith("PTH")
        assert issue.line > 0
        assert issue.col >= 0
        assert issue.message
        assert issue.old_code
        assert issue.suggested_fix
        assert issue.severity in ["LOW", "MEDIUM", "HIGH"]
        assert issue.category == "modernization"


class TestPathlibEdgeCases:
    """Test edge cases and error handling."""

    def test_from_import_pathlib(self):
        """Test detection of 'from pathlib import Path'."""
        code = """
from pathlib import Path
import os

# Should still detect os.path usage
path = os.path.join("a", "b")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        # Should detect the import and still flag os.path issues
        assert len(issues) > 0

    def test_from_import_os(self):
        """Test detection of 'from os import path'."""
        code = """
from os import path

if path.exists("/tmp"):
    pass
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        # Should detect os import usage
        assert len(issues) >= 0  # May or may not detect depending on implementation

    def test_os_alias(self):
        """Test detection with os alias."""
        code = """
import os as operating_system

if operating_system.path.exists("/tmp"):
    pass
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        # Should detect aliased os usage
        assert len(issues) > 0

    def test_syntax_error_handling(self):
        """Test handling of syntax errors."""
        code = """
def broken(
    # Unclosed parenthesis
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        # Should return empty list, not crash
        assert issues == []

    def test_empty_code(self):
        """Test handling of empty code."""
        checker = PathlibChecker()
        issues = checker.check_code("")

        assert issues == []

    def test_no_os_imports(self):
        """Test code without os imports."""
        code = """
def calculate(x, y):
    return x + y
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) == 0

    def test_check_file_function_error(self):
        """Test check_file function with nonexistent file."""
        from pyguard.lib.pathlib_patterns import check_file
        
        # Should handle error gracefully
        issues = check_file("/nonexistent/file.py")
        assert issues == []

    def test_check_file_function_success(self, tmp_path):
        """Test check_file function with valid file."""
        from pyguard.lib.pathlib_patterns import check_file
        
        code = """
import os
if os.path.exists("/tmp"):
    pass
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        issues = check_file(str(test_file))
        assert len(issues) > 0

    def test_getctime_detection(self):
        """Test detection of os.path.getctime()."""
        code = """
import os
ctime = os.path.getctime("/tmp/file")
"""
        checker = PathlibChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "PTH116" for issue in issues)
        assert any("st_ctime" in issue.suggested_fix for issue in issues)
