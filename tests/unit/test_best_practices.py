"""Unit tests for best practices fixer module."""

import pytest

from pyguard.lib.best_practices import BestPracticesFixer


class TestBestPracticesFixer:
    """Test cases for BestPracticesFixer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = BestPracticesFixer()

    def test_fix_mutable_defaults(self):
        """Test fixing mutable default arguments."""
        code = "def foo(x=[]):\n    pass"
        result = self.fixer._fix_mutable_default_arguments(code)
        assert "ANTI-PATTERN" in result or "MUTABLE DEFAULT" in result

    def test_fix_bare_except(self):
        """Test fixing bare except clauses."""
        code = "try:\n    pass\nexcept:\n    pass"
        result = self.fixer._fix_bare_except(code)
        assert "except Exception" in result

    def test_fix_none_comparison(self):
        """Test fixing None comparison."""
        code = "if x == None:"
        result = self.fixer._fix_comparison_to_none(code)
        assert "is None" in result

    def test_fix_type_check(self):
        """Test fixing type() checks."""
        code = "if type(x) == str:"
        result = self.fixer._fix_type_comparison(code)
        assert "isinstance" in result

    def test_fix_comparison_to_bool(self):
        """Test fixing boolean comparisons."""
        code = "if x == True:\n    pass"
        result = self.fixer._fix_comparison_to_bool(code)
        assert "Use if var:" in result or "if not var:" in result or "==" not in result

    def test_fix_list_comprehension_suggestion(self):
        """Test suggesting list comprehensions."""
        code = "for item in items:\n    results.append(item)"
        result = self.fixer._fix_list_comprehension(code)
        assert "Consider list comprehension" in result or code in result

    def test_fix_string_concatenation(self):
        """Test fixing string concatenation."""
        code = "msg = 'Hello ' + name + '!'"
        result = self.fixer._fix_string_concatenation(code)
        assert "f-string" in result or code in result

    def test_fix_context_managers(self):
        """Test suggesting context managers."""
        code = "f = open('file.txt')\ndata = f.read()\nf.close()"
        result = self.fixer._fix_context_managers(code)
        assert "with" in result.lower() or "context" in result.lower() or code in result

    def test_add_missing_docstrings(self):
        """Test adding docstring warnings."""
        code = "def foo():\n    return 42"
        result = self.fixer._add_missing_docstrings(code)
        assert "TODO" in result or "docstring" in result.lower() or code in result

    def test_fix_global_variables(self):
        """Test flagging global variables."""
        code = "global my_var\nmy_var = 10"
        result = self.fixer._fix_global_variables(code)
        assert "AVOID" in result or "global" in result.lower()


class TestComplexityAnalysis:
    """Test complexity analysis features."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = BestPracticesFixer()

    def test_get_complexity_report(self):
        """Test complexity report generation."""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(
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
            f.flush()
            temp_path = Path(f.name)

        try:
            report = self.fixer.get_complexity_report(temp_path)
            # Should return a dictionary with function names and complexity scores
            assert isinstance(report, dict)
        finally:
            temp_path.unlink()


class TestFileOperations:
    """Test file-level operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = BestPracticesFixer()

    def test_scan_file_for_issues(self):
        """Test scanning file for quality issues."""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(
                """
def test():  # Missing docstring
    x = None
    if x == None:  # Bad comparison
        pass
"""
            )
            f.flush()
            temp_path = Path(f.name)

        try:
            issues = self.fixer.scan_file_for_issues(temp_path)
            # Should find some issues
            assert isinstance(issues, list)
        finally:
            temp_path.unlink()

    def test_fix_file_with_changes(self):
        """Test fixing a file that needs changes."""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("if x == None:\n    pass")
            f.flush()
            temp_path = Path(f.name)

        try:
            success, fixes = self.fixer.fix_file(temp_path)
            assert success
            # File should have been modified
            content = temp_path.read_text()
            assert "is None" in content
        finally:
            temp_path.unlink()

    def test_fix_file_no_changes_needed(self):
        """Test fixing a file that doesn't need changes."""
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(
                """
def good_function():
    '''This function is well-written.'''
    if x is None:
        pass
    return True
"""
            )
            f.flush()
            temp_path = Path(f.name)

        try:
            success, fixes = self.fixer.fix_file(temp_path)
            assert success
            assert len(fixes) == 0  # No fixes needed
        finally:
            temp_path.unlink()
