"""Tests for modern Python modernization checks."""

import ast
from pathlib import Path
from tempfile import NamedTemporaryFile

from pyguard.lib.modern_python import ModernPythonFixer, ModernPythonVisitor


class TestModernPythonVisitor:
    """Test modern Python detection."""

    def test_detect_old_super(self):
        """Test detection of old-style super() calls."""
        code = """
class MyClass(BaseClass):
    def __init__(self):
        super(MyClass, self).__init__()
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("super()" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "UP001" for issue in visitor.issues)

    def test_detect_typing_list(self):
        """Test detection of typing.List instead of list."""
        code = """
from typing import List

def func() -> List[int]:
    return [1, 2, 3]
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("List" in issue.message and "PEP 585" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "UP006" for issue in visitor.issues)

    def test_detect_optional(self):
        """Test detection of Optional instead of X | None."""
        code = """
from typing import Optional

def func(x: Optional[str]) -> None:
    pass
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("Optional" in issue.message and "PEP 604" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "UP007" for issue in visitor.issues)

    def test_detect_union(self):
        """Test detection of Union instead of X | Y."""
        code = """
from typing import Union

def func(x: Union[str, int]) -> None:
    pass
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("Union" in issue.message and "PEP 604" in issue.message for issue in visitor.issues)

    def test_detect_six_usage(self):
        """Test detection of six library usage."""
        code = """
import six

if six.PY3:
    pass
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("six" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "UP004" for issue in visitor.issues)

    def test_detect_unnecessary_future(self):
        """Test detection of unnecessary __future__ imports."""
        code = """
from __future__ import print_function
from __future__ import division

print("hello")
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any("print_function" in issue.message for issue in visitor.issues)
        assert any("division" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "UP005" for issue in visitor.issues)

    def test_no_issues_with_modern_code(self):
        """Test that modern code has no issues."""
        code = """
class MyClass:
    def __init__(self):
        super().__init__()

def func(x: str | None) -> list[int]:
    return [1, 2, 3]
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        # Modern code may still have some issues, but should not have old-style patterns
        old_style_issues = [i for i in visitor.issues if i.rule_id in ["UP001", "UP006", "UP007"]]
        assert len(old_style_issues) == 0


class TestModernPythonFixer:
    """Test modern Python fixes."""

    def test_fix_old_super(self):
        """Test fixing old-style super() calls."""
        code = """
class MyClass(BaseClass):
    def __init__(self):
        super(MyClass, self).__init__()
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = ModernPythonFixer()
        success, fixes = fixer.fix_file(path)

        assert success
        assert len(fixes) > 0
        assert any("UP001" in fix for fix in fixes)

        # Clean up
        path.unlink()

    def test_fix_unnecessary_future_imports(self):
        """Test removing unnecessary __future__ imports."""
        code = """
from __future__ import print_function
from __future__ import division

print("hello")
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = ModernPythonFixer()
        success, fixes = fixer.fix_file(path)

        assert success
        assert len(fixes) > 0
        assert any("UP005" in fix for fix in fixes)

        # Clean up
        path.unlink()

    def test_scan_file_for_issues(self):
        """Test scanning file for modernization issues."""
        code = """
from typing import List, Optional
import six

def func() -> List[str]:
    return []
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = ModernPythonFixer()
        issues = fixer.scan_file_for_issues(path)

        assert len(issues) > 0
        assert any("List" in issue.message for issue in issues)
        assert any("six" in issue.message for issue in issues)

        # Clean up
        path.unlink()
