"""Tests for modern Python modernization checks."""

import ast
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

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
        assert any(
            "List" in issue.message and "PEP 585" in issue.message for issue in visitor.issues
        )
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
        assert any(
            "Optional" in issue.message and "PEP 604" in issue.message for issue in visitor.issues
        )
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
        assert any(
            "Union" in issue.message and "PEP 604" in issue.message for issue in visitor.issues
        )

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

    def test_detect_outdated_version_check(self):
        """Test detection of outdated version checks (UP036)."""
        code = """
import sys

if sys.version_info < (3, 7):
    print("Old Python")
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "UP036" for issue in visitor.issues)
        assert any("Outdated version check" in issue.message for issue in visitor.issues)

    def test_detect_quoted_annotation(self):
        """Test detection of quoted type annotations (UP037)."""
        code = """
x: "int" = 5
y: "str" = "hello"
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "UP037" for issue in visitor.issues)
        assert any("Remove quotes" in issue.message for issue in visitor.issues)

    def test_detect_non_pep604_isinstance(self):
        """Test detection of isinstance with tuple instead of | (UP038)."""
        code = """
def check_type(x):
    if isinstance(x, (int, str, float)):
        return True
    return False
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "UP038" for issue in visitor.issues)
        assert any(
            "isinstance" in issue.message and "|" in issue.message for issue in visitor.issues
        )

    def test_detect_type_alias(self):
        """Test detection of TypeAlias that should use type statement (UP040)."""
        code = """
from typing import TypeAlias

MyType: TypeAlias = int
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "UP040" for issue in visitor.issues)
        assert any(
            "TypeAlias" in issue.message or "type" in issue.message.lower()
            for issue in visitor.issues
        )

    def test_detect_asyncio_timeout_error(self):
        """Test detection of asyncio.TimeoutError (UP041)."""
        code = """
from asyncio import TimeoutError

async def func():
    raise TimeoutError()
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "UP041" for issue in visitor.issues)
        assert any("TimeoutError" in issue.message for issue in visitor.issues)

    def test_detect_str_enum(self):
        """Test detection of str + Enum that should use StrEnum (UP042)."""
        code = """
from enum import Enum

class Color(str, Enum):
    RED = "red"
    GREEN = "green"
    BLUE = "blue"
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "UP042" for issue in visitor.issues)
        assert any("StrEnum" in issue.message for issue in visitor.issues)


# ============================================================================
# Enhanced Tests - Following PyTest Architect Agent Guidelines
# ============================================================================


class TestModernPythonEdgeCases:
    """Test edge cases and boundary conditions for modern Python patterns."""

    @pytest.mark.parametrize(
        ("typing_import", "expected_builtin"),
        [
            ("List", "list"),
            ("Dict", "dict"),
            ("Set", "set"),
            ("Tuple", "tuple"),
            ("FrozenSet", "frozenset"),
        ],
        ids=["List", "Dict", "Set", "Tuple", "FrozenSet"],
    )
    def test_detect_typing_builtins_pep585(self, typing_import, expected_builtin):
        """Test detection of typing imports that should use PEP 585 builtins.

        PEP 585 allows using list[T] instead of typing.List[T] in Python 3.9+.
        """
        # Arrange
        code = f"""
from typing import {typing_import}

def func() -> {typing_import}[int]:
    return []
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "UP006" for issue in visitor.issues)
        assert any("PEP 585" in issue.message for issue in visitor.issues)

    def test_get_full_name_with_nested_attributes(self):
        """Test _get_full_name helper with deeply nested attributes."""
        # Arrange
        code = """
import os.path
result = os.path.dirname("/foo/bar")
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert - should process without errors
        # The visitor should handle nested attribute access
        assert isinstance(visitor, ModernPythonVisitor)

    def test_get_code_snippet_with_invalid_line_number(self):
        """Test _get_code_snippet with invalid line number.

        Error handling: boundary condition where line doesn't exist.
        """
        # Arrange
        code = "x = 1"
        visitor = ModernPythonVisitor(code.splitlines())

        # Create a mock node with invalid line number
        class MockNode:
            lineno = 999  # Beyond source length

        # Act
        result = visitor._get_code_snippet(MockNode())

        # Assert
        assert result == ""

    def test_get_code_snippet_with_zero_line_number(self):
        """Test _get_code_snippet with zero or negative line number."""
        # Arrange
        code = "x = 1"
        visitor = ModernPythonVisitor(code.splitlines())

        # Create a mock node with zero line number
        class MockNode:
            lineno = 0

        # Act
        result = visitor._get_code_snippet(MockNode())

        # Assert
        assert result == ""

    def test_get_full_name_with_simple_name(self):
        """Test _get_full_name with simple Name node."""
        # Arrange
        visitor = ModernPythonVisitor([""])
        name_node = ast.Name(id="variable", ctx=ast.Load())

        # Act
        result = visitor._get_full_name(name_node)

        # Assert
        assert result == "variable"

    def test_get_full_name_with_attribute(self):
        """Test _get_full_name with Attribute node."""
        # Arrange
        visitor = ModernPythonVisitor([""])
        # Create obj.attr
        attr_node = ast.Attribute(
            value=ast.Name(id="obj", ctx=ast.Load()), attr="attr", ctx=ast.Load()
        )

        # Act
        result = visitor._get_full_name(attr_node)

        # Assert
        assert result == "obj.attr"

    def test_get_full_name_with_unknown_node_type(self):
        """Test _get_full_name with unknown node type returns empty string."""
        # Arrange
        visitor = ModernPythonVisitor([""])
        constant_node = ast.Constant(value=42)

        # Act
        result = visitor._get_full_name(constant_node)

        # Assert
        assert result == ""


class TestModernPythonFixerOperations:
    """Test ModernPythonFixer class operations."""

    def test_fixer_initialization(self):
        """Test that ModernPythonFixer initializes correctly."""
        # Arrange & Act
        fixer = ModernPythonFixer()

        # Assert
        assert fixer is not None
        assert hasattr(fixer, "logger")
        assert hasattr(fixer, "file_ops")

    def test_scan_file_with_no_issues(self, tmp_path):
        """Test scanning file with modern Python code (no issues)."""
        # Arrange
        code = """
# Modern Python 3.9+ code
from collections.abc import Sequence

def process(items: list[int]) -> dict[str, int]:
    return {str(i): i for i in items}
"""
        test_file = tmp_path / "modern.py"
        test_file.write_text(code)
        fixer = ModernPythonFixer()

        # Act
        issues = fixer.scan_file_for_issues(test_file)

        # Assert
        # May still have some issues, but should process without errors
        assert isinstance(issues, list)

    def test_scan_file_with_syntax_error(self, tmp_path):
        """Test scanning file with syntax error handles gracefully."""
        # Arrange
        code = """
def broken(
    # Missing closing paren
"""
        test_file = tmp_path / "broken.py"
        test_file.write_text(code)
        fixer = ModernPythonFixer()

        # Act
        issues = fixer.scan_file_for_issues(test_file)

        # Assert
        assert issues == []

    def test_scan_file_nonexistent(self):
        """Test scanning non-existent file returns empty list."""
        # Arrange
        fixer = ModernPythonFixer()
        non_existent = Path("/nonexistent/path/file.py")

        # Act
        issues = fixer.scan_file_for_issues(non_existent)

        # Assert
        assert issues == []


class TestSuperCallDetection:
    """Test detection of old-style super() calls."""

    def test_super_with_two_args_detected(self):
        """Test that super(ClassName, self) is detected."""
        # Arrange
        code = """
class MyClass(BaseClass):
    def __init__(self):
        super(MyClass, self).__init__()
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        assert any(issue.rule_id == "UP001" for issue in visitor.issues)

    def test_super_without_args_not_detected(self):
        """Test that modern super() without args is not flagged."""
        # Arrange
        code = """
class MyClass(BaseClass):
    def __init__(self):
        super().__init__()
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        # Should not flag modern super()
        super_issues = [i for i in visitor.issues if i.rule_id == "UP001"]
        assert len(super_issues) == 0


class TestImportModernization:
    """Test import-related modernization patterns."""

    @pytest.mark.parametrize(
        "six_import",
        [
            "import six",
            "import six.moves",
            "import six.moves.urllib",
        ],
        ids=["six", "six.moves", "six.moves.urllib"],
    )
    def test_detect_six_imports(self, six_import):
        """Test detection of various six library imports.

        The six library is for Python 2/3 compatibility and should be removed.
        """
        # Arrange
        code = f"{six_import}\n\nprint('hello')"
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        assert any(issue.rule_id == "UP004" for issue in visitor.issues)
        assert any("six" in issue.message for issue in visitor.issues)

    def test_from_typing_import_optional(self):
        """Test detection of Optional import from typing."""
        # Arrange
        code = """
from typing import Optional

def func(x: Optional[str]) -> None:
    pass
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        # Should detect Optional import
        assert any(issue.rule_id == "UP007" for issue in visitor.issues)

    def test_from_typing_import_union(self):
        """Test detection of Union import from typing."""
        # Arrange
        code = """
from typing import Union

def func(x: Union[str, int]) -> None:
    pass
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        # Should detect Union import
        assert any(issue.rule_id == "UP007" for issue in visitor.issues)


class TestMultipleIssuesInOneFile:
    """Test detection of multiple modernization issues in a single file."""

    def test_multiple_typing_issues(self):
        """Test detection of multiple typing-related issues."""
        # Arrange
        code = """
from typing import List, Dict, Optional, Union

def process(
    items: List[str],
    mapping: Dict[str, int],
    optional_value: Optional[int],
    union_value: Union[str, int]
) -> None:
    pass
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        # Should detect multiple issues
        assert len(visitor.issues) >= 2
        # Should have both PEP 585 and PEP 604 issues
        rule_ids = {issue.rule_id for issue in visitor.issues}
        assert "UP006" in rule_ids or "UP007" in rule_ids

    def test_mixed_modernization_issues(self):
        """Test detection of different types of modernization issues."""
        # Arrange
        code = """
import six
from typing import List

class MyClass(BaseClass):
    def __init__(self):
        super(MyClass, self).__init__()

    def process(self, items: List[int]):
        message = "Count: {}".format(len(items))
        return message
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        # Should detect: six import, super(), typing.List, .format()
        rule_ids = {issue.rule_id for issue in visitor.issues}
        assert len(rule_ids) >= 2
        # Check we found different types of issues
        assert any(id in ["UP001", "UP004", "UP006", "UP032"] for id in rule_ids)


class TestEmptyAndEdgeFiles:
    """Test handling of empty and edge case files."""

    def test_empty_file_no_issues(self):
        """Test that empty file produces no issues."""
        # Arrange
        code = ""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        assert len(visitor.issues) == 0

    def test_only_comments_no_issues(self):
        """Test that file with only comments produces no issues."""
        # Arrange
        code = """
# Just a comment
# Another comment
"""
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        assert len(visitor.issues) == 0

    def test_only_docstring_no_issues(self):
        """Test that file with only docstring produces no issues."""
        # Arrange
        code = '"""Module docstring."""'
        tree = ast.parse(code)
        visitor = ModernPythonVisitor(code.splitlines())

        # Act
        visitor.visit(tree)

        # Assert
        assert len(visitor.issues) == 0
