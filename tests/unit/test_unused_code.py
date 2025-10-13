"""Tests for unused code detection."""

import ast
from pathlib import Path
from tempfile import NamedTemporaryFile

from pyguard.lib.unused_code import UnusedCodeFixer, UnusedCodeVisitor


class TestUnusedCodeVisitor:
    """Test unused code detection."""

    def test_detect_unused_import(self):
        """Test detection of unused imports."""
        code = """
import os
import sys

print("hello")
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        assert len(visitor.issues) >= 2
        assert any("import" in issue.message.lower() and issue.name == "os" for issue in visitor.issues)
        assert any("import" in issue.message.lower() and issue.name == "sys" for issue in visitor.issues)
        assert any(issue.rule_id == "F401" for issue in visitor.issues)

    def test_detect_unused_from_import(self):
        """Test detection of unused from imports."""
        code = """
from os import path
from sys import argv

print("hello")
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        assert len(visitor.issues) >= 2
        assert any(issue.name == "path" for issue in visitor.issues)
        assert any(issue.name == "argv" for issue in visitor.issues)

    def test_detect_unused_argument(self):
        """Test detection of unused function arguments."""
        code = """
def process(data, config, verbose):
    return data
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        assert len(visitor.issues) >= 2
        assert any("argument" in issue.message.lower() and issue.name == "config" for issue in visitor.issues)
        assert any("argument" in issue.message.lower() and issue.name == "verbose" for issue in visitor.issues)
        assert any(issue.rule_id == "ARG001" for issue in visitor.issues)

    def test_ignore_self_cls(self):
        """Test that self and cls arguments are ignored."""
        code = """
class MyClass:
    def method(self, data):
        pass

    @classmethod
    def factory(cls, data):
        pass
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should not report self or cls as unused
        assert not any(issue.name == "self" for issue in visitor.issues)
        assert not any(issue.name == "cls" for issue in visitor.issues)

    def test_ignore_underscore_prefix(self):
        """Test that underscore-prefixed names are ignored."""
        code = """
def process(_unused, data):
    return data

_private = 42
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should not report underscore-prefixed names
        assert not any(issue.name == "_unused" for issue in visitor.issues)
        assert not any(issue.name == "_private" for issue in visitor.issues)

    def test_used_imports_not_reported(self):
        """Test that used imports are not reported."""
        code = """
import os
from sys import argv

path = os.path.join("a", "b")
print(argv)
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should not report used imports
        assert not any(issue.name == "os" for issue in visitor.issues)
        assert not any(issue.name == "argv" for issue in visitor.issues)

    def test_detect_unused_variable(self):
        """Test detection of unused variables."""
        code = """
unused_var = 42
CONSTANT = 100  # Constants are ignored

used_var = 10
print(used_var)
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should report unused_var but not CONSTANT or used_var
        assert any(issue.name == "unused_var" for issue in visitor.issues)
        assert not any(issue.name == "CONSTANT" for issue in visitor.issues)
        assert not any(issue.name == "used_var" for issue in visitor.issues)


class TestUnusedCodeFixer:
    """Test unused code fixes."""

    def test_scan_file_for_issues(self):
        """Test scanning file for unused code issues."""
        code = """
import os
import sys
from pathlib import Path

def process(data, unused_arg):
    return data
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = UnusedCodeFixer()
        issues = fixer.scan_file_for_issues(path)

        assert len(issues) > 0
        assert any("import" in issue.message.lower() for issue in issues)
        assert any("argument" in issue.message.lower() for issue in issues)

        # Clean up
        path.unlink()

    def test_fix_unused_imports(self):
        """Test fixing unused imports."""
        code = """
import os
import sys

print("hello")
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = UnusedCodeFixer()
        success, fixes = fixer.fix_file(path)

        assert success
        assert len(fixes) > 0
        assert any("F401" in fix for fix in fixes)

        # Verify imports were removed
        content = path.read_text()
        assert "import os" not in content
        assert "import sys" not in content

        # Clean up
        path.unlink()

    def test_keep_used_imports(self):
        """Test that used imports are kept."""
        code = """
import os
from sys import argv

path = os.path.join("a", "b")
print(argv)
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = UnusedCodeFixer()
        success, fixes = fixer.fix_file(path)

        assert success

        # Verify used imports were kept
        content = path.read_text()
        assert "import os" in content
        assert "from sys import argv" in content

        # Clean up
        path.unlink()
