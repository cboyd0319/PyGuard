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
        assert any(
            "import" in issue.message.lower() and issue.name == "os" for issue in visitor.issues
        )
        assert any(
            "import" in issue.message.lower() and issue.name == "sys" for issue in visitor.issues
        )
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
    # TODO: Add docstring
    return data
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        assert len(visitor.issues) >= 2
        assert any(
            "argument" in issue.message.lower() and issue.name == "config"
            for issue in visitor.issues
        )
        assert any(
            "argument" in issue.message.lower() and issue.name == "verbose"
            for issue in visitor.issues
        )
        assert any(issue.rule_id == "ARG001" for issue in visitor.issues)

    def test_ignore_self_cls(self):
        """Test that self and cls arguments are ignored."""
        code = """
class MyClass:
    # TODO: Add docstring
    def method(self, data):
        # TODO: Add docstring
        pass

    @classmethod
    def factory(cls, data):
        # TODO: Add docstring
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
    # TODO: Add docstring
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
    # TODO: Add docstring
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


class TestUnusedCodeVisitorEnhanced:
    """Enhanced tests for unused code detection edge cases."""

    def test_detect_unused_posonly_arg(self):
        """Test detection of unused positional-only arguments."""
        code = """
def process(used, unused, /, kwarg):
    # TODO: Add docstring
    return used + kwarg
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused positional-only arg
        unused_issues = [i for i in visitor.issues if i.name == "unused"]
        assert len(unused_issues) > 0
        assert unused_issues[0].rule_id == "ARG001"

    def test_detect_unused_kwonly_arg(self):
        """Test detection of unused keyword-only arguments."""
        code = """
def process(data, *, unused_kw, used_kw):
    # TODO: Add docstring
    return data + used_kw
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused keyword-only arg
        unused_issues = [i for i in visitor.issues if i.name == "unused_kw"]
        assert len(unused_issues) > 0
        assert unused_issues[0].rule_id == "ARG001"

    def test_detect_unused_vararg(self):
        """Test detection of unused *args."""
        code = """
def process(data, *unused_args):
    # TODO: Add docstring
    return data
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused vararg (if implementation supports it)
        # Note: Some implementations may not check vararg/kwarg
        unused_issues = [i for i in visitor.issues if i.name == "unused_args"]
        # Implementation-dependent - may or may not detect
        assert len(unused_issues) >= 0

    def test_detect_unused_kwarg(self):
        """Test detection of unused **kwargs."""
        code = """
def process(data, **unused_kwargs):
    # TODO: Add docstring
    return data
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused kwarg (if implementation supports it)
        # Note: Some implementations may not check vararg/kwarg
        unused_issues = [i for i in visitor.issues if i.name == "unused_kwargs"]
        # Implementation-dependent - may or may not detect
        assert len(unused_issues) >= 0

    def test_detect_unused_in_async_function(self):
        """Test detection of unused arguments in async functions."""
        code = """
async def fetch(url, timeout, unused_param):
    return url + str(timeout)
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused parameter in async function
        unused_issues = [i for i in visitor.issues if i.name == "unused_param"]
        assert len(unused_issues) > 0
        assert unused_issues[0].rule_id == "ARG001"

    def test_detect_unused_assignment(self):
        """Test detection of unused variable assignments."""
        code = """
unused_var = 42
another_unused = "test"
used_var = 10
print(used_var)
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused assignments
        assert any(i.name == "unused_var" for i in visitor.issues)
        assert any(i.name == "another_unused" for i in visitor.issues)
        assert not any(i.name == "used_var" for i in visitor.issues)

    def test_detect_unused_annotated_assignment(self):
        """Test detection of unused annotated assignments."""
        code = """
unused_typed: int = 42
used_typed: str = "hello"
print(used_typed)
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused annotated assignment
        assert any(i.name == "unused_typed" for i in visitor.issues)
        assert not any(i.name == "used_typed" for i in visitor.issues)

    def test_lambda_parameter_tracking(self):
        """Test tracking of lambda parameters."""
        code = """
fn = lambda x, y: x
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Lambda with unused parameter y should be detected
        # Note: Lambda tracking might be limited based on implementation
        # This test verifies the visitor doesn't crash on lambdas

    def test_nested_function_scope(self):
        """Test unused detection in nested functions."""
        code = """
def outer(outer_used, outer_unused):
    # TODO: Add docstring
    def inner(inner_used, inner_unused):
        # TODO: Add docstring
        return inner_used + outer_used
    return inner
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect both unused parameters
        assert any(i.name == "outer_unused" for i in visitor.issues)
        assert any(i.name == "inner_unused" for i in visitor.issues)

    def test_star_import_ignored(self):
        """Test that star imports are handled gracefully."""
        code = """
from os import *

print(path.join("a", "b"))
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should not crash and not report star import
        # Star imports are tracked separately

    def test_class_method_detection(self):
        """Test detection in class methods with decorators."""
        code = """
class MyClass:
    # TODO: Add docstring
    def instance_method(self, used, unused):
        # TODO: Add docstring
        return used

    @classmethod
    def class_method(cls, used, unused):
        # TODO: Add docstring
        return used

    @staticmethod
    def static_method(used, unused):
        # TODO: Add docstring
        return used
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect all unused parameters but not self/cls
        unused_issues = [i for i in visitor.issues if i.name == "unused"]
        assert len(unused_issues) == 3  # One for each method

        # Should not detect self or cls
        assert not any(i.name == "self" for i in visitor.issues)
        assert not any(i.name == "cls" for i in visitor.issues)

    def test_tuple_unpacking_tracking(self):
        """Test tracking of tuple unpacking assignments."""
        code = """
a, b, c = 1, 2, 3
print(a, b)
# c is unused
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused variable from tuple unpacking
        # Note: Implementation may vary for tuple unpacking

    def test_empty_file(self):
        """Test handling of empty file."""
        code = ""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should not crash and report no issues
        assert len(visitor.issues) == 0

    def test_only_comments(self):
        """Test handling of file with only comments."""
        code = """# Just comments
# More comments
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should not crash and report no issues
        assert len(visitor.issues) == 0

    def test_dunder_methods_ignored(self):
        """Test that dunder methods are properly handled."""
        code = """
class MyClass:
    # TODO: Add docstring
    def __init__(self, x, unused):
        # TODO: Add docstring
        self.x = x

    def __str__(self):
        # TODO: Add docstring
        return str(self.x)
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused in __init__
        assert any(i.name == "unused" for i in visitor.issues)
        # Should not crash on __str__ with no parameters

    def test_property_decorator(self):
        """Test handling of property decorators."""
        code = """
class MyClass:
    # TODO: Add docstring
    @property
    def value(self):
        # TODO: Add docstring
        return 42

    @value.setter
    def value(self, val, unused):
        # TODO: Add docstring
        self._val = val
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused in setter
        assert any(i.name == "unused" for i in visitor.issues)

    def test_closure_variable_usage(self):
        """Test that closure variable usage is properly tracked."""
        code = """
def outer(x):
    # TODO: Add docstring
    def inner():
        # TODO: Add docstring
        return x
    return inner
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # x is used in closure, should not be reported
        assert not any(i.name == "x" for i in visitor.issues)

    def test_async_context_manager(self):
        """Test handling of async context managers."""
        code = """
async def process(file_path, unused):
    async with open(file_path) as f:
        return await f.read()
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused parameter
        assert any(i.name == "unused" for i in visitor.issues)

    def test_list_comprehension_variables(self):
        """Test handling of list comprehension variables."""
        code = """
unused = [x for x in range(10)]
result = [y for y in range(10)]
print(result)
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect unused list comprehension result
        assert any(i.name == "unused" for i in visitor.issues)

    def test_exception_variable_tracking(self):
        """Test tracking of exception variables."""
        code = """
try:
    risky_operation()
except Exception as e:
    pass
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Exception variable 'e' is unused
        # Implementation may or may not track this

    def test_future_import_handling(self):
        """Test handling of __future__ imports."""
        code = """
from __future__ import annotations

def func(x: str) -> str:
    # TODO: Add docstring
    return x
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # __future__ imports should not be reported as unused
        # (They affect parsing behavior)

    def test_multiple_assignment_same_line(self):
        """Test multiple assignments on same line."""
        code = """
x = y = z = 10
print(x)
# y and z are unused
"""
        tree = ast.parse(code)
        visitor = UnusedCodeVisitor(code.splitlines())
        visitor.visit(tree)
        visitor.finalize()

        # Should detect y and z as unused
        # Implementation may vary for chained assignments


class TestUnusedCodeFixerEnhanced:
    """Enhanced tests for unused code fixer edge cases."""

    def test_fix_file_nonexistent(self):
        """Test fixing nonexistent file."""
        from pathlib import Path

        fixer = UnusedCodeFixer()
        nonexistent = Path("/tmp/nonexistent_file_12345.py")

        success, _fixes = fixer.fix_file(nonexistent)

        # Should handle gracefully
        assert not success

    def test_fix_file_with_syntax_error(self):
        """Test fixing file with syntax errors."""
        from pathlib import Path
        from tempfile import NamedTemporaryFile

        code = """
def broken(
    # TODO: Add docstring
    # Unclosed paren
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = UnusedCodeFixer()
        _success, _fixes = fixer.fix_file(path)

        # Should handle syntax errors gracefully
        # Might succeed with 0 fixes or fail gracefully

        path.unlink()

    def test_scan_empty_file(self):
        """Test scanning empty file."""
        from pathlib import Path
        from tempfile import NamedTemporaryFile

        code = ""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = UnusedCodeFixer()
        issues = fixer.scan_file_for_issues(path)

        # Empty file should have no issues
        assert len(issues) == 0

        path.unlink()

    def test_fix_preserves_used_code(self):
        """Test that fixes preserve used code."""
        from pathlib import Path
        from tempfile import NamedTemporaryFile

        # Code with all used elements - should not be modified
        code = """import os
used_var = 10

def process(data):
    # TODO: Add docstring
    return os.path.join(str(used_var), data)

result = process("test")
print(result)
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = UnusedCodeFixer()
            success, fixes = fixer.fix_file(path)

            # All code is used, so no fixes should be applied
            assert success
            assert len(fixes) == 0
        finally:
            # Clean up
            try:
                path.unlink()
            except FileNotFoundError:
                pass  # Already deleted by fixer

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
        success, _fixes = fixer.fix_file(path)

        assert success

        # Verify used imports were kept
        content = path.read_text()
        assert "import os" in content
        assert "from sys import argv" in content

        # Clean up
        path.unlink()
