"""Tests for naming convention checks."""

import ast
from pathlib import Path
from tempfile import NamedTemporaryFile

from pyguard.lib.naming_conventions import NamingConventionFixer, NamingConventionVisitor


class TestNamingConventionVisitor:
    """Test naming convention detection."""

    def test_detect_class_name_violation(self):
        """Test detection of class name violations."""
        code = """
class my_class:
    pass

class snake_case_class:
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any("CamelCase" in issue.message and issue.name == "my_class" for issue in visitor.issues)
        assert any(issue.rule_id == "N801" for issue in visitor.issues)

    def test_detect_function_name_violation(self):
        """Test detection of function name violations."""
        code = """
def MyFunction():
    pass

def camelCaseFunction():
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any("snake_case" in issue.message and issue.name == "MyFunction" for issue in visitor.issues)
        assert any(issue.rule_id == "N802" for issue in visitor.issues)

    def test_detect_argument_name_violation(self):
        """Test detection of argument name violations."""
        code = """
def process(camelCaseArg, AnotherArg):
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any("snake_case" in issue.message and issue.name == "camelCaseArg" for issue in visitor.issues)
        assert any(issue.rule_id == "N803" for issue in visitor.issues)

    def test_detect_variable_name_violation(self):
        """Test detection of variable name violations."""
        code = """
MyVariable = 42
camelCaseVar = 100
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any("snake_case" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "N806" for issue in visitor.issues)

    def test_detect_ambiguous_names(self):
        """Test detection of ambiguous single-letter names."""
        code = """
class l:
    pass

def O():
    pass

I = 1
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 3
        assert any("ambiguous" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "E741" for issue in visitor.issues)

    def test_allow_magic_methods(self):
        """Test that magic methods are allowed."""
        code = """
class MyClass:
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __custom_method__(self):
        pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Should not report __init__ or __str__ but should report __custom_method__
        assert not any("__init__" in issue.name for issue in visitor.issues)
        assert not any("__str__" in issue.name for issue in visitor.issues)
        assert any("__custom_method__" in issue.name for issue in visitor.issues)

    def test_allow_constants(self):
        """Test that UPPER_CASE constants are allowed."""
        code = """
MAX_SIZE = 100
API_KEY = "secret"
_PRIVATE_CONSTANT = 42
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Should not report constants
        assert not any(issue.name == "MAX_SIZE" for issue in visitor.issues)
        assert not any(issue.name == "API_KEY" for issue in visitor.issues)

    def test_allow_private_names(self):
        """Test that _private names are allowed."""
        code = """
_private_var = 42
__double_underscore = 100

def _private_function():
    pass

class _PrivateClass:
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Private names should not be reported for naming violations
        # (though they might have other issues)
        assert not any(issue.name == "_private_var" for issue in visitor.issues)

    def test_allow_test_methods(self):
        """Test that test methods are allowed."""
        code = """
def test_feature():
    pass

def setUp():
    pass

def tearDown():
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Test methods should not be reported
        assert not any("test_feature" in issue.name for issue in visitor.issues)
        assert not any("setUp" in issue.name for issue in visitor.issues)
        assert not any("tearDown" in issue.name for issue in visitor.issues)

    def test_correct_naming(self):
        """Test that correctly named elements have no issues."""
        code = """
class MyClass:
    def __init__(self):
        self.my_attribute = 42

    def my_method(self, argument_name):
        local_var = argument_name
        return local_var

MAX_SIZE = 100
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Should have no or minimal issues
        naming_issues = [i for i in visitor.issues if i.rule_id in ["N801", "N802", "N803", "N806"]]
        assert len(naming_issues) == 0


class TestNamingConventionFixer:
    """Test naming convention fixes."""

    def test_scan_file_for_issues(self):
        """Test scanning file for naming issues."""
        code = """
class my_class:
    def MyMethod(self, CamelArg):
        MyVar = 42
        return MyVar
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = NamingConventionFixer()
        issues = fixer.scan_file_for_issues(path)

        assert len(issues) > 0
        assert any("CamelCase" in issue.message or "snake_case" in issue.message for issue in issues)

        # Clean up
        path.unlink()

    def test_fix_file_detection(self):
        """Test that fix_file detects issues."""
        code = """
def MyFunction(CamelArg):
    pass
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = NamingConventionFixer()
        success, fixes = fixer.fix_file(path)

        assert success
        # Note: naming fixes are detection-only, not auto-applied

        # Clean up
        path.unlink()
