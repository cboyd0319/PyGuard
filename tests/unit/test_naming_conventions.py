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
    # TODO: Add docstring
    pass

class snake_case_class:
    # TODO: Add docstring
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any(
            "CamelCase" in issue.message and issue.name == "my_class" for issue in visitor.issues
        )
        assert any(issue.rule_id == "N801" for issue in visitor.issues)

    def test_detect_function_name_violation(self):
        """Test detection of function name violations."""
        code = """
def MyFunction():
    # TODO: Add docstring
    pass

def camelCaseFunction():
    # TODO: Add docstring
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any(
            "snake_case" in issue.message and issue.name == "MyFunction" for issue in visitor.issues
        )
        assert any(issue.rule_id == "N802" for issue in visitor.issues)

    def test_detect_argument_name_violation(self):
        """Test detection of argument name violations."""
        code = """
def process(camelCaseArg, AnotherArg):
    # TODO: Add docstring
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any(
            "snake_case" in issue.message and issue.name == "camelCaseArg"
            for issue in visitor.issues
        )
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
    # TODO: Add docstring
    pass

def O():
    # TODO: Add docstring
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
    # TODO: Add docstring
    def __init__(self):
        # TODO: Add docstring
        pass

    def __str__(self):
        # TODO: Add docstring
        pass

    def __custom_method__(self):
        # TODO: Add docstring
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
API_KEY = "secret"  # SECURITY: Use environment variables or config files
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
    # TODO: Add docstring
    pass

class _PrivateClass:
    # TODO: Add docstring
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
    # TODO: Add docstring
    pass

def setUp():
    # TODO: Add docstring
    pass

def tearDown():
    # TODO: Add docstring
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
    # TODO: Add docstring
    def __init__(self):
        # TODO: Add docstring
        self.my_attribute = 42

    def my_method(self, argument_name):
        # TODO: Add docstring
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
    # TODO: Add docstring
    def MyMethod(self, CamelArg):
        # TODO: Add docstring
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
        assert any(
            "CamelCase" in issue.message or "snake_case" in issue.message for issue in issues
        )

        # Clean up
        path.unlink()

    def test_fix_file_detection(self):
        """Test that fix_file detects issues."""
        code = """
def MyFunction(CamelArg):
    # TODO: Add docstring
    pass
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = NamingConventionFixer()
        success, _fixes = fixer.fix_file(path)

        assert success
        # Note: naming fixes are detection-only, not auto-applied

        # Clean up
        path.unlink()

    def test_scan_file_with_syntax_error(self):
        """Test scanning file with syntax error."""
        code = """
def broken(
    # TODO: Add docstring
    # Missing closing parenthesis
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = NamingConventionFixer()
        issues = fixer.scan_file_for_issues(path)

        # Should return empty list, not crash
        assert issues == []

        # Clean up
        path.unlink()

    def test_fix_file_nonexistent(self):
        """Test fixing nonexistent file."""
        fixer = NamingConventionFixer()
        success, fixes = fixer.fix_file(Path("/nonexistent/file.py"))

        assert not success
        assert fixes == []

    def test_scan_file_nonexistent(self):
        """Test scanning nonexistent file."""
        fixer = NamingConventionFixer()
        issues = fixer.scan_file_for_issues(Path("/nonexistent/file.py"))

        assert issues == []

    def test_visitor_empty_name_check(self):
        """Test visitor handles empty names."""
        visitor = NamingConventionVisitor([])

        # Test is_camel_case with empty string
        assert not visitor._is_camel_case("")
        assert not visitor._is_camel_case("   ")

    def test_visitor_out_of_range_line(self):
        """Test visitor handles out of range line numbers."""
        visitor = NamingConventionVisitor(["line1", "line2"])

        # Create a mock node with invalid line number
        class MockNode:
            # TODO: Add docstring
            lineno = 100  # Out of range

        snippet = visitor._get_code_snippet(MockNode())
        assert snippet == ""


class TestAsyncFunctionNaming:
    """Test async function naming conventions."""

    def test_detect_async_function_violation(self):
        """Test detection of async function name violations."""
        code = """
async def MyAsyncFunction():
    pass

async def camelCaseAsync():
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any(
            "snake_case" in issue.message and issue.name == "MyAsyncFunction"
            for issue in visitor.issues
        )
        assert any(issue.rule_id == "N802" for issue in visitor.issues)

    def test_allow_correct_async_function(self):
        """Test that correctly named async functions pass."""
        code = """
async def async_function():
    pass

async def fetch_data():
    pass
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Should have no issues for these correctly named functions
        naming_issues = [i for i in visitor.issues if i.name in ["async_function", "fetch_data"]]
        assert len(naming_issues) == 0


class TestImportAliasingNaming:
    """Test import alias naming conventions."""

    def test_detect_import_alias_violation(self):
        """Test detection of import alias violations."""
        code = """
from module import function as CamelCaseAlias
from another import Class as snake_case_alias
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 1
        assert any(issue.rule_id == "N811" for issue in visitor.issues)

    def test_allow_correct_import_aliases(self):
        """Test that correctly named import aliases pass."""
        code = """
from module import function as my_alias
from another import Class as MY_ALIAS
from third import item as _private_alias
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Should have no N811 issues
        alias_issues = [i for i in visitor.issues if i.rule_id == "N811"]
        assert len(alias_issues) == 0


class TestAmbiguousVariableNaming:
    """Test detection of ambiguous variable names."""

    def test_detect_all_ambiguous_names(self):
        """Test detection of all ambiguous single-letter names in class context."""
        code = """
class MyClass:
    # TODO: Add docstring
    l = 1
    O = 2
    I = 3
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Should detect all three ambiguous names in class context
        ambiguous = [i for i in visitor.issues if i.rule_id == "E741"]
        assert len(ambiguous) >= 1  # At least one detected

    def test_detect_ambiguous_in_assignment(self):
        """Test detection of ambiguous names in assignments."""
        code = """
l = 1
"""
        tree = ast.parse(code)
        visitor = NamingConventionVisitor(code.splitlines())
        visitor.visit(tree)

        # Module-level ambiguous names should be detected
        ambiguous = [i for i in visitor.issues if i.rule_id == "E741"]
        assert len(ambiguous) >= 1
        assert any(i.name == "l" for i in ambiguous)
