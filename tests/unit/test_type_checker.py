"""Tests for type checker module."""

from pathlib import Path

import pytest

from pyguard.lib.type_checker import (
    MISSING_PARAM_TYPE_RULE,
    MISSING_RETURN_TYPE_RULE,
    TYPE_COMPARISON_RULE,
    TypeChecker,
    TypeInferenceEngine,
)


class TestTypeInference:
    """Test type inference engine."""

    def test_infer_from_int_default(self):
        """Test inferring int from default value."""
        import ast

        engine = TypeInferenceEngine()
        node = ast.Constant(value=42)
        inferred = engine.infer_from_default(node)
        assert inferred == "int"

    def test_infer_from_str_default(self):
        """Test inferring str from default value."""
        import ast

        engine = TypeInferenceEngine()
        node = ast.Constant(value="hello")
        inferred = engine.infer_from_default(node)
        assert inferred == "str"

    def test_infer_from_bool_default(self):
        """Test inferring bool from default value."""
        import ast

        engine = TypeInferenceEngine()
        node = ast.Constant(value=True)
        inferred = engine.infer_from_default(node)
        assert inferred == "bool"

    def test_infer_from_list_default(self):
        """Test inferring list from default value."""
        import ast

        engine = TypeInferenceEngine()
        node = ast.List(elts=[], ctx=ast.Load())
        inferred = engine.infer_from_default(node)
        assert inferred == "list"


class TestMissingTypeHints:
    """Test missing type hint detection."""

    def test_detect_missing_return_type(self, tmp_path):
        """Test detection of missing return type."""
        code = """
def calculate_sum(a, b):
    return a + b
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should detect missing return type and param types
        assert any(v.rule_id == MISSING_RETURN_TYPE_RULE.rule_id for v in violations)

    def test_detect_missing_param_type(self, tmp_path):
        """Test detection of missing parameter type."""
        code = """
def greet(name):
    print(f"Hello, {name}")
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should detect missing param type
        assert any(v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id for v in violations)

    def test_no_violation_with_full_types(self, tmp_path):
        """Test no violations when types are present."""
        code = """
def calculate_sum(a: int, b: int) -> int:
    return a + b
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should not detect missing types
        type_violations = [
            v
            for v in violations
            if v.rule_id in (MISSING_RETURN_TYPE_RULE.rule_id, MISSING_PARAM_TYPE_RULE.rule_id)
        ]
        assert len(type_violations) == 0

    def test_skip_private_functions(self, tmp_path):
        """Test that private functions are skipped."""
        code = """
def _internal_helper(x):
    return x * 2
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should not flag private functions
        assert len(violations) == 0

    def test_skip_init_method(self, tmp_path):
        """Test that __init__ doesn't need return type."""
        code = """
class MyClass:
    def __init__(self, value):
        self.value = value
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should not flag __init__ for missing return type
        return_violations = [v for v in violations if v.rule_id == MISSING_RETURN_TYPE_RULE.rule_id]
        assert len(return_violations) == 0


class TestTypeComparison:
    """Test type() comparison detection."""

    def test_detect_type_comparison_eq(self, tmp_path):
        """Test detection of type() == comparison."""
        code = """
def check_type(obj):
    if type(obj) == str:
        return True
    return False
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should detect type() == comparison
        assert any(v.rule_id == TYPE_COMPARISON_RULE.rule_id for v in violations)

    def test_detect_type_comparison_is(self, tmp_path):
        """Test detection of type() is comparison."""
        code = """
def check_type(obj):
    if type(obj) is str:
        return True
    return False
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should detect type() is comparison
        assert any(v.rule_id == TYPE_COMPARISON_RULE.rule_id for v in violations)

    def test_no_violation_with_isinstance(self, tmp_path):
        """Test no violation with isinstance."""
        code = """
def check_type(obj):
    if isinstance(obj, str):
        return True
    return False
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should not flag isinstance
        type_comp_violations = [v for v in violations if v.rule_id == TYPE_COMPARISON_RULE.rule_id]
        assert len(type_comp_violations) == 0


class TestTypeChecker:
    """Test TypeChecker class."""

    def test_analyze_file_with_multiple_issues(self, tmp_path):
        """Test analyzing file with multiple type issues."""
        code = """
def process_data(data):
    if type(data) == list:
        return len(data)
    return 0
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should detect both missing types and type() comparison
        assert len(violations) > 0

    def test_analyze_file_syntax_error(self, tmp_path):
        """Test analyzing file with syntax error."""
        code = """
def broken_function(
    # Missing closing parenthesis
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        checker = TypeChecker()
        violations = checker.analyze_file(test_file)

        # Should handle syntax error gracefully
        assert violations == []

    def test_analyze_nonexistent_file(self):
        """Test analyzing non-existent file."""
        checker = TypeChecker()
        violations = checker.analyze_file(Path("/nonexistent/file.py"))

        # Should handle missing file gracefully
        assert violations == []
