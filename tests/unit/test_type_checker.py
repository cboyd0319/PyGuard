"""Tests for type checker module."""

import ast
from pathlib import Path

import pytest

from pyguard.lib.type_checker import (
    ANY_TYPE_USAGE_RULE,
    MISSING_PARAM_TYPE_RULE,
    MISSING_RETURN_TYPE_RULE,
    TYPE_COMPARISON_RULE,
    TypeChecker,
    TypeInferenceEngine,
)
from pyguard.lib.rule_engine import (
    RuleViolation,
    RuleSeverity as Severity,
    FixApplicability,
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


# ============================================================================
# Enhanced Tests - Following PyTest Architect Agent Guidelines
# ============================================================================


class TestTypeInferenceEdgeCases:
    """Test type inference with edge cases and boundary conditions."""

    @pytest.mark.parametrize(
        "value,expected_type",
        [
            (42, "int"),
            (3.14, "float"),
            ("hello", "str"),
            (True, "bool"),
            (False, "bool"),
            (None, "Optional"),
        ],
        ids=["int", "float", "str", "true", "false", "none"],
    )
    def test_infer_from_constant_values(self, value, expected_type):
        """Test type inference from various constant values.
        
        Validates AAA pattern and parametrization for input matrix coverage.
        """
        # Arrange
        engine = TypeInferenceEngine()
        node = ast.Constant(value=value)
        
        # Act
        result = engine.infer_from_default(node)
        
        # Assert
        assert result == expected_type, f"Expected {expected_type} for {value}, got {result}"

    @pytest.mark.parametrize(
        "node_type,expected",
        [
            (ast.List(elts=[], ctx=ast.Load()), "list"),
            (ast.Dict(keys=[], values=[]), "dict"),
            (ast.Set(elts=[]), "set"),
            (ast.Tuple(elts=[], ctx=ast.Load()), "tuple"),
        ],
        ids=["list", "dict", "set", "tuple"],
    )
    def test_infer_from_collection_literals(self, node_type, expected):
        """Test type inference from collection literals.
        
        Covers common container type patterns.
        """
        # Arrange
        engine = TypeInferenceEngine()
        
        # Act
        result = engine.infer_from_default(node_type)
        
        # Assert
        assert result == expected

    def test_infer_from_unknown_node_returns_none(self):
        """Test that unknown AST nodes return None gracefully.
        
        Error handling: boundary condition where inference cannot proceed.
        """
        # Arrange
        engine = TypeInferenceEngine()
        # Use a node type that shouldn't have type inference
        unknown_node = ast.Name(id="unknown", ctx=ast.Load())
        
        # Act
        result = engine.infer_from_default(unknown_node)
        
        # Assert
        assert result is None

    def test_infer_from_constant_complex_number(self):
        """Test type inference from complex number constant.
        
        Branch coverage: Tests Constant node with value type not in (bool, int, float, str, None).
        """
        # Arrange
        engine = TypeInferenceEngine()
        # Complex numbers are valid Python constants but not in the handled types
        node = ast.Constant(value=complex(1, 2))
        
        # Act
        result = engine.infer_from_default(node)
        
        # Assert
        # Should return None for unhandled constant types
        assert result is None

    def test_infer_from_constant_bytes(self):
        """Test type inference from bytes constant.
        
        Branch coverage: Another constant type not in the handled set.
        """
        # Arrange
        engine = TypeInferenceEngine()
        node = ast.Constant(value=b"bytes")
        
        # Act
        result = engine.infer_from_default(node)
        
        # Assert
        # Should return None for bytes
        assert result is None

    def test_infer_return_type_single_return(self):
        """Test inferring return type from single return statement."""
        # Arrange
        engine = TypeInferenceEngine()
        code = """
def get_number():
    return 42
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        
        # Act
        result = engine.infer_return_type(func_node)
        
        # Assert
        assert result == "int"

    def test_infer_return_type_multiple_consistent_returns(self):
        """Test inferring when multiple returns have same type."""
        # Arrange
        engine = TypeInferenceEngine()
        code = """
def get_value(x):
    if x:
        return 1
    return 2
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        
        # Act
        result = engine.infer_return_type(func_node)
        
        # Assert
        assert result == "int"

    def test_infer_return_type_multiple_inconsistent_returns(self):
        """Test inferring union type from mixed return types."""
        # Arrange
        engine = TypeInferenceEngine()
        code = """
def get_value(x):
    if x:
        return 1
    return "string"
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        
        # Act
        result = engine.infer_return_type(func_node)
        
        # Assert
        assert result is not None
        assert "Union" in result
        assert "int" in result
        assert "str" in result

    def test_infer_return_type_no_return_statement(self):
        """Test inferring when function has no return statement."""
        # Arrange
        engine = TypeInferenceEngine()
        code = """
def no_return():
    x = 5
    print(x)
"""
        tree = ast.parse(code)
        func_node = tree.body[0]
        
        # Act
        result = engine.infer_return_type(func_node)
        
        # Assert
        assert result is None

    def test_infer_from_assignment_delegates_to_default(self):
        """Test that infer_from_assignment uses infer_from_default."""
        # Arrange
        engine = TypeInferenceEngine()
        node = ast.Constant(value=42)
        
        # Act
        result = engine.infer_from_assignment(node)
        
        # Assert
        assert result == "int"


class TestAnyTypeDetection:
    """Test detection of Any type usage."""

    def test_detect_any_type_in_variable_annotation(self, tmp_path):
        """Test detection of Any in variable annotation."""
        # Arrange
        code = """
from typing import Any

x: Any = 5
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        assert any(v.rule_id == ANY_TYPE_USAGE_RULE.rule_id for v in violations)

    def test_no_false_positive_for_non_any_annotation(self, tmp_path):
        """Test that non-Any annotations don't trigger false positives."""
        # Arrange
        code = """
x: int = 5
y: str = "hello"
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        any_violations = [v for v in violations if v.rule_id == ANY_TYPE_USAGE_RULE.rule_id]
        assert len(any_violations) == 0


class TestSpecialMethodHandling:
    """Test handling of special methods and edge cases."""

    @pytest.mark.parametrize(
        "method_name",
        [
            "__init__",
            "__str__",
            "__repr__",
            "__enter__",
            "__exit__",
            "__call__",
            "__len__",
        ],
        ids=["init", "str", "repr", "enter", "exit", "call", "len"],
    )
    def test_special_methods_skip_return_type_check(self, tmp_path, method_name):
        """Test that special methods don't require return type annotation.
        
        Special methods have well-defined return types by convention.
        """
        # Arrange
        code = f"""
class MyClass:
    def {method_name}(self):
        pass
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        return_violations = [v for v in violations if v.rule_id == MISSING_RETURN_TYPE_RULE.rule_id]
        assert len(return_violations) == 0

    def test_self_parameter_not_flagged(self, tmp_path):
        """Test that 'self' parameter doesn't need type annotation."""
        # Arrange
        code = """
class MyClass:
    def method(self, other) -> None:
        pass
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should only flag 'other', not 'self'
        param_violations = [v for v in violations if v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id]
        assert len(param_violations) == 1
        assert "other" in str(violations)

    def test_cls_parameter_not_flagged(self, tmp_path):
        """Test that 'cls' parameter doesn't need type annotation."""
        # Arrange
        code = """
class MyClass:
    @classmethod
    def method(cls, other) -> None:
        pass
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should only flag 'other', not 'cls'
        param_violations = [v for v in violations if v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id]
        assert len(param_violations) == 1


class TestTypeComparisonEdgeCases:
    """Test type comparison detection with various patterns."""

    @pytest.mark.parametrize(
        "comparison_op,should_detect",
        [
            ("==", True),
            ("is", True),
            ("!=", False),  # Currently not detected by implementation
            ("is not", False),  # Currently not detected by implementation
        ],
        ids=["eq", "is", "ne", "is_not"],
    )
    def test_detect_type_comparison_operators(self, tmp_path, comparison_op, should_detect):
        """Test detection of various type() comparison operators.
        
        Currently detects == and is operators. NotEq and IsNot are not detected
        but could be added in future enhancements.
        """
        # Arrange
        code = f"""
def check(obj):
    if type(obj) {comparison_op} str:
        return True
    return False
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        has_violation = any(v.rule_id == TYPE_COMPARISON_RULE.rule_id for v in violations)
        if should_detect:
            assert has_violation, f"Expected to detect type() {comparison_op} pattern"
        else:
            assert not has_violation, f"Did not expect to detect type() {comparison_op} pattern"

    def test_type_comparison_in_nested_expression(self, tmp_path):
        """Test detection of type() in nested boolean expressions."""
        # Arrange
        code = """
def check(obj):
    return type(obj) == str and obj.startswith("test")
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        assert any(v.rule_id == TYPE_COMPARISON_RULE.rule_id for v in violations)

    def test_comparison_without_type_call_left_side(self, tmp_path):
        """Test comparison where left side is not type() call.
        
        Branch coverage: Tests Compare node where left is not a Call (line 278->275).
        """
        # Arrange
        code = """
def check(value):
    # Regular comparison, not type()
    return value == 42
"""
        test_file = tmp_path / "regular_compare.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should not detect type comparison violation
        type_comp_violations = [v for v in violations if v.rule_id == TYPE_COMPARISON_RULE.rule_id]
        assert len(type_comp_violations) == 0

    def test_comparison_with_non_type_call(self, tmp_path):
        """Test comparison with a call that's not type().
        
        Branch coverage: Tests Compare with Call node but not type() (line 279->275).
        """
        # Arrange
        code = """
def check(obj):
    # Call to len(), not type()
    return len(obj) == 5
"""
        test_file = tmp_path / "other_call.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should not detect type comparison violation
        type_comp_violations = [v for v in violations if v.rule_id == TYPE_COMPARISON_RULE.rule_id]
        assert len(type_comp_violations) == 0


class TestBoundaryConditions:
    """Test boundary conditions and edge cases for robustness."""

    def test_empty_file_no_violations(self, tmp_path):
        """Test that empty file produces no violations."""
        # Arrange
        test_file = tmp_path / "empty.py"
        test_file.write_text("")
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        assert violations == []

    def test_only_comments_no_violations(self, tmp_path):
        """Test file with only comments."""
        # Arrange
        code = """
# Just a comment
# Another comment
"""
        test_file = tmp_path / "comments.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        assert violations == []

    def test_only_docstring_no_violations(self, tmp_path):
        """Test file with only module docstring."""
        # Arrange
        code = '"""Module docstring."""'
        test_file = tmp_path / "docstring.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        assert violations == []

    def test_function_with_all_defaults_inferred(self, tmp_path):
        """Test type inference from parameter defaults."""
        # Arrange
        code = """
def greet(name="World", count=1):
    return f"Hello {name} " * count
"""
        test_file = tmp_path / "defaults.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should detect missing types even with defaults
        assert any(v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id for v in violations)

    def test_function_with_uninferrable_defaults(self, tmp_path):
        """Test type inference when defaults cannot be inferred.
        
        Branch coverage: Tests loop where no default can be inferred (line 118->116).
        """
        # Arrange
        code = """
def process(callback=lambda x: x):
    return callback(42)
"""
        test_file = tmp_path / "uninferrable.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should detect missing param type with "Unknown" as inferred type
        assert any(v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id for v in violations)
        # The inferred type should be Unknown since lambda can't be inferred
        param_violations = [v for v in violations if v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id]
        assert len(param_violations) > 0

    def test_unicode_identifiers_handled(self, tmp_path):
        """Test that unicode identifiers are handled correctly."""
        # Arrange
        code = """
def 处理数据(数据):
    return 数据 * 2
"""
        test_file = tmp_path / "unicode.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should detect missing types for unicode parameter names
        assert any(v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id for v in violations)

    def test_lambda_functions_not_flagged(self, tmp_path):
        """Test that lambda functions are not flagged for missing types.
        
        Lambdas cannot have type annotations in the same way.
        """
        # Arrange
        code = """
square = lambda x: x * 2
"""
        test_file = tmp_path / "lambda.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Lambdas should not be flagged
        assert len(violations) == 0

    def test_nested_functions_detected(self, tmp_path):
        """Test that nested functions are also checked."""
        # Arrange
        code = """
def outer():
    def inner(x):
        return x * 2
    return inner
"""
        test_file = tmp_path / "nested.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Both outer and inner should be flagged
        assert any(v.rule_id == MISSING_RETURN_TYPE_RULE.rule_id for v in violations)
        assert any(v.rule_id == MISSING_PARAM_TYPE_RULE.rule_id for v in violations)


class TestComplexTypeAnnotations:
    """Test handling of complex type annotations."""

    def test_generic_types_recognized(self, tmp_path):
        """Test that generic types are recognized as valid annotations."""
        # Arrange
        code = """
from typing import List, Dict

def process(items: List[int]) -> Dict[str, int]:
    return {str(i): i for i in items}
"""
        test_file = tmp_path / "generics.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        # Should not flag properly typed function
        type_violations = [
            v for v in violations 
            if v.rule_id in (MISSING_RETURN_TYPE_RULE.rule_id, MISSING_PARAM_TYPE_RULE.rule_id)
        ]
        assert len(type_violations) == 0

    def test_union_types_recognized(self, tmp_path):
        """Test that Union types are recognized."""
        # Arrange
        code = """
from typing import Union

def process(value: Union[int, str]) -> Union[int, None]:
    if isinstance(value, int):
        return value
    return None
"""
        test_file = tmp_path / "union.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        type_violations = [
            v for v in violations 
            if v.rule_id in (MISSING_RETURN_TYPE_RULE.rule_id, MISSING_PARAM_TYPE_RULE.rule_id)
        ]
        assert len(type_violations) == 0

    def test_callable_types_recognized(self, tmp_path):
        """Test that Callable types are recognized."""
        # Arrange
        code = """
from typing import Callable

def apply(func: Callable[[int], int], value: int) -> int:
    return func(value)
"""
        test_file = tmp_path / "callable.py"
        test_file.write_text(code)
        
        # Act
        checker = TypeChecker()
        violations = checker.analyze_file(test_file)
        
        # Assert
        type_violations = [
            v for v in violations 
            if v.rule_id in (MISSING_RETURN_TYPE_RULE.rule_id, MISSING_PARAM_TYPE_RULE.rule_id)
        ]
        assert len(type_violations) == 0


class TestTypeCheckerSyntaxErrors:
    """Test type checker handles syntax errors gracefully."""

    def test_detect_type_hints_with_syntax_error(self, tmp_path):
        """Test type hint detection handles syntax errors."""
        # Arrange
        code = "def broken_syntax(\n    # Unclosed paren"
        test_file = tmp_path / "broken.py"
        test_file.write_text(code)
        
        # Act
        from pyguard.lib.type_checker import _detect_type_hints
        violations = _detect_type_hints(code, test_file)
        
        # Assert - should return empty list, not crash
        assert violations == []

    def test_detect_type_comparison_with_syntax_error(self, tmp_path):
        """Test type comparison detection handles syntax errors."""
        # Arrange
        code = "if type(x) == int\n    # Missing colon"
        test_file = tmp_path / "broken.py"
        test_file.write_text(code)
        
        # Act
        from pyguard.lib.type_checker import _detect_type_comparison
        violations = _detect_type_comparison(code, test_file)
        
        # Assert - should return empty list, not crash
        assert violations == []


class TestTypeCheckerAutoFix:
    """Test type checker auto-fix functionality."""

    def test_apply_type_hints_with_none_content(self, tmp_path):
        """Test add_type_hints handles file read failure."""
        # Arrange
        nonexistent_file = tmp_path / "nonexistent.py"
        checker = TypeChecker()
        
        # Act
        success, count = checker.add_type_hints(nonexistent_file, [])
        
        # Assert
        assert success is False
        assert count == 0

    def test_apply_type_hints_with_no_fixable_violations(self, tmp_path):
        """Test add_type_hints with no fixable violations."""
        # Arrange
        code = "def func():\n    pass"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        checker = TypeChecker()
        # Create violations without fix_data
        from pyguard.lib.rule_engine import RuleCategory
        violations = [
            RuleViolation(
                rule_id="TC001",
                category=RuleCategory.TYPE,
                severity=Severity.MEDIUM,
                message="Missing type hint",
                file_path=test_file,
                line_number=1,
                column=0,
                fix_applicability=FixApplicability.SUGGESTED,
                fix_data=None,  # No fix data
            )
        ]
        
        # Act
        success, count = checker.add_type_hints(test_file, violations)
        
        # Assert
        assert success is True
        assert count == 0

    def test_apply_type_hints_with_fixable_violations(self, tmp_path):
        """Test add_type_hints with fixable violations (placeholder)."""
        # Arrange
        code = "def func():\n    return 42"
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        checker = TypeChecker()
        # Create violations with inferred types
        from pyguard.lib.rule_engine import RuleCategory
        violations = [
            RuleViolation(
                rule_id=MISSING_RETURN_TYPE_RULE.rule_id,
                category=RuleCategory.TYPE,
                severity=Severity.MEDIUM,
                message="Missing return type",
                file_path=test_file,
                line_number=1,
                column=0,
                fix_applicability=FixApplicability.SUGGESTED,
                fix_data={"inferred_type": "int"},
            )
        ]
        
        # Act
        success, count = checker.add_type_hints(test_file, violations)
        
        # Assert - currently returns 0 as it's a TODO
        assert success is True
        assert count == 0
