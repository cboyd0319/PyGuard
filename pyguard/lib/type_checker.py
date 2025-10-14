"""
Type checking and inference for Python code.

Provides type analysis, type hint validation, and type hint auto-addition.
Complements mypy/pytype by focusing on practical type improvements and auto-fixes.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class TypeInferenceEngine:
    """Simple type inference for common patterns."""

    def __init__(self):
        """Initialize type inference engine."""
        self.logger = PyGuardLogger()

    def infer_from_default(self, default_value: ast.AST) -> Optional[str]:
        """Infer type from default value."""
        if isinstance(default_value, ast.Constant):
            value = default_value.value
            if isinstance(value, bool):
                return "bool"
            elif isinstance(value, int):
                return "int"
            elif isinstance(value, float):
                return "float"
            elif isinstance(value, str):
                return "str"
            elif value is None:
                return "Optional"
        elif isinstance(default_value, ast.List):
            return "list"
        elif isinstance(default_value, ast.Dict):
            return "dict"
        elif isinstance(default_value, ast.Set):
            return "set"
        elif isinstance(default_value, ast.Tuple):
            return "tuple"
        return None

    def infer_from_assignment(self, value: ast.AST) -> Optional[str]:
        """Infer type from assignment value."""
        return self.infer_from_default(value)

    def infer_return_type(self, func_node: ast.FunctionDef) -> Optional[str]:
        """Infer return type from function body."""
        # Simple inference from return statements
        return_types = set()

        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value:
                inferred = self.infer_from_assignment(node.value)
                if inferred:
                    return_types.add(inferred)

        if len(return_types) == 1:
            return list(return_types)[0]
        elif len(return_types) > 1:
            # Multiple return types - suggest Union
            return f"Union[{', '.join(sorted(return_types))}]"

        return None


class TypeHintVisitor(ast.NodeVisitor):
    """AST visitor for type hint analysis."""

    def __init__(self, source_lines: List[str]):
        """Initialize visitor."""
        self.source_lines = source_lines
        self.violations: List[Tuple[Rule, Dict[str, Any]]] = []
        self.type_inference = TypeInferenceEngine()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        # Skip private functions
        if node.name.startswith("_") and not node.name.startswith("__"):
            self.generic_visit(node)
            return

        # Check for missing return type annotation
        if not node.returns and not self._is_init_or_special(node.name):
            # Try to infer return type
            inferred_type = self.type_inference.infer_return_type(node)
            # Always report missing return type, even if we can't infer it
            self.violations.append(
                (
                    MISSING_RETURN_TYPE_RULE,
                    {
                        "line_number": node.lineno,
                        "column": node.col_offset,
                        "function_name": node.name,
                        "inferred_type": inferred_type or "Unknown",
                    },
                )
            )

        # Check for missing parameter type annotations
        for arg in node.args.args:
            if not arg.annotation and arg.arg not in ("self", "cls"):
                # Try to infer from default
                inferred_type = None
                for default in node.args.defaults:
                    inferred_type = self.type_inference.infer_from_default(default)
                    if inferred_type:
                        break

                self.violations.append(
                    (
                        MISSING_PARAM_TYPE_RULE,
                        {
                            "line_number": arg.lineno,
                            "column": arg.col_offset,
                            "parameter_name": arg.arg,
                            "function_name": node.name,
                            "inferred_type": inferred_type or "Unknown",
                        },
                    )
                )

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit annotated assignment."""
        # Check for Any type usage
        if self._contains_any_type(node.annotation):
            self.violations.append(
                (
                    ANY_TYPE_USAGE_RULE,
                    {
                        "line_number": node.lineno,
                        "column": node.col_offset,
                    },
                )
            )

        self.generic_visit(node)

    def _is_init_or_special(self, name: str) -> bool:
        """Check if function is __init__ or other special method."""
        return name.startswith("__") and name.endswith("__")

    def _contains_any_type(self, node: ast.AST) -> bool:
        """Check if annotation contains Any type."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id == "Any":
                return True
        return False


class TypeCheckingRule(Rule):
    """Base class for type checking rules."""

    def __init__(self, **kwargs):
        """Initialize type checking rule."""
        super().__init__(category=RuleCategory.TYPE, **kwargs)


# Define type checking rules
MISSING_RETURN_TYPE_RULE = TypeCheckingRule(
    rule_id="PG-T001",
    name="missing-return-type",
    severity=RuleSeverity.MEDIUM,
    message_template="Function '{function_name}' missing return type annotation",
    description="Public functions should have return type annotations for better type safety",
    explanation=(
        "Type annotations help catch bugs early, improve code documentation, "
        "and enable better IDE support. Return type annotations are especially important "
        "as they document the contract of the function."
    ),
    fix_applicability=FixApplicability.SUGGESTED,
    tags={"type-hint", "documentation", "pep484"},
    references=["https://peps.python.org/pep-0484/"],
)

MISSING_PARAM_TYPE_RULE = TypeCheckingRule(
    rule_id="PG-T002",
    name="missing-parameter-type",
    severity=RuleSeverity.MEDIUM,
    message_template="Parameter '{parameter_name}' in '{function_name}' missing type annotation",
    description="Function parameters should have type annotations",
    explanation=(
        "Parameter type annotations help catch type errors at call sites and "
        "improve code documentation. They are essential for static type checking."
    ),
    fix_applicability=FixApplicability.SUGGESTED,
    tags={"type-hint", "documentation", "pep484"},
    references=["https://peps.python.org/pep-0484/"],
)

ANY_TYPE_USAGE_RULE = TypeCheckingRule(
    rule_id="PG-T003",
    name="any-type-usage",
    severity=RuleSeverity.LOW,
    message_template="Using 'Any' type annotation reduces type safety",
    description="Avoid using Any type; use specific types or generics instead",
    explanation=(
        "The Any type disables type checking for that value. While sometimes necessary, "
        "it should be used sparingly. Consider using generics (TypeVar) or Union types instead."
    ),
    fix_applicability=FixApplicability.MANUAL,
    tags={"type-hint", "type-safety"},
    references=["https://mypy.readthedocs.io/en/stable/kinds_of_types.html#the-any-type"],
)

TYPE_COMPARISON_RULE = TypeCheckingRule(
    rule_id="PG-T004",
    name="type-comparison",
    severity=RuleSeverity.MEDIUM,
    message_template="Use isinstance() instead of type() for type checking",
    description="type() comparison doesn't respect inheritance",
    explanation=(
        "Using type(x) == SomeClass is fragile and doesn't work with inheritance. "
        "Use isinstance(x, SomeClass) instead, which properly handles subclasses."
    ),
    fix_applicability=FixApplicability.AUTOMATIC,
    tags={"type-checking", "best-practice"},
)


# Implement detection for type checking rules
def _detect_type_hints(code: str, file_path: Path, tree: Optional[ast.AST] = None):
    """Detect missing type hints."""
    if tree is None:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

    source_lines = code.split("\n")
    visitor = TypeHintVisitor(source_lines)
    visitor.visit(tree)

    violations = []
    for rule, data in visitor.violations:
        violation = RuleViolation(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=rule.severity,
            message=rule.format_message(**data),
            file_path=file_path,
            line_number=data["line_number"],
            column=data.get("column", 0),
            fix_applicability=rule.fix_applicability,
            fix_data=data,
        )
        violations.append(violation)

    return violations


def _detect_type_comparison(code: str, file_path: Path, tree: Optional[ast.AST] = None):
    """Detect type() == comparisons."""
    if tree is None:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

    violations = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            # Check for type(x) == SomeClass or type(x) is SomeClass
            if isinstance(node.left, ast.Call):
                if (
                    isinstance(node.left.func, ast.Name)
                    and node.left.func.id == "type"
                    and len(node.left.args) == 1
                ):
                    # Found type() call in comparison
                    for op in node.ops:
                        if isinstance(op, (ast.Eq, ast.Is)):
                            violation = RuleViolation(
                                rule_id=TYPE_COMPARISON_RULE.rule_id,
                                category=TYPE_COMPARISON_RULE.category,
                                severity=TYPE_COMPARISON_RULE.severity,
                                message=TYPE_COMPARISON_RULE.message_template,
                                file_path=file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                fix_applicability=TYPE_COMPARISON_RULE.fix_applicability,
                            )
                            violations.append(violation)

    return violations


# Note: Detection functions are handled by the Rule base class detect() method
# The TypeCheckingRule class can override detect() if needed for custom behavior


class TypeChecker:
    """Main type checker class."""

    def __init__(self):
        """Initialize type checker."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.inference_engine = TypeInferenceEngine()

    def analyze_file(self, file_path: Path) -> List[RuleViolation]:
        """Analyze a file for type-related issues."""
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        violations = []

        # Run all type checking rules
        violations.extend(_detect_type_hints(content, file_path, tree))
        violations.extend(_detect_type_comparison(content, file_path, tree))

        return violations

    def add_type_hints(
        self, file_path: Path, violations: List[RuleViolation]
    ) -> Tuple[bool, int]:
        """
        Add type hints based on violations.

        Args:
            file_path: Path to file
            violations: List of type-related violations

        Returns:
            Tuple of (success, number of hints added)
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return False, 0

        # Filter for type hint violations with inferred types
        hint_violations = [
            v
            for v in violations
            if v.rule_id in (MISSING_RETURN_TYPE_RULE.rule_id, MISSING_PARAM_TYPE_RULE.rule_id)
            and v.fix_data
            and v.fix_data.get("inferred_type")
        ]

        if not hint_violations:
            return True, 0

        # TODO: Implement AST-based type hint addition
        # This is a placeholder for the actual implementation
        self.logger.info(
            f"Would add {len(hint_violations)} type hints",
            file_path=str(file_path),
        )

        return True, 0


# Register all type checking rules
register_rules(
    [
        MISSING_RETURN_TYPE_RULE,
        MISSING_PARAM_TYPE_RULE,
        ANY_TYPE_USAGE_RULE,
        TYPE_COMPARISON_RULE,
    ]
)
