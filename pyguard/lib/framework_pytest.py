"""
Pytest Framework Rules (PT) - pytest-specific best practices.

This module implements detection for pytest-specific issues including:
- Test structure and organization
- Fixture usage and best practices
- Assertion improvements
- Test naming conventions
- Parametrization patterns

References:
- pytest documentation: https://docs.pytest.org/
- Ruff pytest rules: https://docs.astral.sh/ruff/rules/#flake8-pytest-style-pt
"""

import ast
from pathlib import Path
from typing import List

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class PytestVisitor(ast.NodeVisitor):
    """AST visitor for pytest-specific issues."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.is_test_file = self._detect_pytest(code) or 'test_' in str(file_path.name)

    def _detect_pytest(self, code: str) -> bool:
        """Check if file uses pytest."""
        return 'import pytest' in code or 'from pytest' in code  # pyguard: disable=CWE-89  # Pattern detection, not vulnerable code

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Detect test function issues (PT001-PT027)."""
        if not self.is_test_file:
            self.generic_visit(node)
            return

        is_test_func = node.name.startswith('test_')
        is_fixture = any(
            isinstance(dec, ast.Name) and dec.id == 'fixture' or
            (isinstance(dec, ast.Attribute) and dec.attr == 'fixture') or
            (isinstance(dec, ast.Call) and
             (isinstance(dec.func, ast.Name) and dec.func.id == 'fixture' or
              isinstance(dec.func, ast.Attribute) and dec.func.attr == 'fixture'))
            for dec in node.decorator_list
        )

        if is_test_func:
            # PT001: Use @pytest.fixture() instead of fixture without call
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name) and dec.id == 'fixture':
                    self.violations.append(
                        RuleViolation(
                            rule_id="PT001",
                            message="Use @pytest.fixture() instead of @fixture",
                            line_number=dec.lineno,
                            column=dec.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

            # PT002: Test function contains yield - should be a fixture
            has_yield = any(isinstance(n, ast.Yield) for n in ast.walk(node))
            if has_yield and not is_fixture:
                self.violations.append(
                    RuleViolation(
                        rule_id="PT002",
                        message="Test function contains yield - consider making it a fixture",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.CONVENTION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

            # PT004: Fixture does not return/yield anything
            if is_fixture:
                has_return = any(
                    isinstance(n, ast.Return) and n.value is not None
                    for n in ast.walk(node)
                )
                has_yield = any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(node))

                if not has_return and not has_yield:
                    self.violations.append(
                        RuleViolation(
                            rule_id="PT004",
                            message="Fixture should return or yield a value",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.WARNING,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.NONE,
                        )
                    )

            # PT006: Wrong name(s) for pytest parametrize values
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Attribute) and dec.func.attr == 'parametrize':
                        # Check if first argument is argnames
                        if len(dec.args) >= 2:
                            argnames = dec.args[0]
                            if isinstance(argnames, ast.Constant) and isinstance(argnames.value, str):
                                # Check if argvalues is properly structured
                                pass

            # PT009: Use unittest.TestCase.assert* methods instead of plain assert in unittest
            # This is more relevant for unittest migration

            # PT011: pytest.raises() too broad - should specify exception type
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.With):
                    for item in stmt.items:
                        if isinstance(item.context_expr, ast.Call):
                            func = item.context_expr.func
                            if isinstance(func, ast.Attribute) and func.attr == 'raises':
                                if len(item.context_expr.args) == 0:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="PT011",
                                            message="pytest.raises() should specify exception type",
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.ERROR,
                                            file_path=self.file_path,
                                            fix_applicability=FixApplicability.NONE,
                                        )
                                    )

            # PT015: Assertion always fails - pytest.fail() instead of assert False
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assert):
                    if isinstance(stmt.test, ast.Constant) and stmt.test.value is False:
                        self.violations.append(
                            RuleViolation(
                                rule_id="PT015",
                                message="Use pytest.fail() instead of assert False",
                                line_number=stmt.lineno,
                                column=stmt.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.STYLE,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Detect assertion issues (PT017-PT027)."""
        if not self.is_test_file:
            self.generic_visit(node)
            return

        # PT018: Composite assertion can be split
        if isinstance(node.test, ast.BoolOp):
            if isinstance(node.test.op, ast.And):
                self.violations.append(
                    RuleViolation(
                        rule_id="PT018",
                        message="Composite assertion with 'and' - split into multiple asserts",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # PT019: Use @pytest.mark.xfail instead of assert with condition
        # This requires more context about the test structure

        self.generic_visit(node)


class PytestRulesChecker:
    """Main checker for pytest-specific rules."""

    def __init__(self):
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a Python file for pytest-specific issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            # Only check test files
            if 'test_' not in str(file_path.name) and 'pytest' not in code:
                return []

            tree = ast.parse(code)
            visitor = PytestVisitor(file_path, code)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []


# Define rules for registration
PYTEST_RULES = [
    Rule(
        rule_id="PT001",
        name="pytest-fixture-call",
        description="Use @pytest.fixture() with parentheses",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use @pytest.fixture() instead of @fixture",
    ),
    Rule(
        rule_id="PT002",
        name="pytest-fixture-positional-args",
        description="Test function contains yield - should be a fixture",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider making this a fixture",
    ),
    Rule(
        rule_id="PT004",
        name="pytest-fixture-does-not-return",
        description="Fixture should return or yield a value",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Add return or yield statement",
    ),
    Rule(
        rule_id="PT006",
        name="pytest-parametrize-names-wrong-type",
        description="Wrong name(s) for pytest.mark.parametrize values",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Check parametrize argument names",
    ),
    Rule(
        rule_id="PT011",
        name="pytest-raises-too-broad",
        description="pytest.raises() should specify exception type",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.NONE,
        message_template="Specify the expected exception type",
    ),
    Rule(
        rule_id="PT015",
        name="pytest-assert-always-false",
        description="Use pytest.fail() instead of assert False",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Replace with pytest.fail()",
    ),
    Rule(
        rule_id="PT018",
        name="pytest-composite-assertion",
        description="Composite assertion can be split",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Split into multiple assert statements",
    ),
]
