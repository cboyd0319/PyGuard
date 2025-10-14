"""
FURB (refurb) - Refactoring opportunities and code modernization patterns.

This module implements detection and auto-fixes for refactoring opportunities
that make Python code more modern, efficient, and idiomatic.

References:
- Refurb tool: https://github.com/dosisod/refurb
- Ruff FURB rules: https://docs.astral.sh/ruff/rules/#refurb-furb
"""

import ast
import re
from pathlib import Path
from typing import List, Tuple

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class RefurbPatternVisitor(ast.NodeVisitor):
    """AST visitor for detecting refactoring opportunities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []

    def visit_While(self, node: ast.While) -> None:
        """Detect while loops that should be for loops (FURB101)."""
        # Check for pattern: while line := file.read(...):
        # Better: for line in file:
        if isinstance(node.test, ast.NamedExpr):
            # Check if it's a file.read() or file.readline() pattern
            if isinstance(node.test.value, ast.Call):
                if isinstance(node.test.value.func, ast.Attribute):
                    attr = node.test.value.func
                    if attr.attr in ("read", "readline", "readlines"):
                        self.violations.append(
                            RuleViolation(
                                rule_id="FURB101",
                                message=f"Use 'for {node.test.target.id if isinstance(node.test.target, ast.Name) else 'line'} in file' instead of while with assignment",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect various refactoring opportunities in function calls."""
        # FURB102: sorted() on list comprehension - use generator instead
        if isinstance(node.func, ast.Name) and node.func.id == "sorted":
            if len(node.args) > 0 and isinstance(node.args[0], ast.ListComp):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB102",
                        message="Use generator expression instead of list comprehension with sorted()",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.PERFORMANCE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # FURB103: open() without context manager
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            # Check if this is inside a 'with' statement
            # This requires checking parent nodes which we'll implement in checker
            pass

        # FURB104: Unnecessary list() around sorted()
        if isinstance(node.func, ast.Name) and node.func.id == "list":
            if len(node.args) > 0 and isinstance(node.args[0], ast.Call):
                inner_call = node.args[0]
                if isinstance(inner_call.func, ast.Name) and inner_call.func.id == "sorted":
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB104",
                            message="Unnecessary list() wrapper around sorted() - sorted() already returns a list",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SIMPLIFICATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        # FURB105: print() with sep="" - use ''.join() instead
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            for keyword in node.keywords:
                if keyword.arg == "sep" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value == "":
                        self.violations.append(
                            RuleViolation(
                                rule_id="FURB105",
                                message="Use ''.join() instead of print() with sep=''",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.SIMPLIFICATION,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Detect with statement patterns."""
        # Check for pathlib usage opportunities
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                if isinstance(item.context_expr.func, ast.Name):
                    if item.context_expr.func.id == "open":
                        # Check if using string paths instead of Path objects
                        if len(item.context_expr.args) > 0:
                            arg = item.context_expr.args[0]
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="FURB106",
                                        message="Consider using pathlib.Path instead of string paths with open()",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.LOW,
                                        category=RuleCategory.MODERNIZATION,
                                        file_path=self.file_path,
                                        fix_applicability=FixApplicability.SUGGESTED,
                                    )
                                )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect comparison patterns that could be improved."""
        # FURB107: sys.version_info >= (3, x) - use sys.version_info >= (3, x, 0) for clarity
        if isinstance(node.left, ast.Attribute):
            if (
                isinstance(node.left.value, ast.Name)
                and node.left.value.id == "sys"
                and node.left.attr == "version_info"
            ):
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Tuple):
                        if len(comparator.elts) == 2:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FURB107",
                                    message="Use full version tuple (3, x, 0) for sys.version_info comparisons",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.CONVENTION,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Detect attribute access patterns."""
        # FURB108: os.path.join() should use Path() / operator
        if isinstance(node.value, ast.Attribute):
            if (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "path"
                and node.attr in ("join", "exists", "isfile", "isdir")
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB108",
                        message=f"Use pathlib.Path instead of os.path.{node.attr}()",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        self.generic_visit(node)


class RefurbPatternChecker:
    """Main checker for refactoring pattern detection and fixes."""

    def __init__(self):
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a Python file for refactoring opportunities.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            tree = ast.parse(code)
            visitor = RefurbPatternVisitor(file_path, code)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []

    def fix_file(self, file_path: Path) -> Tuple[bool, int]:
        """
        Automatically fix refactoring opportunities in a file.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (success, number of fixes applied)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            original_code = code
            fixes_applied = 0

            # Fix FURB104: Remove unnecessary list() around sorted()
            pattern = r"\blist\(sorted\("
            if re.search(pattern, code):
                code = re.sub(r"\blist\(sorted\(([^)]+)\)\)", r"sorted(\1)", code)
                fixes_applied += len(re.findall(pattern, original_code))

            # Fix FURB102: Convert list comprehension to generator in sorted()
            # This is more complex and requires AST manipulation
            # We'll implement this in a future iteration

            if fixes_applied > 0:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(code)

                self.logger.info(
                    f"Fixed {fixes_applied} refactoring opportunities",
                    file_path=str(file_path),
                )
                return True, fixes_applied

            return True, 0

        except Exception as e:
            self.logger.error(f"Error fixing file: {e}", file_path=str(file_path))
            return False, 0


# Define rules for registration
REFURB_RULES = [
    Rule(
        rule_id="FURB101",
        name="while-read-loop",
        description="Use 'for line in file' instead of while with assignment",
        category=RuleCategory.REFACTOR,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using a for loop instead of while with assignment for file reading",
    ),
    Rule(
        rule_id="FURB102",
        name="sorted-list-comp",
        description="Use generator expression instead of list comprehension with sorted()",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use generator expression for better performance: sorted(x for x in ...)",
    ),
    Rule(
        rule_id="FURB104",
        name="unnecessary-list-sorted",
        description="Unnecessary list() wrapper around sorted()",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove list() - sorted() already returns a list",
    ),
    Rule(
        rule_id="FURB105",
        name="print-sep-empty",
        description="Use ''.join() instead of print() with sep=''",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using ''.join() for string concatenation instead of print()",
    ),
    Rule(
        rule_id="FURB106",
        name="string-paths-with-open",
        description="Consider using pathlib.Path instead of string paths",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use Path objects from pathlib for better path handling",
    ),
    Rule(
        rule_id="FURB107",
        name="version-info-tuple",
        description="Use full version tuple for sys.version_info comparisons",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use (major, minor, micro) format for version comparisons",
    ),
    Rule(
        rule_id="FURB108",
        name="os-path-to-pathlib",
        description="Use pathlib.Path instead of os.path operations",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using pathlib.Path for better path handling",
    ),
]
