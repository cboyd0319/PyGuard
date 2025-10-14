"""
PIE (flake8-pie) - Code smell detection and unnecessary pattern detection.

This module implements detection for common code smells and unnecessary patterns
that reduce code quality and maintainability.

References:
- flake8-pie: https://github.com/sbdchd/flake8-pie
- Ruff PIE rules: https://docs.astral.sh/ruff/rules/#flake8-pie-pie
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


class PIEPatternVisitor(ast.NodeVisitor):
    """AST visitor for detecting code smells and unnecessary patterns."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []

    def visit_Pass(self, node: ast.Pass) -> None:
        """Detect unnecessary pass statements (PIE790)."""
        # Check if pass is the only statement in a block
        # This requires checking parent nodes, which we'll handle in post-processing
        self.violations.append(
            RuleViolation(
                rule_id="PIE790",
                message="Unnecessary pass statement",
                line_number=node.lineno,
                column=node.col_offset,
                severity=RuleSeverity.LOW,
                category=RuleCategory.STYLE,
                file_path=self.file_path,
                fix_applicability=FixApplicability.SAFE,
            )
        )
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        """Detect unnecessary ellipsis and other expression statements (PIE791, PIE800)."""
        # PIE791: Unnecessary ellipsis
        if isinstance(node.value, ast.Constant) and node.value.value == ...:
            self.violations.append(
                RuleViolation(
                    rule_id="PIE791",
                    message="Unnecessary ... (ellipsis) statement",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.STYLE,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

        # PIE800: Unnecessary spread operator
        if isinstance(node.value, ast.Starred):
            self.violations.append(
                RuleViolation(
                    rule_id="PIE800",
                    message="Unnecessary spread (*) operator",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.STYLE,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect comparison patterns that should use 'is' (PIE792, PIE793)."""
        # PIE792: Prefer 'is False' over '== False'
        for i, (op, comparator) in enumerate(zip(node.ops, node.comparators)):
            if isinstance(op, ast.Eq) and isinstance(comparator, ast.Constant):
                if comparator.value is False:
                    self.violations.append(
                        RuleViolation(
                            rule_id="PIE792",
                            message="Use 'is False' instead of '== False'",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )
                # PIE793: Prefer 'is True' over '== True'
                elif comparator.value is True:
                    self.violations.append(
                        RuleViolation(
                            rule_id="PIE793",
                            message="Use 'is True' instead of '== True'",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Detect classes with only __init__ (PIE794)."""
        # Check if class has only __init__ method
        methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
        if len(methods) == 1 and methods[0].name == "__init__":
            self.violations.append(
                RuleViolation(
                    rule_id="PIE794",
                    message="Class with only __init__ - consider using a function or dataclass",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.DESIGN,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Detect function-related code smells (PIE795, PIE796, PIE798, PIE799)."""
        # PIE795: Prefer 'pass' over '...' in function body
        if len(node.body) == 1 and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant) and node.body[0].value.value == ...:
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE795",
                        message="Prefer 'pass' over '...' in function body",
                        line_number=node.body[0].lineno,
                        column=node.body[0].col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # PIE796: Unnecessary dict() call
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Name) and stmt.func.id == "dict":
                    if not stmt.args and all(isinstance(k, ast.keyword) for k in stmt.keywords):
                        self.violations.append(
                            RuleViolation(
                                rule_id="PIE796",
                                message="Prefer dict literal {} over dict() call",
                                line_number=stmt.lineno,
                                column=stmt.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.STYLE,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

        # PIE798: Unnecessary __future__ import with no effect
        # This is handled separately

        # PIE799: Unnecessary dict comprehension with .items()
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.DictComp):
                if isinstance(stmt.value, ast.Name) and isinstance(stmt.key, ast.Name):
                    # Check if iterating over .items()
                    if isinstance(stmt.generators[0].iter, ast.Call):
                        call = stmt.generators[0].iter
                        if isinstance(call.func, ast.Attribute) and call.func.attr == "items":
                            self.violations.append(
                                RuleViolation(
                                    rule_id="PIE799",
                                    message="Unnecessary dict comprehension over .items()",
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.PERFORMANCE,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SUGGESTED,
                                )
                            )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect call-related code smells (PIE797, PIE801, PIE804)."""
        # PIE797: Unnecessary list comprehension
        if isinstance(node.func, ast.Name) and node.func.id == "list":
            if len(node.args) == 1 and isinstance(node.args[0], ast.ListComp):
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE797",
                        message="Unnecessary list comprehension - list() already creates a list",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # PIE801: Lambda that just returns a function call
        if isinstance(node.func, ast.Lambda):
            if isinstance(node.func.body, ast.Call):
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE801",
                        message="Lambda that just calls a function - use the function directly",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # PIE804: Unnecessary dict.keys() in loop
        if isinstance(node.func, ast.Name) and node.func.id in ("list", "tuple", "set"):
            if len(node.args) == 1 and isinstance(node.args[0], ast.Call):
                inner = node.args[0]
                if isinstance(inner.func, ast.Attribute) and inner.func.attr == "keys":
                    self.violations.append(
                        RuleViolation(
                            rule_id="PIE804",
                            message="Unnecessary .keys() call - iterate over dict directly",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.PERFORMANCE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Detect if-related code smells (PIE807, PIE808)."""
        # PIE807: Prefer 'or' over single-item 'in' check
        if isinstance(node.test, ast.Compare):
            if len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.In):
                if isinstance(node.test.comparators[0], (ast.List, ast.Tuple)):
                    if len(node.test.comparators[0].elts) == 1:
                        self.violations.append(
                            RuleViolation(
                                rule_id="PIE807",
                                message="Prefer '==' over 'in [...]' for single item",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.SIMPLIFICATION,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

        # PIE808: Unnecessary 'else' after 'return'
        if node.orelse:
            # Check if if-block ends with return
            if node.body and isinstance(node.body[-1], ast.Return):
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE808",
                        message="Unnecessary 'else' after 'return' - remove the else",
                        line_number=node.orelse[0].lineno if node.orelse else node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        self.generic_visit(node)


class PIEPatternChecker:
    """Main checker for PIE pattern detection and fixes."""

    def __init__(self):
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a Python file for code smells and unnecessary patterns.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            tree = ast.parse(code)
            visitor = PIEPatternVisitor(file_path, code)
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
        Automatically fix code smells in a file.

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

            # Fix PIE792: == False -> is False
            pattern = r"==\s*False"
            matches = list(re.finditer(pattern, code))
            for match in reversed(matches):  # Reverse to maintain positions
                code = code[:match.start()] + "is False" + code[match.end():]
                fixes_applied += 1

            # Fix PIE793: == True -> is True
            pattern = r"==\s*True"
            matches = list(re.finditer(pattern, code))
            for match in reversed(matches):
                code = code[:match.start()] + "is True" + code[match.end():]
                fixes_applied += 1

            # Fix PIE796: dict(...) -> {...}
            # This is complex and requires AST manipulation
            # We'll implement this in a future iteration

            if fixes_applied > 0:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(code)

                self.logger.info(
                    f"Fixed {fixes_applied} code smells",
                    file_path=str(file_path),
                )
                return True, fixes_applied

            return True, 0

        except Exception as e:
            self.logger.error(f"Error fixing file: {e}", file_path=str(file_path))
            return False, 0


# Define rules for registration
PIE_RULES = [
    Rule(
        rule_id="PIE790",
        name="unnecessary-pass",
        description="Unnecessary pass statement",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove unnecessary pass statement",
    ),
    Rule(
        rule_id="PIE791",
        name="unnecessary-ellipsis",
        description="Unnecessary ellipsis (...) statement",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove unnecessary ellipsis",
    ),
    Rule(
        rule_id="PIE792",
        name="is-false-comparison",
        description="Prefer 'is False' over '== False'",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use 'is False' instead of '== False'",
    ),
    Rule(
        rule_id="PIE793",
        name="is-true-comparison",
        description="Prefer 'is True' over '== True'",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use 'is True' instead of '== True'",
    ),
    Rule(
        rule_id="PIE794",
        name="class-with-only-init",
        description="Class with only __init__ method",
        category=RuleCategory.DESIGN,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using a function or dataclass instead of a class with only __init__",
    ),
    Rule(
        rule_id="PIE795",
        name="prefer-pass-over-ellipsis",
        description="Prefer 'pass' over '...' in function body",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use 'pass' instead of '...' for empty function bodies",
    ),
    Rule(
        rule_id="PIE796",
        name="prefer-dict-literal",
        description="Prefer dict literal over dict() call",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use {} instead of dict() for empty or keyword-only dicts",
    ),
    Rule(
        rule_id="PIE797",
        name="unnecessary-list-comp",
        description="Unnecessary list comprehension with list()",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove list() wrapper - list comprehension already creates a list",
    ),
    Rule(
        rule_id="PIE799",
        name="unnecessary-dict-comp",
        description="Unnecessary dict comprehension over .items()",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use dict() constructor or dict literal instead",
    ),
    Rule(
        rule_id="PIE800",
        name="unnecessary-spread",
        description="Unnecessary spread (*) operator",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Remove unnecessary spread operator",
    ),
    Rule(
        rule_id="PIE801",
        name="lambda-function-call",
        description="Lambda that just calls a function",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use the function directly instead of wrapping in lambda",
    ),
    Rule(
        rule_id="PIE804",
        name="unnecessary-dict-keys",
        description="Unnecessary .keys() call",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Iterate over dict directly instead of calling .keys()",
    ),
    Rule(
        rule_id="PIE807",
        name="prefer-equality",
        description="Prefer '==' over 'in [...]' for single item",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use '==' instead of 'in [single_item]'",
    ),
    Rule(
        rule_id="PIE808",
        name="unnecessary-else-after-return",
        description="Unnecessary 'else' after 'return'",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Remove 'else' after 'return' - code can be dedented",
    ),
]
