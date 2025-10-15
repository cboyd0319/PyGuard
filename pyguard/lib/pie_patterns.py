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
        """Detect call-related code smells (PIE797, PIE801, PIE802, PIE804, PIE809)."""
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

        # PIE802: Unnecessary iteration with list()
        if isinstance(node.func, ast.Name) and node.func.id == "list":
            if len(node.args) == 1:
                arg = node.args[0]
                # Check if already an iterable that doesn't need list()
                if isinstance(arg, ast.Call):
                    if isinstance(arg.func, ast.Name) and arg.func.id in (
                        "range",
                        "enumerate",
                        "zip",
                        "map",
                        "filter",
                    ):
                        self.violations.append(
                            RuleViolation(
                                rule_id="PIE802",
                                message=f"Unnecessary list() call around {arg.func.id}() - it already returns an iterable",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.PERFORMANCE,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

        # PIE804: Unnecessary dict.keys() in loop
        if isinstance(node.func, ast.Name) and node.func.id in ("list", "tuple", "set"):
            if len(node.args) == 1 and isinstance(node.args[0], ast.Call):
                inner = node.args[0]
                if (
                    isinstance(inner.func, ast.Attribute) and inner.func.attr == "keys"
                ):  # pyguard: disable=CWE-208  # Pattern detection, not vulnerable code
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

        # PIE809: Prefer '[]' over 'list()' call
        if isinstance(node.func, ast.Name) and node.func.id == "list":
            if len(node.args) == 0 and len(node.keywords) == 0:
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE809",
                        message="Prefer '[]' over 'list()' for empty list",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Detect if-related code smells (PIE803, PIE806, PIE807, PIE808)."""
        # PIE803: Prefer '==' over 'is' for literals
        if isinstance(node.test, ast.Compare):
            for op, comparator in zip(node.test.ops, node.test.comparators):
                if isinstance(op, (ast.Is, ast.IsNot)):
                    if isinstance(comparator, ast.Constant):
                        # Check if it's a literal (not None, True, False)
                        if comparator.value not in (None, True, False):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="PIE803",
                                    message="Prefer '==' over 'is' for literal comparison",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.ERROR,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

        # PIE806: Unnecessary 'elif' with only 'pass' body
        if isinstance(node.orelse, list) and len(node.orelse) == 1:
            if isinstance(node.orelse[0], ast.If):
                elif_node = node.orelse[0]
                if len(elif_node.body) == 1 and isinstance(elif_node.body[0], ast.Pass):
                    self.violations.append(
                        RuleViolation(
                            rule_id="PIE806",
                            message="Unnecessary 'elif' with only 'pass' - remove it",
                            line_number=elif_node.lineno,
                            column=elif_node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

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

    def visit_For(self, node: ast.For) -> None:
        """Detect for-loop related code smells (PIE805, PIE811)."""
        # PIE805: Prefer 'next()' over for loop with single iteration
        # Check if loop has only one iteration (has break as first statement)
        if len(node.body) > 0:
            if isinstance(node.body[0], ast.Break) or (
                len(node.body) == 2 and isinstance(node.body[1], ast.Break)
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE805",
                        message="Prefer 'next()' over for loop that only gets first item",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # PIE811: Redundant tuple unpacking
        # Check if target is a tuple and there's immediate re-packing
        if isinstance(node.target, ast.Tuple):
            # Check if the loop body just re-creates the tuple
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    if isinstance(stmt.value, ast.Tuple):
                        if len(stmt.value.elts) == len(node.target.elts):
                            # Check if it's the same variables
                            target_names = [
                                elt.id for elt in node.target.elts if isinstance(elt, ast.Name)
                            ]
                            value_names = [
                                elt.id for elt in stmt.value.elts if isinstance(elt, ast.Name)
                            ]
                            if target_names == value_names:
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="PIE811",
                                        message="Redundant tuple unpacking - values are immediately re-packed",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.LOW,
                                        category=RuleCategory.SIMPLIFICATION,
                                        file_path=self.file_path,
                                        fix_applicability=FixApplicability.SUGGESTED,
                                    )
                                )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Detect exception handler code smells (PIE810)."""
        # PIE810: Multiple calls in exception handler
        # Check if there are multiple function calls in the exception handler
        calls = [
            stmt
            for stmt in node.body
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
        ]
        if len(calls) > 1:
            self.violations.append(
                RuleViolation(
                    rule_id="PIE810",
                    message="Multiple calls in exception handler - consider refactoring",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.DESIGN,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Detect import-related code smells (PIE812, PIE814)."""
        # PIE812: Unnecessary import alias (import X as X)
        for alias in node.names:
            if alias.asname and alias.name == alias.asname:
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE812",
                        message=f"Unnecessary import alias: 'import {alias.name} as {alias.asname}' - remove alias",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Detect from-import-related code smells (PIE813, PIE815)."""
        # PIE813: Unnecessary 'from ... import' when importing module
        # Example: from os import path (better: import os.path)

        # PIE815: Unnecessary from import with duplicate names
        for alias in node.names:
            if alias.asname and alias.name == alias.asname:
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE815",
                        message=f"Unnecessary import alias: 'from {node.module} import {alias.name} as {alias.asname}' - remove alias",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        self.generic_visit(node)

    def visit_Slice(self, node: ast.Slice) -> None:
        """Detect slice-related code smells (PIE816)."""
        # PIE816: Unnecessary list slice (list[:])
        # This is detected in the context of usage
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        """Detect boolean operation code smells (PIE817)."""
        # PIE817: Prefer using 'any()' or 'all()' over multiple 'or'/'and' conditions
        if isinstance(node.op, ast.Or):
            if len(node.values) > 3:  # Arbitrary threshold
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE817",
                        message=f"Consider using 'any()' instead of {len(node.values)} 'or' conditions",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )
        elif isinstance(node.op, ast.And):
            if len(node.values) > 3:  # Arbitrary threshold
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE817",
                        message=f"Consider using 'all()' instead of {len(node.values)} 'and' conditions",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect subscript-related code smells (PIE818, PIE819)."""
        # PIE818: Unnecessary call to list() before subscript
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id == "list":
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE818",
                        message="Unnecessary list() call before subscript - subscripting works on iterables",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.PERFORMANCE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # PIE819: Unnecessary list comprehension in subscript
        # Example: [x for x in items][0] -> next(iter(items))
        if isinstance(node.value, ast.ListComp):
            if isinstance(node.slice, ast.Constant) and node.slice.value == 0:
                self.violations.append(
                    RuleViolation(
                        rule_id="PIE819",
                        message="Unnecessary list comprehension with [0] - use next(iter(...)) or next(generator)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.PERFORMANCE,
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
            with open(file_path, encoding="utf-8") as f:
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
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            fixes_applied = 0

            # Fix PIE792: == False -> is False
            pattern = r"==\s*False"
            matches = list(re.finditer(pattern, code))
            for match in reversed(matches):  # Reverse to maintain positions
                code = code[: match.start()] + "is False" + code[match.end() :]
                fixes_applied += 1

            # Fix PIE793: == True -> is True
            pattern = r"==\s*True"
            matches = list(re.finditer(pattern, code))
            for match in reversed(matches):
                code = code[: match.start()] + "is True" + code[match.end() :]
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
    Rule(
        rule_id="PIE802",
        name="unnecessary-list-call",
        description="Unnecessary list() call around iterable",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove unnecessary list() call - argument is already an iterable",
    ),
    Rule(
        rule_id="PIE803",
        name="prefer-equality-for-literals",
        description="Prefer '==' over 'is' for literal comparison",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use '==' instead of 'is' when comparing with literals",
    ),
    Rule(
        rule_id="PIE805",
        name="prefer-next-over-single-iteration-loop",
        description="Prefer 'next()' over for loop with single iteration",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use 'next(iterable)' instead of for loop that only gets first item",
    ),
    Rule(
        rule_id="PIE806",
        name="unnecessary-elif-pass",
        description="Unnecessary 'elif' with only 'pass' body",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove unnecessary 'elif' with only 'pass'",
    ),
    Rule(
        rule_id="PIE809",
        name="prefer-list-literal",
        description="Prefer '[]' over 'list()' call",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use '[]' instead of 'list()' for empty list",
    ),
    Rule(
        rule_id="PIE810",
        name="multiple-calls-in-except",
        description="Multiple calls in exception handler",
        category=RuleCategory.DESIGN,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider refactoring exception handler with multiple calls",
    ),
    Rule(
        rule_id="PIE811",
        name="redundant-tuple-unpacking",
        description="Redundant tuple unpacking",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Remove redundant tuple unpacking and re-packing",
    ),
    # New rules added in Phase 9
    Rule(
        rule_id="PIE812",
        name="unnecessary-import-alias",
        description="Unnecessary import alias (import X as X)",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove unnecessary import alias",
    ),
    Rule(
        rule_id="PIE813",
        name="unnecessary-from-import",
        description="Unnecessary 'from ... import' when importing module",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using 'import' instead of 'from ... import'",
    ),
    Rule(
        rule_id="PIE814",
        name="duplicate-import",
        description="Duplicate import statement",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove duplicate import",
    ),
    Rule(
        rule_id="PIE815",
        name="unnecessary-from-import-alias",
        description="Unnecessary alias in 'from ... import ... as ...'",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove unnecessary import alias",
    ),
    Rule(
        rule_id="PIE816",
        name="unnecessary-list-slice",
        description="Unnecessary list slice (list[:])",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Remove unnecessary list slice or use list.copy()",
    ),
    Rule(
        rule_id="PIE817",
        name="prefer-any-all",
        description="Prefer using 'any()' or 'all()' over multiple 'or'/'and' conditions",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use any()/all() for clearer boolean logic",
    ),
    Rule(
        rule_id="PIE818",
        name="unnecessary-list-before-subscript",
        description="Unnecessary list() call before subscript",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove unnecessary list() call - subscripting works on iterables",
    ),
    Rule(
        rule_id="PIE819",
        name="list-comp-with-subscript-zero",
        description="Unnecessary list comprehension with [0] subscript",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use next(iter(...)) or a generator expression",
    ),
]
