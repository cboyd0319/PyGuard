"""
Return Pattern Analysis Module

Implements Ruff RET rules for detecting suboptimal return patterns.
"""

import ast
from pathlib import Path
from typing import List, Optional

from .rule_engine import Rule, RuleCategory, RuleSeverity, RuleViolation


class ReturnPatternVisitor(ast.NodeVisitor):
    """AST visitor for detecting return pattern issues."""

    def __init__(self, file_path: Path = Path("<string>")):
        self.violations: List[RuleViolation] = []
        self.current_function: Optional[ast.FunctionDef] = None
        self.file_path = file_path

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions to analyze return patterns."""
        old_function = self.current_function
        self.current_function = node

        # Check for RET501: Unnecessary explicit return None
        self._check_unnecessary_return_none(node)

        # Check for RET502: Implicit return mixed with explicit
        self._check_implicit_return_mixed(node)

        # Check for RET503: Missing explicit return
        self._check_missing_explicit_return(node)

        # Check for RET504: Unnecessary variable assignment before return
        self._check_unnecessary_assignment_before_return(node)

        # Check for RET505: Unnecessary else after return
        self._check_unnecessary_else_after_return(node)

        # Check for RET506: Unnecessary elif after return
        self._check_unnecessary_elif_after_return(node)

        # Check for RET507: Unnecessary else after continue
        self._check_unnecessary_else_after_continue(node)

        # Check for RET508: Unnecessary else after break
        self._check_unnecessary_else_after_break(node)

        self.generic_visit(node)
        self.current_function = old_function

    def _check_unnecessary_return_none(self, node: ast.FunctionDef) -> None:
        """RET501: Check for explicit 'return None' that can be simplified."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                if stmt.value.value is None:
                    self.violations.append(
                        RuleViolation(
                            rule_id="RET501",
                            message="Do not explicitly return None, implicit return is sufficient",
                            line_number=stmt.lineno,
                            column=stmt.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.REFACTOR,
                            file_path=self.file_path,
                            fix_suggestion="Remove 'return None' or use bare 'return'",
                        )
                    )

    def _check_implicit_return_mixed(self, node: ast.FunctionDef) -> None:
        """RET502: Check for mixing implicit and explicit return values."""
        has_explicit_value = False
        has_implicit_return = False
        has_bare_return = False

        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Return):
                if stmt.value is None:
                    has_bare_return = True
                elif not (isinstance(stmt.value, ast.Constant) and stmt.value.value is None):
                    has_explicit_value = True

        # Check if function ends without explicit return
        if node.body and not isinstance(node.body[-1], ast.Return):
            has_implicit_return = True

        if has_explicit_value and (has_implicit_return or has_bare_return):
            self.violations.append(
                RuleViolation(
                    rule_id="RET502",
                    message="Do not implicitly return None in function capable of returning non-None value",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.ERROR,
                    file_path=self.file_path,
                    fix_suggestion="Add explicit 'return None' or 'return' statement",
                )
            )

    def _check_missing_explicit_return(self, node: ast.FunctionDef) -> None:
        """RET503: Check for missing explicit return in function."""
        # Skip if function is empty or only has docstring/pass
        if not node.body:
            return

        # Skip if function only has pass statement
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            return

        # Skip if function only has docstring
        if len(node.body) == 1 and isinstance(node.body[0], ast.Expr):
            return

        # Skip if function already has return statements
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Return):
                return

        # Skip if function only raises exceptions
        only_raises = all(isinstance(stmt, (ast.Raise, ast.Expr, ast.Pass)) for stmt in node.body)
        if only_raises:
            return

        self.violations.append(
            RuleViolation(
                rule_id="RET503",
                message="Function with implicit return should have explicit 'return None'",
                line_number=node.lineno,
                column=node.col_offset,
                severity=RuleSeverity.LOW,
                category=RuleCategory.CONVENTION,
                file_path=self.file_path,
                fix_suggestion="Add 'return None' at end of function",
            )
        )

    def _check_unnecessary_assignment_before_return(self, node: ast.FunctionDef) -> None:
        """RET504: Check for unnecessary variable assignment before return."""
        for i, stmt in enumerate(node.body[:-1]):
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name):
                    # Check if next statement is return with same variable
                    next_stmt = node.body[i + 1]
                    if isinstance(next_stmt, ast.Return) and isinstance(next_stmt.value, ast.Name):
                        if next_stmt.value.id == target.id:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="RET504",
                                    message=f"Unnecessary assignment to '{target.id}' before return",
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.REFACTOR,
                                    file_path=self.file_path,
                                    fix_suggestion=f"Return the expression directly instead of assigning to '{target.id}'",
                                )
                            )

    def _check_unnecessary_else_after_return(self, node: ast.FunctionDef) -> None:
        """RET505: Check for unnecessary else after return."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.If) and stmt.orelse:
                # Check if all branches in if/elif end with return
                if_ends_with_return = self._branch_ends_with_return(stmt.body)

                if if_ends_with_return and stmt.orelse:
                    # Check if it's an elif or else
                    first_else = stmt.orelse[0]
                    if not isinstance(first_else, ast.If):  # It's an else block
                        self.violations.append(
                            RuleViolation(
                                rule_id="RET505",
                                message="Unnecessary else after return statement",
                                line_number=(
                                    first_else.lineno
                                    if hasattr(first_else, "lineno")
                                    else stmt.lineno
                                ),
                                column=(
                                    first_else.col_offset
                                    if hasattr(first_else, "col_offset")
                                    else stmt.col_offset
                                ),
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Remove else and unindent its body",
                            )
                        )

    def _check_unnecessary_elif_after_return(self, node: ast.FunctionDef) -> None:
        """RET506: Check for unnecessary elif after return."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.If) and stmt.orelse:
                if_ends_with_return = self._branch_ends_with_return(stmt.body)

                if if_ends_with_return and stmt.orelse:
                    first_else = stmt.orelse[0]
                    if isinstance(first_else, ast.If):  # It's an elif
                        self.violations.append(
                            RuleViolation(
                                rule_id="RET506",
                                message="Unnecessary elif after return statement",
                                line_number=first_else.lineno,
                                column=first_else.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace elif with if since previous branch returns",
                            )
                        )

    def _check_unnecessary_else_after_continue(self, node: ast.FunctionDef) -> None:
        """RET507: Check for unnecessary else after continue."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.If) and stmt.orelse:
                if_ends_with_continue = self._branch_ends_with_continue(stmt.body)

                if if_ends_with_continue:
                    first_else = stmt.orelse[0]
                    if not isinstance(first_else, ast.If):
                        self.violations.append(
                            RuleViolation(
                                rule_id="RET507",
                                message="Unnecessary else after continue statement",
                                line_number=(
                                    first_else.lineno
                                    if hasattr(first_else, "lineno")
                                    else stmt.lineno
                                ),
                                column=(
                                    first_else.col_offset
                                    if hasattr(first_else, "col_offset")
                                    else stmt.col_offset
                                ),
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Remove else and unindent its body",
                            )
                        )

    def _check_unnecessary_else_after_break(self, node: ast.FunctionDef) -> None:
        """RET508: Check for unnecessary else after break."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.If) and stmt.orelse:
                if_ends_with_break = self._branch_ends_with_break(stmt.body)

                if if_ends_with_break:
                    first_else = stmt.orelse[0]
                    if not isinstance(first_else, ast.If):
                        self.violations.append(
                            RuleViolation(
                                rule_id="RET508",
                                message="Unnecessary else after break statement",
                                line_number=(
                                    first_else.lineno
                                    if hasattr(first_else, "lineno")
                                    else stmt.lineno
                                ),
                                column=(
                                    first_else.col_offset
                                    if hasattr(first_else, "col_offset")
                                    else stmt.col_offset
                                ),
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Remove else and unindent its body",
                            )
                        )

    def _branch_ends_with_return(self, body: List[ast.stmt]) -> bool:
        """Check if a branch ends with a return statement."""
        if not body:
            return False
        last_stmt = body[-1]
        return isinstance(last_stmt, ast.Return)

    def _branch_ends_with_continue(self, body: List[ast.stmt]) -> bool:
        """Check if a branch ends with a continue statement."""
        if not body:
            return False
        last_stmt = body[-1]
        return isinstance(last_stmt, ast.Continue)

    def _branch_ends_with_break(self, body: List[ast.stmt]) -> bool:
        """Check if a branch ends with a break statement."""
        if not body:
            return False
        last_stmt = body[-1]
        return isinstance(last_stmt, ast.Break)


class ReturnPatternChecker:
    """Main checker for return pattern issues."""

    def __init__(self):
        self.rules = self._create_rules()

    def _create_rules(self) -> List[Rule]:
        """Create return pattern rules."""
        from .rule_engine import FixApplicability, Rule, RuleCategory, RuleSeverity

        return [
            Rule(
                rule_id="RET501",
                name="unnecessary-return-none",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Do not explicitly return None",
                description="Use implicit return or bare return instead of explicit 'return None'",
                fix_applicability=FixApplicability.SUGGESTED,
            ),
            Rule(
                rule_id="RET502",
                name="implicitly-returns-none",
                category=RuleCategory.ERROR,
                severity=RuleSeverity.MEDIUM,
                message_template="Do not implicitly return None in function with non-None returns",
                description="Mixing implicit and explicit return values can be confusing",
                fix_applicability=FixApplicability.SUGGESTED,
            ),
            Rule(
                rule_id="RET503",
                name="missing-explicit-return",
                category=RuleCategory.CONVENTION,
                severity=RuleSeverity.LOW,
                message_template="Missing explicit return at end of function",
                description="Functions should have explicit return statements for clarity",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="RET504",
                name="unnecessary-assignment",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary variable assignment before return",
                description="Return the expression directly instead of assigning to a variable",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="RET505",
                name="superfluous-else-return",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary else after return",
                description="Remove else clause and unindent its body when previous branch returns",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="RET506",
                name="superfluous-elif-return",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary elif after return",
                description="Replace elif with if when previous branch returns",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="RET507",
                name="superfluous-else-continue",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary else after continue",
                description="Remove else clause when previous branch continues",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="RET508",
                name="superfluous-else-break",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary else after break",
                description="Remove else clause when previous branch breaks",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
        ]

    def check_code(self, code: str, filename: str = "<string>") -> List[RuleViolation]:
        """
        Check code for return pattern issues.

        Args:
            code: Python source code to analyze
            filename: Name of the file being analyzed

        Returns:
            List of RuleViolation objects
        """
        try:
            tree = ast.parse(code)
            visitor = ReturnPatternVisitor(file_path=Path(filename))
            visitor.visit(tree)
            return visitor.violations
        except SyntaxError:
            return []

    def get_rules(self) -> List[Rule]:
        """Get all rules defined by this checker."""
        return self.rules
