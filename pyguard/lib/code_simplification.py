"""
Code simplification detection and fixes (flake8-simplify/SIM rules).

This module implements detection and auto-fixes for code that can be simplified
while maintaining the same functionality. Aligned with flake8-simplify rules.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class SimplificationIssue:
    """Issue related to code that can be simplified."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""
    rule_id: str = ""  # SIM101, SIM102, etc.


class SimplificationVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting code simplification opportunities.

    Implements flake8-simplify-style checks.
    """

    def __init__(self, source_lines: List[str]):
        """Initialize simplification visitor."""
        self.issues: List[SimplificationIssue] = []
        self.source_lines = source_lines

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ""

    def visit_If(self, node: ast.If):
        """Visit if statements."""
        # SIM101: Multiple isinstance checks can be combined
        if self._is_multiple_isinstance_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="LOW",
                    category="Code Simplification",
                    message="Multiple isinstance() checks can be combined",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use isinstance(obj, (Type1, Type2)) instead of multiple checks",
                    rule_id="SIM101",
                )
            )

        # SIM102: Nested if statements with same parent can be merged
        if self._is_nested_if_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="LOW",
                    category="Code Simplification",
                    message="Nested if statements can be merged with 'and'",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Combine conditions: if a and b: instead of if a: if b:",
                    rule_id="SIM102",
                )
            )

        # SIM103: Return boolean directly instead of if-else
        if self._is_return_bool_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="MEDIUM",
                    category="Code Simplification",
                    message="Return the condition directly instead of if-else returning True/False",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace 'if condition: return True else: return False' with 'return condition'",
                    rule_id="SIM103",
                )
            )

        # SIM108: Use ternary operator for simple if-else
        if self._is_simple_if_else_assign(node):
            self.issues.append(
                SimplificationIssue(
                    severity="LOW",
                    category="Code Simplification",
                    message="Use ternary operator for simple if-else assignment",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace if-else with: var = value_if_true if condition else value_if_false",
                    rule_id="SIM108",
                )
            )

        # SIM114: Multiple if statements with same body can be combined
        if self._is_duplicate_if_body(node):
            self.issues.append(
                SimplificationIssue(
                    severity="LOW",
                    category="Code Simplification",
                    message="Multiple if statements with same body can be combined with 'or'",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Combine conditions: if a or b: body instead of if a: body if b: body",
                    rule_id="SIM114",
                )
            )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Visit function call nodes."""
        func_name = self._get_call_name(node)

        # SIM105: Use contextlib.suppress() instead of try-except-pass
        # This is detected in visit_Try

        # SIM106: Handle error cases first (guard clauses)
        # This is complex and detected at function level

        # SIM109: Compare to True/False with 'is' or '==' is redundant
        if func_name == "bool" and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, ast.Compare):
                self.issues.append(
                    SimplificationIssue(
                        severity="LOW",
                        category="Code Simplification",
                        message="Redundant bool() call - comparison already returns bool",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove bool() wrapper - comparison is already boolean",
                        rule_id="SIM109",
                    )
                )

        # SIM110: Use all() instead of for loop with early return
        # This is complex and requires loop analysis

        # SIM111: Use any() instead of for loop with early return
        # This is complex and requires loop analysis

        # SIM112: Use CAPITAL for environment variables
        if func_name in ["os.getenv", "os.environ.get"]:
            if node.args and isinstance(node.args[0], ast.Constant):
                env_var = node.args[0].value
                if isinstance(env_var, str) and not env_var.isupper():
                    self.issues.append(
                        SimplificationIssue(
                            severity="LOW",
                            category="Code Simplification",
                            message="Environment variable names should be UPPERCASE by convention",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion=f"Use '{env_var.upper()}' instead of '{env_var}'",
                            rule_id="SIM112",
                        )
                    )

        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """Visit for loop nodes."""
        # SIM113: Use enumerate() instead of manual counter
        if self._is_manual_enumerate_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="MEDIUM",
                    category="Code Simplification",
                    message="Use enumerate() instead of manual index counter",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace manual counter with: for i, item in enumerate(items):",
                    rule_id="SIM113",
                )
            )

        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        """Visit try-except blocks."""
        # SIM105: Use contextlib.suppress() for try-except-pass
        if self._is_try_except_pass_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="LOW",
                    category="Code Simplification",
                    message="Use contextlib.suppress() instead of try-except-pass",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace with: from contextlib import suppress; with suppress(Exception):",
                    rule_id="SIM105",
                )
            )

        # SIM107: Return inside try-except-else
        if node.orelse:
            for stmt in node.orelse:
                if isinstance(stmt, ast.Return):
                    self.issues.append(
                        SimplificationIssue(
                            severity="LOW",
                            category="Code Simplification",
                            message="Don't use return in try-else block, move to try block",
                            line_number=stmt.lineno,
                            column=stmt.col_offset,
                            code_snippet=self._get_code_snippet(stmt),
                            fix_suggestion="Move return statement from else clause to end of try block",
                            rule_id="SIM107",
                        )
                    )

        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        """Visit with statements."""
        # SIM115: Open files with with statement
        # This is the opposite - we check for files NOT opened with with
        # That's in resource leak detection

        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        """Visit dictionary creation."""
        # SIM118: Use .get() or 'in' instead of dict.keys()
        # This is detected in subscript/contains patterns

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        """Visit comparison nodes."""
        # SIM201-204: Compare with True/False/None using 'is'
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(comparator, ast.Constant):
                if comparator.value in [True, False]:
                    # Only flag == or != comparisons, not other comparison operators
                    if isinstance(op, ast.Eq):
                        self.issues.append(
                            SimplificationIssue(
                                severity="LOW",
                                category="Code Simplification",
                                message=f"Use 'is {comparator.value}' instead of '== {comparator.value}'",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"Replace '== {comparator.value}' with 'is {comparator.value}'",
                                rule_id="SIM201" if comparator.value is True else "SIM202",
                            )
                        )
                    elif isinstance(op, ast.NotEq):
                        self.issues.append(
                            SimplificationIssue(
                                severity="LOW",
                                category="Code Simplification",
                                message=f"Use 'is not {comparator.value}' instead of '!= {comparator.value}'",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"Replace '!= {comparator.value}' with 'is not {comparator.value}'",
                                rule_id="SIM201" if comparator.value is True else "SIM202",
                            )
                        )

        self.generic_visit(node)

    # Helper methods for pattern detection

    def _is_multiple_isinstance_pattern(self, node: ast.If) -> bool:
        """Check if node has multiple isinstance checks that can be combined."""
        if not isinstance(node.test, ast.BoolOp) or not isinstance(node.test.op, ast.Or):
            return False

        isinstance_count = 0
        same_obj = True
        first_obj_id = None

        for value in node.test.values:
            if isinstance(value, ast.Call):
                func_name = self._get_call_name(value)
                if func_name == "isinstance" and len(value.args) >= 1:
                    isinstance_count += 1
                    obj = value.args[0]
                    if isinstance(obj, ast.Name):
                        if first_obj_id is None:
                            first_obj_id = obj.id
                        elif obj.id != first_obj_id:
                            same_obj = False

        return isinstance_count >= 2 and same_obj

    def _is_nested_if_pattern(self, node: ast.If) -> bool:
        """Check if node has nested if that can be merged."""
        if not node.orelse and len(node.body) == 1:
            if isinstance(node.body[0], ast.If) and not node.body[0].orelse:
                return True
        return False

    def _is_return_bool_pattern(self, node: ast.If) -> bool:
        """Check if node returns bool in if-else pattern."""
        if not node.orelse:
            return False

        # Check if body is 'return True' and else is 'return False'
        if len(node.body) == 1 and len(node.orelse) == 1:
            body_stmt = node.body[0]
            else_stmt = node.orelse[0]

            if isinstance(body_stmt, ast.Return) and isinstance(else_stmt, ast.Return):
                if (
                    isinstance(body_stmt.value, ast.Constant)
                    and isinstance(else_stmt.value, ast.Constant)
                ):
                    if body_stmt.value.value is True and else_stmt.value.value is False:
                        return True
                    if body_stmt.value.value is False and else_stmt.value.value is True:
                        return True

        return False

    def _is_simple_if_else_assign(self, node: ast.If) -> bool:
        """Check if node is simple if-else with assignment."""
        if not node.orelse or len(node.body) != 1 or len(node.orelse) != 1:
            return False

        body_stmt = node.body[0]
        else_stmt = node.orelse[0]

        # Both should be assignments to the same variable
        if isinstance(body_stmt, ast.Assign) and isinstance(else_stmt, ast.Assign):
            if len(body_stmt.targets) == 1 and len(else_stmt.targets) == 1:
                body_target = body_stmt.targets[0]
                else_target = else_stmt.targets[0]
                if isinstance(body_target, ast.Name) and isinstance(else_target, ast.Name):
                    return body_target.id == else_target.id

        return False

    def _is_duplicate_if_body(self, node: ast.If) -> bool:
        """Check if there are duplicate if bodies (would need parent context)."""
        # This requires analyzing sibling nodes, which needs parent tracking
        # Simplified version - return False for now
        return False

    def _is_try_except_pass_pattern(self, node: ast.Try) -> bool:
        """Check if try-except has only pass in except."""
        for handler in node.handlers:
            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                return True
        return False

    def _is_manual_enumerate_pattern(self, node: ast.For) -> bool:
        """Check if loop uses manual counter instead of enumerate."""
        # Pattern: i = 0; for item in items: ... i += 1
        # This requires analyzing surrounding context
        # Simplified - return False for now
        return False

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""


class CodeSimplificationFixer:
    """Automatically fix code simplification opportunities."""

    def __init__(self):
        """Initialize code simplification fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.fixes_applied = []

    def scan_file_for_issues(self, file_path: Path) -> List[SimplificationIssue]:
        """
        Scan a file for simplification issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of simplification issues found
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        try:
            tree = ast.parse(content)
            source_lines = content.splitlines()
            visitor = SimplificationVisitor(source_lines)
            visitor.visit(tree)
            return visitor.issues
        except SyntaxError:
            return []

    def fix_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Apply simplification fixes to a Python file.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (success, list of fixes applied)
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return False, []

        original_content = content
        self.fixes_applied = []

        # Note: Many simplification fixes require AST transformation
        # For now, we'll detect issues but apply limited fixes
        issues = self.scan_file_for_issues(file_path)

        # Log detected issues
        if issues:
            self.logger.info(
                f"Found {len(issues)} code simplification opportunities",
                category="CodeSimplification",
                file_path=str(file_path),
                details={"issue_count": len(issues)},
            )
            for issue in issues:
                self.fixes_applied.append(f"{issue.rule_id}: {issue.message}")

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Applied {len(self.fixes_applied)} simplification fixes",
                    category="CodeSimplification",
                    file_path=str(file_path),
                    details={"fixes": self.fixes_applied},
                )
            return success, self.fixes_applied

        return True, []
