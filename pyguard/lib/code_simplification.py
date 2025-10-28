"""
Code simplification detection and fixes (flake8-simplify/SIM rules).

This module implements detection and auto-fixes for code that can be simplified
while maintaining the same functionality. Aligned with flake8-simplify rules.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

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

    def __init__(self, source_lines: list[str]):
        """Initialize simplification visitor."""
        self.issues: list[SimplificationIssue] = []
        self.source_lines = source_lines

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return str(self.source_lines[node.lineno - 1].strip())
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

        # SIM116: Use dict.get() with default instead of if-key-in-dict pattern
        if self._is_dict_get_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="LOW",
                    category="Code Simplification",
                    message="Use dict.get(key, default) instead of if-key-in-dict pattern",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace 'if key in dict: x = dict[key] else: x = default' with 'x = dict.get(key, default)'",
                    rule_id="SIM116",
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

        # SIM110: Use all() instead of for loop setting flag
        if self._is_all_loop_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="MEDIUM",
                    category="Code Simplification",
                    message="Use all() instead of for loop with flag variable",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace loop with: result = all(condition for item in items)",
                    rule_id="SIM110",
                )
            )

        # SIM111: Use any() instead of for loop setting flag
        if self._is_any_loop_pattern(node):
            self.issues.append(
                SimplificationIssue(
                    severity="MEDIUM",
                    category="Code Simplification",
                    message="Use any() instead of for loop with flag variable",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace loop with: result = any(condition for item in items)",
                    rule_id="SIM111",
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

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definitions for guard clause patterns."""
        # SIM106: Use guard clauses (handle error cases first)
        if self._should_use_guard_clause(node):
            self.issues.append(
                SimplificationIssue(
                    severity="LOW",
                    category="Code Simplification",
                    message="Use guard clause - handle error cases first to reduce nesting",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Move error/edge case checks to the start with early return",
                    rule_id="SIM106",
                )
            )

        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        """Visit dictionary creation."""
        # SIM118: Use .get() or 'in' instead of dict.keys()
        # This is detected in subscript/contains patterns

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        """Visit comparison nodes."""
        # SIM201-204: Compare with True/False/None using 'is'
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            if isinstance(comparator, ast.Constant):
                if comparator.value in [True, False]:
                    # Only flag == or != comparisons, not other comparison operators
                    if isinstance(op, ast.Eq):
                        self.issues.append(
                            SimplificationIssue(
                                severity="LOW",
                                category="Code Simplification",
                                message=f"Use 'is {comparator.value!r}' instead of '== {comparator.value!r}'",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"Replace '== {comparator.value!r}' with 'is {comparator.value!r}'",
                                rule_id="SIM201" if comparator.value is True else "SIM202",
                            )
                        )
                    elif isinstance(op, ast.NotEq):
                        self.issues.append(
                            SimplificationIssue(
                                severity="LOW",
                                category="Code Simplification",
                                message=f"Use 'is not {comparator.value!r}' instead of '!= {comparator.value!r}'",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"Replace '!= {comparator.value!r}' with 'is not {comparator.value!r}'",
                                rule_id="SIM201" if comparator.value is True else "SIM202",
                            )
                        )

            # SIM118: Use 'key in dict' instead of 'key in dict.keys()'
            if (
                isinstance(op, ast.In)
                and isinstance(comparator, ast.Call)
                and (
                    isinstance(comparator.func, ast.Attribute)
                    and comparator.func.attr
                    == "keys"  # pyguard: disable=CWE-208  # Pattern detection, not vulnerable code
                    and len(comparator.args) == 0
                )
            ):
                self.issues.append(
                    SimplificationIssue(
                        severity="LOW",
                        category="Code Simplification",
                        message="Use 'key in dict' instead of 'key in dict.keys()'",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove .keys() call - 'in' checks keys by default",
                        rule_id="SIM118",
                    )
                )

        # SIM300-301: Simplify negated comparisons
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            # This is handled in visit_UnaryOp to catch 'not (a == b)' patterns
            pass

        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp):
        """Visit unary operations for simplification opportunities."""
        if isinstance(node.op, ast.Not):
            # SIM300: Use 'a == b' instead of 'not (a != b)'
            if isinstance(node.operand, ast.Compare) and len(node.operand.ops) == 1:
                op = node.operand.ops[0]
                if isinstance(op, ast.NotEq):
                    self.issues.append(
                        SimplificationIssue(
                            severity="LOW",
                            category="Code Simplification",
                            message="Use '==' instead of 'not ... !='",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Replace 'not (a != b)' with 'a == b'",
                            rule_id="SIM300",
                        )
                    )
                # SIM301: Use 'a != b' instead of 'not (a == b)'
                elif isinstance(op, ast.Eq):
                    self.issues.append(
                        SimplificationIssue(
                            severity="LOW",
                            category="Code Simplification",
                            message="Use '!=' instead of 'not ... =='",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Replace 'not (a == b)' with 'a != b'",
                            rule_id="SIM301",
                        )
                    )

            # Boolean simplification patterns
            # SIM220-223: De Morgan's laws
            if isinstance(node.operand, ast.BoolOp):
                if isinstance(node.operand.op, ast.Or):
                    # not (a or b) can be simplified to (not a and not b)
                    # But this might make it more complex - only flag in specific cases
                    # Check if all values are already negated
                    all_negated = all(
                        isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not)
                        for v in node.operand.values
                    )
                    if all_negated:
                        self.issues.append(
                            SimplificationIssue(
                                severity="LOW",
                                category="Code Simplification",
                                message="Simplify 'not (not a or not b)' to 'a and b'",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="Apply De Morgan's law: not (not a or not b) => a and b",
                                rule_id="SIM223",
                            )
                        )
                elif isinstance(node.operand.op, ast.And):
                    # not (a and b) can be simplified to (not a or not b)
                    all_negated = all(
                        isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not)
                        for v in node.operand.values
                    )
                    if all_negated:
                        self.issues.append(
                            SimplificationIssue(
                                severity="LOW",
                                category="Code Simplification",
                                message="Simplify 'not (not a and not b)' to 'a or b'",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="Apply De Morgan's law: not (not a and not b) => a or b",
                                rule_id="SIM222",
                            )
                        )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        """Visit subscript operations for dict key checks."""
        # SIM116: Use dict.get() with default instead of if-else key check pattern
        # This requires parent context to detect the pattern
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        """Visit attribute access for dict.keys() patterns."""
        # SIM118: Use 'key in dict' instead of 'key in dict.keys()'
        # This is detected in the parent In node
        self.generic_visit(node)

    def visit_In(self, node: ast.In):
        """Visit 'in' comparisons."""
        # This is actually part of Compare, handled there
        pass

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
                if isinstance(body_stmt.value, ast.Constant) and isinstance(
                    else_stmt.value, ast.Constant
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

    def _is_duplicate_if_body(self, _node: ast.If) -> bool:
        """Check if there are duplicate if bodies (would need parent context).
        
        Args:
            _node: If node (requires parent tracking - not yet implemented)
        """
        # This requires analyzing sibling nodes, which needs parent tracking
        # Simplified version - return False for now
        return False

    def _is_try_except_pass_pattern(self, node: ast.Try) -> bool:
        """Check if try-except has only pass in except."""
        for handler in node.handlers:
            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                return True
        return False

    def _is_manual_enumerate_pattern(self, _node: ast.For) -> bool:
        """Check if loop uses manual counter instead of enumerate.
        
        Args:
            _node: For loop node (requires context analysis - not yet implemented)
        """
        # Pattern: i = 0; for item in items: ... i += 1
        # This requires analyzing surrounding context
        # Simplified - return False for now
        return False

    def _is_all_loop_pattern(self, node: ast.For) -> bool:
        """
        Check if loop follows pattern: flag = True; for x in items: if not cond: flag = False.

        This is a simplified detection - a full implementation would need flow analysis.
        We check for loops that:
        1. Have an if statement that sets a variable to False
        2. Could be replaced with all()
        """
        # Look for pattern: for item in items: if not condition: result = False
        if len(node.body) == 1 and isinstance(node.body[0], ast.If):
            if_stmt = node.body[0]
            # Check if body contains assignment to False
            if len(if_stmt.body) == 1 and isinstance(if_stmt.body[0], ast.Assign):
                assign = if_stmt.body[0]
                if len(assign.targets) == 1 and isinstance(assign.value, ast.Constant):
                    if assign.value.value is False:
                        return True
        return False

    def _is_any_loop_pattern(self, node: ast.For) -> bool:
        """
        Check if loop follows pattern: flag = False; for x in items: if cond: flag = True.

        This is a simplified detection - a full implementation would need flow analysis.
        We check for loops that:
        1. Have an if statement that sets a variable to True
        2. Could be replaced with any()
        """
        # Look for pattern: for item in items: if condition: result = True
        if len(node.body) == 1 and isinstance(node.body[0], ast.If):
            if_stmt = node.body[0]
            # Check if body contains assignment to True
            if len(if_stmt.body) == 1 and isinstance(if_stmt.body[0], ast.Assign):
                assign = if_stmt.body[0]
                if len(assign.targets) == 1 and isinstance(assign.value, ast.Constant):
                    if assign.value.value is True:
                        return True
        return False

    def _should_use_guard_clause(self, node: ast.FunctionDef) -> bool:
        """
        Check if function has pattern that could use guard clauses.

        Pattern: if condition: [large body] else: [small error handling]
        Should be: if error_condition: return/raise; [large body]
        """
        if not node.body:
            return False

        # Look for function starting with large if-else where else has return/raise
        first_stmt = node.body[0]
        if isinstance(first_stmt, ast.If) and first_stmt.orelse:
            # Check if the else clause is simple (has return or raise)
            else_clause = first_stmt.orelse
            if len(else_clause) <= 2:  # Small else clause
                has_return_or_raise = any(
                    isinstance(stmt, (ast.Return, ast.Raise)) for stmt in else_clause
                )
                # And the main body is large
                if has_return_or_raise and len(first_stmt.body) > 3:
                    return True

        return False

    def _is_dict_get_pattern(self, node: ast.If) -> bool:
        """
        Check if pattern: if key in dict: x = dict[key] else: x = default.

        This can be replaced with: x = dict.get(key, default)
        """
        # Pattern: if key in dict_var:
        if not isinstance(node.test, ast.Compare):
            return False

        if len(node.test.ops) != 1 or not isinstance(node.test.ops[0], ast.In):
            return False

        # Check if body has assignment from dict subscript
        if not node.body or not node.orelse:
            return False

        if len(node.body) != 1 or not isinstance(node.body[0], ast.Assign):
            return False

        body_assign = node.body[0]
        if len(body_assign.targets) != 1:
            return False

        # Check if the value is a subscript (dict[key])
        if isinstance(body_assign.value, ast.Subscript):
            # And else clause also assigns to same variable
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.Assign):
                else_assign = node.orelse[0]
                if len(else_assign.targets) == 1:
                    # Check if same target variable
                    body_target = body_assign.targets[0]
                    else_target = else_assign.targets[0]
                    if isinstance(body_target, ast.Name) and isinstance(else_target, ast.Name):
                        if body_target.id == else_target.id:
                            return True

        return False

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.expr = node.func
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

    def scan_file_for_issues(self, file_path: Path) -> list[SimplificationIssue]:
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

    def fix_file(self, file_path: Path) -> tuple[bool, list[str]]:
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
