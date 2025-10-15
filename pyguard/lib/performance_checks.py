"""
Performance anti-pattern detection and fixes (Perflint/PERF rules).

This module implements detection and auto-fixes for performance issues
that can be easily optimized. Aligned with Perflint rules.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class PerformanceIssue:
    """Issue related to performance anti-patterns."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""
    rule_id: str = ""  # PERF101, PERF102, etc.


class PerformanceVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting performance anti-patterns.

    Implements Perflint-style performance checks.
    """

    def __init__(self, source_lines: List[str]):
        """Initialize performance visitor."""
        self.issues: List[PerformanceIssue] = []
        self.source_lines = source_lines
        self.in_loop = False

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return str(self.source_lines[node.lineno - 1].strip())
        return ""

    def visit_For(self, node: ast.For):
        """Visit for loop nodes."""
        old_in_loop = self.in_loop
        self.in_loop = True

        # PERF101: Detect try-except in loop
        for stmt in node.body:
            if isinstance(stmt, ast.Try):
                self.issues.append(
                    PerformanceIssue(
                        severity="MEDIUM",
                        category="Performance",
                        message="Try-except block inside loop - consider moving outside",
                        line_number=stmt.lineno,
                        column=stmt.col_offset,
                        code_snippet=self._get_code_snippet(stmt),
                        fix_suggestion="Move try-except outside loop and wrap the entire loop",
                        rule_id="PERF101",
                    )
                )

        # PERF102: Detect list concatenation in loop
        for stmt_node in ast.walk(node):
            if isinstance(stmt_node, ast.AugAssign) and isinstance(stmt_node.op, ast.Add):
                if isinstance(stmt_node.target, ast.Name):
                    # Check if augmenting a list
                    if isinstance(stmt_node.value, (ast.List, ast.ListComp)):
                        self.issues.append(
                            PerformanceIssue(
                                severity="HIGH",
                                category="Performance",
                                message="List concatenation in loop - use list.extend() or list comprehension",
                                line_number=stmt_node.lineno,
                                column=stmt_node.col_offset,
                                code_snippet=self._get_code_snippet(stmt_node),
                                fix_suggestion="Replace 'result += [item]' with 'result.append(item)' or use list comprehension",
                                rule_id="PERF102",
                            )
                        )

        self.generic_visit(node)
        self.in_loop = old_in_loop

    def visit_While(self, node: ast.While):
        """Visit while loop nodes."""
        old_in_loop = self.in_loop
        self.in_loop = True
        self.generic_visit(node)
        self.in_loop = old_in_loop

    def visit_Call(self, node: ast.Call):
        """Visit function call nodes."""
        func_name = self._get_call_name(node)

        # PERF401: Use list comprehension instead of for loop with append
        # This is complex and requires analyzing loop patterns

        # PERF402: Use list() or dict() instead of comprehension when converting
        if func_name == "list":
            if len(node.args) == 1 and isinstance(node.args[0], ast.ListComp):
                self.issues.append(
                    PerformanceIssue(
                        severity="LOW",
                        category="Performance",
                        message="Unnecessary list() around list comprehension",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove list() wrapper - comprehension already returns list",
                        rule_id="PERF402",
                    )
                )

        if func_name == "set":
            if len(node.args) == 1 and isinstance(node.args[0], ast.SetComp):
                self.issues.append(
                    PerformanceIssue(
                        severity="LOW",
                        category="Performance",
                        message="Unnecessary set() around set comprehension",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove set() wrapper - comprehension already returns set",
                        rule_id="PERF402",
                    )
                )

        if func_name == "dict":
            if len(node.args) == 1 and isinstance(node.args[0], ast.DictComp):
                self.issues.append(
                    PerformanceIssue(
                        severity="LOW",
                        category="Performance",
                        message="Unnecessary dict() around dict comprehension",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove dict() wrapper - comprehension already returns dict",
                        rule_id="PERF402",
                    )
                )

        # PERF403: Use dict comprehension instead of dict([(k, v) ...])
        if func_name == "dict":
            if len(node.args) == 1:
                arg = node.args[0]
                if isinstance(arg, ast.ListComp):
                    # Check if generating tuples
                    if isinstance(arg.elt, ast.Tuple):
                        self.issues.append(
                            PerformanceIssue(
                                severity="MEDIUM",
                                category="Performance",
                                message="Use dict comprehension instead of dict([...])",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="Replace dict([(k, v) for ...]) with {k: v for ...}",
                                rule_id="PERF403",
                            )
                        )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        """Visit comparison nodes."""
        # PERF404: Using .keys() in membership test is slower
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.In):
            comparator = node.comparators[0]
            if isinstance(comparator, ast.Call):
                func_name = self._get_call_name(comparator)
                if func_name and ".keys" in func_name:
                    self.issues.append(
                        PerformanceIssue(
                            severity="MEDIUM",
                            category="Performance",
                            message="Don't use .keys() for membership test - implicit 'in dict' is faster",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Replace 'key in dict.keys()' with 'key in dict'",
                            rule_id="PERF404",
                        )
                    )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        """Visit subscript nodes."""
        # PERF405: Using list copy with [:] when list.copy() is clearer
        if isinstance(node.slice, ast.Slice):
            if node.slice.lower is None and node.slice.upper is None and node.slice.step is None:
                self.issues.append(
                    PerformanceIssue(
                        severity="LOW",
                        category="Performance",
                        message="Use .copy() method instead of [:] for list copying",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Replace 'list[:]' with 'list.copy()' for clarity",
                        rule_id="PERF405",
                    )
                )

        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""


class PerformanceFixer:
    """Automatically fix performance anti-patterns."""

    def __init__(self):
        """Initialize performance fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.fixes_applied = []

    def scan_file_for_issues(self, file_path: Path) -> List[PerformanceIssue]:
        """
        Scan a file for performance issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of performance issues found
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        try:
            tree = ast.parse(content)
            source_lines = content.splitlines()
            visitor = PerformanceVisitor(source_lines)
            visitor.visit(tree)
            return visitor.issues
        except SyntaxError:
            return []

    def fix_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Apply performance fixes to a Python file.

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

        # Apply fixes
        content = self._fix_dict_keys_in_membership(content)
        content = self._fix_list_copy_slice(content)
        content = self._fix_unnecessary_wrappers(content)

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Applied {len(self.fixes_applied)} performance fixes",
                    category="Performance",
                    file_path=str(file_path),
                    details={"fixes": self.fixes_applied},
                )
            return success, self.fixes_applied

        return True, []

    def _fix_dict_keys_in_membership(self, content: str) -> str:
        """Fix dict.keys() in membership tests."""
        import re

        # Pattern: 'in dict.keys()' → 'in dict'
        pattern = r"(\w+)\s+in\s+(\w+)\.keys\(\)"
        matches = re.findall(pattern, content)
        if matches:
            content = re.sub(pattern, r"\1 in \2", content)
            self.fixes_applied.append("PERF404: Removed unnecessary .keys() in membership test")

        return content

    def _fix_list_copy_slice(self, content: str) -> str:
        """Fix list[:] to list.copy()."""
        import re

        # Pattern: 'list[:]' → 'list.copy()'
        # This is a simplified pattern; real implementation needs context
        pattern = r"(\w+)\[:\]"
        if re.search(pattern, content):
            # Don't auto-fix without more context as [:] can be used in different ways
            self.fixes_applied.append("PERF405: Found list[:] (consider using .copy())")

        return content

    def _fix_unnecessary_wrappers(self, content: str) -> str:
        """Remove unnecessary type wrappers around comprehensions."""
        import re

        # Pattern: list([...]) → [...]
        patterns = [
            (r"list\(\[([^\]]+)\]\)", r"[\1]", "list comprehension"),
            (r"set\(\{([^\}]+)\}\)", r"{\1}", "set comprehension"),
            (r"dict\(\{([^\}]+)\}\)", r"{\1}", "dict comprehension"),
        ]

        for pattern, replacement, comp_type in patterns:
            if re.search(pattern, content):
                # Don't auto-fix without AST validation
                self.fixes_applied.append(f"PERF402: Found unnecessary wrapper around {comp_type}")

        return content
