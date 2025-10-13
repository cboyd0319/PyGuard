"""
Naming convention detection (pep8-naming/N rules).

This module implements detection for naming convention violations
following PEP 8 guidelines.
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class NamingIssue:
    """Issue related to naming conventions."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""
    rule_id: str = ""  # N801, N802, etc.
    name: str = ""  # The problematic name


class NamingConventionVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting naming convention violations.

    Implements PEP 8 naming conventions (pep8-naming).
    """

    def __init__(self, source_lines: List[str]):
        """Initialize naming convention visitor."""
        self.issues: List[NamingIssue] = []
        self.source_lines = source_lines

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ""

    def _is_snake_case(self, name: str) -> bool:
        """Check if name follows snake_case convention."""
        # Allow leading underscore(s)
        name = name.lstrip("_")
        return name.islower() or "_" in name and name.replace("_", "").islower()

    def _is_camel_case(self, name: str) -> bool:
        """Check if name follows CamelCase convention."""
        if not name:
            return False
        return name[0].isupper() and "_" not in name

    def _is_upper_case(self, name: str) -> bool:
        """Check if name follows UPPER_CASE convention."""
        # Allow leading underscore(s)
        name = name.lstrip("_")
        return name.isupper() or (name.replace("_", "").isupper() and "_" in name)

    def _suggest_snake_case(self, name: str) -> str:
        """Suggest snake_case conversion."""
        # Simple camelCase to snake_case conversion
        result = re.sub("([A-Z]+)", r"_\1", name).lower()
        return result.lstrip("_")

    def _suggest_camel_case(self, name: str) -> str:
        """Suggest CamelCase conversion."""
        parts = name.split("_")
        return "".join(word.capitalize() for word in parts if word)

    def visit_ClassDef(self, node: ast.ClassDef):
        """Check class naming conventions."""
        # N801: Class names should use CamelCase
        if not self._is_camel_case(node.name):
            suggested = self._suggest_camel_case(node.name)
            self.issues.append(
                NamingIssue(
                    severity="MEDIUM",
                    category="Naming Convention",
                    message=f"Class name '{node.name}' should use CamelCase",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion=f"Rename to '{suggested}'",
                    rule_id="N801",
                    name=node.name,
                )
            )

        # Check for lowercase L, uppercase O, uppercase I (confusing names)
        if node.name in ["l", "O", "I"]:
            self.issues.append(
                NamingIssue(
                    severity="HIGH",
                    category="Naming Convention",
                    message=f"Class name '{node.name}' is ambiguous (looks like digit/letter)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use a more descriptive name",
                    rule_id="E741",
                    name=node.name,
                )
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check function naming conventions."""
        # N802: Function names should use snake_case
        # Exception: methods can have different conventions in frameworks
        if not self._is_snake_case(node.name):
            # Allow common test method patterns like test_*, setUp, tearDown
            if not node.name.startswith("test_") and node.name not in ["setUp", "tearDown"]:
                suggested = self._suggest_snake_case(node.name)
                self.issues.append(
                    NamingIssue(
                        severity="MEDIUM",
                        category="Naming Convention",
                        message=f"Function name '{node.name}' should use snake_case",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion=f"Rename to '{suggested}'",
                        rule_id="N802",
                        name=node.name,
                    )
                )

        # N807: Function name should not start and end with '__'
        if node.name.startswith("__") and node.name.endswith("__"):
            # Allow magic methods
            magic_methods = [
                "__init__",
                "__str__",
                "__repr__",
                "__eq__",
                "__ne__",
                "__lt__",
                "__le__",
                "__gt__",
                "__ge__",
                "__hash__",
                "__bool__",
                "__len__",
                "__getitem__",
                "__setitem__",
                "__delitem__",
                "__iter__",
                "__next__",
                "__contains__",
                "__call__",
                "__enter__",
                "__exit__",
                "__aenter__",
                "__aexit__",
                "__getattr__",
                "__setattr__",
                "__delattr__",
                "__dir__",
                "__get__",
                "__set__",
                "__delete__",
                "__set_name__",
                "__init_subclass__",
                "__class_getitem__",
                "__add__",
                "__sub__",
                "__mul__",
                "__truediv__",
                "__floordiv__",
                "__mod__",
                "__pow__",
                "__and__",
                "__or__",
                "__xor__",
                "__lshift__",
                "__rshift__",
                "__neg__",
                "__pos__",
                "__invert__",
            ]
            if node.name not in magic_methods:
                self.issues.append(
                    NamingIssue(
                        severity="MEDIUM",
                        category="Naming Convention",
                        message=f"Function name '{node.name}' should not use double underscores (reserved for magic methods)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion=f"Use single underscore or regular name",
                        rule_id="N807",
                        name=node.name,
                    )
                )

        # Check for confusing names
        if node.name in ["l", "O", "I"]:
            self.issues.append(
                NamingIssue(
                    severity="HIGH",
                    category="Naming Convention",
                    message=f"Function name '{node.name}' is ambiguous",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use a more descriptive name",
                    rule_id="E741",
                    name=node.name,
                )
            )

        # N803: Check argument names
        for arg in node.args.args:
            if not self._is_snake_case(arg.arg) and arg.arg not in ["self", "cls"]:
                suggested = self._suggest_snake_case(arg.arg)
                self.issues.append(
                    NamingIssue(
                        severity="LOW",
                        category="Naming Convention",
                        message=f"Argument name '{arg.arg}' should use snake_case",
                        line_number=arg.lineno,
                        column=arg.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion=f"Rename to '{suggested}'",
                        rule_id="N803",
                        name=arg.arg,
                    )
                )

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Check async function naming conventions."""
        # Same rules as regular functions
        if not self._is_snake_case(node.name):
            suggested = self._suggest_snake_case(node.name)
            self.issues.append(
                NamingIssue(
                    severity="MEDIUM",
                    category="Naming Convention",
                    message=f"Async function name '{node.name}' should use snake_case",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion=f"Rename to '{suggested}'",
                    rule_id="N802",
                    name=node.name,
                )
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check variable naming conventions."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id

                # Skip special names
                if name.startswith("_"):
                    continue

                # N806: Variable in function should be lowercase (snake_case)
                # N816: Variable at module level should be lowercase or UPPER_CASE

                # Check if it looks like a constant (all uppercase)
                if self._is_upper_case(name):
                    # Constants are fine
                    continue

                # Check for camelCase variables (should be snake_case)
                if not self._is_snake_case(name):
                    suggested = self._suggest_snake_case(name)
                    self.issues.append(
                        NamingIssue(
                            severity="LOW",
                            category="Naming Convention",
                            message=f"Variable name '{name}' should use snake_case",
                            line_number=target.lineno,
                            column=target.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion=f"Rename to '{suggested}'",
                            rule_id="N806",
                            name=name,
                        )
                    )

                # Check for confusing names
                if name in ["l", "O", "I"]:
                    self.issues.append(
                        NamingIssue(
                            severity="HIGH",
                            category="Naming Convention",
                            message=f"Variable name '{name}' is ambiguous",
                            line_number=target.lineno,
                            column=target.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use a more descriptive name",
                            rule_id="E741",
                            name=name,
                        )
                    )

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check import naming conventions."""
        for alias in node.names:
            if alias.asname:
                # N811: Check alias names
                if not self._is_snake_case(alias.asname) and not self._is_upper_case(alias.asname):
                    self.issues.append(
                        NamingIssue(
                            severity="LOW",
                            category="Naming Convention",
                            message=f"Import alias '{alias.asname}' should use snake_case or UPPER_CASE",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use appropriate naming convention",
                            rule_id="N811",
                            name=alias.asname,
                        )
                    )

        self.generic_visit(node)


class NamingConventionFixer:
    """Automatically fix naming convention violations."""

    def __init__(self):
        """Initialize naming convention fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.fixes_applied = []

    def scan_file_for_issues(self, file_path: Path) -> List[NamingIssue]:
        """
        Scan a file for naming convention issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of naming convention issues found
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        try:
            tree = ast.parse(content)
            source_lines = content.splitlines()
            visitor = NamingConventionVisitor(source_lines)
            visitor.visit(tree)
            return visitor.issues
        except SyntaxError:
            return []

    def fix_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Apply naming convention fixes to a Python file.

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

        # Get all naming issues
        issues = self.scan_file_for_issues(file_path)

        # Log detected issues (actual renaming requires careful AST transformation)
        if issues:
            self.logger.info(
                f"Found {len(issues)} naming convention issues",
                category="NamingConvention",
                file_path=str(file_path),
                details={"issue_count": len(issues)},
            )
            for issue in issues:
                self.fixes_applied.append(f"{issue.rule_id}: {issue.message}")

        # Note: Automatic renaming is complex and requires:
        # 1. Renaming all references to the identifier
        # 2. Checking for name conflicts
        # 3. Updating docstrings and comments
        # For now, we just detect issues

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Detected {len(self.fixes_applied)} naming convention issues",
                    category="NamingConvention",
                    file_path=str(file_path),
                    details={"fixes": self.fixes_applied},
                )
            return success, self.fixes_applied

        return True, []
