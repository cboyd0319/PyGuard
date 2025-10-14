"""
Unused code detection and fixes (Pyflakes/ARG/F rules).

This module implements detection and auto-fixes for unused imports,
variables, arguments, and other unused code patterns.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class UnusedCodeIssue:
    """Issue related to unused code."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""
    rule_id: str = ""  # F401, ARG001, etc.
    name: str = ""  # Name of the unused element


class UnusedCodeVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting unused code patterns.

    Implements Pyflakes and flake8-unused-arguments checks.
    """

    def __init__(self, source_lines: List[str]):
        """Initialize unused code visitor."""
        self.issues: List[UnusedCodeIssue] = []
        self.source_lines = source_lines

        # Track imports
        self.imports: Dict[str, Tuple[int, int]] = {}  # name -> (line, col)
        self.import_froms: Dict[str, Tuple[int, int]] = {}  # name -> (line, col)

        # Track variable assignments
        self.assignments: Dict[str, Tuple[int, int]] = {}  # name -> (line, col)

        # Track function arguments
        self.function_args: Dict[str, Set[str]] = {}  # func_name -> set of arg names

        # Track usage
        self.used_names: Set[str] = set()

        # Current function context
        self.current_function = None

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ""

    def visit_Import(self, node: ast.Import):
        """Track import statements."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = (node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from...import statements."""
        for alias in node.names:
            if alias.name == "*":
                # Star imports are problematic but tracked separately
                continue
            name = alias.asname if alias.asname else alias.name
            self.import_froms[name] = (node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function definitions and arguments."""
        old_function = self.current_function
        self.current_function = node.name

        # Track arguments
        arg_names = set()
        for arg in node.args.args:
            arg_names.add(arg.arg)
        for arg in node.args.posonlyargs:
            arg_names.add(arg.arg)
        for arg in node.args.kwonlyargs:
            arg_names.add(arg.arg)
        if node.args.vararg:
            arg_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            arg_names.add(node.args.kwarg.arg)

        self.function_args[node.name] = arg_names

        # Visit function body to find unused arguments
        used_in_function = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                used_in_function.add(child.id)

        # Find unused arguments (skip 'self', 'cls', '_' prefix)
        for arg_name in arg_names:
            if arg_name in ["self", "cls"]:
                continue
            if arg_name.startswith("_"):
                continue
            if arg_name not in used_in_function:
                # Find the argument node for line number
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    if arg.arg == arg_name:
                        self.issues.append(
                            UnusedCodeIssue(
                                severity="LOW",
                                category="Unused Code",
                                message=f"Unused function argument: {arg_name}",
                                line_number=arg.lineno,
                                column=arg.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"Remove argument or prefix with underscore: _{arg_name}",
                                rule_id="ARG001",
                                name=arg_name,
                            )
                        )
                        break

        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Track async function definitions."""
        # Same logic as FunctionDef
        old_function = self.current_function
        self.current_function = node.name

        arg_names = set()
        for arg in node.args.args:
            arg_names.add(arg.arg)
        for arg in node.args.posonlyargs:
            arg_names.add(arg.arg)
        for arg in node.args.kwonlyargs:
            arg_names.add(arg.arg)
        if node.args.vararg:
            arg_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            arg_names.add(node.args.kwarg.arg)

        self.function_args[node.name] = arg_names

        used_in_function = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                used_in_function.add(child.id)

        for arg_name in arg_names:
            if arg_name in ["self", "cls"]:
                continue
            if arg_name.startswith("_"):
                continue
            if arg_name not in used_in_function:
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    if arg.arg == arg_name:
                        self.issues.append(
                            UnusedCodeIssue(
                                severity="LOW",
                                category="Unused Code",
                                message=f"Unused function argument: {arg_name}",
                                line_number=arg.lineno,
                                column=arg.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"Remove argument or prefix with underscore: _{arg_name}",
                                rule_id="ARG001",
                                name=arg_name,
                            )
                        )
                        break

        self.generic_visit(node)
        self.current_function = old_function

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments[target.id] = (node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Track annotated assignments."""
        if isinstance(node.target, ast.Name):
            self.assignments[node.target.id] = (node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        """Track name usage."""
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        """Track attribute access."""
        # If accessing an attribute, the base object is used
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)
        self.generic_visit(node)

    def finalize(self):
        """Finalize analysis and generate unused import/variable issues."""
        # Check for unused imports
        for name, (line, col) in self.imports.items():
            if name not in self.used_names:
                if line <= len(self.source_lines):
                    snippet = self.source_lines[line - 1].strip()
                else:
                    snippet = ""
                self.issues.append(
                    UnusedCodeIssue(
                        severity="LOW",
                        category="Unused Code",
                        message=f"Unused import: {name}",
                        line_number=line,
                        column=col,
                        code_snippet=snippet,
                        fix_suggestion=f"Remove unused import: {name}",
                        rule_id="F401",
                        name=name,
                    )
                )

        for name, (line, col) in self.import_froms.items():
            if name not in self.used_names:
                if line <= len(self.source_lines):
                    snippet = self.source_lines[line - 1].strip()
                else:
                    snippet = ""
                self.issues.append(
                    UnusedCodeIssue(
                        severity="LOW",
                        category="Unused Code",
                        message=f"Unused import: {name}",
                        line_number=line,
                        column=col,
                        code_snippet=snippet,
                        fix_suggestion=f"Remove unused import: {name}",
                        rule_id="F401",
                        name=name,
                    )
                )

        # Check for unused variables (only module-level, not local)
        # This is simplified; real implementation would track scopes
        for name, (line, col) in self.assignments.items():
            # Skip special names and private names
            if name.startswith("_"):
                continue
            if name.isupper():  # Constants are often unused
                continue
            if name not in self.used_names:
                if line <= len(self.source_lines):
                    snippet = self.source_lines[line - 1].strip()
                else:
                    snippet = ""
                self.issues.append(
                    UnusedCodeIssue(
                        severity="LOW",
                        category="Unused Code",
                        message=f"Unused variable: {name}",
                        line_number=line,
                        column=col,
                        code_snippet=snippet,
                        fix_suggestion=f"Remove unused variable or prefix with underscore: _{name}",
                        rule_id="F841",
                        name=name,
                    )
                )


class UnusedCodeFixer:
    """Automatically fix unused code issues."""

    def __init__(self):
        """Initialize unused code fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.fixes_applied = []

    def scan_file_for_issues(self, file_path: Path) -> List[UnusedCodeIssue]:
        """
        Scan a file for unused code issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of unused code issues found
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        try:
            tree = ast.parse(content)
            source_lines = content.splitlines()
            visitor = UnusedCodeVisitor(source_lines)
            visitor.visit(tree)
            visitor.finalize()
            return visitor.issues
        except SyntaxError:
            return []

    def fix_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Apply unused code fixes to a Python file.

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

        # Get all unused code issues
        issues = self.scan_file_for_issues(file_path)

        # Group issues by type
        unused_imports = [i for i in issues if i.rule_id == "F401"]
        # unused_vars and unused_args not used yet but reserved for future functionality

        # Remove unused imports
        lines = content.splitlines(keepends=True)
        lines_to_remove = set()

        for issue in unused_imports:
            # Find the line with this import
            line_idx = issue.line_number - 1
            if 0 <= line_idx < len(lines):
                line = lines[line_idx]
                # Check if this is a simple import line
                if line.strip().startswith(("import ", "from ")):
                    # Check if line only imports this one thing
                    if issue.name in line and line.count(",") == 0:
                        lines_to_remove.add(line_idx)
                        self.fixes_applied.append(f"F401: Removed unused import {issue.name}")

        # Remove marked lines
        if lines_to_remove:
            lines = [line for i, line in enumerate(lines) if i not in lines_to_remove]
            content = "".join(lines)

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Applied {len(self.fixes_applied)} unused code fixes",
                    category="UnusedCode",
                    file_path=str(file_path),
                    details={"fixes": self.fixes_applied},
                )
            return success, self.fixes_applied

        return True, []
