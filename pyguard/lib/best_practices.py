"""
Best practices fixes for Python code.

Enforces PEP 8, Python idioms, and coding standards.
"""

import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from pyguard.lib.ast_analyzer import ASTAnalyzer, CodeQualityIssue
from pyguard.lib.core import FileOperations, PyGuardLogger


class BestPracticesFixer:
    """Automatically fix Python best practice violations."""

    def __init__(self):
        """Initialize best practices fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.fixes_applied = []
        self.ast_analyzer = ASTAnalyzer()

    def scan_file_for_issues(self, file_path: Path) -> List[CodeQualityIssue]:
        """
        Scan a file for code quality issues using AST analysis.

        Args:
            file_path: Path to Python file

        Returns:
            List of code quality issues found
        """
        _, quality_issues = self.ast_analyzer.analyze_file(file_path)
        return quality_issues

    def get_complexity_report(self, file_path: Path) -> Dict[str, int]:
        """
        Get cyclomatic complexity report for a file.

        Args:
            file_path: Path to Python file

        Returns:
            Dictionary mapping function names to complexity scores
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return {}
        return self.ast_analyzer.get_complexity_report(content)

    def fix_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Apply best practice fixes to a Python file.

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

        # Apply best practice fixes
        content = self._fix_mutable_default_arguments(content)
        content = self._fix_bare_except(content)
        content = self._fix_comparison_to_none(content)
        content = self._fix_comparison_to_bool(content)
        content = self._fix_type_comparison(content)
        content = self._fix_list_comprehension(content)
        content = self._fix_string_concatenation(content)
        content = self._fix_context_managers(content)
        content = self._add_missing_docstrings(content)
        content = self._fix_global_variables(content)

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Applied {len(self.fixes_applied)} best practice fixes",
                    category="BestPractices",
                    file_path=str(file_path),
                    details={"fixes": self.fixes_applied},
                )
            return success, self.fixes_applied

        return True, []

    def _fix_mutable_default_arguments(self, content: str) -> str:
        """Fix mutable default arguments in function definitions."""
        # Pattern: def func(arg=[]) or def func(arg={})
        pattern = r"def\s+\w+\([^)]*=\s*(\[\]|\{\})"

        if re.search(pattern, content):
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if re.search(pattern, line) and "# MUTABLE DEFAULT" not in line:
                    lines[i] = f"{line}  # ANTI-PATTERN: Use None and create in function body"
                    self.fixes_applied.append("Added warning about mutable default argument")
            content = "\n".join(lines)

        return content

    def _fix_bare_except(self, content: str) -> str:
        """Fix bare except clauses."""
        # Replace bare except with except Exception
        lines = content.split("\n")
        for i, line in enumerate(lines):
            # Match bare except (not except Exception, except SomeError, etc.)
            match = re.match(r"^(\s*)except\s*:\s*$", line)
            if match:
                indent = match.group(1)
                lines[i] = f"{indent}except Exception:  # FIXED: Catch specific exceptions"
                self.fixes_applied.append("Replaced bare except with except Exception")

        return "\n".join(lines)

    def _fix_comparison_to_none(self, content: str) -> str:
        """Fix comparisons to None (should use 'is' not '==')."""
        # Pattern: == None or != None
        replacements = [
            (r"(\w+)\s*==\s*None", r"\1 is None"),
            (r"(\w+)\s*!=\s*None", r"\1 is not None"),
        ]

        for pattern, replacement in replacements:
            if re.search(pattern, content):
                content = re.sub(pattern, replacement, content)
                self.fixes_applied.append("Fixed None comparison to use 'is'")

        return content

    def _fix_comparison_to_bool(self, content: str) -> str:
        """Fix comparisons to True/False."""
        # Pattern: if x == True or if x == False
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if "== True" in line:
                lines[i] = line.replace("== True", "  # Use if var: instead")
                self.fixes_applied.append("Added suggestion to simplify boolean comparison")
            elif "== False" in line:
                lines[i] = line.replace("== False", "  # Use if not var: instead")
                self.fixes_applied.append("Added suggestion to simplify boolean comparison")

        return "\n".join(lines)

    def _fix_type_comparison(self, content: str) -> str:
        """Fix type comparisons (should use isinstance())."""
        # Pattern: type(x) == SomeType
        pattern = r"type\((\w+)\)\s*==\s*(\w+)"

        if re.search(pattern, content):
            lines = content.split("\n")
            for i, line in enumerate(lines):
                match = re.search(pattern, line)
                if match and "# Better:" not in line:
                    var_name = match.group(1)
                    type_name = match.group(2)
                    lines[i] = f"{line}  # Better: isinstance({var_name}, {type_name})"
                    self.fixes_applied.append("Added suggestion to use isinstance()")
            content = "\n".join(lines)

        return content

    def _fix_list_comprehension(self, content: str) -> str:
        """Suggest list comprehensions for simple loops."""
        # Pattern: for loop that appends to list
        pattern = r"for\s+\w+\s+in\s+.*:\s*\n\s+\w+\.append\("

        if re.search(pattern, content, re.MULTILINE):
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if "for " in line and i + 1 < len(lines) and ".append(" in lines[i + 1]:
                    if "# Consider list comprehension" not in line:
                        lines[i] = f"{line}  # Consider list comprehension"
                        self.fixes_applied.append("Suggested list comprehension")
            content = "\n".join(lines)

        return content

    def _fix_string_concatenation(self, content: str) -> str:
        """Fix string concatenation in loops."""
        # Pattern: string += in a loop
        lines = content.split("\n")
        in_loop = False

        for i, line in enumerate(lines):
            if re.match(r"^\s*(for|while)\s+", line):
                in_loop = True
            elif in_loop and re.match(r'^\s*\w+\s*\+=\s*["\']', line):
                if "# Use list and join()" not in line:
                    lines[i] = f"{line}  # PERFORMANCE: Use list and join()"
                    self.fixes_applied.append("Added warning about string concatenation")
            elif not line.startswith(" " * 4) and line.strip():
                in_loop = False

        return "\n".join(lines)

    def _fix_context_managers(self, content: str) -> str:
        """Suggest using context managers for file operations."""
        # Pattern: file = open() without with statement
        lines = content.split("\n")

        for i, line in enumerate(lines):
            if "open(" in line and not line.strip().startswith("with"):
                if "=" in line and "# Use 'with' statement" not in line:
                    lines[i] = f"{line}  # Best Practice: Use 'with' statement"
                    self.fixes_applied.append("Suggested using context manager")

        return "\n".join(lines)

    def _add_missing_docstrings(self, content: str) -> str:
        """Add placeholders for missing docstrings."""
        lines = content.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]

            # Check for function or class definition
            if re.match(r"^\s*(def|class)\s+\w+", line):
                # Check if next non-empty line is a docstring
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1

                if j < len(lines):
                    next_line = lines[j].strip()
                    if not (next_line.startswith('"""') or next_line.startswith("'''")):
                        # No docstring found
                        indent = len(line) - len(line.lstrip())
                        indent_str = " " * (indent + 4)

                        # Don't add if already has a comment about missing docstring
                        if j < len(lines) and "# TODO: Add docstring" not in lines[j]:
                            lines.insert(j, f"{indent_str}# TODO: Add docstring")
                            self.fixes_applied.append("Added TODO for missing docstring")
                            i += 1

            i += 1

        return "\n".join(lines)

    def _fix_global_variables(self, content: str) -> str:
        """Warn about global variable usage."""
        lines = content.split("\n")

        for i, line in enumerate(lines):
            if line.strip().startswith("global ") and "# Avoid global" not in line:
                lines[i] = f"{line}  # Avoid global variables; consider class attributes"
                self.fixes_applied.append("Added warning about global variables")

        return "\n".join(lines)

    def analyze_complexity(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze code complexity metrics.

        Args:
            file_path: Path to Python file

        Returns:
            Dictionary with complexity metrics
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return {}

        try:
            tree = ast.parse(content)

            metrics = {
                "functions": 0,
                "classes": 0,
                "lines": len(content.split("\n")),
                "imports": 0,
            }

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    metrics["functions"] += 1
                elif isinstance(node, ast.ClassDef):
                    metrics["classes"] += 1
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    metrics["imports"] += 1

            return metrics

        except SyntaxError:
            self.logger.error(
                "Syntax error in file",
                category="BestPractices",
                file_path=str(file_path),
            )
            return {}


class NamingConventionFixer:
    """Fix naming convention issues."""

    def __init__(self):
        """Initialize naming convention fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def check_naming_conventions(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Check for naming convention violations.

        Args:
            file_path: Path to Python file

        Returns:
            List of naming violations
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        violations: List[Dict[str, Any]] = []

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                # Check function names (should be snake_case)
                if isinstance(node, ast.FunctionDef):
                    if not re.match(r"^[a-z_][a-z0-9_]*$", node.name) and not node.name.startswith(
                        "__"
                    ):
                        violations.append(
                            {
                                "type": "function",
                                "name": node.name,
                                "line": node.lineno,
                                "issue": "Should use snake_case",
                            }
                        )

                # Check class names (should be PascalCase)
                elif isinstance(node, ast.ClassDef):
                    if not re.match(r"^[A-Z][a-zA-Z0-9]*$", node.name):
                        violations.append(
                            {
                                "type": "class",
                                "name": node.name,
                                "line": node.lineno,
                                "issue": "Should use PascalCase",
                            }
                        )

            return violations

        except SyntaxError:
            return []
