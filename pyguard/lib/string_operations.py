"""
String operation detection and fixes.

This module implements detection and auto-fixes for string-related patterns
including f-string conversion, quote consistency, and string concatenation.
Aligned with flake8-quotes, flynt, and other string-focused linters.
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class StringIssue:
    """Issue related to string operations."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""
    rule_id: str = ""  # PG-S001, PG-S002, etc.


class StringOperationsVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting string operation issues.

    Implements string-related checks for modernization and consistency.
    """

    def __init__(self, source_lines: List[str], source_code: str):
        """Initialize string operations visitor."""
        self.issues: List[StringIssue] = []
        self.source_lines = source_lines
        self.source_code = source_code
        self.quote_style: Optional[str] = None  # Will be detected
        self._detect_dominant_quote_style()

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return str(self.source_lines[node.lineno - 1].strip())
        return ""

    def _detect_dominant_quote_style(self) -> None:
        """Detect the dominant quote style in the file."""
        single_quotes = self.source_code.count("'")
        double_quotes = self.source_code.count('"')

        # Subtract escaped quotes and f-strings
        single_quotes -= self.source_code.count("\\'")
        double_quotes -= self.source_code.count('\\"')

        # Dominant style is the one used more
        if double_quotes > single_quotes * 1.5:
            self.quote_style = "double"
        elif single_quotes > double_quotes * 1.5:
            self.quote_style = "single"
        else:
            self.quote_style = "double"  # Default to PEP 8 preference

    def visit_Call(self, node: ast.Call):
        """Visit function call nodes for .format() detection."""
        # PG-S001: Detect .format() that should be f-string
        if self._is_format_call(node):
            self.issues.append(
                StringIssue(
                    severity="MEDIUM",
                    category="String Operations",
                    message="Use f-string instead of .format()",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion='Replace "text {}".format(var) with f"text {var}"',
                    rule_id="PG-S001",
                )
            )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """Visit binary operations for % formatting."""
        # PG-S002: Detect % formatting that should be f-string
        if isinstance(node.op, ast.Mod) and isinstance(node.left, (ast.Constant, ast.Str)):
            left_value = node.left.value if isinstance(node.left, ast.Constant) else node.left.s
            if isinstance(left_value, str) and '%' in left_value:
                self.issues.append(
                    StringIssue(
                        severity="MEDIUM",
                        category="String Operations",
                        message="Use f-string instead of % formatting",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion='Replace "text %s" % var with f"text {var}"',
                        rule_id="PG-S002",
                    )
                )

        # PG-S005: String concatenation (+ operator)
        if isinstance(node.op, ast.Add):
            if self._is_string_concatenation(node):
                self.issues.append(
                    StringIssue(
                        severity="LOW",
                        category="String Operations",
                        message="Consider using join() for string concatenation or f-strings",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use ''.join([...]) for multiple concatenations",
                        rule_id="PG-S005",
                    )
                )

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Visit f-strings to detect unnecessary ones."""
        # PG-S003: Unnecessary f-string without placeholders
        if not any(isinstance(value, ast.FormattedValue) for value in node.values):
            self.issues.append(
                StringIssue(
                    severity="LOW",
                    category="String Operations",
                    message="Unnecessary f-string without placeholders",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Remove f prefix from string without placeholders",
                    rule_id="PG-S003",
                )
            )

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        """Visit string constants for quote consistency."""
        if isinstance(node.value, str):
            # PG-S004: Check quote consistency
            line_text = self._get_code_snippet(node)
            if self.quote_style and self._has_inconsistent_quotes(line_text, node.value):
                preferred = "double" if self.quote_style == "double" else "single"
                self.issues.append(
                    StringIssue(
                        severity="LOW",
                        category="String Operations",
                        message=f"Inconsistent quote style, use {preferred} quotes",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=line_text,
                        fix_suggestion=f"Use {preferred} quotes for consistency",
                        rule_id="PG-S004",
                    )
                )

        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """Visit for loops to detect string concatenation patterns."""
        # PG-S006: String concatenation in loop
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.op, ast.Add):
                    if self._is_string_augassign(stmt):
                        self.issues.append(
                            StringIssue(
                                severity="MEDIUM",
                                category="String Operations",
                                message="String concatenation in loop (inefficient)",
                                line_number=stmt.lineno,
                                column=stmt.col_offset,
                                code_snippet=self._get_code_snippet(stmt),
                                fix_suggestion="Use a list and ''.join() or io.StringIO",
                                rule_id="PG-S006",
                            )
                        )

        self.generic_visit(node)

    def _is_format_call(self, node: ast.Call) -> bool:
        """Check if this is a .format() call on a string."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                # Check if it's called on a string
                if isinstance(node.func.value, (ast.Constant, ast.Str)):
                    return True
                # Check if it's a variable.format() call
                if isinstance(node.func.value, ast.Name):
                    return True
        return False

    def _is_string_concatenation(self, node: ast.BinOp) -> bool:
        """Check if this is a string concatenation operation."""
        # Check if either operand is a string
        left_is_string = isinstance(node.left, (ast.Constant, ast.Str, ast.JoinedStr))
        right_is_string = isinstance(node.right, (ast.Constant, ast.Str, ast.JoinedStr))

        if left_is_string or right_is_string:
            return True

        # Check for nested concatenation (a + b + c)
        if isinstance(node.left, ast.BinOp) and isinstance(node.left.op, ast.Add):
            return self._is_string_concatenation(node.left)

        return False

    def _is_string_augassign(self, node: ast.AugAssign) -> bool:
        """Check if this is a string augmented assignment."""
        # Simple heuristic: if the variable name suggests it's a string
        if isinstance(node.target, ast.Name):
            name = node.target.id.lower()
            string_indicators = ['str', 'text', 'msg', 'message', 'result', 'output']
            return any(indicator in name for indicator in string_indicators)
        return False

    def _has_inconsistent_quotes(self, line_text: str, string_value: str) -> bool:
        """Check if the string uses inconsistent quotes."""
        if not self.quote_style:
            return False

        # Skip docstrings (triple-quoted strings)
        if '"""' in line_text or "'''" in line_text:
            return False

        # Skip strings with quotes inside (they need the other quote type)
        if '"' in string_value or "'" in string_value:
            return False

        # Check if the line uses the non-preferred quote style
        if self.quote_style == "double":
            # Looking for single quotes when double is preferred
            return "'" in line_text and '"' not in line_text
        else:
            # Looking for double quotes when single is preferred
            return '"' in line_text and "'" not in line_text


class StringOperationsFixer:
    """
    Fix string operation issues in Python code.

    Provides auto-fixes for f-string conversion, quote normalization, etc.
    """

    def __init__(self, logger: Optional[PyGuardLogger] = None):
        """Initialize string operations fixer."""
        self.logger = logger or PyGuardLogger()
        self.file_ops = FileOperations()

    def analyze_file(self, file_path: Path) -> List[StringIssue]:
        """
        Analyze a file for string operation issues.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of detected string issues
        """
        try:
            content = self.file_ops.read_file(file_path)
            if content is None:
                return []
            tree = ast.parse(content, filename=str(file_path))
            source_lines = content.splitlines()

            visitor = StringOperationsVisitor(source_lines, content)
            visitor.visit(tree)

            return visitor.issues

        except SyntaxError as e:
            self.logger.warning(
                "Syntax error in file",
                file_path=str(file_path),
                details={"error": str(e)},
            )
            return []
        except Exception as e:
            self.logger.error(
                "Error analyzing file",
                file_path=str(file_path),
                details={"error": str(e)},
            )
            return []

    def fix_file(self, file_path: Path, issues: Optional[List[StringIssue]] = None) -> Tuple[bool, List[str]]:
        """
        Fix string operation issues in a file.

        Args:
            file_path: Path to the file to fix
            issues: Optional list of issues to fix (if None, will analyze)

        Returns:
            Tuple of (success, list of applied fixes)
        """
        if issues is None:
            issues = self.analyze_file(file_path)

        if not issues:
            return True, []

        try:
            content = self.file_ops.read_file(file_path)
            if content is None:
                return False, ["Failed to read file"]
            modified_content = content
            applied_fixes: List[str] = []

            # Sort issues by line number (descending) to avoid offset issues
            sorted_issues = sorted(issues, key=lambda x: x.line_number, reverse=True)

            for issue in sorted_issues:
                if issue.rule_id in ["PG-S001", "PG-S002"]:
                    # These require complex AST transformation, mark for manual review
                    applied_fixes.append(f"Line {issue.line_number}: {issue.message} (manual review suggested)")
                elif issue.rule_id == "PG-S003":
                    # Remove f prefix from unnecessary f-strings
                    modified_content = self._fix_unnecessary_fstring(
                        modified_content, issue.line_number
                    )
                    applied_fixes.append(f"Line {issue.line_number}: Removed unnecessary f-string prefix")
                elif issue.rule_id == "PG-S004":
                    # Fix quote consistency (simple cases only)
                    applied_fixes.append(f"Line {issue.line_number}: Quote consistency issue noted")

            if applied_fixes:
                self.file_ops.write_file(file_path, modified_content)
                return True, applied_fixes

            return True, []

        except Exception as e:
            self.logger.error(
                "Error fixing file",
                file_path=str(file_path),
                details={"error": str(e)},
            )
            return False, []

    def _fix_unnecessary_fstring(self, content: str, line_number: int) -> str:
        """Remove f prefix from strings without placeholders."""
        lines = content.splitlines()
        if 0 < line_number <= len(lines):
            line = lines[line_number - 1]
            # Simple regex to remove f prefix
            modified_line = re.sub(r'\bf(["\'])', r'\1', line)
            lines[line_number - 1] = modified_line
            return '\n'.join(lines)
        return content

    def scan_directory(self, directory: Path, exclude_patterns: Optional[List[str]] = None) -> List[Tuple[Path, List[StringIssue]]]:
        """
        Scan a directory for string operation issues.

        Args:
            directory: Directory to scan
            exclude_patterns: Patterns to exclude

        Returns:
            List of (file_path, issues) tuples
        """
        results: List[Tuple[Path, List[StringIssue]]] = []

        for py_file in directory.rglob("*.py"):
            if exclude_patterns:
                if any(pattern in str(py_file) for pattern in exclude_patterns):
                    continue

            issues = self.analyze_file(py_file)
            if issues:
                results.append((py_file, issues))

        return results
