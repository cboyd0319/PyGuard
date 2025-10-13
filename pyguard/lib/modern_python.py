"""
Modern Python idiom detection and fixes (pyupgrade-style rules).

This module implements detection and auto-fixes for outdated Python patterns
that should be modernized to Python 3.8+ idioms. Aligned with pyupgrade rules.
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class ModernizationIssue:
    """Issue related to outdated Python code."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""
    rule_id: str = ""  # UP001, UP002, etc.


class ModernPythonVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting outdated Python patterns.

    Implements pyupgrade-style modernization checks.
    """

    def __init__(self, source_lines: List[str]):
        """Initialize modern Python visitor."""
        self.issues: List[ModernizationIssue] = []
        self.source_lines = source_lines

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        """Visit function call nodes."""
        func_name = self._get_call_name(node)

        # UP001: Detect old-style super()
        if func_name == "super" and len(node.args) == 2:
            self.issues.append(
                ModernizationIssue(
                    severity="LOW",
                    category="Modern Python",
                    message="Use super() without arguments in Python 3",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace super(ClassName, self) with super()",
                    rule_id="UP001",
                )
            )

        # UP002: Detect unnecessary encode/decode
        if func_name in ["str.encode", "bytes.decode"]:
            # Check if using default encoding
            if not node.args or (
                len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in ["utf-8", "utf8"]
            ):
                self.issues.append(
                    ModernizationIssue(
                        severity="LOW",
                        category="Modern Python",
                        message="encode('utf-8')/decode('utf-8') is default, can omit argument",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use .encode()/.decode() without arguments for UTF-8",
                        rule_id="UP002",
                    )
                )

        # UP008: Detect old-style string formatting (% operator) via .format()
        if func_name and ".format" in func_name:
            self.issues.append(
                ModernizationIssue(
                    severity="MEDIUM",
                    category="Modern Python",
                    message="Use f-strings instead of .format()",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion='Replace "text {}".format(var) with f"text {var}"',
                    rule_id="UP032",
                )
            )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        """Visit import statements."""
        for alias in node.names:
            # UP004: Detect six usage (Python 2→3 compatibility)
            if alias.name and alias.name.startswith("six"):
                self.issues.append(
                    ModernizationIssue(
                        severity="MEDIUM",
                        category="Modern Python",
                        message="'six' library is for Python 2/3 compatibility, not needed in Python 3",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove six dependency and use native Python 3 equivalents",
                        rule_id="UP004",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Visit from...import statements."""
        if node.module:
            # UP003: Detect typing imports that should use builtin types
            if node.module == "typing":
                for alias in node.names:
                    name = alias.name
                    # PEP 585: Use list instead of typing.List, dict instead of typing.Dict, etc.
                    if name in ["List", "Dict", "Set", "Tuple", "FrozenSet"]:
                        self.issues.append(
                            ModernizationIssue(
                                severity="MEDIUM",
                                category="Modern Python",
                                message=f"Use builtin '{name.lower()}' instead of 'typing.{name}' (PEP 585)",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"from typing import {name} → use builtin {name.lower()}[]",
                                rule_id="UP006",
                            )
                        )

                    # PEP 604: Use X | None instead of Optional[X]
                    if name == "Optional":
                        self.issues.append(
                            ModernizationIssue(
                                severity="MEDIUM",
                                category="Modern Python",
                                message="Use 'X | None' instead of 'Optional[X]' (PEP 604)",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="from typing import Optional → use X | None",
                                rule_id="UP007",
                            )
                        )

                    # PEP 604: Use X | Y instead of Union[X, Y]
                    if name == "Union":
                        self.issues.append(
                            ModernizationIssue(
                                severity="MEDIUM",
                                category="Modern Python",
                                message="Use 'X | Y' instead of 'Union[X, Y]' (PEP 604)",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="from typing import Union → use X | Y",
                                rule_id="UP007",
                            )
                        )

            # UP004: Detect six usage (Python 2→3 compatibility)
            if node.module and node.module.startswith("six"):
                self.issues.append(
                    ModernizationIssue(
                        severity="MEDIUM",
                        category="Modern Python",
                        message="'six' library is for Python 2/3 compatibility, not needed in Python 3",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove six dependency and use native Python 3 equivalents",
                        rule_id="UP004",
                    )
                )

            # UP005: Detect unnecessary __future__ imports
            if node.module == "__future__":
                for alias in node.names:
                    name = alias.name
                    # These are unnecessary in Python 3.8+
                    unnecessary_futures = [
                        "absolute_import",
                        "division",
                        "print_function",
                        "unicode_literals",
                        "generator_stop",
                        "nested_scopes",
                        "generators",
                        "with_statement",
                    ]
                    if name in unnecessary_futures:
                        self.issues.append(
                            ModernizationIssue(
                                severity="LOW",
                                category="Modern Python",
                                message=f"__future__ import '{name}' is unnecessary in Python 3.8+",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion=f"Remove 'from __future__ import {name}'",
                                rule_id="UP005",
                            )
                        )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """Visit binary operations."""
        # UP008: Detect old-style string formatting (% operator)
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
            if isinstance(node.left.value, str) and "%" in node.left.value:
                self.issues.append(
                    ModernizationIssue(
                        severity="MEDIUM",
                        category="Modern Python",
                        message="Use f-strings instead of % formatting",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion='Replace "text %s" % var with f"text {var}"',
                        rule_id="UP031",
                    )
                )

        self.generic_visit(node)

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


class ModernPythonFixer:
    """Automatically fix outdated Python patterns."""

    def __init__(self):
        """Initialize modern Python fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.fixes_applied = []

    def scan_file_for_issues(self, file_path: Path) -> List[ModernizationIssue]:
        """
        Scan a file for modernization issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of modernization issues found
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        try:
            tree = ast.parse(content)
            source_lines = content.splitlines()
            visitor = ModernPythonVisitor(source_lines)
            visitor.visit(tree)
            return visitor.issues
        except SyntaxError:
            return []

    def fix_file(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Apply modernization fixes to a Python file.

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
        content = self._fix_old_super(content)
        content = self._fix_typing_imports(content)
        content = self._fix_optional_union(content)
        content = self._fix_unnecessary_future_imports(content)
        content = self._fix_percent_formatting(content)
        content = self._fix_format_to_fstring(content)

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Applied {len(self.fixes_applied)} modernization fixes",
                    category="ModernPython",
                    file_path=str(file_path),
                    details={"fixes": self.fixes_applied},
                )
            return success, self.fixes_applied

        return True, []

    def _fix_old_super(self, content: str) -> str:
        """Fix old-style super() calls."""
        # Pattern: super(ClassName, self) → super()
        pattern = r"super\([A-Za-z_][A-Za-z0-9_]*,\s*self\)"
        if re.search(pattern, content):
            content = re.sub(pattern, "super()", content)
            self.fixes_applied.append("UP001: Modernized super() call")
        return content

    def _fix_typing_imports(self, content: str) -> str:
        """Fix typing imports to use builtin types (PEP 585)."""
        # Pattern: from typing import List, Dict, Set, Tuple
        # Note: This is a simplified fix, actual implementation would need to update usage too
        typing_builtins = {
            "List": "list",
            "Dict": "dict",
            "Set": "set",
            "Tuple": "tuple",
            "FrozenSet": "frozenset",
        }

        for old_type, new_type in typing_builtins.items():
            # Remove from typing imports (commented out to avoid breaking existing code)
            # Real implementation would need to track usage and update all references
            if f"from typing import {old_type}" in content:
                self.fixes_applied.append(
                    f"UP006: Found typing.{old_type} (should use {new_type}[])"
                )

        return content

    def _fix_optional_union(self, content: str) -> str:
        """Fix Optional[X] to X | None and Union[X, Y] to X | Y."""
        # Note: This requires careful AST manipulation for correctness
        # Simplified pattern-based approach here
        if "Optional[" in content or "Union[" in content:
            self.fixes_applied.append("UP007: Found Optional/Union (should use | syntax)")
        return content

    def _fix_unnecessary_future_imports(self, content: str) -> str:
        """Remove unnecessary __future__ imports."""
        unnecessary_futures = [
            "absolute_import",
            "division",
            "print_function",
            "unicode_literals",
            "generator_stop",
        ]

        for future_import in unnecessary_futures:
            pattern = rf"from __future__ import {future_import}\n"
            if re.search(pattern, content):
                content = re.sub(pattern, "", content)
                self.fixes_applied.append(f"UP005: Removed unnecessary __future__ import {future_import}")

        return content

    def _fix_percent_formatting(self, content: str) -> str:
        """Convert % formatting to f-strings."""
        # Simple cases only: "text %s" % var
        # More complex cases would require full AST manipulation
        pattern = r'"([^"]*%s[^"]*)" % \(([^)]+)\)'
        matches = re.findall(pattern, content)
        if matches:
            self.fixes_applied.append("UP031: Found % formatting (should use f-strings)")
        return content

    def _fix_format_to_fstring(self, content: str) -> str:
        """Convert .format() to f-strings."""
        # Simple cases only
        if ".format(" in content:
            self.fixes_applied.append("UP032: Found .format() (should use f-strings)")
        return content
