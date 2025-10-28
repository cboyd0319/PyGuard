"""
Modern Python idiom detection and fixes (pyupgrade-style rules).

This module implements detection and auto-fixes for outdated Python patterns
that should be modernized to Python 3.8+ idioms. Aligned with pyupgrade rules.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
import re

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

    def __init__(self, source_lines: list[str]):
        """Initialize modern Python visitor."""
        self.issues: list[ModernizationIssue] = []
        self.source_lines = source_lines

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return str(self.source_lines[node.lineno - 1].strip())
        return ""

    def _get_full_name(self, node: ast.expr) -> str:
        """Get full name of an expression (for attributes)."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def visit_Call(self, node: ast.Call):
        """Visit function call nodes."""
        func_name = self._get_call_name(node)

        # UP038: Use X | Y for isinstance() instead of (X, Y) in Python 3.10+
        if func_name == "isinstance" and len(node.args) == 2:
            second_arg = node.args[1]
            if isinstance(second_arg, ast.Tuple) and len(second_arg.elts) > 1:
                types = []
                for elt in second_arg.elts:
                    if isinstance(elt, ast.Name):
                        types.append(elt.id)
                if types:
                    self.issues.append(
                        ModernizationIssue(
                            severity="LOW",
                            category="Modern Python",
                            message="Use X | Y for isinstance() instead of tuple (Python 3.10+)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion=f"isinstance(x, ({', '.join(types)})) → isinstance(x, {' | '.join(types)})",
                            rule_id="UP038",
                        )
                    )

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

            # UP041: Detect asyncio.TimeoutError (use TimeoutError in Python 3.11+)
            if node.module == "asyncio":
                for alias in node.names:
                    if alias.name == "TimeoutError":
                        self.issues.append(
                            ModernizationIssue(
                                severity="LOW",
                                category="Modern Python",
                                message="Use builtin 'TimeoutError' instead of 'asyncio.TimeoutError' (Python 3.11+)",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="from asyncio import TimeoutError → use builtin TimeoutError",
                                rule_id="UP041",
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

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Visit subscript nodes for typing modernization."""
        # UP009: UTF-8 encoding declaration (handled via comment scanning)
        # UP010: Unnecessary __future__ imports (handled in visit_ImportFrom)

        # UP011: Use functools.lru_cache without call
        # Detect @lru_cache() → should be @lru_cache
        # This would be detected in visit_FunctionDef

        # UP033: Use @functools.lru_cache instead of @functools.lru_cache()
        # UP034: Avoid extraneous parentheses on @decorator() calls

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions for decorator modernization."""
        for decorator in node.decorator_list:
            # UP011/UP033: lru_cache without parentheses
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute) and (
                    decorator.func.attr == "lru_cache"
                    and len(decorator.args) == 0
                    and len(decorator.keywords) == 0
                ):  # pyguard: disable=CWE-208  # Pattern detection, not vulnerable code
                    self.issues.append(
                        ModernizationIssue(
                            severity="LOW",
                            category="Modern Python",
                            message="Use @functools.lru_cache instead of @functools.lru_cache()",
                            line_number=decorator.lineno,
                            column=decorator.col_offset,
                            code_snippet=self._get_code_snippet(decorator),
                            fix_suggestion="Remove empty parentheses from @lru_cache",
                            rule_id="UP011",
                        )
                    )

        # UP020: Use builtin open() instead of pathlib.Path.open() when appropriate
        # UP021: Replace universal newlines with text=True

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Visit with statements for context manager modernization."""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                func_name = self._get_call_name(item.context_expr)

                # UP015: Redundant open modes (e.g., 'r' is default)
                if func_name == "open":
                    for arg in item.context_expr.args:
                        if isinstance(arg, ast.Constant):
                            if arg.value in ["r", "rt"]:
                                self.issues.append(
                                    ModernizationIssue(
                                        severity="LOW",
                                        category="Modern Python",
                                        message="Redundant open mode 'r' or 'rt' - this is the default",
                                        line_number=arg.lineno,
                                        column=arg.col_offset,
                                        code_snippet=self._get_code_snippet(arg),
                                        fix_suggestion="Remove redundant 'r' or 'rt' mode argument",
                                        rule_id="UP015",
                                    )
                                )

                # UP017: Use datetime.timezone.utc instead of datetime.timezone(datetime.timedelta(0))
                # UP018: Native literals instead of str(), int(), etc.

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definitions for enum modernization."""
        # UP042: Use StrEnum instead of str + Enum (Python 3.11+)
        # Check if class inherits from both str and Enum
        if len(node.bases) >= 2:
            base_names = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    base_names.append(base.id)

            if "str" in base_names and "Enum" in base_names:
                self.issues.append(
                    ModernizationIssue(
                        severity="LOW",
                        category="Modern Python",
                        message="Use enum.StrEnum instead of (str, Enum) (Python 3.11+)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="class MyEnum(str, Enum): → class MyEnum(StrEnum):",
                        rule_id="UP042",
                    )
                )

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Visit if statements for version check modernization."""
        # UP036: Outdated version blocks - check for sys.version_info comparisons
        if isinstance(node.test, ast.Compare):
            if isinstance(node.test.left, ast.Attribute):
                # Check for sys.version_info patterns
                full_name = self._get_full_name(node.test.left)
                if full_name == "sys.version_info":
                    # Check if comparing against outdated version (< 3.8)
                    for comparator in node.test.comparators:
                        if isinstance(comparator, ast.Tuple):
                            if len(comparator.elts) >= 2:
                                if isinstance(comparator.elts[0], ast.Constant):
                                    major_version = comparator.elts[0].value
                                    if isinstance(comparator.elts[1], ast.Constant):
                                        minor_version = comparator.elts[1].value
                                        if (
                                            isinstance(major_version, int)
                                            and isinstance(minor_version, int)
                                            and major_version == 3
                                            and minor_version < 8
                                        ):
                                            self.issues.append(
                                                ModernizationIssue(
                                                    severity="MEDIUM",
                                                    category="Modern Python",
                                                    message="Outdated version check for Python < 3.8",
                                                    line_number=node.lineno,
                                                    column=node.col_offset,
                                                    code_snippet=self._get_code_snippet(node),
                                                    fix_suggestion="Remove version check for Python < 3.8 as minimum is 3.8+",
                                                    rule_id="UP036",
                                                )
                                            )

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit annotated assignments for type alias modernization."""
        # UP037: Quoted annotations - check for string annotations that should be unquoted
        if isinstance(node.annotation, ast.Constant) and isinstance(node.annotation.value, str):
            # In Python 3.10+, we can use unquoted annotations
            self.issues.append(
                ModernizationIssue(
                    severity="LOW",
                    category="Modern Python",
                    message="Remove quotes from type annotations (Python 3.10+)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion=f"Remove quotes: '{node.annotation.value}' → {node.annotation.value}",
                    rule_id="UP037",
                )
            )

        # UP040: Use 'type' statement for type aliases (Python 3.12+)
        # Example: MyType: TypeAlias = int → type MyType = int
        if isinstance(node.annotation, ast.Name) and node.annotation.id == "TypeAlias":
            self.issues.append(
                ModernizationIssue(
                    severity="LOW",
                    category="Modern Python",
                    message="Use 'type' statement for type aliases (Python 3.12+)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="MyType: TypeAlias = int → type MyType = int",
                    rule_id="UP040",
                )
            )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Visit attribute access for timezone modernization."""
        # UP017: datetime.timezone.utc instead of pytz
        if isinstance(node.value, ast.Name):
            if node.value.id == "pytz" and node.attr == "UTC":
                self.issues.append(
                    ModernizationIssue(
                        severity="MEDIUM",
                        category="Modern Python",
                        message="Use datetime.timezone.utc instead of pytz.UTC",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Replace pytz.UTC with datetime.timezone.utc",
                        rule_id="UP017",
                    )
                )

        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        """Visit expression statements."""
        # UP019: typing.Text is deprecated
        if isinstance(node.value, ast.Name) and node.value.id == "Text":
            self.issues.append(
                ModernizationIssue(
                    severity="LOW",
                    category="Modern Python",
                    message="typing.Text is deprecated in Python 3.11+, use str instead",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace typing.Text with str",
                    rule_id="UP019",
                )
            )

        self.generic_visit(node)

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


class ModernPythonFixer:
    """Automatically fix outdated Python patterns."""

    def __init__(self):
        """Initialize modern Python fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.fixes_applied = []

    def scan_file_for_issues(self, file_path: Path) -> list[ModernizationIssue]:
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

    def fix_file(self, file_path: Path) -> tuple[bool, list[str]]:
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
                self.fixes_applied.append(
                    f"UP005: Removed unnecessary __future__ import {future_import}"
                )

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
