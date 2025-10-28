"""
Import management and analysis for Python code.

Provides import sorting, unused import detection, and import organization.
Implements isort-like functionality natively with additional analysis capabilities.
"""

import ast
from pathlib import Path

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class ImportAnalyzer:
    """Analyzes imports in Python code."""

    def __init__(self):
        """Initialize import analyzer."""
        self.logger = PyGuardLogger()

    def extract_imports(self, tree: ast.AST) -> dict[str, list[ast.AST]]:
        """
        Extract all imports from AST.

        Returns:
            Dict with keys: 'stdlib', 'third_party', 'local', 'future'
        """
        imports: dict[str, list[ast.AST]] = {
            "future": [],
            "stdlib": [],
            "third_party": [],
            "local": [],
        }

        stdlib_modules = self._get_stdlib_modules()

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                category = self._categorize_import(node, stdlib_modules)
                imports[category].append(node)

        return imports

    def find_unused_imports(self, tree: ast.AST, _code: str) -> set[str]:
        """Find imports that are never used.

        Args:
            tree: AST to analyze
            _code: Source code (reserved for advanced analysis)
        """
        imported_names = set()
        used_names = set()

        # Collect all imported names
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name.split(".")[0]
                    imported_names.add(name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        # Star imports - can't track usage reliably
                        continue
                    name = alias.asname if alias.asname else alias.name
                    imported_names.add(name)

        # Collect all used names (simple name references)
        class NameCollector(ast.NodeVisitor):
            def __init__(self):
                self.names = set()
                self.in_import = False

            def visit_Import(self, node):
                self.in_import = True
                self.generic_visit(node)
                self.in_import = False

            def visit_ImportFrom(self, node):
                self.in_import = True
                self.generic_visit(node)
                self.in_import = False

            def visit_Name(self, node):
                if not self.in_import:
                    self.names.add(node.id)
                self.generic_visit(node)

            def visit_Attribute(self, node):
                if not self.in_import and isinstance(node.value, ast.Name):
                    self.names.add(node.value.id)
                self.generic_visit(node)

        collector = NameCollector()
        collector.visit(tree)
        used_names = collector.names

        # Find unused
        return imported_names - used_names

    def sort_imports(self, code: str) -> str:
        """
        Sort imports in code following PEP 8 and isort conventions.

        Sections:
        1. __future__ imports
        2. Standard library
        3. Third-party
        4. Local/project

        Within each section: alphabetical order
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code

        lines = code.split("\n")
        imports = self.extract_imports(tree)

        # Find import block boundaries
        first_import_line = None
        last_import_line = None

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if first_import_line is None or node.lineno < first_import_line:
                    first_import_line = node.lineno
                if last_import_line is None or node.lineno > last_import_line:
                    last_import_line = node.lineno

        if first_import_line is None:
            return code  # No imports to sort

        # Sort imports by category
        sorted_imports = []

        for category in ["future", "stdlib", "third_party", "local"]:
            category_imports = imports[category]
            if category_imports:
                sorted_category = sorted(
                    [self._get_import_line(node, lines) for node in category_imports]
                )
                sorted_imports.extend(sorted_category)
                sorted_imports.append("")  # Blank line between sections

        # Remove trailing blank lines
        while sorted_imports and not sorted_imports[-1].strip():
            sorted_imports.pop()

        # Reconstruct code
        new_lines = lines[: first_import_line - 1] + sorted_imports + lines[last_import_line:]

        return "\n".join(new_lines)

    def _categorize_import(self, node: ast.AST, stdlib_modules: set[str]) -> str:
        """Categorize an import as future, stdlib, third_party, or local."""
        module_name = None

        if isinstance(node, ast.Import):
            module_name = node.names[0].name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module_name = node.module.split(".")[0]
            if node.level > 0:  # Relative import
                return "local"

        if module_name == "__future__":
            return "future"
        if module_name in stdlib_modules:
            return "stdlib"
        if module_name and module_name.startswith("."):
            return "local"
        return "third_party"

    def _get_stdlib_modules(self) -> set[str]:
        """Get set of standard library module names."""
        # Common stdlib modules (subset for efficiency)
        return {
            "abc",
            "argparse",
            "ast",
            "asyncio",
            "base64",
            "collections",
            "concurrent",
            "configparser",
            "contextlib",
            "copy",
            "csv",
            "dataclasses",
            "datetime",
            "decimal",
            "enum",
            "functools",
            "glob",
            "hashlib",
            "http",
            "importlib",
            "io",
            "itertools",
            "json",
            "logging",
            "math",
            "multiprocessing",
            "operator",
            "os",
            "pathlib",
            "pickle",
            "platform",
            "queue",
            "random",
            "re",
            "shutil",
            "signal",
            "socket",
            "sqlite3",
            "string",
            "struct",
            "subprocess",
            "sys",
            "tempfile",
            "threading",
            "time",
            "traceback",
            "typing",
            "unittest",
            "urllib",
            "warnings",
            "weakref",
            "xml",
            "zipfile",
        }

    def _get_import_line(self, node: ast.AST, lines: list[str]) -> str:
        """Get the source line for an import node."""
        if hasattr(node, "lineno"):
            return str(lines[node.lineno - 1])
        return ""


class ImportRule(Rule):
    """Base class for import-related rules."""

    def __init__(self, **kwargs):
        """Initialize import rule."""
        super().__init__(category=RuleCategory.IMPORT, **kwargs)


# Define import rules
UNUSED_IMPORT_RULE = ImportRule(
    rule_id="PG-I001",
    name="unused-import",
    severity=RuleSeverity.MEDIUM,
    message_template="Unused import: '{import_name}'",
    description="Import is never used in the file",
    explanation=(
        "Unused imports clutter code, slow down module loading, and can hide errors. "
        "Remove imports that aren't being used."
    ),
    fix_applicability=FixApplicability.AUTOMATIC,
    tags={"import", "unused", "cleanup"},
)

IMPORT_SHADOWING_RULE = ImportRule(
    rule_id="PG-I002",
    name="import-shadowing",
    severity=RuleSeverity.HIGH,
    message_template="Import '{import_name}' shadows built-in or previous import",
    description="Import name conflicts with built-in or earlier import",
    explanation=(
        "Shadowing built-ins or imports can cause confusing bugs. "
        "Use 'as' to rename the import or choose a different name."
    ),
    fix_applicability=FixApplicability.MANUAL,
    tags={"import", "naming", "builtin"},
)

UNSORTED_IMPORTS_RULE = ImportRule(
    rule_id="PG-I003",
    name="unsorted-imports",
    severity=RuleSeverity.LOW,
    message_template="Imports are not sorted according to PEP 8",
    description="Imports should be sorted: stdlib, third-party, local",
    explanation=(
        "PEP 8 recommends grouping imports in a specific order: "
        "__future__, stdlib, third-party, then local. Within each group, "
        "imports should be alphabetically sorted."
    ),
    fix_applicability=FixApplicability.AUTOMATIC,
    tags={"import", "style", "pep8"},
)

STAR_IMPORT_RULE = ImportRule(
    rule_id="PG-I004",
    name="star-import",
    severity=RuleSeverity.MEDIUM,
    message_template="Star import from '{module}' makes code harder to understand",
    description="Avoid wildcard imports (from module import *)",
    explanation=(
        "Star imports make it unclear which names are present in the namespace, "
        "complicate refactoring, and can lead to name conflicts. "
        "Import specific names instead."
    ),
    fix_applicability=FixApplicability.MANUAL,
    tags={"import", "best-practice", "clarity"},
)


def _detect_unused_imports(code: str, file_path: Path, tree: ast.AST | None = None):
    """Detect unused imports."""
    if tree is None:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

    analyzer = ImportAnalyzer()
    unused = analyzer.find_unused_imports(tree, code)

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name.split(".")[0]
                if name in unused:
                    violation = RuleViolation(
                        rule_id=UNUSED_IMPORT_RULE.rule_id,
                        category=UNUSED_IMPORT_RULE.category,
                        severity=UNUSED_IMPORT_RULE.severity,
                        message=UNUSED_IMPORT_RULE.format_message(import_name=name),
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_applicability=UNUSED_IMPORT_RULE.fix_applicability,
                    )
                    violations.append(violation)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                if name in unused:
                    violation = RuleViolation(
                        rule_id=UNUSED_IMPORT_RULE.rule_id,
                        category=UNUSED_IMPORT_RULE.category,
                        severity=UNUSED_IMPORT_RULE.severity,
                        message=UNUSED_IMPORT_RULE.format_message(import_name=name),
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_applicability=UNUSED_IMPORT_RULE.fix_applicability,
                    )
                    violations.append(violation)

    return violations


def _detect_star_imports(code: str, file_path: Path, tree: ast.AST | None = None):
    """Detect star imports."""
    if tree is None:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    module = node.module or "<relative>"
                    violation = RuleViolation(
                        rule_id=STAR_IMPORT_RULE.rule_id,
                        category=STAR_IMPORT_RULE.category,
                        severity=STAR_IMPORT_RULE.severity,
                        message=STAR_IMPORT_RULE.format_message(module=module),
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_applicability=STAR_IMPORT_RULE.fix_applicability,
                    )
                    violations.append(violation)

    return violations


# Note: Detection functions are handled by the Rule base class detect() method
# The ImportRule class can override detect() if needed for custom behavior


class ImportManager:
    """Main import manager class."""

    def __init__(self):
        """Initialize import manager."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.analyzer = ImportAnalyzer()

    def analyze_file(self, file_path: Path) -> list[RuleViolation]:
        """Analyze a file for import issues."""
        content = self.file_ops.read_file(file_path)
        if content is None:
            return []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        violations = []

        # Run all import rules
        violations.extend(_detect_unused_imports(content, file_path, tree))
        violations.extend(_detect_star_imports(content, file_path, tree))

        return violations

    def fix_imports(self, file_path: Path) -> tuple[bool, list[str]]:
        """
        Fix import issues in a file.

        Returns:
            Tuple of (success, list of fixes applied)
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return False, []

        fixes = []

        # Sort imports
        sorted_content = self.analyzer.sort_imports(content)
        if sorted_content != content:
            fixes.append("Sorted imports")
            content = sorted_content

        # Remove unused imports
        try:
            tree = ast.parse(content)
            unused_imports = self.analyzer.find_unused_imports(tree, content)

            if unused_imports:
                # Remove unused imports from the content
                lines = content.splitlines()
                lines_to_remove = set()

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            name = alias.asname if alias.asname else alias.name.split(".")[0]
                            if name in unused_imports:
                                # Mark line for removal if all imports on it are unused
                                lines_to_remove.add(node.lineno - 1)

                    elif isinstance(node, ast.ImportFrom):
                        names_to_keep = []
                        for alias in node.names:
                            if alias.name == "*":
                                continue
                            name = alias.asname if alias.asname else alias.name
                            if name not in unused_imports:
                                names_to_keep.append(alias)

                        # If all imports from this line are unused, mark for removal
                        if not names_to_keep and node.lineno:
                            lines_to_remove.add(node.lineno - 1)

                # Remove marked lines
                if lines_to_remove:
                    new_lines = [line for i, line in enumerate(lines) if i not in lines_to_remove]
                    content = "\n".join(new_lines)
                    fixes.append(f"Removed {len(lines_to_remove)} unused imports")

        except SyntaxError:
            # If there's a syntax error, skip unused import removal
            self.logger.warning(
                "Syntax error in file, skipping unused import removal",
                file_path=str(file_path),
            )

        if fixes:
            success = self.file_ops.write_file(file_path, content)
            return success, fixes

        return True, []


# Register all import rules
register_rules(
    [
        UNUSED_IMPORT_RULE,
        IMPORT_SHADOWING_RULE,
        UNSORTED_IMPORTS_RULE,
        STAR_IMPORT_RULE,
    ]
)
