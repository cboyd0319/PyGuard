"""
Import Management Rules (TID/TCH/I) - Comprehensive import analysis and organization.

This module implements detection and auto-fixes for import-related issues including:
- TID (flake8-tidy-imports): Import organization and tidiness
- TCH (flake8-type-checking): Type-checking import optimization
- I (isort): Import sorting and grouping

References:
- flake8-tidy-imports: https://github.com/adamchainz/flake8-tidy-imports
- flake8-type-checking: https://github.com/snok/flake8-type-checking
- isort: https://pycqa.github.io/isort/
- Ruff import rules: https://docs.astral.sh/ruff/rules/#import-conventions
"""

import ast
from pathlib import Path

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class ImportVisitor(ast.NodeVisitor):
    """AST visitor for detecting import-related issues."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.imports: list[ast.Import] = []
        self.from_imports: list[ast.ImportFrom] = []
        self.type_checking_block = False
        self.in_type_checking_block_line = -1

    def visit_Import(self, node: ast.Import) -> None:
        """Detect Import statement issues (TID001-TID003, I001-I003)."""
        self.imports.append(node)

        # TID001: Banned imports (configurable)
        banned_modules = ["os.path"]  # Should use pathlib
        for alias in node.names:
            if alias.name in banned_modules:
                self.violations.append(
                    RuleViolation(
                        rule_id="TID001",
                        message=f"Import '{alias.name}' is banned - use alternative",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # TID002: Relative imports beyond parent (dangerous)
        # Handled in visit_ImportFrom

        # TID003: Import module only, not from import for certain modules
        # Example: import typing vs from typing import Dict
        # This is a style choice

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Detect ImportFrom statement issues (TID002-TID005, TCH001-TCH003)."""
        self.from_imports.append(node)

        # TID002: Relative imports beyond parent level
        if node.level and node.level > 2:
            self.violations.append(
                RuleViolation(
                    rule_id="TID002",
                    message=f"Relative import with level {node.level} is too deep - max 2 levels recommended",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.CONVENTION,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        # TID004: Import from future should be at top
        if node.module == "__future__":
            # Check if it's not at the top (allowing docstring)
            if node.lineno > 10:  # Heuristic: should be in first 10 lines
                self.violations.append(
                    RuleViolation(
                        rule_id="TID004",
                        message="__future__ imports should be at the top of the file",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.ERROR,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # TID005: Banned from imports
        if node.module and node.module.startswith("typing"):
            # Check if we're in TYPE_CHECKING block
            if not self.type_checking_block:
                # TCH001: Type checking imports should be in TYPE_CHECKING block
                type_only_imports = {"TYPE_CHECKING", "Protocol", "TypedDict", "TypeAlias"}
                for alias in node.names:
                    if alias.name in type_only_imports and alias.name != "TYPE_CHECKING":
                        self.violations.append(
                            RuleViolation(
                                rule_id="TCH001",
                                message=f"Move type-only import '{alias.name}' into TYPE_CHECKING block",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.PERFORMANCE,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        # TCH002: Type-checking imports for third-party types
        if node.module in ["numpy", "pandas", "django", "flask"]:
            # Check if imported for type hints only
            # This requires flow analysis to determine if used at runtime
            pass

        # TCH003: Type-checking imports in TYPE_CHECKING block used at runtime
        if self.type_checking_block:
            # Would need to track usage to detect this
            pass

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Detect TYPE_CHECKING blocks."""
        # Check if this is a TYPE_CHECKING block
        if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
            self.type_checking_block = True
            self.in_type_checking_block_line = node.lineno
        elif isinstance(node.test, ast.Attribute):
            if node.test.attr == "TYPE_CHECKING":
                self.type_checking_block = True
                self.in_type_checking_block_line = node.lineno

        self.generic_visit(node)
        self.type_checking_block = False


class ImportOrderChecker:
    """Check import ordering and grouping (isort rules)."""

    def __init__(self):
        self.logger = PyGuardLogger()

    def check_import_order(self, file_path: Path, code: str) -> list[RuleViolation]:
        """
        Check if imports are properly ordered according to PEP 8.

        Import order should be:
        1. Standard library
        2. Third-party
        3. Local/first-party

        Within each group, imports should be alphabetically sorted.
        """
        violations: list[RuleViolation] = []

        try:
            tree = ast.parse(code)
            imports = []

            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    imports.append(node)

            # I001: Import block not sorted
            # Check if imports are grouped correctly
            stdlib_modules = {
                "os",
                "sys",
                "re",
                "json",
                "pathlib",
                "typing",
                "collections",
                "datetime",
                "itertools",
                "functools",
                "io",
                "abc",
                "contextlib",
                "ast",
                "unittest",
                "logging",
                "warnings",
                "traceback",
                "time",
            }

            prev_group = -1
            for node in imports:
                if isinstance(node, ast.Import):
                    module = node.names[0].name.split(".")[0]
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module = node.module.split(".")[0]
                    else:
                        continue  # Relative import
                # No else needed - only Import and ImportFrom are added to imports list

                # Determine group: 0=stdlib, 1=third-party, 2=local
                if module in stdlib_modules:
                    curr_group = 0
                elif module.startswith("."):
                    curr_group = 2
                else:
                    curr_group = 1

                # Check if order is violated
                if curr_group < prev_group:
                    violations.append(
                        RuleViolation(
                            rule_id="I001",
                            message=f"Import group out of order: {module} (group {curr_group}) after group {prev_group}",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

                prev_group = curr_group

            # I002: Missing blank line between import groups
            # Would need to check line spacing between imports

        except SyntaxError:
            pass

        return violations


class ImportRulesChecker:
    """Main checker for import rules."""

    def __init__(self):
        self.logger = PyGuardLogger()
        self.order_checker = ImportOrderChecker()

    def check_file(self, file_path: Path) -> list[RuleViolation]:
        """
        Check a Python file for import issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            violations = []

            # AST-based checks
            tree = ast.parse(code)
            visitor = ImportVisitor(file_path, code)
            visitor.visit(tree)
            violations.extend(visitor.violations)

            # Import order checks
            order_violations = self.order_checker.check_import_order(file_path, code)
            violations.extend(order_violations)

            return violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []

    def fix_file(self, file_path: Path) -> tuple[bool, int]:
        """
        Automatically fix import issues in a file.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (success, number of fixes applied)
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            fixes_applied = 0

            # Auto-fix: Move __future__ imports to top
            # This is complex and requires careful AST manipulation
            # We'll implement in a future iteration

            # Auto-fix: Sort imports using isort
            # For now, we'll leave this to the external isort tool
            # Or implement a simple alphabetical sort

            if fixes_applied > 0:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(code)

                self.logger.info(
                    f"Fixed {fixes_applied} import issues",
                    file_path=str(file_path),
                )
                return True, fixes_applied

            return True, 0

        except Exception as e:
            self.logger.error(f"Error fixing file: {e}", file_path=str(file_path))
            return False, 0


# Define rules for registration
IMPORT_RULES = [
    Rule(
        rule_id="TID001",
        name="banned-imports",
        description="Banned module imports",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Import is banned - use recommended alternative",
    ),
    Rule(
        rule_id="TID002",
        name="relative-imports-level",
        description="Relative imports should not be too deep",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Avoid deep relative imports (max 2 levels)",
    ),
    Rule(
        rule_id="TID004",
        name="future-imports-position",
        description="__future__ imports must be at top of file",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SAFE,
        message_template="Move __future__ imports to the top",
    ),
    Rule(
        rule_id="TCH001",
        name="type-checking-imports",
        description="Type-only imports should be in TYPE_CHECKING block",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Move type-only imports to TYPE_CHECKING block for runtime performance",
    ),
    Rule(
        rule_id="TCH002",
        name="third-party-type-imports",
        description="Third-party type imports should be in TYPE_CHECKING block",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Move third-party type imports to TYPE_CHECKING block",
    ),
    Rule(
        rule_id="TCH003",
        name="typing-only-standard-library-import",
        description="Standard library import used only for type annotations",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Move standard library type import to TYPE_CHECKING block",
    ),
    Rule(
        rule_id="I001",
        name="unsorted-imports",
        description="Import groups are not properly sorted",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Sort imports: stdlib, third-party, then local",
    ),
    Rule(
        rule_id="I002",
        name="missing-required-import-newline",
        description="Missing blank line between import groups",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Add blank line between import groups",
    ),
]
