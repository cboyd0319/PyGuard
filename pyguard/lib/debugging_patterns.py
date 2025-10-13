"""
Debugging pattern detection for Python code.

Detects debugging statements that should not be in production code:
- print() statements
- pdb/ipdb/breakpoint() calls
- Debug imports
- Console logging
"""

import ast
import re
from pathlib import Path
from typing import List, Optional

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class DebuggingPatternVisitor(ast.NodeVisitor):
    """AST visitor for detecting debugging patterns."""

    def __init__(self, file_path: Path, code: str):
        """Initialize visitor."""
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Visit call nodes to detect debugging function calls."""
        # T201: print() statements
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            self.violations.append(
                RuleViolation(
                    rule_id="T201",
                    message="print() statement found - use logging instead",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.STYLE,
                    fix_applicability=FixApplicability.SUGGESTED,
                    fix_suggestion="Replace with logger.info() or logger.debug()",
                )
            )

        # T100: breakpoint() statements
        elif isinstance(node.func, ast.Name) and node.func.id == "breakpoint":
            self.violations.append(
                RuleViolation(
                    rule_id="T100",
                    message="breakpoint() call found - should not be in production",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.ERROR,
                    fix_applicability=FixApplicability.AUTOMATIC,
                    fix_suggestion="Remove breakpoint() call",
                )
            )

        # T101: pdb.set_trace() statements
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "set_trace"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in ("pdb", "ipdb", "pudb")
        ):
            debugger = node.func.value.id
            self.violations.append(
                RuleViolation(
                    rule_id="T101",
                    message=f"{debugger}.set_trace() call found - should not be in production",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.ERROR,
                    fix_applicability=FixApplicability.AUTOMATIC,
                    fix_suggestion=f"Remove {debugger}.set_trace() call",
                )
            )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Visit import statements to detect debug imports."""
        for alias in node.names:
            # T102: Debug imports (pdb, ipdb, pudb)
            if alias.name in ("pdb", "ipdb", "pudb", "pdbpp"):
                self.violations.append(
                    RuleViolation(
                        rule_id="T102",
                        message=f"Debug import found: {alias.name}",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.STYLE,
                        fix_applicability=FixApplicability.AUTOMATIC,
                        fix_suggestion=f"Remove debug import: {alias.name}",
                    )
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit from-import statements to detect debug imports."""
        if node.module in ("pdb", "ipdb", "pudb", "pdbpp"):
            self.violations.append(
                RuleViolation(
                    rule_id="T102",
                    message=f"Debug import found: from {node.module}",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.STYLE,
                    fix_applicability=FixApplicability.AUTOMATIC,
                    fix_suggestion=f"Remove debug import from {node.module}",
                )
            )

        self.generic_visit(node)


class DebuggingPatternChecker:
    """Checks for debugging patterns in Python code."""

    def __init__(self):
        """Initialize checker."""
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a file for debugging patterns.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            tree = ast.parse(code)
            visitor = DebuggingPatternVisitor(file_path, code)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []

    def fix_file(self, file_path: Path) -> tuple[bool, int]:
        """
        Automatically fix debugging patterns in a file.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (success, number of fixes applied)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            original_code = code
            fixes_applied = 0

            # Remove/comment out debugging statements
            lines = code.splitlines()
            new_lines = []

            for line in lines:
                # Skip lines with breakpoint(), pdb.set_trace(), etc.
                if re.search(r"\bbreakpoint\s*\(", line):
                    new_lines.append(f"# {line}  # REMOVED by PyGuard")
                    fixes_applied += 1
                elif re.search(r"\b(pdb|ipdb|pudb)\.set_trace\s*\(", line):
                    new_lines.append(f"# {line}  # REMOVED by PyGuard")
                    fixes_applied += 1
                # Keep print statements but add a comment (user might need them)
                elif re.search(r"\bprint\s*\(", line):
                    if "# TODO: Replace with logging" not in line:
                        new_lines.append(f"{line}  # TODO: Replace with logging")
                        fixes_applied += 1
                    else:
                        new_lines.append(line)
                # Remove debug imports
                elif re.search(r"^import\s+(pdb|ipdb|pudb|pdbpp)\b", line):
                    new_lines.append(f"# {line}  # REMOVED by PyGuard")
                    fixes_applied += 1
                elif re.search(r"^from\s+(pdb|ipdb|pudb|pdbpp)\s+import", line):
                    new_lines.append(f"# {line}  # REMOVED by PyGuard")
                    fixes_applied += 1
                else:
                    new_lines.append(line)

            if fixes_applied > 0:
                fixed_code = "\n".join(new_lines)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(fixed_code)

                self.logger.info(
                    f"Fixed {fixes_applied} debugging patterns",
                    file_path=str(file_path),
                )
                return True, fixes_applied

            return True, 0

        except Exception as e:
            self.logger.error(f"Error fixing file: {e}", file_path=str(file_path))
            return False, 0


# Define rules for registration
DEBUGGING_RULES = [
    Rule(
        rule_id="T201",
        name="print-statement",
        description="print() statement found - use logging instead",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="print() statement found on line {line} - consider using logging",
    ),
    Rule(
        rule_id="T100",
        name="breakpoint-call",
        description="breakpoint() call found - should not be in production",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.AUTOMATIC,
        message_template="breakpoint() call found on line {line}",
    ),
    Rule(
        rule_id="T101",
        name="pdb-set-trace",
        description="pdb/ipdb/pudb.set_trace() call found",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.AUTOMATIC,
        message_template="Debug trace call found on line {line}",
    ),
    Rule(
        rule_id="T102",
        name="debug-import",
        description="Debug library import (pdb, ipdb, pudb)",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.AUTOMATIC,
        message_template="Debug import found on line {line}",
    ),
]

# Register rules
register_rules(DEBUGGING_RULES)
