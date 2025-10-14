"""
FURB (refurb) - Refactoring opportunities and code modernization patterns.

This module implements detection and auto-fixes for refactoring opportunities
that make Python code more modern, efficient, and idiomatic.

References:
- Refurb tool: https://github.com/dosisod/refurb
- Ruff FURB rules: https://docs.astral.sh/ruff/rules/#refurb-furb
"""

import ast
import re
from pathlib import Path
from typing import List, Tuple

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class RefurbPatternVisitor(ast.NodeVisitor):
    """AST visitor for detecting refactoring opportunities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []

    def visit_While(self, node: ast.While) -> None:
        """Detect while loops that should be for loops (FURB101)."""
        # Check for pattern: while line := file.read(...):
        # Better: for line in file:
        if isinstance(node.test, ast.NamedExpr):
            # Check if it's a file.read() or file.readline() pattern
            if isinstance(node.test.value, ast.Call):
                if isinstance(node.test.value.func, ast.Attribute):
                    attr = node.test.value.func
                    if attr.attr in ("read", "readline", "readlines"):
                        self.violations.append(
                            RuleViolation(
                                rule_id="FURB101",
                                message=f"Use 'for {node.test.target.id if isinstance(node.test.target, ast.Name) else 'line'} in file' instead of while with assignment",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect various refactoring opportunities in function calls (FURB102-118)."""
        # FURB102: sorted() on list comprehension - use generator instead
        if isinstance(node.func, ast.Name) and node.func.id == "sorted":
            if len(node.args) > 0 and isinstance(node.args[0], ast.ListComp):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB102",
                        message="Use generator expression instead of list comprehension with sorted()",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.PERFORMANCE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # FURB103: open() without context manager
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            # Check if this is inside a 'with' statement
            # This requires checking parent nodes which we'll implement in checker
            pass

        # FURB104: Unnecessary list() around sorted()
        if isinstance(node.func, ast.Name) and node.func.id == "list":
            if len(node.args) > 0 and isinstance(node.args[0], ast.Call):
                inner_call = node.args[0]
                if isinstance(inner_call.func, ast.Name) and inner_call.func.id == "sorted":
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB104",
                            message="Unnecessary list() wrapper around sorted() - sorted() already returns a list",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SIMPLIFICATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        # FURB105: print() with sep="" - use ''.join() instead
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            for keyword in node.keywords:
                if keyword.arg == "sep" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value == "":
                        self.violations.append(
                            RuleViolation(
                                rule_id="FURB105",
                                message="Use ''.join() instead of print() with sep=''",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.SIMPLIFICATION,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        # FURB109: Use int() instead of math.floor()/ceil() for integers
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "math"
                and node.func.attr in ("floor", "ceil")
            ):
                if len(node.args) > 0 and isinstance(node.args[0], (ast.Constant, ast.Name)):
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB109",
                            message=f"Use int() instead of math.{node.func.attr}() for integer conversion",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SIMPLIFICATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

        # FURB111: Use Path.iterdir() instead of os.listdir()
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "listdir"
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB111",
                        message="Use Path.iterdir() instead of os.listdir() for better path handling",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # FURB113: Use extend() instead of repeated append()
        # This requires tracking multiple statements, handled separately

        # FURB114: Use str.replace() method
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Attribute)
                and node.func.value.func.attr == "split"
                and node.func.attr == "join"
            ):
                # Pattern: ''.join(s.split())
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB114",
                        message="Consider using str.replace() for simple string replacements",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # FURB117: Use min()/max() with default parameter
        if isinstance(node.func, ast.Name) and node.func.id in ("min", "max"):
            # Check if this is being used in try-except for empty sequence
            # This requires context, will be checked in separate pass
            pass

        # FURB120: Use dict.setdefault()
        # This requires checking if-not-in-dict pattern, handled separately

        # FURB122: Use str.removeprefix()/removesuffix() (Python 3.9+)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "replace" and len(node.args) == 2:
                # Check if replacing prefix/suffix with empty string
                if isinstance(node.args[1], ast.Constant) and node.args[1].value == "":
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB122",
                            message="Consider using str.removeprefix() or str.removesuffix() for Python 3.9+",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.MODERNIZATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

        # FURB128: Merge isinstance() calls
        if isinstance(node.func, ast.Name) and node.func.id == "isinstance":
            if len(node.args) == 2 and isinstance(node.args[1], ast.Tuple):
                # Good pattern - already using tuple
                pass
            elif len(node.args) == 2:
                # Could suggest tuple for future combining
                pass

        # FURB132: Use max() instead of sorted()[-1]
        if isinstance(node.func, ast.Name) and node.func.id == "sorted":
            # Will check for [-1] subscript in parent node
            pass

        # FURB133: Use min() instead of sorted()[0]
        if isinstance(node.func, ast.Name) and node.func.id == "sorted":
            # Will check for [0] subscript in parent node
            pass

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Detect with statement patterns."""
        # Check for pathlib usage opportunities
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                if isinstance(item.context_expr.func, ast.Name):
                    if item.context_expr.func.id == "open":
                        # Check if using string paths instead of Path objects
                        if len(item.context_expr.args) > 0:
                            arg = item.context_expr.args[0]
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="FURB106",
                                        message="Consider using pathlib.Path instead of string paths with open()",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.LOW,
                                        category=RuleCategory.MODERNIZATION,
                                        file_path=self.file_path,
                                        fix_applicability=FixApplicability.SUGGESTED,
                                    )
                                )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect comparison patterns that could be improved."""
        # FURB107: sys.version_info >= (3, x) - use sys.version_info >= (3, x, 0) for clarity
        if isinstance(node.left, ast.Attribute):
            if (
                isinstance(node.left.value, ast.Name)
                and node.left.value.id == "sys"
                and node.left.attr == "version_info"
            ):
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Tuple):
                        if len(comparator.elts) == 2:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FURB107",
                                    message="Use full version tuple (3, x, 0) for sys.version_info comparisons",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.CONVENTION,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Detect attribute access patterns (FURB108, FURB115, FURB121)."""
        # FURB108: os.path.join() should use Path() / operator
        if isinstance(node.value, ast.Attribute):
            if (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "path"
                and node.attr in ("join", "exists", "isfile", "isdir")
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB108",
                        message=f"Use pathlib.Path instead of os.path.{node.attr}()",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # FURB115: Use pathlib for path operations
        if isinstance(node.value, ast.Attribute):
            if (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "path"
                and node.attr in ("abspath", "dirname", "basename", "splitext")
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB115",
                        message=f"Use pathlib.Path.{node.attr}() instead of os.path.{node.attr}()",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # FURB121: Use pathlib's stat methods
        if isinstance(node.value, ast.Attribute):
            if (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "path"
                and node.attr in ("getsize", "getmtime", "getctime")
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB121",
                        message=f"Use Path.stat().st_size/st_mtime instead of os.path.{node.attr}()",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect subscript patterns (FURB132, FURB133)."""
        # FURB132: Use max() instead of sorted()[-1]
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id == "sorted":
                if isinstance(node.slice, ast.UnaryOp):
                    if isinstance(node.slice.op, ast.USub) and isinstance(node.slice.operand, ast.Constant):
                        if node.slice.operand.value == 1:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FURB132",
                                    message="Use max() instead of sorted()[-1] for better performance",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.PERFORMANCE,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )
                # FURB133: Use min() instead of sorted()[0]
                elif isinstance(node.slice, ast.Constant) and node.slice.value == 0:
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB133",
                            message="Use min() instead of sorted()[0] for better performance",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.PERFORMANCE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Detect if statement patterns (FURB110, FURB120)."""
        # FURB110: Use if-else expression instead of separate if statements
        # Check for pattern: if cond: x = a; else: x = b → x = a if cond else b
        if len(node.body) == 1 and len(node.orelse) == 1:
            if isinstance(node.body[0], ast.Assign) and isinstance(node.orelse[0], ast.Assign):
                if_assign = node.body[0]
                else_assign = node.orelse[0]
                # Check if assigning to same target
                if (
                    len(if_assign.targets) == 1
                    and len(else_assign.targets) == 1
                    and isinstance(if_assign.targets[0], ast.Name)
                    and isinstance(else_assign.targets[0], ast.Name)
                    and if_assign.targets[0].id == else_assign.targets[0].id
                ):
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB110",
                            message="Use conditional expression: x = a if cond else b",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SIMPLIFICATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        # FURB120: Use dict.setdefault()
        # Pattern: if key not in dict: dict[key] = value
        if isinstance(node.test, ast.Compare):
            if len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.NotIn):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Assign):
                    assign = node.body[0]
                    if len(assign.targets) == 1 and isinstance(assign.targets[0], ast.Subscript):
                        self.violations.append(
                            RuleViolation(
                                rule_id="FURB120",
                                message="Use dict.setdefault(key, value) instead of if-not-in pattern",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.SIMPLIFICATION,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Detect for loop patterns (FURB113)."""
        # FURB113: Use extend() instead of repeated append() in loop
        if len(node.body) == 1 and isinstance(node.body[0], ast.Expr):
            expr = node.body[0].value
            if isinstance(expr, ast.Call):
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "append":
                    # Check if appending loop variable
                    if len(expr.args) == 1:
                        self.violations.append(
                            RuleViolation(
                                rule_id="FURB113",
                                message="Use list.extend() or list comprehension instead of append() in loop",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.PERFORMANCE,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        self.generic_visit(node)


class RefurbPatternChecker:
    """Main checker for refactoring pattern detection and fixes."""

    def __init__(self):
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a Python file for refactoring opportunities.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            tree = ast.parse(code)
            visitor = RefurbPatternVisitor(file_path, code)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []

    def fix_file(self, file_path: Path) -> Tuple[bool, int]:
        """
        Automatically fix refactoring opportunities in a file.

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

            # Fix FURB104: Remove unnecessary list() around sorted()
            pattern = r"\blist\(sorted\("
            if re.search(pattern, code):
                code = re.sub(r"\blist\(sorted\(([^)]+)\)\)", r"sorted(\1)", code)
                fixes_applied += len(re.findall(pattern, original_code))

            # Fix FURB102: Convert list comprehension to generator in sorted()
            # This is more complex and requires AST manipulation
            # We'll implement this in a future iteration

            if fixes_applied > 0:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(code)

                self.logger.info(
                    f"Fixed {fixes_applied} refactoring opportunities",
                    file_path=str(file_path),
                )
                return True, fixes_applied

            return True, 0

        except Exception as e:
            self.logger.error(f"Error fixing file: {e}", file_path=str(file_path))
            return False, 0


# Define rules for registration
REFURB_RULES = [
    Rule(
        rule_id="FURB101",
        name="while-read-loop",
        description="Use 'for line in file' instead of while with assignment",
        category=RuleCategory.REFACTOR,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using a for loop instead of while with assignment for file reading",
    ),
    Rule(
        rule_id="FURB102",
        name="sorted-list-comp",
        description="Use generator expression instead of list comprehension with sorted()",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use generator expression for better performance: sorted(x for x in ...)",
    ),
    Rule(
        rule_id="FURB104",
        name="unnecessary-list-sorted",
        description="Unnecessary list() wrapper around sorted()",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove list() - sorted() already returns a list",
    ),
    Rule(
        rule_id="FURB105",
        name="print-sep-empty",
        description="Use ''.join() instead of print() with sep=''",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using ''.join() for string concatenation instead of print()",
    ),
    Rule(
        rule_id="FURB106",
        name="string-paths-with-open",
        description="Consider using pathlib.Path instead of string paths",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use Path objects from pathlib for better path handling",
    ),
    Rule(
        rule_id="FURB107",
        name="version-info-tuple",
        description="Use full version tuple for sys.version_info comparisons",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use (major, minor, micro) format for version comparisons",
    ),
    Rule(
        rule_id="FURB108",
        name="os-path-to-pathlib",
        description="Use pathlib.Path instead of os.path operations",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using pathlib.Path for better path handling",
    ),
    Rule(
        rule_id="FURB109",
        name="int-instead-of-math-floor-ceil",
        description="Use int() instead of math.floor()/ceil() for integers",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use int() for simple integer conversion",
    ),
    Rule(
        rule_id="FURB110",
        name="if-else-expression",
        description="Use if-else expression instead of separate if statements",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use conditional expression: x = a if cond else b",
    ),
    Rule(
        rule_id="FURB111",
        name="path-iterdir",
        description="Use Path.iterdir() instead of os.listdir()",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use pathlib.Path.iterdir() for better path handling",
    ),
    Rule(
        rule_id="FURB113",
        name="repeated-append",
        description="Use extend() or list comprehension instead of repeated append()",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use list.extend() or list comprehension for better performance",
    ),
    Rule(
        rule_id="FURB114",
        name="simplify-string-operations",
        description="Use str.replace() for simple string replacements",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Consider using str.replace() for simple replacements",
    ),
    Rule(
        rule_id="FURB115",
        name="pathlib-for-paths",
        description="Use pathlib for path operations",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use pathlib.Path methods instead of os.path",
    ),
    Rule(
        rule_id="FURB120",
        name="dict-setdefault",
        description="Use dict.setdefault() instead of if-not-in pattern",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use dict.setdefault(key, value) for cleaner code",
    ),
    Rule(
        rule_id="FURB121",
        name="pathlib-stat-methods",
        description="Use pathlib's stat methods instead of os.path",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use Path.stat() methods for file metadata",
    ),
    Rule(
        rule_id="FURB122",
        name="str-removeprefix-suffix",
        description="Use str.removeprefix()/removesuffix() for Python 3.9+",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use removeprefix()/removesuffix() for cleaner code",
    ),
    Rule(
        rule_id="FURB132",
        name="max-instead-of-sorted-last",
        description="Use max() instead of sorted()[-1]",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use max() for better performance - O(n) vs O(n log n)",
    ),
    Rule(
        rule_id="FURB133",
        name="min-instead-of-sorted-first",
        description="Use min() instead of sorted()[0]",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use min() for better performance - O(n) vs O(n log n)",
    ),
]
