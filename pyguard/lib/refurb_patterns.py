"""
FURB (refurb) - Refactoring opportunities and code modernization patterns.

This module implements detection and auto-fixes for refactoring opportunities
that make Python code more modern, efficient, and idiomatic.

References:
- Refurb tool: https://github.com/dosisod/refurb
- Ruff FURB rules: https://docs.astral.sh/ruff/rules/#refurb-furb
"""

import ast
from pathlib import Path
import re

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
        # TODO: Add docstring
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []

    def visit_While(self, node: ast.While) -> None:
        """Detect while loops that should be for loops (FURB101)."""
        # Check for pattern: while line := file.read(...):
        # Better: for line in file:
        if isinstance(node.test, ast.NamedExpr) and isinstance(node.test.value, ast.Call) and isinstance(node.test.value.func, ast.Attribute):
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

    def visit_Call(self, node: ast.Call) -> None:  # noqa: PLR0912 - Complex refactoring pattern detection requires many checks
        """Detect various refactoring opportunities in function calls (FURB102-118)."""
        # FURB102: sorted() on list comprehension - use generator instead
        if isinstance(node.func, ast.Name) and node.func.id == "sorted" and len(node.args) > 0 and isinstance(node.args[0], ast.ListComp):
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
        if isinstance(node.func, ast.Name) and node.func.id == "list" and len(node.args) > 0 and isinstance(node.args[0], ast.Call):
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
                if keyword.arg == "sep" and isinstance(keyword.value, ast.Constant) and keyword.value.value == "":
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

        # FURB106: String path with open() - use Path
        if isinstance(node.func, ast.Name) and node.func.id == "open" and len(node.args) > 0:
            first_arg = node.args[0]
            # Check if first argument is a string constant (not a Path object)
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB106",
                        message="Use pathlib.Path for file paths instead of strings",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # FURB109: Use int() instead of math.floor()/ceil() for integers
        if isinstance(node.func, ast.Attribute):  # noqa: SIM102
            if (  # noqa: SIM102
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
        if isinstance(node.func, ast.Attribute) and (
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
        if isinstance(node.func, ast.Attribute) and (
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
        if isinstance(node.func, ast.Attribute) and node.func.attr == "replace" and len(node.args) == 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value == "":  # noqa: PLR2004 - threshold
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
            if len(node.args) == 2 and isinstance(node.args[1], ast.Tuple):  # noqa: PLR2004 - threshold
                # Good pattern - already using tuple
                pass
            elif len(node.args) == 2:  # noqa: PLR2004 - threshold
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
        """Detect with statement patterns (FURB106, FURB116, 118-119, 123-127)."""
        # Check for pathlib usage opportunities (FURB106)
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func, ast.Name) and item.context_expr.func.id == "open" and len(item.context_expr.args) > 0:
                arg = item.context_expr.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB106",
                            message="Consider using pathlib.Path instead of string paths with open()",  # Best Practice: Use 'with' statement
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.MODERNIZATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

        # FURB123: Unnecessary assignment before return in context manager
        if len(node.body) >= 2 and isinstance(node.body[-2], ast.Assign) and isinstance(node.body[-1], ast.Return):  # noqa: PLR2004 - threshold
            ret = node.body[-1]
            assign = node.body[-2]
            if isinstance(ret.value, ast.Name) and isinstance(assign.targets[0], ast.Name) and ret.value.id == assign.targets[0].id:
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB123",
                        message="Unnecessary assignment before return - return the expression directly",
                        line_number=assign.lineno,
                        column=assign.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect comparison patterns (FURB107, FURB150, FURB152, FURB154)."""
        # FURB107: sys.version_info >= (3, x) - use sys.version_info >= (3, x, 0) for clarity
        if isinstance(node.left, ast.Attribute):  # noqa: SIM102
            if (
                isinstance(node.left.value, ast.Name)
                and node.left.value.id == "sys"
                and node.left.attr == "version_info"
            ):
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Tuple) and len(comparator.elts) == 2:  # noqa: PLR2004 - threshold
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

        # FURB150: Use operator.eq() instead of == in certain contexts
        # FURB152: Use math.log() instead of log2/log10 where applicable
        # FURB154: Use math.perm/comb instead of manual calculation
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq) and isinstance(node.left, ast.BinOp):
            # Check for factorial/combinatorial patterns
            pass

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Detect attribute access patterns (FURB108, FURB115, FURB121)."""
        # FURB108: os.path.join() should use Path() / operator
        if isinstance(node.value, ast.Attribute) and (
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
        if isinstance(node.value, ast.Attribute) and (
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
        if isinstance(node.value, ast.Attribute) and (
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
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "sorted":
            if isinstance(node.slice, ast.UnaryOp):
                if (
                    isinstance(node.slice.op, ast.USub)
                    and isinstance(node.slice.operand, ast.Constant)
                    and node.slice.operand.value == 1
                ):
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
        if len(node.body) == 1 and len(node.orelse) == 1 and isinstance(node.body[0], ast.Assign) and isinstance(node.orelse[0], ast.Assign):
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
        if isinstance(node.test, ast.Compare) and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.NotIn) and len(node.body) == 1 and isinstance(node.body[0], ast.Assign):
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
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "append" and len(expr.args) == 1:
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

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Detect binary operation patterns (FURB116, 118-119)."""
        # FURB118: operator.itemgetter() instead of lambda
        # This is detected in visit_Lambda

        # FURB119: operator.attrgetter() instead of lambda
        # This is detected in visit_Lambda

        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Detect lambda patterns that could use operator module (FURB118-119)."""
        # FURB118: lambda x: x[key] -> operator.itemgetter(key)
        if isinstance(node.body, ast.Subscript) and isinstance(node.body.value, ast.Name) and len(node.args.args) == 1 and node.body.value.id == node.args.args[0].arg:
            self.violations.append(
                RuleViolation(
                    rule_id="FURB118",
                    message="Use operator.itemgetter() instead of lambda for item access",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.SIMPLIFICATION,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        # FURB119: lambda x: x.attr -> operator.attrgetter('attr')
        if isinstance(node.body, ast.Attribute) and isinstance(node.body.value, ast.Name) and len(node.args.args) == 1 and node.body.value.id == node.args.args[0].arg:
            self.violations.append(
                RuleViolation(
                    rule_id="FURB119",
                    message="Use operator.attrgetter() instead of lambda for attribute access",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.SIMPLIFICATION,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Detect try/except patterns (FURB124-127, 134-143)."""
        # FURB124: Use contextlib.suppress() for try-except-pass
        if len(node.handlers) == 1:
            handler = node.handlers[0]
            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB124",
                        message="Use contextlib.suppress() instead of try-except-pass",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # FURB136: Delete instead of assigning None/empty
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant) and (stmt.value.value is None or stmt.value.value in ("", [])):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB136",
                        message="Use 'del' instead of assigning None/empty value",
                        line_number=stmt.lineno,
                        column=stmt.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        """Detect list comprehension patterns (FURB129-131, 144-148)."""
        # FURB129: Use list.copy() instead of list comprehension for copying
        if len(node.generators) == 1:
            gen = node.generators[0]
            if isinstance(node.elt, ast.Name) and isinstance(gen.target, ast.Name) and node.elt.id == gen.target.id and not gen.ifs:
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB129",
                        message="Use list.copy() or list() instead of identity list comprehension",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # FURB145: Use startswith/endswith instead of slice comparison in comprehension
        for generator in node.generators:
            for if_clause in generator.ifs:
                if isinstance(if_clause, ast.Compare) and isinstance(if_clause.left, ast.Subscript):
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB145",
                            message="Consider using str.startswith() or str.endswith() instead of slice comparison",
                            line_number=if_clause.lineno,
                            column=if_clause.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        """Detect dict comprehension patterns (FURB140-141)."""
        # FURB140: Use dict() constructor instead of dict comprehension for simple cases
        if len(node.generators) == 1:
            gen = node.generators[0]
            if isinstance(gen.target, ast.Tuple) and len(gen.target.elts) == 2 and isinstance(node.key, ast.Name) and isinstance(node.value, ast.Name):  # noqa: PLR2004 - threshold
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB140",
                        message="Use dict() constructor instead of dict comprehension for unpacking",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: PLR0912 - Complex function pattern detection requires many checks
        """Detect function definition patterns (FURB112, FURB125-127, FURB131)."""
        # FURB112: Use contextlib.suppress() instead of delete-except-pass
        # This is partially covered by FURB124 in visit_Try

        # FURB125: Do not use unnecessary lambda in sorted/map/filter
        # Check function body for lambda usage
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                func = stmt.func
                if isinstance(func, ast.Name) and func.id in ("sorted", "map", "filter"):
                    # Check if there's a lambda argument
                    for arg in stmt.args:
                        if isinstance(arg, ast.Lambda) and isinstance(arg.body, ast.Call) and isinstance(arg.body.func, ast.Name):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FURB125",
                                    message=f"Replace lambda with direct function reference in {func.id}()",
                                    line_number=arg.lineno,
                                    column=arg.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.SIMPLIFICATION,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

        # FURB126: Use isinstance() check instead of type() == check
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Compare) and len(stmt.ops) == 1 and isinstance(stmt.ops[0], ast.Eq) and isinstance(stmt.left, ast.Call) and isinstance(stmt.left.func, ast.Name) and stmt.left.func.id == "type":
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB126",
                        message="Use isinstance() instead of type() == comparison",
                        line_number=stmt.lineno,
                        column=stmt.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.CONVENTION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # FURB127: Use dict.fromkeys() instead of dict comprehension with constant value
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.DictComp) and isinstance(stmt.value, ast.Constant):
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB127",
                        message="Use dict.fromkeys() instead of dict comprehension with constant value",
                        line_number=stmt.lineno,
                        column=stmt.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SIMPLIFICATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # FURB131: Delete exception and re-raise instead of using raise
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Try):
                for handler in stmt.handlers:
                    for body_stmt in handler.body:
                        if isinstance(body_stmt, ast.Raise):
                            if body_stmt.exc is None:
                                # This is a bare raise, which is good
                                pass
                            elif isinstance(body_stmt.exc, ast.Name):  # noqa: SIM102
                                # Check if it's the same as the caught exception
                                if handler.name and body_stmt.exc.id == handler.name:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="FURB131",
                                            message="Use bare 'raise' instead of re-raising caught exception",
                                            line_number=body_stmt.lineno,
                                            column=body_stmt.col_offset,
                                            severity=RuleSeverity.LOW,
                                            category=RuleCategory.SIMPLIFICATION,
                                            file_path=self.file_path,
                                            fix_applicability=FixApplicability.SAFE,
                                        )
                                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect assignment patterns (FURB130, FURB134-135, FURB137-139)."""
        # FURB130: Use Path.read_text()/write_text() instead of open+read/write
        if isinstance(node.value, ast.Call):
            func = node.value.func
            # Check for pattern: content = open('file').read()  # Best Practice: Use 'with' statement
            if isinstance(func, ast.Attribute) and func.attr == "read" and isinstance(func.value, ast.Call) and isinstance(func.value.func, ast.Name) and func.value.func.id == "open":
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB130",
                        message="Use Path.read_text() instead of open().read()",  # Best Practice: Use 'with' statement
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        # FURB134: Use Path.exists() instead of try-except FileNotFoundError
        # This is complex - needs context from try-except block

        # FURB135: Use datetime.now() instead of datetime.fromtimestamp(time.time())
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute):  # noqa: SIM102
                if (  # noqa: SIM102
                    func.attr == "fromtimestamp"
                ):  # pyguard: disable=CWE-89  # Pattern detection, not vulnerable code
                    # Check if argument is time.time()
                    if len(node.value.args) > 0:
                        arg = node.value.args[0]
                        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "time":
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FURB135",
                                    message="Use datetime.now() instead of datetime.fromtimestamp(time.time())",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.SIMPLIFICATION,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

        # FURB137: Use min/max with default instead of try-except ValueError
        # FURB138: Use list.sort(key=str.lower) instead of list.sort(key=lambda x: x.lower())
        # FURB139: Use math.ceil(x/y) instead of -(-x//y)
        if (
            isinstance(node.value, ast.UnaryOp)
            and isinstance(node.value.op, ast.USub)
            and (
                isinstance(node.value.operand, ast.UnaryOp)
                and isinstance(node.value.operand.op, ast.USub)
                and isinstance(node.value.operand.operand, ast.BinOp)
            )
            and isinstance(node.value.operand.operand.op, ast.FloorDiv)
        ):
            self.violations.append(
                RuleViolation(
                    rule_id="FURB139",
                    message="Use math.ceil(x/y) instead of -(-x//y)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.SIMPLIFICATION,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        """Detect expression patterns (FURB141-144, FURB146-149)."""
        if isinstance(node.value, ast.Call):
            func = node.value.func

            # FURB141: Use list.extend() instead of list += [item]
            # Covered in visit_AugAssign

            # FURB142: Use str.format() or f-string instead of %
            # Covered in string_operations.py

            # FURB143: Use enumerate() instead of range(len())
            # Check for pattern: for i in range(len(seq)): ... seq[i] ...
            if isinstance(func, ast.Name) and func.id == "range" and len(node.value.args) == 1:
                arg = node.value.args[0]
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "len":
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB143",
                            message="Use enumerate() instead of range(len())",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SIMPLIFICATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

            # FURB144: Use any()/all() instead of for-loop with flag
            # This requires more complex analysis

            # FURB146: Use open() with encoding parameter
            if isinstance(func, ast.Name) and func.id == "open":
                # Check if encoding parameter is missing
                has_encoding = False
                for keyword in node.value.keywords:
                    if keyword.arg == "encoding":
                        has_encoding = True
                        break
                if not has_encoding:
                    self.violations.append(
                        RuleViolation(
                            rule_id="FURB146",
                            message="open() call missing explicit encoding parameter",  # Best Practice: Use 'with' statement
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.CONVENTION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

            # FURB147: Use Path.glob() instead of glob.glob() with pathlib
            if isinstance(func, ast.Attribute) and func.attr == "glob" and isinstance(func.value, ast.Name) and func.value.id == "glob":
                self.violations.append(
                    RuleViolation(
                        rule_id="FURB147",
                        message="Use Path.glob() instead of glob.glob() for better path handling",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

            # FURB148: Use enumerate() with start parameter
            if isinstance(func, ast.Name) and func.id == "enumerate":
                # Check for pattern: for i, x in enumerate(seq): but using i+1
                # This requires analysis of the loop body
                pass

            # FURB149: Use itertools.chain() instead of nested loops
            # This requires more complex analysis

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Detect augmented assignment patterns (FURB141)."""
        # FURB141: Use list.extend() instead of list += [item]
        if isinstance(node.op, ast.Add) and isinstance(node.value, ast.List) and len(node.value.elts) == 1:
            self.violations.append(
                RuleViolation(
                    rule_id="FURB141",
                    message="Use list.append() instead of list += [item]",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.PERFORMANCE,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

        self.generic_visit(node)


class RefurbPatternChecker:
    """Main checker for refactoring pattern detection and fixes."""

    def __init__(self):
        # TODO: Add docstring
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> list[RuleViolation]:
        """
        Check a Python file for refactoring opportunities.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, encoding="utf-8") as f:
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

    def fix_file(self, file_path: Path) -> tuple[bool, int]:
        """
        Automatically fix refactoring opportunities in a file.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (success, number of fixes applied)
        """
        try:
            with open(file_path, encoding="utf-8") as f:
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
    Rule(
        rule_id="FURB116",
        name="f-string-in-logging",
        description="Use lazy % formatting in logging instead of f-strings",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use logging with % formatting for lazy evaluation",
    ),
    Rule(
        rule_id="FURB118",
        name="operator-itemgetter",
        description="Use operator.itemgetter() instead of lambda for item access",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Replace lambda x: x[key] with operator.itemgetter(key)",
    ),
    Rule(
        rule_id="FURB119",
        name="operator-attrgetter",
        description="Use operator.attrgetter() instead of lambda for attribute access",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Replace lambda x: x.attr with operator.attrgetter('attr')",
    ),
    Rule(
        rule_id="FURB123",
        name="unnecessary-assignment-before-return",
        description="Unnecessary assignment before return",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Return the expression directly instead of assigning to a variable first",
    ),
    Rule(
        rule_id="FURB124",
        name="contextlib-suppress",
        description="Use contextlib.suppress() instead of try-except-pass",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use contextlib.suppress() for cleaner exception suppression",
    ),
    Rule(
        rule_id="FURB129",
        name="list-copy-method",
        description="Use list.copy() instead of identity list comprehension",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use list.copy() or list() for clarity",
    ),
    Rule(
        rule_id="FURB136",
        name="delete-instead-of-none-assignment",
        description="Use 'del' instead of assigning None/empty value",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use 'del variable' instead of 'variable = None'",
    ),
    Rule(
        rule_id="FURB140",
        name="dict-constructor-instead-of-comprehension",
        description="Use dict() constructor instead of dict comprehension for unpacking",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use dict() constructor for simpler dict creation",
    ),
    Rule(
        rule_id="FURB145",
        name="startswith-endswith-instead-of-slice",
        description="Use str.startswith()/endswith() instead of slice comparison",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use startswith()/endswith() for better readability",
    ),
    # New rules added in Phase 9
    Rule(
        rule_id="FURB125",
        name="unnecessary-lambda-in-call",
        description="Replace lambda with direct function reference",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use direct function reference instead of lambda",
    ),
    Rule(
        rule_id="FURB126",
        name="isinstance-instead-of-type-comparison",
        description="Use isinstance() instead of type() == comparison",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use isinstance() for more robust type checking",
    ),
    Rule(
        rule_id="FURB127",
        name="dict-fromkeys-instead-of-comprehension",
        description="Use dict.fromkeys() instead of dict comprehension with constant value",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use dict.fromkeys() for simpler dict creation with constant values",
    ),
    Rule(
        rule_id="FURB130",
        name="path-read-text-instead-of-open",
        description="Use Path.read_text() instead of open().read()",  # Best Practice: Use 'with' statement
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use pathlib's read_text() for cleaner file reading",
    ),
    Rule(
        rule_id="FURB131",
        name="bare-raise-instead-of-exception-name",
        description="Use bare 'raise' instead of re-raising caught exception",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use bare 'raise' to preserve exception context",
    ),
    Rule(
        rule_id="FURB135",
        name="datetime-now-instead-of-fromtimestamp",
        description="Use datetime.now() instead of datetime.fromtimestamp(time.time())",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use datetime.now() for current time",
    ),
    Rule(
        rule_id="FURB137",
        name="min-max-with-default",
        description="Use min/max with default instead of try-except ValueError",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use min/max with default parameter",
    ),
    Rule(
        rule_id="FURB138",
        name="sort-key-str-lower",
        description="Use str.lower as key instead of lambda",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use str.lower directly as sort key",
    ),
    Rule(
        rule_id="FURB139",
        name="math-ceil-instead-of-neg-floor-div",
        description="Use math.ceil(x/y) instead of -(-x//y)",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use math.ceil() for clearer ceiling division",
    ),
    Rule(
        rule_id="FURB141",
        name="list-append-instead-of-augmented-assign",
        description="Use list.append() instead of list += [item]",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use append() for better performance",
    ),
    Rule(
        rule_id="FURB143",
        name="enumerate-instead-of-range-len",
        description="Use enumerate() instead of range(len())",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use enumerate() for cleaner iteration with indices",
    ),
    Rule(
        rule_id="FURB146",
        name="open-with-encoding",
        description="open() call missing explicit encoding parameter",  # Best Practice: Use 'with' statement
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Always specify encoding parameter in open() calls",  # Best Practice: Use 'with' statement
    ),
    Rule(
        rule_id="FURB147",
        name="path-glob-instead-of-glob-module",
        description="Use Path.glob() instead of glob.glob()",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use pathlib's glob() for better path handling",
    ),
]
