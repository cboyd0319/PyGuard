"""
Bugbear-style common mistake detection for PyGuard.

This module implements detection rules similar to flake8-bugbear, catching likely bugs
and design problems that other linters might miss. These are common mistakes that can
lead to unexpected behavior or bugs in production.

Based on flake8-bugbear rules: https://github.com/PyCQA/flake8-bugbear
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)

logger = PyGuardLogger()


@dataclass
class BugbearRule(Rule):
    """Bugbear-style rule definition."""

    pass


class BugbearVisitor(ast.NodeVisitor):
    """AST visitor for detecting bugbear-style issues."""

    def __init__(self, file_path: Path):
        """Initialize visitor."""
        self.file_path = file_path
        self.violations: List[RuleViolation] = []
        self.function_names: Set[str] = set()
        self.class_names: Set[str] = set()
        self.in_loop = False
        self.loop_depth = 0

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Check exception handling patterns."""
        # B001: Bare except without exception type
        if node.type is None and len(node.body) > 0:
            self.violations.append(
                RuleViolation(
                    rule_id="B001",
                    category=RuleCategory.ERROR,
                    severity=RuleSeverity.HIGH,
                    message="Do not use bare 'except:' without exception type",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Specify the exception type: except Exception:",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="bugbear",
                )
            )

        # B014: Redundant exception types in except clause
        if node.type and isinstance(node.type, ast.Tuple):
            types = [self._get_exception_name(t) for t in node.type.elts]
            if len(types) != len(set(types)):
                self.violations.append(
                    RuleViolation(
                        rule_id="B014",
                        category=RuleCategory.ERROR,
                        severity=RuleSeverity.MEDIUM,
                        message="Duplicate exception types in except clause",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Remove duplicate exception types",
                        fix_applicability=FixApplicability.AUTOMATIC,
                        source_tool="bugbear",
                    )
                )

        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        """Check raise statement patterns."""
        # B016: Cannot raise a literal - no exception will be caught
        if node.exc and isinstance(node.exc, (ast.Constant, ast.Num, ast.Str)):
            self.violations.append(
                RuleViolation(
                    rule_id="B016",
                    category=RuleCategory.ERROR,
                    severity=RuleSeverity.HIGH,
                    message="Cannot raise a literal. Did you mean to raise an exception?",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Raise an exception instance: raise ValueError(...)",
                    fix_applicability=FixApplicability.MANUAL,
                    source_tool="bugbear",
                )
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definition patterns."""
        # B002: Python does not support the unary prefix increment
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.UnaryOp) and isinstance(stmt.op, ast.UAdd):
                if isinstance(stmt.operand, ast.UnaryOp) and isinstance(
                    stmt.operand.op, ast.UAdd
                ):
                    self.violations.append(
                        RuleViolation(
                            rule_id="B002",
                            category=RuleCategory.ERROR,
                            severity=RuleSeverity.HIGH,
                            message="Python does not support the unary prefix increment operator (++)",
                            file_path=self.file_path,
                            line_number=stmt.lineno,
                            column=stmt.col_offset,
                            fix_suggestion="Use x += 1 instead of ++x",
                            fix_applicability=FixApplicability.AUTOMATIC,
                            source_tool="bugbear",
                        )
                    )

        # B006: Mutable default arguments
        for arg in node.args.args + node.args.kwonlyargs:
            default_idx = None
            if arg in node.args.args:
                idx = node.args.args.index(arg)
                if idx >= len(node.args.args) - len(node.args.defaults):
                    default_idx = idx - (len(node.args.args) - len(node.args.defaults))
            elif arg in node.args.kwonlyargs:
                idx = node.args.kwonlyargs.index(arg)
                if idx < len(node.args.kw_defaults):
                    default = node.args.kw_defaults[idx]
                    if default and self._is_mutable_default(default):
                        self.violations.append(
                            RuleViolation(
                                rule_id="B006",
                                category=RuleCategory.ERROR,
                                severity=RuleSeverity.HIGH,
                                message=f"Do not use mutable data structures (list, dict, set) as default argument for '{arg.arg}'",
                                file_path=self.file_path,
                                line_number=arg.lineno,
                                column=arg.col_offset,
                                fix_suggestion=f"Use None as default and initialize inside function:\n    if {arg.arg} is None:\n        {arg.arg} = []",
                                fix_applicability=FixApplicability.SUGGESTED,
                                source_tool="bugbear",
                            )
                        )

            if default_idx is not None and default_idx < len(node.args.defaults):
                default = node.args.defaults[default_idx]
                if self._is_mutable_default(default):
                    self.violations.append(
                        RuleViolation(
                            rule_id="B006",
                            category=RuleCategory.ERROR,
                            severity=RuleSeverity.HIGH,
                            message=f"Do not use mutable data structures (list, dict, set) as default argument for '{arg.arg}'",
                            file_path=self.file_path,
                            line_number=arg.lineno,
                            column=arg.col_offset,
                            fix_suggestion=f"Use None as default and initialize inside function:\n    if {arg.arg} is None:\n        {arg.arg} = []",
                            fix_applicability=FixApplicability.SUGGESTED,
                            source_tool="bugbear",
                        )
                    )

        # B018: Useless expression - statement has no effect
        for stmt in node.body:
            if isinstance(stmt, ast.Expr) and not isinstance(
                stmt.value,
                (
                    ast.Call,
                    ast.Yield,
                    ast.YieldFrom,
                    ast.Await,
                    ast.JoinedStr,
                    ast.FormattedValue,
                ),
            ):
                if isinstance(stmt.value, (ast.Constant, ast.Num, ast.Str)):
                    # Skip docstrings
                    if stmt is node.body[0]:
                        continue
                    self.violations.append(
                        RuleViolation(
                            rule_id="B018",
                            category=RuleCategory.WARNING,
                            severity=RuleSeverity.MEDIUM,
                            message="Found useless expression. Statement has no effect",
                            file_path=self.file_path,
                            line_number=stmt.lineno,
                            column=stmt.col_offset,
                            fix_suggestion="Remove useless expression or assign to variable",
                            fix_applicability=FixApplicability.MANUAL,
                            source_tool="bugbear",
                        )
                    )

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Check class definition patterns."""
        # B003: Assigning to __class__ - this is a Python footgun
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "__class__":
                        self.violations.append(
                            RuleViolation(
                                rule_id="B003",
                                category=RuleCategory.ERROR,
                                severity=RuleSeverity.HIGH,
                                message="Assigning to __class__ is dangerous and can break your code",
                                file_path=self.file_path,
                                line_number=stmt.lineno,
                                column=stmt.col_offset,
                                fix_suggestion="Avoid assigning to __class__",
                                fix_applicability=FixApplicability.MANUAL,
                                source_tool="bugbear",
                            )
                        )

        # B004: Using hasattr with a try/except - hasattr hides errors
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                if (
                    isinstance(stmt.func, ast.Name)
                    and stmt.func.id == "hasattr"
                    and len(stmt.args) == 2
                ):
                    # Check if we're in a try/except
                    pass  # Simplified for now

        # Check for __eq__ without __hash__
        has_eq = False
        has_hash = False
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                if item.name == "__eq__":
                    has_eq = True
                elif item.name == "__hash__":
                    has_hash = True

        if has_eq and not has_hash:
            self.violations.append(
                RuleViolation(
                    rule_id="B009",
                    category=RuleCategory.ERROR,
                    severity=RuleSeverity.MEDIUM,
                    message="Class defines __eq__ but not __hash__. This makes instances unhashable",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Define __hash__ method or set __hash__ = None",
                    fix_applicability=FixApplicability.MANUAL,
                    source_tool="bugbear",
                )
            )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check function call patterns."""
        # B005: Using .strip() with same character repeated
        if isinstance(node.func, ast.Attribute) and node.func.attr == "strip":
            if node.args and isinstance(node.args[0], (ast.Constant, ast.Str)):
                value = (
                    node.args[0].value
                    if isinstance(node.args[0], ast.Constant)
                    else node.args[0].s
                )
                if isinstance(value, str) and len(value) > 1:
                    if len(set(value)) == 1:
                        self.violations.append(
                            RuleViolation(
                                rule_id="B005",
                                category=RuleCategory.WARNING,
                                severity=RuleSeverity.LOW,
                                message=f"Using .strip() with same character repeated: '{value}'",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                fix_suggestion=f"Use .strip('{value[0]}') instead",
                                fix_applicability=FixApplicability.AUTOMATIC,
                                source_tool="bugbear",
                            )
                        )



        # B012: return/break/continue inside finally blocks
        # (handled in visit_Try)

        # B013: Redundant tuple in exception clause
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "except"
            and node.args
            and len(node.args) == 1
        ):
            if isinstance(node.args[0], ast.Tuple) and len(node.args[0].elts) == 1:
                self.violations.append(
                    RuleViolation(
                        rule_id="B013",
                        category=RuleCategory.WARNING,
                        severity=RuleSeverity.LOW,
                        message="Redundant tuple in exception handler",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Remove unnecessary tuple",
                        fix_applicability=FixApplicability.AUTOMATIC,
                        source_tool="bugbear",
                    )
                )

        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Check try/except patterns."""
        # B012: return/break/continue inside finally
        if hasattr(node, "finalbody"):
            for stmt in node.finalbody:
                for sub_stmt in ast.walk(stmt):
                    if isinstance(sub_stmt, (ast.Return, ast.Break, ast.Continue)):
                        self.violations.append(
                            RuleViolation(
                                rule_id="B012",
                                category=RuleCategory.ERROR,
                                severity=RuleSeverity.HIGH,
                                message=f"'{sub_stmt.__class__.__name__.lower()}' inside finally block can hide exceptions",
                                file_path=self.file_path,
                                line_number=sub_stmt.lineno,
                                column=sub_stmt.col_offset,
                                fix_suggestion="Avoid control flow statements in finally blocks",
                                fix_applicability=FixApplicability.MANUAL,
                                source_tool="bugbear",
                            )
                        )

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Check assert statement patterns."""
        # B011: Do not use assert False
        if isinstance(node.test, ast.Constant) and node.test.value is False:
            self.violations.append(
                RuleViolation(
                    rule_id="B011",
                    category=RuleCategory.ERROR,
                    severity=RuleSeverity.MEDIUM,
                    message="Do not use 'assert False'. Use 'raise AssertionError()' instead",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="raise AssertionError()",
                    fix_applicability=FixApplicability.AUTOMATIC,
                    source_tool="bugbear",
                )
            )

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Check with statement patterns."""
        # B017: assertRaises(Exception) and pytest.raises(Exception) should be avoided
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                if isinstance(item.context_expr.func, ast.Attribute):
                    method_name = item.context_expr.func.attr
                    if method_name in ("assertRaises", "raises"):
                        if item.context_expr.args and isinstance(
                            item.context_expr.args[0], ast.Name
                        ):
                            exc_name = item.context_expr.args[0].id
                            if exc_name == "Exception":
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="B017",
                                        category=RuleCategory.WARNING,
                                        severity=RuleSeverity.MEDIUM,
                                        message=f"{method_name}(Exception) is too broad. Catch specific exceptions",
                                        file_path=self.file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        fix_suggestion="Use a more specific exception type",
                                        fix_applicability=FixApplicability.MANUAL,
                                        source_tool="bugbear",
                                    )
                                )

        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Check for loop patterns."""
        old_in_loop = self.in_loop
        old_depth = self.loop_depth
        self.in_loop = True
        self.loop_depth += 1

        # B007: Loop control variable not used within loop body
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            used = False
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Name) and stmt.id == var_name and stmt != node.target:
                    used = True
                    break

            if not used and not var_name.startswith("_"):
                self.violations.append(
                    RuleViolation(
                        rule_id="B007",
                        category=RuleCategory.WARNING,
                        severity=RuleSeverity.LOW,
                        message=f"Loop variable '{var_name}' not used within loop body",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=f"Rename to '_{var_name}' to indicate it's unused",
                        fix_applicability=FixApplicability.AUTOMATIC,
                        source_tool="bugbear",
                    )
                )

        self.generic_visit(node)
        self.in_loop = old_in_loop
        self.loop_depth = old_depth

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check assignment patterns."""
        # B010: Do not call setattr with constant attribute names
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id == "setattr":
                if len(node.value.args) >= 2 and isinstance(
                    node.value.args[1], (ast.Constant, ast.Str)
                ):
                    attr_name = (
                        node.value.args[1].value
                        if isinstance(node.value.args[1], ast.Constant)
                        else node.value.args[1].s
                    )
                    self.violations.append(
                        RuleViolation(
                            rule_id="B010",
                            category=RuleCategory.WARNING,
                            severity=RuleSeverity.LOW,
                            message=f"Do not use setattr with constant attribute name '{attr_name}'",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            fix_suggestion=f"Use direct assignment: obj.{attr_name} = value",
                            fix_applicability=FixApplicability.AUTOMATIC,
                            source_tool="bugbear",
                        )
                    )

        self.generic_visit(node)

    def _is_mutable_default(self, node: ast.AST) -> bool:
        """Check if a node represents a mutable default argument."""
        if isinstance(node, ast.List):
            return True
        if isinstance(node, ast.Dict):
            return True
        if isinstance(node, ast.Set):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ("list", "dict", "set"):
                    return True
        return False

    def _get_exception_name(self, node: ast.AST) -> str:
        """Get the name of an exception type."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""


class BugbearChecker:
    """Main class for detecting bugbear-style issues."""

    def __init__(self):
        """Initialize checker."""
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a file for bugbear-style issues.

        Args:
            file_path: Path to file to check

        Returns:
            List of violations found
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source, filename=str(file_path))
            visitor = BugbearVisitor(file_path)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(
                "Syntax error in file",
                details={"file_path": str(file_path), "error": str(e)},
            )
            return []
        except Exception as e:
            self.logger.error(
                "Error checking file",
                details={"file_path": str(file_path), "error": str(e)},
            )
            return []

    def check_code(self, code: str, file_path: Optional[Path] = None) -> List[RuleViolation]:
        """
        Check code for bugbear-style issues.

        Args:
            code: Source code to check
            file_path: Optional path for error reporting

        Returns:
            List of violations found
        """
        if file_path is None:
            file_path = Path("<string>")

        try:
            tree = ast.parse(code, filename=str(file_path))
            visitor = BugbearVisitor(file_path)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(
                "Syntax error in code",
                details={"file_path": str(file_path), "error": str(e)},
            )
            return []
        except Exception as e:
            self.logger.error(
                "Error checking code",
                details={"file_path": str(file_path), "error": str(e)},
            )
            return []


# Rule definitions for integration with rule engine
BUGBEAR_RULES = [
    BugbearRule(
        rule_id="B001",
        name="bare-except",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        message_template="Do not use bare 'except:' without exception type",
        description="Bare except clauses catch all exceptions including system-exiting exceptions",
        explanation="This can hide bugs and make debugging very difficult. Always specify the exception type.",
        fix_applicability=FixApplicability.SUGGESTED,
        tags={"bugbear", "exceptions"},
        references=[
            "https://github.com/PyCQA/flake8-bugbear#b001",
        ],
    ),
    BugbearRule(
        rule_id="B002",
        name="unary-prefix-increment",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        message_template="Python does not support the unary prefix increment operator (++)",
        description="++n is valid Python syntax but does not do what you think it does",
        explanation="Python does not have ++ or -- operators. Use += 1 or -= 1 instead.",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"bugbear", "syntax"},
    ),
    BugbearRule(
        rule_id="B003",
        name="assign-to-class",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        message_template="Assigning to __class__ is dangerous",
        description="Assigning to __class__ can break your code in unexpected ways",
        explanation="This is a Python footgun. Don't do it.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"bugbear", "classes"},
    ),
    BugbearRule(
        rule_id="B005",
        name="strip-with-repeated-characters",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.LOW,
        message_template="Using .strip() with same character repeated",
        description="Using .strip('xx') is the same as .strip('x')",
        explanation="The argument to strip() is not a prefix/suffix, it's a set of characters.",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"bugbear", "strings"},
    ),
    BugbearRule(
        rule_id="B006",
        name="mutable-default-argument",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        message_template="Do not use mutable data structures as default argument values",
        description="Mutable default arguments are shared between all calls to the function",
        explanation="Use None as default and initialize inside the function instead.",
        fix_applicability=FixApplicability.SUGGESTED,
        tags={"bugbear", "functions"},
    ),
    BugbearRule(
        rule_id="B007",
        name="unused-loop-control-variable",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.LOW,
        message_template="Loop variable not used within loop body",
        description="Loop control variable is not used in loop body",
        explanation="Prefix with underscore to indicate it's intentionally unused.",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"bugbear", "loops"},
    ),
    BugbearRule(
        rule_id="B009",
        name="eq-without-hash",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        message_template="Class defines __eq__ but not __hash__",
        description="Instances of this class will be unhashable",
        explanation="When you define __eq__, Python sets __hash__ to None by default.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"bugbear", "classes"},
    ),
    BugbearRule(
        rule_id="B010",
        name="setattr-with-constant",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.LOW,
        message_template="Do not use setattr with constant attribute name",
        description="Use direct assignment instead of setattr with constant",
        explanation="obj.attr = value is clearer than setattr(obj, 'attr', value)",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"bugbear", "attributes"},
    ),
    BugbearRule(
        rule_id="B011",
        name="assert-false",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        message_template="Do not use 'assert False'",
        description="assert statements can be optimized away with -O flag",
        explanation="Use 'raise AssertionError()' instead for guaranteed failure.",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"bugbear", "assertions"},
    ),
    BugbearRule(
        rule_id="B012",
        name="return-in-finally",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        message_template="Control flow statement inside finally block",
        description="return/break/continue in finally can hide exceptions",
        explanation="The finally block will suppress exceptions from try/except blocks.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"bugbear", "exceptions"},
    ),
    BugbearRule(
        rule_id="B013",
        name="redundant-tuple-in-exception",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.LOW,
        message_template="Redundant tuple in exception handler",
        description="Single exception in tuple is redundant",
        explanation="Use 'except ValueError:' not 'except (ValueError,):'",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"bugbear", "exceptions"},
    ),
    BugbearRule(
        rule_id="B014",
        name="duplicate-exception-types",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        message_template="Duplicate exception types in except clause",
        description="Same exception type listed multiple times",
        explanation="Remove the duplicate exception types.",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"bugbear", "exceptions"},
    ),
    BugbearRule(
        rule_id="B016",
        name="raise-literal",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        message_template="Cannot raise a literal",
        description="Literals are not exceptions and cannot be caught",
        explanation="Raise an exception instance: raise ValueError(...)",
        fix_applicability=FixApplicability.MANUAL,
        tags={"bugbear", "exceptions"},
    ),
    BugbearRule(
        rule_id="B017",
        name="assert-raises-exception",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        message_template="assertRaises(Exception) is too broad",
        description="Catching Exception is too broad for testing",
        explanation="Catch specific exception types in tests.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"bugbear", "testing"},
    ),
    BugbearRule(
        rule_id="B018",
        name="useless-expression",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        message_template="Found useless expression",
        description="Statement has no effect",
        explanation="The expression is evaluated but the result is discarded.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"bugbear", "statements"},
    ),
]
