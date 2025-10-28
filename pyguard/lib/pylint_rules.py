"""
Pylint Rules (PLR/PLC/PLW/PLE) - Comprehensive code quality checks.

This module implements Pylint's rule categories:
- PLR (Refactor): Code refactoring opportunities
- PLC (Convention): Coding standard violations
- PLW (Warning): Code issues that may lead to bugs
- PLE (Error): Code that will likely cause errors

References:
- Pylint messages: https://pylint.pycqa.org/en/latest/user_guide/messages/
- Ruff Pylint rules: https://docs.astral.sh/ruff/rules/#pylint-pl
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


class PylintVisitor(ast.NodeVisitor):
    """AST visitor for Pylint rule detection."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.function_complexity: dict[str, int] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Detect function-related issues (PLR0911-PLR0917, PLW0120-PLW0129)."""
        # PLR0911: Too many return statements
        returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        if len(returns) > 6:
            self.violations.append(
                RuleViolation(
                    rule_id="PLR0911",
                    message=f"Too many return statements ({len(returns)}/6)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.COMPLEXITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        # PLR0912: Too many branches
        branches = 0
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                branches += 1

        if branches > 12:
            self.violations.append(
                RuleViolation(
                    rule_id="PLR0912",
                    message=f"Too many branches ({branches}/12)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.COMPLEXITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        # PLR0913: Too many arguments
        total_args = len(node.args.posonlyargs) + len(node.args.args) + len(node.args.kwonlyargs)
        if node.args.vararg or node.args.kwarg:
            total_args += 1

        if total_args > 5:
            self.violations.append(
                RuleViolation(
                    rule_id="PLR0913",
                    message=f"Too many arguments ({total_args}/5)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.DESIGN,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        # PLR0915: Too many statements
        statements = [n for n in ast.walk(node) if isinstance(n, ast.stmt)]
        if len(statements) > 50:
            self.violations.append(
                RuleViolation(
                    rule_id="PLR0915",
                    message=f"Too many statements ({len(statements)}/50)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.COMPLEXITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        # PLW0120: Else clause on loop without break
        for child in ast.walk(node):
            if isinstance(child, (ast.For, ast.While)) and child.orelse:
                # Check if loop has break statement
                has_break = False
                for stmt in ast.walk(child):
                    if isinstance(stmt, ast.Break):
                        has_break = True
                        break

                if not has_break:
                    self.violations.append(
                        RuleViolation(
                            rule_id="PLW0120",
                            message="Else clause on loop without break statement - misleading",
                            line_number=child.lineno,
                            column=child.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.WARNING,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Detect class-related issues (PLR0901-PLR0904, PLE0102-PLE0116)."""
        # PLR0902: Too many instance attributes
        instance_attrs = set()
        for child in ast.walk(node):
            if isinstance(child, ast.FunctionDef) and child.name == "__init__":
                for stmt in ast.walk(child):
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Attribute) and (
                                isinstance(target.value, ast.Name)
                                and target.value.id == "self"
                            ):
                                instance_attrs.add(target.attr)

        if len(instance_attrs) > 7:
            self.violations.append(
                RuleViolation(
                    rule_id="PLR0902",
                    message=f"Too many instance attributes ({len(instance_attrs)}/7)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.DESIGN,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        # PLR0903: Too few public methods
        public_methods = 0
        for child in node.body:
            if isinstance(child, ast.FunctionDef) and not child.name.startswith("_"):
                public_methods += 1

        if public_methods < 2 and len(node.body) > 1:
            # Only flag if class has more than just __init__
            methods = [m for m in node.body if isinstance(m, ast.FunctionDef)]
            if len(methods) > 1 or (len(methods) == 1 and methods[0].name != "__init__"):
                self.violations.append(
                    RuleViolation(
                        rule_id="PLR0903",
                        message=f"Too few public methods ({public_methods}/2) - consider using a function or dataclass",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.DESIGN,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.NONE,
                    )
                )

        # PLR0904: Too many public methods
        if public_methods > 20:
            self.violations.append(
                RuleViolation(
                    rule_id="PLR0904",
                    message=f"Too many public methods ({public_methods}/20)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.DESIGN,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        # PLE0102: Function redefinition (same name)
        method_names: dict[str, int] = {}
        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                if child.name in method_names:
                    self.violations.append(
                        RuleViolation(
                            rule_id="PLE0102",
                            message=f"Method '{child.name}' redefined (previously at line {method_names[child.name]})",
                            line_number=child.lineno,
                            column=child.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.ERROR,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.NONE,
                        )
                    )
                method_names[child.name] = child.lineno

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Detect if-statement issues (PLR1701, PLR1714, PLW0125)."""
        # PLR1714: Consider merging isinstance calls
        if isinstance(node.test, ast.BoolOp) and isinstance(node.test.op, ast.Or):
            isinstance_calls = []
            for value in node.test.values:
                if isinstance(value, ast.Call):
                    if isinstance(value.func, ast.Name) and value.func.id == "isinstance":
                        isinstance_calls.append(value)

            if len(isinstance_calls) >= 2:
                # Check if they all check the same variable
                first_arg = isinstance_calls[0].args[0]
                if all(
                    isinstance(call.args[0], ast.Name)
                    and isinstance(first_arg, ast.Name)
                    and call.args[0].id == first_arg.id
                    for call in isinstance_calls
                ):
                    self.violations.append(
                        RuleViolation(
                            rule_id="PLR1714",
                            message="Consider merging isinstance calls using a tuple: isinstance(x, (A, B))",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SIMPLIFICATION,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        # PLW0125: Using type() instead of isinstance()
        if isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Call):
            if isinstance(node.test.left.func, ast.Name) and node.test.left.func.id == "type":
                self.violations.append(
                    RuleViolation(
                        rule_id="PLW0125",
                        message="Use isinstance() instead of type() comparison",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        """Detect raise statement issues (PLW0707, PLE0711, PLE0712)."""
        # PLW0707: Raise with from inside except without chaining
        # Would need to track if we're in an except handler

        # PLE0711: NotImplemented raised instead of NotImplementedError
        if isinstance(node.exc, ast.Name) and node.exc.id == "NotImplemented":
            self.violations.append(
                RuleViolation(
                    rule_id="PLE0711",
                    message="Raising NotImplemented - did you mean NotImplementedError?",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.ERROR,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect comparison issues (PLR1701, PLR1706, PLC1901, PLW0127)."""
        # PLC1901: Compare to empty string
        if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant) and comparator.value == "":
                    self.violations.append(
                        RuleViolation(
                            rule_id="PLC1901",
                            message="Compare to empty string - use 'if not s:' instead",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        # PLW0127: Self-comparison (x == x)
        if len(node.ops) == 1 and len(node.comparators) == 1:
            if isinstance(node.left, ast.Name) and isinstance(node.comparators[0], ast.Name):
                if node.left.id == node.comparators[0].id:
                    self.violations.append(
                        RuleViolation(
                            rule_id="PLW0127",
                            message="Self-comparison - always evaluates to the same value",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.ERROR,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.NONE,
                        )
                    )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        """Detect return statement issues (PLR1711)."""
        # PLR1711: Useless return at end of function
        # This requires knowing if it's the last statement, handled elsewhere

        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        """Detect global statement issues (PLW0602, PLW0603)."""
        # PLW0602: Global variable undefined
        # PLW0603: Global statement used
        self.violations.append(
            RuleViolation(
                rule_id="PLW0603",
                message=f"Using the global statement - consider refactoring: {', '.join(node.names)}",
                line_number=node.lineno,
                column=node.col_offset,
                severity=RuleSeverity.MEDIUM,
                category=RuleCategory.CONVENTION,
                file_path=self.file_path,
                fix_applicability=FixApplicability.NONE,
            )
        )

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Detect assert statement issues (PLW0129)."""
        # PLW0129: Assert on tuple (always True)
        if isinstance(node.test, ast.Tuple):
            self.violations.append(
                RuleViolation(
                    rule_id="PLW0129",
                    message="Assert on tuple - always true, likely a bug",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.ERROR,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.NONE,
                )
            )

        self.generic_visit(node)


class PylintRulesChecker:
    """Main checker for Pylint rules."""

    def __init__(self):
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> list[RuleViolation]:
        """
        Check a Python file for Pylint rule violations.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            tree = ast.parse(code)
            visitor = PylintVisitor(file_path, code)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []


# Define rules for registration
PYLINT_RULES = [
    # PLR - Refactor
    Rule(
        rule_id="PLR0911",
        name="too-many-return-statements",
        description="Too many return statements in function",
        category=RuleCategory.COMPLEXITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Too many return statements ({count}/6)",
    ),
    Rule(
        rule_id="PLR0912",
        name="too-many-branches",
        description="Too many branches in function",
        category=RuleCategory.COMPLEXITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Too many branches ({count}/12)",
    ),
    Rule(
        rule_id="PLR0913",
        name="too-many-arguments",
        description="Too many arguments in function definition",
        category=RuleCategory.DESIGN,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Too many arguments ({count}/5)",
    ),
    Rule(
        rule_id="PLR0915",
        name="too-many-statements",
        description="Too many statements in function",
        category=RuleCategory.COMPLEXITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Too many statements ({count}/50)",
    ),
    Rule(
        rule_id="PLR0902",
        name="too-many-instance-attributes",
        description="Too many instance attributes in class",
        category=RuleCategory.DESIGN,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Too many instance attributes ({count}/7)",
    ),
    Rule(
        rule_id="PLR0903",
        name="too-few-public-methods",
        description="Too few public methods - consider using a function",
        category=RuleCategory.DESIGN,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.NONE,
        message_template="Too few public methods ({count}/2)",
    ),
    Rule(
        rule_id="PLR0904",
        name="too-many-public-methods",
        description="Too many public methods in class",
        category=RuleCategory.DESIGN,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Too many public methods ({count}/20)",
    ),
    Rule(
        rule_id="PLR1701",
        name="repeated-isinstance-calls",
        description="Consider merging isinstance calls",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Merge isinstance calls: isinstance(x, (A, B))",
    ),
    Rule(
        rule_id="PLR1714",
        name="consider-using-in",
        description="Consider merging isinstance calls using tuple",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use isinstance(x, (type1, type2)) instead of multiple calls",
    ),
    Rule(
        rule_id="PLR1711",
        name="useless-return",
        description="Useless return at end of function",
        category=RuleCategory.SIMPLIFICATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Remove useless return statement",
    ),
    # PLC - Convention
    Rule(
        rule_id="PLC1901",
        name="compare-to-empty-string",
        description="Avoid comparing to empty string",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use 'if not s:' instead of 's == \"\"'",
    ),
    # PLW - Warning
    Rule(
        rule_id="PLW0120",
        name="useless-else-on-loop",
        description="Else clause on loop without break",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Else clause without break is misleading",
    ),
    Rule(
        rule_id="PLW0125",
        name="using-constant-test",
        description="Using type() instead of isinstance()",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use isinstance() instead of type() comparison",
    ),
    Rule(
        rule_id="PLW0127",
        name="self-assigning-variable",
        description="Self-comparison detected",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.NONE,
        message_template="Variable compared to itself",
    ),
    Rule(
        rule_id="PLW0129",
        name="assert-on-tuple",
        description="Assert on tuple - always True",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.NONE,
        message_template="Assert on tuple always evaluates to True",
    ),
    Rule(
        rule_id="PLW0602",
        name="global-variable-undefined",
        description="Using global for undefined variable",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.NONE,
        message_template="Global variable not defined",
    ),
    Rule(
        rule_id="PLW0603",
        name="global-statement",
        description="Using the global statement",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.NONE,
        message_template="Avoid global statement - consider refactoring",
    ),
    Rule(
        rule_id="PLW0707",
        name="raise-missing-from",
        description="Raise without exception chaining",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use 'raise ... from ...' for exception chaining",
    ),
    # PLE - Error
    Rule(
        rule_id="PLE0102",
        name="function-redefined",
        description="Function/method redefined",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.NONE,
        message_template="Function redefined - second definition will override first",
    ),
    Rule(
        rule_id="PLE0711",
        name="notimplemented-raised",
        description="NotImplemented raised instead of NotImplementedError",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use NotImplementedError instead of NotImplemented",
    ),
]
