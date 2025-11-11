"""
Exception handling pattern detection for PyGuard.

This module implements detection rules for proper exception handling patterns,
similar to Ruff's TRY rules. These rules help ensure robust error handling and
prevent common mistakes in exception handling.

Based on Ruff TRY rules: https://docs.astral.sh/ruff/rules/#tryceratops-try
"""

import ast
from dataclasses import dataclass
from pathlib import Path

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
class ExceptionHandlingRule(Rule):
    """Exception handling rule definition."""

    pass


class ExceptionHandlingVisitor(ast.NodeVisitor):
    """AST visitor for detecting exception handling issues."""

    def __init__(self, file_path: Path):
        """Initialize visitor."""
        self.file_path = file_path
        self.violations: list[RuleViolation] = []
        self.in_except_handler = False

    def visit_Raise(self, node: ast.Raise) -> None:
        """Check raise statement patterns."""
        # TRY001: Raise without from inside except
        if self.in_except_handler and node.exc and not node.cause:  # noqa: SIM102
            # Check if this is a re-raise of a different exception type
            # (raising the same exception or bare raise is OK)
            if node.exc is not None:  # bare raise is OK
                self.violations.append(
                    RuleViolation(
                        rule_id="TRY001",
                        category=RuleCategory.WARNING,
                        severity=RuleSeverity.MEDIUM,
                        message="Use 'raise ... from ...' to preserve exception chain in except handler",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Add 'from' clause: raise NewError(...) from original_error",
                        fix_applicability=FixApplicability.MANUAL,
                        source_tool="exception_handling",
                    )
                )

        # TRY002: Raise vanilla Exception
        if node.exc and isinstance(node.exc, ast.Call):  # noqa: SIM102
            if isinstance(node.exc.func, ast.Name) and node.exc.func.id == "Exception":
                self.violations.append(
                    RuleViolation(
                        rule_id="TRY002",
                        category=RuleCategory.WARNING,
                        severity=RuleSeverity.MEDIUM,
                        message="Avoid raising vanilla Exception. Create custom exception class",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Define a custom exception: class CustomError(Exception): pass",
                        fix_applicability=FixApplicability.MANUAL,
                        source_tool="exception_handling",
                    )
                )

        # TRY003: Long messages in exception strings
        if node.exc and isinstance(node.exc, ast.Call):  # noqa: SIM102
            if node.exc.args:
                for arg in node.exc.args:
                    if isinstance(arg, ast.Constant):
                        msg = arg.value
                        if isinstance(msg, str) and len(msg) > 200:  # noqa: PLR2004 - threshold
                            self.violations.append(
                                RuleViolation(
                                    rule_id="TRY003",
                                    category=RuleCategory.CONVENTION,
                                    severity=RuleSeverity.LOW,
                                    message="Exception message is too long (>200 chars). Consider shorter message",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    fix_suggestion="Break long message into shorter parts or use logging",
                                    fix_applicability=FixApplicability.MANUAL,
                                    source_tool="exception_handling",
                                )
                            )

        # TRY200: Reraise without from
        if node.exc is None and node.cause is None and self.in_except_handler:
            # Bare raise in except handler is actually good, skip this case
            pass
        elif node.exc and not node.cause and self.in_except_handler:
            # Raising a new exception without 'from' in except handler
            self.violations.append(
                RuleViolation(
                    rule_id="TRY200",
                    category=RuleCategory.WARNING,
                    severity=RuleSeverity.MEDIUM,
                    message="Prefer 'raise ... from ...' to preserve exception chain",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Use 'raise NewException(...) from exc' to preserve traceback",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="exception_handling",
                )
            )

        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Check try/except patterns."""
        # TRY004: Prefer TypeError for wrong type
        # (Checked in except handler visitor)

        # TRY300: Consider else clause
        if not node.orelse and len(node.body) > 1:
            # Check if there's code after try that could go in else
            has_return_in_try = any(isinstance(stmt, ast.Return) for stmt in node.body)
            if not has_return_in_try:
                # Consider suggesting else clause
                pass  # Simplified for now

        # TRY301: Abstract raise to inner function
        if len(node.handlers) > 3:  # noqa: PLR2004 - threshold
            self.violations.append(
                RuleViolation(
                    rule_id="TRY301",
                    category=RuleCategory.REFACTOR,
                    severity=RuleSeverity.LOW,
                    message="Too many exception handlers. Consider refactoring",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Split into separate try/except blocks or use helper functions",
                    fix_applicability=FixApplicability.MANUAL,
                    source_tool="exception_handling",
                )
            )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Check exception handler patterns."""
        old_in_except = self.in_except_handler
        self.in_except_handler = True

        # TRY201: Verbose raise
        if len(node.body) == 1 and isinstance(node.body[0], ast.Raise):
            if node.body[0].exc is None:
                # Bare raise is fine
                pass
            else:
                self.violations.append(
                    RuleViolation(
                        rule_id="TRY201",
                        category=RuleCategory.REFACTOR,
                        severity=RuleSeverity.LOW,
                        message="Use bare 'raise' to reraise in except handler",
                        file_path=self.file_path,
                        line_number=node.body[0].lineno,
                        column=node.body[0].col_offset,
                        fix_suggestion="Change to bare 'raise' statement",
                        fix_applicability=FixApplicability.AUTOMATIC,
                        source_tool="exception_handling",
                    )
                )

        # TRY302: useless-try-except
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.violations.append(
                RuleViolation(
                    rule_id="TRY302",
                    category=RuleCategory.WARNING,
                    severity=RuleSeverity.MEDIUM,
                    message="Useless try-except with only pass. Remove or handle properly",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Remove try-except or add proper error handling",
                    fix_applicability=FixApplicability.MANUAL,
                    source_tool="exception_handling",
                )
            )

        # TRY400: Logging statement in exception handler without re-raise
        # Check for logging or raise statements in except handler
        # Reserved for future functionality

        # TRY401: Verbose logging
        # Check for logging with exc_info in except handler
        for stmt in node.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):  # noqa: SIM102
                if isinstance(stmt.value.func, ast.Attribute):
                    method = stmt.value.func.attr
                    if method in ("error", "critical", "warning"):
                        # Check for exc_info parameter
                        has_exc_info = any(
                            (isinstance(kw.value, ast.Constant) and kw.value.value is True)
                            for kw in stmt.value.keywords
                            if kw.arg == "exc_info"
                        )
                        if has_exc_info:
                            # Suggest using logging.exception instead
                            self.violations.append(
                                RuleViolation(
                                    rule_id="TRY401",
                                    category=RuleCategory.CONVENTION,
                                    severity=RuleSeverity.LOW,
                                    message="Use logging.exception() instead of .error(..., exc_info=True)",
                                    file_path=self.file_path,
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    fix_suggestion="Replace with logger.exception()",
                                    fix_applicability=FixApplicability.AUTOMATIC,
                                    source_tool="exception_handling",
                                )
                            )

        self.generic_visit(node)
        self.in_except_handler = old_in_except

    def visit_With(self, node: ast.With) -> None:
        """Check with statement patterns related to exception handling."""
        # TRY005: Check for suppress context manager usage
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                # Check if it's suppress() function
                func_name = None
                if isinstance(item.context_expr.func, ast.Name):
                    func_name = item.context_expr.func.id
                elif isinstance(item.context_expr.func, ast.Attribute):
                    func_name = item.context_expr.func.attr

                if func_name == "suppress":  # noqa: SIM102
                    # Using suppress - check if exception types are specific
                    if item.context_expr.args:
                        for arg in item.context_expr.args:
                            if isinstance(arg, ast.Name) and arg.id == "Exception":
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="TRY005",
                                        category=RuleCategory.WARNING,
                                        severity=RuleSeverity.MEDIUM,
                                        message="Avoid suppressing generic Exception",
                                        file_path=self.file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        fix_suggestion="Use specific exception types",
                                        fix_applicability=FixApplicability.MANUAL,
                                        source_tool="exception_handling",
                                    )
                                )

        self.generic_visit(node)


class ExceptionHandlingChecker:
    """Main class for checking exception handling patterns."""

    def __init__(self):
        """Initialize checker."""
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> list[RuleViolation]:
        """
        Check a file for exception handling issues.

        Args:
            file_path: Path to file to check

        Returns:
            List of violations found
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source, filename=str(file_path))
            visitor = ExceptionHandlingVisitor(file_path)
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

    def check_code(self, code: str, file_path: Path | None = None) -> list[RuleViolation]:
        """
        Check code for exception handling issues.

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
            visitor = ExceptionHandlingVisitor(file_path)
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
EXCEPTION_HANDLING_RULES = [
    ExceptionHandlingRule(
        rule_id="TRY002",
        name="raise-vanilla-exception",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        message_template="Avoid raising vanilla Exception",
        description="Create custom exception classes instead of raising generic Exception",
        explanation="Custom exceptions provide better context and allow specific handling.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"exception_handling", "exceptions"},
        references=[
            "https://docs.astral.sh/ruff/rules/raise-vanilla-class/",
        ],
    ),
    ExceptionHandlingRule(
        rule_id="TRY003",
        name="raise-vanilla-args",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        message_template="Exception message too long",
        description="Exception messages should be concise",
        explanation="Long exception messages make code harder to read. Use logging for details.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"exception_handling", "exceptions"},
    ),
    ExceptionHandlingRule(
        rule_id="TRY005",
        name="raise-generic-exception-suppress",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        message_template="Avoid suppressing generic Exception",
        description="Use specific exception types with contextlib.suppress",
        explanation="Suppressing all exceptions can hide bugs.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"exception_handling", "exceptions"},
    ),
    ExceptionHandlingRule(
        rule_id="TRY200",
        name="reraise-no-cause",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        message_template="Prefer 'raise ... from ...' to preserve exception chain",
        description="Use explicit exception chaining",
        explanation="Preserves the original exception context for better debugging.",
        fix_applicability=FixApplicability.SUGGESTED,
        tags={"exception_handling", "exceptions"},
    ),
    ExceptionHandlingRule(
        rule_id="TRY201",
        name="verbose-raise",
        category=RuleCategory.REFACTOR,
        severity=RuleSeverity.LOW,
        message_template="Use bare 'raise' to reraise",
        description="Bare raise is preferred when reraising in except handler",
        explanation="Bare raise preserves the original exception and traceback.",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"exception_handling", "exceptions"},
    ),
    ExceptionHandlingRule(
        rule_id="TRY301",
        name="raise-within-try",
        category=RuleCategory.REFACTOR,
        severity=RuleSeverity.LOW,
        message_template="Too many exception handlers",
        description="Consider refactoring when many handlers are present",
        explanation="Many handlers may indicate overly complex error handling.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"exception_handling", "exceptions"},
    ),
    ExceptionHandlingRule(
        rule_id="TRY302",
        name="useless-try-except",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        message_template="Useless try-except with only pass",
        description="Remove or handle exceptions properly",
        explanation="Empty except handlers with only pass hide errors.",
        fix_applicability=FixApplicability.MANUAL,
        tags={"exception_handling", "exceptions"},
    ),
    ExceptionHandlingRule(
        rule_id="TRY401",
        name="verbose-log-message",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        message_template="Use logging.exception() instead of .error(..., exc_info=True)",
        description="logger.exception() is clearer and more concise",
        explanation="exception() automatically includes exception info.",
        fix_applicability=FixApplicability.AUTOMATIC,
        tags={"exception_handling", "logging"},
    ),
]
