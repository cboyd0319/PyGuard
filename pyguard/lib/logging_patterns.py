"""
Logging pattern detection and best practices (LOG prefix rules).

This module implements flake8-logging and flake8-logging-format rules
to detect common logging mistakes and anti-patterns.

Part of PyGuard's comprehensive linter replacement initiative.
"""

import ast
from dataclasses import dataclass


@dataclass
class LoggingIssue:
    """Represents a logging pattern issue."""

    rule_id: str
    line: int
    col: int
    message: str
    severity: str = "MEDIUM"
    category: str = "logging"
    suggested_fix: str | None = None


class LoggingPatternVisitor(ast.NodeVisitor):
    """
    AST visitor to detect logging anti-patterns and issues.

    Detects patterns like:
    - String formatting in logging calls (use lazy %)
    - Exception info not captured properly
    - Redundant exc_info parameter
    - Using warn() instead of warning()
    - And more...
    """

    def __init__(self):
        # TODO: Add docstring
        self.issues: list[LoggingIssue] = []
        self.logger_names: set[str] = {"logging", "logger", "log", "LOGGER", "LOG"}

    def visit_Call(self, node: ast.Call) -> None:
        """Check for logging-related calls."""
        if isinstance(node.func, ast.Attribute):
            self._check_logging_call(node)

        self.generic_visit(node)

    def _check_logging_call(self, node: ast.Call) -> None:
        """Check if this is a logging call and validate it."""
        if not isinstance(node.func, ast.Attribute):
            return

        # Check if it's a logging method
        method_name = node.func.attr
        if method_name not in {
            "debug",
            "info",
            "warning",
            "error",
            "critical",
            "log",
            "exception",
            "warn",
        }:
            return

        # Check if it's called on a logger object
        if isinstance(node.func.value, ast.Name):
            caller_name = node.func.value.id
            if caller_name not in self.logger_names and not caller_name.lower().endswith("logger"):
                return
        elif isinstance(node.func.value, ast.Attribute):
            # logging.debug(), logging.info(), etc.
            if isinstance(node.func.value.value, ast.Name):  # noqa: SIM102
                if node.func.value.value.id != "logging":
                    return

        # Now we know it's a logging call, check for issues
        self._check_string_formatting(node, method_name)
        self._check_warn_deprecated(node, method_name)
        self._check_exception_without_exc_info(node, method_name)
        self._check_redundant_exc_info(node, method_name)
        self._check_string_concat(node, method_name)

    def _check_string_formatting(self, node: ast.Call, _method_name: str) -> None:
        """Check for string formatting in logging calls.

        Args:
            node: Call node to check
            _method_name: Logging method name (reserved for context)
        """
        if not node.args:
            return

        first_arg = node.args[0]

        # Check for f-strings (LOG001)
        if isinstance(first_arg, ast.JoinedStr):
            self.issues.append(
                LoggingIssue(
                    rule_id="LOG001",
                    line=node.lineno,
                    col=node.col_offset,
                    message="Avoid f-strings in logging calls, use lazy % formatting",
                    severity="MEDIUM",
                    suggested_fix="Use logger.info('message %s', variable) instead of f-strings",
                )
            )

        # Check for .format() calls (LOG002)
        elif isinstance(first_arg, ast.Call):
            if isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                self.issues.append(
                    LoggingIssue(
                        rule_id="LOG002",
                        line=node.lineno,
                        col=node.col_offset,
                        message="Avoid .format() in logging calls, use lazy % formatting",
                        severity="MEDIUM",
                        suggested_fix="Use logger.info('message %s', variable) instead of .format()",
                    )
                )

        # Check for % formatting in the call (acceptable)
        # But check for string concatenation
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
            self._check_if_string_concat(first_arg, node)

    def _check_if_string_concat(self, binop: ast.BinOp, node: ast.Call) -> None:
        """Check if this is string concatenation."""
        # If both sides are strings or contain strings, it's likely concatenation
        if self._contains_string(binop.left) or self._contains_string(binop.right):
            self.issues.append(
                LoggingIssue(
                    rule_id="LOG005",
                    line=node.lineno,
                    col=node.col_offset,
                    message="Avoid string concatenation in logging, use lazy formatting",
                    severity="MEDIUM",
                    suggested_fix="Use logger.info('message %s', variable) instead of concatenation",
                )
            )

    def _contains_string(self, node: ast.AST) -> bool:
        """Check if node contains string constants."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.BinOp):
            return self._contains_string(node.left) or self._contains_string(node.right)
        return False

    def _check_string_concat(self, node: ast.Call, _method_name: str) -> None:
        """Check for string concatenation in logging.

        Args:
            node: Call node to check
            _method_name: Logging method name (reserved for context)
        """
        if not node.args:
            return

        # Already handled in _check_string_formatting via _check_if_string_concat
        pass

    def _check_warn_deprecated(self, node: ast.Call, method_name: str) -> None:
        """Check for deprecated warn() method."""
        if method_name == "warn":
            self.issues.append(
                LoggingIssue(
                    rule_id="LOG003",
                    line=node.lineno,
                    col=node.col_offset,
                    message="Use warning() instead of deprecated warn()",
                    severity="LOW",
                    suggested_fix="Replace logger.warn() with logger.warning()",
                )
            )

    def _check_exception_without_exc_info(self, node: ast.Call, method_name: str) -> None:
        """Check for logging in except blocks without exc_info."""
        # This is a simplified check - would need more context for full analysis
        # For now, just check if error/critical is called and we're in an except block
        pass  # Needs control flow analysis

    def _check_redundant_exc_info(self, node: ast.Call, method_name: str) -> None:
        """Check for redundant exc_info in exception() calls."""
        if method_name == "exception":
            # exception() already includes exc_info=True by default
            for keyword in node.keywords:
                if keyword.arg == "exc_info":
                    self.issues.append(
                        LoggingIssue(
                            rule_id="LOG004",
                            line=node.lineno,
                            col=node.col_offset,
                            message="Redundant exc_info in exception() call (already included)",
                            severity="LOW",
                            suggested_fix="Remove exc_info=True from logger.exception() call",
                        )
                    )


class LoggingChecker:
    """Main checker class for logging pattern detection."""

    def __init__(self):
        # TODO: Add docstring
        self.visitor = LoggingPatternVisitor()

    def check_code(self, code: str, filename: str = "<string>") -> list[LoggingIssue]:
        """
        Check Python code for logging anti-patterns.

        Args:
            code: Python source code to check
            filename: Optional filename for error reporting

        Returns:
            List of LoggingIssue objects representing detected issues
        """
        try:
            tree = ast.parse(code, filename=filename)
            self.visitor.visit(tree)
            return self.visitor.issues
        except SyntaxError:
            return []

    def get_issues(self) -> list[LoggingIssue]:
        """Get all detected issues."""
        return self.visitor.issues


def check_file(filepath: str) -> list[LoggingIssue]:
    """
    Check a Python file for logging anti-patterns.

    Args:
        filepath: Path to Python file

    Returns:
        List of LoggingIssue objects
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            code = f.read()
        checker = LoggingChecker()
        return checker.check_code(code, filepath)
    except Exception:
        return []
