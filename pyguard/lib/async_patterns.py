"""
Async pattern detection and best practices (ASYNC prefix rules).

This module implements flake8-async rules to detect common mistakes
and anti-patterns in async/await code. Helps catch blocking calls
in async functions, improper async context manager usage, and more.

Part of PyGuard's comprehensive linter replacement initiative.
"""

import ast
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass
class AsyncIssue:
    """Represents an async pattern issue."""

    rule_id: str
    line: int
    col: int
    message: str
    severity: str = "HIGH"
    category: str = "async"
    suggested_fix: Optional[str] = None


class AsyncPatternVisitor(ast.NodeVisitor):
    """
    AST visitor to detect async anti-patterns and issues.

    Detects patterns like:
    - Blocking I/O calls in async functions
    - Missing await on async functions
    - time.sleep() instead of asyncio.sleep()
    - open() instead of aiofiles
    - And more...
    """

    def __init__(self):
        self.issues: List[AsyncIssue] = []
        self.in_async_function = False
        self.current_function: Optional[str] = None
        self.has_await_in_function = False
        self.blocking_calls: Set[str] = {
            "open",
            "read",
            "write",
            "close",
            "time.sleep",
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "urllib.request.urlopen",
        }

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition."""
        # Save previous state
        prev_in_async = self.in_async_function
        prev_function = self.current_function
        prev_has_await = self.has_await_in_function

        # Set new state
        self.in_async_function = True
        self.current_function = node.name
        self.has_await_in_function = False

        # Visit function body
        self.generic_visit(node)

        # Check if async function has no await
        if not self.has_await_in_function:
            self.issues.append(
                AsyncIssue(
                    rule_id="ASYNC102",
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"Async function '{node.name}' has no await, consider making it synchronous",
                    severity="MEDIUM",
                    suggested_fix="Remove 'async' keyword or add await statements",
                )
            )

        # Restore previous state
        self.in_async_function = prev_in_async
        self.current_function = prev_function
        self.has_await_in_function = prev_has_await

    def visit_Await(self, node: ast.Await) -> None:
        """Track await statements."""
        self.has_await_in_function = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for blocking calls in async functions."""
        if self.in_async_function:
            self._check_blocking_call(node)
            self._check_time_sleep(node)
            self._check_open_call(node)
            self._check_sync_requests(node)

        self.generic_visit(node)

    def _check_blocking_call(self, node: ast.Call) -> None:
        """Check for generic blocking calls."""
        call_name = self._get_call_name(node)

        if call_name in self.blocking_calls:
            self.issues.append(
                AsyncIssue(
                    rule_id="ASYNC100",
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"Blocking call '{call_name}' in async function '{self.current_function}'",
                    severity="HIGH",
                    suggested_fix="Use async equivalent (e.g., aiohttp, aiofiles)",
                )
            )

    def _check_time_sleep(self, node: ast.Call) -> None:
        """Check for time.sleep() in async function."""
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "time"
                and node.func.attr == "sleep"
            ):
                self.issues.append(
                    AsyncIssue(
                        rule_id="ASYNC101",
                        line=node.lineno,
                        col=node.col_offset,
                        message="Use 'await asyncio.sleep()' instead of 'time.sleep()' in async function",
                        severity="HIGH",
                        suggested_fix="Replace time.sleep() with await asyncio.sleep()",
                    )
                )

    def _check_open_call(self, node: ast.Call) -> None:
        """Check for open() in async function."""
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            self.issues.append(
                AsyncIssue(
                    rule_id="ASYNC105",
                    line=node.lineno,
                    col=node.col_offset,
                    message="Use async file operations (aiofiles) instead of open() in async function",
                    severity="MEDIUM",
                    suggested_fix="Use 'async with aiofiles.open()' instead of open()",
                )
            )

    def _check_sync_requests(self, node: ast.Call) -> None:
        """Check for synchronous HTTP requests in async function."""
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "requests"
                and node.func.attr in {"get", "post", "put", "delete", "patch"}
            ):
                self.issues.append(
                    AsyncIssue(
                        rule_id="ASYNC106",
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"Use async HTTP client (aiohttp) instead of requests.{node.func.attr}()",
                        severity="HIGH",
                        suggested_fix="Use 'async with aiohttp.ClientSession()' for HTTP requests",
                    )
                )

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ""

    def visit_With(self, node: ast.With) -> None:
        """Check for non-async context managers in async functions."""
        if self.in_async_function and not isinstance(node, ast.AsyncWith):
            # Check if context manager should be async
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    call_name = self._get_call_name(item.context_expr)
                    if "open" in call_name or "connection" in call_name.lower():
                        self.issues.append(
                            AsyncIssue(
                                rule_id="ASYNC107",
                                line=node.lineno,
                                col=node.col_offset,
                                message="Use 'async with' for async context managers",
                                severity="MEDIUM",
                                suggested_fix="Replace 'with' with 'async with'",
                            )
                        )

        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Check for non-async iteration in async functions."""
        if self.in_async_function and not isinstance(node, ast.AsyncFor):
            # Check if we're iterating over something that should be async
            if isinstance(node.iter, ast.Call):
                call_name = self._get_call_name(node.iter)
                if any(
                    keyword in call_name.lower() for keyword in ["fetch", "query", "read", "get"]
                ):
                    self.issues.append(
                        AsyncIssue(
                            rule_id="ASYNC108",
                            line=node.lineno,
                            col=node.col_offset,
                            message="Consider using 'async for' for async iterables",
                            severity="LOW",
                            suggested_fix="Use 'async for' if iterating over async iterable",
                        )
                    )

        self.generic_visit(node)


class AsyncChecker:
    """Main checker class for async pattern detection."""

    def __init__(self):
        self.visitor = AsyncPatternVisitor()

    def check_code(self, code: str, filename: str = "<string>") -> List[AsyncIssue]:
        """
        Check Python code for async anti-patterns.

        Args:
            code: Python source code to check
            filename: Optional filename for error reporting

        Returns:
            List of AsyncIssue objects representing detected issues
        """
        try:
            tree = ast.parse(code, filename=filename)
            self.visitor.visit(tree)
            return self.visitor.issues
        except SyntaxError:
            return []

    def get_issues(self) -> List[AsyncIssue]:
        """Get all detected issues."""
        return self.visitor.issues


def check_file(filepath: str) -> List[AsyncIssue]:
    """
    Check a Python file for async anti-patterns.

    Args:
        filepath: Path to Python file

    Returns:
        List of AsyncIssue objects
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            code = f.read()
        checker = AsyncChecker()
        return checker.check_code(code, filepath)
    except Exception:
        return []
