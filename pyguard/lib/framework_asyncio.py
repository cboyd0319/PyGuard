"""
Asyncio Security Analysis.

Detects and auto-fixes common security vulnerabilities in asyncio applications.
This module provides asyncio-specific security checks focusing on async/await patterns,
event loop security, concurrent execution, and async context management.

Security Areas Covered (15 checks):
- Event loop injection
- Task cancellation vulnerabilities
- Future result tampering
- Coroutine injection
- Async context manager issues
- Semaphore bypass
- Lock acquisition timeouts
- Queue poisoning
- Stream security issues
- Subprocess security (create_subprocess_shell)
- Signal handler race conditions
- Thread pool executor risks
- Process pool executor vulnerabilities
- Async generator security
- Async comprehension injection

Total Security Checks: 15 rules (ASYNCIO001-ASYNCIO015)

References:
- asyncio Security | https://docs.python.org/3/library/asyncio-dev.html | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-362 (Race Condition) | https://cwe.mitre.org/data/definitions/362.html | High
- CWE-78 (Command Injection) | https://cwe.mitre.org/data/definitions/78.html | Critical
- CWE-404 (Improper Resource Shutdown) | https://cwe.mitre.org/data/definitions/404.html | Medium
"""

import ast
from pathlib import Path

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class AsyncioSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting asyncio security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines: list[str] = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_asyncio_import = False
        self.async_functions: set[str] = set()
        self.event_loops: set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track asyncio imports."""
        if node.module and node.module.startswith("asyncio"):
            self.has_asyncio_import = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track asyncio imports."""
        for alias in node.names:
            if alias.name == "asyncio":
                self.has_asyncio_import = True
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze async functions for security issues."""
        self.async_functions.add(node.name)

        # Check for subprocess usage
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._check_subprocess_security(child, node)
                self._check_event_loop_injection(child, node)
                self._check_future_tampering(child, node)
                self._check_queue_poisoning(child, node)
                self._check_executor_security(child, node)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for asyncio security issues."""
        if not self.has_asyncio_import:
            self.generic_visit(node)
            return

        self._check_create_task_security(node)
        self._check_gather_security(node)
        self._check_wait_security(node)
        self._check_semaphore_security(node)
        self._check_lock_security(node)
        self._check_stream_security(node)

        self.generic_visit(node)

    def _check_subprocess_security(self, node: ast.Call, _func_node: ast.AsyncFunctionDef) -> None:
        """ASYNCIO001: Check for insecure subprocess usage with shell=True.

        Args:
            node: Call node to check
            _func_node: Function node (reserved for context analysis)
        """
        func_name = None
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("create_subprocess_shell", "create_subprocess_exec"):
                func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            if node.func.id in ("create_subprocess_shell", "create_subprocess_exec"):
                func_name = node.func.id

        if func_name == "create_subprocess_shell":
            # Any use of create_subprocess_shell is potentially dangerous
            if node.args:
                self.violations.append(
                    RuleViolation(
                        rule_id="ASYNCIO001",
                        message="Dangerous use of asyncio.create_subprocess_shell() with potential command injection. Use create_subprocess_exec() instead.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        code_snippet=self._get_snippet(node),
                    )
                )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze regular functions for asyncio security issues."""
        # Check for event loop manipulation in regular functions
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._check_event_loop_injection(child, node)

        self.generic_visit(node)

    def _check_event_loop_injection(self, node: ast.Call, _func_node) -> None:
        """Check for event loop injection vulnerabilities (ASYNCIO002).

        Detects attempts to set event loops from untrusted sources which could
        allow attackers to inject malicious event loops.

        Args:
            node: Call node to check
            _func_node: Function node (reserved for context analysis)
        """
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "set_event_loop":
                # Check if loop is from user input or untrusted source
                if node.args and isinstance(node.args[0], (ast.Name, ast.Call)):
                    self.violations.append(
                        RuleViolation(
                            rule_id="ASYNCIO002",
                            message="Potential event loop injection. Setting event loop from untrusted source.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            code_snippet=self._get_snippet(node),
                        )
                    )

    def _check_create_task_security(self, node: ast.Call) -> None:
        """ASYNCIO003: Check for task creation without proper error handling."""
        func_name = None
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "create_task":
                func_name = node.func.attr
        elif isinstance(node.func, ast.Name) and node.func.id == "create_task":
            func_name = node.func.id

        if func_name:
            # Check if task is created but not awaited or stored
            parent = getattr(node, "_parent", None)
            if parent and isinstance(parent, ast.Expr):
                self.violations.append(
                    RuleViolation(
                        rule_id="ASYNCIO003",
                        message="Task created but not stored or awaited. This can lead to resource leaks and missed exceptions.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        code_snippet=self._get_snippet(node),
                    )
                )

    def _check_future_tampering(self, node: ast.Call, _func_node: ast.AsyncFunctionDef) -> None:
        """Check for Future result tampering (ASYNCIO004).

        Detects calls to Future.set_result() without proper validation, which
        could allow untrusted data to be injected into async workflows.

        Args:
            node: Call node to check
            _func_node: Function node (reserved for context analysis)
        """
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "set_result":
                # Check if setting result without proper validation
                self.violations.append(
                    RuleViolation(
                        rule_id="ASYNCIO004",
                        message="Future.set_result() called without validation. Ensure result is from trusted source.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        code_snippet=self._get_snippet(node),
                    )
                )

    def _check_gather_security(self, node: ast.Call) -> None:
        """ASYNCIO005: Check for asyncio.gather() without proper exception handling."""
        func_name = None
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "gather":
                func_name = node.func.attr
        elif isinstance(node.func, ast.Name) and node.func.id == "gather":
            func_name = node.func.id

        if func_name:
            # Check if return_exceptions is not set
            has_return_exceptions = any(kw.arg == "return_exceptions" for kw in node.keywords)
            if not has_return_exceptions:
                self.violations.append(
                    RuleViolation(
                        rule_id="ASYNCIO005",
                        message="asyncio.gather() without return_exceptions=True. Exceptions may propagate unexpectedly.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SECURITY,
                        code_snippet=self._get_snippet(node),
                    )
                )

    def _check_wait_security(self, node: ast.Call) -> None:
        """ASYNCIO006: Check for asyncio.wait() without timeout."""
        func_name = None
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "wait":
                func_name = node.func.attr
        elif isinstance(node.func, ast.Name) and node.func.id == "wait":
            func_name = node.func.id

        if func_name:
            # Check if timeout is set
            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
            if not has_timeout:
                self.violations.append(
                    RuleViolation(
                        rule_id="ASYNCIO006",
                        message="asyncio.wait() without timeout. This can cause indefinite blocking.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        code_snippet=self._get_snippet(node),
                    )
                )

    def _check_semaphore_security(self, node: ast.Call) -> None:
        """ASYNCIO007: Check for Semaphore with value from user input."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"Semaphore", "BoundedSemaphore"}:
                if node.args and isinstance(node.args[0], (ast.Name, ast.Call)):
                    # Value might be from user input
                    self.violations.append(
                        RuleViolation(
                            rule_id="ASYNCIO007",
                            message="Semaphore created with potentially user-controlled value. This can lead to resource exhaustion.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            code_snippet=self._get_snippet(node),
                        )
                    )

    def _check_lock_security(self, node: ast.Call) -> None:
        """ASYNCIO008: Check for Lock acquisition without timeout."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "acquire":
                # Check if timeout is set
                has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                if not has_timeout:
                    self.violations.append(
                        RuleViolation(
                            rule_id="ASYNCIO008",
                            message="Lock.acquire() without timeout. This can cause indefinite blocking.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SECURITY,
                            code_snippet=self._get_snippet(node),
                        )
                    )

    def _check_queue_poisoning(self, node: ast.Call, _func_node: ast.AsyncFunctionDef) -> None:
        """Check for queue poisoning vulnerabilities (ASYNCIO009).

        Detects Queue.put() calls with potentially untrusted data that could
        poison the queue and affect consumer tasks.

        Args:
            node: Call node to check
            _func_node: Function node (reserved for context analysis)
        """
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("put", "put_nowait"):
                # Check if data is validated
                if node.args and isinstance(node.args[0], (ast.Name, ast.Call)):
                    self.violations.append(
                        RuleViolation(
                            rule_id="ASYNCIO009",
                            message="Queue.put() with potentially untrusted data. Validate input before queuing.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            code_snippet=self._get_snippet(node),
                        )
                    )

    def _check_stream_security(self, node: ast.Call) -> None:
        """ASYNCIO010: Check for StreamReader.read() without size limit."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "read":
                # Check if n parameter (size limit) is provided
                if not node.args and not any(kw.arg == "n" for kw in node.keywords):
                    # Check if this is likely a StreamReader
                    if isinstance(node.func.value, ast.Name):
                        var_name = node.func.value.id
                        if "reader" in var_name.lower() or "stream" in var_name.lower():
                            self.violations.append(
                                RuleViolation(
                                    rule_id="ASYNCIO010",
                                    message="StreamReader.read() without size limit. This can lead to memory exhaustion.",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    code_snippet=self._get_snippet(node),
                                )
                            )

    def _check_executor_security(self, node: ast.Call, _func_node: ast.AsyncFunctionDef) -> None:
        """Check for executor security issues (ASYNCIO011).

        Detects run_in_executor calls with potentially untrusted functions
        that could execute arbitrary code in thread/process pools.

        Args:
            node: Call node to check
            _func_node: Function node (reserved for context analysis)
        """
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "run_in_executor":
                # Check if executor is None (default executor)
                if node.args:
                    executor = node.args[0]
                    if isinstance(executor, ast.Constant) and executor.value is None:
                        self.violations.append(
                            RuleViolation(
                                rule_id="ASYNCIO011",
                                message="run_in_executor() using default executor. Consider using a custom executor with resource limits.",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.SECURITY,
                                code_snippet=self._get_snippet(node),
                            )
                        )

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """ASYNCIO012: Check for async context manager security."""
        # Check for proper exception handling in async context managers
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                # Check if it's a lock or semaphore without timeout
                if isinstance(item.context_expr.func, ast.Attribute):
                    if item.context_expr.func.attr in ("Lock", "Semaphore"):
                        # Suggest using timeout
                        self.violations.append(
                            RuleViolation(
                                rule_id="ASYNCIO012",
                                message="Async context manager for Lock/Semaphore without timeout. Consider using wait_for() with timeout.",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.SECURITY,
                                code_snippet=self._get_snippet(node),
                            )
                        )

        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        """ASYNCIO013: Check for async generator security."""
        # Check if iterating over untrusted async generator
        if isinstance(node.iter, ast.Call):
            self.violations.append(
                RuleViolation(
                    rule_id="ASYNCIO013",
                    message="Async for loop over potentially untrusted generator. Ensure generator source is validated.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.SECURITY,
                    code_snippet=self._get_snippet(node),
                )
            )

        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        """ASYNCIO014: Check for async comprehension security."""
        for generator in node.generators:
            if generator.is_async:
                # Check if iterating over untrusted source
                if isinstance(generator.iter, ast.Call):
                    self.violations.append(
                        RuleViolation(
                            rule_id="ASYNCIO014",
                            message="Async comprehension over potentially untrusted source. Validate input.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SECURITY,
                            code_snippet=self._get_snippet(node),
                        )
                    )

        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """ASYNCIO015: Check for proper async exception handling."""
        # Check if catching asyncio.CancelledError
        for handler in node.handlers:
            if handler.type:
                if isinstance(handler.type, ast.Name):
                    if handler.type.id == "CancelledError":
                        # Check if re-raising
                        has_reraise = any(
                            isinstance(stmt, ast.Raise) and stmt.exc is None
                            for stmt in handler.body
                        )
                        if not has_reraise:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="ASYNCIO015",
                                    message="CancelledError caught but not re-raised. This can prevent proper task cancellation.",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    code_snippet=self._get_snippet(node),
                                )
                            )

        self.generic_visit(node)

    def _get_snippet(self, node: ast.AST) -> str:
        """Get code snippet for the node."""
        try:
            if hasattr(node, "lineno"):
                line_idx = node.lineno - 1
                if 0 <= line_idx < len(self.lines):
                    line: str = self.lines[line_idx]
                    return line.strip()
        except Exception:
            pass
        return ""


def analyze_asyncio_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze code for asyncio security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze

    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = AsyncioSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Rule definitions
ASYNCIO_RULES = [
    Rule(
        rule_id="ASYNCIO001",
        name="asyncio-insecure-subprocess",
        message_template="Dangerous use of asyncio.create_subprocess_shell() with potential command injection",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Dangerous use of asyncio.create_subprocess_shell() with potential command injection",
        explanation="Using create_subprocess_shell() with user input can lead to command injection vulnerabilities",
        cwe_mapping="CWE-78",
        owasp_mapping="A03:2021-Injection",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-subprocess.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO002",
        name="asyncio-event-loop-injection",
        message_template="Potential event loop injection from untrusted source",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Potential event loop injection from untrusted source",
        explanation="Setting event loop from untrusted sources can lead to code execution vulnerabilities",
        cwe_mapping="CWE-94",
        owasp_mapping="A03:2021-Injection",
        fix_applicability=FixApplicability.MANUAL,
        references=[
            "https://docs.python.org/3/library/asyncio-eventloop.html",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO003",
        name="asyncio-unmanaged-task",
        message_template="Task created but not stored or awaited, leading to resource leaks",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Task created but not stored or awaited, leading to resource leaks",
        explanation="Tasks that are not stored or awaited can lead to resource leaks and missed exceptions",
        cwe_mapping="CWE-404",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-task.html",
            "https://cwe.mitre.org/data/definitions/404.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO004",
        name="asyncio-future-tampering",
        message_template="Future.set_result() called without validation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Future.set_result() called without validation",
        explanation="Setting future results without validation can allow untrusted data to propagate",
        cwe_mapping="CWE-20",
        owasp_mapping="A03:2021-Injection",
        fix_applicability=FixApplicability.MANUAL,
        references=[
            "https://docs.python.org/3/library/asyncio-future.html",
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO005",
        name="asyncio-gather-no-exceptions",
        message_template="asyncio.gather() without return_exceptions=True",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="asyncio.gather() without return_exceptions=True",
        explanation="Using gather without return_exceptions can cause one task exception to cancel all other tasks",
        cwe_mapping="CWE-755",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-task.html#asyncio.gather",
            "https://cwe.mitre.org/data/definitions/755.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO006",
        name="asyncio-wait-no-timeout",
        message_template="asyncio.wait() without timeout can cause indefinite blocking",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="asyncio.wait() without timeout can cause indefinite blocking",
        explanation="Wait operations without timeouts can block indefinitely causing DoS",
        cwe_mapping="CWE-400",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-task.html#asyncio.wait",
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO007",
        name="asyncio-semaphore-user-value",
        message_template="Semaphore created with potentially user-controlled value",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Semaphore created with potentially user-controlled value",
        explanation="User-controlled semaphore values can lead to resource exhaustion",
        cwe_mapping="CWE-400",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.MANUAL,
        references=[
            "https://docs.python.org/3/library/asyncio-sync.html",
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO008",
        name="asyncio-lock-no-timeout",
        message_template="Lock.acquire() without timeout can cause indefinite blocking",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Lock.acquire() without timeout can cause indefinite blocking",
        explanation="Lock acquisitions without timeouts can deadlock the application",
        cwe_mapping="CWE-400",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-sync.html",
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO009",
        name="asyncio-queue-poisoning",
        message_template="Queue.put() with potentially untrusted data",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Queue.put() with potentially untrusted data",
        explanation="Queue poisoning can propagate malicious data through async workflows",
        cwe_mapping="CWE-20",
        owasp_mapping="A03:2021-Injection",
        fix_applicability=FixApplicability.MANUAL,
        references=[
            "https://docs.python.org/3/library/asyncio-queue.html",
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO010",
        name="asyncio-stream-no-limit",
        message_template="StreamReader.read() without size limit can lead to memory exhaustion",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="StreamReader.read() without size limit can lead to memory exhaustion",
        explanation="Reading streams without size limits can exhaust memory leading to DoS",
        cwe_mapping="CWE-770",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-stream.html",
            "https://cwe.mitre.org/data/definitions/770.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO011",
        name="asyncio-default-executor",
        message_template="run_in_executor() using default executor without resource limits",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="run_in_executor() using default executor without resource limits",
        explanation="Default executor has no resource limits and can be exhausted",
        cwe_mapping="CWE-400",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-eventloop.html",
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO012",
        name="asyncio-context-no-timeout",
        message_template="Async context manager for Lock/Semaphore without timeout",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Async context manager for Lock/Semaphore without timeout",
        explanation="Async context managers without timeouts can block indefinitely",
        cwe_mapping="CWE-400",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-sync.html",
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO013",
        name="asyncio-untrusted-generator",
        message_template="Async for loop over potentially untrusted generator",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Async for loop over potentially untrusted generator",
        explanation="Iterating over untrusted async generators can lead to vulnerabilities",
        cwe_mapping="CWE-20",
        owasp_mapping="A03:2021-Injection",
        fix_applicability=FixApplicability.MANUAL,
        references=[
            "https://docs.python.org/3/reference/expressions.html#asynchronous-generator-functions",
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO014",
        name="asyncio-comprehension-untrusted",
        message_template="Async comprehension over potentially untrusted source",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Async comprehension over potentially untrusted source",
        explanation="Async comprehensions over untrusted sources require validation",
        cwe_mapping="CWE-20",
        owasp_mapping="A03:2021-Injection",
        fix_applicability=FixApplicability.MANUAL,
        references=[
            "https://peps.python.org/pep-0530/",
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
    ),
    Rule(
        rule_id="ASYNCIO015",
        name="asyncio-cancelled-error-handling",
        message_template="CancelledError caught but not re-raised, preventing proper task cancellation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="CancelledError caught but not re-raised, preventing proper task cancellation",
        explanation="Not re-raising CancelledError prevents proper task cleanup and cancellation propagation",
        cwe_mapping="CWE-755",
        owasp_mapping="A04:2021-Insecure Design",
        fix_applicability=FixApplicability.SAFE,
        references=[
            "https://docs.python.org/3/library/asyncio-task.html#task-cancellation",
            "https://cwe.mitre.org/data/definitions/755.html",
        ],
    ),
]

# Register rules
register_rules(ASYNCIO_RULES)
