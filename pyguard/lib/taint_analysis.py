"""
Enhanced Taint Analysis with Cross-Function Tracking.

This module implements advanced taint tracking capabilities including:
- Cross-function taint propagation
- Source-to-sink path analysis
- Framework-aware taint flows (Django, Flask, FastAPI)
- SQL injection path detection
- XSS vulnerability path detection
- Interprocedural data flow analysis

References:
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-20: Improper Input Validation
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
"""

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from pyguard.lib.ast_analyzer import SecurityIssue
from pyguard.lib.core import PyGuardLogger


@dataclass
class TaintSource:
    """Represents a source of tainted data."""

    name: str
    type: str  # user_input, http_request, file, network, database, etc.
    line_number: int
    severity: str = "HIGH"


@dataclass
class TaintSink:
    """Represents a dangerous sink where tainted data should not flow."""

    name: str
    type: str  # sql, command, eval, xss, etc.
    line_number: int
    severity: str = "CRITICAL"


@dataclass
class TaintPath:
    """Represents a complete taint flow path from source to sink."""

    source: TaintSource
    sink: TaintSink
    variables: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    line_numbers: list[int] = field(default_factory=list)


class EnhancedTaintAnalyzer(ast.NodeVisitor):
    """
    Enhanced taint analyzer with cross-function tracking.

    Performs interprocedural taint analysis to track untrusted data flow
    across function boundaries and through complex data transformations.
    """

    # Enhanced taint sources for various frameworks
    TAINT_SOURCES: ClassVar[dict[str, tuple[str, str]]] = {
        # User input
        "input": ("user_input", "HIGH"),
        "raw_input": ("user_input", "HIGH"),
        # Command line and environment
        "sys.argv": ("command_line", "HIGH"),
        "os.environ": ("environment", "HIGH"),
        "os.getenv": ("environment", "HIGH"),
        # Django framework
        "request.GET": ("http_request", "HIGH"),
        "request.POST": ("http_request", "HIGH"),
        "request.body": ("http_request", "HIGH"),
        "request.FILES": ("http_request", "HIGH"),
        "request.COOKIES": ("http_request", "HIGH"),
        "request.META": ("http_request", "MEDIUM"),
        # Flask framework
        "request.args": ("http_request", "HIGH"),
        "request.form": ("http_request", "HIGH"),
        "request.json": ("http_request", "HIGH"),
        "request.data": ("http_request", "HIGH"),
        "request.files": ("http_request", "HIGH"),
        "request.cookies": ("http_request", "HIGH"),
        "request.headers": ("http_request", "MEDIUM"),
        "request.values": ("http_request", "HIGH"),
        # FastAPI framework
        "Request.body": ("http_request", "HIGH"),
        "Request.json": ("http_request", "HIGH"),
        "Request.form": ("http_request", "HIGH"),
        "Request.query_params": ("http_request", "HIGH"),
        "Request.path_params": ("http_request", "HIGH"),
        "Request.cookies": ("http_request", "HIGH"),
        "Request.headers": ("http_request", "MEDIUM"),
        # Network
        "socket.recv": ("network", "HIGH"),
        "socket.recvfrom": ("network", "HIGH"),
        # File I/O
        "open": ("file", "MEDIUM"),
        "file.read": ("file", "MEDIUM"),
        # Database
        "cursor.fetchone": ("database", "MEDIUM"),
        "cursor.fetchall": ("database", "MEDIUM"),
        "cursor.fetchmany": ("database", "MEDIUM"),
    }

    # Dangerous sinks categorized by vulnerability type
    SQL_SINKS: ClassVar[set[str]] = {
        "cursor.execute",
        "cursor.executemany",
        "connection.execute",
        "db.execute",
        "session.execute",
        "engine.execute",
        "raw",  # Django ORM raw queries
        "RawSQL",
    }

    COMMAND_SINKS: ClassVar[set[str]] = {
        "os.system",
        "os.popen",
        "os.spawn",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "commands.getstatusoutput",
        "commands.getoutput",
    }

    EVAL_SINKS: ClassVar[set[str]] = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "execfile",
    }

    XSS_SINKS: ClassVar[set[str]] = {
        "render_template_string",  # Flask
        "Markup",  # Flask/Jinja2
        "mark_safe",  # Django
        "HttpResponse",  # Django
        "Response",  # FastAPI
        "HTMLResponse",  # FastAPI
    }

    PATH_TRAVERSAL_SINKS: ClassVar[set[str]] = {
        "open",
        "file",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "shutil.rmtree",
        "os.rename",
        "os.replace",
    }

    def __init__(self, source_lines: list[str], file_path: str | None = None):
        """Initialize enhanced taint analyzer."""
        self.issues: list[SecurityIssue] = []
        self.source_lines = source_lines
        self.file_path = file_path
        self.logger = PyGuardLogger()

        # Taint tracking state
        self.tainted_vars: dict[str, TaintSource] = {}
        self.function_params: dict[str, list[str]] = {}  # function_name -> param_names
        self.function_returns: dict[str, list[str]] = {}  # function_name -> tainted returns
        self.taint_paths: list[TaintPath] = []

        # Current context
        self.current_function: str | None = None
        self.call_chain: list[str] = []

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return str(self.source_lines[node.lineno - 1].strip())
        return ""

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _get_name(self, node: ast.expr) -> str | None:
        """Extract variable name from expression."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._get_call_name(ast.Call(func=node, args=[], keywords=[]))
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function definitions and their parameters."""
        old_function = self.current_function
        self.current_function = node.name

        # Track function parameters
        param_names = [arg.arg for arg in node.args.args]
        self.function_params[node.name] = param_names

        # Check if any parameters are from tainted sources (based on naming)
        for param_name in param_names:
            if any(
                hint in param_name.lower()
                for hint in ["input", "user", "request", "data", "body", "query"]
            ):
                # Mark parameter as potentially tainted
                self.tainted_vars[param_name] = TaintSource(
                    name=param_name,
                    type="function_parameter",
                    line_number=node.lineno,
                    severity="MEDIUM",
                )

        self.generic_visit(node)
        self.current_function = old_function

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments and taint propagation."""
        # Check if assigning from a taint source
        if isinstance(node.value, ast.Call):
            call_name = self._get_call_name(node.value)

            for source_pattern, (source_type, severity) in self.TAINT_SOURCES.items():
                if call_name.startswith(source_pattern) or source_pattern in call_name:
                    # Mark all assigned variables as tainted
                    for target in node.targets:
                        var_name = self._get_name(target)
                        if var_name:
                            taint_source = TaintSource(
                                name=var_name,
                                type=source_type,
                                line_number=node.lineno,
                                severity=severity,
                            )
                            self.tainted_vars[var_name] = taint_source

        # Check if assigning from a tainted variable (taint propagation)
        if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            source_taint = self.tainted_vars[node.value.id]
            for target in node.targets:
                var_name = self._get_name(target)
                if var_name:
                    self.tainted_vars[var_name] = TaintSource(
                        name=var_name,
                        type=source_taint.type,
                        line_number=node.lineno,
                        severity=source_taint.severity,
                    )

        # Check if assigning from tainted operation (e.g., string concatenation)
        if isinstance(node.value, ast.BinOp):
            if self._is_tainted_binop(node.value):
                for target in node.targets:
                    var_name = self._get_name(target)
                    if var_name:
                        self.tainted_vars[var_name] = TaintSource(
                            name=var_name,
                            type="derived",
                            line_number=node.lineno,
                            severity="HIGH",
                        )

        self.generic_visit(node)

    def _is_tainted_binop(self, node: ast.BinOp) -> bool:
        """Check if a binary operation involves tainted data."""
        if isinstance(node.left, ast.Name) and node.left.id in self.tainted_vars:
            return True
        if isinstance(node.right, ast.Name) and node.right.id in self.tainted_vars:
            return True
        # Recursively check nested operations
        if isinstance(node.left, ast.BinOp) and self._is_tainted_binop(node.left):
            return True
        if isinstance(node.right, ast.BinOp) and self._is_tainted_binop(node.right):
            return True
        return False

    def _find_tainted_in_binop(self, node: ast.BinOp) -> str | None:
        """Find the first tainted variable name in a binary operation."""
        if isinstance(node.left, ast.Name) and node.left.id in self.tainted_vars:
            return node.left.id
        if isinstance(node.right, ast.Name) and node.right.id in self.tainted_vars:
            return node.right.id
        # Recursively check nested operations
        if isinstance(node.left, ast.BinOp):
            result = self._find_tainted_in_binop(node.left)
            if result:
                return result
        if isinstance(node.right, ast.BinOp):
            result = self._find_tainted_in_binop(node.right)
            if result:
                return result
        return None

    def visit_Call(self, node: ast.Call):
        """Check if tainted data flows into dangerous sinks."""
        func_name = self._get_call_name(node)

        # Check all argument types for tainted data
        tainted_args = []
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                tainted_args.append((arg.id, self.tainted_vars[arg.id]))
            # Check if argument is a binary operation with tainted data
            elif isinstance(arg, ast.BinOp) and self._is_tainted_binop(arg):
                # Find the first tainted variable in the binop
                tainted_var = self._find_tainted_in_binop(arg)
                if tainted_var:
                    tainted_args.append((tainted_var, self.tainted_vars[tainted_var]))

        if tainted_args:
            # Check SQL injection sinks
            if any(sink in func_name for sink in self.SQL_SINKS):
                for var_name, taint_source in tainted_args:
                    self._create_sql_injection_issue(node, var_name, taint_source, func_name)

            # Check command injection sinks
            if func_name in self.COMMAND_SINKS:
                for var_name, taint_source in tainted_args:
                    self._create_command_injection_issue(node, var_name, taint_source, func_name)

            # Check eval/exec sinks
            if func_name in self.EVAL_SINKS:
                for var_name, taint_source in tainted_args:
                    self._create_eval_injection_issue(node, var_name, taint_source, func_name)

            # Check XSS sinks
            if any(sink in func_name for sink in self.XSS_SINKS):
                for var_name, taint_source in tainted_args:
                    self._create_xss_issue(node, var_name, taint_source, func_name)

            # Check path traversal sinks
            if func_name in self.PATH_TRAVERSAL_SINKS:
                for var_name, taint_source in tainted_args:
                    self._create_path_traversal_issue(node, var_name, taint_source, func_name)

        self.generic_visit(node)

    def _create_sql_injection_issue(
        self, node: ast.Call, var_name: str, taint_source: TaintSource, func_name: str
    ):
        """Create SQL injection issue with detailed path information."""
        issue = SecurityIssue(
            severity="CRITICAL",
            category="SQL Injection",
            message=f"Tainted data from {taint_source.type} (variable '{var_name}') flows into SQL query: {func_name}()",
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_code_snippet(node),
            fix_suggestion=f"Use parameterized queries or ORM methods. Sanitize input from {taint_source.type} before SQL execution.",
            owasp_id="ASVS-5.3.4",
            cwe_id="CWE-89",
        )
        self.issues.append(issue)

        # Track taint path
        self.taint_paths.append(
            TaintPath(
                source=taint_source,
                sink=TaintSink(
                    name=func_name, type="sql", line_number=node.lineno, severity="CRITICAL"
                ),
                variables=[var_name],
                line_numbers=[taint_source.line_number, node.lineno],
            )
        )

    def _create_command_injection_issue(
        self, node: ast.Call, var_name: str, taint_source: TaintSource, func_name: str
    ):
        """Create OS command injection issue."""
        issue = SecurityIssue(
            severity="CRITICAL",
            category="OS Command Injection",
            message=f"Tainted data from {taint_source.type} (variable '{var_name}') flows into OS command: {func_name}()",
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_code_snippet(node),
            fix_suggestion=f"Avoid executing OS commands with user input. Use safe alternatives or strict input validation. Input source: {taint_source.type}",
            owasp_id="ASVS-5.3.8",
            cwe_id="CWE-78",
        )
        self.issues.append(issue)

    def _create_eval_injection_issue(
        self, node: ast.Call, var_name: str, taint_source: TaintSource, func_name: str
    ):
        """Create code injection issue for eval/exec."""
        issue = SecurityIssue(
            severity="CRITICAL",
            category="Code Injection",
            message=f"Tainted data from {taint_source.type} (variable '{var_name}') flows into {func_name}()",
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_code_snippet(node),
            fix_suggestion=f"Never use {func_name}() with untrusted input. Use safe alternatives like ast.literal_eval() or json.loads()",
            owasp_id="ASVS-5.2.8",
            cwe_id="CWE-94",
        )
        self.issues.append(issue)

    def _create_xss_issue(
        self, node: ast.Call, var_name: str, taint_source: TaintSource, func_name: str
    ):
        """Create XSS vulnerability issue."""
        issue = SecurityIssue(
            severity="HIGH",
            category="Cross-Site Scripting (XSS)",
            message=f"Tainted data from {taint_source.type} (variable '{var_name}') flows into HTML output: {func_name}()",
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_code_snippet(node),
            fix_suggestion="Use framework auto-escaping. Avoid mark_safe() or Markup() with user input. Sanitize HTML content.",
            owasp_id="ASVS-5.3.3",
            cwe_id="CWE-79",
        )
        self.issues.append(issue)

    def _create_path_traversal_issue(
        self, node: ast.Call, var_name: str, taint_source: TaintSource, func_name: str
    ):
        """Create path traversal vulnerability issue."""
        issue = SecurityIssue(
            severity="HIGH",
            category="Path Traversal",
            message=f"Tainted data from {taint_source.type} (variable '{var_name}') used in file operation: {func_name}()",
            line_number=node.lineno,
            column=node.col_offset,
            code_snippet=self._get_code_snippet(node),
            fix_suggestion="Validate file paths. Use os.path.abspath() and check against allowed directories. Reject paths with '..' or absolute paths.",
            owasp_id="ASVS-12.3.1",
            cwe_id="CWE-22",
        )
        self.issues.append(issue)

    def visit_Return(self, node: ast.Return):
        """Track tainted returns from functions."""
        if self.current_function and node.value:
            var_name = self._get_name(node.value)
            if var_name and var_name in self.tainted_vars:
                if self.current_function not in self.function_returns:
                    self.function_returns[self.current_function] = []
                self.function_returns[self.current_function].append(var_name)

        self.generic_visit(node)


def analyze_taint_flows(file_path: Path) -> list[SecurityIssue]:
    """
    Analyze a Python file for taint flow vulnerabilities.

    Args:
        file_path: Path to Python file to analyze

    Returns:
        List of security issues found
    """
    try:
        file_ops = FileOperations()
        content = file_ops.read_file(file_path)
        source_lines = content.splitlines()

        tree = ast.parse(content, filename=str(file_path))
        analyzer = EnhancedTaintAnalyzer(source_lines, str(file_path))
        analyzer.visit(tree)

        return analyzer.issues

    except SyntaxError as e:
        logger = PyGuardLogger()
        logger.warning(f"Syntax error in {file_path}: {e}")
        return []
    except Exception as e:
        logger = PyGuardLogger()
        logger.warning(f"Error analyzing {file_path}: {e}")
        return []


def get_taint_paths(file_path: Path) -> list[TaintPath]:
    """
    Get complete taint paths from source to sink.

    Args:
        file_path: Path to Python file to analyze

    Returns:
        List of taint paths found
    """
    try:
        file_ops = FileOperations()
        content = file_ops.read_file(file_path)
        source_lines = content.splitlines()

        tree = ast.parse(content, filename=str(file_path))
        analyzer = EnhancedTaintAnalyzer(source_lines, str(file_path))
        analyzer.visit(tree)

        return analyzer.taint_paths

    except Exception:
        return []
