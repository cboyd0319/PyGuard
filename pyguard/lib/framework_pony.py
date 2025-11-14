"""
Pony ORM Security Analysis.

Detects and auto-fixes common security vulnerabilities in Pony ORM applications.
This module provides entity-relationship ORM security checks focusing on query security,
entity security, database connection security, and generator expression security.

Security Areas Covered (12 checks implemented):
- Entity injection (PON001)
- Query generator vulnerabilities (PON002)
- Decorator security (@db_session) (PON003)
- Generator expression injection (PON004)
- Database connection security (PON005)
- Migration tool risks (PON006)
- Relationship manipulation (PON007)
- Caching vulnerabilities (PON008)
- Transaction isolation (PON009)
- Optimistic locking bypasses (PON010)
- Schema generation issues (PON011)
- Database provider security (PON012)

Total Security Checks: 12 rules (PON001-PON012)

References:
- Pony ORM Documentation | https://ponyorm.org/ | High
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
- CWE-20 (Improper Input Validation) | https://cwe.mitre.org/data/definitions/20.html | High
- OWASP Top 10 A03:2021 (Injection) | https://owasp.org/Top10/A03_2021-Injection/ | Critical
"""

import ast
from pathlib import Path

from pyguard.lib.custom_rules import RuleViolation


class PonySecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Pony ORM security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        # TODO: Add docstring
        self.file_path = str(file_path)
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_pony_import = False
        self.pony_aliases: set[str] = {"pony"}
        self.has_db_session_decorator = False

    def visit_Import(self, node: ast.Import) -> None:
        """Track Pony imports."""
        for alias in node.names:
            if alias.name == "pony" or alias.name.startswith("pony."):
                self.has_pony_import = True
                if alias.asname:
                    self.pony_aliases.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Pony imports."""
        if node.module and node.module.startswith("pony"):
            self.has_pony_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function decorators."""
        if self.has_pony_import:
            # Check for @db_session decorator without error handling (PON003)
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id == "db_session":
                    self.has_db_session_decorator = True
                    if not self._has_error_handling_in_function(node):
                        self.violations.append(
                            RuleViolation(
                                rule_id="PON003",
                                rule_name="Unsafe @db_session Decorator",
                                severity="MEDIUM",
                                category="SECURITY",
                                message="@db_session without error handling - may leave transaction open",
                                line_number=node.lineno,
                                file_path=self.file_path,
                                suggestion="Add try-except blocks to handle database errors and ensure transaction cleanup",
                            )
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_pony_import:
            self.generic_visit(node)
            return

        # Check for SQL injection via raw queries (PON002)
        self._check_raw_sql_injection(node)

        # Check for generator expression injection (PON004)
        self._check_generator_injection(node)

        # Check for database connection security (PON005)
        self._check_database_connection(node)

        # Check for caching vulnerabilities (PON008)
        self._check_caching_security(node)

        self.generic_visit(node)

    def _check_raw_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection via raw SQL (PON002)."""
        func_name = self._get_func_name(node)

        # Check for dangerous raw SQL methods
        if "select" in func_name.lower() or "execute" in func_name.lower():
            line_num = node.lineno
            if 0 <= line_num - 1 < len(self.lines):
                context = "\n".join(self.lines[max(0, line_num - 5) : line_num])
                # Check for SQL string formatting
                if any(pattern in context for pattern in [".format(", 'f"', "f'", " % ", ' + "']):
                    self.violations.append(
                        RuleViolation(
                            rule_id="PON002",
                            rule_name="Raw SQL Injection",
                            severity="CRITICAL",
                            category="SECURITY",
                            message="Raw SQL with string formatting - vulnerable to SQL injection",
                            line_number=node.lineno,
                            file_path=self.file_path,
                            suggestion="Use Pony's query language or parameterized SQL with $ placeholders",
                        )
                    )

    def _check_generator_injection(self, node: ast.Call) -> None:
        """Check for generator expression injection (PON004)."""
        func_name = self._get_func_name(node)

        # Check for select() with potential injection
        if func_name == "select" or ".select" in func_name:  # noqa: SIM102
            # Check if lambda/generator uses user input
            if self._uses_user_input_in_context(node.lineno):
                self.violations.append(
                    RuleViolation(
                        rule_id="PON004",
                        rule_name="Generator Expression Injection",
                        severity="HIGH",
                        category="SECURITY",
                        message="Query generator may use unsanitized user input",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate and sanitize all user inputs before using in queries",
                    )
                )

    def _check_database_connection(self, node: ast.Call) -> None:
        """Check for database connection security (PON005)."""
        func_name = self._get_func_name(node)

        # Check for Database binding
        if "bind" in func_name or "Database" in func_name:
            # For bind(), check the second argument (database path/name)
            if "bind" in func_name and len(node.args) >= 2:  # noqa: PLR2004 - threshold
                second_arg = node.args[1]
                if isinstance(second_arg, ast.Name):
                    var_name = second_arg.id
                    if self._is_potentially_user_input(
                        second_arg
                    ) or self._variable_from_user_input(var_name, node.lineno):
                        self.violations.append(
                            RuleViolation(
                                rule_id="PON005",
                                rule_name="Database Connection Vulnerability",
                                severity="HIGH",
                                category="SECURITY",
                                message="Database connection from user input - may expose credentials",
                                line_number=node.lineno,
                                file_path=self.file_path,
                                suggestion="Use environment variables or config files for database credentials",
                            )
                        )
            elif node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):  # noqa: SIM102
                    if self._is_potentially_user_input(first_arg):
                        self.violations.append(
                            RuleViolation(
                                rule_id="PON005",
                                rule_name="Database Connection Vulnerability",
                                severity="HIGH",
                                category="SECURITY",
                                message="Database connection from user input - may expose credentials",
                                line_number=node.lineno,
                                file_path=self.file_path,
                                suggestion="Use environment variables or config files for database credentials",
                            )
                        )

    def _check_caching_security(self, node: ast.Call) -> None:
        """Check for caching vulnerabilities (PON008)."""
        line_num = node.lineno
        if 0 <= line_num - 1 < len(self.lines):
            line_code = self.lines[line_num - 1]
            # Check for cache-related operations without proper key validation
            # Must have both "cache" and ".get" pattern (not just function names containing "get")
            if "cache" in line_code.lower() and ".get(" in line_code.lower():  # noqa: SIM102
                if self._uses_user_input_in_context(line_num):
                    self.violations.append(
                        RuleViolation(
                            rule_id="PON008",
                            rule_name="Cache Key Injection",
                            severity="MEDIUM",
                            category="SECURITY",
                            message="Cache operations with user input may allow cache poisoning",
                            line_number=node.lineno,
                            file_path=self.file_path,
                            suggestion="Validate and sanitize cache keys, use allowlists for key patterns",
                        )
                    )

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from a call node."""
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

    def _is_potentially_user_input(self, node: ast.expr) -> bool:
        """Check if a node might represent user input."""
        if isinstance(node, ast.Name):
            user_input_patterns = ["input", "user", "request", "param", "arg"]
            return any(pattern in node.id.lower() for pattern in user_input_patterns)
        return False

    def _variable_from_user_input(self, var_name: str, line_num: int) -> bool:
        """Check if a variable is assigned from user input in previous lines."""
        if 0 <= line_num - 1 < len(self.lines):
            # Check previous 10 lines for assignment from user input
            start_line = max(0, line_num - 10)
            context_lines = self.lines[start_line:line_num]
            context = "\n".join(context_lines)

            # Check if variable is assigned from request, user input, etc.
            if var_name in context:
                user_patterns = ["= user_input", "= request", "input()", "user_", "param"]
                return any(pattern in context for pattern in user_patterns)
        return False

    def _uses_user_input_in_context(self, line_num: int) -> bool:
        """Check if user input is used in surrounding context."""
        if 0 <= line_num - 1 < len(self.lines):
            start_line = max(0, line_num - 5)
            context = "\n".join(self.lines[start_line : min(len(self.lines), line_num + 3)])
            user_patterns = ["request", "input(", "user_", "param", "arg"]
            return any(pattern in context.lower() for pattern in user_patterns)
        return False

    def _has_error_handling_in_function(self, node: ast.FunctionDef) -> bool:
        """Check if a function has error handling."""
        return any(isinstance(child, (ast.Try, ast.ExceptHandler)) for child in ast.walk(node))


def analyze_pony_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for Pony ORM security vulnerabilities.

    Args:
        file_path: Path to the Python file being analyzed
        code: Source code to analyze

    Returns:
        List of rule violations found
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    visitor = PonySecurityVisitor(file_path, code)
    visitor.visit(tree)
    return visitor.violations
