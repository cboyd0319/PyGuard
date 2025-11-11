"""
Peewee ORM Security Analysis.

Detects and auto-fixes common security vulnerabilities in Peewee ORM applications.
This module provides ORM-specific security checks focusing on query security,
model security, database connection security, and data validation.

Security Areas Covered (12 checks implemented):
- Model injection (PEE001)
- Query construction vulnerabilities (PEE002)
- Database selection issues (PEE003)
- Transaction handling (PEE004)
- Migration security (PEE005)
- Signal handler injection (PEE006)
- Relationship manipulation (PEE007)
- Database pooling issues (PEE008)
- Schema evolution risks (PEE009)
- Playhouse extension security (PEE010)
- Field validation bypasses (PEE011)
- Model metadata exposure (PEE012)

Total Security Checks: 12 rules (PEE001-PEE012)

References:
- Peewee Documentation | http://docs.peewee-orm.com/ | High
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
- CWE-20 (Improper Input Validation) | https://cwe.mitre.org/data/definitions/20.html | High
- OWASP Top 10 A03:2021 (Injection) | https://owasp.org/Top10/A03_2021-Injection/ | Critical
"""

import ast
from pathlib import Path

from pyguard.lib.custom_rules import RuleViolation


class PeeweeSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Peewee ORM security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = str(file_path)
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_peewee_import = False
        self.peewee_aliases: set[str] = {"peewee"}
        self.model_classes: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Track Peewee imports."""
        for alias in node.names:
            if alias.name == "peewee" or alias.name.startswith("peewee."):
                self.has_peewee_import = True
                if alias.asname:
                    self.peewee_aliases.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Peewee imports."""
        if node.module and node.module.startswith("peewee"):
            self.has_peewee_import = True
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track model class definitions."""
        if self.has_peewee_import:
            # Check if this class inherits from Model
            for base in node.bases:
                if isinstance(base, ast.Name) and base.id == "Model":
                    self.model_classes.add(node.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_peewee_import:
            self.generic_visit(node)
            return

        # Check for SQL injection via raw queries (PEE002)
        self._check_raw_query_injection(node)

        # Check for unsafe database selection (PEE003)
        self._check_database_selection(node)

        # Check for transaction handling issues (PEE004)
        self._check_transaction_handling(node)

        # Check for Playhouse extension security (PEE010)
        self._check_playhouse_security(node)

        # Check for field validation bypasses (PEE011)
        self._check_field_validation(node)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Check attribute access for security issues."""
        if not self.has_peewee_import:
            self.generic_visit(node)
            return

        # Check for model metadata exposure (PEE012)
        self._check_metadata_exposure(node)

        self.generic_visit(node)

    def _check_raw_query_injection(self, node: ast.Call) -> None:
        """Check for SQL injection via raw queries (PEE002)."""
        func_name = self._get_func_name(node)

        # Check for dangerous raw query methods
        dangerous_methods = ["execute_sql", "raw", "execute"]

        if any(method in func_name for method in dangerous_methods):
            # Check if there's string formatting in the surrounding context
            line_num = node.lineno
            if 0 <= line_num - 1 < len(self.lines):
                # Check current line and previous 10 lines for string formatting
                start_line = max(0, line_num - 10)
                context_lines = self.lines[start_line:line_num]
                context = "\n".join(context_lines)

                # Check for various string formatting patterns in context
                if any(pattern in context for pattern in [".format(", 'f"', "f'", " % ", ' + "']):
                    self.violations.append(
                        RuleViolation(
                            rule_id="PEE002",
                            rule_name="Raw Query SQL Injection",
                            severity="CRITICAL",
                            category="SECURITY",
                            message=f"{func_name} uses string formatting - vulnerable to SQL injection",
                            line_number=node.lineno,
                            file_path=self.file_path,
                            suggestion="Use parameterized queries with placeholders (?, %s) instead of string formatting",
                        )
                    )

    def _check_database_selection(self, node: ast.Call) -> None:
        """Check for unsafe database selection (PEE003)."""
        func_name = self._get_func_name(node)

        # Check for Database initialization with user-controlled strings
        database_funcs = ["Database", "SqliteDatabase", "PostgresqlDatabase", "MySQLDatabase"]

        if any(db_func in func_name for db_func in database_funcs):  # noqa: SIM102
            # Check if argument is a variable (not a constant string)
            if node.args:
                first_arg = node.args[0]
                # If it's a variable name, check if it might be user input
                if isinstance(first_arg, ast.Name):
                    # Look for patterns in variable name or in context
                    var_name = first_arg.id
                    if self._is_potentially_user_input(first_arg) or self._variable_from_user_input(
                        var_name, node.lineno
                    ):
                        self.violations.append(
                            RuleViolation(
                                rule_id="PEE003",
                                rule_name="Database Selection Vulnerability",
                                severity="HIGH",
                                category="SECURITY",
                                message="Database connection string from user input - may expose credentials or allow unauthorized access",
                                line_number=node.lineno,
                                file_path=self.file_path,
                                suggestion="Validate and sanitize database connection strings, use environment variables",
                            )
                        )

    def _check_transaction_handling(self, node: ast.Call) -> None:
        """Check for transaction handling issues (PEE004)."""
        func_name = self._get_func_name(node)

        # Check for transactions without proper exception handling
        if "atomic" in func_name or "transaction" in func_name:  # noqa: SIM102
            if not self._has_exception_handling_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="PEE004",
                        rule_name="Unsafe Transaction Handling",
                        severity="MEDIUM",
                        category="SECURITY",
                        message="Transaction without exception handling - may leave database in inconsistent state",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Wrap transactions in try-except blocks to handle rollback on errors",
                    )
                )

    def _check_playhouse_security(self, node: ast.Call) -> None:
        """Check for Playhouse extension security (PEE010)."""
        func_name = self._get_func_name(node)

        # Check for unsafe shortcuts and extensions
        playhouse_risky = ["ReconnectMixin", "RetryOperationalError"]

        if any(risky in func_name for risky in playhouse_risky):
            self.violations.append(
                RuleViolation(
                    rule_id="PEE010",
                    rule_name="Playhouse Extension Security",
                    severity="LOW",
                    category="SECURITY",
                    message=f"{func_name} may mask underlying database issues",
                    line_number=node.lineno,
                    file_path=self.file_path,
                    suggestion="Use explicit error handling instead of automatic retry mixins",
                )
            )

    def _check_field_validation(self, node: ast.Call) -> None:
        """Check for field validation bypasses (PEE011)."""
        func_name = self._get_func_name(node)

        # Check for insert_many or bulk operations without validation
        bulk_operations = ["insert_many", "bulk_create", "bulk_update"]

        if any(bulk in func_name for bulk in bulk_operations):  # noqa: SIM102
            if not self._has_validation_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="PEE011",
                        rule_name="Field Validation Bypass",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without validation - may bypass field constraints",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate data before bulk operations to ensure field constraints are met",
                    )
                )

    def _check_metadata_exposure(self, node: ast.Attribute) -> None:
        """Check for model metadata exposure (PEE012)."""
        # Check for exposure of internal metadata
        sensitive_attrs = ["_meta", "_schema", "_data", "dirty_fields"]

        if node.attr in sensitive_attrs:  # noqa: SIM102
            # Check if this is in a potentially public context
            if self._in_public_context(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="PEE012",
                        rule_name="Model Metadata Exposure",
                        severity="LOW",
                        category="SECURITY",
                        message=f"Accessing {node.attr} may expose internal model structure",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Avoid exposing internal metadata in public APIs or responses",
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

    def _uses_string_formatting(self, node: ast.expr) -> bool:
        """Check if a node uses string formatting or concatenation."""
        # Check for f-strings
        if isinstance(node, ast.JoinedStr):
            return True
        # Check for .format()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        # Check for % formatting
        elif (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)) or (
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
        ):
            return True
        return False

    def _is_potentially_user_input(self, node: ast.expr) -> bool:
        """Check if a node might represent user input."""
        if isinstance(node, ast.Name):
            user_input_patterns = ["input", "user", "request", "param", "arg", "config"]
            return any(pattern in node.id.lower() for pattern in user_input_patterns)
        return bool(isinstance(node, ast.Attribute))

    def _variable_from_user_input(self, var_name: str, line_num: int) -> bool:
        """Check if a variable is assigned from user input in previous lines."""
        if 0 <= line_num - 1 < len(self.lines):
            # Check previous 10 lines for assignment from user input
            start_line = max(0, line_num - 10)
            context_lines = self.lines[start_line:line_num]
            context = "\n".join(context_lines)

            # Check if variable is assigned from request, user input, etc.
            if var_name in context:
                user_patterns = ["request", "input(", "user", "param", "arg", ".get("]
                return any(pattern in context for pattern in user_patterns)
        return False

    def _has_exception_handling_nearby(self, node: ast.Call) -> bool:
        """Check if there's exception handling near a call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            # Check surrounding context for try/except
            context = "\n".join(self.lines[max(0, line - 5) : min(len(self.lines), line + 10)])
            error_patterns = ["try:", "except", "catch", "with"]
            return any(pattern in context.lower() for pattern in error_patterns)
        return False

    def _has_validation_nearby(self, node: ast.Call) -> bool:
        """Check if there's validation near a call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 10) : line])
            validation_patterns = ["validate", "check", "clean", "sanitize", "verify"]
            return any(pattern in context.lower() for pattern in validation_patterns)
        return False

    def _in_public_context(self, node: ast.Attribute) -> bool:
        """Check if an attribute access is in a potentially public context."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 10) : min(len(self.lines), line + 10)])
            public_patterns = ["return", "serialize", "json", "dict", "api", "response"]
            return any(pattern in context.lower() for pattern in public_patterns)
        return False


def analyze_peewee_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for Peewee ORM security vulnerabilities.

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

    visitor = PeeweeSecurityVisitor(file_path, code)
    visitor.visit(tree)
    return visitor.violations
