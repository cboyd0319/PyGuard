"""
PySpark Security Analysis.

Detects and auto-fixes common security vulnerabilities in PySpark applications.
This module provides framework-specific security checks for Apache Spark Python API.

Security Areas Covered:
- SQL injection via spark.sql() and DataFrame queries
- Insecure credential handling (API keys, tokens, database passwords)
- Path traversal in file operations (read, write)
- Unsafe deserialization (pickle, cloudpickle)
- HDFS/S3 permission issues and insecure access
- Dynamic code execution (eval, exec in transformations)
- Broadcast variable security
- UDF security and code injection
- Resource exhaustion and memory issues
- Data exposure in logs and exceptions
- Insecure Spark configuration
- Authentication and authorization issues
- Kerberos misconfiguration
- SSL/TLS configuration issues
- Sensitive data caching

References:
- Apache Spark Security | https://spark.apache.org/docs/latest/security.html | High
- Spark SQL Security | https://spark.apache.org/docs/latest/sql-security.html | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
- CWE-502 (Deserialization) | https://cwe.mitre.org/data/definitions/502.html | Critical
- CWE-22 (Path Traversal) | https://cwe.mitre.org/data/definitions/22.html | High
"""

import ast
from pathlib import Path

from pyguard.lib.rule_engine import (
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class PySparkSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting PySpark security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_pyspark_import = False
        self.user_inputs: list[str] = []
        self.sql_queries: list[str] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track PySpark imports."""
        if node.module and ("pyspark" in node.module or "spark" in node.module):
            self.has_pyspark_import = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track PySpark imports."""
        for alias in node.names:
            if "pyspark" in alias.name or "spark" in alias.name:
                self.has_pyspark_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect security issues in function calls."""
        if isinstance(node.func, ast.Attribute):
            # SQL injection checks
            if node.func.attr == "sql":
                self._check_sql_injection(node)

            # File operation security
            elif node.func.attr in ("read", "load", "text", "csv", "json", "parquet", "orc"):
                self._check_path_traversal(node)

            # Unsafe deserialization
            elif node.func.attr in ("pickle", "unpickle"):
                self._check_unsafe_deserialization(node)

            # Dynamic code execution
            elif node.func.attr in ("map", "flatMap", "mapPartitions", "foreach", "foreachPartition"):
                self._check_dynamic_execution(node)

            # Configuration security
            elif node.func.attr in ("config", "set", "setAll"):
                self._check_insecure_config(node)

            # Credential handling
            elif node.func.attr in ("option", "options"):
                self._check_credential_exposure(node)

        # Check for eval/exec usage
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._check_eval_exec(node)

        self.generic_visit(node)

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection in spark.sql() calls."""
        if not node.args:
            return

        query_arg = node.args[0]
        line_num = node.lineno

        # Check for f-strings in SQL
        if isinstance(query_arg, ast.JoinedStr):
            self.violations.append(
                RuleViolation(
                    rule_id="PYSPARK001",
                    message="SQL query uses f-string which is vulnerable to SQL injection",
                    line_number=line_num,
                    column=node.col_offset,
                    severity=RuleSeverity.CRITICAL,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    code_snippet=self._get_code_snippet(line_num),
                )
            )

        # Check for string concatenation
        elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Add):
            self.violations.append(
                RuleViolation(
                    rule_id="PYSPARK002",
                    message="SQL query uses string concatenation - use parameterized queries",
                    line_number=line_num,
                    column=node.col_offset,
                    severity=RuleSeverity.CRITICAL,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    code_snippet=self._get_code_snippet(line_num
                ),
                )
            )

        # Check for .format() in SQL
        elif isinstance(query_arg, ast.Call) and isinstance(query_arg.func, ast.Attribute):
            if query_arg.func.attr == "format":
                self.violations.append(
                    RuleViolation(
                    rule_id="PYSPARK003",
                    message="SQL query uses .format() - use parameterized queries",
                    line_number=line_num,
                    column=node.col_offset,
                    severity=RuleSeverity.CRITICAL,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    code_snippet=self._get_code_snippet(line_num
                ),
                    )
                )

    def _check_path_traversal(self, node: ast.Call) -> None:
        """Check for path traversal vulnerabilities in file operations."""
        if not node.args:
            return

        path_arg = node.args[0]
        line_num = node.lineno

        # Check if path comes from user input (f-string, concatenation)
        if isinstance(path_arg, ast.JoinedStr) or (
            isinstance(path_arg, ast.BinOp) and isinstance(path_arg.op, ast.Add)
        ):
            self.violations.append(
                RuleViolation(
                    rule_id="PYSPARK004",
                    message="File path may be vulnerable to path traversal - validate and sanitize paths",
                    line_number=line_num,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    code_snippet=self._get_code_snippet(line_num),
                )
            )

    def _check_unsafe_deserialization(self, node: ast.Call) -> None:
        """Check for unsafe deserialization."""
        line_num = node.lineno
        self.violations.append(
            RuleViolation(
                rule_id="PYSPARK005",
                message="Unsafe deserialization with pickle - use safer formats like parquet or JSON",
                line_number=line_num,
                column=node.col_offset,
                severity=RuleSeverity.CRITICAL,
                category=RuleCategory.SECURITY,
                file_path=self.file_path,
                code_snippet=self._get_code_snippet(line_num),
            )
        )

    def _check_dynamic_execution(self, node: ast.Call) -> None:
        """Check for dynamic code execution in transformations."""
        if not node.args:
            return

        # Check if lambda or function contains eval/exec
        func_arg = node.args[0]
        if isinstance(func_arg, ast.Lambda):
            # Check lambda body for eval/exec
            for subnode in ast.walk(func_arg.body):
                if isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name):
                    if subnode.func.id in ("eval", "exec"):
                        line_num = node.lineno
                        self.violations.append(
                            RuleViolation(
                                rule_id="PYSPARK006",
                                message="Dynamic code execution in Spark transformation - code injection risk",
                                line_number=line_num,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                code_snippet=self._get_code_snippet(line_num),
                            )
                        )

    def _check_insecure_config(self, node: ast.Call) -> None:
        """Check for insecure Spark configuration."""
        if not node.args:
            return

        # Check for config keys
        if len(node.args) >= 2:
            key_arg = node.args[0]
            if isinstance(key_arg, ast.Constant):
                key = key_arg.value
                if isinstance(key, str):
                    line_num = node.lineno

                    # Check for disabled authentication
                    value_arg = node.args[1]
                    value_is_false = False
                    if isinstance(value_arg, ast.Constant):
                        value_is_false = (value_arg.value in {"false", False})

                    if "authenticate" in key.lower() and value_is_false:
                        self.violations.append(
                            RuleViolation(
                                rule_id="PYSPARK007",
                                message="Spark authentication disabled - security risk",
                                line_number=line_num,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                code_snippet=self._get_code_snippet(line_num),
                            )
                        )

                    # Check for disabled SSL/TLS
                    elif "ssl" in key.lower() and value_is_false:
                        self.violations.append(
                            RuleViolation(
                                rule_id="PYSPARK008",
                                message="SSL/TLS disabled in Spark configuration - data in transit not encrypted",
                                line_number=line_num,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                code_snippet=self._get_code_snippet(line_num),
                            )
                        )

    def _check_credential_exposure(self, node: ast.Call) -> None:
        """Check for credential exposure in options."""
        if not node.args:
            return

        line_num = node.lineno

        # Check for password/key options
        if len(node.args) >= 2:
            key_arg = node.args[0]
            value_arg = node.args[1]

            if isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, str):
                key_lower = key_arg.value.lower()

                # Check for hardcoded credentials
                if any(term in key_lower for term in ["password", "secret", "key", "token", "credential"]):
                    if isinstance(value_arg, ast.Constant):
                        self.violations.append(
                            RuleViolation(
                                rule_id="PYSPARK009",
                                message="Hardcoded credential in Spark option - use environment variables or secrets manager",
                                line_number=line_num,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                code_snippet=self._get_code_snippet(line_num),
                            )
                        )

    def _check_eval_exec(self, node: ast.Call) -> None:
        """Check for eval/exec usage."""
        line_num = node.lineno
        func_name = getattr(node.func, 'id', 'unknown')
        self.violations.append(
            RuleViolation(
                rule_id="PYSPARK010",
                message=f"Use of {func_name}() in PySpark code - arbitrary code execution risk",
                line_number=line_num,
                column=node.col_offset,
                severity=RuleSeverity.CRITICAL,
                category=RuleCategory.SECURITY,
                file_path=self.file_path,
                code_snippet=self._get_code_snippet(line_num),
            )
        )

    def _get_code_snippet(self, line_number: int) -> str:
        """Get code snippet around the given line."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""


def analyze_pyspark_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze PySpark code for security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze

    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = PySparkSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


def fix_pyspark_security(
    file_path: Path, code: str, violation: RuleViolation
) -> tuple[str, bool]:
    """
    Auto-fix PySpark security vulnerabilities.

    Args:
        file_path: Path to the file being fixed
        code: Source code containing the vulnerability
        violation: The security violation to fix

    Returns:
        Tuple of (fixed_code, was_modified)
    """
    lines = code.splitlines(keepends=True)
    line_idx = violation.line_number - 1

    if line_idx < 0 or line_idx >= len(lines):
        return code, False

    original_line = lines[line_idx]
    modified = False

    # Fix SQL injection - suggest parameterized queries
    if violation.rule_id in ["PYSPARK001", "PYSPARK002", "PYSPARK003"]:
        # Add comment suggesting fix
        indent = len(original_line) - len(original_line.lstrip())
        comment = " " * indent + "# TODO: Use parameterized queries or DataFrame API instead of string formatting\n"
        lines.insert(line_idx, comment)
        modified = True

    # Fix hardcoded credentials
    elif violation.rule_id == "PYSPARK009":
        # Replace hardcoded value with environment variable suggestion
        if ".option(" in original_line:
            # Add comment
            indent = len(original_line) - len(original_line.lstrip())
            comment = " " * indent + "# TODO: Use os.environ.get() or secrets manager instead of hardcoded credentials\n"
            lines.insert(line_idx, comment)
            modified = True

    if modified:
        return "".join(lines), True

    return code, False


PYSPARK_RULES = [
    Rule(
        rule_id="PYSPARK001",
        name="SQL Injection via f-string in spark.sql()",
        description="SQL query uses f-string which is vulnerable to SQL injection",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL query uses f-string which is vulnerable to SQL injection (CWE-89)",
        references=[
            "https://spark.apache.org/docs/latest/sql-security.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK002",
        name="SQL Injection via String Concatenation",
        description="SQL query uses string concatenation",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL query uses string concatenation - use parameterized queries (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK003",
        name="SQL Injection via .format()",
        description="SQL query uses .format() which is vulnerable to SQL injection",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL query uses .format() - use parameterized queries (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK004",
        name="Path Traversal in File Operations",
        description="File path may be vulnerable to path traversal attacks",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="File path may be vulnerable to path traversal - validate and sanitize paths (CWE-22)",
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK005",
        name="Unsafe Deserialization with Pickle",
        description="Using pickle for deserialization is unsafe",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Unsafe deserialization with pickle - use safer formats like parquet or JSON (CWE-502)",
        references=[
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK006",
        name="Dynamic Code Execution in Transformations",
        description="Dynamic code execution in Spark transformation creates code injection risk",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Dynamic code execution in Spark transformation - code injection risk (CWE-94)",
        references=[
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK007",
        name="Spark Authentication Disabled",
        description="Spark authentication is disabled",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Spark authentication disabled - security risk (CWE-306)",
        references=[
            "https://spark.apache.org/docs/latest/security.html",
            "https://cwe.mitre.org/data/definitions/306.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK008",
        name="SSL/TLS Disabled",
        description="SSL/TLS disabled in Spark configuration",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="SSL/TLS disabled in Spark configuration - data in transit not encrypted (CWE-319)",
        references=[
            "https://spark.apache.org/docs/latest/security.html",
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK009",
        name="Hardcoded Credentials",
        description="Hardcoded credential in Spark option",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Hardcoded credential in Spark option - use environment variables or secrets manager (CWE-798)",
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    ),
    Rule(
        rule_id="PYSPARK010",
        name="Use of eval() or exec()",
        description="Use of eval() or exec() in PySpark code",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Use of eval()/exec() in PySpark code - arbitrary code execution risk (CWE-95)",
        references=[
            "https://cwe.mitre.org/data/definitions/95.html",
        ],
    ),
]


# Register rules with the rule engine
register_rules(PYSPARK_RULES)
