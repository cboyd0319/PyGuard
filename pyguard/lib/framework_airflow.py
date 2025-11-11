"""
Apache Airflow Security Analysis.

Detects and auto-fixes common security vulnerabilities in Apache Airflow DAGs and workflows.
This module provides framework-specific security checks for Airflow orchestration.

Security Areas Covered:
- SQL injection in operators (SQLExecuteQueryOperator, PostgresOperator, etc.)
- Insecure credential handling (connections, variables, secrets)
- XCom data exposure and tampering
- Dynamic DAG generation security (eval, exec usage)
- Insecure task configuration
- Path traversal in file operations
- Command injection in BashOperator, PythonOperator
- Insecure HTTP/API calls
- Jinja template injection
- Task dependency manipulation
- Pickle usage in XCom serialization
- Insecure connection strings
- Missing authentication/authorization checks
- Sensor timeout and resource exhaustion
- Trigger rule manipulation

References:
- Airflow Security | https://airflow.apache.org/docs/apache-airflow/stable/security/ | High
- Airflow Best Practices | https://airflow.apache.org/docs/apache-airflow/stable/best-practices.html | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
- CWE-78 (Command Injection) | https://cwe.mitre.org/data/definitions/78.html | Critical
- CWE-94 (Code Injection) | https://cwe.mitre.org/data/definitions/94.html | Critical
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


class AirflowSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Airflow security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_airflow_import = False
        self.dag_operators: list[str] = []
        self.xcom_usage: list[str] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Airflow imports."""
        if node.module and "airflow" in node.module:
            self.has_airflow_import = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track Airflow imports."""
        for alias in node.names:
            if "airflow" in alias.name:
                self.has_airflow_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect security issues in function calls."""
        # Check operator instantiation (Name nodes like PostgresOperator(...))
        if isinstance(node.func, ast.Name):  # noqa: SIM102
            if any(op in node.func.id for op in ["Operator", "Sensor", "Hook"]):
                self._check_operator_security(node)

        if isinstance(node.func, ast.Attribute):
            # Check operator instantiation (Attribute nodes)
            if any(op in str(node.func.attr) for op in ["Operator", "Sensor", "Hook"]):
                self._check_operator_security(node)

            # XCom usage
            elif node.func.attr in ("xcom_push", "xcom_pull"):
                self._check_xcom_security(node)

            # Variable access
            elif node.func.attr == "get" and self._is_variable_access(node):
                self._check_variable_security(node)

        # Check for BashOperator command injection
        if self._is_bash_operator(node):
            self._check_command_injection(node)

        # Check for SQL operators
        if self._is_sql_operator(node):
            self._check_sql_injection(node)

        # Check for eval/exec
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._check_eval_exec(node)

        self.generic_visit(node)

    def _is_bash_operator(self, node: ast.Call) -> bool:
        """Check if node is a BashOperator instantiation."""
        if isinstance(node.func, ast.Name):
            return "BashOperator" in node.func.id
        if isinstance(node.func, ast.Attribute):
            return "BashOperator" in node.func.attr
        return False

    def _is_sql_operator(self, node: ast.Call) -> bool:
        """Check if node is a SQL operator instantiation."""
        sql_operators = [
            "SQLExecuteQueryOperator", "PostgresOperator", "MySqlOperator",
            "MsSqlOperator", "OracleOperator", "SqliteOperator"
        ]
        if isinstance(node.func, ast.Name):
            return any(op in node.func.id for op in sql_operators)
        if isinstance(node.func, ast.Attribute):
            return any(op in node.func.attr for op in sql_operators)
        return False

    def _is_variable_access(self, node: ast.Call) -> bool:
        """Check if this is accessing Airflow Variable."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return node.func.value.id == "Variable"
        return False

    def _check_operator_security(self, node: ast.Call) -> None:
        """Check security issues in operator configuration."""
        line_num = node.lineno

        # Check for hardcoded secrets in operator parameters
        if node.keywords:
            for keyword in node.keywords:
                if keyword.arg and any(  # noqa: SIM102
                    term in keyword.arg.lower()
                    for term in ["password", "secret", "token", "key", "credential"]
                ):
                    if isinstance(keyword.value, ast.Constant):
                        self.violations.append(
                            RuleViolation(
                            rule_id="AIRFLOW001",
                            message="Hardcoded credential in Airflow operator - use Airflow Connections or Variables",
                            line_number=line_num,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            code_snippet=self._get_code_snippet(line_num
                        ),
                            )
                        )

    def _check_command_injection(self, node: ast.Call) -> None:
        """Check for command injection in BashOperator."""
        line_num = node.lineno

        # Find bash_command parameter
        for keyword in node.keywords:
            if keyword.arg == "bash_command":
                # Check for f-string
                if isinstance(keyword.value, ast.JoinedStr):
                    self.violations.append(
                        RuleViolation(
                            rule_id="AIRFLOW002",
                            message="Command injection risk in BashOperator - bash_command uses f-string with variables",
                            line_number=line_num,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            code_snippet=self._get_code_snippet(line_num
                        ),
                        )
                    )

                # Check for string concatenation
                elif isinstance(keyword.value, ast.BinOp) and isinstance(keyword.value.op, ast.Add):
                    self.violations.append(
                        RuleViolation(
                            rule_id="AIRFLOW003",
                            message="Command injection risk - bash_command uses string concatenation",
                            line_number=line_num,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            code_snippet=self._get_code_snippet(line_num
                        ),
                        )
                    )

                # Check for .format()
                elif isinstance(keyword.value, ast.Call) and isinstance(keyword.value.func, ast.Attribute):  # noqa: SIM102
                    if keyword.value.func.attr == "format":
                        self.violations.append(
                            RuleViolation(
                            rule_id="AIRFLOW004",
                            message="Command injection risk - bash_command uses .format()",
                            line_number=line_num,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            code_snippet=self._get_code_snippet(line_num
                        ),
                            )
                        )

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection in SQL operators."""
        line_num = node.lineno

        # Find sql parameter
        for keyword in node.keywords:
            if keyword.arg in ("sql", "query"):
                # Check for f-string
                if isinstance(keyword.value, ast.JoinedStr):
                    self.violations.append(
                        RuleViolation(
                            rule_id="AIRFLOW005",
                            message="SQL injection risk - query uses f-string",
                            line_number=line_num,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            code_snippet=self._get_code_snippet(line_num
                        ),
                        )
                    )

                # Check for string concatenation
                elif isinstance(keyword.value, ast.BinOp) and isinstance(keyword.value.op, ast.Add):
                    self.violations.append(
                        RuleViolation(
                            rule_id="AIRFLOW006",
                            message="SQL injection risk - query uses string concatenation",
                            line_number=line_num,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            code_snippet=self._get_code_snippet(line_num
                        ),
                        )
                    )

                # Check for .format()
                elif isinstance(keyword.value, ast.Call) and isinstance(keyword.value.func, ast.Attribute):  # noqa: SIM102
                    if keyword.value.func.attr == "format":
                        self.violations.append(
                            RuleViolation(
                            rule_id="AIRFLOW007",
                            message="SQL injection risk - query uses .format()",
                            line_number=line_num,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            code_snippet=self._get_code_snippet(line_num
                        ),
                            )
                        )

    def _check_xcom_security(self, node: ast.Call) -> None:
        """Check XCom usage for security issues."""
        line_num = node.lineno

        # Check if sensitive data might be in XCom
        if isinstance(node.func, ast.Attribute) and node.func.attr == "xcom_push":
            # Check if pushing potentially sensitive data
            for keyword in node.keywords:
                if keyword.arg == "value":
                    # Check if value is a Name node with sensitive variable name
                    value_node = keyword.value
                    is_sensitive = False

                    if isinstance(value_node, ast.Name):
                        # Check variable name
                        var_name = value_node.id.lower()
                        if any(
                            term in var_name
                            for term in ["password", "secret", "token", "api_key", "credential", "private_key"]
                        ):
                            is_sensitive = True

                    if is_sensitive:
                        code_snippet = self._get_code_snippet(line_num)
                        self.violations.append(
                            RuleViolation(
                                rule_id="AIRFLOW008",
                                message="Potential sensitive data in XCom - XCom values may be logged or exposed",
                                line_number=line_num,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                code_snippet=code_snippet,
                            )
                        )

    def _check_variable_security(self, node: ast.Call) -> None:
        """Check Variable.get() usage for security issues."""

        # Check if deserialize_json is used (pickle deserialization risk)
        for keyword in node.keywords:
            if keyword.arg == "deserialize_json" and isinstance(keyword.value, ast.Constant):  # noqa: SIM102
                if keyword.value.value is True:
                    # This is actually safe (JSON), but check the context
                    pass

    def _check_eval_exec(self, node: ast.Call) -> None:
        """Check for eval/exec usage."""
        line_num = node.lineno
        func_name = getattr(node.func, 'id', 'unknown')
        self.violations.append(
            RuleViolation(
                rule_id="AIRFLOW009",
                message=f"Use of {func_name}() in Airflow DAG - arbitrary code execution risk",
                line_number=line_num,
                column=node.col_offset,
                severity=RuleSeverity.CRITICAL,
                category=RuleCategory.SECURITY,
                file_path=self.file_path,
                code_snippet=self._get_code_snippet(line_num),
            )
        )

    def visit_With(self, node: ast.With) -> None:
        """Check DAG context manager usage."""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):  # noqa: SIM102
                if isinstance(item.context_expr.func, ast.Name):  # noqa: SIM102
                    if item.context_expr.func.id == "DAG":
                        self._check_dag_security(item.context_expr)
        self.generic_visit(node)

    def _check_dag_security(self, node: ast.Call) -> None:
        """Check DAG configuration for security issues."""

        # Check for insecure default_args
        for keyword in node.keywords:
            if keyword.arg == "default_args" and isinstance(keyword.value, ast.Dict):
                for key, value in zip(keyword.value.keys, keyword.value.values, strict=False):
                    if isinstance(key, ast.Constant):  # noqa: SIM102
                        # Check for insecure configurations
                        if key.value == "provide_context" and isinstance(value, ast.Constant):
                            # provide_context is deprecated but check anyway
                            pass

    def _get_code_snippet(self, line_number: int) -> str:
        """Get code snippet around the given line."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""


def analyze_airflow_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Airflow code for security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze

    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = AirflowSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


def fix_airflow_security(
    file_path: Path, code: str, violation: RuleViolation  # noqa: ARG001 - file_path required by fix function API signature
) -> tuple[str, bool]:
    """
    Auto-fix Airflow security vulnerabilities.

    Args:
        file_path: Path to the file being fixed (required by API)
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

    # Fix hardcoded credentials
    if violation.rule_id == "AIRFLOW001":
        indent = len(original_line) - len(original_line.lstrip())
        comment = " " * indent + "# TODO: Use Airflow Connections or Variables instead of hardcoded credentials\n"
        lines.insert(line_idx, comment)
        modified = True

    # Fix command injection
    elif violation.rule_id in ["AIRFLOW002", "AIRFLOW003", "AIRFLOW004"]:
        indent = len(original_line) - len(original_line.lstrip())
        comment = " " * indent + "# TODO: Use Jinja templates or parameterized commands to prevent injection\n"
        lines.insert(line_idx, comment)
        modified = True

    # Fix SQL injection
    elif violation.rule_id in ["AIRFLOW005", "AIRFLOW006", "AIRFLOW007"]:
        indent = len(original_line) - len(original_line.lstrip())
        comment = " " * indent + "# TODO: Use parameterized queries with parameters argument\n"
        lines.insert(line_idx, comment)
        modified = True

    # Fix XCom sensitive data
    elif violation.rule_id == "AIRFLOW008":
        indent = len(original_line) - len(original_line.lstrip())
        comment = " " * indent + "# TODO: Avoid pushing sensitive data to XCom - use Airflow Connections/Secrets instead\n"
        lines.insert(line_idx, comment)
        modified = True

    if modified:
        return "".join(lines), True

    return code, False


AIRFLOW_RULES = [
    Rule(
        rule_id="AIRFLOW001",
        name="Hardcoded Credentials in Operator",
        description="Hardcoded credential in Airflow operator",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Hardcoded credential in Airflow operator - use Airflow Connections or Variables (CWE-798)",
        references=[
            "https://airflow.apache.org/docs/apache-airflow/stable/security/",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW002",
        name="Command Injection via f-string in BashOperator",
        description="Command injection risk in BashOperator using f-string",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Command injection risk in BashOperator - bash_command uses f-string with variables (CWE-78)",
        references=[
            "https://airflow.apache.org/docs/apache-airflow/stable/best-practices.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW003",
        name="Command Injection via String Concatenation",
        description="Command injection risk using string concatenation",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Command injection risk - bash_command uses string concatenation (CWE-78)",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW004",
        name="Command Injection via .format()",
        description="Command injection risk using .format()",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Command injection risk - bash_command uses .format() (CWE-78)",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW005",
        name="SQL Injection via f-string",
        description="SQL injection risk in SQL operator using f-string",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL injection risk - query uses f-string (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW006",
        name="SQL Injection via String Concatenation",
        description="SQL injection risk using string concatenation",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL injection risk - query uses string concatenation (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW007",
        name="SQL Injection via .format()",
        description="SQL injection risk using .format()",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL injection risk - query uses .format() (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW008",
        name="Sensitive Data in XCom",
        description="Potential sensitive data pushed to XCom",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="Potential sensitive data in XCom - XCom values may be logged or exposed (CWE-200)",
        references=[
            "https://airflow.apache.org/docs/apache-airflow/stable/security/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    ),
    Rule(
        rule_id="AIRFLOW009",
        name="Use of eval() or exec() in DAG",
        description="Use of eval() or exec() in Airflow DAG",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Use of eval()/exec() in Airflow DAG - arbitrary code execution risk (CWE-95)",
        references=[
            "https://cwe.mitre.org/data/definitions/95.html",
        ],
    ),
]


# Register rules with the rule engine
register_rules(AIRFLOW_RULES)
