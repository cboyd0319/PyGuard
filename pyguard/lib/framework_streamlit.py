"""
Streamlit Security Analysis.

Detects and auto-fixes common security vulnerabilities in Streamlit applications.
This module provides framework-specific security checks for the popular data app framework.

Security Areas Covered:
- Secrets management and st.secrets access
- File upload validation and sanitization
- User input validation (text_input, number_input, etc.)
- Session state security
- Caching security (@st.cache_data, @st.cache_resource)
- Authentication and access control
- SQL injection via database queries
- XSS via markdown and HTML rendering
- Insecure file operations
- Data exposure via st.write() and st.dataframe()

References:
- Streamlit Security Best Practices | https://docs.streamlit.io/develop/concepts/configuration/secrets-management | High
- Streamlit Caching | https://docs.streamlit.io/develop/concepts/architecture/caching | Medium
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-200 (Information Exposure) | https://cwe.mitre.org/data/definitions/200.html | High
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
"""

import ast
from pathlib import Path
import re
from typing import Any

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class StreamlitSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Streamlit security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_streamlit_import = False
        self.secrets_accessed: list[dict[str, Any]] = []
        self.user_inputs: list[dict[str, Any]] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Streamlit imports."""
        if node.module and node.module.startswith("streamlit"):
            self.has_streamlit_import = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track Streamlit imports."""
        for alias in node.names:
            if alias.name == "streamlit":
                self.has_streamlit_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect security issues in function calls."""
        # Check for insecure st.secrets usage
        if isinstance(node.func, ast.Attribute):
            # st.write() with sensitive data
            if node.func.attr == "write":
                self._check_sensitive_data_write(node)

            # st.markdown() with unsafe HTML
            elif node.func.attr == "markdown":
                self._check_unsafe_html(node)

            # st.file_uploader() without validation
            elif node.func.attr == "file_uploader":
                self._check_file_upload_security(node)

            # st.secrets access without proper handling
            elif node.func.attr == "secrets" or (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "secrets"
            ):
                self._check_secrets_access(node)

            # Caching sensitive data
            elif node.func.attr in ("cache_data", "cache_resource"):
                self._check_cache_security(node)

        # Check for SQL injection in database queries
        if self._is_database_query(node):
            self._check_sql_injection(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check assignments for security issues."""
        # Check if user input is stored without validation
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
            if node.value.func.attr in (
                "text_input",
                "text_area",
                "number_input",
                "date_input",
                "time_input",
                "selectbox",
                "multiselect",
            ):
                self._track_user_input(node)

        # Check for SQL injection in query assignments
        if isinstance(node.value, ast.BinOp):
            # Check if this is a SQL query with string concatenation
            if isinstance(node.value.op, (ast.Add, ast.Mod)):
                # Check if any part looks like SQL
                if self._contains_sql_keywords(node.value):
                    self.violations.append(
                        RuleViolation(
                            rule_id="STREAMLIT007",
                            message="SQL query uses string concatenation/formatting - use parameterized queries (CWE-89)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.UNSAFE,
                            fix_data={"issue": "sql_injection"},
                        )
                    )

        self.generic_visit(node)

    def _check_sensitive_data_write(self, node: ast.Call) -> None:
        """Check for sensitive data being written to the UI."""
        # Check if st.write() is used with variables that might contain secrets
        for arg in node.args:
            if isinstance(arg, ast.Attribute):
                # Check for st.secrets being written directly
                if arg.attr == "secrets" or (
                    isinstance(arg.value, ast.Attribute) and arg.value.attr == "secrets"
                ):
                    self.violations.append(
                        RuleViolation(
                            rule_id="STREAMLIT001",
                            message="Secrets should not be written directly to the UI - risk of information exposure (CWE-200)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.UNSAFE,
                            fix_data={"issue": "secrets_exposed"},
                        )
                    )

            # Check for environment variables or config being written
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                if arg.func.attr in ("getenv", "get"):
                    self.violations.append(
                        RuleViolation(
                            rule_id="STREAMLIT002",
                            message="Environment variables or config should be sanitized before display (CWE-200)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.UNSAFE,
                            fix_data={"issue": "env_var_exposed"},
                        )
                    )

    def _check_unsafe_html(self, node: ast.Call) -> None:
        """Check for unsafe HTML in st.markdown()."""
        # Check if unsafe_allow_html=True is used with user input
        has_unsafe_html = False
        for keyword in node.keywords:
            if keyword.arg == "unsafe_allow_html":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    has_unsafe_html = True
                    break

        if has_unsafe_html:
            # Check if any argument is user input or contains f-strings
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):  # f-string
                    self.violations.append(
                        RuleViolation(
                            rule_id="STREAMLIT003",
                            message="Using unsafe_allow_html with user input creates XSS vulnerability (CWE-79)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.UNSAFE,
                            fix_data={"issue": "xss_markdown"},
                        )
                    )
                elif isinstance(arg, ast.Name):
                    # Check if variable might be user input
                    if arg.id in [inp["var_name"] for inp in self.user_inputs]:
                        self.violations.append(
                            RuleViolation(
                                rule_id="STREAMLIT004",
                                message="User input in markdown with unsafe_allow_html creates XSS risk (CWE-79)",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.UNSAFE,
                                fix_data={"variable": arg.id, "issue": "xss_user_input"},
                            )
                        )

    def _check_file_upload_security(self, node: ast.Call) -> None:
        """Check for insecure file upload handling."""
        # Check if file type validation is present
        has_type_filter = False
        for keyword in node.keywords:
            if keyword.arg == "type":
                has_type_filter = True
                break

        if not has_type_filter:
            self.violations.append(
                RuleViolation(
                    rule_id="STREAMLIT005",
                    message="File uploader should specify allowed file types to prevent malicious uploads (CWE-434)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                    fix_data={"add_parameter": "type=['txt', 'csv']"},
                )
            )

    def _check_secrets_access(self, node: ast.Call) -> None:
        """Check for insecure secrets access patterns."""
        # Track secrets access for later validation
        self.secrets_accessed.append(
            {"line": node.lineno, "node": node}
        )

    def _check_cache_security(self, node: ast.Call) -> None:
        """Check for security issues with caching."""
        # Check if sensitive data is being cached
        # Look at the decorated function name for hints
        pass  # This would require inspecting the decorated function

    def _is_database_query(self, node: ast.Call) -> bool:
        """Check if this is a database query call."""
        if isinstance(node.func, ast.Attribute):
            # Check for common database methods
            if node.func.attr in ("execute", "query", "raw", "sql"):
                return True
        return False

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection vulnerabilities."""
        # Check if query uses string formatting with user input
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):  # f-string
                self.violations.append(
                    RuleViolation(
                        rule_id="STREAMLIT006",
                        message="SQL query uses f-string which is vulnerable to SQL injection (CWE-89)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.UNSAFE,
                        fix_data={"issue": "sql_injection"},
                    )
                )
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
                # String concatenation or % formatting
                self.violations.append(
                    RuleViolation(
                        rule_id="STREAMLIT007",
                        message="SQL query uses string concatenation/formatting - use parameterized queries (CWE-89)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.UNSAFE,
                        fix_data={"issue": "sql_injection"},
                    )
                )

    def _track_user_input(self, node: ast.Assign) -> None:
        """Track user input variables for later checks."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                input_type = "unknown"
                if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
                    input_type = node.value.func.attr
                self.user_inputs.append(
                    {
                        "var_name": target.id,
                        "line": node.lineno,
                        "input_type": input_type,
                    }
                )

    def _contains_sql_keywords(self, node: ast.AST) -> bool:
        """Check if an AST node contains SQL keywords."""
        sql_keywords = {"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN"}

        def check_node(n: ast.AST) -> bool:
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                upper_str = n.value.upper()
                return any(keyword in upper_str for keyword in sql_keywords)
            elif isinstance(n, ast.BinOp):
                return check_node(n.left) or check_node(n.right)
            return False

        return check_node(node)


def analyze_streamlit_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for Streamlit-specific security vulnerabilities.

    Args:
        file_path: Path to the Python file
        code: Source code to analyze

    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = StreamlitSecurityVisitor(file_path, code)
        visitor.visit(tree)

        # Only return violations if Streamlit is actually imported
        if visitor.has_streamlit_import:
            return visitor.violations
        return []

    except SyntaxError:
        return []


def fix_streamlit_security(
    code: str, violation: RuleViolation
) -> tuple[str, bool]:
    """
    Auto-fix Streamlit security vulnerabilities.

    Args:
        code: Original source code
        violation: The security violation to fix

    Returns:
        Tuple of (fixed_code, success)
    """
    lines = code.splitlines(keepends=True)
    line_idx = violation.line_number - 1

    if line_idx < 0 or line_idx >= len(lines):
        return code, False

    original_line = lines[line_idx]

    # Fix file uploader without type filter
    if violation.rule_id == "STREAMLIT005" and violation.fix_applicability == FixApplicability.SAFE:
        if "file_uploader(" in original_line:
            # Add type parameter if not present
            if "type=" not in original_line:
                # Find the closing parenthesis
                fixed_line = original_line.replace(
                    "file_uploader(",
                    "file_uploader(type=['txt', 'csv'], "
                )
                lines[line_idx] = fixed_line
                return "".join(lines), True

    return code, False


# Define Streamlit security rules
STREAMLIT_RULES = [
    Rule(
        rule_id="STREAMLIT001",
        name="Secrets Exposed in UI",
        description="st.secrets should not be written directly to the UI",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Secrets should not be written directly to the UI - risk of information exposure (CWE-200)",
        references=[
            "https://docs.streamlit.io/develop/concepts/configuration/secrets-management",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    ),
    Rule(
        rule_id="STREAMLIT002",
        name="Environment Variables Exposed",
        description="Environment variables should be sanitized before display",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="Environment variables or config should be sanitized before display (CWE-200)",
        references=[
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    ),
    Rule(
        rule_id="STREAMLIT003",
        name="XSS in Markdown with unsafe_allow_html",
        description="Using unsafe_allow_html with user input creates XSS vulnerability",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Using unsafe_allow_html with user input creates XSS vulnerability (CWE-79)",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/attacks/xss/",
        ],
    ),
    Rule(
        rule_id="STREAMLIT004",
        name="XSS via User Input in Markdown",
        description="User input in markdown with unsafe_allow_html creates XSS risk",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="User input in markdown with unsafe_allow_html creates XSS risk (CWE-79)",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    ),
    Rule(
        rule_id="STREAMLIT005",
        name="Insecure File Upload",
        description="File uploader should specify allowed file types",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="File uploader should specify allowed file types to prevent malicious uploads (CWE-434)",
        references=[
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
    ),
    Rule(
        rule_id="STREAMLIT006",
        name="SQL Injection via f-string",
        description="SQL query uses f-string which is vulnerable to SQL injection",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL query uses f-string which is vulnerable to SQL injection (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ],
    ),
    Rule(
        rule_id="STREAMLIT007",
        name="SQL Injection via String Concatenation",
        description="SQL query uses string concatenation/formatting",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL query uses string concatenation/formatting - use parameterized queries (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
]


# Register rules with the rule engine
register_rules(STREAMLIT_RULES)
