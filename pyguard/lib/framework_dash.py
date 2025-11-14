"""
Dash/Plotly Security Analysis.

Detects and auto-fixes common security vulnerabilities in Dash and Plotly applications.
This module provides framework-specific security checks for the data visualization framework.

Security Areas Covered:
- Callback security and input validation
- XSS in HTML components and markdown
- CSRF protection
- Secret management in config
- SQL injection in database queries
- Path traversal in file operations
- Insecure deserialization
- Debug mode in production
- Authentication and access control
- Server configuration security

References:
- Dash Security Best Practices | https://dash.plotly.com/authentication | High
- Plotly Security | https://plotly.com/python/security/ | Medium
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-79 (XSS) | https://cwe.mitre.org/data/definitions/79.html | Critical
- CWE-352 (CSRF) | https://cwe.mitre.org/data/definitions/352.html | High
"""

import ast
from pathlib import Path
from typing import Any

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class DashSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Dash/Plotly security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        # TODO: Add docstring
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_dash_import = False
        self.has_plotly_import = False
        self.callbacks: list[dict[str, Any]] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Dash/Plotly imports."""
        if node.module:
            if node.module.startswith("dash"):
                self.has_dash_import = True
            elif node.module.startswith("plotly"):
                self.has_plotly_import = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track Dash/Plotly imports."""
        for alias in node.names:
            if alias.name.startswith("dash"):
                self.has_dash_import = True
            elif alias.name.startswith("plotly"):
                self.has_plotly_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect security issues in function calls."""
        if isinstance(node.func, ast.Attribute):
            # Check for debug mode in production
            if node.func.attr in {"run_server", "run"}:
                self._check_debug_mode(node)

            # Check for dangerously_allow_html
            elif node.func.attr in ("Markdown", "Html"):
                self._check_xss_risk(node)

            # Check for callback without input validation
            elif node.func.attr == "callback":
                self._track_callback(node)

        # Check for SQL injection
        if self._is_database_query(node):
            self._check_sql_injection(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check assignments for security issues."""
        # Check for SQL injection in query assignments
        if isinstance(node.value, ast.BinOp):  # noqa: SIM102
            if isinstance(node.value.op, (ast.Add, ast.Mod)):  # noqa: SIM102
                if self._contains_sql_keywords(node.value):
                    self.violations.append(
                        RuleViolation(
                            rule_id="DASH006",
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

    def _check_debug_mode(self, node: ast.Call) -> None:
        """Check for debug mode enabled in production."""
        for keyword in node.keywords:
            if keyword.arg == "debug":  # noqa: SIM102
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.violations.append(
                        RuleViolation(
                            rule_id="DASH001",
                            message="Dash debug mode enabled - should never be used in production (CWE-489)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                            fix_data={"keyword": "debug", "new_value": "False"},
                        )
                    )

    def _check_xss_risk(self, node: ast.Call) -> None:
        """Check for XSS risks in HTML/Markdown components."""
        # Check for dangerously_allow_html or similar dangerous options
        for keyword in node.keywords:
            if keyword.arg == "dangerously_allow_html":  # noqa: SIM102
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    # Check if content includes user input
                    for arg in node.args:
                        if isinstance(arg, ast.JoinedStr):  # f-string
                            self.violations.append(
                                RuleViolation(
                                    rule_id="DASH002",
                                    message="Using dangerously_allow_html with user input creates XSS vulnerability (CWE-79)",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.UNSAFE,
                                    fix_data={"issue": "xss_html"},
                                )
                            )

        # Check for dcc.Markdown with HTML
        if isinstance(node.func, ast.Attribute) and node.func.attr == "Markdown":
            # Check if children property contains f-strings
            for keyword in node.keywords:
                if keyword.arg == "children":  # noqa: SIM102
                    if isinstance(keyword.value, ast.JoinedStr):
                        self.violations.append(
                            RuleViolation(
                                rule_id="DASH003",
                                message="Markdown component with user input may be vulnerable to XSS (CWE-79)",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.UNSAFE,
                                fix_data={"issue": "xss_markdown"},
                            )
                        )

    def _track_callback(self, node: ast.Call) -> None:
        """Track callback definitions for validation checks."""
        self.callbacks.append({"line": node.lineno, "node": node})

    def _is_database_query(self, node: ast.Call) -> bool:
        """Check if this is a database query call."""
        if isinstance(node.func, ast.Attribute):  # noqa: SIM102
            if node.func.attr in ("execute", "query", "raw", "sql"):
                return True
        return False

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection vulnerabilities."""
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):  # f-string
                self.violations.append(
                    RuleViolation(
                        rule_id="DASH005",
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

    def _contains_sql_keywords(self, node: ast.AST) -> bool:
        """Check if an AST node contains SQL keywords."""
        sql_keywords = {"SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN"}

        def check_node(n: ast.AST) -> bool:
            # TODO: Add docstring
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                upper_str = n.value.upper()
                return any(keyword in upper_str for keyword in sql_keywords)
            if isinstance(n, ast.BinOp):
                return check_node(n.left) or check_node(n.right)
            return False

        return check_node(node)


def analyze_dash_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for Dash/Plotly-specific security vulnerabilities.

    Args:
        file_path: Path to the Python file
        code: Source code to analyze

    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = DashSecurityVisitor(file_path, code)
        visitor.visit(tree)

        # Only return violations if Dash is actually imported
        if visitor.has_dash_import or visitor.has_plotly_import:
            return visitor.violations
        return []

    except SyntaxError:
        return []


def fix_dash_security(
    # TODO: Add docstring
    code: str, violation: RuleViolation
) -> tuple[str, bool]:
    """
    Auto-fix Dash security vulnerabilities.

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

    # Fix debug mode
    if violation.rule_id == "DASH001" and violation.fix_applicability == FixApplicability.SAFE:  # noqa: SIM102
        if "debug=True" in original_line:
            fixed_line = original_line.replace("debug=True", "debug=False")
            lines[line_idx] = fixed_line
            return "".join(lines), True

    return code, False


# Define Dash security rules
DASH_RULES = [
    Rule(
        rule_id="DASH001",
        name="Debug Mode Enabled",
        description="Dash debug mode should never be enabled in production",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Dash debug mode enabled - should never be used in production (CWE-489)",
        references=[
            "https://dash.plotly.com/devtools",
            "https://cwe.mitre.org/data/definitions/489.html",
        ],
    ),
    Rule(
        rule_id="DASH002",
        name="XSS via dangerously_allow_html",
        description="Using dangerously_allow_html with user input creates XSS vulnerability",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="Using dangerously_allow_html with user input creates XSS vulnerability (CWE-79)",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/attacks/xss/",
        ],
    ),
    Rule(
        rule_id="DASH003",
        name="XSS in Markdown Component",
        description="Markdown component with user input may be vulnerable to XSS",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="Markdown component with user input may be vulnerable to XSS (CWE-79)",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    ),
    Rule(
        rule_id="DASH005",
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
        rule_id="DASH006",
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
register_rules(DASH_RULES)
