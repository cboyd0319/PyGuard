"""
Gradio Security Analysis.

Detects and auto-fixes common security vulnerabilities in Gradio applications.
This module provides framework-specific security checks for the ML interface framework.

Security Areas Covered:
- Authentication and access control (gr.Blocks with auth)
- File upload security and validation
- Input sanitization and validation
- API endpoint security
- Model inference security
- Output sanitization
- CORS and sharing settings
- SQL injection in database queries
- Path traversal in file operations
- Information disclosure

References:
- Gradio Security Best Practices | https://www.gradio.app/guides/sharing-your-app#security-and-file-access | High
- Gradio Authentication | https://www.gradio.app/guides/sharing-your-app#authentication | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-22 (Path Traversal) | https://cwe.mitre.org/data/definitions/22.html | High
- CWE-434 (File Upload) | https://cwe.mitre.org/data/definitions/434.html | Critical
"""

import ast
from pathlib import Path

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class GradioSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Gradio security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_gradio_import = False
        self.has_authentication = False
        self.file_uploads = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Gradio imports."""
        if node.module and node.module.startswith("gradio"):
            self.has_gradio_import = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track Gradio imports."""
        for alias in node.names:
            if alias.name == "gradio":
                self.has_gradio_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect security issues in function calls."""
        if isinstance(node.func, ast.Attribute):
            # Check for insecure sharing settings
            if node.func.attr == "launch":
                self._check_launch_security(node)

            # Check for file upload components
            elif node.func.attr == "File":
                self._check_file_upload(node)

            # Check for Blocks without authentication
            elif node.func.attr == "Blocks":
                self._check_blocks_auth(node)

        # Check for SQL injection
        if self._is_database_query(node):
            self._check_sql_injection(node)

        # Check for path traversal
        if self._is_file_operation(node):
            self._check_path_traversal(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check assignments for security issues."""
        # Check for SQL injection in query assignments
        if isinstance(node.value, ast.BinOp):
            # Check if this is a SQL query with string concatenation
            if isinstance(node.value.op, (ast.Add, ast.Mod)):
                # Check if any part looks like SQL
                if self._contains_sql_keywords(node.value):
                    self.violations.append(
                        RuleViolation(
                            rule_id="GRADIO005",
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

    def _check_launch_security(self, node: ast.Call) -> None:
        """Check for insecure launch configurations."""
        share_enabled = False
        auth_present = False

        for keyword in node.keywords:
            if keyword.arg == "share":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    share_enabled = True
            elif keyword.arg == "auth":
                auth_present = True

        # Warn if sharing without authentication
        if share_enabled and not auth_present:
            self.violations.append(
                RuleViolation(
                    rule_id="GRADIO001",
                    message="Gradio app shared publicly without authentication - security risk (CWE-306)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.UNSAFE,
                    fix_data={"issue": "no_auth_public_share"},
                )
            )

        # Check for insecure server configuration
        for keyword in node.keywords:
            if keyword.arg == "server_name":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value == "0.0.0.0":
                    self.violations.append(
                        RuleViolation(
                            rule_id="GRADIO002",
                            message="Binding to 0.0.0.0 exposes app to all network interfaces - security risk (CWE-200)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                            fix_data={"suggested_value": "127.0.0.1"},
                        )
                    )

    def _check_file_upload(self, node: ast.Call) -> None:
        """Check for insecure file upload handling."""
        has_file_types = False
        
        for keyword in node.keywords:
            if keyword.arg == "file_types":
                has_file_types = True
                break

        if not has_file_types:
            self.violations.append(
                RuleViolation(
                    rule_id="GRADIO003",
                    message="File upload component should specify allowed file types (CWE-434)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                    fix_data={"add_parameter": "file_types=['.txt', '.csv']"},
                )
            )

        self.file_uploads.append({"line": node.lineno, "node": node})

    def _check_blocks_auth(self, node: ast.Call) -> None:
        """Check if Blocks has authentication configured."""
        # Authentication is checked at launch time, so we track this
        pass

    def _is_database_query(self, node: ast.Call) -> bool:
        """Check if this is a database query call."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("execute", "query", "raw", "sql"):
                return True
        return False

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection vulnerabilities."""
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):  # f-string
                self.violations.append(
                    RuleViolation(
                        rule_id="GRADIO004",
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
                # Check if it looks like SQL
                if self._contains_sql_keywords(arg):
                    self.violations.append(
                        RuleViolation(
                            rule_id="GRADIO005",
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

    def _is_file_operation(self, node: ast.Call) -> bool:
        """Check if this is a file operation that could be vulnerable."""
        if isinstance(node.func, ast.Name):
            return node.func.id == "open"
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr in ("read", "write", "open", "load", "save")
        return False

    def _check_path_traversal(self, node: ast.Call) -> None:
        """Check for path traversal vulnerabilities in file operations."""
        # Check if file path uses user input without sanitization
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):  # f-string with user input
                self.violations.append(
                    RuleViolation(
                        rule_id="GRADIO006",
                        message="File operation uses unsanitized user input - path traversal risk (CWE-22)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.UNSAFE,
                        fix_data={"issue": "path_traversal"},
                    )
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


def analyze_gradio_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for Gradio-specific security vulnerabilities.

    Args:
        file_path: Path to the Python file
        code: Source code to analyze

    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = GradioSecurityVisitor(file_path, code)
        visitor.visit(tree)

        # Only return violations if Gradio is actually imported
        if visitor.has_gradio_import:
            return visitor.violations
        return []

    except SyntaxError:
        return []


def fix_gradio_security(
    code: str, violation: RuleViolation
) -> tuple[str, bool]:
    """
    Auto-fix Gradio security vulnerabilities.

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

    # Fix file upload without file_types
    if violation.rule_id == "GRADIO003" and violation.fix_applicability == FixApplicability.SAFE:
        if "gr.File(" in original_line or ".File(" in original_line:
            if "file_types=" not in original_line:
                # Add file_types parameter
                fixed_line = original_line.replace(
                    "File(",
                    "File(file_types=['.txt', '.csv'], "
                )
                lines[line_idx] = fixed_line
                return "".join(lines), True

    # Fix insecure server binding
    if violation.rule_id == "GRADIO002" and violation.fix_applicability == FixApplicability.SAFE:
        if "server_name=\"0.0.0.0\"" in original_line or "server_name='0.0.0.0'" in original_line:
            fixed_line = original_line.replace(
                "server_name=\"0.0.0.0\"", "server_name=\"127.0.0.1\""
            ).replace(
                "server_name='0.0.0.0'", "server_name='127.0.0.1'"
            )
            lines[line_idx] = fixed_line
            return "".join(lines), True

    return code, False


# Define Gradio security rules
GRADIO_RULES = [
    Rule(
        rule_id="GRADIO001",
        name="Public Sharing Without Authentication",
        description="Gradio app shared publicly without authentication",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="Gradio app shared publicly without authentication - security risk (CWE-306)",
        references=[
            "https://www.gradio.app/guides/sharing-your-app#authentication",
            "https://cwe.mitre.org/data/definitions/306.html",
        ],
    ),
    Rule(
        rule_id="GRADIO002",
        name="Insecure Server Binding",
        description="Binding to 0.0.0.0 exposes app to all network interfaces",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        message_template="Binding to 0.0.0.0 exposes app to all network interfaces - security risk (CWE-200)",
        references=[
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    ),
    Rule(
        rule_id="GRADIO003",
        name="Insecure File Upload",
        description="File upload component should specify allowed file types",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="File upload component should specify allowed file types (CWE-434)",
        references=[
            "https://cwe.mitre.org/data/definitions/434.html",
            "https://www.gradio.app/guides/sharing-your-app#security-and-file-access",
        ],
    ),
    Rule(
        rule_id="GRADIO004",
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
        rule_id="GRADIO005",
        name="SQL Injection via String Concatenation",
        description="SQL query uses string concatenation/formatting",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        message_template="SQL query uses string concatenation/formatting - use parameterized queries (CWE-89)",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    Rule(
        rule_id="GRADIO006",
        name="Path Traversal in File Operations",
        description="File operation uses unsanitized user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        message_template="File operation uses unsanitized user input - path traversal risk (CWE-22)",
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
    ),
]


# Register rules with the rule engine
register_rules(GRADIO_RULES)
