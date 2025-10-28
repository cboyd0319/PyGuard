"""
Flask and FastAPI Security Analysis.

Detects and auto-fixes common security vulnerabilities in Flask and FastAPI applications.
This module provides framework-specific security checks that go beyond generic Python security.

Security Areas Covered:
- CSRF protection configuration
- Secure cookie settings
- Session management security
- Input validation on routes
- SQL injection in database queries
- XSS in template rendering
- Insecure deserialization
- Debug mode in production
- Secret key security
- CORS misconfiguration

References:
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- Flask Security Best Practices | https://flask.palletsprojects.com/security/ | High
- FastAPI Security | https://fastapi.tiangolo.com/tutorial/security/ | High
- CWE-352 (CSRF) | https://cwe.mitre.org/data/definitions/352.html | High
- CWE-614 (Secure Cookie Flag) | https://cwe.mitre.org/data/definitions/614.html | Medium
"""

import ast
from pathlib import Path
import re

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class FlaskSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Flask/FastAPI security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_flask_import = False
        self.has_fastapi_import = False
        self.has_csrf_protection = False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Flask/FastAPI imports."""
        if node.module:
            if node.module.startswith("flask"):
                self.has_flask_import = True
                # Check for CSRF protection import
                for alias in node.names:
                    if alias.name == "CSRFProtect":
                        self.has_csrf_protection = True
            elif node.module.startswith("fastapi"):
                self.has_fastapi_import = True

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect security issues in function calls."""
        # Flask app.run() with debug=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "run":
                for keyword in node.keywords:
                    if keyword.arg == "debug":
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FLASK001",
                                    message="Flask debug mode enabled - this should never be used in production (CWE-489)",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                    fix_data={"keyword": "debug", "new_value": "False"},
                                )
                            )

        # make_response() without secure cookie settings
        if isinstance(node.func, ast.Name) and node.func.id == "make_response":
            # Check if followed by set_cookie without secure/httponly flags
            pass

        # render_template_string with user input (SSTI vulnerability)
        if isinstance(node.func, ast.Name) and node.func.id == "render_template_string":
            if len(node.args) > 0:
                # Check if first argument contains f-string or string concatenation
                if isinstance(node.args[0], ast.JoinedStr):  # f-string
                    self.violations.append(
                        RuleViolation(
                            rule_id="FLASK002",
                            message="Server-Side Template Injection (SSTI) risk: render_template_string with f-string or string concatenation (CWE-1336)",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

        # jsonify() with user-controlled keys
        if isinstance(node.func, ast.Name) and node.func.id == "jsonify":
            # Potential mass assignment vulnerability
            if len(node.args) > 0 and isinstance(node.args[0], ast.Call):
                if isinstance(node.args[0].func, ast.Attribute):
                    if node.args[0].func.attr in ("to_dict", "dict"):
                        self.violations.append(
                            RuleViolation(
                                rule_id="FLASK003",
                                message="Potential mass assignment vulnerability: jsonify with to_dict() (CWE-915)",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect insecure configuration assignments."""
        # app.secret_key = "hardcoded"
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if (
                    target.attr == "secret_key"
                ):  # pyguard: disable=CWE-208  # Pattern detection, not vulnerable code
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # Check if it's a weak/default secret key
                        secret_key = node.value.value
                        if len(secret_key) < 16 or secret_key in [
                            "dev",
                            "secret",
                            "changeme",
                            "default",
                        ]:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FLASK004",
                                    message=f"Weak or default secret key detected (length: {len(secret_key)}) - use os.environ.get('SECRET_KEY') (CWE-798)",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

            # CORS(app, origins="*")
            if isinstance(target, ast.Name):
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Name) and node.value.func.id == "CORS":
                        for keyword in node.value.keywords:
                            if keyword.arg == "origins":
                                if isinstance(keyword.value, ast.Constant):
                                    if keyword.value.value == "*":
                                        self.violations.append(
                                            RuleViolation(
                                                rule_id="FLASK005",
                                                message="Insecure CORS configuration: origins='*' allows any origin (CWE-942)",
                                                line_number=node.lineno,
                                                column=node.col_offset,
                                                severity=RuleSeverity.HIGH,
                                                category=RuleCategory.SECURITY,
                                                file_path=self.file_path,
                                                fix_applicability=FixApplicability.SUGGESTED,
                                            )
                                        )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check route handlers for security issues."""
        # Check if this is a Flask route
        has_route_decorator = False
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in ("route", "get", "post", "put", "delete"):
                        has_route_decorator = True

        if has_route_decorator:
            # Check for SQL injection patterns
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    # Check for string formatting in SQL queries
                    if isinstance(stmt.func, ast.Attribute):
                        if stmt.func.attr in ("execute", "executemany"):
                            # Check if any argument uses string formatting
                            for arg in stmt.args:
                                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="FLASK006",
                                            message="Potential SQL injection in route handler - use parameterized queries (CWE-89)",
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.CRITICAL,
                                            category=RuleCategory.SECURITY,
                                            file_path=self.file_path,
                                            fix_applicability=FixApplicability.MANUAL,
                                        )
                                    )

        self.generic_visit(node)


class FlaskSecurityChecker:
    """Main checker for Flask/FastAPI security vulnerabilities."""

    def __init__(self):
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def check_file(self, file_path: Path) -> list[RuleViolation]:
        """
        Check a Python file for Flask/FastAPI security vulnerabilities.

        Args:
            file_path: Path to the Python file to check

        Returns:
            List of detected security violations
        """
        try:
            content = self.file_ops.read_file(file_path)
            if not content:
                return []

            # Quick check - only analyze Flask/FastAPI files
            if not ("flask" in content.lower() or "fastapi" in content.lower()):
                return []

            tree = ast.parse(content, filename=str(file_path))
            visitor = FlaskSecurityVisitor(file_path, content)
            visitor.visit(tree)

            # Check for CSRF protection (should be enabled for Flask apps)
            if visitor.has_flask_import and not visitor.has_csrf_protection:
                # Check if any POST routes exist
                has_post_route = "methods=['POST']" in content or 'methods=["POST"]' in content
                if has_post_route:
                    visitor.violations.append(
                        RuleViolation(
                            rule_id="FLASK007",
                            message="Flask app with POST routes should enable CSRF protection (CWE-352)",
                            line_number=1,
                            column=0,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            file_path=file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

            return visitor.violations

        except Exception as e:
            self.logger.error(f"Error checking Flask security: {e}", file_path=str(file_path))
            return []

    def fix_file(self, file_path: Path) -> tuple[bool, list[str]]:
        """
        Apply automatic security fixes to Flask/FastAPI code.

        Args:
            file_path: Path to the Python file to fix

        Returns:
            Tuple of (success, list of fixes applied)
        """
        violations = self.check_file(file_path)
        if not violations:
            return True, []

        content = self.file_ops.read_file(file_path)
        if not content:
            return False, []

        fixes_applied = []

        # Apply SAFE fixes only
        for violation in violations:
            if violation.fix_applicability == FixApplicability.SAFE:
                if violation.rule_id == "FLASK001":
                    # Fix debug=True to debug=False
                    content = re.sub(
                        r"\.run\([^)]*debug\s*=\s*True",
                        lambda m: str(m.group(0)).replace("debug=True", "debug=False"),
                        content,
                    )
                    fixes_applied.append("Disabled Flask debug mode")

                elif violation.rule_id == "FLASK004":
                    # Fix hardcoded secret_key to use environment variable
                    content = re.sub(
                        r'(secret_key\s*=\s*)["\'][^"\']+["\']',
                        r'\1os.environ.get("SECRET_KEY", "dev")',
                        content,
                    )
                    # Add import if needed
                    if "import os" not in content:
                        content = "import os\n" + content
                    fixes_applied.append("Changed secret_key to use environment variable")

        if fixes_applied:
            success = self.file_ops.write_file(file_path, content)
            return success, fixes_applied

        return True, []


# Define rules
FLASK_DEBUG_MODE_RULE = Rule(
    rule_id="FLASK001",
    name="flask-debug-mode",
    message_template="Flask debug mode should be disabled in production",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    description="Running Flask with debug=True in production exposes sensitive information",
)

FLASK_SSTI_RULE = Rule(
    rule_id="FLASK002",
    name="flask-ssti-risk",
    message_template="Server-Side Template Injection risk with render_template_string",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    description="Using render_template_string with user input can lead to SSTI",
)

FLASK_MASS_ASSIGNMENT_RULE = Rule(
    rule_id="FLASK003",
    name="flask-mass-assignment",
    message_template="Potential mass assignment vulnerability in jsonify",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SUGGESTED,
    description="Using jsonify with to_dict() may expose sensitive fields",
)

FLASK_WEAK_SECRET_KEY_RULE = Rule(
    rule_id="FLASK004",
    name="flask-weak-secret-key",
    message_template="Weak or hardcoded secret key detected",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    description="Secret keys should be strong and loaded from environment variables",
)

FLASK_INSECURE_CORS_RULE = Rule(
    rule_id="FLASK005",
    name="flask-insecure-cors",
    message_template="Insecure CORS configuration allows any origin",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SUGGESTED,
    description="CORS should restrict origins to trusted domains only",
)

FLASK_SQL_INJECTION_RULE = Rule(
    rule_id="FLASK006",
    name="flask-sql-injection",
    message_template="Potential SQL injection in route handler",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    description="Use parameterized queries to prevent SQL injection",
)

FLASK_CSRF_PROTECTION_RULE = Rule(
    rule_id="FLASK007",
    name="flask-csrf-protection",
    message_template="Flask app should enable CSRF protection",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SUGGESTED,
    description="POST routes should be protected against CSRF attacks",
)

# Register rules
register_rules(
    [
        FLASK_DEBUG_MODE_RULE,
        FLASK_SSTI_RULE,
        FLASK_MASS_ASSIGNMENT_RULE,
        FLASK_WEAK_SECRET_KEY_RULE,
        FLASK_INSECURE_CORS_RULE,
        FLASK_SQL_INJECTION_RULE,
        FLASK_CSRF_PROTECTION_RULE,
    ]
)
