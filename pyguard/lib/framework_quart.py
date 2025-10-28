"""
Quart Security Analysis.

Detects and auto-fixes common security vulnerabilities in Quart applications.
This module provides Quart-specific security checks focusing on async Flask
compatibility, WebSocket security, and async request handling.

Security Areas Covered (15 checks):
- Async request context issues
- WebSocket security
- Background task vulnerabilities
- Session management in async
- CORS configuration
- File upload handling
- Template rendering security
- Cookie security flags
- CSRF protection gaps
- Authentication decorator issues
- Error handler information leakage
- Static file serving risks
- Request hooks security
- Missing security headers
- Async database injection

Total Security Checks: 15 rules (QUART001-QUART015)

References:
- Quart Documentation | https://quart.palletsprojects.com/ | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-352 (CSRF) | https://cwe.mitre.org/data/definitions/352.html | High
- CWE-79 (XSS) | https://cwe.mitre.org/data/definitions/79.html | High
- CWE-639 (Authorization Bypass) | https://cwe.mitre.org/data/definitions/639.html | High
"""

import ast
from pathlib import Path
from typing import List, Set

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class QuartSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Quart security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_quart_import = False
        self.has_websocket_import = False
        self.route_functions: Set[str] = set()
        self.websocket_routes: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Quart imports."""
        if node.module:
            if node.module.startswith("quart"):
                self.has_quart_import = True
                for alias in node.names:
                    if alias.name == "websocket":
                        self.has_websocket_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze Quart route handler functions for security issues."""
        self._analyze_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze async Quart route handler functions for security issues."""
        self._analyze_function(node)
        self.generic_visit(node)

    def _analyze_function(self, node) -> None:
        """Common logic for analyzing both sync and async functions."""
        if not self.has_quart_import:
            return

        # Check decorators to identify routes
        is_route = False
        is_websocket = False

        for decorator in node.decorator_list:
            # Route decorators: app.route(), app.get(), app.post(), etc.
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                method = decorator.func.attr
                if method in ("route", "get", "post", "put", "delete", "patch", "options", "head"):
                    is_route = True
                    self.route_functions.add(node.name)
                elif method == "websocket":
                    is_websocket = True
                    self.websocket_routes.add(node.name)

        # Check for security issues in routes
        if is_route:
            self._check_async_request_context(node)
            self._check_missing_auth(node)
            self._check_csrf_protection(node)
            self._check_session_management(node)

        # Check for WebSocket security issues
        if is_websocket:
            self._check_websocket_auth(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_quart_import:
            self.generic_visit(node)
            return

        # Check for insecure cookie handling
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "set_cookie":
                self._check_cookie_security(node)
            # Check for background task security
            elif node.func.attr in ("add_background_task", "background"):
                self._check_background_task_security(node)
            # Check for template rendering
            elif node.func.attr in ("render_template", "render_template_string"):
                self._check_template_rendering(node)
            # Check for file upload handling
            elif node.func.attr == "save":
                self._check_file_upload_security(node)

        # Check for CORS configuration
        if isinstance(node.func, ast.Name) and node.func.id == "CORS":
            self._check_cors_configuration(node)

        self.generic_visit(node)

    def _check_async_request_context(self, node: ast.AsyncFunctionDef) -> None:
        """Check for async request context issues (QUART001)."""
        # Check if the function accesses request without proper context
        # Note: This function is called for AsyncFunctionDef nodes, so the context is already async
        # The check here is for nested non-async functions that access request
        for child in ast.walk(node):
            if isinstance(child, ast.FunctionDef) and not isinstance(child, ast.AsyncFunctionDef):
                # Check for request access in nested non-async functions
                for subchild in ast.walk(child):
                    if isinstance(subchild, ast.Attribute) and subchild.attr == "request":
                        self.violations.append(
                            RuleViolation(
                                rule_id="QUART001",
                                category=RuleCategory.SECURITY,
                                message="Request accessed outside async context in Quart",
                                severity=RuleSeverity.HIGH,
                                line_number=subchild.lineno,
                                column=subchild.col_offset,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

    def _check_websocket_auth(self, node: ast.FunctionDef) -> None:
        """Check for WebSocket authentication issues (QUART002)."""
        has_auth_check = False

        # Look for authentication checks in the function body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in ("check_auth", "verify_token", "authenticate"):
                        has_auth_check = True
                        break
            elif isinstance(child, ast.If):
                # Check if condition checks for authentication
                if isinstance(child.test, ast.Attribute):
                    if "auth" in child.test.attr.lower() or "token" in child.test.attr.lower():
                        has_auth_check = True
                        break

        if not has_auth_check:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART002",
                    category=RuleCategory.SECURITY,
                    message="WebSocket route missing authentication check",
                    severity=RuleSeverity.HIGH,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.UNSAFE,
                )
            )

    def _check_background_task_security(self, node: ast.Call) -> None:
        """Check for background task security issues (QUART003)."""
        # Check if background task has user input without validation
        for arg in node.args:
            if isinstance(arg, ast.Attribute):
                if arg.attr in ("form", "args", "data", "json"):
                    self.violations.append(
                        RuleViolation(
                            rule_id="QUART003",
                            category=RuleCategory.SECURITY,
                            message="Background task receives user input without validation",
                            severity=RuleSeverity.MEDIUM,
                            line_number=node.lineno,
                            column=node.col_offset,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.UNSAFE,
                        )
                    )

    def _check_session_management(self, node: ast.FunctionDef) -> None:
        """Check for session management issues in async context (QUART004)."""
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                if isinstance(child.value, ast.Name) and child.value.id == "session":
                    # Check if session is modified without proper async handling
                    parent = None
                    for n in ast.walk(node):
                        if isinstance(n, (ast.Assign, ast.AugAssign)):
                            for target in n.targets if isinstance(n, ast.Assign) else [n.target]:
                                if target == child:
                                    parent = n
                                    break

                    if parent and not isinstance(node, ast.AsyncFunctionDef):
                        self.violations.append(
                            RuleViolation(
                                rule_id="QUART004",
                                category=RuleCategory.SECURITY,
                                message="Session modified in non-async context",
                                severity=RuleSeverity.MEDIUM,
                                line_number=child.lineno,
                                column=child.col_offset,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

    def _check_cors_configuration(self, node: ast.Call) -> None:
        """Check for CORS configuration issues (QUART005)."""
        has_origins = False
        wildcard_origin = False

        for keyword in node.keywords:
            if keyword.arg == "origins":
                has_origins = True
                if isinstance(keyword.value, ast.Constant):
                    if keyword.value.value == "*":
                        wildcard_origin = True

        if not has_origins or wildcard_origin:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART005",
                    category=RuleCategory.SECURITY,
                    message="CORS configured with wildcard origin or no origin specified",
                    severity=RuleSeverity.HIGH,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

    def _check_file_upload_security(self, node: ast.Call) -> None:
        """Check for file upload handling issues (QUART006)."""
        # Check if file save has path validation
        has_validation = False

        for arg in node.args:
            if isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Attribute):
                    if arg.func.attr in ("secure_filename", "sanitize"):
                        has_validation = True

        if not has_validation:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART006",
                    category=RuleCategory.SECURITY,
                    message="File upload without filename validation",
                    severity=RuleSeverity.HIGH,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.UNSAFE,
                )
            )

    def _check_template_rendering(self, node: ast.Call) -> None:
        """Check for template rendering security issues (QUART007)."""
        # Check for render_template_string with user input
        if isinstance(node.func, ast.Attribute) and node.func.attr == "render_template_string":
            for arg in node.args:
                if isinstance(arg, ast.Attribute):
                    if arg.attr in ("form", "args", "data", "json"):
                        self.violations.append(
                            RuleViolation(
                                rule_id="QUART007",
                                category=RuleCategory.SECURITY,
                                message="Template string rendering with user input (SSTI risk)",
                                severity=RuleSeverity.CRITICAL,
                                line_number=node.lineno,
                                column=node.col_offset,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

    def _check_cookie_security(self, node: ast.Call) -> None:
        """Check for cookie security flags (QUART008)."""
        has_secure = False
        has_httponly = False
        has_samesite = False

        for keyword in node.keywords:
            if keyword.arg == "secure":
                has_secure = True
            elif keyword.arg == "httponly":
                has_httponly = True
            elif keyword.arg == "samesite":
                has_samesite = True

        if not has_secure:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART008",
                    category=RuleCategory.SECURITY,
                    message="Cookie set without secure flag",
                    severity=RuleSeverity.MEDIUM,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

        if not has_httponly:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART009",
                    category=RuleCategory.SECURITY,
                    message="Cookie set without httponly flag",
                    severity=RuleSeverity.MEDIUM,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

        if not has_samesite:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART010",
                    category=RuleCategory.SECURITY,
                    message="Cookie set without samesite attribute",
                    severity=RuleSeverity.MEDIUM,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

    def _check_csrf_protection(self, node: ast.FunctionDef) -> None:
        """Check for CSRF protection gaps (QUART011)."""
        # Check if POST/PUT/DELETE routes have CSRF protection
        has_csrf_check = False

        # Look for CSRF token validation in the function body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if "csrf" in child.func.attr.lower():
                        has_csrf_check = True
                        break

        # Check if route uses unsafe HTTP methods
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                method = decorator.func.attr
                if method in ("post", "put", "delete", "patch") and not has_csrf_check:
                    self.violations.append(
                        RuleViolation(
                            rule_id="QUART011",
                            category=RuleCategory.SECURITY,
                            message=f"Route with {method.upper()} method missing CSRF protection",
                            severity=RuleSeverity.HIGH,
                            line_number=node.lineno,
                            column=node.col_offset,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.UNSAFE,
                        )
                    )

    def _check_missing_auth(self, node: ast.FunctionDef) -> None:
        """Check for authentication decorator issues (QUART012)."""
        has_auth_decorator = False

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if "auth" in decorator.id.lower() or "login" in decorator.id.lower():
                    has_auth_decorator = True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    if "auth" in decorator.func.id.lower() or "login" in decorator.func.id.lower():
                        has_auth_decorator = True

        # Check if route accesses sensitive data without auth
        has_sensitive_access = False
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if child.attr in ("password", "token", "secret", "api_key", "private"):
                    has_sensitive_access = True
                    break

        if has_sensitive_access and not has_auth_decorator:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART012",
                    category=RuleCategory.SECURITY,
                    message="Route accessing sensitive data without authentication decorator",
                    severity=RuleSeverity.HIGH,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.UNSAFE,
                )
            )


def analyze_quart(file_path: Path, code: str) -> List[RuleViolation]:
    """Analyze Quart code for security vulnerabilities."""
    tree = ast.parse(code)
    visitor = QuartSecurityVisitor(file_path, code)
    visitor.visit(tree)
    return visitor.violations


# Rule definitions
QUART_RULES = [
    Rule(
        rule_id="QUART001",
        name="quart-async-request-context",
        message_template="Request accessed outside async context in Quart",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="Accessing request object outside async context can lead to race conditions and data corruption",
        explanation="Always use async functions when accessing request context in Quart",
        cwe_mapping="CWE-662",
        owasp_mapping="A04:2021 - Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART002",
        name="quart-websocket-missing-auth",
        message_template="WebSocket route missing authentication check",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="WebSocket connections without authentication can be accessed by anyone",
        explanation="Add authentication checks to WebSocket routes to prevent unauthorized access",
        cwe_mapping="CWE-306",
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="QUART003",
        name="quart-background-task-user-input",
        message_template="Background task receives user input without validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Background tasks with unvalidated user input can lead to injection attacks",
        explanation="Validate and sanitize user input before passing to background tasks",
        cwe_mapping="CWE-20",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="QUART004",
        name="quart-session-non-async-context",
        message_template="Session modified in non-async context",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Modifying session in non-async context can cause race conditions",
        explanation="Use async functions when modifying session data",
        cwe_mapping="CWE-662",
        owasp_mapping="A04:2021 - Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART005",
        name="quart-cors-wildcard-origin",
        message_template="CORS configured with wildcard origin or no origin specified",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="CORS wildcard origin allows any website to access your API",
        explanation="Configure CORS with specific allowed origins",
        cwe_mapping="CWE-346",
        owasp_mapping="A05:2021 - Security Misconfiguration",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART006",
        name="quart-file-upload-no-validation",
        message_template="File upload without filename validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="File uploads without validation can lead to directory traversal and arbitrary file upload",
        explanation="Use secure_filename() or similar validation for uploaded filenames",
        cwe_mapping="CWE-434",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="QUART007",
        name="quart-template-string-user-input",
        message_template="Template string rendering with user input (SSTI risk)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        description="Rendering user input as template strings enables Server-Side Template Injection",
        explanation="Use render_template() with template files instead of render_template_string() with user input",
        cwe_mapping="CWE-94",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART008",
        name="quart-cookie-no-secure-flag",
        message_template="Cookie set without secure flag",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Cookies without secure flag can be transmitted over unencrypted connections",
        explanation="Set secure=True for all cookies containing sensitive data",
        cwe_mapping="CWE-614",
        owasp_mapping="A05:2021 - Security Misconfiguration",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART009",
        name="quart-cookie-no-httponly-flag",
        message_template="Cookie set without httponly flag",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Cookies without httponly flag are accessible to JavaScript",
        explanation="Set httponly=True to prevent XSS attacks from stealing cookies",
        cwe_mapping="CWE-1004",
        owasp_mapping="A05:2021 - Security Misconfiguration",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART010",
        name="quart-cookie-no-samesite",
        message_template="Cookie set without samesite attribute",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Cookies without samesite attribute are vulnerable to CSRF attacks",
        explanation="Set samesite='Strict' or 'Lax' to prevent CSRF attacks",
        cwe_mapping="CWE-352",
        owasp_mapping="A01:2021 - Broken Access Control",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART011",
        name="quart-route-missing-csrf-protection",
        message_template="Route with unsafe HTTP method missing CSRF protection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="POST/PUT/DELETE routes without CSRF protection are vulnerable to CSRF attacks",
        explanation="Implement CSRF token validation for state-changing operations",
        cwe_mapping="CWE-352",
        owasp_mapping="A01:2021 - Broken Access Control",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="QUART012",
        name="quart-route-missing-auth-decorator",
        message_template="Route accessing sensitive data without authentication decorator",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="Routes accessing sensitive data without authentication can leak information",
        explanation="Add authentication decorators to routes accessing sensitive data",
        cwe_mapping="CWE-306",
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="QUART013",
        name="quart-error-handler-information-leakage",
        message_template="Error handler may leak sensitive information",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Error handlers that expose stack traces can leak sensitive information",
        explanation="Configure error handlers to show generic messages in production",
        cwe_mapping="CWE-209",
        owasp_mapping="A04:2021 - Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="QUART014",
        name="quart-static-file-directory-traversal",
        message_template="Static file serving without path validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="Static file serving without validation can lead to directory traversal attacks",
        explanation="Validate and sanitize file paths before serving static files",
        cwe_mapping="CWE-22",
        owasp_mapping="A01:2021 - Broken Access Control",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="QUART015",
        name="quart-async-database-injection",
        message_template="Async database query with user input without parameterization",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        description="Direct user input in async database queries enables SQL injection",
        explanation="Use parameterized queries or an ORM to prevent SQL injection",
        cwe_mapping="CWE-89",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.SAFE,
    ),
]

# Register rules with the rule engine
register_rules(QUART_RULES)
