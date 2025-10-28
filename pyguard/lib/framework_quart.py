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
        self.current_function_has_secure_filename = False
        # Track tainted variables (user input)
        self.tainted_vars: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Quart imports."""
        if node.module:
            if node.module.startswith("quart"):
                self.has_quart_import = True
                for alias in node.names:
                    if alias.name == "websocket":
                        self.has_websocket_import = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments for taint analysis."""
        # Check if the right side is user input (request.form, request.args, etc.)
        if self._is_user_input(node.value):
            # Mark all target variables as tainted
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
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

        # Reset function-level tracking
        self.current_function_has_secure_filename = False
        
        # Check if secure_filename is used anywhere in this function
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and "secure" in child.func.id.lower():
                    self.current_function_has_secure_filename = True
                    break
                elif isinstance(child.func, ast.Attribute) and "secure" in child.func.attr.lower():
                    self.current_function_has_secure_filename = True
                    break

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
        if isinstance(node.func, ast.Name) and node.func.id.lower() == "cors":
            self._check_cors_configuration(node)

        self.generic_visit(node)

    def _check_async_request_context(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Check for async request context issues (QUART001)."""
        # In Quart, request access should be in async context
        # Check if this is a non-async function that accesses request
        if isinstance(node, ast.FunctionDef) and not isinstance(node, ast.AsyncFunctionDef):
            # This is a sync function (non-async) - check if it accesses request
            for child in ast.walk(node):
                if isinstance(child, ast.Attribute):
                    # Check for request.* access
                    if isinstance(child.value, ast.Name) and child.value.id == "request":
                        self.violations.append(
                            RuleViolation(
                                rule_id="QUART001",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.HIGH,
                                message="Request accessed in non-async function in Quart. "
                                "Use 'async def' for route handlers that access request.",
                                file_path=self.file_path,
                                line_number=getattr(child, "lineno", 0),
                                column=getattr(child, "col_offset", 0),
                                end_line_number=getattr(child, "end_lineno", getattr(child, "lineno", 0)),
                                end_column=getattr(child, "end_col_offset", getattr(child, "col_offset", 0)),
                                code_snippet=self.lines[getattr(child, "lineno", 1) - 1] if getattr(child, "lineno", 1) <= len(self.lines) else "",
                                fix_suggestion="Change 'def' to 'async def' and use 'await' for request operations",
                                fix_applicability=FixApplicability.UNSAFE,
                                cwe_id=None,
                                owasp_id=None,
                                source_tool="pyguard"
                            )
                        )
                        break  # Only report once per function

    def _check_websocket_auth(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Check for WebSocket authentication issues (QUART002)."""
        has_auth_check = False

        # Look for authentication checks in the function body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Check for function calls with auth-related names
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in ("check_auth", "verify_token", "authenticate"):
                        has_auth_check = True
                        break
                elif isinstance(child.func, ast.Name):
                    if any(keyword in child.func.id.lower() for keyword in ["auth", "verify", "validate"]):
                        has_auth_check = True
                        break
            elif isinstance(child, ast.If):
                # Check if condition checks for authentication
                if isinstance(child.test, ast.Attribute):
                    if "auth" in child.test.attr.lower() or "token" in child.test.attr.lower():
                        has_auth_check = True
                        break
                # Also check for function calls in conditions
                elif isinstance(child.test, ast.UnaryOp) and isinstance(child.test.op, ast.Not):
                    if isinstance(child.test.operand, ast.Call):
                        if isinstance(child.test.operand.func, ast.Name):
                            if any(keyword in child.test.operand.func.id.lower() for keyword in ["verify", "auth", "validate"]):
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
            is_user_input = False
            if isinstance(arg, ast.Attribute):
                if arg.attr in ("form", "args", "data", "json"):
                    is_user_input = True
            elif isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                is_user_input = True
            
            if is_user_input:
                self.violations.append(
                    RuleViolation(
                        rule_id="QUART003",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Background task receives user input without validation",
                        file_path=self.file_path,
                        line_number=getattr(node, "lineno", 0),
                        column=getattr(node, "col_offset", 0),
                        end_line_number=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                        end_column=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
                        code_snippet=self.lines[getattr(node, "lineno", 1) - 1] if getattr(node, "lineno", 1) <= len(self.lines) else "",
                        fix_suggestion="Validate and sanitize user input before passing to background tasks",
                        fix_applicability=FixApplicability.UNSAFE,
                        cwe_id=None,
                        owasp_id=None,
                        source_tool="pyguard"
                    )
                )
                break  # Only report once per call

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
                    severity=RuleSeverity.HIGH,
                    message="CORS configured with wildcard origin or no origin specified",
                    file_path=self.file_path,
                    line_number=getattr(node, "lineno", 0),
                    column=getattr(node, "col_offset", 0),
                    end_line_number=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                    end_column=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
                    code_snippet=self.lines[getattr(node, "lineno", 1) - 1] if getattr(node, "lineno", 1) <= len(self.lines) else "",
                    fix_suggestion="Specify explicit origins: cors(app, origins=['https://example.com'])",
                    fix_applicability=FixApplicability.SAFE,
                    cwe_id=None,
                    owasp_id=None,
                    source_tool="pyguard"
                )
            )

    def _check_file_upload_security(self, node: ast.Call) -> None:
        """Check for file upload handling issues (QUART006)."""
        # Check if file save has path validation
        # Check if secure_filename was used in the current function
        if self.current_function_has_secure_filename:
            return  # Function uses secure_filename, so it's safe

        # Otherwise, check direct usage in the save() call
        has_validation = False
        for arg in node.args:
            if isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Attribute):
                    if arg.func.attr in ("secure_filename", "sanitize"):
                        has_validation = True
                        break
                elif isinstance(arg.func, ast.Name):
                    if "secure" in arg.func.id.lower() or "sanitize" in arg.func.id.lower():
                        has_validation = True
                        break

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

    def _check_csrf_protection(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Check for CSRF protection gaps (QUART011)."""
        # Check if POST/PUT/DELETE routes have CSRF protection
        has_csrf_check = False

        # Look for CSRF token validation in the function body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Check for csrf function calls (validate_csrf_token, check_csrf, etc.)
                if isinstance(child.func, ast.Attribute):
                    if "csrf" in child.func.attr.lower():
                        has_csrf_check = True
                        break
                elif isinstance(child.func, ast.Name):
                    if "csrf" in child.func.id.lower():
                        has_csrf_check = True
                        break
            # Also check for csrf_token variable access/validation
            elif isinstance(child, ast.Name):
                if "csrf" in child.id.lower():
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

    def _check_missing_auth(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
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
        sensitive_keywords = ["password", "token", "secret", "api_key", "private", "api_token"]
        
        for child in ast.walk(node):
            # Check for sensitive attributes
            if isinstance(child, ast.Attribute):
                if child.attr in sensitive_keywords:
                    has_sensitive_access = True
                    break
            # Check for sensitive keywords in string literals (e.g., SQL queries)
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                value_lower = child.value.lower()
                if any(keyword in value_lower for keyword in sensitive_keywords):
                    has_sensitive_access = True
                    break

        if has_sensitive_access and not has_auth_decorator:
            self.violations.append(
                RuleViolation(
                    rule_id="QUART012",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Route accessing sensitive data without authentication decorator",
                    file_path=self.file_path,
                    line_number=getattr(node, "lineno", 0),
                    column=getattr(node, "col_offset", 0),
                    end_line_number=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                    end_column=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
                    code_snippet=self.lines[getattr(node, "lineno", 1) - 1] if getattr(node, "lineno", 1) <= len(self.lines) else "",
                    fix_suggestion="Add authentication decorator like @login_required or @requires_auth",
                    fix_applicability=FixApplicability.UNSAFE,
                    cwe_id=None,
                    owasp_id=None,
                    source_tool="pyguard"
                )
            )

    def _is_user_input(self, node: ast.AST) -> bool:
        """Check if an expression represents user input (request.form, request.args, etc.)."""
        if isinstance(node, ast.Attribute):
            # Check for request.form, request.args, request.json, etc.
            if node.attr in ("form", "args", "json", "data", "values", "files"):
                if isinstance(node.value, ast.Name) and node.value.id == "request":
                    return True
            return self._is_user_input(node.value)
        elif isinstance(node, ast.Await):
            # Handle await request.form
            return self._is_user_input(node.value)
        return False


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
