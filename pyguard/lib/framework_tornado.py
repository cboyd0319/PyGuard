"""
Tornado Security Analysis.

Detects and auto-fixes common security vulnerabilities in Tornado applications.
This module provides Tornado-specific security checks focusing on async patterns,
WebSocket security, RequestHandler security, and high-performance web application security.

Security Areas Covered (20 checks):
- RequestHandler auth override issues
- Insecure cookie secret generation  
- XSRF protection disabled
- WebSocket origin validation missing
- Async database query injection
- Template auto-escape disabled
- Static file handler directory traversal
- IOLoop blocking operations
- Missing secure flag on cookies
- Concurrent request race conditions
- Insecure HTTP client usage
- Missing TLS/SSL verification
- Cookie manipulation vulnerabilities
- Session fixation in async context
- Missing HSTS configuration
- Authentication decorator bypasses
- Missing input sanitization
- Insecure redirect handling
- Template injection in async handlers
- Improper exception disclosure

Total Security Checks: 20 rules (TORNADO001-TORNADO020)

References:
- Tornado Security | https://www.tornadoweb.org/en/stable/guide/security.html | High
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


class TornadoSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Tornado security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_tornado_import = False
        self.has_requesthandler_import = False
        self.has_websocket_import = False
        self.handler_classes: Set[str] = set()
        self.xsrf_enabled_handlers: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Tornado imports."""
        if node.module:
            if node.module.startswith("tornado"):
                self.has_tornado_import = True
                for alias in node.names:
                    if alias.name == "RequestHandler":
                        self.has_requesthandler_import = True
                    elif alias.name == "WebSocketHandler":
                        self.has_websocket_import = True
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze Tornado handler classes for security issues."""
        if not self.has_tornado_import:
            self.generic_visit(node)
            return

        # Check if it's a Tornado handler
        is_request_handler = any(
            isinstance(base, ast.Name) and base.id in ("RequestHandler", "StaticFileHandler")
            for base in node.bases
        ) or any(
            isinstance(base, ast.Attribute) and base.attr in ("RequestHandler", "StaticFileHandler")
            for base in node.bases
        )

        is_websocket_handler = any(
            isinstance(base, ast.Name) and base.id == "WebSocketHandler"
            for base in node.bases
        ) or any(
            isinstance(base, ast.Attribute) and base.attr == "WebSocketHandler"
            for base in node.bases
        )

        if is_request_handler or is_websocket_handler:
            self.handler_classes.add(node.name)
            
            # TORNADO001: Check for XSRF protection disabled
            self._check_xsrf_disabled(node)
            
            # TORNADO002: Check for missing secure flag on cookies
            self._check_cookie_security(node)
            
            # TORNADO003: Check for weak cookie secret
            self._check_cookie_secret(node)
            
            # TORNADO004: Check for auth override issues
            self._check_auth_override(node)
            
            # TORNADO005: Check for template auto-escape disabled
            self._check_template_autoescape(node)
            
            # TORNADO006: Check for static file directory traversal
            if "StaticFileHandler" in str(node.bases):
                self._check_static_file_traversal(node)
            
            # TORNADO007: Check for missing input sanitization
            self._check_input_sanitization(node)
            
            # TORNADO008: Check for insecure redirect handling
            self._check_redirect_security(node)
            
            # TORNADO009: Check for exception disclosure
            self._check_exception_disclosure(node)
            
            # TORNADO010: Check for missing HSTS configuration
            self._check_hsts_configuration(node)
            
            # TORNADO019: Check for authentication decorator bypasses
            self._check_authentication_decorator_bypass(node)
            
            # TORNADO020: Check for cookie manipulation vulnerabilities
            self._check_cookie_manipulation(node)

        if is_websocket_handler:
            # TORNADO011: Check for WebSocket origin validation missing
            self._check_websocket_origin_validation(node)
            
            # TORNADO012: Check for session fixation in async context
            self._check_session_fixation(node)

        # Check methods in all classes
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if is_request_handler or is_websocket_handler:
                    # TORNADO013: Check for async database query injection
                    self._check_async_query_injection(item)
                    
                    # TORNADO014: Check for IOLoop blocking operations
                    self._check_blocking_operations(item)
                    
                    # TORNADO015: Check for concurrent request race conditions
                    self._check_race_conditions(item)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for insecure HTTP client usage and other call-based vulnerabilities."""
        if not self.has_tornado_import:
            self.generic_visit(node)
            return

        # TORNADO016: Check for insecure HTTP client usage
        self._check_http_client_security(node)
        
        # TORNADO017: Check for missing TLS/SSL verification
        self._check_tls_verification(node)
        
        # TORNADO018: Check for template injection
        self._check_template_injection(node)

        self.generic_visit(node)

    def _check_xsrf_disabled(self, node: ast.ClassDef) -> None:
        """TORNADO001: Detect XSRF protection disabled."""
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "check_xsrf_cookie":
                # Check if it's overridden to pass (disabling XSRF)
                for stmt in item.body:
                    if isinstance(stmt, ast.Pass):
                        self.violations.append(
                            RuleViolation(
                                rule_id="TORNADO001",
                                file_path=self.file_path,
                                line_number=item.lineno,
                                column=item.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                message="XSRF protection disabled in RequestHandler - vulnerable to Cross-Site Request Forgery",
                                fix_suggestion="Remove the check_xsrf_cookie override or implement proper XSRF validation. "
                                              "Use set_xsrf_cookie() and enable xsrf_cookies in application settings.",
                                cwe_id="CWE-352",
                                owasp_id="A01:2021 - Broken Access Control",
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )
                        return

    def _check_cookie_security(self, node: ast.ClassDef) -> None:
        """TORNADO002: Detect missing secure flag on cookies."""
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        if (isinstance(stmt.func, ast.Attribute) and 
                            stmt.func.attr == "set_cookie"):
                            # Check if secure=True is set
                            has_secure = any(
                                kw.arg == "secure" 
                                for kw in stmt.keywords
                            )
                            if not has_secure:
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="TORNADO002",
                                        file_path=self.file_path,
                                        line_number=stmt.lineno,
                                        column=stmt.col_offset,
                                        severity=RuleSeverity.MEDIUM,
                                        category=RuleCategory.SECURITY,
                                        message="Cookie set without 'secure' flag - vulnerable to interception over HTTP",
                                        fix_suggestion="Add 'secure=True' parameter to set_cookie() to ensure cookies are only sent over HTTPS. "
                                                      "Also consider httponly=True to prevent JavaScript access.",
                                        cwe_id="CWE-614",
                                        owasp_id="A05:2021 - Security Misconfiguration",
                                        fix_applicability=FixApplicability.SAFE,
                                    )
                                )

    def _check_cookie_secret(self, node: ast.ClassDef) -> None:
        """TORNADO003: Detect weak cookie secret generation."""
        for item in ast.walk(node):
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id == "cookie_secret":
                        # Check if it's a hardcoded weak secret
                        if isinstance(item.value, ast.Constant):
                            secret_value = str(item.value.value)
                            if len(secret_value) < 32:
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="TORNADO003",
                                        file_path=self.file_path,
                                        line_number=item.lineno,
                                        column=item.col_offset,
                                        severity=RuleSeverity.CRITICAL,
                                        category=RuleCategory.SECURITY,
                                        message="Weak cookie secret - must be at least 32 characters of random data",
                                        fix_suggestion="Generate a strong random secret: import os; cookie_secret = os.urandom(32). "
                                                      "Store in environment variable, not in code.",
                                        cwe_id="CWE-326",
                                        owasp_id="A02:2021 - Cryptographic Failures",
                                        fix_applicability=FixApplicability.MANUAL,
                                    )
                                )

    def _check_auth_override(self, node: ast.ClassDef) -> None:
        """TORNADO004: Detect authentication override issues."""
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "prepare":
                # Check if prepare() method exists but doesn't call super()
                has_super_call = False
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        if (isinstance(stmt.func, ast.Attribute) and 
                            stmt.func.attr == "prepare" and
                            isinstance(stmt.func.value, ast.Call) and
                            isinstance(stmt.func.value.func, ast.Name) and
                            stmt.func.value.func.id == "super"):
                            has_super_call = True
                            break
                
                if not has_super_call and len(item.body) > 0:
                    self.violations.append(
                        RuleViolation(
                            rule_id="TORNADO004",
                            file_path=self.file_path,
                            line_number=item.lineno,
                            column=item.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            message="prepare() override without calling super().prepare() - may bypass authentication",
                            fix_suggestion="Add super().prepare() call to ensure parent authentication logic is executed",
                            cwe_id="CWE-287",
                            owasp_id="A07:2021 - Identification and Authentication Failures",
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

    def _check_template_autoescape(self, node: ast.ClassDef) -> None:
        """TORNADO005: Detect template auto-escape disabled."""
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                if (isinstance(item.func, ast.Attribute) and 
                    item.func.attr == "render"):
                    # Check for autoescape parameter
                    for kw in item.keywords:
                        if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant):
                            if kw.value.value is False or kw.value.value == "None":
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="TORNADO005",
                                        file_path=self.file_path,
                                        line_number=item.lineno,
                                        column=item.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        message="Template auto-escape disabled - vulnerable to XSS attacks",
                                        fix_suggestion="Remove autoescape=None or set autoescape='xhtml_escape'. "
                                                      "Use {% raw %} blocks for specific content that should not be escaped.",
                                        cwe_id="CWE-79",
                                        owasp_id="A03:2021 - Injection",
                                        fix_applicability=FixApplicability.SAFE,
                                    )
                                )

    def _check_static_file_traversal(self, node: ast.ClassDef) -> None:
        """TORNADO006: Detect static file directory traversal risks."""
        # Check class-level configuration
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id == "static_path":
                        # Warn about serving static files from root or sensitive directories
                        if isinstance(item.value, ast.Constant):
                            path = str(item.value.value)
                            if path in ["/", ".", ".."]:
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="TORNADO006",
                                        file_path=self.file_path,
                                        line_number=item.lineno,
                                        column=item.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        message="StaticFileHandler serving from root or parent directory - directory traversal risk",
                                        fix_suggestion="Use a specific subdirectory for static files (e.g., './static' or './public'). "
                                                      "Never serve from '/', '.', or '..'",
                                        cwe_id="CWE-22",
                                        owasp_id="A01:2021 - Broken Access Control",
                                        fix_applicability=FixApplicability.MANUAL,
                                    )
                                )

    def _check_input_sanitization(self, node: ast.ClassDef) -> None:
        """TORNADO007: Detect missing input sanitization."""
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        if (isinstance(stmt.func, ast.Attribute) and 
                            stmt.func.attr in ("get_argument", "get_arguments", "get_body_argument")):
                            # Check if the result is used directly in SQL or template
                            # This is a simplified check - full implementation would track data flow
                            line_num = stmt.lineno
                            if line_num < len(self.lines):
                                line = self.lines[line_num - 1]
                                if "execute(" in line or "query(" in line or "render(" in line:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="TORNADO007",
                                            file_path=self.file_path,
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.MEDIUM,
                                            category=RuleCategory.SECURITY,
                                            message="User input from get_argument() used without sanitization - potential injection",
                                            fix_suggestion="Sanitize user input before use. Use parameterized queries for SQL, "
                                                          "escape HTML for templates, and validate input format.",
                                            cwe_id="CWE-20",
                                            owasp_id="A03:2021 - Injection",
                                            fix_applicability=FixApplicability.MANUAL,
                                        )
                                    )

    def _check_redirect_security(self, node: ast.ClassDef) -> None:
        """TORNADO008: Detect insecure redirect handling."""
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        if (isinstance(stmt.func, ast.Attribute) and 
                            stmt.func.attr == "redirect"):
                            # Check if redirect URL comes from user input without validation
                            for arg in stmt.args:
                                if isinstance(arg, ast.Call):
                                    if (isinstance(arg.func, ast.Attribute) and 
                                        arg.func.attr in ("get_argument", "get_query_argument")):
                                        self.violations.append(
                                            RuleViolation(
                                                rule_id="TORNADO008",
                                                file_path=self.file_path,
                                                line_number=stmt.lineno,
                                                column=stmt.col_offset,
                                                severity=RuleSeverity.MEDIUM,
                                                category=RuleCategory.SECURITY,
                                                message="Redirect to user-controlled URL without validation - open redirect vulnerability",
                                                fix_suggestion="Validate redirect URLs against a whitelist. Use url_for() or check against allowed domains. "
                                                              "Never redirect directly to user input.",
                                                cwe_id="CWE-601",
                                                owasp_id="A01:2021 - Broken Access Control",
                                                fix_applicability=FixApplicability.MANUAL,
                                            )
                                        )

    def _check_exception_disclosure(self, node: ast.ClassDef) -> None:
        """TORNADO009: Detect improper exception disclosure."""
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "write_error":
                # Check if write_error() includes exception details
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        if isinstance(stmt.func, ast.Attribute) and stmt.func.attr == "write":
                            # Check for exception info being written
                            for arg in stmt.args:
                                if isinstance(arg, ast.Dict):
                                    for key in arg.keys:
                                        if isinstance(key, ast.Constant) and key.value in ("exception", "traceback", "exc_info"):
                                            self.violations.append(
                                                RuleViolation(
                                                    rule_id="TORNADO009",
                                                    file_path=self.file_path,
                                                    line_number=stmt.lineno,
                                                    column=stmt.col_offset,
                                                    severity=RuleSeverity.MEDIUM,
                                                    category=RuleCategory.SECURITY,
                                                    message="Exception details exposed in error response - information disclosure",
                                                    fix_suggestion="Only show generic error messages to users. Log detailed exception info server-side. "
                                                                  "Use settings.debug to conditionally show details in development only.",
                                                    cwe_id="CWE-209",
                                                    owasp_id="A04:2021 - Insecure Design",
                                                    fix_applicability=FixApplicability.MANUAL,
                                                )
                                            )

    def _check_hsts_configuration(self, node: ast.ClassDef) -> None:
        """TORNADO010: Detect missing HSTS configuration."""
        has_hsts_header = False
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        if (isinstance(stmt.func, ast.Attribute) and 
                            stmt.func.attr == "set_header"):
                            # Check for HSTS header
                            if stmt.args and isinstance(stmt.args[0], ast.Constant):
                                if "Strict-Transport-Security" in str(stmt.args[0].value):
                                    has_hsts_header = True
                                    break
        
        # If no HSTS header found in handler, flag it
        if not has_hsts_header:
            self.violations.append(
                RuleViolation(
                    rule_id="TORNADO010",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.LOW,
                    category=RuleCategory.SECURITY,
                    message="Missing HSTS (Strict-Transport-Security) header - connections vulnerable to downgrade attacks",
                    fix_suggestion="Add set_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains') "
                                  "to enforce HTTPS connections. Consider adding in prepare() or set_default_headers().",
                    cwe_id="CWE-319",
                    owasp_id="A05:2021 - Security Misconfiguration",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_websocket_origin_validation(self, node: ast.ClassDef) -> None:
        """TORNADO011: Detect WebSocket origin validation missing."""
        has_check_origin = False
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "check_origin":
                has_check_origin = True
                # Check if it always returns True (disabling validation)
                for stmt in item.body:
                    if isinstance(stmt, ast.Return):
                        if isinstance(stmt.value, ast.Constant) and stmt.value.value is True:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="TORNADO011",
                                    file_path=self.file_path,
                                    line_number=item.lineno,
                                    column=item.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    message="WebSocket origin validation disabled - allows connections from any domain",
                                    fix_suggestion="Implement proper origin validation in check_origin(). Compare origin against whitelist. "
                                                  "Never return True unconditionally.",
                                    cwe_id="CWE-346",
                                    owasp_id="A05:2021 - Security Misconfiguration",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )
        
        if not has_check_origin:
            self.violations.append(
                RuleViolation(
                    rule_id="TORNADO011",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message="WebSocket handler missing check_origin() method - no origin validation",
                    fix_suggestion="Implement check_origin(self, origin) to validate WebSocket connection origins. "
                                  "Return True only for trusted domains.",
                    cwe_id="CWE-346",
                    owasp_id="A05:2021 - Security Misconfiguration",
                    fix_applicability=FixApplicability.MANUAL,
                )
            )

    def _check_session_fixation(self, node: ast.ClassDef) -> None:
        """TORNADO012: Detect session fixation in async context."""
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check for session ID being accepted from user without regeneration
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        if (isinstance(stmt.func, ast.Attribute) and 
                            stmt.func.attr == "get_secure_cookie"):
                            # Look for session ID usage without regeneration after auth
                            line_num = stmt.lineno
                            if line_num < len(self.lines):
                                line = self.lines[line_num - 1]
                                if "session" in line.lower() or "user_id" in line.lower():
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="TORNADO012",
                                            file_path=self.file_path,
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.MEDIUM,
                                            category=RuleCategory.SECURITY,
                                            message="Potential session fixation - session ID used without regeneration after authentication",
                                            fix_suggestion="Regenerate session ID after successful authentication using set_secure_cookie() with new value. "
                                                          "Never accept session IDs from user input.",
                                            cwe_id="CWE-384",
                                            owasp_id="A07:2021 - Identification and Authentication Failures",
                                            fix_applicability=FixApplicability.MANUAL,
                                        )
                                    )

    def _check_async_query_injection(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """TORNADO013: Detect async database query injection."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                # Check for SQL execution with string formatting
                if isinstance(stmt.func, ast.Attribute) and stmt.func.attr in ("execute", "query"):
                    for arg in stmt.args:
                        # Check for f-strings or string concatenation
                        if isinstance(arg, ast.JoinedStr) or isinstance(arg, ast.BinOp):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="TORNADO013",
                                    file_path=self.file_path,
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    message="Async SQL query uses string formatting - vulnerable to SQL injection",
                                    fix_suggestion="Use parameterized queries with placeholders. For Motor (MongoDB): use dict parameters. "
                                                  "For databases: cursor.execute(query, params) with %s placeholders.",
                                    cwe_id="CWE-89",
                                    owasp_id="A03:2021 - Injection",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

    def _check_blocking_operations(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """TORNADO014: Detect IOLoop blocking operations."""
        if isinstance(node, ast.AsyncFunctionDef):
            # Check for blocking calls in async functions
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    # Common blocking operations
                    blocking_funcs = ["sleep", "read", "write", "open", "input", "urlopen"]
                    if isinstance(stmt.func, ast.Name) and stmt.func.id in blocking_funcs:
                        # Check if it's not awaited
                        parent = getattr(stmt, '_parent', None)
                        if not isinstance(parent, ast.Await):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="TORNADO014",
                                    file_path=self.file_path,
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.PERFORMANCE,
                                    message=f"Blocking operation '{stmt.func.id}' in async handler - blocks IOLoop",
                                    fix_suggestion="Use async equivalent (e.g., asyncio.sleep(), async file I/O). "
                                                  "Or wrap blocking calls with run_in_executor() to run in thread pool.",
                                    cwe_id="CWE-400",
                                    owasp_id="A04:2021 - Insecure Design",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

    def _check_race_conditions(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """TORNADO015: Detect concurrent request race conditions."""
        # Check for non-atomic operations on shared state
        if isinstance(node, ast.AsyncFunctionDef):
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                            if target.value.id == "self":
                                # Check if there's an await between read and write
                                # This is a simplified check - detected race condition
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="TORNADO015",
                                        file_path=self.file_path,
                                        line_number=stmt.lineno,
                                        column=stmt.col_offset,
                                        severity=RuleSeverity.MEDIUM,
                                        category=RuleCategory.SECURITY,
                                        message="Potential race condition - shared state modified in async handler",
                                        fix_suggestion="Use locks (tornado.locks.Lock) to protect shared state. "
                                                      "Or use atomic operations. Consider request-scoped state instead of instance variables.",
                                        cwe_id="CWE-362",
                                        owasp_id="A04:2021 - Insecure Design",
                                        fix_applicability=FixApplicability.MANUAL,
                                    )
                                )
                                break

    def _check_http_client_security(self, node: ast.Call) -> None:
        """TORNADO016: Detect insecure HTTP client usage."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("fetch", "AsyncHTTPClient"):
                # Check for user-controlled URLs
                for arg in node.args:
                    if isinstance(arg, ast.Call):
                        if (isinstance(arg.func, ast.Attribute) and 
                            arg.func.attr in ("get_argument", "get_query_argument")):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="TORNADO016",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    message="HTTP client fetching user-controlled URL - SSRF vulnerability",
                                    fix_suggestion="Validate and whitelist URLs before fetching. Never fetch URLs directly from user input. "
                                                  "Use URL parsing and check against allowed domains/protocols.",
                                    cwe_id="CWE-918",
                                    owasp_id="A10:2021 - Server-Side Request Forgery",
                                    fix_applicability=FixApplicability.MANUAL,
                                )
                            )

    def _check_tls_verification(self, node: ast.Call) -> None:
        """TORNADO017: Detect missing TLS/SSL verification."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "fetch" or node.func.attr == "AsyncHTTPClient":
                # Check for validate_cert=False
                for kw in node.keywords:
                    if kw.arg == "validate_cert" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is False:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="TORNADO017",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    message="TLS certificate validation disabled - vulnerable to man-in-the-middle attacks",
                                    fix_suggestion="Remove validate_cert=False. Always verify SSL certificates in production. "
                                                  "Use proper certificates or custom CA bundle if needed.",
                                    cwe_id="CWE-295",
                                    owasp_id="A02:2021 - Cryptographic Failures",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )

    def _check_template_injection(self, node: ast.Call) -> None:
        """TORNADO018: Detect template injection in async handlers."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "Template":
            # Check if template string comes from user input
            for arg in node.args:
                if isinstance(arg, ast.Call):
                    if (isinstance(arg.func, ast.Attribute) and 
                        arg.func.attr in ("get_argument", "get_query_argument", "get_body_argument")):
                        self.violations.append(
                            RuleViolation(
                                rule_id="TORNADO018",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                message="Template created from user input - Server-Side Template Injection (SSTI)",
                                fix_suggestion="Never create templates from user input. Use predefined templates with variables. "
                                              "Load templates from file system using template loader.",
                                cwe_id="CWE-94",
                                owasp_id="A03:2021 - Injection",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                        )

    def _check_authentication_decorator_bypass(self, node: ast.ClassDef) -> None:
        """TORNADO019: Detect authentication decorator bypasses."""
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if handler method has tornado.web.authenticated decorator
                _ = any(
                    isinstance(dec, ast.Name) and dec.id == "authenticated"
                    for dec in item.decorator_list
                ) or any(
                    isinstance(dec, ast.Attribute) and dec.attr == "authenticated"
                    for dec in item.decorator_list
                )
                
                # If method is prepare/get_current_user, check for bypass patterns
                if item.name in ("prepare", "get_current_user"):
                    # Check for always returning True/None without validation
                    for stmt in item.body:
                        if isinstance(stmt, ast.Return):
                            if isinstance(stmt.value, ast.Constant):
                                if stmt.value.value is True or stmt.value.value is None:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="TORNADO019",
                                            file_path=self.file_path,
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            message=f"{item.name}() returns constant value - authentication bypass",
                                            fix_suggestion="Implement proper authentication logic. get_current_user() should validate "
                                                          "session/token and return user object or None. Never return True/None unconditionally.",
                                            cwe_id="CWE-287",
                                            owasp_id="A07:2021 - Identification and Authentication Failures",
                                            fix_applicability=FixApplicability.MANUAL,
                                        )
                                    )

    def _check_cookie_manipulation(self, node: ast.ClassDef) -> None:
        """TORNADO020: Detect cookie manipulation vulnerabilities."""
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Call):
                        # Check for set_cookie without httponly flag
                        if (isinstance(stmt.func, ast.Attribute) and 
                            stmt.func.attr == "set_cookie"):
                            has_httponly = any(
                                kw.arg == "httponly" 
                                for kw in stmt.keywords
                            )
                            if not has_httponly:
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="TORNADO020",
                                        file_path=self.file_path,
                                        line_number=stmt.lineno,
                                        column=stmt.col_offset,
                                        severity=RuleSeverity.MEDIUM,
                                        category=RuleCategory.SECURITY,
                                        message="Cookie set without 'httponly' flag - vulnerable to JavaScript access/XSS",
                                        fix_suggestion="Add 'httponly=True' parameter to set_cookie() to prevent JavaScript access. "
                                                      "This protects against XSS-based cookie theft.",
                                        cwe_id="CWE-1004",
                                        owasp_id="A05:2021 - Security Misconfiguration",
                                        fix_applicability=FixApplicability.SAFE,
                                    )
                                )


def analyze_tornado_security(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Analyze Python code for Tornado security vulnerabilities.
    
    Args:
        file_path: Path to the file being analyzed
        code: Source code content
        
    Returns:
        List of rule violations found
    """
    violations: List[RuleViolation] = []
    
    try:
        tree = ast.parse(code)
        visitor = TornadoSecurityVisitor(file_path, code)
        visitor.visit(tree)
        violations.extend(visitor.violations)
    except SyntaxError:
        pass
    
    return violations


# Define rules for registration
TORNADO_RULES = [
    Rule(
        rule_id="TORNADO001",
        name="tornado-xsrf-disabled",
        message_template="XSRF protection disabled in RequestHandler",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects XSRF protection being disabled in Tornado RequestHandler",
        explanation="Disabling XSRF protection makes the application vulnerable to Cross-Site Request Forgery attacks",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A01:2021 - Broken Access Control",
        cwe_mapping="CWE-352",
    ),
    Rule(
        rule_id="TORNADO002",
        name="tornado-cookie-no-secure-flag",
        message_template="Cookie set without secure flag",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects cookies set without the secure flag",
        explanation="Cookies without secure flag can be intercepted over HTTP connections",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A05:2021 - Security Misconfiguration",
        cwe_mapping="CWE-614",
    ),
    Rule(
        rule_id="TORNADO003",
        name="tornado-weak-cookie-secret",
        message_template="Weak cookie secret detected",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects weak or hardcoded cookie secrets",
        explanation="Weak cookie secrets can be cracked, allowing session hijacking",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A02:2021 - Cryptographic Failures",
        cwe_mapping="CWE-326",
    ),
    Rule(
        rule_id="TORNADO004",
        name="tornado-auth-override",
        message_template="prepare() override without calling super()",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects prepare() method overrides that may bypass authentication",
        explanation="Overriding prepare() without calling super() can bypass parent authentication logic",
        fix_applicability=FixApplicability.SUGGESTED,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-287",
    ),
    Rule(
        rule_id="TORNADO005",
        name="tornado-autoescape-disabled",
        message_template="Template auto-escape disabled",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects template auto-escape being disabled",
        explanation="Disabling auto-escape makes templates vulnerable to XSS attacks",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-79",
    ),
    Rule(
        rule_id="TORNADO006",
        name="tornado-static-file-traversal",
        message_template="Static file handler directory traversal risk",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects StaticFileHandler serving from root or sensitive directories",
        explanation="Serving static files from root directory allows directory traversal attacks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A01:2021 - Broken Access Control",
        cwe_mapping="CWE-22",
    ),
    Rule(
        rule_id="TORNADO007",
        name="tornado-missing-input-sanitization",
        message_template="User input used without sanitization",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects user input from get_argument() used without sanitization",
        explanation="Using unsanitized user input can lead to injection attacks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-20",
    ),
    Rule(
        rule_id="TORNADO008",
        name="tornado-open-redirect",
        message_template="Open redirect vulnerability",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects redirect to user-controlled URL without validation",
        explanation="Redirecting to unvalidated URLs enables phishing attacks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A01:2021 - Broken Access Control",
        cwe_mapping="CWE-601",
    ),
    Rule(
        rule_id="TORNADO009",
        name="tornado-exception-disclosure",
        message_template="Exception details exposed in error response",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects exception details being exposed to users",
        explanation="Exposing exception details can leak sensitive system information",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-209",
    ),
    Rule(
        rule_id="TORNADO010",
        name="tornado-missing-hsts",
        message_template="Missing HSTS header",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects missing HSTS (Strict-Transport-Security) header",
        explanation="Without HSTS, connections are vulnerable to downgrade attacks",
        fix_applicability=FixApplicability.SUGGESTED,
        owasp_mapping="A05:2021 - Security Misconfiguration",
        cwe_mapping="CWE-319",
    ),
    Rule(
        rule_id="TORNADO011",
        name="tornado-websocket-origin-validation",
        message_template="WebSocket origin validation missing or disabled",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects WebSocket handlers without proper origin validation",
        explanation="Missing origin validation allows WebSocket connections from any domain",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A05:2021 - Security Misconfiguration",
        cwe_mapping="CWE-346",
    ),
    Rule(
        rule_id="TORNADO012",
        name="tornado-session-fixation",
        message_template="Potential session fixation vulnerability",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects session ID usage without regeneration after authentication",
        explanation="Not regenerating session IDs after authentication enables session fixation attacks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-384",
    ),
    Rule(
        rule_id="TORNADO013",
        name="tornado-async-sql-injection",
        message_template="Async SQL query uses string formatting",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects SQL queries using string formatting in async handlers",
        explanation="String formatting in SQL queries enables SQL injection attacks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-89",
    ),
    Rule(
        rule_id="TORNADO014",
        name="tornado-blocking-operation",
        message_template="Blocking operation in async handler",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.PERFORMANCE,
        description="Detects blocking operations in async handlers that block the IOLoop",
        explanation="Blocking the IOLoop degrades performance and can cause denial of service",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-400",
    ),
    Rule(
        rule_id="TORNADO015",
        name="tornado-race-condition",
        message_template="Potential race condition in async handler",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects potential race conditions from shared state in async handlers",
        explanation="Race conditions in concurrent handlers can lead to data corruption or security bypasses",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-362",
    ),
    Rule(
        rule_id="TORNADO016",
        name="tornado-ssrf",
        message_template="HTTP client fetching user-controlled URL",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects HTTP requests to user-controlled URLs (SSRF)",
        explanation="Fetching user-controlled URLs enables Server-Side Request Forgery attacks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A10:2021 - Server-Side Request Forgery",
        cwe_mapping="CWE-918",
    ),
    Rule(
        rule_id="TORNADO017",
        name="tornado-tls-verification-disabled",
        message_template="TLS certificate validation disabled",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects TLS certificate validation being disabled",
        explanation="Disabling TLS verification enables man-in-the-middle attacks",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A02:2021 - Cryptographic Failures",
        cwe_mapping="CWE-295",
    ),
    Rule(
        rule_id="TORNADO018",
        name="tornado-template-injection",
        message_template="Template created from user input (SSTI)",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects templates being created from user input",
        explanation="Creating templates from user input enables Server-Side Template Injection",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-94",
    ),
    Rule(
        rule_id="TORNADO019",
        name="tornado-auth-bypass",
        message_template="Authentication decorator bypass detected",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects authentication methods returning constant values",
        explanation="Authentication methods that always return True or None bypass security",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-287",
    ),
    Rule(
        rule_id="TORNADO020",
        name="tornado-cookie-no-httponly",
        message_template="Cookie set without httponly flag",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects cookies set without the httponly flag",
        explanation="Cookies without httponly flag can be accessed by JavaScript, enabling XSS-based cookie theft",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A05:2021 - Security Misconfiguration",
        cwe_mapping="CWE-1004",
    ),
]

# Register rules
register_rules(TORNADO_RULES)
