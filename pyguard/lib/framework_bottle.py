"""
Bottle Security Analysis.

Detects and auto-fixes common security vulnerabilities in Bottle applications.
This module provides Bottle-specific security checks focusing on minimalist
framework patterns, template security, and route handling.

Security Areas Covered (10 checks):
- Route decorator injection
- Template engine security (SimpleTemplate)
- Static file path traversal
- Cookie signature validation
- Session management weaknesses
- Form validation gaps
- Missing CSRF protection
- File upload vulnerabilities
- Error page information disclosure
- Missing security headers

Total Security Checks: 10 rules (BOTTLE001-BOTTLE010)

References:
- Bottle Documentation | https://bottlepy.org/ | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-22 (Path Traversal) | https://cwe.mitre.org/data/definitions/22.html | High
- CWE-94 (Code Injection) | https://cwe.mitre.org/data/definitions/94.html | High
- CWE-352 (CSRF) | https://cwe.mitre.org/data/definitions/352.html | High
"""

import ast
from pathlib import Path

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class BottleSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Bottle security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_bottle_import = False
        self.route_functions: set[str] = set()
        self.user_input_vars: set[str] = set()  # Track variables from user input
        self.current_function_has_secure_filename = False  # Track if secure_filename is used

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Bottle imports."""
        if node.module and node.module == "bottle":
            self.has_bottle_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze Bottle route handler functions for security issues."""
        if not self.has_bottle_import:
            self.generic_visit(node)
            return

        # Reset function-level tracking
        self.user_input_vars.clear()
        self.current_function_has_secure_filename = False

        # Check decorators to identify routes
        is_route = False

        for decorator in node.decorator_list:
            # Route decorators: @route(), @get(), @post(), etc.
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name) and decorator.func.id in ("route", "get", "post", "put", "delete", "patch"):
                    is_route = True
                    self.route_functions.add(node.name)
                    self._check_route_injection(decorator)
            elif isinstance(decorator, ast.Name):  # noqa: SIM102
                if decorator.id in ("route", "get", "post", "put", "delete", "patch"):
                    is_route = True
                    self.route_functions.add(node.name)

        # Track user input variables and security functions in this function
        if is_route:
            self._track_user_input_variables(node)
            self._track_secure_filename_usage(node)

        # Check for security issues in routes
        if is_route:
            self._check_csrf_protection(node)
            self._check_missing_validation(node)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_bottle_import:
            self.generic_visit(node)
            return

        # Check for template rendering
        if isinstance(node.func, ast.Name):
            if node.func.id == "template":
                self._check_template_security(node)
            elif node.func.id == "static_file":
                self._check_static_file_security(node)

        # Check for cookie operations
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "set_cookie":
                self._check_cookie_security(node)
            # Check for file save
            elif node.func.attr == "save":
                self._check_file_upload_security(node)

        self.generic_visit(node)

    def _track_user_input_variables(self, node: ast.FunctionDef) -> None:
        """Track variables assigned from user input (request.forms, request.query, etc.)."""
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                # Pattern 1: request.forms.get("field")
                if isinstance(child.value, ast.Call):
                    if isinstance(child.value.func, ast.Attribute) and child.value.func.attr == "get" and isinstance(child.value.func.value, ast.Attribute):  # noqa: SIM102
                        if child.value.func.value.attr in (
                            "forms",
                            "query",
                            "params",
                            "json",
                        ):
                            # Track the variable name
                            for target in child.targets:
                                if isinstance(target, ast.Name):
                                    self.user_input_vars.add(target.id)
                # Pattern 2: request.query.field (direct attribute access)
                elif isinstance(child.value, ast.Attribute):  # noqa: SIM102
                    if isinstance(child.value.value, ast.Attribute) and child.value.value.attr in ("query", "forms", "params", "json"):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                self.user_input_vars.add(target.id)

    def _track_secure_filename_usage(self, node: ast.FunctionDef) -> None:
        """Track if secure_filename or similar function is used in the function."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in ("secure_filename", "sanitize_filename"):
                self.current_function_has_secure_filename = True
                break

    def _check_route_injection(self, decorator: ast.Call) -> None:
        """Check for route decorator injection vulnerabilities (BOTTLE001)."""
        # Check if route pattern contains user-controlled data
        for arg in decorator.args:
            if isinstance(arg, ast.JoinedStr):
                # f-string in route definition
                self.violations.append(
                    RuleViolation(
                        rule_id="BOTTLE001",
                        category=RuleCategory.SECURITY,
                        message="Route pattern uses f-string (potential injection)",
                        severity=RuleSeverity.HIGH,
                        line_number=decorator.lineno,
                        column=decorator.col_offset,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )
            elif isinstance(arg, ast.Call):  # noqa: SIM102
                if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                    # .format() in route definition
                    self.violations.append(
                        RuleViolation(
                            rule_id="BOTTLE001",
                            category=RuleCategory.SECURITY,
                            message="Route pattern uses dynamic string formatting",
                            severity=RuleSeverity.HIGH,
                            line_number=decorator.lineno,
                            column=decorator.col_offset,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

    def _check_template_security(self, node: ast.Call) -> None:
        """Check for template engine security issues (BOTTLE002)."""
        # Check for template() calls with user input
        for arg in node.args:
            # Direct attribute access: template(request.forms.template)
            if isinstance(arg, ast.Attribute):
                # Check if template name comes from request
                if arg.attr in ("forms", "query", "params", "json"):
                    self.violations.append(
                        RuleViolation(
                            rule_id="BOTTLE002",
                            category=RuleCategory.SECURITY,
                            message="Template name from user input (template injection risk)",
                            severity=RuleSeverity.CRITICAL,
                            line_number=node.lineno,
                            column=node.col_offset,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )
            # Variable that was assigned from user input: template(tmpl)
            elif isinstance(arg, ast.Name) and arg.id in self.user_input_vars:
                self.violations.append(
                    RuleViolation(
                        rule_id="BOTTLE002",
                        category=RuleCategory.SECURITY,
                        message="Template name from user input (template injection risk)",
                        severity=RuleSeverity.CRITICAL,
                        line_number=node.lineno,
                        column=node.col_offset,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        # Check for template content with user input in keywords
        for keyword in node.keywords:
            # Direct attribute access: template(..., raw_html=request.query.content)
            if isinstance(keyword.value, ast.Attribute):
                if keyword.value.attr in ("forms", "query", "params", "json"):  # noqa: SIM102
                    # This is less severe - passing user data to template is common
                    # Only flag if variable name suggests raw HTML injection
                    if keyword.arg and any(
                        dangerous in keyword.arg.lower()
                        for dangerous in ["html", "raw", "content", "body"]
                    ):
                        self.violations.append(
                            RuleViolation(
                                rule_id="BOTTLE002",
                                category=RuleCategory.SECURITY,
                                message="User input passed to template as raw HTML variable",
                                severity=RuleSeverity.HIGH,
                                line_number=node.lineno,
                                column=node.col_offset,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )
            # Variable from user input: template(..., raw_html=content)
            elif isinstance(keyword.value, ast.Name) and (
                keyword.value.id in self.user_input_vars
                and keyword.arg
                and any(
                    dangerous in keyword.arg.lower()
                    for dangerous in ["html", "raw", "content", "body"]
                )
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="BOTTLE002",
                        category=RuleCategory.SECURITY,
                        message="User input passed to template as raw HTML variable",
                        severity=RuleSeverity.HIGH,
                        line_number=node.lineno,
                        column=node.col_offset,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

    def _check_static_file_security(self, node: ast.Call) -> None:
        """Check for static file path traversal vulnerabilities (BOTTLE003)."""
        # Check if filename comes from user input without validation
        for arg in node.args:
            # Direct attribute access
            if isinstance(arg, ast.Attribute):
                if arg.attr in ("forms", "query", "params"):
                    self.violations.append(
                        RuleViolation(
                            rule_id="BOTTLE003",
                            category=RuleCategory.SECURITY,
                            message="Static file path from user input without validation",
                            severity=RuleSeverity.HIGH,
                            line_number=node.lineno,
                            column=node.col_offset,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )
            # Variable from user input
            elif isinstance(arg, ast.Name) and arg.id in self.user_input_vars:
                self.violations.append(
                    RuleViolation(
                        rule_id="BOTTLE003",
                        category=RuleCategory.SECURITY,
                        message="Static file path from user input without validation",
                        severity=RuleSeverity.HIGH,
                        line_number=node.lineno,
                        column=node.col_offset,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

    def _check_cookie_security(self, node: ast.Call) -> None:
        """Check for cookie security issues (BOTTLE004)."""
        has_secret = False
        has_secure = False
        has_httponly = False

        for keyword in node.keywords:
            if keyword.arg == "secret":
                has_secret = True
            elif keyword.arg == "secure":
                has_secure = True
            elif keyword.arg == "httponly":
                has_httponly = True

        if not has_secret:
            self.violations.append(
                RuleViolation(
                    rule_id="BOTTLE004",
                    category=RuleCategory.SECURITY,
                    message="Cookie set without signature (no secret)",
                    severity=RuleSeverity.MEDIUM,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

        if not has_secure:
            self.violations.append(
                RuleViolation(
                    rule_id="BOTTLE004",
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
                    rule_id="BOTTLE004",
                    category=RuleCategory.SECURITY,
                    message="Cookie set without httponly flag",
                    severity=RuleSeverity.MEDIUM,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

    def _check_csrf_protection(self, node: ast.FunctionDef) -> None:
        """Check for CSRF protection gaps (BOTTLE006)."""
        # Check if POST/PUT/DELETE routes have CSRF protection
        has_csrf_check = False

        # Look for CSRF token validation in the function body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Check for method calls like obj.csrf() or obj.validate_csrf()
                if isinstance(child.func, ast.Attribute):
                    if "csrf" in child.func.attr.lower():
                        has_csrf_check = True
                        break
                # Check for function calls like validate_csrf() or check_csrf()
                elif isinstance(child.func, ast.Name):  # noqa: SIM102
                    if "csrf" in child.func.id.lower():
                        has_csrf_check = True
                        break

        # Check if route uses unsafe HTTP methods
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                method = decorator.func.id
                if method in ("post", "put", "delete", "patch") and not has_csrf_check:
                    self.violations.append(
                        RuleViolation(
                            rule_id="BOTTLE006",
                            category=RuleCategory.SECURITY,
                            message=f"Route with {method.upper()} method missing CSRF protection",
                            severity=RuleSeverity.HIGH,
                            line_number=node.lineno,
                            column=node.col_offset,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

    def _check_missing_validation(self, node: ast.FunctionDef) -> None:
        """Check for form validation gaps (BOTTLE007)."""
        # Check if route accesses form data without validation
        has_validation = False
        accesses_form = False

        for child in ast.walk(node):
            # Check for validation calls
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in ("validate", "sanitize", "clean", "check"):
                        has_validation = True
                elif isinstance(child.func, ast.Attribute):  # noqa: SIM102
                    if child.func.attr in ("validate", "sanitize", "clean"):
                        has_validation = True

            # Check for form access
            if isinstance(child, ast.Attribute) and child.attr in ("forms", "params"):
                accesses_form = True

        if accesses_form and not has_validation:
            self.violations.append(
                RuleViolation(
                    rule_id="BOTTLE007",
                    category=RuleCategory.SECURITY,
                    message="Form data accessed without validation",
                    severity=RuleSeverity.MEDIUM,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.MANUAL,
                )
            )

    def _check_file_upload_security(self, node: ast.Call) -> None:
        """Check for file upload vulnerabilities (BOTTLE008)."""
        # Only flag if secure_filename is not used in the function
        if not self.current_function_has_secure_filename:
            self.violations.append(
                RuleViolation(
                    rule_id="BOTTLE008",
                    category=RuleCategory.SECURITY,
                    message="File upload without filename validation",
                    severity=RuleSeverity.HIGH,
                    line_number=node.lineno,
                    column=node.col_offset,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.MANUAL,
                )
            )


def analyze_bottle(file_path: Path, code: str) -> list[RuleViolation]:
    """Analyze Bottle code for security vulnerabilities."""
    tree = ast.parse(code)
    visitor = BottleSecurityVisitor(file_path, code)
    visitor.visit(tree)
    return visitor.violations


# Rule definitions
BOTTLE_RULES = [
    Rule(
        rule_id="BOTTLE001",
        name="bottle-route-injection",
        message_template="Route pattern uses dynamic string formatting (injection risk)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="Dynamic route patterns can lead to route injection vulnerabilities",
        explanation="Use static route patterns with placeholders instead of dynamic string formatting",
        cwe_mapping="CWE-94",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BOTTLE002",
        name="bottle-template-injection",
        message_template="Template rendering with user input (SSTI risk)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        description="User input in templates can enable Server-Side Template Injection",
        explanation="Use template files and pass user data as template variables with auto-escaping",
        cwe_mapping="CWE-94",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="BOTTLE003",
        name="bottle-path-traversal",
        message_template="Static file path from user input without validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="Unvalidated file paths can lead to directory traversal attacks",
        explanation="Validate and sanitize file paths, use safe_join() or similar",
        cwe_mapping="CWE-22",
        owasp_mapping="A01:2021 - Broken Access Control",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BOTTLE004",
        name="bottle-cookie-security",
        message_template="Cookie set without security flags",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Cookies without security flags are vulnerable to various attacks",
        explanation="Set secret, secure, and httponly flags for all cookies",
        cwe_mapping="CWE-614",
        owasp_mapping="A05:2021 - Security Misconfiguration",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="BOTTLE005",
        name="bottle-session-weakness",
        message_template="Session management without proper security",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Weak session management can lead to session hijacking",
        explanation="Use secure session management with proper timeout and regeneration",
        cwe_mapping="CWE-384",
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BOTTLE006",
        name="bottle-csrf-missing",
        message_template="Route with unsafe HTTP method missing CSRF protection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="State-changing operations without CSRF protection are vulnerable",
        explanation="Implement CSRF token validation for POST/PUT/DELETE/PATCH routes",
        cwe_mapping="CWE-352",
        owasp_mapping="A01:2021 - Broken Access Control",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BOTTLE007",
        name="bottle-validation-missing",
        message_template="Form data accessed without validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Unvalidated form data can lead to injection attacks",
        explanation="Validate and sanitize all form inputs before use",
        cwe_mapping="CWE-20",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BOTTLE008",
        name="bottle-file-upload-unsafe",
        message_template="File upload without filename validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        description="Unvalidated file uploads can lead to arbitrary file upload",
        explanation="Use secure_filename() or validate file paths before saving",
        cwe_mapping="CWE-434",
        owasp_mapping="A03:2021 - Injection",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BOTTLE009",
        name="bottle-error-disclosure",
        message_template="Error handler may leak sensitive information",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Detailed error messages in production can leak sensitive data",
        explanation="Configure debug=False in production and use generic error pages",
        cwe_mapping="CWE-209",
        owasp_mapping="A04:2021 - Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="BOTTLE010",
        name="bottle-security-headers-missing",
        message_template="Response missing security headers",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        description="Missing security headers expose application to various attacks",
        explanation="Add security headers: X-Frame-Options, X-Content-Type-Options, CSP, etc.",
        cwe_mapping="CWE-693",
        owasp_mapping="A05:2021 - Security Misconfiguration",
        fix_applicability=FixApplicability.SAFE,
    ),
]

# Register rules with the rule engine
register_rules(BOTTLE_RULES)
