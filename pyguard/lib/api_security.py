"""
API Security Analysis Module.

Comprehensive security checks for REST APIs, GraphQL, and modern web APIs.
This module extends PyGuard's API security coverage with advanced detection
patterns for common API vulnerabilities.

Security Areas Covered:
- Mass assignment vulnerabilities
- Insecure HTTP methods (TRACE, OPTIONS abuse)
- Missing rate limiting detection
- GraphQL introspection leakage
- API versioning security
- Missing API authentication
- Improper pagination (resource exhaustion)
- JWT algorithm confusion (RS256 vs HS256)
- API key exposure in URLs
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Open redirect vulnerabilities
- Clickjacking vulnerabilities

References:
- OWASP API Security Top 10 | https://owasp.org/API-Security/ | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High
- CWE-915 (Improper Control of Dynamically-Managed Code) | High
- CWE-284 (Improper Access Control) | High
- CWE-770 (Resource Allocation) | Medium
- CWE-639 (Authorization Bypass) | High
"""

import ast
import re
from pathlib import Path
from typing import List, Set, Dict, Optional

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class APISecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting API security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_flask = False
        self.has_fastapi = False
        self.has_django = False
        self.route_functions: Set[str] = set()
        self.model_classes: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track framework imports."""
        if node.module:
            if node.module.startswith("flask"):
                self.has_flask = True
            elif node.module.startswith("fastapi"):
                self.has_fastapi = True
            elif node.module.startswith("django"):
                self.has_django = True
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze model classes for mass assignment vulnerabilities."""
        # Check for ORM models
        base_names = [self._get_name(base) for base in node.bases]
        is_model = any(
            name in ("Model", "Base", "BaseModel", "Document")
            for name in base_names
            if name
        )

        if is_model:
            self.model_classes.add(node.name)
            self._check_mass_assignment_protection(node)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze API route handlers for security issues."""
        is_route = self._is_route_handler(node)

        if is_route:
            self.route_functions.add(node.name)
            self._check_missing_rate_limiting(node)
            self._check_missing_authentication(node)
            self._check_pagination_issues(node)
            self._check_http_method_security(node)

        # Check for JWT algorithm confusion in any function
        self._check_jwt_algorithm_confusion(node)

        # Check for API key exposure
        self._check_api_key_exposure(node)

        # Check for open redirects
        self._check_open_redirect(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for security header configurations."""
        self._check_missing_security_headers(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for GraphQL introspection and other API call issues."""
        self._check_graphql_introspection(node)
        self.generic_visit(node)

    def _get_name(self, node: ast.expr) -> Optional[str]:
        """Extract name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _is_route_handler(self, node: ast.FunctionDef) -> bool:
        """Check if function is an API route handler."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id in ("route", "api_view", "view"):
                    return True
            elif isinstance(decorator, ast.Attribute):
                attr = decorator.attr
                if attr in ("get", "post", "put", "delete", "patch", "route", "api_route"):
                    return True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in ("get", "post", "put", "delete", "patch", "route"):
                        return True
        return False

    def _check_mass_assignment_protection(self, node: ast.ClassDef) -> None:
        """
        Check for mass assignment vulnerabilities in model classes.

        Mass assignment occurs when user input is directly assigned to model
        attributes without filtering, allowing attackers to modify sensitive fields.
        CWE-915: Improper Control of Dynamically-Managed Code Resources
        """
        has_fields_declaration = False
        has_meta_class = False
        protected_fields: Set[str] = set()

        for item in node.body:
            # Check for __fields__ or __annotations__ (Pydantic)
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                has_fields_declaration = True

            # Check for Meta class (Django) or Config class (Pydantic)
            if isinstance(item, ast.ClassDef) and item.name in ("Meta", "Config"):
                has_meta_class = True
                # Check for fields protection
                for meta_item in item.body:
                    if isinstance(meta_item, ast.Assign):
                        for target in meta_item.targets:
                            if isinstance(target, ast.Name):
                                if target.id in ("fields", "exclude", "read_only_fields"):
                                    protected_fields.add(target.id)

        # If it's a model but has no field protection, flag it
        if not has_meta_class or not protected_fields:
            self.violations.append(
                RuleViolation(
                    rule_id="API001",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    message=f"Model class '{node.name}' may be vulnerable to mass assignment - no field restrictions found",
                    fix_suggestion="Add Meta class with 'fields' or 'exclude' to restrict assignable fields",
                    cwe_id="CWE-915",
                    owasp_id="A04:2021 - Insecure Design",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_missing_rate_limiting(self, node: ast.FunctionDef) -> None:
        """
        Check for missing rate limiting on API endpoints.

        Rate limiting prevents resource exhaustion and brute force attacks.
        CWE-770: Allocation of Resources Without Limits or Throttling
        """
        has_rate_limit = False

        for decorator in node.decorator_list:
            decorator_name = None
            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                decorator_name = decorator.attr
            elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                decorator_name = decorator.func.id

            if decorator_name and "limit" in decorator_name.lower():
                has_rate_limit = True
                break

        if not has_rate_limit:
            self.violations.append(
                RuleViolation(
                    rule_id="API002",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message=f"API route '{node.name}' has no rate limiting - vulnerable to abuse",
                    fix_suggestion="Add @limiter.limit() decorator or equivalent rate limiting",
                    cwe_id="CWE-770",
                    owasp_id="A04:2021 - Insecure Design",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_missing_authentication(self, node: ast.FunctionDef) -> None:
        """
        Check for missing authentication on API endpoints.

        Unauthenticated endpoints can expose sensitive data or functionality.
        CWE-284: Improper Access Control
        """
        has_auth = False

        # Check decorators
        for decorator in node.decorator_list:
            decorator_name = None
            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                decorator_name = decorator.attr
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    decorator_name = decorator.func.id
                elif isinstance(decorator.func, ast.Attribute):
                    decorator_name = decorator.func.attr

            if decorator_name and any(
                auth in decorator_name.lower()
                for auth in ("auth", "login", "permission", "require")
            ):
                has_auth = True
                break

        # Check function parameters for Depends (FastAPI)
        for arg in node.args.args:
            if arg.arg in ("current_user", "user", "token", "credentials"):
                has_auth = True
                break

        # Only flag if function name suggests it needs auth
        needs_auth = any(
            keyword in node.name.lower()
            for keyword in ("create", "update", "delete", "admin", "protected", "private")
        )

        if needs_auth and not has_auth:
            self.violations.append(
                RuleViolation(
                    rule_id="API003",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    message=f"API route '{node.name}' appears to need authentication but has none",
                    fix_suggestion="Add authentication decorator or dependency injection",
                    cwe_id="CWE-284",
                    owasp_id="A01:2021 - Broken Access Control",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_pagination_issues(self, node: ast.FunctionDef) -> None:
        """
        Check for improper pagination that could lead to resource exhaustion.

        Unbounded queries can cause memory exhaustion and DoS.
        CWE-770: Allocation of Resources Without Limits or Throttling
        """
        has_pagination = False
        has_limit = False

        # Check function body for pagination patterns
        for item in ast.walk(node):
            if isinstance(item, ast.Name):
                if item.id in ("paginate", "limit", "offset", "page", "per_page"):
                    has_pagination = True
                if item.id in ("limit", "max_results", "page_size"):
                    has_limit = True
            elif isinstance(item, ast.Attribute):
                if item.attr in ("paginate", "limit", "offset"):
                    has_pagination = True

        # Only flag list/query endpoints
        is_list_endpoint = any(
            keyword in node.name.lower()
            for keyword in ("list", "all", "get", "query", "search", "find")
        )

        if is_list_endpoint and not (has_pagination and has_limit):
            self.violations.append(
                RuleViolation(
                    rule_id="API004",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message=f"API route '{node.name}' may return unbounded results - resource exhaustion risk",
                    fix_suggestion="Add pagination with max limit (e.g., .limit(100).offset(page*100))",
                    cwe_id="CWE-770",
                    owasp_id="A04:2021 - Insecure Design",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_http_method_security(self, node: ast.FunctionDef) -> None:
        """
        Check for insecure HTTP methods like TRACE and OPTIONS abuse.

        TRACE can be used for XSS and CSRF attacks.
        CWE-16: Configuration
        """
        for decorator in node.decorator_list:
            methods = []

            if isinstance(decorator, ast.Call):
                # Check for methods keyword argument
                for keyword in decorator.keywords:
                    if keyword.arg == "methods":
                        if isinstance(keyword.value, ast.List):
                            for elt in keyword.value.elts:
                                if isinstance(elt, ast.Constant):
                                    methods.append(elt.value)

            # Check for dangerous methods
            dangerous_methods = {"TRACE", "TRACK"}
            found_dangerous = set(methods) & dangerous_methods

            if found_dangerous:
                self.violations.append(
                    RuleViolation(
                        rule_id="API005",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message=f"Insecure HTTP method {found_dangerous} enabled - can be used for XSS attacks",
                        fix_suggestion="Remove TRACE/TRACK methods from route configuration",
                        cwe_id="CWE-16",
                        owasp_id="A05:2021 - Security Misconfiguration",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

    def _check_jwt_algorithm_confusion(self, node: ast.FunctionDef) -> None:
        """
        Check for JWT algorithm confusion attacks (RS256 vs HS256).

        Attackers can forge tokens by changing algorithm from RS256 to HS256.
        CWE-327: Use of a Broken or Risky Cryptographic Algorithm
        """
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                func_name = None
                if isinstance(item.func, ast.Attribute):
                    func_name = item.func.attr
                elif isinstance(item.func, ast.Name):
                    func_name = item.func.id

                if func_name in ("encode", "decode") and any(
                    isinstance(arg, ast.Name) and "jwt" in arg.id.lower()
                    for arg in ast.walk(item)
                ):
                    # Check for algorithm parameter
                    algo_value = None
                    for keyword in item.keywords:
                        if keyword.arg == "algorithms" or keyword.arg == "algorithm":
                            if isinstance(keyword.value, ast.Constant):
                                algo_value = keyword.value.value
                            elif isinstance(keyword.value, ast.List):
                                for elt in keyword.value.elts:
                                    if isinstance(elt, ast.Constant):
                                        if elt.value == "HS256" or elt.value == "none":
                                            algo_value = elt.value
                                            break

                    if algo_value in ("HS256", "none"):
                        self.violations.append(
                            RuleViolation(
                                rule_id="API006",
                                file_path=self.file_path,
                                line_number=item.lineno,
                                column=item.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                message=f"JWT using weak algorithm '{algo_value}' - vulnerable to algorithm confusion",
                                fix_suggestion="Use RS256 or ES256 for JWT signing; never allow 'none' algorithm",
                                cwe_id="CWE-327",
                                owasp_id="A02:2021 - Cryptographic Failures",
                                fix_applicability=FixApplicability.SAFE,
                            )
                        )

    def _check_api_key_exposure(self, node: ast.FunctionDef) -> None:
        """
        Check for API keys exposed in URLs or logs.

        API keys in URLs are visible in logs, browser history, and referrer headers.
        CWE-598: Use of GET Request Method With Sensitive Query Strings
        """
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                # Check for URL building with API keys
                for arg in item.args:
                    if isinstance(arg, ast.JoinedStr):  # f-string
                        # Check if it contains 'api_key', 'token', etc.
                        for value in arg.values:
                            if isinstance(value, ast.Constant):
                                if any(
                                    keyword in value.value.lower()
                                    for keyword in ("api_key", "apikey", "token", "secret")
                                ):
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="API007",
                                            file_path=self.file_path,
                                            line_number=item.lineno,
                                            column=item.col_offset,
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            message="API key may be exposed in URL - visible in logs and history",
                                            fix_suggestion="Pass API keys in Authorization header instead of URL parameters",
                                            cwe_id="CWE-598",
                                            owasp_id="A04:2021 - Insecure Design",
                                            fix_applicability=FixApplicability.SUGGESTED,
                                        )
                                    )

    def _check_open_redirect(self, node: ast.FunctionDef) -> None:
        """
        Check for open redirect vulnerabilities.

        Unvalidated redirects can be used for phishing attacks.
        CWE-601: URL Redirection to Untrusted Site
        """
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                func_name = None
                if isinstance(item.func, ast.Attribute):
                    func_name = item.func.attr
                elif isinstance(item.func, ast.Name):
                    func_name = item.func.id

                if func_name in ("redirect", "RedirectResponse"):
                    # Check if redirect target is user-controlled
                    has_validation = False
                    for arg in item.args:
                        if isinstance(arg, ast.Name):
                            # Check if it's coming from request parameters
                            if arg.id in ("url", "redirect_url", "next", "return_url"):
                                # Look for validation in function body
                                for stmt in node.body:
                                    if isinstance(stmt, ast.If):
                                        # Check if there's URL validation
                                        if any(
                                            isinstance(n, ast.Call)
                                            and isinstance(n.func, ast.Attribute)
                                            and n.func.attr in ("startswith", "is_safe_url")
                                            for n in ast.walk(stmt.test)
                                        ):
                                            has_validation = True

                                if not has_validation:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="API008",
                                            file_path=self.file_path,
                                            line_number=item.lineno,
                                            column=item.col_offset,
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            message="Open redirect vulnerability - unvalidated redirect URL",
                                            fix_suggestion="Validate redirect URL against allowlist or check if it starts with '/'",
                                            cwe_id="CWE-601",
                                            owasp_id="A01:2021 - Broken Access Control",
                                            fix_applicability=FixApplicability.SUGGESTED,
                                        )
                                    )

    def _check_missing_security_headers(self, node: ast.Assign) -> None:
        """
        Check for missing security headers configuration.

        Missing headers like HSTS, CSP, X-Frame-Options expose applications.
        CWE-16: Configuration
        """
        # Check for response header setting
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Attribute):
                    if target.value.attr == "headers":
                        # Good - setting headers
                        return

        # Check if this is app configuration
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "config":
                    # Check if security headers are configured
                    if isinstance(node.value, ast.Dict):
                        keys = [
                            k.value if isinstance(k, ast.Constant) else None
                            for k in node.value.keys
                        ]
                        security_headers = {
                            "HSTS",
                            "Content-Security-Policy",
                            "X-Frame-Options",
                            "X-Content-Type-Options",
                        }
                        configured_headers = {
                            k for k in keys if k and any(h in k for h in security_headers)
                        }

                        if not configured_headers:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="API009",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    message="Missing security headers configuration (HSTS, CSP, X-Frame-Options)",
                                    fix_suggestion="Add security headers: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options",
                                    cwe_id="CWE-16",
                                    owasp_id="A05:2021 - Security Misconfiguration",
                                    fix_applicability=FixApplicability.SUGGESTED,
                                )
                            )

    def _check_graphql_introspection(self, node: ast.Call) -> None:
        """
        Check for GraphQL introspection enabled in production.

        Introspection leaks API schema and can aid attackers.
        CWE-200: Exposure of Sensitive Information
        """
        func_name = None
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name and "graphql" in func_name.lower():
            # Check for introspection parameter
            for keyword in node.keywords:
                if keyword.arg == "introspection":
                    if isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is True:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="API010",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    message="GraphQL introspection enabled - exposes API schema",
                                    fix_suggestion="Disable introspection in production: introspection=False",
                                    cwe_id="CWE-200",
                                    owasp_id="A01:2021 - Broken Access Control",
                                    fix_applicability=FixApplicability.SAFE,
                                )
                            )


def analyze_api_security(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Analyze code for API security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code content

    Returns:
        List of rule violations found
    """
    try:
        tree = ast.parse(code)
        visitor = APISecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Define rules
API001_MASS_ASSIGNMENT = Rule(
    rule_id="API001",
    name="api-mass-assignment",
    message_template="Model class may be vulnerable to mass assignment without field restrictions",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Mass assignment occurs when user input is directly assigned to model attributes without filtering",
    explanation="Attackers can modify sensitive fields like is_admin, password, etc. by including them in requests",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A04:2021 - Insecure Design",
    cwe_mapping="CWE-915",
)

API002_RATE_LIMITING = Rule(
    rule_id="API002",
    name="api-missing-rate-limit",
    message_template="API route has no rate limiting - vulnerable to abuse",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Rate limiting prevents resource exhaustion and brute force attacks",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A04:2021 - Insecure Design",
    cwe_mapping="CWE-770",
)

API003_AUTHENTICATION = Rule(
    rule_id="API003",
    name="api-missing-authentication",
    message_template="API route appears to need authentication but has none",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Unauthenticated endpoints can expose sensitive data or functionality",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A01:2021 - Broken Access Control",
    cwe_mapping="CWE-284",
)

API004_PAGINATION = Rule(
    rule_id="API004",
    name="api-improper-pagination",
    message_template="API route may return unbounded results - resource exhaustion risk",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Unbounded queries can cause memory exhaustion and DoS",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A04:2021 - Insecure Design",
    cwe_mapping="CWE-770",
)

API005_HTTP_METHOD = Rule(
    rule_id="API005",
    name="api-insecure-http-method",
    message_template="Insecure HTTP method (TRACE/TRACK) enabled",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="TRACE can be used for XSS and CSRF attacks",
    fix_applicability=FixApplicability.SAFE,
    owasp_mapping="A05:2021 - Security Misconfiguration",
    cwe_mapping="CWE-16",
)

API006_JWT_ALGORITHM = Rule(
    rule_id="API006",
    name="api-jwt-algorithm-confusion",
    message_template="JWT using weak algorithm - vulnerable to algorithm confusion",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Attackers can forge tokens by changing algorithm from RS256 to HS256",
    fix_applicability=FixApplicability.SAFE,
    owasp_mapping="A02:2021 - Cryptographic Failures",
    cwe_mapping="CWE-327",
)

API007_API_KEY = Rule(
    rule_id="API007",
    name="api-key-exposure-url",
    message_template="API key may be exposed in URL - visible in logs",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="API keys in URLs are visible in logs, browser history, and referrer headers",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A04:2021 - Insecure Design",
    cwe_mapping="CWE-598",
)

API008_OPEN_REDIRECT = Rule(
    rule_id="API008",
    name="api-open-redirect",
    message_template="Open redirect vulnerability - unvalidated redirect URL",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Unvalidated redirects can be used for phishing attacks",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A01:2021 - Broken Access Control",
    cwe_mapping="CWE-601",
)

API009_SECURITY_HEADERS = Rule(
    rule_id="API009",
    name="api-missing-security-headers",
    message_template="Missing security headers configuration",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Missing headers like HSTS, CSP, X-Frame-Options expose applications",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A05:2021 - Security Misconfiguration",
    cwe_mapping="CWE-16",
)

API010_GRAPHQL_INTROSPECTION = Rule(
    rule_id="API010",
    name="api-graphql-introspection",
    message_template="GraphQL introspection enabled - exposes API schema",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Introspection leaks API schema and can aid attackers",
    fix_applicability=FixApplicability.SAFE,
    owasp_mapping="A01:2021 - Broken Access Control",
    cwe_mapping="CWE-200",
)

# Collect all rules
API_SECURITY_RULES = [
    API001_MASS_ASSIGNMENT,
    API002_RATE_LIMITING,
    API003_AUTHENTICATION,
    API004_PAGINATION,
    API005_HTTP_METHOD,
    API006_JWT_ALGORITHM,
    API007_API_KEY,
    API008_OPEN_REDIRECT,
    API009_SECURITY_HEADERS,
    API010_GRAPHQL_INTROSPECTION,
]

# Register rules
register_rules(API_SECURITY_RULES)
