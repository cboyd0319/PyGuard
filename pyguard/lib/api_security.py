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
- CORS wildcard origin misconfiguration
- XML External Entity (XXE) attacks
- Insecure deserialization in API payloads
- OAuth flow unvalidated redirects
- Missing CSRF token validation

Total Security Checks: 15

References:
- OWASP API Security Top 10 | https://owasp.org/API-Security/ | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High
- CWE-915 (Improper Control of Dynamically-Managed Code) | High
- CWE-284 (Improper Access Control) | High
- CWE-770 (Resource Allocation) | Medium
- CWE-639 (Authorization Bypass) | High
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


class APISecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting API security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_flask = False
        self.has_fastapi = False
        self.has_django = False
        self.route_functions: set[str] = set()
        self.model_classes: set[str] = set()
        self.defusedxml_imports: set[str] = set()  # Track defusedxml imports
        self.has_hsts_header = False  # Track if HSTS header is set anywhere
        self.has_xframe_header = False  # Track if X-Frame-Options is set
        self.has_csp_header = False  # Track if CSP is set

    def visit_Import(self, node: ast.Import) -> None:
        """Track imports including defusedxml."""
        for alias in node.names:
            if "defusedxml" in alias.name:
                import_name = alias.asname if alias.asname else alias.name.split(".")[-1]
                self.defusedxml_imports.add(import_name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track framework imports."""
        if node.module:
            if node.module.startswith("flask"):
                self.has_flask = True
            elif node.module.startswith("fastapi"):
                self.has_fastapi = True
            elif node.module.startswith("django"):
                self.has_django = True
            elif "defusedxml" in node.module:
                # Track defusedxml imports
                for alias in node.names:
                    import_name = alias.asname if alias.asname else alias.name
                    self.defusedxml_imports.add(import_name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze model classes for mass assignment vulnerabilities."""
        # Check for ORM models
        base_names = [self._get_name(base) for base in node.bases]
        is_model = any(
            name in ("Model", "Base", "BaseModel", "Document") for name in base_names if name
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
            self._check_oauth_flow_misconfig(node)
            self._check_csrf_token_missing(node)
            self._check_api_versioning_security(node)

        # Check for SSRF in any function (not just routes)
        self._check_ssrf_vulnerability(node)

        # Check for JWT algorithm confusion in any function
        self._check_jwt_algorithm_confusion(node)

        # Check for API key exposure
        self._check_api_key_exposure(node)

        # Check for open redirects
        self._check_open_redirect(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for security header configurations and API key exposure in URLs."""
        self._check_missing_security_headers(node)
        self._check_missing_hsts_header(node)
        self._check_missing_xframe_options(node)
        self._check_missing_csp_header(node)

        # Check for API key exposure in URL assignments
        for value in [node.value]:
            if isinstance(value, ast.JoinedStr):
                # Check if this is a URL with sensitive parameters
                url_pattern = False
                has_sensitive_param = False

                for val in value.values:
                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                        # Check if this looks like a URL
                        if "http" in val.value.lower() or "://" in val.value:
                            url_pattern = True
                        # Check for sensitive parameter names in URL
                        if any(
                            keyword in val.value.lower()
                            for keyword in (
                                "api_key=",
                                "apikey=",
                                "token=",
                                "secret=",
                                "password=",
                                "auth=",
                            )
                        ):
                            has_sensitive_param = True

                if url_pattern and has_sensitive_param:
                    self.violations.append(
                        RuleViolation(
                            rule_id="API007",
                            file_path=self.file_path,
                            line_number=value.lineno,
                            column=value.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            message="API key may be exposed in URL - visible in logs and history",
                            fix_suggestion="Pass API keys in Authorization header instead of URL parameters",
                            cwe_id="CWE-598",
                            owasp_id="A04:2021 - Insecure Design",
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for GraphQL introspection and other API call issues."""
        self._check_graphql_introspection(node)
        self._check_cors_misconfiguration(node)
        self._check_xxe_vulnerability(node)
        self._check_insecure_deserialization(node)

        # Check for JWT algorithm confusion in module-level calls
        func_name = None
        is_jwt_call = False

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            # Check if it's jwt.encode() or jwt.decode()
            if isinstance(node.func.value, ast.Name):
                if "jwt" in node.func.value.id.lower():
                    is_jwt_call = True
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if is_jwt_call and func_name in ("encode", "decode"):
            # Check for algorithm parameter
            algo_value = None
            for keyword in node.keywords:
                if keyword.arg in {"algorithms", "algorithm"}:
                    if isinstance(keyword.value, ast.Constant):
                        algo_value = keyword.value.value
                    elif isinstance(keyword.value, ast.List):
                        for elt in keyword.value.elts:
                            if isinstance(elt, ast.Constant):
                                elt_val = elt.value
                                # Handle bytes
                                if isinstance(elt_val, bytes):
                                    elt_val = elt_val.decode("utf-8", errors="ignore")
                                if elt_val in {"HS256", "none"}:
                                    algo_value = elt_val
                                    break

            if algo_value and isinstance(algo_value, str) and algo_value in ("HS256", "none"):
                self.violations.append(
                    RuleViolation(
                        rule_id="API006",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message=f"JWT using weak algorithm '{algo_value}' - vulnerable to algorithm confusion",
                        fix_suggestion="Use RS256 or ES256 for JWT signing; never allow 'none' algorithm",
                        cwe_id="CWE-327",
                        owasp_id="A02:2021 - Cryptographic Failures",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

        self.generic_visit(node)

    def _get_name(self, node: ast.expr) -> str | None:
        """Extract name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
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
        has_meta_class = False
        protected_fields: set[str] = set()

        for item in node.body:
            # Check for __fields__ or __annotations__ (Pydantic)
            # if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            #     has_fields_declaration = True  # Currently unused but reserved for future validation

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
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    decorator_name = decorator.func.id
                elif isinstance(decorator.func, ast.Attribute):
                    decorator_name = decorator.func.attr

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
                if item.attr == "paginate":
                    # paginate implies built-in limit
                    has_pagination = True
                    has_limit = True
                elif item.attr in ("limit", "offset"):
                    has_pagination = True

        # Only flag list/query endpoints
        is_list_endpoint = any(
            keyword in node.name.lower() for keyword in ("list", "all", "query", "search", "find")
        )

        # Don't flag if function has parameters suggesting single item (like user_id)
        has_id_param = any(arg.arg.endswith("_id") or arg.arg == "id" for arg in node.args.args)

        # If it has "get" and an ID parameter, it's probably a single-item endpoint
        if "get" in node.name.lower() and has_id_param:
            is_list_endpoint = False

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
                is_jwt_call = False

                if isinstance(item.func, ast.Attribute):
                    func_name = item.func.attr
                    # Check if it's jwt.encode() or jwt.decode()
                    if isinstance(item.func.value, ast.Name):
                        if "jwt" in item.func.value.id.lower():
                            is_jwt_call = True
                elif isinstance(item.func, ast.Name):
                    func_name = item.func.id

                if is_jwt_call and func_name in ("encode", "decode"):
                    # Check for algorithm parameter
                    algo_value = None
                    for keyword in item.keywords:
                        if keyword.arg in {"algorithms", "algorithm"}:
                            if isinstance(keyword.value, ast.Constant):
                                algo_value = keyword.value.value
                                # Handle bytes
                                if isinstance(algo_value, bytes):
                                    algo_value = algo_value.decode("utf-8", errors="ignore")
                            elif isinstance(keyword.value, ast.List):
                                for elt in keyword.value.elts:
                                    if isinstance(elt, ast.Constant):
                                        elt_val = elt.value
                                        # Handle bytes
                                        if isinstance(elt_val, bytes):
                                            elt_val = elt_val.decode("utf-8", errors="ignore")
                                        if elt_val in {"HS256", "none"}:
                                            algo_value = elt_val
                                            break

                    if (
                        algo_value
                        and isinstance(algo_value, str)
                        and algo_value in ("HS256", "none")
                    ):
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
            # Check f-strings for API keys in URLs (both in assignments and function calls)
            if isinstance(item, ast.JoinedStr):
                # Check if it contains URL with 'api_key', 'token', etc. in query params
                url_pattern = False
                has_sensitive_param = False

                for value in item.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        # Check if this looks like a URL
                        if "http" in value.value.lower() or "://" in value.value:
                            url_pattern = True
                        # Check for sensitive parameter names in URL
                        if any(
                            keyword in value.value.lower()
                            for keyword in (
                                "api_key=",
                                "apikey=",
                                "token=",
                                "secret=",
                                "password=",
                                "auth=",
                            )
                        ):
                            has_sensitive_param = True

                if url_pattern and has_sensitive_param:
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
                            (
                                k.value
                                if isinstance(k, ast.Constant) and isinstance(k.value, str)
                                else None
                            )
                            for k in node.value.keys
                        ]
                        security_headers = {
                            "HSTS",
                            "Content-Security-Policy",
                            "X-Frame-Options",
                            "X-Content-Type-Options",
                        }
                        configured_headers = {
                            k
                            for k in keys
                            if k and isinstance(k, str) and any(h in k for h in security_headers)
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

        # Check for GraphQL-related function calls (Schema, GraphQLApp, etc.)
        if func_name and (
            "graphql" in func_name.lower() or func_name in ("Schema", "GraphQLApp", "GraphQLView")
        ):
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

    def _check_cors_misconfiguration(self, node: ast.Call) -> None:
        """Check for CORS wildcard origin misconfiguration."""
        # Check for CORS configuration with wildcard
        func_check = False
        if isinstance(node.func, ast.Attribute):
            if "cors" in node.func.attr.lower() or "add_middleware" in node.func.attr.lower():
                func_check = True
        elif isinstance(node.func, ast.Name) and "cors" in node.func.id.lower():
            func_check = True

        if func_check:
            for keyword in node.keywords:
                if keyword.arg in ("allow_origins", "origins", "allowed_origins"):
                    # Check for wildcard origin
                    if isinstance(keyword.value, ast.Constant):
                        if keyword.value.value == "*":
                            self.violations.append(
                                RuleViolation(
                                    rule_id="API011",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    message="CORS configured with wildcard origin (*) - allows any domain",
                                    fix_suggestion="Specify exact allowed origins instead of wildcard",
                                    cwe_id="CWE-942",
                                    owasp_id="A05:2021 - Security Misconfiguration",
                                    fix_applicability=FixApplicability.SUGGESTED,
                                )
                            )
                    elif isinstance(keyword.value, ast.List):
                        for elt in keyword.value.elts:
                            if isinstance(elt, ast.Constant) and elt.value == "*":
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="API011",
                                        file_path=self.file_path,
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        message="CORS configured with wildcard origin (*) - allows any domain",
                                        fix_suggestion="Specify exact allowed origins instead of wildcard",
                                        cwe_id="CWE-942",
                                        owasp_id="A05:2021 - Security Misconfiguration",
                                        fix_applicability=FixApplicability.SUGGESTED,
                                    )
                                )

    def _check_xxe_vulnerability(self, node: ast.Call) -> None:
        """Check for XML External Entity (XXE) vulnerabilities."""
        # Check for XML parsing without disabling external entities
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if func_name in ("parse", "fromstring", "XMLParser"):
                # Check if using defusedxml
                using_defusedxml = False

                if isinstance(node.func.value, ast.Name):
                    # Check if the module variable is from defusedxml
                    if (
                        node.func.value.id in self.defusedxml_imports
                        or "defusedxml" in node.func.value.id.lower()
                    ):
                        using_defusedxml = True

                    # Check for XMLParser creation with resolve_entities=False
                    if func_name == "XMLParser":
                        for keyword in node.keywords:
                            if keyword.arg == "resolve_entities" and (
                                isinstance(keyword.value, ast.Constant)
                                and keyword.value.value is False
                            ):
                                return  # Safe - explicitly disabled

                # Only flag if NOT using defusedxml AND NOT using resolve_entities=False
                if not using_defusedxml and func_name in ("parse", "fromstring"):
                    self.violations.append(
                        RuleViolation(
                            rule_id="API012",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            message="XML parsing without XXE protection - vulnerable to XML External Entity attacks",
                            fix_suggestion="Use defusedxml library or disable external entity resolution",
                            cwe_id="CWE-611",
                            owasp_id="A05:2021 - Security Misconfiguration",
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

    def _check_insecure_deserialization(self, node: ast.Call) -> None:
        """Check for insecure deserialization in API payloads."""
        # Check for unsafe pickle, marshal, or shelve usage
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            module_name = None

            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id.lower()

            if module_name in ("pickle", "marshal", "shelve", "dill") and func_name == "loads":
                self.violations.append(
                    RuleViolation(
                        rule_id="API013",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message=f"Insecure deserialization using {module_name}.{func_name}() - can execute arbitrary code",
                        fix_suggestion="Use safe formats like JSON for API payloads; validate all deserialized data",
                        cwe_id="CWE-502",
                        owasp_id="A08:2021 - Software and Data Integrity Failures",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

    def _check_oauth_flow_misconfig(self, node: ast.FunctionDef) -> None:
        """Check for OAuth flow misconfigurations including unvalidated redirects."""
        # First check if this has a route decorator
        has_route_decorator = False
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                if decorator.func.attr in ("get", "post", "route"):
                    has_route_decorator = True
                    break
            elif isinstance(decorator, ast.Attribute):
                if decorator.attr in ("get", "post", "route"):
                    has_route_decorator = True
                    break

        if not has_route_decorator:
            return  # Not a route handler, skip

        # Check for OAuth redirect without validation
        has_redirect = False
        validates_redirect = False

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if "redirect" in child.func.attr.lower():
                        has_redirect = True
                elif isinstance(child.func, ast.Name):
                    if "redirect" in child.func.id.lower():
                        has_redirect = True
                        # Check if redirect URL is validated
                        for arg in child.args:
                            if isinstance(arg, ast.Call):
                                validates_redirect = True

        # Check for validation patterns in the function body
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if "validate" in child.func.id.lower() or "is_safe" in child.func.id.lower():
                        validates_redirect = True
            elif isinstance(child, ast.If):
                # Check for conditional validation
                validates_redirect = True  # Assume if statement might be validating

        if has_redirect and not validates_redirect:
            # Check if function name suggests OAuth
            if any(
                keyword in node.name.lower()
                for keyword in ("oauth", "authorize", "callback", "login")
            ):
                self.violations.append(
                    RuleViolation(
                        rule_id="API014",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="OAuth flow redirect URL not validated - vulnerable to open redirect",
                        fix_suggestion="Validate redirect_uri against whitelist of allowed URLs",
                        cwe_id="CWE-601",
                        owasp_id="A01:2021 - Broken Access Control",
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

    def _check_api_versioning_security(self, node: ast.FunctionDef) -> None:
        """Check for API versioning security issues (API016)."""
        # Check if route has versioning in path
        uses_deprecated_version = False

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                # Check route path for version patterns
                if decorator.args:
                    route_arg = decorator.args[0]
                    if isinstance(route_arg, ast.Constant) and isinstance(route_arg.value, str):
                        route_path = route_arg.value.lower()
                        # Check for deprecated versions (v0, v1 are often deprecated)
                        if "/v0/" in route_path or (
                            "/v1/" in route_path and "/v2/" not in self.code
                        ):
                            uses_deprecated_version = True

        # Check function body for version validation
        has_version_check = False
        for child in ast.walk(node):
            if isinstance(child, ast.Compare):
                for comp in child.comparators:
                    if isinstance(comp, ast.Constant):
                        if isinstance(comp.value, str) and any(
                            v in comp.value.lower() for v in ["v1", "v2", "v3", "version"]
                        ):
                            has_version_check = True

        # Report if using deprecated version without checks
        if uses_deprecated_version and not has_version_check:
            self.violations.append(
                RuleViolation(
                    rule_id="API016",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message="API using deprecated version (v0/v1) without version validation - potential compatibility issues",
                    fix_suggestion="Add version validation and deprecation warnings; migrate to newer API version",
                    cwe_id="CWE-1188",
                    owasp_id="A04:2021 - Insecure Design",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_ssrf_vulnerability(self, node: ast.FunctionDef) -> None:
        """Check for Server-Side Request Forgery (SSRF) vulnerabilities (API017)."""
        # Check for URL requests using user input
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Check for requests library calls
                if isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr

                    # Check for requests.get(), urllib.request.urlopen(), httpx.get(), etc.
                    if func_name in (
                        "get",
                        "post",
                        "put",
                        "delete",
                        "patch",
                        "request",
                        "urlopen",
                        "urlretrieve",
                    ):
                        # Get the module name (could be nested like urllib.request)
                        module = None
                        if isinstance(child.func.value, ast.Name):
                            module = child.func.value.id
                        elif isinstance(child.func.value, ast.Attribute):
                            # Handle urllib.request.urlopen
                            if isinstance(child.func.value.value, ast.Name):
                                module = child.func.value.value.id

                        if module in ("requests", "urllib", "httpx"):
                            # Check if URL is from user input
                            if child.args:
                                url_arg = child.args[0]
                                # Check for function parameters, request.args, etc.
                                has_user_input = self._is_user_input(url_arg)
                                has_url_validation = self._has_url_validation(node, url_arg)

                                if has_user_input and not has_url_validation:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="API017",
                                            file_path=self.file_path,
                                            line_number=child.lineno,
                                            column=child.col_offset,
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            message=f"Potential SSRF vulnerability - {module}.{func_name}() using user-controlled URL without validation",
                                            fix_suggestion="Validate URL against whitelist of allowed domains/IP ranges; use URL parsing to check scheme and hostname",
                                            cwe_id="CWE-918",
                                            owasp_id="A10:2021 - Server-Side Request Forgery",
                                            fix_applicability=FixApplicability.SUGGESTED,
                                        )
                                    )

    def _check_missing_hsts_header(self, node: ast.Assign) -> None:
        """Check for missing HSTS (HTTP Strict Transport Security) header (API018)."""
        # Check for response header setting
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Attribute):
                    if target.value.attr == "headers":
                        # Check if HSTS is being set
                        if isinstance(target.slice, ast.Constant):
                            header_name = target.slice.value
                            if (
                                isinstance(header_name, str)
                                and "strict-transport-security" in header_name.lower()
                            ):
                                self.has_hsts_header = True
                                return  # HSTS is set

        # Check app configuration for HSTS
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "config" and isinstance(node.value, ast.Dict):
                    keys = [
                        k.value if isinstance(k, ast.Constant) else None for k in node.value.keys
                    ]
                    if any(k and "hsts" in str(k).lower() for k in keys):
                        self.has_hsts_header = True
                        return  # HSTS configured

    def _check_missing_xframe_options(self, node: ast.Assign) -> None:
        """Check for missing X-Frame-Options header (clickjacking protection) (API019)."""
        # Check for response header setting
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Attribute):
                    if target.value.attr == "headers":
                        # Check if X-Frame-Options is being set
                        if isinstance(target.slice, ast.Constant):
                            header_name = target.slice.value
                            if (
                                isinstance(header_name, str)
                                and "x-frame-options" in header_name.lower()
                            ):
                                self.has_xframe_header = True
                                return  # X-Frame-Options is set

        # Check app configuration for X-Frame-Options
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "config" and isinstance(node.value, ast.Dict):
                    keys = [
                        k.value if isinstance(k, ast.Constant) else None for k in node.value.keys
                    ]
                    if any(k and "frame" in str(k).lower() for k in keys):
                        self.has_xframe_header = True
                        return  # X-Frame-Options configured

    def _check_missing_csp_header(self, node: ast.Assign) -> None:
        """Check for missing Content-Security-Policy header (API020)."""
        # Check for response header setting
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Attribute):
                    if target.value.attr == "headers":
                        # Check if CSP is being set
                        if isinstance(target.slice, ast.Constant):
                            header_name = target.slice.value
                            if (
                                isinstance(header_name, str)
                                and "content-security-policy" in header_name.lower()
                            ):
                                self.has_csp_header = True
                                return  # CSP is set

        # Check app configuration for CSP (handle both hyphens and underscores)
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "config" and isinstance(node.value, ast.Dict):
                    keys = [
                        k.value if isinstance(k, ast.Constant) else None for k in node.value.keys
                    ]
                    # Check for CSP with hyphens or underscores
                    if any(
                        k and ("content-security-policy" in str(k).lower().replace("_", "-"))
                        for k in keys
                    ):
                        self.has_csp_header = True
                        return  # CSP configured

    def _is_user_input(self, node: ast.AST) -> bool:
        """Check if a node represents user input."""
        # Check for common user input patterns
        if isinstance(node, ast.Name):
            var_name = node.id.lower()
            return any(
                keyword in var_name
                for keyword in ["url", "uri", "link", "redirect", "request", "input", "param"]
            )
        if isinstance(node, ast.Subscript):
            # Check for request.args['url'], request.form['url'], etc.
            if isinstance(node.value, ast.Attribute):
                if node.value.attr in ("args", "form", "json", "data", "params", "query_params"):
                    return True
        elif isinstance(node, ast.Call):
            # Check for request.get('url'), request.args.get('url'), etc.
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "get" and node.args:
                    if isinstance(node.args[0], ast.Constant):
                        arg_name = str(node.args[0].value).lower()
                        return any(
                            keyword in arg_name for keyword in ["url", "uri", "link", "redirect"]
                        )
        return False

    def _has_url_validation(self, func_node: ast.FunctionDef, _url_node: ast.AST) -> bool:
        """Check if URL validation exists in the function.

        Args:
            func_node: Function to check for URL validation
            _url_node: URL node (reserved for future use)
        """
        # Look for URL validation patterns
        for child in ast.walk(func_node):
            # Check for urlparse, domain checking, whitelist validation
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in ("urlparse", "urlsplit"):
                        return True
                elif isinstance(child.func, ast.Attribute) and child.func.attr in (
                    "parse_url",
                    "validate_url",
                    "check_domain",
                    "is_safe_url",
                ):
                    return True
            # Check for 'in allowed_domains' or similar whitelist checks
            elif isinstance(child, ast.Compare):
                for op in child.ops:
                    if isinstance(op, ast.In):
                        for comp in child.comparators:
                            if isinstance(comp, ast.Name):
                                if "allowed" in comp.id.lower() or "whitelist" in comp.id.lower():
                                    return True
        return False

    def _report_missing_headers(self) -> None:
        """Report missing security headers after analyzing the entire file."""
        # Only check if we're in a web framework context
        if not (self.has_flask or self.has_django or self.has_fastapi):
            return

        # Check if we found any app initialization
        has_app_init = "Flask(" in self.code or "FastAPI(" in self.code or "Django" in self.code

        if not has_app_init:
            return

        # Report missing HSTS
        if not self.has_hsts_header:
            self.violations.append(
                RuleViolation(
                    rule_id="API018",
                    file_path=self.file_path,
                    line_number=1,
                    column=0,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message="Missing HSTS (HTTP Strict-Transport-Security) header - forces HTTPS",
                    fix_suggestion="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
                    cwe_id="CWE-319",
                    owasp_id="A05:2021 - Security Misconfiguration",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        # Report missing X-Frame-Options
        if not self.has_xframe_header:
            self.violations.append(
                RuleViolation(
                    rule_id="API019",
                    file_path=self.file_path,
                    line_number=1,
                    column=0,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message="Missing X-Frame-Options header - vulnerable to clickjacking attacks",
                    fix_suggestion="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header",
                    cwe_id="CWE-1021",
                    owasp_id="A05:2021 - Security Misconfiguration",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        # Report missing CSP
        if not self.has_csp_header:
            self.violations.append(
                RuleViolation(
                    rule_id="API020",
                    file_path=self.file_path,
                    line_number=1,
                    column=0,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message="Missing Content-Security-Policy header - helps prevent XSS attacks",
                    fix_suggestion="Add Content-Security-Policy header with strict directives (e.g., default-src 'self')",
                    cwe_id="CWE-693",
                    owasp_id="A05:2021 - Security Misconfiguration",
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_csrf_token_missing(self, node: ast.FunctionDef) -> None:
        """Check for missing CSRF token validation in state-changing operations."""
        # Check if this is a state-changing route (POST, PUT, DELETE, PATCH)
        is_state_changing = False
        has_csrf_check = False

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                method = decorator.func.attr
                if method in ("post", "put", "delete", "patch"):
                    is_state_changing = True

        if is_state_changing:
            # Check for CSRF validation
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    if "csrf" in child.id.lower():
                        has_csrf_check = True
                        break
                elif isinstance(child, ast.Attribute):
                    if "csrf" in child.attr.lower():
                        has_csrf_check = True
                        break

            if not has_csrf_check:
                self.violations.append(
                    RuleViolation(
                        rule_id="API015",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="State-changing endpoint missing CSRF token validation",
                        fix_suggestion="Add CSRF token validation for POST/PUT/DELETE/PATCH endpoints",
                        cwe_id="CWE-352",
                        owasp_id="A01:2021 - Broken Access Control",
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )


def analyze_api_security(file_path: Path, code: str) -> list[RuleViolation]:
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
        # Report missing security headers after analyzing the whole file
        visitor._report_missing_headers()
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

API011_CORS_WILDCARD = Rule(
    rule_id="API011",
    name="api-cors-wildcard",
    message_template="CORS configured with wildcard origin (*)",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Wildcard CORS allows any domain to access the API",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A05:2021 - Security Misconfiguration",
    cwe_mapping="CWE-942",
)

API012_XXE_VULNERABILITY = Rule(
    rule_id="API012",
    name="api-xxe-vulnerability",
    message_template="XML parsing without XXE protection",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="XML External Entity attacks can lead to data disclosure and SSRF",
    fix_applicability=FixApplicability.SAFE,
    owasp_mapping="A05:2021 - Security Misconfiguration",
    cwe_mapping="CWE-611",
)

API013_INSECURE_DESERIALIZATION = Rule(
    rule_id="API013",
    name="api-insecure-deserialization",
    message_template="Insecure deserialization in API payload",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Deserializing untrusted data can execute arbitrary code",
    fix_applicability=FixApplicability.SAFE,
    owasp_mapping="A08:2021 - Software and Data Integrity Failures",
    cwe_mapping="CWE-502",
)

API014_OAUTH_REDIRECT_UNVALIDATED = Rule(
    rule_id="API014",
    name="api-oauth-redirect-unvalidated",
    message_template="OAuth redirect URL not validated",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Unvalidated OAuth redirects can be exploited for phishing",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A01:2021 - Broken Access Control",
    cwe_mapping="CWE-601",
)

API015_CSRF_TOKEN_MISSING = Rule(
    rule_id="API015",
    name="api-csrf-token-missing",
    message_template="State-changing endpoint missing CSRF protection",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Missing CSRF tokens allow attackers to forge requests",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A01:2021 - Broken Access Control",
    cwe_mapping="CWE-352",
)

API016_API_VERSIONING = Rule(
    rule_id="API016",
    name="api-versioning-security",
    message_template="API using deprecated version without validation - potential compatibility issues",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="API versioning security ensures deprecated versions are properly validated and migrated",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A04:2021 - Insecure Design",
    cwe_mapping="CWE-1188",
)

API017_SSRF_VULNERABILITY = Rule(
    rule_id="API017",
    name="api-ssrf-vulnerability",
    message_template="Potential SSRF vulnerability - HTTP request using user-controlled URL without validation",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Server-Side Request Forgery (SSRF) allows attackers to make requests to internal resources",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A10:2021 - Server-Side Request Forgery",
    cwe_mapping="CWE-918",
)

API018_MISSING_HSTS = Rule(
    rule_id="API018",
    name="api-missing-hsts-header",
    message_template="Missing HSTS header - forces HTTPS connections",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="HTTP Strict-Transport-Security (HSTS) header forces browsers to use HTTPS",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A05:2021 - Security Misconfiguration",
    cwe_mapping="CWE-319",
)

API019_MISSING_XFRAME = Rule(
    rule_id="API019",
    name="api-missing-xframe-options",
    message_template="Missing X-Frame-Options header - vulnerable to clickjacking",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="X-Frame-Options header prevents clickjacking attacks by controlling iframe embedding",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A05:2021 - Security Misconfiguration",
    cwe_mapping="CWE-1021",
)

API020_MISSING_CSP = Rule(
    rule_id="API020",
    name="api-missing-csp-header",
    message_template="Missing Content-Security-Policy header - helps prevent XSS attacks",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Content-Security-Policy (CSP) header restricts resource loading to prevent XSS",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A05:2021 - Security Misconfiguration",
    cwe_mapping="CWE-693",
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
    API011_CORS_WILDCARD,
    API012_XXE_VULNERABILITY,
    API013_INSECURE_DESERIALIZATION,
    API014_OAUTH_REDIRECT_UNVALIDATED,
    API015_CSRF_TOKEN_MISSING,
    API016_API_VERSIONING,
    API017_SSRF_VULNERABILITY,
    API018_MISSING_HSTS,
    API019_MISSING_XFRAME,
    API020_MISSING_CSP,
]

# Register rules
register_rules(API_SECURITY_RULES)
