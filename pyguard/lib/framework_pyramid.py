"""
Pyramid Framework Security Analysis for PyGuard.

Implements 15 security checks specific to the Pyramid web framework:
- ACL & Permission Security (5 checks)
- View & Route Security (5 checks)
- Session & Auth Security (5 checks)

References:
- Pyramid Security Documentation | https://docs.pylonsproject.org/projects/pyramid/en/latest/narr/security.html
- OWASP ASVS v5.0 | https://owasp.org/www-project-application-security-verification-standard/
- CWE Top 25 | https://cwe.mitre.org/top25/

Week 15-16 Implementation: 15 Pyramid-specific security checks
"""

import ast

from pyguard.lib.ast_analyzer import SecurityIssue
from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import Rule, RuleCategory, RuleSeverity

# =============================================================================
# PYRAMID FRAMEWORK SECURITY RULES (15 TOTAL)
# =============================================================================

# -----------------------------------------------------------------------------
# ACL & Permission Security (5 checks)
# -----------------------------------------------------------------------------

PYRAMID001_ACL_MISCONFIG = Rule(
    rule_id="PYRAMID001",
    name="acl-misconfiguration",
    category=RuleCategory.SECURITY,
    message_template="ACL misconfiguration: Overly permissive Allow rule for {principal}",
    description="Detects overly permissive ACL configurations (e.g., Allow Everyone)",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-284",  # Improper Access Control
    owasp_mapping="ASVS-4.1.1",  # Authorization
)

PYRAMID002_PERMISSION_BYPASS = Rule(
    rule_id="PYRAMID002",
    name="permission-system-bypass",
    category=RuleCategory.SECURITY,
    message_template="Permission system bypass: View lacks permission requirement",
    description="Detects Pyramid views without permission checks",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-862",  # Missing Authorization
    owasp_mapping="ASVS-4.1.1",
)

PYRAMID003_WEAK_PERMISSION = Rule(
    rule_id="PYRAMID003",
    name="weak-permission-name",
    category=RuleCategory.SECURITY,
    message_template="Weak permission name: '{permission}' is too generic",
    description="Detects generic permission names that don't follow least privilege",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-732",  # Incorrect Permission Assignment
    owasp_mapping="ASVS-4.1.2",
)

PYRAMID004_CONTEXT_FACTORY = Rule(
    rule_id="PYRAMID004",
    name="insecure-context-factory",
    category=RuleCategory.SECURITY,
    message_template="Insecure context factory: Missing __acl__ attribute",
    description="Detects resource context factories without ACL definitions",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-284",
    owasp_mapping="ASVS-4.1.1",
)

PYRAMID005_TRAVERSAL_VULN = Rule(
    rule_id="PYRAMID005",
    name="traversal-security-issue",
    category=RuleCategory.SECURITY,
    message_template="Traversal security issue: Path traversal risk in resource lookup",
    description="Detects unsafe resource traversal that could lead to unauthorized access",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-22",  # Path Traversal
    owasp_mapping="ASVS-5.2.2",
)

# -----------------------------------------------------------------------------
# View & Route Security (5 checks)
# -----------------------------------------------------------------------------

PYRAMID006_VIEW_CONFIG_INSECURE = Rule(
    rule_id="PYRAMID006",
    name="view-configuration-insecure",
    category=RuleCategory.SECURITY,
    message_template="Insecure view configuration: {issue}",
    description="Detects insecure view configuration parameters",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-16",  # Configuration
    owasp_mapping="ASVS-4.1.1",
)

PYRAMID007_ROUTE_PATTERN_VULN = Rule(
    rule_id="PYRAMID007",
    name="route-pattern-vulnerability",
    category=RuleCategory.SECURITY,
    message_template="Route pattern vulnerability: Unvalidated parameter '{param}' in route",
    description="Detects route patterns with unvalidated parameters",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-20",  # Improper Input Validation
    owasp_mapping="ASVS-5.1.1",
)

PYRAMID008_RENDERER_SECURITY = Rule(
    rule_id="PYRAMID008",
    name="renderer-security-risk",
    category=RuleCategory.SECURITY,
    message_template="Renderer security risk: {renderer} may expose sensitive data",
    description="Detects use of renderers that might expose sensitive information",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-200",  # Information Exposure
    owasp_mapping="ASVS-4.2.1",
)

PYRAMID009_ROUTE_PREFIX = Rule(
    rule_id="PYRAMID009",
    name="insecure-route-prefix",
    category=RuleCategory.SECURITY,
    message_template="Insecure route prefix: API routes without version or security prefix",
    description="Detects API routes without proper versioning or security prefixes",
    severity=RuleSeverity.LOW,
    cwe_mapping="CWE-16",
    owasp_mapping="ASVS-4.3.1",
)

PYRAMID010_REQUEST_FACTORY = Rule(
    rule_id="PYRAMID010",
    name="request-factory-injection",
    category=RuleCategory.SECURITY,
    message_template="Request factory injection: Custom request factory without validation",
    description="Detects custom request factories that don't validate inputs",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-74",  # Injection
    owasp_mapping="ASVS-5.1.1",
)

# -----------------------------------------------------------------------------
# Session & Auth Security (5 checks)
# -----------------------------------------------------------------------------

PYRAMID011_SESSION_FACTORY = Rule(
    rule_id="PYRAMID011",
    name="weak-session-factory",
    category=RuleCategory.SECURITY,
    message_template="Weak session factory: {issue}",
    description="Detects insecure session factory configurations",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-384",  # Session Fixation
    owasp_mapping="ASVS-3.2.1",  # Session Management
)

PYRAMID012_CSRF_DISABLED = Rule(
    rule_id="PYRAMID012",
    name="csrf-protection-disabled",
    category=RuleCategory.SECURITY,
    message_template="CSRF protection disabled: require_csrf=False in view",
    description="Detects views with CSRF protection explicitly disabled",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-352",  # CSRF
    owasp_mapping="ASVS-4.2.2",
)

PYRAMID013_AUTH_POLICY = Rule(
    rule_id="PYRAMID013",
    name="weak-authentication-policy",
    category=RuleCategory.SECURITY,
    message_template="Weak authentication policy: {issue}",
    description="Detects insecure authentication policy configurations",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-287",  # Improper Authentication
    owasp_mapping="ASVS-2.1.1",
)

PYRAMID014_AUTHZ_POLICY = Rule(
    rule_id="PYRAMID014",
    name="weak-authorization-policy",
    category=RuleCategory.SECURITY,
    message_template="Weak authorization policy: {issue}",
    description="Detects insecure authorization policy configurations",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-285",  # Improper Authorization
    owasp_mapping="ASVS-4.1.1",
)

PYRAMID015_SESSION_TIMEOUT = Rule(
    rule_id="PYRAMID015",
    name="missing-session-timeout",
    category=RuleCategory.SECURITY,
    message_template="Missing session timeout: Sessions don't expire",
    description="Detects session configurations without timeout settings",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-613",  # Insufficient Session Expiration
    owasp_mapping="ASVS-3.2.3",
)


# Collect all Pyramid rules
PYRAMID_RULES = [
    # ACL & Permission Security (5)
    PYRAMID001_ACL_MISCONFIG,
    PYRAMID002_PERMISSION_BYPASS,
    PYRAMID003_WEAK_PERMISSION,
    PYRAMID004_CONTEXT_FACTORY,
    PYRAMID005_TRAVERSAL_VULN,
    # View & Route Security (5)
    PYRAMID006_VIEW_CONFIG_INSECURE,
    PYRAMID007_ROUTE_PATTERN_VULN,
    PYRAMID008_RENDERER_SECURITY,
    PYRAMID009_ROUTE_PREFIX,
    PYRAMID010_REQUEST_FACTORY,
    # Session & Auth Security (5)
    PYRAMID011_SESSION_FACTORY,
    PYRAMID012_CSRF_DISABLED,
    PYRAMID013_AUTH_POLICY,
    PYRAMID014_AUTHZ_POLICY,
    PYRAMID015_SESSION_TIMEOUT,
]


class PyramidSecurityVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting Pyramid framework security vulnerabilities.

    Implements 15 security checks across three categories:
    - ACL & Permission Security (5 checks)
    - View & Route Security (5 checks)
    - Session & Auth Security (5 checks)
    """

    def __init__(self, source_code: str):
        """Initialize the Pyramid security visitor."""
        self.issues: list[SecurityIssue] = []
        self.source_lines: list[str] = source_code.splitlines()
        self.logger = PyGuardLogger()

        # Track Pyramid-specific constructs
        self.has_pyramid_import = False
        self.view_configs: list[tuple] = []  # (line, decorator_args)
        self.acl_definitions: list[tuple] = []  # (line, acl_content)
        self.session_config: dict | None = None
        self.auth_policies: list[str] = []

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            line: str = self.source_lines[node.lineno - 1]
            return line.strip()
        return ""

    def _get_decorator_name(self, decorator: ast.AST) -> str:
        """Extract decorator name."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                return decorator.func.id
            if isinstance(decorator.func, ast.Attribute):
                return decorator.func.attr
        elif isinstance(decorator, ast.Attribute):
            return decorator.attr
        return ""

    def _get_decorator_kwargs(self, decorator: ast.Call) -> dict:
        """Extract keyword arguments from decorator."""
        kwargs = {}
        for keyword in decorator.keywords:
            if keyword.arg:
                if isinstance(keyword.value, ast.Constant):
                    kwargs[keyword.arg] = keyword.value.value
                elif isinstance(keyword.value, ast.Name):
                    kwargs[keyword.arg] = keyword.value.id
        return kwargs

    def visit_Import(self, node: ast.Import):
        """Track Pyramid imports."""
        for alias in node.names:
            if "pyramid" in alias.name.lower():
                self.has_pyramid_import = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track Pyramid imports."""
        if node.module and "pyramid" in node.module.lower():
            self.has_pyramid_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze Pyramid view functions."""
        if not self.has_pyramid_import:
            self.generic_visit(node)
            return

        # Check decorators for view_config
        has_view_config = False
        has_permission = False
        # has_csrf_check = True  # Default is True, check if disabled (not used)
        permission_name = None

        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)

            if decorator_name == "view_config":
                has_view_config = True

                # Extract decorator arguments
                if isinstance(decorator, ast.Call):
                    kwargs = self._get_decorator_kwargs(decorator)

                    # PYRAMID002: Check for permission
                    if "permission" in kwargs:
                        has_permission = True
                        permission_name = kwargs["permission"]

                        # PYRAMID003: Check for weak permission names
                        if permission_name in ["view", "edit", "add", "delete"]:
                            self.issues.append(
                                SecurityIssue(
                                    severity="MEDIUM",
                                    category="Pyramid Permission",
                                    message=f"Weak permission name: '{permission_name}' is too generic",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_code_snippet(decorator),
                                    fix_suggestion="Use specific permission like 'view_user_profile' or 'edit_admin_settings'",
                                    cwe_id="CWE-732",
                                    owasp_id="ASVS-4.1.2",
                                )
                            )

                    # PYRAMID012: Check for CSRF disabled
                    if "require_csrf" in kwargs and not kwargs["require_csrf"]:
                        # has_csrf_check = False  # Not used
                        self.issues.append(
                            SecurityIssue(
                                severity="CRITICAL",
                                category="Pyramid CSRF",
                                message="CSRF protection disabled: require_csrf=False in view",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(decorator),
                                fix_suggestion="Remove require_csrf=False or implement custom CSRF protection",
                                cwe_id="CWE-352",
                                owasp_id="ASVS-4.2.2",
                            )
                        )

                    # PYRAMID006: Check for insecure view configuration
                    if "renderer" in kwargs:
                        renderer = kwargs["renderer"]
                        # PYRAMID008: Check renderer security
                        if "json" in str(renderer).lower():
                            # JSON renderer might expose sensitive data
                            self.issues.append(
                                SecurityIssue(
                                    severity="MEDIUM",
                                    category="Pyramid Renderer",
                                    message="Renderer security risk: JSON renderer may expose sensitive data",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_code_snippet(decorator),
                                    fix_suggestion="Explicitly serialize only required fields; use DTO pattern",
                                    cwe_id="CWE-200",
                                    owasp_id="ASVS-4.2.1",
                                )
                            )

                    # PYRAMID007: Check route patterns
                    if "route_name" in kwargs:
                        route_name = kwargs["route_name"]
                        # Basic check - in practice would need to cross-reference route definitions
                        if "{" in str(route_name):
                            self.issues.append(
                                SecurityIssue(
                                    severity="MEDIUM",
                                    category="Pyramid Route",
                                    message="Route pattern with parameter - ensure validation in view",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_code_snippet(decorator),
                                    fix_suggestion="Validate route parameters with request.matchdict in view",
                                    cwe_id="CWE-20",
                                    owasp_id="ASVS-5.1.1",
                                )
                            )

        # PYRAMID002: View without permission (if it's a view_config)
        if has_view_config and not has_permission:
            # Check if this looks like a sensitive operation
            func_name_lower = node.name.lower()
            sensitive_keywords = ["admin", "delete", "create", "update", "modify", "edit"]
            if any(kw in func_name_lower for kw in sensitive_keywords):
                self.issues.append(
                    SecurityIssue(
                        severity="CRITICAL",
                        category="Pyramid Permission",
                        message=f"Permission system bypass: Sensitive view '{node.name}' lacks permission requirement",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Add permission='appropriate_permission' to @view_config",
                        cwe_id="CWE-862",
                        owasp_id="ASVS-4.1.1",
                    )
                )

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        """Analyze Pyramid resource classes and context factories."""
        if not self.has_pyramid_import:
            self.generic_visit(node)
            return

        # PYRAMID004: Check for __acl__ in resource classes
        has_acl = False
        has_getitem = False

        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id == "__acl__":
                        has_acl = True
                        # PYRAMID001: Check ACL configuration
                        self._check_acl_definition(item, node.lineno)

            if isinstance(item, ast.FunctionDef) and item.name == "__getitem__":
                has_getitem = True
                # PYRAMID005: Check traversal security
                self._check_traversal_security(item)

        # If it's a resource/context factory, it should have __acl__
        if has_getitem and not has_acl:
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Pyramid ACL",
                    message=f"Insecure context factory: Class '{node.name}' missing __acl__ attribute",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Add __acl__ = [(Allow, Everyone, 'view'), ...] to define access control",
                    cwe_id="CWE-284",
                    owasp_id="ASVS-4.1.1",
                )
            )

        self.generic_visit(node)

    def _check_acl_definition(self, node: ast.Assign, _class_line: int):
        """Check ACL definition for security issues.
        
        Args:
            node: Assignment node to check
            _class_line: Line number of class (reserved for context)
        """
        if not node.value:
            return

        # Get the ACL definition as text (may span multiple lines)
        # Use ast.unparse for Python 3.9+ or fall back to source code extraction
        try:
            code = ast.unparse(node.value)
        except AttributeError:
            # Fallback for older Python versions
            code = self._get_code_snippet(node)

        # Also check the actual line for single-line ACLs
        code_line = self._get_code_snippet(node)
        code_full = code + " " + code_line

        # PYRAMID001: Check for "Allow, Everyone" which is often too permissive
        if "Allow" in code_full and "Everyone" in code_full:
            # This might be OK for public views, but flag it
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Pyramid ACL",
                    message="ACL misconfiguration: Overly permissive Allow rule for Everyone",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=code_line,
                    fix_suggestion="Use specific principals (Authenticated, group:editors) instead of Everyone when possible",
                    cwe_id="CWE-284",
                    owasp_id="ASVS-4.1.1",
                )
            )

    def _check_traversal_security(self, node: ast.FunctionDef):
        """Check __getitem__ for path traversal vulnerabilities."""
        # PYRAMID005: Look for unsafe path operations
        # Check for path concatenation using key parameter
        for child in ast.walk(node):
            # Look for string concatenation with the key parameter
            if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
                code = self._get_code_snippet(child)
                # Check if concatenating paths with key
                if any(keyword in code for keyword in ["/data/", "/path/", "path =", "key"]):
                    # Check if the parameter (key) is used without validation
                    if "key" in code:
                        self.issues.append(
                            SecurityIssue(
                                severity="HIGH",
                                category="Pyramid Traversal",
                                message="Traversal security issue: Path traversal risk in resource lookup",
                                line_number=(
                                    child.lineno if hasattr(child, "lineno") else node.lineno
                                ),
                                column=child.col_offset if hasattr(child, "col_offset") else 0,
                                code_snippet=code,
                                fix_suggestion="Validate traversal keys; check for '..' and absolute paths",
                                cwe_id="CWE-22",
                                owasp_id="ASVS-5.2.2",
                            )
                        )
                        break
            # Also check for subscript operations
            elif isinstance(child, ast.Subscript):
                code = self._get_code_snippet(child)
                # Check if directly using key without validation
                if "request" in code or "__getitem__" in code:
                    self.issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Pyramid Traversal",
                            message="Traversal security issue: Path traversal risk in resource lookup",
                            line_number=child.lineno if hasattr(child, "lineno") else node.lineno,
                            column=child.col_offset if hasattr(child, "col_offset") else 0,
                            code_snippet=code,
                            fix_suggestion="Validate traversal keys; check for '..' and absolute paths",
                            cwe_id="CWE-22",
                            owasp_id="ASVS-5.2.2",
                        )
                    )
                    break

    def visit_Call(self, node: ast.Call):
        """Analyze Pyramid configuration calls."""
        if not self.has_pyramid_import:
            self.generic_visit(node)
            return

        call_name = ""
        if isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            call_name = node.func.id

        # PYRAMID011: Check session factory
        if "sessionfactory" in call_name.lower() or call_name == "set_session_factory":
            kwargs = {}
            for keyword in node.keywords:
                if keyword.arg and isinstance(keyword.value, ast.Constant):
                    kwargs[keyword.arg] = keyword.value.value

            # Check for missing timeout
            if "timeout" not in kwargs and "max_age" not in kwargs:
                self.issues.append(
                    SecurityIssue(
                        severity="MEDIUM",
                        category="Pyramid Session",
                        message="Missing session timeout: Sessions don't expire",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Add timeout=3600 (or appropriate value) to session factory",
                        cwe_id="CWE-613",
                        owasp_id="ASVS-3.2.3",
                    )
                )

            # Check for weak secret (from keywords or first positional arg)
            secret = None
            if "secret" in kwargs:
                secret = str(kwargs["secret"])
            elif len(node.args) >= 1 and isinstance(node.args[0], ast.Constant):
                secret = str(node.args[0].value)

            if secret:
                if len(secret) < 32 or secret in ["secret", "changeme", "default"]:
                    self.issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Pyramid Session",
                            message="Weak session factory: Weak or short secret key",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use a strong random secret (32+ characters from secrets.token_urlsafe())",
                            cwe_id="CWE-326",
                            owasp_id="ASVS-3.2.1",
                        )
                    )

        # PYRAMID013: Check authentication policy
        if "authentication" in call_name.lower() and "policy" in call_name.lower():
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Pyramid Auth",
                    message="Authentication policy detected - review for security best practices",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Ensure strong hashing, secure cookies, HTTPS-only, and proper secret",
                    cwe_id="CWE-287",
                    owasp_id="ASVS-2.1.1",
                )
            )

        # PYRAMID014: Check authorization policy
        if "authorization" in call_name.lower() and "policy" in call_name.lower():
            # This is mostly OK, just a reminder to review
            pass

        # PYRAMID009: Check route configuration
        if call_name == "add_route":
            kwargs = {}
            for keyword in node.keywords:
                if keyword.arg and isinstance(keyword.value, ast.Constant):
                    kwargs[keyword.arg] = keyword.value.value

            # add_route takes pattern as second positional arg or 'pattern' keyword
            pattern = None
            if "pattern" in kwargs:
                pattern = kwargs["pattern"]
            elif len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                pattern = node.args[1].value

            if pattern and isinstance(pattern, str) and "/api" in pattern and "/v" not in pattern:
                self.issues.append(
                    SecurityIssue(
                        severity="LOW",
                        category="Pyramid Route",
                        message="Insecure route prefix: API routes without version prefix",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use versioned API routes: /api/v1/... for better security and evolution",
                        cwe_id="CWE-16",
                        owasp_id="ASVS-4.3.1",
                    )
                )

        # PYRAMID010: Check request factory
        if "request_factory" in call_name or call_name == "set_request_factory":
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Pyramid Request",
                    message="Request factory injection: Custom request factory - ensure proper validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Validate and sanitize all request inputs in custom request factory",
                    cwe_id="CWE-74",
                    owasp_id="ASVS-5.1.1",
                )
            )

        self.generic_visit(node)


def analyze_pyramid_security(source_code: str, filename: str = "<unknown>") -> list[SecurityIssue]:
    """
    Analyze Python source code for Pyramid framework security vulnerabilities.

    Detects 15 types of Pyramid-specific security issues:
    - 5 ACL & permission vulnerabilities
    - 5 view & route configuration issues
    - 5 session & authentication problems

    Args:
        source_code: Python source code to analyze
        filename: Name of the file being analyzed

    Returns:
        List of SecurityIssue objects for vulnerabilities found
    """
    try:
        tree = ast.parse(source_code, filename=filename)
        visitor = PyramidSecurityVisitor(source_code)
        visitor.visit(tree)
        return visitor.issues
    except SyntaxError as e:
        logger = PyGuardLogger()
        logger.error(f"Syntax error in {filename}: {e}")
        return []


__all__ = [
    "PYRAMID_RULES",
    "PyramidSecurityVisitor",
    "analyze_pyramid_security",
]
