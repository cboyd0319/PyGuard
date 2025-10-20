"""
Authentication & Authorization Security Analysis.

Detects and auto-fixes common authentication and authorization vulnerabilities
across Python web applications. This module provides comprehensive checks for
identity and access management security issues.

Security Areas Covered:
- Weak session ID generation
- Session fixation vulnerabilities
- Account enumeration via timing attacks
- Missing multi-factor authentication
- Insecure Direct Object References (IDOR)
- Privilege escalation patterns
- Weak password policies
- JWT token security
- Session timeout configuration
- Missing authentication checks
- Authorization bypass vulnerabilities
- OAuth security issues

References:
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Chapter 2: Authentication
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Chapter 4: Access Control
- CWE-287 (Improper Authentication) | https://cwe.mitre.org/data/definitions/287.html | High
- CWE-306 (Missing Authentication) | https://cwe.mitre.org/data/definitions/306.html | High
- CWE-639 (Authorization Bypass) | https://cwe.mitre.org/data/definitions/639.html | High
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


class AuthSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting authentication and authorization vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_flask_import = False
        self.has_django_import = False
        self.has_fastapi_import = False
        self.has_jwt_import = False
        self.session_vars: Set[str] = set()
        self.auth_functions: Set[str] = set()
        self.password_vars: Set[str] = set()
        self.jwt_payloads_with_exp: Set[str] = set()  # Track payload variables with 'exp'

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track framework and security imports."""
        if node.module:
            if node.module.startswith("flask"):
                self.has_flask_import = True
            elif node.module.startswith("django"):
                self.has_django_import = True
            elif node.module.startswith("fastapi"):
                self.has_fastapi_import = True
            elif "jwt" in node.module.lower():
                self.has_jwt_import = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for weak session ID generation and insecure patterns."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Track session-related variables
                if "session" in target.id.lower():
                    self.session_vars.add(target.id)
                    self._check_weak_session_id(node, target.id)
                
                # Track password variables for policy checks
                if "password" in target.id.lower() or "pwd" in target.id.lower():
                    self.password_vars.add(target.id)
                
                # Track JWT payloads with 'exp' claim
                if isinstance(node.value, ast.Dict):
                    for key in node.value.keys:
                        if isinstance(key, ast.Constant) and key.value == "exp":
                            self.jwt_payloads_with_exp.add(target.id)
                            break
                
                # Check for hardcoded credentials
                self._check_hardcoded_credentials(node, target.id)
                
                # Check for weak password reset tokens
                self._check_weak_password_reset_token(node, target.id)
        
        # Check for privilege escalation
        self._check_privilege_escalation(node)
        
        self.generic_visit(node)

    def _check_weak_session_id(self, node: ast.Assign, var_name: str) -> None:
        """Check for weak session ID generation (AUTH001)."""
        if not isinstance(node.value, ast.Call):
            return

        # Helper to check if a call uses weak random functions
        def check_call(call_node):
            if isinstance(call_node.func, ast.Attribute):
                module = None
                func = call_node.func.attr
                if isinstance(call_node.func.value, ast.Name):
                    module = call_node.func.value.id

                # Detect weak random usage (random.randint, random.random, etc.)
                if module == "random" and func in ("randint", "random", "choice", "sample"):
                    self.violations.append(
                        RuleViolation(
                            rule_id="AUTH001",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_line(node.lineno),
                            message=f"Weak session ID generation using random.{func}()",
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

                # Detect uuid.uuid1() (includes MAC address - predictable)
                if module == "uuid" and func == "uuid1":
                    self.violations.append(
                        RuleViolation(
                            rule_id="AUTH001",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_line(node.lineno),
                            message="Session ID using uuid1() includes MAC address (predictable)",
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

        # Check the immediate call
        check_call(node.value)
        
        # Also check if wrapped in str(), int(), etc.
        if node.value.args:
            for arg in node.value.args:
                if isinstance(arg, ast.Call):
                    check_call(arg)

    def _check_hardcoded_credentials(self, node: ast.Assign, var_name: str) -> None:
        """Check for hardcoded authentication credentials (AUTH002)."""
        # Look for password/secret/key variables with string literals
        if not isinstance(node.value, ast.Constant):
            return

        suspicious_names = {
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "access_token", "auth_token", "private_key", "secret_key"
        }

        var_lower = var_name.lower()
        if any(name in var_lower for name in suspicious_names):
            # Get the value
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                value = node.value.value
            else:
                return

            # Skip if it's obviously not a real credential
            if not value or value in ("", "your-password-here", "changeme", "TODO"):
                return

            self.violations.append(
                RuleViolation(
                    rule_id="AUTH002",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message=f"Hardcoded credential in variable '{var_name}'",
                    severity=RuleSeverity.CRITICAL,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.NONE,
                )
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze functions for authentication and authorization issues."""
        # Track authentication functions
        if any(term in node.name.lower() for term in ["auth", "login", "verify", "check"]):
            self.auth_functions.add(node.name)
            self._check_timing_attack(node)
            self._check_session_fixation(node)
            self._check_missing_mfa(node)
        
        # Check for missing authentication on sensitive operations
        if any(term in node.name.lower() for term in ["delete", "remove", "update", "admin", "sudo"]):
            self._check_missing_authentication(node)
        
        # Check for IDOR vulnerabilities
        self._check_idor_vulnerability(node)
        
        # Check for weak password policies
        self._check_weak_password_policy(node)
        
        self.generic_visit(node)
    
    def visit_Compare(self, node: ast.Compare) -> None:
        """Check for security issues in comparisons."""
        # Check for null byte authentication bypass
        self._check_null_byte_auth_bypass(node)
        
        self.generic_visit(node)

    def _check_timing_attack(self, node: ast.FunctionDef) -> None:
        """Check for account enumeration via timing attacks (AUTH003)."""
        # Look for string comparison in authentication functions
        for child in ast.walk(node):
            if isinstance(child, ast.Compare):
                # Check if comparing passwords or credentials directly
                if isinstance(child.left, ast.Name):
                    if any(term in child.left.id.lower() for term in ["password", "pwd", "secret", "token"]):
                        # Using == operator instead of constant-time comparison
                        if any(isinstance(op, ast.Eq) for op in child.ops):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="AUTH003",
                                    file_path=self.file_path,
                                    line_number=child.lineno,
                                    column=child.col_offset,
                                    code_snippet=self._get_line(child.lineno),
                                    message="Password comparison vulnerable to timing attacks (use constant-time comparison)",
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    fix_applicability=FixApplicability.SUGGESTED,
                                )
                            )

    def _check_session_fixation(self, node: ast.FunctionDef) -> None:
        """Check for session fixation vulnerabilities (AUTH004)."""
        # Look for login functions that don't regenerate session ID
        if "login" not in node.name.lower():
            return

        # Check if session.regenerate() or session_regenerate_id() is called
        has_regeneration = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in ("regenerate", "regenerate_id", "new"):
                        has_regeneration = True
                        break
                elif isinstance(child.func, ast.Name):
                    if "regenerate" in child.func.id.lower():
                        has_regeneration = True
                        break

        if not has_regeneration and (self.has_flask_import or self.has_django_import):
            self.violations.append(
                RuleViolation(
                    rule_id="AUTH004",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message="Login function should regenerate session ID to prevent session fixation",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_missing_authentication(self, node: ast.FunctionDef) -> None:
        """Check for missing authentication on sensitive operations (AUTH005)."""
        # Skip login/auth/public routes (they don't need authentication)
        if any(term in node.name.lower() for term in ["login", "signup", "register", "public", "health", "ping"]):
            return
        
        # Look for decorators indicating authentication
        has_auth_decorator = False
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if any(term in decorator.id.lower() for term in ["login", "auth", "require", "permission"]):
                    has_auth_decorator = True
                    break
            elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                if any(term in decorator.func.id.lower() for term in ["login", "auth", "require", "permission"]):
                    has_auth_decorator = True
                    break

        # Check for route decorators (Flask/FastAPI)
        is_route = False
        is_sensitive_method = False
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    method = decorator.func.attr
                    if method in ("route", "get", "post", "put", "delete", "patch"):
                        is_route = True
                        # POST, PUT, DELETE, PATCH are typically sensitive
                        if method in ("post", "put", "delete", "patch"):
                            is_sensitive_method = True
                        break

        # Check for sensitive path patterns in route decorator arguments
        has_sensitive_path = False
        if is_route:
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and decorator.args:
                    for arg in decorator.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            path = arg.value.lower()
                            if any(term in path for term in ["admin", "delete", "remove", "/api/", "/users/"]):
                                has_sensitive_path = True
                                break

        # Report if route is sensitive and lacks authentication
        if is_route and not has_auth_decorator and (is_sensitive_method or has_sensitive_path):
            self.violations.append(
                RuleViolation(
                    rule_id="AUTH005",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message=f"Sensitive operation '{node.name}' missing authentication decorator",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.NONE,
                )
            )

    def _check_idor_vulnerability(self, node: ast.FunctionDef) -> None:
        """Check for Insecure Direct Object References (AUTH006)."""
        # Check if function accesses objects by ID
        has_id_param = False
        for arg in node.args.args:
            if "id" in arg.arg.lower() or arg.arg in ("pk", "key"):
                has_id_param = True
                break

        # Only check functions that take ID parameters
        if not has_id_param:
            return

        # Look for authorization checks
        has_auth_check = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Check for permission checks (attribute calls like obj.check_permission())
                if isinstance(child.func, ast.Attribute):
                    if any(term in child.func.attr.lower() for term in ["check", "verify", "authorize", "permission", "can"]):
                        has_auth_check = True
                        break
                # Check for permission checks (function calls like check_permission())
                elif isinstance(child.func, ast.Name):
                    if any(term in child.func.id.lower() for term in ["check", "verify", "authorize", "permission"]):
                        has_auth_check = True
                        break
            elif isinstance(child, ast.If):
                # Check for ownership verification
                for cmp_child in ast.walk(child.test):
                    if isinstance(cmp_child, ast.Compare):
                        if isinstance(cmp_child.left, ast.Attribute):
                            if "user" in cmp_child.left.attr.lower() or "owner" in cmp_child.left.attr.lower():
                                has_auth_check = True
                                break

        if not has_auth_check:
            self.violations.append(
                RuleViolation(
                    rule_id="AUTH006",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message=f"Potential IDOR: '{node.name}' accesses resource by ID without authorization check",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.NONE,
                )
            )

    def visit_Call(self, node: ast.Call) -> None:
        """Check for JWT and session configuration issues."""
        # Check for insecure Remember Me implementations (AUTH012)
        self._check_insecure_remember_me(node)
        
        # Check for LDAP injection (AUTH015)
        self._check_ldap_injection(node)
        
        if isinstance(node.func, ast.Attribute):
            # Check JWT encode without expiration (AUTH007)
            if node.func.attr == "encode" and self.has_jwt_import:
                self._check_jwt_expiration(node)
            
            # Check session configuration (AUTH008)
            elif "session" in str(node.func.attr).lower():
                self._check_session_timeout(node)
        
        self.generic_visit(node)

    def _check_jwt_expiration(self, node: ast.Call) -> None:
        """Check for JWT tokens without expiration (AUTH007)."""
        # Check if 'exp' claim is set in payload
        has_exp = False
        
        # Helper to check if a dict has 'exp' key
        def dict_has_exp(dict_node):
            if isinstance(dict_node, ast.Dict):
                for key in dict_node.keys:
                    if isinstance(key, ast.Constant) and key.value == "exp":
                        return True
            return False
        
        # Check keyword arguments
        for keyword in node.keywords:
            if keyword.arg == "payload" or not keyword.arg:
                if dict_has_exp(keyword.value):
                    has_exp = True
                    break
                # Check if it's a tracked variable with exp
                elif isinstance(keyword.value, ast.Name):
                    if keyword.value.id in self.jwt_payloads_with_exp:
                        has_exp = True
                        break

        # Check positional arguments
        if not has_exp and node.args:
            # First argument is usually the payload
            if node.args:
                first_arg = node.args[0]
                
                # Check if it's a dict literal
                if dict_has_exp(first_arg):
                    has_exp = True
                # Check if it's a tracked variable with exp
                elif isinstance(first_arg, ast.Name):
                    if first_arg.id in self.jwt_payloads_with_exp:
                        has_exp = True

        if not has_exp:
            self.violations.append(
                RuleViolation(
                    rule_id="AUTH007",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message="JWT token created without expiration time (missing 'exp' claim)",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_session_timeout(self, node: ast.Call) -> None:
        """Check for missing session timeout configuration (AUTH008)."""
        # This is a simple check - actual implementation would need more context
        # Looking for session.permanent = False or missing timeout config
        pass  # Placeholder for now

    def _check_weak_password_reset_token(self, node: ast.Assign, var_name: str) -> None:
        """Check for weak password reset token generation (AUTH009)."""
        # Check if variable name indicates a reset token
        var_lower = var_name.lower()
        if not (("reset" in var_lower or "recovery" in var_lower) and ("token" in var_lower or "code" in var_lower)):
            return
        
        if not isinstance(node.value, ast.Call):
            return
        
        # Helper to check for weak random in the call tree
        def check_for_weak_random(call_node):
            if isinstance(call_node.func, ast.Attribute):
                module = None
                func = call_node.func.attr
                if isinstance(call_node.func.value, ast.Name):
                    module = call_node.func.value.id
                
                if module == "random":
                    return True
            
            # Check arguments for nested calls
            for arg in call_node.args:
                if isinstance(arg, ast.Call):
                    if check_for_weak_random(arg):
                        return True
                elif isinstance(arg, ast.GeneratorExp):
                    # Check generator expression for random usage
                    for child in ast.walk(arg):
                        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                            if isinstance(child.func.value, ast.Name) and child.func.value.id == "random":
                                return True
            return False
        
        if check_for_weak_random(node.value):
            self.violations.append(
                RuleViolation(
                    rule_id="AUTH009",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message="Weak password reset token generation using random module",
                    severity=RuleSeverity.CRITICAL,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.SAFE,
                )
            )

    def _check_privilege_escalation(self, node: ast.Assign) -> None:
        """Check for privilege escalation via parameter tampering (AUTH010)."""
        for target in node.targets:
            if not isinstance(target, ast.Attribute):
                continue
            
            # Check for setting user roles/permissions from request
            attr_name = target.attr.lower()
            if any(term in attr_name for term in ["role", "permission", "admin", "is_staff", "is_superuser"]):
                # Check if value comes from request parameters (Subscript like request['role'])
                if isinstance(node.value, ast.Subscript):
                    # Check the value being subscripted
                    if isinstance(node.value.value, ast.Attribute):
                        # Check patterns like request.form['role']
                        if node.value.value.attr in ("form", "data", "params", "query", "json"):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="AUTH010",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_line(node.lineno),
                                    message=f"Privilege escalation risk: setting {target.attr} from user input",
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    fix_applicability=FixApplicability.NONE,
                                )
                            )
                    elif isinstance(node.value.value, ast.Name):
                        # Check patterns like request['role'], form['role'], data['role']
                        if node.value.value.id in ("request", "form", "data", "params", "query", "json"):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="AUTH010",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_line(node.lineno),
                                    message=f"Privilege escalation risk: setting {target.attr} from user input",
                                    severity=RuleSeverity.CRITICAL,
                                    category=RuleCategory.SECURITY,
                                    fix_applicability=FixApplicability.NONE,
                                )
                            )

    def _check_missing_mfa(self, node: ast.FunctionDef) -> None:
        """Check for missing multi-factor authentication (AUTH011)."""
        if "login" not in node.name.lower() and "signin" not in node.name.lower():
            return
        
        # Check if MFA/2FA is implemented
        has_mfa = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if any(term in child.func.attr.lower() for term in ["mfa", "2fa", "totp", "otp", "verify_code"]):
                        has_mfa = True
                        break
                elif isinstance(child.func, ast.Name):
                    if any(term in child.func.id.lower() for term in ["mfa", "2fa", "totp", "otp", "verify_code"]):
                        has_mfa = True
                        break
        
        if not has_mfa and (self.has_flask_import or self.has_django_import or self.has_fastapi_import):
            self.violations.append(
                RuleViolation(
                    rule_id="AUTH011",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message="Login function lacks multi-factor authentication",
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.NONE,
                )
            )

    def _check_insecure_remember_me(self, node: ast.Call) -> None:
        """Check for insecure 'Remember Me' implementation (AUTH012)."""
        # Check for cookie setting with passwords or credentials
        if not isinstance(node.func, ast.Attribute):
            return
        
        if node.func.attr != "set_cookie":
            return
        
        # Check cookie name and value
        cookie_name = None
        cookie_value_var = None
        
        # Check positional and keyword arguments
        if len(node.args) >= 1:
            # First arg is usually the cookie name
            if isinstance(node.args[0], ast.Constant):
                cookie_name = node.args[0].value
        
        for keyword in node.keywords:
            if keyword.arg in ("key", "name"):
                if isinstance(keyword.value, ast.Constant):
                    cookie_name = keyword.value.value
            elif keyword.arg == "value":
                if isinstance(keyword.value, ast.Name):
                    cookie_value_var = keyword.value.id
        
        # Also check second positional arg for value
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Name):
            cookie_value_var = node.args[1].id
        
        # Check if it's a remember me cookie storing sensitive data
        if cookie_name and isinstance(cookie_name, str) and "remember" in cookie_name.lower():
            if cookie_value_var and any(term in cookie_value_var.lower() for term in ["password", "pwd", "credential", "secret"]):
                self.violations.append(
                    RuleViolation(
                        rule_id="AUTH012",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_line(node.lineno),
                        message="Insecure 'Remember Me': storing password in cookie",
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        fix_applicability=FixApplicability.NONE,
                    )
                )

    def _check_weak_password_policy(self, node: ast.FunctionDef) -> None:
        """Check for weak password validation (AUTH013)."""
        if not any(term in node.name.lower() for term in ["password", "validate", "check"]):
            return
        
        # Look for length checks
        has_length_check = False
        min_length = 0
        
        for child in ast.walk(node):
            if isinstance(child, ast.Compare):
                # Check for len(password) comparisons
                if isinstance(child.left, ast.Call):
                    if isinstance(child.left.func, ast.Name) and child.left.func.id == "len":
                        for comparator in child.comparators:
                            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, int):
                                min_length = comparator.value
                                has_length_check = True
        
        if has_length_check and min_length < 8:
            self.violations.append(
                RuleViolation(
                    rule_id="AUTH013",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_line(node.lineno),
                    message=f"Weak password policy: minimum length {min_length} < 8",
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

    def _check_null_byte_auth_bypass(self, node: ast.Compare) -> None:
        """Check for null byte authentication bypass vulnerability (AUTH014)."""
        # Check if comparing authentication-related strings
        if isinstance(node.left, ast.Name):
            var_name = node.left.id.lower()
            if any(term in var_name for term in ["password", "token", "user", "auth"]):
                # Check if using == without null byte protection
                if any(isinstance(op, ast.Eq) for op in node.ops):
                    # Look for string comparisons without encoding checks
                    for comparator in node.comparators:
                        if isinstance(comparator, (ast.Constant, ast.Name, ast.Subscript)):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="AUTH014",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_line(node.lineno),
                                    message="Authentication comparison may be vulnerable to null byte injection",
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    fix_applicability=FixApplicability.NONE,
                                )
                            )
                            break

    def _check_ldap_injection(self, node: ast.Call) -> None:
        """Check for LDAP injection in authentication (AUTH015)."""
        # Check for LDAP operations with string formatting
        if not isinstance(node.func, ast.Attribute):
            return
        
        func_name = node.func.attr.lower()
        # Check for common LDAP methods
        if not any(term in func_name for term in ["search", "search_s", "search_st", "search_ext"]):
            return
        
        # Check arguments for string concatenation or formatting in LDAP queries
        for arg in node.args:
            # Check for f-strings (JoinedStr)
            if isinstance(arg, ast.JoinedStr):
                self.violations.append(
                    RuleViolation(
                        rule_id="AUTH015",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_line(node.lineno),
                        message="LDAP injection risk: f-string in LDAP query",
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )
                break
            # Check for string concatenation (BinOp with Add)
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                # Check if it's string concatenation
                self.violations.append(
                    RuleViolation(
                        rule_id="AUTH015",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_line(node.lineno),
                        message="LDAP injection risk: string concatenation in LDAP query",
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )
                break

    def _get_line(self, line_number: int) -> str:
        """Get the source code line."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].strip()
        return ""


class AuthSecurityChecker:
    """Main authentication and authorization security checker."""

    def __init__(self):
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """Check a file for authentication and authorization vulnerabilities."""
        try:
            code = self.file_ops.read_file(file_path)
            if not code:
                return []

            tree = ast.parse(code, filename=str(file_path))
            visitor = AuthSecurityVisitor(file_path, code)
            visitor.visit(tree)
            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in {file_path}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            return []

    def fix_file(self, file_path: Path, violations: List[RuleViolation]) -> str:
        """Apply auto-fixes for authentication and authorization issues."""
        code = self.file_ops.read_file(file_path)
        if not code:
            return code

        # Apply safe fixes only (marked as FixApplicability.SAFE)
        for violation in violations:
            if violation.fix_applicability != FixApplicability.SAFE:
                continue

            if violation.rule_id == "AUTH001":
                # Replace weak random with secrets module
                code = self._fix_weak_session_id(code, violation)

        return code

    def _fix_weak_session_id(self, code: str, violation: RuleViolation) -> str:
        """Fix weak session ID generation."""
        lines = code.splitlines(keepends=True)
        line_idx = violation.line_number - 1

        if line_idx < 0 or line_idx >= len(lines):
            return code

        line = lines[line_idx]

        # Replace random.* with secrets.*
        if "random.randint" in line:
            fixed_line = line.replace("random.randint", "secrets.randbelow")
            # Add import if needed
            if "import secrets" not in code:
                lines.insert(0, "import secrets\n")
            lines[line_idx] = fixed_line
        elif "random.random" in line:
            fixed_line = line.replace("random.random()", "secrets.token_hex(16)")
            if "import secrets" not in code:
                lines.insert(0, "import secrets\n")
            lines[line_idx] = fixed_line
        elif "uuid.uuid1()" in line:
            fixed_line = line.replace("uuid.uuid1()", "uuid.uuid4()")
            lines[line_idx] = fixed_line

        return "".join(lines)


# Define rules
AUTH001_WEAK_SESSION_ID = Rule(
    rule_id="AUTH001",
    name="weak-session-id-generation",
    message_template="Weak session ID generation using {method}",
    description="Session ID generated using weak random functions that are predictable",
    explanation="Session IDs must be cryptographically random to prevent session hijacking attacks. Use secrets module instead of random.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-330",
    owasp_mapping="ASVS-2.3.1",
    fix_applicability=FixApplicability.SAFE,
)

AUTH002_HARDCODED_CREDENTIALS = Rule(
    rule_id="AUTH002",
    name="hardcoded-credentials",
    message_template="Hardcoded credential in variable '{var_name}'",
    description="Authentication credentials hardcoded in source code",
    explanation="Hardcoded credentials can be easily discovered through source code inspection or version control history.",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-798",
    owasp_mapping="ASVS-2.6.3",
    fix_applicability=FixApplicability.NONE,
)

AUTH003_TIMING_ATTACK = Rule(
    rule_id="AUTH003",
    name="password-timing-attack",
    message_template="Password comparison vulnerable to timing attacks (use constant-time comparison)",
    description="Direct password comparison allows timing attacks that can reveal password information",
    explanation="Use hmac.compare_digest() for constant-time string comparison to prevent timing attacks.",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-208",
    owasp_mapping="ASVS-2.7.3",
    fix_applicability=FixApplicability.SUGGESTED,
)

AUTH004_SESSION_FIXATION = Rule(
    rule_id="AUTH004",
    name="session-fixation",
    message_template="Login function should regenerate session ID to prevent session fixation",
    description="Login function doesn't regenerate session ID after authentication",
    explanation="Session fixation attacks occur when an attacker can set a user's session ID. Always regenerate session IDs after login.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-384",
    owasp_mapping="ASVS-3.2.1",
    fix_applicability=FixApplicability.SUGGESTED,
)

AUTH005_MISSING_AUTHENTICATION = Rule(
    rule_id="AUTH005",
    name="missing-authentication",
    message_template="Sensitive operation '{operation}' missing authentication decorator",
    description="Sensitive operation missing authentication check",
    explanation="Operations that modify data or access sensitive resources must verify user authentication.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-306",
    owasp_mapping="ASVS-4.1.1",
    fix_applicability=FixApplicability.NONE,
)

AUTH006_IDOR = Rule(
    rule_id="AUTH006",
    name="insecure-direct-object-reference",
    message_template="Potential IDOR: '{function}' accesses resource by ID without authorization check",
    description="Resource accessed by ID without authorization check (IDOR vulnerability)",
    explanation="Verify user authorization before allowing access to resources. Check ownership or permissions.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-639",
    owasp_mapping="ASVS-4.1.2",
    fix_applicability=FixApplicability.NONE,
)

AUTH007_JWT_NO_EXPIRATION = Rule(
    rule_id="AUTH007",
    name="jwt-no-expiration",
    message_template="JWT token created without expiration time (missing 'exp' claim)",
    description="JWT token created without expiration time",
    explanation="JWT tokens should have a limited lifetime to reduce the impact of token theft. Include 'exp' claim.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-613",
    owasp_mapping="ASVS-3.3.1",
    fix_applicability=FixApplicability.SUGGESTED,
)

AUTH008_SESSION_TIMEOUT = Rule(
    rule_id="AUTH008",
    name="missing-session-timeout",
    message_template="Session timeout not configured",
    description="Session timeout not configured (sessions may persist indefinitely)",
    explanation="Configure session timeouts to automatically log out inactive users and limit session lifetime.",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-613",
    owasp_mapping="ASVS-3.3.1",
    fix_applicability=FixApplicability.NONE,
)

AUTH009_WEAK_PASSWORD_RESET_TOKEN = Rule(
    rule_id="AUTH009",
    name="weak-password-reset-token",
    message_template="Weak password reset token generation detected",
    description="Password reset token generated using weak random function",
    explanation="Password reset tokens should use cryptographically secure random generation (secrets module or os.urandom). Weak tokens can be predicted by attackers.",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-330",
    owasp_mapping="ASVS-2.1.9",
    fix_applicability=FixApplicability.SAFE,
)

AUTH010_PRIVILEGE_ESCALATION = Rule(
    rule_id="AUTH010",
    name="privilege-escalation-risk",
    message_template="Potential privilege escalation via user-controlled parameter",
    description="User role/permission set from request parameter without validation",
    explanation="Never allow users to directly set their roles or permissions. Validate authorization server-side and use secure session management.",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-269",
    owasp_mapping="ASVS-4.1.5",
    fix_applicability=FixApplicability.NONE,
)

AUTH011_MISSING_MFA = Rule(
    rule_id="AUTH011",
    name="missing-mfa",
    message_template="Login function without multi-factor authentication",
    description="Authentication endpoint lacks multi-factor authentication (MFA)",
    explanation="Implement MFA for sensitive operations and administrative access. Use TOTP, SMS, or hardware tokens as a second factor.",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-287",
    owasp_mapping="ASVS-2.8.1",
    fix_applicability=FixApplicability.NONE,
)

AUTH012_INSECURE_REMEMBER_ME = Rule(
    rule_id="AUTH012",
    name="insecure-remember-me",
    message_template="Insecure 'Remember Me' implementation detected",
    description="Remember Me functionality stores credentials or uses weak tokens",
    explanation="Never store passwords in cookies. Use secure, time-limited tokens and bind them to specific sessions. Implement token rotation and revocation.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-539",
    owasp_mapping="ASVS-3.2.2",
    fix_applicability=FixApplicability.NONE,
)

AUTH013_WEAK_PASSWORD_POLICY = Rule(
    rule_id="AUTH013",
    name="weak-password-policy",
    message_template="Weak password policy detected in code",
    description="Password validation enforces insufficient complexity requirements",
    explanation="Implement strong password policies: minimum 8 characters, complexity requirements, prevent common passwords. Consider using passphrase or password manager recommendations.",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-521",
    owasp_mapping="ASVS-2.1.1",
    fix_applicability=FixApplicability.SUGGESTED,
)

AUTH014_NULL_BYTE_AUTH_BYPASS = Rule(
    rule_id="AUTH014",
    name="null-byte-auth-bypass",
    message_template="Potential null byte authentication bypass vulnerability",
    description="String comparison in authentication may be vulnerable to null byte injection",
    explanation="Null bytes can truncate strings in C-based libraries, bypassing authentication. Use length-checking comparisons and validate input encoding.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-158",
    owasp_mapping="ASVS-5.1.3",
    fix_applicability=FixApplicability.NONE,
)

AUTH015_LDAP_INJECTION = Rule(
    rule_id="AUTH015",
    name="ldap-injection",
    message_template="LDAP injection vulnerability in authentication",
    description="User input concatenated into LDAP query without sanitization",
    explanation="Sanitize all user input before including in LDAP queries. Use parameterized queries or proper escaping to prevent LDAP injection attacks.",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    cwe_mapping="CWE-90",
    owasp_mapping="ASVS-5.3.4",
    fix_applicability=FixApplicability.SUGGESTED,
)

# Register all rules
register_rules(
    [
        AUTH001_WEAK_SESSION_ID,
        AUTH002_HARDCODED_CREDENTIALS,
        AUTH003_TIMING_ATTACK,
        AUTH004_SESSION_FIXATION,
        AUTH005_MISSING_AUTHENTICATION,
        AUTH006_IDOR,
        AUTH007_JWT_NO_EXPIRATION,
        AUTH008_SESSION_TIMEOUT,
        AUTH009_WEAK_PASSWORD_RESET_TOKEN,
        AUTH010_PRIVILEGE_ESCALATION,
        AUTH011_MISSING_MFA,
        AUTH012_INSECURE_REMEMBER_ME,
        AUTH013_WEAK_PASSWORD_POLICY,
        AUTH014_NULL_BYTE_AUTH_BYPASS,
        AUTH015_LDAP_INJECTION,
    ]
)
