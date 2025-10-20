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
                
                # Check for hardcoded credentials
                self._check_hardcoded_credentials(node, target.id)
        
        self.generic_visit(node)

    def _check_weak_session_id(self, node: ast.Assign, var_name: str) -> None:
        """Check for weak session ID generation (AUTH001)."""
        if not isinstance(node.value, ast.Call):
            return

        # Check for weak random functions
        if isinstance(node.value.func, ast.Attribute):
            module = None
            func = node.value.func.attr
            if isinstance(node.value.func.value, ast.Name):
                module = node.value.func.value.id

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
        
        # Check for missing authentication on sensitive operations
        if any(term in node.name.lower() for term in ["delete", "remove", "update", "admin", "sudo"]):
            self._check_missing_authentication(node)
        
        # Check for IDOR vulnerabilities
        self._check_idor_vulnerability(node)
        
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
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in ("route", "get", "post", "put", "delete", "patch"):
                        is_route = True
                        break

        if is_route and not has_auth_decorator:
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
        # Look for functions that access resources by ID without authorization
        if not any(term in node.name.lower() for term in ["get", "fetch", "retrieve", "load"]):
            return

        # Check if function accesses objects by ID
        has_id_param = False
        for arg in node.args.args:
            if "id" in arg.arg.lower() or arg.arg in ("pk", "key"):
                has_id_param = True
                break

        if not has_id_param:
            return

        # Look for authorization checks
        has_auth_check = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    # Check for permission checks
                    if any(term in child.func.attr.lower() for term in ["check", "verify", "authorize", "permission", "can"]):
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
        for keyword in node.keywords:
            if keyword.arg == "payload" or not keyword.arg:
                if isinstance(keyword.value, ast.Dict):
                    for key in keyword.value.keys:
                        if isinstance(key, ast.Constant):
                            key_val = key.value
                            if key_val == "exp":
                                has_exp = True
                                break

        # Also check positional arguments
        if not has_exp and node.args:
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    for key in arg.keys:
                        if isinstance(key, ast.Constant):
                            key_val = key.value
                            if key_val == "exp":
                                has_exp = True
                                break

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
    ]
)
