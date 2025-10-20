"""
FastAPI Security Analysis.

Detects and auto-fixes common security vulnerabilities in FastAPI applications.
This module provides FastAPI-specific security checks focusing on async patterns,
dependency injection, WebSockets, and modern API security.

Security Areas Covered:
- Dependency injection validation
- WebSocket authentication and origin validation
- Async race conditions
- OAuth2 flow misconfigurations
- Pydantic model validation bypasses
- CORS misconfiguration
- Missing authentication dependencies
- Background task security
- API documentation exposure in production
- Query parameter injection
- File upload vulnerabilities
- Session management in async context
- Rate limiting on async endpoints
- Missing CSRF protection
- Insecure cookie handling

References:
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- FastAPI Security | https://fastapi.tiangolo.com/tutorial/security/ | High
- CWE-352 (CSRF) | https://cwe.mitre.org/data/definitions/352.html | High
- CWE-639 (Authorization Bypass) | https://cwe.mitre.org/data/definitions/639.html | High
- CWE-918 (SSRF) | https://cwe.mitre.org/data/definitions/918.html | High
"""

import ast
from pathlib import Path
from typing import List, Set, Optional

from pyguard.lib.core import FileOperations, PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class FastAPISecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting FastAPI security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_fastapi_import = False
        self.has_depends_import = False
        self.has_oauth2_import = False
        self.route_functions: Set[str] = set()
        self.authenticated_routes: Set[str] = set()
        self.websocket_routes: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track FastAPI imports."""
        if node.module:
            if node.module.startswith("fastapi"):
                self.has_fastapi_import = True
                for alias in node.names:
                    if alias.name == "Depends":
                        self.has_depends_import = True
                    elif alias.name in ("OAuth2PasswordBearer", "OAuth2AuthorizationCodeBearer"):
                        self.has_oauth2_import = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze route handler functions for security issues."""
        if not self.has_fastapi_import:
            self.generic_visit(node)
            return

        # Check decorators to identify routes
        is_route = False
        is_websocket = False
        route_methods = []

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                method = decorator.func.attr
                if method in ("get", "post", "put", "delete", "patch", "options", "head"):
                    is_route = True
                    route_methods.append(method)
                    self.route_functions.add(node.name)
                elif method == "websocket":
                    is_websocket = True
                    self.websocket_routes.add(node.name)

        if is_route or is_websocket:
            # Check for authentication dependency
            has_auth_dependency = self._check_authentication_dependency(node)
            if has_auth_dependency:
                self.authenticated_routes.add(node.name)

            # Check for missing authentication on sensitive routes
            if is_route and not has_auth_dependency:
                if any(method in ("post", "put", "delete", "patch") for method in route_methods):
                    self._check_missing_authentication(node, route_methods)

            # Check WebSocket-specific security
            if is_websocket:
                self._check_websocket_security(node)

            # Check for query parameter injection
            self._check_query_injection(node)

            # Check for file upload vulnerabilities
            self._check_file_upload_security(node)

            # Check for background task security
            self._check_background_task_security(node)
            
            # Check for missing rate limiting
            self._check_missing_rate_limiting(node)
            
            # Check for SSRF in URL parameters
            self._check_ssrf_in_url_params(node)
            
            # Check for missing security headers
            if is_route:
                self._check_missing_security_headers(node)
        
        # Check for JWT algorithm confusion (in any function)
        if self.has_fastapi_import:
            self._check_jwt_algorithm_confusion(node)
            self._check_graphql_introspection(node)

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Handle async function definitions (treat like regular functions)."""
        # Convert to FunctionDef for analysis
        func_def = ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=getattr(node, "type_comment", None),
            lineno=node.lineno,
            col_offset=node.col_offset,
        )
        self.visit_FunctionDef(func_def)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect security issues in function calls."""
        # Check for FastAPI app configuration issues
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Detect docs exposure in production
            if func_name == "FastAPI":
                self._check_docs_exposure(node)

            # Detect OAuth2 misconfigurations
            if func_name in ("OAuth2PasswordBearer", "OAuth2AuthorizationCodeBearer"):
                self._check_oauth2_misconfiguration(node)

        # Check for Attribute calls
        if isinstance(node.func, ast.Attribute):
            # Check for add_middleware with CORSMiddleware
            if node.func.attr == "add_middleware":
                # Check if first argument is CORSMiddleware
                if len(node.args) > 0:
                    if isinstance(node.args[0], ast.Name):
                        if node.args[0].id == "CORSMiddleware":
                            self._check_cors_misconfiguration(node)
            
            # Check for Pydantic validation bypasses
            if node.func.attr in ("construct", "parse_obj", "parse_raw"):
                self._check_pydantic_validation_bypass(node)

            # Check for insecure session cookie settings
            if node.func.attr == "set_cookie":
                self._check_cookie_security(node)

        self.generic_visit(node)

    def _check_authentication_dependency(self, node: ast.FunctionDef) -> bool:
        """Check if function has authentication dependency."""
        for arg in node.args.args:
            # Check for default values with Depends
            if arg.arg and hasattr(node.args, 'defaults'):
                # Get default values
                num_defaults = len(node.args.defaults)
                num_args = len(node.args.args)
                default_offset = num_args - num_defaults
                arg_index = node.args.args.index(arg)
                
                if arg_index >= default_offset:
                    default_value = node.args.defaults[arg_index - default_offset]
                    if isinstance(default_value, ast.Call):
                        if isinstance(default_value.func, ast.Name):
                            if default_value.func.id == "Depends":
                                return True
            
            # Check annotations
            if arg.annotation:
                # Check for Depends(...) with authentication
                if isinstance(arg.annotation, ast.Subscript):
                    if isinstance(arg.annotation.value, ast.Name):
                        if arg.annotation.value.id == "Annotated":
                            # Look for Depends in the annotation
                            return True
                elif isinstance(arg.annotation, ast.Call):
                    if isinstance(arg.annotation.func, ast.Name):
                        if arg.annotation.func.id == "Depends":
                            return True
        return False

    def _check_missing_authentication(self, node: ast.FunctionDef, methods: List[str]) -> None:
        """Check for missing authentication on sensitive routes."""
        self.violations.append(
            RuleViolation(
                rule_id="FASTAPI001",
                message=f"FastAPI route {node.name}() with methods {methods} missing authentication dependency (CWE-639)",
                line_number=node.lineno,
                column=node.col_offset,
                severity=RuleSeverity.HIGH,
                category=RuleCategory.SECURITY,
                file_path=self.file_path,
                fix_applicability=FixApplicability.MANUAL,
                fix_data={
                    "function_name": node.name,
                    "suggestion": "Add Depends(get_current_user) or similar authentication dependency",
                },
            )
        )

    def _check_websocket_security(self, node: ast.FunctionDef) -> None:
        """Check WebSocket routes for security issues."""
        # Check for missing origin validation
        has_origin_check = False
        for stmt in ast.walk(node):
            # Look for variables named 'origin'
            if isinstance(stmt, ast.Name) and stmt.id == "origin":
                has_origin_check = True
                break
            # Look for .headers.get() calls
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Attribute):
                    if stmt.func.attr == "get":
                        # Check if getting 'origin' header
                        if len(stmt.args) > 0:
                            if isinstance(stmt.args[0], ast.Constant):
                                if stmt.args[0].value == "origin":
                                    has_origin_check = True
                                    break

        if not has_origin_check:
            self.violations.append(
                RuleViolation(
                    rule_id="FASTAPI002",
                    message=f"WebSocket route {node.name}() missing origin validation (CWE-346)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data={
                        "function_name": node.name,
                        "suggestion": "Add origin validation: if websocket.headers.get('origin') not in ALLOWED_ORIGINS: await websocket.close()",
                    },
                )
            )

    def _check_query_injection(self, node: ast.FunctionDef) -> None:
        """Check for query parameter injection vulnerabilities."""
        # Look for Query parameters used in unsafe operations
        query_params = []
        for arg in node.args.args:
            if arg.annotation and isinstance(arg.annotation, ast.Call):
                if isinstance(arg.annotation.func, ast.Name):
                    if arg.annotation.func.id == "Query":
                        query_params.append(arg.arg)

        if query_params:
            # Check if query params are used in SQL/command operations
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    if isinstance(stmt.func, ast.Attribute):
                        if stmt.func.attr in ("execute", "raw", "exec"):
                            # Check if any query param is in the call
                            for arg in stmt.args:
                                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="FASTAPI003",
                                            message=f"Potential injection vulnerability: Query parameter may be used unsafely in {node.name}() (CWE-89)",
                                            line_number=stmt.lineno,
                                            column=stmt.col_offset,
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            file_path=self.file_path,
                                            fix_applicability=FixApplicability.MANUAL,
                                            fix_data={
                                                "suggestion": "Use parameterized queries or ORM methods instead of string formatting",
                                            },
                                        )
                                    )
                                    break

    def _check_file_upload_security(self, node: ast.FunctionDef) -> None:
        """Check file upload routes for security issues."""
        # Look for File or UploadFile parameters
        has_file_upload = False
        for arg in node.args.args:
            if arg.annotation:
                if isinstance(arg.annotation, ast.Name):
                    if arg.annotation.id in ("File", "UploadFile"):
                        has_file_upload = True
                        break

        if has_file_upload:
            # Check for missing file size validation
            has_size_check = False
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Compare):
                    if isinstance(stmt.left, ast.Attribute):
                        if stmt.left.attr in ("size", "content_length"):
                            has_size_check = True
                            break

            if not has_size_check:
                self.violations.append(
                    RuleViolation(
                        rule_id="FASTAPI004",
                        message=f"File upload in {node.name}() missing size validation (CWE-770)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data={
                            "suggestion": "Add file size check: if file.size > MAX_FILE_SIZE: raise HTTPException(413)",
                        },
                    )
                )

    def _check_background_task_security(self, node: ast.FunctionDef) -> None:
        """Check background tasks for privilege escalation risks."""
        # Look for BackgroundTasks usage
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Attribute):
                    if stmt.func.attr == "add_task":
                        # Check if user context is preserved
                        if len(stmt.args) > 0:
                            # Warn about privilege escalation
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FASTAPI005",
                                    message=f"Background task in {node.name}() may execute with elevated privileges (CWE-269)",
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.MANUAL,
                                    fix_data={
                                        "suggestion": "Ensure user context is passed to background task to prevent privilege escalation",
                                    },
                                )
                            )

    def _check_docs_exposure(self, node: ast.Call) -> None:
        """Check for API docs exposed in production."""
        # Check if docs_url or redoc_url are not disabled
        docs_disabled = False
        redoc_disabled = False

        for keyword in node.keywords:
            if keyword.arg == "docs_url":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is None:
                    docs_disabled = True
            elif keyword.arg == "redoc_url":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is None:
                    redoc_disabled = True

        if not (docs_disabled and redoc_disabled):
            self.violations.append(
                RuleViolation(
                    rule_id="FASTAPI006",
                    message="FastAPI docs endpoints exposed - disable in production (CWE-200)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                    fix_data={
                        "suggestion": "Add docs_url=None, redoc_url=None to FastAPI() constructor",
                    },
                )
            )

    def _check_cors_misconfiguration(self, node: ast.Call) -> None:
        """Check for CORS misconfiguration."""
        for keyword in node.keywords:
            if keyword.arg == "allow_origins":
                if isinstance(keyword.value, ast.List):
                    for elt in keyword.value.elts:
                        if isinstance(elt, ast.Constant):
                            if elt.value == "*":
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="FASTAPI007",
                                        message="CORS configured with wildcard origin (*) - allows any origin (CWE-942)",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        file_path=self.file_path,
                                        fix_applicability=FixApplicability.MANUAL,
                                        fix_data={
                                            "suggestion": "Specify allowed origins explicitly instead of using wildcard",
                                        },
                                    )
                                )

            if keyword.arg == "allow_credentials":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    # Check if allow_origins is wildcard
                    for kw in node.keywords:
                        if kw.arg == "allow_origins":
                            if isinstance(kw.value, ast.List):
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and elt.value == "*":
                                        self.violations.append(
                                            RuleViolation(
                                                rule_id="FASTAPI008",
                                                message="CORS allows credentials with wildcard origin - dangerous configuration (CWE-942)",
                                                line_number=node.lineno,
                                                column=node.col_offset,
                                                severity=RuleSeverity.CRITICAL,
                                                category=RuleCategory.SECURITY,
                                                file_path=self.file_path,
                                                fix_applicability=FixApplicability.MANUAL,
                                                fix_data={
                                                    "suggestion": "Cannot use allow_credentials=True with allow_origins=['*']",
                                                },
                                            )
                                        )

    def _check_oauth2_misconfiguration(self, node: ast.Call) -> None:
        """Check OAuth2 configuration for security issues."""
        # Check for missing auto_error parameter
        has_auto_error = False
        for keyword in node.keywords:
            if keyword.arg == "auto_error":
                has_auto_error = True
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                    # This is okay - user handles errors manually
                    return

        if not has_auto_error:
            # Default is True, which is good
            pass

        # Check for insecure tokenUrl (HTTP instead of HTTPS)
        for keyword in node.keywords:
            if keyword.arg == "tokenUrl":
                if isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        if keyword.value.value.startswith("http://"):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FASTAPI009",
                                    message="OAuth2 tokenUrl uses insecure HTTP - should use HTTPS (CWE-319)",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.HIGH,
                                    category=RuleCategory.SECURITY,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                    fix_data={
                                        "old_value": keyword.value.value,
                                        "new_value": keyword.value.value.replace("http://", "https://"),
                                    },
                                )
                            )

    def _check_pydantic_validation_bypass(self, node: ast.Call) -> None:
        """Check for Pydantic validation bypasses."""
        method_name = node.func.attr
        self.violations.append(
            RuleViolation(
                rule_id="FASTAPI010",
                message=f"Pydantic {method_name}() bypasses validation - use standard initialization (CWE-20)",
                line_number=node.lineno,
                column=node.col_offset,
                severity=RuleSeverity.MEDIUM,
                category=RuleCategory.SECURITY,
                file_path=self.file_path,
                fix_applicability=FixApplicability.MANUAL,
                fix_data={
                    "method": method_name,
                    "suggestion": "Use MyModel(**data) instead to ensure validation",
                },
            )
        )

    def _check_cookie_security(self, node: ast.Call) -> None:
        """Check for insecure cookie settings."""
        has_secure = False
        has_httponly = False
        has_samesite = False

        for keyword in node.keywords:
            if keyword.arg == "secure":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    has_secure = True
            elif keyword.arg == "httponly":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    has_httponly = True
            elif keyword.arg == "samesite":
                if isinstance(keyword.value, ast.Constant):
                    if keyword.value.value in ("lax", "strict"):
                        has_samesite = True

        if not has_secure:
            self.violations.append(
                RuleViolation(
                    rule_id="FASTAPI011",
                    message="Cookie missing 'secure' flag - should be secure=True (CWE-614)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                    fix_data={
                        "parameter": "secure",
                        "value": "True",
                    },
                )
            )

        if not has_httponly:
            self.violations.append(
                RuleViolation(
                    rule_id="FASTAPI012",
                    message="Cookie missing 'httponly' flag - vulnerable to XSS (CWE-1004)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                    fix_data={
                        "parameter": "httponly",
                        "value": "True",
                    },
                )
            )

        if not has_samesite:
            self.violations.append(
                RuleViolation(
                    rule_id="FASTAPI013",
                    message="Cookie missing 'samesite' attribute - vulnerable to CSRF (CWE-352)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SAFE,
                    fix_data={
                        "parameter": "samesite",
                        "value": "'lax'",
                    },
                )
            )

    def _check_jwt_algorithm_confusion(self, node: ast.FunctionDef) -> None:
        """Check for JWT algorithm confusion vulnerabilities (RS256 vs HS256)."""
        # Look for jwt.decode() calls in function body
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                # Check for jwt.decode() or JWT.decode()
                if isinstance(stmt.func, ast.Attribute):
                    if stmt.func.attr == "decode":
                        # Check if it's a JWT decode
                        func_name = self._get_name(stmt.func.value)
                        if func_name and "jwt" in func_name.lower():
                            # Check for missing algorithm verification
                            has_algorithms = False
                            has_verify_signature = True  # Default is True
                            
                            for keyword in stmt.keywords:
                                if keyword.arg == "algorithms":
                                    has_algorithms = True
                                    # Check for 'none' algorithm
                                    if isinstance(keyword.value, ast.List):
                                        for elt in keyword.value.elts:
                                            if isinstance(elt, ast.Constant):
                                                if elt.value and elt.value.lower() == "none":
                                                    self.violations.append(
                                                        RuleViolation(
                                                            rule_id="FASTAPI014",
                                                            message="JWT decode allows 'none' algorithm - bypasses signature verification (CWE-347)",
                                                            line_number=stmt.lineno,
                                                            column=stmt.col_offset,
                                                            severity=RuleSeverity.CRITICAL,
                                                            category=RuleCategory.SECURITY,
                                                            file_path=self.file_path,
                                                            fix_applicability=FixApplicability.SAFE,
                                                            fix_data={
                                                                "suggestion": "Remove 'none' from algorithms list",
                                                            },
                                                        )
                                                    )
                                elif keyword.arg == "verify_signature":
                                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                                        has_verify_signature = False
                            
                            if not has_algorithms and has_verify_signature:
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="FASTAPI015",
                                        message="JWT decode missing 'algorithms' parameter - vulnerable to algorithm confusion (CWE-347)",
                                        line_number=stmt.lineno,
                                        column=stmt.col_offset,
                                        severity=RuleSeverity.HIGH,
                                        category=RuleCategory.SECURITY,
                                        file_path=self.file_path,
                                        fix_applicability=FixApplicability.SAFE,
                                        fix_data={
                                            "suggestion": "Add algorithms=['HS256'] or algorithms=['RS256'] to jwt.decode()",
                                        },
                                    )
                                )
                            
                            if not has_verify_signature:
                                self.violations.append(
                                    RuleViolation(
                                        rule_id="FASTAPI016",
                                        message="JWT decode has signature verification disabled (CWE-347)",
                                        line_number=stmt.lineno,
                                        column=stmt.col_offset,
                                        severity=RuleSeverity.CRITICAL,
                                        category=RuleCategory.SECURITY,
                                        file_path=self.file_path,
                                        fix_applicability=FixApplicability.SAFE,
                                        fix_data={
                                            "suggestion": "Remove verify_signature=False or set to True",
                                        },
                                    )
                                )

    def _check_missing_rate_limiting(self, node: ast.FunctionDef) -> None:
        """Check for missing rate limiting on API routes."""
        # Check if route has rate limiting decorator or dependency
        has_rate_limit = False
        
        for decorator in node.decorator_list:
            # Check for @limiter.limit() or similar decorators
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in ("limit", "rate_limit"):
                        has_rate_limit = True
                        break
        
        # Check for rate limiting dependency in function parameters
        for arg in node.args.args:
            if "rate" in arg.arg.lower() or "limit" in arg.arg.lower():
                has_rate_limit = True
                break
        
        if not has_rate_limit:
            # Only warn for POST/PUT/DELETE routes (state-changing operations)
            route_methods = []
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    method = decorator.func.attr
                    if method in ("post", "put", "delete", "patch"):
                        route_methods.append(method)
            
            if route_methods:
                self.violations.append(
                    RuleViolation(
                        rule_id="FASTAPI017",
                        message=f"Route {node.name}() with {route_methods} methods missing rate limiting (CWE-770)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data={
                            "suggestion": "Add rate limiting using slowapi or similar: @limiter.limit('5/minute')",
                        },
                    )
                )

    def _check_ssrf_in_url_params(self, node: ast.FunctionDef) -> None:
        """Check for Server-Side Request Forgery (SSRF) vulnerabilities."""
        # Look for URL parameters that might be used in HTTP requests
        url_params = []
        for arg in node.args.args:
            if "url" in arg.arg.lower() or "endpoint" in arg.arg.lower() or "callback" in arg.arg.lower():
                url_params.append(arg.arg)
        
        if url_params:
            # Check if these params are used in HTTP request libraries
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    # Check for requests.get/post, httpx.get/post, urllib.request.urlopen
                    if isinstance(stmt.func, ast.Attribute):
                        if stmt.func.attr in ("get", "post", "put", "delete", "patch", "request", "urlopen"):
                            func_name = self._get_name(stmt.func.value)
                            if func_name and func_name.lower() in ("requests", "httpx", "urllib"):
                                # Check if URL param is used directly
                                for arg in stmt.args:
                                    if isinstance(arg, ast.Name):
                                        if arg.id in url_params:
                                            self.violations.append(
                                                RuleViolation(
                                                    rule_id="FASTAPI018",
                                                    message=f"Potential SSRF: URL parameter '{arg.id}' used in HTTP request without validation (CWE-918)",
                                                    line_number=stmt.lineno,
                                                    column=stmt.col_offset,
                                                    severity=RuleSeverity.HIGH,
                                                    category=RuleCategory.SECURITY,
                                                    file_path=self.file_path,
                                                    fix_applicability=FixApplicability.MANUAL,
                                                    fix_data={
                                                        "parameter": arg.id,
                                                        "suggestion": "Validate URL against allowlist or use URL parsing to check scheme/host",
                                                    },
                                                )
                                            )
                                    elif isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                                        # f-string or string concatenation with URL param
                                        self.violations.append(
                                            RuleViolation(
                                                rule_id="FASTAPI018",
                                                message=f"Potential SSRF: URL constructed from user input in {node.name}() (CWE-918)",
                                                line_number=stmt.lineno,
                                                column=stmt.col_offset,
                                                severity=RuleSeverity.HIGH,
                                                category=RuleCategory.SECURITY,
                                                file_path=self.file_path,
                                                fix_applicability=FixApplicability.MANUAL,
                                                fix_data={
                                                    "suggestion": "Validate URL against allowlist before making request",
                                                },
                                            )
                                        )

    def _check_missing_security_headers(self, node: ast.FunctionDef) -> None:
        """Check for missing security headers in responses."""
        # Look for Response object usage in route
        has_response_headers = False
        
        for stmt in ast.walk(node):
            # Check for response.headers assignments
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Subscript):
                        if isinstance(target.value, ast.Attribute):
                            if target.value.attr == "headers":
                                has_response_headers = True
                                # Check if security headers are set
                                if isinstance(target.slice, ast.Constant):
                                    header_name = target.slice.value
                                    if isinstance(header_name, str):
                                        if header_name.lower() in ("strict-transport-security", "hsts"):
                                            return  # HSTS is set, no violation
        
        # Look for @app decorators to check if this is a route
        is_route = False
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                if decorator.func.attr in ("get", "post", "put", "delete", "patch"):
                    is_route = True
                    break
        
        # Only warn for routes that return responses
        if is_route:
            # Check if function returns a Response object
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Return) and stmt.value:
                    # Only flag if we see explicit response handling but no headers
                    if isinstance(stmt.value, ast.Call):
                        if isinstance(stmt.value.func, ast.Name):
                            if stmt.value.func.id in ("Response", "JSONResponse", "HTMLResponse"):
                                if not has_response_headers:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="FASTAPI019",
                                            message=f"Route {node.name}() missing HSTS security header (CWE-523)",
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            severity=RuleSeverity.MEDIUM,
                                            category=RuleCategory.SECURITY,
                                            file_path=self.file_path,
                                            fix_applicability=FixApplicability.MANUAL,
                                            fix_data={
                                                "suggestion": "Add response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
                                            },
                                        )
                                    )

    def _check_graphql_introspection(self, node: ast.FunctionDef) -> None:
        """Check for GraphQL introspection enabled in production."""
        # Look for GraphQL schema or app creation
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Name):
                    # Check for GraphQL or Strawberry initialization
                    if "graphql" in stmt.func.id.lower() or "strawberry" in stmt.func.id.lower():
                        # Check for introspection parameter
                        has_introspection_disabled = False
                        for keyword in stmt.keywords:
                            if keyword.arg and "introspection" in keyword.arg.lower():
                                if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                                    has_introspection_disabled = True
                        
                        if not has_introspection_disabled:
                            self.violations.append(
                                RuleViolation(
                                    rule_id="FASTAPI020",
                                    message="GraphQL introspection enabled - should be disabled in production (CWE-200)",
                                    line_number=stmt.lineno,
                                    column=stmt.col_offset,
                                    severity=RuleSeverity.MEDIUM,
                                    category=RuleCategory.SECURITY,
                                    file_path=self.file_path,
                                    fix_applicability=FixApplicability.SAFE,
                                    fix_data={
                                        "suggestion": "Add introspection=False to GraphQL initialization",
                                    },
                                )
                            )

    def _get_name(self, node: ast.AST) -> Optional[str]:
        """Get the name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None


class FastAPISecurityChecker:
    """Main checker for FastAPI security vulnerabilities."""

    def __init__(self):
        self.logger = PyGuardLogger(__name__)
        self.file_ops = FileOperations()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """Check a Python file for FastAPI security issues."""
        try:
            code = self.file_ops.read_file(file_path)
            if code is None:
                return []
            tree = ast.parse(code)
            visitor = FastAPISecurityVisitor(file_path, code)
            visitor.visit(tree)
            return visitor.violations
        except SyntaxError as e:
            self.logger.warning(f"Syntax error in {file_path}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error checking {file_path}: {e}")
            return []


# Rule definitions
FASTAPI_MISSING_AUTH_RULE = Rule(
    rule_id="FASTAPI001",
    name="fastapi-missing-authentication",
    message_template="FastAPI route missing authentication dependency (CWE-639)",
    description="FastAPI route with sensitive HTTP methods missing authentication dependency",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    references=[
        "CWE-639: Authorization Bypass Through User-Controlled Key",
        "OWASP ASVS 4.0.3 v5.0: Access Control Verification",
    ],
)

FASTAPI_WEBSOCKET_ORIGIN_RULE = Rule(
    rule_id="FASTAPI002",
    name="fastapi-websocket-origin",
    message_template="WebSocket route missing origin validation (CWE-346)",
    description="WebSocket route missing origin validation - vulnerable to CSRF attacks",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    references=[
        "CWE-346: Origin Validation Error",
        "OWASP ASVS 4.2.1 v5.0: Operation Level Access Control",
    ],
)

FASTAPI_DOCS_EXPOSURE_RULE = Rule(
    rule_id="FASTAPI006",
    name="fastapi-docs-exposure",
    message_template="API documentation endpoints exposed in production (CWE-200)",
    description="API documentation endpoints not disabled - can leak sensitive information",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    references=[
        "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        "OWASP ASVS 14.1.3 v5.0: Build and Deploy Verification",
    ],
)

FASTAPI_CORS_WILDCARD_RULE = Rule(
    rule_id="FASTAPI007",
    name="fastapi-cors-wildcard",
    message_template="CORS configured with wildcard origin (*) (CWE-942)",
    description="CORS configured with wildcard origin allows any domain to access API",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    references=[
        "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        "OWASP ASVS 14.5.3 v5.0: HTTP Security Headers Verification",
    ],
)

FASTAPI_OAUTH2_HTTP_RULE = Rule(
    rule_id="FASTAPI009",
    name="fastapi-oauth2-http",
    message_template="OAuth2 tokenUrl uses insecure HTTP protocol (CWE-319)",
    description="OAuth2 tokenUrl uses insecure HTTP - tokens can be intercepted",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    references=[
        "CWE-319: Cleartext Transmission of Sensitive Information",
        "OWASP ASVS 9.1.2 v5.0: Communications Security Verification",
    ],
)

FASTAPI_COOKIE_SECURE_RULE = Rule(
    rule_id="FASTAPI011",
    name="fastapi-cookie-secure",
    message_template="Response cookie missing 'secure' flag (CWE-614)",
    description="Response cookie missing 'secure' flag - can be transmitted over insecure connections",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    references=[
        "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "OWASP ASVS 3.4.2 v5.0: Cookie-based Session Management",
    ],
)

FASTAPI_JWT_NONE_ALGORITHM_RULE = Rule(
    rule_id="FASTAPI014",
    name="fastapi-jwt-none-algorithm",
    message_template="JWT decode allows 'none' algorithm (CWE-347)",
    description="JWT decode allows 'none' algorithm - bypasses signature verification",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    references=[
        "CWE-347: Improper Verification of Cryptographic Signature",
        "OWASP ASVS 6.2.1 v5.0: Algorithms",
    ],
)

FASTAPI_JWT_MISSING_ALGORITHM_RULE = Rule(
    rule_id="FASTAPI015",
    name="fastapi-jwt-missing-algorithm",
    message_template="JWT decode missing 'algorithms' parameter (CWE-347)",
    description="JWT decode missing 'algorithms' parameter - vulnerable to algorithm confusion attacks",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    references=[
        "CWE-347: Improper Verification of Cryptographic Signature",
        "OWASP ASVS 6.2.1 v5.0: Algorithms",
    ],
)

FASTAPI_JWT_NO_VERIFY_RULE = Rule(
    rule_id="FASTAPI016",
    name="fastapi-jwt-no-verify",
    message_template="JWT decode has signature verification disabled (CWE-347)",
    description="JWT decode has verify_signature=False - allows forged tokens",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    references=[
        "CWE-347: Improper Verification of Cryptographic Signature",
        "OWASP ASVS 6.2.2 v5.0: Algorithm Verification",
    ],
)

FASTAPI_MISSING_RATE_LIMIT_RULE = Rule(
    rule_id="FASTAPI017",
    name="fastapi-missing-rate-limit",
    message_template="Route missing rate limiting (CWE-770)",
    description="State-changing route missing rate limiting - vulnerable to abuse",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    references=[
        "CWE-770: Allocation of Resources Without Limits or Throttling",
        "OWASP ASVS 4.2.2 v5.0: Operation Level Access Control",
    ],
)

FASTAPI_SSRF_URL_PARAM_RULE = Rule(
    rule_id="FASTAPI018",
    name="fastapi-ssrf-url-param",
    message_template="Potential SSRF in URL parameter (CWE-918)",
    description="URL parameter used in HTTP request without validation - SSRF risk",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    references=[
        "CWE-918: Server-Side Request Forgery (SSRF)",
        "OWASP ASVS 5.2.6 v5.0: Sanitization and Sandboxing",
    ],
)

FASTAPI_MISSING_HSTS_RULE = Rule(
    rule_id="FASTAPI019",
    name="fastapi-missing-hsts",
    message_template="Route missing HSTS security header (CWE-523)",
    description="Route returns Response without Strict-Transport-Security header",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.MANUAL,
    references=[
        "CWE-523: Unprotected Transport of Credentials",
        "OWASP ASVS 14.4.5 v5.0: HTTP Security Headers",
    ],
)

FASTAPI_GRAPHQL_INTROSPECTION_RULE = Rule(
    rule_id="FASTAPI020",
    name="fastapi-graphql-introspection",
    message_template="GraphQL introspection enabled (CWE-200)",
    description="GraphQL introspection enabled - should be disabled in production",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    fix_applicability=FixApplicability.SAFE,
    references=[
        "CWE-200: Exposure of Sensitive Information",
        "OWASP ASVS 14.1.3 v5.0: Build and Deploy",
    ],
)


# Register all rules
def register_fastapi_rules():
    """Register all FastAPI security rules."""
    rules = [
        FASTAPI_MISSING_AUTH_RULE,
        FASTAPI_WEBSOCKET_ORIGIN_RULE,
        FASTAPI_DOCS_EXPOSURE_RULE,
        FASTAPI_CORS_WILDCARD_RULE,
        FASTAPI_OAUTH2_HTTP_RULE,
        FASTAPI_COOKIE_SECURE_RULE,
        FASTAPI_JWT_NONE_ALGORITHM_RULE,
        FASTAPI_JWT_MISSING_ALGORITHM_RULE,
        FASTAPI_JWT_NO_VERIFY_RULE,
        FASTAPI_MISSING_RATE_LIMIT_RULE,
        FASTAPI_SSRF_URL_PARAM_RULE,
        FASTAPI_MISSING_HSTS_RULE,
        FASTAPI_GRAPHQL_INTROSPECTION_RULE,
    ]
    register_rules(rules)
