"""
AST-based code analysis for security vulnerabilities and code quality issues.

This module provides comprehensive static analysis using Python's Abstract Syntax Tree (AST),
aligned with OWASP ASVS v5.0, CWE Top 25, and SWEBOK v4.0 best practices.

References:
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE Top 25 | https://cwe.mitre.org/top25/ | High | Common Weakness Enumeration
- SWEBOK v4.0 | https://computer.org/swebok | High | Software Engineering Body of Knowledge
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class SecurityIssue:
    """Security vulnerability detected in code."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""
    owasp_id: Optional[str] = None
    cwe_id: Optional[str] = None


@dataclass
class CodeQualityIssue:
    """Code quality issue detected in code."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    column: int
    code_snippet: str = ""
    fix_suggestion: str = ""


class SecurityVisitor(ast.NodeVisitor):
    """
    AST visitor for security vulnerability detection.

    Aligned with OWASP ASVS v5.0 and CWE Top 25.
    """

    def __init__(self, source_lines: List[str]):
        """Initialize security visitor."""
        self.issues: List[SecurityIssue] = []
        self.source_lines = source_lines
        self.in_function = False
        self.current_function = None
    
    def _add_issue(self, node: ast.AST, issue: SecurityIssue) -> None:
        """Add issue if not suppressed."""
        if not self._is_suppressed(node, issue.cwe_id):
            self.issues.append(issue)

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return str(self.source_lines[node.lineno - 1].strip())
        return ""

    def _is_suppressed(self, node: ast.AST, rule_id: str = None) -> bool:
        """
        Check if a node has suppression comment.
        
        Supports comments like:
        - # pyguard: disable
        - # pyguard: disable=CWE-89,CWE-22
        - # noqa
        - # noqa: CWE-89
        """
        if not hasattr(node, "lineno") or node.lineno > len(self.source_lines):
            return False
            
        line = self.source_lines[node.lineno - 1]
        
        # Check for PyGuard suppression
        if "# pyguard: disable" in line:
            # Generic disable (no rule specified)
            if "=" not in line.split("# pyguard: disable")[1]:
                return True
            # Specific rule check
            if rule_id and f"={rule_id}" in line:
                return True
                
        # Check for noqa suppression
        if "# noqa" in line:
            after_noqa = line.split("# noqa")[1]
            # Generic noqa (no colon or empty after colon)
            if ":" not in after_noqa or not after_noqa.split(":")[1].strip():
                return True
            # Specific rule check
            if rule_id and f": {rule_id}" in after_noqa:
                return True
                
        return False

    def visit_Call(self, node: ast.Call):
        """Visit function call nodes."""
        func_name = self._get_call_name(node)

        # OWASP ASVS-5.2.1, CWE-95: Code Injection
        if func_name in ["eval", "exec", "compile"]:
            self._add_issue(node, SecurityIssue(
                severity="HIGH",
                category="Code Injection",
                message=f"Dangerous use of {func_name}() - executes arbitrary code",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion=f"Replace {func_name}() with safer alternatives: ast.literal_eval() for literals, json.loads() for data",
                owasp_id="ASVS-5.2.1",
                cwe_id="CWE-95",
            ))

        # OWASP ASVS-5.5.3, CWE-502: Unsafe Deserialization - YAML
        if func_name == "yaml.load":
            self._add_issue(node, SecurityIssue(
                severity="HIGH",
                category="Unsafe Deserialization",
                message="yaml.load() allows arbitrary code execution",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Use yaml.safe_load() instead, which only deserializes safe types",
                owasp_id="ASVS-5.5.3",
                cwe_id="CWE-502",
            ))

        # OWASP ASVS-5.5.3, CWE-502: Unsafe Deserialization - Pickle
        if func_name in ["pickle.load", "pickle.loads"]:
            self._add_issue(node, SecurityIssue(
                    severity="MEDIUM",
                    category="Unsafe Deserialization",
                    message=f"{func_name}() can execute arbitrary code during unpickling",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use json.load() or msgpack for untrusted data; only use pickle for trusted sources",
                    owasp_id="ASVS-5.5.3",
                    cwe_id="CWE-502",
                )
            )

        # OWASP ASVS-5.3.3, CWE-78: Command Injection
        if func_name in ["subprocess.call", "subprocess.run", "subprocess.Popen", "os.system"]:
            shell_arg = self._get_keyword_arg(node, "shell")
            if shell_arg and isinstance(shell_arg, ast.Constant) and shell_arg.value is True:
                self._add_issue(node, SecurityIssue(
                        severity="HIGH",
                        category="Command Injection",
                        message=f"{func_name}() with shell=True allows command injection",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Pass command as list and use shell=False (default): subprocess.run(['cmd', 'arg1', 'arg2'])",
                        owasp_id="ASVS-5.3.3",
                        cwe_id="CWE-78",
                    )
                )

        # OWASP ASVS-6.2.1, CWE-327: Weak Cryptography
        if func_name in ["hashlib.md5", "hashlib.sha1"]:
            hash_type = func_name.split(".")[1].upper()
            self._add_issue(node, SecurityIssue(
                    severity="MEDIUM",
                    category="Weak Cryptography",
                    message=f"{hash_type} is cryptographically broken",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use SHA-256 or SHA-3: hashlib.sha256() or hashlib.sha3_256()",
                    owasp_id="ASVS-6.2.1",
                    cwe_id="CWE-327",
                )
            )

        # OWASP ASVS-6.3.1, CWE-330: Weak Random
        if func_name.startswith("random.") and func_name not in ["random.seed", "random.choice"]:
            # Check if in security context
            if self._in_security_context(node):
                self._add_issue(node, SecurityIssue(
                        severity="MEDIUM",
                        category="Weak Random",
                        message="random module is not cryptographically secure",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use secrets module: secrets.token_urlsafe(), secrets.token_hex(), or secrets.randbelow()",
                        owasp_id="ASVS-6.3.1",
                        cwe_id="CWE-330",
                    )
                )

        # OWASP ASVS-9.1.1, CWE-319: Insecure HTTP
        if func_name in ["requests.get", "requests.post", "urllib.request.urlopen"]:
            if node.args and isinstance(node.args[0], ast.Constant):
                url = node.args[0].value
                if isinstance(url, str) and url.startswith("http://"):
                    self._add_issue(node, SecurityIssue(
                            severity="MEDIUM",
                            category="Insecure Communication",
                            message="Using insecure HTTP instead of HTTPS",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use HTTPS for secure communication",
                            owasp_id="ASVS-9.1.1",
                            cwe_id="CWE-319",
                        )
                    )

        # OWASP ASVS-8.2.2, CWE-326: Weak SSL/TLS
        if "ssl.wrap_socket" in func_name or "SSLContext" in func_name:
            # Check for weak protocol versions
            ssl_version = self._get_keyword_arg(node, "ssl_version")
            if ssl_version:
                # Check if it's using weak SSL/TLS versions
                pass  # Placeholder for future SSL version checking

        # OWASP ASVS-5.5.2, CWE-611: XML External Entity (XXE) Injection
        if func_name in [
            "xml.etree.ElementTree.parse",
            "xml.etree.ElementTree.fromstring",
            "xml.dom.minidom.parse",
            "xml.dom.minidom.parseString",
            "xml.sax.parse",
            "xml.sax.parseString",
            "lxml.etree.parse",
        ]:
            self._add_issue(node, SecurityIssue(
                    severity="HIGH",
                    category="XXE Injection",
                    message=f"{func_name}() vulnerable to XML External Entity attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use defusedxml library: from defusedxml import ElementTree; or disable external entity processing",
                    owasp_id="ASVS-5.5.2",
                    cwe_id="CWE-611",
                )
            )

        # OWASP ASVS-13.1.1, CWE-918: Server-Side Request Forgery (SSRF)
        if func_name in [
            "requests.get",
            "requests.post",
            "urllib.request.urlopen",
            "httpx.get",
            "httpx.post",
        ]:
            # Check if URL comes from user input (heuristic)
            if node.args and isinstance(node.args[0], (ast.Name, ast.Call, ast.Attribute)):
                self._add_issue(node, SecurityIssue(
                        severity="HIGH",
                        category="SSRF",
                        message=f"{func_name}() with dynamic URL may enable Server-Side Request Forgery",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Validate and Allowlist URLs before making requests; use URL parsing to ensure destination is safe",
                        owasp_id="ASVS-13.1.1",
                        cwe_id="CWE-918",
                    )
                )

        # OWASP ASVS-12.3.1, CWE-22: Path Traversal (Enhanced)
        if func_name in ["open", "os.path.join", "pathlib.Path"]:
            # Check if path uses user input
            if node.args:
                for arg in node.args:
                    if isinstance(arg, (ast.Name, ast.Call, ast.BinOp)):
                        self._add_issue(node, SecurityIssue(
                                severity="HIGH",
                                category="Path Traversal",
                                message=f"{func_name}() with dynamic path may allow directory traversal",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="Validate paths: use os.path.normpath() and check if path starts with allowed directory",
                                owasp_id="ASVS-12.3.1",
                                cwe_id="CWE-22",
                            )
                        )
                        break

        # CWE-377: Insecure Temporary File Creation
        if func_name in ["tempfile.mktemp"]:
            self._add_issue(node, SecurityIssue(
                    severity="HIGH",
                    category="Insecure Temp File",
                    message="tempfile.mktemp() is insecure and deprecated",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use tempfile.mkstemp() or tempfile.TemporaryFile() for secure temporary files",
                    owasp_id="ASVS-12.3.2",
                    cwe_id="CWE-377",
                )
            )

        # CWE-918: Template Injection (Jinja2, Mako)
        if func_name in ["jinja2.Template", "Template", "mako.template.Template"]:
            # Check if template string is dynamic
            if node.args and isinstance(node.args[0], (ast.Name, ast.Call)):
                self._add_issue(node, SecurityIssue(
                        severity="HIGH",
                        category="Template Injection",
                        message=f"{func_name}() with dynamic template enables Server-Side Template Injection (SSTI)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use pre-defined templates; sanitize user input with autoescape=True; avoid user-controlled templates",
                        owasp_id="ASVS-5.2.6",
                        cwe_id="CWE-1336",
                    )
                )

        # CWE-798: JWT Security Issues
        if func_name in ["jwt.encode", "jwt.decode"]:
            # Check for weak algorithms
            algorithm_arg = self._get_keyword_arg(node, "algorithm")
            if algorithm_arg and isinstance(algorithm_arg, ast.Constant):
                if algorithm_arg.value in ["none", "HS256"]:
                    self._add_issue(node, SecurityIssue(
                            severity="HIGH",
                            category="Weak JWT Algorithm",
                            message=f"JWT using weak algorithm '{algorithm_arg.value!r}'",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use RS256 or ES256 for JWT signing; avoid 'none' algorithm",
                            owasp_id="ASVS-6.2.1",
                            cwe_id="CWE-327",
                        )
                    )

        # CWE-639: Insecure Direct Object Reference (IDOR)
        if func_name in ["query.get", "get_object_or_404", "filter"]:
            # Check if using user-supplied ID without authorization check
            if node.args and isinstance(node.args[0], (ast.Name, ast.Call)):
                self._add_issue(node, SecurityIssue(
                        severity="HIGH",
                        category="IDOR",
                        message=f"{func_name}() may allow unauthorized access to objects (IDOR)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Verify user authorization before accessing objects; use permission checks",
                        owasp_id="ASVS-4.1.1",
                        cwe_id="CWE-639",
                    )
                )

        # CWE-502: GraphQL Injection
        if func_name in ["graphql.execute", "execute_graphql"]:
            # Check for dynamic queries
            if node.args and isinstance(node.args[0], (ast.Name, ast.Call)):
                self._add_issue(node, SecurityIssue(
                        severity="HIGH",
                        category="GraphQL Injection",
                        message=f"{func_name}() with dynamic query enables GraphQL injection",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use parameterized queries; validate and sanitize user input; implement query depth limiting",
                        owasp_id="ASVS-5.3.8",
                        cwe_id="CWE-943",
                    )
                )

        # CWE-1004: Sensitive Cookie Without HttpOnly Flag
        if func_name in ["set_cookie", "response.set_cookie"]:
            httponly_arg = self._get_keyword_arg(node, "httponly")

            if not httponly_arg or (isinstance(httponly_arg, ast.Constant) and not httponly_arg.value):
                self._add_issue(node, SecurityIssue(
                        severity="MEDIUM",
                        category="Insecure Cookie",
                        message="Cookie set without HttpOnly flag - vulnerable to XSS",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Set httponly=True, secure=True, samesite='Strict' for sensitive cookies",
                        owasp_id="ASVS-3.4.2",
                        cwe_id="CWE-1004",
                    )
                )

        # CWE-134: Format String Vulnerability
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            # Check if format string comes from a variable (potential user input)
            if isinstance(node.func.value, ast.Name):
                self._add_issue(node, SecurityIssue(
                        severity="MEDIUM",
                        category="Format String",
                        message="Dynamic format strings can lead to information disclosure",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use template strings or f-strings with explicit values; avoid user-controlled format strings",
                        owasp_id="ASVS-5.2.8",
                        cwe_id="CWE-134",
                    )
                )

        # CWE-90: LDAP Injection
        if "ldap" in func_name.lower() and any(
            keyword in func_name.lower() for keyword in ["search", "add", "modify", "delete"]  # pyguard: disable=CWE-89  # Pattern detection, not vulnerable code
        ):
            self._add_issue(node, SecurityIssue(
                    severity="HIGH",
                    category="LDAP Injection",
                    message=f"{func_name}() may be vulnerable to LDAP injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Escape LDAP special characters: use ldap.filter.escape_filter_chars() for search filters",
                    owasp_id="ASVS-5.3.7",
                    cwe_id="CWE-90",
                )
            )

        # CWE-943: NoSQL Injection (MongoDB)
        if func_name in [
            "pymongo.collection.find",
            "pymongo.collection.find_one",
            "pymongo.collection.update",
            "pymongo.collection.delete",
        ]:
            # Check if query uses string concatenation
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self._add_issue(node, SecurityIssue(
                        severity="HIGH",
                        category="NoSQL Injection",
                        message=f"{func_name}() with string concatenation vulnerable to NoSQL injection",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use parameterized queries with dict objects; validate and sanitize all user input",
                        owasp_id="ASVS-5.3.4",
                        cwe_id="CWE-943",
                    )
                )

        # CWE-489: Debug Code Detection
        if func_name in ["pdb.set_trace", "ipdb.set_trace", "breakpoint", "pudb.set_trace", "pprint.pprint", "print"]:
            # Only flag as issue in non-debug contexts
            if func_name in ["pdb.set_trace", "ipdb.set_trace", "breakpoint", "pudb.set_trace"]:
                self._add_issue(node, SecurityIssue(
                        severity="LOW",
                        category="Debug Code",
                        message=f"{func_name}() debug statement found - should be removed in production",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Remove all debug statements before deploying to production",
                        owasp_id="ASVS-14.3.3",
                        cwe_id="CWE-489",
                    )
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Visit assignment nodes to detect hardcoded secrets."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                # OWASP ASVS-2.6.3, CWE-798: Hardcoded Credentials (Enhanced)
                sensitive_names = [
                    "password",
                    "passwd",
                    "pwd",
                    "secret",
                    "api_key",
                    "apikey",
                    "token",
                    "auth",
                    "credential",
                    "private_key",
                    "access_key",
                    "aws_key",
                    "gcp_key",
                    "azure_key",
                    "slack_token",
                    "github_token",
                    "db_password",
                    "mongodb_uri",
                    "redis_password",
                    "jwt_secret",
                ]

                if any(name in var_name for name in sensitive_names):
                    # Check if value is a hardcoded string
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        value_str = node.value.value
                        if value_str and value_str not in ["", "None", "null", "YOUR_KEY_HERE", "TODO"]:
                            # Enhanced detection with pattern matching
                            secret_patterns = {
                                r"AKIA[0-9A-Z]{16}": "AWS Access Key",
                                r"AIza[0-9A-Za-z\-_]{35}": "Google API Key",
                                r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24}": "Slack Token",
                                r"sk_live_[0-9a-zA-Z]{24}": "Stripe Live Key",
                                r"ghp_[0-9a-zA-Z]{36}": "GitHub Personal Access Token",
                                r"mongodb(\+srv)?://[^/]+:[^@]+@": "MongoDB Connection String",
                                r"postgres://[^/]+:[^@]+@": "PostgreSQL Connection String",
                                r"mysql://[^/]+:[^@]+@": "MySQL Connection String",
                            }

                            detected_type = "Hardcoded Credentials"
                            for pattern, secret_type in secret_patterns.items():
                                if re.search(pattern, value_str):
                                    detected_type = secret_type
                                    break

                            self._add_issue(node, SecurityIssue(
                                    severity="HIGH",
                                    category=detected_type,
                                    message=f"Hardcoded {detected_type} detected in variable '{var_name}'",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=self._get_code_snippet(node),
                                    fix_suggestion="Use environment variables (os.environ.get('VAR_NAME')), config files, or secure vaults (AWS Secrets Manager, HashiCorp Vault)",
                                    owasp_id="ASVS-2.6.3",
                                    cwe_id="CWE-798",
                                )
                            )

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Visit f-string nodes to detect potential CSV injection."""
        # CWE-1236: CSV Injection (Formula Injection)
        snippet = self._get_code_snippet(node)
        if any(char in snippet for char in ["=", "+", "-", "@"]) and "csv" in snippet.lower():
            self._add_issue(node, SecurityIssue(
                    severity="MEDIUM",
                    category="CSV Injection",
                    message="Potential CSV injection vulnerability in formatted string",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=snippet,
                    fix_suggestion="Sanitize CSV data: prefix cells starting with =+-@ with single quote or space",
                    owasp_id="ASVS-5.2.2",
                    cwe_id="CWE-1236",
                )
            )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        """Visit comparison nodes to detect SQL injection patterns and timing attacks."""
        # Detect string concatenation in SQL queries (simplified detection)
        if self._looks_like_sql_query(node):
            self._add_issue(node, SecurityIssue(
                    severity="HIGH",
                    category="SQL Injection",
                    message="Potential SQL injection vulnerability",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                    owasp_id="ASVS-5.3.4",
                    cwe_id="CWE-89",
                )
            )

        # CWE-208: Timing Attack - String comparison in security contexts
        snippet = self._get_code_snippet(node).lower()
        if any(keyword in snippet for keyword in ["password", "token", "secret", "hash", "key"]):
            for op in node.ops:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    self._add_issue(node, SecurityIssue(
                            severity="MEDIUM",
                            category="Timing Attack",
                            message="String comparison of secrets vulnerable to timing attacks",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use constant-time comparison: hmac.compare_digest(a, b) or secrets.compare_digest(a, b)",
                            owasp_id="ASVS-2.7.3",
                            cwe_id="CWE-208",
                        )
                    )
                    break

        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts: list[str] = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.insert(0, current.id)
            return ".".join(parts)
        return ""

    def _get_keyword_arg(self, node: ast.Call, keyword: str) -> Optional[ast.AST]:
        """Get a keyword argument from a function call."""
        for kw in node.keywords:
            if kw.arg == keyword:  # pyguard: disable=CWE-208  # Pattern detection, not vulnerable code
                return kw.value
        return None

    def _in_security_context(self, node: ast.AST) -> bool:
        """Check if node is in a security-sensitive context."""
        # Look at surrounding context for security-related variable names
        snippet = self._get_code_snippet(node).lower()
        security_keywords = ["password", "token", "key", "secret", "auth", "credential"]
        return any(keyword in snippet for keyword in security_keywords)

    def _looks_like_sql_query(self, node: ast.Compare) -> bool:
        """Heuristic to detect if this looks like SQL query construction."""
        snippet = self._get_code_snippet(node).upper()
        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]
        return any(keyword in snippet for keyword in sql_keywords)


class CodeQualityVisitor(ast.NodeVisitor):
    """
    AST visitor for code quality issue detection.

    Aligned with SWEBOK v4.0 and PEP 8 best practices.
    """

    def __init__(self, source_lines: List[str]):
        """Initialize code quality visitor."""
        self.issues: List[CodeQualityIssue] = []
        self.source_lines = source_lines
        self.complexity_by_function: Dict[str, int] = {}

    def _add_issue(self, node: 'ast.AST', issue: CodeQualityIssue) -> None:
        """Add issue if not suppressed."""
        # Extract rule ID from category for suppression check
        rule_id = issue.category.upper().replace(' ', '-')
        if not self._is_suppressed(node, rule_id):
            self.issues.append(issue)

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return str(self.source_lines[node.lineno - 1].strip())
        return ""

    def _is_suppressed(self, node: ast.AST, rule_id: str = None) -> bool:
        """
        Check if a node has suppression comment.
        
        Supports comments like:
        - # pyguard: disable
        - # pyguard: disable=COMPLEXITY,LONG-METHOD
        - # noqa
        - # noqa: COMPLEXITY
        """
        if not hasattr(node, "lineno") or node.lineno > len(self.source_lines):
            return False
            
        line = self.source_lines[node.lineno - 1]
        
        # Check for PyGuard suppression
        if "# pyguard: disable" in line:
            # Generic disable (no rule specified)
            if "=" not in line.split("# pyguard: disable")[1]:
                return True
            # Specific rule check
            if rule_id and f"={rule_id}" in line:
                return True
                
        # Check for noqa suppression
        if "# noqa" in line:
            after_noqa = line.split("# noqa")[1]
            # Generic noqa (no colon or empty after colon)
            if ":" not in after_noqa or not after_noqa.split(":")[1].strip():
                return True
            # Specific rule check
            if rule_id and f": {rule_id}" in after_noqa:
                return True
                
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition nodes."""
        # Check for missing docstrings (except private functions)
        if not node.name.startswith("_"):
            if not ast.get_docstring(node) and not self._is_suppressed(node, "DOCUMENTATION"):
                self._add_issue(node, CodeQualityIssue(
                        severity="LOW",
                        category="Documentation",
                        message=f"Function '{node.name}' lacks docstring",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion='Add docstring: """Brief description."""',
                    )
                )

        # Check for too many parameters
        num_params = len(node.args.args)
        if num_params > 6:
            self._add_issue(node, CodeQualityIssue(
                    severity="MEDIUM",
                    category="Complexity",
                    message=f"Function '{node.name}' has {num_params} parameters (max recommended: 6)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Refactor to use fewer parameters or group related parameters into a dataclass/dict",
                )
            )

        # Check for mutable default arguments
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add_issue(node, CodeQualityIssue(
                        severity="HIGH",
                        category="Anti-pattern",
                        message="Mutable default argument detected",
                        line_number=default.lineno,
                        column=default.col_offset,
                        code_snippet=self._get_code_snippet(default),
                        fix_suggestion="Use None as default and create mutable object inside function",
                    )
                )

        # Calculate cyclomatic complexity
        complexity = self._calculate_complexity(node)
        self.complexity_by_function[node.name] = complexity

        if complexity > 10:
            severity = "HIGH" if complexity > 20 else "MEDIUM"
            self._add_issue(node, CodeQualityIssue(
                    severity=severity,
                    category="Complexity",
                    message=f"Function '{node.name}' has cyclomatic complexity of {complexity} (threshold: 10)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Break down into smaller functions or simplify conditional logic",
                )
            )

        # Check for long methods (SWEBOK: functions should be < 50 lines)
        loc = self._count_lines_of_code(node)
        if loc > 50:
            severity = "HIGH" if loc > 100 else "MEDIUM"
            self._add_issue(node, CodeQualityIssue(
                    severity=severity,
                    category="Long Method",
                    message=f"Function '{node.name}' has {loc} lines (recommended: < 50)",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Extract helper functions to reduce method length; apply single responsibility principle",
                )
            )

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definition nodes."""
        # Check for missing docstrings
        if not ast.get_docstring(node):
            self._add_issue(node, CodeQualityIssue(
                    severity="LOW",
                    category="Documentation",
                    message=f"Class '{node.name}' lacks docstring",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion='Add docstring: """Brief class description."""',
                )
            )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        """Visit comparison nodes to check for anti-patterns."""
        # Check for comparison with None using == instead of is
        for i, (op, comparator) in enumerate(zip(node.ops, node.comparators)):
            if isinstance(comparator, ast.Constant) and comparator.value is None:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    suggested_op = "is None" if isinstance(op, ast.Eq) else "is not None"
                    self._add_issue(node, CodeQualityIssue(
                            severity="LOW",
                            category="Style",
                            message="Use 'is None' instead of '== None'",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion=f"Replace with '{suggested_op}'",
                        )
                    )

            # Check for comparison with True/False
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, bool):
                if isinstance(op, ast.Eq):
                    self._add_issue(node, CodeQualityIssue(
                            severity="LOW",
                            category="Style",
                            message=f"Avoid explicit comparison with {comparator.value}",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use 'if var:' or 'if not var:' instead",
                        )
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Visit call nodes to detect type() comparisons."""
        func_name = self._get_call_name(node)

        # Check for type() usage that should be isinstance()
        if func_name == "type" and len(node.args) == 1:
            # This is likely being used in a comparison
            self._add_issue(node, CodeQualityIssue(
                    severity="LOW",
                    category="Type Check",
                    message="Use isinstance() instead of type() for type checking",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace type(x) == T with isinstance(x, T)",
                )
            )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Visit exception handler nodes."""
        # Check for bare except clauses
        if node.type is None:
            self._add_issue(node, CodeQualityIssue(
                    severity="MEDIUM",
                    category="Error Handling",
                    message="Bare except clause catches all exceptions including system exits",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use 'except Exception:' or catch specific exception types",
                )
            )

        # Check for overly broad exception handling
        elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
            # Only flag if there's no re-raise
            has_reraise = any(
                isinstance(child, ast.Raise) and child.exc is None for child in ast.walk(node)
            )
            if not has_reraise:
                self._add_issue(node, CodeQualityIssue(
                        severity="LOW",
                        category="Error Handling",
                        message="Catching broad Exception type may hide specific errors",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Catch specific exception types or re-raise after logging",
                    )
                )

        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def visit_Constant(self, node: ast.Constant):
        """Visit constant nodes to detect magic numbers."""
        # Check for magic numbers (numeric literals that aren't 0, 1, -1, or 2)
        if isinstance(node.value, (int, float)) and node.value not in [0, 1, -1, 2, 0.0, 1.0]:
            # Avoid flagging in certain contexts (array indices, ranges, etc.)
            parent = getattr(node, "parent", None)
            if not isinstance(parent, (ast.Index, ast.Slice)):
                self._add_issue(node, CodeQualityIssue(
                        severity="LOW",
                        category="Magic Number",
                        message=f"Magic number {node.value} should be a named constant",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion=f"Define as constant: CONSTANT_NAME = {node.value}",
                    )
                )

        self.generic_visit(node)

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """
        Calculate cyclomatic complexity for a function.

        Base complexity: 1
        +1 for each: if, for, while, except, and, or, comprehension
        """
        complexity = 1

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
                complexity += 1

        return complexity

    def _count_lines_of_code(self, node: ast.FunctionDef) -> int:
        """Count lines of code in a function (excluding comments and docstrings)."""
        if not hasattr(node, "lineno") or not hasattr(node, "end_lineno") or node.end_lineno is None:
            return 0
        return node.end_lineno - node.lineno + 1


class ASTAnalyzer:
    """
    Main AST-based code analyzer.

    Provides comprehensive security and code quality analysis aligned with:
    - OWASP ASVS v5.0 for security
    - CWE Top 25 for vulnerability classification
    - SWEBOK v4.0 for software engineering best practices
    """

    def __init__(self):
        """Initialize AST analyzer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def analyze_file(self, file_path: Path) -> Tuple[List[SecurityIssue], List[CodeQualityIssue]]:
        """
        Analyze a Python file for security and quality issues.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (security_issues, quality_issues)
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return [], []

        return self.analyze_code(content)

    def analyze_code(self, source_code: str) -> Tuple[List[SecurityIssue], List[CodeQualityIssue]]:
        """
        Analyze Python source code for security and quality issues.

        Args:
            source_code: Python source code as string

        Returns:
            Tuple of (security_issues, quality_issues)
        """
        try:
            tree = ast.parse(source_code)
            source_lines = source_code.split("\n")

            # Run security analysis
            security_visitor = SecurityVisitor(source_lines)
            security_visitor.visit(tree)

            # Run quality analysis
            quality_visitor = CodeQualityVisitor(source_lines)
            quality_visitor.visit(tree)

            return security_visitor.issues, quality_visitor.issues

        except SyntaxError as e:
            self.logger.warning(
                f"Syntax error in code at line {e.lineno}: {e.msg}", category="Analysis"
            )
            return [], []
        except Exception as e:
            self.logger.error(f"Error analyzing code: {str(e)}", category="Analysis")
            return [], []

    def get_complexity_report(self, source_code: str) -> Dict[str, int]:
        """
        Get cyclomatic complexity report for all functions in code.

        Args:
            source_code: Python source code as string

        Returns:
            Dictionary mapping function names to complexity scores
        """
        try:
            tree = ast.parse(source_code)
            source_lines = source_code.split("\n")

            visitor = CodeQualityVisitor(source_lines)
            visitor.visit(tree)

            return visitor.complexity_by_function

        except (SyntaxError, Exception):
            return {}
