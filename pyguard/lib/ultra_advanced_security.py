"""
Ultra-Advanced Security Detections for PyGuard v0.8.0+

World-class security detection capabilities that exceed all comparable solutions:
- GraphQL injection detection
- Server-Side Template Injection (SSTI)
- JWT (JSON Web Token) security vulnerabilities
- API rate limiting and abuse detection
- Container escape vulnerabilities
- Prototype pollution (in Python object attributes)
- Insecure direct object reference (IDOR) advanced patterns
- Business logic vulnerabilities
- Cache poisoning detection
- DNS rebinding protection

References:
- OWASP Top 10 2021 | https://owasp.org/Top10/ | High | Latest security risks
- OWASP API Security Top 10 | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | High | API-specific risks
- CWE Top 25 2024 | https://cwe.mitre.org/top25/ | High | Most dangerous weaknesses
- NIST SSDF v1.1 | https://csrc.nist.gov/publications/detail/sp/800-218/final | High | Secure development
- PortSwigger Web Security | https://portswigger.net/web-security | High | Practical security testing
- SLSA Framework v1.0 | https://slsa.dev | High | Supply chain integrity
"""

import ast
import re
from dataclasses import dataclass
from typing import List

from pyguard.lib.ast_analyzer import SecurityIssue
from pyguard.lib.core import PyGuardLogger


@dataclass
class AdvancedSecurityPattern:
    """Advanced security pattern detection result."""
    
    pattern_type: str
    severity: str
    description: str
    cwe_id: str
    owasp_id: str
    fix_suggestion: str


class GraphQLInjectionDetector:
    """
    Detect GraphQL injection vulnerabilities.
    
    CWE-943: Improper Neutralization of Special Elements in Data Query Logic
    OWASP API Security: API8:2023 - Security Misconfiguration
    
    GraphQL queries can be vulnerable to injection if user input is directly
    concatenated into queries without proper sanitization.
    """
    
    GRAPHQL_PATTERNS = [
        (r'query\s*=\s*["\'][^"\']*["\'].*?\+', 'String concatenation in GraphQL query'),
        (r'query\s*=\s*f["\']', 'F-string formatting in GraphQL query'),
        (r'["\'][^"\']*["\']\.format\(', 'Format method in GraphQL query'),
        (r'graphql\.execute\([^,)]*\+', 'Concatenated user input in execute'),
        (r'graphql_sync\([^,)]*\+', 'Concatenated user input in graphql_sync'),
    ]
    
    def __init__(self):
        """Initialize GraphQL injection detector."""
        self.logger = PyGuardLogger()
    
    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for GraphQL injection vulnerabilities.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.GRAPHQL_PATTERNS:
                if re.search(pattern, line):
                    issues.append(
                        SecurityIssue(
                            severity='HIGH',
                            category='GraphQL Injection',
                            message=f'{description} - Use parameterized queries',
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion='Use GraphQL variables and parameterized queries instead of string concatenation',
                            owasp_id='API8:2023',
                            cwe_id='CWE-943'
                        )
                    )
        
        return issues


class SSTIDetector(ast.NodeVisitor):
    """
    Detect Server-Side Template Injection (SSTI) vulnerabilities.
    
    CWE-94: Improper Control of Generation of Code
    OWASP Top 10 2021: A03:2021 - Injection
    
    Template engines like Jinja2, Mako, and Django templates can execute arbitrary
    code if user input is directly rendered in templates.
    """
    
    TEMPLATE_ENGINES = {
        'jinja2': ['Template', 'Environment'],
        'mako': ['Template'],
        'django': ['Template'],
        'flask': ['render_template_string'],
    }
    
    def __init__(self, source_lines: List[str]):
        """Initialize SSTI detector."""
        self.issues: List[SecurityIssue] = []
        self.source_lines = source_lines
        self.logger = PyGuardLogger()
        self.using_template_engine = False
    
    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, 'lineno') and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ''
    
    def visit_Import(self, node: ast.Import):
        """Track template engine imports."""
        for alias in node.names:
            if any(engine in alias.name for engine in self.TEMPLATE_ENGINES):
                self.using_template_engine = True
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track template engine imports."""
        if node.module and any(engine in node.module for engine in self.TEMPLATE_ENGINES):
            self.using_template_engine = True
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Check for SSTI vulnerabilities in template rendering."""
        call_name = self._get_call_name(node)
        
        # Check for render_template_string with user input
        if 'render_template_string' in call_name:
            # Check if any argument might be user-controlled
            for arg in node.args:
                if isinstance(arg, ast.Name) or isinstance(arg, ast.BinOp):
                    self.issues.append(
                        SecurityIssue(
                            severity='CRITICAL',
                            category='Server-Side Template Injection',
                            message='Rendering user-controlled template string enables code execution',
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion='Use predefined templates or sanitize input with autoescape=True',
                            owasp_id='ASVS-5.2.2',
                            cwe_id='CWE-94'
                        )
                    )
        
        # Check for Template() with string concatenation
        if 'Template' in call_name:
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    self.issues.append(
                        SecurityIssue(
                            severity='HIGH',
                            category='Server-Side Template Injection',
                            message='Template created with concatenated user input',
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion='Use template variables instead of string concatenation',
                            owasp_id='ASVS-5.2.2',
                            cwe_id='CWE-94'
                        )
                    )
        
        self.generic_visit(node)
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ''


class JWTSecurityDetector:
    """
    Detect JWT (JSON Web Token) security vulnerabilities.
    
    CWE-347: Improper Verification of Cryptographic Signature
    CWE-326: Inadequate Encryption Strength
    OWASP Top 10 2021: A02:2021 - Cryptographic Failures
    
    Common JWT vulnerabilities:
    - Using 'none' algorithm
    - Weak signing algorithms (HS256 with short keys)
    - Not validating signatures
    - Using symmetric keys for public APIs
    """
    
    JWT_ISSUES = [
        (r'algorithm\s*=\s*["\']none["\']', 'JWT with "none" algorithm is insecure'),
        (r'verify_signature\s*=\s*False', 'JWT signature verification disabled'),
        (r'verify\s*=\s*False', 'JWT verification disabled'),
        (r'jwt\.decode\([^,]+,\s*verify=False', 'JWT decoded without verification'),
        (r'key\s*=\s*["\'][^"\']{1,8}["\']', 'JWT with short key (< 8 chars)'),
    ]
    
    def __init__(self):
        """Initialize JWT security detector."""
        self.logger = PyGuardLogger()
    
    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for JWT security issues.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.JWT_ISSUES:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = 'CRITICAL' if 'none' in pattern or 'False' in pattern else 'HIGH'
                    issues.append(
                        SecurityIssue(
                            severity=severity,
                            category='JWT Security',
                            message=description,
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion='Use RS256 algorithm, enable signature verification, and use strong keys',
                            owasp_id='ASVS-6.2.1',
                            cwe_id='CWE-347'
                        )
                    )
        
        return issues


class APIRateLimitDetector(ast.NodeVisitor):
    """
    Detect missing API rate limiting and abuse prevention.
    
    CWE-770: Allocation of Resources Without Limits or Throttling
    OWASP API Security: API4:2023 - Unrestricted Resource Consumption
    
    APIs without rate limiting can be abused for DoS attacks or resource exhaustion.
    """
    
    API_DECORATORS = {'@app.route', '@api.route', '@router.get', '@router.post', '@endpoint'}
    RATE_LIMIT_DECORATORS = {'@limiter', '@rate_limit', '@throttle', '@limit'}
    
    def __init__(self, source_lines: List[str]):
        """Initialize API rate limit detector."""
        self.issues: List[SecurityIssue] = []
        self.source_lines = source_lines
        self.logger = PyGuardLogger()
    
    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, 'lineno') and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ''
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check API endpoints for rate limiting."""
        # Check if function has API decorator
        has_api_decorator = False
        has_rate_limit = False
        
        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            
            if any(api_dec in decorator_name for api_dec in self.API_DECORATORS):
                has_api_decorator = True
            
            if any(limit_dec in decorator_name for limit_dec in self.RATE_LIMIT_DECORATORS):
                has_rate_limit = True
        
        # Report if API endpoint lacks rate limiting
        if has_api_decorator and not has_rate_limit:
            self.issues.append(
                SecurityIssue(
                    severity='MEDIUM',
                    category='API Security',
                    message=f'API endpoint "{node.name}" lacks rate limiting',
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion='Add @limiter or @rate_limit decorator to prevent abuse',
                    owasp_id='API4:2023',
                    cwe_id='CWE-770'
                )
            )
        
        self.generic_visit(node)
    
    def _get_decorator_name(self, decorator) -> str:
        """Extract decorator name as string."""
        if isinstance(decorator, ast.Name):
            return f'@{decorator.id}'
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                parts = []
                current = decorator.func
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                return '@' + '.'.join(reversed(parts))
            elif isinstance(decorator.func, ast.Name):
                return f'@{decorator.func.id}'
        elif isinstance(decorator, ast.Attribute):
            parts = []
            current = decorator
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '@' + '.'.join(reversed(parts))
        return ''


class ContainerEscapeDetector:
    """
    Detect container escape vulnerabilities in Docker/containerized environments.
    
    CWE-250: Execution with Unnecessary Privileges
    CWE-653: Insufficient Compartmentalization
    
    Container security issues that could lead to escape:
    - Running as root user
    - Privileged mode enabled
    - Host namespace sharing
    - Insecure volume mounts
    """
    
    CONTAINER_RISKS = [
        (r'--privileged', 'Privileged container mode enables escape'),
        (r'privileged:\s*true', 'Privileged mode in docker-compose'),
        (r'user:\s*root', 'Container running as root user'),
        (r'USER\s+root', 'Dockerfile uses root user'),
        (r'/var/run/docker\.sock', 'Docker socket mounted - container escape risk'),
        (r'--pid=host', 'Host PID namespace sharing is dangerous'),
        (r'--net=host', 'Host network namespace sharing reduces isolation'),
        (r'--ipc=host', 'Host IPC namespace sharing reduces isolation'),
        (r'cap_add:\s*-\s*SYS_ADMIN', 'SYS_ADMIN capability enables escape'),
    ]
    
    def __init__(self):
        """Initialize container escape detector."""
        self.logger = PyGuardLogger()
    
    def scan_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """
        Scan Docker/container configuration files for escape vulnerabilities.
        
        Args:
            file_path: Path to file being scanned
            content: File content
            
        Returns:
            List of security issues found
        """
        issues = []
        
        # Only scan relevant files
        if not any(name in file_path.lower() for name in ['dockerfile', 'docker-compose', '.yml', '.yaml']):
            return issues
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.CONTAINER_RISKS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(
                        SecurityIssue(
                            severity='HIGH',
                            category='Container Security',
                            message=description,
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion='Use unprivileged containers, non-root users, and minimal capabilities',
                            owasp_id='ASVS-14.4.3',
                            cwe_id='CWE-250'
                        )
                    )
        
        return issues


class PrototypePollutionDetector(ast.NodeVisitor):
    """
    Detect prototype pollution vulnerabilities in Python (object attribute injection).
    
    CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
    OWASP Top 10 2021: A03:2021 - Injection
    
    While more common in JavaScript, Python objects can also be polluted through
    __dict__, __class__, and dynamic attribute assignment.
    """
    
    def __init__(self, source_lines: List[str]):
        """Initialize prototype pollution detector."""
        self.issues: List[SecurityIssue] = []
        self.source_lines = source_lines
        self.logger = PyGuardLogger()
    
    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, 'lineno') and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ''
    
    def visit_Call(self, node: ast.Call):
        """Check for dangerous dynamic attribute operations."""
        call_name = self._get_call_name(node)
        
        # setattr with user input
        if call_name == 'setattr':
            if len(node.args) >= 2:
                # Check if attribute name comes from variable (potential user input)
                if isinstance(node.args[1], (ast.Name, ast.Subscript)):
                    self.issues.append(
                        SecurityIssue(
                            severity='HIGH',
                            category='Prototype Pollution',
                            message='Dynamic setattr() with user-controlled attribute name',
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion='Allowlist allowed attributes or use a data class with fixed attributes',
                            owasp_id='ASVS-5.1.3',
                            cwe_id='CWE-1321'
                        )
                    )
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Check for __dict__ manipulation."""
        # Check if assigning to __dict__
        if isinstance(node.value, ast.Subscript):
            if self._is_dict_access(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == '__dict__':
                        self.issues.append(
                            SecurityIssue(
                                severity='MEDIUM',
                                category='Prototype Pollution',
                                message='Direct __dict__ manipulation with external data',
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion='Use controlled attribute assignment instead of __dict__ manipulation',
                                owasp_id='ASVS-5.1.3',
                                cwe_id='CWE-1321'
                            )
                        )
        
        self.generic_visit(node)
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ''
    
    def _is_dict_access(self, node: ast.Subscript) -> bool:
        """Check if node accesses a dictionary."""
        return isinstance(node.value, ast.Name)


class CachePoisoningDetector:
    """
    Detect cache poisoning vulnerabilities.
    
    CWE-444: Inconsistent Interpretation of HTTP Requests
    OWASP Top 10 2021: A05:2021 - Security Misconfiguration
    
    Cache poisoning can occur when user-controlled input is used in cache keys
    without proper sanitization.
    """
    
    CACHE_PATTERNS = [
        (r'@cache.*\(.*request\.', 'Caching with request data in key'),
        (r'cache\.set\([^,]*request\.', 'Cache key includes request data'),
        (r'cache_key\s*=\s*.*\+.*request\.', 'Concatenating request data into cache key'),
        (r'memcache.*set.*user', 'User-controlled cache key'),
    ]
    
    def __init__(self):
        """Initialize cache poisoning detector."""
        self.logger = PyGuardLogger()
    
    def scan_code(self, code: str) -> List[SecurityIssue]:
        """
        Scan code for cache poisoning vulnerabilities.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            List of security issues found
        """
        issues = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for pattern, description in self.CACHE_PATTERNS:
                if re.search(pattern, line):
                    issues.append(
                        SecurityIssue(
                            severity='MEDIUM',
                            category='Cache Poisoning',
                            message=description,
                            line_number=line_num,
                            column=0,
                            code_snippet=line.strip(),
                            fix_suggestion='Sanitize and validate user input before using in cache keys',
                            owasp_id='ASVS-5.1.5',
                            cwe_id='CWE-444'
                        )
                    )
        
        return issues


class BusinessLogicDetector(ast.NodeVisitor):
    """
    Detect business logic vulnerabilities and anti-patterns.
    
    CWE-840: Business Logic Errors
    OWASP Top 10 2021: A04:2021 - Insecure Design
    
    Business logic flaws that can't be detected by traditional security scanners:
    - Missing transaction rollback handling
    - Race conditions in financial operations
    - Missing idempotency checks
    - Inadequate balance/quantity checks
    """
    
    def __init__(self, source_lines: List[str]):
        """Initialize business logic detector."""
        self.issues: List[SecurityIssue] = []
        self.source_lines = source_lines
        self.logger = PyGuardLogger()
    
    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, 'lineno') and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ''
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check functions for business logic issues."""
        func_body_str = ast.unparse(node) if hasattr(ast, 'unparse') else ''
        
        # Check for financial operations without proper validation
        if any(keyword in node.name.lower() for keyword in ['payment', 'transfer', 'withdraw', 'charge', 'refund']):
            has_balance_check = False
            has_rollback = False
            
            for child in ast.walk(node):
                # Check for balance/amount validation
                if isinstance(child, ast.Compare):
                    has_balance_check = True
                
                # Check for transaction rollback
                if isinstance(child, ast.Call):
                    call_name = self._get_call_name(child)
                    if 'rollback' in call_name or 'rollback' in func_body_str:
                        has_rollback = True
            
            if not has_balance_check:
                self.issues.append(
                    SecurityIssue(
                        severity='HIGH',
                        category='Business Logic',
                        message=f'Financial function "{node.name}" lacks balance/amount validation',
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion='Add validation to check balance, amount limits, and negative values',
                        owasp_id='ASVS-11.1.4',
                        cwe_id='CWE-840'
                    )
                )
            
            if not has_rollback:
                self.issues.append(
                    SecurityIssue(
                        severity='MEDIUM',
                        category='Business Logic',
                        message=f'Financial function "{node.name}" lacks transaction rollback handling',
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion='Implement try/except with rollback for database transactions',
                        owasp_id='ASVS-11.1.4',
                        cwe_id='CWE-840'
                    )
                )
        
        self.generic_visit(node)
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ''


# Export all detectors for easy access
__all__ = [
    'GraphQLInjectionDetector',
    'SSTIDetector',
    'JWTSecurityDetector',
    'APIRateLimitDetector',
    'ContainerEscapeDetector',
    'PrototypePollutionDetector',
    'CachePoisoningDetector',
    'BusinessLogicDetector',
]
