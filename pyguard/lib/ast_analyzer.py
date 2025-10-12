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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pyguard.lib.core import PyGuardLogger, FileOperations


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
    
    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, 'lineno') and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ""
    
    def visit_Call(self, node: ast.Call):
        """Visit function call nodes."""
        func_name = self._get_call_name(node)
        
        # OWASP ASVS-5.2.1, CWE-95: Code Injection
        if func_name in ['eval', 'exec', 'compile']:
            self.issues.append(SecurityIssue(
                severity="HIGH",
                category="Code Injection",
                message=f"Dangerous use of {func_name}() - executes arbitrary code",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion=f"Replace {func_name}() with safer alternatives: ast.literal_eval() for literals, json.loads() for data",
                owasp_id="ASVS-5.2.1",
                cwe_id="CWE-95"
            ))
        
        # OWASP ASVS-5.5.3, CWE-502: Unsafe Deserialization - YAML
        if func_name == 'yaml.load':
            self.issues.append(SecurityIssue(
                severity="HIGH",
                category="Unsafe Deserialization",
                message="yaml.load() allows arbitrary code execution",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Use yaml.safe_load() instead, which only deserializes safe types",
                owasp_id="ASVS-5.5.3",
                cwe_id="CWE-502"
            ))
        
        # OWASP ASVS-5.5.3, CWE-502: Unsafe Deserialization - Pickle
        if func_name in ['pickle.load', 'pickle.loads']:
            self.issues.append(SecurityIssue(
                severity="MEDIUM",
                category="Unsafe Deserialization",
                message=f"{func_name}() can execute arbitrary code during unpickling",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Use json.load() or msgpack for untrusted data; only use pickle for trusted sources",
                owasp_id="ASVS-5.5.3",
                cwe_id="CWE-502"
            ))
        
        # OWASP ASVS-5.3.3, CWE-78: Command Injection
        if func_name in ['subprocess.call', 'subprocess.run', 'subprocess.Popen', 'os.system']:
            shell_arg = self._get_keyword_arg(node, 'shell')
            if shell_arg and isinstance(shell_arg, ast.Constant) and shell_arg.value is True:
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    category="Command Injection",
                    message=f"{func_name}() with shell=True allows command injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Pass command as list and use shell=False (default): subprocess.run(['cmd', 'arg1', 'arg2'])",
                    owasp_id="ASVS-5.3.3",
                    cwe_id="CWE-78"
                ))
        
        # OWASP ASVS-6.2.1, CWE-327: Weak Cryptography
        if func_name in ['hashlib.md5', 'hashlib.sha1']:
            hash_type = func_name.split('.')[1].upper()
            self.issues.append(SecurityIssue(
                severity="MEDIUM",
                category="Weak Cryptography",
                message=f"{hash_type} is cryptographically broken",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Use SHA-256 or SHA-3: hashlib.sha256() or hashlib.sha3_256()",
                owasp_id="ASVS-6.2.1",
                cwe_id="CWE-327"
            ))
        
        # OWASP ASVS-6.3.1, CWE-330: Weak Random
        if func_name.startswith('random.') and func_name not in ['random.seed', 'random.choice']:
            # Check if in security context
            if self._in_security_context(node):
                self.issues.append(SecurityIssue(
                    severity="MEDIUM",
                    category="Weak Random",
                    message="random module is not cryptographically secure",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use secrets module: secrets.token_urlsafe(), secrets.token_hex(), or secrets.randbelow()",
                    owasp_id="ASVS-6.3.1",
                    cwe_id="CWE-330"
                ))
        
        # OWASP ASVS-9.1.1, CWE-319: Insecure HTTP
        if func_name in ['requests.get', 'requests.post', 'urllib.request.urlopen']:
            if node.args and isinstance(node.args[0], ast.Constant):
                url = node.args[0].value
                if isinstance(url, str) and url.startswith('http://'):
                    self.issues.append(SecurityIssue(
                        severity="MEDIUM",
                        category="Insecure Communication",
                        message="Using insecure HTTP instead of HTTPS",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use HTTPS for secure communication",
                        owasp_id="ASVS-9.1.1",
                        cwe_id="CWE-319"
                    ))
        
        # OWASP ASVS-8.2.2, CWE-326: Weak SSL/TLS
        if 'ssl.wrap_socket' in func_name or 'SSLContext' in func_name:
            # Check for weak protocol versions
            pass  # TODO: Check SSL version arguments
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Visit assignment nodes to detect hardcoded secrets."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # OWASP ASVS-2.6.3, CWE-798: Hardcoded Credentials
                sensitive_names = ['password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 
                                   'token', 'auth', 'credential', 'private_key']
                
                if any(name in var_name for name in sensitive_names):
                    # Check if value is a hardcoded string
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if node.value.value and node.value.value not in ['', 'None', 'null']:
                            self.issues.append(SecurityIssue(
                                severity="HIGH",
                                category="Hardcoded Credentials",
                                message=f"Hardcoded {var_name} detected",
                                line_number=node.lineno,
                                column=node.col_offset,
                                code_snippet=self._get_code_snippet(node),
                                fix_suggestion="Use environment variables: os.environ.get('VAR_NAME') or config files",
                                owasp_id="ASVS-2.6.3",
                                cwe_id="CWE-798"
                            ))
        
        self.generic_visit(node)
    
    def visit_Compare(self, node: ast.Compare):
        """Visit comparison nodes to detect SQL injection patterns."""
        # Detect string concatenation in SQL queries (simplified detection)
        if self._looks_like_sql_query(node):
            self.issues.append(SecurityIssue(
                severity="HIGH",
                category="SQL Injection",
                message="Potential SQL injection vulnerability",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                owasp_id="ASVS-5.3.4",
                cwe_id="CWE-89"
            ))
        
        self.generic_visit(node)
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.insert(0, current.id)
            return '.'.join(parts)
        return ""
    
    def _get_keyword_arg(self, node: ast.Call, keyword: str) -> Optional[ast.AST]:
        """Get a keyword argument from a function call."""
        for kw in node.keywords:
            if kw.arg == keyword:
                return kw.value
        return None
    
    def _in_security_context(self, node: ast.AST) -> bool:
        """Check if node is in a security-sensitive context."""
        # Look at surrounding context for security-related variable names
        snippet = self._get_code_snippet(node).lower()
        security_keywords = ['password', 'token', 'key', 'secret', 'auth', 'credential']
        return any(keyword in snippet for keyword in security_keywords)
    
    def _looks_like_sql_query(self, node: ast.Compare) -> bool:
        """Heuristic to detect if this looks like SQL query construction."""
        snippet = self._get_code_snippet(node).upper()
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
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
    
    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, 'lineno') and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ""
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition nodes."""
        # Check for missing docstrings (except private functions)
        if not node.name.startswith('_'):
            if not ast.get_docstring(node):
                self.issues.append(CodeQualityIssue(
                    severity="LOW",
                    category="Documentation",
                    message=f"Function '{node.name}' lacks docstring",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion='Add docstring: """Brief description."""'
                ))
        
        # Check for too many parameters
        num_params = len(node.args.args)
        if num_params > 6:
            self.issues.append(CodeQualityIssue(
                severity="MEDIUM",
                category="Complexity",
                message=f"Function '{node.name}' has {num_params} parameters (max recommended: 6)",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Refactor to use fewer parameters or group related parameters into a dataclass/dict"
            ))
        
        # Check for mutable default arguments
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.issues.append(CodeQualityIssue(
                    severity="HIGH",
                    category="Anti-pattern",
                    message="Mutable default argument detected",
                    line_number=default.lineno,
                    column=default.col_offset,
                    code_snippet=self._get_code_snippet(default),
                    fix_suggestion="Use None as default and create mutable object inside function"
                ))
        
        # Calculate cyclomatic complexity
        complexity = self._calculate_complexity(node)
        self.complexity_by_function[node.name] = complexity
        
        if complexity > 10:
            severity = "HIGH" if complexity > 20 else "MEDIUM"
            self.issues.append(CodeQualityIssue(
                severity=severity,
                category="Complexity",
                message=f"Function '{node.name}' has cyclomatic complexity of {complexity} (threshold: 10)",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Break down into smaller functions or simplify conditional logic"
            ))
        
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definition nodes."""
        # Check for missing docstrings
        if not ast.get_docstring(node):
            self.issues.append(CodeQualityIssue(
                severity="LOW",
                category="Documentation",
                message=f"Class '{node.name}' lacks docstring",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion='Add docstring: """Brief class description."""'
            ))
        
        self.generic_visit(node)
    
    def visit_Compare(self, node: ast.Compare):
        """Visit comparison nodes to check for anti-patterns."""
        # Check for comparison with None using == instead of is
        for i, (op, comparator) in enumerate(zip(node.ops, node.comparators)):
            if isinstance(comparator, ast.Constant) and comparator.value is None:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    suggested_op = "is None" if isinstance(op, ast.Eq) else "is not None"
                    self.issues.append(CodeQualityIssue(
                        severity="LOW",
                        category="Style",
                        message="Use 'is None' instead of '== None'",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion=f"Replace with '{suggested_op}'"
                    ))
            
            # Check for comparison with True/False
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, bool):
                if isinstance(op, ast.Eq):
                    self.issues.append(CodeQualityIssue(
                        severity="LOW",
                        category="Style",
                        message=f"Avoid explicit comparison with {comparator.value}",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Use 'if var:' or 'if not var:' instead"
                    ))
        
        self.generic_visit(node)
    
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Visit exception handler nodes."""
        # Check for bare except clauses
        if node.type is None:
            self.issues.append(CodeQualityIssue(
                severity="MEDIUM",
                category="Error Handling",
                message="Bare except clause catches all exceptions including system exits",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self._get_code_snippet(node),
                fix_suggestion="Use 'except Exception:' or catch specific exception types"
            ))
        
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
            source_lines = source_code.split('\n')
            
            # Run security analysis
            security_visitor = SecurityVisitor(source_lines)
            security_visitor.visit(tree)
            
            # Run quality analysis
            quality_visitor = CodeQualityVisitor(source_lines)
            quality_visitor.visit(tree)
            
            return security_visitor.issues, quality_visitor.issues
            
        except SyntaxError as e:
            self.logger.warning(
                f"Syntax error in code at line {e.lineno}: {e.msg}",
                category="Analysis"
            )
            return [], []
        except Exception as e:
            self.logger.error(
                f"Error analyzing code: {str(e)}",
                category="Analysis"
            )
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
            source_lines = source_code.split('\n')
            
            visitor = CodeQualityVisitor(source_lines)
            visitor.visit(tree)
            
            return visitor.complexity_by_function
            
        except (SyntaxError, Exception):
            return {}
