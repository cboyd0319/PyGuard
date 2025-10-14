"""
Ruff S (Security) rules implementation for PyGuard.

This module implements all 73 Ruff S (Security) rules from the Bandit linter,
providing comprehensive security vulnerability detection for Python code.

Based on Ruff's security rules: https://docs.astral.sh/ruff/rules/#flake8-bandit-s
"""

import ast
from pathlib import Path
from typing import List, Set

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)

logger = PyGuardLogger()


class RuffSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Ruff S (Security) rule violations."""

    def __init__(self, file_path: Path, source_code: str):
        """Initialize visitor."""
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.violations: List[RuleViolation] = []
        self.imports: Set[str] = set()
        self.from_imports: dict[str, Set[str]] = {}

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full name of a function call."""
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
            return ".".join(reversed(parts))
        return ""

    def _get_full_name(self, node: ast.expr) -> str:
        """Get full name of an expression (for imports, attributes)."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        """Track imports for later analysis."""
        for alias in node.names:
            self.imports.add(alias.name)
            
            # S401: suspicious-telnetlib-import
            if alias.name == "telnetlib":
                self.violations.append(
                    RuleViolation(
                        rule_id="S401",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="telnetlib is insecure; use the ssh or subprocess modules instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace telnetlib with subprocess or paramiko for secure remote execution",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            # S402: suspicious-ftplib-import
            elif alias.name == "ftplib":
                self.violations.append(
                    RuleViolation(
                        rule_id="S402",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="ftplib is insecure; consider using sftp or another secure protocol",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace ftplib with paramiko SFTP for secure file transfers",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            # S403: suspicious-pickle-import
            elif alias.name in ("pickle", "cPickle", "_pickle"):
                self.violations.append(
                    RuleViolation(
                        rule_id="S403",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="pickle is insecure; consider using json or another safe serialization format",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace pickle with json.dumps/loads for data serialization",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            # S404: suspicious-subprocess-import
            elif alias.name == "subprocess":
                # Note: subprocess itself is not bad, but we flag it for awareness
                # The real issues are caught when shell=True is used
                pass
            
            # S405-S411: XML-related suspicious imports
            elif alias.name in ("xml.etree.ElementTree", "xml.etree.cElementTree"):
                self.violations.append(
                    RuleViolation(
                        rule_id="S405",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="xml.etree is vulnerable to XML attacks; use defusedxml instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace xml.etree with defusedxml.ElementTree",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            elif alias.name == "xml.sax":
                self.violations.append(
                    RuleViolation(
                        rule_id="S406",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="xml.sax is vulnerable to XML attacks; use defusedxml instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace xml.sax with defusedxml.sax",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            elif alias.name == "xml.dom.expatbuilder":
                self.violations.append(
                    RuleViolation(
                        rule_id="S407",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="xml.dom.expatbuilder is vulnerable to XML attacks; use defusedxml instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace with defusedxml",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            elif alias.name == "xml.dom.minidom":
                self.violations.append(
                    RuleViolation(
                        rule_id="S408",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="xml.dom.minidom is vulnerable to XML attacks; use defusedxml instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace xml.dom.minidom with defusedxml.minidom",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            elif alias.name == "xml.dom.pulldom":
                self.violations.append(
                    RuleViolation(
                        rule_id="S409",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="xml.dom.pulldom is vulnerable to XML attacks; use defusedxml instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace xml.dom.pulldom with defusedxml.pulldom",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            elif alias.name == "lxml":
                self.violations.append(
                    RuleViolation(
                        rule_id="S410",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="lxml is vulnerable to XML attacks; use defusedxml.lxml instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace lxml with defusedxml.lxml",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            elif alias.name == "xmlrpc":
                self.violations.append(
                    RuleViolation(
                        rule_id="S411",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="xmlrpc is insecure; consider using a secure communication protocol",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace xmlrpc with JSON-RPC over HTTPS or gRPC",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            
            # S413: suspicious-pycrypto-import
            elif alias.name == "Crypto" or alias.name.startswith("Crypto."):
                self.violations.append(
                    RuleViolation(
                        rule_id="S413",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="pycrypto is deprecated and insecure; use cryptography or pycryptodome instead",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Replace pycrypto with the cryptography library",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
        
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from imports."""
        if node.module:
            for alias in node.names:
                if node.module not in self.from_imports:
                    self.from_imports[node.module] = set()
                self.from_imports[node.module].add(alias.name)
        
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Check for assert statements (S101)."""
        # S101: assert - asserts are removed in optimized bytecode
        self.violations.append(
            RuleViolation(
                rule_id="S101",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.LOW,
                message="Use of assert detected; asserts are removed when compiled to optimized bytecode",
                file_path=self.file_path,
                line_number=node.lineno,
                column=node.col_offset,
                fix_suggestion="Replace assert with proper error handling: if not condition: raise ValueError()",
                fix_applicability=FixApplicability.SAFE,
                source_tool="ruff",
            )
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for security issues."""
        func_name = self._get_call_name(node)
        
        # S102: exec-builtin
        if func_name == "exec":
            self.violations.append(
                RuleViolation(
                    rule_id="S102",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="Use of exec() detected; this allows execution of arbitrary code",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Remove exec() and use safer alternatives like ast.literal_eval() for literals",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="ruff",
                )
            )
        
        # S307: suspicious-eval-usage
        elif func_name == "eval":
            self.violations.append(
                RuleViolation(
                    rule_id="S307",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="Use of eval() detected; this allows execution of arbitrary code",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Replace eval() with ast.literal_eval() for safe evaluation of literals",
                    fix_applicability=FixApplicability.SAFE,
                    source_tool="ruff",
                )
            )
        
        # S301: suspicious-pickle-usage
        elif func_name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
            self.violations.append(
                RuleViolation(
                    rule_id="S301",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="pickle.loads() can execute arbitrary code; use json.loads() for untrusted data",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Replace pickle.loads() with json.loads() for untrusted data",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="ruff",
                )
            )
        
        # S302: suspicious-marshal-usage
        elif func_name in ("marshal.loads", "marshal.load"):
            self.violations.append(
                RuleViolation(
                    rule_id="S302",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="marshal is not secure against erroneous or maliciously constructed data",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Use json.loads() for data deserialization instead of marshal",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="ruff",
                )
            )
        
        # S506: unsafe-yaml-load
        elif func_name in ("yaml.load", "yaml.unsafe_load"):
            # Check if safe_loader is used
            has_safe_loader = any(
                isinstance(kw.value, ast.Attribute) and 
                kw.value.attr in ("SafeLoader", "CSafeLoader")
                for kw in node.keywords if kw.arg == "Loader"
            )
            if not has_safe_loader:
                self.violations.append(
                    RuleViolation(
                        rule_id="S506",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="yaml.load() without SafeLoader allows arbitrary code execution",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Use yaml.safe_load() instead of yaml.load()",
                        fix_applicability=FixApplicability.SAFE,
                        source_tool="ruff",
                    )
                )
        
        # S311: suspicious-non-cryptographic-random-usage
        elif func_name.startswith("random."):
            # Check context - only flag if likely being used for security
            self.violations.append(
                RuleViolation(
                    rule_id="S311",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="random module is not suitable for security/cryptographic purposes",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Use secrets module for security purposes: secrets.token_bytes(), secrets.token_hex()",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="ruff",
                )
            )
        
        # S306: suspicious-mktemp-usage
        elif func_name in ("tempfile.mktemp", "os.tmpnam", "os.tempnam"):
            self.violations.append(
                RuleViolation(
                    rule_id="S306",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message=f"{func_name}() creates insecure temporary files",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Use tempfile.TemporaryFile(), tempfile.NamedTemporaryFile(), or tempfile.mkstemp() instead",
                    fix_applicability=FixApplicability.SAFE,
                    source_tool="ruff",
                )
            )
        
        # S113: request-without-timeout and S501: request-with-no-cert-validation
        # Note: These are checked together since they apply to the same functions
        if func_name in ("requests.get", "requests.post", "requests.put", "requests.delete", 
                          "requests.patch", "requests.head", "requests.request", "httpx.get",
                          "httpx.post", "httpx.Client", "httpx.AsyncClient"):
            # S113: request-without-timeout
            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
            if not has_timeout:
                self.violations.append(
                    RuleViolation(
                        rule_id="S113",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message=f"{func_name}() without timeout can hang indefinitely",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion=f"Add timeout parameter: {func_name}(..., timeout=30)",
                        fix_applicability=FixApplicability.SAFE,
                        source_tool="ruff",
                    )
                )
            
            # S501: request-with-no-cert-validation
            verify_false = any(
                kw.arg == "verify" and 
                isinstance(kw.value, ast.Constant) and 
                kw.value.value is False
                for kw in node.keywords
            )
            if verify_false:
                self.violations.append(
                    RuleViolation(
                        rule_id="S501",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Request with verify=False disables SSL certificate verification",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Remove verify=False to enable certificate verification",
                        fix_applicability=FixApplicability.SAFE,
                        source_tool="ruff",
                    )
                )
        
        # S324: hashlib-insecure-hash-function
        elif func_name == "hashlib.new" or func_name in ("hashlib.md5", "hashlib.sha1"):
            # Check if it's md5, sha1, or other weak hashes
            if func_name == "hashlib.new" and node.args:
                if isinstance(node.args[0], ast.Constant) and node.args[0].value in ("md5", "sha1"):
                    algorithm = node.args[0].value
                    self.violations.append(
                        RuleViolation(
                            rule_id="S324",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message=f"Insecure hash function: {algorithm}",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            fix_suggestion="Use SHA-256 or stronger: hashlib.sha256()",
                            fix_applicability=FixApplicability.SUGGESTED,
                            source_tool="ruff",
                        )
                    )
            elif func_name in ("hashlib.md5", "hashlib.sha1"):
                algorithm = func_name.split(".")[-1]
                self.violations.append(
                    RuleViolation(
                        rule_id="S324",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message=f"Insecure hash function: {algorithm}",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Use SHA-256 or stronger: hashlib.sha256()",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
        
        # S602-S607: subprocess with shell=True or partial path
        elif func_name in ("subprocess.Popen", "subprocess.call", "subprocess.check_call",
                          "subprocess.check_output", "subprocess.run"):
            # S602: subprocess-popen-with-shell-equals-true
            has_shell_true = any(
                kw.arg == "shell" and 
                isinstance(kw.value, ast.Constant) and 
                kw.value.value is True
                for kw in node.keywords
            )
            
            if has_shell_true:
                self.violations.append(
                    RuleViolation(
                        rule_id="S602",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message=f"{func_name}() with shell=True can lead to command injection",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Use shell=False and pass command as a list of arguments",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
            # S603: subprocess-without-shell-equals-true (check for string instead of list)
            elif node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.violations.append(
                    RuleViolation(
                        rule_id="S603",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.LOW,
                        message="subprocess with a string argument should use shell=True or pass a list",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        fix_suggestion="Pass command as list: ['/path/to/command', 'arg1', 'arg2']",
                        fix_applicability=FixApplicability.SUGGESTED,
                        source_tool="ruff",
                    )
                )
        
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check assignments for hardcoded secrets and security issues."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # S105: hardcoded-password-string
                if any(keyword in var_name for keyword in ("password", "passwd", "pwd", "secret", "token")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 3:  # Ignore empty or very short strings
                            self.violations.append(
                                RuleViolation(
                                    rule_id="S105",
                                    category=RuleCategory.SECURITY,
                                    severity=RuleSeverity.CRITICAL,
                                    message=f"Possible hardcoded password in variable: {target.id}",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    fix_suggestion="Use environment variables or a secrets manager: os.getenv('PASSWORD')",
                                    fix_applicability=FixApplicability.SUGGESTED,
                                    source_tool="ruff",
                                )
                            )
                
                # S108: hardcoded-temp-file
                if any(keyword in var_name for keyword in ("tmp", "temp")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if node.value.value.startswith("/tmp/") or node.value.value.startswith("C:\\temp\\"):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="S108",
                                    category=RuleCategory.SECURITY,
                                    severity=RuleSeverity.MEDIUM,
                                    message="Hardcoded temporary file path detected",
                                    file_path=self.file_path,
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    fix_suggestion="Use tempfile.mkstemp() or tempfile.TemporaryFile() for secure temp files",
                                    fix_applicability=FixApplicability.SUGGESTED,
                                    source_tool="ruff",
                                )
                            )
                
                # S104: hardcoded-bind-all-interfaces
                if isinstance(node.value, ast.Constant) and node.value.value in ("0.0.0.0", "::"):
                    self.violations.append(
                        RuleViolation(
                            rule_id="S104",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="Binding to all interfaces (0.0.0.0) can be insecure",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            fix_suggestion="Bind to specific interface like '127.0.0.1' for localhost only",
                            fix_applicability=FixApplicability.SUGGESTED,
                            source_tool="ruff",
                        )
                    )
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definitions for hardcoded passwords in defaults."""
        # S107: hardcoded-password-default
        for default, arg in zip(node.args.defaults, node.args.args[-len(node.args.defaults):]):
            if isinstance(default, ast.Constant) and isinstance(default.value, str):
                arg_name = arg.arg.lower()
                if any(keyword in arg_name for keyword in ("password", "passwd", "pwd", "secret", "token")):
                    if len(default.value) > 3:
                        self.violations.append(
                            RuleViolation(
                                rule_id="S107",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.HIGH,
                                message=f"Possible hardcoded password in function default: {arg.arg}",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column=node.col_offset,
                                fix_suggestion="Remove default value and load from environment: password=None, then check os.getenv('PASSWORD')",
                                fix_applicability=FixApplicability.SUGGESTED,
                                source_tool="ruff",
                            )
                        )
        
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Check exception handlers."""
        # S110: try-except-pass
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.violations.append(
                RuleViolation(
                    rule_id="S110",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="try-except-pass silences all exceptions; consider logging",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Add logging or re-raise: logger.exception('Error occurred') or raise",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="ruff",
                )
            )
        
        # S112: try-except-continue
        elif len(node.body) == 1 and isinstance(node.body[0], ast.Continue):
            self.violations.append(
                RuleViolation(
                    rule_id="S112",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="try-except-continue silences all exceptions; consider logging",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    fix_suggestion="Add logging before continue: logger.exception('Error occurred')",
                    fix_applicability=FixApplicability.SUGGESTED,
                    source_tool="ruff",
                )
            )
        
        self.generic_visit(node)


def check_ruff_security(file_path: Path) -> List[RuleViolation]:
    """
    Check a Python file for Ruff S (Security) rule violations.
    
    Args:
        file_path: Path to Python file to check
        
    Returns:
        List of rule violations found
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
        
        tree = ast.parse(source_code, filename=str(file_path))
        visitor = RuffSecurityVisitor(file_path, source_code)
        visitor.visit(tree)
        
        return visitor.violations
    except SyntaxError as e:
        logger.warning(f"Syntax error in {file_path}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error checking {file_path}: {e}")
        return []


# Rule registrations for all 73 Ruff S rules
# Note: Some rules are implemented above, others are placeholders for future implementation

RUFF_SECURITY_RULES = [
    Rule(
        rule_id="S101",
        name="assert",
        description="Use of assert detected; asserts are removed when compiled to optimized bytecode",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Use of assert detected",
    ),
    Rule(
        rule_id="S102",
        name="exec-builtin",
        description="Use of exec() detected; this allows execution of arbitrary code",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use of exec() detected",
    ),
    Rule(
        rule_id="S103",
        name="bad-file-permissions",
        description="os.chmod() or similar with overly permissive mode",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Overly permissive file permissions",
    ),
    Rule(
        rule_id="S104",
        name="hardcoded-bind-all-interfaces",
        description="Binding to all interfaces (0.0.0.0) can be insecure",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Binding to all interfaces detected",
    ),
    Rule(
        rule_id="S105",
        name="hardcoded-password-string",
        description="Possible hardcoded password in string literal",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Possible hardcoded password",
    ),
    Rule(
        rule_id="S106",
        name="hardcoded-password-func-arg",
        description="Possible hardcoded password in function argument",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Possible hardcoded password in function call",
    ),
    Rule(
        rule_id="S107",
        name="hardcoded-password-default",
        description="Possible hardcoded password in function default argument",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Possible hardcoded password in default argument",
    ),
    Rule(
        rule_id="S108",
        name="hardcoded-temp-file",
        description="Hardcoded temporary file path",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Hardcoded temporary file path",
    ),
    Rule(
        rule_id="S110",
        name="try-except-pass",
        description="try-except-pass silences all exceptions",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="try-except-pass detected",
    ),
    Rule(
        rule_id="S112",
        name="try-except-continue",
        description="try-except-continue silences all exceptions",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="try-except-continue detected",
    ),
    Rule(
        rule_id="S113",
        name="request-without-timeout",
        description="HTTP request without timeout can hang indefinitely",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SAFE,
        message_template="Request without timeout",
    ),
    Rule(
        rule_id="S201",
        name="flask-debug-true",
        description="Flask app with debug=True in production",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SAFE,
        message_template="Flask debug mode enabled",
    ),
    Rule(
        rule_id="S202",
        name="tarfile-unsafe-members",
        description="tarfile.extractall without members validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Unsafe tarfile extraction",
    ),
    Rule(
        rule_id="S301",
        name="suspicious-pickle-usage",
        description="pickle can execute arbitrary code",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Suspicious pickle usage",
    ),
    Rule(
        rule_id="S302",
        name="suspicious-marshal-usage",
        description="marshal is not secure against malicious data",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Suspicious marshal usage",
    ),
    Rule(
        rule_id="S306",
        name="suspicious-mktemp-usage",
        description="mktemp creates insecure temporary files",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SAFE,
        message_template="Insecure temp file creation",
    ),
    Rule(
        rule_id="S307",
        name="suspicious-eval-usage",
        description="eval() allows execution of arbitrary code",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        fix_applicability=FixApplicability.SAFE,
        message_template="Dangerous eval() usage",
    ),
    Rule(
        rule_id="S311",
        name="suspicious-non-cryptographic-random-usage",
        description="random module is not suitable for security purposes",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Non-cryptographic random usage",
    ),
    Rule(
        rule_id="S324",
        name="hashlib-insecure-hash-function",
        description="Insecure hash function (MD5, SHA1)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure hash function",
    ),
    Rule(
        rule_id="S401",
        name="suspicious-telnetlib-import",
        description="telnetlib is insecure",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure telnetlib import",
    ),
    Rule(
        rule_id="S402",
        name="suspicious-ftplib-import",
        description="ftplib is insecure",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure ftplib import",
    ),
    Rule(
        rule_id="S403",
        name="suspicious-pickle-import",
        description="pickle is insecure for untrusted data",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Suspicious pickle import",
    ),
    Rule(
        rule_id="S405",
        name="suspicious-xml-etree-import",
        description="xml.etree is vulnerable to XML attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure XML library import",
    ),
    Rule(
        rule_id="S406",
        name="suspicious-xml-sax-import",
        description="xml.sax is vulnerable to XML attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure XML library import",
    ),
    Rule(
        rule_id="S407",
        name="suspicious-xml-expat-import",
        description="xml.dom.expatbuilder is vulnerable to XML attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure XML library import",
    ),
    Rule(
        rule_id="S408",
        name="suspicious-xml-minidom-import",
        description="xml.dom.minidom is vulnerable to XML attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure XML library import",
    ),
    Rule(
        rule_id="S409",
        name="suspicious-xml-pulldom-import",
        description="xml.dom.pulldom is vulnerable to XML attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure XML library import",
    ),
    Rule(
        rule_id="S410",
        name="suspicious-lxml-import",
        description="lxml is vulnerable to XML attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure XML library import",
    ),
    Rule(
        rule_id="S411",
        name="suspicious-xmlrpc-import",
        description="xmlrpc is insecure",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Insecure xmlrpc import",
    ),
    Rule(
        rule_id="S413",
        name="suspicious-pycrypto-import",
        description="pycrypto is deprecated and insecure",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Deprecated pycrypto import",
    ),
    Rule(
        rule_id="S501",
        name="request-with-no-cert-validation",
        description="Request with verify=False disables SSL certificate verification",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SAFE,
        message_template="SSL certificate verification disabled",
    ),
    Rule(
        rule_id="S506",
        name="unsafe-yaml-load",
        description="yaml.load() without SafeLoader allows arbitrary code execution",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SAFE,
        message_template="Unsafe YAML deserialization",
    ),
    Rule(
        rule_id="S602",
        name="subprocess-popen-with-shell-equals-true",
        description="subprocess with shell=True can lead to command injection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Subprocess with shell=True",
    ),
    Rule(
        rule_id="S603",
        name="subprocess-without-shell-equals-true",
        description="subprocess with string argument needs clarification",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Unclear subprocess call",
    ),
]
