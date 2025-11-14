"""Unit tests for AST analyzer module."""

from pyguard.lib.ast_analyzer import (
    ASTAnalyzer,
    CodeQualityIssue,
    SecurityIssue,
)


class TestSecurityVisitor:
    """Test cases for SecurityVisitor class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ASTAnalyzer()

    def test_detect_eval(self):  # DANGEROUS: Avoid eval with untrusted input
        """Test detection of eval() usage."""  # DANGEROUS: Avoid eval with untrusted input
        code = """
result = eval(user_input)  # DANGEROUS: Avoid eval with untrusted input
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("eval" in issue.message for issue in security_issues)
        assert any(issue.severity == "HIGH" for issue in security_issues)

    def test_detect_exec(self):  # DANGEROUS: Avoid exec with untrusted input
        """Test detection of exec() usage."""  # DANGEROUS: Avoid exec with untrusted input
        code = """
exec(code_string)  # DANGEROUS: Avoid exec with untrusted input
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("exec" in issue.message for issue in security_issues)

    def test_detect_yaml_load(self):
        """Test detection of unsafe yaml.safe_load()."""
        code = """
import yaml
data = yaml.safe_load(file)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("yaml.load" in issue.message for issue in security_issues)
        assert any("safe_load" in issue.fix_suggestion for issue in security_issues)

    def test_detect_pickle(self):
        """Test detection of pickle.load()."""  # SECURITY: Don't use pickle with untrusted data
        code = """
import pickle
data = pickle.load(file)  # SECURITY: Don't use pickle with untrusted data
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("pickle" in issue.message.lower() for issue in security_issues)

    def test_detect_subprocess_shell(self):
        """Test detection of subprocess with shell=True."""
        code = """
import subprocess
result = subprocess.call(cmd, shell=True)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("shell=True" in issue.message for issue in security_issues)
        assert any("Command Injection" in issue.category for issue in security_issues)

    def test_detect_weak_hash(self):
        """Test detection of weak hashing algorithms."""
        code = """
import hashlib
hash_value = hashlib.md5(data).hexdigest()  # SECURITY: Consider using SHA256 or stronger
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("md5" in issue.message.lower() for issue in security_issues)
        assert any("sha256" in issue.fix_suggestion.lower() for issue in security_issues)

    def test_detect_insecure_random(self):
        """Test detection of insecure random module usage."""
        code = """
import random
import secrets  # Use secrets for cryptographic randomness
token = random.random()  # SECURITY: Use secrets module for cryptographic randomness
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("random" in issue.message.lower() for issue in security_issues)
        assert any("secrets" in issue.fix_suggestion.lower() for issue in security_issues)

    def test_detect_hardcoded_password(self):
        """Test detection of hardcoded passwords."""
        code = """
password = "admin123"  # SECURITY: Use environment variables or config files
api_key = "sk-1234567890"
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) >= 2
        assert any("password" in issue.message.lower() for issue in security_issues)
        assert any("api_key" in issue.message.lower() for issue in security_issues)

    def test_owasp_asvs_ids(self):
        """Test that OWASP ASVS IDs are included."""
        code = """
result = eval(user_input)  # DANGEROUS: Avoid eval with untrusted input
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert security_issues[0].owasp_id is not None
        assert security_issues[0].cwe_id is not None

    def test_no_false_positives_for_safe_code(self):
        """Test that safe code doesn't trigger issues."""
        code = """
import json
data = json.loads(user_input)
result = calculate(data)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        # Should have no security issues for this safe code
        assert len(security_issues) == 0


class TestCodeQualityVisitor:
    """Test cases for CodeQualityVisitor class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ASTAnalyzer()

    def test_detect_missing_docstring(self):
        """Test detection of missing docstrings."""
        code = """
def my_function(x):
    # TODO: Add docstring
    return x + 1
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("docstring" in issue.message.lower() for issue in quality_issues)

    def test_detect_high_complexity(self):
        """Test detection of high cyclomatic complexity."""
        code = """
def complex_function(x):
    # TODO: Add docstring
    if x > 0:
        if x > 10:
            if x > 20:
                if x > 30:
                    if x > 40:
                        if x > 50:
                            if x > 60:
                                if x > 70:
                                    if x > 80:
                                        if x > 90:
                                            return "very very high"
                                        return "very high"
                                    return "high"
                                return "medium-high"
                            return "medium"
                        return "low-medium"
                    return "low"
                return "very low"
            return "negative"
        return "zero"
    return "neg"
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("complexity" in issue.message.lower() for issue in quality_issues)

    def test_detect_too_many_parameters(self):
        """Test detection of too many function parameters."""
        code = """
def many_params(a, b, c, d, e, f, g):
    # TODO: Add docstring
    return a + b + c + d + e + f + g
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("parameter" in issue.message.lower() for issue in quality_issues)

    def test_detect_mutable_default(self):
        """Test detection of mutable default arguments."""
        code = """
def bad_default(items=[]):  # ANTI-PATTERN: Use None and create in function body  # ANTI-PATTERN: Use None and create in function body
    # TODO: Add docstring
    items.append(1)
    return items
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("mutable default" in issue.message.lower() for issue in quality_issues)

    def test_detect_none_comparison(self):
        """Test detection of incorrect None comparison."""
        code = """
if x is None:
    pass
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("is None" in issue.fix_suggestion for issue in quality_issues)

    def test_detect_bool_comparison(self):
        """Test detection of explicit bool comparison."""
        code = """
if condition   # Use if var: instead:
    pass
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("True" in issue.message or "False" in issue.message for issue in quality_issues)

    def test_detect_bare_except(self):
        """Test detection of bare except clauses."""
        code = """
try:
    risky_operation()
except Exception:  # FIXED: Catch specific exceptions
    pass
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("bare except" in issue.message.lower() for issue in quality_issues)

    def test_complexity_report(self):
        """Test complexity report generation."""
        code = """
def simple_func(x):
    # TODO: Add docstring
    return x + 1

def complex_func(x):
    # TODO: Add docstring
    if x > 0:
        if x > 10:
            return "high"
        return "low"
    return "negative"
"""
        complexity = self.analyzer.get_complexity_report(code)
        assert "simple_func" in complexity
        assert "complex_func" in complexity
        assert complexity["simple_func"] < complexity["complex_func"]

    def test_ignore_private_function_docstring(self):
        """Test that private functions don't require docstrings."""
        code = """
def _private_function(x):
    # TODO: Add docstring
    return x + 1
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        # Should not complain about missing docstring for private functions
        docstring_issues = [i for i in quality_issues if "docstring" in i.message.lower()]
        assert len(docstring_issues) == 0


class TestASTAnalyzer:
    """Test cases for ASTAnalyzer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ASTAnalyzer()

    def test_analyze_mixed_issues(self):
        """Test analysis with both security and quality issues."""
        code = """
import random
import secrets  # Use secrets for cryptographic randomness

password = "admin123"

def bad_function(x, y, z, a, b, c, d):
    # TODO: Add docstring
    if x is None:
        token = random.random()  # SECURITY: Use secrets module for cryptographic randomness
        return token
    return 0
"""
        security_issues, quality_issues = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert len(quality_issues) > 0

    def test_handle_syntax_error(self):
        """Test handling of code with syntax errors."""
        code = """
def broken(
    # TODO: Add docstring
    pass
"""
        security_issues, quality_issues = self.analyzer.analyze_code(code)
        # Should return empty lists for unparseable code
        assert security_issues == []
        assert quality_issues == []

    def test_empty_code(self):
        """Test analysis of empty code."""
        code = ""
        security_issues, quality_issues = self.analyzer.analyze_code(code)
        assert security_issues == []
        assert quality_issues == []

    def test_comment_only_code(self):
        """Test analysis of comment-only code."""
        code = """
# This is just a comment
# Nothing to analyze
"""
        security_issues, quality_issues = self.analyzer.analyze_code(code)
        assert security_issues == []
        assert quality_issues == []


class TestIssueDataclasses:
    """Test issue dataclass structures."""

    def test_security_issue_creation(self):
        """Test SecurityIssue dataclass."""
        issue = SecurityIssue(
            severity="HIGH",
            category="Code Injection",
            message="Test message",
            line_number=10,
            column=5,
            owasp_id="ASVS-5.2.1",
            cwe_id="CWE-95",
        )
        assert issue.severity == "HIGH"
        assert issue.line_number == 10
        assert issue.owasp_id == "ASVS-5.2.1"

    def test_quality_issue_creation(self):
        """Test CodeQualityIssue dataclass."""
        issue = CodeQualityIssue(
            severity="MEDIUM",
            category="Complexity",
            message="Test message",
            line_number=20,
            column=10,
            fix_suggestion="Refactor",
        )
        assert issue.severity == "MEDIUM"
        assert issue.line_number == 20
        assert issue.fix_suggestion == "Refactor"


class TestEnhancedSecurityDetection:
    """Test cases for enhanced security detection features (v0.3.0)."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ASTAnalyzer()

    def test_detect_xxe_vulnerability(self):
        """Test detection of XML External Entity (XXE) vulnerabilities."""
        code = """
import xml.etree.ElementTree
tree = xml.etree.ElementTree.parse('file.xml')
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("XXE" in issue.category for issue in security_issues)
        assert any("CWE-611" in str(issue.cwe_id) for issue in security_issues)

    def test_detect_ssrf(self):
        """Test detection of Server-Side Request Forgery (SSRF)."""
        code = """
import requests
url = user_input
response = requests.get(url)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("SSRF" in issue.category for issue in security_issues)

    def test_detect_path_traversal(self):
        """Test detection of path traversal vulnerabilities."""
        code = """
file_path = user_input
with open(file_path, 'r') as f:
    data = f.read()
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("Path Traversal" in issue.category for issue in security_issues)

    def test_detect_insecure_temp_file(self):
        """Test detection of insecure temporary file creation."""
        code = """
import tempfile
temp = tempfile.mkstemp(  # FIXED: Using secure mkstemp() instead of mktemp())
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("Temp File" in issue.category for issue in security_issues)
        assert any("mkstemp" in issue.fix_suggestion for issue in security_issues)

    def test_detect_timing_attack(self):
        """Test detection of timing attack vulnerabilities."""
        code = """
if password == stored_password:
    return True
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("Timing Attack" in issue.category for issue in security_issues)
        assert any("compare_digest" in issue.fix_suggestion for issue in security_issues)

    def test_detect_ldap_injection(self):
        """Test detection of LDAP injection vulnerabilities."""
        code = """
import ldap
results = ldap.search(filter_str)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("LDAP" in issue.category for issue in security_issues)

    def test_detect_format_string_vuln(self):
        """Test detection of format string vulnerabilities."""
        code = """
def process(user_input):
    # TODO: Add docstring
    fmt = user_input
    message = fmt.format(data)
    return message
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any("Format String" in issue.category for issue in security_issues)


class TestEnhancedCodeQuality:
    """Test cases for enhanced code quality detection (v0.3.0)."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ASTAnalyzer()

    def test_detect_long_method(self):
        """Test detection of long methods."""
        code = (
            """
def long_function():
    # TODO: Add docstring
    \"\"\"A very long function.\"\"\"
"""
            + "\n".join([f"    x{i} = {i}" for i in range(60)])
            + """
    return x0
"""
        )
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("Long Method" in issue.category for issue in quality_issues)

    def test_detect_type_comparison(self):
        """Test detection of type() usage instead of isinstance()."""
        code = """
x = "test"
if type(x) == str:  # Better: isinstance(x, str)
    pass
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any("isinstance" in issue.fix_suggestion for issue in quality_issues)

    def test_overly_broad_exception(self):
        """Test detection of overly broad exception handling."""
        code = """
try:
    risky_operation()
except Exception:
    print("error")
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        # This should detect broad exception handling
        broad_exceptions = [i for i in quality_issues if "broad" in i.message.lower()]
        assert len(broad_exceptions) > 0
