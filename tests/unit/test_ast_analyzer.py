"""Unit tests for AST analyzer module."""

import pytest
from pyguard.lib.ast_analyzer import (
    ASTAnalyzer,
    SecurityVisitor,
    CodeQualityVisitor,
    SecurityIssue,
    CodeQualityIssue
)


class TestSecurityVisitor:
    """Test cases for SecurityVisitor class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ASTAnalyzer()
    
    def test_detect_eval(self):
        """Test detection of eval() usage."""
        code = """
result = eval(user_input)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any('eval' in issue.message for issue in security_issues)
        assert any(issue.severity == "HIGH" for issue in security_issues)
    
    def test_detect_exec(self):
        """Test detection of exec() usage."""
        code = """
exec(code_string)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any('exec' in issue.message for issue in security_issues)
    
    def test_detect_yaml_load(self):
        """Test detection of unsafe yaml.load()."""
        code = """
import yaml
data = yaml.load(file)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any('yaml.load' in issue.message for issue in security_issues)
        assert any('safe_load' in issue.fix_suggestion for issue in security_issues)
    
    def test_detect_pickle(self):
        """Test detection of pickle.load()."""
        code = """
import pickle
data = pickle.load(file)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any('pickle' in issue.message.lower() for issue in security_issues)
    
    def test_detect_subprocess_shell(self):
        """Test detection of subprocess with shell=True."""
        code = """
import subprocess
result = subprocess.call(cmd, shell=True)
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any('shell=True' in issue.message for issue in security_issues)
        assert any('Command Injection' in issue.category for issue in security_issues)
    
    def test_detect_weak_hash(self):
        """Test detection of weak hashing algorithms."""
        code = """
import hashlib
hash_value = hashlib.md5(data).hexdigest()
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any('md5' in issue.message.lower() for issue in security_issues)
        assert any('sha256' in issue.fix_suggestion.lower() for issue in security_issues)
    
    def test_detect_insecure_random(self):
        """Test detection of insecure random module usage."""
        code = """
import random
token = random.random()
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) > 0
        assert any('random' in issue.message.lower() for issue in security_issues)
        assert any('secrets' in issue.fix_suggestion.lower() for issue in security_issues)
    
    def test_detect_hardcoded_password(self):
        """Test detection of hardcoded passwords."""
        code = """
password = "admin123"
api_key = "sk-1234567890"
"""
        security_issues, _ = self.analyzer.analyze_code(code)
        assert len(security_issues) >= 2
        assert any('password' in issue.message.lower() for issue in security_issues)
        assert any('api_key' in issue.message.lower() for issue in security_issues)
    
    def test_owasp_asvs_ids(self):
        """Test that OWASP ASVS IDs are included."""
        code = """
result = eval(user_input)
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
    return x + 1
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any('docstring' in issue.message.lower() for issue in quality_issues)
    
    def test_detect_high_complexity(self):
        """Test detection of high cyclomatic complexity."""
        code = """
def complex_function(x):
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
        assert any('complexity' in issue.message.lower() for issue in quality_issues)
    
    def test_detect_too_many_parameters(self):
        """Test detection of too many function parameters."""
        code = """
def many_params(a, b, c, d, e, f, g):
    return a + b + c + d + e + f + g
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any('parameter' in issue.message.lower() for issue in quality_issues)
    
    def test_detect_mutable_default(self):
        """Test detection of mutable default arguments."""
        code = """
def bad_default(items=[]):
    items.append(1)
    return items
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any('mutable default' in issue.message.lower() for issue in quality_issues)
    
    def test_detect_none_comparison(self):
        """Test detection of incorrect None comparison."""
        code = """
if x == None:
    pass
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any('is None' in issue.fix_suggestion for issue in quality_issues)
    
    def test_detect_bool_comparison(self):
        """Test detection of explicit bool comparison."""
        code = """
if condition == True:
    pass
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any('True' in issue.message or 'False' in issue.message for issue in quality_issues)
    
    def test_detect_bare_except(self):
        """Test detection of bare except clauses."""
        code = """
try:
    risky_operation()
except:
    pass
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        assert len(quality_issues) > 0
        assert any('bare except' in issue.message.lower() for issue in quality_issues)
    
    def test_complexity_report(self):
        """Test complexity report generation."""
        code = """
def simple_func(x):
    return x + 1

def complex_func(x):
    if x > 0:
        if x > 10:
            return "high"
        return "low"
    return "negative"
"""
        complexity = self.analyzer.get_complexity_report(code)
        assert 'simple_func' in complexity
        assert 'complex_func' in complexity
        assert complexity['simple_func'] < complexity['complex_func']
    
    def test_ignore_private_function_docstring(self):
        """Test that private functions don't require docstrings."""
        code = """
def _private_function(x):
    return x + 1
"""
        _, quality_issues = self.analyzer.analyze_code(code)
        # Should not complain about missing docstring for private functions
        docstring_issues = [i for i in quality_issues if 'docstring' in i.message.lower()]
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

password = "admin123"

def bad_function(x, y, z, a, b, c, d):
    if x == None:
        token = random.random()
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
            cwe_id="CWE-95"
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
            fix_suggestion="Refactor"
        )
        assert issue.severity == "MEDIUM"
        assert issue.line_number == 20
        assert issue.fix_suggestion == "Refactor"
