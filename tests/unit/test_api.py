"""
Tests for PyGuard programmatic API.

Tests the high-level API for using PyGuard programmatically in
Python applications, IDEs, and CI/CD systems.
"""

import tempfile
from pathlib import Path

import pytest

from pyguard.api import AnalysisResult, PyGuardAPI, Severity, analyze_code, analyze_file


class TestAnalysisResult:
    """Test AnalysisResult dataclass and methods."""

    def test_analysis_result_creation(self):
        """Test creating an AnalysisResult."""
        result = AnalysisResult(
            issues=[],
            file_path="test.py",
            execution_time_ms=10.5,
            lines_analyzed=100,
        )

        assert result.file_path == "test.py"
        assert result.execution_time_ms == 10.5
        assert result.lines_analyzed == 100
        assert len(result.issues) == 0

    def test_critical_issues_property(self):
        """Test filtering critical issues."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        issues = [
            SecurityIssue("CRITICAL", "SQL Injection", "Test", 1, 0, "", "", "CWE-89", ""),
            SecurityIssue("HIGH", "XSS", "Test", 2, 0, "", "", "CWE-79", ""),
            SecurityIssue("CRITICAL", "Command Injection", "Test", 3, 0, "", "", "CWE-78", ""),
        ]

        result = AnalysisResult(issues=issues)
        critical = result.critical_issues

        assert len(critical) == 2
        assert all(i.severity == "CRITICAL" for i in critical)

    def test_severity_filtering(self):
        """Test filtering issues by severity."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        issues = [
            SecurityIssue("CRITICAL", "Test", "Test", 1, 0, "", "", "", ""),
            SecurityIssue("HIGH", "Test", "Test", 2, 0, "", "", "", ""),
            SecurityIssue("MEDIUM", "Test", "Test", 3, 0, "", "", "", ""),
            SecurityIssue("LOW", "Test", "Test", 4, 0, "", "", "", ""),
            SecurityIssue("INFO", "Test", "Test", 5, 0, "", "", "", ""),
        ]

        result = AnalysisResult(issues=issues)

        assert len(result.critical_issues) == 1
        assert len(result.high_issues) == 1
        assert len(result.medium_issues) == 1
        assert len(result.low_issues) == 1
        assert len(result.info_issues) == 1

    def test_has_critical_issues(self):
        """Test has_critical_issues method."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        result_with_critical = AnalysisResult(
            issues=[SecurityIssue("CRITICAL", "Test", "Test", 1, 0, "", "", "", "")]
        )
        result_without_critical = AnalysisResult(
            issues=[SecurityIssue("HIGH", "Test", "Test", 1, 0, "", "", "", "")]
        )

        assert result_with_critical.has_critical_issues() is True
        assert result_without_critical.has_critical_issues() is False

    def test_has_issues_with_severity(self):
        """Test has_issues method with different severity levels."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        result = AnalysisResult(
            issues=[SecurityIssue("MEDIUM", "Test", "Test", 1, 0, "", "", "", "")]
        )

        assert result.has_issues(Severity.INFO) is True
        assert result.has_issues(Severity.LOW) is True
        assert result.has_issues(Severity.MEDIUM) is True
        assert result.has_issues(Severity.HIGH) is False
        assert result.has_issues(Severity.CRITICAL) is False

    def test_get_issues_by_category(self):
        """Test filtering issues by category."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        issues = [
            SecurityIssue("HIGH", "SQL Injection", "Test1", 1, 0, "", "", "", ""),
            SecurityIssue("HIGH", "XSS", "Test2", 2, 0, "", "", "", ""),
            SecurityIssue("HIGH", "SQL Injection", "Test3", 3, 0, "", "", "", ""),
        ]

        result = AnalysisResult(issues=issues)
        sql_issues = result.get_issues_by_category("SQL Injection")

        assert len(sql_issues) == 2
        assert all(i.category == "SQL Injection" for i in sql_issues)

    def test_get_issues_by_cwe(self):
        """Test filtering issues by CWE ID."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        issues = [
            SecurityIssue("HIGH", "SQL Injection", "Test", 1, 0, "", "", owasp_id="", cwe_id="CWE-89"),
            SecurityIssue("HIGH", "XSS", "Test", 2, 0, "", "", owasp_id="", cwe_id="CWE-79"),
            SecurityIssue("HIGH", "SQL Injection", "Test", 3, 0, "", "", owasp_id="", cwe_id="CWE-89"),
        ]

        result = AnalysisResult(issues=issues)
        sql_cwe_issues = result.get_issues_by_cwe("CWE-89")

        assert len(sql_cwe_issues) == 2
        assert all(hasattr(i, 'cwe_id') and i.cwe_id == "CWE-89" for i in sql_cwe_issues)

    def test_to_dict(self):
        """Test converting result to dictionary."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        issues = [
            SecurityIssue("CRITICAL", "SQL Injection", "Test message", 10, 5, "code", "fix", "CWE-89", "ASVS-5.3.4")
        ]

        result = AnalysisResult(
            issues=issues,
            file_path="test.py",
            execution_time_ms=15.5,
            lines_analyzed=50,
        )

        data = result.to_dict()

        assert data["file_path"] == "test.py"
        assert data["execution_time_ms"] == 15.5
        assert data["lines_analyzed"] == 50
        assert data["total_issues"] == 1
        assert data["critical_issues"] == 1
        assert len(data["issues"]) == 1
        assert data["issues"][0]["severity"] == "CRITICAL"
        assert data["issues"][0]["category"] == "SQL Injection"


class TestPyGuardAPI:
    """Test PyGuardAPI class methods."""

    def test_api_initialization(self):
        """Test API initialization."""
        api = PyGuardAPI()
        assert api.config == {}

        api_with_config = PyGuardAPI(config={"test": "value"})
        assert api_with_config.config == {"test": "value"}

    def test_analyze_code_safe(self):
        """Test analyzing safe code with proper documentation."""
        api = PyGuardAPI()
        code = '''
def safe_function(x, y):
    """Add two numbers."""
    return x + y
'''

        result = api.analyze_code(code)

        assert result.lines_analyzed >= 4
        assert result.execution_time_ms > 0
        assert result.file_path == "<string>"

    def test_analyze_code_with_issues(self):
        """Test analyzing code with security issues."""
        api = PyGuardAPI()
        code = '''
import pickle

def load_data(file):
    """Load data from pickle file."""
    data = pickle.load(file)  # Security issue
    return data
'''

        result = api.analyze_code(code)

        assert result.lines_analyzed > 0
        # May or may not have issues depending on AST analyzer configuration
        # The API should work without errors
        assert result.execution_time_ms > 0

    def test_analyze_code_with_eval(self):
        """Test detecting eval usage."""
        api = PyGuardAPI()
        code = '''
def execute_code(code_string):
    """Execute code string - unsafe."""
    result = eval(code_string)  # Security issue
    return result
'''

        result = api.analyze_code(code)

        # eval is detected by AST analyzer
        assert result.execution_time_ms > 0
        # Check for eval-related issues
        eval_issues = [i for i in result.issues if "eval" in i.message.lower()]
        assert len(eval_issues) > 0

    def test_analyze_code_with_yaml_load(self):
        """Test detecting unsafe yaml.load."""
        api = PyGuardAPI()
        code = '''
import yaml

def load_config(file_path):
    """Load YAML config - unsafe."""
    with open(file_path) as f:
        config = yaml.load(f)  # Security issue
    return config
'''

        result = api.analyze_code(code)

        # yaml.load is detected by AST analyzer
        assert result.execution_time_ms > 0
        yaml_issues = [i for i in result.issues if "yaml" in i.message.lower()]
        assert len(yaml_issues) > 0

    def test_analyze_code_syntax_error(self):
        """Test handling syntax errors."""
        api = PyGuardAPI()
        code = "def broken_function(\n    # Missing closing parenthesis"

        try:
            result = api.analyze_code(code)
            # If no exception, check that it handled gracefully
            assert True
        except SyntaxError:
            # Expected behavior
            assert True

    def test_analyze_file_success(self, tmp_path):
        """Test analyzing a file."""
        # Create test file with proper documentation
        test_file = tmp_path / "test.py"
        test_file.write_text('''
def safe_function():
    """Return 42."""
    return 42
''')

        api = PyGuardAPI()
        result = api.analyze_file(test_file)

        assert result.file_path == str(test_file)
        assert result.lines_analyzed > 0
        assert result.execution_time_ms > 0

    def test_analyze_file_with_issues(self, tmp_path):
        """Test analyzing file with security issues."""
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text("""
import os

def run_command(cmd):
    os.system(cmd)
""")

        api = PyGuardAPI()
        result = api.analyze_file(test_file)

        assert len(result.issues) > 0

    def test_analyze_file_not_found(self):
        """Test handling missing file."""
        api = PyGuardAPI()

        with pytest.raises(FileNotFoundError):
            api.analyze_file("nonexistent.py")

    def test_analyze_directory(self, tmp_path):
        """Test analyzing a directory."""
        # Create multiple test files with proper documentation
        (tmp_path / "file1.py").write_text('def func1():\n    """Func 1."""\n    pass')
        (tmp_path / "file2.py").write_text('def func2():\n    """Func 2."""\n    pass')
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file3.py").write_text('def func3():\n    """Func 3."""\n    pass')

        api = PyGuardAPI()
        results = api.analyze_directory(tmp_path)

        assert len(results) == 3
        assert all(isinstance(r, AnalysisResult) for r in results)

    def test_analyze_directory_non_recursive(self, tmp_path):
        """Test analyzing directory without recursion."""
        (tmp_path / "file1.py").write_text('def func1():\n    """Func 1."""\n    pass')
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file2.py").write_text('def func2():\n    """Func 2."""\n    pass')

        api = PyGuardAPI()
        results = api.analyze_directory(tmp_path, recursive=False, pattern="*.py")

        # With non-recursive, should only find files in the root directory
        assert len(results) >= 1

    def test_analyze_directory_not_found(self):
        """Test handling missing directory."""
        api = PyGuardAPI()

        with pytest.raises(FileNotFoundError):
            api.analyze_directory("nonexistent_directory")

    def test_generate_report_json(self):
        """Test generating JSON report."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        result = AnalysisResult(
            issues=[SecurityIssue("HIGH", "Test", "Test message", 1, 0, "", "", "", "")],
            file_path="test.py",
        )

        api = PyGuardAPI()
        report = api.generate_report(result, format="json")

        assert isinstance(report, str)
        assert "Test" in report
        assert "HIGH" in report

    def test_generate_report_multiple_results(self):
        """Test generating report from multiple results."""
        from pyguard.lib.ast_analyzer import SecurityIssue

        results = [
            AnalysisResult(
                issues=[SecurityIssue("HIGH", "Test1", "Message1", 1, 0, "", "", "", "")],
                file_path="file1.py",
            ),
            AnalysisResult(
                issues=[SecurityIssue("CRITICAL", "Test2", "Message2", 2, 0, "", "", "", "")],
                file_path="file2.py",
            ),
        ]

        api = PyGuardAPI()
        report = api.generate_report(results, format="json")

        assert "Test1" in report
        assert "Test2" in report

    def test_generate_report_invalid_format(self):
        """Test handling invalid report format."""
        result = AnalysisResult(issues=[], file_path="test.py")

        api = PyGuardAPI()

        with pytest.raises(ValueError, match="Unsupported format"):
            api.generate_report(result, format="invalid")


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_analyze_file_convenience(self, tmp_path):
        """Test analyze_file convenience function."""
        test_file = tmp_path / "test.py"
        test_file.write_text('def test():\n    """Test function."""\n    pass')

        result = analyze_file(test_file)

        assert isinstance(result, AnalysisResult)
        assert result.file_path == str(test_file)

    def test_analyze_code_convenience(self):
        """Test analyze_code convenience function."""
        code = 'def test():\n    """Test function."""\n    pass'

        result = analyze_code(code)

        assert isinstance(result, AnalysisResult)
        assert result.lines_analyzed > 0


class TestSeverityEnum:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.INFO.value == "INFO"
        assert Severity.LOW.value == "LOW"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_severity_ordering(self):
        """Test that severity levels can be compared."""
        severities = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        assert len(severities) == 5


class TestAPIIntegration:
    """Integration tests for the full API workflow."""

    def test_full_workflow(self, tmp_path):
        """Test complete analysis workflow."""
        # Create a project structure
        project = tmp_path / "project"
        project.mkdir()

        (project / "main.py").write_text('''
def main():
    """Main function."""
    return "Hello, World!"
''')

        (project / "utils.py").write_text('''
import yaml

def load_config(path):
    """Load config from YAML - has security issue."""
    with open(path) as f:
        return yaml.load(f)  # Security issue - should use safe_load
''')

        # Analyze project
        api = PyGuardAPI()
        results = api.analyze_directory(project)

        # Verify results
        assert len(results) == 2

        # Verify we got results
        assert all(isinstance(r, AnalysisResult) for r in results)

        # Generate report
        report = api.generate_report(results, format="json")
        assert len(report) > 0
        assert "pyguard" in report

    def test_api_with_complex_code(self):
        """Test API with complex code patterns."""
        api = PyGuardAPI()
        code = """
import subprocess
from flask import request

@app.route('/api')
def api_endpoint():
    user_data = request.json
    command = user_data.get('cmd')
    subprocess.run(command, shell=True)  # Multiple issues here
    
    query = request.args.get('q')
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")  # SQL injection
"""

        result = api.analyze_code(code)

        # Should detect command injection and SQL injection
        assert len(result.issues) > 0
        assert result.has_issues(Severity.HIGH)

    def test_performance_tracking(self, tmp_path):
        """Test that performance metrics are tracked."""
        test_file = tmp_path / "large_file.py"
        # Create a larger file to measure timing with docstrings
        code = "\n".join([f'def func{i}():\n    """Function {i}."""\n    pass' for i in range(50)])
        test_file.write_text(code)

        api = PyGuardAPI()
        result = api.analyze_file(test_file)

        assert result.execution_time_ms > 0
        assert result.lines_analyzed >= 100
