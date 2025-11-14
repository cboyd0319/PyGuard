"""Tests for enhanced taint analysis with cross-function tracking."""

import ast

from pyguard.lib.taint_analysis import (
    EnhancedTaintAnalyzer,
    TaintPath,
    TaintSink,
    TaintSource,
    analyze_taint_flows,
)


class TestEnhancedTaintAnalyzer:
    """Test enhanced taint analysis capabilities."""

    def test_detect_sql_injection_from_flask_request(self):
        """Test detection of SQL injection from Flask request data."""
        code = """
import flask
from flask import request

app = flask.Flask(__name__)

@app.route('/search')
def search():
    # TODO: Add docstring
    query = request.args.get('q')
    cursor.execute("SELECT * FROM users WHERE name = '" + query + "'")  # SQL INJECTION RISK: Use parameterized queries
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect SQL injection
        sql_issues = [i for i in analyzer.issues if i.category == "SQL Injection"]
        assert len(sql_issues) >= 1
        assert sql_issues[0].severity == "CRITICAL"
        assert "request.args" in sql_issues[0].message or "query" in sql_issues[0].message

    def test_detect_command_injection_from_user_input(self):
        """Test detection of OS command injection from user input."""
        code = """
import os

user_file = input("Enter filename: ")
os.system("cat " + user_file)  # SECURITY: Use subprocess.run() instead
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect command injection
        cmd_issues = [i for i in analyzer.issues if i.category == "OS Command Injection"]
        assert len(cmd_issues) >= 1
        assert cmd_issues[0].severity == "CRITICAL"
        assert "CWE-78" in cmd_issues[0].cwe_id

    def test_detect_xss_from_django_request(self):
        """Test detection of XSS from Django request data."""
        code = """
from django.http import HttpResponse
from django.utils.safestring import mark_safe

def view(request):
    # TODO: Add docstring
    user_input = request.GET.get('name')
    html = mark_safe(user_input)
    return HttpResponse(html)
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect XSS vulnerability
        xss_issues = [i for i in analyzer.issues if "XSS" in i.category or "Cross-Site" in i.category]
        assert len(xss_issues) >= 1
        assert xss_issues[0].severity in ["HIGH", "CRITICAL"]

    def test_detect_path_traversal(self):
        """Test detection of path traversal vulnerability."""
        code = """
user_path = input("Enter file path: ")
with open("/var/data/" + user_path, 'r') as f:
    content = f.read()
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect path traversal
        path_issues = [i for i in analyzer.issues if "Path Traversal" in i.category]
        assert len(path_issues) >= 1
        assert "CWE-22" in path_issues[0].cwe_id

    def test_taint_propagation_through_assignment(self):
        """Test that taint propagates through variable assignments."""
        code = """
user_input = input("Enter value: ")
temp = user_input
final = temp
eval(final)  # DANGEROUS: Avoid eval with untrusted input
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect taint flow through multiple assignments
        eval_issues = [i for i in analyzer.issues if "Code Injection" in i.category]
        assert len(eval_issues) >= 1

    def test_taint_propagation_through_string_concat(self):
        """Test that taint propagates through string concatenation."""
        code = """
import os

user_cmd = input("Enter command: ")
full_cmd = "ls " + user_cmd
os.system(full_cmd)  # SECURITY: Use subprocess.run() instead
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect taint through concatenation
        cmd_issues = [i for i in analyzer.issues if i.category == "OS Command Injection"]
        assert len(cmd_issues) >= 1

    def test_no_false_positive_on_safe_code(self):
        """Test that safe code doesn't trigger taint issues."""
        code = """
safe_value = "constant"
result = len(safe_value)
print(result)
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should not detect any taint issues
        assert len(analyzer.issues) == 0

    def test_fastapi_request_taint_detection(self):
        """Test detection of taint from FastAPI Request objects."""
        code = """
from fastapi import Request
import subprocess

async def endpoint(request: Request):
    user_data = await request.json()
    cmd = user_data.get('command')
    subprocess.run(cmd, shell=True)
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect command injection from FastAPI request
        cmd_issues = [i for i in analyzer.issues if i.category == "OS Command Injection"]
        assert len(cmd_issues) >= 1

    def test_function_parameter_taint_detection(self):
        """Test that function parameters with suggestive names are marked as tainted."""
        code = """
def process_user_input(user_data):
    # TODO: Add docstring
    eval(user_data)  # DANGEROUS: Avoid eval with untrusted input
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect taint from suspicious parameter name
        eval_issues = [i for i in analyzer.issues if "Code Injection" in i.category]
        assert len(eval_issues) >= 1

    def test_database_cursor_taint_source(self):
        """Test that database results are tracked as taint sources."""
        code = """
cursor = db.cursor()
cursor.execute("SELECT * FROM config")
config_value = cursor.fetchone()
eval(config_value)  # DANGEROUS: Avoid eval with untrusted input
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect taint from database
        eval_issues = [i for i in analyzer.issues if "Code Injection" in i.category]
        assert len(eval_issues) >= 1

    def test_multiple_taint_sources(self):
        """Test detection of multiple taint sources in same code."""
        code = """
import os
from flask import request

user1 = input("User 1: ")
user2 = request.args.get('user2')

os.system(user1)  # SECURITY: Use subprocess.run() instead
cursor.execute("SELECT * FROM users WHERE name = '" + user2 + "'")  # SQL INJECTION RISK: Use parameterized queries
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect both command injection and SQL injection
        cmd_issues = [i for i in analyzer.issues if i.category == "OS Command Injection"]
        sql_issues = [i for i in analyzer.issues if i.category == "SQL Injection"]
        assert len(cmd_issues) >= 1
        assert len(sql_issues) >= 1

    def test_taint_path_tracking(self):
        """Test that complete taint paths are tracked."""
        code = """
user_input = input("Enter: ")
result = eval(user_input)  # DANGEROUS: Avoid eval with untrusted input
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should track taint path
        assert len(analyzer.taint_paths) >= 1
        path = analyzer.taint_paths[0]
        assert path.source.type == "user_input"
        assert path.sink.type in ["eval", "sql", "command"]

    def test_environment_variable_taint(self):
        """Test detection of taint from environment variables."""
        code = """
import os

env_value = os.getenv('USER_CMD')
os.system(env_value)  # SECURITY: Use subprocess.run() instead
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect command injection from environment
        cmd_issues = [i for i in analyzer.issues if i.category == "OS Command Injection"]
        assert len(cmd_issues) >= 1

    def test_flask_request_headers_taint(self):
        """Test detection of taint from Flask request headers."""
        code = """
from flask import request

auth_header = request.headers.get('Authorization')
cursor.execute("SELECT * FROM users WHERE token = '" + auth_header + "'")  # SQL INJECTION RISK: Use parameterized queries
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect SQL injection from headers
        sql_issues = [i for i in analyzer.issues if i.category == "SQL Injection"]
        assert len(sql_issues) >= 1

    def test_socket_receive_taint(self):
        """Test detection of taint from network socket data."""
        code = """
import socket

sock = socket.socket()
data = sock.recv(1024)
eval(data)  # DANGEROUS: Avoid eval with untrusted input
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        # Should detect code injection from network
        eval_issues = [i for i in analyzer.issues if "Code Injection" in i.category]
        assert len(eval_issues) >= 1


class TestTaintAnalysisHelpers:
    """Test helper functions for taint analysis."""

    def test_analyze_taint_flows_with_issues(self, tmp_path):
        """Test analyze_taint_flows function detects issues."""
        # Create test file
        test_file = tmp_path / "test_taint.py"
        test_file.write_text("""
user_input = input("Enter: ")
eval(user_input)  # DANGEROUS: Avoid eval with untrusted input
""")

        issues = analyze_taint_flows(test_file)

        # Should detect at least one issue
        assert len(issues) >= 1
        assert any("Code Injection" in issue.category for issue in issues)

    def test_analyze_taint_flows_with_safe_code(self, tmp_path):
        """Test analyze_taint_flows with safe code."""
        # Create test file
        test_file = tmp_path / "safe_code.py"
        test_file.write_text("""
value = "constant"
print(value)
""")

        issues = analyze_taint_flows(test_file)

        # Should not detect any issues
        assert len(issues) == 0

    def test_analyze_taint_flows_with_syntax_error(self, tmp_path):
        """Test analyze_taint_flows handles syntax errors gracefully."""
        # Create test file with syntax error
        test_file = tmp_path / "syntax_error.py"
        test_file.write_text("""
def broken(
    # TODO: Add docstring
    # Missing closing parenthesis
""")

        issues = analyze_taint_flows(test_file)

        # Should return empty list on syntax error
        assert issues == []


class TestTaintPathConstruction:
    """Test taint path data structures."""

    def test_taint_source_creation(self):
        """Test TaintSource dataclass creation."""
        source = TaintSource(
            name="user_input",
            type="user_input",
            line_number=1,
            severity="HIGH",
        )

        assert source.name == "user_input"
        assert source.type == "user_input"
        assert source.line_number == 1
        assert source.severity == "HIGH"

    def test_taint_sink_creation(self):
        """Test TaintSink dataclass creation."""
        sink = TaintSink(
            name="eval",
            type="eval",
            line_number=5,
            severity="CRITICAL",
        )

        assert sink.name == "eval"
        assert sink.type == "eval"
        assert sink.line_number == 5
        assert sink.severity == "CRITICAL"

    def test_taint_path_creation(self):
        """Test TaintPath dataclass creation."""
        source = TaintSource("user_input", "user_input", 1, "HIGH")
        sink = TaintSink("eval", "eval", 5, "CRITICAL")

        path = TaintPath(
            source=source,
            sink=sink,
            variables=["user_input", "temp"],
            functions=["main", "process"],
            line_numbers=[1, 3, 5],
        )

        assert path.source == source
        assert path.sink == sink
        assert len(path.variables) == 2
        assert len(path.functions) == 2
        assert len(path.line_numbers) == 3


class TestFrameworkSpecificTaintDetection:
    """Test framework-specific taint detection."""

    def test_django_request_get_taint(self):
        """Test Django request.GET taint detection."""
        code = """
from django.http import HttpResponse

def view(request):
    # TODO: Add docstring
    query = request.GET['search']
    cursor.execute("SELECT * FROM items WHERE name = " + query)  # SQL INJECTION RISK: Use parameterized queries
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        sql_issues = [i for i in analyzer.issues if i.category == "SQL Injection"]
        assert len(sql_issues) >= 1

    def test_django_request_post_taint(self):
        """Test Django request.POST taint detection."""
        code = """
def view(request):
    # TODO: Add docstring
    name = request.POST.get('name')
    db.execute("INSERT INTO users VALUES ('" + name + "')")  # SQL INJECTION RISK: Use parameterized queries
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        sql_issues = [i for i in analyzer.issues if i.category == "SQL Injection"]
        assert len(sql_issues) >= 1

    def test_flask_request_json_taint(self):
        """Test Flask request.json taint detection."""
        code = """
from flask import request

@app.route('/api')
def api():
    # TODO: Add docstring
    data = request.json
    name = data['name']
    session.execute("UPDATE users SET name = '" + name + "'")  # SQL INJECTION RISK: Use parameterized queries
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        sql_issues = [i for i in analyzer.issues if i.category == "SQL Injection"]
        assert len(sql_issues) >= 1

    def test_fastapi_query_params_taint(self):
        """Test FastAPI query_params taint detection."""
        code = """
from fastapi import Request

async def endpoint(request: Request):
    search = request.query_params.get('q')
    engine.execute("SELECT * FROM products WHERE name = '" + search + "'")  # SQL INJECTION RISK: Use parameterized queries
"""
        source_lines = code.strip().split("\n")
        analyzer = EnhancedTaintAnalyzer(source_lines)

        tree = ast.parse(code)
        analyzer.visit(tree)

        sql_issues = [i for i in analyzer.issues if i.category == "SQL Injection"]
        assert len(sql_issues) >= 1
