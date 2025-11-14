"""
Unit tests for Gradio security analysis.

Tests cover:
- Authentication and access control
- File upload security
- Launch configuration security
- SQL injection detection
- Path traversal detection
- Server binding security
"""

import ast
from pathlib import Path

from pyguard.lib.framework_gradio import (
    GradioSecurityVisitor,
    analyze_gradio_security,
    fix_gradio_security,
)
from pyguard.lib.rule_engine import RuleSeverity


class TestGradioAuthenticationSecurity:
    """Test detection of authentication and access control issues."""

    def test_detect_public_share_without_auth(self):
        """Test detection of public sharing without authentication."""
        code = """
import gradio as gr

# BAD: Sharing publicly without authentication
demo = gr.Interface(fn=process, inputs="text", outputs="text")
demo.launch(share=True)
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        auth_violations = [v for v in violations if v.rule_id == "GRADIO001"]
        assert len(auth_violations) == 1
        assert auth_violations[0].severity == RuleSeverity.HIGH

    def test_safe_public_share_with_auth(self):
        """Test that public sharing with auth doesn't trigger violations."""
        code = """
import gradio as gr

# GOOD: Sharing with authentication
demo = gr.Interface(fn=process, inputs="text", outputs="text")
demo.launch(share=True, auth=("admin", "password"))
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        auth_violations = [v for v in violations if v.rule_id == "GRADIO001"]
        assert len(auth_violations) == 0

    def test_local_launch_without_auth(self):
        """Test that local launch without sharing doesn't trigger auth warning."""
        code = """
import gradio as gr

# GOOD: Local only, no sharing
demo = gr.Interface(fn=process, inputs="text", outputs="text")
demo.launch()
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        auth_violations = [v for v in violations if v.rule_id == "GRADIO001"]
        assert len(auth_violations) == 0


class TestGradioServerBindingSecurity:
    """Test detection of insecure server binding configurations."""

    def test_detect_insecure_server_binding(self):
        """Test detection of binding to 0.0.0.0."""
        code = """
import gradio as gr

# BAD: Binding to all interfaces
demo = gr.Interface(fn=process, inputs="text", outputs="text")
demo.launch(server_name="0.0.0.0")
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        binding_violations = [v for v in violations if v.rule_id == "GRADIO002"]
        assert len(binding_violations) == 1
        assert binding_violations[0].severity == RuleSeverity.MEDIUM

    def test_safe_server_binding(self):
        """Test that localhost binding doesn't trigger violations."""
        code = """
import gradio as gr

# GOOD: Binding to localhost only
demo = gr.Interface(fn=process, inputs="text", outputs="text")
demo.launch(server_name="127.0.0.1")
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        binding_violations = [v for v in violations if v.rule_id == "GRADIO002"]
        assert len(binding_violations) == 0

    def test_fix_insecure_server_binding(self):
        """Test auto-fix for insecure server binding."""
        code = """demo.launch(server_name="0.0.0.0")"""

        from pyguard.lib.rule_engine import FixApplicability, RuleCategory, RuleViolation

        violation = RuleViolation(
            rule_id="GRADIO002",
            message="Insecure server binding",
            line_number=1,
            column=0,
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.SECURITY,
            file_path=Path("test.py"),
            fix_applicability=FixApplicability.SAFE,
            fix_data={"suggested_value": "127.0.0.1"},
        )

        fixed_code, success = fix_gradio_security(code, violation)
        assert success
        assert "127.0.0.1" in fixed_code
        assert "0.0.0.0" not in fixed_code


class TestGradioFileUploadSecurity:
    """Test detection of insecure file upload handling."""

    def test_detect_file_upload_without_types(self):
        """Test detection of file upload without type restrictions."""
        code = """
import gradio as gr

# BAD: No file type restrictions
upload = gr.File()
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        upload_violations = [v for v in violations if v.rule_id == "GRADIO003"]
        assert len(upload_violations) == 1
        assert upload_violations[0].severity == RuleSeverity.HIGH

    def test_safe_file_upload_with_types(self):
        """Test that file upload with types doesn't trigger violations."""
        code = """
import gradio as gr

# GOOD: File type restrictions specified
upload = gr.File(file_types=['.csv', '.txt'])
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        upload_violations = [v for v in violations if v.rule_id == "GRADIO003"]
        assert len(upload_violations) == 0

    def test_fix_file_upload_security(self):
        """Test auto-fix for file upload without type restrictions."""
        code = """upload = gr.File()"""

        from pyguard.lib.rule_engine import FixApplicability, RuleCategory, RuleViolation

        violation = RuleViolation(
            rule_id="GRADIO003",
            message="File upload needs type restrictions",
            line_number=1,
            column=0,
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECURITY,
            file_path=Path("test.py"),
            fix_applicability=FixApplicability.SAFE,
            fix_data={"add_parameter": "file_types=['.txt', '.csv']"},
        )

        fixed_code, success = fix_gradio_security(code, violation)
        assert success
        assert "file_types=" in fixed_code


class TestGradioSQLInjection:
    """Test detection of SQL injection vulnerabilities."""

    def test_detect_sql_injection_fstring(self):
        """Test detection of SQL injection via f-string."""
        code = """
import gradio as gr
import sqlite3

def query_user(username):
    # TODO: Add docstring
    conn = sqlite3.connect("db.sqlite")
    # BAD: f-string in SQL query
    result = conn.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return result

demo = gr.Interface(fn=query_user, inputs="text", outputs="text")
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "GRADIO004"]
        assert len(sql_violations) == 1
        assert sql_violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_sql_injection_string_concat(self):
        """Test detection of SQL injection via string concatenation."""
        code = """
import gradio as gr

def query_data(user_id):
    # TODO: Add docstring
    # BAD: String concatenation in SQL query
    query = "SELECT * FROM data WHERE id = " + user_id
    conn.execute(query)
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "GRADIO005"]
        assert len(sql_violations) == 1

    def test_safe_parameterized_query(self):
        """Test that parameterized queries don't trigger violations."""
        code = """
import gradio as gr
import sqlite3

def query_user(username):
    # TODO: Add docstring
    conn = sqlite3.connect("db.sqlite")
    # GOOD: Parameterized query
    result = conn.execute("SELECT * FROM users WHERE name = ?", (username,))
    return result

demo = gr.Interface(fn=query_user, inputs="text", outputs="text")
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id in ["GRADIO004", "GRADIO005"]]
        assert len(sql_violations) == 0


class TestGradioPathTraversal:
    """Test detection of path traversal vulnerabilities."""

    def test_detect_path_traversal_in_file_open(self):
        """Test detection of path traversal via unsanitized file paths."""
        code = """
import gradio as gr

def read_file(filename):
    # TODO: Add docstring
    # BAD: Unsanitized user input in file path
    with open(f"/data/{filename}") as f:
        return f.read()

demo = gr.Interface(fn=read_file, inputs="text", outputs="text")
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        path_violations = [v for v in violations if v.rule_id == "GRADIO006"]
        assert len(path_violations) == 1
        assert path_violations[0].severity == RuleSeverity.HIGH

    def test_safe_file_operations(self):
        """Test that safe file operations don't trigger violations."""
        code = """
import gradio as gr
from pathlib import Path

def read_file(filename):
    # TODO: Add docstring
    # GOOD: Using constant path
    with open("/data/file.txt") as f:
        return f.read()

demo = gr.Interface(fn=read_file, inputs="text", outputs="text")
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        path_violations = [v for v in violations if v.rule_id == "GRADIO006"]
        assert len(path_violations) == 0


class TestGradioImportDetection:
    """Test Gradio import detection."""

    def test_detect_gradio_import(self):
        """Test detection of gradio import."""
        code = """
import gradio as gr

demo = gr.Interface(fn=process, inputs="text", outputs="text")
"""
        tree = ast.parse(code)
        visitor = GradioSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_gradio_import is True

    def test_detect_gradio_from_import(self):
        """Test detection of from gradio import."""
        code = """
from gradio import Interface

demo = Interface(fn=process, inputs="text", outputs="text")
"""
        tree = ast.parse(code)
        visitor = GradioSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_gradio_import is True

    def test_no_violations_without_gradio_import(self):
        """Test that violations are not reported without Gradio import."""
        code = """
# Regular Python code without Gradio
def launch(share=True):
    # TODO: Add docstring
    print("Launching app")

launch()
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        # Should return empty list since Gradio is not imported
        assert len(violations) == 0


class TestGradioEdgeCases:
    """Test edge cases and error handling."""

    def test_handle_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
import gradio as gr

# Syntax error
demo.launch(
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        # Should return empty list, not raise exception
        assert violations == []

    def test_empty_file(self):
        """Test analysis of empty file."""
        code = ""
        violations = analyze_gradio_security(Path("test.py"), code)
        assert violations == []

    def test_file_with_only_comments(self):
        """Test analysis of file with only comments."""
        code = """
# This is a comment
# Another comment
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        assert violations == []


class TestGradioMultipleViolations:
    """Test detection of multiple violations in one file."""

    def test_multiple_violation_types(self):
        """Test detection of multiple different violation types."""
        code = """
import gradio as gr
import sqlite3

def process(user_input, filename):
    # TODO: Add docstring
    # Multiple issues:
    # SQL injection
    conn = sqlite3.connect("db.sqlite")
    result = conn.execute(f"SELECT * FROM data WHERE id = {user_input}")
    
    # Path traversal
    with open(f"/data/{filename}") as f:
        data = f.read()
    
    return data

# No auth on public share
demo = gr.Interface(fn=process, inputs=["text", gr.File()], outputs="text")
demo.launch(share=True, server_name="0.0.0.0")
"""
        violations = analyze_gradio_security(Path("test.py"), code)

        # Should have multiple violations
        assert len(violations) >= 4

        rule_ids = [v.rule_id for v in violations]
        assert "GRADIO001" in rule_ids  # No auth
        assert "GRADIO002" in rule_ids  # Insecure binding
        assert "GRADIO003" in rule_ids  # File upload no types
        assert "GRADIO004" in rule_ids  # SQL injection
        assert "GRADIO006" in rule_ids  # Path traversal


class TestGradioRealWorldScenarios:
    """Test real-world Gradio application scenarios."""

    def test_ml_model_inference_app(self):
        """Test a typical ML model inference application."""
        code = """
import gradio as gr
import torch

def predict(image):
    # TODO: Add docstring
    # Safe ML inference
    model = torch.load("model.pth")
    result = model(image)
    return result

demo = gr.Interface(
    fn=predict,
    inputs=gr.Image(type="pil"),
    outputs="text"
)
demo.launch()
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        # Should have no violations - all safe operations
        assert len(violations) == 0

    def test_chatbot_app_with_database(self):
        """Test a chatbot application with database."""
        code = """
import gradio as gr
import sqlite3

def chatbot(message, history):
    # TODO: Add docstring
    # GOOD: Parameterized query
    conn = sqlite3.connect("chat.db")
    conn.execute("INSERT INTO messages (text) VALUES (?)", (message,))
    
    response = generate_response(message)
    return response

demo = gr.ChatInterface(fn=chatbot)
demo.launch()
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        # Should have no SQL injection violations
        sql_violations = [v for v in violations if v.rule_id in ["GRADIO004", "GRADIO005"]]
        assert len(sql_violations) == 0

    def test_file_processing_app_with_issues(self):
        """Test a file processing app with security issues."""
        code = """
import gradio as gr

def process_file(file):
    # TODO: Add docstring
    # BAD: Path traversal risk
    with open(f"/uploads/{file.name}") as f:
        content = f.read()
    return content

# BAD: No file type restrictions
demo = gr.Interface(fn=process_file, inputs=gr.File(), outputs="text")
# BAD: Public sharing without auth
demo.launch(share=True)
"""
        violations = analyze_gradio_security(Path("test.py"), code)
        # Should detect multiple issues
        assert len(violations) >= 3

        rule_ids = [v.rule_id for v in violations]
        assert "GRADIO001" in rule_ids  # No auth
        assert "GRADIO003" in rule_ids  # No file types
        assert "GRADIO006" in rule_ids  # Path traversal
