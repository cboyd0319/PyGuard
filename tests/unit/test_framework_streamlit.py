"""
Unit tests for Streamlit security analysis.

Tests cover:
- Secrets exposure detection
- XSS vulnerabilities in markdown
- File upload security
- SQL injection detection
- Environment variable exposure
- User input validation
"""

import ast
from pathlib import Path

from pyguard.lib.framework_streamlit import (
    StreamlitSecurityVisitor,
    analyze_streamlit_security,
    fix_streamlit_security,
)
from pyguard.lib.rule_engine import RuleSeverity


class TestStreamlitSecretsExposure:
    """Test detection of secrets exposure in Streamlit apps."""

    def test_detect_secrets_written_to_ui(self):
        """Test detection of st.secrets being written directly to UI."""
        code = """
import streamlit as st

# BAD: Writing secrets directly to UI
st.write(st.secrets)
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        assert len(violations) == 1
        assert violations[0].rule_id == "STREAMLIT001"
        assert violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_secrets_attribute_access(self):
        """Test detection of specific secret values being written."""
        code = """
import streamlit as st

# BAD: Writing secret value directly
st.write(st.secrets.api_key)
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        assert len(violations) == 1
        assert violations[0].rule_id == "STREAMLIT001"

    def test_detect_env_var_exposure(self):
        """Test detection of environment variables being exposed."""
        code = """
import streamlit as st
import os

# BAD: Exposing environment variable
st.write(os.getenv("API_KEY"))
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        assert len(violations) == 1
        assert violations[0].rule_id == "STREAMLIT002"
        assert violations[0].severity == RuleSeverity.HIGH

    def test_safe_secrets_usage(self):
        """Test that proper secrets usage doesn't trigger violations."""
        code = """
import streamlit as st

# GOOD: Using secrets internally without exposing
api_key = st.secrets["api_key"]
response = call_api(api_key)
st.write(response)
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        # Should not have STREAMLIT001 or STREAMLIT002 violations
        assert not any(v.rule_id in ["STREAMLIT001", "STREAMLIT002"] for v in violations)


class TestStreamlitXSSVulnerabilities:
    """Test detection of XSS vulnerabilities in Streamlit."""

    def test_detect_xss_markdown_fstring(self):
        """Test detection of XSS via f-string in markdown with unsafe HTML."""
        code = """
import streamlit as st

user_input = st.text_input("Enter HTML")
# BAD: Using f-string with unsafe_allow_html
st.markdown(f"<div>{user_input}</div>", unsafe_allow_html=True)
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        xss_violations = [v for v in violations if v.rule_id in ["STREAMLIT003", "STREAMLIT004"]]
        assert len(xss_violations) >= 1
        assert any(v.severity == RuleSeverity.CRITICAL for v in xss_violations)

    def test_detect_xss_user_input_variable(self):
        """Test detection of XSS via user input variable."""
        code = """
import streamlit as st

username = st.text_input("Username")
# BAD: Using user input with unsafe_allow_html
st.markdown(username, unsafe_allow_html=True)
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        xss_violations = [v for v in violations if v.rule_id == "STREAMLIT004"]
        assert len(xss_violations) == 1

    def test_safe_markdown_without_unsafe_html(self):
        """Test that safe markdown usage doesn't trigger violations."""
        code = """
import streamlit as st

user_input = st.text_input("Enter text")
# GOOD: No unsafe_allow_html
st.markdown(f"Hello {user_input}")
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        xss_violations = [v for v in violations if v.rule_id in ["STREAMLIT003", "STREAMLIT004"]]
        assert len(xss_violations) == 0


class TestStreamlitFileUploadSecurity:
    """Test detection of insecure file upload handling."""

    def test_detect_file_upload_without_type_filter(self):
        """Test detection of file uploader without type restrictions."""
        code = """
import streamlit as st

# BAD: No type filter
uploaded_file = st.file_uploader("Upload file")
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        upload_violations = [v for v in violations if v.rule_id == "STREAMLIT005"]
        assert len(upload_violations) == 1
        assert upload_violations[0].severity == RuleSeverity.HIGH

    def test_safe_file_upload_with_type_filter(self):
        """Test that file uploader with type filter doesn't trigger violations."""
        code = """
import streamlit as st

# GOOD: Type filter specified
uploaded_file = st.file_uploader("Upload CSV", type=['csv'])
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        upload_violations = [v for v in violations if v.rule_id == "STREAMLIT005"]
        assert len(upload_violations) == 0

    def test_fix_file_upload_security(self):
        """Test auto-fix for file upload without type filter."""
        code = """uploaded_file = st.file_uploader("Upload file")"""

        # Create a mock violation
        from pyguard.lib.rule_engine import FixApplicability, RuleCategory, RuleViolation

        violation = RuleViolation(
            rule_id="STREAMLIT005",
            message="File uploader should specify allowed file types",
            line_number=1,
            column=0,
            severity=RuleSeverity.HIGH,
            category=RuleCategory.SECURITY,
            file_path=Path("test.py"),
            fix_applicability=FixApplicability.SAFE,
            fix_data={"add_parameter": "type=['txt', 'csv']"},
        )

        fixed_code, success = fix_streamlit_security(code, violation)
        assert success
        assert "type=['txt', 'csv']" in fixed_code
        assert "file_uploader(" in fixed_code


class TestStreamlitSQLInjection:
    """Test detection of SQL injection vulnerabilities."""

    def test_detect_sql_injection_fstring(self):
        """Test detection of SQL injection via f-string."""
        code = """
import streamlit as st
import sqlite3

user_id = st.text_input("User ID")
conn = sqlite3.connect("db.sqlite")
# BAD: f-string in SQL query
cursor = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "STREAMLIT006"]
        assert len(sql_violations) == 1
        assert sql_violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_sql_injection_string_concat(self):
        """Test detection of SQL injection via string concatenation."""
        code = """
import streamlit as st

user_id = st.text_input("User ID")
# BAD: String concatenation in SQL query
query = "SELECT * FROM users WHERE id = " + user_id
conn.execute(query)
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "STREAMLIT007"]
        assert len(sql_violations) == 1

    def test_safe_parameterized_query(self):
        """Test that parameterized queries don't trigger violations."""
        code = """
import streamlit as st
import sqlite3

user_id = st.text_input("User ID")
conn = sqlite3.connect("db.sqlite")
# GOOD: Parameterized query
cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id in ["STREAMLIT006", "STREAMLIT007"]]
        assert len(sql_violations) == 0


class TestStreamlitUserInputTracking:
    """Test tracking of user input variables."""

    def test_track_text_input(self):
        """Test that text_input variables are tracked."""
        code = """
import streamlit as st

username = st.text_input("Username")
email = st.text_input("Email")
"""
        tree = ast.parse(code)
        visitor = StreamlitSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert len(visitor.user_inputs) == 2
        assert any(inp["var_name"] == "username" for inp in visitor.user_inputs)
        assert any(inp["var_name"] == "email" for inp in visitor.user_inputs)

    def test_track_various_input_types(self):
        """Test tracking of different input widget types."""
        code = """
import streamlit as st

name = st.text_input("Name")
age = st.number_input("Age")
date = st.date_input("Date")
choice = st.selectbox("Choice", ["A", "B"])
"""
        tree = ast.parse(code)
        visitor = StreamlitSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert len(visitor.user_inputs) == 4
        input_types = [inp["input_type"] for inp in visitor.user_inputs]
        assert "text_input" in input_types
        assert "number_input" in input_types
        assert "date_input" in input_types
        assert "selectbox" in input_types


class TestStreamlitImportDetection:
    """Test Streamlit import detection."""

    def test_detect_streamlit_import(self):
        """Test detection of streamlit import."""
        code = """
import streamlit as st

st.title("My App")
"""
        tree = ast.parse(code)
        visitor = StreamlitSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_streamlit_import is True

    def test_detect_streamlit_from_import(self):
        """Test detection of from streamlit import."""
        code = """
from streamlit import title, write

title("My App")
"""
        tree = ast.parse(code)
        visitor = StreamlitSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_streamlit_import is True

    def test_no_violations_without_streamlit_import(self):
        """Test that violations are not reported without Streamlit import."""
        code = """
# Regular Python code without Streamlit
def write(data):
    # TODO: Add docstring
    print(data)

write(os.getenv("API_KEY"))
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        # Should return empty list since Streamlit is not imported
        assert len(violations) == 0


class TestStreamlitEdgeCases:
    """Test edge cases and error handling."""

    def test_handle_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
import streamlit as st

# Syntax error
st.write(
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        # Should return empty list, not raise exception
        assert violations == []

    def test_empty_file(self):
        """Test analysis of empty file."""
        code = ""
        violations = analyze_streamlit_security(Path("test.py"), code)
        assert violations == []

    def test_file_with_only_comments(self):
        """Test analysis of file with only comments."""
        code = """
# This is a comment
# Another comment
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        assert violations == []


class TestStreamlitMultipleViolations:
    """Test detection of multiple violations in one file."""

    def test_multiple_violation_types(self):
        """Test detection of multiple different violation types."""
        code = """
import streamlit as st
import os

# Multiple issues:
st.write(st.secrets)  # STREAMLIT001
st.write(os.getenv("KEY"))  # STREAMLIT002
uploaded = st.file_uploader("Upload")  # STREAMLIT005
user_input = st.text_input("Input")
st.markdown(f"<div>{user_input}</div>", unsafe_allow_html=True)  # STREAMLIT003
"""
        violations = analyze_streamlit_security(Path("test.py"), code)

        # Should have violations for multiple issues
        assert len(violations) >= 4

        rule_ids = [v.rule_id for v in violations]
        assert "STREAMLIT001" in rule_ids
        assert "STREAMLIT002" in rule_ids
        assert "STREAMLIT005" in rule_ids
        assert any(rid in ["STREAMLIT003", "STREAMLIT004"] for rid in rule_ids)

    def test_line_numbers_are_correct(self):
        """Test that line numbers in violations are accurate."""
        code = """import streamlit as st

uploaded = st.file_uploader("Upload")
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        assert len(violations) == 1
        assert violations[0].line_number == 3  # Third line


class TestStreamlitRealWorldScenarios:
    """Test real-world Streamlit app scenarios."""

    def test_data_dashboard_app(self):
        """Test a typical data dashboard application."""
        code = """
import streamlit as st
import pandas as pd

st.title("Data Dashboard")

# Safe operations
uploaded_file = st.file_uploader("Upload CSV", type=['csv'])
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.dataframe(df)
    
    # Safe visualization
    st.line_chart(df)
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        # Should have no violations - all safe operations
        assert len(violations) == 0

    def test_user_authentication_app(self):
        """Test a user authentication scenario."""
        code = """
import streamlit as st
import sqlite3

st.title("Login")

username = st.text_input("Username")
password = st.text_input("Password", type="password")

if st.button("Login"):
    # BAD: SQL injection vulnerability
    conn = sqlite3.connect("users.db")
    # Direct f-string in execute call is detected
    result = conn.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'  # SECURITY: Use environment variables or config files")
"""
        violations = analyze_streamlit_security(Path("test.py"), code)
        # Should detect SQL injection
        sql_violations = [v for v in violations if v.rule_id in ["STREAMLIT006", "STREAMLIT007"]]
        assert len(sql_violations) >= 1
