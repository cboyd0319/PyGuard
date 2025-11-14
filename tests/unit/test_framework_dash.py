"""
Unit tests for Dash/Plotly security analysis.

Tests cover:
- Debug mode detection
- XSS vulnerabilities in HTML/Markdown
- SQL injection detection
- Callback security
- Server configuration
"""

import ast
from pathlib import Path

from pyguard.lib.framework_dash import (
    DashSecurityVisitor,
    analyze_dash_security,
    fix_dash_security,
)
from pyguard.lib.rule_engine import RuleSeverity


class TestDashDebugMode:
    """Test detection of debug mode in production."""

    def test_detect_debug_mode_enabled(self):
        """Test detection of debug=True in run_server."""
        code = """
import dash

app = dash.Dash(__name__)

# BAD: Debug mode in production
app.run_server(debug=True)
"""
        violations = analyze_dash_security(Path("test.py"), code)
        debug_violations = [v for v in violations if v.rule_id == "DASH001"]
        assert len(debug_violations) == 1
        assert debug_violations[0].severity == RuleSeverity.CRITICAL

    def test_safe_production_mode(self):
        """Test that production mode doesn't trigger violations."""
        code = """
import dash

app = dash.Dash(__name__)

# GOOD: Debug mode disabled or not specified
app.run_server(debug=False)
"""
        violations = analyze_dash_security(Path("test.py"), code)
        debug_violations = [v for v in violations if v.rule_id == "DASH001"]
        assert len(debug_violations) == 0

    def test_fix_debug_mode(self):
        """Test auto-fix for debug mode."""
        code = """app.run_server(debug=True)"""

        from pyguard.lib.rule_engine import FixApplicability, RuleCategory, RuleViolation

        violation = RuleViolation(
            rule_id="DASH001",
            message="Debug mode enabled",
            line_number=1,
            column=0,
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.SECURITY,
            file_path=Path("test.py"),
            fix_applicability=FixApplicability.SAFE,
            fix_data={"keyword": "debug", "new_value": "False"},
        )

        fixed_code, success = fix_dash_security(code, violation)
        assert success
        assert "debug=False" in fixed_code
        assert "debug=True" not in fixed_code


class TestDashXSSVulnerabilities:
    """Test detection of XSS vulnerabilities."""

    def test_detect_xss_dangerously_allow_html(self):
        """Test detection of XSS via dangerously_allow_html."""
        code = """
import dash
from dash import dcc, html

app = dash.Dash(__name__)

user_input = "some input"
# BAD: dangerously_allow_html with user input
app.layout = html.Div([
    dcc.Markdown(f"# {user_input}", dangerously_allow_html=True)
])
"""
        violations = analyze_dash_security(Path("test.py"), code)
        xss_violations = [v for v in violations if v.rule_id == "DASH002"]
        assert len(xss_violations) == 1
        assert xss_violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_xss_markdown_user_input(self):
        """Test detection of XSS in Markdown with user input."""
        code = """
import dash
from dash import dcc

user_input = "malicious input"
# BAD: User input in Markdown
layout = dcc.Markdown(children=f"## {user_input}")
"""
        violations = analyze_dash_security(Path("test.py"), code)
        xss_violations = [v for v in violations if v.rule_id == "DASH003"]
        assert len(xss_violations) == 1

    def test_safe_markdown_usage(self):
        """Test that safe Markdown usage doesn't trigger violations."""
        code = """
import dash
from dash import dcc

# GOOD: Static content only
layout = dcc.Markdown("## Static Title")
"""
        violations = analyze_dash_security(Path("test.py"), code)
        xss_violations = [v for v in violations if v.rule_id in ["DASH002", "DASH003"]]
        assert len(xss_violations) == 0


class TestDashSQLInjection:
    """Test detection of SQL injection vulnerabilities."""

    def test_detect_sql_injection_fstring(self):
        """Test detection of SQL injection via f-string."""
        code = """
import dash
import sqlite3

@app.callback()
def query_data(user_id):
    # TODO: Add docstring
    conn = sqlite3.connect("db.sqlite")
    # BAD: f-string in SQL query
    result = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return result
"""
        violations = analyze_dash_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "DASH005"]
        assert len(sql_violations) == 1
        assert sql_violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_sql_injection_string_concat(self):
        """Test detection of SQL injection via string concatenation."""
        code = """
import dash

def query_data(search_term):
    # TODO: Add docstring
    # BAD: String concatenation in SQL query
    query = "SELECT * FROM products WHERE name = " + search_term
    conn.execute(query)
"""
        violations = analyze_dash_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "DASH006"]
        assert len(sql_violations) == 1

    def test_safe_parameterized_query(self):
        """Test that parameterized queries don't trigger violations."""
        code = """
import dash
import sqlite3

@app.callback()
def query_data(user_id):
    # TODO: Add docstring
    conn = sqlite3.connect("db.sqlite")
    # GOOD: Parameterized query
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return result
"""
        violations = analyze_dash_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id in ["DASH005", "DASH006"]]
        assert len(sql_violations) == 0


class TestDashImportDetection:
    """Test Dash import detection."""

    def test_detect_dash_import(self):
        """Test detection of dash import."""
        code = """
import dash

app = dash.Dash(__name__)
"""
        tree = ast.parse(code)
        visitor = DashSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_dash_import is True

    def test_detect_dash_from_import(self):
        """Test detection of from dash import."""
        code = """
from dash import Dash, dcc, html

app = Dash(__name__)
"""
        tree = ast.parse(code)
        visitor = DashSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_dash_import is True

    def test_detect_plotly_import(self):
        """Test detection of plotly import."""
        code = """
import plotly.graph_objects as go

fig = go.Figure()
"""
        tree = ast.parse(code)
        visitor = DashSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_plotly_import is True

    def test_no_violations_without_dash_import(self):
        """Test that violations are not reported without Dash import."""
        code = """
# Regular Python code without Dash
def run_server(debug=True):
    # TODO: Add docstring
    print("Running server")

run_server()
"""
        violations = analyze_dash_security(Path("test.py"), code)
        # Should return empty list since Dash is not imported
        assert len(violations) == 0


class TestDashEdgeCases:
    """Test edge cases and error handling."""

    def test_handle_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
import dash

# Syntax error
app.run_server(
"""
        violations = analyze_dash_security(Path("test.py"), code)
        # Should return empty list, not raise exception
        assert violations == []

    def test_empty_file(self):
        """Test analysis of empty file."""
        code = ""
        violations = analyze_dash_security(Path("test.py"), code)
        assert violations == []

    def test_file_with_only_comments(self):
        """Test analysis of file with only comments."""
        code = """
# This is a comment
# Another comment
"""
        violations = analyze_dash_security(Path("test.py"), code)
        assert violations == []


class TestDashMultipleViolations:
    """Test detection of multiple violations in one file."""

    def test_multiple_violation_types(self):
        """Test detection of multiple different violation types."""
        code = """
import dash
from dash import dcc, html
import sqlite3

app = dash.Dash(__name__)

@app.callback()
def update_data(user_input, search_term):
    # TODO: Add docstring
    # SQL injection
    conn = sqlite3.connect("db.sqlite")
    result = conn.execute(f"SELECT * FROM data WHERE id = {user_input}")
    
    # XSS risk
    layout = dcc.Markdown(children=f"## {search_term}")
    
    return layout

# Debug mode in production
app.run_server(debug=True)
"""
        violations = analyze_dash_security(Path("test.py"), code)

        # Should have multiple violations
        assert len(violations) >= 3

        rule_ids = [v.rule_id for v in violations]
        assert "DASH001" in rule_ids  # Debug mode
        assert "DASH003" in rule_ids  # XSS in Markdown
        assert "DASH005" in rule_ids  # SQL injection


class TestDashRealWorldScenarios:
    """Test real-world Dash application scenarios."""

    def test_dashboard_app_safe(self):
        """Test a typical dashboard application with safe operations."""
        code = """
import dash
from dash import dcc, html
import plotly.graph_objects as go

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("Dashboard"),
    dcc.Graph(
        figure=go.Figure(
            data=[go.Scatter(x=[1, 2, 3], y=[4, 1, 2])]
        )
    )
])

app.run_server()
"""
        violations = analyze_dash_security(Path("test.py"), code)
        # Should have no violations - all safe operations
        assert len(violations) == 0

    def test_data_analytics_app_with_database(self):
        """Test a data analytics app with database."""
        code = """
import dash
from dash import dcc, html
import pandas as pd
import sqlite3

app = dash.Dash(__name__)

@app.callback()
def update_graph(selected_value):
    # TODO: Add docstring
    # GOOD: Parameterized query
    conn = sqlite3.connect("analytics.db")
    df = pd.read_sql("SELECT * FROM metrics WHERE type = ?", conn, params=(selected_value,))
    
    figure = {
        'data': [{'x': df['date'], 'y': df['value']}]
    }
    return figure

app.run_server()
"""
        violations = analyze_dash_security(Path("test.py"), code)
        # Should have no SQL injection violations
        sql_violations = [v for v in violations if v.rule_id in ["DASH005", "DASH006"]]
        assert len(sql_violations) == 0

    def test_interactive_app_with_issues(self):
        """Test an interactive app with security issues."""
        code = """
import dash
from dash import dcc, html, Input, Output

app = dash.Dash(__name__)

app.layout = html.Div([
    dcc.Input(id='user-input', type='text'),
    html.Div(id='output')
])

@app.callback(Output('output', 'children'), Input('user-input', 'value'))
def update_output(value):
    # TODO: Add docstring
    # BAD: User input in Markdown
    return dcc.Markdown(children=f"You entered: {value}")

# BAD: Debug mode enabled
app.run_server(debug=True, host='0.0.0.0')
"""
        violations = analyze_dash_security(Path("test.py"), code)
        # Should detect multiple issues
        assert len(violations) >= 2

        rule_ids = [v.rule_id for v in violations]
        assert "DASH001" in rule_ids  # Debug mode
        assert "DASH003" in rule_ids  # XSS in Markdown


class TestDashCallbackTracking:
    """Test callback tracking functionality."""

    def test_track_callbacks(self):
        """Test that callbacks are tracked."""
        code = """
import dash
from dash import Input, Output

app = dash.Dash(__name__)

@app.callback(Output('output', 'children'), Input('input', 'value'))
def update(value):
    # TODO: Add docstring
    return value
"""
        tree = ast.parse(code)
        visitor = DashSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert len(visitor.callbacks) == 1
        assert visitor.callbacks[0]["line"] == 7
