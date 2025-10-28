"""
Unit tests for Flask/FastAPI security analysis module.

Tests detection and auto-fixing of Flask/FastAPI security vulnerabilities.
"""

import ast
from pathlib import Path
from tempfile import NamedTemporaryFile

from pyguard.lib.framework_flask import (
    FLASK_CSRF_PROTECTION_RULE,
    FLASK_DEBUG_MODE_RULE,
    FLASK_INSECURE_CORS_RULE,
    FLASK_MASS_ASSIGNMENT_RULE,
    FLASK_SQL_INJECTION_RULE,
    FLASK_SSTI_RULE,
    FLASK_WEAK_SECRET_KEY_RULE,
    FlaskSecurityChecker,
    FlaskSecurityVisitor,
)
from pyguard.lib.rule_engine import FixApplicability, RuleCategory, RuleSeverity


class TestFlaskSecurityVisitor:
    """Test the FlaskSecurityVisitor class."""

    def test_detect_debug_mode_enabled(self):
        """Test detection of Flask debug mode enabled."""
        code = """
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK001"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.CRITICAL
        assert "debug mode" in violations[0].message.lower()
        assert violations[0].fix_applicability == FixApplicability.SAFE

    def test_no_violation_debug_mode_disabled(self):
        """Test no violation when debug mode is disabled."""
        code = """
from flask import Flask
app = Flask(__name__)
app.run(debug=False)
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK001"]
        assert len(violations) == 0

    def test_detect_ssti_vulnerability(self):
        """Test detection of Server-Side Template Injection (SSTI)."""
        code = """
from flask import render_template_string

def vulnerable_route():
    user_input = request.args.get('name')
    return render_template_string(f"Hello {user_input}")
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK002"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.HIGH
        assert "SSTI" in violations[0].message
        assert violations[0].fix_applicability == FixApplicability.MANUAL

    def test_detect_weak_secret_key(self):
        """Test detection of weak or hardcoded secret keys."""
        code = """
from flask import Flask
app = Flask(__name__)
app.secret_key = "dev"
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK004"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.CRITICAL
        assert "secret key" in violations[0].message.lower()
        assert violations[0].fix_applicability == FixApplicability.SAFE

    def test_detect_short_secret_key(self):
        """Test detection of too-short secret keys."""
        code = """
from flask import Flask
app = Flask(__name__)
app.secret_key = "short"
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK004"]
        assert len(violations) == 1

    def test_no_violation_env_secret_key(self):
        """Test no violation when using environment variable for secret key."""
        code = """
import os
from flask import Flask
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK004"]
        assert len(violations) == 0

    def test_detect_insecure_cors(self):
        """Test detection of insecure CORS configuration."""
        code = """
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, origins="*")
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK005"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.HIGH
        assert "CORS" in violations[0].message

    def test_detect_mass_assignment(self):
        """Test detection of potential mass assignment vulnerability."""
        code = """
from flask import jsonify

def get_user():
    user = User.query.get(1)
    return jsonify(user.to_dict())
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK003"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.MEDIUM
        assert "mass assignment" in violations[0].message.lower()

    def test_detect_sql_injection_in_route(self):
        """Test detection of SQL injection in route handler."""
        code = """
from flask import Flask, request

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return jsonify(cursor.fetchone())
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "FLASK006"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.CRITICAL
        assert "SQL injection" in violations[0].message

    def test_track_flask_import(self):
        """Test tracking of Flask imports."""
        code = """
from flask import Flask, render_template
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_flask_import is True
        assert visitor.has_fastapi_import is False

    def test_track_fastapi_import(self):
        """Test tracking of FastAPI imports."""
        code = """
from fastapi import FastAPI, Request
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_fastapi_import is True
        assert visitor.has_flask_import is False

    def test_track_csrf_protection_import(self):
        """Test tracking of CSRF protection import."""
        code = """
from flask import Flask
from flask_wtf.csrf import CSRFProtect
"""
        tree = ast.parse(code)
        visitor = FlaskSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        assert visitor.has_csrf_protection is True


class TestFlaskSecurityChecker:
    """Test the FlaskSecurityChecker class."""

    def test_check_file_with_vulnerabilities(self):
        """Test checking a file with multiple vulnerabilities."""
        code = """
from flask import Flask

app = Flask(__name__)
app.secret_key = "dev"
app.run(debug=True)
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            file_path = Path(f.name)

        try:
            checker = FlaskSecurityChecker()
            violations = checker.check_file(file_path)

            assert len(violations) >= 2
            rule_ids = [v.rule_id for v in violations]
            assert "FLASK001" in rule_ids  # debug mode
            assert "FLASK004" in rule_ids  # weak secret key
        finally:
            file_path.unlink()

    def test_check_non_flask_file(self):
        """Test checking a non-Flask file returns empty list."""
        code = """
def hello():
    print("Hello, World!")
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            file_path = Path(f.name)

        try:
            checker = FlaskSecurityChecker()
            violations = checker.check_file(file_path)
            assert len(violations) == 0
        finally:
            file_path.unlink()

    def test_check_csrf_protection_warning(self):
        """Test CSRF protection warning for POST routes."""
        code = """
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    return "OK"
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            file_path = Path(f.name)

        try:
            checker = FlaskSecurityChecker()
            violations = checker.check_file(file_path)

            csrf_violations = [v for v in violations if v.rule_id == "FLASK007"]
            assert len(csrf_violations) == 1
            assert "CSRF" in csrf_violations[0].message
        finally:
            file_path.unlink()

    def test_no_csrf_warning_with_protection(self):
        """Test no CSRF warning when protection is imported."""
        code = """
from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

@app.route('/login', methods=['POST'])
def login():
    return "OK"
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            file_path = Path(f.name)

        try:
            checker = FlaskSecurityChecker()
            violations = checker.check_file(file_path)

            csrf_violations = [v for v in violations if v.rule_id == "FLASK007"]
            assert len(csrf_violations) == 0
        finally:
            file_path.unlink()

    def test_fix_debug_mode(self):
        """Test auto-fixing debug mode."""
        code = """
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            file_path = Path(f.name)

        try:
            checker = FlaskSecurityChecker()
            success, fixes = checker.fix_file(file_path)

            assert success is True
            assert "debug mode" in " ".join(fixes).lower()

            # Verify the fix was applied
            with open(file_path) as f:
                fixed_content = f.read()
            assert "debug=False" in fixed_content
            assert "debug=True" not in fixed_content
        finally:
            file_path.unlink()

    def test_fix_secret_key(self):
        """Test auto-fixing hardcoded secret key."""
        code = """
from flask import Flask
app = Flask(__name__)
app.secret_key = "dev"
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            file_path = Path(f.name)

        try:
            checker = FlaskSecurityChecker()
            success, fixes = checker.fix_file(file_path)

            assert success is True
            assert "secret_key" in " ".join(fixes).lower()

            # Verify the fix was applied
            with open(file_path) as f:
                fixed_content = f.read()
            assert "os.environ.get" in fixed_content
            assert "import os" in fixed_content
        finally:
            file_path.unlink()

    def test_fix_file_no_violations(self):
        """Test fixing a file with no violations."""
        code = """
from flask import Flask
app = Flask(__name__)
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            file_path = Path(f.name)

        try:
            checker = FlaskSecurityChecker()
            success, fixes = checker.fix_file(file_path)

            assert success is True
            assert len(fixes) == 0
        finally:
            file_path.unlink()


class TestFlaskRules:
    """Test Flask security rule definitions."""

    def test_debug_mode_rule(self):
        """Test Flask debug mode rule definition."""
        assert FLASK_DEBUG_MODE_RULE.rule_id == "FLASK001"
        assert FLASK_DEBUG_MODE_RULE.severity == RuleSeverity.CRITICAL
        assert FLASK_DEBUG_MODE_RULE.category == RuleCategory.SECURITY
        assert FLASK_DEBUG_MODE_RULE.fix_applicability == FixApplicability.SAFE

    def test_ssti_rule(self):
        """Test Flask SSTI rule definition."""
        assert FLASK_SSTI_RULE.rule_id == "FLASK002"
        assert FLASK_SSTI_RULE.severity == RuleSeverity.HIGH
        assert FLASK_SSTI_RULE.fix_applicability == FixApplicability.MANUAL

    def test_mass_assignment_rule(self):
        """Test Flask mass assignment rule definition."""
        assert FLASK_MASS_ASSIGNMENT_RULE.rule_id == "FLASK003"
        assert FLASK_MASS_ASSIGNMENT_RULE.severity == RuleSeverity.MEDIUM

    def test_weak_secret_key_rule(self):
        """Test Flask weak secret key rule definition."""
        assert FLASK_WEAK_SECRET_KEY_RULE.rule_id == "FLASK004"
        assert FLASK_WEAK_SECRET_KEY_RULE.severity == RuleSeverity.CRITICAL

    def test_insecure_cors_rule(self):
        """Test Flask insecure CORS rule definition."""
        assert FLASK_INSECURE_CORS_RULE.rule_id == "FLASK005"
        assert FLASK_INSECURE_CORS_RULE.severity == RuleSeverity.HIGH

    def test_sql_injection_rule(self):
        """Test Flask SQL injection rule definition."""
        assert FLASK_SQL_INJECTION_RULE.rule_id == "FLASK006"
        assert FLASK_SQL_INJECTION_RULE.severity == RuleSeverity.CRITICAL
        assert FLASK_SQL_INJECTION_RULE.fix_applicability == FixApplicability.MANUAL

    def test_csrf_protection_rule(self):
        """Test Flask CSRF protection rule definition."""
        assert FLASK_CSRF_PROTECTION_RULE.rule_id == "FLASK007"
        assert FLASK_CSRF_PROTECTION_RULE.severity == RuleSeverity.HIGH
