"""
Tests for Authentication & Authorization Security module.

Tests cover:
- Weak session ID generation (AUTH001)
- Hardcoded credentials (AUTH002)
- Timing attacks (AUTH003)
- Session fixation (AUTH004)
- Missing authentication (AUTH005)
- IDOR vulnerabilities (AUTH006)
- JWT without expiration (AUTH007)
- Session timeout (AUTH008)
"""

import ast
import tempfile
from pathlib import Path

import pytest

from pyguard.lib.auth_security import AuthSecurityChecker, AuthSecurityVisitor
from pyguard.lib.rule_engine import RuleSeverity


class TestWeakSessionIDDetection:
    """Tests for AUTH001: Weak Session ID Generation."""

    def test_detect_random_randint_session_id(self):
        """Detect session ID using random.randint()."""
        code = """
import random
session_id = random.randint(1000, 9999)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH001"]
        assert len(violations) == 1
        assert "random.randint" in violations[0].message
        assert violations[0].severity == RuleSeverity.HIGH

    def test_detect_random_random_session_id(self):
        """Detect session ID using random.random()."""
        code = """
import random
session_token = str(random.random())
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH001"]
        assert len(violations) == 1

    def test_detect_uuid1_session_id(self):
        """Detect session ID using uuid.uuid1() (includes MAC address)."""
        code = """
import uuid
session_id = uuid.uuid1()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH001"]
        assert len(violations) == 1
        assert "uuid1" in violations[0].message

    def test_safe_secrets_module(self):
        """No issue when using secrets module (cryptographically secure)."""
        code = """
import secrets
session_id = secrets.token_hex(32)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH001"]
        assert len(violations) == 0

    def test_safe_uuid4(self):
        """No issue when using uuid.uuid4() (random)."""
        code = """
import uuid
session_id = uuid.uuid4()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH001"]
        assert len(violations) == 0

    def test_fix_random_randint_to_secrets(self):
        """Test auto-fix: random.randint() → secrets.randbelow()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import random\nsession_id = random.randint(1000, 9999)")
            f.flush()
            file_path = Path(f.name)

        try:
            checker = AuthSecurityChecker()
            violations = checker.check_file(file_path)
            fixed_code = checker.fix_file(file_path, violations)

            assert "secrets.randbelow" in fixed_code
            assert "import secrets" in fixed_code
        finally:
            file_path.unlink()


class TestHardcodedCredentials:
    """Tests for AUTH002: Hardcoded Credentials."""

    def test_detect_hardcoded_password(self):
        """Detect hardcoded password in variable."""
        code = """
password = "MySecretPassword123"
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH002"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_hardcoded_api_key(self):
        """Detect hardcoded API key."""
        code = """
api_key = "sk-1234567890abcdef"
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH002"]
        assert len(violations) == 1

    def test_detect_hardcoded_secret_key(self):
        """Detect hardcoded secret key."""
        code = """
SECRET_KEY = "django-insecure-abc123"
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH002"]
        assert len(violations) == 1

    def test_safe_password_from_env(self):
        """No issue when password comes from environment."""
        code = """
import os
password = os.getenv("PASSWORD")
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH002"]
        assert len(violations) == 0

    def test_skip_placeholder_passwords(self):
        """Don't flag obvious placeholders."""
        code = """
password = "changeme"
api_key = ""
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH002"]
        assert len(violations) == 0


class TestTimingAttack:
    """Tests for AUTH003: Password Comparison Timing Attack."""

    def test_detect_direct_password_comparison(self):
        """Detect direct password comparison using ==."""
        code = """
def authenticate(user_password, stored_password):
    if user_password == stored_password:
        return True
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH003"]
        assert len(violations) == 1
        assert "timing attack" in violations[0].message.lower()

    def test_detect_token_comparison(self):
        """Detect direct token comparison."""
        code = """
def verify_token(received_token, expected_token):
    return received_token == expected_token
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH003"]
        assert len(violations) == 1

    def test_safe_constant_time_comparison(self):
        """No issue with constant-time comparison (hmac.compare_digest)."""
        code = """
import hmac
def verify_token(received_token, expected_token):
    return hmac.compare_digest(received_token, expected_token)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH003"]
        assert len(violations) == 0


class TestSessionFixation:
    """Tests for AUTH004: Session Fixation Vulnerability."""

    def test_detect_login_without_session_regeneration(self):
        """Detect login function that doesn't regenerate session."""
        code = """
from flask import session
def user_login(username, password):
    session['username'] = username
    return True
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH004"]
        assert len(violations) == 1
        assert "session fixation" in violations[0].message.lower()

    def test_safe_login_with_regeneration(self):
        """No issue when session is regenerated."""
        code = """
from flask import session
def user_login(username, password):
    session.regenerate()
    session['username'] = username
    return True
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH004"]
        assert len(violations) == 0

    def test_no_false_positive_non_login_function(self):
        """No issue for non-login functions."""
        code = """
def helper_function():
    pass
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH004"]
        assert len(violations) == 0


class TestMissingAuthentication:
    """Tests for AUTH005: Missing Authentication on Sensitive Operations."""

    def test_detect_unprotected_delete_route(self):
        """Detect delete route without authentication."""
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    # Delete user
    pass
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH005"]
        assert len(violations) == 1
        assert "missing authentication" in violations[0].message.lower()

    def test_detect_unprotected_admin_route(self):
        """Detect admin route without authentication."""
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/dashboard')
def admin_dashboard():
    return "Admin Panel"
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH005"]
        assert len(violations) == 1

    def test_safe_protected_route(self):
        """No issue when route has authentication decorator."""
        code = """
from flask import Flask
from flask_login import login_required
app = Flask(__name__)

@app.route('/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    pass
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH005"]
        assert len(violations) == 0


class TestIDORVulnerability:
    """Tests for AUTH006: Insecure Direct Object Reference."""

    def test_detect_idor_in_get_function(self):
        """Detect IDOR in function that gets resource by ID."""
        code = """
def get_document(document_id):
    return database.query(Document).filter_by(id=document_id).first()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH006"]
        assert len(violations) == 1
        assert "IDOR" in violations[0].message

    def test_detect_idor_with_pk_parameter(self):
        """Detect IDOR with 'pk' parameter name."""
        code = """
def fetch_record(pk):
    return Model.objects.get(pk=pk)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH006"]
        assert len(violations) == 1

    def test_safe_with_ownership_check(self):
        """No issue when ownership is verified."""
        code = """
def get_document(document_id, current_user):
    doc = database.query(Document).filter_by(id=document_id).first()
    if doc.owner_id == current_user.id:
        return doc
    raise PermissionError()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH006"]
        assert len(violations) == 0

    def test_safe_with_permission_check(self):
        """No issue when permission check is called."""
        code = """
def retrieve_item(item_id):
    item = get_item(item_id)
    check_permission(item)
    return item
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH006"]
        assert len(violations) == 0


class TestJWTExpiration:
    """Tests for AUTH007: JWT Token Without Expiration."""

    def test_detect_jwt_without_exp(self):
        """Detect JWT token created without 'exp' claim."""
        code = """
import jwt
payload = {'user_id': 123, 'username': 'alice'}
token = jwt.encode(payload, secret_key, algorithm='HS256')
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_jwt_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH007"]
        assert len(violations) == 1
        assert "expiration" in violations[0].message.lower()

    def test_detect_jwt_dict_without_exp(self):
        """Detect JWT with inline dict without exp."""
        code = """
import jwt
token = jwt.encode({'user_id': 123}, secret, algorithm='HS256')
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_jwt_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH007"]
        assert len(violations) == 1

    def test_safe_jwt_with_exp(self):
        """No issue when JWT includes 'exp' claim."""
        code = """
import jwt
import datetime
payload = {
    'user_id': 123,
    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
}
token = jwt.encode(payload, secret_key, algorithm='HS256')
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_jwt_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH007"]
        assert len(violations) == 0

    def test_safe_jwt_inline_with_exp(self):
        """No issue with inline dict containing exp."""
        code = """
import jwt
token = jwt.encode({'user_id': 123, 'exp': 1234567890}, key, algorithm='HS256')
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_jwt_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH007"]
        assert len(violations) == 0


class TestAuthSecurityChecker:
    """Tests for AuthSecurityChecker class."""

    def test_check_file_success(self):
        """Test checking a file with vulnerabilities."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
import random
session_id = random.randint(1000, 9999)
password = "hardcoded123"
""")
            f.flush()
            file_path = Path(f.name)

        try:
            checker = AuthSecurityChecker()
            violations = checker.check_file(file_path)

            assert len(violations) >= 2  # At least weak session + hardcoded pwd
            assert any(v.rule_id == "AUTH001" for v in violations)
            assert any(v.rule_id == "AUTH002" for v in violations)
        finally:
            file_path.unlink()

    def test_check_file_syntax_error(self):
        """Test graceful handling of syntax errors."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("def invalid syntax here")
            f.flush()
            file_path = Path(f.name)

        try:
            checker = AuthSecurityChecker()
            violations = checker.check_file(file_path)
            assert len(violations) == 0  # Should return empty list, not crash
        finally:
            file_path.unlink()

    def test_fix_file_only_safe_fixes(self):
        """Test that only SAFE fixes are applied."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
import random
session_id = random.randint(1000, 9999)
password = "hardcoded123"  # This should NOT be auto-fixed (WARNING_ONLY)
""")
            f.flush()
            file_path = Path(f.name)

        try:
            checker = AuthSecurityChecker()
            violations = checker.check_file(file_path)
            fixed_code = checker.fix_file(file_path, violations)

            # Session ID should be fixed (SAFE)
            assert "secrets" in fixed_code

            # Hardcoded password should NOT be removed (WARNING_ONLY)
            assert "hardcoded123" in fixed_code
        finally:
            file_path.unlink()


class TestRealWorldPatterns:
    """Tests with real-world authentication patterns."""

    def test_flask_login_pattern(self):
        """Test detection in realistic Flask login function."""
        code = """
from flask import Flask, session, request
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Timing attack vulnerability
    if password == get_stored_password(username):
        # Session fixation vulnerability
        session['user'] = username
        return "Login successful"
    return "Login failed"
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        # Should detect both timing attack and session fixation
        timing_violations = [v for v in visitor.violations if v.rule_id == "AUTH003"]
        fixation_violations = [v for v in visitor.violations if v.rule_id == "AUTH004"]
        
        assert len(timing_violations) >= 1
        assert len(fixation_violations) == 1

    def test_django_idor_pattern(self):
        """Test detection in Django view with IDOR."""
        code = """
from django.shortcuts import get_object_or_404
from .models import Order

def order_detail(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    return render(request, 'order.html', {'order': order})
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_django_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH006"]
        assert len(violations) == 1

    def test_fastapi_jwt_pattern(self):
        """Test JWT creation in FastAPI - should detect missing JWT expiration."""
        code = """
from fastapi import FastAPI
import jwt

app = FastAPI()

@app.post("/login")
def login(credentials: dict):
    payload = {"user_id": 123, "role": "admin"}
    token = jwt.encode(payload, "secret", algorithm="HS256")
    return {"access_token": token}
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_fastapi_import = True
        visitor.has_jwt_import = True
        visitor.visit(tree)

        # Should detect missing JWT expiration (but NOT missing auth on login route - that's expected)
        jwt_violations = [v for v in visitor.violations if v.rule_id == "AUTH007"]
        
        assert len(jwt_violations) == 1, f"Expected 1 JWT violation, got {len(jwt_violations)}"


class TestWeakPasswordResetToken:
    """Tests for AUTH009: Weak Password Reset Token Generation."""

    def test_detect_weak_reset_token_random(self):
        """Detect password reset token using random module."""
        code = """
import random
reset_token = str(random.randint(100000, 999999))
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH009"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_weak_reset_token_choice(self):
        """Detect reset token using random.choice()."""
        code = """
import random
import string
password_reset_token = ''.join(random.choice(string.ascii_letters) for _ in range(20))
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH009"]
        assert len(violations) == 1

    def test_safe_reset_token_secrets(self):
        """No issue with secrets module for reset tokens."""
        code = """
import secrets
reset_token = secrets.token_urlsafe(32)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH009"]
        assert len(violations) == 0

    def test_safe_reset_token_os_urandom(self):
        """No issue with os.urandom() for reset tokens."""
        code = """
import os
import binascii
reset_token = binascii.hexlify(os.urandom(32)).decode()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH009"]
        assert len(violations) == 0


class TestPrivilegeEscalation:
    """Tests for AUTH010: Privilege Escalation Risk."""

    def test_detect_role_from_request(self):
        """Detect setting user role from request parameter."""
        code = """
def update_user(request):
    user.role = request.form['role']
    user.save()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH010"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.CRITICAL

    def test_detect_admin_from_params(self):
        """Detect setting is_admin from params."""
        code = """
def register(data):
    user.is_admin = data['is_admin']
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH010"]
        assert len(violations) == 1

    def test_detect_permission_from_form(self):
        """Detect setting permissions from form data."""
        code = """
user.permission = form['permission']
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH010"]
        assert len(violations) == 1

    def test_safe_role_assignment(self):
        """No issue when role is set from safe source."""
        code = """
def create_user():
    user.role = 'user'  # Default role
    user.save()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH010"]
        assert len(violations) == 0


class TestMissingMFA:
    """Tests for AUTH011: Missing Multi-Factor Authentication."""

    def test_detect_login_without_mfa(self):
        """Detect login function without MFA."""
        code = """
from flask import Flask, request
def login():
    username = request.form['username']
    password = request.form['password']
    if check_password(username, password):
        return "Login successful"
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH011"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.MEDIUM

    def test_safe_login_with_totp(self):
        """No issue when MFA/TOTP is implemented."""
        code = """
from flask import Flask
def login(credentials):
    if check_password(credentials):
        if verify_totp(credentials['totp_code']):
            return "Login successful"
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_flask_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH011"]
        assert len(violations) == 0

    def test_safe_login_with_mfa_check(self):
        """No issue when MFA check is present."""
        code = """
def signin(user):
    if authenticate(user):
        return check_mfa(user)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.has_django_import = True
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH011"]
        assert len(violations) == 0


class TestInsecureRememberMe:
    """Tests for AUTH012: Insecure Remember Me Implementation."""

    def test_detect_password_in_remember_cookie(self):
        """Detect storing password in remember me cookie."""
        code = """
from flask import make_response
def login():
    response = make_response("OK")
    response.set_cookie('remember_me', value=password)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH012"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.HIGH

    def test_detect_credential_in_cookie(self):
        """Detect storing credential in cookie."""
        code = """
response.set_cookie(name='remember_token', value=user_credentials)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH012"]
        assert len(violations) == 1

    def test_safe_remember_me_token(self):
        """No issue when using secure token for remember me."""
        code = """
import secrets
response.set_cookie('remember_me', value=secrets.token_hex(32))
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH012"]
        assert len(violations) == 0


class TestWeakPasswordPolicy:
    """Tests for AUTH013: Weak Password Policy."""

    def test_detect_short_password_requirement(self):
        """Detect password validation with short minimum length."""
        code = """
def validate_password(pwd):
    if len(pwd) >= 4:
        return True
    return False
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH013"]
        assert len(violations) == 1
        assert "4 < 8" in violations[0].message

    def test_detect_weak_6_char_policy(self):
        """Detect 6-character password policy."""
        code = """
def check_password_strength(password):
    return len(password) >= 6
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH013"]
        assert len(violations) == 1

    def test_safe_strong_password_policy(self):
        """No issue with 8+ character requirement."""
        code = """
def validate_password(pwd):
    if len(pwd) >= 8:
        return True
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH013"]
        assert len(violations) == 0


class TestNullByteAuthBypass:
    """Tests for AUTH014: Null Byte Authentication Bypass."""

    def test_detect_password_comparison(self):
        """Detect direct password comparison vulnerable to null bytes."""
        code = """
def authenticate(username, password):
    if password == stored_password:
        return True
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH014"]
        assert len(violations) == 1
        assert violations[0].severity == RuleSeverity.HIGH

    def test_detect_token_comparison(self):
        """Detect token comparison vulnerable to null bytes."""
        code = """
if auth_token == valid_token:
    grant_access()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH014"]
        assert len(violations) == 1

    def test_detect_user_comparison(self):
        """Detect user comparison vulnerable to null bytes."""
        code = """
if user == authenticated_user:
    allow()
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH014"]
        assert len(violations) == 1


class TestLDAPInjection:
    """Tests for AUTH015: LDAP Injection in Authentication."""

    def test_detect_ldap_string_concat(self):
        """Detect LDAP query with string concatenation."""
        code = """
import ldap
def authenticate(username):
    conn = ldap.initialize('ldap://server')
    # Direct f-string in search call
    conn.search_s("ou=users", ldap.SCOPE_SUBTREE, f"(uid={username})")
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH015"]
        assert len(violations) >= 1
        assert violations[0].severity == RuleSeverity.HIGH

    def test_detect_ldap_search_with_user_input(self):
        """Detect LDAP search with unsanitized user input."""
        code = """
# Direct string concatenation in search call
result = ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, "(cn=" + user_input + ")")
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH015"]
        assert len(violations) >= 1

    def test_safe_ldap_with_escaping(self):
        """No issue when LDAP input is properly escaped (pattern not detected)."""
        code = """
import ldap.filter
filter_str = ldap.filter.escape_filter_chars(username)
"""
        tree = ast.parse(code)
        visitor = AuthSecurityVisitor(Path("test.py"), code)
        visitor.visit(tree)

        violations = [v for v in visitor.violations if v.rule_id == "AUTH015"]
        # Note: Our check looks for string concat/f-strings in search calls
        # so this safe code won't trigger
        assert len(violations) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
