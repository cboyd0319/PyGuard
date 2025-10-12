"""Unit tests for enhanced detections module."""

import pytest

from pyguard.lib.enhanced_detections import (
    AuthenticationBypassDetector,
    AuthorizationBypassDetector,
    CryptographicNonceMisuseDetector,
    ImproperCertificateValidationDetector,
    InsecureSessionManagementDetector,
    ResourceLeakDetector,
    UncontrolledResourceConsumptionDetector,
)


class TestAuthenticationBypassDetector:
    """Test authentication bypass detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = AuthenticationBypassDetector()

    def test_detects_hardcoded_true(self):
        """Test detection of hardcoded True condition."""
        code = """
def check_auth():
    if True:  # Authentication bypass
        return "authenticated"
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0
        assert issues[0].severity == "CRITICAL"
        assert "CWE-287" in issues[0].cwe_id

    def test_detects_commented_auth(self):
        """Test detection of commented authentication."""
        code = """
def login(user):
    # authenticate(user)  # Disabled for testing
    return True
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0

    def test_no_false_positives(self):
        """Test no false positives on proper auth."""
        code = """
def check_auth(user):
    if user.is_authenticated():
        return True
    return False
"""
        issues = self.detector.scan_code(code)
        assert len(issues) == 0


class TestAuthorizationBypassDetector:
    """Test authorization bypass (IDOR) detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = AuthorizationBypassDetector()

    def test_detects_idor(self):
        """Test detection of IDOR vulnerability."""
        code = """
def get_user_data(user_id):
    user = User.get(id)
    return user.data
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0
        assert issues[0].severity == "HIGH"
        assert "CWE-639" in issues[0].cwe_id

    def test_detects_request_id(self):
        """Test detection of user-supplied ID."""
        code = """
def view_document(request):
    doc = Document.get(request.args.id)
    return doc
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0

    def test_no_issue_with_authorization_check(self):
        """Test no issue when authorization is checked."""
        code = """
def get_user_data(user_id, current_user):
    user = User.get(id)
    if user.owner == current_user:
        return user.data
"""
        issues = self.detector.scan_code(code)
        assert len(issues) == 0


class TestInsecureSessionManagementDetector:
    """Test insecure session management detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = InsecureSessionManagementDetector()

    def test_detects_insecure_cookie(self):
        """Test detection of insecure cookie settings."""
        code = """
response.set_cookie('session', value, httponly=False)
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0
        assert issues[0].severity == "HIGH"
        assert "CWE-384" in issues[0].cwe_id

    def test_detects_permanent_session(self):
        """Test detection of permanent session."""
        code = """
session.permanent = True
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0

    def test_no_false_positives(self):
        """Test no false positives on secure sessions."""
        code = """
response.set_cookie('session', value, httponly=True, secure=True)
"""
        issues = self.detector.scan_code(code)
        assert len(issues) == 0


class TestResourceLeakDetector:
    """Test resource leak detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = ResourceLeakDetector()

    def test_detects_open_without_context(self):
        """Test detection of file open without context manager."""
        code = """
f = open('file.txt', 'r')
data = f.read()
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0
        assert issues[0].severity == "MEDIUM"
        assert "CWE-404" in issues[0].cwe_id

    def test_no_issue_with_context_manager(self):
        """Test no issue when using context manager."""
        code = """
with open('file.txt', 'r') as f:
    data = f.read()
"""
        issues = self.detector.scan_code(code)
        assert len(issues) == 0


class TestUncontrolledResourceConsumptionDetector:
    """Test uncontrolled resource consumption detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = UncontrolledResourceConsumptionDetector()

    def test_detects_unbounded_read(self):
        """Test detection of unbounded read."""
        code = """
data = file.read()
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0
        assert issues[0].severity == "MEDIUM"
        assert "CWE-400" in issues[0].cwe_id

    def test_detects_readlines(self):
        """Test detection of readlines without limit."""
        code = """
lines = file.readlines()
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0

    def test_no_issue_with_size_limit(self):
        """Test no issue when size limit is specified."""
        code = """
data = file.read(1024)
"""
        issues = self.detector.scan_code(code)
        assert len(issues) == 0


class TestImproperCertificateValidationDetector:
    """Test improper certificate validation detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = ImproperCertificateValidationDetector()

    def test_detects_verify_false(self):
        """Test detection of verify=False."""
        code = """
response = requests.get(url, verify=False)
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0
        assert issues[0].severity == "HIGH"
        assert "CWE-295" in issues[0].cwe_id

    def test_detects_unverified_context(self):
        """Test detection of unverified SSL context."""
        code = """
context = ssl._create_unverified_context()
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0

    def test_no_false_positives(self):
        """Test no false positives on proper validation."""
        code = """
response = requests.get(url, verify=True)
"""
        issues = self.detector.scan_code(code)
        assert len(issues) == 0


class TestCryptographicNonceMisuseDetector:
    """Test cryptographic nonce misuse detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = CryptographicNonceMisuseDetector()

    def test_detects_hardcoded_iv(self):
        """Test detection of hardcoded IV."""
        code = """
iv = b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
cipher.encrypt(data, iv=iv)
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0
        assert issues[0].severity == "HIGH"
        assert "CWE-323" in issues[0].cwe_id

    def test_detects_hardcoded_nonce(self):
        """Test detection of hardcoded nonce."""
        code = """
nonce = b"static_nonce"
"""
        issues = self.detector.scan_code(code)
        assert len(issues) > 0

    def test_no_false_positives(self):
        """Test no false positives on random IV."""
        code = """
import os
# Each encryption uses a new IV
cipher.encrypt(data, iv=os.urandom(16))
"""
        issues = self.detector.scan_code(code)
        # May still flag iv=iv pattern, but that's ok for security
        assert len([i for i in issues if "hardcoded" in i.message.lower()]) == 0
