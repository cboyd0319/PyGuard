"""
Tests for enhanced security detections.
"""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.enhanced_detections import (
    BackupFileDetector,
    ClickjackingDetector,
    DependencyConfusionDetector,
    MassAssignmentDetector,
    MemoryDisclosureDetector,
)


class TestBackupFileDetector:
    """Test backup file detection."""

    def test_detect_backup_files(self):
        """Test detection of various backup file extensions."""
        detector = BackupFileDetector()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create backup files
            (temp_path / "file.py.bak").touch()
            (temp_path / "data.txt.old").touch()
            (temp_path / "config.json~").touch()
            
            issues = detector.scan_directory(temp_path)
            
            assert len(issues) == 3
            assert all(issue.category == "Backup File Exposure" for issue in issues)
            assert all(issue.severity == "MEDIUM" for issue in issues)
            assert all(issue.cwe_id == "CWE-530" for issue in issues)

    def test_detect_sensitive_files(self):
        """Test detection of sensitive files like .env and keys."""
        detector = BackupFileDetector()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create sensitive files
            (temp_path / ".env").touch()
            (temp_path / "id_rsa").touch()
            (temp_path / "private.key").touch()
            
            issues = detector.scan_directory(temp_path)
            
            assert len(issues) >= 3
            assert all(issue.category == "Sensitive File Exposure" for issue in issues)
            assert all(issue.severity == "HIGH" for issue in issues)

    def test_ignore_common_directories(self):
        """Test that common directories like .git are ignored."""
        detector = BackupFileDetector()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create .git directory with backup file
            git_dir = temp_path / ".git"
            git_dir.mkdir()
            (git_dir / "config.bak").touch()
            
            issues = detector.scan_directory(temp_path)
            
            # Should not detect files in .git
            assert len(issues) == 0


class TestMassAssignmentDetector:
    """Test mass assignment vulnerability detection."""

    def test_detect_request_update(self):
        """Test detection of model.update(request.data)."""
        detector = MassAssignmentDetector()
        
        code = """
user.update(request.data)
"""
        
        issues = detector.scan_code(code, "test.py")
        
        assert len(issues) >= 1
        assert any(issue.category == "Mass Assignment" for issue in issues)
        assert any(issue.severity == "HIGH" for issue in issues)
        assert any(issue.cwe_id == "CWE-915" for issue in issues)

    def test_detect_dict_update(self):
        """Test detection of **request.json unpacking."""
        detector = MassAssignmentDetector()
        
        code = """
user.update(**request.json)
"""
        
        issues = detector.scan_code(code, "test.py")
        
        assert len(issues) >= 1
        assert any(issue.category == "Mass Assignment" for issue in issues)

    def test_safe_code_no_issues(self):
        """Test that safe code doesn't trigger false positives."""
        detector = MassAssignmentDetector()
        
        code = """
user.update({'name': validated_name, 'email': validated_email})
"""
        
        issues = detector.scan_code(code, "test.py")
        
        # Should not detect this as vulnerable
        assert len([i for i in issues if i.category == "Mass Assignment"]) == 0


class TestClickjackingDetector:
    """Test clickjacking protection detection."""

    def test_detect_flask_without_protection(self):
        """Test detection of Flask app without X-Frame-Options."""
        detector = ClickjackingDetector()
        
        code = """
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello World'
"""
        
        issues = detector.scan_code(code, "app.py")
        
        assert len(issues) >= 1
        assert any(issue.category == "Missing Clickjacking Protection" for issue in issues)
        assert any(issue.cwe_id == "CWE-1021" for issue in issues)

    def test_flask_with_protection(self):
        """Test that Flask app with protection doesn't trigger."""
        detector = ClickjackingDetector()
        
        code = """
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response
"""
        
        issues = detector.scan_code(code, "app.py")
        
        # Should not detect since protection is present
        assert len([i for i in issues if i.category == "Missing Clickjacking Protection"]) == 0

    def test_django_with_middleware(self):
        """Test Django app with ClickjackingMiddleware."""
        detector = ClickjackingDetector()
        
        code = """
from django.middleware.clickjacking import XFrameOptionsMiddleware

MIDDLEWARE = [
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
"""
        
        issues = detector.scan_code(code, "settings.py")
        
        # Should not detect since middleware is present
        assert len([i for i in issues if i.category == "Missing Clickjacking Protection"]) == 0


class TestDependencyConfusionDetector:
    """Test dependency confusion vulnerability detection."""

    def test_detect_private_package_without_index(self):
        """Test detection of private package without explicit index."""
        detector = DependencyConfusionDetector()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            req_file = temp_path / "requirements.txt"
            
            req_file.write_text("""
requests==2.31.0
internal-api-client==1.0.0
numpy==1.24.0
""")
            
            issues = detector.scan_requirements(req_file)
            
            assert len(issues) >= 1
            assert any(issue.category == "Dependency Confusion Risk" for issue in issues)
            assert any("internal-api-client" in issue.message for issue in issues)

    def test_private_package_with_index(self):
        """Test that private package with index URL doesn't trigger."""
        detector = DependencyConfusionDetector()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            req_file = temp_path / "requirements.txt"
            
            req_file.write_text("""
--index-url https://private.pypi.org/simple/
internal-api-client==1.0.0
""")
            
            issues = detector.scan_requirements(req_file)
            
            # Should not detect since index URL is present
            assert len(issues) == 0

    def test_public_packages_only(self):
        """Test that public packages don't trigger warnings."""
        detector = DependencyConfusionDetector()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            req_file = temp_path / "requirements.txt"
            
            req_file.write_text("""
requests==2.31.0
numpy==1.24.0
flask==2.3.0
""")
            
            issues = detector.scan_requirements(req_file)
            
            # Should not detect any issues with public packages
            assert len(issues) == 0


class TestMemoryDisclosureDetector:
    """Test memory disclosure vulnerability detection."""

    def test_detect_traceback_exposure(self):
        """Test detection of traceback.print_exc()."""
        detector = MemoryDisclosureDetector()
        
        code = """
import traceback

try:
    dangerous_operation()
except Exception:
    traceback.print_exc()
"""
        
        issues = detector.scan_code(code, "test.py")
        
        assert len(issues) >= 1
        assert any(issue.category == "Memory Disclosure" for issue in issues)
        assert any(issue.cwe_id == "CWE-212" for issue in issues)

    def test_detect_locals_exposure(self):
        """Test detection of locals() exposure."""
        detector = MemoryDisclosureDetector()
        
        code = """
def debug_info():
    return str(locals())
"""
        
        issues = detector.scan_code(code, "test.py")
        
        assert len(issues) >= 1
        assert any(issue.category == "Memory Disclosure" for issue in issues)

    def test_detect_vars_exposure(self):
        """Test detection of vars() exposure."""
        detector = MemoryDisclosureDetector()
        
        code = """
def show_object(obj):
    return vars(obj)
"""
        
        issues = detector.scan_code(code, "test.py")
        
        assert len(issues) >= 1
        assert any(issue.category == "Memory Disclosure" for issue in issues)

    def test_safe_code_no_issues(self):
        """Test that safe code doesn't trigger false positives."""
        detector = MemoryDisclosureDetector()
        
        code = """
def safe_function():
    data = {'key': 'value'}
    return data
"""
        
        issues = detector.scan_code(code, "test.py")
        
        # Should not detect any issues
        assert len(issues) == 0
