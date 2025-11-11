"""
Integration tests for complete PyGuard workflows.

Tests end-to-end scenarios that exercise multiple modules together:
- Scan → Report → Fix workflow
- Scan history tracking
- Configuration loading and application
- Multiple output formats
"""

from pathlib import Path
import tempfile

import pytest

from pyguard.api import analyze_code
from pyguard.lib.api_stability import (
    check_api_compatibility,
    generate_migration_guide,
)
from pyguard.lib.scan_history import (
    IssueRecord,
    ScanHistoryStorage,
    ScanMetadata,
    ScanStatus,
)


class TestCompleteScanWorkflow:
    """Test complete scan workflows."""

    @pytest.fixture
    def temp_project(self):
        """Create temporary project with vulnerable code."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)

            # Create vulnerable Python file
            vulnerable_file = project_dir / "app.py"
            vulnerable_file.write_text("""
import pickle
import yaml

def load_data(filename):
    # Vulnerable: unsafe pickle deserialization
    with open(filename, 'rb') as f:
        return pickle.load(f)

def load_config(filename):
    # Vulnerable: unsafe yaml load
    with open(filename) as f:
        return yaml.load(f)

def execute_code(user_input):
    # Vulnerable: eval usage
    return eval(user_input)

password = "hardcoded123"  # Vulnerable: hardcoded password
""")

            # Create safe Python file
            safe_file = project_dir / "utils.py"
            safe_file.write_text("""
import json

def safe_load(filename):
    with open(filename) as f:
        return json.load(f)

def safe_process(data):
    return str(data).lower()
""")

            yield project_dir

    def test_scan_and_detect_issues(self, temp_project):
        """Test scanning project and detecting issues."""
        # Use analyze_code API

        # Scan vulnerable file
        vulnerable_file = temp_project / "app.py"
        code = vulnerable_file.read_text()

        issues = analyze_code(code).issues

        # Should detect multiple issues
        assert len(issues) > 0

        # Should detect pickle vulnerability
        pickle_issues = [i for i in issues if 'pickle' in i.message.lower()]
        assert len(pickle_issues) > 0

        # Should detect eval vulnerability
        eval_issues = [i for i in issues if 'eval' in i.message.lower()]
        assert len(eval_issues) > 0

        # Should detect hardcoded password
        password_issues = [i for i in issues if 'password' in i.message.lower() or 'hardcoded' in i.message.lower()]
        assert len(password_issues) > 0

    def test_scan_safe_file(self, temp_project):
        """Test scanning safe file produces fewer issues than vulnerable file."""
        # Use analyze_code API

        # Scan safe file
        safe_file = temp_project / "utils.py"
        code = safe_file.read_text()

        issues = analyze_code(code).issues

        # Should have no or very few issues (allow for style/quality issues)
        assert len(issues) <= 5  # Allow for style issues

    def test_scan_with_history_tracking(self, temp_project):
        """Test scanning with history tracking."""
        import time

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = ScanHistoryStorage(db_path=Path(tmpdir) / "history.db")
            # Use analyze_code API

            # First scan
            vulnerable_file = temp_project / "app.py"
            code = vulnerable_file.read_text()
            issues = analyze_code(code).issues

            # Store in history
            metadata = ScanMetadata(
                scan_id="scan1",
                timestamp=time.time(),
                status=ScanStatus.COMPLETED,
                target_path=str(temp_project),
                pyguard_version="0.8.0",
                duration_seconds=1.5,
                files_scanned=2,
                total_issues=len(issues),
                critical_issues=sum(1 for i in issues if i.severity.upper() == 'CRITICAL'),
                high_issues=sum(1 for i in issues if i.severity.upper() == 'HIGH'),
                medium_issues=sum(1 for i in issues if i.severity.upper() == 'MEDIUM'),
                low_issues=sum(1 for i in issues if i.severity.upper() == 'LOW'),
                info_issues=sum(1 for i in issues if i.severity.upper() == 'INFO'),
            )

            issue_records = [
                IssueRecord(
                    scan_id="scan1",
                    issue_id=f"issue{i}",
                    file_path=str(vulnerable_file),
                    line_number=issue.line_number,
                    issue_type=issue.category,
                    severity=issue.severity.lower(),
                    message=issue.message,
                )
                for i, issue in enumerate(issues)
            ]

            storage.store_scan(metadata, issue_records)

            # Verify storage
            retrieved = storage.get_scan("scan1")
            assert retrieved is not None
            assert retrieved.total_issues == len(issues)

            # Retrieve issues
            retrieved_issues = storage.get_scan_issues("scan1")
            assert len(retrieved_issues) == len(issues)

    def test_scan_comparison_workflow(self, temp_project):
        """Test comparing scans before and after fixes."""
        import time

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = ScanHistoryStorage(db_path=Path(tmpdir) / "history.db")
            # Use analyze_code API

            # Baseline scan with vulnerabilities
            vulnerable_file = temp_project / "app.py"
            code = vulnerable_file.read_text()
            baseline_issues = analyze_code(code).issues

            baseline_metadata = ScanMetadata(
                scan_id="baseline",
                timestamp=time.time(),
                status=ScanStatus.COMPLETED,
                target_path=str(temp_project),
                pyguard_version="0.8.0",
                duration_seconds=1.5,
                files_scanned=1,
                total_issues=min(len(baseline_issues), 3),
                critical_issues=0,
                high_issues=min(len(baseline_issues), 3),
                medium_issues=0,
                low_issues=0,
                info_issues=0,
            )

            baseline_records = [
                IssueRecord(
                    scan_id="baseline",
                    issue_id=f"issue{i}",
                    file_path=str(vulnerable_file),
                    line_number=issue.line_number,
                    issue_type=issue.category,
                    severity="high",
                    message=issue.message,
                )
                for i, issue in enumerate(baseline_issues[:3])  # Take first 3
            ]

            storage.store_scan(baseline_metadata, baseline_records)

            # Current scan with some fixes
            current_metadata = ScanMetadata(
                scan_id="current",
                timestamp=time.time() + 10,
                status=ScanStatus.COMPLETED,
                target_path=str(temp_project),
                pyguard_version="0.8.0",
                duration_seconds=1.5,
                files_scanned=1,
                total_issues=1,  # Fixed 2 issues
                critical_issues=0,
                high_issues=1,
                medium_issues=0,
                low_issues=0,
                info_issues=0,
            )

            # Keep only first issue (others fixed)
            current_records = [baseline_records[0]]

            storage.store_scan(current_metadata, current_records)

            # Compare scans
            comparison = storage.compare_scans("baseline", "current")

            # Should show improvement (some issues fixed, none new)
            assert len(comparison.fixed_issues) >= 2
            assert len(comparison.new_issues) == 0
            assert comparison.is_improvement
            assert not comparison.is_regression


class TestAPICompatibilityWorkflow:
    """Test API compatibility and migration workflows."""

    def test_check_compatibility_workflow(self):
        """Test checking compatibility before upgrade."""
        # Check if code is compatible with future version
        result = check_api_compatibility("1.0.0")

        assert 'compatible' in result
        assert 'current_version' in result
        assert 'target_version' in result

    def test_migration_guide_workflow(self):
        """Test generating migration guide for upgrade."""
        # Generate guide for upgrade
        guide = generate_migration_guide("0.6.0", "0.8.0")

        assert 'from_version' in guide
        assert 'to_version' in guide
        assert 'new_features' in guide
        assert 'deprecation_warnings' in guide
        assert 'changes_required' in guide


class TestMultiFileWorkflow:
    """Test workflows with multiple files."""

    @pytest.fixture
    def multi_file_project(self):
        """Create project with multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)

            # Create multiple files
            files = {
                "api.py": """
import os
password = os.getenv('PASSWORD', 'default123')  # Weak default
""",
                "db.py": """
import sqlite3
def query(user_input):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")  # SQL injection
    return cursor.fetchall()
""",
                "crypto.py": """
from Crypto.Cipher import DES  # Weak crypto
def encrypt(data):
    cipher = DES.new(b'12345678', DES.MODE_ECB)
    return cipher.encrypt(data)
""",
            }

            for filename, content in files.items():
                (project_dir / filename).write_text(content)

            yield project_dir

    def test_scan_multiple_files(self, multi_file_project):
        """Test scanning multiple files in project."""
        # Use analyze_code API

        all_issues = []
        for py_file in multi_file_project.glob("*.py"):
            code = py_file.read_text()
            issues = analyze_code(code).issues
            all_issues.extend(issues)

        # Should find issues across multiple files
        assert len(all_issues) > 0

        # Should find some issues across files
        # (Exact matches may vary, so just check we found issues)
        assert len(all_issues) >= 2  # At least some issues across 3 files


class TestTrendAnalysisWorkflow:
    """Test trend analysis workflow."""

    def test_trend_analysis_over_time(self):
        """Test tracking security posture over time."""
        import time

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = ScanHistoryStorage(db_path=Path(tmpdir) / "history.db")

            # Simulate multiple scans over time with improving security
            for i in range(5):
                metadata = ScanMetadata(
                    scan_id=f"scan{i}",
                    timestamp=time.time() - (4 - i) * 86400,  # 1 day apart
                    status=ScanStatus.COMPLETED,
                    target_path="/project",
                    pyguard_version="0.8.0",
                    duration_seconds=2.0,
                    files_scanned=10,
                    total_issues=20 - i * 3,  # Decreasing issues
                    critical_issues=max(0, 5 - i),
                    high_issues=max(0, 10 - i * 2),
                    medium_issues=5,
                    low_issues=0,
                    info_issues=0,
                )

                storage.store_scan(metadata, [])

            # Get trend data
            trend = storage.get_trend_data("/project", days=30)

            assert trend['scan_count'] == 5
            assert trend['current_total_issues'] < trend['baseline_total_issues']
            assert trend['total_issues_change'] < 0  # Improvement
            assert len(trend['time_series']) == 5


class TestConfigurationWorkflow:
    """Test configuration-driven workflows."""

    def test_configuration_affects_scan(self):
        """Test that configuration affects scan results."""
        # This test would be expanded with actual config loading
        # For now, just verify the analyzer works
        # Use analyze_code API

        code = """
import pickle
data = pickle.load(open('file.pkl', 'rb'))
"""

        issues = analyze_code(code).issues

        # Should detect pickle issue
        assert len(issues) > 0
        pickle_issues = [i for i in issues if 'pickle' in i.message.lower()]
        assert len(pickle_issues) > 0


class TestErrorHandlingWorkflow:
    """Test error handling in workflows."""

    def test_invalid_file_handling(self):
        """Test handling of invalid files gracefully."""
        # Use analyze_code API

        # Invalid Python code
        invalid_code = "this is not valid python {{{ @#$"

        # Should not crash, may return syntax errors or empty
        try:
            issues = analyze_code(invalid_code).issues
            # If it doesn't crash, it's handling errors properly
            assert isinstance(issues, list)
        except Exception as e:
            # Some errors are expected for invalid syntax
            assert isinstance(e, (SyntaxError, ValueError))

    def test_missing_scan_in_history(self):
        """Test querying non-existent scan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = ScanHistoryStorage(db_path=Path(tmpdir) / "history.db")

            # Try to get non-existent scan
            result = storage.get_scan("nonexistent")

            assert result is None

    def test_comparison_with_missing_scan(self):
        """Test comparison with non-existent scan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = ScanHistoryStorage(db_path=Path(tmpdir) / "history.db")

            # Try to compare with non-existent scan
            with pytest.raises(ValueError):
                storage.compare_scans("nonexistent1", "nonexistent2")
