"""Tests for historical scan storage and tracking."""

from pathlib import Path
import sqlite3
import tempfile
import time

import pytest

from pyguard.lib.scan_history import (
    IssueRecord,
    ScanComparison,
    ScanHistoryStorage,
    ScanMetadata,
    ScanStatus,
)


class TestScanMetadata:
    """Test scan metadata."""

    def test_scan_metadata_creation(self):
        """Test creating scan metadata."""
        metadata = ScanMetadata(
            scan_id="scan123",
            timestamp=time.time(),
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=10,
            critical_issues=2,
            high_issues=3,
            medium_issues=3,
            low_issues=2,
            info_issues=0,
        )

        assert metadata.scan_id == "scan123"
        assert metadata.total_issues == 10
        assert metadata.critical_issues == 2

    def test_scan_metadata_to_dict(self):
        """Test converting scan metadata to dict."""
        metadata = ScanMetadata(
            scan_id="scan123",
            timestamp=1234567890.0,
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=10,
            critical_issues=2,
            high_issues=3,
            medium_issues=3,
            low_issues=2,
            info_issues=0,
        )

        result = metadata.to_dict()

        assert result['scan_id'] == "scan123"
        assert result['status'] == "completed"
        assert 'timestamp_iso' in result


class TestIssueRecord:
    """Test issue record."""

    def test_issue_record_creation(self):
        """Test creating issue record."""
        issue = IssueRecord(
            scan_id="scan123",
            issue_id="issue1",
            file_path="/path/to/file.py",
            line_number=42,
            issue_type="sql_injection",
            severity="high",
            message="SQL injection vulnerability",
            cwe_id="CWE-89",
        )

        assert issue.scan_id == "scan123"
        assert issue.line_number == 42
        assert issue.severity == "high"

    def test_issue_fingerprint(self):
        """Test issue fingerprint generation."""
        issue1 = IssueRecord(
            scan_id="scan123",
            issue_id="issue1",
            file_path="/path/to/file.py",
            line_number=42,
            issue_type="sql_injection",
            severity="high",
            message="SQL injection vulnerability",
        )

        issue2 = IssueRecord(
            scan_id="scan456",  # Different scan
            issue_id="issue2",  # Different ID
            file_path="/path/to/file.py",
            line_number=42,
            issue_type="sql_injection",
            severity="high",
            message="SQL injection vulnerability",
        )

        # Same location and type = same fingerprint
        assert issue1.get_fingerprint() == issue2.get_fingerprint()

    def test_issue_fingerprint_different_location(self):
        """Test issue fingerprints differ for different locations."""
        issue1 = IssueRecord(
            scan_id="scan123",
            issue_id="issue1",
            file_path="/path/to/file.py",
            line_number=42,
            issue_type="sql_injection",
            severity="high",
            message="SQL injection vulnerability",
        )

        issue2 = IssueRecord(
            scan_id="scan123",
            issue_id="issue2",
            file_path="/path/to/file.py",
            line_number=43,  # Different line
            issue_type="sql_injection",
            severity="high",
            message="SQL injection vulnerability",
        )

        assert issue1.get_fingerprint() != issue2.get_fingerprint()


class TestScanHistoryStorage:
    """Test scan history storage."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "test.db"

    @pytest.fixture
    def storage(self, temp_db):
        """Create storage instance."""
        return ScanHistoryStorage(db_path=temp_db)

    def test_init_database(self, temp_db):
        """Test database initialization."""
        storage = ScanHistoryStorage(db_path=temp_db)

        assert temp_db.exists()

        # Check tables exist
        with sqlite3.connect(temp_db) as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = {row[0] for row in cursor.fetchall()}

            assert 'scans' in tables
            assert 'issues' in tables

    def test_store_and_retrieve_scan(self, storage):
        """Test storing and retrieving a scan."""
        metadata = ScanMetadata(
            scan_id="scan123",
            timestamp=time.time(),
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=10,
            critical_issues=2,
            high_issues=3,
            medium_issues=3,
            low_issues=2,
            info_issues=0,
        )

        issues = [
            IssueRecord(
                scan_id="scan123",
                issue_id="issue1",
                file_path="/path/to/file.py",
                line_number=42,
                issue_type="sql_injection",
                severity="high",
                message="SQL injection vulnerability",
            )
        ]

        storage.store_scan(metadata, issues)

        # Retrieve scan
        retrieved = storage.get_scan("scan123")

        assert retrieved is not None
        assert retrieved.scan_id == "scan123"
        assert retrieved.total_issues == 10
        assert retrieved.critical_issues == 2

    def test_store_and_retrieve_issues(self, storage):
        """Test storing and retrieving issues."""
        metadata = ScanMetadata(
            scan_id="scan123",
            timestamp=time.time(),
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=2,
            critical_issues=1,
            high_issues=1,
            medium_issues=0,
            low_issues=0,
            info_issues=0,
        )

        issues = [
            IssueRecord(
                scan_id="scan123",
                issue_id="issue1",
                file_path="/path/to/file.py",
                line_number=42,
                issue_type="sql_injection",
                severity="high",
                message="SQL injection vulnerability",
            ),
            IssueRecord(
                scan_id="scan123",
                issue_id="issue2",
                file_path="/path/to/other.py",
                line_number=100,
                issue_type="xss",
                severity="critical",
                message="XSS vulnerability",
            ),
        ]

        storage.store_scan(metadata, issues)

        # Retrieve issues
        retrieved_issues = storage.get_scan_issues("scan123")

        assert len(retrieved_issues) == 2
        assert retrieved_issues[0].issue_id == "issue1"
        assert retrieved_issues[1].issue_id == "issue2"

    def test_list_scans(self, storage):
        """Test listing scans."""
        # Store multiple scans
        for i in range(5):
            metadata = ScanMetadata(
                scan_id=f"scan{i}",
                timestamp=time.time() + i,
                status=ScanStatus.COMPLETED,
                target_path="/path/to/code",
                pyguard_version="0.8.0",
                duration_seconds=5.5,
                files_scanned=100,
                total_issues=10,
                critical_issues=2,
                high_issues=3,
                medium_issues=3,
                low_issues=2,
                info_issues=0,
            )
            storage.store_scan(metadata, [])

        # List all scans
        scans = storage.list_scans()

        assert len(scans) == 5
        # Should be ordered by timestamp (newest first)
        assert scans[0].scan_id == "scan4"
        assert scans[-1].scan_id == "scan0"

    def test_list_scans_with_filter(self, storage):
        """Test listing scans with filters."""
        # Store scans for different targets
        for i in range(3):
            metadata = ScanMetadata(
                scan_id=f"scan_a{i}",
                timestamp=time.time() + i,
                status=ScanStatus.COMPLETED,
                target_path="/path/to/code_a",
                pyguard_version="0.8.0",
                duration_seconds=5.5,
                files_scanned=100,
                total_issues=10,
                critical_issues=2,
                high_issues=3,
                medium_issues=3,
                low_issues=2,
                info_issues=0,
            )
            storage.store_scan(metadata, [])

        for i in range(2):
            metadata = ScanMetadata(
                scan_id=f"scan_b{i}",
                timestamp=time.time() + i,
                status=ScanStatus.COMPLETED,
                target_path="/path/to/code_b",
                pyguard_version="0.8.0",
                duration_seconds=5.5,
                files_scanned=100,
                total_issues=10,
                critical_issues=2,
                high_issues=3,
                medium_issues=3,
                low_issues=2,
                info_issues=0,
            )
            storage.store_scan(metadata, [])

        # Filter by target
        scans = storage.list_scans(target_path="/path/to/code_a")

        assert len(scans) == 3
        assert all(scan.target_path == "/path/to/code_a" for scan in scans)

    def test_compare_scans_new_issues(self, storage):
        """Test comparing scans with new issues."""
        # Baseline scan
        baseline_metadata = ScanMetadata(
            scan_id="baseline",
            timestamp=time.time(),
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=1,
            critical_issues=0,
            high_issues=1,
            medium_issues=0,
            low_issues=0,
            info_issues=0,
        )

        baseline_issues = [
            IssueRecord(
                scan_id="baseline",
                issue_id="issue1",
                file_path="/path/to/file.py",
                line_number=42,
                issue_type="sql_injection",
                severity="high",
                message="SQL injection vulnerability",
            ),
        ]

        storage.store_scan(baseline_metadata, baseline_issues)

        # Current scan with new issue
        current_metadata = ScanMetadata(
            scan_id="current",
            timestamp=time.time() + 10,
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=2,
            critical_issues=0,
            high_issues=2,
            medium_issues=0,
            low_issues=0,
            info_issues=0,
        )

        current_issues = [
            IssueRecord(
                scan_id="current",
                issue_id="issue1",
                file_path="/path/to/file.py",
                line_number=42,
                issue_type="sql_injection",
                severity="high",
                message="SQL injection vulnerability",
            ),
            IssueRecord(
                scan_id="current",
                issue_id="issue2",
                file_path="/path/to/new_file.py",
                line_number=10,
                issue_type="xss",
                severity="high",
                message="XSS vulnerability",
            ),
        ]

        storage.store_scan(current_metadata, current_issues)

        # Compare
        comparison = storage.compare_scans("baseline", "current")

        assert len(comparison.new_issues) == 1
        assert comparison.new_issues[0].issue_id == "issue2"
        assert len(comparison.fixed_issues) == 0
        assert len(comparison.unchanged_issues) == 1
        assert comparison.is_regression

    def test_compare_scans_fixed_issues(self, storage):
        """Test comparing scans with fixed issues."""
        # Baseline scan with 2 issues
        baseline_metadata = ScanMetadata(
            scan_id="baseline",
            timestamp=time.time(),
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=2,
            critical_issues=0,
            high_issues=2,
            medium_issues=0,
            low_issues=0,
            info_issues=0,
        )

        baseline_issues = [
            IssueRecord(
                scan_id="baseline",
                issue_id="issue1",
                file_path="/path/to/file.py",
                line_number=42,
                issue_type="sql_injection",
                severity="high",
                message="SQL injection vulnerability",
            ),
            IssueRecord(
                scan_id="baseline",
                issue_id="issue2",
                file_path="/path/to/file.py",
                line_number=50,
                issue_type="xss",
                severity="high",
                message="XSS vulnerability",
            ),
        ]

        storage.store_scan(baseline_metadata, baseline_issues)

        # Current scan with 1 fixed issue
        current_metadata = ScanMetadata(
            scan_id="current",
            timestamp=time.time() + 10,
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=1,
            critical_issues=0,
            high_issues=1,
            medium_issues=0,
            low_issues=0,
            info_issues=0,
        )

        current_issues = [
            IssueRecord(
                scan_id="current",
                issue_id="issue1",
                file_path="/path/to/file.py",
                line_number=42,
                issue_type="sql_injection",
                severity="high",
                message="SQL injection vulnerability",
            ),
        ]

        storage.store_scan(current_metadata, current_issues)

        # Compare
        comparison = storage.compare_scans("baseline", "current")

        assert len(comparison.new_issues) == 0
        assert len(comparison.fixed_issues) == 1
        assert comparison.fixed_issues[0].issue_id == "issue2"
        assert len(comparison.unchanged_issues) == 1
        assert comparison.is_improvement
        assert not comparison.is_regression

    def test_get_trend_data(self, storage):
        """Test getting trend data."""
        # Store multiple scans over time
        for i in range(5):
            metadata = ScanMetadata(
                scan_id=f"scan{i}",
                timestamp=time.time() - (4 - i) * 86400,  # 1 day apart
                status=ScanStatus.COMPLETED,
                target_path="/path/to/code",
                pyguard_version="0.8.0",
                duration_seconds=5.5,
                files_scanned=100,
                total_issues=10 - i,  # Decreasing issues
                critical_issues=2 - (i // 2),
                high_issues=3,
                medium_issues=3,
                low_issues=2,
                info_issues=0,
            )
            storage.store_scan(metadata, [])

        # Get trend data
        trend = storage.get_trend_data("/path/to/code", days=30)

        assert trend['scan_count'] == 5
        assert trend['current_total_issues'] == 6  # Latest scan
        assert trend['baseline_total_issues'] == 10  # Oldest scan
        assert trend['total_issues_change'] == -4  # Improvement
        assert len(trend['time_series']) == 5

    def test_delete_old_scans(self, storage):
        """Test deleting old scans."""
        # Store scans with different ages
        old_time = time.time() - (400 * 86400)  # 400 days ago
        recent_time = time.time() - (10 * 86400)  # 10 days ago

        # Old scan
        old_metadata = ScanMetadata(
            scan_id="old_scan",
            timestamp=old_time,
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=10,
            critical_issues=2,
            high_issues=3,
            medium_issues=3,
            low_issues=2,
            info_issues=0,
        )
        storage.store_scan(old_metadata, [])

        # Recent scan
        recent_metadata = ScanMetadata(
            scan_id="recent_scan",
            timestamp=recent_time,
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=5,
            critical_issues=1,
            high_issues=2,
            medium_issues=1,
            low_issues=1,
            info_issues=0,
        )
        storage.store_scan(recent_metadata, [])

        # Delete old scans (older than 365 days)
        deleted = storage.delete_old_scans(days=365)

        assert deleted == 1

        # Verify recent scan still exists
        recent = storage.get_scan("recent_scan")
        assert recent is not None

        # Verify old scan deleted
        old = storage.get_scan("old_scan")
        assert old is None

    def test_scan_with_git_metadata(self, storage):
        """Test storing scan with git metadata."""
        metadata = ScanMetadata(
            scan_id="scan123",
            timestamp=time.time(),
            status=ScanStatus.COMPLETED,
            target_path="/path/to/code",
            pyguard_version="0.8.0",
            duration_seconds=5.5,
            files_scanned=100,
            total_issues=10,
            critical_issues=2,
            high_issues=3,
            medium_issues=3,
            low_issues=2,
            info_issues=0,
            git_commit="abc123def456",
            git_branch="main",
            ci_build_id="build-789",
        )

        storage.store_scan(metadata, [])

        # Retrieve and verify
        retrieved = storage.get_scan("scan123")

        assert retrieved.git_commit == "abc123def456"
        assert retrieved.git_branch == "main"
        assert retrieved.ci_build_id == "build-789"


class TestScanComparison:
    """Test scan comparison."""

    def test_is_regression(self):
        """Test regression detection."""
        comparison = ScanComparison(
            baseline_scan_id="baseline",
            current_scan_id="current",
            baseline_timestamp=time.time(),
            current_timestamp=time.time() + 10,
            new_issues=[
                IssueRecord(
                    scan_id="current",
                    issue_id="issue1",
                    file_path="/path/to/file.py",
                    line_number=42,
                    issue_type="sql_injection",
                    severity="high",
                    message="SQL injection vulnerability",
                )
            ],
        )

        assert comparison.is_regression
        assert not comparison.is_improvement

    def test_is_improvement(self):
        """Test improvement detection."""
        comparison = ScanComparison(
            baseline_scan_id="baseline",
            current_scan_id="current",
            baseline_timestamp=time.time(),
            current_timestamp=time.time() + 10,
            fixed_issues=[
                IssueRecord(
                    scan_id="baseline",
                    issue_id="issue1",
                    file_path="/path/to/file.py",
                    line_number=42,
                    issue_type="sql_injection",
                    severity="high",
                    message="SQL injection vulnerability",
                )
            ],
        )

        assert comparison.is_improvement
        assert not comparison.is_regression

    def test_comparison_to_dict(self):
        """Test converting comparison to dict."""
        comparison = ScanComparison(
            baseline_scan_id="baseline",
            current_scan_id="current",
            baseline_timestamp=1234567890.0,
            current_timestamp=1234567900.0,
            new_issues=[],
            fixed_issues=[],
            severity_changes={'critical': -1, 'high': 0},
        )

        result = comparison.to_dict()

        assert result['baseline_scan_id'] == "baseline"
        assert result['current_scan_id'] == "current"
        assert 'summary' in result
        assert 'new_issues' in result
        assert 'fixed_issues' in result
        assert 'severity_changes' in result
