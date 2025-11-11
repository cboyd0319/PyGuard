"""
Tests for audit trail logging.

Tests audit log creation, integrity verification, querying,
and compliance reporting capabilities.
"""

import json
import time

import pytest

from pyguard.lib.audit_logger import (
    AuditEntry,
    AuditEventType,
    AuditLogger,
    AuditSeverity,
    audit_auth_attempt,
    audit_config_changed,
    audit_scan_completed,
    audit_scan_started,
)


class TestAuditEventType:
    """Test audit event type enum."""

    def test_scan_events(self):
        """Test scan event types."""
        assert AuditEventType.SCAN_STARTED.value == "scan.started"
        assert AuditEventType.SCAN_COMPLETED.value == "scan.completed"
        assert AuditEventType.SCAN_FAILED.value == "scan.failed"

    def test_auth_events(self):
        """Test authentication event types."""
        assert AuditEventType.AUTH_SUCCESS.value == "auth.success"
        assert AuditEventType.AUTH_FAILED.value == "auth.failed"

    def test_config_events(self):
        """Test configuration event types."""
        assert AuditEventType.CONFIG_CHANGED.value == "config.changed"
        assert AuditEventType.RULE_ENABLED.value == "rule.enabled"


class TestAuditSeverity:
    """Test audit severity enum."""

    def test_severity_levels(self):
        """Test all severity levels."""
        assert AuditSeverity.DEBUG.value == "debug"
        assert AuditSeverity.INFO.value == "info"
        assert AuditSeverity.WARNING.value == "warning"
        assert AuditSeverity.ERROR.value == "error"
        assert AuditSeverity.CRITICAL.value == "critical"


class TestAuditEntry:
    """Test audit entry data structure."""

    def test_basic_entry_creation(self):
        """Test creating a basic audit entry."""
        entry = AuditEntry(
            timestamp=time.time(),
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.INFO,
            actor="test_user",
            action="Started scan",
        )

        assert entry.event_type == AuditEventType.SCAN_STARTED
        assert entry.severity == AuditSeverity.INFO
        assert entry.actor == "test_user"
        assert entry.result == "success"

    def test_entry_with_details(self):
        """Test entry with detailed information."""
        details = {
            "scan_id": "scan-123",
            "target": "/path/to/code",
            "files_scanned": 50,
        }

        entry = AuditEntry(
            timestamp=time.time(),
            event_type=AuditEventType.SCAN_COMPLETED,
            severity=AuditSeverity.INFO,
            actor="system",
            action="Completed scan",
            resource="/path/to/code",
            resource_type="directory",
            details=details,
        )

        assert entry.details == details
        assert entry.resource == "/path/to/code"
        assert entry.resource_type == "directory"

    def test_entry_compute_hash(self):
        """Test computing entry hash."""
        entry = AuditEntry(
            timestamp=1234567890.0,
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.INFO,
            actor="test_user",
            action="Test action",
        )

        hash1 = entry.compute_hash(include_previous=False)
        hash2 = entry.compute_hash(include_previous=False)

        # Same entry should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex string

    def test_entry_hash_with_previous(self):
        """Test computing hash with previous hash."""
        entry = AuditEntry(
            timestamp=time.time(),
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.INFO,
            actor="test_user",
            action="Test",
            previous_hash="abc123",
        )

        hash_with_prev = entry.compute_hash(include_previous=True)
        hash_without_prev = entry.compute_hash(include_previous=False)

        # Hashes should be different
        assert hash_with_prev != hash_without_prev

    def test_entry_to_dict(self):
        """Test converting entry to dictionary."""
        entry = AuditEntry(
            timestamp=1234567890.0,
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.INFO,
            actor="test_user",
            action="Test action",
            resource="/path/to/file",
        )

        data = entry.to_dict()

        assert data["timestamp"] == 1234567890.0
        assert data["event_type"] == "scan.started"
        assert data["severity"] == "info"
        assert data["actor"] == "test_user"
        assert data["resource"] == "/path/to/file"
        assert "timestamp_iso" in data

    def test_entry_to_json(self):
        """Test converting entry to JSON."""
        entry = AuditEntry(
            timestamp=time.time(),
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.INFO,
            actor="test_user",
            action="Test",
        )

        json_str = entry.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["event_type"] == "scan.started"
        assert parsed["actor"] == "test_user"

    def test_entry_to_cef(self):
        """Test converting entry to Common Event Format."""
        entry = AuditEntry(
            timestamp=time.time(),
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.WARNING,
            actor="test_user",
            action="Started scan",
            resource="/path/to/code",
            client_ip="192.168.1.100",
        )

        cef = entry.to_cef()

        # Check CEF format
        assert cef.startswith("CEF:0|PyGuard|Security Scanner|")
        assert "scan.started" in cef
        assert "Started scan" in cef
        assert "suser=test_user" in cef
        assert "src=192.168.1.100" in cef

    def test_entry_cef_severity_mapping(self):
        """Test CEF severity mapping."""
        # Critical should map to 10
        entry_critical = AuditEntry(
            timestamp=time.time(),
            event_type=AuditEventType.CRITICAL_ISSUE,
            severity=AuditSeverity.CRITICAL,
            actor="system",
            action="Critical issue",
        )
        cef = entry_critical.to_cef()
        assert "|10|" in cef

        # Info should map to 3
        entry_info = AuditEntry(
            timestamp=time.time(),
            event_type=AuditEventType.SCAN_STARTED,
            severity=AuditSeverity.INFO,
            actor="system",
            action="Info event",
        )
        cef = entry_info.to_cef()
        assert "|3|" in cef


class TestAuditLogger:
    """Test audit logger functionality."""

    @pytest.fixture
    def temp_log_file(self, tmp_path):
        """Create temporary log file path."""
        return tmp_path / "test_audit.jsonl"

    @pytest.fixture
    def logger(self, temp_log_file):
        """Create test audit logger."""
        return AuditLogger(
            log_file=temp_log_file,
            format="json",
            enable_integrity=True,
        )

    def test_logger_initialization(self, logger, temp_log_file):
        """Test audit logger initialization."""
        assert logger.log_file == temp_log_file
        assert logger.format == "json"
        assert logger.enable_integrity is True

    def test_log_basic_event(self, logger):
        """Test logging a basic event."""
        entry = logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="test_user",
            action="Started security scan",
        )

        assert entry.event_type == AuditEventType.SCAN_STARTED
        assert entry.actor == "test_user"
        assert entry.severity == AuditSeverity.INFO
        assert entry.entry_hash is not None

    def test_log_creates_file(self, logger, temp_log_file):
        """Test that logging creates log file."""
        assert not temp_log_file.exists()

        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="test",
            action="Test",
        )

        assert temp_log_file.exists()

    def test_log_with_details(self, logger):
        """Test logging with detailed information."""
        details = {
            "scan_id": "scan-456",
            "files": 100,
            "issues": 5,
        }

        entry = logger.log(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="system",
            action="Completed scan",
            resource="/path/to/code",
            details=details,
        )

        assert entry.details == details
        assert entry.resource == "/path/to/code"

    def test_log_with_severity(self, logger):
        """Test logging with different severity levels."""
        entry = logger.log(
            event_type=AuditEventType.ERROR_OCCURRED,
            actor="system",
            action="Error occurred",
            severity=AuditSeverity.ERROR,
        )

        assert entry.severity == AuditSeverity.ERROR

    def test_log_chain_integrity(self, logger):
        """Test hash chain integrity across multiple entries."""
        # Log multiple entries
        entry1 = logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="user1",
            action="First scan",
        )

        entry2 = logger.log(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="user1",
            action="First scan complete",
        )

        entry3 = logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="user2",
            action="Second scan",
        )

        # Check hash chain
        assert entry1.previous_hash is None
        assert entry2.previous_hash == entry1.entry_hash
        assert entry3.previous_hash == entry2.entry_hash

    def test_verify_integrity_valid(self, logger, temp_log_file):
        """Test integrity verification of valid log."""
        # Create some log entries
        for i in range(5):
            logger.log(
                event_type=AuditEventType.SCAN_STARTED,
                actor=f"user{i}",
                action=f"Scan {i}",
            )

        # Verify integrity
        result = logger.verify_integrity()

        assert result["verified"] is True
        assert result["entries_checked"] == 5
        assert "message" in result

    def test_verify_integrity_tampering_detected(self, logger, temp_log_file):
        """Test integrity verification detects tampering."""
        # Create log entries
        for i in range(3):
            logger.log(
                event_type=AuditEventType.SCAN_STARTED,
                actor=f"user{i}",
                action=f"Scan {i}",
            )

        # Manually tamper with log file
        with open(temp_log_file) as f:
            lines = f.readlines()

        # Modify second entry
        if len(lines) > 1:
            entry = json.loads(lines[1])
            entry["actor"] = "TAMPERED"
            lines[1] = json.dumps(entry) + "\n"

            with open(temp_log_file, "w") as f:
                f.writelines(lines)

        # Verify integrity - should detect tampering
        result = logger.verify_integrity()

        assert result["verified"] is False
        assert "tampering_detected" in result
        assert result["tampering_detected"] > 0

    def test_query_all_entries(self, logger):
        """Test querying all entries."""
        # Create some entries
        for i in range(5):
            logger.log(
                event_type=AuditEventType.SCAN_STARTED,
                actor=f"user{i}",
                action=f"Scan {i}",
            )

        results = logger.query()

        assert len(results) == 5

    def test_query_by_event_type(self, logger):
        """Test querying by event type."""
        # Mix of event types
        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="user1",
            action="Start",
        )
        logger.log(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="user1",
            action="Complete",
        )
        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="user2",
            action="Start",
        )

        # Query only SCAN_STARTED
        results = logger.query(
            event_types=[AuditEventType.SCAN_STARTED]
        )

        assert len(results) == 2
        assert all(r["event_type"] == "scan.started" for r in results)

    def test_query_by_actor(self, logger):
        """Test querying by actor."""
        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="alice",
            action="Scan",
        )
        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="bob",
            action="Scan",
        )
        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="alice",
            action="Another scan",
        )

        results = logger.query(actor="alice")

        assert len(results) == 2
        assert all(r["actor"] == "alice" for r in results)

    def test_query_by_time_range(self, logger):
        """Test querying by time range."""
        start_time = time.time()

        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="user1",
            action="Scan 1",
        )

        time.sleep(0.1)
        mid_time = time.time()
        time.sleep(0.1)

        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="user2",
            action="Scan 2",
        )

        # Query from mid_time onward
        results = logger.query(start_time=mid_time)

        assert len(results) == 1
        assert results[0]["actor"] == "user2"

    def test_query_with_limit(self, logger):
        """Test querying with result limit."""
        # Create 10 entries
        for i in range(10):
            logger.log(
                event_type=AuditEventType.SCAN_STARTED,
                actor=f"user{i}",
                action=f"Scan {i}",
            )

        # Query with limit of 5
        results = logger.query(limit=5)

        assert len(results) == 5

    def test_generate_compliance_report(self, logger):
        """Test generating compliance report."""
        start_time = time.time()

        # Create various entries
        logger.log(
            event_type=AuditEventType.SCAN_STARTED,
            actor="user1",
            action="Start scan",
        )
        logger.log(
            event_type=AuditEventType.SCAN_COMPLETED,
            actor="user1",
            action="Complete scan",
        )
        logger.log(
            event_type=AuditEventType.AUTH_FAILED,
            actor="user2",
            action="Login failed",
            severity=AuditSeverity.WARNING,
        )

        end_time = time.time()

        report = logger.generate_compliance_report(
            start_time=start_time,
            end_time=end_time,
        )

        assert "report_period" in report
        assert "summary" in report
        assert report["summary"]["total_events"] == 3
        assert "event_type_counts" in report["summary"]
        assert "severity_counts" in report["summary"]
        assert "entries" in report

    def test_log_rotation_by_size(self, logger, temp_log_file):
        """Test log rotation when size limit reached."""
        # Set small rotation size
        logger.rotate_size_mb = 0.001  # Very small for testing

        # Write enough data to trigger rotation
        for i in range(100):
            logger.log(
                event_type=AuditEventType.SCAN_STARTED,
                actor=f"user{i}",
                action=f"Scan {i}" * 100,  # Make entry larger
                details={"data": "x" * 1000},
            )

        # Should have created rotated files
        rotated_files = list(temp_log_file.parent.glob("test_audit.*.jsonl"))
        assert len(rotated_files) > 0


class TestConvenienceFunctions:
    """Test convenience functions for common audit events."""

    @pytest.fixture
    def logger(self, tmp_path):
        """Create test audit logger."""
        return AuditLogger(log_file=tmp_path / "audit.jsonl")

    def test_audit_scan_started(self, logger):
        """Test audit_scan_started convenience function."""
        entry = audit_scan_started(
            audit_logger=logger,
            scan_id="scan-123",
            actor="test_user",
            target="/path/to/code",
        )

        assert entry.event_type == AuditEventType.SCAN_STARTED
        assert entry.actor == "test_user"
        assert entry.details["scan_id"] == "scan-123"

    def test_audit_scan_completed(self, logger):
        """Test audit_scan_completed convenience function."""
        entry = audit_scan_completed(
            audit_logger=logger,
            scan_id="scan-456",
            actor="system",
            issues_found=10,
        )

        assert entry.event_type == AuditEventType.SCAN_COMPLETED
        assert entry.details["issues_found"] == 10

    def test_audit_config_changed(self, logger):
        """Test audit_config_changed convenience function."""
        entry = audit_config_changed(
            audit_logger=logger,
            actor="admin",
            config_key="max_severity",
            old_value="medium",
            new_value="high",
        )

        assert entry.event_type == AuditEventType.CONFIG_CHANGED
        assert entry.severity == AuditSeverity.WARNING
        assert entry.details["config_key"] == "max_severity"
        assert entry.details["old_value"] == "medium"
        assert entry.details["new_value"] == "high"

    def test_audit_auth_attempt_success(self, logger):
        """Test audit_auth_attempt with successful login."""
        entry = audit_auth_attempt(
            audit_logger=logger,
            actor="user123",
            success=True,
            client_ip="192.168.1.100",
        )

        assert entry.event_type == AuditEventType.AUTH_SUCCESS
        assert entry.severity == AuditSeverity.INFO
        assert entry.result == "success"
        assert entry.client_ip == "192.168.1.100"

    def test_audit_auth_attempt_failure(self, logger):
        """Test audit_auth_attempt with failed login."""
        entry = audit_auth_attempt(
            audit_logger=logger,
            actor="hacker",
            success=False,
            client_ip="10.0.0.1",
        )

        assert entry.event_type == AuditEventType.AUTH_FAILED
        assert entry.severity == AuditSeverity.WARNING
        assert entry.result == "failure"


class TestAuditLoggerIntegration:
    """Integration tests for complete audit logging workflows."""

    @pytest.fixture
    def logger(self, tmp_path):
        """Create test audit logger."""
        return AuditLogger(
            log_file=tmp_path / "integration_audit.jsonl",
            enable_integrity=True,
        )

    def test_complete_scan_workflow(self, logger):
        """Test logging complete scan workflow."""
        # Start scan
        scan_id = "scan-integration-001"

        entry1 = audit_scan_started(
            audit_logger=logger,
            scan_id=scan_id,
            actor="ci_system",
            target="/repo/myproject",
        )

        # Complete scan
        entry2 = audit_scan_completed(
            audit_logger=logger,
            scan_id=scan_id,
            actor="ci_system",
            issues_found=5,
            critical_issues=1,
        )

        # Query scan events
        results = logger.query(
            event_types=[
                AuditEventType.SCAN_STARTED,
                AuditEventType.SCAN_COMPLETED,
            ]
        )

        assert len(results) == 2
        assert results[0]["details"]["scan_id"] == scan_id

        # Verify integrity
        verification = logger.verify_integrity()
        assert verification["verified"] is True

    def test_multiple_user_activity(self, logger):
        """Test logging activity from multiple users."""
        users = ["alice", "bob", "charlie"]

        for user in users:
            # Each user performs multiple actions
            audit_scan_started(
                audit_logger=logger,
                scan_id=f"scan-{user}-1",
                actor=user,
                target=f"/home/{user}/code",
            )

            audit_auth_attempt(
                audit_logger=logger,
                actor=user,
                success=True,
            )

        # Query each user's activity
        for user in users:
            results = logger.query(actor=user)
            assert len(results) == 2

        # Generate compliance report
        report = logger.generate_compliance_report(
            start_time=time.time() - 1000,
            end_time=time.time(),
        )

        assert report["summary"]["total_events"] == 6
        assert len(report["summary"]["actor_counts"]) == 3

    def test_tamper_detection_workflow(self, logger, tmp_path):
        """Test tamper detection in real workflow."""
        # Create valid log entries
        for i in range(5):
            logger.log(
                event_type=AuditEventType.SCAN_STARTED,
                actor=f"user{i}",
                action=f"Scan {i}",
            )

        # Verify integrity (should pass)
        result1 = logger.verify_integrity()
        assert result1["verified"] is True

        # Tamper with log
        log_file = tmp_path / "integration_audit.jsonl"
        with open(log_file) as f:
            lines = f.readlines()

        # Modify middle entry
        entry = json.loads(lines[2])
        entry["actor"] = "TAMPERED_ACTOR"
        lines[2] = json.dumps(entry) + "\n"

        with open(log_file, "w") as f:
            f.writelines(lines)

        # Verify integrity (should fail)
        result2 = logger.verify_integrity()
        assert result2["verified"] is False
        assert result2["tampering_detected"] > 0
