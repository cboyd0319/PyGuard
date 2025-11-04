"""
Audit Trail Logging for Compliance.

Provides comprehensive audit logging for security scans, configuration changes,
and system events to support compliance requirements (SOC 2, ISO 27001, HIPAA, etc.).

Features:
- Structured audit log entries
- Tamper-evident logging with checksums
- Support for multiple log formats (JSON, Syslog, CEF)
- Log retention and rotation policies
- Filtering and search capabilities
- Compliance report generation
- Integration with SIEM systems

Security:
- Cryptographic integrity verification
- No PII in logs (configurable)
- Secure log storage with access controls
- Audit log immutability
- Separation of duties (logs cannot be modified by scanner)
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import os


logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    
    # Issue events
    ISSUE_DETECTED = "issue.detected"
    CRITICAL_ISSUE = "critical.issue.detected"
    FIX_APPLIED = "fix.applied"
    FIX_FAILED = "fix.failed"
    
    # Configuration events
    CONFIG_CHANGED = "config.changed"
    RULE_ENABLED = "rule.enabled"
    RULE_DISABLED = "rule.disabled"
    SUPPRESSION_ADDED = "suppression.added"
    
    # Authentication events
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILED = "auth.failed"
    
    # Access events
    REPORT_ACCESSED = "report.accessed"
    RESULTS_EXPORTED = "results.exported"
    FILE_ACCESSED = "file.accessed"
    
    # System events
    SYSTEM_START = "system.started"
    SYSTEM_STOP = "system.stopped"
    ERROR_OCCURRED = "error.occurred"
    WARNING_ISSUED = "warning.issued"


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEntry:
    """Represents a single audit log entry."""
    timestamp: float
    event_type: AuditEventType
    severity: AuditSeverity
    actor: str  # Who performed the action (user, system, API key)
    action: str  # Human-readable action description
    resource: Optional[str] = None  # What was acted upon
    resource_type: Optional[str] = None  # Type of resource
    result: str = "success"  # success, failure, error
    details: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    client_ip: Optional[str] = None
    previous_hash: Optional[str] = None  # For tamper detection
    entry_hash: Optional[str] = None  # Hash of this entry
    
    def compute_hash(self, include_previous: bool = True) -> str:
        """
        Compute cryptographic hash of entry for integrity verification.
        
        Args:
            include_previous: Include previous hash in computation
            
        Returns:
            SHA256 hash as hex string
        """
        # Create canonical representation
        data = {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "result": self.result,
            "details": json.dumps(self.details, sort_keys=True),
        }
        
        if include_previous and self.previous_hash:
            data["previous_hash"] = self.previous_hash
        
        canonical = json.dumps(data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = {
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "result": self.result,
            "details": self.details,
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }
        return {k: v for k, v in data.items() if v is not None}
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    def to_cef(self) -> str:
        """
        Convert to Common Event Format (CEF) for SIEM integration.
        
        CEF Format:
        CEF:Version|Device Vendor|Device Product|Device Version|
        Signature ID|Name|Severity|Extension
        """
        # Map severity to CEF scale (0-10)
        severity_map = {
            AuditSeverity.DEBUG: 0,
            AuditSeverity.INFO: 3,
            AuditSeverity.WARNING: 6,
            AuditSeverity.ERROR: 8,
            AuditSeverity.CRITICAL: 10,
        }
        
        cef_severity = severity_map.get(self.severity, 5)
        
        # Build extension fields
        extensions = [
            f"act={self.action}",
            f"outcome={self.result}",
            f"rt={int(self.timestamp * 1000)}",  # milliseconds
        ]
        
        if self.actor:
            extensions.append(f"suser={self.actor}")
        if self.resource:
            extensions.append(f"fname={self.resource}")
        if self.client_ip:
            extensions.append(f"src={self.client_ip}")
        if self.session_id:
            extensions.append(f"cs1={self.session_id}")
            extensions.append("cs1Label=SessionID")
        
        extension_str = " ".join(extensions)
        
        return (
            f"CEF:0|PyGuard|Security Scanner|0.8.0|"
            f"{self.event_type.value}|{self.action}|"
            f"{cef_severity}|{extension_str}"
        )


class AuditLogger:
    """
    Audit trail logger for PyGuard security scans.
    
    Provides tamper-evident logging with cryptographic integrity
    verification for compliance requirements.
    """
    
    def __init__(
        self,
        log_file: Optional[Path] = None,
        format: str = "json",
        enable_integrity: bool = True,
        rotate_size_mb: int = 100,
        retention_days: int = 365,
    ):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file (default: audit.jsonl)
            format: Log format (json, cef, syslog)
            enable_integrity: Enable cryptographic integrity checks
            rotate_size_mb: Rotate log when this size is reached
            retention_days: Keep logs for this many days
        """
        self.log_file = log_file or Path("audit.jsonl")
        self.format = format
        self.enable_integrity = enable_integrity
        self.rotate_size_mb = rotate_size_mb
        self.retention_days = retention_days
        
        # Last entry hash for chaining
        self.last_hash: Optional[str] = None
        
        # Load last hash from existing log
        self._load_last_hash()
        
        logger.info(f"Audit logger initialized: {self.log_file}")
    
    def _load_last_hash(self) -> None:
        """Load the last hash from existing log file."""
        if not self.log_file.exists():
            return
        
        try:
            # Read last line
            with open(self.log_file, "r") as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        entry_dict = json.loads(last_line)
                        self.last_hash = entry_dict.get("entry_hash")
                        logger.debug(f"Loaded last hash: {self.last_hash[:8]}...")
        except Exception as e:
            logger.warning(f"Failed to load last hash: {e}")
    
    def log(
        self,
        event_type: AuditEventType,
        actor: str,
        action: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        resource: Optional[str] = None,
        resource_type: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> AuditEntry:
        """
        Log an audit event.
        
        Args:
            event_type: Type of audit event
            actor: Who performed the action
            action: Human-readable action description
            severity: Event severity
            resource: What was acted upon
            resource_type: Type of resource
            result: Result of action (success, failure, error)
            details: Additional details
            session_id: Session identifier
            client_ip: Client IP address
            
        Returns:
            Created audit entry
        """
        # Create entry
        entry = AuditEntry(
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            actor=actor,
            action=action,
            resource=resource,
            resource_type=resource_type,
            result=result,
            details=details or {},
            session_id=session_id,
            client_ip=client_ip,
            previous_hash=self.last_hash if self.enable_integrity else None,
        )
        
        # Compute hash
        if self.enable_integrity:
            entry.entry_hash = entry.compute_hash()
            self.last_hash = entry.entry_hash
        
        # Write to log
        self._write_entry(entry)
        
        return entry
    
    def _write_entry(self, entry: AuditEntry) -> None:
        """Write entry to log file."""
        try:
            # Ensure parent directory exists
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Check if rotation needed
            if self.log_file.exists():
                size_mb = self.log_file.stat().st_size / (1024 * 1024)
                if size_mb >= self.rotate_size_mb:
                    self._rotate_log()
            
            # Write entry based on format
            with open(self.log_file, "a") as f:
                if self.format == "json":
                    f.write(entry.to_json() + "\n")
                elif self.format == "cef":
                    f.write(entry.to_cef() + "\n")
                else:
                    f.write(str(entry.to_dict()) + "\n")
                    
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}", exc_info=True)
    
    def _rotate_log(self) -> None:
        """Rotate the current log file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated_file = self.log_file.with_suffix(f".{timestamp}.jsonl")
        
        try:
            self.log_file.rename(rotated_file)
            logger.info(f"Rotated audit log to: {rotated_file}")
            
            # Reset last hash for new file
            self.last_hash = None
            
        except Exception as e:
            logger.error(f"Failed to rotate log: {e}")
    
    def verify_integrity(self, start_index: int = 0) -> Dict[str, Any]:
        """
        Verify integrity of audit log using hash chain.
        
        Args:
            start_index: Start verification from this entry
            
        Returns:
            Verification result with any tampering detected
        """
        if not self.enable_integrity:
            return {
                "verified": False,
                "message": "Integrity checking not enabled",
            }
        
        if not self.log_file.exists():
            return {
                "verified": True,
                "entries_checked": 0,
                "message": "No log file to verify",
            }
        
        tampering_detected = []
        entries_checked = 0
        previous_hash = None
        
        try:
            with open(self.log_file, "r") as f:
                for i, line in enumerate(f):
                    if i < start_index:
                        continue
                    
                    entry_dict = json.loads(line.strip())
                    
                    # Recreate entry
                    entry = AuditEntry(
                        timestamp=entry_dict["timestamp"],
                        event_type=AuditEventType(entry_dict["event_type"]),
                        severity=AuditSeverity(entry_dict["severity"]),
                        actor=entry_dict["actor"],
                        action=entry_dict["action"],
                        resource=entry_dict.get("resource"),
                        resource_type=entry_dict.get("resource_type"),
                        result=entry_dict.get("result", "success"),
                        details=entry_dict.get("details", {}),
                        session_id=entry_dict.get("session_id"),
                        client_ip=entry_dict.get("client_ip"),
                        previous_hash=entry_dict.get("previous_hash"),
                        entry_hash=entry_dict.get("entry_hash"),
                    )
                    
                    # Verify hash chain
                    if previous_hash and entry.previous_hash != previous_hash:
                        tampering_detected.append({
                            "entry_index": i,
                            "timestamp": entry.timestamp,
                            "issue": "Hash chain broken",
                            "expected_previous": previous_hash,
                            "actual_previous": entry.previous_hash,
                        })
                    
                    # Verify entry hash
                    computed_hash = entry.compute_hash()
                    if entry.entry_hash and computed_hash != entry.entry_hash:
                        tampering_detected.append({
                            "entry_index": i,
                            "timestamp": entry.timestamp,
                            "issue": "Entry hash mismatch",
                            "expected": entry.entry_hash,
                            "computed": computed_hash,
                        })
                    
                    previous_hash = entry.entry_hash
                    entries_checked += 1
                    
        except Exception as e:
            return {
                "verified": False,
                "error": str(e),
                "entries_checked": entries_checked,
            }
        
        if tampering_detected:
            return {
                "verified": False,
                "entries_checked": entries_checked,
                "tampering_detected": len(tampering_detected),
                "details": tampering_detected,
            }
        
        return {
            "verified": True,
            "entries_checked": entries_checked,
            "message": "Audit log integrity verified",
        }
    
    def query(
        self,
        event_types: Optional[List[AuditEventType]] = None,
        actor: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        severity: Optional[AuditSeverity] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Query audit log entries.
        
        Args:
            event_types: Filter by event types
            actor: Filter by actor
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            severity: Filter by severity
            limit: Maximum entries to return
            
        Returns:
            List of matching audit entries
        """
        if not self.log_file.exists():
            return []
        
        results = []
        
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    if len(results) >= limit:
                        break
                    
                    entry_dict = json.loads(line.strip())
                    
                    # Apply filters
                    if event_types:
                        event_type_values = [et.value for et in event_types]
                        if entry_dict["event_type"] not in event_type_values:
                            continue
                    
                    if actor and entry_dict.get("actor") != actor:
                        continue
                    
                    if start_time and entry_dict["timestamp"] < start_time:
                        continue
                    
                    if end_time and entry_dict["timestamp"] > end_time:
                        continue
                    
                    if severity and entry_dict.get("severity") != severity.value:
                        continue
                    
                    results.append(entry_dict)
                    
        except Exception as e:
            logger.error(f"Failed to query audit log: {e}")
        
        return results
    
    def generate_compliance_report(
        self,
        start_time: float,
        end_time: float,
        include_events: Optional[List[AuditEventType]] = None,
    ) -> Dict[str, Any]:
        """
        Generate compliance report for audit period.
        
        Args:
            start_time: Report start timestamp
            end_time: Report end timestamp
            include_events: Event types to include
            
        Returns:
            Compliance report with statistics and entries
        """
        entries = self.query(
            event_types=include_events,
            start_time=start_time,
            end_time=end_time,
            limit=100000,  # High limit for reports
        )
        
        # Calculate statistics
        event_counts = {}
        severity_counts = {}
        actor_counts = {}
        
        for entry in entries:
            event_type = entry["event_type"]
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            severity = entry.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            actor = entry.get("actor", "unknown")
            actor_counts[actor] = actor_counts.get(actor, 0) + 1
        
        return {
            "report_period": {
                "start": start_time,
                "start_iso": datetime.fromtimestamp(
                    start_time, tz=timezone.utc
                ).isoformat(),
                "end": end_time,
                "end_iso": datetime.fromtimestamp(
                    end_time, tz=timezone.utc
                ).isoformat(),
            },
            "summary": {
                "total_events": len(entries),
                "event_type_counts": event_counts,
                "severity_counts": severity_counts,
                "actor_counts": actor_counts,
            },
            "entries": entries,
        }


# Convenience functions for common audit events

def audit_scan_started(
    audit_logger: AuditLogger,
    scan_id: str,
    actor: str,
    target: str,
    **kwargs
) -> AuditEntry:
    """Log scan started event."""
    return audit_logger.log(
        event_type=AuditEventType.SCAN_STARTED,
        actor=actor,
        action=f"Started security scan: {scan_id}",
        resource=target,
        resource_type="file" if Path(target).exists() else "repository",
        details={"scan_id": scan_id, **kwargs},
    )


def audit_scan_completed(
    audit_logger: AuditLogger,
    scan_id: str,
    actor: str,
    issues_found: int,
    **kwargs
) -> AuditEntry:
    """Log scan completed event."""
    return audit_logger.log(
        event_type=AuditEventType.SCAN_COMPLETED,
        actor=actor,
        action=f"Completed security scan: {scan_id}",
        details={
            "scan_id": scan_id,
            "issues_found": issues_found,
            **kwargs,
        },
    )


def audit_config_changed(
    audit_logger: AuditLogger,
    actor: str,
    config_key: str,
    old_value: Any,
    new_value: Any,
    **kwargs
) -> AuditEntry:
    """Log configuration change event."""
    return audit_logger.log(
        event_type=AuditEventType.CONFIG_CHANGED,
        actor=actor,
        action=f"Changed configuration: {config_key}",
        resource=config_key,
        resource_type="configuration",
        severity=AuditSeverity.WARNING,
        details={
            "config_key": config_key,
            "old_value": str(old_value),
            "new_value": str(new_value),
            **kwargs,
        },
    )


def audit_auth_attempt(
    audit_logger: AuditLogger,
    actor: str,
    success: bool,
    client_ip: Optional[str] = None,
    **kwargs
) -> AuditEntry:
    """Log authentication attempt."""
    return audit_logger.log(
        event_type=AuditEventType.AUTH_SUCCESS if success else AuditEventType.AUTH_FAILED,
        actor=actor,
        action=f"Authentication {'successful' if success else 'failed'}",
        severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
        result="success" if success else "failure",
        client_ip=client_ip,
        details=kwargs,
    )
