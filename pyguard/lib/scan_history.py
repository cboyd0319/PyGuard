"""
Historical Scan Storage and Tracking.

Provides persistent storage and tracking of security scan results over time,
enabling trend analysis, regression detection, and security posture monitoring.

Features:
- Persistent storage of scan results with metadata
- Time-series analysis of security posture
- Regression detection (new issues, fixed issues)
- Comparison between scans
- Export to various formats (JSON, CSV, HTML)
- Integration with compliance reporting

Use Cases:
- Track security improvements over time
- Detect when new vulnerabilities are introduced
- Generate trend reports for management
- Compliance audit trails
- CI/CD security gates (fail if posture degrades)
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Status of a scan."""
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    IN_PROGRESS = "in_progress"


@dataclass
class ScanMetadata:
    """Metadata about a security scan."""
    scan_id: str
    timestamp: float
    status: ScanStatus
    target_path: str
    pyguard_version: str
    duration_seconds: float
    files_scanned: int
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    info_issues: int
    issues_fixed: int = 0
    git_commit: Optional[str] = None
    git_branch: Optional[str] = None
    ci_build_id: Optional[str] = None
    scan_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['status'] = self.status.value
        data['timestamp_iso'] = datetime.fromtimestamp(
            self.timestamp, tz=timezone.utc
        ).isoformat()
        return data


@dataclass
class IssueRecord:
    """Record of a security issue found in a scan."""
    scan_id: str
    issue_id: str  # Unique identifier for this issue
    file_path: str
    line_number: int
    issue_type: str
    severity: str
    message: str
    cwe_id: Optional[str] = None
    rule_id: Optional[str] = None
    code_snippet: Optional[str] = None
    fixed: bool = False
    suppressed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def get_fingerprint(self) -> str:
        """
        Generate a fingerprint for this issue to track it across scans.
        
        Uses file path, line number, issue type, and code snippet to identify
        the same issue even if the scan_id changes.
        """
        data = f"{self.file_path}:{self.line_number}:{self.issue_type}:{self.code_snippet or ''}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


@dataclass
class ScanComparison:
    """Comparison between two scans."""
    baseline_scan_id: str
    current_scan_id: str
    baseline_timestamp: float
    current_timestamp: float
    new_issues: List[IssueRecord] = field(default_factory=list)
    fixed_issues: List[IssueRecord] = field(default_factory=list)
    unchanged_issues: List[IssueRecord] = field(default_factory=list)
    severity_changes: Dict[str, int] = field(default_factory=dict)

    @property
    def is_regression(self) -> bool:
        """Check if current scan shows regression (new issues)."""
        return len(self.new_issues) > 0

    @property
    def is_improvement(self) -> bool:
        """Check if current scan shows improvement (fixed issues, no new)."""
        return len(self.fixed_issues) > 0 and len(self.new_issues) == 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'baseline_scan_id': self.baseline_scan_id,
            'current_scan_id': self.current_scan_id,
            'baseline_timestamp': self.baseline_timestamp,
            'baseline_timestamp_iso': datetime.fromtimestamp(
                self.baseline_timestamp, tz=timezone.utc
            ).isoformat(),
            'current_timestamp': self.current_timestamp,
            'current_timestamp_iso': datetime.fromtimestamp(
                self.current_timestamp, tz=timezone.utc
            ).isoformat(),
            'summary': {
                'new_issues': len(self.new_issues),
                'fixed_issues': len(self.fixed_issues),
                'unchanged_issues': len(self.unchanged_issues),
                'is_regression': self.is_regression,
                'is_improvement': self.is_improvement,
            },
            'new_issues': [issue.to_dict() for issue in self.new_issues],
            'fixed_issues': [issue.to_dict() for issue in self.fixed_issues],
            'severity_changes': self.severity_changes,
        }


class ScanHistoryStorage:
    """
    Persistent storage for security scan history.
    
    Uses SQLite for efficient querying and storage of scan results over time.
    Provides API for storing, retrieving, and analyzing scan data.
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize scan history storage.
        
        Args:
            db_path: Path to SQLite database (default: .pyguard/scan_history.db)
        """
        if db_path is None:
            db_path = Path.home() / ".pyguard" / "scan_history.db"

        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_database()
        logger.info(f"Scan history storage initialized: {self.db_path}")

    def _init_database(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    pyguard_version TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    total_issues INTEGER NOT NULL,
                    critical_issues INTEGER NOT NULL,
                    high_issues INTEGER NOT NULL,
                    medium_issues INTEGER NOT NULL,
                    low_issues INTEGER NOT NULL,
                    info_issues INTEGER NOT NULL,
                    issues_fixed INTEGER DEFAULT 0,
                    git_commit TEXT,
                    git_branch TEXT,
                    ci_build_id TEXT,
                    scan_config TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    issue_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    issue_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    cwe_id TEXT,
                    rule_id TEXT,
                    code_snippet TEXT,
                    fixed BOOLEAN DEFAULT 0,
                    suppressed BOOLEAN DEFAULT 0,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)

            # Create indexes for efficient querying
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp 
                ON scans(timestamp)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target 
                ON scans(target_path)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_issues_scan_id 
                ON issues(scan_id)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_issues_fingerprint 
                ON issues(fingerprint)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_issues_severity 
                ON issues(severity)
            """)

            conn.commit()

    def store_scan(
        self,
        metadata: ScanMetadata,
        issues: List[IssueRecord],
    ) -> None:
        """
        Store a scan and its issues.
        
        Args:
            metadata: Scan metadata
            issues: List of issues found in scan
        """
        with sqlite3.connect(self.db_path) as conn:
            # Store scan metadata
            conn.execute("""
                INSERT OR REPLACE INTO scans VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                metadata.scan_id,
                metadata.timestamp,
                metadata.status.value,
                metadata.target_path,
                metadata.pyguard_version,
                metadata.duration_seconds,
                metadata.files_scanned,
                metadata.total_issues,
                metadata.critical_issues,
                metadata.high_issues,
                metadata.medium_issues,
                metadata.low_issues,
                metadata.info_issues,
                metadata.issues_fixed,
                metadata.git_commit,
                metadata.git_branch,
                metadata.ci_build_id,
                json.dumps(metadata.scan_config),
            ))

            # Store issues
            for issue in issues:
                conn.execute("""
                    INSERT INTO issues (
                        scan_id, issue_id, fingerprint, file_path, line_number,
                        issue_type, severity, message, cwe_id, rule_id,
                        code_snippet, fixed, suppressed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    issue.scan_id,
                    issue.issue_id,
                    issue.get_fingerprint(),
                    issue.file_path,
                    issue.line_number,
                    issue.issue_type,
                    issue.severity,
                    issue.message,
                    issue.cwe_id,
                    issue.rule_id,
                    issue.code_snippet,
                    issue.fixed,
                    issue.suppressed,
                ))

            conn.commit()

        logger.info(f"Stored scan {metadata.scan_id} with {len(issues)} issues")

    def get_scan(self, scan_id: str) -> Optional[ScanMetadata]:
        """
        Retrieve scan metadata by ID.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Scan metadata or None if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,)
            )
            row = cursor.fetchone()

            if not row:
                return None

            return ScanMetadata(
                scan_id=row['scan_id'],
                timestamp=row['timestamp'],
                status=ScanStatus(row['status']),
                target_path=row['target_path'],
                pyguard_version=row['pyguard_version'],
                duration_seconds=row['duration_seconds'],
                files_scanned=row['files_scanned'],
                total_issues=row['total_issues'],
                critical_issues=row['critical_issues'],
                high_issues=row['high_issues'],
                medium_issues=row['medium_issues'],
                low_issues=row['low_issues'],
                info_issues=row['info_issues'],
                issues_fixed=row['issues_fixed'],
                git_commit=row['git_commit'],
                git_branch=row['git_branch'],
                ci_build_id=row['ci_build_id'],
                scan_config=json.loads(row['scan_config']) if row['scan_config'] else {},
            )

    def get_scan_issues(self, scan_id: str) -> List[IssueRecord]:
        """
        Retrieve all issues for a scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            List of issues
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM issues WHERE scan_id = ?",
                (scan_id,)
            )

            issues = []
            for row in cursor.fetchall():
                issues.append(IssueRecord(
                    scan_id=row['scan_id'],
                    issue_id=row['issue_id'],
                    file_path=row['file_path'],
                    line_number=row['line_number'],
                    issue_type=row['issue_type'],
                    severity=row['severity'],
                    message=row['message'],
                    cwe_id=row['cwe_id'],
                    rule_id=row['rule_id'],
                    code_snippet=row['code_snippet'],
                    fixed=bool(row['fixed']),
                    suppressed=bool(row['suppressed']),
                ))

            return issues

    def list_scans(
        self,
        target_path: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 100,
    ) -> List[ScanMetadata]:
        """
        List scans with optional filtering.
        
        Args:
            target_path: Filter by target path
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            limit: Maximum number of scans to return
            
        Returns:
            List of scan metadata, sorted by timestamp (newest first)
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            query = "SELECT * FROM scans WHERE 1=1"
            params: List[Any] = []

            if target_path:
                query += " AND target_path = ?"
                params.append(target_path)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)

            scans = []
            for row in cursor.fetchall():
                scans.append(ScanMetadata(
                    scan_id=row['scan_id'],
                    timestamp=row['timestamp'],
                    status=ScanStatus(row['status']),
                    target_path=row['target_path'],
                    pyguard_version=row['pyguard_version'],
                    duration_seconds=row['duration_seconds'],
                    files_scanned=row['files_scanned'],
                    total_issues=row['total_issues'],
                    critical_issues=row['critical_issues'],
                    high_issues=row['high_issues'],
                    medium_issues=row['medium_issues'],
                    low_issues=row['low_issues'],
                    info_issues=row['info_issues'],
                    issues_fixed=row['issues_fixed'],
                    git_commit=row['git_commit'],
                    git_branch=row['git_branch'],
                    ci_build_id=row['ci_build_id'],
                    scan_config=json.loads(row['scan_config']) if row['scan_config'] else {},
                ))

            return scans

    def compare_scans(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> ScanComparison:
        """
        Compare two scans to identify new, fixed, and unchanged issues.
        
        Args:
            baseline_scan_id: Baseline scan identifier
            current_scan_id: Current scan identifier
            
        Returns:
            Comparison results
        """
        baseline_metadata = self.get_scan(baseline_scan_id)
        current_metadata = self.get_scan(current_scan_id)

        if not baseline_metadata or not current_metadata:
            raise ValueError("One or both scans not found")

        baseline_issues = self.get_scan_issues(baseline_scan_id)
        current_issues = self.get_scan_issues(current_scan_id)

        # Build fingerprint maps
        baseline_fingerprints = {
            issue.get_fingerprint(): issue for issue in baseline_issues
        }
        current_fingerprints = {
            issue.get_fingerprint(): issue for issue in current_issues
        }

        # Identify new, fixed, and unchanged issues
        new_issues = [
            issue for fp, issue in current_fingerprints.items()
            if fp not in baseline_fingerprints
        ]

        fixed_issues = [
            issue for fp, issue in baseline_fingerprints.items()
            if fp not in current_fingerprints
        ]

        unchanged_issues = [
            issue for fp, issue in current_fingerprints.items()
            if fp in baseline_fingerprints
        ]

        # Calculate severity changes
        severity_changes = {}
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            baseline_count = getattr(baseline_metadata, f'{severity}_issues', 0)
            current_count = getattr(current_metadata, f'{severity}_issues', 0)
            severity_changes[severity] = current_count - baseline_count

        return ScanComparison(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            baseline_timestamp=baseline_metadata.timestamp,
            current_timestamp=current_metadata.timestamp,
            new_issues=new_issues,
            fixed_issues=fixed_issues,
            unchanged_issues=unchanged_issues,
            severity_changes=severity_changes,
        )

    def get_trend_data(
        self,
        target_path: str,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        Get trend data for a target over time.
        
        Args:
            target_path: Target path to analyze
            days: Number of days to look back
            
        Returns:
            Trend data with time-series statistics
        """
        start_time = time.time() - (days * 24 * 60 * 60)
        scans = self.list_scans(
            target_path=target_path,
            start_time=start_time,
            limit=1000,
        )

        if not scans:
            return {
                'target_path': target_path,
                'days': days,
                'scan_count': 0,
                'message': 'No scans found',
            }

        # Extract time-series data
        timestamps = [scan.timestamp for scan in scans]
        total_issues = [scan.total_issues for scan in scans]
        critical_issues = [scan.critical_issues for scan in scans]
        high_issues = [scan.high_issues for scan in scans]

        # Calculate statistics
        return {
            'target_path': target_path,
            'days': days,
            'scan_count': len(scans),
            'first_scan': datetime.fromtimestamp(
                scans[-1].timestamp, tz=timezone.utc
            ).isoformat(),
            'last_scan': datetime.fromtimestamp(
                scans[0].timestamp, tz=timezone.utc
            ).isoformat(),
            'current_total_issues': scans[0].total_issues,
            'baseline_total_issues': scans[-1].total_issues,
            'total_issues_change': scans[0].total_issues - scans[-1].total_issues,
            'current_critical_issues': scans[0].critical_issues,
            'baseline_critical_issues': scans[-1].critical_issues,
            'critical_issues_change': scans[0].critical_issues - scans[-1].critical_issues,
            'average_total_issues': sum(total_issues) / len(total_issues),
            'max_total_issues': max(total_issues),
            'min_total_issues': min(total_issues),
            'time_series': [
                {
                    'timestamp': scan.timestamp,
                    'timestamp_iso': datetime.fromtimestamp(
                        scan.timestamp, tz=timezone.utc
                    ).isoformat(),
                    'total_issues': scan.total_issues,
                    'critical_issues': scan.critical_issues,
                    'high_issues': scan.high_issues,
                    'medium_issues': scan.medium_issues,
                    'low_issues': scan.low_issues,
                }
                for scan in reversed(scans)  # Chronological order
            ],
        }

    def delete_old_scans(
        self,
        days: int = 365,
    ) -> int:
        """
        Delete scans older than specified days.
        
        Args:
            days: Delete scans older than this many days
            
        Returns:
            Number of scans deleted
        """
        cutoff_time = time.time() - (days * 24 * 60 * 60)

        with sqlite3.connect(self.db_path) as conn:
            # Delete issues first (foreign key constraint)
            conn.execute("""
                DELETE FROM issues WHERE scan_id IN (
                    SELECT scan_id FROM scans WHERE timestamp < ?
                )
            """, (cutoff_time,))

            # Delete scans
            cursor = conn.execute(
                "DELETE FROM scans WHERE timestamp < ?",
                (cutoff_time,)
            )

            deleted_count = cursor.rowcount
            conn.commit()

        logger.info(f"Deleted {deleted_count} scans older than {days} days")
        return deleted_count
