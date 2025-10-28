"""
Core utilities for PyGuard.

Provides logging, backup management, diff generation, and file operations.
"""

from datetime import datetime, timezone, UTC
import difflib
import json
import logging
from pathlib import Path
import shutil
from typing import Any
import uuid


class PyGuardLogger:
    """
    Structured JSON logger for PyGuard operations.

    Features:
    - Correlation IDs for tracing operations across files
    - Structured JSON output for log aggregation
    - Performance metrics tracking
    - Severity-based filtering
    """

    def __init__(self, log_file: str | None = None, correlation_id: str | None = None):
        """
        Initialize the logger.

        Args:
            log_file: Path to log file. If None, uses logs/pyguard.jsonl
            correlation_id: Optional correlation ID for this logger instance
        """
        if log_file is None:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            self.log_file = log_dir / "pyguard.jsonl"
        else:
            self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Generate or use provided correlation ID
        self.correlation_id = correlation_id or str(uuid.uuid4())

        # Track metrics
        self.metrics: dict[str, Any] = {
            "start_time": datetime.now(UTC),
            "files_processed": 0,
            "issues_found": 0,
            "fixes_applied": 0,
            "errors": 0,
        }

        # Setup Python logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger("PyGuard")

    def log(
        self,
        level: str,
        message: str,
        category: str = "General",
        details: dict[str, Any] | None = None,
        file_path: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """
        Log a structured message with correlation tracking.

        Args:
            level: Log level (INFO, WARNING, ERROR, SUCCESS)
            message: Log message
            category: Category of the log entry
            details: Additional structured data
            file_path: Associated file path
            correlation_id: Optional correlation ID (uses instance ID if not provided)
        """
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "correlation_id": correlation_id or self.correlation_id,
            "level": level,
            "category": category,
            "message": message,
            "file": file_path,
            "details": details or {},
        }

        # Write to JSONL file
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            # Fallback to console if file write fails
            self.logger.error(f"Failed to write to log file: {e}")

        # Also log to Python logger
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"[{category}] {message}")

        # Update metrics
        if level == "ERROR":
            self.metrics["errors"] += 1

    def info(self, message: str, **kwargs) -> None:
        """Log info level message."""
        self.log("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log warning level message."""
        self.log("WARNING", message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        """Log error level message."""
        self.log("ERROR", message, **kwargs)

    def success(self, message: str, **kwargs) -> None:
        """Log success level message."""
        self.log("SUCCESS", message, **kwargs)

    def debug(self, message: str, **kwargs) -> None:
        """Log debug level message."""
        self.log("DEBUG", message, **kwargs)

    def track_file_processed(self) -> None:
        """Track that a file was processed."""
        self.metrics["files_processed"] += 1

    def track_issues_found(self, count: int) -> None:
        """Track number of issues found."""
        self.metrics["issues_found"] += count

    def track_fixes_applied(self, count: int) -> None:
        """Track number of fixes applied."""
        self.metrics["fixes_applied"] += count

    def get_metrics(self) -> dict[str, Any]:
        """
        Get current metrics.

        Returns:
            Dictionary with metrics including elapsed time
        """
        elapsed = (datetime.now(UTC) - self.metrics["start_time"]).total_seconds()
        return {
            "start_time": self.metrics["start_time"].isoformat(),
            "files_processed": self.metrics["files_processed"],
            "issues_found": self.metrics["issues_found"],
            "fixes_applied": self.metrics["fixes_applied"],
            "errors": self.metrics["errors"],
            "elapsed_seconds": elapsed,
            "files_per_second": self.metrics["files_processed"] / elapsed if elapsed > 0 else 0,
        }

    def log_metrics(self) -> None:
        """Log current metrics as a structured log entry."""
        metrics = self.get_metrics()
        self.info("PyGuard execution metrics", category="Metrics", details=metrics)


class BackupManager:
    """Manages file backups before modifications."""

    def __init__(self, backup_dir: str = ".pyguard_backups"):
        """
        Initialize backup manager.

        Args:
            backup_dir: Directory to store backups
        """
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.logger = PyGuardLogger()

    def create_backup(self, file_path: str | Path) -> Path | None:
        """
        Create a backup of the specified file.

        Args:
            file_path: Path to file to backup

        Returns:
            Path to backup file, or None if backup failed
        """
        file_path = Path(file_path)

        if not file_path.exists():
            self.logger.warning(f"File not found for backup: {file_path}")
            return None

        try:
            # Create timestamp-based backup name
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_path.name}.{timestamp}.bak"
            backup_path = self.backup_dir / backup_name

            # Copy file to backup location
            shutil.copy2(file_path, backup_path)

            self.logger.info(
                f"Backup created: {backup_path}",
                category="Backup",
                file_path=str(file_path),
            )

            return backup_path

        except Exception as e:
            self.logger.error(
                f"Failed to create backup: {e!s}",
                category="Backup",
                file_path=str(file_path),
            )
            return None

    def restore_backup(self, backup_path: str | Path, target_path: str | Path) -> bool:
        """
        Restore a file from backup.

        Args:
            backup_path: Path to backup file
            target_path: Path where file should be restored

        Returns:
            True if restore was successful, False otherwise
        """
        backup_path = Path(backup_path)
        target_path = Path(target_path)

        if not backup_path.exists():
            self.logger.error(
                f"Backup file not found: {backup_path}",
                category="Backup",
            )
            return False

        try:
            shutil.copy2(backup_path, target_path)
            self.logger.success(
                f"Restored from backup: {backup_path} -> {target_path}",
                category="Backup",
            )
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to restore backup: {e!s}",
                category="Backup",
            )
            return False

    def list_backups(self, pattern: str = "*.bak") -> list[Path]:
        """
        List all backup files.

        Args:
            pattern: Glob pattern to match backup files

        Returns:
            List of backup file paths
        """
        return sorted(self.backup_dir.glob(pattern))

    def cleanup_old_backups(self, keep_count: int = 10) -> None:
        """
        Remove old backup files, keeping only the most recent.

        Args:
            keep_count: Number of recent backups to keep per file
        """
        backups = self.list_backups()

        # Group by original filename
        backup_groups: dict[str, list[Path]] = {}
        for backup in backups:
            base_name = backup.name.split(".")[0]
            backup_groups.setdefault(base_name, []).append(backup)

        # Remove old backups
        for _base_name, group in backup_groups.items():
            if len(group) > keep_count:
                sorted_group = sorted(group, key=lambda p: p.stat().st_mtime, reverse=True)
                for old_backup in sorted_group[keep_count:]:
                    try:
                        old_backup.unlink()
                        self.logger.info(
                            f"Removed old backup: {old_backup}",
                            category="Backup",
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed to remove backup: {e!s}",
                            category="Backup",
                        )


class DiffGenerator:
    """Generates diffs between file versions."""

    @staticmethod
    def generate_diff(
        original_content: str,
        modified_content: str,
        file_path: str = "file",
        context_lines: int = 3,
    ) -> str:
        """
        Generate a unified diff between two versions of content.

        Args:
            original_content: Original file content
            modified_content: Modified file content
            file_path: File path for diff header
            context_lines: Number of context lines in diff

        Returns:
            Unified diff string
        """
        original_lines = original_content.splitlines(keepends=True)
        modified_lines = modified_content.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"{file_path} (original)",
            tofile=f"{file_path} (modified)",
            n=context_lines,
        )

        return "".join(diff)

    @staticmethod
    def generate_side_by_side_diff(
        original_content: str,
        modified_content: str,
        width: int = 80,
    ) -> str:
        """
        Generate a side-by-side diff view.

        Args:
            original_content: Original file content
            modified_content: Modified file content
            width: Width of each column

        Returns:
            Side-by-side diff string
        """
        original_lines = original_content.splitlines()
        modified_lines = modified_content.splitlines()

        differ = difflib.HtmlDiff()
        return differ.make_table(
            original_lines,
            modified_lines,
            fromdesc="Original",
            todesc="Modified",
            context=True,
            numlines=3,
        )


class FileOperations:
    """Common file operations for PyGuard."""

    def __init__(self):
        """Initialize file operations."""
        self.logger = PyGuardLogger()

    def read_file(self, file_path: str | Path) -> str | None:
        """
        Read file content safely.

        Args:
            file_path: Path to file

        Returns:
            File content as string, or None if read failed
        """
        file_path = Path(file_path)

        try:
            with open(file_path, encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, encoding="latin-1") as f:
                    return f.read()
            except Exception as e:
                self.logger.error(
                    f"Failed to read file: {e!s}",
                    category="FileOps",
                    file_path=str(file_path),
                )
                return None
        except Exception as e:
            self.logger.error(
                f"Failed to read file: {e!s}",
                category="FileOps",
                file_path=str(file_path),
            )
            return None

    def write_file(self, file_path: str | Path, content: str) -> bool:
        """
        Write content to file safely.

        Args:
            file_path: Path to file
            content: Content to write

        Returns:
            True if write was successful, False otherwise
        """
        file_path = Path(file_path)

        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            return True

        except Exception as e:
            self.logger.error(
                f"Failed to write file: {e!s}",
                category="FileOps",
                file_path=str(file_path),
            )
            return False

    def find_python_files(
        self,
        directory: str | Path,
        exclude_patterns: list[str] | None = None,
    ) -> list[Path]:
        """
        Find all Python files in a directory.

        Args:
            directory: Directory to search
            exclude_patterns: Patterns to exclude (e.g., ['*test*', 'venv/*'])

        Returns:
            List of Python file paths
        """
        directory = Path(directory)
        exclude_patterns = exclude_patterns or [
            "venv/*",
            ".venv/*",
            "env/*",
            ".env/*",
            "__pycache__/*",
            "*.pyc",
            "build/*",
            "dist/*",
            ".tox/*",
        ]

        python_files = []

        for file_path in directory.rglob("*.py"):
            # Check if file matches any exclude pattern
            excluded = False
            for pattern in exclude_patterns:
                if file_path.match(pattern):
                    excluded = True
                    break

            if not excluded:
                python_files.append(file_path)

        return sorted(python_files)
