"""
Core utilities for PyGuard.

Provides logging, backup management, diff generation, and file operations.
"""

import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import difflib


class PyGuardLogger:
    """Structured JSON logger for PyGuard operations."""

    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize the logger.

        Args:
            log_file: Path to log file. If None, uses logs/pyguard.jsonl
        """
        if log_file is None:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / "pyguard.jsonl"

        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

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
        details: Optional[Dict[str, Any]] = None,
        file_path: Optional[str] = None,
    ) -> None:
        """
        Log a structured message.

        Args:
            level: Log level (INFO, WARNING, ERROR, SUCCESS)
            message: Log message
            category: Category of the log entry
            details: Additional structured data
            file_path: Associated file path
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "category": category,
            "message": message,
            "file": file_path,
            "details": details or {},
        }

        # Write to JSONL file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

        # Also log to Python logger
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"[{category}] {message}")

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

    def create_backup(self, file_path: Union[str, Path]) -> Optional[Path]:
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
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
                f"Failed to create backup: {str(e)}",
                category="Backup",
                file_path=str(file_path),
            )
            return None

    def restore_backup(self, backup_path: Union[str, Path], target_path: Union[str, Path]) -> bool:
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
                f"Failed to restore backup: {str(e)}",
                category="Backup",
            )
            return False

    def list_backups(self, pattern: str = "*.bak") -> List[Path]:
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
        backup_groups: Dict[str, List[Path]] = {}
        for backup in backups:
            base_name = backup.name.split(".")[0]
            backup_groups.setdefault(base_name, []).append(backup)

        # Remove old backups
        for base_name, group in backup_groups.items():
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
                            f"Failed to remove backup: {str(e)}",
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
        html_diff = differ.make_table(
            original_lines,
            modified_lines,
            fromdesc="Original",
            todesc="Modified",
            context=True,
            numlines=3,
        )

        return html_diff


class FileOperations:
    """Common file operations for PyGuard."""

    def __init__(self):
        """Initialize file operations."""
        self.logger = PyGuardLogger()

    def read_file(self, file_path: Union[str, Path]) -> Optional[str]:
        """
        Read file content safely.

        Args:
            file_path: Path to file

        Returns:
            File content as string, or None if read failed
        """
        file_path = Path(file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, "r", encoding="latin-1") as f:
                    return f.read()
            except Exception as e:
                self.logger.error(
                    f"Failed to read file: {str(e)}",
                    category="FileOps",
                    file_path=str(file_path),
                )
                return None
        except Exception as e:
            self.logger.error(
                f"Failed to read file: {str(e)}",
                category="FileOps",
                file_path=str(file_path),
            )
            return None

    def write_file(self, file_path: Union[str, Path], content: str) -> bool:
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
                f"Failed to write file: {str(e)}",
                category="FileOps",
                file_path=str(file_path),
            )
            return False

    def find_python_files(
        self,
        directory: Union[str, Path],
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[Path]:
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
