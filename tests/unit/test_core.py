"""Unit tests for core module."""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.core import BackupManager, DiffGenerator, FileOperations, PyGuardLogger


class TestPyGuardLogger:
    """Test cases for PyGuardLogger class."""

    def test_logger_initialization(self):
        """Test logger initialization."""
        logger = PyGuardLogger()
        assert logger is not None
        assert logger.correlation_id is not None

    def test_logger_with_custom_correlation_id(self):
        """Test logger with custom correlation ID."""
        custom_id = "test-correlation-id"
        logger = PyGuardLogger(correlation_id=custom_id)
        assert logger.correlation_id == custom_id

    def test_info_logging(self):
        """Test info level logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))
            logger.info("Test message", file_path="test.py")
            assert log_file.exists()
            content = log_file.read_text()
            assert "Test message" in content
            assert "INFO" in content

    def test_warning_logging(self):
        """Test warning level logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))
            logger.warning("Test warning", category="Test")
            content = log_file.read_text()
            assert "WARNING" in content

    def test_error_logging(self):
        """Test error level logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))
            logger.error("Test error", file_path="test.py")
            content = log_file.read_text()
            assert "ERROR" in content
            # Check metrics updated
            assert logger.metrics["errors"] == 1

    def test_success_logging(self):
        """Test success level logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))
            logger.success("Operation succeeded")
            content = log_file.read_text()
            assert "SUCCESS" in content

    def test_debug_logging(self):
        """Test debug level logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))
            logger.debug("Debug info")
            content = log_file.read_text()
            assert "DEBUG" in content

    def test_track_file_processed(self):
        """Test tracking files processed."""
        logger = PyGuardLogger()
        initial = logger.metrics["files_processed"]
        logger.track_file_processed()
        assert logger.metrics["files_processed"] == initial + 1

    def test_track_issues_found(self):
        """Test tracking issues found."""
        logger = PyGuardLogger()
        logger.track_issues_found(5)
        assert logger.metrics["issues_found"] == 5

    def test_track_fixes_applied(self):
        """Test tracking fixes applied."""
        logger = PyGuardLogger()
        logger.track_fixes_applied(3)
        assert logger.metrics["fixes_applied"] == 3

    def test_get_metrics(self):
        """Test getting metrics."""
        logger = PyGuardLogger()
        logger.track_file_processed()
        logger.track_issues_found(2)
        metrics = logger.get_metrics()
        assert "files_processed" in metrics
        assert "issues_found" in metrics
        assert "elapsed_seconds" in metrics
        assert metrics["files_processed"] == 1
        assert metrics["issues_found"] == 2

    def test_log_metrics(self):
        """Test logging metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))
            logger.track_file_processed()
            logger.log_metrics()
            content = log_file.read_text()
            assert "Metrics" in content


class TestBackupManager:
    """Test cases for BackupManager class."""

    def test_initialization(self):
        """Test backup manager initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            manager = BackupManager(backup_dir=str(backup_dir))
            assert manager.backup_dir.exists()

    def test_create_backup(self):
        """Test backup creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('hello')")

            # Create backup
            backup_dir = Path(tmpdir) / "backups"
            manager = BackupManager(backup_dir=str(backup_dir))
            backup_path = manager.create_backup(test_file)

            assert backup_path is not None
            assert backup_path.exists()
            assert backup_path.read_text() == "print('hello')"

    def test_create_backup_nonexistent_file(self):
        """Test backup of nonexistent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BackupManager(backup_dir=str(Path(tmpdir) / "backups"))
            backup_path = manager.create_backup(Path(tmpdir) / "nonexistent.py")
            assert backup_path is None

    def test_restore_backup(self):
        """Test backup restoration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('original')")

            # Create backup
            backup_dir = Path(tmpdir) / "backups"
            manager = BackupManager(backup_dir=str(backup_dir))
            backup_path = manager.create_backup(test_file)

            # Modify original
            test_file.write_text("print('modified')")

            # Restore
            success = manager.restore_backup(backup_path, test_file)
            assert success
            assert test_file.read_text() == "print('original')"

    def test_restore_nonexistent_backup(self):
        """Test restoring nonexistent backup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BackupManager(backup_dir=str(Path(tmpdir) / "backups"))
            success = manager.restore_backup(
                Path(tmpdir) / "nonexistent.bak", Path(tmpdir) / "test.py"
            )
            assert not success


class TestDiffGenerator:
    """Test cases for DiffGenerator class."""

    def test_initialization(self):
        """Test diff generator initialization."""
        generator = DiffGenerator()
        assert generator is not None

    def test_generate_diff(self):
        """Test diff generation."""
        generator = DiffGenerator()
        old_code = "x = 1"
        new_code = "x = 2"
        diff = generator.generate_diff(old_code, new_code, "test.py")
        assert diff is not None
        assert "-" in diff or "+" in diff
        assert "1" in diff and "2" in diff

    def test_generate_diff_no_changes(self):
        """Test diff generation with no changes."""
        generator = DiffGenerator()
        code = "x = 1\n"
        diff = generator.generate_diff(code, code, "test.py")
        # No changes should result in empty diff
        assert diff == ""

    def test_generate_side_by_side_diff(self):
        """Test side-by-side diff generation."""
        generator = DiffGenerator()
        old_code = "x = 1\ny = 2\n"
        new_code = "x = 2\ny = 2\n"
        diff = generator.generate_side_by_side_diff(old_code, new_code)
        assert diff is not None
        assert isinstance(diff, str)


class TestFileOperations:
    """Test cases for FileOperations class."""

    def test_initialization(self):
        """Test file operations initialization."""
        ops = FileOperations()
        assert ops is not None

    def test_read_file(self):
        """Test reading a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('test')")

            ops = FileOperations()
            content = ops.read_file(test_file)
            assert content == "print('test')"

    def test_read_nonexistent_file(self):
        """Test reading nonexistent file."""
        ops = FileOperations()
        content = ops.read_file(Path("/nonexistent/file.py"))
        assert content is None

    def test_write_file(self):
        """Test writing to a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"

            ops = FileOperations()
            success = ops.write_file(test_file, "print('hello')")
            assert success
            assert test_file.read_text() == "print('hello')"

    def test_find_python_files(self):
        """Test finding Python files in directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "test1.py").write_text("print('test1')")
            (Path(tmpdir) / "test2.py").write_text("print('test2')")
            (Path(tmpdir) / "data.json").write_text("{}")

            ops = FileOperations()
            python_files = ops.find_python_files(Path(tmpdir))
            assert len(python_files) == 2
            assert all(str(f).endswith(".py") for f in python_files)
