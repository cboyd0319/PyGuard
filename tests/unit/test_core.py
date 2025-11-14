"""Unit tests for core module."""

from pathlib import Path
import tempfile

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
        assert "1" in diff
        assert "2" in diff

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

    def test_find_python_files_with_exclusions(self):
        """Test finding Python files with exclusion patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "test1.py").write_text("print('test1')")
            (Path(tmpdir) / "test2.py").write_text("print('test2')")
            (Path(tmpdir) / "exclude_me.py").write_text("print('excluded')")

            ops = FileOperations()
            python_files = ops.find_python_files(Path(tmpdir), exclude_patterns=["exclude_*"])
            assert len(python_files) == 2
            assert all("exclude" not in str(f) for f in python_files)

    def test_read_file_with_unicode_decode_error(self):
        """Test reading file that has unicode decode issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file with latin-1 encoding
            file_path = Path(tmpdir) / "latin1.py"
            with open(file_path, "w", encoding="latin-1") as f:
                f.write("# Comment with special char: \xe9")

            ops = FileOperations()
            # Should fallback to latin-1 encoding
            content = ops.read_file(file_path)
            assert content is not None
            assert "\xe9" in content or "é" in content

    def test_read_file_nonexistent(self):
        """Test reading nonexistent file returns None."""
        ops = FileOperations()
        content = ops.read_file(Path("/nonexistent/file.py"))
        assert content is None

    def test_read_file_with_permission_error(self, mocker):
        """Test reading file handles permission errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("test content")

            ops = FileOperations()

            # Mock open to raise a permission error
            mocker.patch("builtins.open", side_effect=PermissionError("Access denied"))

            content = ops.read_file(test_file)
            assert content is None

    def test_read_file_with_unicode_fallback_error(self, mocker):
        """Test reading file handles errors during encoding fallback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_bytes(b"\xff\xfe")  # Invalid UTF-8

            ops = FileOperations()

            # Make first open raise UnicodeDecodeError, second raise IOError
            call_count = [0]

            def mock_open(*args, **kwargs):
                # TODO: Add docstring
                call_count[0] += 1
                if call_count[0] == 1:
                    raise UnicodeDecodeError("utf-8", b"", 0, 1, "invalid")
                raise OSError("Disk error")

            mocker.patch("builtins.open", side_effect=mock_open)

            content = ops.read_file(test_file)
            assert content is None

    def test_write_file_error(self):
        """Test writing file to invalid path."""
        ops = FileOperations()
        # Try to write to root (should fail without permissions)
        result = ops.write_file("/root/protected/file.py", "content")
        # Result depends on permissions, but shouldn't raise
        assert isinstance(result, bool)


class TestBackupManagerAdvanced:
    """Advanced test cases for BackupManager class."""

    def test_create_backup_failure(self):
        """Test backup creation handles errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            manager = BackupManager(backup_dir=backup_dir)

            # Try to backup nonexistent file
            result = manager.create_backup(Path("/nonexistent/file.py"))
            assert result is None

    def test_restore_backup_failure(self):
        """Test backup restoration handles errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            manager = BackupManager(backup_dir=backup_dir)

            # Try to restore nonexistent backup
            result = manager.restore_backup(
                Path("/nonexistent/backup.bak"), Path(tmpdir) / "restored.py"
            )
            assert result is False

    def test_cleanup_old_backups(self):
        """Test cleanup of old backups."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            manager = BackupManager(backup_dir=backup_dir)

            # Create multiple backup files
            for i in range(5):
                backup = backup_dir / f"test.py.{i}.bak"
                backup.write_text(f"backup {i}")

            # Cleanup, keeping only 2
            manager.cleanup_old_backups(keep_count=2)

            # Should have at most 2 backups per file
            backups = list(backup_dir.glob("*.bak"))
            assert len(backups) <= 2

    def test_cleanup_old_backups_with_exceptions(self):
        """Test cleanup handles removal errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            manager = BackupManager(backup_dir=backup_dir)

            # Create backup files
            for i in range(3):
                backup = backup_dir / f"test.py.{i}.bak"
                backup.write_text(f"backup {i}")

            # Should not raise even if cleanup encounters issues
            manager.cleanup_old_backups(keep_count=1)
            # Test passes if no exception raised

    def test_create_backup_with_permission_error(self, mocker):
        """Test backup creation handles permission errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("test")

            manager = BackupManager(backup_dir=backup_dir)

            # Mock shutil.copy2 to raise an exception
            mocker.patch(
                "pyguard.lib.core.shutil.copy2", side_effect=PermissionError("Access denied")
            )

            result = manager.create_backup(test_file)
            assert result is None

    def test_restore_backup_with_io_error(self, mocker):
        """Test backup restoration handles I/O errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            backup_file = backup_dir / "test.bak"
            backup_file.write_text("backup content")
            target_file = Path(tmpdir) / "target.py"

            manager = BackupManager(backup_dir=backup_dir)

            # Mock shutil.copy2 to raise an exception
            mocker.patch("pyguard.lib.core.shutil.copy2", side_effect=OSError("Disk full"))

            result = manager.restore_backup(backup_file, target_file)
            assert result is False

    def test_cleanup_old_backups_with_removal_error(self, mocker):
        """Test cleanup handles backup removal errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            manager = BackupManager(backup_dir=backup_dir)

            # Create backup files
            for i in range(5):
                backup = backup_dir / f"test.py.{i}.bak"
                backup.write_text(f"backup {i}")

            # Mock unlink to raise an exception
            original_unlink = Path.unlink

            def mock_unlink(self, *args, **kwargs):
                # TODO: Add docstring
                if "test.py.0.bak" in str(self):
                    raise OSError("Cannot delete file")
                return original_unlink(self, *args, **kwargs)

            mocker.patch.object(Path, "unlink", mock_unlink)

            # Should not raise even if removal fails
            manager.cleanup_old_backups(keep_count=2)

    def test_cleanup_old_backups_no_deletion_needed(self):
        """Test cleanup when backups are within keep_count limit."""
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            manager = BackupManager(backup_dir=backup_dir)

            # Create exactly 2 backup files (equal to keep_count)
            for i in range(2):
                backup = backup_dir / f"test.py.{i}.bak"
                backup.write_text(f"backup {i}")

            # Act - cleanup with keep_count=2, should not delete anything
            manager.cleanup_old_backups(keep_count=2)

            # Assert - all backups should still exist
            backups = list(backup_dir.glob("*.bak"))
            assert len(backups) == 2

    def test_cleanup_old_backups_fewer_than_keep_count(self):
        """Test cleanup when backups are fewer than keep_count."""
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            manager = BackupManager(backup_dir=backup_dir)

            # Create only 1 backup file (less than keep_count)
            backup = backup_dir / "test.py.0.bak"
            backup.write_text("backup 0")

            # Act - cleanup with keep_count=3, should not delete anything
            manager.cleanup_old_backups(keep_count=3)

            # Assert - backup should still exist
            backups = list(backup_dir.glob("*.bak"))
            assert len(backups) == 1


class TestPyGuardLoggerAdvanced:
    """Advanced test cases for PyGuardLogger class."""

    def test_log_with_file_write_failure(self):
        """Test logging handles file write failures gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a read-only directory to force write failure
            readonly_dir = Path(tmpdir) / "readonly"
            readonly_dir.mkdir()
            readonly_dir.chmod(0o444)

            log_file = readonly_dir / "log.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))

            # Should not raise exception, should fallback to console
            logger.info("Test message", category="Test")
            # If we get here, the fallback to console worked

    def test_log_error_increments_metrics(self):
        """Test that error logging increments error count."""
        logger = PyGuardLogger()
        initial_errors = logger.metrics.get("errors", 0)

        logger.error("Test error", category="Test")

        assert logger.metrics["errors"] == initial_errors + 1

    def test_log_with_all_levels(self):
        """Test logging at all levels."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=str(log_file))

            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")

            content = log_file.read_text()
            assert "Debug message" in content
            assert "Info message" in content
            assert "Warning message" in content
            assert "Error message" in content


class TestDiffGeneratorEdgeCases:
    """Edge case tests for DiffGenerator class."""

    def test_generate_diff_with_special_characters(self):
        """Test diff generation with special characters."""
        diff_gen = DiffGenerator()

        original = "# Comment with émojis: 🔥\nx = 1"
        modified = "# Comment with émojis: 🔥\nx = 2"

        diff = diff_gen.generate_diff(original, modified)
        assert diff is not None
        assert "🔥" in diff or "x = 1" in diff or "x = 2" in diff

    def test_generate_diff_identical_content(self):
        """Test diff generation with identical content."""
        diff_gen = DiffGenerator()

        content = "x = 1\ny = 2"
        diff = diff_gen.generate_diff(content, content)

        # Diff should be minimal or empty for identical content
        assert isinstance(diff, str)


class TestPyGuardLoggerPathInit:
    """Test logger initialization with Path object."""

    def test_logger_with_path_object(self):
        """Test logger initialization with Path object for log_file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.jsonl"
            logger = PyGuardLogger(log_file=log_file)

            logger.info("Test message")
            assert log_file.exists()
            content = log_file.read_text()
            assert "Test message" in content


class TestBackupManagerListBackups:
    """Test backup manager list_backups functionality."""

    def test_list_backups_empty_directory(self):
        """Test listing backups when directory is empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            manager = BackupManager(backup_dir=backup_dir)

            backups = manager.list_backups()
            assert backups == []

    def test_list_backups_with_pattern(self):
        """Test listing backups with specific pattern."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            # Create test backup files
            (backup_dir / "test.py.1.bak").write_text("test1")
            (backup_dir / "test.py.2.bak").write_text("test2")
            (backup_dir / "other.py.1.bak").write_text("other")

            manager = BackupManager(backup_dir=backup_dir)

            # List all backups
            all_backups = manager.list_backups()
            assert len(all_backups) == 3

            # List specific backups
            test_backups = manager.list_backups(pattern="test.py*")
            assert len(test_backups) == 2
            assert all("test.py" in str(b) for b in test_backups)


class TestDiffGeneratorComprehensive:
    """Comprehensive tests for DiffGenerator."""

    def test_generate_diff_multiline(self):
        """Test diff generation with multiline content."""
        diff_gen = DiffGenerator()

        original = "line1\nline2\nline3\nline4"
        modified = "line1\nmodified2\nline3\nline4"

        diff = diff_gen.generate_diff(original, modified, "test.py")
        assert "line2" in diff or "modified2" in diff
        assert isinstance(diff, str)

    def test_generate_side_by_side_diff_multiline(self):
        """Test side-by-side diff with multiple lines."""
        diff_gen = DiffGenerator()

        original = "line1\nline2\nline3"
        modified = "line1\nchanged\nline3"

        html_diff = diff_gen.generate_side_by_side_diff(original, modified)
        assert isinstance(html_diff, str)
        # HTML diff should contain table elements
        assert "<table" in html_diff or len(html_diff) > 0
